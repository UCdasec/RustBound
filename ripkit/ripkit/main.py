import json
import math
import multiprocessing
import shutil
import subprocess
from collections import Counter
from dataclasses import asdict, dataclass
from multiprocessing import Pool, Queue
from pathlib import Path
from typing import Any, List, Tuple
from yaspin import yaspin

import analyze_cli
from cargo_picky import db_cli as cargo_db_cli
import evil_mod
from ghidra import cli as ghidra_cli
from ida import cli as ida_cli
import lief
import numpy as np
import ripbin_cli
import typer
from alive_progress import alive_bar, alive_it
from art import text2art
from cli_utils import get_enum_type, opt_lvl_callback
from rich import print
from rich.console import Console
from rich.progress import track
from rich.table import Table
from typing_extensions import Annotated

from ripkit.cargo_picky import (CrateBuildException, RustcStripFlags,
                                RustcTarget, build_crate)

from ripkit.ripbin_cli import load_bins

from ripkit.ripbin import (AnalysisType, RustFileBundle, calculate_md5, 
                           disasm_at, generate_minimal_labeled_features,
                           get_functions, iterable_path_shallow_callback,
                           save_analysis)

console = Console()
app = typer.Typer(pretty_exceptions_show_locals=False)
app.add_typer(ghidra_cli.app, name="ghidra", help="Ghidra related functions")
app.add_typer(ida_cli.app, name="ida", help="IDA related functions")
app.add_typer(cargo_db_cli.app, name="cargo", help="Pull cargo crates")
app.add_typer(
    ripbin_cli.app, name="ripbin", help="Build and stash binaries into ripbin db"
)
app.add_typer(analyze_cli.app, name="profile", help="Profile and analyze datasets")
app.add_typer(evil_mod.app, name="modify", help="Modify binaries")


num_cores = multiprocessing.cpu_count()
CPU_COUNT_75 = math.floor(num_cores * (3 / 4))


# TODO: I have seen that global variables are to be avoided, however this one makes alot of sense... look into why we "should" avoid them and considered alternative ways to set them
RIPBIN_DIR = Path("~/.ripbin")


@dataclass
class arch_stats:
    """
    Architecture Specifics stats when profiling dataset
    """

    files: int
    size: int
    funcs: int


@dataclass
class FoundFunctions:
    """
    Helper Object to make explict found functions
    """

    addresses: np.ndarray
    names: List[str]


@dataclass
class DatasetStat:
    """
    Helper Object for gathering dataset stats
    """

    files: int
    file_size: int
    stripped_size: int
    text_section_size: int
    functions: int
    text_section_functions: int
    alias_count: int


@dataclass
class SequenceCounter:
    """
    Helper Object to count occurances of sequences in the dataset
    """

    sequences: int
    found_in_nonstart: int
    found_only_in_start: int
    found_once_in_start: int

    nonstart_occurances: int
    start_occurances: int


@app.command()
def disasm(
    file: Annotated[Path, typer.Argument(help="Input file")],
    addr: Annotated[str, typer.Argument(help="Address to start at in hex")],
    num_bytes: Annotated[int, typer.Argument(help="Number of bytes to disassameble")],
):
    """
    This function was a proof of concept and is meant to match the function of
    objdump (objdump is a linux command, see objdump --help for more info)

    Parameters
    ----------
    file : Path
        The input file to disassemble
    addr : str
        The address in hex to start the disassemlby
    num_bytes: int
        The number of bytes to disassemble
    """

    if not file.exists():
        return

    res = disasm_at(file, int(addr, 16), num_bytes)
    for line in res:
        print(line)
    return


# TODO: This function should be replaced with one already
#       written in the ripkit lib somewhere
def lief_num_funcs(path: Path):

    functions = get_functions(path)
    parsed_bin = lief.parse(str(path.resolve()))

    # Get the text session
    text_section = parsed_bin.get_section(".text")

    # Get the bytes in the .text section
    text_bytes = text_section.content

    # Get the base address of the loaded binary
    base_address = parsed_bin.imagebase

    func_start_addrs = {
        x.addr: (x.name, x.size)
        for x in functions
        if x.addr > base_address + text_section.virtual_address
        and x.addr < base_address + text_section.virtual_address + len(text_bytes)
    }

    return len(func_start_addrs.keys())


# TODO: Type hinting could be more specific than Any
#       Likey it would be better to return a dataclass
def stat_worker(bin_info: List[Any]) -> List[Any]:
    """
    Worker to retrieve stats from ripbin

    Parameters
    ----------
    bin_info :  list[any]
        A list of length 2, first elements is bin, second element is info


    Returns
    -------
    List
    """
    bin_file = bin_info[0]
    info = bin_info[1]

    return info, bin_file.stat().st_size, lief_num_funcs(bin_file)


@app.command()
def stats(
    workers: Annotated[int, typer.Option(help="Number of workers")] = CPU_COUNT_75,
) -> None:
    """
    Print statistics about the ripped binaries in the ripbin database

    Parameters
    ----------
    workers: int
        The number of CPU cores, or workers, to use
    """

    ripbin_dir = Path("~/.ripbin/ripped_bins").expanduser().resolve()

    if not ripbin_dir.exists():
        print(f"Ripbin dir does not exist at {ripbin_dir}")
        return

    riplist = list(ripbin_dir.iterdir())

    bins_info = []

    for parent in alive_it(riplist, title="Gathering file list"):
        info_file = parent / "info.json"
        info = {}
        try:
            with open(info_file, "r") as f:
                info = json.load(f)
        except FileNotFoundError:
            print(f"File not found: {info_file}")
            continue
        except json.JSONDecodeError as e:
            print(f"JSON decoding error: {e}")
            continue
        except Exception as e:
            print(f"An error occurred: {e}")
            continue

        bin_file = parent / info["binary_name"]
        bins_info.append((bin_file, info))


    with yaspin(text=f"Using {workers} cores to load {len(bins_info)} binaries") as sp:
        queue = Queue()
        with Pool(processes=workers) as pool:
            results = pool.map(stat_worker, bins_info)

            # Start the worker processes
            #results = pool.starmap(stat_worker, bins_info)

            ## Track job completion in the main process
            #completed_jobs = 0
            #while completed_jobs < len(bins_info):
            #    queue.get()  # Wait for a job completion signal
            #    completed_jobs += 1
            #    if completed_jobs % 10 == 0:
            #        sp.write(f"Completed {completed_jobs} jobs of {len(bins_info)}.")

    stats = {}
    for res in results:
        cur_key = (res[0]["target"], res[0]["optimization"])
        if cur_key not in stats.keys():
            stats[cur_key] = arch_stats(0, 0, 0)
        stats[cur_key].files += 1
        stats[cur_key].size += res[1]
        stats[cur_key].funcs += res[2]

    for (arch, opt), data in stats.items():
        if arch != "":
            print(f"{arch} | {opt}")
        else:
            print(f"Unkown | {opt}")
        print(f"    {data.files} files")
        print(f"    {data.size} bytes")
    return



@app.command()
def export(
    inp: Annotated[Path, typer.Argument()],
    out: Annotated[Path, typer.Argument()]):
    """Export the bins in the dirtectory. The direcoty must contain bundles.
    """

    bundles = load_bins(inp)
    out.mkdir(exist_ok=True)
    for bundle in bundles:
        shutil.copyfile(bundle.bin, out.joinpath(bundle.bin.name))

    return 


# TODO: output file should be depreciated
# TODO It shouldn't be possible to have "duplicates" in ripbin. Specifically never should the same source code be compiled the exact same way and get saved twice to ripbin. Assert that this is true and depreciated drop_dups
@app.command()
def export_large_dataset(
    target: Annotated[str, typer.Argument()],
    output_dir: Annotated[
        Path, typer.Option(help="Save the binaries to a directory")
    ] = "",
    output_file: Annotated[
        str, typer.Option(help="Save the binaries paths to a file")
    ] = "",
    min_text_bytes: Annotated[
        int, typer.Option(help="Minimum number of bytes in a files .text section")
    ] = 2000,
    drop_dups: Annotated[
        bool, typer.Option(help="Don't include duplicate files")
    ] = True,
    verbose: Annotated[bool, typer.Option] = False,
) -> None:
    """
    Export a dataset from the ripkit db

    Parameters
    ----------
    target: str
        The rustc supported target triplet to compile for
    output_dir: Path
        The path to export the dataset to
    output_file: str
        The file to export the dataset names to
    min_text_bytes: int
        The minimum number of bytes a file must have in the .text section to export
    drop_dups: bool
        To drop duplicate file names
    verbose: bool
        Verbose messaging to CLI
    """

    out_to_dir = False
    out_to_file = False

    if output_dir != "":
        out_to_dir = True

        out_dir = Path(output_dir)

        if out_dir.exists():
            print("The output directory already exists, please remove it:!")
            print("Run the following command if you are sure...")
            print(f"rm -rf {out_dir.resolve()}")
            return

    if output_file != "":
        out_to_file = True
        out_file = Path(output_file)
        if out_file.exists():
            print("The output directory already exists, please remove it:!")
            print("Run the following command if you are sure...")
            print(f"rm -rf {out_file.resolve()}")
            return

    if not out_to_file and not out_to_dir:
        print("No output to file or directory given")
        return

    # Get a dictionary of all the binaries that are in the ripbin db
    org_bins = ripbin_cli.get_all_bins()

    # Need to find all the bins that exist in each opt lvl
    # and that are atleast the min number of bytes long

    # For each optimization levels and its corresponding bin list:
    # If any binary names appears more than once drop it
    no_dups_bins = {k: [] for k in org_bins.keys()}

    # A dictionary of all the binary names
    dict_of_names = {k: [x.name for x in v] for k, v in org_bins.items()}

    print("Finding binaries whose name occurs in opt lvls more than once...")

    # 1. For each opt level drop all binaries
    #       where they're name appears more than once
    for opt_lvl, bin_list in org_bins.items():
        print(f"[DUP] Before | {opt_lvl} | {len(bin_list)}")
        # For each binary in the list of binaries
        for bin in bin_list:
            # If this binary name appears exactly once, its
            # a good bin
            if dict_of_names[opt_lvl].count(bin.name) == 1:
                no_dups_bins[opt_lvl].append(bin)
        print(f"[DUP] After | {opt_lvl} | {len(no_dups_bins[opt_lvl])}")

    print("Finding binaries that don't match len requirement")

    # New dict to hold bins that meet length requirement
    good_len_bins = {}
    short_bin_names = []

    # Iterate over the dictionary of opt_lvl : [bins]
    # where each list of bins has no duplicates
    for opt_lvl, bins in no_dups_bins.items():
        print(f"[LEN] Before | {opt_lvl} | {len(bins)}")
        cur_good_bins = []
        # TEMP_COUNT = 0
        for bin in track(
            bins, description=f"Checking {opt_lvl} | {len(bins)} bin sizes..."
        ):

            # If the name of the binary has already been
            # found to be short in other opt lvls, don't
            # even consider it
            if bin.name in short_bin_names:
                continue

            # Parse the binary with lief
            parsed_bin = lief.parse(str(bin.resolve()))

            # Get the text section and the bytes themselse
            text_section = parsed_bin.get_section(".text")
            num_text_bytes = len(text_section.content)

            # Append a good binary to the list of current good
            # binaries
            if num_text_bytes >= min_text_bytes:
                cur_good_bins.append(bin)
            else:
                short_bin_names.append(bin.name)
                print(f"[LEN] | SHORT | {opt_lvl} | {bin.name}")

        print(f"[LEN] After | {opt_lvl} | {len(cur_good_bins)}")
        good_len_bins[opt_lvl] = cur_good_bins

    # Update the dict of names
    dict_of_names = {k: [x.name for x in v] for k, v in good_len_bins.items()}

    print(f"[SET] Making sure binaries appear in all lvls")
    # 3. Make sure the names of all the binaries
    #       exist in each opt lvl
    bins_set = []
    for bin_list in dict_of_names.values():
        if len(bins_set) == 0:
            bins_set = bin_list
        else:
            bins_set = set(bins_set) & set(bin_list)

    # Need the intersection of the names of all
    # opt lvls
    set_of_names = list(bins_set)
    final_bins = {}
    print(f"[SET] Found {len(set_of_names)} in final set")

    # remove files that are not in set_of_names
    for opt_lvl, bin_list in no_dups_bins.items():
        print(f"[SET] Before | {opt_lvl} | {len(bin_list)}")
        good_bins = []
        for bin in bin_list:
            if bin.name in set_of_names:
                good_bins.append(bin)

        print(f"[SET] After | {opt_lvl} | {len(good_bins)}")
        final_bins[opt_lvl] = good_bins

    # Write to the output file
    if out_to_file:
        with open(output_file, "w") as f:
            for key in final_bins.keys():
                f.write(str(key) + "\n")
                f.write("\n".join(str(bin.resolve()) for bin in final_bins[key]))

    # Write to output dir
    if out_to_dir:
        out_dir = Path(output_dir)
        out_dir.mkdir()
        for key, bins in final_bins.items():
            opt_out_dir = out_dir / f"{key}_lvl_bins"
            opt_out_dir.mkdir()
            for bin in track(
                bins, description=f"Copying {len(bins)} bins for opt {key}..."
            ):
                dest_file = opt_out_dir / bin.name
                shutil.copy(bin.resolve(), dest_file.resolve())
    return


# TODO: drop bit and file type and replace with a target type.
#       may be have create a custom type that wraps targets for rust and
#       go
@app.command()
def export_large_target_dataset(
    target: Annotated[str, typer.Argument(help="Target triplet to compile")],
    output_dir: Annotated[str, typer.Argument(help="Save the binaries to a directory")],
    output_file: Annotated[
        Path, typer.Option(help="Save the binaries paths to a file")
    ] = "",
    min_text_bytes: Annotated[
        int, typer.Option(help="Minimum number of bytes in a files .text section")
    ] = 2000,
    drop_dups: Annotated[
        bool, typer.Option(help="Don't include duplicate files")
    ] = True,
    verbose: Annotated[bool, typer.Option] = False,
):
    """
    Export a dataset from the CRATES IO DB
    """

    if out_dir.exists():
        print("The output directory already exists, please remove it:!")
        print("Run the following command if you are sure...")
        print(f"rm -rf {out_dir.resolve()}")
        return

    if out_file.exists():
        print("The output directory already exists, please remove it:!")
        print("Run the following command if you are sure...")
        print(f"rm -rf {out_file.resolve()}")
        return

    # Get the corresponding target enum
    target_enum = get_enum_type(RustcTarget, target)

    # Get a dictionary of all the binaries that are in the ripbin db
    org_bins = get_all_target_bins(target_enum)

    # Need to find all the bins that exist in each opt lvl
    # and that are atleast the min number of bytes long

    # For each optimization levels and its corresponding bin list:
    # If any binary names appears more than once drop it
    no_dups_bins = {k: [] for k in org_bins.keys()}

    # A dictionary of all the binary names
    dict_of_names = {k: [x.name for x in v] for k, v in org_bins.items()}

    print("Finding binaries whose name occurs in opt lvls more than once...")

    # 1. For each opt level drop all binaries
    #       where they're name appears more than once
    for opt_lvl, bin_list in org_bins.items():
        print(f"[DUP] Before | {opt_lvl} | {len(bin_list)}")
        # For each binary in the list of binaries
        for bin in bin_list:
            # If this binary name appears exactly once, its
            # a good bin
            if dict_of_names[opt_lvl].count(bin.name) == 1:
                no_dups_bins[opt_lvl].append(bin)
        print(f"[DUP] After | {opt_lvl} | {len(no_dups_bins[opt_lvl])}")

    print("Finding binaries that don't match len requirement")
    # New dict to hold bins that meet length requirement
    good_len_bins = {}
    short_bin_names = []

    # Iterate over the dictionary of opt_lvl : [bins]
    # where each list of bins has no duplicates
    for opt_lvl, bins in no_dups_bins.items():
        print(f"[LEN] Before | {opt_lvl} | {len(bins)}")
        cur_good_bins = []
        # TEMP_COUNT = 0
        for bin in track(
            bins, description=f"Checking {opt_lvl} | {len(bins)} bin sizes..."
        ):

            # TEMP_COUNT+=1
            # if TEMP_COUNT > 100:
            #    break
            # If the name of the binary has already been
            # found to be short in other opt lvls, don't
            # even consider it
            if bin.name in short_bin_names:
                continue

            # Parse the binary with lief
            parsed_bin = lief.parse(str(bin.resolve()))

            # Get the text section and the bytes themselse
            text_section = parsed_bin.get_section(".text")
            num_text_bytes = len(text_section.content)

            # Append a good binary to the list of current good
            # binaries
            if num_text_bytes >= min_text_bytes:
                cur_good_bins.append(bin)
            else:
                short_bin_names.append(bin.name)
                print(f"[LEN] | SHORT | {opt_lvl} | {bin.name}")

        print(f"[LEN] After | {opt_lvl} | {len(cur_good_bins)}")
        good_len_bins[opt_lvl] = cur_good_bins

    # Update the dict of names
    dict_of_names = {k: [x.name for x in v] for k, v in good_len_bins.items()}

    print(f"[SET] Making sure binaries appear in all lvls")
    # 3. Make sure the names of all the binaries
    #       exist in each opt lvl
    bins_set = []
    for bin_list in dict_of_names.values():
        if len(bins_set) == 0:
            bins_set = bin_list
        else:
            bins_set = set(bins_set) & set(bin_list)

    # Need the intersection of the names of all
    # opt lvls
    set_of_names = list(bins_set)
    final_bins = {}
    print(f"[SET] Found {len(set_of_names)} in final set")

    # remove files that are not in set_of_names
    for opt_lvl, bin_list in no_dups_bins.items():
        print(f"[SET] Before | {opt_lvl} | {len(bin_list)}")
        good_bins = []
        for bin in bin_list:
            if bin.name in set_of_names:
                good_bins.append(bin)

        print(f"[SET] After | {opt_lvl} | {len(good_bins)}")
        final_bins[opt_lvl] = good_bins

    # Write to the output file
    if out_to_file:
        with open(output_file, "w") as f:
            for key in final_bins.keys():
                f.write(str(key) + "\n")
                f.write("\n".join(str(bin.resolve()) for bin in final_bins[key]))

    # Write to output dir
    if out_to_dir:
        out_dir.mkdir()
        for key, bins in final_bins.items():
            opt_out_dir = out_dir / f"{key}_lvl_bins"
            opt_out_dir.mkdir()
            for bin in track(
                bins, description=f"Copying {len(bins)} bins for opt {key}..."
            ):
                dest_file = opt_out_dir / bin.name
                shutil.copy(bin.resolve(), dest_file.resolve())
    return


def get_funcs_with(files, backend):

    num_funcs = {}
    f_size = {}
    lief_total = {}
    total_funcs = 0

    if Path(files).is_dir():
        files = list(Path(files).glob("*"))
    else:
        files = [Path(files)]

    for path in alive_it(files):

        f_size[path] = path.stat().st_size

        if backend == "lief":
            functions = get_functions(path)
            parsed_bin = lief.parse(str(path.resolve()))

            # Get the text session
            text_section = parsed_bin.get_section(".text")

            # Get the bytes in the .text section
            text_bytes = text_section.content

            # Get the base address of the loaded binary
            base_address = parsed_bin.imagebase

            # Save total functions per path
            lief_total[path] = len(functions)

            funcs_all = {x.addr: (x.name, x.size) for x in functions}

            funcs_txt = {
                x.addr: (x.name, x.size)
                for x in functions
                if x.addr > base_address + text_section.virtual_address
                and x.addr
                < base_address + text_section.virtual_address + len(text_bytes)
            }

            return funcs_all, funcs_txt

        elif backend == "ghidra":
            # TODO
            return []
        elif backend == "ida":
            # TODO
            print("nop")
            return []
        elif backend == "objdump1":
            cmd = f"objdump -t -f {path.resolve()} | grep 'F .text' | sort"
            res = subprocess.run(
                cmd, shell=True, universal_newlines=True, capture_output=True
            )
            return res.stdout

        elif backend == "objdump2":
            # TODO
            cmd = f"objdump -d {path.resolve()} | grep -cE '^[[:xdigit:]]+ <[^>]+>:'"
            res = subprocess.check_output(cmd, shell=True)
            total_funcs += int(res)
        elif backend == "readelf":
            # TODO
            cmd = f"readelf -Ws {path.resolve()} | grep FUNC | wc -l"
            res = subprocess.check_output(cmd, shell=True)
            print(res)

    return


def parse_obj_stdout(inp):
    addrs = []

    for line in inp.split("\n"):
        addr = line.split(" ")[0].strip()
        if addr != "":
            addrs.append(int(addr, 16))
    return addrs


@app.command()
def count_diff(
    inp: Annotated[
        str, typer.Argument(help="Directory containing files -or- single file")
    ],
    backend: Annotated[
        str, typer.Argument(help="lief, ghidra, ida, objdump1, objdump2, readelf")
    ],
    backend2: Annotated[str, typer.Argument()],
):
    """
    For generation of ground truth there are various tools that can be used to
    extract the addresses. Interesting, despite the function addresses and
    function lengths are explicitly stated in the binary file. Therefore this
    function will take different 'backends' (the tools to extract) the
    ground truth and compre them!
    """

    if backend == "lief":
        tot_funcs, txt_funcs = get_funcs_with(inp, "lief")
        print(txt_funcs)

    if backend2 == "objdump1":
        # Need to parse this output for functions
        stdout_res = get_funcs_with(inp, "objdump1")
        func_addrs = np.array(parse_obj_stdout(stdout_res))
        print(func_addrs)

    same = np.intersect1d(list(txt_funcs.keys()), func_addrs)

    lief_only = np.setdiff1d(list(txt_funcs.keys()), func_addrs)

    obj_only = np.setdiff1d(func_addrs, list(txt_funcs.keys()))
    print(f"Same {len(same)}")
    print(f"Lief only {len(lief_only)}")
    print(f"Obj only {len(obj_only)}")
    print(f"Obj count {len(func_addrs)}")
    print(f"Obj set count {len(set(func_addrs))}")
    print(f"lief count {len(list(txt_funcs.keys()))}")

    # Get the functions that are repeated more than once
    multi_obj = np.setdiff1d(func_addrs, set(func_addrs))

    # TODO: obj repreaeted funcs?
    print(f"The repeated function in obj: {multi_obj}")
    print(f"The repeated function in obj: {len(multi_obj)}")

    with open("SAME", "w") as f:
        for addr in same:
            f.write(f"{hex(addr)}\n")

    with open("LIEF_UNIQUE", "w") as f:
        for addr in lief_only:
            f.write(f"{hex(addr)}\n")

    with open("OBJ_UNIQUE", "w") as f:
        for addr in obj_only:
            f.write(f"{hex(addr)}\n")

    # Then comparse the parsed output with the functions given by lief

    return


def get_text_functions(bin_path: Path):
    """ """
    bin = lief.parse(str(bin_path.resolve()))

    text_section = bin.get_section(".text")
    text_bytes = text_section.content

    # Get the bytes in the .text section
    text_bytes = text_section.content

    # Get the base address of the loaded binary
    base_address = bin.imagebase

    functions = get_functions(bin_path)

    func_start_addrs = {x.addr: (x.name, x.size) for x in functions}
    func_addrs = []
    func_names = []

    # This enumerate the .text byte and sees which ones are functions
    for i, _ in enumerate(text_bytes):
        address = base_address + text_section.virtual_address + i
        if address in func_start_addrs.keys():
            func_addrs.append(address)
            func_names.append(func_start_addrs[address][0])

    # Return the addrs and names
    func_addrs = np.array(func_addrs)
    return FoundFunctions(func_addrs, func_names)


def gen_strip_file(bin_path: Path):
    """
    Strip the passed file and return the path of the
    stripped file
    """

    # Copy the bin and strip it
    strip_bin = bin_path.parent / Path(bin_path.name + "_STRIPPED")
    shutil.copy(bin_path, Path(strip_bin))

    try:
        _ = subprocess.check_output(["strip", f"{strip_bin.resolve()}"])
    except subprocess.CalledProcessError as e:
        print("Error running command:", e)
        return Path("")

    return strip_bin


@app.command()
def DatasetStats(
    dataset: Annotated[str, typer.Argument(help="Input dataset")],
    func_size: Annotated[
        int, typer.Argument(help="Minimum size of function to be considered function")
    ],
):
    """
    Get info on dataset. Expects a dataset to be all binaries, and all nonstripped
    """

    bins = list(Path(dataset).glob("*"))

    stats = DatasetStat(0, 0, 0, 0, 0, 0, 0)

    # Get the size of the stripped bins
    for bin in alive_it(bins):

        stats.files += 1
        stats.file_size += bin.stat().st_size

        functions = get_functions(bin)
        name_counts = Counter([x.name for x in functions])

        alias_count = sum([count for _, count in name_counts.items() if count >= 2])
        stats.alias_count += alias_count

        min_size_functions = [x for x in functions if x.size >= func_size]
        stats.functions += len(min_size_functions)
        stats.text_section_functions += len(get_text_functions(bin).addresses)

        stripped_bin = gen_strip_file(bin)
        stats.stripped_size += stripped_bin.stat().st_size
        stripped_bin.unlink()

        bin = lief.parse(str(bin.resolve()))

        text_section = bin.get_section(".text")
        text_bytes = text_section.content

        # Get the bytes in the .text section
        text_bytes = text_section.content
        stats.text_section_size += len(text_bytes)
    print(stats)
    return


if __name__ == "__main__":

    banner = text2art("Ripkit", "random")
    console.print(banner, highlight=False)
    app()
