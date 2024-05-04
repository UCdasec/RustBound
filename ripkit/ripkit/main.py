import typer
import shlex
from rich import print
from multiprocessing import Pool
import multiprocessing
from collections import Counter
import matplotlib.pyplot as plt
from art import text2art
import numpy as np
from enum import Enum

import ghidra.cli as ghidra_cli
import cargo_picky.db_cli as cargo_db_cli

from typing import List, Tuple
import ida.cli as ida_cli
import shutil
from dataclasses import dataclass, asdict
import subprocess
import lief
import json
from typing_extensions import Annotated
from alive_progress import alive_bar, alive_it
from pathlib import Path
import polars as pl

from rich.console import Console
from rich.table import Table
from rich.progress import track

import ripbin_cli

console = Console()
app = typer.Typer(pretty_exceptions_show_locals=False)
app.add_typer(ghidra_cli.app, name="ghidra")
app.add_typer(ida_cli.app, name="ida")
app.add_typer(cargo_db_cli.app, name="cargo")
app.add_typer(ripbin_cli.app, name="ripbin")

from ripkit.cargo_picky import (
    gen_cargo_build_cmd,
    gen_cross_build_cmd,
    get_target_productions,
    is_executable,
    init_crates_io,
    crates_io_df,
    clone_crate,
    is_remote_crate_exe,
    LocalCratesIO,
    build_crate,
    RustcStripFlags,
    RustcOptimization,
    RustcTarget,
    CrateBuildException,
)

from ripkit.ripbin import (
    get_functions,
    save_analysis,
    calculate_md5,
    RustFileBundle,
    generate_minimal_labeled_features,
    AnalysisType,
    disasm_at,
)

from ripkit.score import analyze_distances

from cli_utils import opt_lvl_callback, get_enum_type
import math

num_cores = multiprocessing.cpu_count()

CPU_COUNT_75 = math.floor(num_cores * (3/4))


# def build_and_stash(
#     crate,
#     opt,
#     target,
#     strip=RustcStripFlags.NOSTRIP,
#     use_cargo=False,
# ):
#     '''
#     Build and stash create in ripbin db
#     '''
#
#     # Build the crate
#     build_crate(crate, opt, target, strip, use_cargo=use_cargo)
#
#     # Need this to get the build command
#     crate_path = Path(LocalCratesIO.CRATES_DIR.value).resolve().joinpath(crate)
#
#     # Need the build command for the bundle info, this is NOT used
#     # to actually exectue a build command
#     if use_cargo:
#         build_cmd = gen_cargo_build_cmd(crate_path, target, strip, opt)
#     else:
#         build_cmd = gen_cross_build_cmd(crate_path, target, strip, opt)
#
#     # Get files of interest from the crate at the target <target>
#     files_of_interest = [
#         x for x in get_target_productions(crate, target) if is_executable(x)
#     ]
#
#     if files_of_interest == []:
#         print(f"Crate {crate} had no build executable productions")
#         # TODO: in the crates_io cache which cloned pkgs don't build any
#         #       files of interest so they are not rebuilt
#         return 99
#
#     # The only file in the list should be the binary
#     binary = files_of_interest[0]
#
#     # Create the file info
#     binHash = calculate_md5(binary)
#
#     filetype = ""
#
#     # Create the file info
#     info = RustFileBundle(binary.name, binHash, target.value, filetype,
#                           opt.value, binary.name, "", build_cmd)
#
#     try:
#         # Save analyiss
#         stash_bin(binary, info, overwrite_existing=True)
#     except Exception as e:
#         print(f"Exception {e} in crate {crate}")
#
#     return
#

# def build_analyze_crate(crate,
#                         opt,
#                         target,
#                         filetype,
#                         strip=RustcStripFlags.NOSTRIP,
#                         use_cargo=True):
#     '''
#     Helper function to build then analyze the crate
#     '''
#
#     # Build the crate
#     build_crate(crate, opt, target, strip, use_cargo=use_cargo)
#
#     # Need this to get the build command
#     crate_path = Path(LocalCratesIO.CRATES_DIR.value).resolve().joinpath(crate)
#
#     # Need the build command for the bundle info, this is NOT used
#     # to actually exectue a build command
#     if use_cargo:
#         build_cmd = gen_cargo_build_cmd(crate_path, target, strip, opt)
#     else:
#         build_cmd = gen_cross_build_cmd(crate_path, target, strip, opt)
#
#     # Get files of interest from the crate at the target <target>
#     files_of_interest = [
#         x for x in get_target_productions(crate, target) if is_executable(x)
#     ]
#
#     if files_of_interest == []:
#         print(f"Crate {crate} had no build executable productions")
#         # TODO: in the crates_io cache which cloned pkgs don't build any
#         #       files of interest so they are not rebuilt
#         return 99
#
#     # The only file in the list should be the binary
#     binary = files_of_interest[0]
#
#     # Create the file info
#     binHash = calculate_md5(binary)
#
#     # Create the file info
#     info = RustFileBundle(binary.name, binHash, target.value, filetype,
#                           opt.value, binary.name, "", build_cmd)
#
#     # Generate analysis
#     data = generate_minimal_labeled_features(binary)
#
#     try:
#         # Save analyiss
#         save_analysis(binary,
#                       data,
#                       AnalysisType.ONEHOT_PLUS_FUNC_LABELS,
#                       info,
#                       overwrite_existing=False)
#     except Exception as e:
#         print(f"Exception {e} in crate {crate}")
#
#     return 0
#

# def get_all_target_bins(target: RustcTarget):
#     '''
#     Get all binaries by the optimization and that are of target target
#     '''
#     bin_by_opt = {
#         '0': [],
#         '1': [],
#         '2': [],
#         '3': [],
#         'z': [],
#         's': [],
#     }
#
#     for parent in Path("/home/ryan/.ripbin/ripped_bins/").iterdir():
#         info_file = parent / 'info.json'
#         info = {}
#         try:
#             with open(info_file, 'r') as f:
#                 info = json.load(f)
#         except FileNotFoundError:
#             print(f"File not found: {info_file}")
#             continue
#         except json.JSONDecodeError as e:
#             print(f"JSON decoding error: {e}")
#             continue
#         except Exception as e:
#             print(f"An error occurred: {e}")
#             continue
#
#         # Define the binary file name
#         bin_file = parent / info['binary_name']
#         opt = info['optimization']
#         bin_target = info['target']
#
#         if opt not in bin_by_opt.keys():
#             bin_by_opt[opt] = []
#
#         if target.value in bin_target:
#             bin_by_opt[opt].append(bin_file.resolve())
#     return bin_by_opt
#

# def get_all_bins() -> dict:
#     '''
#     Get all the binaries by the optimization
#     '''
#
#     bin_by_opt = {
#         '0': [],
#         '1': [],
#         '2': [],
#         '3': [],
#         'z': [],
#         's': [],
#     }
#
#     for parent in Path("/home/ryan/.ripbin/ripped_bins/").iterdir():
#         info_file = parent / 'info.json'
#         info = {}
#         try:
#             with open(info_file, 'r') as f:
#                 info = json.load(f)
#         except FileNotFoundError:
#             print(f"File not found: {info_file}")
#             continue
#         except json.JSONDecodeError as e:
#             print(f"JSON decoding error: {e}")
#             continue
#         except Exception as e:
#             print(f"An error occurred: {e}")
#             continue
#
#         # Define the binary file name
#         bin_file = parent / info['binary_name']
#
#         opt = info['optimization']
#
#         if opt not in bin_by_opt.keys():
#             bin_by_opt[opt] = []
#         else:
#             bin_by_opt[opt].append(bin_file.resolve())
#     return bin_by_opt
#
# @app.command()
# def print_rust_targets():
#     '''
#     Print the rust targets
#     '''
#
#     cmd = shlex.split('rustc --print target-list')
#
#     output = subprocess.run(cmd, capture_output=True, universal_newlines=True)
#     res = output.stdout
#     print(res)
#     return
#
@app.command()
def disasm(
    file: Annotated[str, typer.Argument(help="Input file")],
    addr: Annotated[str,
                    typer.Argument(help="Address to start at in hex")],
    num_bytes: Annotated[int,
                         typer.Argument(
                             help="Number of bytes to disassameble")],
):

    file_path = Path(file)

    if not file_path.exists():
        return

    res = disasm_at(file_path, int(addr, 16), num_bytes)
    for line in res:
        print(line)
    return

#
# @app.command()
# def is_crate_exe(crate: Annotated[str, typer.Argument()]):
#
#     print(is_remote_crate_exe(crate))
#     return
#

# @app.command()
# def cargo_clone(
#     crate: Annotated[str, typer.Argument()],
#     update: Annotated[
#         bool,
#         typer.Option(help="Update the crate if its already cloned")] = False):
#
#     clone_crate(crate, exist_ok=update)
#
#     return
#
#
# @app.command()
# def show_cratesio(column: Annotated[str, typer.Option()] = '', ):
#     '''
#     Show the head of cratesw io dataframe
#     '''
#
#     # Get the df
#     crates_df = crates_io_df()
#
#     if column == '':
#         print(crates_df.head())
#     else:
#         print(crates_df[column])
#     print(crates_df.columns)
#

# @app.command()
# def clone_many_exe(number: Annotated[int, typer.Argument()],
#                    verbose: Annotated[bool, typer.Option()] = False):
#     '''
#     Clone many new executable rust crates.
#     '''
#
#     # Get the remote crate reg
#     reg = crates_io_df()
#
#     # List of crate current installed
#     installed_crates = [
#         x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir()
#         if x.is_dir()
#     ]
#
#     # List of crate names
#     crate_names = [
#         x for x in reg['name'].tolist() if x not in installed_crates
#     ]
#     print("Finding uninstalled registry...")
#
#     # With progress bar, enumerate over the registry
#     cloned_count = 0
#     with alive_bar(number) as bar:
#         for i, crate in enumerate(crate_names):
#             if i % 100 == 0:
#                 print(f"Searching... {i} crates so far")
#             # See if the crate is exe before cloning
#             if is_remote_crate_exe(crate):
#                 print(f"Cloning crate {crate}")
#                 try:
#                     if verbose:
#                         clone_crate(crate, debug=True)
#                     else:
#                         clone_crate(crate)
#
#                     cloned_count += 1
#                     bar()
#                 except Exception as e:
#                     print(e)
#                     #bar(skipped=True)
#                 #bar(skipped=True)
#             # Break out of the loop if enough have cloned
#             if cloned_count >= number:
#                 break
#

# def get_enum_type(enum, input_string) -> Enum:
#     try:
#         return enum(input_string)
#     except Exception:
#         raise ValueError(
#             f"No matching enum type for the string '{input_string}'")
#

@app.command()
def build(
    crate: Annotated[str, typer.Argument(help="crate name")],
    opt_lvl: Annotated[str, typer.Argument(help="O0, O1, O2, O3, Oz, Os")],
    target: Annotated[str, typer.Argument(help="crate target")],
    strip: Annotated[bool, typer.Option()] = False,
    verbose: Annotated[bool, typer.Option()] = False,
):
    '''
    Build a crate for a specific target
    '''

    #TODO: For simpilicity I prompt for only
    # 64 vs 32 bit and pe vs elf. Really I
    # should prompt for the whole target arch
    # b/c theres many different ways to get
    # a 64bit pe  or 32bit elf

    # Opt lvl call back
    try:
        opt = opt_lvl_callback(opt_lvl)
    except Exception as e:
        print(e)
        return

    # Match the target to its enum
    target_enum = get_enum_type(RustcTarget, target)

    #if bit == "64":
    #    if filetype == "elf":
    #        target = RustcTarget.X86_64_UNKNOWN_LINUX_GNU
    #    elif filetype == "pe":
    #        target = RustcTarget.X86_64_PC_WINDOWS_GNU
    #    else:
    #        print("UNknown filetype")
    #        return
    #elif bit == "32":
    #    if filetype == "elf":
    #        target = RustcTarget.I686_UNKNOWN_LINUX_GNU
    #    elif filetype == "pe":
    #        target = RustcTarget.I686_PC_WINDOWS_GNU
    #    else:
    #        print("UNknown filetype")
    #        return
    #else:
    #    print("UNknown bit")
    #    return

    if not strip:
        strip_lvl = RustcStripFlags.NOSTRIP
    else:
        # SYM_TABLE is the all the symbols
        strip_lvl = RustcStripFlags.SYM_TABLE

    if target_enum == RustcTarget.X86_64_UNKNOWN_LINUX_GNU:
        build_crate(crate,
                    opt,
                    target_enum,
                    strip_lvl,
                    use_cargo=True,
                    debug=verbose)
    else:
        build_crate(crate,
                    opt,
                    target_enum,
                    strip_lvl,
                    use_cargo=False,
                    debug=verbose)

    print(f"Crate {crate} built")
    return


@app.command()
def build_all(
    opt_lvl: Annotated[str, typer.Argument(help="O0, O1, O2, O3, Oz, Os")],
    target: Annotated[str, typer.Argument()],
):
    '''
    Build all the installed crates
    '''

    #TODO: For simpilicity I prompt for only
    # 64 vs 32 bit and pe vs elf. Really I
    # should prompt for the whole target arch
    # b/c theres many different ways to get
    # a 64bit pe  or 32bit elf

    # Opt lvl call back
    try:
        opt = opt_lvl_callback(opt_lvl)
    except Exception as e:
        print(e)
        return

    strip_lvl = RustcStripFlags.NOSTRIP

    # List of crate current installed
    installed_crates = [
        x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir()
        if x.is_dir()
    ]

    target = get_enum_type(RustcTarget, target)

    for crate in alive_it(installed_crates):
        if target == RustcTarget.X86_64_UNKNOWN_LINUX_GNU:
            build_crate(crate,
                        opt,
                        target,
                        strip_lvl,
                        use_cargo=True,
                        debug=True)
        else:
            try:
                build_crate(crate, opt, target, strip_lvl)
            except Exception as e:
                print(f"Error on {crate}")


# @app.command()
# def build_all(
#     opt_lvl: Annotated[str, typer.Argument(help="O0, O1, O2, O3, Oz, Os")],
#     bit: Annotated[str, typer.Argument(help="32 or 64")],
#     filetype: Annotated[str, typer.Argument(help="pe or elf")],
#     strip: Annotated[bool, typer.Option()] = False,
# ):
#     '''
#     Build all the installed crates
#     '''
#
#     #TODO: For simpilicity I prompt for only
#     # 64 vs 32 bit and pe vs elf. Really I
#     # should prompt for the whole target arch
#     # b/c theres many different ways to get
#     # a 64bit pe  or 32bit elf
#
#     # Opt lvl call back
#     try:
#         opt = opt_lvl_callback(opt_lvl)
#     except Exception as e:
#         print(e)
#         return
#
#     if bit == "64":
#         if filetype == "elf":
#             target = RustcTarget.X86_64_UNKNOWN_LINUX_GNU
#         elif filetype == "pe":
#             target = RustcTarget.X86_64_PC_WINDOWS_GNU
#         else:
#             return
#     elif bit == "32":
#         if filetype == "elf":
#             target = RustcTarget.I686_UNKNOWN_LINUX_GNU
#         elif filetype == "pe":
#             target = RustcTarget.I686_PC_WINDOWS_GNU
#         else:
#             return
#     else:
#         return
#
#     if not strip:
#         strip_lvl = RustcStripFlags.NOSTRIP
#     else:
#         # SYM_TABLE is the all the symbols
#         strip_lvl = RustcStripFlags.SYM_TABLE
#
#     # List of crate current installed
#     installed_crates = [
#         x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir()
#         if x.is_dir()
#     ]
#
#     for crate in alive_it(installed_crates):
#
#         if target == RustcTarget.X86_64_UNKNOWN_LINUX_GNU:
#             build_crate(crate,
#                         opt,
#                         target,
#                         strip_lvl,
#                         use_cargo=True,
#                         debug=True)
#         else:
#             build_crate(crate, opt, target, strip_lvl)
#
#
# @app.command()
# def list_cloned():
#     '''
#     List the cloned crates
#     '''
#
#     # List of crate current installed
#     installed_crates = [
#         x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir()
#         if x.is_dir()
#     ]
#
#     for crate in installed_crates:
#         print(crate)
#     print(f"Thats {len(installed_crates)} crates")
#

@app.command()
def analyze(
    bin_path: Annotated[str, typer.Argument()],
    language: Annotated[str, typer.Argument()],
    opt_lvl: Annotated[str, typer.Argument(help="O0, O1, O2, O3, Oz, Os")],
    save: Annotated[bool, typer.Option()] = True,
    verbose: Annotated[bool, typer.Option()] = False,
    overwrite_existing: Annotated[bool, typer.Option()] = False,
):
    '''
    Analyze binary file 
    '''

    binary = Path(bin_path).resolve()
    if not binary.exists():
        print(f"Binary {binary} doesn't exist")
        return

    # Generate analysis
    if verbose:
        print("Generating Tensors...")
    data = generate_minimal_labeled_features(binary)

    # Create the file info
    if verbose: print("Calculating bin hash...")
    binHash = calculate_md5(binary)

    # TODO: Anlysis not being saved with target or ELF vs PE?

    # Create the file info
    info = RustFileBundle(binary.name, binHash, "", opt_lvl,
                          binary.name, "", "")

    if verbose: print("Saving Tensor and binary")
    # Save analyiss
    save_analysis(binary,
                  data,
                  AnalysisType.ONEHOT_PLUS_FUNC_LABELS,
                  info,
                  overwrite_existing=overwrite_existing)

@dataclass
class arch_stats():
    files: int
    size: int
    funcs: int


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
        if x.addr > base_address + text_section.virtual_address and
        x.addr < base_address + text_section.virtual_address + len(text_bytes)
    }

    return len(func_start_addrs.keys())


@app.command()
def stats():
    '''
    Print statistics about the ripped binaries in the ripbin database
    '''

    # Dict of info
    stats = {}

    ripbin_dir = Path("~/.ripbin/ripped_bins").expanduser().resolve()
    if not ripbin_dir.exists():
        print(f"Ripbin dir does not exist at {ripbin_dir}")
        return

    riplist = list(ripbin_dir.iterdir())

    #for parent in alive_it(Path("/home/ryan/.ripbin/ripped_bins/").iterdir()):
    for parent in alive_it(riplist):
        info_file = parent / 'info.json'
        info = {}
        try:
            with open(info_file, 'r') as f:
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


        bin_file = parent / info['binary_name']
        dict_key = (info['target'], info['optimization'])

        print(bin_file.resolve())
        if dict_key not in stats.keys():
            stats[dict_key] = arch_stats(0, 0, 0)

        stats[dict_key].files += 1
        stats[dict_key].size += bin_file.stat().st_size
        stats[dict_key].funcs += lief_num_funcs(bin_file)

    for (arch, opt), data in stats.items():
        if arch != "":
            print(f"{arch} | {opt}")
        else:
            print(f"Unkown | {opt}")
        print(f"    {data.files} files")
        print(f"    {data.size} bytes")
    return


@app.command()
def export_large_dataset(
    target: Annotated[str, typer.Argument()],
    output_dir: Annotated[str,
                          typer.Option(
                              help="Save the binaries to a directory")] = "",
    output_file: Annotated[str,
                           typer.Option(
                               help="Save the binaries paths to a file")] = "",
    min_text_bytes: Annotated[
        int,
        typer.Option(
            help="Minimum number of bytes in a files .text section")] = 2000,
    drop_dups: Annotated[bool,
                         typer.Option(
                             help="Don't include duplicate files")] = True,
    verbose: Annotated[bool, typer.Option] = False,
):
    '''
    Export a dataset from the ripkit db
    '''

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
    org_bins = get_all_bins()

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
        #TEMP_COUNT = 0
        for bin in track(
                bins,
                description=f"Checking {opt_lvl} | {len(bins)} bin sizes..."):

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
        with open(output_file, 'w') as f:
            for key in final_bins.keys():
                f.write(str(key) + "\n")
                f.write("\n".join(
                    str(bin.resolve()) for bin in final_bins[key]))

    # Write to output dir
    if out_to_dir:
        out_dir = Path(output_dir)
        out_dir.mkdir()
        for key, bins in final_bins.items():
            opt_out_dir = out_dir / f"{key}_lvl_bins"
            opt_out_dir.mkdir()
            for bin in track(
                    bins,
                    description=f"Copying {len(bins)} bins for opt {key}..."):
                dest_file = opt_out_dir / bin.name
                shutil.copy(bin.resolve(), dest_file.resolve())
    return


#TODO: drop bit and file type and replace with a target type.
#       may be have create a custom type that wraps targets for rust and
#       go
@app.command()
def export_large_target_dataset(
    target: Annotated[str, typer.Argument()],
    output_dir: Annotated[str,
                          typer.Argument(
                              help="Save the binaries to a directory")],
    output_file: Annotated[str,
                           typer.Option(
                               help="Save the binaries paths to a file")] = "",
    min_text_bytes: Annotated[
        int,
        typer.Option(
            help="Minimum number of bytes in a files .text section")] = 2000,
    drop_dups: Annotated[bool,
                         typer.Option(
                             help="Don't include duplicate files")] = True,
    verbose: Annotated[bool, typer.Option] = False,
):
    '''
    Export a dataset from the CRATES IO DB 
    '''

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
        #TEMP_COUNT = 0
        for bin in track(
                bins,
                description=f"Checking {opt_lvl} | {len(bins)} bin sizes..."):

            #TEMP_COUNT+=1
            #if TEMP_COUNT > 100:
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
        with open(output_file, 'w') as f:
            for key in final_bins.keys():
                f.write(str(key) + "\n")
                f.write("\n".join(
                    str(bin.resolve()) for bin in final_bins[key]))

    # Write to output dir
    if out_to_dir:
        out_dir = Path(output_dir)
        out_dir.mkdir()
        for key, bins in final_bins.items():
            opt_out_dir = out_dir / f"{key}_lvl_bins"
            opt_out_dir.mkdir()
            for bin in track(
                    bins,
                    description=f"Copying {len(bins)} bins for opt {key}..."):
                dest_file = opt_out_dir / bin.name
                shutil.copy(bin.resolve(), dest_file.resolve())
    return


# @app.command()
# def export_dataset(
#     opt_lvl: Annotated[str, typer.Argument()],
#     bit: Annotated[int, typer.Argument()],
#     filetype: Annotated[str, typer.Argument()],
#     output_dir: Annotated[str,
#                           typer.Option(
#                               help="Save the binaries to a directory")] = "",
#     output_file: Annotated[str,
#                            typer.Option(
#                                help="Save the binaries paths to a file")] = "",
#     min_text_bytes: Annotated[int, typer.Option()] = 2000,
#     drop_dups: Annotated[bool, typer.Option()] = True,
#     verbose: Annotated[bool, typer.Option] = False,
# ):
#     '''
#     Generate a dataset of files from the ripbin database.
#     Either copy all the binaries to a output directory 
#     -or-
#     Create a file containing the absolute paths to the binaries
#     '''
#
#     # Opt lvl call back
#     try:
#         opt = opt_lvl_callback(opt_lvl)
#     except Exception as e:
#         print(e)
#         return
#     opt = opt.value.upper()
#
#     out_to_dir = False
#     out_to_file = False
#
#     if output_dir != "":
#         out_to_dir = True
#
#         out_dir = Path(output_dir)
#
#         if out_dir.exists():
#             print("The output directory already exists, please remove it:!")
#             print("Run the following command if you are sure...")
#             print(f"rm -rf {out_dir.resolve()}")
#             return
#
#     if output_file != "":
#         out_to_file = True
#         out_file = Path(output_file)
#         if out_file.exists():
#             print("The output directory already exists, please remove it:!")
#             print("Run the following command if you are sure...")
#             print(f"rm -rf {out_file.resolve()}")
#             return
#
#     if not out_to_file and not out_to_dir:
#         print("No output to file or directory given")
#         return
#
#     # Get a dictionary of all the binaries that are in the ripbin db
#     bins = get_all_bins()
#
#     if verbose:
#         print(f"Total {len(bins[opt_lvl])} binaries with opt_lvl {opt_lvl}")
#
#     # Create the set of binary names that ripbin has a binary for as long
#     # as the binary has been compiled for all optimization levels
#     set_of_names = set([x.name for x in bins[opt]])
#     for key in bins.keys():
#         set_of_names = set_of_names.intersection([x.name for x in bins[key]])
#
#     print(f"Found {len(set_of_names)} bins that are present in all opt lvls")
#
#     # Get a list of pathlib objects for the binaries
#     potential_bins = [x for x in bins[opt] if x.name in set_of_names]
#
#     #TODO: Binary files can have the same name if they come from different
#     #       packages, for now I'm not allowing these to be in any dataset
#     o0_name_set = [x.name for x in potential_bins]
#     dup_names = []
#     for bin in o0_name_set:
#         if o0_name_set.count(bin) > 1:
#             dup_names.append(bin)
#     if dup_names != []:
#         print(f"Dropping {len(dup_names)} binaries with matching names")
#
#     bins = [x for x in potential_bins if x.name not in dup_names]
#
#     final_binset = []
#     for bin in track(bins, description=f"Checking {len(bins)} bin sizes..."):
#         parsed_bin = lief.parse(str(bin.resolve()))
#
#         # Get the text section and the bytes themselse
#         text_section = parsed_bin.get_section(".text")
#         num_text_bytes = len(text_section.content)
#         if num_text_bytes > min_text_bytes:
#             final_binset.append(bin)
#
#     if out_to_file:
#         with open(output_file, 'w') as f:
#             f.write("\n".join(bin.resolve for bin in final_binset))
#
#     if out_to_dir:
#         out_dir = Path(output_dir)
#         out_dir.mkdir()
#         for bin in track(bins, description=f"Copying {len(final_binset)}..."):
#             dest_file = out_dir / bin.name
#             shutil.copy(bin.resolve(), dest_file.resolve())
#
#     return
#

def get_funcs_with(files, backend):

    num_funcs = {}
    f_size = {}
    lief_total = {}
    total_funcs = 0

    if Path(files).is_dir():
        files = list(Path(files).glob('*'))
    else:
        files = [Path(files)]

    for path in alive_it(files):

        f_size[path] = path.stat().st_size

        if backend == 'lief':
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
                for x in functions if x.addr > base_address +
                text_section.virtual_address and x.addr < base_address +
                text_section.virtual_address + len(text_bytes)
            }

            return funcs_all, funcs_txt

        elif backend == 'ghidra':
            #TODO
            return []
        elif backend == 'ida':
            #TODO
            print('nop')
            return []
        elif backend == 'objdump1':
            cmd = f"objdump -t -f {path.resolve()} | grep 'F .text' | sort"
            res = subprocess.run(cmd,
                                 shell=True,
                                 universal_newlines=True,
                                 capture_output=True)
            return res.stdout

        elif backend == 'objdump2':
            #TODO
            cmd = f"objdump -d {path.resolve()} | grep -cE '^[[:xdigit:]]+ <[^>]+>:'"
            res = subprocess.check_output(cmd, shell=True)
            total_funcs += int(res)
        elif backend == 'readelf':
            #TODO
            cmd = f"readelf -Ws {path.resolve()} | grep FUNC | wc -l"
            res = subprocess.check_output(cmd, shell=True)
            print(res)

    return


def parse_obj_stdout(inp):
    addrs = []

    for line in inp.split('\n'):
        addr = line.split(' ')[0].strip()
        if addr != '':
            addrs.append(int(addr, 16))
    return addrs


@app.command()
def count_diff(
    inp: Annotated[str,
                   typer.Argument(
                       help="Directory containing files -or- single file")],
    backend: Annotated[
        str,
        typer.Argument(help="lief, ghidra, ida, objdump1, objdump2, readelf")],
    backend2: Annotated[str, typer.Argument()],
):

    # TODO: Very bad func structure right now

    if backend == "lief":
        tot_funcs, txt_funcs = get_funcs_with(inp, 'lief')
        print(txt_funcs)

    if backend2 == "objdump1":
        # Need to parse this output for functions
        stdout_res = get_funcs_with(inp, 'objdump1')
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

    with open("SAME", 'w') as f:
        for addr in same:
            f.write(f"{hex(addr)}\n")

    with open("LIEF_UNIQUE", 'w') as f:
        for addr in lief_only:
            f.write(f"{hex(addr)}\n")

    with open("OBJ_UNIQUE", 'w') as f:
        for addr in obj_only:
            f.write(f"{hex(addr)}\n")

    # Then comparse the parsed output with the functions given by lief

    return

#
# @app.command()
# def count_funcs(
#     inp: Annotated[str,
#                    typer.Argument(
#                        help="Directory containing files -or- single file")],
#     backend: Annotated[
#         str,
#         typer.Argument(
#             help="lief, ghidra, ida, objdump1, objdump2, readelf")] = 'lief',
#     list_functions: Annotated[
#         bool,
#         typer.Option(
#             help="List all the functions in the given files")] = False,
# ):
#     '''
#     Count the functions in the .text section. Files must be non-stripped
#     '''
#
#     num_funcs = {}
#     f_size = {}
#     lief_total = {}
#
#     # Check that the backend is good
#     if backend not in [
#             "lief", "ghidra", "ida", "objdump1", "objdump2", "readelf"
#     ]:
#         print(f"The backend is not in {backend}")
#         return
#
#     if Path(inp).is_dir():
#         files = list(Path(inp).glob('*'))
#     else:
#         files = [Path(inp)]
#
#     total_funcs = 0
#     if backend == 'lief':
#         print("Using Lief for function boundary")
#
#         res = """
#         NOTICE: elffile seems to ignore functions injected by gcc such as 
#         "register_tm...", "deregister_tm...", 
#         Therefore those names will be included in the list, but will have 
#         a size of 0 
#             elf = ELFFile(f)
#
#             # Get the symbol table
#             symbol_table = elf.get_section_by_name('.symtab')
#
#             # Create a list of functionInfo objects... symbol_table will give a 
#             # list of symbols, grab the function sybols and get there name, 
#             # their 'st_value' which is start addr and size 
#             functionInfo = [FunctionInfo(x.name, x['st_value'], f"0x{x['st_value']:x}",x['st_size']) 
#                 for x in symbol_table.iter_symbols() if x['st_info']['type'] == 'STT_FUNC']
#
#         """
#         print(res)
#     elif backend == 'ida':
#         print('nop')
#     elif backend == 'objdump1':
#         cmd = "objdump -t -f <FILE_PATH> | grep 'F .text' | sort | wc -l"
#         print(f"The command being used is {cmd}")
#     elif backend == 'objdump2':
#         cmd = "objdump -d <FILE_PATH> | grep -cE '^[[:xdigit:]]+ <[^>]+>:'"
#         print(f"The command being used is {cmd}")
#     elif backend == 'readelf':
#         cmd = "readelf -Ws <FILE_PATH> | grep FUNC | wc -l"
#         print(f"The command being used is {cmd}")
#
#     for path in alive_it(files):
#
#         f_size[path] = path.stat().st_size
#
#         if backend == 'lief':
#             functions = get_functions(path)
#             parsed_bin = lief.parse(str(path.resolve()))
#
#             # Get the text session
#             text_section = parsed_bin.get_section(".text")
#
#             # Get the bytes in the .text section
#             text_bytes = text_section.content
#
#             # Get the base address of the loaded binary
#             base_address = parsed_bin.imagebase
#
#             lief_total[path] = len(functions)
#             func_start_addrs = {
#                 x.addr: (x.name, x.size)
#                 for x in functions if x.addr > base_address +
#                 text_section.virtual_address and x.addr < base_address +
#                 text_section.virtual_address + len(text_bytes)
#             }
#
#             num_funcs[path] = len(func_start_addrs.keys())
#             if list_functions:
#                 for addr, (name, size) in func_start_addrs.items():
#                     print(f'{hex(addr)} : {name}')
#
#         elif backend == 'ghidra':
#             #TODO
#             print('nop')
#         elif backend == 'ida':
#             #TODO
#             print('nop')
#         elif backend == 'objdump1':
#             #TODO
#             cmd = f"objdump -t -f {path.resolve()} | grep 'F .text' | sort | wc -l"
#             res = subprocess.check_output(cmd, shell=True)
#             total_funcs += int(res)
#         elif backend == 'objdump2':
#             #TODO
#             cmd = f"objdump -d {path.resolve()} | grep -cE '^[[:xdigit:]]+ <[^>]+>:'"
#             res = subprocess.check_output(cmd, shell=True)
#             total_funcs += int(res)
#         elif backend == 'readelf':
#             #TODO
#             cmd = f"readelf -Ws {path.resolve()} | grep FUNC | wc -l"
#             res = subprocess.check_output(cmd, shell=True)
#             print(res)
#
#     if backend == 'lief':
#         print(f"lief Total funcs: {sum(lief_total.values())}")
#         print(f"Total funcs: {sum(num_funcs.values())}")
#         print(f"Total file size: {sum(f_size.values())}")
#     else:
#         print(f"Total functions: {total_funcs}")
#         print(f"Total files: {len(files)}")
#
#     return
#
#
# @app.command()
# def build_all_and_stash(
#     opt_lvl: Annotated[str, typer.Argument()],
#     target: Annotated[str, typer.Argument(help="crate target")],
#     stop_on_fail: Annotated[bool, typer.Option()] = False,
# ):
#     '''
#     Build the crates in crates io and stash into ripbin db
#     '''
#
#     # Opt lvl call back
#     try:
#         opt = opt_lvl_callback(opt_lvl)
#     except Exception as e:
#         print(e)
#         return
#
#     target_enum = get_enum_type(RustcTarget, target)
#
#     # List of crate current installed that can be built
#     crates_to_build = [
#         x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir()
#         if x.is_dir()
#     ]
#
#     # If we don't have to build all the crates, find the crates that
#     # are already built with the specified optimization and arch
#     # an dremovet that from the list of installed crates
#     for parent in Path("/home/ryan/.ripbin/ripped_bins/").iterdir():
#         info_file = parent / 'info.json'
#         info = {}
#         try:
#             with open(info_file, 'r') as f:
#                 info = json.load(f)
#         except FileNotFoundError:
#             print(f"File not found: {info_file}")
#             continue
#         except json.JSONDecodeError as e:
#             print(f"JSON decoding error: {e}")
#             continue
#         except Exception as e:
#             print(f"An error occurred: {e}")
#             continue
#
#         if info['optimization'].upper() in opt_lvl and \
#             info['target'].upper() in target_enum.value.upper():
#             # Remove this file from the installed crates list
#             if (x := info['binary_name']) in crates_to_build:
#                 crates_to_build.remove(x)
#
#     success = 0
#     # Build and analyze each crate
#     for crate in alive_it(crates_to_build):
#         res = 0
#         try:
#             res = build_and_stash(crate,
#                             opt,
#                             target_enum,
#                             use_cargo=False)
#         except CrateBuildException as e:
#             print(f"[bold red]Failed to build crate {crate}:: {e}[/bold red]")
#             continue
#         if res != 99:
#             success += 1
#             print(f"[bold green][SUCCESS][/bold green] crate {crate}")
#
#     print(f"[bold green][SUCCESS] {success}")
#     print(f"[bold red][FAILED] {len(crates_to_build)-success}")
#     return
#

@app.command()
def build_analyze_all(
    opt_lvl: Annotated[str, typer.Argument()],
    #bit: Annotated[int, typer.Argument()],
    filetype: Annotated[str, typer.Argument()],
    target: Annotated[str, typer.Argument(help="crate target")],
    stop_on_fail: Annotated[bool, typer.Option()] = False,
    force_build_all: Annotated[bool, typer.Option()] = False,
    build_arm: Annotated[bool, typer.Option()] = False,
):
    '''
    Build and analyze pkgs
    '''

    # Opt lvl call back
    try:
        opt = opt_lvl_callback(opt_lvl)
    except Exception as e:
        print(e)
        return

    target_enum = get_enum_type(RustcTarget, target)

    # List of crate current installed that can be built
    crates_to_build = [
        x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir()
        if x.is_dir()
    ]

    # If we don't have to build all the crates, find the crates that
    # are already built with the specified optimization and arch
    # an dremovet that from the list of installed crates
    if not force_build_all:

        for parent in Path("/home/ryan/.ripbin/ripped_bins/").iterdir():
            info_file = parent / 'info.json'
            info = {}
            try:
                with open(info_file, 'r') as f:
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

            if info['optimization'].upper() in opt_lvl and \
                info['target'].upper() in target_enum.value.upper():
                # Remove this file from the installed crates list
                if (x := info['binary_name']) in crates_to_build:
                    crates_to_build.remove(x)

    # Any crates that are already built with the same target don't rebuild or analyze

    # Need to get all the analysis for the given optimization and target...
    crates_with_no_interest = Path(
        f"~/.crates_io/uninteresting_crates_cache_{target_enum.value}"
    ).expanduser()

    boring_crates = []
    # If the file doesn't exist throw in the empty list
    if not crates_with_no_interest.exists():
        crates_with_no_interest.touch()
        with open(crates_with_no_interest, 'w') as f:
            json.dump({'names': boring_crates}, f)

    # Add to the boring crates that aren't being built if we are
    # not forcing the build of all crates
    if not force_build_all:
        # If the file does exist read it, ex
        with open(crates_with_no_interest, 'r') as f:
            boring_crates.extend(json.load(f)['names'])

    # Dont build any crate that have been found to have no executable
    crates_to_build = [x for x in crates_to_build if x not in boring_crates]

    #for x in boring_crates:
    #    if x in crates_to_build:
    #        crates_to_build.remove(x)

    success = 0

    # Build and analyze each crate
    for crate in alive_it(crates_to_build):
        #TODO: the following conditional is here because when building for
        #       x86_64 linux I know that cargo will work, and I know
        #       cargo's toolchain version
        res = 0
        if target == RustcTarget.X86_64_UNKNOWN_LINUX_GNU:
            try:
                res = build_analyze_crate(crate,
                                          opt,
                                          target_enum,
                                          filetype,
                                          RustcStripFlags.NOSTRIP,
                                          use_cargo=True)
            except CrateBuildException:
                print(f"Failed to build crate {crate}")
        else:
            try:
                res = build_analyze_crate(crate,
                                          opt,
                                          target_enum,
                                          filetype,
                                          RustcStripFlags.NOSTRIP,
                                          use_cargo=False)
            except CrateBuildException:
                print(f"Failed to build crate {crate}")
                continue
        if res == 99:
            boring_crates.append(crate)
            print(f"Success build but adding {crate} to boring crates")
            with open(crates_with_no_interest, 'w') as f:
                json.dump({'names': boring_crates}, f)
        else:
            success += 1
            print(f"[SUCCESS] crate {crate}")

    print(f"Total build success: {success}")


def get_text_functions(bin_path: Path):
    '''
    '''
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


@dataclass
class FoundFunctions():
    addresses: np.ndarray
    names: List[str]


@dataclass
class dataset_stat:
    files: int
    file_size: int
    stripped_size: int
    text_section_size: int
    functions: int
    text_section_functions: int
    alias_count: int


def gen_strip_file(bin_path: Path):
    '''
    Strip the passed file and return the path of the 
    stripped file
    '''

    # Copy the bin and strip it
    strip_bin = bin_path.parent / Path(bin_path.name + "_STRIPPED")
    shutil.copy(bin_path, Path(strip_bin))

    try:
        _ = subprocess.check_output(['strip', f'{strip_bin.resolve()}'])
    except subprocess.CalledProcessError as e:
        print("Error running command:", e)
        return Path("")

    return strip_bin


@app.command()
def dataset_stats(
    dataset: Annotated[str, typer.Argument()], func_size: Annotated[
        int,
        typer.Argument(
            help="Minimum size of function to be considered function")]):
    '''
    Get info on dataset. Expects a dataset to be all binaries, and all nonstripped
    '''

    bins = list(Path(dataset).glob('*'))

    stats = dataset_stat(0, 0, 0, 0, 0, 0, 0)

    # Get the size of the stripped bins
    for bin in alive_it(bins):

        stats.files += 1
        stats.file_size += bin.stat().st_size

        functions = get_functions(bin)
        name_counts = Counter([x.name for x in functions])

        alias_count = sum(
            [count for _, count in name_counts.items() if count >= 2])
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


def byte_search(dataset, input_seq, count_only=False):
    '''
    Search the dataset for the byte sting. 
    '''

    if Path(dataset).is_dir():
        # Get the files
        files = list(Path(dataset).glob('*'))
    elif Path(dataset).is_file():
        files = [Path(dataset)]
    else:
        return [], []

    # Save the occruacnes here
    prologue_occurances = []
    non_pro_occurances = []

    length = len(input_seq.split(" "))

    prog_occurs = 1
    non_prog_occurs = 0

    #for file in alive_it(files):
    for file in files:
        # get the start addrs
        func_start_addrs = {
            x.addr: (x.name, x.size)
            for x in get_functions(file)
        }

        bin = lief.parse(str(file.resolve()))
        text_section = bin.get_section(".text")

        # Get the bytes in the .text section
        text_bytes = text_section.content

        # Get the base address of the loaded binary
        base_address = bin.imagebase

        # This enumerate the .text byte and sees which ones are functions
        for i, _ in enumerate(text_bytes):
            address = base_address + text_section.virtual_address + i

            if i + length > len(text_bytes) + 1:
                break

            sub_seq = " ".join(str(hex(x)) for x in text_bytes[i:i + length])

            if sub_seq == input_seq:
                if address in func_start_addrs.keys():
                    if count_only:
                        prog_occurs += 1
                    else:
                        prologue_occurances.append((address, file))
                else:
                    if count_only:
                        non_prog_occurs += 1
                    else:
                        non_pro_occurances.append((address, file))
    if count_only:
        return prog_occurs, non_prog_occurs
    else:
        return prologue_occurances, non_pro_occurances


@app.command()
def search_for_bytes(
    dataset: Annotated[str, typer.Argument(help="The dataset")],
    input_seq: Annotated[str,
                         typer.Argument(
                             help="Bytes in format: 0x<byte1> 0x<byte2> ")],
    save_to_files: Annotated[bool, typer.Option()] = False,
):
    '''
    Search the dataset for the byte sting. 
    '''

    if Path(dataset).is_dir():
        # Get the files
        files = list(Path(dataset).glob('*'))
    elif Path(dataset).is_file():
        files = [Path(dataset)]
    else:
        return

    # Save the occruacnes here
    prologue_occurances = []
    non_pro_occurances = []

    length = len(input_seq.split(" "))

    for file in alive_it(files):

        # get the start addrs
        func_start_addrs = {
            x.addr: (x.name, x.size)
            for x in get_functions(file)
        }

        bin = lief.parse(str(file.resolve()))
        text_section = bin.get_section(".text")

        # Get the bytes in the .text section
        text_bytes = text_section.content

        # Get the base address of the loaded binary
        base_address = bin.imagebase

        # This enumerate the .text byte and sees which ones are functions
        for i, _ in enumerate(text_bytes):
            address = base_address + text_section.virtual_address + i

            if i + length > len(text_bytes) + 1:
                break

            sub_seq = " ".join(str(hex(x)) for x in text_bytes[i:i + length])

            if sub_seq == input_seq:
                if address in func_start_addrs.keys():
                    prologue_occurances.append((address, file))
                else:
                    non_pro_occurances.append((address, file))

    #print("Done searching")

    #with open("NON_PRO_OCCURNACE", 'w') as f:
    #    for (addr, file) in non_pro_occurances:
    #        f.write(f"{file} ||||| {hex(addr)}\n")

    print(f"Total {len(prologue_occurances) + len(non_pro_occurances)}")
    if len(prologue_occurances) > 0:
        print(
            f"Prologue {len(prologue_occurances)} | First occurance {hex(prologue_occurances[0][0])} file: {prologue_occurances[0][1]}"
        )
    if len(non_pro_occurances) > 0:
        print(
            f"NonPrologue {len(non_pro_occurances)} | First occurance {hex(non_pro_occurances[0][0])}  file: {non_pro_occurances[0][1]}"
        )

    if save_to_files:
        with open("_PROLOGUES", 'w') as f:
            for (addr, file) in prologue_occurances:
                f.write(f"{file}, {hex(addr)}\n")

        with open("NON_PROLOGUES", 'w') as f:
            for (addr, file) in non_pro_occurances:
                f.write(f"{file}, {hex(addr)}\n")
    return


@dataclass
class file_addr:
    name: str
    addr: int


@dataclass
class prologue:
    key: str
    files_and_addrs: List[file_addr]


def profile_worker(dataset_and_sequence):

    dataset = dataset_and_sequence[0]
    sequence = dataset_and_sequence[1]

    prog_occurs, non_prog_occurs = byte_search(dataset,
                                               sequence,
                                               count_only=True)
    return sequence, prog_occurs, non_prog_occurs

@app.command()
def profile_epilogues(
    dataset: Annotated[str, typer.Argument(help="The dataset")],
    length: Annotated[int,
                      typer.Argument(help="Number of bytes for the epilogue")],
    savefile: Annotated[str, typer.Argument(help="File to save to")],
    workers: Annotated[int, typer.Argument(help="Number of workers")] = CPU_COUNT_75,
):
    '''
    Profile the dataset for it's epilogues. Get info about epilogue frequencey,
    whether or not the epilogues occur in other places that are not epilogues.
    '''

    savepath = Path(savefile)
    if savepath.exists():
        print(f"Path {savepath} already exists")
        return

    schem = {
        'epilogue': pl.Series([], dtype=pl.Utf8),
        'file': pl.Series([], dtype=pl.Utf8),
        'addr': pl.Series([], dtype=pl.Int64),
    }

    progs = {}
    files = list(Path(dataset).glob('*'))
    for file in alive_it(files):

        # Get the functions
        functions = get_functions(file)
        bin = lief.parse(str(file.resolve()))
        text_section = bin.get_section(".text")
        text_bytes = text_section.content

        # Get the bytes in the .text section
        text_bytes = text_section.content

        # Get the base address of the loaded binary
        base_address = bin.imagebase
        func_start_addrs = {x.addr: (x.name, x.size) for x in functions}

        # This enumerate the .text byte and sees which ones are functions
        for i, _ in enumerate(text_bytes):
            address = base_address + text_section.virtual_address + i
            if address in func_start_addrs.keys():

                base_index = i + func_start_addrs[address][1] - length

                epilogue = " ".join(
                    str(hex(x)) for x in text_bytes[base_index:i + length])
                epilogue = epilogue.strip()
                if epilogue in progs.keys():
                    progs[epilogue].append((file, address))
                else:
                    progs[epilogue] = [(file, address)]

    prog_counter = {}
    chunks = []

    for epilogue in progs.keys():
        chunks.append((dataset, epilogue))

    with Pool(processes=workers) as pool:
        results = pool.map(profile_worker, chunks)

    for (seq, pro, nonpro) in alive_it(results):
        if seq in prog_counter.keys():
            prog_counter[seq][0] += pro
            prog_counter[seq][1] += nonpro
        else:
            prog_counter[seq] = [0, 0]
            prog_counter[seq][0] += pro
            prog_counter[seq][1] += nonpro

    print(f"Total number of epilogues: {len(progs.keys())}")


    start_counter = SequenceCounter(0,0,0,0,0,0)

    # Iterate over each sequence, looking it the number of occurance in epilogue,
    # and non-epilogue
    start_counter.sequences = len(prog_counter.keys())
    for seq, (pro_count, nonpro_count) in prog_counter.items():

        if pro_count == 1:
            start_counter.found_once_in_start+=1

        if nonpro_count == 0:
            start_counter.found_only_in_start+=1
        else:
            start_counter.found_in_nonstart+=1

        start_counter.nonstart_occurances+=nonpro_count
        start_counter.start_occurances+=pro_count

    print(f"Number of epilogues that occur else where: {start_counter.found_in_nonstart}")
    print(f"Number of epilogues that didnot occur else where: {start_counter.found_only_in_start}")
    print(f"Number of epilogues that are unique: {start_counter.found_once_in_start}")

    prog_counter['dataset'] = dataset
    prog_counter['seq_len'] = length
    prog_counter['counts'] = asdict(start_counter)

    with open(savepath, 'w') as f:
        json.dump(prog_counter, f)
    return


@dataclass
class SequenceCounter:
    sequences: int
    found_in_nonstart: int 
    found_only_in_start: int 
    found_once_in_start: int

    nonstart_occurances:int
    start_occurances:int




@app.command()
def profile_prologues(
    dataset: Annotated[str, typer.Argument(help="The dataset")],
    length: Annotated[int,
                      typer.Argument(help="Number of bytes for the prologue")],
    savefile: Annotated[str, typer.Argument(help="File to save to")],
    workers: Annotated[int, typer.Argument(help="Number of workers")] = CPU_COUNT_75,
):
    '''
    Profile the dataset for it's prologues. Get info about prologue frequencey,
    whether or not the prologues occur in other places that are not prologues.
    '''

    savepath = Path(savefile)
    if savepath.exists():
        print(f"Path {savepath} already exists")
        return

    schem = {
        'prologue': pl.Series([], dtype=pl.Utf8),
        'file': pl.Series([], dtype=pl.Utf8),
        'addr': pl.Series([], dtype=pl.Int64),
    }

    progs = {}
    files = list(Path(dataset).glob('*'))
    for file in alive_it(files):

        # Get the functions
        functions = get_functions(file)
        bin = lief.parse(str(file.resolve()))
        text_section = bin.get_section(".text")
        text_bytes = text_section.content

        # Get the bytes in the .text section
        text_bytes = text_section.content

        # Get the base address of the loaded binary
        base_address = bin.imagebase
        func_start_addrs = {x.addr: (x.name, x.size) for x in functions}

        # This enumerate the .text byte and sees which ones are functions
        for i, _ in enumerate(text_bytes):
            address = base_address + text_section.virtual_address + i
            if address in func_start_addrs.keys():

                prologue = " ".join(
                    str(hex(x)) for x in text_bytes[i:i + length])
                prologue = prologue.strip()
                if prologue in progs.keys():
                    progs[prologue].append((file, address))
                else:
                    progs[prologue] = [(file, address)]

    prog_counter = {}
    chunks = []

    for prologue in progs.keys():
        chunks.append((dataset, prologue))

    with Pool(processes=workers) as pool:
        results = pool.map(profile_worker, chunks)

    for (seq, pro, nonpro) in alive_it(results):
        if seq in prog_counter.keys():
            prog_counter[seq][0] += pro
            prog_counter[seq][1] += nonpro
        else:
            prog_counter[seq] = [0, 0]
            prog_counter[seq][0] += pro
            prog_counter[seq][1] += nonpro

    print(f"Total number of prologues: {len(progs.keys())}")


    start_counter = SequenceCounter(0,0,0,0,0,0)

    # Iterate over each sequence, looking it the number of occurance in prologue,
    # and non-prologue
    start_counter.sequences = len(prog_counter.keys())
    for seq, (pro_count, nonpro_count) in prog_counter.items():

        if pro_count == 1:
            start_counter.found_once_in_start+=1

        if nonpro_count == 0:
            start_counter.found_only_in_start+=1
        else:
            start_counter.found_in_nonstart+=1

        start_counter.nonstart_occurances+=nonpro_count
        start_counter.start_occurances+=pro_count

    print(f"Number of prologues that occur else where: {start_counter.found_in_nonstart}")
    print(f"Number of prologues that didnot occur else where: {start_counter.found_only_in_start}")
    print(f"Number of prologues that are unique: {start_counter.found_once_in_start}")

    prog_counter['dataset'] = dataset
    prog_counter['seq_len'] = length
    prog_counter['counts'] = asdict(start_counter)

    with open(savepath, 'w') as f:
        json.dump(prog_counter, f)
    return


@app.command()
def top_epilogues(
    dataset: Annotated[str, typer.Argument(help="The dataset")],
    length: Annotated[int,
                      typer.Argument(help="Number of bytes for the prologue")],
    examples: Annotated[int,
                        typer.Argument(help="Num of head and tail prologues")],
):
    '''
    Find Common prologues
    '''

    if Path(dataset).is_dir():
        files = list(Path(dataset).glob('*'))
    elif Path(dataset).is_file():
        files = [Path(dataset)]
    else:
        return

    prologues = {}

    # Save the adresses where a prologue occurs
    addrs = {}
    file_names = {}

    # Save the disasm
    disams = {}

    for file in alive_it(files):

        # Get the functions
        functions = get_functions(file)

        # Add to the prologues dict the prologues

        bin = lief.parse(str(file.resolve()))

        text_section = bin.get_section(".text")
        text_bytes = text_section.content

        # Get the bytes in the .text section
        text_bytes = text_section.content

        # Get the base address of the loaded binary
        base_address = bin.imagebase

        func_start_addrs = {x.addr: (x.name, x.size) for x in functions}
        func_end_addrs = {
            x.addr + x.size: (x.name, x.size, x.addr)
            for x in functions
        }

        # Want to count the number of times a prolog accors and in what file
        # and address it occurs in

        # This enumerate the .text byte and sees which ones are functions
        for i, _ in enumerate(text_bytes):

            # The end address need to be the last byte
            address = base_address + text_section.virtual_address + i
            #if address in func_start_addrs.keys():
            if address + length in func_end_addrs.keys():
                key = " ".join(str(hex(x)) for x in text_bytes[i:i + length])
                key = key.strip()
                if key in prologues.keys():
                    prologues[key] += 1
                    #addrs[key].append((address,file))
                    addrs[key].append(address)
                    file_names[key].append(
                        (file.name, address,
                         func_end_addrs[address + length][2],
                         address + length))
                else:
                    prologues[key] = 1
                    #addrs[key] = [(address,file)]
                    addrs[key] = [(address)]
                    file_names[key] = [((file.name, address,
                                         func_end_addrs[address + length][2],
                                         address + length))]

                # BUG: This was not working, I was unable to correctly diasm
                # Want to get the disasmable of a key
                #disams[key] = disasm_at(file, address, length)
                #disams[key] = disasm_with(file, address, length, file_disasm)

    most_common = dict(
        sorted(prologues.items(), key=lambda item: item[1], reverse=True))
    print(f"Max occurances: {max(prologues.values())}")

    count = 0
    for key, value in most_common.items():
        print(file_names[key][0][0])
        print(hex(file_names[key][0][1]))
        print(
            f"Count {value} | key: {key} | example at {file_names[key][0][0]}:0x{hex(file_names[key][0][1])}"
        )

        # TODO: The following was to print the assmebly for the prologue
        # to the screen, but... has been difficult, and doesn't make
        # sense for shorter prologues (however in the same breath, shorter
        # prologues don't make much sense unless they make atleast a whole
        # instruction)
        #res =  disasm_bytes(files[0], key.encode())

        ## See the below for how the bytes_string is created, this does that
        ## but finds the longest one so I can format the output string nicely
        #max_len = max(len(' '.join([f'{b:02x}' for b in x.bytes ])) for x in res)

        ## Format each byte in the res nicely
        #for thing in res:
        #    byte_ar = thing.bytes
        #    bytes_string = ' '.join([f'{b:02x}' for b in byte_ar])
        #    print(f"0x{thing.address:x}: {bytes_string:<{max_len}} {thing.mnemonic} {thing.op_str}")

        #print(f"Disass:\n{[str(disasm_bytes(files[0], key.encode())}")
        # Turn the key into the disasm

        #print(f"Disam: {disams[key]}")
        count += 1
        if count > examples:
            print(f"Total unique funcs {len(prologues.values())}")
            print(f"Total functions {sum(prologues.values())}")
            break

    least_common = dict(
        sorted(prologues.items(), key=lambda item: item[1], reverse=False))
    # Least common
    print("Least common prologues...")
    count = 0
    for key, value in least_common.items():
        print(
            f"Count {value} | key: {key} | example at {file_names[key][0][0]}:{hex(file_names[key][0][1])}, Start at:{hex(file_names[key][0][2])}, End at {hex(file_names[key][0][3])} "
        )

        # TODO: The following was to print the assmebly for the prologue
        # to the screen, but... has been difficult, and doesn't make
        # sense for shorter prologues (however in the same breath, shorter
        # prologues don't make much sense unless they make atleast a whole
        # instruction)
        #res =  disasm_bytes(files[0], key.encode())

        ## See the below for how the bytes_string is created, this does that
        ## but finds the longest one so I can format the output string nicely
        #max_len = max(len(' '.join([f'{b:02x}' for b in x.bytes ])) for x in res)

        ## Format each byte in the res nicely
        #for thing in res:
        #    byte_ar = thing.bytes
        #    bytes_string = ' '.join([f'{b:02x}' for b in byte_ar])
        #    print(f"0x{thing.address:x}: {bytes_string:<{max_len}} {thing.mnemonic} {thing.op_str}")

        #print(f"Disass:\n{[str(disasm_bytes(files[0], key.encode())}")
        # Turn the key into the disasm

        #print(f"Disam: {disams[key]}")
        count += 1
        if count > examples:
            print(f"Total unique funcs {len(prologues.values())}")
            print(f"Total functions {sum(prologues.values())}")
            return
    return


#TODO: Parallelize this. Also get the disasm working
@app.command()
def top_prologues(
    dataset: Annotated[str, typer.Argument(help="The dataset")],
    length: Annotated[int,
                      typer.Argument(help="Number of bytes for the prologue")],
    examples: Annotated[int,
                        typer.Argument(help="Num of head and tail prologues")],
):
    '''
    Find Common prologues
    '''

    if Path(dataset).is_dir():
        files = list(Path(dataset).glob('*'))
    elif Path(dataset).is_file():
        files = [Path(dataset)]
    else:
        return

    prologues = {}

    # Save the adresses where a prologue occurs
    addrs = {}
    file_names = {}

    # Save the disasm
    disams = {}

    for file in alive_it(files):

        # Get the functions
        functions = get_functions(file)

        # Add to the prologues dict the prologues

        bin = lief.parse(str(file.resolve()))

        text_section = bin.get_section(".text")
        text_bytes = text_section.content

        # Get the bytes in the .text section
        text_bytes = text_section.content

        # Get the base address of the loaded binary
        base_address = bin.imagebase

        func_start_addrs = {x.addr: (x.name, x.size) for x in functions}

        # Want to count the number of times a prolog accors and in what file
        # and address it occurs in

        # This enumerate the .text byte and sees which ones are functions
        for i, _ in enumerate(text_bytes):
            address = base_address + text_section.virtual_address + i
            if address in func_start_addrs.keys():
                key = " ".join(str(hex(x)) for x in text_bytes[i:i + length])
                key = key.strip()
                if key in prologues.keys():
                    prologues[key] += 1
                    #addrs[key].append((address,file))
                    addrs[key].append(address)
                    file_names[key].append((file.name, address))
                else:
                    prologues[key] = 1
                    #addrs[key] = [(address,file)]
                    addrs[key] = [(address)]
                    file_names[key] = [(file.name, address)]

                # BUG: This was not working, I was unable to correctly diasm
                # Want to get the disasmable of a key
                #disams[key] = disasm_at(file, address, length)
                #disams[key] = disasm_with(file, address, length, file_disasm)

    most_common = dict(
        sorted(prologues.items(), key=lambda item: item[1], reverse=True))
    print(f"Max occurances: {max(prologues.values())}")

    count = 0
    for key, value in most_common.items():
        print(file_names[key][0][0])
        print(hex(file_names[key][0][1]))
        print(
            f"Count {value} | key: {key} | example at {file_names[key][0][0]}:0x{hex(file_names[key][0][1])}"
        )

        # TODO: The following was to print the assmebly for the prologue
        # to the screen, but... has been difficult, and doesn't make
        # sense for shorter prologues (however in the same breath, shorter
        # prologues don't make much sense unless they make atleast a whole
        # instruction)
        #res =  disasm_bytes(files[0], key.encode())

        ## See the below for how the bytes_string is created, this does that
        ## but finds the longest one so I can format the output string nicely
        #max_len = max(len(' '.join([f'{b:02x}' for b in x.bytes ])) for x in res)

        ## Format each byte in the res nicely
        #for thing in res:
        #    byte_ar = thing.bytes
        #    bytes_string = ' '.join([f'{b:02x}' for b in byte_ar])
        #    print(f"0x{thing.address:x}: {bytes_string:<{max_len}} {thing.mnemonic} {thing.op_str}")

        #print(f"Disass:\n{[str(disasm_bytes(files[0], key.encode())}")
        # Turn the key into the disasm

        #print(f"Disam: {disams[key]}")
        count += 1
        if count > examples:
            print(f"Total unique funcs {len(prologues.values())}")
            print(f"Total functions {sum(prologues.values())}")
            break

    least_common = dict(
        sorted(prologues.items(), key=lambda item: item[1], reverse=False))
    # Least common
    print("Least common prologues...")
    count = 0
    for key, value in least_common.items():
        print(
            f"Count {value} | key: {key} | example at {file_names[key][0][0]}:0x{hex(file_names[key][0][1])}"
        )

        # TODO: The following was to print the assmebly for the prologue
        # to the screen, but... has been difficult, and doesn't make
        # sense for shorter prologues (however in the same breath, shorter
        # prologues don't make much sense unless they make atleast a whole
        # instruction)
        #res =  disasm_bytes(files[0], key.encode())

        ## See the below for how the bytes_string is created, this does that
        ## but finds the longest one so I can format the output string nicely
        #max_len = max(len(' '.join([f'{b:02x}' for b in x.bytes ])) for x in res)

        ## Format each byte in the res nicely
        #for thing in res:
        #    byte_ar = thing.bytes
        #    bytes_string = ' '.join([f'{b:02x}' for b in byte_ar])
        #    print(f"0x{thing.address:x}: {bytes_string:<{max_len}} {thing.mnemonic} {thing.op_str}")

        #print(f"Disass:\n{[str(disasm_bytes(files[0], key.encode())}")
        # Turn the key into the disasm

        #print(f"Disam: {disams[key]}")
        count += 1
        if count > examples:
            print(f"Total unique funcs {len(prologues.values())}")
            print(f"Total functions {sum(prologues.values())}")
            return
    return


@app.command()
def get_function_list(binary: Annotated[str,
                                        typer.Argument(help="Binary File")], ):
    '''
    Get list of functions
    '''

    bin = Path(binary)

    # Get the functions
    functions = get_functions(bin)

    # Add to the prologues dict the prologues
    bin = lief.parse(str(bin.resolve()))
    text_section = bin.get_section(".text")

    # Get the base address of the loaded binary
    base_address = bin.imagebase

    for i, func in enumerate(functions):
        print(f"{i}: {func.name} : {func.addr}")
    return


@app.command()
def get_function(
    binary: Annotated[str, typer.Argument(help="Binary File")],
    name_like: Annotated[str,
                         typer.Option(help="Substring of function name")] = "",
    name_exact: Annotated[str,
                          typer.Option(help="The exact function name")] = "",
):
    '''
    Get information on the given function in the binary 
    '''

    exact = False
    like = False
    if name_like == "" and name_exact == "":
        print("Need a function name")
        return
    elif name_like != "":
        name = name_like
        like = True
    else:
        name = name_exact
        exact = True

    bin = Path(binary)

    # Get the functions
    functions = get_functions(bin)

    # Add to the prologues dict the prologues
    bin = lief.parse(str(bin.resolve()))

    text_section = bin.get_section(".text")
    text_bytes = text_section.content

    # Get the bytes in the .text section
    text_bytes = text_section.content

    # Get the base address of the loaded binary
    base_address = bin.imagebase

    func_info = ()
    for func in functions:
        if func.name == name and exact:
            func_info = (func.addr, func.name, func.size)
        elif name in func.name and like:
            func_info = (func.addr, func.name, func.size)

    if func_info == ():
        print(f"Function {name} not found in {binary}")
        return

    print("Lief info:")
    print(f"Raw address: {func_info[0]}")
    print(f"Length: {func_info[2]}")

    # Need to apply the offset to get the correct addr:
    # correct addr = cur_byte_index + base_image_addr + text_sec_addr
    offset = base_address + text_section.virtual_address
    blist = text_bytes[func_info[0] - offset:func_info[0] - offset +
                       func_info[2]]

    hex_repr = " ".join(str(hex(x)) for x in blist)
    print(f"HEX REPR:\n {hex_repr}")
    return


def make_ends_distance_pdf_graph(
        bin_size: int,
        max_delta: int,
        ends_delta: np.ndarray,
        xticks: List[int] = [-512, -256, -0, 256, 512, 1024, 2048],
        xlim: Tuple[int, int] = (-512, 2048),
        show=False,
        save=True,
        savename="ends_pdf.png"):
    '''
    Make a PDF graph for the function ends
    '''
    bin_size = 32
    max_edge = max_delta

    # Define the bin size
    custom_edges = [x for x in range(-max_edge, max_edge - bin_size, bin_size)]
    # Calculate the PDF (the density=True function makes this a PDF)
    counts, bin_edges = np.histogram(ends_delta,
                                     bins=custom_edges,
                                     density=True)

    #
    bin_midpoints = (bin_edges[:-1] + bin_edges[1:]) / 2
    plt.bar(bin_midpoints, counts, width=bin_size, edgecolor='k', alpha=0.7)

    # Add labels and title
    plt.xlabel("Binned Distances (End Address- Predicted End Address)")
    plt.xlim(xlim)
    plt.xticks(xticks)
    plt.ylabel("Probability of Label in bin (log scale)")
    plt.yscale('log')
    plt.title("End Prediction Distance Missed PDF, O3 Binaries")

    if save:
        savepath = Path(f"{savename}_ends_pdf")
        plt.savefig(savepath)
    if show:
        plt.show()

    return


def make_pdf(bins: Annotated[str, typer.Argument(help="Input bins")],
             res: Annotated[str, typer.Argument(help="results files")],
             bin_size: Annotated[int, typer.Argument()],
             x_max: Annotated[int, typer.Argument()],
             x_min: Annotated[int, typer.Argument()],
             zero_center: Annotated[bool, typer.Argument()]):

    return


if __name__ == "__main__":

    banner = text2art("Ripkit", "random")
    console.print(banner, highlight=False)
    app()
