import json
import math
import multiprocessing
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from multiprocessing import Pool
from pathlib import Path

import lief
import typer
from alive_progress import alive_bar, alive_it

#from .cli_utils import get_enum_type, opt_lvl_callback
from cli_utils import get_enum_type, opt_lvl_callback

from rich import print
from rich.console import Console
from rich.progress import track
from typing_extensions import Annotated

from ripkit.cargo_picky import (CrateBuildException, LocalCratesIO,
                                RustcOptimization, RustcStripFlags,
                                RustcTarget, build_crate, gen_cargo_build_cmd,
                                gen_cross_build_cmd, get_target_productions,
                                is_executable)
from ripkit.ripbin import (CompileTimeAttacks, RustFileBundle, calculate_md5,
                           ripbin_init, stash_bin)

console = Console()
app = typer.Typer(pretty_exceptions_show_locals=False)

CPU_COUNT = multiprocessing.cpu_count()
CPU_COUNT_75 = math.floor(CPU_COUNT * 0.75)


def build_helper(args):
    crate = args[0]
    opt = args[1]
    target = args[2]
    overwrite_existing = args[3]
    verbose = args[4]
    podman = args[5]
    attack = args[6]

    strip = RustcStripFlags.NOSTRIP
    use_cargo = False

    # Build the crate
    try:
        build_crate(crate, opt, target, strip, use_cargo, podman, attack)
    except CrateBuildException as e:
        print(f"[bold red][FAILED][/bold red] Crate {crate} failed to build")
        return

    print(f"[bold yellow][BUILT][/bold yellow] Crate {crate} built")

    # Need this to get the build command
    crate_path = Path(LocalCratesIO.CRATES_DIR.value).resolve().joinpath(crate)

    # Need the build command for the bundle info, this is NOT used
    # to actually execute a build command
    if use_cargo:
        build_cmd = gen_cargo_build_cmd(
            crate_path, target, strip, opt
        )
    else:
        build_cmd = gen_cross_build_cmd(crate_path, target, strip, opt, podman, attack)

    # Get files of interest from the crate at the target <target>
    files_of_interest = [
        x for x in get_target_productions(crate, target) if is_executable(x)
    ]

    if files_of_interest == []:
        print(
            f"[bold yellow][BORING][/bold yellow] Crate {crate} had no executable production"
        )
        if verbose:
            print(
                f" [bold yellow][VERBOSE][/bold yellow] Crate {crate} cmd: {build_cmd}"
            )
        return 99


    # The only file in the list should be the binary
    binary = files_of_interest[0]

    # Create the file info
    binHash = calculate_md5(binary)

    filetype = ""

    # Create the file info
    info = RustFileBundle(
        binary.name, binHash, target.value, opt.value, binary.name, "", build_cmd
    )

    try:
        # Save analysis
        stash_bin(binary, info, overwrite_existing=overwrite_existing)
        print(f"[bold green][SUCCESS][/bold green]Crate {crate} has been stashed")
    except Exception as e:
        print(f"Exception {e} in crate {crate}")
    return


def build_and_stash(
    crate,
    opt,
    target,
    attack="",
    strip=RustcStripFlags.NOSTRIP,
    use_cargo=False,
    overwrite_existing=False,
):
    """
    Build and stash create in ripbin db
    """

    # Build the crate
    build_crate(crate, opt, target, strip, use_cargo, attack=attack)

    # Need this to get the build command
    crate_path = Path(LocalCratesIO.CRATES_DIR.value).resolve().joinpath(crate)

    # Need the build command for the bundle info, this is NOT used
    # to actually execute a build command
    if use_cargo:
        build_cmd = gen_cargo_build_cmd(crate_path, target, strip, opt)
    else:
        build_cmd = gen_cross_build_cmd(crate_path, target, strip, opt, attack=attack)

    # Get files of interest from the crate at the target <target>
    files_of_interest = [
        x for x in get_target_productions(crate, target) if is_executable(x)
    ]

    if files_of_interest == []:
        print(
            f"[bold yellow][BORING][/bold yellow] Crate {crate} had no executable production"
        )
        # TODO: in the crates_io cache which cloned pkgs don't build any
        #       files of interest so they are not rebuilt
        return 99

    # The only file in the list should be the binary
    binary = files_of_interest[0]

    # Create the file info
    binHash = calculate_md5(binary)

    # Create the file info
    info = RustFileBundle(
        binary.name,
        binHash,
        target.value,
        opt.value,
        binary.name,
        "",
        build_cmd,
    )

    try:
        # Save analysis
        stash_bin(binary, info, overwrite_existing)
    except Exception as e:
        print(f"Exception {e} in crate {crate}")

    return

def load_info(inp: Path)-> dict:
    """
    Load the bundle information 
    """
    try:
        with open(inp, "r") as f:
            info = json.load(f)
    except FileNotFoundError:
        print(f"File not found: {inp}")
        info = {}
    except json.JSONDecodeError as e:
        print(f"JSON decoding error: {e}")
        info = {} 
    except Exception as e:
        print(f"An error occurred: {e}")
        info = {}

    return info


    
@dataclass
class BinInfoBundle:
    bin: Path
    info: Path



def load_bins(
    bin_path: Path,
) -> list[BinInfoBundle]:
    """
    Get the binaries from an exported dataset of 

    dataset
    |
    | - binary_hash_name
    | | - bin
    | | - info.json
    """

    bins = []
    #TODO Check for hases
    hashes = []

    for parent in bin_path.expanduser().resolve().iterdir():
        info_file = parent / "info.json"
        info = load_info(info_file)
        if info == {}: 
            continue

        if info['binary_hash'] in hashes:
            continue

        hashes.append(info['binary_hash'])
        bins.append(BinInfoBundle(parent.joinpath(info["binary_name"]).absolute(), info_file.absolute()))
    return bins




def get_bins(
    target: RustcTarget,
    optimization: RustcOptimization,
    bin_path: Path = Path("~/.ripbin/ripped_bins/").expanduser(),
) -> list[BinInfoBundle]:
    """
    Get all binaries of the target
    """

    bins = []
    #TODO Check for hases
    hashes = []

    for parent in bin_path.expanduser().resolve().iterdir():
        info_file = parent / "info.json"
        info = load_info(info_file)
        if info == {}: 
            continue

        #try:
        #    with open(info_file, "r") as f:
        #        info = json.load(f)
        #except FileNotFoundError:
        #    print(f"File not found: {info_file}")
        #    continue
        #except json.JSONDecodeError as e:
        #    print(f"JSON decoding error: {e}")
        #    continue
        #except Exception as e:
        #    print(f"An error occurred: {e}")
        #    continue

        if info['binary_hash'] in hashes:
            continue

        if info["optimization"] in optimization.value and info["target"] in target.value:
            hashes.append(info['binary_hash'])
            bins.append(BinInfoBundle(parent.joinpath(info["binary_name"]).absolute(), info_file.absolute()))

    return bins


@app.command()
def print_rust_targets():
    """
    Print the rust targets
    """
    cmd = shlex.split("rustc --print target-list")
    output = subprocess.run(cmd, capture_output=True, universal_newlines=True)
    res = output.stdout
    print(res)
    return


@app.command()
def init():
    '''
    Initialize the ripbin db
    '''

    ripbin_init()
    return

@app.command()
def print_compile_time_attacks():
    """
    Print a list of supported compile time attacks
    """
    print("Supported compile time attacks:")
    for member in CompileTimeAttacks:
        print(f"{member.name}: \"{member.value}\"")
    print("")
    return

@app.command()
def build_stash_all(
    opt_lvl: Annotated[
        list[str], typer.Argument(help="The optimization level to compile for")
    ],
    target: Annotated[str, typer.Argument(help="crate target")],
    num_workers: Annotated[int, typer.Option(help="number of workers")] = CPU_COUNT_75,
    overwrite_existing: Annotated[
        bool, typer.Option(help="Overwrite existing binaries in the db")
    ] = False,
    verbose: Annotated[bool, typer.Option(help="Print verbose info")] = False,
    force_podman: Annotated[
        bool, typer.Option(help="Force the usage of podman for the Cross engine")
    ] = True,
    compile_time_attack: Annotated[str, typer.Option(help="Compile time attack(s) to use. For multiple attack types, format as a space "
                                                "separated list enclosed in double quotes Ex: \"attack_type1 attack_type2\" For a "
                                                "list of available attacks, see the list-compile-time-attacks command. Currently, compile time "
                                                "attacks through ripbin are only supported using the cross compilation project")] = "",
):
    """
    Build the crates in crates io and stash into ripbin db
    """


    for single_opt_lvl in opt_lvl:
        # Opt lvl call back
        try:
            opt = opt_lvl_callback(single_opt_lvl)
        except Exception as e:
            print(e)
            return

        # Parse compile time attacks given to generate attack string
        attack_str = ""
        if compile_time_attack != "":
            for attack in compile_time_attack.split():
                try:
                    string = CompileTimeAttacks[attack].value
                    attack_str += string
                    attack_str += " "
                except KeyError:
                    print(f"Invalid attack type: {attack}")
                    return

        target_enum = get_enum_type(RustcTarget, target)

        # list of crate current installed that can be built
        crates_to_build = [
            x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir() if x.is_dir()
        ]

        # If we don't have to build all the crates, find the crates that
        # are already built with the specified optimization and arch
        # and remove that from the list of installed crates
        for parent in Path("~/.ripbin/ripped_bins/").expanduser().resolve().iterdir():
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

            if (
                info["optimization"].upper() in opt_lvl
                and info["target"].upper() in target_enum.value.upper()
            ):
                # Remove this file from the installed crates list
                if (x := info["binary_name"]) in crates_to_build:
                    crates_to_build.remove(x)

        # Build and analyze each crate
        args = []
        for crate in crates_to_build:
            args.append(
                (crate, opt, target_enum, overwrite_existing, verbose, force_podman, attack_str)
            )
        print(f"Building {len(args)} crates!")

        with Pool(processes=num_workers) as pool:
            results = pool.map(build_helper, args)

    return


@app.command()
def seq_build_all_and_stash(
    opt_lvl: Annotated[str, typer.Argument(help="opt lvl to compile for")],
    target: Annotated[str, typer.Argument(help="crate target")],
    stop_on_fail: Annotated[
        bool, typer.Option(help="Stop all compilation when one crate fails")
    ] = False,
    compile_time_attack: Annotated[str, typer.Option(help="Compile time attack(s) to use. For multiple attack types, format as a space "
                                                "separated list enclosed in double quotes Ex: \"attack_type1 attack_type2\" For a "
                                                "list of available attacks, see the list-compile-time-attacks command. Currently, compile time "
                                                "attacks through ripbin are only supported using the cross compilation project")] = "",
):
    """
    Sequentially build all the crates found in the local crates_io
    """
    # Opt lvl call back
    try:
        opt = opt_lvl_callback(opt_lvl)
    except Exception as e:
        print(e)
        return
    
    # Parse compile time attacks given to generate attack string
    attack_str = ""
    if compile_time_attack != "":
        for attack in compile_time_attack.split():
            try:
                string = CompileTimeAttacks[attack].value
                attack_str += string
                attack_str += " "
            except KeyError:
                print(f"Invalid attack type: {attack}")
                return

    target_enum = get_enum_type(RustcTarget, target)

    # list of crate current installed that can be built
    crates_to_build = [
        x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir() if x.is_dir()
    ]

    # If we don't have to build all the crates, find the crates that
    # are already built with the specified optimization and arch
    # and remove that from the list of installed crates
    for parent in Path("~/.ripbin/ripped_bins/").expanduser().resolve().iterdir():
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

        if (
            info["optimization"].upper() in opt_lvl
            and info["target"].upper() in target_enum.value.upper()
        ):
            # Remove this file from the installed crates list
            if (x := info["binary_name"]) in crates_to_build:
                crates_to_build.remove(x)

    success = 0
    # Build and analyze each crate
    #for crate in alive_it(crates_to_build):
    for crate in crates_to_build:
        res = 0
        try:
            res = build_and_stash(crate, opt, target_enum, attack_str)
        except CrateBuildException as e:
            print(f"[bold red]Failed to build crate {crate}:: {e}[/bold red]")
            continue
        if res != 99:
            success += 1
            print(f"[bold green][SUCCESS][/bold green] crate {crate}")

    print(f"[bold green][SUCCESS] {success}")
    print(f"[bold red][FAILED] {len(crates_to_build)-success}")
    return


@app.command()
def export_dataset(
    output: Annotated[Path, typer.Argument(help="Directory to save binaries to")],
    target: Annotated[str, typer.Argument(help="Compilation Target")],
    opt: Annotated[list[str], typer.Argument(help="Opt Lvl of bin")],
    min_text_bytes: Annotated[
        int, typer.Option(help="Minimum number of bytes in a files .text section")
    ] = 0,
    seperate_bins: Annotated[bool, typer.Option(help="Binaries must be avilable in all optimiztation levels")]=False,
    
):
    """
    Export a dataset from the ripkit db
    """

    if output.exists():
        if output.is_file():
            print("The output directory already exists, please remove it:!")
            return
    else:
        output.mkdir()


    for opt_lvl in opt:

        # Get a dictionary of all the binaries that are in the ripbin db
        target_enum = get_enum_type(RustcTarget, target)
        opt_enum = opt_lvl_callback(opt_lvl)
        opt_output = output.joinpath(opt_enum.value)
        opt_output.mkdir()


        #TODO: check that the hash is not 
        bins = get_bins(target_enum, opt_enum)

        cur_good_bins = []
        for bundle in track(bins, description=f"Checking  bin sizes..."):
            bin = bundle.bin

            # Parse the binary with lief
            parsed_bin = lief.parse(str(bin.resolve()))

            # Get the text section and the bytes themselse
            text_section = parsed_bin.get_section(".text")
            num_text_bytes = len(text_section.content)

            # Append a good binary to the list of current good
            # binaries
            if num_text_bytes >= min_text_bytes:
                cur_good_bins.append(bin)

        # Export the bundle, which will be the binary and it's compilation
        # information. Default will save the bundle together. 
        # 
        # If we wish to divide the bins and bundle info then split 
        if seperate_bins:
            binary_output = opt_output.joinpath("bins")
            binary_output.mkdir()
            info_output = opt_output.joinpath("info")
            info_output.mkdir()

            for bundle in track(cur_good_bins, description=f"Copying..."):

                #NOTICE: This will renamed the binary itself
                bin_name_and_hash = bundle.info.parent.name
                binary_dest_file = binary_output.joinpath(bin_name_and_hash)
                shutil.copy(bundle.bin.resolve(), binary_dest_file.resolve())

                #NOTICE: This will renamed the information file itself
                info_dest_file = info_output.joinpath(bin_name_and_hash+".json")
                shutil.copy(bundle.bin.resolve(), info_dest_file.resolve())
        else:

            for bundle in track(bins, description=f"Copying..."):
                bin_name_and_hash = bundle.info.parent.name
                dest_dir = opt_output.joinpath(bin_name_and_hash)
                dest_dir.mkdir()

                shutil.copy(bundle.bin.resolve(), dest_dir.joinpath(bundle.bin.name).resolve())
                shutil.copy(bundle.info.resolve(), dest_dir.joinpath("info.json").resolve())
    return


if __name__ == "__main__":
    app()
