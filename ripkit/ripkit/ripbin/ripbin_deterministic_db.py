import hashlib
import inspect
import json
import shutil
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Generator, Union

import numpy as np
import pandas as pd

from .analyzer_types import (AnalysisType, Compiler, Coptimization, FileType,
                             GoOptimization, ProgLang, RustcOptimization)
from .binary_analyzer import get_functions
from .ripbin_exceptions import (AnalysisExistsError, RipbinAnalysisError,
                                RipbinDbError, RipbinRegistryError)

# One file is going to be a dataclass
# the name of the file

# Every version of a binary file will recieve its own
# directory. The name of the directory is going to be the
# file name and a hash of the file

# Inside the directory will be the binary file, a file that contains
# all the information about the compilation of the binay file
# metadata of the package
# and any of the analysis array files that were saved

# It's unrealistic to include the flags used to compile the
# binaries because of the extremely large number of falgs and
# flag combinations

# exa_<hash>
# | exa_binay
# | bin_info
# | analysis...

# I'd like to have a register file that keeps track of all of this
# to make gathering binaries faster, but then I have to
# worry about keeping the two insync


DB_PATH = Path("~/.ripbin/").expanduser().resolve()
RIPBIN_BINS = DB_PATH.joinpath("ripped_bins")


@dataclass
class RustFileBundle:
    binary_name: str
    binary_hash: str
    target: str
    optimization: str
    crate_name: str
    flag_list: str
    compile_command: str


@dataclass
class RustBundleMetaData:
    rustup_toolchain: str
    rustc_target: str
    pkg_url: str
    pkg_version: str


def ripbin_init() -> None:
    """
    Init the ripbin db

    Default path is '~/.ripbin/'
    """

    # Guard for case where db exists
    if DB_PATH.exists():
        raise RipbinDbError("~/.ripbin exists")

    # Make the db
    DB_PATH.mkdir()

    # Make the ripped bins path
    ripped_bins_store = DB_PATH.joinpath("ripped_bins")
    ripped_bins_store.mkdir()

    # Now I have
    #
    #  ~/.ripbin
    #       | ripped_bins
    #
    # :D
    return


def calculate_md5(file_path, buffer_size=8192):
    """
    Get the hash of a file. This is helpful for storing binaries of the same
    names that were compiled with different flags / for different OSs
    """

    md5_hash = hashlib.md5()

    # Open, read, and take hash of file iterating over the buffers until
    # there's no more
    with open(file_path, "rb") as file:
        buffer = file.read(buffer_size)
        while buffer:
            md5_hash.update(buffer)
            buffer = file.read(buffer_size)

    # Return the digest
    return md5_hash.hexdigest()


def stash_bin(
    bin_path: Path, file_info: RustFileBundle, overwrite_existing: bool = False
):

    # Calc the hash for the file
    binHash = calculate_md5(bin_path)

    # See if the hash is present in any other pkg directory name
    common_binary_hash = [x for x in RIPBIN_BINS.iterdir() if binHash in x.name]

    matches = [
        x for x in common_binary_hash if f"opt_{file_info.optimization}" in x.name
    ]

    # if common_analysis.empty:
    if common_binary_hash == []:
        pkg_path = RIPBIN_BINS.joinpath(f"{bin_path.name}_{str(binHash)}")
    else:
        pkg_path = RIPBIN_BINS.joinpath(
            f"{bin_path.name}_{str(binHash)}_opt_{file_info.optimization}"
        )

    if matches != []:
        if not overwrite_existing:
            print(f"Not overridding bin {bin_path.name} with info{file_info}")
            print(f"Bin has common hash: {common_binary_hash}")
            print(f"Would be path: {pkg_path}")
            return
    else:
        # Need to make a pkg_dir for this binary
        pkg_path.mkdir()

    # Path for the info file
    info_path = pkg_path.joinpath("info.json")

    # Save the info to file
    with open(info_path.resolve(), "w") as json_file:
        json.dump(file_info.__dict__, json_file, indent=4)

    # Copy the binary
    bin_file = pkg_path.joinpath(bin_path.name).resolve()
    shutil.copy(bin_path, bin_file)
    return


def save_analysis(
    bin_path: Path,
    analysis_data: Union[
        pd.DataFrame, np.ndarray, Generator[np.ndarray, None, None], Path
    ],
    analysis_type: AnalysisType,
    file_info: RustFileBundle,
    save_bin: bool = True,
    overwrite_existing: bool = True,
):

    # Calc the hash for the file
    binHash = calculate_md5(bin_path)

    # See if the hash is present in any other pkg directory name
    common_binary_hash = [x for x in RIPBIN_BINS.iterdir() if binHash in x.name]

    # if common_analysis.empty:
    pkg_path = RIPBIN_BINS.joinpath(f"{bin_path.name}_{str(binHash)}")

    if common_binary_hash != []:
        if not overwrite_existing:
            # print("Existing analysis, without overwrite_existing")
            # print(f"Common binary hashes: {common_binary_hash}")
            raise Exception
    else:
        # Need to make a pkg_dir for this binary
        pkg_path.mkdir()

    # Path for the info file
    info_path = pkg_path.joinpath("info.json")
    analysis_file = pkg_path.joinpath(f"{analysis_type.value}.npz")

    # Handle the different instances of analysis_data
    if isinstance(analysis_data, pd.DataFrame):
        analysis_data = analysis_data.to_numpy()
    elif isinstance(analysis_data, np.ndarray):
        # Save numpy analysis_data to npz
        analysis_data = analysis_data
    elif inspect.isgenerator(analysis_data):
        # Load the lines from generator into numpy array
        analysis_data = np.array(list(analysis_data))
    else:
        raise TypeError("Data is of unknown type")

    try:
        # Save the analysis to file
        np.savez_compressed(analysis_file, data=analysis_data)
        # Save the info to file
        with open(info_path.resolve(), "w") as json_file:
            json.dump(file_info.__dict__, json_file, indent=4)
    except Exception as e:
        st = f"Np save error: {e}"
        raise Exception(st)

    # Copy the binary
    if save_bin:
        bin_file = pkg_path.joinpath(bin_path.name).resolve()
        shutil.copy(bin_path, bin_file)
    return


def save_lief_ground_truth(bin_path: Path):
    """
    Save a file in the db of the lief ground truth
    """

    if not bin_path.exists():
        raise Exception()

    # Get the pkg_path
    pkg_path = bin_path.parent

    # Make the exported file path
    func_list_path = pkg_path / "lief_ground_truth.txt"

    functions = get_functions(bin_path)

    func_start_addrs = {x.addr: (x.name, x.size) for x in functions}

    with open(func_list_path, "w") as f:
        for addr, info in func_start_addrs.items():
            f.write(f"{hex(addr)}: {info[0]}\n")
    return
