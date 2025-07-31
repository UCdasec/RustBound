from pathlib import Path 
import itertools
import shutil
import subprocess
import time
import random
import json
from typing import List, Generator
from typing_extensions import Annotated
from fairseq.models.roberta import RobertaModel
import torch
import lief 
import os
from elftools.elf.elffile import ELFFile
from dataclasses import dataclass, asdict
from colorama import Fore, Back, Style
import numpy as np
from alive_progress import alive_it


import sys

sys.path.append("../ripkit/")

from ripkit.ripbin import ( 
    ConfusionMatrix,
    calc_metrics,
    lief_gnd_truth,
)
from ripkit import (
    load_bins,
)
import time
import typer 
from rich.console import Console
from rich.table import Table
from rich.progress import track

console = Console()
console.width = console.width - 10
app = typer.Typer(pretty_exceptions_show_locals=False)

@dataclass 
class FunctionInfo():
    name: str
    addr: int
    addrHex: str
    size: int



def get_elf_functions(path:Path, warn_if_stripped: bool = False)->List[FunctionInfo]:
    """
        Get the functions in an ELF file. 
        NOTICE: elffile seems to ignore functions injected by gcc such as 
        "register_tm...", "deregister_tm...", 
        Therefore those names will be included in the list, but will have 
        a size of 0 
    """

    with open(path, 'rb') as f:
        elf = ELFFile(f)

        # Get the symbol table
        symbol_table = elf.get_section_by_name('.symtab')

        # Get the .text section
        text_section = elf.get_section_by_name('.text')

        if symbol_table is None:
            raise Exception(f"No symbol table in file {path}")
        elif text_section is None:
            raise Exception(f"No .text section in file {path}")

        # Create a list of functionInfo objects... symbol_table will give a 
        # list of symbols, grab the function sybols and get there name, 
        # their 'st_value' which is start addr and size 
        functionInfo = [FunctionInfo(x.name, x['st_value'], f"0x{x['st_value']:x}",x['st_size']) 
            for x in symbol_table.iter_symbols() if x['st_info']['type'] == 'STT_FUNC']

        if functionInfo == [] and warn_if_stripped:
            # TODO: This warning wont make sense when someone is analyzing an 
            #   file without knowing if its stripped or not, maybe take out?
            warnings.warn("There is no function info, and expect stripped is off")

    return functionInfo


def get_hex_str(inp):
    hex_str = f"{str(hex(inp))[2:]}"
    if len(hex_str) == 1:
        hex_str= "0" + hex_str
    return hex_str


# Load the binary and 
def gen_data_raw_func_bound(path: Path, output: Path):
    #TODO: Use lief to get the .text section of the binary and but here 
    #      (... or is it use lief to get every byte from the file and put here?...)

    functions = get_elf_functions(path)

    func_start_addrs = {x.addr : (x.name, x.size) for x in functions}

    func_end_addrs = {} 
    for start, info in func_start_addrs.items():
        # NOTE: THIS IS IMPORTANT
        # Ignoring functions that are of zero length
        if info[1] > 0:
            func_end_addrs[start+info[1]] = info[0]


    parsed_bin = lief.parse(str(path.resolve()))
    text_section = parsed_bin.get_section(".text")

    # Get the bytes in the .text section
    text_bytes = text_section.content

    # Get the base address of the loaded binary
    base_address = parsed_bin.imagebase

    with open(output, 'w') as out:
        for i, byte in enumerate(text_bytes):

            # Starting at the text section, the address of each byte is 
            # the base_address + the text_section's virtual address 
            # plus the number of bytes we've gone over 
            address = base_address + text_section.virtual_address + i
            func_start = True if address in func_start_addrs.keys() else False
            func_end = True if address in func_end_addrs.keys() else False
            func_middle = True if not func_start and not func_end else False

            if func_start:
                lbl = 'F'
            elif func_end:
                lbl= 'R'
            else:
                lbl = '-'

            hex_str = get_hex_str(address)
            #line = f"{hex_str} {lbl}"
            line = f"{byte} {lbl}"

            #print(line)
            out.write(line+'\n')

    print("WARNING THIS ONLY HAS THE .TEXT section")
    return

def get_start_and_end_addrs(bin):

    functions = get_elf_functions(bin)

    func_start_addrs = {x.addr : (x.name, x.size) for x in functions}

    func_end_addrs = {} 
    for start, info in func_start_addrs.items():
        # NOTE: THIS IS IMPORTANT
        # Ignoring functions that are of zero length
        if info[1] > 0:
            func_end_addrs[start+info[1]] = info[0]

    return func_start_addrs, func_end_addrs



def load_bin_for_xda_inp(path: Path):
    '''
    Generate npy matrix with vectors:
        <isStart, isMiddle, isEnd, byte>
    '''
    functions = get_elf_functions(path)

    func_start_addrs = {x.addr : (x.name, x.size) for x in functions}

    func_end_addrs = {} 
    for start, info in func_start_addrs.items():
        # NOTE: THIS IS IMPORTANT
        # Ignoring functions that are of zero length
        if info[1] > 0:
            func_end_addrs[start+info[1]] = info[0]


    parsed_bin = lief.parse(str(path.resolve()))
    text_section = parsed_bin.get_section(".text")

    # Get the bytes in the .text section
    text_bytes = text_section.content

    # Get the base address of the loaded binary
    base_address = parsed_bin.imagebase

    for i, byte in enumerate(text_bytes):
        address = base_address + text_section.virtual_address + i
        if address in func_start_addrs.keys():
            lbl = 'S'
        elif address in func_end_addrs.keys():
            lbl = 'E'
        else:
            lbl = 'N'
        yield [str(byte), lbl]

def xda_predict_raw(bin: Path, model): #-> Generator[tuple[np.ndarray,float], None, None]:
    '''
    Predict all the bytes in the .text section of the binary model
    '''
    # Parse the bin 
    parsed_bin = lief.parse(str(bin.resolve()))

    #TODO: Get the text section contents
    text_bytes = parsed_bin.get_section(".text").content

    #TODO: Make sure contents are bytes wihtout 0x
    text_bytes = [f"{get_hex_str(x)}" for x in text_bytes] 

    STEP = 512
    total_time = 0
    total_res = np.zeros((int(len(text_bytes)/STEP)+1 , 512,3))
    loop_counter = 0

    #for i in alive_it(range(0, len(text_bytes)-STEP-1, STEP)):
    for i in range(0, len(text_bytes)-STEP-1, STEP):
        loop_counter+=1

        # Get the total chunnk, and the labeled chunk 
        token_chunk = text_bytes[i:i+STEP]

        # Make a sting of 512 tokens
        encoded_tokens = model.encode(' '.join(token_chunk))

        # Get the prediction
        start = time.time()
        logprobs = model.predict('funcbound', encoded_tokens)
        total_time += time.time() - start

        total_res[loop_counter] = logprobs.detach().cpu().numpy()
    return total_res,total_time

def xda_predict(inp_file: Path, model, out_file:Path = None):

    token_gen = load_bin_for_xda_inp(inp_file)
    token_list = list(token_gen)


    # inp and lbl
    token_raw = [x[0] for x in token_list]
    token_inp = []
    for x in token_raw:
        repr =  str(hex(int(x))[2:])
        if len(repr) == 1:
            repr = '0' + repr
        token_inp.append(repr)
    token_lbl = [x[1] for x in token_list]

    STEP = 512
    START = 1 
    END = 2 
    NEITHER = 0
    true_pos = 0
    true_neg = 0
    false_pos = 0
    false_neg = 0

    total_time = 0

    # Open the log file so that we can freely write to it
    with open(out_file, 'w') as out_f:
        for i in alive_it(range(0, len(token_inp)-STEP-1, STEP)):

            # Get the total chunnk, and the labeled chunk 
            token_chunk = token_inp[i:i+STEP]
            lbl_chunk = token_lbl[i:i+STEP]

            # Make a sting of 512 tokens
            encoded_tokens = model.encode(' '.join(token_chunk))

            # Get the prediction
            start = time.time()
            logprobs = model.predict('funcbound', encoded_tokens)
            total_time += time.time() - start
            predictions = logprobs.argmax(dim=2).view(-1).data


            # TODO: numpy should be used evenutally for this comparison
            # Iterate over the bytes and the predicted label see if 
            # labels are correct
            for i, (raw_byte, prediction, lbl) in enumerate(
                zip(token_chunk, predictions, lbl_chunk)):

                #TODO: right now I only care about its ability to 
                # label function starts

                # Check for true and false positives
                if prediction == START:
                    if lbl == 'S':
                        true_pos +=1 
                    else:
                        false_pos +=1 
                if prediction == END or prediction == NEITHER:
                    if lbl != 'S' :
                        true_neg +=1 
                    else:
                        false_neg +=1 
                out_f.write(f"{raw_byte} {prediction} {lbl}\n")


    return true_pos, false_pos, true_neg, false_neg, total_time


@app.command()
def unified_gen_training(
    num_pretrain: Annotated[int, typer.Argument()],
    num_finetune: Annotated[int, typer.Argument()],
    num_valid: Annotated[int, typer.Argument()],
    base_path: Annotated[str, typer.Argument()],
    ):
    '''
    For each pretraining dataset used in other experiemnts, pick x binaries.
    For each finetuning dataset used in other expriments, pick y binaries 

    Pretraining requires a minimum of 4 bins for pre training 
    '''

    # Store the bins
    pretrain_dict = {}
    finetune_dict = {}

    # All pretrain, valid,finetune
    pretrain_tot = []
    finetune_tot = []
    valid_tot = []

    base_path = Path(base_path)

    base_saved = Path("unified_sampled_bins")
    base_saved.mkdir()

    for dir in base_path.iterdir():
        pretrain = dir / Path("dataset_pretrain")
        finetune = dir / Path("dataset_finetune")

        pretrain_and_valid = random.sample(list(pretrain.glob('*')), num_pretrain+num_valid)

        pretrain_bins = pretrain_and_valid[0:num_pretrain]
        valid_bins = pretrain_and_valid[-num_valid:]

        for bin in pretrain_bins:
            pretrain_tot.append(bin)
        pretrain_dict[dir] = pretrain_bins

        finetune_bins = random.sample(list(finetune.glob('*')), num_finetune)
        for bin in finetune_bins:
            finetune_tot.append(bin)
        finetune_dict[dir] = finetune_bins

        for bin in valid_bins:
            valid_tot.append(bin)
        finetune_dict[f"VALID_{dir}"] = valid_bins

        # Copy the bins for pretrain, finetune, and pretrain_valid all to one ouputdir
        opt_dir = base_saved / dir.name
        opt_dir.mkdir()

    # so that BiRNN can be trained on the same sample


    print(f"Pretain: {pretrain_tot}")
    print(f"Finetuen: {finetune_tot}")
    generate_data_src_pretrain_all(pretrain_tot, valid_tot)
    generate_data_src_finetune_for_funcbound(finetune_tot)

    return

@app.command()
def cherry_pick_test(
    train_cache: Annotated[Path, typer.Argument()],
    finetune_cache: Annotated[Path, typer.Argument()],
    whole_dataset: Annotated[Path, typer.Argument()],
    output: Annotated[Path, typer.Argument()],
    ):
    """
    Cherry pick binaries from the whole dataset that are not in the 
    train or finetune cache
    """

    # Accumulate the train list 
    train_list = [x.name for x in train_cache.joinpath("train").glob('*')]
    train_list.extend([x.name for x in train_cache.joinpath("valid").glob('*')])

    # Accumulate the finetuning list 
    train_list.extend([x.name for x in finetune_cache.joinpath("train").glob('*')])



    # Accumulate the whole datset 
    # TODO: Expecting the dataset to be in strucute of:
    #  <hash>_<bin_name>_|opt|
    #   | info.json
    #   | <bin_name>
    test_set:list[Path] = []

    duplicate = 0

    # Pop the used data from the dataset
    for path in whole_dataset.glob('*'):
        if path.name not in train_list:
            test_set.append(path)
        else:
            duplicate +=1

    print(f"Found {duplicate} files in the  train and finetune in the whole")
    output.mkdir(exist_ok=True)

    for path in track(test_set, description=f"Saving test dataset to {output}"):
        shutil.copytree(path.absolute(), output.joinpath(path.name))

    return 


#TODO: Force generationg of gen finetune and gen pretrain at the same tiem 
#      So that we don't acciendatally overlap binary selection
@app.command()
def gen_pretrain_data(
    bin_dir: Annotated[Path, typer.Argument()],
    num_train_bins: Annotated[int, typer.Argument()],
    cache_dataset: Annotated[Path, typer.Argument()]=None,
    ):
    """
    Preprocess data for finetuning 
    """

    bins_path = Path(bin_dir)
    if not bins_path.exists():
        print(f"Bin path {bins_path} does not exist")
        return

    # Get the bins... 
    # Need to load the dataset and each bins info for thi
    #bins_list = list(bins_path.rglob('*'))

    bin_bundles = load_bins(bin_dir)

    # Chop down the list 
    sampled_bundles = random.sample(bin_bundles, num_train_bins)

    # Get a list of just the binaries to pass to the generator
    bins = [x.bin for x in sampled_bundles]

    print(f"Caching the datasets at {cache_dataset.absolute()}")
    if cache_dataset is not None:
        if cache_dataset.is_file():
            print(f"the cache dataset path exists but it is a file")
            return 
        elif not cache_dataset.exists(): 
            cache_dataset.mkdir()

        train_out = cache_dataset.joinpath("train")
        train_out.mkdir()

        # Save the bundles
        for bundle in sampled_bundles:
            # Copy the binary and the bundle
            shutil.copytree(bundle.bin.parent, train_out.joinpath(f"{bundle.bin.parent.name}"))


    generate_data_src_finetune_for_funcbound(bins)
    return 



#TODO: Force generationg of gen finetune and gen pretrain at the same tiem 
#      So that we don't acciendatally overlap binary selection
@app.command()
def gen_finetune_data(
    bin_dir: Annotated[Path, typer.Argument()],
    num_train_bins: Annotated[int, typer.Argument()],
    cache_dataset: Annotated[Path, typer.Argument()]=None,
    ):
    """
    Preprocess data for finetuning 
    """

    bins_path = Path(bin_dir)
    if not bins_path.exists():
        print(f"Bin path {bins_path} does not exist")
        return

    # Get the bins... 
    # Need to load the dataset and each bins info for thi
    #bins_list = list(bins_path.rglob('*'))

    bin_bundles = load_bins(bin_dir)

    # Chop down the list 
    sampled_bundles = random.sample(bin_bundles, num_train_bins)

    # Get a list of just the binaries to pass to the generator
    bins = [x.bin for x in sampled_bundles]

    print(f"Caching the datasets at {cache_dataset.absolute()}")
    if cache_dataset is not None:
        if cache_dataset.is_file():
            print(f"the cache dataset path exists but it is a file")
            return 
        elif not cache_dataset.exists(): 
            cache_dataset.mkdir()

        train_out = cache_dataset.joinpath("train")
        train_out.mkdir()

        # Save the bundles
        for bundle in sampled_bundles:
            # Copy the binary and the bundle
            shutil.copytree(bundle.bin.parent, train_out.joinpath(f"{bundle.bin.parent.name}"))


    generate_data_src_finetune_for_funcbound(bins)
    return 


@app.command()
def gen_pre_fine(
        bin_dir: Annotated[Path, typer.Argument()],
):
    """
    Loads the bins from gen_data_splits and remakes the 
    data-src
    """

    # train bins 
    train_dir = bin_dir.joinpath(f"{bin_dir.name}_train/train")
    assert train_dir.exists()
    train_bins_list = load_bins(train_dir)

    # valid bins 
    valid_dir = bin_dir.joinpath(f"{bin_dir.name}_train/valid")
    assert valid_dir.exists()
    valid_bins_list = load_bins(valid_dir)

    # fine bins
    fine_dir = bin_dir.joinpath(f"{bin_dir.name}_fine/")
    assert fine_dir.exists()
    fine_bins_list = load_bins(fine_dir)

    train_bins = [x.bin for x in train_bins_list]
    valid_bins = [x.bin for x in valid_bins_list]

    # Make the list for finetuning
    finetune_bins = [x.bin for x in fine_bins_list]

    generate_data_src_pretrain_all(train_bins, valid_bins)
    generate_data_src_finetune_for_funcbound(finetune_bins)

    return



@app.command()
def gen_pretrain_and_finetune(
        bin_dir: Annotated[Path, typer.Argument()],
        num_train_bins: Annotated[int, typer.Argument()],
        num_validation_bins: Annotated[int, typer.Argument()],
        num_finetune_bins: Annotated[int, typer.Argument()],
        train_out: Annotated[Path, typer.Argument()],
        finetune_out: Annotated[Path, typer.Argument()],
        test_out: Annotated[Path, typer.Argument()],
    ):
    """
    Generate the data splits for: 
        pretraining
        finetuning 
        testing

    The bin dir should be a directory of the bins (not the bundles used in 
    other functions)
    """

    if not bin_dir.exists():
        print(f"Bin path {bin_dir} does not exist")
        return


    # Load all the binaries
    bins_list = list(bin_dir.glob('*'))

    # Sample for training 
    training_bins = random.sample(bins_list, num_train_bins+num_validation_bins)

    finetune_bundle = []

    # Sample for finetuning
    while len(finetune_bundle) < num_finetune_bins:
        bundle = random.sample(bins_list, 1)[0]
        if bundle not in training_bins and bundle not in finetune_bundle:
            finetune_bundle.append(bundle)


    # Get random valudation bins, default to 4 of them 
    valid_bundle = random.sample(training_bins, num_validation_bins)
    train_bundle = [x for x in training_bins if x not in valid_bundle]

    # Get a list of just the binaries to pass to the generator
    valid_bins = [x.bin for x in valid_bundle]
    train_bins = [x.bin for x in train_bundle]

    # Make the list for finetuning
    finetune_bins = [x.bin for x in finetune_bundle]

    # Get the remained of the dataset 
    test_bins = [x for x in bins_list if x not in training_bins and x not in finetune_bundle]

    # Save the training data
    train_out.mkdir(exist_ok=True)
    train_base = train_out
    train_out = train_base.joinpath("train")
    train_out.mkdir()
    valid_out = train_base.joinpath("valid")
    valid_out.mkdir()


    # Save the bundles
    for bundle in train_bundle:
        # Copy the binary and the bundle
        shutil.copytree(bundle.bin.parent, train_out.joinpath(f"{bundle.bin.parent.name}"))

    # Save the bundles
    for bundle in valid_bundle:
        # Copy the binary and the bundle
        shutil.copytree(bundle.bin.parent, valid_out.joinpath(f"{bundle.bin.parent.name}"))

    # Save the finetuning data
    finetune_out.mkdir(exist_ok=True)
    for bundle in finetune_bundle:
        # Copy the binary and the bundle
        shutil.copytree(bundle.bin.parent, finetune_out.joinpath(f"{bundle.bin.parent.name}"))

    # Save the test out 
    test_out.mkdir(exist_ok=True)
    for bundle in test_bins:
        # Copy the binary and the bundle
        shutil.copytree(bundle.bin.parent, test_out.joinpath(f"{bundle.bin.parent.name}"))

    generate_data_src_pretrain_all(train_bins, valid_bins)
    generate_data_src_finetune_for_funcbound(finetune_bins)

    return




@app.command()
def gen_data_splits(
        bin_dir: Annotated[Path, typer.Argument()],
        num_train_bins: Annotated[int, typer.Argument()],
        num_validation_bins: Annotated[int, typer.Argument()],
        num_finetune_bins: Annotated[int, typer.Argument()],
        train_out: Annotated[Path, typer.Argument()],
        finetune_out: Annotated[Path, typer.Argument()],
        test_out: Annotated[Path, typer.Argument()],
    ):
    """
    Generate the data splits for: 
        pretraining
        finetuning 
        testing
    """

    if not bin_dir.exists():
        print(f"Bin path {bin_dir} does not exist")
        return


    # Load all the binaries
    bins_list = load_bins(bin_dir)

    # Sample for training 
    training_bins = random.sample(bins_list, num_train_bins+num_validation_bins)

    finetune_bundle = []

    # Sample for finetuning
    while len(finetune_bundle) < num_finetune_bins:
        bundle = random.sample(bins_list, 1)[0]
        if bundle not in training_bins and bundle not in finetune_bundle:
            finetune_bundle.append(bundle)


    # Get random valudation bins, default to 4 of them 
    valid_bundle = random.sample(training_bins, num_validation_bins)
    train_bundle = [x for x in training_bins if x not in valid_bundle]

    # Get a list of just the binaries to pass to the generator
    valid_bins = [x.bin for x in valid_bundle]
    train_bins = [x.bin for x in train_bundle]

    # Make the list for finetuning
    finetune_bins = [x.bin for x in finetune_bundle]

    # Get the remained of the dataset 
    test_bins = [x for x in bins_list if x not in training_bins and x not in finetune_bundle]

    # Save the training data
    train_out.mkdir(exist_ok=True)
    train_base = train_out
    train_out = train_base.joinpath("train")
    train_out.mkdir()
    valid_out = train_base.joinpath("valid")
    valid_out.mkdir()


    # Save the bundles
    for bundle in train_bundle:
        # Copy the binary and the bundle
        shutil.copytree(bundle.bin.parent, train_out.joinpath(f"{bundle.bin.parent.name}"))

    # Save the bundles
    for bundle in valid_bundle:
        # Copy the binary and the bundle
        shutil.copytree(bundle.bin.parent, valid_out.joinpath(f"{bundle.bin.parent.name}"))

    # Save the finetuning data
    finetune_out.mkdir(exist_ok=True)
    for bundle in finetune_bundle:
        # Copy the binary and the bundle
        shutil.copytree(bundle.bin.parent, finetune_out.joinpath(f"{bundle.bin.parent.name}"))

    # Save the test out 
    test_out.mkdir(exist_ok=True)
    for bundle in test_bins:
        # Copy the binary and the bundle
        shutil.copytree(bundle.bin.parent, test_out.joinpath(f"{bundle.bin.parent.name}"))

    generate_data_src_pretrain_all(train_bins, valid_bins)
    generate_data_src_finetune_for_funcbound(finetune_bins)

    return

def generate_data_src_pretrain_all(train_bins, validation_bins):
    '''
    For pretraining on our own data, concatenate all bytes from 
    all binaries and delimit by a newline so that each line does 
    not exceed what the model expects.

    What the model expects by default seems to be 512 so Im going to 
    follow that convention

    and 4 binaries were used for validation in valid.in

    No label, just bytes

    data-src/pretrain-all/train.in
    data-src/pretrain-all/valid.in
    '''

    train_path = Path("data-src/pretrain_all/train.in")
    valid_path = Path("data-src/pretrain_all/valid.in")

    if train_path.exists():
        train_path.unlink()
    if not train_path.parent.exists():
        train_path.parent.mkdir()

    if valid_path.exists():
        valid_path.unlink()
    if not valid_path.parent.exists():
        valid_path.parent.mkdir()

    train_files = train_bins
    valid_files = validation_bins

    with open(train_path, 'w') as f:
        for file in train_files:
            # Parse the bin 
            parsed_bin = lief.parse(str(file.resolve()))

            #TODO: Get the text section contents
            text_bytes = parsed_bin.get_section(".text").content

            #TODO: Make sure contents are bytes wihtout 0x
            text_bytes = [f"{get_hex_str(x)}" for x in text_bytes] 

            #TODO: Write chunks of 512 to the file 
            for i in range(0,len(text_bytes)-512-1, 512):
                f.write(" ".join(text_bytes[i:i+512]) + "\n")

    with open(valid_path, 'w') as f:
        for file in valid_files:
            # Parse the bin 
            parsed_bin = lief.parse(str(file.resolve()))

            #TODO: Get the text section contents
            text_bytes = parsed_bin.get_section(".text").content

            #TODO: Make sure contents are bytes wihtout 0x
            text_bytes = [f"{get_hex_str(x)}" for x in text_bytes] 

            #TODO: Write chunks of 512 to the file 
            for i in range(0,len(text_bytes)-512-1, 512):
                f.write(" ".join(text_bytes[i:i+512]) + "\n")
    
    print("Run ./scripts/pretrain/preprocess-pretrain-all.sh to put data in the data-bin/pretrain_all [REQUIRED]")
    return

def generate_data_src_finetune_for_funcbound(list_of_paths):
    '''
    S = Start
    E = End
    N = Neither

    train.data  : bytes from files concatenated
    train.label : labels for each bytes in data 
    '''

    train_data = Path("data-src/funcbound/train.data")
    train_lbl = Path("data-src/funcbound/train.label")

    valid_data = Path("data-src/funcbound/valid.data")
    valid_lbl = Path("data-src/funcbound/valid.label")

    train_files = list_of_paths[:-4]
    valid_files = list_of_paths[-4:]

    with open(train_data, 'w') as f:
        with open(train_lbl, 'w') as lbl_f:
            for file in train_files:


                functions = get_elf_functions(file)

                func_start_addrs = {x.addr : (x.name, x.size) for x in functions}

                func_end_addrs = {} 
                for start, info in func_start_addrs.items():
                    # NOTE: THIS IS IMPORTANT
                    # Ignoring functions that are of zero length
                    if info[1] > 0:
                        func_end_addrs[start+info[1]] = info[0]


                # Parse the bin 
                parsed_bin = lief.parse(str(file.resolve()))

                text_section = parsed_bin.get_section(".text")

                #TODO: Get the text section contents
                text_bytes = text_section.content

                #TODO: Make sure contents are bytes wihtout 0x
                text_bytes = [f"{get_hex_str(x)}" for x in text_bytes] 

                # Get the base address of the loaded binary
                base_address = parsed_bin.imagebase

                #TODO: Write chunks of 512 to the file 
                for i in range(0,len(text_bytes)-512-1, 512):
                    chunk_base_address = base_address + text_section.virtual_address + i
                    #func_start = True if address in func_start_addrs.keys() else False
                    #func_end = True if address in func_end_addrs.keys() else False
                    #func_middle = True if not func_start and not func_end else False

                    lbls = []
                    for lbl_offset in range(512):
                        if chunk_base_address + lbl_offset in func_start_addrs.keys():
                            lbls.append("S")
                        elif chunk_base_address + lbl_offset in func_end_addrs.keys():
                            lbls.append("E")
                        else:
                            lbls.append("N")


                    f.write(" ".join(text_bytes[i:i+512]) + "\n")
                    lbl_f.write(" ".join(lbls) + "\n")


    with open(valid_data, 'w') as f:
        with open(valid_lbl, 'w') as lbl_f:
            for file in valid_files:


                functions = get_elf_functions(file)

                func_start_addrs = {x.addr : (x.name, x.size) for x in functions}

                func_end_addrs = {} 
                for start, info in func_start_addrs.items():
                    # NOTE: THIS IS IMPORTANT
                    # Ignoring functions that are of zero length
                    if info[1] > 0:
                        func_end_addrs[start+info[1]] = info[0]


                # Parse the bin 
                parsed_bin = lief.parse(str(file.resolve()))

                text_section = parsed_bin.get_section(".text")

                #TODO: Get the text section contents
                text_bytes = text_section.content

                #TODO: Make sure contents are bytes wihtout 0x
                text_bytes = [f"{get_hex_str(x)}" for x in text_bytes] 

                # Get the base address of the loaded binary
                base_address = parsed_bin.imagebase

                #TODO: Write chunks of 512 to the file 
                for i in range(0,len(text_bytes)-512-1, 512):
                    chunk_base_address = base_address + text_section.virtual_address + i
                    #func_start = True if address in func_start_addrs.keys() else False
                    #func_end = True if address in func_end_addrs.keys() else False
                    #func_middle = True if not func_start and not func_end else False

                    lbls = []
                    for lbl_offset in range(512):
                        if chunk_base_address + lbl_offset in func_start_addrs.keys():
                            lbls.append("S")
                        elif chunk_base_address + lbl_offset in func_end_addrs.keys():
                            lbls.append("E")
                        else:
                            lbls.append("N")


                    f.write(" ".join(text_bytes[i:i+512]) + "\n")
                    lbl_f.write(" ".join(lbls) + "\n")


    print("Run ./scripts/finetune/preprocess.sh to put data in the data-bin/funcbound [REQUIRED]")
    return 


def xda_experiment(pretrain_bins, finetune_bins, test_bins):


    # In the paper they used whole dataset for pretraining (b/c they had 3)
    #   and 4 binaries were used for validation
    #pretrain_files = []

    # Used 10% of a whole dataset for finetuning 
    #finetune_files = []

    # Used the whole third dataset for testing
    #test_files = []


    # For each binary in pretrain_bins, the contents need to all be concatenated and 
    # put into "data-src/pretain/train.in  generate_data_src_pretrain_all
    generate_data_src_pretrain_all(pretrain_bins)

    # Need to run ./scripts/pretrain/preprocess-pretrain-all.sh to put data in data-bin/pretrain_all
    # Popen.call([ " ./scripts/pretrain/preprocess-pretrain-all.sh])
    # TODO: When does the above process terminate 

    # For each file in finetune_files need to concatenate all bytes, and genarete a train and label file
    generate_data_src_finetune_for_funcbound(finetune_bins)

    # Need to run "Run ./scripts/finetune/preprocess.sh to put data in the data-bin/funcbound [REQUIRED]")
    # Popen.call(["./scripts/finetune/preprocess.sh" ])
    # TODO: When does the above process terminate 

    # For each file in the test file I need to run a test experiemnt

    




    return

def read_saved(path_in):

    # tp, tn, fp, fn
    res = []

    tp = 0
    tn = 0
    fp = 0
    fn = 0

    with open(path_in, 'r') as f:
        for line in f:
            _, prediction, lbl = line.split(" ")
            lbl = lbl.strip()
            prediction = int(prediction.strip())

            if prediction == 1 :
                if lbl == 'S':
                    tp+=1
                else:
                    fp+=1

            elif prediction != 0:
                if lbl != 'S':
                    tn+=1
                else:
                    fn +=1

    return [tp,fp,tn,fn]



#def save_raw_results(binary:Path, out_dir:Path, predictions: np.ndarray, runtime:float)->None:
#    '''
#    Save the results to a npz file and save the time to runtime.txt
#
#    Save path structure
#    out_dir
#    |
#    | binary.name
#    |     |
#    |     | {binary.name_result}.npz
#    |     | runtime.txt
#    '''
#
#    if not out_dir.exists():
#        out_dir.mkdir()
#    elif out_dir.exists() and out_dir.is_file():
#        raise Exception
#
#    # Make the new binary dir
#    result_path = out_dir.joinpath(f"{binary.name}")
#    if result_path.exists():
#        raise Exception
#    result_path.mkdir()
#
#    # Save the data 
#    npz_file = result_path / f"{binary.name}_result.npz"
#    np.savez_compressed(npz_file, predictions)
#
#    # save the runtime
#    runtime_path = result_path / "runtime.txt"
#    with open(runtime_path, 'w') as f:
#        f.write(f"{runtime}")
#
#    return

# TODO: Save results on a per file basis 
def save_results_timed(res, out_file:Path):
    '''
    Save the .text file and a corresponding file with 
    the count(tp), count(tn), count(fp), count(fn), runtime
    '''
        # print(f"TP: {res[0]}")
        # print(f"FP: {res[1]}")
        # print(f"TN: {res[2]}")
        # print(f"FN: {res[3]}")
        # print(f"Runtime {res[4]")

    data = {
        'tp' : res[0],
        'fp' : res[1],
        'tn' : res[2],
        'fn' : res[3], 
        'runtime' : res[4],
    }

    with open(out_file, 'w') as f:
        json.dump(data, f)

    return

@dataclass
class ConfMatrix:
    tp: int
    fp: int
    tn: int
    fn: int

def xda_predict_many(inp_files, model, out_dir, save_results=False, use_saved=True):
    tot_tp = 0
    tot_tn = 0
    tot_fp = 0
    tot_fn = 0

    confusion_matrix = ConfMatrix(0,0,0,0)

    for i, file_to_predict in enumerate(inp_files):
        print(f"File {i} of {len(inp_files)}")
        if not file_to_predict.exists():
            print(f"Bad file {file_to_predict}")
            continue

        # See if the cached result exists 
        saved = out_dir / f"{file_to_predict.name}"
        time_dir = Path(f"{out_dir}_TIMES")

        if not time_dir.exists():
            time_dir.mkdir()
        time_file = time_dir.resolve() / f"{file_to_predict.name}_time"

        not_good_res = False
        if saved.exists():
            res = read_saved(saved)
            if len(res) < 5:
                not_good_res = True

        if not saved.exists() or not_good_res:
            if save_results:
                res = xda_predict(file_to_predict, model, 
                                  saved)
                save_results_timed(res, time_file)
            else:
                res = xda_predict(file_to_predict, model)

        print(f"File {file_to_predict.name} results...")
        print(f"TP: {res[0]}")
        print(f"FP: {res[1]}")
        print(f"TN: {res[2]}")
        print(f"FN: {res[3]}")
        print(f"Runtime: {res[4]}")
        

        confusion_matrix.tp += res[0]
        confusion_matrix.tn += res[1]
        confusion_matrix.fp += res[2]
        confusion_matrix.fn += res[3]

        print("Running totals:")
        print(f"TP: {confusion_matrix.tp}")
        print(f"TN: {confusion_matrix.tn}")
        print(f"FP: {confusion_matrix.fp}")
        print(f"FN: {confusion_matrix.fn}")


    return tot_tp, tot_tn, tot_fp, tot_fn


def gen_strip_file(bin_path:Path):
    '''
    Strip the passed file and return the path of the 
    stripped file
    '''

    # Copy the bin and strip it 
    strip_bin = bin_path.parent / Path(bin_path.name + "_STRIPPED")
    shutil.copy(bin_path, Path(strip_bin))

    try:
        _ = subprocess.check_output(['strip',f'{strip_bin.resolve()}'])
    except subprocess.CalledProcessError as e:
        print("Error running command:", e)
        return Path("")

    return strip_bin

#TODO:  Probably not used 
@app.command()
def read_log(
    bin_dir: Annotated[str, typer.Argument()],
    res_dir: Annotated[str, typer.Argument()],
    ):
    '''
    Read the timed XDA logs 
    '''
    res = {
        'tp' : 0,
        'fp' : 0,
        'tn' : 0,
        'fn' : 0,
        'stripped_size':0,
        'size':0,
    }

    files = []
    for file in Path(res_dir).rglob('*'):
        for bin in Path(bin_dir).rglob('*'):
            # Does not append directories
            if bin.name.lower() == file.name.lower():
                continue
            if bin.name.lower() in file.name.lower():
                files.append((file,bin))
                continue
        #if file.name.lower() in x.name.lower() for x in Path(bin_dir).rglob('*')):
            #files.append(file)

    tot_runtime = 0
    for (file,bin) in files:
        # read as json, get runtime key
        key = 'runtime'
        with open(file, 'r') as f:
            data = json.load(f)
        tot_runtime += data[key]
        res['tp'] += data['tp']
        res['fp'] += data['fp']
        res['tn'] += data['tn']
        res['fp'] += data['fp']

        # Stip the bin, then record the size
        stripped_bin = gen_strip_file(bin)
        res['size'] += bin.stat().st_size
        res['stripped_size'] += stripped_bin.stat().st_size
        stripped_bin.unlink()

    print(res)
    print(f" The total runtime: {tot_runtime} seconds")
    print(f"The BPS: {res['stripped_size'] / tot_runtime}")
    #print(f"


    # Recall = # Correct Pos lbls /  # Ground Trurth Pos lbls
    # Recall = tp / (tp+fn) 
    recall = res['tp'] / (res['tp']+res['fn'])

    # Prec = #pos_lbl / #
    # Prec = tp / (tp+fp)
    prec = res['tp'] / ( res['tp'] + res['fp'])

    # F1 
    f1 = (2*prec*recall)/(prec+recall)

    print(f"Prec: {prec}")
    print(f"Recall: {recall}")
    print(f"F1: {f1}")
    return

def safe_nump_save(data: np.ndarray, npz_file: Path):
    '''
    Read the memory mapped npz file to append the data to it 
    '''
    #npz_open_file= np.load(npz_file, mmap_mode="r")
    #npz_data = npz_open_file[list(npz_open_file.keys())[0]]
    matrix_mmap = np.memmap(npz_file, mode="r+" ),#dtype=npz_data.dtype, shape=npz_data.shape)

    matrix_mmap.resize((matrix_mmap.shape[0] + data.shape[0], matrix_mmap.shape[1]))
    npz_open_file.close()
    return



@app.command()
def raw_test(
    bins: Annotated[Path, typer.Argument()],
    checkpoint_dir: Annotated[Path, typer.Argument()],
    checkpoint: Annotated[str, typer.Argument()],
    result_path: Annotated[Path, typer.Argument()],
    check_for_existing_results: Annotated[bool, typer.Option()]=True,
    bins_are_bundles: Annotated[bool, typer.Option(help="If the directory is not _only_ bins, and has sub dirs with info.json files, set this to true to load only the bins")]=False,
    ):
    '''
    Temp test to see how to save raw predictions in pbnz file
    '''


    if not result_path.exists():
        result_path.mkdir()
    elif result_path.is_file():
        raise Exception

    if not bins.exists():
        print(f"Path {bins} doesn't exist")
        return
    elif bins.is_dir():
        if bins_are_bundles:
            inp_bins = [x.bin for x in load_bins(bins)]
        else:
            inp_bins =  list(bins.rglob('*'))
    else:
        if bins_are_bundles:
            inp_bins = [x.bin for x in load_bins(bins)]
        else:
            inp_bins = [bins]

    # Load our model
    roberta = RobertaModel.from_pretrained(checkpoint_dir, 
                                            checkpoint,
                                            'data-bin/funcbound', 
                                            user_dir='finetune_tasks')
    roberta.cuda()
    roberta.eval()

    for bin_path in alive_it(inp_bins):
        print(f"On bin: {bin_path.name}")

        single_result_path = result_path.joinpath(f"{bin_path.name}")
        if single_result_path.exists() and check_for_existing_results:
            if all( x in [z.name for z in single_result_path.rglob('*')] for x in ["runtime.txt", f"{bin_path.name}_result.npz"]):
                print(f"Skipping {bin_path.name}... already done")
                continue
            else:
                #single_result_path.unlink()
                shutil.rmtree(single_result_path)
        elif single_result_path.exists():
            raise Exception("result file already exists, pass arguments to chose to delete the existing path or skip over this experiemtn")

        # Get the xda res  and save
        #res_generator = xda_predict_raw(bin_path, roberta)
        tot_res, runtime = xda_predict_raw(bin_path, roberta)


        # Check that the dir exists, and is not a file 
        if single_result_path.exists():
            if single_result_path.is_file():
                raise Exception
        elif not single_result_path.exists():
            single_result_path.mkdir()

        # Make the sub directory
        sub_dir = single_result_path.joinpath(bin_path.name)
        if not sub_dir.exists():
            sub_dir.mkdir()
        elif sub_dir.is_file():
            raise Exception("Subdir is a file")

        # Save the compressed matrix
        matrix_saved = sub_dir.joinpath(f"{bin_path.name}_result.npz")
        if matrix_saved.exists():
            raise Exception("Matrix has been saved")
        
        np.savez(matrix_saved, tot_res)
        # For every 10,000 bytes saze it into its own array 
        print("saved")


        # Save the runtime
        runtime_file = sub_dir.joinpath("runtime.txt")
        with open(runtime_file, 'w') as f:
            f.write(f"{runtime}")
    return

def sum_runtimes(results_dir: Path) -> float:
    total_runtime = 0.0
    for file in results_dir.rglob('runtime.txt'):
        try:
            with file.open('r') as f:
                runtime = float(f.read().strip())
                total_runtime += runtime
        except ValueError:
            print(f"Warning: Could not convert the contents of {file} to a float.")
    
    return total_runtime


@app.command()
def read_bounds_raw(
    input_path: Annotated[Path,typer.Argument()],
    bin_path: Annotated[Path, typer.Argument()],
    verbose: Annotated[bool, typer.Option()] = False,
    supress_warn: Annotated[bool, typer.Option()] = False,
    out_dir: Annotated[str, typer.Option()] = "",
    tex_charts: Annotated[Path, typer.Option()] = Path(""),
    bins_are_bundles: Annotated[bool, typer.Option(help="If the directory is not _only_ bins, and has sub dirs with info.json files, set this to true to load only the bins")]=False,
    ):
    '''
    Read the input dir and compute results using the lief module
    '''


    if not input_path.exists(): 
        print(f"Inp dir {input_path} is not a dir")
        return

    if not bin_path.exists():
        print(f"Bin dir {bin_path} is not a dir")
        return

    if bin_path.is_file():
        if bins_are_bundles:
            bins = [x.bin for x in load_bins(bin_path)]
        else:
            bins = [bin_path]
    else:
        if bins_are_bundles:
            bins = [x.bin for x in load_bins(bin_path)]
        else:
            bins = list(bin_path.glob('*'))

    matching_files = {}
    for bin in bins:
        matching = False
        for res_file in input_path.rglob('*'):
            if ".npz" not in res_file.name:
                continue
            if res_file.name.replace("_result.npz","") == bin.name:
                matching_files[bin] = res_file
                matching = True
        if not matching:
            print(f"Never found {bin.name}")


    if len(matching_files.keys()) != len(bins):
        msg = f"Found {len(matching_files.keys())}: {matching_files.keys()}"
        print(f"{matching_files.keys()}")
        print(f"Some bins don't have matching result file")
        raise Exception(msg)


    total_start_conf = ConfusionMatrix(0,0,0,0)
    total_bound_conf = ConfusionMatrix(0,0,0,0)
    total_end_conf = ConfusionMatrix(0,0,0,0)
    total_bytes = 0

    START = 1 
    END = 2 
    for bin in alive_it(list(matching_files.keys())):
        # Init the confusion matrix for this bin
        start_conf = ConfusionMatrix(0,0,0,0)
        bound_conf = ConfusionMatrix(0,0,0,0)
        end_conf = ConfusionMatrix(0,0,0,0)


        # 1  - Ground truth for bin file, this time the matrix will be...
        #           | start addr | end addr | 
        #   where end addr is the address of the final byte that is in the function
        #   end_addr = start_addr + length - 1

        #  0x01  mov 
        #  0x02  pop
        #  0x03  ret
        # start = 1 
        # len = 3
        # end = 3

        gnd_truth = lief_gnd_truth(bin.resolve())
        # NOTICE: IMPORTANT... xda seems to the first byte outside of the function 
        #               as the end of the function 
        lengths_adjusted = gnd_truth.func_lens
        ends = gnd_truth.func_addrs + lengths_adjusted
        gnd_matrix = np.concatenate((gnd_truth.func_addrs.T.reshape(-1,1), 
                                    ends.T.reshape(-1,1)), axis=1)
        # gnd_matrix = np.concatenate((gnd_truth.func_addrs.T.reshape(-1,1), 
        #                            gnd_truth.func_lens.T.reshape(-1,1)), axis=1)

        # 2 - Find the npz with the xda funcs and addrs, chop of functions that 
        #     are out-of-bounds of the lief functions (these are functions that are
        #       likely outside of the .text section)
        xda_funcs = read_xda_npz(matching_files[bin])
        predictions = torch.Tensor(xda_funcs).argmax(dim=2).view(-1).data #.numpy()
        start_indices = np.where(predictions == START)[0]
        end_indices = np.where(predictions == END)[0]

        # 3 - Get the address of the first byte in the .text section and add this
        #     to all the function bound indices
        parsed_bin = lief.parse(str(bin.resolve()))
        text_section_virt_addr = parsed_bin.get_section(".text").virtual_address
        text_section_start = parsed_bin.imagebase + text_section_virt_addr

        xda_starts = start_indices + text_section_start - 512
        xda_ends = end_indices + text_section_start - 512

        # 4 - Compare the two lists
        # Get all the start addrs that are in both, in ida only, in gnd_trush only
        start_conf.tp=len(np.intersect1d(gnd_matrix[:,0], xda_starts))
        start_conf.fp=len(np.setdiff1d( xda_starts, gnd_matrix[:,0] ))
        start_conf.fn=len(np.setdiff1d(gnd_matrix[:,0], xda_starts))

        # 5 - Compare the ends
        end_conf.tp=len(np.intersect1d(gnd_matrix[:,1], xda_ends))
        end_conf.fp=len(np.setdiff1d( xda_ends, gnd_matrix[:,1] ))
        end_conf.fn=len(np.setdiff1d(gnd_matrix[:,1], xda_ends))


        # Create tuple of the starts to the ends 
        #if len(xda_starts) == len(xda_ends):
        #    xda_bounds = np.concatenate((xda_starts.T.reshape(-1,1), xda_ends.T.reshape(-1,1)),axis=1)
        #else:
        # When we don't have the same number of start predictions as we do end predictions, 
        # We have the cases:

        # Case 1: Two or more starts in a row 
        # Case 2: Two or more ends in a row

        # In either case, always take the first predictions
        
        # To achieve this, take the two lists of starts and ends,
        #   | start | end | 
        #   |  ..   | ..  | 
        # 
        # Any convert to a style:
        # 
        #  | Addresses | label | 
        #  |  ..       | start | 
        #  | ..        | end   | 

        # There, I can iterate through the list, and whenever a second start is read 
        # or a second end it read, pop it. 

        # 1. Add a column of all 1s for the start addrs, and a column of all 2s for the end addrs
        all_ones = np.ones((1,len(xda_starts)))
        tmp_starts = np.vstack((xda_starts, all_ones)).T

        all_twos = np.full((1,len(xda_ends)),2)
        tmp_ends = np.vstack((xda_ends, all_twos)).T

        # 2. Vertically stack the start and end columns and sort by adddress
        comb =  np.vstack((tmp_starts, tmp_ends))
        sorted_indices = np.argsort(comb[:, 0])
        bounds = comb[sorted_indices]

        # 3. Filter any occurancce where theres more than 1 start, or end in a row
        # Specifically, the following line..
        #   a. bounds[1:,1] gets the second column excluding the first row
        #   b. bounds[:,1] gets the second column excluding the last row
        #   c. Compare these two 
        #    
        #  1                                     1
        #  2   ->   2  !=   1  ->  True    ->    2
        #  1        1       2      True          1
        #  1        1       1      False

        if bounds.shape[0] == 0:
            xda_bounds = np.array([[]])
        else:
            # Again, keep only indicies that are sequentially the first label of there kind...
            indices_to_keep = np.append(True, bounds[1:, 1] != bounds[:-1, 1])
            filt_sorted_bounds = bounds[indices_to_keep]

            # If the first label is a function end, remove it,
            # If the last label is a function start, remove it 

            # Check to see if theres no rows,
            # This would be the case is the first 
            # prediction is an end and there is only 1 prediction
            if filt_sorted_bounds.shape[0] == 0 or filt_sorted_bounds.shape[1] == 0:
                xda_bounds = np.array([[]])
            else:
                # Check to see if the first index is an end prediction, if so remove it 
                if filt_sorted_bounds[0,1] == 2:
                    filt_sorted_bounds = filt_sorted_bounds[1:,:]

                # Check to see if the last prediction is a start, if so remove it

                # See if theres any remaining predictions
                #print(filt_sorted_bounds.shape)
                if filt_sorted_bounds.shape[0] == 0 or filt_sorted_bounds.shape[1] == 0:
                    xda_bounds = np.array([[]])
                elif filt_sorted_bounds[-1,1] == 1:
                    filt_sorted_bounds = filt_sorted_bounds[:-1,:]

                # Lastly, combine the start and ends array to make matrix:   | start | end |
                    starts = filt_sorted_bounds[filt_sorted_bounds[:,1] == 1]
                    ends = filt_sorted_bounds[filt_sorted_bounds[:,1] == 2]
                    xda_bounds = np.hstack(( starts[:,0].reshape(-1,1), ends[:,0].reshape(-1,1)))


                else:

                # Lastly, combine the start and ends array to make matrix:   | start | end |
                    starts = filt_sorted_bounds[filt_sorted_bounds[:,1] == 1]
                    ends = filt_sorted_bounds[filt_sorted_bounds[:,1] == 2]
                    xda_bounds = np.hstack(( starts[:,0].reshape(-1,1), ends[:,0].reshape(-1,1)))

        #dot = np.dot(gnd_matrix[, xda_bounds)
        #norm_gnd = np.dot(gnd_matrix,gnd_matrix)
        #norm_xda = np.dot(xda_bounds,xda_bounds)
        #jac_sim = dot / (norm_gnd + norm_xda - dot)
        #print(jac_sim)

        #if total_start_conf.tp == 0:
        #    np.save("TMP_XDA_BOUINDS", xda_bounds)
        #    np.save("TMP_GND_M", gnd_matrix)

        # 6 - Compare the ends
        #bound_conf.tp=len(np.intersect1d(gnd_matrix, xda_bounds))
        #bound_conf.fp=len(np.setdiff1d( xda_bounds, gnd_matrix ))
        #bound_conf.fn=len(np.setdiff1d(gnd_matrix, xda_bounds))

        # 3.3 - Function bounds stats
        # Check the predicted bounds for correctness
        # FP = Total number of functions in pred - tp
        # FN = Total number of functions in ground - tp
        for row in xda_bounds:
            if xda_bounds.shape[0] == 0 or xda_bounds.shape[1] !=2:
                break
            #print(xda_bounds.shape)
            if np.any(np.all(row == gnd_matrix, axis=1)): 
                bound_conf.tp+=1

        bound_conf.fp = xda_bounds.shape[0] - bound_conf.tp
        bound_conf.fn = gnd_matrix.shape[0] - bound_conf.tp


        # tp + fp = Total predicted
        if not start_conf.tp + start_conf.fp == xda_starts.shape[0]:
            print(f"start TP: {start_conf.tp}")
            print(f"start FP: {start_conf.fp}")
            print(f"Xda starts: {xda_starts.shape}")
            print(f"gnd matrix {gnd_matrix.shape[0]}")
            return

        # tp + fn = total pos
        if not start_conf.tp + start_conf.fn == gnd_matrix.shape[0]:
            print(f"{start_conf.fp}")
            print(f"{start_conf.fn}")
            print(f"{gnd_matrix.shape[0]}")
            print(f"start total: {xda_starts.shape}")
            print(f"gnd matrix {gnd_matrix.shape[0]}")
            return

        total_bytes += gnd_truth.num_bytes

        # Update the total confusion matrices 
        total_start_conf.tp += start_conf.tp
        total_start_conf.fp += start_conf.fp
        total_start_conf.fn += start_conf.fn

        total_bound_conf.tp += bound_conf.tp
        total_bound_conf.fp += bound_conf.fp
        total_bound_conf.fn += bound_conf.fn

        total_end_conf.tp += end_conf.tp
        total_end_conf.fp += end_conf.fp
        total_end_conf.fn += end_conf.fn

        if verbose:
            print(f"binary: {bin.name}")
            print(f"Starts: {start_conf}")
            print(f"Starts Metrics: {calc_metrics(start_conf)}")
            print(f"Ends : {end_conf}")
            print(f"Ends Metrics: {calc_metrics(end_conf)}")
            print(f"Bounds: {bound_conf}")
            print(f"Bounds Metrics: {calc_metrics(bound_conf)}")

    total_runtime = sum_runtimes(Path(input_path))

    start_metrics = calc_metrics(total_start_conf)
    end_metrics = calc_metrics(total_end_conf)
    bound_metrics = calc_metrics(total_bound_conf)

    if out_dir != "":
        out_path = Path(out_dir)
        with open(out_path, 'w') as f:
            json.dump({'start': {
                            'conf_matrix': asdict(total_start_conf), 
                            'metrics': asdict(start_metrics)}, 
                        'end': { 
                            'conf_matrix': asdict(total_end_conf),
                            'metrics': asdict(end_metrics)}, 
                        'bound': { 
                            'conf_matrix': asdict(total_bound_conf),
                            'metrics': asdict(bound_metrics)}, 
                        'runtime': total_runtime}, f)

    print(f"Starts Conf: {total_start_conf}")
    print(f"Starts Metrics: {start_metrics}")
    print(f"Ends Conf: {total_end_conf}")
    print(f"Ends Metrics: {end_metrics}")
    print(f"Bounds Conf: {total_bound_conf}")
    print(f"Bounds Metrics: {bound_metrics}")

    if tex_charts != Path(""):
        with open(tex_charts, 'w') as f:
            # end: 
            # bounds: tp tn fp fn
            f.write("CONFUSION MATRIX:\n\n")
            cols = f" & ".join(k for k, _ in asdict(total_start_conf).items())
            f.write(cols+' \\\\ \n')
            start_line = " & ".join(str(val) for k, val in asdict(total_start_conf).items())
            f.write(start_line+' \\\\ \n')
            ends_line = " & ".join(str(val) for k, val in asdict(total_end_conf).items())
            f.write(ends_line+' \\\\ \n')
            bounds_line = " & ".join(str(val) for k, val in asdict(total_bound_conf).items())
            f.write(bounds_line+' \\\\ \n')

            f.write("METRICS:\n")
            start_res = calc_metrics(total_start_conf)
            cols = f" & ".join(k for k, _ in asdict(start_res).items())
            f.write(cols+' \\\\ \n')
            start_res_line = f" & ".join(str(val) for _, val in asdict(start_res).items())
            f.write(start_res_line+' \\\\ \n')
            end_res = calc_metrics(total_end_conf)
            end_res_line = f" & ".join(str(val) for k, val in asdict(end_res).items())
            f.write(end_res_line+' \\\\ \n')
            bound_res = calc_metrics(total_bound_conf)
            bound_res_line = f" & ".join(str(val) for k, val in asdict(bound_res).items())
            f.write(bound_res_line+' \\\\ \n')
    return 

@app.command()
def  test_and_evaluate(
    bin_path: Annotated[Path, typer.Argument(help="Path to the directory or file containing binary files for inference.")],
    checkpoint_dir: Annotated[Path, typer.Argument(help="Directory containing the model checkpoint files.")],
    checkpoint: Annotated[str, typer.Argument(help="Specific checkpoint file to be used for loading the model.")],
    raw_result_path: Annotated[Path, typer.Argument(help="Directory where raw prediction results will be saved.")],
    eval_result_path: Annotated[Path, typer.Argument(help="Directory where evaluation is to be saved in JSON format. Default is empty, meaning no output will be saved.")],
    check_for_existing_results: Annotated[bool, typer.Option(help="Flag to check for existing results during prediction and skip computation if found. Default is True.")] = True,
    verbose: Annotated[bool, typer.Option(help="Flag to enable verbose output during evaluation. Default is False.")] = False,
    suppress_warn: Annotated[bool, typer.Option(help="Flag to suppress warnings during evaluation. Default is False.")] = False,
    tex_charts: Annotated[str, typer.Option(help="Optional path to save evaluation metrics in LaTeX format. Default is empty, meaning no LaTeX output will be saved.")] = "",
    bins_are_bundles: Annotated[bool, typer.Option(help="If the directory is not _only_ bins, and has sub dirs with info.json files, set this to true to load only the bins")]=False,
) -> str:
    """
    Function to perform inference on a given dataset and evaluate the results, making use of raw-test and read-bounds-raw
    """
    full_output = ""
    out_chunk = "-" * console.width + "\n"
    out_chunk += "Test and Evaluate" + "\n"
    out_chunk += "-" * console.width + "\n"
    out_chunk += "-" * console.width + "\n"


    # Step 1: Run raw_test to perform inference and save raw predictions
    cmd = gen_raw_test_cmd(bin_path, checkpoint_dir, checkpoint, raw_result_path, check_for_existing_results)
    out_chunk += f"Raw Test:\n"
    out_chunk += "-" * console.width + "\n"
    out_chunk += f"Command executed (equivalent): [bold cyan]{cmd}[/bold cyan]\n"
    full_output = record_and_print(full_output, out_chunk)
    raw_test(bin_path, checkpoint_dir, checkpoint, raw_result_path, check_for_existing_results, bins_are_bundles)

    # Step 2: Run read_bounds_raw to read and evaluate the raw predictions
    cmd = gen_read_bounds_raw_cmd(raw_result_path, bin_path, verbose, suppress_warn, eval_result_path, tex_charts)
    out_chunk = "-" * console.width + "\n"
    out_chunk += f"Read Bounds Raw:\n"
    out_chunk += "-" * console.width + "\n"
    out_chunk += f"Command executed (equivalent): [bold cyan]{cmd}[/bold cyan]\n"
    out_chunk += "-" * console.width + "\n"
    full_output = record_and_print(full_output, out_chunk)
    if bins_are_bundles:
        bins = load_bins(bin_path)
    else:
        bins = bin_path
    read_bounds_raw(Path(raw_result_path), bins, verbose, suppress_warn, eval_result_path, Path(tex_charts))

    return full_output


@app.command()
def modify_test_evaluate(
    bin_path: Annotated[str, typer.Argument(help="Directory or file containing binary files to modify")],
    opt_level: Annotated[str, typer.Argument(help="Optimization level of the binaries in the dataset")],
    mod_type: Annotated[str, typer.Argument(help="Name of modification pattern (for file/directory names), enter `random` for --random-injection flag")],
    bytestring: Annotated[str, typer.Argument(help="Byte pattern to inject, write in hex separated by comma (e.g. 90,90: nop,nop for x86-64)")],
    result_path: Annotated[str, typer.Argument(help="Directory where raw prediction results and evaluation will be saved.")],
    must_follow: Annotated[str, typer.Option(help="What the last byte of a function must be to allow padding modification. Write in hex separated by commas (e.g. c3,00,ff)")] = "",
    verbose_mod: Annotated[bool, typer.Option(help="Flag to enable verbose output during modification. Default is False.")] = False,
    verbose_eval: Annotated[bool, typer.Option(help="Flag to enable verbose output during evaluation. Default is False.")] = False,
    suppress_warn: Annotated[bool, typer.Option(help="Flag to suppress warnings during evaluation. Default is False.")] = False,
    tex_charts: Annotated[str, typer.Option(help="Optional path to save evaluation metrics in LaTeX format. Default is empty, meaning no LaTeX output will be saved.")] = "",
    delete_existing: Annotated[bool, typer.Option(help="Flag to delete existing results before running the command (Use with caution). Default is False.")] = False,
):
    """
    Function to modify a given dataset (edit-padding), perform inference on said dataset (raw-test), and evaluate the results (read-bounds-raw). 
    
    This function should only be used by a user who thoroughly understands the three commands mentioned above. This command bridges the functionality of the ripkit and XDA githubs, 
    so in order for this command to function, the two folders must be located in the same parent directory (e.g. ~/ghPackages/BoundDetector). Additionally, this command requires a 
    combination of the virtual environments used by XDA and ripkit, so it must be run from the xda3.10 virtual environment (uses python 3.10, contains both xda and ripkit dependencies)
    
    This command has several hard coded paths, as it is only built to expedite the collection of results on our specific server. In a different directory structure, more arguments
    can be added, or the hard coded paths can be modified.
    """
    full_output = ""
    error_output = ""

    out_chunk = "-" * console.width + "\n"
    out_chunk += "Modify, Test, Evaluate:\n"
    out_chunk += "-" * console.width + "\n"
    out_chunk += "-" * console.width + "\n"
    out_chunk += f"Command executed: [bold cyan]{gen_modify_test_eval_cmd(bin_path, opt_level, mod_type, bytestring, result_path, must_follow, verbose_mod, verbose_eval, suppress_warn, tex_charts, delete_existing)}[/bold cyan]\n"

    # Step 0: Handle directories and error check input (don't want to start extended commands if arguments/options are incorrect)
    log_dir = Path(f"{result_path}/{opt_level}/logs").expanduser().resolve()
    if not log_dir.exists():
        log_dir.mkdir(parents=True, exist_ok=True)
    log_path = Path(f"{log_dir}/{mod_type}.txt").resolve()

    bin_path = Path(bin_path).resolve()
    if not bin_path.exists():
        error_output += f"ERROR: The bin directory does not exist:\n{bin_path}\n"
        print(out_chunk + error_output)
        return

    if delete_existing:
        if result_path.find("../") != -1:
            error_output += f"ERROR: The --delete-existing flag cannot be used with relative paths.\n"
            print(out_chunk + error_output)
            return

    mod_out_path = Path(f"~/ghPackages/BoundDetector/{opt_level}_nonstripped_{mod_type}_mod").expanduser().resolve()
    
    raw_result_path = Path(f"{result_path}/{opt_level}/raw/{mod_type}").resolve()
    dir_paths = [raw_result_path]

    for path in dir_paths:
        if path.exists():
            if delete_existing:
                out_chunk += f"Deleting existing directory: {path}\n"
                shutil.rmtree(path)
            else:
                # error_output += f"The following result directories/files are present:\n{path}\n"
                continue
        else:
            path.mkdir(parents=True, exist_ok=True)

    eval_result_dir = Path(f"{result_path}/{opt_level}/results").resolve()
    eval_result_path = Path(f"{result_path}/{opt_level}/results/{mod_type}.txt").resolve()

    if not eval_result_dir.exists():
        eval_result_dir.mkdir(parents=True, exist_ok=True)
    if not eval_result_path.exists():
        eval_result_path.touch()

    checkpoint_dir = Path(f"~/ghPackages/BoundDetector/model_weights/xda/{opt_level.lower()}/checkpoints/funcbound").expanduser().resolve()
    checkpoint = "checkpoint_best.pt"
    if not Path(f"{checkpoint_dir}/{checkpoint}").exists():
        error_output += f"ERROR: The given checkpoint does not exist:\n{checkpoint_dir}{checkpoint}\n"

    if error_output != "":
        out_chunk += error_output
        full_output = record_and_print(full_output, out_chunk)
        write_to_log_file(log_path, full_output)
        return
    
    out_chunk += "\nDirectory paths created successfully.\n"
    out_chunk += "-" * console.width + "\n"
    out_chunk += "Modify (edit-padding)" + "\n"
    out_chunk += "-" * console.width + "\n"
    out_chunk += "-" * console.width + "\n"
    
    # Step 1: Build and execute the modify edit-padding command in a subproces

    if mod_out_path.exists():
        out_chunk += f"WARNING: The modified directory already exists and --delete-existing flag is not present: {mod_out_path}\n"
        out_chunk += "Existing dataset will be used, skipping edit-padding command.\n"
        full_output = record_and_print(full_output, out_chunk)
        out_chunk = ""
    else: 
        mod_out_path.mkdir(parents=True, exist_ok=True)
        cmd = f"cd ../ripkit && "
        cmd += gen_edit_padding_cmd(bin_path, mod_out_path, bytestring, mod_type, must_follow, verbose_mod)
        out_chunk += f"Command executed: [bold cyan]{cmd}[/bold cyan]\n"
        full_output = record_and_print(full_output, out_chunk)
        out_chunk = ""
        print("NOTE: output will print after command completes (ripkit edit-padding command is run in subprocess)")
        try:
            run_cmd_in_subprocess(cmd)
        except Exception as e:
            full_output += f"ERROR: Modify command failed: {e}\n"
            write_to_log_file(log_path, full_output)
            print(f"{e}")
            return

    # Step 2: Run test-and-evaluate command with the given/derived arguments/options to conduct and evalute inference
    print("Modify command succeeded\n")
    try:
        out_chunk += test_and_evaluate(mod_out_path, checkpoint_dir, checkpoint, raw_result_path, eval_result_path, True, verbose_eval, suppress_warn, tex_charts)
    except Exception as e:
        out_chunk += f"ERROR: Test and evaluate command failed: {e}\n"
        full_output += out_chunk
        write_to_log_file(log_path, full_output)
        print(f"{e}")
        return
    
    # Step 3: Write output to log file in result_path
    full_output += out_chunk
    write_to_log_file(log_path, full_output)
    return

def run_cmd_in_subprocess(cmd: str):
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    stdout, stderr = process.communicate()
    if stdout:
        console.print(stdout)
    if stderr:
        console.print(stderr)
        raise Exception(f"{stderr}")
    return

def write_to_log_file(file: Path, msg: str):
    with open(file, 'a') as f:
        f.write(msg)
    print(f"\nOutput written to log file: {file}\n")
    return

def record_and_print(fullout: str, msg: str) -> str:
    fullout += msg
    console.print(msg)
    return fullout

def gen_modify_test_eval_cmd(bin_path, opt_level, mod_type, bytestring, result_path, must_follow, verbose_mod, verbose_eval, suppress_warn, tex_charts, delete_existing) -> str:
    cmd = "python ryan_cli.py modify_test_evaluate "
    cmd += f"--verbose-mod " if verbose_mod else ""
    cmd += f"--delete-existing " if delete_existing else ""
    cmd += f"--must-follow {must_follow} " if must_follow != "" else ""
    cmd += f"--verbose-eval " if verbose_eval else ""
    cmd += f"--suppress-warn " if suppress_warn else ""
    cmd += f"--tex-charts {tex_charts} " if tex_charts != "" else ""
    cmd += f"{bin_path} {opt_level} {mod_type} {bytestring} {result_path} "
    return cmd

def gen_raw_test_cmd(bins, checkpoint_dir, checkpoint, result_path, check_for_existing_results) -> str:
    cmd = "python ryan_cli.py raw-test "
    cmd += f"--no-check-for-existing-results " if not check_for_existing_results else ""
    cmd += f"{bins} {checkpoint_dir} {checkpoint} {result_path}"
    return cmd

def gen_read_bounds_raw_cmd(input_path, bin_path, verbose, supress_warn, out_dir, tex_charts) -> str:
    cmd = "python ryan_cli.py read-bounds-raw "
    cmd += f"--verbose " if verbose else ""
    cmd += f"--supress-warn " if supress_warn else ""
    cmd += f"--out-dir {out_dir} " if out_dir != "" else ""
    cmd += f"--tex-charts {tex_charts} " if tex_charts != "" else ""
    cmd += f"{input_path} {bin_path}"
    return cmd

def gen_edit_padding_cmd(bin_path, mod_out_path, bytestring, mod_type, must_follow, verbose_mod) -> str:
    cmd = "python ripkit/main.py modify edit-padding "
    cmd += f"--verbose " if verbose_mod else ""
    cmd += f"--must-follow {must_follow} " if must_follow != "" else ""
    cmd += f"--random-injection " if mod_type == random else ""
    cmd += f"{bin_path} {mod_out_path} {bytestring}"
    return cmd

def read_xda_npz(inp: Path)->np.ndarray:
    '''
    Read the ida npz
    '''
    npz_file = np.load(inp)
    return npz_file[list(npz_file.keys())[0]]

@app.command()
def extract_metrics_from_directory(result_dir: Annotated[str, typer.Argument(help="Directory containing results of raw-test/read-bounds-raw")],):
    '''
    Extracts metrics from the results of raw-test/read-bounds-raw in a given directory.
    '''
    result_path = Path(result_dir)
    import pdb; pdb.set_trace()
    for opt_level in result_path.iterdir():
        if opt_level.is_dir():
            print(f"{opt_level.name}:")
            results_dir = opt_level / 'results'
            for result_file in results_dir.iterdir():
                if result_file.is_file() and result_file.suffix == '.txt':
                    with result_file.open('r', encoding='utf-8') as file:
                        content = file.read()
                        if content == '':
                            continue
                        data = json.loads(content)
                        
                        start_metrics = data.get('start', {}).get('metrics', {})
                        end_metrics = data.get('end', {}).get('metrics', {})
                        bound_metrics = data.get('bound', {}).get('metrics', {})
                        runtime = data.get('runtime', None)

                        print(f"  Model: {result_file.stem}")
                        
                        print("    Starts:")
                        print(f"        Precision: {start_metrics.get('prec', 'N/A'):.3g}")
                        print(f"        Recall: {start_metrics.get('recall', 'N/A'):.3g}")
                        print(f"        F1-score: {start_metrics.get('f1', 'N/A'):.3g}")
                        
                        print("    Ends:")
                        print(f"        Precision: {end_metrics.get('prec', 'N/A'):.3g}")
                        print(f"        Recall: {end_metrics.get('recall', 'N/A'):.3g}")
                        print(f"        F1-score: {end_metrics.get('f1', 'N/A'):.3g}")
                        
                        print("    Bounds:")
                        print(f"        Precision: {bound_metrics.get('prec', 'N/A'):.3g}")
                        print(f"        Recall: {bound_metrics.get('recall', 'N/A'):.3g}")
                        print(f"        F1-score: {bound_metrics.get('f1', 'N/A'):.3g}")
                        
                        print(f"    Runtime: {runtime}")
                        print("\n")

#@app.command()
#def test(
#        inp_dir: Annotated[str, typer.Argument()],
#        out_dir: Annotated[str, typer.Argument()],
#        checkpoint_dir: Annotated[str, typer.Argument()],
#        checkpoint: Annotated[str, typer.Argument()],
#        ):
#    '''
#    Test XDA on a set of binaries.
#    '''
#
#
#    # Make a list of the input file 
#    test_files = [x.resolve() for x in Path(inp_dir).resolve().rglob('*')]
#
#    out_path = Path(out_dir)
#    if not out_path.exists():
#        out_path.mkdir()
#
#    # Load our model
#    roberta = RobertaModel.from_pretrained(checkpoint_dir, 
#                                        checkpoint,
#                                        'data-bin/funcbound', 
#                                        user_dir='finetune_tasks')
#    roberta.eval()
#    results = xda_predict_many(test_files, roberta, out_path.resolve(), save_results=True)
#
#    return


def chunkwise_hamming_distance(pred_file, gnd, chunk_size=1024):
    """
    Compute the Hamming distance between two large datasets stored in numpy files,
    processing the data in chunks to avoid memory issues.
    
    Parameters:
    - file1, file2: Paths to the numpy files.
    - chunk_size: The size of chunks to use for reading the data.
    
    Returns:
    - The normalized Hamming distance as a float.
    """
    total_distance = 0
    total_elements = 0  # Keep track of the total number of elements processed.
    
    # Open both files in 'read' mode.
    pred = np.load(pred_file, mmap_mode='r')
    index = 0 
    chunk_size = 4096

    # Loop and both are exhausted. Which ever is exachuated first padd with 0s
    done = False
    while not done:
        gnd_exhuasted = False
        pred_exhuasted = False

        # Load a chunk of data from each file
        if index+chunk_size < pred.shape[0]:
            pred_chunk = pred[index:index+chunk_size]
            pred_exhuasted = True
        else:
            # Get the rest and pad with zeros
            pred_chunk = pred[index::]
            zeros = np.zeros(chunk_size-len(pred_chunk), dtype=pred_chunk.dtype)
            pred_chunk = np.concatenate((pred_chunk,zeros))

        # Load a chunk from the prediction

        if index+chunk_size < gnd.shape[0]:
            gnd_chunk = gnd[index:index+chunk_size]
            gnd_exhuasted = True
        else:
            # Get the rest and pad with zeros
            gnd_chunk = gnd[index::]
            zeros = np.zeros(chunk_size-len(gnd_chunk), dtype=gnd_chunk.dtype)
            gnd_chunk = np.concatenate((gnd_chunk,zeros))

        
        # Compute the Hamming distance for this chunk.
        distance = np.sum(pred_chunk != gnd_chunk)
        total_distance += distance
        total_elements += chunk_size  # Update the total number of elements.

        if gnd_exhuasted and pred_exhuasted:
            done = True
    
    # Normalize the total distance by the total number of elements.
    return total_distance / total_elements if total_elements else 0


def jaccard_similarity(inp1:np.ndarray, inp2:np.ndarray):
    '''
    Jaccard sim is equivelantly:

    jac(pred,gnd):
        TP / (FP + TP + FN)
    '''

    intersection_size = len(set1.intersection(set2))
    union_size = len(set1.union(set2))

    if union_size == 0:
        return 0
    else:
        return 1 - (intersection_size/union_size)

if __name__ == '__main__':
    app()
    exit()
