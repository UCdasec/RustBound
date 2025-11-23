# RustBound !! 

**The dataset and code are for research purpose only** 

Analysis of current methods of Function Boundary Detection in Stripped Binary Files on executable files generated from Rust source code

The main components of this repository are:
1. Ripkit : tool for cloning and compiling rust binaries
2. XDA : Implementation from "XDA: Accurate, Robust Disassembly with Transfer Learning" of a function boundary detector
3. ghidra_bench: tool for benchmarking ghidra

## Reference
When reporting results that use the dataset or code in this repository, please cite the paper below:

Ryan Evans, William Hawkins, and Boyang Wang "RustBound: Function Boundary Detection over Rust Stripped Binaries," The 2nd EAI International Conference on Security and Privacy in Cyber-Physical Systems and Smart Vehicles (**SmartSP 2024**), New Orleans, LA, USA, Nov. 7 - Nov. 8, 2024.

## Dataset 
Our datasets used in this study can be accessed through the link below (**last modified: Nov. 2025**):

https://mailuc-my.sharepoint.com/:f:/g/personal/wang2ba_ucmail_uc_edu/EvqFCk8YX1dIkY_wrJG_L5kBlq9DrMhkbfSo_AfZST6oGw?e=FPtQiQ 

Note: the above link need to be updated every 6 months due to certain settings of OneDrive. If you find the links are expired and you cannot access the data, please feel free to email us (Dr. Boyang Wang, boyang.wang@uc.edu). We will be update the links as soon as we can (typically within 1~2 days). Thanks!

## Ripkit... 

*Ripkit* can:
1. Clone rust crates and compile them for various targets
2. Save produced Rust binaries in db 
3. Export rust datasets 
4. Profile such datasets
5. Use Ghidra, or IDA to analyze function boundary detection in datasets

See the README.md file in the `ripkit` directory for ripkit installation and setup. 

## Training BiRNN...

*Input:* The BiRNN requires ".npy" files for training. These can be generated using the command:
```bash
cli.py gen-npzs
```
This will extract the .text section of the provided binaires and generate feature vectors for the model.


*Training:* Use the command:
```bash
cli.py train-on
```

*Testing:* Use the command:
```bash
cli.py test-on-nongpu
```

## Training XDA... 
There are some preprocesing steps that are best exapline dby XDA's
github repo. 

Once those are done, the cli tool ryan_cli.py is what I used to 
help me train test and log expirements


## Running IDA / Ghidra

Ripkit has just one function to support extracting function bounds from a file uploaded to IDA. Look at the command for ripkit 'ida':
```bash
python ripkit/main.py ida
```
Similarly ghidra is supported as well:
```bash
python ripkit/main ghidra
```
## Contacts
Ryan Evans evans2ra@mail.uc.edu

Boyang Wang boyang.wang@uc.edu
