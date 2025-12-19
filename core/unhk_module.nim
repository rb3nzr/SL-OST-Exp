import std/[strutils]
import ptr_math
import nimvoke/syscalls 
import nimvoke/dinvoke 
import static_strs
from winim import NTSTATUS, NT_SUCCESS, LPVOID, ULONG, HANDLE, MODULEINFO, PIMAGE_DOS_HEADER, PIMAGE_NT_HEADERS, PIMAGE_SECTION_HEADER, LPMODULEINFO, WINBOOL, LPCWSTR, LPCSTR, SEC_IMAGE, 
                  PAGE_READONLY, PVOID, PSIZE_T, NULL, FILE_MAP_READ, DWORD_PTR, DWORD, SIZE_T, IMAGE_FIRST_SECTION, IMAGE_SIZEOF_SECTION_HEADER, LPSECURITY_ATTRIBUTES, HMODULE, 
                  SECTION_MAP_READ, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, OBJECT_ATTRIBUTES, PUNICODE_STRING, UNICODE_STRING, IO_STATUS_BLOCK, SYNCHRONIZE, 
                  FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_READ_DATA, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT,
                  FreeLibrary, GetModuleHandleA, GetModuleInformation, RtlDosPathNameToNtPathName_U, RtlFreeUnicodeString, `&`

proc toString(bytes: openarray[byte]): string = 
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

proc getNtFileHandle(path: string): HANDLE =
  var 
    hFile: HANDLE = INVALID_HANDLE_VALUE
    isob: IO_STATUS_BLOCK
    oa: OBJECT_ATTRIBUTES
    un: UNICODE_STRING
    ntPath: UNICODE_STRING

  var dosPath = newWideCString(path)
  var pNtPath: PUNICODE_STRING = addr ntPath
  if RtlDosPathNameToNtPathName_U(dosPath, pNtPath, nil, nil):
    defer: RtlFreeUnicodeString(pNtPath)
    
    oa.Length = sizeof(OBJECT_ATTRIBUTES).ULONG
    oa.RootDirectory = 0
    oa.ObjectName = pNtPath
    oa.Attributes = OBJ_CASE_INSENSITIVE
    oa.SecurityDescriptor = NULL
    oa.SecurityQualityOfService = NULL
    
    let status = syscall(NtCreateFile, &hFile, FILE_READ_DATA or SYNCHRONIZE, &oa, &isob, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)
    if NT_SUCCESS(status):
      return hFile
  return INVALID_HANDLE_VALUE

proc uhkModule*(module: string): bool =
  var 
    mi: MODULEINFO 
    base: LPVOID 
    hFile: HANDLE
    status: NTSTATUS 
    hSection: HANDLE
    freshBase: LPVOID 
    hkedDOSHeader: PIMAGE_DOS_HEADER 
    hkedNTHeader: PIMAGE_NT_HEADERS
    hkedSectionHeader: PIMAGE_SECTION_HEADER 
    hModule = GetModuleHandleA(module)
    hProc: HANDLE = 0xFFFFFFFFFFFFFFFF # current proc
  
  GetModuleInformation(hProc, hModule, addr mi, cast[DWORD](sizeof(mi)))
  base = mi.lpBaseOfDll

  var path = jam("C:\\windows\\system32\\")
  path.add(module)
  hFile = getNtFileHandle(path)
  if hFile == INVALID_HANDLE_VALUE:
    FreeLibrary(hModule)
    return false 

  status = syscall(NtCreateSection, &hSection, SECTION_MAP_READ, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile)
  if not NT_SUCCESS(status):
    status = syscall(NtClose, hFile)
    FreeLibrary(hModule)
    return false 

  var regionSize: SIZE_T = 0
  status = syscall(NtMapViewOfSection, hSection, hProc, &freshBase, 0, 0, NULL, &regionSize, 2, 0, PAGE_READONLY) # SECTION_INHERIT value: ViewUnmap = 2
  if not NT_SUCCESS(status):
    status = syscall(NtClose, hSection)
    status = syscall(NtClose, hFile)
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
  
  status = syscall(NtClose, hProc)
  status = syscall(NtClose, hFile)
  status = syscall(NtClose, hSection)
  FreeLibrary(hModule)
  return true 
