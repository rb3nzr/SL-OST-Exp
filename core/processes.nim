import nimvoke/syscalls
import nimvoke/dinvoke
from strutils import toLower, alignLeft
from winim/lean import DWORD, LPDWORD, HANDLE, HMODULE, CLIENT_ID, MAX_PATH, WINBOOL, NULL, NTSTATUS, LPSTR,
                       OBJECT_ATTRIBUTES, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, `&`, `T`, `$`

dinvokeDefine(K32EnumProcesses, "kernel32.dll", proc (lpidProcess: ptr DWORD, cb: DWORD, cbNeeded: LPDWORD): WINBOOL {.stdcall.})
dinvokeDefine(K32EnumProcessModules, "kernel32.dll", proc (hProcess: HANDLE, lphModule: ptr HMODULE, cb: DWORD, lpcbNeeded: LPDWORD): WINBOOL {.stdcall.})
dinvokeDefine(K32GetModuleBaseNameA, "kernel32.dll", proc (hProcess: HANDLE, hModule: HMODULE, lpBaseName: LPSTR, nSize: DWORD): DWORD {.stdcall.})
dinvokeDefine(QueryFullProcessImageNameA, "kernel32.dll", proc(hProcess: HANDLE, dwFlags: DWORD, lpExeName: LPSTR, lpdwSize: LPDWORD): WINBOOL {.stdcall.})

type ProcRow = object
  pid: DWORD
  name: string
  path: string

proc findTargetProc*(targetProc: string): DWORD =
  var
    cbNeeded: DWORD
    hModule: HMODULE
    cid: CLIENT_ID
    hProc: HANDLE
    oa: OBJECT_ATTRIBUTES
    aProcesses: array[4096, DWORD]
    nameBuff: array[MAX_PATH, char]

  zeroMem(&oa, sizeof(oa))
  oa.Length = cast[DWORD](sizeof(oa)) 

  if K32EnumProcesses(&aProcesses[0], cast[DWORD](sizeof(aProcesses)), &cbNeeded) != 0:
    for i in 0 ..< cbNeeded div sizeof(DWORD):
      if aProcesses[i] == 0: 
        continue
      hProc = 0
      cid.UniqueProcess = cast[HANDLE](aProcesses[i])
      cid.UniqueThread = 0
      let status: NTSTATUS = syscall(NtOpenProcess, &hProc, PROCESS_QUERY_INFORMATION or PROCESS_VM_READ, &oa, &cid)

      if status == 0 and hProc != 0:
        var needed: DWORD = 0
        if K32EnumProcessModules(hProc, &hModule, cast[DWORD](sizeof(hModule)), &needed) != 0:
          discard K32GetModuleBaseNameA(hProc, hModule, cast[LPSTR](&nameBuff[0]), MAX_PATH.DWORD)
          let procName = $cast[cstring](&nameBuff[0])
          if procName.toLower() == targetProc.toLower():
            discard syscall(NtClose, hProc)
            return aProcesses[i]

        discard syscall(NtClose, hProc)
  return 0

proc formatRows(rows: seq[ProcRow]): string =
  var maxNameLen = "[NAME]".len
  for r in rows:
    if r.name.len > maxNameLen: 
      maxNameLen = r.name.len

  if maxNameLen < 16: maxNameLen = 16
  if maxNameLen > 48: maxNameLen = 48

  var res = ""
  res.add("[PID]\t")
  res.add(alignLeft("[NAME]", maxNameLen + 2))
  res.add("[PATH]\r\n\n")

  for r in rows:
    res.add($r.pid)
    res.add("\t")
    var nm = r.name
    if nm.len > maxNameLen:
      nm = nm[0 ..< maxNameLen]
    res.add(alignLeft(nm, maxNameLen + 2))
    res.add(r.path)
    res.add("\r\n")
  return res

proc procList*(): string =
  var
    cbNeeded: DWORD
    hModule: HMODULE
    cid: CLIENT_ID
    hProc: HANDLE
    oa: OBJECT_ATTRIBUTES
    aProcesses: array[4096, DWORD]
    nameBuff: array[MAX_PATH, char]
    pathBuff: array[4096, char]
    pathLen: DWORD = DWORD(pathBuff.len)
    rows: seq[ProcRow] = @[]

  zeroMem(&oa, sizeof(oa))
  oa.Length = cast[DWORD](sizeof(oa)) 

  if K32EnumProcesses(&aProcesses[0], cast[DWORD](sizeof(aProcesses)), &cbNeeded) != 0:
    for i in 0 ..< cbNeeded div sizeof(DWORD):
      let pid = aProcesses[i]
      if pid == 0: 
        continue
      hProc = 0
      cid.UniqueProcess = cast[HANDLE](aProcesses[i])
      cid.UniqueThread = 0
      let status: NTSTATUS = syscall(NtOpenProcess, &hProc, PROCESS_QUERY_INFORMATION or PROCESS_VM_READ, &oa, &cid)

      if status != 0 or hProc == 0:
        continue
      
      hModule = 0
      var 
        name = "<none>"
        path = "<none>"
        needed: DWORD = 0

      zeroMem(&nameBuff[0], sizeof(nameBuff))
      if K32EnumProcessModules(hProc, &hModule, cast[DWORD](sizeof(hModule)), &needed) != 0 and hModule != 0:
        let n = K32GetModuleBaseNameA(hProc, hModule, cast[LPSTR](&nameBuff[0]), MAX_PATH.DWORD)
        if n != 0:
          name = $cast[cstring](&nameBuff[0])

      pathLen = DWORD(pathBuff.len)
      zeroMem(&pathBuff[0], sizeof(pathBuff))
      if QueryFullProcessImageNameA(hProc, 0.DWORD, cast[LPSTR](&pathBuff[0]), &pathLen) != 0:
        path = $cast[cstring](&pathBuff[0])

      rows.add(ProcRow(pid: pid, name: name, path: path))
      discard syscall(NtClose, hProc)

  return formatRows(rows)

when isMainModule:
  echo procList()