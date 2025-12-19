import segfaults
from strutils import find, split
from os import joinPath, dirExists, createDir, getEnv

type WCHAR = uint16 

proc bytesToString*(b: openArray[byte]): string =
  result = newString(b.len)
  for i in 0..<b.len: result[i] = char(b[i])

proc toBytes*(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i in 0 ..< s.len:
    result[i] = byte(s[i])

proc readBin*(path: string): seq[byte] =
  let s = readFile(path)         
  result = newSeq[byte](s.len)
  for i in 0 ..< s.len:
    result[i] = byte(s[i])

proc writeBin*(path: string, data: openArray[byte]) =
  var s = newString(data.len)
  for i in 0 ..< data.len:
    s[i] = char(data[i])
  writeFile(path, s)

proc toString*(wchars: array[260, WCHAR]): string =
  result = ""
  for ch in wchars:
    if ch == '\0'.ord:
      break
    result.add(char(ch))

proc fromString*(s: string): array[260, WCHAR] = 
  var wchars: array[260, WCHAR]
  var i = 0

  for ch in s:
    if i >= wchars.len:
      break 
    wchars[i] = WCHAR(ch.ord)
    inc(i)
  
  wchars[i] = '\0'.ord 
  result = wchars

func toByteSeq*(str: string): seq[byte] {.inline.} =
    @(str.toOpenArrayByte(0, str.high))

proc getFullPath*(envString: string): string =
  let startIdx = envString.find('"') + 1
  let endIdx = envString.find('"', startIdx)
  let envVarName = envString[startIdx .. endIdx - 1]

  let envVarValue = getEnv(envVarName)
  let pathSuffix = envString[endIdx + 1 .. ^1]

  return joinPath(envVarValue, pathSuffix)

proc convertSeconds*(seconds: int64): int64 = 
  return seconds * 10_000_000

