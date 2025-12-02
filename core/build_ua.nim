import static_strs
import nimvoke/dinvoke 
from winim/lean import HKEY, NULL, LPCSTR, DWORD, REGSAM, PHKEY, LONG, LPDWORD, LPBYTE, KEY_READ, ERROR_SUCCESS, REG_SZ, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
                       RegOpenKeyExA, RegQueryValueExA, RegCloseKey

proc readRegStr(h: HKEY; path, name: string): string =
  var key: HKEY
  if RegOpenKeyExA(h, path, 0, REGSAM(KEY_READ), addr key) == ERROR_SUCCESS:
    defer: RegCloseKey(key)
    var typ: DWORD = REG_SZ
    var need: DWORD = 0
    discard RegQueryValueExA(key, name, NULL, addr typ, NULL, addr need)
    if need > 1:
      var buf = newString(need.int)        
      if RegQueryValueExA(key, name, NULL, addr typ, cast[LPBYTE](buf.cstring), addr need) == ERROR_SUCCESS:
        return $cast[cstring](buf.cstring)
  return ""

proc getChromeVersion(): string =
  result = readRegStr(HKEY_CURRENT_USER, jam("Software\\Google\\Chrome\\BLBeacon"), "version")
  if result.len == 0:
    result = readRegStr(HKEY_LOCAL_MACHINE, jam("Software\\Google\\Chrome\\BLBeacon"), "version")
  if result.len == 0:
    result = readRegStr(HKEY_LOCAL_MACHINE, jam("Software\\WOW6432Node\\Google\\Chrome\\BLBeacon"), "version")

proc getEdgeVersion(): string =
  result = readRegStr(HKEY_CURRENT_USER, jam("Software\\Microsoft\\Edge\\BLBeacon"), "version")
  if result.len == 0:
    result = readRegStr(HKEY_LOCAL_MACHINE, jam("Software\\Microsoft\\Edge\\BLBeacon"), "version")
  if result.len == 0:
    result = readRegStr(HKEY_LOCAL_MACHINE, jam("Software\\WOW6432Node\\Microsoft\\Edge\\BLBeacon"), "version")

proc buildChromiumUA*(preferEdge=false): string =
  let osTok  = jam("Windows NT 10.0" )  
  let arch   = jam("Win64; X64")       

  var ver = if preferEdge: getEdgeVersion() else: getChromeVersion()
  var isEdge = preferEdge and ver.len > 0
  if ver.len == 0:
    ver = if preferEdge: getChromeVersion() else: getEdgeVersion()
    isEdge = (not preferEdge) and ver.len > 0

  if ver.len == 0:
    ver = "141.0.0.0"

  result = jam("Mozilla/5.0 (") & osTok & "; " & arch & ")" &
           jam(" AppleWebKit/537.36 (KHTML, like Gecko) ") &
           jam("Chrome/") & ver & jam(" Safari/537.36") &
           (if isEdge: " Edg/" & ver else: "")
