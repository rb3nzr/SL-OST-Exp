import std/[macros, random, times, tables, os, volatile]

#[
  Experimenting with Nim's AST to manipulate code at compile time.
  This file exports a macro. The macro gets the AST of the code block passed to it (NimNode represnting a statement list),
  and returns a new statement list that includes the original statements, mixed with obfuscated code.
]#

var rng {.compileTime.}: Rand 
var idCounter {.compileTime.}: int = 0

static:
  const seed = 12345
  rng = initRand(seed)

template ctRand(max: int): int = rng.rand(max)
#template ctRandFloat(): float = rng.rand(1.0)

proc randIdent(prefix="xyz"): NimNode =
  idCounter += 1
  let randomSuffix = ctRand(1000)  
  result = ident(prefix & $idCounter & "_" & $randomSuffix)

# Volatile operations that force side effects. Prevent compiler from optimizing away
proc volatileTouchNode(x: NimNode): NimNode =
  let tmp = randIdent("vtmp")
  result = quote do:
    block:
      var `tmp` {.volatile.} = 0
      volatileStore(addr `tmp`, volatileLoad(addr `tmp`))
      let check = volatileLoad(addr `tmp`)
      discard check
      discard `x`

#[proc forceSideEffect(x: NimNode): NimNode =
  let tmp = randIdent("fse")
  result = quote do:
    block:
      var `tmp` {.volatile.} = `x`
      volatileStore(addr `tmp`, volatileLoad(addr `tmp`))
      `tmp`]#

const wordList = [
  "Other", "NoBranch", "RegionFailure", "DiscReadError", "CopyProtectFail",
  "InvalidDiscRegion", "Unexpected", "LowParentalLevel", "MacrovisionFail",
  "GetValueByIndex", "Count", "AddValue", "AddRef", "Reset", "Release", 
  "Public", "IDispatch", "Query", "Render", "IRpcStubBuffer", "MediaTypes",
  "Connect", "GetTypeInfo", "GetIDsOfNames", "Direction", "Disconnect"
]

proc opaqueTrue(): NimNode =
  let n = ctRand(1_000) * 2 + 1
  let m = ctRand(1_000)
  result = quote do:
    block:
      var tmp1 {.volatile.} = `n`
      var tmp2 {.volatile.} = `m`
      (volatileLoad(addr tmp1) * volatileLoad(addr tmp1) + 1) mod 2 == 1

proc opaqueCondition(): NimNode = 
  let a = ctRand(1000)
  let b = ctRand(1000)
  let c = ctRand(1000)
  result = quote do:
    block:
      var va {.volatile.} = `a`
      var vb {.volatile.} = `b` 
      var vc {.volatile.} = `c`
      (volatileLoad(addr va) xor volatileLoad(addr vb)) == (volatileLoad(addr va) xor volatileLoad(addr vb)) and
      ((volatileLoad(addr va) + volatileLoad(addr vb)) * volatileLoad(addr vc)) == 
      (volatileLoad(addr va) * volatileLoad(addr vc) + volatileLoad(addr vb) * volatileLoad(addr vc))

proc generateSS(word: string): NimNode =
  let id   = randIdent("ss_")
  let n    = word.len
  var stmt = nnkStmtList.newTree()

  stmt.add quote do:
    var `id`: array[`n`, char]

  for i, ch in word:
    stmt.add quote do:
      `id`[`i`] = `ch`

  stmt.add quote do:
    discard volatileLoad(addr `id`)

  result = stmt

proc randSS(): NimNode =
  generateSS(wordList[ctRand(wordList.len - 1)])

proc jStmt(): NimNode =
  case ctRand(10) 
  of 0:
    let cond = opaqueTrue()
    let tmp = randIdent("jtmp")
    result = quote do:
      var `tmp` {.volatile.} = 0
      if `cond`:
        volatileStore(addr `tmp`, 1)
      else:
        volatileStore(addr `tmp`, 2)
      discard volatileLoad(addr `tmp`)
  of 1:
    let a = ctRand(100)
    let b = ctRand(100)
    let c = randIdent("jtmp")
    result = quote do:
      var `c` {.volatile.} = `a` + `b` * 2 div 3
      for i in 0..<10:
        volatileStore(addr `c`, volatileLoad(addr `c`) + i)
      discard volatileLoad(addr `c`)
  of 2:
    let arr = randIdent("jarr")
    let idx = randIdent("jidx")
    result = quote do:
      var `arr`: array[10, int]
      var `idx` {.volatile.} = 0
      for i in 0..<10:
        `arr`[i] = i * 2
        volatileStore(addr `idx`, i)
      discard volatileLoad(addr `arr`[volatileLoad(addr `idx`)])
  of 3:
    let v = randIdent()
    result = quote do: 
      var `v` {.volatile.} = 0
      for i in 0..<5:
        volatileStore(addr `v`, volatileLoad(addr `v`) + i)
      discard volatileLoad(addr `v`)
  of 4:
    let v = randIdent()
    result = quote do:
      let `v` = 10
      var tmp {.volatile.} = `v`
      discard volatileLoad(addr tmp)
  of 5:
    let i = randIdent()
    let tmp = randIdent()
    result = quote do:
      var `tmp` {.volatile.} = 0
      for `i` in 0..<3:
        volatileStore(addr `tmp`, volatileLoad(addr `tmp`) + `i`)
      discard volatileLoad(addr `tmp`)
  of 6:
    result = quote do: 
      when not compiles(volatileLoad): 
        discard
      else:
        var tmp {.volatile.} = 1
        discard volatileLoad(addr tmp)
  of 7:
    let val = newLit(ctRand(100))
    result = volatileTouchNode(val)
  of 8:
    let val = newLit(ctRand(100))
    result = volatileTouchNode(val)
  of 9:
    result = randSS()
  else:
    result = randSS()

proc addTo(body: NimNode): NimNode =
  result = nnkStmtList.newTree()
  
  let strategy = ctRand(2) 
  
  case strategy
  of 0:
    for i in 0..<ctRand(5)+3:  
      result.add jStmt()
    
    for stmt in body:
      # Wrap each statement with volatile operations
      let wrappedStmt = quote do:
        block:
          var pre_junk {.volatile.} = 0
          volatileStore(addr pre_junk, 1)
          `stmt`
          var post_junk {.volatile.} = 0  
          volatileStore(addr post_junk, volatileLoad(addr pre_junk))
          discard volatileLoad(addr post_junk)
      
      for j in 0..<ctRand(3):
        result.add jStmt()
      result.add wrappedStmt
      for j in 0..<ctRand(3):
        result.add jStmt()
    
    for i in 0..<ctRand(5)+3:
      result.add jStmt()
  
  of 1:
    # Opaque condition wrapping
    result.add jStmt()
    
    for stmt in body:
      let cond = if ctRand(2) == 0: opaqueTrue() else: opaqueCondition()
      let junk = jStmt()
      
      let wrapped = quote do:
        if `cond`:
          `stmt`
        else:
          `junk`
          `stmt`
      
      result.add wrapped
      result.add jStmt()
    
    result.add jStmt()
  
  else:
    result = addTo(body)

macro morph*(body: untyped): untyped =
  idCounter = 0
  result = addTo(body)