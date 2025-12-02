import os, strformat
import core/rc_for
import core/util
from base64 import encode

proc processShellcode(binFile: string, key: string) =
  var
    keyBytes  = toBytes(key)
    data      = readBin(binFile)
    data2     = readFile(binFile)
    outDat    = rc4Apply(keyBytes, data) 
    outTxt    = trcEnc(key, data2)
    encsc: seq[byte] = toByteSeq(outTxt)
    b64 = encode(encsc)
  
  let f = open(&"{binFile}_encrypted.txt", fmWrite)
  defer: f.close()
  f.write(b64)
  writeBin(&"{binFile}_encrypted.dat", outDat)

when isMainModule:
  if paramCount() < 2:
    echo "Usage: .\\converter.exe in.bin 'RC4keyString'"
    quit 1

  let 
    binFile   = paramStr(1)
    keyStr    = paramStr(2)


  processShellcode(binFile, keyStr)
