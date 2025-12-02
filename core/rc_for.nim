from strutils import toHex, fromHex
import os

type
  SBox = array[256, byte]

proc rc4Init(key: openArray[byte]): SBox =
  for i in 0 .. 255:
    result[i] = byte(i)
  var j = 0
  var k = 0
  for i in 0 .. 255:
    j = (j + int(result[i]) + int(key[k])) and 0xFF
    swap(result[i], result[j])
    k = (k + 1) mod key.len

proc rc4Apply*(key: openArray[byte], data: openArray[byte]): seq[byte] =
  var S = rc4Init(key)
  var i = 0
  var j = 0
  result = newSeq[byte](data.len)
  for idx in 0 ..< data.len:
    i = (i + 1) and 0xFF
    j = (j + int(S[i])) and 0xFF
    swap(S[i], S[j])
    let t = (int(S[i]) + int(S[j])) and 0xFF
    let kByte = S[t]
    result[idx] = data[idx] xor kByte

proc rc4ApplyInPlace*(key: openArray[byte], data: var seq[byte]) =
  var S = rc4Init(key)
  var i = 0
  var j = 0
  for idx in 0 ..< data.len:
    i = (i + 1) and 0xFF
    j = (j + int(S[i])) and 0xFF
    swap(S[i], S[j])
    let t = (int(S[i]) + int(S[j])) and 0xFF
    let kByte = S[t]
    data[idx] = data[idx] xor kByte

proc kStream(key:string): array[256, int] = 
  var j, k = 0 
  for i in 0..255:
    result[i] = i 

  for i in 0..255:
    j = (j + result[i] + ord(key[k])) mod 256
    swap(result[i], result[j])
    k = (k + 1) mod key.len

iterator itr(ks: var array[256, int], size: int, inc = 1): tuple[i, j, k: int] = 
  var i, j, k = 0 
  while i < size:
    j = (j + 1) mod 256 
    k = (k + ks[j]) mod 256 
    swap(ks[k], ks[j])
    yield(i, j, k)
    i += inc 

# To RC4
proc trcEnc*(k, s: string): string =
  var ks = kStream(k)
  for i, j, k in itr(ks, s.len):
    result.add((ord(s[i]) xor ks[(ks[j] + ks[k]) mod 256]).toHex(2))

# From RC4
proc frcDec*(k, s: string): string = 
  var ks = kStream(k)
  for i, j, k in itr(ks, s.len, 2):
    result.add((fromHex[int](s[i] & s[i+1]) xor ks[(ks[j] + ks[k]) mod 256]).char)
    

