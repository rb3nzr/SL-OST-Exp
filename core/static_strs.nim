#[ Macro for static string obfuscation ]#

import macros
import rc_for

from times import cpuTime
from checksums/md5 import getMD5

macro jam*(s: string): untyped = 
  if len($s) < 100:
    let key = getMD5($cpuTime())
    var encStr = trcEnc(key, $s)

    result = quote do:
      frcDec(`key`, `encStr`)
  else:
    result = s
