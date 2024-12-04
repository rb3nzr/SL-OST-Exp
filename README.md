This project is my experimentation with a method to gain persistence on a machine through changing the target path on the [LNK/Shortcut](https://github.com/libyal/liblnk/blob/main/documentation/Windows%20Shortcut%20File%20(LNK)%20format.asciidoc) files for the User/Public desktop, startup menu, and task bar. It's a very simple POC, and there is a lot that could be added/removed. This was purely made for fun and education. 

### General Idea
The main goal here would require some type of payload to stay on disk, and this payload itself or another intermediate executable would change the shortcut's target paths to that payload. Once a shortcut it clicked, the original target paths have to be restored in order for the shortcut to open up the intended target, otherwise we tank all the shortcuts on the machine. The routine currently is to modify the target paths to the payload > save the original target paths to a file > delay execution for a minute or two > reset the target paths back to the payload. In example this would result in some end user clicked on a chrome shortcut, chrome doesn't open on first click, but on the second attempt it opens. If the delay window before setting the target paths back to the payload is short enough, there is a high likelihood (provided shortcuts are used on the machine) that on a shutdown or logoff event, once a user is back on the machine, we would get a connection back. 

### Method One
This would be the path changing routine implemented inside some type of single payload. For testing the project contains a shellcode loader:

![](img/methodone.png)

### Method Two 
The purpose of method two would be to package some type of payload that does not contian the path changing routine within it. This would require two binaries on disk (a launcher and the payload). Shortcut paths would start the launcher which would handle the path changing routine and starting the payload. For testing the project contains a simple winsock reverse shell with some options as the payload:

![](img/methodtwo.png)

### Usage 
+ If compiling on Linux and don't have the mingw toolchain: `sudo apt install mingw-w64`
+ If you don't already have Nim installed then use [choosenim](https://github.com/dom96/choosenim)
+ `nimble install winim checksums zippy parsetoml`
+ `nimble install https://github.com/nbaertsch/nimvoke`
+ Edit one of the .toml config files. If using `loader.nim` for method one, there are a few hardcoded vars that need to be edited at the top of the file.
+ `pip install -r requirements.txt` 
+ Run the `setup.py` script
+ For shellcode conversion: ` output/converter <.bin file> <"rc4 key">`

#### Options if using rev_shell.nim
Keep in mind that there is no spoofing for shell commands.

+ `[pwsh]` Execute PowerShell without calling powershell.exe. Usage: `pwsh [commands]`
+ `[patch]` AMSI and ETW memory patching
+ `[inject]` Spawn a remote process and inject shellcode: `inject [path to bin] [shellcode str]`
+ `[start_proc]` Start a PPID spoofed process: `start_proc [path to bin]`
+ `[exit]` To smoothly close the connection and process
+ `[?]` To print options

### References 
+ https://github.com/nbaertsch/nimvoke/tree/main
+ https://github.com/byt3bl33d3r/OffensiveNim/tree/master/src
+ https://github.com/chvancooten/NimPlant/tree/main
+ https://github.com/libyal/liblnk/blob/main/documentation/Windows%20Shortcut%20File%20(LNK)%20format.asciidoc
