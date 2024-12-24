# About 
This project is my experimentation with gaining persistence on a machine through swapping target paths back and forth on already existing [LNK/shortcut](https://github.com/libyal/liblnk/blob/main/documentation/Windows%20Shortcut%20File%20(LNK)%20format.asciidoc) files. The goal here is to not mess around with the startup directories, avoid creating any new .LNKs, avoid messing with arguments, and purley rely on a user clicking on a shortcut. Currently the `modifyAllLnkPaths` and `restoreOrigLnkPaths` functions in `lnks.nim` are set to target the Desktop, TaskBar, and Start Menu shortcuts. This current implementation was put into a reverse shell that I put together for testing and learning.
```
┌────────────────────────┐             ┌────────────────────────┐                      
│ Implant                │             │ LNK file               │                      
│                        │             │                        │                      
└────────────────────────┘             └────────────────────────┘                      
│┌──────────────────────┐│             │┌──────────────────────┐│                      
││Target paths are set  ││             ││Target path set to the││◄───── User clicks LNK
││back to the intended  │◄─────────────┼┤implant is executed   ││       + Nothing opens
│└──────────────┬───────┘│             │└──────────────────────┘│                      
│               │        │             │                        │                      
│ Execution Delayed      │             │┌──────────────────────┐│                      
│               └────────┼─────────────►│LNK back to original  ││◄───── User clicks LNK
│                        │             │└──────────────────────┘│       + Program opens
│ + Pull in winsock funcs│             │                        │                      
│ + Connect back         │             │                        │                      
│ + Do stuff             │             │                        │                      
│┌──────────────────────┐│             │┌──────────────────────┐│                      
││Use 'exit_persist'    ├┼─────────────►│Target set to implant ││                      
│└──────────────────────┘│             │└──────────────────────┘│                      
│┌──────────────────────┐│             └────────────────────────┘                      
││Use 'exit'            ││                                                             
││+ Exit without edit   ││                                                             
││  to target paths     ││                                                             
│└──────────────────────┘│                                                             
└────────────────────────┘                                                             
```
A few problems with this example: If target paths are set to the implant's path and a user clicks and executes it, but no connection is made to a listener, then the program will set the target paths back to itself before exiting. This would happen over and over again depending on the shortcut click rate of the user and the execution delay time that has been set. It would look weird as it would take a second click each time to open the intended program. 

## Usage 
+ `nimble install winim checksums`
+ `nimble install https://github.com/nbaertsch/nimvoke`
+ `python compile.py`

## Reverse Shell
Before tooling around with some persistence techniques regarding LNK files, I had been putting together this reverse shell as something that I can quickly compile and use on boxes with defender in CTF challenges. It works well for this at the time of writing, just use something to pack it. Credit to both [nimplant](https://github.com/chvancooten/NimPlant/tree/main) and the [offensive Nim](https://github.com/byt3bl33d3r/OffensiveNim/tree/master/src) projects, as a good amount of the code regarding the features like injection etc., came from/edited from those projects. Indirect system calls and DInvoke-style delegate declarations were done using [nimvoke](https://github.com/nbaertsch/nimvoke/tree/main).

**Options once connected:**
+ `[exit]` Exit without changing target paths
+ `[exit_persist]` Exit and set target paths back to the implant
+ `[pwsh]` Execute powershell commands through the System.Management.Automation assembly
+ `[patch]` AMSI and ETW memory patches
+ `[inject]` Spawn a remote process and inject shellcode.
+ `[start_proc]` Start a PPID spoofed process
+ `[?]` Print options

For the `inject` command run:
>> `converter.exe sc.bin "<key>"` 
>> copy output
>> `[LP_SHELL] > inject C:\path\to\bin.exe <b64 blob>`
