# About
Repo for my experiments with payload creation and sideloading/forward sideloading.
**WIP** - will update over time.

Some useful resources:
- [Koppeling](https://github.com/monoxgas/Koppeling)
- [siofra](https://github.com/Cybereason/siofra)
- [Hijacklibs](https://hijacklibs.net)
- [NimDllSideload](https://github.com/byt3bl33d3r/NimDllSideload)

# Compile
```text
nimble install ptr_math winim checksums
nimble install https://github.com/nbaertsch/nimvoke
```
example:
```text
nim c converter.nim 
.\converter.exe sc.bin 'pass'

generate .def file

nim c --app:lib -d:strip -d:ondisk -d:release --passL:"-def:hid.def" --nomain --cc:gcc --passL:-static --out:hid.dll loader_hid_t2.nim
```

