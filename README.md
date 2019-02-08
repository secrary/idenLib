# idenLib - Library Function Identification

When analyzing malware or 3rd party software, it's challenging to identify statically linked libraries and to understand what a function from the library is doing.

[`idenLib.exe`](https://github.com/secrary/idenLib) is a tool for generating library signatures from `.lib` files.

[`idenLib.dp32`](https://github.com/secrary/idenLibX) is a `x32dbg` plugin to identify library functions.

[`idenLib.py`](https://github.com/secrary/IDA-scripts/tree/master/idenLib) is an `IDA Pro` plugin to identify library functions.


##### Any feedback is greatly appreciated: [@_qaz_qaz](https://twitter.com/_qaz_qaz)

## How does idenLib.exe generate signatures?

1. Parse input file(`.lib` file) to get a list of function addresses and function names.
2. Get the last opcode from each instruction

![sig](https://user-images.githubusercontent.com/16405698/52433535-35442500-2b05-11e9-92a2-7ed0dfb319ab.png)

3. Compress the signature with [zstd](https://github.com/facebook/zstd)

4. Save the signature under the `SymEx` directory, if the input filename is `zlib.lib`, the output will be `zlib.lib.sig`,
if `zlib.lib.sig` already exists under the `SymEx` directory from a previous execution or from the previous version of the library, the next execution will append different signatures.
If you execute `idenLib.exe` several times with different version of the `.lib` file, the `.sig` file will include all unique function signatures.

Inside of a signature (it's compressed):
![signature](https://user-images.githubusercontent.com/16405698/52490971-e9a18200-2bbd-11e9-8d29-e85a71826c8f.png)

## Generating library signatures

![lib](https://user-images.githubusercontent.com/16405698/52433541-35dcbb80-2b05-11e9-918a-6d39afc5de91.gif)

## `x32dbg`, `IDAPro` plugin usage:

1. Copy `SymEx` directory under `x32dbg`/`IDA Pro`'s main directory
2. Apply signatures:

`x32dbg`:

![xdb](https://user-images.githubusercontent.com/16405698/52433536-35442500-2b05-11e9-990e-8d4889bfe1c6.gif)

`IDAPro`:

![ida_boost_2](https://user-images.githubusercontent.com/16405698/52433540-35dcbb80-2b05-11e9-9dd3-9bb44d678ea5.gif)


Only `x86` is supported (adding `x64` should be trivial).

Tested on `Windows 10 17763.292`

## Useful links:
- Detailed information about [`C Run-Time Libraries (CRT)`](https://docs.microsoft.com/en-us/cpp/c-runtime-library/crt-library-features);

## Credits
- Disassembly powered by [Zydis](https://zydis.re)
- Compression/Decompression by [zstd](https://github.com/facebook/zstd)
- Icon by [freepik](https://www.flaticon.com/authors/freepik)
