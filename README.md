# idenLib - Library Function Identification

When analyzing malware or 3rd party software, it's challenging to identify statically linked libraries and to understand what a function from the library is doing.

[`idenLib.exe`](https://github.com/secrary/idenLib) is a tool for generating library signatures from `.lib`/`.obj`/`.exe`/`.dll` files.

[`idenLib.dp32`/`idenLib.dp64`](https://github.com/secrary/idenLibX) is a [`x32dbg`/`x64dbg`](https://x64dbg.com) plugin to identify library functions.

[`idenLib.py`](https://github.com/secrary/IDA-scripts/tree/master/idenLib) is an [`IDA Pro`](https://www.hex-rays.com/products/ida/index.shtml) plugin to identify library functions.


##### Any feedback is greatly appreciated: [@_qaz_qaz](https://twitter.com/_qaz_qaz)

## How does idenLib.exe generate signatures?

1. Parses input file(`.lib`/`.obj` file) to get a list of function addresses and function names.
2. Gets the last opcode from each instruction

![sig](https://user-images.githubusercontent.com/16405698/52433535-35442500-2b05-11e9-92a2-7ed0dfb319ab.png)

3. Compresses the signature with [zstd](https://github.com/facebook/zstd)

4. Saves the signature under the `SymEx` directory, if the input filename is `zlib.lib`, the output will be `zlib.lib.sig` or `zlib.lib.sig64`,
if `zlib.lib.sig(64)` already exists under the `SymEx` directory from a previous execution or from the previous version of the library, the next execution will append different signatures.
If you execute `idenLib.exe` several times with different version of the `.lib` file, the `.sig`/`sig64` file will include all unique function signatures.

Inside of a signature (it's compressed):
![signature](https://user-images.githubusercontent.com/16405698/52490971-e9a18200-2bbd-11e9-8d29-e85a71826c8f.png)

## Usage:
- Generate library signatures: `idenLib.exe /path/to/file` or `idenLib.exe /path/to/directory`
- Generate `main` function signature: `idenLib.exe /path/to/pe`

## Generating library signatures

![lib](https://user-images.githubusercontent.com/16405698/52433541-35dcbb80-2b05-11e9-918a-6d39afc5de91.gif)

## [`x32dbg`/`x64dbg`](https://x64dbg.com), [`IDA Pro`](https://www.hex-rays.com/products/ida/index.shtml) plugin usage:

1. Copy `SymEx` directory under `x32dbg`/`x64dbg`/`IDA Pro`'s main directory
2. Apply signatures:

[`x32dbg`/`x64dbg`](https://github.com/secrary/idenLibX):

![xdb](https://user-images.githubusercontent.com/16405698/52433536-35442500-2b05-11e9-990e-8d4889bfe1c6.gif)

[`IDA Pro`](https://github.com/secrary/IDA-scripts/tree/master/idenLib):

![ida_boost_2](https://user-images.githubusercontent.com/16405698/52433540-35dcbb80-2b05-11e9-9dd3-9bb44d678ea5.gif)

## Generating `main` function signature:
If you want to generate a signature for `main` function compiled using `MSVC 14` you need to create a  `hello world` application with the corresponding compiler and use the application as input for `idenLib`

[gif]

`main` function signature files are `EntryPointSignatures.sig` and `EntryPointSignatures.sig64`

![IDAProMain](https://user-images.githubusercontent.com/16405698/53022517-3c4b2b80-3453-11e9-9e0a-5d1421f9c8f3.gif)

## TODO
At this moment, only `IDA Pro` plugin supports finding `main` functions

## NOTE
`idenLib` uses the `DIA APIs` to browse debug information stored in a PDB file. To run `idenLib` with `-getmain` parameter you will need to ensure that the msdia140.dll (found in `Microsoft Visual Studio\2017\Community\DIA SDK\bin`) is registered as a COM component, by invoking regsvr32.exe on the dll. 

Supports [`x86`](https://en.wikipedia.org/wiki/X86) and [`AMD64/x86-64`](https://en.wikipedia.org/wiki/X86-64) architectures.

## Useful links:
- Detailed information about [`C Run-Time Libraries (CRT)`](https://docs.microsoft.com/en-us/cpp/c-runtime-library/crt-library-features);

## Credits
- Disassembly by [Zydis](https://zydis.re)
- Compression by [zstd](https://github.com/facebook/zstd)
- Icon by [freepik](https://www.flaticon.com/authors/freepik)
