# LatticeMico32 processor module for IDA Pro 7.7 and 8.3

This is a processor module for LM32 mostly generated from 
[CGEN](https://github.com/yifanlu/cgen) with lots of hand coding to fix
the autonomous abominations... very little of the original cgen generated code remains.

## Features

* Analysis of the core instruction set 
* Basic data/code reference detection
* Basic branch detection
* Basic stack behavior detection
* Standard switch jumptable support
* 32bit address fusing



## Building

[Windows]

[GUI]
1) Install Visual Studio 2022.
2) Unpack the IDA SDK to a directory on your computer.
3) Clone this repository into the IDA SDK `module` directory.
4) Open the `vs\lm32.sln` solution in Visual Studio and build. There are targets for debug and release for both 32bit and 64bit.
5) Proc modules will be copied into the users %APPDATA\Hex-Rays\IDA Pro\procs folder
6) Copy the cfg/LM32.cfg file to your %APPDATA\Hex-Rays\IDA Pro\cfg folder and update the definitions as appropriate for your implementation.

[Non-Windows]

[makefile]
1) Configure the `$IDASDK` environment variable.
2) Clone this repository into the `$IDASDK/module` directory.
3) Edit the `$IDASDK/module/makefile` and add the repository directory to `DIRS32`.
4) Follow the IDA SDK build instructions.
5) Copy files from bin/procs to your appropriate location

## License

The code is licensed under [MIT License](LICENSE) as permitted by the special 
exception to GPLv3 specified by CGEN. The CGEN headers included are licensed 
under GPLv3, however the FSF 
[said](http://lkml.iu.edu/hypermail/linux/kernel/0301.1/0362.html) previously 
that headers does not count as derivative work.
