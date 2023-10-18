# Lattice Mico 32 processor module for IDA Pro 7.7 and 8.3


## Features

* Analysis of the core instruction set as well as pseudo instructions 
* Basic data/code reference detection
* Branch detection
* Stack behavior detection
* 32bit address fusin
* Standard switch jumptable support



## Building

[Windows]

[GUI]
1) Install Visual Studio 2022.
2) Unpack the IDA SDK to a directory on your computer.
3) Clone this repository into the IDA SDK `module` directory.
4) Open the `lm32.sln` solution in Visual Studio and build.
5) Proc modules will be copied into the users %APPDATA\Hex-Rays\IDA Pro\procs folder
6) Copy the `cfg\LM32.cfg` file to your `%APPDATA\Hex-Rays\IDA Pro\cfg` folder and update the definitions as appropriate for your implementation.

[makefile]
1) Configure the `$IDASDK` environment variable.
2) Clone this repository into the `$IDASDK/module` directory.
3) Edit the `$IDASDK/module/makefile` and add the repository directory to `DIRS32`.
4) Follow the IDA SDK build instructions.

## License

The code is licensed under [MIT License](LICENSE) 
