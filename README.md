# Skoolkit Control File Generator

Generates a stub Skoolkit control file for the game in the current directory.

The generated code will need manipulating, as it's just "dumb" output and has
no context of binding commands together (nor can it tell what they actually
do).

The idea here, is that this script provides you with enough "flow" to be able
to more quickly interpret the code and change it to a fuller disassembly.

## Installation

To install this package locally, navigate to the package directory and run:

pip install .

## Usage

```
$ disassemble --help
usage: disassemble [-h] --start START --stop STOP --output OUTPUT z80_file

Generates a stub Skoolkit control file for the game in the current directory.

positional arguments:
  z80_file         Path to the Z80 file

options:
  -h, --help       show this help message and exit
  --start START    Start address for disassembly (in hex)
  --stop STOP      Stop address for disassembly (in hex)
  --output OUTPUT  Output filename (without .ctl extension)
```

The code does expect your Skoolkit code to be in a certain format:

```
.
└───Game.z80
└───sources
    ├───game.ctl
    ├───game.ref
    ├───game.skool
```

The output file will be written to the /sources directory.
