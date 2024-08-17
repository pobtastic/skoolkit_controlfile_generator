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
  -v, --verbose    Show more details
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

And the output file will be written to the /sources directory.

### Example

```
disassemble --start 0xD602 --stop 0xD60B --output disassemble Booty.z80
```

Will create the following output in sources/disassemble.ctl:
```
  $D602,$01 Restore #REGbc from the stack.
  $D603,$02 #REGa=#N$03.
  $D605,$03 Write #REGa to *#R$5BF0.
  $D608,$03 Call #R$DEA8.
  $D60B,$03 Jump to #R$CD86.
```

The more "correct" version of this output would be:
```
c $D602 Demo Mode
@ $D602 label=DemoMode
  $D602,$01 Restore #REGbc from the stack.
  $D603,$05 Write "Demo Mode" (#N$03) to #R$5BF0.
  $D608,$03 Call #R$DEA8.
  $D60B,$03 Jump to #R$CD86.
```

As you start to interpret the code, you can group commands together and
eventually name the functionality.

Obviously this program cannot distinguish between data and instruction
code, so only use it where the start and end points are known to be
instructions (else your output will be garbage).
