#!/usr/bin/env python3

import sys
import os
import argparse
from collections import OrderedDict
from .skoolkit_controlfile_generator import Disassembler

try:
    from skoolkit.snapshot import get_snapshot
    from skoolkit import tap2sna, sna2skool
except ImportError:
    SKOOLKIT_HOME = os.environ.get('SKOOLKIT_HOME')
    if not SKOOLKIT_HOME:
        sys.stderr.write('SKOOLKIT_HOME is not set; aborting\n')
        sys.exit(1)
    if not os.path.isdir(SKOOLKIT_HOME):
        sys.stderr.write('SKOOLKIT_HOME={}; directory not found\n'.format(SKOOLKIT_HOME))
        sys.exit(1)
    sys.path.insert(0, SKOOLKIT_HOME)
    from skoolkit.snapshot import get_snapshot
    from skoolkit import tap2sna, sna2skool

def main():
	parser = argparse.ArgumentParser(description="Generates a stub Skoolkit control file for the game in the current directory.")
	parser.add_argument("z80_file", help="Path to the Z80 file")
	parser.add_argument("--start", type=lambda x: int(x, 0), required=True, help="Start address for disassembly (in hex)")
	parser.add_argument("--stop", type=lambda x: int(x, 0), required=True, help="Stop address for disassembly (in hex)")
	parser.add_argument("--output", required=True, help="Output filename (without .ctl extension)")

	args = parser.parse_args()

	lines = Disassembler(get_snapshot(args.z80_file), args.start, args.stop)
	ctlfile = 'sources/{}.ctl'.format(args.output)

	with open(ctlfile, 'wt') as f:
		f.write(lines.run())

	print(f"\x1b[1;32mGenerated {ctlfile} successfully.\x1b[0m")

if __name__ == "__main__":
	main()
