#!/usr/bin/env python3

from num2words import num2words
from typing import List, Dict, Optional
from .constants import ODDBALLS, FLIPPED_ODDBALLS, ADD, ADC, AND, CALL, CP, DEC, INC, JUMP, LOAD_1, LOAD_2, LOAD_3, OR, POP, PUSH, RET, SBC, SUB, XOR, CB_BITS, ED_2, ED_3, ED_4, IX_ADD, IX_ADC, IX_LOAD, IX_CB_BITS, IY_CB_BITS, IY_ADD, IY_ADC, IY_LOAD


class Disassembler:

    def __init__(self, snapshot: bytes, pc: int, end: int, context: Optional[Dict] = None):
        self.snapshot = snapshot
        self._pc = pc
        self._end = end
        self._context = context or ''
        self._toggle = False
        self._aggregate: List[str] = []
        self._lines: List[str] = []

    @property
    def pc(self) -> int:
        return self._pc

    @property
    def end(self) -> int:
        return self._end

    @property
    def context(self) -> str:
        return self._context

    @property
    def toggle(self) -> bool:
        return self._toggle

    @property
    def aggregate(self) -> List[str]:
        return self._aggregate

    @property
    def lines(self) -> List[str]:
        return self._lines

    def get_address(self, addr: int) -> int:
        return self.snapshot[addr] + self.snapshot[addr + 1] * 0x100

    def identify_set_bits(self, byte):
        set_bits = []
        start = None

        # Iterate through each of the 8 bits
        for bit in range(8):
            # Check if the bit is set
            if byte & (1 << bit):
                if start is None:
                    start = bit
            else:
                if start is not None:
                    end = bit - 1
                    set_bits.append(f'{start}-{end}' if start != end else str(start))
                    start = None

        # Check if the last bit(s) in the byte were set
        if start is not None:
            set_bits.append(f'{start}-{7}' if start != 7 else str(start))

        # Format the output.
        output = ', '.join(set_bits)
        return output

    def process_adc_operation(self, cmd: int):
        if cmd == 0xCE:
            self.lines.append(f'  ${self.pc:04X},$02 #REGa+=#N${self.snapshot[self.pc + 0x01]:02X}.')
            self._pc += 0x02
        else:
            self.lines.append(f'  ${self.pc:04X},$01 {ADC[cmd]}.')
            self._pc += 0x01

    def process_add_operation(self, cmd: int):
        if cmd == 0xC6:
            self.lines.append(f'  ${self.pc:04X},$02 #REGa+=#N${self.snapshot[self.pc + 0x01]:02X}.')
            self._pc += 0x02
        else:
            self.lines.append(f'  ${self.pc:04X},$01 {ADD[cmd]}.')
            self._pc += 0x01

    def process_and_operation(self, cmd: int):
        # AND A.
        if cmd == 0xA7:
            self.lines.append(f'  ${self.pc:04X},$01 Set flags.')
            self._pc += 0x01
        # AND nn.
        elif cmd == 0xE6:
            self.lines.append(f'  ${self.pc:04X},$02,b$01 Keep only bits {self.identify_set_bits(self.snapshot[self.pc + 0x01])}.')
            self._pc += 0x02
        # Everything else.
        else:
            self.lines.append(f'  ${self.pc:04X},$01 Merge the bits from {AND[cmd]}.')
            self._pc += 0x01

    def process_call_operation(self, cmd: int):
        # "Normal" call.
        if cmd == 0xCD:
            self.lines.append(f'  ${self.pc:04X},$03 Call #R${self.get_address(self.pc + 0x01):04X}.')
        # Everything else.
        else:
            self.lines.append(f'  ${self.pc:04X},$03 Call #R${self.get_address(self.pc + 0x01):04X} {CALL[cmd]}.')
        self._pc += 0x03

    def process_cb_operation(self, cmd: int):
        cmd = self.snapshot[self.pc + 0x01]
        self.lines.append(f'  ${self.pc:04X},$02 {CB_BITS[cmd]}.')
        self._pc += 0x2

    def process_compare_operation(self, cmd: int):
        self._context = '#REGa'
        if cmd == 0xFE:
            self.lines.append(
                '  ${:X},$02 Compare #REGa with #N${:02X}.'.format(self.pc, self.snapshot[self.pc + 0x01]))
            self._pc += 0x02
        else:
            self.lines.append('  ${:X},$01 Compare #REGa with {}.'.format(self.pc, CP[cmd]))
            self._pc += 0x01

    def process_decrease_operation(self, cmd: int):
        self._context = DEC[cmd]
        count = 0x00
        while self.snapshot[self.pc + count] == cmd:
            count += 0x01
        self.lines.append(f'  ${self.pc:04X},${count:02X} Decrease {self.context} by {num2words(count)}.')
        self._pc += count

    def process_djnz_operation(self, cmd: int):
        self.lines.append(
            '  ${:X},$02 Decrease counter by one and loop back to #R${:04X} until counter is zero.'
            .format(self.pc, self.pc + 2 + (
                self.snapshot[self.pc + 0x01] - 0x100 if self.snapshot[self.pc + 0x01] >= 0x80 else
                self.snapshot[self.pc + 0x01])))
        self._pc += 0x02

    def process_ed_operation(self, cmd: int):
        cmd = self.snapshot[self.pc + 0x01]
        if cmd in ED_2:
            self.lines.append('  ${:X},$02 {}.'.format(self.pc, ED_2[cmd]))
            self._pc += 0x02
        elif cmd in ED_4:
            self.lines.append('  ${:X},$04 {}.'.format(self.pc, ED_4[cmd]).format(self.get_address(self.pc + 0x02)))
            self._pc += 0x04

    def process_increment_operation(self, cmd: int):
        self._context = INC[cmd]
        count = 0x00
        while self.snapshot[self.pc + count] == cmd:
            count += 0x01
        self.lines.append(f'  ${self.pc:04X},${count:02X} Increment {self.context} by {num2words(count)}.')
        self._pc += count

    def process_ix_operation(self, cmd: int):
        cmd = self.snapshot[self.pc + 0x01]
        if cmd in IX_LOAD:
            if cmd in [0x46, 0x4E, 0x56, 0x5E, 0x66, 0x6E, 0x7E]:
                self.lines.append('  ${:X},$03 {}=*#REGix+#N${:02X}.'.format(self.pc, IX_LOAD[cmd],
                                                                              self.snapshot[self.pc + 0x02]))
                self._pc += 0x03
            elif cmd in [0x36]:
                self.lines.append('  ${:X},$04 Write #N${:02X} to {}+#N${:02X}.'.format(self.pc,
                                                                                        self.snapshot[
                                                                                            self.pc + 0x03],
                                                                                        IX_LOAD[cmd],
                                                                                        self.snapshot[
                                                                                            self.pc + 0x02]))
                self._pc += 0x04
            elif cmd in [0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x77]:
                self.lines.append('  ${:X},$03 Write {} to *#REGix+#N${:02X}.'.format(self.pc, IX_LOAD[cmd],
                                                                              self.snapshot[self.pc + 0x02]))
                self._pc += 0x03
            else:
                value = self.get_address(self.pc + 0x02)
                self.lines.append('  ${:X},$04 {}=#R${:X}.'.format(self.pc, IX_LOAD[cmd], value))
                self._pc += 0x04
        elif cmd == 0xA6:
            self.lines.append(
                '  ${:X},$03 Merge the bits of #REGa with *#REGix+#N${:02X}.'.format(self.pc,
                                                                                   self.snapshot[
                                                                                       self.pc + 0x02]))
            self._pc += 0x03
        elif cmd in IX_ADD:
            self.lines.append('  ${:X},$02 {}.'.format(self.pc, IX_ADD[cmd]))
            self._pc += 0x02
        elif cmd in IX_ADC:
            self.lines.append('  ${:X},$03 {}.'.format(self.pc, IX_ADC[cmd]).format(self.snapshot[self.pc + 0x02]))
            self._pc += 0x03
        elif cmd == 0x34:
            self.lines.append('  ${:X},$03 Increment *#REGix+#N${:02X} by one.'.format(self.pc, self.snapshot[self.pc + 0x02]))
            self._pc += 0x03
        elif cmd == 0x35:
            self.lines.append('  ${:X},$03 Decrease *#REGix+#N${:02X} by one.'.format(self.pc, self.snapshot[self.pc + 0x02]))
            self._pc += 0x03
        elif cmd == 0xB6:
            self.lines.append(
                '  ${:X},$03 Set the bits of #REGa with *#REGix+#N${:02X}.'.format(self.pc,
                                                                           self.snapshot[self.pc + 0x02]))
            self._pc += 0x03
        elif cmd == 0xBE:
            self.lines.append(
                '  ${:X},$03 Compare #REGa with *#REGix+#N${:02X}.'.format(self.pc, self.snapshot[self.pc + 0x02]))
            self._pc += 0x03
        elif cmd == 0xE1:
            self.lines.append('  ${:X},$02 Restore #REGix from the stack.'.format(self.pc))
            self._pc += 0x02
        elif cmd == 0xE5:
            self.lines.append('  ${:X},$02 Stash #REGix on the stack.'.format(self.pc))
            self._pc += 0x02
        elif cmd == 0xCB:
            cmd = self.snapshot[self.pc + 0x03]
            value = self.snapshot[self.pc + 0x02]
            self.lines.append('  ${:X},$04 {}.'.format(self.pc, IX_CB_BITS[cmd]).format(value))
            self._pc += 0x04

    def process_iy_operation(self, cmd: int):
        cmd = self.snapshot[self.pc + 0x01]
        if cmd in IY_LOAD:
            if cmd in [0x46, 0x4E, 0x56, 0x5E, 0x66, 0x6E, 0x7E]:
                self.lines.append('  ${:X},$03 {}=*#REGiy+#N${:02X}.'.format(self.pc, IY_LOAD[cmd],
                                                                              self.snapshot[self.pc + 0x02]))
                self._pc += 0x03
            elif cmd in [0x36]:
                self.lines.append('  ${:X},$04 Write #N${:02X} to {}+#N${:02X}.'.format(self.pc,
                                                                                        self.snapshot[
                                                                                            self.pc + 0x03],
                                                                                        IY_LOAD[cmd],
                                                                                        self.snapshot[
                                                                                            self.pc + 0x02]))
                self._pc += 0x04
            elif cmd in [0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x77]:
                self.lines.append('  ${:X},$03 Write {} to *#REGiy+#N${:02X}.'.format(self.pc, IY_LOAD[cmd],
                                                                              self.snapshot[self.pc + 0x02]))
                self._pc += 0x03
            else:
                value = self.get_address(self.pc + 0x02)
                self.lines.append('  ${:X},$04 {}=#R${:X}.'.format(self.pc, IY_LOAD[cmd], value))
                self._pc += 0x04
        elif cmd == 0xA6:
            self.lines.append(
                '  ${:X},$03 Merge the bits of #REGa with *#REGiy+#N${:02X}.'.format(self.pc,
                                                                                   self.snapshot[
                                                                                       self.pc + 0x02]))
            self._pc += 0x03
        elif cmd in IY_ADD:
            self.lines.append('  ${:X},$02 {}.'.format(self.pc, IY_ADD[cmd]))
            self._pc += 0x02
        elif cmd in IY_ADC:
            self.lines.append('  ${:X},$03 {}.'.format(self.pc, IY_ADC[cmd]).format(self.snapshot[self.pc + 0x02]))
            self._pc += 0x03
        elif cmd == 0x34:
            self.lines.append('  ${:X},$03 Increment *#REGiy+#N${:02X} by one.'.format(self.pc, self.snapshot[self.pc + 0x02]))
            self._pc += 0x03
        elif cmd == 0x35:
            self.lines.append('  ${:X},$03 Decrease *#REGiy+#N${:02X} by one.'.format(self.pc, self.snapshot[self.pc + 0x02]))
            self._pc += 0x03
        elif cmd == 0xB6:
            self.lines.append(
                '  ${:X},$03 Set the bits of #REGa with *#REGiy+#N${:02X}.'.format(self.pc,
                                                                           self.snapshot[self.pc + 0x02]))
            self._pc += 0x03
        elif cmd == 0xBE:
            self.lines.append(
                '  ${:X},$03 Compare #REGa with *#REGiy+#N${:02X}.'.format(self.pc, self.snapshot[self.pc + 0x02]))
            self._pc += 0x03
        elif cmd == 0xE1:
            self.lines.append('  ${:X},$02 Restore #REGiy from the stack.'.format(self.pc))
            self._pc += 0x02
        elif cmd == 0xE5:
            self.lines.append('  ${:X},$02 Stash #REGiy on the stack.'.format(self.pc))
            self._pc += 0x02
        elif cmd == 0xCB:
            cmd = self.snapshot[self.pc + 0x03]
            value = self.snapshot[self.pc + 0x02]
            self.lines.append('  ${:X},$04 {}.'.format(self.pc, IY_CB_BITS[cmd]).format(value))
            self._pc += 0x04

    def process_jump_operation(self, cmd: int):
        # JR calls.
        if cmd < 0x40:
            if cmd == 0x18:
                self.lines.append('  ${:X},$02 Jump to #R${:04X}.'
                                  .format(self.pc, self.pc + 0x02 + (
                    self.snapshot[self.pc + 0x01] - 0x100 if self.snapshot[self.pc + 0x01] >= 0x80 else
                    self.snapshot[self.pc + 0x01])))
            else:
                self.lines.append('  ${:X},$02 Jump to #R${:04X} {}.'
                                  .format(self.pc, self.pc + 0x02 + (
                    self.snapshot[self.pc + 0x01] - 0x100 if self.snapshot[self.pc + 0x01] >= 0x80 else
                    self.snapshot[self.pc + 0x01]), JUMP[cmd]).format(self.context))
            self._pc -= 0x01
        # "Normal" call.
        elif cmd == 0xC3:
            self.lines.append(
                '  ${:X},$03 Jump to #R${:X}.'.format(self.pc, self.get_address(self.pc + 0x01), JUMP[cmd]))
        # Everything else.
        else:
            self.lines.append(
                '  ${:X},$03 Jump to #R${:X} {}.'.format(self.pc, self.get_address(self.pc + 0x01), JUMP[cmd]).format(self.context))
        self._pc += 0x03

    def process_load_1_operation(self, cmd: int):
        self.lines.append('  ${:X},$01 {}.'.format(self.pc, LOAD_1[cmd]))
        self._pc += 0x01

    def process_load_2_operation(self, cmd: int):
        if cmd == 0x36:
            self.lines.append(
                '  ${:X},$02 Write #N${:02X} to *#REGhl.'.format(self.pc, self.snapshot[self.pc + 0x01]))
        else:
            self.lines.append(
                '  ${:X},$02 {}=#N${:02X}.'.format(self.pc, LOAD_2[cmd], self.snapshot[self.pc + 0x01]))
        self._pc += 0x02

    def process_load_3_operation(self, cmd: int):
        value = self.get_address(self.pc + 0x01)
        if cmd in [0x22, 0x32]:
            if value > 0x5B00:
                self.lines.append('  ${:X},$03 Write {} to *#R${:X}.'.format(self.pc, LOAD_3[cmd], value))
            elif value >= 0x5800:
                self.lines.append(
                    '  ${:X},$03 Write {} to *#N${:04X} (attribute buffer location).'.format(self.pc, LOAD_3[cmd], value))
            elif value >= 0x4000:
                self.lines.append(
                    '  ${:X},$03 Write {} to *#N${:04X} (screen buffer location).'.format(self.pc, LOAD_3[cmd], value))
            else:
                self.lines.append(
                    '  ${:X},$03 Write {} to *#N(${:04X},$04,$04).'.format(self.pc, LOAD_3[cmd], value))
        elif cmd in [0x2A, 0x3A]:
            if value > 0x5B00:
                self.lines.append('  ${:X},$03 {}=*#R${:X}.'.format(self.pc, LOAD_3[cmd], value))
            elif value >= 0x5800:
                self.lines.append('  ${:X},$03 {}=*#N${:04X} (attribute buffer location).'.format(self.pc, LOAD_3[cmd], value))
            elif value >= 0x4000:
                self.lines.append('  ${:X},$03 {}=*#N${:04X} (screen buffer location).'.format(self.pc, LOAD_3[cmd], value))
            else:
                self.lines.append('  ${:X},$03 {}=*#N(${:04X},$04,$04).'.format(self.pc, LOAD_3[cmd], value))
        else:
            if value > 0x5B00:
                self.lines.append('  ${:X},$03 {}=#R${:X}.'.format(self.pc, LOAD_3[cmd], value))
            elif value > 0x5800:
                self.lines.append('  ${:X},$03 {}=#N${:X} (attribute buffer location).'.format(self.pc, LOAD_3[cmd], value))
            elif value > 0x4000:
                self.lines.append('  ${:X},$03 {}=#N${:X} (screen buffer location).'.format(self.pc, LOAD_3[cmd], value))
            else:
                self.lines.append('  ${:X},$03 {}=#N(${:04X},$04,$04).'.format(self.pc, LOAD_3[cmd], value))
        self._pc += 0x03

    def process_oddballs_operation(self, cmd: int):
        if cmd in [0x08, 0xD9] and self.toggle:
            self.lines.append(f'  ${self.pc:04X},$01 {FLIPPED_ODDBALLS[cmd]}.')
        else:
            self.lines.append(f'  ${self.pc:04X},$01 {ODDBALLS[cmd]}.')
        self._toggle = not self.toggle
        self._pc += 0x01

    def process_or_operation(self, cmd: int):
        if cmd == 0xF6:
            self.lines.append('  ${:X},$02,b$01 Set bits {}.'.format(self.pc, self.identify_set_bits(
                self.snapshot[self.pc + 0x01])))
            self._pc += 0x02
        else:
            self.lines.append('  ${:X},$01 Set the bits from {}.'.format(self.pc, OR[cmd]))
            self._pc += 0x01

    def process_out_operation(self, cmd: int):
        value = self.get_address(self.pc + 0x01)
        if value == 0xFE:
            self.lines.append('  ${:X},$02 Set border to #COLOUR${:02X}.'.format(self.pc, value))
        else:
            self.lines.append('  ${:X},$02 OUT #N${:02X}'.format(self.pc, value))
        self._pc += 0x02

    def process_pop_operation(self, cmd: int):
        registers = []
        count = 0x00
        while self.snapshot[self.pc + count] in POP:
            registers.append(POP[self.snapshot[self.pc + count]])
            count += 0x01
        self.lines.append('  ${:X},${:02X} Restore {} from the stack.'
                          .format(self.pc, count, ' and '
                                  .join(filter(None, [', '.join(registers[:-1])] + registers[-1:])), count))
        self._pc += count

    def process_push_operation(self, cmd: int):
        registers = []
        count = 0x00
        while self.snapshot[self.pc + count] in PUSH:
            registers.append(PUSH[self.snapshot[self.pc + count]])
            count += 0x01
        self.lines.append('  ${:X},${:02X} Stash {} on the stack.'
                          .format(self.pc, count, ' and '
                                  .join(filter(None, [', '.join(registers[:-1])] + registers[-1:])), count))
        self._pc += count

    def process_return_operation(self, cmd: int):
        self.lines.append(f'  ${self.pc:04X},$01 {RET[cmd]}.')
        self._pc += 0x01

    def process_sbc_operation(self, cmd: int):
        if cmd == 0xDE:
            self.lines.append('  ${:X},$02 #REGa-=#N${:02X}.'.format(self.pc, self.snapshot[self.pc + 0x01]))
        else:
            self.lines.append('  ${:X},$01 {}.'.format(self.pc, SBC[cmd]))
            self._pc += 0x01

    def process_sub_operation(self, cmd: int):
        if cmd == 0xD6:
            self.lines.append('  ${:X},$02 #REGa-=#N${:02X}.'.format(self.pc, self.snapshot[self.pc + 0x01]))
            self._pc += 0x02
        else:
            self.lines.append('  ${:X},$01 {}.'.format(self.pc, SUB[cmd]))
            self._pc += 0x01

    def process_xor_operation(self, cmd: int):
        if cmd == 0xAF:
            self.lines.append(f'  ${self.pc:04X},$01 #REGa=#N$00.')
            self._pc += 0x01
        elif cmd == 0xEE:
            self.lines.append('  ${:X},$02,b$01 Flip bits {}.'.format(self.pc, self.identify_set_bits(
                self.snapshot[self.pc + 0x01])))
            self._pc += 0x02
        else:
            self.lines.append(f'  ${self.pc:04X},$01 Flip the bits according to {XOR[cmd]}.')
            self._pc += 0x01

    def run(self) -> str:
        while self.pc <= self.end:
            try:
                cmd = self.snapshot[self.pc]
                #print(hex(cmd))
                # Oddballs.
                if cmd in ODDBALLS:
                    self.process_oddballs_operation(cmd)
                # LD (1 byte) operations.
                elif cmd in LOAD_1:
                    self.process_load_1_operation(cmd)
                # LD (2 byte) operations.
                elif cmd in LOAD_2:
                    self.process_load_2_operation(cmd)
                # LD (3 byte) operations.
                elif cmd in LOAD_3:
                    self.process_load_3_operation(cmd)
                # PUSH operations.
                elif cmd in PUSH:
                    self.process_push_operation()
                # POP operations.
                elif cmd in POP:
                    self.process_pop_operation()
                # ADC operations.
                elif cmd in ADC:
                    self.process_adc_operation()
                # ADD operations.
                elif cmd in ADD:
                    self.process_add_operation(cmd)
                # AND operations.
                elif cmd in AND:
                    self.process_and_operation(cmd)
                # CALL operations.
                elif cmd in CALL:
                    self.process_call_operation(cmd)
                # CB (bit) operations.
                elif cmd == 0xCB:
                    self.process_cb_operation(cmd)
                # CP operations.
                elif cmd in CP:
                    self.process_compare_operation(cmd)
                # DEC operations.
                elif cmd in DEC:
                    self.process_decrease_operation(cmd)
                # DJNZ.
                elif cmd in [0x10]:
                    self.process_djnz_operation(cmd)
                # ED operations.
                elif cmd == 0xED:
                    self.process_ed_operation(cmd)
                # INC operations.
                elif cmd in INC:
                     self.process_increment_operation(cmd)
                # IX instructions.
                elif cmd == 0xDD:
                    self.process_ix_operation(cmd)
                # IY instructions.
                elif cmd == 0xFD:
                    self.process_iy_operation(cmd)
                # JUMP operations.
                elif cmd in JUMP:
                    self.process_jump_operation(cmd)
                # OR operations.
                elif cmd in OR:
                    self.process_or_operation(cmd)
                # OUT operation.
                elif cmd in [0xD3]:
                    self.process_out_operation(cmd)
                # Return operation.
                elif cmd in RET:
                    self.process_return_operation(cmd)
                # SBC operations.
                elif cmd in SBC:
                    self.process_sbc_operation(cmd)
                # SUB operations.
                elif cmd in SUB:
                    self.process_sub_operation(cmd)
                # XOR operations.
                elif cmd in XOR:
                     self.process_xor_operation(cmd)
                else:
                    self.process_unknown_operation(cmd)
            except IndexError:
                print(f"Error: Attempted to access memory out of bounds at PC=${self.pc:04X}")
                break
        return '\n'.join(self.lines)

    def process_unknown_operation(self, cmd: int):
        print(f"UNKNOWN ${cmd:02X}")
        self._pc += 1
