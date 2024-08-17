

ODDBALLS = {
    0x00: "No operation",
    0x07: "RLCA",
    0x08: "Exchange the #REGaf register with the shadow #REGaf register",
    0x0F: "RRCA",
    0x17: "RLA",
    0x1F: "RRA",
    0x27: "DAA",
    0x2F: "Invert the bits in #REGa",
    0x37: "Set the carry flag",
    0x3F: "Invert the carry flag",
    0x76: "Halt operation (suspend CPU until the next interrupt)",
    0xD9: "Switch to the shadow registers",
    0xE3: "Exchange the *#REGsp with the #REGhl register",
    0xEB: "Exchange the #REGde and #REGhl registers",
    0xF3: "Disable interrupts",
    0xFB: "Enable interrupts",
}

FLIPPED_ODDBALLS = {
    0x08: "Exchange the shadow #REGaf register with the #REGaf register",
    0xD9: "Switch back to the normal registers",
}

ADD = {
    0x09: "#REGhl+=#REGbc",
    0x19: "#REGhl+=#REGde",
    0x29: "#REGhl+=#REGhl",
    0x39: "#REGhl+=#REGsp",
    0x80: "#REGa+=#REGb",
    0x81: "#REGa+=#REGc",
    0x82: "#REGa+=#REGd",
    0x83: "#REGa+=#REGe",
    0x84: "#REGa+=#REGh",
    0x85: "#REGa+=#REGl",
    0x86: "#REGa+=*#REGhl",
    0x87: "#REGa+=#REGa",
    0xC6: "nn",
}

ADC = {
    0x88: "#REGa+=#REGb",
    0x89: "#REGa+=#REGc",
    0x8A: "#REGa+=#REGd",
    0x8B: "#REGa+=#REGe",
    0x8C: "#REGa+=#REGh",
    0x8D: "#REGa+=#REGl",
    0x8E: "#REGa+=*#REGhl",
    0x8F: "#REGa+=#REGa",
    0xCE: "nn",
}

AND = {
    0xA0: "#REGb",
    0xA1: "#REGc",
    0xA2: "#REGd",
    0xA3: "#REGe",
    0xA4: "#REGh",
    0xA5: "#REGl",
    0xA6: "*#REGhl",
    0xA7: "#REGa",
    0xE6: "nn",
}

CALL = {
    0xC4: "not zero",
    0xCC: "zero",
    0xCD: "nn",
    0xD4: "is higher",
    0xDC: "is lower",
    0xE4: "is odd",
    0xEC: "is even",
    0xF4: "P",
    0xFC: "M",
}

CP = {
    0xB8: "#REGb",
    0xB9: "#REGc",
    0xBA: "#REGd",
    0xBB: "#REGe",
    0xBC: "#REGh",
    0xBD: "#REGl",
    0xBE: "*#REGhl",
    0xBF: "#REGa",
    0xFE: "nn",
}

DEC = {
    0x05: "#REGb",
    0x0B: "#REGbc",
    0x0D: "#REGc",
    0x15: "#REGd",
    0x1B: "#REGde",
    0x1D: "#REGe",
    0x25: "#REGh",
    0x2B: "#REGhl",
    0x2D: "#REGl",
    0x35: "*#REGhl",
    0x3B: "#REGsp",
    0x3D: "#REGa",
}

INC = {
    0x03: "#REGbc",
    0x04: "#REGb",
    0x0C: "#REGc",
    0x13: "#REGde",
    0x14: "#REGd",
    0x1C: "#REGe",
    0x23: "#REGhl",
    0x24: "#REGh",
    0x2C: "#REGl",
    0x33: "#REGsp",
    0x34: "*#REGhl",
    0x3C: "#REGa",
}

JUMP = {
    0x18: "nn",
    0x20: "if {} is not zero",
    0x28: "if {} is zero",
    0x30: "if {} is higher",
    0x38: "if {} is lower",
    0xC2: "if {} is not zero",
    0xC3: "nn",
    0xCA: "if {} is zero",
    0xD2: "if {} is higher",
    0xDA: "if {} is lower",
    0xE2: "if {} is odd",
    0xE9: "*#REGhl",
    0xEA: "if {} is even",
    0xF2: "P",
    0xFA: "M",
}

LOAD_1 = {
    0x02: "Write #REGa to *#REGbc",
    0x0A: "#REGa=*#REGbc",
    0x12: "Write #REGa to *#REGde",
    0x1A: "#REGa=*#REGde",
    0x40: "#REGb=#REGb",
    0x41: "#REGb=#REGc",
    0x42: "#REGb=#REGd",
    0x43: "#REGb=#REGe",
    0x44: "#REGb=#REGh",
    0x45: "#REGb=#REGl",
    0x46: "#REGb=*#REGhl",
    0x47: "#REGb=#REGa",
    0x48: "#REGc=#REGb",
    0x49: "#REGc=#REGc",
    0x4A: "#REGc=#REGd",
    0x4B: "#REGc=#REGe",
    0x4C: "#REGc=#REGh",
    0x4D: "#REGc=#REGl",
    0x4E: "#REGc=*#REGhl",
    0x4F: "#REGc=#REGa",
    0x50: "#REGd=#REGb",
    0x51: "#REGd=#REGc",
    0x52: "#REGd=#REGd",
    0x53: "#REGd=#REGe",
    0x54: "#REGd=#REGh",
    0x55: "#REGd=#REGl",
    0x56: "#REGd=*#REGhl",
    0x57: "#REGd=#REGa",
    0x58: "#REGe=#REGb",
    0x59: "#REGe=#REGc",
    0x5A: "#REGe=#REGd",
    0x5B: "#REGe=#REGe",
    0x5C: "#REGe=#REGh",
    0x5D: "#REGe=#REGl",
    0x5E: "#REGe=*#REGhl",
    0x5F: "#REGe=#REGa",
    0x60: "#REGh=#REGb",
    0x61: "#REGh=#REGc",
    0x62: "#REGh=#REGd",
    0x63: "#REGh=#REGe",
    0x64: "#REGh=#REGh",
    0x65: "#REGh=#REGl",
    0x66: "#REGh=*#REGhl",
    0x67: "#REGh=#REGa",
    0x68: "#REGl=#REGb",
    0x69: "#REGl=#REGc",
    0x6A: "#REGl=#REGd",
    0x6B: "#REGl=#REGe",
    0x6C: "#REGl=#REGh",
    0x6D: "#REGl=#REGl",
    0x6E: "#REGl=*#REGhl",
    0x6F: "#REGl=#REGa",
    0x70: "Write #REGb to *#REGhl",
    0x71: "Write #REGc to *#REGhl",
    0x72: "Write #REGd to *#REGhl",
    0x73: "Write #REGe to *#REGhl",
    0x74: "Write #REGh to *#REGhl",
    0x75: "Write #REGl to *#REGhl",
    0x77: "Write #REGa to *#REGhl",
    0x78: "#REGa=#REGb",
    0x79: "#REGa=#REGc",
    0x7A: "#REGa=#REGd",
    0x7B: "#REGa=#REGe",
    0x7C: "#REGa=#REGh",
    0x7D: "#REGa=#REGl",
    0x7E: "#REGa=*#REGhl",
    0x7F: "#REGa=#REGa",
}

LOAD_2 = {
    0x06: "#REGb",
    0x0E: "#REGc",
    0x16: "#REGd",
    0x1E: "#REGe",
    0x26: "#REGh",
    0x2E: "#REGl",
    0x36: "nn",
    0x3E: "#REGa",
}

LOAD_3 = {
    0x01: "#REGbc",
    0x11: "#REGde",
    0x21: "#REGhl",
    0x22: "#REGhl",
    0x2A: "#REGhl",
    0x31: "#REGsp",
    0x32: "#REGa",
    0x3A: "#REGa",
}

OR = {
    0xB0: "#REGb",
    0xB1: "#REGc",
    0xB2: "#REGd",
    0xB3: "#REGe",
    0xB4: "#REGh",
    0xB5: "#REGl",
    0xB6: "*#REGhl",
    0xB7: "#REGa",
    0xF6: "nn",
}

POP = {
    0xC1: "#REGbc",
    0xD1: "#REGde",
    0xE1: "#REGhl",
    0xF1: "#REGaf",
}

PUSH = {
    0xC5: "#REGbc",
    0xD5: "#REGde",
    0xE5: "#REGhl",
    0xF5: "#REGaf",
}

RET = {
    0xC0: "Return if {} is not zero",
    0xC8: "Return if {} is zero",
    0xC9: "Return",
    0xD0: "Return if {} is higher",
    0xD8: "Return if {} is lower",
    0xE0: "Return if {} is odd",
    0xE8: "Return if {} is even",
    0xF0: "Return P",
    0xF8: "Return M",
}

SBC = {
    0x98: "#REGa-=#REGb",
    0x99: "#REGa-=#REGc",
    0x9A: "#REGa-=#REGd",
    0x9B: "#REGa-=#REGe",
    0x9C: "#REGa-=#REGh",
    0x9D: "#REGa-=#REGl",
    0x9E: "#REGa-=*#REGhl",
    0x9F: "#REGa-=#REGa",
}

SUB = {
    0x90: "#REGa-=#REGb",
    0x91: "#REGa-=#REGc",
    0x92: "#REGa-=#REGd",
    0x93: "#REGa-=#REGe",
    0x94: "#REGa-=#REGh",
    0x95: "#REGa-=#REGl",
    0x96: "#REGa-=*#REGhl",
    0x97: "#REGa-=#REGa",
    0xD6: "nn",
}

XOR = {
    0xA8: "#REGb",
    0xA9: "#REGc",
    0xAA: "#REGd",
    0xAB: "#REGe",
    0xAC: "#REGh",
    0xAD: "#REGl",
    0xAE: "*#REGhl",
    0xAF: "#REGa",
    0xEE: "nn",
}

CB_BITS = {
    0x00: "Rotate #REGb left (with carry)",
    0x01: "Rotate #REGc left (with carry)",
    0x02: "Rotate #REGd left (with carry)",
    0x03: "Rotate #REGe left (with carry)",
    0x04: "Rotate #REGh left (with carry)",
    0x05: "Rotate #REGl left (with carry)",
    0x06: "Rotate *#REGhl left (with carry)",
    0x07: "Rotate #REGa left (with carry)",
    0x08: "Rotate #REGb right (with carry)",
    0x09: "Rotate #REGc right (with carry)",
    0x0A: "Rotate #REGd right (with carry)",
    0x0B: "Rotate #REGe right (with carry)",
    0x0C: "Rotate #REGh right (with carry)",
    0x0D: "Rotate #REGl right (with carry)",
    0x0E: "Rotate *#REGhl right (with carry)",
    0x0F: "Rotate #REGa right (with carry)",
    0x10: "Rotate #REGb left",
    0x11: "Rotate #REGc left",
    0x12: "Rotate #REGd left",
    0x13: "Rotate #REGe left",
    0x14: "Rotate #REGh left",
    0x15: "Rotate #REGl left",
    0x16: "Rotate *#REGhl left",
    0x17: "Rotate #REGa left",
    0x18: "Rotate #REGb right",
    0x19: "Rotate #REGc right",
    0x1A: "Rotate #REGd right",
    0x1B: "Rotate #REGe right",
    0x1C: "Rotate #REGh right",
    0x1D: "Rotate #REGl right",
    0x1E: "Rotate *#REGhl right",
    0x1F: "Rotate #REGa right",
    0x20: "Shift #REGb left (with carry)",
    0x21: "Shift #REGc left (with carry)",
    0x22: "Shift #REGd left (with carry)",
    0x23: "Shift #REGe left (with carry)",
    0x24: "Shift #REGh left (with carry)",
    0x25: "Shift #REGl left (with carry)",
    0x26: "Shift *#REGhl left (with carry)",
    0x27: "Shift #REGa left (with carry)",
    0x28: "Shift #REGb right (with carry)",
    0x29: "Shift #REGc right (with carry)",
    0x2A: "Shift #REGd right (with carry)",
    0x2B: "Shift #REGe right (with carry)",
    0x2C: "Shift #REGh right (with carry)",
    0x2D: "Shift #REGl right (with carry)",
    0x2E: "Shift *#REGhl right (with carry)",
    0x2F: "Shift #REGa right (with carry)",
    0x30: "Shift #REGb left",
    0x31: "Shift #REGc left",
    0x32: "Shift #REGd left",
    0x33: "Shift #REGe left",
    0x34: "Shift #REGh left",
    0x35: "Shift #REGl left",
    0x36: "Shift *#REGhl left",
    0x37: "Shift #REGa left",
    0x38: "Shift #REGb right",
    0x39: "Shift #REGc right",
    0x3A: "Shift #REGd right",
    0x3B: "Shift #REGe right",
    0x3C: "Shift #REGh right",
    0x3D: "Shift #REGl right",
    0x3E: "Shift *#REGhl right",
    0x3F: "Shift #REGa right",
    0x40: "Test bit 0 of #REGb",
    0x41: "Test bit 0 of #REGc",
    0x42: "Test bit 0 of #REGd",
    0x43: "Test bit 0 of #REGe",
    0x44: "Test bit 0 of #REGh",
    0x45: "Test bit 0 of #REGl",
    0x46: "Test bit 0 of *#REGhl",
    0x47: "Test bit 0 of #REGa",
    0x48: "Test bit 1 of #REGb",
    0x49: "Test bit 1 of #REGc",
    0x4A: "Test bit 1 of #REGd",
    0x4B: "Test bit 1 of #REGe",
    0x4C: "Test bit 1 of #REGh",
    0x4D: "Test bit 1 of #REGl",
    0x4E: "Test bit 1 of *#REGhl",
    0x4F: "Test bit 1 of #REGa",
    0x50: "Test bit 2 of #REGb",
    0x51: "Test bit 2 of #REGc",
    0x52: "Test bit 2 of #REGd",
    0x53: "Test bit 2 of #REGe",
    0x54: "Test bit 2 of #REGh",
    0x55: "Test bit 2 of #REGl",
    0x56: "Test bit 2 of *#REGhl",
    0x57: "Test bit 2 of #REGa",
    0x58: "Test bit 3 of #REGb",
    0x59: "Test bit 3 of #REGc",
    0x5A: "Test bit 3 of #REGd",
    0x5B: "Test bit 3 of #REGe",
    0x5C: "Test bit 3 of #REGh",
    0x5D: "Test bit 3 of #REGl",
    0x5E: "Test bit 3 of *#REGhl",
    0x5F: "Test bit 3 of #REGa",
    0x60: "Test bit 4 of #REGb",
    0x61: "Test bit 4 of #REGc",
    0x62: "Test bit 4 of #REGd",
    0x63: "Test bit 4 of #REGe",
    0x64: "Test bit 4 of #REGh",
    0x65: "Test bit 4 of #REGl",
    0x66: "Test bit 4 of *#REGhl",
    0x67: "Test bit 4 of #REGa",
    0x68: "Test bit 5 of #REGb",
    0x69: "Test bit 5 of #REGc",
    0x6A: "Test bit 5 of #REGd",
    0x6B: "Test bit 5 of #REGe",
    0x6C: "Test bit 5 of #REGh",
    0x6D: "Test bit 5 of #REGl",
    0x6E: "Test bit 5 of *#REGhl",
    0x6F: "Test bit 5 of #REGa",
    0x70: "Test bit 6 of #REGb",
    0x71: "Test bit 6 of #REGc",
    0x72: "Test bit 6 of #REGd",
    0x73: "Test bit 6 of #REGe",
    0x74: "Test bit 6 of #REGh",
    0x75: "Test bit 6 of #REGl",
    0x76: "Test bit 6 of *#REGhl",
    0x77: "Test bit 6 of #REGa",
    0x78: "Test bit 7 of #REGb",
    0x79: "Test bit 7 of #REGc",
    0x7A: "Test bit 7 of #REGd",
    0x7B: "Test bit 7 of #REGe",
    0x7C: "Test bit 7 of #REGh",
    0x7D: "Test bit 7 of #REGl",
    0x7E: "Test bit 7 of *#REGhl",
    0x7F: "Test bit 7 of #REGa",
    0x80: "Reset bit 0 of #REGb",
    0x81: "Reset bit 0 of #REGc",
    0x82: "Reset bit 0 of #REGd",
    0x83: "Reset bit 0 of #REGe",
    0x84: "Reset bit 0 of #REGh",
    0x85: "Reset bit 0 of #REGl",
    0x86: "Reset bit 0 of *#REGhl",
    0x87: "Reset bit 0 of #REGa",
    0x88: "Reset bit 1 of #REGb",
    0x89: "Reset bit 1 of #REGc",
    0x8A: "Reset bit 1 of #REGd",
    0x8B: "Reset bit 1 of #REGe",
    0x8C: "Reset bit 1 of #REGh",
    0x8D: "Reset bit 1 of #REGl",
    0x8E: "Reset bit 1 of *#REGhl",
    0x8F: "Reset bit 1 of #REGa",
    0x90: "Reset bit 2 of #REGb",
    0x91: "Reset bit 2 of #REGc",
    0x92: "Reset bit 2 of #REGd",
    0x93: "Reset bit 2 of #REGe",
    0x94: "Reset bit 2 of #REGh",
    0x95: "Reset bit 2 of #REGl",
    0x96: "Reset bit 2 of *#REGhl",
    0x97: "Reset bit 2 of #REGa",
    0x98: "Reset bit 3 of #REGb",
    0x99: "Reset bit 3 of #REGc",
    0x9A: "Reset bit 3 of #REGd",
    0x9B: "Reset bit 3 of #REGe",
    0x9C: "Reset bit 3 of #REGh",
    0x9D: "Reset bit 3 of #REGl",
    0x9E: "Reset bit 3 of *#REGhl",
    0x9F: "Reset bit 3 of #REGa",
    0xA0: "Reset bit 4 of #REGb",
    0xA1: "Reset bit 4 of #REGc",
    0xA2: "Reset bit 4 of #REGd",
    0xA3: "Reset bit 4 of #REGe",
    0xA4: "Reset bit 4 of #REGh",
    0xA5: "Reset bit 4 of #REGl",
    0xA6: "Reset bit 4 of *#REGhl",
    0xA7: "Reset bit 4 of #REGa",
    0xA8: "Reset bit 5 of #REGb",
    0xA9: "Reset bit 5 of #REGc",
    0xAA: "Reset bit 5 of #REGd",
    0xAB: "Reset bit 5 of #REGe",
    0xAC: "Reset bit 5 of #REGh",
    0xAD: "Reset bit 5 of #REGl",
    0xAE: "Reset bit 5 of *#REGhl",
    0xAF: "Reset bit 5 of #REGa",
    0xB0: "Reset bit 6 of #REGb",
    0xB1: "Reset bit 6 of #REGc",
    0xB2: "Reset bit 6 of #REGd",
    0xB3: "Reset bit 6 of #REGe",
    0xB4: "Reset bit 6 of #REGh",
    0xB5: "Reset bit 6 of #REGl",
    0xB6: "Reset bit 6 of *#REGhl",
    0xB7: "Reset bit 6 of #REGa",
    0xB8: "Reset bit 7 of #REGb",
    0xB9: "Reset bit 7 of #REGc",
    0xBA: "Reset bit 7 of #REGd",
    0xBB: "Reset bit 7 of #REGe",
    0xBC: "Reset bit 7 of #REGh",
    0xBD: "Reset bit 7 of #REGl",
    0xBE: "Reset bit 7 of *#REGhl",
    0xBF: "Reset bit 7 of #REGa",
    0xC0: "Set bit 0 of #REGb",
    0xC1: "Set bit 0 of #REGc",
    0xC2: "Set bit 0 of #REGd",
    0xC3: "Set bit 0 of #REGe",
    0xC4: "Set bit 0 of #REGh",
    0xC5: "Set bit 0 of #REGl",
    0xC6: "Set bit 0 of *#REGhl",
    0xC7: "Set bit 0 of #REGa",
    0xC8: "Set bit 1 of #REGb",
    0xC9: "Set bit 1 of #REGc",
    0xCA: "Set bit 1 of #REGd",
    0xCB: "Set bit 1 of #REGe",
    0xCC: "Set bit 1 of #REGh",
    0xCD: "Set bit 1 of #REGl",
    0xCE: "Set bit 1 of *#REGhl",
    0xCF: "Set bit 1 of #REGa",
    0xD0: "Set bit 2 of #REGb",
    0xD1: "Set bit 2 of #REGc",
    0xD2: "Set bit 2 of #REGd",
    0xD3: "Set bit 2 of #REGe",
    0xD4: "Set bit 2 of #REGh",
    0xD5: "Set bit 2 of #REGl",
    0xD6: "Set bit 2 of *#REGhl",
    0xD7: "Set bit 2 of #REGa",
    0xD8: "Set bit 3 of #REGb",
    0xD9: "Set bit 3 of #REGc",
    0xDA: "Set bit 3 of #REGd",
    0xDB: "Set bit 3 of #REGe",
    0xDC: "Set bit 3 of #REGh",
    0xDD: "Set bit 3 of #REGl",
    0xDE: "Set bit 3 of *#REGhl",
    0xDF: "Set bit 3 of #REGa",
    0xE0: "Set bit 4 of #REGb",
    0xE1: "Set bit 4 of #REGc",
    0xE2: "Set bit 4 of #REGd",
    0xE3: "Set bit 4 of #REGe",
    0xE4: "Set bit 4 of #REGh",
    0xE5: "Set bit 4 of #REGl",
    0xE6: "Set bit 4 of *#REGhl",
    0xE7: "Set bit 4 of #REGa",
    0xE8: "Set bit 5 of #REGb",
    0xE9: "Set bit 5 of #REGc",
    0xEA: "Set bit 5 of #REGd",
    0xEB: "Set bit 5 of #REGe",
    0xEC: "Set bit 5 of #REGh",
    0xED: "Set bit 5 of #REGl",
    0xEE: "Set bit 5 of *#REGhl",
    0xEF: "Set bit 5 of #REGa",
    0xF0: "Set bit 6 of #REGb",
    0xF1: "Set bit 6 of #REGc",
    0xF2: "Set bit 6 of #REGd",
    0xF3: "Set bit 6 of #REGe",
    0xF4: "Set bit 6 of #REGh",
    0xF5: "Set bit 6 of #REGl",
    0xF6: "Set bit 6 of *#REGhl",
    0xF7: "Set bit 6 of #REGa",
    0xF8: "Set bit 7 of #REGb",
    0xF9: "Set bit 7 of #REGc",
    0xFA: "Set bit 7 of #REGd",
    0xFB: "Set bit 7 of #REGe",
    0xFC: "Set bit 7 of #REGh",
    0xFD: "Set bit 7 of #REGl",
    0xFE: "Set bit 7 of *#REGhl",
    0xFF: "Set bit 7 of #REGa",
}

ED_2 = {
    0x42: "#REGhl-=#REGbc",
    0x44: "NEG",
    0x46: "Interrupt mode 0",
    0x52: "#REGhl-=#REGde (with carry)",
    0x56: "Interrupt mode 1",
    0x5E: "Interrupt mode 2",
    0x6F: "RLD",
    0x79: "Send #REGa to port *#REGc",
    0xA0: "LDI",
    0xA1: "CPI",
    0xA2: "IDI",
    0xA3: "OUTI",
    0xA8: "LDD",
    0xA9: "CPD",
    0xAA: "IDD",
    0xAB: "OUTD",
    0xB0: "LDIR",
    0xB1: "CPIR",
    0xB2: "IDIR",
    0xB3: "OUTIR",
    0xB8: "LDDR",
    0xB9: "CPDR",
    0xBA: "IDDR",
    0xBB: "OUTDR",
}

ED_3 = {}

ED_4 = {
    0x43: "Write #REGbc to *#R${:04X}",
    0x4B: "#REGbc=*#R${:04X}",
    0x53: "Write #REGde to *#R${:04X}",
    0x5B: "#REGde=*#R${:04X}",
    0x63: "Write #REGhl to *#R${:04X}",
    0x6B: "#REGhl=*#R${:04X}",
    0x73: "Write #REGsp to *#R${:04X}",
    0x7B: "#REGsp=*#R${:04X}",
}

IX_ADD = {
    0x09: "#REGix+=#REGbc",
    0x19: "#REGix+=#REGde",
    0x23: "Increment #REGix by one",
    0x29: "#REGix+=#REGhl",
    0x2B: "Decrease #REGix by one",
    0x39: "#REGix+=#REGsp",
}

IX_ADC = {
    0x86: "#REGa+=*#REGix+#N${:02X}",
    0x96: "#REGa-=*#REGix+#N${:02X}",
    0x8E: "#REGa+=*#REGix+#N${:02X}",
    0x9E: "#REGa-=*#REGix+#N${:02X}",
}

IX_LOAD = {
    0x21: "#REGix",
    0x22: "#REGix",
    0x2A: "#REGix",
    0x36: "*#REGix",
    0x46: "#REGb",
    0x4E: "#REGc",
    0x56: "#REGd",
    0x5E: "#REGe",
    0x66: "#REGh",
    0x6E: "#REGl",
    0x70: "#REGb",
    0x71: "#REGc",
    0x72: "#REGd",
    0x73: "#REGe",
    0x74: "#REGh",
    0x75: "#REGl",
    0x77: "#REGa",
    0x7E: "#REGa",
    0xF9: "#REGsp",
}

IX_CB_BITS = {
    0x0E: "Rotate *#REGix+#N${:02X} right (with carry)",
    0x16: "Rotate *#REGix+#N${:02X} left",
    0x1E: "Rotate *#REGix+#N${:02X} right",
    0x26: "Shift *#REGix+#N${:02X} left (with carry)",
    0x3E: "Shift *#REGix+#N${:02X} right",
    0x46: "Test bit 0 of *#REGix+#N${:02X}",
    0x4E: "Test bit 1 of *#REGix+#N${:02X}",
    0x56: "Test bit 2 of *#REGix+#N${:02X}",
    0x5E: "Test bit 3 of *#REGix+#N${:02X}",
    0x66: "Test bit 4 of *#REGix+#N${:02X}",
    0x6E: "Test bit 5 of *#REGix+#N${:02X}",
    0x76: "Test bit 6 of *#REGix+#N${:02X}",
    0x7E: "Test bit 7 of *#REGix+#N${:02X}",
    0x86: "Reset bit 0 of *#REGix+#N${:02X}",
    0x8E: "Reset bit 1 of *#REGix+#N${:02X}",
    0x96: "Reset bit 2 of *#REGix+#N${:02X}",
    0x9E: "Reset bit 3 of *#REGix+#N${:02X}",
    0xA6: "Reset bit 4 of *#REGix+#N${:02X}",
    0xAE: "Reset bit 5 of *#REGix+#N${:02X}",
    0xB6: "Reset bit 6 of *#REGix+#N${:02X}",
    0xBE: "Reset bit 7 of *#REGix+#N${:02X}",
    0xC6: "Set bit 0 of *#REGix+#N${:02X}",
    0xCB: "Set bit 1 of *#REGix+#N${:02X} and store the result in #REGe",
    0xCE: "Set bit 1 of *#REGix+#N${:02X}",
    0xD6: "Set bit 2 of *#REGix+#N${:02X}",
    0xDE: "Set bit 3 of *#REGix+#N${:02X}",
    0xE6: "Set bit 4 of *#REGix+#N${:02X}",
    0xEE: "Set bit 5 of *#REGix+#N${:02X}",
    0xF6: "Set bit 6 of *#REGix+#N${:02X}",
    0xFE: "Set bit 7 of *#REGix+#N${:02X}",
}

IY_CB_BITS = {
    0x0E: "Rotate *#REGix+#N${:02X} right (with carry)",
    0x16: "Rotate *#REGix+#N${:02X} left",
    0x1E: "Rotate *#REGix+#N${:02X} right",
    0x26: "Shift *#REGix+#N${:02X} left (with carry)",
    0x3E: "Shift *#REGix+#N${:02X} right",
    0x46: "Test bit 0 of *#REGix+#N${:02X}",
    0x4E: "Test bit 1 of *#REGix+#N${:02X}",
    0x56: "Test bit 2 of *#REGix+#N${:02X}",
    0x5E: "Test bit 3 of *#REGix+#N${:02X}",
    0x66: "Test bit 4 of *#REGix+#N${:02X}",
    0x6E: "Test bit 5 of *#REGix+#N${:02X}",
    0x76: "Test bit 6 of *#REGix+#N${:02X}",
    0x7E: "Test bit 7 of *#REGix+#N${:02X}",
    0x86: "Reset bit 0 of *#REGix+#N${:02X}",
    0x8E: "Reset bit 1 of *#REGix+#N${:02X}",
    0x96: "Reset bit 2 of *#REGix+#N${:02X}",
    0x9E: "Reset bit 3 of *#REGix+#N${:02X}",
    0xA6: "Reset bit 4 of *#REGix+#N${:02X}",
    0xAE: "Reset bit 5 of *#REGix+#N${:02X}",
    0xB6: "Reset bit 6 of *#REGix+#N${:02X}",
    0xBE: "Reset bit 7 of *#REGix+#N${:02X}",
    0xC6: "Set bit 0 of *#REGix+#N${:02X}",
    0xCB: "Set bit 1 of *#REGix+#N${:02X} and store the result in #REGe",
    0xCE: "Set bit 1 of *#REGix+#N${:02X}",
    0xD6: "Set bit 2 of *#REGix+#N${:02X}",
    0xDE: "Set bit 3 of *#REGix+#N${:02X}",
    0xE6: "Set bit 4 of *#REGix+#N${:02X}",
    0xEE: "Set bit 5 of *#REGix+#N${:02X}",
    0xF6: "Set bit 6 of *#REGix+#N${:02X}",
    0xFE: "Set bit 7 of *#REGix+#N${:02X}",
}

IY_ADD = {
    0x09: "#REGiy+=#REGbc",
    0x19: "#REGiy+=#REGde",
    0x29: "#REGiy+=#REGiy",
    0x39: "#REGiy+=#REGsp",
}

IY_ADC = {
    0x86: "#REGa+=*#REGiy+#N${:02X}",
    0x96: "#REGa-=*#REGiy+#N${:02X}",
    0x8E: "#REGa+=*#REGiy+#N${:02X}",
    0x9E: "#REGa-=*#REGiy+#N${:02X}",
}

IY_LOAD = {
    0x21: "#REGiy",
    0x22: "#REGiy",
    0x2A: "#REGiy",
    0x36: "*#REGiy",
    0x46: "#REGb",
    0x4E: "#REGc",
    0x56: "#REGd",
    0x5E: "#REGe",
    0x66: "#REGh",
    0x6E: "#REGl",
    0x70: "#REGb",
    0x71: "#REGc",
    0x72: "#REGd",
    0x73: "#REGe",
    0x74: "#REGh",
    0x75: "#REGl",
    0x77: "#REGa",
    0x7E: "#REGa",
    0xF9: "#REGsp",
}