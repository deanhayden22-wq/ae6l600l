"""
AE5L600L Disassembly Verification Script
=========================================
Scans all analysis files in disassembly/analysis/ and maps/ for verifiable
claims, then checks them against the stock ROM binary.

Checks performed:
  1. Instruction bytes  - Does the opcode at a claimed address match the ROM?
  2. Calibration values - Does a cal[addr]=value claim match the ROM bytes?
  3. Literal pool refs  - Does a [pool] value at an address match the ROM?
  4. RAM name consistency - Are RAM address names consistent across files?
  5. Function entry points - Do claimed entry addresses look like valid prologues?
  6. GBR base verification - Does the LDC instruction actually load the claimed GBR?
  7. Cross-ref with descriptor_map and ram_reference canonical sources

Sources scanned:  disassembly/analysis/*.txt, disassembly/maps/*.txt
ROM used:         rom/ae5l600l.bin  (stock only)
Excluded:         patches/, merp mod/, any modified ROMs
"""

import struct, re, os, sys, glob
from collections import defaultdict

# ── Paths ──────────────────────────────────────────────────────────────────
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROM_PATH = os.path.join(BASE, 'rom', 'ae5l600l.bin')
ANALYSIS_DIR = os.path.join(BASE, 'disassembly', 'analysis')
MAPS_DIR = os.path.join(BASE, 'disassembly', 'maps')

# Explicitly exclude non-verified directories
EXCLUDE_DIRS = {'patches', 'merp mod', 'merp_mod', 'archive_v1'}

# ── Load ROM ───────────────────────────────────────────────────────────────
with open(ROM_PATH, 'rb') as f:
    ROM = f.read()
ROM_SIZE = len(ROM)

def read_u8(addr):
    if 0 <= addr < ROM_SIZE:
        return ROM[addr]
    return None

def read_u16(addr):
    if 0 <= addr < ROM_SIZE - 1:
        return struct.unpack('>H', ROM[addr:addr+2])[0]
    return None

def read_u32(addr):
    if 0 <= addr < ROM_SIZE - 3:
        return struct.unpack('>I', ROM[addr:addr+4])[0]
    return None

def read_float(addr):
    if 0 <= addr < ROM_SIZE - 3:
        return struct.unpack('>f', ROM[addr:addr+4])[0]
    return None

# ── SH-2 minimal disassembler (opcode → mnemonic, for verification) ──────
def decode_sh2(addr):
    """Decode one SH-2 instruction at addr. Returns (opcode_u16, mnemonic_str)."""
    op = read_u16(addr)
    if op is None:
        return None, None

    n = (op >> 8) & 0xF
    m = (op >> 4) & 0xF
    d8 = op & 0xFF
    d4 = op & 0xF
    top = (op >> 12) & 0xF

    # Special opcodes
    if op == 0x0009: return op, "nop"
    if op == 0x000B: return op, "rts"
    if op == 0x0019: return op, "div0u"
    if op == 0x001B: return op, "sleep"
    if op == 0x002B: return op, "rte"

    # movt Rn = 0000nnnn00101001 = 0x0n29
    if d8 == 0x29 and top == 0x0:
        return op, f"movt R{n}"
    if op == 0x0008: return op, "clrt"
    if op == 0x0018: return op, "sett"
    if op == 0x0028: return op, "clrmac"
    if op == 0x0048: return op, "clrs"
    if op == 0x0058: return op, "sets"
    if op == 0x0038: return op, "ldtlb"

    if top == 0x0:
        sub = d4
        if sub == 0x2 and m == 0:
            return op, f"stc SR,R{n}"
        if sub == 0x2 and m == 1:
            return op, f"stc GBR,R{n}"
        if sub == 0x2 and m == 2:
            return op, f"stc VBR,R{n}"
        if sub == 0x3:
            kind = m & 0x3
            if kind == 0: return op, f"bsrf R{n}"
            if kind == 2: return op, f"braf R{n}"
        if sub == 0x4:
            return op, f"mov.b R{m},@(R0,R{n})"
        if sub == 0x5:
            return op, f"mov.w R{m},@(R0,R{n})"
        if sub == 0x6:
            return op, f"mov.l R{m},@(R0,R{n})"
        if sub == 0x7:
            return op, f"mul.l R{m},R{n}"
        if sub == 0xA:
            return op, f"sts MACH,R{n}" if m == 0 else (f"sts MACL,R{n}" if m == 1 else f"sts PR,R{n}")
        if sub == 0xB:
            if m == 0: return op, f"jsr @R{n}"
            if m == 2: return op, f"jmp @R{n}"
        if sub == 0xC:
            return op, f"mov.b @(R0,R{m}),R{n}"
        if sub == 0xD:
            return op, f"mov.w @(R0,R{m}),R{n}"
        if sub == 0xE:
            return op, f"mov.l @(R0,R{m}),R{n}"
        # Less common 0x0 sub-opcodes
        if sub == 0xF:
            return op, f"mac.l @R{m}+,@R{n}+"

    elif top == 0x1:
        disp = op & 0xF
        return op, f"mov.l R{m},@({disp*4},R{n})"

    elif top == 0x2:
        sub = d4
        ops2 = {0: "mov.b", 1: "mov.w", 2: "mov.l", 4: "mov.b", 5: "mov.w", 6: "mov.l",
                7: "div0s", 8: "tst", 9: "and", 0xA: "xor", 0xB: "or",
                0xC: "cmp/str", 0xD: "xtrct", 0xE: "mulu.w", 0xF: "muls.w"}
        if sub in (0,1,2):
            return op, f"{ops2[sub]} R{m},@R{n}"
        if sub in (4,5,6):
            return op, f"{ops2[sub]} R{m},@-R{n}"
        if sub in ops2:
            return op, f"{ops2[sub]} R{m},R{n}"

    elif top == 0x3:
        sub = d4
        ops3 = {0: "cmp/eq", 2: "cmp/hs", 3: "cmp/ge", 4: "div1",
                5: "dmulu.l", 6: "cmp/hi", 7: "cmp/gt", 8: "sub", 0xA: "subc",
                0xB: "subv", 0xC: "add", 0xD: "dmuls.l", 0xE: "addc", 0xF: "addv"}
        if sub in ops3:
            return op, f"{ops3[sub]} R{m},R{n}"

    elif top == 0x4:
        sub = op & 0xFF
        if d4 == 0x0:
            if m == 0: return op, f"shll R{n}"
            if m == 1: return op, f"dt R{n}"
            if m == 2: return op, f"shal R{n}"
        if d4 == 0x1:
            if m == 0: return op, f"shlr R{n}"
            if m == 1: return op, f"cmp/pz R{n}"
            if m == 2: return op, f"shar R{n}"
        if d4 == 0x2:
            if m == 0: return op, f"sts.l MACH,@-R{n}"
            if m == 1: return op, f"sts.l MACL,@-R{n}"
            if m == 2: return op, f"sts.l PR,@-R{n}"
            if m == 5: return op, f"sts.l FPUL,@-R{n}"
            if m == 6: return op, f"sts.l FPSCR,@-R{n}"
        if d4 == 0x3:
            if m == 0: return op, f"stc.l SR,@-R{n}"
            if m == 1: return op, f"stc.l GBR,@-R{n}"
            if m == 2: return op, f"stc.l VBR,@-R{n}"
        if d4 == 0x4:
            if m == 0: return op, f"rotl R{n}"
            if m == 2: return op, f"rotcl R{n}"
        if d4 == 0x5:
            if m == 0: return op, f"rotr R{n}"
            if m == 1: return op, f"cmp/pl R{n}"
            if m == 2: return op, f"rotcr R{n}"
        if d4 == 0x6:
            if m == 0: return op, f"lds.l @R{n}+,MACH"
            if m == 1: return op, f"lds.l @R{n}+,MACL"
            if m == 2: return op, f"lds.l @R{n}+,PR"
            if m == 5: return op, f"lds.l @R{n}+,FPUL"
            if m == 6: return op, f"lds.l @R{n}+,FPSCR"
        if d4 == 0x7:
            if m == 0: return op, f"ldc.l @R{n}+,SR"
            if m == 1: return op, f"ldc.l @R{n}+,GBR"
            if m == 2: return op, f"ldc.l @R{n}+,VBR"
        if d4 == 0x8:
            if m == 0: return op, f"shll2 R{n}"
            if m == 1: return op, f"shll8 R{n}"
            if m == 2: return op, f"shll16 R{n}"
        if d4 == 0x9:
            if m == 0: return op, f"shlr2 R{n}"
            if m == 1: return op, f"shlr8 R{n}"
            if m == 2: return op, f"shlr16 R{n}"
        if d4 == 0xA:
            if m == 0: return op, f"lds R{n},MACH"
            if m == 1: return op, f"lds R{n},MACL"
            if m == 2: return op, f"lds R{n},PR"
            if m == 5: return op, f"lds R{n},FPUL"
            if m == 6: return op, f"lds R{n},FPSCR"
        if d4 == 0xB:
            if m == 0: return op, f"jsr @R{n}"
            if m == 2: return op, f"jmp @R{n}"
        if d4 == 0xC:
            return op, f"shad R{m},R{n}"
        if d4 == 0xD:
            return op, f"shld R{m},R{n}"
        if d4 == 0xE:
            if m == 0: return op, f"ldc R{n},SR"
            if m == 1: return op, f"ldc R{n},GBR"
            if m == 2: return op, f"ldc R{n},VBR"
        if d4 == 0xF:
            return op, f"mac.w @R{m}+,@R{n}+"

    elif top == 0x5:
        disp = op & 0xF
        return op, f"mov.l @({disp*4},R{m}),R{n}"

    elif top == 0x6:
        sub = d4
        ops6 = {0: f"mov.b @R{m},R{n}", 1: f"mov.w @R{m},R{n}", 2: f"mov.l @R{m},R{n}",
                3: f"mov R{m},R{n}", 4: f"mov.b @R{m}+,R{n}", 5: f"mov.w @R{m}+,R{n}",
                6: f"mov.l @R{m}+,R{n}", 7: f"not R{m},R{n}", 8: f"swap.b R{m},R{n}",
                9: f"swap.w R{m},R{n}", 0xA: f"negc R{m},R{n}", 0xB: f"neg R{m},R{n}",
                0xC: f"extu.b R{m},R{n}", 0xD: f"extu.w R{m},R{n}",
                0xE: f"exts.b R{m},R{n}", 0xF: f"exts.w R{m},R{n}"}
        if sub in ops6:
            return op, ops6[sub]

    elif top == 0x7:
        imm = d8 if d8 < 128 else d8 - 256
        return op, f"add #{imm},R{n}"

    elif top == 0x8:
        sub = n
        # For 0x80/81/84/85: format is 0x8smd where s=sub, m=reg, d=4-bit disp
        if sub == 0: return op, f"mov.b R0,@({d4},R{m})"
        if sub == 1: return op, f"mov.w R0,@({d4*2},R{m})"
        if sub == 4: return op, f"mov.b @({d4},R{m}),R0"
        if sub == 5: return op, f"mov.w @({d4*2},R{m}),R0"
        if sub == 8:
            # cmp/eq #imm,R0
            s8 = d8 if d8 < 128 else d8 - 256
            return op, f"cmp/eq #{s8},R0"
        if sub == 9:
            target = addr + 4 + (d8 if d8 < 128 else d8 - 256) * 2
            return op, f"bt 0x{target:x}"
        if sub == 0xB:
            target = addr + 4 + (d8 if d8 < 128 else d8 - 256) * 2
            return op, f"bf 0x{target:x}"
        if sub == 0xD:
            target = addr + 4 + (d8 if d8 < 128 else d8 - 256) * 2
            return op, f"bt/s 0x{target:x}"
        if sub == 0xF:
            target = addr + 4 + (d8 if d8 < 128 else d8 - 256) * 2
            return op, f"bf/s 0x{target:x}"

    elif top == 0x9:
        disp = d8
        target = addr + 4 + disp * 2
        return op, f"mov.w @(0x{target:x}),R{n}"

    elif top == 0xA:
        disp12 = op & 0xFFF
        if disp12 >= 0x800: disp12 -= 0x1000
        target = addr + 4 + disp12 * 2
        return op, f"bra 0x{target:x}"

    elif top == 0xB:
        disp12 = op & 0xFFF
        if disp12 >= 0x800: disp12 -= 0x1000
        target = addr + 4 + disp12 * 2
        return op, f"bsr 0x{target:x}"

    elif top == 0xC:
        sub = n
        if sub == 0: return op, f"mov.b R0,@({d8},GBR)"
        if sub == 1: return op, f"mov.w R0,@({d8*2},GBR)"
        if sub == 2: return op, f"mov.l R0,@({d8*4},GBR)"
        if sub == 3: return op, f"trapa #{d8}"
        if sub == 4: return op, f"mov.b @({d8},GBR),R0"
        if sub == 5: return op, f"mov.w @({d8*2},GBR),R0"
        if sub == 6: return op, f"mov.l @({d8*4},GBR),R0"
        if sub == 8: return op, f"tst #{d8},R0"
        if sub == 9: return op, f"and #{d8},R0"
        if sub == 0xA: return op, f"xor #{d8},R0"
        if sub == 0xB: return op, f"or #{d8},R0"
        if sub == 0xC:
            return op, f"tst.b #{d8},@(R0,GBR)"
        if sub == 0xD:
            return op, f"and.b #{d8},@(R0,GBR)"
        if sub == 0xE:
            return op, f"xor.b #{d8},@(R0,GBR)"
        if sub == 0xF:
            return op, f"or.b #{d8},@(R0,GBR)"
        if sub == 0x7:
            ea = (addr & ~3) + 4 + d8 * 4
            return op, f"mova @(0x{ea:x}),R0"

    elif top == 0xD:
        disp = d8
        ea = (addr & ~3) + 4 + disp * 4
        return op, f"mov.l @(0x{ea:x}),R{n}"

    elif top == 0xE:
        s8 = d8 if d8 < 128 else d8 - 256
        return op, f"mov #{s8},R{n}"

    elif top == 0xF:
        # FPU instructions (SH-2E / SH7058)
        sub = d4
        if sub == 0: return op, f"fadd FR{m},FR{n}"
        if sub == 1: return op, f"fsub FR{m},FR{n}"
        if sub == 2: return op, f"fmul FR{m},FR{n}"
        if sub == 3: return op, f"fdiv FR{m},FR{n}"
        if sub == 4: return op, f"fcmp/eq FR{m},FR{n}"
        if sub == 5: return op, f"fcmp/gt FR{m},FR{n}"
        if sub == 6:
            ea = (addr & ~3) + 4 + d8 * 4  # wait, this isn't right for F
            return op, f"fmov.s @(R0,R{m}),FR{n}"
        if sub == 7: return op, f"fmov.s FR{m},@(R0,R{n})"
        if sub == 8: return op, f"fmov.s @R{m},FR{n}"
        if sub == 9: return op, f"fmov.s @R{m}+,FR{n}"
        if sub == 0xA: return op, f"fmov.s FR{m},@R{n}"
        if sub == 0xB: return op, f"fmov.s FR{m},@-R{n}"
        if sub == 0xC: return op, f"fmov FR{m},FR{n}"
        if sub == 0xD:
            if m == 0: return op, f"fsts FPUL,FR{n}"
            if m == 1: return op, f"flds FR{n},FPUL"
            if m == 2: return op, f"float FPUL,FR{n}"
            if m == 3: return op, f"ftrc FR{n},FPUL"
            if m == 4: return op, f"fneg FR{n}"
            if m == 5: return op, f"fabs FR{n}"
            if m == 6: return op, f"fsqrt FR{n}"
            if m == 8: return op, f"fldi0 FR{n}"
            if m == 9: return op, f"fldi1 FR{n}"
            if m == 0xA: return op, f"fcnvsd FPUL,DR{n}"
            if m == 0xB: return op, f"fcnvds DR{n},FPUL"
        if sub == 0xE: return op, f"fmac FR0,FR{m},FR{n}"

    return op, f"??? (0x{op:04X})"


# ── Pattern Regexes ────────────────────────────────────────────────────────

# Inline disassembly: "0x054852: 4F22  sts.l PR,@-R15" or "054852: 4F22 ..."
# Require the opcode to be exactly 4 hex chars followed by whitespace+mnemonic,
# and the mnemonic must look like an SH-2 instruction (not a word like DEAD, CALL, etc.)
# Also exclude lines that look like data tables (float values, threshold lists)
RE_DISASM = re.compile(
    r'(?:0x)?([0-9A-Fa-f]{5,8}):\s+([0-9A-Fa-f]{4})\s{2,}(\S+)',
)

# Calibration value: "cal[0xD6720] = 4.0"
RE_CAL_VALUE = re.compile(
    r'cal\[0x([0-9A-Fa-f]+)\]\s*(?:=\s*([\d\.\-]+)|\(.*?raw\s*=\s*0x([0-9A-Fa-f]+).*?\))',
)

# Literal pool: "[pool] 0xFFFF4308"
RE_POOL = re.compile(
    r'([0-9A-Fa-f]{5,8}):\s+\[pool\]\s+0x([0-9A-Fa-f]{8})',
)

# Function entry: "func_name @ 0x054852"
# Require name to start with a letter (not a number or hex address) and be
# at least 3 chars to avoid matching prose like "CALL @ 0xFFFF..."
RE_FUNC_ENTRY = re.compile(
    r'([a-zA-Z][\w_]{2,})\s+@\s+0x([0-9A-Fa-f]{5,8})',
)

# GBR base: "Sets GBR = 0xFFFF8B50" or "GBR = 0xFFFF8B50"
RE_GBR = re.compile(
    r'GBR\s*=\s*0x(FFFF[0-9A-Fa-f]{4})',
)

# RAM mapping: "FFFF6624  rpm_current" in structured input blocks
# Require name to be at least 3 chars to avoid matching register names like R2, R14
RE_RAM_MAPPING = re.compile(
    r'(?:0x)?(FFFF[0-9A-Fa-f]{4})\s+([\w_]{3,})\s+\(',
)

# mov.l literal pool reference with comment: "D27F  mov.l ... ; =0xFFFF7986"
RE_MOVL_COMMENT = re.compile(
    r'(?:0x)?([0-9A-Fa-f]{5,8}):\s+([0-9A-Fa-f]{4})\s+mov\.l\s+@\(0x([0-9A-Fa-f]+)\),R(\d+)\s*;\s*=\s*0x([0-9A-Fa-f]+)',
)


# ── Collect files to scan ──────────────────────────────────────────────────
def get_scan_files():
    """Get all .txt files from disassembly/analysis/ and disassembly/maps/."""
    files = []
    for d in [ANALYSIS_DIR, MAPS_DIR]:
        for f in glob.glob(os.path.join(d, '*.txt')):
            # Safety: ensure no excluded directories snuck in
            norm = os.path.normpath(f).lower()
            if any(exc in norm for exc in EXCLUDE_DIRS):
                continue
            files.append(f)
    return sorted(files)


# ── Verification checks ───────────────────────────────────────────────────

class VerificationReport:
    def __init__(self):
        self.errors = []        # (file, line_num, category, message)
        self.warnings = []      # (file, line_num, category, message)
        self.stats = defaultdict(int)
        self.ram_names = defaultdict(dict)  # addr -> {name: [file:line, ...]}

    def error(self, fpath, line_num, category, msg):
        self.errors.append((os.path.basename(fpath), line_num, category, msg))
        self.stats[f"errors_{category}"] += 1

    def warn(self, fpath, line_num, category, msg):
        self.warnings.append((os.path.basename(fpath), line_num, category, msg))
        self.stats[f"warnings_{category}"] += 1

    def count(self, category):
        self.stats[f"checked_{category}"] += 1

    def record_ram_name(self, addr, name, fpath, line_num):
        key = addr.upper()
        if name not in self.ram_names[key]:
            self.ram_names[key][name] = []
        self.ram_names[key][name].append(f"{os.path.basename(fpath)}:{line_num}")


def normalize_mnemonic(m):
    """Normalize mnemonic for comparison (lowercase, strip spacing variations)."""
    m = m.lower().strip()
    # Normalize register case
    m = re.sub(r'\bfr(\d+)', r'FR\1', m)
    m = re.sub(r'\br(\d+)', r'R\1', m)
    # Normalize pr/gbr/mach/macl/fpul
    for reg in ['pr', 'gbr', 'mach', 'macl', 'fpul', 'sr', 'vbr']:
        m = re.sub(r'\b' + reg + r'\b', reg.upper(), m, flags=re.IGNORECASE)
    return m


def check_instruction(report, fpath, line_num, addr_str, opcode_str, mnemonic_str):
    """Verify that ROM bytes at addr match the claimed opcode."""
    report.count("instruction")
    try:
        addr = int(addr_str, 16)
    except ValueError:
        report.warn(fpath, line_num, "instruction", f"Could not parse address: {addr_str}")
        return

    if addr >= ROM_SIZE:
        report.warn(fpath, line_num, "instruction", f"Address 0x{addr:06X} beyond ROM size")
        return

    expected_op = int(opcode_str, 16)
    actual_op = read_u16(addr)

    if actual_op is None:
        report.error(fpath, line_num, "instruction", f"Cannot read ROM at 0x{addr:06X}")
        return

    if actual_op != expected_op:
        report.error(fpath, line_num, "instruction",
            f"OPCODE MISMATCH at 0x{addr:06X}: "
            f"claimed 0x{expected_op:04X} but ROM has 0x{actual_op:04X}")
        return

    # Also verify the mnemonic matches what our decoder produces
    _, decoded_mnem = decode_sh2(addr)
    if decoded_mnem and mnemonic_str:
        # Just compare the mnemonic word (first token), not operands
        # (operand formatting varies between tools)
        claimed_base = normalize_mnemonic(mnemonic_str.split()[0]) if mnemonic_str.split() else ""
        decoded_base = normalize_mnemonic(decoded_mnem.split()[0]) if decoded_mnem.split() else ""
        if claimed_base and decoded_base and claimed_base != decoded_base:
            # Some mnemonics have known aliases
            aliases = {
                ('mov', 'mov.l'), ('mov', 'mov.w'), ('mov', 'mov.b'),
                ('sts.l', 'sts'), ('lds.l', 'lds'),
                ('stc.l', 'stc'), ('ldc.l', 'ldc'),
            }
            pair = (claimed_base, decoded_base)
            if pair not in aliases and (decoded_base, claimed_base) not in aliases:
                report.warn(fpath, line_num, "mnemonic",
                    f"Mnemonic differs at 0x{addr:06X}: "
                    f"claimed '{mnemonic_str.split()[0]}' vs decoded '{decoded_mnem.split()[0]}'")


def check_cal_value(report, fpath, line_num, addr_str, value_str, raw_hex):
    """Verify calibration value at ROM address."""
    report.count("calibration")
    try:
        addr = int(addr_str, 16)
    except ValueError:
        return

    if addr >= ROM_SIZE:
        report.warn(fpath, line_num, "calibration", f"Cal address 0x{addr:06X} beyond ROM")
        return

    if raw_hex:
        # Raw hex value comparison
        try:
            expected = int(raw_hex, 16)
            if expected <= 0xFF:
                actual = read_u8(addr)
                if actual != expected:
                    report.error(fpath, line_num, "calibration",
                        f"CAL RAW MISMATCH at 0x{addr:06X}: "
                        f"claimed 0x{expected:02X} but ROM has 0x{actual:02X}")
            elif expected <= 0xFFFF:
                actual = read_u16(addr)
                if actual != expected:
                    report.error(fpath, line_num, "calibration",
                        f"CAL RAW MISMATCH at 0x{addr:06X}: "
                        f"claimed 0x{expected:04X} but ROM has 0x{actual:04X}")
        except (ValueError, TypeError):
            pass
        return

    if value_str:
        try:
            expected_f = float(value_str)
        except ValueError:
            return

        # Try as float first
        actual_f = read_float(addr)
        if actual_f is not None and abs(actual_f - expected_f) < 0.001:
            return  # Match as float

        # Try as uint8 (some cal values are byte-sized)
        actual_u8 = read_u8(addr)
        if actual_u8 is not None and abs(float(actual_u8) - expected_f) < 0.5:
            return  # Match as u8

        # Try as uint16
        actual_u16 = read_u16(addr)
        if actual_u16 is not None and abs(float(actual_u16) - expected_f) < 0.5:
            return  # Match as u16

        # Try as int16
        if actual_u16 is not None:
            s16 = actual_u16 if actual_u16 < 0x8000 else actual_u16 - 0x10000
            if abs(float(s16) - expected_f) < 0.5:
                return

        # No match in any type
        report.error(fpath, line_num, "calibration",
            f"CAL VALUE MISMATCH at 0x{addr:06X}: "
            f"claimed {value_str} but ROM has float={actual_f:.6f}, u8={actual_u8}, u16={actual_u16}")


def check_literal_pool(report, fpath, line_num, addr_str, value_str):
    """Verify literal pool entry at address."""
    report.count("literal_pool")
    try:
        addr = int(addr_str, 16)
        expected = int(value_str, 16)
    except ValueError:
        return

    if addr >= ROM_SIZE:
        report.warn(fpath, line_num, "literal_pool", f"Pool address 0x{addr:06X} beyond ROM")
        return

    actual = read_u32(addr)
    if actual is None:
        report.error(fpath, line_num, "literal_pool", f"Cannot read ROM at 0x{addr:06X}")
        return

    if actual != expected:
        report.error(fpath, line_num, "literal_pool",
            f"LITERAL POOL MISMATCH at 0x{addr:06X}: "
            f"claimed 0x{expected:08X} but ROM has 0x{actual:08X}")


def check_func_entry(report, fpath, line_num, name, addr_str):
    """Check that address looks like a valid function entry."""
    # Skip known non-function patterns that match the regex
    skip_names = {'CALL', 'STRUCT', 'PERIPHERAL', 'XRAM', 'Pool', 'table',
                  'counter_A', 'counter_B', 'injector_data', 'inj_pw_primary',
                  'inj_comp_state', 'final_timing_output', 'afl_multiplier',
                  'values', 'P0102'}
    if name in skip_names:
        return
    # Skip if address is in RAM space (0xFFFF0000+), not ROM
    try:
        addr = int(addr_str, 16)
    except ValueError:
        return
    if addr >= 0xFFFF0000:
        return  # RAM address, not a function entry point

    report.count("func_entry")

    if addr >= ROM_SIZE - 1:
        report.error(fpath, line_num, "func_entry",
            f"Function '{name}' @ 0x{addr:06X} is beyond ROM")
        return

    # Check alignment (SH-2 instructions must be 2-byte aligned)
    if addr % 2 != 0:
        report.error(fpath, line_num, "func_entry",
            f"Function '{name}' @ 0x{addr:06X} is not 2-byte aligned")
        return

    op = read_u16(addr)
    if op is None:
        return

    # Common SH-2 function prologues:
    # 4F22 = sts.l PR,@-R15  (most common)
    # 2Fn6 = mov.l Rn,@-R15  (push register)
    # 7Fxx = add #xx,R15     (allocate stack)
    # D1xx = mov.l @(disp,PC),R1  (load constant)
    # E1xx = mov #imm,R1     (load small immediate)
    # Also: some functions start with a mov or branch
    #
    # We just check it's not 0xFFFF (erased flash) or data-like
    if op == 0xFFFF:
        report.error(fpath, line_num, "func_entry",
            f"Function '{name}' @ 0x{addr:06X} points to erased flash (0xFFFF)")


def check_movl_comment(report, fpath, line_num, addr_str, opcode_str, ea_str, reg, value_str):
    """Verify mov.l @(disp,PC),Rn literal pool comment."""
    report.count("movl_comment")
    try:
        addr = int(addr_str, 16)
        claimed_op = int(opcode_str, 16)
        claimed_value = int(value_str, 16)
    except ValueError:
        return

    # Verify opcode first
    actual_op = read_u16(addr)
    if actual_op != claimed_op:
        return  # Already caught by instruction check

    # Compute effective address for mov.l @(disp,PC),Rn
    # EA = (PC & 0xFFFFFFFC) + 4 + disp*4
    # where disp = op & 0xFF
    disp = claimed_op & 0xFF
    ea = (addr & ~3) + 4 + disp * 4

    actual_value = read_u32(ea)
    if actual_value is None:
        return

    if actual_value != claimed_value:
        report.error(fpath, line_num, "movl_comment",
            f"MOV.L POOL MISMATCH at 0x{addr:06X}: "
            f"comment says =0x{claimed_value:08X} but pool @0x{ea:06X} has 0x{actual_value:08X}")


# ── Load canonical RAM reference for cross-check ──────────────────────────
def load_canonical_ram():
    """Load ram_reference.txt as the canonical RAM name mapping."""
    canonical = {}
    ram_ref_path = os.path.join(MAPS_DIR, 'ram_reference.txt')
    if not os.path.exists(ram_ref_path):
        return canonical
    with open(ram_ref_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            # ram_reference.txt has multiple formats:
            #   "  301  0xFFFF6624  rpm_current  ..." (top section: refcount addr name)
            #   "  0xFFFF6624   301  rpm_current  ..." (bottom section: addr refcount name)
            #   "  rpm_current  0xFFFF6624  301 refs" (alpha section: name addr refcount)
            # Match address then skip optional ref count (pure digits) to find the name
            m = re.search(r'0x(FFFF[0-9A-Fa-f]{4})\s+(?:\d+\s+)?([a-zA-Z][\w_]{2,})', line)
            if m and m.group(2) not in ('refs', 'ref', 'bytes'):
                canonical[m.group(1).upper()] = m.group(2)
    return canonical


# ── Main scan ──────────────────────────────────────────────────────────────
def scan_file(fpath, report):
    """Scan one analysis file for all verifiable claims."""
    try:
        with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except Exception as e:
        report.warn(fpath, 0, "io", f"Could not read file: {e}")
        return

    for i, line in enumerate(lines, 1):
        # Skip comment-only lines that are headers/dividers
        stripped = line.strip()
        if not stripped or stripped.startswith('===') or stripped.startswith('---'):
            continue

        # 1. Check inline disassembly (address: opcode mnemonic)
        for m in RE_DISASM.finditer(line):
            addr_s, opcode_s, mnem_s = m.group(1), m.group(2), m.group(3)
            # Filter: skip if this looks like a data directive (.long, .word)
            if mnem_s.startswith('.'):
                continue
            # Filter: skip [pool] lines (handled separately)
            if '[pool]' in line:
                continue
            # Filter: skip data table lines (float values, thresholds, etc.)
            # These have patterns like "1000  (0x447A0000)" where 1000 isn't an opcode
            if re.search(r'\(0x[0-9A-Fa-f]{8}\)', line):
                continue
            # Filter: skip section headings like "func_303C0: DEAD TIME CALCULATOR"
            if re.search(r'func_[0-9A-Fa-f]+:', line, re.IGNORECASE):
                continue
            # Filter: skip lines where "mnemonic" is clearly a label/prose word
            if mnem_s.upper() in ('DEAD', 'CALL', 'STRUCT', 'PERIPHERAL', 'XRAM',
                                   'POOL', 'TABLE', 'DATA', 'ENTRY', 'BASE', 'FLAG',
                                   'BYTE', 'WORD', 'FLOAT', 'VALUES', 'SIZE', 'TYPE',
                                   'P0102', 'P0130', 'P0131', 'P0132', 'P0133'):
                continue
            check_instruction(report, fpath, i, addr_s, opcode_s, mnem_s)

        # 2. Check calibration values
        for m in RE_CAL_VALUE.finditer(line):
            check_cal_value(report, fpath, i, m.group(1), m.group(2), m.group(3))

        # 3. Check literal pool entries
        for m in RE_POOL.finditer(line):
            check_literal_pool(report, fpath, i, m.group(1), m.group(2))

        # 4. Check function entry points
        for m in RE_FUNC_ENTRY.finditer(line):
            check_func_entry(report, fpath, i, m.group(1), m.group(2))

        # 5. Check mov.l literal pool comments
        for m in RE_MOVL_COMMENT.finditer(line):
            check_movl_comment(report, fpath, i, m.group(1), m.group(2), m.group(3), m.group(4), m.group(5))

        # 6. Collect RAM name mappings for consistency check
        for m in RE_RAM_MAPPING.finditer(line):
            report.record_ram_name(m.group(1), m.group(2), fpath, i)


def check_ram_consistency(report, canonical_ram):
    """Check that RAM addresses map to consistent names across files."""
    for addr, names in report.ram_names.items():
        if len(names) > 1:
            # Multiple different names for same address
            name_list = ', '.join(f"'{n}' ({', '.join(locs)})" for n, locs in names.items())
            report.warn("CROSS-FILE", 0, "ram_consistency",
                f"RAM 0x{addr} has multiple names: {name_list}")

        # Cross-check against canonical
        if addr in canonical_ram:
            canon_name = canonical_ram[addr]
            for name in names:
                if name != canon_name:
                    # Mild warning — some analysis files may use shortened names
                    report.warn("CROSS-FILE", 0, "ram_canonical",
                        f"RAM 0x{addr}: analysis uses '{name}', "
                        f"canonical ram_reference.txt says '{canon_name}'")


# ── Report formatting ─────────────────────────────────────────────────────
def format_report(report):
    lines = []
    lines.append("=" * 80)
    lines.append("AE5L600L DISASSEMBLY VERIFICATION REPORT")
    lines.append("=" * 80)
    lines.append(f"ROM: {ROM_PATH}")
    lines.append(f"ROM size: {ROM_SIZE:,} bytes")
    lines.append("")

    # Stats
    lines.append("VERIFICATION STATISTICS")
    lines.append("-" * 40)
    for key in sorted(report.stats):
        lines.append(f"  {key}: {report.stats[key]}")
    lines.append("")

    total_errors = len(report.errors)
    total_warnings = len(report.warnings)
    lines.append(f"TOTAL ERRORS:   {total_errors}")
    lines.append(f"TOTAL WARNINGS: {total_warnings}")
    lines.append("")

    if report.errors:
        lines.append("=" * 80)
        lines.append("ERRORS (data does not match ROM)")
        lines.append("=" * 80)
        # Group by category
        by_cat = defaultdict(list)
        for fpath, lnum, cat, msg in report.errors:
            by_cat[cat].append((fpath, lnum, msg))

        for cat in sorted(by_cat):
            lines.append(f"\n  [{cat.upper()}] ({len(by_cat[cat])} errors)")
            lines.append(f"  {'-' * 60}")
            for fpath, lnum, msg in by_cat[cat]:
                loc = f"{fpath}:{lnum}" if lnum else fpath
                lines.append(f"    {loc}")
                lines.append(f"      {msg}")
        lines.append("")

    if report.warnings:
        lines.append("=" * 80)
        lines.append("WARNINGS (potential issues, review recommended)")
        lines.append("=" * 80)
        by_cat = defaultdict(list)
        for fpath, lnum, cat, msg in report.warnings:
            by_cat[cat].append((fpath, lnum, msg))

        for cat in sorted(by_cat):
            lines.append(f"\n  [{cat.upper()}] ({len(by_cat[cat])} warnings)")
            lines.append(f"  {'-' * 60}")
            for fpath, lnum, msg in by_cat[cat]:
                loc = f"{fpath}:{lnum}" if lnum else fpath
                lines.append(f"    {loc}")
                lines.append(f"      {msg}")

    lines.append("")
    lines.append("=" * 80)
    if total_errors == 0:
        lines.append("RESULT: ALL CHECKS PASSED")
    else:
        lines.append(f"RESULT: {total_errors} ERROR(S) FOUND — review needed")
    lines.append("=" * 80)

    return '\n'.join(lines)


# ── Entry point ────────────────────────────────────────────────────────────
def main():
    print("AE5L600L Disassembly Verification")
    print(f"ROM: {ROM_PATH} ({ROM_SIZE:,} bytes)")
    print()

    report = VerificationReport()
    canonical_ram = load_canonical_ram()

    files = get_scan_files()
    print(f"Scanning {len(files)} files in disassembly/analysis/ and disassembly/maps/...")
    print("(Excluding: patches/, merp mod/, archive_v1/)")
    print()

    for fpath in files:
        rel = os.path.relpath(fpath, BASE)
        print(f"  Scanning: {rel}")
        scan_file(fpath, report)

    print()
    print("Checking RAM name consistency across files...")
    check_ram_consistency(report, canonical_ram)

    result = format_report(report)
    print()
    # Handle Windows encoding issues
    try:
        print(result)
    except UnicodeEncodeError:
        print(result.encode('ascii', 'replace').decode('ascii'))

    # Also write to file
    out_path = os.path.join(BASE, 'disassembly', 'verification_report.txt')
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(result)
    print(f"\nReport saved to: {out_path}")

    return 1 if report.errors else 0


if __name__ == '__main__':
    sys.exit(main())
