import struct
import sys

ROM_PATH = r"C:\Users\Dean\Documents\GitHub\ae6l600l\rom\AE5L600L 20g rev 20.5 tiny wrex.bin"

with open(ROM_PATH, "rb") as f:
    rom = f.read()

def read16(addr):
    return struct.unpack(">H", rom[addr:addr+2])[0]

def read32(addr):
    return struct.unpack(">I", rom[addr:addr+4])[0]

def readf32(addr):
    return struct.unpack(">f", rom[addr:addr+4])[0]

def sign_ext8(v):
    if v & 0x80:
        return v - 0x100
    return v

def sign_ext12(v):
    if v & 0x800:
        return v - 0x1000
    return v

# Collect literal pool references for post-dump
literal_refs = {}  # addr -> set of PCs that reference it
ram_reads = set()
ram_writes = set()

def disasm_one(pc):
    """Disassemble one 16-bit SH-2 instruction at pc. Returns (mnemonic, comment, is_rts)"""
    op = read16(pc)
    hi4 = (op >> 12) & 0xF
    comment = ""
    is_rts = False
    is_jmp_like = False

    # RTS
    if op == 0x000B:
        return "rts", "", True
    if op == 0x0009:
        return "nop", "", False

    # mov #imm8, Rn  (0xEnDD)
    if hi4 == 0xE:
        n = (op >> 8) & 0xF
        imm = sign_ext8(op & 0xFF)
        return f"mov    #{imm},R{n}", f"; R{n} = {imm} (0x{imm & 0xFF:02X})", False

    # mov.l @(disp,PC),Rn (0xDnDD)
    if hi4 == 0xD:
        n = (op >> 8) & 0xF
        disp = op & 0xFF
        addr = (pc & 0xFFFFFFFC) + 4 + disp * 4
        val = read32(addr)
        literal_refs.setdefault(addr, set()).add(pc)
        if val >= 0xFFFF0000:
            comment = f"; @0x{addr:06X} -> [RAM 0x{val:08X}]"
        elif 0x000A0000 <= val <= 0x000FFFFF:
            fval = readf32(addr)
            comment = f"; @0x{addr:06X} -> [CAL 0x{val:08X}] = {fval}"
        elif val < 0x00100000:
            comment = f"; @0x{addr:06X} -> [ROM func 0x{val:08X}]"
        else:
            comment = f"; @0x{addr:06X} -> 0x{val:08X}"
        return f"mov.l  @(0x{disp:02X},PC),R{n}", comment, False

    # mov.w @(disp,PC),Rn (0x9nDD)
    if hi4 == 0x9:
        n = (op >> 8) & 0xF
        disp = op & 0xFF
        addr = pc + 4 + disp * 2
        val = read16(addr)
        comment = f"; @0x{addr:06X} -> 0x{val:04X} ({val})"
        return f"mov.w  @(0x{disp:02X},PC),R{n}", comment, False

    # 0x6nmX family
    if hi4 == 0x6:
        n = (op >> 8) & 0xF
        m = (op >> 4) & 0xF
        lo = op & 0xF
        if lo == 0x0:
            return f"mov.b  @R{m},R{n}", "", False
        if lo == 0x1:
            return f"mov.w  @R{m},R{n}", "", False
        if lo == 0x2:
            return f"mov.l  @R{m},R{n}", "", False
        if lo == 0x3:
            return f"mov    R{m},R{n}", "", False
        if lo == 0xC:
            return f"extu.b R{m},R{n}", "", False
        if lo == 0xD:
            return f"extu.w R{m},R{n}", "", False
        if lo == 0x6:
            # mov.l @R15+,Rn check
            if m == 0xF:
                return f"mov.l  @R15+,R{n}", "", False
            return f"mov.l  @R{m}+,R{n}", "", False  # general form
        if lo == 0x9:
            return f"swap.w R{m},R{n}", "", False
        if lo == 0xA:
            return f"negc   R{m},R{n}", "", False
        if lo == 0xE:
            return f"exts.b R{m},R{n}", "", False
        if lo == 0xF:
            return f"exts.w R{m},R{n}", "", False

    # 0x2nmX family
    if hi4 == 0x2:
        n = (op >> 8) & 0xF
        m = (op >> 4) & 0xF
        lo = op & 0xF
        if lo == 0x0:
            return f"mov.b  R{m},@R{n}", "", False
        if lo == 0x1:
            return f"mov.w  R{m},@R{n}", "", False
        if lo == 0x2:
            return f"mov.l  R{m},@R{n}", "", False
        if lo == 0x8:
            return f"tst    R{m},R{n}", "", False
        if lo == 0x6:
            # mov.l Rm,@-Rn
            return f"mov.l  R{m},@-R{n}", "", False
        if lo == 0x9:
            return f"and    R{m},R{n}", "", False
        if lo == 0xA:
            return f"xor    R{m},R{n}", "", False
        if lo == 0xB:
            return f"or     R{m},R{n}", "", False

    # 0x4nXX family
    if hi4 == 0x4:
        n = (op >> 8) & 0xF
        lo8 = op & 0xFF
        if lo8 == 0x0B:
            return f"jsr    @R{n}", "", False
        if lo8 == 0x2B:
            return f"jmp    @R{n}", "", False
        if lo8 == 0x22 and n == 0xF:
            return f"sts.l  PR,@-R15", "", False
        if lo8 == 0x26 and n == 0xF:
            return f"lds.l  @R15+,PR", "", False
        if lo8 == 0x22:
            return f"sts.l  PR,@-R{n}", "", False
        if lo8 == 0x26:
            return f"lds.l  @R{n}+,PR", "", False
        if lo8 == 0x11:
            return f"cmp/pz R{n}", "", False
        if lo8 == 0x15:
            return f"cmp/pl R{n}", "", False
        if lo8 == 0x18:
            return f"shll8  R{n}", "", False
        if lo8 == 0x19:
            return f"shlr8  R{n}", "", False
        if lo8 == 0x28:
            return f"shll16 R{n}", "", False
        if lo8 == 0x29:
            return f"shlr16 R{n}", "", False
        if lo8 == 0x00:
            return f"shll   R{n}", "", False
        if lo8 == 0x01:
            return f"shlr   R{n}", "", False
        if lo8 == 0x04:
            return f"rotl   R{n}", "", False
        if lo8 == 0x05:
            return f"rotr   R{n}", "", False
        if lo8 == 0x20:
            return f"shal   R{n}", "", False
        if lo8 == 0x21:
            return f"shar   R{n}", "", False

    # 0x7nDD: add #imm8, Rn
    if hi4 == 0x7:
        n = (op >> 8) & 0xF
        imm = sign_ext8(op & 0xFF)
        return f"add    #{imm},R{n}", "", False

    # 0x3nmC: add Rm,Rn
    if hi4 == 0x3:
        n = (op >> 8) & 0xF
        m = (op >> 4) & 0xF
        lo = op & 0xF
        if lo == 0xC:
            return f"add    R{m},R{n}", "", False
        if lo == 0x0:
            return f"cmp/eq R{m},R{n}", "", False
        if lo == 0x2:
            return f"cmp/hs R{m},R{n}", "", False
        if lo == 0x3:
            return f"cmp/ge R{m},R{n}", "", False
        if lo == 0x6:
            return f"cmp/hi R{m},R{n}", "", False
        if lo == 0x7:
            return f"cmp/gt R{m},R{n}", "", False
        if lo == 0x8:
            return f"sub    R{m},R{n}", "", False
        if lo == 0xE:
            return f"addc   R{m},R{n}", "", False

    # 0x88XX: cmp/eq #imm,R0
    if (op >> 8) == 0x88:
        imm = sign_ext8(op & 0xFF)
        return f"cmp/eq #{imm},R0", "", False

    # Branch instructions
    if (op >> 8) == 0x89:
        disp = sign_ext8(op & 0xFF)
        target = pc + 4 + disp * 2
        return f"bt     0x{target:05X}", f"; branch if T=1", False
    if (op >> 8) == 0x8B:
        disp = sign_ext8(op & 0xFF)
        target = pc + 4 + disp * 2
        return f"bf     0x{target:05X}", f"; branch if T=0", False
    if (op >> 8) == 0x8D:
        disp = sign_ext8(op & 0xFF)
        target = pc + 4 + disp * 2
        return f"bt/s   0x{target:05X}", f"; branch if T=1 (delayed)", False
    if (op >> 8) == 0x8F:
        disp = sign_ext8(op & 0xFF)
        target = pc + 4 + disp * 2
        return f"bf/s   0x{target:05X}", f"; branch if T=0 (delayed)", False

    # BRA
    if hi4 == 0xA:
        disp = sign_ext12(op & 0xFFF)
        target = pc + 4 + disp * 2
        return f"bra    0x{target:05X}", "", False
    # BSR
    if hi4 == 0xB:
        disp = sign_ext12(op & 0xFFF)
        target = pc + 4 + disp * 2
        return f"bsr    0x{target:05X}", f"; call sub_0x{target:05X}", False

    # GBR-relative
    if (op >> 8) == 0xC0:
        disp = op & 0xFF
        return f"mov.b  R0,@(0x{disp:02X},GBR)", "", False
    if (op >> 8) == 0xC4:
        disp = op & 0xFF
        return f"mov.b  @(0x{disp:02X},GBR),R0", "", False
    if (op >> 8) == 0xC7:
        disp = op & 0xFF
        addr = (pc & 0xFFFFFFFC) + 4 + disp * 4
        val = read32(addr)
        literal_refs.setdefault(addr, set()).add(pc)
        return f"mova   @(0x{disp:02X},PC),R0", f"; R0 = 0x{addr:06X} -> 0x{val:08X}", False

    # mov.l @(disp,Rm),Rn  (0x5nmD)
    if hi4 == 0x5:
        n = (op >> 8) & 0xF
        m = (op >> 4) & 0xF
        disp = op & 0xF
        return f"mov.l  @(0x{disp*4:02X},R{m}),R{n}", "", False

    # mov.l Rm,@(disp,Rn) (0x1nmD)
    if hi4 == 0x1:
        n = (op >> 8) & 0xF
        m = (op >> 4) & 0xF
        disp = op & 0xF
        return f"mov.l  R{m},@(0x{disp*4:02X},R{n})", "", False

    # mov.b @(disp,Rm),R0 (0x84mD)
    if (op >> 8) == 0x84:
        m = (op >> 4) & 0xF
        disp = op & 0xF
        return f"mov.b  @(0x{disp:02X},R{m}),R0", "", False

    # mov.b R0,@(disp,Rn) (0x80nD)
    if (op >> 8) == 0x80:
        n = (op >> 4) & 0xF
        disp = op & 0xF
        return f"mov.b  R0,@(0x{disp:02X},R{n})", "", False

    # mov.w @(disp,Rm),R0 (0x85mD)
    if (op >> 8) == 0x85:
        m = (op >> 4) & 0xF
        disp = op & 0xF
        return f"mov.w  @(0x{disp*2:02X},R{m}),R0", "", False

    # mov.w R0,@(disp,Rn) (0x81nD)
    if (op >> 8) == 0x81:
        n = (op >> 4) & 0xF
        disp = op & 0xF
        return f"mov.w  R0,@(0x{disp*2:02X},R{n})", "", False

    # Floating point
    if hi4 == 0xF:
        n = (op >> 8) & 0xF
        m = (op >> 4) & 0xF
        lo = op & 0xF
        if lo == 0x8:
            return f"fmov.s @R{m},FR{n}", "", False
        if lo == 0xA:
            return f"fmov.s FR{m},@R{n}", "", False
        if lo == 0x6:
            return f"fmov.s @(R0,R{m}),FR{n}", "", False
        if lo == 0x7:
            return f"fmov.s FR{m},@(R0,R{n})", "", False
        if lo == 0xC:
            return f"fmov   FR{m},FR{n}", "", False
        if lo == 0x0:
            return f"fadd   FR{m},FR{n}", "", False
        if lo == 0x1:
            return f"fsub   FR{m},FR{n}", "", False
        if lo == 0x2:
            return f"fmul   FR{m},FR{n}", "", False
        if lo == 0x3:
            return f"fdiv   FR{m},FR{n}", "", False
        if lo == 0x5:
            return f"fcmp/gt FR{m},FR{n}", "", False
        if lo == 0x4:
            return f"fcmp/eq FR{m},FR{n}", "", False
        if lo == 0xD:
            if m == 0x8:
                return f"fldi0  FR{n}", "", False
            if m == 0x9:
                return f"fldi1  FR{n}", "", False
            if m == 0x2:
                return f"float  FPUL,FR{n}", "", False
            if m == 0x3:
                return f"ftrc   FR{n},FPUL", "", False
            if m == 0x0:
                return f"fsts   FPUL,FR{n}", "", False
            if m == 0x1:
                return f"flds   FR{n},FPUL", "", False
            if m == 0x4:
                return f"fneg   FR{n}", "", False
            if m == 0x5:
                return f"fabs   FR{n}", "", False
            if m == 0x6:
                return f"fsqrt  FR{n}", "", False
        if lo == 0x9:
            return f"fmov.s @R{m}+,FR{n}", "", False
        if lo == 0xB:
            return f"fmov.s FR{m},@-R{n}", "", False
        if lo == 0xE:
            return f"fmac   FR0,FR{m},FR{n}", "", False

    # 0x0nm7: mul.l Rm,Rn
    if hi4 == 0x0:
        lo = op & 0xF
        n = (op >> 8) & 0xF
        m = (op >> 4) & 0xF
        if lo == 0x7:
            return f"mul.l  R{m},R{n}", "", False
        if lo == 0xC:
            return f"mov.b  @(R0,R{m}),R{n}", "", False
        if lo == 0xD:
            return f"mov.w  @(R0,R{m}),R{n}", "", False
        if lo == 0xE:
            return f"mov.l  @(R0,R{m}),R{n}", "", False
        if op & 0xFF == 0x0A:
            return f"sts    MACH,R{n}", "", False
        if op & 0xFF == 0x1A:
            return f"sts    MACL,R{n}", "", False
        if op & 0xFF == 0x5A:
            return f"sts    FPUL,R{n}", "", False

    # cmp/eq Rm,Rn already handled in 0x3 family
    # 0xC9DD: and #imm,R0
    if (op >> 8) == 0xC9:
        imm = op & 0xFF
        return f"and    #0x{imm:02X},R0", "", False

    # 0xCBDD: or #imm,R0
    if (op >> 8) == 0xCB:
        imm = op & 0xFF
        return f"or     #0x{imm:02X},R0", "", False

    # 0xCADD: xor #imm,R0
    if (op >> 8) == 0xCA:
        imm = op & 0xFF
        return f"xor    #0x{imm:02X},R0", "", False

    # 0xC8DD: tst #imm,R0
    if (op >> 8) == 0xC8:
        imm = op & 0xFF
        return f"tst    #0x{imm:02X},R0", "", False

    return f".word  0x{op:04X}", "; UNKNOWN", False


def disassemble_function(start_addr, max_insns=200):
    pc = start_addr
    found_rts = False
    insn_count = 0
    lines = []

    while insn_count < max_insns:
        op = read16(pc)
        mnemonic, comment, is_rts = disasm_one(pc)
        line = f"  0x{pc:05X}:  {op:04X}    {mnemonic:30s} {comment}"
        lines.append(line)
        insn_count += 1

        if found_rts:
            # This was the delay slot after RTS
            break

        if is_rts:
            found_rts = True

        pc += 2

    return lines, pc + 2  # return end address (past last instruction)


print("=" * 80)
print("DISASSEMBLY OF sub_1FD7C")
print("=" * 80)

lines, end_addr = disassemble_function(0x1FD7C)
for l in lines:
    print(l)

print()
print("=" * 80)
print("LITERAL POOL VALUES")
print("=" * 80)
for addr in sorted(literal_refs.keys()):
    val = read32(addr)
    refs = sorted(literal_refs[addr])
    ref_str = ", ".join(f"0x{r:05X}" for r in refs)
    if val >= 0xFFFF0000:
        print(f"  0x{addr:06X}: 0x{val:08X}  (RAM)  referenced from: {ref_str}")
    elif 0x000A0000 <= val <= 0x000FFFFF:
        fval = readf32(addr)
        print(f"  0x{addr:06X}: 0x{val:08X}  (CAL float={fval})  referenced from: {ref_str}")
    elif val < 0x00100000:
        print(f"  0x{addr:06X}: 0x{val:08X}  (ROM func)  referenced from: {ref_str}")
    else:
        print(f"  0x{addr:06X}: 0x{val:08X}  referenced from: {ref_str}")

# Now analyze RAM accesses by re-reading instructions
print()
print("=" * 80)
print("RAM ADDRESSES ACCESSED")
print("=" * 80)
# Collect from literal pool
ram_addrs = {}
for addr in sorted(literal_refs.keys()):
    val = read32(addr)
    if val >= 0xFFFF0000:
        ram_addrs[val] = ram_addrs.get(val, [])
        for r in sorted(literal_refs[addr]):
            ram_addrs[val].append(f"loaded at 0x{r:05X}")

for raddr in sorted(ram_addrs.keys()):
    refs = "; ".join(ram_addrs[raddr])
    print(f"  0x{raddr:08X}  ({refs})")

print()
print("=" * 80)
print("PSEUDOCODE ANALYSIS")
print("=" * 80)
print()
print("(See below for manual analysis based on instruction flow)")
print()

# Let's do a more detailed trace
print("Detailed instruction trace for pseudocode:")
print()
pc = 0x1FD7C
for l in lines:
    print(l)
