import struct
import sys

ROM_PATH = "C:/Users/Dean/Documents/GitHub/ae6l600l/disassembly/.claude/worktrees/strange-agnesi/rom/ae5l600l.bin"

with open(ROM_PATH, "rb") as f:
    ROM = f.read()

def read16(offset):
    return struct.unpack(">H", ROM[offset:offset+2])[0]

def read32(offset):
    return struct.unpack(">I", ROM[offset:offset+4])[0]

def sign8(v):
    return v - 0x100 if v & 0x80 else v

def sign12(v):
    return v - 0x1000 if v & 0x800 else v

def disasm(pc):
    op = read16(pc)
    n = (op >> 8) & 0xF
    m = (op >> 4) & 0xF
    top = (op >> 12) & 0xF
    lo = op & 0xF

    if op == 0x0009: return "nop"
    if op == 0x000B: return "rts"
    if op == 0x002B: return "rte"
    if op == 0x0008: return "clrt"
    if op == 0x0018: return "sett"
    if op == 0x0028: return "clrmac"

    if top == 0xD:
        d = op & 0xFF
        a = ((pc+2) & ~3) + d*4
        v = read32(a)
        return f"mov.l @(0x{d*4:X},PC),R{n}  ; [0x{a:06X}]=0x{v:08X}"
    if top == 0xE:
        imm = sign8(op & 0xFF)
        return f"mov #{imm},R{n}"
    if top == 0x9:
        d = op & 0xFF
        a = (pc+2) + d*2
        v = read16(a)
        return f"mov.w @(0x{d*2:X},PC),R{n}  ; [0x{a:06X}]=0x{v:04X}"

    # 0010nnnnmmmm____
    if top == 0x2:
        if lo == 0x0: return f"mov.b R{m},@R{n}"
        if lo == 0x1: return f"mov.w R{m},@R{n}"
        if lo == 0x2: return f"mov.l R{m},@R{n}"
        if lo == 0x4: return f"mov.b R{m},@-R{n}"
        if lo == 0x5: return f"mov.w R{m},@-R{n}"
        if lo == 0x6: return f"mov.l R{m},@-R{n}"
        if lo == 0x8: return f"tst R{m},R{n}"
        if lo == 0x9: return f"and R{m},R{n}"
        if lo == 0xA: return f"xor R{m},R{n}"
        if lo == 0xB: return f"or R{m},R{n}"
        if lo == 0xE: return f"mulu.w R{m},R{n}"
        if lo == 0xF: return f"muls.w R{m},R{n}"

    # 0110nnnnmmmm____
    if top == 0x6:
        if lo == 0x0: return f"mov.b @R{m},R{n}"
        if lo == 0x1: return f"mov.w @R{m},R{n}"
        if lo == 0x2: return f"mov.l @R{m},R{n}"
        if lo == 0x3: return f"mov R{m},R{n}"
        if lo == 0x4: return f"mov.b @R{m}+,R{n}"
        if lo == 0x5: return f"mov.w @R{m}+,R{n}"
        if lo == 0x6: return f"mov.l @R{m}+,R{n}"
        if lo == 0x7: return f"not R{m},R{n}"
        if lo == 0x8: return f"swap.b R{m},R{n}"
        if lo == 0x9: return f"swap.w R{m},R{n}"
        if lo == 0xB: return f"neg R{m},R{n}"
        if lo == 0xC: return f"extu.b R{m},R{n}"
        if lo == 0xD: return f"extu.w R{m},R{n}"
        if lo == 0xE: return f"exts.b R{m},R{n}"
        if lo == 0xF: return f"exts.w R{m},R{n}"

    # 0011nnnnmmmm____
    if top == 0x3:
        if lo == 0x0: return f"cmp/eq R{m},R{n}"
        if lo == 0x2: return f"cmp/hs R{m},R{n}"
        if lo == 0x3: return f"cmp/ge R{m},R{n}"
        if lo == 0x5: return f"dmulu.l R{m},R{n}"
        if lo == 0x6: return f"cmp/hi R{m},R{n}"
        if lo == 0x7: return f"cmp/gt R{m},R{n}"
        if lo == 0x8: return f"sub R{m},R{n}"
        if lo == 0xA: return f"subc R{m},R{n}"
        if lo == 0xC: return f"add R{m},R{n}"
        if lo == 0xD: return f"dmuls.l R{m},R{n}"
        if lo == 0xE: return f"addc R{m},R{n}"

    if top == 0x7:
        imm = sign8(op & 0xFF)
        return f"add #{imm},R{n}"

    # 0001nnnnmmmmdddd
    if top == 0x1:
        d = lo
        return f"mov.l R{m},@(0x{d*4:X},R{n})"

    # 0101nnnnmmmmdddd
    if top == 0x5:
        d = lo
        return f"mov.l @(0x{d*4:X},R{m}),R{n}"

    # 0100nnnn________
    if top == 0x4:
        lo8 = op & 0xFF
        if lo8 == 0x00: return f"shll R{n}"
        if lo8 == 0x01: return f"shlr R{n}"
        if lo8 == 0x04: return f"rotl R{n}"
        if lo8 == 0x05: return f"rotr R{n}"
        if lo8 == 0x08: return f"shll2 R{n}"
        if lo8 == 0x09: return f"shlr2 R{n}"
        if lo8 == 0x0B: return f"jsr @R{n}"
        if lo8 == 0x10: return f"dt R{n}"
        if lo8 == 0x11: return f"cmp/pz R{n}"
        if lo8 == 0x15: return f"cmp/pl R{n}"
        if lo8 == 0x18: return f"shll8 R{n}"
        if lo8 == 0x19: return f"shlr8 R{n}"
        if lo8 == 0x1E: return f"ldc R{n},GBR"
        if lo8 == 0x20: return f"shal R{n}"
        if lo8 == 0x21: return f"shar R{n}"
        if lo8 == 0x22: return f"sts.l PR,@-R{n}"
        if lo8 == 0x24: return f"rotcl R{n}"
        if lo8 == 0x25: return f"rotcr R{n}"
        if lo8 == 0x26: return f"lds.l @R{n}+,PR"
        if lo8 == 0x28: return f"shll16 R{n}"
        if lo8 == 0x29: return f"shlr16 R{n}"
        if lo8 == 0x2A: return f"lds R{n},PR"
        if lo8 == 0x2B: return f"jmp @R{n}"

    # 0000nnnnmmmm____
    if top == 0x0:
        if lo == 0x4: return f"mov.b R{m},@(R0,R{n})"
        if lo == 0x5: return f"mov.w R{m},@(R0,R{n})"
        if lo == 0x6: return f"mov.l R{m},@(R0,R{n})"
        if lo == 0x7: return f"mul.l R{m},R{n}"
        if lo == 0xC: return f"mov.b @(R0,R{m}),R{n}"
        if lo == 0xD: return f"mov.w @(R0,R{m}),R{n}"
        if lo == 0xE: return f"mov.l @(R0,R{m}),R{n}"
        lo8 = op & 0xFF
        if lo8 == 0x0A: return f"sts MACH,R{n}"
        if lo8 == 0x1A: return f"sts MACL,R{n}"
        if lo8 == 0x2A: return f"sts PR,R{n}"
        if lo8 == 0x12: return f"stc GBR,R{n}"

    # 1000xxxx
    hi8 = (op >> 8) & 0xFF
    if hi8 == 0x80: return f"mov.b R0,@(0x{m:X},R{m})"
    if hi8 == 0x81: return f"mov.w R0,@(0x{(op&0xF)*2:X},R{m})"
    if hi8 == 0x84: return f"mov.b @(0x{lo:X},R{m}),R0"
    if hi8 == 0x85: return f"mov.w @(0x{lo*2:X},R{m}),R0"
    if hi8 == 0x88:
        imm = sign8(op & 0xFF)
        return f"cmp/eq #{op & 0xFF},R0  ; ={imm}"
    if hi8 == 0x89:
        d = sign8(op & 0xFF)
        return f"bt 0x{pc+2+d*2:06X}"
    if hi8 == 0x8B:
        d = sign8(op & 0xFF)
        return f"bf 0x{pc+2+d*2:06X}"
    if hi8 == 0x8D:
        d = sign8(op & 0xFF)
        return f"bt/s 0x{pc+2+d*2:06X}"
    if hi8 == 0x8F:
        d = sign8(op & 0xFF)
        return f"bf/s 0x{pc+2+d*2:06X}"

    if top == 0xA:
        d = sign12(op & 0xFFF)
        return f"bra 0x{pc+2+d*2:06X}"
    if top == 0xB:
        d = sign12(op & 0xFFF)
        return f"bsr 0x{pc+2+d*2:06X}"

    if hi8 == 0xC0: return f"mov.b R0,@(0x{op&0xFF:X},GBR)"
    if hi8 == 0xC1: return f"mov.w R0,@(0x{(op&0xFF)*2:X},GBR)"
    if hi8 == 0xC2: return f"mov.l R0,@(0x{(op&0xFF)*4:X},GBR)"
    if hi8 == 0xC4: return f"mov.b @(0x{op&0xFF:X},GBR),R0"
    if hi8 == 0xC5: return f"mov.w @(0x{(op&0xFF)*2:X},GBR),R0"
    if hi8 == 0xC6: return f"mov.l @(0x{(op&0xFF)*4:X},GBR),R0"
    if hi8 == 0xC8: return f"tst #0x{op&0xFF:02X},R0"
    if hi8 == 0xC9: return f"and #0x{op&0xFF:02X},R0"
    if hi8 == 0xCB: return f"or #0x{op&0xFF:02X},R0"

    return f".word 0x{op:04X}"


def dump(start, end, marks=None):
    if marks is None: marks = set()
    pc = start
    while pc <= end:
        m = disasm(pc)
        flag = " <<<" if pc in marks else ""
        print(f"  {pc:06X}: {read16(pc):04X}  {m}{flag}")
        pc += 2


def track_r6(load_pc, write_pc):
    """Track R6 from load_pc+2 to write_pc. Return True if R6 still holds FFFF7448."""
    pc = load_pc + 2
    ok = True
    while pc < write_pc:
        op = read16(pc)
        top = (op >> 12) & 0xF
        n = (op >> 8) & 0xF
        lo = op & 0xF

        if n == 6:
            # Instructions that write to Rn (R6)
            if top == 0xD:  # mov.l @(disp,PC),R6
                d = op & 0xFF
                a = ((pc+2) & ~3) + d*4
                v = read32(a)
                if v == 0xFFFF7448:
                    pass  # reloaded same value
                else:
                    print(f"    R6 OVERWRITTEN at {pc:06X}: mov.l -> 0x{v:08X}")
                    ok = False
            elif top == 0xE:  # mov #imm,R6
                print(f"    R6 OVERWRITTEN at {pc:06X}: mov #{sign8(op&0xFF)},R6")
                ok = False
            elif top == 0x9:  # mov.w @(disp,PC),R6
                d = op & 0xFF
                a = (pc+2) + d*2
                v = read16(a)
                print(f"    R6 OVERWRITTEN at {pc:06X}: mov.w -> 0x{v:04X}")
                ok = False
            elif top == 0x6 and lo in (0,1,2,3,4,5,6,0xB,0xC,0xD,0xE,0xF):
                print(f"    R6 OVERWRITTEN at {pc:06X}: {disasm(pc)}")
                ok = False
            elif top == 0x7:  # add #imm,R6
                print(f"    R6 MODIFIED at {pc:06X}: add #{sign8(op&0xFF)},R6")
                ok = False
            elif top == 0x3 and lo == 0xC:  # add Rm,R6
                print(f"    R6 MODIFIED at {pc:06X}: add R{(op>>4)&0xF},R6")
                ok = False
            elif top == 0x3 and lo == 0x8:  # sub Rm,R6
                print(f"    R6 MODIFIED at {pc:06X}: sub R{(op>>4)&0xF},R6")
                ok = False
        pc += 2
    return ok


def analyze(name, load_pc, write_pc):
    print(f"\n{'='*78}")
    print(f"  {name}")
    print(f"  Load: {load_pc:06X}  Write: {write_pc:06X}")
    print(f"{'='*78}")

    # Verify literal pool
    op = read16(load_pc)
    if (op >> 12) == 0xD:
        rn = (op >> 8) & 0xF
        d = op & 0xFF
        a = ((load_pc+2) & ~3) + d*4
        v = read32(a)
        print(f"  Literal load: R{rn} = 0x{v:08X} from pool at 0x{a:06X}")
        if v != 0xFFFF7448:
            print(f"  *** NOT 0xFFFF7448 -- SKIP ***")
            return

    # Disassemble context
    ctx_start = max(0, load_pc - 0x20)
    ctx_end = min(len(ROM)-2, write_pc + 0x20)
    print(f"\n  Disassembly {ctx_start:06X}..{ctx_end:06X}:")
    dump(ctx_start, ctx_end, {load_pc, write_pc})

    # Track R6
    print(f"\n  R6 tracking {load_pc:06X}+2 .. {write_pc:06X}:")
    ok = track_r6(load_pc, write_pc)
    if ok:
        print(f"  >>> CONFIRMED: R6 = FFFF7448 at write {write_pc:06X}")
    else:
        print(f"  >>> NOT CONFIRMED: R6 changed before write {write_pc:06X}")

    # What is written
    wop = read16(write_pc)
    src_reg = (wop >> 4) & 0xF
    wtype = "mov.b" if (wop & 0xF) == 0 else "mov.w"
    print(f"  Write instruction: {wtype} R{src_reg},@R6")

    # Try to trace what R{src_reg} holds by looking ~20 instructions back
    print(f"\n  Tracing R{src_reg} value (scanning backwards from write):")
    scan_start = max(load_pc, write_pc - 0x30)
    pc = write_pc - 2
    while pc >= scan_start:
        op2 = read16(pc)
        t2 = (op2 >> 12) & 0xF
        n2 = (op2 >> 8) & 0xF
        if n2 == src_reg:
            if t2 == 0xE:
                imm = sign8(op2 & 0xFF)
                print(f"    {pc:06X}: mov #{imm},R{src_reg}  <-- likely value = {imm}")
                break
            elif t2 == 0xD:
                d2 = op2 & 0xFF
                a2 = ((pc+2) & ~3) + d2*4
                v2 = read32(a2)
                print(f"    {pc:06X}: mov.l -> R{src_reg} = 0x{v2:08X}")
                break
            elif t2 == 0x6 and (op2 & 0xF) == 0x3:
                sm = (op2 >> 4) & 0xF
                print(f"    {pc:06X}: mov R{sm},R{src_reg}  <-- value from R{sm}")
                # continue tracing R{sm}
                src_reg = sm
            elif t2 == 0x6 and (op2 & 0xF) in (0, 1, 2, 4, 5, 6):
                print(f"    {pc:06X}: {disasm(pc)}  <-- loaded from memory")
                break
            elif t2 == 0x9:
                d2 = op2 & 0xFF
                a2 = (pc+2) + d2*2
                v2 = read16(a2)
                print(f"    {pc:06X}: mov.w -> R{src_reg} = 0x{v2:04X}")
                break
            else:
                print(f"    {pc:06X}: {disasm(pc)}  <-- modifies R{src_reg}")
                break
        pc -= 2
    print()


# ============================================================
# Function 0x0387E4 context
# ============================================================
print("="*78)
print("  FUNCTION 0x0387E4 - entry and structure")
print("="*78)
dump(0x0387E4, 0x038840)

# ============================================================
# All groups
# ============================================================

analyze("Group 1: func ~0x0387E4, load 0x038914, write 0x0389B0",
        0x038914, 0x0389B0)

# Extended view around write
print("  Extended context around 0x0389B0:")
dump(0x038990, 0x0389E0, {0x0389B0})

analyze("Group 2: load 0x032E3E, write 0x032FB8 (mov.w)",
        0x032E3E, 0x032FB8)

analyze("Group 3: load 0x039542, write 0x039964",
        0x039542, 0x039964)

analyze("Group 4: load 0x03CD68, write 0x03CFD0",
        0x03CD68, 0x03CFD0)

analyze("Group 5a: load 0x07D6D4, write 0x07DA12",
        0x07D6D4, 0x07DA12)

analyze("Group 5b: load 0x07D6D4, write 0x07DA1A",
        0x07D6D4, 0x07DA1A)
