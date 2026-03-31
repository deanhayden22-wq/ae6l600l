#!/usr/bin/env python3
"""
Find all code that writes to RAM address FFFF79E0 in the SH-2 ECU ROM.
"""
import struct, sys

ROM_PATH = 'C:/Users/Dean/Documents/GitHub/ae6l600l/rom/AE5L600L 20g rev 20.5 tiny wrex.bin'
TARGET = 0xFFFF79E0

with open(ROM_PATH, 'rb') as f:
    rom = f.read()

print(f"ROM size: 0x{len(rom):X} bytes")
print(f"Target RAM address: 0x{TARGET:08X}")
print()

def read_u16(data, addr):
    return struct.unpack('>H', data[addr:addr+2])[0]

def read_u32(data, addr):
    return struct.unpack('>I', data[addr:addr+4])[0]

def read_float(data, addr):
    return struct.unpack('>f', data[addr:addr+4])[0]

def sign12(v):
    return v if v < 2048 else v - 4096

def read_s8(val):
    if val > 127: return val - 256
    return val

# ============================================================
# STEP 1: Scan all 4-byte aligned literal pool entries for
#         values that could reach FFFF79E0 via offset
# ============================================================
print("=" * 80)
print("STEP 1: Scanning literal pools for addresses near FFFF79E0")
print("=" * 80)

nearby_bases = []
for addr in range(0, len(rom) - 3, 4):
    val = read_u32(rom, addr)
    if 0xFFFF7900 <= val <= 0xFFFF7A20:
        offset = TARGET - val
        nearby_bases.append((addr, val, offset))
        print(f"  ROM 0x{addr:05X}: 0x{val:08X}  (offset to target: {offset:+d} = 0x{offset & 0xFFFFFFFF:08X})")

print(f"\nTotal nearby base addresses found: {len(nearby_bases)}")
print()

# ============================================================
# STEP 2: Scan ALL fmov.s write instructions
# ============================================================
print("=" * 80)
print("STEP 2: Scan ALL fmov.s write instructions in ROM")
print("=" * 80)

all_fmov_writes = []
for addr in range(0, len(rom) - 1, 2):
    op = read_u16(rom, addr)
    top = (op >> 12) & 0xF
    d4 = op & 0xF
    n = (op >> 8) & 0xF
    m = (op >> 4) & 0xF

    # fmov.s FRm,@(R0,Rn) = 1111nnnnmmmm0111
    if top == 0xF and d4 == 0x7:
        all_fmov_writes.append((addr, n, m, 'fmov.s_indexed'))
    # fmov.s FRm,@Rn = 1111nnnnmmmm1010
    if top == 0xF and d4 == 0xA:
        all_fmov_writes.append((addr, n, m, 'fmov.s_direct'))

print(f"Total fmov.s write instructions in ROM: {len(all_fmov_writes)}")

# ============================================================
# STEP 3: For each write, look back for base register loads
# ============================================================
print()
print("=" * 80)
print("STEP 3: Check each fmov.s write for FFFF79E0 context")
print("=" * 80)

def lookback_regs(write_addr, rn_reg, max_back=150):
    """Look backwards from write_addr to find what registers contain."""
    reg_vals = {}  # reg -> (load_addr, value)

    for j in range(1, max_back):
        a = write_addr - j * 2
        if a < 0:
            break
        op2 = read_u16(rom, a)
        top2 = (op2 >> 12) & 0xF
        n2 = (op2 >> 8) & 0xF
        m2 = (op2 >> 4) & 0xF
        d8_2 = op2 & 0xFF
        d4_2 = op2 & 0xF

        # mov.l @(pool,PC), Rn
        if top2 == 0xD:
            pool = ((a + 4) & ~3) + d8_2 * 4
            if pool + 3 < len(rom):
                val = read_u32(rom, pool)
                if n2 not in reg_vals:
                    reg_vals[n2] = (a, val)

        # mov #imm, Rn
        if top2 == 0xE:
            imm = read_s8(d8_2)
            if n2 not in reg_vals:
                reg_vals[n2] = (a, imm)

        # mov.w @(pool,PC), Rn (sign extended)
        if top2 == 0x9:
            pool = a + 4 + d8_2 * 2
            if pool + 1 < len(rom):
                val16 = struct.unpack('>h', rom[pool:pool+2])[0]
                if n2 not in reg_vals:
                    reg_vals[n2] = (a, val16)

        # Stop at function prologue (sts.l PR,@-SP = 4F22)
        if op2 == 0x4F22:
            break

    return reg_vals

confirmed_writes = []
candidates = []

for (write_addr, rn_reg, fm_reg, kind) in all_fmov_writes:
    if kind == 'fmov.s_indexed':
        # addr = R0 + Rn
        reg_vals = lookback_regs(write_addr, rn_reg)

        rn_info = reg_vals.get(rn_reg)
        r0_info = reg_vals.get(0)

        if rn_info and r0_info:
            rn_val = rn_info[1]
            r0_val = r0_info[1]
            computed = (rn_val + r0_val) & 0xFFFFFFFF
            if computed == TARGET:
                print(f"\n  *** CONFIRMED WRITE at 0x{write_addr:05X}: fmov.s FR{fm_reg},@(R0,R{rn_reg}) ***")
                print(f"      R{rn_reg}=0x{rn_val:08X} (from 0x{rn_info[0]:05X}), R0={r0_val} (from 0x{r0_info[0]:05X})")
                print(f"      Computed address: 0x{computed:08X} == TARGET")
                confirmed_writes.append((write_addr, rn_reg, fm_reg, rn_val, r0_val))

        elif rn_info:
            rn_val = rn_info[1]
            needed = (TARGET - rn_val) & 0xFFFFFFFF
            needed_s = needed if needed < 0x80000000 else needed - 0x100000000
            if -128 <= needed_s <= 127:
                print(f"\n  CANDIDATE WRITE at 0x{write_addr:05X}: fmov.s FR{fm_reg},@(R0,R{rn_reg})")
                print(f"      R{rn_reg}=0x{rn_val:08X} (from 0x{rn_info[0]:05X}), need R0={needed_s}")
                print(f"      (R0 not definitively tracked in lookback window)")
                candidates.append((write_addr, rn_reg, fm_reg, rn_val, needed_s))

    elif kind == 'fmov.s_direct':
        # addr = Rn directly
        reg_vals = lookback_regs(write_addr, rn_reg)
        rn_info = reg_vals.get(rn_reg)
        if rn_info and (rn_info[1] & 0xFFFFFFFF) == TARGET:
            print(f"\n  *** DIRECT WRITE at 0x{write_addr:05X}: fmov.s FR{fm_reg},@R{rn_reg} ***")
            print(f"      R{rn_reg}=0x{rn_info[1]:08X} (from 0x{rn_info[0]:05X})")
            confirmed_writes.append((write_addr, rn_reg, fm_reg, rn_info[1], 0))

print(f"\nTotal confirmed writes: {len(confirmed_writes)}")
print(f"Total candidates (R0 untracked): {len(candidates)}")

# ============================================================
# STEP 4: Also check integer writes (mov.l Rn,@(R0,Rm))
# ============================================================
print()
print("=" * 80)
print("STEP 4: Check integer mov.l @(R0,Rn) writes")
print("=" * 80)

int_writes = []
for addr in range(0, len(rom) - 1, 2):
    op = read_u16(rom, addr)
    # mov.l Rm,@(R0,Rn) = 0000nnnnmmmm0110
    if (op & 0xF00F) == 0x0006:
        n = (op >> 8) & 0xF
        m = (op >> 4) & 0xF
        reg_vals = lookback_regs(addr, n)
        rn_info = reg_vals.get(n)
        r0_info = reg_vals.get(0)
        if rn_info and r0_info:
            computed = (rn_info[1] + r0_info[1]) & 0xFFFFFFFF
            if computed == TARGET:
                print(f"  INT WRITE at 0x{addr:05X}: mov.l R{m},@(R0,R{n})")
                print(f"      R{n}=0x{rn_info[1]:08X}, R0={r0_info[1]}")
                int_writes.append(addr)

print(f"Total integer writes to FFFF79E0: {len(int_writes)}")
print()

# ============================================================
# STEP 5: Full disassembly context
# ============================================================

def disasm_brief(addr):
    if addr < 0 or addr + 1 >= len(rom):
        return f"  {addr:05X}: (out of range)"
    op = read_u16(rom, addr)
    top = (op >> 12) & 0xF
    n = (op >> 8) & 0xF
    m = (op >> 4) & 0xF
    d4 = op & 0xF
    d8 = op & 0xFF

    GBR_BASE = 0xFFFF7450

    if op == 0x000B: return f"  {addr:05X}: {op:04X}  rts"
    if op == 0x0009: return f"  {addr:05X}: {op:04X}  nop"
    if op == 0x0028: return f"  {addr:05X}: {op:04X}  clrmac"
    if op == 0x4F22: return f"  {addr:05X}: {op:04X}  sts.l  PR,@-R15  ; function prologue"

    if top == 0x0:
        sub = op & 0xF
        if sub == 0x6: return f"  {addr:05X}: {op:04X}  mov.l  R{m},@(R0,R{n})"
        if sub == 0x7: return f"  {addr:05X}: {op:04X}  mul.l  R{m},R{n}"
        if sub == 0x2:
            if m == 1: return f"  {addr:05X}: {op:04X}  stc    GBR,R{n}"
            if m == 0: return f"  {addr:05X}: {op:04X}  stc    SR,R{n}"
        if sub == 0xA:
            if m == 2: return f"  {addr:05X}: {op:04X}  sts    PR,R{n}"
        if sub == 0xE: return f"  {addr:05X}: {op:04X}  mov.l  @(R0,R{m}),R{n}"
        if sub == 0x3: return f"  {addr:05X}: {op:04X}  bsrf   R{n}"
    if top == 0x1:
        disp = d4 * 4
        return f"  {addr:05X}: {op:04X}  mov.l  R{m},@({disp},R{n})"
    if top == 0x2:
        sub = op & 0xF
        if sub == 0: return f"  {addr:05X}: {op:04X}  mov.b  R{m},@R{n}"
        if sub == 1: return f"  {addr:05X}: {op:04X}  mov.w  R{m},@R{n}"
        if sub == 2: return f"  {addr:05X}: {op:04X}  mov.l  R{m},@R{n}"
        if sub == 4: return f"  {addr:05X}: {op:04X}  mov.b  R{m},@-R{n}"
        if sub == 5: return f"  {addr:05X}: {op:04X}  mov.w  R{m},@-R{n}"
        if sub == 6: return f"  {addr:05X}: {op:04X}  mov.l  R{m},@-R{n}"
        if sub == 8: return f"  {addr:05X}: {op:04X}  tst    R{m},R{n}"
        if sub == 9: return f"  {addr:05X}: {op:04X}  and    R{m},R{n}"
        if sub == 0xA: return f"  {addr:05X}: {op:04X}  xor    R{m},R{n}"
        if sub == 0xB: return f"  {addr:05X}: {op:04X}  or     R{m},R{n}"
        if sub == 7: return f"  {addr:05X}: {op:04X}  div0s  R{m},R{n}"
    if top == 0x3:
        sub = op & 0xF
        ops3 = {0:"cmp/eq",2:"cmp/hs",3:"cmp/ge",4:"div1",5:"dmulu.l",
                6:"cmp/hi",7:"cmp/gt",8:"sub",0xA:"subc",0xC:"add",0xD:"dmuls.l",0xE:"addc"}
        if sub in ops3: return f"  {addr:05X}: {op:04X}  {ops3[sub]}  R{m},R{n}"
    if top == 0x4:
        low8 = op & 0xFF
        if low8 == 0x22: return f"  {addr:05X}: {op:04X}  sts.l  PR,@-R{n}"
        if low8 == 0x26: return f"  {addr:05X}: {op:04X}  lds.l  @R{n}+,PR"
        if low8 == 0x0B: return f"  {addr:05X}: {op:04X}  jsr    @R{n}"
        if low8 == 0x2B: return f"  {addr:05X}: {op:04X}  jmp    @R{n}"
        if low8 == 0x15: return f"  {addr:05X}: {op:04X}  cmp/pl R{n}"
        if low8 == 0x11: return f"  {addr:05X}: {op:04X}  cmp/pz R{n}"
        if low8 == 0x10: return f"  {addr:05X}: {op:04X}  dt     R{n}"
        if low8 == 0x00: return f"  {addr:05X}: {op:04X}  shll   R{n}"
        if low8 == 0x01: return f"  {addr:05X}: {op:04X}  shlr   R{n}"
        if low8 == 0x08: return f"  {addr:05X}: {op:04X}  shll2  R{n}"
        if low8 == 0x09: return f"  {addr:05X}: {op:04X}  shlr2  R{n}"
        if low8 == 0x18: return f"  {addr:05X}: {op:04X}  shll8  R{n}"
        if low8 == 0x28: return f"  {addr:05X}: {op:04X}  shll16 R{n}"
        if low8 == 0x2A: return f"  {addr:05X}: {op:04X}  lds    R{n},PR"
        if low8 == 0x0A: return f"  {addr:05X}: {op:04X}  lds    R{n},MACH"
        if low8 == 0x1A: return f"  {addr:05X}: {op:04X}  lds    R{n},MACL"
        if low8 == 0x1E: return f"  {addr:05X}: {op:04X}  ldc    R{n},GBR"
        if low8 == 0x24: return f"  {addr:05X}: {op:04X}  rotcl  R{n}"
        lo1 = op & 0xF
        if lo1 == 0xC: return f"  {addr:05X}: {op:04X}  shad   R{m},R{n}"
        if lo1 == 0xD: return f"  {addr:05X}: {op:04X}  shld   R{m},R{n}"
    if top == 0x5:
        disp = d4 * 4
        return f"  {addr:05X}: {op:04X}  mov.l  @({disp},R{m}),R{n}"
    if top == 0x6:
        sub = op & 0xF
        if sub == 0: return f"  {addr:05X}: {op:04X}  mov.b  @R{m},R{n}"
        if sub == 1: return f"  {addr:05X}: {op:04X}  mov.w  @R{m},R{n}"
        if sub == 2: return f"  {addr:05X}: {op:04X}  mov.l  @R{m},R{n}"
        if sub == 3: return f"  {addr:05X}: {op:04X}  mov    R{m},R{n}"
        if sub == 4: return f"  {addr:05X}: {op:04X}  mov.b  @R{m}+,R{n}"
        if sub == 5: return f"  {addr:05X}: {op:04X}  mov.w  @R{m}+,R{n}"
        if sub == 6: return f"  {addr:05X}: {op:04X}  mov.l  @R{m}+,R{n}"
        if sub == 7: return f"  {addr:05X}: {op:04X}  not    R{m},R{n}"
        if sub == 0xB: return f"  {addr:05X}: {op:04X}  neg    R{m},R{n}"
        if sub == 0xC: return f"  {addr:05X}: {op:04X}  extu.b R{m},R{n}"
        if sub == 0xD: return f"  {addr:05X}: {op:04X}  extu.w R{m},R{n}"
        if sub == 0xE: return f"  {addr:05X}: {op:04X}  exts.b R{m},R{n}"
        if sub == 0xF: return f"  {addr:05X}: {op:04X}  exts.w R{m},R{n}"
    if top == 0x7:
        imm = read_s8(d8)
        return f"  {addr:05X}: {op:04X}  add    #{imm},R{n}"
    if top == 0x8:
        sub = (op >> 8) & 0xF
        if sub == 0x9:
            disp = read_s8(d8) * 2 + 4
            return f"  {addr:05X}: {op:04X}  bt     0x{addr+disp:05X}"
        if sub == 0xB:
            disp = read_s8(d8) * 2 + 4
            return f"  {addr:05X}: {op:04X}  bf     0x{addr+disp:05X}"
        if sub == 0xD:
            disp = read_s8(d8) * 2 + 4
            return f"  {addr:05X}: {op:04X}  bt/s   0x{addr+disp:05X}"
        if sub == 0xF:
            disp = read_s8(d8) * 2 + 4
            return f"  {addr:05X}: {op:04X}  bf/s   0x{addr+disp:05X}"
        if sub == 0x8:
            return f"  {addr:05X}: {op:04X}  cmp/eq #{read_s8(d8)},R0"
        if sub == 0x0:
            return f"  {addr:05X}: {op:04X}  mov.b  R0,@({d4},R{m})"
        if sub == 0x1:
            return f"  {addr:05X}: {op:04X}  mov.w  R0,@({d4*2},R{m})"
    if top == 0x9:
        pool = addr + 4 + d8 * 2
        if pool + 1 < len(rom):
            val = read_u16(rom, pool)
            return f"  {addr:05X}: {op:04X}  mov.w  @(0x{pool:05X},PC),R{n}  ; R{n}=0x{val:04X}"
    if top == 0xA:
        disp12 = op & 0xFFF
        target = addr + 4 + sign12(disp12) * 2
        return f"  {addr:05X}: {op:04X}  bra    0x{target:05X}"
    if top == 0xB:
        disp12 = op & 0xFFF
        target = addr + 4 + sign12(disp12) * 2
        return f"  {addr:05X}: {op:04X}  bsr    0x{target:05X}"
    if top == 0xC:
        sub = (op >> 8) & 0xF
        if sub == 0x7:
            pool_addr = ((addr + 4) & ~3) + d8 * 4
            if pool_addr + 3 < len(rom):
                val = read_u32(rom, pool_addr)
                return f"  {addr:05X}: {op:04X}  mova   @(0x{pool_addr:05X},PC),R0  ; R0=0x{pool_addr:05X}"
        if sub == 0x6:
            disp = d8 * 4
            return f"  {addr:05X}: {op:04X}  mov.l  @({disp:#x},GBR),R0  ; [{GBR_BASE+disp:08X}]"
        if sub == 0x2:
            disp = d8 * 4
            return f"  {addr:05X}: {op:04X}  mov.l  R0,@({disp:#x},GBR)  ; [{GBR_BASE+disp:08X}]"
        if sub == 0x8: return f"  {addr:05X}: {op:04X}  tst    #0x{d8:02X},R0"
        if sub == 0x9: return f"  {addr:05X}: {op:04X}  and    #0x{d8:02X},R0"
        if sub == 0xB: return f"  {addr:05X}: {op:04X}  or     #0x{d8:02X},R0"
        if sub == 0xF: return f"  {addr:05X}: {op:04X}  or.b   #0x{d8:02X},@(R0,GBR)"
    if top == 0xD:
        disp = d8 * 4
        pool_addr = ((addr + 4) & ~3) + disp
        if pool_addr + 3 < len(rom):
            val = read_u32(rom, pool_addr)
            extra = ""
            if 0xFFFF0000 <= val <= 0xFFFFFFFF:
                diff = val - TARGET
                if diff == 0:
                    extra = f"  *** TARGET 0x{val:08X} ***"
                elif abs(diff) <= 256:
                    extra = f"  (RAM {diff:+d} from FFFF79E0 => 0x{val:08X})"
                else:
                    extra = f"  (RAM 0x{val:08X})"
            elif val < 0x50000:
                extra = f"  (ROM 0x{val:05X})"
            else:
                try:
                    fv = struct.unpack('>f', struct.pack('>I', val))[0]
                    if 1e-8 < abs(fv) < 1e8:
                        extra = f"  (const float={fv:.6f})"
                except:
                    pass
            return f"  {addr:05X}: {op:04X}  mov.l  @(0x{pool_addr:05X},PC),R{n}  ; R{n}=0x{val:08X}{extra}"
        return f"  {addr:05X}: {op:04X}  mov.l  @(pool),R{n}"
    if top == 0xE:
        imm = read_s8(d8)
        return f"  {addr:05X}: {op:04X}  mov    #{imm},R{n}"
    if top == 0xF:
        sub = op & 0xF
        fn = n; fm = m
        if sub == 0x0: return f"  {addr:05X}: {op:04X}  fadd   FR{fm},FR{fn}"
        if sub == 0x1: return f"  {addr:05X}: {op:04X}  fsub   FR{fm},FR{fn}"
        if sub == 0x2: return f"  {addr:05X}: {op:04X}  fmul   FR{fm},FR{fn}"
        if sub == 0x3: return f"  {addr:05X}: {op:04X}  fdiv   FR{fm},FR{fn}"
        if sub == 0x4: return f"  {addr:05X}: {op:04X}  fcmp/eq FR{fm},FR{fn}"
        if sub == 0x5: return f"  {addr:05X}: {op:04X}  fcmp/gt FR{fm},FR{fn}"
        if sub == 0x6: return f"  {addr:05X}: {op:04X}  fmov.s @(R0,R{m}),FR{fn}"
        if sub == 0x7: return f"  {addr:05X}: {op:04X}  fmov.s FR{fn},@(R0,R{m})"
        if sub == 0x8: return f"  {addr:05X}: {op:04X}  fmov.s @R{m},FR{fn}"
        if sub == 0x9: return f"  {addr:05X}: {op:04X}  fmov.s @R{m}+,FR{fn}"
        if sub == 0xA: return f"  {addr:05X}: {op:04X}  fmov.s FR{fn},@R{m}"
        if sub == 0xB: return f"  {addr:05X}: {op:04X}  fmov.s FR{fn},@-R{m}"
        if sub == 0xC: return f"  {addr:05X}: {op:04X}  fmov   FR{fm},FR{fn}"
        if sub == 0xD:
            if fm == 0: return f"  {addr:05X}: {op:04X}  fsts   FPUL,FR{fn}"
            if fm == 1: return f"  {addr:05X}: {op:04X}  flds   FR{fn},FPUL"
            if fm == 2: return f"  {addr:05X}: {op:04X}  float  FPUL,FR{fn}"
            if fm == 3: return f"  {addr:05X}: {op:04X}  ftrc   FR{fn},FPUL"
            if fm == 4: return f"  {addr:05X}: {op:04X}  fneg   FR{fn}"
            if fm == 5: return f"  {addr:05X}: {op:04X}  fabs   FR{fn}"
            if fm == 8: return f"  {addr:05X}: {op:04X}  fldi0  FR{fn}"
            if fm == 9: return f"  {addr:05X}: {op:04X}  fldi1  FR{fn}"
            if fm == 0xA: return f"  {addr:05X}: {op:04X}  lds    R{n},FPUL"
        if sub == 0xE: return f"  {addr:05X}: {op:04X}  fmac   FR0,FR{fm},FR{fn}"
    return f"  {addr:05X}: {op:04X}  .word 0x{op:04X}"

def dump_context(addr, before=50, after=50):
    start = max(0, addr - before * 2)
    end = min(len(rom) - 2, addr + after * 2)
    for a in range(start, end + 1, 2):
        line = disasm_brief(a)
        if a == addr:
            line = ">>>" + line[3:]
        print(line)

print()
print("=" * 80)
print("STEP 5: Full disassembly context for all writes/candidates")
print("=" * 80)

all_to_dump = set()
for w in confirmed_writes:
    all_to_dump.add(w[0])
for w in candidates:
    all_to_dump.add(w[0])

for write_addr in sorted(all_to_dump):
    print(f"\n{'='*70}")
    print(f"  WRITE/CANDIDATE at ROM 0x{write_addr:05X}")
    print(f"{'='*70}")
    dump_context(write_addr, before=60, after=60)

print()
print("=" * 80)
print("SUMMARY")
print("=" * 80)
print(f"Confirmed writes to FFFF79E0: {len(confirmed_writes)}")
for w in confirmed_writes:
    print(f"  0x{w[0]:05X}: fmov.s FR{w[2]},@(R0,R{w[1]})  base=0x{w[3]:08X} R0={w[4]}")
print(f"Candidates (R0 not tracked): {len(candidates)}")
for w in candidates:
    print(f"  0x{w[0]:05X}: fmov.s FR{w[2]},@(R0,R{w[1]})  base=0x{w[3]:08X} need R0={w[4]}")
