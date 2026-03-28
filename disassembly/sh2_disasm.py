import struct, sys

with open('C:/Users/Dean/Documents/GitHub/ae6l600l/rom/ae5l600l.bin', 'rb') as f:
    rom = f.read()

with open('C:/Users/Dean/Documents/GitHub/ae6l600l/rom/AE5L600L 20g rev 20.5 tiny wrex.bin', 'rb') as f:
    mod_rom = f.read()

GBR = 0xFFFF7450

def read_u16(data, addr):
    return struct.unpack('>H', data[addr:addr+2])[0]

def read_u32(data, addr):
    return struct.unpack('>I', data[addr:addr+4])[0]

def read_float(data, addr):
    return struct.unpack('>f', data[addr:addr+4])[0]

def read_s8(val):
    if val > 127: return val - 256
    return val

def rn(n): return f"R{n}"
def frn(n): return f"FR{n}"

start = 0x03162C
end_addr = 0x031A00

addr = start
lines = []

while addr < end_addr:
    if addr >= len(rom) - 1:
        break

    op = read_u16(rom, addr)
    nibbles = [(op >> 12) & 0xF, (op >> 8) & 0xF, (op >> 4) & 0xF, op & 0xF]
    n_reg = nibbles[1]
    m_reg = nibbles[2]
    d8 = op & 0xFF
    d4 = op & 0xF

    mnemonic = ""
    comment = ""

    top = nibbles[0]

    if op == 0x0009:
        mnemonic = "nop"
    elif op == 0x000B:
        mnemonic = "rts"
    elif op == 0x0019:
        mnemonic = "div0u"
    elif top == 0x0:
        sub = nibbles[3]
        if sub == 0xC:
            mnemonic = f"mov.b  @(R0,{rn(m_reg)}),{rn(n_reg)}"
        elif sub == 0xD:
            mnemonic = f"mov.w  @(R0,{rn(m_reg)}),{rn(n_reg)}"
        elif sub == 0xE:
            mnemonic = f"mov.l  @(R0,{rn(m_reg)}),{rn(n_reg)}"
        elif sub == 0x4:
            mnemonic = f"mov.b  {rn(m_reg)},@(R0,{rn(n_reg)})"
        elif sub == 0x5:
            mnemonic = f"mov.w  {rn(m_reg)},@(R0,{rn(n_reg)})"
        elif sub == 0x6:
            mnemonic = f"mov.l  {rn(m_reg)},@(R0,{rn(n_reg)})"
        elif sub == 0x7:
            mnemonic = f"mul.l  {rn(m_reg)},{rn(n_reg)}"
        elif sub == 0x2:
            if m_reg == 0:
                mnemonic = f"stc    SR,{rn(n_reg)}"
            elif m_reg == 1:
                mnemonic = f"stc    GBR,{rn(n_reg)}"
            else:
                mnemonic = f".word  0x{op:04X}"
        elif sub == 0xA:
            if m_reg == 0:
                mnemonic = f"sts    MACH,{rn(n_reg)}"
            elif m_reg == 1:
                mnemonic = f"sts    MACL,{rn(n_reg)}"
            elif m_reg == 2:
                mnemonic = f"sts    PR,{rn(n_reg)}"
            else:
                mnemonic = f".word  0x{op:04X}"
        else:
            mnemonic = f".word  0x{op:04X}"

    elif top == 0x1:
        disp = d4 * 4
        mnemonic = f"mov.l  {rn(m_reg)},@({disp},{rn(n_reg)})"
        if n_reg == 15:
            comment = f"  ; stack[0x{disp:02X}]"

    elif top == 0x2:
        sub = nibbles[3]
        if sub in (0,1,2):
            sz = {0:".b",1:".w",2:".l"}[sub]
            mnemonic = f"mov{sz}  {rn(m_reg)},@{rn(n_reg)}"
        elif sub in (4,5,6):
            sz = {4:".b",5:".w",6:".l"}[sub]
            mnemonic = f"mov{sz}  {rn(m_reg)},@-{rn(n_reg)}"
        elif sub == 8:
            mnemonic = f"tst    {rn(m_reg)},{rn(n_reg)}"
        elif sub == 9:
            mnemonic = f"and    {rn(m_reg)},{rn(n_reg)}"
        elif sub == 0xA:
            mnemonic = f"xor    {rn(m_reg)},{rn(n_reg)}"
        elif sub == 0xB:
            mnemonic = f"or     {rn(m_reg)},{rn(n_reg)}"
        else:
            mnemonic = f".word  0x{op:04X}"

    elif top == 0x3:
        sub = nibbles[3]
        ops3 = {0:"cmp/eq",2:"cmp/hs",3:"cmp/ge",4:"div1",5:"dmulu.l",
                6:"cmp/hi",7:"cmp/gt",8:"sub",0xA:"subc",0xC:"add",
                0xD:"dmuls.l",0xE:"addc",0xF:"addv"}
        if sub in ops3:
            mnemonic = f"{ops3[sub]:7s}{rn(m_reg)},{rn(n_reg)}"
        else:
            mnemonic = f".word  0x{op:04X}"

    elif top == 0x4:
        low8 = op & 0xFF
        if low8 == 0x22:
            mnemonic = f"sts.l  PR,@-{rn(n_reg)}"
        elif low8 == 0x26:
            mnemonic = f"lds.l  @{rn(n_reg)}+,PR"
        elif low8 == 0x13:
            mnemonic = f"stc.l  GBR,@-{rn(n_reg)}"
        elif low8 == 0x17:
            mnemonic = f"ldc.l  @{rn(n_reg)}+,GBR"
        elif low8 == 0x1E:
            mnemonic = f"ldc    {rn(n_reg)},GBR"
        elif low8 == 0x0B:
            mnemonic = f"jsr    @{rn(n_reg)}"
        elif low8 == 0x2B:
            mnemonic = f"jmp    @{rn(n_reg)}"
        elif low8 == 0x15:
            mnemonic = f"cmp/pl {rn(n_reg)}"
        elif low8 == 0x11:
            mnemonic = f"cmp/pz {rn(n_reg)}"
        elif low8 == 0x10:
            mnemonic = f"dt     {rn(n_reg)}"
        elif low8 == 0x00:
            mnemonic = f"shll   {rn(n_reg)}"
        elif low8 == 0x01:
            mnemonic = f"shlr   {rn(n_reg)}"
        elif low8 == 0x04:
            mnemonic = f"rotl   {rn(n_reg)}"
        elif low8 == 0x05:
            mnemonic = f"rotr   {rn(n_reg)}"
        elif low8 == 0x08:
            mnemonic = f"shll2  {rn(n_reg)}"
        elif low8 == 0x09:
            mnemonic = f"shlr2  {rn(n_reg)}"
        elif low8 == 0x18:
            mnemonic = f"shll8  {rn(n_reg)}"
        elif low8 == 0x19:
            mnemonic = f"shlr8  {rn(n_reg)}"
        elif low8 == 0x28:
            mnemonic = f"shll16 {rn(n_reg)}"
        elif low8 == 0x29:
            mnemonic = f"shlr16 {rn(n_reg)}"
        elif low8 == 0x24:
            mnemonic = f"rotcl  {rn(n_reg)}"
        elif low8 == 0x25:
            mnemonic = f"rotcr  {rn(n_reg)}"
        else:
            mnemonic = f".word  0x{op:04X}  ; 4xxx"

    elif top == 0x5:
        disp = d4 * 4
        mnemonic = f"mov.l  @({disp},{rn(m_reg)}),{rn(n_reg)}"

    elif top == 0x6:
        sub = nibbles[3]
        if sub == 0: mnemonic = f"mov.b  @{rn(m_reg)},{rn(n_reg)}"
        elif sub == 1: mnemonic = f"mov.w  @{rn(m_reg)},{rn(n_reg)}"
        elif sub == 2: mnemonic = f"mov.l  @{rn(m_reg)},{rn(n_reg)}"
        elif sub == 3: mnemonic = f"mov    {rn(m_reg)},{rn(n_reg)}"
        elif sub == 4: mnemonic = f"mov.b  @{rn(m_reg)}+,{rn(n_reg)}"
        elif sub == 5: mnemonic = f"mov.w  @{rn(m_reg)}+,{rn(n_reg)}"
        elif sub == 6: mnemonic = f"mov.l  @{rn(m_reg)}+,{rn(n_reg)}"
        elif sub == 7: mnemonic = f"not    {rn(m_reg)},{rn(n_reg)}"
        elif sub == 8: mnemonic = f"swap.b {rn(m_reg)},{rn(n_reg)}"
        elif sub == 9: mnemonic = f"swap.w {rn(m_reg)},{rn(n_reg)}"
        elif sub == 0xA: mnemonic = f"negc   {rn(m_reg)},{rn(n_reg)}"
        elif sub == 0xB: mnemonic = f"neg    {rn(m_reg)},{rn(n_reg)}"
        elif sub == 0xC: mnemonic = f"extu.b {rn(m_reg)},{rn(n_reg)}"
        elif sub == 0xD: mnemonic = f"extu.w {rn(m_reg)},{rn(n_reg)}"
        elif sub == 0xE: mnemonic = f"exts.b {rn(m_reg)},{rn(n_reg)}"
        elif sub == 0xF: mnemonic = f"exts.w {rn(m_reg)},{rn(n_reg)}"
        else: mnemonic = f".word  0x{op:04X}"

    elif top == 0x7:
        imm = read_s8(d8)
        mnemonic = f"add    #{imm},{rn(n_reg)}"
        if n_reg == 15:
            comment = f"  ; SP += {imm}"

    elif top == 0x8:
        sub = nibbles[1]
        if sub == 0x0:
            mnemonic = f"mov.b  R0,@({d4},{rn(m_reg)})"
        elif sub == 0x1:
            mnemonic = f"mov.w  R0,@({d4*2},{rn(m_reg)})"
        elif sub == 0x4:
            mnemonic = f"mov.b  @({d4},{rn(m_reg)}),R0"
        elif sub == 0x5:
            mnemonic = f"mov.w  @({d4*2},{rn(m_reg)}),R0"
        elif sub == 0x8:
            imm = read_s8(d8)
            mnemonic = f"cmp/eq #{imm},R0"
        elif sub == 0x9:
            disp = read_s8(d8) * 2 + 4
            target = addr + disp
            mnemonic = f"bt     0x{target:06X}"
        elif sub == 0xB:
            disp = read_s8(d8) * 2 + 4
            target = addr + disp
            mnemonic = f"bf     0x{target:06X}"
        elif sub == 0xD:
            disp = read_s8(d8) * 2 + 4
            target = addr + disp
            mnemonic = f"bt/s   0x{target:06X}"
        elif sub == 0xF:
            disp = read_s8(d8) * 2 + 4
            target = addr + disp
            mnemonic = f"bf/s   0x{target:06X}"
        else:
            mnemonic = f".word  0x{op:04X}"

    elif top == 0x9:
        disp = d8 * 2
        pool_addr = addr + 4 + disp
        val = read_u16(rom, pool_addr)
        mnemonic = f"mov.w  @(0x{pool_addr:06X}),{rn(n_reg)}"
        comment = f"  ; #{val} (0x{val:04X})"

    elif top == 0xA:
        disp12 = op & 0xFFF
        if disp12 > 0x7FF:
            disp12 -= 0x1000
        target = addr + 4 + disp12 * 2
        mnemonic = f"bra    0x{target:06X}"

    elif top == 0xB:
        disp12 = op & 0xFFF
        if disp12 > 0x7FF:
            disp12 -= 0x1000
        target = addr + 4 + disp12 * 2
        mnemonic = f"bsr    0x{target:06X}"

    elif top == 0xC:
        sub = nibbles[1]
        if sub == 0x0:
            disp = d8
            gbr_addr = GBR + disp
            mnemonic = f"mov.b  R0,@(0x{disp:02X},GBR)"
            comment = f"  ; write [{gbr_addr:08X}]"
        elif sub == 0x1:
            disp = d8 * 2
            gbr_addr = GBR + disp
            mnemonic = f"mov.w  R0,@(0x{disp:04X},GBR)"
            comment = f"  ; write [{gbr_addr:08X}]"
        elif sub == 0x2:
            disp = d8 * 4
            gbr_addr = GBR + disp
            mnemonic = f"mov.l  R0,@(0x{disp:04X},GBR)"
            comment = f"  ; write [{gbr_addr:08X}]"
        elif sub == 0x4:
            disp = d8
            gbr_addr = GBR + disp
            mnemonic = f"mov.b  @(0x{disp:02X},GBR),R0"
            comment = f"  ; read [{gbr_addr:08X}]"
        elif sub == 0x5:
            disp = d8 * 2
            gbr_addr = GBR + disp
            mnemonic = f"mov.w  @(0x{disp:04X},GBR),R0"
            comment = f"  ; read [{gbr_addr:08X}]"
        elif sub == 0x6:
            disp = d8 * 4
            gbr_addr = GBR + disp
            mnemonic = f"mov.l  @(0x{disp:04X},GBR),R0"
            comment = f"  ; read [{gbr_addr:08X}]"
        elif sub == 0x7:
            disp = d8 * 4
            pool_addr = ((addr + 4) & ~3) + disp
            mnemonic = f"mova   @(0x{pool_addr:06X}),R0"
        elif sub == 0x8:
            mnemonic = f"tst    #0x{d8:02X},R0"
        elif sub == 0x9:
            mnemonic = f"and    #0x{d8:02X},R0"
        elif sub == 0xD:
            mnemonic = f"and.b  #0x{d8:02X},@(R0,GBR)"
        elif sub == 0xF:
            mnemonic = f"or.b   #0x{d8:02X},@(R0,GBR)"
        else:
            mnemonic = f".word  0x{op:04X}  ; Cxxx"

    elif top == 0xD:
        disp = d8 * 4
        pool_addr = ((addr + 4) & ~3) + disp
        if pool_addr + 3 < len(rom):
            val = read_u32(rom, pool_addr)
            mnemonic = f"mov.l  @(0x{pool_addr:06X}),{rn(n_reg)}"
            if 0xFFFF0000 <= val <= 0xFFFFFFFF:
                comment = f"  ; =0x{val:08X} (RAM)"
            elif val < 0x00200000:
                comment = f"  ; =0x{val:08X} (ROM/code)"
            elif 0x000A0000 <= val <= 0x000FFFFF:
                comment = f"  ; =0x{val:08X} (cal)"
                try:
                    fval = read_float(rom, val)
                    fval_mod = read_float(mod_rom, val)
                    if fval != fval_mod:
                        comment += f" stock={fval} mod={fval_mod} ***CHANGED***"
                    else:
                        comment += f" val={fval}"
                except:
                    pass
            else:
                comment = f"  ; =0x{val:08X}"
        else:
            mnemonic = f"mov.l  @(0x{pool_addr:06X}),{rn(n_reg)}"

    elif top == 0xE:
        imm = read_s8(d8)
        mnemonic = f"mov    #{imm},{rn(n_reg)}"

    elif top == 0xF:
        sub = nibbles[3]
        fn = n_reg
        fm = m_reg
        if sub == 0x0: mnemonic = f"fadd   {frn(fm)},{frn(fn)}"
        elif sub == 0x1: mnemonic = f"fsub   {frn(fm)},{frn(fn)}"
        elif sub == 0x2: mnemonic = f"fmul   {frn(fm)},{frn(fn)}"
        elif sub == 0x3: mnemonic = f"fdiv   {frn(fm)},{frn(fn)}"
        elif sub == 0x4: mnemonic = f"fcmp/eq {frn(fm)},{frn(fn)}"
        elif sub == 0x5: mnemonic = f"fcmp/gt {frn(fm)},{frn(fn)}"
        elif sub == 0x6: mnemonic = f"fmov.s @(R0,{rn(m_reg)}),{frn(fn)}"
        elif sub == 0x7: mnemonic = f"fmov.s {frn(fm)},@(R0,{rn(n_reg)})"
        elif sub == 0x8: mnemonic = f"fmov.s @{rn(m_reg)},{frn(fn)}"
        elif sub == 0x9: mnemonic = f"fmov.s @{rn(m_reg)}+,{frn(fn)}"
        elif sub == 0xA: mnemonic = f"fmov.s {frn(fm)},@{rn(n_reg)}"
        elif sub == 0xB: mnemonic = f"fmov.s {frn(fm)},@-{rn(n_reg)}"
        elif sub == 0xC: mnemonic = f"fmov   {frn(fm)},{frn(fn)}"
        elif sub == 0xD:
            if fm == 0x0: mnemonic = f"fsts   FPUL,{frn(fn)}"
            elif fm == 0x1: mnemonic = f"flds   {frn(fn)},FPUL"
            elif fm == 0x2: mnemonic = f"float  FPUL,{frn(fn)}"
            elif fm == 0x3: mnemonic = f"ftrc   {frn(fn)},FPUL"
            elif fm == 0x4: mnemonic = f"fneg   {frn(fn)}"
            elif fm == 0x5: mnemonic = f"fabs   {frn(fn)}"
            elif fm == 0x6: mnemonic = f"fsqrt  {frn(fn)}"
            elif fm == 0x8: mnemonic = f"fldi0  {frn(fn)}"
            elif fm == 0x9: mnemonic = f"fldi1  {frn(fn)}"
            else: mnemonic = f".word  0x{op:04X}  ; FPU_xD"
        else:
            mnemonic = f".word  0x{op:04X}  ; FPU"

    if not mnemonic:
        mnemonic = f".word  0x{op:04X}"

    lines.append(f"{addr:06X}: {op:04X}  {mnemonic}{comment}")
    addr += 2

for line in lines:
    print(line)
