#!/usr/bin/env python3
"""
Disassemble ipw_calc_main @ 0x38158
Central IPW computation - integrates all corrections.
"""

import struct

ROM_PATH = r"C:\Users\Dean\Documents\GitHub\ae6l600l\rom\ae5l600l.bin"
MOD_PATH = r"C:\Users\Dean\Documents\GitHub\ae6l600l\rom\AE5L600L 20g rev 20.5 tiny wrex.bin"

with open(ROM_PATH, "rb") as f:
    ROM = f.read()
with open(MOD_PATH, "rb") as f:
    MOD = f.read()

def r16(d, a): return struct.unpack(">H", d[a:a+2])[0]
def r32(d, a): return struct.unpack(">I", d[a:a+4])[0]
def rf32(d, a): return struct.unpack(">f", d[a:a+4])[0]
def s8(v): return v - 256 if v > 127 else v
def s12(v): return v - 0x1000 if v > 0x7FF else v

GBR = 0xFFFF7450

LABELS = {
    0xFFFF7AB4: "afl_multiplier",
    0xFFFF77C8: "CL_base_params",
    0xFFFF77DC: "CL_target_comp_A_out",
    0xFFFF77E0: "CL_target_comp_B_out",
    0xFFFF781C: "AFC_result",
    0xFFFF7448: "CLOL_mode_flag",
    0xFFFF895C: "injector_data",
    0xFFFF6624: "engine_load_float",
    0xFFFF63F8: "RPM_float",
    0xFFFF65F0: "CL_OL_status",
    0xFFFF7C68: "engine_status_flag",
    0xFFFF62F8: "engine_load",
    0xFFFF80E4: "inj_pw_output",
    0xFFFF80F8: "final_timing",
    0xFFFF5FB8: "maf_value",
    0xFFFF79E0: "decay_delta",
    0xFFFF798C: "decay_accum",
    0xFFFF79F2: "ol_active_flag",
    0xFFFF77D8: "CL_target_comp_out",
    0xFFFF7864: "AFC_struct",
    0xFFFF7BA8: "AFC_PI_struct",
    0xFFFF7D68: "transient_fuel",
    0xFFFF6540: "sensor_state",
    0xFFFF65C0: "throttle_pos",
    0xFFFF73AC: "fuel_base_combined",
    0xFFFF7340: "fuel_base_param",
    0xFFFF7400: "fuel_base_tbl_out",
    0xFFFF744B: "fuel_enable_state",
    0xFFFF770C: "fuel_corr_filter",
    0xFFFF7B60: "ltft_workspace",
    0xFFFF668C: "inj_timing_state",
    0xFFFF6650: "maf_voltage_a",
    0xFFFF6654: "maf_voltage_b",
    0xFFFF6790: "manifold_pressure",
    0xFFFF6810: "boost_pressure",
}

def label(addr):
    if addr in LABELS:
        return LABELS[addr]
    # Check GBR-relative
    return None

def decode_gbr(disp, size):
    """Decode GBR-relative address"""
    mul = {"b": 1, "w": 2, "l": 4}[size]
    addr = GBR + disp * mul
    return addr

def disasm(start, end):
    addr = start
    # Collect branch targets
    branch_targets = set()
    a = start
    while a < end:
        op = r16(ROM, a)
        top = (op >> 12) & 0xF
        if top == 0x8:
            sub = (op >> 8) & 0xF
            if sub in (0x9, 0xB, 0xD, 0xF):
                d8 = op & 0xFF
                disp = s8(d8) * 2 + 4
                branch_targets.add(a + disp)
        elif top in (0xA, 0xB):
            d12 = op & 0xFFF
            target = a + 4 + s12(d12) * 2
            branch_targets.add(target)
        a += 2

    addr = start
    while addr < end:
        op = r16(ROM, addr)
        n = (op >> 8) & 0xF
        m = (op >> 4) & 0xF
        top = (op >> 12) & 0xF
        d8 = op & 0xFF
        d4 = op & 0xF

        prefix = ""
        if addr in branch_targets:
            lbl = label(addr)
            prefix = f"\n.L_{addr:06X}:" if not lbl else f"\n; --- {lbl} ---"
        elif addr == start:
            prefix = f"; === ipw_calc_main @ 0x{start:06X} ==="

        mnem = ""
        comment = ""

        # Decode instruction
        if op == 0x0009: mnem = "nop"
        elif op == 0x000B: mnem = "rts"

        elif top == 0xE:
            imm = s8(d8)
            mnem = f"mov    #{imm},R{n}"

        elif top == 0xD:
            disp = d8 * 4
            pool_addr = ((addr + 4) & ~3) + disp
            val = r32(ROM, pool_addr)
            mnem = f"mov.l  @(0x{pool_addr:06X}),R{n}"
            lbl = label(val)
            if lbl:
                comment = f"; ={lbl} (0x{val:08X})"
            elif 0xFFFF0000 <= val <= 0xFFFFFFFF:
                rlbl = label(val)
                comment = f"; =0x{val:08X} (RAM) {rlbl or ''}"
            elif val < 0x100000:
                comment = f"; =0x{val:08X} (ROM)"
            elif 0xA0000 <= val <= 0xFFFFF:
                try:
                    fv = rf32(ROM, val)
                    fvm = rf32(MOD, val)
                    chg = " ***MOD***" if fv != fvm else ""
                    comment = f"; =0x{val:08X} (cal) stock={fv} mod={fvm}{chg}"
                except:
                    comment = f"; =0x{val:08X} (cal)"
            else:
                try:
                    fv = struct.unpack(">f", struct.pack(">I", val))[0]
                    if 1e-8 < abs(fv) < 1e8:
                        comment = f"; float={fv}"
                    else:
                        comment = f"; =0x{val:08X}"
                except:
                    comment = f"; =0x{val:08X}"

        elif top == 0x9:
            disp = d8 * 2
            pool_addr = addr + 4 + disp
            val = r16(ROM, pool_addr)
            mnem = f"mov.w  @(0x{pool_addr:06X}),R{n}"
            comment = f"; =0x{val:04X} ({val})"

        elif top == 0x8:
            sub = n
            if sub == 0x0: mnem = f"mov.b  R0,@({d4},R{m})"
            elif sub == 0x1: mnem = f"mov.w  R0,@({d4*2},R{m})"
            elif sub == 0x4: mnem = f"mov.b  @({d4},R{m}),R0"
            elif sub == 0x5: mnem = f"mov.w  @({d4*2},R{m}),R0"
            elif sub == 0x8: mnem = f"cmp/eq #{s8(d8)},R0"
            elif sub in (0x9, 0xB, 0xD, 0xF):
                nm = {0x9:"bt",0xB:"bf",0xD:"bt/s",0xF:"bf/s"}[sub]
                disp2 = s8(d8) * 2 + 4
                target = addr + disp2
                mnem = f"{nm:6s} .L_{target:06X}"
                comment = f"; -> {target:06X}"
            else: mnem = f".word  0x{op:04X}"

        elif top == 0xA:
            d12 = op & 0xFFF
            target = addr + 4 + s12(d12) * 2
            lbl2 = label(target)
            mnem = f"bra    {lbl2 or '.L_%06X'%target}"
            comment = f"; -> {target:06X}"

        elif top == 0xB:
            d12 = op & 0xFFF
            target = addr + 4 + s12(d12) * 2
            lbl2 = label(target) or f"sub_{target:06X}"
            mnem = f"bsr    {lbl2}"
            comment = f"; -> {target:06X}"

        elif top == 0xC:
            sub = n
            if sub in (0, 1, 2):
                sz = "bwl"[sub]
                mul = [1,2,4][sub]
                ga = GBR + d8 * mul
                lbl2 = label(ga) or f"GBR+0x{d8*mul:X}"
                mnem = f"mov.{sz}  R0,@(0x{d8*mul:X},GBR)"
                comment = f"; [{lbl2}] = R0"
            elif sub in (4, 5, 6):
                sz = "bwl"[sub-4]
                mul = [1,2,4][sub-4]
                ga = GBR + d8 * mul
                lbl2 = label(ga) or f"GBR+0x{d8*mul:X}"
                mnem = f"mov.{sz}  @(0x{d8*mul:X},GBR),R0"
                comment = f"; R0 = [{lbl2}]"
            elif sub == 0x7:
                disp = d8 * 4
                pool_addr = ((addr + 4) & ~3) + disp
                mnem = f"mova   @(0x{pool_addr:06X}),R0"
            elif sub == 0x8: mnem = f"tst    #0x{d8:02X},R0"
            elif sub == 0x9: mnem = f"and    #0x{d8:02X},R0"
            else: mnem = f".word  0x{op:04X}"

        elif top == 0x1:
            disp = d4 * 4
            mnem = f"mov.l  R{m},@({disp},R{n})"

        elif top == 0x2:
            sub = d4
            if sub == 0: mnem = f"mov.b  R{m},@R{n}"
            elif sub == 1: mnem = f"mov.w  R{m},@R{n}"
            elif sub == 2: mnem = f"mov.l  R{m},@R{n}"
            elif sub == 4: mnem = f"mov.b  R{m},@-R{n}"
            elif sub == 5: mnem = f"mov.w  R{m},@-R{n}"
            elif sub == 6: mnem = f"mov.l  R{m},@-R{n}"
            elif sub == 8: mnem = f"tst    R{m},R{n}"
            elif sub == 9: mnem = f"and    R{m},R{n}"
            elif sub == 0xA: mnem = f"xor    R{m},R{n}"
            elif sub == 0xB: mnem = f"or     R{m},R{n}"
            else: mnem = f".word  0x{op:04X}"

        elif top == 0x3:
            sub = d4
            ops = {0:"cmp/eq",2:"cmp/hs",3:"cmp/ge",6:"cmp/hi",7:"cmp/gt",8:"sub",0xC:"add",0xD:"dmuls.l",0xE:"addc"}
            if sub in ops: mnem = f"{ops[sub]:7s} R{m},R{n}"
            else: mnem = f".word  0x{op:04X}"

        elif top == 0x4:
            low8 = op & 0xFF
            ops4 = {0x22:"sts.l  PR,@-R",0x26:"lds.l  @R+,PR -> R",0x0B:"jsr    @R",
                    0x2B:"jmp    @R",0x15:"cmp/pl R",0x11:"cmp/pz R",0x10:"dt     R",
                    0x00:"shll   R",0x01:"shlr   R",0x08:"shll2  R",0x09:"shlr2  R",
                    0x18:"shll8  R",0x19:"shlr8  R",0x28:"shll16 R",0x29:"shlr16 R",
                    0x13:"stc.l  GBR,@-R",0x17:"ldc.l  @R+,GBR -> R",0x1E:"ldc    R,GBR -> R"}
            if low8 in ops4:
                if low8 == 0x26: mnem = f"lds.l  @R{n}+,PR"
                elif low8 == 0x17: mnem = f"ldc.l  @R{n}+,GBR"
                elif low8 == 0x1E: mnem = f"ldc    R{n},GBR"
                else: mnem = f"{ops4[low8]}{n}"
            else: mnem = f".word  0x{op:04X}"

        elif top == 0x5:
            disp = d4 * 4
            mnem = f"mov.l  @({disp},R{m}),R{n}"

        elif top == 0x6:
            sub = d4
            if sub == 0: mnem = f"mov.b  @R{m},R{n}"
            elif sub == 1: mnem = f"mov.w  @R{m},R{n}"
            elif sub == 2: mnem = f"mov.l  @R{m},R{n}"
            elif sub == 3: mnem = f"mov    R{m},R{n}"
            elif sub == 4: mnem = f"mov.b  @R{m}+,R{n}"
            elif sub == 5: mnem = f"mov.w  @R{m}+,R{n}"
            elif sub == 6: mnem = f"mov.l  @R{m}+,R{n}"
            elif sub == 0xC: mnem = f"extu.b R{m},R{n}"
            elif sub == 0xD: mnem = f"extu.w R{m},R{n}"
            else: mnem = f".word  0x{op:04X}"

        elif top == 0x7:
            imm = s8(d8)
            mnem = f"add    #{imm},R{n}"
            if n == 15: comment = f"; SP {'+'if imm>=0 else ''}{imm}"

        elif top == 0xF:
            sub = d4
            fn_r = n; fm_r = m
            fpu = {0:"fadd",1:"fsub",2:"fmul",3:"fdiv",4:"fcmp/eq",5:"fcmp/gt"}
            if sub in fpu: mnem = f"{fpu[sub]:8s}FR{fm_r},FR{fn_r}"
            elif sub == 0x6: mnem = f"fmov.s @(R0,R{m}),FR{fn_r}"
            elif sub == 0x7: mnem = f"fmov.s FR{fm_r},@(R0,R{n})"
            elif sub == 0x8: mnem = f"fmov.s @R{m},FR{fn_r}"
            elif sub == 0x9: mnem = f"fmov.s @R{m}+,FR{fn_r}"
            elif sub == 0xA: mnem = f"fmov.s FR{fm_r},@R{n}"
            elif sub == 0xB: mnem = f"fmov.s FR{fm_r},@-R{n}"
            elif sub == 0xC: mnem = f"fmov   FR{fm_r},FR{fn_r}"
            elif sub == 0xD:
                fops = {0:"fsts   FPUL,FR",1:"flds   FR,FPUL",2:"float  FPUL,FR",
                        3:"ftrc   FR,FPUL",4:"fneg   FR",5:"fabs   FR",6:"fsqrt  FR",
                        8:"fldi0  FR",9:"fldi1  FR"}
                if fm_r in fops:
                    mnem = f"{fops[fm_r]}{fn_r}"
                else: mnem = f".word  0x{op:04X}"
            else: mnem = f".word  0x{op:04X}"

        if not mnem:
            mnem = f".word  0x{op:04X}"

        line = f"  {addr:06X}: {op:04X}  {mnem}"
        if comment:
            line = f"{line:58s} {comment}"
        if prefix:
            print(prefix)
        print(line)
        addr += 2

# Main
start = 0x38158
# Find all RTS
rts = []
for i in range(start, start + 0x800, 2):
    if r16(ROM, i) == 0x000B:
        rts.append(i)

end = rts[0] + 4  # first RTS + delay slot
print(f"ipw_calc_main: 0x{start:06X} - 0x{end:06X} ({end-start} bytes)")
print(f"First RTS at 0x{rts[0]:06X}")
print()

disasm(start, end)

# Literal pool
print(f"\n{'='*70}")
print("LITERAL POOL")
print(f"{'='*70}")
# The pool is typically aligned after the delay slot
pool = end
# But SH code often has the pool embedded at known offsets
# Let's scan the references from mov.l @(disp,PC) instructions
print()
refs = set()
for a in range(start, end, 2):
    op = r16(ROM, a)
    top = (op >> 12) & 0xF
    if top == 0xD:
        d8v = op & 0xFF
        disp = d8v * 4
        pool_addr = ((a + 4) & ~3) + disp
        refs.add(pool_addr)

for pa in sorted(refs):
    val = r32(ROM, pa)
    lbl2 = label(val)
    info = ""
    if lbl2:
        info = f"-> {lbl2}"
    elif 0xFFFF0000 <= val <= 0xFFFFFFFF:
        rlbl = label(val)
        info = f"(RAM) {rlbl or ''}"
    elif val < 0x100000:
        info = "(ROM func)"
    elif 0xA0000 <= val <= 0xFFFFF:
        try:
            fv = rf32(ROM, val)
            fvm = rf32(MOD, val)
            chg = " ***MOD***" if fv != fvm else ""
            info = f"(cal) stock={fv} mod={fvm}{chg}"
        except:
            info = "(cal)"
    else:
        try:
            fv = struct.unpack(">f", struct.pack(">I", val))[0]
            if 1e-8 < abs(fv) < 1e8:
                info = f"(float={fv})"
        except:
            pass
    print(f"  {pa:06X}: {val:08X}  {info}")
