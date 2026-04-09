#!/usr/bin/env python3
"""
Layer 2: Disassemble injector compensation pipeline
- fuel_injector_comp @ 0x37B68
- injector_trim_application @ 0x37ABA
- Decode InjectorLatency descriptor @ 0xAD7E8
- Decode InjectorFlowScaling @ 0xCBE0C
"""

import struct

ROM_PATH = r"C:\Users\Dean\Documents\GitHub\ae6l600l\rom\ae5l600l.bin"
MOD_PATH = r"C:\Users\Dean\Documents\GitHub\ae6l600l\rom\AE5L600L 20g rev 20.5 tiny wrex.bin"

with open(ROM_PATH, "rb") as f:
    ROM = f.read()
with open(MOD_PATH, "rb") as f:
    MOD = f.read()

def r8(d, a): return d[a]
def r16(d, a): return struct.unpack(">H", d[a:a+2])[0]
def r32(d, a): return struct.unpack(">I", d[a:a+4])[0]
def rf32(d, a): return struct.unpack(">f", d[a:a+4])[0]
def ri16(d, a): return struct.unpack(">h", d[a:a+2])[0]
def s8(v): return v - 256 if v > 127 else v
def s12(v): return v - 0x1000 if v > 0x7FF else v

LABELS = {
    0xFFFF7AB4: "afl_multiplier_output",
    0xFFFF7348: "fuel_base_factor",
    0xFFFF73A4: "fuel_correction_A",
    0xFFFF7A08: "fuel_correction_B",
    0xFFFF7BC4: "fuel_correction_C",
    0xFFFF76D4: "fuel_enrichment_A",
    0xFFFF7878: "fuel_enrichment_B",
    0xFFFF7AE4: "fuel_enrichment_C",
    0xFFFF7344: "fuel_struct_base",
    0xFFFF7B6C: "fuel_blend_A",
    0xFFFF7B70: "fuel_blend_B",
    0xFFFF7B74: "fuel_blend_C",
    0xFFFF7B78: "fuel_blend_D",
    0xFFFF895C: "injector_data",
    0xFFFF63F8: "iat_current",
    0xFFFF62F8: "engine_load",
    0xFFFF6540: "sensor_state",
    0xFFFF77C8: "CL_base_params",
    0xFFFF7D68: "transient_fuel",
    0xFFFF80E4: "inj_pw_primary",
    0xFFFF7448: "CLOL_mode_flag",
    0xFFFF65C0: "throttle_pos",
}

SUB_NAMES = {
    0x0BE830: "table_desc_lookup",
    0x0BE874: "LowPW_TableProcessor",
    0x0BE56C: "float_clamp_apply",
    0x0BE608: "float_compare_range",
    0x0BE8AC: "table_helper_b",
    0x029858: "sub_29858",
    0x02997C: "sub_2997C",
    0x037B74: "afl_application",
    0x037ABA: "injector_trim_application",
    0x037B68: "fuel_injector_comp",
    0x033304: "CL_fuel_dispatcher",
    0x033460: "fuel_aggregator_tail",
    0x0301E4: "fuel_pulse_width_calc",
    0x037186: "fuel_transient_comp",
    0x039528: "fuel_wot_enrich_calc",
}

def label(addr):
    return LABELS.get(addr)

def disasm_func(start, max_bytes=0x400, gbr=0xFFFF7450):
    """Disassemble from start until RTS+delay slot, return (lines, end_addr)."""
    # Find first RTS
    end = start
    for i in range(start, start + max_bytes, 2):
        if i + 1 >= len(ROM):
            break
        op = r16(ROM, i)
        if op == 0x000B:  # RTS
            end = i + 4
            break
    if end == start:
        end = start + max_bytes

    lines = []
    addr = start
    while addr < end:
        if addr >= len(ROM) - 1:
            break
        op = r16(ROM, addr)
        n4 = [(op >> 12) & 0xF, (op >> 8) & 0xF, (op >> 4) & 0xF, op & 0xF]
        top = n4[0]
        n_reg = n4[1]; m_reg = n4[2]; d8 = op & 0xFF; d4 = op & 0xF

        mnem = ""; comment = ""

        if op == 0x0009: mnem = "nop"
        elif op == 0x000B: mnem = "rts"
        elif op == 0x0019: mnem = "div0u"
        elif top == 0x0:
            sub = n4[3]
            if sub == 0xC: mnem = f"mov.b  @(R0,R{m_reg}),R{n_reg}"
            elif sub == 0xD: mnem = f"mov.w  @(R0,R{m_reg}),R{n_reg}"
            elif sub == 0xE: mnem = f"mov.l  @(R0,R{m_reg}),R{n_reg}"
            elif sub == 0x4: mnem = f"mov.b  R{m_reg},@(R0,R{n_reg})"
            elif sub == 0x5: mnem = f"mov.w  R{m_reg},@(R0,R{n_reg})"
            elif sub == 0x6: mnem = f"mov.l  R{m_reg},@(R0,R{n_reg})"
            elif sub == 0x7: mnem = f"mul.l  R{m_reg},R{n_reg}"
            elif sub == 0x2:
                if m_reg == 0: mnem = f"stc    SR,R{n_reg}"
                elif m_reg == 1: mnem = f"stc    GBR,R{n_reg}"
            elif sub == 0xA:
                if m_reg == 0: mnem = f"sts    MACH,R{n_reg}"
                elif m_reg == 1: mnem = f"sts    MACL,R{n_reg}"
                elif m_reg == 2: mnem = f"sts    PR,R{n_reg}"
            if not mnem: mnem = f".word  0x{op:04X}"
        elif top == 0x1:
            disp = d4 * 4
            mnem = f"mov.l  R{m_reg},@({disp},R{n_reg})"
        elif top == 0x2:
            sub = n4[3]
            if sub in (0,1,2):
                sz = {0:".b",1:".w",2:".l"}[sub]
                mnem = f"mov{sz}  R{m_reg},@R{n_reg}"
            elif sub in (4,5,6):
                sz = {4:".b",5:".w",6:".l"}[sub]
                mnem = f"mov{sz}  R{m_reg},@-R{n_reg}"
            elif sub == 8: mnem = f"tst    R{m_reg},R{n_reg}"
            elif sub == 9: mnem = f"and    R{m_reg},R{n_reg}"
            elif sub == 0xA: mnem = f"xor    R{m_reg},R{n_reg}"
            elif sub == 0xB: mnem = f"or     R{m_reg},R{n_reg}"
            else: mnem = f".word  0x{op:04X}"
        elif top == 0x3:
            sub = n4[3]
            ops3 = {0:"cmp/eq",2:"cmp/hs",3:"cmp/ge",4:"div1",5:"dmulu.l",
                    6:"cmp/hi",7:"cmp/gt",8:"sub",0xA:"subc",0xC:"add",
                    0xD:"dmuls.l",0xE:"addc",0xF:"addv"}
            if sub in ops3: mnem = f"{ops3[sub]:7s} R{m_reg},R{n_reg}"
            else: mnem = f".word  0x{op:04X}"
        elif top == 0x4:
            low8 = op & 0xFF
            if low8 == 0x22: mnem = f"sts.l  PR,@-R{n_reg}"
            elif low8 == 0x26: mnem = f"lds.l  @R{n_reg}+,PR"
            elif low8 == 0x13: mnem = f"stc.l  GBR,@-R{n_reg}"
            elif low8 == 0x17: mnem = f"ldc.l  @R{n_reg}+,GBR"
            elif low8 == 0x1E: mnem = f"ldc    R{n_reg},GBR"
            elif low8 == 0x0B: mnem = f"jsr    @R{n_reg}"
            elif low8 == 0x2B: mnem = f"jmp    @R{n_reg}"
            elif low8 == 0x15: mnem = f"cmp/pl R{n_reg}"
            elif low8 == 0x11: mnem = f"cmp/pz R{n_reg}"
            elif low8 == 0x10: mnem = f"dt     R{n_reg}"
            elif low8 in (0x00,0x01,0x04,0x05,0x08,0x09,0x18,0x19,0x28,0x29,0x24,0x25):
                names = {0x00:"shll",0x01:"shlr",0x04:"rotl",0x05:"rotr",
                         0x08:"shll2",0x09:"shlr2",0x18:"shll8",0x19:"shlr8",
                         0x28:"shll16",0x29:"shlr16",0x24:"rotcl",0x25:"rotcr"}
                mnem = f"{names[low8]:7s} R{n_reg}"
            else: mnem = f".word  0x{op:04X}"
        elif top == 0x5:
            disp = d4 * 4
            mnem = f"mov.l  @({disp},R{m_reg}),R{n_reg}"
        elif top == 0x6:
            sub = n4[3]
            if sub in (0,1,2):
                sz = {0:".b",1:".w",2:".l"}[sub]
                mnem = f"mov{sz}  @R{m_reg},R{n_reg}"
            elif sub in (4,5,6):
                sz = {4:".b",5:".w",6:".l"}[sub]
                mnem = f"mov{sz}  @R{m_reg}+,R{n_reg}"
            elif sub == 3: mnem = f"mov    R{m_reg},R{n_reg}"
            elif sub == 7: mnem = f"not    R{m_reg},R{n_reg}"
            elif sub >= 8:
                ops6 = {8:"swap.b",9:"swap.w",0xA:"negc",0xB:"neg",
                        0xC:"extu.b",0xD:"extu.w",0xE:"exts.b",0xF:"exts.w"}
                mnem = f"{ops6.get(sub,'???'):7s} R{m_reg},R{n_reg}"
        elif top == 0x7:
            imm = s8(d8)
            mnem = f"add    #{imm},R{n_reg}"
        elif top == 0x8:
            sub = n4[1]
            if sub == 0x0: mnem = f"mov.b  R0,@({d4},R{m_reg})"
            elif sub == 0x1: mnem = f"mov.w  R0,@({d4*2},R{m_reg})"
            elif sub == 0x4: mnem = f"mov.b  @({d4},R{m_reg}),R0"
            elif sub == 0x5: mnem = f"mov.w  @({d4*2},R{m_reg}),R0"
            elif sub == 0x8: mnem = f"cmp/eq #{s8(d8)},R0"
            elif sub in (0x9,0xB,0xD,0xF):
                names = {0x9:"bt",0xB:"bf",0xD:"bt/s",0xF:"bf/s"}
                target = addr + s8(d8) * 2 + 4
                mnem = f"{names[sub]:7s} 0x{target:06X}"
                comment = f"; -> {target:06X}"
            else: mnem = f".word  0x{op:04X}"
        elif top == 0x9:
            disp = d8 * 2
            pa = addr + 4 + disp
            if pa + 1 < len(ROM):
                val = r16(ROM, pa)
                mnem = f"mov.w  @(0x{pa:06X}),R{n_reg}"
                comment = f"; =0x{val:04X} ({val})"
        elif top == 0xA:
            d12 = op & 0xFFF
            target = addr + 4 + s12(d12) * 2
            sn = SUB_NAMES.get(target, label(target))
            mnem = f"bra    {sn or f'0x{target:06X}'}"
            comment = f"; -> {target:06X}"
        elif top == 0xB:
            d12 = op & 0xFFF
            target = addr + 4 + s12(d12) * 2
            sn = SUB_NAMES.get(target, label(target))
            mnem = f"bsr    {sn or f'0x{target:06X}'}"
            comment = f"; -> {target:06X}"
        elif top == 0xC:
            sub = n4[1]
            if sub in (0x0,0x1,0x2):
                mul = {0:1,1:2,2:4}[sub]
                sz = {0:".b",1:".w",2:".l"}[sub]
                disp = d8 * mul
                ga = gbr + disp
                lbl = label(ga) or f"0x{ga:08X}"
                mnem = f"mov{sz}  R0,@({disp:#x},GBR)"
                comment = f"; write [{lbl}]"
            elif sub in (0x4,0x5,0x6):
                mul = {4:1,5:2,6:4}[sub]
                sz = {4:".b",5:".w",6:".l"}[sub]
                disp = d8 * mul
                ga = gbr + disp
                lbl = label(ga) or f"0x{ga:08X}"
                mnem = f"mov{sz}  @({disp:#x},GBR),R0"
                comment = f"; read [{lbl}]"
            elif sub == 0x7:
                disp = d8 * 4
                pa = ((addr + 4) & ~3) + disp
                mnem = f"mova   @(0x{pa:06X}),R0"
            elif sub == 0x8: mnem = f"tst    #{d8:#x},R0"
            elif sub == 0x9: mnem = f"and    #{d8:#x},R0"
            elif sub == 0xD: mnem = f"and.b  #{d8:#x},@(R0,GBR)"
            elif sub == 0xF: mnem = f"or.b   #{d8:#x},@(R0,GBR)"
            else: mnem = f".word  0x{op:04X}"
        elif top == 0xD:
            disp = d8 * 4
            pa = ((addr + 4) & ~3) + disp
            if pa + 3 < len(ROM):
                val = r32(ROM, pa)
                mnem = f"mov.l  @(0x{pa:06X}),R{n_reg}"
                lbl = label(val) or SUB_NAMES.get(val)
                if lbl:
                    comment = f"; ={lbl} (0x{val:08X})"
                elif 0xFFFF0000 <= val: comment = f"; =0x{val:08X} (RAM)"
                elif val < 0x100000:
                    comment = f"; =0x{val:08X} (ROM)"
                elif 0xA0000 <= val <= 0xFFFFF:
                    comment = f"; =0x{val:08X} (cal)"
                    try:
                        fv = rf32(ROM, val)
                        fvm = rf32(MOD, val)
                        if fv != fvm: comment += f" stk={fv} mod={fvm}"
                        else: comment += f" val={fv}"
                    except: pass
                else:
                    try:
                        fv = struct.unpack(">f", struct.pack(">I", val))[0]
                        if 1e-8 < abs(fv) < 1e8: comment = f"; =float({fv})"
                        else: comment = f"; =0x{val:08X}"
                    except: comment = f"; =0x{val:08X}"
        elif top == 0xE:
            mnem = f"mov    #{s8(d8)},R{n_reg}"
        elif top == 0xF:
            sub = n4[3]; fn = n_reg; fm = m_reg
            fpu = {0:"fadd",1:"fsub",2:"fmul",3:"fdiv",4:"fcmp/eq",5:"fcmp/gt",
                   0xC:"fmov"}
            if sub in fpu: mnem = f"{fpu[sub]:7s} FR{fm},FR{fn}"
            elif sub == 6: mnem = f"fmov.s @(R0,R{m_reg}),FR{fn}"
            elif sub == 7: mnem = f"fmov.s FR{fm},@(R0,R{n_reg})"
            elif sub == 8: mnem = f"fmov.s @R{m_reg},FR{fn}"
            elif sub == 9: mnem = f"fmov.s @R{m_reg}+,FR{fn}"
            elif sub == 0xA: mnem = f"fmov.s FR{fm},@R{n_reg}"
            elif sub == 0xB: mnem = f"fmov.s FR{fm},@-R{n_reg}"
            elif sub == 0xD:
                fpuD = {0:"fsts   FPUL,",1:"flds   ,FPUL",2:"float  FPUL,",
                        3:"ftrc   ,FPUL",4:"fneg   ",5:"fabs   ",6:"fsqrt  ",
                        8:"fldi0  ",9:"fldi1  "}
                if fm in fpuD:
                    if fm == 1: mnem = f"flds   FR{fn},FPUL"
                    elif fm == 3: mnem = f"ftrc   FR{fn},FPUL"
                    else: mnem = f"{fpuD[fm]}FR{fn}"
                else: mnem = f".word  0x{op:04X}"
            elif sub == 0xE:
                mnem = f"fmac   FR0,FR{fm},FR{fn}"
            else: mnem = f".word  0x{op:04X}"

        if not mnem:
            mnem = f".word  0x{op:04X}"

        line = f"  {addr:06X}: {op:04X}  {mnem}"
        if comment: line = f"{line:60s} {comment}"
        lines.append(line)
        addr += 2

    return lines, end


# ==========================================
# SECTION 1: fuel_injector_comp @ 0x37B68
# ==========================================
print("=" * 90)
print("LAYER 2A: fuel_injector_comp @ 0x37B68")
print("=" * 90)
print()

lines, end1 = disasm_func(0x37B68)
print(f"Function span: 0x037B68 - 0x{end1:06X} ({end1 - 0x37B68} bytes)")
print()
for l in lines: print(l)

# Literal pool
print(f"\nLiteral pool after 0x{end1:06X}:")
for a in range(end1, min(end1 + 0x40, len(ROM)), 4):
    val = r32(ROM, a)
    lbl = label(val) or SUB_NAMES.get(val)
    if lbl:
        print(f"  {a:06X}: {val:08X}  -> {lbl}")
    elif 0xFFFF0000 <= val:
        print(f"  {a:06X}: {val:08X}  (RAM)")
    elif val < 0x100000:
        print(f"  {a:06X}: {val:08X}  (ROM)")
    else:
        try:
            fv = struct.unpack(">f", struct.pack(">I", val))[0]
            if 1e-8 < abs(fv) < 1e8:
                print(f"  {a:06X}: {val:08X}  (float={fv})")
        except: pass

# ==========================================
# SECTION 2: injector_trim_application @ 0x37ABA
# ==========================================
print()
print("=" * 90)
print("LAYER 2B: injector_trim_application @ 0x37ABA")
print("=" * 90)
print()

lines, end2 = disasm_func(0x37ABA)
print(f"Function span: 0x037ABA - 0x{end2:06X} ({end2 - 0x37ABA} bytes)")
print()
for l in lines: print(l)

# Literal pool
print(f"\nLiteral pool after 0x{end2:06X}:")
for a in range(end2, min(end2 + 0x40, len(ROM)), 4):
    val = r32(ROM, a)
    lbl = label(val) or SUB_NAMES.get(val)
    if lbl:
        print(f"  {a:06X}: {val:08X}  -> {lbl}")
    elif 0xFFFF0000 <= val:
        print(f"  {a:06X}: {val:08X}  (RAM)")
    elif val < 0x100000:
        print(f"  {a:06X}: {val:08X}  (ROM)")

# ==========================================
# SECTION 3: Decode InjectorLatency descriptor
# ==========================================
print()
print("=" * 90)
print("LAYER 2C: InjectorLatency Descriptor Decode")
print("=" * 90)
print()

# Descriptor at 0xAD7E8 points to InjectorLatency data
desc_addr = 0xAD7E8
print(f"Descriptor @ 0x{desc_addr:06X}:")
for i in range(0, 0x30, 4):
    val = r32(ROM, desc_addr + i)
    fv = rf32(ROM, desc_addr + i)
    print(f"  +{i:02X}: {val:08X}  (float={fv})")

# The descriptor structure typically has:
# +00: type/flags
# +04: data pointer -> table data
# +08: axis pointer -> axis values
# +0C: size info
# Let's decode assuming standard descriptor format

print()
print("Attempting table decode based on descriptor pointers:")
data_ptr = r32(ROM, desc_addr + 4)  # 0xD106C
axis_ptr = r32(ROM, desc_addr + 0)  # 0xD1060
print(f"  Axis pointer:  0x{axis_ptr:08X}")
print(f"  Data pointer:  0x{data_ptr:08X}")

# Read axis values (likely voltage axis for dead time)
print(f"\n  Axis values at 0x{axis_ptr:06X} (likely battery voltage):")
for i in range(0, 24, 2):
    val = r16(ROM, axis_ptr + i)
    # Could be scaled - common scaling is /100 or /10
    print(f"    [{i//2}]: raw={val} (÷256={val/256:.2f}V) (÷100={val/100:.2f}V)")

# Read data values (dead time in some unit)
print(f"\n  Data values at 0x{data_ptr:06X} (injector dead time):")
for i in range(0, 24, 2):
    val = r16(ROM, data_ptr + i)
    ri = ri16(ROM, data_ptr + i)
    print(f"    [{i//2}]: raw={val} (0x{val:04X}) signed={ri} (÷1000={val/1000:.3f}ms) (÷256={val/256:.3f}ms)")

# Also check the area after for more descriptor entries
print(f"\n  Extended data at 0x{data_ptr:06X}+24:")
for i in range(24, 48, 2):
    val = r16(ROM, data_ptr + i)
    print(f"    [{i//2}]: raw={val} (0x{val:04X}) (÷256={val/256:.3f})")

# Check second descriptor entry
desc2 = 0xAD7FC
print(f"\nSecond descriptor @ 0x{desc2:06X}:")
for i in range(0, 0x20, 4):
    val = r32(ROM, desc2 + i)
    print(f"  +{i:02X}: {val:08X}")

d2_data = r32(ROM, desc2 + 4)
print(f"\n  Data at 0x{d2_data:06X}:")
for i in range(0, 24, 4):
    val = r32(ROM, d2_data + i)
    fv = rf32(ROM, d2_data + i)
    print(f"    [{i//4}]: {val:08X}  float={fv}")

# ==========================================
# SECTION 4: InjectorFlowScaling and related cal
# ==========================================
print()
print("=" * 90)
print("LAYER 2D: Injector Calibration Constants")
print("=" * 90)
print()

print(f"InjectorFlowScaling @ 0xCBE0C:")
for d, name in [(ROM, "stock"), (MOD, "mod")]:
    fv = rf32(d, 0xCBE0C)
    print(f"  {name}: {fv} cc/min")

# Scan nearby cal area for related constants
print(f"\nNearby calibration @ 0xCBE00-0xCBE20:")
for a in range(0xCBE00, 0xCBE20, 4):
    vs = rf32(ROM, a)
    vm = rf32(MOD, a)
    changed = " ***CHANGED***" if vs != vm else ""
    print(f"  {a:06X}: stock={vs:.4f}  mod={vm:.4f}{changed}")

# CrankingFuel IPW tables
print(f"\nCrankingFuel_IPW_A @ 0xCD2E6:")
for i in range(0, 32, 2):
    vs = r16(ROM, 0xCD2E6 + i)
    vm = r16(MOD, 0xCD2E6 + i)
    changed = " ***" if vs != vm else ""
    print(f"  [{i//2:2d}]: stock={vs/256:.3f}ms  mod={vm/256:.3f}ms{changed}")

# ==========================================
# SECTION 5: afl_application @ 0x37B74
# ==========================================
print()
print("=" * 90)
print("LAYER 2E: afl_application @ 0x37B74 (for completeness)")
print("=" * 90)
print()

lines, end3 = disasm_func(0x37B74, max_bytes=0x200)
print(f"Function span: 0x037B74 - 0x{end3:06X} ({end3 - 0x37B74} bytes)")
print()
for l in lines: print(l)

print(f"\nLiteral pool after 0x{end3:06X}:")
for a in range(end3, min(end3 + 0x60, len(ROM)), 4):
    val = r32(ROM, a)
    lbl = label(val) or SUB_NAMES.get(val)
    if lbl:
        print(f"  {a:06X}: {val:08X}  -> {lbl}")
    elif 0xFFFF0000 <= val:
        print(f"  {a:06X}: {val:08X}  (RAM)")
    elif val < 0x100000:
        print(f"  {a:06X}: {val:08X}  (ROM)")
