#!/usr/bin/env python3
"""
Layer 1: Disassemble fuel_pulse_width_calc @ 0x301E4
Traces base injection pulse width calculation from entry to RTS.
Identifies: inputs, AFL multiplier application, table lookups, output writes.
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

# Known labels
LABELS = {
    # RAM
    0xFFFF7AB4: "afl_multiplier_output",
    0xFFFF77C8: "CL_base_params_struct",
    0xFFFF77DC: "CL_target_comp_A_output",
    0xFFFF77E0: "CL_target_comp_B_output",
    0xFFFF781C: "AFC_pipeline_result",
    0xFFFF7448: "CLOL_mode_flag",
    0xFFFF895C: "injector_data",
    0xFFFF6624: "rpm_current",
    0xFFFF63F8: "iat_current",
    0xFFFF65F0: "CL_OL_status_byte",
    0xFFFF7C68: "engine_status_flag",
    0xFFFF62F8: "engine_load",
    0xFFFF80E4: "inj_pw_output_primary",
    0xFFFF80F8: "final_timing_output",
    0xFFFF668C: "inj_timing_state",
    0xFFFF6650: "maf_voltage_a",
    0xFFFF6654: "maf_voltage_b",
    0xFFFF6790: "manifold_pressure",
    0xFFFF6810: "boost_pressure",
    0xFFFF5FB8: "maf_value",
    0xFFFF79E0: "decay_delta",
    0xFFFF798C: "decay_accumulator",
    0xFFFF79F2: "ol_active_flag",
    0xFFFF77D8: "CL_target_comp_output",
    0xFFFF7864: "AFC_struct_base",
    0xFFFF7BA8: "AFC_PI_struct_base",
    0xFFFF7D68: "transient_fuel_timing",
    0xFFFF6540: "sensor_state",
    0xFFFF65C0: "throttle_position",
    # ROM functions
    0x0301E4: "fuel_pulse_width_calc",
    0x033304: "CL_fuel_dispatcher",
    0x033460: "fuel_aggregator_tail",
    0x037186: "fuel_transient_comp",
    0x037ABA: "injector_trim_application",
    0x037B68: "fuel_injector_comp",
    0x037B74: "afl_application",
    0x039528: "fuel_wot_enrich_calc",
    0x0342A8: "AFC_PI_controller",
    0x0BE830: "table_desc_lookup",
    0x0BE874: "LowPW_TableProcessor",
    0x0BE8AC: "table_helper_b",
    0x0BE608: "float_compare_range",
    # Calibration
    0x0CBE0C: "InjectorFlowScaling",
    0x0D106C: "InjectorLatency",
    0x0D0244: "PrimaryOL_KCA_Low",
    0x0D0404: "PrimaryOL_KCA_High",
    0x0CFD30: "PrimaryOL_KCA_Alternate",
}

# Subroutine names
SUB_NAMES = {
    0x0BE830: "table_desc_lookup",
    0x0BE874: "LowPW_TableProcessor",
    0x0BE8AC: "table_helper_b",
    0x0BE608: "float_compare_range",
    0x029858: "sub_29858",
    0x02997C: "sub_2997C",
    0x0299BC: "sub_299BC",
    0x0297A0: "sub_297A0",
    0x01CF16: "sub_1CF16",
    0x01CF46: "sub_1CF46",
    0x037B74: "afl_application",
    0x037ABA: "injector_trim_application",
    0x037B68: "fuel_injector_comp",
    0x033304: "CL_fuel_dispatcher",
    0x033460: "fuel_aggregator_tail",
}

def label(addr):
    if addr in LABELS:
        return LABELS[addr]
    return None

def disasm_range(start, end, gbr=0xFFFF7450):
    """Disassemble a range of SH-2 code with full annotation."""
    lines = []
    addr = start
    literal_refs = {}  # addr -> (pool_addr, value)
    branch_targets = set()

    # First pass: collect branch targets
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
        elif top == 0xA or top == 0xB:
            d12 = op & 0xFFF
            target = a + 4 + s12(d12) * 2
            branch_targets.add(target)
        a += 2

    addr = start
    while addr < end:
        if addr >= len(ROM) - 1:
            break

        prefix = ""
        if addr in branch_targets:
            lbl = label(addr)
            if lbl:
                prefix = f"\n  ; --- {lbl} ---\n"
            else:
                prefix = f"\n  .L_{addr:06X}:\n"
        elif addr == start:
            lbl = label(addr)
            if lbl:
                prefix = f"  ; === {lbl} ===\n"

        op = r16(ROM, addr)
        n4 = [(op >> 12) & 0xF, (op >> 8) & 0xF, (op >> 4) & 0xF, op & 0xF]
        top = n4[0]
        n_reg = n4[1]
        m_reg = n4[2]
        d8 = op & 0xFF
        d4 = op & 0xF

        mnem = ""
        comment = ""

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
                else: mnem = f".word  0x{op:04X}"
            elif sub == 0xA:
                if m_reg == 0: mnem = f"sts    MACH,R{n_reg}"
                elif m_reg == 1: mnem = f"sts    MACL,R{n_reg}"
                elif m_reg == 2: mnem = f"sts    PR,R{n_reg}"
                else: mnem = f".word  0x{op:04X}"
            else: mnem = f".word  0x{op:04X}"

        elif top == 0x1:
            disp = d4 * 4
            mnem = f"mov.l  R{m_reg},@({disp},R{n_reg})"
            if n_reg == 15: comment = f"; stack[{disp:#x}]"

        elif top == 0x2:
            sub = n4[3]
            szm = {0:".b",1:".w",2:".l",4:".b",5:".w",6:".l"}
            if sub in (0,1,2):
                mnem = f"mov{szm[sub]}  R{m_reg},@R{n_reg}"
            elif sub in (4,5,6):
                mnem = f"mov{szm[sub]}  R{m_reg},@-R{n_reg}"
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
            if sub in ops3:
                mnem = f"{ops3[sub]:7s} R{m_reg},R{n_reg}"
            else: mnem = f".word  0x{op:04X}"

        elif top == 0x4:
            low8 = op & 0xFF
            if low8 == 0x22: mnem = f"sts.l  PR,@-R{n_reg}"
            elif low8 == 0x26: mnem = f"lds.l  @R{n_reg}+,PR"
            elif low8 == 0x13: mnem = f"stc.l  GBR,@-R{n_reg}"
            elif low8 == 0x17: mnem = f"ldc.l  @R{n_reg}+,GBR"
            elif low8 == 0x1E: mnem = f"ldc    R{n_reg},GBR"
            elif low8 == 0x0B:
                mnem = f"jsr    @R{n_reg}"
            elif low8 == 0x2B:
                mnem = f"jmp    @R{n_reg}"
            elif low8 == 0x15: mnem = f"cmp/pl R{n_reg}"
            elif low8 == 0x11: mnem = f"cmp/pz R{n_reg}"
            elif low8 == 0x10: mnem = f"dt     R{n_reg}"
            elif low8 == 0x00: mnem = f"shll   R{n_reg}"
            elif low8 == 0x01: mnem = f"shlr   R{n_reg}"
            elif low8 == 0x04: mnem = f"rotl   R{n_reg}"
            elif low8 == 0x05: mnem = f"rotr   R{n_reg}"
            elif low8 == 0x08: mnem = f"shll2  R{n_reg}"
            elif low8 == 0x09: mnem = f"shlr2  R{n_reg}"
            elif low8 == 0x18: mnem = f"shll8  R{n_reg}"
            elif low8 == 0x19: mnem = f"shlr8  R{n_reg}"
            elif low8 == 0x28: mnem = f"shll16 R{n_reg}"
            elif low8 == 0x29: mnem = f"shlr16 R{n_reg}"
            elif low8 == 0x24: mnem = f"rotcl  R{n_reg}"
            elif low8 == 0x25: mnem = f"rotcr  R{n_reg}"
            else: mnem = f".word  0x{op:04X}  ; 4xxx"

        elif top == 0x5:
            disp = d4 * 4
            mnem = f"mov.l  @({disp},R{m_reg}),R{n_reg}"

        elif top == 0x6:
            sub = n4[3]
            ops6 = {0:"mov.b  @",1:"mov.w  @",2:"mov.l  @",3:"mov    ",
                    4:"mov.b  @",5:"mov.w  @",6:"mov.l  @",7:"not    ",
                    8:"swap.b ",9:"swap.w ",0xA:"negc   ",0xB:"neg    ",
                    0xC:"extu.b ",0xD:"extu.w ",0xE:"exts.b ",0xF:"exts.w "}
            if sub in (0,1,2):
                mnem = f"mov{'.b' if sub==0 else '.w' if sub==1 else '.l'}  @R{m_reg},R{n_reg}"
            elif sub in (4,5,6):
                sz = {4:".b",5:".w",6:".l"}[sub]
                mnem = f"mov{sz}  @R{m_reg}+,R{n_reg}"
            elif sub == 3: mnem = f"mov    R{m_reg},R{n_reg}"
            elif sub == 7: mnem = f"not    R{m_reg},R{n_reg}"
            elif sub == 8: mnem = f"swap.b R{m_reg},R{n_reg}"
            elif sub == 9: mnem = f"swap.w R{m_reg},R{n_reg}"
            elif sub == 0xA: mnem = f"negc   R{m_reg},R{n_reg}"
            elif sub == 0xB: mnem = f"neg    R{m_reg},R{n_reg}"
            elif sub == 0xC: mnem = f"extu.b R{m_reg},R{n_reg}"
            elif sub == 0xD: mnem = f"extu.w R{m_reg},R{n_reg}"
            elif sub == 0xE: mnem = f"exts.b R{m_reg},R{n_reg}"
            elif sub == 0xF: mnem = f"exts.w R{m_reg},R{n_reg}"
            else: mnem = f".word  0x{op:04X}"

        elif top == 0x7:
            imm = s8(d8)
            mnem = f"add    #{imm},R{n_reg}"
            if n_reg == 15: comment = f"; SP += {imm}"

        elif top == 0x8:
            sub = n4[1]
            if sub == 0x0:
                mnem = f"mov.b  R0,@({d4},R{m_reg})"
            elif sub == 0x1:
                mnem = f"mov.w  R0,@({d4*2},R{m_reg})"
            elif sub == 0x4:
                mnem = f"mov.b  @({d4},R{m_reg}),R0"
            elif sub == 0x5:
                mnem = f"mov.w  @({d4*2},R{m_reg}),R0"
            elif sub == 0x8:
                imm = s8(d8)
                mnem = f"cmp/eq #{imm},R0"
            elif sub == 0x9:
                disp = s8(d8) * 2 + 4
                target = addr + disp
                tl = label(target) or f"0x{target:06X}"
                mnem = f"bt     {tl}"
                comment = f"; -> {target:06X}"
            elif sub == 0xB:
                disp = s8(d8) * 2 + 4
                target = addr + disp
                tl = label(target) or f"0x{target:06X}"
                mnem = f"bf     {tl}"
                comment = f"; -> {target:06X}"
            elif sub == 0xD:
                disp = s8(d8) * 2 + 4
                target = addr + disp
                tl = label(target) or f"0x{target:06X}"
                mnem = f"bt/s   {tl}"
                comment = f"; -> {target:06X}"
            elif sub == 0xF:
                disp = s8(d8) * 2 + 4
                target = addr + disp
                tl = label(target) or f"0x{target:06X}"
                mnem = f"bf/s   {tl}"
                comment = f"; -> {target:06X}"
            else:
                mnem = f".word  0x{op:04X}"

        elif top == 0x9:
            disp = d8 * 2
            pool_addr = addr + 4 + disp
            if pool_addr + 1 < len(ROM):
                val = r16(ROM, pool_addr)
                mnem = f"mov.w  @(0x{pool_addr:06X}),R{n_reg}"
                comment = f"; =0x{val:04X} ({val})"
            else:
                mnem = f"mov.w  @(0x{pool_addr:06X}),R{n_reg}"

        elif top == 0xA:
            d12 = op & 0xFFF
            target = addr + 4 + s12(d12) * 2
            tl = label(target) or f"0x{target:06X}"
            mnem = f"bra    {tl}"
            comment = f"; -> {target:06X}"

        elif top == 0xB:
            d12 = op & 0xFFF
            target = addr + 4 + s12(d12) * 2
            tl = label(target)
            sn = SUB_NAMES.get(target)
            if sn:
                mnem = f"bsr    {sn}"
            elif tl:
                mnem = f"bsr    {tl}"
            else:
                mnem = f"bsr    0x{target:06X}"
            comment = f"; -> {target:06X}"

        elif top == 0xC:
            sub = n4[1]
            if sub == 0x0:
                ga = gbr + d8
                lbl = label(ga) or f"0x{ga:08X}"
                mnem = f"mov.b  R0,@({d8:#x},GBR)"
                comment = f"; write [{lbl}]"
            elif sub == 0x1:
                disp = d8 * 2
                ga = gbr + disp
                lbl = label(ga) or f"0x{ga:08X}"
                mnem = f"mov.w  R0,@({disp:#x},GBR)"
                comment = f"; write [{lbl}]"
            elif sub == 0x2:
                disp = d8 * 4
                ga = gbr + disp
                lbl = label(ga) or f"0x{ga:08X}"
                mnem = f"mov.l  R0,@({disp:#x},GBR)"
                comment = f"; write [{lbl}]"
            elif sub == 0x4:
                ga = gbr + d8
                lbl = label(ga) or f"0x{ga:08X}"
                mnem = f"mov.b  @({d8:#x},GBR),R0"
                comment = f"; read [{lbl}]"
            elif sub == 0x5:
                disp = d8 * 2
                ga = gbr + disp
                lbl = label(ga) or f"0x{ga:08X}"
                mnem = f"mov.w  @({disp:#x},GBR),R0"
                comment = f"; read [{lbl}]"
            elif sub == 0x6:
                disp = d8 * 4
                ga = gbr + disp
                lbl = label(ga) or f"0x{ga:08X}"
                mnem = f"mov.l  @({disp:#x},GBR),R0"
                comment = f"; read [{lbl}]"
            elif sub == 0x7:
                disp = d8 * 4
                pool_addr = ((addr + 4) & ~3) + disp
                mnem = f"mova   @(0x{pool_addr:06X}),R0"
            elif sub == 0x8:
                mnem = f"tst    #{d8:#x},R0"
            elif sub == 0x9:
                mnem = f"and    #{d8:#x},R0"
            elif sub == 0xD:
                mnem = f"and.b  #{d8:#x},@(R0,GBR)"
            elif sub == 0xF:
                mnem = f"or.b   #{d8:#x},@(R0,GBR)"
            else:
                mnem = f".word  0x{op:04X}  ; Cxxx"

        elif top == 0xD:
            disp = d8 * 4
            pool_addr = ((addr + 4) & ~3) + disp
            if pool_addr + 3 < len(ROM):
                val = r32(ROM, pool_addr)
                mnem = f"mov.l  @(0x{pool_addr:06X}),R{n_reg}"
                lbl = label(val)
                if lbl:
                    comment = f"; ={lbl} (0x{val:08X})"
                elif 0xFFFF0000 <= val <= 0xFFFFFFFF:
                    comment = f"; =0x{val:08X} (RAM)"
                elif val < 0x00100000:
                    sn = SUB_NAMES.get(val)
                    if sn:
                        comment = f"; ={sn} (0x{val:08X})"
                    else:
                        comment = f"; =0x{val:08X} (ROM)"
                elif 0x000A0000 <= val <= 0x000FFFFF:
                    comment = f"; =0x{val:08X} (cal)"
                    try:
                        fv = rf32(ROM, val)
                        fv_m = rf32(MOD, val)
                        if fv != fv_m:
                            comment += f" stock={fv} mod={fv_m} ***CHANGED***"
                        else:
                            comment += f" val={fv}"
                    except:
                        pass
                else:
                    # Try as float constant
                    try:
                        fv = struct.unpack(">f", struct.pack(">I", val))[0]
                        if abs(fv) > 1e-8 and abs(fv) < 1e8:
                            comment = f"; =0x{val:08X} (float={fv})"
                        else:
                            comment = f"; =0x{val:08X}"
                    except:
                        comment = f"; =0x{val:08X}"
            else:
                mnem = f"mov.l  @(0x{pool_addr:06X}),R{n_reg}"

        elif top == 0xE:
            imm = s8(d8)
            mnem = f"mov    #{imm},R{n_reg}"

        elif top == 0xF:
            sub = n4[3]
            fn = n_reg; fm = m_reg
            if sub == 0x0: mnem = f"fadd   FR{fm},FR{fn}"
            elif sub == 0x1: mnem = f"fsub   FR{fm},FR{fn}"
            elif sub == 0x2: mnem = f"fmul   FR{fm},FR{fn}"
            elif sub == 0x3: mnem = f"fdiv   FR{fm},FR{fn}"
            elif sub == 0x4: mnem = f"fcmp/eq FR{fm},FR{fn}"
            elif sub == 0x5: mnem = f"fcmp/gt FR{fm},FR{fn}"
            elif sub == 0x6: mnem = f"fmov.s @(R0,R{m_reg}),FR{fn}"
            elif sub == 0x7: mnem = f"fmov.s FR{fm},@(R0,R{n_reg})"
            elif sub == 0x8: mnem = f"fmov.s @R{m_reg},FR{fn}"
            elif sub == 0x9: mnem = f"fmov.s @R{m_reg}+,FR{fn}"
            elif sub == 0xA: mnem = f"fmov.s FR{fm},@R{n_reg}"
            elif sub == 0xB: mnem = f"fmov.s FR{fm},@-R{n_reg}"
            elif sub == 0xC: mnem = f"fmov   FR{fm},FR{fn}"
            elif sub == 0xD:
                if fm == 0x0: mnem = f"fsts   FPUL,FR{fn}"
                elif fm == 0x1: mnem = f"flds   FR{fn},FPUL"
                elif fm == 0x2: mnem = f"float  FPUL,FR{fn}"
                elif fm == 0x3: mnem = f"ftrc   FR{fn},FPUL"
                elif fm == 0x4: mnem = f"fneg   FR{fn}"
                elif fm == 0x5: mnem = f"fabs   FR{fn}"
                elif fm == 0x6: mnem = f"fsqrt  FR{fn}"
                elif fm == 0x8: mnem = f"fldi0  FR{fn}"
                elif fm == 0x9: mnem = f"fldi1  FR{fn}"
                else: mnem = f".word  0x{op:04X}  ; FPU_xD"
            else:
                mnem = f".word  0x{op:04X}  ; FPU"

        if not mnem:
            mnem = f".word  0x{op:04X}"

        line = f"  {addr:06X}: {op:04X}  {mnem}"
        if comment:
            line = f"{line:60s} {comment}"
        if prefix:
            lines.append(prefix.rstrip())
        lines.append(line)
        addr += 2

    return lines


print("=" * 90)
print("LAYER 1: fuel_pulse_width_calc @ 0x301E4")
print("=" * 90)
print()

# Disassemble the function - we don't know exact end, so go ~512 bytes and look for RTS
# First, scan for RTS to find function boundary
addr = 0x301E4
rts_count = 0
end = addr
for i in range(addr, addr + 0x400, 2):
    op = r16(ROM, i)
    if op == 0x000B:  # RTS
        rts_count += 1
        # RTS + delay slot = i + 4 is next function
        end = i + 4
        if rts_count >= 1:
            break

print(f"Function span: 0x{0x301E4:06X} - 0x{end:06X} ({end - 0x301E4} bytes)")
print()

lines = disasm_range(0x301E4, end)
for l in lines:
    print(l)

print()
print("=" * 90)
print("LITERAL POOL / CONSTANT ANALYSIS")
print("=" * 90)
print()

# Scan the literal pool area after the function for data references
pool_start = end
pool_end = min(pool_start + 0x80, len(ROM))
print(f"Scanning literal pool 0x{pool_start:06X} - 0x{pool_end:06X}:")
for a in range(pool_start, pool_end, 4):
    val = r32(ROM, a)
    lbl = label(val)
    if lbl:
        print(f"  {a:06X}: {val:08X}  -> {lbl}")
    elif 0xFFFF0000 <= val <= 0xFFFFFFFF:
        print(f"  {a:06X}: {val:08X}  (RAM)")
    elif val < 0x00100000:
        sn = SUB_NAMES.get(val)
        if sn:
            print(f"  {a:06X}: {val:08X}  -> {sn}")
        else:
            print(f"  {a:06X}: {val:08X}  (ROM)")
    elif 0x000A0000 <= val <= 0x000FFFFF:
        try:
            fv = rf32(ROM, val)
            print(f"  {a:06X}: {val:08X}  (cal) -> {fv}")
        except:
            print(f"  {a:06X}: {val:08X}  (cal)")
    else:
        try:
            fv = struct.unpack(">f", struct.pack(">I", val))[0]
            if abs(fv) > 1e-8 and abs(fv) < 1e8:
                print(f"  {a:06X}: {val:08X}  (float={fv})")
            else:
                print(f"  {a:06X}: {val:08X}")
        except:
            print(f"  {a:06X}: {val:08X}")

print()
print("=" * 90)
print("CROSS-REFERENCE: Who calls fuel_pulse_width_calc?")
print("=" * 90)
print()

# Scan entire ROM for BSR/JSR to 0x301E4
target_addr = 0x301E4
callers = []
for a in range(0, len(ROM) - 2, 2):
    op = r16(ROM, a)
    top = (op >> 12) & 0xF
    if top == 0xB:  # BSR
        d12 = op & 0xFFF
        dest = a + 4 + s12(d12) * 2
        if dest == target_addr:
            callers.append(("BSR", a))
    elif top == 0x4 and (op & 0xFF) == 0x0B:  # JSR @Rn
        # Need to check if register was loaded with our target
        # Just flag potential JSR sites near literal pool loads of 0x301E4
        pass

# Also scan for literal pool references to 0x301E4
for a in range(0, len(ROM) - 4, 4):
    val = r32(ROM, a)
    if val == target_addr:
        # Check if any mov.l instruction references this pool address
        callers.append(("POOL_REF", a))

for kind, a in callers:
    lbl = label(a) or ""
    print(f"  {kind} at 0x{a:06X}  {lbl}")

print()
print("=" * 90)
print("INJECTOR LATENCY TABLE DECODE")
print("=" * 90)
print()

# Decode InjectorLatency @ 0xD106C
# This is likely a descriptor-pointed table. Let's examine what's there.
lat_addr = 0xD106C
print(f"InjectorLatency @ 0x{lat_addr:06X}:")
print(f"  Raw bytes:")
for i in range(0, 64, 4):
    val = r32(ROM, lat_addr + i)
    fv = rf32(ROM, lat_addr + i)
    print(f"    +{i:02X}: {val:08X}  float={fv:.6f}")

print()
print("InjectorFlowScaling @ 0xCBE0C:")
fv = rf32(ROM, 0xCBE0C)
print(f"  Value: {fv} cc/min")

print()
# Also check if there's a descriptor that points to InjectorLatency
print("Scanning for descriptors referencing InjectorLatency address range...")
for a in range(0x0A0000, 0x0B0000, 4):
    val = r32(ROM, a)
    if 0xD1060 <= val <= 0xD1100:
        print(f"  Descriptor field at 0x{a:06X} -> 0x{val:08X}")
