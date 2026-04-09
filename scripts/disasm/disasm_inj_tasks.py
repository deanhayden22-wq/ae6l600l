#!/usr/bin/env python3
"""
Layer 3: Disassemble scheduler tasks 46, 47, 48
- task46_inj_mps_timing @ 0x43368
- task47_mapswitch_lowpw @ 0x43464
- task48_final_timing @ 0x4359C
Also:
- Layer 4: fuel_aggregator_tail @ 0x33460
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

LABELS = {
    0xFFFF7AB4: "afl_multiplier_output", 0xFFFF895C: "injector_data",
    0xFFFF63F8: "iat_current", 0xFFFF62F8: "engine_load",
    0xFFFF6540: "sensor_state", 0xFFFF77C8: "CL_base_params",
    0xFFFF7D68: "transient_fuel", 0xFFFF80E4: "inj_pw_primary",
    0xFFFF80F8: "final_timing_output", 0xFFFF668C: "inj_timing_state",
    0xFFFF6650: "maf_voltage_a", 0xFFFF6654: "maf_voltage_b",
    0xFFFF6790: "manifold_pressure", 0xFFFF6810: "boost_pressure",
    0xFFFF5FB8: "maf_value", 0xFFFF7448: "CLOL_mode_flag",
    0xFFFF65C0: "throttle_pos", 0xFFFF6812: "boost_pressure_w",
    0xFFFF80EC: "inj_comp_state", 0xFFFF5BE3: "ect_byte",
    0xFFFF6624: "rpm_current", 0xFFFF65BF: "throttle_byte",
    0xFFFF77DC: "CL_target_comp_A", 0xFFFF77E0: "CL_target_comp_B",
    0xFFFF781C: "AFC_pipeline_result", 0xFFFF7864: "AFC_struct_base",
    0xFFFF7BA8: "AFC_PI_struct_base", 0xFFFF7348: "fuel_base_factor",
    0xFFFF73A4: "fuel_correction_A", 0xFFFF7A08: "fuel_correction_B",
    0xFFFF7BC4: "fuel_correction_C", 0xFFFF76D4: "fuel_enrichment_A",
    0xFFFF7878: "fuel_enrichment_B", 0xFFFF7AE4: "fuel_enrichment_C",
    0xFFFF7344: "fuel_struct_base", 0xFFFF80C8: "timing_lu_state",
    0xFFFF80DA: "timing_lu_flag", 0xFFFF8910: "ign_output_state",
    0xFFFF8098: "ign_ctrl_a", 0xFFFF80AE: "ign_ctrl_b",
    0xFFFF6364: "ect_startup",
}

SUB_NAMES = {
    0x0BE830: "table_desc_lookup", 0x0BE874: "LowPW_TableProcessor",
    0x0BE56C: "float_clamp_apply", 0x0BE608: "float_compare_range",
    0x0BE8AC: "table_helper_b", 0x029858: "sub_29858",
    0x02997C: "sub_2997C", 0x0299BC: "sub_299BC",
    0x0297A0: "sub_297A0", 0x01CF16: "sub_1CF16",
    0x01CF46: "sub_1CF46", 0x037B74: "afl_application",
    0x037ABA: "injector_trim_application",
    0x037B68: "fuel_injector_comp",
    0x033304: "CL_fuel_dispatcher", 0x033460: "fuel_aggregator_tail",
    0x0301E4: "fuel_pulse_width_calc", 0x037186: "fuel_transient_comp",
    0x039528: "fuel_wot_enrich_calc", 0x0342A8: "AFC_PI_controller",
    0x043368: "task46_inj_mps_timing", 0x043464: "task47_mapswitch_lowpw",
    0x04359C: "task48_final_timing", 0x042A78: "task38_ign_output",
    0x0278D2: "sub_278D2",
}

def label(addr):
    return LABELS.get(addr) or SUB_NAMES.get(addr)

def disasm_func(start, max_bytes=0x400, gbr=0xFFFF7450, find_all_rts=False):
    """Disassemble from start. If find_all_rts, scan for multiple RTS to get a larger function."""
    end = start
    rts_found = 0
    target_rts = 2 if find_all_rts else 1
    for i in range(start, start + max_bytes, 2):
        if i + 1 >= len(ROM): break
        op = r16(ROM, i)
        if op == 0x000B:
            rts_found += 1
            end = i + 4
            if rts_found >= target_rts:
                break
    if end == start: end = start + max_bytes

    lines = []
    addr = start
    while addr < end:
        if addr >= len(ROM) - 1: break
        op = r16(ROM, addr)
        n4 = [(op >> 12) & 0xF, (op >> 8) & 0xF, (op >> 4) & 0xF, op & 0xF]
        top = n4[0]; nr = n4[1]; mr = n4[2]; d8 = op & 0xFF; d4 = op & 0xF
        mnem = ""; comment = ""

        if op == 0x0009: mnem = "nop"
        elif op == 0x000B: mnem = "rts"
        elif op == 0x0019: mnem = "div0u"
        elif top == 0x0:
            sub = n4[3]
            if sub == 0xC: mnem = f"mov.b  @(R0,R{mr}),R{nr}"
            elif sub == 0xD: mnem = f"mov.w  @(R0,R{mr}),R{nr}"
            elif sub == 0xE: mnem = f"mov.l  @(R0,R{mr}),R{nr}"
            elif sub == 0x4: mnem = f"mov.b  R{mr},@(R0,R{nr})"
            elif sub == 0x5: mnem = f"mov.w  R{mr},@(R0,R{nr})"
            elif sub == 0x6: mnem = f"mov.l  R{mr},@(R0,R{nr})"
            elif sub == 0x7: mnem = f"mul.l  R{mr},R{nr}"
            elif sub == 0x2:
                if mr == 0: mnem = f"stc    SR,R{nr}"
                elif mr == 1: mnem = f"stc    GBR,R{nr}"
            elif sub == 0xA:
                if mr == 0: mnem = f"sts    MACH,R{nr}"
                elif mr == 1: mnem = f"sts    MACL,R{nr}"
                elif mr == 2: mnem = f"sts    PR,R{nr}"
            if not mnem: mnem = f".word  0x{op:04X}"
        elif top == 0x1:
            disp = d4 * 4; mnem = f"mov.l  R{mr},@({disp},R{nr})"
        elif top == 0x2:
            sub = n4[3]
            if sub in (0,1,2):
                sz = {0:".b",1:".w",2:".l"}[sub]; mnem = f"mov{sz}  R{mr},@R{nr}"
            elif sub in (4,5,6):
                sz = {4:".b",5:".w",6:".l"}[sub]; mnem = f"mov{sz}  R{mr},@-R{nr}"
            elif sub == 8: mnem = f"tst    R{mr},R{nr}"
            elif sub == 9: mnem = f"and    R{mr},R{nr}"
            elif sub == 0xA: mnem = f"xor    R{mr},R{nr}"
            elif sub == 0xB: mnem = f"or     R{mr},R{nr}"
            else: mnem = f".word  0x{op:04X}"
        elif top == 0x3:
            sub = n4[3]
            ops3 = {0:"cmp/eq",2:"cmp/hs",3:"cmp/ge",4:"div1",5:"dmulu.l",
                    6:"cmp/hi",7:"cmp/gt",8:"sub",0xA:"subc",0xC:"add",
                    0xD:"dmuls.l",0xE:"addc",0xF:"addv"}
            if sub in ops3: mnem = f"{ops3[sub]:7s} R{mr},R{nr}"
            else: mnem = f".word  0x{op:04X}"
        elif top == 0x4:
            low8 = op & 0xFF
            sh = {0x00:"shll",0x01:"shlr",0x04:"rotl",0x05:"rotr",0x08:"shll2",
                  0x09:"shlr2",0x18:"shll8",0x19:"shlr8",0x28:"shll16",
                  0x29:"shlr16",0x24:"rotcl",0x25:"rotcr"}
            if low8 == 0x22: mnem = f"sts.l  PR,@-R{nr}"
            elif low8 == 0x26: mnem = f"lds.l  @R{nr}+,PR"
            elif low8 == 0x13: mnem = f"stc.l  GBR,@-R{nr}"
            elif low8 == 0x17: mnem = f"ldc.l  @R{nr}+,GBR"
            elif low8 == 0x1E: mnem = f"ldc    R{nr},GBR"
            elif low8 == 0x0B: mnem = f"jsr    @R{nr}"
            elif low8 == 0x2B: mnem = f"jmp    @R{nr}"
            elif low8 == 0x15: mnem = f"cmp/pl R{nr}"
            elif low8 == 0x11: mnem = f"cmp/pz R{nr}"
            elif low8 == 0x10: mnem = f"dt     R{nr}"
            elif low8 in sh: mnem = f"{sh[low8]:7s} R{nr}"
            else: mnem = f".word  0x{op:04X}"
        elif top == 0x5:
            disp = d4 * 4; mnem = f"mov.l  @({disp},R{mr}),R{nr}"
        elif top == 0x6:
            sub = n4[3]
            if sub in (0,1,2):
                sz = {0:".b",1:".w",2:".l"}[sub]; mnem = f"mov{sz}  @R{mr},R{nr}"
            elif sub in (4,5,6):
                sz = {4:".b",5:".w",6:".l"}[sub]; mnem = f"mov{sz}  @R{mr}+,R{nr}"
            elif sub == 3: mnem = f"mov    R{mr},R{nr}"
            elif sub == 7: mnem = f"not    R{mr},R{nr}"
            elif sub >= 8:
                o6 = {8:"swap.b",9:"swap.w",0xA:"negc",0xB:"neg",
                      0xC:"extu.b",0xD:"extu.w",0xE:"exts.b",0xF:"exts.w"}
                mnem = f"{o6.get(sub,'?'):7s} R{mr},R{nr}"
        elif top == 0x7:
            imm = s8(d8); mnem = f"add    #{imm},R{nr}"
        elif top == 0x8:
            sub = n4[1]
            if sub == 0x0: mnem = f"mov.b  R0,@({d4},R{mr})"
            elif sub == 0x1: mnem = f"mov.w  R0,@({d4*2},R{mr})"
            elif sub == 0x4: mnem = f"mov.b  @({d4},R{mr}),R0"
            elif sub == 0x5: mnem = f"mov.w  @({d4*2},R{mr}),R0"
            elif sub == 0x8: mnem = f"cmp/eq #{s8(d8)},R0"
            elif sub in (0x9,0xB,0xD,0xF):
                nm = {0x9:"bt",0xB:"bf",0xD:"bt/s",0xF:"bf/s"}
                t = addr + s8(d8) * 2 + 4
                tl = label(t)
                mnem = f"{nm[sub]:7s} {tl or f'0x{t:06X}'}"
                comment = f"; -> {t:06X}"
            else: mnem = f".word  0x{op:04X}"
        elif top == 0x9:
            pa = addr + 4 + d8 * 2
            if pa + 1 < len(ROM):
                val = r16(ROM, pa)
                mnem = f"mov.w  @(0x{pa:06X}),R{nr}"
                comment = f"; =0x{val:04X} ({val})"
        elif top == 0xA:
            t = addr + 4 + s12(op & 0xFFF) * 2
            tl = label(t)
            mnem = f"bra    {tl or f'0x{t:06X}'}"
            comment = f"; -> {t:06X}"
        elif top == 0xB:
            t = addr + 4 + s12(op & 0xFFF) * 2
            tl = label(t)
            mnem = f"bsr    {tl or f'0x{t:06X}'}"
            comment = f"; -> {t:06X}"
        elif top == 0xC:
            sub = n4[1]
            if sub in (0,1,2):
                mul = {0:1,1:2,2:4}[sub]; sz = {0:".b",1:".w",2:".l"}[sub]
                disp = d8 * mul; ga = gbr + disp
                lbl = label(ga) or f"0x{ga:08X}"
                mnem = f"mov{sz}  R0,@({disp:#x},GBR)"
                comment = f"; write [{lbl}]"
            elif sub in (4,5,6):
                mul = {4:1,5:2,6:4}[sub]; sz = {4:".b",5:".w",6:".l"}[sub]
                disp = d8 * mul; ga = gbr + disp
                lbl = label(ga) or f"0x{ga:08X}"
                mnem = f"mov{sz}  @({disp:#x},GBR),R0"
                comment = f"; read [{lbl}]"
            elif sub == 0x7:
                pa = ((addr + 4) & ~3) + d8 * 4
                mnem = f"mova   @(0x{pa:06X}),R0"
            elif sub == 0x8: mnem = f"tst    #{d8:#x},R0"
            elif sub == 0x9: mnem = f"and    #{d8:#x},R0"
            elif sub == 0xD: mnem = f"and.b  #{d8:#x},@(R0,GBR)"
            elif sub == 0xF: mnem = f"or.b   #{d8:#x},@(R0,GBR)"
            else: mnem = f".word  0x{op:04X}"
        elif top == 0xD:
            pa = ((addr + 4) & ~3) + d8 * 4
            if pa + 3 < len(ROM):
                val = r32(ROM, pa)
                mnem = f"mov.l  @(0x{pa:06X}),R{nr}"
                lbl = label(val)
                if lbl: comment = f"; ={lbl} (0x{val:08X})"
                elif 0xFFFF0000 <= val: comment = f"; =0x{val:08X} (RAM)"
                elif val < 0x100000: comment = f"; =0x{val:08X} (ROM)"
                elif 0xA0000 <= val <= 0xFFFFF:
                    comment = f"; =0x{val:08X} (cal)"
                    try:
                        fv = rf32(ROM, val); fvm = rf32(MOD, val)
                        if fv != fvm: comment += f" stk={fv} mod={fvm}"
                        else: comment += f" val={fv}"
                    except: pass
                else:
                    try:
                        fv = struct.unpack(">f", struct.pack(">I", val))[0]
                        if 1e-8 < abs(fv) < 1e8: comment = f"; =float({fv})"
                        else: comment = f"; =0x{val:08X}"
                    except: comment = f"; =0x{val:08X}"
        elif top == 0xE: mnem = f"mov    #{s8(d8)},R{nr}"
        elif top == 0xF:
            sub = n4[3]; fn = nr; fm = mr
            fpu = {0:"fadd",1:"fsub",2:"fmul",3:"fdiv",4:"fcmp/eq",5:"fcmp/gt",0xC:"fmov"}
            if sub in fpu: mnem = f"{fpu[sub]:7s} FR{fm},FR{fn}"
            elif sub == 6: mnem = f"fmov.s @(R0,R{mr}),FR{fn}"
            elif sub == 7: mnem = f"fmov.s FR{fm},@(R0,R{nr})"
            elif sub == 8: mnem = f"fmov.s @R{mr},FR{fn}"
            elif sub == 9: mnem = f"fmov.s @R{mr}+,FR{fn}"
            elif sub == 0xA: mnem = f"fmov.s FR{fm},@R{nr}"
            elif sub == 0xB: mnem = f"fmov.s FR{fm},@-R{nr}"
            elif sub == 0xD:
                fpd = {0:"fsts   FPUL,",1:"flds   ",2:"float  FPUL,",
                       3:"ftrc   ",4:"fneg   ",5:"fabs   ",6:"fsqrt  ",
                       8:"fldi0  ",9:"fldi1  "}
                if fm in fpd:
                    if fm in (1,3):
                        suf = ",FPUL" if fm == 1 else ",FPUL"
                        mnem = f"{'flds' if fm==1 else 'ftrc':7s} FR{fn}{suf}"
                    else: mnem = f"{fpd[fm]}FR{fn}"
                else: mnem = f".word  0x{op:04X}"
            elif sub == 0xE: mnem = f"fmac   FR0,FR{fm},FR{fn}"
            else: mnem = f".word  0x{op:04X}"

        if not mnem: mnem = f".word  0x{op:04X}"

        line = f"  {addr:06X}: {op:04X}  {mnem}"
        if comment: line = f"{line:60s} {comment}"
        lines.append(line)
        addr += 2
    return lines, end


def print_pool(end, size=0x60):
    """Print literal pool after function."""
    print(f"\n  Literal pool after 0x{end:06X}:")
    for a in range(end, min(end + size, len(ROM)), 4):
        val = r32(ROM, a)
        lbl = label(val)
        if lbl:
            print(f"    {a:06X}: {val:08X}  -> {lbl}")
        elif 0xFFFF0000 <= val:
            print(f"    {a:06X}: {val:08X}  (RAM)")
        elif val < 0x100000:
            sn = SUB_NAMES.get(val)
            if sn: print(f"    {a:06X}: {val:08X}  -> {sn}")
            else: print(f"    {a:06X}: {val:08X}  (ROM)")
        elif 0xA0000 <= val <= 0xFFFFF:
            try:
                fv = rf32(ROM, val)
                fvm = rf32(MOD, val)
                ch = " ***CHANGED***" if fv != fvm else ""
                print(f"    {a:06X}: {val:08X}  (cal) val={fv}{ch}")
            except:
                print(f"    {a:06X}: {val:08X}  (cal)")
        else:
            try:
                fv = struct.unpack(">f", struct.pack(">I", val))[0]
                if 1e-8 < abs(fv) < 1e8:
                    print(f"    {a:06X}: {val:08X}  (float={fv})")
            except: pass


# ==================================================================
for task_name, task_addr, max_b, find_rts in [
    ("TASK 46: inj_mps_timing", 0x43368, 0x200, True),
    ("TASK 47: mapswitch_lowpw", 0x43464, 0x200, True),
    ("TASK 48: final_timing", 0x4359C, 0x200, True),
    ("LAYER 4: fuel_aggregator_tail", 0x33460, 0x300, True),
    ("TASK 38: ign_output (reads injector_data)", 0x42A78, 0x200, True),
]:
    print()
    print("=" * 90)
    print(task_name + f" @ 0x{task_addr:06X}")
    print("=" * 90)
    print()

    lines, end = disasm_func(task_addr, max_bytes=max_b, find_all_rts=find_rts)
    print(f"Function span: 0x{task_addr:06X} - 0x{end:06X} ({end - task_addr} bytes)")
    print()
    for l in lines: print(l)
    print_pool(end)

# ==================================================================
# Also disassemble sub_278D2 called by task38
# ==================================================================
print()
print("=" * 90)
print("SUB_278D2 (called by task38_ign_output)")
print("=" * 90)
print()

lines, end = disasm_func(0x278D2, max_bytes=0x200)
print(f"Function span: 0x0278D2 - 0x{end:06X} ({end - 0x278D2} bytes)")
print()
for l in lines: print(l)
print_pool(end)

# Also: sub 0x436B6 called by task48
print()
print("=" * 90)
print("SUB_436B6 (called by task48_final_timing)")
print("=" * 90)
print()

lines, end = disasm_func(0x436B6, max_bytes=0x300, find_all_rts=True)
print(f"Function span: 0x0436B6 - 0x{end:06X} ({end - 0x436B6} bytes)")
print()
for l in lines: print(l)
print_pool(end)
