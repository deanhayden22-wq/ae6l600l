#!/usr/bin/env python3
"""
Layer 6 Deep Dive: Disassemble ISR handlers for injection/ignition events
- ISR dispatch handlers [21] 0x04793C, [22] 0x048732, [26] 0x047B66,
  [27] 0x049A7A, [37] 0x04A03E, [41-44] 0x04A420..0x04A6FA
- Low-ROM ATU handlers [2] 0x5840, [3] 0xD658, [28] 0xC36C, [31] 0xC370, [34] 0xD4FC
- Vector handlers: 0xFEC, 0xFF8, 0x40, 0xFE4, 0xDA8, 0xDE4, 0xDCC
- Trace ATU register 0xFFFF4024 write context
- Trace InternalIO port write sites
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
    0xFFFF4024: "ATU_primary_ctrl", 0xFFFF40C8: "ATU_compare_reg",
    0xFFFF40E0: "ATU_output_ctrl", 0xFFFF3B06: "io_inj_ign_port_ctrl",
    0xFFFF366C: "io_inj_driver_ctrl", 0xFFFF3836: "io_ign_driver_ctrl",
    0xFFFF895C: "fuel_ign_shared_state", 0xFFFF7344: "fuel_per_cyl_struct",
    0xFFFF7348: "fuel_base_factor", 0xFFFF7AB4: "afl_multiplier_output",
    0xFFFF63F8: "RPM_float", 0xFFFF62F8: "engine_load",
    0xFFFF6624: "engine_load_float", 0xFFFF65C0: "throttle_pos",
    0xFFFF80E4: "timing_comp_mps", 0xFFFF80F8: "final_ign_timing_output",
    0xFFFF1288: "isr_state_reg", 0xFFFF1230: "TIER_MTU0",
    0xFFFF76D4: "fuel_enrichment_A", 0xFFFF7878: "fuel_enrichment_B",
    0xFFFF7AE4: "fuel_enrichment_C", 0xFFFF7904: "aggregator_fuel_output",
    0xFFFF3234: "io_reg_3234", 0xFFFF3244: "io_knock_base",
    0xFFFF318C: "io_reg_318C", 0xFFFF3158: "io_reg_3158",
    0xFFFF20F4: "io_reg_20F4", 0xFFFF20CC: "io_reg_20CC",
    0xFFFF212C: "io_reg_212C", 0xFFFF212E: "io_reg_212E",
    0xFFFF2150: "io_reg_2150", 0xFFFF233C: "io_timer_cfg",
    0xFFFF251C: "io_atu_port_en", 0xFFFF25CC: "io_output_cmp_cfg",
    0xFFFF2AB4: "io_reg_2AB4", 0xFFFF2F48: "io_reg_2F48",
    0xFFFF3480: "io_port_data", 0xFFFF34D8: "io_reg_34D8",
    0xFFFF365C: "io_reg_365C", 0xFFFF3674: "io_reg_3674",
    0xFFFF3694: "io_reg_3694", 0xFFFF36B8: "io_reg_36B8",
    0xFFFF36BE: "io_reg_36BE", 0xFFFF36F0: "io_timing_A",
    0xFFFF36F4: "io_timing_B", 0xFFFF3718: "io_reg_3718",
    0xFFFF399E: "io_port_status",
    0xFFFF4000: "ATU_base", 0xFFFF4040: "ATU_reg_40",
    0xFFFF4044: "ATU_reg_44", 0xFFFF4050: "ATU_reg_50",
    0xFFFF4058: "ATU_reg_58", 0xFFFF405C: "ATU_reg_5C",
    0xFFFF4060: "ATU_reg_60", 0xFFFF4064: "ATU_reg_64",
    0xFFFF407C: "ATU_reg_7C", 0xFFFF4094: "ATU_reg_94",
    0xFFFF40A4: "ATU_reg_A4", 0xFFFF40A8: "ATU_reg_A8",
    0xFFFF40B4: "ATU_ch_ctrl", 0xFFFF40B8: "ATU_reg_B8",
    0xFFFF40BC: "ATU_reg_BC", 0xFFFF40C0: "ATU_counter",
    0xFFFF40C4: "ATU_compare_B", 0xFFFF40CC: "ATU_reg_CC",
    0xFFFF40D0: "ATU_ctrl_ext", 0xFFFF40D4: "ATU_mode",
    0xFFFF40D8: "ATU_config", 0xFFFF40DC: "ATU_reg_DC",
    0xFFFF40E4: "ATU_output_B", 0xFFFF40E8: "ATU_reg_E8",
    0xFFFF40EC: "ATU_reg_EC", 0xFFFF40F0: "ATU_reg_F0",
    0xFFFF40F4: "ATU_reg_F4", 0xFFFF40F8: "ATU_reg_F8",
    0xFFFF40FC: "ATU_reg_FC",
    0xFFFF402C: "ATU_reg_2C",
    0xFFFF403C: "ATU_reg_3C",
}

SUB_NAMES = {
    0x00002B8C: "isr_context_save",
    0x0000317C: "interrupt_priority_set",
    0x00003190: "interrupt_restore",
    0x000BE554: "uint16_add_sat",
    0x000BE53C: "uint8_add_sat",
    0x000BE56C: "float_clamp_range",
    0x000BE588: "fmac_interp_uint8",
    0x000BE598: "fmac_interp_uint16",
    0x000BE830: "table_desc_lookup",
    0x000BE874: "LowPW_TableProcessor",
    0x000BE81C: "critical_section_enter",
    0x000BE82C: "critical_section_exit",
    0x0000E5EC: "isr_dispatch_table",
    0x00004A94C: "isr_task_scheduler",
}

def label(addr):
    return LABELS.get(addr) or SUB_NAMES.get(addr)

def disasm_func(start, max_bytes=0x300, gbr=0xFFFF7450, find_rts=1):
    """Disassemble from start until find_rts RTS instructions found."""
    end = start
    rts_found = 0
    for i in range(start, min(start + max_bytes, len(ROM) - 1), 2):
        op = r16(ROM, i)
        if op == 0x000B:
            rts_found += 1
            end = i + 4
            if rts_found >= find_rts:
                break
    if end == start: end = start + max_bytes

    lines = []
    addr = start
    while addr < end and addr < len(ROM) - 1:
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
            elif sub >= 7:
                o6 = {7:"not",8:"swap.b",9:"swap.w",0xA:"negc",0xB:"neg",
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
                elif 0xFFFF0000 <= val: comment = f"; =0x{val:08X} (RAM/IO)"
                elif val < 0x100000:
                    sn = SUB_NAMES.get(val)
                    if sn: comment = f"; ={sn}"
                    else: comment = f"; =0x{val:08X} (ROM)"
                elif 0xA0000 <= val <= 0xFFFFF:
                    comment = f"; =0x{val:08X} (cal)"
                    try:
                        fv = rf32(ROM, val)
                        comment += f" val={fv}"
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
                fpd = {0:"fsts   FPUL,",1:"flds   ,FPUL",2:"float  FPUL,",
                       3:"ftrc   ,FPUL",4:"fneg   ",5:"fabs   ",6:"fsqrt  ",
                       8:"fldi0  ",9:"fldi1  "}
                if fm in fpd:
                    if fm == 1: mnem = f"flds   FR{fn},FPUL"
                    elif fm == 3: mnem = f"ftrc   FR{fn},FPUL"
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


def print_section(title, start, max_b=0x300, find_rts=1, gbr=0xFFFF7450):
    print()
    print("=" * 90)
    print(f"{title} @ 0x{start:06X}")
    print("=" * 90)
    print()
    lines, end = disasm_func(start, max_bytes=max_b, find_rts=find_rts, gbr=gbr)
    print(f"Function span: 0x{start:06X} - 0x{end:06X} ({end - start} bytes)")
    print()
    for l in lines: print(l)
    # Print literal pool
    print(f"\n  Literal pool:")
    for a in range(end, min(end + 0x60, len(ROM)), 4):
        val = r32(ROM, a)
        lbl = label(val) or SUB_NAMES.get(val)
        if lbl:
            print(f"    {a:06X}: {val:08X}  -> {lbl}")
        elif 0xFFFF0000 <= val:
            print(f"    {a:06X}: {val:08X}  (RAM/IO)")
        elif val < 0x100000 and val > 0x100:
            print(f"    {a:06X}: {val:08X}  (ROM)")
        elif 0xA0000 <= val <= 0xFFFFF:
            try:
                fv = rf32(ROM, val)
                print(f"    {a:06X}: {val:08X}  (cal) val={fv}")
            except: pass
    return end


# ================================================================
# SECTION A: Exception vector handlers (hardware entry points)
# ================================================================

print_section("VEC 107: MTU5_TGIW5 — Crank sync input capture", 0x40, max_b=0x200)
print_section("VEC 108: POE0_OEI1 — Port output enable safety", 0xFE4, max_b=0x100)
print_section("VEC 103: MTU4_TGID4 — Timer compare match D", 0xFEC, max_b=0x100)
print_section("VEC 104: MTU4_TCIV4 — Timer overflow", 0xFF8, max_b=0x100)
print_section("VEC 202: ATU interrupt A", 0xDA8, max_b=0x100)
print_section("VEC 204: ATU interrupt B", 0xDE4, max_b=0x100)
print_section("VEC 206: ATU interrupt C", 0xDCC, max_b=0x100)

# ================================================================
# SECTION B: ISR dispatch handler — injection-relevant handlers
# ================================================================

print_section("ISR[2] handler — ATU/timer ISR A", 0x5840, max_b=0x300, find_rts=2)
print_section("ISR[3] handler — ATU timing ISR", 0xD658, max_b=0x200)
print_section("ISR[21] handler — Injection timing event?", 0x4793C, max_b=0x400, find_rts=2)
print_section("ISR[22] handler — Injection output event?", 0x48732, max_b=0x400, find_rts=2)
print_section("ISR[26] handler — Injection window?", 0x47B66, max_b=0x300, find_rts=2)
print_section("ISR[28] handler — ATU capture", 0xC36C, max_b=0x200)
print_section("ISR[31] handler — ATU capture paired", 0xC370, max_b=0x200)
print_section("ISR[34] handler — ATU compare", 0xD4FC, max_b=0x200)

# ================================================================
# SECTION C: Scan ATU_primary_ctrl (0xFFFF4024) write sites
# ================================================================

print()
print("=" * 90)
print("ATU_primary_ctrl (0xFFFF4024) — 36 pool refs context")
print("=" * 90)
print()

# Find all literal pool entries pointing to 0xFFFF4024
atu_refs = []
for a in range(0, len(ROM) - 4, 4):
    if r32(ROM, a) == 0xFFFF4024:
        atu_refs.append(a)

print(f"Found {len(atu_refs)} pool references to ATU_primary_ctrl:")
for ref in atu_refs:
    # Find which instruction loads this pool entry
    # mov.l @(disp,PC),Rn uses top nibble 0xD
    # Pool addr = ((PC+4) & ~3) + disp*4
    # So we search backwards for a mov.l instruction referencing this pool addr
    found = False
    for scan in range(max(0, ref - 0x200), ref, 2):
        op = r16(ROM, scan)
        if (op >> 12) == 0xD:
            d8 = op & 0xFF
            pa = ((scan + 4) & ~3) + d8 * 4
            if pa == ref:
                nr = (op >> 8) & 0xF
                # Show a few instructions around the load
                print(f"\n  Pool @ 0x{ref:06X}, loaded at 0x{scan:06X} into R{nr}:")
                for i in range(max(0, scan - 6), min(scan + 14, len(ROM) - 1), 2):
                    op2 = r16(ROM, i)
                    marker = " <<<" if i == scan else ""
                    # Quick decode of interesting instructions
                    if (op2 >> 12) == 0x2 and (op2 & 0xF) in (0,1,2):
                        # mov.x Rm,@Rn — this is a WRITE
                        sz = {0:".b",1:".w",2:".l"}[op2 & 0xF]
                        m = (op2 >> 4) & 0xF; n = (op2 >> 8) & 0xF
                        print(f"    {i:06X}: {op2:04X}  mov{sz} R{m},@R{n}  *** WRITE ***{marker}")
                    elif (op2 >> 12) == 0x6 and (op2 & 0xF) in (0,1,2):
                        # mov.x @Rm,Rn — this is a READ
                        sz = {0:".b",1:".w",2:".l"}[op2 & 0xF]
                        m = (op2 >> 4) & 0xF; n = (op2 >> 8) & 0xF
                        print(f"    {i:06X}: {op2:04X}  mov{sz} @R{m},R{n}  *** READ ***{marker}")
                    else:
                        print(f"    {i:06X}: {op2:04X}{marker}")
                found = True
                break
    if not found:
        print(f"  Pool @ 0x{ref:06X} — load instruction not found nearby")

# ================================================================
# SECTION D: InternalIO injection port (0xFFFF366C) write sites
# ================================================================

print()
print("=" * 90)
print("io_inj_driver_ctrl (0xFFFF366C) — 31 pool refs")
print("=" * 90)
print()

inj_refs = []
for a in range(0, len(ROM) - 4, 4):
    if r32(ROM, a) == 0xFFFF366C:
        inj_refs.append(a)

print(f"Found {len(inj_refs)} pool references:")
for ref in inj_refs[:15]:  # Show first 15
    for scan in range(max(0, ref - 0x200), ref, 2):
        op = r16(ROM, scan)
        if (op >> 12) == 0xD:
            d8 = op & 0xFF
            pa = ((scan + 4) & ~3) + d8 * 4
            if pa == ref:
                nr = (op >> 8) & 0xF
                print(f"  Pool @ 0x{ref:06X}, loaded at 0x{scan:06X} into R{nr}")
                # Show 5 instructions after
                for i in range(scan, min(scan + 20, len(ROM) - 1), 2):
                    op2 = r16(ROM, i)
                    if (op2 >> 12) == 0x2 and (op2 & 0xF) in (0,1,2):
                        sz = {0:".b",1:".w",2:".l"}[op2 & 0xF]
                        m = (op2 >> 4) & 0xF; n = (op2 >> 8) & 0xF
                        print(f"    {i:06X}: {op2:04X}  mov{sz} R{m},@R{n}  *** WRITE ***")
                    elif (op2 >> 12) == 0x6 and (op2 & 0xF) in (0,1,2):
                        sz = {0:".b",1:".w",2:".l"}[op2 & 0xF]
                        m = (op2 >> 4) & 0xF; n = (op2 >> 8) & 0xF
                        print(f"    {i:06X}: {op2:04X}  mov{sz} @R{m},R{n}  *** READ ***")
                    else:
                        print(f"    {i:06X}: {op2:04X}")
                break
