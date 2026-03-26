#!/usr/bin/env python3
"""
Disassemble code around ADC register access points in the AE5L600L ROM.
Focus on the 5 locations that construct 0xFFFFF800 (ADDR0 base).
"""
import os
import struct
import sys

ROM_PATH = os.path.join(os.path.dirname(__file__), "..", "rom", "ae5l600l.bin")

# ADC data register offsets from 0xFFFFF800
ADC_CHAN_MAP = {}
for i in range(12):
    ADC_CHAN_MAP[i*2] = f"ADDR{i}H"
    ADC_CHAN_MAP[i*2+1] = f"ADDR{i}L"
ADC_CHAN_MAP[0x18] = "ADCSR0"
ADC_CHAN_MAP[0x19] = "ADCR0"
# Group 1 starts at offset 0x20
for i in range(12):
    ADC_CHAN_MAP[0x20+i*2] = f"ADDR{12+i}H"
    ADC_CHAN_MAP[0x20+i*2+1] = f"ADDR{12+i}L"
ADC_CHAN_MAP[0x38] = "ADCSR1"
ADC_CHAN_MAP[0x39] = "ADCR1"
# Group 2 at offset 0x40
for i in range(8):
    ADC_CHAN_MAP[0x40+i*2] = f"ADDR{24+i}H"
    ADC_CHAN_MAP[0x40+i*2+1] = f"ADDR{24+i}L"
ADC_CHAN_MAP[0x58] = "ADCSR2"
ADC_CHAN_MAP[0x59] = "ADCR2"

# Known RAM addresses
RAM_NAMES = {
    0xFFFF8244: "RPM",
    0xFFFF824C: "ECT_raw",
    0xFFFF8264: "MAF_voltage",
    0xFFFF828C: "TPS",
    0xFFFF82B0: "IAT",
    0xFFFF8398: "Vehicle_Speed",
    0xFFFF9270: "IAM",
    0xFFFF9374: "Knock_Sum",
    0xFFFF93DC: "FBKC",
    0xFFFF93E0: "FLKC",
    0xFFFF5E58: "TGV_Left_GBR",
    0xFFFF5F1C: "TGV_Right_GBR",
}

# Known function addresses
FUNC_NAMES = {
    0x00000BFA: "DefaultExceptionHandler",
    0x00000BAC: "NMI_Handler",
    0x00000C0C: "Reset_Entry",
    0x00043750: "knock_wrapper",
    0x00043782: "knock_detector",
    0x00043D68: "task12_knock_post",
    0x0004438C: "task11_knock_flag_read",
    0x00045BFE: "flkc_path_J",
    0x000463BA: "flkc_paths_FG",
    0x0004A94C: "sched_periodic_dispatch",
    0x000BE608: "Pull2DFloat",
    0x000BE830: "Pull3DFloat",
    0x000BE874: "LowPW_TableProcessor",
    0x000BECA8: "LowPW_AxisLookup",
}


def sign_extend_8(val):
    return val - 0x100 if val & 0x80 else val


def sign_extend_12(val):
    return val - 0x1000 if val & 0x800 else val


def decode_insn(code, pc, rom):
    """Decode a single 16-bit SH-2 instruction."""
    n = (code >> 8) & 0xF
    m = (code >> 4) & 0xF
    d = code & 0xF
    i = code & 0xFF

    top4 = (code >> 12) & 0xF

    if code == 0x0009: return "nop", 2
    if code == 0x000B: return "rts", 2
    if code == 0x002B: return "rte", 2
    if code == 0x0019: return "div0u", 2
    if code == 0x001B: return "sleep", 2

    if top4 == 0x0:
        if (code & 0xF00F) == 0x0003: return f"bsrf   r{n}", 2
        if (code & 0xF0FF) == 0x0012: return f"stc    GBR,r{n}", 2
        if (code & 0xF0FF) == 0x0022: return f"stc    VBR,r{n}", 2
        if (code & 0xF00F) == 0x0004: return f"mov.b  r{m},@(r0,r{n})", 2
        if (code & 0xF00F) == 0x0005: return f"mov.w  r{m},@(r0,r{n})", 2
        if (code & 0xF00F) == 0x0006: return f"mov.l  r{m},@(r0,r{n})", 2
        if (code & 0xF00F) == 0x0007: return f"mul.l  r{m},r{n}", 2
        if (code & 0xF00F) == 0x000C: return f"mov.b  @(r0,r{m}),r{n}", 2
        if (code & 0xF00F) == 0x000D: return f"mov.w  @(r0,r{m}),r{n}", 2
        if (code & 0xF00F) == 0x000E: return f"mov.l  @(r0,r{m}),r{n}", 2
        if (code & 0xF00F) == 0x000F: return f"mac.l  @r{m}+,@r{n}+", 2
        return f"??       ; 0x{code:04X}", 2

    if top4 == 0x1:
        disp = code & 0xF
        return f"mov.l  r{m},@({disp*4},r{n})", 2

    if top4 == 0x2:
        sub = code & 0xF
        ops = {0:"mov.b",1:"mov.w",2:"mov.l",4:"mov.b",5:"mov.w",6:"mov.l",
               7:"div0s",8:"tst",9:"and",0xA:"xor",0xB:"or",0xC:"cmp/str",
               0xD:"xtrct",0xE:"mulu.w",0xF:"muls.w"}
        if sub in (0,1,2): return f"{ops[sub]}  r{m},@r{n}", 2
        if sub == 3: return f"cas.l  r{m},r{n},@r0", 2
        if sub in (4,5,6): return f"{ops[sub]}  r{m},@-r{n}", 2
        if sub in ops: return f"{ops[sub]}  r{m},r{n}", 2
        return f"??       ; 0x{code:04X}", 2

    if top4 == 0x3:
        sub = code & 0xF
        cmpops = {0:"cmp/eq",2:"cmp/hs",3:"cmp/ge",4:"div1",5:"dmulu.l",
                  6:"cmp/hi",7:"cmp/gt",8:"sub",0xA:"subc",0xB:"subv",
                  0xC:"add",0xD:"dmuls.l",0xE:"addc",0xF:"addv"}
        if sub in cmpops: return f"{cmpops[sub]}  r{m},r{n}", 2
        return f"??       ; 0x{code:04X}", 2

    if top4 == 0x4:
        lo = code & 0xFF
        if lo == 0x18: return f"shll8  r{n}", 2
        if lo == 0x19: return f"shlr8  r{n}", 2
        if lo == 0x28: return f"shll16 r{n}", 2
        if lo == 0x29: return f"shlr16 r{n}", 2
        if lo == 0x00: return f"shll   r{n}", 2
        if lo == 0x01: return f"shlr   r{n}", 2
        if lo == 0x04: return f"rotl   r{n}", 2
        if lo == 0x05: return f"rotr   r{n}", 2
        if lo == 0x08: return f"shll2  r{n}", 2
        if lo == 0x09: return f"shlr2  r{n}", 2
        if lo == 0x10: return f"dt     r{n}", 2
        if lo == 0x11: return f"cmp/pz r{n}", 2
        if lo == 0x15: return f"cmp/pl r{n}", 2
        if lo == 0x20: return f"shal   r{n}", 2
        if lo == 0x21: return f"shar   r{n}", 2
        if lo == 0x24: return f"rotcl  r{n}", 2
        if lo == 0x25: return f"rotcr  r{n}", 2
        if (code & 0xF00F) == 0x400B:
            target_name = FUNC_NAMES.get(None, "")
            return f"jsr    @r{m}", 2
        if (code & 0xF00F) == 0x400E: return f"ldc    r{m},SR", 2
        if (code & 0xF0FF) == 0x401E: return f"ldc    r{n},GBR", 2
        if (code & 0xF0FF) == 0x402E: return f"ldc    r{n},VBR", 2
        if lo == 0x22: return f"sts.l  pr,@-r{n}", 2
        if lo == 0x26: return f"lds.l  @r{n}+,pr", 2
        if lo == 0x02: return f"sts.l  mach,@-r{n}", 2
        if lo == 0x06: return f"lds.l  @r{n}+,mach", 2
        if lo == 0x12: return f"sts.l  macl,@-r{n}", 2
        if lo == 0x16: return f"lds.l  @r{n}+,macl", 2
        if lo == 0x2A: return f"lds    r{n},pr", 2
        if lo == 0x0A: return f"lds    r{n},mach", 2
        if lo == 0x1A: return f"lds    r{n},macl", 2
        if (code & 0xF00F) == 0x400F: return f"mac.w  @r{m}+,@r{n}+", 2
        return f"??       ; 0x{code:04X} (grp4)", 2

    if top4 == 0x5:
        disp = code & 0xF
        return f"mov.l  @({disp*4},r{m}),r{n}", 2

    if top4 == 0x6:
        sub = code & 0xF
        ops = {0:"mov.b",1:"mov.w",2:"mov.l",3:"mov",4:"mov.b",5:"mov.w",
               6:"mov.l",7:"not",8:"swap.b",9:"swap.w",0xA:"negc",0xB:"neg",
               0xC:"extu.b",0xD:"extu.w",0xE:"exts.b",0xF:"exts.w"}
        if sub in (0,1,2): return f"{ops[sub]}  @r{m},r{n}", 2
        if sub == 3: return f"mov    r{m},r{n}", 2
        if sub in (4,5,6): return f"{ops[sub]}  @r{m}+,r{n}", 2
        if sub in ops: return f"{ops[sub]}  r{m},r{n}", 2
        return f"??       ; 0x{code:04X}", 2

    if top4 == 0x7:
        imm = sign_extend_8(i)
        return f"add    #{imm},r{n}", 2

    if top4 == 0x8:
        sub = (code >> 8) & 0xF
        if sub == 0: return f"mov.b  r0,@({d},r{m})", 2
        if sub == 1: return f"mov.w  r0,@({d*2},r{m})", 2
        if sub == 4: return f"mov.b  @({d},r{m}),r0", 2
        if sub == 5: return f"mov.w  @({d*2},r{m}),r0", 2
        if sub == 8:
            imm = sign_extend_8(i)
            return f"cmp/eq #{imm},r0", 2
        if sub == 9:
            disp = sign_extend_8(i)
            target = pc + 4 + disp * 2
            return f"bt     0x{target:05X}", 2
        if sub == 0xB:
            disp = sign_extend_8(i)
            target = pc + 4 + disp * 2
            return f"bf     0x{target:05X}", 2
        if sub == 0xD:
            disp = sign_extend_8(i)
            target = pc + 4 + disp * 2
            return f"bt/s   0x{target:05X}", 2
        if sub == 0xF:
            disp = sign_extend_8(i)
            target = pc + 4 + disp * 2
            return f"bf/s   0x{target:05X}", 2
        return f"??       ; 0x{code:04X} (grp8)", 2

    if top4 == 0x9:
        disp = code & 0xFF
        target = pc + 4 + disp * 2
        if target + 2 <= len(rom):
            val = struct.unpack_from(">H", rom, target)[0]
            return f"mov.w  @(0x{target:05X}),r{n}  ; =0x{val:04X}", 2
        return f"mov.w  @(0x{target:05X}),r{n}", 2

    if top4 == 0xA:
        disp = sign_extend_12(code & 0xFFF)
        target = pc + 4 + disp * 2
        tname = FUNC_NAMES.get(target, "")
        extra = f"  [{tname}]" if tname else ""
        return f"bra    0x{target:05X}{extra}", 2

    if top4 == 0xB:
        disp = sign_extend_12(code & 0xFFF)
        target = pc + 4 + disp * 2
        tname = FUNC_NAMES.get(target, "")
        extra = f"  [{tname}]" if tname else ""
        return f"bsr    0x{target:05X}{extra}", 2

    if top4 == 0xC:
        sub = (code >> 8) & 0xF
        if sub == 0: return f"mov.b  r0,@({i},GBR)", 2
        if sub == 1: return f"mov.w  r0,@({i*2},GBR)", 2
        if sub == 2: return f"mov.l  r0,@({i*4},GBR)", 2
        if sub == 3: return f"trapa  #{i}", 2
        if sub == 4: return f"mov.b  @({i},GBR),r0", 2
        if sub == 5: return f"mov.w  @({i*2},GBR),r0", 2
        if sub == 6: return f"mov.l  @({i*4},GBR),r0", 2
        if sub == 7:
            disp = i
            target = (pc & ~3) + 4 + disp * 4
            if target + 4 <= len(rom):
                val = struct.unpack_from(">I", rom, target)[0]
                vname = FUNC_NAMES.get(val, RAM_NAMES.get(val, ""))
                extra = f" ({vname})" if vname else ""
                return f"mova   @(0x{target:05X}),r0  ; =0x{val:08X}{extra}", 2
            return f"mova   @(0x{target:05X}),r0", 2
        if sub == 8: return f"tst    #0x{i:02X},r0", 2
        if sub == 9: return f"and    #0x{i:02X},r0", 2
        if sub == 0xA: return f"xor    #0x{i:02X},r0", 2
        if sub == 0xB: return f"or     #0x{i:02X},r0", 2
        if sub == 0xC: return f"tst.b  #0x{i:02X},@(r0,GBR)", 2
        if sub == 0xD: return f"and.b  #0x{i:02X},@(r0,GBR)", 2
        if sub == 0xE: return f"xor.b  #0x{i:02X},@(r0,GBR)", 2
        if sub == 0xF: return f"or.b   #0x{i:02X},@(r0,GBR)", 2

    if top4 == 0xD:
        disp = code & 0xFF
        target = (pc & ~3) + 4 + disp * 4
        if target + 4 <= len(rom):
            val = struct.unpack_from(">I", rom, target)[0]
            vname = FUNC_NAMES.get(val, RAM_NAMES.get(val, ""))
            extra = f" ({vname})" if vname else ""
            return f"mov.l  @(0x{target:05X}),r{n}  ; =0x{val:08X}{extra}", 2
        return f"mov.l  @(0x{target:05X}),r{n}", 2

    if top4 == 0xE:
        imm = sign_extend_8(i)
        return f"mov    #{imm},r{n}", 2

    if top4 == 0xF:
        # FPU instructions
        sub = code & 0xF
        fpu_ops = {0:"fadd",1:"fsub",2:"fmul",3:"fdiv",4:"fcmp/eq",5:"fcmp/gt",
                   6:"fmov.s",7:"fmov.s",8:"fmov.s",9:"fmov.s",0xA:"fmov.s",
                   0xB:"fmov.s",0xC:"fmov",0xD:"??fpu",0xE:"fmac"}
        if sub <= 5:
            return f"{fpu_ops[sub]}  fr{m},fr{n}", 2
        if sub == 6: return f"fmov.s @(r0,r{m}),fr{n}", 2
        if sub == 7: return f"fmov.s fr{m},@(r0,r{n})", 2
        if sub == 8: return f"fmov.s @r{m},fr{n}", 2
        if sub == 9: return f"fmov.s @r{m}+,fr{n}", 2
        if sub == 0xA: return f"fmov.s fr{m},@r{n}", 2
        if sub == 0xB: return f"fmov.s fr{m},@-r{n}", 2
        if sub == 0xC: return f"fmov   fr{m},fr{n}", 2
        if (code & 0xF0FF) == 0xF02D: return f"float  FPUL,fr{n}", 2
        if (code & 0xF0FF) == 0xF03D: return f"ftrc   fr{n},FPUL", 2
        if (code & 0xF0FF) == 0xF04D: return f"fneg   fr{n}", 2
        if (code & 0xF0FF) == 0xF05D: return f"fabs   fr{n}", 2
        if (code & 0xF0FF) == 0xF08D: return f"fldi0  fr{n}", 2
        if (code & 0xF0FF) == 0xF09D: return f"fldi1  fr{n}", 2
        if (code & 0xF0FF) == 0xF00D: return f"fsts   FPUL,fr{n}", 2
        if (code & 0xF0FF) == 0xF01D: return f"flds   fr{n},FPUL", 2
        if (code & 0xF0FF) == 0xF06D: return f"fsqrt  fr{n}", 2
        return f"??fpu    ; 0x{code:04X}", 2

    return f"??       ; 0x{code:04X}", 2


def disasm_range(rom, start, end, title=""):
    """Disassemble a range of ROM and annotate ADC accesses."""
    if title:
        print(f"\n{'='*80}")
        print(f"  {title}")
        print(f"{'='*80}")

    # Track register state for ADC base detection
    reg_vals = {}  # rN -> known value

    pc = start
    while pc < end:
        code = struct.unpack_from(">H", rom, pc)[0]
        mnem, size = decode_insn(code, pc, rom)

        # Track register values
        n = (code >> 8) & 0xF
        top4 = (code >> 12) & 0xF

        annotation = ""

        # mov #imm, Rn
        if top4 == 0xE:
            imm = sign_extend_8(code & 0xFF)
            reg_vals[n] = imm & 0xFFFFFFFF

        # shll8 Rn
        elif code & 0xF0FF == 0x4018:
            rn = (code >> 8) & 0xF
            if rn in reg_vals:
                reg_vals[rn] = (reg_vals[rn] << 8) & 0xFFFFFFFF
                if reg_vals[rn] == 0xFFFFF800:
                    annotation = " <<< ADC BASE (ADDR0)"
                elif 0xFFFFF700 <= reg_vals[rn] <= 0xFFFFF860:
                    regname = ADC_CHAN_MAP.get(reg_vals[rn] - 0xFFFFF800, f"0x{reg_vals[rn]:08X}")
                    annotation = f" <<< PERIPH: {regname}"

        # add #imm, Rn - adjust tracked value
        elif top4 == 0x7:
            rn = (code >> 8) & 0xF
            imm = sign_extend_8(code & 0xFF)
            if rn in reg_vals:
                reg_vals[rn] = (reg_vals[rn] + imm) & 0xFFFFFFFF

        # mov.b/w @(r0,Rm), Rn or mov.b/w @Rm, Rn - if Rm is ADC base, annotate channel
        elif top4 == 0x6:
            sub = code & 0xF
            rm = (code >> 4) & 0xF
            if sub in (0, 1, 2) and rm in reg_vals:
                base = reg_vals[rm]
                if 0xFFFFF800 <= base <= 0xFFFFF860:
                    offset = base - 0xFFFFF800
                    ch_name = ADC_CHAN_MAP.get(offset, f"offset_{offset:02X}")
                    annotation = f" <<< READ {ch_name}"

        # mov.b @(disp, Rm), R0 - if Rm has ADC base
        elif top4 == 0x8:
            sub = (code >> 8) & 0xF
            if sub == 4:  # mov.b @(d,Rm),R0
                rm = (code >> 4) & 0xF
                disp = code & 0xF
                if rm in reg_vals:
                    effective = reg_vals[rm] + disp
                    if 0xFFFFF800 <= effective <= 0xFFFFF860:
                        offset = effective - 0xFFFFF800
                        ch_name = ADC_CHAN_MAP.get(offset, f"offset_{offset:02X}")
                        annotation = f" <<< READ {ch_name}"
            elif sub == 5:  # mov.w @(d*2,Rm),R0
                rm = (code >> 4) & 0xF
                disp = code & 0xF
                if rm in reg_vals:
                    effective = reg_vals[rm] + disp * 2
                    if 0xFFFFF800 <= effective <= 0xFFFFF860:
                        offset = effective - 0xFFFFF800
                        ch_name = ADC_CHAN_MAP.get(offset, f"offset_{offset:02X}")
                        annotation = f" <<< READ {ch_name}"

        # mov.w/b R0, @(disp, Rm) - write to ADC control reg?
        elif top4 == 0x8:
            sub = (code >> 8) & 0xF
            if sub in (0, 1):  # mov.b/w r0, @(d, Rm)
                rm = (code >> 4) & 0xF
                disp = code & 0xF
                sz = 1 if sub == 0 else 2
                if rm in reg_vals:
                    effective = reg_vals[rm] + disp * sz
                    if 0xFFFFF800 <= effective <= 0xFFFFF860:
                        offset = effective - 0xFFFFF800
                        ch_name = ADC_CHAN_MAP.get(offset, f"offset_{offset:02X}")
                        annotation = f" <<< WRITE {ch_name}"

        # mov.l @(disp,PC),Rn -> track literal pool loads
        elif top4 == 0xD:
            disp = code & 0xFF
            lit_addr = (pc & ~3) + 4 + disp * 4
            if lit_addr + 4 <= len(rom):
                val = struct.unpack_from(">I", rom, lit_addr)[0]
                reg_vals[n] = val

        # mov.w @(disp,PC),Rn -> track word literal loads
        elif top4 == 0x9:
            disp = code & 0xFF
            lit_addr = pc + 4 + disp * 2
            if lit_addr + 2 <= len(rom):
                val = struct.unpack_from(">H", rom, lit_addr)[0]
                reg_vals[n] = val

        # On branch/call, don't clear state (might be useful for context)

        print(f"  {pc:05X}:  {code:04X}  {mnem}{annotation}")
        pc += size


def main():
    with open(ROM_PATH, "rb") as f:
        rom = f.read()

    print(f"ROM: {len(rom)} bytes")
    print(f"\nADC Register Base: 0xFFFFF800 (ADDR0)")
    print(f"Identified ADC access locations:")
    print(f"  0x04178, 0x0437C, 0x04392, 0x043A8, 0x043BA")

    # Disassemble around each ADC access point with generous context
    # These are all in the knock detection area

    # First access: 0x04178 - before knock_wrapper (0x43750)
    disasm_range(rom, 0x04140, 0x041E0,
        "ADC ACCESS #1: 0x04178 (pre-knock area)")

    # Accesses 2-5: 0x0437C, 0x04392, 0x043A8, 0x043BA - in/near knock_detector
    disasm_range(rom, 0x04360, 0x04420,
        "ADC ACCESSES #2-5: 0x0437C-0x043BA (knock_detector area)")

    # Also check what function contains 0x04178
    # Look for the function entry by scanning backward for push/prolog patterns
    print(f"\n{'='*80}")
    print(f"  SEARCHING FOR FUNCTION CONTAINING 0x04178")
    print(f"{'='*80}")

    # Scan backward from 0x04178 for common function prologs
    for addr in range(0x04178, 0x04100, -2):
        code = struct.unpack_from(">H", rom, addr)[0]
        # sts.l pr, @-r15 (0x4F22) is a common prolog
        if code == 0x4F22:
            # Check if previous instruction is also a push (mov.l rN, @-r15 = 0x2FN6)
            prev = struct.unpack_from(">H", rom, addr - 2)[0]
            if (prev & 0xF00F) == 0x2F06:
                print(f"  Likely function start at 0x{addr-2:05X}")
                break
            else:
                print(f"  Possible function start at 0x{addr:05X} (sts.l pr,@-r15)")
                break

    # Also look for VBR setup in reset code (how peripheral interrupts are vectored)
    print(f"\n{'='*80}")
    print(f"  RESET CODE: VBR SETUP (0x0C0C-0x0D40)")
    print(f"{'='*80}")
    disasm_range(rom, 0x0C0C, 0x0D40,
        "")

    # Scan for 'ldc Rn, VBR' (0x4n2E) anywhere in ROM
    print(f"\n{'='*80}")
    print(f"  ALL 'ldc Rn,VBR' INSTRUCTIONS IN ROM")
    print(f"{'='*80}")
    for pc in range(0, len(rom) - 2, 2):
        code = struct.unpack_from(">H", rom, pc)[0]
        if (code & 0xF0FF) == 0x402E:
            rn = (code >> 8) & 0xF
            print(f"  0x{pc:05X}: ldc r{rn},VBR")
            # Show context
            if pc >= 4:
                for ctx_pc in range(max(0, pc-8), min(len(rom)-2, pc+8), 2):
                    c = struct.unpack_from(">H", rom, ctx_pc)[0]
                    m, _ = decode_insn(c, ctx_pc, rom)
                    marker = " <<<" if ctx_pc == pc else ""
                    print(f"    {ctx_pc:05X}: {c:04X}  {m}{marker}")


if __name__ == "__main__":
    main()
