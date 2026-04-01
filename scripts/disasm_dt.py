"""Disassemble injector dead time pipeline functions."""
import struct

ROM_PATH = "disassembly/ghidra/AE5L600L Ghidra Export.bytes"
with open(ROM_PATH, "rb") as f:
    rom = f.read()

def r16(a): return struct.unpack_from(">H", rom, a)[0]
def r32(a): return struct.unpack_from(">I", rom, a)[0]
def rf32(a): return struct.unpack_from(">f", rom, a)[0]

def disasm(start, length=120, label=""):
    if label:
        print(f"\n=== {label} @ 0x{start:06X} ===")
    pc = start
    end = start + length
    rts_seen = 0
    while pc < end:
        op = r16(pc)
        hi4 = (op >> 12) & 0xF
        n = (op >> 8) & 0xF
        m = (op >> 4) & 0xF
        d8 = op & 0xFF
        d4 = op & 0xF
        out = f"  {pc:06X}: {op:04X}  "
        is_rts = False

        if op == 0x000B:
            out += "RTS"
            is_rts = True
        elif op == 0x0009:
            out += "NOP"
        elif op == 0x002B:
            out += "RTE"
        elif op == 0x0028:
            out += "CLRMAC"
        elif hi4 == 0xE:
            v = d8 if d8 < 128 else d8 - 256
            out += f"MOV #{v},R{n}"
        elif hi4 == 0x7:
            v = d8 if d8 < 128 else d8 - 256
            out += f"ADD #{v},R{n}"
        elif hi4 == 0x9:
            tgt = pc + 4 + d8 * 2
            out += f"MOV.W @(+{d8*2},PC),R{n}  [{tgt:06X}]={r16(tgt):04X}"
        elif hi4 == 0xD:
            tgt = (pc + 4 + d8 * 4) & ~3
            val = r32(tgt)
            fval = ""
            if 0xFFFF0000 <= val <= 0xFFFFFFFF or 0x00000000 <= val <= 0x00FFFFFF:
                try:
                    fval = f" (={rf32(tgt):.4f})"
                except:
                    pass
            out += f"MOV.L @(+{d8*4},PC),R{n}  [{tgt:06X}]={val:08X}{fval}"
        elif hi4 == 0x6:
            sub = op & 0xF
            ops6 = {0: "MOV.B @R%m,R%n", 1: "MOV.W @R%m,R%n", 2: "MOV.L @R%m,R%n",
                    3: "MOV.L @R%m+,R%n",
                    0xC: "EXTU.B R%m,R%n", 0xD: "EXTU.W R%m,R%n",
                    0xE: "EXTS.B R%m,R%n", 0xF: "EXTS.W R%m,R%n"}
            out += ops6.get(sub, f"6{sub:X}_{op:04X}").replace("%m", str(m)).replace("%n", str(n))
        elif hi4 == 0x2:
            sub = op & 0xF
            ops2 = {0: "MOV.B R%n,@R%m", 1: "MOV.W R%n,@R%m", 2: "MOV.L R%n,@R%m",
                    4: "MOV.B R%n,@-R%m", 5: "MOV.W R%n,@-R%m", 6: "MOV.L R%n,@-R%m",
                    8: "TST R%m,R%n", 9: "AND R%m,R%n", 0xA: "XOR R%m,R%n", 0xB: "OR R%m,R%n",
                    0xE: "MULU.W R%m,R%n", 0xF: "MULS.W R%m,R%n"}
            out += ops2.get(sub, f"2_{op:04X}").replace("%m", str(m)).replace("%n", str(n))
        elif hi4 == 0x3:
            sub = op & 0xF
            ops3 = {0: "CMP/EQ", 2: "CMP/HS", 3: "CMP/GE", 4: "DIV1", 5: "DMULU.L",
                    6: "CMP/HI", 7: "CMP/GT", 8: "SUB", 0xA: "SUBC",
                    0xC: "ADD", 0xD: "DMULS.L", 0xE: "ADDC", 0xF: "ADDV"}
            out += f"{ops3.get(sub, f'3{sub:X}')} R{m},R{n}"
        elif hi4 == 0x4:
            sub = op & 0xFF
            if sub == 0x22:   out += f"STS.L PR,@-R{n}"
            elif sub == 0x26: out += f"LDS.L @R{n}+,PR"
            elif sub == 0x0A: out += f"LDS R{n},PR"
            elif sub == 0x0B: out += f"JSR @R{n}"
            elif sub == 0x2B: out += f"JMP @R{n}"
            elif sub == 0x10: out += f"DT R{n}"
            elif sub == 0x00: out += f"SHLL R{n}"
            elif sub == 0x01: out += f"SHLR R{n}"
            elif sub == 0x08: out += f"SHLL2 R{n}"
            elif sub == 0x09: out += f"SHLR2 R{n}"
            elif sub == 0x18: out += f"SHLL8 R{n}"
            elif sub == 0x19: out += f"SHLR8 R{n}"
            elif sub == 0x28: out += f"SHLL16 R{n}"
            elif sub == 0x29: out += f"SHLR16 R{n}"
            elif sub == 0x15: out += f"CMP/PL R{n}"
            elif sub == 0x11: out += f"CMP/PZ R{n}"
            elif sub == 0x20: out += f"SHAL R{n}"
            elif sub == 0x21: out += f"SHAR R{n}"
            elif sub == 0x06: out += f"LDS.L @R{n}+,MACH"
            elif sub == 0x16: out += f"LDS.L @R{n}+,MACL"
            elif sub == 0x0E: out += f"LDC R{n},SR"
            elif sub == 0x03: out += f"STC SR,R{n}"
            else: out += f"4_{sub:02X} R{n}"
        elif hi4 == 0x5:
            out += f"MOV.L @({d4*4},R{m}),R{n}"
        elif hi4 == 0x1:
            out += f"MOV.L R{n},@({d4*4},R{m})"
        elif hi4 == 0xA:
            d12 = op & 0xFFF
            if d12 & 0x800:
                d12 |= 0xFFFFF000
            tgt = pc + 4 + d12 * 2
            out += f"BRA 0x{tgt:06X}"
        elif hi4 == 0xB:
            d12 = op & 0xFFF
            if d12 & 0x800:
                d12 |= 0xFFFFF000
            tgt = pc + 4 + d12 * 2
            out += f"BSR 0x{tgt:06X}"
        elif hi4 == 0x8:
            sub2 = (op >> 8) & 0xF
            v = d8 if d8 < 128 else d8 - 256
            tgt = pc + 4 + v * 2
            if sub2 == 9:    out += f"BT 0x{tgt:06X}"
            elif sub2 == 0xD: out += f"BT/S 0x{tgt:06X}"
            elif sub2 == 0xB: out += f"BF 0x{tgt:06X}"
            elif sub2 == 0xF: out += f"BF/S 0x{tgt:06X}"
            elif sub2 == 0:   out += f"MOV.B R0,@({d4},R{m})"
            elif sub2 == 1:   out += f"MOV.W R0,@({d4*2},R{m})"
            elif sub2 == 4:   out += f"MOV.B @({d4},R{m}),R0"
            elif sub2 == 5:   out += f"MOV.W @({d4*2},R{m}),R0"
            else: out += f"8{sub2:X}_{op:04X}"
        elif hi4 == 0xC:
            sub2 = (op >> 8) & 0xF
            if sub2 == 7:
                r0 = (pc + 4 + d8 * 4) & ~3
                out += f"MOVA @(+{d8*4},PC),R0  R0=0x{r0:06X}"
            elif sub2 == 8:  out += f"TST #{d8},R0"
            elif sub2 == 9:  out += f"AND #{d8},R0"
            elif sub2 == 0xA: out += f"XOR #{d8},R0"
            elif sub2 == 0xB: out += f"OR #{d8},R0"
            elif sub2 == 3:  out += f"TRAPA #{d8}"
            else: out += f"C{sub2:X}_{op:04X}"
        elif hi4 == 0xF:
            sub = op & 0xF
            fn = (op >> 8) & 0xF
            fm = (op >> 4) & 0xF
            if sub == 0:    out += f"FADD FR{fm},FR{fn}"
            elif sub == 1:  out += f"FSUB FR{fm},FR{fn}"
            elif sub == 2:  out += f"FMUL FR{fm},FR{fn}"
            elif sub == 3:  out += f"FDIV FR{fm},FR{fn}"
            elif sub == 4:  out += f"FCMP/EQ FR{fm},FR{fn}"
            elif sub == 5:  out += f"FCMP/GT FR{fm},FR{fn}"
            elif sub == 8:  out += f"FMOV @R{fm},FR{fn}"
            elif sub == 9:  out += f"FMOV @R{fm}+,FR{fn}"
            elif sub == 0xA: out += f"FMOV FR{fn},@R{fm}"
            elif sub == 0xB: out += f"FMOV FR{fn},@-R{fm}"
            elif sub == 0xC: out += f"FMOV @(R0,R{fm}),FR{fn}"
            elif sub == 6:  out += f"FMOV @(R0,R{fm}),FR{fn}"
            elif sub == 7:  out += f"FMOV FR{fn},@(R0,R{fm})"
            elif sub == 0xD:
                if fm == 0xA:   out += f"FSTS FPUL,FR{fn}"
                elif fm == 0xB: out += f"FLDS FR{fn},FPUL"
                elif fm == 0xE: out += f"FTRC FR{fn},FPUL"
                elif fm == 0xC: out += f"FLOAT FPUL,FR{fn}"
                else: out += f"F{fm:X}D FR{fn}"
            elif sub == 0xE:
                if fm == 0xC:   out += f"FLOAT FPUL,FR{fn}"
                elif fm == 0xD: out += f"FNEG FR{fn}"
                elif fm == 0xE: out += f"FABS FR{fn}"
                elif fm == 0x8: out += f"FLDI0 FR{fn}"
                elif fm == 0x9: out += f"FLDI1 FR{fn}"
                elif fm == 0xA: out += f"FSQRT FR{fn}"
                else: out += f"FE{fm:X} FR{fn}"
            elif sub == 0xF:
                out += f"FF_{op:04X}"
            else: out += f"F{sub:X}_{op:04X}"
        elif hi4 == 0x0:
            sub = op & 0xFF
            if sub == 0x09:   out += "NOP"
            elif sub == 0x0B: out += "RTS"; is_rts = True
            elif sub == 0x2B: out += "RTE"
            elif sub == 0x23: out += f"BRAF R{n}"
            elif sub == 0x03: out += f"BSRF R{n}"
            elif (sub & 0xF) == 4: out += f"MOV.B R{m},@(R0,R{n})"
            elif (sub & 0xF) == 5: out += f"MOV.W R{m},@(R0,R{n})"
            elif (sub & 0xF) == 6: out += f"MOV.L R{m},@(R0,R{n})"
            elif (sub & 0xF) == 0xC: out += f"MOV.B @(R0,R{m}),R{n}"
            elif (sub & 0xF) == 0xD: out += f"MOV.W @(R0,R{m}),R{n}"
            elif (sub & 0xF) == 0xE: out += f"MOV.L @(R0,R{m}),R{n}"
            elif sub == 0x28: out += "CLRMAC"
            elif sub == 0x18: out += "SETT"
            elif sub == 0x08: out += "CLRT"
            elif sub == 0x19: out += "DIV0U"
            elif sub == 0x02: out += f"STC SR,R{n}"
            elif sub == 0x12: out += f"STC GBR,R{n}"
            elif sub == 0x22: out += f"STC VBR,R{n}"
            elif sub == 0x0A: out += f"STS MACH,R{n}"
            elif sub == 0x1A: out += f"STS MACL,R{n}"
            elif sub == 0x2A: out += f"STS PR,R{n}"
            else: out += f"0_{sub:02X} R{n}"
        else:
            out += f"???_{op:04X}"

        print(out)
        if is_rts:
            rts_seen += 1
            if rts_seen >= 1:
                # print slot instruction too
                slot_op = r16(pc + 2)
                print(f"  {pc+2:06X}: {slot_op:04X}  [delay slot]")
                break
        pc += 2


# --- Main pipeline functions ---
disasm(0x9E4A, 160, "func_9E4A (per-cyl DT entry, tail-called from 0x0303C2)")
disasm(0x9ED6, 160, "func_9ED6 (DT_APPLIED cluster)")
disasm(0xA0C8, 120, "func_A0C8 (DT cluster)")
disasm(0xA148, 120, "func_A148 (DT cluster)")
disasm(0x9B2C, 120, "func_9B2C (FP DT ops, reads DT_APPLIED)")
disasm(0x317C, 80,  "func_317C (called before tail-call to 9E4A)")
disasm(0x48732, 160, "ISR22 (reads FFFF4280, applies to ATU)")
