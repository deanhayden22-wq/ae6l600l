import struct
import sys

class SH2Disassembler:
    def __init__(self, rom_data, base_addr=0):
        self.rom = rom_data
        self.base = base_addr

    def read_word(self, addr):
        off = addr - self.base
        if 0 <= off < len(self.rom) - 1:
            return struct.unpack('>H', self.rom[off:off+2])[0]
        return None

    def read_long(self, addr):
        off = addr - self.base
        if 0 <= off < len(self.rom) - 3:
            return struct.unpack('>I', self.rom[off:off+4])[0]
        return None

    def read_float(self, addr):
        off = addr - self.base
        if 0 <= off < len(self.rom) - 3:
            return struct.unpack('>f', self.rom[off:off+4])[0]
        return None

    def resolve_pc_long(self, addr, disp8):
        """Resolve mov.l @(disp,PC),Rn target address"""
        return (addr & 0xFFFFFFFC) + 4 + disp8 * 4

    def resolve_pc_word(self, addr, disp8):
        """Resolve mov.w @(disp,PC),Rn target address"""
        return addr + 4 + disp8 * 2

    def decode(self, addr):
        w = self.read_word(addr)
        if w is None:
            return None, "???"

        op = w
        hi4 = (op >> 12) & 0xF
        nn = (op >> 8) & 0xF
        mm = (op >> 4) & 0xF
        lo4 = op & 0xF
        lo8 = op & 0xFF

        # === 0000 ====
        if op == 0x0009:
            return w, "nop"
        if op == 0x000B:
            return w, "rts"
        if op == 0x0008:
            return w, "clrt"
        if op == 0x0018:
            return w, "sett"
        if op == 0x0028:
            return w, "clrmac"
        if op == 0x001B:
            return w, "sleep"
        if op == 0x002B:
            return w, "rte"

        if hi4 == 0 and lo4 == 2:
            src_map = {0: "SR", 1: "GBR", 2: "VBR"}
            src = src_map.get(mm, "CR%d" % mm)
            return w, "stc %s,R%d" % (src, nn)

        if hi4 == 0 and lo4 == 3:
            if mm == 0:
                return w, "bsrf R%d" % nn
            if mm == 2:
                return w, "braf R%d" % nn
            return w, "mov R%d,R%d" % (mm, nn)

        if hi4 == 0 and lo4 == 4:
            return w, "mov.b R%d,@(R0,R%d)" % (mm, nn)
        if hi4 == 0 and lo4 == 5:
            return w, "mov.w R%d,@(R0,R%d)" % (mm, nn)
        if hi4 == 0 and lo4 == 6:
            return w, "mov.l R%d,@(R0,R%d)" % (mm, nn)
        if hi4 == 0 and lo4 == 7:
            return w, "mul.l R%d,R%d" % (mm, nn)

        if hi4 == 0 and lo4 == 0xC:
            return w, "mov.b @(R0,R%d),R%d" % (mm, nn)
        if hi4 == 0 and lo4 == 0xD:
            return w, "mov.w @(R0,R%d),R%d" % (mm, nn)
        if hi4 == 0 and lo4 == 0xE:
            return w, "mov.l @(R0,R%d),R%d" % (mm, nn)

        if hi4 == 0 and lo4 == 0xA:
            src_map = {0: "MACH", 1: "MACL", 2: "PR"}
            src = src_map.get(mm, "SR%d" % mm)
            return w, "sts %s,R%d" % (src, nn)

        if hi4 == 0 and lo4 == 0xB:
            # not standard
            pass

        # === 0001: mov.l Rm,@(disp,Rn) ===
        if hi4 == 1:
            disp = lo8 * 4
            return w, "mov.l R%d,@(%d,R%d)" % (mm, disp, nn)

        # === 0010 ===
        if hi4 == 2:
            ops2 = {
                0: "mov.b R%d,@R%d" % (mm, nn),
                1: "mov.w R%d,@R%d" % (mm, nn),
                2: "mov.l R%d,@R%d" % (mm, nn),
                4: "mov.b R%d,@-R%d" % (mm, nn),
                5: "mov.w R%d,@-R%d" % (mm, nn),
                6: "mov.l R%d,@-R%d" % (mm, nn),
                7: "div0s R%d,R%d" % (mm, nn),
                8: "tst R%d,R%d" % (mm, nn),
                9: "and R%d,R%d" % (mm, nn),
                0xA: "xor R%d,R%d" % (mm, nn),
                0xB: "or R%d,R%d" % (mm, nn),
                0xC: "cmp/str R%d,R%d" % (mm, nn),
                0xD: "xtrct R%d,R%d" % (mm, nn),
                0xE: "mulu.w R%d,R%d" % (mm, nn),
                0xF: "muls.w R%d,R%d" % (mm, nn),
            }
            if lo4 in ops2:
                return w, ops2[lo4]

        # === 0011 ===
        if hi4 == 3:
            ops3 = {
                0: "cmp/eq R%d,R%d" % (mm, nn),
                2: "cmp/hs R%d,R%d" % (mm, nn),
                3: "cmp/ge R%d,R%d" % (mm, nn),
                4: "div1 R%d,R%d" % (mm, nn),
                5: "dmulu.l R%d,R%d" % (mm, nn),
                6: "cmp/hi R%d,R%d" % (mm, nn),
                7: "cmp/gt R%d,R%d" % (mm, nn),
                8: "sub R%d,R%d" % (mm, nn),
                0xA: "subc R%d,R%d" % (mm, nn),
                0xB: "subv R%d,R%d" % (mm, nn),
                0xC: "add R%d,R%d" % (mm, nn),
                0xD: "dmuls.l R%d,R%d" % (mm, nn),
                0xE: "addc R%d,R%d" % (mm, nn),
                0xF: "addv R%d,R%d" % (mm, nn),
            }
            if lo4 in ops3:
                return w, ops3[lo4]

        # === 0100 ===
        if hi4 == 4:
            if lo8 == 0x00: return w, "shll R%d" % nn
            if lo8 == 0x01: return w, "shlr R%d" % nn
            if lo8 == 0x02: return w, "sts.l MACH,@-R%d" % nn
            if lo8 == 0x04: return w, "rotl R%d" % nn
            if lo8 == 0x05: return w, "rotr R%d" % nn
            if lo8 == 0x06: return w, "lds.l @R%d+,MACH" % nn
            if lo8 == 0x08: return w, "shll2 R%d" % nn
            if lo8 == 0x09: return w, "shlr2 R%d" % nn
            if lo8 == 0x0A: return w, "lds R%d,MACH" % nn
            if lo8 == 0x0B: return w, "jsr @R%d" % nn
            if lo8 == 0x0E: return w, "ldc R%d,SR" % nn
            if lo8 == 0x10: return w, "dt R%d" % nn
            if lo8 == 0x11: return w, "cmp/pz R%d" % nn
            if lo8 == 0x12: return w, "sts.l MACL,@-R%d" % nn
            if lo8 == 0x13: return w, "stc.l GBR,@-R%d" % nn
            if lo8 == 0x15: return w, "cmp/pl R%d" % nn
            if lo8 == 0x16: return w, "lds.l @R%d+,MACL" % nn
            if lo8 == 0x17: return w, "ldc.l @R%d+,GBR" % nn
            if lo8 == 0x18: return w, "shll8 R%d" % nn
            if lo8 == 0x19: return w, "shlr8 R%d" % nn
            if lo8 == 0x1A: return w, "lds R%d,MACL" % nn
            if lo8 == 0x1B: return w, "tas.b @R%d" % nn
            if lo8 == 0x1E: return w, "ldc R%d,GBR" % nn
            if lo8 == 0x20: return w, "shal R%d" % nn
            if lo8 == 0x21: return w, "shar R%d" % nn
            if lo8 == 0x22: return w, "sts.l PR,@-R%d" % nn
            if lo8 == 0x23: return w, "stc.l VBR,@-R%d" % nn
            if lo8 == 0x24: return w, "rotcl R%d" % nn
            if lo8 == 0x25: return w, "rotcr R%d" % nn
            if lo8 == 0x26: return w, "lds.l @R%d+,PR" % nn
            if lo8 == 0x27: return w, "ldc.l @R%d+,VBR" % nn
            if lo8 == 0x28: return w, "shll16 R%d" % nn
            if lo8 == 0x29: return w, "shlr16 R%d" % nn
            if lo8 == 0x2A: return w, "lds R%d,PR" % nn
            if lo8 == 0x2B: return w, "jmp @R%d" % nn
            if lo8 == 0x2E: return w, "ldc R%d,VBR" % nn
            if lo8 == 0x5A: return w, "lds R%d,FPUL" % nn
            if lo8 == 0x56: return w, "lds.l @R%d+,FPUL" % nn
            if lo8 == 0x52: return w, "sts.l FPUL,@-R%d" % nn
            if lo8 == 0x6A: return w, "lds R%d,FPSCR" % nn
            if lo8 == 0x66: return w, "lds.l @R%d+,FPSCR" % nn
            if lo8 == 0x62: return w, "sts.l FPSCR,@-R%d" % nn

        # === 0101: mov.l @(disp,Rm),Rn ===
        if hi4 == 5:
            disp = lo8 * 4
            return w, "mov.l @(%d,R%d),R%d" % (disp, mm, nn)

        # === 0110 ===
        if hi4 == 6:
            ops6 = {
                0: "mov.b @R%d,R%d" % (mm, nn),
                1: "mov.w @R%d,R%d" % (mm, nn),
                2: "mov.l @R%d,R%d" % (mm, nn),
                3: "mov R%d,R%d" % (mm, nn),
                4: "mov.b @R%d+,R%d" % (mm, nn),
                5: "mov.w @R%d+,R%d" % (mm, nn),
                6: "mov.l @R%d+,R%d" % (mm, nn),
                7: "not R%d,R%d" % (mm, nn),
                8: "swap.b R%d,R%d" % (mm, nn),
                9: "swap.w R%d,R%d" % (mm, nn),
                0xA: "negc R%d,R%d" % (mm, nn),
                0xB: "neg R%d,R%d" % (mm, nn),
                0xC: "extu.b R%d,R%d" % (mm, nn),
                0xD: "extu.w R%d,R%d" % (mm, nn),
                0xE: "exts.b R%d,R%d" % (mm, nn),
                0xF: "exts.w R%d,R%d" % (mm, nn),
            }
            if lo4 in ops6:
                return w, ops6[lo4]

        # === 0111: add #imm,Rn ===
        if hi4 == 7:
            imm = lo8
            if imm >= 0x80:
                imm = imm - 256
            return w, "add #%d,R%d" % (imm, nn)

        # === 1000 ===
        if hi4 == 8:
            sub = nn
            if sub == 0:
                rm = mm
                disp = lo4
                return w, "mov.b R0,@(%d,R%d)" % (disp, rm)
            if sub == 1:
                rm = mm
                disp = lo4 * 2
                return w, "mov.w R0,@(%d,R%d)" % (disp, rm)
            if sub == 4:
                rm = mm
                disp = lo4
                return w, "mov.b @(%d,R%d),R0" % (disp, rm)
            if sub == 5:
                rm = mm
                disp = lo4 * 2
                return w, "mov.w @(%d,R%d),R0" % (disp, rm)
            if sub == 8:
                imm = lo8
                if imm >= 0x80:
                    imm = imm - 256
                return w, "cmp/eq #%d,R0" % imm
            if sub == 9:
                disp = lo8
                if disp >= 0x80:
                    disp = disp - 256
                target = addr + 4 + disp * 2
                return w, "bt 0x%06X" % target
            if sub == 0xB:
                disp = lo8
                if disp >= 0x80:
                    disp = disp - 256
                target = addr + 4 + disp * 2
                return w, "bf 0x%06X" % target
            if sub == 0xD:
                disp = lo8
                if disp >= 0x80:
                    disp = disp - 256
                target = addr + 4 + disp * 2
                return w, "bt/s 0x%06X" % target
            if sub == 0xF:
                disp = lo8
                if disp >= 0x80:
                    disp = disp - 256
                target = addr + 4 + disp * 2
                return w, "bf/s 0x%06X" % target

        # === 1001: mov.w @(disp,PC),Rn ===
        if hi4 == 9:
            disp = lo8
            target = addr + 4 + disp * 2
            val = self.read_word(target)
            comment = ""
            if val is not None:
                sval = val if val < 0x8000 else val - 0x10000
                comment = "  ; =%d (0x%04X)" % (sval, val)
            return w, "mov.w @(0x%06X),R%d%s" % (target, nn, comment)

        # === 1010: bra ===
        if hi4 == 0xA:
            disp = op & 0xFFF
            if disp >= 0x800:
                disp = disp - 0x1000
            target = addr + 4 + disp * 2
            return w, "bra 0x%06X" % target

        # === 1011: bsr ===
        if hi4 == 0xB:
            disp = op & 0xFFF
            if disp >= 0x800:
                disp = disp - 0x1000
            target = addr + 4 + disp * 2
            return w, "bsr 0x%06X" % target

        # === 1100: GBR-relative and misc ===
        if hi4 == 0xC:
            sub = nn
            if sub == 0:
                return w, "mov.b R0,@(%d,GBR)" % lo8
            if sub == 1:
                disp = lo8 * 2
                return w, "mov.w R0,@(%d,GBR)" % disp
            if sub == 2:
                disp = lo8 * 4
                return w, "mov.l R0,@(%d,GBR)" % disp
            if sub == 3:
                return w, "trapa #%d" % lo8
            if sub == 4:
                return w, "mov.b @(%d,GBR),R0" % lo8
            if sub == 5:
                disp = lo8 * 2
                return w, "mov.w @(%d,GBR),R0" % disp
            if sub == 6:
                disp = lo8 * 4
                return w, "mov.l @(%d,GBR),R0" % disp
            if sub == 7:
                disp = lo8 * 4
                target = (addr & 0xFFFFFFFC) + 4 + disp
                return w, "mova @(0x%06X),R0" % target
            if sub == 8:
                return w, "tst #%d,R0" % lo8
            if sub == 9:
                return w, "and #%d,R0" % lo8
            if sub == 0xA:
                return w, "xor #%d,R0" % lo8
            if sub == 0xB:
                return w, "or #%d,R0" % lo8
            if sub == 0xC:
                return w, "tst.b #%d,@(R0,GBR)" % lo8
            if sub == 0xD:
                return w, "and.b #%d,@(R0,GBR)" % lo8
            if sub == 0xE:
                return w, "xor.b #%d,@(R0,GBR)" % lo8
            if sub == 0xF:
                return w, "or.b #%d,@(R0,GBR)" % lo8

        # === 1101: mov.l @(disp,PC),Rn ===
        if hi4 == 0xD:
            disp = lo8
            target = (addr & 0xFFFFFFFC) + 4 + disp * 4
            val = self.read_long(target)
            comment = ""
            if val is not None:
                if 0xFFFF0000 <= val <= 0xFFFFFFFF:
                    comment = "  ; =0x%08X (RAM)" % val
                elif 0x000A0000 <= val <= 0x000FFFFF:
                    comment = "  ; =0x%08X (CAL)" % val
                elif 0x00000000 < val < 0x00100000:
                    comment = "  ; =0x%08X (ROM)" % val
                else:
                    fval = self.read_float(target)
                    comment = "  ; =0x%08X (float: %g)" % (val, fval)
                    if abs(fval) < 1e-30 or abs(fval) > 1e30:
                        comment = "  ; =0x%08X" % val
            return w, "mov.l @(0x%06X),R%d%s" % (target, nn, comment)

        # === 1110: mov #imm,Rn ===
        if hi4 == 0xE:
            imm = lo8
            if imm >= 0x80:
                imm = imm - 256
            return w, "mov #%d,R%d" % (imm, nn)

        # === 1111: FPU ===
        if hi4 == 0xF:
            fn = nn
            fm = mm

            if lo4 == 0x0: return w, "fadd FR%d,FR%d" % (fm, fn)
            if lo4 == 0x1: return w, "fsub FR%d,FR%d" % (fm, fn)
            if lo4 == 0x2: return w, "fmul FR%d,FR%d" % (fm, fn)
            if lo4 == 0x3: return w, "fdiv FR%d,FR%d" % (fm, fn)
            if lo4 == 0x4: return w, "fcmp/eq FR%d,FR%d" % (fm, fn)
            if lo4 == 0x5: return w, "fcmp/gt FR%d,FR%d" % (fm, fn)
            if lo4 == 0x6: return w, "fmov.s @(R0,R%d),FR%d" % (fm, fn)
            if lo4 == 0x7: return w, "fmov.s FR%d,@(R0,R%d)" % (fm, fn)
            if lo4 == 0x8: return w, "fmov.s @R%d,FR%d" % (fm, fn)
            if lo4 == 0x9: return w, "fmov.s @R%d+,FR%d" % (fm, fn)
            if lo4 == 0xA: return w, "fmov.s FR%d,@R%d" % (fm, fn)
            if lo4 == 0xB: return w, "fmov.s FR%d,@-R%d" % (fm, fn)
            if lo4 == 0xC: return w, "fmov FR%d,FR%d" % (fm, fn)
            if lo4 == 0xD:
                if fm == 0x8: return w, "fldi0 FR%d" % fn
                if fm == 0x9: return w, "fldi1 FR%d" % fn
                if fm == 0x2: return w, "float FPUL,FR%d" % fn
                if fm == 0x3: return w, "ftrc FR%d,FPUL" % fn
                if fm == 0x0: return w, "fsts FPUL,FR%d" % fn
                if fm == 0x1: return w, "flds FR%d,FPUL" % fn
                if fm == 0x4: return w, "fneg FR%d" % fn
                if fm == 0x5: return w, "fabs FR%d" % fn
                if fm == 0x6: return w, "fsqrt FR%d" % fn
                return w, ".word 0x%04X  ; fpu special" % op
            if lo4 == 0xE: return w, "fmac FR0,FR%d,FR%d" % (fm, fn)

        return w, ".word 0x%04X" % op

    def disassemble_function(self, start, end):
        lines = []
        addr = start
        while addr < end:
            w, mnemonic = self.decode(addr)
            if w is None:
                break
            lines.append("  0x%06X:  %04X    %s" % (addr, w, mnemonic))
            addr += 2
        return "\n".join(lines)


def annotate_gbr(gbr_base, disp, size):
    """Given GBR base and displacement, return the RAM address"""
    return gbr_base + disp


def main():
    rom_path = sys.argv[1]
    start = int(sys.argv[2], 16)
    end = int(sys.argv[3], 16)

    with open(rom_path, "rb") as f:
        rom_data = f.read()

    dis = SH2Disassembler(rom_data, base_addr=0)

    print("=" * 78)
    print("  SH2 Disassembly: 0x%06X - 0x%06X" % (start, end))
    print("=" * 78)
    print(dis.disassemble_function(start, end))

    # Also dump literal pool area after code
    if len(sys.argv) > 4:
        lp_start = int(sys.argv[4], 16)
        lp_end = int(sys.argv[5], 16) if len(sys.argv) > 5 else lp_start + 0x80
        print()
        print("  --- Literal Pool (0x%06X - 0x%06X) ---" % (lp_start, lp_end))
        laddr = lp_start
        while laddr < lp_end:
            val = dis.read_long(laddr)
            if val is None:
                break
            fval = dis.read_float(laddr)
            if 0xFFFF0000 <= val <= 0xFFFFFFFF:
                print("  0x%06X:  %08X  -> RAM 0x%08X" % (laddr, val, val))
            elif 0x000A0000 <= val <= 0x000FFFFF:
                print("  0x%06X:  %08X  -> CAL @0x%06X" % (laddr, val, val))
            elif 0x00000000 < val < 0x00100000:
                print("  0x%06X:  %08X  -> ROM @0x%06X" % (laddr, val, val))
            else:
                print("  0x%06X:  %08X  (float: %g)" % (laddr, val, fval))
            laddr += 4


if __name__ == "__main__":
    main()
