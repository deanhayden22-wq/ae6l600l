#!/usr/bin/env python3
"""Trace ISR22 (func_48732) body from 0x488CA onward.
Real body starts at 0x488CA after 'bra 0x488CA' at 0x48746.
"""
import struct, sys, os

ROM_PATH = None
for p in [
    r"rom/ae5l600l.bin",
    r"rom/AE5L600L 20g rev 20.5 tiny wrex.bin",
]:
    for base in [os.path.dirname(os.path.abspath(__file__)),
                 os.getcwd(),
                 r"C:\Users\DeanHayden\OneDrive - Vytal\Documents\GitHub\ae6l600l"]:
        fp = os.path.normpath(os.path.join(base, "..", "..", p))
        if os.path.isfile(fp): ROM_PATH = fp; break
        fp2 = os.path.normpath(os.path.join(base, p))
        if os.path.isfile(fp2): ROM_PATH = fp2; break
    if ROM_PATH: break

if not ROM_PATH:
    sys.exit("ERROR: ROM not found")

rom = open(ROM_PATH, 'rb').read()
print(f"ROM: {ROM_PATH} ({len(rom)} bytes)", flush=True)

KNOWN_LABELS = {
    0xFFFF4280: "injector_dead_time_applied",
    0xFFFF3D00: "cyl_desc_array",
    0xFFFF3D08: "cyl1_period",
    0xFFFF3D10: "cyl2_period",
    0xFFFF3D18: "cyl3_period",
    0xFFFF3D1C: "cyl4_period",
    0xFFFF895C: "inj_struct_895C",
    0xFFFF8964: "inj_struct_8964",
    0xFFFF76D4: "fuel_enrichment_A",
    0xFFFF7878: "fuel_enrichment_B",
    0xFFFF7AE4: "fuel_enrichment_C",
    0xFFFF76C8: "fuel_pw_final",
    0xFFFF76CC: "fuel_pw_cyl1",
    0xFFFF76D0: "fuel_pw_cyl2",
    0xBE960: "float_min",
    0xBE970: "rate_limit_interp",
}

KNOWN_SUBS = {
    0x3190: "injector_output",
    0x48732: "isr22_dead_time",
    0x82DE: "per_cyl_pulse_emit",
    0xBE960: "float_min",
    0xBE970: "rate_limit_interp",
    0x4760A: "pulse_lookup",
    0x30378: "injector_latency_user",
    0x3664: "mtu_write_gate",
    0x9E4A: "dead_time_store",
    0x304BE: "injdata_writer_A",
    0x37604: "injdata_writer_B",
}

def pool_val(addr, disp):
    pa = (addr & ~3) + 4 + disp * 4
    if pa + 4 <= len(rom):
        v = struct.unpack('>I', rom[pa:pa+4])[0]
        lbl = KNOWN_LABELS.get(v, '')
        return v, lbl
    return None, None

def pool_val_w(addr, disp):
    pa = (addr & ~1) + 4 + disp * 2
    if pa + 2 <= len(rom):
        v = struct.unpack('>H', rom[pa:pa+2])[0]
        return v
    return None

def fmt_addr(v):
    if v is None: return '???'
    lbl = KNOWN_LABELS.get(v, KNOWN_SUBS.get(v, ''))
    if lbl:
        return '0x%08X (%s)' % (v, lbl)
    return '0x%08X' % v

def disasm_range(start, end, max_insn=300):
    addr = start
    count = 0
    lines = []
    while addr < end and count < max_insn:
        if addr + 2 > len(rom): break
        w = struct.unpack('>H', rom[addr:addr+2])[0]
        n   = (w >> 8) & 0xF
        m   = (w >> 4) & 0xF
        imm =  w & 0xFF
        d4  =  w & 0xF
        sign8 = imm if imm < 128 else imm - 256

        op = None

        if w == 0x000B: op = 'rts'
        elif w == 0x0009: op = 'nop'
        elif w == 0x002B: op = 'rte'
        elif w == 0x4F22: op = 'sts.l PR,@-R15'
        elif w == 0x4F26: op = 'lds.l @R15+,PR'
        elif (w & 0xFF0F) == 0x2F06: op = 'mov.l R%d,@-R15' % n
        elif (w & 0xFF0F) == 0x60F6: op = 'mov.l @R15+,R%d' % n

        elif (w >> 12) == 0xD:
            v, lbl = pool_val(addr, imm)
            if v is not None:
                op = 'mov.l @(0x%02X,PC),R%d  ; =%s' % (imm, n, fmt_addr(v))
            else:
                op = 'mov.l @(0x%02X,PC),R%d' % (imm, n)

        elif (w >> 12) == 0x9:
            v = pool_val_w(addr, imm)
            if v is not None:
                op = 'mov.w @(0x%02X,PC),R%d  ; =0x%04X' % (imm, n, v)
            else:
                op = 'mov.w @(0x%02X,PC),R%d' % (imm, n)

        elif (w >> 12) == 0xE:
            op = 'mov #%d,R%d' % (sign8, n)

        elif (w >> 12) == 0xA:
            d = w & 0xFFF
            if d >= 0x800: d -= 0x1000
            tgt = addr + 4 + d * 2
            op = 'bra 0x%05X' % tgt

        elif (w >> 12) == 0xB:
            d = w & 0xFFF
            if d >= 0x800: d -= 0x1000
            tgt = addr + 4 + d * 2
            lbl = KNOWN_SUBS.get(tgt, '')
            op = 'bsr 0x%05X%s' % (tgt, '  ; %s' % lbl if lbl else '')

        elif (w >> 8) == 0x89:
            tgt = addr + 4 + sign8 * 2
            op = 'bt 0x%05X' % tgt
        elif (w >> 8) == 0x8B:
            tgt = addr + 4 + sign8 * 2
            op = 'bf 0x%05X' % tgt
        elif (w >> 8) == 0x8D:
            tgt = addr + 4 + sign8 * 2
            op = 'bt/s 0x%05X' % tgt
        elif (w >> 8) == 0x8F:
            tgt = addr + 4 + sign8 * 2
            op = 'bf/s 0x%05X' % tgt

        elif (w >> 12) == 0x6 and d4 == 3: op = 'mov R%d,R%d' % (m, n)
        elif (w >> 12) == 0x6 and d4 == 2: op = 'mov.l @R%d,R%d' % (m, n)
        elif (w >> 12) == 0x6 and d4 == 1: op = 'mov.w @R%d,R%d' % (m, n)
        elif (w >> 12) == 0x6 and d4 == 0: op = 'mov.b @R%d,R%d' % (m, n)
        elif (w >> 12) == 0x6 and d4 == 4: op = 'mov.b @R%d+,R%d' % (m, n)
        elif (w >> 12) == 0x6 and d4 == 5: op = 'mov.w @R%d+,R%d' % (m, n)
        elif (w >> 12) == 0x6 and d4 == 6: op = 'mov.l @R%d+,R%d' % (m, n)
        elif (w >> 12) == 0x6 and d4 == 0xC: op = 'extu.b R%d,R%d' % (m, n)
        elif (w >> 12) == 0x6 and d4 == 0xD: op = 'extu.w R%d,R%d' % (m, n)
        elif (w >> 12) == 0x6 and d4 == 0xE: op = 'exts.b R%d,R%d' % (m, n)
        elif (w >> 12) == 0x6 and d4 == 0xF: op = 'exts.w R%d,R%d' % (m, n)
        elif (w >> 12) == 0x6 and d4 == 7: op = 'not R%d,R%d' % (m, n)

        elif (w >> 12) == 0x2 and d4 == 0: op = 'mov.b R%d,@R%d' % (m, n)
        elif (w >> 12) == 0x2 and d4 == 1: op = 'mov.w R%d,@R%d' % (m, n)
        elif (w >> 12) == 0x2 and d4 == 2: op = 'mov.l R%d,@R%d' % (m, n)
        elif (w >> 12) == 0x2 and d4 == 6: op = 'mov.l R%d,@-R%d' % (m, n)
        elif (w >> 12) == 0x2 and d4 == 8: op = 'tst R%d,R%d' % (m, n)
        elif (w >> 12) == 0x2 and d4 == 9: op = 'and R%d,R%d' % (m, n)
        elif (w >> 12) == 0x2 and d4 == 0xA: op = 'xor R%d,R%d' % (m, n)
        elif (w >> 12) == 0x2 and d4 == 0xB: op = 'or R%d,R%d' % (m, n)

        elif (w >> 12) == 0x5:
            op = 'mov.l @(0x%X,R%d),R%d' % (d4*4, m, n)

        elif (w >> 12) == 0x1:
            op = 'mov.l R%d,@(0x%X,R%d)' % (m, d4*4, n)

        elif (w >> 12) == 0xC:
            sub = (w >> 8) & 0xF
            if sub == 0: op = 'mov.b R0,@(0x%02X,GBR)' % imm
            elif sub == 1: op = 'mov.w R0,@(0x%02X,GBR)' % (imm*2)
            elif sub == 2: op = 'mov.l R0,@(0x%02X,GBR)' % (imm*4)
            elif sub == 4: op = 'mov.b @(0x%02X,GBR),R0' % imm
            elif sub == 5: op = 'mov.w @(0x%02X,GBR),R0' % (imm*2)
            elif sub == 6: op = 'mov.l @(0x%02X,GBR),R0' % (imm*4)
            elif sub == 8: op = 'tst #0x%02X,R0' % imm
            elif sub == 9: op = 'and #0x%02X,R0' % imm
            elif sub == 0xA: op = 'xor #0x%02X,R0' % imm
            elif sub == 0xB: op = 'or #0x%02X,R0' % imm
            elif sub == 0xF: op = 'or.b #0x%02X,@(R0,GBR)' % imm
            elif sub == 0xD: op = 'and.b #0x%02X,@(R0,GBR)' % imm
            elif sub == 3: op = 'trapa #0x%02X' % imm
            else: op = 'C_op_%X_0x%02X' % (sub, imm)

        elif (w >> 12) == 0x7:
            op = 'add #%d,R%d' % (sign8, n)

        elif (w >> 12) == 0x3:
            if d4 == 0: op = 'cmp/eq R%d,R%d' % (m, n)
            elif d4 == 2: op = 'cmp/hs R%d,R%d' % (m, n)
            elif d4 == 3: op = 'cmp/ge R%d,R%d' % (m, n)
            elif d4 == 4: op = 'div1 R%d,R%d' % (m, n)
            elif d4 == 6: op = 'cmp/hi R%d,R%d' % (m, n)
            elif d4 == 7: op = 'cmp/gt R%d,R%d' % (m, n)
            elif d4 == 8: op = 'sub R%d,R%d' % (m, n)
            elif d4 == 0xA: op = 'subc R%d,R%d' % (m, n)
            elif d4 == 0xC: op = 'add R%d,R%d' % (m, n)
            elif d4 == 0xE: op = 'addc R%d,R%d' % (m, n)
            else: op = '3_%X_R%d_R%d' % (d4, m, n)

        elif (w >> 12) == 0x8:
            sub = (w >> 8) & 0xF
            if sub == 0: op = 'mov.b R0,@(0x%X,R%d)' % (d4, m)
            elif sub == 1: op = 'mov.w R0,@(0x%X,R%d)' % (d4*2, m)
            elif sub == 4: op = 'mov.b @(0x%X,R%d),R0' % (d4, m)
            elif sub == 5: op = 'mov.w @(0x%X,R%d),R0' % (d4*2, m)
            elif sub == 8: op = 'cmp/eq #%d,R0' % sign8
            else: op = '8_%X_0x%02X' % (sub, imm)

        elif (w >> 12) == 0x4:
            sub = w & 0xFF
            if sub == 0x22: op = 'sts.l PR,@-R%d' % n
            elif sub == 0x26: op = 'lds.l @R%d+,PR' % n
            elif sub == 0x5A: op = 'lds.l @R%d+,FPUL' % n
            elif sub == 0x6A: op = 'lds.l @R%d+,FPSCR' % n
            elif sub == 0x0B: op = 'jsr @R%d' % n
            elif sub == 0x2B: op = 'jmp @R%d' % n
            elif sub == 0x0A: op = 'lds R%d,PR' % n   # m==0
            elif (w & 0xF0FF) == 0x401A: op = 'lds R%d,FPUL' % n
            elif (w & 0xF0FF) == 0x406A: op = 'lds R%d,FPSCR' % n
            elif sub == 0x00: op = 'shll R%d' % n
            elif sub == 0x01: op = 'shlr R%d' % n
            elif sub == 0x20: op = 'shal R%d' % n
            elif sub == 0x21: op = 'shar R%d' % n
            elif sub == 0x08: op = 'shll2 R%d' % n
            elif sub == 0x09: op = 'shlr2 R%d' % n
            elif sub == 0x18: op = 'shll8 R%d' % n
            elif sub == 0x28: op = 'shll16 R%d' % n
            elif sub == 0x29: op = 'shlr16 R%d' % n
            elif sub == 0x15: op = 'cmp/pl R%d' % n
            elif sub == 0x11: op = 'cmp/pz R%d' % n
            elif sub == 0x05: op = 'rotr R%d' % n
            elif sub == 0x04: op = 'rotl R%d' % n
            elif sub == 0x24: op = 'rotcl R%d' % n
            elif sub == 0x25: op = 'rotcr R%d' % n
            elif (w & 0x0F0F) == 0x000F: op = 'mac.l @R%d+,@R%d+' % (m, n)
            else: op = '4_R%d_0x%02X' % (n, sub)

        elif (w >> 12) == 0x0:
            sub = w & 0xFF
            if sub == 0x02 and n == 0: op = 'stc SR,R0'
            elif sub == 0x22: op = 'stc GBR,R%d' % n  # 0nX22
            elif (w & 0xF0FF) == 0x0022: op = 'stc GBR,R%d' % n
            elif sub == 0x0A: op = 'sts MACH,R%d' % n  # 0nX0A
            elif (w & 0xF0FF) == 0x001A: op = 'sts MACL,R%d' % n
            elif (w & 0xF0FF) == 0x002A: op = 'sts PR,R%d' % n
            elif (w & 0xF0FF) == 0x005A: op = 'sts FPUL,R%d' % n
            elif (w & 0xF0FF) == 0x006A: op = 'sts FPSCR,R%d' % n
            elif sub == 0x07: op = 'mul.l R%d,R%d' % (m, n)
            elif sub == 0x0B: op = 'rts'
            elif sub == 0x23: op = 'braf R%d' % n
            elif sub == 0x03: op = 'bsrf R%d' % n
            elif sub == 0x04: op = 'mov.b @(R0,R%d),R%d' % (m, n)
            elif sub == 0x05: op = 'mov.w @(R0,R%d),R%d' % (m, n)
            elif sub == 0x06: op = 'mov.l @(R0,R%d),R%d' % (m, n)
            elif sub == 0x24: op = 'mov.b R%d,@(R0,R%d)' % (m, n)
            elif sub == 0x25: op = 'mov.w R%d,@(R0,R%d)' % (m, n)
            elif sub == 0x26: op = 'mov.l R%d,@(R0,R%d)' % (m, n)
            elif sub == 0x09: op = 'nop'
            elif sub == 0x28: op = 'clrt'
            elif sub == 0x48: op = 'clrs'
            elif sub == 0x58: op = 'sets'
            elif sub == 0x68: op = 'clrmac'
            elif sub == 0x19: op = 'div0u'
            else: op = '0_0x%04X' % w

        elif (w >> 12) == 0xF:
            sub = w & 0xF
            if sub == 0x0: op = 'fadd FR%d,FR%d' % (m, n)
            elif sub == 0x1: op = 'fsub FR%d,FR%d' % (m, n)
            elif sub == 0x2: op = 'fmul FR%d,FR%d' % (m, n)
            elif sub == 0x3: op = 'fdiv FR%d,FR%d' % (m, n)
            elif sub == 0x4: op = 'fcmp/eq FR%d,FR%d' % (m, n)
            elif sub == 0x5: op = 'fcmp/gt FR%d,FR%d' % (m, n)
            elif sub == 0x6: op = 'fmov.s @(R0,R%d),FR%d' % (m, n)
            elif sub == 0x7: op = 'fmov.s FR%d,@(R0,R%d)' % (n, m)
            elif sub == 0x8: op = 'fmov.s @R%d+,FR%d' % (m, n)
            elif sub == 0x9: op = 'fmov.s FR%d,@-R%d' % (n, m)
            elif sub == 0xA: op = 'fmov.s FR%d,@R%d' % (n, m)
            elif sub == 0xB: op = 'fmov.s @R%d,FR%d' % (m, n)
            elif sub == 0xC: op = 'fmov.s @R%d,FR%d' % (m, n)  # same as 0xB?
            elif sub == 0xD:
                if m == 0: op = 'float FPUL,FR%d' % n
                elif m == 1: op = 'float FPUL,DR%d' % n
                else: op = 'ftrc FR%d,FPUL' % n
            elif sub == 0xE: op = 'fmac FR0,FR%d,FR%d' % (m, n)
            elif sub == 0xF:
                if w == 0xF0FD: op = 'fsca FPUL,DR0'
                elif w == 0xFBFD: op = 'frchg'
                elif w == 0xF3FD: op = 'fschg'
                elif (w & 0x01FF) == 0x00FD:
                    if (w >> 9) & 7 == 0: op = 'fsqrt FR%d' % n
                    else: op = 'F_0xFD_R%d_%X' % (n, (w>>9)&7)
                else:
                    sub2 = (w >> 4) & 0xF
                    if sub2 == 0x8: op = 'fldi0 FR%d' % n
                    elif sub2 == 0x9: op = 'fldi1 FR%d' % n
                    elif sub2 == 0xA: op = 'fneg FR%d' % n
                    elif sub2 == 0xB: op = 'fabs FR%d' % n
                    elif sub2 == 0xC: op = 'fsqrt FR%d' % n
                    elif sub2 == 0xD:
                        # ftrc or float
                        if n == 0: op = 'ftrc FR%d,FPUL' % m
                        else: op = 'fsts FPUL,FR%d' % n
                    elif sub2 == 0xE: op = 'flds FR%d,FPUL' % m
                    else: op = 'F_R%d_0x%04X' % (n, w)
            else: op = 'F_0x%04X' % w

        if op is None:
            op = '??? 0x%04X' % w

        lines.append((addr, w, op))
        addr += 2
        count += 1

        # Stop at rts/rte only (not bra — we trace linearly past jumps)
        if op in ('rts', 'rte') or op.startswith('jmp '):
            # decode delay slot
            if addr + 2 <= len(rom) and count < max_insn:
                w2 = struct.unpack('>H', rom[addr:addr+2])[0]
                lines.append((addr, w2, '  [delay slot] 0x%04X' % w2))
                addr += 2
            break

    return lines


# Show ISR22 prologue (0x48732) so we understand the frame, then body from 0x488B0
# ISR22 has several disjoint code sections separated by literal pools.
# We trace each code section individually, noting the pool boundaries.
# bra 0x488CA at 0x48746 → body at 0x488B0-ish
# Within body: bra 0x488EE at 0x488D2 (delay 0x488D4) → pool 0x488D6-0x488ED → continue at 0x488EE
# We trace each segment, then follow branch targets

def find_pools(start, end):
    """Return list of (pool_start, pool_end) by scanning for pools after mov.l @(disp,PC)"""
    pools = []
    # Simple approach: when we hit jsr/bra with pool data after delay slot, mark pool
    return pools

def disasm_segments(start, end, max_total=600):
    """Decode multiple segments separated by known pool gaps."""
    segments = []
    addr = start
    total = 0

    while addr < end and total < max_total:
        if addr + 2 > len(rom): break
        w = struct.unpack('>H', rom[addr:addr+2])[0]
        n   = (w >> 8) & 0xF
        m   = (w >> 4) & 0xF
        imm =  w & 0xFF
        d4  =  w & 0xF
        sign8 = imm if imm < 128 else imm - 256

        op = None
        is_term = False
        branch_tgt = None
        is_rts = False

        if w == 0x000B:  op = 'rts'; is_rts = True
        elif w == 0x0009: op = 'nop'
        elif w == 0x002B: op = 'rte'; is_rts = True
        elif w == 0x4F22: op = 'sts.l PR,@-R15'
        elif w == 0x4F26: op = 'lds.l @R15+,PR'
        elif (w & 0xFF0F) == 0x2F06: op = 'mov.l R%d,@-R15' % n
        elif (w & 0xFF0F) == 0x60F6: op = 'mov.l @R15+,R%d' % n
        elif (w >> 12) == 0xD:
            v, lbl = pool_val(addr, imm)
            if v is not None:
                op = 'mov.l @(0x%02X,PC),R%d  ; =%s' % (imm, n, fmt_addr(v))
            else:
                op = 'mov.l @(0x%02X,PC),R%d' % (imm, n)
        elif (w >> 12) == 0x9:
            v = pool_val_w(addr, imm)
            if v is not None:
                op = 'mov.w @(0x%02X,PC),R%d  ; =0x%04X' % (imm, n, v)
            else:
                op = 'mov.w @(0x%02X,PC),R%d' % (imm, n)
        elif (w >> 12) == 0xE:
            op = 'mov #%d,R%d' % (sign8, n)
        elif (w >> 12) == 0xA:
            d = w & 0xFFF
            if d >= 0x800: d -= 0x1000
            tgt = addr + 4 + d * 2
            op = 'bra 0x%05X' % tgt
            branch_tgt = tgt
            is_term = True
        elif (w >> 12) == 0xB:
            d = w & 0xFFF
            if d >= 0x800: d -= 0x1000
            tgt = addr + 4 + d * 2
            lbl = KNOWN_SUBS.get(tgt, '')
            op = 'bsr 0x%05X%s' % (tgt, '  ; %s' % lbl if lbl else '')
        elif (w >> 8) == 0x89:
            tgt = addr + 4 + sign8 * 2
            op = 'bt 0x%05X' % tgt
        elif (w >> 8) == 0x8B:
            tgt = addr + 4 + sign8 * 2
            op = 'bf 0x%05X' % tgt
        elif (w >> 8) == 0x8D:
            tgt = addr + 4 + sign8 * 2
            op = 'bt/s 0x%05X' % tgt
        elif (w >> 8) == 0x8F:
            tgt = addr + 4 + sign8 * 2
            op = 'bf/s 0x%05X' % tgt
        elif (w >> 12) == 0x6 and d4 == 3: op = 'mov R%d,R%d' % (m, n)
        elif (w >> 12) == 0x6 and d4 == 2: op = 'mov.l @R%d,R%d' % (m, n)
        elif (w >> 12) == 0x6 and d4 == 1: op = 'mov.w @R%d,R%d' % (m, n)
        elif (w >> 12) == 0x6 and d4 == 0: op = 'mov.b @R%d,R%d' % (m, n)
        elif (w >> 12) == 0x6 and d4 == 4: op = 'mov.b @R%d+,R%d' % (m, n)
        elif (w >> 12) == 0x6 and d4 == 5: op = 'mov.w @R%d+,R%d' % (m, n)
        elif (w >> 12) == 0x6 and d4 == 6: op = 'mov.l @R%d+,R%d' % (m, n)
        elif (w >> 12) == 0x6 and d4 == 0xC: op = 'extu.b R%d,R%d' % (m, n)
        elif (w >> 12) == 0x6 and d4 == 0xD: op = 'extu.w R%d,R%d' % (m, n)
        elif (w >> 12) == 0x6 and d4 == 0xE: op = 'exts.b R%d,R%d' % (m, n)
        elif (w >> 12) == 0x6 and d4 == 0xF: op = 'exts.w R%d,R%d' % (m, n)
        elif (w >> 12) == 0x6 and d4 == 7: op = 'not R%d,R%d' % (m, n)
        elif (w >> 12) == 0x2 and d4 == 0: op = 'mov.b R%d,@R%d' % (m, n)
        elif (w >> 12) == 0x2 and d4 == 1: op = 'mov.w R%d,@R%d' % (m, n)
        elif (w >> 12) == 0x2 and d4 == 2: op = 'mov.l R%d,@R%d' % (m, n)
        elif (w >> 12) == 0x2 and d4 == 6: op = 'mov.l R%d,@-R%d' % (m, n)
        elif (w >> 12) == 0x2 and d4 == 8: op = 'tst R%d,R%d' % (m, n)
        elif (w >> 12) == 0x2 and d4 == 9: op = 'and R%d,R%d' % (m, n)
        elif (w >> 12) == 0x2 and d4 == 0xA: op = 'xor R%d,R%d' % (m, n)
        elif (w >> 12) == 0x2 and d4 == 0xB: op = 'or R%d,R%d' % (m, n)
        elif (w >> 12) == 0x5: op = 'mov.l @(0x%X,R%d),R%d' % (d4*4, m, n)
        elif (w >> 12) == 0x1: op = 'mov.l R%d,@(0x%X,R%d)' % (m, d4*4, n)
        elif (w >> 12) == 0xC:
            sub = (w >> 8) & 0xF
            if sub == 0: op = 'mov.b R0,@(0x%02X,GBR)' % imm
            elif sub == 1: op = 'mov.w R0,@(0x%02X,GBR)' % (imm*2)
            elif sub == 2: op = 'mov.l R0,@(0x%02X,GBR)' % (imm*4)
            elif sub == 4: op = 'mov.b @(0x%02X,GBR),R0' % imm
            elif sub == 5: op = 'mov.w @(0x%02X,GBR),R0' % (imm*2)
            elif sub == 6: op = 'mov.l @(0x%02X,GBR),R0' % (imm*4)
            elif sub == 8: op = 'tst #0x%02X,R0' % imm
            elif sub == 9: op = 'and #0x%02X,R0' % imm
            elif sub == 0xA: op = 'xor #0x%02X,R0' % imm
            elif sub == 0xB: op = 'or #0x%02X,R0' % imm
            elif sub == 3: op = 'trapa #0x%02X' % imm
            else: op = 'C_op_%X_0x%02X' % (sub, imm)
        elif (w >> 12) == 0x7: op = 'add #%d,R%d' % (sign8, n)
        elif (w >> 12) == 0x3:
            if d4 == 0: op = 'cmp/eq R%d,R%d' % (m, n)
            elif d4 == 2: op = 'cmp/hs R%d,R%d' % (m, n)
            elif d4 == 3: op = 'cmp/ge R%d,R%d' % (m, n)
            elif d4 == 6: op = 'cmp/hi R%d,R%d' % (m, n)
            elif d4 == 7: op = 'cmp/gt R%d,R%d' % (m, n)
            elif d4 == 8: op = 'sub R%d,R%d' % (m, n)
            elif d4 == 0xA: op = 'subc R%d,R%d' % (m, n)
            elif d4 == 0xC: op = 'add R%d,R%d' % (m, n)
            elif d4 == 0xE: op = 'addc R%d,R%d' % (m, n)
            else: op = '3_%X_R%d_R%d' % (d4, m, n)
        elif (w >> 12) == 0x8:
            sub = (w >> 8) & 0xF
            if sub == 0: op = 'mov.b R0,@(0x%X,R%d)' % (d4, m)
            elif sub == 1: op = 'mov.w R0,@(0x%X,R%d)' % (d4*2, m)
            elif sub == 4: op = 'mov.b @(0x%X,R%d),R0' % (d4, m)
            elif sub == 5: op = 'mov.w @(0x%X,R%d),R0' % (d4*2, m)
            elif sub == 8: op = 'cmp/eq #%d,R0' % sign8
            else: op = '8_%X_0x%02X' % (sub, imm)
        elif (w >> 12) == 0x4:
            sub = w & 0xFF
            if sub == 0x22: op = 'sts.l PR,@-R%d' % n
            elif sub == 0x26: op = 'lds.l @R%d+,PR' % n
            elif sub == 0x5A: op = 'lds.l @R%d+,FPUL' % n
            elif sub == 0x6A: op = 'lds.l @R%d+,FPSCR' % n
            elif sub == 0x0B: op = 'jsr @R%d' % n
            elif sub == 0x2B: op = 'jmp @R%d' % n; is_term = True
            elif (w & 0xF0FF) == 0x400A: op = 'lds R%d,PR' % n
            elif (w & 0xF0FF) == 0x401A: op = 'lds R%d,FPUL' % n
            elif (w & 0xF0FF) == 0x406A: op = 'lds R%d,FPSCR' % n
            elif sub == 0x00: op = 'shll R%d' % n
            elif sub == 0x01: op = 'shlr R%d' % n
            elif sub == 0x20: op = 'shal R%d' % n
            elif sub == 0x21: op = 'shar R%d' % n
            elif sub == 0x08: op = 'shll2 R%d' % n
            elif sub == 0x09: op = 'shlr2 R%d' % n
            elif sub == 0x18: op = 'shll8 R%d' % n
            elif sub == 0x28: op = 'shll16 R%d' % n
            elif sub == 0x29: op = 'shlr16 R%d' % n
            elif sub == 0x15: op = 'cmp/pl R%d' % n
            elif sub == 0x11: op = 'cmp/pz R%d' % n
            elif sub == 0x05: op = 'rotr R%d' % n
            elif sub == 0x04: op = 'rotl R%d' % n
            else: op = '4_R%d_0x%02X' % (n, sub)
        elif (w >> 12) == 0x0:
            sub = w & 0xFF
            if (w & 0xF0FF) == 0x0022: op = 'stc GBR,R%d' % n
            elif (w & 0xF0FF) == 0x001A: op = 'sts MACL,R%d' % n
            elif (w & 0xF0FF) == 0x002A: op = 'sts PR,R%d' % n
            elif (w & 0xF0FF) == 0x005A: op = 'sts FPUL,R%d' % n
            elif (w & 0xF0FF) == 0x006A: op = 'sts FPSCR,R%d' % n
            elif sub == 0x07: op = 'mul.l R%d,R%d' % (m, n)
            elif sub == 0x0B: op = 'rts'; is_rts = True
            elif sub == 0x23: op = 'braf R%d' % n; is_term = True
            elif sub == 0x03: op = 'bsrf R%d' % n
            elif sub == 0x04: op = 'mov.b @(R0,R%d),R%d' % (m, n)
            elif sub == 0x05: op = 'mov.w @(R0,R%d),R%d' % (m, n)
            elif sub == 0x06: op = 'mov.l @(R0,R%d),R%d' % (m, n)
            elif sub == 0x24: op = 'mov.b R%d,@(R0,R%d)' % (m, n)
            elif sub == 0x25: op = 'mov.w R%d,@(R0,R%d)' % (m, n)
            elif sub == 0x26: op = 'mov.l R%d,@(R0,R%d)' % (m, n)
            elif sub == 0x09: op = 'nop'
            elif sub == 0x19: op = 'div0u'
            elif sub == 0x02 and n == 0: op = 'stc SR,R0'
            else: op = '0_0x%04X' % w
        elif (w >> 12) == 0xF:
            sub = w & 0xF
            if sub == 0x0: op = 'fadd FR%d,FR%d' % (m, n)
            elif sub == 0x1: op = 'fsub FR%d,FR%d' % (m, n)
            elif sub == 0x2: op = 'fmul FR%d,FR%d' % (m, n)
            elif sub == 0x3: op = 'fdiv FR%d,FR%d' % (m, n)
            elif sub == 0x4: op = 'fcmp/eq FR%d,FR%d' % (m, n)
            elif sub == 0x5: op = 'fcmp/gt FR%d,FR%d' % (m, n)
            elif sub == 0x6: op = 'fmov.s @(R0,R%d),FR%d' % (m, n)
            elif sub == 0x7: op = 'fmov.s FR%d,@(R0,R%d)' % (n, m)
            elif sub == 0x8: op = 'fmov.s @R%d+,FR%d' % (m, n)
            elif sub == 0x9: op = 'fmov.s FR%d,@-R%d' % (n, m)
            elif sub == 0xA: op = 'fmov.s FR%d,@R%d' % (n, m)
            elif sub == 0xB: op = 'fmov.s @R%d,FR%d' % (m, n)
            elif sub == 0xC: op = 'fmov.s @R%d,FR%d (alt)' % (m, n)
            elif sub == 0xD:
                sub2 = (w >> 4) & 0xF
                if sub2 == 8: op = 'fldi0 FR%d' % n
                elif sub2 == 9: op = 'fldi1 FR%d' % n
                elif sub2 == 0xA: op = 'fneg FR%d' % n
                elif sub2 == 0xB: op = 'fabs FR%d' % n
                elif sub2 == 0xC: op = 'fsqrt FR%d' % n
                elif sub2 == 0xE: op = 'flds FR%d,FPUL' % m
                elif m == 0: op = 'float FPUL,FR%d' % n
                else: op = 'ftrc FR%d,FPUL' % n
            elif sub == 0xE: op = 'fmac FR0,FR%d,FR%d' % (m, n)
            elif sub == 0xF:
                sub2 = (w >> 4) & 0xF
                if sub2 == 8: op = 'fldi0 FR%d' % n
                elif sub2 == 9: op = 'fldi1 FR%d' % n
                elif sub2 == 0xA: op = 'fneg FR%d' % n
                elif sub2 == 0xB: op = 'fabs FR%d' % n
                elif w == 0xF0FD: op = 'fsca FPUL,DR0'
                elif w == 0xFBFD: op = 'frchg'
                elif w == 0xF3FD: op = 'fschg'
                else: op = 'F_0x%04X' % w
            else: op = 'F_0x%04X' % w

        if op is None:
            op = '??? 0x%04X' % w

        print('  0x%05X: %04X  %s' % (addr, w, op))
        addr += 2
        total += 1

        # After bra/jmp, decode delay slot then jump to target
        if is_term and branch_tgt is not None:
            # print delay slot
            if addr + 2 <= len(rom):
                w2 = struct.unpack('>H', rom[addr:addr+2])[0]
                print('  0x%05X: %04X  [delay] ???' % (addr, w2))
                addr += 2; total += 1
            # Check if pool data follows before branch target
            if addr < branch_tgt:
                pool_bytes = branch_tgt - addr
                print('  ... [pool/pad 0x%05X-0x%05X, %d bytes]' % (addr, branch_tgt-1, pool_bytes))
                # Dump pool words
                pa = addr
                while pa < branch_tgt and pa + 4 <= len(rom):
                    pv = struct.unpack('>I', rom[pa:pa+4])[0]
                    lbl = KNOWN_LABELS.get(pv, KNOWN_SUBS.get(pv, ''))
                    note = '  ; %s' % lbl if lbl else ''
                    print('  0x%05X: [pool] 0x%08X%s' % (pa, pv, note))
                    pa += 4
                addr = branch_tgt
            elif is_term:
                pass
        elif is_rts:
            # print delay slot
            if addr + 2 <= len(rom):
                w2 = struct.unpack('>H', rom[addr:addr+2])[0]
                print('  0x%05X: %04X  [delay]' % (addr, w2))
                addr += 2; total += 1
            break
        elif is_term:  # jmp without known target
            if addr + 2 <= len(rom):
                w2 = struct.unpack('>H', rom[addr:addr+2])[0]
                print('  0x%05X: %04X  [delay]' % (addr, w2))
                addr += 2; total += 1
            break

    return addr

# ISR22 prologue
print()
print('=' * 70)
print('ISR22 prologue: func_48732 @ 0x48732')
print('=' * 70)
disasm_segments(0x48732, 0x4874A, max_total=30)

# ISR22 loop body (starting from loop body, before condition)
print()
print('=' * 70)
print('ISR22 loop body: 0x488C0 -> condition at 0x488CA -> exit at 0x488EE')
print('=' * 70)
disasm_segments(0x488C0, 0x48F00, max_total=500)
