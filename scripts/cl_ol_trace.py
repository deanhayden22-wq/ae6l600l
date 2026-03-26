#!/usr/bin/env python3
"""
Disassemble the CL/OL mode flag function (0x034600-0x034B20) from AE5L600L ROM.
Traces all 11 writes to RAM FFFF7448 and identifies conditions/values.
"""
import os, struct, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sh2_disasm import decode_insn
from sh2_disasm import disasm_sh2

ROM_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rom", "ae5l600l.bin")

START = 0x034600
END   = 0x034B40

WRITE_ADDRS = {0x03476C, 0x034822, 0x034830, 0x03487A, 0x0348D6,
               0x03496A, 0x034A26, 0x034A42, 0x034A4E, 0x034B02, 0x034B08}

with open(ROM_PATH, "rb") as f:
    rom = f.read()


def resolve_pool_l(addr, opcode):
    disp8 = opcode & 0xFF
    ea = (addr & 0xFFFFFFFC) + 4 + disp8 * 4
    if ea + 4 <= len(rom):
        return ea, struct.unpack(">I", rom[ea:ea+4])[0]
    return ea, None


def resolve_pool_w(addr, opcode):
    disp8 = opcode & 0xFF
    ea = addr + 4 + disp8 * 2
    if ea + 2 <= len(rom):
        return ea, struct.unpack(">H", rom[ea:ea+2])[0]
    return ea, None


def annotate_val(val):
    if val == 0xFFFF7448:
        return "CL/OL mode flag"
    if 0xFFFF0000 <= val <= 0xFFFFFFFF:
        return "RAM"
    if 0x000C0000 <= val <= 0x000FFFFF:
        return "CAL table"
    if 0 < val < 0x100000:
        return "ROM"
    return ""


# Pass 1: collect branch targets and literal pool refs
branch_targets = set()
pool_longs = {}
pool_words = {}

addr = START
while addr < END:
    if addr + 2 > len(rom):
        break
    op = struct.unpack(">H", rom[addr:addr+2])[0]
    t4 = (op >> 12) & 0xF
    sub8 = (op >> 8) & 0xF

    if t4 == 0x8 and sub8 in (0x9, 0xB, 0xD, 0xF):
        d = op & 0xFF
        disp = d if d < 128 else d - 256
        branch_targets.add(addr + 4 + disp * 2)
    elif t4 == 0xA:
        d12 = op & 0xFFF
        disp = d12 if d12 < 0x800 else d12 - 0x1000
        branch_targets.add(addr + 4 + disp * 2)
    elif t4 == 0xB:
        d12 = op & 0xFFF
        disp = d12 if d12 < 0x800 else d12 - 0x1000
        branch_targets.add(addr + 4 + disp * 2)

    if t4 == 0xD:
        rn = sub8
        ea, val = resolve_pool_l(addr, op)
        pool_longs[ea] = (addr, rn, val)
    elif t4 == 0x9:
        rn = sub8
        ea, val = resolve_pool_w(addr, op)
        pool_words[ea] = (addr, rn, val)

    addr += 2


# Pass 2: disassemble
print("=" * 110)
print("FULL DISASSEMBLY: CL/OL Mode Flag Function (0x034600 - 0x034B20)")
print("Writes to RAM FFFF7448 marked with >>>")
print("=" * 110)

addr = START
while addr < END:
    if addr + 2 > len(rom):
        break

    # Literal pool long?
    if addr in pool_longs:
        _, _, val = pool_longs[addr]
        if val is not None:
            b = rom[addr:addr+4]
            a = annotate_val(val)
            print("  0x%06X:  %02X%02X %02X%02X  .long 0x%08X      ; %s" % (addr, b[0], b[1], b[2], b[3], val, a))
            addr += 4
            continue

    if addr in branch_targets:
        print("loc_%06X:" % addr)

    marker = ">>>" if addr in WRITE_ADDRS else "   "
    op = struct.unpack(">H", rom[addr:addr+2])[0]
    mnem, _ = decode_insn(op, addr, rom)
    mnem = disasm_sh2(op, addr)

    comment = ""
    t4 = (op >> 12) & 0xF
    if t4 == 0xD:
        ea, val = resolve_pool_l(addr, op)
        if val is not None:
            a = annotate_val(val)
            comment = "=0x%08X" % val
            if a:
                comment += " (%s)" % a
    elif t4 == 0x9:
        ea, val = resolve_pool_w(addr, op)
        if val is not None:
            comment = "=0x%04X (%d)" % (val, val)

    if addr in WRITE_ADDRS:
        comment += "  *** WRITE FFFF7448 ***"

    print("%s 0x%06X:  %04X    %-42s ; %s" % (marker, addr, op, mnem, comment))
    addr += 2


# Pass 3: trace each write
print()
print("=" * 110)
print("DETAILED WRITE TRACE: Values written to FFFF7448")
print("=" * 110)

for wa in sorted(WRITE_ADDRS):
    op = struct.unpack(">H", rom[wa:wa+2])[0]
    src_reg = (op >> 4) & 0xF
    dst_reg = (op >> 8) & 0xF

    print()
    print("--- WRITE @ 0x%06X: mov.b R%d,@R%d ---" % (wa, src_reg, dst_reg))

    # Trace source register
    trace_reg = src_reg
    scan = wa - 2
    for _ in range(50):
        if scan < START:
            break
        sop = struct.unpack(">H", rom[scan:scan+2])[0]
        st4 = (sop >> 12) & 0xF
        sn = (sop >> 8) & 0xF
        sm = (sop >> 4) & 0xF

        if st4 == 0xE and sn == trace_reg:
            imm = sop & 0xFF
            simm = imm if imm < 128 else imm - 256
            print("  Value: %d (0x%02X)   (mov #%d,R%d at 0x%06X)" % (simm, imm, simm, sn, scan))
            break
        if st4 == 0x6 and sn == trace_reg and (sop & 0xF) == 0xE:
            trace_reg = sm
            scan -= 2
            continue
        if st4 == 0x6 and sn == trace_reg and (sop & 0xF) == 0x3:
            trace_reg = sm
            scan -= 2
            continue
        if st4 == 0x6 and sn == trace_reg and (sop & 0xF) == 0x0:
            print("  Value: byte from @R%d   (mov.b @R%d,R%d at 0x%06X)" % (sm, sm, sn, scan))
            break
        if st4 == 0x8 and (sop >> 8 & 0xF) == 0x4 and trace_reg == 0:
            disp = sop & 0xF
            print("  Value: byte from @(%d,R%d)   (at 0x%06X)" % (disp, sm, scan))
            break
        if st4 == 0xD and sn == trace_reg:
            ea, val = resolve_pool_l(scan, sop)
            print("  Value: 0x%08X from pool   (at 0x%06X)" % (val, scan))
            break
        if st4 == 0x7 and sn == trace_reg:
            scan -= 2
            continue
        scan -= 2
    else:
        print("  Value: could not trace")

    # Find controlling branch
    print("  Condition:")
    scan = wa - 2
    for _ in range(40):
        if scan < START:
            break
        sop = struct.unpack(">H", rom[scan:scan+2])[0]
        st4 = (sop >> 12) & 0xF
        sub8 = (sop >> 8) & 0xF

        if st4 == 0x8 and sub8 in (0x9, 0xB, 0xD, 0xF):
            d = sop & 0xFF
            disp = d if d < 128 else d - 256
            target = scan + 4 + disp * 2
            bnames = {0x9: "bt", 0xB: "bf", 0xD: "bt/s", 0xF: "bf/s"}
            btype = bnames[sub8]

            if target > wa:
                rel = "skips over write (write is fall-through)"
            elif target == wa:
                rel = "branches directly to write"
            elif abs(target - wa) <= 4:
                rel = "branches near write"
            else:
                rel = "branches to 0x%06X" % target

            # Find comparison
            cscan = scan - 2
            cmp_str = ""
            for __ in range(10):
                if cscan < START:
                    break
                cop = struct.unpack(">H", rom[cscan:cscan+2])[0]
                ct4 = (cop >> 12) & 0xF
                cn = (cop >> 8) & 0xF
                cm = (cop >> 4) & 0xF

                if ct4 == 0x8 and cn == 0x8:
                    cimm = cop & 0xFF
                    csimm = cimm if cimm < 128 else cimm - 256
                    cmp_str = "cmp/eq #%d,R0" % csimm
                    break
                if ct4 == 0x3 and (cop & 0xF) == 0x0:
                    cmp_str = "cmp/eq R%d,R%d" % (cm, cn)
                    break
                if ct4 == 0x3 and (cop & 0xF) in (0x2, 0x3, 0x6, 0x7):
                    names = {0x2: "cmp/hs", 0x3: "cmp/ge", 0x6: "cmp/hi", 0x7: "cmp/gt"}
                    cmp_str = "%s R%d,R%d" % (names[cop & 0xF], cm, cn)
                    break
                if ct4 == 0x2 and (cop & 0xF) == 0x8:
                    cmp_str = "tst R%d,R%d" % (cm, cn)
                    break
                if ct4 == 0xC and cn == 0x8:
                    cmp_str = "tst #%d,R0" % (cop & 0xFF)
                    break
                cscan -= 2

            print("    %s 0x%06X at 0x%06X -> %s" % (btype, target, scan, rel))
            if cmp_str:
                print("    Test: %s at 0x%06X" % (cmp_str, cscan))
            break

        if st4 == 0xA:
            d12 = sop & 0xFFF
            disp = d12 if d12 < 0x800 else d12 - 0x1000
            target = scan + 4 + disp * 2
            print("    bra 0x%06X at 0x%06X" % (target, scan))
            break

        if sop == 0x000B:
            print("    (after rts at 0x%06X)" % scan)
            break

        if scan in WRITE_ADDRS and scan != wa:
            print("    (preceded by another write at 0x%06X)" % scan)
            break

        scan -= 2


# Pass 4: Literal pool summary
print()
print("=" * 110)
print("LITERAL POOL ENTRIES (32-bit)")
print("=" * 110)
for ea in sorted(pool_longs.keys()):
    ia, rn, val = pool_longs[ea]
    if val is not None:
        a = annotate_val(val)
        print("  Pool 0x%06X: 0x%08X  R%d @ 0x%06X  %s" % (ea, val, rn, ia, a))


# Pass 5: Calibration addresses
print()
print("=" * 110)
print("CALIBRATION ADDRESSES (0x0Cxxxx)")
print("=" * 110)
for ea in sorted(pool_longs.keys()):
    _, rn, val = pool_longs[ea]
    if val is not None and 0x000C0000 <= val <= 0x000FFFFF:
        if val + 2 <= len(rom):
            b = rom[val]
            w = struct.unpack(">H", rom[val:val+2])[0]
            print("  0x%06X: byte=0x%02X (%3d), word=0x%04X (%5d)  (pool 0x%06X, R%d)" % (val, b, b, w, w, ea, rn))
        else:
            print("  0x%06X: (out of range)" % val)
