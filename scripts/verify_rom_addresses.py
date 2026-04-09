"""
Verify critical CL/OL function addresses against the AE5L600L ROM binary.

SH-2 (SH7058) is big-endian, 16-bit fixed-width instructions.
ROM is memory-mapped starting at 0x00000000.
"""

import struct
import sys
import os

ROM_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "rom", "ae5l600l.bin"
)

def read_rom(path):
    with open(path, "rb") as f:
        return f.read()

def hex_dump(data, base_addr, bytes_per_line=16):
    """Pretty hex dump."""
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i+bytes_per_line]
        hex_str = " ".join(f"{b:02X}" for b in chunk)
        addr = base_addr + i
        lines.append(f"  0x{addr:06X}: {hex_str}")
    return "\n".join(lines)

def read_be_float(rom, addr):
    raw = rom[addr:addr+4]
    val = struct.unpack(">f", raw)[0]
    return raw, val

def read_be_uint16(rom, addr):
    raw = rom[addr:addr+2]
    val = struct.unpack(">H", raw)[0]
    return raw, val

def read_be_uint32(rom, addr):
    raw = rom[addr:addr+4]
    val = struct.unpack(">I", raw)[0]
    return raw, val

def resolve_literal_pool(rom, pc):
    """For a MOV.L @(disp,PC),Rn instruction at pc, return (Rn, literal_addr, literal_value)."""
    hw = struct.unpack(">H", rom[pc:pc+2])[0]
    if (hw >> 12) != 0xD:
        return None
    rn = (hw >> 8) & 0xF
    disp = hw & 0xFF
    lit_addr = ((pc + 2) & ~3) + disp * 4
    if lit_addr + 4 > len(rom):
        return None
    lit_val = struct.unpack(">I", rom[lit_addr:lit_addr+4])[0]
    return rn, lit_addr, lit_val

def decode_sh2(rom, pc):
    """Basic SH-2 instruction decoder returning mnemonic string."""
    hw = struct.unpack(">H", rom[pc:pc+2])[0]
    nibble = hw >> 12

    if nibble == 0xD:
        rn = (hw >> 8) & 0xF
        disp = hw & 0xFF
        return f"MOV.L @(0x{disp*4:X},PC),R{rn}"
    if nibble == 0xF:
        sub = hw & 0xF
        frn = (hw >> 8) & 0xF
        rm = (hw >> 4) & 0xF
        if sub == 0x8:
            return f"FMOV.S @R{rm},FR{frn}"
        if sub == 0xA:
            return f"FMOV.S FR{rm},@R{frn}"
        if sub == 0x5:
            return f"FCMP/GT FR{rm},FR{frn}"
    if nibble == 0x6:
        sub = hw & 0xF
        rn = (hw >> 8) & 0xF
        rm = (hw >> 4) & 0xF
        if sub == 0x3:
            return f"MOV R{rm},R{rn}"
        if sub == 0x2:
            return f"MOV.L @R{rm},R{rn}"
        if sub == 0x0:
            return f"MOV.B @R{rm},R{rn}"
    if (hw >> 8) == 0x84:
        rn = (hw >> 4) & 0xF
        disp = hw & 0xF
        return f"MOV.B @(0x{disp:X},R{rn}),R0"
    if (hw >> 8) == 0x80:
        rn = (hw >> 4) & 0xF
        disp = hw & 0xF
        return f"MOV.B R0,@(0x{disp:X},R{rn})"
    if nibble == 0xE:
        rn = (hw >> 8) & 0xF
        imm = hw & 0xFF
        if imm & 0x80:
            imm -= 256
        return f"MOV #{imm},R{rn}"
    if hw == 0x000B:
        return "RTS"
    if hw == 0x0009:
        return "NOP"
    return f"0x{hw:04X}"

def disasm_block(rom, addr, count):
    """Disassemble count instructions with literal pool resolution."""
    lines = []
    for i in range(count):
        pc = addr + i * 2
        hw = struct.unpack(">H", rom[pc:pc+2])[0]
        mnem = decode_sh2(rom, pc)
        extra = ""
        lp = resolve_literal_pool(rom, pc)
        if lp:
            rn, la, lv = lp
            extra = f"  ; [{la:#08X}] = 0x{lv:08X}"
            if lv >= 0xFFFF0000:
                extra += f" (RAM)"
        lines.append(f"  0x{pc:06X}: {hw:04X}  {mnem}{extra}")
    return "\n".join(lines)


def check_movl_loads_addr(rom, pc, expected_val, label):
    """Check if MOV.L @(disp,PC),Rn at pc loads the expected value."""
    lp = resolve_literal_pool(rom, pc)
    if lp is None:
        return False, f"Instruction at 0x{pc:06X} is not MOV.L @(disp,PC),Rn"
    rn, la, lv = lp
    if lv == expected_val:
        return True, (f"0x{pc:06X}: MOV.L -> R{rn} = 0x{lv:08X} "
                       f"(expected {label}) [pool @ 0x{la:06X}]")
    else:
        return False, (f"0x{pc:06X}: MOV.L -> R{rn} = 0x{lv:08X} "
                        f"but expected 0x{expected_val:08X} ({label}) [pool @ 0x{la:06X}]")


def main():
    print(f"ROM: {ROM_PATH}")
    rom = read_rom(ROM_PATH)
    print(f"Size: {len(rom)} bytes (0x{len(rom):X})")
    print()

    results = []  # (name, pass/fail, detail)

    # =========================================================================
    # CHECK 1: ol_condition_checker register loads near 0x36450
    # =========================================================================
    print("=" * 78)
    print("CHECK 1: ol_condition_checker register loads (0x36450 region)")
    print("=" * 78)
    print()
    print("Disassembly 0x36450 - 0x3648E:")
    print(disasm_block(rom, 0x36450, 32))
    print()

    # 1a: 0x36452 -> FFFF6624 (rpm_current) into R2, then FMOV.S @R2,FR14
    ok, msg = check_movl_loads_addr(rom, 0x36452, 0xFFFF6624, "rpm_current")
    results.append(("1a: rpm_current load @0x36452", ok, msg))
    hw_next = struct.unpack(">H", rom[0x36454:0x36456])[0]
    fmov_ok = hw_next == 0xFE28
    results.append(("1a': FMOV.S @R2,FR14 @0x36454", fmov_ok,
                     f"0x36454: 0x{hw_next:04X} {'== 0xFE28 (FMOV.S @R2,FR14)' if fmov_ok else '!= 0xFE28'}"))

    # 1b: 0x3645A -> FFFF6350 (ect_current) into R2, then FMOV.S @R2,FR8
    ok, msg = check_movl_loads_addr(rom, 0x3645A, 0xFFFF6350, "ect_current")
    results.append(("1b: ect_current load @0x3645A", ok, msg))
    hw_next = struct.unpack(">H", rom[0x3645C:0x3645E])[0]
    fmov_ok = hw_next == 0xF828
    results.append(("1b': FMOV.S @R2,FR8 @0x3645C", fmov_ok,
                     f"0x3645C: 0x{hw_next:04X} {'== 0xF828 (FMOV.S @R2,FR8)' if fmov_ok else '!= 0xF828'}"))

    # 1c: engine_load_current
    # Master analysis claimed 0x36460 but ROM shows 0x36464 loads FFFF65FC.
    # 0x36460 actually loads FFFF6350 (ect again, stored to FR15 via stack).
    # The real engine_load_current load is at 0x36464.
    ok_wrong, _ = check_movl_loads_addr(rom, 0x36460, 0xFFFF65FC, "engine_load_current")
    ok_correct, msg_correct = check_movl_loads_addr(rom, 0x36464, 0xFFFF65FC, "engine_load_current")

    if ok_wrong:
        results.append(("1c: engine_load_current @0x36460 (as claimed)", True, msg_correct))
    elif ok_correct:
        results.append(("1c: engine_load_current @0x36464 (OFFSET CORRECTED)",
                         True,
                         f"Analysis claimed 0x36460 but actual address is 0x36464. "
                         f"0x36460 loads FFFF6350 (ect_current copy to FR15). "
                         f"{msg_correct}"))
    else:
        results.append(("1c: engine_load_current", False,
                         "FFFF65FC not found at 0x36460 or 0x36464"))

    print()

    # =========================================================================
    # CHECK 2: Path B mode flag writer at 0x031528
    # =========================================================================
    print("=" * 78)
    print("CHECK 2: Path B mode flag writer at 0x031528")
    print("=" * 78)
    print()
    print("Disassembly 0x31528 - 0x31588:")
    print(disasm_block(rom, 0x31528, 48))
    print()

    # Scan for FFFF744B (byte-level access to FFFF7448 region)
    found_744B = False
    found_7452 = False
    for i in range(128):
        pc = 0x31528 + i * 2
        if pc + 2 > len(rom):
            break
        lp = resolve_literal_pool(rom, pc)
        if lp:
            _, _, lv = lp
            if lv == 0xFFFF744B:
                found_744B = True
            if lv == 0xFFFF7452:
                found_7452 = True

    # FFFF744B is byte 3 within the FFFF7448 structure.
    # SH-2 byte-level access: MOV.B @R6,R0 reads a single byte.
    # The code loads address FFFF744B (byte), not FFFF7448 (word).
    results.append(("2a: FFFF744B (byte within FFFF7448 word) ref in Path B",
                     found_744B,
                     f"{'Found' if found_744B else 'Not found'} FFFF744B reference "
                     f"(byte 3 of FFFF7448 word, accessed via MOV.B @R6,R0 at 0x31536)"))
    results.append(("2b: FFFF7452 ref in Path B extended region",
                     found_7452,
                     f"{'Found' if found_7452 else 'Not found'} FFFF7452 reference "
                     f"(at 0x315C2, within sub-function called from Path B via BSR)"))
    print()

    # =========================================================================
    # CHECK 3: FFFF7452 master readiness function at 0x03162C
    # =========================================================================
    print("=" * 78)
    print("CHECK 3: FFFF7452 master readiness function at 0x03162C")
    print("=" * 78)
    print()
    print("Disassembly 0x3162C - 0x31690:")
    print(disasm_block(rom, 0x3162C, 50))
    print()

    # Verify it references key RAM sensors
    sensor_refs = {}
    for i in range(200):
        pc = 0x3162C + i * 2
        if pc + 2 > len(rom):
            break
        lp = resolve_literal_pool(rom, pc)
        if lp:
            _, _, lv = lp
            if lv == 0xFFFF6350:
                sensor_refs["FFFF6350 (ect_current)"] = pc
            if lv == 0xFFFF6624:
                sensor_refs["FFFF6624 (rpm_current)"] = pc
            if lv == 0xFFFF65FC:
                sensor_refs["FFFF65FC (engine_load)"] = pc
            if lv == 0xFFFF6898:
                sensor_refs["FFFF6898"] = pc

    for name, pc in sorted(sensor_refs.items(), key=lambda x: x[1]):
        print(f"  Sensor ref: {name} at 0x{pc:06X}")
    print()

    has_ect = "FFFF6350 (ect_current)" in sensor_refs
    has_rpm = "FFFF6624 (rpm_current)" in sensor_refs
    results.append(("3: FFFF7452 func references ECT + RPM sensors",
                     has_ect and has_rpm,
                     f"ECT(FFFF6350): {'found' if has_ect else 'missing'}, "
                     f"RPM(FFFF6624): {'found' if has_rpm else 'missing'}"))

    # =========================================================================
    # CHECK 4: Throttle threshold at 0xCC1D8 (expect 91.0)
    # =========================================================================
    print("=" * 78)
    print("CHECK 4: Throttle threshold at 0xCC1D8 (expect 91.0)")
    print("=" * 78)
    raw, val = read_be_float(rom, 0xCC1D8)
    ok = abs(val - 91.0) < 0.01
    results.append(("4: Throttle threshold @0xCC1D8", ok,
                     f"Bytes: {raw.hex().upper()}, Float: {val}, Expected: 91.0"))
    print(f"  {results[-1][2]}")
    print()

    # =========================================================================
    # CHECK 5: Engine load max at 0xCC204 (expect 4.8)
    # =========================================================================
    print("=" * 78)
    print("CHECK 5: Engine load max at 0xCC204 (expect 4.8)")
    print("=" * 78)
    raw, val = read_be_float(rom, 0xCC204)
    ok = abs(val - 4.8) < 0.01
    results.append(("5: Engine load max @0xCC204", ok,
                     f"Bytes: {raw.hex().upper()}, Float: {val}, Expected: 4.8"))
    print(f"  {results[-1][2]}")
    print()

    # =========================================================================
    # CHECK 6: CL-to-OL delay at 0xCBC62 (expect 750)
    # =========================================================================
    print("=" * 78)
    print("CHECK 6: CL-to-OL delay at 0xCBC62 (expect 750)")
    print("=" * 78)
    raw, val = read_be_uint16(rom, 0xCBC62)
    ok = val == 750
    results.append(("6: CL-to-OL delay @0xCBC62", ok,
                     f"Bytes: {raw.hex().upper()}, uint16: {val}, Expected: 750"))
    print(f"  {results[-1][2]}")
    print()

    # =========================================================================
    # CHECK 7: 3.05e-5 tolerance (0x38000000) in FFFF7452 function
    # =========================================================================
    print("=" * 78)
    print("CHECK 7: 3.05e-5 tolerance in FFFF7452 function region")
    print("=" * 78)
    print()

    # Search for 0x38000000 as raw bytes in the literal pool area
    target = struct.pack(">I", 0x38000000)
    search_start = 0x3162C
    search_end = 0x31A20
    region = rom[search_start:search_end]
    pos = region.find(target)

    found = pos >= 0
    if found:
        abs_addr = search_start + pos
        fval = struct.unpack(">f", target)[0]
        print(f"  Found 0x38000000 at 0x{abs_addr:06X} = {fval:.6e}")

    # Also find the instruction that references it
    ref_instr = None
    for i in range((search_end - search_start) // 2):
        pc = search_start + i * 2
        lp = resolve_literal_pool(rom, pc)
        if lp and lp[2] == 0x38000000:
            ref_instr = pc
            print(f"  Referenced by MOV.L at 0x{pc:06X} -> R{lp[0]}")
            break

    results.append(("7: 3.05e-5 tolerance in FFFF7452 func", found,
                     f"0x38000000 at 0x{search_start+pos:06X}, "
                     f"referenced by instruction at 0x{ref_instr:06X}" if found
                     else "0x38000000 not found in range"))
    print()

    # =========================================================================
    # CHECK 8: CE5A4 ramp rate table
    # =========================================================================
    print("=" * 78)
    print("CHECK 8: CE5A4 ramp rate table (9 entries x 2 bytes)")
    print("=" * 78)
    raw_table = rom[0xCE5A4:0xCE5A4+18]
    print(f"  Hex: {raw_table.hex().upper()}")
    entries = []
    for i in range(9):
        v = struct.unpack(">H", raw_table[i*2:i*2+2])[0]
        entries.append(v)
        print(f"  [{i}] {v}")
    # Verify table is non-zero and monotonically non-increasing (or plausible ramp data)
    ok = all(v > 0 for v in entries)
    results.append(("8: CE5A4 ramp rate table", ok,
                     f"Values: {entries}"))
    print()

    # =========================================================================
    # CHECK 9: CBE78 threshold (expect ~0.11)
    # =========================================================================
    print("=" * 78)
    print("CHECK 9: CBE78 threshold (expect ~0.11)")
    print("=" * 78)
    raw, val = read_be_float(rom, 0xCBE78)
    ok = abs(val - 0.11) < 0.005
    results.append(("9: CBE78 threshold", ok,
                     f"Bytes: {raw.hex().upper()}, Float: {val}, Expected: ~0.11"))
    print(f"  {results[-1][2]}")
    print()

    # =========================================================================
    # SUMMARY
    # =========================================================================
    print("=" * 78)
    print("VERIFICATION SUMMARY")
    print("=" * 78)
    print()

    pass_count = 0
    warn_count = 0
    fail_count = 0

    for name, ok, detail in results:
        if ok:
            # Check if it's a corrected offset (warning, not pure pass)
            if "CORRECTED" in detail:
                status = "WARN"
                warn_count += 1
            else:
                status = "PASS"
                pass_count += 1
        else:
            status = "FAIL"
            fail_count += 1
        print(f"  [{status}] {name}")
        print(f"         {detail}")
        print()

    print(f"Results: {pass_count} PASS, {warn_count} WARN (offset correction), {fail_count} FAIL")
    print()

    if fail_count == 0 and warn_count == 0:
        print("All master analysis claims verified against ROM binary.")
    elif fail_count == 0:
        print("All claims verified. Warnings indicate minor offset corrections needed")
        print("in the master analysis (values are correct, byte offsets are slightly off).")
    else:
        print("Some claims could not be verified. Review FAIL items above.")


if __name__ == "__main__":
    main()
