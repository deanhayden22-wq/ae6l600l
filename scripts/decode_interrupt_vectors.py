#!/usr/bin/env python3
"""
Decode the SH7058 interrupt/exception vector table.

SH-2A ROM vector table at 0x000000 (when VBR=0 at reset):
  Offset 0x000: Power-on reset initial PC
  Offset 0x004: Power-on reset initial SP
  Offset 0x008: Manual reset initial PC
  Offset 0x00C: Manual reset initial SP
  Offset 0x010: Illegal instruction handler
  Offset 0x014: Illegal slot instruction handler
  Offset 0x018: CPU address error handler
  Offset 0x01C: DMA bus error handler
  Offset 0x020: NMI handler
  Offset 0x024: User break / DBG
  Offset 0x028-0x033: Reserved exception vectors
  Total exception table: 0x000-0x033 (13 entries = 52 bytes)

Then 0x034-0xBAB: System startup data/tables (code after reset)

Peripheral IRQ vectors are at VBR + vector_number * 4.
This script searches for `ldc Rm, VBR` (opcode 0x4?3E) to find where VBR is set,
then decodes the peripheral IRQ table at that address.

SH7058 peripheral vector assignments (from SH7058 Hardware Manual):
  Vector 64+: external IRQs (IRQ0-7)
  Vector 72+: DMAC channels
  Vector 80+: MTU2 (multi-function timer unit)
  Vector 112+: WDT
  Vector 113+: SCI (serial)
  Vector 125+: A/D converter
  Vector 128+: Flash memory
  Vector 130+: CMT (compare match timer — scheduler tick)
  Vector 132+: IIC
  Vector 140+: CAN (RCAN)
"""
import os
import struct
import sys

ROM_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rom")
DISASM_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "disassembly")

def load_rom():
    p = os.path.join(ROM_DIR, "ae5l600l.bin")
    if os.path.isfile(p):
        with open(p, "rb") as f:
            return f.read()
    for fn in sorted(os.listdir(ROM_DIR)):
        if fn.lower().endswith(".bin"):
            with open(os.path.join(ROM_DIR, fn), "rb") as f:
                return f.read()
    sys.exit("No ROM found")


def r_u16(rom, a): return struct.unpack_from(">H", rom, a)[0]
def r_u32(rom, a): return struct.unpack_from(">I", rom, a)[0]


# SH7058 exception vectors (first 13, fixed at VBR + offset)
# Format: (offset, label_suffix, description)
EXCEPTION_VECTORS = [
    (0x000, "RESET_PC",        "Power-on reset initial PC"),
    (0x004, "RESET_SP",        "Power-on reset initial SP"),
    (0x008, "MRESET_PC",       "Manual reset initial PC"),
    (0x00C, "MRESET_SP",       "Manual reset initial SP"),
    (0x010, "ILLEGAL_INSTR",   "Illegal instruction handler"),
    (0x014, "ILLEGAL_SLOT",    "Illegal slot instruction handler"),
    (0x018, "CPU_ADDR_ERR",    "CPU address error handler"),
    (0x01C, "DMA_ADDR_ERR",    "DMA bus error handler"),
    (0x020, "NMI",             "NMI handler"),
    (0x024, "USER_BREAK",      "User break / debug handler"),
    (0x028, "RESERVED_A",      "Reserved exception A"),
    (0x02C, "RESERVED_B",      "Reserved exception B"),
    (0x030, "RESERVED_C",      "Reserved exception C"),
]

# SH7058 peripheral interrupt vector numbers and names
# These are at VBR + vector_number * 4
SH7058_PERIPHERAL_VECS = [
    # External interrupts
    (64, "IRQ0",          "External interrupt IRQ0"),
    (65, "IRQ1",          "External interrupt IRQ1"),
    (66, "IRQ2",          "External interrupt IRQ2"),
    (67, "IRQ3",          "External interrupt IRQ3"),
    (68, "IRQ4",          "External interrupt IRQ4"),
    (69, "IRQ5",          "External interrupt IRQ5"),
    (70, "IRQ6",          "External interrupt IRQ6"),
    (71, "IRQ7",          "External interrupt IRQ7"),
    # DMAC (DMA controller)
    (72, "DMAC0_DEI",     "DMA ch0 transfer end"),
    (73, "DMAC0_HEI",     "DMA ch0 half-end"),
    (74, "DMAC1_DEI",     "DMA ch1 transfer end"),
    (75, "DMAC1_HEI",     "DMA ch1 half-end"),
    (76, "DMAC2_DEI",     "DMA ch2 transfer end"),
    (77, "DMAC2_HEI",     "DMA ch2 half-end"),
    (78, "DMAC3_DEI",     "DMA ch3 transfer end"),
    (79, "DMAC3_HEI",     "DMA ch3 half-end"),
    # MTU2 channel 0
    (80, "MTU0_TGIA0",    "MTU ch0 capture/compare A"),
    (81, "MTU0_TGIB0",    "MTU ch0 capture/compare B"),
    (82, "MTU0_TGIC0",    "MTU ch0 capture/compare C"),
    (83, "MTU0_TGID0",    "MTU ch0 capture/compare D"),
    (84, "MTU0_TCIV0",    "MTU ch0 overflow"),
    (85, "MTU0_TGIE0",    "MTU ch0 capture E"),
    (86, "MTU0_TGIF0",    "MTU ch0 capture F"),
    # MTU2 channel 1
    (87, "MTU1_TGIA1",    "MTU ch1 capture/compare A"),
    (88, "MTU1_TGIB1",    "MTU ch1 capture/compare B"),
    (89, "MTU1_TCIV1",    "MTU ch1 overflow"),
    (90, "MTU1_TCIU1",    "MTU ch1 underflow"),
    # MTU2 channel 2
    (91, "MTU2_TGIA2",    "MTU ch2 capture/compare A"),
    (92, "MTU2_TGIB2",    "MTU ch2 capture/compare B"),
    (93, "MTU2_TCIV2",    "MTU ch2 overflow"),
    (94, "MTU2_TCIU2",    "MTU ch2 underflow"),
    # MTU2 channel 3 (likely crank/cam timing input capture)
    (95, "MTU3_TGIA3",    "MTU ch3 capture/compare A (crank/cam input)"),
    (96, "MTU3_TGIB3",    "MTU ch3 capture/compare B"),
    (97, "MTU3_TGIC3",    "MTU ch3 capture/compare C"),
    (98, "MTU3_TGID3",    "MTU ch3 capture/compare D"),
    (99, "MTU3_TCIV3",    "MTU ch3 overflow"),
    # MTU2 channel 4 (likely injector/ignition output compare)
    (100, "MTU4_TGIA4",   "MTU ch4 capture/compare A (inj/ign output)"),
    (101, "MTU4_TGIB4",   "MTU ch4 capture/compare B"),
    (102, "MTU4_TGIC4",   "MTU ch4 capture/compare C"),
    (103, "MTU4_TGID4",   "MTU ch4 capture/compare D"),
    (104, "MTU4_TCIV4",   "MTU ch4 overflow"),
    # MTU2 channel 5
    (105, "MTU5_TGIU5",   "MTU ch5 input capture U"),
    (106, "MTU5_TGIV5",   "MTU ch5 input capture V"),
    (107, "MTU5_TGIW5",   "MTU ch5 input capture W"),
    # POE
    (108, "POE0_OEI1",    "Port output enable INT1"),
    (109, "POE0_OEI2",    "Port output enable INT2"),
    # WDT
    (112, "WDT_ITI",      "Watchdog timer interval"),
    # SCI channel 0
    (113, "SCI0_ERI",     "SCI ch0 receive error"),
    (114, "SCI0_RXI",     "SCI ch0 receive data full"),
    (115, "SCI0_TXI",     "SCI ch0 transmit data empty"),
    (116, "SCI0_TEI",     "SCI ch0 transmit end"),
    # SCI channel 1
    (117, "SCI1_ERI",     "SCI ch1 receive error"),
    (118, "SCI1_RXI",     "SCI ch1 receive data full"),
    (119, "SCI1_TXI",     "SCI ch1 transmit data empty"),
    (120, "SCI1_TEI",     "SCI ch1 transmit end"),
    # SCI channel 2
    (121, "SCI2_ERI",     "SCI ch2 receive error"),
    (122, "SCI2_RXI",     "SCI ch2 receive data full"),
    (123, "SCI2_TXI",     "SCI ch2 transmit data empty"),
    (124, "SCI2_TEI",     "SCI ch2 transmit end"),
    # ADC
    (125, "ADC0_ADI",     "A/D conversion complete unit 0 (ECU sensor inputs)"),
    (126, "ADC1_ADI",     "A/D conversion complete unit 1"),
    # Flash
    (127, "FLASH_FWER",   "Flash write error"),
    (128, "FLASH_FIFERR", "Flash interface error"),
    (129, "FLASH_FRDYR",  "Flash ready"),
    # CMT (Compare Match Timer — this drives the ECU task scheduler)
    (130, "CMT0_CMTI",    "Compare match timer 0 interrupt (task scheduler tick)"),
    (131, "CMT1_CMTI",    "Compare match timer 1 interrupt"),
    # IIC
    (132, "IIC0_STPI",    "IIC ch0 stop condition"),
    (133, "IIC0_NAKI",    "IIC ch0 NAK"),
    (134, "IIC0_RXI",     "IIC ch0 receive"),
    (135, "IIC0_TXI",     "IIC ch0 transmit"),
    (136, "IIC0_TEI",     "IIC ch0 transmit end"),
    # SSU
    (137, "SSU0_SSERI",   "SSU ch0 error"),
    (138, "SSU0_SSRXI",   "SSU ch0 receive"),
    (139, "SSU0_SSTXI",   "SSU ch0 transmit"),
    # CAN (RCAN)
    (140, "RCAN0_ERS",    "RCAN ch0 error/status"),
    (141, "RCAN0_OVR",    "RCAN ch0 overrun"),
    (142, "RCAN0_RM0",    "RCAN ch0 receive mailbox 0"),
    (143, "RCAN0_RM1",    "RCAN ch0 receive mailbox 1"),
    (144, "RCAN0_SLE",    "RCAN ch0 sleep"),
    (145, "RCAN1_ERS",    "RCAN ch1 error/status"),
    (146, "RCAN1_OVR",    "RCAN ch1 overrun"),
    (147, "RCAN1_RM0",    "RCAN ch1 receive mailbox 0"),
    (148, "RCAN1_RM1",    "RCAN ch1 receive mailbox 1"),
    (149, "RCAN1_SLE",    "RCAN ch1 sleep"),
]

VEC_NAME = {v: n for v, n, d in SH7058_PERIPHERAL_VECS}
VEC_DESC = {v: d for v, n, d in SH7058_PERIPHERAL_VECS}


def find_vbr_setup(rom):
    """Find `ldc Rm, VBR` instructions (opcode 0x4m3E) in startup code."""
    rom_len = len(rom)
    results = []
    # Look in startup region: 0x000-0xBAC
    for pc in range(0x034, min(0xBAC, rom_len - 1), 2):
        word = r_u16(rom, pc)
        if (word & 0xF0FF) == 0x403E:  # ldc Rm, VBR: 0100 mmmm 0011 1110
            rm = (word >> 8) & 0xF
            results.append((pc, rm, word))

    # Also search wider if not found
    if not results:
        for pc in range(0, min(0x2000, rom_len - 1), 2):
            word = r_u16(rom, pc)
            if (word & 0xF0FF) == 0x403E:
                rm = (word >> 8) & 0xF
                results.append((pc, rm, word))
    return results


def trace_vbr_value(rom, ldc_pc, reg):
    """Trace backwards from ldc_pc to find the value loaded into reg before ldc."""
    # Look back up to 32 instructions for mov.l @(disp,PC), Rn then ldc
    for back in range(2, 64, 2):
        pc = ldc_pc - back
        if pc < 0:
            break
        word = r_u16(rom, pc)
        # mov.l @(disp, PC), Rn  -- opcode 1101 nnnn dddddddd
        if (word >> 12) == 0xD:
            rn = (word >> 8) & 0xF
            if rn == reg:
                disp = word & 0xFF
                lit_pc = (pc & ~3) + 4 + disp * 4
                if lit_pc + 4 <= len(rom):
                    val = r_u32(rom, lit_pc)
                    return val, lit_pc
        # mov Rm, Rn (6nm3 pattern) — might relay through another register
        if (word >> 12) == 0x6 and (word & 0xF) == 0x3:
            rn = (word >> 8) & 0xF
            if rn == reg:
                reg = (word >> 4) & 0xF  # follow the source register
    return None, None


def decode_vbr_table(rom, vbr):
    """Decode peripheral interrupt vector table at vbr."""
    rom_len = len(rom)
    results = []
    for vec_num, name, desc in SH7058_PERIPHERAL_VECS:
        offset = vbr + vec_num * 4
        if offset + 4 > rom_len:
            continue
        handler = r_u32(rom, offset)
        results.append((vec_num, offset, handler, name, desc))
    return results


def is_valid_code_addr(addr, rom_len):
    return 0 < addr < rom_len


def main():
    rom = load_rom()
    rom_len = len(rom)
    print(f"Loaded ROM: {rom_len} bytes\n")

    OUTPUT_FILE = os.path.join(DISASM_DIR, "interrupt_vectors.txt")
    LABEL_FILE = os.path.join(DISASM_DIR, "isr_labels.txt")

    # Step 1: Decode exception vector table (fixed at ROM 0x000000)
    print("=" * 80)
    print("EXCEPTION VECTOR TABLE (ROM 0x000000, fixed at reset VBR=0)")
    print("=" * 80)
    print(f"{'Offset':>8} {'Value':>12}  {'Label':<25} Description")
    print("-" * 80)

    exception_handlers = []  # (addr, name, desc)
    for offset, label, desc in EXCEPTION_VECTORS:
        val = r_u32(rom, offset)
        val_str = f"0x{val:08X}"
        is_addr = (offset >= 0x010) and is_valid_code_addr(val, rom_len)
        marker = " <-- handler" if is_addr else ""
        print(f"  0x{offset:04X}  {val_str}  {label:<25} {desc}{marker}")
        if is_addr:
            exception_handlers.append((val, f"exc_{label}", desc))

    # Step 2: Find VBR setup
    print(f"\n{'='*80}")
    print("VBR SETUP (searching for `ldc Rm, VBR` in startup code)")
    print("=" * 80)

    vbr_instructions = find_vbr_setup(rom)
    vbr_value = None

    for pc, rm, opcode in vbr_instructions:
        val, lit_pc = trace_vbr_value(rom, pc, rm)
        if val is not None:
            print(f"  0x{pc:06X}: ldc R{rm}, VBR  (opcode 0x{opcode:04X})")
            print(f"           R{rm} loaded from literal pool at 0x{lit_pc:06X} = 0x{val:08X}")
            if is_valid_code_addr(val, rom_len) or val == 0:
                vbr_value = val
                print(f"           => VBR = 0x{val:08X}")
        else:
            print(f"  0x{pc:06X}: ldc R{rm}, VBR (value unknown)")

    if vbr_value is None:
        print("  Could not determine VBR value. Assuming VBR = 0x000000 (default).")
        vbr_value = 0

    # Step 3: Decode peripheral ISR table
    print(f"\n{'='*80}")
    print(f"PERIPHERAL ISR TABLE (at VBR=0x{vbr_value:08X})")
    print("=" * 80)

    isr_entries = decode_vbr_table(rom, vbr_value)

    active_isrs = []
    print(f"\n{'Vec':>5} {'ROM Offset':>12} {'Handler':>12}  {'ISR Name':<22} Description")
    print("-" * 80)

    for vec_num, offset, handler, name, desc in isr_entries:
        if not is_valid_code_addr(handler, rom_len):
            continue
        # Skip obvious non-code (unlikely to be real handlers)
        active_isrs.append((vec_num, offset, handler, name, desc))
        print(f"  {vec_num:>3}  0x{offset:06X}  0x{handler:08X}  {name:<22} {desc}")

    print(f"\nFound {len(active_isrs)} active peripheral ISR handlers")

    # Step 4: Find unique handler addresses and detect shared ISRs
    handler_map = {}
    for vec_num, offset, handler, name, desc in active_isrs:
        handler_map.setdefault(handler, []).append((name, desc))

    shared = {h: names for h, names in handler_map.items() if len(names) > 1}
    if shared:
        print(f"\nShared ISR handlers (same function for multiple interrupts):")
        for handler, names in sorted(shared.items()):
            print(f"  0x{handler:06X}  <- {', '.join(n for n, d in names)}")

    # Step 5: Generate Java label block
    label_lines = []
    label_lines.append("        // ============================================================")
    label_lines.append("        // SH7058 EXCEPTION + PERIPHERAL ISR ENTRY POINTS")
    label_lines.append("        // Exception table fixed at ROM 0x000000 (VBR=0 at reset)")
    label_lines.append("        // ============================================================")
    label_lines.append("")

    label_lines.append("        // Exception vector table entries (ROM 0x000-0x033)")
    for offset, label, desc in EXCEPTION_VECTORS:
        val = r_u32(rom, offset)
        label_lines.append(
            f"        count += labelComment(0x{offset:06X}L, \"vtbl_{label}\", \"{desc} = 0x{val:08X}\");"
        )
    label_lines.append("")

    label_lines.append("        // Exception handler entry points (code in ROM)")
    for handler, name, desc in exception_handlers:
        label_lines.append(
            f"        count += labelComment(0x{handler:06X}L, \"{name}\", \"{desc}\");"
        )
    label_lines.append("")

    label_lines.append(f"        // Peripheral ISR handlers (VBR=0x{vbr_value:06X})")
    seen = set()
    for vec_num, offset, handler, name, desc in sorted(active_isrs, key=lambda x: x[2]):
        if handler not in seen:
            seen.add(handler)
            label_lines.append(
                f"        count += labelComment(0x{handler:06X}L, \"isr_{name}\", \"vec{vec_num}: {desc}\");"
            )

    with open(LABEL_FILE, 'w') as f:
        f.write('\n'.join(label_lines))
        f.write('\n')
    print(f"\nJava label block written to {LABEL_FILE}")

    # Step 6: Save full report
    with open(OUTPUT_FILE, 'w') as f:
        f.write("SH7058 INTERRUPT VECTOR TABLE -- AE5L600L\n")
        f.write("=" * 80 + "\n\n")

        f.write("EXCEPTION VECTOR TABLE (ROM 0x000000)\n")
        f.write("-" * 80 + "\n")
        for offset, label, desc in EXCEPTION_VECTORS:
            val = r_u32(rom, offset)
            f.write(f"  0x{offset:04X}  0x{val:08X}  {label:<25} {desc}\n")

        f.write(f"\nPERIPHERAL ISR TABLE (VBR=0x{vbr_value:08X})\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'Vec':>5} {'ROM Offset':>12} {'Handler':>12}  {'ISR Name':<22} Description\n")
        f.write("-" * 80 + "\n")
        for vec_num, offset, handler, name, desc in active_isrs:
            f.write(f"  {vec_num:>3}  0x{offset:06X}  0x{handler:08X}  {name:<22} {desc}\n")

        f.write(f"\nTotal active ISRs: {len(active_isrs)}\n")
        f.write(f"Unique handler addresses: {len(seen)}\n")

        if shared:
            f.write("\nShared handlers:\n")
            for handler, names in sorted(shared.items()):
                f.write(f"  0x{handler:06X}  <- {', '.join(n for n, d in names)}\n")

    print(f"Report written to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
