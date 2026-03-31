#!/usr/bin/env python3
"""
Scan AE5L600L ROM for ADC peripheral register references and interrupt vectors.

SH7055/SH7058 ADC Register Map (from nissutils/Renesas HW manual):
  ADC Data Registers:
    0xFFFFF800-0xFFFFF817: ADDR0-ADDR11 (Group 0, channels 0-11)
    0xFFFFF820-0xFFFFF837: ADDR12-ADDR23 (Group 1, channels 12-23)
    0xFFFFF840-0xFFFFF84F: ADDR24-ADDR31 (Group 2, channels 24-31)
  ADC Control/Status:
    0xFFFFF818: ADCSR0  (Group 0 control/status)
    0xFFFFF819: ADCR0   (Group 0 control)
    0xFFFFF838: ADCSR1  (Group 1 control/status)
    0xFFFFF839: ADCR1   (Group 1 control)
    0xFFFFF858: ADCSR2  (Group 2 control/status)
    0xFFFFF859: ADCR2   (Group 2 control)
  ADC Trigger:
    0xFFFFF72E: ADTRGR1
    0xFFFFF72F: ADTRGR2
    0xFFFFF76E: ADTRG0
"""
import struct
import sys
import os

ROM_PATH = os.path.join(os.path.dirname(__file__), "..", "rom", "ae5l600l.bin")

# ADC register definitions
ADC_REGS = {}
# Group 0: ADDR0-ADDR11
for i in range(12):
    ADC_REGS[0xFFFFF800 + i*2] = f"ADDR{i}H"
    ADC_REGS[0xFFFFF800 + i*2 + 1] = f"ADDR{i}L"
# Group 1: ADDR12-ADDR23
for i in range(12):
    ADC_REGS[0xFFFFF820 + i*2] = f"ADDR{12+i}H"
    ADC_REGS[0xFFFFF820 + i*2 + 1] = f"ADDR{12+i}L"
# Group 2: ADDR24-ADDR31
for i in range(8):
    ADC_REGS[0xFFFFF840 + i*2] = f"ADDR{24+i}H"
    ADC_REGS[0xFFFFF840 + i*2 + 1] = f"ADDR{24+i}L"
# Control registers
ADC_REGS[0xFFFFF818] = "ADCSR0"
ADC_REGS[0xFFFFF819] = "ADCR0"
ADC_REGS[0xFFFFF838] = "ADCSR1"
ADC_REGS[0xFFFFF839] = "ADCR1"
ADC_REGS[0xFFFFF858] = "ADCSR2"
ADC_REGS[0xFFFFF859] = "ADCR2"
ADC_REGS[0xFFFFF72E] = "ADTRGR1"
ADC_REGS[0xFFFFF72F] = "ADTRGR2"
ADC_REGS[0xFFFFF76E] = "ADTRG0"

# Other peripheral registers of interest
PERIPH_REGS = {
    0xFFFFED00: "IPRA", 0xFFFFED02: "IPRB", 0xFFFFED04: "IPRC",
    0xFFFFED06: "IPRD", 0xFFFFED08: "IPRE", 0xFFFFED0A: "IPRF",
    0xFFFFED0C: "IPRG", 0xFFFFED0E: "IPRH", 0xFFFFED10: "IPRI",
    0xFFFFED12: "IPRJ", 0xFFFFED14: "IPRK", 0xFFFFED16: "IPRL",
    0xFFFFED18: "ICR",  0xFFFFED1A: "ISR",
}
ADC_REGS.update(PERIPH_REGS)

# SH7055/SH7058 Interrupt vector table assignments (peripheral interrupts)
# Based on SH7055 hardware manual - vectors start at specific numbers
# Each vector = 4 bytes at address (vector_number * 4)
# Standard SH7055 peripheral interrupt vectors:
VECTOR_NAMES = {
    0: "Power-On Reset PC",
    1: "Power-On Reset SP",
    2: "Manual Reset PC",
    3: "Manual Reset SP",
    4: "General Illegal Instruction",
    5: "Reserved",
    6: "Slot Illegal Instruction",
    7: "Reserved",
    8: "Reserved",
    9: "CPU Address Error",
    10: "DMA Address Error",
    11: "NMI",
    12: "User Break",
    # 13-31: Reserved
    # 32-63: TRAPA #0-31
    # 64+: External/peripheral interrupts
    64: "IRQ0", 65: "IRQ1", 66: "IRQ2", 67: "IRQ3",
    68: "IRQ4", 69: "IRQ5", 70: "IRQ6", 71: "IRQ7",
    # DMAC
    72: "DMAC0_DEI0", 73: "DMAC0_HEI0",
    74: "DMAC1_DEI1", 75: "DMAC1_HEI1",
    76: "DMAC2_DEI2", 77: "DMAC2_HEI2",
    78: "DMAC3_DEI3", 79: "DMAC3_HEI3",
    # ATU (Advanced Timer Unit)
    80: "ATU0_ITV",
    # ATU-II channels
    84: "ATU1_IMI0A", 85: "ATU1_IMI0B", 86: "ATU1_IMI0C", 87: "ATU1_IMI0D",
    88: "ATU1_OV0",
    92: "ATU2_IMI1A", 93: "ATU2_IMI1B", 94: "ATU2_IMI1C", 95: "ATU2_IMI1D",
    96: "ATU2_OV1",
    100: "ATU3_IMI2A", 101: "ATU3_IMI2B", 102: "ATU3_IMI2C", 103: "ATU3_IMI2D",
    104: "ATU3_OV2",
    108: "ATU4_IMI3A", 109: "ATU4_IMI3B", 110: "ATU4_IMI3C", 111: "ATU4_IMI3D",
    112: "ATU4_OV3",
    116: "ATU5_IMI4A", 117: "ATU5_IMI4B", 118: "ATU5_IMI4C", 119: "ATU5_IMI4D",
    120: "ATU5_OV4",
    # ATU-III
    124: "ATU6_CMI5A", 125: "ATU6_CMI5B", 126: "ATU6_CMI5C", 127: "ATU6_CMI5D",
    128: "ATU6_OV5",
    132: "ATU7_CMI6A", 133: "ATU7_CMI6B", 134: "ATU7_CMI6C", 135: "ATU7_CMI6D",
    136: "ATU7_OV6",
    140: "ATU8_CMI7A", 141: "ATU8_CMI7B", 142: "ATU8_CMI7C", 143: "ATU8_CMI7D",
    144: "ATU8_OV7",
    148: "ATU9_CMI8AE", 149: "ATU9_CMI8BF", 150: "ATU9_CMI8CG", 151: "ATU9_CMI8DH",
    152: "ATU9_OV8",
    156: "ATU10_CMI9A", 157: "ATU10_CMI9B", 158: "ATU10_CMI9C", 159: "ATU10_CMI9D",
    160: "ATU10_OV9",
    164: "ATU11_CMI10AE", 165: "ATU11_CMI10BF",
    168: "ATU11_CMI11AE", 169: "ATU11_CMI11BF",
    # CMT (Compare Match Timer)
    172: "CMT_CMI0", 173: "CMT_CMI1",
    # A/D Converter interrupts
    176: "ADI0",  # A/D Group 0 conversion complete
    177: "ADI1",  # A/D Group 1 conversion complete
    # SCI (Serial Communication Interface)
    180: "SCI0_ERI0", 181: "SCI0_RXI0", 182: "SCI0_TXI0", 183: "SCI0_TEI0",
    184: "SCI1_ERI1", 185: "SCI1_RXI1", 186: "SCI1_TXI1", 187: "SCI1_TEI1",
    188: "SCI2_ERI2", 189: "SCI2_RXI2", 190: "SCI2_TXI2", 191: "SCI2_TEI2",
    192: "SCI3_ERI3", 193: "SCI3_RXI3", 194: "SCI3_TXI3", 195: "SCI3_TEI3",
    # HCAN
    196: "HCAN0",
    200: "HCAN1",
    # WDT
    204: "WDT_ITI",
}


def load_rom(path):
    with open(path, "rb") as f:
        return f.read()


def scan_literal_pools(rom):
    """Scan for 32-bit literal pool values that reference ADC peripheral registers.

    SH-2 uses mov.l @(disp,PC),Rn to load 32-bit constants from literal pools.
    Opcode: 1101nnnndddddddd  (0xDndd)
    The literal address = (PC & ~3) + 4 + disp*4
    """
    results = []
    rom_size = len(rom)

    for pc in range(0, rom_size - 2, 2):
        insn = struct.unpack_from(">H", rom, pc)[0]
        # mov.l @(disp,PC),Rn => 0xDndd
        if (insn >> 12) == 0xD:
            rn = (insn >> 8) & 0xF
            disp = insn & 0xFF
            lit_addr = (pc & ~3) + 4 + disp * 4
            if lit_addr + 4 <= rom_size:
                value = struct.unpack_from(">I", rom, lit_addr)[0]
                # Check if value points to ADC register range
                if value in ADC_REGS:
                    results.append((pc, rn, lit_addr, value, ADC_REGS[value]))
                # Also check for base addresses that could be used with offsets
                # Common pattern: load 0xFFFFF800 then add offset
                elif 0xFFFFF700 <= value <= 0xFFFFF860:
                    name = ADC_REGS.get(value, f"PERIPH_{value:08X}")
                    results.append((pc, rn, lit_addr, value, name))
    return results


def scan_gbr_relative(rom):
    """Scan for GBR-relative accesses that might target ADC registers.

    mov.b @(disp,GBR),R0 => 0xC4dd
    mov.w @(disp,GBR),R0 => 0xC5dd
    mov.l @(disp,GBR),R0 => 0xC6dd
    mov.b R0,@(disp,GBR) => 0xC0dd
    mov.w R0,@(disp,GBR) => 0xC1dd
    mov.l R0,@(disp,GBR) => 0xC2dd
    """
    # GBR-relative accesses use small displacements from GBR value,
    # they won't directly address 0xFFFFF8xx unless GBR is set near there
    # This is less likely for ADC - more likely used for RAM variables
    pass


def dump_vector_table(rom, max_vector=220):
    """Dump the full interrupt vector table."""
    print("\n" + "="*80)
    print("FULL INTERRUPT VECTOR TABLE")
    print("="*80)

    # Track unique handler addresses
    handler_counts = {}

    for vec in range(min(max_vector, len(rom) // 4)):
        addr = vec * 4
        value = struct.unpack_from(">I", rom, addr)[0]
        name = VECTOR_NAMES.get(vec, "")

        # Skip reserved/zero vectors
        if value == 0 and not name:
            continue

        # Count handler addresses
        if value < 0x100000:  # Valid ROM address
            handler_counts[value] = handler_counts.get(value, 0) + 1

        # Only print vectors with valid handlers or known names
        if value != 0 or name:
            flag = ""
            if value == 0x00000BFA:
                flag = " [DefaultExceptionHandler]"
            elif value == 0x00000BAC:
                flag = " [NMI Handler]"
            elif value == 0x00000C0C:
                flag = " [Reset Entry]"
            elif 13 <= vec <= 31 and value == 0:
                continue  # Skip empty reserved vectors

            print(f"  Vec {vec:3d} (0x{addr:03X}): 0x{value:08X}  {name}{flag}")

    # Print handler frequency analysis
    print(f"\n" + "-"*60)
    print("Handler Frequency Analysis (excluding DefaultExceptionHandler):")
    for handler, count in sorted(handler_counts.items(), key=lambda x: -x[1]):
        if handler != 0x00000BFA and count > 1:
            print(f"  0x{handler:08X}: used by {count} vectors")


def scan_shll8_pattern(rom):
    """Scan for the shll8 pattern used to construct peripheral base addresses.

    Common SH pattern for peripheral access:
      mov #0xF8, rn     ; 0xE_F8 -> rn = 0xFFFFFFF8
      shll8 rn          ; rn = 0xFFFFF800 (ADDR0 base!)
    Or:
      mov #-8, rn       ; rn = 0xFFFFFFF8
      shll8 rn          ; rn = 0xFFFFF800
    """
    results = []
    rom_size = len(rom)

    for pc in range(0, rom_size - 4, 2):
        insn1 = struct.unpack_from(">H", rom, pc)[0]
        insn2 = struct.unpack_from(">H", rom, pc + 2)[0]

        # mov #imm, Rn => 0xEnii (sign-extended 8-bit)
        if (insn1 >> 12) == 0xE:
            rn1 = (insn1 >> 8) & 0xF
            imm = insn1 & 0xFF
            if imm & 0x80:
                imm_se = imm | 0xFFFFFF00  # sign extend
            else:
                imm_se = imm

            # shll8 Rn => 0x4n18
            if insn2 == (0x4000 | (rn1 << 8) | 0x18):
                shifted = (imm_se << 8) & 0xFFFFFFFF
                # Check if this creates an address in the peripheral range
                if 0xFFFFF700 <= shifted <= 0xFFFFF860:
                    reg_name = ADC_REGS.get(shifted, f"PERIPH_{shifted:08X}")
                    results.append((pc, rn1, shifted, reg_name))
                # Also check for 0xFFFFE400-0xFFFFEFFF (INTC, DMAC, etc.)
                elif 0xFFFFE000 <= shifted <= 0xFFFFF000:
                    results.append((pc, rn1, shifted, f"PERIPH_{shifted:08X}"))

    return results


def scan_shll16_pattern(rom):
    """Scan for shll16 pattern: mov #imm, rn; shll16 rn; shll8 rn

    This constructs addresses like 0xFFFF0000 then shifts further.
    """
    results = []
    rom_size = len(rom)

    for pc in range(0, rom_size - 6, 2):
        insn1 = struct.unpack_from(">H", rom, pc)[0]
        insn2 = struct.unpack_from(">H", rom, pc + 2)[0]

        if (insn1 >> 12) == 0xE:
            rn1 = (insn1 >> 8) & 0xF
            imm = insn1 & 0xFF
            if imm & 0x80:
                imm_se = imm | 0xFFFFFF00
            else:
                imm_se = imm

            # shll16 Rn => 0x4n28
            if insn2 == (0x4000 | (rn1 << 8) | 0x28):
                shifted16 = (imm_se << 16) & 0xFFFFFFFF
                if 0xFFFF0000 <= shifted16 <= 0xFFFFFFFF:
                    results.append((pc, rn1, shifted16, "base_after_shll16"))

    return results


def main():
    rom = load_rom(ROM_PATH)
    print(f"ROM loaded: {len(rom)} bytes ({len(rom)/1024:.0f} KB)")

    # 1. Dump full vector table
    dump_vector_table(rom)

    # 2. Scan literal pools for ADC register references
    print("\n" + "="*80)
    print("LITERAL POOL REFERENCES TO ADC/PERIPH REGISTERS")
    print("="*80)
    lit_refs = scan_literal_pools(rom)
    if lit_refs:
        for pc, rn, lit_addr, value, name in lit_refs:
            print(f"  0x{pc:05X}: mov.l @(0x{lit_addr:05X}),r{rn}  ; r{rn} = 0x{value:08X} ({name})")
    else:
        print("  No literal pool references to ADC registers found.")

    # 3. Scan for shll8 patterns constructing peripheral addresses
    print("\n" + "="*80)
    print("SHLL8 PATTERN: mov #imm,Rn; shll8 Rn -> PERIPHERAL ADDRESS")
    print("="*80)
    shll8_refs = scan_shll8_pattern(rom)
    if shll8_refs:
        for pc, rn, addr, name in shll8_refs:
            print(f"  0x{pc:05X}: mov #0x{(addr >> 8) & 0xFF:02X},r{rn}; shll8 -> 0x{addr:08X} ({name})")
    else:
        print("  No shll8 patterns found constructing ADC addresses.")

    # 4. Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)

    # Collect all ADC-referencing code locations
    all_adc_locs = set()
    for pc, rn, lit_addr, value, name in lit_refs:
        if "ADDR" in name or "ADCSR" in name or "ADCR" in name:
            all_adc_locs.add(pc)
    for pc, rn, addr, name in shll8_refs:
        if "ADDR" in name or "ADCSR" in name or "ADCR" in name:
            all_adc_locs.add(pc)

    print(f"  Total ADC register references found: {len(all_adc_locs)}")
    print(f"  Total peripheral register refs (literal pool): {len(lit_refs)}")
    print(f"  Total peripheral address constructions (shll8): {len(shll8_refs)}")


if __name__ == "__main__":
    main()
