#!/usr/bin/env python3
"""
Comprehensive ADC pipeline analysis for AE5L600L ROM.
Traces: ADC hardware registers -> raw conversion -> GBR-relative RAM -> sensor variables.

Key discoveries from adc_disasm.py:
  1. Bulk ADC reader at ~0x04140: reads all ADC channels, stores to GBR-relative RAM
  2. Knock ADC reader at 0x0437C: re-reads Group 0 for knock detection -> 0xFFFF4064
  3. Group 1 reader at 0x04410: reads Group 1 for multi-cylinder -> 0xFFFF407C
  4. VBR set to 0x000FFC50 at 0x0FA40 (peripheral interrupt vector base)
"""
import os
import struct

ROM_PATH = os.path.join(os.path.dirname(__file__), "..", "rom", "ae5l600l.bin")


def load_rom():
    with open(ROM_PATH, "rb") as f:
        return f.read()


def dump_vbr_vector_table(rom, vbr=0x000FFC50):
    """Dump the peripheral interrupt vector table at VBR."""
    print("="*80)
    print(f"PERIPHERAL INTERRUPT VECTOR TABLE (VBR = 0x{vbr:08X})")
    print("="*80)

    # SH7055 interrupt vector assignments (from hardware manual)
    sh7055_vectors = {
        # IRQ
        64: "IRQ0", 65: "IRQ1", 66: "IRQ2", 67: "IRQ3",
        68: "IRQ4", 69: "IRQ5", 70: "IRQ6", 71: "IRQ7",
        # DMAC
        72: "DMAC_DEI0", 73: "DMAC_HEI0", 74: "DMAC_DEI1", 75: "DMAC_HEI1",
        76: "DMAC_DEI2", 77: "DMAC_HEI2", 78: "DMAC_DEI3", 79: "DMAC_HEI3",
        # ATU-I interval timer
        80: "ATU_ITV",
        # ATU-II
        84: "ATU_IMI0A", 85: "ATU_IMI0B", 86: "ATU_IMI0C", 87: "ATU_IMI0D", 88: "ATU_OV0",
        92: "ATU_IMI1A", 93: "ATU_IMI1B", 94: "ATU_IMI1C", 95: "ATU_IMI1D", 96: "ATU_OV1",
        100: "ATU_IMI2A", 101: "ATU_IMI2B", 102: "ATU_IMI2C", 103: "ATU_IMI2D", 104: "ATU_OV2",
        108: "ATU_IMI3A", 109: "ATU_IMI3B", 110: "ATU_IMI3C", 111: "ATU_IMI3D", 112: "ATU_OV3",
        116: "ATU_IMI4A", 117: "ATU_IMI4B", 118: "ATU_IMI4C", 119: "ATU_IMI4D", 120: "ATU_OV4",
        # ATU-III
        124: "ATU_CMI5A", 125: "ATU_CMI5B", 126: "ATU_CMI5C", 127: "ATU_CMI5D", 128: "ATU_OV5",
        132: "ATU_CMI6A", 133: "ATU_CMI6B", 134: "ATU_CMI6C", 135: "ATU_CMI6D", 136: "ATU_OV6",
        140: "ATU_CMI7A", 141: "ATU_CMI7B", 142: "ATU_CMI7C", 143: "ATU_CMI7D", 144: "ATU_OV7",
        # ATU-IV
        148: "ATU_CMI8AE", 149: "ATU_CMI8BF", 150: "ATU_CMI8CG", 151: "ATU_CMI8DH", 152: "ATU_OV8",
        156: "ATU_CMI9A", 157: "ATU_CMI9B", 158: "ATU_CMI9C", 159: "ATU_CMI9D", 160: "ATU_OV9",
        164: "ATU_CMI10AE", 165: "ATU_CMI10BF",
        168: "ATU_CMI11AE", 169: "ATU_CMI11BF",
        # CMT
        172: "CMT_CMI0", 173: "CMT_CMI1",
        # A/D Converter
        176: "ADI0", 177: "ADI1",
        # SCI
        180: "SCI_ERI0", 181: "SCI_RXI0", 182: "SCI_TXI0", 183: "SCI_TEI0",
        184: "SCI_ERI1", 185: "SCI_RXI1", 186: "SCI_TXI1", 187: "SCI_TEI1",
        188: "SCI_ERI2", 189: "SCI_RXI2", 190: "SCI_TXI2", 191: "SCI_TEI2",
        192: "SCI_ERI3", 193: "SCI_RXI3", 194: "SCI_TXI3", 195: "SCI_TEI3",
        # HCAN
        196: "HCAN0_OVR_RM", 200: "HCAN1_OVR_RM",
        # WDT
        204: "WDT_ITI",
    }

    default_handler = 0x00000BFA  # DefaultExceptionHandler

    for vec_num in sorted(sh7055_vectors.keys()):
        rom_offset = vbr + vec_num * 4
        if rom_offset + 4 > len(rom):
            continue
        handler = struct.unpack_from(">I", rom, rom_offset)[0]
        name = sh7055_vectors[vec_num]

        # Only print non-default handlers (interesting ones)
        flag = ""
        if handler == default_handler:
            flag = " [default/unused]"
        elif handler < 0x100000:
            flag = " *** ACTIVE ***"
        elif handler > 0xFFFF0000:
            flag = " [RAM handler]"

        if handler != default_handler or "ADI" in name or "IRQ" in name:
            print(f"  Vec {vec_num:3d}: {name:20s} -> 0x{handler:08X}{flag}")

    # Specifically check ADI0 and ADI1
    print(f"\n--- A/D Converter Interrupt Handlers ---")
    for vec_num, name in [(176, "ADI0"), (177, "ADI1")]:
        rom_offset = vbr + vec_num * 4
        if rom_offset + 4 <= len(rom):
            handler = struct.unpack_from(">I", rom, rom_offset)[0]
            print(f"  {name}: VBR+0x{vec_num*4:03X} = ROM 0x{rom_offset:05X} -> handler 0x{handler:08X}")
        else:
            print(f"  {name}: ROM offset 0x{rom_offset:05X} is BEYOND ROM!")


def find_gbr_context(rom, target_addr):
    """Search backward from target_addr to find where GBR is set."""
    # Look for 'ldc Rn,GBR' (0x4n1E) before the target
    results = []
    for pc in range(max(0, target_addr - 0x200), target_addr, 2):
        code = struct.unpack_from(">H", rom, pc)[0]
        if (code & 0xF0FF) == 0x401E:
            rn = (code >> 8) & 0xF
            # Look backward for how rn was set
            results.append((pc, rn))
    return results


def analyze_adc_bulk_read(rom):
    """Analyze the bulk ADC read function around 0x04140."""
    print("\n" + "="*80)
    print("ADC BULK READ FUNCTION ANALYSIS")
    print("="*80)

    # The bulk read function at 0x04178 reads ADDR0-ADDR11 to GBR+0..GBR+22
    # Then reads from r12 (Group 1 base) to GBR+24..GBR+46
    # Then reads from r11 (Group 2 base?) to GBR+48+

    print("\nGroup 0 ADC Channel Mapping (from 0x04178):")
    print("  ADC Base: r14 = 0xFFFFF800")
    print("  Storage: GBR-relative (GBR = context struct base)")
    print()
    for i in range(12):
        src_offset = i * 2
        gbr_offset = i * 2
        print(f"  ADDR{i:2d} (0xFFFFF{0x800+src_offset:03X}) -> GBR+{gbr_offset:3d} (0x{gbr_offset:02X})")

    print()
    print("Group 1 ADC Channel Mapping (from r12 base):")
    print("  ADC Base: r12 = 0xFFFFF820 (ADDR12)")
    print("  Storage: GBR+24 to GBR+46")
    print()
    # r12 base is ADDR12 (0xFFFFF820), with word offsets
    for i in range(12):
        src_reg = f"r12+{8+i*2}"  # starts at @(8,r12) = r12+8
        gbr_offset = 24 + i * 2
        ch = 12 + i
        # The code reads @(8+i*2, r12), but r12 = ADDR12 base (0xFFFFF820)
        # Actually looking at the code: 85C4 = mov.w @(8,r12),r0
        # If r12 = 0xFFFFF820, then @(8,r12) = 0xFFFFF828 = ADDR16H
        # But that doesn't match sequential channels...

    # Let me re-examine. r12 might be ADDR12 base (0xFFFFF820)
    # 0x041AE: 85C4 = mov.w @(8,r12),r0 -> stores to GBR+24
    # @(8,r12) with r12=0xFFFFF820 = 0xFFFFF828 = ADDR16H
    # 0x041B2: 85C5 = mov.w @(10,r12),r0 -> stores to GBR+26
    # @(10,r12) = 0xFFFFF82A = ADDR17H
    # etc.

    # But wait - maybe r12 is set to 0xFFFFF820 earlier, and the offset starts
    # at 8 because ADDR12-15 were read differently?
    # With r12=0xFFFFF820: @(0,r12)=ADDR12, @(2)=ADDR13, @(4)=ADDR14, @(6)=ADDR15
    # @(8)=ADDR16, @(10)=ADDR17, ...
    # But the code starts at @(8,r12) for GBR+24...
    # This means ADDR12-15 might be read elsewhere, or r12 might be a different value.

    # Actually let me check: before the ADC read, r14 is used for ADCSR polling.
    # @(1,r14) is written with config, @r14 is written with 0x2B.
    # If r14 was initially ADCSR0 (0xFFFFF818), then @r14 = ADCSR0, @(1,r14) = ADCR0
    # Then r14 is reloaded as 0xFFFFF800 at 0x04178.
    # Similarly r12 and r11 were used for polling other ADCSRs.

    print("  (r12 base needs context - checking Group 1 read from r12)")
    print("  GBR+24: @(8,r12)  -> channel depends on r12 value")
    print("  GBR+26: @(10,r12) -> channel depends on r12 value")
    print("  ...through GBR+46")

    print()
    print("Knock ADC Snapshot (from 0x0437C):")
    print("  Destination: 0xFFFF4064 (knock ADC struct)")
    print("  Reads ALL 12 Group 0 channels (ADDR11 down to ADDR0)")
    print("  Pattern: ADDR[n] -> *(0xFFFF4064 + n*2)")
    print()
    for i in range(12):
        src = f"ADDR{i:2d}"
        dst = 0xFFFF4064 + i * 2
        print(f"  {src} (0xFFFFF{0x800+i*2:03X}) -> 0x{dst:08X}")

    print()
    print("Group 1 Knock Read (from 0x04410):")
    print("  r6 = 0xFFFFF820 (via mov.w literal 0xF820, sign-extended)")
    print("  Destination: 0xFFFF407C (knock Group 1 struct)")
    for i in range(12):
        src = f"ADDR{12+i:2d}"
        dst = 0xFFFF407C + i * 2
        print(f"  {src} (0xFFFFF{0x820+i*2:03X}) -> 0x{dst:08X}")


def scan_all_peripheral_accesses(rom):
    """Find ALL shll8 patterns to map peripheral register access patterns."""
    print("\n" + "="*80)
    print("ALL PERIPHERAL REGISTER ACCESS PATTERNS (shll8)")
    print("="*80)

    periph_names = {
        0xFFFFE400: "HCAN0", 0xFFFFE600: "HCAN1",
        0xFFFFE800: "FLASH", 0xFFFFEC00: "UBC/WDT/BSC",
        0xFFFFED00: "INTC",
        0xFFFFF000: "SCI", 0xFFFFF400: "ATU",
        0xFFFFF700: "APC/CMT/IO/ADC_CTRL",
        0xFFFFF800: "ADC_DATA",
    }

    by_base = {}
    for pc in range(0, len(rom) - 4, 2):
        insn1 = struct.unpack_from(">H", rom, pc)[0]
        insn2 = struct.unpack_from(">H", rom, pc + 2)[0]

        if (insn1 >> 12) == 0xE:
            rn1 = (insn1 >> 8) & 0xF
            imm = insn1 & 0xFF
            if imm & 0x80:
                imm_se = imm | 0xFFFFFF00
            else:
                imm_se = imm

            if insn2 == (0x4000 | (rn1 << 8) | 0x18):
                shifted = (imm_se << 8) & 0xFFFFFFFF
                if 0xFFFFE000 <= shifted <= 0xFFFFF900:
                    base = shifted
                    if base not in by_base:
                        by_base[base] = []
                    by_base[base].append(pc)

    for base in sorted(by_base.keys()):
        name = periph_names.get(base, "UNKNOWN")
        locs = by_base[base]
        print(f"\n  0x{base:08X} ({name}): {len(locs)} references")
        for loc in locs:
            print(f"    0x{loc:05X}")


def find_adc_conversion_functions(rom):
    """Look for functions that convert raw ADC values to engineering units.

    Common pattern: read raw 10-bit ADC value, apply scaling (float mul/div),
    store result as float in RAM.

    Key: find code that reads from known ADC RAM locations and writes float results.
    """
    print("\n" + "="*80)
    print("SEARCHING FOR ADC->FLOAT CONVERSION PATTERNS")
    print("="*80)

    # Look for functions that:
    # 1. Load a 16-bit value (raw ADC) from known locations
    # 2. Convert to float (use FPU: float FPUL,FRn)
    # 3. Multiply by scaling factor
    # 4. Store result

    # Search for 'float FPUL,FRn' (Fn2D) near ADC-related RAM addresses
    float_locs = []
    for pc in range(0, len(rom) - 2, 2):
        code = struct.unpack_from(">H", rom, pc)[0]
        if (code & 0xF0FF) == 0xF02D:  # float FPUL,FRn
            float_locs.append(pc)

    print(f"  Total 'float FPUL,FRn' instructions: {len(float_locs)}")

    # Look for 'lds Rm,FPUL' (0x4m5A) followed by 'float FPUL,FRn'
    # This is the int->float conversion pattern
    int_to_float_count = 0
    for pc in range(0, len(rom) - 4, 2):
        code1 = struct.unpack_from(">H", rom, pc)[0]
        code2 = struct.unpack_from(">H", rom, pc + 2)[0]
        if (code1 & 0xF0FF) == 0x405A and (code2 & 0xF0FF) == 0xF02D:
            int_to_float_count += 1
    print(f"  'lds Rm,FPUL; float FPUL,FRn' pairs: {int_to_float_count}")


def check_vbr_value(rom):
    """Check what VBR is set to, and whether the vector table at VBR makes sense."""
    print("\n" + "="*80)
    print("VBR (VECTOR BASE REGISTER) ANALYSIS")
    print("="*80)

    # Check at 0x0FA40 where we found ldc r2,VBR with r2 loaded from 0x0FCC4
    vbr_lit_addr = 0x0FCC4
    if vbr_lit_addr + 4 <= len(rom):
        vbr_value = struct.unpack_from(">I", rom, vbr_lit_addr)[0]
        print(f"  VBR literal at 0x{vbr_lit_addr:05X}: 0x{vbr_value:08X}")

        # Check if vector table at VBR makes sense
        # Vectors should contain ROM addresses (0x00000000-0x000FFFFF)
        print(f"\n  Testing vector table validity at VBR=0x{vbr_value:08X}:")

        valid_count = 0
        for vec in [64, 72, 80, 84, 92, 172, 176, 177, 180, 196, 204]:
            offset = vbr_value + vec * 4
            if offset + 4 <= len(rom):
                handler = struct.unpack_from(">I", rom, offset)[0]
                is_valid = 0 < handler < 0x100000
                valid_count += is_valid
                print(f"    Vec {vec:3d} @ ROM 0x{offset:05X}: 0x{handler:08X} {'VALID' if is_valid else 'INVALID'}")
            else:
                print(f"    Vec {vec:3d} @ ROM 0x{offset:05X}: BEYOND ROM")

        print(f"\n  Valid handlers: {valid_count} (VBR {'looks correct' if valid_count > 5 else 'may be wrong'})")

    # Also try VBR=0 (boot default) and check if that works for low vectors
    print(f"\n  Boot VBR=0x00000000 vectors (first 14):")
    for vec in range(14):
        handler = struct.unpack_from(">I", rom, vec * 4)[0]
        if handler < 0x100000:
            print(f"    Vec {vec:3d}: 0x{handler:08X} VALID ROM")


def main():
    rom = load_rom()
    print(f"ROM: {len(rom)} bytes")

    # 1. Check VBR value
    check_vbr_value(rom)

    # 2. Dump vector table at VBR if valid
    # First check what VBR actually is
    vbr_value = struct.unpack_from(">I", rom, 0x0FCC4)[0]
    if vbr_value < len(rom):
        dump_vbr_vector_table(rom, vbr_value)

    # 3. Analyze ADC bulk read
    analyze_adc_bulk_read(rom)

    # 4. All peripheral accesses
    scan_all_peripheral_accesses(rom)

    # 5. Float conversion patterns
    find_adc_conversion_functions(rom)


if __name__ == "__main__":
    main()
