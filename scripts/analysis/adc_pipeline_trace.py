#!/usr/bin/env python3
"""
ADC Pipeline Trace for AE5L600L ROM.
Complete mapping: Hardware ADC channels -> Raw RAM -> Filtering -> Sensor Variables.

Architecture:
  SH7058 has 3 ADC groups:
    Group 0: ADDR0-ADDR11  (0xFFFFF800-0xFFFFF817)
    Group 1: ADDR12-ADDR23 (0xFFFFF820-0xFFFFF837)
    Group 2: ADDR24-ADDR31 (0xFFFFF840-0xFFFFF84F)

  Bulk reader at 0x040DE:
    1. Configures ADCSR0 (0xFFFFF818), ADCSR1 (0xFFFFF838), ADCSR2 (0xFFFFF858)
    2. Polls for conversion complete (bit 7 of ADCSR)
    3. Reads all 32 channels to GBR-relative RAM (GBR = 0xFFFF4024)
    4. GBR+0..GBR+22  = ADDR0-ADDR11  (Group 0)
       GBR+24..GBR+46 = ADDR12-ADDR23 (Group 1)
       GBR+48..GBR+62 = ADDR24-ADDR31 (Group 2)

  Conversion pipeline per sensor:
    Raw ADC (16-bit) -> Copy to filtered_addr -> IIR Filter (0xBEA6C)
    -> Lookup table (Pull2DFloat/Pull3DFloat) -> Sensor float in RAM

  ISR chain:
    ADI0 (Vec 176) -> stub at 0x2814 -> common ISR entry 0x2B8C
    -> handler 0xF312 -> reconfigure ADTSR (0xFFFFF6E8) -> dispatcher 0xE774
    -> calls 0xBEAB8 (post-processing) -> task system picks up raw values
"""
import os
import struct

ROM_PATH = os.path.join(os.path.dirname(__file__), "..", "rom", "ae5l600l.bin")


# ── Confirmed sensor assignments ─────────────────────────────────────────────
# Format: ADDR# -> (raw_ram, filtered_ram, output_ram, sensor_name, confidence, notes)
ADC_CHANNEL_MAP = {
    # Group 0 (ADDR0-ADDR11) - also used for knock snapshot at 0xFFFF4064
    0:  (0xFFFF4024, None,       None,       "Knock/Sensor Group 0 Base", "HIGH",
         "56 literal pool refs as struct base; also snapshot to 0xFFFF4064 for knock"),
    1:  (0xFFFF4026, None,       None,       "Knock Channel 1", "MED",
         "Accessed via base+2 offset; part of knock ADC snapshot"),
    2:  (0xFFFF4028, None,       None,       "Knock Channel 2", "MED",
         "5 offset-based accesses from base"),
    3:  (0xFFFF402A, None,       None,       "Knock Channel 3", "MED",
         "1 offset-based access from base"),
    4:  (0xFFFF402C, 0xFFFF4134, 0xFFFF4130, "Atmospheric Pressure (Baro)", "MED",
         "Filter coeff 0x0100@0x0C009C; refs 0x0D8A8C-0x0D8A8E near MAP limits; "
         "Pull3DFloat@0xBE830 with desc; stores float to 0xFFFF4130/0xFFFF4138"),
    5:  (0xFFFF402E, 0xFFFF410C, 0xFFFF4108, "TPS / Throttle Position A", "MED",
         "Filter coeff 0x0100@0x0C00BA; uses 0xBE82C+0xBE9C0 (same pattern as ECT); "
         "9 offset-based accesses; stores to 0xFFFF4104, 0xFFFF410C, 0xFFFF4108"),
    6:  (0xFFFF4030, None,       None,       "Knock/Sensor Ch 6", "LOW",
         "No direct literal pool refs; accessed only via base offset"),
    7:  (0xFFFF4032, 0xFFFF41E4, 0xFFFF41E0, "Battery Voltage", "MED",
         "Heaviest filter 0x0010@0x0C0104 (slowest response = slow-changing signal); "
         "5 offset-based accesses; stores to 0xFFFF41DC, 0xFFFF41E0, 0xFFFF443C"),
    8:  (0xFFFF4034, None,       None,       "Knock/Sensor Ch 8", "LOW",
         "2 offset-based accesses from base"),
    9:  (0xFFFF4036, None,       None,       "Knock/Sensor Ch 9", "LOW",
         "7 offset-based accesses from base"),
    10: (0xFFFF4038, None,       None,       "Knock/Sensor Ch 10", "LOW",
         "6 offset-based accesses from base"),
    11: (0xFFFF403A, None,       None,       "Knock/Sensor Ch 11", "LOW",
         "5 offset-based accesses from base"),

    # Group 1 (ADDR12-ADDR23)
    12: (0xFFFF403C, None,       0xFFFF40D0, "TGV Position / APP Indexed", "MED",
         "Per-cylinder indexed (shll2 r14); float*scale to indexed array at 0xFFFF40D0+; "
         "scale factor 0x38A00000 (1/32768)"),
    13: (0xFFFF403E, None,       None,       "Group 1 Ch 13", "LOW",
         "1 offset-based access from base; no direct refs"),
    14: (0xFFFF4040, 0xFFFF4300, 0xFFFF42FC, "MAP Sensor (Barometric)", "HIGH",
         "Filter coeff 0x0100@0x0C00B8; uses MAP_Sensor_Scaling desc at 0x0D8ADC; "
         "MAP_Sensor_Limits at 0x0D8A88; stores float to 0xFFFF42FC, 0xFFFF4318/4314"),
    15: (0xFFFF4042, None,       0xFFFF40B4, "MAF Sensor Voltage", "CONFIRMED",
         "pMafSensorVoltage=0xFFFF4042 (MerpMod); Pull3DFloat with desc 0x0AF45C; "
         "MAF_Sensor data@0x0D8BC4, MAF_Scaling@0x0D8C9C; MAF(g/s) to 0xFFFF40B4"),
    16: (0xFFFF4044, None,       0xFFFF40B8, "TGV Position / APP Indexed B", "MED",
         "Per-cylinder indexed like ADDR12; float*scale to indexed array at 0xFFFF40B8+; "
         "uses 0xBE960; secondary scale factor 0x3DCCCCCC (0.1)"),
    17: (0xFFFF4046, None,       None,       "Group 1 Ch 17 (unused)", "LOW", "No refs"),
    18: (0xFFFF4048, None,       None,       "Group 1 Ch 18 (unused)", "LOW", "No refs"),
    19: (0xFFFF404A, None,       None,       "Group 1 Ch 19 (unused)", "LOW", "No refs"),
    20: (0xFFFF404C, None,       None,       "Group 1 Ch 20 (unused)", "LOW", "No refs"),
    21: (0xFFFF404E, None,       None,       "Group 1 Ch 21 (unused)", "LOW", "No refs"),
    22: (0xFFFF4050, None,       0xFFFF43FC, "MAP Sensor (Manifold Pressure)", "HIGH",
         "Direct voltage normalization: raw * (1/32768) -> float at 0xFFFF43FC; "
         "25 downstream refs; MAP_Sensor_CEL@0x0D8A60; most-used sensor value"),
    23: (0xFFFF4052, None,       None,       "Group 1 Ch 23 (unused)", "LOW", "No refs"),

    # Group 2 (ADDR24-ADDR31)
    24: (0xFFFF4054, None,       None,       "Group 2 Ch 24 (unused)", "LOW", "No refs"),
    25: (0xFFFF4056, None,       None,       "Group 2 Ch 25 (unused)", "LOW", "No refs"),
    26: (0xFFFF4058, 0xFFFF41EC, 0xFFFF41E8, "Fuel Temperature", "HIGH",
         "Filter coeff 0x0040@0x0AF932; desc 0x0AF48C -> Fuel_Temp_Sensor@0x0D8FAC, "
         "Fuel_Temp_Scaling@0x0D9024; Pull3DFloat@0xBE830; float to 0xFFFF41F4"),
    27: (0xFFFF405A, None,       None,       "Switch Input (A/C or PS)", "MED",
         "Threshold comparisons at 0x1999(10%), 0x4CCC(30%), 0x8000(50%); "
         "returns discrete state 0-3; no filtering = binary/switch type"),
    28: (0xFFFF405C, 0xFFFF4114, 0xFFFF4110, "Front O2 / A-F Sensor", "MED",
         "Filter coeff 0x0001@0x0AF92C (nearly no filtering = fast response); "
         "refs 0x0D8ACC/0x0D8ACA near MAP_Scaling; stores to 0xFFFF4120, 0xFFFF4124"),
    29: (0xFFFF405E, 0xFFFF4148, 0xFFFF4144, "Coolant Temperature (ECT)", "CONFIRMED",
         "pCoolantTemp=0xFFFF4144 (MerpMod); desc 0x0AF474 -> ECT_Sensor@0x0D8DDC, "
         "ECT_Scaling@0x0D8E4C; filter coeff 0x0040@0x0AF92E; float to 0xFFFF4144"),
    30: (0xFFFF4060, 0xFFFF412C, 0xFFFF4128, "Intake Air Temperature (IAT)", "HIGH",
         "desc 0x0AF480 -> IAT_Sensor@0x0D8EBC, IAT_Scaling@0x0D8F34; "
         "filter coeff 0x0040@0x0AF930; Pull3DFloat; float to 0xFFFF4128"),
    31: (0xFFFF4062, None,       0xFFFF4311, "MAP/Pressure Threshold", "MED",
         "Threshold comparisons using vals from 0x0D8A9C/0x0D8A9E near MAP limits; "
         "stores discrete state to 0xFFFF4311 (byte); pressure range detection"),
}


# ── Key function addresses ────────────────────────────────────────────────────
PIPELINE_FUNCTIONS = {
    0x000040DE: "adc_bulk_read       - Reads all 32 ADC channels to RAM",
    0x00002814: "ADI0_ISR_stub       - ADC Group 0 interrupt stub",
    0x0000F312: "ADI0_handler        - Reconfigures ADTSR, dispatches",
    0x0000E774: "isr_dispatcher      - Common ISR -> task dispatcher",
    0x0000E852: "isr_default_stub    - Default ISR (shared by many vectors)",
    0x00002B8C: "isr_common_entry    - Save context (regs + FPU)",
    0x000BEA6C: "iir_filter          - IIR low-pass filter (r4=new, r5=old, r6=coeff)",
    0x000BE830: "Pull3DFloat         - 3D table lookup (descriptor-based)",
    0x000BE608: "Pull2DFloat         - 2D table lookup (descriptor-based)",
    0x000BE960: "adc_convert_indexed  - Per-cylinder ADC conversion",
    0x000BE9C0: "sensor_post_process  - Secondary sensor processing",
    0x000BE82C: "sensor_init_convert  - Initial conversion (temp sensors)",
    0x000BE598: "float_lookup_1D      - 1D float interpolation",
    0x000FBA4:  "isr_exit             - ISR context restore and return",
}


# ── Descriptor chain (sequential in ROM) ──────────────────────────────────────
SENSOR_DESCRIPTORS = {
    0x0AF45C: ("MAF Sensor",          "data@0x0D8BC4 MAF_Sensor",
               "scale@0x0D8C9C MAF_Sensor_Scaling", "ADDR15"),
    0x0AF468: ("Front O2 Sensor",     "data@0x0D8D74 Front_O2_Sensor",
               "scale@0x0D8DA8 Front_O2_Sensor_Scaling", "ADDR28?"),
    0x0AF474: ("Coolant Temp Sensor", "data@0x0D8DDC Coolant_Temp_Sensor",
               "scale@0x0D8E4C Coolant_Temp_Sensor_Scaling", "ADDR29"),
    0x0AF480: ("Intake Temp Sensor",  "data@0x0D8EBC Intake_Temp_Sensor",
               "scale@0x0D8F34 Intake_Temp_Sensor_Scaling", "ADDR30"),
    0x0AF48C: ("Fuel Temp Sensor",    "data@0x0D8FAC Fuel_Temp_Sensor",
               "scale@0x0D9024 Fuel_Temp_Sensor_Scaling", "ADDR26"),
}


def load_rom():
    with open(ROM_PATH, "rb") as f:
        return f.read()


def print_channel_map():
    """Print the complete ADC channel map."""
    print("=" * 100)
    print("  AE5L600L COMPLETE ADC CHANNEL MAP")
    print("  Bulk reader: 0x040DE | GBR base: 0xFFFF4024 | 32 channels")
    print("=" * 100)

    conf_order = {"CONFIRMED": 0, "HIGH": 1, "MED": 2, "LOW": 3}

    for group_name, ch_range in [("Group 0 (ADDR0-11)", range(12)),
                                  ("Group 1 (ADDR12-23)", range(12, 24)),
                                  ("Group 2 (ADDR24-31)", range(24, 32))]:
        print(f"\n{'-' * 100}")
        print(f"  {group_name}")
        print(f"{'-' * 100}")

        for ch in ch_range:
            raw, filt, out, name, conf, notes = ADC_CHANNEL_MAP[ch]
            filt_str = f"0x{filt:08X}" if filt else "    ---     "
            out_str = f"0x{out:08X}" if out else "    ---     "
            conf_str = f"[{conf}]"

            print(f"  ADDR{ch:2d}  raw=0x{raw:08X}  filt={filt_str}  "
                  f"out={out_str}  {conf_str:12s} {name}")


def print_pipeline_diagram():
    """Print the data flow diagram."""
    print("\n" + "=" * 100)
    print("  ADC DATA FLOW PIPELINE")
    print("=" * 100)
    print("""
  +-------------------------------------------------------------------------+
  |  SH7058 ADC Hardware                                                    |
  |  +----------+  +----------+  +----------+                              |
  |  | Group 0  |  | Group 1  |  | Group 2  |                              |
  |  | ADDR0-11 |  | ADDR12-23|  | ADDR24-31|                              |
  |  | 0xF800   |  | 0xF820   |  | 0xF840   |                              |
  |  +----+-----+  +----+-----+  +----+-----+                              |
  +-------+-------------+-------------+------------------------------------+
          |              |              |
          v              v              v
  +-----------------------------------------------------------------------+
  |  Bulk Reader (0x040DE)                                                 |
  |  GBR = 0xFFFF4024                                                      |
  |  Polls ADCSR0/1/2 for conversion complete                              |
  |  Reads all 32 channels to GBR+0..GBR+62                                |
  |                                                                        |
  |  ADDR0  -> 0xFFFF4024    ADDR12 -> 0xFFFF403C    ADDR24 -> 0xFFFF4054  |
  |  ADDR5  -> 0xFFFF402E    ADDR15 -> 0xFFFF4042    ADDR29 -> 0xFFFF405E  |
  |  ADDR7  -> 0xFFFF4032    ADDR22 -> 0xFFFF4050    ADDR30 -> 0xFFFF4060  |
  |  ...                     ...                     ...                   |
  +----------------------------+-------------------------------------------+
                               |
          +--------------------+--------------------+
          v                    v                    v
  +--------------+   +--------------+   +---------------+
  | IIR Filter   |   | Direct Float |   | Threshold     |
  | (0xBEA6C)    |   | Conversion   |   | Comparison    |
  |              |   |              |   |               |
  | ECT, IAT,    |   | MAP (ADDR22) |   | ADDR27: switch|
  | Fuel Temp,   |   | raw * 1/32768|   | ADDR31: MAP   |
  | Battery,     |   | -> float     |   | threshold     |
  | O2, TPS,     |   | -> 0xFFFF43FC|   | -> discrete   |
  | Baro         |   |              |   | state 0-3     |
  +------+-------+   +------+-------+   +-------+-------+
         |                  |                    |
         v                  |                    |
  +--------------+          |                    |
  | Lookup Table |          |                    |
  | (descriptor) |          |                    |
  |              |          |                    |
  | Pull3DFloat  |          |                    |
  | or float_1D  |          |                    |
  | interpolation|          |                    |
  +------+-------+          |                    |
         |                  |                    |
         v                  v                    v
  +-----------------------------------------------------------------------+
  |  Processed Sensor Variables (RAM)                                      |
  |                                                                        |
  |  pMafSensorVoltage = 0xFFFF4042 (raw short, ADDR15)                    |
  |  MAF (g/s)         = 0xFFFF40B4 (float, via Pull3DFloat)               |
  |  MAP (normalized)  = 0xFFFF43FC (float, 25 consumers)                  |
  |  pCoolantTemp      = 0xFFFF4144 (float, via ECT desc)                  |
  |  IAT               = 0xFFFF4128 (float, via IAT desc)                  |
  |  Fuel Temp          = 0xFFFF41F4 (float, via Fuel Temp desc)            |
  |  Battery Voltage   = 0xFFFF41E0 (float, heavy filter)                  |
  |  Baro/Atm Pressure = 0xFFFF42FC (float, MAP Scaling desc)              |
  +-----------------------------------------------------------------------+
""")


def print_descriptor_chain(rom):
    """Print the sensor descriptor chain."""
    print("=" * 100)
    print("  SENSOR DESCRIPTOR CHAIN (ROM 0x0AF45C - 0x0AF498)")
    print("=" * 100)

    for desc_addr, (name, data_info, scale_info, adc_ch) in SENSOR_DESCRIPTORS.items():
        data = rom[desc_addr:desc_addr + 20]
        words = struct.unpack(">5I", data)
        print(f"\n  Descriptor 0x{desc_addr:06X}: {name} ({adc_ch})")
        print(f"    {data_info}")
        print(f"    {scale_info}")
        print(f"    Raw: {' '.join(f'0x{w:08X}' for w in words)}")


def print_filter_coefficients(rom):
    """Print IIR filter coefficients for each sensor."""
    print("\n" + "=" * 100)
    print("  IIR FILTER COEFFICIENTS (0xBEA6C)")
    print("  Formula: filtered = old + (new - old) * coeff/65536")
    print("=" * 100)

    coeffs = [
        (0x0AF92C, "ADDR28 Front O2/AF",     "Fast response"),
        (0x0AF92E, "ADDR29 Coolant Temp",     "Moderate"),
        (0x0AF930, "ADDR30 Intake Air Temp",  "Moderate"),
        (0x0AF932, "ADDR26 Fuel Temp",        "Moderate"),
        (0x0C009C, "ADDR4  Atm. Pressure",    "Moderate"),
        (0x0C00B8, "ADDR14 MAP/Baro",         "Moderate"),
        (0x0C00BA, "ADDR5  TPS/Throttle A",   "Moderate"),
        (0x0C0104, "ADDR7  Battery Voltage",  "Very slow"),
    ]

    for addr, name, speed in coeffs:
        val = struct.unpack_from(">H", rom, addr)[0]
        ratio = val / 65536.0
        tc = 1.0 / ratio if ratio > 0 else float("inf")
        print(f"  0x{addr:06X}: 0x{val:04X} ({val:5d})  ratio={ratio:.6f}  "
              f"~{tc:.0f} samples to settle  [{speed}]  {name}")


def print_knock_adc(rom):
    """Print the knock ADC snapshot mapping."""
    print("\n" + "=" * 100)
    print("  KNOCK ADC SNAPSHOT (0x0437C)")
    print("  Separate fast-path read of Group 0 for knock detection")
    print("=" * 100)
    print("  Destination struct: 0xFFFF4064")
    for i in range(12):
        src = f"ADDR{i:2d}"
        dst = 0xFFFF4064 + i * 2
        print(f"    {src} (0xFFFFF{0x800 + i * 2:03X}) -> 0x{dst:08X}")

    print("\n  Group 1 knock read (0x04410):")
    print("  Destination struct: 0xFFFF407C")
    for i in range(12):
        src = f"ADDR{12 + i:2d}"
        dst = 0xFFFF407C + i * 2
        print(f"    {src} (0xFFFFF{0x820 + i * 2:03X}) -> 0x{dst:08X}")


def scan_all_adc_refs(rom):
    """Count total references to each ADC raw RAM address."""
    print("\n" + "=" * 100)
    print("  ADC RAW ADDRESS REFERENCE COUNTS")
    print("  (Literal pool refs + base-offset accesses combined)")
    print("=" * 100)

    for ch in range(32):
        info = ADC_CHANNEL_MAP[ch]
        raw_addr = info[0]
        name = info[3]

        # Count literal pool refs
        lit_count = 0
        for pc in range(0, len(rom) - 4, 2):
            code = struct.unpack_from(">H", rom, pc)[0]
            if (code >> 12) == 0xD:
                disp = code & 0xFF
                lit_addr = (pc & ~3) + 4 + disp * 4
                if lit_addr + 4 <= len(rom):
                    val = struct.unpack_from(">I", rom, lit_addr)[0]
                    if val == raw_addr:
                        lit_count += 1

        if lit_count > 0 or info[4] in ("CONFIRMED", "HIGH"):
            print(f"  ADDR{ch:2d} (0x{raw_addr:08X}): {lit_count:3d} lit.pool refs  "
                  f"  [{info[4]:9s}] {name}")


def print_isr_chain():
    """Print the ISR dispatch chain."""
    print("\n" + "=" * 100)
    print("  ADC INTERRUPT SERVICE ROUTINE CHAIN")
    print("=" * 100)
    print("""
  VBR = 0x000FFC50 (set at 0x0FA40)

  Vec 176 (ADI0 - Group 0 complete):
    VBR + 0x2C0 = ROM 0xFFF10 -> handler 0x2814

    0x2814: mov.l r0,@-r15          ; push r0
            mov.l @(lit),r0         ; r0 = 0x2B8C (common ISR entry)
            sts.l pr,@-r15          ; push PR
            jsr   @r0               ; call common_entry (saves all regs + FPU)
            mov.l r1,@-r15          ; push r1 (delay slot)
            mov.l @(lit),r1         ; r1 = 0xF312 (ADI0 handler)
            jmp   @r1               ; jump to ADI0 handler
            lds   r0,pr             ; restore PR (delay slot)

  ADI0 Handler (0xF312):
    Reads ADTSR at 0xFFFFF6E8 (save old status)
    Writes #14 to ADTSR (configure next conversion mode)
    Loads r4 = 0x00B0 (parameter)
    Branches to 0xE774 (ISR dispatcher)

  ISR Dispatcher (0xE774):
    Adjusts interrupt priority (SR register)
    Calls 0x10800 (event processing)
    Calls 0xFBA4 (ISR exit/restore)
    Calls 0xBEAB8 (post-processing with FPU save/restore)
    Returns via RTE

  Vec 177 (ADI1 - Group 1 complete):
    VBR + 0x2C4 = ROM 0xFFF14 -> 0xE852 (default stub -> dispatches to 0xE774)
""")


def main():
    rom = load_rom()
    print(f"ROM loaded: {len(rom)} bytes ({len(rom) // 1024} KB)")

    # Print the main outputs
    print_channel_map()
    print_pipeline_diagram()
    print_descriptor_chain(rom)
    print_filter_coefficients(rom)
    print_knock_adc(rom)
    print_isr_chain()

    import sys
    if "--full" in sys.argv:
        # Full reference scan is slow, only run if requested
        scan_all_adc_refs(rom)

    # Summary
    print("\n" + "=" * 100)
    print("  SUMMARY")
    print("=" * 100)
    confirmed = sum(1 for v in ADC_CHANNEL_MAP.values() if v[4] in ("CONFIRMED", "HIGH"))
    med = sum(1 for v in ADC_CHANNEL_MAP.values() if v[4] == "MED")
    unused = sum(1 for v in ADC_CHANNEL_MAP.values() if "unused" in v[3].lower())
    print(f"  Total ADC channels: 32")
    print(f"  Confirmed/High confidence: {confirmed}")
    print(f"  Medium confidence: {med}")
    print(f"  Likely unused: {unused}")
    print(f"  Knock-related (Group 0): ~8 channels")
    print()
    print("  KEY CONFIRMED SENSORS:")
    print("    ADDR15 = MAF Sensor Voltage    -> 0xFFFF4042 (raw) -> 0xFFFF40B4 (g/s float)")
    print("    ADDR22 = MAP Sensor            -> 0xFFFF4050 (raw) -> 0xFFFF43FC (normalized float)")
    print("    ADDR29 = Coolant Temp (ECT)    -> 0xFFFF405E (raw) -> 0xFFFF4144 (°C float)")
    print("    ADDR30 = Intake Air Temp (IAT) -> 0xFFFF4060 (raw) -> 0xFFFF4128 (°C float)")
    print("    ADDR26 = Fuel Temperature      -> 0xFFFF4058 (raw) -> 0xFFFF41F4 (°C float)")
    print("    ADDR14 = Atmospheric/Baro Pres -> 0xFFFF4040 (raw) -> 0xFFFF42FC (kPa float)")
    print()
    print("  KEY RAM ADDRESSES FOR DOWNSTREAM USE:")
    print("    0xFFFF4024 = ADC raw buffer base (32 x 16-bit words)")
    print("    0xFFFF4064 = Knock snapshot Group 0 (12 x 16-bit)")
    print("    0xFFFF407C = Knock snapshot Group 1 (12 x 16-bit)")
    print("    0xFFFF40B4 = MAF (g/s, float)")
    print("    0xFFFF4128 = IAT (°C, float)")
    print("    0xFFFF4144 = ECT (°C, float) = pCoolantTemp")
    print("    0xFFFF41F4 = Fuel Temp (°C, float)")
    print("    0xFFFF43FC = MAP (normalized voltage, float)")


if __name__ == "__main__":
    main()
