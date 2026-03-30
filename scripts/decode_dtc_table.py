#!/usr/bin/env python3
"""
Decode the DTC (Diagnostic Trouble Code) table at 0x9A770.
93 entries, each entry is a byte index into the DTC code lookup.

DTC table structure: Each byte at 0x9A770+index represents a DTC status flag.
The dtc_set_code/dtc_clear_code functions take an index r4 (0-92) and read
from 0x9A770+r4 to check/set the DTC status.

The actual P-codes are likely stored elsewhere. Let's find them by
examining what dtc_set_code calls (0xA58D6) and how diagnostic scan
tools request DTCs.

We'll also scan for the standard Subaru DTC P-code table format.
"""
import os
import struct
import sys

ROM_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rom")

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

def r_u8(rom, a): return rom[a]
def r_u16(rom, a): return struct.unpack_from(">H", rom, a)[0]
def r_u32(rom, a): return struct.unpack_from(">I", rom, a)[0]

# Standard OBD-II P-code encoding:
# First byte high nibble encodes the type:
#   0x00-0x3F = P0xxx (Powertrain generic)
#   0x40-0x7F = P1xxx (Powertrain manufacturer)
#   0x80-0xBF = C0xxx (Chassis) / B0xxx (Body) / U0xxx (Network)
#
# Subaru commonly uses 2-byte BCD or packed encoding for DTCs.

def decode_pcode(b1, b2):
    """Try to decode 2 bytes as an OBD-II P-code."""
    # Standard ISO 15031-6 encoding
    prefix_map = {0: 'P0', 1: 'P1', 2: 'P2', 3: 'P3',
                  4: 'C0', 5: 'C1', 6: 'C2', 7: 'C3',
                  8: 'B0', 9: 'B1', 0xA: 'B2', 0xB: 'B3',
                  0xC: 'U0', 0xD: 'U1', 0xE: 'U2', 0xF: 'U3'}
    hi_nibble = (b1 >> 6) & 0x3
    prefix = ['P', 'C', 'B', 'U'][hi_nibble]
    second = (b1 >> 4) & 0x3
    code = f"{prefix}{second}{b1 & 0x0F:01X}{b2:02X}"
    return code


# Known Subaru DTC P-codes for 2013 WRX
KNOWN_DTCS = {
    "P0335": "Crankshaft Position Sensor A",
    "P0340": "Camshaft Position Sensor A (Bank 1)",
    "P0016": "Crankshaft-Camshaft Position Correlation Bank 1",
    "P0017": "Crankshaft-Camshaft Position Correlation Bank 2",
    "P0011": "Intake Camshaft Position Timing Over-Advanced Bank 1",
    "P0021": "Intake Camshaft Position Timing Over-Advanced Bank 2",
    "P0130": "O2 Sensor Circuit Bank 1 Sensor 1",
    "P0131": "O2 Sensor Low Voltage Bank 1 Sensor 1",
    "P0132": "O2 Sensor High Voltage Bank 1 Sensor 1",
    "P0133": "O2 Sensor Slow Response Bank 1 Sensor 1",
    "P0134": "O2 Sensor No Activity Bank 1 Sensor 1",
    "P0136": "O2 Sensor Circuit Bank 1 Sensor 2",
    "P0137": "O2 Sensor Low Voltage Bank 1 Sensor 2",
    "P0138": "O2 Sensor High Voltage Bank 1 Sensor 2",
    "P0139": "O2 Sensor Slow Response Bank 1 Sensor 2",
    "P0171": "System Too Lean Bank 1",
    "P0172": "System Too Rich Bank 1",
    "P0301": "Cylinder 1 Misfire",
    "P0302": "Cylinder 2 Misfire",
    "P0303": "Cylinder 3 Misfire",
    "P0304": "Cylinder 4 Misfire",
    "P0325": "Knock Sensor 1 Circuit",
    "P0328": "Knock Sensor 1 High",
    "P0420": "Catalyst System Efficiency Below Threshold Bank 1",
    "P0440": "Evaporative Emission System",
    "P0441": "EVAP Incorrect Purge Flow",
    "P0442": "EVAP System Small Leak",
    "P0443": "EVAP Purge Control Valve Circuit",
    "P0456": "EVAP System Very Small Leak",
    "P0500": "Vehicle Speed Sensor",
    "P0506": "Idle Control System RPM Lower Than Expected",
    "P0507": "Idle Control System RPM Higher Than Expected",
    "P0604": "Internal Control Module RAM",
    "P2004": "Intake Manifold Runner Control Stuck Open Bank 1",
    "P2006": "Intake Manifold Runner Control Stuck Closed Bank 1",
    "P2008": "Intake Manifold Runner Control Circuit Open Bank 1",
    "P2009": "Intake Manifold Runner Control Circuit Low Bank 1",
    "P0101": "MAF Sensor Range/Performance",
    "P0102": "MAF Sensor Low Input",
    "P0103": "MAF Sensor High Input",
    "P0107": "MAP Sensor Low Input",
    "P0108": "MAP Sensor High Input",
    "P0111": "IAT Sensor Range/Performance",
    "P0112": "IAT Sensor Low Input",
    "P0113": "IAT Sensor High Input",
    "P0117": "ECT Sensor Low Input",
    "P0118": "ECT Sensor High Input",
    "P0122": "TPS A Low Input",
    "P0123": "TPS A High Input",
    "P0125": "ECT Insufficient for Closed Loop",
    "P0126": "ECT Insufficient for Operation",
}


def main():
    rom = load_rom()
    print(f"Loaded ROM: {len(rom)} bytes\n")

    DTC_TABLE = 0x9A770
    DTC_COUNT = 93

    print(f"DTC Table at 0x{DTC_TABLE:06X}, {DTC_COUNT} entries\n")

    # First, dump raw bytes at DTC table
    print("Raw DTC table bytes:")
    for i in range(0, DTC_COUNT, 16):
        chunk = rom[DTC_TABLE + i: DTC_TABLE + min(i + 16, DTC_COUNT)]
        hex_str = " ".join(f"{b:02X}" for b in chunk)
        print(f"  0x{DTC_TABLE + i:06X} [{i:>2}-{min(i+15, DTC_COUNT-1):>2}]: {hex_str}")

    # The DTC table at 0x9A770 is actually a status/flag table, not P-codes.
    # The actual P-code mappings are typically in a separate structure.
    # Let's search for the P-code table by looking for known DTC byte patterns.

    # Standard P0335 in ISO encoding: first byte encodes P0, second byte is 0x35
    # P0335 = 0x03, 0x35 in ISO 15031-6
    # Or in raw: high nibble 0=P, bits 5:4=0 (0xxx), so byte1=0x03, byte2=0x35

    print("\n\nSearching for P-code table patterns...")

    # Search for P0335 encoding (0x03 0x35)
    p0335_locations = []
    for addr in range(0, len(rom) - 2):
        if rom[addr] == 0x03 and rom[addr+1] == 0x35:
            # Check if nearby bytes also look like DTCs
            context_ok = 0
            for delta in [-2, 2, 4, -4]:
                a = addr + delta
                if 0 <= a < len(rom) - 1:
                    b1, b2 = rom[a], rom[a+1]
                    code = decode_pcode(b1, b2)
                    if code in KNOWN_DTCS:
                        context_ok += 1
            if context_ok >= 1:
                p0335_locations.append(addr)

    print(f"  P0335 (0x0335) found at {len(p0335_locations)} locations with DTC context:")
    for loc in p0335_locations[:10]:
        # Decode surrounding entries
        codes = []
        for i in range(-4, 8, 2):
            a = loc + i
            if 0 <= a + 1 < len(rom):
                code = decode_pcode(rom[a], rom[a+1])
                known = KNOWN_DTCS.get(code, "")
                codes.append(f"{code}{'*' if known else ''}")
        print(f"    0x{loc:06X}: {' '.join(codes)}")

    # Let's also look at what 0xA58D6 (called by dtc_set_code) does with the DTC index
    # to find where P-codes are stored
    print(f"\n\nDTC handler analysis:")
    print(f"  dtc_set_code (0x9EDEC) calls 0xA58D6 and 0xA5ABC")
    print(f"  dtc_clear_code (0x9ED90) calls 0xA1CC0 and 0xA240C")

    # Check what's at 0xA58D6
    print(f"\n  Code at 0xA58D6 (first 10 instructions):")
    for i in range(10):
        pc = 0xA58D6 + i * 2
        w = r_u16(rom, pc)
        print(f"    0x{pc:05X}: {w:04X}")

    # Also scan for a table of 2-byte entries in the 0x9A000-0x9B000 range
    # that decode to valid P-codes
    print(f"\n\nScanning 0x9A000-0x9B000 for P-code tables...")
    best_run = (0, 0, [])
    for start in range(0x9A000, 0x9B000, 2):
        codes = []
        for i in range(100):
            a = start + i * 2
            if a + 1 >= len(rom):
                break
            code = decode_pcode(rom[a], rom[a+1])
            if code in KNOWN_DTCS:
                codes.append((i, code))
        if len(codes) > best_run[1]:
            best_run = (start, len(codes), codes)

    print(f"  Best P-code run at 0x{best_run[0]:06X} ({best_run[1]} known codes):")
    if best_run[1] > 0:
        for idx, code in best_run[2][:20]:
            print(f"    Entry [{idx:>2}]: {code} - {KNOWN_DTCS.get(code, '?')}")

    # Also check at 0x9A600 range and broader
    for region_start in [0x9A400, 0x9A500, 0x9A600, 0x9A700, 0x9A800, 0x9AB00]:
        codes_found = 0
        for i in range(100):
            a = region_start + i * 2
            if a + 1 >= len(rom):
                break
            code = decode_pcode(rom[a], rom[a+1])
            if code in KNOWN_DTCS:
                codes_found += 1
        if codes_found >= 3:
            print(f"\n  Candidate P-code table at 0x{region_start:06X} ({codes_found} known)")
            for i in range(min(20, 100)):
                a = region_start + i * 2
                code = decode_pcode(rom[a], rom[a+1])
                known = KNOWN_DTCS.get(code, "")
                marker = " <--" if known else ""
                print(f"    [{i:>2}] 0x{rom[a]:02X}{rom[a+1]:02X} -> {code}{' - ' + known if known else ''}{marker}")


if __name__ == "__main__":
    main()
