#!/usr/bin/env python3
"""
MerpMod ROM Patcher for AE5L600L
Applies compiled MerpMod code to a Subaru ECU ROM binary.

This replaces SharpTune's rommod functionality:
1. Overlays compiled code into the ROM hole
2. Reads MetaReplace patch entries from the ELF metadata section
3. Applies 4-byte hook patches to redirect OEM code to MerpMod functions
4. Fixes the Subaru DBW checksum
"""

import struct
import sys
import os
import subprocess

TOOLCHAIN = "/home/user/cross-sh/toolchain/bin"

def read_elf_sections(elf_path):
    """Extract sections from ELF file using objcopy."""
    sections = {}
    # Get section list
    result = subprocess.run(
        [f"{TOOLCHAIN}/sh-elf-objdump", "-h", elf_path],
        capture_output=True, text=True
    )

    for line in result.stdout.split('\n'):
        parts = line.strip().split()
        if len(parts) >= 7 and parts[0].isdigit():
            idx = int(parts[0])
            name = parts[1]
            size = int(parts[2], 16)
            vma = int(parts[3], 16)
            lma = int(parts[4], 16)
            offset = int(parts[5], 16)

            if size > 0:
                sections[name] = {
                    'name': name,
                    'size': size,
                    'vma': vma,
                    'lma': lma,
                    'offset': offset,
                }

    # Read the actual ELF file to extract section data
    with open(elf_path, 'rb') as f:
        elf_data = f.read()

    for name, info in sections.items():
        info['data'] = elf_data[info['offset']:info['offset'] + info['size']]

    return sections


def extract_meta_replaces(metadata_bytes):
    """Parse MetaReplace entries from the MetaData section.

    MetaReplace struct:
        long op;       // OpReplace4Bytes = 0x12340003
        long address;  // ROM address to patch
        long oldval;   // Expected original value
        long newval;   // New value to write
        char name[];   // Null-terminated string
    """
    OpReplace4Bytes = 0x12340003
    OpReplaceLast2Of4Bytes = 0x12340013

    patches = []
    i = 0
    while i + 16 <= len(metadata_bytes):
        op = struct.unpack('>I', metadata_bytes[i:i+4])[0]

        if op == OpReplace4Bytes or op == OpReplaceLast2Of4Bytes:
            address = struct.unpack('>I', metadata_bytes[i+4:i+8])[0]
            oldval = struct.unpack('>I', metadata_bytes[i+8:i+12])[0]
            newval = struct.unpack('>I', metadata_bytes[i+12:i+16])[0]

            # Read name string
            name_start = i + 16
            name_end = metadata_bytes.find(b'\x00', name_start)
            if name_end == -1:
                name_end = len(metadata_bytes)
            name = metadata_bytes[name_start:name_end].decode('ascii', errors='replace')

            patches.append({
                'op': op,
                'op_name': 'Replace4Bytes' if op == OpReplace4Bytes else 'ReplaceLast2Of4',
                'address': address,
                'oldval': oldval,
                'newval': newval,
                'name': name.strip(),
            })

            # Skip past the name and any padding
            i = name_end + 1
            # Align to 4 bytes
            i = (i + 3) & ~3
        else:
            i += 4  # Skip unknown ops, scan forward

    return patches


def compute_subaru_checksum(rom_data):
    """Compute Subaru 32-bit checksum for DBW ECUs.

    The checksum is the sum of all 32-bit words in the ROM,
    stored at offset 0x20000 (the checksum location for 1MB SH7058 ROMs).
    The ROM should sum to 0x5AA5A55A when the checksum word is correct.
    """
    # Standard checksum location for 1MB Subaru DBW ROM
    checksum_offset = 0x20000
    target_sum = 0x5AA5A55A

    # Zero out the checksum location temporarily
    rom = bytearray(rom_data)
    rom[checksum_offset:checksum_offset+4] = b'\x00\x00\x00\x00'

    # Sum all 32-bit words
    total = 0
    for i in range(0, len(rom), 4):
        word = struct.unpack('>I', rom[i:i+4])[0]
        total = (total + word) & 0xFFFFFFFF

    # The checksum value is what makes the total equal target_sum
    checksum = (target_sum - total) & 0xFFFFFFFF

    return checksum, checksum_offset


def main():
    elf_path = "build/MerpMod.elf"
    rom_path = "AE5L600L 20g rev 20 tiny wrex.bin"
    output_path = "AE5L600L_MerpMod.bin"

    if not os.path.exists(elf_path):
        print("ERROR: build/MerpMod.elf not found. Run 'make' first.")
        sys.exit(1)

    if not os.path.exists(rom_path):
        print(f"ERROR: {rom_path} not found.")
        sys.exit(1)

    # Read the ROM
    with open(rom_path, 'rb') as f:
        rom = bytearray(f.read())

    print(f"ROM: {rom_path} ({len(rom)} bytes)")

    # Extract ELF sections
    sections = read_elf_sections(elf_path)
    print(f"\nELF sections:")
    for name, info in sections.items():
        print(f"  {name}: 0x{info['vma']:06X} size=0x{info['size']:X}")

    # Step 1: Overlay ROM hole code
    romhole = sections.get('ROMHOLE_START')
    if romhole:
        start = romhole['vma']
        data = romhole['data']
        print(f"\n--- Step 1: Write ROM hole code ---")
        print(f"  Address: 0x{start:06X} - 0x{start + len(data):06X} ({len(data)} bytes)")

        if start + len(data) > len(rom):
            print(f"  ERROR: ROM hole code extends beyond ROM!")
            sys.exit(1)

        # Check that the target area is mostly 0xFF (unused)
        existing = rom[start:start + len(data)]
        non_ff = sum(1 for b in existing if b != 0xFF)
        if non_ff > 0:
            print(f"  WARNING: {non_ff} non-0xFF bytes in target area (may overwrite existing data)")

        rom[start:start + len(data)] = data
        print(f"  OK: Wrote {len(data)} bytes to ROM hole")

    # Also overlay other code sections that belong in ROM
    for sec_name in ['.rodata.str1.4', 'MetaData', 'MetaDataHeader',
                     'TestSection1', 'DefinitionDataEnd', 'DefinitionData',
                     'Test_Section']:
        sec = sections.get(sec_name)
        if sec and sec['vma'] < len(rom):
            # Only overlay sections that are in ROM address range
            if sec['vma'] >= 0xDB000 and sec['vma'] < 0x100000:
                rom[sec['vma']:sec['vma'] + sec['size']] = sec['data']
                print(f"  Also wrote {sec_name}: 0x{sec['vma']:06X} ({sec['size']} bytes)")

    # Step 2: Extract and apply hook patches from MetaData section
    print(f"\n--- Step 2: Apply hook patches ---")

    # The MetaDataHeader section contains the patch definitions
    meta_header = sections.get('MetaDataHeader')
    if meta_header:
        patches = extract_meta_replaces(meta_header['data'])

        if not patches:
            print("  WARNING: No MetaReplace patches found in MetaDataHeader")
            # Try MetaData section too
            meta = sections.get('MetaData')
            if meta:
                patches = extract_meta_replaces(meta['data'])

    # Also check if patches are elsewhere
    if not patches:
        print("  Trying to find patches in all metadata sections...")
        for sec_name, sec in sections.items():
            if 'Meta' in sec_name or 'meta' in sec_name:
                p = extract_meta_replaces(sec['data'])
                patches.extend(p)

    if patches:
        for p in patches:
            addr = p['address']
            oldval = p['oldval']
            newval = p['newval']
            name = p['name']

            if addr >= len(rom):
                print(f"  SKIP: {name} - address 0x{addr:06X} outside ROM")
                continue

            # Read current value at address
            current = struct.unpack('>I', rom[addr:addr+4])[0]

            if p['op'] == 0x12340013:  # ReplaceLast2Of4Bytes
                # Only replace the last 2 bytes
                current_last2 = current & 0xFFFF
                old_last2 = oldval & 0xFFFF
                new_last2 = newval & 0xFFFF
                print(f"  {name}:")
                print(f"    Address: 0x{addr:06X}, current last2: 0x{current_last2:04X}, "
                      f"expected: 0x{old_last2:04X}, new: 0x{new_last2:04X}")
                new_full = (current & 0xFFFF0000) | new_last2
                rom[addr:addr+4] = struct.pack('>I', new_full)
                print(f"    APPLIED")
            else:
                print(f"  {name}:")
                print(f"    Address: 0x{addr:06X}, current: 0x{current:08X}, "
                      f"expected: 0x{oldval:08X}, new: 0x{newval:08X}")

                if current == newval:
                    print(f"    SKIP: Already patched")
                    continue

                if current != oldval:
                    print(f"    WARNING: Current value doesn't match expected! "
                          f"Patching anyway (ROM may already be modified)")

                rom[addr:addr+4] = struct.pack('>I', newval)
                print(f"    APPLIED")
    else:
        print("  WARNING: No patches found in metadata. Applying hooks manually...")
        # Fall back to manual hook application using known addresses
        apply_manual_hooks(rom)

    # Step 3: Fix checksum
    print(f"\n--- Step 3: Fix checksum ---")
    checksum, cksum_offset = compute_subaru_checksum(rom)
    old_cksum = struct.unpack('>I', rom[cksum_offset:cksum_offset+4])[0]
    rom[cksum_offset:cksum_offset+4] = struct.pack('>I', checksum)
    print(f"  Checksum at 0x{cksum_offset:06X}: 0x{old_cksum:08X} -> 0x{checksum:08X}")

    # Verify
    verify_sum = 0
    for i in range(0, len(rom), 4):
        verify_sum = (verify_sum + struct.unpack('>I', rom[i:i+4])[0]) & 0xFFFFFFFF
    print(f"  Verify sum: 0x{verify_sum:08X} (expected 0x5AA5A55A)")

    # Write output
    with open(output_path, 'wb') as f:
        f.write(rom)

    print(f"\n=== Output: {output_path} ({len(rom)} bytes) ===")
    print("Done!")


def apply_manual_hooks(rom):
    """Apply hooks manually if metadata parsing fails."""
    # These are the hooks from AE5L600L.h + compiled function addresses
    hooks = [
        # (address, old_value, new_value, description)
        # hMafCalc: literal pool entry for Pull3D in MAF calc
        # hRevLimDelete: task dispatch table entry for rev limiter
        # hWgdc: literal pool entry for WGDC function
        # hMemoryReset: literal pool entry for memory reset
    ]

    # Get function addresses from ELF
    result = subprocess.run(
        [f"{TOOLCHAIN}/sh-elf-nm", "build/MerpMod.elf"],
        capture_output=True, text=True
    )

    symbols = {}
    for line in result.stdout.strip().split('\n'):
        parts = line.split()
        if len(parts) == 3:
            addr = int(parts[0], 16)
            name = parts[2].lstrip('_')
            symbols[name] = addr

    print(f"  Found {len(symbols)} symbols in ELF")

    manual_patches = [
        (0x0000496C, symbols.get('ComputeMassAirFlow', 0), "SD/MAF Hook (hMafCalc)"),
        (0x0004AE24, symbols.get('RevLimHook', 0), "Rev Limit Hook (hRevLimDelete)"),
        (0x0004A8AC, symbols.get('WGDCHack', 0), "WGDC Main Hook (hWgdc literal pool)"),
        (0x0000FC20, symbols.get('Initializer', 0), "Memory Reset Hook (hMemoryReset)"),
        (0x000A03CE, int(0xFFFFB720) + 4, "CEL Signal Hook (hCelSignal -> pRamVariables->CelSignal)"),
    ]

    for addr, newval, desc in manual_patches:
        if newval == 0:
            print(f"  SKIP: {desc} - symbol not found")
            continue
        current = struct.unpack('>I', rom[addr:addr+4])[0]
        rom[addr:addr+4] = struct.pack('>I', newval & 0xFFFFFFFF)
        print(f"  {desc}: 0x{addr:06X} = 0x{current:08X} -> 0x{newval:08X}")


if __name__ == '__main__':
    main()
