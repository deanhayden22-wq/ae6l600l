#!/usr/bin/env python3
"""
extract_rom.py - Extract raw bytes from disassembly.txt into a binary file.

Parses the SH2 disassembly text and reconstructs a partial ROM binary from
the opcode bytes and .long data present in the file. The output can be
imported into Ghidra as a raw binary (processor: SuperH SH-2, big-endian).

Usage:
    python3 extract_rom.py disassembly.txt output.bin
"""

import re
import sys


def extract_bytes(input_path, output_path):
    # Pattern for instruction lines:  "  00000BAC:  2f76        mov.l ..."
    # Captures address and 2-byte or 4-byte hex opcode
    instr_re = re.compile(
        r'^\s*([0-9A-Fa-f]{8}):\s+([0-9A-Fa-f]{4})\s+'
    )

    # Pattern for .long data:  "  00000000:  .long  0x00000C0C  ; comment"
    long_re = re.compile(
        r'^\s*([0-9A-Fa-f]{8}):\s+\.long\s+0x([0-9A-Fa-f]{8})'
    )

    entries = []  # list of (address, bytes)

    with open(input_path, 'r') as f:
        for line in f:
            m = long_re.match(line)
            if m:
                addr = int(m.group(1), 16)
                val = int(m.group(2), 16)
                entries.append((addr, val.to_bytes(4, 'big')))
                continue

            m = instr_re.match(line)
            if m:
                addr = int(m.group(1), 16)
                opcode = bytes.fromhex(m.group(2))
                entries.append((addr, opcode))

    if not entries:
        print("No byte data found in input file.", file=sys.stderr)
        sys.exit(1)

    entries.sort(key=lambda e: e[0])

    min_addr = entries[0][0]
    max_addr = entries[-1][0] + len(entries[-1][1])
    size = max_addr - min_addr

    print(f"Address range: 0x{min_addr:08X} - 0x{max_addr:08X} ({size} bytes)")
    print(f"Entries parsed: {len(entries)}")

    buf = bytearray(b'\xff' * size)  # fill with 0xFF (typical flash erased state)

    for addr, data in entries:
        offset = addr - min_addr
        buf[offset:offset + len(data)] = data

    with open(output_path, 'wb') as f:
        f.write(buf)

    print(f"Written to: {output_path}")
    print(f"\nGhidra import instructions:")
    print(f"  1. File > Import File > select '{output_path}'")
    print(f"  2. Format: Raw Binary")
    print(f"  3. Language: SuperH:SH-2:32:default (Big Endian)")
    print(f"  4. Options > Base Address: 0x{min_addr:08X}")
    print(f"  5. After import, run import_disassembly.py via")
    print(f"     Script Manager to apply labels and comments")


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <disassembly.txt> <output.bin>")
        sys.exit(1)
    extract_bytes(sys.argv[1], sys.argv[2])
