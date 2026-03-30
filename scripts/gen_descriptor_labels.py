#!/usr/bin/env python3
"""
Generate Java label() calls for all 760 calibration descriptors.
Reads named_descriptors.txt, deduplicates names by appending address suffix,
outputs a Java code block ready to insert into ImportAE5L600L.java.
"""
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DISASM_DIR = os.path.join(SCRIPT_DIR, "..", "disassembly")

NAMED_DESC_FILE = os.path.join(DISASM_DIR, "named_descriptors.txt")
OUTPUT_FILE = os.path.join(DISASM_DIR, "descriptor_labels.txt")

# Sanitize a name to be a valid Java/Ghidra identifier
def sanitize(name):
    # Replace brackets and dots with underscores
    n = re.sub(r'[\[\].\-]', '_', name)
    # Replace .. range notation
    n = n.replace('..', '_to_')
    # Remove any remaining non-alphanumeric/underscore characters
    n = re.sub(r'[^A-Za-z0-9_]', '_', n)
    # Collapse multiple underscores
    n = re.sub(r'_+', '_', n)
    n = n.strip('_')
    return n


def main():
    # Parse named_descriptors.txt
    # Format: "   N 0xADDR  NAME   Scale   Bias   DataPtr"
    descs = []
    in_table = False

    with open(NAMED_DESC_FILE, 'r') as f:
        for line in f:
            line = line.rstrip()
            if 'NAMED DESCRIPTOR MAP' in line:
                in_table = True
                continue
            if not in_table:
                continue
            # Match lines like:   0 0x0AA760 1D_Throttle_u8_16   0.003906   0   0x0C02D4
            m = re.match(r'\s*(\d+)\s+(0x[0-9A-Fa-f]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(0x[0-9A-Fa-f]+)', line)
            if m:
                idx = int(m.group(1))
                addr = int(m.group(2), 16)
                name = m.group(3)
                scale = m.group(4)
                data_ptr = int(m.group(6), 16)
                descs.append((idx, addr, name, scale, data_ptr))

    if not descs:
        print("ERROR: No descriptors found in named_descriptors.txt")
        sys.exit(1)

    print(f"Parsed {len(descs)} descriptors")

    # Track name usage to deduplicate
    name_counts = {}
    for idx, addr, name, scale, data_ptr in descs:
        base = sanitize(name)
        name_counts[base] = name_counts.get(base, 0) + 1

    # Generate unique names: if a base name appears more than once, suffix with address
    name_seen = {}
    labeled = []
    for idx, addr, name, scale, data_ptr in descs:
        base = sanitize(name)
        if name_counts[base] == 1:
            label_name = f"desc_{base}"
        else:
            # Append address to make unique: desc_1D_ECT_u8_16_AA760
            label_name = f"desc_{base}_{addr:05X}"
        name_seen[base] = name_seen.get(base, 0) + 1
        labeled.append((addr, label_name, data_ptr, scale))

    # Write output
    lines = []
    lines.append("        // ============================================================")
    lines.append("        // CALIBRATION DESCRIPTOR LABELS (760 total, auto-generated)")
    lines.append("        // Format: desc_<type>_<dtype>_<size>[_<addr>] -> descriptor struct")
    lines.append("        // Each descriptor struct points to axis data + calibration table")
    lines.append("        // ============================================================")
    lines.append("")

    # Group by axis type prefix for readability
    groups = {}
    for addr, label_name, data_ptr, scale in labeled:
        # Extract type prefix (1D_ECT, 2D_LoadxRPM, etc.)
        parts = label_name.split('_')
        if len(parts) >= 3:
            grp = f"{parts[1]}_{parts[2]}"  # e.g. "1D_ECT" or "2D_Load"
        else:
            grp = parts[1] if len(parts) > 1 else "other"
        groups.setdefault(grp, []).append((addr, label_name, data_ptr, scale))

    total = 0
    for grp in sorted(groups.keys()):
        entries = groups[grp]
        lines.append(f"        // --- {grp} ({len(entries)} descriptors) ---")
        for addr, label_name, data_ptr, scale in sorted(entries):
            lines.append(f"        count += label(0x{addr:06X}L, \"{label_name}\");")
            total += 1
        lines.append("")

    print(f"Generated {total} label() calls")

    # Write the Java block
    with open(OUTPUT_FILE, 'w') as f:
        f.write('\n'.join(lines))
        f.write('\n')

    print(f"Written to {OUTPUT_FILE}")

    # Also print a summary
    print(f"\nTop groups by count:")
    for grp, entries in sorted(groups.items(), key=lambda x: -len(x[1]))[:15]:
        print(f"  {grp:<30} {len(entries):>4}")


if __name__ == "__main__":
    main()
