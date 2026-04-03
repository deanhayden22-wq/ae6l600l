#!/usr/bin/env python3
"""
Generate Ghidra label statements for unnamed GBR bases.

Reads gbr_registry.txt, cross-references against RAM region definitions,
and produces Java label() calls for ImportAE5L600L.java.

Also checks for duplicates against the existing Ghidra script.
"""

import re
import sys
from pathlib import Path

# RAM region definitions from ram_map_raw.txt
# These define the functional purpose of each RAM address range
RAM_REGIONS = {
    # (start, end): (prefix, description)
    (0xFFFF2000, 0xFFFF2FFF): ("sys", "system_state"),
    (0xFFFF3000, 0xFFFF3FFF): ("cal", "cal_mirrors"),
    (0xFFFF4000, 0xFFFF4FFF): ("sens", "sensor_data"),
    (0xFFFF5000, 0xFFFF5FFF): ("sens", "sensor_data"),
    (0xFFFF6000, 0xFFFF6FFF): ("adc", "adc_processed"),
    (0xFFFF7000, 0xFFFF7FFF): ("fuel", "fuel_timing"),
    (0xFFFF8000, 0xFFFF8FFF): ("kflk", "knock_flkc"),
    (0xFFFF9000, 0xFFFF9FFF): ("sched", "scheduler"),
    (0xFFFFA000, 0xFFFFAFFF): ("diag", "diag_state"),
    (0xFFFFB000, 0xFFFFBFFF): ("stk", "stack_area"),
}

# Sub-regions with more specific naming
SUB_REGIONS = {
    # Knock/FLKC workspace sub-regions
    (0xFFFF80FC, 0xFFFF81FF): ("knock", "knock detection"),
    (0xFFFF8200, 0xFFFF82FF): ("flkc", "FLKC state"),
    (0xFFFF8300, 0xFFFF83FF): ("idle", "idle control"),
    (0xFFFF8400, 0xFFFF86FF): ("eng", "engine state"),
    (0xFFFF8700, 0xFFFF88FF): ("ign", "ignition/timing"),
    (0xFFFF8900, 0xFFFF8AFF): ("sens", "sensor structs"),
    (0xFFFF8B00, 0xFFFF8BFF): ("boost", "boost control"),
    (0xFFFF8C00, 0xFFFF8DFF): ("tim", "timing workspace"),
    (0xFFFF8E00, 0xFFFF8FFF): ("sched", "scheduler/CL-OL"),
    # Fuel timing sub-regions
    (0xFFFF7000, 0xFFFF74FF): ("fuel", "fuel state"),
    (0xFFFF7500, 0xFFFF77FF): ("fuel", "fuel pipeline"),
    (0xFFFF7800, 0xFFFF79FF): ("afc", "AFC/AFL state"),
    (0xFFFF7A00, 0xFFFF7BFF): ("afl", "AFL/fuel trim"),
    (0xFFFF7C00, 0xFFFF7DFF): ("tim", "timing state"),
    (0xFFFF7E00, 0xFFFF7FFF): ("tim", "timing workspace"),
    # Scheduler sub-regions
    (0xFFFF9000, 0xFFFF90FF): ("sched", "scheduler core"),
    (0xFFFF9100, 0xFFFF92FF): ("sched", "scheduler queues"),
    (0xFFFF9300, 0xFFFF94FF): ("evap", "EVAP/emissions diag"),
    (0xFFFF9500, 0xFFFF97FF): ("learn", "learning/adaptation"),
    (0xFFFF9800, 0xFFFF99FF): ("sched", "scheduler periodic"),
    (0xFFFF9A00, 0xFFFF9FFF): ("sched", "scheduler timers"),
    # Diagnostic sub-regions
    (0xFFFFA000, 0xFFFFA1FF): ("diag", "diag monitor"),
    (0xFFFFA200, 0xFFFFA5FF): ("diag", "diag trip/fault"),
    (0xFFFFA600, 0xFFFFA7FF): ("diag", "diag maturation"),
    (0xFFFFA800, 0xFFFFABFF): ("dtc", "DTC state"),
    (0xFFFFAC00, 0xFFFFADFF): ("diag", "diag protocol"),
    (0xFFFFAE00, 0xFFFFAFFF): ("diag", "diag history"),
    # Sensor data sub-regions
    (0xFFFF5B00, 0xFFFF5CFF): ("io", "I/O peripheral"),
    (0xFFFF5D00, 0xFFFF5EFF): ("io", "I/O state"),
    (0xFFFF5F00, 0xFFFF5FFF): ("io", "I/O workspace"),
    (0xFFFF6000, 0xFFFF61FF): ("adc", "ADC channels"),
    (0xFFFF6200, 0xFFFF63FF): ("adc", "ADC sensors"),
    (0xFFFF6400, 0xFFFF65FF): ("adc", "ADC throttle/TPS"),
    (0xFFFF6600, 0xFFFF67FF): ("adc", "ADC RPM/speed"),
    (0xFFFF6800, 0xFFFF6BFF): ("adc", "ADC pressure/misc"),
}


def get_region_prefix(addr):
    """Get the most specific region prefix for an address."""
    # Check sub-regions first (more specific)
    for (start, end), (prefix, desc) in SUB_REGIONS.items():
        if start <= addr <= end:
            return prefix, desc
    # Fall back to main regions
    for (start, end), (prefix, desc) in RAM_REGIONS.items():
        if start <= addr <= end:
            return prefix, desc
    return "ram", "unknown"


def parse_gbr_registry(filepath):
    """Parse gbr_registry.txt and return list of (uses, addr, name, desc)."""
    entries = []
    with open(filepath, 'r') as f:
        for line in f:
            # Match lines like:  19  0xFFFF837E  idle_control_GBR   description...
            m = re.match(r'\s+(\d+)\s+0x([0-9A-Fa-f]+)\s+(\S+)\s*(.*)', line)
            if m:
                uses = int(m.group(1))
                addr = int(m.group(2), 16)
                name = m.group(3).strip()
                desc = m.group(4).strip()
                entries.append((uses, addr, name, desc))
    return entries


def get_existing_labels(java_filepath):
    """Extract all hex addresses already labeled in the Ghidra script."""
    existing = set()
    with open(java_filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Match label(0xFFFF1234L, or labelComment(0xFFFF1234L,
            for m in re.finditer(r'(?:label|labelComment)\(0x([0-9A-Fa-f]+)L?', line):
                existing.add(int(m.group(1), 16))
    return existing


def generate_label_name(addr, prefix):
    """Generate a systematic label name from address and region prefix."""
    short_addr = addr & 0xFFFF
    return f"gbr_{prefix}_{short_addr:04X}"


def main():
    base = Path(__file__).resolve().parent.parent
    registry_path = base / "disassembly" / "maps" / "gbr_registry.txt"
    java_path = base / "disassembly" / "ghidra" / "ImportAE5L600L.java"

    entries = parse_gbr_registry(registry_path)
    existing = get_existing_labels(java_path)

    print(f"Parsed {len(entries)} GBR registry entries")
    print(f"Found {len(existing)} existing labels in Ghidra script")

    unnamed = [(u, a, n, d) for u, a, n, d in entries if n == "???"]
    already_named = [(u, a, n, d) for u, a, n, d in entries if n != "???"]

    print(f"Unnamed GBR bases: {len(unnamed)}")
    print(f"Already named: {len(already_named)}")

    # Check which named entries are already in Ghidra script
    named_in_script = sum(1 for _, a, _, _ in already_named if a in existing)
    named_missing = [(u, a, n, d) for u, a, n, d in already_named if a not in existing]
    print(f"Named entries already in script: {named_in_script}")
    print(f"Named entries missing from script: {len(named_missing)}")

    # Generate labels for unnamed entries
    new_labels = []
    skipped_existing = 0

    for uses, addr, _, _ in unnamed:
        if addr in existing:
            skipped_existing += 1
            continue
        prefix, region_desc = get_region_prefix(addr)
        label_name = generate_label_name(addr, prefix)
        comment = f"GBR workspace base ({uses} use{'s' if uses > 1 else ''}). Region: {region_desc}."
        new_labels.append((addr, label_name, comment, uses))

    # Also generate for named entries missing from the script
    for uses, addr, name, desc in named_missing:
        if addr in existing:
            skipped_existing += 1
            continue
        # Use the existing name instead of generating one
        comment = desc if desc else f"GBR workspace ({uses} uses)"
        new_labels.append((addr, name, comment, uses))

    print(f"Skipped (already in script): {skipped_existing}")
    print(f"New labels to generate: {len(new_labels)}")

    # Sort by address for clean output
    new_labels.sort(key=lambda x: x[0])

    # Write Java label statements
    output_path = base / "disassembly" / "ghidra" / "gbr_labels_generated.txt"
    with open(output_path, 'w') as f:
        f.write("        // =====================================================================\n")
        f.write("        // GBR WORKSPACE LABELS (auto-generated from gbr_registry.txt)\n")
        f.write(f"        // {len(new_labels)} labels for GBR bases cross-referenced against RAM regions\n")
        f.write("        // =====================================================================\n\n")

        current_region = None
        for addr, name, comment, uses in new_labels:
            _, region_desc = get_region_prefix(addr)
            if region_desc != current_region:
                current_region = region_desc
                f.write(f"\n        // --- {region_desc} ---\n")

            # Escape any quotes in comment
            safe_comment = comment.replace('"', '\\"')
            f.write(f'        count += labelComment(0x{addr:08X}L, "{name}",\n')
            f.write(f'            "{safe_comment}");\n')

    print(f"\nWrote {len(new_labels)} label statements to: {output_path}")

    # Summary by region
    print("\nLabels by region:")
    region_counts = {}
    for addr, _, _, _ in new_labels:
        _, region_desc = get_region_prefix(addr)
        region_counts[region_desc] = region_counts.get(region_desc, 0) + 1
    for region, count in sorted(region_counts.items(), key=lambda x: -x[1]):
        print(f"  {region}: {count}")

    # Write summary stats
    stats_path = base / "disassembly" / "maps" / "gbr_labeling_stats.txt"
    with open(stats_path, 'w') as f:
        f.write("GBR Bulk Labeling Results\n")
        f.write("========================\n")
        f.write(f"Date: 2026-04-03\n\n")
        f.write(f"GBR Registry: {len(entries)} total entries\n")
        f.write(f"  Already named: {len(already_named)}\n")
        f.write(f"  Unnamed (???): {len(unnamed)}\n\n")
        f.write(f"Ghidra script: {len(existing)} existing labels\n")
        f.write(f"  Already present: {skipped_existing}\n")
        f.write(f"  New labels generated: {len(new_labels)}\n\n")
        f.write("New labels by region:\n")
        for region, count in sorted(region_counts.items(), key=lambda x: -x[1]):
            f.write(f"  {region}: {count}\n")
        f.write(f"\nTotal new label operations: {len(new_labels)}\n")
        f.write(f"New total Ghidra labels: {len(existing) + len(new_labels)}\n")

    print(f"Stats written to: {stats_path}")


if __name__ == "__main__":
    main()
