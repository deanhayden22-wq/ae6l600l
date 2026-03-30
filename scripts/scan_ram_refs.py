#!/usr/bin/env python3
"""
Scan the AE5L600L ROM for all RAM address references.

Methods:
1. Literal pool scan: mov.l @(disp,PC),Rn where loaded value is 0xFFFF####
2. GBR base scan: mov.l loads of 0xFFFF#### followed by ldc Rn,GBR
   Then trace GBR-relative accesses from that function.

Outputs a ranked RAM address map showing:
- Address, reference count, read/write pattern, likely purpose
"""
import os
import struct
import sys
from collections import defaultdict

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

def r_u16(rom, a): return struct.unpack_from(">H", rom, a)[0]
def r_u32(rom, a): return struct.unpack_from(">I", rom, a)[0]

# Already-labeled RAM addresses from ImportAE5L600L.java
KNOWN_RAM = {
    0xFFFF80FC: "knock_det_GBR_base",
    0xFFFF81BA: "KNOCK_FLAG",
    0xFFFF81BB: "KNOCK_BANK_FLAG",
    0xFFFF81D9: "fn_043d68_output",
    0xFFFF323C: "FLKC_BASE_STEP",
    0xFFFF8290: "flkc_fg_GBR_base",
    0xFFFF8294: "flkc_fg_counter",
    0xFFFF8298: "flkc_fg_cyl_index",
    0xFFFF829C: "flkc_fg_active",
    0xFFFF829D: "flkc_fg_retard_done",
    0xFFFF829E: "flkc_fg_enable",
    0xFFFF82A0: "flkc_fg_exit_flag",
    0xFFFF82A1: "flkc_fg_bank_route",
    0xFFFF82AA: "flkc_fg_prev_cyl",
    0xFFFF8258: "flkc_fg_limit_FR15",
    0xFFFF3234: "flkc_fg_ref_FR14",
    0xFFFF3244: "flkc_fg_R0_init",
    0xFFFF3248: "flkc_fg_var_3248",
    0xFFFF8233: "flkc_fg_flag_8233",
    0xFFFF7D18: "sched_status_R1",
    0xFFFF3360: "flkc_output_table",
    0xFFFF8EDC: "sched_disable_flag",
    0xFFFF7814: "afc_p_term",
    0xFFFF7448: "clol_mode_flag",
    0xFFFF7449: "clol_cond_A",
    0xFFFF744A: "clol_cond_B",
    0xFFFF744B: "cl_inhibit",
    0xFFFF744C: "cl_readiness_A",
    0xFFFF744D: "cl_readiness_B",
    0xFFFF744E: "cl_mode_state",
    0xFFFF7452: "cl_master_readiness",
    0xFFFF79C4: "ol_delay_counter_B",
    0xFFFF79C6: "ol_mode_state",
    0xFFFF79F2: "ol_active_flag",
    0xFFFF7AB4: "afl_multiplier_output",
    0xFFFF7C68: "engine_status_flag",
    0xFFFF65F6: "cl_active_flag",
    0xFFFF65C5: "engine_running_flag",
    0xFFFFB71C: "dtc_master_enable",
    0xFFFF36F0: "diag_mode_status",
    0xFFFF36F4: "dtc_enable_flag",
    0xFFFFAE08: "diag_enable_A",
    0xFFFFAE09: "diag_enable_B",
    0xFFFF726C: "transient_flag",
    0xFFFF1288: "isr_state_base",
    0xFFFF8F24: "cl_global_enable",
}


def scan_literal_pool_ram_refs(rom):
    """Find all mov.l @(disp,PC),Rn instructions that load RAM addresses."""
    rom_len = len(rom)
    ram_refs = defaultdict(list)  # ram_addr -> [(pc, register, context)]

    for pc in range(0, rom_len - 1, 2):
        word = r_u16(rom, pc)
        # mov.l @(disp,PC),Rn: 1101nnnndddddddd
        if (word >> 12) == 0xD:
            rn = (word >> 8) & 0xF
            disp = word & 0xFF
            lit_addr = (pc & ~3) + 4 + disp * 4
            if lit_addr + 4 <= rom_len:
                val = r_u32(rom, lit_addr)
                if 0xFFFF0000 <= val <= 0xFFFFFFFF:
                    ram_refs[val].append(pc)

    return ram_refs


def classify_ram_region(addr):
    """Classify RAM address by region."""
    offset = addr & 0xFFFF
    if 0x0000 <= offset < 0x1000:
        return "peripheral_regs"
    elif 0x1000 <= offset < 0x3000:
        return "system_state"
    elif 0x3000 <= offset < 0x4000:
        return "cal_mirrors"  # Calibration mirror area
    elif 0x4000 <= offset < 0x6000:
        return "sensor_data"
    elif 0x6000 <= offset < 0x7000:
        return "adc_processed"
    elif 0x7000 <= offset < 0x8000:
        return "fuel_timing"
    elif 0x8000 <= offset < 0x9000:
        return "knock_flkc"
    elif 0x9000 <= offset < 0xA000:
        return "scheduler"
    elif 0xA000 <= offset < 0xB000:
        return "diag_state"
    elif 0xB000 <= offset < 0xC000:
        return "stack_area"
    else:
        return "other"


def find_gbr_bases(rom):
    """Find all GBR base addresses by scanning for ldc Rn,GBR preceded by mov.l loads."""
    rom_len = len(rom)
    gbr_bases = defaultdict(list)  # gbr_addr -> [pc_of_ldc]

    for pc in range(0, rom_len - 1, 2):
        word = r_u16(rom, pc)
        # ldc Rn,GBR: 0100nnnn00011110
        if (word & 0xF0FF) == 0x401E:
            rn = (word >> 8) & 0xF
            # Look back for mov.l @(disp,PC),Rn
            for back in range(1, 10):
                prev_pc = pc - back * 2
                if prev_pc < 0:
                    break
                prev_word = r_u16(rom, prev_pc)
                if (prev_word >> 12) == 0xD and ((prev_word >> 8) & 0xF) == rn:
                    disp = prev_word & 0xFF
                    lit_addr = (prev_pc & ~3) + 4 + disp * 4
                    if lit_addr + 4 <= rom_len:
                        val = r_u32(rom, lit_addr)
                        if 0xFFFF0000 <= val <= 0xFFFFFFFF:
                            gbr_bases[val].append(pc)
                    break

    return gbr_bases


def main():
    rom = load_rom()
    rom_len = len(rom)
    print(f"Loaded ROM: {rom_len} bytes\n")

    # Phase 1: Scan literal pool RAM references
    print("Phase 1: Scanning literal pool mov.l for RAM addresses...")
    ram_refs = scan_literal_pool_ram_refs(rom)
    print(f"  Found {len(ram_refs)} unique RAM addresses referenced via literal pool\n")

    # Phase 2: Find GBR bases
    print("Phase 2: Scanning for GBR base addresses...")
    gbr_bases = find_gbr_bases(rom)
    print(f"  Found {len(gbr_bases)} unique GBR bases\n")

    # Combine and rank
    all_addrs = set(ram_refs.keys()) | set(gbr_bases.keys())
    print(f"Total unique RAM addresses: {len(all_addrs)}")

    # Stats by region
    region_counts = defaultdict(int)
    for addr in all_addrs:
        region_counts[classify_ram_region(addr)] += 1

    print(f"\nRegion distribution:")
    for region, count in sorted(region_counts.items(), key=lambda x: -x[1]):
        print(f"  {region:<20} {count:>4} addresses")

    # Sort by reference count
    ranked = sorted(all_addrs,
                    key=lambda a: len(ram_refs.get(a, [])) + len(gbr_bases.get(a, [])) * 5,
                    reverse=True)

    # Print top unlabeled addresses
    print(f"\n{'='*100}")
    print(f"TOP RAM ADDRESSES BY REFERENCE COUNT (unlabeled only)")
    print(f"{'='*100}")
    print(f"{'Rank':>4} {'Address':>12} {'LitPool':>8} {'GBR':>4} {'Region':<20} {'Known Label':<30}")
    print(f"{'-'*100}")

    unlabeled_rank = 0
    for addr in ranked:
        lit_count = len(ram_refs.get(addr, []))
        gbr_count = len(gbr_bases.get(addr, []))
        total = lit_count + gbr_count
        if total < 2:
            continue
        label = KNOWN_RAM.get(addr, "")
        region = classify_ram_region(addr)

        if not label:
            unlabeled_rank += 1
            if unlabeled_rank <= 150:
                print(f"{unlabeled_rank:>4} 0x{addr:08X} {lit_count:>8} {gbr_count:>4} {region:<20}")

    # Print all labeled for reference
    print(f"\n{'='*100}")
    print(f"ALREADY LABELED ({len(KNOWN_RAM)} addresses)")
    print(f"{'='*100}")
    for addr in sorted(KNOWN_RAM.keys()):
        lit_count = len(ram_refs.get(addr, []))
        gbr_count = len(gbr_bases.get(addr, []))
        print(f"  0x{addr:08X} {lit_count:>6}+{gbr_count}G  {KNOWN_RAM[addr]}")

    # Print GBR bases ranked
    print(f"\n{'='*100}")
    print(f"GBR BASE ADDRESSES (used as GBR register base, ranked)")
    print(f"{'='*100}")
    gbr_ranked = sorted(gbr_bases.items(), key=lambda x: -len(x[1]))
    for addr, pcs in gbr_ranked[:40]:
        label = KNOWN_RAM.get(addr, "")
        print(f"  0x{addr:08X} ({len(pcs):>3} uses)  {label}")

    # Cluster analysis: find groups of adjacent addresses (likely structs)
    print(f"\n{'='*100}")
    print(f"RAM CLUSTERS (groups of adjacent addresses = likely data structures)")
    print(f"{'='*100}")

    sorted_addrs = sorted(all_addrs)
    clusters = []
    current_cluster = [sorted_addrs[0]] if sorted_addrs else []

    for addr in sorted_addrs[1:]:
        if addr - current_cluster[-1] <= 8:  # Within 8 bytes = same cluster
            current_cluster.append(addr)
        else:
            if len(current_cluster) >= 4:  # Only report clusters of 4+ addresses
                clusters.append(current_cluster)
            current_cluster = [addr]
    if len(current_cluster) >= 4:
        clusters.append(current_cluster)

    for cluster in sorted(clusters, key=lambda c: -len(c))[:30]:
        start = cluster[0]
        end = cluster[-1]
        span = end - start
        label_count = sum(1 for a in cluster if a in KNOWN_RAM)
        region = classify_ram_region(start)
        total_refs = sum(len(ram_refs.get(a, [])) for a in cluster)
        print(f"\n  0x{start:08X}-0x{end:08X} ({len(cluster)} addrs, {span} bytes, "
              f"{total_refs} refs, {label_count} labeled) [{region}]")
        for addr in cluster[:12]:
            lit = len(ram_refs.get(addr, []))
            gbr = len(gbr_bases.get(addr, []))
            label = KNOWN_RAM.get(addr, "")
            suffix = f"  <- {label}" if label else ""
            print(f"    0x{addr:08X}: {lit:>3} refs{suffix}")
        if len(cluster) > 12:
            print(f"    ... +{len(cluster)-12} more")


if __name__ == "__main__":
    main()
