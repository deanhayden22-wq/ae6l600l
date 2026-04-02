#!/usr/bin/env python3
"""
Identify unnamed GBR workspaces by cross-referencing:
  - ROM binary (ldc Rn,GBR instruction scan)
  - task_call_graph.txt (GBR base -> task mapping)
  - ram_reference.txt (named RAM within GBR struct range)
  - gbr_structures.txt (struct fingerprints for clone detection)

Outputs an enriched GBR registry with suggested names and subsystem mappings.
"""
import os
import re
import struct
import sys
from collections import defaultdict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.join(SCRIPT_DIR, "..", "..")
ROM_DIR = os.path.join(ROOT_DIR, "rom")
MAPS_DIR = os.path.join(ROOT_DIR, "disassembly", "maps")


# ---------------------------------------------------------------------------
# ROM helpers (from map_gbr_structures.py)
# ---------------------------------------------------------------------------
def load_rom():
    p = os.path.join(ROM_DIR, "ae5l600l.bin")
    if os.path.isfile(p):
        with open(p, "rb") as f:
            return f.read()
    for fn in sorted(os.listdir(ROM_DIR)):
        if fn.lower().endswith(".bin"):
            with open(os.path.join(ROM_DIR, fn), "rb") as f:
                return f.read()
    sys.exit("No ROM found in " + ROM_DIR)

def r_u16(rom, a): return struct.unpack_from(">H", rom, a)[0]
def r_u32(rom, a): return struct.unpack_from(">I", rom, a)[0]


# ---------------------------------------------------------------------------
# Known names (authoritative — already verified)
# ---------------------------------------------------------------------------
KNOWN_NAMES = {
    0xFFFF80FC: "knock_det_GBR_base",
    0xFFFF81BA: "KNOCK_FLAG",
    0xFFFF81BB: "KNOCK_BANK_FLAG",
    0xFFFF8290: "flkc_fg_GBR_base",
    0xFFFF837E: "idle_control_GBR",
    0xFFFF83AC: "idle_workspace_GBR",
    0xFFFF9094: "sched_task_GBR",
    0xFFFFA160: "diag_monitor_GBR",
    0xFFFF69F0: "boost_pressure",
    0xFFFF81F0: "knock_state_base",
    0xFFFF8EA8: "sched_control_GBR",
    0xFFFF6155: "adc_channel_status",
    0xFFFF980C: "sched_periodic_GBR",
    0xFFFFAC6C: "diag_protocol_GBR",
    0xFFFF726C: "transient_state_flag",
    0xFFFF7448: "clol_mode_flag",
    0xFFFF5C98: "ssm_diagnostic_GBR",
    0xFFFF9FC6: "sched_timer_base",
    0xFFFF91C4: "sched_queue_base",
    0xFFFFA198: "egr_diag_state",
    0xFFFF77BC: "fuel_pipeline_base",
    0xFFFF798C: "timing_state_var",
    0xFFFF7AB4: "afl_multiplier_output",
    0xFFFF7AF4: "fuel_ipw_state_B",
    0xFFFF4024: "adc_raw_workspace",
    0xFFFF36F0: "diag_mode_status",
    0xFFFF3480: "cal_mirror_base",
    0xFFFFA156: "diag_state_B_start",
    0xFFFFAF70: "diag_state_A_start",
    0xFFFF7FBC: "timing_final_advance",
    0xFFFF8C9C: "timing_workspace_A",
    0xFFFF9FA8: "sched_timer_B",
    0xFFFF7878: "fuel_enrichment_B",
    0xFFFF8F08: "cl_readiness_A_input",
    0xFFFF8998: "sensor_struct_8998",
    # Tier 1 — verified from analysis files and struct patterns
    0xFFFF837B: "idle_dispatch_workspace",   # idle_control_analysis.txt: main dispatcher state
    0xFFFF8387: "knock_flkc_workspace",      # ram_map_raw: knock_flkc region, 13 refs
    0xFFFF35E4: "cal_mirror_lookup",         # 26 fields; callers 0x9672C/0x96BC0 (cal_mirror)
    0xFFFF3718: "cal_descriptor_queue",      # 39 fields, 129 accesses; descriptor write pattern
    0xFFFF3682: "cal_output_buffer",         # 22 fields; single caller 0x5B16C
    0xFFFF8EC7: "sched_control_secondary",   # adjacent to sched_control_GBR (0xFFFF8EA8)
    # Task-mapped — from task_call_graph.txt
    0xFFFF81F8: "knock_thresh_config",       # task04_knock_thresh, task10_knock_config
    0xFFFF8210: "knock_window_state",        # task08_knock_window
    0xFFFF821C: "knock_thresh_calc",         # task03_knock_thresh
    0xFFFF8258: "roughness_correction",      # task15_rough_corr
    0xFFFF8277: "roughness_detection",       # task13_rough_corr
    0xFFFF8298: "knock_percyl_state",        # task22_knock_percyl
    0xFFFF829E: "knock_window_update",       # task21_knock_win_upd
    0xFFFF8B50: "boost_wastegate_calc",      # task51_boost_wg_calc
    0xFFFF7EC0: "base_advance_state",        # task49_base_advance
    0xFFFF7E90: "warmup_blend_state",        # task50_timing_blend_int (base=warmup_corr_cyl0)
    0xFFFF7F0C: "timing_blend_app",          # task32_timing_blend_app
    0xFFFF7F10: "base_timing_state",         # task30_base_timing
    0xFFFF7FD4: "timing_ws_init",            # task33_timing_ws_init
    0xFFFF8000: "timing_percond_state",      # task36_timing_percond
    0xFFFF8290: "flkc_fg_state",             # task25_flkc_FG (already in original but adding desc)
}


# ---------------------------------------------------------------------------
# Parse task_call_graph.txt -> {gbr_addr: [task_name, ...]}
# ---------------------------------------------------------------------------
def parse_task_call_graph():
    path = os.path.join(MAPS_DIR, "task_call_graph.txt")
    gbr_to_tasks = defaultdict(list)
    task_gbr_to_addr = {}  # (task_name, gbr_addr) -> task_entry_addr

    if not os.path.isfile(path):
        print(f"WARNING: {path} not found", file=sys.stderr)
        return gbr_to_tasks

    current_task = None
    current_addr = None
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            # Match task header: [NN] task_name  @ 0xADDR
            m = re.match(r'\[\s*(\d+)\]\s+(\S+)\s+@\s+(0x[0-9A-Fa-f]+)', line)
            if m:
                current_task = m.group(2)
                current_addr = int(m.group(3), 16)
                continue
            # Match GBR line
            m = re.match(r'\s+GBR:\s+(.*)', line)
            if m and current_task:
                for addr_str in m.group(1).split(','):
                    addr_str = addr_str.strip()
                    if addr_str.startswith('0x'):
                        addr = int(addr_str, 16)
                        gbr_to_tasks[addr].append(current_task)
                        task_gbr_to_addr[(current_task, addr)] = current_addr

    return gbr_to_tasks


# ---------------------------------------------------------------------------
# Parse ram_reference.txt -> {addr: name}
# ---------------------------------------------------------------------------
def parse_ram_reference():
    path = os.path.join(MAPS_DIR, "ram_reference.txt")
    ram_names = {}

    if not os.path.isfile(path):
        print(f"WARNING: {path} not found", file=sys.stderr)
        return ram_names

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            m = re.match(r'\s+\d+\s+(0x[0-9A-Fa-f]+)\s+(\S+)', line)
            if m:
                addr = int(m.group(1), 16)
                name = m.group(2)
                if name != "???":
                    ram_names[addr] = name

    return ram_names


# ---------------------------------------------------------------------------
# Parse gbr_structures.txt -> struct fingerprints
# ---------------------------------------------------------------------------
def parse_gbr_structures():
    path = os.path.join(MAPS_DIR, "gbr_structures.txt")
    structs = {}  # gbr_addr -> {size, fields, total_accesses, callers, field_list}

    if not os.path.isfile(path):
        print(f"WARNING: {path} not found", file=sys.stderr)
        return structs

    current_addr = None
    current_info = None

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            m = re.match(r'GBR = (0x[0-9A-Fa-f]+)', line)
            if m:
                if current_addr and current_info:
                    structs[current_addr] = current_info
                current_addr = int(m.group(1), 16)
                current_info = {'size': 0, 'fields': 0, 'total_accesses': 0,
                                'callers': set(), 'field_list': []}
                continue

            if current_info is None:
                continue

            # Parse struct size line
            m = re.match(r'\s+Struct size: >= (\d+) bytes\s+\|\s+(\d+) unique fields\s+\|\s+(\d+) total accesses', line)
            if m:
                current_info['size'] = int(m.group(1))
                current_info['fields'] = int(m.group(2))
                current_info['total_accesses'] = int(m.group(3))
                continue

            # Parse field line for caller addresses
            m = re.match(r'\s+\+0x([0-9A-Fa-f]+)\s+\(0x[0-9A-Fa-f]+\):\s+(\S+)\s+([RW/]+)\s+\[\s*(\d+)x\].*from:\s+(.*)', line)
            if m:
                offset = int(m.group(1), 16)
                dtype = m.group(2)
                rw = m.group(3)
                count = int(m.group(4))
                callers_str = m.group(5)
                current_info['field_list'].append((offset, dtype, rw, count))
                for c in callers_str.split(','):
                    c = c.strip()
                    if c.startswith('0x'):
                        try:
                            current_info['callers'].add(int(c, 16))
                        except ValueError:
                            pass

    if current_addr and current_info:
        structs[current_addr] = current_info

    return structs


# ---------------------------------------------------------------------------
# Scan ROM for all ldc Rn,GBR instructions -> {gbr_addr: [caller_pcs]}
# ---------------------------------------------------------------------------
def scan_gbr_sets(rom):
    gbr_sets = defaultdict(list)  # gbr_addr -> [pc where ldc happens]
    rom_len = len(rom)

    for pc in range(0, rom_len - 1, 2):
        word = r_u16(rom, pc)
        # ldc Rn,GBR: 0100nnnn00011110
        if (word & 0xF0FF) == 0x401E:
            rn = (word >> 8) & 0xF
            # Find the mov.l that loaded Rn (search back up to 10 instructions)
            for back in range(1, 10):
                prev_pc = pc - back * 2
                if prev_pc < 0:
                    break
                prev_word = r_u16(rom, prev_pc)
                if (prev_word >> 12) == 0xD and ((prev_word >> 8) & 0xF) == rn:
                    disp = prev_word & 0xFF
                    lit_addr = (prev_pc & ~3) + 4 + disp * 4
                    if lit_addr + 4 <= rom_len:
                        gbr_val = r_u32(rom, lit_addr)
                        if 0xFFFF0000 <= gbr_val <= 0xFFFFFFFF:
                            gbr_sets[gbr_val].append(pc)
                    break

    return gbr_sets


# ---------------------------------------------------------------------------
# Find GBR-relative accesses near a ldc instruction
# ---------------------------------------------------------------------------
def find_gbr_accesses(rom, ldc_pc, search_range=400):
    accesses = []
    start = max(0, ldc_pc - 20)
    end = min(len(rom) - 1, ldc_pc + search_range)

    for pc in range(start, end, 2):
        if pc + 2 > len(rom):
            break
        word = r_u16(rom, pc)
        hi = (word >> 8) & 0xFF
        disp = word & 0xFF

        if hi == 0xC4:
            accesses.append((disp, 1, 'R', pc))
        elif hi == 0xC5:
            accesses.append((disp * 2, 2, 'R', pc))
        elif hi == 0xC6:
            accesses.append((disp * 4, 4, 'R', pc))
        elif hi == 0xC0:
            accesses.append((disp, 1, 'W', pc))
        elif hi == 0xC1:
            accesses.append((disp * 2, 2, 'W', pc))
        elif hi == 0xC2:
            accesses.append((disp * 4, 4, 'W', pc))

        if word == 0x000B:  # RTS
            break

    return accesses


# ---------------------------------------------------------------------------
# Compute struct fingerprint for clone detection
# ---------------------------------------------------------------------------
def struct_fingerprint(struct_info):
    """Return (size, fields, access_pattern_hash) for clone detection."""
    if not struct_info or not struct_info.get('field_list'):
        return None
    fl = struct_info['field_list']
    # Pattern: sequence of (dtype, rw) tuples
    pattern = tuple((dtype, rw) for _, dtype, rw, _ in sorted(fl))
    return (struct_info['size'], struct_info['fields'], hash(pattern))


# ---------------------------------------------------------------------------
# RAM region classification
# ---------------------------------------------------------------------------
REGION_MAP = [
    (0xFFFF2000, 0xFFFF3600, "descriptor/cal_mirror"),
    (0xFFFF3600, 0xFFFF4000, "cal_mirror/timer"),
    (0xFFFF4000, 0xFFFF4400, "hw_io/adc"),
    (0xFFFF5B00, 0xFFFF6200, "peripheral/sensor"),
    (0xFFFF6200, 0xFFFF6A00, "sensor_data"),
    (0xFFFF6A00, 0xFFFF7000, "boost/misc"),
    (0xFFFF7000, 0xFFFF7800, "fuel_state"),
    (0xFFFF7800, 0xFFFF8000, "fuel/timing"),
    (0xFFFF8000, 0xFFFF8400, "timing/idle/knock"),
    (0xFFFF8400, 0xFFFF8E00, "ignition/knock_ext"),
    (0xFFFF8E00, 0xFFFF9200, "cl_ol/scheduler"),
    (0xFFFF9200, 0xFFFFA000, "scheduler_ext"),
    (0xFFFFA000, 0xFFFFB000, "diagnostics"),
]

def classify_region(addr):
    for lo, hi, name in REGION_MAP:
        if lo <= addr < hi:
            return name
    return "unknown"


# ---------------------------------------------------------------------------
# Suggest name based on all available context
# ---------------------------------------------------------------------------
def suggest_name(gbr_addr, tasks, ram_names, struct_info, gbr_sets):
    """Generate a suggested name and confidence level."""
    # Check if already named
    if gbr_addr in KNOWN_NAMES:
        return KNOWN_NAMES[gbr_addr], "KNOWN", ""

    evidence = []
    suggested = None
    confidence = "LOW"

    # 1. Task-based naming
    if tasks:
        task_str = tasks[0]
        # Extract subsystem from task name
        subsys_map = {
            'knock': 'knock', 'flkc': 'flkc', 'timing': 'timing',
            'idle': 'idle', 'boost': 'boost', 'diag': 'diag',
            'fuel': 'fuel', 'inj': 'injection', 'ign': 'ignition',
            'maf': 'maf', 'evap': 'evap', 'egr': 'egr',
            'rough': 'roughness', 'mps': 'mapswitch',
        }
        for key, subsys in subsys_map.items():
            if key in task_str:
                suggested = f"{subsys}_workspace_{gbr_addr & 0xFFFF:04X}"
                evidence.append(f"task: {', '.join(tasks)}")
                confidence = "MEDIUM"
                break
        if not suggested:
            suggested = f"task_workspace_{gbr_addr & 0xFFFF:04X}"
            evidence.append(f"task: {', '.join(tasks)}")
            confidence = "LOW"

    # 2. Nearby named RAM
    nearby = []
    for offset in range(-16, 64):
        check_addr = gbr_addr + offset
        if check_addr in ram_names:
            nearby.append((offset, ram_names[check_addr]))
    if nearby:
        evidence.append(f"near: {', '.join(f'{n}({o:+d})' for o, n in nearby[:4])}")
        # Use nearest named address for subsystem hint
        if not suggested:
            closest_name = min(nearby, key=lambda x: abs(x[0]))[1]
            prefix = closest_name.split('_')[0] if '_' in closest_name else closest_name[:4]
            suggested = f"{prefix}_workspace_{gbr_addr & 0xFFFF:04X}"
            confidence = "LOW"

    # 3. Struct fingerprint — descriptor table clone detection
    #    Full clones: 222B/66 fields. Partial clones: 200-222B / 60-66 fields
    #    with alternating long-write/word-read pattern from a single caller range.
    if struct_info:
        si = struct_info
        if si['size'] >= 200 and si['fields'] >= 60 and si['size'] <= 222:
            suggested = f"desc_table_copy_{gbr_addr & 0xFFFF:04X}"
            evidence.append(f"{si['size']}-byte/{si['fields']}-field descriptor clone")
            confidence = "HIGH"
        elif (si['size'] >= 50 and si['fields'] >= 15
              and si['total_accesses'] <= si['fields'] + 5
              and all(rw in ('W', 'R') for _, _, rw, _ in si.get('field_list', []))
              and 0xFFFF2000 <= gbr_addr < 0xFFFF3600):
            # Single-pass write pattern in descriptor region
            suggested = f"desc_partial_copy_{gbr_addr & 0xFFFF:04X}"
            evidence.append(f"{si['size']}-byte/{si['fields']}-field descriptor partial")
            confidence = "MEDIUM"
        else:
            evidence.append(f"struct: {si['size']}B, {si['fields']} fields, {si['total_accesses']} accesses")

    # 4. Access pattern (read-heavy vs write-heavy)
    use_count = len(gbr_sets.get(gbr_addr, []))
    if use_count > 0:
        evidence.append(f"{use_count} ldc uses")

    # 5. Region classification
    region = classify_region(gbr_addr)
    evidence.append(f"region: {region}")

    if not suggested:
        suggested = f"workspace_{gbr_addr & 0xFFFF:04X}"

    return suggested, confidence, "; ".join(evidence)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("Loading ROM...", file=sys.stderr)
    rom = load_rom()

    print("Scanning GBR instructions...", file=sys.stderr)
    gbr_sets = scan_gbr_sets(rom)

    print("Parsing task call graph...", file=sys.stderr)
    gbr_to_tasks = parse_task_call_graph()

    print("Parsing RAM reference...", file=sys.stderr)
    ram_names = parse_ram_reference()

    print("Parsing GBR structures...", file=sys.stderr)
    gbr_structs = parse_gbr_structures()

    # Merge all known GBR addresses
    all_gbr = set(gbr_sets.keys()) | set(gbr_to_tasks.keys()) | set(gbr_structs.keys())

    # Build enriched registry
    entries = []
    for addr in sorted(all_gbr):
        uses = len(gbr_sets.get(addr, []))
        tasks = gbr_to_tasks.get(addr, [])
        struct_info = gbr_structs.get(addr, None)

        name, confidence, evidence = suggest_name(
            addr, tasks, ram_names, struct_info, gbr_sets)

        entries.append({
            'addr': addr,
            'uses': uses,
            'name': name,
            'confidence': confidence,
            'evidence': evidence,
            'tasks': tasks,
            'struct_info': struct_info,
        })

    # --- Output ---

    # 1. Summary stats
    total = len(entries)
    known = sum(1 for e in entries if e['confidence'] == 'KNOWN')
    high = sum(1 for e in entries if e['confidence'] == 'HIGH')
    medium = sum(1 for e in entries if e['confidence'] == 'MEDIUM')
    low = sum(1 for e in entries if e['confidence'] == 'LOW')

    print(f"\nGBR Workspace Identification Report")
    print(f"=" * 100)
    print(f"Total GBR bases: {total}")
    print(f"  Already named (KNOWN): {known}")
    print(f"  High confidence:       {high}")
    print(f"  Medium confidence:     {medium}")
    print(f"  Low confidence:        {low}")
    print()

    # 2. Descriptor clones
    clones = [e for e in entries if e['confidence'] == 'HIGH'
              and 'descriptor clone' in e.get('evidence', '')]
    if clones:
        print(f"\nDESCRIPTOR TABLE CLONES (222-byte / 66-field pattern)")
        print(f"-" * 100)
        for e in clones:
            print(f"  0x{e['addr']:08X}  {e['name']}")
        print()

    # 3. Task-mapped workspaces (MEDIUM+)
    task_mapped = [e for e in entries if e['confidence'] == 'MEDIUM']
    if task_mapped:
        print(f"\nTASK-MAPPED WORKSPACES")
        print(f"-" * 100)
        print(f"  {'Address':>12}  {'Uses':>5}  {'Suggested Name':<40}  Evidence")
        print(f"  {'-'*12}  {'-'*5}  {'-'*40}  {'-'*40}")
        for e in sorted(task_mapped, key=lambda x: -x['uses']):
            print(f"  0x{e['addr']:08X}  {e['uses']:>5}  {e['name']:<40}  {e['evidence']}")
        print()

    # 4. All entries sorted by uses (full registry)
    print(f"\nFULL ENRICHED REGISTRY (sorted by use count)")
    print(f"=" * 120)
    print(f"  {'Uses':>5}  {'Address':>12}  {'Conf':>6}  {'Suggested Name':<40}  Evidence")
    print(f"  {'-'*5}  {'-'*12}  {'-'*6}  {'-'*40}  {'-'*40}")

    for e in sorted(entries, key=lambda x: -x['uses']):
        conf = e['confidence']
        marker = {'KNOWN': ' ', 'HIGH': '*', 'MEDIUM': '+', 'LOW': '.'}[conf]
        print(f"{marker} {e['uses']:>5}  0x{e['addr']:08X}  {conf:>6}  "
              f"{e['name']:<40}  {e['evidence']}")

    # 5. Export suggested KNOWN_RAM additions
    print(f"\n\n# --- Suggested KNOWN_RAM additions for map_gbr_structures.py ---")
    print(f"# Copy verified entries into KNOWN_RAM dict\n")
    new_names = [e for e in entries
                 if e['confidence'] in ('HIGH', 'MEDIUM')
                 and e['addr'] not in KNOWN_NAMES]
    for e in sorted(new_names, key=lambda x: x['addr']):
        print(f"    0x{e['addr']:08X}: \"{e['name']}\",  # {e['confidence']} - {e['evidence']}")


if __name__ == "__main__":
    main()
