#!/usr/bin/env python3
"""
Audit script: extract every human-readable label paired with target RAM addresses
across the entire project and compare against canonical names.

Approach: For each target address, find every line in every file that contains
the address hex string, extract the surrounding context (the label/name), and
flag anything that doesn't match the canonical name.

This is the INVERSE of searching for known-wrong labels — it finds ALL labels
and flags non-canonical ones, catching errors we might not have anticipated.
"""

import os
import re
import sys

# Canonical identities from ram_reference.txt (verified from ROM bytes)
CANONICAL = {
    "FFFF6624": ("rpm_current", {"rpm", "rpm_current", "RPM"}),
    "FFFF6350": ("ect_current", {"ect", "ect_current", "ECT", "ECT_float", "coolant", "coolant_temp", "coolant temperature"}),
    "FFFF65FC": ("engine_load_current", {"engine_load", "engine_load_current", "load", "engine load"}),
    "FFFF63C4": ("ect_compensation", {"ect_compensation", "ect_comp"}),
    "FFFF63F8": ("iat_current", {"iat", "iat_current", "IAT", "intake air temp", "intake_air_temp"}),
    "FFFF6364": ("ect_startup", {"ect_startup", "ect_start", "ECT at engine start", "ECT at start"}),
}

# Known wrong labels (the ones we were fixing)
KNOWN_WRONG = {
    "FFFF6624": {"MAF", "maf", "mass airflow", "engine_load", "engine load", "engine_load_float",
                 "curr_throttle", "curr_throttle_pos", "throttle", "MAF alt", "MAF alternate"},
    "FFFF6350": {"RPM", "rpm", "Engine RPM", "rpm_current", "Vehicle speed", "vehicle_speed"},
    "FFFF65FC": {"BPW", "bpw", "base pulse width", "base_pulse_width", "APP", "app",
                 "accelerator pedal", "manifold_pressure", "manifold pressure"},
    "FFFF63C4": {"engine load", "engine_load", "processed_sensor", "processed_sensor_A"},
    "FFFF63F8": {"RPM_float", "rpm_float", "MAP", "map", "RPM alt", "RPM_alt",
                 "Boost", "boost", "manifold pressure"},
    "FFFF6364": {"RPM", "rpm", "RPM_float_B", "rpm_float_b", "IAT_float", "iat_float",
                 "Throttle", "throttle", "rpm_period", "atm_pressure", "atmospheric"},
}

# Directories to scan
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCAN_DIRS = [
    os.path.join(PROJECT_ROOT, "disassembly"),
    os.path.join(PROJECT_ROOT, "scripts"),
    os.path.join(PROJECT_ROOT, "definitions"),
]

# Skip patterns
SKIP_DIRS = {"__pycache__", ".git", "merp mod", "patches"}
SKIP_EXTENSIONS = {".bin", ".pyc", ".bytes"}

# Lines that are correction notices (document old wrong names intentionally)
CORRECTION_PATTERNS = [
    r"\bWAS\b", r"\bWRONG\b", r"\bCORRECTION\b", r"\bcorrected\b",
    r"\bmislabeled\b", r"\bSWAPPED\b", r"\bsupersedes\b", r"previously",
    r"old.*wrong", r"should not be used",
]
correction_re = re.compile("|".join(CORRECTION_PATTERNS), re.IGNORECASE)


def is_correction_line(line):
    """Check if a line is documenting a correction (not an active wrong label)."""
    return bool(correction_re.search(line))


def extract_label_context(line, addr_hex):
    """Extract the label/name near an address reference in a line."""
    labels = []

    # Pattern 1: Python dict — 0xFFFF6624: "label"
    m = re.search(r'0x' + addr_hex + r'[L]?\s*[:,]\s*["\']([^"\']+)["\']', line, re.IGNORECASE)
    if m:
        labels.append(("py_dict", m.group(1)))

    # Pattern 2: Disasm comment — [label] or (label)
    m = re.search(addr_hex + r'[^]]*\[([^\]]+)\]', line, re.IGNORECASE)
    if m:
        labels.append(("disasm_bracket", m.group(1)))

    # Pattern 3: address followed by label text — FFFF6624 = label or FFFF6624: label
    m = re.search(addr_hex + r'\s*[=:]\s*(\w[\w\s/]*?)(?:\s{2,}|\s*[(\[,;|]|$)', line, re.IGNORECASE)
    if m:
        label = m.group(1).strip()
        if len(label) > 2 and not label.startswith("0x"):
            labels.append(("equals", label))

    # Pattern 4: address in parens with label — (FFFF6624, label) or FFFF6624 (label)
    m = re.search(addr_hex + r'\s*\(([^)]+)\)', line, re.IGNORECASE)
    if m:
        labels.append(("parens", m.group(1).strip()))

    # Pattern 5: "label (FFFFxxxx)" or "label from FFFF6624"
    m = re.search(r'(\w[\w_]*)\s*(?:\(|from\s+)(?:0x|RAM\[?)?' + addr_hex, line, re.IGNORECASE)
    if m:
        label = m.group(1).strip()
        if len(label) > 2 and label.lower() not in ("at", "to", "of", "in", "if", "is", "or", "and",
                                                       "mov", "fmov", "from", "ram", "float", "byte",
                                                       "word", "the", "ref", "address", "hex"):
            labels.append(("prefix", label))

    # Pattern 6: table row — | FFFF6624 | type | refs | description |
    m = re.search(addr_hex + r'\s*│[^│]*│[^│]*│\s*([^│]+)', line, re.IGNORECASE)
    if m:
        labels.append(("table", m.group(1).strip()))

    return labels


def check_label(addr_hex, label_type, label_text):
    """Check if a label matches canonical or is known-wrong."""
    canonical_name, acceptable = CANONICAL[addr_hex]
    wrong_set = KNOWN_WRONG[addr_hex]

    label_lower = label_text.lower().strip()
    label_clean = label_lower.replace("_", " ").replace("-", " ")

    # Check if it matches any acceptable form
    for acc in acceptable:
        if acc.lower() in label_lower or label_lower in acc.lower():
            return "OK", canonical_name

    # Check if it's a known wrong label
    for wrong in wrong_set:
        if wrong.lower() in label_lower or label_lower in wrong.lower():
            return "WRONG", f"'{label_text}' should be '{canonical_name}'"

    # Unknown — might be a new wrong label we haven't seen
    return "UNKNOWN", f"'{label_text}' (canonical: '{canonical_name}')"


def scan_file(filepath):
    """Scan a file for all target address references and their labels."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return findings

    for line_num, line in enumerate(lines, 1):
        for addr_hex in CANONICAL:
            if addr_hex.lower() in line.lower() or addr_hex.upper() in line:
                # Skip lines that are just hex addresses without labels
                if is_correction_line(line):
                    continue

                labels = extract_label_context(line, addr_hex)
                for label_type, label_text in labels:
                    status, detail = check_label(addr_hex, label_type, label_text)
                    if status != "OK":
                        findings.append({
                            "file": filepath,
                            "line": line_num,
                            "addr": addr_hex,
                            "status": status,
                            "detail": detail,
                            "context": line.rstrip()[:120],
                        })
    return findings


def main():
    all_findings = []

    for scan_dir in SCAN_DIRS:
        if not os.path.isdir(scan_dir):
            continue
        for root, dirs, files in os.walk(scan_dir):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            rel_root = os.path.relpath(root, PROJECT_ROOT)
            if any(skip in rel_root for skip in SKIP_DIRS):
                continue

            for fname in sorted(files):
                ext = os.path.splitext(fname)[1].lower()
                if ext in SKIP_EXTENSIONS:
                    continue
                filepath = os.path.join(root, fname)
                findings = scan_file(filepath)
                all_findings.extend(findings)

    # Report
    wrong = [f for f in all_findings if f["status"] == "WRONG"]
    unknown = [f for f in all_findings if f["status"] == "UNKNOWN"]

    print("=" * 80)
    print("RAM ADDRESS LABEL AUDIT REPORT")
    print("=" * 80)
    print(f"\nScanned directories: {', '.join(os.path.basename(d) for d in SCAN_DIRS)}")
    print(f"Target addresses: {len(CANONICAL)}")
    print(f"\nResults: {len(wrong)} WRONG, {len(unknown)} UNKNOWN\n")

    if wrong:
        print("-" * 80)
        print("WRONG LABELS (known-bad patterns still present)")
        print("-" * 80)
        for f in wrong:
            relpath = os.path.relpath(f["file"], PROJECT_ROOT)
            print(f"  {relpath}:{f['line']}  [{f['addr']}] {f['detail']}")
        print()

    if unknown:
        print("-" * 80)
        print("UNKNOWN LABELS (not canonical, not known-wrong — review manually)")
        print("-" * 80)
        for f in unknown:
            relpath = os.path.relpath(f["file"], PROJECT_ROOT)
            print(f"  {relpath}:{f['line']}  [{f['addr']}] {f['detail']}")
        print()

    if not wrong and not unknown:
        print("ALL CLEAR — no wrong or unknown labels found.\n")

    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(main())
