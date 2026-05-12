#!/usr/bin/env python3
"""
ROM binary-diff helper.

Byte-diffs two ROM .bin files and reports which tables changed, how many
cells, and the magnitude range. Designed for the auto-rollup in
log_review_ingest.py so that a "what actually changed in this rev" summary
gets attached to every REVIEW_LOG entry.

The 20.11 "AVCS-only" mis-claim (caught 2026-05-08) is the canonical case:
user said only AVCS moved, but a binary diff showed Base Timing × 4 variants
and MAF Sensor Scaling also got touched. This tool makes that visible
automatically.

Usage:
    python rom_diff.py --before 20.10 --after 20.11
    python rom_diff.py --before-bin rom/foo.bin --after-bin rom/bar.bin

The rev → .bin resolver handles the inconsistent naming in rom/:
  20.8  → "AE5L600L 20g rev 20.8 tiny wrex.bin"
  20.11 → "AE5L600L 20g rev 20.11.bin"          (no "tiny wrex" suffix)
  stock → "ae5l600l.bin"
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ROM_DIR = REPO_ROOT / "rom"

# Known table address regions. Verified addresses live in
# memory/reference_cruise_tuning_tables.md and tune-state.md.
# (addr_start, addr_end_exclusive, name)
KNOWN_TABLES: list[tuple[int, int, str]] = [
    # ---- WGDC / boost (verified single addresses per current_rev_anchor.md
    #      and reference_wgdc_physics_and_philosophy.md, 16 RPM × 18 load,
    #      2 bytes/cell = 0x240 = 576 bytes per table)
    (0xC0F58, 0xC0F58 + 0x1F8, "Max Wastegate Duty"),
    (0xC1150, 0xC1150 + 0x1F8, "Initial Wastegate Duty"),
    (0xC1340, 0xC1340 + 0x240, "Target Boost"),
    # ---- Overrun
    (0xCEED0, 0xCEED0 + 0x40,  "Overrun Fueling RPM Resume Threshold"),
    # ---- Base Timing × 4 variants (Primary / Reference × Cruise / NC)
    (0xD4714, 0xD4714 + 0x200, "Base Timing Primary Cruise"),
    (0xD48D4, 0xD48D4 + 0x200, "Base Timing Primary Non-Cruise"),
    (0xD4A94, 0xD4A94 + 0x200, "Base Timing Reference Cruise"),
    (0xD4C54, 0xD4C54 + 0x200, "Base Timing Reference Non-Cruise"),
    # ---- Knock Correction Adv Max
    (0xD5904, 0xD5904 + 0x200, "Knock Adv Max Cruise"),
    # ---- MAF Sensor Scaling
    (0xD8C9C, 0xD8C9C + 0x100, "MAF Sensor Scaling"),
    # ---- AVCS Intake
    (0xDA96C, 0xDA96C + 0x240, "AVCS Intake Cruise"),
    (0xDAC34, 0xDAC34 + 0x240, "AVCS Intake Non-Cruise"),
    # ---- Pedal maps
    (0xF99E0, 0xF99E0 + 0x140, "Sport Pedal Map"),
    # ---- Firmware checksum region (auto-updates after any change)
    (0xFFB88, 0xFFB88 + 0x20,  "Firmware checksum (auto)"),
]

# rev → filename mapping. Glob-based fallback for filename variation.
def resolve_bin(rev: str) -> Path | None:
    """Find the .bin file for a rom_rev."""
    if rev == "stock":
        p = ROM_DIR / "ae5l600l.bin"
        return p if p.exists() else None
    # 20.X — try both naming styles
    candidates = [
        ROM_DIR / f"AE5L600L 20g rev {rev} tiny wrex.bin",
        ROM_DIR / f"AE5L600L 20g rev {rev}.bin",
    ]
    for c in candidates:
        if c.exists():
            return c
    # last-resort glob
    hits = list(ROM_DIR.glob(f"*{rev}*.bin"))
    return hits[0] if hits else None


def label_addr(addr: int) -> str:
    for start, end, name in KNOWN_TABLES:
        if start <= addr < end:
            return name
    return "(unknown region)"


def diff_bins(before: Path, after: Path) -> dict:
    """Byte-diff two .bin files, group consecutive diff runs, label each."""
    a = before.read_bytes()
    b = after.read_bytes()
    if len(a) != len(b):
        print(f"warn: bin sizes differ: {len(a)} vs {len(b)}", file=sys.stderr)
    n = min(len(a), len(b))
    diffs: list[tuple[int, int, int]] = []  # (addr, prev_byte, new_byte)
    for i in range(n):
        if a[i] != b[i]:
            diffs.append((i, a[i], b[i]))

    # Group consecutive diff addresses into runs
    runs: list[tuple[int, int]] = []  # (start_addr, end_addr_exclusive)
    if diffs:
        run_start = diffs[0][0]
        prev_addr = diffs[0][0]
        for addr, _, _ in diffs[1:]:
            if addr - prev_addr <= 4:  # tolerate small gaps within a run
                prev_addr = addr
            else:
                runs.append((run_start, prev_addr + 1))
                run_start = addr
                prev_addr = addr
        runs.append((run_start, prev_addr + 1))

    # Aggregate runs into table-level summary
    table_summary: dict[str, dict] = {}
    for start, end in runs:
        name = label_addr(start)
        bucket = table_summary.setdefault(
            name, {"n_runs": 0, "n_bytes": 0, "addr_min": start, "addr_max": end}
        )
        bucket["n_runs"] += 1
        bucket["n_bytes"] += (end - start)
        bucket["addr_min"] = min(bucket["addr_min"], start)
        bucket["addr_max"] = max(bucket["addr_max"], end)

    return {
        "before_path": str(before),
        "after_path": str(after),
        "before_size": len(a),
        "after_size": len(b),
        "n_diff_bytes": len(diffs),
        "n_runs": len(runs),
        "runs": runs,
        "tables": table_summary,
    }


def format_report(result: dict) -> str:
    """Human-readable report suitable for REVIEW_LOG.md append."""
    out = []
    out.append(f"## ROM binary-diff: `{Path(result['before_path']).name}` → `{Path(result['after_path']).name}`")
    out.append("")
    out.append(f"- bytes changed: **{result['n_diff_bytes']}** in **{result['n_runs']}** contiguous run(s)")
    if result["before_size"] != result["after_size"]:
        out.append(f"- ⚠ bin sizes differ: {result['before_size']} → {result['after_size']}")
    out.append("")
    out.append("| Table region | runs | bytes | addr range |")
    out.append("|---|---:|---:|---|")
    # Sort: unknown last
    items = sorted(result["tables"].items(),
                   key=lambda kv: (kv[0] == "(unknown region)", -kv[1]["n_bytes"]))
    for name, b in items:
        out.append(f"| {name} | {b['n_runs']} | {b['n_bytes']} | "
                   f"0x{b['addr_min']:X}–0x{b['addr_max']:X} |")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--before", help="prior rom_rev (e.g. 20.10)")
    ap.add_argument("--after", help="this rom_rev (e.g. 20.11)")
    ap.add_argument("--before-bin", help="explicit prior .bin path")
    ap.add_argument("--after-bin", help="explicit this .bin path")
    args = ap.parse_args()

    if args.before_bin and args.after_bin:
        bp = Path(args.before_bin)
        ap_ = Path(args.after_bin)
    elif args.before and args.after:
        bp = resolve_bin(args.before)
        ap_ = resolve_bin(args.after)
        if bp is None:
            sys.exit(f"could not resolve .bin for rev {args.before!r}")
        if ap_ is None:
            sys.exit(f"could not resolve .bin for rev {args.after!r}")
    else:
        ap.error("provide either --before / --after revs OR --before-bin / --after-bin paths")

    result = diff_bins(bp, ap_)

    result = diff_bins(bp, ap_)
    print(format_report(result))


if __name__ == "__main__":
    main()
