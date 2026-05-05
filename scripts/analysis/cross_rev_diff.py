"""
Cross-rev table diff with behavioral overlay.

Given two ROM revs (with logs mapped via logs/rom_rev_map.csv), this tool:
  1. Reads the AVCS Cruise table from each ROM
  2. Identifies cells that changed
  3. For each changed cell with sufficient residency on each side, pulls
     matched-condition log samples and computes the actual behavioral delta
     (MAF g/s, throttle, MRP, IAT) — the "did the edit do what we think" check
  4. Outputs a per-cell ledger: table-Δ + measured behavioral-Δ

Two matching strategies, both reported:
  A. Match on (RPM bin, load bin)  — same operating fill, see how throttle/MRP shifted
  B. Match on (RPM bin, throttle bin, IAT bin) — same pedal, see how MAF g/s shifted

Usage:
  python scripts/analysis/cross_rev_diff.py --before 20.9 --after 20.10
  python scripts/analysis/cross_rev_diff.py --before stock --after 20.8 \
      --table-addr 0xda96c
"""
from __future__ import annotations

import argparse
import csv
import glob
import math
import os
import statistics
import struct
import sys
from collections import defaultdict
from pathlib import Path

# bin layout
LOAD_ADDR = 0xDA8E4
RPM_ADDR  = 0xDA92C
DEFAULT_TABLE_ADDR = 0xDA96C  # AVCS Cruise
N_LOAD = 18
N_RPM  = 16
SCALE  = 0.0054931640625

REPO_ROOT = Path(__file__).resolve().parents[2]
LOGS_DIR  = REPO_ROOT / "logs"
ROM_DIR   = REPO_ROOT / "rom"
TRENDS_DIR = REPO_ROOT / "scripts" / "analysis" / "trends"

# ROM filename → label mapping. Project XML/scripts use these labels for the
# loaded variant; rom_rev_map.csv references logs by these same labels.
ROM_FILES = {
    "stock": "ae5l600l.bin",
    "20.8":  "AE5L600L 20g rev 20.8 tiny wrex.bin",
    "20.9":  "AE5L600L 20g rev 20.9 tiny wrex.bin",
    "20.10": "AE5L600L 20g rev 20.10 tiny wrex.bin",
    "20.11": "AE5L600L 20g rev 20.11.bin",
}

DEFAULT_MIN_SAMPLES = 30  # per cell per side to qualify for behavioral diff

# Matching tolerances for strategy B
THROTTLE_BIN = 1.0   # %
IAT_BIN      = 5.0   # °C
RPM_BIN      = 100   # ±100 RPM around cell center


def read_table(path: str, table_addr: int):
    with open(path, "rb") as f:
        buf = f.read()
    load = list(struct.unpack(">" + "f" * N_LOAD, buf[LOAD_ADDR:LOAD_ADDR + 4 * N_LOAD]))
    rpm  = list(struct.unpack(">" + "f" * N_RPM,  buf[RPM_ADDR:RPM_ADDR + 4 * N_RPM]))
    raw  = struct.unpack(">" + "H" * (N_LOAD * N_RPM),
                         buf[table_addr:table_addr + 2 * N_LOAD * N_RPM])
    tab  = [[raw[y * N_LOAD + x] * SCALE for x in range(N_LOAD)] for y in range(N_RPM)]
    return load, rpm, tab


def load_rev_map() -> dict[str, list[str]]:
    """Return {rev_label: [log_path, ...]} from logs/rom_rev_map.csv."""
    p = LOGS_DIR / "rom_rev_map.csv"
    out: dict[str, list[str]] = defaultdict(list)
    with open(p, newline="") as f:
        for row in csv.DictReader(f):
            rev = row["rom_rev"].strip()
            log_rel = row["log_path"].strip()
            full = LOGS_DIR / log_rel
            if full.exists():
                out[rev].append(str(full))
    return dict(out)


def find_col(header, *candidates):
    low = [h.strip().lower() for h in header]
    for c in candidates:
        cl = c.lower()
        if cl in low:
            return low.index(cl)
    return None


def load_log_rows(log_path: str, want: list[str]) -> list[dict]:
    """Load only the columns we need from a log; cheap and tolerant of schema drift."""
    with open(log_path, newline="") as f:
        r = csv.reader(f)
        h = next(r, None)
        if not h:
            return []
        col_map = {}
        for k in want:
            i = find_col(h, k, k.upper(), k.lower())
            if i is not None:
                col_map[k] = i
        rows = []
        for row in r:
            try:
                d = {}
                for k, i in col_map.items():
                    s = row[i].strip() if i < len(row) else ""
                    d[k] = float(s) if s not in ("", "-") else float("nan")
                rows.append(d)
            except (ValueError, IndexError):
                continue
    return rows


def collect_samples(log_paths: list[str]) -> list[dict]:
    want = ["RPM", "load", "MAF", "Throttle", "CL/OL", "IAT", "ATM(psi)", "mrp", "avcs"]
    out = []
    for p in log_paths:
        try:
            rows = load_log_rows(p, want)
            out.extend(rows)
        except (OSError, UnicodeDecodeError) as e:
            print(f"  skip {p}: {e}", file=sys.stderr)
    return out


def in_cell(d: dict, rpm_lo: float, rpm_hi: float, load_lo: float, load_hi: float, cl_only: bool = True) -> bool:
    try:
        if math.isnan(d.get("RPM", float("nan"))) or math.isnan(d.get("load", float("nan"))):
            return False
        if not (rpm_lo <= d["RPM"] < rpm_hi and load_lo <= d["load"] < load_hi):
            return False
        if cl_only and d.get("CL/OL", -1) != 8:
            return False
    except KeyError:
        return False
    return True


def cell_bounds(rpm_axis, load_axis, yi: int, xi: int):
    rpm_lo = rpm_axis[yi]
    rpm_hi = rpm_axis[yi + 1] if yi + 1 < len(rpm_axis) else rpm_axis[yi] + 500
    load_lo = load_axis[xi]
    load_hi = load_axis[xi + 1] if xi + 1 < len(load_axis) else load_axis[xi] + 0.1
    return rpm_lo, rpm_hi, load_lo, load_hi


def stat(vals):
    """Return (n, mean, sd) tolerant of NaN and short series."""
    clean = [v for v in vals if not (v is None or math.isnan(v))]
    if not clean:
        return 0, float("nan"), float("nan")
    if len(clean) == 1:
        return 1, clean[0], 0.0
    return len(clean), statistics.mean(clean), statistics.stdev(clean)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--before", required=True, help="rev label, e.g. 20.9 or stock")
    ap.add_argument("--after",  required=True, help="rev label, e.g. 20.10")
    ap.add_argument("--table-addr", default=hex(DEFAULT_TABLE_ADDR),
                    help=f"table address (default {hex(DEFAULT_TABLE_ADDR)} = AVCS Cruise)")
    ap.add_argument("--min-samples", type=int, default=DEFAULT_MIN_SAMPLES)
    ap.add_argument("--out", default=None,
                    help="output report path (default trends/cross_rev_<before>_<after>.txt)")
    args = ap.parse_args()

    table_addr = int(args.table_addr, 0)

    if args.before not in ROM_FILES or args.after not in ROM_FILES:
        print(f"Unknown rev label. Known: {list(ROM_FILES)}", file=sys.stderr)
        sys.exit(2)
    rom_a = ROM_DIR / ROM_FILES[args.before]
    rom_b = ROM_DIR / ROM_FILES[args.after]
    if not rom_a.exists() or not rom_b.exists():
        print(f"Missing ROM: {rom_a if not rom_a.exists() else rom_b}", file=sys.stderr)
        sys.exit(2)

    load_a, rpm_a, tab_a = read_table(str(rom_a), table_addr)
    load_b, rpm_b, tab_b = read_table(str(rom_b), table_addr)

    sections = [f"Cross-rev diff: {args.before} -> {args.after}",
                f"  before rom: {rom_a}",
                f"  after rom:  {rom_b}",
                f"  table addr: {hex(table_addr)}",
                ""]

    # Axis check
    same_axis = (load_a == load_b) and (rpm_a == rpm_b)
    if not same_axis:
        sections.append(f"⚠ axes differ — cell-by-cell diff not directly comparable")
        sections.append(f"  before load: {[f'{v:.2f}' for v in load_a]}")
        sections.append(f"  after  load: {[f'{v:.2f}' for v in load_b]}")
        sections.append(f"  before rpm:  {[f'{v:.0f}' for v in rpm_a]}")
        sections.append(f"  after  rpm:  {[f'{v:.0f}' for v in rpm_b]}")
        sections.append("")
        # Don't proceed with cell-by-cell behavioral diff in this case;
        # would need bilinear remapping. Future work.
        out_path = Path(args.out) if args.out else TRENDS_DIR / f"cross_rev_{args.before}_{args.after}.txt"
        out_path.write_text("\n".join(sections))
        print("\n".join(sections))
        print(f"\n[written] {out_path}", file=sys.stderr)
        return

    # Same axis: find changed cells
    changed = []
    for y in range(N_RPM):
        for x in range(N_LOAD):
            d = tab_b[y][x] - tab_a[y][x]
            if abs(d) > 0.01:
                changed.append((y, x, tab_a[y][x], tab_b[y][x], d))
    sections.append(f"=== {len(changed)} cells changed ===")
    if not changed:
        sections.append("  (no cells changed)")
        out_path = Path(args.out) if args.out else TRENDS_DIR / f"cross_rev_{args.before}_{args.after}.txt"
        out_path.write_text("\n".join(sections))
        print("\n".join(sections))
        print(f"\n[written] {out_path}", file=sys.stderr)
        return
    sections.append("")

    # Load logs
    rev_map = load_rev_map()
    logs_a = rev_map.get(args.before, [])
    logs_b = rev_map.get(args.after, [])
    sections.append(f"Logs mapped to {args.before}: {len(logs_a)}")
    for p in logs_a:
        sections.append(f"  {os.path.relpath(p, REPO_ROOT)}")
    sections.append(f"Logs mapped to {args.after}: {len(logs_b)}")
    for p in logs_b:
        sections.append(f"  {os.path.relpath(p, REPO_ROOT)}")
    sections.append("")

    samples_a = collect_samples(logs_a)
    samples_b = collect_samples(logs_b)
    sections.append(f"Samples loaded: before={len(samples_a)}, after={len(samples_b)}")
    sections.append("")

    # Strategy A: match by (RPM bin, load bin) — same operating fill
    sections.append(f"=== Strategy A: match on (RPM, load) cell ===")
    sections.append(f"  Same fill — see how throttle / MAF / MRP shifted")
    sections.append(f"  {'RPM':>5} {'Load':>5}  "
                    f"{'AVCS Δ':>8}  "
                    f"{'n_a':>5} {'n_b':>5}  "
                    f"{'AVCS_a':>7} {'AVCS_b':>7} {'AVCSact Δ':>9}  "
                    f"{'MAF_a':>6} {'MAF_b':>6} {'ΔMAF':>6}  "
                    f"{'Thr_a':>6} {'Thr_b':>6} {'ΔThr':>6}  "
                    f"{'MRP_a':>6} {'MRP_b':>6} {'ΔMRP':>6}")
    for y, x, va, vb, d in changed:
        rl, rh, ll, lh = cell_bounds(rpm_a, load_a, y, x)
        a_in = [s for s in samples_a if in_cell(s, rl, rh, ll, lh)]
        b_in = [s for s in samples_b if in_cell(s, rl, rh, ll, lh)]
        if len(a_in) < args.min_samples or len(b_in) < args.min_samples:
            continue
        n_a = len(a_in); n_b = len(b_in)
        avcs_a = stat([s["avcs"] for s in a_in])[1]
        avcs_b = stat([s["avcs"] for s in b_in])[1]
        maf_a = stat([s["MAF"] for s in a_in])[1]
        maf_b = stat([s["MAF"] for s in b_in])[1]
        thr_a = stat([s["Throttle"] for s in a_in])[1]
        thr_b = stat([s["Throttle"] for s in b_in])[1]
        mrp_a = stat([s["mrp"] for s in a_in])[1]
        mrp_b = stat([s["mrp"] for s in b_in])[1]
        sections.append(f"  {rpm_a[y]:>5.0f} {load_a[x]:>5.2f}  "
                        f"{d:>+8.2f}  "
                        f"{n_a:>5d} {n_b:>5d}  "
                        f"{avcs_a:>7.2f} {avcs_b:>7.2f} {avcs_b - avcs_a:>+9.2f}  "
                        f"{maf_a:>6.2f} {maf_b:>6.2f} {maf_b - maf_a:>+6.2f}  "
                        f"{thr_a:>6.2f} {thr_b:>6.2f} {thr_b - thr_a:>+6.2f}  "
                        f"{mrp_a:>+6.2f} {mrp_b:>+6.2f} {mrp_b - mrp_a:>+6.2f}")
    sections.append("")

    # Strategy B: match by (RPM bin, throttle bin, IAT bin)
    # — same pedal, see how MAF g/s and load shifted
    sections.append(f"=== Strategy B: match on (RPM±{RPM_BIN}, Throttle±{THROTTLE_BIN}%, IAT±{IAT_BIN}°C) ===")
    sections.append(f"  Same pedal — see how MAF g/s and load actually moved")
    sections.append(f"  {'RPM':>5} {'Load':>5}  "
                    f"{'AVCS Δ':>8}  "
                    f"{'n_a':>5} {'n_b':>5}  "
                    f"{'MAF_a':>6} {'MAF_b':>6} {'ΔMAF':>6} ({'%':>4})  "
                    f"{'Load_a':>6} {'Load_b':>6} {'ΔLoad':>6}")

    def thr_bucket(t):
        return None if math.isnan(t) else round(t / THROTTLE_BIN) * THROTTLE_BIN
    def iat_bucket(t):
        return None if math.isnan(t) else round(t / IAT_BIN) * IAT_BIN
    def rpm_bucket(r, center):
        return None if math.isnan(r) or abs(r - center) > RPM_BIN else round(r / RPM_BIN) * RPM_BIN

    for y, x, va, vb, d in changed:
        rl, rh, ll, lh = cell_bounds(rpm_a, load_a, y, x)
        rpm_center = (rl + rh) / 2
        # samples near cell RPM, regardless of load — what we want is "same pedal
        # and ambient, look at airflow output."
        def filter_near(samples):
            return [s for s in samples
                    if not math.isnan(s.get("RPM", float("nan")))
                    and abs(s["RPM"] - rpm_center) <= RPM_BIN
                    and ll <= s.get("load", -1) < lh
                    and s.get("CL/OL", -1) == 8]
        a_near = filter_near(samples_a)
        b_near = filter_near(samples_b)
        if len(a_near) < args.min_samples or len(b_near) < args.min_samples:
            continue
        # bucket by (thr, iat)
        a_by = defaultdict(list)
        b_by = defaultdict(list)
        for s in a_near:
            t = thr_bucket(s.get("Throttle", float("nan")))
            i = iat_bucket(s.get("IAT", float("nan")))
            if t is None or i is None: continue
            a_by[(t, i)].append(s)
        for s in b_near:
            t = thr_bucket(s.get("Throttle", float("nan")))
            i = iat_bucket(s.get("IAT", float("nan")))
            if t is None or i is None: continue
            b_by[(t, i)].append(s)
        # weighted average over matching buckets
        common = set(a_by) & set(b_by)
        common = [k for k in common if len(a_by[k]) >= 5 and len(b_by[k]) >= 5]
        if not common:
            continue
        # weight by min(n_a, n_b) per bucket
        w = []
        maf_a_w = maf_b_w = 0.0
        load_a_w = load_b_w = 0.0
        n_a_tot = n_b_tot = 0
        for k in common:
            wt = min(len(a_by[k]), len(b_by[k]))
            ma = statistics.mean(s["MAF"] for s in a_by[k] if not math.isnan(s["MAF"]))
            mb = statistics.mean(s["MAF"] for s in b_by[k] if not math.isnan(s["MAF"]))
            la = statistics.mean(s["load"] for s in a_by[k] if not math.isnan(s["load"]))
            lb = statistics.mean(s["load"] for s in b_by[k] if not math.isnan(s["load"]))
            maf_a_w += ma * wt; maf_b_w += mb * wt
            load_a_w += la * wt; load_b_w += lb * wt
            w.append(wt)
            n_a_tot += len(a_by[k]); n_b_tot += len(b_by[k])
        if not w:
            continue
        ws = sum(w)
        maf_a_avg = maf_a_w / ws; maf_b_avg = maf_b_w / ws
        load_a_avg = load_a_w / ws; load_b_avg = load_b_w / ws
        delta_maf = maf_b_avg - maf_a_avg
        pct = 100 * delta_maf / maf_a_avg if maf_a_avg else float("nan")
        sections.append(f"  {rpm_a[y]:>5.0f} {load_a[x]:>5.2f}  "
                        f"{d:>+8.2f}  "
                        f"{n_a_tot:>5d} {n_b_tot:>5d}  "
                        f"{maf_a_avg:>6.2f} {maf_b_avg:>6.2f} {delta_maf:>+6.2f} ({pct:>+4.1f})  "
                        f"{load_a_avg:>6.2f} {load_b_avg:>6.2f} {load_b_avg - load_a_avg:>+6.2f}")
    sections.append("")

    text = "\n".join(sections)
    out_path = Path(args.out) if args.out else TRENDS_DIR / f"cross_rev_{args.before}_{args.after}.txt"
    out_path.write_text(text)
    print(text)
    print(f"\n[written] {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
