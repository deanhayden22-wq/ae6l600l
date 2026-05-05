"""
AVCS Cruise table review tool.

Inputs: a ROM rev (path to .bin), optional prior ROM (for diff), log glob.
Outputs (printed and written to scripts/analysis/trends/avcs_review_<rom>.txt):
  - Current AVCS Cruise table (deg) and Non-Cruise table; flags whether they're identical
  - Diff vs prior ROM (if --prior given)
  - Diff vs stock cruise + stock non-cruise (both, side by side at common cells)
  - Cruise-state residency heatmap (CL=8, MPH>20 if available, RPM 1500-5500 × load 0.2-1.5)
  - All-state residency heatmap
  - Cliff detection: per-row and per-col absolute deltas; flagged where > threshold
  - Candidate-edit list: cells where (residency >= MIN_SEC) AND (max-neighbor-cliff >= MIN_CLIFF)
  - Optional join with trends/knock_by_cell.csv for the same ROM rev

Design choices:
  - Read tables raw from the bin to avoid trusting any def XML edit history.
  - Use 25 Hz sample assumption (verified in reference_logs.md); make overridable.
  - Cruise filter follows feedback_cruise_residency_method.md: CL=8, MPH>20 if
    column present, with the 1s std-on-(RPM,accel,throttle) gate optional via flag.
  - Output in plain text + a CSV companion so it can feed downstream views.

Usage:
  python scripts/analysis/avcs_cruise_review.py \
      --rom "rom/AE5L600L 20g rev 20.11.bin" \
      --prior "rom/AE5L600L 20g rev 20.10 tiny wrex.bin" \
      --logs "logs/**/*.csv" \
      --label 20.11

  python scripts/analysis/avcs_cruise_review.py --rom rom/ae5l600l.bin --label stock
"""
from __future__ import annotations

import argparse
import csv
import glob
import math
import os
import struct
import sys
from pathlib import Path

# ---------- Bin layout (per reference_cruise_tuning_tables.md) ----------
# verified by raw byte read of 20.9 and 20.10 in earlier sessions
LOAD_ADDR = 0xDA8E4   # 18 floats, g/rev
RPM_ADDR  = 0xDA92C   # 16 floats, RPM
CRUISE_ADDR    = 0xDA96C  # 18x16 uint16 BE
NONCRUISE_ADDR = 0xDAC34  # 18x16 uint16 BE  (per project XML line 691)
N_LOAD = 18
N_RPM  = 16
SCALE  = 0.0054931640625  # deg per LSB

# Stock bin uses identical addresses but different axis values.
DEFAULT_STOCK_ROM = "rom/ae5l600l.bin"

# Cliff thresholds (degrees) — start permissive, the user can tighten via flag
DEFAULT_RPM_CLIFF_DEG  = 3.0   # row-to-row delta at fixed load
DEFAULT_LOAD_CLIFF_DEG = 3.0   # col-to-col delta at fixed RPM
DEFAULT_MIN_RESIDENCY_S = 30   # seconds in cruise state for "candidate cell"

REPO_ROOT = Path(__file__).resolve().parents[2]
TRENDS_DIR = REPO_ROOT / "scripts" / "analysis" / "trends"


# ---------- Bin reading ----------
def read_table(path: str, table_addr: int) -> tuple[list[float], list[float], list[list[float]]]:
    """Return (load_axis, rpm_axis, table[rpm_idx][load_idx])."""
    with open(path, "rb") as f:
        buf = f.read()
    load = list(struct.unpack(">" + "f" * N_LOAD, buf[LOAD_ADDR:LOAD_ADDR + 4 * N_LOAD]))
    rpm  = list(struct.unpack(">" + "f" * N_RPM,  buf[RPM_ADDR:RPM_ADDR + 4 * N_RPM]))
    raw  = struct.unpack(">" + "H" * (N_LOAD * N_RPM), buf[table_addr:table_addr + 2 * N_LOAD * N_RPM])
    tab  = [[raw[y * N_LOAD + x] * SCALE for x in range(N_LOAD)] for y in range(N_RPM)]
    return load, rpm, tab


def fmt_table(load: list[float], rpm: list[float], tab: list[list[float]],
              title: str, mark: callable | None = None) -> str:
    out = [f"=== {title} ==="]
    out.append("RPM\\Load  " + "  ".join(f"{l:5.2f}" for l in load))
    for yi, r in enumerate(rpm):
        cells = []
        for xi, _ in enumerate(load):
            v = tab[yi][xi]
            if mark and mark(yi, xi):
                cells.append(f"{v:5.2f}*")
            else:
                cells.append(f"{v:5.2f} ")
        out.append(f"{r:5.0f}    " + " ".join(cells))
    return "\n".join(out)


def diff_tables(a: list[list[float]], b: list[list[float]],
                load: list[float], rpm: list[float], tol: float = 0.01) -> list[tuple]:
    """Return list of (rpm, load, a_val, b_val, delta) where |delta| > tol."""
    out = []
    for y in range(N_RPM):
        for x in range(N_LOAD):
            d = b[y][x] - a[y][x]
            if abs(d) > tol:
                out.append((rpm[y], load[x], a[y][x], b[y][x], d))
    return out


# ---------- Stock comparison (axes differ → bilinear) ----------
def bilinear(rpm_q: float, load_q: float,
             rpm_axis: list[float], load_axis: list[float],
             tab: list[list[float]]) -> float:
    def find(arr: list[float], v: float):
        if v <= arr[0]:  return 0, 0, 0.0
        if v >= arr[-1]: return len(arr) - 1, len(arr) - 1, 1.0
        for i in range(len(arr) - 1):
            if arr[i] <= v <= arr[i + 1]:
                t = (v - arr[i]) / (arr[i + 1] - arr[i])
                return i, i + 1, t
        return len(arr) - 1, len(arr) - 1, 1.0
    yi, yj, ty = find(rpm_axis, rpm_q)
    xi, xj, tx = find(load_axis, load_q)
    a = tab[yi][xi] * (1 - tx) + tab[yi][xj] * tx
    b = tab[yj][xi] * (1 - tx) + tab[yj][xj] * tx
    return a * (1 - ty) + b * ty


# ---------- Log residency ----------
def find_col(header: list[str], *candidates: str) -> int | None:
    """Case-insensitive column lookup; returns first match or None."""
    low = [h.strip().lower() for h in header]
    for c in candidates:
        cl = c.lower()
        if cl in low:
            return low.index(cl)
    return None


def build_residency(log_paths: list[str], rpm_axis: list[float], load_axis: list[float],
                    samples_per_sec: float = 25.0, mph_min: float = 20.0,
                    require_steady: bool = False
                    ) -> tuple[list[list[int]], list[list[int]], int]:
    """Return (cruise_count, all_count, total_samples_seen).

    Cruise filter: CL/OL == 8 (closed loop). MPH>20 if column present.
    """
    cruise = [[0] * N_LOAD for _ in range(N_RPM)]
    allst  = [[0] * N_LOAD for _ in range(N_RPM)]
    total = 0

    def bin_idx(arr, v):
        if v < arr[0] or v > arr[-1]:
            return None
        for i in range(len(arr) - 1):
            if arr[i] <= v < arr[i + 1]:
                return i
        return len(arr) - 1

    for fp in log_paths:
        try:
            with open(fp, newline="") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                if not header:
                    continue
                rpm_col   = find_col(header, "RPM", "Engine Speed (rpm)")
                load_col  = find_col(header, "load", "Engine Load (Calculated) (g/rev)")
                cl_col    = find_col(header, "CL/OL", "CL/OL Fueling* (status)")
                mph_col   = find_col(header, "MPH", "Vehicle Speed (mph)")
                if rpm_col is None or load_col is None:
                    continue
                for row in reader:
                    total += 1
                    try:
                        rpm = float(row[rpm_col])
                        ld  = float(row[load_col])
                    except (ValueError, IndexError):
                        continue
                    if math.isnan(rpm) or math.isnan(ld):
                        continue
                    yi = bin_idx(rpm_axis, rpm)
                    xi = bin_idx(load_axis, ld)
                    if yi is None or xi is None:
                        continue
                    allst[yi][xi] += 1
                    cl_n = -1
                    if cl_col is not None and cl_col < len(row):
                        try: cl_n = int(float(row[cl_col]))
                        except (ValueError, IndexError): pass
                    in_cruise = cl_n == 8
                    if in_cruise and mph_col is not None and mph_col < len(row):
                        try:
                            if float(row[mph_col]) < mph_min:
                                in_cruise = False
                        except ValueError:
                            pass
                    if in_cruise:
                        cruise[yi][xi] += 1
        except (OSError, UnicodeDecodeError) as e:
            print(f"  skip {fp}: {e}", file=sys.stderr)
    return cruise, allst, total


def fmt_residency(cruise: list[list[int]], rpm: list[float], load: list[float],
                  samples_per_sec: float, title: str,
                  rpm_lo: float = 1500, rpm_hi: float = 5000,
                  load_lo: float = 0.20, load_hi: float = 1.50) -> str:
    out = [f"=== {title} ==="]
    cols = [(xi, l) for xi, l in enumerate(load) if load_lo <= l <= load_hi]
    rows = [(yi, r) for yi, r in enumerate(rpm) if rpm_lo <= r <= rpm_hi]
    out.append("RPM\\Load  " + "  ".join(f"{l:5.2f}" for _, l in cols))
    for yi, r in rows:
        line = []
        for xi, _ in cols:
            sec = cruise[yi][xi] / samples_per_sec
            line.append(f"{sec:5.0f}s")
        out.append(f"{r:5.0f}    " + " ".join(line))
    return "\n".join(out)


# ---------- Cliff detection ----------
def detect_cliffs(tab: list[list[float]],
                  rpm: list[float], load: list[float],
                  rpm_thresh: float, load_thresh: float
                  ) -> tuple[list[tuple], list[tuple]]:
    """Return (rpm_cliffs, load_cliffs).

    rpm_cliffs: (rpm_lo, rpm_hi, load, val_lo, val_hi, delta) where adjacent rows
    differ by > rpm_thresh at fixed load.
    """
    rpm_cliffs = []
    for x in range(N_LOAD):
        for y in range(N_RPM - 1):
            d = tab[y + 1][x] - tab[y][x]
            if abs(d) > rpm_thresh:
                rpm_cliffs.append((rpm[y], rpm[y + 1], load[x], tab[y][x], tab[y + 1][x], d))
    load_cliffs = []
    for y in range(N_RPM):
        for x in range(N_LOAD - 1):
            d = tab[y][x + 1] - tab[y][x]
            if abs(d) > load_thresh:
                load_cliffs.append((rpm[y], load[x], load[x + 1], tab[y][x], tab[y][x + 1], d))
    return rpm_cliffs, load_cliffs


# ---------- Candidate cells (residency × cliff) ----------
def candidate_cells(tab: list[list[float]], cruise: list[list[int]],
                    rpm: list[float], load: list[float],
                    samples_per_sec: float,
                    min_residency_s: float, min_neighbor_cliff_deg: float
                    ) -> list[tuple]:
    """Cells with cruise dwell >= min and any RPM-neighbor delta >= cliff threshold."""
    out = []
    for y in range(N_RPM):
        for x in range(N_LOAD):
            sec = cruise[y][x] / samples_per_sec
            if sec < min_residency_s:
                continue
            neighbors = []
            if y > 0:           neighbors.append(("dn", tab[y - 1][x] - tab[y][x]))
            if y < N_RPM - 1:   neighbors.append(("up", tab[y + 1][x] - tab[y][x]))
            if x > 0:           neighbors.append(("L-", tab[y][x - 1] - tab[y][x]))
            if x < N_LOAD - 1:  neighbors.append(("L+", tab[y][x + 1] - tab[y][x]))
            worst = max(neighbors, key=lambda kv: abs(kv[1])) if neighbors else (None, 0.0)
            if abs(worst[1]) >= min_neighbor_cliff_deg:
                out.append((rpm[y], load[x], tab[y][x], sec, worst[0], worst[1]))
    out.sort(key=lambda t: (-t[3], -abs(t[5])))  # most-resident first, then biggest cliff
    return out


# ---------- Knock cell join ----------
def load_knock_by_cell(rom_rev_label: str | None) -> list[dict]:
    p = TRENDS_DIR / "knock_by_cell.csv"
    if not p.exists():
        return []
    out = []
    with open(p, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if rom_rev_label and row.get("rom_rev", "").strip() != rom_rev_label:
                continue
            try:
                row["rpm_bin"] = float(row["rpm_bin"])
                row["load_bin"] = float(row["load_bin"])
                row["event_count_fbkc"] = int(row.get("event_count_fbkc") or 0)
            except (ValueError, KeyError):
                continue
            out.append(row)
    return out


# ---------- Main ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rom", required=True, help="path to ROM .bin to review")
    ap.add_argument("--prior", default=None, help="optional prior ROM .bin for diff")
    ap.add_argument("--stock", default=str(REPO_ROOT / DEFAULT_STOCK_ROM),
                    help="path to stock ROM bin (default rom/ae5l600l.bin)")
    ap.add_argument("--logs", default=str(REPO_ROOT / "logs/**/*.csv"),
                    help="glob for log CSVs (default logs/**/*.csv)")
    ap.add_argument("--label", default=None, help="rom rev label for output naming")
    ap.add_argument("--rpm-cliff", type=float, default=DEFAULT_RPM_CLIFF_DEG)
    ap.add_argument("--load-cliff", type=float, default=DEFAULT_LOAD_CLIFF_DEG)
    ap.add_argument("--min-residency", type=float, default=DEFAULT_MIN_RESIDENCY_S)
    ap.add_argument("--samples-per-sec", type=float, default=25.0)
    ap.add_argument("--out", default=None,
                    help="output text file (default trends/avcs_review_<label>.txt)")
    args = ap.parse_args()

    label = args.label or Path(args.rom).stem
    out_path = Path(args.out) if args.out else TRENDS_DIR / f"avcs_review_{label}.txt"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    sections = []

    sections.append(f"AVCS Cruise review — {label}")
    sections.append(f"  rom:   {args.rom}")
    sections.append(f"  stock: {args.stock}")
    if args.prior: sections.append(f"  prior: {args.prior}")
    sections.append("")

    # 1) Current tables (cruise + non-cruise)
    load, rpm, cruise_tab = read_table(args.rom, CRUISE_ADDR)
    _,    _,   noncruise_tab = read_table(args.rom, NONCRUISE_ADDR)
    sections.append(fmt_table(load, rpm, cruise_tab, f"AVCS CRUISE ({label})"))
    sections.append("")

    diffs_cn = diff_tables(cruise_tab, noncruise_tab, load, rpm)
    if not diffs_cn:
        sections.append(f"AVCS NON-CRUISE: byte-identical to cruise (0/{N_LOAD * N_RPM} cells differ)")
    else:
        sections.append(f"AVCS NON-CRUISE: {len(diffs_cn)}/{N_LOAD * N_RPM} cells differ from cruise")
        for r, l, a, b, d in diffs_cn[:30]:
            sections.append(f"  rpm={r:.0f}  load={l:.2f}  cruise={a:.2f}  noncruise={b:.2f}  delta={d:+.2f}")
    sections.append("")

    # 2) Diff vs prior
    if args.prior:
        _, _, prior_tab = read_table(args.prior, CRUISE_ADDR)
        diffs = diff_tables(prior_tab, cruise_tab, load, rpm)
        sections.append(f"=== Cruise diff vs {Path(args.prior).stem} ===")
        if not diffs:
            sections.append("  no cells changed")
        else:
            sections.append(f"  cells changed: {len(diffs)}")
            for r, l, a, b, d in diffs:
                sections.append(f"  rpm={r:.0f}  load={l:.2f}  prior={a:.2f}  current={b:.2f}  delta={d:+.2f}")
        sections.append("")

    # 3) Stock comparison (cruise + non-cruise)
    s_load, s_rpm, s_cruise = read_table(args.stock, CRUISE_ADDR)
    _,      _,     s_nc     = read_table(args.stock, NONCRUISE_ADDR)
    sections.append("=== Stock comparison (bilinear interp onto current axis) ===")
    sections.append(f"{'RPM':>5} {'Load':>5}  {'Tune':>6} {'StkCru':>7} {'StkNC':>7} "
                    f"{'Δ(T-Cr)':>9} {'Δ(T-NC)':>9}")
    for y in range(N_RPM):
        if rpm[y] < 1500 or rpm[y] > 5000:
            continue
        for x in range(N_LOAD):
            if load[x] < 0.30 or load[x] > 1.50:
                continue
            t  = cruise_tab[y][x]
            sc = bilinear(rpm[y], load[x], s_rpm, s_load, s_cruise)
            sn = bilinear(rpm[y], load[x], s_rpm, s_load, s_nc)
            sections.append(f"{rpm[y]:>5.0f} {load[x]:>5.2f}  {t:>6.2f} {sc:>7.2f} {sn:>7.2f} "
                            f"{t - sc:>+9.2f} {t - sn:>+9.2f}")
    sections.append("")

    # 4) Residency
    log_paths = sorted(set(glob.glob(args.logs, recursive=True)))
    log_paths = [p for p in log_paths if not p.endswith(".json")]
    sections.append(f"=== Log corpus: {len(log_paths)} CSVs ===")
    for p in log_paths:
        sections.append(f"  {os.path.relpath(p, REPO_ROOT)}")
    sections.append("")

    cruise_res, all_res, total = build_residency(log_paths, rpm, load, args.samples_per_sec)
    sections.append(f"  total samples seen: {total}")
    sections.append("")
    sections.append(fmt_residency(cruise_res, rpm, load, args.samples_per_sec,
                                   "Cruise residency (CL=8, MPH>20 if avail) seconds"))
    sections.append("")
    sections.append(fmt_residency(all_res, rpm, load, args.samples_per_sec,
                                   "All-state residency seconds"))
    sections.append("")

    # 5) Cliff detection
    rpm_cliffs, load_cliffs = detect_cliffs(cruise_tab, rpm, load,
                                            args.rpm_cliff, args.load_cliff)
    sections.append(f"=== RPM cliffs (|Δ| > {args.rpm_cliff}° between adjacent rows) ===")
    for r_lo, r_hi, l, a, b, d in rpm_cliffs:
        if l < 0.30 or l > 1.50:
            continue
        sections.append(f"  load={l:>5.2f}  {r_lo:>5.0f}->{r_hi:<5.0f}  {a:>5.2f}->{b:<5.2f}  Δ={d:+.2f}°")
    sections.append("")
    sections.append(f"=== Load cliffs (|Δ| > {args.load_cliff}° between adjacent cols) ===")
    for r, l_lo, l_hi, a, b, d in load_cliffs:
        if r < 1500 or r > 5000:
            continue
        sections.append(f"  rpm={r:>5.0f}  {l_lo:>5.2f}->{l_hi:<5.2f}  {a:>5.2f}->{b:<5.2f}  Δ={d:+.2f}°")
    sections.append("")

    # 6) Candidate-edit cells (residency × cliff)
    cands = candidate_cells(cruise_tab, cruise_res, rpm, load, args.samples_per_sec,
                            args.min_residency, args.rpm_cliff)
    sections.append(f"=== Candidate cells: dwell ≥ {args.min_residency:.0f}s "
                    f"AND a neighbor delta ≥ {args.rpm_cliff:.1f}° ===")
    sections.append(f"{'RPM':>5} {'Load':>5}  {'Tune':>6}  {'Dwell':>7}  Worst neighbor")
    for r, l, t, sec, dirn, d in cands:
        sections.append(f"{r:>5.0f} {l:>5.2f}  {t:>6.2f}  {sec:>6.0f}s  {dirn or '-':>2} Δ={d:+.2f}°")
    sections.append("")

    # 7) Knock join
    knock = load_knock_by_cell(label)
    if knock:
        sections.append(f"=== Knock-cell overlay (rom_rev='{label}', from trends/knock_by_cell.csv) ===")
        sections.append(f"{'RPM':>5} {'Load':>5}  {'AVCS':>6}  {'Dwell':>7}  {'fbkc evts':>10}  {'min_fbkc':>9}")
        for row in sorted(knock, key=lambda r: -r["event_count_fbkc"]):
            r = row["rpm_bin"]; l = row["load_bin"]
            try:
                t = bilinear(r, l, rpm, load, cruise_tab)
            except Exception:
                t = float("nan")
            # find nearest residency cell
            yi = min(range(N_RPM), key=lambda i: abs(rpm[i] - r))
            xi = min(range(N_LOAD), key=lambda i: abs(load[i] - l))
            sec = cruise_res[yi][xi] / args.samples_per_sec
            sections.append(f"{r:>5.0f} {l:>5.2f}  {t:>6.2f}  {sec:>6.0f}s  "
                            f"{row['event_count_fbkc']:>10d}  {row.get('min_fbkc', '') or '-':>9}")
    else:
        sections.append(f"=== Knock-cell overlay: no rows in trends/knock_by_cell.csv "
                        f"matching rom_rev='{label}' ===")
    sections.append("")

    text = "\n".join(sections)
    out_path.write_text(text)
    print(text)
    print(f"\n[written] {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
