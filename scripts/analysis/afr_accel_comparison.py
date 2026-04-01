"""
AFR Spike Analysis: Acceleration Zone Comparison (4-1 vs 3-30)

Filters to the acceleration zone (3000-5000 RPM, 0.5-0.9 g/rev load, 40-70 g/s MAF)
and compares AFR behavior between the two log iterations.
"""

import csv
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LOGS = REPO / "logs"

# Acceleration zone filters
RPM_MIN, RPM_MAX = 3000, 5000
LOAD_MIN, LOAD_MAX = 0.5, 0.9
MAF_MIN, MAF_MAX = 40, 70

# AFR lean threshold for "spike" detection
AFR_LEAN_THRESHOLD = 13.0  # anything leaner than this is suspect under load


def load_log(path):
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            try:
                row = {
                    "sample": int(r["sample"]),
                    "time": float(r["time"]),
                    "AFR": float(r["AFR"]),
                    "FFB": float(r["FFB"]),
                    "AFC": float(r["AFC"]),
                    "AFL": float(r["AFL"]),
                    "RPM": float(r["RPM"]),
                    "load": float(r["load"]),
                    "MAF": float(r["MAF"]),
                    "Throttle": float(r["Throttle"]),
                    "CL/OL": int(r["CL/OL"]),
                    "FLKC": float(r["FLKC"]),
                    "FBKC": float(r["FBKC"]),
                    "IPW": float(r["IPW"]),
                    "mrp": float(r["mrp"]),
                    "MAP": float(r["MAP"]),
                    "Accelerator": float(r["Accelerator"]),
                    "wbo2": float(r["wbo2"]),
                }
                rows.append(row)
            except (ValueError, KeyError):
                continue
    return rows


def in_accel_zone(row):
    return (RPM_MIN <= row["RPM"] <= RPM_MAX
            and LOAD_MIN <= row["load"] <= LOAD_MAX
            and MAF_MIN <= row["MAF"] <= MAF_MAX)


def stats(values):
    if not values:
        return {"n": 0}
    n = len(values)
    mean = sum(values) / n
    mn = min(values)
    mx = max(values)
    var = sum((v - mean) ** 2 for v in values) / n
    std = var ** 0.5
    s = sorted(values)
    p5 = s[max(0, int(n * 0.05))]
    p95 = s[min(n - 1, int(n * 0.95))]
    return {"n": n, "mean": mean, "min": mn, "max": mx, "std": std, "p5": p5, "p95": p95}


def find_lean_spikes(rows, all_rows):
    """Find lean AFR events in accel zone and return context windows."""
    spikes = []
    sample_idx = {r["sample"]: i for i, r in enumerate(all_rows)}

    for r in rows:
        if r["AFR"] > AFR_LEAN_THRESHOLD:
            idx = sample_idx.get(r["sample"])
            if idx is not None:
                ctx_start = max(0, idx - 5)
                ctx_end = min(len(all_rows), idx + 6)
                spikes.append({
                    "event": r,
                    "context": all_rows[ctx_start:ctx_end],
                    "center_idx": idx - ctx_start,
                })
    return spikes


def detect_clol_transitions(rows, all_rows):
    """Find CL/OL transitions near accel zone events."""
    sample_idx = {r["sample"]: i for i, r in enumerate(all_rows)}
    transitions = []
    for r in rows:
        idx = sample_idx.get(r["sample"])
        if idx is None or idx < 1:
            continue
        prev_clol = all_rows[idx - 1]["CL/OL"]
        curr_clol = r["CL/OL"]
        if prev_clol != curr_clol:
            transitions.append({
                "sample": r["sample"],
                "time": r["time"],
                "from": prev_clol,
                "to": curr_clol,
                "AFR": r["AFR"],
                "RPM": r["RPM"],
                "load": r["load"],
            })
    return transitions


def clol_label(val):
    return {7: "CL-hi", 8: "OL", 0: "CL-lo"}.get(val, f"?{val}")


def analyze_log(name, path):
    print(f"\n{'='*70}")
    print(f"  LOG: {name} ({path.name})")
    print(f"{'='*70}")

    all_rows = load_log(path)
    accel = [r for r in all_rows if in_accel_zone(r)]

    print(f"\n  Total samples: {len(all_rows)}")
    print(f"  Accel zone samples: {len(accel)}")

    if not accel:
        print("  ** No data in acceleration zone **")
        return None

    # AFR stats
    afr_vals = [r["AFR"] for r in accel]
    afr_s = stats(afr_vals)
    print(f"\n  AFR in accel zone:")
    print(f"    Mean:  {afr_s['mean']:.2f}")
    print(f"    Min:   {afr_s['min']:.2f}  (richest)")
    print(f"    Max:   {afr_s['max']:.2f}  (leanest)")
    print(f"    Std:   {afr_s['std']:.3f}")
    print(f"    P5:    {afr_s['p5']:.2f}")
    print(f"    P95:   {afr_s['p95']:.2f}")

    # Count lean spikes
    lean_count = sum(1 for v in afr_vals if v > AFR_LEAN_THRESHOLD)
    very_lean = sum(1 for v in afr_vals if v > 14.0)
    print(f"\n  Lean events (AFR > {AFR_LEAN_THRESHOLD}):")
    print(f"    Count:     {lean_count} / {len(accel)} ({100*lean_count/len(accel):.1f}%)")
    print(f"    Very lean (>14.0): {very_lean}")

    # CL/OL distribution in accel zone
    clol_dist = {}
    for r in accel:
        key = clol_label(r["CL/OL"])
        clol_dist[key] = clol_dist.get(key, 0) + 1
    print(f"\n  CL/OL distribution in accel zone:")
    for k, v in sorted(clol_dist.items()):
        pct = 100 * v / len(accel)
        print(f"    {k}: {v} ({pct:.1f}%)")

    # AFR by CL/OL mode
    print(f"\n  AFR by CL/OL mode:")
    for mode in sorted(set(r["CL/OL"] for r in accel)):
        mode_afr = [r["AFR"] for r in accel if r["CL/OL"] == mode]
        if mode_afr:
            s = stats(mode_afr)
            label = clol_label(mode)
            print(f"    {label}: mean={s['mean']:.2f}  min={s['min']:.2f}  max={s['max']:.2f}  std={s['std']:.3f}  n={s['n']}")

    # Correction stats
    afc_vals = [r["AFC"] for r in accel]
    afl_vals = [r["AFL"] for r in accel]
    afc_s = stats(afc_vals)
    afl_s = stats(afl_vals)
    print(f"\n  Fuel corrections in accel zone:")
    print(f"    AFC: mean={afc_s['mean']:.2f}%  min={afc_s['min']:.2f}%  max={afc_s['max']:.2f}%")
    print(f"    AFL: mean={afl_s['mean']:.2f}%  min={afl_s['min']:.2f}%  max={afl_s['max']:.2f}%")

    # Knock in accel zone
    knock_events = [r for r in accel if r["FBKC"] != 0 or r["FLKC"] != 0]
    print(f"\n  Knock events in accel zone: {len(knock_events)}")
    if knock_events:
        fbkc_vals = [r["FBKC"] for r in knock_events]
        print(f"    FBKC range: {min(fbkc_vals):.2f} to {max(fbkc_vals):.2f}")

    # CL/OL transitions in accel zone
    transitions = detect_clol_transitions(accel, all_rows)
    print(f"\n  CL/OL transitions in accel zone: {len(transitions)}")
    for t in transitions[:5]:
        print(f"    sample={t['sample']} t={t['time']:.2f}s  "
              f"{clol_label(t['from'])}->{clol_label(t['to'])}  "
              f"AFR={t['AFR']:.1f}  RPM={t['RPM']:.0f}  load={t['load']:.3f}")

    # Worst lean spikes with context
    spikes = find_lean_spikes(accel, all_rows)
    # Deduplicate - only show top 5 worst unique events (separated by at least 20 samples)
    spikes.sort(key=lambda s: s["event"]["AFR"], reverse=True)
    shown = []
    for sp in spikes:
        if all(abs(sp["event"]["sample"] - prev["event"]["sample"]) > 20 for prev in shown):
            shown.append(sp)
        if len(shown) >= 5:
            break

    if shown:
        print(f"\n  Top {len(shown)} worst lean spike events (with context):")
        for i, sp in enumerate(shown):
            ev = sp["event"]
            print(f"\n  --- Spike #{i+1}: AFR={ev['AFR']:.2f} @ sample={ev['sample']} "
                  f"t={ev['time']:.2f}s RPM={ev['RPM']:.0f} load={ev['load']:.3f} "
                  f"MAF={ev['MAF']:.1f} {clol_label(ev['CL/OL'])} ---")
            print(f"  {'sample':>7} {'time':>7} {'AFR':>6} {'RPM':>6} {'load':>7} "
                  f"{'MAF':>6} {'CL/OL':>5} {'AFC':>6} {'AFL':>7} {'FBKC':>5} {'Throttle':>8}")
            for j, c in enumerate(sp["context"]):
                marker = " >>>" if j == sp["center_idx"] else "    "
                print(f"  {marker}{c['sample']:>5} {c['time']:>7.2f} {c['AFR']:>6.2f} "
                      f"{c['RPM']:>6.0f} {c['load']:>7.3f} {c['MAF']:>6.1f} "
                      f"{clol_label(c['CL/OL']):>5} {c['AFC']:>6.1f} {c['AFL']:>7.2f} "
                      f"{c['FBKC']:>5.1f} {c['Throttle']:>8.1f}")

    return {
        "name": name,
        "n_total": len(all_rows),
        "n_accel": len(accel),
        "afr": afr_s,
        "lean_count": lean_count,
        "very_lean": very_lean,
        "lean_pct": 100 * lean_count / len(accel) if accel else 0,
        "afc": afc_s,
        "afl": afl_s,
        "knock_count": len(knock_events),
        "transitions": len(transitions),
        "clol_dist": clol_dist,
    }


def comparison_table(results):
    print(f"\n\n{'='*70}")
    print(f"  COMPARISON: {results[0]['name']} vs {results[1]['name']}")
    print(f"{'='*70}")

    old, new = results[0], results[1]

    rows = [
        ("Accel zone samples", f"{old['n_accel']}", f"{new['n_accel']}"),
        ("AFR mean", f"{old['afr']['mean']:.2f}", f"{new['afr']['mean']:.2f}"),
        ("AFR min (richest)", f"{old['afr']['min']:.2f}", f"{new['afr']['min']:.2f}"),
        ("AFR max (leanest)", f"{old['afr']['max']:.2f}", f"{new['afr']['max']:.2f}"),
        ("AFR std dev", f"{old['afr']['std']:.3f}", f"{new['afr']['std']:.3f}"),
        ("AFR P5", f"{old['afr']['p5']:.2f}", f"{new['afr']['p5']:.2f}"),
        ("AFR P95", f"{old['afr']['p95']:.2f}", f"{new['afr']['p95']:.2f}"),
        (f"Lean events (>{AFR_LEAN_THRESHOLD})",
         f"{old['lean_count']} ({old['lean_pct']:.1f}%)",
         f"{new['lean_count']} ({new['lean_pct']:.1f}%)"),
        ("Very lean (>14.0)", f"{old['very_lean']}", f"{new['very_lean']}"),
        ("AFC mean", f"{old['afc']['mean']:.2f}%", f"{new['afc']['mean']:.2f}%"),
        ("AFL mean", f"{old['afl']['mean']:.2f}%", f"{new['afl']['mean']:.2f}%"),
        ("Knock events", f"{old['knock_count']}", f"{new['knock_count']}"),
        ("CL/OL transitions", f"{old['transitions']}", f"{new['transitions']}"),
    ]

    w1 = max(len(r[0]) for r in rows) + 2
    w2 = max(len(r[1]) for r in rows) + 2
    w3 = max(len(r[2]) for r in rows) + 2

    hdr = f"  {'Metric':<{w1}} {'3-30 (prev)':<{w2}} {'4-1 (new)':<{w3}} Delta"
    print(f"\n{hdr}")
    print(f"  {'-'*len(hdr)}")

    for label, v_old, v_new in rows:
        # Try to compute delta for numeric values
        delta = ""
        try:
            a = float(v_old.replace("%", "").strip().split("(")[0].strip())
            b = float(v_new.replace("%", "").strip().split("(")[0].strip())
            d = b - a
            if "lean" in label.lower() or "max" in label.lower() or "std" in label.lower():
                # lower is better for these
                arrow = "improved" if d < 0 else ("worse" if d > 0 else "same")
            elif "min" in label.lower():
                # for richest, more negative = richer, depends on context
                arrow = ""
            else:
                arrow = ""
            delta = f"{d:+.2f}" + (f" ({arrow})" if arrow else "")
        except (ValueError, IndexError):
            pass
        print(f"  {label:<{w1}} {v_old:<{w2}} {v_new:<{w3}} {delta}")


def main():
    log_old = LOGS / "3-30.csv"
    log_new = LOGS / "4-1.csv"

    if not log_old.exists() or not log_new.exists():
        print(f"Missing log files: {log_old} or {log_new}")
        sys.exit(1)

    results = []
    results.append(analyze_log("3-30 (previous)", log_old))
    results.append(analyze_log("4-1 (new tune)", log_new))

    if all(r is not None for r in results):
        comparison_table(results)

    print("\n")


if __name__ == "__main__":
    main()
