"""
Lean Spike Analysis - 4-23 logs (20.8 stock ROM)

Adapts prior afr_accel_comparison logic to the 4-23 logger schema, which lacks
the computed 'load' column. Load is derived as MAF*60/RPM (g/rev) per user spec.

Accel zone:   RPM 3000-5000, load 0.5-0.9 g/rev, MAF 40-70 g/s
Lean spike:   AFR > 13.0 inside the accel zone
Sample rate:  25 Hz (40 ms)
"""

import csv
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LOGS = REPO / "logs" / "4-23"

# Accel zone filters (unchanged from prior analyses)
RPM_MIN, RPM_MAX = 3000, 5000
LOAD_MIN, LOAD_MAX = 0.5, 0.9
MAF_MIN, MAF_MAX = 40, 70
AFR_LEAN_THRESHOLD = 13.0


def load_log(path):
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            try:
                rpm = float(r["RPM"])
                maf = float(r["MAF"])
                # Derived load per user spec: load = MAF*60 / RPM  (g/rev)
                load = (maf * 60.0 / rpm) if rpm > 0 else 0.0
                row = {
                    "sample": int(r["sample"]),
                    "time": float(r["time"]),
                    "AFR": float(r["AFR"]),
                    "wbo2": float(r["wbo2"]),
                    "FFB": float(r["FFB"]),
                    "AFC": float(r["AFC"]),
                    "AFL": float(r["AFL"]),
                    "RPM": rpm,
                    "MAF": maf,
                    "load": load,
                    "Throttle": float(r["Throttle"]),
                    "Accelerator": float(r["Accelerator"]),
                    "CL/OL": int(r["CL/OL"]),
                    "FLKC": float(r["FLKC"]),
                    "FBKC": float(r["FBKC"]),
                    "MAP": float(r["MAP"]),
                    "Trgt_Boost": float(r["Trgt_Boost"]),
                    "wgdc": float(r["wgdc"]),
                    "IPW": float(r["IPW"]),
                    "Timing": float(r["Timing"]),
                    "IAT": float(r["IAT"]),
                    "IAM": float(r["IAM"]),
                }
                rows.append(row)
            except (ValueError, KeyError):
                continue
    return rows


def in_accel_zone(row):
    return (RPM_MIN <= row["RPM"] <= RPM_MAX
            and LOAD_MIN <= row["load"] <= LOAD_MAX
            and MAF_MIN <= row["MAF"] <= MAF_MAX)


def clol_label(val):
    # Per disassembly/analysis/cl_ol_master_analysis.txt: 7=off, 8=CL, 10=OL.
    # (Prior afr_accel_comparison.py used a map from a different ROM and
    # mislabeled 8 as OL; fixed here.)
    return {7: "off", 8: "CL", 10: "OL"}.get(val, f"?{val}")


def stats(values):
    if not values:
        return {"n": 0}
    n = len(values)
    s = sorted(values)
    mean = sum(values) / n
    var = sum((v - mean) ** 2 for v in values) / n
    return {
        "n": n, "mean": mean, "min": min(values), "max": max(values),
        "std": var ** 0.5,
        "p5":  s[max(0, int(n * 0.05))],
        "p50": s[n // 2],
        "p95": s[min(n - 1, int(n * 0.95))],
    }


def find_top_spikes(accel_rows, all_rows, top_n=5, separation=20):
    sample_idx = {r["sample"]: i for i, r in enumerate(all_rows)}
    leans = [r for r in accel_rows if r["AFR"] > AFR_LEAN_THRESHOLD]
    leans.sort(key=lambda r: r["AFR"], reverse=True)
    shown = []
    for r in leans:
        if all(abs(r["sample"] - s["sample"]) > separation for s in shown):
            shown.append(r)
        if len(shown) >= top_n:
            break
    # Build context windows
    windows = []
    for r in shown:
        idx = sample_idx.get(r["sample"])
        if idx is None:
            continue
        start = max(0, idx - 5)
        end = min(len(all_rows), idx + 6)
        windows.append({"event": r, "context": all_rows[start:end],
                        "center_idx": idx - start})
    return windows


def detect_clol_transitions(accel_rows, all_rows):
    sample_idx = {r["sample"]: i for i, r in enumerate(all_rows)}
    transitions = []
    for r in accel_rows:
        idx = sample_idx.get(r["sample"])
        if idx is None or idx < 1:
            continue
        if all_rows[idx - 1]["CL/OL"] != r["CL/OL"]:
            transitions.append({
                "sample": r["sample"], "time": r["time"],
                "from": all_rows[idx - 1]["CL/OL"], "to": r["CL/OL"],
                "AFR": r["AFR"], "RPM": r["RPM"], "load": r["load"],
            })
    return transitions


def analyze(name, path):
    print(f"\n{'=' * 78}")
    print(f"  {name}  ({path.name})")
    print(f"{'=' * 78}")

    rows = load_log(path)
    accel = [r for r in rows if in_accel_zone(r)]

    dur = rows[-1]["time"] - rows[0]["time"] if rows else 0
    print(f"\n  Total samples:      {len(rows)}  ({dur:.1f} s @ 25 Hz)")
    print(f"  Accel-zone samples: {len(accel)}  ({100*len(accel)/max(1,len(rows)):.1f}%)")

    if not accel:
        print("  ** No data in accel zone **")
        return None

    afr = stats([r["AFR"] for r in accel])
    print(f"\n  AFR in accel zone:")
    print(f"    n={afr['n']}  mean={afr['mean']:.2f}  std={afr['std']:.3f}")
    print(f"    min(richest)={afr['min']:.2f}  max(leanest)={afr['max']:.2f}")
    print(f"    P5={afr['p5']:.2f}  P50={afr['p50']:.2f}  P95={afr['p95']:.2f}")

    lean13 = sum(1 for r in accel if r["AFR"] > 13.0)
    lean14 = sum(1 for r in accel if r["AFR"] > 14.0)
    lean16 = sum(1 for r in accel if r["AFR"] > 16.0)
    pegged = sum(1 for r in accel if r["AFR"] >= 20.3)
    print(f"\n  Lean events:")
    print(f"    AFR > 13.0: {lean13:5d}  ({100*lean13/len(accel):.1f}%)")
    print(f"    AFR > 14.0: {lean14:5d}  ({100*lean14/len(accel):.1f}%)")
    print(f"    AFR > 16.0: {lean16:5d}  ({100*lean16/len(accel):.1f}%)")
    print(f"    pegged >=20.3: {pegged}")

    # CL/OL distribution
    print(f"\n  CL/OL in accel zone:")
    clol_dist = {}
    for r in accel:
        k = clol_label(r["CL/OL"])
        clol_dist[k] = clol_dist.get(k, 0) + 1
    for k, v in sorted(clol_dist.items()):
        print(f"    {k:<6} {v:5d}  ({100*v/len(accel):.1f}%)")

    # AFR split by CL/OL
    print(f"\n  AFR by CL/OL:")
    for mode in sorted(set(r["CL/OL"] for r in accel)):
        vals = [r["AFR"] for r in accel if r["CL/OL"] == mode]
        s = stats(vals)
        lean13_m = sum(1 for v in vals if v > 13.0)
        print(f"    {clol_label(mode):<6} n={s['n']:5d}  mean={s['mean']:.2f}  "
              f"max={s['max']:.2f}  std={s['std']:.3f}  lean>13: {lean13_m}")

    # Corrections
    afc = stats([r["AFC"] for r in accel])
    afl = stats([r["AFL"] for r in accel])
    print(f"\n  Corrections in accel zone:")
    print(f"    AFC: mean={afc['mean']:+.2f}%  min={afc['min']:+.2f}%  max={afc['max']:+.2f}%")
    print(f"    AFL: mean={afl['mean']:+.2f}%  min={afl['min']:+.2f}%  max={afl['max']:+.2f}%")

    # Knock
    knock = [r for r in accel if r["FBKC"] != 0 or r["FLKC"] != 0]
    print(f"\n  Knock events in accel zone: {len(knock)}")
    if knock:
        fb = [r["FBKC"] for r in knock]
        fl = [r["FLKC"] for r in knock]
        print(f"    FBKC range: {min(fb):+.2f} .. {max(fb):+.2f} deg")
        print(f"    FLKC range: {min(fl):+.2f} .. {max(fl):+.2f} deg")

    # CL/OL transitions
    transitions = detect_clol_transitions(accel, rows)
    print(f"\n  CL/OL transitions in accel zone: {len(transitions)}")
    for t in transitions[:8]:
        print(f"    s={t['sample']:5d} t={t['time']:.2f}  "
              f"{clol_label(t['from'])}->{clol_label(t['to'])}  "
              f"AFR={t['AFR']:.1f}  RPM={t['RPM']:.0f}  load={t['load']:.3f}")

    # Top worst spikes
    spikes = find_top_spikes(accel, rows)
    if spikes:
        print(f"\n  Top {len(spikes)} worst lean spikes (with +/-5 sample context):")
        for i, sp in enumerate(spikes):
            ev = sp["event"]
            print(f"\n  --- Spike #{i+1}: AFR={ev['AFR']:.2f}  s={ev['sample']}  "
                  f"t={ev['time']:.2f}  RPM={ev['RPM']:.0f}  load={ev['load']:.3f}  "
                  f"MAF={ev['MAF']:.1f}  MAP={ev['MAP']:.1f}  {clol_label(ev['CL/OL'])} ---")
            print(f"  {'':>3}{'s':>6} {'t':>7} {'AFR':>6} {'wbo2':>6} {'RPM':>5} "
                  f"{'load':>6} {'MAF':>5} {'MAP':>5} {'Thrtl':>5} {'CL/OL':>5} "
                  f"{'AFC':>6} {'FBKC':>6} {'IPW':>5}")
            for j, c in enumerate(sp["context"]):
                mk = ">>>" if j == sp["center_idx"] else "   "
                print(f"  {mk}{c['sample']:>6} {c['time']:>7.2f} {c['AFR']:>6.2f} "
                      f"{c['wbo2']:>6.2f} {c['RPM']:>5.0f} {c['load']:>6.3f} "
                      f"{c['MAF']:>5.1f} {c['MAP']:>5.1f} {c['Throttle']:>5.1f} "
                      f"{clol_label(c['CL/OL']):>5} {c['AFC']:>+6.1f} "
                      f"{c['FBKC']:>+6.2f} {c['IPW']:>5.2f}")

    return {"name": name, "path": str(path), "afr": afr,
            "lean13": lean13, "lean14": lean14, "lean16": lean16,
            "pegged": pegged, "n_accel": len(accel), "n_total": len(rows),
            "clol_dist": clol_dist, "afc": afc, "afl": afl,
            "knock": len(knock), "transitions": len(transitions),
            "rows": rows, "accel": accel}


def main():
    paths = [LOGS / "log0001.csv", LOGS / "log0002.csv"]
    missing = [p for p in paths if not p.exists()]
    if missing:
        print(f"Missing: {missing}"); sys.exit(1)

    results = [analyze(p.stem, p) for p in paths]

    print(f"\n\n{'=' * 78}")
    print(f"  SIDE-BY-SIDE (4-23 logs, stock 20.8 ROM)")
    print(f"{'=' * 78}")
    cols = [r["name"] for r in results]
    def row(label, vals): print(f"  {label:<28} " + "  ".join(f"{v:>14}" for v in vals))
    row("Metric", cols)
    row("-" * 28, ["-" * 14] * len(cols))
    row("Accel-zone samples", [f"{r['n_accel']}" for r in results])
    row("AFR mean",        [f"{r['afr']['mean']:.2f}" for r in results])
    row("AFR max (leanest)", [f"{r['afr']['max']:.2f}" for r in results])
    row("AFR P95",         [f"{r['afr']['p95']:.2f}" for r in results])
    row("AFR std",         [f"{r['afr']['std']:.3f}" for r in results])
    row("Lean > 13.0",     [f"{r['lean13']} ({100*r['lean13']/r['n_accel']:.1f}%)" for r in results])
    row("Lean > 14.0",     [f"{r['lean14']}" for r in results])
    row("Lean > 16.0",     [f"{r['lean16']}" for r in results])
    row("Pegged >=20.3",   [f"{r['pegged']}" for r in results])
    row("AFC mean",        [f"{r['afc']['mean']:+.2f}%" for r in results])
    row("AFL mean",        [f"{r['afl']['mean']:+.2f}%" for r in results])
    row("Knock events",    [f"{r['knock']}" for r in results])
    row("CL/OL transitions", [f"{r['transitions']}" for r in results])

    return results


if __name__ == "__main__":
    main()
