"""
5-25 20.15 AVCS-lockout: how far off is airflow, and what's salvageable?

Context:
  - 20.14 -> 20.15 binary diff (rom_diff.py) = 69 bytes, ONLY in 0xCC4A0-0xCD185
    (tip-in logic) + checksum. MAF scaling, AVCS tables, base timing, pedal/
    throttle tables are all BYTE-IDENTICAL 20.14 -> 20.15.
  - => any steady-cruise MAF/load difference between 20.15 and 20.14 at a
    matched RPM x pedal x IAT cell is attributable to the AVCS lockout
    (a drive condition), not a tune change. Clean natural experiment.

This script matches 20.15 (avcs locked ~6 deg) against 20.14 working-AVCS
logs at the same RPM x APP(pedal) x IAT cells, closed-loop steady cruise,
and reports the load (g/rev) and MAF (g/s) deficit.
"""
from pathlib import Path
import numpy as np
import pandas as pd

BASE = Path(".")
TARGET = ("20.15", "logs/5-25 20.15/log0001.csv")
BASELINES = [
    ("20.14_l3", "logs/5-23 20.14/log0003.csv"),  # 253 min, working AVCS
    ("20.14_l1", "logs/5-23 20.14/log0001.csv"),  # 24 min warm, working AVCS
    ("20.13_l1", "logs/5-22 20.13/log0001.csv"),  # working AVCS
]


def load(path):
    d = pd.read_csv(BASE / path)
    for c in d.columns:
        d[c] = pd.to_numeric(d[c], errors="coerce")
    d = d.sort_values("sample").reset_index(drop=True)
    # contiguous-sample rolling stats (25 Hz -> 25 samples = 1 s)
    w = 25
    d["rpm_sd"] = d["RPM"].rolling(w, center=True, min_periods=15).std()
    d["tps_sd"] = d["Throttle"].rolling(w, center=True, min_periods=15).std()
    d["app_sd"] = d["Accelerator"].rolling(w, center=True, min_periods=15).std()
    return d


def gear_from_ratio(d):
    r = d["RPM"] / d["MPH"].replace(0, np.nan)
    g = pd.Series(np.nan, index=d.index)
    g[r < 50] = 5
    g[(r >= 50) & (r < 72)] = 4
    g[(r >= 72) & (r < 92)] = 3
    g[(r >= 92) & (r < 122)] = 2
    g[r >= 122] = 1
    return g


def steady_cruise(d):
    """Closed-loop steady cruise, warm, AVCS-relevant RPM band."""
    return (
        (d["CL/OL"] == 8)
        & (d["RPM"].between(1800, 4200))
        & (d["MPH"] > 20)
        & (d["rpm_sd"] < 75)
        & (d["tps_sd"] < 1.5)
        & (d["app_sd"] < 1.5)
        & (d["MAF"] > 0)
        & (d["load"] > 0)
        & (d["MAF(V)"] > 0)
    )


def cell_table(d):
    m = steady_cruise(d)
    s = d[m].copy()
    s["gear"] = gear_from_ratio(s)
    s["rpm_bin"] = (s["RPM"] // 200 * 200).astype(int)
    s["app_bin"] = (s["Accelerator"] // 2 * 2).astype(int)
    s["iat_bin"] = (s["IAT"] // 10 * 10).astype(int)
    return s


print("=" * 78)
print("AVCS LOCKOUT -> AIRFLOW DEFICIT  (closed-loop steady cruise, 1800-4200 RPM)")
print("=" * 78)

tgt = cell_table(load(TARGET[1]))
print(f"\n20.15 steady-cruise samples: {len(tgt)}")
print(f"  avcs: median {tgt['avcs'].median():.1f} deg, p95 {tgt['avcs'].quantile(.95):.1f}")
print(f"  IAT : {tgt['IAT'].min():.0f}-{tgt['IAT'].max():.0f} F   ATM: {tgt['ATM(psi)'].median():.2f} psi")

all_pairs = []
for name, path in BASELINES:
    base = cell_table(load(path))
    print(f"\n{name} steady-cruise samples: {len(base)}  | avcs median {base['avcs'].median():.1f} deg"
          f"  | IAT {base['IAT'].min():.0f}-{base['IAT'].max():.0f} F  ATM {base['ATM(psi)'].median():.2f}")

    key = ["rpm_bin", "app_bin", "iat_bin"]
    agg = dict(n=("MAF", "size"), avcs=("avcs", "median"), tps=("Throttle", "median"),
               maf=("MAF", "median"), load=("load", "median"), map=("MAP", "median"),
               atm=("ATM(psi)", "median"), iat=("IAT", "median"))
    gt = tgt.groupby(key, observed=True).agg(**agg)
    gb = base.groupby(key, observed=True).agg(**agg)

    j = gt.join(gb, lsuffix="_15", rsuffix="_b", how="inner")
    j = j[(j["n_15"] >= 12) & (j["n_b"] >= 12)].copy()
    if len(j) == 0:
        print(f"  no matched cells with n>=12 on both sides")
        continue
    j["d_avcs"] = j["avcs_b"] - j["avcs_15"]
    j["d_load_pct"] = 100 * (j["load_15"] - j["load_b"]) / j["load_b"]
    j["d_maf_pct"] = 100 * (j["maf_15"] - j["maf_b"]) / j["maf_b"]
    j["d_tps"] = j["tps_15"] - j["tps_b"]
    j = j.reset_index()

    wsum = (j["n_15"] + j["n_b"])
    w_load = np.average(j["d_load_pct"], weights=wsum)
    w_maf = np.average(j["d_maf_pct"], weights=wsum)
    w_avcs = np.average(j["d_avcs"], weights=wsum)
    print(f"  matched cells: {len(j)}  (RPM x APP x IAT, n>=12 both sides)")
    print(f"  ALL cells           : AVCS gap {w_avcs:4.1f} deg | LOAD {w_load:+5.1f}% | MAF {w_maf:+5.1f}%")
    # well-TPS-matched cells only: |d_tps|<1.0 -> throttle plate genuinely lined
    # up, so the deficit is pure VE/AVCS, not residual throttle mismatch. This
    # is the HONEST headline figure.
    good = j[j["d_tps"].abs() < 1.0]
    if len(good):
        wg = good["n_15"] + good["n_b"]
        print(f"  well-matched (|dTPS|<1, n={len(good)}): AVCS gap "
              f"{np.average(good['d_avcs'], weights=wg):4.1f} deg | "
              f"LOAD {np.average(good['d_load_pct'], weights=wg):+5.1f}% | "
              f"MAF {np.average(good['d_maf_pct'], weights=wg):+5.1f}%  <-- headline")
    print(f"  median TPS mismatch in cells: {j['d_tps'].median():+.2f} %  (want ~0 = pedal/plate matched)")
    print(f"\n  per-cell detail (sorted by RPM, then APP):")
    cols = ["rpm_bin", "app_bin", "iat_bin", "n_15", "n_b", "tps_15", "tps_b",
            "avcs_15", "avcs_b", "load_15", "load_b", "d_load_pct",
            "maf_15", "maf_b", "d_maf_pct"]
    with pd.option_context("display.width", 200, "display.max_rows", 100,
                           "display.float_format", "{:.2f}".format):
        print(j.sort_values(["rpm_bin", "app_bin"])[cols].to_string(index=False))

    j["baseline"] = name
    all_pairs.append(j)

# ---- pooled regression: load deficit vs AVCS deficit ----
if all_pairs:
    P = pd.concat(all_pairs, ignore_index=True)
    # well-TPS-matched cells with a real AVCS gap -> cleanest coefficient
    P = P[(P["d_avcs"] > 2) & (P["d_tps"].abs() < 1.0)]
    w = P["n_15"] + P["n_b"]
    # slope through origin: d_load_pct ~ k * d_avcs
    k = np.average(P["d_load_pct"] / P["d_avcs"], weights=w)
    print("\n" + "=" * 78)
    print("PREDICTING THE GAIN WHEN AVCS IS RESTORED")
    print("=" * 78)
    print(f"pooled well-matched cells (|dTPS|<1, AVCS gap > 2 deg): {len(P)}")
    print(f"load-deficit per degree of AVCS deficit: {k:.2f} %/deg (sample-weighted)")
    print(f"  -> restoring AVCS from ~6 to ~18 deg (+12 deg) projects to "
          f"+{abs(k)*12:.1f}% load at matched pedal/RPM in cruise")
    print(f"  pooled well-matched load deficit (sample-wt): "
          f"{np.average(P['d_load_pct'], weights=w):+.1f}%  MAF "
          f"{np.average(P['d_maf_pct'], weights=w):+.1f}%")
