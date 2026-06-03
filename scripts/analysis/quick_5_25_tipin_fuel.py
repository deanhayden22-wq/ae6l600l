"""
Dean's question: with AVCS locked we're ~11% short on air. Tip-in enrichment is
feedforward (Throttle Tip-in Enrichment A/B are indexed on Throttle Angle Change,
NOT on load/MAF -- verified in definitions/AE5L600L 2013 USDM Impreza WRX MT.xml).
So are 20.15 tip-ins running rich, and does steady-state carry more fuel than a
working-AVCS log?

Method (wbo2-independent -- the wideband was cold/saturated on 5-25):
  fuel rate ~ (IPW - deadtime) * RPM ;  air rate = MAF.
  Fit per log on steady closed-loop cruise (where actual AFR == cruise AFR):
     MAF/RPM = slope*IPW + intercept   ->   deadtime = -intercept/slope
  calc_AFR = AFR_cruise * MAF / (slope*(IPW-dt)*RPM)
  = a fuel-implied AFR from MAF + injector command, no wideband.
  (Caveat: during a tip-in MAF lags the real air-rush ~320 ms, so calc_AFR
  reads rich in the transient -- but that bias hits BOTH logs, so the
  20.15-vs-20.14 comparison is the valid part.)
"""
from pathlib import Path
import numpy as np
import pandas as pd

TGT = "logs/5-25 20.15/log0001.csv"
BASE = "logs/5-23 20.14/log0003.csv"


def load(path):
    d = pd.read_csv(path)
    for c in d.columns:
        d[c] = pd.to_numeric(d[c], errors="coerce")
    d = d.sort_values("sample").reset_index(drop=True)
    w = 25
    d["rpm_sd"] = d["RPM"].rolling(w, center=True, min_periods=15).std()
    d["tps_sd"] = d["Throttle"].rolling(w, center=True, min_periods=15).std()
    d["app_sd"] = d["Accelerator"].rolling(w, center=True, min_periods=15).std()
    d["app_d5"] = d["Accelerator"].diff().rolling(5, min_periods=1).sum()
    return d


def fit_calc_afr(d):
    """Self-calibrate a fuel-implied AFR from steady closed-loop cruise."""
    cr = d[(d["CL/OL"] == 8) & (d["RPM"].between(1500, 4500)) & (d["MPH"] > 20)
           & (d["rpm_sd"] < 60) & (d["tps_sd"] < 1.2)
           & (d["IPW"] > 0.5) & (d["MAF"] > 0) & (d["wbo2"].between(13, 16))].copy()
    afr_cruise = cr["wbo2"].median()
    y = cr["MAF"] / cr["RPM"]
    x = cr["IPW"]
    slope, intercept = np.polyfit(x, y, 1)
    dt = -intercept / slope
    return afr_cruise, slope, dt, len(cr)


def calc_afr(d, afr_cruise, slope, dt):
    pred = slope * (d["IPW"] - dt) * d["RPM"]          # MAF if at afr_cruise
    return afr_cruise * d["MAF"] / pred


print("=" * 78)
print("FUEL vs AIR -- 20.15 (AVCS locked) vs 20.14 log0003 (AVCS working)")
print("=" * 78)

d15 = load(TGT)
d14 = load(BASE)
for nm, d in [("20.15", d15), ("20.14", d14)]:
    afrc, sl, dt, n = fit_calc_afr(d)
    d["calc_afr"] = calc_afr(d, afrc, sl, dt)
    d.attrs["cal"] = (afrc, sl, dt)
    print(f"{nm}: cruise-AFR anchor {afrc:.2f}, fitted injector deadtime {dt:.2f} ms"
          f"  (fit n={n})")

# ---------------------------------------------------------------------------
# (1) STEADY STATE -- "not during tip-in": matched RPM x APP x IAT cells
# ---------------------------------------------------------------------------
print("\n" + "-" * 78)
print("(1) STEADY CRUISE  (closed-loop, not tip-in) -- matched RPM x APP x IAT")
print("-" * 78)


def steady_cells(d):
    m = ((d["CL/OL"] == 8) & d["RPM"].between(1800, 4200) & (d["MPH"] > 20)
         & (d["rpm_sd"] < 75) & (d["tps_sd"] < 1.5) & (d["app_sd"] < 1.5)
         & (d["MAF"] > 0) & (d["IPW"] > 0.5))
    s = d[m].copy()
    s["rpm_bin"] = (s["RPM"] // 200 * 200).astype(int)
    s["app_bin"] = (s["Accelerator"] // 2 * 2).astype(int)
    s["iat_bin"] = (s["IAT"] // 10 * 10).astype(int)
    return s


agg = dict(n=("MAF", "size"), tps=("Throttle", "median"), maf=("MAF", "median"),
           ipw=("IPW", "median"), idc=("IDC", "median"), ffb=("FFB", "median"),
           cafr=("calc_afr", "median"), wbo2=("wbo2", "median"))
g15 = steady_cells(d15).groupby(["rpm_bin", "app_bin", "iat_bin"], observed=True).agg(**agg)
g14 = steady_cells(d14).groupby(["rpm_bin", "app_bin", "iat_bin"], observed=True).agg(**agg)
j = g15.join(g14, lsuffix="_15", rsuffix="_14", how="inner")
j = j[(j["n_15"] >= 12) & (j["n_14"] >= 12) & ((j["tps_15"] - j["tps_14"]).abs() < 1.0)]
w = j["n_15"] + j["n_14"]
for col, lbl in [("maf", "MAF (air)"), ("ipw", "IPW (fuel cmd)"),
                 ("idc", "IDC (fuel duty)")]:
    dpct = 100 * (j[f"{col}_15"] - j[f"{col}_14"]) / j[f"{col}_14"]
    print(f"  {lbl:18s}: 20.15 vs 20.14 = {np.average(dpct, weights=w):+5.1f}%  "
          f"(well-matched cells, n={len(j)})")
print(f"  calc_AFR  20.15 {np.average(j['cafr_15'], weights=w):.2f}  "
      f"vs 20.14 {np.average(j['cafr_14'], weights=w):.2f}   "
      f"(both ~cruise stoich = not rich in steady state)")
print(f"  FFB cmd   20.15 {np.average(j['ffb_15'], weights=w):.2f}  "
      f"vs 20.14 {np.average(j['ffb_14'], weights=w):.2f}")

# ---------------------------------------------------------------------------
# (2) TIP-IN events -- feedforward squirt onto reduced air
# ---------------------------------------------------------------------------
print("\n" + "-" * 78)
print("(2) TIP-IN EVENTS  (pedal rising fast) -- fuel command vs air")
print("-" * 78)


def tipins(d, warm_only_15=False):
    """Detect tip-in onsets: APP rise >=8% over 5 samples, from a settled pedal."""
    m = (d["app_d5"] >= 8) & (d["RPM"].between(1500, 4500)) & (d["IPW"] > 0.5)
    if warm_only_15:
        m = m & (d["time"] - d["time"].min()).between(60, 361) | \
            (m & (d["time"] - d["time"].min()).between(660, 723))
    idx = np.where(m.to_numpy())[0]
    events = []
    last = -999
    for i in idx:
        if i - last < 25 or i < 6 or i > len(d) - 20:
            continue
        last = i
        pre = d.iloc[i - 6:i]                  # ~0.25 s before onset
        post = d.iloc[i:i + 18]                # ~0.7 s of the stab
        events.append(dict(
            i=i, rpm=pre["RPM"].median(),
            app_pre=pre["Accelerator"].median(), app_pk=post["Accelerator"].max(),
            tps_rate=post["Throttle"].diff().max(),
            maf_pk=post["MAF"].max(),
            ipw_pre=pre["IPW"].median(), ipw_pk=post["IPW"].max(),
            idc_pre=pre["IDC"].median(), idc_pk=post["IDC"].max(),
            ffb_min=post["FFB"].min(),
            cafr_min=post["calc_afr"].min(),       # richest point in stab
            avcs=post["avcs"].median(),
        ))
    return pd.DataFrame(events)


e15 = tipins(d15)
e14 = tipins(d14)
# match on trigger: RPM band + throttle-rate band
for df in (e15, e14):
    df["rpm_b"] = (df["rpm"] // 500 * 500).astype(int)
    df["rate_b"] = pd.cut(df["tps_rate"], [0, 8, 16, 30, 100]).astype(str)

print(f"20.15 tip-in events: {len(e15)}   20.14 tip-in events: {len(e14)}")
print(f"\n20.15 tip-in detail (sorted by RPM):")
cols = ["rpm", "app_pre", "app_pk", "tps_rate", "avcs", "maf_pk",
        "ipw_pre", "ipw_pk", "idc_pk", "ffb_min", "cafr_min"]
with pd.option_context("display.width", 200, "display.float_format", "{:.2f}".format):
    print(e15.sort_values("rpm")[cols].to_string(index=False))

# matched-trigger comparison: median fuel-command excess + calc_afr
print(f"\nMatched-trigger comparison (RPM band x throttle-rate band):")
print(f"{'RPMband':>8} {'rate':>10} {'n15':>4} {'n14':>4} "
      f"{'ipw_pk15':>9} {'ipw_pk14':>9} {'idc_pk15':>9} {'idc_pk14':>9} "
      f"{'cafr15':>7} {'cafr14':>7}")
for (rb, rt), gg15 in e15.groupby(["rpm_b", "rate_b"]):
    gg14 = e14[(e14["rpm_b"] == rb) & (e14["rate_b"] == rt)]
    if len(gg14) < 2 or len(gg15) < 1:
        continue
    print(f"{rb:>8} {rt:>10} {len(gg15):>4} {len(gg14):>4} "
          f"{gg15['ipw_pk'].median():>9.2f} {gg14['ipw_pk'].median():>9.2f} "
          f"{gg15['idc_pk'].median():>9.1f} {gg14['idc_pk'].median():>9.1f} "
          f"{gg15['cafr_min'].median():>7.2f} {gg14['cafr_min'].median():>7.2f}")
