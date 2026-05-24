"""
Shift-knock detector / filter for FBKC events.

A 5-speed manual without a gear-position channel still leaks gear info through
MPH/RPM ratio. We use that ratio to detect gear changes; shift knock events
fire as the clutch re-engages.

Signatures we look for in a +/-2s window around each FBKC<0 sample:
  1. throttle dipped to near-zero (driver lifted to shift) in the recent past
  2. MPH/RPM ratio changed discretely (gear actually changed)
  3. RPM stepped down then up (engine speed transient on clutch out/in)
  4. The knock fired DURING the rev-match / clutch-engage moment, not at
     sustained load

If any of these fire, we tag the event as 'shift-like'. We require >=2 of the
4 signatures to call it shift (single-signature events stay ambiguous so we
don't wash out real knock).

Outputs:
  - per-event classification CSV (scripts/analysis/trends/knock_shift_classification.csv)
  - knock map split by class
  - a reusable function classify_knock_events() that other scripts can import
"""
from __future__ import annotations

from pathlib import Path
import numpy as np
import pandas as pd

# ROM grid (same as log_review_ingest)
RPM_BP = np.array([800,1200,1600,1900,2200,2600,3000,3300,3700,4000,4400,4800,5200,5500,6000,6300,6600,7000], dtype=float)
LOAD_BP = np.array([0.27,0.57,0.73,1.00,1.17,1.36,1.51,1.36,1.78,1.95,2.12,2.28,2.44,2.6,2.9,3.22,3.7], dtype=float)
# (typo guard: 1.36 twice was a copy error; fix:)
LOAD_BP = np.array([0.27,0.57,0.73,1.00,1.17,1.36,1.51,1.64,1.78,1.95,2.12,2.28,2.44,2.6,2.9,3.22,3.7], dtype=float)


def _nearest(v, bp):
    if pd.isna(v): return np.nan
    return float(bp[np.argmin(np.abs(bp - v))])


def classify_knock_events(df: pd.DataFrame,
                          sample_hz: float = 25.0,
                          lookback_s: float = 3.0,
                          throttle_lift_thresh: float = 10.0,
                          ratio_change_pct: float = 0.18,
                          rpm_drop_thresh: float = 500.0) -> pd.DataFrame:
    """
    Classify each FBKC<0 sample as 'shift' / 'maybe-shift' / 'load'.

    Dominant signal: gear-ratio change in lookback window. mph_per_krpm
    jumping >20% between max and min in the prior 3 seconds = a gear actually
    happened. This catches post-shift load-step knock (the false-positive
    pattern Dean's been chasing).

    Secondary signals:
      - throttle was sustained <thr% in lookback (clutch-in moment)
      - RPM dropped >thr then rose (rev-match transient)
      - knock fires while throttle still low (pure shift mechanical shock)

    Classification:
      - 'shift'       : gear-ratio signal fires (dominant signal alone is enough)
      - 'maybe-shift' : no gear change but throttle+RPM signals both fire
      - 'load'        : neither — real load-domain knock
    """
    n = len(df)
    rpm = df["RPM"].to_numpy(dtype=float)
    mph = df["MPH"].to_numpy(dtype=float)
    thr = df["Throttle"].to_numpy(dtype=float)

    with np.errstate(divide="ignore", invalid="ignore"):
        # require MPH > 10 — launches from stop give noisy ratios that look
        # like gear changes when they're just acceleration through low MPH.
        mph_per_krpm = np.where((rpm > 800) & (mph > 10),
                                mph / (rpm / 1000.0),
                                np.nan)

    w = max(1, int(round(lookback_s * sample_hz)))  # samples in lookback

    sig_gear = np.zeros(n, dtype=bool)
    gear_change_pct = np.full(n, np.nan)
    sig_lift_sustained = np.zeros(n, dtype=bool)   # throttle <thr for at least 0.3s in lookback
    sig_rpm_step = np.zeros(n, dtype=bool)
    sig_now_lifted = np.zeros(n, dtype=bool)
    time_since_shift_s = np.full(n, np.nan)

    fbkc_neg = (df["FBKC"].to_numpy() < 0)
    knock_idx = np.where(fbkc_neg)[0]

    min_lift_samples = max(1, int(round(0.3 * sample_hz)))  # 0.3s sustained lift

    for i in knock_idx:
        lo = max(0, i - w)
        hi = i + 1  # only look BACK
        win_thr = thr[lo:hi]
        win_rpm = rpm[lo:hi]
        win_ratio = mph_per_krpm[lo:hi]

        # 1) gear-ratio signal — max vs min of valid ratio in lookback
        valid = win_ratio[~np.isnan(win_ratio)]
        if len(valid) >= 6:
            rmin, rmax = float(np.nanmin(valid)), float(np.nanmax(valid))
            if rmin > 0:
                pct = (rmax - rmin) / rmin
                gear_change_pct[i] = pct
                if pct >= ratio_change_pct:
                    sig_gear[i] = True
                    # locate when gear change happened (approx) — first sample where
                    # ratio exceeds midpoint between rmin and rmax
                    mid = (rmin + rmax) / 2
                    # going up: find first >= mid; going down: first <= mid
                    diffs = np.abs(np.diff(np.where(np.isnan(win_ratio), rmin, win_ratio)))
                    if len(diffs):
                        idx_shift = int(np.argmax(diffs)) + 1
                        # idx_shift is index INTO win_ratio; convert to time-since
                        time_since_shift_s[i] = (len(win_ratio) - 1 - idx_shift) / sample_hz

        # 2) throttle sustained-low in lookback
        if len(win_thr):
            low = win_thr < throttle_lift_thresh
            # rolling-sum check: any contiguous run >= min_lift_samples
            run = 0
            best = 0
            for v in low:
                run = run + 1 if v else 0
                if run > best: best = run
            if best >= min_lift_samples:
                sig_lift_sustained[i] = True

        # 3) RPM dip-then-rise
        if len(win_rpm) >= 5:
            mn_idx = int(np.argmin(win_rpm))
            mn = win_rpm[mn_idx]
            after = win_rpm[mn_idx:]
            mx_after = float(after.max()) if len(after) else mn
            if (mx_after - mn) >= rpm_drop_thresh and win_thr.min() < throttle_lift_thresh:
                sig_rpm_step[i] = True

        # 4) throttle low NOW
        if thr[i] < throttle_lift_thresh:
            sig_now_lifted[i] = True

    # classification
    # Gear-ratio change alone is the dominant signal (MPH>10 filter already eliminates
    # launch-from-stop false positives). Throttle-lift + RPM-step is a backup pattern
    # for clutchless shifts or weak gear-ratio signals.
    shift_class = np.where(fbkc_neg, "load", "")
    shift_class = np.where(fbkc_neg & sig_gear, "shift", shift_class)
    # backup: lift + RPM step but no clear gear ratio (e.g. small ratio change between
    # close gears, or noisy signal). Mark as maybe-shift.
    shift_class = np.where(fbkc_neg & ~sig_gear & sig_lift_sustained & sig_rpm_step,
                           "maybe-shift", shift_class)
    # knock fires while throttle still low → almost certainly shift mechanical shock
    shift_class = np.where(fbkc_neg & sig_now_lifted, "shift", shift_class)

    out = pd.DataFrame({
        "is_fbkc_neg": fbkc_neg,
        "sig_gear": sig_gear,
        "gear_change_pct": gear_change_pct,
        "time_since_shift_s": time_since_shift_s,
        "sig_lift_sustained": sig_lift_sustained,
        "sig_rpm_step": sig_rpm_step,
        "sig_now_lifted": sig_now_lifted,
        "shift_class": shift_class,
    }, index=df.index)
    return out


def main():
    LOG = Path("logs/5-23 20.14/log0003.csv")
    print(f"loading {LOG}...")
    d = pd.read_csv(LOG)
    for c in d.columns: d[c] = pd.to_numeric(d[c], errors="coerce")
    d = d.sort_values("sample").reset_index(drop=True)
    d["t_rel_s"] = d["time"] - d["time"].min()

    # sample rate
    dur = d["time"].max() - d["time"].min()
    hz = len(d) / dur
    print(f"loaded {len(d):,} samples @ ~{hz:.1f} Hz, {dur/60:.1f} min")

    cls = classify_knock_events(d, sample_hz=hz)
    d = d.join(cls)

    total = (d["FBKC"] < 0).sum()
    by_cls = d.loc[d["FBKC"] < 0, "shift_class"].value_counts()
    print(f"\nTotal FBKC<0 samples: {total}")
    print(f"Classification:")
    for c in ["load", "maybe-shift", "shift"]:
        n = int(by_cls.get(c, 0))
        pct = 100*n/total if total else 0
        print(f"  {c:12s} {n:5d}  ({pct:.1f}%)")

    # per-cell breakdown - LOAD class only
    d["rpm_bin"] = d["RPM"].apply(lambda x: _nearest(x, RPM_BP))
    d["load_bin"] = d["load"].apply(lambda x: _nearest(x, LOAD_BP))

    print("\n## Knock cells AFTER excluding shift-class events")
    real = d[(d["FBKC"] < 0) & (d["shift_class"].isin(["load", "maybe-shift"]))]
    cell = real.groupby(["rpm_bin","load_bin"]).agg(
        n=("FBKC","size"),
        min_fbkc=("FBKC","min"),
        med_fbkc=("FBKC","median"),
        avcs_med=("avcs","median"),
        timing_med=("Timing","median"),
        mrp_med=("mrp","median"),
        ol_pct=("CL/OL", lambda x: (x==10).mean()*100),
    ).reset_index().sort_values("n", ascending=False).head(15)
    print(f"  total LOAD/MAYBE samples: {len(real)}")
    with pd.option_context("display.float_format","{:.2f}".format,"display.width",160):
        print(cell.to_string(index=False))

    print("\n## SHIFT-class knock cells (the false positives we're filtering)")
    sh = d[(d["FBKC"] < 0) & (d["shift_class"] == "shift")]
    sh_cell = sh.groupby(["rpm_bin","load_bin"]).agg(
        n=("FBKC","size"),
        min_fbkc=("FBKC","min"),
        med_fbkc=("FBKC","median"),
    ).reset_index().sort_values("n", ascending=False).head(15)
    print(f"  total SHIFT samples: {len(sh)}")
    with pd.option_context("display.float_format","{:.2f}".format,"display.width",140):
        print(sh_cell.to_string(index=False))

    # Show 3 example shift events with context
    print("\n## Example shift-class events (3 with most context):")
    sh_idx = d.index[d["shift_class"] == "shift"].tolist()
    samples_to_show = []
    last_t = -10
    for i in sh_idx:
        t = d.iloc[i]["t_rel_s"]
        if t - last_t > 5.0:
            samples_to_show.append(i)
            last_t = t
        if len(samples_to_show) >= 3: break
    cols = ["t_rel_s","RPM","MPH","Throttle","load","mrp","Timing","FBKC","FLKC","sig_gear","gear_change_pct","time_since_shift_s","sig_lift_sustained","sig_rpm_step","sig_now_lifted","shift_class"]
    for i in samples_to_show:
        lo = max(0, i-30); hi = min(len(d), i+15)
        print(f"\n  knock @ sample {i}, t={d.iloc[i]['t_rel_s']:.1f}s, FBKC={d.iloc[i]['FBKC']:.2f}, "
              f"gear_change_pct={d.iloc[i]['gear_change_pct']:.2f}, time_since_shift={d.iloc[i]['time_since_shift_s']:.2f}s")
        with pd.option_context("display.float_format","{:.2f}".format,"display.width",200,"display.max_columns",None):
            print(d.iloc[lo:hi][cols].to_string(index=False))

    # write classification
    out = Path("scripts/analysis/trends/knock_shift_classification.csv")
    save = d.loc[d["FBKC"] < 0, ["t_rel_s","RPM","MPH","Throttle","load","FBKC","FLKC","avcs","Timing","rpm_bin","load_bin","CL/OL","sig_gear","gear_change_pct","time_since_shift_s","sig_lift_sustained","sig_rpm_step","sig_now_lifted","shift_class"]].copy()
    save["log"] = "5-23 20.14/log0003.csv"
    save["rom"] = "20.14"
    out.parent.mkdir(exist_ok=True, parents=True)
    save.to_csv(out, index=False)
    print(f"\nwrote per-event classification: {out}")

if __name__ == "__main__":
    main()
