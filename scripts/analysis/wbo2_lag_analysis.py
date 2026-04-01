"""
WBO2 Transport Delay Analysis

Estimates wideband O2 sensor lag by:
1. Cross-correlating AFR with a fueling proxy (IPW) during transients
2. Re-evaluating the "lean spikes" with the lag offset applied
3. Showing what AFR actually reads once the sensor catches up
"""

import csv
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LOGS = REPO / "logs"

# Accel zone filters
RPM_MIN, RPM_MAX = 3000, 5000
LOAD_MIN, LOAD_MAX = 0.5, 0.9
MAF_MIN, MAF_MAX = 40, 70


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
                    "wbo2": float(r["wbo2"]),
                    "FFB": float(r["FFB"]),
                    "IPW": float(r["IPW"]),
                    "AFC": float(r["AFC"]),
                    "AFL": float(r["AFL"]),
                    "RPM": float(r["RPM"]),
                    "load": float(r["load"]),
                    "MAF": float(r["MAF"]),
                    "Throttle": float(r["Throttle"]),
                    "CL/OL": int(r["CL/OL"]),
                    "Accelerator": float(r["Accelerator"]),
                    "mrp": float(r["mrp"]),
                }
                rows.append(row)
            except (ValueError, KeyError):
                continue
    return rows


def clol_label(val):
    return {7: "CL-hi", 8: "OL", 0: "CL-lo"}.get(val, f"?{val}")


def find_tip_in_events(rows, min_load_delta=0.3, window=4):
    """Find rapid throttle openings where load jumps significantly."""
    events = []
    for i in range(window, len(rows) - 15):
        load_before = rows[i - window]["load"]
        load_now = rows[i]["load"]
        if (load_now - load_before >= min_load_delta
                and load_before < 0.3
                and RPM_MIN <= rows[i]["RPM"] <= RPM_MAX):
            # Check we haven't already found one nearby
            if not events or (i - events[-1]["idx"]) > 20:
                events.append({"idx": i, "row": rows[i]})
    return events


def cross_correlate_tipin(rows, events, max_lag=10):
    """
    For each tip-in event, find when AFR starts responding to the fuel change.

    Logic: IPW jumps immediately with load. AFR should follow with a delay.
    We look for when AFR starts dropping (going richer) after IPW jumps.
    """
    print(f"\n{'='*80}")
    print(f"  WBO2 LAG ESTIMATION: Cross-correlating IPW step vs AFR response")
    print(f"{'='*80}")

    lags = []

    for ev_num, ev in enumerate(events[:15]):  # analyze up to 15 events
        idx = ev["idx"]

        # Find the sample where IPW first jumps (fuel delivery start)
        ipw_baseline = rows[idx - 4]["IPW"]
        ipw_jump_idx = None
        for j in range(idx - 2, min(idx + 6, len(rows))):
            if rows[j]["IPW"] > ipw_baseline * 1.3:  # 30% increase threshold
                ipw_jump_idx = j
                break

        if ipw_jump_idx is None:
            continue

        # Find when AFR starts responding (dropping from lean toward rich)
        afr_at_jump = rows[ipw_jump_idx]["AFR"]
        afr_response_idx = None
        for j in range(ipw_jump_idx, min(ipw_jump_idx + max_lag + 1, len(rows))):
            if rows[j]["AFR"] < afr_at_jump - 0.3:  # AFR drops by 0.3+
                afr_response_idx = j
                break

        if afr_response_idx is None:
            # AFR might already be dropping, or wbo2 maxed — still informative
            # Look for ANY AFR movement
            for j in range(ipw_jump_idx, min(ipw_jump_idx + max_lag + 1, len(rows))):
                if rows[j]["AFR"] < afr_at_jump - 0.1:
                    afr_response_idx = j
                    break

        lag = (afr_response_idx - ipw_jump_idx) if afr_response_idx else None

        if lag is not None:
            lags.append(lag)

        # Print this event
        start = max(0, idx - 4)
        end = min(len(rows), idx + 12)

        print(f"\n  --- Tip-in #{ev_num+1}: sample={rows[idx]['sample']} "
              f"RPM={rows[idx]['RPM']:.0f} ---")
        print(f"  IPW jumps at sample {rows[ipw_jump_idx]['sample']}, "
              f"AFR responds {'at sample ' + str(rows[afr_response_idx]['sample']) + ' (lag=' + str(lag) + ' samples)' if afr_response_idx else 'NOT DETECTED in window'}")

        print(f"  {'':>4}{'sample':>7} {'time':>7} {'AFR':>6} {'wbo2':>6} "
              f"{'IPW':>7} {'load':>7} {'MAF':>6} {'Thrtl':>6} {'CL/OL':>5} {'Accel':>6}")

        for j in range(start, end):
            r = rows[j]
            markers = ""
            if j == ipw_jump_idx:
                markers += " <--IPW"
            if afr_response_idx and j == afr_response_idx:
                markers += " <--AFR"
            if j == idx:
                markers += " <--TIP"

            print(f"  {markers:>4}{r['sample']:>7} {r['time']:>7.2f} {r['AFR']:>6.2f} "
                  f"{r['wbo2']:>6.2f} {r['IPW']:>7.3f} {r['load']:>7.3f} "
                  f"{r['MAF']:>6.1f} {r['Throttle']:>6.1f} {clol_label(r['CL/OL']):>5} "
                  f"{r['Accelerator']:>6.1f}")

    return lags


def estimate_lag(lags):
    print(f"\n{'='*80}")
    print(f"  LAG SUMMARY")
    print(f"{'='*80}")

    if not lags:
        print("  No measurable lag events found.")
        return None

    mean_lag = sum(lags) / len(lags)
    median_lag = sorted(lags)[len(lags) // 2]

    print(f"\n  Measured lags (IPW jump -> AFR response): {lags}")
    print(f"  Count:  {len(lags)} events")
    print(f"  Mean:   {mean_lag:.1f} samples")
    print(f"  Median: {median_lag} samples")
    print(f"  Min:    {min(lags)} samples")
    print(f"  Max:    {max(lags)} samples")

    # At ~25Hz sample rate, 1 sample = 0.04s
    sample_period = 0.04
    print(f"\n  At ~25Hz sample rate ({sample_period*1000:.0f}ms/sample):")
    print(f"    Mean lag:   {mean_lag * sample_period * 1000:.0f} ms")
    print(f"    Median lag: {median_lag * sample_period * 1000:.0f} ms")

    return median_lag


def reeval_with_lag(rows, lag):
    """Re-evaluate accel zone AFR with the lag offset applied."""
    print(f"\n{'='*80}")
    print(f"  RE-EVALUATION: Accel zone AFR with {lag}-sample wbo2 lag correction")
    print(f"{'='*80}")

    # For each sample in the accel zone, the REAL AFR is at sample + lag
    accel_afr_raw = []
    accel_afr_shifted = []

    for i, r in enumerate(rows):
        if (RPM_MIN <= r["RPM"] <= RPM_MAX
                and LOAD_MIN <= r["load"] <= LOAD_MAX
                and MAF_MIN <= r["MAF"] <= MAF_MAX):
            accel_afr_raw.append(r["AFR"])
            # The AFR reading `lag` samples later is what actually reflects THIS sample's combustion
            shifted_idx = i + lag
            if shifted_idx < len(rows):
                accel_afr_shifted.append(rows[shifted_idx]["AFR"])

    if not accel_afr_raw:
        print("  No accel zone data")
        return

    def stats(vals):
        n = len(vals)
        mean = sum(vals) / n
        s = sorted(vals)
        return {
            "n": n, "mean": mean,
            "min": min(vals), "max": max(vals),
            "p5": s[int(n * 0.05)], "p95": s[min(n-1, int(n * 0.95))],
            "std": (sum((v - mean)**2 for v in vals) / n) ** 0.5,
        }

    raw = stats(accel_afr_raw)
    shifted = stats(accel_afr_shifted)

    print(f"\n  {'Metric':<25} {'Raw (no offset)':<18} {'Lag-corrected (+{lag})':<18} {'Delta'}")
    print(f"  {'-'*75}")

    metrics = [
        ("Mean", "mean"), ("Min (richest)", "min"), ("Max (leanest)", "max"),
        ("Std dev", "std"), ("P5", "p5"), ("P95", "p95"),
    ]
    for label, key in metrics:
        fmt = ".3f" if key == "std" else ".2f"
        r_val = raw[key]
        s_val = shifted[key]
        d = s_val - r_val
        print(f"  {label:<25} {r_val:<18{fmt}} {s_val:<18{fmt}} {d:+.2f}")

    lean_raw = sum(1 for v in accel_afr_raw if v > 14.0)
    lean_shifted = sum(1 for v in accel_afr_shifted if v > 14.0)
    very_lean_raw = sum(1 for v in accel_afr_raw if v > 16.0)
    very_lean_shifted = sum(1 for v in accel_afr_shifted if v > 16.0)

    print(f"\n  Lean events (>14.0):  raw={lean_raw} ({100*lean_raw/raw['n']:.1f}%)  "
          f"corrected={lean_shifted} ({100*lean_shifted/len(accel_afr_shifted):.1f}%)")
    print(f"  Very lean (>16.0):   raw={very_lean_raw} ({100*very_lean_raw/raw['n']:.1f}%)  "
          f"corrected={very_lean_shifted} ({100*very_lean_shifted/len(accel_afr_shifted):.1f}%)")
    print(f"  Pegged at 20.33:     raw={sum(1 for v in accel_afr_raw if v >= 20.3)}  "
          f"corrected={sum(1 for v in accel_afr_shifted if v >= 20.3)}")


def main():
    log_path = LOGS / "4-1.csv"
    if not log_path.exists():
        print(f"Missing: {log_path}")
        sys.exit(1)

    print("Loading 4-1.csv...")
    rows = load_log(log_path)
    print(f"  {len(rows)} samples loaded")

    # Find tip-in events
    events = find_tip_in_events(rows)
    print(f"  {len(events)} tip-in events detected")

    # Cross-correlate to measure lag
    lags = cross_correlate_tipin(rows, events)

    # Estimate lag
    median_lag = estimate_lag(lags)

    if median_lag is not None:
        # Re-evaluate accel zone with lag correction
        reeval_with_lag(rows, median_lag)

        # Also try +/- 1 for sensitivity
        print(f"\n  --- Sensitivity check ---")
        for test_lag in [median_lag - 1, median_lag + 1]:
            if test_lag >= 1:
                reeval_with_lag(rows, test_lag)


if __name__ == "__main__":
    main()
