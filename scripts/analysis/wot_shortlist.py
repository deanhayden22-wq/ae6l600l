"""
WOT shortlist computation (SOP step 2.7).

Qualifying-pull detection + per-pull trajectory + phased summary + per-pull
markdown writeups. Imported by log_review_ingest.py; called from ingest_one().

Qualifying bar (all must hold):
  - Throttle >= 95% sustained >= 50 samples (>=2s at 25 Hz)
  - peak mrp during the Throttle-high window >= 7 psi
  (knock_during does NOT disqualify - it tags)

Pull-type tag (metadata, not qualification):
  - true_wot           = APP>=95% for >=80% of window
  - throttle_saturated = APP<95% AND Throttle=100% for >=80%
  - mixed              = neither dominant

Multi-gear pulls kept whole; shift_samples recorded. Gear ratios = RPM/MPH
(median per inter-shift segment).

Phases auto-detected:
  pre_spool       start -> first sample mrp >= 10 psi
  main_spool      pre_end -> first sample (target-mrp) < 3 psi
  target_approach main_end -> peak mrp sample
  hold_fade       peak -> Throttle-drop end
"""
from __future__ import annotations
from pathlib import Path
import numpy as np
import pandas as pd

WOT_MIN_THROTTLE = 95.0
WOT_MIN_RUN_SAMPLES = 50        # >=2s at 25 Hz
WOT_MIN_PEAK_MRP = 7.0          # psi (clears pre-spool)
WOT_TYPE_APP_HIGH = 95.0
WOT_TYPE_THR_FULL = 99.0
WOT_TYPE_DOMINANCE = 0.80
WOT_SHIFT_RPM_DROP = 300
WOT_SHIFT_WINDOW = 5            # samples (200 ms at 25 Hz)
WOT_GEAR_MIN_MPH = 5.0
WOT_PHASE_PRESPOOL_MRP = 10.0
WOT_PHASE_APPROACH_GAP = 3.0


def _detect_shifts(seg_rpm, seg_mph):
    shifts = []
    n = len(seg_rpm)
    i = 0
    while i + WOT_SHIFT_WINDOW < n:
        drop = seg_rpm[i] - seg_rpm[i + WOT_SHIFT_WINDOW]
        mph_a, mph_b = seg_mph[i], seg_mph[i + WOT_SHIFT_WINDOW]
        mph_ok = (not np.isfinite(mph_a)) or (not np.isfinite(mph_b)) or (mph_b >= mph_a - 1.0)
        if drop >= WOT_SHIFT_RPM_DROP and seg_rpm[i + WOT_SHIFT_WINDOW] > 1000 and mph_ok:
            shifts.append(i + WOT_SHIFT_WINDOW)
            i += WOT_SHIFT_WINDOW * 2
        else:
            i += 1
    return shifts


def _gear_segments(seg_rpm, seg_mph, shift_offsets):
    bounds = [0] + list(shift_offsets) + [len(seg_rpm)]
    out = []
    for i in range(len(bounds) - 1):
        a, b = bounds[i], bounds[i + 1]
        if b <= a:
            continue
        mph_seg = seg_mph[a:b]
        rpm_seg = seg_rpm[a:b]
        valid = np.isfinite(mph_seg) & (mph_seg >= WOT_GEAR_MIN_MPH) & np.isfinite(rpm_seg)
        if valid.any():
            ratio = float(np.median(rpm_seg[valid] / mph_seg[valid]))
        else:
            ratio = np.nan
        out.append((a, b, ratio))
    return out


def find_qualifying_pulls(df, samples_per_sec=25):
    """Find pulls satisfying SOP 2.7 bar. Returns list of dicts."""
    n = len(df)
    if n < samples_per_sec * 2:
        return []
    thr = df["Throttle"].to_numpy()
    in_wot = thr >= WOT_MIN_THROTTLE
    diff = np.diff(in_wot.astype(int), prepend=0, append=0)
    starts = np.where(diff == 1)[0]
    ends = np.where(diff == -1)[0]

    app = df["Accelerator"].to_numpy()
    rpm = df["RPM"].to_numpy()
    mph = df["MPH"].to_numpy() if "MPH" in df.columns else np.full(n, np.nan)
    mrp = df["mrp"].to_numpy()
    target = df["Trgt_Boost"].to_numpy() if "Trgt_Boost" in df.columns else np.full(n, np.nan)

    out = []
    for s_i, e_i in zip(starts, ends):
        if e_i - s_i < WOT_MIN_RUN_SAMPLES:
            continue
        seg_mrp = mrp[s_i:e_i]
        if not np.isfinite(seg_mrp).any():
            continue
        peak_mrp = float(np.nanmax(seg_mrp))
        if peak_mrp < WOT_MIN_PEAK_MRP:
            continue

        seg_app = app[s_i:e_i]
        seg_thr = thr[s_i:e_i]
        app_high_frac = float(np.mean(seg_app >= WOT_TYPE_APP_HIGH))
        thr_full_frac = float(np.mean(seg_thr >= WOT_TYPE_THR_FULL))
        saturated_mask = (seg_app < WOT_TYPE_APP_HIGH) & (seg_thr >= WOT_TYPE_THR_FULL)
        saturated_frac = float(np.mean(saturated_mask))
        if app_high_frac >= WOT_TYPE_DOMINANCE:
            pull_type = "true_wot"
        elif saturated_frac >= WOT_TYPE_DOMINANCE:
            pull_type = "throttle_saturated"
        else:
            pull_type = "mixed"

        seg_rpm = rpm[s_i:e_i]
        seg_mph = mph[s_i:e_i]
        shift_offsets = _detect_shifts(seg_rpm, seg_mph)
        gear_segs = _gear_segments(seg_rpm, seg_mph, shift_offsets)

        peak_off = int(np.nanargmax(seg_mrp))
        peak_idx = s_i + peak_off
        seg_target = target[s_i:e_i]
        win = e_i - s_i

        pre_end = None
        for k in range(win):
            if np.isfinite(seg_mrp[k]) and seg_mrp[k] >= WOT_PHASE_PRESPOOL_MRP:
                pre_end = k
                break
        if pre_end is None:
            pre_end = peak_off
        main_end = None
        for k in range(pre_end, win):
            if (np.isfinite(seg_target[k]) and np.isfinite(seg_mrp[k])
                    and (seg_target[k] - seg_mrp[k]) < WOT_PHASE_APPROACH_GAP):
                main_end = k
                break
        if main_end is None or main_end > peak_off:
            main_end = peak_off
        phase_bounds = {
            "pre_spool": (0, pre_end),
            "main_spool": (pre_end, main_end),
            "target_approach": (main_end, peak_off),
            "hold_fade": (peak_off, win),
        }
        out.append({
            "s_i": int(s_i), "e_i": int(e_i), "peak_idx": int(peak_idx),
            "pull_type": pull_type,
            "app_high_frac": app_high_frac,
            "thr_full_frac": thr_full_frac,
            "saturated_frac": saturated_frac,
            "shift_offsets": shift_offsets,
            "gear_segments": gear_segs,
            "phase_bounds": phase_bounds,
        })
    return out


def _pull_id(rom_rev, log_path, s_i):
    stem = Path(log_path).stem
    return f"{rom_rev}__{stem}__s{s_i}"


def _col(df, name, n):
    return df[name].to_numpy() if name in df.columns else np.full(n, np.nan)


def compute_shortlist(df, log_date, rom_rev, log_path, samples_per_sec=25):
    pulls = find_qualifying_pulls(df, samples_per_sec)
    if not pulls:
        return pd.DataFrame()
    n = len(df)
    t = df["time"].to_numpy()
    rpm = df["RPM"].to_numpy()
    mrp = df["mrp"].to_numpy()
    target = _col(df, "Trgt_Boost", n)
    wgdc = _col(df, "wgdc", n)
    tdp = _col(df, "Tdp", n)
    tdi = _col(df, "tdi", n)
    avcs = _col(df, "avcs", n)
    timing = _col(df, "Timing", n)
    wbo2 = _col(df, "wbo2", n)
    ffb = _col(df, "FFB", n)
    fbkc = _col(df, "FBKC", n)
    flkc = _col(df, "FLKC", n)
    flkc_prev = np.concatenate([[np.nan], flkc[:-1]])
    flkc_decr_mask = (flkc < flkc_prev) & np.isfinite(flkc) & np.isfinite(flkc_prev)

    def _nan_or(arr, fn):
        return float(fn(arr)) if np.isfinite(arr).any() else np.nan

    def _phase_dur(seg_t, a, b):
        a = max(0, min(a, len(seg_t) - 1))
        b = max(0, min(b, len(seg_t) - 1))
        if b <= a:
            return 0.0
        return float(seg_t[b] - seg_t[a])

    rows = []
    for p in pulls:
        s_i, e_i, peak_idx = p["s_i"], p["e_i"], p["peak_idx"]
        seg_t = t[s_i:e_i]
        pid = _pull_id(rom_rev, log_path, s_i)
        ph = p["phase_bounds"]
        appr_a, appr_b = ph["target_approach"]
        hold_a, hold_b = ph["hold_fade"]
        seg_wgdc = wgdc[s_i:e_i]
        seg_mrp = mrp[s_i:e_i]
        seg_target = target[s_i:e_i]
        appr_slice = seg_wgdc[appr_a:appr_b] if appr_b > appr_a else np.array([])
        if appr_slice.size and np.isfinite(appr_slice).any():
            slam = float(np.nanmax(appr_slice) - np.nanmin(appr_slice))
        else:
            slam = np.nan
        peak_mrp = float(seg_mrp[peak_idx - s_i])
        tap = float(seg_target[peak_idx - s_i]) if np.isfinite(seg_target[peak_idx - s_i]) else np.nan
        attainment = (peak_mrp / tap) if (np.isfinite(tap) and tap > 0) else np.nan
        under = (tap - peak_mrp) if np.isfinite(tap) else np.nan
        seg_wbo2 = wbo2[s_i:e_i]
        seg_ffb = ffb[s_i:e_i]
        if seg_wbo2.size > 8:
            wbo2_lead = np.concatenate([seg_wbo2[8:], np.full(8, np.nan)])
            delta_series = wbo2_lead - seg_ffb
            mean_afr_delta = float(np.nanmean(delta_series)) if np.isfinite(delta_series).any() else np.nan
        else:
            mean_afr_delta = np.nan

        gear_parts = []
        shifts = p["shift_offsets"]
        for idx, (a, b, r) in enumerate(p["gear_segments"]):
            label = f"r={r:.1f}" if np.isfinite(r) else "r=nan"
            gear_parts.append(label)
            if idx < len(shifts):
                gear_parts.append(f"s@{shifts[idx]}")
        gear_ratios_str = ",".join(g[2:] for g in gear_parts if g.startswith("r="))
        gear_path_str = ",".join(gear_parts)
        shift_offsets_str = ",".join(str(x) for x in shifts)

        rows.append({
            "log_date": log_date, "rom_rev": rom_rev, "log_path": log_path,
            "pull_id": pid,
            "start_sample": s_i, "end_sample": e_i,
            "pull_type": p["pull_type"],
            "gear_path": gear_path_str,
            "gear_ratios": gear_ratios_str,
            "shift_offsets": shift_offsets_str,
            "duration_s": float(seg_t[-1] - seg_t[0]) if len(seg_t) > 1 else 0.0,
            "start_RPM": float(rpm[s_i]),
            "peak_RPM": float(np.nanmax(rpm[s_i:e_i])),
            "RPM_span": float(np.nanmax(rpm[s_i:e_i]) - rpm[s_i]),
            "pre_spool_duration_s": _phase_dur(seg_t, *ph["pre_spool"]),
            "main_spool_duration_s": _phase_dur(seg_t, *ph["main_spool"]),
            "target_approach_duration_s": _phase_dur(seg_t, *ph["target_approach"]),
            "hold_fade_duration_s": _phase_dur(seg_t, *ph["hold_fade"]),
            "entry_mrp": float(mrp[s_i]),
            "peak_mrp": peak_mrp,
            "target_mrp_at_peak": tap,
            "attainment_pct": attainment,
            "peak_under_target_psi": under,
            "slam_magnitude_wgdc": slam,
            "min_Tdp": _nan_or(tdp[s_i:e_i], np.nanmin),
            "max_Tdp": _nan_or(tdp[s_i:e_i], np.nanmax),
            "max_tdi": _nan_or(tdi[s_i:e_i], np.nanmax),
            "peak_wgdc": _nan_or(seg_wgdc, np.nanmax),
            "hold_wgdc_median": (float(np.nanmedian(seg_wgdc[hold_a:hold_b]))
                                 if hold_b > hold_a and np.isfinite(seg_wgdc[hold_a:hold_b]).any()
                                 else np.nan),
            "avcs_at_pull_start": float(avcs[s_i]) if np.isfinite(avcs[s_i]) else np.nan,
            "avcs_at_peak": float(avcs[peak_idx]) if np.isfinite(avcs[peak_idx]) else np.nan,
            "avcs_at_lift": float(avcs[e_i - 1]) if np.isfinite(avcs[e_i - 1]) else np.nan,
            "timing_at_peak": float(timing[peak_idx]) if np.isfinite(timing[peak_idx]) else np.nan,
            "mean_wbo2": _nan_or(wbo2[s_i:e_i], np.nanmean),
            "mean_AFR_delta": mean_afr_delta,
            "min_FBKC": _nan_or(fbkc[s_i:e_i], np.nanmin),
            "flkc_decrements": int(np.sum(flkc_decr_mask[s_i:e_i])),
            "knock_during": int(np.any(fbkc[s_i:e_i] < 0) or np.any(flkc_decr_mask[s_i:e_i])),
            "app_high_frac": p["app_high_frac"],
            "thr_full_frac": p["thr_full_frac"],
            "saturated_frac": p["saturated_frac"],
            "writeup_path": f"logs/wot_pulls/{pid}.md",
        })
    return pd.DataFrame(rows)


def compute_trajectories(df, log_date, rom_rev, log_path, samples_per_sec=25):
    pulls = find_qualifying_pulls(df, samples_per_sec)
    if not pulls:
        return pd.DataFrame()
    n = len(df)
    t = df["time"].to_numpy()
    rpm = df["RPM"].to_numpy()
    mph = _col(df, "MPH", n)
    app = df["Accelerator"].to_numpy()
    thr = df["Throttle"].to_numpy()
    mrp = df["mrp"].to_numpy()
    target = _col(df, "Trgt_Boost", n)
    wgdc = _col(df, "wgdc", n)
    tdp = _col(df, "Tdp", n)
    tdi = _col(df, "tdi", n)
    avcs = _col(df, "avcs", n)
    timing = _col(df, "Timing", n)
    ffb = _col(df, "FFB", n)
    wbo2 = _col(df, "wbo2", n)
    maf = _col(df, "MAF", n)
    fbkc = _col(df, "FBKC", n)
    flkc = _col(df, "FLKC", n)
    iam = _col(df, "IAM", n)

    rows = []
    for p in pulls:
        s_i, e_i = p["s_i"], p["e_i"]
        end = e_i + min(5, n - e_i)
        pid = _pull_id(rom_rev, log_path, s_i)
        for ai in range(s_i, end):
            mph_v = mph[ai] if np.isfinite(mph[ai]) else np.nan
            gear_ratio = (rpm[ai] / mph_v) if (np.isfinite(mph_v) and mph_v >= WOT_GEAR_MIN_MPH) else np.nan
            def f(arr):
                v = arr[ai]
                return float(v) if np.isfinite(v) else np.nan
            rows.append({
                "log_date": log_date, "rom_rev": rom_rev, "log_path": log_path,
                "pull_id": pid,
                "sample_offset": ai - s_i,
                "abs_sample": ai,
                "time": f(t), "RPM": f(rpm), "MPH": float(mph_v) if np.isfinite(mph_v) else np.nan,
                "gear_ratio": float(gear_ratio) if np.isfinite(gear_ratio) else np.nan,
                "APP": f(app), "Throttle": f(thr),
                "mrp": f(mrp), "Trgt_Boost": f(target),
                "wgdc": f(wgdc), "Tdp": f(tdp), "tdi": f(tdi),
                "avcs": f(avcs), "Timing": f(timing),
                "FFB": f(ffb), "wbo2": f(wbo2), "MAF": f(maf),
                "FBKC": f(fbkc), "FLKC": f(flkc), "IAM": f(iam),
            })
    return pd.DataFrame(rows)


def write_writeups(df, log_date, rom_rev, log_path, samples_per_sec=25, out_dir=None):
    pulls = find_qualifying_pulls(df, samples_per_sec)
    if not pulls:
        return 0
    if out_dir is None:
        from pathlib import Path as _P
        out_dir = _P(__file__).resolve().parents[2] / "logs" / "wot_pulls"
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    n = len(df)
    t = df["time"].to_numpy()
    rpm = df["RPM"].to_numpy()
    mrp = df["mrp"].to_numpy()
    target = _col(df, "Trgt_Boost", n)
    wgdc = _col(df, "wgdc", n)
    tdp = _col(df, "Tdp", n)
    tdi = _col(df, "tdi", n)
    avcs = _col(df, "avcs", n)
    fbkc = _col(df, "FBKC", n)
    flkc = _col(df, "FLKC", n)
    flkc_prev = np.concatenate([[np.nan], flkc[:-1]])
    flkc_decr_mask = (flkc < flkc_prev) & np.isfinite(flkc) & np.isfinite(flkc_prev)

    def _fmt(arr, idx, prec=2):
        if 0 <= idx < len(arr) and np.isfinite(arr[idx]):
            return f"{arr[idx]:.{prec}f}"
        return "nan"

    count = 0
    for p in pulls:
        s_i, e_i, peak_idx = p["s_i"], p["e_i"], p["peak_idx"]
        pid = _pull_id(rom_rev, log_path, s_i)
        ph = p["phase_bounds"]
        seg_dur = float(t[e_i - 1] - t[s_i]) if e_i > s_i else 0.0

        def phase_row(name, a, b):
            if b <= a:
                return f"| {name} | - | - | - | - | - | - |"
            ka, kb = s_i + a, s_i + b - 1
            return (
                f"| {name} | s{ka}-s{kb} | {(t[kb] - t[ka]):.2f}s "
                f"| {_fmt(rpm, ka, 0)}->{_fmt(rpm, kb, 0)} "
                f"| {_fmt(mrp, ka)}->{_fmt(mrp, kb)} "
                f"| {_fmt(target, ka)}->{_fmt(target, kb)} "
                f"| {_fmt(wgdc, ka, 1)}->{_fmt(wgdc, kb, 1)} |"
            )

        peak_mrp = float(mrp[peak_idx])
        peak_target = float(target[peak_idx]) if np.isfinite(target[peak_idx]) else float("nan")
        attainment = (peak_mrp / peak_target) if (np.isfinite(peak_target) and peak_target > 0) else float("nan")
        under = (peak_target - peak_mrp) if np.isfinite(peak_target) else float("nan")

        appr_a, appr_b = ph["target_approach"]
        if appr_b > appr_a:
            wgdc_seg = wgdc[s_i + appr_a:s_i + appr_b]
            tdp_seg = tdp[s_i + appr_a:s_i + appr_b]
            tdi_seg = tdi[s_i + appr_a:s_i + appr_b]
            slam = float(np.nanmax(wgdc_seg) - np.nanmin(wgdc_seg)) if np.isfinite(wgdc_seg).any() else float("nan")
            tdp_swing = float(np.nanmax(tdp_seg) - np.nanmin(tdp_seg)) if np.isfinite(tdp_seg).any() else float("nan")
            tdi_swing = float(np.nanmax(tdi_seg) - np.nanmin(tdi_seg)) if np.isfinite(tdi_seg).any() else float("nan")
        else:
            slam = tdp_swing = tdi_swing = float("nan")

        knock_in = bool(np.any(fbkc[s_i:e_i] < 0) or np.any(flkc_decr_mask[s_i:e_i]))
        min_fbkc = float(np.nanmin(fbkc[s_i:e_i])) if np.isfinite(fbkc[s_i:e_i]).any() else float("nan")
        flkc_count = int(np.sum(flkc_decr_mask[s_i:e_i]))

        gear_lines = []
        shifts = p["shift_offsets"]
        for idx, (a, b, r) in enumerate(p["gear_segments"]):
            label = f"r={r:.1f}" if np.isfinite(r) else "r=nan"
            gear_lines.append(f"  - segment offsets {a}-{b}: median RPM/MPH = {label}")
        shift_line = ", ".join(f"s+{sh}" for sh in shifts) if shifts else "none"

        lines = [
            f"# WOT pull - {pid}",
            "",
            "*Auto-generated by scripts/analysis/log_review_ingest.py (SOP 2.7).*",
            "*Not memory-promoted. Designate as a canonical anchor manually if it merits one.*",
            "",
            f"**Source:** `{log_path}` samples {s_i}-{e_i - 1} ({e_i - s_i} samples, {seg_dur:.2f} s)",
            f"**Rev:** {rom_rev}  **Date:** {log_date}",
            f"**Pull type:** {p['pull_type']}  (APP>={WOT_TYPE_APP_HIGH:.0f}% frac={p['app_high_frac']:.2f}, "
            f"Thr>={WOT_TYPE_THR_FULL:.0f}% frac={p['thr_full_frac']:.2f}, "
            f"saturated frac={p['saturated_frac']:.2f})",
            "",
            "## Gear path",
            *gear_lines,
            f"  - shifts at offset: {shift_line}",
            "",
            "## Phases",
            "",
            "| phase | samples | duration | RPM | mrp | target | wgdc |",
            "| ----- | ------- | -------- | --- | --- | ------ | ---- |",
            phase_row("pre_spool",        *ph["pre_spool"]),
            phase_row("main_spool",       *ph["main_spool"]),
            phase_row("target_approach",  *ph["target_approach"]),
            phase_row("hold_fade",        *ph["hold_fade"]),
            "",
            "## Key facts",
            "",
            f"- Peak mrp = **{peak_mrp:.2f}** psi at s{peak_idx} (RPM {_fmt(rpm, peak_idx, 0)}) "
            f"vs target {peak_target:.2f} psi -> attainment {attainment*100:.1f}%, "
            f"under by {under:+.2f} psi",
            f"- Target-approach slam: wgdc swing **{slam:.1f}%**, "
            f"Tdp swing {tdp_swing:.2f}%, tdi swing {tdi_swing:.2f}%",
            f"- AVCS: start {_fmt(avcs, s_i, 1)} -> peak {_fmt(avcs, peak_idx, 1)} -> lift {_fmt(avcs, e_i - 1, 1)} deg",
            f"- Knock during pull: **{knock_in}** (min FBKC {min_fbkc:+.2f}, FLKC decrements {flkc_count})",
            "",
        ]
        out_path = out_dir / f"{pid}.md"
        out_path.write_text("\n".join(lines), encoding="utf-8")
        count += 1
    return count
