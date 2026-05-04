"""
Per-rev VE comparison.

Aggregates ve_proxy.csv across all logs in each rom_rev, finds (rpm_bin,
mrp_bin) cells with adequate sample coverage in BOTH revs, computes
mean MAF g/s delta, and reports top gains/losses.

Usage:
    python rev_comparison.py --rev-a 20.10 --rev-b 20.11
    python rev_comparison.py --rev-a 20.10 --rev-b 20.11 --min-samples 30
    python rev_comparison.py --auto             # compare each consecutive pair

VE proxy: under steady state (std RPM<50, std mrp<0.5, std TPS<1.0),
mean MAF g/s at a given (RPM, mrp) is a proxy for volumetric efficiency.
Same RPM × same MAP → should produce same airflow if pumping efficiency
unchanged. Cell-mean delta across revs at same operating point = real VE
change (good if intentional, suspicious if not).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
TRENDS_DIR = REPO_ROOT / "scripts" / "analysis" / "trends"

# Rev order for --auto. Read from rom_rev_map.csv if available else use this.
DEFAULT_REV_ORDER = ["stock", "old_2023_base", "20.7", "20.8", "20.9", "20.10", "20.11"]


def _agg_rev(ve: pd.DataFrame, rev: str) -> pd.DataFrame:
    """Aggregate VE-proxy rows for one rev: weighted mean MAF g/s per cell."""
    sub = ve[ve["rom_rev"].astype(str) == rev]
    if sub.empty:
        return sub
    sub = sub.copy()
    sub["weighted_sum"] = sub["mean_maf_gs"] * sub["sample_count"]
    g = sub.groupby(["rpm_bin", "mrp_bin"]).agg(
        samples=("sample_count", "sum"),
        weighted_sum=("weighted_sum", "sum"),
    ).reset_index()
    g["mean_maf_gs"] = g["weighted_sum"] / g["samples"]
    grp = g[["rpm_bin", "mrp_bin", "samples", "mean_maf_gs"]]
    return grp




def _agg_mc(rev: str) -> "pd.DataFrame":
    """Aggregate MAF-correction rows for one rev."""
    mc_path = TRENDS_DIR / "maf_corr_by_mafcell.csv"
    if not mc_path.exists():
        return pd.DataFrame()
    mc = pd.read_csv(mc_path)
    mc["rom_rev"] = mc["rom_rev"].astype(str)
    sub = mc[mc["rom_rev"] == rev]
    if sub.empty:
        return sub
    sub = sub.copy()
    sub["wsum"] = sub["mean_correction"] * sub["sample_count"]
    sub["wabs"] = sub["mean_correction"].abs() * sub["sample_count"]
    g = sub.groupby(["mafv_bin", "mafgs_bin"]).agg(
        samples=("sample_count", "sum"),
        wsum=("wsum", "sum"),
        wabs=("wabs", "sum"),
    ).reset_index()
    g["mean_correction"] = g["wsum"] / g["samples"]
    g["abs_correction"] = g["wabs"] / g["samples"]
    return g[["mafv_bin", "mafgs_bin", "samples", "mean_correction", "abs_correction"]]


def trim_health(rev: str, min_samples: int = 30, in_tol_pct: float = 2.0):
    """Return weighted mean |correction|, %in-tolerance, etc, for a rev."""
    a = _agg_mc(rev)
    if a is None or a.empty:
        return None
    a = a[a["samples"] >= min_samples]
    if a.empty:
        return None
    weighted_abs = float((a["abs_correction"] * a["samples"]).sum() / a["samples"].sum())
    in_tol = (a["mean_correction"].abs() < in_tol_pct).sum()
    out_tol = (a["mean_correction"].abs() >= in_tol_pct).sum()
    pct_in_tol = 100.0 * in_tol / max(in_tol + out_tol, 1)
    return dict(
        cells=int(len(a)),
        mean_abs=weighted_abs,
        median_abs=float(a["abs_correction"].median()),
        pct_in_tol=pct_in_tol,
        max_corr=float(a["mean_correction"].abs().max()),
    )


def compare(rev_a: str, rev_b: str, min_samples: int = 30,
            min_pct_delta: float = 3.0) -> dict:
    ve = pd.read_csv(TRENDS_DIR / "ve_proxy.csv")
    ve["rom_rev"] = ve["rom_rev"].astype(str)
    A = _agg_rev(ve, rev_a)
    B = _agg_rev(ve, rev_b)
    if A.empty or B.empty:
        return {"error": f"no data for {rev_a if A.empty else rev_b}"}

    J = A.merge(B, on=["rpm_bin", "mrp_bin"], suffixes=("_a", "_b"))
    J = J[(J["samples_a"] >= min_samples) & (J["samples_b"] >= min_samples)]
    if J.empty:
        return {"error": f"no overlap cells with >= {min_samples} samples in both revs"}

    J["delta_gs"] = J["mean_maf_gs_b"] - J["mean_maf_gs_a"]
    J["delta_pct"] = (J["delta_gs"] / J["mean_maf_gs_a"] * 100).round(2)
    J["mean_maf_gs_a"] = J["mean_maf_gs_a"].round(2)
    J["mean_maf_gs_b"] = J["mean_maf_gs_b"].round(2)
    J["delta_gs"] = J["delta_gs"].round(2)

    sig = J[J["delta_pct"].abs() >= min_pct_delta].sort_values("delta_pct", ascending=False)

    return {
        "rev_a": rev_a, "rev_b": rev_b,
        "n_cells_a": len(A), "n_cells_b": len(B),
        "n_overlap": len(J),
        "n_significant": len(sig),
        "top_gains": sig.head(10),
        "top_losses": sig.tail(10).iloc[::-1],
        "all_changes": sig,
    }


def format_report(r: dict) -> str:
    if "error" in r:
        return f"  {r['error']}\n"
    lines = []
    lines.append(f"## VE proxy: {r['rev_b']} vs {r['rev_a']}")
    lines.append(f"  cells with data — {r['rev_a']}: {r['n_cells_a']}, {r['rev_b']}: {r['n_cells_b']}")
    lines.append(f"  overlap (≥30 samples in each): {r['n_overlap']}")
    lines.append(f"  cells with |Δ| ≥ 3%: {r['n_significant']}")
    lines.append("")
    if len(r["top_gains"]):
        lines.append(f"  Top VE GAINS (rpm × mrp psi → MAF g/s {r['rev_a']} → {r['rev_b']}):")
        for _, row in r["top_gains"].iterrows():
            lines.append(
                f"    {int(row['rpm_bin']):>4} × {row['mrp_bin']:>+5.1f}  "
                f"{row['mean_maf_gs_a']:>6.2f} → {row['mean_maf_gs_b']:>6.2f} g/s  "
                f"({row['delta_pct']:+5.2f}%, n={int(row['samples_a'])}/{int(row['samples_b'])})"
            )
        lines.append("")
    if len(r["top_losses"]):
        lines.append(f"  Top VE LOSSES:")
        for _, row in r["top_losses"].iterrows():
            lines.append(
                f"    {int(row['rpm_bin']):>4} × {row['mrp_bin']:>+5.1f}  "
                f"{row['mean_maf_gs_a']:>6.2f} → {row['mean_maf_gs_b']:>6.2f} g/s  "
                f"({row['delta_pct']:+5.2f}%, n={int(row['samples_a'])}/{int(row['samples_b'])})"
            )
        lines.append("")
    # Trim health side-by-side
    ta = trim_health(r["rev_a"]); tb = trim_health(r["rev_b"])
    if ta and tb:
        lines.append(f"  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):")
        lines.append(f"    {r['rev_a']:>15}: cells={ta['cells']:>3}  mean|c|={ta['mean_abs']:>5.2f}%  median|c|={ta['median_abs']:>5.2f}%  in_tol={ta['pct_in_tol']:>5.1f}%  max={ta['max_corr']:>4.1f}%")
        lines.append(f"    {r['rev_b']:>15}: cells={tb['cells']:>3}  mean|c|={tb['mean_abs']:>5.2f}%  median|c|={tb['median_abs']:>5.2f}%  in_tol={tb['pct_in_tol']:>5.1f}%  max={tb['max_corr']:>4.1f}%")
        # Verdict logic
        ve_pos = (r["top_gains"]["delta_pct"] > 0).sum() > (r["top_losses"]["delta_pct"] < 0).sum() if not r["all_changes"].empty else False
        # Net direction across all sig cells:
        if not r["all_changes"].empty:
            net_gain = (r["all_changes"]["delta_pct"] > 0).sum()
            net_loss = (r["all_changes"]["delta_pct"] < 0).sum()
            ve_pos = net_gain > net_loss
        else:
            ve_pos = True
        trim_pos = ta["mean_abs"] - tb["mean_abs"] > 0  # trim got tighter
        if ve_pos and trim_pos: verdict = "WIN — VE up + trim tighter"
        elif (not ve_pos) and (not trim_pos): verdict = "LOSS — VE down + trim worse"
        elif ve_pos and not trim_pos: verdict = "MIXED — VE up but trim looser (suspect MAF over-scale)"
        else: verdict = "MIXED — VE down but trim tighter (correcting prior over-scale?)"
        lines.append(f"    verdict: {verdict}")
        lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rev-a", help="prior rom_rev (baseline)")
    ap.add_argument("--rev-b", help="newer rom_rev (compared to baseline)")
    ap.add_argument("--min-samples", type=int, default=30)
    ap.add_argument("--min-pct", type=float, default=3.0,
                    help="minimum |%% delta| to flag (default 3.0)")
    ap.add_argument("--auto", action="store_true",
                    help="compare each consecutive rev pair from rom_rev_map")
    args = ap.parse_args()

    if args.auto:
        # Determine rev order from rom_rev_map by date (skip stock, old_2023_base)
        rmap = pd.read_csv(REPO_ROOT / "logs" / "rom_rev_map.csv")
        rmap["rom_rev"] = rmap["rom_rev"].astype(str)
        rmap = rmap.sort_values("log_date")
        revs_in_order = []
        for r in rmap["rom_rev"]:
            if r not in revs_in_order:
                revs_in_order.append(r)
        for a, b in zip(revs_in_order, revs_in_order[1:]):
            r = compare(a, b, args.min_samples, args.min_pct)
            print(format_report(r))
        return

    if not (args.rev_a and args.rev_b):
        print("provide --rev-a and --rev-b, or --auto", file=sys.stderr)
        sys.exit(2)
    print(format_report(compare(args.rev_a, args.rev_b, args.min_samples, args.min_pct)))


if __name__ == "__main__":
    main()
