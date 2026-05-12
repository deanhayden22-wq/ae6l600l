#!/usr/bin/env python3
"""
Regeneratable scorecard dashboard.

Reads the live trends store and emits a self-contained HTML file with:
- Top: KPI cards for the active rev (auto-detected as last rev in REV_ORDER
  present in scorecard.csv)
- Per-rev metric trends (line chart)
- Active-rev cluster signal-set distribution (bar chart)
- Active-rev RPM × dominant-signal stacked bar
- Table of every 20.11 AVCS-led cluster with location

Re-run anytime to refresh against current trends data.

Usage:
    python3 scripts/analysis/dashboard.py
    python3 scripts/analysis/dashboard.py --rev 20.10
    python3 scripts/analysis/dashboard.py --out /path/to/dashboard.html
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
TRENDS_DIR = REPO_ROOT / "scripts" / "analysis" / "trends"
DEFAULT_OUT = REPO_ROOT / "scorecard_dashboard.html"

REV_ORDER = ["old_2023_base", "stock", "20.7", "20.8", "20.9", "20.10", "20.11", "20.12"]


def trend_series(sc: pd.DataFrame, thread: str, metric: str, revs: list[str]) -> list:
    out = []
    for r in revs:
        m = sc[(sc["thread"] == thread) & (sc["metric"] == metric) & (sc["rom_rev"] == r)]
        out.append(round(float(m["value"].iloc[0]), 3) if len(m) else None)
    return out


def latest_metric(sc: pd.DataFrame, rev: str, thread: str, metric: str) -> tuple[float, float, float]:
    m = sc[(sc["rom_rev"] == rev) & (sc["thread"] == thread) & (sc["metric"] == metric)]
    if not len(m):
        return (float("nan"),) * 3
    return (
        float(m["value"].iloc[0]),
        float(m["delta_vs_baseline"].iloc[0]) if pd.notna(m["delta_vs_baseline"].iloc[0]) else float("nan"),
        float(m["delta_vs_prior"].iloc[0]) if pd.notna(m["delta_vs_prior"].iloc[0]) else float("nan"),
    )


def build_data(rev: str) -> dict:
    sc = pd.read_csv(TRENDS_DIR / "scorecard_latest.csv", dtype={"rom_rev": str})
    revs = [r for r in REV_ORDER if r in sc["rom_rev"].values]

    # ---- KPI cards (active rev value + Δ vs prior)
    kpi_specs = [
        ("Stutter signature / min", "cross_thread", "stutter_signature_per_min", "lower_is_better"),
        ("Total knock / min", "timing_sum", "total_knock_per_min", "lower_is_better"),
        ("MAF trim |mean| %", "ol_fueling", "maf_corr_mean_abs_pct", "lower_is_better"),
        ("Min FBKC depth (°)", "timing_sum", "min_fbkc_depth", "higher_is_better"),
    ]
    kpis = []
    for label, t, m, dir_ in kpi_specs:
        v, _, dprior = latest_metric(sc, rev, t, m)
        kpis.append({"label": label, "value": v, "delta_prior": dprior, "dir": dir_})

    # ---- Trend chart
    trend_metrics = [
        ("stutter signature", "#534AB7", None, "cross_thread", "stutter_signature_per_min"),
        ("throttle hunt",     "#185FA5", [4, 3], "pedal_throttle", "throttle_hunt_per_min"),
        ("AVCS osc",          "#0F6E56", None, "avcs", "avcs_osc_per_min"),
        ("total knock",       "#BA7517", [4, 3], "timing_sum", "total_knock_per_min"),
        ("AFR osc",           "#D85A30", None, "ol_fueling", "afr_osc_per_min"),
        ("FFB-wbo2 div",      "#D4537E", [2, 2], "ol_fueling", "ffb_wbo2_div_per_min"),
    ]
    trends = []
    for label, color, dash, thr, met in trend_metrics:
        trends.append({
            "label": label, "color": color, "dash": dash or [],
            "data": trend_series(sc, thr, met, revs),
        })

    # ---- Stutter clusters for active rev
    cl = pd.read_csv(TRENDS_DIR / "stutter_clusters.csv", dtype={"rom_rev": str})
    active = cl[cl["rom_rev"] == rev].copy()
    n_clusters = len(active)

    sigset_counts = active["signal_set"].value_counts().head(6)
    # Pretty-label signal sets
    def _pretty(s: str) -> str:
        return (s.replace("ffb_wbo2_divergence", "FFB-wbo2")
                  .replace("avcs_oscillation", "AVCS")
                  .replace("rpm_swing_steady_tps", "RPM-swing")
                  .replace("throttle_hunt_at_steady_app", "throttle-hunt")
                  .replace("timing_osc", "timing osc")
                  .replace("afr_osc", "AFR osc")
                  .replace("+", " + "))
    sigset_data = [{"label": _pretty(s), "n": int(n)} for s, n in sigset_counts.items()]

    # ---- RPM band × dominant signal
    rpm_bins = [0, 1500, 2000, 2500, 3000, 3500, 4000, 8000]
    rpm_labels = ["<1500", "1500-2000", "2000-2500", "2500-3000", "3000-3500", "3500-4000", "4000+"]
    if n_clusters:
        active["rpm_band"] = pd.cut(active["rpm_mean"], bins=rpm_bins, labels=rpm_labels)
        rpm_x = active.groupby(["rpm_band", "dominant_signal"], observed=True).size().unstack(fill_value=0)
    else:
        rpm_x = pd.DataFrame()
    SIG_COLORS = {
        "ffb_wbo2_divergence": "#D4537E",
        "avcs_oscillation": "#0F6E56",
        "afr_osc": "#D85A30",
        "timing_osc": "#BA7517",
        "throttle_hunt_at_steady_app": "#185FA5",
        "rpm_swing_steady_tps": "#534AB7",
    }
    rpm_stack = []
    if len(rpm_x):
        for sig in rpm_x.columns:
            data = [int(rpm_x.loc[b, sig]) if b in rpm_x.index else 0 for b in rpm_labels if b in rpm_x.index]
            full = [int(rpm_x.loc[b, sig]) if (b in rpm_x.index) else 0 for b in rpm_labels]
            rpm_stack.append({
                "label": _pretty(sig),
                "color": SIG_COLORS.get(sig, "#888"),
                "data": full,
            })

    # ---- AVCS-led cluster table for active rev
    avcs_led = active[active["signal_set"].str.contains("avcs_oscillation", na=False)].copy()
    avcs_led = avcs_led.sort_values("rpm_mean")
    avcs_rows = []
    for _, r in avcs_led.iterrows():
        avcs_rows.append({
            "log": Path(r["log_path"]).name,
            "t": round(float(r["start_time"]), 1),
            "n": int(r["n_events"]),
            "rpm": int(round(r["rpm_mean"])),
            "load": round(float(r["load_mean"]), 2),
            "app": round(float(r["app_mean"]), 1),
            "sigs": _pretty(r["signal_set"]),
        })

    return {
        "rev": rev,
        "revs": revs,
        "kpis": kpis,
        "trends": trends,
        "n_clusters": n_clusters,
        "n_avcs_clusters": len(avcs_led),
        "sigset_data": sigset_data,
        "rpm_labels": rpm_labels,
        "rpm_stack": rpm_stack,
        "avcs_rows": avcs_rows,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AE5L600L scorecard – rev __REV__</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; max-width: 1100px; margin: 2rem auto; padding: 0 1.5rem; color: #222; background: #fafaf8; }
  h1 { font-size: 22px; font-weight: 500; margin: 0 0 0.25rem; }
  .meta { color: #666; font-size: 13px; margin-bottom: 1.5rem; }
  .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 1.5rem; }
  .kpi { background: #fff; border-radius: 8px; padding: 1rem; border: 0.5px solid #ddd; }
  .kpi-label { font-size: 13px; color: #666; margin-bottom: 4px; }
  .kpi-value { font-size: 24px; font-weight: 500; }
  .kpi-delta { font-size: 12px; margin-top: 4px; }
  .kpi-delta.bad { color: #A32D2D; }
  .kpi-delta.good { color: #3B6D11; }
  .kpi-delta.neutral { color: #666; }
  .panel { background: #fff; border-radius: 12px; padding: 1.25rem; margin-bottom: 1rem; border: 0.5px solid #ddd; }
  .panel-title { font-size: 14px; color: #666; margin: 0 0 8px; }
  .legend { display: flex; flex-wrap: wrap; gap: 14px; margin-bottom: 8px; font-size: 12px; color: #666; }
  .legend span { display: flex; align-items: center; gap: 4px; }
  .legend-swatch { width: 10px; height: 10px; border-radius: 2px; display: inline-block; }
  .chart-wrap { position: relative; height: 280px; }
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th { text-align: left; font-weight: 500; border-bottom: 1px solid #ddd; padding: 4px 6px; color: #666; }
  td { padding: 3px 6px; border-bottom: 0.5px solid #eee; }
  .footer { color: #888; font-size: 12px; margin-top: 1.5rem; text-align: right; }
</style>
</head>
<body>
<h1>AE5L600L tuning scorecard — active rev __REV__</h1>
<div class="meta">Generated __TS__ — re-run <code>python3 scripts/analysis/dashboard.py</code> to refresh</div>

<div class="kpi-grid" id="kpis"></div>

<div class="panel">
  <div class="panel-title">Per-rev metric trends (events/min)</div>
  <div class="legend" id="trend-legend"></div>
  <div class="chart-wrap"><canvas id="trendChart"></canvas></div>
</div>

<div class="two-col">
  <div class="panel">
    <div class="panel-title">Active-rev cluster signal-sets (<span id="n-clusters"></span> clusters)</div>
    <div class="chart-wrap"><canvas id="sigsetChart"></canvas></div>
  </div>
  <div class="panel">
    <div class="panel-title">RPM band × dominant signal</div>
    <div class="chart-wrap"><canvas id="rpmStackChart"></canvas></div>
  </div>
</div>

<div class="panel">
  <div class="panel-title">AVCS-led clusters (n=<span id="n-avcs"></span>) — sorted by RPM</div>
  <table id="avcs-table"><thead><tr>
    <th>log</th><th>t (s)</th><th>n</th><th>RPM</th><th>load</th><th>APP %</th><th>signals</th>
  </tr></thead><tbody></tbody></table>
</div>

<div class="footer">scorecard data: <code>scripts/analysis/trends/scorecard_latest.csv</code> · clusters: <code>scripts/analysis/trends/stutter_clusters.csv</code></div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<script>
const DATA = __DATA__;

function renderKPIs() {
  const el = document.getElementById('kpis');
  for (const k of DATA.kpis) {
    const dprior = k.delta_prior;
    let cls = 'neutral', arrow = '';
    if (!isNaN(dprior) && dprior !== null) {
      const improving = (k.dir === 'lower_is_better') ? (dprior < 0) : (dprior > 0);
      cls = improving ? 'good' : (dprior === 0 ? 'neutral' : 'bad');
      arrow = dprior > 0 ? '↑' : (dprior < 0 ? '↓' : '·');
    }
    const dstr = isNaN(dprior) || dprior === null ? '—' : `${arrow} ${dprior >= 0 ? '+' : ''}${dprior.toFixed(2)} vs prior`;
    el.insertAdjacentHTML('beforeend', `
      <div class="kpi">
        <div class="kpi-label">${k.label}</div>
        <div class="kpi-value">${k.value !== null && !isNaN(k.value) ? k.value.toFixed(2) : '—'}</div>
        <div class="kpi-delta ${cls}">${dstr}</div>
      </div>`);
  }
}

function renderTrendChart() {
  const el = document.getElementById('trend-legend');
  for (const t of DATA.trends) {
    el.insertAdjacentHTML('beforeend',
      `<span><span class="legend-swatch" style="background:${t.color}"></span>${t.label}</span>`);
  }
  new Chart(document.getElementById('trendChart'), {
    type: 'line',
    data: {
      labels: DATA.revs,
      datasets: DATA.trends.map(t => ({
        label: t.label, data: t.data,
        borderColor: t.color, backgroundColor: t.color,
        borderWidth: 1.5, borderDash: t.dash || [],
        pointRadius: 3, pointHoverRadius: 5, tension: 0.2,
      })),
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false }, tooltip: { mode: 'index', intersect: false } },
      scales: {
        y: { beginAtZero: true, grid: { color: 'rgba(0,0,0,0.08)' } },
        x: { grid: { display: false } },
      },
    },
  });
}

function renderSigsetChart() {
  document.getElementById('n-clusters').textContent = DATA.n_clusters;
  const labels = DATA.sigset_data.map(d => d.label);
  const data = DATA.sigset_data.map(d => d.n);
  const palette = ['#D85A30','#534AB7','#BA7517','#0F6E56','#185FA5','#D4537E'];
  new Chart(document.getElementById('sigsetChart'), {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{ data: data, backgroundColor: palette.slice(0, data.length), borderWidth: 0 }],
    },
    options: {
      indexAxis: 'y',
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { beginAtZero: true, grid: { color: 'rgba(0,0,0,0.08)' }, ticks: { precision: 0 } },
        y: { grid: { display: false }, ticks: { font: { size: 10 } } },
      },
    },
  });
}

function renderRpmStackChart() {
  new Chart(document.getElementById('rpmStackChart'), {
    type: 'bar',
    data: {
      labels: DATA.rpm_labels,
      datasets: DATA.rpm_stack.map(s => ({
        label: s.label, data: s.data, backgroundColor: s.color, borderWidth: 0,
      })),
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: true, position: 'bottom',
        labels: { boxWidth: 10, boxHeight: 10, font: { size: 10 }, padding: 6 } } },
      scales: {
        x: { stacked: true, grid: { display: false } },
        y: { stacked: true, beginAtZero: true, grid: { color: 'rgba(0,0,0,0.08)' }, ticks: { precision: 0 } },
      },
    },
  });
}

function renderAvcsTable() {
  document.getElementById('n-avcs').textContent = DATA.n_avcs_clusters;
  const tb = document.querySelector('#avcs-table tbody');
  for (const r of DATA.avcs_rows) {
    tb.insertAdjacentHTML('beforeend', `<tr>
      <td>${r.log}</td><td>${r.t}</td><td>${r.n}</td>
      <td>${r.rpm}</td><td>${r.load}</td><td>${r.app}</td>
      <td>${r.sigs}</td></tr>`);
  }
}

renderKPIs();
renderTrendChart();
renderSigsetChart();
renderRpmStackChart();
renderAvcsTable();
</script>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rev", help="active rev (default: latest in REV_ORDER present in scorecard)")
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args()

    sc = pd.read_csv(TRENDS_DIR / "scorecard_latest.csv", dtype={"rom_rev": str})
    revs_present = [r for r in REV_ORDER if r in sc["rom_rev"].values]
    active = args.rev or (revs_present[-1] if revs_present else None)
    if not active:
        raise SystemExit("no revs found in scorecard")

    data = build_data(active)
    html = (HTML_TEMPLATE
            .replace("__REV__", active)
            .replace("__TS__", data["generated_at"])
            .replace("__DATA__", json.dumps(data)))
    out = Path(args.out)
    out.write_text(html)
    print(f"Wrote {out}")
    print(f"  active rev: {active}")
    print(f"  clusters: {data['n_clusters']} ({data['n_avcs_clusters']} AVCS-led)")


if __name__ == "__main__":
    main()
