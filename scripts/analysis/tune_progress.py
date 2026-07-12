#!/usr/bin/env python3
"""
Issue-centric tune progress report -> tune_progress.html (repo root).

Why this exists (2026-07-12): the scorecard dashboard is rev-grain — it
averages a 502-min highway log with an 8-min errand and can't show whether
the thing a rev was flashed to fix actually moved. This report is per-LOG
grain, chronological, with rev-flash boundaries and the PCV-fix fueling-era
boundary drawn on every chart, points sized/hidden by exposure, and an
issue ledger on top (status curated per REVIEW_LOG; numbers pulled live).

Reads:  trends/log_health.csv, trends/zone_fire_rates.csv,
        trends/tipin_per_log.csv
Writes: <repo_root>/tune_progress.html   (Chart.js CDN, same as dashboard)

Usage:  python3 scripts/analysis/tune_progress.py
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

SCRIPT_DIR = Path(__file__).resolve().parent
TRENDS = SCRIPT_DIR / "trends"
REPO_ROOT = SCRIPT_DIR.parents[1]
OUT = REPO_ROOT / "tune_progress.html"

PCV_BOUNDARY = "2026-06-21"       # first clean-PCV log (fueling era break)
MIN_ZONE_RES_MIN = 0.5            # hide zone rates below this exposure


def load():
    lh = pd.read_csv(TRENDS / "log_health.csv")
    lh = lh.sort_values(["log_date", "log_path"]).reset_index(drop=True)
    z = pd.read_csv(TRENDS / "zone_fire_rates.csv")
    tip = pd.read_csv(TRENDS / "tipin_per_log.csv")
    tip["log_path"] = "logs/" + tip["log"].astype(str)
    return lh, z, tip


def build_series(lh, z, tip):
    order = lh["log_path"].tolist()
    labels = [[d[5:], r] for d, r in zip(lh["log_date"], lh["rom_rev"])]

    def zone_rate(zone, col):
        m = z[z["zone"] == zone].set_index("log_path")
        out = []
        for p in order:
            if p in m.index:
                row = m.loc[p]
                v = row[col] if row["residency_min"] >= MIN_ZONE_RES_MIN else None
                out.append(None if v is None or pd.isna(v) else round(float(v), 2))
            else:
                out.append(None)
        return out

    hrs = lh["duration_min"] / 60.0

    def per_hr(col):
        return [round(float(v), 2) if pd.notna(v) else None
                for v in (lh[col] / hrs)]

    tipm = tip.set_index("log_path")
    tip_lean, tip_follow = [], []
    for p in order:
        if p in tipm.index and tipm.loc[p, "n"] >= 20:
            tip_lean.append(round(float(tipm.loc[p, "med_lean"]), 2))
            rm = float(tipm.loc[p, "ramp_min"])
            tip_follow.append(round(float(tipm.loc[p, "fbkc_follow"]) / rm, 2) if rm > 0.2 else None)
        else:
            tip_lean.append(None)
            tip_follow.append(None)

    # show IDC whenever injectors actually worked (idc_max >= 40), not only
    # on sustained-boost logs -- the 7-12 114.9% peak was a 0.4 s stab.
    worked = lh["idc_max"] >= 40
    idc_max = [round(float(v), 1) if b and pd.notna(v) else None
               for v, b in zip(lh["idc_max"], worked)]
    idc_p99 = [round(float(v), 1) if b and pd.notna(v) else None
               for v, b in zip(lh["idc_p99"], worked)]

    def col(name, r=2):
        return [round(float(v), r) if pd.notna(v) else None for v in lh[name]]

    # boundaries: index where rom_rev changes vs previous log
    rev_bounds = [i for i in range(1, len(lh))
                  if lh["rom_rev"][i] != lh["rom_rev"][i - 1]]
    pcv_idx = int(lh.index[lh["log_date"] >= PCV_BOUNDARY][0]) if (lh["log_date"] >= PCV_BOUNDARY).any() else None

    return dict(
        labels=labels, rev_bounds=rev_bounds, pcv_idx=pcv_idx,
        cusp=zone_rate("cusp", "fires_per_min"),
        rect=zone_rate("rect", "fires_per_min"),
        iat=col("iat_med", 0),
        deep_resume_hr=per_hr("fbkc_deep_resume"),
        deep_other_hr=[round(a - b, 2) if a is not None and b is not None else None
                       for a, b in zip(per_hr("fbkc_deep"), per_hr("fbkc_deep_resume"))],
        flkc_dec_hr=per_hr("flkc_decrements"),
        flkc_min=col("flkc_min"),
        trim=col("total_trim_cruise_med"),
        afl_med=col("afl_med"),
        afl_end=col("afl_end"),
        idc_max=idc_max, idc_p99=idc_p99,
        tip_lean=tip_lean, tip_follow=tip_follow,
        dur=col("duration_min", 1),
    )


LEDGER = [
    # (issue, status, css, now, next lever)
    ("DFCO-resume deep knock (wall-wetting)", "ACTIVE", "active",
     "{resume_share} of deep (≤−3°) events corpus-wide fire ≤5 s after DFCO exit; 7-12: 8/12",
     "Warm rising-tau restore (0xCD6E6 ECT 80–110 cols) — single-var rev, flash BEFORE 20.19"),
    ("Cruise-band fueling error (~2% over-read)", "ACTIVE", "active",
     "Total trim (AFC+AFL) steady CL cruise: {trim_now} — flat since 6-7 despite AFL moving",
     "WB-driven region refit at pre-injector-swap MAF baseline; do NOT cell-patch"),
    ("Injector ceiling", "HW-BLOCKED", "blocked",
     "IDC {idc_now}% peak @ 6052 RPM / 18.7 psi (7-12); mixture held, margin zero",
     "Injector swap decision gates all top-end work incl. the missing redline pull"),
    ("5th-gear rect / steady cusp knock", "CONTAINED — WATCH", "watch",
     "~2% tip-over, FBKC+FLKC handling it (IAM 1.0 throughout); hot+AC day = +73% fires/min",
     "No clean gated fix exists; optional ~1° at low-load ignition cells; re-score after tau rev"),
    ("AFL drift toward rich", "RECOVERING", "watch",
     "med −1.56, end-of-day 0.0 on 7-12 (was −6.25 in leak era) — redistribution, see fueling error",
     "Watch next log; folds into MAF refit"),
    ("Idle-band MAF (1.18–1.30 V)", "WATCH", "watch",
     "+3.4% on 7-12 (was +0.78 on 6-21) — AC compressor confound, not actionable",
     "Re-read on a mild no-AC day before touching anything"),
    ("3.2–3.6 V over-read", "WATCH", "watch",
     "−5.2% (n=520, 7-12) — possible overshoot of 20.18's +10% boost-onset rescale",
     "Confirm with more OL residency; bundle into MAF refit"),
    ("Boost under target", "ACCEPTED", "resolved",
     "Turbo ceiling, not a leak (ruled out 6-13); targets sit above natural flow by design",
     "Tune timing/fuel for actual mrp; no action"),
    ("Load-comp lean dead zone", "RESOLVED", "resolved",
     "−0.8% on 7-12 (was +4–8% lean pre-20.18)", "Regression tripwire only"),
    ("Pedal hunting · cusp stutter · decel-tier overrun knock · 20.16 P0s · boost leak",
     "RESOLVED / CLOSED", "resolved",
     "All confirmed stable through 7-12", "Tripwires only — no active tracking"),
]


def html(s, lh):
    last = lh.iloc[-1]
    total_deep = lh["fbkc_deep"].sum()
    total_res = lh["fbkc_deep_resume"].sum()
    fill = dict(
        resume_share=f"{total_res}/{int(total_deep)}",
        trim_now=f"{last['total_trim_cruise_med']:+.2f}",
        idc_now=f"{last['idc_max']:.1f}",
    )
    rows = "\n".join(
        f"<tr><td>{n}</td><td><span class='pill {css}'>{st}</span></td>"
        f"<td>{now.format(**fill)}</td><td>{nxt}</td></tr>"
        for n, st, css, now, nxt in LEDGER)
    corpus = f"{len(lh)} logs · {lh['duration_min'].sum()/60:.0f} h · active rev {last['rom_rev']} · latest {last['log_date']}"
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>AE5L600L tune progress</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
 body {{ font: 13px/1.45 -apple-system, Segoe UI, sans-serif; margin: 18px; background:#111; color:#ddd; }}
 h1 {{ font-size:18px; margin:0 0 2px; }} .sub {{ color:#888; margin-bottom:14px; }}
 h2 {{ font-size:14px; margin:22px 0 4px; color:#fff; }}
 .hint {{ color:#8a8a8a; font-size:12px; margin:0 0 6px; }}
 table {{ border-collapse: collapse; width:100%; font-size:12.5px; }}
 td, th {{ border-bottom:1px solid #2a2a2a; padding:5px 8px; text-align:left; vertical-align:top; }}
 th {{ color:#999; font-weight:600; }}
 .pill {{ padding:1px 7px; border-radius:9px; font-size:11px; white-space:nowrap; }}
 .active {{ background:#5a2020; color:#ff9d9d; }} .watch {{ background:#4d3d14; color:#ffd479; }}
 .blocked {{ background:#3a2a4d; color:#c9a6ff; }} .resolved {{ background:#1d3d24; color:#8fdba4; }}
 .chart-wrap {{ position:relative; height:260px; margin-bottom:6px; }}
</style></head><body>
<h1>AE5L600L — tune progress (issue-centric, per-log)</h1>
<div class="sub">{corpus}. Vertical solid line = ROM flash (rev change). Dashed line = PCV-fix
fueling-era boundary (6-21) — fueling series are NOT comparable across it. Gaps = the log
didn't exercise that condition (thin exposure is hidden, not zero).</div>

<h2>Issue ledger</h2>
<table><tr><th>Issue</th><th>Status</th><th>Where it stands</th><th>Next lever</th></tr>
{rows}</table>

<h2>1 · Knock in the money zones (first-instance fires/min)</h2>
<p class="hint">Down = better. Read WITH the IAT line — same ROM knocks more on hot+AC days.
Hidden when zone residency &lt; {MIN_ZONE_RES_MIN} min.</p>
<div class="chart-wrap"><canvas id="c1"></canvas></div>

<h2>2 · Deep knock (≤−3°) per hour — resume family vs everything else</h2>
<p class="hint">The stacked red is what the tau rev targets. If the tau restore works, red
shrinks and gray stays put.</p>
<div class="chart-wrap"><canvas id="c2"></canvas></div>

<h2>3 · FLKC tier engagement</h2>
<p class="hint">Decrements/hr = how often sustained knock forced the learning tier. Floor on
right axis. Always recovered so far (IAM 1.0 everywhere).</p>
<div class="chart-wrap"><canvas id="c3"></canvas></div>

<h2>4 · Fueling error — total trim at steady CL cruise (the honest signal)</h2>
<p class="hint">AFL alone redistributes; total trim (AFC+AFL) is the scaling truth. Goal band
±2%. Do not read across the dashed era line.</p>
<div class="chart-wrap"><canvas id="c4"></canvas></div>

<h2>5 · Injector headroom</h2>
<p class="hint">Flag 85%, saturation 100%. Gaps = injectors never worked hard that log
(max &lt; 40%). This chart ends the argument about the swap.</p>
<div class="chart-wrap"><canvas id="c5"></canvas></div>

<h2>6 · Tip-in stab lean (strict detector, per log)</h2>
<p class="hint">med peak lean AFR on ≥20-event logs; knock-follow/min on right axis. Scoring
chart for the tau rev.</p>
<div class="chart-wrap"><canvas id="c6"></canvas></div>

<script>
const S = {json.dumps(s)};
Chart.defaults.color = '#bbb'; Chart.defaults.borderColor = '#2a2a2a';
const boundaries = {{
  id: 'boundaries',
  afterDraw(chart) {{
    const {{ctx, chartArea, scales}} = chart; if (!scales.x) return;
    ctx.save();
    for (const i of S.rev_bounds) {{
      const x = scales.x.getPixelForValue(i) - (scales.x.getPixelForValue(1)-scales.x.getPixelForValue(0))/2;
      ctx.strokeStyle = 'rgba(255,255,255,0.28)'; ctx.setLineDash([]);
      ctx.beginPath(); ctx.moveTo(x, chartArea.top); ctx.lineTo(x, chartArea.bottom); ctx.stroke();
    }}
    if (S.pcv_idx !== null) {{
      const x = scales.x.getPixelForValue(S.pcv_idx) - (scales.x.getPixelForValue(1)-scales.x.getPixelForValue(0))/2;
      ctx.strokeStyle = 'rgba(255,215,0,0.55)'; ctx.setLineDash([5,4]);
      ctx.beginPath(); ctx.moveTo(x, chartArea.top); ctx.lineTo(x, chartArea.bottom); ctx.stroke();
    }}
    ctx.restore();
  }}
}};
const X = {{ ticks: {{ autoSkip: true, maxRotation: 0, font: {{size:10}} }} }};
const common = {{ responsive: true, maintainAspectRatio: false, spanGaps: false,
  plugins: {{ legend: {{ labels: {{ boxWidth: 12 }} }} }} }};
function line(d, label, color, extra={{}}) {{
  return Object.assign({{ data: d, label: label, borderColor: color, backgroundColor: color,
    borderWidth: 1.6, pointRadius: 2.5, tension: 0.15 }}, extra);
}}
new Chart(c1, {{ type:'line', plugins:[boundaries], options: Object.assign({{scales:{{x:X,
    y:{{title:{{display:true,text:'fires/min'}}}},
    y2:{{position:'right',grid:{{display:false}},title:{{display:true,text:'IAT med °F'}}}}}}}}, common),
  data: {{ labels: S.labels, datasets: [
    line(S.cusp,'cusp 1600-3000×1.00-1.25','#ff6b6b'),
    line(S.rect,'rect 2250-3150×1.05-1.40 (5th)','#ffa94d'),
    line(S.iat,'IAT med','#4dabf7',{{yAxisID:'y2',borderDash:[4,3],pointRadius:0,borderWidth:1}}) ]}}}});
new Chart(c2, {{ type:'bar', plugins:[boundaries], options: Object.assign({{scales:{{x:Object.assign({{stacked:true}},X),
    y:{{stacked:true,title:{{display:true,text:'deep events/hr'}}}}}}}}, common),
  data: {{ labels: S.labels, datasets: [
    {{label:'DFCO-resume (≤5s from IPW=0 exit)', data:S.deep_resume_hr, backgroundColor:'#e03131'}},
    {{label:'other deep', data:S.deep_other_hr, backgroundColor:'#666'}} ]}}}});
new Chart(c3, {{ type:'bar', plugins:[boundaries], options: Object.assign({{scales:{{x:X,
    y:{{title:{{display:true,text:'FLKC decrements/hr'}}}},
    y2:{{position:'right',grid:{{display:false}},title:{{display:true,text:'floor °'}}}}}}}}, common),
  data: {{ labels: S.labels, datasets: [
    {{label:'decrements/hr', data:S.flkc_dec_hr, backgroundColor:'#845ef7'}},
    line(S.flkc_min,'FLKC floor','#ffd43b',{{yAxisID:'y2',type:'line'}}) ]}}}});
new Chart(c4, {{ type:'line', plugins:[boundaries], options: Object.assign({{scales:{{x:X,
    y:{{title:{{display:true,text:'%'}}, suggestedMin:-7, suggestedMax:4}}}}}}, common),
  data: {{ labels: S.labels, datasets: [
    line(S.trim,'total trim, steady CL cruise (AFC+AFL)','#69db7c',{{borderWidth:2.2}}),
    line(S.afl_med,'AFL median','#748ffc'),
    line(S.afl_end,'AFL end-of-log','#4dabf7',{{borderDash:[4,3],pointRadius:0}}) ]}}}});
new Chart(c5, {{ type:'line', plugins:[boundaries], options: Object.assign({{scales:{{x:X,
    y:{{title:{{display:true,text:'IDC %'}}, suggestedMax:120}}}}}}, common),
  data: {{ labels: S.labels, datasets: [
    line(S.idc_max,'IDC max','#ff6b6b',{{borderWidth:2}}),
    line(S.idc_p99,'IDC p99','#fab005'),
    line(S.idc_max.map(v=>85),'flag 85%','#888',{{borderDash:[3,3],pointRadius:0,borderWidth:1}}),
    line(S.idc_max.map(v=>100),'static 100%','#e03131',{{borderDash:[3,3],pointRadius:0,borderWidth:1}}) ]}}}});
new Chart(c6, {{ type:'line', plugins:[boundaries], options: Object.assign({{scales:{{x:X,
    y:{{title:{{display:true,text:'med peak lean (AFR)'}}}},
    y2:{{position:'right',grid:{{display:false}},title:{{display:true,text:'knock-follow/min'}}}}}}}}, common),
  data: {{ labels: S.labels, datasets: [
    line(S.tip_lean,'median peak stab-lean','#ffa94d',{{borderWidth:2}}),
    line(S.tip_follow,'FBKC within follow window /min','#ff6b6b',{{yAxisID:'y2',borderDash:[4,3]}}) ]}}}});
</script></body></html>"""


def main():
    lh, z, tip = load()
    s = build_series(lh, z, tip)
    OUT.write_text(html(s, lh), encoding="utf-8")
    print(f"wrote {OUT} ({len(lh)} logs)")


if __name__ == "__main__":
    main()
