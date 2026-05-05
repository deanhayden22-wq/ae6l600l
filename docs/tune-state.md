# Tune state — AE5L600L 20G

Captured 2026-05-04. Active rev: **20.11**.

ROM revs are in `rom/AE5L600L 20g rev X.Y tiny wrex.bin`. Bins are
overwritten in place — same filename, new content — so a recorded hash
or table dump may not match what's currently on disk. Re-extract before
acting.

The high-level direction is **cruise smoothness via cliff resolution**
in RPM × Load tables, applied across AVCS, base timing, knock advance,
OL, and CL fueling comp. The same residency-on-grid method applies to
all of them — see `methodology/cruise-residency.md`.

## What each rev changed

### 20.9 → 20.10 (cruise smoothness session, ended 2026-04-25)

| Table | Change |
|---|---|
| **Intake AVCS Cruise** | Cliff count 55 → 37. Cruise-on-cliff cells dropped to 3 (near 5–5.5° threshold floor in 0.20–0.30 load corner at 1900–2200 RPM). Closed. |
| **Base Timing Cruise** | 47 cells changed. 0.27/0.50 load columns pulled −1.4 to −2.8° at 1600–5550 RPM (those cols sat at 30°+ advance). 0.94 column got selective bumps at 1900–3000 RPM. **Side effect:** bumping (1900, 0.94) +1.05° without touching (1900, 1.20) grew that pair's load-direction cliff to 7.03°. Outstanding, lower priority — only ~7s residency. |
| **Knock Correction Adv Max Cruise** | Unchanged from 20.9. Has its own 4.57° cliff at the 0.94→1.20 boundary (2200–3300 RPM) which **stacks** with base timing cliffs at the same boundary. Combined effective swing ~10° if load wanders across. |
| **OL B Low / B High** | At the 4-25 snapshot, unchanged. Superseded by 4-27 amendment below. |
| **CL Fueling Target Comp A (Load)** | Unchanged. Essentially flat. |

### 20.10 amendments (4-27 part-throttle / OL fueling chat, 2026-04-28)

Same `20.10` file, overwritten in place with additional changes:

- **Primary OL Fueling B Low + B High + KCA Alt** (kept identical per
  the all-three rule — see [ol-fueling.md](ol-fueling.md)): smoothed
  to reduce column-direction cliffs.
  - Cliff at 0.57→0.73 column (high-RPM) reduced ~25%: 4400 row, AFR
    drop went −1.26 → −0.97.
  - Cliff at 1.17→1.36 column softened: 2200 row, −0.86 → −0.39.
  - Method: graduated leanout +0.21 to +0.40 AFR in 3700–5500 RPM ×
    0.73–1.36 cells; mostly +0.32 to +0.40 in column 1.36 across
    2200–6000 RPM. 6000–6600 RPM extended +0.07 to +0.25.
  - One cell deliberately **richer**: (2200, 1.17) by −0.10 AFR, paired
    with leaning (2200, 1.36) by +0.37 — smoothed gradient between the
    two.
- **Other tables also changed in 20.10** (per byte-diff of 20.9 →
  20.10), origin not established in the 4-27 chat — likely from a
  parallel session: Max Wastegate Duty (0xc0fe0), Initial Wastegate
  Duty (0xc11d8), Overrun Fueling RPM Resume Threshold (0xceed0),
  Base Timing Primary Non-Cruise (0xd48d4 — companion to the Cruise
  change), Base Timing Reference Cruise + Non-Cruise (0xd4a94, 0xd4c54),
  Intake Cam Advance Non-Cruise (0xdac34 — companion to AVCS Cruise).

**Verification — 4-27 logs (3 logs, ~36k samples):**

- cmd-vs-actual fueling delta improved: +0.26 (20.9) → +0.14 (20.10) in
  4000–4500 OL, 0.7–1.3 load. Engine now closer to commanded.
- WBO2 went leaner ~0.08 in 3500–4000, 1.0–1.3 load (target effect,
  achieved).
- **Knock activity up significantly in the leaned cells:**

  | Cell | Before | After |
  |---|---|---|
  | 3500–4000, 1.0–1.3 | 0.0% | 2.9% |
  | 4000–4500, 0.7–1.0 | 0.0% | 8.7% |
  | 4000–4500, 1.0–1.3 | 0.0% | 9.9% |
  | 3500–4500, 1.3–1.6 | 0.0% | **34.1%** |

- IAM still 1.000 — knock not sustained enough to ratchet.
- **Confound:** timing + AVCS were also changed simultaneously, so
  knock can't be cleanly attributed to the OL leanout alone. See
  [open-issues.md](open-issues.md) for the disentangling plan.

**Two distinct knock event patterns identified in 4-27 logs:**

1. **Log 0002, one event, 16 samples in 0.7s** — 6-second steady
   tip-in, AVCS pinned at 0° the entire time. Not a shift event.
   AVCS map appears to command 0° in 3500–4500 RPM × ~1.2 load ×
   non-cruise (static map issue).
2. **Log 0003, one event, 13 samples** — post-DFCO recovery with AVCS
   ramping 0→23° at ~18°/s. Knock fires at AVCS=12° (mid-ramp).
   Matches the "tip-in + AVCS ramp lag" hypothesis. AFC accel
   enrichment had already expired before knock — extending its decay
   tail could help.

### 20.10 → 20.11 (5-2 log analysis session, 2026-05-03)

File: `rom/AE5L600L 20g rev 20.11.bin`.

- **AVCS Cruise + AVCS Non-Cruise** (paired, identical 7-cell change):
  softened the 1900↔2200 / 0.20–0.30 cliff (35 mph stutter zone).
  - Lifted: (1600, 0.20) 5.0→6.5; (1600, 0.30) 9.5→11.0; (1900, 0.20)
    9.5→11.0; (1900, 0.30) 13.2→14.5.
  - Dropped: (2200, 0.20) 14.0→13.5; (2200, 0.30) 18.0→17.5; (2500,
    0.30) 20.0→19.5.
  - Reduces 1900↔2200 cliff from 4.5–4.7° to 2.5–3.0° at the 35 mph
    residency cells.
- **Base Timing × 4 variants** (Primary Cruise, Primary Non-Cruise,
  Reference Cruise, Reference Non-Cruise — kept identical, 25 cells
  each):
  - **1.20 load column** pulled −0.4 to −2.1° (mostly −1.0 to −1.8°)
    from 1900 to 5900 RPM. Targets the 38540/38622/38777-knock cluster
    at 2200–3000 RPM × 1.0–1.2 load.
  - **3.07 load column** pulled mostly −0.7° from 3000 to 7000 RPM.
    Targets the 32871 high-RPM/high-load OL knock at 4247 / 3.30.
  - **(2200, 3.07) intentionally bumped UP**: raw 69→70, +0.35° —
    smoothing only, prevents a steep cliff into adjacent cells in the
    3.07 column. Confirmed intentional, **not** an error.
- **MAF Sensor Scaling** (0xd8c9c, 32-entry float table + 3 extended
  cells past idx 31):
  - Pulled idx 11 (1.302V): 4.890 → 4.700 g/s (−3.90%)
  - Pulled idx 12 (1.363V): 5.681 → 5.625 g/s (−0.99%)
  - Pulled idx 30 (2.388V): 38.329 → 37.573 g/s (−1.97%)
  - Pulled idx 31 (2.449V): 43.067 → 42.218 g/s (−1.97%)
  - Bumped 3 extended cells UP: 133.114 → 135.790, 155.534 → 161.849,
    167.332 → 172.402.
  - **Method:** per-cell wbo2 vs commanded AFR. ECU was consistently
    pulling fuel (negative trim) at those V points — engine running
    rich there — MAF over-reading airflow. Pulling MAF down brings
    ECU's calc in line with delivered AFR. Independent of FBKC/load
    knock — different correction loop on a different axis.
- **0xffb88 region** updated automatically (firmware
  checksum/signature).

**Verification pending on 20.11.** When driven and logged, check:
(a) 35 mph stutter resolved, (b) FBKC events at 2200–3000 / 1.0–1.3
reduced, (c) trim corrections at 1.30V and 2.39V MAF cells move toward
zero.

## Baseline log

`logs/4-25/4-25 full.csv` — 131,516 samples, ~33.8% pass cruise filter
(~1,778s of cruise time). Captures real-world cruise distribution well
at 2200–3400 RPM / 0.30–0.94 g/rev. **Almost no cruise residency above
4150 RPM** in this log — if asked about cruise behavior at higher RPM
or far outside the captured cells, this log is silent there.

## Plots and scripts produced from this iteration

- `logs/4-25/plots/avcs_cruise_heatmap_4-25.png`,
  `heatmap_Base_Timing_Cruise_4-25.png`,
  `heatmap_Knock_Adv_Max_Cruise_4-25.png`,
  `heatmap_OL_B_{Low,High}_4-25.png`,
  `heatmap_CL_Fuel_Comp_A_Load_4-25.png`
- `scripts/analysis/extract_avcs_table.py`,
  `cruise_heatmap_avcs_4-25.py`, `cruise_heatmap_multi_4-25.py`
- `logs/4-25/avcs_tables_209_vs_2010.json` — extracted axis + table
  values

Scripts have hardcoded session paths at the top — they need a path
edit before running locally.
