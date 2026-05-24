# Tune state — AE5L600L 20G

Captured 2026-05-23 after the 20.14 verification drives (3 logs on 5-23: 24-min warm city, 8.9-min cold around-town, 253-min way-home).
**On car right now:** 20.14 (`rom/AE5L600L 20g rev 20.14.bin` — pedal-hump build, driven).
**Staged for next flash:** 20.15 (tip-in enrichment fix) — see "20.14 → 20.15" below.
**MAF rescale status:** Dean verified converged on 378k-sample offline analysis (5-23). No MAF changes needed for 20.15. The 8-50 g/s cruise band runs −0.1% to −1.4% (median ≈ −0.5%); only the 161-180 g/s band shows a coherent −3 to −5.7% lean across 3 cells but residency is lower (boost-build transient territory). Defer.

ROM revs are in `rom/AE5L600L 20g rev X.Y tiny wrex.bin`. Bins are
overwritten in place — same filename, new content — so a recorded hash
or table dump may not match what's currently on disk. Re-extract before
acting.

The high-level direction is **cruise smoothness via cliff resolution**
in RPM × Load tables, applied across AVCS, base timing, knock advance,
OL, and CL fueling comp. The same residency-on-grid method applies to
all of them — see `methodology/cruise-residency.md`.

## Pre-20.7 history

This document starts at 20.9. Earlier revs (`AE5L600L 20g rev 20.7
tiny wrex.bin`, `20.8`, etc., plus the stock `ae5l600l.bin` and the
`13 20g Base rev 25 e garn.hex` starting point in `rom/`) exist as
binaries but their per-rev change history wasn't captured in working
notes that travel with the repo. If you need to know what changed in
an older rev, byte-diff the bins directly (e.g.,
`scripts/analysis/cross_rev_diff.py` once axis-mismatch support
lands — see [avcs.md](avcs.md) "Pending tool enhancements"). The
trend store at `scripts/analysis/trends/knock_by_cell.csv` does carry
older revs as `rom_rev` rows for ghost-zone analysis.

## What each rev changed

### 20.9 → 20.10 (cruise smoothness session, ended 2026-04-25)

| Table | Change |
|---|---|
| **Intake AVCS Cruise** | Cliff count 55 → 37. Cruise-on-cliff cells dropped to 3 (near 5–5.5° threshold floor in 0.20–0.30 load corner at 1900–2200 RPM). Closed. |
| **Base Timing Cruise** | 47 cells changed. 0.27/0.50 load columns pulled −1.4 to −2.8° at 1600–5550 RPM (those cols sat at 30°+ advance). 0.94 column got selective bumps at 1900–3000 RPM. **Side effect:** BTC-only delta at the (1900, 0.94)→(1900, 1.20) pair grew to 7.03°. **Score on Sum map (BTC + KCA·IAM), not BTC alone** — see open-issues.md. |
| **Knock Correction Adv Max Cruise** | Unchanged from 20.9. Has its own 4.57° step at the 0.94→1.20 boundary (2200–3300 RPM) but that step **opposes** BTC at the same boundary (BTC drops, KCA rises). Net Sum cliff at this pair is only −1.4 to −2.1°, not the previously-noted ~10°. Worst Sum cliff in the cruise zone is at **0.65→0.94** (KCA=0 on both sides), where Sum drops 4.9–7.7° depending on RPM. See `open-issues.md` "Cruise-zone advance cliffs" for the full table. |
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

**20.11 in-rev findings (cumulative over 6 logs: 5-8, 5-10/log0003,
5-11/log0001+0002+0003, 5-12; full per-log writeups in
`logs/REVIEW_LOG.md`):**

- *35 MPH stutter not fully resolved.* AVCS-led clusters concentrated
  at 2500-3000 RPM × 0.20-0.30 load (25/82 clusters on 20.11). Root
  cause: a single-cell peak at (2500, 0.20) = 18° on AVCS Cruise,
  inherited from 20.10 — the 20.11 1600/1900 fix didn't reach it.
  Motivated 20.12's AVCS plateau extension.
- *Ghost zone 2200-3300 × 1.0-1.4 g/rev elevated on 20.11.* 4 of 4
  zone-exposed logs fired FBKC<0 in zone. 20.10 pooled = 85.4
  FBKC<0/zone-min; 20.11 pooled = ≥217/zone-min. IAM held 1.000 in
  every log. Not single-log noise.
- *5-12 added a high-RPM ghost extension* at 4000-4400 × 1.0-1.17
  (15 fresh FBKC<0 from one partial-throttle climb pull).
- *5-11/log0001 added a low-RPM ghost extension* at 1250-1750 × 1.0
  (23 FBKC<0). All three sub-zones likely share a root.
- *Post-20.10 OL knock 3500-4500 × high-load still firing.* 5-10's
  log0003 ratcheted FLKC=-1 across two pulls; 5-11/log0001's WOT pull
  (sole sustained TPS>95 on 20.11) hit FBKC -1.4 / FLKC -1.0 at
  4039-4497 × 3.43-3.86, then recovered. Motivated 20.12's BT retard
  at L=2.25-4.00 and Max WG cut.
- *WOT health (5-11/log0001):* peak mrp 21.74 psi at 4071 RPM, target
  22.29, 97.5% attainment. Healthy. 5-10 had 1.04-1.05 over-target on
  similar RPM, which is what the Max WG cut was sized against.
- *AVCS-swing "regression" claim from 5-10 doesn't hold up* under
  strict-SOP measurement. Recomputed: 4-27=1.84, 5-2=5.84, 5-8=3.73,
  5-10=4.19, 5-11=5.60, 5-12=2.63 clu/min. 20.11 vs 20.10 inconclusive.
  AVCS osc at 2000-RPM band is real (16/21 events in 5-11/log0001)
  but the monotonic upward trend was a methodology artifact.
- *MAF rescale moved trim health right direction.* 20.10 in_tol 50%,
  mean|c| 1.92%; 20.11 in_tol 82-89%, mean|c| 1.05-1.34% across 4
  logs. But 5-12 introduced a new mid-V slope walk (V=1.91→2.45,
  -1.79% → -4.44% — engine ~3-4% richer than cmd in that band).
  Tracked but didn't trigger action on 20.12.

### 20.11 → 20.12 (2026-05-10)

File: `rom/AE5L600L 20g rev 20.12.bin` (md5
`534720b84959cac2a0f14ee641cc6360`).

- **AVCS Intake Cruise (0xDA96C) + Non-Cruise (0xDAC34)** — paired,
  identical 12-cell edit per table. Plateau extension on the 0.20 and
  0.30 load columns to match higher-load (0.50+) column shape.
  - 0.20 column: (2200) 13.5→14.0, **(2500) 18.0→15.0**, (2800) 15.0
    (keep), (3000) 12.5→14.0, (3400) 9.0→10.0, plus shape-only
    (3800) 5.0→6.25.
  - 0.30 column: (2200) 17.5→18.0, **(2500) 19.5→18.0**, (2800)
    17.5→18.0, (3000) 15.5→17.0, (3400) 12.25→13.25, plus shape-only
    (3800) 8.0→9.25.
  - 0.50 column: shape-only (3800) 11.0→11.76.
  - The (3800) edits at all three loads are sub-1% strict-cruise
    residency, accepted as shape-only edits per the residency
    threshold rule — they smooth the column but won't appear in
    logs to verify.
  - Targets the 2500-3000 RPM × 0.20-0.30 AVCS-led stutter zone
    (19 of 25 clusters on 20.11 fired in this region).
- **Base Timing × 4 variants** (Primary Cruise/NC, Reference Cruise/NC
  — locked-identity holds, all four byte-identical to each other):
  30 cells retarded per table, -0.35 to -1.05°.
  - Cruise-side cells (2800-4150 RPM × 0.20-0.70 load): pulls
    timing in the AVCS-led stutter zone (timing osc is a
    co-participant in the stutter signature).
  - High-load cells (2800-4150 RPM × 2.25-4.00 load): pulls timing
    in the post-20.10 OL knock zone (3500-4500 RPM × high load,
    14 FBKC events on 20.11's 5-10 log).
  - One rev tests both hypotheses simultaneously. Scorecard's
    `timing_osc_per_min` resolves the cruise-side question;
    `total_knock_per_min` and `min_fbkc_depth` resolve the OL
    question.
- **Max Wastegate Duty (0xC0F58)** — 70 cells reduced, -0.4 to -2.1%.
  Spool-region focus: 1350-2200 RPM band gets the bulk of the pulls.
  Absolute max raw stays at 32768 (50.0% full-range). Reduces spool
  aggressiveness, not the ceiling — `glide-not-slam` per memory.
- **Initial WG Duty (0xC1150):** UNCHANGED.
- **Target Boost (0xC1340):** UNCHANGED.
- **MAF Sensor Scaling (0xD8C9C):** UNCHANGED (deferred to 20.13+
  pending more 20.11/20.12 cruise samples per small-sample reasoning).
- **0xF1054 (2 bytes):** changed; possible FFS RPM delta or similar.
  Identity to confirm on next verification pass.

**20.12 flashed between 5-12 and 5-17.** Verification drive on 5-17
produced 6 logs in `logs/5-17 20.12/` (log0002, log0003-0006, log0007;
total ~5.7 h of operation — log0002 at 157.6 min and log0007 at 133.7
min are full road sessions, the rest are 12-14 min each).

**20.12 verification — 5-17 logs vs 20.11 baseline (scorecard delta):**

| Gate | 20.11 → 20.12 | Result |
|---|---|---|
| AVCS plateau drops global stutter signature (gate <1.80) | 1.89 → 1.37 | **PASS** (-0.53) |
| BT retard reduces cruise-side timing osc (gate <0.70/min) | 0.87 → 0.71 | **MARGINAL** (-0.17, just over gate) |
| BT retard reduces OL knock events (gate <0.40/min) | 0.64 → 0.26 | **PASS** (-0.38) |
| BT retard reduces FBKC depth (gate shallower than -4.0°) | -4.2° → -7.0° | **FAIL — regressed -2.8°** |
| Max WG smooths spool (attn 0.75-0.90, no overshoot >1.05) | attn 0.77 → 0.83; peak mrp 13.56 → 9.87 psi; 0 overshoot pulls | **PASS** |
| AVCS-led clusters at 2500-3000 × 0.20-0.30 (gate ≤10, was 19) | TBD — needs per-cell cluster re-bin on 5-17 data | Open |

Also moved on 5-17 data:
- `rpm_swing_per_min`: 2.38 → 1.07 (-1.31, big improvement)
- `throttle_hunt_per_min`: 0.50 → 0.23 (-0.27)
- `afr_osc_per_min`: 1.20 → 0.90 (-0.30)
- `ffb_wbo2_div_per_min`: 2.81 → 2.05 (-0.76)
- `maf_corr_mean_pct`: -1.08% → **+1.83%** (sign flip; engine now leaner
  than commanded — likely the long log0007 sat in cells where wbo2
  ran lean of FFB; 20.12 didn't touch MAF directly)
- `maf_corr_mean_abs_pct`: 1.43% → 2.39% (trim health degraded)

**Headline 20.12 read:** 3 gates passed, 1 marginal, 1 regressed. The
event-count regression (FBKC depth -4.2 → -7.0) is concentrated in
the **ghost zone proper at 2600-3300 RPM × 1.0-2.0 g/rev** — the BT
retard was applied at L=2.25-4.00 and missed the dominant ghost
cells. log0007 hit this cluster hard:

- 2600 × 1.17: 81 FBKC<0, min -7.0°
- 2600 × 1.36: 23 FBKC<0, min -7.0°
- 2600 × 1.51: 23 FBKC<0, min -6.65°
- 2600 × 1.64-1.95: 30 FBKC<0, min -5.6 to -6.3°
- 3000 × 1.95-2.6: 89 FBKC<0, min -3.85 to -5.6°
- 3300 × 1.51-1.95: 44 FBKC<0, min -5.6 to -6.65°
- Plus FLKC ratchet at 3300-4000 × 2.0-3.0 (57 FLKC events on 5-17).

This is a worse cluster (deeper) than anything seen on 20.11 — both
the OL knock zone and the ghost zone proper need attention in 20.13.

### 20.12 → 20.13 (2026-05-17 — built today, not flashed)

File: `rom/AE5L600L 20g rev 20.13.bin`.

Rom byte-diff (`scripts/analysis/rom_diff.py`): **439 bytes** in **43
runs** (after the 5-21 axis revert — see #3 below). Full cell-by-cell
decode done 2026-05-21 (byte-diff of the two bins, all changed tables
decoded in scaled units).

| Table region | runs | bytes | addr range |
|---|---:|---:|---|
| AVCS Intake Cruise (`0xDA96C`) | 9 | 38 | 0xDA96D–0xDAA90 |
| AVCS Intake Non-Cruise (`0xDAC34`) | 8 | 37 | 0xDAC58–0xDAD58 |
| Firmware checksum (auto) | 1 | 4 | 0xFFB88–0xFFB8C |
| OL fueling block (3 tables, all-three) | 24 | 426 | 0xCFD68–0xD04F1 |
| **Timing Compensation A (IAT)** (`0xD3288`) | 1 | 11 | 0xD328D–0xD3298 |

(`rom_diff.py`'s KNOWN_TABLES doesn't carry the OL-fueling, IAT-comp, or
AVCS-axis addresses, so it lumps them into "(unknown region)
0xCFD68–0xDA932". The table above is the resolved identity per
`definitions/AE5L600L 2013 USDM Impreza WRX MT.xml`.)

**1. OL richening (DOCUMENTED, intentional).** Three tables changed
**byte-identically** — 117 cells each, same coords, same values
(all-three rule confirmed, see [ol-fueling.md](ol-fueling.md)):

- Primary OL Fueling (KCA Alternate Mode) — `0xCFD30`
- Primary OL Fueling (KCA Additive B Low) — `0xD0244`
- Primary OL Fueling (KCA Additive B High) — `0xD0404`

(Failsafe `0xD05C4` and Failsafe-KCA-Alt `0xCFEF0` were **not** touched.)
Predominantly richer, sized to the 5-17 knock clusters:
- 2600-3300 RPM × 1.0-2.0 load: −0.1 to −0.5 AFR (the FBKC −7.0° depth
  cluster).
- High-RPM/high-load 4000-5500 × 1.36-1.95: the largest pulls, −0.7 to
  **−1.04 AFR** (the FLKC ratchet band at 3300-4000 × 2.0-3.0 and above).
- A handful of low-RPM/high-load cells (800-1900 × 2.28-2.90) leaned
  slightly +0.07 to +0.23 — gradient smoothing, not a richening target.

**2. AVCS plateau extension (DOCUMENTED, intentional).** Cruise +
Non-Cruise, **20 paired cells** (byte-identical between the two tables):
0.30 column lifted 0→5°; 0.50 column flattened to a 10° plateau across
1900-3400 (was 1.75-7.0°); 0.60/0.70 selective bumps; and the 18° peak
**trimmed to 17°** at high-RPM/high-load (0.80×4150, 0.90×4750,
1.00×5500) plus 1.20×1100 17→16°. Extends 20.12's plateau work.

**3. Three changes NOT in the original announcement (surfaced by the
5-21 diff per `feedback_verify_rom_changes_against_user_claims`; Dean
confirmed to document and keep — all judged in-line with active knock
issues):**

- **Timing Compensation A (IAT)** (`0xD3288`, scaling
  `IgnitionTimingCorrection(degrees)`, axis = intake-air temp −40→110°C):
  11 cells, **added retard at hot IAT** (cells ≤0°C untouched):
  10°C −0.70°; 20-30°C −1.05°; 40-70°C −0.70°; 80-90°C −0.35°;
  100-110°C −1.05°. End state: −1.41° at 10°C ramping to −8.09° at
  110°C. **Alignment:** IAT rises under sustained boost, so this is a
  second lever (IAT axis) on the **same** high-load knock cluster the OL
  richen targets — complementary, plausibly helpful. **Caveat:** it
  confounds 20.13 knock attribution (OL-richen vs IAT-retard both pull
  the same cells the same way; scorecard can't separate them).
- **AVCS Cruise RPM axis** breakpoint idx1 had moved **1100 → 1300 RPM**
  (`0xDA930`) while the Non-Cruise axis (`0xDABF4`) stayed at 1100 —
  this was an **accidental** edit (would have de-paired the two AVCS
  tables' RPM axes). **Reverted locally 2026-05-21**; both axes are back
  at 1100 in the bin. This is why the diff is now 439 bytes / 43 runs
  (was 440 / 44).
- **AVCS Cruise-only cell** (0.20 load, 1000 RPM): 0.50 → 0.00°, with
  **no** matching Non-Cruise edit. Sub-1% residency → shape-only per the
  residency-threshold rule; not a testable hypothesis. Kept.

**MAF Sensor Scaling (0xD8C9C):** UNCHANGED. MAF rescale work is in
progress against the 20.12 5-17 evidence (Dean working on it manually
— "a lot of info, going to take some time"). Targeted for 20.14.

**20.13 flashed; verified on 5-22 (2026-05-22).** One long log
`logs/5-22 20.13/log0001.csv` (249,171 samples / ~166 min, 1 road
session). Scored against the pre-drive gates:

| Gate | 20.12 → 20.13 | Result |
|---|---|---|
| OL richen kills FBKC depth (gate shallower than -4.5°) | -7.0° → **-2.8°** | **PASS** |
| FLKC ratchet at 3300-4000 × 2.0-3.0 (gate <0.05/min) | 0.166 → **0.000**/min (55 → **0** events) | **PASS (strong)** |
| AVCS work tightens cluster (gate avcs_osc <1.0/min) | 1.127 → 1.114 | **FAIL — didn't move** |
| OL richen no wbo2 blowback (gate ≤2.5/min) | 2.05 → 2.00 | **PASS** |

- **IAM held 1.000 the entire drive; FLKC never ratcheted negative
  anywhere.** No learned-knock damage. The severe knock is gone.
- **Caveat — knock is de-fanged, not eliminated.** Depth dropped
  decisively (nothing deeper than -2.8° in the whole 2600-3300 × 1.0-2.0
  band, was -7.0°) but shallow FBKC trims got **more frequent and more
  spread**. Cluster band fbkc<0 samples: 20.12 log0007 = 468 (deepest
  -7.0°) → 20.13 = 774 (deepest -2.8°), and the 3000-RPM row + upper
  3300 row (1.36-1.95) now show shallow knock that 20.12 log0007 didn't.
  Normalized by duration the shallow-knock rate rose ~33%. Reading: the
  cells are still right at the knock threshold; the ECU now catches it
  with many small -1.0 to -2.8° trims instead of occasional -7.0° slams.
- **ATTRIBUTION CONFOUND stands:** OL richen and the IAT retard both
  pull these same cells the same way — this is "OL richen AND/OR IAT
  retard worked," not OL richen alone.
- **AVCS gate failed for a clear reason:** the 20.13 edit lifted the
  0.30/0.50 columns, but the residency-weighted oscillation lives in the
  **0.20 load column at 2800-3000 RPM** (3000×0.20: 46→48 events;
  2800×0.20: 25→28; 2500×0.20: 19→19 — essentially untouched). 123 of
  185 osc events still in the 2500-3000 × 0.20-0.30 zone. Next AVCS lever
  is the 0.20 column, not 0.30+.
- **Also moved (scorecard, 20.12 → 20.13):** `mean_target_attainment`
  0.829 → **0.955** (boost healthier, 37 pulls, 0 wgdc-pegged);
  `rpm_swing_per_min` 1.069 → 0.921; `ffb_wbo2_div` 2.05 → 2.00;
  `maf_corr_mean_abs_pct` 2.393 → **1.121** (trim health improved — but
  20.13 didn't touch MAF; drive-context shift). Slight regressions:
  `afr_osc_per_min` 0.904 → 1.011, `stutter_signature_per_min` 1.366 →
  1.451 (minor; possibly the OL richen adding small AFR ripple).

### 20.13 → 20.14 (staged 2026-05-22 — pedal map; bin exists, not yet driven)

Driven by Dean's "sluggish off the line" report. Analysis on the 5-22
log established that 20.13's pedal map gives **less than half** the
low-RPM throttle stock does at light pedal (16.5% APP @ 800 RPM:
commanded throttle 8.6% vs stock 18.9%) — the cruise-hunting fix that
lowered the 16.5% column also flattened/inverted stock's low-RPM
"tip-in hump." See `methodology/` and the new `pedal-map.md` /
`feedback`/`project` memory for the DBW pedal→ratio→throttle chain.

**1. Pedal-map hump restore (Sport map `0xF99E0`; i==s==sharp identical).**
8 cells, low-RPM launch block only, partial-restore toward stock
(monotonicity-capped under the unchanged 31% column):

| RPM | APP col | 20.13 RQTQ | → 20.14 | raw |
|---|---|---|---|---|
| 800 | 16.5% | 109.9 | 135 | 17280 |
| 1200 | 16.5% | 127.2 | 150 | 19200 |
| 1600 | 16.5% | 135.1 | 155 | 19840 |
| 2000 | 16.5% | 133.5 | 155 | 19840 |
| 800 | 25% | 137.4 | 150 | 19200 |
| 1200 | 25% | 165.6 | 178 | 22784 |
| 1600 | 25% | 194.2 | 210 | 26880 |
| 2000 | 25% | 197.8 | 218 | 27904 |

(Values scaled Requested Torque, ×128 = raw uint16. 10% column left
alone — already ≥ stock. All rows ≥2400 left alone — keeps clear of the
2700-3300 steady-cruise hunt band and the spool region.) Recovers ~70-80%
of the stock low-RPM throttle: commanded throttle at 16.5%@800 goes
8.6% → 15.4% (stock 18.9). **Dean applied + lightly smoothed this in his
tool**; the smoothed commanded-throttle surface was reviewed — monotonic
across the driving range (only inversion is the 6400-RPM rev-limiter
taper), hump restored, 2700-3300 hunt rows untouched (gain stays 0.83
vs stock 0.97 %thr/%APP).

**Push-further rule (if still soft):** each cell must stay below the cell
to its right; the 16.5% column has the most headroom under its 25%
neighbor. Going fully to stock requires lifting 31%/37%/44% too, which
re-creates stock's steep 10%→16.5% tip-in cliff (the thing the hunt fix
removed) — so increment the 800-1600 rows modestly, don't overshoot.

**2. MAF rescale** — Dean working offline on the 20.12 5-17 evidence.
Outcome (5-23 analysis, 378k samples): current MAF curve is converged
across the cruise band (8-50 g/s runs −0.1% to −1.4%). No MAF table
changes shipped in 20.14. See `### 20.14 verification drive` below for
the residency-weighted check.

**Evaluated and DEFERRED for 20.14 (with reasons):**
- **AVCS:** no broad work. With steady inputs at low RPM, true AVCS
  hunting is <1% — most low-RPM cam motion is legitimate commanded sweep.
  Only confirmed steady hunt is the 0.20-load column at 2800-3000 (the
  25-mph cruise stutter; gate-3 miss) — ~4% of low-RPM time. Optional
  micro-smooth later if it nags; the pedal hump may mask it by getting
  through the light-load zone faster.
- **Timing cliffs / knock:** not the low-RPM smoothness lever. Steady
  low-RPM timing osc is ~1%, only 3% knock-adjacent, and clusters at
  0.30 load (not the 0.65→0.94 BTC cliff). Dean accepts the shallow
  -1.4 to -2.8° FBKC ("noisy engine, not worried").

**Key finding behind the deferrals:** the low-RPM "not super smooth"
feel is **transient (load/throttle transitions), not steady-state
hunt** — held steady, the engine is calm (≤1% osc on AVCS/timing/RPM).
So the lever is spending *less time* in the low-RPM transition zone,
which the pedal hump does directly. Also confirmed: during take-offs
the driver is **not** pedal-chasing — APP-vs-RPM correlation median
−0.50 (foot eases as revs climb) while commanded throttle holds/rises;
the torque-based DBW scales throttle up with RPM correctly.

### 20.14 verification drive (5-23, three logs)

Flashed and driven 2026-05-23. Three logs: log0001 (warm, 24 min city,
WOT pull, 125 FBKC<0 with min −4.2°), log0002 (cold start, 8.9 min,
0 knock, 25-mph AVCS hunting), log0003 (BIG way-home, 253 min, 21 psi
peak boost, 699 FBKC<0, FLKC latched in some boost cells).

**Pedal-hump scoring:**
- **PASS** — stutter_events/min: 6.02 (20.13) → **3.95** (20.14 big log) = −34%. The 20.14 lever measurably reduced stutter signature.
- **Subjective:** Dean reports sluggishness fix achieved; low-RPM transit feel is improved.
- Cold 25-mph stutter still present but separate mechanism — AVCS oil-hydraulics-limited cam tracking during warmup (`avcs_pct_zero` 86% in first 100s, then bimodal 0°↔20° as oil warms). Not a calibration issue; oil viscosity. No calibration lever in this ROM gates AVCS by ECT directly. Accept as cold-start character.

**MAF check** (`378k samples, Dean's offline analysis`):
| g/s range | avg correction | comment |
|---|---|---|
| 8–50 (cruise band) | −0.1% to −1.4%, median ≈ −0.5% | **clean** |
| 50–90 (mid-load) | +0.81 to +2.56% | mild positive bias, 4-cell coherent |
| 89–135 | −1.13 to −0.30% | near-neutral |
| 161–180 | −3.07 to −5.73% | coherent 3-cell lean band; lower residency (boost build) |
| 203–286 | mixed, max +3.76% | high-boost samples, noisier |
| 349+ g/s | flagged unused | exclude |

**Verdict: no MAF changes for 20.15.** The 161-180 band is the only candidate for a future minor bump (+3-5%) and is deferred until more samples accumulate.

**Lean-on-accel discovery (the headline new finding):**
Diagnosed across all three logs and especially log0003. 279
tip-in-shortfall lean events in 253 min (1.1/min), median lean peak
+7.22 AFR, in OL at throttle-opening transitions. Mechanism: tip-in
enrichment effectively inactive in 20.14 due to two coupled issues:

1. **Min Throttle Activation at 2.0%** (20.x value vs stock/garn 0.85%) — DBW-smoothed pedal ramps produce ~1.5-2%/sample throttle Δ, below the gate.
2. **BoostErr comp curve calibrated for stock's structurally-elevated target boost.** Stock keeps target ~5-12 psi ABOVE achievable at light-throttle/mid-RPM, so BE during transients lives ABOVE the 9.9 psi axis top (comp = 0%, neutral). The 20.x base was edited to bring target closer to achievable, which moved BE distribution into the 2-6 psi range (BE comp = −50 to −80%, suppression zone). See `project_target_boost_tipin_coupling.md` memory for the coupling.

Sample-105349 root cause walk-through preserved in
`scripts/analysis/quick_5_23_105385_drill.py` output.

**Knock map after shift-knock filter** (see
`project_shift_knock_filter.md`): 699 raw FBKC<0 reduced to **447
real load-knock samples** (36% were shift-related false positives,
including ALL of the 1600/1900 × 1.00 cells). The cleaned cluster is
2600-3700 RPM × 1.00-1.17 load, peak −8.05° at 3000/1.17. This may
partially resolve with the 20.15 tip-in fix (less transient lean →
less heat dump arriving at the transition cusp).

### 20.14 → 20.15 (staged 2026-05-23 — tip-in enrichment fix)

The full changeset, with byte-level edits to flash:

**1. Min Tip-in Throttle Activation** (`0xCC4A0`, float, %):
- 2.00 → **0.85** (match stock/garn — DBW-smoothed ramps now pass first gate)

**2. Min Tip-in IPW Activation** (`0xCC4A4`, float × 0.004 → ms):
- 1.32 ms (raw float 330) → **1.00 ms** (raw float 250)
- Lets smaller computed enrichments still apply; smooth-ramp throttle changes now have a chance to clear post-comp.

**3. Tip-in Applied Counter Threshold A** (`0xCD165`, 16 uint8, ECT-indexed):
- All 16 cells: 3 → **5** (match garn)
- Extends the enrichment window from ~160ms to ~265ms.

**4. Tip-in Applied Counter Threshold B** (`0xCD175`, 16 uint8):
- All 16 cells: 3 → **5** (paired with A)

**5. Tip-in BoostErr comp axis compression** (`0xCD128`, 9 floats × 4 bytes):
- Compresses the axis from 0-9.9 psi to **0-6.7253 psi** to fit the observed BE distribution. **DATA bytes at `0xCD14C` UNCHANGED** (preserves the Subaru-tuned S-curve shape).

| cell | current axis psi | **new axis psi** | raw float (current) | **raw float (new)** | comp % at this cell |
|---:|---:|---:|---:|---:|---:|
| 0 | 0.00 | **0.000** | 0.0000 | **0.0000** | −90.62 |
| 1 | 1.24 | **0.930** | 64.1265 | **48.0949** | −87.50 |
| 2 | 2.48 | **1.860** | 128.2531 | **96.1898** | −81.25 |
| 3 | 3.71 | **2.790** | 191.8624 | **144.2847** | −73.44 |
| 4 | 4.95 | **3.710** | 255.9890 | **191.8624** | −63.28 |
| 5 | 6.19 | **4.640** | 320.1155 | **239.9573** | −50.00 |
| 6 | 7.43 | **5.570** | 384.2420 | **288.0522** | −32.03 |
| 7 | 8.66 | **6.500** | 447.8514 | **336.1471** | −5.47 |
| 8 | 9.90 | **6.7253** | 511.9780 | **347.7985** | 0.00 |

Anything BE > 6.7253 psi clamps at comp = 0 (neutral). The tight final cell (6.50 → 6.7253, 0.23 psi span) creates a sharp "soft clamp" shoulder.

**Why this combination:**
- Throttle gate at 0.85% + IPW gate at 1.0 ms together let smooth pedal ramps with reasonable RPM comp clear the floor at moderate BE.
- Applied counter 5 doubles the enrichment window so tip-in lasts long enough to bridge the AFC-PI catch-up time.
- The BE axis compression is shape-preserving (zero data bytes change). It moves the Subaru-tuned S-curve to operate at the BE values you actually see (2-6 psi instead of 7-12 psi).
- **No changes to RPM comp.** Already aggressive in 20.x (+71% at 2800 RPM, +87% at 3600). Doesn't need a touch and adding a 5th lever hurts test attribution.
- **No changes to base Tip-in A/B tables.** 20.x values are already 17-32% bigger than stock — magnitude is fine, the gates were the bottleneck.
- **No changes to target boost map or its compensations.** This avoids re-touching the WGDC/spool work from 20.12.

**Coverage prediction:** ~30-45% of the 279 lean events should now fire tip-in (those with throttle stab ≥7% AND BE ≥ 4-6 psi). Smooth ramps under ~4-5% per sample remain blocked by the 1.0 ms IPW gate and won't fire. That's acceptable; the deepest lean events tend to be the harder stabs.

**Gates for scoring 20.15** (see `open-issues.md` for the full table):
- **G1 (primary):** tip-in-shortfall events/min: 1.10 → target **< 0.8** (a ≥30% reduction)
- **G2:** median lean peak: 7.22 AFR → target **< 6.0**
- **G3 (regression check):** CL steady cruise AFC mean shifts: must stay **within ±1.5%** (no over-enrichment in steady cruise)

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
