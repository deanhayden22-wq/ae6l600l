# Open issues — AE5L600L tuning

Last updated 2026-05-08 after 5-8 log review and Dean review pass.
Active rev: **20.11**.

Each entry: symptom → where it shows in data → what's been tried →
what's next.

This is a working list, not a final state. Update as issues open and
close per ROM rev. The same content lives in working memory and may
diverge from this snapshot.

---

## Staged for verification (opened during pedal-tuning, 2026-04-27/28)

### Cruise pedal hunting at 12–22% APP / 2700–3300 RPM

- **Symptom:** `4-24/log0004.csv` (50.9k samples) shows constant pedal
  correction in cruise zone. Heatmap of APP-direction-reversal events
  from 13 logs (656k samples, 12,202 events): worst cell APP 15–18% /
  RPM 3000–3300 = 392 over-response events (driver pulled back); paired
  under-response peak at APP 9–12% / RPM 3000–3300 = 389 events. Net
  heatmap shows hunting around ~14% APP — pushes to 17%, overshoots,
  pulls to 12%, under-shoots, pushes back. Classic too-steep-slope-in-
  cruise-zone signature.
- **Where:** Sport pedal map (0xF99E0) col 3 (16.5% APP) — RQTQ jumps
  from 42 (10% APP) to 165 (16.5% APP) at 3200 RPM = slope 18.8 RQTQ
  per 1% pedal. With 0.39% APP LSB pedal jitter, that's 7.2 RQTQ per
  LSB → through ratio→TPS that's enough to move throttle by detectable
  amounts.
- **Tried:** v9 design + Dean's tweaks, flashed/staged but not yet
  driven & logged. Uniform multipliers across all driving rows: 10%
  APP × 1.30 (raise — under-response), 16.5% APP × 0.85 (lower —
  over-response), 25% APP × 0.92 (mild lower). Cliff slope cut to
  ~13 RQTQ/% at 3200 RPM. Cols 5+ (31% APP onward) preserved from 20.8.
  WOT trigger pushed to 80% APP at RPM ≥ 2000 by Dean's x-axis edit
  (was 86.7% APP); 100% APP only at RPM < 2000.
- **Confound:** under-response cluster at 9–12% APP / 2700–3300 RPM is
  **turbo-spool-limited, not pedal-map-limited** — see
  [turbo-character.md](turbo-character.md). v9 may shrink the
  over-response cluster (cliff fix should reduce overshoot) but the
  under-response cluster will likely persist, and that's expected.
- **Next:** Drive v9, log it, re-run pedal-correction event detection
  (per [methodology/pedal-correction.md](methodology/pedal-correction.md)).
  Expected: over-response cluster at 15–18% APP / 3000–3300 shrinks
  below ~150 events. If it shrinks to that, close as resolved. If still
  hunts, raise multiplier asymmetry (e.g., 1.35/0.82 instead of 1.30/
  0.85) — limit is monotonicity at 800 RPM row.

### Marginal 2000 RPM × 80% APP cell (ratio at 1.001)

- **Symptom:** v9 + Dean's edits put RQTQ 250.3 at 2000 RPM × 80% APP,
  vs Base[2000]=250 → ratio = 1.001. Just barely past the WOT trigger
  (ratio ≥ 1.0). DBW PID could oscillate around that boundary if pedal/
  RPM noise pushes ratio just below/above 1.0.
- **Watch in next log:** look for hunting specifically at 80% APP /
  2000 RPM. Likely won't be an issue in practice (you'd usually be
  transiting through, not parked at it) but worth flagging.
- **If it shows:** Either raise the cell to ~260 (decisively WOT) or
  lower to ~245 (decisively non-WOT). Pick a side of the ratio=1.0
  cliff.

### Low-RPM under-response is fundamentally turbo-lag bound

- **Symptom:** Response-lag analysis on 13 logs (656k samples) — see
  [turbo-character.md](turbo-character.md) for the table.
- **Where:** 20G doesn't spool until ~3000 RPM; boost attainment ratio
  averages 0.38 across this band. Even WOT, the engine isn't making
  boost yet. **No pedal map can fix this.**
- **Lever (NOT in pedal map):** Target Boost (0xC1340), Initial WG Duty
  (0xC1150), Max WG Duty (0xC0F58), AVCS at cruise/light-load.
- **Status (2026-05-08):** Dean reports drive on 20.11 felt good in
  this regime ("really good today"). Provisionally close, but verify
  on next drive before retiring — 5-8 log had no sustained WOT pulls
  and didn't hit the response-lag conditions head-on. One more log
  with deliberate low-RPM tip-ins, then close if subjective and
  measured response both look fine.
- **If next log confirms:** Close as accepted. Boost-control table
  review (Round 2) deferred — only revisit if a regression appears.

---

## Observation phase (opened 2026-05-03)

### Ghost-knock zone: 2200–3300 RPM × 1.0–1.4 g/rev (5-rev persistence)

- **Symptom:** Knock has appeared in **every** rom_rev (stock + 20.7 +
  20.8 + 20.9 + 20.10) in cells (2200, 1.17), (2600, 1.0), (3300,
  1.36) — 5/5 revs each. Adjacent cells in zone hit 4/5. Source:
  `scripts/analysis/trends/knock_by_cell.csv` from 11-log backfill.
- **Stock-vs-20.10 table compare in this zone:**

  | Table | Comparison |
  |---|---|
  | Base Timing Cruise | ±2° (similar) |
  | Base Timing Non-Cruise | 20.10 is **5–17° LESS** than stock at load=1.0 (already conservative) |
  | KCA Max Cruise | 20.10 = 0° at load=1.0 (was 3–4° on stock); recovery disabled |
  | AVCS Cruise/Non-Cruise | 20.10 is **+5 to +11° more advance** than stock (10–15° → 20–23.5°) — flagged as the most likely contributor to persistence |
  | OL Fueling | doesn't apply (this zone runs CL=8 in logs) |

- **Decision (Dean, 2026-05-03):** Hold further table changes. Existing
  20.x timing + AVCS smoothing is in place; observe whether it resolves
  before iterating.
- **How to apply:** Do **not** propose new edits to Base Timing / AVCS
  / KCA in 2200–3300 / 1.0–1.4 until at least one fresh log on the
  currently-flashed rev has been ingested. Watch for reduction in
  `event_count_fbkc` per cell across new logs in `knock_by_cell.csv`.
  If knock persists or grows after 2–3 fresh logs on flashed rev,
  revisit with AVCS-toward-stock as the leading candidate.
- **Workflow:** New log → `python3 scripts/analysis/log_review_ingest.py
  --log <path> --date <YYYY-MM-DD> --rom <rev>` → diff
  `trends/knock_by_cell.csv` against prior rev rows.

---

## Open (from 4-27 chat, 2026-04-28)

### Knock at high-RPM mid-load OL after 20.10 OL leanout

- **Symptom:** 4-27 logs show 9–34% knock samples in 3500–5500 RPM ×
  0.7–1.6 load OL cells; pre-20.10 these were 0.0%. Worst cell
  3500–4500 / 1.3–1.6 → 34.1% (n=85, FBKC min −2.10°).
- **Confound:** 20.10 also changed timing (Base Timing Primary +
  Reference, Cruise + Non-Cruise) and AVCS (Intake Cam Advance Cruise
  + Non-Cruise) — knock cannot be attributed to OL leanout alone.
- **Next:** disentangle by either (a) reverting just the OL leanout in
  20.11, or (b) reverting just the timing/AVCS changes — observe which
  restores knock margin.

### Tip-in enrichment expires before AVCS finishes ramping (post-DFCO) — CLOSED on 5-8 evidence (2026-05-08)

- **Original symptom:** `4-27 20.10/log0003.csv` showed AVCS ramping
  0→23° over ~2.5s after DFCO; AFC accel enrichment expired partway
  through; knock fired while AVCS still mid-ramp (FBKC min -7.0,
  70 fbkc<0 samples in the post-DFCO window). AVCS ramp rate ~18°/s.
- **Lever (kept on file):** Extending AFC decay rate / magnitude tables
  would keep fuel-cooling active during the AVCS ramp window. Def XML
  analysis exists at `disassembly/analysis/accel_enrichment_analysis.txt`.
- **Re-screen on 5-8 20.11 (2026-05-08):** 33 post-DFCO tip-ins detected
  (DFCO via AFR=20.33, APP rise ≥5% within 1s of exit). Of those, 9 had
  cold AVCS at exit (≤2°) — the structural match to the original. **3 of
  9 hit the original prerequisite (AFC expired before AVCS reached 90% of
  peak); 0 of 9 produced any FBKC<0.** Cleanest match: t=2065.12, AVCS
  1→23° over 1.76s, AFC active 0.96s — no knock. Trend file
  `scripts/analysis/trends/postdfco_tipins_5_8.csv`.
- **One residual event:** t=420.84 had FBKC down to -2.8 in the post-DFCO
  window, but AVCS exit was 18° (already advanced) and knock fired at
  avcs=19° AFTER ramp completed — high-load spool tip-in pattern, not
  AVCS-ramp pattern. Severity also lower than original (-2.8 vs -7.0).
- **Cross-check on full-log knock distribution:** 196 of 276 FBKC<0
  samples in 5-8 fall within 3s of a DFCO exit, but 187/196 (95%) at
  AVCS >15° (settled). 0 samples at AVCS ≤5°. Post-DFCO knock in this
  log is ghost-zone knock, not AVCS-ramp knock.
- **Caveat:** n=9 cold-AVCS events from a single 30-min log. Reopen if
  a future log shows knock during a cold-AVCS post-DFCO ramp.

### +0.22 AFR cmd-vs-actual delta in 4000–4500 cell (engine richer than commanded)

- **Symptom:** Steady-state OL operation in 4000–4500 RPM × 0.7–1.3
  load shows engine delivering ~0.22 AFR richer than FFB commands
  (improved to +0.14 in 20.10 but not eliminated).
- **Hypothesis:** MAF over-read, or injector flow scaling overestimating
  delivered fuel mass.
- **Plan for 20.12 (Dean, 2026-05-08):** MAF rescale targeted for the
  20.12 rev. Pre-rescale workflow: pull MAF g/s vs commanded AFR
  delta from 5-8 log (and prior backfill where comparable conditions
  exist) → identify breakpoints needing adjustment → emit a proposed
  MAF curve diff before flashing. Trends data already in
  `scripts/analysis/trends/maf_corr_by_mafcell.csv` and
  `maf_scaling_breakpoints.csv` — start there.
- **Coupling note:** AVCS edits in cruise zone don't materially shift
  MAF readings (median |ΔMAF| 1.7% across 20.9→20.10 cross-rev diff
  at fixed pedal). Safe to iterate MAF independent of cruise AVCS.

---

## Open (earlier sessions)

### Cruise-zone advance cliffs — analyze on the COMBINED map (BTC + KCA·IAM)

**Methodology change (Dean, 2026-05-08):** Stop scoring Base Timing
Cruise (BTC, 0xd4714) and Knock Correction Adv Max Cruise (KCA, 0xd5904)
as separate cliffs. The advance the engine actually sees in cruise is
**Sum = BTC + (KCA × IAM)**, with IAM=1.0 at no learned-knock damage.
Score cliffs on the Sum map.

**Sum at 0.94→1.20 boundary (20.11, IAM=1.0):**

| RPM | BTC@.94 | KCA@.94 | Sum@.94 | BTC@1.20 | KCA@1.20 | Sum@1.20 | ΔSum |
|----:|--------:|--------:|--------:|---------:|---------:|---------:|-----:|
| 1600 | 16.91 | 0.00 | 16.91 | 10.23 | 5.27 | 15.51 | **−1.41** |
| 1900 | 18.67 | 0.00 | 18.67 | 11.64 | 5.27 | 16.91 | **−1.76** |
| 2200 | 19.38 | 0.00 | 19.38 | 12.70 | 4.57 | 17.27 | **−2.11** |
| 2600 | 20.43 | 0.00 | 20.43 | 14.10 | 4.57 | 18.67 | **−1.76** |
| 3000 | 20.78 | 0.00 | 20.78 | 14.45 | 4.57 | 19.02 | **−1.76** |
| 3300 | 21.48 | 0.00 | 21.48 | 15.16 | 4.57 | 19.73 | **−1.76** |

The 0.94→1.20 boundary **does not stack** — BTC drops ~−6.5° but KCA
rises +4.6 to +5.3° (KCA Cruise has zeros across the 0.27/0.50/0.65/0.94
columns then jumps to ~5°). Net Sum cliff is only −1.4 to −2.1°. The
prior "stacking ~10° swing" framing in earlier notes was wrong — they
oppose, not stack.

**Largest Sum cliffs in the cruise zone are at 0.65→0.94** (KCA = 0 on
both sides, so it's pure BTC):

| RPM | Sum@.65 | Sum@.94 | ΔSum |
|----:|--------:|--------:|-----:|
|  800 | 19.38 | 11.64 | **−7.73** |
| 1200 | 21.84 | 16.21 | **−5.62** |
| 1600 | 22.54 | 16.91 | **−5.62** |
| 1900 | 23.95 | 18.67 | **−5.27** |
| 2200 | 24.65 | 19.38 | **−5.27** |
| 2600 | 25.70 | 20.43 | **−5.27** |
| 3000 | 26.05 | 20.78 | **−5.27** |
| 3300 | 26.41 | 21.48 | **−4.92** |

**Priority:** Cruise residency at 0.65 column is also limited (light
loads), so this cliff matters mainly when load briefly transits across
it during pedal modulation. Lower priority than the 5-8 ghost-zone
knock issue.

**Next when revisiting:** Soften the 0.65→0.94 column step in BTC by
shaving 1–2° from the 0.65-column rows in the 800–2200 RPM band, so
Sum delta moves into the −3 to −4° range. Don't touch the 0.94→1.20
boundary unless KCA is also re-shaped at the same time.

**Tooling todo:** Add Sum-map computation to `cross_rev_diff.py` /
new helper, so cliff scoring is always done on Sum, not on BTC and
KCA separately.

---

## Closed / resolved (kept for verification trail)

### Intake AVCS Cruise — oscillation in steady cruise

- **Resolved in 20.10** — cliff count 55 → 37, cruise-on-cliff cells
  dropped to 3.
- **Status:** Dean confirmed "nailed it" per cruise-smoothness session.

### AVCS pinned at 0° in non-cruise high-load (load 1.0–1.4 × RPM 3000–4500)

- **Original symptom:** `4-27 20.10/log0002.csv` showed AVCS at 0°
  during 6-second steady tip-in; knock at upper end.
- **Resolution (Dean, 2026-05-08):** Caused by ECU restart, not a
  table value. AVCS was sitting in the post-restart re-learn / warm-up
  state; not a calibration issue.
- **Status:** Closed. If pattern reappears in a log without a recent
  restart event, reopen.
