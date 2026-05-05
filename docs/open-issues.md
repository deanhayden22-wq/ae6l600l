# Open issues — AE5L600L tuning

Captured 2026-05-04. Active rev: **20.11**.

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
- **Next:** Round 2 after v9 verification — boost-control table review.
  Need a fresh log on v9 first to understand the new operating-point
  distribution before changing boost strategy.

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

### AVCS commands 0° in non-cruise high-load (load 1.0–1.4 × RPM 3000–4500)

- **Symptom:** `4-27 20.10/log0002.csv` shows AVCS pinned at 0° during
  6-second steady tip-in acceleration; knock fires at the upper end.
- **Where:** Non-cruise path of AVCS (table 0xdac34 per project XML;
  Dean changed this in 20.10).
- **Hypothesis:** Either Dean's 20.10 AVCS Non-Cruise edit set this
  region to 0°, or it was already 0° pre-20.10 and the OL leanout
  exposed the marginality.
- **Next:** extract Intake Cam Advance Non-Cruise from 20.9 vs 20.10
  bins; compare cells in 3000–4500 RPM × 1.0–1.4 load.

### Tip-in enrichment expires before AVCS finishes ramping (post-DFCO)

- **Symptom:** `4-27 20.10/log0003.csv` shows AVCS ramping 0→23° over
  ~2.5s after DFCO; AFC accel enrichment expires partway through; knock
  fires while AVCS still mid-ramp.
- **AVCS ramp rate observed:** ~18°/s.
- **Lever:** Extending AFC decay rate / magnitude tables would keep
  fuel-cooling active during the AVCS ramp window.
- **Next:** locate accel enrichment decay/magnitude tables in def XML
  (analysis already exists per
  `disassembly/analysis/accel_enrichment_analysis.txt`).

### +0.22 AFR cmd-vs-actual delta in 4000–4500 cell (engine richer than commanded)

- **Symptom:** Steady-state OL operation in 4000–4500 RPM × 0.7–1.3
  load shows engine delivering ~0.22 AFR richer than FFB commands
  (improved to +0.14 in 20.10 but not eliminated).
- **Hypothesis:** MAF over-read, or injector flow scaling overestimating
  delivered fuel mass.
- **Next:** check injector flow scaling table value vs known injector
  size; check for any RPM-bin-specific MAF cal anomaly.

---

## Open (earlier sessions)

### Base Timing Cruise (1900, 0.94) vs (1900, 1.20) cliff

- **Symptom:** 20.10 base timing cruise edits bumped (1900, 0.94)
  +1.05° without touching (1900, 1.20) → load-direction cliff grew to
  7.03°.
- **Priority:** Lower — cruise residency at (1900, 0.94) is only ~7s
  on the 4-25 baseline.
- **Next:** Soften when revisiting base timing.

### Knock Correction Adv Max Cruise — 4.57° cliff at 0.94→1.20 (2200–3300 RPM)

- **Stacks with** base timing cliffs at the same boundary.
- **Combined swing** ~10° if load wanders across.
- **Next:** smooth at next cruise-tuning iteration.

---

## Closed / resolved (kept for verification trail)

### Intake AVCS Cruise — oscillation in steady cruise

- **Resolved in 20.10** — cliff count 55 → 37, cruise-on-cliff cells
  dropped to 3.
- **Status:** Dean confirmed "nailed it" per cruise-smoothness session.
