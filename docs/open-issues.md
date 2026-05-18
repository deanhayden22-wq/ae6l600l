# Open issues — AE5L600L tuning

Last updated 2026-05-17 after 20.12 verification drive (5-17, 6 logs, 5.7 h) and 20.13 build.
**On car right now:** 20.12 (`534720b8…`). **Staged for next flash:** 20.13 (`rom/AE5L600L 20g rev 20.13.bin`). MAF rescale work is in progress on 5-17 evidence — slated for 20.14.

Each entry: symptom → where it shows in data → what's been tried →
what's next.

This is a working list, not a final state. Update as issues open and
close per ROM rev. The same content lives in working memory and may
diverge from this snapshot.

---

## 20.12 watch — gate scoring after 5-17 drive (CLOSED 2026-05-17)

20.12 was flashed between 5-12 and 5-17. Verification drive on 5-17
produced 6 logs / ~5.7 h on `logs/5-17 20.12/` (log0002, 0003-0006,
0007 — log0002 and log0007 are full road sessions). Scoring against
the pre-drive gates:

| hypothesis | gate | actual | verdict |
|---|---|---|---|
| AVCS plateau extension softens 28-36 MPH stutter | AVCS-led cluster ≤10 in 2500-3000 × 0.20-0.30 (was 19) | per-cell cluster re-bin not yet run on 5-17 data | OPEN — needs cluster re-bin |
| AVCS plateau drops global stutter signature | `stutter_signature_per_min` 2.20 → <1.80 | 1.89 → **1.37** | **PASS** (-0.53) |
| BT retard reduces cruise-side timing oscillation | `timing_osc_per_min` 0.94 → <0.70 | 0.87 → **0.71** | **MARGINAL** (just over gate) |
| BT retard reduces OL knock events | `total_knock_per_min` <0.40, `min_fbkc_depth` shallower than -4.0° | 0.64 → 0.26 ✓; -4.2° → **-7.0°** ✗ | **MIXED** — events down but depth REGRESSED |
| Max WG spool reduction smooths boost build | attainment 0.75-0.90, no overshoot >1.05 | attn 0.77 → 0.83; peak mrp 13.56 → 9.87 psi; 0 overshoot pulls | **PASS** |

**Where the FBKC depth regression came from:** 20.12's BT retard at
2800-4150 × **2.25-4.00** missed the dominant cluster, which on 5-17
fired at 2600-3300 × **1.0-2.0** g/rev. log0007 shows:

- 2600 × 1.17: 81 FBKC<0, min -7.0°
- 2600 × 1.36-1.95: 76 FBKC<0, min -5.6 to -7.0°
- 3000 × 1.95-2.6: 89 FBKC<0, min -3.85 to -5.6°
- 3300 × 1.51-1.95: 44 FBKC<0, min -5.6 to -6.65°
- Plus 57 FLKC events at 3300-4000 × 2.0-3.0 (ratchet still firing
  in this band even though FBKC events dropped overall).

This cluster overlaps the ghost zone (2200-3300 × 1.0-1.4) and
extends both up in RPM and up in load. **Dean's response in 20.13:
richen the OL map** (rom_diff shows 426 bytes in the OL fueling block
at 0xCFD68-0xDA932 covering Primary OL Fueling + KCA variants) plus
further AVCS work. See [tune-state.md](tune-state.md) "20.12 → 20.13"
for the changeset.

**Also moved on 5-17:**
- `rpm_swing_per_min`: 2.38 → 1.07 (-1.31, big improvement)
- `throttle_hunt_per_min`: 0.50 → 0.23 (-0.27)
- `afr_osc_per_min`: 1.20 → 0.90 (-0.30)
- `ffb_wbo2_div_per_min`: 2.81 → 2.05 (-0.76)
- `maf_corr_mean_pct`: -1.08% → **+1.83%** (sign flip; 20.12 didn't
  touch MAF directly — probably long log0007 cell exposure pulled the
  pooled mean lean)
- `maf_corr_mean_abs_pct`: 1.43% → 2.39% (trim health degraded)

---

## 20.13 watch — pre-drive scoring gates (opened 2026-05-17)

20.13 is built but not flashed. These gates apply to the first
20.13-flashed log.

| hypothesis | change | win signal (next log) | target |
|---|---|---|---|
| OL richening eliminates the 2600-3300 × 1.0-2.0 FBKC depth cluster | OL fueling block 426 bytes / 26 runs at 0xCFD68-0xDA932 (Primary OL + KCA variants) | `timing_sum.min_fbkc_depth` and per-cell FBKC at 2600-3300 × 1.0-2.0 | depth shallower than -4.5°; per-cell FBKC<0 sample count at 2600×1.17 drops from 81 → <20 |
| OL richening reduces FLKC ratchet at 3300-4000 × 2.0-3.0 | (same) | `timing_sum.flkc_events_per_min` and per-cell FLKC events at 3300-4000 × 2.0-3.0 | flkc events <0.05/min (was 0.17/min on 20.12) |
| Further AVCS work tightens the AVCS-led cluster | AVCS Cruise/NC 9+8 runs (35+34 bytes) extending 20.12 plateau | `avcs_osc_per_min`; per-cell residency at touched AVCS cells | avcs_osc <1.0/min (was 1.13 on 20.12); AVCS-led cluster count at 2500-3000 × 0.20-0.30 drops further |
| OL richening doesn't blow back into pre-20.10 wbo2 lag | `ffb_wbo2_div_per_min` and at-cell wbo2-vs-FFB delta | divergence stays ≤2.5/min; no lean spikes >+0.5 AFR on partial-throttle climbs | |

**Methodology notes for the 20.13 review:**
- Re-run `python3 scripts/analysis/scorecard.py --recompute-durations` after ingesting 20.13 logs (the `--recompute-durations` flag is needed when new rom_rev_map entries land).
- For the OL richening verdict, compare per-cell FBKC<0 sample counts at the cells listed in the 20.12 cluster (above) — these are the cells the richen was sized to address.
- Per `feedback_verify_rom_changes_against_user_claims`: 20.13 rom_diff surfaces ~436 bytes across AVCS + OL fueling block. Dean announced OL richening + MAF work; the OL block matches. The AVCS edits are an additional load on top of 20.12's plateau — flag in next session if not already discussed.
- MAF rescale is NOT in 20.13. Slated for 20.14. Don't propose MAF changes until that work lands.

**If any gate fails on next log:**
- min_fbkc_depth stays at -7.0 → OL richening was insufficient at the dominant cells. Re-shape the OL targets at 2600-3300 × 1.0-2.0 by 0.3-0.5 AFR more, OR layer a BT retard on the L=1.0-2.0 columns that 20.12 missed.
- flkc events stay elevated at 3300-4000 × 2.0-3.0 → boost overshoot is reaching cells the OL doesn't cover (CL-rich region) — consider another Max WG pull in the 3000-4000 RPM band.
- avcs_osc per min doesn't move → the 20.13 AVCS edit didn't reach the dominant osc cells. Re-bin AVCS osc events by exact RPM/load and compare against the edited cell coords.
- ffb_wbo2_div regresses → check at-cell wbo2-FFB at the richened cells; OL leanout might be inverted (too rich → ECU's MAF correction loop fights it).

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

## Active — lever in flight (escalated 2026-05-17)

### Ghost-knock zone: now 2200–3300 RPM × 1.0–2.0 g/rev (5-rev + 20.11 + 20.12 persistence; OL-richen lever flying in 20.13)

- **Persistence backstory:** Knock has appeared in **every** rom_rev
  (stock + 20.7 + 20.8 + 20.9 + 20.10) in cells (2200, 1.17), (2600,
  1.0), (3300, 1.36) — 5/5 revs each. Adjacent cells 4/5. On 20.11,
  4 of 4 zone-exposed logs fired in zone at ~217 FBKC<0/zone-min vs
  20.10's 85/zone-min. **On 20.12, the cluster expanded outward and
  deepened** — 5-17 log0007 hit FBKC -7.0° at 2600×1.17 (n=81), -7.0°
  at 2600×1.36, -6.65° at 2600×1.51 and 3300×1.51, plus 57 FLKC events
  in the adjacent 3300-4000 × 2.0-3.0 band. Reframing the zone as
  **2200-3300 × 1.0-2.0** per 20.12 evidence (the old "1.0-1.4"
  framing was too narrow).
- **What 20.12 tried and missed:** BT retard at 2800-4150 × 2.25-4.00
  + AVCS plateau extension at 0.20-0.30 + Max WG cut. The BT retard
  was applied at L=2.25-4.00 — one load band ABOVE where the cluster
  actually fired (L=1.0-2.0). Total knock events dropped (0.64 →
  0.26/min) but FBKC depth got worse (-4.2° → -7.0°) because the
  dominant cluster never got addressed.
- **20.13 lever in flight (built 2026-05-17, not flashed):** OL
  fueling richen — 426 bytes in 26 runs across the OL block
  (0xCFD68-0xDA932), covering Primary OL Fueling + KCA Alternate Mode
  + KCA Additive B Low/High + Failsafe variants. Plus further AVCS
  edits (35+34 bytes across Cruise + Non-Cruise) extending 20.12's
  plateau work. Scoring gates in the "20.13 watch" section above.
- **Stock-vs-20.10 table compare in this zone (kept for reference):**

  | Table | Comparison |
  |---|---|
  | Base Timing Cruise | ±2° (similar) |
  | Base Timing Non-Cruise | 20.10 is **5–17° LESS** than stock at load=1.0 (already conservative) |
  | KCA Max Cruise | 20.10 = 0° at load=1.0 (was 3–4° on stock); recovery disabled |
  | AVCS Cruise/Non-Cruise | 20.10 is **+5 to +11° more advance** than stock (10–15° → 20–23.5°) — flagged in early sessions as likely contributor |
  | OL Fueling | NOW APPLIES — load extension into 1.5-2.0 + FLKC ratchet at 3300-4000 × 2.0-3.0 puts the cluster squarely into OL territory; that's why 20.13's lever is OL-side |

- **Open levers if 20.13 OL richen is insufficient:** (a) layer BT
  retard on L=1.0-2.0 columns at 2600-3300 (which 20.12's L=2.25-4.00
  retard missed), (b) revert some of 20.11's MAF rescale (the rescale
  improved trim health but coincides with the 20.11 ghost-zone
  intensification — Dean is doing MAF analysis separately for 20.14),
  (c) AVCS-toward-stock in 2200-3300 × 1.0-1.4 (-5 to -11°).
- **Workflow:** New log → `python3 scripts/analysis/log_review_ingest.py
  --log <path> --date <YYYY-MM-DD> --rom <rev>` → re-run scorecard
  with `--recompute-durations` → check per-cell FBKC<0 counts at the
  cluster cells listed above.

---

## Open (from 4-27 chat, 2026-04-28; updated through 20.12 evidence)

### Knock at high-RPM mid-load OL after 20.10 OL leanout — folded into ghost-zone lever for 20.13

- **Symptom history:** 4-27 logs showed 9–34% knock samples in
  3500–5500 RPM × 0.7–1.6 OL; 5-10/log0003 ratcheted FLKC=-1 across
  two WOT pulls at 4000-4400 × 1.5-3.2; 5-11/log0001's WOT pull hit
  FBKC -1.4 / FLKC -1.0 at 4039-4497 × 3.43-3.86; **5-17 log0007 shows
  57 FLKC events at 3300-4000 × 2.0-3.0 — the cluster is still active
  on 20.12.**
- **20.12 partially addressed it:** BT retard at 2800-4150 × 2.25-4.00
  + Max WG cut. Total knock event rate dropped (0.64 → 0.26/min); peak
  mrp dropped 13.56 → 9.87 psi. But FBKC depth got worse (-4.2° →
  -7.0°) and FLKC events stayed (57 on 5-17 vs 26 on 20.11).
- **Now coupled with the ghost zone.** The 5-17 cluster spans
  2600-4000 RPM × 1.0-3.0 load — the historical "ghost zone" and the
  "post-20.10 OL knock" are not separate clusters anymore. Both folded
  into the same 20.13 OL-richen lever (see ghost-zone entry above).
- **Status:** Open, lever flying in 20.13. If 20.13 doesn't move the
  3300-4000 × 2.0-3.0 FLKC ratchet specifically, the open levers are
  another Max WG pull in 3000-4000 RPM or a layered BT retard on
  L=2.0-3.0 (which 20.12 covered at L=2.25-4.0 only — the 2.0 column
  is just outside).

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

### AFR cmd-vs-actual delta — now MAF analysis is the work item for 20.14

- **History:** Steady-state OL operation in 4000-4500 × 0.7-1.3 showed
  engine ~+0.22 AFR richer than cmd on 4-27 (20.10); improved to +0.14
  in early 20.10 amendments but never zeroed. 20.11 MAF rescale moved
  trim health right direction (in_tol 50% → 82-89%) but didn't
  resolve. 5-11 showed engine -0.34 AFR LEANER than cmd at adjacent
  high-load OL cells (3750-4250 × 1.3-3.4) — sign flipped at different
  cells. 5-12 showed a new mid-V slope walk at V=1.91-2.45 (engine
  3-4% richer than cmd in that band).
- **5-17 / 20.12 read:** Pooled `maf_corr_mean_pct` flipped again:
  -1.08% on 20.11 → +1.83% on 20.12 (engine now ~2% leaner than cmd
  on average). Trim health degraded: `maf_corr_mean_abs_pct` 1.43% →
  2.39%. 20.12 didn't touch MAF — the shift is from drive context
  (long log0007 sat in cells where wbo2 ran lean of FFB).
- **Status (2026-05-17):** Dean is doing manual MAF analysis on the
  5-17 evidence — "a lot of info, going to take some time". Slated for
  20.14, NOT in 20.13. Until then, don't propose MAF table changes.
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
