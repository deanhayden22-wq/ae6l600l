# Open issues — AE5L600L tuning

Last updated 2026-06-05 — 20.17a driven 6-5 (`logs/6-5 20.17a/log0001.csv`, 32 min, thin cusp data): **the cusp lean/knock is NOT a tip-in fuel deficit** (G1 barely moved despite +2 ms more IPW; deep FBKC is overrun noise) → move to the load/timing/AVCS substrate. See "20.17a watch". Still **part-throttle only — 3rd log running with no real boost** (peak 13.77 psi), so the 20.17 top-end / 17-psi FLKC fix is STILL untested (WOT test pending). 20.15 tip-in fix was a real ~18% gain; tip-in is now ~3× lifted at the cusp via 20.17a BE-comp but the residual lean is wall-wetting, not fuel.
**On car for 6-5:** 20.17a *as-driven* = BE-comp lift + an accidental `0xCC4EC` decel-tier change (reverted post-drive). **On-disk `rom/AE5L600L 20g rev 20.17a.bin` is now BE-comp-only**, staged for the weekend long drive. (Underlying 20.17 base: target → ~17 to arm Turbo Dynamics + WGDC down + TD-negative up + per-gear 5th timing comp + OL richen; TD-arm confirmed 6-3, high-load knock fix still UNTESTED.)
**Prior P0s (from 20.16, still open):** ghost-zone −11.8° knock (2200-3300 × 1.0-1.4) + injector IDC >100% at top end — see "20.16 watch". (6-3 in-zone IDC was fine at 54-62%, but that was part-throttle, ≤14.3 psi.)
**MAF rescale:** CLOSED — Dean's 378k-sample offline check showed the current curve is converged in the cruise band. No changes needed.

Each entry: symptom → where it shows in data → what's been tried →
what's next.

This is a working list, not a final state. Update as issues open and
close per ROM rev. The same content lives in working memory and may
diverge from this snapshot.

---

## ACTIVE — shift/overrun knock mitigation (opened 6-7, investigation 6-7/6-8)

**Symptom:** deep FBKC chains (−4 to −10.85°) triggered by shift/DFCO-resume
rattle, not real knock. 6-7 first-instance data: 52% of SHIFT/MAYBE fires within
1.0 s of DFCO-resume vs 3% of real LOAD-class — time-since-resume separates the
populations 17:1; load does NOT (4/10 deep shift events at load ≥1.3, incl. both
worst). Cost is real: recovery is +0.35°/0.56 s, so a false −8.4° = ~13 s of
degraded timing right after a shift.

**Rejected:** raising FBKC min load to 1.3 (Dean's first instinct). FLKC's own
floor is 1.25/1.30 (0xD2F7C), so 0.95–1.3 would have NO knock response at all —
and that band holds 80% of real LOAD-class knock incl. the −10.15 steady cusp
chain. Also misses both worst shift events (load ≥1.3). Note: FBKC min load was
already raised 0.75/0.80 → 0.95/1.00 in 20.x; garn runs 1.0/1.05 but pairs it
with FLKC floor LOWERED to 0.95 (continuous coverage — different architecture).

**Primary lever found (6-7/6-8 disassembly + cross-ROM survey):** factory
post-transient knock window, dormant on WRX cals. Window B (0xD29C4, uint16)
= 438 on every STI cal checked, 0 on every WRX cal. While active it bleeds the
knock accumulator (FFFF7FBC) by 0.015/tick (0xD2BCC/0xD2BD0). Full trace:
`disassembly/analysis/transient_knock_window_trace.txt`. ECUFlash defs added
2026-06-08 ("Post-Transient Knock Window A/B Length", "...Accumulator Bleed
A/B" + 2 alt-path bleeds). Survey data: `rom/reference/README.md`.

**Open before flash:** effect SIGN unproven (noise-floor adder → sensitizes vs
evidence-integrator → desensitizes); event-B source untraced; tick unit
unverified (~8 ms family → 438 ≈ 3.5 s). Either sign is engine-safe to A/B.

**Plan (Dean to schedule):**
1. 20.18 candidate = single-variable: arm window B 0 → 438 (factory STI value,
   bleed untouched). Purpose of first log = sign determination via shift-class
   fires/min vs 6-7 baseline (`trends/zone_fire_rates.csv` + knock_shift_filter).
   Do NOT soften (438/2 or 0.015/2) on the first test — weakens the signal;
   tune duration only after the direction is known.
2. Fallback/companion lever (proven plumbing): FBKC no-knock advance delay
   0xD29DE 70 → 35 — halves false-pull duration (13 s → 6.5 s from −8.4°).
   Hold for 20.19 to keep attribution clean.
3. Next disassembly session: FFFF7FBC comparison consumer (sign, static), flagB
   writer (event B), ctrB incrementer (tick unit), FFFF65C1 writer (the other
   inhibit's duration source).

## ACTIVE — steady-state cusp knock: substrate work (opened 6-7)

**6-7 BIG log (502 min, fixed bin) settled the 20.17a test — see `tune-state.md`
"20.17a verification drive (6-7 BIG)".** Outcomes:
- **NOT a tip-in fuel deficit (final):** non-DFCO stab-lean flat at 1.71 AFR across
  ~3× BE-comp authority. Tip-in fuel thread CLOSED.
- **Steady-state cusp knock confirmed** at 12x residency: 1.70 fires/min in steady
  context, typical −1.4°, one fueled chain to −8.05 (episode −10.15) at 2140-2270 ×
  ~1.15. The "transient-only" comfort from 6-3 was a test-power artifact.
- **Decel-tier oopsie confirmed as the deep-overrun-FBKC feeder** (0.124/min on the
  6-5 bin → 0.016/min after revert). CLOSED.
- **Next lever: load/timing/AVCS substrate at 1600-3000 × 1.0-1.25.** Candidates
  from the 6-3 deep dive: 20.x added AVCS advance / pulled-base-timing interaction
  at the cusp; design a single-variable test. Do NOT stack with the pending
  injector/boost work.
- Cross-rev metric note: use `trends/zone_fire_rates.csv` fires/min (first-instance)
  for any cusp/ghost rate claim; the legacy samp/min metric double-counts retard-holds.

## 20.17a watch — tip-in cusp-knock TEST — CLOSED 2026-06-07 (settled by 6-7 BIG log)

**6-5 first read (`logs/6-5 20.17a/log0001.csv`, 32.3 min, thin cusp data — DECISIVE branch fired: NOT fuel).**
Sanity PASS (AVCS p95 20°, IAM 1.0, FLKC 0). 3rd log running with **no real boost**
(peak mrp 13.77 psi) — top-end still untested. **G1 FAIL** (cusp stab-lean 2.24 → 2.08;
real non-DFCO 1.76) *despite tip-in firing +2.05 ms more IPW* — the residual lean is
wall-wetting/sensor-lag, not deliverable fuel. **G2 no fuel-attributable change** —
shift/overrun-filtered, no real cusp knock deeper than −1.4°; the scary −8.40° FBKC is
overrun noise at −1.2 psi vacuum. G3b IDC 70% PASS; G3a cruise AFC −1.8% WATCH; cold
over-richness did not appear (+0.25 AFR warmup tip-ins). **Read: the cusp lean/knock is
NOT a tip-in fuel deficit → move to the load/timing/AVCS substrate, not more tip-in fuel.**
Two caveats keep it formally open: cusp residency was only 0.59 min (low power), and the
as-driven bin carried an **accidental `0xCC4EC` decel-tier change** (2250/3000/4500 →
1000/2000/3500, reverted post-drive — on-disk bin is now BE-comp-only). **Weekend long
drive on the clean bin settles it.** Full scoring in `tune-state.md` "20.17a verification
drive (6-5)" + `REVIEW_LOG.md` 6-5 entry.

Perceived "tip-in knock" lives at **1600-3000 RPM × load 1.0-1.25**. Deep dive on the 6-3 20.17 log established two things that reframe it:

- **It's transient-bound, not steady** — 1.04 min of steady cusp cruise fired 0 knock; all fires followed a stab/load-change at the *same* load steady cruise sits at calmly. Knock fires at near-commanded mixture ~0.5 s after the acute lean (which is largely wbo2 recovering from fuel-cut).
- **It's probably NOT a tip-in fuel deficit** — 20.x already runs MORE tip-in than stock on every lever and sees the same BE at stab (~2.3 psi), yet **stock had ZERO cusp transient knock**. Likely the built-engine/20G airflow transient into knock-marginal cells. Memory: `[[cusp-transient-knock-is-not-a-tip-in-fuel-deficit-likely-hardware-transient]]`.

**20.17a = single-variable test.** Only the BE-comp DATA (`0xCD14C`) low-BE cells were lifted (−88/−58/−40/−25/−14/−7/−3/−1/0; ~3× tip-in at the cusp, deep-settled unchanged). Full byte table + rationale in `tune-state.md` "20.17 → 20.17a".

- **Gates:** G1 cusp stab-lean 2.24 → <1.5; G2 fewer cusp transient knock-fires, nothing deeper than −2.8°; G3 steady AFC ±1.5%, IDC <85%, watch cold richness.
- **DECISIVE:** lean drops but knock persists → it was never fuel; stop touching tip-in, look at load/timing substrate. Both drop → fuel was the lever. **Do not move AVCS yet** (possible original cliff cause).
- Dead ends ruled out this session: `cc4ec` is a decel-fuelcut tier boundary (not an overrun-cut lever, mislabeled); raising base/RPM-comp/gate further is fighting a system already richer than stock.

## 20.16 watch — TWO P0 REGRESSIONS (5-30 drive) — OPEN

20.16 (Target Boost raise + base-timing pull) flashed and driven 2026-05-30 (`logs/5-30 20.16/log0001.csv`, 48.8 min). Two P0s, neither learned-damaging yet (IAM 1.0, FLKC 0 all log) but both one repeat from harm.

### P0-1: Ghost-zone knock REGRESSION (2200-3300 × 1.0-1.4) — NOT REPRODUCED on 20.17/20.17a (6-7 update)
- **6-7 update:** under the consistent first-instance metric (`zone_fire_rates.csv`),
  ghost-zone fires/min: 20.16 **17.7** → 20.17 2.33 → 20.17a 2.27 pooled (1.97 on the
  502-min 6-7 log). No −11.8 events since 5-30; IAM 1.0 throughout. The 20.16 spike was
  real and the 20.17 boost-path reshape removed the trigger. Residual 2/min sits slightly
  above the 20.12-20.15 era (0.6-1.7) — folded into the steady-cusp substrate thread above.
  Downgraded from P0; keep the cell on watch in each review.
- **Symptom:** FBKC ratcheted to **−11.80°** twice in 1.5 s on the same 2627 × 1.05 cell (coast→spool tip-ins). Ghost-zone FBKC<0 rate **156 samp/min vs 20.15's 24.2 (6.4×)**; ~50/min even excluding the −11.8 cluster.
- **Mechanism:** the 20.16 Target Boost raise spools harder into the un-protected ghost-zone cells. The 20.16 base-timing pull sits one load band ABOVE where the cell fires (it covers 1.67-2.37, the cell is at 1.05) so it does nothing here.
- **Candidate levers (pick one to attribute):** (a) extend the base-timing pull DOWN to L=1.0-1.2 at R=2400-3000; (b) pull AVCS back from the 19-20° plateau at that cell; (c) roll Target Boost back at the cells feeding the harder spool.
- **Note:** 20.17 does NOT address this — its Target Boost edits are top-end; the ghost-zone cells are unchanged on the logged pedal paths.

### P0-2: Injector IDC saturation >100% — CEILING NOW MEASURED (6-7 update)
- **6-7 update:** IDC peaked **85.5% at 57% throttle** (5204 RPM, 17.7 psi, MAF 4.08 V) —
  no >100% repeat, but the margin to saturation at full pedal is gone. Injector swap remains
  BLOCKING for sustained top-end work; one diagnostic WOT pull is acceptable exposure,
  repeated pulls are not.
- **Symptom:** IDC hit **101.86%** at partial throttle (TPS 54%, 4923 RPM, 17.68 psi). 3 samples ≥100%, 49 ≥85%. IPW 24.83 ms at 4923 RPM = duty ≥100%.
- **Cause:** the 20.16 boost raise pushes the current injectors past their physical limit. Fuel — not knock — is now the top-end ceiling under 20.16 targets.
- **Status:** injector swap (already on the horizon) is now **blocking** further boost work. 20.17 raises top-end boost further, which makes this worse unless new injectors are on-car or OL-KCA leans the top-end (see tune-state "20.16 → 20.17" tension).

### AFL drift — WATCH, REPRODUCES FROM CLEAN SLATE (6-7 update: fresh-reflash re-learned 0 → −2.34 over 8 h; AFC not clamping; per-cell MAF corr mild ≤2.2%; fold into pre-injector-swap MAF baseline refit rather than standalone fix)
- **Symptom:** long-term fuel trim has walked monotonically 0 → 0 → −1.07 → −2.34 median across 20.13 → 20.14 L1 → 20.14 L3 → 20.15, and held at −2.34 on 20.16 (not deepening, not reverting). Engine learned-rich; >|2%| on ~53% of CL samples.
- **Candidates:** MAF over-read in the cruise V-range (floor at V=1.6-2.0), injector-flow drift, or fuel-pressure drift. ROM hasn't touched MAF scaling, so this is hardware/sensor drift.
- **Next:** if it holds ≤ −2.0 for one more log, plan a MAF mid-V investigation against WB residuals (Josh F exp fit per `feedback_maf_no_cellwise_patches.md`).

### FLKC −1.75 in 3400-3800 × high-load OL — MECHANISM SOLVED (6-04), WOT TEST STILL PENDING (6-7: no 3400-3800 WOT exposure; NEW sibling cluster at 2800-3250 × 1.2-1.5, transient −1.0, fully recovered — 2nd instance of the boost-transition-band FLKC family)
- **What it is (solved this session):** genuine knock from the boost OVERSHOOT. The 5th-gear target was capped at 12.7 (below the 15 psi spring), so boost floored at the spring and ran UNCONTROLLED to 17-18 psi; 17 psi at 3400-3800 is knock-limited to ~7.5-8° and FLKC (the per-cell *Fine Correction* — retard 1.01 / adv 0.25 / delay 90, grid `0xD2F0C`/`0xD2F28`) pulled to −1.75. FLKC is INDEPENDENT of FBKC and load-gated; knock detection has NO boost/MAP input — **but the mechanism stated here was wrong and is corrected**: `0xAE284` is a 1-D knock-signal TRANSFER CURVE (65 pt float32, data 0..304), not an RPM×IAT threshold; the "IAT axis" was that table's DATA misread (corrections items 49/59). The real threshold is RAM `0xFFFF8154` = clamp(baseline + K×deviation, 50, 359), where K is desc `0xAE6D4`, a DIMENSIONLESS sigma multiplier whose two load planes are byte-identical (item 82). No-boost-input is right about the EFFECT, wrong about the mechanism — overboost reaches it via LOAD + cylinder pressure. Full mechanism: `[[knock-detector-has-no-boost-input]]`.
- **Why TD couldn't fight the overshoot before:** Turbo Dynamics was hard-zeroed because target (12.7) sat under its activation gate (`0xC0BD4` = enable >13 psi).
- **20.17 fix (flying):** target → ~17 (clears the 13 gate → arms TD to *control* boost instead of overshooting), WGDC down, TD-negative up, per-gear 5th timing comp populated (−1.08/−1.56° @ load 2.5/3.0 — `[[per-gear-timing-comp-5th-lever]]`), AVCS-pull held as fallback.
- **20.17 drive (6-3 log) — PARTIAL validation only:** TD **ARMED** ✓ (tdi/Tdp now live vs hard-0 before — the gate fix worked), AVCS valid (p95 29°), boost controlled, AFR rich/good, **zero FLKC**. BUT never went WOT (max 51% throttle, max 14.3 psi) → **the 17-psi knock condition was never recreated, so the fix is UNTESTED at the conditions that matter.**
- **Open action items:**
  1. **WOT 5th-gear pull at 3400-3800 needed** to validate. Note: target=17 + TD armed means that pull WILL now drive boost to ~17 in the zone (controlled, not an overshoot) — so it's both the test and the first real exposure.
  2. **Verify the per-gear 5th timing comp actually arms BEFORE that pull** — its load activation (`0xD2D40` enable>0 / disable<8 g/rev) looked possibly inert; if it isn't arming, 17 psi runs at the old too-aggressive timing and FLKC (or sub-sample knock) finds it.
  3. **Fallback if 15 psi still knocks at the spring floor:** drop AVCS in the Non-Cruise high-load cells (cylinder-pressure lever that works *under* the spring; cam is at ~28° advance there). The real "more power here" path is octane/E85 + new injectors, not more boost at less timing (knock-limited zone, ~7.5° at 17 psi cool IAT = boost-heavy/timing-light = heat). No EGT probe = flying blind on the thermal floor.

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

## 20.13 watch — gate scoring after 5-22 drive (CLOSED 2026-05-22)

20.13 flashed; verified on one ~166-min log `logs/5-22 20.13/log0001.csv`.
Scoring against the pre-drive gates:

| hypothesis | gate | actual | verdict |
|---|---|---|---|
| OL richening eliminates the 2600-3300 × 1.0-2.0 FBKC depth cluster | depth shallower than -4.5°; per-cell FBKC<0 at 2600×1.17 drops 81 → <20 | depth -7.0° → **-2.8°** ✓; per-cell 2600×1.17 81 → **129** ✗ (but all shallow, max -1.4°) | **MIXED** — depth fixed, count rose |
| OL richening reduces FLKC ratchet at 3300-4000 × 2.0-3.0 | flkc events <0.05/min (was 0.17/min) | 0.166 → **0.000**/min; 55 → **0** events in band | **PASS (strong)** |
| Further AVCS work tightens the AVCS-led cluster | avcs_osc <1.0/min (was 1.13); cluster count at 2500-3000 × 0.20-0.30 drops | 1.127 → **1.114** (flat); zone osc 109 → **123** | **FAIL** |
| OL richening doesn't blow back into wbo2 lag | divergence ≤2.5/min; no lean spikes >+0.5 AFR | 2.05 → **2.00** | **PASS** |

**Headline:** the dangerous part of the ghost zone is gone — deepest
FBKC in the whole 2600-3300 × 1.0-2.0 band went -7.0° → -2.8°, the
3300-4000 × 2.0-3.0 FLKC ratchet went from 55 events to **zero**, and
**IAM held 1.000 the entire drive with FLKC never ratcheting negative**.
No learned-knock damage anywhere.

**But the zone is de-fanged, not eliminated.** Shallow FBKC trims got
more frequent and more widespread: cluster-band fbkc<0 samples 468
(20.12 log0007, deepest -7.0°) → 774 (20.13, deepest -2.8°); the
3000-RPM row (3000 × 1.0-1.51) and the upper 3300 row (3300 × 1.36-1.95)
now carry shallow knock that 20.12 log0007 didn't show. Duration-
normalized, shallow-knock rate rose ~33%. The cells are still sitting
right at the knock threshold — the ECU now catches it early with many
small -1.0 to -2.8° trims instead of occasional -7.0° slams. **This is
acceptable as-is** (no deep knock, no IAM damage), but the zone is not
"resolved" — it's been moved from dangerous to benign.

**Attribution confound stands (per the pre-drive note):** OL richen and
the IAT retard both pull these cells the same direction; the scorecard
can't separate them. The knock pass is "OL richen AND/OR IAT retard
worked."

**Why the AVCS gate failed:** the 20.13 AVCS edit lifted the 0.30/0.50
columns, but the residency-weighted oscillation lives in the **0.20 load
column at 2800-3000 RPM** — which the edit barely touched (only the
sub-1% (0.20, 1000) cell was zeroed). Per-cell osc on 5-22: 3000×0.20 =
48 (was 46), 2800×0.20 = 28 (was 25), 2500×0.20 = 19 (unchanged). 123 of
185 osc events still in the 2500-3000 × 0.20-0.30 zone. **Next AVCS
lever: the 0.20 column at 2800-3000 RPM, not the 0.30+ columns already
worked.**

**Boost/secondary movement (20.12 → 20.13):** `mean_target_attainment`
0.829 → 0.955 (37 pulls, 0 wgdc-pegged, healthy); `rpm_swing_per_min`
1.069 → 0.921; `maf_corr_mean_abs_pct` 2.393 → 1.121 (trim health up —
20.13 didn't touch MAF, drive-context shift). Minor regressions:
`afr_osc_per_min` 0.904 → 1.011 and `stutter_signature_per_min` 1.366 →
1.451 (small; possibly OL richen adding AFR ripple — watch, don't act).

---

## Superseded — 20.13 pre-drive gates (opened 2026-05-17, scored above)

**Methodology notes for the 20.13 review:**
- Re-run `python3 scripts/analysis/scorecard.py --recompute-durations` after ingesting 20.13 logs (the `--recompute-durations` flag is needed when new rom_rev_map entries land).
- For the OL richening verdict, compare per-cell FBKC<0 sample counts at the cells listed in the 20.12 cluster (above) — these are the cells the richen was sized to address.
- Per `feedback_verify_rom_changes_against_user_claims`: full 5-21 cell-by-cell diff = **439 bytes** (after the axis revert below). OL block matches the announcement (3 tables, 117 cells each, all-three rule holds, richer at the knock cluster). AVCS = 20-cell paired plateau extension. **Three items were NOT in the original announcement** (details in [tune-state.md](tune-state.md) "20.12 → 20.13"):
  1. **Timing Comp A (IAT)** `0xD3288` — 11-cell hot-IAT retard (−0.35 to −1.05° at 10-110°C). KEPT — a second lever on the same high-load knock cluster as the OL richen.
  2. **AVCS Cruise RPM axis** idx1 1100→1300 — **ACCIDENTAL, reverted locally 2026-05-21** (both axes back at 1100). Was a stray byte that would have de-paired the AVCS RPM axes.
  3. **AVCS Cruise-only cell** (0.20, 1000) 0.50→0.00 — KEPT, sub-1% residency, shape-only.
- **ATTRIBUTION CONFOUND for the knock verdict:** the IAT retard (#1 above) and the OL richen both pull the *same* high-load knock cells in the *same* direction. If 20.13 knock improves, the scorecard cannot separate which lever did it. Note this when scoring the OL-richening gates — a pass is "OL richen AND/OR IAT retard worked," not OL richen alone.
- MAF rescale is NOT in 20.13. Slated for 20.14. Don't propose MAF changes until that work lands.

**If any gate fails on next log:**
- min_fbkc_depth stays at -7.0 → OL richening was insufficient at the dominant cells. Re-shape the OL targets at 2600-3300 × 1.0-2.0 by 0.3-0.5 AFR more, OR layer a BT retard on the L=1.0-2.0 columns that 20.12 missed.
- flkc events stay elevated at 3300-4000 × 2.0-3.0 → boost overshoot is reaching cells the OL doesn't cover (CL-rich region) — consider another Max WG pull in the 3000-4000 RPM band.
- avcs_osc per min doesn't move → the 20.13 AVCS edit didn't reach the dominant osc cells. Re-bin AVCS osc events by exact RPM/load and compare against the edited cell coords.
- ffb_wbo2_div regresses → check at-cell wbo2-FFB at the richened cells; OL leanout might be inverted (too rich → ECU's MAF correction loop fights it).

---

## 20.14 watch — gate scoring after 5-23 drives (CLOSED 2026-05-23)

20.14 was flashed and driven on 2026-05-23 (3 logs: 24-min warm,
8.9-min cold, 253-min way-home — ~286 min total).

| hypothesis | gate | actual | verdict |
|---|---|---|---|
| Pedal hump restores low-RPM throttle | low-RPM transit time / stutter signature | stutter_events/min 6.02 → 3.95 (−34%) | **PASS** |
| Pedal hump fixes felt sluggishness | subjective Dean report | "sluggishness fix achieved" | **PASS** |
| Pedal hump doesn't re-create cruise hunt | AVCS std at highway 60-95 mph cruise | 0.71° (rock solid) | **PASS** |
| MAF rescale (deferred from 20.13) | 8-50 g/s correction in tolerance | −0.1 to −1.4%, median ≈ −0.5% | **PASS** (no change needed) |

**New issue discovered (escalated to 20.15 lever):**
- Lean-on-accel transients in OL — 279 events / 253 min, median +7.22 AFR lean, identified as tip-in enrichment shortfall (see new section "Active — lever in flight" below).

**Existing issues still open (carry over):**
- Cold 25-mph AVCS hunting — confirmed in log0002. Mechanism is oil-hydraulics-limited cam tracking during warmup (cam pct_zero = 86% first 100s, then bimodal 0°↔20° toggle as oil warms). No calibration lever in this ROM gates AVCS by ECT directly. **Accept as cold-start character.**
- Transition-cusp knock 2600-3700 × 1.00-1.17 — survives shift-knock filter (447 of 699 raw FBKC<0 samples are real load knock; peak −8.05° at 3000/1.17). May partially resolve with the 20.15 tip-in fix if heat-dump from transient lean is contributing. If not, revisit base timing or OL targets in 20.16+.

---

## Staged for verification (opened during pedal-tuning, 2026-04-27/28)

### Low-RPM "sluggish off the line" — pedal hump (CLOSED 2026-05-23 — see 20.14 watch above)

- **Symptom (Dean):** sluggish off the line; low RPM "not super smooth /
  a bit stuttery" though "felt pretty good overall."
- **Root cause (5-22 analysis):** 20.13's pedal map gives <half the
  low-RPM throttle stock does at light pedal (16.5% APP @ 800 RPM:
  commanded throttle 8.6% vs stock 18.9%). The cruise-hunting fix that
  lowered the 16.5% column also inverted stock's low-RPM tip-in hump.
- **Lever staged:** 8-cell pedal-hump restore (16.5% + 25% columns, rows
  800-2000), partial toward stock, monotonicity-capped. Full cell list
  in [tune-state.md](tune-state.md) "20.13 → 20.14". Recovers ~70-80% of
  stock low-RPM throttle without touching the 2700-3300 hunt rows.
- **The low-RPM stutter is TRANSIENT, not steady-state.** Held steady
  (foot+RPM+load), low-RPM oscillation is ≤1% on every signal (AVCS
  range≥8 = 0.9%, timing std>2 = 1.0%). The roughness is during load/
  throttle transitions through the lugging zone — partly inherent to a
  built turbo engine down low. So the lever is *less time in the zone*,
  which the pedal hump does directly (gets through it faster).
- **No pedal-chasing.** In low-speed take-offs, APP-vs-RPM correlation
  median −0.50 (foot eases as revs climb) while commanded throttle holds/
  rises — the torque-based DBW scales throttle up with RPM correctly. No
  mid-pull throttle deficit. Take-off pedal range: ~11% → ~24% peak.
- **AVCS NOT needed broadly** (see 20.14 deferrals in tune-state). Only
  confirmed steady hunt is the 0.20-load column at 2800-3000 (the 25-mph
  cruise stutter, gate-3 miss) — ~4% of low-RPM time; optional micro-fix
  later, may be masked by faster transit from the pedal hump.
- **Cruise residency (5-22):** city (20-55 mph) lives at 10% APP /
  2400-3200 RPM; highway (65-90 mph) lives at 16.5% APP / 2800-3600 —
  i.e. highway cruise sits ON the hunt band. Verdict: don't bump throttle
  in cruise (re-raises hunt gain where you spend cruise time); the
  10→16.5 cliff that caused the hunt is already smoothed (18.8 → ~12-13
  RQTQ/% pedal, matching the 16.5→25 slope) so no remaining cliff to
  smooth either. Cruise zone is in good shape — leave it.

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

## 20.15 watch — post-reflash AVCS LOCKOUT contaminated 5-25 drive (data invalid)

20.15 was flashed and driven 2026-05-25. The drive captured a **post-reflash AVCS lockout** (see `[[avcs-post-reflash-lockout-known-quirk]]` memory) — known intermittent quirk where AVCS doesn't engage on the first start after a flash. A restart clears it.

**AVCS lockout symptom on this log:**
- Whole-log AVCS p95 = 7°, max = 11° (vs ~22° / ~31° on a working drive)
- Median AVCS in the 2000-3500 RPM band: 5-6° (vs ~19° normal)
- WOT pull at 4304 RPM topped out at 8° (should be 22-25°)
- 99.9% of samples ≤ 10° advance

**What's contaminated** (all metric categories that depend on cam being where it should be):
- Lean-event magnitudes (G2)
- Knock-rate and depth (G4 — "zero knock" is meaningless under retarded cam)
- Cruise AFC drift (G5 — the -3.4% low-load richening goes away with working AVCS)
- Stutter / RPM swing / target attainment

**What survives:**
- **G3 BE-coverage shift** (events with BE ≥ 5 psi: 85.7% vs target >40%) — this is a ROM-byte-pure check. The BE axis compression is in the bin, operating exactly as designed. The lever landed structurally.

**No 20.15 conclusions and no 20.16 levers are being staged from this log.** Required: Dean restarts to clear AVCS, then a normal 30-60 min drive. Re-score G1-G5 from there.

The pre-drive contingency (drop **Min Tip-in IPW Activation 0xCC4A4** from 1.0 → 0.7 ms) is still in the queue *if* G1/G2 miss on a clean drive. Not staged yet.

---

## CLOSED — tip-in enrichment fix VERIFIED in 20.15 (5-26 + 5-28, ~18% reduction)

**Result (2026-06-02):** the 5 staged edits work. On the 5-28 log (n=1816 tip-ins) the fix delivers **~18% overall lean-spike reduction vs 20.14 L3**, strongest in 1500-2000 RPM (−37%). The 5-26 single-log 40-50% was small-sample optimism; the uniform same-code rerun lands at 18%. No meaningful gain <1500 RPM (gate may still sit above the tiniest deltas there — left as a minor open item). Combined n=1953. The contingency lever (drop IPW gate 1.0 → 0.7 ms) was NOT needed and is dropped from the queue. Original analysis kept below for the verification trail.

### Lean-on-accel transients in OL — tip-in enrichment fix flying in 20.15

- **Symptom:** wbo2 climbs to 16-20 AFR for 200-400ms during pedal-opening transitions in OL, while ECU is commanding FFB ~10-13. Lean recovers in 1-2s as AFC PI catches up.
- **Sample drill:** sample 105349 in `logs/5-23 20.14/log0003.csv` — 70 mph 5th-gear stab after lift. Throttle climbed 9.4 → 20% over 0.32s (~1.5%/sample). MAF jumped 10.2 → 30.8 g/s (+65 g/s/s). IPW climbed 2.3 → 3.3 ms — *not enough to keep up with MAF rate*. wbo2 peaked at 16.7. Full trace in `scripts/analysis/quick_5_23_105385_drill.py`.
- **Drive-wide sweep:** 279 lean events in 253-min way-home log (1.1/min in OL). Median throttle change at event onset: 1.96%/sample (right at the 2.0% activation threshold). Median lean peak: +7.22 AFR. Median BoostErr: 3.62 psi.
- **Root cause (NEW insight 5-23):** tip-in is effectively dormant for DBW-smoothed pedal ramps in 20.14 due to two coupled issues:
  1. **Throttle activation gate at 2.0%** (stock/garn 0.85%) — most smooth ramps don't pass
  2. **BoostErr comp calibrated for stock's structurally-elevated target boost.** Stock target sits 5-12 psi above achievable at light-throttle cells, so BE during transients lives above the comp axis top (9.9 psi → comp=0%). The 20.x base brought target close to achievable, moving BE into the 2-6 psi range (comp = −50 to −80%, suppression zone).
- **Lever staged for 20.15 (5 edits, see `tune-state.md`):**
  - Min Throttle Activation 2.00 → 0.85% (`0xCC4A0`)
  - Min IPW Activation 1.32 → 1.0 ms (`0xCC4A4`)
  - Applied Counter A & B both: 3 → 5 (`0xCD165` / `0xCD175`)
  - BoostErr axis: compress 0-9.9 psi → 0-6.7253 psi (`0xCD128`) — preserves S-curve shape, no data byte changes
  - **NO** changes to RPM comp, base tip-in A/B, or target boost map (deliberately — single-variable test discipline)
- **Coverage prediction:** ~30-45% of the 279 lean events should fire tip-in after the change.

### Pre-drive gates for scoring 20.15

| gate | metric | source | current | target |
|---|---|---|---|---|
| **G1: tip-in shortfall events** | OL-opening lean events ≥2 AFR for ≥100ms, per minute | sweep tool (`scripts/analysis/tipin_lean_event_sweep.py`) | 1.10/min | **<0.8/min** (≥30% reduction) |
| G2: median lean peak | peak (wbo2 − FFB) within events | sweep | 7.22 | **<6.0** |
| G3: BE-coverage shift | % lean events with BE ≥ 5 psi vs < 5 psi | sweep + classifier | 26% above 5 | **>40% above 5** (means tip-in caught the easy-to-fire half) |
| G4: knock at transition cusp | shift-filtered FBKC<0 events at 2600-3700 × 1.0-1.17 | `knock_shift_filter.py` | 304 samples | **<200** (only counts if 20.15's tip-in fixes the upstream heat issue) |
| G5: cruise regression check | CL steady cruise AFC mean | filter throttle_d ≈ 0, CL=8, RPM ≥ 1200 | +0.93% | **±1.5%** (no over-enrichment) |

**If any gate fails:**
- G1 or G2 fails by a lot → IPW activation gate is still too high for smooth ramps. Try dropping to 0.7 ms next rev. Or bump the base tip-in A/B values (currently in 20.x already 17-32% bigger than stock — could go further).
- G3 fails → the lean events are in the smooth-ramp regime that the IPW gate still blocks, regardless of BE comp. Either accept that those events are non-tip-in (might be tau / load filter), or bigger IPW gate cut.
- G4 doesn't move → transition-cusp knock isn't downstream of the tip-in lean. Go after it directly via base timing pull at 2600-3700 × 1.0-1.17 or richen OL targets there.
- G5 drifts negative >2% → tip-in is over-enriching in CL cruise. Tighten the BE comp axis cells 0-2 (raise the attenuation back toward original 20.14 values at the low-BE end).

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
- **20.13 lever landed & scored (5-22):** OL fueling richen + IAT
  retard + AVCS plateau extension. **Result: severe knock eliminated,
  zone de-fanged but not gone.** Deepest FBKC -7.0° → -2.8° across the
  whole band; 3300-4000 × 2.0-3.0 FLKC ratchet 55 events → 0; IAM held
  1.000. But shallow FBKC (-1.0 to -2.8°) is now more frequent and
  spread into the 3000-RPM row and upper 3300 row. Cells still sit at
  the knock threshold. Full scoring in the "20.13 watch (CLOSED)"
  section above. Knock improvement is OL-richen AND/OR IAT-retard
  (confounded — both pull the same cells).
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
