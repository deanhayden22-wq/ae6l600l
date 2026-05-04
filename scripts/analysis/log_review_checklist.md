# AE5L600L — Log Review Checklist (SOP)

Authoritative procedure for reviewing a new log. Every step has explicit
filters and thresholds. If a step says "[VERIFY]", the threshold has not
been pinned down with data — flag it during the review and we'll set it.

Living doc: auto-memory `project_open_issues.md` (open issues across chats).
Trends store: `scripts/analysis/trends/` (one CSV per metric).
Per-log review: `logs/REVIEW_LOG.md` (append-only, dated section per log).

Sample rate: 25 Hz (40 ms per sample). All "≥1 second sustained" rules =
≥25 consecutive samples meeting the condition.

---

## Step 0 — Pre-flight

0.1  Read `project_open_issues.md` (memory). Note every open issue with
     its RPM/load zone or table location. These are the **prior-flagged
     areas** we explicitly re-check in this log.

0.2  Read the most recent dated section in `logs/REVIEW_LOG.md`. Pull
     the "areas staged for verification" line — these are commitments
     from last session.

0.3  Identify the ROM rev this log was captured on. (Filename, in-log
     marker, or ask user. Do **not** assume.) Record as `rom_rev` —
     used as a column in every trends CSV.

0.4  Identify the log file path(s) and dates. Record as `log_date`.

---

## Step 1 — Knock pass

**Definition:** any sample where `FBKC < 0` OR `FLKC` stepped down vs
the prior sample (FLKC decrement = learned-knock event).

1.1  Build per-sample knock mask:
     - `fbkc_neg` = `FBKC < 0`
     - `flkc_decr` = `FLKC[t] < FLKC[t-1]`
     - `knock_any` = `fbkc_neg OR flkc_decr`

1.2  Event detection (per signal):
     - **FBKC event** = each sample where `FBKC[t] < FBKC[t-1]` (deepening
       of the pull). A 0→−1.4→−2.8→−4.2 pull counts as 3 events, not 1.
     - **FLKC event** = each sample where `FLKC[t] < FLKC[t-1]` (learned
       knock decrement).
     - Recoveries (FBKC or FLKC moving back toward 0) do NOT count.

1.3  For each event, capture: time, RPM, load (g/rev * 60), MAF g/s,
     mrp (psi), AFR commanded (FFB), AFR actual (wbo2),
     AFR delta (wbo2 − FFB), Throttle, Accelerator, AVCS,
     Timing, IAM, FBKC value, FLKC value, FLKC delta.

1.4  Bin by RPM (250 RPM bins) × load. For each cell, record:
     - `sample_count_fbkc_neg`, `sample_count_flkc_decr`
     - `event_count_fbkc`, `event_count_flkc`
     - `mean_fbkc`, `min_fbkc`

1.5  **Ghost-knock detection:** join this log's per-cell knock
     count against `trends/knock_by_cell.csv` history. Any cell with
     knock events in **3+ separate ROM revs** is flagged "ghost knock"
     — change history is not solving it. Flag for root-cause review
     beyond the timing table (could be MAF scaling, fueling, or AVCS).

1.6  Cross-check against prior-flagged zones from Step 0.1.
     - "Knock returned to a zone we patched last rev" = high-priority.
     - "Knock in a new zone we never flagged" = add to open issues.

1.7  **Append rows to `trends/knock_by_cell.csv`.**

---

## Step 2 — WOT pulls

**Definition:** `Throttle > 95%` sustained ≥25 consecutive samples
(≥1 s). TPS-based, not APP. APP-vs-TPS gaps go in Step 5.

2.1  Edge-detect WOT pulls. Merge pulls separated by <0.5 s gap.

2.2  Per pull, record: start_time, duration_s, peak_rpm, peak_mrp_psi,
     peak_maf_gs, min_fbkc (during pull), min_flkc, knock_during
     (bool, from Step 1 mask), peak_wbo2, mean of (wbo2 − FFB),
     peak_wgdc, IAM at pull start, IAM at pull end.

2.3  For each pull, sanity checks:
     - Boost vs Trgt_Boost: gap > 1 psi sustained = boost-control issue.
     - wbo2 vs FFB: |delta| > 0.5 AFR sustained = fueling drift.
     - WGDC pegged at 100% with boost short of target = mechanical.
     - IAM dropped during pull = accumulating knock — flag.

2.4  Cross-check against prior-flagged zones from Step 0.

2.5  **Append rows to `trends/wot_pulls.csv`.**

---

## Step 3 — MAF correction (closed-loop fuel trim)

**Goal:** track per-cell mean/median fuel trim on the **MAF Scaling
table grid** (MAF voltage × MAF g/s output) so we can refine the MAF
curve, not the fuel table.

**Filter (user's standing filter):**
- `FFB ≤ 14.7` (commanded stoich)
- `|correction| < 25` (drop crazy excursions)
- `Accelerator > 2` (not idle/coast)
- `CL/OL == 8` (closed loop active)

`correction` per the log augment = `AFC + AFL` when `CL/OL=8`.

3.1  Apply filter. Confirm sample count > 5000 in this log;
     if lower, note in REVIEW_LOG that confidence is low this pass.

3.2  Bin by `MAF(V)` × `MAF (g/s)` using the active MAF Scaling
     table breakpoints. [VERIFY: confirm current MAF scaling table
     address/breakpoints from `definitions/` for this rom_rev.]

3.3  For each (mafv_bin, mafgs_bin) cell, record sample_count, mean
     correction, median correction, std correction.

3.4  Cell-by-cell delta vs previous log in
     `trends/maf_corr_by_mafcell.csv`:
     - Cell mean shifted by >2% with sample_count > 100 in both logs
       = directional drift — propose MAF scaling adjustment.
     - Cell mean stable across 3+ logs but offset > 3% = MAF scaling
       error in that cell; correct the table, not the fuel target.

3.5  **Append rows to `trends/maf_corr_by_mafcell.csv`.**

---

## Step 4 — Cliff scan (table-side)

Cliffs = adjacent-cell jumps in a tuning table that the car can land
on at steady state. User's canonical example: AVCS table where a 20°
plateau drops to 0° within a few hundred RPM.

Tables to scan (addresses in `reference_cruise_tuning_tables.md` memory):
- AVCS Intake Advance
- Base Timing (Cruise + Primary)
- Knock Adv Max Cruise
- Primary OL Fueling B Low / B High / KCA Alt (the "three" identity set)
- Target Throttle Plate (TT)
- Req Torque APP (the pedal map)

4.1  For each table, compute per-row and per-column adjacent-cell
     deltas. Flag pairs exceeding:
     - AVCS: |Δ| ≥ 5° between adjacent cells
     - Base Timing: |Δ| ≥ 3°
     - OL Fueling: |Δ| ≥ 0.5 AFR
     - Throttle Plate: |Δ| ≥ 5%
     - Pedal map (APP→RQTQ): user-flagged uniform smoothing rules
       from `project_pedal_map_v9.md` apply

4.2  For each flagged cliff, compute residency in **this log**:
     - sample_count of cells on each side of the cliff (steady-state,
       std on 1-s window low).
     - residency_pct = samples_at_cliff / total_samples_in_log.

4.3  Rank by `residency_samples × |delta|`. Worst actor first.

4.4  Cross-check against prior-flagged cliffs from Step 0.

4.5  **Append rows to `trends/cliffs_flagged.csv`.**

---

## Step 5 — Stutter / oscillation events (signal-side)

Same idea as Step 4 but detected from log signals — catches things the
car actually *does*, regardless of which table caused it. 1-s rolling
window on 25-sample (1-s) blocks.

5.1  **Throttle hunting at steady APP:**
     condition: `std(Accelerator, 1s) < 0.5%` AND
                `std(Throttle, 1s) > 1.0%`
     Each 1-s block satisfying = one stutter event.

5.2  **AVCS oscillation:**
     condition: `(max(avcs) − min(avcs))` over 1 s `≥ 10°` AND
                `std(RPM, 1s) < 50` AND `std(load, 1s) < 0.05`
     (Was 5°; tightened to ~p75 of measured range.)

5.3  **Timing or AFR oscillation at steady operating point:**
     condition: `std(Timing, 1s) > 3.5°` OR `std(wbo2, 1s) > 1.0`
                AND `std(RPM, 1s) < 50`, `std(load, 1s) < 0.05`,
                `std(Throttle, 1s) < 1%`
     (Was 2°/0.5; tightened to ~p75.)

5.4  **RPM swing under steady throttle:**
     condition: `(max(RPM) − min(RPM))` over 1 s `≥ 400`
                AND `std(Throttle, 1s) < 1%`
     (Was 150; 271 RPM is the median real swing — most are normal driving,
     not stutter. 400 catches the worst quartile.)

5.5  **FFB vs wbo2 divergence (driver-felt fueling fluctuation):**
     condition: `std(wbo2 − FFB, 1s) > 1.0`
                AND `std(Throttle, 1s) < 1%`
     (Was 0.4; was the noisiest signal. p25 was 0.47 — now we catch
     only the meaningfully large divergences.)
     Note: wbo2 has ~320 ms transport lag (per memory) — when
     comparing, shift wbo2 backwards by 8 samples before subtracting.

5.6  For each event: time, signal, magnitude, RPM, load, Accelerator,
     Throttle, AVCS, Timing.

5.7  **Append rows to `trends/stutter_events.csv`.**

---

## Step 6 — VE proxy (did the rev actually help?)

Bin steady-state samples on RPM × mrp grid. Mean MAF g/s in each cell
is a proxy for VE — same RPM × mrp should produce same airflow if
the engine's pumping efficiency hasn't changed. Cell-mean drift across
revs at the **same RPM × mrp** = an actual VE change (good if
intentional, suspicious if not).

**Filter:**
- `std(RPM, 1s) < 50`
- `std(mrp, 1s) < 0.5`
- `std(Throttle, 1s) < 1%`
- (no CL/OL gating — this is airflow, not fuel)

6.1  Bin by RPM (250 RPM) × mrp (0.5 psi). For each cell:
     sample_count, mean MAF g/s, median MAF g/s, std MAF g/s.

6.2  Cell-by-cell delta vs `trends/ve_proxy.csv` history:
     - Cell mean shifted by >3% with sample_count > 50 in both
       logs = real VE change. Tag with rom_rev so the change is
       traceable to a specific tune iteration.

6.3  **Append rows to `trends/ve_proxy.csv`.**

---

## Step 7 — Per-log writeup

Append a section to `logs/REVIEW_LOG.md` using this template:

```
## YYYY-MM-DD — log: <relative path> — rom: <rom_rev>

**Knock:** <event count>, top cells: <(rpm,load): n>, ghost zones: <list>
**WOT:** <pull count>, knock-during: <n>, fueling notes: <...>
**MAF corr:** filtered samples: <n>, drift cells: <list with delta>
**Cliffs:** <count by table, top 3 by residency × delta>
**Stutter:** <count by signal type, top 3 events>
**VE:** <cells changed >3% vs last log, with rom_rev attribution>

**Prior-flagged areas re-checked:**
- <issue>: <status — resolved / improved / unchanged / regressed>

**New issues:**
- <description, RPM/load zone, evidence>

**Staged for next session:**
- <action items requiring follow-up logs or table changes>
```

---

## Step 8 — Memory update

8.1  Re-read `project_open_issues.md`.

8.2  For each open issue with status "resolved" or "improved >2 logs
     in a row" in this review: remove or downgrade.

8.3  For each new issue surfaced: add with date stamp, RPM/load zone,
     evidence (specific cells, sample counts), and proposed next step.

8.4  Update memory file. (User confirmed auto-update is OK at end of
     each review.)

---

## Standing filter library (for quick reference)

| Purpose | Filter |
|--|--|
| Cruise residency (per `feedback_cruise_residency_method.md`) | CL/OL=8, MPH>20, std(RPM,1s)<low, std(accel,1s)<low, std(Throttle,1s)<low |
| MAF correction | FFB≤14.7, |correction|<25, Accelerator>2, CL/OL=8 |
| WOT pull | Throttle>95% sustained ≥25 samples |
| Knock event | FBKC<0 OR FLKC[t]<FLKC[t-1] |
| Steady-state (for cliff residency / VE) | std(RPM,1s)<50, std(load or mrp,1s)<threshold, std(Throttle,1s)<1% |

---

## Reminders for Claude reviewing logs

- User reviews map changes in **TPS**, not RQTQ. Show TPS view alongside
  any RQTQ-side proposal. (`feedback_table_format.md`.)
- wbo2 has ~320 ms transport lag. Shift before AFR delta comparisons.
- 20.327 in stock O2 (`AFR` column) = fuel-cut flag, ignore for fuel
  analysis. Use `wbo2`.
- Don't infer-and-assert. Flag uncertainty, name log subsets, defend
  claims when challenged. (`feedback_no_inference_assumptions.md`.)
- Cross-reference cells against `disassembly/` and `definitions/`
  before claiming a cell is at a specific value — `merp mod/archive_v1/`
  and `patches/` are not authoritative (CLAUDE.md project rule).
