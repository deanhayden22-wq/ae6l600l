# Scope: cliffs_flagged.csv auto-populate

Authored 2026-05-10. Open task — not yet implemented.

## What's missing today

The trends store has `scripts/analysis/trends/cliffs_flagged.csv` with the schema documented in `trends/README.md`:

```
log_date,rom_rev,table_name,axis_a_label,axis_a_value,axis_b_label,
axis_b_value_a,axis_b_value_b,table_value_a,table_value_b,delta,
residency_samples,residency_pct,priority_score,notes
```

The CSV currently contains only the header row. SOP Step 4 ("Cliff scan — table-side") in `log_review_checklist.md` defines what should populate it. `log_review_ingest.py` does not implement Step 4 today, so cliff data only enters the trends store when someone manually runs the AVCS-only side script (`avcs_cruise_review.py`).

## What "done" looks like

Every time a new log is ingested, every watched table in the rev's `.bin` is scanned for adjacent-cell cliffs exceeding the SOP thresholds, joined against this log's per-cell residency, scored by `residency_samples × |Δ|`, and appended to `cliffs_flagged.csv` — one row per cliff per log.

## Tables in scope (per SOP Step 4 and active issues)

1. **AVCS Intake Cruise** (`0xDA96C`) — scale `0.0054932°/raw`, 18 load × 16 RPM. Extractor exists: `extract_avcs_table.py`.
2. **AVCS Intake Non-Cruise** (`0xDAC34`) — same structure as Cruise.
3. **Base Timing Primary Cruise** (`0xD4714`) — verify scale + axis breakpoints from `definitions/`.
4. **Base Timing Primary Non-Cruise** (`0xD48D4`) — same structure as Primary Cruise.
5. **Base Timing Reference Cruise** (`0xD4A94`) — same.
6. **Base Timing Reference Non-Cruise** (`0xD4C54`) — same.
7. **Knock Adv Max Cruise** (`0xD5904`) — scale + structure TBD.
8. **OL Fueling B Low / B High / KCA Alt** (3 tables, identity-locked per `reference_ol_fueling_tables.md`) — only need to scan one, but extractor needs to verify the identity rule still holds on every rev.
9. **OL Fueling Failsafe + Failsafe Alt** (2 tables, separate pair).
10. **Target Throttle Plate** — address TBD; user reviews this view, so it's load-bearing.
11. **Sport Pedal Map** (`0xF99E0`) — RQTQ scale `×0.0078125`; cliff metric is `feedback_table_format.md`-defined uniform-smoothing rules from `project_pedal_map_v9.md`, not a simple Δ.

**Per-table thresholds (from SOP 4.1):**
- AVCS: `|Δ| ≥ 5°` between adjacent cells
- Base Timing: `|Δ| ≥ 3°`
- OL Fueling: `|Δ| ≥ 0.5 AFR`
- Throttle Plate: `|Δ| ≥ 5%`
- Pedal map: user-specific smoothing rules (different scoring)

**Timing-as-Sum special case (per `docs/open-issues.md`, decision 2026-05-08):** cliffs on Base Timing and KCA should be scored on the **Sum map = BTC + (KCA × IAM)** with IAM=1.0, not on BTC and KCA separately. The 0.94→1.20 boundary opposes (BTC drops, KCA rises) so individual cliffs overstate the actual cruise-zone advance step. Sum map needs its own derived table at extract time.

## Phased build

### Phase 1 — Table extractors for 6 tables (no log residency yet)
- Reuse `extract_avcs_table.py` patterns: read `rom/*.bin`, slice at known address, apply scale, return a labelled `pd.DataFrame` indexed by load × RPM.
- Build extractors for AVCS × 2 (have), Base Timing × 4 (new). All five tables share the same axis structure (18 load × 16 RPM) — one extractor with parameterized address + scale.
- Verify each table's first cell against RomRaider visually on rev 20.11.
- Emit table-side cliffs (cell pair, Δ) to a per-rev snapshot. Skip the residency join for now.
- **Estimated lines: ~120. Effort: 1 focused session.**

### Phase 2 — Log-residency join + cliffs_flagged.csv writes
- For each cliff identified in Phase 1, compute per-side cell residency in the current log (using the cruise-residency filter from `feedback_cruise_residency_method.md`: CL/OL=8, MPH>20, 1s std on RPM/accel/throttle).
- Score = `residency_samples × |Δ|`. Append row to `cliffs_flagged.csv`.
- Hook into `log_review_ingest.py` as Step 4 in the per-log pipeline.
- **Estimated lines: ~100. Effort: 1 focused session.**

### Phase 3 — Sum-map for timing
- Add a derived `compute_sum_map(btc_table, kca_table, iam=1.0)` helper.
- Replace separate BTC and KCA cliff scans with a single Sum scan in cruise zones.
- Re-verify against the 0.65→0.94 Sum cliff table in `docs/open-issues.md` (BTC=0 on KCA side; pure BTC step −4.9 to −7.7°).
- **Estimated lines: ~40. Effort: half-session.**

### Phase 4 — Remaining tables
- Knock Adv Max Cruise extractor (used in Sum map already, so this is the standalone view).
- OL Fueling × 5 (B Low/High/KCA Alt + Failsafe pair); include the identity-rule verifier.
- Throttle Plate extractor.
- Sport Pedal Map extractor with the v9 smoothing-rule scorer (not a simple Δ — see `project_pedal_map_v9.md`).
- **Estimated lines: ~200. Effort: 1-2 focused sessions.**

## Risks & open questions

- **Axis breakpoints per table.** AVCS has `LOAD_ADDR = 0xDA8E4` and `RPM_ADDR = 0xDA92C` documented. Base Timing tables likely have their own axis breakpoints; need to extract from `definitions/` or verify against RomRaider before assuming they share AVCS's axis.
- **`scale` per table.** AVCS uses `0.0054932°/raw` but Base Timing and KCA use different scales (Subaru ROMs typically `0.25°/raw` for timing, varies). Each table needs verified scale from `definitions/`.
- **The pedal map "cliff" is not a Δ.** It's a uniform-smoothing-rule check tied to `project_pedal_map_v9.md`. Trying to fit it into the same `cliffs_flagged.csv` schema may be the wrong move — could end up as a separate `pedal_smoothness_flagged.csv` if it doesn't fit.
- **Sum-map cliffs vs. individual BTC/KCA cliffs.** Per `docs/open-issues.md` the Sum is the "real" cliff the engine sees in cruise. But for OL or non-cruise modes, KCA may not apply (KCA is by definition a cruise-only correction in this firmware). The Sum derivation needs the right cruise/non-cruise gate. Verify before merging.
- **Throttle Plate address verification.** Address not yet documented in memory or the existing extractors. Need to identify from `definitions/` before Phase 4.
- **Residency filter precision.** SOP Step 4.2 says "steady-state, std on 1-s window low". The thresholds for "low" are documented in `feedback_cruise_residency_method.md`. Make sure cliff residency uses the same filter as cruise residency, not a separate one — otherwise the scorecard and cliffs_flagged disagree on which cells are "occupied".

## Recommended order of attack

Phase 1 + Phase 2 together get the most leverage: 6 tables (AVCS × 2 + Base Timing × 4) covered with full per-log scoring. That's enough to make `cliffs_flagged.csv` populated on every ingest and unblock the scorecard's `avcs` and `timing_sum` threads from needing the workaround they have now (signal-side oscillation as a stand-in).

Phase 3 (Sum map) is short and isolates the BTC-vs-KCA decision per the open-issues entry.

Phase 4 is the long tail — important but lower priority since the active issues are mostly in AVCS and timing zones today.

**Total scope estimate: 4-5 focused sessions.**
