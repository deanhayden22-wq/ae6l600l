# Tuning iteration workflow

Captured 2026-05-04. The loop that produces every rev in `rom/`. Read
[../README.md](../README.md) for repo orientation first; this page is
the operational sequence.

## The loop

```
       ┌──────────────────────────────────────────────────┐
       ▼                                                  │
   1. drive  ──►  2. log  ──►  3. ingest  ──►  4. diff trends
                                                          │
   8. flash  ◄──  7. propose ◄──  6. analyze cliff/zone ◄─┘
                                       │
                                       └──► 5. write up REVIEW_LOG
```

## Step 1 — drive

The active calibration ROM lives in `rom/`. The current rev is the
highest 20.x file in there. Bins overwrite in place (same filename,
new content), so always re-extract to confirm what's actually flashed
right now — don't trust prior reads.

## Step 2 — log

Logs are RomRaider Logger CSVs at 25 Hz. The schema definition is in
`logs/logcfg.txt`. Save new captures to a dated folder under `logs/`
following the existing convention (e.g., `logs/4-27 20.10/log0001.csv`
where the folder name encodes both date and ROM rev). See
[logs.md](logs.md) for the full inventory and column meanings.

## Step 3 — ingest

Run the per-log review. The full SOP is at
`scripts/analysis/log_review_checklist.md`. Eight steps with locked
filter constants:

```
0. Pre-flight — read open issues + last review entry
1. Knock pass — FBKC<0 or FLKC step-down
2. WOT pass — Throttle>95% sustained ≥1s
3. MAF correction pass — fuel trim by MAF V × g/s cell
4. Cliff scan — neighbor delta thresholds per table
5. Stutter detection — APP/Throttle/RPM oscillation
6. VE proxy — RPM × MRP → mean MAF g/s
7. Per-log writeup — append to logs/REVIEW_LOG.md
8. Memory update — close issues that resolved, open new ones
```

The trend store at `scripts/analysis/trends/` is append-only — never
overwrite. Every row carries `log_date` and `rom_rev` so a cell's
history can be traced log-over-log and across tune iterations.

`scripts/analysis/log_review_ingest.py` is the entry point script. The
SOP is the source of truth on filter constants — don't drift them.

## Step 4 — diff trends

After ingest, compare the new log's rows in each trend CSV against the
prior rev rows. Things to look for:

- `knock_by_cell.csv` — did `event_count_fbkc` drop in cells we
  recently changed? Did any new cells appear?
- `wot_pulls.csv` — boost shape, fueling stability, knock during pulls.
- `maf_corr_by_mafcell.csv` — did the `(mafv_bin, mafgs_bin)` cells we
  re-scaled move toward zero trim?
- `cliffs_flagged.csv` — did the cliffs we softened drop their
  residency? Did edits create new cliffs as side-effects?
- `stutter_events.csv` — did stutters in the targeted RPM/load zones
  reduce?

For AVCS specifically, run `scripts/analysis/avcs_cruise_review.py
--rom <new> --prior <old> --logs "logs/**/*.csv" --label <rev>` for the
single-rev review, and `cross_rev_diff.py --before <old> --after <new>`
for a behavioral diff at fixed pedal/RPM. See [avcs.md](avcs.md) for
those tools' details.

## Step 5 — write up

Append a new section to `logs/REVIEW_LOG.md` (template at top of that
file). Newest first.

## Step 6 — analyze

For any new issue or persisting issue, do the residency-on-grid pass.
Methodology in [methodology/cruise-residency.md](methodology/cruise-residency.md).
Pair with [methodology/no-inference.md](methodology/no-inference.md) —
the rule is "defend the read with numbers, name the log subset, flag
uncertainty."

If the issue is a pedal/throttle hunting symptom, run pedal-correction
event detection per
[methodology/pedal-correction.md](methodology/pedal-correction.md), and
**always** pair with a response-lag check — the cluster may be
turbo-lag, not pedal-map.

## Step 7 — propose

Write the proposed table change with:

- Cell-level deltas in the table's native units (deg, AFR, etc.)
- Cruise residency per cell so trades are visible
- Cliffs that **grow** as side-effects, not just cliffs that shrink
- For pedal-map work, **also** the resulting TPS table (RQTQ → ratio →
  Target Throttle) — see [pedal-throttle.md](pedal-throttle.md), the
  user reviews at the TPS layer

If the change touches AVCS in cruise, recall: AVCS↔MAF coupling in
cruise is below the practical noise floor — see [avcs.md](avcs.md).
Don't propose MAF re-scaling as a follow-up.

If the change compares to stock, segment by load band per
[methodology/stock-comparator.md](methodology/stock-comparator.md). The
stock VF52 is in boost at 1.0+ load; the 20G isn't until 1.3+.

## Step 8 — flash

Apply the proposed change in RomRaider, save to the same `rom/AE5L600L
20g rev X.Y tiny wrex.bin` filename or bump the rev. Update the entry
in [tune-state.md](tune-state.md) and add the next-action entry to
[open-issues.md](open-issues.md).

Then drive (step 1).

## Where each piece lives

| Piece | Path |
|---|---|
| SOP | `scripts/analysis/log_review_checklist.md` |
| Trend store | `scripts/analysis/trends/` |
| Per-log review history | `logs/REVIEW_LOG.md` |
| Active calibration | `rom/AE5L600L 20g rev X.Y tiny wrex.bin` (highest X.Y) |
| Definitions XML | `definitions/AE5L600L 2013 USDM Impreza WRX MT.xml` |
| Verified addresses | [cruise-tables.md](cruise-tables.md) |
| Open issues list | [open-issues.md](open-issues.md) |
| Per-rev change log | [tune-state.md](tune-state.md) |
