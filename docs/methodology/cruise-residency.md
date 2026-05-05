# Methodology — cruise residency on grid

Captured 2026-05-04. The method for identifying cruise-on-cliff cells
in any RPM × Load table — used across AVCS, base timing, knock advance,
OL, and CL fueling comp.

## Concept

Overlay cruise residency on a table's RPM × Load grid. Cells where the
user spends real cruise time **AND** that sit adjacent to a steep
gradient (cliff) are the most likely sources of perceived oscillation.

Doing it once with a fixed filter and threshold set, then reusing
across revs, makes diffs comparable. Don't drift the filter constants.

## Cruise filter (locked)

Use exactly these. Dean signed off on this set — it's also the locked
filter referenced in `scripts/analysis/log_review_checklist.md`.

- `CL/OL == 8` (closed loop — see [../logs.md](../logs.md) for state
  codes)
- `MPH > 20`
- 1-second rolling std (~20 samples at 25 Hz):
  - `RPM` std < 100
  - `Accelerator` std < 1.0
  - `Throttle` std < 1.0

On the 4-25 baseline log this captures ~33.8% of samples / ~1778 s.

## Binning onto the table grid

Read the load and RPM axis arrays from the ROM (addresses in
[../cruise-tables.md](../cruise-tables.md)), build cell-edge midpoints,
then `np.histogram2d` with `weights=dt`, clipping `dt` to 0.5s so log-
break gaps don't inflate residency.

Storage layout for all of these tables: row-major with outer index = Y
(RPM), inner = X (Load). Read as `T[y][x] = raw[y × N_load + x]`.

## Cliff thresholds per table

These are tuning judgment — adjust if scope changes.

| Table | Neighbor delta threshold |
|---|---|
| AVCS Cruise | 5° |
| Base Timing Cruise | 3° |
| Knock Adv Max Cruise | 2° |
| OL Fueling | 0.5 AFR |
| CL Fueling Target Comp A (Load) | 0.30 AFR pts |

## Cruise-on-cliff definition

A cell with cruise residency ≥ 5s **AND** any neighbor delta ≥ the
table's cliff threshold.

Report sorted descending by residency, with cruise time, current cell
value, max neighbor delta, and (rev_new − rev_old) delta where
applicable.

## Special case — OL tables under cruise filter

The cruise filter produces a residency overlay even though OL is
inactive during cruise. Call this out explicitly in the report. The OL
panel is informative as "where in OL-axis-space cruise driving falls"
but the cliffs there don't cause cruise oscillation.

To analyze OL-active behavior, switch the filter to `CL/OL == 10`.

## Default deliverable shape

Two side-by-side heatmaps (rev A vs rev B) with cell labels showing
both the table value and cruise seconds, red lines for cliff edges,
blue rectangles for cruise-on-cliff cells, log-scale residency colormap.

When iterating within a single rev, also report:

- (a) cliff count delta
- (b) cruise-on-cliff cell delta with named cells
- (c) any cliffs that **grew** as a side-effect of edits — Dean wants
  to see trades, not just wins.

Pair with [no-inference.md](no-inference.md) — defend the read with
numbers.

## Reference scripts

Paths from the 4-25 work; scripts have hardcoded session paths at the
top, so they need a path edit before running locally.

- `scripts/analysis/extract_avcs_table.py` — extracts axes + values to
  JSON
- `scripts/analysis/cruise_heatmap_avcs_4-25.py` — AVCS-specific
  heatmap
- `scripts/analysis/cruise_heatmap_multi_4-25.py` — multi-table sweep
  (OL, base timing, knock adv, CL comp)
