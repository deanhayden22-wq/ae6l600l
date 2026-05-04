# Trends store

Per-metric CSVs that accumulate across log reviews. Append-only; never
overwrite. Every row carries `log_date` and `rom_rev` so any cell's
history can be traced log-over-log and across tune iterations.

Schemas and filter definitions live in
`scripts/analysis/log_review_checklist.md`. Do not change column order
without also updating that file.

| File | One row per | Step in SOP |
|--|--|--|
| `knock_by_cell.csv` | (log, rom_rev, rpm_bin, load_bin) | 1.4 |
| `wot_pulls.csv` | (log, rom_rev, pull) | 2.2 |
| `maf_corr_by_mafcell.csv` | (log, rom_rev, mafv_bin, mafgs_bin) | 3.3 |
| `cliffs_flagged.csv` | (log, rom_rev, table, cell-pair) | 4.5 |
| `stutter_events.csv` | (log, rom_rev, event) | 5.6 |
| `ve_proxy.csv` | (log, rom_rev, rpm_bin, mrp_bin) | 6.1 |

Ghost-knock criterion: a (rpm_bin, load_bin) cell with `event_count_fbkc>0`
across 3+ distinct rom_rev values in `knock_by_cell.csv` = ghost zone.
