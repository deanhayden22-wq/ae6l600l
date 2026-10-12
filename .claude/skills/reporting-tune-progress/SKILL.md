---
name: reporting-tune-progress
description: Use when Dean asks for a progress report, impact report, scorecard, dashboard refresh or "are we getting better" across recent AE5L600L tune revisions, or asks to update the trackers.
---

# Reporting tune progress

The reports already exist as generators. Refresh them, then summarise; do not build a new report.

## Refresh, in this order

Run from the repo root.

1. `python scripts/analysis/log_review_ingest.py --map logs/rom_rev_map.csv --all` (idempotent)
2. `python scripts/analysis/log_health.py --only-missing`
3. `python scripts/analysis/scorecard.py`
4. `python scripts/analysis/rom_changeset.py`
5. `python scripts/analysis/dashboard.py`
6. `python scripts/analysis/metrics_dashboard_data.py`
7. `python scripts/analysis/tune_progress.py`

If a rev is missing from the output, it is missing from `REV_ORDER` in `scripts/analysis/rev_order.py` or from `logs/rom_rev_map.csv`.

## Which report answers what

| Question | Use |
|---|---|
| Did the issue a rev targeted actually move? | `tune_progress.html` (per log, issue ledger) |
| How do revs compare overall? | `scorecard_dashboard.html` / `trends/scorecard_latest.csv` |
| What tables changed per rev? | `trends/rom_changeset.json` |

## Summary shape

1. Per open issue: status and the number that shows it, first rev to latest.
2. What got worse, with the rev where it turned.
3. What cannot be judged yet and the log that would settle it.

## Common mistakes

- Comparing a long highway log to a short errand as equals. Weight by exposure.
- Comparing ramp or knock rates without matching entry condition, IAT and A/C.
- Including an old baseline that flattens the chart. Drop it and say so.
- Counting a locked-out AVCS log.
