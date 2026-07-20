"""Canonical rev order — THE single source of truth.

Every script that needs the rev lineage imports from here:

    from rev_order import REV_ORDER

Rev-bump procedure (replaces editing 5 hardcoded lists):
  1. Append the new rev string to REV_ORDER below.
  2. Add the log's row to logs/rom_rev_map.csv.
  3. Re-run generators (ingest, ghost_zone_fires, log_health, scorecard,
     dashboard, rom_changeset, dfco_recovery_sweep, tipin_corpus_sweep,
     tune_progress).

History: before 2026-07-16 this list was hardcoded separately in scorecard.py,
dashboard.py, rom_changeset.py, dfco_recovery_sweep.py and tipin_corpus_sweep.py,
and went stale silently on every rev bump (see reference_log_review_sop memory).
"""

REV_ORDER = [
    "stock", "garn_base", "20.7", "20.8", "20.9", "20.10", "20.11", "20.12",
    "20.13", "20.14", "20.15", "20.16", "20.17", "20.17a", "20.18", "20.18a", "20.19",
]

DEFAULT_BASELINE = "garn_base"
