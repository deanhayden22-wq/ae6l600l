#!/usr/bin/env python3
"""
ROM changeset rollup.

Runs rom_diff.diff_bins() across every consecutive rev pair in REV_ORDER
where both .bin files exist, then emits a JSON manifest for the
dashboard. This is the "what tables actually moved between revs"
panel data — directly answers the "changes we've made" question.

Output: scripts/analysis/trends/rom_changeset.json

Usage:
    python3 scripts/analysis/rom_changeset.py
"""
from __future__ import annotations

import json
from pathlib import Path

from rom_diff import KNOWN_TABLES, diff_bins, resolve_bin  # type: ignore

REPO_ROOT = Path(__file__).resolve().parents[2]
OUT_PATH = REPO_ROOT / "scripts" / "analysis" / "trends" / "rom_changeset.json"

# Mirror dashboard.py REV_ORDER. stock baseline is the first comparable bin.
REV_ORDER = ["stock", "20.7", "20.8", "20.9", "20.10", "20.11", "20.12", "20.13"]


def _table_summary(diff_tables: dict) -> list[dict]:
    """Sort tables by bytes-changed, push unknown to the end."""
    rows = []
    for name, b in diff_tables.items():
        rows.append(
            {
                "name": name,
                "n_runs": b["n_runs"],
                "n_bytes": b["n_bytes"],
                "addr_min": b["addr_min"],
                "addr_max": b["addr_max"],
            }
        )
    rows.sort(key=lambda r: (r["name"] == "(unknown region)", -r["n_bytes"]))
    return rows


def build_manifest() -> dict:
    transitions: list[dict] = []
    # Walk rev pairs, skipping any missing .bin
    pairs: list[tuple[str, str]] = []
    prev = None
    for r in REV_ORDER:
        if resolve_bin(r) is None:
            continue
        if prev is not None:
            pairs.append((prev, r))
        prev = r

    for before_rev, after_rev in pairs:
        bp = resolve_bin(before_rev)
        ap = resolve_bin(after_rev)
        result = diff_bins(bp, ap)
        transitions.append(
            {
                "before_rev": before_rev,
                "after_rev": after_rev,
                "before_bin": Path(result["before_path"]).name,
                "after_bin": Path(result["after_path"]).name,
                "n_diff_bytes": result["n_diff_bytes"],
                "n_runs": result["n_runs"],
                "tables": _table_summary(result["tables"]),
            }
        )

    return {
        "rev_order": [r for r in REV_ORDER if resolve_bin(r) is not None],
        "transitions": transitions,
        "known_tables": [
            {"name": name, "addr_start": s, "addr_end": e}
            for s, e, name in KNOWN_TABLES
        ],
    }


def main():
    manifest = build_manifest()
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(manifest, indent=2))
    n_tr = len(manifest["transitions"])
    n_bytes = sum(t["n_diff_bytes"] for t in manifest["transitions"])
    print(f"Wrote {OUT_PATH}")
    print(f"  {n_tr} transitions, {n_bytes} total bytes changed across all revs")
    for t in manifest["transitions"]:
        labeled = sum(b["n_bytes"] for b in t["tables"] if b["name"] != "(unknown region)")
        print(
            f"  {t['before_rev']:>6} → {t['after_rev']:<6} "
            f"{t['n_diff_bytes']:>4}B in {t['n_runs']:>3} runs "
            f"({labeled} labeled)"
        )


if __name__ == "__main__":
    main()
