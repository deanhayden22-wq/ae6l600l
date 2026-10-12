---
name: diffing-rom-revs
description: Use when Dean asks what changed between two AE5L600L ROM revisions or bins - "diff 17a and 18", "changes from 20.12 to 20.13", "what's in this rev", "compare these two ROMs", "changelog" - or announces a new rev whose changes need confirming.
---

# Diffing ROM revs

The diff is the truth; Dean's description of the rev is a claim to check against it.

## Steps

1. **Read the bins fresh.** Dean saves from ECUFlash mid-session and filenames get reused. Never rely on an earlier read.
2. **Byte diff.**
   - By rev: `python scripts/analysis/rom_diff.py --before 20.12 --after 20.13`
   - By file: `python scripts/analysis/rom_diff.py --before-bin <a> --after-bin <b>`
3. **Name what moved.** Load tables through `scripts/defs.py` (`defs.load()`, `d.get(name).read(rom)`), which applies inheritance and scaling. Do not parse the XMLs by hand or hand-roll `raw * scale + bias`.
4. **Cover the whole image.** Injected code lives in the 0xFF hole, so do not filter to code regions. Bytes that match no definition are reported as unnamed with address and length.
5. **Compare to the announcement.** List anything changed that Dean did not mention and ask whether it was intended.
6. **Behavioural check, if logs exist on both revs.** `python scripts/analysis/cross_rev_diff.py --before <a> --after <b>` for a changed cruise table; `python scripts/analysis/rev_comparison.py --rev-a <a> --rev-b <b>` for VE.
7. Refresh the dashboard feed when a new bin lands: `python scripts/analysis/rom_changeset.py`.

## Report shape

| Table | Cells changed | Before to after (display units) | Announced? |
|---|---|---|---|

Then one line per unannounced change, and one line on what the change should do in the driving the car actually sees.

## Common mistakes

- Showing raw bytes. Dean reasons in degrees, psi, AFR and percent.
- Recomputing or "fixing" the checksum. ECUFlash owns it.
- Calling a table a live lever without reading its clamp or multiplier (per-gear timing comp is multiplied by a 0.0 constant).
- Trusting a table name. Check its flag in `docs/verification-status.md` first.
