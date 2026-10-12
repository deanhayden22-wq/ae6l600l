---
name: proposing-table-changes
description: Use when suggesting or drafting an edit to an AE5L600L calibration table - timing, fueling, AVCS, boost target, wastegate duty, pedal or throttle maps, tip-in - or when Dean asks "what should I change", "anything else we can tweak", or wants a proposal packaged for the next rev.
---

# Proposing table changes

A proposal is only useful if the next log can confirm or refute it.

## Before proposing

1. Read the current values from the newest bin with `scripts/defs.py`. Re-read; do not reuse an earlier read.
2. Check the table's flag in `docs/verification-status.md` and confirm it is a live lever (clamps, multipliers, consumer).
3. Get residency for the cells: `python scripts/analysis/cell_residency.py`.
4. Check `docs/open-issues.md`, `docs/tune-state.md` and `logs/REVIEW_LOG.md` so the idea has not already been tried.

## Standing constraints

| Fact | Consequence |
|---|---|
| 15 psi wastegate spring | WGDC does nothing below 15 psi; not a spool lever |
| 4th/5th torque capped at 350 on purpose | Do not pitch raising it |
| Injectors near 100% duty around 17 psi / 4800+ | Fuel, not knock, limits the top end until the new injectors |
| Target boost is deliberately above achievable | Lowering it to match cuts tip-in through the boost-error comp |
| Stock per-gear timing comp is multiplied by 0.0 | Populating it does nothing |
| No exhaust AVCS; 5-speed | Gear 6 cells unused |
| Built engine, 20G turbo | Stock values are a reference, not a target; compare by load band |

## Proposal shape

For each table:

| Cell (RPM x load) | Now | Proposed | Delta | Residency | Why |
|---|---|---|---|---|---|

Then:
- New cliffs the edit creates, not only the ones it removes.
- For pedal work, the resulting throttle-plate view. Dean reviews in TPS.
- What the next log should show if it worked, and what would show it did not.
- Cells under 1% residency marked "shape only, not testable".

Offer more than one angle when the cause is not settled, and name the cheapest test first.

## Common mistakes

- Inflating BPW hysteresis to stop CL/OL oscillation (lean on the way back to closed loop).
- Following an AVCS cruise change with a MAF rescale.
- Proposing in raw units.
- Editing the bin or checksum directly. Dean applies changes in his editor.
