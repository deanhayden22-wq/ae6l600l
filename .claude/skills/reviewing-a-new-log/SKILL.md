---
name: reviewing-a-new-log
description: Use when Dean drops in a new datalog or says "new log", "log from today", "take a look", "review 20.x", "how did we do", or asks about knock, lean spikes, stutter, boost or fueling in a specific drive of the AE5L600L WRX.
---

# Reviewing a new log

Run the existing SOP, do not re-derive it. Source of truth for thresholds: `scripts/analysis/log_review_checklist.md`. Do not write a new `quick_*.py` script until the steps below have run.

## Order

1. **Pre-flight.** Read `docs/open-issues.md`, `docs/tune-state.md` and the newest entry in `logs/REVIEW_LOG.md`. Identify the rev and the log date. If the rev is unclear, ask.
2. **Combine if raw.** Several `log000N.csv` files: `python scripts/combine_logs.py -n "<M-D rev>" <files>`. Add the row to `logs/rom_rev_map.csv`. New rev: append it to `REV_ORDER` in `scripts/analysis/rev_order.py`.
3. **Check the changeset.** Use the diffing-rom-revs skill against the prior rev. Anything in the diff Dean did not announce gets raised before scoring.
4. **AVCS lockout check.** If AVCS p95 across all RPM is under 12 degrees the cams never engaged (post-reflash quirk). Stop: the log cannot score the tune. Tell Dean to restart and re-log.
5. **Ingest.** `python scripts/analysis/log_review_ingest.py --log <path> --date YYYY-MM-DD --rom <rev>` then `python scripts/analysis/log_health.py --only-missing`.
6. **Knock.** Classify every FBKC event with `classify_knock_events()` from `scripts/analysis/knock_shift_filter.py` before reporting a cell. Separate shift, fuel-cut-resume and A/C events from sustained-load knock. FBKC = 0 at high load does not prove no knock (25 Hz aliasing).
7. **Remaining passes** per the checklist: WOT pulls, MAF correction, cliffs, stutter, VE proxy.
8. **Residency rule.** A cell under 1% strict-cruise residency cannot be confirmed from logs. Label any finding there low-validation.

## Report shape

1. The thing this rev was flashed to fix: better, same or worse, with numbers.
2. New rev vs prior rev.
3. New rev vs the all-time corpus.
4. Verdict and what to change or log next.

Scaled values with units. Each claim marked observed, inferred or hunch. Skip the list of things that are fine.

## Write-up

Append the entry to `logs/REVIEW_LOG.md` (template at its top), update `docs/tune-state.md` and `docs/open-issues.md`, then use handing-off-between-chats. Commit only on Dean's word.

## Common mistakes

- Attributing an effect because a number matches. Say whether it was observed.
- Treating `correction` as active trim in open loop. It is AFC+AFL only when CL/OL = 8.
- Subtracting atmosphere from mrp. mrp is already boost.
- Comparing wbo2 to FFB without the 8-sample lag shift.
- Chasing MAF scaling for the 3400-3700 lean area. It is two AVCS states.
