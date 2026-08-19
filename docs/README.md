# docs/

Active-tune reasoning and reference material that doesn't fit into the
disassembly proper. Captured from working notes on **2026-05-04**.

These are point-in-time snapshots, not live state. ROM bins are
overwritten in place (same filename, new content), so any address,
table value, or rev-specific finding here may be stale by the time
you read it. Re-verify against the current ROM and `definitions/` XML
before making a decision.

## Contents

**Tune state**

- [tune-state.md](tune-state.md) — what each 20.x rev changed, what's
  baselined where, the 4-25 baseline log, what's been verified vs
  pending.
- [open-issues.md](open-issues.md) — the active issues list. Symptoms,
  data location, what's been tried, what's next. Updated per rev.

**Workflow**

- [analysis-plan.md](analysis-plan.md) — the ROM-analysis game plan.
  Where coverage actually stands, the measured hit rate from the first two
  triage slices, the triage-before-decode sequence, and the standing rules.
  **Read before starting a new line of analysis.**
- [open-holes.md](open-holes.md) — the live worklist.
- [workflow.md](workflow.md) — the drive→log→ingest→diff→propose→flash
  iteration loop. Read this before running any analysis script.

**Subsystem notes**

- [pedal-throttle.md](pedal-throttle.md) — three-table pedal-to-throttle
  architecture (RQTQ APP × Base × Target Throttle), the ratio=1.0 WOT
  cliff, current pedal map design state.
- [turbo-character.md](turbo-character.md) — 20G spool data, boost
  attainment, response-lag findings. The reason most low-RPM under-
  response complaints are not pedal-map fixable.
- [boost-control.md](boost-control.md) — Task 51 / Task 52 architecture,
  Target Boost / Initial WG / Max WG tables, PID terms, knock-driven
  disable conditions.
- [avcs.md](avcs.md) — AVCS findings: stock-comparator caveat, AVCS-MAF
  coupling result, available analysis tools.
- [knock.md](knock.md) — knock detection pipeline, FLKC sign convention,
  ghost-zone analysis, boost-control coupling.
- [transient-fuel.md](transient-fuel.md) — accel enrichment + tau-alpha
  wall-film dynamics. Levers for the AVCS-ramp-lag knock open issue.
- [ol-fueling.md](ol-fueling.md) — five OL fueling tables, the
  "identity-of-three" rule, where it lives in the def XML.

**Reference**

- [cruise-tables.md](cruise-tables.md) — verified addresses and
  scalings for the five RPM × Load tables used in cruise residency
  analysis.
- [logs.md](logs.md) — log file inventory, schema notes, logger column
  meanings (FFB vs AFR vs wbo2, EGT in ohms, CL/OL state codes, AFC
  sign convention — all the non-obvious things).

**Methodology**

- [methodology/cruise-residency.md](methodology/cruise-residency.md) —
  cruise filter definition, per-table cliff thresholds, deliverable
  shape for cruise-on-grid analysis.
- [methodology/pedal-correction.md](methodology/pedal-correction.md) —
  detecting hunting from APP direction reversals; pairing with
  response-lag check to separate pedal-map issues from turbo-lag.
- [methodology/stock-comparator.md](methodology/stock-comparator.md) —
  why stock-vs-tune AVCS comparison breaks at the boost-transition
  load band, and how to segment recommendations.
- [methodology/no-inference.md](methodology/no-inference.md) — rigor
  rule: don't reverse-engineer values from saturated/lossy data; defend
  claims with numbers; ask before assuming.

## See also

- [../README.md](../README.md) — top-level repo orientation, directory
  map, source-of-truth rules.
- [../CONTRIBUTING.md](../CONTRIBUTING.md) — commit-message convention,
  doc-update conventions, script path conventions.
- `scripts/analysis/log_review_checklist.md` — the per-log review SOP
  (eight steps with locked filter constants).
- `logs/REVIEW_LOG.md` — append-only per-log review history.
- `scripts/analysis/trends/` — append-only per-metric CSVs.
