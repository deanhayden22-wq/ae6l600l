# Knock and FLKC

Captured 2026-05-04. Full disassembly is in
`disassembly/analysis/knock_flkc_analysis.txt` (2,748 lines) with a
shorter summary in `knock_flkc_report.txt` (605 lines). This page is
the navigation layer + tuning-relevant summary.

## Pipeline

Event-driven, executes on every 4th cylinder firing event (cylinders
0, 6, 12, 18 in internal indexing = one full engine cycle):

```
knock_wrapper (0x43750)        — cylinder gate + status guard
      │
      ▼
knock_detector (0x43782)       — signal processing + threshold compare
      │
      ▼
knock_wrapper_cont (0x43B7C)   — RPM gate + level code (0/2/4/5/6/7)
      │
      ▼
task12_knock_post (0x43D68)    — per-cycle retard amount table lookups
      │
      ▼
flkc_path_J (0x45BFE)          — FAST: per-event retard + counter recovery
      │
      ▼
flkc_paths_FG (0x463BA)        — SLOW: sustained knock state machine
```

A separate task (`task11_knock_flag_read @ 0x4438C`) reads the knock
flag from a different path.

## Key constants

From `0x000D2F40`–`0x000D2F58`:

| Address | Value | Meaning |
|---|---|---|
| 0x000D2F40 | 100.0f | FLKC gate — knock_metric must be ≤ this for retard to apply |
| 0x000D2F44 | 8.0f | FLKC upper clamp (max recovery advance cap) |
| 0x000D2F48 | 0.35f | **FLKC retard step per knock event (deg)** |
| 0x000D2F4C | −11.75f | **FLKC lower clamp = max retard (deg)** |
| 0x000D2F54 | 0.35f | FLKC recovery rate (deg/cycle, path 1) |
| 0x000D2F58 | 0.35f | FLKC recovery rate (deg/cycle, path 2) |
| 0x000D29EE | 125 | FLKC counter threshold — cycles without knock before recovery begins |

Knock-intensity thresholds (input to level code 0/2/4/5/6/7):

| Threshold | Value (raw signal) |
|---|---|
| Above limit (code 0) | 224.0f |
| Code 2 | 160.0f |
| Code 4 | 128.0f |
| Code 5 | 96.0f |
| Code 6 | 64.0f |
| Else (code 7) | < 64.0f |

`task12_knock_post` thresholds: 80.0f (low/high gate) and 100.0f
(secondary gate).

## RPM gate

`rpm_current @ 0xFFFF6624` stores RPM × 16/9 ≈ RPM × 1.7778. The knock
RPM gate fires above 12799.8 raw → ~7200 RPM. Above this, knock
detection enters the high-RPM gated path.

## Sign convention

Internal FLKC working values: **positive = retard**, range
[−11.75, +8.0] deg. RomRaider displays FLKC as negative — there's a
commit function around 0x73600 that maps the working register to
the viewable `0xFFFF93E0` (FLKC) and `0xFFFF93DC` (FBKC).

In log column terms (see [logs.md](logs.md)):

- **FBKC** column — feedback knock correction (degrees).
  **Negative = pulling timing for active knock.**
- **FLKC** column — fine learning knock correction. Long-term learning.
- **IAM** — ignition advance multiplier. 1.0 = max. Drops only under
  sustained knock; transient knock that doesn't pull IAM is still real
  but hasn't ratcheted yet.

## Tunable tables

The Pull3DFloat descriptors used by the knock pipeline:

> **The detection threshold is RAM, not a table** — `docs/corrections.md` item
> 82, full trace `disassembly/analysis/knock_threshold_trace.txt`:
>
> ```
> threshold_A = clamp( baseline + K * deviation,          50.0,  359.0 )  -> 0xFFFF8154
> threshold_B = clamp( baseline + K * 1000.0 * deviation, 50.0, 1000.0 )  -> 0xFFFF8158
> ```
>
> `K` is `0xAE6D4` and is **dimensionless** — it multiplies a tracked deviation,
> so it is a sigma count, not knock-signal units. `baseline` (`0xFFFF8148`) and
> `deviation` (`0xFFFF8150`) are per-cylinder tracked statistics. **Lower K =
> more sensitive detection.** `r9` in the detector is the literal `0xFFFF8158`,
> not a stack frame — reading it as one is what kept this open for a year.
>
> **None of the twelve knock-detection calibrations has an `address=` entry in
> the project XML.** The whole detection front-end is invisible to ECUFlash.

| Descriptor | Used in | Purpose |
|---|---|---|
| 0x000AE284 | knock_detector | **1-D curve on the KNOCK SIGNAL** (`0xFFFF4304`, clamped >=0), 65 pt float32, data 0..304. **NOT an RPM/load or RPM/IAT threshold** — corrected 2026-08-16, corrections.md items 49/59 |
| 0x000AE290 | knock_detector | 1-D on RPM 800..8000, data 8,10,10,10,10,10,12,13,10,10 |
| 0x0AE6D4/6E8/6FC/710 | knock_detector | **the SIGMA MULTIPLIER `K`** — dimensionless, per-cylinder 18 RPM x 2 LOAD, data 3.60 -> 3.45. **NOT the threshold** (corrected 2026-08-19, item 82). The two load planes are BYTE-IDENTICAL, so the load axis is exactly flat |
| 0x0AE724/738/74C/760 | knock_detector | per-cylinder 2x2 RPM x LOAD, 1000.0 everywhere. Multiplies `K` for **threshold B only** |
| 0x0AE29C/2A8/2B4/2C0 | knock_detector | per-cylinder 1-D RPM, 16.0 everywhere |
| 0x000AE0F8 | task12_knock_post | per-cycle retard amount lookup 1 |
| 0x000AE00C | task12_knock_post | per-cycle retard amount lookup 2 |
| 0x000AE020 | task12_knock_post | per-cycle retard amount lookup 3 |
| 0x000AE10C | task12_knock_post | per-cycle retard amount lookup 4 |
| 0x000AE134 | flkc_path_J | RPM-indexed FLKC threshold |
| 0x000AE2CC | flkc_path_J | per-cyl knock retard amount |

The user-tunable table set is:

| Table | Address |
|---|---|
| Knock Correction Adv Max Cruise | 0xd5904 |
| Knock Correction Adv Max Non-Cruise | 0xd5ac4 |

(Full address/scaling reference in
[cruise-tables.md](cruise-tables.md).)

## Trend store — knock-by-cell

The append-only `scripts/analysis/trends/knock_by_cell.csv` accumulates
per-(rpm_bin, load_bin) knock event counts across every reviewed log,
with `rom_rev` as a column. This is what enables ghost-zone detection:
**a (rpm_bin, load_bin) cell with `event_count_fbkc > 0` across 3+
distinct rom_rev values is a ghost zone** — knock that persists across
revs in the same cell despite changes elsewhere.

Per [open-issues.md](open-issues.md), the current ghost zone is:

> **2200–3300 RPM × 1.0–1.4 g/rev** — knock has appeared in every
> rom_rev (stock + 20.7 + 20.8 + 20.9 + 20.10) in cells (2200, 1.17),
> (2600, 1.0), (3300, 1.36). Adjacent cells in zone hit 4/5.

The leading hypothesis is that AVCS in this zone is +5 to +11° more
advance than stock (10–15° → 20–23.5°). Decision (2026-05-03): hold
further table changes; observe whether the existing 20.x timing + AVCS
smoothing resolves it. Don't propose new edits until 2–3 fresh logs on
flashed rev are ingested.

## Boost-control coupling

The boost control system reads IAM and fine knock correction and
backs off the wastegate when they go bad. See
[boost-control.md](boost-control.md):

- `BoostControlDisable_IAM` (0xC0BFC) = 0.2 — disable boost control
  if IAM < 0.2.
- `BoostControlDisable_FineCorrection` (0xC0BF8) = −1.0 — disable if
  fine knock corr < −1.0.

So sustained knock cuts boost as a side effect; you don't see this
directly in the knock pipeline but it's the safety interaction.

## Open questions (from disassembly)

Documented in `knock_flkc_report.txt`, kept here for context:

- `rpm_current @ 0xFFFF6624` is RPM-scaled (RPM × 16/9). Source likely
  computed from crank timer ISR.
- `0xFFFF63F8` is **ENGINE LOAD**, not IAT — settled in corrections.md item 9
  and stated in CLAUDE.md; IAT is `0xFFFF6364`. The detector reads it at
  `0x0437A0` into FR14 and uses it as the X axis of the per-cylinder
  RPM x LOAD lookup at `0x043858`. So the detector DOES have a load input —
  but that axis is calibrated exactly flat, which is why "knock detection has
  no load input" held up empirically while being false about the code.
- `knock_metric @ 0xFFFF8258` — cumulative knock signal used as the
  exponential weight in `flkc_paths_FG`. Computed elsewhere; not yet
  fully traced.
- `0xFFFF93E0` (FLKC displayed by RomRaider) sign convention vs the
  internal positive-is-retard working values — likely inverted/scaled
  in the commit function around 0x73600.
- IAM (`0xFFFF9270`) is not directly referenced in these paths. IAM is
  likely updated separately based on cumulative FLKC state.
