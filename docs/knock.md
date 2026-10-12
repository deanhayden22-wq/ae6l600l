# Knock and FLKC

Captured 2026-05-04. Full disassembly is in
`disassembly/analysis/knock_flkc_analysis.txt` (2,748 lines) with a
shorter summary in `knock_flkc_report.txt` (605 lines). This page is
the navigation layer + tuning-relevant summary.

**Values on this page** were re-read on 2026-10-11 from **rev 20.19c**
(`rom/AE5L600L 20g rev 20.19c.bin`, the rev on the car, md5 `92cae827…`)
through `scripts/defs.py`, with stock alongside where it differs. Corrections
items 98 and 99.

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

> **Disputed 2026-10-11 — not settled (corrections item 98).** The addresses
> of `0x4438C`, `0x43D68`, `0x45BFE` and `0x463BA` are stored together in one
> 15-entry pointer list at `0x04AD6C`–`0x04ADA4`, which reads more like "called
> from a list" than the event-driven chain drawn above. `0xFFFF3234` (IAM) is
> loaded at `0x045BA4`, `0x045BBC` and `0x045D50`, and by `0x0463BA` itself at
> `0x0463D0`. Calling `0x45BFE` the per-event retard path is unverified.
> Decode before relying on the ordering.

## Key constants

All eight are read by `flkc_paths_FG` (`0x0463BA`, GBR `0xFFFF8290`), in
its advance branch `0x04648E`–`0x046532` and retard branches from `0x04669C`.
Rev 20.19c.

| Address | 20.19c | Stock | Definition name | What the code does with it |
|---|---|---|---|---|
| `0xD29EE` | **90** | 125 | Fine Correction Advance Delay | the advance branch runs only when counter `word[gbr+4]` ≥ this; otherwise it branches to `0x04679A` (`0x04648E`–`0x046498`) |
| `0xD2F48` | **0.25** | 0.35 | Fine Correction **Advance** Value | **added** to the cell value (`0x0464AE`–`0x0464B2`, `0x046534`–`0x046538`), then `float_min` against a ceiling computed at `0x0463FC`–`0x046400` from IAM and `[0xFFFF8258]` |
| `0xD2F44` | 8.0 | 8.0 | Fine Correction Advance Limit | upper bound of `float_clamp_range` (`0xBE56C`) after each step |
| `0xD2F4C` | **−15.0** | −11.75 | Fine Correction Retard Limit | lower bound of the same clamp |
| `0xD2F50` | **−1.01** | −1.40 | Fine Correction Retard Value (stored +1.01, scaling `-x`) | loaded at `0x04669C` and `0x04673A`, followed by the same clamp. Arithmetic not decoded |
| `0xD2F40` | 100.0 | 100.0 | — (no definition) | compared with `[0xFFFF8258]` at `0x04649C`–`0x0464A2`; selects between two branches that **both** add the advance value. Not a retard gate |
| `0xD2F54` | 0.35 | 0.35 | — (no definition) | stored to `[0xFFFF8290]` (this function's GBR base) when `byte[gbr+17]` ≠ 1 (`0x04652A`–`0x046532`) |
| `0xD2F58` | 0.35 | 0.35 | — (no definition) | stored to the same place when `byte[gbr+17]` == 1 (`0x046520`–`0x046528`) |

The earlier version called `0xD2F48` the retard step per knock event; the
retard step is `0xD2F50`. It called `0xD2F40` a gate on retard and
`0xD2F54`/`0xD2F58` recovery rates; neither holds as written. What reads
`[0xFFFF8290]` was **not checked**, so no replacement meaning is given for
`0xD2F54`/`0xD2F58`. `0xFFFF8258` carries three conflicting labels in
`ImportAE5L600L.java` (`flkc_fg_limit_FR15`, `flkc_retard`,
`knock_metric_accum`); its identity is not settled.

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

Internal FLKC working values: **positive = advance, negative = retard**,
clamped to [`0xD2F4C`, `0xD2F44`] = **[−15.0, +8.0]** deg on 20.19c (stock
[−11.75, +8.0]). Evidence: the advance branch **adds** +`0xD2F48` at
`0x0464B2` before the clamp, and the definition names the +8.0 bound the
Advance Limit. This reverses the earlier "positive = retard".

Not checked: the claim that a commit function around `0x73600` maps the
working value to `0xFFFF93E0` (FLKC) and `0xFFFF93DC` (FBKC), and any sign
flip it applies (corrections item 98).

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

- Boost Control Disable (IAM) (`0xC0BFC`) = **0.50, 0.65** on 20.19c
  (stock 0.20, 0.65) — per the definition, disable below the first,
  re-enable at the second.
- Boost Control Disable (Fine Correction) (`0xC0BF8`) = **−2.0** on 20.19c
  (stock −1.0).

Both conditions plus the delay `0xC0BAD` must hold, per the definition's
description; the reading code (near `0x013AB0`) is not traced.

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
- `0xFFFF93E0` (FLKC displayed by RomRaider) vs the internal working
  values (positive = advance, see Sign convention) — the commit function
  around 0x73600 is not checked.
- IAM is `0xFFFF3234` (corrections item 81), not `0xFFFF9270`, and it IS
  read in these paths: `flkc_paths_FG` loads it at `0x0463D0` (pool
  `0x0465B0`), and four more literals for it sit in `0x43D00`–`0x46800`
  (`0x44F70`, `0x45AC4`, `0x45D94`, `0x46060`). `0xFFFF9270` has no literal
  reference anywhere in the image. Where IAM is **written** was not
  checked (rev 20.19c, 2026-10-11).
