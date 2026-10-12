# Boost control

Captured 2026-05-04. Full disassembly is in
`disassembly/analysis/boost_control_analysis.txt` (430 lines) — this
page is the navigation layer + tuning-relevant summary.

**Values on this page** were re-read on 2026-10-11 from **rev 20.19c**
(`rom/AE5L600L 20g rev 20.19c.bin`, the rev on the car, md5 `92cae827…`)
through `scripts/defs.py`, with stock (`rom/ae5l600l.bin`) alongside where it
differs. Identities come from the definition XMLs. Corrections items 98 and 99.

## Architecture

Two periodic scheduler tasks plus a reset:

- **Task 51 — target calculation** (`task51_boost_wg_calc @ 0x054852`):
  reads throttle / MAF / RPM / load / ECT and computes target wastegate
  duty cycle via three RPM-indexed 1D descriptors plus a MAF-error
  correction.
- **Task 52 — feedback / trim** (`task52_boost_feedback @ 0x0549FA`):
  IIR (exponential moving average) loop on boost error and RPM error.
- **Reset** (`boost_feedback_reset @ 0x054A5A`): zeros all feedback
  workspace on engine-state change.

> **Disputed 2026-10-11 — corrections item 99.** `0x054852` reads **none** of
> the boost calibrations in the definition XML. Each has exactly one
> literal-pool reference in the image, and none is in this function:
> `0xC0BF8`/`0xC0BFC` at `0x013AB0`/`0x013AC4`, `0xC0BD4` at `0x013D18`, the
> three Turbo Dynamics tables through descriptors at `0x0AA91C`/`0x0AA930`/
> `0x0AA944`, Target Boost through `0x0AA9FC`. The function's own constants
> (`0xD670C`–`0xD6724`, descriptors `0xAEFE4`/`0xAEFF0`/`0xAEFFC`) have no
> definition entry, and the value its enable flag compares is `0xFFFF65FC`,
> **vehicle speed** (corrections item 8). Whether `0x054852`/`0x0549FA` are
> boost control at all is NOT settled, and the RAM names under GBR
> `0xFFFF8B50` carry the same doubt. What `0x054852` does is decoded under
> "What `0x054852` does" below.

The wastegate solenoid is driven via PWM at the frequency set by
`WastegateDutyCycleFreq` (0xC009E, ~1.93 Hz stock).

GBR workspace base for boost: **0xFFFF8B50**.

## Tunable tables (from project XML)

| Table | Address | Notes |
|---|---|---|
| Target Boost | 0xC1340 | RPM × RQTQ (3D) |
| Initial Wastegate Duty | 0xC1150 | RPM × RQTQ (3D) |
| Max Wastegate Duty | 0xC0F58 | RPM × RQTQ (3D) |
| Target Boost Comp ECT | 0xC0CF4 | ECT compensation |
| Target Boost Comp IAT | 0xC0E3C | IAT compensation |
| Target Boost Comp Atm | 0xC0EC4 | altitude compensation |
| Target Boost Comp 1st Gear | 0xC0C0C | (currently 1.0 = no comp) |
| Init Max WG Duty Comp ECT | 0xC0CB4 | ECT compensation on WG duty |
| Init Max WG Duty Comp IAT | 0xC0C94 | IAT compensation on WG duty |
| Init Max WG Duty Comp Atm | 0xC0E7C | altitude compensation on WG duty |
| Boost Limit Fuel Cut | 0xD2560 | boost-pressure overpressure cut |
| Wastegate Duty Cycle Freq | 0xC009E | 1.93 Hz stock |

**RQTQ axis dependency:** Target Boost, Initial WG Duty, and Max WG
Duty all use RQTQ as their X-axis. Pedal-map changes shift these
lookups too — see [pedal-throttle.md](pedal-throttle.md).

## Turbo Dynamics correction tables

Rev 20.19c. Three 9-cell tables indexed by **boost error** (target − actual,
psi); output is wastegate duty correction (% absolute). Data is uint16,
displayed `(x*.00390625)-50`. **There is no derivative term** — the definition
set has only these three.

| Table | Data | Boost Error axis |
|---|---|---|
| Turbo Dynamics Proportional | `0xC0D28` | `0xC0D04` |
| Turbo Dynamics Integral Negative | `0xC0D60` | `0xC0D3C` |
| Turbo Dynamics Integral Positive | `0xC0D98` | `0xC0D74` |

```
Turbo Dynamics Proportional
  20.19c  axis  -3.00  -2.00  -1.00   0.00   0.58   1.10   2.02   4.00   8.00
          data -15.07 -10.00  -5.01   0.01   1.92   3.50   5.77   9.51  15.08
  stock   axis  -3.09  -1.55  -0.77  -0.39   0.00   0.39   0.77   1.55   3.09
          data  -8.00  -3.00  -1.00  -0.50   0.00   0.50   1.00   3.00   8.00

Turbo Dynamics Integral Negative
  20.19c  axis  -4.64  -3.87  -3.09  -2.32  -1.55  -0.77  -0.39  -0.19  -0.01
          data  -1.00  -0.75  -0.55  -0.35  -0.20  -0.10  -0.05  -0.03  -0.02
  stock   axis  -4.64  -3.87  -3.09  -2.32  -1.55  -0.77  -0.39  -0.19   0.00
          data  -2.50  -1.50  -1.00  -0.70  -0.45  -0.20  -0.10  -0.05   0.00

Turbo Dynamics Integral Positive
  20.19c  axis   0.00   0.19   0.39   0.77   1.55   2.32   3.19   3.97   4.00
          data   0.00   0.04   0.07   0.14   0.28   0.45   0.70   1.00   0.00
  stock   axis   0.00   0.19   0.39   0.77   1.55   2.32   3.09   3.87   4.64
          data   0.00   0.05   0.10   0.20   0.45   0.70   1.00   1.50   2.50
```

An earlier version of this section listed `0xC0D04` (−160), `0xC0D3C` (−240)
and `0xC0D74` (0.0) as the P, I and D **gains**. They are the three axes above;
those numbers were each axis's first breakpoint in raw units. It also called
`0xC0D74` Task 52's IIR filter coefficient with a value of 0.5; it reads 0.0
in every rev.
Whether Task 52 has a filter coefficient elsewhere was **not checked**.

### Activation and range constants

Boost-error and target-boost constants are stored raw and displayed
`x*.01933677` psi (definition scaling). The previous table mixed raw and
display units.

| Address | 20.19c | Stock | Definition name | Raw (20.19c) |
|---|---|---|---|---|
| `0xC0BD4` | **12.0, 13.0 psi** | 4.06, 5.03 psi | TD Activation Thresholds (Target Boost) | 620.58, 672.29 (stock 210, 260) |
| `0xC0BDC` | **0.1 psi** | 0.0 | TD Integral Negative Activation (Boost Error) | 5.17 |
| `0xC0BE0` | 0.097 psi | same | TD Integral Positive Activation (Boost Error) | 5.0 |
| `0xC0BE4` | 5.0 % | same | TD Integral Negative Activation (Wastegate Duty) | 5.0 |
| `0xC0BF0` | −90, **5** % | −90, 15 % | TD Integral Cumulative Range (WGDC Correction) | same |

`0xC0BD4` and `0xC0BDC` have held these values since at least 20.10
(corrections item 98). What each constant does is the definition's description,
not a decode; the code that reads them (literal at `0x013D18` for `0xC0BD4`)
was not traced.

## Knock-related boost disable

| Address | 20.19c | Stock | Definition name |
|---|---|---|---|
| `0xC0BFC` | **0.50**, 0.65 | 0.20, 0.65 | Boost Control Disable (IAM) |
| `0xC0BF8` | **−2.0** | −1.0 | Boost Control Disable (Fine Correction) |
| `0xC0BAD` | 2 | 2 | Boost Control Disable Delay (Fine Correction) |

Per the definition's description (not decoded here): wastegate duty is set to
zero when IAM drops below the first `0xC0BFC` value **and** fine knock
correction has been below `0xC0BF8` for the `0xC0BAD` delay; it re-enables when
IAM reaches the second value. The reading code sits by the literal pool at
`0x013AB0`–`0x013AC4`, which also holds `0xFFFF3234` (IAM, corrections item 81)
at `0x013AC0`. Not traced.

## What `0x054852` does (decoded 2026-10-11, rev 20.19c)

This replaces the old "Enable hysteresis" section and ramp table, which had the
compared value (load → actually vehicle speed) and the flag direction wrong,
and named inputs from labels since corrected. Whether this is boost control is
the open question in the Architecture note above.

**Enable flag `byte[gbr+128]`** (`0x05488C`–`0x0548A6`), compared value
`[0xFFFF65FC]` = vehicle speed (km/h):

- **set to 1** when speed ≤ `[0xD6720]` = 4.0
- **cleared** when speed > `[0xD6724]` = 5.0
- held between.

**Output `[0xFFFF8B5C]`** (GBR-relative `[0xFFFF8BD0 − 116]`), by path:

| Condition (checked in this order) | Address | Effect |
|---|---|---|
| `0x22CF4` returns 0 (labelled `check_engine_running`) | `0x0548B8`–`0x0548C6` | `[0xFFFF8B50]` and output set to 0.0 at once |
| `byte[0xFFFF65C0]` == 1 (diag precondition, item 16) or `byte[0xFFFF64F5]` == 1 (debounced closed pedal, item 76) | `0x0548C8`–`0x0548D2` → `0x054978` | output = max(output − `[0xD6714]` (1.0), 0) |
| flag == 0 | `0x0548D4`–`0x0548D8` → `0x05495E` | output = max(output − `[0xD6710]` (0.01), 0) |
| counter `byte[gbr+124]` < `byte[0xD6185]` (8) | `0x0548DC`–`0x0548EA` → `0x05495E` | same 0.01 decay |
| otherwise (active) | `0x0548EC`–`0x05495C` | RPM (`0xFFFF6624`) lookups of `0xAEFE4`, `0xAEFF0`; output = max(output − `[0xD670C]` (0.005), computed floor) — rises at once, falls at most 0.005 per call |

The counter (`0x054990`–`0x0549B4`) increments (saturating, `0xBE53C`) while
both bytes above are 0 and the flag is set; otherwise it is zeroed.

Corrections to the old table: `0xFFFF65C0` is a diag precondition byte, not
throttle (corrections item 16); `0xFFFF64F5` is a debounced closed-pedal flag
(item 76), not a boost flag; the 0.005
rate is the active path's descent limit, **not** a "counter < 8" ramp — that
case decays at 0.01. `0x22CF4`'s "engine running" meaning is its label, not
re-checked.

## Why this matters for the current tune

The 20G undershoots target boost at 0.38 attainment ratio across
1500–4000 RPM (see [turbo-character.md](turbo-character.md)).
Low-RPM under-response is fundamentally a boost-control problem, not a
pedal-map problem. The lever for fixing it is in this subsystem —
specifically Target Boost (0xC1340), Initial WG Duty (0xC1150), and Max
WG Duty (0xC0F58). All three use RQTQ as X-axis, so any pedal-map
changes propagate through.

This is a queued workstream — see "Low-RPM under-response is
fundamentally turbo-lag bound" in [open-issues.md](open-issues.md).
The plan is to wait for v9 pedal-map verification first (so the
operating-point distribution stabilizes), then review the WG strategy.

## Recently changed in 20.10 (per byte-diff)

Two boost-related tables changed in 20.10 with origin not established:

- **Max Wastegate Duty** — definition address `0xC0F58`, which is where
  the table **data starts**. `0xC0FE0` is a cell 0x88 bytes into it.
- **Initial Wastegate Duty** — definition address `0xC1150`, again the
  start of the data. `0xC11D8` is a cell 0x88 bytes into it.

Corrected 2026-10-11 (corrections item 100): this used to call `0xC0F58`
and `0xC1150` "table headers" and the other two addresses "the table
data". Definitions point at data, never at a header.

These changes were detected via byte-diff of the 20.9 → 20.10 ROMs but
weren't documented in working notes. If they need re-derivation,
extract both versions and diff cell-by-cell.
