# Transient fueling — accel enrichment + tau-alpha

Captured 2026-05-04. Full disassembly in
`disassembly/analysis/accel_enrichment_analysis.txt` (607 lines) and
`disassembly/analysis/tau_alpha_analysis.txt` (437 lines). This page is
the navigation layer + tuning-relevant summary.

> **Corrected 2026-10-11 — corrections item 100, rev 20.19c.** `0x3BB6C` is the
> **speed limiter (fuel cut)**, not tip-in enrichment, and `0x3735A` / `0x3740C`
> are not the tau table handlers. The sections below are rewritten or flagged
> where that changes them. The real tip-in tables are listed in the definition
> XML under "Fueling - Base / Enrichment"; they are not described on this page.

> **Added 2026-08-19 — a staged decay bank in this workspace, and it is INERT at
> operating temperature.** `disassembly/analysis/coolant_decay_bank_trace.txt`,
> corrections item 88. Function `0x02EFD2` (GBR `0xFFFF726C`, two bytes below the
> transient-knock-inhibit flag `0xFFFF726E`) decays an accumulator by a
> coolant-indexed rate with four staged latch-off thresholds. **All eight rate
> curves are a flat 0.900 above 40 °C**, so the coolant axis does nothing in the
> 80–100 °C regime the car runs in. It was briefly suspected of being a
> wall-wetting / X-factor term bearing on the cusp stab-lean — **that is
> retired**. None of the eight is defined in any XML.

## What's transient fueling for

Two physical effects need transient correction:

1. **Tip-in / tip-out** — driver moves throttle. Air arrives faster
   than fuel through the wall film, so the mixture leans for a moment.
   Add fuel proportional to throttle rate.
2. **Wall film dynamics (tau-alpha)** — fuel sticks to port/manifold
   walls, especially when cold. The film evaporates over time. As load
   rises, more fuel goes to the wall (lean transient); as load falls,
   the wall releases fuel (rich transient). Compensate for both.

Both run from the same dispatcher (`fuel_transient_comp @ 0x37186`).

## Pipeline

```
fuel_transient_comp (0x37186) — top-level dispatcher
   │
   ├── tip_in_ramp (0x37492)              — tip-in ramp state machine
   ├── tau_rising_handler (0x3735A)       — wall film, rising load
   ├── tau_falling_handler (0x3740C)      — wall film, falling load
   ├── overrun_fuel_cut (0x37450)         — DFCO logic
   ├── transient_condition_check (0x3726A) — gating
   └── transient_final_enrichment (0x371E6) — combines all corrections

```

`0x3BB6C` used to be drawn here as `fuel_accel_enrich`. It is the speed
limiter; see the next section. Its address is stored at `0x04A0B0`, so it
is called from a list, not from `fuel_transient_comp`.

The two `tau_*_handler` names above are also wrong as descriptions; see
"Tau-alpha" below.

## `0x3BB6C` is the speed limiter, not tip-in enrichment

Decoded 2026-10-11 from rev 20.19c (corrections item 100). This section
used to describe `0x3BB6C` as `fuel_accel_enrich`, with "gains" of 510 and
505 multiplied by a throttle delta. There is **no float arithmetic of any
kind** in `0x03BB6C`–`0x03BCCA`: the constants are only compared.

### What the constants are

| Address | 20.19c | Definition name | What the code does with it |
|---|---|---|---|
| `0xCC520` | 510 km/h (317 mph) | Speed Limiting Enable (Fuel Cut) | enable threshold when `0x22CF4` returns 1 (`0x03BBAC`) |
| `0xCC528` | 505 km/h (314 mph) | Speed Limiting Disable (Fuel Cut) | disable threshold, same case (`0x03BBB0`) |
| `0xCC51C` | 510 | — (no definition) | enable threshold when `0x22CF4` does not return 1 (`0x03BBB6`) |
| `0xCC524` | 505 | — (no definition) | disable threshold, same case (`0x03BBBA`) |
| `0xCC52C` | 1260.0 | — (no definition) | compared with `[0xFFFF620C]`, **manifold pressure** (corrections item 9), not RPM. Units not checked |
| `0xCC530` | 10000.0 | — (no definition) | compared with RPM (`0xFFFF6624`) |
| `0xCBC0B` | 3 | — (no definition) | count of consecutive active calls before the later flag bytes are set |
| `0xCBC0C` | 3 | — (no definition) | same, for inactive calls |

All eight are unchanged from stock. The speed compared is `[0xFFFF65FC]`,
vehicle speed in km/h (corrections item 8).

### The state machine

State byte `[0xFFFF7CE0]` (1 = limiter active). Four condition bytes come
from calls to `0x1CF16`, `0x22CF4`, `0x297A0` and `0x299BC`; what those
helpers compute was not decoded.

- **Inactive → active** (`0x03BC44`–`0x03BC76`) needs all of:
  speed ≥ the enable threshold (or the `0x297A0` or `0x299BC` result
  equal to 2), **RPM ≥ `[0xCC530]` = 10000**, and the `0x1CF16` result
  equal to 0.
- **Active → inactive** (`0x03BBC8`–`0x03BC0A`) on any of: speed below
  the disable threshold with manifold pressure below 1260 and both of
  those helper results 0; RPM below 10000 with manifold pressure below
  1260; or the `0x1CF16` result equal to 1.
- The outputs are flag bytes at `0xFFFF7CE1`–`0xFFFF7CE5`, staged by
  the two counters, then a tail jump to `0x3D2FC` (not decoded).

On this calibration the limiter cannot switch on by this path: it needs
10,000 RPM. Whether anything else writes `[0xFFFF7CE0]` was not checked.

**None of this is a tip-in lever.** Editing `0xCC51C`–`0xCC528`,
`0xCBC0B` or `0xCBC0C` changes the speed limiter.

## Tau-alpha (wall film dynamics)

The classic mass-transfer model:

```
fuel_delivered(t) = alpha × fuel_injected(t) + (1 - alpha) × film(t-1)
film(t)           = (1 - tau) × film(t-1) + (1 - alpha) × fuel_injected(t)
```

The ROM implements this as multiplier tables rather than the
differential-equation form. **Tau values are dimensionless multipliers
that scale the base enrichment adder.**

Triggered on **load rate**, not throttle rate. This matters because:

- Turbo spool: boost arrives without throttle movement → tip-in sees
  nothing, but wall film sees the load rise.
- Gear changes: RPM drops, load rises without throttle input.
- Altitude changes: air density shifts affecting g/rev at same TPS.

### Rising-load tau

> **Corrected 2026-10-11 — corrections item 100.** This heading used to
> name `tau_rising_handler @ 0x3735A`. `0x3735A` reads no table: it runs
> `float_lag_filter` (`0xBEA40`) on `[0xFFFF7A60]` and stores the result
> to `0xFFFF7A54`. What `0xFFFF7A60` holds was not checked. The table
> below is "Tau Input A Rising Load Activation" (data `0xCD6E6`); its
> descriptor `0xACB40` is loaded at `0x030D40`, in a different function,
> and is **1-D: 16 points on the Coolant Temperature axis `0xCC624`**
> (uint16, scale 1/2048), not 3 load × 16 ECT. A second descriptor,
> `0xACB54` (data `0xCD706`), is loaded on the other branch at
> `0x030D3C`. The three "Load" rows below were **not re-checked** and do
> not fit a 1-D table; the axis is stored in °C (−40…110), so the °F
> column headings are also suspect.

Single table — `Tau_RisingLoad_A @ 0xCD6E6`. 3 load × 16 ECT (uint16,
scale 1/2048).

| | −40°F | 0°F | 70°F | 110°F |
|---|---|---|---|---|
| Load 1.4 g/rev | 3.40 | 2.20 | 0.80 | 0.40 |
| Load 3.0 g/rev | 3.40 | 2.20 | 0.80 | 0.30 |
| Load 8.0 g/rev | 3.40 | 2.20 | 1.40 | 0.25 |

Cold plateau (≤ −20°F): uniformly 3.40× across all loads. Warm
(≥ 80°F): drops sharply to 0.25–0.40×. The load effect only matters
at warm temps (above 70°F, higher load = lower tau = better
vaporization). Below 70°F all three load bins are nearly identical.

The literal **0.004578** at `0x0373E8` is the fourth argument (`fr7`) of
the lag-filter call in `0x3735A`; "tau weight" was a guess at its role.

### Falling-load tau

> **Corrected 2026-10-11 — corrections item 100.** This heading used to
> name `tau_falling_handler @ 0x3740C`. `0x3740C` reads none of the four
> tables. It is an accumulator: it adds `[0xFFFF7A54]` (the lag-filter
> output above) to `[0xFFFF3194]` each call, and resets the sum to 0
> when `byte[0xFFFFAF3B]` goes from 0 to 1 while `[0xFFFF8EAC]` ≥
> `[0xCC2B0]` = 720.0. The four tables are real definition entries
> ("Tau Input A Falling Load Activation", "… A", "… B", "… C"); two of
> their descriptors, `0xACB7C` and `0xACB90`, are loaded from the same
> function that loads the rising one. The variant descriptions below are
> not decoded.

Four tables (PRIMARY + A + B + C):

| Table | Address | Character |
|---|---|---|
| Tau_FallingLoad PRIMARY | 0xCD746 | cold 1.42, warm 0.30 (smoothest) |
| Tau_FallingLoad_A | 0xCD766 | flat 0.50, ECT-independent |
| Tau_FallingLoad_B | 0xCD848 | cold 0.90, warm 0.30 (weaker cold) |
| Tau_FallingLoad_C | 0xCD868 | cold 0.70, **0.00 at ≥90°F** |

Variant selection logic isn't fully traced — described in the
disassembly notes as `comms_state_byte (0xFFFFAF3B)` controlling at
least one branch. In tuner terms (best understood):

- **PRIMARY** — normal closed-throttle deceleration, mild enrichment
  hold.
- **Variant A** — steady-state / cruise, flat 0.50.
- **Variant B** — partial throttle tip-out, moderate correction.
- **Variant C** — aggressive tip-out or overrun; removes correction at
  hot (90°F+).

Falling tau values are **lower than rising tau** at equivalent
temperatures (e.g., rising 1.4 g/rev × −40°F = 3.40×, falling −40°F =
1.42×; ratio ≈ 2.4:1). Tip-in needs more fuel than tip-out needs
subtracting — wall film dynamics are asymmetric.

### Load threshold gate

`CAL @ 0xCC2B0 = 720.0`. Compared against `0xFFFF8EAC` in
`tau_falling_handler`:

- `≥ 720.0`, on a 0 → 1 edge of `byte[0xFFFFAF3B]` → the accumulator
  `[0xFFFF3194]` is **reset to 0** (`0x037410`–`0x037434`).
- otherwise → `[0xFFFF7A54]` is added to it.

Corrected 2026-10-11 (corrections item 100): the earlier "PRIMARY path /
accumulation path" reading and the "720 RPM ≈ idle" guess are withdrawn.
What `0xFFFF8EAC` holds was not checked.

## How this matters for the current tune

The accel enrichment system is implicated in one open issue (see
[open-issues.md](open-issues.md)):

> **Tip-in enrichment expires before AVCS finishes ramping (post-DFCO)**
>
> `4-27 20.10/log0003.csv` shows AVCS ramping 0→23° over ~2.5s after
> DFCO; AFC accel enrichment expires partway through; knock fires
> while AVCS still mid-ramp. AVCS ramp rate observed ~18°/s.
>
> **Lever:** Extending AFC decay rate / magnitude tables would keep
> fuel-cooling active during the AVCS ramp window.

**Corrected 2026-10-11 — corrections item 100.** This section used to
list three "levers in the disassembly": the 510 / 505 "gains"
(`0xCC51C`–`0xCC528`), the `0xCBC0B` / `0xCBC0C` counters, and a "1260
RPM threshold" (`0xCC52C`). **None of them is a tip-in lever.** They are
the speed limiter's thresholds and stage counts (see above), and 1260 is
compared with manifold pressure. Changing them would not extend any
enrichment.

The open issue itself stands as an observation from the log. Which
tables would address it has **not** been re-derived here; start from the
definition XML's tip-in tables ("Fueling - Base / Enrichment"), not from
this function.

## Related

- [knock.md](knock.md) — the post-DFCO knock event sits at the
  intersection of AVCS ramp and tip-in expiration.
- [open-issues.md](open-issues.md) — "Tip-in enrichment expires before
  AVCS finishes ramping" entry.
- [logs.md](logs.md) — `AFC` column meaning (negative = enriching, the
  more negative the more fuel added).
