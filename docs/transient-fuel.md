# Transient fueling — accel enrichment + tau-alpha

Captured 2026-05-04. Full disassembly in
`disassembly/analysis/accel_enrichment_analysis.txt` (607 lines) and
`disassembly/analysis/tau_alpha_analysis.txt` (437 lines). This page is
the navigation layer + tuning-relevant summary.

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

fuel_accel_enrich (0x3BB6C)               — separate state machine,
   │                                        called from a different path
   ├── condition queries
   ├── gain selection (A or B)
   ├── ACTIVE / NOT-ACTIVE state machine
   └── enrich_apply (tail call)            — applies workspace state
```

`fuel_accel_enrich` is **not** called from `fuel_transient_comp`. Both
are periodic tasks dispatched separately by the scheduler.

## Tip-in enrichment (`fuel_accel_enrich @ 0x3BB6C`)

State machine on `0xFFFF7CE0` workspace. Two states (active /
not-active), two counters (applied, inactive), both with the same
threshold of 3 cycles.

### Gain calibration

| Address | Value | What |
|---|---|---|
| 0xCC51C | 510.0 | tip-in gain, set A |
| 0xCC520 | 510.0 | tip-in gain, set B |
| 0xCC524 | 505.0 | tip-out / decay gain, set A |
| 0xCC528 | 505.0 | tip-out / decay gain, set B |
| 0xCC52C | 1260.0 | RPM threshold (deactivation gate) |
| 0xCC530 | 10000.0 | decay saturation sentinel |

Both gain sets are currently **identical**. The B-set appears to be an
OEM provision for alternate operating conditions (likely closed-loop
vs open-loop mode), but as currently calibrated they don't differ.

### Counter thresholds

| Address | Value |
|---|---|
| 0xCBC0B | 3 (= active counter threshold) |
| 0xCBC0C | 3 (= inactive counter threshold) |

### RPM gate

Enrichment can't deactivate below 1260 RPM. This sustains tip-in fuel
at low RPM where the engine is most susceptible to lean stumble.

### Magnitude

Gain × throttle delta. At 10% TPS opening: 510.0 × 0.10 = 51.0 (units:
IPW ms × gain). The throttle delta is normalized 0.0–1.0, computed by
`throttle_delta_calc`.

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

### Rising-load tau (`tau_rising_handler @ 0x3735A`)

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

Tau weight constant: **0.004578** (ROM literal at 0x0373E8).

### Falling-load tau (`tau_falling_handler @ 0x3740C`)

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

- `≥ 720.0` → PRIMARY path (active falling tau correction).
- `< 720.0` → accumulation path (history-based fallback).

Likely RPM units (720 RPM ≈ target idle); the gate says "only apply
falling tau correction above idle." Below idle, falling tau would
fight idle stability.

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

The relevant levers in the disassembly:

- The 510.0 / 505.0 gains (0xCC51C–0xCC528) — magnitude.
- The 0xCBC0B / 0xCBC0C counters (= 3 cycles each) — duration.
- The 1260 RPM threshold (0xCC52C) — when deactivation is allowed.

Increasing the counters or the gains would extend the decay tail
through the AVCS ramp window. The tau falling tables are a different
correction loop; the AFR delta in the post-DFCO case is throttle-rate
driven, not load-rate driven, so this is a tip-in problem.

## Related

- [knock.md](knock.md) — the post-DFCO knock event sits at the
  intersection of AVCS ramp and tip-in expiration.
- [open-issues.md](open-issues.md) — "Tip-in enrichment expires before
  AVCS finishes ramping" entry.
- [logs.md](logs.md) — `AFC` column meaning (negative = enriching, the
  more negative the more fuel added).
