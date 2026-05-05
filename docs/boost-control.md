# Boost control

Captured 2026-05-04. Full disassembly is in
`disassembly/analysis/boost_control_analysis.txt` (430 lines) — this
page is the navigation layer + tuning-relevant summary.

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

## PID terms

| Address | Value | What |
|---|---|---|
| 0xC0D04 | −160.0 | Proportional, WG duty correction per boost error |
| 0xC0D3C | −240.0 | Integral, WG duty correction per boost error |
| 0xC0D74 | 0.0 | Derivative (disabled) |
| 0xC0BD4 | 210.0 | TD activation threshold (target boost) |
| 0xC0BF0 | −90.0 | TD integral cumulative range clamp |
| 0xC0BDC | 0.0 | TD integral negative activation |
| 0xC0BE0 | 5.0 | TD integral positive activation |
| 0xC0BE4 | 5.0 | TD integral WG duty activation |

Task 52's IIR filter uses `0xC0D74 = 0.5` (filter coefficient) —
exponential moving average on boost error and RPM error.

## Safety / disable conditions

The control loop disables and ramps down when:

| Condition | Ramp rate |
|---|---|
| Engine not running | Instant 0 |
| Throttle == 1 or boost_flag == 1 | −1.0/cycle (fast, ~1% per scheduler cycle) |
| Boost-control enable byte == 0 | −0.01/cycle (medium) |
| Enable counter < 8 | −0.005/cycle (very slow, hysteresis warmup) |

Knock-related disables:

| Cal | Value | What |
|---|---|---|
| 0xC0BFC | 0.2 | `BoostControlDisable_IAM` — disable if IAM < 0.2 |
| 0xC0BF8 | −1.0 | `BoostControlDisable_FineCorrection` — disable if fine knock corr < −1.0 |
| 0xC0BAD | 2 | `BoostControlDisableDelay_FineCorr` — delay counter |

So the boost system itself reads IAM and fine knock correction and
backs off when it sees them. Knock work elsewhere flows through here.

## Enable hysteresis

The control loop uses 0xD6720 = 4.0 (enable threshold) and 0xD6724 =
5.0 (disable threshold) on engine load:

- Enable when load > 4.0
- Disable when load ≤ 5.0
- Hysteresis: enable at 4.0, hold until > 5.0

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

- **Max Wastegate Duty** (0xC0FE0) — note: this address is the table
  data; the table header is at 0xC0F58.
- **Initial Wastegate Duty** (0xC11D8) — table header at 0xC1150.

These changes were detected via byte-diff of the 20.9 → 20.10 ROMs but
weren't documented in working notes. If they need re-derivation,
extract both versions and diff cell-by-cell.
