# Cruise tuning tables — verified addresses and scalings

Captured 2026-05-04. For AE5L600L (2013 USDM Impreza WRX MT, 20g
tinywrex variant). Re-verify against
`definitions/AE5L600L 2013 USDM Impreza WRX MT.xml` before relying on
any value.

The project XML overrides base XML axis sizes for several of these.
Values below are from the project XML, with scalings inherited from
`definitions/32BITBASE.xml`. Confirmed by reading raw bytes from rev
20.9 and 20.10 ROMs and verifying that
`load_addr + 4 × N_load == rpm_addr` and
`rpm_addr + 4 × N_rpm == table_addr`.

Axes are float32 big-endian; raw value = display value (g/rev for load,
RPM for speed).

## The five RPM × Load tables used in cruise residency analysis

| Table | Table addr | Load addr / N | RPM addr / N | Cell type | Scaling | Units |
|---|---|---|---|---|---|---|
| Intake Cam Advance Cruise (AVCS) | 0xda96c | 0xda8e4 / 18 | 0xda92c / 16 | uint16 BE | raw × 0.0054931640625 | deg |
| Primary OL Fueling KCA-B Low | 0xd0244 | 0xd01b8 / 17 | 0xd01fc / 18 | uint8 | 14.7 / (1 + raw × 0.0078125) | AFR |
| Primary OL Fueling KCA-B High | 0xd0404 | 0xd0378 / 17 | 0xd03bc / 18 | uint8 | same as B Low | AFR |
| Base Timing Primary Cruise | 0xd4714 | 0xd4688 / 17 | 0xd46cc / 18 | uint8 | raw × 0.3515625 − 20 | deg BTDC |
| Knock Correction Adv Max Cruise | 0xd5904 | 0xd5878 / 17 | 0xd58bc / 18 | uint8 | raw × 0.3515625 | deg |
| CL Fueling Target Comp A (Load) | 0xd14d0 | 0xd147c / 11 | 0xd14a8 / 10 | uint16 BE | raw × 0.000224304213 − 7.35 | AFR pts |

**Storage layout for all:** row-major with outer index = Y (RPM), inner
= X (Load). Read as `T[y][x] = raw[y × N_load + x]`.

## Non-Cruise siblings

Same storage layout, different tables. Addresses from project XML:

| Table | Address |
|---|---|
| Base Timing Primary Non-Cruise | 0xd48d4 |
| Base Timing Reference Non-Cruise | 0xd4c54 |
| Knock Correction Adv Max Non-Cruise | 0xd5ac4 |
| Intake Cam Advance Non-Cruise | 0xdac34 |

Note: a stale candidate of 0xdac7c for Non-Cruise AVCS has appeared in
working notes; the canonical from the project XML is **0xdac34**.

## All five OL fueling tables

For the full set including Failsafe and KCA Alternate Mode, plus the
"identity of three" rule, see [ol-fueling.md](ol-fueling.md).

Identity findings as of 20.9 and 20.10 — these may go stale silently
on any new rev:

- B Low ≡ B High ≡ KCA Alternate Mode (byte-identical).
- Failsafe ≡ Failsafe Alt (byte-identical to each other, different
  from B Low).

Re-verify with md5 / cmp before assuming on any future rev.

## Pedal-to-throttle table addresses

Documented in [pedal-throttle.md](pedal-throttle.md). Summary:

| Table | Address |
|---|---|
| Requested Torque APP — Sport | 0xF99E0 |
| Requested Torque APP — Sport Sharp | 0xF9C60 |
| Requested Torque APP — Intelligent | 0xF9EE0 |
| Requested Torque Base (RPM) | 0xF8B54 |
| Target Throttle Plate — Cruise | 0xF9004 |
| Target Throttle Plate — Non-Cruise | 0xF9284 |
| Target Throttle Plate — Maximum | 0xF9504 |

## Boost control RQTQ-axis tables

| Table | Address |
|---|---|
| Target Boost | 0xC1340 |
| Initial WG Duty | 0xC1150 |
| Max WG Duty | 0xC0F58 |

## MAF Sensor Scaling

| Table | Address |
|---|---|
| MAF Sensor Scaling | 0xd8c9c |

32-entry float table + 3 extended-region cells past idx 31. Edited in
20.11 — see [tune-state.md](tune-state.md).
