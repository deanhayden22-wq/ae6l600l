# 20G turbo engine character

Captured 2026-05-04. The car is a 2013 USDM WRX MT with a 20G turbo
upgraded from stock VF52. Engine character matters for any throttle or
boost tuning decision.

## Spool

- Stock VF52 (twin-scroll) lights ~2000–2200 RPM.
- This 20G doesn't really make power until **~3000 RPM**.
- Boost attainment ratio (actual / target) averages **0.38** in driving
  logs across 1500–4000 RPM. The engine consistently undershoots target
  in that band.
- Real boost only catches up to target above ~4500 RPM.

## Response lag

From event detection across 656k log samples (13 logs). After the driver
pushes pedal +3% APP, RPM gain in the next 1.0s by starting RPM band:

| Starting RPM | dRPM / 1s |
|---|---|
| 1500–2000 | +60 (some response) |
| 2000–2500 | +5 (barely) |
| 2500–3000 | +3 (essentially nothing) |
| 3000–3500 | 0 (no response — turbo not yet spooled) |
| 3500–4000 | −2 (no response) |

**Implication:** under-response complaints at 9–12% APP / 2700–3300 RPM
are turbo-spool-limited, not pedal-map-limited. The pedal map can shape
throttle to help spool, but cannot manufacture torque the turbo isn't
making.

## Soft rev limiter

User-implemented in the pedal map on top of the stock hard cut:

- 6700 RPM hard fuel-cut (from 0xCC500 / 0xCC504, stock).
- Pedal-map rows 6450 and 6500 cap RQTQ to 70 (well below
  Base[6450/6500] = 279), which forces ratio ≪ 1.0 → TPS clamped low
  → engine can't make power → RPM rolls back.
- 6400 RPM row also has soft taper (RQTQ at 100% APP = 70 — soft cut
  starts here).
- Per Dean: "the current cut works well, no need to smooth into those
  values" — leave 6400 / 6450 / 6500 alone.

## How to apply

- Don't propose pedal-map changes that promise more low-RPM response
  than physics allows. Anywhere below ~3000 RPM, more pedal authority
  doesn't add torque — it's mostly throttle hunting / feel.
- The real lever for low-RPM under-response is **Target Boost**
  (0xC1340) and **WG duty** tables, not the pedal map.
- Soft cut rows (6400 / 6450 / 6500) are user-tuned and correct —
  preserve byte-identical.

## Related

- [pedal-throttle.md](pedal-throttle.md) — the three-table architecture
  the pedal map sits in.
- [open-issues.md](open-issues.md) — "Low-RPM under-response is
  fundamentally turbo-lag bound" entry tracks the boost-control work
  that's queued.
