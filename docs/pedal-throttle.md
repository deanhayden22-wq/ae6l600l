# Pedal-to-throttle architecture

Captured 2026-05-04. Verify table addresses against
`definitions/AE5L600L 2013 USDM Impreza WRX MT.xml` before acting on
them. Bins are overwritten in place; table contents drift.

## The three-table chain

The drive-by-wire pedal-to-throttle path on AE5L600L goes through three
tables:

```
APP, RPM ─► Requested Torque (APP)            (3D, 15×17 uint16 × 0.0078125)
            0xF99E0  Sport
            0xF9C60  Sport Sharp
            0xF9EE0  Intelligent
            (byte-identical on this ROM — USDM MT has no SI-DRIVE switch)
            outputs RQTQ (logged as Requested Torque, raw 0–360)
                          │
                          ▼
RPM       ─► Requested Torque Base (RPM)      (2D, 16-entry uint16 × 0.0078125)
            0xF8B54
            ratio = RQTQ / Base
                          │
                          ▼
ratio,RPM ─► Target Throttle Plate Position   (3D, 16×16 uint16 × 0.002270655)
            0xF9004  Cruise
            0xF9284  Non-Cruise
            0xF9504  Maximum
            outputs target TPS%, then DBW PID closes on it
```

## Why this matters

Touching the pedal map ripples through every downstream lookup: ratio
(col 1) → TPS (col 2) → and into Target Boost, which uses RQTQ as its
own X-axis directly. You can't reason about pedal-map effects in
isolation.

Reverse-engineering an RQTQ value from a TPS table **fails** when TPS
saturates at 102.4 — every RQTQ ≥ Base produces TPS = 102.4. If you're
inspecting a TPS table from the user's mapping app and a cell shows
102.4, the underlying RQTQ is unrecoverable; ask for the RQTQ table.

## State of the structural tables on this ROM

- **Cruise / Non-Cruise Target Throttle** are byte-identical from rev
  20.6 onward. The prior tuner flattened the 162 cells that differ in
  stock. The cruise/non-cruise blend is effectively a no-op here.
- **Maximum Target Throttle** (0xF9504) is fully open at 102.4 across
  the board — also a no-op limiter.
- **Sport / Sport Sharp / Intelligent pedal maps** are byte-identical
  on this ROM (no SI-DRIVE switch on USDM MT). Update all three together
  to preserve identity.

## The ratio = 1.0 cliff (the WOT trigger)

The Target Throttle table has a **step at ratio = 1.0**:

- ratio 0.99 → 52.8% TPS at 3200 RPM
- ratio 1.00 → 102.4% TPS

That step **is** the WOT mode trigger. You cannot get TPS > ~52% without
crossing it. Anywhere a pedal map cell lands ratio ≥ 1.0 produces a
hard throttle-open cliff at that pedal position.

This is structural — design the pedal map around where the ratio = 1.0
cliff lands in pedal travel. Don't try to engineer around the cliff
without moving it.

## Downstream consumers of RQTQ

Pedal-map changes shift these lookups too:

- **Target Boost** (0xC1340) — uses RQTQ as X-axis.
- **Initial WG Duty** (0xC1150) — uses RQTQ.
- **Max WG Duty** (0xC0F58) — uses RQTQ.

Any RQTQ shift moves the operating point through the boost-control
strategy. If the goal is purely pedal feel, keep RQTQ shifts modest in
the operating band.

## Current pedal map design state

As of 2026-04-27, the Sport pedal map is being iterated to fix cruise
oscillation and customize throttle character for the 20G turbo. Working
files are in `Throttle tuning/`.

X-axis was modified from stock `…78.6, 86.7, 100` to `…75, 80, 100` to
bring the WOT trigger closer in pedal travel.

Cruise smoothing applied to fix hunting at APP 12–22% / RPM 2700–3300
(heatmap showed 392 over-response events at the worst cell — see
[methodology/pedal-correction.md](methodology/pedal-correction.md)):

- Col 2 (10% APP) × 1.30 across all driving rows — raise (was
  under-pushing here)
- Col 3 (16.5% APP) × 0.85 — lower (was over-pushing here)
- Col 4 (25% APP) × 0.92 — mild lower
- Cols 5+ (31% APP onward) preserved from 20.8

Slope through 10→16.5% APP cliff: cut from ~18.8 RQTQ/% (20.8) to
~13 RQTQ/% (current) at the worst hunting RPMs.

### WOT trigger placement (per-RPM, intentional)

| RPM range | WOT trigger |
|---|---|
| 800–1600 | 100% APP only (col 14) — 20G can't spool, no benefit from early WOT, avoid low-RPM lurch |
| 2000+ | 80% APP (col 13) — helps the 20G light off |
| 6400+ | never WOT — soft cut zone |

At 5600 and 6000 RPM the user explicitly lowered col 12 (75% APP) below
Base (313 and 302 respectively) to keep the cliff cleanly at
75→80% APP at high RPM.

### Boost modulation 80→100% APP (verified working)

| RPM | 80% APP | 100% APP | Sweep |
|---|---|---|---|
| 2400 | +24 psi | +28 psi | +4 psi |
| 2800 | +26 psi | +33 psi | +6 psi (biggest) |
| 3200 | +30 psi | +35 psi | +5 psi |
| 3600+ | ~34–37 psi | ~34–37 psi | flat (TB map ceiling) |

### Marginal cell to watch

(2000 RPM, col 13) = 250.3 RQTQ vs Base = 250 → ratio 1.001. Just past
the WOT trigger. See the corresponding entry in
[open-issues.md](open-issues.md).

### Soft rev limiter

User-implemented soft cut on top of the 6700 RPM hard fuel-cut (from
0xCC500/CC504, stock value):

- Rows 6450 and 6500 in the pedal map cap RQTQ to 70 (well below
  Base[6450/6500] = 279) — forces ratio ≪ 1.0 → TPS clamped low →
  engine can't make power → RPM rolls back.
- 6400 RPM row also has soft taper (RQTQ at 100% APP = 70).
- Per Dean: "the current cut works well, no need to smooth into those
  values" — leave 6400/6450/6500 alone.

## Reviewing proposed map changes

When proposing a new pedal map (RQTQ table), **also compute and show
the resulting TPS table**. The TPS table is what the user reviews — TPS
is what the engine sees and what causes the felt behavior. RQTQ is an
intermediate; sanity-checking only at the RQTQ layer misses problems
caused by the Target Throttle table (ratio = 1.0 cliff, low-RPM
plateaus, monotonicity violations across RPM).

Specifically watch for:

- **TPS cliffs** (large jumps between adjacent cells in pedal direction)
  — caused by ratio crossing 1.0.
- **Cross-RPM bumps in a single APP column** (TPS not monotonic as RPM
  rises) — caused by uneven RPM-weighted smoothing.
- **TPS at the cruise dwell points** (12–21% APP, 2400–3800 RPM)
  matches expectation.

Apply changes uniformly across rows unless there's a specific physical
reason to bias by RPM. v8 had cross-RPM bumps from per-RPM-weighted
smoothing; v9's uniform multiplier fixed it.

## Related

- [turbo-character.md](turbo-character.md) — the 20G's spool/response
  character constrains what the pedal map can fix.
- [methodology/pedal-correction.md](methodology/pedal-correction.md) —
  how to detect hunting in logs to validate post-flash.
- [open-issues.md](open-issues.md) — current pedal-tuning issues are
  staged for verification there.

## Pedal map history and log check (added 2026-11-27)

Fingerprinted across every saved bin (`Requested Torque (Accelerator Pedal) SI-DRIVE Sport`):
changed in garn (88 cells vs stock), 20.8 (215), 20.9 (87, axis tail 78.6/86.7 -> 75/80),
20.14 (24), 20.16 (16), 20.19e (8, top-end only). Identical 20.9-20.13, 20.14-20.15, 20.16-20.19d.
`Requested Torque Base` and both Target Throttle tables were rewritten in 20.8 and are unchanged since.
Per-gear `Requested Torque Limit A/B` are 500 everywhere (no limiting).

Light pedal has been raised three times (20.8, 20.9, 20.16): at 8% pedal RQTQ is 56-92 vs stock 28-48.
16.5-25% is back near stock after the 20.9 hunting cut and the 20.14 partial restore.

Logs (steady pedal, warm, garn 3-21/3-30/4-1 vs 19c 8-22/11-20 vs 19e 11-24):
- Town driving sits at 0-16.5% pedal almost all the time; above 25% is under 3% of on-pedal time.
  Median pedal fell from ~12% (garn) to ~8% (19e).
- Load per pedal at 2400-2800 rpm (19e): 0.32 / 0.45 / 0.59 / 0.76 / 0.89 for 0-4 / 4-8 / 8-12 /
  12-16.5 / 16.5-20%: close to linear in airflow. Garn base: 0.25 / 0.35 / 0.44 / 0.70 / 1.00.
- Throttle saturation (19c+19e): manifold reaches ~atmospheric at ~28% plate at 1400-2000 rpm and
  ~28-32% at 2000-3200. More plate than that waits on the turbo.
- Only deficit vs stock: 1200-2000 rpm x 20-37% pedal, modelled target plate 20-25% vs stock 25-31%
  (i.e. stock reaches atmospheric there, 19e stops about 2 psi short). The 20.14 "push further" rule applies.
- Modelled target plate (this chain) reads ~8 points below the logged `Throttle` channel at every
  opening; relative comparisons are unaffected, absolute plate % is not established.
