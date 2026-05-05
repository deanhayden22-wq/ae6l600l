# Methodology — pedal-correction event detection

Captured 2026-05-04. An empirical method for finding pedal-map tuning
targets from logs by detecting APP direction reversals. Pairs with a
response-lag check to separate pedal-map issues from turbo-lag.

## Concept

When the driver's pedal input doesn't match what the car delivers,
they correct. Two kinds of corrections:

- **Over-response** — driver pushed pedal, car gave more than wanted,
  driver pulls back. Manifests as a local *maximum* in APP within
  ~0.5s.
- **Under-response** — driver lifted, car didn't give enough, driver
  pushes back. Manifests as a local *minimum* in APP within ~0.5s.

## Detection algorithm

- Smooth APP with a 5-sample (200ms) median to kill 1-LSB sensor
  jitter.
- For each sample i, look in window [i−12, i+12] (~0.5s each side).
- **Peak event:** `APP[i]` is the max in window AND pre-rise > 1.5%
  AND post-fall > 1.5%.
- **Trough event:** `APP[i]` is the min in window AND pre-fall > 1.5%
  AND post-rise > 1.5%.

Filters:

- RPM 1500–6300, MPH > 5 (exclude idle/launch).
- Trough events at APP < 3% — these are mostly clutch/lift, not real
  under-response. Drop them.

## Result on the current 13-log corpus

656k samples, 12,202 reversal events:

- Over-response peaks at APP 15–18% / RPM 3000–3300 = **392 events**
  (worst single cell).
- Under-response peaks at APP 9–12% / RPM 3000–3300 = **389 events**.
- Net (under − over) heatmap: below ~14% APP user wants more response,
  above ~14% APP user wants less. Classic "hunting around an inflection
  point" — caused by pedal-map slope being too steep through that zone.

## Critical follow-up — response-lag check

After detecting under-response events, look at what happens in the next
1.0s. For this car (data from same 656k samples):

| Starting RPM | dRPM / 1s |
|---|---|
| 1500–2000 | +60 (some response) |
| 2000–3500 | 0–3 (essentially none) |
| 3500–4000 | −2 (none) |

So in 2000–3500 RPM, pedal +3% → RPM gain ≈ 0. The engine is
unresponsive. The under-response is **turbo lag**, not a pedal-map
limitation.

The heatmap identifies **where** the user is hunting; the lag check
identifies **whether** it's a pedal-map fix (yes for over-response, no
for under-response in turbo-lag zones).

See [../turbo-character.md](../turbo-character.md) for the full
response-lag profile.

## Why this works

It beats just looking at the pedal map shape — it tells you which cells
the user actually struggles with in real driving, weighted by usage
frequency.

## How to apply

Re-run after each pedal-map iteration on a fresh log. Both clusters
should shrink if the new map fixes the cliff. If the under-response
cluster persists, the lever is **Target Boost / WG duty**, not the
pedal map. See [../open-issues.md](../open-issues.md) for the active
verification.

Pair with [no-inference.md](no-inference.md) — when reporting a result
on this method, name the log subset and the events count, don't assert
hunting from a heatmap alone.
