# Methodology — stock vs 20G AVCS comparison

Captured 2026-05-04. Comparing the tuned AVCS against stock is only
valid where both engines are in the same pressure regime. Stock is a
VF52 (small twin-scroll, lights ~2000–2200 RPM); the 20G doesn't make
positive boost in cruise until ~1.3 g/rev × 2500+ RPM. The mismatch is
load-band specific.

## Why this matters

Stock pulls AVCS sharply at 1.0+ load because *stock* is entering boost
there. Subaru is managing residual gas content (ultimately knock margin)
under positive IMP. On the 20G, those same cells are still in vacuum,
so the inference "stock pulled, so we should pull" applies the wrong
calibration goal to the wrong pressure regime.

Mechanism nuance: small turbos in modest boost still have EMP > IMP
(turbine restriction), so it's not literally "blow-through" — it's
hot-residual management for knock under positive IMP. Outcome direction
is the same — pull overlap when entering load — but the trigger
condition isn't met on the 20G in those same load cells.

## Verified MRP from 20G logs (CL=8 means)

| Load | RPM | 20G state |
|---|---|---|
| 1.00–1.10 | 2200–3400 | vacuum (MRP −0.5 to −2 psi) |
| 1.20 | 2500–3000 | borderline (MRP +0.1 to +0.5 psi cruise) |
| 1.30 | 2500–3400 | real boost (MRP +1.3 to +1.7 psi cruise) |

## How to apply — segment by load band

Treat the stock comparator as:

- **VALID at 0.20–0.95 load** — both engines in vacuum. Ignore stock
  cruise's 40° EGR overlay at 0.5–0.8; that's emissions strategy, not
  VE.
- **BROKEN at 1.0–1.2 load** — stock in boost regime, 20G in
  vacuum/transition. Don't recommend AVCS pulls here based on "tune is
  X° above stock" alone.
- **VALID at 1.5+ load** — both in boost, mostly.

## Examples

- The **21.5° plateau at 1.2 load × 2200–3000 RPM** is a defensible 20G
  value, NOT a "tune is 6.5° too advanced vs stock" finding.
- The **3400→3800 RPM cliff at 1.0–1.2 load (−4.25 to −4.50°)** may be
  intentionally aligned with the 20G's boost-on transition, not a
  defect.
- The cliffs that **are** clean candidates for smoothing are at 0.5–0.9
  load (both turbos in vacuum), where the doc's "stock and model both
  indicate less advance at higher RPM" reasoning still applies.

## Tooling

The `avcs_cruise_review.py` tool shows stock cruise + stock non-cruise
comparator columns side-by-side; pick the right one per turbo regime.
A queued enhancement adds a boost-regime overlay column that fires this
caveat automatically — see [../avcs.md](../avcs.md) for the tool list.
