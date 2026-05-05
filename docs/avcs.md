# AVCS — findings and tools

Captured 2026-05-04. AVCS = Active Valve Control System (Subaru's
intake cam phaser). On AE5L600L there's a Cruise / Non-Cruise pair for
the Intake Cam Advance Angle table. Both are addressed by RPM × Load.

## Verified addresses

| Table | Address | Notes |
|---|---|---|
| Intake Cam Advance Cruise | 0xda96c | uint16 BE × 0.0054931640625, deg |
| Intake Cam Advance Non-Cruise | 0xdac34 | per project XML line 691 |

The 4-27 chat referenced 0xdac7c for Non-Cruise; that's stale. The
canonical from the project XML is **0xdac34**. Re-verify before acting.

For full table addressing including axes and storage layout, see
[cruise-tables.md](cruise-tables.md).

## Stock comparator caveat

Comparing tuned AVCS values against stock is only valid where both
engines are in the same pressure regime. Stock is a VF52 (lights
~2000–2200 RPM); the 20G doesn't make positive boost in cruise until
~1.3 g/rev × 2500+ RPM.

This is important enough to have its own methodology page —
[methodology/stock-comparator.md](methodology/stock-comparator.md).
The short version: don't recommend AVCS pulls in 1.0–1.2 load just
because the tune is X° above stock. Stock is in boost there; the 20G
isn't.

## AVCS↔MAF coupling in cruise (empirical, 20.9 → 20.10)

Measured via `cross_rev_diff.py --before 20.9 --after 20.10` on 254k
samples spanning 4-25 (20.9, 131k samples) and 4-27 + 5-2 (20.10, 124k
samples).

**Fact:** Across 16 changed cells with sufficient sample coverage on
each side, matched at same pedal/RPM/IAT (Strategy B):

- Median |ΔMAF| = 0.30 g/s (~1.7%)
- Largest = −1.67 g/s at (3000, 0.30) (−7.8%, only +1.54° actual AVCS
  shift, likely transient-contaminated)
- The deliberate +18° table jump at (2500, 0.20) produced only
  −0.27 g/s of MAF shift (−2.5%) at fixed pedal
- Sign of ΔMAF was inconsistent across cells with similar AVCS Δ — no
  coherent predictive coefficient

**Why this matters:** The framing "if I reduce AVCS by X, g/s reduces
by X" isn't supportable at this signal level. The corollary is
operationally useful: **AVCS edits in the cruise zone don't significantly
contaminate MAF scaling**, so AVCS can be iterated without chasing MAF
behind it.

**How to apply:**

- Don't propose MAF re-scaling as a follow-up to small AVCS
  cliff-smoothing edits in cruise. The signal is below the practical
  noise floor for fuel trim tuning.
- Cross-rev diff still has value as a **diagnostic** ("did the edit
  move actual AVCS at the operating points the engine spent time at"),
  not predictive ("if I move AVCS by X, MAF moves by Y").
- The +18° cell at (2500, 0.20) was a deliberate cliff fix for a felt
  35–40 mph stutter; "actual delta only +5°" reflects oscillation
  removal, not unrealized intent. **Mean-AVCS is the wrong diagnostic
  for cliff fixes — swing-in-window is right** (queued as a tool
  enhancement, see below).
- This finding is for the cruise zone only (CL=8, 0.2–1.0 g/rev, mid
  RPM). At full boost / OL the coupling may be stronger; not yet
  measured.

## Analysis tools

Both live in `scripts/analysis/` and write reports into
`scripts/analysis/trends/`.

### `avcs_cruise_review.py` — single-rev review

Inputs: `--rom`, optional `--prior`, `--logs`, `--label`.

Outputs: AVCS Cruise table dump, NC=Cruise byte-identity check, diff vs
prior ROM, bilinear-interp comparison vs stock cruise + stock non-
cruise (both columns shown side-by-side; pick the right comparator per
turbo regime), cruise + all-state residency heatmaps, RPM cliffs and
load cliffs above thresholds, residency-weighted candidate-edit cells,
and an optional knock overlay from `trends/knock_by_cell.csv` if
`rom_rev` row exists there.

Example:

```
python scripts/analysis/avcs_cruise_review.py \
    --rom "rom/AE5L600L 20g rev 20.11.bin" \
    --prior "rom/AE5L600L 20g rev 20.10 tiny wrex.bin" \
    --logs "logs/**/*.csv" \
    --label 20.11
```

Output: `scripts/analysis/trends/avcs_review_<label>.txt`

### `cross_rev_diff.py` — diagnostic before/after across two revs

Inputs: `--before <label>`, `--after <label>` (labels match
`rom_rev_map.csv` and the `ROM_FILES` dict at top of the script).
Auto-pulls logs mapped to each rev.

Outputs: list of changed cells with table-Δ; for each cell with
sufficient samples on each side, two matching strategies:

- **A.** Match on (RPM, load) cell — same fill, see how throttle / MAF
  / MRP shifted.
- **B.** Match on (RPM±100, Throttle±1%, IAT±5°C) — same pedal, see how
  MAF and load shifted.

Example:

```
python scripts/analysis/cross_rev_diff.py --before 20.9 --after 20.10
```

Output: `scripts/analysis/trends/cross_rev_<before>_<after>.txt`

### Pending tool enhancements

Sessions queued, not yet built:

1. `avcs_cruise_review.py` — boost-regime overlay column on the stock
   comparison table, auto-flagging cells where stock is in boost but
   the 20G isn't. So the regime-mismatch caveat fires automatically
   without re-deriving it.
2. `cross_rev_diff.py` — apply the steady-state filter from
   [methodology/cruise-residency.md](methodology/cruise-residency.md)
   (1s std on RPM/load/throttle) before computing AVCS statistics; add
   max-swing-in-2s-window per cell. Without stability gating,
   transient samples inflate variance and mask cliff-fix wins.
3. `cross_rev_diff.py` — bilinear-remap support for stock → 20.8 (axes
   differ between Subaru and tuned ROMs); current code aborts on axis
   mismatch.

## Related

- [methodology/stock-comparator.md](methodology/stock-comparator.md) —
  why stock-vs-tune AVCS comparison breaks at the boost-transition load
  band.
- [methodology/cruise-residency.md](methodology/cruise-residency.md) —
  the cruise filter and cliff thresholds these tools use.
- [open-issues.md](open-issues.md) — AVCS-pinned-at-0° in non-cruise
  high-load and AVCS ramp-lag issues.
