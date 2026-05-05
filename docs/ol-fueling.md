# Primary OL Fueling — five tables, identity rule

Captured 2026-05-04. For full table addressing including axes and
storage layout, see [cruise-tables.md](cruise-tables.md).

## The five tables

In the project XML category "Fueling - CL/OL Transition":

| Table | Address |
|---|---|
| Primary OL Fueling (KCA Additive B Low) | 0xd0244 |
| Primary OL Fueling (KCA Additive B High) | 0xd0404 |
| Primary OL Fueling (Failsafe) | 0xd05c4 |
| Primary OL Fueling (KCA Alternate Mode) | 0xcfd30 |
| Primary OL Fueling (Failsafe)(KCA Alternate Mode) | 0xcfef0 |

Each is **17 cols × 18 rows = 306 bytes, uint8** encoded.

Scaling: `AFR = 14.7 / (1 + raw × 0.0078125)`.

## The identity-of-three rule

Dean keeps three of the five mirrored:

> "There's three OL maps, I make them all the same."

Verified by md5 in 20.9 and 20.10:

- **B Low ≡ B High ≡ KCA Alt** — all three byte-identical. This is
  "the three" Dean keeps in sync.
- **Failsafe ≡ Failsafe Alt** — these two are byte-identical to each
  other but **different** from B Low (separate pair, presumably
  failsafe-specific values).

So the actual variants on this ROM are 2, not 5.

## How to apply

- When proposing changes to OL fueling, change all three of B Low,
  B High, KCA Alt **together**. Dean keeps them mirrored.
- The Failsafe pair is independent; touch only if specifically
  discussing failsafe behavior.
- Re-verify identity by md5 on any new rev. Bins overwrite in place;
  prior identity claims can go stale silently.

## Recent changes

20.10 leanout (per [tune-state.md](tune-state.md)) — graduated +0.21 to
+0.40 AFR in 3700–5500 RPM × 0.73–1.36 cells, mostly +0.32 to +0.40 in
column 1.36 across 2200–6000 RPM. This produced a knock spike in
3500–5500 RPM × 0.7–1.6 OL — see [open-issues.md](open-issues.md).
