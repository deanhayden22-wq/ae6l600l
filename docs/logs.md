# Logs — inventory and column meanings

Captured 2026-05-04. Logs come from RomRaider Logger as CSV at 25 Hz
(0.04s per sample). They live in `logs/` of the repo.

## Inventory

13 files as of 2026-04-27, ~656k samples (~438 minutes of driving).
Newer logs from 4-27 onward and 5-2 are in subfolders.

```
logs/3-21.csv             36 cols, 55,414 rows  — has Misfire1-4 cols, missing AFR
logs/3-30.csv             33 cols, 63,923 rows
logs/3-31 black.csv       33 cols
logs/4-1.csv              33 cols, 21,305 rows
logs/4-11.csv             33 cols, 40,855 rows
logs/4-12 big.csv         33 cols, 255,150 rows  — biggest single log
logs/4-23/log0001.csv     29 cols, 23,508 rows  — older 29-col format
logs/4-23/log0002.csv     29 cols, 10,215 rows
logs/4-24/log0003.csv     29 cols, 27,006 rows
logs/4-24/log0004.csv     33 cols, 50,914 rows  — was THE oscillation log
logs/4-24/log0005.csv     29 cols, 4,549 rows
logs/4-24/log0006.csv     29 cols, 63,163 rows
logs/4-25/4-25 full.csv   33 cols, 131,516 rows  — 20.9 baseline
logs/4-27 20.10/4-27.csv  33 cols, 35,886 rows  — 20.10 verification
logs/4-27 20.10/log0001.csv
logs/4-27 20.10/log0002.csv
logs/4-27 20.10/log0003.csv
logs/5-2/5-2.csv          33 cols, 87,585 rows
logs/log0004.csv          29 cols, 20,327 rows
logs/log0005.csv          29 cols, 20,528 rows
logs/logcfg.txt           — RomRaider Logger config defining params
```

When loading logs, also load `logs/log0004.csv` and `logs/log0005.csv`
from the root — they're easy to miss alongside the dated subdirs.

When analyzing pedal/throttle behavior, **use all logs** unless there's
a specific reason to subset. Older logs (3-21, 3-30, 4-1, 4-11) were on
earlier tune revisions but still useful for engine-character profiling
(turbo response, AVCS, MAF-vs-TPS curve) since those are physics, not
tune-dependent.

## Standard schema (33-column logs)

```
sample, time, wbo2, AFR, FFB, EGT, AFC, AFL, correction, RPM, load, MPH,
Timing, IAT, MAF, MAF(V), Accelerator, Throttle, RQTQ, ATM(psi), MAP,
mrp, Trgt_Boost, IAM, CL/OL, FLKC, FBKC, avcs, wgdc, tdi, Tdp, IPW, IDC
```

29-column logs are missing some derivative cols but have all the
throttle-tuning-relevant fields.

## Column meanings — non-obvious or inverted

Several columns required user corrections to get right. These are
worth knowing before doing any log analysis:

| Column | Meaning |
|---|---|
| **FFB** | **Commanded** AFR. This is what the ECU is *asking* for (e.g., 12.86 = ECU wants 12.86 AFR). Use this for "what the ECU wants." |
| **AFR** | Stock O2 sensor reading. "Fine but not totally reliable." Value **20.327** is a flag/state placeholder (likely DFCO/fuel-cut), not a real AFR — appears as a top-5 most-common value. Don't conflate with commanded; FFB is commanded. |
| **wbo2** | Measured wideband AFR. Has **~320ms sensor lag** (peak cross-correlation between wbo2 and FFB at 8 samples × 0.04s/sample at 25 Hz). Use for actual cylinder AFR but expect transient excursions to lag the command. |
| **EGT** | Measured in **OHMS, not degrees**. **Lower ohms = HOTTER.** 31–33 ohms is normal cruise; 29 is hotter than 31. Inverted from intuition. |
| **CL/OL** | Fueling state. State **8 = closed-loop stoich**. State **10 = open-loop** (covers acceleration enrichment AND decel/post-DFCO; it's not "OL = always accel"). |
| **AFC** | Accel enrichment value. **Negative = enriching**; the more negative, the more fuel added. Fires during tip-in events, decays after. |
| **AFL** | Appears related to AFC (accel fueling learning?). Not deeply characterized. Don't lean on it. |
| **FBKC** | Feedback knock correction (degrees). **Negative = pulling timing for active knock.** |
| **FLKC** | Fine learning knock correction (degrees). Long-term knock learning. |
| **IAM** | Ignition advance multiplier. 1.0 = max. Drops only under sustained knock; transient knock that doesn't pull IAM is still real but hasn't ratcheted yet. |
| **avcs** | Intake cam advance, degrees. |
| **wgdc** | Wastegate duty cycle, %. |
| **RQTQ** | Requested torque, raw 0–360. The pedal-map output. |
| **load** | Engine load, g/rev. |
| **MAP** | Manifold absolute pressure, psia. |
| **ATM(psi)** | Atmospheric pressure, psia. **Computed boost = MAP − ATM.** |
| **Accelerator** | APP %. |
| **Throttle** | TPS %. |

A new column **KNOCK_FLAG** appears in 4-27 logs onward (not in earlier
logs). Meaning not yet confirmed.

## Per-LSB quantization to know about

- APP sensor: **0.392% LSB** (0.39% pedal jitter visible in raw values
  like 11.37, 11.76, 12.16).
- TPS: similar 0.39% LSB.
- RQTQ: floats so smooth, but pedal-map output is uint16 × 0.0078125
  underlying.

## Per-log review

The full SOP for reviewing a new log is in
`scripts/analysis/log_review_checklist.md`. Per-log writeups go in
`logs/REVIEW_LOG.md` (append-only, newest first). Per-metric trend
CSVs accumulate in `scripts/analysis/trends/`.

See also [methodology/cruise-residency.md](methodology/cruise-residency.md)
for the cruise filter that's locked across reviews.
