# Log Review Log

Append-only running history. Newest entries on top.
SOP: `scripts/analysis/log_review_checklist.md`.
Trends: `scripts/analysis/trends/`.

Per-entry template:

```
## YYYY-MM-DD — log: <relative path> — rom: <rom_rev>

**Knock:** <event count>, top cells: <(rpm,load): n>, ghost zones: <list>
**WOT:** <pull count>, knock-during: <n>, fueling notes: <...>
**MAF corr:** filtered samples: <n>, drift cells: <list with delta>
**Cliffs:** <count by table, top 3 by residency × delta>
**Stutter:** <count by signal type, top 3 events>
**VE:** <cells changed >3% vs last log, with rom_rev attribution>

**Prior-flagged areas re-checked:**
- <issue>: <status — resolved / improved / unchanged / regressed>

**New issues:**
- <description, RPM/load zone, evidence>

**Staged for next session:**
- <action items>
```

---

<!-- Entries below this line, newest first -->
## ingest 2026-05-02 (rev 20.10) auto-rollup (2026-05-04 00:07)

## VE proxy: 20.10 vs 20.9
  cells with data — 20.9: 211, 20.10: 200
  overlap (≥30 samples in each): 129
  cells with |Δ| ≥ 3%: 51

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.9 → 20.10):
    1200 ×  -8.5    6.51 →   8.55 g/s  (+31.38%, n=49/811)
    1200 × -10.5    5.12 →   5.94 g/s  (+16.12%, n=74/66)
    1200 ×  -9.0    6.65 →   7.57 g/s  (+13.98%, n=513/2979)
    3300 × -11.0    9.65 →  10.79 g/s  (+11.75%, n=193/304)
    3700 × -10.5   15.97 →  17.62 g/s  (+10.31%, n=34/33)
    2200 ×  -6.0   22.83 →  24.88 g/s  (+8.99%, n=237/428)
    2200 ×  -3.5   32.38 →  34.48 g/s  (+6.47%, n=224/261)
    2200 ×  -5.0   27.11 →  28.77 g/s  (+6.12%, n=443/383)
    3300 × -10.5   14.32 →  15.15 g/s  (+5.78%, n=44/74)
    1900 ×  -4.0   26.27 →  27.71 g/s  (+5.48%, n=90/190)

  Top VE LOSSES:
    2600 × -10.5   10.73 →   9.90 g/s  (-7.66%, n=1188/590)
    3300 ×  -8.5   24.12 →  22.57 g/s  (-6.44%, n=495/271)
    3000 ×  -0.5   56.18 →  53.00 g/s  (-5.67%, n=43/53)
    1900 ×  -8.0   15.51 →  14.64 g/s  (-5.57%, n=143/282)
     800 ×  -8.5    6.06 →   5.73 g/s  (-5.41%, n=703/245)
     800 × -10.0    4.30 →   4.07 g/s  (-5.36%, n=314/87)
    3300 ×  +0.5   68.63 →  65.09 g/s  (-5.16%, n=143/50)
    3000 ×  -1.5   52.28 →  49.68 g/s  (-4.98%, n=290/32)
    3000 ×  -0.0   59.26 →  56.32 g/s  (-4.95%, n=44/71)
    1900 ×  -5.5   22.52 →  21.46 g/s  (-4.73%, n=129/91)


