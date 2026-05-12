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
## auto-generated rev rollup (2026-05-12 00:56)

## VE proxy: stock vs old_2023_base
  cells with data — old_2023_base: 53, stock: 210
  overlap (≥30 samples in each): 11
  cells with |Δ| ≥ 3%: 10

  Top VE GAINS (rpm × mrp psi → MAF g/s old_2023_base → stock):
     800 ×  -9.5    3.41 →   4.19 g/s  (+22.73%, n=718/13727)
    1200 × -10.0    4.71 →   5.64 g/s  (+19.75%, n=32/396)
    1900 × -11.0    6.28 →   7.41 g/s  (+17.97%, n=65/269)
    2600 × -11.0    7.73 →   8.27 g/s  (+7.01%, n=57/2237)
     800 × -10.0    3.62 →   3.80 g/s  (+4.94%, n=81/299)
    1600 × -10.5    6.63 →   6.90 g/s  (+4.03%, n=32/934)
    1600 × -11.0    5.54 →   5.70 g/s  (+3.02%, n=55/137)
    2600 × -11.5    7.32 →   7.02 g/s  (-4.05%, n=51/543)
    1600 ×  -9.0    9.44 →   9.05 g/s  (-4.20%, n=37/6770)
    2200 × -11.5    6.91 →   6.48 g/s  (-6.24%, n=213/69)

  Top VE LOSSES:
    2200 × -11.5    6.91 →   6.48 g/s  (-6.24%, n=213/69)
    1600 ×  -9.0    9.44 →   9.05 g/s  (-4.20%, n=37/6770)
    2600 × -11.5    7.32 →   7.02 g/s  (-4.05%, n=51/543)
    1600 × -11.0    5.54 →   5.70 g/s  (+3.02%, n=55/137)
    1600 × -10.5    6.63 →   6.90 g/s  (+4.03%, n=32/934)
     800 × -10.0    3.62 →   3.80 g/s  (+4.94%, n=81/299)
    2600 × -11.0    7.73 →   8.27 g/s  (+7.01%, n=57/2237)
    1900 × -11.0    6.28 →   7.41 g/s  (+17.97%, n=65/269)
    1200 × -10.0    4.71 →   5.64 g/s  (+19.75%, n=32/396)
     800 ×  -9.5    3.41 →   4.19 g/s  (+22.73%, n=718/13727)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
      old_2023_base: cells= 19  mean|c|= 5.12%  median|c|= 4.89%  in_tol=  0.0%  max= 7.5%
              stock: cells= 52  mean|c|= 1.84%  median|c|= 1.96%  in_tol= 67.3%  max= 5.2%
    verdict: WIN — VE up + trim tighter

## VE proxy: 20.7 vs stock
  cells with data — stock: 210, 20.7: 244
  overlap (≥30 samples in each): 127
  cells with |Δ| ≥ 3%: 88

  Top VE GAINS (rpm × mrp psi → MAF g/s stock → 20.7):
    1200 ×  -9.0    7.19 →   9.19 g/s  (+27.86%, n=9552/292)
    3300 × -11.0    9.63 →  11.78 g/s  (+22.35%, n=105/318)
    2200 × -11.5    6.48 →   7.86 g/s  (+21.29%, n=69/3489)
    1600 × -11.0    5.70 →   6.80 g/s  (+19.23%, n=137/841)
    1600 ×  -8.5   10.34 →  12.25 g/s  (+18.43%, n=2742/606)
    2200 × -10.5    8.83 →  10.40 g/s  (+17.75%, n=1168/728)
    2600 × -11.5    7.02 →   8.22 g/s  (+17.08%, n=543/4905)
    1200 ×  -8.0    8.88 →  10.39 g/s  (+17.05%, n=323/95)
    1200 × -10.5    4.95 →   5.79 g/s  (+17.02%, n=79/1161)
    3300 × -12.0    8.21 →   9.58 g/s  (+16.71%, n=85/378)

  Top VE LOSSES:
    2200 ×  -4.5   31.44 →  28.47 g/s  (-9.46%, n=638/50)
    2200 ×  -4.0   34.10 →  31.08 g/s  (-8.86%, n=749/184)
    3300 × -10.5   16.63 →  15.47 g/s  (-6.97%, n=43/608)
    2200 ×  -3.5   35.52 →  33.43 g/s  (-5.89%, n=761/125)
    3700 ×  -9.5   23.92 →  22.66 g/s  (-5.26%, n=65/276)
    3300 ×  -7.0   36.20 →  34.35 g/s  (-5.13%, n=32/1354)
    4000 × -10.5   22.67 →  21.51 g/s  (-5.12%, n=98/31)
    2200 ×  -5.0   29.03 →  27.73 g/s  (-4.51%, n=907/114)
    3700 ×  -7.5   36.12 →  34.60 g/s  (-4.22%, n=90/474)
    3700 ×  -6.5   41.41 →  39.70 g/s  (-4.11%, n=134/663)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              stock: cells= 52  mean|c|= 1.84%  median|c|= 1.96%  in_tol= 67.3%  max= 5.2%
               20.7: cells= 59  mean|c|= 2.44%  median|c|= 1.50%  in_tol= 74.6%  max= 6.3%
    verdict: MIXED — VE up but trim looser (suspect MAF over-scale)

## VE proxy: 20.8 vs 20.7
  cells with data — 20.7: 244, 20.8: 257
  overlap (≥30 samples in each): 158
  cells with |Δ| ≥ 3%: 100

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.7 → 20.8):
    2200 ×  -4.5   28.47 →  30.99 g/s  (+8.85%, n=50/251)
    3700 ×  +2.0   85.75 →  91.11 g/s  (+6.24%, n=32/35)
    1600 ×  -7.5   13.08 →  13.79 g/s  (+5.42%, n=52/1884)
    2200 ×  -4.0   31.08 →  32.06 g/s  (+3.18%, n=184/338)
    2600 ×  -1.5   45.86 →  47.27 g/s  (+3.07%, n=427/159)
    2600 ×  -2.5   44.86 →  43.45 g/s  (-3.14%, n=439/196)
    3300 ×  -5.5   41.59 →  40.27 g/s  (-3.18%, n=2296/534)
     800 ×  -9.5    4.29 →   4.15 g/s  (-3.25%, n=35932/15876)
    2200 ×  -7.0   22.16 →  21.44 g/s  (-3.25%, n=106/409)
    3300 ×  +2.5   81.60 →  78.94 g/s  (-3.27%, n=100/40)

  Top VE LOSSES:
    1200 ×  -8.5    9.73 →   7.53 g/s  (-22.60%, n=109/372)
    1200 ×  -9.0    9.19 →   7.46 g/s  (-18.77%, n=292/3495)
    3300 × -11.0   11.78 →   9.75 g/s  (-17.20%, n=318/1326)
    1200 × -10.5    5.79 →   4.82 g/s  (-16.85%, n=1161/63)
    1600 ×  -8.5   12.25 →  10.21 g/s  (-16.65%, n=606/994)
    2200 × -10.5   10.40 →   8.77 g/s  (-15.72%, n=728/972)
    1200 ×  -8.0   10.39 →   8.81 g/s  (-15.24%, n=95/35)
    1600 ×  -9.0   10.49 →   9.02 g/s  (-14.01%, n=719/5193)
    3000 × -11.0   10.51 →   9.04 g/s  (-13.98%, n=834/3859)
    2600 × -10.5   11.81 →  10.32 g/s  (-12.62%, n=779/1528)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
               20.7: cells= 59  mean|c|= 2.44%  median|c|= 1.50%  in_tol= 74.6%  max= 6.3%
               20.8: cells= 58  mean|c|= 1.85%  median|c|= 2.03%  in_tol= 51.7%  max= 5.5%
    verdict: MIXED — VE down but trim tighter (correcting prior over-scale?)

## VE proxy: 20.9 vs 20.8
  cells with data — 20.8: 257, 20.9: 211
  overlap (≥30 samples in each): 155
  cells with |Δ| ≥ 3%: 45

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.8 → 20.9):
     800 × -10.0    3.83 →   4.30 g/s  (+12.22%, n=127/314)
    4000 ×  -9.5   27.17 →  30.39 g/s  (+11.87%, n=48/54)
     800 ×  -8.5    5.50 →   6.06 g/s  (+10.18%, n=278/703)
    2200 ×  -1.5   39.69 →  43.70 g/s  (+10.09%, n=252/269)
    4000 × -11.5   11.08 →  12.16 g/s  (+9.78%, n=32/40)
    2200 ×  -2.0   37.89 →  41.28 g/s  (+8.96%, n=79/182)
    1900 ×  -8.0   14.39 →  15.51 g/s  (+7.77%, n=203/143)
    1900 ×  -8.5   12.77 →  13.65 g/s  (+6.88%, n=469/210)
    1200 × -10.0    5.68 →   6.06 g/s  (+6.60%, n=1141/441)
    1200 × -10.5    4.82 →   5.12 g/s  (+6.24%, n=63/74)

  Top VE LOSSES:
    1200 ×  -8.5    7.53 →   6.51 g/s  (-13.52%, n=372/49)
    1200 ×  -9.0    7.46 →   6.65 g/s  (-10.97%, n=3495/513)
    2200 ×  -6.0   24.23 →  22.83 g/s  (-5.77%, n=548/237)
    3700 × -10.5   16.93 →  15.97 g/s  (-5.65%, n=137/34)
    3700 ×  +2.5   96.62 →  91.17 g/s  (-5.64%, n=33/38)
    2200 × -10.5    8.77 →   8.27 g/s  (-5.63%, n=972/341)
    2600 ×  -0.5   50.11 →  47.39 g/s  (-5.44%, n=34/471)
    3700 ×  -9.0   24.66 →  23.43 g/s  (-5.01%, n=80/88)
    2200 ×  -5.0   28.33 →  27.11 g/s  (-4.28%, n=343/443)
    3000 × -10.5   12.14 →  11.67 g/s  (-3.94%, n=1091/337)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
               20.8: cells= 58  mean|c|= 1.85%  median|c|= 2.03%  in_tol= 51.7%  max= 5.5%
               20.9: cells= 47  mean|c|= 1.33%  median|c|= 0.86%  in_tol= 80.9%  max= 3.2%
    verdict: WIN — VE up + trim tighter

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

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
               20.9: cells= 47  mean|c|= 1.33%  median|c|= 0.86%  in_tol= 80.9%  max= 3.2%
              20.10: cells= 52  mean|c|= 1.92%  median|c|= 1.93%  in_tol= 50.0%  max= 6.0%
    verdict: MIXED — VE up but trim looser (suspect MAF over-scale)

## VE proxy: 20.11 vs 20.10
  cells with data — 20.10: 200, 20.11: 181
  overlap (≥30 samples in each): 111
  cells with |Δ| ≥ 3%: 41

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.10 → 20.11):
    1200 ×  -7.0   12.03 →  13.42 g/s  (+11.56%, n=98/31)
    3300 ×  -8.5   22.57 →  24.34 g/s  (+7.86%, n=271/449)
    2600 ×  -0.5   48.01 →  50.45 g/s  (+5.08%, n=270/34)
    3300 ×  -8.0   25.93 →  27.16 g/s  (+4.74%, n=98/442)
    1900 ×  -8.0   14.64 →  15.18 g/s  (+3.67%, n=282/257)
    3000 ×  -5.5   34.31 →  35.56 g/s  (+3.63%, n=481/241)
    3300 ×  -7.5   28.63 →  29.66 g/s  (+3.57%, n=123/545)
    2600 ×  -9.0   16.75 →  16.23 g/s  (-3.10%, n=1089/563)
    2200 ×  -3.0   36.90 →  35.72 g/s  (-3.21%, n=315/495)
    2200 ×  -6.0   24.88 →  24.07 g/s  (-3.27%, n=428/388)

  Top VE LOSSES:
    1200 ×  -8.5    8.55 →   6.90 g/s  (-19.35%, n=811/219)
     800 ×  -9.0    4.88 →   4.42 g/s  (-9.45%, n=635/721)
    1200 × -10.5    5.94 →   5.39 g/s  (-9.29%, n=66/172)
    3300 × -11.0   10.79 →   9.83 g/s  (-8.88%, n=304/420)
    1900 ×  -5.0   24.22 →  22.25 g/s  (-8.13%, n=178/224)
     800 × -10.0    4.07 →   3.76 g/s  (-7.57%, n=87/372)
    2200 ×  -4.0   33.32 →  30.83 g/s  (-7.46%, n=310/339)
    3300 ×  -5.0   44.06 →  41.00 g/s  (-6.95%, n=79/198)
    3300 ×  -6.0   38.52 →  35.96 g/s  (-6.65%, n=91/222)
     800 ×  -8.5    5.73 →   5.36 g/s  (-6.50%, n=245/266)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.10: cells= 52  mean|c|= 1.92%  median|c|= 1.93%  in_tol= 50.0%  max= 6.0%
              20.11: cells= 50  mean|c|= 1.34%  median|c|= 1.32%  in_tol= 82.0%  max= 3.4%
    verdict: MIXED — VE down but trim tighter (correcting prior over-scale?)


## ingest 2026-05-11 (rev 20.11) auto-rollup (2026-05-11 19:11)

## VE proxy: 20.11 vs 20.10
  cells with data — 20.10: 200, 20.11: 181
  overlap (≥30 samples in each): 111
  cells with |Δ| ≥ 3%: 41

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.10 → 20.11):
    1200 ×  -7.0   12.03 →  13.42 g/s  (+11.56%, n=98/31)
    3300 ×  -8.5   22.57 →  24.34 g/s  (+7.86%, n=271/449)
    2600 ×  -0.5   48.01 →  50.45 g/s  (+5.08%, n=270/34)
    3300 ×  -8.0   25.93 →  27.16 g/s  (+4.74%, n=98/442)
    1900 ×  -8.0   14.64 →  15.18 g/s  (+3.67%, n=282/257)
    3000 ×  -5.5   34.31 →  35.56 g/s  (+3.63%, n=481/241)
    3300 ×  -7.5   28.63 →  29.66 g/s  (+3.57%, n=123/545)
    2600 ×  -9.0   16.75 →  16.23 g/s  (-3.10%, n=1089/563)
    2200 ×  -3.0   36.90 →  35.72 g/s  (-3.21%, n=315/495)
    2200 ×  -6.0   24.88 →  24.07 g/s  (-3.27%, n=428/388)

  Top VE LOSSES:
    1200 ×  -8.5    8.55 →   6.90 g/s  (-19.35%, n=811/219)
     800 ×  -9.0    4.88 →   4.42 g/s  (-9.45%, n=635/721)
    1200 × -10.5    5.94 →   5.39 g/s  (-9.29%, n=66/172)
    3300 × -11.0   10.79 →   9.83 g/s  (-8.88%, n=304/420)
    1900 ×  -5.0   24.22 →  22.25 g/s  (-8.13%, n=178/224)
     800 × -10.0    4.07 →   3.76 g/s  (-7.57%, n=87/372)
    2200 ×  -4.0   33.32 →  30.83 g/s  (-7.46%, n=310/339)
    3300 ×  -5.0   44.06 →  41.00 g/s  (-6.95%, n=79/198)
    3300 ×  -6.0   38.52 →  35.96 g/s  (-6.65%, n=91/222)
     800 ×  -8.5    5.73 →   5.36 g/s  (-6.50%, n=245/266)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.10: cells= 52  mean|c|= 1.92%  median|c|= 1.93%  in_tol= 50.0%  max= 6.0%
              20.11: cells= 50  mean|c|= 1.34%  median|c|= 1.32%  in_tol= 82.0%  max= 3.4%
    verdict: MIXED — VE down but trim tighter (correcting prior over-scale?)


## ROM binary-diff: `AE5L600L 20g rev 20.10 tiny wrex.bin` → `AE5L600L 20g rev 20.11.bin`

- bytes changed: **148** in **112** contiguous run(s)

| Table region | runs | bytes | addr range |
|---|---:|---:|---|
| Base Timing Primary Cruise | 26 | 26 | 0xD474B–0xD490C |
| Base Timing Primary Non-Cruise | 25 | 25 | 0xD491C–0xD4ACC |
| Base Timing Reference Cruise | 25 | 25 | 0xD4ADC–0xD4C8C |
| Base Timing Reference Non-Cruise | 24 | 24 | 0xD4C9C–0xD4D82 |
| MAF Sensor Scaling | 3 | 24 | 0xD8CC9–0xD8D4B |
| AVCS Intake Cruise | 4 | 13 | 0xDA9D8–0xDAA48 |
| AVCS Intake Non-Cruise | 4 | 13 | 0xDACA0–0xDAD10 |
| Firmware checksum (auto) | 1 | 4 | 0xFFB88–0xFFB8C |

## ingest 2026-05-11 (rev 20.11) auto-rollup (2026-05-11 19:11)

## VE proxy: 20.11 vs 20.10
  cells with data — 20.10: 200, 20.11: 180
  overlap (≥30 samples in each): 111
  cells with |Δ| ≥ 3%: 41

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.10 → 20.11):
    1200 ×  -7.0   12.03 →  13.42 g/s  (+11.56%, n=98/31)
    3300 ×  -8.5   22.57 →  24.31 g/s  (+7.71%, n=271/395)
    2600 ×  -0.5   48.01 →  50.45 g/s  (+5.08%, n=270/34)
    3300 ×  -8.0   25.93 →  27.13 g/s  (+4.62%, n=98/418)
    1900 ×  -8.0   14.64 →  15.18 g/s  (+3.67%, n=282/257)
    3000 ×  -5.5   34.31 →  35.45 g/s  (+3.32%, n=481/208)
    1600 × -10.5    6.72 →   6.94 g/s  (+3.24%, n=526/309)
    3300 ×  -7.5   28.63 →  29.54 g/s  (+3.18%, n=123/504)
    2600 ×  -9.0   16.75 →  16.24 g/s  (-3.03%, n=1089/520)
    2200 ×  -3.0   36.90 →  35.72 g/s  (-3.21%, n=315/495)

  Top VE LOSSES:
    1200 × -10.5    5.94 →   4.68 g/s  (-21.28%, n=66/66)
    1200 ×  -8.5    8.55 →   6.91 g/s  (-19.19%, n=811/209)
     800 ×  -9.0    4.88 →   4.41 g/s  (-9.50%, n=635/713)
    3300 × -11.0   10.79 →   9.89 g/s  (-8.35%, n=304/382)
    1900 ×  -5.0   24.22 →  22.24 g/s  (-8.17%, n=178/172)
     800 ×  -8.0    6.05 →   5.56 g/s  (-8.07%, n=30/38)
    2200 ×  -4.0   33.32 →  30.83 g/s  (-7.46%, n=310/339)
     800 × -10.0    4.07 →   3.79 g/s  (-6.96%, n=87/293)
     800 ×  -8.5    5.73 →   5.35 g/s  (-6.79%, n=245/262)
    3300 ×  -5.0   44.06 →  41.09 g/s  (-6.73%, n=79/158)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.10: cells= 52  mean|c|= 1.92%  median|c|= 1.93%  in_tol= 50.0%  max= 6.0%
              20.11: cells= 50  mean|c|= 1.38%  median|c|= 1.27%  in_tol= 82.0%  max= 3.7%
    verdict: MIXED — VE down but trim tighter (correcting prior over-scale?)


## ROM binary-diff: `AE5L600L 20g rev 20.10 tiny wrex.bin` → `AE5L600L 20g rev 20.11.bin`

- bytes changed: **148** in **112** contiguous run(s)

| Table region | runs | bytes | addr range |
|---|---:|---:|---|
| Base Timing Primary Cruise | 26 | 26 | 0xD474B–0xD490C |
| Base Timing Primary Non-Cruise | 25 | 25 | 0xD491C–0xD4ACC |
| Base Timing Reference Cruise | 25 | 25 | 0xD4ADC–0xD4C8C |
| Base Timing Reference Non-Cruise | 24 | 24 | 0xD4C9C–0xD4D82 |
| MAF Sensor Scaling | 3 | 24 | 0xD8CC9–0xD8D4B |
| AVCS Intake Cruise | 4 | 13 | 0xDA9D8–0xDAA48 |
| AVCS Intake Non-Cruise | 4 | 13 | 0xDACA0–0xDAD10 |
| Firmware checksum (auto) | 1 | 4 | 0xFFB88–0xFFB8C |

## 2026-05-11 — log: logs/5-11 20.11/log0001.csv — rom: 20.11

Log: 23,672 rows / 15.78 min @ 25 Hz. Schema 34 cols (includes KNOCK_FLAG).
Sample-locator convention per `feedback_log_output_units`: events cited by sample
row, not seconds. Time(s) = sample × 0.04 + first-sample offset (4.48s here).

**Drive shape:** RPM 169–5981 (median 2065); MPH 0–60 (median 27); CL/OL state
8 (CL) 20,143 / 10 (OL) 3,000 / 7 (warmup) 529. Strict-cruise filter passes 9,201
samples = 38.9% of log = 6.13 min — solid cruise coverage. One sustained WOT
pull (TPS>95 for 3.16s, samples 19169–19248).

**Knock:** 364 FBKC<0 samples / 5 FBKC events; 5 FLKC decrement events. 24
KNOCK_FLAG=1 samples. IAM held 1.000 throughout. FLKC start=0 end=0 (full
recovery within the drive, unlike 5-10 which ended at −1.0).
- Top cells by FBKC<0 sample count:
  - 2200×1.00: **196 samples / 4 events / min −2.10** — ghost zone, hammered
  - 2000×1.00: **78 samples** — extension of ghost zone into low-RPM
  - 1500×1.00 + 1750×1.00: 10+7 samples — new low-RPM cluster
  - 5500–5750 × 3.25–3.50: 5+5 samples — WOT pull tail
- Ghost zone re-check (2200-3300 × 1.0-1.4, FBKC<0 per zone-minute):
  - 20.10 pooled (n=2 logs, 3.43 min in-zone): **85.4/min**
  - 20.11 pooled (n=3 logs, 1.86 min in-zone): **217.2/min**
  - This log alone (0.77 min in-zone): **310/min**, 1160 in-zone samples
  - 20.11 stays elevated across n=3 logs. The "single-log noise" hypothesis
    from 5-10's review is weaker with this data.
- FLKC decrement zones: 4000 RPM × 1.78-3.70 load (5 events, all in two pulls).
  Same 4000-4400 high-load cluster as 5-10. FLKC ratchet still present, but
  recovered to 0 within the drive — looser hold than 5-10.

**WOT (TPS>95):** 1 pull, 3.24s, peak RPM 5981, peak mrp 21.74 psi @ 4071 RPM /
load 3.99, target 22.29 — **97.5% attainment, NOT overshooting** (5-10 had
1.04-1.05 attn at similar RPM). FBKC min −1.4 during pull (at 5472-5846 RPM ×
2.5-3.4 load), FLKC −1.0 (at 4039-4497 × 3.43-3.86). knock_during=1. Timing
already pulled to 9.5-13° at peak boost — aggressive cal even before FBKC fired.
Tdp tracked positive through ramp (max +10.08), wgdc peaked 80% at start then
glided to 64-71% as target was approached — boost-control behavior healthy.
mean(wbo2−FFB)=+0.25 during pull (slightly leaner than commanded).

**Pull ramps:** 4 detected, all `post_dfco`.
- pull 0: small, 7.68 psi peak, attn 0.50 — driver short-shifted or relented
- pull 1: 8.40 psi peak @ 2.76s, attn 0.58
- pull 2: 16.38 psi peak @ 4091 RPM, attn 0.92, 1 FLKC event during
- pull 3: 21.74 psi peak @ 4071 RPM, attn 0.975, FBKC −1.4, FLKC −1.0, 2 FLKC
  events — matches pull 3 in 5-10. Boost-control healthy; knock pressure real.

**MAF corr:** 108 cells appended. ALL-pedal high-OL operating cells:
4000-4500 RPM × 0.7-1.3 g/rev OL × APP>30 = **0 samples** — the car never drove
that operating combo in this log (low-load OL only happens at low pedal here).
Cannot refresh the historical "+0.22 AFR engine-richer-than-cmd" measurement
from this log. At HIGH-load OL though (1.3–3.4 g/rev, where this log lived):
delta = FFB−wbo2 = +0.06 to −0.42 AFR — engine LEANER than commanded across
3500-4250 RPM (median −0.34 at 3750-4250). Different cell, different sign —
flag but don't act on a 12-14 sample/cell read.

**Cliffs:** Residency check on 20.11-edit zones:
- AVCS Cruise 1600-2500 × 0.20-0.30 (the 7 cells changed in 20.11):
  - 1900 × 0.20-0.30: 245 strict-cruise samples (1.03%)
  - 2200 × 0.20-0.30: 253 (1.07%)
  - 2500 × 0.20-0.30: 296 (1.25%)
  - All above 1% residency rule. The 20.11 edits ARE being driven over.
- BTC 0.65→0.94 worst-cliff cells: 1900 × 0.65-0.94 = 473 samples (2.0%),
  2200 × 0.65-0.94 = 1102 (4.66%). Well-driven; cliff still unaddressed.

**Stutter:** 118 events appended.
- ffb_wbo2_divergence: 35
- rpm_swing_steady_tps: 31
- avcs_oscillation: 21 — **16 of 21 at 2000-RPM band**, median magnitude 16°,
  load 0.17-0.89. This is exactly the AVCS-edit zone × cruise band.
- timing_osc: 15, afr_osc: 14, throttle_hunt: 2
- AVCS-swing rate in 28-36 MPH × APP≤20 band (consistent re-measurement
  across all logs, strict SOP criteria): 4-27=1.84, 5-2=5.84, 5-8=3.73,
  5-10=4.19, **5-11=5.60 clu/min**. Re-measured numbers DO NOT match the
  trend cited in memory (0.25/0.70/1.47/1.91) — methodology used to produce
  the memory numbers is not present in current scripts. Under consistent
  measurement, 5-11 is in the same band as 5-2/5-8/5-10 (3.7-5.8/min), not
  a step-change. Cross-rev verdict on 20.11 vs 20.10 is **inconclusive** at
  the strict-SOP detector; the AVCS osc clustering at 2000 RPM in this log
  is still notable on its own.

**VE:** vs 20.10 pooled — 109 overlap cells ≥30 samples, 42 with |Δ|≥3%.
Largest losses still at 1200-RPM low-mrp (−21%, −19%) — almost certainly
shift-tail air-flow tails, not cal change. MAF trim health: 20.11 mean|c|
1.05% vs 20.10's 1.92%, in_tol 89.6% vs 50.0% — **MAF trim is tighter on
20.11**. Suggests the 20.11 MAF rescale at idx 11/12/30/31 did move the
needle the right direction. Stand by the "MAF rescale stays deferred for
20.12" call until or unless we see a high-pedal OL drift cell reopen.

**KNOCK_FLAG (24 samples):**
- Disassembly: KNOCK_FLAG = RAM byte FFFF81BA, read by task11_knock_flag
  (0x4438C). The task is gated by transient_knock_inhibit (FFFF726E via
  0x2F8FE) and by FLKC learning state — meaning the flag can fire without
  necessarily triggering FBKC if a gate blocks the corresponding correction
  application. Threshold byte: cal 0xD2995 `knock_count_thresh_val`.
- Observed: 22/24 KNOCK_FLAG=1 samples have FBKC=0 at the same instant; only
  2/24 co-occur with FBKC<0 within ±200 ms. 20/24 in CL state, 4/24 in OL.
  Heavily clustered at low-RPM/low-load (500-2500 × 0.25-1.25), often coast/
  vacuum conditions.
- Provisional reading: knock-detection threshold trip, sometimes gated off
  from triggering FBKC. Treat as leading-indicator log signal, not actionable
  in isolation. Defer characterization until we have a deeper trace.

**Prior-flagged areas re-checked:**
- **Ghost zone 2200-3300 × 1.0-1.4 (5-10 staged)**: Not resolved. n=3 20.11
  logs at 217/zone-min vs n=2 20.10 logs at 85/zone-min. Stays elevated.
  5-10 staged target was >2000 in-zone samples; 5-11 contributed 1160 alone,
  pooled 20.11 = 2800 — at-target. Verdict: real elevation, not single-log
  noise.
- **FLKC ratchet 4000-4400 × 1.5-3+ load (5-10 staged)**: FLKC fired again
  (5 decrements at 4000 RPM × 1.78-3.70 load), but recovered to 0 within
  drive. Less persistent than 5-10. **Still firing under WOT** — 20.12 boost
  cap + timing pull plan stays relevant.
- **28-36 MPH AVCS-swing regression (5-10 staged)**: Re-measurement
  inconclusive (see Stutter section). Still see AVCS osc clustering at
  2000-RPM band, magnitude 16° median — the symptom is present but the
  monotonic upward trend in memory does not reproduce.
- **KNOCK_FLAG semantic characterization (5-10 staged)**: Partial — see
  KNOCK_FLAG block. Disassembly identified the address, task, gates. Full
  trace-level semantics still open.
- **MAF cmd-vs-actual delta refresh (5-10 staged)**: Can't refresh the
  4000-4500 × 0.7-1.3 OL cell from this log; car never drove that combo
  with APP>30. Adjacent high-load OL cells show engine LEANER than cmd by
  −0.3 to −0.4 AFR at 3750-4250 — opposite sign from historical concern.

**New issues:**
- **Ghost-zone elevation now sustained across 3 20.11 logs** at ~2.5× the
  20.10 pooled rate. Either revert MAF high-V scaling, extend timing pull
  to L=1.10/1.30 columns, or test AVCS-toward-stock in 2200-3300 × 1.0-1.4.
- **High-load OL leaner-than-cmd at 3750-4250 RPM** (n=33 samples, median
  Δ −0.34 AFR). Opposite of historical concern; suggests the boost is
  reaching cells where the OL fueling table is undercommanding fuel
  delivery. Watch for FBKC/FLKC ratchet at these cells in next log.
- **Low-RPM ghost-zone extension (1250-1750 × 1.0 g/rev)**: 23 FBKC<0
  samples across this band. Not previously a hot zone. May share root with
  ghost-zone; check timing cliffs / AVCS at these cells.

**Staged for next session:**
- Decide ghost-zone lever: MAF revert vs timing extend vs AVCS revert.
- Verify whether 20.12 (built but not flashed) was re-saved relative to the
  `400ebaa7...` md5 recorded in `project_open_issues.md`. Current disk md5
  is `534720b8...` and matches `current_rev_anchor`. Re-diff 20.11 → 20.12.bin
  on disk and refresh the changeset section before flashing.
- Add cliff scan to ingest pipeline (currently skipped — cliffs_flagged.csv
  is empty header-only).
- Investigate methodology gap on the AVCS-swing trend numbers — the
  in-memory trend doesn't reproduce under strict SOP criteria.
- Get one more 20.11 log under WOT conditions to settle the 4000-4400
  FLKC ratchet question definitively.

---

## ingest 2026-05-11 (rev 20.11) auto-rollup (2026-05-11 11:00)

## VE proxy: 20.11 vs 20.10
  cells with data — 20.10: 200, 20.11: 175
  overlap (≥30 samples in each): 109
  cells with |Δ| ≥ 3%: 42

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.10 → 20.11):
    3300 ×  -8.5   22.57 →  24.18 g/s  (+7.15%, n=271/317)
    2600 ×  -0.5   48.01 →  50.45 g/s  (+5.08%, n=270/34)
    3300 ×  -8.0   25.93 →  27.08 g/s  (+4.43%, n=98/385)
    3000 ×  -6.0   32.16 →  33.36 g/s  (+3.74%, n=1035/436)
    2200 × -10.0   11.13 →  11.50 g/s  (+3.33%, n=386/133)
    3000 ×  -5.5   34.31 →  35.45 g/s  (+3.32%, n=481/208)
    1600 ×  -8.0   12.19 →  12.59 g/s  (+3.30%, n=1358/368)
    1600 × -10.5    6.72 →   6.94 g/s  (+3.18%, n=526/308)
    3300 ×  -7.5   28.63 →  29.52 g/s  (+3.10%, n=123/467)
    2200 ×  -3.0   36.90 →  35.72 g/s  (-3.21%, n=315/495)

  Top VE LOSSES:
    1200 × -10.5    5.94 →   4.68 g/s  (-21.28%, n=66/66)
    1200 ×  -8.5    8.55 →   6.97 g/s  (-18.51%, n=811/118)
     800 ×  -9.0    4.88 →   4.41 g/s  (-9.50%, n=635/713)
    3300 × -11.0   10.79 →   9.88 g/s  (-8.40%, n=304/377)
    1900 ×  -5.0   24.22 →  22.24 g/s  (-8.17%, n=178/172)
     800 ×  -8.0    6.05 →   5.56 g/s  (-8.07%, n=30/38)
    2200 ×  -4.0   33.32 →  30.83 g/s  (-7.46%, n=310/339)
     800 ×  -8.5    5.73 →   5.33 g/s  (-7.08%, n=245/259)
     800 × -10.0    4.07 →   3.79 g/s  (-6.96%, n=87/293)
    3300 ×  -5.0   44.06 →  41.09 g/s  (-6.73%, n=79/158)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.10: cells= 52  mean|c|= 1.92%  median|c|= 1.93%  in_tol= 50.0%  max= 6.0%
              20.11: cells= 48  mean|c|= 1.05%  median|c|= 1.06%  in_tol= 89.6%  max= 3.5%
    verdict: MIXED — VE down but trim tighter (correcting prior over-scale?)


## ROM binary-diff: `AE5L600L 20g rev 20.10 tiny wrex.bin` → `AE5L600L 20g rev 20.11.bin`

- bytes changed: **148** in **112** contiguous run(s)

| Table region | runs | bytes | addr range |
|---|---:|---:|---|
| Base Timing Primary Cruise | 26 | 26 | 0xD474B–0xD490C |
| Base Timing Primary Non-Cruise | 25 | 25 | 0xD491C–0xD4ACC |
| Base Timing Reference Cruise | 25 | 25 | 0xD4ADC–0xD4C8C |
| Base Timing Reference Non-Cruise | 24 | 24 | 0xD4C9C–0xD4D82 |
| MAF Sensor Scaling | 3 | 24 | 0xD8CC9–0xD8D4B |
| AVCS Intake Cruise | 4 | 13 | 0xDA9D8–0xDAA48 |
| AVCS Intake Non-Cruise | 4 | 13 | 0xDACA0–0xDAD10 |
| Firmware checksum (auto) | 1 | 4 | 0xFFB88–0xFFB8C |

## ingest 2026-05-10 (rev 20.11) auto-rollup (2026-05-11 00:32)

## VE proxy: 20.11 vs 20.10
  cells with data — 20.10: 200, 20.11: 166
  overlap (≥30 samples in each): 91
  cells with |Δ| ≥ 3%: 44

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.10 → 20.11):
    3300 ×  -8.5   22.57 →  23.89 g/s  (+5.84%, n=271/183)
    2600 ×  -0.5   48.01 →  50.45 g/s  (+5.08%, n=270/34)
    3700 × -11.5    9.65 →   9.96 g/s  (+3.18%, n=120/81)
    3000 ×  -4.5   40.10 →  38.89 g/s  (-3.01%, n=345/107)
    1600 ×  -6.0   17.07 →  16.52 g/s  (-3.23%, n=53/103)
    3700 ×  -5.0   47.22 →  45.66 g/s  (-3.29%, n=72/30)
    2600 ×  -9.0   16.75 →  16.20 g/s  (-3.31%, n=1089/436)
    2600 ×  -4.0   38.05 →  36.78 g/s  (-3.35%, n=209/31)
    3300 ×  -5.5   41.30 →  39.88 g/s  (-3.44%, n=45/56)
    2200 × -10.5    8.44 →   8.14 g/s  (-3.61%, n=891/301)

  Top VE LOSSES:
    1200 × -10.5    5.94 →   4.68 g/s  (-21.28%, n=66/66)
    1200 ×  -9.0    7.57 →   6.45 g/s  (-14.89%, n=2979/47)
    1200 ×  -9.5    6.82 →   5.93 g/s  (-13.14%, n=6017/416)
    2200 ×  -4.0   33.32 →  30.19 g/s  (-9.40%, n=310/166)
     800 ×  -9.0    4.88 →   4.46 g/s  (-8.67%, n=635/184)
    1900 ×  -5.0   24.22 →  22.13 g/s  (-8.63%, n=178/66)
    3300 × -11.0   10.79 →   9.89 g/s  (-8.28%, n=304/321)
    2200 ×  -6.0   24.88 →  23.09 g/s  (-7.23%, n=428/94)
    2600 ×  -5.0   34.29 →  31.83 g/s  (-7.18%, n=469/159)
     800 ×  -8.0    6.05 →   5.62 g/s  (-7.17%, n=30/34)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.10: cells= 52  mean|c|= 1.92%  median|c|= 1.93%  in_tol= 50.0%  max= 6.0%
              20.11: cells= 44  mean|c|= 0.85%  median|c|= 0.91%  in_tol= 95.5%  max= 4.0%
    verdict: MIXED — VE down but trim tighter (correcting prior over-scale?)


## ROM binary-diff: `AE5L600L 20g rev 20.10 tiny wrex.bin` → `AE5L600L 20g rev 20.11.bin`

- bytes changed: **148** in **112** contiguous run(s)

| Table region | runs | bytes | addr range |
|---|---:|---:|---|
| Base Timing Primary Cruise | 26 | 26 | 0xD474B–0xD490C |
| Base Timing Primary Non-Cruise | 25 | 25 | 0xD491C–0xD4ACC |
| Base Timing Reference Cruise | 25 | 25 | 0xD4ADC–0xD4C8C |
| Base Timing Reference Non-Cruise | 24 | 24 | 0xD4C9C–0xD4D82 |
| MAF Sensor Scaling | 3 | 24 | 0xD8CC9–0xD8D4B |
| AVCS Intake Cruise | 4 | 13 | 0xDA9D8–0xDAA48 |
| AVCS Intake Non-Cruise | 4 | 13 | 0xDACA0–0xDAD10 |
| Firmware checksum (auto) | 1 | 4 | 0xFFB88–0xFFB8C |

## 2026-05-10 — log: logs/5-10 20.11/log0003.csv — rom: 20.11

Log: 11,021 rows / 7.34 min @ 25 Hz. Schema includes KNOCK_FLAG.
**Sample-locator convention** in this entry (per feedback_log_output_units): events
cited by sample row, not time-in-seconds. Time(s) = sample × 0.04 + 174.92 if needed.
Caveat: short log; multiple SOP steps will be sample-count-light vs the 5-8 baseline.

**Knock (FBKC<0 OR FLKC[t]<FLKC[t-1]):**
- 0 FBKC<0 samples; 14 FLKC step-down events; 83 FLKC<0 samples (none new — single
  ratchet to -1.0 in each pull, sustained while in-zone).
- Cells (RPM bin × load bin) with FLKC events:
  4000×1.51 (1), 4000×2.28 (1), 4000×2.44 (1), 4000×2.60 (2), 4000×2.90 (4),
  4000×3.22 (2), 4400×2.44 (1), 4400×2.90 (2). Pattern = 4000-4400 RPM ×
  load 1.51-3.22 g/rev = high-RPM mid-to-high-load OL.
- KNOCK_FLAG=1 (separate signal, meaning still uncharacterized): 6 events.
  - sample 112 (idle, APP=0, load 0.39): noise.
  - sample 1416 (RPM 2252, APP=0, load 0.21, MAP 3.19, coast): noise.
  - **sample 1692 (RPM 1887, MPH 19, APP 20, load 0.97, MAP 10.30, timing 19.5°,
    OL): hits the 1900/0.94 Sum-map cliff — open issue.**
  - sample 1957 (idle, APP=0): noise.
  - sample 8620 (RPM 3122, APP 7, load 0.34, MAP 4.64, OL): light load, mild.
  - **sample 9004 (RPM 2838, MPH 71, APP 14, load 0.77, MAP 10.01, timing 22°,
    OL): post-20.10 OL knock zone, expected.**
- Cross-check ghost zone (2200-3300 RPM × 1.0-1.4): **0 SOP-knock events in zone.**
  Re-bin filter on full data: 119 samples in zone, 0 with FBKC<0 and 0 FLKC<0.
  20.11's first-log ghost-zone rate-jump signal does NOT recur in this drive.
  But this drive only spent 119/11021 = 1.08% in the zone (vs 5-8's 2.74%) — n
  is too small to claim a trend. Need more zone exposure on 20.11.
- Cross-check post-20.10 OL knock zone (3500-5500 RPM × 0.7-1.6 OL): **all 14
  FLKC events fell in the higher-RPM/higher-load extension of this band**
  (4000-4400 × 1.51-3.22). Pulls 1+2 sustained FLKC=-1 while in zone. Issue
  was open from 4-27 chat — not resolved on 20.11.

**WOT/Pull ramps:** 0 sustained TPS>95 pulls (longest 22 samples = 0.88s, missed
the ≥25-sample threshold — same as 5-8). 6 APP-based pull ramps captured (all
post_dfco entry). Per-pull peaks (mrp psi / RPM):
- pull 0 sample 6495: 12.75 / 4513, target_attn 0.75
- pull 1 sample 6625: 13.91 / 3990, target_attn 0.82
- pull 2 sample 10543: 5.07 / 3578, target_attn 0.40
- pull 3 sample 13142: 16.09 / 4397, target_attn 0.94
- **pull 4 sample 13241: 18.99 / 4607, target_attn 1.05 (over-target)**
- **pull 5 sample 13293: 18.70 / 4143, target_attn 1.04 (over-target)**
- knock_during=0 in all 6 (ingest only counts FBKC<0; gap noted below).
- Cross-rev (post_dfco only, all logs): 20.11 mean peak_mrp 13.85 (n=11) vs
  20.10 11.01 (n=4). 20.11 mean target_attn 0.79 vs 20.10 0.69. Both go in the
  right direction. min_fbkc -0.13 mean (one pull from 5-8 had FBKC, none in
  this log).

**MAF corr:** 3,767 filtered samples (BELOW the >5,000 SOP threshold — flag low
confidence). 23 cells n>=30. **In-tol 95.7%** (vs 5-8 92.3%, 20.10 50.0%).
mean|c|=0.99%, max|c|=3.20% (5-8 max=4.4%). Two cells differ from 5-8 by >2pp:
mafv=2.253 / g/s=33.7 (+4.5pp) and mafv=2.253 / g/s=30.9 (+2.4pp) — same V bin,
adjacent g/s bins, 5-10 reads about 2-4pp richer. Possibly operating-condition
delta (warmer/different grade fuel/road) at the 2.25V breakpoint, not enough
samples to claim drift.

**Cliffs:** Pipeline still not auto-populating cliffs_flagged.csv (same gap as
5-8 review). Manual residency in known cliff zones:
- 1900/0.94 Sum-map cliff: 40 samples in 1800-2050 × 0.85-1.05 (0.36% residency).
  **Hit by KNOCK_FLAG once (sample 1692).** Light-load (cold-AVCS) tip-in event.
- 28-36 MPH cruise band: 1,286 samples (10.18% residency, single-largest band).
  **14 AVCS-swing clusters (≥8° in 1s, APP≤20)** — see Stutter.
- 4150 RPM AVCS cliff (-3.6 to -5.3°): present in pull windows. Pulls 4+5 peaked
  at 4143 / 4607 RPM straddling this cliff with avcs going 14→11 (pull 4) and
  20→22 (pull 5) — coupled with FLKC=-1 in both pulls.

**Stutter:** 85 events total. Signal-side breakdown:
  rpm_swing_steady_tps: 29
  ffb_wbo2_divergence: 26
  afr_osc: 14
  avcs_oscillation: 7
  throttle_hunt_at_steady_app: 5
  timing_osc: 4
- **User-reported felt stutter at 30-35 MPH:** focused review on 28-36 MPH band
  (1,286 samples, 10 stutter events). Co-occurrence cluster sample 10079→10153
  (~3s span, 28-29 MPH, 2850-2950 RPM): throttle_hunt + avcs_oscillation 14° +
  timing_osc 3.7° + ffb_wbo2_divergence — all firing during a coast→tip-back-on
  transition where AVCS collapsed from 24°→1° in ~1s during DFCO and then had
  to re-ramp. Same pattern at samples 9735-9766 (30-32 MPH, AVCS swing 23°)
  and 10322-10347 (30-32 MPH, AVCS swing 19°). Repeats throughout the log.
- **Cross-rev rate (AVCS-swing clusters at 28-36 MPH cruise, APP≤20):**
  | rev   | log         | clu/min |
  |-------|-------------|--------:|
  | 20.10 | 4-27        | 0.25    |
  | 20.10 | 5-2         | 0.70    |
  | 20.11 | 5-8         | 1.47    |
  | 20.11 | 5-10        | 1.91    |
  20.11 shows 2-3× more AVCS-swing clusters in this band than 20.10 across both
  20.11 logs. **Candidate stutter source matches user's felt sensation.**

**VE:** 4,212 sample base (low, like MAF corr). 16 cells |delta|>3% vs 5-8 within
20.11 (no rom change between 5-8 and 5-10): 12 gains concentrated 2600-3300 ×
-5 to -9 mrp (cruise zone, 5-10 read MAF higher). 2 losses at 800/-8.5 (-19%)
and 1200/-10.0 (-15%) idle/decel cells. Plausibly trip-profile difference (5-10
spent more time at mid-RPM cruise than 5-8). Not a ROM-attributable change.

**Prior-flagged areas re-checked:**
- 1900/0.94 base timing cliff: KNOCK_FLAG fired at this exact cell (sample 1692,
  RPM 1887, load 0.97). One sample, low load, OL. **REGRESSED — first observed
  hit.** Note: KNOCK_FLAG is the new uncharacterized column; FBKC and FLKC did
  NOT fire at this sample. Severity unclear pending KNOCK_FLAG semantics.
- Post-20.10 OL knock 3500-5500 × 0.7-1.6: **UNCHANGED — recurring on 20.11.**
  All 14 FLKC step-downs cluster at 4000-4400 RPM × 1.5-3.2 load (extension of
  the prior zone toward higher RPM/load). FLKC went 0→-0.25→-0.5→-0.75→-1.0
  in pull 1 (samples 2168-2176), held at -1.0, ratcheted back in pull 2 starting
  at sample 8828.
- Ghost zone 2200-3300 × 1.0-1.4: **n too small this log to update rate (1.08%
  residency).** No FBKC/FLKC events in zone. Don't draw conclusions.
- Marginal 2000/80% APP cell: no high-APP cruise samples this log; can't evaluate.
- Cruise pedal hunt (v9): 0 throttle_hunt events in 10-25% APP range. **HOLDING.**
- AVCS=0 in NC high-load: log starts at idle (sample 0 RPM 197, EGT 255Ω cold);
  AVCS=0 in early samples is post-start warm-up (closed previously). No new
  evidence.
- WOT pulls were finally captured (n=6) — ingest now has 20.11 pull data.

**New issues:**
- **NEW (P2 — observation):** 28-36 MPH AVCS-swing rate up 2-3× on 20.11 vs 20.10
  across both 20.11 logs. Light-cruise/coast transitions fire AVCS osc + timing
  osc + AFR div + throttle hunt within ~1s windows. Plausible source of user's
  felt "tiniest stutter at 30-35 MPH". Lever candidates: AVCS Cruise edits at
  1600-2500 × 0.20-0.30 in 20.11 may be making AVCS more responsive at a load
  boundary that's heavily occupied during 28-36 MPH light cruise.
- **NEW (P3 — gap):** ingest's `knock_during` flag for pull_ramps only counts
  FBKC<0, not FLKC step-downs. This log has 14 FLKC events inside pull windows
  but knock_during=0 on all 6 pulls. Methodology gap; consider extending the
  flag to FBKC<0 OR FLKC[t]<FLKC[t-1].

**Staged for next session:**
- Get 1 more 20.11 log targeting the ghost zone (need >2,000 samples in the
  2200-3300 × 1.0-1.4 cell range) to settle the rate-jump question.
- Watch FLKC trajectory in 4000-4400 × high-load OL: stays at -1.0 in this log
  meaning the long-term learning hasn't recovered. If it ratchets to -1.5 or
  -2.0 in subsequent logs, the post-20.10 OL knock issue is escalating.
- 28-36 MPH AVCS-swing investigation: pull AVCS Cruise NC table values at the
  exact load boundary (~0.20-0.30) the cruise zone is hitting; consider rolling
  back the 20.11 1600-2500 × 0.20-0.30 edits as a test.
- Pull-ramp `knock_during` should include FLKC; patch ingest.

---

## ingest 2026-05-10 (rev 20.11) auto-rollup (2026-05-10 18:11)

## VE proxy: 20.11 vs 20.10
  cells with data — 20.10: 200, 20.11: 166
  overlap (≥30 samples in each): 91
  cells with |Δ| ≥ 3%: 44

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.10 → 20.11):
    3300 ×  -8.5   22.57 →  23.89 g/s  (+5.84%, n=271/183)
    2600 ×  -0.5   48.01 →  50.45 g/s  (+5.08%, n=270/34)
    3700 × -11.5    9.65 →   9.96 g/s  (+3.18%, n=120/81)
    3000 ×  -4.5   40.10 →  38.89 g/s  (-3.01%, n=345/107)
    1600 ×  -6.0   17.07 →  16.52 g/s  (-3.23%, n=53/103)
    3700 ×  -5.0   47.22 →  45.66 g/s  (-3.29%, n=72/30)
    2600 ×  -9.0   16.75 →  16.20 g/s  (-3.31%, n=1089/436)
    2600 ×  -4.0   38.05 →  36.78 g/s  (-3.35%, n=209/31)
    3300 ×  -5.5   41.30 →  39.88 g/s  (-3.44%, n=45/56)
    2200 × -10.5    8.44 →   8.14 g/s  (-3.61%, n=891/301)

  Top VE LOSSES:
    1200 × -10.5    5.94 →   4.68 g/s  (-21.28%, n=66/66)
    1200 ×  -9.0    7.57 →   6.45 g/s  (-14.89%, n=2979/47)
    1200 ×  -9.5    6.82 →   5.93 g/s  (-13.14%, n=6017/416)
    2200 ×  -4.0   33.32 →  30.19 g/s  (-9.40%, n=310/166)
     800 ×  -9.0    4.88 →   4.46 g/s  (-8.67%, n=635/184)
    1900 ×  -5.0   24.22 →  22.13 g/s  (-8.63%, n=178/66)
    3300 × -11.0   10.79 →   9.89 g/s  (-8.28%, n=304/321)
    2200 ×  -6.0   24.88 →  23.09 g/s  (-7.23%, n=428/94)
    2600 ×  -5.0   34.29 →  31.83 g/s  (-7.18%, n=469/159)
     800 ×  -8.0    6.05 →   5.62 g/s  (-7.17%, n=30/34)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.10: cells= 52  mean|c|= 1.92%  median|c|= 1.93%  in_tol= 50.0%  max= 6.0%
              20.11: cells= 44  mean|c|= 0.85%  median|c|= 0.91%  in_tol= 95.5%  max= 4.0%
    verdict: MIXED — VE down but trim tighter (correcting prior over-scale?)


## auto-generated rev rollup (2026-05-09 02:39)

## VE proxy: stock vs old_2023_base
  cells with data — old_2023_base: 53, stock: 210
  overlap (≥30 samples in each): 11
  cells with |Δ| ≥ 3%: 10

  Top VE GAINS (rpm × mrp psi → MAF g/s old_2023_base → stock):
     800 ×  -9.5    3.41 →   4.19 g/s  (+22.73%, n=718/13727)
    1200 × -10.0    4.71 →   5.64 g/s  (+19.75%, n=32/396)
    1900 × -11.0    6.28 →   7.41 g/s  (+17.97%, n=65/269)
    2600 × -11.0    7.73 →   8.27 g/s  (+7.01%, n=57/2237)
     800 × -10.0    3.62 →   3.80 g/s  (+4.94%, n=81/299)
    1600 × -10.5    6.63 →   6.90 g/s  (+4.03%, n=32/934)
    1600 × -11.0    5.54 →   5.70 g/s  (+3.02%, n=55/137)
    2600 × -11.5    7.32 →   7.02 g/s  (-4.05%, n=51/543)
    1600 ×  -9.0    9.44 →   9.05 g/s  (-4.20%, n=37/6770)
    2200 × -11.5    6.91 →   6.48 g/s  (-6.24%, n=213/69)

  Top VE LOSSES:
    2200 × -11.5    6.91 →   6.48 g/s  (-6.24%, n=213/69)
    1600 ×  -9.0    9.44 →   9.05 g/s  (-4.20%, n=37/6770)
    2600 × -11.5    7.32 →   7.02 g/s  (-4.05%, n=51/543)
    1600 × -11.0    5.54 →   5.70 g/s  (+3.02%, n=55/137)
    1600 × -10.5    6.63 →   6.90 g/s  (+4.03%, n=32/934)
     800 × -10.0    3.62 →   3.80 g/s  (+4.94%, n=81/299)
    2600 × -11.0    7.73 →   8.27 g/s  (+7.01%, n=57/2237)
    1900 × -11.0    6.28 →   7.41 g/s  (+17.97%, n=65/269)
    1200 × -10.0    4.71 →   5.64 g/s  (+19.75%, n=32/396)
     800 ×  -9.5    3.41 →   4.19 g/s  (+22.73%, n=718/13727)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
      old_2023_base: cells= 19  mean|c|= 5.12%  median|c|= 4.89%  in_tol=  0.0%  max= 7.5%
              stock: cells= 52  mean|c|= 1.84%  median|c|= 1.96%  in_tol= 67.3%  max= 5.2%
    verdict: WIN — VE up + trim tighter

## VE proxy: 20.7 vs stock
  cells with data — stock: 210, 20.7: 244
  overlap (≥30 samples in each): 127
  cells with |Δ| ≥ 3%: 88

  Top VE GAINS (rpm × mrp psi → MAF g/s stock → 20.7):
    1200 ×  -9.0    7.19 →   9.19 g/s  (+27.86%, n=9552/292)
    3300 × -11.0    9.63 →  11.78 g/s  (+22.35%, n=105/318)
    2200 × -11.5    6.48 →   7.86 g/s  (+21.29%, n=69/3489)
    1600 × -11.0    5.70 →   6.80 g/s  (+19.23%, n=137/841)
    1600 ×  -8.5   10.34 →  12.25 g/s  (+18.43%, n=2742/606)
    2200 × -10.5    8.83 →  10.40 g/s  (+17.75%, n=1168/728)
    2600 × -11.5    7.02 →   8.22 g/s  (+17.08%, n=543/4905)
    1200 ×  -8.0    8.88 →  10.39 g/s  (+17.05%, n=323/95)
    1200 × -10.5    4.95 →   5.79 g/s  (+17.02%, n=79/1161)
    3300 × -12.0    8.21 →   9.58 g/s  (+16.71%, n=85/378)

  Top VE LOSSES:
    2200 ×  -4.5   31.44 →  28.47 g/s  (-9.46%, n=638/50)
    2200 ×  -4.0   34.10 →  31.08 g/s  (-8.86%, n=749/184)
    3300 × -10.5   16.63 →  15.47 g/s  (-6.97%, n=43/608)
    2200 ×  -3.5   35.52 →  33.43 g/s  (-5.89%, n=761/125)
    3700 ×  -9.5   23.92 →  22.66 g/s  (-5.26%, n=65/276)
    3300 ×  -7.0   36.20 →  34.35 g/s  (-5.13%, n=32/1354)
    4000 × -10.5   22.67 →  21.51 g/s  (-5.12%, n=98/31)
    2200 ×  -5.0   29.03 →  27.73 g/s  (-4.51%, n=907/114)
    3700 ×  -7.5   36.12 →  34.60 g/s  (-4.22%, n=90/474)
    3700 ×  -6.5   41.41 →  39.70 g/s  (-4.11%, n=134/663)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              stock: cells= 52  mean|c|= 1.84%  median|c|= 1.96%  in_tol= 67.3%  max= 5.2%
               20.7: cells= 59  mean|c|= 2.44%  median|c|= 1.50%  in_tol= 74.6%  max= 6.3%
    verdict: MIXED — VE up but trim looser (suspect MAF over-scale)

## VE proxy: 20.8 vs 20.7
  cells with data — 20.7: 244, 20.8: 257
  overlap (≥30 samples in each): 158
  cells with |Δ| ≥ 3%: 100

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.7 → 20.8):
    2200 ×  -4.5   28.47 →  30.99 g/s  (+8.85%, n=50/251)
    3700 ×  +2.0   85.75 →  91.11 g/s  (+6.24%, n=32/35)
    1600 ×  -7.5   13.08 →  13.79 g/s  (+5.42%, n=52/1884)
    2200 ×  -4.0   31.08 →  32.06 g/s  (+3.18%, n=184/338)
    2600 ×  -1.5   45.86 →  47.27 g/s  (+3.07%, n=427/159)
    2600 ×  -2.5   44.86 →  43.45 g/s  (-3.14%, n=439/196)
    3300 ×  -5.5   41.59 →  40.27 g/s  (-3.18%, n=2296/534)
     800 ×  -9.5    4.29 →   4.15 g/s  (-3.25%, n=35932/15876)
    2200 ×  -7.0   22.16 →  21.44 g/s  (-3.25%, n=106/409)
    3300 ×  +2.5   81.60 →  78.94 g/s  (-3.27%, n=100/40)

  Top VE LOSSES:
    1200 ×  -8.5    9.73 →   7.53 g/s  (-22.60%, n=109/372)
    1200 ×  -9.0    9.19 →   7.46 g/s  (-18.77%, n=292/3495)
    3300 × -11.0   11.78 →   9.75 g/s  (-17.20%, n=318/1326)
    1200 × -10.5    5.79 →   4.82 g/s  (-16.85%, n=1161/63)
    1600 ×  -8.5   12.25 →  10.21 g/s  (-16.65%, n=606/994)
    2200 × -10.5   10.40 →   8.77 g/s  (-15.72%, n=728/972)
    1200 ×  -8.0   10.39 →   8.81 g/s  (-15.24%, n=95/35)
    1600 ×  -9.0   10.49 →   9.02 g/s  (-14.01%, n=719/5193)
    3000 × -11.0   10.51 →   9.04 g/s  (-13.98%, n=834/3859)
    2600 × -10.5   11.81 →  10.32 g/s  (-12.62%, n=779/1528)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
               20.7: cells= 59  mean|c|= 2.44%  median|c|= 1.50%  in_tol= 74.6%  max= 6.3%
               20.8: cells= 58  mean|c|= 1.85%  median|c|= 2.03%  in_tol= 51.7%  max= 5.5%
    verdict: MIXED — VE down but trim tighter (correcting prior over-scale?)

## VE proxy: 20.9 vs 20.8
  cells with data — 20.8: 257, 20.9: 211
  overlap (≥30 samples in each): 155
  cells with |Δ| ≥ 3%: 45

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.8 → 20.9):
     800 × -10.0    3.83 →   4.30 g/s  (+12.22%, n=127/314)
    4000 ×  -9.5   27.17 →  30.39 g/s  (+11.87%, n=48/54)
     800 ×  -8.5    5.50 →   6.06 g/s  (+10.18%, n=278/703)
    2200 ×  -1.5   39.69 →  43.70 g/s  (+10.09%, n=252/269)
    4000 × -11.5   11.08 →  12.16 g/s  (+9.78%, n=32/40)
    2200 ×  -2.0   37.89 →  41.28 g/s  (+8.96%, n=79/182)
    1900 ×  -8.0   14.39 →  15.51 g/s  (+7.77%, n=203/143)
    1900 ×  -8.5   12.77 →  13.65 g/s  (+6.88%, n=469/210)
    1200 × -10.0    5.68 →   6.06 g/s  (+6.60%, n=1141/441)
    1200 × -10.5    4.82 →   5.12 g/s  (+6.24%, n=63/74)

  Top VE LOSSES:
    1200 ×  -8.5    7.53 →   6.51 g/s  (-13.52%, n=372/49)
    1200 ×  -9.0    7.46 →   6.65 g/s  (-10.97%, n=3495/513)
    2200 ×  -6.0   24.23 →  22.83 g/s  (-5.77%, n=548/237)
    3700 × -10.5   16.93 →  15.97 g/s  (-5.65%, n=137/34)
    3700 ×  +2.5   96.62 →  91.17 g/s  (-5.64%, n=33/38)
    2200 × -10.5    8.77 →   8.27 g/s  (-5.63%, n=972/341)
    2600 ×  -0.5   50.11 →  47.39 g/s  (-5.44%, n=34/471)
    3700 ×  -9.0   24.66 →  23.43 g/s  (-5.01%, n=80/88)
    2200 ×  -5.0   28.33 →  27.11 g/s  (-4.28%, n=343/443)
    3000 × -10.5   12.14 →  11.67 g/s  (-3.94%, n=1091/337)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
               20.8: cells= 58  mean|c|= 1.85%  median|c|= 2.03%  in_tol= 51.7%  max= 5.5%
               20.9: cells= 47  mean|c|= 1.33%  median|c|= 0.86%  in_tol= 80.9%  max= 3.2%
    verdict: WIN — VE up + trim tighter

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

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
               20.9: cells= 47  mean|c|= 1.33%  median|c|= 0.86%  in_tol= 80.9%  max= 3.2%
              20.10: cells= 52  mean|c|= 1.92%  median|c|= 1.93%  in_tol= 50.0%  max= 6.0%
    verdict: MIXED — VE up but trim looser (suspect MAF over-scale)

## VE proxy: 20.11 vs 20.10
  cells with data — 20.10: 200, 20.11: 143
  overlap (≥30 samples in each): 83
  cells with |Δ| ≥ 3%: 40

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.10 → 20.11):
     800 ×  -8.5    5.73 →   6.17 g/s  (+7.65%, n=245/34)
    3300 ×  -8.5   22.57 →  23.50 g/s  (+4.11%, n=271/101)
    3700 × -11.5    9.65 →   9.95 g/s  (+3.11%, n=120/47)
    3000 ×  -9.5   17.01 →  16.48 g/s  (-3.10%, n=1150/480)
    3000 ×  -5.0   37.14 →  35.98 g/s  (-3.14%, n=890/128)
    1600 ×  -6.0   17.07 →  16.52 g/s  (-3.23%, n=53/103)
    3700 ×  -5.0   47.22 →  45.66 g/s  (-3.29%, n=72/30)
    2600 ×  -4.0   38.05 →  36.78 g/s  (-3.35%, n=209/31)
    2600 ×  -9.0   16.75 →  16.18 g/s  (-3.38%, n=1089/432)
    3300 ×  -7.0   32.99 →  31.81 g/s  (-3.57%, n=52/68)

  Top VE LOSSES:
    1200 × -10.5    5.94 →   4.67 g/s  (-21.34%, n=66/61)
    1200 ×  -9.0    7.57 →   6.45 g/s  (-14.89%, n=2979/47)
    1200 ×  -9.5    6.82 →   5.95 g/s  (-12.89%, n=6017/364)
    1900 ×  -5.0   24.22 →  21.94 g/s  (-9.40%, n=178/50)
    2200 ×  -4.0   33.32 →  30.19 g/s  (-9.40%, n=310/166)
    2600 ×  -5.0   34.29 →  31.48 g/s  (-8.20%, n=469/143)
     800 ×  -9.0    4.88 →   4.48 g/s  (-8.14%, n=635/132)
    3300 × -11.0   10.79 →   9.93 g/s  (-7.92%, n=304/265)
     800 × -10.0    4.07 →   3.77 g/s  (-7.39%, n=87/278)
    2200 ×  -6.0   24.88 →  23.09 g/s  (-7.23%, n=428/94)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.10: cells= 52  mean|c|= 1.92%  median|c|= 1.93%  in_tol= 50.0%  max= 6.0%
              20.11: cells= 39  mean|c|= 0.83%  median|c|= 1.03%  in_tol= 92.3%  max= 4.4%
    verdict: MIXED — VE down but trim tighter (correcting prior over-scale?)


## 2026-05-08 — log: logs/5-8 20.11/5-8.csv — rom: 20.11

Log: 44,906 rows / 29.9 min @ 25 Hz. Schema = 33 std + new KNOCK_FLAG col.
Driving profile: city/cruise mix, RPM 146-5362, MPH 0-74, peak Throttle 100% but
**zero sustained WOT pulls** (longest TPS>95% run = 22 samples = 0.88s, missed
the ≥25-sample threshold). CL/OL split: CL=8 30,473 (68%), OL=10 11,622 (26%),
CL=7 2,811 (6%). IAM held 1.00 entire drive — no learned-knock damage.
Caveat: 20.11 has only THIS log; n=1 vs 20.10's 5 logs / 218 min. Rates below
are normalized per-minute where comparison is meaningful.

**Knock:** 12 FBKC events / 276 fbkc<0 samples (verified equal to raw counts).
Top cells (raw fbkc<0 sample count):
- 2600/1.10  n=30  min=-2.45°  AVCS@knock=19.5°  CL/OL=10
- 2600/1.20  n=16  min=-2.80°  AVCS@knock=19.7°  CL/OL=10
- 2800/1.10  n=16  min=-1.40°  AVCS@knock=20.2°  CL/OL=10
- 2600/1.30  n=14  min=-2.80°  AVCS@knock=22.5°  CL/OL=10

201/276 knock samples (73%) in CL/OL=10 (OL with O2). Of total samples, 164
fall in **the ghost zone (2200-3300 RPM × 1.0-1.4 g/rev)** — same zone flagged
in `project_open_issues.md`. Per-min rate vs prior revs:

| rev   | mins  | events/min | samps/min | min FBKC |
|-------|-------|-----------:|----------:|---------:|
| 20.7  | 197   | 0.13       | 3.56      | -9.45    |
| 20.8  | 95    | 0.12       | 2.76      | -4.20    |
| 20.9  | 72    | 0.04       | 1.31      | -2.80    |
| 20.10 | 218   | 0.07       | 1.70      | -7.00    |
| 20.11 | 30    | **0.30**   | **6.76**  | -4.20    |

20.11 ghost-zone knock RATE is the highest of any rev, but DEPTH is shallower
than 20.10 (-4.2° vs -7.0°). 2600/1.17 zone breakdown: 377 samples, 69 with
FBKC<0, AVCS at knock = 20.1° vs all-zone-mean 17.3° — knock fires when AVCS
commands ABOVE-mean advance. Timing 15.6° at knock vs 16.7° all-zone =
FBKC pulled it back, not over-advanced at command. wbo2=13.21 / FFB=12.78
at knock = engine slightly RICHER than commanded (not the lean culprit).

**Hypothesis tested and REJECTED.** Diffed 20.10 NC vs 20.11 NC AVCS table
directly from the .bin files (Cruise 0xda96c, NC 0xdac34, scaling=raw×0.0054932°).
Result: **NC AVCS at the ghost zone (2200-3300 × 1.0-1.4) is byte-identical
between 20.10 and 20.11.** Both have 20.0° / 20.0° / 21.5° / 23.5° at load
1.00 / 1.10 / 1.20 / 1.30. Furthermore, **20.10 NC was already byte-identical
to 20.10 Cruise across the entire 288-cell table**, and so were 20.9 and 20.8.
The "NC=Cruise change in 20.11" never happened — NC has equaled Cruise for at
least 4 ROM revs. The actual 20.11 AVCS NC change vs 20.10 NC is just the
4 cells at 1600-1900 RPM × 0.20-0.30 (+1.3 to +1.5°), inherited because Cruise
got those edits and NC mirrors Cruise.

**ROM diff (full) 20.10 → 20.11 — what actually changed:**
- AVCS Cruise (0xda96c): 7 cells at 1600-2500 RPM × 0.20-0.30, ±0.49 to +1.50°
- AVCS Non-Cruise (0xdac34): same 7 cells (because NC mirrors Cruise)
- **Base Timing Primary Cruise (0xd4714): 23 cells RETARDED, mostly at L=1.20
  column from 1900-4400 RPM, range -1.05° to -2.11°**
- **Base Timing Primary Non-Cruise (0xd48d4): identical 23-cell retard**
- **Base Timing Reference Cruise (0xd4a94): identical 23-cell retard**
- **Base Timing Reference Non-Cruise (0xd4c54): identical 23-cell retard**
- **MAF Sensor Scaling (0xd8c9c) g/s output: 7 floats changed.** Low end
  (V=0.07-0.31) trimmed -0.06 to -0.19 g/s. High end (V=4.66+) bumped UP
  +2.7 to +6.3 g/s.
- (Pedal maps Sport / Sport Sharp / Intelligent: byte-identical 20.10→20.11.
  v9 has been flashed since 20.9 — its first log was 4-25.)

**Ghost-zone re-analysis with corrected change set:** Base Timing was PULLED
1.05-1.76° at 2200-3300 × 1.20 in all 4 timing tables. Pulling timing should
REDUCE knock m