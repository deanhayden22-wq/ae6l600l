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
## ingest 2026-07-15 (rev 20.18a) auto-rollup (2026-07-15 20:57)

## VE proxy: 20.18a vs 20.18
  cells with data — 20.18: 318, 20.18a: 157
  overlap (≥30 samples in each): 106
  cells with |Δ| ≥ 3%: 54

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.18 → 20.18a):
    3700 × -10.5   13.18 →  15.63 g/s  (+18.61%, n=65/89)
     800 ×  -7.5    5.93 →   6.59 g/s  (+11.04%, n=6511/569)
    3700 × -11.0    9.84 →  10.64 g/s  (+8.11%, n=219/118)
    2200 × -10.0    9.54 →  10.08 g/s  (+5.65%, n=1582/101)
    1200 ×  -8.5    7.94 →   8.33 g/s  (+4.98%, n=1071/2586)
    3000 ×  -4.0   41.35 →  43.28 g/s  (+4.67%, n=3147/118)
     800 ×  -9.0    4.53 →   4.73 g/s  (+4.56%, n=2400/305)
    3700 ×  -6.0   39.66 →  41.25 g/s  (+4.01%, n=726/34)
    3300 ×  -5.0   40.19 →  41.72 g/s  (+3.80%, n=2671/79)
    1200 ×  -9.0    7.19 →   7.44 g/s  (+3.47%, n=2267/1128)

  Top VE LOSSES:
    2200 × -11.0    7.72 →   6.33 g/s  (-17.91%, n=5587/116)
    2600 × -10.0   12.01 →  10.18 g/s  (-15.24%, n=2103/32)
    1200 ×  -7.5   10.31 →   9.02 g/s  (-12.49%, n=327/306)
    1900 ×  -8.0   14.64 →  12.97 g/s  (-11.43%, n=302/40)
    1900 ×  -9.5    9.89 →   8.81 g/s  (-10.95%, n=888/88)
    2600 ×  +4.0   72.15 →  64.64 g/s  (-10.41%, n=87/57)
    2600 ×  +3.0   63.76 →  57.52 g/s  (-9.78%, n=73/31)
    1600 ×  -9.5    8.73 →   7.92 g/s  (-9.24%, n=983/79)
    2600 ×  +2.5   61.17 →  55.67 g/s  (-8.99%, n=176/51)
    2600 ×  -9.5   14.48 →  13.19 g/s  (-8.88%, n=3305/32)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.18: cells= 69  mean|c|= 1.62%  median|c|= 1.75%  in_tol= 69.6%  max= 3.3%
             20.18a: cells= 38  mean|c|= 2.58%  median|c|= 2.18%  in_tol= 47.4%  max= 6.0%
    verdict: LOSS — VE down + trim worse


## 2026-07-15 — log: 7-15 20.18a/7-15 20.18a.csv — rom: 20.18a (AVCS CARVE, first driven log)

**Setup verified:** rom_diff 20.18 → 20.18a re-confirmed: 280 B / 25 runs = AVCS Intake Cruise
(0xDA97A–0xDAB0E) + NC (0xDAC42–0xDADD6, byte-identical edit) + checksum. md5 fb5807e4… matches
the 7-14 anchor. Cell decode: core box 1900–3400 × L 1.1–1.3 carved 20–23.5° → **10–11.75°**
(−10 to −11.75°); blend cols at L 0.8/0.9/1.0/1.5 as designed. **DESIGN DEVIATION: rows
1000–1600 ALSO carved (e.g. 1600×1.3: 22.21→12.79) and 3800 row + 4150×1.3 tapered — the 7-13
design entry said no edits ≤1600 or ≥3800. Flagged to Dean (intentional?).**
**Driven-bin confirmed from log:** steady carve-core cam med 12.5°, resid +0.36° vs 20.18a
targets (−10.07 vs 20.18). **No reflash lockout** (per-segment avcs p95 16–20°, max 29).

**Log:** 6 short around-town segments, 31.5 min total, warm (seg IAT med 88–106°F — overlaps
7-12 hot baseline). NO qualifying WOT pull, no highway/5th-gear. Coverage thin: rect residency
0.85 min, ghost 1.24 min, cusp 0.91 min (baselines had 7.6–16 min).

**Knock (headline — carve elimination test, EARLY READ):**
- **Zero fires in rect (0/0.85 min) and ghost (0/1.24 min).** Whole-log FBKC min **−1.4**,
  FLKC 0 decrements, IAM 1.0. Zero deep events anywhere.
- **[RESOLVED same session] Metric discrepancy:** the 7-12 "matched cross-log" rates (rect
  1.97→3.41/min) were **onsets-from-zero** (down-step with FBKC==0 prior — the strict
  first-instance definition); the store's fires_per_min (3.38→6.16) counts **every down-step**
  incl. within-chain deepening. Reproduced exactly. ghost_zone_fires.py now emits BOTH
  (n_onsets/onsets_per_min added; store fully regenerated, 43 logs).
- Poisson read on the zero, both metrics: all-steps rect P(0|0.85 min) ≈ 5.7% (6-21) / 0.5%
  (7-12); **onsets rect P(0) ≈ 18.8% (6-21) / 5.6% (7-12)**. IAT-matched comparator is 7-12.
  Under the stricter onset metric the zero is suggestive, not significant.
- The only 2 fires: 1784×1.02 and 1712×1.22 RPM×load, both **−1.4 trivial**, 11.6–14.1 s after
  DFCO exit (outside <5 s resume family), first has KNOCK_FLAG=1 (noise-reject flagged). Both
  sit in rows that WERE carved (~12–13° commanded) — trivial fires persist under mild cam;
  faint first hint that the noise floor doesn't go to zero.
- **Verdict: LEANS knock-drop, NOT callable.** Deep-rate unreadable at this residency
  (P(0 deep|0.85 min) ≈ 41–57% even at baseline rates). Need a highway/5th-gear log with
  ≥8–10 min box residency.

**Carve cost watch (CORRECTED same session — match on THROTTLE, not load):** the first pass
matched RPM×load cells (−0.3 to −1.0%) but load is MAF-derived, so it hides VE loss. Steady
warm RPM×Throttle-matched cells in the box (load>0.85): **median MAF −2.0% vs 7-12, −3.9% vs
6-21**; ~1% of that is baro (7-15 ATM 14.22 vs 14.36 psi) + ~1% IAT vs 6-21 → **net carve VE
cost ≈ −1 to −3% at matched pedal**, and it scales with the carve: deepest-carved cells (cam
10–12°, thr 24–27%) run −5 to −9%, lightly-carved 21%-thr column −2% to flat — weather can't
produce that cell structure. Load at matched throttle fell 0.02–0.04. Caveat: 7-15 cells are
thin (n 19–165 vs thousands). This is the predicted earlier-IVC filling loss, real but modest;
Dean to seat-check. Spool/transient feel unmeasurable (no scoreable pulls). Boost: 161 samples
>7 psi, med 5.5 psi under target (spool-dominated), peak mrp 19.4, wgdc max 74.9. One 1.28 s
throttle-saturated stab shortlisted (s42845, knock-free, attainment 48%) — ran with cam ~0°
the whole stab; same-metric dead-cam rate (cmd≥8°, avcs≤1°, warm) is 7.6% on this log vs
5.9%/3.0% on 7-12/6-21 → within normal transient/DFCO behavior, NOT a new anomaly, but it
depresses that stab's spool numbers.

**Backstop sweep:**
- AFL med −0.78 (fresh post-reflash relearn, max 0.0/min −4.69); steady-CL-cruise TOTAL trim
  **−1.56** (n=4.8k) vs −2.34 on 7-12 — improving, keep watching.
- AFC −25 saturation: 168 samples, 157 cold warmup (ECT 84–100°F post-reflash), 11 warm
  (0.44 s, log0002) — transient, not a concern.
- IDC peak 91.2% @4747 (brief; known injector ceiling). MAF(V) 4.16. Tip-in stab lean med
  0.59 AFR (n=64, detector not strictly matched — no strong claim).
- **CL=8 with FFB<13.8 confirmed functionally OL** (Dean's row-46358 question): AFC/AFL frozen
  through the FFB 12.8→11.0 stretch (s46360–46410), wbo2 tracks OL command, narrowband pegged.
  12.3% of flagged-CL samples. Consistent with cc170=13.82 being the real switch. These regions
  are valid for manual MAF math (lag-shift wbo2, skip transitions).
- Rest is clean: no tip-in lean spikes of note, no overrun-FBKC regression visible (residency
  thin), MPH max 66.

**Bookkeeping (closed this session):** 7-15 ingested (log_review_ingest: ve_proxy 157 rows,
maf_corr 99, stutter 260, wot 1, knock_by_cell 13 — rollup below); zone_fire_rates regenerated
corpus-wide with the new onsets metric; rom_rev_map row added; rect-rate discrepancy resolved
(see above). Ingest gap flagged on 7-12 was already closed same-day (log_health/ve_proxy
current through 7-12 before this session).

**Staged for next session:**
- Get a highway/5th-gear log on 20.18a: ≥8–10 min in rect at steady cruise + passing pulls —
  that's the log that calls the elimination test. Note IAT.
- Ask Dean: 1000–1600-row + 3800-row carve = intentional design change? Also seat-check the
  −1 to −3% matched-pedal airflow cost.

## 2026-07-13 — DEEP-HISTORY AUDIT (Car folder archive, 2023→2026) — CAM IS THE LAST UNTESTED LEVER

**Source:** Desktop/Car folder — full rev lineage (garn a–h, lettered L→P11x, AI 2–20, 20–20.4)
+ Logs/2023.7z (227 csvs, Jan–Nov 2023) + 2024/2025 zips + 2026 folders. Silver-car bins
present (separate car — VF52→11-blade stage 2; excluded).

**Finding 1 — measured cam at the knock box is ~19–21° in EVERY driven era, 2023→2026.**
Bins tell a different story (L/N/O/P command 15.0; garn b–d command 10.0) but the LOGS from
those eras measured 20.0 at the box — the saved bins were not what was driven (third
bins-vs-road divergence today, after the "stock" mislabel and the stock-valley-never-ran
finding). THE CAR HAS NEVER DRIVEN THE KNOCK CELLS AT MILD CAM outside reflash lockouts
(5.5 min corpus-wide, 2026: 0.90 fires/min, 0 deep — vs 1.41/min, 0.276 deep/min normal-cam;
suggestive, thin).

**Finding 2 — the box knock is PERMANENT, not a regression.** Every era shows 0.4–5
first-instance fires/min at 1600–3200 × 1.0–1.35: garn-rev 2023 ~0.5–1.4, summer-2023 L-era
2.0–5.1 (with deep −4.2/−5.6), P11-fall-2023 2.9–3.9 (0 deep), 2026 spring 1.1–2.1, 2026
summer 2.9–5.1. Never absent, never IAM-threatening. Three years of timing/fuel/boost/tau
work modulated it; nothing eliminated it.

**Finding 3 — era/IAT/delay attribution is CONFOUNDED at this residency** (1–4.5 min per
era×IAT cell). Delay-125 eras trend cleaner than delay-70 eras but the summer-2023 L-era
(delay 125) is the dirtiest cell in the table, and within-2023 the cool logs out-knocked the
hot ones (5.1 vs 2.0/min) — opposite of 2026. The 7-12 IAT-dominance read did not survive
either. Nothing here is clean enough to act on alone.

**VERDICT (Dean's call, 2026-07-13): AVCS carve REINSTATED as the decisive ELIMINATION
experiment** — not on the dead factory-valley argument, but because cam is literally the last
untested lever at these cells. Both outcomes are decisive: knock drops → real combustion
knock, keep carve, consider timing give-back; knock unchanged → with fuel/timing/tau/boost/cam
all acquitted, the NOISE hypothesis (sensor artifact — mechanical/lash; note 8/12 deep 7-12
events sit ≤5 s after DFCO exit = torque-reversal moments) becomes primary → respond
detection-side (delay revert, thresholds) + accept-and-contain, stop spending timing.
**Design:** carve on TOP OF 20.18 (NOT 20.19 — its load-comp reshape moves the load calc and
muddies the cam A/B vs the two clean 20.18 baselines 6-21/7-12); core 50% toward stock at
1900–3400 × 1.1–1.3, residency-informed edges per the 7-12 analysis (−1° blend at 1.0 col;
−2° at 1.5 × 2800–3400 only; no edits ≤1600 (launch cells, stock agrees) or ≥3800; Cruise ≡
NC). Score IAT-matched: zone_fire_rates (cusp/rect) + log_health deep-split vs 6-21 (IAT 88)
and 7-12 (IAT 97). AVCS post-reflash lockout check applies (ironically, lockout minutes are
bonus mild-cam data — log them, don't discard).

**Housekeeping:** channel mapper extended — old logger names "Feedback Knock Correction
(4-byte)* (degrees)" (asterisk variant) and "Intake VVT Advance Angle Left (degrees)" now map
to FBKC/avcs; one missing asterisk had blinded 57 of the 2023 logs. 94/156 old files still
fail to parse (format variants — open item). 4 logs carry per-cylinder Knock Sum channels
(which-cylinder question — open item). 2023 scan artifacts: outputs/scan2023_v2.csv.
Standing rule learned three times today: BINS AND LABELS LIE; LOGS ARE GROUND TRUTH — verify
what was DRIVEN from measured channels before any era claim.

---

## ingest 2026-07-12 (rev 20.18) auto-rollup (2026-07-12 17:39)

## VE proxy: 20.18 vs 20.17a
  cells with data — 20.17a: 348, 20.18: 318
  overlap (≥30 samples in each): 220
  cells with |Δ| ≥ 3%: 76

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.17a → 20.18):
    2600 × -11.5    7.05 →   9.00 g/s  (+27.59%, n=760/163)
    1600 × -11.0    5.50 →   6.46 g/s  (+17.47%, n=151/32)
    1200 × -10.5    4.82 →   5.51 g/s  (+14.48%, n=190/460)
    2600 ×  +3.5   63.73 →  71.39 g/s  (+12.02%, n=87/54)
    2600 ×  +4.5   69.09 →  75.86 g/s  (+9.80%, n=68/77)
    1200 ×  -7.5    9.41 →  10.31 g/s  (+9.54%, n=318/327)
    3300 ×  +1.5   72.17 →  78.86 g/s  (+9.28%, n=2785/434)
    3300 ×  +1.0   69.40 →  75.66 g/s  (+9.02%, n=2843/318)
    3300 ×  +2.0   74.69 →  81.26 g/s  (+8.80%, n=1816/228)
    2600 ×  +4.0   66.42 →  72.15 g/s  (+8.63%, n=124/87)

  Top VE LOSSES:
    3700 × -11.0   11.55 →   9.84 g/s  (-14.77%, n=452/219)
    2200 × -10.0   10.58 →   9.54 g/s  (-9.84%, n=2200/1582)
     800 ×  -9.5    4.25 →   3.85 g/s  (-9.50%, n=59770/16557)
    4400 × -11.5   15.06 →  13.64 g/s  (-9.46%, n=91/473)
    3700 × -10.5   14.43 →  13.18 g/s  (-8.68%, n=117/65)
     800 × -10.0    4.15 →   3.81 g/s  (-8.31%, n=787/1811)
    3300 × -10.5   12.64 →  11.64 g/s  (-7.91%, n=1313/900)
     800 ×  -7.5    6.40 →   5.93 g/s  (-7.26%, n=2273/6511)
    3700 × -10.0   18.56 →  17.23 g/s  (-7.13%, n=118/49)
    3700 ×  -9.5   21.68 →  20.24 g/s  (-6.62%, n=279/170)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
             20.17a: cells= 94  mean|c|= 0.86%  median|c|= 1.80%  in_tol= 56.4%  max= 5.4%
              20.18: cells= 69  mean|c|= 1.62%  median|c|= 1.75%  in_tol= 69.6%  max= 3.3%
    verdict: MIXED — VE up but trim looser (suspect MAF over-scale)


## ingest 2026-06-14 (rev 20.17a) auto-rollup (2026-07-12 17:39)

## VE proxy: 20.17a vs 20.17
  cells with data — 20.17: 217, 20.17a: 348
  overlap (≥30 samples in each): 141
  cells with |Δ| ≥ 3%: 61

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.17 → 20.17a):
    1200 ×  -6.5   11.30 →  13.54 g/s  (+19.81%, n=367/168)
     800 ×  -6.0    7.35 →   8.22 g/s  (+11.83%, n=31/253)
    2600 ×  -2.0   40.87 →  44.42 g/s  (+8.69%, n=35/1390)
    1200 ×  -7.0   10.58 →  11.47 g/s  (+8.45%, n=185/122)
    2600 ×  -2.5   39.89 →  42.91 g/s  (+7.57%, n=69/989)
    1200 ×  -8.0    7.86 →   8.45 g/s  (+7.55%, n=209/402)
    3700 ×  -8.5   25.50 →  27.28 g/s  (+6.95%, n=35/732)
    3300 ×  -1.5   52.62 →  56.03 g/s  (+6.47%, n=254/6799)
    3300 ×  +1.5   67.85 →  72.17 g/s  (+6.37%, n=114/2785)
    3300 ×  -1.0   54.92 →  58.24 g/s  (+6.06%, n=108/5986)

  Top VE LOSSES:
     800 ×  -9.0    5.41 →   4.60 g/s  (-14.96%, n=153/9412)
    1900 × -11.0    7.62 →   6.83 g/s  (-10.30%, n=39/491)
    1900 ×  -9.0   11.86 →  10.76 g/s  (-9.29%, n=99/998)
    1900 ×  -8.5   13.36 →  12.25 g/s  (-8.26%, n=213/804)
    2200 ×  -9.0   14.99 →  13.83 g/s  (-7.74%, n=283/1772)
    3300 × -10.5   13.67 →  12.64 g/s  (-7.55%, n=225/1313)
    1900 ×  -9.5   10.76 →   9.97 g/s  (-7.33%, n=165/1719)
    3300 × -11.0   10.38 →   9.64 g/s  (-7.20%, n=524/5391)
    2600 × -10.5    9.83 →   9.20 g/s  (-6.39%, n=965/9120)
    2200 ×  -9.5   12.43 →  11.66 g/s  (-6.21%, n=377/3322)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.17: cells= 44  mean|c|= 1.14%  median|c|= 1.26%  in_tol= 77.3%  max= 3.6%
             20.17a: cells= 94  mean|c|= 0.86%  median|c|= 1.80%  in_tol= 56.4%  max= 5.4%
    verdict: WIN — VE up + trim tighter


## 2026-07-12 — log: 7-12 20.18/7-12 20.18.csv — rom: 20.18 (2nd log on this build; HOT DAY + AC)

**Context:** 408,951 samples / 272.6 min, 8 segments (two long highway legs 121.6 + 109.4 min).
Hot: IAT med 97°F, p95 124, max 149 (heat soak). AC on. AVCS sanity PASS (p95 21°, max 30).
**Driven-bin verification:** 20.18 (md5 506e90b9, unchanged since 6-16) — inferred from log, not
assumed: at the 412 steady samples where 20.18 and the unflashed 20.19 AVCS tables disagree
(L=1.50 row, 1900–3000), actual cam sits +0.33° off 20.18 targets vs +1.04° off 20.19. 20.19
(built 6-21, 194 bytes = Load Comp Cruise+NC + 20 AVCS intake cells, NOT flashed) stays staged.

**Knock:** 46 first-instance FBKC events, 0.174/min overall (vs 6-21 0.262/min), worst −8.4
(s404270, 2607×1.23, 0.5 s after DFCO exit, 31% APP swing). 12 deep (≤−3), ALL in cusp band
1875–3050 × 1.02–1.26, partial throttle, low/neg mrp.
- **Deep-event attribution: 8/12 are DFCO-resume** (<5 s since IPW=0 exit, APP swings 20–43%);
  only 2–3 quasi-steady (s47076, s209503, s396200 borderline). Only 2 of 12 in 5th (RPM/MPH ≈40);
  most are 3rd/4th tip-ins around town. Today's deep knock is the overrun-resume family, not the
  5th-gear steady substrate.
- **Matched cross-log vs 6-21 (same bin, first-instance fires/min):** rect (2250–3150 × 1.05–1.40)
  1.97 → 3.41/min (+73%), deep 0.66 → 1.05/min; cusp (1600–3000 × 1.00–1.25) 2.00 → 2.89/min,
  deep 0.38 → 0.80/min. Same ROM both days → environmental (heat/AC/fuel batch) + driving mix,
  not a tune regression. Onset rate by IAT band is NOT monotonic (0.13 / 0.21 / 0.15 per min for
  60-90/90-110/110-150°F) — AC ran all day so heat vs compressor-load can't be separated.
- **FLKC now participating: 518 decrements (6-21: 7), floor −1.75, 1.7% of samples.** Fully
  recovered to 0 by end of every segment; IAM 1.0 all day. Cascade behaving as designed
  (sustained cusp knock → FLKC tier engages). Decrements concentrate 2000–3000 RPM ×
  ~1.0–1.27 load; heaviest in log0001 (299) incl. the IAT 120–145°F heat-soak first 15 min.

**WOT:** 0 qualifying pulls (≥95% ≥1 s + mrp≥7). BUT one short ripper s232136–232160 (log0005):
4557→6214 RPM, peak mrp 18.7 psi, **IDC peaked 114.9% @ 6052 RPM** (11 samples >85%, IPW 23.0 ms).
Knock-free (FBKC 0), timing 11.5–14° in boost, wbo2 ~10.5–11.1 through the lag-shifted peak-demand
window — commanded ~10.0–10.5, so actual ran slightly lean-of-command but rich of 11.3; injectors
technically saturated (>100% static) yet mixture held THIS time. First >100% IDC at true top-end
RPM — hardest injector-ceiling datapoint yet (6-21 peak was 93.7%). Boost during stab tracked
−6.3 psi under 22.2 target (turbo ceiling, consistent with 6-13 finding). MAF(V) max 4.38 — headroom.
Clean 3rd-gear pull to redline STILL missing (this was a quick stab + shift at 6682).

**MAF corr (recomputed, CL=AFC+AFL / OL=wbo2 lag-3 vs FFB):**
- Idle band 1.18–1.30V: **+3.41%** (n=7.9k) — was +0.78% on 6-21, −5.5% pre-rescale. Sign flipped
  to under-read. CONFOUND: AC compressor load on idle all day; don't touch MAF off this log.
- Cruise bands: 1.9–2.2V −1.8%, 2.2–2.5V −1.2%, 2.7–2.96V −2.2% — the ~2% cruise over-read persists.
- **3.2–3.6V: −5.2% (n=520)** — boost-onset region where the 20.18 rescale added +10% (2.83–3.26V).
  Possible overshoot of that rescale; watch, n small and mostly OL.
- OL mrp≥14: med(wbo2−FFB) −0.17 AFR (n=81, thin) — rich bias family still visible.

**Fuel trims:** AFL med −1.56 (was −2.34), decile walk −3.91 → **0.0 by end of day** — the 6-21
"slow lean re-learn after MAF rescale" hunch is holding. BUT total trim (AFC+AFL) at steady CL
cruise: med **−2.34** (n=142k) — unchanged. AFL recovery is learning redistribution; the cruise
flow band still over-reads ~2%. AFC not clamping (0.01% at limit).

**Transients:** non-DFCO tip-in peak lean med +2.93 AFR / p90 +4.99 (n=824; broader detector than
the 6-21 cusp-specific 2.16 figure — NOT directly comparable, do not trend these two numbers).

**Cliffs / Stutter / VE:** not run — trends pipeline not ingested (see gap below).

**Prior-flagged areas re-checked:**
- Load-comp lean dead zone (2.7–2.96V, <3350, >−1 psi): **−0.80%** — fix HOLDING (was +4–8% lean).
- Idle-band over-read: regressed to +3.41% but AC/heat confounded — WATCH, not actionable.
- AFL drift: recovering (above). Cruise total trim unchanged −2.34.
- Deep overrun IPW=0 FBKC (decel-tier family): clean — deep events are resume-side, not in-DFCO.
- AVCS: p95 21°, tracking +0.33° median at steady state. Clean.
- Boost: no overboost; stab tracked under target (ceiling). wgdc peak 74%.
- 20.16 P0s: no −11.8 ghost events; IDC>100 DID recur but at true redline WOT (mechanism is
  injector size, not the 20.16 partial-throttle pathology).

**New issues:**
- **IDC >100% at top end** (s232150, 114.9% @ 6052 RPM / 18.7 psi). Mixture survived; margin is
  zero. Injector swap is now blocking for ANY top-end work, incl. the missing redline pull.
- Knock-rate elevation on hot+AC days (rect +73% fires/min at same ROM) — quantifies the
  environmental sensitivity of the edge-of-knock cusp zone; FLKC tier absorbs it as designed.

**Pipeline gap:** rom_rev_map.csv + trends/ CSVs last ingested 6-7. Missing: 6-13, 6-15, 6-21,
7-12. REV_ORDER lists in scorecard/dashboard/rom_changeset also stale (no 20.18). Backfill needed
before any trends-CSV-based cross-rev claim.

**Staged for next session:**
- ~~Warm rising-tau restore (0xCD6E6)~~ **RETRACTED same day — see amendment below.**
- Clean 3rd-gear WOT pull to redline still owed — but IDC hit 114.9% at 6052/18.7 psi today;
  margin at the top is zero, decide injector timing first.
- Backfill trends ingest 6-13 → 7-12. **DONE same day** (commit 2f0b5a9: 7 logs, all trend
  surfaces through 20.18, rect zone + log_health.csv added).

**AMENDMENT (same day, after Dean supplied the tau history):** The warm-tau cut was DELIBERATE,
not inherited-unexplained: with tau at stock, leaning into high-boost zones stacked transient
enrichment on the OL map — map commanded 11.1, FFB delivered ~10.1 — maxing injectors early.
Dean landed the current values where high-load pulls command ≈ the OL map. Two measurements on
the 7-12 log then killed the restore proposal outright:
1. **The deep-resume knock events don't consult the halved cells.** 6/8 never exceeded load 1.4
   in the 2 s pre-onset window; the load ≤1.4 row is ALREADY STOCK. Restoring the 3.0/8.0 warm
   columns adds nothing at the loads where the deep events fire.
2. **The landing criterion still holds on 20.18:** settled high-load OL FFB sits +0.24 AFR rich
   of the OL B map (n=37); rising-load transients stack +0.47 median / +0.97 peak (redline stab:
   map 11.0, FFB 10.04 at the IDC-114.9% moment). Restoring warm tau would widen exactly this
   stack with injectors already saturated.
Also downgraded: "resume family" may be stab-selection — aggressive stabs in normal driving
follow coasts, so ≤5 s-from-IPW=0 tags stabs, not a distinct resume mechanism; the stab-lean
fuel thread already died on 6-5/6-7 BE-comp evidence. Deep transient knock = the transient face
of the edge-of-knock substrate, contained by FBKC/FLKC (IAM 1.0 throughout).
**Revised next flash: 20.19 as-built** (Engine Load Comp Cruise+NC pull in the cusp band —
lowers calc load → timing demand where BOTH knock flavors fire — plus 12 AVCS trim cells).
Score it on: rect/cusp fires/min (zone_fire_rates), deep events/hr (log_health), FLKC
engagement, with weather noted — 7-12 showed hot+AC inflates rates ~+70% at fixed ROM.

**AMENDMENT 2 (same day — outside-the-box sweep):**
- **AVCS knock-cell plateau found (prime substrate suspect).** Stock intake-cam table dives
  to 0–15° at exactly 2000–3400 × load 1.10–1.40 (factory anti-knock valley: 0.0° at
  2300×1.25); the 20.8 base map filled it to a flat 20–25.5° and it's byte-stable through
  20.19. Every "NOT cam" verdict only verified actual-tracks-target. Corpus: stock cusp
  0.38 fires/min max −1.4 vs 20.x pooled 2.82/min to −11.8; deep (≤−4) cusp knock first
  appears at 20.8. Confounds noted (thin stock residency, March weather, VF52 regime, 20.8
  changed everything at once). **20.20 candidate: half-carve the valley (1.10–1.40 cols
  only, ≈10–13°), after 20.19 baselines.** Details: memory project_avcs_knock_cell_plateau.
- **Window B acquitted as the stab-rate culprit:** consistent onset-only detector shows cusp
  stab-context fires FLAT across the arming boundary (6-7: 2.62/min → 6-21: 2.63/min); the
  old 6.59→9.42 "jump" was the legacy counter's artifact. Steady-context walked 0.74→1.26→
  1.97/min across the same span — 3-way confounded (load-comp reshape / weather / window B),
  sign test still open but demoted.
- **Tau corpus scan (tau_effect_scan.csv):** cut era holds the landing criterion everywhere
  (rising stack +0.38 pooled, settled +0.14, never the old ~1.0); the pre-cut counterfactual
  predates the corpus; 20.18's row-1 warm restore was a measurable no-op. Tau book closed.

---

## 2026-06-15 — ROM binary-diff: 20.17a → 20.18 (no log; bin diff only)

**Bins:** 20.17a md5 `234c0839…` (unchanged) → 20.18 md5 `506e90b9…` (re-saved mid-session;
the Turbo Dynamics Proportional table picked up 2 more low-boost-error cells during the diff).
**502 bytes / 38 runs, fully labeled** (added Boost Error, Turbo-D P, Engine Load Comp blocks,
Tau Rising-Load A, Post-Transient Knock Window to `rom_diff.py` KNOWN_TABLES; re-run `python
scripts/analysis/rom_diff.py --before 20.17a --after 20.18`).

**Reconciles the open commit note ("docs say 20.18 = arm window B; bin = load-comp reshape").**
It is ONE bin doing BOTH, not two builds:

1. **Post-Transient Knock Window B Length @0xD29C4: 0 → 438** — window B ARMED, to the STI
   factory value. Window A (0xD29C2) stays 0; accumulator bleed targets (0xD2BCC/0xD2BD0 =
   15477) unchanged — window turned on, bleed mechanism stock.
2. **Engine Load Comp (Cruise + Non-Cruise, IDENTICAL reshape) — matches
   `load_comp_proposed_20.18.csv` as proposed.** Full re-grid, not a cell bump: RPM axis
   1600–4000 (was the degenerate 3350–4475 cluster), MP axis −10.6..+3.87 psi (was −11.8..0).
   True interpolated surface delta (18 − 17a, comp %):
   - **+1 to +3.3%** added at 2000–3200 RPM × 0..+2 psi (raises calc load at tip-into-boost).
   - **−4 to −13%** pulled at 3600–4000 RPM × −8..−4 psi (lowers calc load in the steady-cusp
     knock band → pulls timing demand with it — the load/timing substrate move the 6-7 cusp
     thread pointed to).
3. **MAF Sensor Scaling rescale (29/54 pts, 0.93–3.84V):** −10% at low airflow (0.9–1.4V ≈
   idle/light cruise) → leaner; **+10% at boost-onset airflow (2.83–3.26V ≈ 67–126 g/s)** →
   richer into boost; mid −1..−5%.
4. **Boost control:** Boost Error axis + Turbo Dynamics Proportional nudged; Max WGDC (7 cells)
   + Initial WGDC (6 cells) top rows.
5. **Tau Input A Rising Load** (transient enrichment): a few cells, faster rising-load tau.

**Confound to flag before scoring:** the global MAF rescale shifts fueling everywhere, so a
clean log on 20.18 will NOT isolate whether window-B arming vs the load-comp pull is what moves
the cusp knock. The window-B + load-comp pair was the intended test; the MAF rescale muddies the
attribution. Verification checklist from the 6-07 proposal entry still applies for the load-comp half.

---

## ingest 2026-06-05 (rev 20.17a) auto-rollup (2026-06-07 22:50)

## VE proxy: 20.17a vs 20.17
  cells with data — 20.17: 217, 20.17a: 345
  overlap (≥30 samples in each): 141
  cells with |Δ| ≥ 3%: 65

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.17 → 20.17a):
    1200 ×  -6.5   11.30 →  13.39 g/s  (+18.54%, n=367/117)
     800 ×  -6.0    7.35 →   8.22 g/s  (+11.83%, n=31/253)
    2600 ×  -2.0   40.87 →  44.49 g/s  (+8.87%, n=35/1349)
    2600 ×  -2.5   39.89 →  42.97 g/s  (+7.70%, n=69/976)
    1200 ×  -8.0    7.86 →   8.42 g/s  (+7.21%, n=209/237)
    3700 ×  -8.5   25.50 →  27.28 g/s  (+6.95%, n=35/732)
    1900 ×  -6.5   17.94 →  19.15 g/s  (+6.75%, n=61/119)
    3300 ×  -1.5   52.62 →  56.03 g/s  (+6.47%, n=254/6793)
    1200 ×  -7.0   10.58 →  11.25 g/s  (+6.39%, n=185/107)
    3300 ×  +1.5   67.85 →  72.17 g/s  (+6.37%, n=114/2785)

  Top VE LOSSES:
     800 ×  -9.0    5.41 →   4.55 g/s  (-16.01%, n=153/5394)
    1900 × -11.0    7.62 →   6.83 g/s  (-10.30%, n=39/491)
    3300 × -10.5   13.67 →  12.61 g/s  (-7.80%, n=225/837)
    3000 × -10.5   11.25 →  10.41 g/s  (-7.50%, n=285/3551)
    2600 × -10.5    9.83 →   9.11 g/s  (-7.30%, n=965/8766)
    3300 × -11.0   10.38 →   9.63 g/s  (-7.22%, n=524/5387)
    1900 ×  -4.5   25.77 →  24.27 g/s  (-5.85%, n=34/170)
    1600 × -10.5    7.38 →   6.96 g/s  (-5.62%, n=61/1288)
    3700 × -11.5   10.70 →  10.10 g/s  (-5.56%, n=38/1465)
    2200 ×  -9.0   14.99 →  14.19 g/s  (-5.32%, n=283/1221)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.17: cells= 44  mean|c|= 1.14%  median|c|= 1.26%  in_tol= 77.3%  max= 3.6%
             20.17a: cells= 65  mean|c|= 0.63%  median|c|= 1.02%  in_tol= 73.8%  max= 3.8%
    verdict: WIN — VE up + trim tighter


## ingest 2026-06-03 (rev 20.17) auto-rollup (2026-06-07 22:50)

## VE proxy: 20.17 vs 20.16
  cells with data — 20.16: 163, 20.17: 217
  overlap (≥30 samples in each): 91
  cells with |Δ| ≥ 3%: 66

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.16 → 20.17):
    3000 × -11.5    8.26 →   9.23 g/s  (+11.76%, n=188/61)
    1600 × -10.5    6.66 →   7.38 g/s  (+10.75%, n=792/61)
    1900 × -10.5    7.22 →   7.93 g/s  (+9.82%, n=659/450)
     800 ×  -9.0    5.02 →   5.41 g/s  (+7.85%, n=4495/153)
    1900 ×  -6.0   19.97 →  21.15 g/s  (+5.94%, n=50/37)
     800 × -10.0    4.18 →   4.38 g/s  (+4.67%, n=374/35)
    2600 × -10.0   12.29 →  12.86 g/s  (+4.66%, n=216/235)
    3700 × -11.5   10.26 →  10.70 g/s  (+4.30%, n=105/38)
    1900 ×  -9.5   10.33 →  10.76 g/s  (+4.23%, n=48/165)
    1900 × -11.0    7.31 →   7.62 g/s  (+4.14%, n=359/39)

  Top VE LOSSES:
    1200 ×  -8.5    9.92 →   7.26 g/s  (-26.89%, n=211/824)
    1200 ×  -8.0   10.60 →   7.86 g/s  (-25.87%, n=118/209)
    1200 ×  -9.0    8.31 →   7.08 g/s  (-14.81%, n=333/467)
    1200 ×  -7.5   11.23 →   9.78 g/s  (-12.95%, n=117/246)
    2600 ×  -3.5   42.46 →  37.38 g/s  (-11.96%, n=69/56)
    2200 ×  -4.5   33.53 →  29.64 g/s  (-11.61%, n=45/262)
    3000 ×  +0.0   60.81 →  54.30 g/s  (-10.70%, n=38/256)
    1200 ×  -9.5    7.35 →   6.58 g/s  (-10.51%, n=984/3217)
    2600 ×  -2.0   45.40 →  40.87 g/s  (-9.99%, n=69/35)
    2200 × -10.5    9.51 →   8.57 g/s  (-9.90%, n=468/1376)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.16: cells= 43  mean|c|= 1.79%  median|c|= 1.69%  in_tol= 69.8%  max= 4.5%
              20.17: cells= 44  mean|c|= 1.14%  median|c|= 1.26%  in_tol= 77.3%  max= 3.6%
    verdict: MIXED — VE down but trim tighter (correcting prior over-scale?)



## auto-generated rev rollup (2026-06-03 00:24)

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
  cells with data — 20.10: 200, 20.11: 185
  overlap (≥30 samples in each): 113
  cells with |Δ| ≥ 3%: 37

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.10 → 20.11):
    1200 ×  -7.0   12.03 →  13.42 g/s  (+11.56%, n=98/31)
    3300 ×  -8.5   22.57 →  24.34 g/s  (+7.86%, n=271/449)
    2200 × -10.5    8.44 →   9.00 g/s  (+6.61%, n=891/1214)
    1900 × -10.0    8.88 →   9.36 g/s  (+5.34%, n=198/207)
    2600 ×  -0.5   48.01 →  50.45 g/s  (+5.08%, n=270/34)
    3300 ×  -8.0   25.93 →  27.16 g/s  (+4.74%, n=98/449)
    2200 ×  -9.5   12.70 →  13.21 g/s  (+4.03%, n=859/765)
    3300 ×  -7.5   28.63 →  29.70 g/s  (+3.72%, n=123/585)
    3000 ×  -5.5   34.31 →  35.53 g/s  (+3.56%, n=481/243)
    2200 ×  -2.0   40.49 →  39.21 g/s  (-3.15%, n=378/350)

  Top VE LOSSES:
    1200 ×  -8.5    8.55 →   7.22 g/s  (-15.56%, n=811/299)
    1200 × -10.5    5.94 →   5.40 g/s  (-9.18%, n=66/173)
    3300 × -11.0   10.79 →   9.83 g/s  (-8.88%, n=304/420)
    1900 ×  -5.0   24.22 →  22.42 g/s  (-7.44%, n=178/288)
     800 × -10.0    4.07 →   3.78 g/s  (-7.11%, n=87/389)
    3300 ×  -5.0   44.06 →  41.07 g/s  (-6.78%, n=79/209)
    1900 ×  -4.5   25.80 →  24.12 g/s  (-6.48%, n=212/47)
     800 ×  -8.0    6.05 →   5.69 g/s  (-6.06%, n=30/45)
    3300 × -10.0   17.39 →  16.42 g/s  (-5.57%, n=97/191)
     800 ×  -8.5    5.73 →   5.44 g/s  (-5.20%, n=245/308)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.10: cells= 52  mean|c|= 1.92%  median|c|= 1.93%  in_tol= 50.0%  max= 6.0%
              20.11: cells= 52  mean|c|= 1.42%  median|c|= 1.28%  in_tol= 84.6%  max= 3.7%
    verdict: MIXED — VE down but trim tighter (correcting prior over-scale?)

## VE proxy: 20.12 vs 20.11
  cells with data — 20.11: 185, 20.12: 299
  overlap (≥30 samples in each): 126
  cells with |Δ| ≥ 3%: 47

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.11 → 20.12):
    1600 × -10.0    7.10 →   8.11 g/s  (+14.36%, n=223/387)
    1900 ×  -9.5   10.18 →  11.46 g/s  (+12.53%, n=215/364)
    1600 ×  -9.5    8.35 →   9.27 g/s  (+11.06%, n=265/2157)
     800 ×  -9.0    4.63 →   4.96 g/s  (+7.01%, n=1096/1298)
    2600 × -10.5   10.00 →  10.69 g/s  (+6.85%, n=492/1344)
    1600 ×  -8.5   10.94 →  11.67 g/s  (+6.67%, n=528/548)
    1900 ×  -8.5   13.12 →  13.92 g/s  (+6.11%, n=523/496)
    1900 ×  -9.0   11.68 →  12.39 g/s  (+6.05%, n=217/312)
    2600 × -10.0   12.09 →  12.82 g/s  (+6.02%, n=242/882)
    3000 × -10.5   11.57 →  12.23 g/s  (+5.70%, n=413/947)

  Top VE LOSSES:
    3700 × -12.0    9.98 →   8.46 g/s  (-15.20%, n=115/90)
    3700 ×  -8.5   29.30 →  26.47 g/s  (-9.65%, n=272/456)
    3700 ×  -9.0   25.87 →  23.56 g/s  (-8.93%, n=106/571)
    1200 ×  -7.0   13.42 →  12.47 g/s  (-7.06%, n=31/57)
    1200 ×  -8.5    7.22 →   6.78 g/s  (-6.18%, n=299/50)
    3300 ×  -9.5   19.84 →  18.63 g/s  (-6.11%, n=433/2323)
    3700 ×  -7.5   35.24 →  33.30 g/s  (-5.52%, n=222/780)
    3300 × -10.5   14.46 →  13.69 g/s  (-5.36%, n=219/291)
    3300 ×  -8.0   27.16 →  25.73 g/s  (-5.25%, n=449/1173)
    3700 ×  -8.0   32.13 →  30.45 g/s  (-5.23%, n=115/396)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.11: cells= 52  mean|c|= 1.42%  median|c|= 1.28%  in_tol= 84.6%  max= 3.7%
              20.12: cells= 70  mean|c|= 2.39%  median|c|= 1.88%  in_tol= 84.3%  max= 3.8%
    verdict: MIXED — VE up but trim looser (suspect MAF over-scale)

## VE proxy: 20.13 vs 20.12
  cells with data — 20.12: 299, 20.13: 280
  overlap (≥30 samples in each): 172
  cells with |Δ| ≥ 3%: 97

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.12 → 20.13):
    3700 × -11.0   12.12 →  14.33 g/s  (+18.16%, n=124/34)
    3700 × -12.0    8.46 →   9.72 g/s  (+14.88%, n=90/826)
    4000 ×  -9.5   25.91 →  29.40 g/s  (+13.50%, n=98/40)
    2200 ×  +0.0   42.92 →  47.66 g/s  (+11.04%, n=40/49)
    2200 ×  +0.5   42.87 →  47.43 g/s  (+10.63%, n=36/39)
    3700 ×  -8.5   26.47 →  29.17 g/s  (+10.18%, n=456/430)
    3700 ×  -9.0   23.56 →  25.83 g/s  (+9.64%, n=571/296)
    4000 ×  -3.0   59.72 →  64.72 g/s  (+8.37%, n=129/73)
    4000 ×  -4.0   54.65 →  59.21 g/s  (+8.35%, n=183/138)
    3300 × -11.0    9.62 →  10.42 g/s  (+8.29%, n=1982/404)

  Top VE LOSSES:
    1200 ×  -9.5    6.68 →   5.57 g/s  (-16.66%, n=5668/298)
    4000 × -12.0   12.17 →  10.97 g/s  (-9.82%, n=115/40)
     800 ×  -9.0    4.96 →   4.67 g/s  (-5.79%, n=1298/80)
    1200 × -10.0    5.86 →   5.58 g/s  (-4.75%, n=1713/1065)
    1900 ×  -9.0   12.39 →  11.82 g/s  (-4.63%, n=312/41)
    1900 ×  -9.5   11.46 →  10.93 g/s  (-4.57%, n=364/164)
    1600 × -11.0    6.52 →   6.24 g/s  (-4.34%, n=189/777)
     800 ×  -9.5    4.23 →   4.10 g/s  (-3.19%, n=22846/8149)
    3300 × -11.5    9.38 →   9.08 g/s  (-3.17%, n=2877/3415)
    3700 ×  +0.0   69.92 →  72.04 g/s  (+3.04%, n=974/280)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.12: cells= 70  mean|c|= 2.39%  median|c|= 1.88%  in_tol= 84.3%  max= 3.8%
              20.13: cells= 57  mean|c|= 1.12%  median|c|= 1.25%  in_tol= 91.2%  max= 2.6%
    verdict: WIN — VE up + trim tighter

## VE proxy: 20.14 vs 20.13
  cells with data — 20.13: 280, 20.14: 313
  overlap (≥30 samples in each): 160
  cells with |Δ| ≥ 3%: 77

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.13 → 20.14):
    1900 × -11.5    5.69 →   7.37 g/s  (+29.68%, n=113/271)
    1200 ×  -9.5    5.57 →   7.13 g/s  (+27.97%, n=298/2775)
     800 ×  -9.0    4.67 →   5.65 g/s  (+20.92%, n=80/309)
    3000 × -11.0    9.38 →  10.94 g/s  (+16.64%, n=1866/430)
    2600 × -11.0    8.54 →   9.87 g/s  (+15.52%, n=2034/917)
    3300 × -11.0   10.42 →  11.92 g/s  (+14.41%, n=404/164)
    2200 × -11.0    7.84 →   8.77 g/s  (+11.88%, n=713/799)
    2600 × -10.0   13.17 →  14.64 g/s  (+11.13%, n=336/1009)
    3000 × -10.5   12.62 →  13.83 g/s  (+9.57%, n=740/711)
    2600 × -10.5   11.24 →  12.16 g/s  (+8.13%, n=627/611)

  Top VE LOSSES:
    1600 ×  -9.5    9.90 →   8.76 g/s  (-11.52%, n=62/2307)
    1900 ×  -8.5   14.72 →  13.89 g/s  (-5.62%, n=94/100)
    1900 × -10.0    9.92 →   9.52 g/s  (-4.09%, n=135/144)
    2600 ×  -3.5   41.43 →  39.90 g/s  (-3.69%, n=180/352)
    3000 ×  -3.5   44.03 →  45.37 g/s  (+3.03%, n=950/379)
    3700 ×  +0.5   75.12 →  77.42 g/s  (+3.05%, n=302/774)
    3000 ×  -9.0   19.75 →  20.36 g/s  (+3.10%, n=1836/1634)
     800 × -10.0    3.97 →   4.10 g/s  (+3.11%, n=3235/19999)
    3300 × -11.5    9.08 →   9.37 g/s  (+3.12%, n=3415/2505)
    3000 ×  -1.5   50.46 →  52.08 g/s  (+3.20%, n=664/500)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.13: cells= 57  mean|c|= 1.12%  median|c|= 1.25%  in_tol= 91.2%  max= 2.6%
              20.14: cells= 61  mean|c|= 0.66%  median|c|= 0.74%  in_tol= 95.1%  max= 2.6%
    verdict: WIN — VE up + trim tighter

## VE proxy: 20.15 vs 20.14
  cells with data — 20.14: 313, 20.15: 272
  overlap (≥30 samples in each): 177
  cells with |Δ| ≥ 3%: 144

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.14 → 20.15):
    4000 × -12.0   11.56 →  11.98 g/s  (+3.65%, n=185/71)
    2200 ×  +1.5   48.80 →  47.29 g/s  (-3.09%, n=30/251)
    1900 ×  -6.5   18.92 →  18.31 g/s  (-3.24%, n=45/159)
    2600 ×  -4.0   38.96 →  37.66 g/s  (-3.34%, n=439/265)
    2600 ×  -4.5   37.32 →  36.05 g/s  (-3.40%, n=403/388)
    3000 ×  -6.5   31.18 →  30.12 g/s  (-3.41%, n=559/658)
    3700 ×  -4.0   51.59 →  49.80 g/s  (-3.46%, n=3240/995)
    3000 ×  -1.0   54.28 →  52.33 g/s  (-3.60%, n=394/856)
    3000 ×  -4.5   40.98 →  39.47 g/s  (-3.69%, n=572/1260)
     800 ×  -9.5    4.34 →   4.18 g/s  (-3.70%, n=14133/4590)

  Top VE LOSSES:
     800 ×  -7.5    8.11 →   5.56 g/s  (-31.44%, n=55/412)
     800 ×  -8.0    7.89 →   5.73 g/s  (-27.37%, n=52/3016)
    1200 ×  -7.0   14.21 →  11.39 g/s  (-19.79%, n=36/112)
    3300 × -11.0   11.92 →   9.57 g/s  (-19.70%, n=164/1318)
     800 ×  -8.5    6.87 →   5.53 g/s  (-19.47%, n=158/1295)
    1200 ×  -7.5   12.96 →  10.73 g/s  (-17.20%, n=57/227)
    3000 × -11.0   10.94 →   9.09 g/s  (-16.94%, n=430/5522)
    3300 × -12.0    9.29 →   7.74 g/s  (-16.65%, n=1554/39)
    2600 × -11.0    9.87 →   8.24 g/s  (-16.52%, n=917/6882)
    2200 × -11.5    7.70 →   6.48 g/s  (-15.76%, n=2178/340)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.14: cells= 61  mean|c|= 0.66%  median|c|= 0.74%  in_tol= 95.1%  max= 2.6%
              20.15: cells= 60  mean|c|= 0.81%  median|c|= 1.07%  in_tol= 80.0%  max= 3.2%
    verdict: LOSS — VE down + trim worse

## VE proxy: 20.16 vs 20.15
  cells with data — 20.15: 272, 20.16: 163
  overlap (≥30 samples in each): 101
  cells with |Δ| ≥ 3%: 49

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.15 → 20.16):
    1200 ×  -8.5    8.48 →   9.92 g/s  (+17.00%, n=514/211)
     800 ×  -7.5    5.56 →   6.44 g/s  (+15.77%, n=412/386)
    1200 ×  -9.0    7.33 →   8.31 g/s  (+13.34%, n=2528/333)
    1200 ×  -9.5    6.57 →   7.35 g/s  (+11.89%, n=2302/984)
    2200 ×  -5.0   27.33 →  30.58 g/s  (+11.88%, n=229/61)
    2200 ×  -4.5   30.02 →  33.53 g/s  (+11.71%, n=260/45)
     800 ×  -8.0    5.73 →   6.38 g/s  (+11.38%, n=3016/705)
    1200 ×  -8.0    9.54 →  10.60 g/s  (+11.04%, n=355/118)
    3300 × -11.0    9.57 →  10.36 g/s  (+8.20%, n=1318/30)
     800 ×  -8.5    5.53 →   5.97 g/s  (+7.87%, n=1295/158)

  Top VE LOSSES:
    2600 × -11.5    7.64 →   6.83 g/s  (-10.58%, n=560/100)
    3000 × -11.5    8.86 →   8.26 g/s  (-6.77%, n=2881/188)
    1600 ×  -8.0   12.10 →  11.35 g/s  (-6.20%, n=489/137)
    2600 × -10.0   12.95 →  12.29 g/s  (-5.11%, n=632/216)
    3000 × -10.5   11.94 →  11.49 g/s  (-3.80%, n=1201/105)
    1900 ×  -9.5   10.71 →  10.33 g/s  (-3.58%, n=376/48)
    2600 ×  -7.0   24.58 →  23.71 g/s  (-3.56%, n=386/319)
    3000 ×  -7.5   25.48 →  26.33 g/s  (+3.34%, n=905/343)
    1900 × -11.0    7.08 →   7.31 g/s  (+3.37%, n=746/359)
    1900 ×  -6.0   19.31 →  19.97 g/s  (+3.41%, n=163/50)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.15: cells= 60  mean|c|= 0.81%  median|c|= 1.07%  in_tol= 80.0%  max= 3.2%
              20.16: cells= 43  mean|c|= 1.79%  median|c|= 1.69%  in_tol= 69.8%  max= 4.5%
    verdict: MIXED — VE up but trim looser (suspect MAF over-scale)


## 2026-05-30 — log: 5-30 20.16/log0001.csv — rom: 20.16 — **CATASTROPHIC −11.8° KNOCK + IDC SATURATION; ANCHOR/BUILD MISMATCH FLAGGED**

48.8 min, 67,872 samples @ 25 Hz, 35 cols.

**ROM fingerprint — CRITICAL DRIFT:** Current 20.16.bin md5 = `b8bd7091b918ab16820eb05dd7aebf7e` (mtime 2026-05-30 14:16:45 UTC). Anchor was `9e47549801946d8ada6c4a6e562f49f4`. **Dean re-flashed 20.16 today.** Re-ran binary diff vs 20.15:

- **Target Boost (0xC1340): RAISED at 16 cells.** Anchor said "UNCHANGED." Actual deltas +1.99 to +8.01 psi. Headline cells: +7.00, +7.50, +8.01 psi. This is the dominant change in the new build.
- **Initial WGDC (0xC1150): LOWERED at 2 cells.** 70.20%→67.01% and 66.95%→63.96% (Δ ≈ −3 pts each). Anchor said "raised to ~67% at WOT column" — current build has the lower values, not the raise.
- **Base Timing × 4 tables (all identical):** 5 small runs each, much smaller pyramid than anchor described.
- **Sport + Sport Sharp + Intelligent pedal maps:** all 3 updated identically (12-cell Sport diff shown earlier, repeated in Sharp/Intel).
- **MAF Sensor Scaling: UNCHANGED** (matches anchor — only thing that does).
- 185 bytes / 81 runs total.

The active build is DIFFERENT from what the anchor described. Treat all anchor-cited 20.16 claims as stale; this entry reflects the build actually flashed today.

**Drive shape:** mostly partial-throttle cruise with a few aggressive tip-ins. 78% CL=8, 20% OL=10, 1.6% warm-up. Peak MAF V 4.34 (well under 4.8). Throttle≥95% sustained ≥1 s: 0 qualifying pulls. 9 APP-based pull ramps detected; two were ramps the driver shoved to TPS=100% briefly but never sustained.

**HEADLINE EVENT #1 — Sample 67380–67429 (t=2923.4–2925.3 s): FBKC ratchet to −11.80°.**
Tip-in from coast into spool. At first knock onset (s67380): RPM 2627 × **load 1.045 g/rev** × mrp 2.71 psi (climbing, target 3.6) × Throttle 25.88% × APP 23.14% × Timing 16° × **AVCS 19-20°** × wgdc pegged 74.9 × wbo2 13.37 / FFB 12.35 (engine 1.0 AFR RICHER than commanded after lag — **not a lean failure**). FBKC ratchets in 9 samples (0.36 s): −1.4, −2.8, −4.2, −5.6, −7.0, −8.4, −9.8, −11.2, −11.8. Held at −11.8 for ~2 s. Driver lifted; re-attempted same spool 0.5 s later (s67442); cell fired again at −1.4. **IAM stayed 1.0, FLKC stayed 0** — no learning damage, but the FBKC budget got fully spent twice on the same operating cell within 1.5 s.

The first-knock cell (2627, 1.045) sits squarely in the **2200-3300 × 1.0-1.4 ghost zone** that's persisted across 6+ revs. The 20.16 base-timing pull at 2600-3300 × L=1.67-2.37 **does not cover this cell** (load axis lower than pull region). Mechanism candidates: AVCS plateau at 19-20° + raised Target Boost driving harder spool into the cell + un-pulled timing.

**HEADLINE EVENT #2 — Sample 26357 (t=1070.9 s): IDC saturated at 101.86%.**
At PARTIAL THROTTLE (TPS 54.51%, APP 53.73%), RPM 4923 × load 3.81 × mrp 17.68 psi (target 17.90 → attainment 0.99). IPW 24.83 ms at 4923 RPM = injector duty cycle physically ≥100%. wbo2 10.46 / FFB 11.10 → engine 0.6 AFR richer than commanded. 3 samples ≥100% IDC, 49 samples ≥85% IDC. The 20.16 Target Boost raises plus the existing OL fueling tables are demanding more fuel than the injectors can deliver at this duty cycle. **Injector swap (already on the horizon per `project_injector_upgrade.md`) is no longer optional under the 20.16 boost targets.**

**Knock summary:**
- FBKC<0 samples: 411 across 11 clusters / 36 deepening events / FBKC min −11.80
- FLKC stayed at 0 throughout (no learned ratchet)
- IAM stayed at 1.0 throughout (no learned timing damage)
- Top clusters: s67380-67429 (n=104, RPM 2298-2668, the −11.8 event), s37658-37761 (n=104, similar zone, FBKC min −11.2), s37269-37314 (n=46, −4.2), s37347-37385 (n=39, −7.0)

**Ghost-zone (2200-3300 × 1.0-1.4) FBKC<0 rate (apples-to-apples, samp/zone-min):**
- 20.13 5-22: 22.2
- 20.14 5-23 L3: 14.1
- 20.15 5-28: 24.2
- **20.16 5-30: 156.0** — 6.4× worse than 20.15. Even excluding the −11.8 cluster, the remainder of the ghost-zone samples still puts the rate at ~50/min — 2× the 20.15 baseline.

**AFL drift — HOLDING, not deepening.** CL filter (CL=8, FFB≤14.7, |corr|<25, APP>2): n=23,865.
- AFL median: **−2.34** (identical to 5-28)
- AFL mean:  −1.46 (improved from 5-28 −1.85)
- >|2%|: 53.5% (was 56.5%)
- AFC mean: −0.37 (clean, not clamping)
- AFL by MAF V band: AFL=−2.34 floor at V=1.6–2.0 (light cruise), then AFL=0 at V≥2.1 — same shape as 5-28; not deepening but not reverting. ROM didn't touch MAF Scaling, so this is unchanged sensor/injector/fuel-pressure drift — consistent with the hypothesis space in `project_afl_drift_5_28.md`.

**Tip-in lean spikes (strict detector, n=60 in this log):**
- Overall mean lean: +3.83 AFR (vs 5-28 +2.35, +63% regression direction)
- <1500 RPM: +4.11 (vs 5-28 +3.12)
- 1500-2000 RPM: +3.37 (vs 5-28 +2.99) — still better than 20.14 L3 +4.73
- 2000-2500 RPM: +3.60 (vs 5-28 +2.52)
- **Caveat: n=60 vs 5-28 n=1816** — small sample. Direction is concerning but not statistically locked. The 20.16 pedal map raised APP=16.5% column (+0.24 to +0.98%), which would deliver MORE air sooner during a tip-in — that mechanism is consistent with bigger lean spikes if accel-enrichment can't keep up. Worth a focused tip-in log next session.

**AVCS swing in 28-36 MPH × APP≤20:**
- Inband samples: 9,202 (6.13 min)
- AVCS swings (rolling 1 s, max−min ≥10°, std(RPM)<50, std(load)<0.05): 380 samples → **2.48 clu/min**
- vs 5-2 (20.10): 5.84, 5-11 (20.11): 5.60 — **down**. The 20.16 build is calmer in this band.

**WOT pulls:** 0 qualifying (Throttle≥95% sustained ≥1 s with peak mrp ≥7). 9 partial-throttle ramps with peak mrp 6-19 psi; best attainment 1.08 (s33654, 3rd-gear partial). Boost in-boost median attainment 0.857, mean 0.711 — undertarget. New higher Target Boost in 20.16 isn't being reached; the turbo isn't natural-flow-capable at the new targets in the operating-points logged.

**FLKC zone (3000 × 2.13) targeted by 20.16 base-timing pull:** only 101 samples landed inside the pulled box (2600-3300 × 1.67-2.37) — engine never made the load to test it. Cannot score the pull from this log.

**MAF V peak:** 4.34 V — well under 4.8 bar.
**IAM:** 1.0 throughout — no learned timing damage.

**Prior-flagged areas re-checked:**
- **Ghost-zone knock 2200-3300 × 1.0-1.4:** **MAJOR REGRESSION.** 156 samp/min vs 20.15's 24.2. Driven by Target Boost raise causing harder spool into un-protected ghost zone cells.
- **AFL drift:** **STEADY** at −2.34 median. Not deepening, not reverting. Open.
- **20.15 tip-in fix:** **PROVISIONAL REGRESSION** (+3.83 vs +2.35), but n=60 is too small. Re-log needed.
- **FLKC 3400-3800 × high-load (5-28 ratched to −1.75):** **NOT RE-OBSERVED** in this log (9 FBKC<0 in the box, no FLKC). Either zone wasn't visited under conditions to trigger or the 20.16 timing pull helped; can't separate.
- **AVCS 28-36 MPH cruise band:** **IMPROVED.** 2.48 clu/min vs 5.6-5.8 prior.

**New issues / surfaced:**
- **(P0) Ghost-zone regression severe enough to risk IAM ratchet.** Two −11.x knock events in the same log. If next drive repeats the partial-throttle spool through 2627×1.05, FLKC will start ratcheting. Action candidates: extend 20.16 base-timing pull DOWN to L=1.0-1.2 at R=2400-3000, OR pull AVCS back from 20° plateau at the same cell, OR drop Target Boost back at the cells driving harder spool into the ghost zone. Need to pick one to attribute.
- **(P0) Injector saturation at partial-throttle high-boost OL.** IDC>100% at TPS 54% × RPM 4923. The 20.16 boost raise pushes existing injectors past their physical limit. Injector swap is now blocking further boost work; alternatively, OL fueling target leaned out at this cell to reduce IPW demand.

**Staged for next session:**
- Re-flash decision needed: roll Target Boost back to 20.15 at the ghost-zone-feeding cells, OR pull timing at L=1.0-1.2 × R=2400-3000 in next build, OR leave 20.16 alone and gather more data to see if knock reproduces.
- Update `current_rev_anchor.md` to reflect ACTUAL 20.16 build (b8bd7091, not 9e475498). Anchor's "Target Boost UNCHANGED" / "Initial WGDC raised" claims are wrong for the current build.
- One more 20.16 log to confirm AFL drift status (drift is steady, not deepening — close to acting on MAF investigation if it holds 2 more logs).
- Targeted tip-in log on 20.16 — Dean does deliberate small APP rises across 1000-3000 RPM band, 30+ events min, so lean-spike regression can be confirmed/refuted at n≥200.

---

## 2026-05-28 — log: 5-28 20.15/log0001.csv — rom: 20.15 — TIP-IN FIX PARTIAL CONFIRM; AFL drift + transient FLKC -1.75 flagged

164.2 min, 246,366 samples @ 25 Hz, 35 cols. ROM bin md5 `55f28ef9d7c22344a79b3f20a9994f5e` (unchanged from 5-24 — same 20.15 build that produced 5-25 and 5-26 logs). This is the 3rd 20.15 log and the biggest by far.

**Drive shape:** Heavily cruise-weighted — 73% of warm samples in 2500-3500 RPM band, only 71 in-boost samples (mrp>5 with throttle>50), Throttle>95% for 12 samples total (0.5 s), peak MAF V=4.0, peak IDC 77.2%. No qualifying WOT pulls.

**AVCS sanity (post-reflash lockout check):** PASS — overall p95=21°, max=30°, 2000-3500 band median=19°, p95=21°. Cam working.

**Baseline-sweep health bars:**
- AFL: median **-2.34%**, mean -1.85%, 56.5% of CL samples outside ±2% (acceptable but at the edge of the ±5% ideal-window margin). **Drift trend:** AFL median has walked 0 → 0 → -1.07 → **-2.34** across 5-22 (20.13) / 5-23 L1 (20.14) / 5-23 L3 (20.14) / 5-28 (20.15). Monotonic and now sitting outside the ±2% ideal band. Convention reminder: AFL negative = ECU has learned engine runs rich and is pulling fuel via long-term trim. Consistent with MAF over-reading at the V-range exercised by this drive (V=1.5-3.0 cruise).
- AFC: mean +1.18%, clamp <0.05%. Clean.
- IDC: peak 77.2%, p99 29.7% — under the 85% bar.
- MAF V: peak 4.0 V, no samples >4.8 V — under the bar (and no WOT to exercise high-V region).
- Boost: only 71 samples in boost. p05 mrp-target delta -8.64 (target running ahead in low-spool transitions). Can't draw conclusions on boost control from this log.

**Knock:** 1153 FBKC<0 samples / 32 deepening events / FBKC min -7.00. FLKC traveled **down to -1.75** (deeper than any prior 20.15 log; deeper than 5-23 20.14 L3's -1.0 latch), then recovered to 0 by end of log. Time at FLKC<0: 11.3 s (vs 5-23 L3's 42.7 s, vs 5-26's 0 s). Less persistent but more intense single excursion.

  Top knock cells (FBKC<0 sample count):
  - (2500, 1.19): 154
  - (3250, 1.19): 143
  - (3250, 1.02): 114
  - (2750, 1.19): 102
  All squarely inside the **2200-3300 × 1.0-1.4 ghost zone**.

  **Ghost-zone knock rate (apples-to-apples, FBKC<0 samples per zone-minute):**
  - 20.13 5-22: 22.2 samp/min
  - 20.14 5-23 L3: 14.1 samp/min
  - 20.15 5-28: 24.2 samp/min
  Ghost zone is alive and active on 20.15. Not regressed vs 20.13 baseline; not improved vs 20.14.

  **FLKC walk events (all OL, 3400-3800 RPM × load 2.0-3.1 × mrp 7-18 psi — the "high-RPM mid-load OL" open-issue cluster):**
  - s=182165 (R3426 × L=3.07 × 17.97 psi): instant -1.0 ratchet (large single step, unusual)
  - s=186771-186778 (R3386-3413 × L=2.5-2.7): standard 0→-0.75 ratchet
  - s=196044-196051 (R3400-3429 × L=2.0-2.2): standard 0→-0.75
  - s=199983-199993 (R3407-3415 × L=2.99-3.11 × 17.4 psi): **walked to -1.75 (biggest)**
  - s=222902-223017 (R3404-3565 × L=2.6-2.9): walked to -1.5
  - s=223047-223050: brief +1.25/-1.25 spike-recover
  20.15 didn't touch base timing or boost in this zone (only tip-in fueling), so the persistence is expected.

**Tip-in lean-spike (strict detector — CL/OL=7 excluded, fuel-cut excluded, wbo2 saturation gated):**

| RPM band | 20.14 5-23 L3 (n=1703) | 20.15 5-26 (n=122) | 20.15 5-28 (n=1816) |
|---|---|---|---|
| <1500 | +3.39 | +3.08 | +3.12 |
| 1500-2000 | +4.73 | +2.06 | **+2.99** (−37% vs L3) |
| 2000-2500 | +2.84 | +2.64 | +2.52 (−11%) |
| 2500-3000 | +2.54 | +1.28 (n=4) | **+2.06** (−19%) |
| 3000-3500 | +2.35 | +2.12 (n=3) | +2.06 (−12%) |
| 3500+ | +2.21 | — | +3.00 (n=25 — small) |
| OVERALL | +2.85 | +2.55 | **+2.35** (−18%) |

Note: prior 5-26 review compared bands with a stricter (now-irreproducible) detector that produced n=38 / +2.21 overall. Under a uniform same-code rerun applied to all three logs, 20.14 L3 lands at +2.85 overall (not +2.57 quoted in memory), 5-26 at +2.55, and 5-28 at +2.35. The improvement direction holds — 20.15 is better than 20.14 baseline in 1500-3500 RPM bands — but the magnitude is closer to **18% overall** than the 40-50% the 5-26 single-log suggested. The 5-26 numbers were small-sample optimism.

**<1500 band shows no meaningful improvement** on 5-28 (n=246, +3.12 vs L3 n=316, +3.39). The 20.15 changeset's APP-gate at 0.85% may still be above the tiniest tip-in deltas at very low RPM, or the BE-axis isn't active at idle-region loads. Worth a future look.

**Worst lean spikes are detector artifacts:** Top 5 spikes on 5-28 (8.7-14.4 lean) are all wbo2-transport-lag artifacts at coast→tip-in transitions where wbo2 was still saturated lean (>17 AFR) from prior DFCO/idle when the tip-in fired. The 8-sample lag-shift isn't enough at <1500 RPM where exhaust transport is slower. Detector enhancement deferred (gate on pre-tipin wbo2 saturation).

**MAF correction by V band (re-check of 5-12 mid-V slope walk):** 5-12 had a monotonic negative drift at V=1.91-2.45. **Does NOT cleanly reproduce on 5-28.** Pattern is now:
- V=1.55-1.65 cluster: median -2.34% (small but offset)
- V=1.80-1.85 cluster: median -2.34/-1.56% (n=4345/3847, real)
- V=1.90-2.10: median 0 to +0.78% (slightly positive — opposite of 5-12)
- V=2.15-2.90: median 0 to -0.78%
No basis for a mid-V refit on this evidence. The AFL whole-log drift is the cleaner signal.

**Stutter quick check (28-36 MPH × APP≤20, 1s AVCS swing ≥10°, std(RPM)<50, std(load)<0.05):** 607 windows in 8.37 in-band minutes = 72.5/min. Vastly higher than 5-11's 5.60/min under the same SOP. Worth a careful look but I want to re-verify the methodology against the 5-11 detector code before raising it as a regression — could be a noise difference between the two implementations.

**Prior-flagged areas re-checked:**
- AVCS post-reflash lockout: PASSED (cam healthy whole log).
- 20.15 tip-in fix: PARTIALLY CONFIRMED. 18% overall reduction vs L3 holds at n=1816. Strongest in 1500-2000 (-37%). No real improvement <1500 RPM.
- Ghost-zone knock (2200-3300 × 1.0-1.4): UNCHANGED — 24.2 samp/min vs 20.13 baseline 22.2.
- High-RPM mid-load OL FLKC cluster (3400-3800 × 2.0-3.1): ACTIVE — went to -1.75 transiently. 20.15 didn't address this zone; persistence expected.

**New observations:**
- **AFL monotonic drift toward -2.34% median across 20.13→20.14→20.15.** Long-term trim is increasingly pulling fuel — engine learned-rich. Direction: MAF over-read in cruise V-range, OR injector-flow drift, OR fuel-pressure drift. Watch on next log; if it continues, candidate for action.
- 5-12 V=1.91-2.45 monotonic slope walk did NOT reproduce. Pattern now scattered, not monotonic.

**Staged for next session:**
- Resolve stutter-detector methodology (72.5/min vs historical 5.6/min suggests measurement difference, not 13× regression). Pin the exact filter & re-baseline.
- One more substantial drive on 20.15 to lock in tip-in improvement (now n=1953 across 5-26+5-28 — call it confirmed at -18% overall if the next log holds).
- Decide on AFL drift: re-measure next log; if median stays ≤-2.0%, plan a MAF mid-V investigation against WB residuals (Josh F exp fit per `feedback_maf_no_cellwise_patches.md`).
- 20.15 still has no high-load OL action — FLKC excursion to -1.75 in 5-28 reinforces that the 4000-4400 × L≥1.5 cluster is open. Next ROM iteration candidate.

---

## 2026-05-26 — log: 5-26 20.15/log0001.csv — rom: 20.15 — TIP-IN FIX VALID (single log, n=38)

26.3 min drive across 4 chunks, 39,510 samples at 25 Hz. Mostly 1800-2300 RPM around-town. Bin md5 `55f28ef9d7c22344a79b3f20a9994f5e`, mtime 2026-05-24 02:10:13 UTC.

**AVCS sanity (post-reflash lockout check):** PASSED — warm p95=20°, max=28°, median 18° in 2000-3500 RPM band. The 5-25 lockout cleared with restart. Log is valid for scoring.

**Tip-in lean-spike comparison (peak `wbo2 − FFB` first 1 s post-tipin, 320 ms lag-corrected, fuel-cut filtered):**

| RPM band | 20.14 5-23 L1 (n=35) | 20.14 5-23 L3 (n=463) | 20.15 5-26 (n=38) |
|---|---|---|---|
| <1500 | +4.38 | +4.51 | **+2.73** (−40% vs L3) |
| 1500-2000 | +2.75 | +3.83 | **+1.86** (−51% vs L3) |
| 2000-2500 | +2.08 | +2.40 | **+1.82** |
| 2500-3000 | +0.49 | +2.23 | **+1.51** |
| 3000-3500 | +0.78 (n=1) | +2.16 | +3.11 (n=2) |
| OVERALL | +3.22 | +2.57 | **+2.21** |

20.15 changeset (accel-enrich throttle gate 2.0→0.85%, IPW gate 1.32→1.0 ms, applied counter 3→5, BE axis 0→6.7253 psi) is doing what it was designed to do. Biggest wins in the bands that historically had the worst spikes.

**Knock at tip-in:** 2/38 events (5.3%), comparable to 20.14 L1 (8.6%) and L3 (3.5%). No regression.
- s=19038: FBKC −1.4 on low-RPM 798→1637 tip-in, mrp stayed in vacuum — ghost-zone signature, not tip-in fueling.
- s=25854: FBKC −2.8 at boost-crossing moment (mrp first +0 at s=25901, BE=−5.88 psi). Spool-up knock, not tip-in.

**Worst lean spike:** +5.51 at s=21006 (RPM 690.75, OL state). KNOCK_FLAG ×3 but FBKC=0. Very-low-RPM corner — possibly below the new gate window. Worth eyeballing if Dean cares.

**IPW step in 400 ms post-tipin:** median 1.54 ms on 20.15 vs 2.05 ms on 20.14 L3 — smaller bump, longer apply, smoother delivery. Consistent with design intent.

**Prior-flagged areas re-checked:**
- AVCS post-reflash lockout: resolved by restart, log valid.
- Tip-in lean spike: improved across all bands with sufficient n.

**New issues:** None opened. 3000-3500 band (n=2) and very-low-RPM corner (n=1 at +5.51 spike) under-sampled.

**Staged for next session:**
- 1-2 more mixed 20.15 logs to confirm lean-spike improvement at n>100.
- Full SOP review on next 20.15 log (knock, MAF corr, cliffs, stutter, VE, WOT) — Dean called this thread short, full diag is next thread.

---

## 2026-05-25 — log: 5-25 20.15/log0001.csv — rom: 20.15 — DATA INVALID (AVCS LOCKOUT)

12.05 min, 12893 samples, 17.83 Hz. Drive shape: stop-and-go around-town with a mid-drive gas-station stop. **Post-reflash AVCS lockout active for the whole drive** — known intermittent quirk that a restart clears (see new memory `project_avcs_post_reflash_lockout.md`).

**AVCS lockout evidence:**
- Whole-log AVCS p95 = 7°, max = 11° (vs 22° / 31° on the 20.14 5-23 baseline)
- RPM 2000-3500 band: AVCS median 5-6° (working: ~19°)
- WOT pull at 4304 RPM: AVCS max 8° (working: 22-25°)
- 99.9% of samples at AVCS ≤ 10°

**Verdict: log is unusable for 20.15 gate scoring.** Knock metrics, fueling metrics, stutter signatures, and lean-event magnitudes are all contaminated because the cam was in the wrong place. Pre-drive gate readings (G1 marginal, G2 fail, G4 pass strong, G5 mixed) are not meaningful — discarded.

**What survives the contamination:**
- G3 BE-coverage shift (85.7% of events at BE ≥ 5 psi vs target >40%) — pure ROM-byte check, axis compression is in the bin and operating as designed.

**Lesson saved as memory:** `project_avcs_post_reflash_lockout.md` — on any first log after a fresh reflash, sanity-check AVCS p95 across the drive before scoring anything else. If p95 < 12°, treat as locked out and ask Dean to restart and re-drive.

**Required next step:** Dean restarts the car (clears AVCS lockout), drives a normal 30-60 min mixed log. Re-run gate scoring on that.

---

## ingest 2026-05-23 (rev 20.14) auto-rollup (2026-05-23 19:46)

## VE proxy: 20.14 vs 20.13
  cells with data — 20.13: 280, 20.14: 313
  overlap (≥30 samples in each): 160
  cells with |Δ| ≥ 3%: 77

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.13 → 20.14):
    1900 × -11.5    5.69 →   7.37 g/s  (+29.68%, n=113/271)
    1200 ×  -9.5    5.57 →   7.13 g/s  (+27.97%, n=298/2775)
     800 ×  -9.0    4.67 →   5.65 g/s  (+20.92%, n=80/309)
    3000 × -11.0    9.38 →  10.94 g/s  (+16.64%, n=1866/430)
    2600 × -11.0    8.54 →   9.87 g/s  (+15.52%, n=2034/917)
    3300 × -11.0   10.42 →  11.92 g/s  (+14.41%, n=404/164)
    2200 × -11.0    7.84 →   8.77 g/s  (+11.88%, n=713/799)
    2600 × -10.0   13.17 →  14.64 g/s  (+11.13%, n=336/1009)
    3000 × -10.5   12.62 →  13.83 g/s  (+9.57%, n=740/711)
    2600 × -10.5   11.24 →  12.16 g/s  (+8.13%, n=627/611)

  Top VE LOSSES:
    1600 ×  -9.5    9.90 →   8.76 g/s  (-11.52%, n=62/2307)
    1900 ×  -8.5   14.72 →  13.89 g/s  (-5.62%, n=94/100)
    1900 × -10.0    9.92 →   9.52 g/s  (-4.09%, n=135/144)
    2600 ×  -3.5   41.43 →  39.90 g/s  (-3.69%, n=180/352)
    3000 ×  -3.5   44.03 →  45.37 g/s  (+3.03%, n=950/379)
    3700 ×  +0.5   75.12 →  77.42 g/s  (+3.05%, n=302/774)
    3000 ×  -9.0   19.75 →  20.36 g/s  (+3.10%, n=1836/1634)
     800 × -10.0    3.97 →   4.10 g/s  (+3.11%, n=3235/19999)
    3300 × -11.5    9.08 →   9.37 g/s  (+3.12%, n=3415/2505)
    3000 ×  -1.5   50.46 →  52.08 g/s  (+3.20%, n=664/500)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.13: cells= 57  mean|c|= 1.12%  median|c|= 1.25%  in_tol= 91.2%  max= 2.6%
              20.14: cells= 61  mean|c|= 0.66%  median|c|= 0.74%  in_tol= 95.1%  max= 2.6%
    verdict: WIN — VE up + trim tighter


## auto-generated rev rollup (2026-05-23 09:12)

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
  cells with data — 20.10: 200, 20.11: 185
  overlap (≥30 samples in each): 113
  cells with |Δ| ≥ 3%: 37

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.10 → 20.11):
    1200 ×  -7.0   12.03 →  13.42 g/s  (+11.56%, n=98/31)
    3300 ×  -8.5   22.57 →  24.34 g/s  (+7.86%, n=271/449)
    2200 × -10.5    8.44 →   9.00 g/s  (+6.61%, n=891/1214)
    1900 × -10.0    8.88 →   9.36 g/s  (+5.34%, n=198/207)
    2600 ×  -0.5   48.01 →  50.45 g/s  (+5.08%, n=270/34)
    3300 ×  -8.0   25.93 →  27.16 g/s  (+4.74%, n=98/449)
    2200 ×  -9.5   12.70 →  13.21 g/s  (+4.03%, n=859/765)
    3300 ×  -7.5   28.63 →  29.70 g/s  (+3.72%, n=123/585)
    3000 ×  -5.5   34.31 →  35.53 g/s  (+3.56%, n=481/243)
    2200 ×  -2.0   40.49 →  39.21 g/s  (-3.15%, n=378/350)

  Top VE LOSSES:
    1200 ×  -8.5    8.55 →   7.22 g/s  (-15.56%, n=811/299)
    1200 × -10.5    5.94 →   5.40 g/s  (-9.18%, n=66/173)
    3300 × -11.0   10.79 →   9.83 g/s  (-8.88%, n=304/420)
    1900 ×  -5.0   24.22 →  22.42 g/s  (-7.44%, n=178/288)
     800 × -10.0    4.07 →   3.78 g/s  (-7.11%, n=87/389)
    3300 ×  -5.0   44.06 →  41.07 g/s  (-6.78%, n=79/209)
    1900 ×  -4.5   25.80 →  24.12 g/s  (-6.48%, n=212/47)
     800 ×  -8.0    6.05 →   5.69 g/s  (-6.06%, n=30/45)
    3300 × -10.0   17.39 →  16.42 g/s  (-5.57%, n=97/191)
     800 ×  -8.5    5.73 →   5.44 g/s  (-5.20%, n=245/308)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.10: cells= 52  mean|c|= 1.92%  median|c|= 1.93%  in_tol= 50.0%  max= 6.0%
              20.11: cells= 52  mean|c|= 1.42%  median|c|= 1.28%  in_tol= 84.6%  max= 3.7%
    verdict: MIXED — VE down but trim tighter (correcting prior over-scale?)

## VE proxy: 20.12 vs 20.11
  cells with data — 20.11: 185, 20.12: 299
  overlap (≥30 samples in each): 126
  cells with |Δ| ≥ 3%: 47

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.11 → 20.12):
    1600 × -10.0    7.10 →   8.11 g/s  (+14.36%, n=223/387)
    1900 ×  -9.5   10.18 →  11.46 g/s  (+12.53%, n=215/364)
    1600 ×  -9.5    8.35 →   9.27 g/s  (+11.06%, n=265/2157)
     800 ×  -9.0    4.63 →   4.96 g/s  (+7.01%, n=1096/1298)
    2600 × -10.5   10.00 →  10.69 g/s  (+6.85%, n=492/1344)
    1600 ×  -8.5   10.94 →  11.67 g/s  (+6.67%, n=528/548)
    1900 ×  -8.5   13.12 →  13.92 g/s  (+6.11%, n=523/496)
    1900 ×  -9.0   11.68 →  12.39 g/s  (+6.05%, n=217/312)
    2600 × -10.0   12.09 →  12.82 g/s  (+6.02%, n=242/882)
    3000 × -10.5   11.57 →  12.23 g/s  (+5.70%, n=413/947)

  Top VE LOSSES:
    3700 × -12.0    9.98 →   8.46 g/s  (-15.20%, n=115/90)
    3700 ×  -8.5   29.30 →  26.47 g/s  (-9.65%, n=272/456)
    3700 ×  -9.0   25.87 →  23.56 g/s  (-8.93%, n=106/571)
    1200 ×  -7.0   13.42 →  12.47 g/s  (-7.06%, n=31/57)
    1200 ×  -8.5    7.22 →   6.78 g/s  (-6.18%, n=299/50)
    3300 ×  -9.5   19.84 →  18.63 g/s  (-6.11%, n=433/2323)
    3700 ×  -7.5   35.24 →  33.30 g/s  (-5.52%, n=222/780)
    3300 × -10.5   14.46 →  13.69 g/s  (-5.36%, n=219/291)
    3300 ×  -8.0   27.16 →  25.73 g/s  (-5.25%, n=449/1173)
    3700 ×  -8.0   32.13 →  30.45 g/s  (-5.23%, n=115/396)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.11: cells= 52  mean|c|= 1.42%  median|c|= 1.28%  in_tol= 84.6%  max= 3.7%
              20.12: cells= 70  mean|c|= 2.39%  median|c|= 1.88%  in_tol= 84.3%  max= 3.8%
    verdict: MIXED — VE up but trim looser (suspect MAF over-scale)

## VE proxy: 20.13 vs 20.12
  cells with data — 20.12: 299, 20.13: 280
  overlap (≥30 samples in each): 172
  cells with |Δ| ≥ 3%: 97

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.12 → 20.13):
    3700 × -11.0   12.12 →  14.33 g/s  (+18.16%, n=124/34)
    3700 × -12.0    8.46 →   9.72 g/s  (+14.88%, n=90/826)
    4000 ×  -9.5   25.91 →  29.40 g/s  (+13.50%, n=98/40)
    2200 ×  +0.0   42.92 →  47.66 g/s  (+11.04%, n=40/49)
    2200 ×  +0.5   42.87 →  47.43 g/s  (+10.63%, n=36/39)
    3700 ×  -8.5   26.47 →  29.17 g/s  (+10.18%, n=456/430)
    3700 ×  -9.0   23.56 →  25.83 g/s  (+9.64%, n=571/296)
    4000 ×  -3.0   59.72 →  64.72 g/s  (+8.37%, n=129/73)
    4000 ×  -4.0   54.65 →  59.21 g/s  (+8.35%, n=183/138)
    3300 × -11.0    9.62 →  10.42 g/s  (+8.29%, n=1982/404)

  Top VE LOSSES:
    1200 ×  -9.5    6.68 →   5.57 g/s  (-16.66%, n=5668/298)
    4000 × -12.0   12.17 →  10.97 g/s  (-9.82%, n=115/40)
     800 ×  -9.0    4.96 →   4.67 g/s  (-5.79%, n=1298/80)
    1200 × -10.0    5.86 →   5.58 g/s  (-4.75%, n=1713/1065)
    1900 ×  -9.0   12.39 →  11.82 g/s  (-4.63%, n=312/41)
    1900 ×  -9.5   11.46 →  10.93 g/s  (-4.57%, n=364/164)
    1600 × -11.0    6.52 →   6.24 g/s  (-4.34%, n=189/777)
     800 ×  -9.5    4.23 →   4.10 g/s  (-3.19%, n=22846/8149)
    3300 × -11.5    9.38 →   9.08 g/s  (-3.17%, n=2877/3415)
    3700 ×  +0.0   69.92 →  72.04 g/s  (+3.04%, n=974/280)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.12: cells= 70  mean|c|= 2.39%  median|c|= 1.88%  in_tol= 84.3%  max= 3.8%
              20.13: cells= 57  mean|c|= 1.12%  median|c|= 1.25%  in_tol= 91.2%  max= 2.6%
    verdict: WIN — VE up + trim tighter

## VE proxy: 20.14 vs 20.13
  cells with data — 20.13: 280, 20.14: 106
  overlap (≥30 samples in each): 60
  cells with |Δ| ≥ 3%: 41

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.13 → 20.14):
    1900 × -11.5    5.69 →   7.38 g/s  (+29.72%, n=113/93)
    1200 ×  -9.5    5.57 →   7.22 g/s  (+29.55%, n=298/2265)
     800 ×  -9.0    4.67 →   5.72 g/s  (+22.42%, n=80/51)
    2600 × -11.0    8.54 →  10.36 g/s  (+21.33%, n=2034/161)
    3000 × -10.5   12.62 →  14.40 g/s  (+14.04%, n=740/44)
    3000 × -10.0   15.38 →  17.38 g/s  (+13.01%, n=512/35)
    2600 × -10.0   13.17 →  14.84 g/s  (+12.69%, n=336/317)
    2200 × -11.0    7.84 →   8.71 g/s  (+11.09%, n=713/319)
    2600 × -10.5   11.24 →  12.36 g/s  (+9.91%, n=627/135)
    3300 ×  -9.5   19.52 →  21.45 g/s  (+9.89%, n=1272/122)

  Top VE LOSSES:
    1600 ×  -9.5    9.90 →   8.65 g/s  (-12.61%, n=62/2061)
    2600 ×  -5.0   34.80 →  35.90 g/s  (+3.15%, n=331/183)
    3000 ×  -5.0   37.33 →  38.55 g/s  (+3.27%, n=923/62)
    1900 × -11.0    7.14 →   7.43 g/s  (+4.05%, n=1282/393)
    3300 ×  -7.5   30.28 →  31.54 g/s  (+4.15%, n=1112/31)
    3000 ×  -6.0   33.15 →  34.53 g/s  (+4.17%, n=956/179)
    2200 ×  -7.5   19.74 →  20.58 g/s  (+4.26%, n=254/359)
    2600 ×  -9.0   17.44 →  18.20 g/s  (+4.37%, n=529/711)
    2600 ×  -7.5   23.12 →  24.14 g/s  (+4.41%, n=224/268)
    3000 ×  -8.5   21.40 →  22.35 g/s  (+4.44%, n=1818/123)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.13: cells= 57  mean|c|= 1.12%  median|c|= 1.25%  in_tol= 91.2%  max= 2.6%
              20.14: cells= 35  mean|c|= 1.90%  median|c|= 1.75%  in_tol= 60.0%  max= 3.5%
    verdict: MIXED — VE up but trim looser (suspect MAF over-scale)


## ingest 2026-05-12 (rev 20.11) auto-rollup (2026-05-13 00:03)

## VE proxy: 20.11 vs 20.10
  cells with data — 20.10: 200, 20.11: 185
  overlap (≥30 samples in each): 113
  cells with |Δ| ≥ 3%: 37

  Top VE GAINS (rpm × mrp psi → MAF g/s 20.10 → 20.11):
    1200 ×  -7.0   12.03 →  13.42 g/s  (+11.56%, n=98/31)
    3300 ×  -8.5   22.57 →  24.34 g/s  (+7.86%, n=271/449)
    2200 × -10.5    8.44 →   9.00 g/s  (+6.61%, n=891/1214)
    1900 × -10.0    8.88 →   9.36 g/s  (+5.34%, n=198/207)
    2600 ×  -0.5   48.01 →  50.45 g/s  (+5.08%, n=270/34)
    3300 ×  -8.0   25.93 →  27.16 g/s  (+4.74%, n=98/449)
    2200 ×  -9.5   12.70 →  13.21 g/s  (+4.03%, n=859/765)
    3300 ×  -7.5   28.63 →  29.70 g/s  (+3.72%, n=123/585)
    3000 ×  -5.5   34.31 →  35.53 g/s  (+3.56%, n=481/243)
    2200 ×  -2.0   40.49 →  39.21 g/s  (-3.15%, n=378/350)

  Top VE LOSSES:
    1200 ×  -8.5    8.55 →   7.22 g/s  (-15.56%, n=811/299)
    1200 × -10.5    5.94 →   5.40 g/s  (-9.18%, n=66/173)
    3300 × -11.0   10.79 →   9.83 g/s  (-8.88%, n=304/420)
    1900 ×  -5.0   24.22 →  22.42 g/s  (-7.44%, n=178/288)
     800 × -10.0    4.07 →   3.78 g/s  (-7.11%, n=87/389)
    3300 ×  -5.0   44.06 →  41.07 g/s  (-6.78%, n=79/209)
    1900 ×  -4.5   25.80 →  24.12 g/s  (-6.48%, n=212/47)
     800 ×  -8.0    6.05 →   5.69 g/s  (-6.06%, n=30/45)
    3300 × -10.0   17.39 →  16.42 g/s  (-5.57%, n=97/191)
     800 ×  -8.5    5.73 →   5.44 g/s  (-5.20%, n=245/308)

  MAF trim health (cells with ≥30 samples; in-tol = |mean_corr|<2%):
              20.10: cells= 52  mean|c|= 1.92%  median|c|= 1.93%  in_tol= 50.0%  max= 6.0%
              20.11: cells= 52  mean|c|= 1.42%  median|c|= 1.28%  in_tol= 84.6%  max= 3.7%
    verdict: MIXED — VE down but trim tighter (correcting prior over-scale?)


## auto-generated rev rollup (2026-05-12 01:28)

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

## 2026-05-12 — log: logs/5-12 20.11/5-12.csv — rom: 20.11

Log: 17,715 rows / 11.81 min @ 25 Hz. Schema 34 cols (includes KNOCK_FLAG).
20.12 still staged, NOT flashed — md5 `74f59846…` unchanged on disk since
2026-05-11 01:25:33 UTC. 6th log on 20.11.

**Drive shape:** RPM 353–4530 (median 1840); MPH 0–62 (median 25); CL/OL
state 8 (CL) 16,260 / 10 (OL) 1,453 / 0 (key-on, 2 samples only). Throttle
peak **32.2%**, APP peak **29.0%**, **mrp peak 0.43 psi** — no boost, no
WOT. IAM=1.000 throughout (sample 0 was the key-on IAM=0 artifact, cleared
by sample 1). FLKC start=0, end=0, min=0 — no learned-knock decrement.
Strict-cruise filter passes 5,363 samples = 30.3% of log = 3.58 min.

**Single-event log.** ALL 56 FBKC<0 samples fall inside ONE 2.20-second
window (samples 8065–8120, time 322.6→324.8 s). Zero FBKC<0 outside that
window. The pull is a **partial-throttle cruise climb** with the following
trajectory:
- RPM 2009 → 4448 in 2.5 s
- Load 0.22 → 1.20 g/rev (climbed into the mid-load band)
- mrp -10.01 → -2.18 psi (vacuum throughout — turbo never produced boost)
- APP 0 → 25.5%, TPS 12 → 31% (held ~24-30% APP for the climb)
- wgdc 0 → 74.9% (cap pegged at the 20.11 Max WGDC ceiling, not at 100)
- AVCS 17° → peak 21° → falls to 4° as RPM climbs past 4000
- Timing 17 → 27.5 → pulled back to 11° at end of event
- CL/OL transitions CL=8 → OL=10 at sample 8102 (RPM 3660 / load 1.06)
- Lag-corrected AFR delta (wbo2[t+8] − FFB[t]): min −1.77 (engine richer
  by 1.77 AFR at OL transition), max +1.10 (early CL phase). Median −0.34.

**Knock:** 56 FBKC<0 samples, depths {-1.4, -1.05, -0.7, -0.35}, 1 FBKC
event. 0 FLKC decrements. 20 KNOCK_FLAG=1 samples (no overlap with FBKC<0,
no co-occurrence within 200ms). 9 cell rows appended to knock_by_cell.csv.

**Knock by cell:**
- Ghost zone (2200-3300 × 1.0-1.4): 33 FBKC<0 samples, ALL at load_bin=1.00
  (zero at 1.17 / 1.36 columns). Concentrated at the **left edge** of the
  zone — different distribution from 5-8 (spread across all 3 cols) and
  5-11/log0001 (heavy at 2200×1.00 specifically).
- High-RPM extension (3700-4400 × 1.0-1.17): 23 FBKC<0 samples — NEW
  signal at these cells. Prior 20.11 logs had 0 samples here.
  - 4000 × 1.17: 6 samples, depth -0.35
  - 4400 × 1.17: 7 samples, depth -0.35
  - All from the same pull bleeding into OL territory at the RPM tail.

**Ghost-zone re-check (FBKC<0 / zone-min, warm-only):**
- 20.10 pooled (n=2): **85.4/min**
- 20.11 pooled (n=3, prior): **217/min**
- 5-12 alone: 33 FBKC<0 / 0.10 zone-min = **278/min** (rate matches log0001)
- 20.11 pooled (n=4 incl. 5-12): rate stays elevated
- Verdict: 4th 20.11 log to confirm ghost-zone elevation vs 20.10. Cluster
  reproducible. No FLKC ratchet this time — looser hold than 5-10/log0003
  (which carried FLKC=−1 across the drive). FBKC handled it.

**WOT (TPS>95):** 0 pulls. Throttle never exceeded 32.2%. wot_shortlist=0,
wot_trajectories=0, wot_writeups=0.

**Pull ramps (APP≥30 ≥0.6s, peak mrp ≥5):** 0 pulls. The partial-throttle
climb peaked at APP=25.5% and mrp=-2.18 — fails both criteria. The detector
working as designed; the event of interest is sub-threshold for "pull"
classification but is captured by knock_by_cell as the single FBKC cluster.

**MAF corr (filter: FFB≤14.7, |corr|<25, APP>2, CL=8):** 65 cells appended.
Trim health (cells ≥30 samples):
- 5-12: 25 cells, mean|c| **2.01%**, in_tol 52.0%, max 4.44%
- 5-11 pooled (n=3): 84 cells, mean|c| 1.75%, in_tol 60.7%, max 5.15%
- 5-10: 23 cells, mean|c| 0.99%, in_tol 95.7%, max 3.20%
- 5-12 is WORSE than both prior windows. mean|c| up +0.26%, in_tol down 8.7pp.
- **Monotonic slope walk in V=1.91→2.28 band** (cell mean correction):
  V=1.91 → -1.79%, V=2.05 → -0.21%, V=2.17 → -2.14%, V=2.25 → -3.52%,
  V=2.28 → -4.44%, V=2.39 → -3.82%, V=2.45 → -3.37%. Engine running
  ~3-4% richer than commanded across the 30-42 g/s mid-airflow band
  (highway cruise / partial-throttle). MAF over-reading in this V range.
- This is a different V band from the historical 4000-4500 OL concern
  (V=3.5-4.5). 5-12 saw very little high-V residency (no WOT). The mid-V
  slope walk is a fresh signal worth tracking.

**Cliffs (cruise residency check on 20.11-edited zones):** Cliff scan still
not auto-ingested; manual residency check below.
- AVCS edit 1900 × 0.20-0.30: **5.37% cruise residency** ✓ (above 1% rule)
- AVCS edit 2200 × 0.20-0.30: **6.86% cruise residency** ✓
- AVCS edit 2500 × 0.20-0.30: 0.34% cruise residency ✗ (sub-1% — this log
  can't validate the 2500 RPM AVCS edit)
- BTC cliff 1900 × 0.65-0.94: 3.64% cruise residency ✓
- BTC cliff 2200 × 0.65-0.94: **7.53% cruise residency** ✓ (highest)

**Stutter:** 67 events.
- ffb_wbo2_divergence: 19
- rpm_swing_steady_tps: 18
- avcs_oscillation: 13 (median magnitude 15°, clustered at 2000-2250 RPM ×
  load 0.21-0.28 — same 2000-RPM band signature as 5-11/log0001's 16/21
  AVCS osc cluster)
- afr_osc: 8
- throttle_hunt_at_steady_app: 5
- timing_osc: 4
- **AVCS-swing rate at 28-36 MPH × APP≤20 (strict SOP detector): 3 clusters
  in 1.14 inband-min = 2.63 clu/min.** LOWER than all prior 20.11 logs
  (3.73-6.14) and lower than 5-2 (5.84, 20.10). Two reasonable readings:
  (a) cruise stutter regime got smaller exposure in 5-12 — only 1.14
  inband-min vs 1.43/0.98 in 5-11 logs. Small-sample variance. (b) Real
  reduction, possible if drive context (longer steady-cruise stretches at
  speed) muted the trigger. Don't read a step-down from a 1-log point.

**VE proxy (cells ≥3% drift vs 5-11 pooled, ≥30 samples each side):**
- Largest gains: 1200 × -8.5 (+17%, low n), 800 × -9.0 (+15%, idle),
  3300 × -6.0 (+12%), 800 × -9.5 (+11%), 2200 × -10.5 (+11%).
- Largest losses: 1200 × -9.5 (-9%, n_5-12=3373 / n_prior=533), 1900 × -7.5 (-8%).
- Mostly low-mrp cruise/idle cells. Heavy weighting in 5-12 at specific
  RPM × mrp combos (long cruise climb visiting different residency than
  prior logs) — likely sample-distribution variance within bin, not true
  VE shift. The MAF over-reading direction (sec above) is consistent with
  the +11-17% reading-up cluster — if MAF reads 3-4% high at mid-V, the VE
  proxy will skew up by the same amount in cells residing in that V band.

**KNOCK_FLAG (20 samples):**
- Same characterization as log0001: clustered at low-RPM/low-load
  (500-2250 × 0.25-0.5). 12/20 in CL state, 8/20 in OL.
- ZERO co-occurrence with FBKC<0 (not even within ±200ms). Reinforces the
  "leading-indicator gated by transient_knock_inhibit / FLKC learning"
  interpretation — events that the ECU detected but didn't pull timing for.

**Prior-flagged areas re-checked:**
- **Ghost zone 2200-3300 × 1.0-1.4 (open since 5-3, elevated since 5-8):**
  STILL ELEVATED. 4th 20.11 log to reproduce. 5-12 specifically lit up the
  load=1.0 column edge during a partial-throttle climb. Rate ≈ log0001.
  Not resolving on its own. Lever decision still pending — MAF revert vs
  timing extend vs AVCS-toward-stock.
- **Historic concern 4000-4500 × 0.7-1.3 (open since 4-28):** This log
  introduced FRESH FBKC<0 evidence at this cell (15 samples at 4000-4400
  × 1.0-1.17, all from the partial-throttle pull tail in OL). Prior 20.11
  logs hadn't visited these cells under conditions producing FBKC. This
  expands the cluster's footprint from "high-load WOT-adjacent" to also
  "partial-throttle climb into OL transition" — broader than expected.
- **High-load lean at 3750-4250 OL (5-11 new finding):** 5-12 visited this
  band but at low load (1.0-1.2 g/rev, not 2.5-3.4 where 5-11 saw it). Not
  a refresh of that measurement. AFR delta at the OL transition this log
  was negative (engine richer) — opposite of 5-11's high-load delta.
- **MAF cmd-vs-actual delta refresh at 4000-4500 × 0.7-1.3:** Engine in
  this cell hit FBKC<0 in 5-12. At-cell wbo2-vs-FFB lag-shifted = up to
  −1.4 AFR (engine RICHER than cmd by 1.4 AFR) at the OL transition end
  — same direction as the historic +0.22 finding, magnitude much larger.
  Caveat: only the tail end of a 2.2s pull, n~10 lagged samples — not a
  steady-state measurement.
- **28-36 MPH AVCS-swing stutter (5-10 staged):** 5-12 rate 2.63 clu/min is
  LOWER than 20.11 pooled. The "monotonic 20.11 elevation vs 20.10" claim
  remains unsupported under strict SOP detector across 4 20.11 logs.
- **KNOCK_FLAG characterization:** Reinforced — 20 KNOCK_FLAG=1 samples,
  zero overlap with FBKC<0. Disassembly trace from 5-11 holds.

**New issues:**
- **Mid-V MAF slope walk (V=1.91→2.45 band)**: monotonic negative drift
  -1.79 → -4.44% across n≥45 samples per cell. Different V band from
  historic concern. Per `feedback_maf_no_cellwise_patches.md`, this is the
  exact slope-walk signature the methodology warns about — track for at
  least 1 more log before considering a region refit.
- **High-RPM/low-load FBKC extension (4000-4400 × 1.0-1.17)**: 15 fresh
  FBKC<0 samples at cells previously unobserved on 20.11. Same root pull
  as ghost zone. If the next log reproduces, the ghost zone footprint
  extends 1100 RPM further up than current "2200-3300" framing.

**Staged for next session:**
- Decide on 20.13 plan now that 20.12 is BUILT but not flashed AND we have
  the cleanest single-event ghost-zone signature on 20.11. Three options
  still on the table from the 5-11 review (MAF revert / timing extend /
  AVCS toward stock); the 5-12 evidence on mid-V MAF slope walk is the
  newest input — argues for MAF revert/refit as a candidate.
- Flash 20.12 to see if WGDC cap + L=1.67-2.83 timing pull shifts the
  partial-throttle climb behavior. Open question: 20.12 doesn't directly
  touch the 2200-3300 × 1.0-1.2 cells where 5-12 fired (it pulls timing
  at L=1.67+). So 20.12 may NOT move the 5-12-style event.
- Add cliff scan to ingest pipeline (still on prior staging list).
- Get one more 20.11 log with WOT pull conditions to re-measure the
  4000-4400 cluster under high-load OL, before deciding lever for 20.13.

---

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
---

## 2026-06-03 — log: logs/6-3 20.17/log0001.csv — rom: 20.17 (first driven log)

**Bin verification:** 20.17 ≠ 20.16, 363 bytes / 70 runs, concentrated in the
boost/WGDC region (0xC0D05–0xC1485, incl. verified WGDC 0xC1150/0xC1340), plus
6-byte-row tables 0xCFDB5–0xD0533 (per-gear timing comp pattern) and isolated
bytes 0xCD119, 0xD2D38, 0xD5457, 0xFFB88. Consistent with documented 20.17
intent (boost taper kill + Max/Initial WGDC + Turbo Dynamics P + OL KCA +
per-gear timing). Log carries no embedded ROM byte — flash identity rests on
folder label, not binary proof.

**Sanity gate (post-reflash AVCS lockout):** PASS. avcs p95 (RPM>2000) = 21.0°,
median 19°, max 30°. Not locked out; log is scoreable.

**Time-units note:** `time` col is non-monotonic — 8 recording segments, 7
discontinuities (−87.7 s to +29,555 s jumps). Raw time_end = 41,897 s is
garbage; real recorded drive = 98,427 samples / 25 Hz = **65.6 min**. Locate
all events by `sample` index. (Memory feedback_log_output_units updated.)

**Coverage gap:** NO WOT. Throttle max 51%, APP max 51%, RPM max 5246, peak mrp
14.35 psi. Cruise/partial-throttle drive only. The headline 20.17 intent
(top-end boost taper kill, ~15 psi flat 3600-6400) is UNTESTED by this log.
Need a clean WOT pull to evaluate it — and to see whether IDC saturates given
72.6% at part throttle.

**Baseline sweep:**
- IDC: peak 72.6% @ Throttle 51% (0 samples >85, 0 >100). No saturation here,
  but 72.6% at half throttle corroborates the 20.16 injector-limit finding —
  a WOT pull on 20.17 will likely peg.
- MAF(V): peak 3.90 V (well under 4.8).
- AFC: median 0.0, range −25 to +16.4; 9 samples clamped at −25 (minor).
- AFL: median 0.0, min −6.25. **AFL=0 is the post-reflash learn-reset, NOT a
  reversal of the 5-28 rich drift (−2.34). Drift trend cannot be evaluated
  from a first-post-reflash log.**
- IAM: 1.0 throughout (single IAM=0 is the startup-glitch sample 1864, ECT=0).
- FLKC: never decremented (min 0). **Zero learned knock.** Contrast 20.16's
  ghost-zone FLKC −11.80.
- AVCS: p95 21°, tracking (no lockout, no obvious oscillation flagged).

**KNOCK pass (first-instance attribution, 6 onsets; 301 FBKC<0 samples are
mostly recovery carrying the −1.4 retard):** All onsets FBKC −1.4 (one mild
step, two deepened to −2.8), ALL at low load (1.02–1.13 g/rev) in/near vacuum
(mrp −0.6 to −1.9). This is **part-throttle / tip-in knock, not high-load.**

| sample | RPM | load | mrp | Thr | APP | MPH | wbo2 | FFB | class | note |
|--------|-----|------|-----|-----|-----|-----|------|-----|-------|------|
| 24658 | 2293 | 1.13 | −1.6 | 30 | 27 | 37 | 12.36 | 12.61 | load (tip-in) | rich, fine |
| 34861 | 1651 | 1.09 | −1.3 | 26 | 15 | 8 | 15.10 | 13.67 | maybe-shift | LEAN tip-in, low speed |
| 36406 | 1644 | 1.02 | −1.9 | 23 | 17 | 9 | 14.42 | 13.93 | maybe-shift / AC-like | LEAN, steady light thr |
| 42817 | 2625 | 1.13 | −0.9 | 36 | 32 | 66 | 11.94 | 12.87 | load (tip-in) | hwy tip-in, rich |
| 47423 | 1567 | 1.12 | −0.6 | 31 | 28 | 15 | 14.72 | 13.59 | SHIFT (gear 0.64) | post-shift load step |
| 89281 | 3142 | 1.02 | −0.6 | 29 | 24 | 38 | 14.72 | 12.79 | SHIFT (gear 0.61) | post-shift load step |

**Shift knock:** 2 of 6 (samples 47423, 89281) are gear-ratio-confirmed shift
events — clutch-engage load step, not a tune target. Discard from timing-table
attribution.

**A/C knock:** CANNOT confirm. The logger has no A/C-clutch status channel.
IAT ran 93°F median / 136°F peak (heat-soak at low speed) so A/C was plausibly
on. Sample 36406 fits an A/C-load profile (steady light throttle, 9 MPH, 1644
RPM, load present) but is indistinguishable from light creeping throttle without
a clutch channel. **Action: add A/C status to logcfg if we want to settle this.**

**Real (tune-relevant) knock:** 4 of 6 are part-throttle tip-in. Two are LEAN
(samples 34861, 36406: wbo2 15.1/14.4 vs cmd 13.7/13.9) at low RPM/low speed —
lean tip-in → knock. Tip-in lean is broadly present (232 rising-pedal samples
with wbo2 leaner than command, some inflated by overrun). This points back at
tip-in enrichment / AFL, not the timing table. None of it learned (FLKC=0), so
not urgent, but it's the live thread.

**Staged for verification next log:** clean WOT pull on 20.17 to (1) test the
boost-taper-kill intent and (2) check IDC saturation at top end.


## 2026-06-05 — log: logs/6-5 20.17a/log0001.csv — rom: 20.17a (BE-comp tip-in test)

First driven log on 20.17a. **As-driven bin = BE-comp lift (`0xCD14C`) PLUS an
accidental decel-tier change (`0xCC4EC`: 2250/3000/4500 → 1000/2000/3500 RPM).**
The verify-on-ingest step caught it (per `feedback_verify_rom_changes_against_user_claims`):
the bin was NOT the BE-comp-only single-variable test the build notes claimed.
Dean confirmed the decel edit was a leftover from a walked-back "go back to stock
decel" idea and **reverted it immediately after the drive** (his tool recomputed
the checksum). On-disk 20.17a is now BE-comp-only (11-byte diff vs 20.17). So
THIS log carries a decel confound the weekend log won't.

**Sanity gate: PASS.** AVCS p95 (RPM>2000) = 20°, max 28°. Not locked out;
scoreable. 48,440 samples / 25 Hz = **32.3 min, ONE continuous segment** (no time
discontinuities — contrast 6-3's 8 segments). IAM 1.000 flat, FLKC 0 all drive.

**Coverage gap (3rd log running): NO real boost.** Peak mrp 13.77 psi (spring is
15). Throttle hit 100% for a single sample (3 psi @ 4039 RPM); max APP 75%.
Top-end / WOT intent STILL untested. Peak IDC 70.4% (part-throttle, no saturation).
ECT 66→189 °F (cold start → operating temp; ~12 min warmup).

### Gate scoring (cusp 1600-3000 × load 1.00-1.25)

| gate | target | result | verdict |
|---|---|---|---|
| G1 cusp stab-lean | < 1.5 AFR | 2.24 → **2.08** (real non-DFCO 1.76) | **FAIL** |
| G2 fewer fires / nothing deeper than −2.8° | — | shift-filtered ≤ −1.4°; deep events are overrun noise | **no fuel-attributable change** |
| G3a steady-cruise AFC | ±1.5% | −1.80% mean / −1.56% median | WATCH |
| G3b peak IDC | < 85% | 70.4% | **PASS** |

**G1 — FAIL but informative.** DFCO-recovery stabs (15/54) = 3.22 AFR (wbo2
climbing out of fuel-cut, not fixable by tip-in); real non-DFCO stabs (39/54) =
**1.76 AFR**. **Tip-in IS firing** — median IPW jump at cusp stabs **+2.05 ms**
(post 7.17 ms), BE-at-stab median 3.29 psi. ~40% more fuel delivered and the real
lean only moved 2.24 → 1.76. The residual cusp lean is wall-wetting / wbo2
sensor-lag, **not a deliverable-fuel deficit**.

**G2 — deep numbers are noise.** Whole-log FBKC min −8.40°, cusp min −4.20°, BUT
all 4 deep (≤−3°) episodes are overrun/shift artifacts at mrp ≤ 1.3 psi (the
−8.40 is at **−1.2 psi