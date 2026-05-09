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
REDUCE knock margin pressure, not increase it. The 20.11 knock-rate jump is
NOT explained by 20.11's timing changes — they go the right direction.
Possible alternate causes:
1. **Single-log noise.** 30 min @ 2.74% ghost-zone exposure = 1,232 samples.
   Knock-per-zone-second was 16.4% (vs 20.10's 6.15% over 218 min). Wide CIs.
2. **MAF curve shift at high-V end (+5-6 g/s).** Engine reads MORE air at
   high MAF V → calculates MORE fuel → would run RICHER. wbo2/FFB at knock
   samples (13.21 / 12.78) confirms engine is 0.43 AFR richer than commanded.
   Richer should HELP knock, not hurt. Doesn't explain the increase either.
3. **Operating-condition delta.** Different ambient T, fuel batch, or trip
   profile that just landed more time in the marginal slice of the zone.
4. The L=1.20 column got the timing pull — but the knock samples cluster
   at L=1.10, 1.20, AND 1.30. Cells at 1.10 and 1.30 had timing UNCHANGED
   in 20.11. So the timing pull doesn't reach the entire zone where knock
   appeared.

**WOT:** 0 pulls (sustained ≥1s TPS>95%). Single 0.88s near-pull peaked at
4689 RPM / 22.3 psi mrp. **Insufficient WOT data this drive — boost-control
review still needs a future log.**

**MAF corr:** 16,997 filtered samples, 39 cells with ≥30 samples.
**92.3% in-tolerance** (|mean|<2%) vs 20.10 50.0%. mean|c|=0.83% (20.10=1.92%),
max|c|=4.4% (20.10=6.0%). Only outlier cell: MAF V=1.64 / g/s=9.96, mean
-4.45% but median=0.0% with std=7.89% — bimodal noise, not directional drift.
**MAF cal looks tighter on 20.11 than 20.10.**

**Cliffs:** None auto-flagged (cliffs_flagged.csv pipeline not populated by
ingest script — only manual AVCS table review at `trends/avcs_review_20.11.txt`).
That review shows 7 AVCS Cruise cells changed vs 20.10 (1600-2500/0.20-0.30,
all small ±0.5-1.5° tweaks); 22 cruise residency cells ≥30s with ≥3° neighbor
delta — same pattern as 20.10, AVCS-edit cells fixed those mid-zone cliffs but
RPM-direction cliffs at 3400→3800 (-5° at all loads ≥0.7) and 4150→4450
(-3.6 to -5.3° at all loads ≥0.5) PERSIST.

**Stutter (rate-normalized vs 20.10):**
| signal                         | 20.10/min | 20.11/min |  ratio |
|--------------------------------|-----------|-----------|--------|
| afr_osc                        | 0.28      | 1.54      | 5.5×   |
| avcs_oscillation               | 0.35      | 1.57      | 4.5×   |
| ffb_wbo2_divergence            | 0.72      | 3.44      | 4.8×   |
| rpm_swing_steady_tps           | 0.61      | 2.58      | 4.2×   |
| throttle_hunt_at_steady_app    | 0.11      | 0.67      | 6.1×   |
| timing_osc                     | 0.22      | 1.04      | 4.7×   |

But: **ALL 20 throttle_hunt events at APP ~0% / TPS 5-9%** = idle/coast oscillation,
NOT cruise-pedal hunting (the v9 issue). Cruise zone (APP 10-25%) had 0
throttle_hunt events. **v9 cruise hunt fix appears to be holding** in this log.

**AVCS oscillation:** 0/47 events in the previously-resolved cruise zone
(2500-3300 × 0.5-0.9). 16/47 in AVCS-edit zone (1600-2500 × 0.18-0.32) — these
are coast-to-light-cruise transitions where AVCS swings 0↔17° (load
transitioning across the cliff). The cruise-zone resolution is HOLDING; the
new transitions are coast/decel artifacts in 30 min of stop-and-go.

**VE:** 83 overlap cells with prior. MAF trim health: 50% in-tol (20.10) →
92.3% (20.11) — but with smaller sample base. Top losses concentrate at 1200
RPM (-21%, -15%, -13%) and small samples in 20.11 (n<400). 800 RPM idle cells
also down -7-8%. **Not concerning at idle/coast speeds; possibly seasonal/IAT
effect (need ambient-temp check across these logs).**

**Prior-flagged areas re-checked:**
- AVCS=0 in non-cruise high-load (3000-4500 RPM × 1.0-1.4): **CLOSED — root
  cause was post-start AVCS warm-up gate.** 4-27 log0002 starts with
  EGT=255Ω (cold sensor) and CL/OL=7 (warm-up state) at idle — fresh
  restart log. The AVCS=0° tip-in was at t=124.6s post-restart, inside the
  AVCS warm-up window. User confirmed it was right after a gas-station
  restart with a quick parking-lot exit. Not a tune issue. 5-8 log's lack of
  recurrence (high-load samples all came after minute 15) is consistent.
- Cruise pedal hunting at 12-22% APP / 2700-3300 RPM (v9): **HOLDING.** 0
  throttle_hunt events in cruise APP range (10-25%). v9 was flashed in 20.9
  (saved 2026-04-25), not 20.11 — so this is now its 4th log on v9 (4-25,
  4-27, 5-2, 5-8). The "STAGED" tag in memory was wrong; v9 has been driven
  and verified for 13+ days.
- Marginal 2000/80% APP cell (ratio=1.001): no high-APP cruise samples in this
  log; can't evaluate.
- Ghost zone 2200-3300 × 1.0-1.4: **REGRESSED on RATE** (4.4× higher events/min
  vs 20.10) but DEPTH improved (-4.2° vs -7.0°). IAM held at 1.00. Concerning
  signal — see new issue below.
- Knock activity 3500-5500 × 0.7-1.6 OL (post-20.10 leanout): 0 events / 25
  samps in 30 min, vs 20.10 1 evt / 43 samps in 218 min — sample-rate
  comparable, no escalation. **HOLDING.**
- AVCS commands 0° in non-cruise high-load: **CLOSED — post-start warm-up
  gate** (see above).
- Tip-in enrichment expires before AVCS finishes ramping: needs DFCO event;
  none clearly captured — defer.
- +0.22 AFR cmd-vs-actual delta in 4000-4500 cell: only ~5-7 high-load samples
  in 4000-4500 in this log; insufficient to compute.
- Base Timing Cruise 1900/0.94 cliff and KCA Cruise 4.57° cliff at 0.94→1.20:
  no edits in 20.11; not re-checked.

**New issues:**
- **NEW (P3 — observation):** Ghost-zone knock rate jumped 4.4× in 20.11 first
  log despite base timing being PULLED 1-2° at L=1.20 in this zone. Direction
  of change is wrong for the data — needs a 2nd or 3rd log on 20.11 before
  reading anything into the rate (n=1 vs 20.10's n=5 logs). Sample-count
  caveat is large.
- **NEW (P2 — methodology):** User-reported "20.11 = AVCS-only" is incorrect.
  ROM diff shows 20.11 also retarded all 4 base timing tables (Primary +
  Reference, Cruise + Non-Cruise) by 1-2° at L=1.20 column 1900-4400 RPM,
  AND tweaked MAF Sensor Scaling g/s output (low-V trimmed down, high-V
  bumped up +2.7 to +6.3 g/s). User memory and this writeup needed
  correction. Ingest pipeline doesn't track table-level binary diffs;
  rev rollups stop at trends-CSV stats.
- WOT pull data missing this drive — can't update boost-control trend store.

**Staged for next session:**
- Get 1-2 more logs on 20.11 to settle whether the ghost-zone rate jump is
  real or a single-log artifact.
- Capture a log with at least 2-3 sustained WOT pulls (≥1s) to feed
  trends/wot_pulls.csv.
- Treat AVCS=0-in-NC as still OPEN — the 20.11 log doesn't prove resolution
  because NC table didn't change in the relevant zone. Need the 4-27-style
  6-second steady tip-in to be repeated under the same conditions to rule
  out an AVCS warm-up / startup-conditional path.
- Consider extending log_review_ingest.py with a ROM-binary-diff step so
  that when a new rom_rev appears, the rollup auto-summarizes which tables
  changed (AVCS, Base Timing, MAF, etc) by reading the .bin against the
  prior rev's .bin.

(Earlier paragraph fragment about pedal v9 staging was wrong — v9 was
flashed in 20.9 saved 2026-04-25 and has been on every log since. See
"Cruise pedal hunting" entry above.)

- Add a cliff-scan implementation to log_review_ingest.py so cliffs_flagged.csv
  starts populating (currently only AVCS via standalone script).

---

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


