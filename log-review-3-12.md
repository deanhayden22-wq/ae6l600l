# Log Review: 3-12 all.csv (Rev 20.3 ROM)

**Log Size:** 235,250 rows (~12+ hours of logging at 25Hz)
**Filters Applied:** CL/OL=7 excluded, corrections >25 or <-25 excluded (decel)
**ATM Baseline:** ~14.07 psi

---

## 1. KNOCK ANALYSIS

### IAM / FLKC
- **IAM: Rock solid at 1.0** throughout the entire log. Never drops.
- **FLKC: Always 0.** No learned knock corrections at all.

### FBKC (Feedback Knock Correction)
19 distinct FBKC events found (775 total samples). FLKC staying at 0 means the ECU never considered any of this knock persistent enough to learn from, which is good.

#### CRITICAL EVENT - Event 2 (t=751.68s - 757.04s)
- **Peak FBKC: -9.80** (this is significant)
- RPM: ~2043-2218 (low RPM, high load)
- Load: up to 1.480
- MAP: up to 15.95 psi (~1.9 psi boost)
- Timing pulled from ~15 down to **5.5 degrees**
- IAT: 42.8-44.6F
- Duration: **5.36 seconds** (134 samples)

This is the biggest trouble spot in the log. At ~2050 RPM under moderate boost (~1.9 psi), the ECU is seeing enough knock to pull -9.8 degrees of FBKC and crush timing down to 5.5-6.0 degrees. At this RPM/load the base timing table is probably calling for ~15-16 degrees, so the ECU is pulling roughly 10 degrees - that's substantial.

**Possible causes:** Low RPM + high load is the classic knock zone. The tune may need timing pulled in the ~2000-2200 RPM / 1.3-1.5 load area. Could also be fuel quality related.

#### Event 8 (t=42204.72s - 42206.00s)
- Peak FBKC: **-7.00**
- RPM: ~2995-3056
- MAP: up to 15.37 psi (~1.3 psi boost)
- Timing pulled from ~19.5 down to **13.0**
- Another significant knock event at moderate RPM/load

#### Event 4 (t=37622.88s - 37624.72s) - During the Big Pull
- Peak FBKC: -1.40
- RPM: 4018-4709
- MAP: 26.25-30.59 psi (12-16 psi boost!)
- Timing: 12.0-17.0
- Minor knock during the hardest pull in the log. Only -1.40 at these boost levels is actually pretty reasonable.

#### Event 5 (t=41039.96s - 41042.16s)
- Peak FBKC: -1.40
- RPM: 3440-3671
- MAP: up to 28.71 psi (~14.6 psi boost)
- Minor knock during another big pull

#### Remaining Events (3, 6, 7, 9-19)
- All peak at -1.40 to -2.80 FBKC
- Mostly in the 2400-3500 RPM range at low/moderate boost (11-15 psi MAP)
- These are minor and typical for a street-driven Subaru

### FBKC by RPM Summary
| RPM Range | Samples | Avg FBKC | Peak FBKC |
|-----------|---------|----------|-----------|
| 2000-2500 | 262 | -4.74 | -9.80 |
| 2500-3000 | 192 | -1.39 | -2.80 |
| 3000-3500 | 139 | -2.11 | -7.00 |
| 3500-4000 | 127 | -1.08 | -1.75 |
| 4000-4500 | 41 | -1.14 | -1.40 |
| 4500-5000 | 14 | -0.57 | -0.70 |

**The 2000-2500 RPM range is clearly the problem zone for knock.** The higher RPM ranges are clean.

---

## 2. AFR / FUELING

### Open Loop (WOT) AFR
Most of the CL/OL=8 data is at low load (partial throttle cruise, not true WOT pulls). Looking specifically at the actual boosted pulls:

#### The Big Pull (t=37621.40s - 37626.80s)
- RPM: 3600-5300, Boost: up to 16.4 psi, MAP up to 30.59
- **WBO2: 10.72 - 12.87 (avg 11.44)**
- 31 samples with WBO2 > 11.5 at MAP > 18 psi
- Leanest point: ~12.87 AFR at high boost
- **This is on the lean side for the boost levels being seen.** At 16 psi of boost you'd want to see consistent 10.8-11.0 AFR. Seeing 12+ at 20+ psi MAP is concerning.

#### Multiple Medium Pulls (3-8 psi boost range)
Across pulls at 39634s, 40480s, 41037s, 41146s, 42432s, 42912s, 43331s, 43568s, 44174s, 44190s, 44198s - these all show the same pattern:
- AFRs running **11.5-12.8** through the boost range
- Once MAP exceeds ~18 psi, AFRs are consistently 11.5-12.5
- **This is lean for the load being carried.** Target should be closer to 10.8-11.2 under boost.

#### Summary
The fueling under boost is consistently lean across the entire log. Not dangerously lean (nothing in the 13+ range at high boost), but definitely leaner than ideal. The tune could use more fuel in the open-loop high-load cells.

### Closed Loop Fuel Trims
- **Average correction: -2.86%** (running slightly rich of target in closed loop)
- 68.8% of corrections are negative (adding fuel)
- 31.2% positive (removing fuel)
- Range: -24.98% to 24.99% (hitting the limits, though these are near the decel threshold)

#### By RPM:
| RPM Range | Avg Correction | Notable |
|-----------|---------------|---------|
| 1000-1500 | +0.77% | Fine |
| 1500-2000 | +4.17% | Slightly lean, removing fuel |
| 2000-2500 | -1.28% | Fine |
| 2500-3000 | -3.61% | Adding fuel |
| 3000-3500 | **-4.83%** | Consistently adding fuel |
| 3500-4000 | +2.15% | Removing fuel |
| 4000-4500 | -1.54% | Fine |

The **3000-3500 RPM** range at -4.83% suggests the closed-loop fuel tables are slightly lean in this zone. Not alarming but worth noting - the ECU is consistently compensating by adding ~5% fuel.

### AFL (A/F Learning)
- **Average: -1.93** (non-zero values)
- Range: -3.91 to +2.34
- The learning is biased negative, meaning the ECU has learned it consistently needs to add fuel. This aligns with the correction data - the base fuel tables are running slightly lean overall.

### AFC (A/F Correction)
- Average: -0.43 (close to zero, fine)
- Range: -25.00 to +25.00 (hits the limits during transients)

### Injector Duty Cycle
- **Max IDC: 72.4%** - well within safe limits
- Never exceeds 85%
- Plenty of injector headroom

---

## 3. BOOST CONTROL

### Peak Boost
- **Max MAP: 30.59 psi (16.4 psi boost)**
- Occurred at t=37622.92s, RPM=4039, load=3.23
- WGDC at peak: 65.1% (not even maxed out)
- WGDC never hits 95% or above in the entire log

### Overboost Events
81 overboost clusters detected (MAP > Target + 1.0 psi). The most significant ones:

#### MAJOR: Pull at t=37621-37627s
- **24.70 psi over target** at one point
- Target boost appears to be reporting -2.66 to 16.29 while actual MAP hit 30.59
- RPM 3624-5300
- This is the biggest pull in the log and the target boost values seem to be lagging significantly behind actual boost

#### Recurring Pattern (~12-13 psi overboost vs target)
Multiple clusters show 10-13 psi over target:
- t=752s: 12.29 psi over (low RPM ~2100)
- t=37610s: 13.57 psi over
- t=37758s: 12.24 psi over
- t=37828s: 13.23 psi over
- t=38436-38449s: 13.17 psi over (long, 310 samples)
- t=39634-39643s: 13.49 psi over (long, 222 samples)

**The target boost values appear to be significantly lower than actual boost across many pulls.** This suggests either:
1. The target boost table needs to be updated to reflect actual boost targets
2. There's a boost control tuning issue where the wastegate can't keep up
3. The target boost parameter being logged may not represent the actual boost target the ECU is using for control

### Boost Creep
- **None detected.** No instances of MAP rising above 2 psi boost with WGDC < 10%. The wastegate is controlling properly.

### WGDC
- Never hits 95%+, maxing around 65% during the biggest pull
- Plenty of wastegate authority remaining

---

## 4. TIMING

### WOT Timing by RPM
| RPM Range | Avg Timing | Min | Max |
|-----------|-----------|-----|-----|
| 2000-2500 | 25.2 | -3.0 | 33.0 |
| 2500-3000 | 26.0 | -0.5 | 34.5 |
| 3000-3500 | 25.7 | 2.5 | 34.0 |
| 3500-4000 | 27.0 | 3.0 | 31.5 |
| 4000-4500 | 27.5 | 20.0 | 31.5 |
| 4500-5000 | 22.5 | 18.0 | 23.0 |

Note: The very low minimum timing values (negative to single-digit) at lower RPMs correspond with the knock events - ECU pulling timing in response to detected knock.

### IAT
- **Range: 39.2 - 71.6F** (that's very cool - good intercooler performance)
- Average: 45.9F
- Average at WOT: 46.6F
- IATs barely climb during pulls, suggesting an effective intercooler setup
- No heat soak concerns at all

### EGT
- EGT data appears to be sensor temperature (27-106F range), not exhaust gas temperature. Likely not a true EGT probe or values aren't being read correctly. Not useful for analysis.

---

## 5. SUMMARY OF TROUBLE SPOTS

### RED FLAGS (Action Recommended)

1. **Low-RPM knock (2000-2200 RPM under boost)** - The -9.80 FBKC event at ~752s is significant. The timing is getting crushed to 5.5 degrees at only ~1.9 psi of boost. The 2000-2500 RPM column averages -4.74 FBKC. **Consider pulling 2-3 degrees of timing in the low RPM / high load cells (~2000-2200 RPM, load 1.3-1.5).** This is the most actionable finding.

2. **Lean AFRs under boost** - Consistently seeing 11.5-12.5 AFR at MAP levels above 18 psi across multiple pulls throughout the log. The big pull shows 12+ AFR at 20+ psi MAP. **The open-loop fueling tables need enrichment in the high-load cells.** Target should be ~10.8-11.0 at these boost levels.

### YELLOW FLAGS (Monitor)

3. **Closed-loop trims biased negative** - The -2.86% average correction and -1.93 AFL learning suggest the base fuel tables are slightly lean across the board. The 3000-3500 RPM range at -4.83% is the most notable. Not dangerous but indicates the fuel tables could use a bump.

4. **Overboost vs target discrepancy** - Multiple pulls show 10-13+ psi over target. Need to verify whether the logged Trgt_Boost parameter is the actual control target or a different value. If it's the real target, boost control needs tuning.

5. **3000 RPM knock event** (Event 8, FBKC -7.00) - Less severe than the 2000 RPM event but still notable. Worth watching.

### GREEN (Healthy)

- IAM locked at 1.0 - no learned knock issues
- FLKC always 0 - nothing persistent
- IDC maxing at 72.4% - plenty of injector headroom
- IATs excellent (39-72F range, avg 46F)
- No boost creep
- WGDC has plenty of authority (never hits 95%+)
- High RPM (4000+) runs clean with minimal knock
- Timing is stable and consistent outside of knock events
