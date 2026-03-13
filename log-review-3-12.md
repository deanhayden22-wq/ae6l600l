# Log Review: 3-12 all.csv (Rev 20.3 ROM)

**Log Size:** 235,250 rows (~12+ hours of logging at 25Hz)
**Filters Applied:** CL/OL=7 excluded, corrections >25 or <-25 excluded (decel)
**ATM Baseline:** ~14.07 psi
**Boost values reported as MRP (gauge pressure)**

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
- MRP: up to ~1.9 psi boost
- Timing pulled from ~15 down to **5.5 degrees**
- IAT: 42.8-44.6F
- Duration: **5.36 seconds** (134 samples)

This is the biggest trouble spot in the log. At ~2050 RPM under moderate boost (~1.9 psi), the ECU is seeing enough knock to pull -9.8 degrees of FBKC and crush timing down to 5.5-6.0 degrees. At this RPM/load the base timing table is probably calling for ~15-16 degrees, so the ECU is pulling roughly 10 degrees - that's substantial.

**Possible causes:** Low RPM + high load is the classic knock zone. The tune may need timing pulled in the ~2000-2200 RPM / 1.3-1.5 load area. Could also be fuel quality related.

#### Event 8 (t=42204.72s - 42206.00s)
- Peak FBKC: **-7.00**
- RPM: ~2995-3056
- MRP: up to ~1.3 psi boost
- Timing pulled from ~19.5 down to **13.0**
- Another significant knock event at moderate RPM/load

#### Event 4 (t=37622.88s - 37624.72s) - During the Big Pull
- Peak FBKC: -1.40
- RPM: 4018-4709
- MRP: 12-16 psi boost
- Timing: 12.0-17.0
- Minor knock during the hardest pull in the log. Only -1.40 at these boost levels is actually pretty reasonable.

#### Event 5 (t=41039.96s - 41042.16s)
- Peak FBKC: -1.40
- RPM: 3440-3671
- MRP: up to ~14.6 psi boost
- Minor knock during another big pull

#### Remaining Events (3, 6, 7, 9-19)
- All peak at -1.40 to -2.80 FBKC
- Mostly in the 2400-3500 RPM range at low/moderate boost
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
Most of the CL/OL=8 data is at low load (partial throttle cruise, not true WOT pulls). Looking specifically at the actual boosted pulls using MRP:

#### The Big Pull (t=37621.72s - 37626.80s)
- RPM: 3661-5300, MRP: 3.2-16.4 psi boost
- **WBO2: 10.72 - 12.61 (avg 11.38)**
- 27 samples with WBO2 > 11.5 at MRP > 5 psi
- At peak boost (15-16 psi MRP), WBO2 was **10.7-11.4** -- appropriately rich
- Lean spots occur during spool-up (5-7 psi MRP range) where WBO2 is 12.0-12.5 before the fueling catches up
- No knock events during the lean transition window

#### Multiple Medium Pulls (5-14 psi MRP range)
Across pulls at 39634s, 40480s, 41038s, 41147s, 42433s, 42913s, 43569s, 44178s, 44191s, 44200s - consistent pattern:
- AFRs running **11.5-12.8** through the 5-8 psi MRP range
- As MRP climbs above 8-10 psi, WBO2 drops into the 10.7-11.5 range (appropriate)
- The lean area is in the **spool-up transition zone (5-8 psi MRP)** where the fueling map transitions but hasn't fully enriched yet

#### Tip-In Transient Lean Spikes
- t=44640.6s: WBO2 spiked to 20.16 momentarily during boost onset -- **FBKC stayed at 0, no knock**
- t=689.7s: WBO2 hit 17.0 briefly -- **FBKC stayed at 0, no knock**
- Neither tip-in event produced any knock events

### Closed Loop Fuel Trims
- **Average correction: -2.86%** (running slightly rich of target in closed loop, ECU pulling fuel)
- 68.8% of corrections are negative (pulling fuel)
- 31.2% positive (adding fuel)

#### By RPM:
| RPM Range | Avg Correction | Notable |
|-----------|---------------|---------|
| 1000-1500 | +0.77% | Fine |
| 1500-2000 | +4.17% | Slightly lean, adding fuel |
| 2000-2500 | -1.28% | Fine |
| 2500-3000 | -3.61% | Pulling fuel |
| 3000-3500 | **-4.83%** | Consistently pulling fuel |
| 3500-4000 | +2.15% | Adding fuel |
| 4000-4500 | -1.54% | Fine |

The **3000-3500 RPM** range at -4.83% is the most notable. ECU is consistently pulling ~5% fuel (base map slightly rich here).

#### CL Trim Bleed-Into-OL Check
- AFL during OL at boost: **-0.59** avg (minimal)
- AFL during OL no-boost: **-1.56** avg
- **CL learning is NOT significantly bleeding into OL fueling.** The AFL values under boost are close to zero.

### AFL (A/F Learning)
- **Average: -1.93** (non-zero values)
- Range: -3.91 to +2.34
- The learning is biased negative (pulling fuel / base map runs slightly rich)
- AFL trending more negative over the log session (from -0.41 early to -2.00 late)

### Injector Duty Cycle
- **Max IDC: 72.4%** - well within safe limits
- Never exceeds 85%
- Plenty of injector headroom

---

## 3. BOOST CONTROL

### Peak Boost
- **Peak MRP: 16.38 psi boost** (MAP 30.59 psi absolute)
- Occurred at t=37622.92s, RPM=4039, load=3.23
- WGDC at peak: 65.1% (not even maxed out)
- WBO2 at peak: 11.39 (safe)
- WGDC never hits 95% or above in the entire log

### Overboost Events (MRP vs Trgt_Boost)
10 overboost clusters detected where MRP exceeded Trgt_Boost by > 1 psi while under real boost (MRP > 3 psi):

| Cluster | Time | RPM Range | Max Over Target | Notes |
|---------|------|-----------|----------------|-------|
| 1 | 37624-37627s | 4559-5300 | 10.48 psi | Wind-down of big pull, target dropping faster than turbo despools |
| 2 | 40481-40482s | 3595-3619 | 2.72 psi | Minor, spool-up |
| 3 | 41040-41042s | 3524-3664 | 8.97 psi | Second biggest pull, target lagging during build |
| 4 | 41148-41150s | 3245-3300 | 3.31 psi | Moderate |
| 5 | 42435-42438s | 3120-3364 | 4.47 psi | Spool-up overshoot |
| 6 | 42915-42918s | 3050-3287 | 5.79 psi | Boost built faster than ECU expected |
| 7-10 | Various | Various | 1.0-2.9 psi | Minor |

The largest overboost (Cluster 1, 10.48 psi over target) is during pull wind-down where the ECU is aggressively dropping the target at high RPM but the turbo can't despool that fast. This is expected behavior, not a true overboost concern.

Cluster 6 (~42915s, 5.79 psi over at 3050-3287 RPM) is the most notable -- boost built faster than the ECU anticipated during spool-up.

### Boost Creep
- **None detected.** The wastegate is controlling properly.

### WGDC
- Never hits 95%+, maxing around 65-75% during pulls
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
- **Range: 39.2 - 71.6F** (very cool - good intercooler performance)
- Average: 45.9F
- Average at WOT: 46.6F
- IATs barely climb during pulls, suggesting an effective intercooler setup
- No heat soak concerns at all

### EGT
- EGT data appears to be sensor temperature (27-106F range), not exhaust gas temperature. Likely not a true EGT probe or values aren't being read correctly. Not useful for analysis.

---

## 5. SUMMARY OF TROUBLE SPOTS

### RED FLAGS (Action Recommended)

1. **Low-RPM knock (2000-2200 RPM under boost)** - The -9.80 FBKC event at ~752s is significant. The timing is getting crushed to 5.5 degrees at only ~1.9 psi MRP. The 2000-2500 RPM column averages -4.74 FBKC. **Consider pulling 2-3 degrees of timing in the low RPM / high load cells (~2000-2200 RPM, load 1.3-1.5).** This is the most actionable finding.

### YELLOW FLAGS (Monitor)

2. **Lean AFRs during spool-up (5-8 psi MRP)** - WBO2 runs 11.5-12.8 in the transition zone as boost builds. Once boost is up (>8-10 psi MRP), fueling catches up and AFRs are appropriate. The tip-in lean spikes did not produce any knock events. May want to enrich the spool-up transition cells slightly.

3. **3000 RPM knock event** (Event 8, FBKC -7.00) - Less severe than the 2000 RPM event but still notable at ~1.3 psi MRP. Worth watching.

4. **Overboost during spool at ~3000-3300 RPM** (Cluster 6, 5.79 psi over target) - Boost builds faster than the ECU expects. Not dangerous in this log but worth understanding the target boost table behavior.

5. **Closed-loop trims biased negative** - The -2.86% average correction and -1.93 AFL learning show the base fuel map runs slightly rich. Not bleeding into OL at boost (AFL only -0.59 under boost). Acceptable as-is.

### GREEN (Healthy)

- IAM locked at 1.0 - no learned knock issues
- FLKC always 0 - nothing persistent
- IDC maxing at 72.4% - plenty of injector headroom
- IATs excellent (39-72F range, avg 46F)
- No boost creep
- WGDC has plenty of authority (never hits 95%+)
- High RPM (4000+) runs clean with minimal knock
- Timing is stable and consistent outside of knock events
- Big pull fueling safe: WBO2 10.7-11.4 at peak boost (15-16 psi MRP)
- Tip-in lean spikes did not cause any knock
- CL trim bias not bleeding into OL under boost
