# CL/OL Full System Analysis

## All Tables Identified

### CL → OL TRIGGERS (What causes Open Loop)

**1. CL to OL Transition with Delay (BPW) — THE PRIMARY OL TRIGGER**
When injector pulse width exceeds this threshold at a given RPM, ECU goes OL.

| RPM  | BPW Threshold (ms) |
|------|-------------------|
| 0    | 5.30 |
| 400  | 5.30 |
| 800  | 5.30 |
| 1200 | 5.70 |
| 1600 | 6.70 |
| 2000 | 6.60 |
| 2400 | 6.60 |
| 2800 | 6.50 |
| 3200 | 5.60 |
| 3600 | 5.60 |
| 4000 | 4.10 |
| 4400 | 3.60 |
| 4800 | 1.80 |
| 5200 | 0.00 (always OL) |
| 5600 | 0.00 |
| 6000 | 0.00 |

**2. CL to OL Transition (Throttle) — SECONDARY OL TRIGGER**
When throttle exceeds this % at a given RPM, ECU goes OL.

| RPM  | Throttle Threshold (%) |
|------|----------------------|
| 0-4800 | 86.0 |
| 5200+ | 0.0 (always OL) |

**3. Hysteresis values (prevent bouncing)**
- BPW Hysteresis: 0.256 ms
- Throttle Hysteresis: 4.6%

**4. SI-DRIVE Intelligent Mode**: 0 (disabled)

### OL → CL TRIGGERS (What returns to Closed Loop)

**CL Delay Maximum tables** — ALL must be satisfied to return to CL:

| Table | Check Other CL | Clear CL Delay |
|-------|---------------|----------------|
| Engine Load | < 1.15 | > 1.25 (if counter > 200) |
| Vehicle Speed | < 88 MPH | > 90 MPH |
| Throttle | — | < 52.0% |
| Engine Speed (Neutral) | < 6000 | > 6100 |
| RPM 1st gear | — | < 4000 |
| RPM 2nd gear | — | < 4100 |
| RPM 3rd gear | — | < 3900 |
| RPM 4th gear | — | < 3900 |
| RPM 5th/6th gear | — | < 3700-3800 |

**CL Delay Engine Load Counter Threshold**: 200
**CL Delay Minimum (ECT)**: 10.4°

## How The System Actually Works

```
CL → OL transition:
  IF (IPW > BPW_threshold[RPM])         ← PRIMARY TRIGGER
  OR (Throttle > Throttle_threshold[RPM])  ← 86% = basically WOT only
  THEN → go Open Loop

OL → CL transition:
  IF (CL delay timer expired)            ← timer = 0, so immediate
  AND (RPM < gear_breakpoint)
  AND (Load < 1.15 OR (Load > 1.25 AND counter > 200))
  AND (Speed < 88 OR Speed > 90)
  AND (Throttle < 52%)
  AND (ECT > 10.4°)
  THEN → go Closed Loop

Hysteresis prevents re-triggering:
  Won't go OL again until IPW exceeds threshold + 0.256 ms
  Won't go OL again until throttle exceeds threshold + 4.6%
```

## Root Cause: Why the Car Goes Lean

### The BPW table is the smoking gun

From the 200k sample log, at the RPMs where boost builds with new gearing:

| RPM range | BPW threshold | Actual IPW under boost | Result |
|-----------|--------------|----------------------|--------|
| 2000-2400 | 6.60 ms | 4.5-5.5 ms | STAYS IN CL — IPW never reaches threshold |
| 2800 | 6.50 ms | 5.0-6.0 ms | STAYS IN CL — barely reaches threshold |
| 3200-3600 | 5.60 ms | 3.5-5.1 ms | STAYS IN CL — IPW too low |
| 4000 | 4.10 ms | 4.8-5.1 ms | GOES OL — threshold crossed |

From the afr lean log at 3400-3800 RPM:
- IPW was 3.58 - 5.38 ms for most of the log
- BPW threshold at 3200-3600 RPM = 5.60 ms
- **IPW barely touches the threshold, so the car stays in CL**
- CL correction (AFC) maxes out and resets, can't keep up
- Car runs 14-17+ AFR when it should be 11-12

### The throttle table doesn't help either
At 86% throttle threshold, only true WOT triggers OL via throttle.
Most boost-building happens at 22-36% throttle — nowhere near 86%.

### The CL Delay Maximum RPM breakpoints are irrelevant
With new gearing, boost builds at 2000-3200 RPM.
The RPM breakpoints (3800-4100) are only relevant for the OL→CL return path,
and the car rarely reaches those RPMs anyway.

## The Chain of Events

1. Driver gets on throttle (22-35%) at 2000-3500 RPM
2. Boost starts building, load rises toward 1.0+
3. IPW reaches 4.5-5.5 ms — BELOW the BPW threshold (5.60-6.60 ms)
4. ECU stays in CL
5. AFL is -7.03% (learned negative trim) — REMOVES fuel
6. AFC tries to add fuel (climbs to 6-17%) but can't keep up
7. WBO2 reads 14-17+ AFR — dangerously lean
8. If IPW briefly crosses threshold → goes OL
9. OL fuel map runs, but then conditions change and it bounces back to CL
10. AFC resets to 0 on transition → lean again

## Recommendations

### Option A: Lower BPW thresholds (go OL earlier)

This is the most direct fix. Lower the BPW table so the ECU goes OL at the actual IPW values seen under boost:

| RPM  | Current | Proposed | Why |
|------|---------|----------|-----|
| 0    | 5.30 | 5.30 | No change |
| 400  | 5.30 | 5.30 | No change |
| 800  | 5.30 | 5.30 | No change |
| 1200 | 5.70 | 5.30 | Boost starts building here in 1st/2nd |
| 1600 | 6.70 | 5.30 | Boost onset zone |
| 2000 | 6.60 | 5.00 | Key boost zone — IPW ~4.5-5.5 ms |
| 2400 | 6.60 | 4.80 | Key boost zone |
| 2800 | 6.50 | 4.60 | Key boost zone |
| 3200 | 5.60 | 4.40 | Primary lean zone — IPW 3.5-5.1 ms |
| 3600 | 5.60 | 4.20 | Primary lean zone |
| 4000 | 4.10 | 3.80 | Already close, slight adjustment |
| 4400 | 3.60 | 3.40 | Minor adjustment |
| 4800 | 1.80 | 1.80 | No change |
| 5200 | 0.00 | 0.00 | Always OL |
| 5600 | 0.00 | 0.00 | Always OL |
| 6000 | 0.00 | 0.00 | Always OL |

**Impact**: ECU goes OL ~0.5-1.5 ms earlier in IPW. This means OL enrichment engages sooner, before the lean condition develops. However, this ONLY works if the OL fuel map has proper enrichment for these conditions. If the OL map is also lean, this just shifts the problem.

### Option B: Keep BPW thresholds, fix CL fueling

Leave the CL→OL transition alone and instead:
1. Reset AFL (clear learned trims) — removes the -7% penalty
2. Increase CL fuel compensation in the 2000-3600 RPM / 0.8-1.2 load cells
3. This keeps the car in CL longer with CORRECT fueling

**Impact**: More conservative. CL correction can work properly once AFL is reset. But doesn't address the structural issue of boost building at lower RPMs.

### Option C: Combined approach (RECOMMENDED)

1. **Moderately lower BPW thresholds** (split the difference):

| RPM  | Current | Proposed |
|------|---------|----------|
| 1600 | 6.70 | 5.80 |
| 2000 | 6.60 | 5.50 |
| 2400 | 6.60 | 5.30 |
| 2800 | 6.50 | 5.10 |
| 3200 | 5.60 | 4.80 |
| 3600 | 5.60 | 4.60 |
| 4000 | 4.10 | 3.90 |

2. **Increase BPW hysteresis**: 0.256 → 0.512 ms (prevent CL/OL bouncing)

3. **Lower CL Delay Maximum RPM per gear** (match new gearing):

| Gear | Current | Proposed |
|------|---------|----------|
| 1st  | 4000 | 2500 |
| 2nd  | 4100 | 2800 |
| 3rd  | 3900 | 3000 |
| 4th  | 3900 | 3000 |
| 5th  | 3700-3800 | 2800 |

4. **Lower CL Delay Maximum Load**: 1.15/1.25 → 0.95/1.10

5. **Lower CL Delay Maximum Throttle**: 52% → 40%

6. **Reset ECU learned values** (clear AFL -7%)

### How these changes interact

- Lower BPW thresholds → ECU goes OL earlier under load
- Higher BPW hysteresis → ECU STAYS in OL once triggered, doesn't bounce
- Lower CL Delay RPM breakpoints → ECU stays in OL longer (won't snap back to CL at 3000 RPM)
- Lower Load/Throttle delay maximums → Additional protection against premature CL return
- Together: OL engages sooner, stays engaged through the boost event, returns to CL when truly off-boost

### What NOT to change
- CL to OL Transition (Throttle): 86% is fine — this is a WOT safety catch
- Throttle Hysteresis: 4.6% is reasonable
- Vehicle Speed: 88/90 MPH is fine
- Engine Speed Neutral: 6000/6100 is fine
- CL Delay Minimum ECT: 10.4° is fine
- Engine Load Counter Threshold: 200 is fine (provides stability for high-load CL return)
- SI-DRIVE: 0 is correct
