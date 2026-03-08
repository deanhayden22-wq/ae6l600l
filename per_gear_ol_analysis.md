# Per-Gear CL/OL Transition Analysis

## How the CL/OL System Actually Works (from ROM code)

Reading the actual ECU code reveals a **two-layer system**:

### Layer 1: "CL Delay" — The Gatekeeper

The ECU maintains a "CL Delay" value. When this delay is **non-zero**, the
BPW/throttle thresholds ("with Delay" tables) control CL→OL transition.
When the delay is **zero**, the ECU skips those tables entirely and decides
CL/OL based on the Primary Open Loop Fueling map enrichment value alone.

**Multiple conditions can CLEAR the CL Delay (set it to zero = instant OL):**

| Table | Your ROM Values | How it Works |
|-------|----------------|--------------|
| CL Delay Max Engine Speed (Per Gear) | 1st: 4000/4100, 2nd: 4000/4100, 3rd: 3900/4000, 4th: 3800/3900, 5th: 3700/3800 | RPM ≥ upper value → delay=0 (instant OL). RPM drops below lower → re-check other tables |
| CL Delay Max (Throttle) | ~52% | Throttle ≥ this → delay=0 |
| CL Delay Max (Vehicle Speed) | ~88/90 MPH | Speed ≥ upper → delay=0 |
| CL Delay Min (ECT) | -12°F | ECT < this → delay=0 (cold engine) |
| CL Delay Max (EGT) | (two values) | EGT ≥ upper → delay=0 |
| **CL Delay Max (Engine Load)** | **1.15 / 1.25 g/rev** | **Load ≥ 1.25 AND counter ≥ 200 → delay=0** |

**The Engine Load path is the ONLY counter-based one.** All others are instant.

### Layer 2: "CL to OL Transition with Delay" — The Actual Switch

When CL Delay is NON-ZERO, the ECU uses BPW and throttle thresholds:

1. Look up BPW threshold from RPM table
2. Look up throttle threshold from RPM table
3. If BPW ≥ threshold OR throttle ≥ threshold → start incrementing counter
4. Counter increments by **step value** (from MAF table) each ECU cycle
5. If BPW/throttle drops below threshold → **counter resets to zero**
6. When counter ≥ **CL to OL Delay** value → transition to OL

**Your ROM values:**

```
CL to OL Delay_ (primary):        0  ← ZERO!
CL to OL Delay SI-DRIVE Int:   1250
```

**The primary delay is ZERO.** This means for non-SI-DRIVE-Intelligent mode,
the "with Delay" BPW/throttle tables are **completely bypassed**. The ECU goes
straight to the Primary Open Loop Fueling map to decide CL vs OL.

If you're in SI-DRIVE Intelligent mode, the delay is 1250 counter cycles.
With step value = 1, that's 1250 ECU cycles (~15-20 seconds!) of continuously
exceeding the BPW threshold before the transition happens.

### Layer 1 Details: The Engine Load Counter

```
CL Delay Maximum (Engine Load):
  - Below 1.15 g/rev → reset counter to 0, check other CL tables
  - Above 1.25 g/rev → increment counter each cycle
  - When counter ≥ 200 → set CL Delay = 0 (enables OL based on fuel map)

CL Delay Engine Load Counter Threshold: 200
```

So the load path works like this:
1. Load must reach **1.25 g/rev** (not 1.15!) to start counting
2. Must STAY ≥ 1.25 for **200 consecutive cycles**
3. If load drops below **1.15** at any point → counter resets to zero
4. Only after 200 cycles does CL Delay clear → OL possible

### The Counter Step Value (MAF)

```
MAF Axis: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 g/s
Step:     1, 1, 1, 1, 1, 1, 1, 1, 1, 1
```

All 1s. Every MAF value gives the same increment of 1 per cycle.

## What This Means for Your Car

### The Real Flow (non-SI-DRIVE Intelligent mode):

```
1. CL Delay starts at some value from "CL to OL Delay" table
   → YOUR VALUE = 0 → delay is already zero!

2. Since delay = 0, BPW/throttle "with Delay" tables are SKIPPED entirely

3. CL/OL is decided SOLELY by:
   - Primary Open Loop Fueling map enrichment value
   - vs "Minimum Active Primary Open Loop Enrichment" threshold
   - If enrichment > minimum → OL. Otherwise → CL.

4. UNLESS a "CL Delay Maximum" condition clears the delay
   (but delay is already 0, so this is redundant)
```

### Wait — if delay=0 means BPW tables are bypassed, what IS controlling CL/OL?

**The Primary Open Loop Fueling map.** The ECU looks up the current enrichment
target from the OL fuel map. If it's richer than the "Minimum Active Primary
Open Loop Enrichment" threshold (an AFR value), the ECU goes OL.

This means the CL/OL transition is actually controlled by:
- Where in the OL fuel map the ECU is looking (RPM × Load)
- Whether that cell's AFR target is rich enough to trigger OL
- The car stays in CL at moderate loads because the OL fuel map says
  "stoichiometric" (14.7) at those cells, which doesn't exceed the minimum
  enrichment threshold

### Confirmed by the data:

At 3000-3500 RPM, load ~1.0-1.1:
- The OL fuel map likely has ~14.7 AFR (stoich) at these load points
- Only when load climbs to ~1.2-1.3+ does the OL map start commanding
  enrichment (lower AFR like 12.5-13.0)
- THAT'S when the car actually goes OL — not because of BPW thresholds,
  but because the OL fuel map finally commands enrichment

## Per-Gear Detailed Breakdown

### Gear Ratios (from RPM/MPH analysis)
| Gear | RPM/MPH Ratio | Speed at 3000 RPM | Speed at 4000 RPM |
|------|---------------|-------------------|-------------------|
| 1st  | 185.2         | 16 MPH            | 22 MPH            |
| 2nd  | 101.6         | 30 MPH            | 39 MPH            |
| 3rd  | 83.0          | 36 MPH            | 48 MPH            |
| 4th  | 61.8          | 49 MPH            | 65 MPH            |
| 5th  | 39.5          | 76 MPH            | 101 MPH           |

### Gear 1 (RPM/MPH ratio ~185)
| RPM       | g/rev | Boost  | Load  | BPW   | Thresh | BPW>Thr | %CL   | %OL   |
|-----------|-------|--------|-------|-------|--------|---------|-------|-------|
| 1000-1500 | 1.047 | -3.0   | 1.047 | 6.38  | 5.83   | 71.6%   | 83.2% | 0.0%  |
| 1500-2000 | 1.039 | -2.6   | 1.039 | 6.39  | 6.66   | 31.1%   | 94.9% | 0.0%  |
| 2000-2500 | 1.057 | -2.5   | 1.057 | 6.43  | 6.60   | 38.4%   | 94.0% | 0.5%  |
| 2500-3000 | 1.047 | -2.3   | 1.047 | 6.56  | 6.51   | 49.1%   | 88.7% | 5.0%  |
| 3000-3500 | 1.052 | -1.9   | 1.052 | 6.79  | 5.60   | 100%    | 81.4% | 8.2%  |
| 3500-4000 | 1.106 | -2.0   | 1.106 | 6.88  | 5.04   | 100%    | 57.1% | 23.8% |
| 4000-4500 | 1.252 | -1.5   | 1.252 | 7.90  | 3.79   | 100%    | 17.2% | 51.7% |
| 4500-5000 | 1.299 | -0.7   | 1.299 | 8.18  | 2.03   | 100%    | 0.0%  | 100%  |

Gear 1 OL kicks in at 4500+ RPM — that's when **RPM exceeds 4000/4100 per-gear
breakpoint**, clearing CL delay instantly. Below that, load never reaches 1.25
g/rev to trigger the load counter path.

### Gear 2 (RPM/MPH ratio ~102)
| RPM       | g/rev | Boost  | Load  | BPW   | Thresh | BPW>Thr | %CL   | %OL   |
|-----------|-------|--------|-------|-------|--------|---------|-------|-------|
| 1000-1500 | 1.146 | -1.3   | 1.147 | 7.05  | 5.83   | 95.4%   | 100%  | 0.0%  |
| 1500-2000 | 1.136 | -2.0   | 1.136 | 6.81  | 6.66   | 50.9%   | 86.6% | 13.4% |
| 2000-2500 | 1.147 | -1.7   | 1.147 | 7.10  | 6.60   | 64.5%   | 55.7% | 43.5% |
| 2500-3000 | 1.143 | -1.3   | 1.143 | 7.35  | 6.51   | 75.9%   | 25.1% | 69.9% |
| 3000-3500 | 1.137 | -1.0   | 1.137 | 7.33  | 5.60   | 98.9%   | 8.5%  | 82.8% |
| 3500-4000 | 1.108 | -1.7   | 1.108 | 6.94  | 5.04   | 100%    | 5.4%  | 88.6% |
| 4000-4500 | 2.028 | +4.5   | 2.027 | 12.75 | 3.79   | 100%    | 0.0%  | 100%  |

### Gear 3 (RPM/MPH ratio ~83)
| RPM       | g/rev | Boost  | Load  | BPW   | Thresh | BPW>Thr | %CL   | %OL   |
|-----------|-------|--------|-------|-------|--------|---------|-------|-------|
| 1500-2000 | 1.179 | -1.8   | 1.179 | 6.90  | 6.66   | 84.5%   | 97.2% | 2.8%  |
| 2000-2500 | 1.153 | -1.8   | 1.153 | 7.06  | 6.60   | 67.2%   | 62.7% | 37.3% |
| 2500-3000 | 1.090 | -2.0   | 1.090 | 6.85  | 6.51   | 46.4%   | 41.7% | 58.0% |
| 3000-3500 | 1.128 | -1.5   | 1.128 | 7.29  | 5.60   | 99.4%   | 42.5% | 52.6% |
| 3500-4000 | 1.451 | +0.5   | 1.451 | 9.10  | 5.04   | 99.1%   | 0.0%  | 100%  |
| 4000-4500 | 1.652 | +1.3   | 1.652 | 10.69 | 3.79   | 100%    | 19.1% | 80.9% |

### Gear 4 (RPM/MPH ratio ~62)
| RPM       | g/rev | Boost  | Load  | BPW   | Thresh | BPW>Thr | %CL   | %OL   |
|-----------|-------|--------|-------|-------|--------|---------|-------|-------|
| 2000-2500 | 1.084 | -2.4   | 1.084 | 6.57  | 6.60   | 34.1%   | 54.5% | 45.5% |
| 2500-3000 | 1.040 | -2.4   | 1.040 | 6.32  | 6.51   | 27.1%   | 57.0% | 43.0% |
| 3000-3500 | 1.110 | -1.7   | 1.110 | 6.98  | 5.60   | 98.8%   | 29.9% | 70.1% |
| 3500-4000 | 1.385 | -0.0   | 1.385 | 8.53  | 5.04   | 99.1%   | 22.8% | 77.2% |
| 4000-4500 | 1.731 | +2.1   | 1.731 | 11.02 | 3.79   | 100%    | 0.0%  | 100%  |

### Gear 5 (RPM/MPH ratio ~40)
| RPM       | g/rev | Boost  | Load  | BPW   | Thresh | BPW>Thr | %CL   | %OL   |
|-----------|-------|--------|-------|-------|--------|---------|-------|-------|
| 1500-2000 | 1.074 | -2.1   | 1.075 | 6.34  | 6.66   | 27.5%   | 87.9% | 12.1% |
| 2000-2500 | 1.063 | -2.6   | 1.063 | 6.24  | 6.60   | 19.0%   | 78.8% | 21.2% |
| 2500-3000 | 1.244 | -0.2   | 1.244 | 7.82  | 6.51   | 57.5%   | 48.4% | 51.6% |
| 3000-3500 | 1.045 | -2.0   | 1.045 | 6.60  | 5.60   | 98.9%   | 16.9% | 83.1% |
| 3500-4000 | 1.029 | -2.4   | 1.030 | 6.38  | 5.04   | 100%    | 0.5%  | 99.5% |

## CL→OL Load Transition Analysis (from logged data)

At 3000-3500 RPM, CL/OL transition correlates with load:

| Load (g/rev) | %CL   | %OL   | Avg Boost |
|-------------|-------|-------|-----------|
| 0.80-0.85   | 79.0% | 20.7% | -4.6 psi  |
| 0.85-0.90   | 70.5% | 28.4% | -4.0 psi  |
| 0.90-0.95   | 39.7% | 60.1% | -3.3 psi  |
| 0.95-1.00   | 25.2% | 74.0% | -2.8 psi  |
| 1.00-1.05   | 15.9% | 82.4% | -2.2 psi  |
| 1.05-1.10   | 6.7%  | 92.5% | -1.7 psi  |
| 1.10-1.15   | 3.9%  | 95.5% | -1.1 psi  |
| 1.25+       | ~6%   | ~93%  | 0+ psi    |

At 2000-3000 RPM:

| Load (g/rev) | %CL   | %OL   | Avg Boost |
|-------------|-------|-------|-----------|
| 0.80-0.85   | 90.2% | 9.8%  | -4.9 psi  |
| 0.90-0.95   | 85.1% | 14.9% | -3.9 psi  |
| 1.00-1.05   | 78.7% | 21.0% | -2.9 psi  |
| 1.10-1.15   | 54.5% | 43.6% | -1.7 psi  |
| 1.20-1.25   | 28.7% | 71.3% | -0.6 psi  |
| 1.30-1.35   | 22.4% | 77.2% | +0.4 psi  |
| 1.55+       | ~8%   | ~92%  | +2.9 psi  |

**The transition correlates with LOAD, not with the BPW threshold table.**
This confirms the Primary OL Fuel Map is the actual gatekeeper, since it's
indexed by load. The OL fuel map probably transitions from stoich (14.7) to
enrichment around load 0.90-1.00 at 3000+ RPM, and around 1.10-1.25 at
2000-3000 RPM.

## What Needs to Change

Since `CL to OL Delay_` = 0, the BPW threshold table is **irrelevant** for your
car (unless you're in SI-DRIVE Intelligent mode). The actual CL/OL decision is
made by:

1. **Primary Open Loop Fueling map** — what AFR does it command at current RPM/Load?
2. **Minimum Active Primary Open Loop Enrichment** — the AFR threshold

### Option A: Modify the Primary OL Fuel Map
Add enrichment (richer AFR targets) at lower load cells so OL kicks in earlier.
This is the most direct fix since it's the actual control path.

### Option B: Set CL to OL Delay to non-zero
Set `CL to OL Delay_` to a small value like 5-10. This ENABLES the BPW threshold
table, which we know gets exceeded at lower loads than the OL fuel map triggers.
Then lower the BPW thresholds as previously analyzed.

### Option C: Lower the per-gear RPM breakpoints
The "CL Delay Maximum Engine Speed (Per Gear)" table instantly clears CL delay
when RPM exceeds the threshold. Current values (3700-4100) are too high for
the new gearing. Lowering these would cause earlier OL entry per gear.

Current per-gear RPM breakpoints:
| Gear | Enter (below=check) | Exit (above=clear delay) |
|------|---------------------|-------------------------|
| 1st  | 4000                | 4100                    |
| 2nd  | 4000                | 4100                    |
| 3rd  | 3900                | 4000                    |
| 4th  | 3800                | 3900                    |
| 5th  | 3700                | 3800                    |

### Option D: Lower the Engine Load threshold
Change from 1.25 g/rev to 1.00-1.05 g/rev and reduce counter from 200 to 50.
This lets the load-based CL delay clear faster at lower loads.
