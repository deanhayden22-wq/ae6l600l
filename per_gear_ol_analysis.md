# Per-Gear CL/OL Transition Analysis

## Key Discovery

The BPW thresholds aren't the ONLY problem. Look at these numbers:

**Gear 5, 3000-3500 RPM**: 9,729 samples under load
- BPW avg: 6.60 ms vs threshold: 5.60 ms
- **98.9% of samples have BPW ABOVE the threshold**
- Yet **16.9% are STILL in CL** ← the "delay" in "CL to OL Transition with Delay"

**Gear 3, 3000-3500 RPM**: 650 samples under load
- BPW avg: 7.29 ms vs threshold: 5.60 ms
- **99.4% of samples have BPW ABOVE the threshold**
- Yet **42.5% are STILL in CL**

**Gear 4, 3000-3500 RPM**: 344 samples under load
- BPW avg: 6.98 ms vs threshold: 5.60 ms
- **98.8% have BPW ABOVE threshold**
- Yet **29.9% STILL in CL**

This means there's a TRANSITION DELAY/COUNTER preventing immediate OL entry even
when BPW exceeds the threshold. The "CL to OL Counter Increment" tables control
how fast the counter ramps up to trigger the actual switch.

## Two Separate Problems

### Problem 1: BPW thresholds too high at 2000-2800 RPM
At these RPMs, the thresholds (6.50-6.60 ms) are too high — BPW only exceeds
them 27-65% of the time under load:

| Gear | RPM Range | BPW avg | Threshold | % Above | % in CL |
|------|-----------|---------|-----------|---------|---------|
| 2    | 2000-2500 | 7.10    | 6.60      | 64.5%   | 55.7%   |
| 2    | 2500-3000 | 7.35    | 6.51      | 75.9%   | 25.1%   |
| 3    | 2500-3000 | 6.85    | 6.51      | 46.4%   | 41.7%   |
| 4    | 2000-2500 | 6.57    | 6.60      | 34.1%   | 54.5%   |
| 4    | 2500-3000 | 6.32    | 6.51      | 27.1%   | 57.0%   |
| 5    | 2000-2500 | 6.24    | 6.60      | 19.0%   | 78.8%   |

### Problem 2: Transition delay keeps car in CL even when BPW exceeds threshold
At 3000-3500 RPM, BPW exceeds threshold ~99% of the time, but CL% is still
17-43%. The counter/delay mechanism is too slow to react.

## Per-Gear Detailed Breakdown

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

Notes: Boost doesn't go positive until ~3500+ RPM. But load > 1.0 the whole time.
BPW exceeds threshold from 3000+ RPM — yet 81% still in CL at 3000-3500!
OL doesn't dominate until 4500+ RPM.

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

Notes: g/rev > 1.1 from 1000 RPM. BPW exceeds threshold ~65-96% from 1000-2500.
Despite this, 56-100% in CL. Transition delay holding car in CL.

### Gear 3 (RPM/MPH ratio ~83)
| RPM       | g/rev | Boost  | Load  | BPW   | Thresh | BPW>Thr | %CL   | %OL   |
|-----------|-------|--------|-------|-------|--------|---------|-------|-------|
| 1500-2000 | 1.179 | -1.8   | 1.179 | 6.90  | 6.66   | 84.5%   | 97.2% | 2.8%  |
| 2000-2500 | 1.153 | -1.8   | 1.153 | 7.06  | 6.60   | 67.2%   | 62.7% | 37.3% |
| 2500-3000 | 1.090 | -2.0   | 1.090 | 6.85  | 6.51   | 46.4%   | 41.7% | 58.0% |
| 3000-3500 | 1.128 | -1.5   | 1.128 | 7.29  | 5.60   | 99.4%   | 42.5% | 52.6% |
| 3500-4000 | 1.451 | +0.5   | 1.451 | 9.10  | 5.04   | 99.1%   | 0.0%  | 100%  |
| 4000-4500 | 1.652 | +1.3   | 1.652 | 10.69 | 3.79   | 100%    | 19.1% | 80.9% |

Notes: Positive boost at 3500+. BPW > threshold 99% at 3000-3500 but 42.5% STILL in CL.
Even at 4000-4500 with positive boost, 19.1% in CL — transition delay too slow.

### Gear 4 (RPM/MPH ratio ~62)
| RPM       | g/rev | Boost  | Load  | BPW   | Thresh | BPW>Thr | %CL   | %OL   |
|-----------|-------|--------|-------|-------|--------|---------|-------|-------|
| 2000-2500 | 1.084 | -2.4   | 1.084 | 6.57  | 6.60   | 34.1%   | 54.5% | 45.5% |
| 2500-3000 | 1.040 | -2.4   | 1.040 | 6.32  | 6.51   | 27.1%   | 57.0% | 43.0% |
| 3000-3500 | 1.110 | -1.7   | 1.110 | 6.98  | 5.60   | 98.8%   | 29.9% | 70.1% |
| 3500-4000 | 1.385 | -0.0   | 1.385 | 8.53  | 5.04   | 99.1%   | 22.8% | 77.2% |
| 4000-4500 | 1.731 | +2.1   | 1.731 | 11.02 | 3.79   | 100%    | 0.0%  | 100%  |

Notes: Boost at 0 psi at 3500-4000, positive at 4000+. BPW exceeds threshold
99% at 3000-3500 but 30% still CL. At 2000-3000, threshold barely exceeded.

### Gear 5 (RPM/MPH ratio ~40)
| RPM       | g/rev | Boost  | Load  | BPW   | Thresh | BPW>Thr | %CL   | %OL   |
|-----------|-------|--------|-------|-------|--------|---------|-------|-------|
| 1500-2000 | 1.074 | -2.1   | 1.075 | 6.34  | 6.66   | 27.5%   | 87.9% | 12.1% |
| 2000-2500 | 1.063 | -2.6   | 1.063 | 6.24  | 6.60   | 19.0%   | 78.8% | 21.2% |
| 2500-3000 | 1.244 | -0.2   | 1.244 | 7.82  | 6.51   | 57.5%   | 48.4% | 51.6% |
| 3000-3500 | 1.045 | -2.0   | 1.045 | 6.60  | 5.60   | 98.9%   | 16.9% | 83.1% |
| 3500-4000 | 1.029 | -2.4   | 1.030 | 6.38  | 5.04   | 100%    | 0.5%  | 99.5% |

Notes: Gear 5 is where the car spends most time (50k samples). At 2000-2500,
BPW barely touches threshold (19%). At 3000-3500, BPW exceeds 99% but 17% CL.

## Revised Recommendations

### The transition delay/counter is as important as the BPW thresholds

Even when BPW clearly exceeds the threshold, 17-43% of samples remain in CL at
3000-3500 RPM. Two things need to change:

1. **Lower BPW thresholds at 1600-2800 RPM** (the threshold problem)
2. **Speed up the CL to OL counter increment** (the delay problem)

### Suggested BPW threshold changes:

| RPM  | Current | BPW at load>0.9 | Proposed | Rationale |
|------|---------|-----------------|----------|-----------|
| 1200 | 5.70    | ~6.4            | 5.30     | Under-boost building zone |
| 1600 | 6.70    | ~6.4-6.8        | 5.80     | BPW only 31-51% above current |
| 2000 | 6.60    | ~6.2-7.1        | 5.50     | BPW only 19-65% above current |
| 2400 | 6.60    | ~6.3-7.1        | 5.30     | Key boost-building zone |
| 2800 | 6.50    | ~6.3-7.4        | 5.10     | BPW only 27-76% above current |
| 3200 | 5.60    | ~6.6-7.3        | 5.00     | Already mostly above, lower slightly |
| 3600 | 5.60    | ~6.4-9.1        | 4.60     | Positive boost zone |
| 4000 | 4.10    | ~7.9-12.8       | 3.80     | Well above, minor tweak |

### CL to OL Counter needs investigation

The "CL to OL Counter Increment" table and any associated delay timers need
to be checked. The counter determines how many samples BPW must stay above
the threshold before the ECU actually switches to OL. If this counter is too
high, the transition is delayed even when conditions clearly warrant OL.
