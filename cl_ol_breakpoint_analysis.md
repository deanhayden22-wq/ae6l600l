# CL/OL Delay Maximum Breakpoint Analysis

## Data Source
- Log: `3-5 all.csv` — 200,487 samples, 220 minutes of driving
- Gears inferred from RPM/MPH ratio

## Current Breakpoints

| Parameter | Check Other CL | Clear CL Delay |
|-----------|---------------|----------------|
| Engine Load | 1.15 | 1.25 |
| Vehicle Speed | 88 MPH | 90 MPH |
| Throttle | — | 52.0% |
| 1st Gear RPM | — | 4000 |
| 2nd Gear RPM | — | 4100 |
| 3rd Gear RPM | — | 4000 |
| 4th Gear RPM | — | 3900 |
| 5th/6th Gear RPM | — | 3800 |

CL delay counter = 0 (immediate transition)

## Gear Ratios (New Gearing)

| Gear | RPM/MPH | 3000 RPM = | 4000 RPM = | Max RPM seen |
|------|---------|-----------|-----------|-------------|
| 1st | 185.2 | 16 MPH | 22 MPH | 4787 |
| 2nd | 101.6 | 30 MPH | 39 MPH | 6167 |
| 3rd | 83.0 | 36 MPH | 48 MPH | 5823 |
| 4th | 61.8 | 49 MPH | 65 MPH | 5190 |
| 5th | 39.5 | 76 MPH | 101 MPH | 3758 |

## Problem: RPM Breakpoints Never Hit

The current RPM breakpoints (3800-4100) are almost never reached during enrichment conditions:

| Gear | Current RPM BP | Median enrichment OL transition RPM | Gap |
|------|---------------|-------------------------------------|-----|
| 1st | 4000 | 3555 | Only 1/3 hit the BP |
| 2nd | 4100 | 2341 | 0/15 hit the BP |
| 3rd | 4000 | 3301 | 1/16 hit the BP |
| 4th | 3900 | 2654 | 0/16 hit the BP |
| 5th | 3800 | 3181 | 0/51 hit the BP |

**68 out of 101 enrichment OL transitions had NO known threshold met** — something else is triggering OL (likely a table not shown in the screenshot, such as a CL fueling enrichment map or load-based OL switch).

## Where Boost Builds (Load > 1.0) with New Gearing

| Gear | Boost onset RPM (min) | p25 | Median | Load > 1.15 starts at |
|------|----------------------|-----|--------|----------------------|
| 1st | 1027 | 2050 | 2533 | 1027 |
| 2nd | 1011 | 2172 | 2628 | 1046 |
| 3rd | 1620 | 2601 | 3116 | 1632 |
| 4th | 2051 | 2552 | 2659 | 2160 |
| 5th | 1861 | 2250 | 3135 | 1937 |

## Lean Samples Under Boost While in CL

The car is going lean while still in closed loop across all gears:

| Gear | CL+Lean samples | Avg WBO2 | Avg lean error vs FFB |
|------|-----------------|----------|----------------------|
| 1st | 342 / 1579 (22%) | 16.34 | +3.74 |
| 2nd | 359 / 4636 (8%) | 14.99 | +2.73 |
| 3rd | 242 / 4582 (5%) | 18.82 | +5.23 |
| 4th | 355 / 15929 (2%) | 15.59 | +2.42 |
| 5th | 228 / 21810 (1%) | 15.64 | +2.28 |

## Recommended New Breakpoints

### RPM per Gear (CL Delay Maximum)

Based on where boost actually builds with the new gearing. Set ~200 RPM above the p25 boost onset to give the OL fuel map time to establish enrichment before boost comes fully on:

| Gear | Current | Recommended | Rationale |
|------|---------|-------------|-----------|
| 1st | 4000 | 2200 | Boost builds from 1700+ RPM, p25 = 2050 |
| 2nd | 4100 | 2400 | Boost builds from 1700+ RPM, p25 = 2172 |
| 3rd | 4000 | 2800 | Boost builds from 2200+ RPM, p25 = 2601 |
| 4th | 3900 | 2800 | Boost builds from 2400+ RPM, p25 = 2552 |
| 5th/6th | 3800 | 2500 | Boost builds from 2100+ RPM, p25 = 2250 |

### Engine Load

The current 1.15/1.25 load thresholds are mostly working but the car goes lean at loads below 1.15. Consider lowering:

| Param | Current | Recommended |
|-------|---------|-------------|
| Check Other CL | 1.15 | 0.95 |
| Clear CL Delay | 1.25 | 1.10 |

This ensures OL enrichment kicks in before the lean condition develops. The data shows lean samples starting at load 0.88-0.97 across all gears.

### Vehicle Speed

| Param | Current | Recommended |
|-------|---------|-------------|
| Check Other CL | 88 | 88 |
| Clear CL Delay | 90 | 90 |

No change needed — 5th gear at 90 MPH = ~3550 RPM, which is appropriate.

### Throttle

| Param | Current | Recommended |
|-------|---------|-------------|
| Clear CL Delay | 52.0 | 40.0 |

Most enrichment OL transitions happen at 22-36% throttle. The current 52% threshold is too high — the car is already under significant load/boost well before 52% throttle. Dropping to 40% catches the actual enrichment zone.
