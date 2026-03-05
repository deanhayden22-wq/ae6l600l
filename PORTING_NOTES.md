# MerpMod Port: AE5L600L (2013 USDM Impreza WRX MT)

## Overview

This document describes the process of porting [MerpMod](https://github.com/Merp/MerpMod) to the **AE5L600L** ROM (2013 USDM Subaru Impreza WRX, manual transmission, SH7058).

AE5L600L is **not** in MerpMod's supported ROM list (166 targets). The closest supported AE5-series ROMs are AE5F301C, AE5IB00V, and AE5K700V. This port is based primarily on cross-referencing with **AE5K700V** (also a 2013 WRX).

## ROM Specifications

| Property | Value |
|---|---|
| CALID | AE5L600L |
| ECU ID | 8A12587007 |
| MCU | Renesas SH7058 |
| Architecture | SH-2, Big-Endian |
| ROM Size | 1 MB (0x100000) |
| RAM | 32 KB (0xFFFF8000-0xFFFFFFFF) |
| Flash Method | subarucan |
| Checksum | subarudbw |
| Stack Pointer | 0xFFFFBFA0 |

## What Has Been Identified

### Fully Verified Addresses

These were confirmed through binary analysis and cross-reference:

| Define | Address | Method |
|---|---|---|
| `dCalId` | 0x002004 | Standard location, string verified |
| `dEcuId` | 0x0D97F0 | Hex byte search for 8A12587007 |
| `dRomHoleStart` | 0x0DB000 | Binary scan: 0xFF from 0xDAE8C-0xF88FF (118.6 KB) |
| `pRamHoleStart` | 0xFFFFB720 | RAM reference gap analysis |
| `pRamHoleEnd` | 0xFFFFBF70 | Largest unreferenced RAM gap (2144 bytes) |
| `pMemoryResetLimit` | 0xFFFFBF9F | Literal pool at 0x11CE8 |

### High-Confidence Addresses

Derived from literal pool, descriptor, and cross-reference analysis:

| Define | Address | Evidence |
|---|---|---|
| `sPull2DFloat` | 0x0BE608 | 95 XREF in ROM, used by rev limit code |
| `sPull3DFloat` | 0x0BE830 | 218 XREF in ROM, used by MAF calc code |
| `tTargetBoost` | 0x0C1340 | Descriptor at 0xAA9FC, XML confirmed |
| `tWgdcInitial` | 0x0C1150 | Descriptor at 0xAA9E0, XML confirmed |
| `tWgdcMax` | 0x0C0F58 | Descriptor at 0xAA9C4, XML confirmed |
| `tBaseTimingPCruise` | 0x0D4714 | XML definition confirmed |
| `tBaseTimingPNonCruise` | 0x0D48D4 | XML definition confirmed |
| `tBaseTimingRCruiseAvcs` | 0x0D4A94 | XML definition confirmed |
| `tBaseTimingRNonCruiseAvcs` | 0x0D4C54 | XML definition confirmed |
| `tPolfKcaBLo` | 0x0D0244 | XML definition confirmed |
| `tPolfKcaBHi` | 0x0D0404 | XML definition confirmed |
| `tPolfKcaAlt` | 0x0CFD30 | XML definition confirmed |
| `dInjectorScaling` | 0x0CCA68 | Same as AE5K700V, value = 800.0 |
| `sMemoryReset` | 0x0101C4 | sts.l pr prolog found |
| `hMemoryReset` | 0x00FC20 | Near memory reset call chain |
| `hMemoryResetLimit` | 0x011CE8 | Literal pool containing pMemoryResetLimit |
| Engine params | Various | Cross-referenced with AE5K700V (same gen) |

### Addresses That NEED Ghidra/IDA Verification

These addresses could not be reliably determined from the available disassembly and require interactive reverse engineering:

#### Critical (Required for basic MerpMod functionality)

1. **hRevLimDelete** - Task/jump table entry that calls the rev limit function
   - *Hint*: Rev limit code is near 0x3B66C. Trace backward to find what calls it.
   - *Hint*: Check task entries 49-58 in the task table at 0x4AD40.

2. **sRevLimStart / sRevLimEnd** - Rev limit routine boundaries
   - *Hint*: Function prolog (sts.l pr) at 0x3B66C, rts at 0x3B76A.
   - *Hint*: Literal pool at 0x3B79C has Rev Limit On/Off table addresses.
   - *Hint*: Code at 0x3B6AE loads Rev Limit On address from pool.
   - *Verify*: The bitmask at pFlagsRevLim (0xFFFF7CB8) and RevLimBitMask.

3. **Cruise/Brake/Clutch Flags** - Required for launch control, CEL flash, prog mode
   - *Hint*: Navigate to SSM Get_Switches routine. Map switches 63-67.
   - *Hint*: 0xFFFF65FC appears in rev limit area, may be clutch-related.
   - *Hint*: AE5K700V uses: Resume=0xFFFF5FCB, Coast=0xFFFF5FCA, Brake=0xFFFF5FCC, Clutch=0xFFFF65F4.

#### Important (Required for specific features)

4. **hMafCalc / sMafCalc** - MAF calculation hook (for Speed Density)
   - *Hint*: MAF calc literal pool at 0x4A7C-0x4A90.
   - *Hint*: Function start at 0x491C (sts.l pr). hMafCalc is the offset
     where Pull2DFloat is called with MAF sensor voltage.
   - *Hint*: pMassAirFlow write at 0xFFFF40B4, read at 0xFFFF4042.

5. **sCelTrigger / hCelSignal / pCelSignalOem** - CEL flash hooks
   - *Hint*: Search for port F746 references (found at 0xD4C, 0xB5EC, 0xB878, etc.).
   - *Hint*: Follow the README_PORTING.md method: search for "009b1" from end of
     names list, find "extu.w r2,r2" pattern, mark sub3 as sCelTrigger.

6. **hWgdc / sWgdc / hPullWgdc** - WGDC hooks (for per-gear boost/WGDC)
   - *Hint*: The WGDC routine processes descriptors at 0xAA9B8-0xAAA04.
   - *Hint*: Trace from these descriptors to find the calling routine.
   - *Hint*: hWgdc should be a jump table entry that routes to sWgdc.

7. **hPolf / sPolf / hPull3DPolf** - POLF hooks
   - *Hint*: Trace from POLF table addresses (0xD0244, 0xD0404) backward
     through descriptor references to find the fueling routine.

8. **hBaseTiming / sBaseTiming / pBaseTiming / hPull3DTiming** - Timing hooks
   - *Hint*: Task entries 30-37 (0x3FCA2-0x419BA) are timing-related.
   - *Hint*: Task[33] at 0x4ADC4 -> fn_040918 is likely the base timing task.
   - *Hint*: Trace from base timing table addresses to find the hook points.

9. **Load Smoothing** (dLoadSmoothingA/B/Alt/Final)
   - *Hint*: Follow MAF Compensation (IAT) at 0xC3BB0 to find the Engine Load
     calculation subroutine. In graph view, find the smoothing values.

## How to Complete This Port

### Prerequisites

- [Ghidra](https://ghidra-sre.org/) (free) or IDA Pro
- The stock AE5L600L ROM binary
- [MerpMod source](https://github.com/Merp/MerpMod) cloned locally
- [SharpTune](https://github.com/Merp/SharpTune)
- [SubaruDefs](https://github.com/Merp/SubaruDefs)
- Renesas HEW with GNUSH toolchain

### Step-by-Step

1. **Load the ROM in Ghidra**
   - Create a new SH-2 Big-Endian project
   - Set ROM base address to 0x00000000
   - Set RAM base at 0xFFFF8000 (32KB)
   - Import the `AE5L600L` binary

2. **Apply known labels**
   - Use the SharpTune XMLtoIDC function to generate an IDC script from your XML definitions
   - Or manually label the addresses from the `AE5L600L.h` file and `disassembly.txt`

3. **Find the remaining hook addresses** (follow the hints above for each one)
   - The most efficient order is:
     a. Pull2DFloat/Pull3DFloat (verify the candidates at 0xBE608/0xBE830)
     b. Rev Limit (trace from 0xCC500 table reference)
     c. MAF Calc (trace from 0xFFFF4042 usage near 0x491C)
     d. CEL Signal (trace from port F746)
     e. WGDC (trace from descriptors at 0xAA9B8+)
     f. POLF (trace from table addresses)
     g. Timing (trace from task entries 30-37)
     h. Cruise flags (trace SSM switches)

4. **Update `AE5L600L.h`** with the verified addresses

5. **Build MerpMod**
   - Copy `AE5L600L.h` and `AE5L600LConfig.h` to `MerpMod/Targets/`
   - Set `TARGETROM` to `AE5L600L` in HEW
   - Generate the `.map` file using IDAtoHEW
   - Compile and patch

6. **Test carefully**
   - Start with rev limit only (minimal risk)
   - **ALWAYS verify RAM variables at ALL stages of testing**
   - Monitor for corruption, unexpected behavior
   - Add features incrementally

## ROM Memory Map

```
0x00000000-0x00000030  Exception vector table
0x00000BAC-0x00000BFC  NMI handler + default exception handler
0x00000C0C-0x00000D36  Reset / startup initialization
0x0000E628             Scheduler table
0x00014004-0x000F9EE0  Calibration tables (535+)
0x00029858             Helper functions
0x00030674-0x00030A78  Post Start Enrichment code
0x00043470             Low PW Injector Comp gate function
0x00043750-0x00043B62  Knock detection
0x00045BFE-0x00045DD8  FLKC Path J (fast knock correction)
0x000463BA-0x000466A0  FLKC Paths F/G (sustained knock correction)
0x0004A94C             Scheduler periodic dispatch
0x0004AD40-0x0004AE2C  59-entry periodic task table
0x0009A770-0x0009A82B  DTCs
0x000AC948-0x000ACB3F  PSE descriptor table (26 entries)
0x000AD620             AVCS Intake descriptor
0x000AD848             AVCS Exhaust descriptor
0x000AE000+            Low PW Injector Comp descriptors
0x000BE608             Pull2DFloat (candidate)
0x000BE830             Pull3DFloat (candidate)
0x000C0000-0x000FFFFF  Primary calibration data region
0x000DB000-0x000F88FF  ROM HOLE (available for MerpMod code, ~118 KB)

RAM:
0xFFFF8000-0xFFFFB71F  Used RAM variables
0xFFFFB720-0xFFFFBF70  RAM HOLE (available for MerpMod variables, ~2 KB)
0xFFFFBF9F             Memory reset limit
0xFFFFBFA0             Stack pointer (grows down)
```

## Key Differences from AE5K700V

| Item | AE5K700V | AE5L600L | Notes |
|---|---|---|---|
| ROM Hole Start | 0x0E1000 | 0x0DB000 | AE5L600L has more free space |
| RAM Hole Start | 0xFFFFB984 | 0xFFFFB720 | AE5L600L has more free RAM |
| RAM Hole End | 0xFFFFBF70 | 0xFFFFBF70 | Same |
| Pull2DFloat | 0x0BE7F4 | 0x0BE608 | Different offsets |
| Pull3DFloat | 0x0BE8A8 | 0x0BE830 | Different offsets |
| ECU ID location | 0x0DA924 | 0x0D97F0 | Different offset |
| Injector Scaling | 0x0CCA68 | 0x0CCA68 | Same address |
| pMemoryResetLimit | 0xFFFFBF9F | 0xFFFFBF9F | Same |
| Task table entries | 59 | 59 | Same count |
| Task table start | 0x04AD40 | 0x04AD40 | Same address |

## References

- [MerpMod README_PORTING.md](https://github.com/Merp/MerpMod/blob/master/README_PORTING.md) - Official porting guide
- [SharpTune](https://github.com/Merp/SharpTune) - Patch application tool
- [SubaruDefs](https://github.com/Merp/SubaruDefs) - ROM definition files
- `disassembly.txt` - Annotated partial disassembly of AE5L600L
- `AE5L600L 2013 USDM Impreza WRX MT.xml` - RomRaider definition file
