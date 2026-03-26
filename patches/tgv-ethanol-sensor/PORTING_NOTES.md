# MerpMod Port: AE5L600L (2013 USDM Impreza WRX MT)

## Overview

This document describes the port of [MerpMod](https://github.com/Merp/MerpMod) to the **AE5L600L** ROM (2013 USDM Subaru Impreza WRX, manual transmission, SH7058).

AE5L600L is **not** in MerpMod's supported ROM list (166 targets). The closest supported AE5-series ROMs are AE5F301C, AE5IB00V, and AE5K700V. This port is based primarily on cross-referencing with **AE5K700V** (also a 2013 WRX MT).

All addresses in `AE5L600L.h` have been derived from binary analysis of the ROM, cross-referenced against the three existing AE5 targets, and verified via literal pool tracing, descriptor analysis, and the TinyWrex patch at 0xF1000.

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

## Address Derivation Summary

### Verified Addresses (binary analysis + cross-reference)

| Define | Address | Method |
|---|---|---|
| `dCalId` | 0x002004 | Standard location, string verified |
| `dEcuId` | 0x0D97F0 | Hex byte search for 8A12587007 |
| `dRomHoleStart` | 0x0DB000 | Binary scan: 0xFF from 0xDAE8C-0xF88FF (118.6 KB) |
| `pRamHoleStart` | 0xFFFFB720 | RAM reference gap analysis |
| `pRamHoleEnd` | 0xFFFFBF70 | Largest unreferenced RAM gap (2144 bytes) |
| `pMemoryResetLimit` | 0xFFFFBF9F | Literal pool at 0x11CE8 |
| `pResumeFlags` | 0xFFFF5FCB | Literal pool refs at 0x1A24C+ (same as AE5K700V) |
| `pCoastFlags` | 0xFFFF5FCA | Literal pool refs at 0x147E0+ (same as AE5K700V) |
| `pBrakeFlags` | 0xFFFF5FCC | Literal pool refs at 0x1A248+ (same as AE5K700V) |
| `pClutchFlags` | 0xFFFF65FC | TinyWrex patch at 0xF1038 + literal pools at 0x120B0+ |
| `pPolf4Byte` | 0xFFFF79A0 | Literal pool at 0x36A74 (same as AE5K700V) |
| `pCelSignalOem` | 0xFFFFAD52 | Literal pool at 0xA0334 |
| `pMassAirFlow` | 0xFFFF40B4 | Literal pool at 0x4A8C (identical across all AE5 targets) |
| `pMafSensorVoltage` | 0xFFFF4042 | Literal pool at 0x4A7C (identical across all AE5 targets) |
| `pIntakeAirTemp` | 0xFFFF4128 | Identical across all AE5 targets |
| `pAf1Res` | 0xFFFF40C8 | Identical across all AE5 targets |

### High-Confidence Addresses (literal pool / descriptor / code tracing)

| Define | Address | Evidence |
|---|---|---|
| `sPull2DFloat` | 0x0BE608 | 95 XREF in ROM, used by rev limit code |
| `sPull3DFloat` | 0x0BE830 | 218 XREF in ROM, used by MAF calc code |
| `hMafCalc` | 0x0496C | JSR to Pull3DFloat within sMafCalc function |
| `sMafCalc` | 0x0491C | Function prolog (sts.l pr) |
| `hRevLimDelete` | 0x4AE24 | Task table entry [57] |
| `sRevLimStart` | 0x3B66C | Function prolog (sts.l pr) |
| `sRevLimEnd` | 0x3B76A | rts instruction |
| `pFlagsRevLim` | 0xFFFF7CB8 | Literal pool at 0x3B7AC |
| `sCelTrigger` | 0xA034A | Function prolog (sts.l pr) |
| `hCelSignal` | 0xA03CE | Offset +0x84 from sCelTrigger (matches AE5K700V pattern) |
| `hWgdc` | 0x4A6E4 | JSR in main dispatch (same addr as AE5K700V, verified) |
| `sWgdc` | 0x13774 | WGDC subroutine, code verified at address |
| `hPullWgdc` | 0x13E1A | JSR @r13 to Pull3DFloat in WGDC function |
| `hTableWgdcMax` | 0x13E3C | mov.l that loads WGDC Max descriptor (0xAA9B8) |
| `hPullTargetBoost` | 0x13A2C | JSR to Pull3DFloat in boost area |
| `hTableTargetBoost` | 0x13A28 | mov.l that loads boost descriptor (0xAA900) |
| `hBaseTiming` | 0x4AF08 | JSR in post-task-table code |
| `sBaseTiming` | 0x40918 | Task[33] function entry |
| `pBaseTiming` | 0xFFFF7F10 | Literal pool at 0x3FE08 (timing task area) |
| `pKcaIam` | 0xFFFF8250 | Same as AE5K700V, near FLKC vars in RAM |
| `sPolf` | 0x36440 | Function prolog (sts.l pr) |
| `hPolf` | 0x4AE48 | Post-task-table code (same as AE5K700V) |
| All timing tables | Various | XML definition confirmed |
| All POLF tables | Various | XML definition confirmed |
| All WGDC/Boost tables | Various | Descriptor analysis + XML confirmed |
| `dLoadSmoothingA/B/Alt/Final` | 0xC2D38-0xC2D4C | Same as AE5K700V, float values verified |
| `dInjectorScaling` | 0x0CCA68 | Same as AE5K700V, value = 800.0 |
| `sMemoryReset` | 0x0101C4 | sts.l pr prolog found |
| `hMemoryReset` | 0x00FC20 | Near memory reset call chain |
| `hMemoryResetLimit` | 0x011CE8 | Literal pool containing pMemoryResetLimit |
| `sShortToFloat` | 0x0BE598 | extu.w/lds/float sequence, 83 call sites |
| `sCharToFloat` | 0x0BE588 | Byte-to-float companion function |
| `pTGVLeftVoltsOem` | 0xFFFF5EB4 | OEM float output from Left TGV ADC (see TGV section) |
| `pTGVRightVoltsOem` | 0xFFFF5F54 | OEM float output from Right TGV ADC (see TGV section) |
| Engine params | Various | Cross-referenced with AE5K700V (same gen MT) |

## TGV Position Sensor Mapping (Ethanol Sensor / Map Blending)

### Overview

The TGV (Tumble Generator Valve) position sensors provide two 0-5V analog inputs that can be repurposed for ethanol content sensing or general-purpose map blending when the TGVs are deleted.

### How TGV Voltage Processing Works on AE5L600L

The TGV subsystem is managed by a master function at **0x167F0** dispatched from the task table at 0x493A4. It uses GBR-relative addressing for two separate data structures:

| | Left TGV | Right TGV |
|---|---|---|
| GBR base | `0xFFFF5E58` | `0xFFFF5F1C` |
| Processing function | `0x16950` | `0x17B46` |
| Raw ADC low byte | `0xFFFF5E86` (GBR+0x2E) | `0xFFFF5F1D` (GBR+0x01) |
| Raw ADC high byte | `0xFFFF5E87` (GBR+0x2F) | `0xFFFF5F1E` (GBR+0x02) |
| **OEM float output** | **`0xFFFF5EB4`** | **`0xFFFF5F54`** |

The OEM code reads two bytes, reconstructs a 16-bit value as `(high_byte << 8) | low_byte` (little-endian storage), then calls `sShortToFloat` at 0xBE598 to convert to a float voltage. The result is stored at the float output address.

### Key Difference from A8DH202X

On **A8DH202X** (the only MerpMod target with TGV defines), the raw ADC values are stored as big-endian `uint16` at adjacent addresses:
```c
#define pTGVLeftVoltage  ((unsigned short*)0xFFFF5C0A)  // A8DH202X
#define pTGVRightVoltage ((unsigned short*)0xFFFF5C0C)  // A8DH202X
```

On **AE5L600L**, the raw ADC bytes are stored in **little-endian** order within GBR-relative structures. A direct `uint16*` dereference on the big-endian SH7058 would give **byte-swapped** values. The OEM float outputs are the correct way to read these values.

### Integration with MerpMod BlendAndSwitch

MerpMod's stock `InputUpdate()` in `BlendAndSwitch.c` does:
```c
pRamVariables->TGVLeftVolts = ShortToFloatHooked(*pTGVLeftVoltage, grad, offs);
```

For AE5L600L, replace with direct float reads:
```c
pRamVariables->TGVLeftVolts = *pTGVLeftVoltsOem;
pRamVariables->TGVRightVolts = *pTGVRightVoltsOem;
```

This skips the `ShortToFloatHooked` call entirely since the OEM already computes the voltage float. The rest of `InputUpdate()` (scaling tables, blend ratio, map switch logic) works unchanged.

### Ethanol Sensor Wiring

To use as an ethanol content blender:
1. Wire ethanol sensor (with freq-to-voltage converter) to one TGV input connector
2. Disable TGV DTCs: P2004-P2012, P2016-P2022 (addresses `0x9A7CE`-`0x9A7DA`)
3. Configure `MapBlendingInputMode = MapBlendingInputModeTGVLeft` (or Right)
4. Tune the `TGVLeftScaling` table to map your sensor's voltage range to 0.0-1.0
5. Map1 = gasoline calibration, Map2 = E85 calibration
6. Intermediate blends (E30, E50, etc.) are handled automatically

## How to Build

### Prerequisites

- [MerpMod source](https://github.com/Merp/MerpMod) cloned locally
- [SharpTune](https://github.com/Merp/SharpTune)
- [SubaruDefs](https://github.com/Merp/SubaruDefs)
- Renesas HEW with GNUSH toolchain

### Steps

1. **Copy target files** to `MerpMod/Targets/`:
   - `AE5L600L.h`
   - `AE5L600LConfig.h`

2. **Generate `.map` file** using IDAtoHEW or SharpTune's XMLtoIDC

3. **Set `TARGETROM`** to `AE5L600L` in the HEW project settings

4. **Compile and patch** - MerpMod will use the addresses in `AE5L600L.h` to hook into the stock ROM code

5. **Test carefully**
   - Start with rev limit only (minimal risk)
   - **ALWAYS verify RAM variables at ALL stages**
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
0x000BE608             Pull2DFloat
0x000BE830             Pull3DFloat
0x000C0000-0x000FFFFF  Primary calibration data region
0x000DB000-0x000F88FF  ROM HOLE (available for MerpMod code, ~118 KB)

RAM:
0xFFFF8000-0xFFFFB71F  Used RAM variables
0xFFFFB720-0xFFFFBF70  RAM HOLE (available for MerpMod variables, ~2 KB)
0xFFFFBF9F             Memory reset limit
0xFFFFBFA0             Stack pointer (grows down)
```

## Cross-Reference: All AE5-Series Targets

Addresses **identical** across all three existing AE5 targets (high confidence for AE5L600L):

| Parameter | AE5F301C | AE5IB00V | AE5K700V | AE5L600L |
|---|---|---|---|---|
| pIntakeAirTemp | 0xFFFF4128 | 0xFFFF4128 | 0xFFFF4128 | 0xFFFF4128 |
| pMassAirFlow | 0xFFFF40B4 | 0xFFFF40B4 | 0xFFFF40B4 | 0xFFFF40B4 |
| pMafSensorVoltage | 0xFFFF4042 | 0xFFFF4042 | 0xFFFF4042 | 0xFFFF4042 |
| pAf1Res | 0xFFFF40C8 | 0xFFFF40C8 | 0xFFFF40C8 | 0xFFFF40C8 |
| pObdVinDirect | 0xFFFF2004 | - | 0xFFFF2004 | 0xFFFF2004 |
| pMemoryResetLimit | 0xFFFFBF9F | 0xFFFFBF9F | 0xFFFFBF9F | 0xFFFFBF9F |
| dCalId | 0x2004 | 0x2004 | 0x2004 | 0x2004 |

Addresses that **vary** between AE5 targets (our values determined via binary analysis):

| Parameter | AE5F301C | AE5IB00V | AE5K700V | AE5L600L |
|---|---|---|---|---|
| pEngineSpeed | 0xFFFF69C8 | 0xFFFF663C | 0xFFFF6648 | 0xFFFF6648 |
| pVehicleSpeed | - | 0xFFFF6618 | 0xFFFF6624 | 0xFFFF6624 |
| pCoolantTemp | - | 0xFFFF4140 | 0xFFFF4144 | 0xFFFF4144 |
| pClutchFlags | 0xFFFF6974 | 0xFFFF65E8 | 0xFFFF65F4 | 0xFFFF65FC |
| pResumeFlags | 0xFFFF6317 | 0xFFFF5FBF | 0xFFFF5FCB | 0xFFFF5FCB |
| pCoastFlags | 0xFFFF6316 | 0xFFFF5FBE | 0xFFFF5FCA | 0xFFFF5FCA |
| pBrakeFlags | 0xFFFF6318 | 0xFFFF5FC0 | 0xFFFF5FCC | 0xFFFF5FCC |
| pBaseTiming | 0xFFFF7B58 | 0xFFFF7B38 | 0xFFFF7F20 | 0xFFFF7F10 |
| pFlagsRevLim | - | 0xFFFF7904 | 0xFFFF7CD0 | 0xFFFF7CB8 |
| pCelSignalOem | 0xFFFF9C5A | 0xFFFFA7AA | 0xFFFFAEEE | 0xFFFFAD52 |
| sPull2DFloat | 0xBE990 | 0xBE7F4 | 0xBE7F4 | 0xBE608 |
| sPull3DFloat | 0xBEA44 | 0xBE8A8 | 0xBE8A8 | 0xBE830 |
| hMafCalc | 0x4800 | 0x49E8 | 0x49E8 | 0x496C |
| dRomHoleStart | 0xE1000 | 0xE1000 | 0xE1000 | 0xDB000 |
| dInjectorScaling | 0xC8A70 | 0xCBEF0 | 0xCCA68 | 0xCCA68 |

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
| pClutchFlags | 0xFFFF65F4 | 0xFFFF65FC | +8 bytes |
| pFlagsRevLim | 0xFFFF7CD0 | 0xFFFF7CB8 | -24 bytes |
| pBaseTiming | 0xFFFF7F20 | 0xFFFF7F10 | -16 bytes |
| pCelSignalOem | 0xFFFFAEEE | 0xFFFFAD52 | Different region |
| Task table entries | 59 | 59 | Same count |
| Task table start | 0x04AD40 | 0x04AD40 | Same address |

## TinyWrex Patch Analysis

The ROM binary (`AE5L600L 20g rev 20 tiny wrex.bin`) contains an existing TinyWrex patch at **0xF1000** that implements launch control:

- Patches literal pool at 0x3B79C and 0x3B7A8 (rev limit table pointers) to redirect to 0xF1000
- At 0xF1000: checks clutch flag (0xFFFF65FC) and vehicle speed (0xFFFF65D0)
- Jumps back to rev limit code at 0x3B6B2 to apply modified rev limit
- References Rev Limit On table at 0xCC500 and launch control parameters at 0xF1048-0xF1054

This patch confirmed the pClutchFlags address (0xFFFF65FC) and the rev limit code area (0x3B66C-0x3B7BC).

## References

- [MerpMod README_PORTING.md](https://github.com/Merp/MerpMod/blob/master/README_PORTING.md) - Official porting guide
- [SharpTune](https://github.com/Merp/SharpTune) - Patch application tool
- [SubaruDefs](https://github.com/Merp/SubaruDefs) - ROM definition files
- `disassembly.txt` - Annotated partial disassembly of AE5L600L
- `AE5L600L 2013 USDM Impreza WRX MT.xml` - RomRaider definition file
- `AE5L600L 20g AI rev 16 RA gears timing avcs.bin.xml` - Ghidra project export
