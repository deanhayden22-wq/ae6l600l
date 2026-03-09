# AE5L600L Ghidra Import

ROM: 2013 USDM Subaru WRX Manual Transmission  
ECU: AE5L600L rev 20.x (tiny_wrex build)  
Architecture: Renesas SH-2 / SH-2E, big-endian, 1MB (0x100000)

---

## Ghidra Import Steps

### 1. Create a new Ghidra project
File → New Project → Non-Shared Project → name it `AE5L600L`

### 2. Import the ROM binary
File → Import File → select `AE5L600L_20g_rev_20_2_tiny_wrex.bin`

In the import dialog:
- **Format:** Raw Binary
- **Language:** `SH-2 (Hitachi)/SH2 [default]` — search for "SH-2"
  - Processor: SH-2
  - Endian: big
  - Size: 32
- **Base Address:** `0x00000000`

Click OK, then open the file in CodeBrowser.

### 3. Run the import script
Window → Script Manager → click the green "+" to add a script directory  
Point it at the folder containing `AE5L600L_import.py`  
Find the script in the list → double-click to run

This applies all known symbols, comments, and data types.

### 4. Recommended: Auto-analyze
Analysis → Auto Analyze → accept defaults (SH-2 will disassemble from entry points)  
The script pre-seeds entry points so analysis will find the reset vector and patch code.

---

## What the Script Applies

| Address | Symbol | Notes |
|---------|--------|-------|
| `0x000000` | `VEC_RESET_SP` | Initial SP = 0x00000C0C |
| `0x000004` | `VEC_RESET_PC` | Reset PC = 0xFFFFBFA0 |
| `0x0CC500` | `RevLimit_On_Stock` | 6700.0 RPM fuel cut ON |
| `0x0CC504` | `RevLimit_Off_Stock` | 6680.0 RPM fuel cut OFF |
| `0x0F1000` | `Patch_LC_FFS_Entry` | tinywrex patch code start |
| `0x0F1018` | `Patch_FFS_Path` | FFS branch |
| `0x0F1024` | `Patch_LC_Path` | Launch control branch |
| `0x0F102A` | `Patch_NormalDriving_Path` | Clutch-up normal path |
| `0x0F102C` | `Patch_ApplyDelta` | Common delta application |
| `0x0F1038` | `Patch_Ptr_VehicleSpeedReg` | -> FFFF65FC |
| `0x0F103C` | `Patch_Ptr_ClutchReg` | -> FFFF65D0 |
| `0x0F1040` | `Patch_ReturnAddr` | -> 0x0003B6B2 |
| `0x0F1044` | `Patch_Ptr_RevLimitOn` | -> 0x000CC500 |
| `0x0F1048` | `Param_NormalDriving_RPM_Delta` | 0.0 (should stay 0) |
| `0x0F104C` | `Param_LC_SpeedThreshold_KPH` | ~8.05 kph = ~5 mph |
| `0x0F1050` | `Param_LC_RPM_Delta` | 2700.0 → 4000 RPM cut |
| `0x0F1054` | `Param_FFS_RPM_Delta` | 2000.0 → 4700 RPM cut |
| `0x03B6AE` | `Hook_A_JMP_to_Patch` | JMP into patch (path A) |
| `0x03B6B2` | `Patch_Return_Point` | Patch returns here |
| `0x03B6B8` | `Hook_B_JMP_to_Patch` | JMP into patch (path B) |
| `0x0FFB80` | `Checksum_Table_Header` | ROM integrity table |
| `0x0FFB88` | `Checksum_Entry_0` | Patched entry for tinywrex |
| `0x0F99E0` | `Table_RequestedTorque_SIDrive_Sport` | 3D torque map |
| `0x0F9C60` | `Table_RequestedTorque_SIDrive_SportSharp` | 3D torque map |
| `0x0CD058` | `Axis_FuelInjTrimSmall_RPM` | RPM axis, 8 floats |
| `0x0CD078` | `Table_FuelInjTrimSmall_IFW` | Data, 8 x uint8, x/128 |

---

## Known RAM Registers (not in ROM address space)

These are referenced by patch code but live in SH-2 external RAM:

| Address | Name | Description |
|---------|------|-------------|
| `FFFF65FC` | `RAM_VehicleSpeed` | Vehicle speed, float32 |
| `FFFF65D0` | `RAM_ClutchSwitch` | Clutch pedal state, byte (1=pressed) |
| `FFFF6620` | `RAM_EngineRPM` | Engine RPM, float32 — loaded into FR15 before hooks |

To annotate these in Ghidra, you'd need to add a RAM memory block:  
Memory Map → add block at `0xFFFF0000`, size `0x10000`, type External/Volatile

---

## Patch Logic Summary

```
Entry (F1000):
  FR9 = vehicle_speed (from FFFF65FC)
  FR6 = LC_speed_threshold (from F104C, ~5 mph)
  R0  = clutch_state (from FFFF65D0)

  if clutch == 1:
    FR6 = float(@R9+)   ; inherited R9 -> speed compare prep
    if T==1 (CMP/EQ still set):
      goto LC_Path       ; F1024 -> use F1050 delta
    else:
      goto FFS_Path      ; F1018 -> use F1054 delta
  else:
    FR9 = float(@R6+)   ; inherited R6
    if T==1: goto F102A  ; (never taken, T==0 here)
    else:    goto LC_Path ; (falls through -> F1024 -> F1050)

  NormalDriving_Path (F102A): R0 -> F1048 (delta=0.0)

  ApplyDelta (F102C):
    FR8 = float(@R0)     ; selected delta
    FR15 += FR8          ; adjust effective RPM vs rev limit
    R2  = 0x000CC500     ; RevLimit_On address
    R0  = 0x0003B6B2     ; return address
    JMP @R0              ; return to caller
    FR8 = float(@R2)     ; delay slot: FR8 = 6700.0 RPM
```

Current values in this ROM:
- `F1048` = 0.0 (normal driving: no change) ✓
- `F104C` = 8.05 kph (~5 mph) ✓
- `F1050` = 2700.0 → LC cut = 6700 - 2700 = **4000 RPM** ✓
- `F1054` = 2000.0 → FFS cut = 6700 - 2000 = **4700 RPM** ✓

---

## Adding More Symbols

As you reverse-engineer more of the ROM, add symbols to `AE5L600L_import.py`  
using the same pattern. Run the script again to re-apply.  
This file is the source of truth — the Ghidra project is derived from it.
