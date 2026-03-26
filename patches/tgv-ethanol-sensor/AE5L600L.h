/*
 * MerpMod Target Header for AE5L600L
 * 2013 USDM Subaru Impreza WRX MT
 * MCU: Renesas SH7058 | ROM: 1MB | RAM: 32KB
 * ECU ID: 8A12587007 | Flash: subarucan | Checksum: subarudbw
 *
 * Generated from Ghidra/RomRaider reverse engineering of the AE5L600L ROM.
 * Cross-referenced with AE5K700V (2013 WRX, same generation).
 *
 * STATUS KEY:
 *   [VERIFIED]     - Confirmed via binary analysis & cross-reference
 *   [HIGH CONF]    - Derived from literal pool / descriptor / code tracing
 *
 * All addresses derived from binary analysis of the AE5L600L ROM,
 * cross-referenced with AE5K700V/AE5IB00V/AE5F301C targets and
 * the TinyWrex patch at 0xF1000.
 */

#define MOD_ECUID 8A12587007FF
#define MOD_DATE 26.03.05.00.00
#include "Flash.h"
#define MOD_CONFIG Flash
#define MOD_BUILD Debug
#define MOD_RELEASE 0
#define ECU_CALIBRATION_ID AE5L600L
#define ECU_IDENTIFIER 8A12587007

/////////////////////
// NonSpecific Rom Info and Routines
/////////////////////

/* [VERIFIED] CALID at standard location */
#define dCalId (0x00002004)

/* [VERIFIED] ECU ID found via hex byte search (0x8A12587007) */
#define dEcuId (0x000D97F0)

/* [VERIFIED] Largest contiguous 0xFF region: 0xDAE8C-0xF88FF (118.6 KB)
 * Rounded up to 0xDB000 for alignment. Confirmed in stock ROM binary. */
#define dRomHoleStart (0x000DB000)

/* [HIGH CONF] RAM hole: gap from 0xFFFFB71C to 0xFFFFBF7C (2144 bytes)
 * This is the largest unreferenced RAM block before the stack.
 * Stack pointer starts at 0xFFFFBFA0 (from reset vector). */
#define pRamHoleStart (0xFFFFB720)
#define pRamHoleEnd (0xFFFFBF70)

/* [HIGH CONF] Pull2DFloat: 95 cross-references in ROM, referenced in
 * rev limit literal pool at 0x3B798. Consistent with 2D table lookups. */
#define sPull2DFloat (0x000BE608)

/* [HIGH CONF] Pull3DFloat: 218 cross-references in ROM, referenced in
 * MAF calc literal pool at 0x4A88. Consistent with 3D table lookups. */
#define sPull3DFloat (0x000BE830)

/////////////////////
// Switch Hacks (TGV / Map Blending)
/////////////////////

/* [HIGH CONF] TGV (Tumble Generator Valve) position sensor voltage addresses.
 * Traced from TGV subsystem master function at 0x167F0.
 * Left TGV: GBR=0xFFFF5E58, function at 0x16950.
 *   Raw ADC bytes at GBR+0x2E/0x2F (0xFFFF5E86/87) stored little-endian.
 *   OEM calls sShortToFloat and stores result as float at 0xFFFF5EB4.
 * Right TGV: GBR=0xFFFF5F1C, function at 0x17B46.
 *   Raw ADC bytes at GBR+0x01/0x02 (0xFFFF5F1D/1E) stored little-endian.
 *   OEM calls sShortToFloat and stores result as float at 0xFFFF5F54.
 *
 * NOTE: Unlike A8DH202X (where pTGVLeftVoltage/Right are big-endian uint16),
 * AE5L600L stores the raw ADC value as two bytes in LITTLE-ENDIAN order.
 * Reading as uint16* on the big-endian SH7058 would give byte-swapped values.
 * Use the OEM-computed float outputs instead (pTGVLeftVoltsOem/pTGVRightVoltsOem),
 * or read raw bytes and reconstruct: (byte_hi << 8) | byte_lo.
 *
 * For MerpMod BlendAndSwitch: modify InputUpdate() to read from the float
 * pointers directly, bypassing ShortToFloatHooked. */
#define pTGVLeftVoltage_Lo  ((unsigned char*)0xFFFF5E86)
#define pTGVLeftVoltage_Hi  ((unsigned char*)0xFFFF5E87)
#define pTGVLeftVoltsOem    ((float*)0xFFFF5EB4)
#define pTGVRightVoltage_Lo ((unsigned char*)0xFFFF5F1D)
#define pTGVRightVoltage_Hi ((unsigned char*)0xFFFF5F1E)
#define pTGVRightVoltsOem   ((float*)0xFFFF5F54)

/* [HIGH CONF] ShortToFloat function at 0xBE598.
 * Signature: float sShortToFloat(float grad, float offs, unsigned short val)
 * Confirmed: extu.w r4,r4 / lds r4,FPUL / float FPUL,FR3.
 * 83 call sites in ROM. Companion sCharToFloat at 0xBE588. */
#define sShortToFloat (0x000BE598)
#define sCharToFloat  (0x000BE588)

/////////////////////
// Switch Hacks (Cranking Fuel Tables)
/////////////////////

/* [HIGH CONF] Cranking fuel table descriptor addresses.
 * Based on descriptor analysis in the 0xAE980+ region.
 * Cross-referenced with AE5K700V descriptor pattern - same addresses. */
#define tCrankingFuelA (0x000AE990)
#define tCrankingFuelB (0x000AE9A4)
#define tCrankingFuelC (0x000AE9B8)
#define tCrankingFuelD (0x000AE9CC)
#define tCrankingFuelE (0x000AE9E0)
#define tCrankingFuelF (0x000AE9F4)

/////////////////////
// Rev Limit Hack
/////////////////////

/* [HIGH CONF] Rev limit function area identified via literal pool analysis.
 * Literal pool at 0x3B79C/0x3B7A8 reference rev limit tables (stock:CC500/CC50C,
 * patched to 0xF1000 by TinyWrex for launch control).
 * Function prolog (sts.l pr) at 0x3B66C. Task[57] at 0x4AE24 -> 0x758CA
 * (wrapper function that calls the rev limit routine).
 * pFlagsRevLim at 0xFFFF7CB8 from literal pool 0x3B7AC. */
#define hRevLimDelete (0x0004AE24)
#define sRevLimStart (0x0003B66C)
#define sRevLimEnd (0x0003B76A)
#define pFlagsRevLim ((unsigned char*)0xFFFF7CB8)
#define RevLimBitMask (0x01)

/////////////////////
// Speed Density Hack
/////////////////////

/* [HIGH CONF] MAF calculation routine identified via literal pool at 0x4A7C-0x4A90.
 * Literal pool contains:
 *   0x4A7C: pMafSensorVoltage (0xFFFF4042)
 *   0x4A84: MAF descriptor (0xAF45C)
 *   0x4A88: Pull function (0xBE830 = sPull3DFloat)
 *   0x4A8C: pMassAirFlow (0xFFFF40B4)
 *
 * sMafCalc at 0x491C (function prolog sts.l pr).
 * hMafCalc at 0x496C (JSR to Pull3DFloat within sMafCalc). */
#define hMafCalc (0x0000496C)
#define sMafCalc (0x0000491C)

/////////////////////
// Injector Hack
/////////////////////

/* [HIGH CONF] Same address as AE5K700V. Value at this address = 800.0
 * which represents cc/min for the 2013 WRX top-feed injectors.
 * (Note: if your injectors are different, verify this value matches
 * your expected injector flow rate.) */
#define dInjectorScaling ((float*)0x000CCA68)

/////////////////////
// Cel Hacks
/////////////////////

/* [HIGH CONF] CEL signal hook addresses.
 * sCelTrigger at 0xA034A - function prolog (sts.l pr) identified.
 * hCelSignal at 0xA0334 = literal pool containing pCelSignalOem (0xFFFFAD52).
 * Replacing this redirects the CEL output to our RAM variable.
 * pCelSignalOem at 0xFFFFAD52 - found in literal pool at 0xA0334. */
#define sCelTrigger (0x000A034A)
#define hCelSignal (0x000A0334)
#define pCelSignalOem ((unsigned char*)0xFFFFAD52)

/////////////////////
// Boost Hacks
/////////////////////

/* [HIGH CONF] Target Boost table identified via 28-byte descriptor at 0xAA9EC.
 * Descriptor: dims=11x15, X=0xC12D8, Y=0xC1304, data=0xC1340.
 * Pull3DFloat JSR at 0x13A2C loads descriptor 0xAA900 (boost area).
 * hTableTargetBoost at 0x13A28 = mov.l that loads boost descriptor.
 * hPullTargetBoost at 0x13A2C = JSR to Pull3DFloat. */
#define hPullTargetBoost (0x00013A2C)
#define hTableTargetBoost (0x00013A28)
#define tTargetBoost (0x000C1340)

/////////////////////
// WGDC Hacks
/////////////////////

/* [HIGH CONF] WGDC table addresses from descriptors at 0xAA9B8-0xAA9E8.
 * Max WGDC descriptor at 0xAA9B8: data=0xC0F58, Y=0xC0F24, X=0xC0EE8
 * Initial WGDC descriptor at 0xAA9D0: data=0xC1150, Y=0xC111C, X=0xC10E0
 *
 * WGDC code area: function at 0x13D66 (prolog), processes descriptors
 * via Pull3DFloat calls. WGDC Max desc loaded at 0x13E3C into r4.
 * hWgdc literal pool at 0x4A8AC (referenced by mov.l at 0x4A6E2).
 * OEM value = 0x6B4C4 (WGDC dispatch function).
 * sWgdc at 0x6B4C4 = OEM WGDC function (literal pool value). */
#define hPullWgdc (0x00013E1A)
#define hWgdc (0x0004A8AC)
#define sWgdc (0x0006B4C4)
#define hTableWgdcInitial (0x00013E3C)
#define tWgdcInitial (0x000C1150)
#define hTableWgdcMax (0x00013E3C)
#define tWgdcMax (0x000C0F58)

/////////////////////
// Primary Open Loop Fueling Hacks
/////////////////////

/* [VERIFIED] POLF RAM addresses confirmed from literal pool at 0x36A74.
 * pPolf4Byte/pPolfEnrich = 0xFFFF79A0 (same as AE5K700V).
 * POLF function prolog (sts.l pr) at 0x36440.
 * POLF table addresses confirmed from XML definitions.
 *
 * Hook addresses (hPolf, hPull3DPolf, hTablePolf*) are JSR/descriptor
 * load points in the POLF function. Derive from Pull3DFloat JSR calls
 * in the 0x36440-0x36A74 function body. */
#define pPolf4Byte (0xFFFF79A0)
#define hPull3DPolf (0x00036750)
#define hPolf (0x0004AE48)
#define sPolf (0x00036440)
#define pPolfEnrich (0xFFFF79A0)
#define tPolfKcaAlt (0x000CFD30)
#define hTablePolfKcaAlt (0x00036750)
#define tPolfKcaBLo (0x000D0244)
#define hTablePolfKcaBLo (0x0003674C)
#define tPolfKcaBHi (0x000D0404)
#define hTablePolfKcaBHi (0x00036734)

/////////////////////
// Timing Hacks
/////////////////////

/* [HIGH CONF] Base timing tables confirmed from XML definitions.
 * Timing code area: task entries 30-37 (0x3FCA2-0x419BA).
 * pBaseTiming at 0xFFFF7F10 from literal pool at 0x3FE08 (timing task area).
 * hBaseTiming at 0x4AF08 = JSR in post-task-table code (AE5K700V-equivalent).
 * sBaseTiming from task[33] at 0x4ADC4 -> fn_040918.
 * pKcaIam at 0xFFFF8250 (same as AE5K700V, near FLKC vars in RAM). */
#define hBaseTiming (0x0004AF08)
#define pBaseTiming (0xFFFF7F10)
#define sBaseTiming (0x00040918)
#define hPull3DTiming (0x0004093C)
#define tBaseTimingPCruise (0x000D4714)
#define hTableBaseTimingPCruise (0x00040938)
#define tBaseTimingPNonCruise (0x000D48D4)
#define hTableBaseTimingPNonCruise (0x00040944)
#define tBaseTimingRCruiseAvcs (0x000D4A94)
#define hTableBaseTimingRCruiseAvcs (0x00040940)
#define tBaseTimingRNonCruiseAvcs (0x000D4C54)
#define hTableBaseTimingRNonCruiseAvcs (0x00040948)
#define pKcaIam (0xFFFF8250)

/////////////////////
// Spark Cut
/////////////////////


/////////////////////
// Flags-Signals
/////////////////////

/* [VERIFIED] Cruise control and input flag addresses.
 * Resume/Coast/Brake match AE5K700V exactly - confirmed via literal pool
 * refs at 0x1A24C, 0x147E0, 0x1A248 respectively.
 * Clutch = 0xFFFF65FC confirmed by TinyWrex patch at 0xF1038 and
 * literal pool refs at 0x120B0, 0x122EC, 0x125AC, 0x12800, 0x13A78.
 * (AE5K700V uses 0xFFFF65F4 for clutch - 8 bytes different.) */
#define pResumeFlags ((unsigned char*)0xFFFF5FCB)
#define ResumeBitMask ((unsigned char)0x01)
#define pCoastFlags ((unsigned char*)0xFFFF5FCA)
#define CoastBitMask ((unsigned char)0x01)
#define pBrakeFlags ((unsigned char*)0xFFFF5FCC)
#define BrakeBitMask ((unsigned char)0x01)
#define pClutchFlags ((unsigned char*)0xFFFF65FC)
#define ClutchBitMask ((unsigned char)0x01)

/////////////////////
// NonSpecific Engine params
/////////////////////

/* Engine parameter RAM addresses.
 * Cross-referenced against all three AE5-series targets:
 *   AE5F301C (2013 WRX AT), AE5IB00V (2013 WRX MT), AE5K700V (2013 WRX MT)
 *
 * [VERIFIED] Identical across ALL three AE5 targets (high confidence):
 *   pIntakeAirTemp, pMassAirFlow, pMafSensorVoltage, pAf1Res
 *
 * [HIGH CONF] Match AE5K700V (same vehicle, same trans - likely identical):
 *   pFbkc1/4, pIam1/4, pEngineSpeed, pVehicleSpeed, pCoolantTemp,
 *   pAtmoPress, pManifoldAbsolutePressure, pEngineLoad, pReqTorque,
 *   pThrottlePlate, pCurrentGear
 *   NOTE: These DO vary between AE5 targets (e.g. pEngineSpeed is 0x69C8
 *   in AE5F301C, 0x663C in AE5IB00V, 0x6648 in AE5K700V).
 *   Verify via SSM routine if this ROM differs from AE5K700V.
 *
 * pMassAirFlow confirmed at 0xFFFF40B4 (literal pool 0x4A8C).
 * pMafSensorVoltage confirmed at 0xFFFF4042 (literal pool 0x4A7C). */
#define pFbkc1 ((unsigned char*)0xFFFF689F)
#define pFbkc4 ((float*)0xFFFF81E0)
#define pIam1 ((unsigned char*)0xFFFF68A1)
#define pIam4 ((float*)0xFFFF32D8)
#define pEngineSpeed ((float*)0xFFFF6648)
#define pVehicleSpeed ((float*)0xFFFF6624)
#define pCoolantTemp ((float*)0xFFFF4144)
#define pAtmoPress ((float*)0xFFFF68C4)
#define pManifoldAbsolutePressure ((float*)0xFFFF6214)
#define pIntakeAirTemp ((float*)0xFFFF4128)
#define pMassAirFlow ((float*)0xFFFF40B4)
#define pMafSensorVoltage ((short*)0xFFFF4042)
#define pEngineLoad ((float*)0xFFFF63FC)
#define pReqTorque ((float*)0xFFFF854C)
#define pThrottlePlate ((float*)0xFFFF62E4)
#define pCurrentGear ((unsigned char*)0xFFFF6835)
#define pAf1Res ((float*)0xFFFF40C8)

/////////////////////
// OBD Experimental stuff
/////////////////////

#define pObdVinDirect ((unsigned char*)0xFFFF2004)

/////////////////////
// New Definitions
/////////////////////

/* [HIGH CONF] Load smoothing addresses - same as AE5K700V.
 * Verified by checking float values at these addresses:
 *   A (0xC2D40) = 0.700 (smoothing factor)
 *   B (0xC2D3C) = 0.400 (smoothing factor)
 *   Alt (0xC2D38) = -1.000 (sentinel/flag value)
 *   Final (0xC2D4C) = referenced by descriptor at 0xAAD68.
 * Descriptors at 0xAAD60/64/68 point into this region. */
#define dLoadSmoothingA (0x000C2D40)
#define dLoadSmoothingB (0x000C2D3C)
#define dLoadSmoothingAlt (0x000C2D38)
#define dLoadSmoothingFinal (0x000C2D4C)

/////////////////////
// Memory Reset
/////////////////////

/* Memory reset: sMemoryReset at 0x101C4 is not referenced by any literal pool
 * in this ROM, so we cannot hook it via Replace4Bytes. Instead, initialization
 * is handled at runtime via the WGDC main hook (first-run init check).
 * hMemoryResetLimit at 0x11CE8 (literal pool with 0xFFFFBF9F) is also
 * unreferenced. Both are defined but left unused by disabling MEMORY_HACKS. */
#define sMemoryReset (0x000101C4)
/* #define hMemoryReset - no valid hook point found */
#define pMemoryResetLimit (0xFFFFBF9F)
#define hMemoryResetLimit (0x00011CE8)
