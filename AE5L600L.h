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
 *   [HIGH CONF]    - Derived from literal pool / descriptor analysis
 *   [NEEDS VERIFY] - Requires Ghidra/IDA verification before use
 *
 * WARNING: Several hook addresses (marked NEEDS VERIFY) require manual
 * confirmation in a disassembler before flashing. See PORTING_NOTES.md.
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
// Switch Hacks (Cranking Fuel Tables)
/////////////////////

/* [NEEDS VERIFY] Cranking fuel table descriptor addresses.
 * Based on descriptor analysis in the 0xAE980+ region.
 * Cross-reference with AE5K700V descriptor pattern. */
#define tCrankingFuelA (0x000AE990)
#define tCrankingFuelB (0x000AE9A4)
#define tCrankingFuelC (0x000AE9B8)
#define tCrankingFuelD (0x000AE9CC)
#define tCrankingFuelE (0x000AE9E0)
#define tCrankingFuelF (0x000AE9F4)

/////////////////////
// Rev Limit Hack
/////////////////////

/* [NEEDS VERIFY] Rev limit function area identified via literal pool analysis.
 * Literal pool at 0x3B79C contains Rev Limit On (0xCC500) reference.
 * Code loading rev limit at 0x3B6AE. Function prolog (sts.l pr) at 0x3B66C.
 * Task table entry not directly found - rev limit may be called from
 * a subtask rather than being a direct task table entry.
 *
 * hRevLimDelete: The task table or jump table entry that calls the rev lim fn.
 *   In AE5K700V this was the last task entry. In our ROM, the task table
 *   ends at 0x4AE2C (terminator). Check task entries 49-58 or trace
 *   the call chain to the rev limit function at ~0x3B66C.
 *
 * sRevLimStart: The start of the rev limit routine (~0x3B66C based on
 *   sts.l pr prolog found there).
 *
 * sRevLimEnd: The end/exit branch of the rev limit routine (~0x3B76A
 *   based on rts found there).
 *
 * pFlagsRevLim: Rev limit flags byte at 0xFFFF7CB8 (from literal pool 0x3B7AC).
 */
/* TODO: Verify these in Ghidra by tracing from Rev Limit On table */
#define hRevLimDelete (0x0004AE24)
#define sRevLimStart (0x0003B66C)
#define sRevLimEnd (0x0003B76A)
#define pFlagsRevLim ((unsigned char*)0xFFFF7CB8)
#define RevLimBitMask (0x01)

/////////////////////
// Speed Density Hack
/////////////////////

/* [NEEDS VERIFY] MAF calculation routine identified via literal pool at 0x4A7C-0x4A90.
 * Literal pool contains:
 *   0x4A7C: pMafSensorVoltage (0xFFFF4042)
 *   0x4A84: MAF descriptor (0xAF45C)
 *   0x4A88: Pull function (0xBE830)
 *   0x4A8C: pMassAirFlow (0xFFFF40B4)
 *
 * sMafCalc: Function start appears to be at 0x491C (sts.l pr prolog).
 * hMafCalc: The specific offset within sMafCalc where the Pull2DFloat
 *   call occurs for the MAF sensor voltage -> airflow lookup.
 *   Needs Ghidra trace from sMafCalc to the bsr/jsr that calls Pull2DFloat. */
/* TODO: Verify exact hMafCalc offset in Ghidra */
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

/* [NEEDS VERIFY] CEL signal hook addresses.
 * Port 0xF746 references found at multiple code locations.
 * sCelTrigger and hCelSignal need Ghidra verification.
 * Search for the "extu.w r2,r2" pattern after the 009b1 DTC reference
 * as described in README_PORTING.md.
 * Alternatively, search port F746 references and find the one with
 * a nearby RAM write (that's pCelSignalOem). */
/* TODO: Find via Ghidra - trace from port F746 references */
// #define sCelTrigger (0x00000000)
// #define hCelSignal (0x00000000)
// #define pCelSignalOem ((unsigned char*)0x00000000)

/////////////////////
// Boost Hacks
/////////////////////

/* [HIGH CONF] Target Boost table identified via 28-byte descriptor at 0xAA9EC.
 * Descriptor: dims=11x15, X=0xC12D8, Y=0xC1304, data=0xC1340.
 * hPullTargetBoost/hTableTargetBoost need Ghidra trace from the
 * WGDC/boost control routine. */
/* TODO: Verify hook addresses in Ghidra by tracing boost control code */
// #define hPullTargetBoost (0x00000000)
// #define hTableTargetBoost (0x00000000)
#define tTargetBoost (0x000C1340)

/////////////////////
// WGDC Hacks
/////////////////////

/* [HIGH CONF] WGDC table addresses from descriptors at 0xAA9B8-0xAA9E8.
 * Max WGDC descriptor at 0xAA9B8: data=0xC0F58, Y=0xC0F24, X=0xC0EE8
 * Initial WGDC descriptor at 0xAA9D0: data=0xC1150, Y=0xC111C, X=0xC10E0
 *
 * The hWgdc hook is a jump table entry that calls the WGDC routine.
 * sWgdc is the WGDC routine itself. Both need Ghidra verification.
 * Trace from the WGDC descriptors backward to find the code that
 * loads and processes them. */
/* TODO: Find hWgdc (jump table entry) and sWgdc (routine start) in Ghidra */
// #define hPullWgdc (0x00000000)
// #define hWgdc (0x00000000)
// #define sWgdc (0x00000000)
// #define hTableWgdcInitial (0x00000000)
#define tWgdcInitial (0x000C1150)
// #define hTableWgdcMax (0x00000000)
#define tWgdcMax (0x000C0F58)

/////////////////////
// Primary Open Loop Fueling Hacks
/////////////////////

/* [HIGH CONF] POLF table addresses confirmed from XML definitions.
 * The POLF hook/routine addresses need Ghidra verification.
 * In AE5K700V, POLF is an alternative main hook when WGDC isn't available. */
/* TODO: Find hPolf, sPolf, hPull3DPolf in Ghidra */
// #define pPolf4Byte (0x00000000)
// #define hPull3DPolf (0x00000000)
// #define hPolf (0x00000000)
// #define sPolf (0x00000000)
// #define pPolfEnrich (0x00000000)
#define tPolfKcaAlt (0x000CFD30)
// #define hTablePolfKcaAlt (0x00000000)
#define tPolfKcaBLo (0x000D0244)
// #define hTablePolfKcaBLo (0x00000000)
#define tPolfKcaBHi (0x000D0404)
// #define hTablePolfKcaBHi (0x00000000)

/////////////////////
// Timing Hacks
/////////////////////

/* [HIGH CONF] Base timing table addresses confirmed from XML definitions.
 * The timing hook addresses need Ghidra verification.
 * Task entries 30-37 point to timing-area code (0x3FCA2-0x419BA). */
/* TODO: Find hBaseTiming, sBaseTiming, pBaseTiming, hPull3DTiming in Ghidra.
 * Start by examining task[33] at 0x4ADC4 -> fn_040918 */
// #define hBaseTiming (0x00000000)
// #define pBaseTiming (0x00000000)
// #define sBaseTiming (0x00000000)
// #define hPull3DTiming (0x00000000)
#define tBaseTimingPCruise (0x000D4714)
// #define hTableBaseTimingPCruise (0x00000000)
#define tBaseTimingPNonCruise (0x000D48D4)
// #define hTableBaseTimingPNonCruise (0x00000000)
#define tBaseTimingRCruiseAvcs (0x000D4A94)
// #define hTableBaseTimingRCruiseAvcs (0x00000000)
#define tBaseTimingRNonCruiseAvcs (0x000D4C54)
// #define hTableBaseTimingRNonCruiseAvcs (0x00000000)
// #define pKcaIam (0x00000000)

/////////////////////
// Spark Cut
/////////////////////


/////////////////////
// Flags-Signals
/////////////////////

/* [NEEDS VERIFY] Cruise control and input flag addresses.
 * These need to be found by tracing the SSM Get_Switches routine.
 * Navigate to SsmGet_Switches_63 and map the RAM references.
 *
 * Switch 63 = Clutch, 64 = Stoplight, 65 = Cruise Set/Coast,
 * 66 = Cruise Accel/Resume, 67 = Brake.
 *
 * The literal pool at 0x3B77C shows 0xFFFF65FC which may be
 * clutch or a related flag. AE5K700V uses 0xFFFF65F4 for clutch.
 *
 * For 2013 WRX, cruise flags are typically near 0xFFFF5FC0-0xFFFF5FD0. */
/* TODO: Verify all flag addresses in Ghidra via SSM switch routine */
// #define pResumeFlags ((unsigned char*)0x00000000)
// #define ResumeBitMask ((unsigned char)0x01)
// #define pCoastFlags ((unsigned char*)0x00000000)
// #define CoastBitMask ((unsigned char)0x01)
// #define pBrakeFlags ((unsigned char*)0x00000000)
// #define BrakeBitMask ((unsigned char)0x01)
// #define pClutchFlags ((unsigned char*)0x00000000)
// #define ClutchBitMask ((unsigned char)0x01)

/////////////////////
// NonSpecific Engine params
/////////////////////

/* [HIGH CONF] Engine parameter RAM addresses.
 * These are commonly shared across same-generation SH7058 ROMs.
 * Cross-referenced with AE5K700V and verified via literal pool analysis.
 * pMassAirFlow confirmed at 0xFFFF40B4 (literal pool 0x4A8C).
 * pMafSensorVoltage confirmed at 0xFFFF4042 (literal pool 0x4A7C). */
/* TODO: Verify all RAM param addresses via SSM routine or Ghidra XREF */
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

/* [NEEDS VERIFY] Load smoothing addresses.
 * Follow MAF Compensation (IAT) table references at 0xC3BB0
 * to find the Engine Load calculation subroutine. */
/* TODO: Find via Ghidra by tracing from MAF Compensation (IAT) XREFs */
// #define dLoadSmoothingA (0x00000000)
// #define dLoadSmoothingB (0x00000000)
// #define dLoadSmoothingAlt (0x00000000)
// #define dLoadSmoothingFinal (0x00000000)

/////////////////////
// Memory Reset
/////////////////////

/* [HIGH CONF] Memory reset routine identified via VBR vector trace.
 * Literal pool at 0x11CE4 contains 0xFFFF4000 (RAM clear start)
 * and 0x11CE8 contains 0xFFFFBF9F (RAM clear limit = pMemoryResetLimit).
 * sMemoryReset function starts at 0x101C4 (sts.l pr prolog found).
 * hMemoryReset at 0xFC20 area (references sMemoryReset).
 * hMemoryResetLimit at 0x11CE8 (the literal pool entry holding 0xFFFFBF9F). */
#define sMemoryReset (0x000101C4)
#define hMemoryReset (0x0000FC20)
#define pMemoryResetLimit (0xFFFFBF9F)
#define hMemoryResetLimit (0x00011CE8)
