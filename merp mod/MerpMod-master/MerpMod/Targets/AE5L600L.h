#define MOD_ECUID AE5L600L00
#define MOD_DATE 26.04.04.00.00
#include "SDOnly.h"
#define MOD_CONFIG SDOnly
#define MOD_BUILD Debug
#define MOD_RELEASE 0
#define ECU_CALIBRATION_ID AE5L600L
#define ECU_IDENTIFIER 8A12587007
/////////////////////
// NonSpecific Rom Info and Routines
/////////////////////

#define dCalId (0x00002000)
#define dEcuId (0x00002004)
#define dRomHoleStart (0x000DAE8C)
#define pRamHoleStart (0xFFFFC000)
#define sPull2DFloat (0x000BE830)
#define sPull3DFloat (0x000BE8E4)

/////////////////////
// Speed Density Hack
/////////////////////

// MAF hook: literal pool in frontO2_scaling_init (0x4A2C)
// 0x4A84 = descriptor 0xAF45C, 0x4A88 = Pull2DFloat, 0x4A8C = output 0xFFFF40B4
// Patcher replaces 4 bytes at 0x4A88 (sPull2DFloat) with ComputeMassAirFlow
#define hMafCalc (0x00004A88)
#define sMafCalc (0x00004A2C)

/////////////////////
// NonSpecific Engine params
/////////////////////

#define pEngineSpeed ((float*)0xFFFF6624)
#define pVehicleSpeed ((float*)0xFFFF61CC)
#define pCoolantTemp ((float*)0xFFFF6350)
#define pAtmoPress ((float*)0xFFFF67EC)
#define pManifoldAbsolutePressure ((float*)0xFFFF6898)
#define pIntakeAirTemp ((float*)0xFFFF63F8)
#define pMassAirFlow ((float*)0xFFFF6254)
#define pMafSensorVoltage ((short*)0xFFFF4042)
#define pEngineLoad ((float*)0xFFFF65FC)
#define pThrottlePlate ((float*)0xFFFF65C0)

/////////////////////
// Memory Reset
/////////////////////

// Memory reset hook
// Boot sequence at 0x0C14: mov.l @(0x0D64),r3 / mov #0,r5 / jsr @r3 / mov r5,r4
// 0x0D64 is the literal pool entry holding 0x00065C (RTOS startup).
// Option A: Patch pointer at 0x0D64 to point to MerpMod Initializer
// Option B: Patch JSR at 0x0C18 (requires trampoline, ROM hole out of BRA range)
#define sMemoryReset (0x0000065C)
#define hMemoryReset (0x00000D64)

