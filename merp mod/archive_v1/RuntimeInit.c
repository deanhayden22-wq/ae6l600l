/*
 * Runtime initialization for AE5L600L MerpMod port.
 * Since this ROM has no hookable memory reset function,
 * we check on every WGDCHack call if init has been done.
 * Uses pRamVariables->ECUIdentifier as the init flag (same as
 * MerpMod's InitRamVariables approach).
 */

#include "EcuHacks.h"

#if RUNTIME_INIT

void RuntimeInitCheck(void) ROMCODE;

void RuntimeInitCheck(void)
{
    /* If ECUIdentifier doesn't match, RAM variables need initialization.
     * After power-on, RAM is random, so this will trigger on first call.
     * After initialization, ECUIdentifier is set to match dEcuId. */
    if (pRamVariables->ECUIdentifier != *(long*)dEcuId)
    {
        ClearRamVariables((long*)pRamVariables, (long*)&pRamVariables->RamHoleEndMarker);
        PopulateRamVariables();
    }
}

#endif
