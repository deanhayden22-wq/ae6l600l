/*
 * Flash configuration for AE5L600L
 * Based on MerpMod Flash.h but with MEMORY_HACKS=0 because
 * this ROM has no hookable literal pool for the memory reset function.
 * Initialization is handled via runtime first-run check in WGDCHack.
 */

///////////////////////////////
//		HACK CONFIGURATION	//
//////////////////////////////
							//
#define MEMORY_HACKS 0		// Disabled: no hookable memory reset in this ROM
#define SD_HACKS	1		//
#define REVLIM_HACKS 1		//
#define	LC_ADJ_HACKS 0		//
#define PROG_MODE 0			//
#define SPARK_HACKS 0		//
#define CEL_HACKS 1			//
#define BOOST_HACKS 0		//
#define TIMING_HACKS 0		//
#define POLF_HACKS 0		//
#define PGWG_HACKS 0		//
#define INJECTOR_HACKS 0	//
							//
//////////////////////////////

/* Runtime initialization flag - WGDCHack checks this on every call.
 * If RAM variables haven't been initialized, it calls PopulateRamVariables. */
#define RUNTIME_INIT 1
