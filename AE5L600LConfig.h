//////////////////////////////
//		OPTIONS
//////////////////////////////

#define AUTO_TRANS 0
#define SD_DMAP		0

#define ECU_IDENTIFIER_CHARS (10)
#define ECU_CALIBRATION_CHARS (8)
#define MOD_CALIBRATION_ID	FFFFFFFF
#define MOD_ECU_IDENTIFIER FFFFFFFFFF

/* MAF sensor expected voltage values for SD (Speed Density) hack.
 * EXPECTED_MAF_SENSOR = 3.487375 matches AE5K700V and AE5IB00V
 * (both 2013 WRX MT, same physical MAF sensor as AE5L600L).
 * AE5F301C (AT) uses 3.42 due to different intake setup.
 * EXPECTED_MAF_SD = 3.73053 is standard across all AE5 MT targets. */
#define EXPECTED_MAF_SENSOR 3.487375f
#define EXPECTED_MAF_SD 3.73053f
