//////////////////////////////
//		OPTIONS
//////////////////////////////

#define AUTO_TRANS 0
#define SD_DMAP		0

#define ECU_IDENTIFIER_CHARS (10)
#define ECU_CALIBRATION_CHARS (8)
#define MOD_CALIBRATION_ID	FFFFFFFF
#define MOD_ECU_IDENTIFIER FFFFFFFFFF

/* MAF sensor expected values.
 * EXPECTED_MAF_SENSOR: The expected MAF sensor voltage at a known airflow.
 *   This varies by ROM calibration. Needs verification for AE5L600L.
 *   AE5K700V uses 3.487375, A2UG002T uses 3.3264.
 *   Check your MAF Sensor Scaling table to determine correct value.
 * EXPECTED_MAF_SD: Speed Density expected MAF equivalent.
 *   Typically 3.73053 across most ROMs.
 */
#define EXPECTED_MAF_SENSOR 3.487375f
#define EXPECTED_MAF_SD 3.73053f
