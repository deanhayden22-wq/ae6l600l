# Rear O2 Sensor Investigation - AE5L600L Rev 20.2

## Summary

On this ROM (rev 20.2), unplugging the rear O2 sensor will **NOT** cause a rich loop or affect fueling in any way. The AF 3 correction system (the only code path where the rear O2 influences fueling) has been disabled by zeroing the correction limits.

However, **4 diagnostic trouble codes remain enabled** and could potentially throw a CEL.

---

## AF 3 Correction System (Rear O2 Fuel Trim)

The rear O2 sensor feeds into the ECU's "AF 3" correction loop, which is a secondary fuel trim that adjusts the target AFR based on the rear (post-cat) O2 sensor reading. This is the **only** code path where the rear O2 sensor influences fueling -- confirmed via disassembly analysis.

### AF 3 Correction Limits (0x35FFC) - DISABLED

| Limit | Value |
|-------|-------|
| + (max enrichment) | **0.00%** |
| - (max enleanment) | **0.00%** |

Both limits are zeroed, which clamps the AF 3 correction to 0%. Even if the ECU reads 0V from an unplugged sensor and interprets it as a lean condition, it **cannot** apply any fuel correction.

ROM description for this table:
> "CHANGING THIS VALUE MIN-MAX TO 0 INPUT RESULTS IN THE DISABLITY OF THE REAR O2 SENSOR INPUT ON TARGET AFR, THIS AFR TRIM 3 CAN CAUSE RICHER THAT DISIRED IDLES WHEN LEFT ON. DISABLE IF EXPERINCING RICHER THAN IDEAL IDLES WHEN ALL OTHER SCALING IS VERIFYED CORRECT OR REAR O2 SENSOR DELETE."

### AF 3 Learning Limits (0x36000) - DISABLED

Also zeroed out, preventing any long-term learning from the rear O2 sensor.

### Why People Report Rich Running (Stock ROMs)

On a stock tune, the AF 3 Correction Limits are set to +/- several percent. When the rear O2 is unplugged:

1. Sensor reads 0V (grounded/no signal)
2. ECU interprets 0V as a lean exhaust condition (narrowband O2 outputs ~0.5V at stoich)
3. AF 3 Correction Adder (Increase) table adds fuel to "fix" the lean reading
4. This creates observable rich running, especially at idle

This does NOT apply to rev 20.2 because the correction limits are zeroed.

---

## Diagnostic Trouble Codes

### Rear O2 DTCs - DISABLED (9 codes)

| DTC | Description | Address | Status |
|-----|-------------|---------|--------|
| P0037 | Rear O2 Sensor Low Input | 0x9A7A2 | DISABLED |
| P0038 | Rear O2 Sensor High Input | 0x9A7A0 | DISABLED |
| P0137 | Rear O2 Sensor Low Voltage | 0x9A799 | DISABLED |
| P0138 | Rear O2 Sensor High Voltage | 0x9A79C | DISABLED |
| P0140 | Rear O2 Sensor No Activity | 0x9A7E2 | DISABLED |
| P0141 | Rear O2 Sensor Malfunction | 0x9A78A | DISABLED |
| P0420 | Catalyst Efficiency Below Threshold | 0x9A78D | DISABLED |
| P2096 | Post Catalyst Too Lean B1 | 0x9A7B6 | DISABLED |
| P2097 | Post Catalyst Too Rich B1 | 0x9A7BD | DISABLED |

### Rear O2 DTCs - STILL ENABLED (4 codes)

| DTC | Description | Address | Status |
|-----|-------------|---------|--------|
| P013A | O2 Sensor Slow Response Rich-to-Lean B1S2 | 0x9A815 | **ENABLED** |
| P013B | O2 Sensor Slow Response Lean-to-Rich B1S2 | 0x9A814 | **ENABLED** |
| P013E | O2 Sensor Delayed Response Rich-to-Lean B1S2 | 0x9A813 | **ENABLED** |
| P013F | O2 Sensor Delayed Response Lean-to-Rich B1S2 | 0x9A812 | **ENABLED** |

These are **diagnostic only** and do not affect fueling. However, they could potentially trigger a CEL if the ECU runs readiness monitors and detects no valid response from the rear O2 sensor.

To fully disable, set bytes at 0x9A812-0x9A815 to 0x00 in the ROM binary.

---

## Conclusion

| Concern | Risk on Rev 20.2 |
|---------|-------------------|
| Rich running / rich loop | **None** - AF 3 correction zeroed |
| Fueling changes | **None** - rear O2 has no fuel influence |
| CEL from main rear O2 codes | **None** - 9 DTCs disabled |
| CEL from slow/delayed response codes | **Possible** - 4 DTCs still enabled |
