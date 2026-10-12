# Blind audit of settled claims

> A sample of claims this project treats as settled, re-derived from bytes by a reader
> that could not see the claim, then graded against it. **Agreement is weak evidence;
> disagreement means one side is wrong, not which.** Every disagreement below is a
> decode-by-hand item. Batches msgbatch_013L7mUfV12GdrvLEXxBih1Z (blind) and msgbatch_01QRcLK8rUZkZ8sg8GkMkccQ (grading), model claude-opus-5-5, 2026-10-11 19:45:40.

## Agreement by group

| Group | Sampled | agree | partly_agree | disagree | blind_abstained | not_comparable | no answer |
|---|---|---|---|---|---|---|---|
| named_table | 30 | 7 | 20 | 0 | 2 | 0 | 1 |
| traced_function | 30 | 1 | 21 | 5 | 1 | 0 | 2 |
| unverified_function | 18 | 0 | 13 | 3 | 2 | 0 | 0 |

## How the blind reader's own confidence held up (named tables only)

| Blind evidence class | agree | partly_agree | disagree | blind_abstained | not_comparable |
|---|---|---|---|---|---|
| inferred | 7 | 16 | 0 | 0 | 0 |
| hunch | 0 | 2 | 0 | 1 | 0 |
| unknown | 0 | 2 | 0 | 1 | 0 |

## named_table

### 0xAAA80 -- AGREE

- **On record:** Definition-file table "Calculated Engine Torque B", category "Alpha Drive-by-Wire Throttle (DBW)". Axes: Engine Load; Engine Speed. Output units: Requested Torque (raw ecu value). Description: This table determines the expected Crank Engine Torque output relative to engine load and engine speed.
- **Blind (inferred):** Engine torque estimate from load and RPM, variant C of four (blend weight (1-f_A)*f_B) -- One of four load-by-RPM maps looked up back-to-back with identical inputs. The function blends the four results bilinearly using two 0..1 factors read from RAM, and stores the blended result to 0xFFFF5D58 and 0xFFFF5D5C. This map's raw value goes to 0xFFFF5E00 and enters the blend with weight (1-[FFFF90A8])*[FFFF3234].
- **Grader:** Both describe an engine torque map indexed by engine load and engine speed, one of several variants. The blind answer's 'variant C' lettering is its own ordering and does not contradict the claim's 'B'; the torque identity, though inferred, matches.
- **Differs on:** none

### 0xAEBD4 -- AGREE

- **On record:** Definition-file table "Idle Speed Target D", category "Idle Control". Axes: Coolant Temperature. Output units: Engine Speed (RPM). Description: Idle speed target at different coolant temperatures.
- **Blind (inferred):** Idle target engine speed vs coolant temperature (state 7/8 or 4/7 branch, r11==1 variant) -- Indexed by current coolant temperature (fr12 from 0xFFFF6350). Gives a target of 1700 cold falling to 800 warm. The function then ramps a running value toward this target at a rate taken from a second ECT-indexed table, which is the typical shape of an idle-speed target.
- **Grader:** Both describe an idle speed target in RPM indexed by coolant temperature. The blind answer's inferred identity and units match the claim.
- **Differs on:** none

### 0xAE62C -- AGREE

- **On record:** Definition-file table "Timing Compensation Per Cylinder D", category "Ignition Timing - Compensation". Axes: Engine Speed; Engine Load. Output units: Ignition Timing Correction (degrees). Description: This is the change in total ignition timing per cylinder based on RPM and engine load. It is not currently known which table corresponds to which cylinder, however it is suspected that table A corresponds to cylinder #1. When logging 'ignition timing' only cylinder A is monitored.
- **Blind (inferred):** Per-cylinder ignition timing compensation, 4th of a set of four (likely cylinder 4), RPM x load -- Looked up by RPM and engine load only when RPM is below a limit, load and coolant temperature are above thresholds and a status byte from 0x2F8EA is zero; otherwise all four outputs are forced to 0. The result is stored as the fourth float of a four-element RAM array (0xFFFF81DC..0xFFFF81E8) filled from four sibling tables with the same geometry.
- **Grader:** Both describe the fourth of four per-cylinder ignition timing correction tables indexed by RPM and engine load, with output in degrees. The blind answer's cylinder guess is hedged, and the claim itself says the cylinder mapping is unknown.
- **Differs on:** none

### 0xACA78 -- AGREE

- **On record:** Definition-file table "Table_Post_Start_Enrich_High_Speed_Decay_Step_Value_1", category "Post Start Enrichment". Axes: Coolant Temperature. Output units: units
- **Blind (inferred):** Coolant-temperature-indexed decay rate for an accumulator at 0xFFFF7378, possibly a start/after-start fuel term -- Each time the gate passes, the value looked up against coolant temperature is multiplied by a factor at 0xFFFF7388 and subtracted from a float accumulator at 0xFFFF7378, floored at 0. That accumulator, scaled by a second coolant table and added to a base value, feeds a max() and then a 2D-table multiply whose result is stored at 0xFFFF7374.
- **Grader:** Both describe a coolant-temperature-indexed decay step value for an accumulator, and the blind answer tentatively ties it to an after-start fuel enrichment term. That matches the claimed post-start enrichment decay step. The 'high speed' qualifier isn't identified, but the core identity matches.
- **Differs on:** Blind answer doesn't specify the 'high speed' variant and hedges on the enrichment purpose.

### 0xAEB48 -- AGREE

- **On record:** Definition-file table "Idle Speed Target B", category "Idle Control". Axes: Coolant Temperature. Output units: Engine Speed (RPM). Description: Idle speed target at different coolant temperatures.
- **Blind (inferred):** Target idle speed (RPM) vs coolant temperature, mode 2 with flag r11=1 (one of 10 mode/flag variants) -- This is a coolant-temperature-indexed base target that is high when cold (1700) and falls to 800 when warm. It is selected when state byte GBR+80 equals 2 and flag r11 equals 1. The result is stored as a target and then approached by a rate-limited ramp, which behaves like an idle-speed target.
- **Grader:** Both describe an idle speed target in RPM indexed by coolant temperature, one of several variants. The blind answer hedges on the units but proposes exactly this identity.
- **Differs on:** none

### 0xAF468 -- AGREE

- **On record:** Definition-file table "Front Oxygen Sensor Scaling", category "Fueling - Closed Loop". Axes: Front Oxygen Sensor. Output units: Air/Fuel Ratio. Description: This is the scaling for the front oxygen sensor.
- **Blind (inferred):** Front A/F sensor signal to lambda (equivalence ratio) conversion curve (candidate) -- This small wrapper reads a float from RAM 0xFFFF40E0, converts it through a 13-point curve and stores the result to RAM 0xFFFF8DE4. The shape looks like a wideband A/F sensor characteristic: a signed input with zero mapping to 1.0, and outputs that look like lambda or AFR divided by 14.5.
- **Grader:** Both describe the front (wideband) oxygen sensor scaling curve, which converts the sensor signal to an air/fuel quantity. The blind answer gives the output as lambda (AFR/14.5) rather than AFR directly, but that is the same quantity scaled.
- **Differs on:** Output units: the claim says Air/Fuel Ratio, the blind answer says dimensionless lambda (AFR/14.5).

### 0xAF2B8 -- AGREE

- **On record:** Definition-file table "Requested Torque Limit B (Per Gear/Engine Speed)", category "Alpha Per Gear Requested Torque". Axes: Engine Speed; Gear. Output units: Requested Torque (raw ecu value). Description: This table determines the Max requested torque based on calculated Gear and engine speed.
- **Blind (inferred):** Gear- and RPM-dependent upper limit, probably a torque ceiling (base mode, operand of the min chain) -- In the default mode, where the function argument r4/r14 is 0, this descriptor is loaded into gbr+224 and looked up against two inputs that likely carry RPM (Y axis) and gear (X axis). The result is stored to 0xFFFF8714 and then min'ed against a sibling table's result, so it acts as a ceiling. That ceiling feeds a weighted blend whose result goes to stack slot 68. The data allows 500 in gears 1–3 and 350 in gears 4–6, flat across RPM.
- **Grader:** The blind answer names a torque ceiling indexed by gear and engine speed, used as a max limit, which matches the claim of a max requested torque table by gear and RPM. It hedges on the output units but still proposes torque.
- **Differs on:** none

### 0xAC7D8 -- PARTLY_AGREE

- **On record:** Definition-file table "Tip-in Enrichment Compensation A (ECT)", category "Fueling - Tip-in Enrichment". Axes: Coolant Temperature. Output units: Throttle Tip-in Enrichment Compensation (%). Description: This is the change in 'Throttle Tip-in Enrichment' based on coolant temperature.
- **Blind (inferred):** ECT multiplier on a gated, counted event amount (possibly an extra/async injection pulse); stock flat 1.0 -- Indexed by coolant temperature, it gives a dimensionless factor stored to 0xFFFF7C44. That factor is the last term in a product of several factors. If the product reaches a minimum it triggers an event that is counted, budgeted and handed to routine 0xDCE4. Every cell is 1.0, so this calibration applies no temperature correction.
- **Grader:** Both describe an ECT-indexed compensation multiplier, and the blind answer's guess of an extra or asynchronous injection pulse is in the tip-in enrichment area. It does not name it as tip-in enrichment, so the identity is vaguer than the claim.
- **Differs on:** Blind answer calls it a multiplier on an unidentified gated event amount (possibly an async injection pulse) rather than identifying it as tip-in enrichment compensation.

### 0xAF8D8 -- PARTLY_AGREE

- **On record:** Definition-file table "Intake Cam Advance Angle Cruise (AVCS)", category "Variable Valve Timing (AVCS)". Axes: Engine Load; Engine Speed. Output units: Advance (degrees). Description: This map selects the degree of intake cam advance for the variable valve timing system during cruise conditions. Cruise and non-cruise conditions are determined by a number of factors including engine speed, requested torque, MAF, vehicle speed, IAT, idle mode, ECT, and SI-Drive mode (if applicable). The ECU will ramp between the cruise and non-cruise map values when conditions dictate the switch.
- **Blind (inferred):** Base target map A (load x RPM), blended with map B by weight 0xFFFF90A8. Possibly the intake AVCS cam advance target, which is a hunch. -- Looked up with engine load (g/rev, Y) and RPM (X). The result is weighted by (1 - [FFFF90A8]) and added to map 0xAF8F4 weighted by [FFFF90A8], plus map 0xAF910 times an ECT-based 1D factor. The sum is floored at 0 and stored to 0xFFFF921C. Then 0xFFFF921C times a 1D lookup on 0xFFFF912C, plus a constant, is written to 0xFFFF9230, 0xFFFF9224 and 0xFFFF9228.
- **Grader:** The blind answer has the load x RPM axes and a blended map pair, which fits the cruise/non-cruise ramp. It names intake cam advance only as a hunch and cannot establish the purpose, the units, or that the blend is cruise-driven.
- **Differs on:** Blind answer only hypothesizes intake AVCS cam advance and does not identify the blend weight as the cruise/non-cruise ramp, whereas the claim states it is the cruise intake cam advance map in degrees.

### 0xAE5A0 -- PARTLY_AGREE

- **On record:** Definition-file table "Timing Compensation Per Gear (4th)", category "Ignition Timing - Compensation". Axes: Engine Load; Engine Speed. Output units: Timing Compensation (degrees)
- **Blind (inferred):** unknown: case-4 member of a five-way rpm x load table set (selector byte 0xFFFF6812), all zero -- When the enable conditions hold and the selector byte at 0xFFFF6812 equals 4, this table is looked up from engine load and rpm. The result is stored to 0xFFFF80F4, multiplied by the float constant at 0xD2D48, and stored to 0xFFFF80F0. Because every cell is 0, both outputs are 0 whenever this table is selected.
- **Grader:** The blind answer correctly identifies a load x rpm table selected when a byte equals 4 out of five, and tentatively suggests that byte is gear position. It does not identify the output as timing compensation and leaves the purpose unknown.
- **Differs on:** Claim says the output is ignition timing compensation in degrees for 4th gear; blind leaves the output quantity and the selector meaning unknown.

### 0xADB74 -- PARTLY_AGREE

- **On record:** Definition-file table "Base Timing Idle A (Neutral)", category "Ignition Timing - Advance". Axes: Coolant Temperature. Output units: Base Ignition Timing (degrees BTDC). Description: This is the base timing in idle mode when the transmission is in neutral. Although the map switching between A and B is not entirely understood, it appears to be related to the TGVs.
- **Blind (inferred):** Coolant-temperature-indexed value, probably ignition timing in degrees (variant 2 of 4, chosen by two flags) -- Looks up a value against current coolant temperature and stores it as a float to RAM 0xFFFF7F2C. This descriptor is one of four (0xADB4C, 0xADB60, 0xADB74, 0xADB88), chosen by the byte at 0xFFFF65C0 and by the return value of routine 0x021016. It is used when the 0xFFFF65C0 byte is non-zero and 0x021016 returns zero.
- **Grader:** The blind answer gets the coolant-temperature axis, the probable ignition-timing output and the existence of switchable A/B-style variants. It does not identify the role as idle base timing in neutral, and it hedges on the quantity itself.
- **Differs on:** Claim names the table as base idle timing in neutral (map A); the blind answer offers only a generic, uncertain 'variant 2 of 4' coolant-indexed timing-like value with unknown selection flags.

### 0xAC338 -- PARTLY_AGREE

- **On record:** Definition-file table "Min Primary Base Enrichment 1 (Non-Primary OL)_", category "Fueling - Warm-Up Enrichment". Axes: Coolant Temperature. Output units: Minimum Primary Enrichment Offset Additive 1. Description: This is one of three factors which determines the minimum primary fuel afterstart enrichment. The primary fuel enrichment is a multiplier (determined primarily by the open loop fuel maps) applied to the base injector duration to determine the level of primary enrichment. The minimum enrichment offsets determined by tables 1, 2, and 3 are added together to determine the final primary minimum enrichment. That is, regardless of the primary open loop fuel map value, enrichment will not
- **Blind (inferred):** Coolant-temperature compensation multiplier, conditionally enabled (all cells 1.0, currently neutral) -- When the byte flag at 0xFFFF65C1 equals 1, coolant temperature is looked up in this table and the result is stored to 0xFFFF7288, with 0xFFFF726E set to 1. Otherwise 0xFFFF7288 is forced to 1.0 and 0xFFFF726E is cleared, so the result acts as a unity-default factor whose consumer is not in this listing.
- **Grader:** Both describe a coolant-temperature-indexed table whose value is used only under a gating condition, but the blind answer cannot name its purpose. It treats the output as a unity-default multiplier, whereas the claim says it is an additive offset to the minimum primary enrichment.
- **Differs on:** Blind calls the output a multiplicative compensation factor that defaults to 1.0; the claim calls it an additive minimum primary enrichment offset, applied only in non-primary open loop.

### 0xAA928 -- PARTLY_AGREE

- **On record:** Definition-file table "Turbo Dynamics Integral Negative", category "Boost Control - Turbo Dynamics". Axes: Boost Error. Output units: Wastegate Duty Correction (% absolute). Description: This is the correction to wastegate duty at different levels of boost error (target boost - actual boost) in order to achieve target boost. This table is designed to modify wastegate duty to correct for boost error over time. It allows an absolute percentage of correction to be applied to wastegate duty based on the difference between target boost and actual boost.
- **Blind (inferred):** Integrator decrement step vs. negative error signal at 0xFFFF5CA0 (IAT-scaled). The quantity being integrated is unidentified. -- When the input at 0xFFFF5CA0 is below the threshold at 0xC0BDC (i.e. negative), this table gives a negative step from that input. The step is multiplied by an IAT-indexed factor (table 0xAA8D8), added to the running accumulator at 0xFFFF5CB0 and floored at the constant at 0xC0BF0. It is the 'decrease' half of an asymmetric integral/learning update; table 0xAA93C with an upper clamp at 0xC0BF4 handles the positive side.
- **Grader:** The blind answer correctly identifies the mechanism, a negative-side integral step indexed by a negative error and accumulated over time. It cannot say that the error is boost error or that the output is a wastegate duty correction, and it even guesses idle rpm.
- **Differs on:** The claim says the table is a boost-error integral correction to wastegate duty; the blind answer leaves both the regulated quantity and the accumulator unidentified, guessing idle rpm error.

### 0xADBC4 -- PARTLY_AGREE

- **On record:** Definition-file table "Timing Compensation Imm. Non-Cruise A (ECT)", category "Ignition Timing - Compensation". Axes: Coolant Temperature. Output units: Ignition Timing Correction (degrees). Description: This is the change in total ignition timing based on coolant temperature. Cruise and non-cruise conditions are determined by a number of factors including engine speed, requested torque, MAF, vehicle speed, IAT, idle mode, ECT, and SI-Drive mode (if applicable). Note: This is based on the immediate conditions related to cruise/non-cruise and results in an immediate switch, not the ramping behavior inherent with other tables when switching.
- **Blind (inferred):** Coolant-temperature compensation, probably ignition timing in degrees (variant 1 of 4: flag 0xFFFF90BE == 0 and mode byte 0xFFFF6254 == 1) -- Looks up a signed correction, likely in degrees, against current coolant temperature and stores it as a float to RAM 0xFFFF7F68. The correction is +8 at -10 °C and below, tapers to 0 between 50 and 90 °C, and goes to -3.9 at 110 °C. It is one of four sibling tables (0xADBD8, 0xADBC4, 0xADC00, 0xADBEC), chosen by two RAM state bytes.
- **Grader:** The blind answer correctly identifies a coolant-temperature-indexed ignition timing correction in degrees, one of several variant tables chosen by state bytes. It does not identify the selectors as immediate cruise/non-cruise, and it hedges that the output might be AVCS rather than ignition timing.
- **Differs on:** The claim identifies this as the immediate non-cruise variant (A); the blind answer treats the selector meaning as unknown and calls it only variant 1 of 4.

### 0xAA888 -- PARTLY_AGREE

- **On record:** Definition-file table "Initial/Max Wastegate Duty Compensation (IAT)", category "Boost Control - Wastegate". Axes: Intake Temperature. Output units: Initial/Max Wastegate Duty Compensation (% relative). Description: This is the change in wastegate duty based on intake temperature. This is applied to both the initial and max wastegate duty values.
- **Blind (inferred):** IAT multiplier (cold-air reduction) on a rpm-based target/limit in routine 0x13D66 -- Gives a unitless factor from intake air temperature: 0.30 at -40°C rising to 1.0 at 10°C and above. It is multiplied with two rpm-indexed 2D tables and an ECT table, and the product is clamped to 0..80 to form a ceiling for a quantity this routine computes and rate-limits. What that quantity is cannot be fixed from this listing.
- **Grader:** Both describe an IAT-indexed compensation factor applied to a computed limit or ceiling. The blind answer gets the mechanism right, a multiplier clamped to 0..80 used as a ceiling, but cannot identify the quantity as wastegate duty (initial/max).
- **Differs on:** Claim identifies the scaled quantity as initial/max wastegate duty; blind answer says the quantity cannot be determined.

### 0xAE584 -- PARTLY_AGREE

- **On record:** Definition-file table "Timing Compensation Per Gear (3rd)", category "Ignition Timing - Compensation". Axes: Engine Load; Engine Speed. Output units: Timing Compensation (degrees)
- **Blind (inferred):** unknown – rpm×load term, third of five variants picked by RAM selector 0xFFFF6812 (possibly gear 3); all zeros -- The table is looked up from engine load and rpm. The byte at 0xFFFF6812 picks one of five sibling tables (values 1..5), and this is variant 3. The same table is also forced in by a separate override path. The result is stored to 0xFFFF80F4, then scaled by the constant at 0xD2D48 and stored to 0xFFFF80F0, which other code consumes. Every cell is 0, so the output is currently 0 in every case.
- **Grader:** The blind answer has the mechanism right: a load×rpm table, variant 3 of five chosen by a selector it tentatively reads as gear. It cannot name the purpose (timing compensation) or the output units.
- **Differs on:** Blind answer leaves the output purpose and units unknown and only guesses gear; the claim states it is ignition timing compensation in degrees for 3rd gear.

### 0xAD3A4 -- PARTLY_AGREE

- **On record:** Definition-file table "Tip-in Enrichment Compensation C (ECT)", category "Fueling - Tip-in Enrichment". Axes: Coolant Temperature. Output units: Throttle Tip-in Enrichment Compensation (%). Description: This is the change in 'Throttle Tip-in Enrichment' based on coolant temperature.
- **Blind (inferred):** Coolant-temperature multiplier (cold factor), selected when flag 0xFFFF844F != 1; consumer unknown -- Looks up a dimensionless factor from current coolant temperature, 3.5 at -40 °C falling to 1.0 at 60 °C and above, and stores it as a float to RAM 0xFFFF7C58. It is the alternate to table 0xAD390, which the code uses instead when byte flag 0xFFFF844F == 1.
- **Grader:** Both describe a 1D coolant-temperature table producing a correction factor that is large when cold and tapers to no correction when warm. The blind answer could not say what the factor scales, whereas the claim identifies it as tip-in enrichment compensation.
- **Differs on:** The claim says the factor modifies throttle tip-in enrichment; the blind answer leaves its consumer unknown.

### 0xACB90 -- PARTLY_AGREE

- **On record:** Definition-file table "Tau Input A Falling Load Activation A", category "Alpha Transient Fueling (Tau)". Axes: Coolant Temperature. Output units: Enrichment Adder Multiplier. Description: This table determines the Tau A enrichment multiplier when engine load is decreasing.
- **Blind (inferred):** Coolant-temp-scheduled gain for the middle term of a three-term feedback/correction output (branch where the selector signal at 0xFFFF73EC is negative, mode != 2) -- A 1D lookup on coolant temperature returns a unitless gain, flat at 0.5. It is stored to 0xFFFF73B8 and multiplied by an rpm-scheduled gain (0xFFFF73C4) and by a computed signal (0xFFFF73F0). That product is the middle of three gain×gain×signal products. The three are summed, scaled by 0xFFFF7400, optionally clamped to >= 0, and written to 0xFFFF73B4.
- **Grader:** Both describe a coolant-temperature-indexed unitless multiplier. The blind reader saw the sign-based branch selection, which is consistent with a falling-load branch, but never identified it as transient (tau) fueling enrichment and instead framed it as a generic PID-like correction gain.
- **Differs on:** The claim names the purpose as Tau A transient enrichment under falling load; the blind answer gives only an unspecified feedback/correction gain selected when a signal is negative.

### 0xAC360 -- PARTLY_AGREE

- **On record:** Definition-file table "Cranking Fuel IPW Compensation (Accelerator)", category "Fueling - Cranking". Axes: Accelerator Pedal Angle. Output units: Cranking Fuel Injector Pulse Width Compensation (%). Description: This is the change to the 'Cranking Fuel Injector Pulse Width (ECT)', based on the accelerator pedal.
- **Blind (unknown):** unknown (0..1 fade-out factor vs RAM 0xFFFF64D8, written to 0xFFFF72E4) -- When flag byte 0xFFFF726C equals 1, the routine looks this table up using the float at 0xFFFF64D8 and stores the result to 0xFFFF72E4. The result is 1.0 up to an input of 60, then falls linearly-ish to 0 at 90. It is one of four coefficients written side by side; nothing in this listing uses them.
- **Grader:** The blind reader describes the mechanism: a 1-D lookup against an unidentified input, with a 0..1 factor that falls from unity above 60 to zero at 90. That shape fits a cranking fuel cut-back with pedal angle (clear-flood), but the reader names neither the pedal-angle axis nor the cranking-fuel purpose.
- **Differs on:** The claim identifies the input as accelerator pedal angle and the output as a cranking IPW compensation; the blind answer leaves both the input and the purpose unidentified.

### 0xAC90C -- PARTLY_AGREE

- **On record:** Definition-file table "Cranking Fuel Injector Pulse Width D (ECT)", category "Fueling - Cranking". Axes: Coolant Temperature. Output units: Injector Pulse Width (ms). Description: This is the injector pulse width based on coolant temp when cranking the motor. Compensation tables may impact the final pulse width. Although the exact conditions for map switching is not entirely known, some of it is based on whether the ignition switch is on or off and whether the motor has begun to start or not at any given time in the cranking process. TGV status may also be involved. WARNING: UNTESTED
- **Blind (hunch):** Coolant-temperature-dependent threshold or duration (one of six mode-selected variants); meaning unknown -- Looks up a value against current coolant temperature, picking one of six 1D tables from the byte flags at 0xFFFF90C1 and 0xFFFF72A1, and stores the float result to 0xFFFF72FC. A tiny getter at 0x02FCBA returns that RAM value to other code. The value falls steeply from 150000 at -40 C to 5000 at 80 C and above, which fits a cold-start threshold or duration, but no consumer is in the listing.
- **Grader:** The blind answer correctly identifies a coolant-temperature 1D table, one of several mode-selected variants, which matches the claim's map-switching description. It cannot name the purpose, though, and leaves the units as unknown rather than cranking injector pulse width in ms.
- **Differs on:** The claim says the output is cranking injector pulse width in ms; the blind answer calls it an unknown threshold or duration.

### 0xAA8D8 -- PARTLY_AGREE

- **On record:** Definition-file table "TD Integral Negative Compensation (IAT)", category "Boost Control - Turbo Dynamics". Axes: Intake Temperature. Output units: TD Integral Negative Map Target Compensation (% relative). Description: This is the change in wastegate correction for the 'Turbo Dynamics Integral Negative' table based on intake temperature.
- **Blind (inferred):** IAT-dependent gain on the up-count rate of an unidentified accumulator at 0xFFFF5CB0 -- This is a dimensionless multiplier looked up from fr15 (RAM 0xFFFF6364, labelled iat_current). It scales a rate taken from table 0xAA928 (indexed by fr14 = RAM 0xFFFF5CA0). The product is stored to 0xFFFF5D0C and added each pass to an accumulator at 0xFFFF5CB0, which is then clamped by float_max against constant 0xC0BF0. Below about -9 °C it cuts the rate to ~0.65x; above about 50 °C it raises it to ~1.06x.
- **Grader:** Both describe an IAT-indexed multiplicative compensation applied to an accumulating, integral-like term. The blind answer could not identify it as the turbo dynamics integral negative wastegate correction. It describes an "up-count" accumulator, and the claim says "negative", but the blind reader did not name the purpose.
- **Differs on:** Blind answer leaves the accumulator unidentified rather than naming it as the TD integral negative wastegate correction.

### 0xAA8C4 -- PARTLY_AGREE

- **On record:** Definition-file table "TD Proportional Compensation (IAT)", category "Boost Control - Turbo Dynamics". Axes: Intake Temperature. Output units: TD Proportional Map Target Compensation (% relative). Description: This is the change in wastegate correction for the 'Turbo Dynamics Proportional' table based on intake temperature.
- **Blind (inferred):** Intake-air-temperature multiplier applied to the AA914 lookup (purpose of the product unknown) -- Indexed by the value loaded from 0xFFFF6364 (labelled iat_current), this table returns a factor of about 0.65 at cold temperatures, rising to about 1.06 at warm ones. The factor multiplies the output of table 0xAA914, which is indexed by the RAM float at 0xFFFF5CA0, and the product is stored to 0xFFFF5CAC. The product is forced to 0 when either of two hysteresis flags at GBR+129 and GBR+130 is set.
- **Grader:** Both describe an IAT-indexed compensation multiplier applied to another table's output. The blind answer gets the mechanism and axis right but cannot say that the scaled quantity is the turbo dynamics proportional wastegate correction.
- **Differs on:** The claim identifies the scaled quantity as the Turbo Dynamics Proportional wastegate correction; the blind answer leaves the AA914 lookup's purpose unknown.

### 0xAD738 -- PARTLY_AGREE

- **On record:** Definition-file table "Per Injector Pulse Width Compensation A", category "Fueling - Injectors". Axes: Last Calculated Base Pulse Width; Engine Speed. Output units: Injector Pulse Width Compensation. Description: This determines the compensation (per injector) to the current calculated injector duration based on the last calculated injector duration and engine speed. The calculated injector pulse width is based on engine load and a number of other correction factors necessary to achieve the desired fueling. It is not currently known which table corresponds to which injector. WARNING: UNTESTED
- **Blind (inferred):** Per-cylinder multiplier, first of four (possibly cylinder 1 fuel trim), indexed by RPM and RAM 0xFFFF7324 -- Returns a dimensionless multiplier near 1.0 (0.906..1.078) from engine speed and an unknown quantity at 0xFFFF7324. The result is stored as the first float of a 4-float array at 0xFFFF7B6C..0xFFFF7B78. Three sibling tables with the same inputs fill the other three slots, which suggests one correction per cylinder of the 4-cylinder engine.
- **Grader:** The blind answer gets the mechanism right: a per-cylinder/injector correction multiplier, the first of four parallel tables, indexed by engine speed and a quantity it says could be an injector pulse width. It does not commit to the axis being the base pulse width or to the output being an injector pulse width compensation, and leaves open whether it applies to fuel at all.
- **Differs on:** The claim says the table is a fuel injector pulse width compensation indexed by last base pulse width; the blind answer leaves the second axis and the fuel role unverified.

### 0xAD3C4 -- PARTLY_AGREE

- **On record:** Definition-file table "Tip-in Enrichment Compensation D (ECT)", category "Fueling - Tip-in Enrichment". Axes: Coolant Temperature. Output units: Throttle Tip-in Enrichment Compensation (%). Description: This is the change in 'Throttle Tip-in Enrichment' based on coolant temperature.
- **Blind (inferred):** Coolant-temp initial value of a decaying multiplier (floored at 1.0), possibly a post-event enrichment start value -- Indexed by coolant temperature (ect_gated_c at 0xFFFF6354), it gives the starting value of a float factor kept at 0xFFFF7C34 and 0xFFFF7C38. A periodic routine steps that factor down by a constant at a counter-timed rate until it reaches 1.0, and reloads the start value from this table while a word counter at 0xFFFF67EC is below a second coolant-indexed threshold table (0xAD3B8). Every cell is 1.0, so the factor starts at 1.0 and never changes.
- **Grader:** Both describe a coolant-indexed enrichment-style compensation factor, but the blind answer cannot pin it to tip-in enrichment. It describes a generic decaying multiplier (possibly post-event enrichment) whose consumer is unknown.
- **Differs on:** Claim says it is throttle tip-in enrichment compensation; the blind answer calls it a decaying multiplier start value for an unknown quantity, possibly post-start/after-event enrichment.

### 0xAA8B0 -- PARTLY_AGREE

- **On record:** Definition-file table "Initial/Max Wastegate Duty Compensation (ECT)", category "Boost Control - Wastegate". Axes: Coolant Temperature. Output units: Initial/Max Wastegate Duty Compensation (% relative). Description: This is the change in wastegate duty based on coolant temperature. This is applied to both the initial and max wastegate duty values.
- **Blind (inferred):** Coolant-temperature enable multiplier (0 when cold, 1 when warm) for an unidentified clamped 0..80 target -- Looks up a factor from coolant temperature: 0 at 10 °C and below, ramping to 1 at 20 °C and above. The function multiplies it into a product of other table factors, so the target computed here is forced to zero on a cold engine. What that target physically is cannot be told from this listing.
- **Grader:** Both describe a coolant-temperature-indexed compensation factor applied multiplicatively. The blind answer could not identify that the factor applies to wastegate duty, the initial and max duty values, and it treats it as a 0..1 multiplier rather than a % relative compensation.
- **Differs on:** Claim says it compensates initial/max wastegate duty; blind says it gates an unidentified clamped 0..80 target and suggests AVCS as a possible subsystem.

### 0xAE54C -- PARTLY_AGREE

- **On record:** Definition-file table "Timing Compensation Per Gear (1st)", category "Ignition Timing - Compensation". Axes: Engine Load; Engine Speed. Output units: Timing Compensation (degrees)
- **Blind (unknown):** unknown: variant 1 of 5 per-mode RPM x load map (selector byte FFFF6812 == 1), output to FFFF80F4/FFFF80F0 -- When several enable conditions hold, the function picks one of five identically shaped 3x5 tables (AE54C, AE568, AE584, AE5A0, AE5BC) by the byte at 0xFFFF6812, which takes values 1..5. It looks the chosen table up by engine load and RPM, stores the raw result to 0xFFFF80F4, and stores that result times the constant at 0xD2D48 to 0xFFFF80F0. This table is the variant for selector 1, and every cell is 0, so it currently contributes nothing.
- **Grader:** The blind answer correctly identifies one of five per-selector load × RPM maps, with variant 1 matching 1st gear, and it guesses gear only as a hunch. It does not identify the output as timing compensation and leaves its purpose unknown.
- **Differs on:** Purpose and output: the claim says ignition timing compensation in degrees per gear, while the blind answer leaves the output quantity unknown and the selector meaning unconfirmed.

### 0xAC9A4 -- PARTLY_AGREE

- **On record:** Definition-file table "Table_Post_Start_Enrich_High_Speed_Decay_Initial_Start_1A", category "Post Start Enrichment". Axes: Coolant Temperature. Output units: units
- **Blind (hunch):** Coolant-temperature coefficient, slot 0 of a 4-value set written to 0xFFFF7378. Possibly a transient-fuel or wall-wetting factor (hunch). -- Looks up a dimensionless coefficient against current coolant temperature: 0.85 at -40/-30 °C, falling to 0.10 at 80 °C and above. It multiplies the result by a common RAM multiplier at 0xFFFF7288 and stores it to 0xFFFF7378, the first of four ECT-derived coefficients (0xFFFF7378/737C/7380/7384) written together.
- **Grader:** Both describe a coolant-temperature-indexed dimensionless coefficient that runs high when cold and low when hot, which matches a post-start enrichment decay value. The blind answer only guesses transient fuel or wall wetting and does not identify it as post-start enrichment high-speed decay.
- **Differs on:** Blind suggests a transient-fuel/wall-wetting factor rather than post-start enrichment high-speed decay for the initial start.

### 0xAD368 -- BLIND_ABSTAINED

- **On record:** Definition-file table "Throttle Tip-in Enrichment A", category "Fueling - Tip-in Enrichment". Axes: Throttle Angle Change. Output units: Additional Injector Pulse Width (ms). Description: This is the additional enrichment during throttle tip-in. Throttle tip-in is the difference between the current throttle position and the last throttle position. This enrichment represents an additional and separate firing of the injectors. The larger the value, the more fuel is potentially added. Tip-in Enrichment is not active if the thresholds, as determined by the 'Minimum Tip-in Enrichment Activation' and 'Minimum Tip-in Enrichment Activation (Throttle)' tables, are not met as well as other undefined t
- **Blind (unknown):** unknown: flag-selected 1D curve of RAM 0xFFFF62E4, result to 0xFFFF7C54 (flag==1 variant) -- When the byte flag at 0xFFFF844F equals 1, this curve maps the float at 0xFFFF62E4 to a value stored at 0xFFFF7C54; otherwise the sibling table 0xAD37C fills the same slot. A second pair of curves (0xAD390 / 0xAD3A4), chosen by the same flag and indexed by coolant temperature (0xFFFF6350), fills 0xFFFF7C58.
- **Grader:** The blind answer explicitly calls the input, the output and the purpose unknown. It describes only the flag-selected curve structure, with no identification of tip-in enrichment or throttle angle change to compare against the claim.
- **Differs on:** none

### 0xAC5D0 -- BLIND_ABSTAINED

- **On record:** Definition-file table "CL to OL Enrichment Threshold (MAF)", category "Fueling - CL/OL Transition". Output units: Air/Fuel Ratio
- **Blind (hunch):** unknown (step contribution vs RAM 0xFFFF62DC, max-combined in routine 0x036070) -- A 1D lookup on the float at 0xFFFF62DC. Its output is 0 up to 70 on the axis and 0.109 from 73.4 up. The result is stored to 0xFFFF7998 and combined with float_max against two sibling contributions (0xFFFF7994 and 0xFFFF799C). The routine then scales, deadbands and min-limits that maximum into 0xFFFF7990 and 0xFFFF798C.
- **Grader:** The blind answer describes a 1D step lookup on an unidentified RAM float, with an output of 0 to 0.109 combined by max with sibling contributions. It names no purpose and no units, and gives no CL/OL, MAF or AFR identification, so there is nothing substantive to compare.
- **Differs on:** Claim says this is a CL-to-OL enrichment threshold indexed by MAF with AFR output. The blind answer calls the input and the output unknown.


## traced_function

### 0x45098 -- DISAGREE

- **On record:** Project label "task02_knock_window" [TRACED]. Comment: [TRACED] Task [2] Knock window setup. KNOCK_FLAG+MAF, sets GBR, cal 0xD29E4/D2E60/D2E64
- **Blind (inferred):** update_iat_running_minimum -- Keeps a running minimum of intake air temperature in 0xFFFF8210. Each call lowers the stored value if the current IAT is colder. This looks like a 'lowest IAT seen' latch, probably since key-on or since some reset event. Other code may use it for cold-start or heat-soak decisions. When it is reset and who reads it are not shown.
- **Grader:** The claim describes a task that sets up the knock window using the knock flag, MAF, GBR and specific calibrations. The blind answer describes a small function that keeps a running minimum of IAT in a RAM variable. These are different functions.
- **Differs on:** knock window setup using KNOCK_FLAG+MAF and calibrations vs running minimum of intake air temperature

### 0x0DD52 -- DISAGREE

- **On record:** Project label "rtos_task1_fast_minimal" [TRACED]. Comment: [TRACED] RTOS Task 1: fast minimal (10 ms, pri 4). TCB=FFFF11D0. Body: JSR epilogue (0x35A4), RTS. Heartbeat / scheduler tick counter.
- **Blind (inferred):** task_drain_callback_queue_FFFF4520 -- Most likely a scheduler or RTOS task body that drains a queue or service object at 0xFFFF4520. For each item that 0xF97C reports as available (return 0), it runs the callback whose pointer is stored at 0xFFFF4520, passing a context at +4. It keeps going while a pending count or flag at 0xFFFF4572 is non-zero, then hands off through 0x35A4 (possibly a task-end or wait call).
- **Grader:** The claim describes a minimal body consisting only of JSR to the 0x35A4 epilogue and RTS, a heartbeat or tick task. The blind answer describes a substantial queue-drain loop with critical sections and a callback, then a call to 0x35A4. It agrees only on the task framing and the 0x35A4 call.
- **Differs on:** The claim says the body is just JSR epilogue then RTS (fast minimal heartbeat); the blind answer says it drains a queue at 0xFFFF4520 in a loop before calling 0x35A4.

### 0x88BD2 -- DISAGREE

- **On record:** Project label "diag_sensor_threshold_multi" [TRACED]. Comment: [TRACED] Template C: 6-channel sensor threshold comparison. Unpack via uint16_unpack (0xBE990), branch to DTC set/clear.
- **Blind (observed):** any_nonzero_in_status_block_FFFF2F88_305E -- unknown. From the code alone it is a boolean 'any element of these two RAM arrays is non-zero' test. Possibly an 'any timer, counter or request still active' check used to gate something such as sleep or a store, but the code shown does not support that.
- **Grader:** The claim describes a 6-channel sensor threshold comparison that branches to set or clear DTCs. The blind answer traces an OR over 33 fields (22 16-bit and 11 8-bit) that only checks for non-zero and returns a boolean, with no threshold comparison and no DTC set/clear. Both mention uint16_unpack, but the structure and the function differ.
- **Differs on:** Claim: a 6-channel threshold comparison that branches to DTC set/clear. Blind: a non-zero check over 33 RAM fields that returns a boolean, with no thresholds and no DTC writes.

### 0x0DE92 -- DISAGREE

- **On record:** Project label "rtos_task4_minimal" [TRACED]. Comment: [TRACED] RTOS Task 4: minimal task (20 ms, pri 1). TCB=FFFF11E8. Body: epilogue (0x35A4), RTS. Lowest-priority placeholder.
- **Blind (inferred):** task_service_callback_slot_loop -- Most likely an OS or kernel-style service routine. It repeatedly polls or claims a control object at 0xFFFF455C through 0xF97C(3, obj) under interrupts-masked protection. On success (return 0) it dispatches the callback stored in that object, passing the object's payload area (obj+4). It keeps going while a pending/active flag at 0xFFFF457B is set, then finishes with a closing call to 0x35A4 (possibly task exit, wait or reschedule). The concrete engine-control meaning is unknown.
- **Grader:** The claim describes a minimal placeholder task whose body is only the epilogue call at 0x35A4 followed by RTS. The blind answer describes a substantive loop that claims a control object and dispatches callbacks before calling 0x35A4. Both see it as an RTOS task-like routine ending in 0x35A4, but the blind answer directly contradicts the claim that the body is trivial.
- **Differs on:** Claim: the body is just the epilogue (0x35A4) and RTS, a minimal placeholder. Blind: a callback dispatch loop guarded by a critical section with a flag check, ending in 0x35A4.

### 0x11880 -- DISAGREE

- **On record:** Project label "atu_timer_capture_read" [TRACED]. Comment: [TRACED] 4 callers. Reads ATU timer counter at FFFFF738 with overflow-bit handling; struct_init/struct_init2 sandwich.
- **Blind (inferred):** toggle_port_b_bit15_atomic -- Atomically toggles one output bit (bit 15) of an on-chip I/O register. 0xFFFFF738 most likely corresponds to the Port B data register (PBDR) in the SH7058 I/O map, so this would flip port pin PB15. A pin toggled like this is typically a heartbeat or external-watchdog kick, but what the pin drives cannot be determined from this code.
- **Grader:** The claim says this reads an ATU timer counter at FFFFF738 with overflow-bit handling. The blind answer says it is an atomic read-modify-write that toggles bit 15 of what it identifies as a Port B data register at that address. Both describe the same address, a bit-15 manipulation and an enter/exit sandwich, but they assign different functions and different peripheral identities.
- **Differs on:** Claim: a timer-capture read of the ATU counter. Blind: a write-back that toggles bit 15 of a Port B output register.

### 0x5E774 -- AGREE

- **On record:** Project label "diag_monitor_interp_write_8F04" [TRACED]. Comment: [TRACED] Interpolation + write float result to FFFF8F04.
- **Blind (inferred):** store_u8_arg_as_float_FFFF8F04 -- unknown. It is a setter that publishes an 8-bit value (passed in by the caller) as a float in RAM 0xFFFF8F04. What that value means depends on the callers and on whoever reads 0xFFFF8F04, and neither is shown.
- **Grader:** Both describe a routine that calls an interpolation helper and writes the float result to FFFF8F04. The blind answer adds detail (gain 1.0, offset 0.0) and does not identify the diagnostic-monitor context, but the claim itself offers little beyond the mechanism.
- **Differs on:** none

### 0x37F00 -- PARTLY_AGREE

- **On record:** Project label "afl_multiplier_computation" [TRACED]. Comment: [TRACED] AFL multiplier computation subroutine. Reads FFFF31AC (primary) and FFFF31A4 (secondary) with weights CC2F4/CC2FC.
- **Blind (inferred):** calc_weighted_blend_31A4_31AC_to_7AB8 -- Unknown. The shape (a*K1 + b*K2)/K3 is that of a weighted average or blend of two related RAM quantities, for example a mix of two sensor or estimate values, or one step of a filter. The constant values and the identities of the RAM variables are not shown, so what is being blended cannot be determined.
- **Grader:** Both describe a weighted combination of 0xFFFF31AC and 0xFFFF31A4 using the CC2F4/CC2FC constants, so the mechanism matches. The blind answer cannot name the purpose, while the claim identifies it as the AFL multiplier computation.
- **Differs on:** The claim says the result is an AFL multiplier; the blind answer calls it an unknown weighted blend and leaves the purpose open.

### 0x0FE5C -- PARTLY_AGREE

- **On record:** Project label "charge_channel_dispatch_7" [TRACED]. Comment: [TRACED] IRQ-protected charge calc dispatcher for channel 7. interrupt_save(0xE0), stack_frame_setup(7), calls charge_calc_active(0x107B6) or charge_calc_idle(0x107F4), interrupt_restore.
- **Blind (inferred):** sync_item7_state_masked -- Most likely a critical section. 0x317C would raise the SR interrupt mask (0xE0 in the SR I-bit field is level 14) and return the old SR, and 0x3190 would restore it. Inside, the function reads a state or flag for item/channel 7 through 0x2EDC and applies one of two complementary actions through 0x107B6 or 0x107F4, perhaps set/clear or enable/disable. What item 7 is and what the two actions do cannot be told from this code.
- **Grader:** The blind answer matches the mechanism: an interrupt-masked wrapper that tests something for index 7 and dispatches to 0x107B6 or 0x107F4. It cannot say that this is charge calculation or that the two handlers are the active and idle variants.
- **Differs on:** The claim says these are charge calc active/idle handlers for channel 7; the blind answer leaves the purpose unknown, guessing set/clear or enable/disable.

### 0x582D2 -- PARTLY_AGREE

- **On record:** Project label "check_engine_running_diag" [TRACED]. Comment: [TRACED] 108 calls. Calls engine_running_eval(0xA6728) with R4=DTC_index. Returns R0=1 if engine running. Used by task55 (R4=72), task58 (R4=39).
- **Blind (observed):** wrap_A6728_ret_s8 -- unknown. It is an adapter that forwards its arguments to the routine at 0xA6728 and converts the result to a signed 8-bit value. What that routine computes cannot be told from this listing.
- **Grader:** The blind answer correctly identifies a thin wrapper that calls 0xA6728 and passes R4 through, but it cannot name the purpose: an engine-running check keyed by DTC index.
- **Differs on:** Claim says it checks whether the engine is running for a given DTC index; blind says purpose unknown, only a forwarding wrapper returning a sign-extended byte.

### 0x0FC04 -- PARTLY_AGREE

- **On record:** Project label "fuel_system_init" [TRACED]. Comment: [TRACED] Task 9 fuel vtable initialization. Writes 0xFB0 to FFFF5B64, validates via 0xFD34/0xFD6A. If FFFF415C==1: one-shot hw sync (raises IRQ to 15, programs ATU, enters sync loop). Normally early-exits when fuel system not being initialized.
- **Blind (inferred):** check_fault_and_halt_for_reset -- Most likely a fatal-fault or reset-request path. When a check returns a code other than -1 and a mode flag is 1, it locks out interrupts, leaves a marker (0x77) in RAM that survives reset, clears a control bit, calls a handler through a vector with the code, and then hangs, presumably so the watchdog resets the ECU.
- **Grader:** Both describe the same mechanism: writing 0xFB0 to FFFF5B64, validating via FD34/FD6A, gating on FFFF415C==1, raising the IRQ mask to 15 and entering a loop. The claim reads this as fuel-system vtable init with a one-shot hardware sync, while the blind answer reads it as a fatal-fault/reset halt path.
- **Differs on:** Purpose: the claim says fuel vtable init with a hw sync loop, the blind answer says a fault marker followed by an infinite hang for a watchdog reset.

### 0x37156 -- PARTLY_AGREE

- **On record:** Project label "fuel_trim_input" [TRACED]. Comment: [TRACED] A/F ratio to FFFF7A74 fuel trim input.
- **Blind (inferred):** seed_float_states_from_FFFF69F4_and_set_flags -- Most likely an initialise/reset routine for a group of float states (filter, previous or target values) around 0xFFFF7A54-0xFFFF7A64. It seeds all three with the current value of the quantity at 0xFFFF69F4, sets a byte flag or counter at 0xFFFF7A50 to 0xFF, and records the helper's result as a status byte at 0xFFFF7A75. The physical quantity at 0xFFFF69F4 and the meaning of the flags cannot be told from this code.
- **Grader:** The claim says this routine passes an A/F ratio into the FFFF7A74 fuel trim structure. The blind answer traces the same data flow, copying the value at FFFF69F4 into the FFFF7A74-based state block, but it cannot identify the quantity as A/F ratio or the block as fuel trim, and reads the routine as a generic state seed or reset.
- **Differs on:** The claim identifies the input as A/F ratio and its purpose as fuel trim; the blind answer leaves the quantity unidentified and calls the routine a generic state initialiser.

### 0x71D92 -- PARTLY_AGREE

- **On record:** Project label "sensor_float_interpolation" [TRACED]. Comment: [TRACED] Float interpolation sub (called from dispatcher 1 body).
- **Blind (inferred):** obd_similar_conditions_check_dtc31_32 (with input snapshot preamble) -- Most likely the OBD-II 'similar conditions' test used for pending or confirmed DTC handling (for example a misfire or fuel-system monitor). The rule is: engine speed within ~375 rpm of the stored value, load within 20 %, and the same warm-up status (coolant on the same side of ~71 °C) as the stored snapshot. The flag is raised when DTC slots 31 or 32 are already flagged in either status array while current conditions match.
- **Grader:** The claim calls the routine a float interpolation sub. The blind answer shows the preamble calling the uint8 interpolation helper and producing a float, but it identifies the overall function as an OBD similar-conditions check. The mechanism overlaps while the stated identity differs, and the claim is fairly thin.
- **Differs on:** The claim says the routine is a float interpolation subroutine; the blind answer says it is an OBD similar-conditions check whose preamble only uses interpolation.

### 0x067A6 -- PARTLY_AGREE

- **On record:** Project label "io_sched_event_atomic" [TRACED]. Comment: [TRACED] 26 calls. Atomic scheduler event + I/O: calls subroutines for event setup, sched_event_post, critical_section_exit.
- **Blind (inferred):** hw_transfer_then_write_port_F76C -- Likely a low-level peripheral transaction. It sets up a channel or device (0x68E0, then 0x6984 with mode 2) and reads a 16-bit result (0x6A48). It then, with interrupts masked, does a read-modify-write on I/O register 0xFFFFF76C, probably clearing or setting bit 4 (or a 4-wide field) to 0. A chip-select or control-pin release is a plausible reading. What the device or signal actually is cannot be told from this code.
- **Grader:** Both describe a routine that calls setup subroutines and does I/O inside a critical section, ending with critical_section_exit. The claim names it a scheduler event post. The blind answer reads it as a peripheral transaction with a register read-modify-write and never mentions scheduler events.
- **Differs on:** The claim says one call is sched_event_post (a scheduler event). The blind answer treats the calls as device setup/read and a write to I/O register 0xFFFFF76C.

### 0x7D526 -- PARTLY_AGREE

- **On record:** Project label "o2_catalyst_diag_dispatch" [TRACED]. Comment: [TRACED] Catalyst/O2 sensor diagnostic monitor — outer dispatch shell. 10 BSR calls + tail-call to EEPROM adapt store at 0x07E014.
- **Blind (observed):** sub_07D526_call_sequence_07D9F8_to_07E014 -- unknown. The code fits a dispatcher that runs one group of related routines in sequence, probably once per scheduler tick. Nothing shown identifies what that group does. The callees sit in 0x07D9F8-0x07E13C, close after this function. The order is not strictly ascending (0x07E13C runs before 0x07DC88), which suggests a data dependency between those routines.
- **Grader:** The blind answer matches the mechanism exactly: an outer dispatcher making 10 BSR calls and then tail-calling 0x07E014. It could not identify the purpose, which the claim gives as catalyst/O2 diagnostic with an EEPROM adapt store.
- **Differs on:** The claim names the subsystem as the catalyst/O2 sensor diagnostic and 0x07E014 as an EEPROM adapt store; the blind answer leaves the purpose unknown.

### 0x8E3E4 -- PARTLY_AGREE

- **On record:** Project label "percyl_precalc_ect_gate" [TRACED]. Comment: [TRACED] Stage 0: Read ECT from FFFF4144, compare thresholds (cal 0xC545C), gate pipeline on check_diag_state.
- **Blind (observed):** sub_08E3E4_copy_byte_65C2_and_conditional_tailcall_08EF14 -- unknown. Structurally it is a periodic task or sequencing wrapper: run a sub-step, latch a status byte into local RAM, then run a second step (0x08EF14) only when the predicate routine 0x000582AC returns false/zero. What the bytes and the called routines mean cannot be told from this listing.
- **Grader:** Both describe a routine that gates a later pipeline step on a predicate call, which plausibly matches 'gate pipeline on check_diag_state'. The blind answer sees no ECT read from FFFF4144 or threshold compare against cal 0xC545C; it reports a byte copy from 65C2 to AB60 and gives no purpose.
- **Differs on:** Claim says it reads ECT from FFFF4144 and compares against thresholds at 0xC545C; blind answer observes only a call to 0x08E474 and a 65C2→AB60 byte copy, with purpose unknown.

### 0x66DEC -- PARTLY_AGREE

- **On record:** Project label "task56_evap_sub_disabled_B" [TRACED]. Comment: [TRACED] EVAP sub when diagnostics disabled (path B).
- **Blind (hunch):** eval_flagbit_0D86_via_066E2E -- Unknown from the code shown. Structurally it is a thin wrapper: it tests one packed status bit, selected through a (byte-offset, bitmask) descriptor table into a RAM flag array. It passes that bit, a value from 0x582D2(8), and two ROM parameter blocks (0x97520, 0x9756C) to a shared evaluator at 0x066E2E. That shape is typical of per-monitor or per-DTC diagnostic wrappers that feed an enable condition plus calibration blocks to a common judging routine, but this is a hunch.
- **Grader:** The blind answer gets the mechanism: a thin wrapper that tests a flag bit and passes it, with calibration blocks, to a shared evaluator, and it guesses a diagnostic-monitor context. It does not identify EVAP or the diagnostics-disabled path, and it states the purpose is unknown.
- **Differs on:** Claim identifies it as the EVAP sub-routine for the diagnostics-disabled path B; the blind answer only offers a generic diagnostic-wrapper hunch.

### 0x43750 -- PARTLY_AGREE

- **On record:** Project label "knock_wrapper" [TRACED]. Comment: [TRACED] Checks cyl index R4 in {0,6,12,18} and counter < 4, then BSR to knock_detector
- **Blind (inferred):** latch_index_and_dispatch_on_slot_0_6_12_18 -- A gated dispatcher. On every sixth value of an index argument (a 0..23 slot or step counter?) it snapshots a small index byte from 0xFFFF4308 into 0xFFFF81AC. If that index is valid (0-3) it runs two processing routines, 0x043782 and then 0x043B7C. The 0-3 range would fit a per-cylinder index on a 4-cylinder engine, but the code does not prove it. The exact meaning is unknown.
- **Grader:** The blind answer matches the gating mechanism: R4 must be in {0,6,12,18} and the counter must be below 4 before it calls a subroutine. It does not identify the purpose as a knock-detection wrapper and calls the meaning unknown.
- **Differs on:** The claim identifies the callee as knock_detector. The blind answer cannot name the callees' purpose.

### 0x07086 -- PARTLY_AGREE

- **On record:** Project label "avcs_solenoid_background" [TRACED]. Comment: [TRACED] Task 0 call_11. AVCS/VVT solenoid duty at slow rate. Checks FFFF4191==1, writes via sched_timer_dispatch to I/O port 0xF6EA.
- **Blind (observed):** critsec_run_71CC_then_flag4191_call_E6E4 -- unknown. It wraps a call to the routine at 0x71CC, plus a conditional follow-up action, in an interrupt-masked critical section. The follow-up runs only when the RAM byte at 0xFFFF4191 is 1. The (0xFFFFF6EA, 4, 1) arguments look like 'set bit 4 of an on-chip peripheral register to 1', but neither the helper at 0xE6E4 nor the register is identified here.
- **Grader:** The blind answer matches the mechanism: it checks 0xFFFF4191==1 and then calls a helper that writes to 0xF6EA. It does not identify the function as AVCS/VVT solenoid duty control and leaves the purpose unknown.
- **Differs on:** Claim identifies purpose as AVCS solenoid duty background task; blind says purpose unknown and guesses a generic bit-write helper rather than sched_timer_dispatch.

### 0x602DC -- PARTLY_AGREE

- **On record:** Project label "task53_diag_monitor" [TRACED]. Comment: [TRACED] Task 53: diagnostic readiness computation.
- **Blind (observed):** scale_raw_4158_to_float_9088_and_run_subtasks -- unknown. The visible part converts a raw integer quantity into a scaled float copy at 0xFFFF9088 and then sequences three subroutines, apparently a small task or step wrapper. What the quantity is and what the scale factor means cannot be told from this code.
- **Grader:** The blind answer describes the mechanism: it scales a raw value and runs a sequence of subroutines, which it calls a task or step wrapper. That fits a task routine, but it explicitly cannot name the purpose, so it never reaches the claim's diagnostic readiness computation.
- **Differs on:** The claim identifies the routine as diagnostic readiness computation (Task 53). The blind answer leaves the purpose unknown beyond a generic task wrapper that scales a value.

### 0x7C280 -- PARTLY_AGREE

- **On record:** Project label "egr_output_handler" [TRACED]. Comment: [TRACED] EGR output handler. GBR=FFFFA158. Reads FFFF2BFC period. Iterates 10 monitor bits across GBR+0/1/2, clearing each processed bit.
- **Blind (observed):** prioritized_request_to_4bit_output_pattern_timer -- Unknown. The code is a timed sequencer. Ten pending request bits, taken in fixed priority order, each produce a 4-bit on/off pattern on four output flags. The pattern is held while an arm flag (GBR+37 bit0, set elsewhere) is on and the counter has not exceeded a limit. When the time runs out, the arm flag is dropped and the serviced request is consumed. The codes form the full set of 1-hot and 2-hot 4-bit patterns (1,2,4,8 / 5,6,10,9 / 3,12). That suggests four discrete drive lines tested singly and in pairs, for example an actuator or output self-test or a phase pattern. This reading is not established by the code shown.
- **Grader:** The mechanics match the claim: GBR=FFFFA158, a period/limit read from FFFF2BFC, and 10 request bits across GBR+0/1/2, each cleared once it has been processed. The blind answer could not name the purpose, so it never identifies this as an EGR output handler. It instead speculates about an actuator self-test or phase pattern.
- **Differs on:** The claim says this is EGR output handling; the blind answer leaves the purpose unknown and suggests a generic 4-line actuator test or phase pattern.

### 0x07034 -- PARTLY_AGREE

- **On record:** Project label "task10_avcs_solenoid_output" [TRACED]. Comment: [TRACED] Task 10 call_30: AVCS/VVT solenoid PWM output. Accesses I/O register 0xF6EA (solenoid duty control port), reads ROM calibration table 0xE6E4. Workspace: FFFF4166-4193 (solenoid state bytes and words).
- **Blind (inferred):** subsys_init_4166_block -- Most likely a one-shot initialisation/reset routine for one subsystem. It clears that subsystem's byte-sized state variables (flags or counters) in the 0xFFFF4166–0xFFFF4199 RAM block and chains to its sub-init routines. Which subsystem it serves is unknown from this code.
- **Grader:** Both describe the same routine, which touches 0xF6EA, 0xE6E4 and the FFFF4166-4193 workspace. The blind answer reads it as a subsystem init/reset that zeroes state and cannot name the subsystem. The claim calls it the AVCS solenoid PWM output and treats 0xE6E4 as a calibration table, whereas the blind answer sees 0xE6E4 as a called helper.
- **Differs on:** Claim says AVCS solenoid PWM output; blind says generic init/reset of unidentified subsystem state.

### 0x403C4 -- PARTLY_AGREE

- **On record:** Project label "ect_warmup_correction" [TRACED]. Comment: [TRACED] Mode-selected ECT correction, 4 curves.
- **Blind (observed):** calc_ect_based_value_4table_select -- Unknown. The code computes a coolant-temperature-dependent 1D table value and stores it at 0xFFFF7F68. Which of four calibration variants is used depends on a mode/state flag (0xFFFF90BE, zero vs non-zero) and on whether a second state byte (0xFFFF6254) equals 1. It is most likely an ECT-based compensation or target used elsewhere, but neither flag nor the output is identified.
- **Grader:** The blind answer matches the mechanism: an ECT-based 1D lookup with four mode-selected curves. It does not name the purpose as a warmup correction and only calls it a generic ECT-based compensation or target.
- **Differs on:** Claim identifies it as a warmup correction; blind leaves the purpose unknown (generic ECT compensation).

### 0x3F374 -- PARTLY_AGREE

- **On record:** Project label "ect_warmup_consumer" [TRACED]. Comment: [TRACED] ECT warmup consumer (2050 bytes). Reads FFFF7F68, outputs 8 per-channel corrections.
- **Blind (inferred):** calc_final_per_cylinder_advance_with_mode_overrides -- Most likely the final per-cylinder ignition advance. It takes a base value (7F0C), adds a set of correction terms and subtracts others (likely knock/retard terms 7FBC/8000), then applies two per-cylinder 4-element offset arrays. Special modes override with fixed values: a cranking/test mode (8F16==3 or 1), and conditional fixed-timing windows. Those windows are gated by rpm range, low load, coolant temperature and post-event hold timers. The windows may be idle or post-start events, but this is not confirmed.
- **Grader:** Both describe a routine that reads 0xFFFF7F68 and produces per-channel corrections. The blind answer treats 7F68 as one term among many in a final per-cylinder advance sum with mode overrides, rather than an ECT-warmup-specific consumer, and it reports four outputs, not eight.
- **Differs on:** The claim calls it an ECT warmup consumer with 8 per-channel outputs; the blind answer calls it a general final per-cylinder advance aggregator with 4 float outputs, where 7F68 is just one additive term.

### 0x34EF4 -- PARTLY_AGREE

- **On record:** Project label "afl_airflow_update" [TRACED]. Comment: [TRACED] AFL airflow update (Dispatch B entry).
- **Blind (inferred):** subsys_7940_snapshot_inputs_and_run_subtasks -- Top-level periodic routine for one subsystem whose working variables sit around 0xFFFF7920-0xFFFF7941. It first copies a float and a byte status or flag from elsewhere in RAM into that block as a snapshot. It then runs that subsystem's sub-steps in sequence. Which engine function the subsystem is (e.g. a particular control or diagnostic) cannot be determined from this code.
- **Grader:** The blind answer correctly identifies this as a top-level dispatch or update routine that snapshots inputs and runs subtasks. It cannot name the subsystem as airflow/AFL, so it gets the mechanism but not the purpose.
- **Differs on:** Claim identifies the subsystem as the AFL airflow update. The blind answer says the subsystem's identity cannot be determined.

### 0x3697A -- PARTLY_AGREE

- **On record:** Project label "clol_hysteresis_sub" [TRACED]. Comment: [TRACED] CL/OL hysteresis sub-function. Reads CL->OL throttle and BPW descriptors.
- **Blind (observed):** check_two_inputs_below_rpm_thresholds_hyst -- unknown. It is a boolean enable/condition check: true when two unidentified quantities are both below their own RPM-dependent limits, with hysteresis. That fits something like a low-load/low-airflow region detector feeding a diagnostic or mode enable, but what the two inputs are cannot be told from this code.
- **Grader:** The blind answer correctly describes a hysteresis comparison of two inputs (plausibly throttle and BPW) against RPM-dependent thresholds producing a boolean, which matches the mechanism of a CL->OL hysteresis check. However, it cannot identify the inputs or say that the function serves the closed-loop/open-loop transition.
- **Differs on:** Claim identifies it as the CL/OL hysteresis check using throttle and BPW; blind leaves inputs and purpose unknown (guesses low-load region detector).

### 0x4BA30 -- PARTLY_AGREE

- **On record:** Project label "fuel_pump_mode_select" [TRACED]. Comment: [TRACED] Fuel pump mode selection state machine - selects 100/66.7/33.3/0% duty.
- **Blind (hunch):** indicator_output_pair_sequencer_8366 -- Hunch: it drives two related on/off outputs (blk[2], blk[3]), possibly a warning lamp or MIL state. They are forced on as a default or bulb-check state when a float (possibly battery voltage) is <=8.0 or a word (possibly engine speed or a timer) is below a calibration threshold. They follow a 3-phase blink/step pattern of 47 ticks per phase in a special mode, and they are handed to 0x04BDAA for normal operation. The exact purpose cannot be fixed from this code.
- **Grader:** The blind answer describes a mode-selecting state machine that drives two coupled outputs through stepped states, which could encode the claimed duty levels. Its hedged guess that this is a warning lamp or MIL blink pattern differs from the claimed fuel pump duty selection.
- **Differs on:** The blind answer guesses a warning lamp/MIL output; the claim says fuel pump duty selection (100/66.7/33.3/0%).

### 0x30744 -- PARTLY_AGREE

- **On record:** Project label "sensor_prep" [TRACED]. Comment: [TRACED] Calls 0x23E48, writes FFFF73A2.
- **Blind (observed):** store_result_of_sub_23E48_to_FFFF73A2 -- unknown. It is a thin wrapper that latches an 8-bit result from routine 0x23E48 (possibly a flag or state code) into the RAM byte 0xFFFF73A2. What that value means cannot be told from this code.
- **Grader:** Both describe the same mechanism: a call to 0x23E48 followed by a write to FFFF73A2. The claim labels it sensor preparation, while the blind answer leaves the purpose unknown, so the blind answer is vaguer.
- **Differs on:** Claim names the purpose as sensor prep; blind answer says purpose unknown.

### 0x34EC8 -- BLIND_ABSTAINED

- **On record:** Project label "afl_airflow_processor" [TRACED]. Comment: [TRACED] AFL airflow processor. Dispatch Table A entry [7].
- **Blind (observed):** ect_lookup_set_ram_78B0_78B8_then_continue -- unknown. This looks like one branch or entry path of a routine that fills a small block of float state around 0xFFFF78B0-0xFFFF792C. It sets one coolant-temperature-dependent value, copies another RAM value, and loads a fixed ROM constant, then joins shared code at 0x034F28. What the table at 0xAD054 and the RAM at 0xFFFF43FC and 0xFFFF78B0-B8 mean cannot be told from this code.
- **Grader:** The claim says this is the AFL airflow processor, dispatch entry [7]. The blind answer describes a coolant-temperature table lookup and some RAM stores but explicitly gives the purpose as unknown. It never mentions airflow or AFL, so there is nothing about the claimed function to compare.
- **Differs on:** none


## unverified_function

### 0x09B2C -- DISAGREE

- **On record:** Project label "dt_float_correction" [UNVERIFIED]. Comment: [UNVERIFIED] Dead time float correction. Reads FFFF4280, FFFF42F4, FFFF4158, FFFF4168. R1=[FFFF4280]+[FFFF42F4]+@(8,stack); converts to float index; 3-branch interpolation from float tables at 0x9C14-0x9C28. Produces corrected dead time float for runtime compensation.
- **Blind (inferred):** crank_angle_event_schedule -- Likely schedules a per-channel crank-angle event, such as ignition or injection. The timer counts appear to be turned into degrees elapsed since the last reference (counts*180/period). It then finds the degrees left from the current reference angle to the target within a 720-degree four-stroke cycle. If the event is less than 35 degrees away it is armed straight away through 0x9F72 (state 0); otherwise it is left pending (state 2) for later tooth or reference processing.
- **Grader:** The claim describes a dead-time float correction that interpolates from float tables. The blind answer describes a crank-angle event scheduler: it converts timer counts to degrees, wraps the angle within a 720-degree cycle and fills a per-channel event record. Both read the same RAM addresses, but they assign different functions.
- **Differs on:** The claim says this is a dead time correction using 3-branch interpolation from tables at 0x9C14-0x9C28. The blind answer says it schedules a crank-angle event, computing degrees as counts*180/period, wrapping within 720 degrees and storing a record at 0xFFFF4284+idx*28.

### 0x0300E -- DISAGREE

- **On record:** Project label "injector_ic_trigger" [UNVERIFIED]. Comment: [UNVERIFIED] Sets bit15 on external injector IC at 0xF00F00.
- **Blind (inferred):** call_hook_3F2C_with_flag_1290_bit15 -- A wrapper that raises a status/'in-progress' flag (bit 15 of the word at 0xFFFF1290) for the duration of an indirect call through the pointer stored at 0x3F2C, so that other code (for example an interrupt or a scheduler check) can see that the routine is running. What the flag word and the called routine actually are cannot be told from this listing.
- **Grader:** The claim says the routine sets bit 15 on an external injector IC at 0xF00F00. The blind reading has it setting bit 15 of the RAM word at 0xFFFF1290 around an indirect call, then clearing it, with no external IC address involved.
- **Differs on:** Target of the bit15 write: the claim says the external injector IC at 0xF00F00, the blind answer says RAM 0xFFFF1290 set temporarily around a call through 0x3F2C.

### 0x44DB0 -- DISAGREE

- **On record:** Project label "task09_knock_det" [UNVERIFIED]. Comment: [UNVERIFIED] Task [9] Knock detection. KNOCK_FLAG+IAM+RPM, sets GBR
- **Blind (inferred):** update_engine_load_filtered_and_delta -- Keeps a smoothed (first-order lagged) engine load and a load-minus-filtered-load signal. That difference acts as a high-pass, rate-of-change measure of load. It is most likely used to detect load transients such as tip-in/tip-out or load-change enrichment and compensation logic, but no consumer of 0xFFFF81F8 is shown.
- **Grader:** The claim describes a knock detection task that uses the knock flag, IAM and RPM and sets GBR. The blind answer describes an engine load lag filter that also computes a load-minus-filtered delta, with nothing about knock, IAM or GBR.
- **Differs on:** Knock detection task (KNOCK_FLAG+IAM+RPM, sets GBR) vs. engine load lag-filter and load-delta computation

### 0x02FEC -- PARTLY_AGREE

- **On record:** Project label "inj_final_hw_write" [UNVERIFIED]. Comment: [UNVERIFIED] Final hardware write to injector IC + XRAM.
- **Blind (inferred):** call_hook_3F28_with_busy_bit14 -- A wrapper that raises a status or flag bit (bit 14 of the flags word at 0xFFFF1290) while one routine, taken from a ROM pointer table, runs. The most likely use is an 'in progress' or re-entrancy marker that other code (an interrupt or scheduler path) can test. The pointer at 0x3F28 and the meaning of the flag are not resolved in this listing, so the specific purpose is unknown.
- **Grader:** The claim says this is the final hardware write to the injector IC and XRAM. The blind answer describes a wrapper that sets a flag bit around an indirect call through a ROM pointer, and leaves the purpose unknown. It neither confirms nor contradicts an injector write; the wrapped callee could be that write.
- **Differs on:** The claim names the routine as the injector IC/XRAM hardware write; the blind answer sees only a flag-setting wrapper around an unresolved indirect call.

### 0x71A7A -- PARTLY_AGREE

- **On record:** Project label "sensor_diag_state_helper" [UNVERIFIED]. Comment: [UNVERIFIED] Packs uint8(0) -> FFFF255E (diagnostic state byte).
- **Blind (observed):** store_uint8_pack0_to_FFFF255E -- unknown. It is a thin wrapper that refreshes or initialises the 16-bit RAM word at 0xFFFF255E from uint8_pack(0). Its structure suggests an init or periodic-update hook, but what the packed value means cannot be told from this code.
- **Grader:** Both describe packing uint8(0) and storing the result to FFFF255E. The blind answer cannot name the purpose, while the claim calls it a sensor diagnostic state byte. The blind answer also says the store is a 16-bit word rather than a byte.
- **Differs on:** The claim identifies FFFF255E as a diagnostic state byte; the blind answer leaves the purpose unknown and describes a word store.

### 0x34C18 -- PARTLY_AGREE

- **On record:** Project label "afl_clol_transition_handler" [UNVERIFIED]. Comment: [UNVERIFIED] AFL CL/OL transition handler. Calls afl_clol_mode_check at 0x34C54.
- **Blind (observed):** latch_table_value_on_flag_edge_7874 -- unknown. Structurally it samples and holds a value: a table lookup indexed by the float at 0xFFFF7874 is captured into 0xFFFF787E only at the moment a flag turns on or a word/counter reaches zero, and held between those events. What the flag, the word and the table mean cannot be told from this code.
- **Grader:** Both describe a transition or edge-triggered handler, but the blind reader leaves the purpose unknown and cannot confirm any AFL closed-loop/open-loop role. The blind answer also names its only call as a table helper at 0xBE874, not a CL/OL mode check.
- **Differs on:** The claim says the routine calls afl_clol_mode_check at 0x34C54 and handles the AFL CL/OL transition. The blind answer says it calls LowPW_TableProcessor at 0xBE874 to latch a table value on a flag or word edge, purpose unknown.

### 0x45A84 -- PARTLY_AGREE

- **On record:** Project label "task15_rough_corr" [UNVERIFIED]. Comment: [UNVERIFIED] Task [15] Rough correction range. Rough Corr Min KC Advance (0xD2EDC)
- **Blind (observed):** update_flag_8278_when_float_8258_reaches_threshold -- unknown. Structurally this is an enable/condition flag: a module state byte (8277) must be 1, two inhibit conditions (8233 non-zero, bit 0 of 3244) must be absent, and a float quantity at the head of the same RAM block must have reached a calibrated minimum. Which subsystem it belongs to cannot be told from this code.
- **Grader:** The claim says this is a task that sets a rough-correction range flag using a minimum KC-advance calibration at 0xD2EDC. The blind answer gets the mechanism right: a flag is set when a RAM float reaches the 0xD2EDC calibration minimum, subject to inhibit conditions. It cannot name the knock-control or rough-correction purpose, so it is vaguer than the claim.
- **Differs on:** The claim identifies the function as the knock-control rough-correction range enable based on minimum KC advance; the blind answer leaves the purpose unknown.

### 0x0F320 -- PARTLY_AGREE

- **On record:** Project label "ADI0_Handler2" [UNVERIFIED]. Comment: [UNVERIFIED] ADI0 second handler: calls ADC_DataCopy(0x7110), Sensor_Scaling(0x7D26), ADC_Notify(0xBB6C).
- **Blind (inferred):** periph_flag_ack_then_run_tasks_F320 -- Probably the body of an interrupt or periodic handler. It acknowledges or clears a hardware status/flag register (a dummy read followed by a write, the usual SH7058 sequence for clearing flags), or rewrites a control register, and then runs three sub-tasks in a fixed order. What the tasks are and which peripheral the register belongs to cannot be told from this listing.
- **Grader:** Both describe a handler that calls 0x7110, 0x7D26 and 0xBB6C in order. The blind answer suspects an interrupt handler with a flag acknowledge. It cannot tie the routine to the ADI0 (A/D) interrupt or name the callees as ADC copy, sensor scaling and notify.
- **Differs on:** The claim identifies the routine as the ADI0 A/D interrupt handler and names the callees' roles; the blind answer leaves the peripheral and the task roles unknown.

### 0x035FC -- PARTLY_AGREE

- **On record:** Project label "inj_channel_timer_setup" [UNVERIFIED]. Comment: [UNVERIFIED] RAM-resident injection channel timer setup.
- **Blind (inferred):** channel_handle_init_and_dispatch -- Likely a low-level driver or OS-style service. It binds a per-call request/handle object to one of a static table of channel descriptors, records the request, then either starts the operation (the idle path calls 0x3820 with a descriptor parameter) or dispatches through a state-indexed jump table to a handler for the channel's current state. The exact peripheral or service (serial/CAN comms, flash/EEPROM access, task scheduler) cannot be told from this code alone.
- **Grader:** Both describe channel setup through descriptor tables, which fits a channel timer setup. The blind answer cannot name the purpose, though: it suggests comms, flash or a scheduler rather than injection timing, so it is vaguer than the claim.
- **Differs on:** The claim says the channels are injection timer channels; the blind answer leaves the peripheral or service unidentified.

### 0x44834 -- PARTLY_AGREE

- **On record:** Project label "task14_knock_thresh_lu" [UNVERIFIED]. Comment: [UNVERIFIED] Task [14] Knock threshold lookup. 8 cal params 0xD2DEC-0xD2E04
- **Blind (observed):** window_gated_counter_update_0x044834 -- Unknown. The shape fits a diagnostic or learning monitor that counts qualifying samples inside an rpm/load/parameter window. Counter 0xFFFF822B counts window samples whose previous-call 0xFFFF81F0 value failed the deadband test, and it stops at a calibrated limit. Counter 0xFFFF822A counts window samples taken while flag 0xFFFF8254 == 1. What the monitored quantities are cannot be determined from this code.
- **Grader:** Both describe a function that uses cal params 0xD2DEC-0xD2E04. The blind reading treats them as rpm/load/parameter window gates that feed sample counters and cannot name the purpose. The claim calls the function a knock threshold lookup. The blind reading is vaguer on purpose and frames the mechanism as a windowed counter rather than a threshold lookup.
- **Differs on:** The claim says the function is a knock threshold lookup. The blind reading describes window-gated counter increments and does not identify knock.

### 0x0E54E -- PARTLY_AGREE

- **On record:** Project label "subtask_wrap_fuel_tableB" [UNVERIFIED]. Comment: [UNVERIFIED] Secondary sub-task wrapper for fuel_dispatch_table_B path. Indexed at secondary sub-table [0x11BF0], flags=0 (always execute). JSR 0x5798 (fuel_tableB pre-calc/setup), then JMP 0x049CF0 (tableB runner). Called via: Task2/3 -> rtos_secondary_dispatcher -> this wrapper.
- **Blind (observed):** seq_call_005798_then_049CF0 -- unknown. It is a dispatcher or wrapper that chains two routines, probably one step of a scheduler or init list. What the two routines do cannot be told without disassembling 0x5798 and 0x49CF0.
- **Grader:** The blind answer matches the mechanism exactly: a wrapper that calls 0x5798 and then tail-jumps to 0x49CF0. It even guesses a scheduler step, but it cannot name the fuel table B purpose that the claim gives.
- **Differs on:** The claim says this is the fuel_dispatch_table_B setup/runner wrapper. The blind answer says the purpose is unknown.

### 0x21A40 -- PARTLY_AGREE

- **On record:** Project label "frontO2_process" [UNVERIFIED]. Comment: [UNVERIFIED] Front O2 sensor processing. Reads rich limit (0.75 lambda) inline, atm pressure comp via descriptor 0xAAE8C.
- **Blind (observed):** update_scaled_multiplier_and_lag_filtered_copies -- Unknown. Mechanically it maintains a multiplier centred on 1.0 and limited to 2.0 at the top. The 0xFFFF6898-indexed table scales how far the multiplier departs from 1.0. Three lag-filtered versions are produced. They are snapped to the target while a condition is active or has just ended, held at 1.0 when an enable byte is 0 or a mode byte equals 1, and bypassed when calibration byte 0xC0354 is set to 0xFF.
- **Grader:** Both describe the same mechanism: a multiplier around 1.0 scaled by table 0xAAE8C with clamps (the 0.75 lower clamp would be the rich limit). The blind answer cannot name the purpose (front O2 / lambda processing, atmospheric pressure compensation), and the claim does not mention the lag filters.
- **Differs on:** The claim identifies this as front O2 sensor processing with atmospheric pressure compensation; the blind answer leaves the purpose unknown.

### 0x34778 -- PARTLY_AGREE

- **On record:** Project label "afl_range_selection" [UNVERIFIED]. Comment: [UNVERIFIED] AFL range selection with additional enable logic.
- **Blind (inferred):** eval_window_stability_enable_flag_FFFF78A4 -- Most likely an enable or 'conditions met' flag for some monitor or learning routine. The conditions are: a parameter inside a calibrated window, a second quantity (possibly a rate or deviation) near zero, a state byte equal to 1, an optional counter or timer having reached a calibrated minimum, and a further variable below a limit. Which subsystem it serves cannot be told from this code.
- **Grader:** The blind answer describes an enable flag built from several conditions, which matches the claim's 'additional enable logic'. It does not identify AFL range selection or any subsystem, so it is vaguer than the claim.
- **Differs on:** The claim names the purpose as AFL range selection; the blind answer finds only a generic enable/conditions-met flag with no subsystem identified.

### 0x71AFA -- PARTLY_AGREE

- **On record:** Project label "sensor_conditional_calc" [UNVERIFIED]. Comment: [UNVERIFIED] Conditional sensor computation: sensor_val - offset + corrections, float_abs, float_clamp. Output -> FFFF97B0/97B4. Cal bounds at 0xC50B4.
- **Blind (observed):** update_filtered_sum_97B0_97B4 -- unknown. It keeps a raw value at 0xFFFF97B0 and a smoothed value at 0xFFFF97B4. That value is a non-negative combination of four RAM floats (A - B + C + D). The value 1.0 is used as the inactive or reset default.
- **Grader:** Both describe a conditional computation of val - offset + corrections, clamped and written to 97B0/97B4, with a cal constant at C50B4. The blind answer reads the second step as a lag filter using C50B4 as a parameter, where the claim calls it abs/clamp with cal bounds. Neither identifies the physical quantity, and the claim itself is generic.
- **Differs on:** The claim says float_abs/float_clamp with cal bounds at C50B4. The blind answer says float_max(x,0) followed by float_lag_filter, with C50B4 as a filter constant, so 97B4 is a smoothed copy.

### 0x0E794 -- PARTLY_AGREE

- **On record:** Project label "sched_timer_dispatch" [UNVERIFIED]. Comment: [UNVERIFIED] 8 calls. Timer-based scheduler dispatch. Manages periodic callback timing.
- **Blind (inferred):** os_service_masked_call_current_ctx_field8 -- Most likely a kernel or RTOS service wrapper. It enters a critical section with all interrupts masked and looks up a context or control-block structure (probably the current task's) via 0x40CE. It runs a service routine on the caller's argument together with a field at offset 8 of that structure, then leaves through a common exit path at 0xFBA4. That exit probably restores the interrupt level and/or runs a scheduler/dispatch check. The specific service performed is unknown.
- **Grader:** Both place the routine in the OS/scheduler layer. The claim names a specific function, timer-based dispatch managing periodic callbacks. The blind answer describes a generic masked kernel service wrapper with a possible dispatch-check exit and says the specific service is unknown, so it is vaguer and mentions no timer.
- **Differs on:** The claim says timer-based periodic callback dispatch. The blind answer says a generic critical-section service call on the current context field at +8, purpose unknown.

### 0x33CC4 -- PARTLY_AGREE

- **On record:** Project label "cl_fuel_target_calc" [UNVERIFIED]. Comment: [UNVERIFIED] CL Fueling Target computation. Accesses both Comp A (0xD14D0) and Comp B (0xD1740) via descriptors.
- **Blind (inferred):** lookup_rpm_load_map_4way_select -- Unknown which calibration this is. It computes a value from an engine-load by RPM 2D map, picking one of four calibration variants. The choice depends on a mode/state byte returned by 0x22CF4 (==1 or not) and a RAM flag at 0xFFFF984D, which the caller can override with the r5 argument. Typical candidates would be ignition, AVCS, fuel or boost target maps with alternate variants, but nothing shown fixes which.
- **Grader:** The blind answer finds a descriptor-based load×RPM 2D map lookup with selectable calibration variants, which fits a target computation drawing on multiple compensation tables. It cannot name the purpose, though, and lists fuel only as one candidate among several, so it does not confirm the closed-loop fueling target identity.
- **Differs on:** The claim identifies the function as the CL fueling target using Comp A and Comp B. The blind answer leaves the calibration unidentified and describes a four-way table selection rather than two named compensation tables.

### 0x07110 -- BLIND_ABSTAINED

- **On record:** Project label "ADC_DataCopy" [UNVERIFIED]. Comment: [UNVERIFIED] Copy ADC conversion results to working RAM structures.
- **Blind (observed):** task_group_dispatch_with_cal_option_0x5A -- unknown. Structurally this is a sequencer or dispatcher for a group of sub-routines. The group is suppressed while the RAM flag 0xFFFF4172 is nonzero, and one optional routine is enabled by a calibration byte set to the magic value 0x5A. A trailing routine at 0x0076B0 always runs. What the routines do cannot be told from this listing.
- **Grader:** The blind answer describes a dispatcher that calls subroutines, gated by a flag and a cal byte, but states its purpose is unknown. It offers nothing about ADC data copying that could be compared with the claim.
- **Differs on:** Blind says purpose unknown (generic dispatcher); claim says copies ADC results to RAM.

### 0x45A3E -- BLIND_ABSTAINED

- **On record:** Project label "task13_rough_corr" [UNVERIFIED]. Comment: [UNVERIFIED] Task [13] Rough correction range. Rough Corr Min KC Advance (0xD2EDC)
- **Blind (observed):** update_rpm_load_subcheck_and_combine_4_flags -- Unknown from this code alone. It refreshes an rpm/load-based sub-evaluation in 0x045F9A, then publishes a combined 'all conditions satisfied' flag at 0xFFFF8277. Possibly an enable or permission flag for some monitor or feature (hunch). It is also unconfirmed that 0x045F9A writes any of the four flags it checks.
- **Grader:** The claim says this is a rough knock-correction range task. The blind answer describes the mechanism (an rpm/load subcall plus an AND of four flags) but states the purpose is unknown and offers only a vague hunch about an enable flag. Nothing in it can be compared with knock or rough correction.
- **Differs on:** none

## No answer

- fn-0DDAC: grading stopped: refusal (cyber)
- fn-0E4E6: grading stopped: refusal (cyber)
- tab-AE370: stopped: refusal (cyber)
