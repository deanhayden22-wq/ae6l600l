# Blind audit of tuning conclusions

> Memory notes and subsystem-doc sections, re-derived from ROM bytes by a reader that
> could not see them, then compared statement by statement. **A contradiction means one
> side is wrong, not which.** Decode it by hand before changing a doc or a tune.
> Batches msgbatch_01VVa9aiVY42JwoZx2gJMGtc (blind) and msgbatch_01UCJwNm1a9u6AhqTo3B9pUM (grading), model claude-opus-5-5, 2026-10-11 20:53:44.

## By source

| Source | Claims | agree | partly_agree | disagree | blind_abstained | not_comparable | no answer |
|---|---|---|---|---|---|---|---|
| memory | 28 | 20 | 4 | 4 | 0 | 0 | 0 |
| docs | 51 | 25 | 11 | 15 | 0 | 0 | 0 |

Individual statements: 457 supported, **52 contradicted**, 352 not addressed.

## Contradictions

### transient-fuel.md :: Tip-in enrichment (`fuel_accel_enrich @ 0x3BB6C`)

- **Contradicted:** Claim says 0x3BB6C is tip-in (acceleration) fuel enrichment; blind answer says it is a speed-limit fuel-cut state machine with staged cut output flags.
- **Contradicted:** Claim says 0xCC51C/0xCC520 (510) are tip-in gains; blind answer says they are speed enable thresholds (activate when speed >= 510).
- **Contradicted:** Claim says 0xCC524/0xCC528 (505) are tip-out/decay gains; blind answer says they are speed disable thresholds.
- **Contradicted:** Claim says 0xCC530 (10000) is a decay saturation sentinel; blind answer says it is an RPM threshold: activation needs rpm >= 10000, and one release path fires when rpm < 10000.
- **Contradicted:** Claim says 0xCC52C (1260) is an RPM gate, so enrichment can't deactivate below 1260 RPM; blind answer says 1260 is compared with an unknown signal fr13 = 0xFFFF620C, not rpm (rpm is 0xFFFF6624), and fr13 < 1260 is a condition for release, not a block on it.
- **Contradicted:** Claim says magnitude = gain × throttle delta (from throttle_delta_calc); blind answer has no multiplication. The 510/505 values are only compared against speed as thresholds.
- **Contradicted:** Claim says the B set is likely for closed-loop vs open-loop; blind answer says the set is chosen by whether helper 0x22CF4 returns 1, and what that helper computes is unknown.
- Supported: 4 statement(s). Not addressed: 1.
- Blind mechanism: 0x03BB6C is the real entry of a periodic speed-limit fuel-cut state machine. The pack's 0x03BB6E bound is one instruction late; 0x03BB6C pushes r14. The task list at 0x049E74 calls it once per pass. Inputs: fr12=[0xFFFF65FC] (inferred vehicle speed, because it is compared with the DEFINITION speed-limit thresholds), rpm=[0xFFFF6624] kept at @r15, fr13=[0xFFFF620C] (unknown signal), and four byte results from helpers 0x1CF16(@4), 0x22CF4(@8), 0x297A0(@12) and 0x299BC(@16). Threshold pair selection: if @8==1 the code uses enable=0x0CC520 and disable=0x0CC528; otherwise it uses 0x0CC51C and 0x0CC524. 0xFFFF7CE0 is the cut-active byte. Bytes +1..+5 of that block are cut output flags, +6 is an inactive-time counter and +7 is an active-time counter, both incremented with uint8_add_sat. Activation (state 0) needs a trigger, rpm >= 0x0CC530 (10000) and @4==0. The trigger is speed >= enable thres
- Inert or gated: Effectively inert in this calibration. Both threshold sets are identical (enable 510, disable 505), so the @8 selector changes nothing, and 510/505 km/h speeds are unreachable. Activation also requires rpm >= 10000 (0x0CC530), far above any real redline. Even the @12==2 or @16==2 trigger paths cannot latch the cut. The 10000 floor also forces release whenever fr13 < 1260.

### project_ol_trigger_matrix.md

- **Contradicted:** Claim says 0xCC184 is the 2nd-gear RPM ON/OFF pair; blind answer says 0xCC184 is the gear-1 upper/set threshold (3500), the partner of 0xCC180.
- **Contradicted:** Claim says 0xCC188 is the 3rd-gear pair and 0xCC18C the 4th-gear pair; blind answer says 0xCC188 and 0xCC18C are the gear-2 lower and upper thresholds (3400/3500).
- **Contradicted:** Claim says 0xCC190 is the combined 5th/6th pair; blind answer says 0xCC190 is the gear-3 lower threshold, with its partner at 0xCC194.
- **Contradicted:** Claim says the 1st-gear pair at 0xCC180 is 3900/4000 RPM; blind answer says 0xCC180 = 3400 and 0xCC184 = 3500.
- **Contradicted:** Claim says the 2nd/3rd/4th pairs are 3700/3800, 3600/3700 and 3500/3600; blind answer reads 3400 at 0xCC188 and 0xCC190 and 3500 at 0xCC18C.
- **Contradicted:** Claim says the five pairs sit at 0xCC180–0xCC190 (4-byte stride); blind answer's 8-byte stride gives gear 4 at 0xCC198/0xCC19C and gear 5 at 0xCC1A0/0xCC1A4, outside that range.
- Supported: 11 statement(s). Not addressed: 5.
- Blind mechanism: Closed-loop to open-loop (CL→OL) delay and transition logic.

1) FUNCTION 0x036440 (GBR=0xFFFF79A4) decides the CL-delay count.
- Inputs: rpm_current (fr14), 0xFFFF62DC (fr13; compared against the 'Throttle' table, so likely throttle), ect_current, 0xFFFF65FC (fr15; compared against the 'Vehicle Speed' table, so likely speed), 0xFFFF6898 (fr12), engine_load_current, the gear byte 0xFFFF6810, bytes 0xFFFF5E92/5E93/5E94/5DB5, and a mode byte r14 returned by sub 0x022CF4.
- When r14==1, the gear byte 0xFFFF6810 (1..5) picks a pair of rpm thresholds from 0xCC180.. (lower in fr9, upper in fr6). When r14!=1, the larger of 5E92/5E93 picks a pair from 0xCC1B0... Any other gear value falls back to the Neutral pair 0xCC1A8/0xCC1AC.
- Each input sets a hysteresis flag. The flag is set to 1 when the input is at or above the upper threshold and cleared when it drops below the lower threshold:
  - rpm
- Inert or gated: 0xCBC62 (CL to OL Delay_) is 0 when read as uint16, so on the r14==1 path the delay written to 0xFFFF79C4 is always 0, the same as the forced-zero branches. Whether 0 downstream means 'no delay' is not shown. The 0xCBC5C SI-DRIVE delay applies only if byte 0xFFFF5DB5==3 and its value is nonzero (value not shown). Gears 1 and 2 use near-identical 3400/3500 thresholds; gear 3 lower is 3400. The ECT minimum 0xCC17C gates everything, value not shown.

### knock.md :: Key constants

- **Contradicted:** 0x0D2F48: the claim says 0.35f is the FLKC retard step per knock event. The blind answer says 0x0D2F48 is the 'Fine Correction Advance Value (0.25)', added on each advance step, and that the retard step is 0x0D2F50.
- **Contradicted:** 0x0D2F4C value: the claim says -11.75f. The blind answer says -15.0.
- **Contradicted:** 0x0D29EE value: the claim says 125. The blind answer says uint16 90.
- **Contradicted:** 0x0D2F40 use: the claim says knock_metric must be ≤ 100 for retard to apply. The blind answer says retard applies whenever 0xFFFF81BA != 0, and A >= 100 only selects an extra special path that writes 0xFFFF8290 and sets GBR+16.
- **Contradicted:** 0x0D2F54/0x0D2F58 use: the claim says these are FLKC recovery rates in deg/cycle. The blind answer says they are values written to the float at 0xFFFF8290 after an advance step when A >= 100, not the step added to the learned value.
- Supported: 5 statement(s). Not addressed: 2.
- Blind mechanism: This is one routine of the per-range knock 'fine correction' learner. Its GBR block is at 0xFFFF8290. The current range index is the byte at GBR+8. The learned values form a float array at 0xFFFF3248 with an 8-byte stride; the value for the current range is loaded into fr4. Two RAM floats are read at entry: A = 0xFFFF8258 and B = 0xFFFF3234. From them the code builds an upper ceiling fr12 = (1-B)*A and a lower reference fr8 = -A*B. The branch is selected by the knock-related byte 0xFFFF81BA.

Advance branch (0xFFFF81BA == 0):
- The gating flags must agree: the return of 0x29858 (==2), 0xFFFF7D18, bit0 of 0xFFFF3244, 0xFFFF8233 and GBR+14.
- The range must be the same as on the previous call (GBR+26 == GBR+8), and GBR+12 must be set.
- A word counter at GBR+4 must have reached 'Fine Correction Advance Delay' (0x0D29EE, uint16 90).
- When all hold, it computes new = clamp(min(fr4 + 'Fine C
- Inert or gated: 0x0D2F54 and 0x0D2F58 both hold 0.35, so the GBR+17 flag that chooses between them has no effect on the value written to 0xFFFF8290. The advance step is gated by the 90-count delay at 0x0D29EE, an unchanged range and GBR+12. The step is also bounded by min(ceiling (1-B)*A) and the clamp to [-15, +8]. The 0xFFFF8290/GBR+16 sub-paths require A >= 100. If A is a degree-scale quantity that never reaches 100, those sub-paths, including the 0x0D2F54/0x0D2F58 writes and the 0x0D2F64/0x0D2F68/0x0D2F60/0

### boost-control.md :: PID terms

- **Contradicted:** Claim says 0xC0BD4 = 210.0; blind answer says 0xC0BD4 = 620.58.
- **Contradicted:** Claim says 0xC0BDC = 0.0; blind answer says 0xC0BDC = 5.1715.
- **Contradicted:** Claim says 0xC0D04 = -160.0 and is a proportional gain (WG duty correction per boost error); blind answer says 0xC0D04 is a 'Boost Error' X axis of a TD 1D table with first value -155.14.
- **Contradicted:** Claim says 0xC0D74 is the derivative term (disabled, 0.0) and elsewhere a 0.5 IIR filter coefficient; blind answer says 0xC0D74 is a 'Boost Error' X axis of a TD 1D table (first value 0), possibly Integral Positive. It reports no derivative term or filter coefficient.
- Supported: 6 statement(s). Not addressed: 1.
- Blind mechanism: This is the turbo dynamics (TD) wastegate-duty correction routine: a proportional term plus an accumulated integral term. GBR is 0xFFFF5C98 and r5 is 0xFFFF5D18. The routine loads the integral accumulator into fr12 from 0xFFFF5CB0, boost error into fr14 from 0xFFFF5CA0, target boost into fr8 from 0xFFFF5CA4, IAT and RPM. (1) Activation gating with hysteresis. If 0xC0BD4 (620.58) > target boost, flag byte GBR+129 (0xFFFF5D19) is set to 1. It is cleared to 0 only once target boost reaches 0xC0BD8 or more. The RPM thresholds 0xC0BE8 and 0xC0BEC set flag GBR+130 (0xFFFF5D1A) the same way. If either flag is 1, TD is inhibited: the proportional output 0xFFFF5CAC and the integral accumulator 0xFFFF5CB0 are both written 0.0. (2) Proportional term. When enabled, P = table_lookup_1D('Turbo Dynamics Proportional', boost error) × table_lookup_1D('TD Proportional Compensation (IAT)', IAT), stored at 
- Inert or gated: The whole TD mechanism is gated. If target boost < 620.58 (0xC0BD4), with release at >= 0xC0BD8, or RPM is below the 0xC0BE8/0xC0BEC hysteresis pair, both the P term and the integral accumulator are forced to 0.0. The negative-integral boost-error threshold (5.1715) overlaps the positive one (5.0). For 5.0 <= error < 5.1715 with WGDC >= 5.0, the negative branch wins and the positive branch is skipped. If WGDC < 5.0 there, the code falls through and the positive branch can still run if 0xFFFF5CC4

### transient-fuel.md :: Tau-alpha (wall film dynamics)

- **Contradicted:** Claim says 0x3735A is tau_rising_handler, which uses the rising-load table 0xCD6E6; blind answer says 0x3735A is a small routine that low-pass filters 0xFFFF7A60 via float_lag_filter into 0xFFFF7A54, and that the tau tables are used in function 0x030C46.
- **Contradicted:** Claim says 0x3740C is tau_falling_handler, which uses the four falling tables; blind answer says 0x3740C is an accumulator routine that adds 0xFFFF7A54 to 0xFFFF3194 and resets it on an AF3B rising edge.
- **Contradicted:** Claim says the 720.0 gate sends >=720 to the PRIMARY path (active falling tau correction) and <720 to an accumulation path; blind answer says >=720 only permits the accumulator 0xFFFF3194 to be reset on the rising edge of AF3B.
- **Contradicted:** Claim says comms_state_byte 0xFFFFAF3B controls falling-variant selection; blind answer says the variants are selected by a mode byte (mode==2) from sub 0x21016 and by 0xFFFF844F, and that AF3B is the edge trigger for the accumulator reset.
- Supported: 9 statement(s). Not addressed: 4.
- Blind mechanism: Two separate pieces of logic are bundled here.

(1) Transient (tau) fuelling term, FUNCTION 0x030C46. This is a three-term model, each term built as a temperature factor times a second factor.
- Inputs: ECT 0xFFFF6350 and an rpm copy at 0xFFFF7414.
- Two signed delta-style values at 0xFFFF73EC (r8-40) and 0xFFFF73D8 (r8-60). Their sign picks rising-load or falling-load tables.
- A mode byte from sub 0x21016, held at r15+8.
- A selector byte at 0xFFFF844F.

First branch, on the value at r8-40:
- If it is >= 0 (rising), with mode==2 and 0xFFFF844F==1, it uses 'Tau Input A Rising Load Activation' (desc 0xACB40) vs ECT. With mode==2 and the flag !=1 it uses desc 0xACB54. With mode !=2 it uses 0xACB68.
- If it is < 0 (falling), mode==2 uses 'Falling Load Activation' (0xACB7C). Otherwise it uses 'Falling Load Activation A' (0xACB90).
- The result goes to 0xFFFF73B8 (r8-92). An rpm-indexed fact
- Inert or gated: - 'Tau Input A Falling Load Activation A' is a constant 0.5 at every ECT, so its temperature dependence is inert.
- 'Falling Load Activation C' is 0 at 90-110 C, which zeroes that product term when hot and mode !=2.
- The tau output is forced to 0 while counter 0xFFFF67EC < cal 0xCBC2C/0xCBC2A, or when sub 0x1CF5E returns 1.
- The output is floored at 0 while counter 0xFFFF67EC < 0xCBC26.
- The accumulator reset is gated by AF3B edge AND 0xFFFF8EAC >= 720.0.
- The values at 0xCBC26, 0xCBC2A and 

### transient-fuel.md :: How this matters for the current tune

- **Contradicted:** The claim says 0xCC51C–0xCC528 (510.0 / 505.0) are accel-enrichment gains that set magnitude. The blind answer says they are speed-limiter fuel-cut enable and disable thresholds (510 enable, 505 disable), compared against vehicle speed at 0xFFFF65FC.
- **Contradicted:** The claim says 0xCBC0B and 0xCBC0C set the duration of the accel-enrichment decay tail. The blind answer says they are stage-delay and hysteresis counts in a speed-limiter fuel-cut state machine. They control when cut flags 3 and 4 are added and when flags clear.
- **Contradicted:** The claim says 0xCC52C is a 1260 RPM threshold. The blind answer says 1260 is compared against fr13 from RAM 0xFFFF620C, whose meaning is unidentified. RPM is read separately (0xFFFF6624) and checked against 0xCC530.
- **Contradicted:** The claim says these addresses belong to the accel/tip-in enrichment system, so raising the gains or counters would extend fuel enrichment. The blind answer says the routine is a speed-limiter fuel-cut state machine whose outputs are cut flags 0xFFFF7CE1..7CE5.
- Supported: 2 statement(s). Not addressed: 2.
- Blind mechanism: Speed-limiter fuel-cut state machine with hysteresis and staged cut flags. Inputs: fr12 from RAM 0xFFFF65FC (compared against the speed-limit enable/disable tables, so presumably vehicle speed), rpm_current 0xFFFF6624, fr13 from 0xFFFF620C, and status bytes returned by 0x1CF16 (sp+4), 0x22CF4 (sp+8), 0x297A0 (sp+12) and 0x299BC (sp+16). If the 0x22CF4 result is 1, the thresholds are enable=0x0CC520 and disable=0x0CC528 (505). Otherwise they are enable=0x0CC51C (510) and disable=0x0CC524. The state byte 0xFFFF7CE0 holds 1 while the cut is active. Inactive: counter @7CE6 is incremented with saturation (uint8_add_sat) and @7CE7 is cleared. Entry happens if (speed >= enable, or sp+12==2, or sp+16==2) and rpm >= 0x0CC530 and sp+4==0. On entry the state is set to 1. If counter6 <= 0x0CBC0C, flags 7CE1..7CE5 are set to 1 and counter7 is preloaded with the 0x0CBC0B value. Counter6 is then zeroed
- Inert or gated: Threshold set is selected by the 0x22CF4 return value (==1 gives 0x0CC520/0x0CC528, else 0x0CC51C/0x0CC524). Enable 510 and disable 505 are far above any reachable vehicle speed in km/h, so the speed path is probably never triggered in this calibration. That depends on fr12 being km/h, which is inferred. 0x0CC520 and 0x0CC524 values are not shown. Entry can still occur via sp+12==2 or sp+16==2. Entry is also gated by rpm >= 0x0CC530 (value not shown) and sp+4==0. Both stage-delay counts are 3.

### boost-control.md :: Enable hysteresis

- **Contradicted:** Claim says the function enables when load > 4.0; blind answer says the flag is set to 1 when the value is <= 4.0.
- **Contradicted:** Claim says the function disables when load ≤ 5.0; blind answer says the flag is cleared to 0 when the value is > 5.0, and holds its state between 4.0 and 5.0.
- **Contradicted:** Claim says it holds until the value goes above 5.0 after enabling at 4.0; blind answer says crossing above 5.0 clears the flag, so the active state is the 'low' side and the logic runs the opposite way.
- Supported: 2 statement(s). Not addressed: 2.
- Blind mechanism: 0x0D6720 (4.0) and 0x0D6724 (5.0) are the lower and upper thresholds of a hysteresis comparator on the RAM float at 0xFFFF65FC. Two routines apply the same logic, each to its own flag byte. If the value is <= 4.0, the flag is set to 1. If the value is > 5.0, the flag is cleared to 0. Between 4.0 and 5.0 the flag keeps its previous state.

Routine 0x054B1A writes this flag to GBR 0xFFFF8BA1+48 = 0xFFFF8BD1. It builds a second hysteresis flag at 0xFFFF8BD2 from coolant temperature (ect_current) against 0x0D6728 and 0x0D672C. It then ANDs both flags with:
- calibration enable byte 0x0D6186 == 1,
- the result of 0x022CF4 == 1,
- byte 0xFFFF65D0 == 1,
- the return of 0x01CF16 == 0.
The combined enable is written to 0xFFFF8BA1.

Routine 0x054858 writes its flag to GBR 0xFFFF8B50+128 = 0xFFFF8BD0. It uses the flag to:
- run a saturating up-counter at 0xFFFF8BCC (counts while the flag is 1 and b
- Inert or gated: The thresholds themselves are active: a 1.0-wide hysteresis band (4.0 / 5.0), with no zero or degenerate value.

Downstream gating in 0x054B1A: the enable output requires calibration byte 0x0D6186 == 1. Its value is not shown in the pack.

Downstream gating in 0x054858:
- The table path requires counter 0xFFFF8BCC >= calibration byte 0x0D6185 (value not shown).
- The whole routine zeroes its outputs when the result of 0x022CF4 is 0.
- The table path is bypassed when byte 0xFFFF64F5 == 1 or byte 

### rev-limit-patch.md :: The injected code

- **Contradicted:** Claim says 0x0F1038 holds the literal pointer 0xFFFF65FC, which the injected code uses to read vehicle speed; blind answer says 0x0F1038 is 'Calibration data, 0xFFFF pattern; appears unset/placeholder', i.e. a 'disabled/unused calibration slot'.
- **Contradicted:** Claim says 0x0F103C holds the pointer 0xFFFF65D0 to the state flag byte read by the code; blind answer says 0x0F103C 'appears unset/placeholder', consistent with a disabled/unused slot.
- **Contradicted:** Claim says 0x0F1000–0x0F1036 is executable injected code, for example 0x0F101E fcmp/gt, 0x0F1024 mova and 0x0F102C fmov.s; blind answer says 0x0F101E, 0x0F1024, 0x0F102A and 0x0F102C are 'Calibration data' and that the 0x0F10xx block is 'calibration constants/tables'.
- Supported: 6 statement(s). Not addressed: 6.
- Blind mechanism: 0xFFFF65FC is a heavily-referenced float32 RAM variable (136 literal refs) that behaves like a central vehicle-speed signal (km/h). Multiple consumers read it: a lag filter updates another RAM slot from it (0x015EAC); it is compared against constant thresholds to set flags (0x033FA2 writes 0xFFFF77F8; 0x037FBC sets flag at 0xFFFF7AEC+3 and feeds a counter via uint8_add_sat; 0x03528A sets a GBR flag @(148,gbr)); it drives 1D table lookups as the X-axis input (0x011EAE, 0x0161F0, 0x03528A with 0x000AC544); it is used in float_safe_div as a divisor/numerator for an accumulator (0x02505C); and it gates 1st-gear boost compensation logic against a speed-disable threshold (0x013B1A). The 0x0F10xx block and 0x0CC500 are calibration constants/tables (rev limit, launch-control RPM/speed thresholds, FFS/LC deltas) in the same calibration region, several unreferenced by direct literals and likely re
- Inert or gated: FFS RPM delta (0x0F1054)=0, which would null any FFS RPM-delta offset in this calibration. 0x0F1048=0. 0x0F1038/0x0F103C read as 0xFFFF (all-ones), consistent with disabled/unused calibration slots. In 0x02505C the accumulator is forced to 0 (fldi0) unless a speed threshold and a set of flags pass, so that path is conditionally gated.

### boost-control.md :: Safety / disable conditions

- **Contradicted:** Claim says 0xC0BFC = 0.2 (disable if IAM < 0.2); blind answer says 0xC0BFC is float 0.5 (disable engages when 0.5 > IAM value)
- **Contradicted:** Claim says 0xC0BF8 = −1.0 (disable if fine knock corr < −1.0); blind answer says 0xC0BF8 is float −2.0 (values below −2.0 increment the exceed counter)
- Supported: 4 statement(s). Not addressed: 5.
- Blind mechanism: Three routines together build a boost-control disable latch. They are driven by fine (knock) correction and then by IAM. (1) 0x013936 passes the uint8 at 0xFFFF5D01 to 0x046ACC and gets a float back in fr0. If -2.0 > fr0, i.e. that correction value is below -2, it does a saturating +1 on the uint8 counter at 0xFFFF5D02. (2) 0x013960 compares the 0xFFFF5D02 count with the uint8 at 0x0C0BAD (=2). If count >= 2 it sets the flag at 0xFFFF5D05 = 1 and clears 0xFFFF5D01 and 0xFFFF5D02. Otherwise it does a saturating +1 on 0xFFFF5D01. (3) The block at 0x01398E resets 0xFFFF5D05, 0xFFFF5D01 and 0xFFFF5D02 to 0 when 0xFFFF5D01 >= 35 or when bit0 of 0xFFFF3244 is clear. That bit acts as an enable for the scan. (4) The block at 0x0139B0 reads the float at 0xFFFF3234, presumably IAM. If 0.5 (0x0C0BFC) > that value and 0xFFFF5D05 == 1, it sets 0xFFFF5D07 = 1 and latch 0xFFFF5D06 = 1. Otherwise, if th
- Inert or gated: Nothing in this calibration is shown to be inert. Gates: the counters only run while 0xFFFF3244 bit0 is set, and are reset when the index 0xFFFF5D01 reaches 35. The count threshold is 2. The IAM engage threshold is 0.5, which is meaningful if IAM is on a 0-1 scale (unverified). The value of the release threshold 0x0C0C00 is not given, so the size of the hysteresis band is unknown.

### boost-control.md :: Recently changed in 20.10 (per byte-diff)

- **Contradicted:** Claim says 0xC0F58 is the table header and 0xC0FE0 is where the Max Wastegate Duty table data is. Blind answer says 0xC0F58 is the base of the map itself. It says 0xC0FE0 is an interior cell 0x88 bytes in (element 68, RPM 3200, axis 240, value 79.305%), not the start of the data.
- **Contradicted:** Claim says 0xC1150 is the table header and 0xC11D8 is where the Initial Wastegate Duty data is. Blind answer says 0xC1150 is the map base. It says 0xC11D8 is element 68 inside the map (RPM 3200, axis 240, value 70.457%).
- Supported: 3 statement(s). Not addressed: 1.
- Blind mechanism: Both addresses are single cells inside the two base wastegate-duty maps, not separate scalars. 0x0C0FE0 is 0x88 bytes (element 68) into "Max Wastegate Duty_" at 0x0C0F58. 0x0C11D8 is 0x88 bytes (element 68) into "Initial Wastegate Duty_" at 0x0C1150. Read as uint16 with a 1/256 scale, they give 20302/256 = 79.305 and 18037/256 = 70.457. Those are exactly the listed cells at RPM 3200 and the ninth breakpoint (240) of the 0–360 axis. The code never addresses the cells directly. Function 0x013D66 passes the descriptors 0xAA9B8 and 0xAA9D4 to table_lookup_2D (0xBE8E4). The inputs are fr5 = rpm_current (0xFFFF6624) and fr4 = RAM 0xFFFF8558, an unnamed load or boost-type variable on the 0–360 axis. Results: the Initial lookup is stored at 0xFFFF5CB8 (5D14-92) and the Max lookup at 0xFFFF5CC8 (5D14-76). Compensation tables are also looked up: Atm-pressure 2D from 0xFFFF6898 and rpm, stored at -
- Inert or gated: The max-duty product is clamped to 0..80.0 (literal 0x42A00000 at 0x014004). Max-map cells of 85–90 % can therefore only take effect if the compensations pull the product below 80; the 87.5/90 cells at 1600–2000 rpm, top of the axis, are capped at 80 when the compensations are 1. The RPM 6400 row and the RPM 1600/axis-0 cell are 0 in both maps, so duty there is 0. Initial duty is clamped to [0, max-limit]. Several status flags send execution to 0x01400C: r10 from 0xFFFF85D7 == 1, helper results 

### knock.md :: Pipeline

- **Contradicted:** The claim puts 0x43D68, 0x45BFE and 0x463BA in the event-driven chain after 0x43B7C, executing on every 4th cylinder event. The blind answer says they are called by a separate periodic scheduler at 0x04AA58, in the fixed order 0x4438C, 0x43D68, 0x45BFE, 0x463BA, and not from the event-driven 0x43750 path.
- **Contradicted:** The claim says 0x45BFE is the 'FAST: per-event retard + counter recovery' path. The blind answer says 0x45BFE is advance-multiplier (IAM) learning: it adds or subtracts a step on IAM in FFFF3234, clamps it to 0..1, and halves the step on reversal. The blind answer instead places per-knock retard and recovery in 0x4438C (FBKC).
- Supported: 4 statement(s). Not addressed: 2.
- Blind mechanism: These are the knock-control tasks of the ignition timing strategy: per-cylinder knock signal evaluation, feedback knock correction (FBKC) and advance-multiplier (IAM) learning. A periodic scheduler at 0x04AA58 runs only when byte FFFF8EDC is 0. It calls 0x04438C (FBKC), 0x043D68 (knock-count and threshold block), 0x045BFE (IAM update) and 0x0463BA (body not shown) in fixed order, among about 100 other tasks. A second, event-driven dispatcher at 0x04A94C (also gated by FFFF8EDC==0) calls 0x043750 with a byte event index in r4. 0x043750 acts only when r4 is 0, 6, 12 or 18. It then copies the cylinder index FFFF4308 into FFFF81AC and continues only if that index is below 4. It calls 0x043782, the per-cylinder knock evaluation, then tail-branches to 0x043B7C, the per-cylinder knock state classifier. 0x043782 works per cylinder, indexed by FFFF81AC (GBR FFFF80FC +176). Inputs are rpm_current,
- Inert or gated: The whole chain is skipped when FFFF8EDC != 0 (both 0x04AA58 and 0x04A94C). 0x043750 acts only for r4 in {0,6,12,18} and FFFF4308 < 4. In 0x043B7E the threshold classification runs only if calibration byte 0xD2994 == 0xFF; otherwise the class is forced to (0xD2994 & 7). The ROM value of 0xD2994 is not shown, so whether classification is live is unknown. 0x045BFE skips learning when FFFF7D18 == 1. It resets the timers when FFFF8274+4 == 1 and 0x29858 returns 2. IAM is clamped to 0..1. FBKC is bou

### knock.md :: Boost-control coupling

- **Contradicted:** claim says BoostControlDisable_IAM (0xC0BFC) = 0.2; blind answer says the float at 0x0C0BFC is 0.5
- **Contradicted:** claim says BoostControlDisable_FineCorrection (0xC0BF8) = −1.0; blind answer says the float at 0x0C0BF8 is -2.0
- Supported: 3 statement(s). Not addressed: 2.
- Blind mechanism: These two floats are threshold constants for a boost-control disable supervisor that watches two engine-health signals: a fine-correction (fuel trim / knock fine correction) value and the IAM (Ignition Advance Multiplier). Function 0x013936 reads a byte at 0xFFFF5D01, converts it to a float (via the 0x00046ACC helper) into fr0, loads the 'Boost Control Disable (Fine Correction)' threshold -2.0 from 0x0C0BF8 into fr8, and tests fcmp/gt fr0,fr8 (i.e. -2.0 > correction, meaning correction is more negative than -2.0). If so it increments a saturating 8-bit delay counter at 0xFFFF5D02 (byte @(1,0xFFFF5D01)) via uint8_add_sat. Function 0x013960 compares that counter against the calibrated delay byte at 0x0C0BAD ('Boost Control Disable Delay (Fine Correction)'); when the counter reaches/exceeds the delay it sets a disable flag at @(4,0xFFFF5D01)=1 and clears the counters, otherwise keeps increm
- Inert or gated: none found; both thresholds are actively compared. Note the IAM path uses a companion threshold 0.5->? at 0x0C0C00 (value not given) as a second bound; disable-flag logic at 0xFFFF5D05 also gated by a prior-state byte @(1,0xFFFF5D05).

### rev-limit-patch.md :: The host function

- **Contradicted:** Claim says the rev limiter begins at 0x03B668; blind answer says the function entry is 0x03B66C and 0x03B668 is 'code just before the function entry… inside the neighbouring listing'.
- **Contradicted:** Claim says FR12 / 0xFFFF620C is airflow_maf_current; blind answer says it is a pressure value, 'likely manifold pressure', compared with 'Rev Limit Fuel Resume (Boost)' and with atmospheric subtracted from it.
- Supported: 7 statement(s). Not addressed: 1.
- Blind mechanism: This is the rev-limiter fuel-cut decision at 0x03B66C. It reads rpm_current (0xFFFF6624) into fr15, 0xFFFF65FC into fr14 and 0xFFFF620C into fr12. It passes fr14 to float_deadband_check(x, 0.0, 1.0). A non-zero result takes the 0x03B6AE path, which pairs with Rev Limit On/Off. A zero result takes the 0x03B6B8 path, which pairs with Rev Limit On(2)/Off(2). At 0x03B6C0 a hysteresis comparator runs against the selected pair. If rpm >= the On threshold (fr8), byte 0xFFFF7CB8+1 is set to 1. If rpm < the Off threshold (fr6), that byte is cleared. A second comparator does the same with Rev Limit On(3)/Off(3) into byte 0xFFFF7CB8+2. The +2 state is selected when all of these hold: 0x22CF4 returned 0; 0xFFFF65C0==1 or 0x299AC returned 2; 0xFFFF5E95==5 or 7, or 0x299BC returned 2. Otherwise the +1 state is used. The output is byte 0xFFFF7CB8+0, the cut-active flag. It is set when the selected stat
- Inert or gated: Set 1 (On 6700 / Off 6680) and set 2 (On(2) 6700 / Off(2) 6680) hold identical values. Unless the 0x0F1000 code substitutes other thresholds, the speed-based choice between them makes no numerical difference. Hysteresis is 20 rpm. All limiter state is forced to 0 whenever 0x22F92 returns 1. Resume after a cut is also gated by 0xFFFF620C falling below 'Rev Limit Fuel Resume (Boost)'; that value is not shown. The values of Rev Limit On(3)/Off(3) are not shown.

### knock.md :: Sign convention

- **Contradicted:** Claim says the code around 0x73600 is a commit function that maps the working knock register to the viewable 0xFFFF93E0 (FLKC) and 0xFFFF93DC (FBKC). Blind answer says 0x073600 loads the pointer for a 1D table lookup (table 0xAB484, input 0xFFFF9834, output 0xFFFF98AC). It says 0xFFFF93E0 is only read there and copied to 0xFFFF98A8 as a multiplicative factor in a gated, lag-filtered product. The writer of 0xFFFF93E0 is 'not shown', and 0xFFFF93DC has 'no reference in this listing'.
- Supported: 0 statement(s). Not addressed: 3.
- Blind mechanism: 0x073600 is the instruction that loads the pointer to a calibration 1D table at 0x000AB484 and calls table_lookup_1D. The table input is the float at 0xFFFF9834 (r9-88, r9=0xFFFF988C). The result goes to 0xFFFF98AC (r9+32). Straight after, the float in RAM 0xFFFF93E0 is copied into the work struct at 0xFFFF98A8 (r9+28). Further on, under several flag gates, the code forms a product P = [0xFFFF9820] * table(0xFFFF9834) * [0xFFFF93E0] and stores it at 0xFFFF9824 (r9-104). 0xFFFF9820 is the r4 output pointer passed to bsr 0x074208, so that routine probably computes it. P then takes one of two paths. On the first path (byte 0xFFFF98F2 == 1), P is used directly as the target in 0xFFFF9828. On the second path (byte 0xFFFF984E == 1), the target is P + (K * x * P) / T2(x). Here x is uint16 0xFFFF9846 converted to float by fmac_interp_uint16 with a pool scale and offset 0. T2 is the 1D table at 0
- Inert or gated: The product and filter section runs only if all of these hold: byte GBR+143 (0xFFFF989B) == 0, byte GBR+63 (0xFFFF984B) == 1, and byte 0xFFFF94B0 == 1. Path selection then depends on byte GBR+230 (0xFFFF98F2). It is set to 1 when word 0xFFFFA48A < the calibration word at 0x000C487A, and is not cleared in this function. If 0xFFFF98F2 == 1 the simple path P is taken. Otherwise byte GBR+66 (0xFFFF984E) must be 1 for the corrected path; else everything is skipped. GBR+142 and GBR+143 are cleared to 

### rev-limit-patch.md :: The three rev-limit pairs — which are live

- **Contradicted:** Claim says both entries now jump to 0x0F1000, pair 2 is dead, and editing 0xCC508 does nothing; blind answer says only the false-condition branch goes through the trampoline, and 'Rev Limit On (2)' 0x0CC508 is 'Loaded into fr6 at 0x03B6BE as the ON threshold on the branch taken when the deadband condition is true', so pair 2 is live on one branch.
- Supported: 8 statement(s). Not addressed: 3.
- Blind mechanism: This is the engine rev-limiter (fuel-cut) hysteresis logic. Function 0x03B66C compares current RPM (0xFFFF6624 rpm_current, loaded into fr15) against a set of ON/OFF thresholds and maintains a 3-byte fuel-cut flag block at 0xFFFF7CB8[0..2]. The routine first selects which ON/OFF pair to use based on a deadband/condition check (float_deadband_check on the byte at 0xFFFF5E95 vs 1.0/0.0): when the condition is false it branches via the trampoline at 0x0F1000, which applies an RPM offset (fadd of a selected correction into fr15, offset chosen by comparing 0xFFFF65FC against a constant gated by the flag byte at 0xFFFF65D0) and then jumps back into the ON-table arm at 0x03B6B2, loading 'Rev Limit On'(0x0CC500). The two arms load the OFF threshold ('Rev Limit Off' 0x0CC504) or ON threshold ('Rev Limit On (2)' 0x0CC508) into fr6. Standard hysteresis follows: if RPM > ON threshold, set the active
- Inert or gated: ON and OFF thresholds for each pair are 6700/6680 (float32), giving a 20 RPM hysteresis band; the (2) and (3) pairs hold the same 6700/6680 values in this calibration. The OFF arm uses fcmp/gt fr15,fr6 then bf, so the state only clears below the OFF threshold. 0x0CC50C ('Rev Limit Off (2)') has 0 direct references in this pack so its contribution is not demonstrated here. Trampoline offset selection at 0x0F1048 reads 0x00000000 (fr8=0), i.e. one branch adds a zero RPM correction.

### ssm-read-patch.md :: Stock behaviour — indices, not addresses

- **Contradicted:** claim says 0x09A4DA bound is 848 (reject if index >= 848); blind answer says 0x09A4DA = 0x0350 = 848 — actually 0x0350 = 848 decimal, so these agree
- Supported: 5 statement(s). Not addressed: 1.
- Blind mechanism: 0x0006423C is the base of a jump table of 32-bit function pointers (one per entry, indexed by entry<<2). The code at 0x09A45E/0x05F72A/0x09A694 loads this base, shifts an identifier left by 2 (shll2), indexes mov.l @(r0,r5),r6 to fetch a handler pointer, and calls it via jsr @r6. Each table slot holds a ROM code address (pool at 0x06423E onward shows values like 0x0005DEB2, 0x0005DFBA, 0x0005D1D0, 0x0005DCAE, etc., where 0x0005D1D0 recurs as a shared default/stub handler). The function at 0x09A3BA parses a byte-stream record: it reads 3-byte big-endian records (mov.b @r12+ three times into r1, with a type byte in r0 checked against -1/-12/-14), and for a non-special record whose assembled value r1 is below 0x0350 (mov.w @(0x09A4DA)=0x0350 bound check, cmp/hs r8,r1 -> skip if >=), it dispatches through the 0x6423C table using that value as index, storing each handler's byte return into an
- Inert or gated: IDs with r1 >= 0x0350 are gated out (cmp/hs r8,r1 then bt skips dispatch). Table slots equal to 0x0005D1D0 act as a shared default handler rather than a unique one. In 0x09A62A a separate guard rejects slot value 0x0005E76A (cmp/eq r5,r6 -> bt out) before dispatch.

### project_gear_determination.md

- **Contradicted:** Claim says the threshold set is 'selected by state bytes FFFF5E93/FFFF5F03'. Blind answer says selection uses FFFF5F03 (==1 gives set A) and FFFF5FB8 (==1 gives set B, else C), and that FFFF5E93 is a separate, externally supplied gear code used directly when FFFF65C5==0.
- Supported: 7 statement(s). Not addressed: 4.
- Blind mechanism: Calculated gear determination for the manual gearbox. 0x023EB8 first copies one of three five-entry float threshold sets into RAM 0xFFFF6814..0xFFFF6824. Set A (0x0C3474..84) is used when byte 0xFFFF5F03==1. Otherwise set B (0x0C3488..98) is used when 0xFFFF5FB8==1, else set C (0x0C349C..AC). The routine then works out a gear by one of two routes. (a) If flag 0xFFFF65C5==0, it takes the byte at 0xFFFF5E93 as the gear. Values 1–5 are copied unchanged, 7 maps to gear 1, and 0 or 6 maps to 'none' (6810=6, 6811=0). Values above 7 leave both bytes unchanged. (b) Otherwise, if flag 0xFFFF65C0==1 or the helper 0x297A0 returns 2, the result is 'none' (6/0). If rpm_current is below the pool constant at 0x024130, the result is the top-gear code (6810=5, 6811=6). If neither applies, it computes ratio = speed / (rpm / K), with speed at 0xFFFF65FC and K at 0x024138, using float_safe_div twice. The ra
- Inert or gated: The debounced gear 6812 is gated by cal 0x0C30BE = 31 stable counts and is frozen whenever 0xFFFF65C0==1. The calculated path is bypassed when 0xFFFF65C5==0, when 65C0==1, or when 0x297A0 returns 2 (forced 6/0). It is also bypassed below the rpm constant at 0x024130 (forced 5/6). 6810 is clamped to a maximum of 5. The first value of all three threshold sets reads 13.416; whether the remaining entries differ between sets is not shown.

### project_overrun_fuelcut_tier_system.md

- **Contradicted:** Claim says 0xCBCC0 is a per-tier counter-threshold array [38,38,38,6] selected by the RPM tier (ticks before cut engages). Blind answer says 0xCBCC0 is a single uint16 value of 38, compared against the word at 0xFFFF5E74 (with the 0x22CF4 return == 0) to choose a dedicated counter set. In the blind answer, the per-band counts come from pointer tables at 0x63B70–0x63D40 indexed by band, not from 0xCBCC0.
- Supported: 5 statement(s). Not addressed: 5.
- Blind mechanism: This is the overrun (decel) fuel-cut delay-counter scheduler and its resume threshold. Function 0x03AF94 uses GBR=0xFFFF7C80. It reads rpm_current (0xFFFF6624) into fr14 and ECT into fr12. When GBR+30 is 0 and the flag byte 0xFFFF65C0 is not 1, it puts RPM into one of four bands using three float thresholds. 0x0CC4EC=2250 is the defined 'Cut Counter RPM Threshold', and 0x0CC4F0=3000 and 0x0CC4F4=4500 follow it. The band index r1 is 0 for rpm<2250, 1 for <3000, 2 for <4500 and 3 for >=4500. r1 is shifted left by 2 and indexes pointer tables at 0x63B70–0x63D40, each pointing to a uint16 calibration value. Each pass loads three counts: one into r4 (later GBR+12), one into GBR+14 and one into GBR+16. Which pointer set is used depends on four things: flag 0xFFFF5DB8 (set A or B); the result r6 of call 0x22CF4; the word 0xFFFF5E74 compared against 0x0CBCC0 (=38); and byte 0xFFFF6810, whose cas
- Inert or gated: The Resume Threshold table at 0x0CEED0 is flat at 1000 rpm across all 16 ECT points (-40..110 °C), so its ECT dependence is inert in this calibration; only the additive terms change the resume RPM. The whole counter-selection block is skipped when GBR+30 (0xFFFF7C9E) is nonzero. When 0xFFFF65C0==1, the RPM bands are bypassed: GBR+12 is set to the value at 0x0CBC9E and GBR+14 and GBR+16 to 0. The GBR+4..+10 offsets from 0x0C2220..6 are zeroed unless 0xFFFF6155==1 and 0xFFFF615F==0. The floor at 0

### project_undefined_rom_programme.md

- **Contradicted:** The claim lists 0xABC1C as a scanner artefact, a false descriptor to be filtered out ('Some "descriptors" are scanner artefacts — absurd value ranges (0xABC1C spans 1.7e22)'). The blind answer says it is a real descriptor consumed by code: at 0x0783C2 it is looked up through helper 0xBE928 with engine load and 0xFFFF98, the byte result feeds a running minimum at 0xFFFF9FCB, and the 'float decoding of its values is garbage, so the data are likely integer-typed'.
- Supported: 5 statement(s). Not addressed: 6.
- Blind mechanism: The pack groups four separate mechanisms. (1) 0x033CC4 selects the closed-loop fuel target compensation table. It takes a pointer argument in r4 and a flag in r5. It reads rpm (0xFFFF6624) and engine load (0xFFFF63F8) and calls 0x22CF4, which returns a byte mode. A second selector is formed: it is 0 if the r5 flag is nonzero, otherwise it is the byte at 0xFFFF984D. With selector 0, mode==1 picks descriptor 0xAD8B8 (Comp A) and any other mode picks 0xAD8D4. With selector nonzero, mode==1 picks 0xAD8F0 (Comp B) and any other mode picks 0xAD90C. table_lookup_2D is called with fr4=load and fr5=rpm, and the float result is written to *(r4 argument). Comp A values are all negative, from -0.008 to -0.15. They become most negative at 5000 rpm and high load. (2) 0x039530 computes a value from RAM 0xFFFF7800 (x): 1/(1-x) - 1. It is guarded by float_deadband_check and float_safe_div. It then looks 
- Inert or gated: 0x0D2D48 = 0.0, so the per-gear timing compensation output 0xFFFF80F0 is always 0 regardless of the per-gear tables or activation. Table 0xAD258 is all 1.0, so the ECT scaling in 0x039530 is a no-op; only the clamp limits at 0xCC3EC/0xCC3F0 (values not shown) matter. Comp A use is gated by the mode byte from 0x22CF4 == 1 and selector byte 0xFFFF984D == 0 (forced to 0 when the r5 flag is nonzero). 0xABC1C lookup is gated by bit0 of 0xFFFFA176.

## Everything else

| Claim | Grade | Supported | Not addressed | Functions shown |
|---|---|---|---|---|
| architecture.md :: Evidence | partly_agree | 1 | 8 | 7 |
| architecture.md :: Memory map | agree | 4 | 4 | 8 |
| architecture.md :: Ghidra | agree | 3 | 5 | 8 |
| architecture.md :: Which ROM to analyze | agree | 5 | 5 | 6 |
| avcs.md :: Verified addresses | agree | 4 | 1 | 1 |
| boost-control.md :: Architecture | agree | 6 | 4 | 7 |
| boost-control.md :: Tunable tables (from project XML) | agree | 13 | 2 | 7 |
| boost-control.md :: Why this matters for the current tune | agree | 4 | 1 | 2 |
| cruise-tables.md :: Before you tune a Cruise table: does it ever run? | agree | 9 | 8 | 8 |
| cruise-tables.md :: The five RPM × Load tables used in cruise residency analysis | agree | 7 | 4 | 5 |
| cruise-tables.md :: Non-Cruise siblings | agree | 5 | 1 | 3 |
| cruise-tables.md :: Pedal-to-throttle table addresses | agree | 7 | 0 | 6 |
| cruise-tables.md :: Boost control RQTQ-axis tables | agree | 4 | 1 | 2 |
| injector-rescale.md :: 1. The one constant everything else follows | agree | 6 | 4 | 8 |
| injector-rescale.md :: 2. Scale the DATA by k | agree | 7 | 4 | 8 |
| injector-rescale.md :: 3. Scale the ms AXIS by k, leave the %-data alone | agree | 10 | 7 | 8 |
| injector-rescale.md :: 4. Replace from the data sheet — do NOT scale by k | agree | 5 | 4 | 1 |
| injector-rescale.md :: 5. Do NOT touch | agree | 8 | 11 | 8 |
| injector-rescale.md :: 6. Adjacent, not part of the rescale | partly_agree | 4 | 3 | 1 |
| injector-rescale.md :: 7. After the swap | agree | 3 | 3 | 3 |
| knock.md :: Tunable tables | partly_agree | 9 | 7 | 7 |
| knock.md :: Open questions (from disassembly) | agree | 6 | 5 | 8 |
| ol-fueling.md :: The five tables | partly_agree | 5 | 8 | 6 |
| pedal-throttle.md :: The three-table chain | agree | 6 | 6 | 6 |
| pedal-throttle.md :: Downstream consumers of RQTQ | partly_agree | 4 | 2 | 2 |
| rev-limit-patch.md :: The `0x0F1000` Rev-Limit Patch (launch control / 2-step) | agree | 5 | 4 | 5 |
| rev-limit-patch.md :: What the patch changes | agree | 5 | 0 | 3 |
| rev-limit-patch.md :: What it does, in one line | partly_agree | 3 | 4 | 0 |
| rev-limit-patch.md :: Open question — `0xFFFF65D0` | agree | 6 | 2 | 8 |
| scope-cliffs-flagged.md :: Tables in scope (per SOP Step 4 and active issues) | agree | 9 | 6 | 6 |
| scope-cliffs-flagged.md :: Risks & open questions | partly_agree | 3 | 6 | 0 |
| ssm-read-patch.md :: The SSM Read-Addresses Patch | partly_agree | 2 | 4 | 2 |
| ssm-read-patch.md :: Patched behaviour — real RAM reads, with a width tag | partly_agree | 2 | 8 | 8 |
| transient-fuel.md :: Transient fueling — accel enrichment + tau-alpha | partly_agree | 2 | 5 | 8 |
| transient-fuel.md :: Pipeline | agree | 4 | 6 | 8 |
| turbo-character.md :: Soft rev limiter | partly_agree | 1 | 4 | 3 |
| feedback_derived_artifacts_are_wrong_at_scale.md | partly_agree | 1 | 6 | 8 |
| feedback_dont_attribute_from_magnitude.md | agree | 4 | 7 | 6 |
| feedback_ect_axis_celsius.md | agree | 3 | 5 | 1 |
| feedback_ram_address_identities.md | agree | 8 | 6 | 8 |
| feedback_verify_before_claiming.md | agree | 5 | 3 | 3 |
| feedback_verify_rom_changes_against_user_claims.md | partly_agree | 2 | 4 | 1 |
| project_clol_delay_zero_disables.md | agree | 7 | 4 | 5 |
| project_clol_function_identities.md | agree | 11 | 5 | 8 |
| project_cruise_noncruise_mechanism.md | partly_agree | 7 | 10 | 8 |
| project_dbw_pedal_throttle_chain.md | agree | 7 | 6 | 5 |
| project_engine_load_comp_fix.md | agree | 6 | 4 | 1 |
| project_ffb_transient_clamp.md | agree | 7 | 8 | 8 |
| project_ffff77d8_inert_fuel_trim.md | partly_agree | 8 | 7 | 8 |
| project_flkc_grid_is_bucketed.md | agree | 11 | 3 | 8 |
| project_hardware_and_explored_subsystems.md | agree | 7 | 7 | 1 |
| project_injector_rescale.md | agree | 8 | 7 | 8 |
| project_knock_flag_channel.md | agree | 6 | 4 | 8 |
| project_knock_no_boost_input.md | agree | 14 | 7 | 8 |
| project_map_switch_patch_idea.md | agree | 6 | 7 | 6 |
| project_per_gear_timing_comp.md | agree | 9 | 5 | 8 |
| project_per_gear_torque_cap_intentional.md | agree | 3 | 4 | 2 |
| project_scheduler_event_queue.md | agree | 13 | 9 | 8 |
| project_target_boost_tipin_coupling.md | agree | 7 | 5 | 2 |
| project_tipin_architecture.md | agree | 14 | 6 | 8 |
