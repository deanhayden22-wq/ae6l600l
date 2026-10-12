# Blind audit of settled claims

> A sample of claims this project treats as settled, re-derived from bytes by a reader
> that could not see the claim, then graded against it. **Agreement is weak evidence;
> disagreement means one side is wrong, not which.** Every disagreement below is a
> decode-by-hand item. Batches msgbatch_01RHci54BCunnzCEJ17vxwZ1 (blind) and msgbatch_01F4vrmigvjpdS7wf5pJ99FK (grading), model claude-opus-5-5, 2026-10-11 20:13:43.

## Agreement by group

| Group | Sampled | agree | partly_agree | disagree | blind_abstained | not_comparable | no answer |
|---|---|---|---|---|---|---|---|
| named_table | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| traced_function | 123 | 3 | 77 | 15 | 11 | 11 | 6 |
| unverified_function | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

## How the blind reader's own confidence held up (named tables only)

| Blind evidence class | agree | partly_agree | disagree | blind_abstained | not_comparable |
|---|---|---|---|---|---|

## named_table


## traced_function

### 0x32958 -- DISAGREE

- **On record:** Project label "fuel_correction_filter_init" [TRACED]. Comment: [TRACED] Zeros 3 floats at FFFF770C correction filter.
- **Blind (observed):** reset_3_float_factors_to_1_if_cond_022F92 -- Unknown. The code re-initialises three adjacent floats to 1.0, a unity or neutral value such as a multiplier, learned factor or filter state. It does this when the condition returned by 0x22F92 is true, which could be an init, reset or reinitialise request. The listing does not show what the three variables or the condition represent.
- **Grader:** The claim says the function zeros three floats at the FFFF770C correction filter. The blind answer says it writes 1.0f to three floats (FFFF7704/08/0C), and only when a condition is met. The location and the init/reset role match, but the written value contradicts the claim.
- **Differs on:** Claim says zeros; blind says stores 1.0f (unity), conditionally.

### 0x50DE2 -- DISAGREE

- **On record:** Project label "etb_target_compute_main" [TRACED]. Comment: [TRACED] ETB main throttle target computation. 626B (largest). ECT + atm + throttle.
- **Blind (observed):** subsystem_task_sequence_0x050DE2 -- unknown. The structure fits a periodic task wrapper that runs one subsystem's sub-steps in a fixed order, but nothing in this code says which subsystem.
- **Grader:** The claim describes a large 626-byte ETB target computation that reads ECT, atmospheric pressure and throttle. The blind answer finds a short pure dispatcher that touches no RAM, makes nine fixed subroutine calls and ends within a few dozen bytes. It names no subsystem.
- **Differs on:** The claim says this is a 626-byte computation reading ECT, atm and throttle; the blind answer says it is a tiny dispatcher with no direct RAM access, ending at 0x050E06.

### 0x00F4C -- DISAGREE

- **On record:** Project label "isr_dispatch_manager" [TRACED]. Comment: [TRACED] ISR sub-dispatch: identifies interrupt source, calls handler from isr_dispatch_table
- **Blind (observed):** call_D78_with_arg_doubled_if_EE4 -- unknown. It is a thin wrapper that passes its argument to 0xD78, doubled when the predicate at 0xEE4 reports true. The pattern fits a count or delay value scaled by an operating or clock mode, but the code shown does not establish that.
- **Grader:** The claim describes an ISR dispatcher that identifies the interrupt source and calls a handler from a dispatch table. The blind answer instead describes a thin wrapper that calls a fixed predicate, optionally doubles its argument and tail-jumps to a fixed address, with no table or RAM reads.
- **Differs on:** Claim says it calls a handler looked up from isr_dispatch_table; the blind answer says it tail-jumps to a fixed 0xD78 with no memory or table access.

### 0x0DF14 -- DISAGREE

- **On record:** Project label "rtos_task10_sensors" [TRACED]. Comment: [TRACED] RTOS Task 10: ADC sensor processing pipeline (20 ms, pri 4). TCB=FFFF1218. Highest-priority 20 ms task. NO gate function -- runs unconditionally. 63 JSR calls total: 43 in main block (DF14-E028) + 20 in continuation (E0D8-E15A). Raises SR interrupt level to 13 at entry (STC SR,R0 / OR #D0 / LDC R0,SR). Lowers level back to 0 at E14A before final call (call_63 @ FBBA). PRIMARY ROLE: ADC bulk read + all sensor conditioning. ADC workspace GBR base = FFFF4024 (32 channels raw, 0x40 bytes). Produces: MAF(FFFF40B4), TPS(FFFF4108), BatteryVolts(FFFF4130 -- was 'Baro', CORRECTED 2026-07-26), ECT(FFFF4144), IAT(FFFF4128), Battery(FFFF41E
- **Blind (inferred):** startup_init_sequence_then_enable_interrupts -- Most likely the ECU power-on initialisation dispatcher: it runs each software module's init routine with interrupts masked, enables interrupts, then hands control to the next stage of the scheduler or start-up at 0x35A4. The merged code at 0xE1B0 looks like the endless background (main) loop that calls the per-module background tasks.
- **Grader:** The claim describes a periodic 20 ms RTOS task that reads the ADC and conditions sensors. The blind answer calls it a one-time power-on init dispatcher. Both see the same mechanism: interrupt mask raised to 13, a long list of calls, the mask cleared, then a call to FBBA. The functional identities differ.
- **Differs on:** Periodic ADC sensor processing task (claim) vs one-shot startup module-init sequence (blind)

### 0x11848 -- DISAGREE

- **On record:** Project label "descriptor_interpolation" [TRACED]. Comment: [TRACED] Descriptor-based 1D interpolation. Allocs 224-byte workspace, calls 0xBE81C/0xBE82C. Used by MAF and other sensor channels.
- **Blind (observed):** atomic_store_u16_twice -- A generic helper that writes a 16-bit value to a caller-supplied address with interrupts masked, so the write is atomic with respect to ISRs. Writing it twice suggests the target is a peripheral or hardware register that needs a repeated write to take effect or to be reliable, or a volatile store the compiler did not merge. The exact reason for the double write cannot be told from this code alone.
- **Grader:** The claim describes a descriptor-based 1D interpolation routine that allocates a 224-byte workspace. The blind answer reads the same calls (0xBE81C/0xBE82C) and the 0xE0 value as a critical-section enter/exit pair around a double 16-bit store, with no interpolation at all.
- **Differs on:** Interpolation with a 224-byte (0xE0) workspace versus an atomic 16-bit store with interrupts masked at level 0xE0.

### 0x0ADD6 -- DISAGREE

- **On record:** Project label "diagnostic_monitor_dispatch" [TRACED]. Comment: [TRACED] Task 0 call_04. PRIMARY DIAGNOSTIC MONITOR — calls 17 sub-routines (0xAFB0 through 0xB8A8) covering OBD-II readiness checks, sensor plausibility, DTC evaluation. Sub 0xAE1C clears diagnostic timer registers at 0xED00-0xED0A.
- **Blind (inferred):** peripheral_init_sequence -- Most likely a one-shot top-level init routine that runs a chain of on-chip peripheral or module setup routines in order, probably at startup. The neighbouring code writes the SH7058 INTC interrupt-priority registers (IPRA–IPRL at 0xFFFFED00–ED16): it zeroes all of them, then sets one 4-bit priority field in IPRL to 14. That fits the callees being hardware-configuration routines placed in the same code region.
- **Grader:** Both describe a dispatcher that calls 17 subroutines from 0xAFB0 to 0xB8A8. The claim says it is a diagnostic monitor (OBD readiness, DTC evaluation) that clears diagnostic timer registers at 0xED00. The blind answer says it is a one-shot peripheral init sequence, and reads 0xFFFFED00-ED16 as INTC interrupt priority registers rather than diagnostic timers.
- **Differs on:** Purpose: a diagnostic monitor dispatcher with diagnostic timer registers, versus a hardware/peripheral init chain whose neighbour zeroes the INTC IPR registers.

### 0x71D14 -- DISAGREE

- **On record:** Project label "sensor_float_clamp_b" [TRACED]. Comment: [TRACED] Float clamp B (called from dispatcher 1 body).
- **Blind (observed):** update_deadband_timer_and_condition_flag -- unknown. Structurally it debounces a float signal against a deadband around 0, counting consecutive loops in a saturating counter. It then derives a gated enable/condition byte, plausibly a diagnostic or monitor enable. That byte depends on a mode byte equal to 1, the debounce count, a 16-bit RAM quantity reaching a threshold, and another float staying below a calibrated limit. The identities of 0xFFFF69F0, 0xFFFF7D68, 0xFFFF6A22 and the output byte are not established by this code.
- **Grader:** The claim calls this a float clamp routine. The blind answer describes a deadband check, a saturating debounce counter and a gated condition-flag output, which is a different function and not a clamp.
- **Differs on:** Claim says the function clamps a float. Blind says it debounces a deadband check with a counter and sets a gated enable flag.

### 0x37ABA -- DISAGREE

- **On record:** Project label "injector_trim_application" [TRACED]. Comment: [TRACED] Injector trim application. Uses A/F learning tables.
- **Blind (inferred):** update_lagged_iat_ect_pair -- Keeps lag-filtered copies of intake-air and coolant temperature at 0xFFFF31A4 and 0xFFFF31AC. Smoothing applies only when IAT is below one calibration threshold and ECT is at or above another. Outside that region the copies track the raw sensors. This is probably feeding a temperature-dependent model or compensation, perhaps a heat-soak or intake-temperature estimate. Which consumer uses them is unknown from this code.
- **Grader:** The claim says this routine applies injector trim using A/F learning tables. The blind answer describes lag-filtering IAT and ECT into stored copies, with no fuel trim or A/F learning involved.
- **Differs on:** injector trim application using A/F learning vs. lag-filtered IAT/ECT temperature copies

### 0x627D8 -- DISAGREE

- **On record:** Project label "vvt_error_feedback" [TRACED]. Comment: [TRACED] VVT error feedback PID function. Reads 4 descriptor tables (9x9, zeroed in stock). Writes FFFF920C-FFFF9228.
- **Blind (observed):** table_AF830_lookup_store_and_multiply -- unknown. The shape is a 1-D table value (likely a compensation or correction factor) kept as an intermediate in 0xFFFF91FC, then scaled by a base quantity held at 0xFFFF9210, which is probably part of the same RAM block. Neither the table nor the RAM variables are identified, so the physical meaning cannot be told from this code.
- **Grader:** The blind answer describes one 1-D table lookup that is stored to 0xFFFF91FC and then multiplied by 0xFFFF9210. That contradicts the claim of a PID function that reads four 9x9 tables and writes 0xFFFF920C-0xFFFF9228, and the blind answer gives no VVT or feedback purpose.
- **Differs on:** The claim has four 9x9 descriptor tables feeding a PID that writes 0xFFFF920C-0xFFFF9228. The blind answer has a single 2D-lookup table, 0xAF830, written to 0xFFFF91FC and scaled by 0xFFFF9210.

### 0x431B0 -- DISAGREE

- **On record:** Project label "task45_timing_lu_b" [TRACED]. Comment: [TRACED] Task [45] Timing lookup B. RPM+MAF, cal 0xD2D10
- **Blind (observed):** update_rpm_x_ectiat_comp_with_decay -- unknown. It computes a correction term at FFFF80C4 as f(RPM) × g(ECT,IAT) while a state/counter byte sits inside a calibrated window, and sets a 'computed' flag. Once the byte passes the upper threshold, the term is moved by a fixed step toward 0 and capped at 0. That fits a temperature-dependent compensation applied at an event (start or after-start, transition) that then decays away, but the actual quantity cannot be identified from this code.
- **Grader:** Both involve an RPM-based table lookup, but the claim says the inputs are RPM and MAF. The blind answer instead observes ECT and IAT as the 2D axes, with no MAF, and finds 0xD2D10 used as a fixed decay step rather than a timing lookup table. It cannot confirm a timing purpose.
- **Differs on:** The claim has RPM+MAF as the lookup inputs; the blind answer has f(RPM) × g(ECT,IAT) with 0xD2D10 as a step increment.

### 0x343CE -- DISAGREE

- **On record:** Project label "afc_output_clamp" [TRACED]. Comment: [TRACED] AFC output clamp. Upper=200% (0xCC014), Lower=190% (0xCC018). Reads/writes 0xFFFF7820.
- **Blind (observed):** update_hysteresis_flag_and_windowed_constant_7820 -- unknown. Structurally this is a gate: a fixed float value is output only while some input is above a hysteresis band and a u16 quantity (likely a counter or timer at 0xFFFF79C2) is non-zero and below a limit (0xFFFF79C4). The physical meaning of the input, the counter and the output cannot be determined from this code.
- **Grader:** The claim describes an AFC output clamp that limits a value between upper and lower bounds. The blind answer describes a hysteresis flag using those same two constants as set and clear thresholds, which gates a fixed constant (or 0) into 0xFFFF7820. That is not a clamp. The addresses match, but the functions differ.
- **Differs on:** The claim says 0xCC014 and 0xCC018 are the upper and lower limits of an output clamp. The blind answer says they are hysteresis thresholds on an input, and the output is a gated constant from 0xCC01C.

### 0x45670 -- DISAGREE

- **On record:** Project label "task03_knock_thresh" [TRACED]. Comment: [TRACED] Task [3] Knock threshold config. Feedback Corr Min Load (0xD2DA4), sets GBR
- **Blind (inferred):** update_mode_gated_ramp_factor_0to1 -- Most likely produces a 0..1 blend or weighting factor for a transition. The ramp is enabled once a counter or timer reaches a delay threshold, and its step size depends on the active mode (code 10 or 98). Which engine function this blend serves is unknown from this code.
- **Grader:** The claim calls this routine the knock threshold config tied to Feedback Corr Min Load at 0xD2DA4. The blind answer puts the main routine down as a mode-gated 0..1 ramp using other ROM constants, and says 0xD2DA4 belongs to a separate neighbouring hysteresis routine. It describes the hysteresis on 0xD2DA4/0xD2DA8 but gives it no knock or load identity.
- **Differs on:** The claim says the function is knock threshold config using 0xD2DA4. The blind answer says the main routine is a mode-dependent ramp factor, and that 0xD2DA4 is used by a different routine as a hysteresis flag.

### 0x0D118 -- DISAGREE

- **On record:** Project label "clamp_filter" [TRACED]. Comment: [TRACED] Clamp/filter function. Called by task53 readiness.
- **Blind (inferred):** atomic_store_float_pair_FFFF4498_FFFF449C -- Writes two related float values (fr4 then fr5) into a pair of adjacent RAM variables at 0xFFFF4498/0xFFFF449C. The write sits between a 'raise level / save state' call (0x317C, argument 16) and a 'restore state' call (0x3190, given the saved token). It is most likely an interrupt-masked critical section, so other tasks or ISRs never see a half-updated pair. What the two floats mean is unknown from this code.
- **Grader:** The claim calls this a clamp/filter function. The blind answer describes an atomic store of two floats to RAM inside a critical section, with no clamping or filtering.
- **Differs on:** Clamp/filter computation versus an interrupt-masked store of a float pair to 0xFFFF4498/449C.

### 0x66C40 -- DISAGREE

- **On record:** Project label "task56_evap_test_sequence" [TRACED]. Comment: [TRACED] EVAP active test sequence (state 1 or 2).
- **Blind (inferred):** track_minmax_of_ffff653c_when_state2 -- Running min/max (peak and trough) capture of the float at 0xFFFF653C. It runs only while a mode/condition returned by 0x021D9A equals 2 and re-arms whenever that mode is left. The 0.75 and 2.0 seeds suggest a quantity normally near 1.0, such as a lambda or equivalence ratio or a correction ratio. That fits min/max amplitude tracking for an O2-sensor or catalyst-type diagnostic, but the specific signal is not identified.
- **Grader:** The claim calls this an EVAP active test sequence. The blind answer describes min/max capture of a near-1.0 ratio signal during state 2 and guesses an O2 or catalyst diagnostic, which is a different subsystem. The shared notion of a state code is too generic to count as partial agreement.
- **Differs on:** Claim: EVAP active test sequence. Blind: min/max amplitude tracking of a lambda-like signal, likely for an O2 or catalyst diagnostic.

### 0x0A660 -- DISAGREE

- **On record:** Project label "task10_knock_signal_read" [TRACED]. Comment: [TRACED] Task 10 call_32: Knock signal per-cylinder read. Accesses FFFF4309 (knock byte), FFFF430D (knock byte 2), FFFF4311 (MAP/pressure threshold). Reads processed knock ADC values into per-cylinder knock state bytes.
- **Blind (observed):** init_4elem_byte_arrays_FFFF4309_430D -- An initialisation or reset routine: it runs a sub-initialiser, then loads default values into two adjacent 4-entry byte arrays (all 1s and all 7s) and clears the byte that follows them. The four entries could be per-cylinder slots (the EJ engine has 4 cylinders), but the code does not show that. What the arrays actually hold is unknown.
- **Grader:** The claim says the routine reads processed knock ADC values into per-cylinder state bytes. The blind answer finds that it writes constant defaults (1s and 7s) to the same addresses and clears 0xFFFF4311. That makes it an init or reset routine, not a signal read. Both touch the same addresses and hint at per-cylinder slots, but the function they describe is opposite.
- **Differs on:** The claim says it reads knock ADC values into per-cylinder bytes; the blind answer says it initialises those bytes to the constants 1 and 7 and zeroes 0xFFFF4311.

### 0x4A94C -- AGREE

- **On record:** Project label "sched_periodic_dispatch" [TRACED]. Comment: [TRACED] NOT AN ISR (item 84): absent from the 0x0-0x400 vector table, and its body is a straight-line run of 23 jsr plus one tail jmp gated on byte[0xFFFF8EDC]. COUNT CORRECTED 2026-08-19 (item 84): 23 jsr @r2 + one tail jmp @r2 = 24 tasks, NOT 59, and there is no task_table. Straight-line body, gated on byte[0xFFFF8EDC] != 0 at 0x04A954, rts at 0x04A9F0. Task 1 = 0x043750 (knock_wrapper), task 9 = 0x033304, tail jmp -> 0x00022F8A.
- **Blind (inferred):** task_dispatch_group_gated_by_8EDC -- Most likely one periodic scheduler slot (a time-sliced task list) that runs a batch of engine-control subsystem routines in a fixed order. It forwards a byte parameter, possibly a tick or phase index, to some of them. The whole batch is suppressed while the flag byte at 0xFFFF8EDC is set. That flag could be an init-in-progress, inhibit or busy marker. Its exact meaning and the jobs of the callees are unknown from this listing.
- **Grader:** Both describe a periodic scheduler dispatch: a straight-line run of 23 calls plus a tail jump to 0x22F8A, gated on byte 0xFFFF8EDC. The blind answer's call list matches the claim's details, with 0x43750 as task 1 and 0x33304 as task 9.
- **Differs on:** The gate polarity is unclear: the blind answer says the routine runs only when the byte is zero, while the claim's wording 'gated on != 0' could be read either way.

### 0x3684A -- AGREE

- **On record:** Project label "fn_3684A_rpm_load_pair_select" [TRACED]. Comment: [TRACED] GBR = 0xFFFF798C. Reads RPM [FFFF6624] -> fr12 and ENGINE LOAD [FFFF63F8] -> fr15 as the two lookup axes, folds [FFFF7F48]+[FFFF8258]-[FFFF7E90] into FFFF79B4, then selects desc 0xAD960 vs 0xAD97C on whether [FFFF798C] != 0 (helper 0x0BE608, eps 3.0518e-05). Structure established, MEANING NOT -- do not name these tables from the ol_enrichment_accum label. corrections.md item 86.
- **Blind (hunch):** rpm_load_map_with_asymmetric_two_stage_lag_update -- Unknown. The code computes a modelled quantity: an rpm/load base map scaled by a correction looked up from a sum/difference of three other RAM values. The value is then smoothed through two lag stages, with separate rise and fall rates. A slow, asymmetric two-stage response like this fits a thermal model, such as an estimated exhaust gas or catalyst temperature, but the code does not confirm that.
- **Grader:** Both describe the same structure: RPM/load axes, the 79B4 sum/difference fold, and selection between 0xAD960 and 0xAD97C based on whether 798C is non-zero via a deadband helper. The claim explicitly leaves the meaning unestablished, and the blind answer likewise says the purpose is unknown, adding more downstream detail without contradicting anything.
- **Differs on:** none

### 0x040DE -- AGREE

- **On record:** Project label "adc_bulk_read" [TRACED]. Comment: [TRACED] ADC bulk reader inner function. GBR base = FFFF4024. Polls ADCSR0/1/2 for conversion complete, reads all 32 channels to GBR+0..GBR+62. Channel map: ADDR4=Baro(402C), ADDR5=TPS(402E), ADDR7=VBatt(4032), ADDR14=MAP-baro(4040), ADDR15=MAF(4042), ADDR22=MAP-man(4050), ADDR26=FuelT(4058), ADDR28=O2(405C), ADDR29=ECT(405E), ADDR30=IAT(4060).
- **Blind (inferred):** adc_convert_all_channels_blocking_and_copy_raw -- A synchronous one-shot A/D pass over all 32 analog channels, most likely run at initialisation. It reconfigures and starts all three SH7058 A/D converters, waits for them to finish by polling, and stores the raw results in a contiguous RAM buffer at 0xFFFF4024. Other code presumably reads sensor voltages from that buffer before normal interrupt-driven sampling takes over. The bytes at 0xFFFF40A4/A9/AA are probably A/D scheduler state or mode variables; their meaning is unknown.
- **Grader:** Both describe a function that sets GBR to FFFF4024, polls the three ADCSR registers for conversion complete, and copies all 32 ADC channels into GBR+0..62. The blind answer gives no per-channel sensor map, but the mechanism and role match.
- **Differs on:** none

### 0x42F48 -- PARTLY_AGREE

- **On record:** Project label "task42_timing_comp_b" [TRACED]. Comment: [TRACED] Task [42] IAM-gated Timing Comp B. IAM+knock→Timing Comp B (IAT) activation
- **Blind (inferred):** update_iat_target_ramp_state_80B8 -- The mechanism is a rate-limited ramp of an IAT-scheduled correction. It rises toward an IAT-table value plus a capped difference term and decays toward zero when its enable flags drop. A clamped copy is published to 0xFFFF322C. What the correction physically controls is unknown from this code.
- **Grader:** The blind answer finds the same mechanism, an IAT-scheduled correction that is gated by flags, rate-limited and clamped. It cannot say this is a timing compensation, and it does not identify the gates as IAM and knock.
- **Differs on:** The claim identifies it as an IAM- and knock-gated Timing Comp B (IAT); the blind answer says what the correction controls is unknown.

### 0x4530A -- PARTLY_AGREE

- **On record:** Project label "task05_knock_det" [TRACED]. Comment: [TRACED] Task [5] Knock detection. KNOCK_FLAG+MAF+IAM, sets GBR
- **Blind (observed):** latch_rpm_and_count_calls_below_threshold -- unknown. Mechanically, it times how long an unnamed float signal (0xFFFF8584) has been below a calibrated threshold and keeps the RPM from the moment that condition was last met. This is typical of an event-entry timer, for example a timer started after some load, flow or speed variable drops below a limit. Which signal it is cannot be told from this code.
- **Grader:** The claim says this is the knock detection task, using a knock flag, MAF and IAM and setting GBR. The blind answer describes a generic threshold timer with an RPM latch and says the purpose is unknown. It mentions nothing about knock, IAM or GBR, so it gets the mechanism but not the purpose.
- **Differs on:** The claim identifies the routine as knock detection using KNOCK_FLAG/MAF/IAM; the blind answer treats it as an unidentified float-below-threshold timer with an RPM latch.

### 0x3162C -- PARTLY_AGREE

- **On record:** Project label "cl_master_readiness_eval" [TRACED]. Comment: [TRACED] Computes FFFF7452 (cl_master_readiness) and 3 secondary flags. GBR=FFFF7450. Outputs: FFFF7450 (speed CL flag), FFFF7451 (speed+coolant CL flag), FFFF7452 (master CL enable), FFFF7453 (strictest: AFR stability required). 7 conditions must ALL pass: (1) bit3(FFFF61F4)==0 early exit; (2) speed: FFFF67EC>=lookup AND FFFF798C near 0 (3.05e-5) AND FFFF7A20 near 0 AND FFFF7D18==0 AND FFFF77C8>-1.0; (3) throttle hyst flags (FFFF7458/745D/745E) AND FFFF65F6!=1 AND FFFF7464==0; (4) FFFF7BA8<0.11; (5) FFFF7BB0==0; (6) delay counters FFFF745B/745C both>=4; (7) coolant float@FFFF77C0 in [0.5,5.0]. FFFF798C is the BRIDGE: Path A OL enri
- **Blind (inferred):** diag_enable_conditions_update_7450 -- Most likely the enable-condition evaluator for a group of OBD diagnostic monitors. Four monitor-permission bytes (7450..7453) are produced from coolant temperature (including a minimum time-after-start that depends on coolant temperature), low rpm / idle-like conditions, settling counters after switch transitions, and other gates. Which monitor these enables serve is unknown from this code alone.
- **Grader:** Both describe the same routine structurally: GBR 7450, four output flags 7450-7453, the 67EC lookup comparison, deadband checks on 798C/7A20, 7D18==0, 77C8, 7BA8 threshold, 7BB0==0, two counters, and 77C0 window conditions. The purpose differs: the claim says closed-loop fueling readiness/enable, while the blind answer guesses OBD diagnostic monitor enable conditions.
- **Differs on:** Claim says the outputs are closed-loop fueling enable/readiness flags (master CL enable). The blind answer calls them OBD diagnostic monitor enable flags.

### 0x7D554 -- PARTLY_AGREE

- **On record:** Project label "o2_diag_init" [TRACED]. Comment: [TRACED] O2 diagnostic workspace init. GBR=FFFFA248. Sets enable flag FFFFA291, zeros counters, sets 9 sentinel floats to 8000.0.
- **Blind (observed):** reset_A248_state_block_when_flag_set -- A one-shot reinitialisation of one RAM state block (0xFFFFA248-0xFFFFA295), gated by the condition helper at 0x22F92. It zeroes three floats, two words and four 4-element word arrays, presets six floats to 8000.0, sets a 'reset done/active' flag at A291 and clears a flag at A295. What the block represents (for example per-cylinder or 4-channel counters, or 8000.0 as a high starting value for minimum tracking or a timer preset) cannot be determined from this function.
- **Grader:** Both describe the same workspace init at GBR=FFFFA248: it sets the enable flag at A291, zeroes counters and presets floats to 8000.0. The blind answer cannot tie it to O2 diagnostics, and it counts six 8000.0 floats plus three 0.0 floats, where the claim says nine sentinels.
- **Differs on:** Claim says 9 sentinel floats are set to 8000.0; the blind answer says only six are set to 8000.0 and three are set to 0.0, and it does not identify the block as O2 diagnostic.

### 0x4A674 -- PARTLY_AGREE

- **On record:** Project label "stubpool_target_42" [TRACED]. Comment: [TRACED] Slot 42 of the LITERAL POOL at 0x00E5EC (0x0E694), called from a 0x00E4xx task stub. RENAMED from \"isr_handler_42\", which was positional over a structure misread as an ISR dispatch table -- it is a literal pool (item 84), and this address is NOT in the 0x0-0x400 vector table. corrections.md item 91.
- **Blind (observed):** task_run_subsystem_updates_if_flag_clear -- A scheduler or dispatcher step. It runs a batch of eleven subsystem routines, probably one periodic task slice, but only while the inhibit or mode flag at 0xFFFF8EDC is clear. The specific subsystems, and what the flag means, cannot be told from this code.
- **Grader:** The claim only says this is a literal-pool target called from a task stub, and the blind answer's reading of it as a task routine that dispatches a batch of subsystems fits that. The claim gives no specific function to test against, so the blind answer adds detail rather than matching a stated identity.
- **Differs on:** The claim identifies it only as pool slot 42 reached from a task stub. The blind answer specifies a flag-gated batch of eleven subsystem calls, which the claim neither confirms nor contradicts.

### 0x4AF12 -- PARTLY_AGREE

- **On record:** Project label "ol_ignition_timing_B" [TRACED]. Comment: [TRACED] Sub-table B [11]. OL ignition timing path B. Same structure as path A but calls 0x75C4A for base timing lookup. Likely second cylinder bank or alternate timing map.
- **Blind (observed):** run_gated_subtask_chain_04AF12 -- unknown. Structurally it is a scheduler-style dispatcher. A global inhibit byte at 0xFFFF8EDC (zero means run) gates a fixed sequence of subtasks. The last three run only while the mode/state byte at 0xFFFF98F6 equals 1. The neighbouring wrappers suggest 0xFFFF8EDC is a module-wide 'disabled / not ready' flag, but nothing shown identifies the subsystem.
- **Grader:** The blind answer gets the mechanism right, including the call to 0x75C4A that the claim cites as the base timing lookup, but it cannot say what the routine is for. It never identifies it as an open-loop ignition timing path.
- **Differs on:** The claim says this is OL ignition timing path B, and the blind answer calls it an unidentified gated subtask dispatcher.

### 0x06BC4 -- PARTLY_AGREE

- **On record:** Project label "io_write_word_atomic" [TRACED]. Comment: [TRACED] 35 calls. Atomic word write: critical_section_enter, BSR to formatter, BSR to writer, critical_section_exit. Used for peripheral register updates.
- **Blind (observed):** atomic_call_6CFC_then_6DB8_u8 -- unknown. It is a thread-safe wrapper that runs two helpers back-to-back without interruption: the first is fed a byte parameter and the second's byte result is returned. The pattern fits 'select channel/index, then read value' on some peripheral or shared table, but nothing shown fixes what the helpers do.
- **Grader:** Both describe the same structure: a critical section wrapping two BSR calls. The claim calls it an atomic word write used for peripheral register updates. The blind answer finds that the second call's byte result is returned and suggests a select-then-read pattern, and it leaves the purpose unknown.
- **Differs on:** The claim says it is a write ('formatter then writer'); the blind answer says it returns the second helper's byte result, which suggests a read.

### 0x32AA8 -- PARTLY_AGREE

- **On record:** Project label "fuel_correction_array" [TRACED]. Comment: [TRACED] 29-element gear-dependent correction array.
- **Blind (hunch):** conditional_reset_float_block_FFFF7710_with_29_entry_history_seed -- Most likely a re-initialisation of one subsystem's float state block, run when the condition returned by 0x22F92 is true (value 1). The block holds several scale or gain-like values set to 1.0, two configurable constants, and cleared flags and accumulator. The 29-entry array seeded with one live value is consistent with a history or filter buffer (for example a moving average) being preset to the current reading, so that it starts without a transient. Which subsystem, and what 0x22F92 tests, cannot be told from this code.
- **Grader:** Both describe a 29-element float array. The blind answer reads it as a history/filter buffer seeded with one live value and cannot name the subsystem; the claim calls it a gear-dependent fuel correction array. The mechanism and size match, but the purpose the claim gives is not identified.
- **Differs on:** Claim: gear-dependent fuel correction array. Blind: a generic history or filter buffer of unknown subsystem, preset to the current reading.

### 0x758CA -- PARTLY_AGREE

- **On record:** Project label "task57_egr_emissions" [TRACED]. Comment: [TRACED] Task [57] EGR/emissions monitor. Calls egr_sub_a(0x7BF3C) for maturation counters, egr_sub_b(0x7C242) for completion check, tail-calls 0x7C280 output handler. GBR bases: FFFFA198/A156/A158. Critical section at 0xBA84.
- **Blind (observed):** seq_call_7BF3C_7C242_tail_7C280 -- unknown. It runs three routines in a fixed order, and only the first gets an explicit 8-bit argument (likely an index, channel or mode byte). What that argument or the three routines mean cannot be told without disassembling the callees.
- **Grader:** The blind answer matches the call structure exactly: it calls 0x7BF3C, then 0x7C242, then tail-jumps to 0x7C280. It declines to name the purpose, while the claim calls it an EGR/emissions monitor task. The claim's GBR bases and critical section aren't seen in the blind answer, which says the wrapper touches no RAM; the claim may be describing the callees.
- **Differs on:** The claim identifies the function as an EGR/emissions monitor task with maturation and completion roles; the blind answer gives the purpose as unknown.

### 0x46978 -- PARTLY_AGREE

- **On record:** Project label "task26_flkc_output" [TRACED]. Comment: [TRACED] Task [26] FLKC output stage. flkc output+cal 0xD29F0
- **Blind (observed):** sat_increment_counter_FFFF8296_when_enabled -- unknown. Mechanically it is a saturating up-counter (timer) at 0xFFFF8296. It advances once per call while two enable bytes in its struct are 1 and an inhibit byte at 0xFFFF82AC is 0. The neighbour at 0x0469A4 shows a run-until-calibrated-limit pattern: the +11 enable flag is cleared once the counter reaches the ROM threshold at 0xD29F0 and re-armed from 0xFFFF827C. Which engine feature this timer serves cannot be told from the code shown.
- **Grader:** The blind answer describes the mechanism in detail, including a saturating counter and its comparison against the calibration at 0xD29F0, which matches the claim's 'flkc output+cal 0xD29F0'. It cannot name the purpose as FLKC (fine learning knock correction), so it is vaguer than the claim.
- **Differs on:** The claim identifies the routine as the FLKC output stage; the blind answer calls it a generic enabled saturating timer of unknown purpose.

### 0x10800 -- PARTLY_AGREE

- **On record:** Project label "sched_event_post" [TRACED]. Comment: [TRACED] Packs (r4 = event id, r5 = payload), enters critical section via 0x0BE81C, calls the walker 0x010B2A, leaves via 0x0BE82C. Same thing the earlier \"event_notify\" label described; merged (item 90).
- **Blind (observed):** locked_call_010B2A -- This makes the call to 0x010B2A atomic with respect to most interrupts, i.e. a thread-safe front end for a routine taking (int16, uint32). What 0x010B2A itself does is unknown from this listing.
- **Grader:** The blind answer matches the mechanism exactly: it saves r4 and r5, enters the critical section at 0x0BE81C, calls 0x010B2A and exits via 0x0BE82C. It cannot say what 0x010B2A does, so it never identifies the function as posting an event (event id plus payload) through a walker.
- **Differs on:** The claim says this posts a scheduler event with r4 = event id and r5 = payload; the blind answer only calls it a generic locked wrapper around an unknown routine.

### 0x06BF0 -- PARTLY_AGREE

- **On record:** Project label "io_write_2word_atomic" [TRACED]. Comment: [TRACED] 31 calls. Atomic 2-word write: critical_section_enter, write 2 values, critical_section_exit. Extended I/O update.
- **Blind (observed):** atomic_apply_byte_pair_6CFC_6D5A -- unknown. The code only shows that this wrapper runs two subroutines with interrupts masked, each taking one of the caller's byte arguments. What those subroutines set up (possibly a peripheral or channel configuration) is not visible here.
- **Grader:** Both describe an atomic wrapper: critical_section_enter, two operations on two arguments, critical_section_exit. The blind answer does not identify these as I/O writes and leaves the purpose unknown, so it is vaguer than the claim.
- **Differs on:** Claim says the two inner operations are I/O word writes (extended I/O update); blind answer says only that two unknown subroutines are called with byte args.

### 0x48E16 -- PARTLY_AGREE

- **On record:** Project label "ol_gated_atu_dispatch" [TRACED]. Comment: [TRACED] OL-gated ATU channel dispatch. Called from Task 8 (rtos_task8_atu_hw). Checks ol_dispatch_gate (FFFF8EDC): same gate logic as 0x049CF0. If OL active: dispatches ATU channels for OL injection mode. Also labeled isr_handler (entry in sub-table area).
- **Blind (inferred):** periodic_task_dispatch_by_mode_FFFF8EDC -- Most likely a periodic (time-sliced) task scheduler or dispatcher for a group of engine-control routines. A mode or state byte at 0xFFFF8EDC chooses between three cases: the normal full task list (0), a minimal alternate path (0xFF), and a reduced path (other values). The reduced paths might be for initialisation, shutdown or a special operating state, but the meaning of those modes cannot be told from this code. 0x317C/0x3190 look like a save-and-raise / restore pair (for example of the interrupt mask or a lock) that protects 0x6FC1E as a critical section.
- **Grader:** Both describe a dispatcher that branches on the gate byte at FFFF8EDC and sequences calls. The blind answer cannot identify the gate as open-loop or the ATU/injection role, and it reads the routine as a general three-way task dispatcher.
- **Differs on:** The claim says this is an OL-gated dispatch of ATU channels for OL injection mode; the blind answer calls it a generic mode-based periodic task scheduler with an unknown meaning for the mode byte.

### 0x2C078 -- PARTLY_AGREE

- **On record:** Project label "eeprom_persistence_state_machine" [TRACED]. Comment: [TRACED] EEPROM read/write state machine for learned value persistence. Uses FFFF6C4C buffer, calls EEPROM helpers at 0x6B5A/0x6884/0x67DC.
- **Blind (hunch):** init_status_block_FFFF6C4C_marker_5A -- unknown. The code seeds a byte-wide control/status block at 0xFFFF6C4C with a 16-bit value and 0x5A marker bytes. The companion routine can set 0xA5 into the same marker positions. A 0x5A/0xA5 complementary pair suggests a 'valid/armed' signature, for example for a RAM backup, handshake or watchdog-style flag block. The code shown does not confirm that.
- **Grader:** Both describe the same routine, which calls the 0x6B5A helper and writes to the FFFF6C4C block. The blind answer reads it as a marker/signature block, possibly for RAM backup, but cannot confirm the claim's EEPROM persistence state machine role.
- **Differs on:** The claim says this is an EEPROM read/write state machine for learned values; the blind answer leaves the purpose unknown and describes only initializing a status block with 0x5A/0xA5 markers.

### 0x66D20 -- PARTLY_AGREE

- **On record:** Project label "task56_evap_sub_disabled_A" [TRACED]. Comment: [TRACED] EVAP sub when diagnostics disabled (path A).
- **Blind (inferred):** diag_check_wrapper_flagbit_97520 -- Probably a thin wrapper that feeds one condition bit and one status value into a shared evaluation routine, together with two ROM parameter blocks. The routine at 0x066D5E looks generic (it takes table pointers and saves registers). That pattern fits a per-code diagnostic or monitor check, but the code shown cannot confirm what is being monitored.
- **Grader:** The blind answer correctly sees a wrapper that feeds a diagnostic-enable flag bit into a shared evaluation routine. It does not identify EVAP or the 'diagnostics disabled' path that the claim specifies, so it is vaguer than the claim.
- **Differs on:** The claim names this as the EVAP subroutine for when diagnostics are disabled (path A); the blind answer only calls it a generic diagnostic/monitor check wrapper and does not name the subsystem.

### 0x06738 -- PARTLY_AGREE

- **On record:** Project label "hw_register_conditioning_B" [TRACED]. Comment: [TRACED] Task 0 call_08. Double BE81C, accesses HW ports F018-F026. Peripheral port conditioning — ensures correct HW reg state.
- **Blind (inferred):** sci3_configure_clocked_sync_msb_first -- This is most likely an idempotent setup or refresh of one SH7058 SCI channel, probably SCI3 at base 0xFFFFF018, for clocked-synchronous serial with internal clock and MSB-first bit order. In that reading: SMR3=0x80 selects C/A=1 (clocked synchronous, 8-bit, CKS=00). Clearing SCR3 CKE1:0 selects the internal clock with SCK output. SDCR3=0xFA, the reset value 0xF2 plus DIR, gives MSB-first. BRR3=6 sets the bit rate. It is run with interrupts masked so the reconfiguration is atomic. The use of a synchronous serial link to an external chip is a hunch; a serial EEPROM is a plausible candidate.
- **Grader:** Both describe idempotent conditioning of the HW peripheral registers at F018-F01E, done under double critical sections. The claim is generic about the purpose, while the blind answer names a specific use (SCI3 clocked-sync configuration), so the match is on mechanism with only a vague claim to test the identity against.
- **Differs on:** The claim says only 'peripheral port conditioning'; the blind answer specifically identifies SCI3 serial setup.

### 0x5E798 -- PARTLY_AGREE

- **On record:** Project label "diag_monitor_pack_write_36BC" [TRACED]. Comment: [TRACED] uint8_pack -> write to FFFF36BC.
- **Blind (observed):** set_FFFF36BC_from_u8_packed -- unknown. Structurally this is a compiler-generated setter or accessor: it converts a uint8 argument through uint8_pack and writes it to the 16-bit RAM variable at 0xFFFF36BC. The code shown does not reveal what that variable means.
- **Grader:** Both describe the same mechanism: the function passes a uint8 through uint8_pack and writes the result to FFFF36BC. The claim also places it in diagnostic monitoring, and the blind answer does not identify that purpose.
- **Differs on:** The claim's 'diag_monitor' role is not confirmed by the blind answer, which leaves the purpose unknown.

### 0x34C54 -- PARTLY_AGREE

- **On record:** Project label "afl_clol_mode_check" [TRACED]. Comment: [TRACED] AFL CL/OL mode check. Reads FFFF7448. When 0 (OL): AFL learning FROZEN.
- **Blind (observed):** counter_timeout_and_window_decrement_787E -- unknown. The shape is a nonzero count A that ages: timer B runs while A is set, and A is dropped once B reaches the calibrated limit. A is also stepped down by one on each call where two status flags are 1 and a float signal lies inside a calibrated window. What A, B, the flags and the float at 0xFFFF7708 represent cannot be told from this code.
- **Grader:** The blind answer does read 0xFFFF7448 and gates on it being 1, which is consistent with a CL/OL flag where 0 freezes the action. It cannot say what the flag means or connect it to AFL learning, and it describes a counter/timer routine rather than an explicit mode check.
- **Differs on:** Claim names the function as an AFL closed/open-loop mode check that freezes learning in OL; the blind answer gives no purpose and treats 0xFFFF7448 as one unexplained gating flag inside a counter-aging routine.

### 0x0CBAC -- PARTLY_AGREE

- **On record:** Project label "maf_timer_prescaler" [TRACED]. Comment: [TRACED] Task 9: reloads 9 timer channels (IDs 0,1,2,4,8,9,10,12) via timer_reload(0xCA72) every 4th tick (80ms). Counter at FFFF447A.
- **Blind (observed):** every4th_call_run_CA72_for_channels_0_1_2_4_8_9_10_12 -- A divide-by-4 prescaler: on every 4th invocation it runs a per-index routine (0x00CA72) for a fixed, non-contiguous set of indices (0,1,2,4,8,9,10,12). These are likely channel or slot numbers in some table, such as sensor or ADC channels, but what the indices mean and what 0x00CA72 does cannot be told from this code. The exact purpose is unknown.
- **Grader:** The blind answer matches the mechanism exactly: the counter at FFFF447A, divide-by-4, and calls to CA72 for indices 0,1,2,4,8,9,10,12. However, it cannot say that CA72 is a timer reload or that the timers relate to MAF, so the purpose stays unknown.
- **Differs on:** The claim identifies CA72 as timer_reload and the channels as timer channels (MAF-related, 80ms); the blind answer leaves the purpose of the routine and the indices unknown.

### 0x6F114 -- PARTLY_AGREE

- **On record:** Project label "task58_maf_diag_part2" [TRACED]. Comment: [TRACED] MAF diag part 2: maturation and DTC set/clear.
- **Blind (inferred):** diag_monitor_debounce_and_report_9EDxx -- Most likely a diagnostic (DTC) debounce. When the enable conditions hold and the monitored input reports state 2 (probably abnormal), it counts up to a calibrated limit and then reports a fault through 0x9ED90. When the input reports state 1 (probably normal), it clears the count and reports a pass through 0x9EDEC. The argument r4=1 probably picks the DTC or monitor index. Which fault is monitored cannot be told from this code.
- **Grader:** The blind answer correctly identifies a diagnostic debounce (maturation) routine that sets or clears a DTC, which matches the claim's mechanism. It cannot say which fault is monitored, while the claim specifies MAF.
- **Differs on:** Claim identifies it as the MAF diagnostic; the blind answer says the monitored fault cannot be determined.

### 0x49CF0 -- PARTLY_AGREE

- **On record:** Project label "fuel_dispatch_tableB_runner" [TRACED]. Comment: [TRACED] fuel_dispatch_table_B RUNNER. Checks ol_dispatch_gate (FFFF8EDC): if 0x00 = OL active: dispatches all 18 table-B functions (including 7-phase OL pipeline). if 0xFF = special mode: JMP to 0x5AB44 (cl_monitor_state_machine) with R4=1. if other non-zero: JMP to 0x5AB44 (cl_monitor_state_machine) with R4=0. Called via secondary dispatch: Task2/3 -> F97C -> E54E -> 5798 -> 049CF0. Also labeled isr_handler_33 (that label is also valid).
- **Blind (inferred):** main_task_dispatch_by_mode -- Most likely a top-level periodic scheduler or task-list runner that picks which group of subsystem routines to execute from a mode/state byte at 0xFFFF8EDC. 0 would be the normal-run full task list, 0xFF a reduced special-mode list, and other values a minimal path. The 0x317C/0x3190 pairs are probably a save-SR/raise-interrupt-mask and restore critical section around routines that need atomic access.
- **Grader:** Both describe a three-way dispatcher keyed on the byte at 0xFFFF8EDC, with value 0 running a long list of subroutines and the other values going to 0x5AB44. The branch details conflict, though. The blind answer has 0xFF running a short sequence with 0x5AB44(r4=0) and other nonzero values tail-calling 0x5AB44 with r4=1. The claim says 0xFF jumps there with R4=1 and other values with R4=0. The blind answer also counts about 90 calls on the zero path, not 18.
- **Differs on:** Behaviour of the 0xFF and other-nonzero branches (the R4 values are swapped, and the blind answer has 0xFF running a multi-call sequence), plus the size of the zero-path list (about 90 calls versus 18 functions).

### 0x44296 -- PARTLY_AGREE

- **On record:** Project label "task29_timing_percyl" [TRACED]. Comment: [TRACED] Task 29: secondary per-cylinder timing computation.
- **Blind (observed):** compute_float_81EC_sum_with_inhibit -- Unknown from the code alone. Structurally it builds a combined value: a base term (81F0) plus two additive terms (8260, 828C). The two additive terms are dropped whenever either helper flag is set, and the whole output is forced to zero when the mode byte at 6254 equals 1. This fits a total-correction or total-compensation aggregator with conditional inhibits, such as a sum of correction terms, but nothing shown identifies the quantity.
- **Grader:** The claim calls this a per-cylinder timing computation. The blind answer describes the mechanism precisely, a base plus two correction terms with inhibit conditions, but explicitly cannot name the quantity. Its guess of a correction aggregator is compatible with a timing computation but does not identify timing or the per-cylinder aspect.
- **Differs on:** The claim identifies the output as per-cylinder ignition timing; the blind answer says the summed quantity is unknown.

### 0x33278 -- PARTLY_AGREE

- **On record:** Project label "fuel_precalc" [TRACED]. Comment: [TRACED] Fueling pre-calculation. Dispatched from fuel_dispatch_table_A.
- **Blind (observed):** init_ram_block_7858_and_load_float_cals -- Unknown. The shape (unconditional fill of two halfwords with all-ones, a sub-initialisation call, then seeding three float RAM variables from ROM constants) looks like a power-on or reset initialiser for one subsystem's state block. 0xFFFF may be an 'invalid/not yet computed' sentinel or an all-bits-set mask. The floats are probably calibration defaults or starting values. Which subsystem it is cannot be told from this code.
- **Grader:** The claim calls this a fueling pre-calculation routine dispatched from a fuel dispatch table. The blind answer describes an initialiser that seeds a state block but cannot name the subsystem. A pre-calc that sets sentinels and loads cal floats into RAM is broadly compatible with that description, but the blind answer gives neither the fuel identity nor the dispatch role.
- **Differs on:** The claim says this is fueling pre-calculation. The blind answer leaves the subsystem unknown and guesses a power-on/reset initialiser.

### 0x303C2 -- PARTLY_AGREE

- **On record:** Project label "injector_dead_time_calc" [TRACED]. Comment: [TRACED] Dead time table lookup (descriptor 0x0AD7E0, via the 2D uint16 helper 0x0BE944). Inputs: FR4=[FFFF4130] = BATTERY VOLTAGE -> axis 0xD104C 'Injector Latency_ / Battery Output' (6.5..16.5 V); FR5=[FFFF6210] = MANIFOLD PRESSURE (relative) -> axis 0xD1060 'Injector Latency_ / Manifold Pressure' (-1000..1000 raw = -19.3..+19.3 psi rel). Both settled 2026-07-26; FFFF4130 was 'atm_pressure_baro'. descriptor 0xAD7E0 (InjLat 5x3, VBatt axis 6.5-16.5V). Calls 0xBE944 (2D interp), stores uint16 result to FFFF7350, then calls 0x9E4A stub to write FFFF4280. Also calls 0xBE598 for float path. Tail-calls 0x3190 (irq level restore). Called 
- **Blind (observed):** update_from_table_AD7E0_raw_and_scaled -- unknown. It computes a 2-input table value (raw uint16 at 0xFFFF7350, plus a scaled copy, raw×0.25, as a float at 0xFFFF734C) and hands the raw value to routine 0x9E4A inside what looks like an interrupt-protected section, plausibly to load it into a hardware or shared scheduling parameter. What the two inputs, the table and the output represent cannot be told from this code.
- **Grader:** The blind answer matches the mechanism exactly: the same inputs, descriptor, 2D uint16 lookup, store to FFFF7350, the 0x9E4A call, the float path and the 0x3190 tail call. It cannot name the purpose, injector dead time from battery voltage and manifold pressure.
- **Differs on:** Blind says the purpose and the input identities are unknown; the claim identifies an injector dead time table indexed by battery voltage and manifold pressure.

### 0x81A64 -- PARTLY_AGREE

- **On record:** Project label "percyl_interp_gate" [TRACED]. Comment: [TRACED] Stage 1: Gate on check_diag_state, then call interp_pipeline for multi-dim fuel table interpolation.
- **Blind (observed):** guarded_call_081E14_then_081EB2_if_0582AC_false -- unknown. Structurally this is a gate: the boolean or flag from 0x0582AC decides whether two follow-on routines (0x081E14, then 0x081EB2) run this cycle. What the condition and the routines represent cannot be told from this listing.
- **Grader:** Both describe a gate: a check routine's result decides whether follow-on routines run. The blind answer gets that mechanism but cannot say the check is diagnostic state or that the follow-on is fuel table interpolation.
- **Differs on:** The claim identifies the gate as check_diag_state and the called routine as interp_pipeline for fuel table interpolation. The blind answer leaves the purpose unknown and describes two follow-on calls, not one.

### 0x4B970 -- PARTLY_AGREE

- **On record:** Project label "fuel_pump_duty_ctrl" [TRACED]. Comment: [TRACED] Fuel pump duty controller - initial prime + descriptor lookup. Called from task10 call_52.
- **Blind (observed):** init_block_8354_from_map_AE774 -- Unknown. The pattern looks like an initialisation or reset of a RAM state block around 0xFFFF8354-0xFFFF836E: one map-derived value, one constant, two words set to 0xFFFF (possibly 'invalid' or 'not yet set' markers), and a normalised ratio handed to a helper. What the variables physically mean cannot be told from this code.
- **Grader:** The blind answer describes the mechanism: a 2D table lookup, setting initial state and sentinel values, then a helper call. That fits 'initial prime + descriptor lookup', but the blind reader could not name the function as the fuel pump duty controller.
- **Differs on:** The claim identifies the function as the fuel pump duty controller; the blind answer calls it a generic RAM state block initialisation with unknown purpose.

### 0x0E448 -- PARTLY_AGREE

- **On record:** Project label "rtos_task9_fuel_clol" [TRACED]. Comment: [TRACED] RTOS Task 9: MAIN FUEL / CLOL calculation task (20 ms, pri 2). TCB=FFFF1210. gate(9) -> 0xFC04 (fuel pre-calc FFFF5B64) -> 0x5840 (crank-angle interp engine) -> 0xD658 (ATU channel set) -> 0xCBAC (MAF/intake FFFF447A) -> 0x4907C (fuel_dispatch_tableA runner, OL-gated FFFF8EDC) -> 0x9A58 (intake-B FFFF42F8) -> 0xD268 (ATU injection FFFF44A5) -> 0xCBEE (stub, immediate RTS) -> epilogue. fuel_dispatch_table_B runner (0x049CF0) is called separately via secondary dispatch: Task2/3 -> F97C -> E54E -> 5798 -> 049CF0.
- **Blind (inferred):** sched_task_list_E448 -- Most likely one entry in the ECU's periodic task schedule: a fixed list of subsystem routines run together in one time slot. The call to 0x010A46 with the constant 9 probably selects or marks a task, slot or channel index first. Which subsystems these are cannot be told from this code, so the specific purpose is unknown.
- **Grader:** The blind answer correctly identifies the mechanism: a periodic task slot that calls gate(9) and then the same sequence of subroutines through to an epilogue. It cannot say the task is the main fuel/CLOL calculation, so it is vaguer than the claim.
- **Differs on:** Claim identifies the task as the main fuel/CLOL calculation (20 ms, priority 2); blind answer says the specific purpose is unknown.

### 0x24EE8 -- PARTLY_AGREE

- **On record:** Project label "fn_24EE8_map_rationality_monitor" [TRACED]. Comment: [TRACED] GBR = 0xFFFF68A4. Builds an expected manifold pressure from RPM [FFFF6624] x THROTTLE [FFFF62DC] via desc 0xAB03C plus an RPM term via desc 0xAAF84, and compares it against actual MAP [FFFF620C]. Enable gate: ECT > -30.0 [0x0C34F0], 1000 [0x0C34F4] < RPM < 6500 [0x0C34F8], throttle above the 0xAAF84 threshold, precondition byte clear. OBD-II rationality monitor -- DIAGNOSTIC, not a control path. corrections.md item 94.
- **Blind (inferred):** monitor_deviation_low_debounce_counter -- A debounced condition monitor, most likely a diagnostic check. It runs only when the engine is warm, rpm is inside a window, the 0xFFFF62DC quantity (probably load) is above an rpm-dependent minimum, and no inhibit is reported by 0x029AA0. It counts how long the 0xFFFF2240 value stays at or below an expected value: a base value (0xFFFF620C) plus an rpm/load table offset, plus a margin. When the count reaches the calibrated limit it raises a flag. Which physical signal is being monitored cannot be determined from this code.
- **Grader:** Both describe the same diagnostic monitor: a 2D table over RPM and the 62DC quantity plus a 1D RPM table, the same enable gates, and a comparison involving 620C. The blind answer cannot name it as a MAP rationality monitor, and it treats 620C as a base value added to the table result, with 2240 as the monitored signal.
- **Differs on:** The claim says actual MAP at 620C is compared against the expected value. The blind answer says 2240 is compared against 620C plus the table offset, and leaves the monitored physical signal unidentified.

### 0x6F0B8 -- PARTLY_AGREE

- **On record:** Project label "task58_maf_diag" [TRACED]. Comment: [TRACED] Task 58: MAF sensor diagnostic monitor entry.
- **Blind (observed):** seq_call_06F0CE_then_tail_06F114 -- unknown. It is a dispatcher or wrapper that runs routine 0x06F0CE and then routine 0x06F114, probably as one step of a scheduler task or init chain. The bodies of those two routines are not shown, so what they do cannot be determined. The trailing neighbour sets a boolean RAM byte at 0xFFFF96A5 when its argument equals 1, and its meaning is also unknown.
- **Grader:** The blind answer describes the function as a task-entry wrapper that calls two routines in sequence, which fits a scheduler task entry structurally. It cannot identify the MAF diagnostic purpose and leaves that unknown.
- **Differs on:** The claim identifies it as the MAF sensor diagnostic monitor entry; the blind answer says its purpose is unknown beyond being a generic two-call dispatcher.

### 0x10CE2 -- PARTLY_AGREE

- **On record:** Project label "scheduler_state_update" [TRACED]. Comment: [TRACED] Task 0 call_02. ATU HW reg config (F710 OR bit1, F718=C0, F71C=9C3). Sub at 0x10D10: prescaler at FFFF5BBE drives FDB4 calls with R4=0/1/3/4 at different rates (mod 3, mod 5).
- **Blind (inferred):** cmt1_start_periodic_interrupt -- One-time setup that starts Compare Match Timer channel 1 as a periodic interrupt source. Under the SH7058 CMT register map: CMSTR |= STR1 starts channel 1; CMCSR1 = 0xC0 sets CMIE (interrupt enabled) with clock select 0 (Pphi/8); CMCOR1 = 2499 gives one compare match every 2500 counts. If Pphi is 40 MHz that is a 0.5 ms tick; if 20 MHz, a 1 ms tick. This is most likely the fixed-rate timebase interrupt for the ECU scheduler.
- **Grader:** Both describe the same register writes (F710 OR bit 1, F718=0xC0, F71C=0x9C3) as hardware timer configuration. The claim calls the peripheral ATU and labels the function a scheduler state update that also covers the prescaler sub at 0x10D10. The blind answer identifies it as CMT1 periodic-interrupt setup and places 0x10D10 in a separate function.
- **Differs on:** Whether the function is ATU config and scheduler state update including the 0x10D10 prescaler logic, or a standalone CMT1 timer-start routine that ends before 0x10D10.

### 0x6F0CE -- PARTLY_AGREE

- **On record:** Project label "task58_maf_diag_part1" [TRACED]. Comment: [TRACED] MAF diag part 1: precondition + IAT/load check.
- **Blind (observed):** update_enable_flag_96A4_status39_val4130_ge_cal_rpm_lt_cal -- unknown. It computes a boolean enable/condition-met flag that requires two status checks to equal 1, a RAM float at or above a calibrated minimum, and engine speed below a calibrated maximum. It may be an enable condition for a diagnostic monitor or a control feature (hunch), but neither the helpers' meaning nor the identity of 0xFFFF4130 is established here.
- **Grader:** The blind answer correctly finds a precondition/enable-flag computation (status checks plus a RAM float threshold and an rpm limit), and guesses it may be a diagnostic enable. It does not identify it as MAF diagnostics and does not identify the float as IAT or load.
- **Differs on:** The claim names this as the MAF diagnostic precondition with an IAT/load check; the blind answer leaves the purpose and the identity of 0xFFFF4130 unknown, and its rpm check is not mentioned in the claim.

### 0x49A7A -- PARTLY_AGREE

- **On record:** Project label "stubpool_target_27" [TRACED]. Comment: [TRACED] Slot 27 of the LITERAL POOL at 0x00E5EC (0x0E658), called from a 0x00E4xx task stub. RENAMED from \"isr_handler_27\", which was positional over a structure misread as an ISR dispatch table -- it is a literal pool (item 84), and this address is NOT in the 0x0-0x400 vector table. corrections.md item 91.
- **Blind (observed):** dispatch_task_group_if_8EDC_clear -- A scheduler or task-list entry: it runs a fixed group of seven subsystem routines only while the byte flag at 0xFFFF8EDC is zero. The flag therefore acts as an inhibit or mode gate. What the flag means and what the seven routines do cannot be told from this code, so the specific purpose is unknown.
- **Grader:** The claim only says this is a function reached through a literal-pool slot from a task stub, with no specific function. The blind answer describes it as a task-group dispatcher gated by a flag, which fits a task-stub target. It adds detail the claim cannot test, so the match is at the level of role only.
- **Differs on:** The claim gives no specific function beyond being a task-stub target. The blind answer specifies a flag-gated dispatcher for seven routines.

### 0x71ABA -- PARTLY_AGREE

- **On record:** Project label "sensor_diag_dispatch_1_body" [TRACED]. Comment: [TRACED] Real dispatcher body: 13 BSR calls — sensor acq, FPU compute, float clamp, 6 DTC monitor pairs, EEPROM storage, final handler. GBR=FFFF7C9F.
- **Blind (observed):** task_snapshot_byte_then_run_subtask_chain_071ABA -- A periodic wrapper or scheduler for one module. It first copies an external state byte (0xFFFF7C9F) into a variable in the module's own RAM area (0xFFFF97CC) so that every subroutine in this pass sees the same value. It then runs the module's 14 sub-steps in sequence. Which subsystem this is cannot be told from this code: unknown.
- **Grader:** Both describe a fixed-sequence dispatcher body of 13 BSR calls plus a final handler, but the blind answer cannot identify the subsystem (sensor acquisition, FPU compute, DTC monitors, EEPROM). It also treats 0xFFFF7C9F as a RAM byte being snapshotted rather than a GBR value, which is a minor discrepancy.
- **Differs on:** Claim identifies the callees as sensor acquisition/FPU/clamp/DTC monitors/EEPROM; blind says subsystem unknown.

### 0x36E60 -- PARTLY_AGREE

- **On record:** Project label "ol_post_correction_select" [TRACED]. Comment: [TRACED] Phase 7 sub-A: selects post-transition correction float based on engine state (0x22CF4). Loads from ROM 0xCC288 or 0xCC284. Writes to FFFF7A38 struct.
- **Blind (observed):** select_calib_float_by_flag_22CF4 -- unknown. The function picks one of two calibration floats from a boolean or mode condition and writes it to two RAM variables, likely an active value and a copy or initial value. What the condition and the constants mean cannot be told from this code.
- **Grader:** The mechanism matches: the routine calls 0x22CF4, selects between the floats at 0xCC288 and 0xCC284, and writes the result to the 0xFFFF7A38 area. The blind answer cannot name the purpose (a post-transition correction) and leaves the purpose unknown.
- **Differs on:** The claim identifies the float as a post-transition correction value chosen by engine state; the blind answer only says a generic calibration float chosen by an unknown flag.

### 0x5AE60 -- PARTLY_AGREE

- **On record:** Project label "post_convergence_handler" [TRACED]. Comment: [TRACED] Wrapper called on ACTIVE->CONVERGED transition. Calls 0x24DE4 (timer utility) then tail-calls 0x2259C (convergence commit).
- **Blind (observed):** call_24DE4_then_tailjump_2259C -- unknown. This is a thin wrapper that runs two other routines back to back, most likely an entry in a periodic or initialisation task list. What it achieves depends on 0x24DE4 and 0x2259C, which are not shown.
- **Grader:** The blind answer reproduces the mechanism exactly: it calls 0x24DE4 and then tail-calls 0x2259C. It cannot name the purpose, which the claim gives as running on the ACTIVE->CONVERGED transition with a timer utility and a convergence commit. Its guess of a periodic or init task list does not match that context.
- **Differs on:** The claim says the wrapper runs post-convergence (ACTIVE->CONVERGED handling with a timer utility and a convergence commit). The blind answer leaves the purpose unknown and guesses a task-list entry.

### 0x04A2C -- PARTLY_AGREE

- **On record:** Project label "frontO2_scaling_init" [TRACED]. Comment: [TRACED] Front O2 sensor scaling initialization/read. Accesses descriptor near 0xAF45C.
- **Blind (inferred):** adc_ch_4042_volts_to_physical_via_table (followed by neighbour adc_ch_4042_range_check) -- Converts one analog sensor's A/D reading to volts (0-5 V full scale) and then to an engineering value through a 1D calibration table, stored as a float at 0xFFFF40B4. The adjacent routine gives the out-of-range high/low classification for the same input channel, as used for circuit-high/circuit-low diagnostics. Which physical sensor this is (e.g. a temperature or pressure input) cannot be told from the code.
- **Grader:** Both describe a routine that scales a sensor reading through the descriptor at 0xAF45C. The blind answer gets the mechanism (ADC volts to a 1D table) but cannot say which sensor it is, while the claim names it as the front O2 sensor.
- **Differs on:** Identity of the sensor: the claim says front O2, while the blind answer says it is an unknown analog sensor (e.g. temperature or pressure).

### 0x4B0FC -- PARTLY_AGREE

- **On record:** Project label "ol_can_comm_dispatch" [TRACED]. Comment: [TRACED] Sub-table B [13]. OL CAN communication dispatch. Checks port status via 0x6334, if bit 15 set: JMP 0x9CFA8 (CAN/OBD-II handler).
- **Blind (observed):** gated_call_9CFA8_if_status_bit15 -- unknown. Structurally it is a gate: when an inhibit/busy byte at 0xFFFF8EDC is clear, it queries a status or request word from 0x6334 (selector 0) and runs the handler at 0x9CFA8 only when the word's MSB flag is set. The meaning of the byte, the word and the handler cannot be told from this code.
- **Grader:** The blind answer reproduces the mechanism exactly: it calls 0x6334, tests bit 15 and tail-jumps to 0x9CFA8. It does not identify the purpose as CAN/OBD-II communication dispatch, and offers that only as a speculative guess.
- **Differs on:** The claim identifies this as CAN communication dispatch to a CAN/OBD-II handler; the blind answer leaves the purpose unknown.

### 0x549FA -- PARTLY_AGREE

- **On record:** Project label "task52_boost_feedback" [TRACED]. Comment: [TRACED] Task [52] Boost feedback/trim. IIR filter on boost error + RPM error. Filter coeff cal[0xD6748]=0.5. Workspace base FFFF8BC4.
- **Blind (inferred):** update_filtered_rpm_and_smoothed_deltas -- Likely a periodic task that keeps a low-pass-filtered engine speed and a smoothed rate of change (delta per call) of that speed. It runs the same smoothed-delta calculation on a second quantity at 0xFFFF8B7C, whose identity is unknown. It also keeps the previous rpm-rate sample at 0xFFFF8BC0, possibly for a second-derivative or 'rate increasing' check elsewhere. Such smoothed rpm-rate values are typically used for transient detection (tip-in/tip-out, decel or rev-hang logic), but the consumer is not shown.
- **Grader:** Both describe IIR filtering that uses the coefficient at cal 0xD6748 and the workspace at FFFF8BC4, and both involve RPM. The claim calls this boost feedback/trim on boost error plus RPM error. The blind answer describes a filtered rpm with smoothed rate-of-change deltas for transient detection and leaves the second quantity unidentified, so it gets the mechanism right but not the boost purpose.
- **Differs on:** The claim says the task is boost feedback/trim filtering boost error. The blind answer says it filters rpm and rpm rate for transient detection, with the second input unidentified rather than named as boost error.

### 0x3EB8C -- PARTLY_AGREE

- **On record:** Project label "overrun_fuel_cutoff" [TRACED]. Comment: [TRACED] Deceleration fuel cut. RPM/airflow thresholds.
- **Blind (observed):** timer_since_flag65BD_clear_latch_7E8C -- A generic elapsed-time or debounce timer. While the condition byte 0xFFFF65BD is zero, a saturating counter runs once per call. Once it reaches the calibration threshold at 0xD29AA, a 'time elapsed' flag at 0xFFFF7E8C is latched to 1. Both counter and flag reset whenever 0xFFFF65BD becomes nonzero. What the condition and the flag mean in engine terms is unknown from this code.
- **Grader:** The blind answer describes a generic delay/debounce timer that latches a flag once a counter passes a calibration threshold, and says it cannot tell the engine meaning. The claim is a decel fuel cut based on RPM/airflow thresholds. The timer could plausibly be a fuel-cut entry delay, but the blind reading shows a time-based threshold rather than RPM/airflow and never identifies the purpose.
- **Differs on:** The claim says the routine is a deceleration fuel cut using RPM/airflow thresholds; the blind answer finds only a time-counter threshold with an unknown purpose.

### 0x4AED4 -- PARTLY_AGREE

- **On record:** Project label "ol_ignition_timing_A" [TRACED]. Comment: [TRACED] Sub-table B [10]. OL ignition timing path A. Gates FFFF8EDC. Calls 0x758DE (base timing), 0x7D526 (knock retard) if FFFF98F6==1. Output chain: 0x232A2→0x3757A→0x3A226.
- **Blind (observed):** gated_subtask_dispatcher_04AED4 -- unknown. Structurally it is a scheduler or dispatch routine that runs a fixed group of subroutines. The group is skipped entirely when 0xFFFF8EDC is non-zero (an inhibit or busy flag). Its later stages run only while 0xFFFF98F6 equals 1 (a mode or state byte). The code shown does not reveal what the callees or flags mean.
- **Grader:** The blind answer reproduces the mechanism exactly: the gate on 0xFFFF8EDC, the call to 0x758DE, the conditional call to 0x7D526 when 98F6==1, and the 232A2→3757A→3A226 chain. It cannot name the purpose, which the claim gives as open-loop ignition timing path A with base timing and knock retard.
- **Differs on:** Purpose: the claim calls it OL ignition timing (base timing plus knock retard); the blind answer says purpose unknown, a generic gated dispatcher.

### 0x5E788 -- PARTLY_AGREE

- **On record:** Project label "diag_monitor_pack_write_36BA" [TRACED]. Comment: [TRACED] uint8_pack -> write to FFFF36BA.
- **Blind (observed):** set_word_FFFF36BA_from_u8_pack -- unknown. It is a setter that turns a byte argument into a 16-bit value with uint8_pack and writes it to the RAM word at 0xFFFF36BA. Nothing shown identifies what that variable stands for.
- **Grader:** Both describe the same mechanism: call uint8_pack and write the result to FFFF36BA. The claim adds a 'diag monitor' purpose, which the blind answer cannot identify.
- **Differs on:** Claim labels it as a diagnostic monitor write; blind answer leaves the purpose unknown.

### 0x9ED4C -- PARTLY_AGREE

- **On record:** Project label "cl_entry_full_init" [TRACED]. Comment: [TRACED] Full CL entry initialization. IRQ-protected (priority 16). Checks FFFF36F4 diagnostic mode, calls 0x72DD4 (DTC handler), walks 6 descriptor table entries via desc_table_walk, sets FFFFAF60 = 90 (countdown). Called from cl_monitor_state_machine.
- **Blind (inferred):** locked_sequence_then_set_AF60_0x5A -- unknown. The structure looks like a protected (probably interrupt-masked) sequence. It conditionally runs one sub-step, always runs three more, then writes the marker byte 0x5A to 0xFFFFAF60, plausibly to record that the sequence has been done. What the sub-steps and the flag mean in engine-control terms cannot be told from this code alone.
- **Grader:** The blind answer matches the mechanism: an IRQ-protected section at priority 16, the 36F4 check, the call to 0x72DD4, a call with count 6 (the descriptor walk), and AF60 set to 90. It cannot name the purpose (closed-loop entry initialization) and reads AF60 as a done marker rather than a countdown.
- **Differs on:** The claim says AF60=90 is a countdown for closed-loop entry initialization; the blind answer calls it a completion marker and leaves the purpose unknown.

### 0x0E4BA -- PARTLY_AGREE

- **On record:** Project label "rtos_task6_fuel_subB" [TRACED]. Comment: [TRACED] RTOS Task 6: fuel sub-group B (20 ms, pri 2). TCB=FFFF11F8. gate(6) -> 0xFE22 (air charge/mass-flow) -> 0x4AA58 (AFL trim-2) -> 0x9A34 (loop integration-2) -> 0x85AC -> 0xD3DC (ATU channel data FFFF44A4) -> epilogue.
- **Blind (observed):** periodic_task_group_E4BA -- unknown. The shape (a fixed list of subroutine calls, small constant arguments, a tail call at the end) fits a scheduler or task-slot body that runs a group of sub-tasks each tick. The constants 6 and 1 look like channel or mode selectors. What the group does cannot be told without analysing the callees.
- **Grader:** The blind answer reproduces the same call sequence (gate(6), 0xFE22, 0x4AA58, 0x9A34, 0x85AC, 0xD3DC, then an epilogue tail call) and guesses it is a task-slot body. It cannot say that the task is fuel sub-group B, nor what the callees do.
- **Differs on:** The claim identifies the function as RTOS Task 6, fuel sub-group B (20 ms), and names what each callee does. The blind answer leaves the purpose unknown.

### 0x0DE38 -- PARTLY_AGREE

- **On record:** Project label "rtos_task3_secondary_dispatch" [TRACED]. Comment: [TRACED] RTOS Task 3: secondary sub-task dispatch (20 ms, pri 2). TCB=FFFF11E0. gate(3) -> secondary_dispatcher(0xF97C) -> epilogue. Parallel to Task 2, allows independent phase offset for same sub-table.
- **Blind (inferred):** task_callback_dispatch_loop_FFFF4548 -- Most likely an RTOS-style task or service loop. It repeatedly asks a kernel or queue routine (0xF97C, op/ID 2) about the control block at 0xFFFF4548. On a zero (ready/success) result it invokes that block's stored handler pointer with a pointer to the block's payload at +4. It keeps going while a continue/pending flag at 0xFFFF4578 is set, then calls a closing or yield routine (0x35A4). What the handler actually does at the engine level is unknown.
- **Grader:** Both describe an RTOS task body that calls a gate with 3, then dispatches through 0xF97C, then runs an epilogue. The blind answer reads it as a generic callback dispatch loop. It does not identify it as Task 3, the secondary sub-task dispatcher (20 ms) parallel to Task 2.
- **Differs on:** The claim gives a specific identity (Task 3 secondary sub-task dispatch, 20 ms, parallel to Task 2); the blind answer stops at a generic task/service loop.

### 0x36070 -- PARTLY_AGREE

- **On record:** Project label "clol_main_transition" [TRACED]. Comment: [TRACED] CL/OL main transition function. Reads IAM vs 0xCC16C, CL->OL throttle and BPW thresholds.
- **Blind (inferred):** compute_max_of_three_sources_ramped_target_798C -- unknown. It is a generic 'target = max of three demand sources (two 1D-scheduled, one rpm/load map blended by x / w), scaled by factor 79A0, with rpm-dependent ramp-up on activation or override modes 1/2'. It may be an enrichment/airflow/torque demand request, but the code does not fix which.
- **Grader:** The blind answer describes the mechanism in detail, including the CC16C > x comparison that matches the claim's 'IAM vs 0xCC16C'. It does not identify the function as the CL/OL transition and says outright that the purpose is unknown.
- **Differs on:** The claim says this is the CL/OL main transition function. The blind answer calls it a generic max-of-three ramped demand target and leaves the purpose unknown.

### 0x71268 -- PARTLY_AGREE

- **On record:** Project label "eeprom_adapt_validate" [TRACED]. Comment: [TRACED] EEPROM validation: reads 5 slots (FFFF2520-253C) via desc_read_int_safe. Returns 0=valid, 1=corrupt.
- **Blind (observed):** any_nonzero_in_block_FFFF2520 -- unknown. Mechanically it is an 'any of these five RAM fields is nonzero' predicate over 0xFFFF2520-0xFFFF253D. It is probably a summary flag (such as 'something pending or active') for a structure of three 8-byte fields followed by two 16-bit fields. What those fields mean cannot be told from this code.
- **Grader:** Both describe a function that checks five slots at FFFF2520-253C and returns 0 or 1. The blind answer gets the mechanism right but cannot name the purpose (EEPROM adaptation validation/corruption check). It reads the result instead as a generic 'any nonzero' flag.
- **Differs on:** Claim says it is EEPROM validation returning 1 for corrupt; blind says an unknown-purpose any-nonzero predicate.

### 0x66626 -- PARTLY_AGREE

- **On record:** Project label "evap_ect_threshold_lookup" [TRACED]. Comment: [TRACED] EVAP ECT-based threshold lookup. Two 1D tables (desc 0xACF64, 0xACF78) compute lower/upper EVAP pressure bounds. Delta/sum stored to FFFF9314/9318.
- **Blind (inferred):** compute_lower_upper_band_around_FFFF318C -- Builds an asymmetric window [Y - A(X), Y + B(X)] around a reference value Y. The two half-widths are scheduled from X through two 1-D tables, and the two limits sit next to each other in RAM (lower at 0xFFFF9314, upper at 0xFFFF9318). This looks like a deadband, hysteresis or tolerance check that some later code tests a measured value against. Which physical quantities X and Y are (for example idle-speed target versus a coolant- or load-based schedule) cannot be told from this code.
- **Grader:** Both describe the same mechanism: two 1D lookups at 0xACF64 and 0xACF78 produce the lower and upper bounds stored at FFFF9314 and FFFF9318. The blind answer cannot say that this is EVAP or that the input is coolant temperature (ECT).
- **Differs on:** The claim identifies the bounds as EVAP pressure bounds indexed by ECT; the blind answer leaves the subsystem and the physical quantities unknown.

### 0x31A4C -- PARTLY_AGREE

- **On record:** Project label "fuel_trim_init_B" [TRACED]. Comment: [TRACED] Writes FFFF7464, checks cal IDs.
- **Blind (observed):** clear_ram7464_if_check_22F92_true -- unknown. Structurally this clears or resets a byte flag or state at 0xFFFF7464 whenever the condition reported by the routine at 0x22F92 is true (returns 1). What that condition or flag means cannot be determined from this listing.
- **Grader:** The blind answer confirms the write to FFFF7464 and finds the cal-ID comparisons, though it places them in a neighbouring routine. It cannot name a purpose, so it does not support the fuel-trim-init identity.
- **Differs on:** Claim calls it fuel trim init. The blind answer leaves the purpose unknown and puts the cal ID check in a separate adjacent routine.

### 0x0E3B2 -- PARTLY_AGREE

- **On record:** Project label "rtos_task8_atu_hw" [TRACED]. Comment: [TRACED] RTOS Task 8: ATU hardware interface (20 ms, pri 2). TCB=FFFF1208. gate(8) -> 0xCFB0 (ATU setup FFFF447C/FFFF4488) -> 0x5A20 -> 0xC5FC -> 0x56F4 -> 0x70BA -> 0x48E16 (OL-gated ATU channels, checks FFFF8EDC) -> epilogue, BRA 0xEF3E.
- **Blind (inferred):** sched_task_slot8_run_subtasks -- Most likely a scheduler task body: a fixed list of subsystem routines run together, bracketed by a call taking the constant 8 (possibly a task or slot ID passed to a timing, bookkeeping or 'task begin' helper) and a tail call to a common routine at 0x35A4 (possibly 'task end' or post-processing, since the next stub also ends in it). What the subsystems are cannot be told from this code.
- **Grader:** The blind answer correctly identifies an RTOS task body for slot 8 that gates on 8 and then calls the same six routines in the same order. It cannot name the ATU hardware-interface purpose, and its epilogue tail-call target (0x35A4) differs from the claim's BRA 0xEF3E.
- **Differs on:** Claim identifies the task as the ATU hardware interface (20 ms, pri 2); the blind answer says the subsystems cannot be determined.

### 0x3FA8C -- PARTLY_AGREE

- **On record:** Project label "warmup_state_init" [TRACED]. Comment: [TRACED] Embedded sub: initializes warmup state struct.
- **Blind (inferred):** init_block_7EC0_with_ect_table_value -- Most likely a one-shot initializer or reset routine for the state block at 0xFFFF7EC0-0xFFFF7EFF. It writes fixed defaults to several float variables and 0xFFFF/0xFF markers to word and byte variables, which look like 'not yet set' sentinels or counters. It seeds one variable (0xFFFF7EE4) from an ECT-indexed 1D table, presumably a coolant-temperature-dependent starting value. Which subsystem owns this block cannot be told from this code.
- **Grader:** The blind answer correctly identifies the routine as an initializer for a state struct, seeded with an ECT-dependent value. It does not identify the warmup subsystem and says outright that the owning subsystem is unknown.
- **Differs on:** The claim says the struct is the warmup state; the blind answer leaves the owner unidentified.

### 0x461D2 -- PARTLY_AGREE

- **On record:** Project label "task22_knock_percyl" [TRACED]. Comment: [TRACED] Task [22] Knock per-cyl config. Cyl index (0xFFFF8298L), sets GBR
- **Blind (inferred):** calc_rpm_load_zone_index_7x5_with_hysteresis -- Picks the cell of a 7 (RPM) x 5 (load) grid the engine is currently in, with downward hysteresis on both axes. Some per-zone feature (likely a learning or correction map) can then index by this value. Which subsystem consumes the zone byte is not shown. A guess is the fine knock-learning or similar learned-correction zones, which in Subaru ROMs use separate RPM and load range breakpoint tables.
- **Grader:** Both tie the function to knock-related state at 0xFFFF8298 via GBR, and the blind answer tentatively guesses knock learning. The blind answer, however, finds that the stored byte is an RPM×load zone index with hysteresis, not a per-cylinder index.
- **Differs on:** Claim says 0xFFFF8298 is a cylinder index for per-cyl knock config; blind says it is a 7x5 RPM/load zone index (0..34).

### 0x36F76 -- PARTLY_AGREE

- **On record:** Project label "ol_transition_completion_check" [TRACED]. Comment: [TRACED] Phase 7 sub-C: OL-to-CL transition completion detector. GBR=FFFF7A24. Computes MAF*BPW correction via table_2d_lookup (descriptors 0xAD9EC/0xADA08). Counts consecutive cycles where correction is within/outside bounds (thresholds at 0xCBBF3/0xCBBF4). Sets FFFF7454 flag when transition complete.
- **Blind (observed):** update_debounced_flag_vs_rpm_table_threshold -- Maintains a debounced on/off state flag at 0xFFFF7A28. It latches on when the RAM quantity at 0xFFFF6400 stays at or above a threshold from an rpm-indexed table (one of two tables, chosen by the mode returned from 0x22CF4) for 0xCBBF3 consecutive calls. It latches off only after that quantity stays below the threshold for 0xCBBF4 calls while coolant is below 0xCC25C. What physical quantity or feature this is cannot be told from this code, so the specific purpose is unknown.
- **Grader:** Both describe the same structure: GBR=FFFF7A24, a 2D lookup from 0xAD9EC/0xADA08, and consecutive-cycle counters checked against 0xCBBF3/0xCBBF4 that set or clear a flag. The blind reader cannot name the purpose (an OL-to-CL transition detector) and treats the table output as a comparison threshold rather than a MAF*BPW correction.
- **Differs on:** The claim says the flag set is FFFF7454 and calls the lookup a MAF*BPW correction. The blind answer says the flag is at 0xFFFF7A28 (GBR+4) and that the table output is an rpm-indexed threshold compared with 0xFFFF6400.

### 0x44188 -- PARTLY_AGREE

- **On record:** Project label "task00_timing_percyl" [TRACED]. Comment: [TRACED] Task [0] Per-cylinder timing comp. RPM+MAF, cal Timing Comp Max RPM/Min Load/Min ECT
- **Blind (inferred):** calc_4x_rpm_load_comp_low_rpm_high_load_warm -- Produces four parallel rpm-by-load-scheduled values that are active only at low rpm, higher load and a warmed-up engine, and zero otherwise. The EJ257 has four cylinders, so these could plausibly be per-cylinder corrections (fuel or timing), but nothing in this code shows which. The exact quantity is unknown.
- **Grader:** The blind answer matches the mechanism: rpm/load lookups gated by max RPM, min load and min ECT calibrations, with four per-cylinder-like outputs. It suggests per-cylinder correction but cannot say whether the outputs are timing or fuel, so it is vaguer than the claim.
- **Differs on:** The claim identifies the outputs as per-cylinder timing compensation; the blind answer leaves the quantity unknown (fuel or timing).

### 0x30ACC -- PARTLY_AGREE

- **On record:** Project label "base_fuel_map_combiner" [TRACED]. Comment: [TRACED] 2D map + descriptors to FFFF73AC base fuel.
- **Blind (observed):** calc_ect_load_blended_map_plus_gated_ect_adder -- The function computes a correction indexed by coolant temperature and engine load. It cross-fades between two ECT x load maps using a weight f (0xFFFF90A8), which is presumably kept between 0 and 1. It then adds an ECT-only term that applies only when the condition from 0x023E48 is true. The result goes to 0xFFFF73A4, with its two parts kept at 0xFFFF73A8 (blend) and 0xFFFF73AC (adder). Which engine quantity it corrects (timing, fuel, idle or similar) cannot be told from this code.
- **Grader:** Both describe a function that combines 2D maps into a result in the FFFF73Ax area. The blind answer cannot say it is fuel, and it places the 2D map blend at 0xFFFF73A8/73A4 rather than at 0xFFFF73AC.
- **Differs on:** The claim says the 2D map result goes to FFFF73AC as base fuel. The blind answer says FFFF73AC holds only a gated 1D ECT adder (or 0), with the blended 2D maps stored at 73A8 and the sum at 73A4, and it does not identify the quantity as fuel.

### 0x467AE -- PARTLY_AGREE

- **On record:** Project label "task21_knock_win_upd" [TRACED]. Comment: [TRACED] Task [21] Knock window per-cyl update. MAF+cyl index, sets GBR
- **Blind (inferred):** update_rpm_load_conditions_and_combine_enable_flag_829E -- Most likely the evaluation routine for one feature or diagnostic's enable conditions. The subroutine called with rpm and load probably works out some of the per-condition flags, and this function ANDs four of them into one master 'conditions met' flag at 0xFFFF829E. Which feature or monitor this is cannot be told from this code.
- **Grader:** Both describe a task that sets GBR and works on load and rpm inputs. The claim names it a per-cylinder knock window update using MAF plus a cylinder index. The blind answer sees an rpm/load-driven combination of enable conditions into one flag and cannot name the feature, with no knock or per-cylinder identification.
- **Differs on:** Claim: knock window per-cylinder update using MAF and cylinder index. Blind: an AND of four condition flags into a master enable flag at 0xFFFF829E, with the feature unidentified.

### 0x419BA -- PARTLY_AGREE

- **On record:** Project label "task37_timing_multiaxis" [TRACED]. Comment: [TRACED] Task [37] Timing multi-axis. RPM+MAF, 3 cal params, 3 BSR calls
- **Blind (observed):** dispatch_041A02_041A48_041A7E_041BE4 -- unknown. It is a wrapper that runs four related sub-tasks in a fixed order, most likely one periodic task or one subsystem's update split into stages. The four callees, which are all close together around 0x041A00-0x041BE4, would have to be analysed to say which subsystem.
- **Grader:** The blind answer matches the mechanism, a dispatcher making three BSR calls plus a tail call, but it cannot name the purpose. The claim identifies the task as ignition-timing multi-axis work using RPM and MAF, and the blind answer says that is unknown.
- **Differs on:** The claim says this is task 37 timing multi-axis using RPM, MAF and 3 cal params. The blind answer reports no data access of its own and an unknown subsystem.

### 0x0CB88 -- PARTLY_AGREE

- **On record:** Project label "timer_channel_bg_reload" [TRACED]. Comment: [TRACED] Task 0 call_09. Calls sub 0xCC80 4x with (R4,R5) pairs (0,0xA4)/(0,0xA8)/(1,0xA4)/(1,0xA8). Timer reload.
- **Blind (observed):** init_clear_A4_A8_for_units_0_1 -- Unknown. The structure looks like initialisation or reset: the same pair of offsets or IDs (0xA4, 0xA8) is set to value 0 for two instances or channels (index 0 and 1). The meaning of 0xA4/0xA8 and what 0x00CC80 writes to cannot be determined from this listing.
- **Grader:** Both describe the same four calls to 0xCC80 with the same (R4,R5) pairs. The claim names the purpose as a timer channel reload. The blind answer leaves the purpose unknown and only guesses at per-channel initialisation or reset.
- **Differs on:** Claim identifies the function as a timer reload; blind answer cannot name the purpose beyond generic init/clear of 0xA4/0xA8 for units 0/1.

### 0x5CC9A -- PARTLY_AGREE

- **On record:** Project label "sensor_diag_helper" [TRACED]. Comment: [TRACED] 20 calls. Sensor diagnostic utility. Called from O2 sensor, boost, and idle contexts.
- **Blind (observed):** latch_byte_8EF6_from_8ECC -- unknown. The structure is a sample-and-hold or freeze of a byte variable under a condition. What the two RAM bytes mean cannot be told from this code.
- **Grader:** The claim calls this a sensor diagnostic utility used from O2, boost and idle contexts. The blind answer describes a conditional sample-and-hold of one RAM byte into another, which is a plausible helper mechanism, but it cannot name a diagnostic or sensor purpose. The blind answer is vaguer than the claim without contradicting it.
- **Differs on:** The claim says it is a sensor diagnostic utility; the blind answer finds only a generic byte latch with unknown purpose.

### 0x332A2 -- PARTLY_AGREE

- **On record:** Project label "fuel_main_entry" [TRACED]. Comment: [TRACED] Main fueling entry (non-returning). Dispatched from fuel_dispatch_table_B.
- **Blind (inferred):** reset_state_block_77BC_if_flag -- Event-triggered reset/initialisation of one subsystem's state. Several floats go to a neutral 1.0 (they look like multipliers/ratios), several floats and flags/counters are cleared to 0, and a reference byte is latched from 0xFFFF8E7E. It runs when the predicate at 0x22F92 returns 1, plausibly an init or reset request. What the subsystem is cannot be told from this code, so the specific purpose is unknown.
- **Grader:** The claim calls this the main fueling entry routine. The blind answer describes a conditional reset of a state block (multipliers set to 1.0, other values cleared) and does not identify the subsystem. A fuel main entry could plausibly start with such an init, but the blind answer does not reach the fueling identity and is vaguer than the claim.
- **Differs on:** Claim identifies the routine as the main fueling entry; blind answer sees only a generic conditional state-block reset with the subsystem unknown.

### 0x04BCA -- PARTLY_AGREE

- **On record:** Project label "charge_validation_check" [TRACED]. Comment: [TRACED] Sub-table B [03b]. OL charge validation. Reads FFFF2058, loads ROM 0xC0064 cal, calls BDBCC + BDB6E.
- **Blind (inferred):** init_state_FFFF2050_FFFF2058 -- Probably an initialisation or reset routine for two adjacent RAM objects. The object at 0xFFFF2050 is set up from a fixed ROM float constant, and the object at 0xFFFF2058 is set up or cleared with an integer 0. What these objects are (for example a filter, timer or ramp state) cannot be told without the two callees or the value at 0x000C0064. The specific purpose is unknown.
- **Grader:** Both describe the same mechanics: FFFF2058, the ROM 0xC0064 constant and calls to BDBCC and BDB6E. The claim names the purpose as overload charge validation, while the blind answer calls it an init/reset of two RAM objects and says the purpose is unknown.
- **Differs on:** Claim says OL charge validation; blind says probable initialisation/reset of state objects, purpose unknown.

### 0x58902 -- PARTLY_AGREE

- **On record:** Project label "frontO2_scaling_lookup" [TRACED]. Comment: [TRACED] Front O2 sensor scaling table lookup. Accesses descriptor near 0xAF468.
- **Blind (observed):** update_FFFF8DE4_from_table_AF468 -- unknown. It is a single-axis calibration-table lookup: the output 0xFFFF8DE4 is a function of the input 0xFFFF40E0 through the table at 0xAF468. Neither the input variable, the table nor the output is identified, so the physical meaning cannot be told from this code.
- **Grader:** The blind answer correctly identifies a 1D table lookup through the descriptor at 0xAF468, which matches the claim's mechanism. It cannot name the purpose, while the claim says it is front O2 sensor scaling.
- **Differs on:** Claim identifies the table as front O2 sensor scaling; blind answer leaves the physical meaning unknown.

### 0x84A28 -- PARTLY_AGREE

- **On record:** Project label "percyl_engine_status_gate" [TRACED]. Comment: [TRACED] Stage 5: Call check_engine_status (0x3AB20), store result + fuel_state_byte to output at FFFFA52D.
- **Blind (observed):** latch_3AB20_result_and_7C9D_into_A52D_block -- unknown. It looks like a small periodic task that copies two byte-wide status or flag values into a RAM record at 0xFFFFA52D. Byte +2 gets the result of 0x3AB20 and byte +0 gets a copy of the 0xFFFF7C9D byte. What those values mean cannot be told from this code.
- **Grader:** Both describe the same mechanism: call 0x3AB20, then store its result and a second state byte into the output block at FFFFA52D. The blind answer cannot identify the purpose (engine status check, fuel state byte) or the per-cylinder gate role that the claim gives.
- **Differs on:** Claim names 0x3AB20 as check_engine_status and 7C9D as fuel_state_byte; blind leaves the meaning of these values unknown.

### 0x4AFC4 -- PARTLY_AGREE

- **On record:** Project label "ol_sensor_processing" [TRACED]. Comment: [TRACED] Sub-table B [12]. OL sensor processing. Gates FFFF8EDC. Calls 0x2262C, 0x1D2FC, 0x57018, tail-calls 0x4B1C4.
- **Blind (observed):** RunSubtasksIfFlag8EDCClear -- Unknown in detail. Structurally this is a scheduler or task-list wrapper: it runs a group of four routines (three calls plus the tail call to 0x04B1C4) only while the byte flag at 0xFFFF8EDC is zero. The flag acts as an enable/inhibit gate, possibly a mode, initialisation or suspend state. Its meaning and the callees' roles cannot be told from this code.
- **Grader:** The blind answer matches the mechanism exactly: the gate on FFFF8EDC, the same three calls and the tail-call to 0x4B1C4. It could not identify the purpose, whereas the claim says this is OL sensor processing.
- **Differs on:** The claim identifies the function as open-loop sensor processing; the blind answer leaves the purpose as an unknown flag-gated task group.

### 0x459F6 -- PARTLY_AGREE

- **On record:** Project label "task20_knock_win_upd" [TRACED]. Comment: [TRACED] Task [20] Knock window per-cyl update. IAM+MAF, sets GBR
- **Blind (hunch):** calc_load_indexed_scaled_sum_with_optional_2d_term -- Combines a scaled base value with an optional, scaled 2D-map term indexed by engine load and a second variable. The pattern is consistent with a Subaru ignition-timing build-up: base x factor + knock-advance map(load, RPM) x IAM-style multiplier [0xFFFF8200], enabled by a calibration flag. This is not confirmed by the code.
- **Grader:** Both place the routine in knock/ignition control and both involve an IAM-style multiplier. The claim says it is a per-cylinder knock window update using IAM and MAF that sets GBR. The blind answer describes a load-indexed timing build-up, base × factor plus a knock-advance map × IAM, and mentions neither a knock window, per-cylinder handling, nor GBR.
- **Differs on:** The claim identifies a per-cylinder knock window update that sets GBR. The blind answer describes an ignition-timing sum of a base term and an optional knock map × IAM term.

### 0x717B2 -- PARTLY_AGREE

- **On record:** Project label "eeprom_maturation_check" [TRACED]. Comment: [TRACED] EEPROM maturation counter: increments FFFF979D if state matches expected, else resets to 0xFF.
- **Blind (inferred):** program_flow_checkpoint_advance -- Most likely a program-flow (execution-order) monitor. Each checkpoint in a sequence calls this with its expected step index. The counter advances only if the checkpoints run in order; any out-of-order call latches it to 0xFF. The neighbouring routine then checks once per cycle that exactly 25 checkpoints ran in order. It sets an error flag at 0xFFFF9795 if not, and restarts the sequence.
- **Grader:** Both describe the same mechanism: the counter at FFFF979D increments when it matches the expected value and is otherwise set to 0xFF. They differ on purpose. The claim calls it EEPROM maturation, while the blind answer calls it a program-flow checkpoint monitor.
- **Differs on:** Purpose: EEPROM maturation counter vs program-flow/execution-order checkpoint monitor.

### 0x067DC -- PARTLY_AGREE

- **On record:** Project label "io_sched_event_atomic_2" [TRACED]. Comment: [TRACED] 21 calls. Variant of io_sched_event_atomic with different event type.
- **Blind (hunch):** periph_channel_op_then_masked_reg_write_F76C -- unknown. Most likely a shutdown or reconfigure step for a hardware channel: two per-channel helper calls, then an interrupt-protected update of an on-chip peripheral register at 0xFFFFF76C, probably an I/O-port or pin-function register. The (4, 0) arguments could mean clearing bit 4, or writing 0 into a field. That reading is not verified.
- **Grader:** Both descriptions see an interrupt-protected (atomic) operation on an I/O peripheral. The blind answer gets that mechanism, but it cannot name the purpose as I/O event scheduling, and it does not tie the r5=2 argument to an event type.
- **Differs on:** The claim calls it scheduling an I/O event of a specific type; the blind answer calls it a generic channel shutdown/reconfigure plus a masked write to the register at 0xFFFFF76C, with purpose unknown.

### 0x549D4 -- PARTLY_AGREE

- **On record:** Project label "boost_ign_switch_filter" [TRACED]. Comment: [TRACED] Boost ignition switch EMA filter. Reads FFFF4130, writes FFFF8B9C workspace.
- **Blind (observed):** max_of_current_and_previous_4130 -- A two-sample peak hold on whatever signal lives at 0xFFFF4130. The output follows rises at once but drops one call late, so a single-sample dip is ignored. What the signal is cannot be told from this code, so its physical meaning is unknown.
- **Grader:** Both agree that the function reads FFFF4130, filters it and writes FFFF8B9C. The claim calls it an EMA filter on the boost ignition switch. The blind answer finds a two-sample max (peak hold), which contradicts EMA as the mechanism, and it cannot name the signal.
- **Differs on:** The claim says EMA filter; the blind answer says max of the current and previous sample (peak hold). The blind answer also does not identify the signal as the boost ignition switch.

### 0x3B7C4 -- PARTLY_AGREE

- **On record:** Project label "torque_request_decel_gate" [TRACED]. Comment: [TRACED] Torque request decel counter. Checks FFFF65BD (decel flag), manages counter at FFFF7CBC. Tail-calls 0x3D2FC.
- **Blind (observed):** debounce_flag_7CBC_when_65BD_clear -- A persistence (debounce) filter. Flag 0xFFFF7CBC is set only after the input 0xFFFF65BD has been zero on at least 2 consecutive executions, and any non-zero input resets it at once. What condition 0xFFFF65BD represents, and what the flag gates, is unknown. The tail-jump suggests this is one step in a chain of periodic task routines.
- **Grader:** Both describe a routine that checks FFFF65BD, manages a counter and flag at FFFF7CBC and tail-calls 0x3D2FC. The blind answer gets the debounce mechanism right but cannot say that 65BD is a decel flag or that this relates to torque request.
- **Differs on:** The claim identifies FFFF65BD as a decel flag in a torque request context; the blind answer leaves its meaning unknown.

### 0x5CA32 -- PARTLY_AGREE

- **On record:** Project label "cl_reentry_handler" [TRACED]. Comment: [TRACED] Writes uint8_pack(1) to FFFF3692 on forced CL re-entry. Called from cl_monitor_state_machine when R4=1.
- **Blind (observed):** set_FFFF3692_from_uint8_pack_1 -- unknown. It is a small wrapper or init step that writes one fixed result of uint8_pack(1) into the word variable at 0xFFFF3692. What that variable means, and what packing uint8_pack does, cannot be told from this code.
- **Grader:** The blind answer gets the same mechanism, writing uint8_pack(1) to FFFF3692. It cannot name the purpose, which the claim gives as forced closed-loop re-entry handling called from cl_monitor_state_machine.
- **Differs on:** The claim says this is the forced CL re-entry handler. The blind answer gives the purpose as unknown.

### 0x486EE -- PARTLY_AGREE

- **On record:** Project label "clol_background_dispatch" [TRACED]. Comment: [TRACED] Task 0 call_28. CL/OL BACKGROUND MAINTENANCE hub. Clears FFFF8323, calls 10 subs: 0x588FE, 0x1CB68, 0x1CF0C, 0x261A8, 0x5CBC8, 0x98482, 0xA9914, 0x3D7F0, 0x47138, tail-call 0x587FC. AFL consolidation, FLKC updates, adaptive fuel trim persistence.
- **Blind (observed):** task_clear_flag8323_and_run_subtasks -- A scheduler or dispatcher routine. It clears a byte flag or status, then runs a fixed list of periodic subsystem routines, with the last one reached by a tail call. What the subsystems are, and what 0xFFFF8323 means, cannot be told from this code.
- **Grader:** The blind answer matches the mechanism exactly: it clears 0xFFFF8323, makes the same sequence of calls and ends with a tail call to 0x587FC. It does not identify the purpose as closed-loop/open-loop background maintenance (AFL, FLKC, fuel trim) and only calls it a generic dispatcher.
- **Differs on:** The claim identifies the purpose as CL/OL background maintenance (AFL consolidation, FLKC updates, fuel trim persistence); the blind answer says the subsystem purpose is unknown.

### 0x40918 -- PARTLY_AGREE

- **On record:** Project label "task33_timing_ws_init" [TRACED]. Comment: [TRACED] Task [33] Timing workspace init. Multi-GBR-write, 3 BSR calls
- **Blind (observed):** sub_040918_call_sequence_4 -- unknown. It is a sequencer or dispatcher that runs four neighbouring routines in order, most likely the sub-steps of one engine-control subsystem's periodic update, but which subsystem cannot be told without analysing the callees.
- **Grader:** Both describe a routine that makes three BSR calls, but the blind reader could not name its purpose as timing-workspace init. The blind reader also says the function does no writes of its own, whereas the claim cites multiple GBR writes, which may happen inside the callees.
- **Differs on:** Claim says multi-GBR-write timing workspace init; blind says it stores nothing itself and its purpose is unknown.

### 0x0FC88 -- PARTLY_AGREE

- **On record:** Project label "hw_port_init_background" [TRACED]. Comment: [TRACED] Task 0 call_01. HW port refresh: finalize_set_mode(R4=1), struct_init(224), io_port_read/write port 20.
- **Blind (observed):** set_bit3_of_reg_index20_locked -- unknown. This is a locked set of flag bit 3 in an indexed byte register or shadow (index 20) that the 0x6BC4/0x6BF0 accessors manage. It is preceded by a call to 0x00FBBA(1). It could be enabling or requesting something in a peripheral or driver-state byte, but what index 20 bit 3 means cannot be determined from this code.
- **Grader:** Both describe the same sequence: a call with R4=1, a call taking 224 (0xE0), and a read then write of port/index 20. The blind answer gives the mechanism (setting bit 3) but leaves the purpose unknown, and it reads the 224 call differently from the claim.
- **Differs on:** The claim calls the 224 call struct_init(224); the blind answer reads it as critical_section_enter with a 0xE0 mask level, and it does not identify this as a hardware port refresh.

### 0x31C9C -- PARTLY_AGREE

- **On record:** Project label "fuel_percyl_array_init" [TRACED]. Comment: [TRACED] Zeros 3x42 floats per-cylinder init.
- **Blind (inferred):** conditional_reset_float_arrays_and_state_7700 -- Re-initialises one RAM block of a subsystem: three float arrays (42/42/41 entries) are reset to 0.0, several scale/factor floats are reset to 1.0, and a state byte is reseeded from 0xFFFF94B3. This is done only when the predicate at 0x22F92 returns 1, most plausibly a reset, init or 'conditions changed' request. The subsystem itself (learning/adaptation, filter history or other) cannot be identified from this code.
- **Grader:** Both describe zeroing three float arrays of about 42 entries as an init or reset. The blind answer matches the mechanism but cannot name the subsystem, so it does not confirm the per-cylinder fuel identity. It also counts the third array as 41 floats, not 42.
- **Differs on:** The claim identifies the arrays as per-cylinder fuel data; the blind answer says the subsystem cannot be identified.

### 0x3452A -- PARTLY_AGREE

- **On record:** Project label "afl_core_entry" [TRACED]. Comment: [TRACED] AFL core entry. Calls: airflow range -> CL check -> range select -> value update -> store -> max check -> transition.
- **Blind (observed):** subsystem_7874_update_task (input snapshot + sub-step dispatcher) -- Top-level periodic routine for one control subsystem whose working variables live at 0xFFFF7874–0xFFFF78A6. It takes a consistent snapshot of its inputs (coolant temp, intake air temp, two more floats, a word, one state byte with its previous value, and the result of helper 0x22F92). It then runs its computation sub-steps in a fixed order. Which subsystem this is cannot be determined from this code alone; that part is unknown.
- **Grader:** Both describe a top-level entry routine that dispatches a fixed sequence of sub-steps for one subsystem. The blind answer cannot name the subsystem as AFL (air-fuel learning) or identify the individual steps.
- **Differs on:** The claim says this is the AFL core entry, running airflow range, CL check, range select and the steps after; the blind answer leaves the subsystem unknown.

### 0x0E774 -- PARTLY_AGREE

- **On record:** Project label "sched_isr_common_entry" [TRACED]. Comment: [TRACED] Every ISR stub in the 0x00E9xx family bra's here with r4 = its event id (80, 84, 90, 92 seen). Raises SR to IMASK=15 (or #240) before posting. SUPERSEDES the earlier \"ADC_StateMachine\" label (item 90).
- **Blind (inferred):** critical_section_call_10800_mask4000 -- Likely a small atomic wrapper: with interrupts disabled, it runs helper 0x10800 on constant 0x4000 (perhaps a bit mask, an ID or a size) and the caller's argument. It then hands off to 0xFBA4, which probably re-enables or restores interrupts and finishes the operation. The exact meaning of 0x4000 and of the two callees is unknown from this listing.
- **Grader:** Both describe raising IMASK to 15 and then handing the incoming r4 argument to a helper. The blind answer reads this as a generic atomic wrapper and does not see it as the shared ISR entry that posts an event id from the 0x00E9xx stubs.
- **Differs on:** The claim says this is the common ISR entry where r4 is the event id being posted. The blind answer calls it a generic critical-section wrapper around 0x10800 with an argument of unknown meaning.

### 0x455E6 -- PARTLY_AGREE

- **On record:** Project label "task04_knock_thresh" [TRACED]. Comment: [TRACED] Task [4] Knock sensitivity config. MAF, cal 0xD2E9C-D2EB0, sets GBR
- **Blind (observed):** update_rpm_window_hysteresis_and_inhibit_flag -- Unknown which subsystem. Structurally it is an enable/inhibit condition: GBR+62 = 1 means 'conditions not met', and 0 means 'all conditions met'. The conditions are an rpm window with hysteresis on both edges, a range check on a second float, a mode/fault byte not equal to 1, and a counter or timer at or above a calibrated minimum. This pattern is typical of diagnostic-monitor enable or a feature-inhibit flag, but the code does not show which.
- **Grader:** Both describe the same routine, which sets GBR and uses the calibrations at 0xD2E9C–D2EB0. The blind reader works out the mechanism (rpm hysteresis window, a range check on a second float that could be MAF, and an inhibit flag) but cannot name the subsystem, while the claim calls it knock sensitivity configuration.
- **Differs on:** The claim identifies the routine as knock sensitivity/threshold configuration. The blind answer describes a generic enable/inhibit condition flag of unknown subsystem and never mentions knock.

### 0x54A5A -- PARTLY_AGREE

- **On record:** Project label "boost_feedback_reset" [TRACED]. Comment: [TRACED] Boost feedback workspace reset. Calls 0x22F92 (engine state check). Zeros 9 workspace fields on state change.
- **Blind (inferred):** clear_float_states_8B50_8BC4_if_cond -- Most likely a reset or initialisation routine. It clears a block of float accumulators or filter states (nine floats in 0xFFFF8B50-0xFFFF8BC4) when a condition reported by 0x22F92 is active, for example a reset request or an operating-mode change. Which subsystem owns these variables cannot be told from this code.
- **Grader:** Both describe the same mechanism: call 0x22F92 and, on a condition, zero nine workspace fields. The blind answer cannot name the boost feedback subsystem.
- **Differs on:** Claim identifies the fields as boost feedback workspace; blind answer says the owning subsystem is unknown.

### 0x6F260 -- BLIND_ABSTAINED

- **On record:** Project label "task58_maf_diag_part3" [TRACED]. Comment: [TRACED] MAF diag part 3: hardware fault line checks.
- **Blind (observed):** call_sub_06F26A_then_tailjump_06F322 -- unknown. It is a small sequencing wrapper that runs two routines back to back, likely part of a task or scheduler step. What it achieves depends on the bodies of 0x06F26A and 0x06F322, and neither is shown.
- **Grader:** The blind answer describes only a call-then-tail-jump wrapper and gives the purpose as unknown. It offers nothing about MAF diagnostics or fault line checks that could be compared with the claim.
- **Differs on:** none

### 0x40516 -- BLIND_ABSTAINED

- **On record:** Project label "task34_timing_throttle" [TRACED]. Comment: [TRACED] Task [34] Timing throttle comp. Throttle+MAF voltage+injector
- **Blind (observed):** clear_byte_FFFF7F82_then_enter_body -- unknown. The visible code only clears a RAM byte flag or state at 0xFFFF7F82 and then enters a larger routine whose body lies past the listing. Clearing a status or enable byte before running a periodic or initialisation routine fits the shape, but it is not supported by the code shown.
- **Grader:** The blind answer describes only an entry stub that clears a RAM byte and explicitly says the purpose is unknown. That gives nothing to test against the timing throttle compensation claim.
- **Differs on:** none

### 0x38E30 -- BLIND_ABSTAINED

- **On record:** Project label "ltft_learning_algorithm" [TRACED]. Comment: [TRACED] LTFT learning algorithm. RPM threshold 3600.
- **Blind (observed):** set_bits_7_5_3_in_flag_bytes_FFFF7B9F_7BA0 -- unknown. It looks like an initialisation or 'force all' step that raises three flags in each of two adjacent RAM flag/status bytes, between two helper calls. What the flags mean cannot be told from this code.
- **Grader:** The blind answer gives the mechanism (it sets flag bits in two RAM bytes between helper calls) but says the purpose is unknown. It makes no link to LTFT learning or to an RPM threshold, so there is no functional identity to compare against the claim.
- **Differs on:** none

### 0x66580 -- BLIND_ABSTAINED

- **On record:** Project label "task56_evap_purge" [TRACED]. Comment: [TRACED] Task 56: EVAP purge system diagnostic.
- **Blind (observed):** cond_tailcall_66C40_if_state_1or2 -- Unknown. Structurally it is a gate: it runs the routine at 0x066C40 only when a state or mode byte returned by 0x582AC is 1 or 2. What that state is, and what 0x066C40 does, cannot be told from this listing.
- **Grader:** The blind answer describes only a generic gate mechanism and says outright that its purpose is unknown. It offers nothing about EVAP or purge diagnostics to compare against the claim.
- **Differs on:** none

### 0x3CD34 -- BLIND_ABSTAINED

- **On record:** Project label "warmup_coldstart_enrichment" [TRACED]. Comment: [TRACED] ECT/IAT indexed warmup enrichment.
- **Blind (observed):** task_seq_03CD34_run4 -- unknown. It is most likely a scheduler entry that runs one subsystem's update routines in a fixed order. Which subsystem cannot be told without the callee bodies.
- **Grader:** The blind answer describes only a call wrapper and says the purpose is unknown. It never names a subsystem, so it offers nothing to test against the warmup enrichment claim.
- **Differs on:** none

### 0x357D0 -- BLIND_ABSTAINED

- **On record:** Project label "clol_transition_sub_B" [TRACED]. Comment: [TRACED] CL/OL transition sub B. Dispatched from fuel_dispatch_table_A.
- **Blind (observed):** init_flags_7986_794C_after_35E88 -- unknown. Writing fixed constants after a sub-call looks like an initialisation or reset routine: an all-ones byte marker or sentinel at 0xFFFF7986 and a starting value of 512 at 0xFFFF794C. What those variables represent cannot be told from this code.
- **Grader:** The blind answer gives a detailed mechanism but says the purpose is unknown, offering only a generic 'init routine' guess. It never connects the function to the CL/OL transition or to fuel, so nothing can be tested against the claim's identity.
- **Differs on:** none

### 0x43464 -- BLIND_ABSTAINED

- **On record:** Project label "task47_ign_timing_lowpw" [TRACED]. Comment: [TRACED] IGNITION timing low-PW deactivation + map switch. Gate logic for timing comp. NOT fuel injection.
- **Blind (observed):** call_sub_04346E_then_tailcall_0434F2 -- unknown. It sequences two neighbouring routines, which looks like a scheduler-task or dispatcher entry that runs two related sub-steps. What those steps compute cannot be told from this listing.
- **Grader:** The blind answer describes only a wrapper structure that calls two subroutines and says its purpose is unknown. It gives nothing to test against the claim of ignition timing low-PW deactivation and map switching.
- **Differs on:** none

### 0x1FE54 -- BLIND_ABSTAINED

- **On record:** Project label "frontO2_comp_atm" [TRACED]. Comment: [TRACED] Front O2 atmospheric compensation sub-function. Accesses descriptor at 0xAAE78.
- **Blind (observed):** calc_rpm_iat_gated_ratio_model_6430 -- unknown. A modelled quantity is built from an averaged input, IAT, RPM and 0xFFFF69F4. It is capped, scaled per RPM and per 0xFFFF679C, lag-filtered and multiplied by an RPM/load-blended table. The result becomes a ratio to a linear function of 0xFFFF620C, clamped to >=1. Enabling uses ECT/RPM thresholds with latch and counter hysteresis. Hunch only: a per-revolution or ratio-type correction or enrichment model. The code alone cannot identify it.
- **Grader:** The claim calls this a front O2 atmospheric compensation sub-function that accesses descriptor 0xAAE78. The blind answer notes the 0xAAE78 table access but gives the purpose as unknown, offering only a vague hunch about a ratio or enrichment correction model. It never mentions O2 or atmospheric compensation, so there is no proposed identity to test against the claim.
- **Differs on:** Blind purpose is unknown, a hunch about a ratio/enrichment model, versus front O2 atmospheric compensation.

### 0x47B66 -- BLIND_ABSTAINED

- **On record:** Project label "isr26_injection_window" [TRACED]. Comment: [TRACED] ISR[26]: Injection window handler (62 bytes).
- **Blind (observed):** wrapper_call_58800_then_tailcall_587FC -- unknown. It runs two subroutines in a fixed order, probably as one entry in a scheduler or task table, but the work they do cannot be seen in this listing.
- **Grader:** The claim says this is the ISR[26] injection window handler. The blind answer describes only a wrapper that calls two subroutines and says its purpose is unknown, guessing at most a scheduler task entry. That gives nothing about injection or an interrupt role to compare against the claim.
- **Differs on:** Claim identifies the routine as the ISR[26] injection window handler; the blind answer states its purpose is unknown.

### 0x36008 -- BLIND_ABSTAINED

- **On record:** Project label "clol_delay_manager_A" [TRACED]. Comment: [TRACED] CL/OL delay manager A. Dispatched from fuel_dispatch_table_A.
- **Blind (inferred):** init_ram_block_FFFF79F4 -- Unknown from this code alone. The shape fits a subsystem initialise/reset routine that works on the RAM block around 0xFFFF79A4-0xFFFF79F8: it seeds a float with a constant, installs a ROM pointer, runs three helper routines, and records a byte status or state in 0xFFFF79F4. Which subsystem this is cannot be told.
- **Grader:** The claim says this is a closed-loop/open-loop delay manager. The blind answer describes only generic mechanics, a guessed init/reset routine, and explicitly says the subsystem cannot be told, so it offers nothing that could confirm or contradict the CL/OL delay identity.
- **Differs on:** none

### 0x34488 -- BLIND_ABSTAINED

- **On record:** Project label "afl_sub_dispatcher" [TRACED]. Comment: [TRACED] AFL sub-dispatcher. Dispatch Table A entry [5]. Orchestrates AFL learning cycle.
- **Blind (observed):** latch_indexed_float_clamped_and_set_flag_78AA -- unknown. Structurally it is a one-shot latch or initialisation step. It copies a status/mode byte into the 0xFFFF78A0 block, takes one entry from a RAM array of float records selected by an index byte, bounds it to fixed ROM limits, stores it as a working value in the same block, and sets a flag byte to 1, possibly meaning 'value latched' or 'valid'. The physical quantity cannot be determined from this code.
- **Grader:** The blind answer describes only the mechanics (latching a byte, clamping an indexed float, setting a flag) and says the purpose is unknown. It never mentions AFL learning or dispatch orchestration, so there is nothing substantive to compare against the claim.
- **Differs on:** Claim says this function orchestrates the AFL learning cycle as a sub-dispatcher. The blind answer sees a simple latch/clamp routine of unknown purpose with no dispatching.

### 0x52092 -- NOT_COMPARABLE

- **On record:** Project label "sensor_struct_8998_manager" [TRACED]. Comment: [TRACED] GBR=FFFF8998, manages sensor struct.
- **Blind (inferred):** diag_monitor_enable_conditions_eval -- Most likely the enable-condition evaluator for an OBD diagnostic monitor: it debounces the required operating conditions over time (rpm windows, temperature- or load-like floats, status flags), and only when all have held for their calibrated durations does it allow the monitor or test to run. Which monitor this is cannot be told from the code shown.
- **Grader:** The claim only says the routine uses GBR=FFFF8998 and "manages sensor struct", which is too generic to test. The blind answer agrees on the GBR base but gives a specific function, a diagnostic enable-condition evaluator, that the claim neither supports nor contradicts.
- **Differs on:** Claim says 'sensor struct manager'; blind answer says diagnostic monitor enable-condition timers and flags.

### 0x0D1F4 -- NOT_COMPARABLE

- **On record:** Project label "stubpool_target_48" [TRACED]. Comment: [TRACED] Slot 48 of the LITERAL POOL at 0x00E5EC (0x0E6AC), called from a 0x00E4xx task stub. RENAMED from \"isr_handler_48\", which was positional over a structure misread as an ISR dispatch table -- it is a literal pool (item 84), and this address is NOT in the 0x0-0x400 vector table. corrections.md item 91.
- **Blind (observed):** reset_state_FFFF44A4_flag_and_FFFF4494_FFFF44A0_to_max -- unknown. This is an atomic reset or initialisation of one small group of related RAM variables: a byte flag or state cleared to 0, and a 16-bit value and a float both set to their saturated maximum, 0xFFFF and 65535.0. That pattern fits resetting a timer, counter or minimum-tracker to an 'idle / not yet valid' state. Which subsystem it belongs to cannot be told from this code.
- **Grader:** The claim only says this is a literal-pool call target reached from a task stub, and that it was renamed from a mistaken ISR label. It gives no functional content that the blind answer's description of an atomic RAM reset could be tested against.
- **Differs on:** none

### 0x49BA4 -- NOT_COMPARABLE

- **On record:** Project label "stubpool_target_30" [TRACED]. Comment: [TRACED] Slot 30 of the LITERAL POOL at 0x00E5EC (0x0E664), called from a 0x00E4xx task stub. RENAMED from \"isr_handler_30\", which was positional over a structure misread as an ISR dispatch table -- it is a literal pool (item 84), and this address is NOT in the 0x0-0x400 vector table. corrections.md item 91.
- **Blind (inferred):** periodic_task_group_dispatch -- Most likely a scheduler task-list body: one fixed-rate time slice of the main loop that runs a group of control and diagnostic routines in order. The byte at 0xFFFF8EDC acts as an inhibit flag that skips the whole group when nonzero. The 0x317C(16) and 0x3190(saved) pair is most likely an interrupt-level raise and restore, i.e. a critical-section guard around three routines that must not be pre-empted. What the individual tasks do cannot be told from this listing.
- **Grader:** The claim only says this is a routine whose address sits in slot 30 of a literal pool and is called from a task stub. It says nothing about what the routine does, so the blind answer's description of a gated, ordered task-group dispatcher cannot be tested against it.
- **Differs on:** none

### 0x4A6FA -- NOT_COMPARABLE

- **On record:** Project label "stubpool_target_44" [TRACED]. Comment: [TRACED] Slot 44 of the LITERAL POOL at 0x00E5EC (0x0E69C), called from a 0x00E4xx task stub. RENAMED from \"isr_handler_44\", which was positional over a structure misread as an ISR dispatch table -- it is a literal pool (item 84), and this address is NOT in the 0x0-0x400 vector table. corrections.md item 91.
- **Blind (inferred):** run_task_group_by_mode_byte_FFFF8EDC -- Probably a scheduler task-group entry. A mode/state byte at 0xFFFF8EDC selects between running the normal list of periodic subsystem routines (value 0), running one alternate routine (value 0xFF, possibly an init, shutdown or special-mode path), or skipping entirely (any other value). Which subsystems the callees are, and what the mode byte means, cannot be told from this code.
- **Grader:** The claim only says this is a literal-pool slot target called from a task stub, and it records a rename. It says nothing about what the function does, so the blind answer's mode-byte dispatcher description cannot be tested against it. The blind answer's 'scheduler task group' reading is loosely consistent with 'task stub'.
- **Differs on:** none

### 0x4AA58 -- NOT_COMPARABLE

- **On record:** Project label "stubpool_target_16" [TRACED]. Comment: [TRACED] Slot 16 of the LITERAL POOL at 0x00E5EC (0x0E62C), called from a 0x00E4xx task stub. RENAMED from \"isr_handler_16\", which was positional over a structure misread as an ISR dispatch table -- it is a literal pool (item 84), and this address is NOT in the 0x0-0x400 vector table. corrections.md item 91.
- **Blind (inferred):** periodic_task_list_dispatch -- Most likely one of the engine computer's scheduler task routines: a fixed, ordered list of module update functions that runs each time the task is called. It can be suppressed by a global inhibit/mode flag at 0xFFFF8EDC. The byte argument looks like a slot or phase number that a few modules use, and that decides whether 0x6F0B8 runs (slots 0 and 2). A second flag at 0xFFFF8322 gates two further calls.
- **Grader:** The claim only records that this is a literal-pool call target reached from a task stub, a structural correction, and says nothing about what the routine does. The blind answer's reading of it as a scheduler task routine fits that, but there is no stated function to test it against.
- **Differs on:** none

### 0x4A03E -- NOT_COMPARABLE

- **On record:** Project label "stubpool_target_37" [TRACED]. Comment: [TRACED] Slot 37 of the LITERAL POOL at 0x00E5EC (0x0E680), called from a 0x00E4xx task stub. RENAMED from \"isr_handler_37\", which was positional over a structure misread as an ISR dispatch table -- it is a literal pool (item 84), and this address is NOT in the 0x0-0x400 vector table. corrections.md item 91.
- **Blind (inferred):** task_list_dispatch_by_mode_8EDC -- Most likely a top-level scheduler slot that picks which list of subsystem routines to run from a mode/state byte at 0xFFFF8EDC. Mode 0 runs the full list, which is probably the normal operating task list. Mode 0xFF runs a reduced list. Any other value runs only three routines. What each mode means (e.g. normal / init / shutdown) cannot be told from this code.
- **Grader:** The claim only records provenance: the routine is the target of literal-pool slot 37, called from a 0x00E4xx task stub, and it is not an ISR. It says nothing about what the routine does, so the blind answer's mode-byte dispatch of task lists cannot be checked against it. The blind answer's 'scheduler slot' framing fits loosely with being a task-stub target.
- **Differs on:** none

### 0x72584 -- NOT_COMPARABLE

- **On record:** Project label "sensor_data_acq_a" [TRACED]. Comment: [TRACED] Sensor data acquisition A (called from dispatcher 1 body).
- **Blind (observed):** lookup_pair_1d_from_ffff63cc -- unknown. It derives two calibration-table values from one shared input (0xFFFF63CC) and stores them in neighbouring RAM floats. The listing does not show what the input or the outputs mean.
- **Grader:** The claim only says it is a sensor data acquisition routine called from a dispatcher, which is too generic to test. The blind answer describes two 1D table lookups from one input and does not name a purpose.
- **Differs on:** none

### 0x4A420 -- NOT_COMPARABLE

- **On record:** Project label "stubpool_target_41" [TRACED]. Comment: [TRACED] Slot 41 of the LITERAL POOL at 0x00E5EC (0x0E690), called from a 0x00E4xx task stub. RENAMED from \"isr_handler_41\", which was positional over a structure misread as an ISR dispatch table -- it is a literal pool (item 84), and this address is NOT in the 0x0-0x400 vector table. corrections.md item 91.
- **Blind (inferred):** dispatch_task_list_by_state_FFFF8EDC -- A task-list dispatcher gated by a state or mode byte. When the byte is zero it runs a fixed sequence of about 30 subsystem routines, probably one periodic scheduler slot of the engine-control code. When the byte is 0xFF it runs one alternative routine, possibly an initialisation or special-mode path. For any other value it skips the slot. The meaning of the three states cannot be fixed from this code alone.
- **Grader:** The claim only says this routine is a literal-pool slot target called from a task stub, and says nothing about what it does. The blind answer's three-way task-list dispatcher description therefore has nothing specific in the claim to test against.
- **Differs on:** none

### 0x724C8 -- NOT_COMPARABLE

- **On record:** Project label "sensor_data_acq_b" [TRACED]. Comment: [TRACED] Sensor data acquisition B (called from dispatcher 1 body).
- **Blind (observed):** update_ect_iat_rpm_load_debounced_hold_timer -- unknown. The code is a debounce counter plus a hold-off (stretch) timer gated on an ECT window, an IAT ceiling, minimum RPM and load, a state byte from 0x584DC, and a comparison of two block floats against a third. Which feature it enables cannot be told from this code alone.
- **Grader:** The claim only says this is a generic 'sensor data acquisition B' routine called from a dispatcher, which is too thin to test. The blind answer describes a specific debounce counter and hold-timer gated on ECT, IAT, RPM and load conditions, and there is nothing specific in the claim to check that against.
- **Differs on:** none

### 0x4A6C6 -- NOT_COMPARABLE

- **On record:** Project label "stubpool_target_43" [TRACED]. Comment: [TRACED] Slot 43 of the LITERAL POOL at 0x00E5EC (0x0E698), called from a 0x00E4xx task stub. RENAMED from \"isr_handler_43\", which was positional over a structure misread as an ISR dispatch table -- it is a literal pool (item 84), and this address is NOT in the 0x0-0x400 vector table. corrections.md item 91.
- **Blind (observed):** task_dispatch_gated_by_flag_8EDC -- A scheduler or dispatcher stub that runs a group of six subsystem routines only while the flag at 0xFFFF8EDC is clear. The flag may be an inhibit, init-not-done or mode flag. What the flag means and what the six routines do cannot be told from this code, so the specific purpose is unknown.
- **Grader:** The claim only says this is slot 43 of a literal pool reached from a task stub. It gives no function or purpose to test against the blind answer's description of a flag-gated dispatcher of six routines.
- **Differs on:** none

### 0x41A7E -- NOT_COMPARABLE

- **On record:** Project label "task37_stage3" [TRACED]. Comment: [TRACED] Uses desc 0xAE170 / 0xAE17C, both all-zero on this calibration.
- **Blind (inferred):** correction_offset_state_machine_step_and_rpm_ramp -- Likely a correction offset with a step-and-ramp shape. When a condition held for a calibrated count is met and the 0xFFFF43FC value is below a threshold, the offset jumps to a fixed calibrated value (probably negative). It then ramps back toward 0, capped at 0, using one of two rpm-dependent step tables. State 0 forces it to zero. Which engine quantity it corrects (for example timing or a torque reduction) cannot be told from this code.
- **Grader:** The claim only gives a task stage label and notes that it uses tables 0xAE170 and 0xAE17C, which are all zero. It names no function or quantity to test. The blind answer is consistent with those two tables, but it cannot be checked against any stated purpose.
- **Differs on:** none


## unverified_function

## No answer

- fn-035A4: stopped: refusal (cyber)
- fn-06828: stopped: refusal (cyber)
- fn-0E2FC: grading stopped: refusal (cyber)
- fn-0E486: grading stopped: refusal (cyber)
- fn-47C40: grading stopped: refusal (cyber)
- fn-48DB8: grading stopped: refusal (cyber)
