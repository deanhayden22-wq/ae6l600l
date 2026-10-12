# Blind audit of tuning conclusions

> Memory notes and subsystem-doc sections, re-derived from ROM bytes by a reader that
> could not see them, then compared statement by statement. **A contradiction means one
> side is wrong, not which.** Decode it by hand before changing a doc or a tune.
> Batches msgbatch_013otVLwJKYKdQNjU2VMSDkB (blind) and msgbatch_01CLD2t3WMSdUYX4c8yqvXHm (grading), model claude-opus-5-5, 2026-10-11 20:36:32.

## By source

| Source | Claims | agree | partly_agree | disagree | blind_abstained | not_comparable | no answer |
|---|---|---|---|---|---|---|---|
| memory | 4 | 1 | 1 | 2 | 0 | 0 | 0 |
| docs | 6 | 3 | 0 | 1 | 0 | 0 | 2 |

Individual statements: 51 supported, **7 contradicted**, 31 not addressed.

## Contradictions

### boost-control.md :: PID terms

- **Contradicted:** Claim says 0xC0BD4 = 210.0; blind answer reads 620.58.
- **Contradicted:** Claim says 0xC0BDC = 0.0; blind answer reads 5.1715, with the negative integral allowed only when boost error < 5.1715.
- **Contradicted:** Claim says 0xC0D74 is the derivative term, disabled at 0.0; blind answer says it is the boost-error axis (first value 0) of a TD table, likely Integral Positive, and sees no derivative term (P plus clamped integral only).
- **Contradicted:** Claim says 0xC0D04 = −160.0; blind answer reads the first value as −155.14 (an axis value of a 1D table).
- **Contradicted:** Claim says 0xC0D74 = 0.5 is the IIR filter coefficient in Task 52; blind answer reads 0xC0D74 as a TD table axis whose first value is 0.
- Supported: 7 statement(s). Not addressed: 2.
- Blind mechanism: This is the turbo-dynamics (TD) boost-error feedback for wastegate duty: a proportional term plus a clamped integral accumulator. Inputs are boost error (fr14 = RAM 0xFFFF5CA0), target boost (fr8 = RAM 0xFFFF5CA4), IAT (0xFFFF6364), RPM (0xFFFF6624), a wastegate-duty value at 0xFFFF5C98 (GBR base) and a WGDC ceiling at 0xFFFF5CC4. The previous integral is loaded from 0xFFFF5CB0.

1) Enable flags with hysteresis. If 620.58 (0x0C0BD4) > target boost, the byte at GBR+129 (0xFFFF5D19) is set to 1, which inhibits TD. Otherwise it is cleared to 0 only once target boost >= the value at 0x0C0BD8; between the two it holds. RPM does the same against 0x0C0BE8 / 0x0C0BEC into GBR+130 (0xFFFF5D1A). If either flag is 1, the proportional (0xFFFF5CAC) and integral (0xFFFF5CB0) are both zeroed.

2) Proportional. When enabled, proportional = TurboDynamicsProportional(boost error) × TD Proportional Compens
- Inert or gated: The whole mechanism is gated by two hysteresis flags. Target boost below 620.58 inhibits it (release level at 0x0C0BD8, value not shown), and the RPM threshold at 0x0C0BE8 / 0x0C0BEC does the same; while inhibited, P and I are forced to 0.

The negative integral needs boost error < 5.1715 and WGDC >= 5. The positive integral needs boost error >= 5 and WGDC < RAM 0xFFFF5CC4. Because the negative branch is tested first, a boost error between 5 and 5.1715 takes the negative path.

The integral is f

### project_gear_determination.md

- **Contradicted:** Claim says the threshold set is 'selected by state bytes FFFF5E93/FFFF5F03'; blind answer says the selectors are FFFF5F03 and FFFF5FB8, and that FFFF5E93 is an externally supplied gear byte copied through as the gear when FFFF65C5==0, not a set selector.
- Supported: 8 statement(s). Not addressed: 5.
- Blind mechanism: Manual-gear estimation from road speed and engine speed, followed by a debounce. Function 0x023EB8 picks one of three 5-float threshold sets: A (0x0C3474..84) if byte 0xFFFF5F03==1, else B (0x0C3488..98) if byte 0xFFFF5FB8==1, else C (0x0C349C..AC). It copies the chosen set into RAM 0xFFFF6814..0xFFFF6824 (base 0xFFFF6810 +4..+20). If flag 0xFFFF65C5==0, the gear is copied from byte 0xFFFF5E93: values 1-5 pass through, 7 becomes 1, 0 or 6 become 6/0, and values above 7 leave the result unchanged. If 0xFFFF65C5!=0, the gear is computed. When 0xFFFF65C0==1, or 0x297A0() returns 2, the result is 6/0. When rpm_current is below a literal at 0x024130, the result is 5/6. Otherwise ratio = float_safe_div(speed 0xFFFF65FC, float_safe_div(rpm, K@0x024138)), i.e. speed*K/rpm. The ratio is stored to 0xFFFF680C and compared against the five thresholds in ascending order: ratio<=thr1 gives gear 1, ...
- Inert or gated: Gated rather than inert. The ratio ladder runs only when 0xFFFF65C5!=0, 0xFFFF65C0!=1, 0x297A0()!=2 and rpm >= the constant at 0x024130 (value not shown); below that rpm the output is forced to 5/6. The debounce latch requires 0xFFFF65C0!=1 and a counter >= 31 (0x0C30BE). All three threshold sets share the same first value (13.416), so the 1st/2nd boundary does not depend on which set is selected. The remaining four values of each set are not shown.

### project_overrun_fuelcut_tier_system.md

- **Contradicted:** The claim says 0xCBCC0 holds per-tier counter thresholds [38,38,38,6], one per tier, selected by the RPM tier. The blind answer says 0xCBCC0 is a single uint16 value of 38. It is compared with word 0xFFFF5E74 in a special case to choose a dedicated table set. The per-bin counts come from pointer tables at 0x63B70–0x63D40, not from 0xCBCC0.
- Supported: 5 statement(s). Not addressed: 4.
- Blind mechanism: The two listings at 0x03AF94 are the same function, found twice by the bounds heuristic. It builds an overrun fuel-cut delay schedule. It runs only when GBR+30 (0xFFFF7C9E) is 0 (GBR = 0xFFFF7C80).

If flag 0xFFFF65C0 == 1, the base count comes from 0x0CBC9E and the stage-2/3 counts (GBR+14, GBR+16) are zeroed. Otherwise rpm_current is binned against three float thresholds: bin 0 if rpm < 2250 (0x0CC4EC), bin 1 if rpm < 3000 (0x0CC4F0), bin 2 if rpm < 4500 (0x0CC4F4), bin 3 at 4500 and above.

The bin (×4) indexes pointer tables in ROM at 0x63B70–0x63D40. The pointers lead to uint16 calibration values loaded into r4 (later GBR+12), GBR+14 and GBR+16. Which pointer-table family is used depends on three things:
- whether byte 0xFFFF5DB8 is zero (two families);
- a special case: the result of call 0x22CF4 is 0 and word 0xFFFF5E74 >= 38 (uint16 at 0x0CBCC0);
- otherwise the selector byte 0xF
- Inert or gated: - The resume RPM table 0x0CEED0 is flat at 1000 rpm for every ECT from -40 to 110 °C, so its ECT dependence is inert in this calibration.
- The whole delay-schedule computation is skipped when GBR+30 (0xFFFF7C9E) != 0.
- When 0xFFFF65C0 == 1, the RPM binning and the 2250/3000/4500 thresholds are bypassed: the base count comes from 0x0CBC9E and stages 2/3 are 0.
- The extra offsets from 0x0C2220.. are applied only when 0xFFFF6155 == 1 and 0xFFFF615F == 0; otherwise they are zero.
- The 0x0CBC92 m

## Everything else

| Claim | Grade | Supported | Not addressed | Functions shown |
|---|---|---|---|---|
| cruise-tables.md :: Non-Cruise siblings | agree | 5 | 1 | 3 |
| injector-rescale.md :: 5. Do NOT touch | agree | 10 | 7 | 8 |
| rev-limit-patch.md :: What the patch changes | agree | 5 | 0 | 3 |
| feedback_derived_artifacts_are_wrong_at_scale.md | partly_agree | 1 | 6 | 8 |
| project_clol_function_identities.md | agree | 10 | 6 | 8 |

## No answer

- doc-architecture-02: stopped: refusal (cyber)
- doc-knock-07: stopped: refusal (cyber)
