# Verify-item claims for the valet limiter (Gate 0)

Each `## V<n>` section is the claim one verify item tests. Start one with the
command under it, or from the console's **+ New item** form: claim file
`docs/plans/valet-limiter.claims.md`, section `## V<n>`. The blind readers never
see this file. They get the addresses and the bytes, and the claim is what their
answers are compared against.

Every claim is the project's **current best reading**, written so it can be
wrong. Where nothing is known, the claim says so and states the hypothesis being
tested.

## V1. On-chip RAM is retained across key-off; a marker tells warm start from cold

```
rom new valet-v1-ram-retention --addrs 0xFFFFBFFC,0x00068A,0x000752,0x0007E0,0xFFFF3234 \
    --claim-file docs/plans/valet-limiter.claims.md --section "## V1."
```

- The start-up routine reached through the literal at `0x000D64` (= `0x00065C`)
  loads the long at `0xFFFFBFFC` and compares it with `0x5AA5A55A`
  (`00068A`-`000692`). Equal means RAM survived (a warm start). Otherwise it calls
  `0x0007E0` with `r4 = 7`.
- At the end of start-up it writes `0x5AA5A55A` to `0xFFFFBFFC` (`000752`-`000756`).
- Hypothesis: while the battery stays connected, on-chip RAM keeps its contents
  across key-off. Learned values such as the IAM at `0xFFFF3234` survive this way,
  and are lost only when the battery is disconnected.
- Hypothesis: a cold start (marker absent) clears or re-initialises some RAM range,
  and a warm start does not. **Which ranges each path clears is not known**, and is
  the main question.
- Unknown: whether any checksum or integrity check covers retained RAM besides the
  marker, and what happens when it fails.

## V2. Cruise switch inputs -- DISCOVERY, not yet runnable as a verify item

The owner chose a cruise-button hold (2026-11-15). **Nothing in this repo identifies
the cruise-control switch inputs.** The definitions' "Cruise" tables are the
steady-cruise timing regime, and `0xFFFF90BE` is that regime's flag (corrections
item 38), not a button. Off-limits sources (`merp mod/`, `patches/`) are not used.
The verify pipeline needs addresses to hand the blind readers, so this item runs in
three steps:

- **V2a: candidate search -- DONE 2026-11-15** (from stock bytes; decodes below).
- **V2b: standstill button log (owner, the decisive test).** Procedure and logger
  lines below.
- **V2c: verify.** `rom new valet-v2-cruise --addrs <the byte V2b picks>` with the
  claim "byte X reads A at rest and B while CANCEL is held", as the log showed.

### V2a findings

**Discrete switch inputs, not an analog ladder.** Two driver routines copy port-image
words into one flag byte per switch. Each flag is 1 while the input bit is in its
active state.

```
0186C4..018712  (port image 0xFFFF447C word, 0xFFFF4482 byte)
  0186CE 6041 mov.w @r4,r0 / C804 tst #4,r0 / 0529 movt r5   -> 0xFFFF5FC1  (447C bit 2, active-low)
  0186D6 6041 mov.w @r4,r0 / C802 tst #2,r0 / 0029 movt r0   -> 0xFFFF5FC4  (447C bit 1, active-low)
  0186E0 6060 mov.b @r6,r0 / C801 tst #1,r0 / CA01 xor #1    -> 0xFFFF5FC5  (4482 bit 0, active-high)
  0186EC C808 tst #8,r0 / 8F01 bf/s                          -> 0xFFFF5FC6  (447C bit 3, active-low; forced 0 when 0x022CEA returns 0: 018708 tst r2,r2 / bf/s)
01871E..0187AC  (GBR = 0xFFFF5FC2; port image 0xFFFF4484 word)
  018734 C802 tst #2,r0 / CA01 xor #1 -> C000 mov.b r0,@(0,gbr)   -> 0xFFFF5FC2  (4484 bit 1)
  01873E C808 tst #8,r0 / CA01 xor #1 -> C001 mov.b r0,@(1,gbr)   -> 0xFFFF5FC3  (4484 bit 3)
  018748 C801 tst #1,r0 / CA01 xor #1 -> C014 mov.b r0,@(20,gbr)  -> 0xFFFF5FD6  (4484 bit 0)
  018752 C804 tst #4,r0 / CA01 xor #1 -> C013 mov.b r0,@(19,gbr)  -> 0xFFFF5FD5  (4484 bit 2)
  01875C C810 tst #16,r0              -> C011 @(17,gbr)            -> 0xFFFF5FD3  (4484 bit 4), debounced into 0xFFFF5FD2
0187B0..0187EA  0xFFFF5FC9 = 0xFFFF5FC1 held for >= [0xC21C4] = 6 ticks (counter 0xFFFF5FDA);
                0xFFFF5FC8 is LATCHED to 1 at the same moment (0187E4 mov.b r0,@r1) and cleared elsewhere
```

**No other writers.** `find_writers.py FFFF5FC1 FFFF5FC9` (direct, displacement and
GBR forms) lists exactly the stores above (`018700`, `018704`, `01870C`, `018712`,
`018766`, `01876A`, `0187E4`) plus `5FC7` at `018942`/`01894A`. **Trap:** it marks
every one "LIKELY NOT A REAL WRITER", and `--code-only` hides them all, because
`rom_region_map.txt` classifies `0x0186C4`-`0x01894A` as unmapped/float_data. They
decode as complete SH-2E functions with matching prologues and epilogues
(`0186C4 2FD6 mov.l r13,@-r15` ... `01871A 000B rts`), so the region map is wrong
there. Do not use `--code-only` in the I/O driver layer `0x018000`-`0x01FFFF`
without checking.

**The five-button group.** `0x06E2C6` reads exactly five of these flags together:
`5FC2`, `5FC3`, `5FC1`, `5FD6` and `5FD5` (`06E2D4`-`06E2E6`). It runs only while
`[0xFFFF9634] == 1` (`06E2E8`-`06E2EE`). It gives each one its own held-time
counter (`@(2..10,r9)`, `r9 = 0xFFFF9634`) against `[0xC222E] = 16250`. Any switch
held past that sets `r14 = 1`. If all five stay released for `[0xC222C] = 250`, it
sets `@(1,r9)`. **Inferred: a stuck-switch monitor for a five-switch panel, the
cruise switches.** The CANCEL input is most likely one of these five. Not
established: which flag is which button, and what `0xFFFF9634` is.

**Cross-check of the method.** The SSM switch bytes are built by getters in the
table at `0x06423C`. Decoded mechanically, SSM `0x000063` bit 2 is `0xFFFF81BA`, the
knock signal this project already proved (corrections item 4). And SSM
`0x000121` = b7 `0xFFFF65D0`, b6 `5FC5`, b5 `5FC2`, b4 `5FC3`, b3 `5FC4`, b1 `5FC1`,
b0 `5FC8` (getter `0x05E3E8`). So **V5's `0xFFFF65D0` is a discrete switch reported
next to these**, which supports the "clutch" reading. The button log decides that
too.

### V2b: the standstill button log

Add these to `logs/logcfg.txt`. The `0xFF` tag is the SSM read patch's direct RAM
read, the same mechanism as the existing `paramid = 0xFF6852` line:

```
;valet V2b -- cruise/clutch/brake switch candidates (remove after the test)
paramname = SW5FC1
paramid = 0xFF5FC1
scalingrpn = x

paramname = SW5FC2
paramid = 0xFF5FC2
scalingrpn = x

paramname = SW5FC3
paramid = 0xFF5FC3
scalingrpn = x

paramname = SW5FD5
paramid = 0xFF5FD5
scalingrpn = x

paramname = SW5FD6
paramid = 0xFF5FD6
scalingrpn = x

paramname = SW5FC4
paramid = 0xFF5FC4
scalingrpn = x

paramname = SW5FC5
paramid = 0xFF5FC5
scalingrpn = x

paramname = SW65D0
paramid = 0xFF65D0
scalingrpn = x

paramname = CC9634
paramid = 0xFF9634
scalingrpn = x

paramname = PORT447C
paramid = 0xFF447C
databits = 16
scalingrpn = x

paramname = PORT4484
paramid = 0xFF4484
databits = 16
scalingrpn = x
```

Procedure: parked, handbrake on, neutral, engine running. Keep about 3 s between
steps, and say each step out loud or note the time:

1. Nothing pressed, 5 s (baseline).
2. Cruise MAIN on, then off.
3. Hold SET/COAST 2 s. 4. Hold RES/ACC 2 s. 5. Hold CANCEL 2 s. Do 3-5 with MAIN on,
   then again with MAIN off.
6. Press the clutch 2 s. 7. Press the brake 2 s.

Expected: each button moves exactly one byte, 0 to 1 and back. CANCEL's byte is
V2c's address. The clutch step should move `SW65D0` if V5's lead is right.
`CC9634` shows whether MAIN gates the group.

## V3. `0xFFFF65FC` is vehicle speed in km/h, 0 at a standstill

```
rom new valet-v3-speed --addrs 0xFFFF65FC \
    --claim-file docs/plans/valet-limiter.claims.md --section "## V3."
```

- `0xFFFF65FC` is vehicle speed in km/h (corrections items 8 and 9): it is compared
  against the definition's speed-limit thresholds and the launch patch's 8.0515 km/h
  (5 mph) threshold.
- Hypothesis: it reads exactly 0.0 at a standstill, not a small noise value.

## V4. The rev-limiter host runs at a fixed scheduler period

```
rom new valet-v4-limiter-schedule --addrs 0x03B668,0x03D2FC \
    --claim-file docs/plans/valet-limiter.claims.md --section "## V4."
```

- The rev limiter begins at `0x03B668` and tail-calls `0x03D2FC` on exit
  (`docs/rev-limit-patch.md`; `docs/patch-specs/launch_control.json`).
- Hypothesis: it is called from one periodic scheduler task at a fixed period.
  The 5.0 s hold is counted in calls, so the period must be exact. **The calling
  task and its period are not known.**

## V5. `0xFFFF65D0` is a driver-input state byte (unidentified)

```
rom new valet-v5-launch-flag --addrs 0xFFFF65D0 \
    --claim-file docs/plans/valet-limiter.claims.md --section "## V5."
```

- `0xFFFF65D0` is a byte read at 10 sites (idle control, ETB/boost `0x050A90`,
  `0x0540B2`, `0x054B38`, CL/OL `0x03AE88`, ignition `0x03EEDC`, DTC `0x0A95D0`,
  `0x0BC74A`, `0x0BC8C6`). It is compared against 1 at `0x014B92` and `0x03AE94`
  (`docs/rev-limit-patch.md`, "Open question").
- Hypothesis: a gear/neutral/clutch state input. **Not verified; no writer found.**
