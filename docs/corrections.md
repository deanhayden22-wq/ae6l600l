# Known Corrections — verified errors still present in committed files

Each entry was re-verified from ROM bytes on the date shown. Where the wrong value
is still baked into analysis files, that is stated explicitly.

---

## 1. `0xBE960` / `0xBE970` — min and max were SWAPPED — **SWEPT AND FIXED 2026-07-26**

| Address | **Truth** | Files said (before the sweep) |
|---|---|---|
| `0xBE960` | **`float_max`** | `float_min` |
| `0xBE970` | **`float_min`** | `float_max` |

This was "corrected" on 2026-04-07 — in the wrong direction. The `ImportAE5L600L.java`
labels, the Ghidra export XML, and all analysis files were then updated to the
wrong identity, so the error became consistent and self-reinforcing. That is why
it survived so long: every file agreed with every other file.

**Root cause:** operand order rendered backwards. `0xFnm5` is `FCMP/GT FRm,FRn`
with `n` = bits 8–11 and `m` = bits 4–7, setting `T = (FRn > FRm)`. So `F455` is
`fcmp/gt fr5,fr4` (n=4, m=5) — **not** `fcmp/gt fr4,fr5`. Reversing the operands
inverts the result.

**Proof:**

```
0BE960  F455  fcmp/gt fr5,fr4   ; T = (FR4 > FR5)
0BE962  8F02  bf/s 0x0BE96A     ; T==0  -> FR6 = FR5
0BE966  A001  bra 0x0BE96C
0BE968  F64C  fmov fr4,fr6      ; delay slot; T==1 -> FR6 = FR4
0BE96A  F65C  fmov fr5,fr6
0BE96C  000B  rts
0BE96E  F06C  fmov fr6,fr0      ; FR6 always gets the LARGER value => MAX
```

`0xBE970` is the same shape with `F545` (n=5, m=4), so it keeps the **smaller**
value => MIN.

**Affected subsystems** (files referencing these): CL/OL master + ramp + state
machine, AFC PI controller trace, boost control, fueling pipeline, knock/FLKC,
ignition timing, injection timing, map switching, FBKC path trace.

**Downstream consequence — now resolved.** Every "float_max provides a floor
clamp" reading was actually a **ceiling/cap**, and vice versa. The CE5A4
OL-enrichment-ramp finding depended on this; its clamp direction has been
corrected and now reads more coherently than before (see the sweep notes below).

**Sweep completed 2026-07-26.** Method: normalize-to-truth per address rather
than a blanket swap, because the corpus was *not* uniformly wrong — 3 lines
already carried the correct pairing and a blind swap would have broken them.

- 268 lines referenced `BE960`/`BE970`; most are bare address references
  (`; =0x000BE960 (ROM)`) that carry no semantic label and were left alone.
- **81 lines corrected** across 19 files, plus 4 `FCMP/GT` operand-order
  renderings (`F455 = fcmp/gt FR4,FR5` → `FR5,FR4`, and the mirror for `F545`).
- **3 lines already correct** — untouched, which validated the method.
- **3 lines naming both addresses** — fixed by hand.
- **10 historical/narrative lines** rewritten by hand, because they described the
  *earlier* swap and a mechanical pass would have made them doubly confusing.
- **2 duplicate label blocks** in `ImportAE5L600L.java`; the later one still had
  stale descriptions and would have overwritten the corrected comment in Ghidra.
- Ghidra DB re-labelled (3,445 label operations re-applied).
- Verified: **0 remaining wrong assertions** in the corpus.

Directional prose was corrected too: `0xBE970` = min means the CE5A4 OL-enrichment
accumulator is **capped from above** at the blended target (`FFFF7990`), not
clamped from below. That is more physically coherent than the old reading — the
accumulator ramps up and converges on its target rather than being held above it.

**Still open:** `0xBE960`/`0xBE970` carry unrelated wrong identities in a few
places — `float_abs` (`sensor_diag_analysis.txt:97,124`), `pack_helper` /
`pack/unpack` (`region_010000_scout.txt:179,201,438`), `rate_limit_interp`
(`isr22_trace.py`, `trace_fuel_pump.py`, `disasm_afc_stages.py`, and
`SYMBOL NAME="rate_limit_interp"` in the old export XML),
`adc_convert_indexed` (`adc_pipeline_trace.py:127`), and "Table processor
variant" (`disassembly.txt:3176-3177`). 14 lines total — a separate cleanup.

---

## 2. RAM range in `disassembly.txt` header — FIXED 2026-07-26

Was `RAM: 0xFFFF8000-0xFFFFFFFF (32KB)`. Actual: **`0xFFFF0000-0xFFFFBFFF` (48KB)**.

Proof: reset SP at `0x00000004` = `0xFFFFBFA0`; highest RAM literal anywhere in
the ROM is `0xFFFFBFFC`.

Mattered because the logged addresses `FFFF6624` (RPM), `FFFF6350` (ECT), and
`FFFF65FC` (load) all sit *below* `0xFFFF8000` and looked invalid under the old
range.

---

## 3. VBR is `0x000FFC50`, not `0x00000000` — **FIXED 2026-07-26**

Startup at `0x00FA3E`: `mov.l @(0x00FCC4),r2` (= `0x000FFC50`) then `ldc r2,vbr`.
Peripheral vector *N* resolves to `0x000FFC50 + 4N`. The table at `0x0-0x3FF` is
only the reset/exception block hardware uses *before* VBR is programmed.

`isr_map.txt` previously claimed "The SH7058 in this ECU does NOT use per-vector
hardware dispatch for peripherals." That was **wrong**, and the cause is
instructive: the peripheral vectors were read at VBR = 0, where they land in
instruction bytes (`vec[64] @0x000100 = 0x8B04D62B`) — which looks like garbage,
so the conclusion drawn was that dispatch must not be used.

The real table is fully populated: **236 entries, 234 pointing into ROM, 134
distinct handlers**. Default `0x0000E852` (71 vectors), then `0x0000E8CE` (32).
Single-use handlers share a shape — load a small ID into R4, call a common
reporter at `0xE794`/`0xE774`, then `bra self` — i.e. a per-source fault trap.

**For patching:** hook the table at `0x0FFC50`. The free-space map does not
overlap it (holes stop at `0x0FFAF8` / `0x0FFB00-0x0FFB80`), but the "PRIMARY
PATCH AREA" ends only `0x158` bytes before it — an overrunning patch there would
silently clobber interrupt vectors. Prefer `0x0DAE8C-0x0F8900` for anything big.

Also at `0x00FA42`: `lds r2,fpscr` with `0x00040001` — round-toward-zero,
denormals flushed. FPSCR is live state, not a don't-care.

---

## 4. Ghidra language was `SH-2` (no FPU) — FIXED 2026-07-26

Re-imported as `SuperH:BE:32:SH-2A`. Old DB decoded 0 FPU instructions and 16.4%
of the ROM; new DB decodes 26,933 FPU instructions and 51.4%. See
[`architecture.md`](architecture.md).

---

## 5. Fake `FSQRT` in ~27 scripts — FIXED 2026-07-26

`0xFn6D` was decoded as `fsqrt`, which SH-2E does not have. Now emits
`.INVALID_SH2E`. Seeing that token means data is being decoded as code.

---

## 6. `~/ghidra_scripts/ImportAE5L600L.java` shadowed the repo copy — FIXED 2026-07-26

Ghidra's default script path outranks `-scriptPath`. The home copy was stale and
labelled `FFFF65FC` as "vehicle speed" (it is `engine_load_current`) and
`FFFF63F8` as "engine load g/rev" (it is `iat_current`). Replaced from repo;
backup at `ImportAE5L600L.java.stale-backup-2026-07-26`.

---

## 7. Operand-level errors — **FOUND AND FIXED 2026-07-26**

**Baseline: `disassembly/verification_report_v2.txt`.** Regenerate with:

```
python scripts/verify_disasm_v2.py
```

| | Before | After |
|---|---|---|
| Instruction lines checked | 22,487 | 22,487 |
| Agree | 22,041 (98.02%) | **22,458 (99.87%)** |
| **Real errors** | **415** | **0** |
| Symbolic labels (not errors) | 28 | 28 |
| Prose replacing an instruction | 3 | 0 |

Mnemonics were essentially perfect all along; the errors were in **operands**,
which is why they survived — the old verifier compared mnemonics only, skipped
every `.word` line, and misdecoded FPUL/FPSCR. See the deprecation banner in
`scripts/verify_disassembly.py`.

### What was wrong, and what it was worth

| Count | Class | Example |
|---|---|---|
| 141 | DROPPED | real instruction as `.word`: `0x4F13`=`stc.l gbr,@-r15`, `0x0D29`=`movt r13`, `0x425A`=`lds r2,fpul` |
| 113 | DATA-AS-CODE | `SHAD`/`SHLD` decoded where SH-2E has no such instruction — every one inside a literal pool |
| 95 | WRONG REGISTER FIELD | every `jsr` in `knock_flkc_analysis.txt` read `jsr @r0`; truth `@r2`, `@r5`, `@r14` |
| 43 | WRONG DISPLACEMENT | low byte instead of low nibble: `0x8062` → `@(98,r6)`, truth `@(2,r6)` |
| 22 | OTHER | `MOV.W @(disp,PC)` off by 2 (the `& ~3` mask is for `MOV.L`/`MOVA`, not `MOV.W`); `0x4n12`/`0x4n16` as FPSCR when they are MACL |
| 1 | WRONG MNEMONIC | prose explaining the PC-relative rule that computed the wrong target |

The one that mattered: **the knock call graph was wrong at 95 sites.** With the
registers corrected and back-traced, `knock_detector` is now readable — it calls
`float_clamp_range` (`0xBE56C`), `float_lerp` (`0xBEA40`), and
`table_desc_1d_float` (`0xBE830`), none of which were visible before.

### How it was repaired

`scripts/repair_disasm.py` rewrites only verifier-flagged lines, preserving
column layout and hand-written annotations. Annotations *derived* from the bad
decode (e.g. `; CALL @ 0xFFFFFFE4`, computed by reading `jsr @r5` as `jsr @r0`)
are discarded and recomputed: for `JSR`/`JMP` it back-traces the target register
to the literal-pool load that filled it and names the callee from
`ImportAE5L600L.java`. Correcting the register text alone would have left the
call graph unreadable.

Deliberately **not** auto-repaired:
- `clol_gap_closure.txt:414` — a worked reasoning passage that gets the answer
  wrong, catches itself, and lands correctly two lines later. The trail is worth
  more than the tidy line.
- 28 lines using symbolic labels (`bf skip`, `@pool`) rather than addresses.
  Legitimate style, not errors.

`accel_enrichment_raw.txt:135-148` was fixed by hand: it asserted "each JSR reads
args from words embedded after the call". Those words are the JSRs' **delay
slots**. Since a delay slot executes before control transfers, R0 still holds the
*previous* call's result — the idiom saves each query's result to the local frame
at `@(4,R15)`, `@(8,R15)`, `@(12,R15)`.

---

## 8. `0xFFFF65FC` is VEHICLE SPEED (km/h), not engine load — **FIXED 2026-07-26** (see item 9 for the full identity set)

`disassembly/maps/ram_reference.txt` and `ImportAE5L600L.java` label `0xFFFF65FC`
as `engine_load_current` ("Engine load in g/rev", 135 refs). **That is wrong.**
It is vehicle speed in km/h.

History: analysis files originally called it "BPW"; a 2026-04-07 pass "corrected"
it to `engine_load_current`. Both readings are wrong.

### Three independent proofs

1. **Behavioural.** The launch-control patch at `0x0F1000` reads `*0xFFFF65FC`
   and compares it to `8.0515`. Below the threshold it adds **2700 RPM** to the
   value the rev limiter tests — fuel cut at ~4000 RPM. Log
   `logs/7-26 20.19b/` reaches **6027 RPM**, so the comparison must have gone the
   other way. But logged load maxes at **3.53 g/rev** and can never exceed 8.05.
   As load, launch control would be permanently armed and the car capped at 4000
   RPM at all times — which plainly is not happening.
2. **Definition scaling.** That constant is exposed as *"LC disable speed(MPH)
   threshold"* (`0xF104C`) with `LCSPEED(MPH) toexpr="x*.621"` — **raw is km/h**.
   Raw `8.0515` displays as **5 mph**, a textbook launch cutoff. `LoadGRev` is
   defined `max="5"` g/rev; 8.05 is not representable as load.
3. **Axis breakpoints.** `0xFFFF65FC` is the `FR4` axis input to descriptor
   `0x0AA760` (called via `table_desc_1d_float` @ `0xBE830`); its axis at
   `0x0C0294` reads `0, 8, 16, … 120` — 0–120 km/h in steps of 8. A load axis
   would run 0–5 g/rev.

### Scope

- **Log-based analysis is unaffected.** The CSV `load` column holds plausible
  g/rev values (0.11–3.53) with `MPH` as a separate column, so the logger sources
  load elsewhere. `logs/logcfg.txt` is stale (no `load`, `EGT`, `AFR`, `IDC`,
  `KNOCK_FLAG` channels) and cannot confirm which address.
- **ROM-side analysis is affected** at up to 135 read sites.
- `0xFFFF61CC` is separately labelled `vehicle_speed` (56 refs). Both cannot be
  as labelled; **the relationship between the two is unresolved.**
- **The true engine-load address has NOT been identified.** Do not substitute a
  guess.

### Not yet applied

`ram_reference.txt`, `ImportAE5L600L.java`, and any analysis text reasoning about
"engine load" at this address still carry the wrong identity. Fixing it needs the
`61CC`/`65FC` relationship resolved first, so the replacement label is right —
this project has now been bitten three times by corrections applied in the wrong
direction, and a fourth is not wanted.

---

## 9. Four core RAM identities were wrong — **FIXED 2026-07-26**

Item 8 found one. Systematic re-derivation found it was four, rotated.

| Address | `ram_reference.txt` said | **Truth** |
|---|---|---|
| `0xFFFF63F8` | `iat_current` | **engine load (g/rev)** |
| `0xFFFF65FC` | `engine_load_current` | **vehicle speed (km/h)** |
| `0xFFFF620C` | `airflow_maf_current` | **manifold pressure** |
| `0xFFFF61CC` | `vehicle_speed` | **diag monitor status bytes** (not a float) |

Real IAT is **`0xFFFF6364`** (see item 12). *An earlier version of this item
claimed `0xFFFF69F0`; that is RETRACTED — see the retraction note further down.*
`0xFFFF69F0` is listed in `ram_reference.txt` as `iat_input_float`
with the correct "float, −40..120 C" range. **Two IAT entries was the tell.**

### The method that settled it

The breakthrough was using the **definition XMLs' axis names**, which the project
had never exploited. A RAM variable is traced to the table-lookup axis it feeds;
the definitions *name* that axis. That turns identity into a mechanical lookup
instead of an inference.

1. **Definition-named axes.** `0xFFFF63F8` feeds **21 of 21** definition-named
   axes, every one named "**Engine Load**" — `Calculated Engine Torque A–D`
   (`0xC1780`/`0xC1A00`/`0xC1C80`/`0xC1F00`), `CL Fueling Target Compensation B
   (Load)` (`0xD16DC`), `Timing Compensation Per Gear (1st)` (`0xD5374`). Never
   once a temperature axis. `0xFFFF620C` feeds `0xCC840` "*Cranking Fuel IPW
   Compensation (MAP) / **Manifold Pressure***".
2. **Axis breakpoint envelope.** `0xFFFF65FC` feeds 13 axes spanning **0..300**;
   every definition-named load axis in this ROM spans 0.2..8. Its axis `0x0C0294`
   reads `0, 8, 16 … 120` = km/h.
3. **Access-width census.** `0xFFFF61CC`: **26 int8 accesses, zero float** —
   against `0xFFFF63F8` 86/86 float and `0xFFFF6624` 298/301 float.
4. **Threshold pairing.** The function at `0x0141D6` compares three RAM values
   against the three `c0bc*` thresholds *in order*, and the definitions name each
   threshold: Boost→`0xFFFF620C`, **Load→`0xFFFF63F8`**, RPM→`0xFFFF6624`.

### Why it survived so long

It was **noticed at least five times and never acted on**. `knock_flkc_report.txt`
calls `0xFFFF63F8` "load/TPS-like value" (:98), "load-like" (:134), "Load-like
variable used as Y-axis in 3D tables" (:585); `docs/knock.md:151` repeats it;
`scripts/analysis/knock_flkc_analysis.py:51` names the handler "knock load/TPS
area"; `cl_ol_master_analysis.txt:602` tags the IAT reading `[NEEDS VERIFICATION]`.

Every author saw the smell, wrote a hedge, and deferred to the label. Nothing
recorded how strongly the label was held, so a confident name outranked five
hedged observations. That is precisely what `docs/verification-status.md` exists
to prevent.

`ImportAE5L600L.java` even contains the wrong-direction correction in the act:

```
// REMOVED: 0xFFFF65FC "vehicle_speed" — wrong. This is engine_load, not speed.
```

The removed label was the correct one. Both stale notes are now marked SUPERSEDED.

### Also corrected

The stale `~/ghidra_scripts/ImportAE5L600L.java` shadow copy (corrections item 6)
had **both** `0xFFFF65FC` = "vehicle speed" and `0xFFFF63F8` = "engine load g/rev"
— i.e. it was **right on both**, and was overwritten from the wrong repo copy on
2026-07-26 during this same session. Backup: `ImportAE5L600L.java.stale-backup-2026-07-26`.
Item 6's framing was wrong; only its point about shadowing order stands.

### Still open — flagged CONFLICT, not corrected

`0xFFFF65C0 throttle_position` (89 int8 / 0 float) and `0xFFFF6254 maf_current`
(51 int8 / 0 float) claim `(float)` but are only ever accessed as bytes. The
**names** may be right; the **storage width** is unsupported. Not renamed —
a byte-sized field at the base of a struct whose float lives at an offset would
produce the same census, and this project has now been burned four times by
corrections applied on incomplete evidence.

---

# Second pass, 2026-07-26 — items 10 to 25

Same mechanical method as item 9 (trace a RAM variable into a table-lookup call,
read the axis **name** out of the definition XMLs), with two extensions that both
paid off:

1. **All eight lookup entry points**, not two. The ROM has a family of eight
   routines sharing one calling convention (`R4` = descriptor, `FR4` = axis-0
   input, `FR5` = axis-1 input) and differing only in return type:
   1D `0x0BE830` (float), `0x0BE874`/`0x0BE88C` (u8), `0x0BE8AC`/`0x0BE8C4` (u16);
   2D `0x0BE8E4` (float), `0x0BE928` (u8), `0x0BE944` (u16).
   `scripts/coverage_map.py` follows only the two float ones. **Both** proofs
   that `0xFFFF4130` is battery voltage run through `0x0BE944`.
2. **Struct-field addressing.** `mov #imm,Rn` + `fmov.s @(R0,Rm),FRn` reaches a
   large fraction of this ECU's RAM. `0xFFFF5CA0` (boost error) has **zero** pool
   literals and is invisible without it.

**Everything below was re-derived from `rom/ae5l600l.bin` bytes for this commit.**
No derived `.txt` file was used as evidence for any claim.

---

## 10. `0xFFFF4130` is BATTERY VOLTAGE, not atmospheric/baro — **FIXED 2026-07-26**

`ram_reference.txt` had it as `atm_pressure_baro`, "Atmospheric pressure / baro
ADC output (float). ADDR 4 in ADC pipeline", 77 refs — and added the further
wrong claim "Real battery voltage is at FFFF41E0".

Two independent definition-named pairings, both through `0x0BE944` (the 2D
uint16 lookup, which `coverage_map.py` does not follow):

```
00894A: D30C  mov.l @(0x00897C),r3   ; pool 00897C = 0xFFFF4130
00894C: D20C  mov.l @(0x008980),r2   ; pool 008980 = 0xFFFF4150
00894E: F538  fmov.s @r3,fr5         ; FR5 = *(0xFFFF4130)
008950: D40C  mov.l @(0x008984),r4   ; = 0x000AF4B0  (descriptor)
008952: D10D  mov.l @(0x008988),r1   ; = 0x000BE944  (2D u16 lookup)
008954: 410B  jsr @r1
008956: F428  fmov.s @r2,fr4         ; delay slot: FR4 = *(0xFFFF4150)
```

Descriptor `0x0AF4B0` = counts 16 x 5, axis0 `0xD918C`, axis1 `0xD91CC`.

| slot | fed from | axis | definition name | breakpoints |
|---|---|---|---|---|
| FR4 / axis0 | `0xFFFF4150` | `0xD918C` | `Ignition Dwell / Engine Speed` | 500 … 8000 RPM |
| FR5 / axis1 | `0xFFFF4130` | `0xD91CC` | `Ignition Dwell / Battery Volts` | 8, 10, 12, 14, 16 V |

Second, independent site — injector dead time:

```
0303C6: D210  mov.l @(0x030408),r2   ; = 0xFFFF4130
0303C8: F428  fmov.s @r2,fr4
0303CA: D210  mov.l @(0x03040C),r2   ; = 0xFFFF6210
0303CC: F528  fmov.s @r2,fr5
0303CE: D410  mov.l @(0x030410),r4   ; = 0x000AD7E0 (descriptor)
0303D0: D210  mov.l @(0x030414),r2   ; = 0x000BE944
0303D2: 420B  jsr @r2
```

Descriptor `0x0AD7E0` = counts 5 x 3, axis0 `0xD104C` =
`Injector Latency_ / Battery Output` (**6.5, 9.0, 11.5, 14.0, 16.5 V**), axis1
`0xD1060` = `Injector Latency_ / Manifold Pressure` (−1000, 0, +1000 raw =
−19.34 … +19.34 psi relative).

**Every one of the 8 axes this variable feeds spans 6..20.** Zero pressure-shaped
axes. Width census: float x77, 0 integer. Injector dead time as *f*(battery
volts, MAP) and dwell as *f*(RPM, battery volts) are the textbook forms.

Note `ram_reference.txt` already called the sibling `0xFFFF6210` "Second input
to dead time table lookup" — the file was internally contradicting itself.

---

## 11. `0xFFFF6898` is ATMOSPHERIC PRESSURE, not manifold pressure and not an RPM delta — **FIXED 2026-07-26**

`ram_reference.txt:61` said `manifold_pressure`; `ImportAE5L600L.java` said
`rpm_delta` in one place and `manifold_pressure` in another. All three wrong.

```
013B02: D272  mov.l @(0x013CCC),r2   ; = 0xFFFF6898
013B04: F428  fmov.s @r2,fr4
013B06: D272  mov.l @(0x013CD0),r2   ; = 0xFFFF6624  (rpm)
013B08: F528  fmov.s @r2,fr5
013B0A: D472  mov.l @(0x013CD4),r4   ; = 0x000AA99C  (descriptor)
013B0C: D272  mov.l @(0x013CD8),r2   ; = 0x000BE8E4  (2D float lookup)
013B0E: 420B  jsr @r2
```

Descriptor `0x0AA99C` = counts 6 x 6, axis0 `0xC0E94` =
`Target Boost Compensation (Atm. Pressure)_ / **Atmospheric Pressure**`,
breakpoints **440, 580, 670, 720, 740, 760** (= 8.51 … 14.70 psi absolute via
`psi1` toexpr `x*.01933677`); axis1 `0xC0EAC` = `/ Engine Speed`.

Three more definition-named `Atmospheric Pressure` axes are fed from it:
`0xC0E54` (Initial/Max WGDC Comp (Atm. Pressure)), `0xC36F8` (Front Oxygen
Sensor Compensation (Atm. Pressure)), `0xD2530` (Boost Limit (Fuel Cut)).
**Zero** `Manifold Pressure` axes. Width: float x48.

**Two corroborations that also kill the `rpm_delta` reading:**

* The thresholds it is compared against, `CC1DC` = 691.9 and `CC1E0` = 699.9,
  sit inside the 440..760 barometric range — an altitude hysteresis pair.
* `ImportAE5L600L.java` documented `FFFF7458 set=1 if (FFFF6898-FFFF620C) <= 570`.
  `0xFFFF620C` is manifold pressure (settled, item 9). **Baro minus MAP is
  manifold vacuum** — dimensionally coherent. "RPM delta minus manifold
  pressure" is not.

The calibration labels `OL_Condition_RPMDelta_Lo/Hi` are therefore misnamed;
flagged in the Java file, not renamed (they are calibration labels, out of scope
for this pass).

---

## 12. `0xFFFF6364` is INTAKE AIR TEMPERATURE, not ECT at start — **FIXED 2026-07-26**

Was `ect_startup`, "ECT at engine start or secondary RPM (float). NOT
atmospheric pressure", 48 refs. The width claim (float) was right; the name was
wrong.

```
013A0A: D235  mov.l @(0x013AE0),r2   ; = 0xFFFF6364
013A0C: FF28  fmov.s @r2,fr15
...
013A34: D431  mov.l @(0x013AFC),r4   ; = 0x000AA974  (descriptor)
013A36: D230  mov.l @(0x013AF8),r2   ; = 0x000BE830  (1D float lookup)
013A38: 420B  jsr @r2
013A3A: F4FC  fmov fr15,fr4          ; delay slot supplies the axis input
```

Descriptor `0x0AA974` axis `0xC0E24` = `Target Boost Compensation (IAT)_ /
**Intake Temperature**`, breakpoints −20, −10, 0, 10, 20, 40 °C.

Independent second site:

```
040428: D20C  mov.l @(0x04045C),r2   ; = 0xFFFF6364
04042A: FE28  fmov.s @r2,fr14
04043C: D40C  mov.l @(0x040470),r4   ; = 0x000ADC14
04043E: D20D  mov.l @(0x040474),r2   ; = 0x000BE830
040440: 420B  jsr @r2
040442: F4EC  fmov fr14,fr4
```

Descriptor `0x0ADC14` axis `0xD3248` = `Timing Compensation A (IAT) / **Intake
Temperature**`.

Across its traced descriptors, **8 of 8** definition-named axes are Intake
Temperature (`0xD3248`, `0xC0C54`, `0xC0E24`, `0xCC8A8`); **zero** are coolant.

**The decisive detail:** the *same instruction block* at `0x013A06` loads
`0xFFFF6350` separately into FR14 and feeds it to `0xC0C14` "Initial/Max
Wastegate Duty Compensation (ECT) / **Coolant Temperature**". The ROM uses the
two side by side. They cannot both be coolant.

---

## 13. `0xFFFF62DC` is THROTTLE PLATE angle and `0xFFFF64D8` is ACCELERATOR PEDAL angle — **FIXED 2026-07-26**

`ram_reference.txt` had `fuel_rate` and `throttle_raw`; `ImportAE5L600L.java`
additionally had `engine_load_metric` for `0xFFFF62DC`.

Both settle in one function, in adjacent instructions:

```
036094: D280  mov.l @(0x036298),r2   ; = 0xFFFF62DC
036096: F428  fmov.s @r2,fr4         ; FR4 <- throttle
036098: D280  mov.l @(0x03629C),r2   ; = 0xFFFF64D8
03609A: FF28  fmov.s @r2,fr15        ; FR15 <- pedal
...                                    (FR4 is not rewritten on the path below)
0360B0: 8905  bt 0x0360BE
0360BE: D47B  mov.l @(0x0362AC),r4   ; = 0x000AC5D0
0360C0: D279  mov.l @(0x0362A8),r2   ; = 0x000BE830
0360C4: 420B  jsr @r2                ; ---> (Throttle) table, FR4 = 0xFFFF62DC
0360C6: 0009  nop
0360CA: D479  mov.l @(0x0362B0),r4   ; = 0x000AC5E4
0360CC: D276  mov.l @(0x0362A8),r2   ; = 0x000BE830
0360CE: 420B  jsr @r2                ; ---> (Accelerator) table
0360D0: F4FC  fmov fr15,fr4          ; delay slot: FR4 = 0xFFFF64D8
```

| descriptor | axis | definition name | breakpoints |
|---|---|---|---|
| `0x0AC5D0` | `0xCCD88` | `Minimum Primary Open Loop Enrichment (Throttle) / **Throttle Plate Opening Angle**` | 10.93 … 89.06 |
| `0x0AC5E4` | `0xCCDA8` | `Minimum Primary Open Loop Enrichment (Accelerator) / **Accelerator Pedal Angle**` | 0, 20, 40, 60, 80, 100 |

FR4 liveness was checked instruction-by-instruction over `0x036096`–`0x0360C4`:
the only branch in that range is `bt 0x0360BE`, whose *not-taken* path
(`0x0360B2`–`0x0360BC`) ends in `bra 0x0360D2` and skips the lookup entirely.
On the path that reaches the call, FR4 is untouched.

This is the strongest single piece of evidence in this pass: the ROM feeds the
(Throttle) variant and the (Accelerator) variant of the *same table* from those
two addresses in two consecutive calls. Widths: float x18 and float x27.

Second site for the pedal: `0x02F9B8` → descriptor `0x0AC360` → axis `0xCC874`
`Cranking Fuel IPW Compensation (Accelerator) / Accelerator Pedal Angle`.

**Bonus:** this explains a value that never made sense. `ol_condition_checker`
compares `0xFFFF62DC` against 90.0 / 91.0, which the calibration labels call
`OL_Condition_Load_A/B`. Load axes in this ROM span 0.2..3, so 90 was never a
load; it sits just above the top of the 10.93..89.06 throttle axis — a
wide-open-throttle gate.

---

## 14. `0xFFFF6C48` is a diagnostic status BYTE, not battery voltage — **FIXED 2026-07-26**

Width census: **int8 x34, float x0** (13 loads, 21 stores). Every store writes a
nibble-doubled sentinel — `0x00`, `0x33`, `0x55`, `0x77`, `0xAA`, `0xBB`,
`0xDD`, `0xEE`:

```
02C148: E2BB  mov #-69,r2            ; 0xBB
02C14A: D12C  mov.l @(0x02C1FC),r1   ; = 0xFFFF6C48
02C14C: 2120  mov.b r2,@r1
```

Consumption is boolean: `02C11C mov.b @r1,r2 / 02C11E tst r2,r2 / 02C120 bt`.
A voltage does not take eight discrete hand-written values. It reaches zero
lookup axes. Renamed `diag_status_code_6C48`; **which** diagnostic it reports is
UNRESOLVED and deliberately not guessed. Real battery voltage is item 10.

---

## 15. `0xFFFF67EC` is a uint16 DTC maturation COUNTER, not atmospheric pressure — **FIXED 2026-07-26**

Both the width and the name were wrong.

**Width:** 99 of 99 dereferences are `mov.w`, zero `fmov.s` — e.g. `01202A
mov.l @(0x01210C),r6 ; 01202C mov.w @r6,r11`. The same function reads genuine
floats through `fmov.s` from `0xFFFF6624` / `0xFFFF6634`, so the FPU is
available and simply is not used here.

**Name:**

```
023AA2: E000  mov #0,r0
023AA4: D119  mov.l @(0x023B0C),r1   ; = 0xFFFF67E8
023AA6: A00F  bra 0x023AC8
023AA8: 8112  mov.w r0,@(4,r1)       ; reset [0xFFFF67EC] = 0
...
023AAE: 8512  mov.w @(4,r1),r0
023AB0: 640D  extu.w r0,r4
023AB2: 460B  jsr @r6                ; = 0x000BE554
023AB4: E501  mov #1,r5              ; increment by 1
```

`0x0BE554` is the universal saturating u16 increment
(`extu.w/extu.w/add/cmp.hs 0xFFFF/clamp`), verified from bytes.
Threshold pairing: `012076 mov.l @(0x01211C),r2` (= `0x000C0212`) `; 012078
mov.w @r2,r6 ; 01207E cmp/ge r6,r2` — the counter is compared against a uint16
**calibration** at `0xC0212` (= 306). Barometric pressure is not compared
against an integer count.

Neighbourhood census corroborates a counter block: `0xFFFF67E8/EA/EC/EE/F0/F2`
are int16 ×3/×8/×99/×14/×2/×1 with **zero** float accesses anywhere in the run.

Renamed `dtc_maturation_counter_67EC`. Barometric pressure is `0xFFFF6898`
(item 11).

---

## 16. `0xFFFF65C0` is a diagnostic precondition BYTE flag, not throttle position — **FIXED 2026-07-26**

Left flagged CONFLICT by item 9 ("the NAME may still be right"). It is not.

**Width:** 89 of 89 dereferences are `mov.b`, zero float.

**Name:** used as a boolean —
`01573A mov.l @(0x015808),r2 ; 01573C mov.b @r2,r0 ; 015748 cmp/eq #1,r0 ;
01574A bt/s 0x015778`, and `0x015778` zeroes a DTC maturation counter,
skipping the `0x0BE554` increment. Same shape at `0x01F798`, `0x023C7A`,
`0x015DD2`, `0x018972`.

**The struct-offset escape was checked and it fails.** The whole run
`0xFFFF65B7, 65BA, 65BC, 65BD, 65BE, 65BF, 65C0, 65C1 … 65C6` is byte-addressed
at every offset with zero float accesses anywhere in the block, so there is no
float field an offset could point at. `0xFFFF65BD` is already named
`engine_state_byte` in the same file.

Renamed `diag_precondition_flag_65C0`. Which monitor it gates is UNRESOLVED.
Pedal angle is `0xFFFF64D8`, throttle plate angle `0xFFFF62DC` (item 13).

---

## 17. `0xFFFF6254` is a BYTE flag, not MAF — **FIXED 2026-07-26**

Also left flagged CONFLICT by item 9. **Width:** 51 of 51 `mov.b`, zero float.

**Name:** it is set as part of a block initialisation, to the literal 1,
alongside four sibling bytes:

```
01DA98: E001  mov #1,r0
01DA9A: D551  mov.l @(0x01DBE0),r5   ; = 0xFFFF6250
01DA9C: 8052  mov.b r0,@(2,r5)
01DA9E: 8053  mov.b r0,@(3,r5)
01DAA0: 8059  mov.b r0,@(9,r5)
01DAA2: 8055  mov.b r0,@(5,r5)
01DAA4: 8054  mov.b r0,@(4,r5)       ; 0xFFFF6254
01DAA6: D64F  mov.l @(0x01DBE4),r6   ; the uint16 cal at 0xC3078 ...
01DAA8: 6261  mov.w @r6,r2           ; ... into the uint16 at 0xFFFF6250
```

A mass-airflow reading in g/s is not set to the constant 1 alongside four
siblings. Consumption is `cmp/eq #1` (`0x01D5A8`, `0x025148`, `0x01A2BE`).
Neighbourhood: `0xFFFF624C` int8, `0xFFFF6250` int16, `0xFFFF6254` int8,
`0xFFFF6264` int32 — nearest floats are `0xFFFF6270`/`0x6274`, 0x1C–0x20 bytes
away and unreachable as a field of this base.

Renamed `flag_6254`. **The real MAF variable is NOT identified and was not
guessed** — no axis in either definition XML is named MAF / mass air / airflow,
so the axis-name method has nothing to vote against. See item 23.

---

## 18. `0xFFFF8C98` is a uint16 DTC counter struct, not a timing float workspace — **FIXED 2026-07-26**

**Width:** 5 accesses, all `mov.w`, zero float.

```
055F74: D157  mov.l @(0x0560D4),r1   ; = 0xFFFF8C98
055F76: 8511  mov.w @(2,r1),r0
055F78: 640D  extu.w r0,r4
055F7A: 420B  jsr @r2                ; = 0x000BE554 (saturating u16 increment)
055F7C: E501  mov #1,r5
...
055FA2: 6611  mov.w @r1,r6           ; the base word itself
055FA4: 420B  jsr @r2
055FA6: 646D  extu.w r6,r4
055FAC: 2101  mov.w r0,@r1
055FB0: 2121  mov.w r2,@r1           ; reset arm, r2 = 0
```

The `+2` counter is compared against the uint16 calibration at `0xD61C8`
(`0x055F8C`) and the verdict written as a byte to `+8` (`0x055F96`). Struct
members: `+0` int16 ×5, `+2` int16 ×1, `+4` int16 ×14, `+6` int16 ×1, `+8` int8
×7 — a counter/flag struct.

The "(float)" claim rested entirely on the note *"Adjacent to
timing_workspace_A"*. **Adjacency is not evidence.** The float at `0xFFFF8C88`
is *before* the base, not at an offset from it. Renamed `dtc_counter_struct_8C98`.

---

## 19. `0xFFFF8CFC` is a BYTE flag inside the knock struct, not a float workspace — **FIXED 2026-07-26**

5 accesses, all `mov.b`, zero float.
`056CCC mov #1,r2 ; 056CCE mov.l @(0x056D90),r6 (= 0xFFFF8CFC) ; 056CD0
mov.b r2,@r6`, after a chain of byte tests on `0xFFFF366C`, the calibration byte
at `0xD6177`, and `0xFFFF307C`. Loads are `cmp/eq #1` / `tst`.

**This is the one address where the "byte field inside a float struct" escape
was genuinely available, and it still fails.** `0xFFFF8CE8`, `8CEC`, `8CF0`,
`8CF8` *are* float, and `ram_reference.txt` correctly calls `0xFFFF8CE0` a
116-byte knock/timing struct. Floats do live in this struct — just not at
`+0x1C`. Those 4 bytes are byte-accessed 5/5 times and `0xFFFF8D04` beside them
is int8 too. Renamed `knock_struct_flag_8CFC`.

---

## 20. `0xFFFF4254` is a BYTE flag, not an AFR/lambda workspace — **FIXED 2026-07-26**

9 accesses, all `mov.b` (7 stores, 2 loads), zero float. The only values ever
written are the literals 0 and 1:

```
0089DE: E400  mov #0,r4
0089EA: D132  mov.l @(0x008AB4),r1   ; = 0xFFFF4254
0089EC: 2140  mov.b r4,@r1           ; clear, in a run that also zeroes
                                     ; 0xFFFF4237 and 0xFFFF4252
008D96: E301  mov #1,r3
008D98: D220  mov.l @(0x008E1C),r2   ; = 0xFFFF4254
008D9A: 2230  mov.b r3,@r2           ; set
```

A lambda ratio is a continuous float. The whole run `0xFFFF4246, 4247, 4248,
4252, 4253, 4254, 4255, 425D, 425E` is int8 and `0xFFFF4258`/`425A` are int16 —
**no float anywhere**, so no offset can rescue the claim. `ram_reference.txt`
already names `0xFFFF425F` `injection_state_flag`, i.e. a known byte-flag
cluster. Renamed `flag_4254`; the specific meaning is UNRESOLVED and deliberately
not named after a quantity.

---

## 21. `0xFFFF61CC` was a FALSE CONFLICT — the tool matched its own correction — **FIXED 2026-07-26**

`docs/verification-status.md` flagged `0xFFFF61CC` CONFLICT. The file was
already right: item 9 had corrected it to *"BYTE array of diag monitor status.
26 int8 accesses, ZERO float. NOT speed."*

`scripts/coverage_map.py` contradiction test (a) fires on
`re.search(r'\bfloat\b', claim_text, re.I)` over name + description. **The word
`float` inside the corrective phrase "ZERO float" matched.** The tool flagged the
correction as the error.

Fixed on the data side: the description now reads "zero FP accesses". Re-derived
independently for this commit and the existing line is confirmed — 26
dereferences, all `mov.b`, zero `fmov.s`; neighbours `0xFFFF61CC/CD/CE/CF/D0` are
int8 ×26/×7/×7/×13/×7 (a contiguous byte array); stores at `0x1BDFE`, `0x1BE4E`,
`0x1BE78`, `0x1BEA2`, `0x1BF10` are all `mov.b`.

**The tool-side fix was NOT applied** — see item 23, tool defect (d). Changing
the measurement instrument in the same commit as the measurement would make the
before/after coverage numbers unattributable.

---

## 22. Five RAM variables identified for the first time — **ADDED 2026-07-26**

None of these appeared in `ram_reference.txt`. All are tuning-relevant.

### `0xFFFF8558` = REQUESTED / CALCULATED ENGINE TORQUE — the Target Boost X axis

```
0139FE: D235  mov.l @(0x013AD4),r2   ; = 0xFFFF8558
013A00: F428  fmov.s @r2,fr4
013A02: D235  mov.l @(0x013AD8),r2   ; = 0xFFFF6624 (rpm)
013A04: F528  fmov.s @r2,fr5
013A1C: D433  mov.l @(0x013AEC),r4   ; = 0x000AA9F0
013A1E: D234  mov.l @(0x013AF0),r2   ; = 0x000BE8E4
013A20: 420B  jsr @r2
```
Descriptor `0x0AA9F0` axis0 `0xC12D8` = `Target Boost_ / **Requested Torque**`
(0, 100, 170, 200, 240, 280, 310, 320, 330, 340, 350); axis1 `0xC1304` =
`/ Engine Speed`. **This is the RAM variable that selects the Target Boost
column.** The same function then folds in the ECT, IAT and Atm. Pressure
compensations. float ×6 + int32 ×1.

### `0xFFFF5CA0` = BOOST ERROR (target − actual) — the Turbo Dynamics input

Reached as a struct field; **zero** pool literals, so it is invisible to any
literal-only trace:

```
013BA8: D559  mov.l @(0x013D10),r5   ; = 0xFFFF5D18
013BAE: E088  mov #-120,r0           ; SIGN-EXTENDED
013BB0: FE56  fmov.s @(r0,r5),fr14   ; => *(0xFFFF5D18-120) = *(0xFFFF5CA0)
```
FR14 is not rewritten anywhere in `0x013BB2`–`0x013C02` (checked instruction by
instruction). Three calls follow, each with delay slot `fmov fr14,fr4`:

| site | descriptor | axis | definition name |
|---|---|---|---|
| `0x013C02` | `0x0AA914` | `0xC0D04` | `Turbo Dynamics Proportional / **Boost Error**` (−160…160) |
| `0x013C32` | `0x0AA928` | `0xC0D3C` | `Turbo Dynamics Integral Negative / **Boost Error**` |
| `0x013C7C` | `0x0AA93C` | `0xC0D74` | `Turbo Dynamics Integral Positive / **Boost Error**` |

3 of 3 named axes agree. **Read the `mov #-120` as unsigned and you land on
`0xFFFF5DA0`** — a plausible-looking wrong address that is self-consistent at
every site. That is the exact failure class item 7 documents; see item 23,
tool defect (a).

### `0xFFFF62E4` = THROTTLE ANGLE CHANGE — the tip-in trigger

`03A9BC mov.l @(0x03AA70),r2 (= 0xFFFF62E4) ; 03A9BE fmov.s @r2,fr4` (FR4 not
rewritten before the call) `; 03A9D0 jsr 0x0BE830` → descriptor `0x0AD368`, axis
`0xCED08` = `Throttle Tip-in Enrichment A / **Throttle Angle Change**`
(0 … 31.3). The alternate branch reaches `0xCED74` (Tip-in Enrichment B),
selected by the byte at `0xFFFF844F`.

Note `ram_reference.txt:111` puts `throttle_delta_pos` at `0xFFFF7D68`, which
feeds only `0xC43CC`/`0xC43E4` (0..0.25) — a different, much smaller quantity.

### `0xFFFF7324` = LAST CALCULATED BASE PULSE WIDTH

`038DCE mov.l @(0x038E14),r2 (= 0xFFFF7324) ; 038DD0 fmov.s @r2,fr4 ; 038DD8
jsr 0x0BE8E4` with delay `fmov fr15,fr5` (FR15 = `[0xFFFF6624]` rpm) →
descriptor `0x0AD738`, axis0 `0xD0760` = `Per Injector Pulse Width Compensation
A / **Last Calculated Base Pulse Width**` (1000 … 16000 = 1 … 16 ms), axis1
`0xD07A4` = `/ Engine Speed`. Repeated at `0x038DE6`/`0x038DF2`/`0x038DFE` for
compensations B/C/D — 4 of 4 named axes agree.

### `0xFFFF7F4C` = ENGINE SPEED (the base-timing / knock-advance copy)

`040160 mov.l @(0x040354),r12 (= 0xFFFF7F60) ; 040174 mov #-20,r0 ; 040176
jsr @r14 (= 0x0BE8E4) ; 040178 fmov.s @(r0,r12),fr5` ⇒ `0xFFFF7F60-20 =
0xFFFF7F4C` → descriptor `0x0AE31C` axis1 `0xD46CC` = `Base Timing Primary
Cruise / **Engine Speed**`. Six further sites give six more Engine Speed axes
(`0xD488C`, `0xD4A4C`, `0xD4C0C`, `0xD58BC`, `0xD5A7C`); 0 dissent.

---

## 23. NOT corrected — insufficient evidence, and what would settle each

This project has been burned four times by corrections applied in the wrong
direction. Everything in this section stays as it is until the named evidence
exists.

### `0xFFFF69F0` — the "Real IAT" claim is NO LONGER SETTLED

Item 9 asserted *"Real IAT is `0xFFFF69F0`"*. Item 12 shows `0xFFFF6364` is the
address every definition-named Intake Temperature axis actually reads.
`0xFFFF69F0` reaches **zero** definition-named axes (its only axis, `0xC4514`,
is an unnamed 0..1 ratio at four sites), and its only two literal-pool stores are
not sensor-like:

```
0273E0: F89D  fldi1 fr8              ; 1.0
0273E2: D23F  mov.l @(0x0274E0),r2   ; = 0xFFFF69F0
0273E6: F28A  fmov.s fr8,@r2         ; set to exactly 1.0
```
and `0x0275B4`–`0x0275C8` reads it, adds the calibration float at `0xC41F4`,
clamps with `0xBE970` against `0xC41F8`, and stores back — a ramp-to-limit.

**NOT renamed.** The evidence identifies which address the cal tables read, not
which address is "the" IAT. `ram_reference.txt` now carries the doubt explicitly
instead of the confident cross-reference.
*What would settle it:* the store path (a `fmov.s FRm,@(R0,Rn)` or
pointer-mediated write that a literal back-trace does not catch), or a log
correlating `0xFFFF69F0` against `0xFFFF6364`.

### Medium-confidence identities held back

| address | one traced named axis | why not applied |
|---|---|---|
| `0xFFFF4150` | `Ignition Dwell / Engine Speed` (item 10, same instruction pair) | single site; float ×7 |
| `0xFFFF6634` | `Idle Speed Stability A / Engine Speed Delta` (−50…50) | 2 sites |
| `0xFFFF89C8` | `Idle Speed Stability A / Idle Speed Error` (−150…600) | 1 site |
| `0xFFFF40E0` | `Front Oxygen Sensor Scaling / Front Oxygen Sensor` (−1.3…0.74 mA) | 1 site; contradicts the existing `ATU_output_ctrl` name (float ×4 from 5 literals argues against a hardware register, but one site is not a family) |
| `0xFFFF63C0` | `MAF Compensation (IAT) / Mass Airflow` (1.6…290 g/s) | 1 site, computed address |
| `0xFFFFA198` | none — 36 hits, all RPM-shaped envelopes, **zero named** | envelope only |

*What would settle these:* more sites, i.e. more **named axes** — see the
binding limit below.

### Genuinely unresolved

* **`0xFFFF63C4` `ect_compensation`** — a real three-way split. Its 9 traced
  hits give `Intake VVT Error` (`0xCF9EC`), `Exhaust VVT Error` (`0xD11D0`) and
  `Mass Airflow` (`0xCE618`). Either it is a reused scratch slot with different
  contents at different call sites, or a linear sweep is carrying a stale FR tag
  across a basic-block boundary. Nothing supports "ECT compensation".
  *What is missing:* per-function control-flow-aware tracing, not a linear sweep.
* **`0xFFFF63CC` `ram_ECT`** — one named hit, the `Smoothed MAF` X axis
  `0xD9280` (20…44 g/s) of the table bound in item 26. Its other envelopes
  (0…75, 10…50, 20…44, 0…60) are temperature-compatible *and*
  time/percentage-compatible. Neither confirmed nor corrected.
* **`0xFFFF5FFC` `io_state_register`** — float ×22 from 16 literals, feeding 12
  numeric lookup axes spanning 0..250. An I/O state register that is only ever
  read as a float and used as a table index is mislabelled; all 12 axes are
  unnamed, so the replacement is unknown.
* **The real MAF/airflow variable** (item 17). *What is missing:* an axis named
  MAF / mass air / airflow in the definition XMLs. Do not guess.
* **Which monitor each settled byte flag belongs to** — `0xFFFF4254`,
  `0xFFFF6254`, `0xFFFF65C0`, `0xFFFF8CFC`, `0xFFFF6C48` — and which DTC the
  counters `0xFFFF67EC` and `0xFFFF8C98` mature. The replacement names are
  deliberately neutral for that reason.
* **Unmapped calibration thresholds.** `0xC0212` (uint16 306, paired with the
  `0xFFFF67EC` counter), `0xD61C8` (paired with `0xFFFF8C98+2`), `0xC3078`
  (loaded into `0xFFFF6250`), `0xD6177` (byte, gates `0xFFFF8CFC`). None has a
  definition entry. Adding them would give future runs a threshold-pairing
  handle on the whole diagnostic block.

### Tool defects found, recorded, NOT applied in this commit

Deliberately deferred: `scripts/coverage_map.py` is the instrument that produces
the before/after coverage numbers. Changing it in the same commit as the data
would make the delta unattributable. Each is verified from ROM bytes.

**(a) `coverage_map.py:461` — `mov #imm,Rn` sign-extension.**
`elif hi == 0xE: reg[n] = w & 0xFF`. SH-2E **sign-extends** the 8-bit immediate.
Latent today only because the tracer nulls `fmov.s @(R0,Rm),FRn` so `R0` never
reaches an address computation; it goes live the moment anyone extends the trace.
Concretely: `0x013BAE mov #-120,r0` must give −120, not +136. Getting it wrong
puts boost error at `0xFFFF5DA0` instead of `0xFFFF5CA0` — wrong by exactly 256,
consistently, at every site.

**(b) `_TYPECODE_WIDTH` (line 351) is incomplete.** `0x0BE830` dispatches on the
byte at descriptor+2 (`0BE83C mov.b @(2,r4),r0 / 0BE840 mova / 0BE842
mov.l @(r0,r3),r2`) through a **five**-entry table at `0x0BE860`, read from ROM as
`0xBEACC, 0xBEB20, 0xBEB6C, 0xBEAE4, 0xBEB00` = float, uint8, uint16, **signed
int8**, **signed int16**. Add `0x0C00 -> 1` and `0x1000 -> 2`.

**(c) Descriptor typecode is DEAD for six of the eight lookups.** `0x0BE874`,
`0x0BE88C`, `0x0BE8AC`, `0x0BE8C4`, `0x0BE928`, `0x0BE944` **hardcode** the cell
width and never read descriptor+16 — verified: `0BE8AC … 0BE8B6 bsr 0x0BEB6C`
(the u16 cell fetch, `0BEB6E shll r0 / 0BEB74 mov.w @r1+,r0`), and `0BE944 …
0BE94E bsr 0x0BEC78 … 0BE956 extu.w r0,r0`. Descriptors consumed by these carry
a **dead** `0x0000` typecode.

This is why `0xD106C` (Injector Latency) and `0xD3C2C` (Rough Correction
Learning Delay) were flagged CONFLICT. **They are false conflicts — the
definitions are right.** `0xD106C`: 15 uint16 = 12588/6857/4499/3225/2693 ×3
→ ×0.00025 = 3.147/1.714/1.125/0.806/0.673 ms, textbook dead time falling with
voltage across the 6.5…16.5 V axis; at 4 bytes/cell the 60-byte extent would
overlap the next descriptor's axis at `0xD108C`. `0xD3C2C`: 10 uint16 = stock
32,32,32,32,40,48,56,64,72,80 and 20.19b 16,16,16,16,20,24,28,32,36,40 (exactly
halved — a coherent edit); as float the same bytes are 2.9e-39 denormals, and
10×2 = 20 bytes abuts the next descriptor's data at `0xD3C40` exactly.

*Fix:* back-trace the descriptor through the pool (D1 already does this) and
suppress the bytes/cell claim when the consumer is one of the six
width-hardcoded entry points. 63 pool references vs 322 to the
typecode-dispatching `0x0BE830`/`0x0BE8E4`.

**(d) Contradiction test (a) matches prose, not type annotations** (item 21).
*Fix:* require the word inside the parenthesised type slot, which is how every
genuine claim in `ram_reference.txt` is written — `(float)`, `(float, g/s)`,
`(float, -40..120 C)` — e.g. `re.search(r'\(\s*(?:[^)]*,\s*)?float\b', ...)`.

**(e) D3 follows only two of the eight lookup entry points.** `trace_axis_feeds`
knows `0x0BE830` and `0x0BE8E4`. Every table whose cells are integers is
invisible to it — which is exactly why the Injector Latency battery-voltage feed
never appeared. The printed headline "93 RAM variables" also double-counts:
it is `len(fr4) + len(fr5)` (line 688), and variables appearing in both are
counted twice.

### The binding limit on this whole method

The definition XMLs name only **211 of the ~780 descriptor axes**. Every unnamed
axis is a lost vote, and roughly 60 traced variables reach only unnamed axes and
therefore get envelope evidence at best. **Naming more axes in
`definitions/AE5L600L*.xml` converts directly into settled RAM identities** and
is higher-leverage than any further tracer work.

---

## 24. `0xC0BCC` was declared uint16 but the ROM reads it as a float — **FIXED 2026-07-26**

`definitions/AE5L600L 2013 USDM Impreza WRX MT.xml`, table
"Boost disable during fuel cut-Load threshold", had
`scaling="EngineLoad(g/rev)"` — a **uint16** scaling
(`32BITBASE.xml:79`, toexpr `x*.00006103516`).

This address is reached by a **raw literal**, not a descriptor: `0x0C0BCC`
appears exactly once in the pools, at `0x014268`.

```
0141DE: D21D  mov.l @(0x014254),r2   ; = 0xFFFF620C  manifold pressure
0141E0: FE28  fmov.s @r2,fr14
0141E2: D21D  mov.l @(0x014258),r2   ; = 0xFFFF63F8  ENGINE LOAD
0141E4: FF28  fmov.s @r2,fr15
0141E6: D21D  mov.l @(0x01425C),r2   ; = 0xFFFF6624  rpm
0141E8: FC28  fmov.s @r2,fr12
0141F0: D61C  mov.l @(0x014264),r6   ; = 0x000C0BC8
0141F2: F868  fmov.s @r6,fr8
0141F4: F8E5  fcmp/gt fr14,fr8       ; vs MAP
0141FA: D61B  mov.l @(0x014268),r6   ; = 0x000C0BCC
0141FC: F868  fmov.s @r6,fr8         ; <-- FLOAT read
0141FE: F8F5  fcmp/gt fr15,fr8       ; vs ENGINE LOAD
014202: D61A  mov.l @(0x01426C),r6   ; = 0x000C0BD0
014204: F868  fmov.s @r6,fr8         ; vs rpm
```

The two siblings read exactly the same way were **already** declared float
(`c0bc8` barpressureabsolute, `c0bd0` LCRPM). Only `c0bcc` was not.

Bytes at `0xC0BCC` = `3F D9 99 99` = float **1.70 g/rev**. Read the declared way
(uint16 `0x3FD9` × .00006103516) it showed **1.00 g/rev** — a plausible-looking
number, which is why the error survived.

**Fix applied:** `scaling="g/rev"` (`32BITBASE.xml:250`, float, toexpr `x`).
Identity toexpr is required: the code compares the raw float against the raw
float at `0xFFFF63F8`. The shared base scaling `EngineLoad(g/rev)` was **not**
touched. Displayed value goes 1.00 → **1.70 g/rev**.

This function is also the threshold-pairing corroboration for three settled
identities at once: MAP → `0xFFFF620C`, load → `0xFFFF63F8`, RPM → `0xFFFF6624`.

---

## 25. `0xD6214` was declared float but the ROM reads it as uint16 — **FIXED 2026-07-26**

Table "Idle Airflow Min Target Decel Initial Idle Activation Max Mode Counter"
inherited `scaling="rawecuvalue"` from `32BITBASE.xml:5373`, which is **float**.

Never reached by a descriptor — only by raw literals (pool slots `0x50998`,
`0x50C98`, `0x50DB8`). All six dereference sites are `mov.w`:

```
0507CA: D273  mov.l @(0x050998),r2   ; = 0x000D6214
0507CC: 6621  mov.w @r2,r6
0507CE: 3062  cmp/hs r6,r0           ; unsigned compare against a counter
...
050CF0: D631  mov.l @(0x050DB8),r6
050CF2: 6261  mov.w @r6,r2
050CF4: 662D  extu.w r2,r6
050CF6: 3563  cmp/ge r6,r5
```
plus `0x0507DC`, `0x050B2C`, `0x050B44`, `0x050D0E`. **Zero `fmov.s`.**

Bytes `0xD6214` = `00 12` = uint16 **18 counts**. Read the declared way the four
bytes `00 12 00 08` are float 1.653e-39 — a **denormal** the ECU never uses — and
the 4-byte extent also swallowed the separate uint16 at `0xD6216` (= 8), which is
why `defs.covering(0xD6216)` returned this table.

**Fix applied:** a new local scaling `rawecuvalue(uint16)` (identity toexpr,
uint16) and `scaling="rawecuvalue(uint16)"` on the table. The base `rawecuvalue`
was **not** touched — 50 base tables reference it and they are genuinely float.
Displayed value goes 0.0 → **18 counts**.

*Side effect:* `0xD6216` (uint16 = 8) is freed and becomes an honest UNMAPPED
word needing its own table.

---

## 26. New table binding: Front AF Sensor Smoothing Table at `0xD92A0` — **ADDED 2026-07-26**

`0xD92A0` was UNMAPPED. Descriptor `0x0AF4C4`, raw bytes:

```
00 04 00 04 | 00 0D 92 80 | 00 0D 92 90 | 00 0D 92 A0 | 00 00 00 00
counts 4 x 4 | axis1 d9280 | axis2 d9290 | data d92a0 | typecode 0x0000 (float)
```

`32BITBASE.xml:5291` declares `Front AF Sensor Smoothing Table` as 3D with
X axis "Smoothed MAF" (4 elements, `g/s`) and Y axis "Engine Load"
(4 elements, `g/rev`). Byte checks against that template:

* axis1 = 20, 26, 32, 44 → plausible g/s
* axis2 = 0.6, 0.75, 0.975, 1.2 → g/rev, matching the load range exactly
* data = 0.05 … 0.90 → through `SmoothingFactor` toexpr `(x*(-100))+100` =
  10 % … 95 %, inside the range the base description warns about
  ("DO NOT SET TO 100% or higher")

**Verified against code, not geometry alone.** The descriptor has exactly one
pool reference (`0x058A54`), and its consumer is:

```
058946: D241  mov.l @(0x058A4C),r2   ; = 0xFFFF63CC
058948: F428  fmov.s @r2,fr4         ; FR4 -> axis1 (Smoothed MAF)
05894A: D241  mov.l @(0x058A50),r2   ; = 0xFFFF63F8  ENGINE LOAD (settled item 9)
05894C: F528  fmov.s @r2,fr5         ; FR5 -> axis2 (Engine Load)
05894E: D441  mov.l @(0x058A54),r4   ; = 0x000AF4C4  descriptor
058950: D241  mov.l @(0x058A58),r2   ; = 0x000BE8E4  2D float lookup
058952: 420B  jsr @r2
058958: F20A  fmov.s fr0,@r2         ; result -> 0xFFFF8DE0
```

The settled engine-load address lands on the axis the base names "Engine Load".
That is the same mechanical check that settled item 9, applied in reverse.

**Caveat recorded in the XML:** the FR4 side comes from `0xFFFF63CC`, whose own
identity is UNRESOLVED (item 23). That does not affect the binding, only the
interpretation of the X axis.

No other proposal from the block triage was applied. Everything else in that
pass was geometry-only, and geometry without a code-verified axis feed is not
enough to name a table here.

---

## 27. Five verified defects in `coverage_map.py` — **FIXED 2026-07-26**

The flag tool itself had bugs, two of which manufactured **false** CONFLICTs.
Found during the semantic-layer pass and deliberately reported rather than
patched mid-run; fixed afterwards. `CONFLICT` went **3 → 0** and the RAM→axis
trace broadened from 93 variables / 572 sites to **98 / 638**.

| # | Defect | Effect |
|---|---|---|
| a | `mov #imm,Rn` read unsigned | SH-2E **sign-extends**. `mov #-120,r0` became +136, shifting computed RAM addresses by exactly 256 — self-consistently, so it looked right. Latent, would have gone live on any trace extension. Same class as item 7. |
| b | `_TYPECODE_WIDTH` missing two cases | The dispatch table at `0x0BE860` has **five** entries — float, uint8, uint16, **signed int8, signed int16**. `0x0C00`→1 and `0x1000`→2 were dropped. |
| c | Dead typecodes treated as width claims | Six of the eight lookup routines (`0xBE874/88C/8AC/8C4/928/944`) **hardcode** cell width and never read the descriptor typecode, so those descriptors carry a dead `0x0000` — which decodes as "4 bytes/cell, float". **Caused both remaining table conflicts.** Now the tool records which routine consumes each descriptor and suppresses the claim when every consumer is width-hardcoded. |
| d | `float` matched corrective prose | The float-vs-access-width test matched the word inside *"NOT a float"* / *"0 float accesses"*, so every address just corrected re-flagged itself against its own correction note. Now requires the parenthesised type slot: `(float)`, `(float, g/rev)`. |
| e | Trace followed only 2 of 8 lookup routines | Every **integer-celled** table was invisible — which is why the Injector Latency battery-voltage feed (`0xFFFF4130`) never appeared. |

Defect (c) is the instructive one: the tool was reading a field the ROM's own
code never reads. `0xD106C` (Injector Latency_) and `0xD3C2C` (Rough Correction
Learning Delay) were **correct all along** and were nearly "corrected" into being
wrong — a fifth wrong-direction correction, caught by the agent refusing to
apply a fix it could not fully justify.

Both now read `VERIFIED-BYTES` with an explicit note naming the consuming
routine, so the reasoning is visible rather than silently suppressed.
