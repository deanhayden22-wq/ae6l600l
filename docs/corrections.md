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

## 24. `0xC0BCC` was declared uint16 but the ROM reads it as a float — **FINDING STANDS, EDIT REVERTED**

> **Status 2026-07-26:** the XML edit was applied and then **reverted** at the
> owner's request — ECUFlash round-trips these files, so repo-side edits are
> lost on its next save and the two copies silently diverge. The *finding*
> below is unaffected and verified from bytes; only the edit was rolled back.
> `c0bcc` still displays 1.00 g/rev in ECUFlash where the true value is 1.70.
> Deliberately left alone: not a table this project tunes.

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

## 25. `0xD6214` was declared float but the ROM reads it as uint16 — **FINDING STANDS, EDIT REVERTED**

> **Status 2026-07-26:** as item 24 — the XML edit was reverted; the
> byte-level finding below is unaffected.

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

## 26. New table binding: Front AF Sensor Smoothing Table at `0xD92A0` — **PROPOSED, NOT IN THE XML**

> **Status 2026-07-26:** the binding was added and then **reverted** with the
> rest of the definition edits. The geometry evidence below stands; re-apply
> it in ECUFlash's UI rather than the repo XML if it is wanted.

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

---

# Third pass, 2026-07-27 — items 28 to 35: the MAF hunt, and the deferred cases

Item 23 left eleven identities deferred and said the axis-name method had hit its
binding limit (the XMLs name only ~211 of ~780 descriptor axes). Two **new
instruments** broke that limit. Neither depends on a definition axis *name*, so
both can be used to arbitrate when the axis names themselves are wrong — which,
for the first time in this project, turned out to matter.

### Instrument A — the SSM getter table at `0x06423C`

`docs/ssm-read-patch.md` documents that the *stock* SSM handler bounds-checks the
requested "address" against 848 and uses it as an **index into a function-pointer
table at `0x06423C`**. Those 848 getters had never been read. Each is a tiny leaf:

```
05D3AC  sts.l pr,@-r15
05D3AE  mov.l @(0x05D5B8),r2   ; = 0xFFFF63C4      <-- the RAM address
05D3B0  fmov.s @r2,fr4         ; FR4 = value
05D3B2  mov.l @(0x05D598),r2   ; = 0x000BE5D8
05D3B4  fldi0 fr6              ; FR6 = offset = 0.0
05D3B6  mova @(0x05D5BC),r0    ; -> 0.01
05D3B8  jsr @r2
05D3BA  fmov.s @r0,fr5         ; delay slot: FR5 = scale = 0.01
```

and `0x0BE5D8` / `0x0BE5A8` are both `clamp_u16(round((FR4 - FR6) / FR5))`,
verified from bytes (`fsub fr6,fr4` / `fdiv fr5,fr4` / `fadd 0.5` / `ftrc` /
clamp against `0x0000FFFF` and 0).

**The address a getter reads is the ECU's own copy of that logged quantity, and
the offset/scale pair is its unit conversion.** Four settled identities reproduce
exactly, which is the self-check:

| PID | getter | RAM | offset / scale | agrees with |
|---|---|---|---|---|
| `0x0E`/`0x0F` | `0x05D334` | `0xFFFF6624` | 0 / 0.25 | settled RPM; `logcfg` `x,4,/` |
| `0x29` | `0x05D4F8` | `0xFFFF64D8` | 0 / 0.392157 | settled pedal (item 13); `logcfg` `x,100,*,255,/` |
| `0x0D`, `0x24` | `0x05D31E`, `0x05D4BC` | `0xFFFF620C` | 0 / 7.5006 | settled MAP (item 9) |
| `0x1C` | `0x05D43E` | `0xFFFF4130` | 0 / **0.08** | settled battery voltage (item 10) |

Four for four, from an instrument that was not used to derive any of them.

### Instrument B — threshold pairing against named calibration **tables**

Item 9 used threshold pairing against *scalars*. Extending it to definition-named
**tables** (`scripts/defs.py` supplies the name *and* the scaling) is much
stronger, because the scaling states the units.

---

## 28. `0xFFFF63C4` is **MASS AIRFLOW (g/s)** — the MAF variable, found at last — **FIXED 2026-07-27**

`ram_reference.txt` and `ImportAE5L600L.java` called it `ect_compensation`. Item
23 listed it under "genuinely unresolved" with a three-way axis split.

**Proof 1 — SSM.** Getter-table entry `0x13`/`0x14` is SSM *Mass Airflow*
(`logs/logcfg.txt`: `paramname = MAF`, `paramid = 0x000013`, `databits = 16`,
`scalingrpn = x,100,/`). Its getter `0x05D3AC` is quoted in full above: it reads
`0xFFFF63C4` with offset 0 and scale 0.01, so the transported word is
`value * 100` and `logcfg`'s `/100` returns **`value` in g/s unchanged**.

**Proof 2 — threshold pairing.**

```
034D52: D245  mov.l @(0x034E68),r2   ; pool 034E68 = 0xFFFF63C4
034D54: F828  fmov.s @r2,fr8         ; FR8 = mass airflow
...                                    (FR8 not rewritten; only int ops + branches)
034D76: D240  mov.l @(0x034E78),r2   ; = 0x000CC074
034D78: F928  fmov.s @r2,fr9
034D7A: F985  fcmp/gt fr8,fr9        ; T = (FR9 > FR8), i.e. MAF < threshold
034D7E: D23F  mov.l @(0x034E7C),r2   ; = 0x000CC078
034D8A: D23D  mov.l @(0x034E80),r2   ; = 0x000CC07C
```

`0xCC074` is the definition table **`A/F Learning #1 Airflow Ranges`**, scaling
`MassAirflow(g/s)1`, values **5.6 / 10.0 / 50.0**. The block is a 4-bin airflow
classifier gated by `0xCC070` = 1.6 and `0xCC080` = 80, result written to
`0xFFFF787F` — already named `afl_airflow_range_idx` in the corpus.

**Proof 3 — the producer.** See item 29: `0xFFFF63C4` is written as
`min(MAF x IATcomp, MAF Limit (Maximum))`, and `MAF Limit (Maximum)` (`0xC3100`)
is stock **300.0 g/s**.

**Proof 4 — the logs.** `logs/7-26 20.19b/` MAF spans **2.40 … 296.24 g/s**; the
widest axis `0xFFFF63C4` feeds is **0..300**.

### The three-way split is resolved — and it was NOT a tracer artefact

Item 23 offered two explanations and said control-flow-aware tracing would
decide. It decided against both: the split survives, because **two of the three
axis NAMES are wrong in `32BITBASE.xml`.**

```
031DD0: D25A  mov.l @(0x031F3C),r2   ; pool 031F3C = 0xFFFF63C4
031DD2: FE28  fmov.s @r2,fr14        ; FR14 = mass airflow   (loaded ONCE)
031DD4: D254  mov.l @(0x031F28),r2   ; = 0xFFFF6624 rpm
031DD6: FF28  fmov.s @r2,fr15
031E16: F4EC  fmov fr14,fr4  / 031E18: 4A0B jsr @r10 / 031E1A: F5FC fmov fr15,fr5
031E36: F4EC  fmov fr14,fr4  / 031E38: 4A0B jsr @r10 / 031E3A: F5FC fmov fr15,fr5
031E6A: F4EC  fmov fr14,fr4  / 031E6C: 4A0B jsr @r10 / 031E6E: F5FC fmov fr15,fr5
```

FR14 is written exactly once, at `0x031DD2`, and never again in the function;
FR12–FR15 are callee-saved and were spilled at entry (`0x031DC4`–`0x031DCA`), so
the three intervening `jsr`s cannot clobber it. The three descriptors decode as:

| desc | counts | axis0 (fed by FR14) | definition name for axis0 | axis1 (fed by FR15 = RPM) |
|---|---|---|---|---|
| `0x0AD620` | 10 x 9 | `0xCF9EC` | `Intake Duty Correction A / **Intake VVT Error**` | `0xCFA14` Engine Speed 650…3600 |
| `0x0AD848` | 10 x 9 | `0xD11D0` | `Exhaust Duty Correction A / **Exhaust VVT Error**` | `0xD11F8` Engine Speed 650…3600 |
| `0x0AD864` | 8 x 9 | `0xD12D0` | (unnamed) | `0xD12F0` |

**One value cannot be both the intake VVT error and the exhaust VVT error.** The
descriptors match the project XML's own bindings exactly (data `0xCFA38` /
`0xD121C`, axes `0xCF9EC` / `0xD11D0`), so the *tables* are bound correctly and
only the axis **labels** are wrong. Both axes read `4, 6, 10, 15, 20, 25, 30, 40,
60, 80` — impossible as cam phase error (authority is ~50 crank degrees; 60 and 80
would be unreachable), and entirely ordinary as g/s across the 650…3600 RPM
sibling axis. Intake/Exhaust Duty Correction A are **f(mass airflow, engine
speed)**.

This is the first case where the axis-name method's own input was shown wrong,
and it is exactly why Instruments A and B matter: the axis-name vote here was 1
for MAF and 2 against, and the *minority* was right.

> **The definition XMLs were NOT edited.** ECUFlash owns them (items 24–26). The
> observation is recorded here and in `ram_reference.txt` only.

Renamed `mass_airflow_gps` in `ram_reference.txt` and `ImportAE5L600L.java` —
**all three duplicate `labelComment` blocks** (`ect_compensation` appeared 3x;
per item 1, a later stale block silently overwrites the corrected one in Ghidra).

---

## 29. The complete MAF pipeline — **ADDED 2026-07-27**

Every step re-derived from `rom/ae5l600l.bin` bytes.

```
0xFFFF4042  uint16 ADC counts        <- SSM PID 0x1D source (getter 0x05D454)
   |  004A32 mov.w @r4,r4 ; 004A3E float fpul,fr3 ; 004A44 fmul fr2,fr4
   |  FR2 = *(0x004A80) = 7.629394531e-05 = 5.0/65536      => VOLTS (never stored)
   v
   |  004A42 jsr 0x0BE830 with r4 = 0x0AF45C
   |    descriptor 0x0AF45C = count 54 / axis 0xD8BC4 / data 0xD8C9C
   |    == definition "MAF Sensor Scaling" (54 g/s) over axis "MAF sensor"
   |       (54 volts, 0.898 .. 5.000)   <-- element counts match exactly
   v
0xFFFF40B4  instantaneous g/s        004A46 mov.l @(0x004A8C),r2 ; 004A4C fmov.s fr0,@r2
   |  0203E0 -> 0xFFFF63B4 -> 0xFFFF6424
   v
0xFFFF63B8 / 0xFFFF63BC   2-entry sample shift register (0x01FF00-0x01FF14)
   |  01FF2A fadd fr9,fr8 ; 01FF30 fmul fr4,fr8 with *(0x020090) = 0.5
   v
0xFFFF63C0  = 0.5*(63B8+63BC)        01FF34 fmov.s fr8,@(r0,r1)  r1=0xFFFF6430 r0=-112
   |  01FF3A fmov.s @(r0,r1),fr5 ; 01FF3E jsr 0x0BE8E4 with r4 = 0x0AAFE8
   |    descriptor 0x0AAFE8 = counts 5 x 8 / axis0 0xC3B7C / axis1 0xC3B90 / data 0xC3BB0
   |    axis1 0xC3B90 == "MAF Compensation (IAT) / Mass Airflow" (1.6 .. 290 g/s)
   |    axis0 0xC3B7C == "... / Intake Temperature"    -> comp factor -> 0xFFFF63F0
   |  01FF56 fmac fr0,fr8,fr14   (FR0 = 0xFFFF63C0, FR8 = comp factor)
   |  01FF5E jsr 0x0BE970 (float_MIN, item 1) with FR5 = *(0x0C3100)
   |    0xC3100 == "MAF Limit (Maximum)"   stock 300.0 g/s, 20.19c 475.0 g/s
   v
0xFFFF63C4  THE MAF (g/s)            01FF66 fmov.s fr0,@(r0,r1)  r0=-108
   |  == SSM PID 0x13/0x14  == the logged MAF channel (2.40 .. 296.24 g/s)
   |  020490 jsr 0x0BEA40 with FR4 = 63C4, FR5 = 63CC, FR6 = *(0x0C3108) = 0.5
   v
0xFFFF63CC  smoothed MAF (g/s)       020496 fmov.s fr0,@(r0,r14)  r14=0xFFFF63D8 r0=-12
```

**`0xFFFF4042` renamed** `pMafSensorVoltage` -> `maf_sensor_adc_counts` (it holds
counts, not volts). **`0xFFFF40B4` renamed** `maf_raw_gs` -> `maf_instantaneous_gps`;
its old note "feeds FFFF6254 and FFFF620C" was wrong — `0xFFFF6254` is a byte flag
(item 17).

**The MAF *voltage* is never stored to RAM.** It exists only in FR4 across
`0x004A44`. Any file claiming a RAM address holds MAF volts is making a claim the
ROM does not support — see item 35.

---

## 30. `0xFFFF63CC` is SMOOTHED MASS AIRFLOW, not ECT — **FIXED 2026-07-27**

Was `ram_ECT`, "Coolant temperature / ECT (float)". Item 23 left it unresolved
with one named hit that later evaporated when the item-26 XML edit was reverted.
It does not need that label:

```
020472: DE68  mov.l @(0x020614),r14  ; = 0xFFFF63D8
020474: E0EC  mov #-20,r0
020476: FEE6  fmov.s @(r0,r14),fr14  ; FR14 = *(0xFFFF63C4)  = the MAF
020482: F4EC  fmov fr14,fr4          ; FR4 = new sample
020484: C766  mova @(0x020620),r0    ; -> 0.00457764
020486: FF08  fmov.s @r0,fr15
020488: F7FC  fmov fr15,fr7          ; FR7 = deadband epsilon
02048A: D266  mov.l @(0x020624),r2   ; = 0x000C3108
02048C: F628  fmov.s @r2,fr6         ; FR6 = alpha = 0.5
02048E: E0F4  mov #-12,r0
020490: 460B  jsr @r6                ; r6 = 0x000BEA40
020492: F5E6  fmov.s @(r0,r14),fr5   ; delay slot: FR5 = *(0xFFFF63CC), previous
020496: FE07  fmov.s fr0,@(r0,r14)   ; *(0xFFFF63CC) = result
```

`0x0BEA40` decoded from bytes is a **first-order lag filter**, not the
`float_lerp`/`rate_limit_interp` its old labels suggest: NaN/Inf reset via the
`0x7F800000` mask, then `fsub fr4,fr5` / `fldi1 fr0` / `fsub fr6,fr0` /
`fmac fr0,fr5,fr6` giving `(1-alpha)*(old-new) + new`, then a
`|new - result| < FR7` deadband that snaps to the new sample.

So `0xFFFF63CC = lag(0xFFFF63C4, alpha 0.5)` — **smoothed mass airflow**. This
independently confirms item 26's proposed binding of axis `0xD9280` as the
`Smoothed MAF` X axis (20 / 26 / 32 / 44 g/s) of the Front AF Sensor Smoothing
Table, from the *code* side rather than from the reverted XML label. Renamed
`maf_smoothed_gps`.

---

## 31. `0xFFFF40E0` is FRONT OXYGEN / AF SENSOR CURRENT (mA) — **FIXED 2026-07-27**

Was `ATU_output_ctrl`, "ATU output control register". Item 23 held it back at one
site. It now has two independent lines, and the single site turns out to be an
entire dedicated function:

```
058902: 4F22  sts.l pr,@-r15
058904: D24B  mov.l @(0x058A34),r2   ; = 0xFFFF40E0
058906: F428  fmov.s @r2,fr4         ; FR4 = value     (no branch, no call between)
058908: D44B  mov.l @(0x058A38),r4   ; = 0x000AF468
05890A: D24C  mov.l @(0x058A3C),r2   ; = 0x000BE830
05890C: 420B  jsr @r2
058910: D24B  mov.l @(0x058A40),r2   ; = 0xFFFF8DE4
058916: F20A  fmov.s fr0,@r2         ; store the resulting AFR
```

Descriptor `0x0AF468` = count **13** / axis `0xD8D74` / data `0xD8DA8` — exactly
the definition `Front Oxygen Sensor Scaling` (13 elements, `Air/FuelRatio`
11.15 … 20.28) over axis `Front Oxygen Sensor` in **mA**, breakpoints
-1.3 … +0.74.

Second, independent: SSM getter-table entry `0x42` (`0x05D726`) reads the same
address with **FR6 = -16.0, FR5 = 0.125**, so `value = (raw - 128) x 0.125` over
`[-16, +15.875]` — a signed bipolar current in the same units and sign convention
as the axis. A hardware output-control register is not read as a float and used
as a table index. Renamed `front_o2_sensor_ma`.

---

## 32. Three idle / engine-speed identities settled — **FIXED 2026-07-27**

### `0xFFFF4150` = ENGINE SPEED from the crank tooth period

Item 23 held this at "single site". The **producer and the consumer** settle it
without using any axis name:

```
007B9E: 425A  lds r2,fpul            ; r2 = accumulated tooth period
007BA2: F32D  float fpul,fr3
007BA4: F208  fmov.s @r0,fr2         ; *(0x007C04) = 1.2e8
007BA6: F233  fdiv fr3,fr2           ; FR2 = 1.2e8 / period  -> a FREQUENCY
007BAA: D317  mov.l @(0x007C08),r3   ; = 0xFFFF4150
007BAC: F32A  fmov.s fr2,@r3
```

```
0232B4: D294  mov.l @(0x023508),r2   ; = 0xFFFF4150
0232B6: F828  fmov.s @r2,fr8
0232B8: DC94  mov.l @(0x02350C),r12  ; = 0xFFFF6648
0232BA: E0DC  mov #-36,r0
0232BC: FC87  fmov.s fr8,@(r0,r12)   ; 0xFFFF6648-36 = 0xFFFF6624
```

**`0xFFFF6624` — the settled `rpm_current` — is a straight copy of this address.**
Third line of support: it is the FR4/axis0 input of descriptor `0x0AF4B0`, axis
`0xD918C` = `Ignition Dwell / Engine Speed` (500…8000), the same call whose
FR5/axis1 is the settled battery voltage `0xFFFF4130` (item 10) — dwell as
*f*(RPM, volts) is the textbook form. Named `rpm_from_tooth_period`.

### `0xFFFF6634` = ENGINE SPEED DELTA (low-pass filtered)

```
r12 = 0xFFFF6648 ; r11 = 0xFFFF67AC
023362: F8C6  fmov.s @(r0,r12),fr8   ; r0=-36 -> 0xFFFF6624, the settled RPM
023366: F9B6  fmov.s @(r0,r11),fr9   ; r0=+16 -> 0xFFFF67BC, the reference speed
023368: F891  fsub fr9,fr8           ; RPM - reference
02336C: F9C6  fmov.s @(r0,r12),fr9   ; r0=-20 -> 0xFFFF6634, previous
02336E: F890  fadd fr9,fr8
023374: F892  fmul fr9,fr8           ; *(0x023544) = 0.5
023378: FC87  fmov.s fr8,@(r0,r12)   ; 0xFFFF6634 = 0.5*((RPM-ref) + previous)
```

A low-pass-filtered difference against the settled RPM, and 2 of 2
definition-named axes agree: `0xD7EC4` / `0xD8060`, both `Idle Speed Stability
A/B / Engine Speed Delta` (-50…50), reached from `0x051D7A fmov.s @r2,fr14` /
`0x051DB4 fmov fr14,fr5` / `0x051DB6 jsr 0x0BE8E4`. Named `engine_speed_delta`.

### `0xFFFF89C8` = IDLE SPEED ERROR

It is computed as a difference **one instruction before** it is used as the axis:

```
051D88: D19C  mov.l @(0x051FFC),r1   ; = 0xFFFF89C8
051D8C: F816  fmov.s @(r0,r1),fr8    ; r0=-28 -> 0xFFFF89AC
051DA2: D69A  mov.l @(0x05200C),r6   ; = 0xFFFF895C
051DA4: F968  fmov.s @r6,fr9
051DA6: F891  fsub fr9,fr8           ; a DIFFERENCE
051DAA: D499  mov.l @(0x052010),r4   ; = 0x000AF0C8
051DAC: 8F01  bf/s 0x051DB2
051DAE: F18A  fmov.s fr8,@r1         ; delay slot: *(0xFFFF89C8) = the difference
051DB0: D498  mov.l @(0x052014),r4   ; = 0x000AF0AC   (the other path)
051DB4: F5EC  fmov fr14,fr5          ; FR5 = 0xFFFF6634 (engine speed delta)
051DB6: 420B  jsr @r2                ; = 0x000BE8E4
051DB8: F418  fmov.s @r1,fr4         ; delay slot: FR4 = the value just stored
```

Both path descriptors' axis0s are definition-named `Idle Speed Error`
(`0xD7E80` / `0xD801C`, -150…600) — 2 of 2. Named `idle_speed_error`.

> **Tool defect, recorded not fixed:** `coverage_map.quantity_of("Idle Speed
> Error")` returns `vehicle_speed`, because the `vehicle_speed` pattern contains a
> bare `\bspeed\b`. Same class as item 27(d). It would flag a *correct*
> `idle_speed_error` name as CONFLICT via contradiction test (b). Not patched in
> this commit, for the reason item 23 gave: do not change the instrument in the
> commit that reports the measurement.

---

## 33. `0xFFFF69F0` is a 0..1 RATIO — the IAT claim is refuted outright — **FIXED 2026-07-27**

Item 9 said "Real IAT is `0xFFFF69F0`"; item 23 **retracted** that but left the
name in place because the write path had not been found. The name is now refuted
positively, not merely unsupported:

```
0272CE: D283  mov.l @(0x0274DC),r2   ; = 0x000BE56C
0272D0: F69D  fldi1 fr6              ; hi = 1.0
0272D2: F58D  fldi0 fr5              ; lo = 0.0
0272D4: D682  mov.l @(0x0274E0),r6   ; = 0xFFFF69F0
0272D6: 420B  jsr @r2
0272D8: F468  fmov.s @r6,fr4         ; delay slot: FR4 = *(0xFFFF69F0)
```

`0x0BE56C` is `clamp(FR4, lo=FR5, hi=FR6)`, verified from bytes
(`F455 fcmp/gt fr5,fr4` -> `T = (FR4 > FR5)`, then `F645` -> `T = (FR6 > FR4)`).
So the value is **clamped to [0.0, 1.0]**; repeated at `0x0273BA`. Its only store
sets it to exactly 1.0 (`0273E0 fldi1 fr8` / `0273E6 fmov.s fr8,@r2`).

A value clamped to [0,1] cannot be a -40…120 °C temperature. Full control-flow
tracing finds 4 sites, all the *same* unnamed 0..1 axis `0xC4514`, and **zero**
Intake Temperature axes — while `0xFFFF6364` (item 12) reaches 9.

Renamed to the neutral `ratio_0to1_69F0`. **Which** ratio it is remains
UNRESOLVED and is deliberately not guessed. Real IAT is `0xFFFF6364`; the stale
"Real IAT is 0xFFFF69F0" cross-reference in the `0xFFFF63F8` comment block of
`ImportAE5L600L.java` was corrected in the same pass.

---

## 34. `0xFFFFA198` is an ENGINE SPEED snapshot, not EGR diag state — **FIXED 2026-07-27**

Item 23 had it at "36 rpm-shaped axes, none NAMED — envelope only", which by this
project's own rule is not enough for a rename. It does not need an axis name:

```
075934: D248  mov.l @(0x075A58),r2   ; = 0xFFFF6624  (settled RPM)
075936: F828  fmov.s @r2,fr8
075938: D243  mov.l @(0x075A48),r2   ; = 0xFFFFA198
07593A: F28A  fmov.s fr8,@r2         ; *(0xFFFFA198) = RPM
```

and identically at `0x075CA2` / `0x075CA6` / `0x075CA8`. Two independent straight
assignments from the settled RPM variable, corroborated by 53 lookup sites across
10 functions whose axes are all RPM-shaped (700…6700, 750…6700, 4000…6700,
3500…7000) with zero dissent.

The old `egr_diag_state` name came from `0xFFFFA198` *also* being loaded into GBR
(`0x0758E8`, `0x075C54`) as a struct base. That describes the **struct**; the
float at offset 0 is an RPM snapshot. Renamed `rpm_snapshot_A198`, with the
struct role kept in the description so nothing is lost.

---

## 35. NOT corrected — `0xFFFF5FFC` and `0xFFFF6228`: names refuted, replacements unknown

Both names are now positively refuted. Neither is renamed: a neutral name would
discard information, and a physical one would be a guess.

### `0xFFFF5FFC` `io_state_register`

A struct base loaded into GBR (`0x018DDA mov.l @(0x019008),r0` / `0x018DDC ldc
r0,gbr`) **and** a float read 26 times, feeding 15 numeric lookup axes spanning
0..250 across 5 functions. An I/O state register is not read as a float and used
as a table index. All 15 axes — `0xC2408`, `C242C`, `C24AC`, `C24F8`, `C2510`,
`C25A4`, `C2614`, `C2764`, `C277C`, `C2794`, `C27AC`, `C2CC8`, `C2D24`, `C2F88` —
are UNNAMED in both definition XMLs. *What would settle it:* name any one of them.

### `0xFFFF6228` `maf_voltage`

The real MAF voltage is `0xFFFF4042 x 5/65536` and is **never stored to RAM**
(item 29). `0xFFFF6228` has a different source and a different scale — it is its
own GBR base (`0x01D8FC` / `0x01D8FE ldc r0,gbr`), and:

```
01D94A: D210  mov.l @(0x01D98C),r2   ; = 0x000BE598  (u16 -> float: FR5 + FR4*x)
01D94C: C50F  mov.w @(30,gbr),r0     ; the uint16 at 0xFFFF6246
01D950: F58D  fldi0 fr5
01D954: 420B  jsr @r2
01D956: F408  fmov.s @r0,fr4         ; *(0x01D990) = 0.0305176
01D95A: F20A  fmov.s fr0,@r2         ; *(0xFFFF6228) = counts * 0.0305176
```

Second writer `0x01D6F0` / `0x01D6FA`, same constant. `0.0305176` is not
`5/65536`, so this is not a 0–5 V ADC conversion. It feeds **zero** lookup axes,
so the axis-name method has nothing to say either. UNRESOLVED.

### Still open from earlier passes, unchanged (as of pass 3)

* Which 0..1 ratio `0xFFFF69F0` is (item 33).
* Which monitor each settled byte flag belongs to (`0xFFFF4254`, `0xFFFF6254`,
  `0xFFFF65C0`, `0xFFFF8CFC`, `0xFFFF6C48`), and which DTC `0xFFFF67EC` /
  `0xFFFF8C98` mature.
* The `coverage_map.quantity_of` `\bspeed\b` defect (item 32).
* The binding limit itself: the XMLs still name only ~211 of ~780 descriptor
  axes. Item 28 adds a caveat that was not there before — **a named axis can also
  be wrong**, so a lone axis-name vote should be corroborated by an SSM getter, a
  threshold pairing, a producer/consumer assignment, or a log range before it is
  treated as settled.

---

# Fourth pass, 2026-07-28 — items 36 to 38: the injector-rescale sweep

Prompted by an upcoming injector swap. The question asked was narrow — "which
tables hold an injector pulse width" — and answering it from ROM bytes rather
than from table names turned up three errors, one of which would have sent the
rescale at a table that has nothing to do with fuelling.

The working list this produced is `docs/injector-rescale.md`; the tool is
`scripts/injector_rescale.py`.

---

## 36. `0xD39A8` "Low Pulse Width Fuel Injector Compensation" is NOT an injector table — its axis is RPM — **FIXED 2026-07-28**

This is a `0xC0BCC`-class error: a real generic Subaru table name from
`32BITBASE.xml`, bound by the project XML to an address that holds something
else entirely on this ROM.

**What the definitions claim.** `Fueling - Injector` category. Data `0xD39A8`,
8 x uint8, scaling `InjectorPulseWidthCompensation` = `(x*.78125)-100`, so the
factory contents (all raw `0x00`) display as **-100% on all eight cells**. Y
axis `0xD3988`, 8 x float32, scaling `BasePulseWidth(ms)` = `x*.001`, so raw
`700..4500` displays as **0.7 to 4.5 ms**. Two companion scalars,
`0xD2D28` "maximum RPM" and `0xD2D2C` "maximum IPW" (`x*.001` -> 10.0 ms).

Taken at face value that reads as: below 4.5 ms of pulse width, delete 100% of
the fuel, with the gate wide open at 10 ms / 10000 RPM. The car runs, so
something in that story is false.

**What the ROM says.** Descriptor `0x0AE000` = `00080000 000D3988 000D39A8
00060400` — 8 elements, axis `0xD3988`, data `0xD39A8`, typecode `0x0400`
(1 byte/cell, per item 27b). It has **exactly one** literal reference in the
1 MB image, at `0x043558`, in the pool of the function at `0x043470`. So there
is one consumer and no other.

That function loads its inputs once, at entry, and never reloads them:

```
043472 mov.l @(0x043530),r2 / 043474 fmov.s @r2,fr8   ; fr8 = [0xFFFF62F8] torque_ratio
043476 mov.l @(0x043534),r2 / 043478 fmov.s @r2,fr9   ; fr9 = [0xFFFF65FC] vehicle speed
04347A mov.l @(0x043538),r2 / 04347C fmov.s @r2,fr4   ; fr4 = [0xFFFF6624] ENGINE SPEED
04347E mov.l @(0x04353C),r2 / 043480 fmov.s @r2,fr6   ; fr6 = [0xFFFF6350] ECT
```

and then calls the lookup with `fr4` still holding RPM:

```
0434C2 mov.l @(0x043558),r4   ; r4 = 0x000AE000  (the descriptor)
0434C4 mov.l @(0x04355C),r2   ; r2 = 0x000BE874
0434C6 jsr   @r2
0434CE mov.b r0,@r5           ; result byte -> [0xFFFF80EC]
```

`0xBE874` takes its axis input in **FR4** — verified from its own bytes:

```
0BE876 mov.w @(0,r4),r0     ; element count  <- descriptor+0
0BE878 mov.l @(4,r4),r1     ; axis pointer   <- descriptor+4
0BE87A bsr   0x0BECA8       ; axis search
0BE87C fmov  fr4,fr0        ; delay slot: THE SEARCH KEY IS FR4
0BE880 mov.l @(8,r4),r1     ; data pointer   <- descriptor+8
0BE88A extu.b r0,r0         ; returns a byte
```

`0xBECA8` in turn walks the axis array comparing each element against **FR0**
(`0BECAC fmov.s @(r0,r1),fr1 / 0BECAE fcmp/gt fr0,fr1`) and returns the
interpolated position `(fr0−fr1)/(fr2−fr1)`. So the key is FR0, which `0xBE874`
sets from FR4 in the delay slot. And FR4 is written exactly once in `0x043470`
— at `0x04347C` — and only read afterwards (`0x0434AE`, `0x0434B6`, both
`fcmp/gt`). It still holds RPM at the call.

`0xFFFF6624` is `rpm_current`: 301 references, the most-referenced float in the
ROM, an SSM-logged channel (`scale 0.25 = logcfg x/4`), settled long before this
item. The function also never touches `0xFFFF7324`
(`last_calc_base_pulse_width`), which is the ROM's actual base-pulse-width
variable and the feed a low-pulse-width compensation would necessarily use.

Two derived files reached the same conclusion independently and were never
reconciled with the XML: `descriptor_map.txt:545` records the axis range as
`[700.0..4500.0]`, and `named_descriptors.txt:680` types the descriptor
`1D_RPM_f32_8`.

### One argument used here originally was wrong — withdrawn

The first version of this item also argued that `700, 800, 900, 1400, 2000,
2500, 3500, 4500` is implausible as milliseconds ("0.1 ms steps at the bottom,
then a jump to 1.4"). **That is not a valid argument and it is withdrawn.**
`0.7/0.8/0.9/1.4/2.0/2.5/3.5/4.5` ms is precisely the shape a low-pulse-width
linearisation axis should have — fine resolution through the non-linear region,
coarse above it. Nor do the raw magnitudes discriminate: this ROM stores a
genuine millisecond axis as raw ×1000 (`0xD0760` holds `1000.0 … 16000.0` for
1–16 ms), so raw `700` = `0.7` ms is exactly the right convention.

The identity rests on the **feed**, and on the feed alone. Retaining a
plausibility argument that does not survive checking would repeat the exact
failure this project keeps hitting — see items 6, 8 and 12, all of which were
"corrections" applied on reasoning that felt right.

### The cheapest argument of all, needing no disassembly

Read the definition at face value: eight cells at **−100%**, `maximum RPM` =
10000, `maximum IPW` = 10.0 ms. Both gates always satisfied, so a 100% fuel cut
below 4.5 ms of pulse width, at every RPM. The car idles. The definition is
therefore not describing what this ECU does, whatever the correct reading turns
out to be.

**`0xD2D28` and `0xD2D2C` are both RPM bounds, and neither is an IPW.** Each has
exactly one literal reference (`0x04354C`, `0x043550`), both in this same pool,
and both are compared against `fr4`:

```
0434AA mov.l @(0x04354C),r2 / 0434AC fmov.s @r2,fr8   ; fr8 = [0xD2D28] = 10000.0
0434AE fcmp/gt fr4,fr8        ; T = (fr8 > fr4) = (10000 > RPM)
0434B0 bt  0x0434D0           ; -> exit.  continue requires RPM >= 0xD2D28
0434B2 mov.l @(0x043550),r2 / 0434B4 fmov.s @r2,fr8   ; fr8 = [0xD2D2C] = 10000.0
0434B6 fcmp/gt fr4,fr8        ; T = (10000 > RPM)
0434B8 bf  0x0434D0           ; -> exit.  continue requires RPM <  0xD2D2C
```

(`fcmp/gt FRm,FRn` sets T when FRn > FRm; `0xF845` is n=8, m=4. Operand order
was checked deliberately — reversing it is the mistake behind item 12.)

They form the half-open window `[0xD2D28, 0xD2D2C)` on RPM. Both hold 10000.0,
so the window is **empty** and the branch is unreachable. `0xD2D2C` displaying
as "10.0 ms" is an artefact of the XML applying `x*.001` to the number 10000.

**The rest of the function is map switching, not fuelling.** Its other gates are
`0xD2A0C` (0.8798) and `0xD2A1C` (80.0) — the same two constants
`map_switching_analysis.txt` names `MapSwitch_TorqueRatioThreshold` and
`MapSwitch_IATThreshold` at `0x03F49A` / `0x03F4CE`. It reads
`0xFFFF5BE3` (`clutch_state`, "task50 map switching" in `ram_reference.txt`) and
writes its result to `0xFFFF80EC`, which `ram_reference.txt:797` already calls
`timing_comp_lowpw_state` — *ignition* timing state, not fuel.

There is a second, independent kill: at `0x0434A6` the code tests
`fcmp/gt fr9,fr8` with `fr8 = [0xD2D24] = 0.0` and `fr9` = vehicle speed, then
`bf` to the exit. That is "continue only if `0.0 > vehicle_speed`" — never true.
The branch is dead twice over.

**Status.** Corrected in `disassembly/maps/disassembly.txt` (the LOW PULSE WIDTH
block and the two task summaries at Tasks 46/47) and in the do-not-touch list of
`scripts/injector_rescale.py`.

**The definition XML is NOT changed here.** ECUFlash owns those files and
rewrites them on save (see CLAUDE.md); a repo-side edit would be lost and would
diverge silently. The names `Low Pulse Width Fuel Injector Compensation`,
`… maximum RPM` and `… maximum IPW` are still wrong in
`definitions/AE5L600L 2013 USDM Impreza WRX MT.xml` and in `32BITBASE.xml`.
Fixing them means editing in the ECUFlash UI and pulling with
`.\scripts\sync_defs.ps1 -Pull` — and the repo is already ~37 tables ahead of
ECUFlash, so that pull needs checking first.

**Practical consequence.** Nothing to do for the injector swap, which is the
point: the all-`-100%` table looks exactly like a broken calibration begging to
be populated, and populating it would have written bytes into an ignition
timing state path.

---

## 37. Injector dead time was stated in microseconds, off by ~40x — **FIXED 2026-07-28**

`disassembly/analysis/injector_deadtime_analysis.txt` printed a "physical
interpretation" of `0xD106C` that divided the stored values by 16 and assumed a
~10 MHz ATU clock:

    6.5V -> 787 ticks ~ 78.7 us   ...   14.0V -> 201 ticks ~ 20.1 us

No port injector opens in 20 microseconds; a Subaru top-feed injector is roughly
0.7–1.1 ms at 14 V. The definition XML declares `Latency(ms)`, uint16,
`toexpr = x*.00025`, which gives **3.147 / 1.714 / 1.125 / 0.806 / 0.673 ms**
across the 6.5…16.5 V axis — a textbook dead-time curve, and the same reading
item 27(c) already used when it cleared this table of its false CONFLICT.

The `>>4` in the apply path (`0x00A152`, `0x00A0D2`) is real and does not
conflict: it shifts `(base_pulse_width + dead_time)` **as a pair**, so the stored
unit is 1/16 ATU tick and the tick works out at 4 us. That 4 us is derived from
the scaling, not read out of the ATU prescaler registers; the file now says so
rather than asserting a clock rate.

Also corrected in the same file: the secondary axis `0xD1060` `[-1000, 0, 1000]`
is raw; the XML scales it `psirelative` to ±19.34 psi, i.e. a fuel-pressure-delta
axis. All three rows are identical, so it is unused on this ROM.

---

## 38. Three CL/OL tables reported as "all zeros" were read as float32 — **FIXED 2026-07-28**

`cl_ol_analysis.txt`, `cl_ol_state_machine.txt` and
`cl_ol_comprehensive_review.txt` all stated that the delay-path thresholds were
empty. They are not. Every one had been read as float32 at stride 4, with the
element count inferred from that stride instead of taken from the definition:

| Address | Claimed | Actual (stock == 20.19c) |
|---|---|---|
| `0xCCD78` | all zeros | 16 x **uint8**, `x*.581287202` -> 86.03% x13, then 0,0,0 |
| `0xCE5F8` | 8 floats, all 0.0000 | 16 x **uint16**, `x*.004` -> 5.3, 5.3, 5.3, 5.7, 6.7, 6.6, 6.6, 6.5, 6.3, 5.6, 4.1, 3.6, 1.8, 0, 0, 0 ms |
| `0xCE640` | `[0,0,0,0,0,1,2,3]` | 10 x **uint16**, identity -> all 1s |

The mechanism is the same each time: `0xCE5F8`'s bytes are `05 2D 05 2D …`, and
`0x052D052D` as a float32 is `8.1e-36` — a denormal that prints as `0.0000` at
four decimal places. Nothing errored; the numbers just looked empty.

`0xCE640`'s scaling is literally named
`CLtoOLCounterIncrement(WARNING-value should NEVER be zero)`. Reporting zeros in
a table whose own name forbids them should have been read as a decode failure on
sight — that is the cheap tell this class of bug leaves behind.

The downstream conclusion in those files ("moot with delay=0") survives, because
`CL to OL Delay_` `0xCBC62` really is 0 in 20.19c (stock 750). But it rested on
the wrong premise. `0xCE5F8` matters for a different reason: it is the **only
absolute-pulse-width threshold in the whole CL/OL path**, so it belongs on the
injector-rescale list even though it is currently inert — if the delay is ever
re-enabled with unrescaled thresholds, the OL trigger moves.

### Also swept, not a numbered item

`map_switching_analysis.txt` labelled `0xFFFF65FC` `load_current` /
"Engine load (g/rev)" in two places while reading it as a vehicle speed in four
others. Item 9 settled it as vehicle speed; the two stale lines are corrected.
~~Left OPEN and flagged in the file: `0xD2A14`/`0xD2A18` hold 550.0 and 1300.0,
which are not km/h-shaped, so what those two actually gate is unresolved.~~
**CLOSED 2026-07-28 by item 38:** both are compared against `fr12` = RPM
(`0xFFFF6624`), not against speed. 550–1300 RPM is an idle band. The
definition names "Map Switching Vehicle Speed Low/High Threshold" are wrong,
and are project-invented rather than inherited from `32BITBASE.xml`.

### Still open after this pass

* Everything listed under pass 3 above.
* The three definition-XML names in item 36 (`0xD39A8`, `0xD2D28`, `0xD2D2C`) —
  correct in the repo's analysis layer, still wrong in the XMLs, and only
  fixable through ECUFlash.
* Whether `Per Injector Pulse Width Compensation A`–`D` are per-cylinder trims
  or a shared linearisation curve. They differ from each other in 151–249 of 289
  cells and sit at stock values, so they encode something real about the OEM
  injector — which means they are wrong for a different injector regardless of
  whether the ms axis is rescaled. See `docs/injector-rescale.md`.

---

## 38. The cruise/non-cruise blend ratio was the wrong address, and the whole subsystem was documented in the wrong place — **FIXED 2026-07-28**

Asked to walk through the cruise→non-cruise logic, the committed answer would
have been wrong in three structural ways at once. All three are corrected.

### (a) The ratio is `0xFFFF90A8`, not `0xFFFF7F60`

`map_switching_analysis.txt` (Sections 1, 2, 8), `torque_management_analysis.txt`
(Section 9 and two diagrams) and `ram_reference.txt` all named `0xFFFF7F60` as
the cruise/non-cruise blend ratio, with a sub-claim that "the actual blend ratio
output is at `0xFFFF7F4C`".

`0xFFFF7F4C` was already settled as ENGINE SPEED by item 22 — the file simply
never got updated. And `0xFFFF7F60` is a **uint16 counter**, read with `mov.w`:

```
04008E: C52A  mov.w @(84,gbr),r0    ; GBR = 0xFFFF7F0C, +0x54 => 0xFFFF7F60
040094: 3026  cmp/hi r2,r0          ; unsigned compare against [0xD29D4] = 88
```

The real ratio is `0xFFFF90A8`. It has **exactly one write site in the ROM**:

```
0611DE: D621  mov.l @(0x061264),r6  ; = 0xFFFF90A8
0611E0: F60A  fmov.s fr0,@r6
```

and is consumed by task 32 as a linear interpolation weight:

```
0401D6: F9F8  fmov.s @r15,fr9       ; fr9 = ratio
0401DC: F862  fmul fr6,fr8          ; fr8 = ratio * NonCruise
0401DE: F09D  fldi1 fr0
0401E0: F091  fsub fr9,fr0          ; fr0 = 1.0 - ratio
0401E6: F89E  fmac fr0,fr9,fr8      ; fr8 += (1 - ratio) * Cruise
```

`ram_reference.txt` called `0xFFFF90A8` `timing_dispatch_state`, and
`ignition_timing_analysis.txt` called it `timing_state`. Both renamed.

### (b) The decision is not in tasks 50/32/31/33

The subsystem was documented as four scheduler tasks in `0x3F368-0x410D4`. Only
task 32 is involved, and only as the *consumer*. The decision is a four-function
chain called back-to-back from one parent:

```
0605E6: B471  bsr 0x060ECC   ; evaluate condition, maintain dwell counter A
0605EA: B57C  bsr 0x0610E6   ; arm  -> writes 0xFFFF90C4
0605EE: B597  bsr 0x061120   ; re-entry lockout counter B
0605F2: B5AC  bsr 0x06114E   ; ramp 0xFFFF90A8 by +/-0.008, clamp [0,1]
```

Its calibration lives at `0xD9AC4-0xD9E26`, an area with **no ECUFlash
definitions at all**. The governing gate is a torque-domain value
(`0xFFFF85E4`) against two RPM-indexed hysteresis curves (`0xD9BE4` SET /
`0xD9C44` CLEAR, axes `0xD9BA4` / `0xD9C04`). In descriptor units:

| RPM | 300 | 400–1600 | 2000 | 2400 | 2800 | 3200 | 3600+ |
|---|---|---|---|---|---|---|---|
| SET | 340 | 130 | 110 | 90 | 55 | **0** | 0 |
| CLEAR | 350 | 180 | 160 | 140 | 105 | 70 | **0** |

The SET curve is zero from 3200 RPM up, so cruise cannot be *entered* above
3200 at any torque; the CLEAR curve is zero from 3600 up, so it is force-exited
there. Plus a 250-count dwell (`0xD9AD8`) that any transient resets, and a
375-count re-entry lockout (`0xD9ADA`). That is the mechanical reason the
Cruise tables see little residency.

### (c) The `Map Switching *` definitions are project-invented and misnamed

Zero of the 48 `Map Switching *` table names occur in
`definitions/32BITBASE.xml`. They exist only in the project XML, with
AI-shaped descriptions ("Stock value: 2000 RPM"). None of them gates cruise.
The block they describe (`0x03F49A-0x03F584`) is a **stationary/idle
classifier**, and every comparison in the write-up was inverted:

```
03F49E: F8E5  fcmp/gt fr14,fr8  ; n=8,m=14 -> T = (0.8798 > torque_ratio)
03F4A0: 8B70  bf 0x03F584       ; continue requires torque_ratio < 0.8798
03F4A6: F8F5  fcmp/gt fr15,fr8  ; T = (2.0 > vehicle_speed)
03F4AE: F8C5  fcmp/gt fr12,fr8  ; T = (550 > RPM)   -- RPM, not speed
03F4B6: F8C5  fcmp/gt fr12,fr8  ; T = (1300 > RPM)
03F4D2: F875  fcmp/gt fr7,fr8   ; T = (80 > ECT)    -- ECT, not IAT
```

Read correctly: warm engine, stopped, 550–1300 RPM, low torque, clutch out.
Same operand-order failure as items 1 and 12 — `fcmp/gt FRm,FRn` sets
`T = (FRn > FRm)`, and `0xFnm5` has n in bits 8–11.

Section 3.3 was inverted the same way: it requires `[0xFFFF7F68] <= 0.0` and
`RPM < 2000`, not `> 0.0` and `RPM > 2000`.

### `0xFFFF90BE` is the cruise-request flag, not `ect_mode_flag`

`fueling_pipeline_analysis.txt` and `startup_enrichment_analysis.txt` both
named `0xFFFF90BE` `ect_mode_flag`. It has one writer — `0x0611BC`, in the
cruise ramp — and 12 readers, all `mov.b` loads.

Those two files are also what **confirmed the polarity**, independently and
before this pass: `startup_enrichment` records `0xFFFF90BE = 0 → 0xCF6B0
(Non-Cruise)` / `≠ 0 → 0xCF704 (Cruise)` for Cranking Fuel IPW Comp, and
`fueling_pipeline` records `R6 == 0 → 0xD3206/0xD3216` (Timing Compensation
Imm. **Non-Cruise** A/B) / `R6 != 0 → 0xD3226/0xD3236` (**Cruise** A/B). Both
match the ramp direction derived from bytes at `0x0611C4-0x0611D4`. Renamed in
both files; the table mappings there were already right.

Worth carrying: these two consumers **hard-select** off the raw flag. They snap.
Only the base-timing path uses the ramped `0xFFFF90A8` interpolation.

### Consequence for the current tune

In `20.19c` the Cruise and Non-Cruise sides have been flattened to identical
for Base Timing Primary (0/306 cells differ; stock 121), Base Timing Reference
(0/306; stock 121), Knock Correction Advance Max (0/306; stock 68), Intake Cam
Advance (0/288; stock 96) and Target Throttle Plate (0/256; stock 162). For
those the blend is a no-op regardless of the ratio. Still differing: CL Fueling
Target Comp (18/48), Cranking Fuel IPW Comp (17/35), Min Primary Base
Enrichment 1 (63/144) — all at stock values.

The decision calibration `0xD9AC0-0xD9E30` is byte-identical to stock.

### Not fixed here

* **The definition XML is unchanged.** ECUFlash owns it (see CLAUDE.md). The 48
  `Map Switching *` names remain wrong in
  `definitions/AE5L600L 2013 USDM Impreza WRX MT.xml`, and `0xD9AD8`/`0xD9ADA`
  and the rest of `0xD9AC4-0xD9E26` remain undefined. Fixing means editing in
  the ECUFlash UI and pulling with `.\scripts\sync_defs.ps1 -Pull`, and the
  repo is already ~37 tables ahead of ECUFlash.
* **The scheduler rate of the `0x60562` parent is not established** — no literal
  reference and no in-range branch to it was found. So the 250/375 dwell counts
  and the 125-invocation ramp **cannot be stated in seconds**. Do not.
* **`0xFFFF85E4`'s physical unit is unverified.** The raw table values (20800,
  28800, 54400) are all divisible by 128 and match the raw-torque encoding of
  the per-gear torque cap (44800 = 350), which is suggestive, not proof.
  Writers are at `0xBC61C-0xBCA3E`.
* ~~`0xFFFF90F0` is unidentified.~~ **RESOLVED same day.** The workspace
  loader at the top of the parent function fills it: `060592 mov.l ...,r2 (=
  0xFFFF63C4) ; 060594 fmov.s @r2,fr8 ; 060598 ... fmov.s fr8,@(r0,r6)` with
  r6 = 0xFFFF9120 and r0 = -48. `0xFFFF63C4` is **mass airflow g/s** (item 28).
  So the 45/50 pair at `0xD9B34`/`0xD9B38` is a **MAF gate: set below 45 g/s,
  clear at 50 g/s** — not a temperature. The same loader settles the rest of
  the workspace: `0xFFFF90E0` <- ECT, `0xFFFF90E4` <- IAT (`0xFFFF6364`),
  `0xFFFF90E8` <- RPM, `0xFFFF90EC` <- vehicle speed. That confirms the
  SET/CLEAR curve axis really is RPM, and makes the `[0xD9B2C] = 4.0` test a
  "stopped" check on speed.
* **Section 4.2's SI-DRIVE reading is unverified and probably wrong** — the bit
  tests at `0x040098`/`0x0400AC` select an engine-speed source, and neither
  branch writes `0xFFFF90A8`. This car has no SI-Drive input.

---

## 39. The descriptor typecode map was guessed, and it mis-sized 611 of 760 tables — **FIXED 2026-08-16**

**Reference bin:** `rom/AE5L600L 20g rev 20.19c.bin`, md5 `92cae8275cd4f9b473a3a9e36efe6449`.

`scripts/mapping/scan_descriptors.py` carried this map in its docstring and in
`TYPE_NAMES`/`TYPE_SIZES`:

```
0x00 = float32   0x02 = int8   0x04 = int16   0x08 = uint8   0x0A = uint16
```

It was never decoded — it was inferred from the data. The real map comes out of
the loader dispatch table at `0x0BE860`, which `table_lookup` (`0x0BE830`)
indexes with the typecode byte via `mova @(0x0BE860),r0 / mov.l @(r0,r3),r2`.
Because that is a table of **longs**, the typecode is always a multiple of 4 —
`0x02` and `0x0A` are structurally impossible encodings.

| typecode | handler | index scaling | load | truth |
|---|---|---|---|---|
| `0x00` | `0x0BEACC` | `shll2` (x4) | `fmov.s` | float32, 4 B |
| `0x04` | `0x0BEB20` | `add r0,r1` (x1) | `mov.b` + `extu.b` | **uint8**, 1 B |
| `0x08` | `0x0BEB6C` | `shll` (x2) | `mov.w` + `extu.w` | **uint16**, 2 B |
| `0x0C` | `0x0BEAE4` | `add r0,r1` (x1) | `mov.b`, no extu | int8, 1 B |
| `0x10` | `0x0BEB00` | `shll` (x2) | `mov.w`, no extu | int16, 2 B |

**Scope of the damage.** Audited every row of `descriptor_map.txt` against the
typecode byte in the bin (1-D at record+2, 2-D at record+16):

* 1-D: 621 rows, **492 wrong** (331 "uint8" really uint16, 161 "int16" really uint8)
* 2-D: 139 rows, **119 wrong** (65 "uint8" really uint16, 54 "int16" really uint8)
* **Total 611 of 760 rows had the wrong cell width**, i.e. the wrong table extent.

The file never once said `uint16`, though 396 of the 760 descriptors are uint16.
It said `int16` 215 times; there are zero int16 descriptors in this ROM.

This is NOT the "1-byte/2-byte inverted" note in CLAUDE.md — that note described
the symptom and got the mechanism wrong. It is a shifted mapping.

**Fixed:** typecode map corrected in `scripts/mapping/scan_descriptors.py`
(names, sizes, `read_data_1d` branches, and both docstrings), and
`disassembly/maps/descriptor_map.txt` regenerated. New totals — uint16 396,
uint8 215, float32 149 — reproduce an independent hand audit exactly. Every
other column (address, dim, count, scale, bias, pointers, axis range) is
identical to the previous file, so only the type/width claim moved.

`disassembly/maps/descriptor_labels.txt` inherited the same error in its label
names (`..._u8_16_AD258`). 610 of its 760 typed labels were rewritten from the
ROM typecode; 150 were already right; the 15 hand-named labels carry no type
token and were left alone. Final tallies match `descriptor_map.txt` exactly.

**Also fixed alongside:** `ROM_DIR` in `scan_descriptors.py` and
`desc_to_func_xref.py`, and `DISASM_DIR` in `gen_descriptor_labels.py`, all
resolved one level short (`scripts/rom`, `scripts/disassembly`). None of the
three could run from the repo as committed.

**Consequence to carry:** anything that read a cell width, a table extent, or a
cell value out of `descriptor_map.txt` before this date is suspect for 80% of
descriptors. The definition XMLs were never affected — they are independent.

---

## 40. `0xFFFF6354` is coolant temperature, not vehicle speed — **FIXED 2026-08-16**

Three artifacts disagreed:

| artifact | claim |
|---|---|
| `disassembly/maps/ram_reference.txt:139` | `ect_raw_adc` — ECT raw ADC value |
| `disassembly/analysis/diag_tasks_analysis.txt:123` | **Vehicle speed** |
| `disassembly/analysis/disasm_3162C_annotated.txt:254` | **Input to speed computation** |

`diag_tasks_analysis.txt` contradicted *itself* — line 54 of the same file
already said `ect_raw_adc`.

**Settled from the writer.** All 69 literal-pool references to `0xFFFF6354` are
**reads**, which is why earlier passes could not resolve it. The writes are
indexed stores off a neighbouring base:

```
01F72C  D283  mov.l @(0x01F93C),r2    ; r2 = 0xFFFF6360
01F72E  E0F4  mov  #-12,r0
01F730  F2E7  fmov.s fr14,@(r0,r2)    ; [FFFF6354] = FR14      (good path)
01F742  D27E  mov.l @(0x01F93C),r2
01F744  E0F4  mov  #-12,r0
01F746  F247  fmov.s fr4,@(r0,r2)     ; [FFFF6354] = FR4       (failsafe path)
```

Routine `0x01F6E0` reads ONE source float — `0xFFFF4144`, the linearised sensor
in the same ADC block as `0xFFFF4130` battery voltage — and fans it out to
`FFFF6350` / `FFFF6354` / `FFFF6358` / `FFFF635C` under four different validity
gates. On every failsafe path it writes the constant at `0x01F940`:

```
0x01F940 = 0x428C0000 = 70.0
```

**70 is the limp-home coolant temperature in Celsius.** A vehicle-speed failsafe
would be 0.0. `FFFF6350` — already accepted as ECT — is written by the same
routine from the same source float, four bytes away.

Corroborating, independently:
* The one table it feeds, descriptor `0xAD258`, has a −40..110 axis at `0xCC664`,
  which the project definition XML names **"Coolant Temperature"** (lines 423, 1646).
* The main IPW calculator at `0x03817C` loads it directly
  (`038194 mov.l @(0x03837C),r2 ; 038196 fmov.s @r2,fr12`, `0x03837C = 0xFFFF6354`) —
  expected for coolant, not for a speed copy.

**"raw ADC" was also wrong.** The raw value is upstream at `0xFFFF4144`;
`0xFFFF6354` is the scaled Celsius value after failsafe substitution.
Renamed `ect_raw_adc` -> **`ect_gated_c`** in `ram_reference.txt`,
`ImportAE5L600L.java`, `diag_tasks_analysis.txt` and `disasm_3162C_annotated.txt`.

The speed label most likely leaked in from the neighbouring `0xFFFF67EC` speed
compare in the same key-address list in `disasm_3162C_annotated.txt`.

---

## 41. The FLKC grid is bucketed 7x5=35, not an interpolated 6x4 — **FIXED 2026-08-16**

Two RAM identities were wrong, and the whole access model was wrong.

**`0xFFFF3248` was `per_cylinder_knock_retard`, "float[4] indexed by cylinder".**
It is the **FLKC learning grid: 35 cells x 8 bytes**. Nothing indexes it by
cylinder. Three independent confirmations:
1. read `0x0462AE` and write `0x0464D8` both use `index*8`;
2. the reset loop at `0x046824` runs `mov #35,r12` / `add #8,r13`;
3. `0xFFFF3248 + 35*8 = 0xFFFF3360`, exactly the base of the parallel u16 array.

**`0xFFFF8298` was `flkc_fg_cyl_index`, "current cylinder/bank index".** It is
the **grid cell index, 0..34**, computed as `rpm_band*5 + load_band` and bounded
by `mov #35,r5 / cmp/ge` at `0x046288`. A cylinder index would be 0..3.
Same mislabel class as the gear byte (`cylinder_index` at `0xFFFF6812`).

**The access model.** The axis values at `0xD2F0C` (6 RPM) and `0xD2F28`
(4 load) are **band BOUNDARIES, not cell centres**. The selector at `0x0461D2`
walks each axis and returns `band = count of boundaries <= input`, giving
**7 RPM bands and 5 load bands = 35 cells**. Downward transitions require extra
margin (`0xD2F24` = 50 rpm, `0xD2F38` = 0.02 load); upward transitions are
immediate. There is **no interpolation anywhere** — write is one cell, read is
one cell. Out-of-grid is unreachable because the outermost band is unbounded.

**Consequence:** a knock event at one load **cannot** bleed into cells at another
load. Any claim that a mid-load event "taxes the boost cells" is false.

Newly named in the same pass: `0xFFFF82A8` `flkc_rpm_band`, `0xFFFF82A9`
`flkc_load_band`, `0xFFFF82AD..B0` the four range-gate flags. The gate
(ANDed into `0xFFFF829E` at `0x0467E8`) gates **writes only** — the readback at
`0x0462AE` is unconditional. Benign at current calibration because the reset
loop zeroes all 35 cells.

Full trace: `disassembly/analysis/flkc_grid_interpolation_trace.txt`.

---

## 42. `0xAD258` is not a WOT enrichment factor and is inert — **FIXED 2026-08-16**

`disassembly/analysis/fueling_pipeline_analysis.txt:60` and `:426` said
`0x39528  WOT enrichment factor (2D map 0xAD258)`, `(RPM x load)`, output
"used by Main IPW calculator". Wrong on four counts:

1. **Function entry is `0x3952C`**, not `0x39528` (`0x39528` is `bra 0x039668`,
   a sibling dispatch stub). `func_3952C` is reached by `bra` from `0x039524`;
   there is no literal `0x0003952C` in the ROM and no bsr in range.
2. **The table is 1-D, 16 points, uint16**, scale 1/2048, bias 0.0 — not 2-D.
3. **Its axis is coolant temperature** (`0xCC664`, −40..110 °C), not RPM x load.
4. **It is not on the IPW path.** Its outputs are `FFFF7BAC`/`FFFF7BA8`
   (AFR-deviation metric); `0xFFFF7BC0` is a scratch spill read once, eight
   instructions later. The IPW calculator at `0x03817C` has **zero** references
   to the `FFFF7B90-7BD0` block (literal pool `0x038370-0x038420` scanned).

**And it is inert three times over**, any one sufficient: the data is flat 1.0
at all 16 points; the branch that uses it is only reached when
`byte[0xFFFF782C] != 0`; and that branch's result is clamped to `[0.0, 0.0]` by
`0x0CC3EC` (CL) and `0x0CC3F0` (OL), **both of which are 0.0**. `clamp(v,0,0)`
returns 0.0 for every v.

The `0xFFFF7448` CL/OL mode flag selects which of the two zero limits is used —
the OL branch is the only one that multiplies by the table at all (`0x0395B8
fmul fr9,fr4`), and it is zeroed regardless.

The sibling branch (`byte[0xFFFF782C] == 0`, subroutine `0x3961C`) never touches
the table and uses a **live** limit of `0x0CC3E8 = 0.03`.

**Consequence:** `0xAD258` was logged as "the last unextracted multiplier in the
IPW stack". It was never in that stack. Closing it removes it as an injector-
sizing lever. Full trace and the redirect for the FFB-below-map gap:
`disassembly/analysis/ad258_wot_enrichment_trace.txt`.

---

## 43. `desc_func_xref.txt` marked 874 of 995 descriptors "invalid" because of an off-by-one — **FIXED 2026-08-16**

`is_valid_axis()` in `scripts/mapping/desc_to_func_xref.py` counted monotonic
**pairs** (maximum `len(vals)-1`) but compared against `len(vals) * 0.7`:

```python
increasing = sum(1 for i in range(len(vals)-1) if vals[i+1] >= vals[i])
return increasing >= len(vals) * 0.7
```

The caller passes `min(size, 3)`, so `vals` has 3 elements, `increasing` maxes
at 2, and the threshold is 2.1. **A perfectly monotonic axis returned False.**
The function returned False for every axis it was ever given, so every 1-D
descriptor was classified `invalid`; only 2-D descriptors (which skip the axis
check) survived.

Fixed to compare against the pair count. A second, unrelated guard rejected
`size > 64`, which is wrong for two real descriptors — `0xAE284` (65 points) and
`0xAB334` (78 points); raised to 256.

**Result: `invalid` drops from 874 to 2**, and both survivors are genuine —
`0xAF970` is float data (`bf800000` = −1.0, ...) that the pointer scan
mis-picked. `0xAD258` now classifies correctly as `1D_vs_ECT`, which is what
CLAUDE.md's rule-1 warning about derived products was pointing at.

**Open, flagged not settled:** with the classifier fixed, `0xAE284` decodes as a
**1-D, 65-point, float32** descriptor (axis `0xD4128` spanning 0..3.5, data
`0xD422C` spanning 0..304), classified `1D_vs_Load` and sitting in `knock_area`.
Project notes record `0xAE284` as an **RPM x IAT** knock-detection threshold.
Those cannot both be right. Not resolved here — flagged for a dedicated pass.

---

## 44. `KNOCK_FLAG` (`0xFFFF81BA`) is the shared pre-gate knock trigger — **RESOLVED 2026-08-16**

The repo's `logs/logcfg.txt` did not define `KNOCK_FLAG`, so the paramid behind
log column 34 was unknown and the channel was barred from use. The live logger
config was pulled off the SD card on 2026-08-16 and now matches the log:

```
paramname = KNOCK_FLAG
paramid   = 0xFF81BA          -> RAM 0xFFFF81BA (byte)
scalingrpn = x
```

**Writer.** Written at exactly two sites, both GBR-relative (which is why a
pointer-based scan finds only reads), inside the knock detector whose prologue
sets `GBR = 0xFFFF80FC` at `0x043798`:

```
043B5A  C0BE  mov.b r0,@(190,gbr)     ; 0xFFFF80FC + 190 = 0xFFFF81BA
043B5E  C0BE  mov.b r0,@(190,gbr)
```

Cleared to 0 on either early-out; set to 1 when the detector's magnitude test
passes and the cycle counter `r11` has reached the u16 threshold at
`0x0D29DC` (= 250). The companion byte `0xFFFF81BB` (`@(191,gbr)`) sub-classifies
the two set paths.

**Consumers.** Thirteen read sites. Two matter:
* `0x0443C4` — the FBKC path (`fbkc_path_trace.txt:21` calls it the primary
  FBKC trigger).
* `0x0463E2` — the FLKC learn routine loads it into `r7`; at `0x046460`
  `tst r7,r7` routes zero to the advance path and non-zero to the retard path.

**Verdict: it is a genuine knock-sensor-domain flag sitting UPSTREAM of both
FBKC and FLKC** — the pre-gate signal the channel was hoped to be. It is usable,
but as a witness of *detection*, not of *applied retard*, and with two caveats:

1. It is a **per-ignition-event** flag. At ~2000 rpm a 4-cylinder fires roughly
   every 15 ms while the logger samples at 25 Hz (40 ms), so the logged channel
   is an aliased ~1-in-2.7 snapshot. Counts are lower bounds and absence proves
   nothing.
2. Detection does not imply correction. The 8-14 concentration at rpm ~1999 x
   load ~0.44 sits **below the FLKC enable gate** (load 1.25, item 41), so FLKC
   provably cannot act there — which explains flag-set samples with no FLKC
   movement without needing any error in either channel.

---

## 45. `0xFFFF4130` — `adc_pipeline_trace.txt` and `boost_control_*` were wrong; item 10 was right — **FIXED 2026-08-16**

Three artifacts disagreed with `docs/corrections.md` item 10:

| artifact | claim |
|---|---|
| `disassembly/analysis/adc_pipeline_trace.txt:15` | ADDR 4 out = `0xFFFF4130` = **Atmospheric Pressure (Baro)** |
| `disassembly/analysis/adc_pipeline_trace.txt:18` | ADDR 7 out = `0xFFFF41E0` = **Battery Voltage** |
| `disassembly/analysis/boost_control_analysis.txt:190,330` | `ignition_switch_state`, "float, Ignition switch" |
| `disassembly/analysis/boost_control_raw.txt:209,274,789,867` | `ignition_switch_state` |

**Item 10 was right. `0xFFFF4130` is BATTERY VOLTAGE.** Settled again here from
the writer and its scaling, independently of the axis-name argument item 10 used:

```
005A40  C70C  mova @(0x005A74),r0    ; [0x5A74] = 0x47800000 = 65536.0
005A46  F32D  float fpul,fr3
005A48  F323  fdiv fr2,fr3           ; fr3 = filtered / 65536.0
005A4C  D30A  mov.l @(0x005A78),r3   ; [0x5A78] -> 0x0C0098, value 20.0
005A52  F312  fmul fr1,fr3           ; fr3 = (filtered/65536) * 20.0
005A56  F23A  fmov.s fr3,@r2         ; [0xFFFF4130] = fr3
```

Full scale is **0..20** — volts. Baro would scale to ~15 psi / ~101 kPa / ~1 bar.
This agrees with item 10's finding that `0xFFFF4130` feeds the definition-named
axis `0xD91CC` "Ignition Dwell / Battery Volts" (8, 10, 12, 14, 16 V).

The ADC **pipeline structure** in `adc_pipeline_trace.txt` is correct and is
corroborated by the writer (raw `0xFFFF402C` → filt `0xFFFF4134` → out
`0xFFFF4130`). Only the sensor NAME attached to ADDR 4 was wrong.

**`0xFFFF41E0` is not battery voltage either**, as item 10 already said. Traced:

```
008150  D215  mov.l @(0x0081A8),r2   ; -> 0x0C00B0 = 25.0
00815C  D313  mov.l @(0x0081AC),r3   ; -> 0x0C00B4 = -62.5
008160  F008  fmov.s @r0,fr0         ; inline float at 0x81B0 = 5/65536
008162  F23E  fmac fr0,fr3,fr2       ; fr2 = raw*25.0*(5/65536) - 62.5
008166  F12A  fmov.s fr2,@r1         ; [0xFFFF41E0] = fr2
```

Range **−62.5 .. +62.5**, zero at mid-scale — a bidirectional quantity, neither
volts nor pressure. **Identity NOT established; left deliberately unnamed.**

Corrected: `adc_pipeline_trace.txt` (ADDR 4, ADDR 7, and the summary line
claiming battery voltage = `0xFFFF41E0`), `boost_control_analysis.txt` and
`boost_control_raw.txt` (`ignition_switch_state` → `battery_voltage`, 5 sites).

`ad258_wot_enrichment_trace.txt` needed no change — its parenthetical
"(same block as FFFF4130 battery voltage)" is correct.

---

## 46. Seven fuel-dispatch slots are `bra` trampolines, and there is a THIRD dispatch table — **RESOLVED 2026-08-16**

Decoded from the bin. A slot is a trampoline when the address it holds is a `bra`.

```
table A @ 0x0480B8 (19 entries) -- one trampoline
  A[13] 0x03756C -> 0x03757E
table B @ 0x04A0B8 (20 entries) -- six trampolines
  B[ 5] 0x03160A -> 0x03161E     B[ 8] 0x039528 -> 0x039668
  B[10] 0x036C3C -> 0x036C48     B[11] 0x037B68 -> 0x037B74
  B[15] 0x03605E -> 0x03643A     B[17] 0x03A222 -> 0x03A230
```

The entry addresses in `fueling_pipeline_analysis.txt:50-72` all match the bin,
so the tables are right — but any analysis that read forward from a stub address
instead of the branch target analysed two instructions and then whatever
followed.

**`func_3952C`'s caller is found.** There is a third dispatch table: 93
contiguous code pointers at **`0x04ACB8`–`0x04AE28`**. Slot 20 (`0x04AD08`)
holds `0x00039524`, the stub whose `bra` lands on `0x03952C`.

```
0x00039524  occurs exactly once in the ROM, at 0x04AD08   (table C slot 20)
0x00039528  occurs exactly once, at 0x04A0D8 = table B base + 4*8  (B[8])
0x0003952C  occurs nowhere
0x00039668  occurs nowhere
```

So the 4-byte-apart stub pair `0x39524`/`0x39528` is **not** an off-by-one — the
two stubs belong to two different dispatch tables. Table B slot 8 reaches
`0x39668`; table C slot 20 reaches `func_3952C`. This closes the "caller
unlocated" item left open in `ad258_wot_enrichment_trace.txt`.

**Still open:** no 4-aligned literal points at `0x04ACB8` or `0x04ACB4`, so
table C's consumer is not located. Presumably reached with a non-zero
displacement or a computed base.

---

## 47. `0x37B74` — both existing names are unsupported — **OPEN 2026-08-16**

`0x037B68` is `A004` = `bra +4` → `0x037B74`, but it is one of **three adjacent
stubs**, not a lone trampoline:

```
0x37B68  A004 -> 0x37B74
0x37B6C  A071 -> 0x37C52
0x37B70  A096 -> 0x37CA0     <- itself slot 29 of table C (0x04AD2C)
```

`func_37B74` preamble, VERIFIED:

```
GBR = 0xFFFF7AB4                    (literal 0x037CEC)
r13 = 0xFFFF7AD8                    (literal 0x037D24)
fr8 = float[0xFFFF6624]  = RPM      -> [r13-4] = 0xFFFF7AD4
fr8 = float[0xFFFF6350]  = ECT      -> [r13]   = 0xFFFF7AD8
two table_lookup (0xBE830) calls on descriptors 0x0AC648 and 0x0AC634
```

Both descriptors decoded:

| desc | dim | count | type | axis | data |
|---|---|---|---|---|---|
| `0x0AC634` | 1D | 16 | uint8, 1/128 | `0x0CCE18` = 0,800,…,6400 (**RPM**) | `0x0CCE58` = **all zero** |
| `0x0AC648` | 1D | 16 | uint8, 1/128 | `0x0CC624` = −40..110 (**ECT**) | `0x0CCE68` = **all zero** |

`fueling_pipeline_analysis.txt:61` calls B[11] "Injector compensation (2D maps,
RPM/load indexed)" — wrong on dimensionality (1-D) and on axis (ECT, not load).
The competing "enrichC / AFL application" name is at least consistent with the
workspace (`enrichC` = `0xFFFF7AE4` = r13+12), but the write to `0xFFFF7AE4` was
**not** traced, so it is not asserted here.

**Neither name is supported by what was decoded, and no third name is invented.**
VERIFIED: 1-D, RPM- and ECT-indexed, both comps flat zero, workspace
`0xFFFF7AD8` under GBR `0xFFFF7AB4`. Like `0xAD258`, this term contributes
nothing on the current calibration. Whether the multiplicative fuel model's
third term is mislabeled remains **OPEN**.

---

## 48. 88 addresses are both a GBR base and a named scalar — `ram_reference.txt` ref counts are contaminated — **DOCUMENTED 2026-08-16**

Brief #2's D2 asked whether `0xFFFF798C` is a GBR workspace base or a scalar.
**It is both, and so are 87 other addresses.**

`cl_ol_analysis.txt:86` was **right**: `0xFFFF798C` is installed as a GBR base at
`0x03607E` and `0x036856` — the exact two sites it names, and the only two of
the ROM's 651 `ldc r0,gbr` sites that install that value. It is *also* written
as a float (`0x03603E`, `0x03621E`, `0x036236`, `0x036270`, `0x036306`, all
`fmov.s frX,@(r0,rN)` off base `0xFFFF79F0` with `r0 = -100`) and as a byte
(`0x0354B2`, `mov.b r0,@(224,gbr)`, GBR `0xFFFF78AC`). Both artifacts were
correct; they were describing different roles of the same address.

Computed mechanically — 459 distinct GBR base values against 481 named scalars:

- **88 addresses are both.** 36 are already named as a base/workspace/struct;
  52 read as physical scalars.
- **Dual-role is normal, not an error.** `0xFFFF6350 ect_current` (205 refs),
  `0xFFFF6624 rpm_current` (301), `0xFFFF63C4 mass_airflow_gps` (43) and
  `0xFFFF62DC throttle_plate_angle` (20) are all correctly named *and* GBR
  bases. A struct base whose offset 0 is the value itself. Do not "fix" them.
- **What is wrong is the `N refs` column** for those 88: it conflates GBR-base
  loads with scalar accesses, so the count overstates the evidence behind the
  NAME.

Treat the low-ref, workspace-shaped ones as **unverified naming** — the name may
have been invented to explain a base load: `0xFFFF798C timing_state_var`,
`0xFFFF7954 ol_enrichment_factor_A`, `0xFFFF7F74 blend_correction_C`,
`0xFFFF7AB4 afl_multiplier_output`, `0xFFFF8000 base_timing_offset`,
`0xFFFF805C timing_corr_5C`, `0xFFFF7A20 o2_sensor2_output`,
`0xFFFF7AF4 fuel_ipw_state_B`.

Banner added to `ram_reference.txt`. Reproduce with
`scripts/mapping/find_writers.py`.

---

## 49. `0xAE284` is a knock-signal transfer curve, not an RPM×IAT threshold — **FIXED 2026-08-16**

Project notes recorded `0xAE284` as the knock detection threshold, **RPM × IAT**,
with "no mrp/load input". Decoded from the bytes, all three parts are wrong.

The descriptor is **1-D, 65 points, float32**: axis `0x0D4128` spanning
0.0–3.5, data `0x0D422C` spanning 0.0–304.0. It read `invalid` in
`desc_func_xref.txt` until item 43's off-by-one was fixed *and* the `size > 64`
guard was raised — which is why it had never been decoded.

Its one consumer is the knock detector at `0x043798` (GBR `0xFFFF80FC`, the same
function that writes `KNOCK_FLAG`). The lookup input is neither RPM, load, nor IAT:

```
0437A8  D283  mov.l @(0x0439B8),r2   ; 0x0439B8 = 0xFFFF4304  (knock signal)
0437AA  F828  fmov.s @r2,fr8
0437AC  FC8D  fldi0 fr12
0437AE  FC85  fcmp/gt fr8,fr12       ; clamp at zero
0437B2  F8CC  fmov fr12,fr8
0437B8  F987  fmov.s fr8,@(r0,r9)    ; [0xFFFF8134] = clamped signal
0437BA  D481  mov.l @(0x0439C0),r4   ; r4 = 0x000AE284
0437BC  DC81  mov.l @(0x0439C4),r12  ; r12 = 0x000BE830 (table_lookup)
0437BE  4C0B  jsr  @r12
0437C0  F496  fmov.s @(r0,r9),fr4    ; delay slot: fr4 = the clamped signal
```

So it maps **knock signal level (0–3.5) → 0–304**. A sensor transfer curve.

The "no load input" claim is contradicted separately: the knock module contains
2-D **RPM × LOAD** tables, decoded from the bytes —

| desc | dim | Y axis (RPM) | X axis (LOAD) |
|---|---|---|---|
| `0x0AE5D8` | 14×5 uint8 | 1200,1600,2000,2400,2800,3200,3600,4000… | 0.5, 0.8, 1.4, 1.8, 2.2 |
| `0x0AE5F4` | 14×5 uint8 | same | same |
| `0x0AE610` | 14×5 uint8 | same | same |
| `0x0AE62C` | 14×6 uint8 | same | 0.5, 0.8, 1.0, 1.3, 1.8, 2.3 |

consumed at `0x0441C0`–`0x0441F0`. The detector itself also reads RPM
(`0xFFFF6624` → FR15) and engine load (`0xFFFF63F8` → FR14) at `0x04379C`/`0x0437A0`.

**Stated limit:** it is NOT established here that the 14×5 tables *are* the
detection threshold. What is settled is narrower and sufficient to retire the
old claim: `0xAE284` is not the threshold, is not 2-D, and is not RPM × IAT.
Treat "knock detection has no load input" as **UNVERIFIED**, not inverted.

---

## 50. The 8-14 FLKC movement was in-drive LEARNING, not map traversal — **CORRECTED 2026-08-16**

The prior reading of the 8-14 log was: "all 33 step-downs passed the traversal
test (0.25 steps in consecutive 40 ms samples) = lookups of a pre-learned map,
not in-drive learning." **That is backwards, and the method was invalid.**

Step SIZE cannot discriminate under a bucketed map (item 41). 0.25 is exactly
the Fine Correction Advance Value (`0xD2F48`), so an in-place ramp and a
traversal look identical by step size. Only the **cell index** separates them.

New tool `scripts/analysis/flkc_cell_trace.py` replicates the ECU band selector
exactly — boundaries plus downward-only hysteresis (50 rpm `0xD2F24`, 0.02 load
`0xD2F38`) — and computes `cell = rpm_band*5 + load_band` per sample.

Result on `logs/8-14 weekend 20.19c` (221,829 samples):

```
FLKC changes total : 64
  CELL TRAVERSAL   :  5   (index moved -- a different cell was read)
  IN-CELL CHANGE   : 59   (index held -- the STORED VALUE moved = LEARNING)
in-cell step sizes : {-1.00: 3, -0.25: 29, +0.25: 23, +0.50: 2, +1.00: 2}
```

**92% of FLKC movement was in-cell.** The textbook learn-then-recover cycle,
in place — e.g. cell 18 ramping 0.00 → −0.25 → −0.50 → −0.75 → −1.00 over four
consecutive samples at 2952–2998 rpm / 1.57–1.67 load, then cell 19 recovering
−1.00 → 0.00 in four +0.25 steps.

**The ECU was actively learning during the 8-14 drive.** Anything that treated
that FLKC map as historical readback needs revisiting.

Caveats: FLKC logs at 0.25 resolution (`x,0.25,*,32,-`), so sub-step movement is
invisible and counts are lower bounds; the band index is reconstructed from the
same 25 Hz rpm/load, so a fast excursion between samples could be misclassified
— but 5 of 64 is far too low to flip the conclusion.

---

## 51. Both registry CONFLICTs settled on the ROM side — XML fix is ECUFlash-side — **ROM SIDE FIXED 2026-08-16**

Both are definition-XML storagetype errors; the ROM code is right in both cases.
Per CLAUDE.md the repo XMLs must not be hand-edited — ECUFlash owns them.

**`0xC0BCC`** — "Boost disable during fuel cut-Load threshold" (tinywrex patches),
XML line 39, `type="1D" scaling="EngineLoad(g/rev)"`.

```
bytes 3f d9 99 99
  as float  = 1.7      <- how the ROM code reads it
  as uint16 = 16345    <- what the XML implies; nonsense as a load
```

**The editor currently displays 1.00 for this table. The real threshold is
1.7 g/rev.** Any reasoning that used "boost disable during fuel cut = 1.00 load"
used a wrong number.

**`0xD6214`** — "Idle Airflow Min Target Decel Initial Idle Activation Max Mode
Counter" (Idle Control), XML line 1422.

```
bytes 00 12 00 08
  as int16 = 18        <- how the ROM code reads it, and a sane counter
  as float = 1.65e-39  <- what the XML declares; a denormal, garbage
```

**Fix, in the ECUFlash UI, then `.\scripts\sync_defs.ps1 -Pull`:**
`c0bcc` → storagetype float; `d6214` → storagetype uint16/int16, scaling
rawecuvalue. Run `.\scripts\sync_defs.ps1` first — repo and ECUFlash have been
out of sync since 2026-04-07 and the repo carries ~37 tables ECUFlash does not,
so a blind `-Pull` deletes them.

---

## 52. Writer traces for items 3–5 — **PARTIALLY FIXED 2026-08-16**

New tool `scripts/mapping/find_writers.py` handles all four write forms (direct,
displacement, indexed `@(r0,Rn)`, GBR-relative) and resolves base registers by
backwards scan. Self-tested against `0xFFFF6354` and `0xFFFF81BA`; it reproduced
every known writer **and found one additional writer for each**
(`0x01F888` and `0x0440A4` respectively) that the hand method had missed.

- **`0xFFFF782C`** (selects which branch of `func_3952C` runs): written at
  `0x03408C` (`mov.b r2,@r5`) and `0x03445E` (`mov.b r0,@(12,gbr)`,
  GBR `0xFFFF7820`). Both byte-sized. The write *conditions* are not decoded.
- **`0xFFFF7800`**: written at `0x03407E` / `0x034088`, `fmov.s frX,@(r0,r5)`
  off base `0xFFFF782C` with `r0 = -44`. Note the base is the item-3 flag
  itself, so `0xFFFF782C` is both a byte flag and a struct base.
- **`0xFFFF77D8` / `0xFFFF77DC`**: **no writer found.** Stated plainly — the
  tool resolves bases loaded from a literal pool, so a base built by arithmetic
  is invisible to it. Do NOT conclude these are read-only.

---

## 53. The knock detector's tables are knock-signal and RPM — the RPM×LOAD tables belong to timing blend — **REFINES item 49, 2026-08-16**

Item 49 established that `0xAE284` is a 1-D knock-signal curve, not an RPM×IAT
threshold, and noted that the knock module contains 2-D **RPM × LOAD** tables.
Tracing those tables end to end changes the second half of that conclusion.

**The detector (`0x043798`, GBR `0xFFFF80FC`) does exactly two lookups:**

| desc | shape | input | data |
|---|---|---|---|
| `0xAE284` | 1-D, 65pt, float32, axis 0.0–3.5 | `float[0xFFFF4304]` clamped ≥0 (knock signal), call site `0x0437BA` | 0.0–304.0 |
| `0xAE290` | 1-D, 10pt, float32, axis 800–8000 | FR15 = RPM (`0xFFFF6624`), call site `0x043942` | **all zero** |

Neither is IAT-indexed. Neither is load-indexed. `0xAE290` is flat zero as
calibrated, so it contributes nothing.

**The four 2-D RPM × LOAD tables are not part of detection.** Traced:

- Written at `0x0441C0`–`0x0441FE`: four `jsr 0xBE8E4` (2-D lookup) calls with
  FR4 = FR15, FR5 = FR12, results stored to `0xFFFF81DC` / `81E0` / `81E4` /
  `81E8` (base `0xFFFF81E8`, `r0` = −12/−8/−4/0).
- Axis inputs, from literals `0x044244`/`0x044248`/`0x04424C`: FR15 = RPM
  (`0xFFFF6624`), FR12 = **engine load** (`0xFFFF63F8`), FR14 = ECT
  (`0xFFFF6350`). Gated on `[0xD2D98]` = 7000, `[0xD2D9C]` = 0.0,
  `[0xD2DA0]` = 60.0.
- **Read at `0x03F5F0`, `0x03F680`, `0x03F734` — all inside
  `task50_timing_blend` (`0x03F368`–`0x03FCA2`)**, not by the knock detector.

**Net, stated carefully because it partly walks back item 49:**

- "Threshold = RPM × IAT @ `0xAE284`" — **wrong**, unchanged.
- "The detector has no load input" — the detector *does* read engine load into
  FR14 at `0x0437A0`, so the literal statement is false. **But** neither of its
  two lookup tables is load-indexed, and the RPM×LOAD tables turn out to be
  timing-blend inputs. So the *spirit* of the old claim — no load term in the
  detection threshold — now looks **more** likely, not less.
- What FR14 is used for inside the detector is **not traced**. Until it is,
  neither "has a load term" nor "has no load term" is established.

The address and the axes were wrong; the conclusion may well be right for the
wrong reason. Do not cite either version as settled.

---

## 54. `0x37B74` does NOT write enrichC — **NARROWS item 47, 2026-08-16**

`scripts/mapping/find_writers.py` over `0xFFFF7AE4` (enrichC) returns exactly
one writer in the whole ROM:

```
FFFF7AE4  WRITE GBR  0367F2: mov.l r0,@(80,gbr)   ; GBR=FFFF79A4 set @03644E
```

Two consequences:

1. The write is `mov.l` of an **integer** register, not `fmov.s`. Whatever
   `0xFFFF7AE4` holds, it is not written as a float here.
2. The writer sits in the function whose GBR is installed at `0x03644E` — the
   **OL fuel map selector** reached via table B[15] (`0x03605E` → `0x03643A`).
   It is **not** `func_37B74`.

So the pairing "enrichC (`0xFFFF7AE4`, AFL application `0x37B74`)" is wrong:
the two halves describe different functions. `func_37B74`'s own outputs go to
its `0xFFFF7AD8` workspace (`[r13-4]` = `0xFFFF7AD4`, `[r13]` = `0xFFFF7AD8`).

**"AFL application writing enrichC" is now positively excluded** — which is
progress, because it was the load-bearing half of the multiplicative fuel
model's third term. What `func_37B74` actually is remains open (item 47); both
candidate names stay unsupported.

---

## 55. ECUFlash definition sync — the repo is ahead by 37 tables but has one bounds REGRESSION — **REPORTED 2026-08-16**

Ran `.\scripts\sync_defs.ps1` (report-only; nothing was written). Both files
show DIVERGED / "ECUFLASH is newer", but that is a **52-second mtime artifact**
(repo 7/26 9:23:08 PM vs ECUFlash 7/26 9:24:00 PM), not newer content.

| | repo | ECUFlash |
|---|---|---|
| project XML | 104,949 B / 533 named tables | 64,712 B / 499 |
| base XML | 585,548 B / 1235 tables | 585,194 B / 1235 |

**Project — the repo is AHEAD.** 37 tables exist only in the repo (matching
CLAUDE.md's "~37 tables"): the fuel-pump duty split, the CL/OL MAF hysteresis
set, post-transient knock window/bleed defs, map-switching secondary gates,
boost enable/disable thresholds, torque-request MAF gates. Only 3 exist only in
ECUFlash, and all three are superseded predecessors:

- `Fuel Pump Duty` → repo split into High / Low / Max
- `CL to OL Enrichment Threshold (MAF)` → repo **deliberately removed** it; the
  repo's 32BITBASE carries a comment recording that it duplicated
  `Minimum Primary Open Loop Enrichment (Throttle)` at the same ROM address,
  with a throttle axis (10.93–89.06), not MAF
- `AFL Ramp Rate (CL to OL Transition Speed)`

A blind `-Pull` would delete 37 tables and resurrect 3 superseded ones.

**Base — identical table membership (1235 both sides).** The 354-byte delta is
almost all reordering plus that removal comment, with one real change, and on
that one **the repo is WRONG**:

```
scaling EngineLoad(g/rev)1
    ECUFlash:  max="8"
    repo:      max="5"     <-- REGRESSION
```

`Engine Load Limit A (Maximum)` reads **8.00** in the 19c bin (via
`scripts/defs.py`). With `max=5` ECUFlash would **clamp** that table — exactly
the `BOUNDS-SUSPECT` failure mode CLAUDE.md warns about.

**Recommended order (not executed — writing to Program Files is Dean's call):**

1. Fix `EngineLoad(g/rev)1` `max` back to **8** first, or a `-Push` writes the
   clamp into ECUFlash.
2. Then `-Push` (repo → ECUFlash), **not** `-Pull`.
3. Re-run `.\scripts\sync_defs.ps1` to confirm convergence.

This closes the "repo and ECUFlash have been out of sync since 2026-04-07"
item with a direction and a reason, rather than leaving it as a standing warning.

---

## 56. The knock detector DOES have a load input — four per-cylinder 2×2 RPM×LOAD tables, all zeroed — **SETTLES items 49 and 53, 2026-08-16**

Items 49 and 53 each got half of this. This is the traced answer.

The detector at `0x043798` performs **three** table lookups, not two. The third
is the one that matters:

```
043860  D65D  mov.l @(0x0439D8),r6   ; r6 = 0x00063E68 (per-cylinder ptr table)
043862  C4B0  mov.b @(176,gbr),r0    ; r0 = byte[0xFFFF81AC] = CYLINDER index
043866  4008  shll2 r0
043868  046E  mov.l @(r0,r6),r4      ; r4 = that cylinder's descriptor
04386A  F4FC  fmov fr15,fr4          ; FR4 = RPM          (0xFFFF6624)
04386C  D559  mov.l @(0x0439D4),r5   ; r5 = 0x000BE8E4 (2-D table_lookup)
04386E  450B  jsr  @r5
043870  F5EC  fmov fr14,fr5          ; FR5 = ENGINE LOAD  (0xFFFF63F8)
043872  E0D8  mov #-40,r0
043874  F907  fmov.s fr0,@(r0,r9)    ; result -> workspace
```

Pointer table at `0x00063E68`, exactly four entries (one per cylinder; the next
two words are `0xFFFF81AD`/`0xFFFF81AF`, adjacent unrelated data):

| cyl | descriptor | shape | Y = RPM | X = LOAD | data |
|---|---|---|---|---|---|
| 0 | `0x0AE724` | 2×2 float32 | 800, 7600 | 0.8, 2.2 | all 0.0 |
| 1 | `0x0AE74C` | 2×2 float32 | 800, 7600 | 0.8, 2.2 | all 0.0 |
| 2 | `0x0AE738` | 2×2 float32 | 800, 7600 | 0.8, 2.2 | all 0.0 |
| 3 | `0x0AE760` | 2×2 float32 | 800, 7600 | 0.8, 2.2 | all 0.0 |

Typecode is `0x00` (float32), so `table_lookup` skips scale/bias entirely — the
apparent scale/bias fields in those records are meaningless and must not be quoted.

**This reconciles the whole argument:**

- The detection path **is** structurally indexed by RPM × engine load, per
  cylinder. "No load input" is **false** as a claim about the code.
- Those tables are **zero in every cell**, so the load term contributes nothing
  as this ROM is calibrated. "No load input" is **true** as a claim about
  observed behaviour.

That is why the old note survived empirical checking for so long: right about
the effect, wrong about the mechanism. Both earlier passes in this session were
half-right — item 49 said the load claim was false, item 53 said it looked true
again; neither had found this lookup.

**It also makes the load term a latent lever.** Populating `0xAE724` / `0xAE738`
/ `0xAE74C` / `0xAE760` would make knock detection load-sensitive. Recorded, not
proposed.

Corrected lookup count for the detector — **three**: `0xAE284` (1-D on knock
signal `0xFFFF4304`, live, 0–304), `0xAE290` (1-D on RPM 800–8000, all zero),
and the four per-cylinder 2×2 RPM × LOAD tables above (all zero).

**Still open:** whether the 2×2 lookup is the threshold itself or a per-cylinder
trim added to one. Its result lands at `[r9-40]` and is consumed by the
arithmetic at `0x043888`–`0x0438B0`.

---

## 57. All three fuel dispatch tables are equally unreferenced — reframes item 46 — **SCOPED 2026-08-16**

Item 46 left "table C's consumer is not located" as an open item. Checked
exhaustively, then checked the same way against the two *known* tables:

| table | address | literal refs anywhere, any alignment | `mova` into it |
|---|---|---|---|
| A | `0x0480B8` | **0** | 0 |
| B | `0x04A0B8` | **0** | 0 |
| C | `0x04ACB8` | **0** | 0 |

**This was never a table-C anomaly.** No dispatch table in this ROM has a
locatable reference, which means the existing analysis of tables A and B never
established their consumer either. The access is presumably a base built by
arithmetic (task id → table address) or a pointer initialised into RAM at
startup.

The open question is therefore not "what calls `func_3952C`" — item 46 answered
that (table C slot 20) — but "what walks the dispatch tables at all". That is a
scheduler question, not a fuel question. Correctly scoped, still open.

---

## 58. `0xAD7E0` is not a valid table; `0xCC51C`/`0xCC530` are not "gains" — **CHECKED 2026-08-16**

The three addresses brief #2 flagged as the genuine unknowns, all sourced from
`fueling_pipeline_analysis.txt` — the file that got `0xAD258` wrong four ways.

**`0xAD7E0`** parses as 2-D 5×3 float32, Y = 6.5 / 9.0 / 11.5 / 14.0 / 16.5,
X = −1000 / 0 / 1000, data at `0x0D106C`. The axes are plausible; the data is not
a table:

```
[0.0, 0.0, 0.0]
[0.0, 0.0, 0.0]
[0.0, 0.0, 5.0]
[7.0, 10.0, 1.29e+20]        <- garbage
[1.73e+18, 131328.0, 0.0]    <- garbage
```

No calibration table contains 1.29e+20. **The descriptor is malformed or its
data pointer is wrong. Treat `0xAD7E0` as NOT a valid table and do not cite it.**
One literal reference, at `0x030410`.

**`0xCC51C`** = `43 ff 00 00` = float **510.0** (literal ref `0x03BD0C`).
**`0xCC530`** = `46 1c 40 00` = float **10000.0** (literal ref `0x03BD20`).

Project notes label these "tip-in/out gains". 510 and 10000 are not gains — they
are limits or counter thresholds, and the surrounding code at `0x03BC30`–`0x03BC64`
is byte flag / state-machine work (`mov.b r0,@(1..7,r14)`, `cmp/hi`), not a
multiplicative fuel path. **Values VERIFIED; the "gains" name is UNSUPPORTED.**
Not renamed — there is no evidence for a replacement name yet.

---

## 59. CORRECTION TO ITEM 56 — the knock threshold tables are NOT zeroed; they are populated, and the load dimension is exactly FLAT — **2026-08-16**

Item 56 said the per-cylinder RPM × LOAD tables were "zero in every cell". **That
was my decode error, not the ROM.** I multiplied by the `scale`/`bias` fields of
records whose typecode is `0x00` (float32) — and `table_lookup` explicitly
**skips** scale/bias for typecode 0 (`0x0BE84A tst r3,r3 / bt 0x0BE858`). Those
fields hold unrelated bytes, so the product came out ~1e-37 and rounded to 0.0.
Same class of error as the descriptor width bug: trusting a field the code
doesn't read.

### The detector's five lookups, decoded correctly

| # | site | helper | descriptor(s) | input | data |
|---|---|---|---|---|---|
| 1 | `0x0437BE` | `0xBE830` 1-D | `0xAE284` | knock signal `0xFFFF4304`, clamped ≥0 | 0, 0, 32, 51, 64, 74 … 304 |
| 2 | `0x043858` | `0xBE8E4` 2-D | per-cyl `0xAE6D4`/`6E8`/`6FC`/`710` via ptr table `0x063E58` | FR4 = RPM, FR5 = **LOAD** | **3.60 → 3.45** |
| 3 | `0x04386E` | `0xBE8E4` 2-D | per-cyl `0xAE724`/`738`/`74C`/`760` via `0x063E68` | FR4 = RPM, FR5 = **LOAD** | **1000.0** everywhere |
| 4 | `0x043920` | `0xBE830` 1-D | per-cyl `0xAE29C`/`2A8`/`2B4`/`2C0` via `0x063E48` | RPM | **16.0** everywhere |
| 5 | `0x043944` | `0xBE830` 1-D | `0xAE290` | RPM | 8, 10, 10, 10, 10, 10, 12, 13, 10, 10 |

There are **five** lookups and **two** of them are 2-D RPM × LOAD, per cylinder.
Item 56 found only one of the two and mis-read its data.

### Lookup 2 is the real threshold, and here are its numbers

`0xAE6D4` (cylinder 0; the other three are structurally identical):
18-point RPM axis `0xD5C0C` = 800, 1200 … 7600; 2-point load axis `0xD5C54` =
**0.8, 2.2**; data at `0xD5C5C`, 36 float32.

```
RPM   800 1200 1600 2000 2400 2800 3200 3600 4000 4400 4800 5200 5600 6000 6400 6800 7200 7600
val  3.60 3.60 3.60 3.60 3.60 3.60 3.55 3.55 3.55 3.55 3.50 3.45 3.45 3.45 3.45 3.45 3.45 3.45
```

**The two load planes are byte-identical** — verified directly:
`rom[0xD5C5C:0xD5C5C+72] == rom[0xD5C5C+72:0xD5C5C+144]` is `True`. The 2-D
helper reads the row count from `mov.w @(0,r4),r0` (= 18) and the data pointer
from `mov.l @(12,r4),r1`, so the layout is two 18-value load planes, not 18
rows of 2.

### Final answer on the load question

- The knock detection threshold **is** structurally RPM × engine load, per
  cylinder, and it **is** populated: 3.60 at low RPM falling to 3.45 above 5200.
- **The load dimension is exactly flat.** Both load planes are identical, so
  changing load changes the threshold by nothing.
- That is why "knock detection has no load input" survived every empirical
  check: correct about the effect, wrong about the mechanism — and item 56's
  "zeroed" explanation was also wrong. The tables are populated; it is the load
  *axis* that is degenerate.
- It remains a **latent lever**: differentiating the two load planes in
  `0xAE6D4`/`6E8`/`6FC`/`710` would make detection load-sensitive. Recorded, not
  proposed — and note the threshold is in knock-signal units (same 0–3.5 domain
  as `0xAE284`'s axis), not degrees.

### Scope of the decode error

Checked every other table decoded this session for the same mistake:
`0xAC634` / `0xAC648` (item 47, `0x37B74`'s comps) are typecode `0x04` (uint8),
where scaling **is** applied — and their RAW bytes are all zero, so that
conclusion stands. `0xAD7E0` (item 58) was read raw both times, so its garbage
data stands. Only item 56's four 2×2 tables and `0xAE290` were affected.

---

## 60. The descriptor scanner under-reported by 30% — two more instances of the same off-by-one, plus a phase-locked walk — **FIXED 2026-08-16**

Ran the typecode-0 sweep Dean asked for. It found no corrupted values in any
committed artifact (see the sweep result at the end), but it did expose that
`descriptor_map.txt` was **missing a third of the descriptors in the ROM**.

### Bug A — the same `is_valid_axis` off-by-one, in two more files

Item 43 fixed this in `desc_to_func_xref.py`. It was also present, verbatim, in
`scan_descriptors.py` and `name_descriptors.py`:

```python
increasing = sum(1 for i in range(len(vals)-1) if vals[i+1] >= vals[i])
return increasing >= len(vals) * 0.7
```

`increasing` counts **pairs**, so its maximum is `len(vals)-1`, but the
threshold is `len(vals)`. **For a 2-point axis that is `1 >= 1.4` — False for a
perfectly monotonic axis.** Every narrow-axis descriptor in the ROM was silently
excluded, including all eight per-cylinder knock tables
(`0xAE6D4`/`6E8`/`6FC`/`710` and `0xAE724`/`738`/`74C`/`760`) — the very tables
item 59 had to decode by hand because they were not in the map.

### Bug B — the walk was phase-locked

```python
d = try_parse_2d(rom, addr) or try_parse_1d(rom, addr)
if d: addr += d["total_bytes"]     # 20 or 28
else: addr += 2
```

Advancing by the **record size** means any descriptor starting inside the
skipped span is never tested. Descriptors are interleaved at 12-byte offsets in
places, so the walk locked onto one phase. Symptom: raising the size guard
swapped `0xAE290`/`2A8`/`2C0`/`2D8` **out** and `0xAE284`/`29C`/`2B4`/`2CC`
**in** — while the detector trace proves *both* sets are real. Fixed to a fixed
4-byte stride (descriptors are 4-byte aligned; they hold u32 pointers).

### Bug C — the `size > 64` guard, third instance

Raised to 256 here too. `0xAE284` is 65 points and `0xAB334` is 78.

### Result

| | before | after |
|---|---|---|
| descriptors | 760 (1D 621 / 2D 139) | **1094** (1D 851 / 2D 243) |
| float32 / uint8 / uint16 | 149 / 215 / 396 | 326 / 287 / 481 |
| known-real descriptors missed | 12 of 16 | **0 of 16** |

Validation, because a 44% jump demands it:
- **1094 distinct data pointers, zero aliasing.** No two descriptors claim the
  same data pointer — random false positives would collide.
- **818 pass the strict contiguity rule** (`axis + count*4 == data`), against
  the 780 that `coverage_map.py` accepts independently by that same rule. The
  ~276 that don't are exactly the case coverage_map documents as its own blind
  spot: descriptors that *share* an axis with a neighbour.
- `scan_descriptors.py` and `name_descriptors.py` are independent
  implementations and now agree on 1094.

### Also fixed

- `scan_descriptors.py` applied `raw * scale + bias` unconditionally in its
  data-sample block, and printed the scale/bias columns for float32 rows. Both
  are now guarded; float32 rows print `--`, so the typecode-0 trap cannot be
  re-entered by reading the artifact.
- `scan_descriptors.py` now imports `TYPE_NAMES`/`TYPE_SIZES` from
  `scripts/desc_types.py` — the last duplicated copy of that map is gone.
- `gen_descriptor_labels.py` read `disassembly/named_descriptors.txt` and wrote
  `disassembly/descriptor_labels.txt`; both live under `disassembly/maps/`.
  Fixed, and `descriptor_labels.txt` regenerated to 1094 labels
  (f32 326 / u8 287 / u16 481 — matching the map exactly).
- `scripts/desc_types.py` gained `read_table()`, `scaling()`, `typecode()` and
  `is_2d()`. **Use `read_table()`; do not hand-roll `raw * scale + bias`.** It
  returns `scale=None` for typecode 0 and decodes 2-D data as X planes of Y
  values (verified on `0xAE6D4`, whose two 18-value load planes are
  byte-identical).

### Sweep result — no committed artifact was corrupted

All 149 (now 326) float32 descriptors hold an implausible value in the scale
field, so applying it always corrupts. Checked every `disassembly/analysis/*.txt`
and `disassembly/maps/*.txt` that mentions a float32 descriptor: eleven files do,
and **none of them print decoded values** — they are pool references, call sites
and labels. The corruption was confined to my own session analysis (item 56),
already corrected by item 59.

### Known gap, deliberately not closed

`ImportAE5L600L.java` still carries **860** `desc_*` labels covering the old
760-descriptor census. Those labels are correct but incomplete — 334 new
descriptors have no Ghidra label. `update_import_java.py` **must not be re-run**
to fix it: it is insert-only (appends a block before the final printf), so a
re-run duplicates every label, and its paths are wrong. A do-not-run banner was
added to that script. Closing the gap needs a replace-in-place rewrite.

---

## 61. `find_writers.py` double-scaled displacements — item 54's citation was wrong — **FIXED 2026-08-16**

Working item 4b exposed two bugs in the tool built for item 52.

**Bug A — displacements were scaled twice.** `sh2e_disasm` already prints every
displacement in **bytes**:

```python
0x1: f"mov.w r0,@({d8*2},gbr)"   0x2: f"mov.l r0,@({d8*4},gbr)"
op 0x1: f"mov.l {F},@({d4*4},{R})"   0x1: f"mov.w r0,@({d4*2},{F})"
```

`find_writers.py` then multiplied by the operand size again, putting every
`mov.w` target **2×** and every `mov.l` target **4×** too far. Fixed in both the
GBR and the register-displacement branches.

**Impact, checked rather than assumed.** In the `0xFFFF77D0`–`0xFFFF7990` sweep,
21 of 121 GBR writes are `mov.w`/`mov.l` and so had wrong targets before; 100 are
`mov.b` and were always correct. Every writer cited in **items 48 and 52** is
`mov.b` or INDEXED — those claims stand unchanged. `0xFFFF798C` in fact gains a
writer (`0x035A6A mov.w r0,@(56,gbr)`, GBR `0xFFFF7954`), reinforcing item 48's
dual-role finding.

**Item 54 is the one that was wrong.** It cited
`0x0367F2 mov.l r0,@(80,gbr)` (GBR `0xFFFF79A4`) as the writer of `0xFFFF7AE4`.
With the correct math that instruction targets `0xFFFF79A4 + 80 = 0xFFFF79F4`,
not `0xFFFF7AE4`. The real writer is:

```
FFFF7AE4  WRITE GBR  0365AA: mov.w r0,@(320,gbr)   ; GBR=FFFF79A4 set @03644E
```

**Item 54's conclusion survives** — the writer is still in the OL fuel map
selector region, still not `func_37B74`, so "enrichC = AFL application at
`0x37B74`" remains positively excluded. Only the address and width were wrong.
The width is worth noting on its own: `0xFFFF7AE4` is written **16-bit**, which
sits badly with the fuel model treating `enrichC` as a float multiplier.

**Bug B — `r0` was only tracked through `mov #imm,r0`.** Real code walks a struct
with `mov #-64,r0 / extu.b r0,r0 / add #4,r0 / …`, so most indexed writes were
invisible. `r0` is now tracked through `add #imm,r0` and `extu.{b,w} r0,r0`, and
invalidated when any other instruction writes it.

---

## 62. Item 4b — `0xFFFF77D8` / `0xFFFF77DC` writers still not found, but the question they gate is now CLOSED — **2026-08-16**

After fixing both tool bugs above, all four addressing forms still find **no
writer** for either address. Stated plainly rather than concluded away: the tool
cannot resolve a base register loaded from memory or built by register
arithmetic, so absence here is not proof.

**But the reason the item mattered is settled without them.** These two feed
branch A of `func_3952C` (the branch that does NOT use `0xAD258`), via
subroutine `0x3961C`:

```
039624  F540  fadd fr4,fr5     ; sum = [FFFF77DC] + [FFFF77D8]
039626  F89D  fldi1 fr8
039628  F580  fadd fr8,fr5     ; t = 1.0 + sum
       BE608(t, 0.0, 1/8192)   ; t approximately zero?  -> output 0
       BE628(1.0, t)           ; 1/t
039650  F080  fadd fr8,fr0     ; fr0 = 1/t - 1     (fr8 = -1.0)
039656  D647  mov.l @(0x039774),r6  ; = 0x000CC3E8 = 0.03
03965A  420B  jsr @r2               ; BE56C = clamp(value, 0.0, 0.03)
03965E  FE0A  fmov.s fr0,@r14       ; [FFFF7BAC] = result
```

The clamp floor is **0.0**, so the output exceeds zero only when
`1/t - 1 > 0`, i.e. `t < 1.0`, i.e.:

> **branch A produces a non-zero result only when
> `[0xFFFF77DC] + [0xFFFF77D8] < 0`, and even then it is capped at 0.03.**

It is a one-sided, 3%-max enrichment that arms only on a *negative* combined
trim. Whatever writes those two addresses, the branch contributes nothing while
their sum is ≥ 0.

**This closes the caveat left open in item 42.** That item said branch B is
clamped to `[0.0, 0.0]` but flagged that "which branch the car actually runs is
UNVERIFIED … it does determine whether the 0.03 limit at `0xCC3E8` is live".
Now: branch B is identically zero, and branch A is zero unless the trim sum goes
negative. So `func_3952C` contributes nothing to `0xFFFF7BAC` in the ordinary
case regardless of which branch runs, and `0xAD258` — which only branch B
consults — is inert either way.

Remaining, and correctly scoped: *what writes* `0xFFFF77D8`/`0xFFFF77DC`, and
whether their sum ever goes negative in practice. The second is a log question
(they are the AFC/AFL trim pair region), not a disassembly one.

---

## 63. ITEM 7 RESOLVED — the "fuel dispatch tables" are LITERAL POOLS, and nothing walks them — **2026-08-16**

Item 57 left this as "what walks the dispatch tables — a scheduler question".
The answer is that **nothing does, because they are not tables.**

### They are literal pools

For each of the three regions, the fraction of entries individually loaded by a
PC-relative `mov.l @(disp,PC),Rn` instruction:

| region | entries | individually PC-relative loaded |
|---|---|---|
| "table A" `0x047F9C`–`0x048100` | 90 | **89 (99%)** |
| "table B" `0x04A070`–`0x04A1D4` | 90 | **90 (100%)** |
| "table C" `0x04ACB8`–`0x04AE28` | 93 | **93 (100%)** |

There is no base pointer because none is needed — every entry is addressed
individually from code within PC-relative range. That is exactly why item 57's
exhaustive search found no literal and no `mova` for any of the three: it was
looking for something that does not exist.

**The analysis-assumed start addresses were also wrong.** `fueling_pipeline_analysis.txt`
treats the tables as beginning at `0x0480B8` and `0x04A0B8`; the actual
contiguous pointer runs begin at `0x047F9C` and `0x04A070`, so the assumed bases
are slots 71 and 18 of their pools, not slot 0.

### What the "slots" actually are

Two of the three pools serve **hand-unrolled straight-line call sequences** —
long runs of the identical three-instruction pattern:

```
04AA6C  D292  mov.l @(0x04ACB8),r2
04AA6E  420B  jsr  @r2
04AA70  1F41  mov.l r4,@(4,r15)      ; delay slot
04AA72  D292  mov.l @(0x04ACBC),r2
04AA74  420B  jsr  @r2
04AA76  0009  nop
                ... 92 consecutive calls ...
```

| pool | call sequence | count |
|---|---|---|
| C | `0x04AA6C`–`0x04AC8E` | 92 consecutive `jsr` |
| B | `0x049E14`–`0x04A030` | 91 consecutive `jsr` |

Pool A's consumers are scattered rather than one unrolled chain, but it is still
a literal pool (89 of 90 entries individually loaded).

The enclosing function for pool C begins at `0x04AA58` and is guarded:

```
04AA5C  D295  mov.l @(0x04ACB4),r2   ; 0x04ACB4 = 0xFFFF8EDC (sched_disable_flag)
04AA5E  6620  mov.b @r2,r6
04AA60  2668  tst r6,r6
04AA62  8901  bt 0x04AA68
04AA64  A1FD  bra 0x04AE62            ; disabled -> skip the whole sequence
```

So these ARE the scheduler task lists — but implemented as unrolled code, not as
data walked by an interpreter. The "slot index" is a pool ordinal, which happens
to equal call order, so the **ordering is meaningful** even though the
"dispatch table" mechanism is fiction.

### This also completes item 46

Item 46 found that `0x04AD08` holds `0x00039524`, the stub whose `bra` reaches
`func_3952C`, and called it "table C slot 20". The fact stands and now has a
mechanism:

```
04AAE4  D288  mov.l @(0x04AD08),r2   ; r2 = 0x00039524
04AAE6  420B  jsr  @r2               ; <-- THE CALLER OF func_3952C
04AAE8  0009  nop
```

`func_3952C` is **call #20** of the 92-call sequence at `0x04AA6C`. For contrast,
`0x039528` (which reaches `0x039668`) is **call #26** of pool B's sequence, from
`0x049EB2`. The two stubs 4 bytes apart are reached from two different call
sequences — as item 46 said, but now with the call sites named rather than
inferred.

### Corrections owed

- `fueling_pipeline_analysis.txt`'s "dispatch table A/B" framing is wrong in
  mechanism and wrong in base address. The entry addresses it lists are correct
  and the ordering is meaningful; the "table" is a literal pool.
- Item 57's framing ("all three dispatch tables are equally unreferenced …
  presumably a base built by arithmetic or a pointer initialised into RAM") is
  superseded: there is no base at all.

---

## 64. ITEM 9b RESOLVED — `func_37B74` is a bounded multiplicative fuel correction, and it IS on the fuel path — **2026-08-16**

Item 47 left both candidate names unsupported. Tracing the function's output
settles it.

### What it computes

```
037C10  F49D  fldi1 fr4              ; fr4 = 1.0
037C14  F0D6  fmov.s @(r0,r13),fr0   ; r0=-28 -> [0xFFFF7ABC]
037C18  F8D6  fmov.s @(r0,r13),fr8   ; r0=-24 -> [0xFFFF7AC0]
037C1A  F082  fmul fr8,fr0
037C1E  F8D6  fmov.s @(r0,r13),fr8   ; r0=-20 -> [0xFFFF7AC4]
037C20  F082  fmul fr8,fr0
037C24  F8D6  fmov.s @(r0,r13),fr8   ; r0=-16 -> [0xFFFF7AC8]
037C26  F48E  fmac fr0,fr8,fr4       ; fr4 = 1.0 + (A*B*C*D)
037C28  D247  mov.l @(0x037D48),r2   ; 0x000BE56C = clamp
037C2C  C748  mova @(0x037D4C),r0    ; upper = 1.5
037C30  420B  jsr  @r2
037C32  F508  fmov.s @r0,fr5         ; lower = 0.5
037C38  FD07  fmov.s fr0,@(r0,r13)   ; r0=-36 -> [0xFFFF7AB4]  <-- OUTPUT
```

with `r13 = 0xFFFF7AD8`, so the output address is **`0xFFFF7AB4`**.

**`output = clamp(1.0 + A·B·C·D, 0.5, 1.5)`** — and the bypass path writes
**1.0** exactly:

```
037C3A  F49D  fldi1 fr4
037C3E  FD47  fmov.s fr4,@(r0,r13)   ; r0=-36 -> [0xFFFF7AB4] = 1.0
```

A term whose neutral value is 1.0 and whose range is bounded ±50% is a
**multiplicative correction**, not a compensation offset.

### It is on the fuel path

`0xFFFF7AB4` has exactly two readers, and both are decisive:

| reader | enclosing function |
|---|---|
| `0x0301FC` | **`fuel_pw_calc`** (`0x0301E4`–`0x030674`) |
| `0x0347D4` | **`afl_pipeline`** (`0x034488`–`0x037B74`) |

`0x0301FC` sits 24 bytes into the fuel pulse-width calculator — it is one of the
first things that routine reads. **That closes item 47's "is it on the fuel path
at all" question: yes.**

### Which name is right

- **"Injector compensation (2D maps, RPM/load indexed)"**
  (`fueling_pipeline_analysis.txt:61`) is **WRONG**. Its two comps are **1-D**
  and indexed by **RPM** (`0xAC634`) and **ECT** (`0xAC648`) — not 2-D, not load.
- **"AFL application"** is **SUPPORTED**: the output RAM `0xFFFF7AB4` is already
  named `afl_multiplier_output` independently, and one of the two readers is the
  AFL pipeline itself.
- The **`enrichC` = `0xFFFF7AE4` half of that pairing stays wrong** (items 54,
  61): `func_37B74` does not write `0xFFFF7AE4`; that address is written 16-bit
  at `0x0365AA` from the OL fuel map selector.

So the fuel model's third term is an **AFL multiplier at `0xFFFF7AB4`**, not
`enrichC` at `0xFFFF7AE4`. Those were two different quantities merged under one
label.

### Gating

Bypass (output forced to 1.0) if any of: three stack status bytes equal 2;
`byte[0xFFFF7AD0] == 1`; `byte[0xFFFF7AD2] == 1`; or RPM ≥ `[0xCC2F0]`.
**`0xCC2F0` = 10000.0**, which is above any reachable engine speed, so that last
gate is a safety guard that never fires.

### Not established

Whether `A·B·C·D` is non-zero in practice. All four inputs
(`0xFFFF7ABC`/`7AC0`/`7AC4`/`7AC8`) have real writers from live code
(`0x037DBE`, `0x037EB0`, `0x037BCC`, `0x037BBC`), so the product is not
structurally zero — but the two comps this function itself contributes
(`0xAC634`, `0xAC648`) are flat zero on this calibration. Whether the whole
term collapses to 1.0 needs the other two inputs traced. Recorded as open.
