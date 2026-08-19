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

---

## 65. ITEM 10b RESOLVED — `0xCC51C` is a speed-limiter cut, `0xCC530` an RPM guard. "Tip-in/out gains" was wrong — **2026-08-16**

Item 58 verified the values (510.0 and 10000.0) but could not support the
"tip-in/out gains" name and declined to invent one. The code trace plus the
definition XML settle it.

### The consuming routine is the LIMITER block

Function `0x03BB6C`. Its three inputs, from literals `0x03BCE8`/`EC`/`F0`:

```
03BB7A  mov.l @(0x03BCE8),r2 ; fmov.s @r2,fr12   ; 0xFFFF65FC = VEHICLE SPEED
03BB7E  mov.l @(0x03BCEC),r2 ; fmov.s @r2,fr9    ; 0xFFFF6624 = RPM  -> @r15
03BB84  mov.l @(0x03BCF0),r2 ; fmov.s @r2,fr13   ; 0xFFFF620C = MANIFOLD PRESSURE
```

It then selects a cut/resume pair on a mode flag:

```
03BBA8  cmp/eq #1,r0
03BBAA  bf 0x03BBB6
03BBAC  mov.l @(0x03BD04),r2 ; fr15 = [0xCC520] = 510   ; mode A cut
03BBB0  mov.l @(0x03BD08),r2 ; fr14 = [0xCC528] = 505   ; mode A resume
03BBB6  mov.l @(0x03BD0C),r2 ; fr15 = [0xCC51C] = 510   ; mode B cut
03BBBA  mov.l @(0x03BD10),r2 ; fr14 = [0xCC524] = 505   ; mode B resume
03BBD4  fcmp/gt fr12,fr14                               ; compare vs VEHICLE SPEED
```

### The definition XML names the sibling pair

`definitions/AE5L600L 2013 USDM Impreza WRX MT.xml`:

```
line 971:  <table name="Speed Limiting Enable (Fuel Cut)"  address="cc520">
line 974:  <table name="Speed Limiting Disable (Fuel Cut)" address="cc528">
```

Mode A uses `0xCC520`/`0xCC528` — **defined**, and named exactly what the code
trace independently shows. Mode B uses `0xCC51C`/`0xCC524` — **undefined**, and
structurally identical.

> **`0xCC51C` = Speed Limiting Enable (Fuel Cut), alternate set** (510)
> **`0xCC524` = Speed Limiting Disable (Fuel Cut), alternate set** (505)

This mirrors the rev limit, which has three parallel pairs in the same block —
`0xCC500`/`504`, `0xCC508`/`50C`, `0xCC510`/`514`, all defined as
"Rev Limit On/Off (1)(2)(3)".

> **`0xCC530` = 10000.0, an RPM ceiling guard** in the same routine, compared
> against `float[0xFFFF6624]` at `0x03BBF2`. Above any reachable engine speed,
> so it never fires — the same never-fires guard pattern as `0xCC2F0` in
> `func_37B74` (item 64).

`0xCC52C` = 1260 is the manifold-pressure guard, compared against
`float[0xFFFF620C]`; the same 1260 appears at `0xCC518`, defined as
"Rev Limit Fuel Resume (Boost)".

### Stock comparison — these are FACTORY values, not a tune change

| addr | stock | 20.19c |
|---|---|---|
| `0xCC500` Rev Limit cut | 6700 | 6700 |
| `0xCC504` Rev Limit resume | 6650 | **6680** |
| `0xCC508`/`50C`, `0xCC510`/`514` | 6700 / 6650 | 6700 / **6680** |
| `0xCC51C`–`0xCC528` speed limiter | 510 / 510 / 505 / 505 | unchanged |
| `0xCC530` | 10000 | unchanged |

510 km/h (~317 mph) is unreachable, i.e. **no speed limiter** — correct for a
USDM car, and factory, not something the tune did. The only changes in this
block are the three rev-limit resume values, 6650 → 6680.

**"Tip-in/out gains: CC51C-CC530" is wrong** and should not be carried forward.
The block is rev limiter + speed limiter + their boost/RPM guards.

---

## 66. ITEM 11 (D5) — the "446 conflicting RAM labels" is really 26 — **2026-08-16**

Brief #2's D5 reported "446 RAM addresses carrying two or more distinct labels,
390 of which differ on the first word", and correctly warned that most of it was
prose noise from a crude regex. Doing the harvest properly:

> **26 addresses carry genuinely conflicting label claims. All 26 touch a
> priority subsystem.** 94% of the original figure was noise.

New durable tool: **`scripts/mapping/reconcile_ram_labels.py`** — harvests
address→label claims from every `disassembly/analysis/*.txt` and
`disassembly/maps/*.txt`, groups them, and ranks by (distinct labels) ×
(priority subsystem) × (registry flag). It **reports only**; adjudication is
writer-based, because the majority label has been the wrong one before
(`0xFFFF4130`, item 45).

### The four noise classes it removes

Each was a real defect in the naive approach, not just tuning:

1. **Prose words.** `\b(FFFF….)\s{2,}(IDENT)\b` harvests "when", "mov", "loaded",
   "does" as names. Fixed by requiring snake_case (`_` present, length ≥ 5) plus
   a small allow-list for genuine single-word names (rpm, iat, ect, …).
2. **Artifact filenames.** "… see `fueling_subfunctions_analysis`" was harvested
   as a label for whatever address preceded it. Rejected by filestem match and by
   `_analysis` / `_raw` / `_trace` / `_report` / `_review` / `_scout` suffix.
3. **Newline spanning — the worst one.** `\s` matches newlines, so
   `fuel_enrichment_A @ FFFF76D4` followed by `fuel_enrichment_B @ FFFF7878`
   paired `FFFF76D4` with `fuel_enrichment_B` and manufactured a conflict in the
   *fuel enrichment term naming* — the exact area where a real mispairing
   existed (item 64). Fixed with `[ \t]` instead of `\s`.
   **`fueling_pipeline_analysis.txt` is in fact self-consistent** on
   A = `0xFFFF76D4`, B = `0xFFFF7878`, C = `0xFFFF7AE4`.
4. **Type tokens** (`u8`, `f32`, `float32`) harvested as names.

### Two resolved this pass, writer-based

**`0xFFFF6254`** — claimed as `maf_current` (avcs, startup), `torque_related`
(ignition), `gear` (fueling), `torque` (accel). All four are unsupported as
stated. It is a **byte at offset +4 of a struct based at `0xFFFF6250`**, written
once, at `0x01DBC2`:

```
01DBAC  cmp/hs r2,r5
01DBB0  mov.b @r15,r1      / tst r1,r1   / bf 0x01DBC0
01DBB6  mov.b @(4,r15),r0  / tst r0,r0   / bf 0x01DBC0
01DBBE  mov #1,r0     <- all conditions met
01DBC0  mov #0,r0     <- otherwise
01DBC2  mov.b r0,@(4,r7)   ; r7 = 0xFFFF6250  ->  [0xFFFF6254]
```

It is written **0 or 1** from a three-condition test — a **boolean validity flag,
not a sensor value**. That rules out `maf_current` (a value) as well as `gear`
and `torque`. Its writer sits in the sensor/MAF region (`0x01Dxxx`, the same
region that hosts the `maf_voltage` GBR base at `0x01D8FE`), so it is
MAF/sensor-domain — consistent with CLAUDE.md already recording "51 int8 / 0
float" accesses for it. **No replacement name is invented**; what is established
is: byte flag, struct `0xFFFF6250`+4, sensor-domain, set by a 3-condition test.

**`0xFFFF7D18`** — claimed as `knock_suppress_flag` (knock_flkc) and
`fuel_system_state` (ignition_timing). **Both are right, from opposite ends.**
Its single writer is `0x03C75C mov.b r0,@(7,gbr)` with GBR `0xFFFF7D11`, in the
**fuel** region; its notable reader is the **FLKC learn routine** (`0x0463DE`).
So it is a fuel-state byte that the knock path consumes as a suppression gate.
`fuel_system_state` names its identity, `knock_suppress_flag` names its use —
a naming collision, not a factual conflict.

### Triage of the remaining 24

| class | count | note |
|---|---|---|
| already settled earlier this session | 5 | `0xFFFF3248`, `0xFFFF8298` (item 41), `0xFFFF4130` (item 45), `0xFFFF6354` (item 40), `0xFFFF829E` (item 6) |
| registry already `VERIFIED-BOTH` | 3 | `0xFFFF6350`, `0xFFFF63F8`, `0xFFFF6354` — the two labels are synonyms (`ect_current`/`ect_float`) |
| synonym / wording only | ~9 | e.g. `0xFFFF4284` `workspace_base` vs `intake_workspace_base` (same file), `0xFFFF826C` `knock_retard_value` vs `..._accumulator` (same file), `0xFFFF726C` three spellings of the same transient flag |
| genuinely open, materially different | ~7 | `0xFFFF64F5` boost flag vs engine-state byte; `0xFFFF3234` `flkc_work_bank1` vs `knock_learn_coarse`; `0xFFFF8258` `knock_metric` vs `flkc_retard`; `0xFFFF7F68`, `0xFFFF1288`, `0xFFFF8F24`, `0xFFFF895C` |

### Brief #2's HUNCH, tested

D5 suspected (~65%) that `boost_control_analysis.txt` and `avcs_analysis.txt`
were over-represented among conflicts. **Not supported.** In the cleaned list the
heaviest contributors are `ignition_timing_analysis.txt` (9 of 26) and
`knock_flkc_analysis.txt` (5); `boost_control_analysis.txt` appears twice and
`avcs_analysis.txt` once. The over-representation was an artifact of the noise
those two files' formatting happened to trigger.

### Status

The sweep is **scoped and tooled, not finished**: ~7 addresses still need
writer-based adjudication. That is a tractable list rather than the 446 it
looked like. Re-run the tool after any label change.

---

## 67. ITEM 12 — the AVCS VVT-error tables are NOT zeroed, and `trace_map_switching.py`'s descriptor decoder was wrong in every field — **FIXED 2026-08-16**

Item 12 was "re-derive the three `*_analysis.txt` prose files against the
corrected widths". Two of the three carried conclusions that the width fix
invalidates, and one generator turned out to be structurally broken.

### A. `avcs_analysis.txt` — a live feedback surface was declared inert

The four VVT-error feedback tables at `0xAF830` / `0xAF84C` / `0xAF868` /
`0xAF884` were described as "9x9, zeroed" and "all zeroed in stock". Decoded at
the correct width (**uint16**, not uint8; scale `0.0030517578125`, bias `-100.0`):

```
Y axis = VVT error  -11 -8 -6 -3  0  3  6  8 11   (degrees)
X axis = RPM        800 1200 1600 2000 2400 2800 3200 3600 4000

plane 0:  -7.00 -7.00 -5.47 -4.69  0.00  2.34  3.52  3.52  3.52
plane 3:  -7.00 -7.00 -7.00 -4.69  0.00  2.34  4.69  4.69  4.69
plane 8: -10.55 -7.00 -7.00 -4.69  0.00  3.52  4.69  4.69  4.69
```

Range **−10.55 .. +4.69**, monotonic in VVT error and **exactly 0.0 at error = 0**
— the signature of a live feedback table, not a stub. It is **byte-identical in
stock and 20.19c**, so this was never a tune artifact; the "zeroed" reading was
simply a wrong-width decode.

**This matters beyond bookkeeping:** an active AVCS error-feedback surface had
been written off as inert, which removes it from consideration in any AVCS
reasoning. Corrected at all six sites in the file.

Also in the same file, `0xAD848` (Exhaust Duty Correction A) was documented as
"uint16, scale=0.000061, **bias=-100**. All values cluster near -100 (effective
zero correction)." Decoded: **bias is 0.0**, and the values are **0.09 .. 0.35** —
they do not cluster near −100. The −100 was picked up from a neighbouring
record's field. The file's *conclusion* ("NOT ACTIVE on EJ255 — no exhaust AVCS
hardware") still stands, but on hardware grounds, not on the numeric argument it
gave.

Checked and found **correct**, no change: `0xAD620` (10x9 uint8, scale 0.2,
values 5.0–22.0 duty %).

### B. `trace_map_switching.py` — `decode_descriptor` was wrong in every field

```python
flags = r_u8(desc_addr)          # +0/+1 is a u16 COUNT, not flags
dtype = r_u8(desc_addr + 1)      # +1 is the SIZE byte; typecode is +2 (1D) / +16 (2D)
ycnt  = r_u8(desc_addr + 2)      # +2 is the TYPECODE
is_2d = bool(flags & 0x01)       # 2-D is signalled by +3 != 0
data_addr  = r_u32(desc_addr + 4)   # +4 is the AXIS pointer
xaxis_addr = r_u32(desc_addr + 8)   # +8 is the DATA pointer
scale_f    = r_f32(desc_addr + 16)  # +16 is the BIAS; scale is +12
```

Every descriptor line that file ever emitted was structurally wrong — which is
why `0xADB4C` printed as `1D unk_10 0 scale=-20`. `unk_10` was the *count* (16)
being read as a typecode, `0` was the typecode being read as a count, and `-20`
was the *bias* labelled as the scale.

**This also means my own earlier "fix" was cosmetic on top of a broken line.**
In corrections item 60 I surgically rewrote the type tokens in that file rather
than regenerating (to preserve hand-added instruction decodes). That put a
correct-looking `uint8` onto a line whose other four fields were still garbage.
Rewritten now from the canonical layout in `scripts/desc_types.py`; the five
`desc_timing_blend_*` lines read correctly:

```
Descriptor @ 0x0ADB4C: 1D uint8 16  scale=0.351562 bias=-20.0000  [desc_timing_blend_0]
```

So the timing-blend tables are 16-point uint8, scale 0.3516, bias −20 — i.e.
degrees over roughly −20 .. +69.7, on an ECT axis at `0x0D2F8C`.

### C. `boost_control_analysis.txt` — nothing to correct

Its only mention of an affected descriptor is a category count
(`1 x 2D_RPMxBoost (0xAB058)`). Verified independently: `0xAB058` is 9x7 uint16,
Y = RPM 800..4000, X = boost 0..25.3, values 0..100. The prose makes no width or
value claim, so there is nothing to fix.

### Status

Item 12 is **done for the width-dependent claims**, which is what it was scoped
to. These files contain much more prose than that, and the rest has not been
re-derived — it was never in scope and is not implied by this entry.

---

## 68. Ghidra descriptor labels synced — 1094/1094, and a new idempotent tool — **FIXED 2026-08-16**

Item 60 left a deliberate gap: `ImportAE5L600L.java` carried labels for the old
760-descriptor census while `descriptor_labels.txt` had grown to 1094. The gap
could not be closed by re-running `update_import_java.py`, which is insert-only
(it appends a block before the final printf) and would have duplicated every
label; its paths were wrong too.

New tool: **`scripts/mapping/sync_import_java_labels.py`**.

### Why address-keyed and additive rather than a rewrite

The java is not machine-owned. Of its existing descriptor entries, **123 are
hand-annotated `labelComment(...)` calls** carrying `"RR: <table name>"` prose
and multi-line comments no generator can reproduce — e.g.

```java
count += labelComment(0x0AF0ACL, "desc_2D_range_150_600_xIAT_u16_17x9_AF0AC",
    "RR: Idle Speed Stability A");
```

A block replace would have destroyed them. So the tool:

- **leaves every address already present exactly as it is** — hand comments,
  and the corrected type tokens from item 60, both survive untouched;
- **adds only missing addresses**, into one delimited block it owns and
  regenerates in place;
- **never deletes.** Addresses in the java that are not in the descriptor list
  are reported and left alone.

### Result

| | before | after |
|---|---|---|
| `desc_*` entries | 860 | 1178 |
| distinct addresses | 795 | 1113 |
| descriptors covered | 780 / 1094 | **1094 / 1094** |
| duplicate addresses | 65 | 65 (unchanged) |
| duplicate names | 0 | 0 |

318 labels added. Idempotency verified by running `--apply` three times and
comparing md5 — identical each time. (The first implementation was **not**
idempotent: `strip_block` removed the managed block but left the blank line
after it, so the file gained one blank line per run. Caught by the md5 check,
fixed by swallowing the trailing newline.)

### Left alone, deliberately — 19 `desc_*` labels that are not descriptors

- **8 RAM workspaces** (`0xFFFF2398`, `0xFFFF24A8`, `0xFFFF2D88`, `0xFFFF2E48`,
  `0xFFFF2EF4`, `0xFFFF2F84`, `0xFFFF30E4`, `0xFFFF34EC`) whose names merely
  begin with `desc_`.
- **3 code addresses** (`0x00DCE4`, `0x0BDBCC`, `0x0BDCB6`) — helper functions.
- **8 ROM addresses** `0xAF238`–`0xAF318` that are **not descriptors**: their
  `+4` field is `0x08000000`, not a ROM pointer. They were mislabelled before
  this session and are flagged here rather than silently removed — deleting a
  label is a human judgement call, not a sync script's.

### Pre-existing issue, reported not fixed

**65 addresses carry two different `desc_*` labels each** — a generated name and
a hand-written semantic one, e.g. `0x0AC484` has both
`desc_1D_ECT_u8_16_AC484` and `desc_avcs_run_time_corr`. This predates the sync
(65 before, 65 after) and would give Ghidra two labels at one address. The hand
names carry meaning and the generated ones carry the type, so which to keep is a
judgement call. Listed for a human pass.

---

## 69. The 61 duplicate Ghidra labels resolved — one label per address — **FIXED 2026-08-16**

Item 68 reported, but did not fix, 61 addresses carrying two `desc_*` labels
each. Ghidra applies every `label()` call, so those addresses ended up with two
symbols and an arbitrary primary. Resolved with a new tool,
**`scripts/mapping/dedupe_import_java_labels.py`**.

They were never factual disagreements — nobody was wrong about what the table
is. They were two naming passes colliding, and they fall into three groups:

| group | count | shape | rule applied |
|---|---|---|---|
| A | 52 | generated + hand, e.g. `desc_1D_ECT_u8_16_AC484` + `desc_avcs_run_time_corr` | keep the **hand** name |
| B | 4 | two hand names, `0xADBC4`–`0xADC00`: `desc_timing_ect_corr_N` vs `desc_ect_warmup_1D_modeNN` | keep the **mode-bit** name |
| C | 5 | two hand names, `0xAE54C`–`0xAE5BC`: `desc_ign_timing_modeN` vs `desc_final_timing_X` | keep `desc_final_timing_*` |

Group B keeps the mode-bit name because it encodes the throttle × engine-running
selector state — the thing you would actually search for; the index name does not
say which condition selects the table. Group C is arbitrary on information
grounds, so the name that says what the table *is* wins over the one that says
which slot it occupies.

### Result

```
entries    1178 -> 1113        distinct addresses 1113 (unchanged)
duplicate addresses 61 -> 0    duplicate names 0 -> 0
descriptor coverage 1094/1094  (unchanged)
braces balanced, paren delta unchanged
```

97 lines removed. Idempotent by construction — after a successful run no address
has two labels, so a second run reports 0 and does nothing. Verified.

### One decision reversed mid-implementation, deliberately

The first draft folded the deleted generated name's geometry (`1D uint8 16pt`)
into the surviving label's comment, so the type information would not be "lost".
**That was the wrong call and it was dropped.**

Geometry is already held authoritatively in `descriptor_map.txt` and
`descriptor_labels.txt`, both regenerated from ROM bytes on every run. Copying it
into a hand-frozen Java comment would create another copy that drifts the moment
a descriptor changes — which is *exactly* the failure mode behind items 39, 43
and 60 (one typecode map copy-pasted into five scripts, all five wrong; one
off-by-one copy-pasted into three). Nothing is lost by omitting it: look the
geometry up where it is derived.

The rationale is recorded in the tool's source so a future pass does not
"helpfully" add it back.

### Note

This is the only **destructive** edit in the whole descriptor sweep — everything
else was additive or in-place correction. Backed by git; the pre-state is commit
`8d7e02f`.

---

## 70. Logged `AFC`/`AFL` are `0xFFFF76D4`/`0xFFFF7878`, NOT `0xFFFF77D8`/`0xFFFF77DC` — item 62's "log question" is unanswerable as posed — **CORRECTS ITEM 62, 2026-08-17**

Reference bin for every byte claim below: `rom/AE5L600L 20g rev 20.19c.bin`,
md5 `92cae8275cd4f9b473a3a9e36efe6449` (re-verified from disk this session).

### What item 62 claimed

Item 62 closed the `func_3952C` branch-A question and left two things open, the
second with a parenthetical:

> Remaining, and correctly scoped: *what writes* `0xFFFF77D8`/`0xFFFF77DC`, and
> whether their sum ever goes negative in practice. The second is a log question
> (they are the AFC/AFL trim pair region), not a disassembly one.

**The parenthetical is wrong, and it is the load-bearing part** — it is what made
the item look answerable from the existing 55-log corpus. It is not.

### VERIFIED — the SSM getters

`logs/logcfg.txt` declares `AFC paramid = 0x000009` and `AFL paramid = 0x00000A`.
Those are **stock SSM parameter indices (P3/P4), not tagged RAM reads**, so they
route through the getter-pointer table at `0x06423C` rather than through the
read-address patch (`docs/ssm-read-patch.md`).

```
064260: 0005D2C0        ; getter table index 0x09  (AFC)
064264: 0005D2DA        ; getter table index 0x0A  (AFL)

05D2C0  4F22  sts.l pr,@-r15
05D2C2  D2AE  mov.l @(0x05D57C),r2      ; [0x05D57C] = FFFF76D4
05D2C4  F428  fmov.s @r2,fr4            ; <- AFC source

05D2DA  4F22  sts.l pr,@-r15
05D2DC  D2AA  mov.l @(0x05D588),r2      ; [0x05D588] = FFFF7878
05D2DE  F428  fmov.s @r2,fr4            ; <- AFL source
```

**Logged `AFC` = `0xFFFF76D4`. Logged `AFL` = `0xFFFF7878`.**

Two independent corroborations, both already in-repo and both previously
un-cross-referenced:

- `disassembly/analysis/cl_ol_master_analysis.txt:786` — "FFFF7878 float SSM AFL
  display value (PID 0x0A reads this)"; `:830` — "0x0005D2DA SSM PID 0x0A getter
  (reads FFFF7878)".
- `disassembly/analysis/fueling_pipeline_analysis.txt:366-367` — `fuel_enrichment_A
  @ FFFF76D4`, `fuel_enrichment_B @ FFFF7878`. So **the logged trims ARE enrichA
  and enrichB**, the first two terms of the multiplicative fuel model.

### Consequence

`[0xFFFF77D8] + [0xFFFF77DC] < 0` **cannot be evaluated against any log we have.**
Neither address appears in `logs/logcfg.txt` in any rev. Do not re-open this as a
corpus query.

### But the static route narrows it to ONE address

`0xFFFF77DC`'s writer IS findable — not by `find_writers.py` (the destination is
passed by pointer, so no literal store exists to match), but by reading the caller.

```
033342  B4BD  bsr 0x033CC0            ; r4 = 0x00063A44  (loaded at 0x033340)
        063A44 -> FFFF77DC            ; pointer-to-destination

033CC0  ...   mov r4,r13
033CCC  D26E  mov.l @(0x033E88),r2    ; = FFFF6624  (RPM)  -> fr15
033CD0  D26E  mov.l @(0x033E8C),r2    ; = FFFF63F8         -> fr14
033CF2  D469  mov.l @(0x033E98),r4    ; = 0x000AD8D4   \
033CF6  D469  mov.l @(0x033E9C),r4    ; = 0x000AD8B8    |  4-way selector on a
033CFE  D468  mov.l @(0x033EA0),r4    ; = 0x000AD90C    |  byte arg + [FFFF984D]
033D02  D468  mov.l @(0x033EA4),r4    ; = 0x000AD8F0   /
033D04  D268  mov.l @(0x033EA8),r2    ; = 0x000BE8E4  (2-D interpolate)
033D0C  62D2  mov.l @r13,r2           ; r2 = *(0x63A44) = FFFF77DC
033D0E  F20A  fmov.s fr0,@r2          ; <- the write
```

So the routine at `0x33CC0` is a **selector over four tables**, not one. All four
descriptor records read from bytes:

| descriptor | shape | data | XML name |
|---|---|---|---|
| `0xAD8B8` | 11×10 | `0xD14D0` | **CL Fueling Target Compensation A (Load)** (`definitions/AE5L600L 2013 USDM Impreza WRX MT.xml:483`) |
| `0xAD8D4` | 11×10 | `0xD1600` | *(not in the XML)* |
| `0xAD8F0` | 13×12 | `0xD1740` | **CL Fueling Target Compensation B (Load)** (`…xml:488`) |
| `0xAD90C` | 13×12 | `0xD18DC` | *(not in the XML)* |

All four: typecode `0x08` = uint16, scale `1/65536`, offset `−0.5`, Y = load
(0.200…1.600), X = RPM (800…5000).

**Every cell of all four tables is negative.** Combined range **−0.00475 …
−0.14999**; `0` cells `>= 0` out of 532. The `0xAD8D4` grid decodes to clean round
calibration values (−0.008 / −0.009 / −0.010 / −0.0105 / −0.011 / −0.012 / −0.013 /
−0.0135 / −0.014 / −0.015 / −0.016 / −0.017 / −0.020 / −0.030 / −0.050 / −0.075 /
−0.100 / −0.125 / −0.150), deepening with load — the 1.6 row walks −0.050 → −0.150
across RPM. Round values are themselves the confirmation that the scale/offset
decode is right.

### What this does to item 62's conclusion

Item 62 stated the criterion correctly but framed it as an edge case:

> branch A produces a non-zero result only when `[0xFFFF77DC] + [0xFFFF77D8] < 0`

**Since `0xFFFF77DC` is unconditionally negative by at least 0.00475 and by up to
0.15, that is the DEFAULT state, not the exception.** Branch A is suppressed only
when `[0xFFFF77D8] >= +0.00475…+0.150` (cell-dependent). The reasonable prior is
now that branch A is **live**, and that the `0.03` cap at `0xCC3E8` is a real
term in the fuel stack — the opposite of the "contributes nothing in the ordinary
case" reading item 62 landed on.

**The whole question now reduces to the sign and magnitude of `0xFFFF77D8` alone.**
`afc_pi_controller_trace.txt:191` places it at `R9+0xB0` — a struct-relative store
that `find_writers.py` structurally cannot resolve (item 62 said as much), so the
tool failing twice on it is expected, not evidence of absence.

### Two traps recorded

1. **`descriptor_map.txt:692` lists `0xD1600` as `0xAD8D4`'s X-axis pointer. It is
   the DATA pointer.** The real X axis is `0xD15D8`. Decoding the table at the
   descriptor address itself produces the item-60 phase-locked walk (values that
   look table-shaped but shift one column every two rows). The descriptor record
   layout read from bytes at `0xAD8D4` is unambiguous:
   `000B 000A | 000D15AC | 000D15D8 | 000D1600 | 08000000 | 37800000 | BF000000`
   = rows | cols | Y | X | **DATA** | typecode | scale | offset.
2. **Definition gap:** `0xD1600` and `0xD18DC` are live, selector-reachable
   siblings of the two named CL Fueling Target Comp tables and are **absent from
   the XML**. Anyone editing Comp A/B in RomRaider is editing two of four
   reachable tables. Candidates for the next definition sync (cf. item 55).

### How to close the remainder

`0xFFFF77D8` is directly loggable — the read-address patch supports arbitrary RAM
reads and the `F4` tag selects a 4-byte read (`docs/ssm-read-patch.md`). Adding
`paramid = 0xF477D8` (plus `0xF477DC` as the control, `0xF47BAC` for branch A's
output, `0xF47AB4` for `func_37B74`'s product — item 64's open question) settles
items 62 and 64 empirically in one drive. Costs +16 bytes on the SSM stream;
watch the cadence, `8-4 20.19c` is already a cadence-era boundary in the corpus.


---

## 71. `Intake`/`Exhaust Duty Correction A` declare X and Y backwards — the data is read with the wrong stride — **EXTENDS ITEM 28, 2026-08-17**

Reference bin for every byte claim below: `rom/ae5l600l.bin`, md5
`a8ea39d447f977e270e27ee670243c88`. Both tables are **byte-identical to stock in
all 19 bins in `rom/`**, so nothing has been mis-edited through the bad view.

### What item 28 established, and the part it did not reach

Item 28 proved from code that descriptor `0x0AD620` takes axis0 (`0xCF9EC`) from
FR14 = `0xFFFF63C4` = **mass airflow g/s**, and axis1 (`0xCFA14`) from FR15 =
RPM — so the axis *name* "Intake VVT Error" is wrong. It then concluded:

> The descriptors match the project XML's own bindings exactly (data `0xCFA38` /
> `0xD121C`, axes `0xCF9EC` / `0xD11D0`), so the *tables* are bound correctly and
> only the axis **labels** are wrong.

The bindings are indeed right. But "only the labels" is incomplete: the axis
**roles** are also wrong. `32BITBASE.xml:5042` types `Engine Speed` (9 elements)
as the **X Axis** and the 10-element axis as the **Y Axis**. X is the fast
(contiguous) axis, so anything honouring that declaration strides the 90 data
bytes by **9** when the ROM lays them out by **10**.

### VERIFIED — three independent lines, none reading a derived file

**1. The descriptor convention.** Across every 3-D table where a ROM descriptor
and both addressed axes exist, the `+4` pointer (with the `+1` count) is the
definition's **X** axis in **61 of 63** tables, and no table fails to match a
pointer. The two exceptions are exactly these:

```
desc 0x0AD620  00 0A 00 09 | 000CF9EC | 000CFA14 | 000CFA38
                  ^ +1 = 10   ^ +4 = the 10-point axis   ^ data
desc 0x0AD848  00 0A 00 09 | 000D11D0 | 000D11F8 | 000D121C
```

The `+4` pointer is the 10-point airflow axis, not the 9-point RPM axis.

**2. Contiguous layout.** `0xCF9EC` (10 floats) + 40 = `0xCFA14` (9 floats)
+ 36 = `0xCFA38` (data). The fast axis is laid down first — the same rule that
holds for the 57 other 3-D tables whose axes are contiguous.

**3. The data.** Read stride-10, the *exhaust* table is **9 identical rows** — a
pure function of airflow, flat in RPM. Read stride-9, it becomes a staircase
that shifts one cell per row. The intake table's row roughness is **5.56**
stride-10 vs **10.59** stride-9.

### It is not a display-orientation choice

A cosmetic X/Y swap would make the declared view the **transpose** of the ROM
view. It does not: stride-9 and stride-10 agree on **2 of 90 cells**. Only the
first cell survives. This is a different byte-to-cell mapping, not a rotated one.

### The correct reading — f(mass airflow, engine speed)

Display values (`Intake Duty Correction (uint8)`, `x*0.2`), 9 RPM rows x 10 g/s
columns:

```
 RPM \ MAF g/s    4     6    10    15    20    25    30    40    60    80
      650      11.6  10.0   6.6   6.0   5.6   5.0   5.0   5.0   5.0   5.0
      800      12.4  10.8   7.0   6.2   5.8   5.6   5.4   5.4   5.4   5.4
     1000      13.6  11.2   8.2   6.8   6.0   5.6   5.4   5.4   5.4   5.4
     1200      14.6  12.2   8.8   7.2   6.4   5.8   5.4   5.4   5.4   5.4
     1600      16.0  15.4  11.2   9.2   7.8   6.8   6.6   6.2   6.0   5.8
     2000      18.0  16.0  12.6  10.4   9.0   8.0   7.2   6.6   6.4   6.2
     2400      19.0  17.0  14.0  11.2  10.2   9.2   8.0   7.2   6.8   6.4
     3000      20.0  18.0  15.6  13.4  12.4  11.0  10.0   8.8   8.0   7.6
     3600      22.0  21.0  19.8  15.2  14.2  13.0  12.6  11.6  10.0  10.0
```

Monotone in both directions — more duty as revs rise, less as airflow rises.
Under the declared stride-9 view the maxima instead walk one cell right per row
(11.6, 12.4, 13.6, 14.6, 16.0, 18.0, 19.0, 20.0, 22.0), which is the signature
of a wrong stride, not a calibration surface.

### The fix — in the ECUFlash UI, not the repo

The X/Y typing is inherited from `32BITBASE.xml`, so it also affects the
unmapped `B`/`C`/`D` variants of both families. For each of the two addressed
tables, the 10-element axis must become the **X Axis** and the 9-element
`Engine Speed` axis the **Y Axis**:

```xml
<table name="Intake Duty Correction A" address="cfa38" scaling="Intake Duty Correction (uint8)">
    <table name="Mass Airflow"  type="X Axis" address="cf9ec" elements="10" scaling="MassAirflow(g/s)1"/>
    <table name="Engine Speed"  type="Y Axis" address="cfa14" elements="9"/>
</table>

<table name="Exhaust Duty Correction A" address="d121c">
    <table name="Mass Airflow"  type="X Axis" address="d11d0" elements="10" scaling="MassAirflow(g/s)1"/>
    <table name="Engine Speed"  type="Y Axis" address="d11f8" elements="9"/>
</table>
```

`MassAirflow(g/s)1` is the correct existing scaling (`32BITBASE.xml:129`:
float, `toexpr="x"`, units `Mass Airflow (g/s)`) -- do **not** invent a new
scaling name, and do **not** use `MassAirflow(g/s)` (line 128), which is uint16
with `x*.004577637`. The axis currently carries `VVT Error`, also `toexpr="x"`
on a float, so the displayed breakpoints do not change -- only the name, the
units and the role do.

The axis rename is item 28's outstanding fix, folded in here because it is the
same edit. Per items 24-26 the repo XMLs are **not** edited: make the change in
ECUFlash and bring it back with `.\scripts\sync_defs.ps1 -Pull`.

> **`sync_defs.ps1` now reports both XMLs SHA256-identical to the ECUFlash copies
> under `C:\Program Files (x86)\OpenECU\EcuFlash\rommetadata\subaru`.** CLAUDE.md
> still warns that the repo is ~37 tables ahead of ECUFlash and that a blind
> `-Pull` would delete them; that warning is **stale as of 2026-08-17** and the
> pull path is clear. Re-check before relying on it.

### Open

**What ECUFlash actually renders is not established here.** All three lines of
evidence above are about ROM bytes and the XML text; none of them observes
ECUFlash's own axis-role resolution. If the table shows column headers
`650 … 3600`, ECUFlash strides by 9 and the displayed surface is scrambled; if
it shows `4 … 80`, ECUFlash reads it correctly and the defect is confined to
`scripts/defs.py` and anything downstream of it. Settle it by looking at the
column headers before assuming which tool needs fixing.

### Status

Recorded here only. No XML edited, no data changed. `docs/verification-status.md`
is unaffected — `coverage_map.py` checks geometry and width, not axis role, so
neither table was ever flagged.

---

## 72. `func_37B74`'s fuel multiplier is DEAD — `A` reads a neutral-filled table and both AFL ramp rates are `0.0` — **CLOSES OPEN-HOLE 2, 2026-08-18**

Open-hole 2 asked whether the product term in

```
[0xFFFF7AB4] = clamp(1.0 + A*B*C*D, 0.5, 1.5)      bypass writes exactly 1.0
A = [0xFFFF7ABC]  B = [0xFFFF7AC0]  C = [0xFFFF7AC4]  D = [0xFFFF7AC8]
```

can ever go non-zero. Its output is read by `fuel_pw_calc` at `0x0301FC` and by
the AFL pipeline at `0x0347D4`, so a non-zero product would be a live
multiplicative fuel term. **It is zero. The multiplier is a constant 1.0.**

Settled by decompiling the two writers in Ghidra (SH-2A re-import, 2026-08-18)
and then verifying every constant against ROM bytes in
`rom/AE5L600L 20g rev 20.19d.bin`.

### A (`0xFFFF7ABC`) is a table read, and the table is neutral everywhere

`FUN_00037d74` — the function holding the two indexed writes at `0x037DBE` /
`0x037DC6` — does not compute `A`. It looks it up:

```c
if (afl_transient_copy == 0 && afl_engine_status_copy == 0
    && afl_counter_1 > 1 && afl_counter_2 > 1) {
    afl_2d_correction = table_lookup_2D(&desc_2D_BoostxLoad_u8_16x2);   // 0xAD71C
} else {
    afl_2d_correction = 0.0;
}
```

Descriptor `0xAD71C` decoded with `scripts/desc_types.py` (never hand-rolled —
see the float32 trap in CLAUDE.md): 2-D, typecode `0x04` = uint8, 16 x 2,
scale `0.00390625`, bias `-0.5`, data at `0x0D0740`.

```
0x0D0740: 8080 8080 8080 8080 8080 8080 8080 8080
          8080 8080 8080 8080 8080 8080 8080 8080
```

All 32 cells are raw `0x80`. `0x80 * 0.00390625 - 0.5 = 0.0`. The table is
**deliberately neutral-filled, not empty** — raw zero would display `-0.5`.

So `A` is identically `0.0` on both branches, therefore `A*B*C*D = 0`,
therefore `[0xFFFF7AB4] = clamp(1.0, 0.5, 1.5) = 1.0` for every operating point.
Same shape as the `0xAD258` result (item 40): live code, dead calibration.

### B (`0xFFFF7AC0`) is a STEP, not a ramp — both rates are zeroed calibrations

`FUN_00037e70` holds all four writers of `B` (`0x037EB0`, `0x037EC6`,
`0x037EEE`, `0x037EF4`). The decompiler renders its two ramp arms as
`afl_ramp_multiplier + 0.0` and `afl_ramp_multiplier - 0.0`. Those are literal
pool loads, resolved from bytes:

```
037EB6: D22E  mov.l @(0x037F70),r2   ->  0x000CC32C   ramp-UP rate
037EDE: D226  mov.l @(0x037F78),r2   ->  0x000CC330   ramp-DOWN rate

0xCC32C: 00000000 = 0.0
0xCC330: 00000000 = 0.0
```

`min(x + 0.0, 1.0)` and `max(x - 0.0, 0.0)` are both no-ops. `B` therefore only
ever takes the values written directly:

```
037EAA: F59D  fldi1 fr5   ...  037EB0: F65A  fmov.s fr5,@r6    ->  1.0
037EF0: F58D  fldi0 fr5   ...  037EF4: F65A  fmov.s fr5,@r6    ->  0.0
```

`B` in `{0.0, 1.0}`. It **can** be non-zero — `A` is what kills the product.
Note this for any future work: even with `A` populated, `B` snaps rather than
ramps until `0xCC32C`/`0xCC330` are set.

### Three latent levers, none defined in either XML

`defs.covering()` returns NONE for all of them.

| what | address | current value |
|---|---|---|
| AFL 2-D correction data | `0x0D0740` | 32 x `0x80` -> `0.0` |
| AFL ramp-up rate | `0x000CC32C` | `0.0` |
| AFL ramp-down rate | `0x000CC330` | `0.0` |

Same pattern as the per-gear timing comp (`0xD5454` gated by `0xD2D48` = 0.0):
live code, zeroed calibration, no definition. Not a lever until defined and
populated — and populating `0x0D0740` alone would revive a fuel multiplier on
the IPW path, so it is not a casual edit.

### Naming caution — `desc_2D_BoostxLoad_u8_16x2` is not supported by the ROM

The descriptor's own axis arrays are placeholder index ramps:

```
y-axis @0x0D06F8 (16 floats): 0,1,2,3,...,15
x-axis @0x0D0738 ( 2 floats): 0,1
```

No physical units, no breakpoints. "Boost x Load" is a project guess, exactly
the `0xD39A8` failure mode of item 36. Whatever selects this surface, it is not
established here. **Do not reason from the name.**

### Incidental: `0xBE960`/`0xBE970` re-confirmed from an undecoded path

```
037F74 -> 0x000BE970   called with ceiling 1.0  (fldi1)  => float_MIN
037F7C -> 0x000BE960   called with floor   0.0  (fldi0)  => float_MAX
```

Independent re-confirmation of the identity that was backwards across ~25 files,
from a function nothing had previously decoded.

### Status

Recorded here. No XML edited, no ROM byte changed. `docs/verification-status.md`
is unaffected — none of `0x0D0740`, `0x0CC32C`, `0x0CC330` is a defined entity,
so `coverage_map.py` never flagged them and still will not.

---

## 73. `find_writers.py` reported PHANTOM WRITERS in calibration space — it decoded the whole 1 MB as code — **FIXED 2026-08-18**

`scripts/mapping/find_writers.py` is the tool CLAUDE.md points at for settling
RAM identities, and three of the four identity fixes on 2026-08-16 came from it.
It had no region filter: it ran the SH-2E decoder over all 1,048,576 bytes and
reported every apparent store, including ones inside calibration tables.

Found while working open-hole 1. `find_writers.py FFFF895C` returned three
writers, two of them at `0x0D7E84` and `0x0D8020`. Decoded in context:

```
0D7E80: C316  trapa #22
0D7E82: 0000  .word 0x0000
0D7E84: C2FA  mov.l r0,@(1000,gbr)
0D7E86: 0000  .word 0x0000
0D7E88: C2C8  mov.l r0,@(800,gbr)
0D7E8C: C296  mov.l r0,@(600,gbr)
0D7E90: C248  mov.l r0,@(288,gbr)
```

Read as 32-bit floats instead — which is what they are:

```
C3160000  C2FA0000  C2C80000  C2960000  C2480000
  -150.0    -125.0    -100.0     -75.0     -50.0
```

A descending float axis. `rom_region_map.txt` puts the main code region at
`0x000C0C-0x0A0000`; `0x0D7E84` is ~220 KB past its end, and the block is
classified `float_data`. `0xFFFF895C` has exactly **one** real writer,
`05189C: fmov.s fr0,@(r0,r14)`.

### Why this is the same failure class as everything else here

The regular `C2xx 0000` stride of a float table decodes as a regular stride of
`mov.l r0,@(disp,gbr)`. It does not look like garbage. It looks like a
purpose-built initialiser writing a series of related offsets off one base —
which is exactly the shape a real RAM-structure writer has. Nothing flags it.

### The fix — annotate, never drop

`find_writers.py` now classifies each hit's PC against
`disassembly/maps/rom_region_map.txt` and marks anything outside `code`:

```
FFFF895C  WRITE GBR  0D7E84: mov.l r0,@(1000,gbr)  <-- IN FLOAT_DATA, LIKELY NOT A REAL WRITER
```

Hits are **annotated, never filtered out**. The region map is itself a derived
product and has misclassified real code as `float_data` before (STATUS.md
records 5 such entries corrected), so a silent filter would hide precisely the
computed-addressing writers this tool exists to find. `--code-only` suppresses
them for anyone who wants that after reading them.

### What else needs rechecking

**Any conclusion resting on a `find_writers.py` hit above `0x0A0000` is
suspect** and should be re-run. The tool has been in use since 2026-08-16.
Re-running is cheap; the affected identities are the ones in
`docs/corrections.md` items 62, 64, 66 and open-hole 1.

### Addendum, same day — two more phantoms, and a region-map error the filter exposed

Re-running open-hole 1 through the annotated tool found two more phantom
writers, both verified from bytes:

**`0xFFFF1288`, apparent writer `0x00336E`.** The bytes there are a literal
pool holding the target address itself:

```
00336C: FFFF 12B0    = 0xFFFF12B0
003370: FFFF 1288    = 0xFFFF1288     <-- the address being searched for
```

Read two bytes out of phase, `12B0` decodes as `mov.l r11,@(0,r2)` and `1288`
as `mov.l r8,@(32,r2)`. The scanner found a "write" whose opcode bytes ARE the
pointer it was looking for. `scripts/sh2e_disasm.py` self-flags it — the words
either side print `.word 0xFFFF (INVALID-SH2E)`.

**`0xFFFF7F68`, apparent writer `0x03C61A`.** A pointer table:

```
03C614: 0x000BE8C4     03C618: 0x000AC298     03C61C: 0x000BE88C
```

Three ROM addresses — two in the table-processor library, one in descriptor
space. Decoded as code they yield `rts / mov #-60,r8 / sts mach,r0 /
mov.l r0,@(608,gbr)`.

**Both identities change as a result.** `0xFFFF7F68` does NOT have one writer
in fuelling and one in ignition; the fuelling-side hit was the phantom. Its
only real writer is `0403F8: fmov.s fr0,@r2`, in the ignition region and in the
delay slot of an `rts`. That favours `blend_output` over `ect_blend_correction`
— it does not settle it.

### The region map got one wrong, in the direction that matters

`0x002DB6` is classified `float_data` and is **real code**:

```
002DB0: mov.b @r5,r3 / cmp/ge r3,r14 / bf 0x002DBC
002DB6: mov.b r7,@r5
002DB8: mov.w @(4,r5),r0 / mov.w r0,@(6,r5)
002DBC: mov.l @r15,r3 / ldc r3,sr      <- restores SR, ends a critical section
```

A guarded byte store inside an interrupt-masked section, updating a small
struct at `r5`. This is the 6th such misclassification (STATUS.md records 5
corrected). **It is the exact reason the filter annotates instead of dropping:**
`--code-only` would have hidden the only real writer of `0xFFFF1288`.

A parser bug found in the same pass: `rom_region_map.txt` carries a coarse
hand-written summary whose ranges overlap the 256-byte blocks
(`0x000C0C-0x0A0000 652276 bytes Main code region`). Matching those lines
shadowed the fine-grained classification and reported the type as `Main`. The
loader now accepts only the block types `code / float_data / mixed_data /
uint8_data / rom_hole`, and parses 522 blocks.

---

## 74. `task37_timing_multiaxis` identified — a ONE-SHOT timing retard feeding the knock workspace, with three neutered gates — **NEW, 2026-08-18**

Found while sweeping descriptors that no definition XML covers (the "option B"
sweep). `task37_timing_multiaxis` at `0x000419BA` had **19 descriptors and zero
definitions**. It is a dispatcher:

```c
void task37_timing_multiaxis(void) {
    FUN_00041a02(); FUN_00041a48(); FUN_00041a7e(); FUN_00041be4();
}
```

`FUN_00041be4` is the one that matters. Decompiled in Ghidra (SH-2A re-import,
2026-08-18) with every literal resolved against ROM bytes.

### The mechanism

```
GBR = 0xFFFF8020  (knock / FLKC workspace)

inputs   fr12 = engine_speed_delta [0xFFFF6634]   fr13 = ect_current [0xFFFF6350]
         fr15 = rpm_current [0xFFFF6624]          fr14 = [0xFFFF7C78]   (unlabelled)
         r13  = byte [0xFFFF5E94]                 r11  = byte [0xFFFF7C9A] (unlabelled)
         r14  = flag_6254 [0xFFFF6254]            r12  = [0xFFFF65C0]
         jsr  0x00022CF4 = check_engine_running

trigger  [0xFFFF8034] == 4  AND  [0xFFFF7C78] > rpm_current
         -> 8032 = 0, 8033 = 1
         8034 latches the PREVIOUS pass's value of 0xFFFF7C9A, so this is
         EDGE detection: it fires on the pass AFTER 7C9A becomes 4.
         8036 likewise latches the previous [0xFFFF65C0].

apply    8033 != 0  ->  [0xFFFF8020] = table_lookup_1D(desc @0x0ADE08)
                        ECT axis, uint8, 16 cells:
                        [0, 0, 0, 0, 0, -8.09, -11.95, -16.17, ...]

recover  8033 == 0  ->  [0xFFFF8020] = float_min([0xFFFF8020] + 0.7, 0.0)
                        +0.7 deg per call, clamped at 0 -- never advances

abort    (!running && [0xFFFF5E94] < 4) || flag_6254 == 0
         || engine_speed_delta < -20.0 || rpm_current < 0.0
         ->  [0xFFFF8020] = 0, both counters = 0

output   [0xFFFF8028] = float_min([0xFFFF8020], [0xFFFF8024])
```

### Why this is worth knowing

**It is a retard source of up to -16.17 deg that is neither FBKC nor FLKC**, and
it writes into the knock GBR workspace. If it fires it moves total timing while
appearing in no knock channel. Anything reading a log and attributing all
retard to the knock channels would misread it.

The `float_min([8020], [8024])` output also shows this is one of SEVERAL such
channels arbitrated most-retard-wins. `FUN_00041be4` touches **only** `0x0ADE08`;
the `-24.96/-15.12` and `-20.04` tables in the same descriptor array belong to
sibling paths (`task33_timing_ws_init`, `task36_timing_percond`,
`task41_ign_calc_b`), not to this one.

### Three parts of it are neutered

| element | address | value | effect |
|---|---|---|---|
| RPM abort threshold | `0x0D2C0C` | `0.0` | `rpm_current < 0.0` can never be true. Gate is dead. |
| recovery multiplier | in-path | `* 1.0` | exact no-op on the `(8036==0 && [65C0]==1)` branch |
| apply-window reload | `0x0D2980/81` | `8032=0, 8033=1` | the ECT table applies for exactly ONE call |

Same shape as item 72 and the per-gear timing comp: live code, zeroed
calibration. The only live gate is `engine_speed_delta < -20.0` at `0x0D2C08`,
which abandons the retard during a hard speed drop.

**None of `0x0D2C08`, `0x0D2C0C`, `0x0D2980`, `0x0D2981`, `0x0D2982` has an XML
definition** (`defs.covering()` returns NONE for all five).

### Descriptor array layout

The 17 records from `0x0ADE08` are contiguous at the 1-D record stride of
`0x14`: `ADE08, ADE1C, ADE30, ADE44 ... ADF48`. Only `0x0ADE08` is loaded by
literal anywhere in `0x419BA-0x41D40`; `0x0AE170`/`0x0AE17C` (both all-zero) are
used by `FUN_00041a7e`. Contiguity makes an indexed array plausible but the code
does NOT demonstrate indexing -- at `0x41C9E` the base is passed straight to
`table_desc_1d_float` as a plain single lookup. **Do not assume the other 16 are
selected by index from here.**

### Open

`0xFFFF7C9A` (the trigger byte -- what makes it 4?) and `0xFFFF7C78` (the RPM
threshold it is compared against) are both unlabelled and unidentified. Until
they are known, **whether this path ever fires on this calibration is unknown.**
Do not assume it does; do not assume it does not.

---

## 75. Correctness-debt audit: NO phantom writers in the corpus — but three more region-map errors — **2026-08-18**

Item 73 warned that any conclusion resting on a `find_writers.py` hit above
`0x0A0000` was suspect, and named items 62, 64 and 66. Rather than re-run the
tool item by item, every writer PC **already cited in prose** was screened
against `rom_region_map.txt`.

Result: **no citation in `docs/corrections.md` is a phantom.** Items 62, 64 and
66 stand exactly as written.

Only two citations landed in a block classified `float_data` — the strong
signal. Both verified from bytes and both are real code:

```
item 33   0273E0: F89D  fldi1 fr8
          0273E2: D23F  mov.l @(0x0274E0),r2
          0273E4: 000B  rts
          0273E6: F28A  fmov.s fr8,@r2        <- delay slot, tail-store of 1.0

item 66   03C75A: E001  mov #1,r0
          03C75C: C007  mov.b r0,@(7,gbr)     <- the cited write
          03C764: 4F17  ldc.l @r15+,gbr       <- function epilogue
          03C766: 4F26  lds.l @r15+,pr
```

The remaining flagged citations are all `region=unmapped`, which means only that
no 256-byte block claims the address. Today established that is **not** evidence
of data: `0x002DB6` is `float_data` and real, `0x0403F8` is `unmapped` and real.
Treat `unmapped` as no information.

### What the audit actually found

**`rom_region_map.txt` misclassifies real code as `float_data` in at least
three more places:** `0x002DB6` (item 73), `0x0273E6`, `0x03C75C`. STATUS.md
records 5 previously corrected. That is 8 known, which is enough to say the map
should be regenerated rather than patched — and enough to justify why
`find_writers.py` annotates instead of filtering.

The debt was in the map, not in the conclusions.

---

## 76. `0xFFFF64F5` is a DEBOUNCED CLOSED-PEDAL flag — both competing labels were wrong — **CLOSES 1 OF 7 IN OPEN-HOLE 1, 2026-08-18**

Open-hole 1 listed `0xFFFF64F5` as `boost_related_flag` (boost_control) vs
`engine_state_byte` (ignition_timing). Neither is right.

`find_writers.py` gave four byte writes, three of them in one function with GBR
based on `0xFFFF64D8` (accelerator pedal). Decompiling `FUN_000218F6`:

```c
if (0.0009999999 <= accel_pedal_angle) {
    if (0.25199997 <= accel_pedal_angle)  [FFFF653B] = 0;   // released -> pressed
} else {
    [FFFF653B] = 1;                                          // pressed  -> released
}
uVar3 = 0;
if ([FFFF653B] == 1) uVar3 = uint16_add_sat([FFFF64F0], 1);
[FFFF64F0] = uVar3;

if (adc_channel_status == 1)      [FFFF64F5] = fuel_system_state;
else if ([FFFF653B] == 1)       { [FFFF64F5] = (2 < uVar3); mode = 1; }
else                            { [FFFF64F5] = 0;           mode = 0; }
[FFFF64F6] = mode;
```

So the chain is:

| address | what it is |
|---|---|
| `0xFFFF653B` | raw pedal-released flag, **hysteretic**: set below `0.001`, cleared at/above `0.252` |
| `0xFFFF64F0` | uint16 saturating counter, incremented while released, zeroed when pressed |
| `0xFFFF64F5` | **`counter > 2`** — pedal released and *debounced* for 3 consecutive passes |
| `0xFFFF64F6` | latched mode byte accompanying it |

`0xFFFF64F5` is a debounced closed-pedal condition. It is not boost-related and
it is not an engine state code.

### The overload worth knowing

When `adc_channel_status == 1`, `0xFFFF64F5` is **not** the debounced flag at
all — it is assigned `fuel_system_state` verbatim. The slot carries two
different quantities depending on ADC status. That is very likely how both
original names arose: one camp read it in one mode, the other in the other.
Same shape as `0xFFFF7D18` (item 66), where both names were right from opposite
ends — except here neither name was right in either mode.

### Status

The hysteresis band (`0.001` / `0.252`) and the debounce depth (`> 2`) are
**inline constants**, not calibrations, and carry no XML definition. They cannot
be tuned without a code patch.

---

## 77. `coverage_map.py` could not see the SECOND calibration band — 38 descriptors, including the whole DBW region — **FIXED 2026-08-18**

Chasing an apparent census mismatch (`coverage_map.py` reported 780 descriptors,
`descriptor_map.txt` reports 1094). **The 780 was not a stale scanner** — item 60
already records that coverage_map applies a deliberately stricter acceptance rule
(exact contiguous layout) and that ~276 shared-axis descriptors are its
documented blind spot. Loosening it would have destroyed the corroboration the
cross-check exists to provide.

But item 60 also predicted **818** rows would pass strict contiguity, against the
780 coverage_map accepted. That 38-row gap was real, and it had exactly one
cause.

### One cause, no residue

Of the 585 1-D rows in `descriptor_map.txt` that satisfy `axis + count*4 ==
data`, coverage_map rejected 22 — every one of them because the **axis pointer
fell outside `CAL_LO..CAL_HI = 0x0C0000..0x0E0000`**. `585 - 22 = 563`, which is
exactly what it accepted. Nothing unexplained.

They point into `0x0F89xx`:

```
0x0AB0A4  axis=0x0F8930  data=0x0F8938
0x0F8930: 459ED000 45AFF800 801A0000  =  5082.0, 5631.0, -0.0
```

Clean RPM breakpoints, and **byte-identical in stock `ae5l600l.bin`** — factory
tables, not patch additions.

### There are TWO calibration bands, not one

`rom_region_map.txt` has said so all along:

```
0x0DAF00-0x0F8900   121344 bytes  rom_hole
0x0F8900-0x0F9700     3584 bytes  float_data
0x0F9700-0x0F9900      512 bytes  mixed_data
0x0F9900-0x0FA500     3072 bytes  float_data
```

A second calibration region sits **above the big ROM hole**, and 38 descriptors
point their axis or data into it. It contains the DBW pedal->throttle tables the
project actively works on: `0x0F8B54` base RPM, `0x0F9004`/`0x0F9284`/`0x0F9504`
throttle-by-ratio, `0x0F99E0` pedal map.

A single window assumed one contiguous band and silently excluded the lot. This
is the same blind spot CLAUDE.md already warns about for rev diffs -- *"do not
filter to code-classified regions only; injected code lives in rom_hole space by
definition"* -- reappearing in a different filter.

### Fix

`CAL_LO/CAL_HI` replaced by `CAL_BANDS` plus an `_in_cal()` helper, applied at
all five acceptance tests:

```python
CAL_BANDS = ((0x0C0000, 0x0E0000), (0x0F8900, 0x0FA600))
```

The acceptance RULE is unchanged -- still exact contiguity, still ~40 bits of
coincidence, still high-precision-not-high-recall. Only the address window moved.

### Result, and why it is trustworthy

```
780 descriptors (563 1D, 217 2D)  ->  818 (584 1D, 234 2D)
```

**818 is exactly the number item 60 predicted** from a completely separate
implementation. Two scanners that do not read each other now agree.

| flag | before | after |
|---|---|---|
| entities | 4,691 | 4,720 |
| VERIFIED-BOTH | 336 | **360** |
| VERIFIED-BYTES | 290 | **266** |
| DISASM-ONLY | 927 | 956 |
| CONFLICT | 2 | 2 |
| UNMAPPED bytes | 79.9% | 79.4% |

The 24 that moved VERIFIED-BYTES -> VERIFIED-BOTH are definitions that always
had correct bytes but no independent corroboration, because the descriptor that
corroborates them lives in the band coverage_map could not see. Per the flag
table those go from *"contents only, never meaning"* to *"reason from it,
including about identity"* -- and they are concentrated in the DBW region.

---

## 78. The last 2 of 765 impossible instructions: a literal pool and 4 bytes of alignment padding — **DIAGNOSED 2026-08-18**

`ClearImpossibleSH2E.java` cleared 763 of 765 in bulk and correctly refused the
last two, flagging both `REVIEW` at 510 and 154 bytes per hit against 5-9 for
every data run. Both needed a human decision, and both turned out to be a
different problem from the other 763.

Both are the word `0x0000`, which matches the `MOVI20` encoding
`0000nnnniiii0000`. Neither is a calibration block.

### `0x04BBE4-0x04BBFB` — a literal pool, 24 bytes

Sits after `04BBE0: rts / 04BBE2: mov #60,r5` (delay slot), with real code
resuming at `04BBFC: mov #0,r0`. Every word resolves to a named entity:

```
04BBE4: 0xFFFF8366  fuel_pump_workspace
04BBE8: 0x0000317C  irq_level_set
04BBEC: 0x00003190  irq_level_restore
04BBF0: 0x41000000  float 8.0
04BBF4: 0x000D6018  cal_FuelPump_RunTimeGateA
04BBF8: 0x000D601A  cal_FuelPump_RunTimeGateB
```

Six words, all meaningful, for the surrounding fuel-pump control code. **The
"impossible instruction" at `0x04BBF2` is the low half of the float 8.0.**
The enclosing function's body over-extends past its own `rts`.

### `0x0BF600-0x0BF603` — alignment padding, 4 bytes

`0x0BEDB8-0x0BF600` is an all-`0xFF` ROM hole. Then two `0x0000` words, then a
genuine prologue:

```
0BF5F0..0BF600: ffffffffffffffffffffffffffffffff
0BF600: 0000 / 0BF602: 0000
0BF604: D225  mov.l @(0x0BF69C),r2
0BF606: F828  fmov.s @r2,fr8
```

**The function starts at `0x0BF604`, not `0x0BF600`.** This is a wrong function
boundary, not a data region.

### Fix, in Ghidra

* `0x04BBE4-0x04BBFB`: clear (`C`), define as 6 dwords (`T`). The function
  should end after the delay slot at `0x04BBE3`.
* `0x0BF600`: delete the function, clear the 4 bytes, create the function at
  `0x0BF604` (`F`).

### Worth keeping

`0x0000` padding and `0x0000`-containing constants decode as `MOVI20` under
`SuperH:BE:32:SH-2A`. Any future impossible-instruction hit that is a lone
`0x0000` is padding or a constant's low half, **not** a calibration block --
the bytes-per-hit ratio separates the two cleanly, and did here.

---

## 79. `task37`'s trigger is the DECEL FUEL-CUT dwell tier, and its sibling channel is inert — **EXTENDS ITEM 74, 2026-08-18**

Item 74 left two things open: what the `0xFFFF7C9A` tiers mean, and what drives
the `gbr_kflk_8024` channel that `0xFFFF8028 = float_min(8020, 8024)` arbitrates
against. Both are now settled from ROM bytes.

### The tier state belongs to the decel fuel-cut classifier

The five writes to `0xFFFF7C9A` (`0x03AF04/20/3A/4C/5E`) sit in the function
starting at `0x03AE6C`, GBR `0xFFFF7C92` (`gbr_tim_7C92`). **The same function**
holds the RPM ladder at `0x03AFF6`, whose thresholds resolve to:

```
03B074 -> 0x000CC4EC   Overrun_FuelCut_RPMThreshold   = 2250.0
03B078 -> 0x000CC4F0                                  = 3000.0
```

That is exactly the 3-tier decel fuel-cut classifier already recorded at code
`0x3AFF6`, at the 20.x value of 2250. So `0xFFFF7C9A` is a state code inside the
**decel fuel-cut / overrun** subsystem, not an unrelated classifier.

### What the tiers are: a DWELL ladder

The `0x03AF04` ladder compares `@(24,gbr)` = `0xFFFF7CAA` against three uint16
thresholds at `0xFFFF7C92/94/96`. `0xFFFF7CAA` is a **saturating uint16
counter**:

```
03B5E4: mov.w @(62,gbr),r0     read  [0xFFFF7CAA]
03B5E8: jsr @r2                saturating add, r5 = 1
03B5EC: mov.w r0,@(62,gbr)     write back        <- INCREMENT while condition holds
03B5FC: mov.w r0,@(62,gbr)     r0 = 0            <- RESET on exit path A
03B610: mov.w r0,@(62,gbr)     r0 = 0            <- RESET on exit path B
03B614: ldc.l @r15+,gbr                             function epilogue
```

So tiers **0-3 are DWELL**: how long the overrun condition has persisted, banded
by three duration thresholds. **Tier 4 is NOT on that ladder** — it is a separate
branch at `0x03AF4A` that also sets four companion flags at once, i.e. an
immediate/exceptional entry rather than an accumulated one.

**`timing_oneshot_retard` fires on the edge into tier 4**, so it is armed by the
exceptional overrun entry, not by dwell.

### The sibling channel is dead

`gbr_kflk_8024` is written only by `FUN_00041a7e` — **task37's own stage 3**, not
an independent subsystem. Stage 3 is a mode switch:

```
mode 1   8024 = float_min(8024 + table_lookup_1D(0x0AE17C), 0.0)
mode 2   8024 = float_min(8024 + table_lookup_1D(0x0AE170), 0.0)
mode 3   8024 = *[0x0D2C28]
else     8024 = 0.0
```

Every source is zero on this calibration:

| source | value |
|---|---|
| `desc 0x0AE17C` | 6 cells, all `0.00` |
| `desc 0x0AE170` | 6 cells, all `0.00` |
| `0x0D2C28` | `0.0` |

Modes 1 and 2 accumulate zero and clamp at zero; mode 3 and the default write
zero outright. **`gbr_kflk_8024` is identically `0.0`.**

Since `0xFFFF8020` is itself always `<= 0` (it is retard, clamped by
`float_min(x, 0.0)`), `float_min(8020, 0.0) == 8020`. **The arbitration is a
no-op: `0xFFFF8028` equals `0xFFFF8020` exactly.**

### Net effect on item 74

`task37` has exactly ONE live retard path: stage 4's ECT table `0x0ADE08`,
applied for one call on entry to overrun tier 4, recovering at `+0.7 deg`/call.
Stage 3 contributes nothing. That also accounts for the `-24.96/-15.12` and
`-20.04` tables in the descriptor array: they are NOT reached by stage 3 either,
so they belong to `task33`/`task36`/`task41` or to nothing at all. **Still
unattributed.**

### Addendum, same day — tier 4 is REACHABLE, and not calibration-gated

Three branches reach the tier-4 entry at `0x03AF4A`, all from one chain:

```
03AED2: cmp/gt r4,r6      r4 = [0x0CBC90] uint16 = 625      require r6 > 625
03AED4: bf 0x03AEF2                                          else -> dwell ladder
03AED8: cmp/eq #1,r0      r0 = byte [0xFFFF65D0]             require == 1
03AEE0: cmp/ge r5,r6                                         require r6 >= r5
03AEE6: tst r13,r13       r13 = [0xFFFF8E46] fuel_mode_flags
03AEE8: bt 0x03AF4A                                          -> TIER 4 if flags == 0
03AEEC: mov.w @r6,r2      r2 = [0x0CBC92] uint16 = 0
03AEEE: tst r2,r2
03AEF0: bt 0x03AF4A                                          -> TIER 4, ALWAYS
```

**`0x0CBC92` is `0` in both stock and 20.19d**, so `tst r2,r2` sets T and the
second branch is taken unconditionally once control reaches `0x03AEEA`. Tier 4
is therefore **not** disabled by calibration, and `timing_oneshot_retard` is a
live path rather than dead code.

Neither `0x0CBC90` nor `0x0CBC92` has an XML definition, and `0xFFFF65D0` is
unlabelled.

**Not established:** what `r6` and `r5` actually are at `0x03AED2`. `r6` comes
from `extu.w r0,r6` at `0x03AECA` off a value spilled at `0x03AEC8`, which was
not traced further back. So the gate STRUCTURE is settled and reachability is
settled, but the operating condition -- when in real driving this fires -- is
NOT. Do not claim it fires during any particular manoeuvre without tracing `r6`.

---

## 80. Open-hole 1: five more RAM conflicts adjudicated from writers — two names right, two pairs BOTH wrong — **2026-08-18**

Continues item 76. Each address had exactly one verified real writer; each writer
was decoded and its literals resolved.

### `0xFFFF7F68` — ECT warm-up blend. `ect_blend_correction` is right.

Writer `0x0403F8`, in the delay slot of an `rts`. The function is a 2x2 selector:

```
0403C6  fr4  = *[0xFFFF6350]          ect_current
0403CA  r6   =  [0xFFFF90BE]          flag A
0403CE  r5   =  [0xFFFF6254]          flag B  (flag_6254)
        r4 = one of four descriptors by (A,B):
             0x0ADBC4 mode00   0x0ADBD8 mode01
             0x0ADBEC mode10   0x0ADC00 mode11
0403EC  jsr 0x0BE830 = table_lookup_1D
0403F8  fmov.s fr0,@r2               -> 0xFFFF7F68
```

All four descriptors are named `desc_ect_warmup_1D_mode**`, 16 cells, live
(`8.09, 8.09, 8.09, 8.09, 7.03, ...`). The input is `ect_current`, which is
`VERIFIED-BOTH`. So this is an ECT warm-up correction blended across four modes.
`ect_blend_correction` names the identity; `blend_output` names the same thing
from the consumer side. **Not a conflict -- identity vs use, like `0xFFFF7D18`.**

### `0xFFFF1288` — `rtos_scheduler_state`. `inj_gate_hook_ptr` is WRONG.

Writer `0x002DB6`, inside an SR-masked critical section:

```
002DA4  r3 = 0xFFFF1230 (SH7058_TIER_MTU0) + index*2 ; store [r5+4]
002DB0  r3 = byte [r5]                     r5 = 0xFFFF1288
002DB2  cmp/ge r3,r14                      raise-to-higher-priority test
002DB6  mov.b r7,@r5
002DBA  [r5+6] = [r5+4]                    save previous
002DBE  ldc r3,sr                          end critical section
```

A byte priority compared and conditionally raised, a previous-value save, and an
`SH7058_TIER_MTU0` timer array indexed alongside -- all under interrupt mask, in
the RTOS region. The long written to `[r5+8]` (`0x1000` at `0x002D20`) is the
pointer-shaped field that probably produced the `inj_gate_hook_ptr` name. The
address already carried `rtos_scheduler_state` in the Java; the code confirms it.

### `0xFFFF8258` — a knock-workspace product INTEGRATOR. `knock_metric` in kind.

Writer `0x0459E4` (base `0xFFFF826C`, `r0 = -20`):

```
0459C0  fr9 = fr8                                     previous value
        fr8 = [0xFFFF8214] * [0xFFFF8204]
                           * [0xFFFF821C] knock_thresh_calc
                           * [0xFFFF8218] knock_det_workspace_ext
0459E0  fmac fr0,fr8,fr9    fr9 += [0xFFFF826C] * product
0459E4  fmov.s fr9,@(r0,r5)                           -> 0xFFFF8258
```

An accumulator over a product of four knock-detector workspace terms, with a
gain. That is a metric being integrated, not a timing quantity. `knock_metric`
describes what it IS. **`flkc_retard` is not supported here** -- nothing in this
function produces degrees. Whether the accumulated value is later converted to
retard is NOT established.

### `0xFFFF8F24` — a debounced status flag. BOTH names unsupported.

Writer `0x05E9C6` (`mov.b r0,@(8,r1)`, `r1 = 0xFFFF8F1C`):

```
05E9AC  r0 = byte [0xFFFF8F12]
05E9B0  cmp/eq #90,r0    ->  [0xFFFF8F24] = 1
        else  r2 = byte [0xFFFF8F1C]
05E9C0  cmp/hs #6,r2     ->  [0xFFFF8F24] = 0
        else             ->  uint8_add_sat path (increment the counter)
05E9CC  [0xFFFF8F1C] = 0                    reset on either decision
```

`0xFFFF8F24` is set when a status byte equals **90**, cleared after **6**
consecutive non-90 samples, with `0xFFFF8F1C` as the debounce counter. Same shape
as `0xFFFF64F5` (item 76). **Neither `blend_state_b` nor `global_cl_enable` is
supported by the code.** `0xFFFF8F12` is unlabelled and unidentified, so what
"status 90" means is open.

### `0xFFFF895C` — a clamped difference. BOTH names unsupported.

Writer `0x05189C` (base `0xFFFF8964`, `r0 = -8`):

```
051878  fr0 = fr0 - [r14-48] - [r14-28]  ; fr14 = fr0
05188E  jsr float_min(fr4, *[0x0D6280] = 1000.0)
051896  jsr float_max(fr14, that)
05189C  -> 0xFFFF895C , and the same value to 0xFFFF8964
```

A difference of two subtractions, floored by `max` against a value ceilinged at
**1000.0**. **Neither `injector_data` nor `afl_value` is supported.** `afl_value`
is additionally doubtful because item 70 established the logged AFL channel is
`0xFFFF7878`.

### Status of open-hole 1

Six of seven addressed (item 76 plus these five). Only `0xFFFF3234` remains, and
it has **no writer even on a 96-byte window scan** -- it needs a method that does
not start from writes.

Two of the five ended with **both** competing names wrong, matching `0xFFFF6254`
and `0xFFFF64F5`. Per the standing rule, no replacement name is invented for
those beyond what the code establishes: a debounced flag, and a clamped
difference.

---

## 81. `0xFFFF3234` is the IAM — settled from the DEFINITION XML — **CLOSES OPEN-HOLE 1, 2026-08-18**

The last of the seven. `find_writers.py` found nothing at this address, nor
anywhere in a 96-byte window, so the base is computed and no writer-based method
could reach it. It was settled from the read side instead.

### The neighbourhood already said knock-learning

`0xFFFF3234` appears as a literal-pool word at **14 sites**, and its neighbours
are all named:

```
0xFFFF322C  FLKC_slow_learning_value   (-8)
0xFFFF3234  ram_IAM                    ( 0)   <- 14 pool sites
0xFFFF323C  FLKC_BASE_STEP             (+8)
0xFFFF3244  flkc_fg_R0_init           (+16)
0xFFFF3248  flkc_grid                 (+20)
```

It is read as a **float** (`fmov.s @r2,fr8`), at `0x042F50`, immediately beside
`FLKC_slow_learning_value` at `0x042F54`.

### The proof is in the definition XML, not the labels

At `0x042F70` the same function gates on it:

```
042F4C  r2 = [0x043070] = 0xFFFF6364   fr4 = *r2     IAT
042F50  r2 = [0x043074] = 0xFFFF3234   fr8 = *r2     <- the address in question
042F70  r2 = [0x04308C] = 0x000D2CF4   fr6 = *r2     a CALIBRATION
042F74  fcmp/gt fr8,fr6
042F76  bt 0x043014                                   bail if cal > [0xFFFF3234]
```

`0x000D2CF4` is a **defined table** in the project XML:

* name **`Timing Compensation B (IAT) IAM Activation`**
* category `Ignition Timing - Compensation`
* scaling **`IgnitionAdvanceMultiplier(IAM)`**, units "Ignition Advance
  Multiplier (IAM)", min `-1.0`, max `1.0`
* value **0.6000** in both stock and 20.19d
* description: *"When the ignition advance multiplier (IAM) is greater than this
  threshold, the 'Timing Compensation B (IAT)' will potentially be active ...
  When the IAM is less than or equal to this threshold, this timing compensation
  will be set to zero."*

The definition says the threshold is compared against IAM. The ROM code compares
it against `0xFFFF3234`, in a function that also loads IAT. **`0xFFFF3234` is
the IAM.** This is the definition-XML method CLAUDE.md recommends -- calibration
name to RAM variable, mechanically -- and it is `VERIFIED-BOTH` class evidence:
definition side and code side, independently.

### Adjudication

| claim | verdict |
|---|---|
| `flkc_work_bank1` (knock_flkc) | **WRONG.** FLKC's own values are the neighbours at `322C`/`323C`/`3244`/`3248`. This is not FLKC workspace. |
| `knock_learn_coarse` (ignition_timing) | **RIGHT in substance.** IAM is exactly the coarse global knock-learning term, as distinct from FLKC's fine per-cell learning. |
| `ram_IAM` (already in `ImportAE5L600L.java`) | **CORRECT**, and now verified rather than asserted. |

### Still open about it

**The writer is still unfound.** IAM is learned, so something must write it, but
it is not reachable by any of the four addressing forms `find_writers.py`
handles. That is a limitation of the tool, not evidence the value is constant.

### Open-hole 1 is CLOSED

All seven addresses adjudicated (items 76, 80, 81). Final tally: **two names
right, one right in substance, and four of seven where BOTH competing labels
were wrong** (`0xFFFF6254`, `0xFFFF64F5`, `0xFFFF8F24`, `0xFFFF895C`).

That last number is the durable lesson. Where a majority of disputed addresses
have no correct name on either side, agreement between artifacts was never
evidence -- it meant two files had copied one guess.

---

## 82. The knock detection threshold: lookup 2 is a SIGMA MULTIPLIER, and `r9` was never a stack frame — **CLOSES OPEN-HOLE 4, 2026-08-19**

Open-hole 4 asked whether `0xAE6D4`/`6E8`/`6FC`/`710` is "the threshold itself or
a per-cylinder trim on one". It is neither. Full trace with verified
disassembly: `disassembly/analysis/knock_threshold_trace.txt` (195/195 lines
agree against ROM bytes; the code is byte-identical in stock and 20.19c).

### The mistake that kept this open

The old entry read `[r9-40]` as a stack slot and pointed at `0x043888`–`0x0438B0`
as the consumer. Both follow from treating `r9` as a frame pointer. It is not:

```
0437B4: D981  mov.l @(0x0439BC),r9      ; [0439BC] = FFFF8158
043798: 401E  ldc r0,gbr                ; [0439A8] = FFFF80FC
```

`r9` is a **fixed RAM workspace base**, `r14` is the same value, and
`mov.b @(176,gbr),r0` is the cylinder index at `0xFFFF81AC`. Once that is fixed,
every slot is a real address and the consumer is findable mechanically.

Lookup 2 stores to `[r9-44]` = **`0xFFFF812C`** (`04385E: F907`), lookup 3 to
`[r9-40]` = `0xFFFF8130` (`043874: F907`). `[r9-44]` is read exactly twice, at
`0x043ABE` and `0x043AEA` — 560 bytes past where the entry said to look.

### What it actually computes

```
043AB8: E0F0  mov #-16,r0
043ABA: F896  fmov.s @(r0,r9),fr8       ; baseline   [r9-16] = FFFF8148
043ABC: E0D4  mov #-44,r0
043ABE: F096  fmov.s @(r0,r9),fr0       ; K          [r9-44] = FFFF812C
043AC0: E0F8  mov #-8,r0
043AC2: F996  fmov.s @(r0,r9),fr9       ; deviation  [r9-8]  = FFFF8150
043AC4: F89E  fmac fr0,fr9,fr8          ; baseline + K*deviation
```

then clamped to `[float 0x0D2D88 = 50.0, float 0x0D2D8C = 359.0]` and stored to
`[r9-4]` = `0xFFFF8154`. A second copy at `0x043AE0`–`0x043B08` multiplies
lookup 3 in and clamps to `[50.0, float 0x0D2D90 = 1000.0]`, stored to `[r9+0]`
= `0xFFFF8158`.

So **K is dimensionless** — it multiplies a deviation. The old "units are
knock-signal units (the same 0–3.5 domain as `0xAE284`'s axis)" is wrong; the
3.45–3.60 resemblance to that axis is coincidence. The signal domain is the
50–359 one the clamps sit in.

`0x043888`–`0x0438B0`, which the entry named as the consumer, is the **deviation
estimator**: `[r9-20] = min(1.0, min(abs(signal - baseline) * [r9-92],
abs([r9-24])))`. That value then drives the baseline tracking at
`0x0438C0`–`0x0438FC`, which is what establishes `[r9-16]` as a tracked mean.

### The decision, and a delay-slot trap

```
043B3C: F895  fcmp/gt fr9,fr8           ; T if threshold_A > signal
043B3E: 890D  bt 0x043B5C               ; -> no knock
043B48: 3253  cmp/ge r5,r2              ; word[FFFF67EC] >= word[0x0D29DC] (250)
043B4A: 8B07  bf 0x043B5C               ; -> no knock
043B52: F895  fcmp/gt fr9,fr8           ; T if threshold_B > signal
043B54: 8D03  bt/s 0x043B5E
043B56: E001    mov #1,r0               ; DELAY SLOT - runs on BOTH paths
043B58: A003  bra 0x043B62
043B5A: C0BE    mov.b r0,@(190,gbr)     ; DELAY SLOT - stores 1
043B5C: E000  mov #0,r0
043B5E: C0BE  mov.b r0,@(190,gbr)
043B60: E000  mov #0,r0
043B62: C0BF  mov.b r0,@(191,gbr)
```

Both arms of the `bt/s` write **1** to `GBR+190` = `0xFFFF81BA` = `KNOCK_FLAG`.
The comparison only selects whether `GBR+191` = `0xFFFF81BB` gets 0 or 1.
Reading that `fcmp` as gating `KNOCK_FLAG` would be wrong.

⇒ **`0xFFFF81BB`'s existing label `KNOCK_BANK_FLAG` is unsupported.** This
function is per-cylinder (index from `0xFFFF4308`, gated `< 4`), not per-bank,
and `81BB` is set by an *upper-threshold* comparison. Recorded, not renamed.

### Calibration inventory — all of it invisible to ECUFlash

`0xAE6D4/6E8/6FC/710`, `0xAE724/738/74C/760`, `0xAE284`, `0xAE290`,
`0xAE29C/2A8/2B4/2C0`, `0x0D2D84` (8.0), `0x0D2D88` (50.0), `0x0D2D8C` (359.0),
`0x0D2D90` (1000.0), `0x0D2D94` (2.0), `0x0D29DC` (uint16 250), `0x0D298B`
(byte 255). Checked 2026-08-19: **zero** of these carry an `address=` entry in
`definitions/AE5L600L 2013 USDM Impreza WRX MT.xml`.

### Consequence for the load-plane lever

The two 18-value load planes of lookup 2 are byte-identical (re-confirmed via
`desc_types.read_table` on `0xAE6D4` and `0xAE6E8`), so the load axis is exactly
flat and "knock detection has no load input" is right about the effect. Because
K is a sigma multiplier, differentiating the planes is a well-defined lever:
**lower K = more sensitive detection**, higher K = less. Breakpoints 0.80 and
2.20 g/rev, RPM 800–7600 in 400 steps.

### Status

Recorded and verified. No ROM bytes changed, no XML edited.

---

## 83. `0xFFFF77D8` has NO writer, and the branch it feeds is a +3%-capped fuel trim — **CLOSES OPEN-HOLE 3, 2026-08-19**

Settled statically, without the drive that option 1 of the hole called for. Full
trace: `disassembly/analysis/ffff77d8_trace.txt` (88/88 instruction lines verify).

### The writer question is answered: there isn't one

Four independent methods, all negative:

1. `find_writers.py FFFF77D8` → no writes.
2. **Exhaustive literal enumeration.** The value `FFFF77D8` occurs at exactly
   four aligned offsets in the image: `0x032450`, `0x03972C`, `0x07D788` (three
   literal pools) and `0x063A34` (a pointer-table slot). Every PC-relative load
   resolving to the three pools was enumerated — three instructions, **all
   reads** (`0x032260`, `0x03953A`, `0x07D680`).
3. **Store-base back-trace** over `0x000000`–`0x0C0000` for `fmov.s frM,@rN`,
   `fmov.s frM,@-rN`, `mov.l rM,@rN`, resolving the base through literal loads,
   `mov rM,rN`, `mov.l @rM,rN`, `mov.l @(disp,rM),rN` and accumulated
   `add #imm,rN`: **zero** hits.
4. **GBR enumeration.** All 651 `ldc rN,gbr` sites resolved to their bases; the
   three that can reach `0xFFFF77D8` have no matching store inside their live
   range (the apparent hits at `0x067900`+ are data-as-code, item 73's class).
   SH-2E has no GBR-relative float store anyway, and all three reads are
   `fmov.s`.

**The pointer-table slot is unreachable.** `0xFFFF77DC`'s writer works by being
handed `&0x063A44` (literal at `0x03342C`, `bsr 0x033CC0`, deref-and-store). No
literal in the image holds `0x00063A34`, and the two helpers that receive a
neighbouring slot index past it, not onto it:

```
0x033658  r11 = r5 = 0x63A2C ; mov.l @(4,r11),r2   -> 0x63A30 = FFFF77CC
0x033D1C  r13 = r5 = 0x63A2C ; mov.l @(12,r13),r2  -> 0x63A38 = FFFF77E4
```

Each of the six helpers has exactly one caller (every `bsr` displacement in the
image was scanned).

### What the pair actually does

Only `func_3952C` consumes them, and only when `byte[0xFFFF782C] == 0` — on the
non-zero path `fr4`/`fr5` are overwritten at `0x039566`/`0x039574` without use.
The live path calls `0x03961C`:

```
S = 1.0 + [0xFFFF77D8] + [0xFFFF77DC]
if |S| <= 0.0001220703125:  [0xFFFF7BAC] = 0.0
else:                       [0xFFFF7BAC] = clamp(1.0/S - 1.0, 0.0, 0.03)
```

Helpers verified from bytes: `0x0BE608(x,c,eps)` returns 1 when `x` is outside
`c ± eps` (a divide-by-zero guard); `0x0BE628` is division (opens with a
zero-denominator test); `0x0BE56C(x,lo,hi)` is `clamp`. Ceiling is float
`[0x0CC3E8] = 0.03`.

### Numerically

`0xFFFF77DC` comes from the four CL Fueling Target Comp tables, re-read
2026-08-19 with `desc_types.read_table`: 532 cells, all negative,
**−0.14999 … −0.00475**. With `[77D8] = 0`, `S ∈ [0.85001, 0.99525]`, so
`1/S − 1 ∈ [0.00477, 0.17646]` — always positive.

* The `[0xFFFF7BAC] = 0.0` path is **unreachable** for any value these tables
  can produce; it would need the sum near −1.0.
* The trim **saturates at the +3% cap for 56 of 532 cells (10.5%)**. The rest
  give a graded +0.48%…+3%.

### Corrections to the previous open-holes entry

* "suppressed only when `[0xFFFF77D8] >= +0.00475…+0.150`" — **wrong**. The test
  is `|1 + [77D8] + [77DC]| <= 1.22e-4`. Those figures are the *magnitudes of the
  77DC table data*, not a threshold on 77D8.
* "Branch A arms by default" — right conclusion, wrong reason. It arms because
  the guard is a divide-by-zero check that never trips.
* The suggested `map_gbr_structures.py` next move does not apply: the
  `afc_pi_controller_trace.txt:191` "R9+0xB0" reading is corroborated by no store
  this trace can find.

### Status

Recorded and verified. No ROM bytes changed, no XML edited. Open: whether
`0xFFFF77D8` is explicitly zeroed at reset (it lies in `FFFF4000..FFFFBF9F`, the
fourth entry of the RAM region table at `0x011CCC`–`0x011CE8`, whose consumer was
not decoded) or merely never written — either way it is constant per power cycle.

---

## 84. The scheduler DOES have a walker — a 5-slot coalescing event queue that silently drops overflow — **CLOSES OPEN-HOLE 5, 2026-08-19**

Item 63 was right that nothing walks the unrolled call runs. What it left open —
"what calls the enclosing functions" — resolves to a real RTOS post/dispatch
path. Full trace: `disassembly/analysis/scheduler_event_queue_trace.txt`
(162/162 instruction lines verify).

### The chain

```
ISR stub (0x00E970 family, r4 = event id)
  -> 0x00E774     raise SR to IMASK=15 (stc sr / and / or #240 / ldc)
  -> 0x00010800   pack (id, payload), enter critical section
  -> 0x00010B2A   THE WALKER
  -> later, task stubs at 0x00E4xx call 0x04A94C / 0x04AA58 / 0x049A7A /
     0x049BA4 / 0x049CF0 — each a straight-line jsr run
```

### The event table

```
count   byte  @ 0xFFFF2060
entries       @ 0xFFFF2064, STRIDE 12   (add #12,r13/r12/r14 at 0x010BB8-0x010BC2)
  +0  word  event id
  +4  long  payload
  +8  byte  pending counter, saturates at 255 (ceiling 0x00FF @ 0x010B92)
last posted id      -> word @ 0xFFFF20A0
last posted payload -> long @ 0xFFFF20A4
```

Two behaviours worth carrying:

* **Coalescing.** A repeat of a queued id bumps that slot's counter instead of
  taking a second slot. The counter is the multiplicity.
* **Silent drop.** `mov #5,r2 / cmp/ge r2,r9 / bt/s` at `0x010BCC` skips the
  insert when the count has reached **5**. A new event id arriving on a full
  queue is discarded — no error path, no overflow flag, no else branch.

### Two Java labels were wrong

* `0x04A94C` was labelled "calls 59 tasks from task_table @ 0x04AD40". It makes
  exactly **23 `jsr @r2` calls plus one tail `jmp @r2`** between its
  `byte[0xFFFF8EDC]` gate and its `rts` at `0x04A9F0`. First task is
  `0x043750` (knock_wrapper); ninth is `0x033304`.
* `0x04AD40` was labelled `task_table`. It is a **literal pool** — the longs are
  `0x00042A32`, `0x0003EA0C`, `0x0003EA5A`, `0x00044188`, `0x00045970`,
  `0x00045098`, `0x00045670`, the jsr targets of the run that precedes it.
  Exactly the shape item 63 described; the label predates that finding.

Likewise `0x00E5EC`–`0x00E6C0` (54 longs, all ROM code addresses, bounded by
`rts/nop` at `0x00E5E8` and code at `0x00E6C4`) is the **shared literal pool** of
the `0x00E4xx` stub region, not a dispatch table. No literal in the image points
at its base; the individual entries are reached by `mov.l @(disp,pc)` from the
stubs (`0x00E4AE`, `0x00E4C8`, `0x00E52E`, `0x00E542`, `0x00E556`).

### Status

Recorded and verified. No ROM bytes changed, no XML edited. Open: what DRAINS the
table (start from `0xFFFF2060`/`0xFFFF2064`); the guarded-RAM accessor prologue
`jsr 0x0000317C ; r4 = 16` shared by `0x0BDA70`/`0x0BDAAC`/`0x0BDB6E`/`0x0BDB80`;
the full event-id map (80, 84, 90, 92 seen); and the writer of `0xFFFF8EDC`.

---

## 85. Definition fixes applied: both registry CONFLICTs cleared, and the AVCS duty tables re-verified before the X/Y swap — **2026-08-19**

Closes the repo half of open-hole 6 and the outstanding fixes from items 51 and
71. **Registry CONFLICT count went 2 → 0** and VERIFIED-BOTH 360 → 363.

### What changed

| where | table / scaling | change |
|---|---|---|
| project | `c0bcc` Boost disable during fuel cut-Load threshold | scaling `EngineLoad(g/rev)` → **`EngineLoad(g/rev)1`** |
| project | *(new)* `rawecuvalue(uint16)` | added |
| project | `d6214` Idle Airflow … Max Mode Counter | scaling → **`rawecuvalue(uint16)`** |
| project | `cfa38` / `d121c` axis children | renamed `* VVT Error` → **`Mass Airflow`**, reordered |
| base | 8 × `{Intake,Exhaust} Duty Correction A-D` | **X/Y swapped**: `Mass Airflow` X/10/`MassAirflow(g/s)1`, `Engine Speed` Y/9 |

Verified through `scripts/defs.py` after the edit: `c0bcc` now reads **1.70**
(was displaying 1.00), `d6214` reads **18** (was the denormal 1.65e-39), and
`Intake Duty Correction A` resolves as **9 rows × 10 cols**.

`rawecuvalue` could **not** be changed in place — it is `storagetype="float"` and
**50 base tables use it**. Hence the sibling scaling rather than a global edit.

### The X/Y swap was re-derived from bytes, not taken from item 71

Item 71 recorded the swap but explicitly left open "what ECUFlash actually
renders". Rather than apply it blind, the data was read both ways:

```
Intake  cfa38 uint8 x0.2   stride 10 -> 9x10  monotone rows 9/9,  cols 10/10
                           stride  9 -> 10x9  monotone rows 2/10, cols  0/9
Exhaust d121c uint16       stride 10 -> 9x10  monotone rows 9/9,  cols 10/10
                           stride  9 -> 10x9  monotone rows 2/10, cols  0/9
```

Stride 10 is the physical surface in both. The axis at `cf9ec`/`d11d0` is
**4, 6, 10, 15, 20, 25, 30, 40, 60, 80** — a mass-airflow ladder, and the
correction *decreases* along it, which is backwards for a position-error input
and correct for an airflow feed-forward. The 9-element axis is
650…3600 RPM. Geometry also checks arithmetically:
`cf9ec + 10*4 = cfa14`, `cfa14 + 9*4 = cfa38`.

> **Trap avoided.** A first pass read `cfa38` as uint16 and got garbage in both
> orientations. The project XML **overrides** the base `Intake Duty Correction`
> (uint16) with `Intake Duty Correction (uint8)`. Resolve inheritance before
> judging a surface — this is exactly what `scripts/defs.py` exists for.

### NEW, recorded not applied — the Exhaust table's scaling is wrong

`d121c` inherits the base `Intake Duty Correction` = `(x*.003051758)-100`, which
displays **−82.5 … −95.5**. Dropping the `-100` gives **17.5, 15.0, 10.0, 7.5,
6.5, 6.0, 5.5, 5.0, 4.5, 4.5** — the same shape and magnitude as the Intake
table's first row (11.6 … 5.0). The `-100` offset looks spurious.

**Not changed.** It is a data-interpretation change outside the authorised fix
set, and getting it wrong would mislead tuning. Also note **every RPM row of the
exhaust table is byte-identical** — its RPM axis is exactly flat, the same
degenerate shape as the knock load planes in item 82.

### Status

Repo-side applied and verified. `.\scripts\sync_defs.ps1 -Push` **still owed** —
it writes into `Program Files` and needs an elevated shell. Restart ECUFlash
after pushing so it reloads. Files were edited byte-safely; both keep LF endings
(a first text-mode attempt rewrote all 7,709 lines to CRLF and was reverted).

---

## 86. The undefined-ROM programme, slice 1: 786 descriptors have no definition; the 41 RPM x load ones triaged — **NEW, 2026-08-19**

`docs/open-holes.md` was empty after items 1-6 closed. This opens the successor
programme. Full slice: `disassembly/analysis/unnamed_tables_rpm_load.txt`.

### Sizing the gap — and a join that had been done wrong

1,094 table descriptors decode cleanly from ROM bytes. Joining each descriptor's
**data and axis pointers** against every address the definition XMLs claim:

```
descriptor data/axis IS defined in the XML :  308
NO definition anywhere                     :  786   (775 plausible, 11 artefacts)
```

> **The join is on the POINTERS INSIDE the record, not the descriptor address.**
> Definitions point at data (`0xD14D0`), never at descriptor records
> (`0xAD8B8`). Joining on the descriptor's own address returns **zero** matches
> and reads as "nothing is defined anywhere", which is wrong by construction.

Axis breakpoints classify mechanically: **441 of 786 (56%)** get at least one
axis physically identified (RPM ladder, ECT/IAT °C, load g/rev, MAF g/s) from a
crude classifier. This is the "axis names are the most under-used asset" method
in CLAUDE.md, run in reverse.

### Slice 1 — the 41 on RPM x engine load

| finding | count |
|---|---|
| FLAT (every cell identical, inert as shipped) | **14** |
| consumer touches the diagnostic-monitor workspace | 11 |
| consumer touches the OL enrichment workspace | 6 |
| already identified — knock front-end, item 82 | 8 |
| CL Fuelling Target Comp siblings, item 70 | 3 |
| scanner artefact (`0xABC1C`, values to 1.7e22) | 1 |

The eight `0xAE6D4`/`0xAE724`-family rows appearing here is itself a result: the
knock front-end carries **no XML definition at all**, exactly as item 82 found.
`0xAD8D4`/`0xAD90C` likewise confirm item 70's "live siblings missing from the
XML".

### The one cluster worth pursuing

`0xAD960`/`0xAD97C`/`0xAD998`/`0xAD9B4`/`0xAD9D0` all hang off `0x03684A`, whose
GBR is `0xFFFF798C`. Its lookup inputs are read straight from RAM:

```
03685A: D26F  mov.l @(0x036A18),r2   ; FFFF6624  RPM
03685E: D26F  mov.l @(0x036A1C),r2   ; FFFF63F8  ENGINE LOAD
036874: F860  fadd fr6,fr8           ; [FFFF7F48] + [FFFF8258]
036876: F891  fsub fr9,fr8           ;          - [FFFF7E90]  -> FFFF79B4
03688E: 8909  bt 0x0368A4            ; [FFFF798C] == 0 -> 0xAD97C, else 0xAD960
```

The selector is `0x0BE608` — the same outside-a-band helper decoded in item 83 —
with `c = 0.0`, `eps = 3.0517578125e-05`, i.e. "is `[0xFFFF798C]` non-zero".

All five are RPM 800–6400 × load 0.30–2.50 g/rev, properly scaled and populated
(except `0xAD9D0`, flat 0.01). `0xFFFF798C` carries the project label
`ol_enrichment_accum` and `0xFFFF8258` was settled in item 80 as a knock-workspace
integrator — so the cluster is both fuel- and knock-adjacent, which is precisely
why it is **not named here**. `0xFFFF7F48` and `0xFFFF7E90` are unidentified.
**Structure established, meaning not.**

### Cautions carried into the worklist

* "Subsystem" in the slice file is a **hint** from RAM referenced near the call
  site. Several of those RAM labels are themselves project guesses.
* **FLAT ≠ a free lever.** `0xAD258` and `0xD2D48` are both flat and both feed
  multipliers separately clamped to zero. Read the consumer first.
* `0xAD6AC` and `0xAE664` are 18×15 RPM × load surfaces, **entirely zero**, whose
  consumers touch the FLKC workspace (`0xFFFF3234` IAM, `0xFFFF323C`
  FLKC_BASE_STEP). A dormant FLKC feature, worth understanding before anyone
  populates it.

### Status

Recorded. No ROM bytes changed, no XML edited, **no table named**.

---

## 87. Item 86's join was wrong (147/947, not 308/786) — and slice 2: 157 unnamed COOLANT-indexed tables — **CORRECTS ITEM 86, 2026-08-19**

Full slice: `disassembly/analysis/unnamed_tables_coolant_axis.txt` (27/27
instruction lines verify).

### The correction

Item 86 counted a descriptor as "defined" if its **data OR an axis** pointer was
claimed. Sharing an axis with a named table says nothing about whether *that*
table is named. The correct test is the **data pointer alone**:

```
join on data OR axis (item 86, WRONG) :  308 named /  786 unnamed
join on DATA pointer only (correct)   :  147 named /  947 unnamed
```

Slice 1's 41-row RPM × load content is unaffected — every row was unnamed under
either rule — but item 86's framing numbers are superseded. **947, not 786.**

The signal item 86 was throwing away is the useful one: **158 unnamed tables
share an axis array with a named table, 157 of them the "Coolant Temperature"
axis.** That is ground-truth axis identity from the XML, not a breakpoint guess —
and it is a far better slice criterion than the heuristic classifier, which would
have mislabelled the 4–80 g/s mass-airflow ladder as a temperature axis.

### The coolant axis

Four distinct arrays, all holding the **identical** 16-point ladder, −40…+110 °C
in 10° steps (−40…+230 °F): `0xD67C8` (67 users), `0xCC624` (57), `0xCC664` (24),
`0xD2F8C` (9). One ladder, four copies, one per consuming subsystem.

### Result

**157 unnamed coolant-indexed tables. 66 are FLAT** — inert as shipped. That is
42%: most of the coolant-indexed surface in this ROM is switched off.

* `0x50000`–`0x55000` (37 populated) — **OBD diagnostics, not levers.** Call
  sites touch `gbr_sens_8A84`, `gbr_sens_8AC0`, `diag_precondition_flag_65C0`;
  payloads are rationality-shaped (0.96–0.99 ratio bands, a 250–400 band, a
  0–180 ramp).
* `0x2F000`–`0x31000` (25 populated) — the **fuel region**, where the
  tuning-relevant material is.

### The find: eight undefined coolant fractions in the transient fuel path

Two 2×2 families, all 1-D uint16 ×16 on the coolant axis, all fractions just
under unity, **none defined in any XML**:

```
0xAC840  0.8500..0.9400     0xAC818  0.9000..0.9600
0xAC890  0.8750..0.9000     0xAC868  0.9000..0.9600
0xAC854  0.8500..0.9400     0xAC82C  0.9000..0.9600
0xAC8A4  0.8750..0.9000     0xAC87C  0.9000..0.9600
```

```
02F03C: D230  mov.l @(0x02F100),r2   ; FFFF6354  coolant
02F040: D617  mov.l @(0x02F0A0),r6   ; FFFF3158
02F044: D22F  mov.l @(0x02F104),r2   ; FFFF90C1
02F04A: 8B65  bf 0x02F118            ; [FFFF90C1] != 0 -> elsewhere
02F04E: 8F12  bf/s 0x02F076          ; [FFFF3158] != 0 -> second pair
02F050: C465    mov.b @(101,gbr),r0
02F058: 8B06  bf 0x02F068            ; gbr+101 == 1 ? 0xAC840 : 0xAC890
```

then `r14 = 0xFFFF72D0`. The second family at `0x2F126`–`0x2F158` is the same
shape into the same workspace.

**Shape argument only, and it is flagged as such in the slice file.** The region
touches `transient_state_flag` and `FFFF7328`/`732C`/`7330`/`7334`, and
`0x02F550` nearby is the known transient-knock-inhibit writer. A coolant-indexed
fraction slightly under 1.0, selected 2×2, feeding a transient workspace has the
shape of a wall-wetting / X-factor term — which would bear directly on the cusp
tip-in conclusion that the stab-lean is wall-wetting rather than deliverable
fuel. `0xFFFF72D0`, `0xFFFF72C8`, `0xFFFF3158` and `gbr+101` are all
unidentified. **Nothing is named.** Settling it means decoding `0x02F162` onward.

### Also worth a look (populated, fuel region, undefined)

`0xACD7C`/`0xACD90` (1.25–2.20, 0–2.75) and `0xACDA4`/`0xACDB8` sit on
`base_fuel_map_output`. `0xAD7F4`/`0xAD810`/`0xAD82C` span **1.00–12.11** — a 12×
authority for a coolant term.

### Status

Recorded. No ROM bytes changed, no XML edited, no table named.

---

## 88. The eight coolant fractions are a STAGED DECAY BANK — and inert above 40 °C. Retires item 87's wall-wetting hypothesis — **2026-08-19**

Full trace: `disassembly/analysis/coolant_decay_bank_trace.txt` (41/41 lines
verify). Closes open-holes #7 next-move 0.

### What they are

The decay **rate** of a single multiplicative accumulator with four staged
latch-off thresholds, in function `0x02EFD2` (GBR `0xFFFF726C`):

```
charge:  [FFFF728C] = [FFFF72DC];  [FFFF7290/7294/7298/729C] = same
         byte[gbr+3..6] = 1
decay:   [FFFF7274] = f(coolant)
         [FFFF728C] = max( [FFFF728C] * f(coolant), 0.0 )     ; 0x0BE960 = MAX
         [FFFF7290] = max(acc, [FFFF7328])  ; gbr+3 -> 0 when acc < threshold
         [FFFF7294] = max(acc, [FFFF732C])  ; gbr+4 -> 0
         [FFFF7298] = max(acc, [FFFF7330])  ; gbr+5 -> 0
         [FFFF729C] = max(acc, [FFFF7334])  ; gbr+6 -> 0
```

`find_writers.py FFFF728C` returns exactly two writes, both inside this
function. `0x0BE960` re-verified from bytes as MAX.

**GBR+2 is `0xFFFF726E`, the transient knock inhibit flag** (writer `0x02F550`,
already traced). The bank sits two bytes away in the same workspace.

### Why item 87's hypothesis is wrong

```
degC     -40    -30    -20    -10      0     10     20     30     40 .. 110
AC840   0.940  0.940  0.920  0.920  0.850  0.850  0.875  0.875  0.900 (flat)
AC818   0.960  0.960  0.940  0.940  0.900  0.900  0.900  0.900  0.900 (flat)
```

* **Above 40 °C all eight curves are a constant 0.900.** Normal coolant is
  80–100 °C. In the entire regime the car runs in, the coolant axis contributes
  nothing.
* **Colder = slower decay**, so the accumulator and its flags persist longer when
  cold — the signature of a cold-start hold, not a fuel-film term.
* The 2×2 selection is nearly moot: `0xAC840` == `0xAC854` byte for byte,
  `0xAC890` == `0xAC8A4`, and all four of `0xAC818`/`868`/`82C`/`87C` are
  identical.

⇒ Item 87 flagged these as having the shape of a wall-wetting / X-factor term,
which would have borne on the cusp stab-lean conclusion. **Ruled out for this
path.** At operating temperature they are a constant and cannot explain any
temperature-varying transient behaviour. They remain a real cold-start lever and
are still undefined in every XML — but they are not the thing.

This is the "read the clamp constants before calling anything a live lever" rule
(CLAUDE.md) catching a hypothesis one step after it was raised.

### Still open

`[FFFF72DC]` (charge value) and the four thresholds `[FFFF7328]`/`[732C]`/
`[7330]`/`[7334]` are **RAM**, so the staging is set at runtime, not by
calibration — their writers are not traced. Nor is what consumes the four flags
`0xFFFF726F`–`0xFFFF7272` or the four outputs `0xFFFF7290`–`0xFFFF729C`.
`byte[0xFFFF3158]`, `byte[0xFFFF90C1]` and `gbr+101` remain unidentified.

### Status

Recorded. No ROM bytes changed, no XML edited, no table named.

---

## 89. The `0xAD960` cluster is a two-stage thermal-lag model with a 930.0 trip — **CLOSES open-holes #7 next-move 1, 2026-08-19**

Full trace: `disassembly/analysis/thermal_lag_model_trace.txt` (72/72 lines
verify).

The five unnamed RPM × load tables from slice 1 are not five maps. They are one
model:

```
target  = table2D(load,RPM)          ; 0xAD960 (390..866) or 0xAD97C (390..1138)
        x table1D(0xAC60C, knock_mix); 1.0000 .. 1.0469
hysteresis band 20.0 (0x0CC224) picks the filter coefficient:
        rising  -> 0xAD998      falling -> 0xAD9B4      (0.0117 .. 0.1094)
stage 1 [FFFF79A4] = lag(target,     [FFFF79A4], alpha(load,RPM), snap 0.02288818)
stage 2 [FFFF79A8] = lag([FFFF79A4], [FFFF79A8], 0.0100,          snap 0.02288818)
trip    [FFFF79A4] >= 930.0 (0x0CC210/0x0CC214) -> byte[FFFF79FC] = 1
```

`knock_mix` = `[FFFF7F48] + [FFFF8258] − [FFFF7E90]`, where `0xFFFF8258` is the
knock-workspace integrator from item 80 — so ignition retard raises the modelled
quantity by up to **+4.7%**.

Helpers verified from bytes: `0x0BEA40` is a first-order lag with a snap-to-target
deadband, `0x0BEAB0` is `|a−b|`, `0x0BE608` is the outside-a-band test from item
83. The snap threshold `0.02288818` is exactly one LSB of `0xAD960`'s scale.

**A second trip is calibrated off.** `0x0457F4` compares the stage-2 output
against `[0x0CC220]`/`[0x0CC21C]`, both **10000.0**, against a quantity whose base
map maxes at 1138. `byte[0xFFFF8253]` can never be set.

**Both stages are exposed for logging** via the SSM getter at `0x024564`, but
neither appears in `logs/logcfg.txt` in any rev.

### What it is — inference, not a name

Every property fits an **exhaust-gas / catalyst temperature model driving
open-loop enrichment for component protection**: a 390–1138 quantity on a
load × RPM base map, two-stage thermal lag with separate heating and cooling
constants, raised by ignition retard, tripping at 930.0 — a textbook
catalyst/turbine limit — in a module whose GBR is labelled `ol_enrichment_accum`.

**No name is asserted.** Settling it means tracing what consumes
`byte[0xFFFF79FC]`. Note also that `[0xFFFF79F8]`, labelled `ol_enrich_func_ptr`,
is **not a function pointer** — it holds a table descriptor address.

None of `0xAD960`, `0xAD97C`, `0xAD998`, `0xAD9B4`, `0xAD9D0`, `0xAC60C`,
`0x0CC20C`–`0x0CC228` has an `address=` entry in the project XML.

---

## 90. 91 Ghidra addresses carry CONFLICTING labels — item 69's sweep only covered `desc_*` — **NEW, 2026-08-19**

Found while checking `0xFFFF798C`, which carries both `ol_enrichment_accum`
(line 1855) and `timing_state_var` (line 2636).

A scan of `labelComment(` calls finds **91 addresses with two or more different
names**.

> **The 91 is an undercount — the real figure is 118, and 112 of them pre-date
> this session (item 91).** This scan keyed on the address *string*, so
> `0x0000E774` and `0xE774` counted as different addresses. Item 91 re-counts by
> parsed integer. Same derived-number failure this repo keeps hitting.

Item 69 resolved 61 duplicates, but
`scripts/mapping/dedupe_import_java_labels.py` handles **`desc_*` labels only** —
the general ones were never in scope. Examples where the two names cannot both be
right:

```
0x000299BC   diag_check_P0137          / float_store_to_ram
0x000278D2   check_maf_valid           / dwell_calculator
0x000281DC   check_diag_mode_active    / sensor_scale_helper
0x00023E48   check_afl_ready           / fuel_desc_reader
0x000297A0   diag_flag_reader_cluster_start / float_load_from_desc
```

One family looks like a **bulk pattern-scan** that assigned diagnostic names
across a range which a later, evidence-based pass renamed as generic helpers.
Whichever is right, the file currently asserts both.

**Six of them are mine, added across this session without checking whether the
address already had a label** — the exact mistake this item documents:

| address | existing | mine | resolution |
|---|---|---|---|
| `0x0000E774` | `ADC_StateMachine` | `sched_isr_common_entry` | item 84's trace supersedes |
| `0x00010800` | `event_notify` | `sched_event_post` | same thing, merged |
| `0xFFFF79A4` | `ol_condition_checker_GBR` | `thermal_model_stage1` | **both true**, merged |
| `0x0BEA40` | `float_lerp` | `float_lag_filter` | **the old name was right**; it is a lerp used as a lag |
| `0x0BEAB0` | `table_lookup_err_scale` | `float_abs_diff` | 3 instructions, `fsub/fabs/rts` — old name unsupported |
| `0xFFFF3158` | `afl_diagnostic_flag` | `fn_2F03C_pair_select` | mine described a *use*, not an identity; folded into the existing comment |

Two of those six went the other way from what I expected: `float_lerp` was
already correct, and my `fn_2F03C_pair_select` was a use-description masquerading
as an identity. All six are merged to one label per address.

**The other 87 are NOT resolved here** — each needs deciding on evidence, which
is exactly the work item 69 did for descriptors. Recorded as open-holes #8.

### Status

Recorded. Two labels merged; 89 conflicts outstanding.

---

## 91. The `isr_handler_N` / `dtbl_isr_*` family: 106 labels built on a table that does not exist — **2026-08-19**

### The decisive test

`0x00E5EC`–`0x00E6C0` carried 52 `dtbl_isr_handler_N` labels ("Dispatch table[N]
-> 0x…"), and the 51 addresses those slots point at carried matching
`isr_handler_N` labels. Three checks, all negative:

1. **Every one of the 51 is a value in that pool, and every `N` equals the pool
   slot index exactly** — 51/51. The naming is purely positional.
2. **Not one of the 51 appears in the `0x0`–`0x400` interrupt vector table**
   (227 distinct entries). They are not ISR handlers.
3. **Item 84 already proved the premise false**: `0x00E5EC`–`0x00E6C0` is the
   shared *literal pool* of the `0x00E4xx` task stubs — 54 longs bounded by
   `rts/nop` at `0x00E5E8` and code at `0x00E6C4`, with no literal anywhere
   pointing at its base.

### What was done

| action | count |
|---|---|
| `isr_handler_N` dropped where a semantic label already existed | 23 |
| `isr_handler_N` renamed → `stubpool_target_N` (was the sole label) | 28 |
| `dtbl_isr_*` renamed → `stubpool_slot_N`, comment re-derived from ROM bytes | 52 |
| short-form false-premise labels dropped (`0x00E5EC`, `0x00E628`, `0x04A94C`) | 3 |
| **total retired** | **106** |

The *pointer* facts were true and are preserved: each `stubpool_slot_N` comment
now states its slot address and the long it holds, re-read from bytes rather than
trusted.

### Also resolved, from evidence already in the repo

`0xFFFF3234` → `ram_IAM` (item 81, proven from the definition XML);
`0xFFFF3248` → `flkc_grid`; `0xFFFF1288` → `rtos_scheduler_state` (item 80);
`0x04A94C` → `sched_periodic_dispatch` (item 84 — 23 `jsr` + a tail `jmp`, and
absent from the vector table, so not an ISR).

### Honest accounting for this session

**13 conflicts were introduced by me**, by adding a label without checking
whether the address already had one. All 13 are merged. Two went against my
expectation: the pre-existing `float_lerp` on `0x0BEA40` was already right, and
my `fn_2F03C_pair_select` was a use-description competing with a real identity
claim. Standing rule now: **keep the pre-existing name unless a byte-level trace
positively contradicts it.**

```
conflicts at session start : 112
introduced this session    : +13   (all merged)
resolved this session      : -42
conflicts now              :  83
```

### Status

`javac` exit 0 against Ghidra 12.0.2. **83 conflicts remain**, all pre-existing.
They are not one family — each needs its own evidence. See open-holes #8.

---

## 92. The auto-generated flag-reader labels were RIGHT; the hand-written "helper" names were wrong — **2026-08-19**

Item 91 left 83 conflicts and predicted that the `check_*` / `diag_*` family —
headed in the file as *"FLAG READER LABELS (auto-generated from ROM byte pattern
scan)"* — was "the same shape of error as the one just retired" and should be
tested as a family first.

**That prediction was backwards.** Decoding the functions settles it the other
way: the auto-generated names describe what the code does; the hand-written
"Miscellaneous High-Call-Count / Sensor Reading Helpers" names do not.

All five contested functions are six-instruction **byte flag readers**:

```
0297A0: D65C  mov.l @(0x029914),r6   ; FFFF9704
0297A2: 6260  mov.b @r6,r2
0297A4: 2228  tst r2,r2
0297A6: 8F01  bf/s 0x0297AC
0297A8: E002    mov #2,r0
0297AA: E000  mov #0,r0
0297AC: 000B  rts
```

| address | reads | retired name | why it is wrong |
|---|---|---|---|
| `0x0297A0` | `byte[FFFF9704]` | `float_load_from_desc` | no float, no descriptor |
| `0x0299BC` | `byte[FFFF971C]` | `float_store_to_ram` | it is a READ, and no float |
| `0x0281DC` | `byte[FFFF96A8]` | `sensor_scale_helper` | no scaling, no float |
| `0x0278D2` | `byte[FFFF6A29]` | `dwell_calculator` | five-instruction bit test |
| `0x023E48` | `byte[FFFF67FC]` | `fuel_desc_reader` | no descriptor |

Tell-tale that should have been caught earlier: **both blocks quoted the same
call counts** for the same addresses (14 for `0x0299BC`, etc.). They were always
describing the same functions.

`0x02999C` was a true synonym pair — `flkc_flag_slot15` and
`flkc_state_flag_slot15` both correctly describe `byte[FFFF971B]` → 2/0. Merged,
alias recorded.

`0x000E5EC`'s last claimant, `isr_dispatch_table` ("Interrupt dispatch table: 54
function pointers"), is retired — it used a third address-literal form
(`0x000E5ECL`) and survived item 91's sweep. **Zero labels now assert a dispatch
table.**

### Lesson

"Auto-generated" is not a synonym for "unreliable". The pattern scan was derived
from the actual byte pattern and was accurate; the hand-written names were
plausible-sounding guesses. Judge the label by whether the bytes support it, not
by how it was produced — the `isr_handler_N` family was wrong because its
*premise* was disproved, not because it was generated.

```
conflicts: 83 (item 91) -> 76
```

### Status

`javac` exit 0. 2,595 labels. **76 conflicts remain.**

## 93. The four `desc_*` vs semantic conflicts resolved — item 85's axis fix settles two of them — **2026-08-19**

| address | verdict |
|---|---|
| `0x0AD090` | **Both wrong.** Data `0x0CE5A4` is named **"AFL Ramp Rate (CL to OL Transition Speed)"** in the project XML. `OL_Enrich_RampRate_Desc` is a misnomer — AFL is the long-term trim, not OL enrichment. `desc_1D_RPM_wide_u16_9` had the geometry right (1-D uint16 ×9 on Engine Speed `0x0CE580`, 0–8000). Renamed **`AFL_RampRate_Desc`**. |
| `0x0AD620` | **Semantic wins.** Data `0x0CFA38` = "Intake Duty Correction A". `desc_2D_ThrottlexRPM_u8_10x9` had geometry right but **axes wrong** — Mass Airflow × Engine Speed, not throttle × RPM. |
| `0x0AD848` | **Semantic wins.** Same, `0x0D121C` = "Exhaust Duty Correction A". Cell type differs from its intake sibling: exhaust uint16, intake uint8. |
| `0x0AD928` | **Neither verified.** Data `0x0D1A68` is claimed by no XML and both axes are unnamed. The two names agreed in substance (AFC integral / PI blend) so they are merged, but the identity is **not** established. What *is* established: all 110 cells are 0.0 — inert as shipped — and the consumer at `0x034106` sits in the CL fuelling path near `byte[FFFF782C]`. |

**Two of the four are settled by this session's own item 85**, which proved from
the data stride that those axes are Mass Airflow × Engine Speed and fixed it in
the XML. The `ThrottlexRPM` naming predates that.

### A tooling lesson that has now cost four failed edits

Address literals in `ImportAE5L600L.java` appear in **at least four forms** for
the same address:

```
0xAD090        0x0AD090L        0x000AD090        0x00E5ECL
```

Regex edits keyed on the literal text silently miss labels — that is why item 91
left `isr_dispatch_table` behind and why three drops failed here. **Any script
that edits this file must match on the PARSED address, not the text.** The
conflict counter was fixed this way in item 91; the editors were not.

### Attempted and NOT settled

`0xFFFF5DB5` (`cl_ol_gate_flag` | `si_drive_mode`) was chased and left open.
It is read as a byte at 11 sites; `find_writers` returns a single hit that the
tool itself annotates as a likely phantom in a data region. The nearby switch
compares (`cmp/eq #1..#5` at `0x03649A` and `0x04F718`) are on a **different
register**, so they do not establish the byte's cardinality. Neither a binary
gate nor a 3-state SI-Drive mode is supported by what was decoded.

```
conflicts: 76 -> 72
```
