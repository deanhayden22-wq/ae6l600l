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

Real IAT is `0xFFFF69F0` — already in `ram_reference.txt` as `iat_input_float`
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
