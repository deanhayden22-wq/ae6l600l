# Open holes — current as of 2026-11-27

Live worklist. Everything here is **scoped, reproducible, and unblocked** — each
entry says what is known, what is not, and the concrete next move.

Reference bin for every address below: `rom/AE5L600L 20g rev 20.19c.bin`,
md5 `92cae8275cd4f9b473a3a9e36efe6449`. **Verify the md5 first** — Dean rebuilds
bins in place and a filename-matched changeset has lied before.

**Method and priorities: [`analysis-plan.md`](analysis-plan.md).** It carries the
measured hit rates (≈40% of unnamed tables are flat, ≈25% diagnostic), the
triage-before-decode sequence, and the standing rules.

House rules still apply: ROM bytes outrank every artifact; cite `file:line` for
derived claims and `address: bytes -> mnemonic` for binary ones; say plainly when
something is unverified. Read the **Tools** section of `CLAUDE.md` before writing
a script — six exist that each replaced an ad-hoc pass that had produced a wrong
answer.

---

## 1. ~~Seven RAM addresses with genuinely conflicting labels~~ — **CLOSED 2026-08-18**

**All seven adjudicated** (corrections items 76, 80, 81). Four of the seven had
**both** competing names wrong. Numbering kept so existing "hole #N" references
stay valid.

`docs/corrections.md` item 66. `scripts/mapping/reconcile_ram_labels.py`
harvested and ranked every address→label claim; 26 conflicts survive filtering,
and these seven are the ones that are materially different rather than wording.

| address | competing claims | registry flag |
|---|---|---|
| ~~`0xFFFF64F5`~~ | **RESOLVED 2026-08-18 — item 76. Neither name. It is a DEBOUNCED CLOSED-PEDAL flag (`counter > 2`), overloaded to carry `fuel_system_state` when `adc_channel_status == 1`.** | |
| ~~`0xFFFF3234`~~ | **RESOLVED — item 81. It is the IAM.** Proven from the definition XML: cal `0x0D2CF4` (`Timing Compensation B (IAT) IAM Activation`, scaling `IgnitionAdvanceMultiplier(IAM)`, 0.60) is compared against it at `0x042F74`. `flkc_work_bank1` WRONG; `knock_learn_coarse` right in substance. | |
| ~~`0xFFFF8258`~~ | **RESOLVED — item 80. A knock-workspace product INTEGRATOR; `knock_metric` in kind, `flkc_retard` unsupported (produces no degrees).** | |
| ~~`0xFFFF7F68`~~ | **RESOLVED — item 80. ECT warm-up blend, 4 modes on `ect_current`. Identity vs use — both names describe it from opposite ends.** | |
| ~~`0xFFFF1288`~~ | **RESOLVED — item 80. `rtos_scheduler_state`: SR-masked priority raise + MTU0 array. `inj_gate_hook_ptr` WRONG.** (Item 107: the "MTU0 array" `0xFFFF1230` is on-chip RAM, the RTOS queued-id array, not a timer register.) | |
| ~~`0xFFFF8F24`~~ | **RESOLVED — item 80. Debounced flag on status byte == 90, 6-count timeout. BOTH names unsupported.** | |
| ~~`0xFFFF895C`~~ | **RESOLVED — item 80. A clamped difference with a 1000.0 ceiling. BOTH names unsupported.** | |

**How to settle each** (this exact method resolved `0xFFFF6254` and
`0xFFFF7D18`, and corrected `0xFFFF4130`, `0xFFFF6354`, `0xFFFF3248`,
`0xFFFF8298`):

```
python scripts/mapping/find_writers.py FFFF64F5 FFFF64F6
```

then read the writer's context. Two outcomes are common and both are results:

* **Identity vs use.** `0xFFFF7D18` was called `knock_suppress_flag` and
  `fuel_system_state`; its writer is in the fuel region and the FLKC learn
  routine reads it as a gate. Both names were right from opposite ends.
* **Both wrong.** `0xFFFF6254` was claimed four ways; it is a byte written 0/1
  from a three-condition test — a validity flag, not any of them. **Do not
  invent a replacement name**; record what is established.

Re-run `reconcile_ram_labels.py` after any label change.

---

## 2. ~~Does `func_37B74`'s product term ever go non-zero?~~ — **CLOSED 2026-08-18**

**No. The term is identically zero and the multiplier is a constant 1.0.**
Full evidence in `docs/corrections.md` item 72.

`A` (`0xFFFF7ABC`) is not computed — `FUN_00037d74` reads it from descriptor
`0xAD71C`, whose 16x2 uint8 data at `0x0D0740` is 32 bytes of raw `0x80`, i.e.
`0.0` in every cell after `scale 0.00390625 / bias -0.5`. So `A*B*C*D = 0` and
`[0xFFFF7AB4] = clamp(1.0, 0.5, 1.5)`. `fuel_pw_calc` at `0x0301FC` reads a dead
multiplier. Same shape as `0xAD258`.

`B` (`0xFFFF7AC0`) *can* be non-zero — it is a step function taking only `1.0`
(`fldi1` @ `0x037EAA`) or `0.0` (`fldi0` @ `0x037EF0`), because both ramp rates
(`0xCC32C`, `0xCC330`) are `0.0`.

Numbering kept so existing "hole #N" references stay valid. Do not re-litigate;
if you want to *revive* the term, corrections item 72 lists the three zeroed,
undefined calibrations that would do it — and warns why it is not a casual edit.

---

## 3. ~~What is `0xFFFF77D8`?~~ — **CLOSED 2026-08-19**

**It has NO WRITER. It is the inert first term of a two-term fuel trim.**
Settled statically — the drive in option 1 was not needed.

Full trace: `disassembly/analysis/ffff77d8_trace.txt` (88/88 lines verify).
Evidence: `docs/corrections.md` item 83.

```
S = 1.0 + [0xFFFF77D8] + [0xFFFF77DC]                  ; consumer 0x03961C
if |S| <= 1.22e-4:  [0xFFFF7BAC] = 0.0
else:               [0xFFFF7BAC] = clamp(1.0/S - 1.0, 0.0, 0.03)
```

Four independent searches found no writer: `find_writers.py`; exhaustive literal
enumeration (the value occurs at exactly four aligned offsets — three pools, all
loaded by reads, plus one pointer-table slot no code path reaches); a store-base
back-trace over `0x0`–`0xC0000`; and GBR-base enumeration over all 651
`ldc rN,gbr` sites.

**Numerically:** `[0xFFFF77DC]` is negative in all 532 comp cells
(−0.14999…−0.00475), so `S ∈ [0.85, 0.995]` and the output is always a positive
enrichment, **saturating at the +3% cap in 56 of 532 cells (10.5%)**. The
`= 0.0` path is unreachable.

**The old entry was wrong about the suppression test.** It is
`|1 + [77D8] + [77DC]| <= 1.22e-4` — a divide-by-zero guard — not
`[77D8] >= +0.00475…+0.150`. Those figures were the 77DC table magnitudes.
The `map_gbr_structures.py` next move does not apply either.

---

## 4. ~~Which knock table is the detection threshold?~~ — **CLOSED 2026-08-19**

**Neither of the two options in the old question. Lookup 2 is the SIGMA
MULTIPLIER — a dimensionless gain on a tracked deviation statistic.**

Full trace: `disassembly/analysis/knock_threshold_trace.txt` (195/195 instruction
lines verify). Evidence summary in `docs/corrections.md` item 82.

```
threshold_A = clamp( baseline + K * deviation,          50.0,  359.0 )  -> 0xFFFF8154
threshold_B = clamp( baseline + K * 1000.0 * deviation, 50.0, 1000.0 )  -> 0xFFFF8158

K         = lookup 2 (0xAE6D4/6FC/6E8/710), 18 RPM x 2 LOAD, 3.45..3.60
baseline  = per-cylinder tracked mean    [r9-16] = 0xFFFF8148
deviation = per-cylinder tracked spread  [r9-8]  = 0xFFFF8150
```

Decision at `0x043B34`: `signal < threshold_A` → no knock; else `0xFFFF67EC` must
have reached 250 (`word[0x0D29DC]`); else `KNOCK_FLAG` (`0xFFFF81BA`) = 1, and
`0xFFFF81BB` = 1 additionally when the signal also clears threshold_B.

**The old entry was wrong on three points** — kept here because each was the kind
of error that survives by nobody re-decoding:

* `r9` is **not a stack frame**. It is the literal `0xFFFF8158` (pool `0x0439BC`),
  so every `[r9-NN]` is a nameable RAM address.
* Lookup 2 stores to **`[r9-44]` = `0xFFFF812C`**, not `[r9-40]` (that is lookup
  3). It is first read at **`0x043ABE`**.
* `0x043888`–`0x0438B0` never touches it — that block is the **deviation
  estimator**, reading `[r9-32]`/`[r9-92]`/`[r9-24]` and writing `[r9-20]`.
* Units are **dimensionless** (a sigma count), not "knock-signal units".

**Latent lever, still recorded not proposed:** the two 18-value load planes are
byte-identical, so the load axis is exactly flat. Because K is a sigma
multiplier, differentiating them is well-defined — **lower K = more sensitive**.
Load breakpoints 0.80 / 2.20 g/rev; RPM 800–7600 in 400 steps.

**Also established:** none of the twelve knock-detection calibrations (the five
lookup families plus `0x0D2D84`–`0x0D2D94`, `0x0D29DC`, `0x0D298B`) has an
`address=` entry in the project XML. The whole detection front-end is invisible
to ECUFlash.

---

## 5. ~~What walks the scheduler task lists?~~ — **CLOSED 2026-08-19**

**There IS a walker — just not over the call runs.** `0x00010B2A` linearly scans
a **5-slot event table** at `0xFFFF2064` (stride 12, count byte `0xFFFF2060`).

Full trace: `disassembly/analysis/scheduler_event_queue_trace.txt` (162/162
lines verify). Evidence: `docs/corrections.md` item 84.

```
ISR stub -> 0x00E774 (IMASK=15) -> 0x00010800 -> 0x00010B2A  [walker]
entry +0 word id | +4 long payload | +8 byte pending count, saturates at 255
```

* **Coalescing:** a repeat of a queued id bumps its counter, not a new slot.
* **Silent drop:** `cmp/ge #5` at `0x010BCC` discards a NEW id once 5 slots are
  used. No error path.

Item 63's finding stands: the task bodies are straight-line `jsr` runs, nothing
walks them. But **two Java labels were wrong** and are now fixed — `0x04A94C`
makes **24** calls (23 `jsr` + tail `jmp`), not 59, and `0x04AD40` is a literal
pool, not a `task_table`.

**Still open** (not blocking anything): what DRAINS the table; the guarded-RAM
accessor prologue at `0x0000317C`; the full event-id map; the writer of
`byte[0xFFFF8EDC]`.

> **RETRACTED 2026-11-27 (corrections item 107).** The table mechanics above are
> right; the identity is not. `0x00E774` **never returns**: it logs {`0x4000`,
> vector number} through `0x010800` and jumps to `0x00FBA4`, which masks all
> interrupts and branches to itself (`00FBB6: AFFE`). The "event ids" are **trap
> vector numbers** and nothing drains the table — it is a fatal-trap log. The
> scheduler is the RTOS in `0x002B8C`–`0x004090` (ready map `0xFFFF12B8`, dispatcher
> `0x0035FC`, deferred switch `0x003664`): `rtos_core_trace.txt`. `0x0000317C` is
> settled too: it raises the SR interrupt-mask field (a critical-section bracket),
> it is not a RAM accessor.

---

## 6. ~~ECUFlash definition sync~~ — **CLOSED 2026-08-19**

All four definition fixes are applied to the repo XMLs and verified through
`scripts/defs.py`. `docs/corrections.md` item 85.

**Registry CONFLICT count is now 0** (was 2); VERIFIED-BOTH 360 → 363.

| table | fix | now reads |
|---|---|---|
| `c0bcc` | scaling → `EngineLoad(g/rev)1` (float) | **1.70** (displayed 1.00) |
| `d6214` | scaling → new `rawecuvalue(uint16)` | **18** (was a denormal) |
| `cfa38` / `d121c` + 8 base variants | X/Y swapped, axis renamed `Mass Airflow` | **9 × 10**, monotone |

**Pushed and confirmed 2026-08-19.** `.\scripts\sync_defs.ps1` now reports both
files *in sync* at the corrected sizes (project 64,893 / base 585,222). Nothing
outstanding.

> The two blockers this entry used to carry are **both gone and were wrong**:
> the "repo is 37 tables ahead, a blind `-Pull` deletes them" warning was stale
> (the copies were byte-identical), and "the repo copy still reads `max=5`" for
> `EngineLoad(g/rev)1` confused it with `EngineLoad(g/rev)` — the `1` variant
> already read `max="8"`.

**Recorded, not applied** (item 85): `d121c` inherits `(x*.003051758)-100` and
displays −82.5…−95.5. Dropping the `-100` yields 17.5…4.5, matching the Intake
table's shape. Left alone deliberately — it is a data-interpretation change, not
part of the authorised fix set. Its RPM axis is also exactly flat (every row
byte-identical), same degenerate shape as the knock load planes.

---

## 7. The undefined-ROM programme (NEW — this is the live worklist now)

Items 1-6 are all closed. `docs/corrections.md` item 86 opens the successor.

**947 of 1,094 ROM-decoded table descriptors have no definition anywhere.** Each
is a *proven* table — the code reads it through `table_lookup`, so geometry, cell
type, scale/bias, axis breakpoints and data are all known. Only the **meaning**
is missing.

> The count was **786** until 2026-08-19; item 87 corrects it. A table is
> unnamed iff its **DATA** pointer is unclaimed. Item 86 also excluded tables
> whose *axis* pointer was claimed, which is wrong — and the discarded signal is
> the most useful one in the whole programme: **158 unnamed tables share an axis
> array with a NAMED table, so their axis identity is free.**

**Slice 1 (RPM × engine load, 41) DONE** —
`disassembly/analysis/unnamed_tables_rpm_load.txt`. 14 flat, 11 diagnostic
monitor, 8 already-identified knock tables, 3 CL-fuelling siblings, 1 artefact.

**Slice 2 (coolant axis, 157) DONE** —
`disassembly/analysis/unnamed_tables_coolant_axis.txt`. **66 flat (42%)**;
37 populated are OBD diagnostics in `0x50000`-`0x55000`; 25 populated are in the
`0x2F000`-`0x31000` fuel region. Four coolant axis arrays, all the identical
16-point −40…110 °C ladder.

### Next moves, in order

0. ~~Settle the eight coolant fractions~~ — **DONE, item 88.** They are the
   decay rate of a staged accumulator bank in the transient workspace, and
   **inert above 40 °C** (all eight are a flat 0.900 there). The wall-wetting
   hypothesis is **retired**. What remains, if anyone wants it: the charge value
   `[FFFF72DC]` and the four thresholds `[FFFF7328]`/`[732C]`/`[7330]`/`[7334]`
   are RAM, so the staging is set at runtime — nobody has traced their writers,
   or what consumes flags `0xFFFF726F`–`0xFFFF7272`.
1. ~~Decode `0x03684A`~~ — **DONE, item 89.** The five tables are one model: a
   load × RPM base quantity × a knock-derived uplift, through **two cascaded lag
   filters** with separate rise/fall coefficients, tripping a flag at **930.0**.
   **Consumer traced (item 95): it drives a DTC maturation counter, NOT
   enrichment.** A modelled temperature with a 930.0 over-temperature monitor;
   no fuel-path consumer exists anywhere in the image. Still open:
   `[0xFFFF7F48]` and `[0xFFFF7E90]`, and whether the counter sets a named DTC.
2. **Triage out the diagnostic-monitor rows** (`0xABDD4`–`0xABE60`, `0xAC0DC`,
   `0xAC0F0`, `0xAC104`, `0xAC12C`). Symmetric ±3999 pairs on RPM × load —
   almost certainly OBD rationality bands, i.e. deliberately not levers.
   Confirming that removes 11 tables from the unknown pile cheaply.
3. **`0xAD6AC` and `0xAE664`** — 18×15 RPM × load, entirely zero, consumers touch
   the FLKC workspace. A dormant FLKC feature.
4. **Remaining slices** of the 786: 157 with an ECT/IAT axis, 116 RPM × unknown,
   29 load-only, 23 index-ramp (no units), 279 with no axis classified.

### Rules for this programme

* **Do not name a table from its subsystem hint.** The hint comes from RAM
  referenced near the call site, and several of those RAM labels are themselves
  project guesses. 48 invented `Map Switching *` names are already a cautionary
  tale. Record what the consumer proves; leave it unnamed otherwise.
* **FLAT ≠ a free lever.** `0xAD258` and `0xD2D48` are flat *and* feed
  multipliers separately clamped to zero.
* **Join on the pointers inside the descriptor record**, never on the descriptor
  address — definitions point at data. Joining wrong returns zero matches and
  reads as "nothing is defined".

---

## 8. 72 Ghidra label conflicts remain (was 118)

`docs/corrections.md` items 90 and **91**.

```
conflicts at session start : 112     (the "91" in item 90 was a string-key undercount)
introduced 2026-08-19      : +13     (all merged)
resolved 2026-08-19        : -53
remaining                  :  72
```

> **Editing this file: match on the PARSED address, not the literal text.**
> The same address appears as `0xAD090`, `0x0AD090L`, `0x000AD090` and
> `0x00E5ECL`. Text-keyed regex edits have silently missed labels four times
> (item 93).

**The big family is gone.** 106 labels rested on a "dispatch table" at
`0x00E5EC`–`0x00E6C0` that item 84 proved is a **literal pool**: all 51
`isr_handler_N` names were positional over pool slots (51/51 index match) and
**none of the 51 is in the `0x0`–`0x400` vector table**. Renamed to
`stubpool_slot_N` / `stubpool_target_N` with byte-derived comments.

### The 83 that remain

They are **not one family** — each needs its own evidence. Three rough groups:

1. **Synonym pairs** — same meaning, different words. Cheap: pick one, fold the
   other's detail into the comment. e.g. ~~`interrupt_priority_set` /
   `irq_level_set`~~, `afc_target_calc` / `afc_target_computation`,
   `fuel_overrun_cutoff` / `overrun_fuel_cutoff`, ~~`table_desc_1d_float` /
   `table_lookup_1D`~~. (Struck pairs resolved by decoding, item 107:
   `0x00317C` is now `sr_mask_raise_return_previous`, `0x0BE830` keeps
   `table_lookup_1D`.)
2. ~~**Generated vs semantic**~~ — **DONE (item 93), all 4 resolved.** The
   `desc_*` geometry was trustworthy every time; its **axis** claims were not
   (`ThrottlexRPM` where item 85 proved Mass Airflow × Engine Speed). One,
   `0x0AD928`, is merged but its identity remains unverified — its data is all
   zero, so it is inert either way.
3. **Genuinely contradictory** — these need decoding:
   ```
   0x000299BC  diag_check_P0137               / float_store_to_ram
   0x000278D2  check_maf_valid                / dwell_calculator
   0x000281DC  check_diag_mode_active         / sensor_scale_helper
   0x00023E48  check_afl_ready                / fuel_desc_reader
   0x000297A0  diag_flag_reader_cluster_start / float_load_from_desc
   0xFFFF4024  ATU_primary_ctrl / knock_adc_working / sensor_group_base
   0xFFFF3B06  diag_indexed_lookup_table / dtc_debounce_state / io_inj_ign_port_ctrl
   ```
   ~~The `check_*` / `diag_*` side looks like a second bulk pattern-scan~~ —
   **tested and the prediction was BACKWARDS (item 92).** The auto-generated
   flag-reader names were accurate; the hand-written "helper" names
   (`float_load_from_desc`, `float_store_to_ram`, `sensor_scale_helper`,
   `dwell_calculator`, `fuel_desc_reader`) were wrong. All five retired.
   **Judge a label by whether the bytes support it, not by how it was produced.**

### Rules

* **Check for an existing label before adding one.** 13 of the 118 got there that
  way this session.
* **Keep the pre-existing name unless a byte-level trace positively contradicts
  it.** Twice this session the older name turned out to be right.
* `scripts/mapping/dedupe_import_java_labels.py` handles **`desc_*` only** — it
  will not see any of these.

---

## 9. Every flashed rev zeroes a ±0.5 clamp on an A/F-correction term (NEW 2026-11-15)

`0x0357C8` / `0x0357CC` hold `+0.5f` / `-0.5f` in stock and `0.0` / `0.0` in every
rev 20.8 -> 20.19d. They are the bounds passed to `float_clamp_range` (`0x0BE56C`,
clamp(fr4, lo=fr5, hi=fr6)) at `0x03572E`-`0x035736`:

```
03572A fmov fr0,fr4            ; result of the previous clamp
03572C mov.l @(0x0357C4),r6    ; 0x000BE56C
03572E mova @(0x0357C8),r0
035730 fmov.s @r0,fr6          ; hi  (stock +0.5, tuned 0.0)
035732 mova @(0x0357CC),r0
035734 jsr @r6
035736 fmov.s @r0,fr5          ; lo  (stock -0.5, tuned 0.0)
03573A..03573E                 ; stored through struct +76 = 0xFFFF7904
```

The routine starts at `0x0355B8` with `r14` = the pointer struct at ROM `0x063A88`
(all `0xFFFF78B4`-`0xFFFF7941`, plus `0xFFFF318C`). With both bounds 0, the value
stored to `0xFFFF7904` is always 0.0. `0xFFFF7904` carries three conflicting labels
(`fuel_corr_param_A`, `aggregator_fuel_output`, `afc_aggregator_output`).

**Open:** what quantity this is, and what zeroing it does to fuelling. It is in the
car today, unrecorded in any definition or tune note. Decode the consumers of
`0xFFFF7904` (rule: find the readers of the output, not the name).

### Update 2026-11-27 — mechanism settled, identity still open (corrections item 107)

Full trace: `disassembly/analysis/hole9_afl_trace.txt` (2,641 lines, verifier clean,
emulated). `0x0355B8` is a **windowed PI controller**; `0xFFFF7904` is its output,
added with weight +1 into the 1.0-centred factor `0xFFFF77BC` (clamped 0.75..1.25)
by `0x033460`. Its window is centred on the guarded record `0xFFFF318C`, which is
stored through a **second clamp, `0x035FFC` (hi) / `0x036000` (lo)** — the pair the
definition calls "AF 3 Correction Limits" (it lists them min/max swapped). That
pair is zeroed too, through the definition.

* Zeroing only the defined pair still leaves `0xFFFF7904` live inside its window.
  **The off-table `0x0357C8`/`CC` edit is what completes the disable.** With both
  zeroed, as in every flashed rev, the term is pinned at 0 except for init/reload
  copies. In stock it stays within about −0.13..+0.09.
* The quoted claim above ("with both bounds 0 the value is always 0.0") holds only
  for the store at `0x03573E`; the init (`0x034F72`) and reload (`0x035046`) writers
  are unclamped.

**Still open:** that it is the rear-O2 (AF #3) trim — only the definition name says
so; what `0xFFFF77BC` multiplies (fuel?), so whether +`0xFFFF7904` is richer or
leaner; which sensor `0xFFFF43FC` is (u16 `[0xFFFF4050]` × 5/65536, copied from
peripheral `0xFFFFF834` — needs the SH7058 pin map). Next move: trace the readers
of `0xFFFF77BC`/`0xFFFF77C8` down to the injector pulse, and the writer of
`[0xFFFF4050]` to its A/D channel.

### Update 2026-11-27 (batch 2) — identity settled to the CL target; two questions left (corrections item 108)

`disassembly/analysis/hole9_identity_trace.txt` (1,925 lines, verifier clean, 70,000+
assertions, independently audited).

* **`0xFFFF77BC` is the closed-loop target in lambda units** (`0x033460`): 1.0 + the
  definition tables "CL Fueling Target Compensation A/B (Load)" and "... Imm. Cruise /
  Non-Cruise (ECT)" (AFR points / 14.7) + `[0xFFFF7904]` + other addends, clamped to
  0.85..`[7BDC]` (≤ 1.05 here) and 0.75..1.25. `0xFFFF77C8` is what other routines read.
* **Sign: positive `0xFFFF7904` = higher target lambda = leaner.** So re-enabling the trim
  (restoring ±0.5 at `0x0357C8`/`CC`, or the defined pair) would let it lean or richen the
  closed-loop target within those clamps.
* **But it only reaches `[77C8]` while byte `[0xFFFF8E7E]` != 1 or byte `[0xFFFF9720]` != 0.**
  Otherwise `0x033460` takes its SPECIAL exit and `[77C8]` is 1.0 (or 1.20 at standstill),
  whatever the trim or the CL target tables say.

**Still open (batch 3, items 2):** (a) whether `[77C8]` reaches the injector pulse —
`0x032204` takes 1/`[77C8]` into its state block, and `0x032B10` is the next consumer;
(b) when `[8E7E]` is 1 — its only writer is `0x05A498`. **Do not re-enable the trim until
(b) is known**: if `[8E7E]` is 1 in normal closed loop, the trim changes nothing that other
routines read. The A/D question (`0xFFFF43FC`) is unchanged.

### Update 2026-11-27 (batch 3) — the trim reaches logged AFC; SPECIAL looks cold-start-only (corrections items 111, 112)

`cl_target_to_fuel_trace.txt`, `afc_coefficients_trace.txt`, `special_exit_gate_trace.txt`.

* **(a) answered up to the injector pulse.** `[77C8]` drives logged AFC `0xFFFF76D4`, a live
  closed-loop integrator: v = ... + P0·(1/`[77C8]` − 1/`[653C]`), P0 = 0.0017..0.059 at the
  emulated operating points, so a positive trim (higher target lambda) pulls AFC down —
  leaner, as item 108 read — within AFC's −25 % / +25 % window. On SPECIAL/STEP exits it
  also moves AFC's clamp bounds. AFC then multiplies, with AFL and `[7348]` (load × "Injector
  Flow Scaling"), into the outputs of `0x0301E4`; **from there to the injector pulse is not
  traced.**
* **(b) narrowed, not closed.** `[8E7E]` = an output of the sequencer `0x05A498` is on; it can
  turn on only with `[8E38]` (coolant `[4144]` latched at start-up) in [0, 60), `[225C]` != 0
  and several latches clear, and `[9720]` is built only from secondary-air DTC bits (which
  20.19c disables). Reading: SPECIAL is the cold-start secondary-air phase — a hypothesis.
  **Settle with one cold-start log of `0xFFFF8E7E`, `0xFFFF8E66`, `0xFFFF8E65`, `0xFFFF8E68`,
  `0xFFFF8EDC`.** If `[8E7E]` drops to 0 once warm and stays there, the trim acts in all
  warm closed loop and re-enabling it is a live fuel change (with the gates still to pass).

---

## 10. The live SSM patch's tagged read has no bound (latent; NEW 2026-11-27)

Corrections item 107; `disassembly/analysis/stub_tables_trace.txt`. In the patched
`0x09A3AC`, an FF / F2 / F4 item copies 1 / 2 / 4 bytes from `0xFFFF0000 | b1 b2`
(ANY b1, b2 — on-chip registers included) to a reply cursor starting at
`0xFFFFB3F4` that nothing compares (`09A44C`–`09A456`). The length rule admits 84
items, so **23+ F4 items (45+ F2) overwrite `0xFFFFB44C`, then `0xFFFFB450` and the
transport ring header at `0xFFFFB454`.** Stock could not pass `0xFFFFB447`.

**Not a live problem:** `logs/logcfg.txt` requests FF items only (one byte each,
84 at most). **It becomes one** if anyone logs through F2/F4 tags with more than
22 four-byte or 44 two-byte items per request. If the patch is ever rebuilt
(`scripts/patchbuild/`), add a bound; what happens after the overwrite was not
traced.

---

## 11. The function programme (NEW 2026-11-27)

`docs/analysis-plan.md` Part 1 is the plan; `disassembly/maps/function_census.json`
the denominator (5,146 functions; after batch 3, 10.7% of code analysed and 13.6%
listed — raw dumps are not analysis, item 108 — and 4,157 functions untouched). Batch 1 (item 107) decoded the runtime library, the RTOS
core, the diagnostic tables, hole #9 and `0x042506`; batch 2 (item 108) the
launch-patch closure, hole #9's identity, five tuned-region functions and the
1,278 classified small functions; batch 3 (items 111-113) logged AFC's controller, the
SPECIAL-exit gate, the FFB residual, the timing-integrator bound, the overrun ladder and
the `0xFFFF8EDC` gate. Threads worth a trace of their own, in order:

1. ~~Readers of `0xFFFF77BC`~~ — done in batches 2-3 (items 108, 111): it is the CL lambda
   target and it drives logged AFC. **Batch 4's list is in `docs/analysis-plan.md`.**
2. The settle times that used the integer lag filter `0x0BEA6C` at 1/65536 — they
   are off by 256× (`maf_scaling_analysis.txt`, `adc_pipeline_trace.txt`).
3. `0xFFFF4144` vs `0xFFFF6350`: the logged ECT is the first; the project's ECT
   identity is the second. Are they one quantity?
4. ~~**The FPU rounding mode after init.**~~ — **settled 2026-11-27 (corrections item
   110):** the SH7058 hardware manual's FPU feature list says it supports round to zero
   only ("subset of IEEE standard"), so FPSCR = 0 at `05873E` cannot select
   round-to-nearest; the emulator's round-toward-zero holds for all running code. Not
   read: the manual's FPSCR bit table (what the RM field does when written 00).
5. The 30 census entries that are fall-through targets (function splits), and the
   dead function `0x002D10` the orphan pass does not seed.

---

## 12. What supplies the FFB transient excess? (REOPENED 2026-11-27, corrections item 109)

At settled WOT this ROM commands the OL map exactly (11.0); during transients FFB sits
up to ~0.8 AFR richer (residual median +0.053, max +0.098 in the 2026-08-19 logs).
`ffb_gap_resolved_2026-08-19.txt` attributed all of it to `0xFFFF7B8C` pinned at its
+0.09998 clamp. **That is retracted:** with this calibration `[7B8C]` cannot exceed
+0.046875 (`fn_038E64_trace.txt`), and `[7AF4]` is never non-zero (`fn_0382C2_trace.txt`).

**Open:** which of the other addends of the base sum at `0x02FFE0` —
`[0xFFFF73B4]`, `[0xFFFF7A08]`, `[0xFFFF7A14]` — supplies the rest. Decode `0x02FFE0`
(confirm the sum's form from bytes; it is from `ffb_command_chain_trace.txt`) and
`0x030C38` (GBR `0xFFFF73B0`); bound `[7A08]`/`[7A14]` from their already-traced
writers `0x036B48`/`0x036BF4`/`0x036C48`. Matters for injector sizing and for any
transient-fuel change: do not tune against `[7B8C]` as if it were the whole term.

### Update 2026-11-27 (batch 3) — `[73B4]` is the candidate (corrections item 111)

`ffb_residual_trace.txt` (2,392 lines, audited). The sum's form is confirmed from bytes, with
six addends that count only through a max(OL, CL) term. **`[73B4]` (written by `0x030C38`) is
the only addend whose range the bytes establish that has a rate-of-change input**, and it can supply the
whole excess by itself: a warm one-call step of 0.01·`[620C]` by 0.20 / 0.25 gives +0.059 / +0.082
for two calls. Its gain includes **tauA, a plane of "Tau Input A Rising Load Activation"** (20.19c
0.25 / 0.30 vs stock 0.5), it has **no upper clamp**, and it has a cold multiplier up to 4.95.
`[7A08]` is 0 warm; `[7A14]` reads no rate.

**Still open:** `[7354]`, `[7374]`, `[7A44]` and the `[79C0]` scaling of `[798C]` are not
bounded, so they are not excluded. **Settle with a log** of `0xFFFF73B4` alongside FFB through
tip-ins: if it tracks the residual, this hole closes. Lift-then-tip-in transients take a
snap branch with a larger tail than the settled-step figures.

---

## 13. What lowers timing during an overrun fuel cut? (NEW 2026-11-27, corrections item 113)

Item 103 logged timing 15-25° low while IPW = 0, recovering within 0.6 s of fuel resume, and
attributed it to the `[0xFFFF8020]` retard armed by `0x041BE4`. On the count path that arm
fires only at the cut exit (rpm below the resume threshold), so it does not explain a retard
held through the cut. Either those cuts took the IMMEDIATE path (`03B53A`..`03B544`), or
another timing term acts during the cut. **Next:** log `0xFFFF7C9A` (tier), `0xFFFF7CAA`,
`0xFFFF8020` and `0xFFFF5E96` / `0xFFFF5D85` through a few lifts; then decode whichever
term moves. Also open: whether the four `[7D80]` channels are injectors or coils (`0x00A280`).

---

## 14. Two definition tables are misnamed for this ROM — owner decision (NEW 2026-11-27, corrections item 112)

"Intake Duty Correction A" (`0x0CFA38`) and "Exhaust Duty Correction A" (`0x0D121C`) are
the dead time and time constant of logged AFC's plant model. Their only consumer is
`0x031DB4`, and they have nothing to do with AVCS. The "Exhaust" table's scaling is also
wrong (it displays −95..−82 where the code reads 0.09..0.35). The XMLs are ECUFlash's, so the
rename and the scaling fix wait for the owner. Use `.\scripts\sync_defs.ps1`, then `-Push`,
as item 85 describes. Neither table differs from stock in any rev.

---

## Closed this session — do not re-litigate

`docs/corrections.md` items 39–69. Headlines worth knowing before you start:

* **`0xAD258` is not a "WOT enrichment factor"** and contributes nothing —
  1-D, uint16, coolant axis, not on the IPW path, and clamped to `[0,0]`.
* **The FLKC grid is bucketed 7×5 = 35**, not an interpolated 6×4. Write and
  read each touch exactly one cell, so a mid-load event cannot smear into boost
  cells.
* **8-14 FLKC movement was in-drive LEARNING**, not map traversal — 59 of 64
  changes were in-cell.
* **`0xFFFF6354` is coolant temperature**, `0xFFFF4130` is battery voltage,
  `0xFFFF3248` is the FLKC grid, `0xFFFF8298` is its cell index.
* **`0xCC51C`/`0xCC530`** are a speed-limiter cut and an RPM guard, not tip-in
  gains.
* **Descriptor census is 1,094**, not 760, and the Java labels all 1,094.
* **Logged `AFC`/`AFL` are `0xFFFF76D4`/`0xFFFF7878`** (= enrichA/enrichB), NOT
  `0xFFFF77D8`/`0xFFFF77DC` — item 70. Hole #3 was rewritten because of it.
* **`0xFFFF77DC` is negative in all 532 cells** of the four CL Fueling Target
  Comp tables it can be written from — item 70.
* **`func_37B74`'s fuel multiplier is dead** — `A` reads descriptor
  `0xAD71C`, neutral-filled `0x80` in all 32 cells, so the product is 0 and
  `[0xFFFF7AB4]` is a constant 1.0. Both AFL ramp rates (`0xCC32C`,
  `0xCC330`) are 0.0, so `0xFFFF7AC0` is a step, not a ramp — item 72.
* **`desc_2D_BoostxLoad_u8_16x2` is a project guess.** Its axes are index
  ramps `0..15` and `0..1` with no units. `0xD39A8`-class; do not reason
  from that name.
