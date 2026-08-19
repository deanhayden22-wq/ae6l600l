# Open holes — current as of 2026-08-19

Live worklist. Everything here is **scoped, reproducible, and unblocked** — each
entry says what is known, what is not, and the concrete next move.

Reference bin for every address below: `rom/AE5L600L 20g rev 20.19c.bin`,
md5 `92cae8275cd4f9b473a3a9e36efe6449`. **Verify the md5 first** — Dean rebuilds
bins in place and a filename-matched changeset has lied before.

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
| ~~`0xFFFF1288`~~ | **RESOLVED — item 80. `rtos_scheduler_state`: SR-masked priority raise + MTU0 array. `inj_gate_hook_ptr` WRONG.** | |
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

**786 of 1,094 ROM-decoded table descriptors have no definition anywhere.** Each
is a *proven* table — the code reads it through `table_lookup`, so geometry, cell
type, scale/bias, axis breakpoints and data are all known. Only the **meaning**
is missing. 775 look real; 11 are scanner artefacts.

**Slice 1 (RPM × engine load, 41 tables) is DONE** —
`disassembly/analysis/unnamed_tables_rpm_load.txt`. 14 flat, 11 diagnostic
monitor, 8 already-identified knock tables, 3 CL-fuelling siblings, 1 artefact.

### Next moves, in order

1. **Decode `0x03684A`** to its output store and either name the
   `0xAD960`/`97C`/`998`/`9B4`/`9D0` cluster or prove it inert. Highest tuning
   value found so far: RPM 800–6400 × load 0.30–2.50, populated, selected on
   whether `[0xFFFF798C]` is non-zero, and it folds the knock integrator
   `0xFFFF8258` in on the way. Also identify `0xFFFF7F48` / `0xFFFF7E90`.
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
