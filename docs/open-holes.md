# Open holes — current as of 2026-08-18

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

## 1. Seven RAM addresses with genuinely conflicting labels

`docs/corrections.md` item 66. `scripts/mapping/reconcile_ram_labels.py`
harvested and ranked every address→label claim; 26 conflicts survive filtering,
and these seven are the ones that are materially different rather than wording.

| address | competing claims | registry flag |
|---|---|---|
| ~~`0xFFFF64F5`~~ | **RESOLVED 2026-08-18 — item 76. Neither name. It is a DEBOUNCED CLOSED-PEDAL flag (`counter > 2`), overloaded to carry `fuel_system_state` when `adc_channel_status == 1`.** | |
| `0xFFFF3234` | `flkc_work_bank1` vs `knock_learn_coarse` — **no writer even on a 0xFFFF3200-325F window scan**; neighbours at `0xFFFF3244` are written from `0x045xxx` (FLKC code). Needs a non-writer method. | UNMAPPED |
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

## 3. What is `0xFFFF77D8`? (was: "does `[77D8]+[77DC]` go negative")

`docs/corrections.md` items 62 and **70**. ⚠ **This entry was rewritten
2026-08-17 — its previous framing was wrong.**

**It is NOT a log question.** Item 62's parenthetical "these two sit in the
AFC/AFL trim-pair region" is false. Verified from the 19c bin: `AFC`/`AFL` are
stock SSM indices `0x09`/`0x0A`, so they route through the getter table at
`0x06423C`, and those getters read

```
064260 -> 05D2C0 :  05D2C2 D2AE mov.l @(0x05D57C),r2   [0x05D57C] = FFFF76D4   <- AFC
064264 -> 05D2DA :  05D2DC D2AA mov.l @(0x05D588),r2   [0x05D588] = FFFF7878   <- AFL
```

`0xFFFF76D4` and `0xFFFF7878` — which are **enrichA and enrichB**
(`fueling_pipeline_analysis.txt:366-367`), not `77D8`/`77DC`. Neither `77D8` nor
`77DC` is in `logs/logcfg.txt` in any rev. **Do not re-open this as a corpus
query.**

**Half of it is already settled statically.** `0xFFFF77DC`'s writer is findable
by reading the caller rather than by `find_writers.py` (the destination is passed
by pointer, so there is no literal store to match):

```
033342  B4BD  bsr 0x033CC0      ; r4 = 0x00063A44 ;  *(0x63A44) = FFFF77DC
033D0C  62D2  mov.l @r13,r2     ; r2 = FFFF77DC
033D0E  F20A  fmov.s fr0,@r2    ; <- the write
```

`0x33CC0` is a **4-way selector** over `0xAD8B8` / `0xAD8D4` / `0xAD8F0` /
`0xAD90C` — the CL Fueling Target Compensation family (A = `0xD14D0`,
B = `0xD1740`; `0xD1600` and `0xD18DC` are live siblings **missing from the
XML**). All four are uint16, scale `1/65536`, offset `−0.5`, load × RPM.
**All 532 cells are negative**, range **−0.00475 … −0.14999**.

⇒ Branch A of `func_3952C` arms **by default**, not as an edge case. It is
suppressed only when `[0xFFFF77D8] >= +0.00475…+0.150`. Item 62's "contributes
nothing in the ordinary case" is the wrong prior.

**Next move — one of two:**

1. **Log it.** The read-address patch takes arbitrary RAM with a width tag
   (`docs/ssm-read-patch.md`); `F4` = 4-byte. Adding `0xF477D8` (+ `0xF477DC` as
   control, `0xF47BAC` for branch A's output, `0xF47AB4` for hole #2) settles
   this and hole #2 in one drive. +16 bytes on the SSM stream — watch cadence.
2. **Trace it.** `afc_pi_controller_trace.txt:191` puts `0xFFFF77D8` at
   `R9+0xB0`, a struct-relative store. `find_writers.py` cannot resolve that by
   construction, so its two misses are expected — use
   `scripts/mapping/map_gbr_structures.py` / `identify_gbr_workspaces.py` and
   find what loads R9 in the AFC PI controller.

---

## 4. Which knock table is the detection threshold?

`docs/corrections.md` items 56, 59. The detector at `0x043798` does **five**
lookups:

| site | descriptor | input | data |
|---|---|---|---|
| `0x0437BE` | `0xAE284` | knock signal `0xFFFF4304`, clamped ≥0 | 0,0,32,51,…,304 |
| `0x043858` | per-cyl `0xAE6D4`/`6E8`/`6FC`/`710` | RPM × **LOAD** | **3.60 → 3.45** |
| `0x04386E` | per-cyl `0xAE724`/`738`/`74C`/`760` | RPM × **LOAD** | 1000.0 everywhere |
| `0x043920` | per-cyl `0xAE29C`/`2A8`/`2B4`/`2C0` | RPM | 16.0 everywhere |
| `0x043944` | `0xAE290` | RPM | 8,10,10,10,10,10,12,13,10,10 |

Lookup 2 is the threshold-shaped one. Its **load axis is exactly flat** — the two
18-value load planes are byte-identical — which is why "knock detection has no
load input" held up empirically for years while being false about the code.

**Open:** whether lookup 2 is the threshold itself or a per-cylinder trim on one.
Its result lands at `[r9-40]` and is consumed by the arithmetic at
`0x043888`–`0x0438B0`. Decoding that stretch settles it.

**Latent lever, recorded not proposed:** differentiating those two load planes
would make detection load-sensitive. Units are knock-signal units (the same
0–3.5 domain as `0xAE284`'s axis), **not degrees**.

---

## 5. What walks the scheduler task lists? (low priority)

`docs/corrections.md` items 57, 63. Resolved in the important sense: the "fuel
dispatch tables" are **literal pools**, not tables, and the "slots" are entries
in hand-unrolled `mov.l @(lit,PC),r2 / jsr @r2` call sequences — 92 consecutive
calls at `0x04AA6C`, 91 at `0x049E14`, gated on `byte[0xFFFF8EDC]`
(`sched_disable_flag`).

Nothing "walks" them, so the original question dissolved. What remains is only
what calls the enclosing functions, which is a scheduler question and does not
block any fuel or knock work.

---

## 6. ECUFlash definition sync (needs Dean, not a session)

`docs/corrections.md` item 55. `.\scripts\sync_defs.ps1` reports DIVERGED, but
"ECUFlash is newer" is a 52-second mtime artifact, not new content.

* **The repo is AHEAD on the project XML by 37 tables.** The 3 ECUFlash-only
  tables are superseded predecessors. **A blind `-Pull` deletes 37 tables.**
* Dean has confirmed the `EngineLoad(g/rev)1` `max=8` in ECUFlash is what he
  wants. The repo copy still reads `max="5"`, so **a `-Push` would write that
  clamp into the editor** — fix the repo value to 8 first, or push selectively.

Also ECUFlash-side, from item 51: `c0bcc` needs `storagetype float`
(reads 1.7, displays 1.00) and `d6214` needs `uint16`/`int16` (reads 18, declared
float). Repo XMLs must **not** be hand-edited — ECUFlash rewrites them on save.

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
