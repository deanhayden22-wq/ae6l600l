# Open holes — current as of 2026-08-16

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
| `0xFFFF64F5` | `boost_related_flag` (boost_control) vs `engine_state_byte` (ignition_timing) | UNMAPPED |
| `0xFFFF3234` | `flkc_work_bank1` (knock_flkc) vs `knock_learn_coarse` (ignition_timing) | UNMAPPED |
| `0xFFFF8258` | `knock_metric` (knock_flkc) vs `flkc_retard` (ignition_timing) | UNMAPPED |
| `0xFFFF7F68` | `ect_blend_correction` (fueling, startup) vs `blend_output` (ignition_timing) | DISASM-ONLY |
| `0xFFFF1288` | `inj_gate_hook_ptr` (fueling) vs `scheduler_state` (task_scheduler) | unflagged |
| `0xFFFF8F24` | `blend_state_b` (ignition_timing) vs `global_cl_enable` (startup_enrichment) | UNMAPPED |
| `0xFFFF895C` | `injector_data` (diag_tasks) vs `afl_value` (ignition_timing) | DISASM-ONLY |

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

## 2. Does `func_37B74`'s product term ever go non-zero?

`docs/corrections.md` item 64. The function computes

```
[0xFFFF7AB4] = clamp(1.0 + A*B*C*D, 0.5, 1.5)      bypass writes exactly 1.0
A = [0xFFFF7ABC]  B = [0xFFFF7AC0]  C = [0xFFFF7AC4]  D = [0xFFFF7AC8]
```

and its output is read by **`fuel_pw_calc`** at `0x0301FC` (24 bytes into the
pulse-width calculator) and by the AFL pipeline at `0x0347D4`. So it is a live
multiplicative fuel term — **if the product is non-zero.**

Known: all four inputs have real writers (`0x037DBE`, `0x037EB0`, `0x037BCC`,
`0x037BBC`), so the product is not structurally zero. But the two comps this
function itself contributes — `0xAC634` (RPM axis) and `0xAC648` (ECT axis) —
are **flat zero** on this calibration.

**Next move:** trace `0x037DBE` and `0x037EB0` (the writers of A and B, which
this function does not compute itself) and decide whether either can be non-zero.
If they cannot, the whole term collapses to 1.0 and the fuel model loses a
multiplier — same shape as the `0xAD258` result.

---

## 3. Does `[0xFFFF77D8] + [0xFFFF77DC]` ever go negative?

`docs/corrections.md` item 62. **This is a log question, not a disassembly one.**

Branch A of `func_3952C` computes
`clamp(1/(1 + [77DC] + [77D8]) − 1, 0.0, 0.03)`. The clamp floor is 0.0, so the
branch contributes **nothing unless that sum goes negative**, and is capped at 3%
even then. These two sit in the AFC/AFL trim-pair region.

Neither address has a locatable writer — `find_writers.py` covers four addressing
forms and finds none, which means the base is built by arithmetic or loaded from
memory. **Do not record them as read-only**; absence is not proof there.

The practical question is answerable from logged AFC/AFL rather than from code.

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
