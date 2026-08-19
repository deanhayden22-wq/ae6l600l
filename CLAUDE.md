# AE5L600L ROM Analysis

## CPU architecture — read this before touching ROM code

**Renesas SH7058 = SH-2E core, big-endian.** SH-2E is the classic SH-2 integer
ISA **plus a single-precision FPU**. Not plain SH-2 (no FPU). Not SH-2A.

About 10% of all instructions in this ROM are FPU instructions (~27,000 sites).
A decoder without FPU support does not error out — it **silently stops**. That
failure mode has already cost this project real time, so:

- **Ghidra language: `SuperH:BE:32:SH-2A`** (the only FPU-capable SuperH language
  in Ghidra 12). Never `SH-2` — it has zero FPU support.
- **Canonical decoder: `scripts/sh2e_disasm.py`.** The ~27 older per-script
  decoders in `scripts/disasm/` are independent copies; usable, not authoritative.
- Full detail and evidence: **[`docs/architecture.md`](docs/architecture.md)**.

### Instructions the SH7058 cannot execute

`FSQRT`, `FSCHG`, `FRCHG`, any double-precision op, `MOVI20`, `MOVU`, any SH-2A
32-bit instruction.

If one appears in a listing, **you are decoding data as code**. That is a region
boundary error, not a discovery. Do not build an explanation on top of it.

## Rules for answering questions about ROM code

These exist because confident-but-wrong answers have been produced here before.

1. **Verify against ROM bytes.** `disassembly/maps/disassembly.txt`, the Ghidra
   export XML, and the `analysis/*.txt` files are all *derived products*. Decode
   the actual bytes with `scripts/sh2e_disasm.py` before making a claim about
   control flow, function boundaries, or semantics. To check a whole file:

   ```
   python scripts/verify_disasm_v2.py disassembly/analysis/<file>.txt
   ```

   Both gates at once (Windows PowerShell 5.1 has no `&&`, so use the wrapper):

   ```
   .\scripts\check.ps1
   ```

   Current baseline: **99.87% of 22,487 lines match; 0 known errors**
   (`disassembly/verification_report_v2.txt`). The 29 remaining mismatches are
   28 deliberate symbolic labels plus one self-correcting reasoning passage.
   Keep it that way — re-run the verifier after editing any analysis file.
   Do **not** use `scripts/verify_disassembly.py` — it is deprecated and was
   structurally blind to every bug class actually present here.
2. **A short function is suspicious.** If a function "ends" and the next word
   starts with `0xF`, that is FPU truncation from the old SH-2 import, not a
   short function.
3. **"This region is data / unanalyzable" is suspect** when it traces back to the
   old Ghidra view. That conclusion was frequently a failed FPU decode.
4. **Don't trust a derived file's header.** `disassembly.txt` stated the RAM range
   as `0xFFFF8000-0xFFFFFFFF (32KB)` for months. It is actually
   `0xFFFF0000-0xFFFFBFFF (48KB)` — and the wrong version excludes the RAM
   addresses this project logs (`FFFF6624` RPM, `FFFF6350` ECT, `FFFF63F8` load).
5. **Check for stale shadow copies — but check which copy is actually right.**
   `~/ghidra_scripts/ImportAE5L600L.java` shadowed the repo copy (Ghidra's default
   script path wins over `-scriptPath`). It was assumed stale and overwritten from
   the repo — but it was **correct** about `FFFF65FC` (vehicle speed) and
   `FFFF63F8` (engine load), and the repo copy was wrong on both. "Differs from
   the repo" is not "wrong". See `docs/corrections.md` items 6 and 9.
6. **State your evidence.** Cite `file:line` for derived claims and
   `address: bytes -> mnemonic` for binary claims. If you did not verify it,
   say so rather than presenting it as established.
7. **Check operands, not just mnemonics.** The known errors in this repo are
   almost all operand-level: wrong displacement field width, wrong register
   field, missing `& ~3` on PC-relative targets, inverted `fmov.s` direction.
   A mnemonic-only comparison passes all of them.

### Open work

**[`docs/open-holes.md`](docs/open-holes.md)** is the live worklist — four scoped,
unblocked items (items 1 and 2 both closed 2026-08-18), each with what is known,
what is not, and the concrete next move. Read it before picking up anything, and update it when you close one.

### Corrections history

**[`docs/corrections.md`](docs/corrections.md)** records every verified error and
its status. Two worth carrying in your head:

- **`0xBE960` is `float_MAX`; `0xBE970` is `float_MIN`.** Swept and fixed
  2026-07-26. They were swapped consistently across ~25 files because a 2026-04
  "correction" reversed the `FCMP/GT` operand order and went the wrong way. If
  you see a claim that BE960 is min, it predates the fix.
- **Operand-level errors are the failure mode here**, not mnemonics. 415 were
  found and fixed on 2026-07-26 — including a knock call graph that was wrong at
  95 sites because every `jsr` decoded as `jsr @r0`.
- **Four core RAM identities were wrong and are now fixed** (item 9):
  `FFFF63F8` = **engine load** (was `iat_current`), `FFFF65FC` = **vehicle speed
  km/h** (was `engine_load_current`), `FFFF620C` = **manifold pressure** (was
  `airflow_maf_current`), `FFFF61CC` = **diag status bytes** (was `vehicle_speed`).
  Settled by tracing each RAM variable to the lookup axis it feeds and reading
  the axis name out of the definition XMLs.
- **A further 17 RAM identities corrected** (items 10-26), including two straight
  swaps: `FFFF4130` is **battery voltage** (was `atm_pressure_baro`) while
  `FFFF6C48` — labelled `battery_voltage` — is a **byte status code**.
  **IAT is `FFFF6364`** (was `ect_startup`); the earlier item-9 claim that IAT
  was `FFFF69F0` is **RETRACTED** — `FFFF69F0` reaches zero named axes.
  Several "sensors" are diagnostic plumbing read only as bytes: `FFFF67EC` is a
  uint16 DTC counter, `FFFF65C0` a precondition flag. Real throttle is
  `FFFF62DC` (plate) and `FFFF64D8` (**pedal**, not throttle_raw).
- **The cruise/non-cruise blend ratio is `0xFFFF90A8`, not `0xFFFF7F60`**
  (item 38). The decision is the `0x60ECC`–`0x6114E` chain calibrated at
  `0xD9AC4`–`0xD9E26`, **not** tasks 50/32/31/33 and **not** the `0xD29AC` /
  `0xD2A08` constants. All 48 `Map Switching *` definition names are
  project-invented (zero hits in `32BITBASE.xml`) and none of them gates
  cruise — treat that whole category as unverified naming.

## Definitions are primary ground truth — and check the flag before trusting an area

### The definition XMLs outrank the disassembly layer on identity and units

Two files, and you need **both** — they are split on purpose:

- `definitions/32BITBASE.xml` — abstract. Category, `<description>`, **axis names**,
  scaling refs. No addresses; it describes every Subaru 32-bit ROM.
- `definitions/AE5L600L 2013 USDM Impreza WRX MT.xml` — concrete. Same names plus
  `address=` for *this* ROM. Declares `<include>32BITBASE</include>`, which binds
  **by table name**. Anything the project states wins; anything it omits is
  inherited. `elements=` from the project **overrides** the base — the base counts
  are generic and wrong for this ROM in both directions.

Do not parse them by hand. **`scripts/defs.py` is the canonical loader** and
already resolves inheritance, scalings and geometry:

```python
import sys; sys.path.insert(0, "scripts")
import defs
d = defs.load()
t = d.get("Target Boost_"); t.read(rom)        # DISPLAY values, toexpr applied
```

Always resolve `toexpr`: **88 of the 135 referenced scalings store something other
than what they display.** `LCSPEED(MPH)` is `x*.621`, so the raw value is km/h;
`CoolantTemp(DegreesF)` is `(x*1.8)+32`, so the raw ECT axis is Celsius.

The axis names are the single most under-used asset in the repo. They are what
lets a RAM address be tied to a physical quantity **mechanically**: descriptor
axis pointer → definition axis name → the RAM variable traced feeding it. That
method is what identified `0xFFFF63F8`, and it would have prevented corrections
#6 and #8 from ever being applied backwards.

### Do NOT edit the definition XMLs in the repo

ECUFlash owns these files. Its definition directory is recorded in
`HKCU:\Software\OpenECU\EcuFlash\files` → *metadata directory* (currently
under `Program Files`), and it **rewrites the whole project XML on save**. A
repo-side edit is therefore lost the next time ECUFlash saves, and the two
copies diverge silently while each looks correct on its own — the same failure
class as every correction in `docs/corrections.md`.

- **Make definition changes in the ECUFlash UI**, then bring them back with
  `.\scripts\sync_defs.ps1 -Pull`.
- `.\scripts\sync_defs.ps1` on its own reports divergence and changes nothing.
- Repo and ECUFlash have been out of sync since 2026-04-07; the repo carries
  ~37 tables ECUFlash does not (post-transient knock window defs, the fuel-pump
  duty split). A blind `-Pull` deletes them. Check before syncing either way.
- Analysis tooling reads the **repo** copy via `scripts/defs.py`.

### Check the flag before building on an area

Every addressed table, every addressed axis, every descriptor-backed calibration
block and every RAM variable carries exactly one flag in
**[`docs/verification-status.md`](docs/verification-status.md)** (human) and
`docs/verification-status.json` (machine, one record per entity, look up by
`entities[].address`).

| Flag | What you may do with it |
|---|---|
| `VERIFIED-BOTH` | Reason from it, including about **identity**. Definition and re-derived ROM-code evidence agree. |
| `VERIFIED-BYTES` | Reason about **contents only, never meaning**. Nothing corroborates the identity; a `0xC0BCC`-class error would not have been caught. |
| `BOUNDS-SUSPECT` | The value is right, the editor's declared min/max is not. Never conclude a value is out of spec because a tool clamped it. |
| `CONFLICT` | **Stop.** Two independent sides disagree. Settle it from ROM bytes, record it in `docs/corrections.md`, then continue. |
| `DEFS-ONLY` / `DISASM-ONLY` / `UNMAPPED` | No cross-check exists. Say so in whatever you write (rule 6 above). |

Current state, regenerated 2026-08-18 (4,720 entities): **360 VERIFIED-BOTH,
266 VERIFIED-BYTES, 2 CONFLICT, 52 BOUNDS-SUSPECT, 6 DEFS-ONLY, 956
DISASM-ONLY, 3,078 UNMAPPED**, and **79.4% of data-classified ROM bytes are
claimed by neither side.** Only ~13% is verified at all. Most of this ROM is
not verified. Treat an unflagged or `UNMAPPED` area as unknown, not as safe.

> The totals moved on 2026-08-16 (was 4,725 / 351 / 293 / 53 / 21) because the
> descriptor census itself changed — see the note below. Fewer VERIFIED-BOTH is
> not a regression in knowledge; the corrected extents changed which definition
> tables corroborate which descriptors.

The 2 CONFLICTs are `0xC0BCC` and `0xD6214`, both **definition-XML storagetype**
errors where the ROM code is right — settled from bytes in `docs/corrections.md`
item 51. `0xC0BCC` reads **1.7** as a float while the editor displays 1.00, so
any reasoning that used "boost disable during fuel cut = 1.00 load" used a wrong
number. Fixing them means editing in the ECUFlash UI, not the repo copy.

> A flag of `VERIFIED-BOTH` covers the *definition vs. ROM-code* cross-check.
> It does **not** mean the table's NAME is right. `0xD39A8` was a well-formed
> entity whose name, axis units and data scaling were all wrong for this ROM —
> caught only by decoding its single consumer. See `docs/corrections.md` item 36.

### Regenerate it — never hand-edit it

```
python scripts/coverage_map.py            # rewrites both files from scratch
python scripts/coverage_map.py --check    # exits 1 if the on-disk copy is stale
```

It re-derives the code side from ROM bytes on every run (literal-pool dereference
back-trace, table descriptors decoded out of ROM, RAM→lookup-axis feed trace) and
treats `ram_reference.txt`, `descriptor_map.txt`, `cal_crossref.txt` and
`analysis/*.txt` as **claims to be tested, never as evidence**. Re-run it after
editing a definition XML, after a new tune rev, and after any correction.

> **Descriptor typecodes — fixed 2026-08-16, see `docs/corrections.md` item 39.**
> The single source of truth is now **`scripts/desc_types.py`**. Import it; never
> re-declare the map (it had been copy-pasted into five scripts and all five
> carried a guess).
>
> ```
> 0x00 -> float32, 4 B    0x04 -> uint8,  1 B    0x08 -> uint16, 2 B
> 0x0C -> int8,    1 B    0x10 -> int16,  2 B
> ```
>
> Decoded from the dispatch table of longs at `0xBE860` (handlers `0xBEACC` /
> `0xBEB20` / `0xBEB6C` / `0xBEAE4` / `0xBEB00`). Because it is indexed by the
> raw byte into a table of longs, the typecode is **always a multiple of 4** —
> `0x02` and `0x0A` are structurally impossible. Typecode lives at record `+2`
> for 1-D and `+16` for 2-D.
>
> The earlier note here said the `Type` column was "1-byte and 2-byte
> **inverted**". That was wrong in three ways: it is a *shifted* mapping, not an
> inversion; signedness was also wrong on all 215 rows labelled `int16` (they
> are unsigned bytes); and typecodes `0x0C`/`0x10` were dropped entirely.
> **611 of 760 descriptors had the wrong cell width**, hence the wrong extent.
>
> **As of 2026-08-16 `descriptor_map.txt`, `descriptor_labels.txt`,
> `named_descriptors.txt`, `desc_func_xref.txt` and the `desc_*` labels in
> `ImportAE5L600L.java` have all been regenerated or rewritten correctly.**
> Anything that read a cell width or table extent out of those files **before**
> that date is still suspect. They remain derived products — rule 1 still applies.
>
> **The census also changed: 760 → 1,094 descriptors** (1-D 851, 2-D 243;
> float32 326, uint8 287, uint16 481). The old scanner missed a third of them
> for three separate reasons, all fixed — see `docs/corrections.md` item 60.
> `ImportAE5L600L.java` now labels all 1,094, one symbol per address.
>
> ### Two traps that have each cost this project a wrong conclusion
>
> **1. Typecode `0x00` (float32) has NO scale/bias.** `table_lookup` skips them
> (`0BE84A tst r3,r3 / bt`), and the record's scale/bias fields hold unrelated
> bytes — all 326 float32 descriptors have an implausible value sitting there.
> Applying it silently collapses a table to ~0. That is how the AVCS VVT-error
> feedback surface got recorded as "zeroed" when it is populated
> (−10.55…+4.69, item 67), and how the knock threshold tables got called
> "all zero" when they hold 3.45–3.60 (item 59).
> **Use `desc_types.read_table()`; never hand-roll `raw * scale + bias`.**
>
> **2. `sh2e_disasm` prints displacements ALREADY IN BYTES** — `mov.l r0,@(d8*4,gbr)`,
> `mov.w r0,@(d4*2,Rn)`. Multiplying by the operand size again puts `mov.w`
> targets 2× and `mov.l` targets 4× too far (item 61).

## Tools — check here before writing a new script

Built 2026-08-16 because each replaced an ad-hoc pass that had already produced a
wrong answer. Import them; do not re-derive.

| tool | use it for |
|---|---|
| `scripts/desc_types.py` | **The** typecode map, plus `read_table()` / `scaling()` / `typecode()` / `is_2d()`. Single source of truth. Never re-declare the map — it was copy-pasted into five scripts and all five carried a guess. |
| `scripts/mapping/find_writers.py` | Find every WRITE to a RAM address. Handles direct, displacement, indexed `@(r0,Rn)` and GBR-relative forms, and tracks `r0` through `add`/`extu`. |
| `scripts/mapping/reconcile_ram_labels.py` | Harvest and rank conflicting RAM-address label claims across the artifacts. Reports; does not adjudicate. |
| `scripts/mapping/sync_import_java_labels.py` | Sync descriptor labels into `ImportAE5L600L.java`. Address-keyed, additive, idempotent. **Use this, not `update_import_java.py`** (insert-only, would duplicate every label). |
| `scripts/mapping/dedupe_import_java_labels.py` | Resolve addresses carrying two `desc_*` labels. |
| `scripts/analysis/flkc_cell_trace.py` | Replicate the FLKC band selector over a log and classify FLKC steps as cell traversal vs in-cell learning. |

### The method that actually settles things

Three of the four identity errors fixed this session were settled the same way,
after label-based reasoning had failed on all of them:

1. **Find the WRITER, not the readers.** `0xFFFF6354`, `0xFFFF4130` and
   `0xFFFF81BA` all had 100% reads in the literal pool. The writes were indexed
   stores off a neighbouring base, or GBR-relative. A literal-pool scan settles
   nothing on its own.
2. **Read the clamp/limit constants before calling anything a live lever.**
   `0xAD258` looked like a live fuel multiplier until its bound turned out to be
   `0.0` on both branches.
3. **Decode the consumer.** A claim that survives only because nobody decoded the
   consuming function is not verified, however many artifacts repeat it.

## Table data vs. code

Tune revs differ almost entirely in **calibration data** — stock → 20.19b is
12,084 differing bytes, of which all but 178 are tables. For code questions the
choice of rev is nearly irrelevant.

**Two exceptions — both are live code patches in every ROM flashed to the car:**

1. **`0x09A3C2`–`0x09A473` (178 bytes)** — the SSM read-addresses patch that makes
   extended datalogging possible. See [`docs/ssm-read-patch.md`](docs/ssm-read-patch.md).
2. **`0x0F1000`–`0x0F1057` (88 bytes)** — launch control / 2-step. Injected into
   the big ROM hole, reached by literal redirects at `0x03B79C`/`0x03B7A8`. When
   engine load is below ~8.05 it adds **2700 RPM** to the value the rev limiter
   compares, so the limiter trips at an actual **4000 RPM** instead of 6700.
   Side effect: the second rev-limit pair (`0xCC508`/`0xCC50C`) is now
   **unreachable** — edit `0xCC500` (cut) and `0xCC504` (resume).
   See [`docs/rev-limit-patch.md`](docs/rev-limit-patch.md).

> When diffing revs, do **not** filter to code-classified regions only. Injected
> code lives in `rom_hole` (0xFF) space by definition, and will be missed.

Note: `patches/` also contains prose about patch 2, but it is untrusted per the
rule below and is factually wrong about which address is which. Use
`docs/rev-limit-patch.md`.

## Do NOT reference

- `patches/` - Experimental patches with unverified addresses and logic.
- `merp mod/archive_v1/` - Archived MerpMod port (v1). Contains known errors. Do not use for reference.

## Verified directories

When analyzing the ROM, use content from:
- `disassembly/` - Verified disassembly work (primary reference)
- `definitions/` - Verified ROM definitions
- `rom/` - Stock ROM binaries
- `scripts/` - Analysis scripts
- `logs/` - Data logs
- `merp mod/` - Active MerpMod port (fresh files only, not archive)
- `docs/` - Subsystem notes, tune state, architecture reference
