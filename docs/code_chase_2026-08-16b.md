> **SUPERSEDED 2026-08-16 — historical record only. Do not act on this file.**
>
> Every FIX and DIG item here is closed. Outcomes in `docs/corrections.md`
> items 48-69. Live work is in **`docs/open-holes.md`**.
>
> Specifically wrong here, corrected later:
> * **D1**: it INFERRED `0xFFFF4130` is baro and named tracing the writer as its
>   weakest link. The weakest link broke — it is **battery voltage** (0..20 V
>   full scale at `0x005A56`); `corrections.md` item 10 was right all along and
>   `adc_pipeline_trace.txt` was the wrong artifact (item 45).
> * **D5**: "446 addresses with 2+ labels" is really **26** — 94% was regex
>   noise, including a `\s`-matches-newline bug that paired an address with the
>   NEXT line's label (item 66).
> * **D5's HUNCH** that `boost_control_analysis.txt` and `avcs_analysis.txt`
>   dominate the conflicts is **not supported**; `ignition_timing_analysis.txt`
>   leads with 9 of 26. The wholesale regeneration that hunch implied would have
>   been harmful — regenerating those files LOSES hand-added instruction decodes
>   the per-script decoders cannot reproduce (item 60).
> * **FIX 1's premise** that the three `trace_*.py` scripts generate the
>   `*_analysis.txt` files. They generate the `*_raw.txt` files; the analysis
>   prose is hand-authored downstream.

# Code-chase brief #2 — descriptor width bug cleanup + artifact reconciliation
**2026-08-16, follow-up to `docs/code_chase_2026-08-16.md`**

**Repo:** `C:\Users\Dean\Documents\GitHub\ae6l600l`
**Reference bin for every byte claim:** `rom/AE5L600L 20g rev 20.19c.bin`, md5 `92cae8275cd4f9b473a3a9e36efe6449`

House rules unchanged: VERIFIED (cited, `file:line` or `address: bytes -> mnemonic`) / INFERRED (chain stated, weakest link named) / HUNCH (confidence number + cheapest test). ROM bytes outrank every artifact. `disassembly/analysis/*.txt` and `disassembly/maps/*` are **claims to test, never evidence** — that rule is the whole point of this brief.

Prior work this builds on: `disassembly/analysis/ad258_wot_enrichment_trace.txt` (the 0xAD258 trace — correct, and its PART 3 audit is the starting point here).

---

## SCOPE NOTE — read this before panicking about "611 of 760"

The width bug does **not** touch the tuning path. Audited 2026-08-16:

- `scripts/defs.py:98-102` reads only `definitions/*.xml`. It has never read a descriptor artifact.
- **Zero** scripts in `scripts/analysis/` open `descriptor_map.txt`, `named_descriptors.txt`, `descriptor_labels.txt` or `desc_func_xref.txt`. (Five match the *word* "descriptor" in comments only.)
- **51 of 57** ROM addresses cited across project memory are defined in the XML (676 distinct XML addresses). Every table we have ever edited — MAF `d8c9c`, Target Boost `c1340`, WGDC `c1150`/`c0f58`, all four base timing tables, load comp `c3c3c`/`c3d3c`, the FBKC/FLKC scalar block, OL fueling, pedal/throttle — is XML-backed.
- Of the 6 unbacked: `cc4f0`/`cc4f4` are elements 2 and 3 of the XML table at `cc4ec` ("Overrun Fueling Cut Counter RPM Threshold", `definitions/AE5L600L 2013 USDM Impreza WRX MT.xml:1410`), so they are fine. `0xAD258` is closed. **The genuine unknowns are `0xAD7E0`, `0xCC51C`, `0xCC530`** — all three sourced from `fueling_pipeline_analysis.txt`, the artifact that got `0xAD258` wrong on four counts. Treat as UNVERIFIED.
- `scripts/coverage_map.py:365` already had the correct `_TYPECODE_WIDTH` and line 345 explicitly refuses `descriptor_map.txt` as evidence, so `docs/verification-status.json` was never poisoned.

So this is a cleanup job on the disassembly-side artifacts, not a re-litigation of the tune.

---

## FIX 1 — the corrected typecode map landed in ONE script. Four others still carry the old one.

`scripts/mapping/scan_descriptors.py` was corrected and `descriptor_map.txt` regenerated (2026-08-17 01:09 UTC). But the old map is a **copy-paste constant that lives in five places**, and four were missed:

| file | line | current (WRONG) |
|---|---|---|
| `scripts/mapping/name_descriptors.py` | 45-46 | `{0x00:"f32", 0x02:"i8", 0x04:"i16", 0x08:"u8", 0x0A:"u16"}` |
| `scripts/disasm/trace_avcs.py` | 44-45 | same |
| `scripts/disasm/trace_boost_control.py` | 50-51 | same |
| `scripts/disasm/trace_map_switching.py` | 566-567 | same |

Correct map, VERIFIED from the dispatch table of longs at `0xBE860` (handlers `0xBEACC`/`0xBEB20`/`0xBEB6C`/`0xBEAE4`/`0xBEB00`):

```
0x00 -> float32, 4 bytes
0x04 -> uint8,   1 byte
0x08 -> uint16,  2 bytes
0x0C -> int8,    1 byte   (SIGNED - was dropped entirely by the old map)
0x10 -> int16,   2 bytes  (SIGNED - was dropped entirely by the old map)
```

Note `coverage_map.py` expresses the same thing as a 16-bit read at +2 (`0x0000/0x0400/0x0800/0x0C00/0x1000`) — equivalent, just word-vs-byte. Pick one convention and factor this constant into a single shared module so it cannot drift a sixth time.

### Why this one matters more than the Ghidra labels

Those three `trace_*.py` scripts generated **`avcs_analysis.txt`, `boost_control_analysis.txt`, and `map_switching_analysis.txt`** — three of the most-cited artifacts in the project, covering two areas we have actively tuned. Every cell width, table extent and decoded value in them is suspect.

**Deliverable:** fix all four, regenerate the three analysis files plus `named_descriptors.txt`, and **diff old vs new**. Report specifically which tables changed extent or value, because that is the list of conclusions that may need revisiting. Do not silently overwrite — the diff *is* the finding.

## FIX 2 — the label chain into Ghidra is still on the bad widths

`name_descriptors.py` (old map) → `named_descriptors.txt` (stale, Apr 1) → `gen_descriptor_labels.py:14,37` → `descriptor_labels.txt` (stale, Apr 3) → `update_import_java.py:18,190` → `disassembly/ghidra/ImportAE5L600L.java`.

VERIFIED by counting the labels in the java file:

```
760 desc_* labels total
149 _f32_   correct
215 _i16_   should be uint8   (wrong width AND wrong signedness)
396 _u8_    should be uint16  (half the real width)
  0 _u16_   though 396 descriptors are uint16
  0 _i8_
```

That independently reproduces the 611/760 figure from a second file. Every one of those wrong widths is currently sitting in the Ghidra symbol names, so any data type applied from them is wrong.

**Deliverable:** re-run the chain after FIX 1 and confirm the new counts are `149 _f32_ / 396 _u16_ / 215 _u8_` plus whatever `_i8_`/`_i16_` fall out of typecodes `0x0C`/`0x10`. Also regenerate `desc_func_xref.txt` (stale Apr 1 — it is the file that marks `0xAD258` "invalid", which the `0x039598` call site disproves).

## FIX 3 — two stale descriptions of the bug itself

- `CLAUDE.md:199-202` says the Type column "has 1-byte and 2-byte **inverted**." That is wrong in three ways: it is a *shifted* mapping, signedness is also wrong on all 215 `int16` rows, and typecodes `0x0C`/`0x10` were dropped entirely. Rewrite it, and add that `descriptor_map.txt` has now been regenerated correctly (so the warning needs a "as of" date, not deletion).
- `scripts/coverage_map.py:345-347` carries the same "INVERTED" characterization and a blanket "that file is therefore never used as evidence here." Now that `descriptor_map.txt` is regenerated, decide deliberately whether that exclusion still stands, and say why either way. Do **not** relax it just because the file was regenerated — its acceptance rule (`axis + count*4 == data`) is stricter and worth keeping independent.

---

## DIG — inconsistencies found while auditing. Each is a task, ranked.

### D1 — `0xFFFF4130` has THREE conflicting identities, and one of them is in a file written tonight

| artifact | claim |
|---|---|
| `disassembly/analysis/adc_pipeline_trace.txt:15` | ADDR 4: `raw=0xFFFF402C  filt=0xFFFF4134  out=0xFFFF4130` → **Atmospheric Pressure (Baro)** |
| `disassembly/analysis/fueling_pipeline_analysis.txt` | `atm_pressure_baro` — **agrees** |
| `disassembly/analysis/boost_control_analysis.txt:190` and `:330` | `ignition_switch_state`, "float, Ignition switch" |
| `disassembly/analysis/boost_control_raw.txt:209,274,789,867` | `ignition_switch_state`, refs at `0x0549D6`, `0x054828` |
| `disassembly/analysis/ad258_wot_enrichment_trace.txt:178` | "same block as FFFF4130 **battery voltage**" |

**INFERRED (weakest link: I have not traced the writer):** baro is right. The ADC pipeline trace derives it structurally from the raw/filt/out triple rather than from a guess, and a boost-control routine reading barometric pressure makes sense where reading an ignition-switch state as a float does not.

This matters beyond bookkeeping: the `ad258` trace used "FFFF4144 sits in the same ADC block as FFFF4130 battery voltage" as one corroborating strand for `FFFF6354` = ECT. That strand is bad. **The ECT conclusion still holds** on the 70.0 °C failsafe constant plus the definition XML naming `cc664` "Coolant Temperature" — but the trace file should be corrected so a future session does not inherit the error as ground truth.

**Deliverable:** settle `0xFFFF4130` from the ADC writer (same method that settled `FFFF6354`: find the indexed store, not the literal-pool reads). Correct whichever files are wrong, including the new one.

### D2 — `0xFFFF798C` is used as a GBR base in one file and a scalar in another

- `disassembly/maps/ram_reference.txt:242,851,946` — `timing_state_var`, "17 refs. Timing state variable."
- `disassembly/analysis/cl_ol_analysis.txt:86,225,253` — `GBR = 0xFFFF798C (set at 0x03607E, 0x036856)`

If it is a GBR workspace base, then every `@(disp,GBR)` access in that workspace has been attributed to a scalar called `timing_state_var`, and the "17 refs" count is counting base loads. This also lands directly on the `0xAD258` work: `ad258_wot_enrichment_trace.txt` lists `FR12 = float[FFFF798C]` as an input to `func_3952C` with identity unresolved.

**Deliverable:** determine whether `0xFFFF798C` is a GBR base, a scalar, or both (a base can also be read as a float). If it is a base, audit `gbr_registry.txt` and `identify_gbr_workspaces.py` for how many other bases are double-listed as scalars in `ram_reference.txt`.

### D3 — 8 of 39 fuel-dispatch entries are `bra` trampolines, and slot B[8] does not go where the analysis says

Read directly from the 19c bin at `0x480B8` and `0x4A0B8`, decoding `bra` as `0xA000|disp12`:

```
A[13] 0x3756C -> 0x3757E
B[ 5] 0x3160A -> 0x3161E     "Major correction aggregator"
B[ 8] 0x39528 -> 0x39668     "WOT enrichment factor"
B[10] 0x36C3C -> 0x36C48     "CL/OL state cleanup"
B[11] 0x37B68 -> 0x37B74     "Injector compensation"
B[15] 0x3605E -> 0x3643A     "OL fuel map selector"
B[17] 0x3A222 -> 0x3A230     "Per-cylinder fuel trim"
```

The entry addresses in `fueling_pipeline_analysis.txt:50-72` all match the bin, so the *table* is right. But seven of those "functions" are two-instruction trampolines, and any analysis that read forward from the stub address rather than the branch target analysed the wrong bytes.

The sharp case: **slot B[8] dispatches to `0x39668`**, which `disasm_3952C_annotated.txt:14` calls "func_39668: Initialization/setup function." So the fuel pipeline's slot-8 call runs the init function — and **nothing in either dispatch table reaches `func_3952C`**, the function containing the `0xAD258` lookup. `ad258_wot_enrichment_trace.txt` notes `func_3952C` is reached by a `bra` at `0x039524` with no literal and no in-range `bsr`, i.e. its caller is unlocated.

**Deliverable:** (a) resolve each of the 8 stubs and state whether the existing analysis of that slot examined the stub or the target; (b) find what calls `0x039524`. `0x39524`/`0x39528` are a 4-byte-apart stub pair, so a computed or table-indexed jump one slot off is the obvious candidate — check for a second dispatch table or an indexed jump whose base lands on `0x39524`.

### D4 — the same function carries two different names in two artifacts

`0x37B68` is a `bra` to `0x37B74`, so they are one function. But:

- `fueling_pipeline_analysis.txt:61` B[11] → "**Injector compensation** (2D maps, RPM/load indexed)"
- `reference_fuel_formula` / the enrich-term breakdown → "enrichC (FFFF7AE4, **AFL application** `0x37B74`)"

One of those is wrong, or the function does both and neither description is complete. This is load-bearing: the multiplicative fuel model treats `enrichC` as the AFL trim product, and if `0x37B74` is actually injector compensation then the model's third term is mislabeled.

**Deliverable:** trace `0x37B74` and give it one name. Correct both artifacts and flag whether the `enrichC` = AFL claim in the fuel-formula model survives.

### D5 — the broad RAM-identity sweep (bigger job, do last)

Harvesting `FFFFxxxx <label>` associations across `disassembly/analysis/*.txt` + `disassembly/maps/*.txt` finds **446 RAM addresses carrying two or more distinct labels**, 390 of which differ on the first word. Most of that is prose noise from my crude regex, but D1 and D2 both came out of it, and these looked real on inspection:

| addr | conflicting claims |
|---|---|
| `FFFF6254` | `maf_current (u8)` (`avcs_analysis.txt`) vs "torque-related condition (byte)" (`accel_enrichment_analysis.txt`) |
| `FFFF65C0` | `throttle_position (u8)` (`boost_control_analysis.txt`, `diag_tasks_analysis.txt`) vs "engine running state" (`cl_ol_analysis.txt`) |
| `FFFF85D7` | `fuel_system_state` (`ignition_timing_analysis.txt`, `startup_enrichment_analysis.txt`) vs "warmup complete flag" (`dtc_diagnostics_analysis.txt`) |
| `FFFF4042` | filtered slot "addr29" (`adc_pipeline_trace.txt`) vs "raw MAF ADC uint16 (**addr15**)" (`merpmod_sd_port_analysis.txt`) — the ADC index disagrees too |
| `FFFF67EC` | `atm_pressure_current` (`avcs_analysis.txt`) vs a speed/counter compare (`clol_gap_closure.txt`, `cl_ol_master_analysis.txt`) |

**Deliverable:** a proper reconciliation pass — writer-based, not label-based, since D1 and the `FFFF6354` case both show the reads are what mislead. Produce a single reconciled `ram_reference.txt` and a list of artifacts corrected. Scope it: settle the ones that appear in fueling, boost, AVCS or knock analysis first; ignore the diagnostic/DTC tail unless it is cheap.

**Suspicion worth stating as HUNCH (~65%):** `boost_control_analysis.txt` and `avcs_analysis.txt` are disproportionately represented in the conflict list, and both were produced by scripts carrying the bad typecode map (FIX 1). If those two files were generated in an early, less careful pass, the right move may be regenerating them wholesale rather than patching labels. Cheapest test: after FIX 1, diff the regenerated `boost_control_analysis.txt` against the current one and see whether the label errors persist or fall out.

---

## Order of work

1. FIX 1 (four scripts + regenerate + **diff report**) — everything else reads cleaner afterward.
2. D3 and D4 — small, self-contained, and both touch the fuel model we are actively reasoning about.
3. FIX 2 + FIX 3 — mechanical.
4. D1, D2 — writer traces.
5. D5 — the sweep, last, informed by whatever FIX 1's diff reveals.

## Out of scope

No ROM edits. No tuning-table re-derivation — the XML path is clean and re-verifying it is wasted effort. Do not touch `logs/`, `scripts/analysis/trends/`, or either dashboard.

## Housekeeping still outstanding from brief #1

- `rom/AE5L600L 20g rev 20.19d.bin` untracked and not gitignored; absent from `scripts/analysis/rev_order.py:21`, `logs/rom_rev_map.csv`, `logs/REVIEW_LOG.md`.
- ~30 modified files under `scripts/analysis/trends/` plus both dashboards, uncommitted.
- `tune_progress.py`'s curated LEDGER still marks open issue #2 as closed.
