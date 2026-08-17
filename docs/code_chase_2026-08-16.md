> **SUPERSEDED 2026-08-16 — historical record only. Do not act on this file.**
>
> Every task in this brief is closed. The outcomes, including where this brief
> was WRONG, are in `docs/corrections.md` items 39-47 and the trace files it
> names. Live work is in **`docs/open-holes.md`**.
>
> Specifically wrong here, corrected later:
> * TASK 1's premise that `0xAD258` is a "WOT enrichment factor" — it is a 1-D
>   uint16 table on a COOLANT axis, not on the IPW path, and clamped to
>   `[0,0]` (item 42).
> * TASK 2's INFERRED bilinear FLKC model — the grid is **bucketed** 7x5=35;
>   write and read each touch exactly ONE cell, so the "mid-load event taxes the
>   boost cells" mechanism does not exist (item 41).
> * TASK 2's reading of the 8-14 traversal test — 59 of 64 FLKC changes were
>   **in-cell learning**, not lookups of a pre-learned map (item 50).
> * The 20-byte descriptor "stride" reading is off by one field; what it calls
>   `pad` is the previous record's BIAS (item 39).

# Code-chase brief — disassembly tasks, 2026-08-16

**Repo:** `C:\Users\Dean\Documents\GitHub\ae6l600l`
**Reference bin for every byte claim below:** `rom/AE5L600L 20g rev 20.19c.bin`, md5 `92cae8275cd4f9b473a3a9e36efe6449`
**Verify the md5 before trusting any address in this doc.** Dean rebuilds bins in place; a filename-matched changeset has lied four times on this project.

## House rules for whoever works this

Every substantive statement you produce is tagged with one of three tiers, and the tier is stated:

- **VERIFIED** — cited. `file:line` for derived claims, `address: bytes -> mnemonic` for binary claims. Open the file and confirm. No inference from memory or from generic SH7058 patterns.
- **INFERRED** — state the reasoning chain and name its weakest link.
- **HUNCH** — confidence as a number, what triggered it, and the cheapest test that would settle it.

If a file or channel you need isn't present, say so and stop. Don't guess.

Three of our own artifacts already disagree with each other on Task 1 (see below). When artifacts conflict, **the ROM bytes win** and the conflict gets written down, not silently resolved.

Write findings to `disassembly/analysis/<topic>_trace.txt` following the existing house style in that folder (see `transient_knock_window_trace.txt` for the format we like).

---

## TASK 1 — `0xAD258`: identify it, decode it, and settle whether it is the "WOT enrichment factor" at all

**Priority: highest.** This is the named blocker on injector sizing. Findings below suggest the premise may be wrong, which is worth more than a clean extraction.

### Why we care

Per `disassembly/analysis/fueling_pipeline_analysis.txt`, injected pulse width is multiplicative:

```
FR8 = enrichA + enrichB + enrichC
FR8 *= base_factor            # airmass / target AFR, scaled by MAF g/s
FR9 = AFL_multiplier * FR8
```

At WOT, commanded FFB sits ~0.8 AFR below the OL map (map 11.0, FFB reads ~10.2). Injector sizing has to be done against delivered FFB, not the map, so we need every multiplier in the stack accounted for. `0xAD258` was logged in project memory as the last unextracted term and therefore the next lever. **That framing now looks wrong — see below.**

### What I already verified (2026-08-16, from the 19c bin)

**Descriptor record.** Reading 20 bytes from `0xAD254`:

| addr | word | reading |
|---|---|---|
| `0xAD254` | `0x00000000` | pad |
| `0xAD258` | `0x00100800` | count = `0x0010` = **16**, flags `0x0800` |
| `0xAD25C` | `0x000CC664` | **axis pointer** |
| `0xAD260` | `0x000CE946` | **data pointer** |
| `0xAD264` | `0x3A000000` | **scale float = 0.00048828125 = 1/2048** |

The same 20-byte stride repeats cleanly at `0xAD268` (`0x00100800`, axis `0xCE968`, data `0xCE9A8`, scale `0x3AFA00FA`) and `0xAD27C` (`0x00100800`, axis `0xCC700`, data `0xCE9C8`, scale `0x3E480000`), so the record layout is `[pad][count|flags][axis][data][scale]`.

**Axis @ `0xCC664`** — 16 × big-endian float32:

```
-40, -30, -20, -10, 0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110
```

That is a **temperature axis in °C**, not RPM and not load.

**Data @ `0xCE946`** — 16 × uint16:

```
2048 × 16     ->  × 1/2048  ->  1.0000, flat across the entire axis
```

**Lookup site.** `disassembly/analysis/disasm_3952C_annotated.txt:204-205`:

```
39598:  D470    mov.l  @(0x3975C,PC),R4    ; R4 = 0x000AD258 (table descriptor)
3959A:  D271    mov.l  @(0x39760,PC),R2    ; R2 = 0x000BE830 (table_lookup func)
3959C:  420B    jsr    @R2
3959E:  F4FC    fmov   FR15,FR4            ; delay slot: FR4 = FR15 = float[0xFFFF6354]
```

Single-argument lookup — one float in, one float out. Consistent with 1-D, inconsistent with 2-D.

Result lands in `float[0xFFFF7BC0]`, then at `0x395B6`:

```
FR4 = (ratio - 1.0) * table_result
```

So the table is a **gain on a ratio deviation**, and at 1.0 it is a pass-through.

### The conflict — three of our artifacts disagree

| artifact | claim |
|---|---|
| `disassembly/analysis/fueling_pipeline_analysis.txt:60` | `0x39528  WOT enrichment factor (2D map 0xAD258)` |
| `disassembly/analysis/fueling_pipeline_analysis.txt:426` | `2D map descriptor 0xAD258 (RPM × load)` |
| `disassembly/maps/descriptor_map.txt:422` | `0x0AD258  1D  16  uint8  0.000488  axis 0x0CC664  data 0x0CE946  [-40.0..110.0]` |
| `disassembly/maps/descriptor_labels.txt:168` | labelled `desc_1D_ECT_u8_16_AD258` |
| `disassembly/maps/desc_func_xref.txt:279` | `0xAD258  invalid` |

The bytes side with the descriptor parser on shape (1-D, 16, temperature axis) and against it on width (**uint16, not uint8** — 16 uint8 at `0xCE946` reads `[8,0,8,0,…]`, which is the uint16 `2048` misread a byte at a time).

### Also unresolved: what `0xFFFF6354` actually is

`disassembly/maps/ram_reference.txt:139` names it `ect_raw_adc` (69 refs). But `disassembly/analysis/diag_tasks_analysis.txt:123` and `disassembly/analysis/disasm_3162C_annotated.txt:254` both call `0xFFFF6354` **vehicle speed**. Those cannot both be right, and the answer changes what this table is:

- temperature → a warmup/thermal multiplier
- speed → something else entirely, and the "enrichment" label is doubly wrong

The −40..110 axis argues temperature, but that is inference, not proof. `disasm_3162C_annotated.txt` describes `0xFFFF6354` as an *input to* a speed computation, which may be where the speed label leaked in.

### Deliverables

1. **VERIFIED identity of `0xAD258`** — shape, element width, scale, axis channel, decoded 16 values in the 19c bin. State whether `descriptor_map.txt`'s uint8 width is a parser bug; if so, say how many other rows in that file inherit it (a systematic width error would poison every uint16 table we've read from that artifact).
2. **VERIFIED identity of `0xFFFF6354`** — ECT or vehicle speed. Resolve against the ADC pipeline (`adc_pipeline_trace.txt`) and the writers, not against the existing labels. Correct whichever artifact is wrong.
3. **VERIFIED role of `func_3952C`** — what does this function compute, what consumes `float[0xFFFF7BC0]`, and is it on the fuel path at all? Specifically: does it feed `enrichA` (`0xFFFF76D4`, main IPW calc `0x38158`) as `fueling_pipeline_analysis.txt` claims? Trace the consumer, don't assume it.
4. **The verdict we actually need:** with the table flat at 1.0 across every axis point, does `0xAD258` contribute **anything** to commanded fuel on this cal? If the answer is "it multiplies a deviation term that is itself zero in steady state," say so plainly — that closes the lever and redirects the FFB-below-map hunt.
5. **If it closes, name the next candidate.** The remaining unaccounted multipliers in `fueling_pipeline_analysis.txt` are the **1.05 baseline enrichment at `0x399EE` → `0xFFFF7BDC`** and the **correction aggregator clamp `[0.75, 1.25]` at `0x33460`**. A steady ~0.8 AFR gap on an 11.0 command is ~7%, which the 1.05 baseline alone does not cover — so either there is a term we have not found, or the gap is not command-side at all and is a MAF/injector-model problem. Say which way the code points.

### Do not

- Do not propose ROM edits. This is an identification task. Any edit proposal gets decided separately against logs.
- Do not "fix" the descriptor artifacts by editing them to match a guess. Correct them only with byte-level citations.

---

## TASK 2 — FLKC learning grid: bilinear or nearest-cell? (gates flashing 20.19d)

**Priority: high, and it is time-sensitive** — there is a built-but-unflashed `20.19d` whose entire justification rests on the answer.

### Context

`20.19d` (md5 `ace1a5f86670ae120eda8925c162cf41`, built 2026-08-16 16:28 EDT, **untracked in git**) differs from 19c by exactly 15 bytes:

- `0xD2F28-0xD2F35` — **Fine Correction Columns (Load)**, the FLKC learning-grid load axis. Def name confirmed at `definitions/AE5L600L 2013 USDM Impreza WRX MT.xml:665`, `address="d2f28"`. Decode: `0.75 / 1.10 / 1.50 / 2.00` → `1.30 / 1.65 / 2.40 / 3.50`
- `0xFFB88` checksum

Nothing else moved. Boost, WGDC, turbo dynamics, all four base timing tables, KCA, MAF, load comp, AVCS, every FBKC/FLKC scalar, both knock windows — byte-identical to 19c.

### The claim that needs proving

On the 8-14 log, a mid-load ghost knock event around load ~1.5 produced an FLKC map that read back **−0.25 to −1.00 across rpm 2500-5000 × load 1.25-3.0**, densest at 3000-3500 × 1.5-2.0 and 4000-4500 × 2.0-3.0. All 33 step-downs passed the traversal test (0.25 steps in consecutive 40 ms samples) = lookups of a pre-learned map, not in-drive learning.

**My INFERRED explanation, which is what needs checking:** under the old axis, a learned correction near load 1.5-1.8 writes into columns 3 (1.50) and 4 (2.00), and every readback from load 2.00 up to the range ceiling of 3.45 clamps to column 4 — so a mid-load event taxes the boost cells. Under 19d's axis the same event writes into columns 1 (1.30) and 2 (1.65) and never reaches the 2.40/3.50 columns.

**Weakest link, stated:** I am assuming the write and the read are both bilinear over the row/column axes. I have not read the FLKC store routine. If the write is nearest-cell, or if the read clamps differently than I think, the 19d edit may do much less than advertised — or something different from what was intended.

### Relevant addresses (all VERIFIED from the 19c bin, 2026-08-16)

| param | addr | 19c value |
|---|---|---|
| Fine Correction Rows (RPM) | `0xD2F0C` | 1600 / 2200 / 2800 / 3400 / 4000 / 4600 |
| Fine Correction Columns (Load) | `0xD2F28` | 0.75 / 1.10 / 1.50 / 2.00 |
| Fine Correction Range (RPM) | `0xD2F6C` | 1500 / 1600 / 6300 / 6400 |
| Fine Correction Range (Load) | `0xD2F7C` | 1.25 / 1.30 / 3.45 / 3.50 |
| Fine Correction Retard Value | `0xD2F50` | −1.01 |
| Fine Correction Retard Limit | `0xD2F4C` | −15.00 |
| Fine Correction Advance Value | `0xD2F48` | 0.25 |
| Fine Correction Advance Limit | `0xD2F44` | 8 |
| FLKC Advance Delay | `0xD29EE` | 90 |

Def names for the first four confirmed at `definitions/AE5L600L 2013 USDM Impreza WRX MT.xml` lines 656-666.

Starting points: `disassembly/analysis/knock_flkc_analysis.txt` (2748 lines), `knock_flkc_report.txt` (605), `fbkc_path_trace.txt` (66), `reference_knock_cascade` notes in `docs/`.

### Deliverables

1. **VERIFIED: the FLKC store path.** When a knock event commits a correction, which grid cells receive it — one cell, two, or four — and with what weighting? Cite the routine and the instructions.
2. **VERIFIED: the FLKC read path.** On lookup at an arbitrary rpm/load, does the ECU interpolate between adjacent grid points, or take nearest, or clamp? What happens **outside** the grid — above the top column (2.00 in 19c, 3.50 in 19d) and below the bottom one, and is out-of-grid behaviour clamp-to-edge or zero?
3. **The answer to the actual question:** does re-spacing the load axis from `0.75/1.10/1.50/2.00` to `1.30/1.65/2.40/3.50` narrow the readback footprint of a load-1.5 event, or not? Yes/no with the code behind it.
4. **Check for a trap.** The old grid put two of four columns below the `1.25/1.30` enable gate, i.e. dead. Confirm from code that cells below the gate genuinely cannot be written **and** cannot be read — if they can be *read* while un-writable, the 19d change alters more than the resolution story suggests.
5. **RPM axis, secondary.** Rows top out at 4600 against a range ceiling of 6300 — everything 4600-6300 shares one row. Same structural issue as the load axis had. Note whether it is real; do not propose an edit. We have no top-end knock in the corpus to justify one yet.

---

## TASK 3 — `KNOCK_FLAG`: establish the channel's semantics or retire it

**Priority: medium. Cheap, and it removes a channel we currently can't use.**

### Context

`KNOCK_FLAG` is column 34 of the combined log (`logs/8-14 weekend 20.19c/8-14 weekend 20.19c.csv`). On 8-14 it read 1 for 175 samples, concentrated at rpm median 1999 × load median 0.44, only 2 of which coincided with `FBKC < 0`, and **zero** within ±60 samples of the deepest FBKC event of the log. Until someone traces it, it is barred from use as a knock witness.

### Blocker to clear first

`logs/logcfg.txt` in the repo **does not define a `KNOCK_FLAG` param.** It ends at `Misfire1-4` (`0x0000CE / CF / D8 / D9`), none of which appear in the log header. So the repo's logcfg is **stale relative to the config that actually produced the 8-14 log** — consistent with the noted "8-4 = cadence-era boundary" logger change.

**Action for Dean, not for Claude Code:** pull the current `logcfg.txt` off the SD card and drop it in `logs/`. Without it the paramid behind `KNOCK_FLAG` is unknown and this task cannot start.

### Deliverables (once the current logcfg exists)

1. **VERIFIED: the paramid / RAM address** behind `KNOCK_FLAG`, from the live logcfg.
2. **VERIFIED: the writer.** Which routine sets that address, under what condition, and with what clear condition. Is it a knock-sensor-domain flag, a diagnostic/DTC flag, a roughness-monitor artifact, or something unrelated?
3. **The verdict:** usable as a knock witness, usable as something else and worth logging under a corrected name, or noise to drop from the logger config. If it is a raw-sensor or pre-gate signal, say where in the cascade it sits relative to FBKC — a pre-gate flag firing where FBKC doesn't would be genuinely useful, and would explain the 1999 × 0.44 concentration.

---

## Housekeeping (small, do alongside)

- `rom/AE5L600L 20g rev 20.19d.bin` is **untracked and not gitignored**. Add it, and add `20.19d` to `scripts/analysis/rev_order.py:21` (the list currently ends at `"20.19c"`). It is absent from `logs/rom_rev_map.csv` and `logs/REVIEW_LOG.md` too — a stub row in each is enough until it's driven.
- Working tree has ~30+ modified files under `scripts/analysis/trends/` plus both dashboards, uncommitted. Commit before starting so the code-chase diff is legible.
- `tune_progress.py`'s curated LEDGER still marks open issue #2 as closed. It isn't.
- Do **not** run `log_review_ingest --all` over the device bridge — 45 s hard kill, no background survival, produces truncated CSVs. Per-log `--log` runs only.

---

## What is explicitly out of scope

- **Any MAF change.** The light-load lean has no established driver (charge-temp hunch is down to ~40% after 8-14), a legitimate fix is a region refit rather than cell patches, and the planned injector swap forces a full rescale anyway. Anything done now gets thrown away.
- **Any timing table edit.** Whole-map and mid-torque timing adds are declined and stay declined.
- **Chasing the 8-14 −4.20 FBKC event.** Settled as shallow-tier ghost knock: incidence flat (Fisher p=0.63 vs 7-19), no discriminator separates the knocking pass from 51 clean ones in the same log, and the load bin fires on 16 of 19 revs including `garn_base`. It is a non-event. The consequence — FLKC banking above the gate — is Task 2.
