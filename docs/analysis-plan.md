# Analysis game plan

Written 2026-08-19, after open-holes 1–7 closed and two slices of the
undefined-ROM programme. Grounded in measured hit rates from those slices, not
in what sounds productive.

Read with **[`open-holes.md`](open-holes.md)** (the live worklist) and the
"How much of this ROM is actually known" section of `CLAUDE.md` (the numbers).

---

# Part 1 — the function programme (written 2026-11-27)

The table programme below (Part 2) asks "what is this table". This part asks the
question it cannot: **which code has nobody read, and in what order should it be
read.** Everything here is measured by `scripts/mapping/function_census.py`
(corrections item 105). Re-run it; do not quote these numbers from memory.

## The denominator, by function

Measured 2026-11-27 after batch 1 and the tool corrections of item 106 (CFG call
resolution, delay-slot walk, data-seed rejection). Item 105's first figures were
5,151 functions / 572,310 bytes / 15,798 traced (5.5%).

```
functions                 5,146      245 labels now [DECODED]
instructions            286,163      = 572,326 bytes of code (NOT 444,928)
  traced, byte-verified  24,930      = 8.7%   (was 15,798 = 5.5% before batch 1)

functions >= 90% traced     541      (was 293)
functions partly traced     143
functions never touched   4,462      (was 4,797)
```

| region | functions | never touched | instructions | traced |
|---|---|---|---|---|
| `0x000000` | 881 | 796 | 26,582 | 6.5% |
| `0x010000` | 505 | 482 | 26,825 | 1.6% |
| `0x020000` | 505 | 425 | 27,750 | 4.1% |
| `0x030000` | 402 | 322 | 26,508 | **22.5%** |
| `0x040000` | 304 | 209 | 26,177 | **29.1%** |
| `0x050000` | 631 | 492 | 26,927 | 11.0% |
| `0x060000` | 369 | 315 | 22,906 | 8.0% |
| `0x070000` | 413 | 398 | 27,602 | 1.9% |
| `0x080000` | 492 | 479 | 27,583 | 0.6% |
| `0x090000` | 353 | 330 | 23,350 | 3.7% |
| `0x0A0000` | 180 | 176 | 17,389 | 0.8% |
| `0x0B0000` | 110 | 37 | 6,536 | **23.4%** |
| `0x0F0000` | 1 | 1 | 28 | 0.0% — the launch patch |

| function size | functions | share of code |
|---|---|---|
| 1–12 instructions | 1,646 | 3.5% |
| 13–40 | 1,660 | 13.9% |
| 41–150 | 1,423 | 38.7% |
| 151–500 | 378 | 32.0% |
| over 500 | 39 | 11.9% |

Two things follow. **A third of the functions are 3.5% of the code** — they get
classified by pattern, not read. And **416 functions hold 44% of the code** — they
get triaged before anyone commits to reading one.

## The unit of work is a function card, produced the same way every time

1. **Listing from the tool, never by hand.** `scripts/mapping/fn_dump.py 0xENTRY`
   prints the function in verifier format with every literal, pool word, resolved
   call target, GBR offset and descriptor geometry annotated from bytes. Blind by
   default; `--labels` adds existing names as claims. Every operand error in
   `corrections.md` came from a hand-made listing.
2. **Blind first.** The contract is worked out from bytes before any label, doc or
   analysis file about that address is opened. Comparison with existing claims is
   a separate, later step, and it reports both contradictions and confirmations.
3. **Emulate what is numeric.** `scripts/sh2e_emu.py`, script saved under
   `scripts/trace/emu_<target>.py`, grid includes the edges. A contract that was
   only read is weaker than one that was run.
4. **A second reader tries to break it.** Independently re-decodes, attacks each
   claim separately (operand order, T-bit sense, delay slots, signedness, resolved
   addresses, typecode), writes its own emulation with different inputs. It never
   edits the file.
5. **A third decode settles disagreements** and repairs the file. Neither earlier
   reader is presumed right.
6. **Gates:** `verify_disasm_v2.py` on the file, mismatch 0, against stock and the
   reference bin. Pool words only as `;` comment lines.
7. **Integrate:** corrections item, relabel through the address-keyed tools,
   `coverage_map.py`, `label_provenance.py`, then re-run the census.

> **Independence caveat.** Steps 2, 4 and 5 are three Claude sessions.
> `pipeline-plan.md` is right that a second vendor is stronger. What makes these
> results trustworthy is the mechanical part — the generated listing, the verifier
> and the emulator — not the head count. Anything a later patch will depend on
> still goes through the two-vendor pipeline.

## Order of attack

**Tier 0 — shared runtime. Bottom of the call graph, read first.** — **DONE, batch 1.**
The helper library `0x0BDB30`–`0x0BEDB8` (about 70 functions, ~1,900 instructions)
and the RTOS primitives (`0x00317C`, `0x003190`, `0x002B8C`, `0x00E6E4`). Between
them they are called from several thousand sites, and almost none has a body on
file. Every trace above them currently rests on the helper's *name*. Item 102
showed what that costs: `int32_div_sat` was a 16.16 fixed-point divide, off by
65536 for anyone who trusted the label.

**Tier 1 — code that is in the car and unexplained.**
Open-holes #9 (the zeroed clamp at `0x0357C8`, routine `0x0355B8`, output
`0xFFFF7904`) — **mechanism done in batch 1**, identity open (readers of
`0xFFFF77BC`). Then the dependency closure of the two live patches — every
function they hook or return into (`pipeline-plan.md` priority 1). The SSM side
is done (batch 1, open-holes #10). **The launch side is not:** the patch code at
`0x0F1000` and the rev-limiter functions that reach it, `0x03B668` (37
instructions) and `0x03B6B2` (75), have **no verified listing on file** — the
prose in `rev-limit-patch.md` and the emulation in `patch_emulate.py` are all there is.

**Tier 2 — tuned subsystems, largest untraced function first.**
`0x2E000`–`0x47000` (fuel, CL/OL, ignition, knock) is 41,795 instructions and 28%
traced. 50 functions of 150+ instructions there are under 20% traced and hold
12,621 instructions between them. The head of that list (`0x042506` and
`0x0359A4` came off it in batch 1):

| entry | instructions | descriptors | GBR |
|---|---|---|---|
| `0x032204` | 748 | 1 | – |
| `0x0382C2` | 593 | 8 | `0xFFFF7AF4` |
| `0x0410D4` | 505 | 0 | `0xFFFF7FBC` |
| `0x038E64` | 479 | 12 | `0xFFFF7B7C` |
| `0x03AF88` | 423 | 0 | `0xFFFF7C80` |
| `0x0448F4` | 421 | 0 | `0xFFFF81F8` |
| `0x037710` | 329 | 3 | `0xFFFF7A78` |
| `0x03D856` | 328 | 0 | – |
| `0x0415B8` | 292 | 6 | `0xFFFF8000` |
| `0x03AB94` | 287 | 0 | `0xFFFF7C6C` |
| `0x02EB02` | 283 | 0 | `0xFFFF7244` |
| `0x030C38` | 279 | 6 | `0xFFFF73B0` |

`python scripts/mapping/function_census.py --rank 60` prints the live list.
Descriptor-heavy functions first: each one decoded also settles the tables it
consumes, which is how Part 2's 947 unnamed tables actually get closed.

**Tier 3 — bulk classification by script.**
~~The stub families behind the dispatch tables at `0x06423C` and `0x064F7C`~~ —
**done in batch 1**: two 848-entry getter/setter tables of the diagnostic services,
224 stubs in 63 classes (`stub_tables_trace.txt`). Left: the 1,646 functions of
12 instructions or fewer (`scripts/mapping/stub_classes.py` groups 1,278 of them
into 127 shapes, `disassembly/maps/stub_classes.json`); the 168 unreferenced
functions. Group by instruction pattern with literals masked, decode
one example per class, emit the map. Reading these one at a time would cost more
than everything in Tiers 0–2 and establish less.

**Tier 4 — triage the giants before reading any.**
`0x028210` (2,541 instructions), `0x092F1A` (2,383), `0x091AA4` (2,263),
`0x0764EE` (1,671), `0x08641C` (1,378), `0x06A61C` (1,112), `0x04D3D2` (1,032).
For each: GBR bases, RAM and peripheral literals, callees, callers — enough to
say comms / diagnostics / bootloader / control, and only then decide.

**Tier 5 — diagnostics, comms, bootloader (`0x000000`–`0x020000`,
`0x050000`–`0x0A0000`).** 60% of the code and the least tuning value. Read on
demand: when a patch, a logging need or a DTC question lands there.

## Batch 1 — done 2026-11-27 (corrections items 106, 107)

Eight clusters: the helper library in three parts, the guarded-record helpers,
the RTOS core, the diagnostic tables, open-holes #9 and `0x042506`. 24 agents
(trace, refute, settle), four clusters settled twice by a workflow re-run, then six
emulation scripts repaired for the emulator fix. About 2.5 hours of wall clock.

| measure | result |
|---|---|
| verified instruction lines added | 11,502 in 8 files (9,132 distinct new instructions in the census) |
| functions newly at >= 90% traced | 248 |
| claims made / confirmed / refuted / imprecise / missed | 398 / 359 / 7 / 32 / 57 |
| contradictions with existing labels and docs, verified from bytes | 125 |
| labels retired (contradicted names) | 60 — `RetireStaleLabels.java` now drops 210 |
| tool bugs found, all fixed | 5 (emulator rounding, call resolution at joins, delay-slot walk, data seeds, 48 mistyped descriptors) |
| items corrected | item 84 retracted in part; item 105's figures; `desc_types.py` |

**What it taught:**

* **Decoding the runtime first paid immediately.** Every one of the 60 retired
  names sat on a function hundreds of traces call by name. 0x0BDBCC, called
  "desc_read_float_safe" from 324 sites, is a WRITE.
* **The tools were the weakest link, and the traces found it.** Every tool bug
  above came out of a tracer or reviewer disagreeing with a tool's output. Feed
  them back BEFORE the next batch; the next batch's listings depend on them.
* **Check the checker.** The emulator had been "validated" by four oracles and
  still rounded the wrong way. The ROM's own FPU self-test settled it. Look for
  the firmware's self-checks before trusting an emulator result to the last bit.
* **A second settle pass found more every time it ran** (four clusters, by
  accident). For a cluster something will later depend on, settle twice.

## Batch 2 — next

In order; one cluster per line.

1. **Launch patch closure (Tier 1):** `0x0F1000` + `0x03B668` + `0x03B6B2`, and
   the rev-limit compare they feed. Live code with no verified listing.
2. **Hole #9 identity:** `0x033460` (252 instructions, 34% traced) and the readers
   of `0xFFFF77BC` / `0xFFFF77C8` down to the injector pulse.
3. **`0x0382C2`** (593, 8 descriptors) — descriptor-heavy, closes tables.
4. **`0x038E64`** (479, 12 descriptors).
5. **`0x032204`** (748) — reads `0xFFFF7904` behind a calibration switch that is 0.
6. **`0x0410D4`** (505) and **`0x0415B8`** (292, the cold retard writer of item 104).
7. **`0x03AF88`** (423) and **`0x03AB94`** (287) — same GBR neighbourhood.
8. **Tier 3:** classify the 127 stub shapes of `stub_classes.json` — one verified
   example per shape, the rest by masked-pattern match.

Run it as a FRESH workflow with these targets; do not resume batch 1's run
(resume re-runs every agent after the first changed one).

## Rules this part adds

* **Count functions, not lines.** A line total cannot tell a pool word from an
  instruction; 2,527 of the old "traced" lines were pool words.
* **`[TRACED]` on a function label means the address was mentioned.** 336 of 489
  have no body on file. Check `traced_pct` in the census before leaning on one.
* **A `bra` out of a function is a call.** 387 functions are entered only that way.
* **No reference is not no function.** 170 functions have no static reference.
* **Do not regenerate shared maps while a batch is running.** Agents read
  `function_census.json`. The same goes for the emulator, `desc_types.py` and
  `fn_dump.py`: change them between batches, then re-run every `scripts/trace/emu_*.py`.
* **A descriptor's typecode byte is only meaningful to the typed wrappers.** 48
  records consumed by fixed-type wrappers carry a dead byte; `desc_types` reads
  `disassembly/maps/fixed_type_records.json` for them (item 106).

---

# Part 2 — the table programme (written 2026-08-19)

> The percentages in the next block are superseded by Part 1 and corrections item
> 105: code is 572,310 bytes, and 5.5% of it is traced. The table counts stand.

## Where we actually are

```
image 1,048,576 B   code 42.4%   float_data 37.7%   rom_hole 18.6%

code decoded in Ghidra          ~100%   (automatic, given SH-2A — means nothing alone)
code traced and byte-verified     8.1%   (18,099 instructions)
table descriptors decoded         1,094
  ...named by a definition          147
  ...unnamed                        947
data bytes claimed by nobody      79.4%
```

**Fully disassembled, barely analysed.** The verified 8% sits almost entirely in
knock, fuelling, CL/OL and the scheduler — the right places, but it means most of
this ROM has never been read.

## The measured hit rate — read this before committing effort

Two slices, 198 tables triaged:

| slice | tables | flat/inert | diagnostic | mechanisms found | *useful* levers |
|---|---|---|---|---|---|
| RPM × load | 41 | 14 (34%) | 11 | 1 (thermal-lag model) | 0 confirmed |
| coolant axis | 157 | 66 (42%) | 37 | 1 (staged decay bank) | 0 — inert above 40 °C |

**Roughly 40% of unnamed tables are flat, and a further ~25% are OBD
diagnostics.** Two full mechanism traces produced zero confirmed tuning levers —
one model is unnamed pending a single unchased consumer, the other turned out
inert in the regime the car runs in.

That is not a reason to stop. It *is* a reason to **triage broadly before
decoding deeply** — the triage is cheap and the deep dives are not.

---

## Phase 0 — build the tool — **DONE 2026-08-19**

`scripts/mapping/table_triage.py`. One row per unnamed descriptor:

```
address | dim | cell type | shape | scale/bias | data min/max | FLAT?
axis addresses + axis NAME where the axis is shared with a defined table
consumer call sites | RAM touched near each | subsystem guess
```

Everything in that row is already proven mechanical. Two details that must be
carried over or the output is wrong:

* **Join on the DATA pointer only.** Definitions point at data, never at
  descriptor records. Including the axis pointer undercounts the unnamed set by
  161 (item 87).
* **Axis identity is free where an axis array is shared with a named table.**
  158 unnamed tables have one; 157 share the *Coolant Temperature* axis. This is
  ground truth from the XML and beats any breakpoint heuristic — a naive
  classifier calls the 4–80 g/s mass-airflow ladder a temperature axis.

## Phase 1 — triage all 947 — **DONE 2026-08-19**

```
python scripts/mapping/table_triage.py --json disassembly/maps/table_triage.json
python scripts/mapping/table_triage.py --live --json disassembly/maps/table_triage_live.json
```

| | predicted | **actual** |
|---|---|---|
| named by a definition | — | 147 |
| scanner artefacts | ~11 | **14** |
| unnamed, triaged | 947 | **936** |
| flat (inert as shipped) | ~380 | **383** (41%) |
| diagnostic | ~240 | **109** |
| **live and non-diagnostic** | ~330 | **472** |
| axis identity free from a shared axis | 158 | **158** |
| with a direct call site | — | 828 |

The flat prediction was almost exact; the diagnostic share was overestimated
because the first two slices happened to land in diagnostic-heavy regions.

## Phase 2 — rank, do not sweep — **SHORTLIST PRODUCED**

The classifier uses **two independent signals**, both hints, never
identifications, and the row records which one fired (`matched_by`):

1. **GBR base of the enclosing function** — strongest of the three. Nearly every
   function sets GBR from a literal, and the repo already labels those bases with
   a subsystem prefix (`gbr_adc_`, `gbr_io_`, `gbr_diag_`, `gbr_tim_`,
   `gbr_fuel_`, `gbr_afc_`, `gbr_sched_`), so mapping the prefix is mechanical.
   **When this disagrees with the RAM signature, prefer it** — item 94 is the
   worked example, where the RAM said boost/MAP and the GBR said ADC/IO and the
   GBR was right.
2. **RAM signature** — a workspace base or subsystem variable near the call site. Discriminating addresses only: `ect_current`, `rpm_current`,
   `vehicle_speed_kmh` and `ect_gated_c` are the four commonest RAM references in
   the corpus and classify nothing, so they are deliberately excluded.
3. **Consumer code region** — which 4KB block the call site lives in. Only regions with a decoded anchor function
   are listed, and each carries its anchor so the claim is auditable.

Widening the signatures on 2026-08-19 (first pass → second pass):

| | first | **widened** |
|---|---|---|
| unassigned (all rows) | 658 | **357** |
| correctly caught as diagnostic | 109 | **204** |
| live, non-diagnostic | 472 | **400** |
| live rows still unassigned | 399 | **211** |

The live count *fell* because 95 more tables were correctly recognised as
diagnostics and dropped — a better result than a bigger list.

### The live set, by hint

```
transient fuel 31 | ADC/IO 29 | AFC/AFL trim 22 | knock 18 | scheduler 16
ignition timing 12 | evap 12 | base fuelling 10 | throttle/pedal 9 | FLKC 9
CL/OL 8 | OL enrichment/thermal 6 | boost/MAP 5 | idle 2 | unassigned 211
```

**132 sit in a subsystem that actually gets tuned**; 57 are infrastructure
(ADC/IO, scheduler, evap) and can wait; 211 remain unclassified — a gap in the
signature list, not evidence the tables are uninteresting.

**947 → 132 worth reading.** Work from
`disassembly/maps/table_triage_live.json`.

Sanity check that the tool finds real things: it independently re-surfaced every
cluster traced by hand — the `0xAC818`/`0xAC840` coolant decay rates (item 88),
the `0xAD960` thermal-lag model (item 89), `0xAE284`/`0xAE290` in the knock
detector (item 82), and `0xAD8D4`/`0xAD90C`, the CL Fuelling Target Comp
siblings (items 70, 83).

### Biggest unexamined candidates

| descriptor | shape | range | status |
|---|---|---|---|
| `0xAB03C` | 2-D uint8 31×15 | 0 … 100 | **DONE, item 94 — MAP rationality monitor, a diagnostic. Not a lever.** |
| `0xAA850` | 2-D uint16 29×11 | 0 … 1045 | GBR `gbr_io_5C24` → ADC/IO |
| `0xAB288` | 2-D uint16 13×13 | 0.053 … 1.0 | GBR `ratio_0to1_69F0` |
| `0xAAD08` / `0xAAD24` | 2-D uint16 6×11 | 7 … 261 / 1.4 … 331 | GBR `FFFF6118` → ADC/IO |
| `0xAD054` | 1-D uint16 ×16 | 0 … 29000 | GBR `FFFF787E` → AFC/AFL trim |

> **`0xAB03C` is the cautionary tale for this whole programme.** It was the
> largest and most promising-looking unexamined table, its consumer touched
> `manifold_pressure_map`, and it turned out to be an OBD rationality monitor.
> Size and an evocative neighbour are not evidence.

### To widen further

Add to `RAM_SIGNATURES` or `CODE_REGIONS` in the tool. The productive move is
**code regions**, since it needs only one decoded anchor per region rather than a
list of variables. The largest unclassified consumer regions are `0x0BB000`,
`0x08E000`, `0x012000`, `0x019000`, `0x025000` and `0x055000` — one anchor
function decoded in each would classify roughly 60 more tables.

## Phase 3 — deep-dive, one cluster at a time — **NEXT**

Only now decode consumers. The sequence that worked on both clusters today:

1. find the consumer (resolve every PC-relative `mov.l` against every aligned
   occurrence of the descriptor address — catches pointer-table dispatch too);
2. read the RAM near the call site for a subsystem;
3. decode the consumer to the **output store**, not just to the lookup;
4. **read the clamp and limit constants before calling anything a lever.**

Step 4 is what matters. It killed two hypotheses today — the coolant fractions
(flat 0.900 above 40 °C) and the second thermal trip (thresholds at 10000.0
against a quantity that maxes at 1138). It is the same rule that caught
`0xAD258` and `0xD2D48`.

---

## Standing rules — each of these cost something today

**On claims**

* **Read the data before arguing from shape.** The eight coolant fractions
  *looked* exactly like a wall-wetting term; the curve values retired that in one
  command. Raise the hypothesis and check it in the same pass.
* **Don't trust a label's provenance.** "Auto-generated" is not a synonym for
  unreliable — the pattern-scan flag-reader names were right and the hand-written
  "helper" names were wrong (item 92). Judge by whether the bytes support it.
* **A family premise is worth testing before individual labels.** One test
  retired 106 labels (item 91); the alternative was 106 individual decisions.

**On derived numbers**

* **Key on parsed values, never on strings.** `0x0000E774` vs `0xE774` gave a
  conflict count of 91 instead of 118. Joining on the wrong pointer gave 786
  unnamed instead of 947. Both were reported before being caught.
* **Re-derive counts after any change**, and state which measurement a number is
  — "descriptors", "entities" and "bytes" are three different denominators, and
  the 3,078 `UNMAPPED` entities are all RAM, not tables.

**On the Ghidra script**

* **Check whether an address already has a label before adding one.** 13 of the
  118 conflicts got there that way in a single session.
* **Keep the pre-existing name unless a byte-level trace positively contradicts
  it.** Twice the older name turned out to be right.
* **Match on the parsed address when editing the file.** The same address appears
  as `0xAD090`, `0x0AD090L`, `0x000AD090`, `0x00E5ECL`; text-keyed edits have
  silently missed labels four times.
* **Labels are additive.** Removing a `labelComment` call does not unlabel
  anything already imported — run `RetireStaleLabels.java` first, then the
  importer.

---

## What NOT to spend time on

* **The remaining 72 label conflicts.** Both bulk families and the `desc_*` group
  are resolved; what is left is ~25 harmless synonym pairs (both names correct —
  nothing is misleading) and ~10 genuinely contradictory ones needing a full
  trace each. Low return.
* **Naming tables from subsystem hints.** The hint comes from RAM near the call
  site, and several of those RAM labels are themselves guesses. 48 invented
  `Map Switching *` names are the cautionary tale.
* **Flat tables, as levers.** Flat ≠ available. `0xAD258` and `0xD2D48` are both
  flat *and* feed multipliers separately clamped to zero.

## Open threads worth picking up, in order

1. **`byte[0xFFFF79FC]`** — the 930.0 trip flag's consumer. One trace converts
   the thermal-lag model from a strong inference into an identification, and it
   is the single highest-value unchased item.
2. **Phase 0 + Phase 1** — the tool and the full 947-table triage. Cheap, and it
   makes every later decision better.
3. **`0xFFFF7F48` / `0xFFFF7E90`** — the two unidentified terms of the knock mix
   that feeds that model.
4. **Knock estimator RAM** — `0xFFFF80FC` (deviation-estimator gain),
   `0xFFFF8100`/`0x8104` (filter coefficients). These set how fast the knock
   baseline tracks, which is the other half of the sigma lever from item 82.
5. **The event-queue drain side** — `0xFFFF2060`/`0xFFFF2064`. Would show whether
   the 5-slot ceiling is ever approached. Curiosity, not a lever.
