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

Measured 2026-11-27 after batch 4 (item 114). Item 105's first figures were
5,151 functions / 572,310 bytes / 15,798 traced (5.5%); after batch 1, 24,930 (8.7%);
after batch 2, 32,111 listed / 22,698 analysed; after batch 3, 38,965 / 30,734.

```
functions                 5,146      572 labels now [DECODED]; 1,759 carry a label
instructions            286,163      = 572,326 bytes of code (NOT 444,928)
  listed, byte-verified  49,418      = 17.3%  (13.6% after batch 3, 11.2% after batch 2)
  ...analysed            42,104      = 14.7%  (10.7% after batch 3; listed in a file that
                                               states what the code does; the 13
                                               *_raw.txt dumps excluded)

functions >= 90% listed     995      (818 after batch 3, 719 after batch 2, 293 before batch 1)
  ...>= 90% analysed        830      (642 after batch 3; 165 are covered by raw dumps alone)
functions partly listed     176
functions never touched   3,975      (4,157 after batch 3, 4,797 before batch 1)
```

(The function count still includes the false splits item 114 found — `0x01FE46` counts as two;
batch 5 step 0 fixes the census.)

**"Listed" is not "decoded".** Until item 108 every figure here, and the `[DECODED]`
tag, counted the `*_raw.txt` files: byte-correct listing dumps with no contracts (and
their headers still say "SH-2" and carry old guessed names). The census now reports
both; `--rank` and the `[DECODED]` tag use `analysed`.

| region | functions | never touched | instructions | listed | analysed |
|---|---|---|---|---|---|
| `0x000000` | 881 | 689 | 26,582 | 14.9% | 13.7% |
| `0x010000` | 505 | 434 | 26,825 | 6.6% | 6.6% |
| `0x020000` | 505 | 356 | 27,750 | 14.8% | 14.0% |
| `0x030000` | 402 | 159 | 26,508 | **70.1%** | **66.8%** |
| `0x040000` | 304 | 177 | 26,177 | **40.1%** | 27.6% |
| `0x050000` | 631 | 463 | 26,927 | 17.9% | 15.2% |
| `0x060000` | 369 | 302 | 22,906 | 9.3% | 3.4% |
| `0x070000` | 413 | 391 | 27,602 | 2.2% | 0.9% |
| `0x080000` | 492 | 473 | 27,583 | 1.0% | 1.0% |
| `0x090000` | 353 | 324 | 23,350 | 4.0% | 3.3% |
| `0x0A0000` | 180 | 171 | 17,389 | 1.0% | 1.0% |
| `0x0B0000` | 110 | 36 | 6,536 | **23.4%** | **23.4%** |
| `0x0F0000` | 1 | 0 | 28 | 100% — the launch patch | 100% |

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

**Tier 1 — code that is in the car and unexplained.** — **done, batches 1–4.**
Open-holes #9 (the zeroed clamp at `0x0357C8`, routine `0x0355B8`, output
`0xFFFF7904`): mechanism (batch 1), identity (batch 2: a trim on the
closed-loop lambda target `0xFFFF77BC`) and reach (batch 3: it drives logged AFC
`0xFFFF76D4`, a live integrator; batch 4: AFC multiplies the injector register,
item 115) settled; what is left is a cold-start log of the SPECIAL-exit bytes.
The dependency closure of both live patches is done (SSM: batch 1, open-holes #10;
launch: batch 2, `launch_closure_trace.txt`; the `0xFFFF8EDC` gate: batch 3 —
written at most once per reset, on a warm start).

**Tier 2 — tuned subsystems, largest untraced function first.**
`0x2E000`–`0x47000` (fuel, CL/OL, ignition, knock). The head of the list as it
stood after batch 1 (`0x042506` and `0x0359A4` came off it in batch 1; the
seven marked ✓ in batch 2, `0x030C38` in batch 3, `0x0448F4`, `0x037710`, `0x03D856`,
`0x02EB02` in batch 4):

| entry | instructions | descriptors | GBR |
|---|---|---|---|
| ✓ `0x032204` | 748 | 1 | – |
| ✓ `0x0382C2` | 593 | 8 | `0xFFFF7AF4` |
| ✓ `0x0410D4` | 505 | 0 | `0xFFFF7FBC` |
| ✓ `0x038E64` | 479 | 12 | `0xFFFF7B7C` |
| ✓ `0x03AF88` | 423 | 0 | `0xFFFF7C80` |
| ✓ `0x0448F4` | 421 | 0 | `0xFFFF81F8` |
| ✓ `0x037710` | 329 | 3 | `0xFFFF7A78` |
| ✓ `0x03D856` | 328 | 0 | – |
| ✓ `0x0415B8` | 292 | 6 | `0xFFFF8000` |
| ✓ `0x03AB94` | 287 | 0 | `0xFFFF7C6C` |
| ✓ `0x02EB02` | 283 | 0 | `0xFFFF7244` |
| ✓ `0x030C38` | 279 | 6 | `0xFFFF73B0` |

`python scripts/mapping/function_census.py --rank 60` prints the live list.
Descriptor-heavy functions first: each one decoded also settles the tables it
consumes, which is how Part 2's 947 unnamed tables actually get closed.

**Tier 3 — bulk classification by script.** — **done, batches 1–3.**
The diagnostic getter/setter tables (batch 1, 224 stubs in 63 classes) and the
127 shapes of `stub_classes.json` (batch 2: 1,278 functions, every member
re-decoded, shape-matched and emulated from its own bytes —
`stub_shapes_a/b_trace.txt`, `--map` on their scripts prints each member's
parameters). Left: the 368 small functions in singleton shapes, the 168
unreferenced functions. **Members are named** (batch 3:
`scripts/mapping/stub_member_names.py` gave 918 of the 1,273 members a name from
their own parameters, e.g. `get_s8_FFFF5B6C`; members that already had a label kept it,
and 104 in classes without a template were left). Group by instruction pattern with literals masked, decode
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

## Batch 2 — done 2026-11-27 (corrections items 108, 109)

Nine clusters: the launch-patch closure, hole #9's identity, five tuned-region
functions (`0x0382C2`, `0x038E64`, `0x032204`, `0x0410D4`/`0x0415B8`,
`0x03AF88`/`0x03AB94`) and the 127 small-function shapes. 29 agents (trace, refute,
settle; an extra audit on the two clusters that are in the car), no failures,
about 1.6 hours of wall clock.

| measure | result |
|---|---|
| verified instruction lines added | 8,254 in 9 files (7,181 distinct new instructions in the census) |
| functions newly at >= 90% traced | 178 |
| claims made / confirmed / refuted / imprecise / missed | 407 / 369 / 1 / 37 / 49 |
| contradictions with existing labels and docs, verified from bytes | 71 |
| labels | 196 new decoded records; 35 more names retired — `RetireStaleLabels.java` drops 245 |
| retracted | the answer of `ffb_gap_resolved_2026-08-19.txt` (item 109) |
| gate fixed | gate 8's launch oracle (`0x0F1048` was hard-coded 0.0) |

**What it taught:**

* **Bound the term before you explain a measurement with it.** The 2026-08-19
  FFB answer read a clamp table and stopped. The seeds and weights upstream of the
  clamp cap the term at half of it. A clamp is a ceiling, not a value.
* **"Is this lever live" has a cheap answer more often than not.** `0x0382C2`'s
  output can never be non-zero (16 flat tables, an empty enable window);
  `0x032204`'s calibration is inert; the hole #9 trim is overridden by the
  SPECIAL exit whenever `[8E7E]`==1. Read the enable path and the clamp constants
  first (standing rule 2), then decide whether the body is worth reading.
* **Cross-check a batch's stubs against the last batch's contracts.** Batch 2
  stubbed `0x00E774` and called 64 handlers "returning to the interrupt exit";
  batch 1 had decoded it as a fatal halt. Integration is where those meet.

## Batch 3 — done 2026-11-27 (corrections items 111, 112, 113)

Seven clusters: the FFB residual (`0x02FFE0`, the `0x030C38` tree), the CL target's
route to fuel (the `0x032B10` bound chain), the SPECIAL-exit gate (`0x05A498`, the
`[9720]` path of `0x028210`), logged AFC's coefficients (`0x031D88`..`0x0320AC`), the
timing integrator's bound (`0x040AF6`), the overrun ladder (`0x03AE6C`, `0x03B3DA`) and
the `0xFFFF8EDC` gate (`0x05CB1C`). 23 agents (trace, refute, settle; an extra audit on
the FFB residual and the SPECIAL exit), no failures, about 2.5 hours of wall clock. The
Tier 3 follow-through (918 member names) ran as a script at integration.

| measure | result |
|---|---|
| verified instruction lines added | 9,982 in 7 files (8,036 more instructions analysed, 6,854 more listed) |
| functions newly at >= 90% analysed | 110 |
| claims made / confirmed / refuted / imprecise / unsupported / missed | 253 / 213 / 3 / 35 / 2 / 37 |
| contradictions with existing labels and docs, verified from bytes | 37 |
| labels | 125 new decoded records + 918 small-function names; 29 more names retired — `RetireStaleLabels.java` drops 274 |
| definition names contradicted by their consumer | 2 — "Intake/Exhaust Duty Correction A" are logged-AFC model tables (item 112) |
| corrected | items 79 and 103 (the overrun retard arm, item 113); item 108's launch-latch caveat (narrowed) |

**What it taught:**

* **The definition layer can be wrong about identity even when every byte agrees.**
  Both misnamed tables are `VERIFIED-BOTH`. Their axis names were right, and that is
  what made the consumer readable: MAF × RPM into a dead time and a time constant.
  Join on the axes, then decode the consumer before trusting a table name.
* **Look for latches before you emulate a climb.** The first timing-bound answer
  was "YES, it can be non-zero". It had set the gate byte to 1 by construction and
  missed a one-way latch that pins the term at 0 the first time the gate is 0. When
  a term "can rise", ask what stops it from ever starting.
* **A log beats a trace for "does it happen on the car".** Four questions this batch
  narrowed now hinge on run-time state the bytes cannot give (power-on RAM, task
  order, which path a cut takes). The logs that settle them are listed below; take
  them before tracing further on those fronts.

**Logs that would settle more than another trace:**

1. Cold start to warm: `0xFFFF8E7E`, `0xFFFF8E66`, `0xFFFF8E65`, `0xFFFF8E68`, `0xFFFF8EDC`
   (does SPECIAL end at warm-up? open-holes #9).
2. Tip-ins, including lift-then-tip-in: `0xFFFF73B4` alongside FFB (open-holes #12).
3. A few overrun lifts: `0xFFFF7C9A`, `0xFFFF7CAA`, `0xFFFF8020`, timing, IPW (open-holes #13).
4. Any drive: `0xFFFF69E6`, `0xFFFF7FF4`, `0xFFFF7FBC` (is the timing integrator ever
   non-zero?).

## Batch 4 — done 2026-11-27 (corrections items 114-118)

Eight clusters: the injector path (`0x0301E4` to the register), the rest of the FFB sum,
`0x01FE46`, the overrun timing terms, power-on RAM, `0x0448F4`, `0x03D856`/`0x02EB02`, and
AFL learning. 26 agents (trace, refute, settle; an extra audit on the injector path and AFL),
no failures, about 2.2 hours of wall clock.

| measure | result |
|---|---|
| verified instruction lines added | 13,953 in 8 files (11,370 more instructions analysed, 10,453 more listed) |
| functions newly at >= 90% analysed | 188 |
| claims made / confirmed / refuted / imprecise / missed | 313 / 264 / 3 / 46 / 41 |
| contradictions with existing labels and docs, verified from bytes | 54 |
| labels | 214 new decoded records; 79 more names retired — `RetireStaleLabels.java` drops 353 |
| closed | open-holes #9 (a): the injector pulse formula (item 115); the power-on questions of items 111/114 (item 117) |
| corrected | item 111's `[79C0]` (it is `[79A0]`), item 74's `0x0ADE08` range and reset gates, item 80's `[8258]` |

**What it taught:**

* **Ask the reset path before arguing about a latch.** Three open questions across two
  batches (the cold-start rev-limit freeze, `[7A44]`, the timing latch's start state) were
  all answered by one fact: the reset DMA zero-fills 0xFFFF4000..BF9F. Decode start-up once,
  early, for any new subsystem.
* **Follow the outputs of a "consumer" to a register, not to a name.** `0x0301E4` had been
  labelled `fuel_pulse_width_calc` for a year; the real pulse also passes through a per-channel
  floor, per-injector trims and an undefined low-pulse table before it reaches `0xFFFFF640`.
* **The census is now the weakest tool again.** It split `0x01FE46` at a false pointer seed and
  works from an 818-record descriptor set. Fix it before the next batch (step 0 below).

## Batch 5 — next

**Step 0 — tools (script work, no agents), before any trace:**

1. `function_census.py`: reject a pointer seed that lands inside already-proven code at an
   address that is not an entry (`0x020000` inside `0x01FE46`); re-run and list every function
   that merges.
2. Reconcile the descriptor scanners: `coverage_map.scan_descriptors` (818 records, used by the
   census, `fn_dump` and the verification registry) vs `descriptor_map.txt` (1,094, item 60's
   scanner). Find which records each misses and why, make one scanner the source, and re-run
   `coverage_map.py` — the registry's counts will move.

Then the traces, in order; each comes out of a batch-4 "not established":

1. **The last FFB piece:** `0x03606C`'s `[798C]` ramp paths with `[79C6]` == 1 / 2 (open-holes #12).
2. **The closed-throttle timing floor (open-holes #13):** `0x03FBBC` (the `[85D7]`-gated blend with
   "Base Timing Idle Minimum") and `0x03ED56` (the `[7EC0]` cap load) with their inputs.
3. **Where the other AFL readers go:** `0x02782C` ((1 + AFL) × table → `[6A00]`/`[6A04]`), `0x071AFA`
   (`[97B0]`), `0x03CD4A`/`0x03D23A` (`[7D68]` → `[7874]`).
4. **The order of start-up:** when `0x047C40` (task 10) runs `0x026634` relative to the first
   `0x0410D4` call — decides whether the timing integrator can ever leave 0.
5. **Who writes `[415C]`** (copied to `[65F6]`, which re-seeds airflow and load and re-arms the
   after-start floor) and **who sets `[36BE]` = 0x4055** (the AFL clear on a warm start, via
   handler `0x098FE4`).
6. **Tier 2 remainder** from `function_census.py --rank 60` after step 0.

**Logs that still settle more than a trace** (from batch 3, all still open): the cold-start
SPECIAL-exit bytes; `0xFFFF73B4` through tip-ins; overrun lifts with `0xFFFF7C9A`, `0xFFFF8028`,
`0xFFFF7F10`, `0xFFFF7EC0` and timing; and `0xFFFF69E6`, `0xFFFF7FF4`, `0xFFFF7FBC` on any drive.

Run it as a FRESH workflow with these targets.

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
