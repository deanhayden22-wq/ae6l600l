# Analysis game plan

Written 2026-08-19, after open-holes 1–7 closed and two slices of the
undefined-ROM programme. Grounded in measured hit rates from those slices, not
in what sounds productive.

Read with **[`open-holes.md`](open-holes.md)** (the live worklist) and the
"How much of this ROM is actually known" section of `CLAUDE.md` (the numbers).

---

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

## Phase 0 — build the tool (do this first)

Today's triage was rebuilt three times in scratchpad. Make it a repo tool:
`scripts/mapping/table_triage.py`, emitting one row per unnamed descriptor:

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

## Phase 1 — triage all 947

Run the tool once. Expected from the two slices: ~380 flat, ~240 diagnostic,
leaving **~330 live and non-diagnostic**. Publish the table; do not decode
anything yet.

## Phase 2 — rank, do not sweep

Keep only tables whose consumer touches RAM belonging to something actually
tuned: fuel, knock, boost/wastegate, AVCS, timing. Drop everything whose
consumer sits in the diagnostic workspaces (`0xFFFFA1xx`, `0xFFFF8Axx`,
`gbr_sens_*`, `diag_precondition_flag_65C0`) — that was 48 of 198 in the two
slices and none of it is a lever.

## Phase 3 — deep-dive, one cluster at a time

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
