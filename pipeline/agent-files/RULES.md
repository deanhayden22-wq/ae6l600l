# Rules for every agent in the AE5L600L pipeline

These apply to every role: the blind readers, the tracer, the reviewer. They
add to the repo's `CLAUDE.md`. Where the two differ, the stricter rule wins.
The design and its reasons are in `docs/pipeline-plan.md`.

## The car cannot be bench-tested

Whatever this pipeline concludes ends up flashed to a car with no recovery rig.
A wrong identity found here becomes a wrong patch later. So:

- **Bytes are the only evidence.** Decode with `scripts/sh2e_disasm.py`; read
  tables with `scripts/desc_types.py` / `scripts/defs.py`. A doc, a label, a memory
  note or another agent's answer is a *claim to be tested*, never a premise.
- **Cite every statement**, as `address: bytes -> mnemonic` for code and
  `file:line` for anything derived. A statement without a cite is a hunch, so
  label it one.
- **Check operands, not mnemonics**: the displacement width, the register
  field, `& ~3` on PC-relative longs, the `fmov.s` direction. `sh2e_disasm` prints
  displacements already in bytes.
- An SH-2A-only instruction (`FSQRT`, `FSCHG`, `FRCHG`, double-precision,
  `MOVI20`, `MOVU`, 32-bit forms) in a listing means **you are decoding data**.
  Move the boundary; do not explain it.
- "Nothing reads/writes this" needs a writer search that covers indexed `@(r0,Rn)`
  and GBR-relative forms (`scripts/mapping/find_writers.py`). A literal-pool scan
  never establishes it.

## Never

- Flash, or produce a bin meant for flashing. That is Track B, behind its own gates.
- Edit `rom/` or `definitions/`. The definition XMLs are owned by ECUFlash.
- `git commit`, `git push`, or branch changes. The runner commits, and only on
  the owner's answer at a gate.
- Delete or rewrite an earlier `### Pass N`, a `corrections.md` item or a
  `## Decisions` line. Append only.
- Use the network.

## Roles

| role | who | reads | writes |
|---|---|---|---|
| blind reader | a fresh Claude and Codex, each in its own folder outside the repo | only that folder: the ROM, the decoder, the definitions, the pack | `answer.md` in that folder |
| tracer | Claude, main checkout | everything | the item's records (`.pipeline/items/<slug>/`); docs only in the apply stage |
| reviewer | Codex (or Gemini), cwd its blind folder | everything, read-only | `critique.md` in its own folder; the runner copies it |

The reviewer may run read-only commands only: `cat`, `sed -n`, `rg`, `ls`, `xxd`,
`git log/show/diff`, `python3 scripts/sh2e_disasm.py`, and `python3 -c` that only
imports `sh2e_disasm`, `desc_types` or `defs` and prints.
