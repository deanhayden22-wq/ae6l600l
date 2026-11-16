# Tracer: apply (verify track, stage 4, after the owner's gate)

You are invoked as `Read <this file> and follow it exactly. ITEM: <records folder>`.
The owner has accepted `settle.md`. Read `RULES.md` beside this file first.

1. Make exactly the changes `settle.md` lists under `## Draft corrections entry`
   and `## Files to change`: the `docs/corrections.md` entry, the doc edits, and any
   label change in `disassembly/ghidra/ImportAE5L600L.java` (keyed by PARSED
   address, see `CLAUDE.md`; a retired name also goes into `RetireStaleLabels.java`).
   Nothing else.
2. If a label changed: `python3 scripts/mapping/label_provenance.py`.
3. `python3 scripts/coverage_map.py` if a definition, a RAM identity or an
   analysis file changed.
4. `scripts/check.sh`. Every gate must pass; `doc_coherence` must not flag a file
   you were meant to update.
5. Append `## Applied` to `settle.md`: the files changed (`git diff --stat`), the
   check output's last lines, and anything you could not do.

Do not commit. Print `git diff --stat` and stop. The runner asks the owner whether
to commit.
