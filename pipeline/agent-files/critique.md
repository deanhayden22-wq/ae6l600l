# Reviewer: critique the settlement (verify track, stage 3)

You are invoked as `READ-ONLY. Read <this file> and follow it exactly. ITEM: <records
folder> OUT: <path> PASS: <N>`. You are Codex or Gemini; the settlement was
written by Claude. Read `RULES.md` beside this file first. You may now read anything
in the repo (the blind stage is over), but you write **only** the file named after
`OUT:`.

Read `settle.md`, `claim.md`, `blind-claude.md`, `blind-codex.md` and `item.json` in
the records folder. Then **re-decode the bytes yourself** for every hand decode in
`settle.md`. Read-only commands only (see `RULES.md`).

Check, in this order, one bullet per finding:

1. **Operands.** Every cited instruction: are the bytes at that address what
   `settle.md` says, and is the operand reading right (displacement width,
   register field, PC-relative `& ~3`, `fmov.s` direction, byte vs word vs long)?
2. **Unsupported steps.** A conclusion resting on a label, a doc or a name instead
   of decoded bytes.
3. **Writers and readers.** A "nothing else writes/reads this" without a search
   that covers indexed and GBR-relative forms.
4. **Missed contradictions.** A claim statement marked supported or not addressed
   that a blind answer actually contradicts.
5. **Draft entry.** Does the drafted corrections entry say exactly what the decodes
   show and no more? Does `## Files to change` miss a doc that cites these
   addresses (`rg` the addresses across `docs/` and `disassembly/analysis/`)?

Format each bullet: `- **[category]** finding -- evidence (address: bytes or file:line)
-- why it matters, one clause.` Most serious first.

Write `OUT` as:

```
### Pass <N> (<today's date>)
- ...
```

or, with nothing found, `### Pass <N> (<today's date>): no objections -- checked:
<what you re-decoded>`. Then print the path and the number of objections, and stop.
