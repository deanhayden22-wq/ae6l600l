# Tracer: settle (verify track, stage 2)

You are invoked as `Read <this file> and follow it exactly. ITEM: <records folder>`.
Read `RULES.md` beside this file and the repo's `CLAUDE.md` first.

The records folder holds:

```
item.json        slug, the addresses, the ROM, where the claim came from
claim.md         what the project currently believes (the claim under test)
pack.md          the evidence pack both blind readers were given
blind-claude.md  a fresh Claude's answer, written without seeing claim.md
blind-codex.md   Codex's answer, written without seeing claim.md or the other answer
```

## Do

1. Split `claim.md` into its distinct **testable statements about the code**.
   Statements about logs, driving or tuning advice are not testable here; list
   them as such.
2. For each claim statement, compare it with both blind answers: `supported`
   (both or one say the same, the other silent), `contradicted` (a blind answer
   says something incompatible; quote both sides), or `not addressed`.
3. Also list every place where **the two blind answers contradict each other**.
4. **Hand-decode every contradiction from ROM bytes** (`rom` in `item.json`) with
   `scripts/sh2e_disasm.py`. Settle each one as `claim right`, `claim wrong`,
   `both blind answers wrong`, or `not settled` with what would settle it. Cite
   `address: bytes -> mnemonic` for every step. Do not take any side's word.
5. Decide the item's outcome: `confirmed` (no contradiction survives decoding),
   `corrected` (the claim is wrong somewhere; say exactly where), or `open`.
6. If the outcome is `corrected` or `open`, draft the `docs/corrections.md`
   entry (next item number, same format as the last item there) and list every
   file that would change, including stale docs that `scripts/doc_coherence.py`
   would flag. **Do not edit those files yet**; that is the apply stage, after
   the owner's gate.

Write `settle.md` in the records folder with exactly these headings:

```
## Outcome
## Claim statements
## Blind disagreements
## Hand decodes
## Draft corrections entry
## Files to change
## Objections
```

`## Outcome`'s first line is exactly `**Outcome:** confirmed|corrected|open -- <one sentence>`.
Leave `## Objections` empty; the reviewer's passes are appended there.

## Fix rounds

If `settle.md` already exists and has objections under `## Objections`, this is a
fix round: answer each objection in a new `### Response to Pass N` under
`## Objections`, change the sections above where an objection holds, and do not
delete anything. Then stop.

Print the path of `settle.md` and the outcome line, then stop.
