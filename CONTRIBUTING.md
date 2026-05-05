# Contributing

Conventions for ongoing work on AE5L600L. The repo holds enough state
that ad-hoc commits make later archaeology painful — these rules are
about keeping `git log` and the docs useful.

## Commit messages

Subject line: imperative mood, ≤ 72 chars, with rev when applicable.

```
Good:  20.11: soften AVCS 1900↔2200 / 0.20-0.30 cliff (35 mph stutter)
Good:  Add docs/knock.md synthesis of FLKC pipeline
Bad:   tuning
Bad:   logs
Bad:   update
```

If the change affects multiple subsystems, lead with the area:

```
docs: add boost-control + transient-fuel
scripts: fix hardcoded paths in cruise heatmap scripts
```

## Body — for non-trivial commits

For anything past a one-line subject, include:

- **What** changed in concrete terms (table addresses, cell coords,
  values).
- **Why** — the symptom, log evidence, or rationale.
- **Where to verify** — log path, trends CSV, plot file.

Example:

```
20.11: soften AVCS 1900↔2200 / 0.20-0.30 cliff (35 mph stutter)

Cells lifted: (1600,0.20) 5.0->6.5; (1600,0.30) 9.5->11.0;
              (1900,0.20) 9.5->11.0; (1900,0.30) 13.2->14.5
Cells dropped: (2200,0.20) 14.0->13.5; (2200,0.30) 18.0->17.5;
               (2500,0.30) 20.0->19.5

Reduces 1900↔2200 cliff from 4.5-4.7° to 2.5-3.0° at the 35 mph
residency cells per 4-25 cruise heatmap.

Verify on next log: stutter at 35 mph resolved, no new cliffs grown
in the surrounding cells. See docs/open-issues.md for the entry.
```

The format that has not aged well is the bare `tuning` / `logs` /
`update` — those tell a future reader nothing about what was tried
or why.

## When you flash a new rev

1. Save to `rom/AE5L600L 20g rev X.Y tiny wrex.bin`. Bump X.Y if
   meaningful, overwrite in place if iterating.
2. Update [docs/tune-state.md](docs/tune-state.md) with the diff vs
   prior rev.
3. Open or close entries in [docs/open-issues.md](docs/open-issues.md).
4. Commit with the rev in the subject.

## When you add a new analysis script

Use repo-relative paths, not absolute Windows or session paths:

```python
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]   # if script is in scripts/<sub>/
LOGS = REPO / "logs"
```

Outputs (plots, JSON dumps) should go under
`logs/<date>/plots/` per the existing convention.

One-off disassembly scripts under `scripts/disasm/` and
`scripts/decode/` are working artifacts — they may have hardcoded
paths from when they were authored. The rule above applies to new
scripts; the older one-offs are output-frozen and not generally
expected to re-run.

## When you add a new doc

Doc-bearing changes go to `docs/`. Follow the existing pattern:

- Lead with a "Captured YYYY-MM-DD" provenance note.
- Note that bins overwrite in place; any address or table value is a
  point-in-time observation, re-verify before acting.
- Cross-link to other docs with relative `[name](file.md)` links.
- Update [docs/README.md](docs/README.md) index when adding a new
  page.
- Where you cite a fact, cite the source (log path, trends CSV row,
  disassembly file + line range, definition XML address). Per
  [docs/methodology/no-inference.md](docs/methodology/no-inference.md):
  if you can't cite it, flag the uncertainty.

## Line endings

Repo enforces LF for text via `.gitattributes`. Don't reintroduce CRLF
— it produces 1000-line diffs on every file and buries real changes.

## Branches

Main is the working branch. Side branches that get merged or
superseded should be deleted (locally and on origin) so `git branch
-a` stays small. Ask before pushing a long-lived side branch.
