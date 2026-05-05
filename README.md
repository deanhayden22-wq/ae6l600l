# AE5L600L

ROM analysis and tuning workspace for a 2013 USDM Subaru Impreza WRX MT
running a 20G turbo on the **AE5L600L** ROM (Denso SH7058, SH-2 CPU,
1 MB).

This repo holds:

- The stock ROM and a series of working revisions (`rom/`).
- Verified disassembly, Ghidra exports, and RAM/descriptor maps
  (`disassembly/`).
- RomRaider definition XMLs (`definitions/`).
- Datalogs from real driving (`logs/`) and the review SOP that turns
  them into actionable tuning signal.
- Throttle / pedal / AVCS work-in-progress files (`Throttle tuning/`).
- MerpMod and SharpTune source mirrors plus the patched MerpMod-SD
  binary (`merp mod/`).
- Experimental patches that have **not** been verified for this ROM
  (`patches/`).
- Disassembly, decode, and log-analysis scripts (`scripts/`).

---

## Toolchain

- **RomRaider** — definition editing, table editing, real-time logging.
- **SharpTune** — applies MerpMod patches; produces the SD binaries.
- **Ghidra** — primary disassembly environment. Project import script
  and label generator are in `disassembly/ghidra/`.
- **Python 3** — every analysis, decode, and disassembly helper. See
  `scripts/`.

---

## Directory map

| Path | What's in it |
|---|---|
| `rom/` | Stock ROM + tuning revisions (`*.bin`, `*.hex`). |
| `definitions/` | RomRaider XMLs — base 32-bit, stock AE5L600L, MerpMod-SD. |
| `disassembly/analysis/` | Per-subsystem disassembly + commentary (`*_analysis.txt` paired with `*_raw.txt`). |
| `disassembly/maps/` | Cross-references: descriptor map, RAM map, GBR registry, ISR map, task call graph, etc. |
| `disassembly/ghidra/` | Ghidra export XML, import script, generated labels. |
| `disassembly/STATUS.md` | Coverage summary — counts of named functions, mapped descriptors, etc. |
| `logs/` | RomRaider datalogs (CSV, 25 Hz). One folder per session. |
| `logs/REVIEW_LOG.md` | Append-only per-log review history. |
| `Throttle tuning/` | Pedal map iterations, AVCS softening CSVs, comparison plots. |
| `merp mod/` | MerpMod-master + SharpTune-master source mirrors and the patched binary. |
| `patches/` | Experimental patch attempts. **Treat as unverified.** |
| `scripts/analysis/` | Log review tooling, including `log_review_checklist.md` (the SOP). |
| `scripts/analysis/trends/` | Append-only per-metric CSVs that accumulate across log reviews. |
| `scripts/disasm/` | One-off SH-2 disassembly scripts targeting specific functions/regions. |
| `scripts/decode/` | Table/descriptor decoders. |
| `scripts/mapping/` | Descriptor scanning, GBR resolution, RAM-ref tracing. |
| `scripts/trace/` | RAM read/write tracers. |

---

## Source-of-truth rules

Trust these directories for ROM analysis:

- `disassembly/` (verified)
- `definitions/` (verified)
- `rom/` (stock + working revs)
- `scripts/`
- `logs/`
- `merp mod/` (active port — the loose `.bin` files at the top of that
  folder, not anything called "archive")

**Do NOT reference for ROM facts:**

- `patches/` — experimental, addresses and logic unverified.

---

## Log review process

The full SOP is in `scripts/analysis/log_review_checklist.md`. Short
version: every datalog gets walked through eight steps (knock → WOT →
MAF correction → cliffs → stutter → VE → AVCS → cruise residency), with
fixed filter definitions and per-table cliff thresholds. Findings get
appended to `logs/REVIEW_LOG.md` and the per-metric trend CSVs in
`scripts/analysis/trends/`.

The SOP is the entry point. Read it before running any new analysis
script — the filter constants and trend-store schema are defined there
and should not drift.

---

## Line endings

A `.gitattributes` at the root enforces LF for text files. If you clone
on Windows, your editor will see LF — that's intentional, and modern
editors (VS Code, Notepad++, anything modern) handle it fine. Don't
re-introduce CRLF: it produces 1000-line diffs on every file and buries
real changes.

---

## What this README does NOT contain

The active reasoning behind the current tune — open issues, design
state of the pedal map, AVCS load-band rules, the boost-transition vs
turbo-regime caveat — lives outside the repo (in the maintainer's
working notes). The repo captures the **state** of the ROM and the
**process** for analyzing logs; the **interpretation** does not travel
with a clone today. That's a known gap.
