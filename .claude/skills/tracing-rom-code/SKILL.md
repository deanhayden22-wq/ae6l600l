---
name: tracing-rom-code
description: Use when a question depends on what AE5L600L ROM code or an address actually does - "what does 0x... do", "what reads this table", "is this a live lever", identifying a RAM variable, an unnamed table or a Ghidra label, continuing disassembly, or closing an item in docs/open-holes.md.
---

# Tracing ROM code

Every identity this project inferred from a label was wrong; every one decoded from bytes held. Decode the consumer.

## Before starting

Read `docs/open-holes.md` and `docs/analysis-plan.md`. Look the address up in `docs/verification-status.json` and state its flag. `UNMAPPED`, `DISASM-ONLY` and `[UNVERIFIED]` mean unknown.

## Steps

1. **Definitions first.** `defs.load()` from `scripts/defs.py`. Axis names tie a RAM variable to a physical quantity.
2. **Decode bytes** with `scripts/sh2e_disasm.py`. Never reason from `disassembly/maps/disassembly.txt` or an `analysis/*.txt` file alone.
3. **Find the writer.** `scripts/mapping/find_writers.py`. A literal-pool scan of readers settles nothing; writes are often indexed or GBR-relative.
4. **Check base registers.** A register loaded from a literal pool makes `[rN-NN]` a RAM address, not a stack slot.
5. **Read the clamps and multipliers** before calling anything live.
6. **Decode the consumer** end to end.
7. **Tables:** `desc_types.read_table()`. Float32 descriptors have no scale or bias.
8. **Unnamed tables:** `scripts/mapping/table_triage.py --live`. Join on the data pointer only.

## Stop signs

- `FSQRT`, `FSCHG`, `FRCHG`, double-precision ops, `MOVI20`, `MOVU`: you are decoding data as code.
- A function that "ends" before a word starting `0xF`: FPU truncation, not a short function.
- The disassembler prints displacements already in bytes. Do not multiply again.

## After a finding

1. Write it to `disassembly/analysis/` with `address: bytes -> mnemonic` evidence.
2. `.\scripts\check.ps1` (verifier and doc coherence). Keep known errors at 0.
3. Add the item to `docs/corrections.md`; close or update `docs/open-holes.md`.
4. `python scripts/coverage_map.py`, then `python scripts/mapping/label_provenance.py`.
5. Label changes: `sync_import_java_labels.py`, matching on parsed address. Retired labels need `RetireStaleLabels.java` before re-import.
6. Do not edit the definition XMLs; run `.\scripts\sync_defs.ps1` to report divergence.

## Answer shape

Claim, evidence class (observed from bytes / cited / unverified), the bytes, and what it means for tuning in one sentence.
