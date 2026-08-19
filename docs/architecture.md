# CPU Architecture — AE5L600L / SH7058

Ground truth for anything touching ROM **code** (not calibration tables).
Everything here was verified from ROM bytes, not from labels or prior docs.

Last verified: 2026-07-26 against `rom/ae5l600l.bin` and `rom/AE5L600L 20g rev 20.19b.bin`.

---

## The one-line answer

**Renesas SH7058, SH-2E core, big-endian.** SH-2E = the classic SH-2 integer
instruction set **plus a single-precision FPU**.

It is **not** plain SH-2 (that has no FPU) and **not** SH-2A (that adds 32-bit
instructions the SH7058 cannot execute).

Older headers in this repo say "SH-2". That is shorthand, and it is what caused
the Ghidra import to be set up wrong. Say **SH-2E**.

---

## Evidence

| Check | Result |
|---|---|
| FPU instruction sites in code regions | **~27,900** (clustered; 186 isolated singles excluded) |
| SH-2A-only encodings | **0** — all 4 candidates verified as float constants in literal pools |
| FSQRT / FSCHG / FRCHG / double-precision | **0** — confirms SH-2E FPU exactly, not SH-4 or SH-2A |
| ROM size | 1,048,576 bytes = SH7058 (SH7055 = 512 KB, SH7059 = 1.5 MB) |
| Reset SP @ `0x00000004` | `0xFFFFBFA0` — just under the top of 48 KB on-chip RAM |
| Highest RAM literal in ROM | `0xFFFFBFFC` — exactly the last aligned word of that RAM |
| Peripheral literals | `0xFFFFF602`–`0xFFFFF666` = SH7058 ATU-II timer block |
| Tuned rev 20.19b | Architecturally identical — same FPU sites at bit-identical addresses |

---

## Memory map

```
ROM          0x00000000 - 0x000FFFFF    1 MB
RAM          0xFFFF0000 - 0xFFFFBFFF    48 KB on-chip
Peripherals  0xFFFFE000 - 0xFFFFFFFF    ATU-II timers at 0xFFFFF6xx
```

> **Correction:** `disassembly/maps/disassembly.txt` used to state
> `RAM: 0xFFFF8000-0xFFFFFFFF (32KB)`. **That was wrong.** It matters because the
> logged RAM addresses this project relies on — `FFFF6624` (RPM), `FFFF6350`
> (ECT), `FFFF65FC` (load) — all sit *below* `0xFFFF8000`. Anything trusting the
> old range concludes those addresses are invalid and invents an explanation.
> Fixed 2026-07-26.

---

## Instructions the SH7058 does NOT have

Seeing any of these in a listing means **you are decoding data as code**. It is a
region-boundary error, never a finding:

```
FSQRT      FSCHG      FRCHG      any double-precision (FCNVDS/FCNVSD/DRn ops)
MOVI20     MOVU       any SH-2A 32-bit fixed-length instruction
```

The canonical decoder `scripts/sh2e_disasm.py` emits `.word 0x#### (INVALID-SH2E)`
for these instead of inventing a mnemonic. The ~27 older per-script decoders in
`scripts/disasm/` each carried a bogus FSQRT decode; patched 2026-07-26 to emit
`.INVALID_SH2E`. If you ever see that token in output, it is a decoder telling
you it has walked off the end of code into data.

---

## Ghidra

**Use Language `SuperH:BE:32:SH-2A`.** Not `SH-2`.

This is not a preference. From Ghidra 12.0.2's own source:

```
sh-2.slaspec:     @define SH_VERSION "2"
sh-2a.slaspec:    @define SH_VERSION "2A"
                  @define FPU "1"            <-- only this one
```

The 36 FPU constructors in `superh.sinc` sit behind `@if defined(FPU)`. Plain
SH-2 therefore has **zero** FPU support.

### Ghidra ships no SH-2E language — but one builds in three lines

`SuperH:BE:32:SH-2A` is a **proxy**, not a match. It is a superset: it also
decodes `MOVI20`/`MOVI20S`/`MOVU`, `FSQRT`/`FSCHG`/`FCNVDS`/`FCNVSD` and the
SH-2A 32-bit fixed-length forms, none of which an SH-2E can execute. That is
why data decoded as code produces plausible-looking instructions instead of
failing loudly, and why `ClearImpossibleSH2E.java` exists to find them after
the fact.

The two gates in `superh.sinc` are **independent** — `@if defined(FPU)` for the
float ops, `@if SH_VERSION == "2A"` for the 32-bit forms (`MOVU` at line 487,
`MOVI20` at 511, inside the 393-826 block). So an exact SH-2E language is:

```
sh-2e.slaspec:    @define SH_VERSION "2"
                  @define FPU "1"
                  @include "superh.sinc"
```

**Verified 2026-08-18:** this compiles clean with `support/sleigh.bat` against
the Ghidra 12.0.2 tree (`4 languages successfully compiled`), producing a
`sh-2e.sla` of 15,996 bytes — between `sh-2.sla` (13,051) and `sh-2a.sla`
(28,508), exactly as the constructor counts predict.

One residue: `FSQRT` (line 2174), `FSCHG` (2168), `FCNVDS` (2022), `FCNVSD`
(2028) and the two 32-bit `FMOV.S @(disp12,…)` forms (2108, 2143) live INSIDE
the `defined(FPU)` block, so the plain build still accepts six instructions the
SH7058 cannot execute. Fencing those six behind `@ifndef STRICT_SH2E` also
compiles (`sh-2e-strict.sla`, 15,475 bytes) and gives what `sh2e_disasm.py`
already gives: **data-as-code self-flags as an undefined instruction instead of
a plausible mnemonic**, automatically, with no post-audit pass.

Neither variant has been tested against ROM bytes inside Ghidra, and adding a
language means editing the `Ghidra/Processors/SuperH` tree under `Program
Files` (or packaging a module extension) plus an entry in `superh.ldefs`. Until
someone does that and diffs a full decode against `scripts/sh2e_disasm.py`,
**`SuperH:BE:32:SH-2A` remains the language to use** — it is proven here and
the strict variant is not.

### What went wrong with the original import

The original DB was built as `SuperH:BE:32:SH-2`. Under that language an FPU
instruction has no constructor, so disassembly **silently stops** — no error, no
bookmark, no bad-instruction marker. Measured from the old export:

- **994 of 3,042 code blocks (33%)** end at the byte immediately before an FPU
  word. They look like short complete functions. They are truncated stubs.
- **~239 KB** of code beginning with an FPU word was never disassembled, vs
  ~172 KB decoded. **More code was missing than present.**
- `fmac_interp_uint16` (`0xBE598`) and `fmac_interp_uint8` (`0xBE588`) — the two
  table-interpolation primitives, **176 call sites** between them — had **0%**
  coverage. Every calibration lookup path dead-ended.
- `KNOCK_DETECTOR`, `FLKC_PATH_J`, `FLKC_PATHS_FG`: 1–5% coverage. That is why
  they were carried as raw hex dumps in `disassembly.txt`.
- The generic ISR prologue at `0x2B8C` (118 callers) decoded 28 bytes, then died
  on its FPU context save.
- "Total functions: 3,642 (+41% improvement)" counted fragments produced by that
  truncation. It overstated coverage.

### Why SH-2A is safe here

SH-2A is a superset: every SH-2E FPU encoding (`FADD 0xFnm0` … `FMAC 0xFnmE`,
`FLDI0/1`, `FLOAT/FTRC`, `LDS/STS FPUL/FPSCR`) decodes identically. The only
risk is that SH-2A *also* defines instructions the SH7058 lacks — and that risk
is self-flagging: genuine code can never contain them, so any `MOVI20`, `MOVU`,
`FSQRT`, or 32-bit form that appears marks a spot where data got read as code.
Audit for those after analysis and clear them manually.

### Re-import procedure (headless, reproducible)

```bash
"C:/Program Files (x86)/ghidra_12.0.2_PUBLIC/support/analyzeHeadless.bat" \
  C:/Users/Dean/GhidraProjects AE5L600L_SH2A \
  -import "<rom>.bin" \
  -loader BinaryLoader -loader-baseAddr 0x0 \
  -processor "SuperH:BE:32:SH-2A" -cspec default \
  -scriptPath disassembly/ghidra -postScript ImportAE5L600L.java
```

Run it from **PowerShell**, not Git Bash — the parentheses in `Program Files
(x86)` break `.bat` argument parsing under bash.

The 3,445 label/comment operations in `ImportAE5L600L.java` are address-based and
language-agnostic; they re-apply unchanged.

---

## Which ROM to analyze

For **code** questions it barely matters — but not quite "not at all".

Stock → rev 20.19b differs in 12,084 bytes. All but **178** are calibration data
(float tables, extended params, uint8 blocks). Two more single bytes inside
code-classified blocks are float constants in literal pools.

The 178 bytes at `0x09A3C2`–`0x09A473` are **real instructions and they differ**.
See [`ssm-read-patch.md`](ssm-read-patch.md).

There is also **injected code at `0x0F1000`–`0x0F1057` (88 bytes)** that a
region-classified diff will miss, because it sits in the big ROM hole
(`0x0DAE8C`–`0x0F8900`) and therefore classifies as `rom_hole`, not `code`. It is
reached via two literal redirects at `0x03B79C` and `0x03B7A8` (both
`0x000CC500`/`0x000CC50C` → `0x000F1000`) and returns into the rev-limit path at
`0x03B6B2`. **When diffing revs for code changes, diff the whole ROM and inspect
`rom_hole` deltas — that is exactly where injected code goes.**

So: use a tuned rev (20.8+) when analyzing anything touching logging,
diagnostics, or the rev limiter. Everywhere else stock and tuned are
byte-identical code.

---

## Rules of thumb

1. **Never answer a code question from a derived file alone.** `disassembly.txt`
   and the Ghidra export are *products*, and the old ones are FPU-blind. Verify
   against ROM bytes with `scripts/sh2e_disasm.py`.
2. **A function that appears to end may have hit a float instruction.** Short
   function + next word starts with `0xF` = truncation, not a short function.
3. **"This region is data / unanalyzable" is suspect** if it came from the old
   Ghidra view. That conclusion was frequently an FPU decode failure.
4. **Impossible instruction ⇒ your region boundary is wrong**, not a discovery.
