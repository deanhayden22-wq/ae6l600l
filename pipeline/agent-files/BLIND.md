# Blind reader

You are one of two independent readers, from two different vendors, of a piece of
an engine-computer ROM. Neither of you can see what the project currently
believes about it. That is the point: where your answer and the project's claim
disagree, someone is wrong, and a human will decide which **from the bytes**.

The ROM: 2013 Subaru WRX, AE5L600L. CPU: Renesas SH7058, an **SH-2E** core (the SH-2
integer set plus a single-precision FPU), big-endian. ROM is `0x000000`-`0x0FFFFF`;
on-chip RAM is `0xFFFF0000`-`0xFFFFBFFF`; peripherals from `0xFFFFE000`.

## Stay in this folder

Everything you need is here:

```
pack.md                 the addresses of interest and the functions that touch them
rom/current.bin         the ROM as flashed to the car
rom/stock.bin           the factory ROM
scripts/sh2e_disasm.py  the decoder:  python3 -c "import sys; sys.path.insert(0,'scripts'); \
                          import sh2e_disasm as D; r=open('rom/current.bin','rb').read(); \
                          [print(f'{p:06X} {w:04X} {t}') for p,w,t,_ in D.disasm(r,0x355B8,0x35600)]"
scripts/desc_types.py   table descriptors: desc_types.read_table(rom, addr)
scripts/defs.py         the definition XMLs (table names, axis names, units): defs.load()
definitions/            those XMLs
```

**Do not read anything outside this folder.** No repo, no docs, no notes, no other
agent's folder. If you cannot answer without something that is not here, say so
under `## Not established`.

## Method

1. Read `pack.md`. It was built mechanically from bytes and follows direct literal
   references only. Indexed `@(r0,Rn)`, displacement-off-a-pointer and GBR-relative
   accesses are invisible to it, so decode further yourself.
2. For each address of interest: what it holds (raw bytes, as the type the code
   reads it), who reads it, who writes it, and how the value is used.
3. Follow the data flow to the mechanism's **inputs** and **outputs**. For an output
   in RAM, find what consumes it.
4. Look for what makes part of it **inert in this calibration**: a zero gain, equal
   bounds, an unreachable threshold, a flag nothing sets. Give the values.
5. Name a physical quantity only when the bytes force it: a definition axis name,
   a definition table that feeds it, a unit conversion in the code. Otherwise call
   it by its address.
6. `sh2e_disasm` prints displacements already in bytes, and PC-relative targets
   already resolved. Do not scale them again.
7. An SH-2A-only instruction in a listing means you are decoding data.

## Answer

Write `answer.md` in this folder with exactly these headings:

```
## Mechanism
## Addresses
## Inputs and outputs
## Inert or gated in this calibration
## Statements
## Not established
```

- **Addresses**: one line each, `0x...: <what it is> -- <evidence class>`, where the
  class is `observed` (the code fixes it), `inferred` (a chain with a named
  unverified link) or `hunch`.
- **Statements**: numbered, one testable fact per line, each with its cite
  (`035730 F608 fmov.s @r0,fr6`). These are what gets compared with the claim, so
  make each one checkable on its own.
- **Not established**: what you could not determine, and what would settle it.

Then stop. Do not edit anything else.
