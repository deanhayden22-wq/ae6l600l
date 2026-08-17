#!/usr/bin/env python3
"""
Find every WRITE to a RAM address (or range) in the AE5L600L ROM.

Why this exists
---------------
The recurring failure mode on this project is a RAM address whose literal-pool
references are 100% READS, because the writes go through computed addressing.
A naive "grep the literal pool" scan therefore settles nothing, and several
identities were wrong for months as a result:

  0xFFFF6354  69 pooled refs, all reads.  Written by an INDEXED store off a
              neighbouring base:  mov.l @(...),r2 (=0xFFFF6360)
                                  mov #-12,r0
                                  fmov.s fr14,@(r0,r2)
  0xFFFF81BA  13 pooled refs, all reads.  Written GBR-RELATIVE:
                                  mov.b r0,@(190,gbr)   with GBR=0xFFFF80FC

This module finds all four write forms:

  1. direct        fmov.s frX,@rN      / mov.{b,w,l} rM,@rN
  2. displacement  mov.{b,w,l} rM,@(disp,rN)
  3. indexed       fmov.s frX,@(r0,rN) / mov.{b,w,l} rM,@(r0,rN)
  4. GBR-relative  mov.{b,w,l} r0,@(disp,gbr)

For forms 1-3 the base register is resolved by scanning backwards for the
`mov.l @(disp,PC),rN` that loaded it, and r0 is tracked through `mov #imm,r0`.
For form 4 the GBR base is resolved from the enclosing function's
`mov.l @(disp,PC),r0 ; ldc r0,gbr` preamble.

Usage
-----
    python scripts/mapping/find_writers.py FFFF6354
    python scripts/mapping/find_writers.py FFFF6350 FFFF6370      # a range
    python scripts/mapping/find_writers.py FFFF81BA --rom "rom/AE5L600L 20g rev 20.19c.bin"
    python scripts/mapping/find_writers.py FFFF798C --reads       # also list reads

Caveats, stated because this tool is evidence:
  * Backwards base-register resolution has a 1KB window and stops at the first
    reassignment of that register. A base built by arithmetic (add/sub of two
    registers) is NOT resolved and is reported as UNRESOLVED, not omitted.
  * GBR bases are resolved per enclosing function by scanning backwards for the
    nearest `ldc r0,gbr`. If a function switches GBR mid-body this can mislead;
    such sites are marked with the GBR site address so they can be checked.
  * Output is a CLAIM to verify by reading the disassembly at the cited address,
    exactly like every other derived product in this repo (CLAUDE.md rule 1).
"""
import os
import re
import struct
import sys

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
sys.path.insert(0, os.path.join(REPO, "scripts"))
from sh2e_disasm import disasm  # noqa: E402

DEFAULT_ROM = os.path.join(REPO, "rom", "AE5L600L 20g rev 20.19c.bin")

STORE_DIRECT = re.compile(r"^(fmov\.s|mov\.[bwl])\s+(\S+),@(r\d+)\+?$")
STORE_DISP = re.compile(r"^(mov\.[bwl])\s+(\S+),@\((\d+),(r\d+)\)$")
STORE_IDX = re.compile(r"^(fmov\.s|mov\.[bwl])\s+(\S+),@\(r0,(r\d+)\)$")
STORE_GBR = re.compile(r"^(mov\.[bwl])\s+r0,@\((\d+),gbr\)$")
LOAD_ANY = re.compile(r"^(fmov\.s|mov\.[bwl])\s+@")
MOVI_R0 = re.compile(r"^mov\s+#(-?\d+),r0$")
ADDI_R0 = re.compile(r"^add\s+#(-?\d+),r0$")
EXTU_R0 = re.compile(r"^extu\.([bw])\s+r0,r0$")
# any other instruction whose destination is r0 invalidates our tracked value
WRITES_R0 = re.compile(r",r0$")
PCREL = re.compile(r"^mov\.l\s+@\(0x([0-9A-Fa-f]+)\),(r\d+)$")

# NOTE: displacements printed by sh2e_disasm are ALREADY in bytes for every
# form (@(d,Rn), @(d,gbr)). Never rescale them. Kept only for reference.
SZ = {"b": 1, "w": 2, "l": 4}


def load_rom(path):
    with open(path, "rb") as f:
        return f.read()


def gbr_bases(rom, lo=0x0, hi=0x100000):
    """Map every `ldc r0,gbr` site -> the GBR value it installs."""
    out = []
    prev = None
    for pc, _w, t, _ds in disasm(rom, lo, hi):
        if t == "ldc r0,gbr" and prev:
            m = PCREL.match(prev[1])
            if m and m.group(2) == "r0":
                lit = int(m.group(1), 16)
                if lit + 4 <= len(rom):
                    out.append((pc, struct.unpack_from(">I", rom, lit)[0]))
        prev = (pc, t)
    return out


def gbr_at(bases, pc):
    """Nearest preceding `ldc r0,gbr` before pc."""
    best = None
    for site, val in bases:
        if site <= pc:
            best = (site, val)
        else:
            break
    return best


def resolve_base(rom, pc, reg, window=1024):
    """Scan backwards for the mov.l @(lit,PC),reg that loaded `reg`."""
    start = max(0, pc - window)
    found = None
    for a, _w, t, _ds in disasm(rom, start, pc):
        m = PCREL.match(t)
        if m and m.group(2) == reg:
            lit = int(m.group(1), 16)
            if lit + 4 <= len(rom):
                found = (a, struct.unpack_from(">I", rom, lit)[0])
        elif re.search(rf",{reg}$", t):
            found = None  # reassigned by something we cannot resolve
    return found


def scan(rom, lo, hi, want_reads=False):
    bases = gbr_bases(rom)
    hits = []
    r0 = None
    for pc, _w, t, _ds in disasm(rom, 0, len(rom)):
        # --- track r0, which is the index register for every @(r0,Rn) store ---
        # Real code walks a struct with `mov #-64,r0 / extu.b r0,r0 / add #4,r0
        # ... `, so tracking only `mov #imm,r0` misses most indexed writes.
        m = MOVI_R0.match(t)
        if m:
            r0 = int(m.group(1))
            continue
        m = ADDI_R0.match(t)
        if m:
            r0 = None if r0 is None else r0 + int(m.group(1))
            continue
        m = EXTU_R0.match(t)
        if m:
            r0 = None if r0 is None else (r0 & (0xFF if m.group(1) == "b" else 0xFFFF))
            continue

        kind = tgt = detail = None
        clobbers_r0 = bool(WRITES_R0.search(t)) and not t.startswith(("mov.b r0,", "mov.w r0,", "mov.l r0,"))

        m = STORE_GBR.match(t)
        if m:
            g = gbr_at(bases, pc)
            if g:
                # BUG FIX 2026-08-16: sh2e_disasm ALREADY prints the GBR
                # displacement pre-scaled in BYTES --
                #   mov.b r0,@({d8},gbr)  mov.w r0,@({d8*2},gbr)  mov.l r0,@({d8*4},gbr)
                # Multiplying by the operand size again put every mov.w target
                # 2x and every mov.l target 4x too far. Use the printed value
                # as-is. corrections.md item 61.
                tgt = g[1] + int(m.group(2))
                kind, detail = "GBR", f"GBR={g[1]:08X} set @{g[0]:06X}"
        if tgt is None:
            m = STORE_IDX.match(t)
            if m:
                b = resolve_base(rom, pc, m.group(3))
                if b and r0 is not None:
                    tgt = (b[1] + r0) & 0xFFFFFFFF
                    kind, detail = "INDEXED", f"base {b[1]:08X}@{b[0]:06X} + r0={r0}"
                elif b:
                    kind, detail, tgt = "INDEXED", f"base {b[1]:08X}, r0 UNRESOLVED", None
        if tgt is None:
            m = STORE_DISP.match(t)
            if m:
                b = resolve_base(rom, pc, m.group(4))
                if b:
                    # Same pre-scaling as the GBR form: sh2e_disasm prints
                    # mov.w r0,@({d4*2},Rn) and mov.l Rm,@({d4*4},Rn) already
                    # in BYTES. Do not multiply again. corrections.md item 61.
                    tgt = b[1] + int(m.group(3))
                    kind, detail = "DISP", f"base {b[1]:08X}@{b[0]:06X}"
        if tgt is None:
            m = STORE_DIRECT.match(t)
            if m:
                b = resolve_base(rom, pc, m.group(3))
                if b:
                    tgt, kind, detail = b[1], "DIRECT", f"ptr set @{b[0]:06X}"

        if tgt is not None and lo <= tgt < hi:
            hits.append((tgt, "WRITE", kind, pc, t, detail))

        if clobbers_r0:
            r0 = None

        if want_reads and LOAD_ANY.match(t):
            m2 = re.match(r"^(fmov\.s|mov\.[bwl])\s+@(r\d+)\+?,", t)
            if m2:
                b = resolve_base(rom, pc, m2.group(2))
                if b and lo <= b[1] < hi:
                    hits.append((b[1], "read", "DIRECT", pc, t, f"ptr set @{b[0]:06X}"))
    return hits


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    rom_path = DEFAULT_ROM
    if "--rom" in sys.argv:
        rom_path = sys.argv[sys.argv.index("--rom") + 1]
        args = [a for a in args if a != rom_path]
    if not args:
        sys.exit(__doc__)
    lo = int(args[0], 16)
    hi = int(args[1], 16) if len(args) > 1 else lo + 1
    rom = load_rom(rom_path)
    print(f"ROM: {rom_path}  ({len(rom)} bytes)")
    print(f"Scanning for writes to {lo:08X}..{hi - 1:08X}\n")
    hits = scan(rom, lo, hi, want_reads="--reads" in sys.argv)
    if not hits:
        print("  no writes found -- if the address is clearly written, the base is")
        print("  built by arithmetic and this tool cannot see it. Say so; do not")
        print("  conclude the address is read-only.")
    for tgt, rw, kind, pc, t, detail in sorted(hits):
        print(f"  {tgt:08X}  {rw:5s} {kind:8s} {pc:06X}: {t:34s} ; {detail}")
    w = sum(1 for h in hits if h[1] == "WRITE")
    print(f"\n  {w} write(s), {len(hits) - w} read(s) shown")


if __name__ == "__main__":
    main()
