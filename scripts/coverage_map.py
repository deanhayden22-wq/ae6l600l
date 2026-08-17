#!/usr/bin/env python3
"""
coverage_map.py -- compute a CORRECTNESS FLAG for every thing this project
claims to know about the AE5L600L ROM, and map what carries no flag at all.

WHY THIS EXISTS
---------------
This project has been bitten four times by a "correction" applied in the wrong
direction (0xBE960/0xBE970 min<->max; float_abs that was really max(x,0.0);
0xFFFF65FC labelled engine_load when it is vehicle speed in km/h; 0xFFFF63F8
labelled iat_current when it is engine load in g/rev).  Every derived file
agreed with every other derived file, which is exactly what made the errors
durable.  AGREEMENT ACROSS DERIVED FILES IS NOT EVIDENCE.

So this script never reads a conclusion out of a derived file and calls it
verified.  It re-derives the code-side evidence from ROM BYTES on every run,
and uses the derived corpus (ram_reference.txt, descriptor_map.txt,
cal_crossref.txt, analysis/*.txt) only for two things:

  * to learn what the disassembly layer CLAIMS (so a claim can be contradicted)
  * to learn what the disassembly layer has even LOOKED AT (coverage, not truth)

THE TWO SIDES
-------------
  DEFINITION side   scripts/defs.py  ->  definitions/32BITBASE.xml
                                    +   definitions/AE5L600L 2013 USDM ....xml
                    (inheritance resolved, scalings resolved, toexpr applied)

  DISASSEMBLY side  re-derived here from rom/ae5l600l.bin:
                      D1  literal-pool back-trace: how does CODE dereference
                          this address?  fmov.s => float, mov.b/w/l => integer
                      D2  table descriptors decoded straight out of ROM
                          (element count + bytes/cell + axis pointers)
                      D3  RAM -> descriptor axis feed trace: which RAM variable
                          is passed as the axis input to a table lookup
                    plus, as CLAIMS only:
                      D4  ram_reference.txt names/descriptions
                      D5  cal_crossref.txt Ghidra labels
                      D6  mentions in disassembly/analysis/*.txt + maps/*.txt

Run:
    python scripts/coverage_map.py            # regenerate registry + summary
    python scripts/coverage_map.py --check    # fail if on-disk registry is stale
    python scripts/coverage_map.py --quiet

Writes (both regenerated from scratch, NEVER hand-edited):
    docs/verification-status.md      human registry
    docs/verification-status.json    machine-readable, one record per entity
"""

from __future__ import annotations

import argparse
import collections
import datetime
import json
import os
import re
import struct
import sys
from collections import Counter, defaultdict

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(_HERE)
# scripts/ contains defs.py; make sure it is importable and that a scratch
# directory on sys.path cannot shadow it.
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import defs  # noqa: E402  canonical definition loader -- do not reimplement

STOCK_ROM = os.path.join(REPO, "rom", "ae5l600l.bin")
REV_ROM = os.path.join(REPO, "rom", "AE5L600L 20g rev 20.19b.bin")
REV_NAME = "20.19b"

MAPS = os.path.join(REPO, "disassembly", "maps")
ANALYSIS = os.path.join(REPO, "disassembly", "analysis")
RAM_REFERENCE = os.path.join(MAPS, "ram_reference.txt")
CAL_CROSSREF = os.path.join(MAPS, "cal_crossref.txt")
DESCRIPTOR_MAP = os.path.join(MAPS, "descriptor_map.txt")
REGION_MAP = os.path.join(MAPS, "rom_region_map.txt")

OUT_MD = os.path.join(REPO, "docs", "verification-status.md")
OUT_JSON = os.path.join(REPO, "docs", "verification-status.json")

ROM_SIZE = defs.ROM_SIZE
RAM_LO, RAM_HI = 0xFFFF0000, 0xFFFFC000     # corrections.md #2
CAL_LO, CAL_HI = 0x0C0000, 0x0E0000         # calibration data band
DESC_LO, DESC_HI = 0x0A0000, 0x0BE000       # descriptor band
LOOKUP_1D, LOOKUP_2D = 0x000BE830, 0x000BE8E4   # table_desc_1d/2d_float
# The other six lookup entry points HARDCODE their cell width instead of
# dispatching on the descriptor typecode, so their descriptors carry a dead
# 0x0000 typecode.  Tracing only the two float ones made every integer-celled
# table invisible -- which is why the Injector Latency battery-voltage feed
# never showed up.  Trace all eight; suppress bytes/cell claims for the six.
LOOKUP_WIDTH_HARDCODED = frozenset((0x000BE874, 0x000BE88C, 0x000BE8AC,
                                    0x000BE8C4, 0x000BE928, 0x000BE944))
LOOKUP_ALL = frozenset((LOOKUP_1D, LOOKUP_2D)) | LOOKUP_WIDTH_HARDCODED

SCHEMA_VERSION = 1


# ==========================================================================
# 1.  THE FLAG TAXONOMY  (single source of truth; rendered into the registry)
# ==========================================================================
#
# Exactly one flag per entity.  Evaluated in the order listed: the first rule
# that fires wins, so the ladder is total and unambiguous.

TAXONOMY = [
    dict(
        flag="CONFLICT",
        means="The definition side and the ROM-code side make incompatible "
              "claims about the SAME bytes. The record must name which side is "
              "suspect and why. A CONFLICT is never silently resolved by this "
              "script -- it is surfaced for a human to settle from bytes.",
        evidence_required=(
            "Both sides must have independently produced a claim about the same "
            "address, and the claims must be mutually exclusive. Accepted "
            "contradictions: (a) declared storagetype width vs the width ROM code "
            "actually dereferences the address with (fmov.s vs mov.b/w/l, from the "
            "literal-pool back-trace); (b) declared element count or bytes/cell vs "
            "the count/width in the ROM's own table descriptor; (c) for RAM, the "
            "physical quantity named in ram_reference.txt vs the physical quantity "
            "of the definition-named axis that this RAM variable is traced feeding."),
        invalidated_by=(
            "Showing the two claims are not about the same bytes (e.g. an alias "
            "table at the same address with a different but COMPATIBLE view -- two "
            "unit views of one float are not a conflict), or showing the code-side "
            "observation was a false positive (pool word matched by coincidence, "
            "register reloaded before the dereference, 0xFF hole bytes read as "
            "data). Downgrades to VERIFIED-BOTH or VERIFIED-BYTES once the losing "
            "side is corrected in its source file."),
    ),
    dict(
        flag="BOUNDS-SUSPECT",
        means="Identity and geometry are fine, but the definition's own declared "
              "min/max is contradicted by the FACTORY ROM's own data. This is an "
              "editor-facing hazard, not a read error: ECUFlash/RomRaider clamp "
              "on write, so the bound can silently refuse a legitimate value. "
              "Kept separate from CONFLICT because the bytes are read correctly.",
        evidence_required=(
            "The STOCK ROM decodes through the declared scaling to a display value "
            "outside [min,max] by more than 1e-4 of the declared span (that "
            "tolerance exists because several bounds are rounded copies of the exact "
            "breakpoint). Stock is the test, not the tuned rev: a 20.19b-only "
            "excursion is Dean's edit, is recorded as a note, and does NOT set this "
            "flag."),
        invalidated_by=(
            "Correcting min/max in the XML so the factory data fits, or proving the "
            "scaling itself (not the bound) is wrong -- in which case the entity "
            "becomes CONFLICT instead."),
    ),
    dict(
        flag="VERIFIED-BOTH",
        means="Definition and disassembly independently describe these bytes and "
              "AGREE, and the bytes decode sanely in both the stock and the "
              "current tuned ROM. Highest confidence available without a "
              "dyno/log experiment.",
        evidence_required=(
            "ALL of: (1) the definition resolves -- address, scaling, storagetype, "
            "element count -- and the extent lies inside the 1 MiB ROM; (2) every "
            "cell decodes in BOTH rom/ae5l600l.bin and rom/AE5L600L 20g rev "
            "20.19b.bin with no NaN/Inf and, for axes, monotonic breakpoints; "
            "(3) stock data lies inside the declared min/max; (4) at least one "
            "INDEPENDENT code-side observation of the same address -- a literal-pool "
            "dereference whose access width matches the declared storagetype, or a "
            "ROM table descriptor whose bytes/cell and element count match the "
            "declared geometry -- and it does not contradict (1)."),
        invalidated_by=(
            "Any edit to the address, scaling, storagetype or elements= of the "
            "table or its axes; a new ROM rev whose bytes fail the decode/range "
            "test; discovery of a second code path that dereferences the address "
            "with a different width. Flags are regenerated from scratch on every "
            "run, so an edit to either side invalidates automatically."),
    ),
    dict(
        flag="VERIFIED-BYTES",
        means="The definition is self-consistent and survives contact with real "
              "ROM bytes in both revs, but NOTHING on the code side independently "
              "corroborates it. The bytes are readable and plausible; the "
              "IDENTITY rests on the definition alone.",
        evidence_required=(
            "Conditions (1)-(3) of VERIFIED-BOTH, and NO code-side observation "
            "either way. Typically the address is reached through a descriptor "
            "pointer or a computed offset rather than a raw pool literal, so the "
            "back-trace has nothing to find."),
        invalidated_by=(
            "Same as VERIFIED-BOTH. Additionally: this flag is an explicit "
            "statement that a wrong-identity error of the 0xC0BCC class would NOT "
            "be caught here. Do not cite a VERIFIED-BYTES entity as proof of what "
            "a table MEANS -- only of what it CONTAINS."),
    ),
    dict(
        flag="DEFS-ONLY",
        means="A definition exists but cannot be checked against anything, "
              "because the definition itself is incomplete -- no address, or a "
              "scaling that is referenced but defined in no XML, so there is no "
              "storagetype and therefore no byte width. These are unopenable in "
              "ECUFlash/RomRaider too.",
        evidence_required=(
            "defs.py resolves the <table>, but Table.readable is False: address "
            "missing, scaling name not found in either XML, storagetype "
            "unsupported/absent, or element count unresolved."),
        invalidated_by=(
            "Supplying the missing <scaling> element or address= attribute. The "
            "entity then re-enters the ladder at whatever its bytes justify -- it "
            "does NOT jump straight to verified."),
    ),
    dict(
        flag="DISASM-ONLY",
        means="The code side describes these bytes -- a ROM table descriptor "
              "points at them, or ram_reference.txt/cal_crossref.txt names them -- "
              "but no definition binds them. Nothing here has been checked against "
              "the definition XMLs, which are the project's primary ground truth "
              "for identity and units.",
        evidence_required=(
            "For ROM: a descriptor decoded from ROM bytes whose data or axis "
            "pointer lands in this extent, and no defs.py table/axis covering any "
            "byte of it. For RAM: an entry in ram_reference.txt (RAM is outside "
            "the ROM image, so no definition can ever cover it) with no "
            "definition-axis corroboration from the feed trace."),
        invalidated_by=(
            "Adding a <table> to the project XML that covers the extent (moves it "
            "into the definition ladder), or -- for RAM -- a feed trace that ties "
            "the address to a definition-named axis, which promotes it to "
            "VERIFIED-BOTH or exposes it as CONFLICT."),
    ),
    dict(
        flag="UNMAPPED",
        means="Neither side says anything. For ROM this is data-classified bytes "
              "claimed by no definition and no descriptor. For RAM it is an "
              "address the ROM's own literal pools reference but ram_reference.txt "
              "does not name. This is the honest measure of what is not known.",
        evidence_required=(
            "ROM: byte falls in a block the region map classifies as float_data / "
            "uint8_data / mixed_data (not code, not a 0xFF hole) and is covered by "
            "no definition extent and no descriptor extent. RAM: address in "
            "0xFFFF0000-0xFFFFBFFF appears as a 4-aligned literal-pool word and is "
            "absent from ram_reference.txt."),
        invalidated_by=(
            "Any definition, descriptor or named RAM entry that claims the "
            "address. UNMAPPED is a residue, computed by subtraction -- it can "
            "only shrink by someone doing work, never by re-running this script."),
    ),
]

FLAG_ORDER = [t["flag"] for t in TAXONOMY]


# ==========================================================================
# 2.  ROM-side evidence, re-derived from bytes on every run
# ==========================================================================

def load_rom(path):
    with open(path, "rb") as fh:
        buf = fh.read()
    if len(buf) != ROM_SIZE:
        raise SystemExit("%s is %d bytes, expected %d" % (path, len(buf), ROM_SIZE))
    return buf


def literal_index(buf):
    """Every 4-aligned word in the ROM -> the offsets holding it.

    SH-2E reaches a constant through `mov.l @(disp,PC),Rn`, and that displacement
    is word-scaled off (PC+4)&~3, so every pointer to a calibration address is a
    4-aligned literal somewhere in a pool.  Indexing them is what makes the
    back-trace below possible.
    """
    lit = defaultdict(list)
    for a in range(0, len(buf) - 3, 4):
        lit[struct.unpack_from(">I", buf, a)[0]].append(a)
    return lit


_ACCESS_CLASS = {"float": "float", "uint8": "int8", "int8": "int8",
                 "uint16": "int16", "int16": "int16",
                 "uint32": "int32", "int32": "int32"}


def deref_widths(buf, lit, addr, back=0x400, fwd=14):
    """D1 -- how does ROM CODE dereference `addr`?

    For each pool slot holding `addr`, walk backwards for the `mov.l @(d,PC),Rn`
    that targets that slot, then forward for the FIRST load through Rn:

        0xFnm8   fmov.s @Rm,FRn     -> single-precision FLOAT
        0x6nm0/1/2  mov.b/w/l @Rm,Rn -> 8 / 16 / 32-bit INTEGER

    Stop if Rn is reloaded (0xD/0xE with n==Rn) before any dereference, so a
    register that was only used to build another address is not miscounted.

    Returns {"float": n, "int8": n, "int16": n, "int32": n} (absent keys = 0).
    """
    res = Counter()
    for site in lit.get(addr, ()):
        for pc in range(max(0, site - back), site, 2):
            w = struct.unpack_from(">H", buf, pc)[0]
            if (w >> 12) != 0xD:
                continue
            if (((pc + 4) & ~3) + (w & 0xFF) * 4) != site:
                continue
            rn = (w >> 8) & 0xF
            for k in range(1, fwd):
                if pc + 2 * k + 1 >= len(buf):
                    break
                v = struct.unpack_from(">H", buf, pc + 2 * k)[0]
                hi, n, m, lo = (v >> 12), (v >> 8) & 0xF, (v >> 4) & 0xF, v & 0xF
                if hi == 0xF and lo == 8 and m == rn:
                    res["float"] += 1
                    break
                if hi == 0xF and lo == 0xA and n == rn:      # fmov.s FRm,@Rn (store)
                    res["float"] += 1
                    break
                if hi == 6 and m == rn and lo in (0, 1, 2):
                    res[{0: "int8", 1: "int16", 2: "int32"}[lo]] += 1
                    break
                if hi == 2 and n == rn and lo in (0, 1, 2):     # store through Rn
                    res[{0: "int8", 1: "int16", 2: "int32"}[lo]] += 1
                    break
                if hi in (0xD, 0xE) and n == rn:
                    break
    return dict(res)


# ---- D2: table descriptors, decoded straight out of ROM -------------------
#
# Struct decoded by hand from ROM bytes, NOT taken from descriptor_map.txt:
#
#   1D int   (20 bytes)  +0 u16 count  +2 u16 typecode  +4 u32 axis
#                        +8 u32 data   +12 f32 scale    +16 f32 bias
#   1D float (12 bytes)  +0 u16 count  +2 u16 0x0000    +4 u32 axis  +8 u32 data
#                        (no scale/bias -- float cells need none)
#   2D       (28 bytes)  +0 u16 count1 +2 u16 count2    +4 u32 axis1 +8 u32 axis2
#                        +12 u32 data  +16 u32 typecode +20 f32 scale +24 f32 bias
#
#   typecode 0x0400 -> 1 byte/cell,  0x0800 -> 2 bytes/cell,  0x0000 -> 4 (float)
#
# The bytes/cell mapping was confirmed independently by pointer spacing across
# every 1D descriptor: for typecode 0x0400 the gap from the data pointer to the
# next descriptor pointer implies 1 byte/cell 83 times vs 2 bytes/cell 7 times;
# for 0x0800 it implies 2 bytes/cell 232 times vs 4 bytes/cell 13 times.
#
# HISTORY: disassembly/maps/descriptor_map.txt used to print 0x0400 as "int16"
# and 0x0800 as "uint8".  That was NOT a 1-byte/2-byte inversion as previously
# noted here -- it was a shifted map that also lost signedness and dropped
# typecodes 0x0C00/0x1000 entirely (docs/corrections.md item 39).  It was
# regenerated correctly on 2026-08-16 and now agrees with _TYPECODE_WIDTH below.
#
# The exclusion nonetheless STANDS, deliberately: that file is still a derived
# product, and this module's acceptance rule (below) is strictly stronger than
# the scanner's -- it requires exact contiguous layout rather than a plausible
# axis.  Keeping the two sides independent is the entire point of the
# cross-check; consuming descriptor_map.txt here would make coverage_map agree
# with the scanner by construction and destroy the corroboration.  Agreement
# between them is now a real signal precisely because neither reads the other.
#
# ACCEPTANCE RULE (deliberately high precision, not high recall): a candidate is
# accepted only when the Subaru contiguous layout holds exactly --
#     1D:  axis + count*4 == data
#     2D:  axis1 + count1*4 == axis2   and   axis2 + count2*4 == data
# (axis breakpoints are always 4-byte floats).  That is a ~40-bit coincidence,
# so false positives are effectively impossible; the cost is that descriptors
# which SHARE an axis with a neighbour are missed.  Missing a descriptor only
# ever costs corroboration -- it can demote VERIFIED-BOTH to VERIFIED-BYTES,
# never the other way round.  780 descriptors survive, with 780 distinct data
# pointers (no aliasing, no 1D/2D shadowing).

# Typecode -> bytes/cell.  The five-entry dispatch table at 0x0BE860 holds
# 0xBEACC float, 0xBEB20 uint8, 0xBEB6C uint16, 0xBEAE4 SIGNED int8,
# 0xBEB00 SIGNED int16 -- so the signed variants (0x0C00/0x1000) are real
# typecodes and were being dropped.
_TYPECODE_WIDTH = {0x0000: 4, 0x0400: 1, 0x0800: 2, 0x0C00: 1, 0x1000: 2}


def _desc_at(buf, a):
    """Try to decode one descriptor at `a`.  Returns dict or None."""
    if a + 28 > len(buf):
        return None
    c1, tc = struct.unpack_from(">HH", buf, a)
    ax, dp = struct.unpack_from(">II", buf, a + 4)
    if (1 <= c1 <= 512 and tc in _TYPECODE_WIDTH
            and CAL_LO <= ax < CAL_HI and CAL_LO <= dp < CAL_HI and ax + c1 * 4 == dp):
        return dict(addr=a, dim="1D", count=c1, width=_TYPECODE_WIDTH[tc],
                    data=dp, axes=[ax], counts=[c1])
    c2 = struct.unpack_from(">H", buf, a + 2)[0]
    a1, a2, dp2, tc2 = struct.unpack_from(">IIII", buf, a + 4)
    tch = tc2 >> 16
    if (1 <= c1 <= 512 and 1 <= c2 <= 512 and tc2 & 0xFFFF == 0 and tch in _TYPECODE_WIDTH
            and CAL_LO <= a1 < CAL_HI and a1 + c1 * 4 == a2 and a2 + c2 * 4 == dp2
            and dp2 < CAL_HI):
        return dict(addr=a, dim="2D", count=c1 * c2, width=_TYPECODE_WIDTH[tch],
                    data=dp2, axes=[a1, a2], counts=[c1, c2])
    return None


def _desc_loose_at(buf, a):
    """Decode a descriptor at an address CODE has already proven is one.

    Used only for addresses recovered from `jsr` sites in the feed trace, where
    the contiguity test is unnecessary because the code itself vouches for the
    address.  This recovers the shared-axis descriptors _desc_at rejects.
    """
    d = _desc_at(buf, a)
    if d is not None:
        return d
    if a + 28 > len(buf):
        return None
    c1, tc = struct.unpack_from(">HH", buf, a)
    ax, dp = struct.unpack_from(">II", buf, a + 4)
    if (1 <= c1 <= 512 and tc in _TYPECODE_WIDTH
            and CAL_LO <= ax < CAL_HI and CAL_LO <= dp < CAL_HI):
        return dict(addr=a, dim="1D", count=c1, width=_TYPECODE_WIDTH[tc],
                    data=dp, axes=[ax], counts=[c1], loose=True)
    c2 = struct.unpack_from(">H", buf, a + 2)[0]
    a1, a2, dp2, tc2 = struct.unpack_from(">IIII", buf, a + 4)
    tch = tc2 >> 16
    if (1 <= c1 <= 512 and 1 <= c2 <= 512 and tc2 & 0xFFFF == 0 and tch in _TYPECODE_WIDTH
            and CAL_LO <= a1 < CAL_HI and CAL_LO <= a2 < CAL_HI and CAL_LO <= dp2 < CAL_HI):
        return dict(addr=a, dim="2D", count=c1 * c2, width=_TYPECODE_WIDTH[tch],
                    data=dp2, axes=[a1, a2], counts=[c1, c2], loose=True)
    return None


def scan_descriptors(buf):
    """Return list of dicts: addr, dim, count, width, data, axes[], implied_width.

    `implied_width` is a SECOND, independent read on bytes/cell: the distance
    from this table's data pointer to the next known table boundary (any other
    descriptor's axis or data pointer) divided by the cell count.  Where the
    typecode and the spacing agree, the width is doubly attested; where they
    disagree, this script refuses to raise a CONFLICT on width.

    Aggregate agreement over all 780 descriptors (spacing verdict per typecode):
        typecode 0x0000 -> 4 bytes  243 agree,  25 disagree
        typecode 0x0400 -> 1 byte    67 agree,  24 disagree
        typecode 0x0800 -> 2 bytes  147 agree,   2 disagree
    """
    import bisect
    out = []
    for a in range(DESC_LO, DESC_HI - 28, 4):
        d = _desc_at(buf, a)
        if d is not None:
            out.append(d)
    bounds = sorted({p for x in out for p in [x["data"]] + list(x["axes"])})
    for x in out:
        i = bisect.bisect_right(bounds, x["data"])
        x["implied_width"] = None
        if i < len(bounds) and x["count"]:
            gap = bounds[i] - x["data"]
            for cand in (1, 2, 4):
                if gap == x["count"] * cand:
                    x["implied_width"] = cand
    return out


# ---- D3: which RAM variable feeds a table-lookup axis? --------------------

def trace_axis_feeds(buf):
    """Linear symbolic trace: RAM address -> descriptor it indexes.

    Tracks pool literals in R0-R15 and, for FR0-FR15, a TAG naming the RAM
    address whose contents were loaded into that FP register.  At every
    `jsr @Rn` where Rn holds 0xBE830 (1D lookup) or 0xBE8E4 (2D lookup) the
    delay slot is applied first, then (R4 = descriptor, FR4 tag, FR5 tag) is
    recorded.  State is cleared at `rts` so tags cannot leak across functions.

    Returns {ram_addr: Counter({descriptor_addr: hits})} for the FR4 (first
    axis) input, and the same for FR5.
    """
    reg = [None] * 16
    fr = [None] * 16
    fr4 = defaultdict(Counter)
    fr5 = defaultdict(Counter)

    def step(pc, w):
        hi, n, m, lo = (w >> 12), (w >> 8) & 0xF, (w >> 4) & 0xF, w & 0xF
        if hi == 0xD:                                   # mov.l @(d,PC),Rn
            slot = ((pc + 4) & ~3) + (w & 0xFF) * 4
            reg[n] = struct.unpack_from(">I", buf, slot)[0] if slot + 4 <= len(buf) else None
        elif hi == 0xE:                                 # mov #imm,Rn
            # SH-2E SIGN-EXTENDS the 8-bit immediate.  Reading it unsigned put
            # e.g. `mov #-120,r0` at +136, shifting every computed RAM address
            # by exactly 256 -- self-consistently, so it looked correct.
            _imm = w & 0xFF
            reg[n] = _imm - 0x100 if _imm & 0x80 else _imm
        elif hi == 6 and lo == 3:                       # mov Rm,Rn
            reg[n] = reg[m]
        elif hi == 0xF and lo == 8:                     # fmov.s @Rm,FRn
            fr[n] = reg[m]
        elif hi == 0xF and lo == 0xC:                   # fmov FRm,FRn
            fr[n] = fr[m]
        elif hi == 0xF and lo == 6:                     # fmov.s @(R0,Rm),FRn
            fr[n] = None
        elif hi == 6 and lo in (0, 1, 2):               # integer load clobbers Rn
            reg[n] = None

    desc_consumers = collections.defaultdict(set)

    pc = 0x400
    end = 0x0A0000
    while pc < end - 2:
        w = struct.unpack_from(">H", buf, pc)[0]
        if w == 0x000B:                                 # rts -> new function soon
            step(pc + 2, struct.unpack_from(">H", buf, pc + 2)[0])
            reg = [None] * 16
            fr = [None] * 16
            pc += 4
            continue
        if (w & 0xF0FF) == 0x400B:                      # jsr @Rn
            target = reg[(w >> 8) & 0xF]
            dslot = struct.unpack_from(">H", buf, pc + 2)[0]
            step(pc + 2, dslot)
            if target in LOOKUP_ALL:
                desc = reg[4]
                if desc is not None and DESC_LO <= desc < DESC_HI:
                    desc_consumers[desc].add(target)
                    if fr[4] is not None and RAM_LO <= fr[4] < RAM_HI:
                        fr4[fr[4]][desc] += 1
                    if target != LOOKUP_1D and fr[5] is not None and RAM_LO <= fr[5] < RAM_HI:
                        fr5[fr[5]][desc] += 1
            pc += 4
            continue
        step(pc, w)
        pc += 2
    return fr4, fr5, desc_consumers


# ---- region map (holes + data/code block classification) ------------------

def load_region_map():
    holes, blocks = [], []
    mode = None
    with open(REGION_MAP, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if "ROM HOLES" in line:
                mode = "holes"
                continue
            if "Region boundaries" in line:
                mode = "blocks"
                continue
            if mode == "holes":
                m = re.match(r"\s*0x([0-9A-Fa-f]+)-0x([0-9A-Fa-f]+)\s+\d+ bytes", line)
                if m:
                    holes.append((int(m.group(1), 16), int(m.group(2), 16)))
            elif mode == "blocks":
                m = re.match(r"\s*0x([0-9A-Fa-f]+)-0x([0-9A-Fa-f]+)\s+\d+ bytes\s+(\w+)", line)
                if m:
                    blocks.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3)))
    return holes, blocks


# ==========================================================================
# 3.  Disassembly-corpus CLAIMS (never treated as truth)
# ==========================================================================

def parse_ram_reference():
    """addr -> dict(name, desc, line).  Claims only."""
    out = {}
    with open(RAM_REFERENCE, encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            m = re.match(r"\s*(?:\d+\s+)?0x(FFFF[0-9A-Fa-f]{4})\s+(\S+)\s*(.*)$", line)
            if m:
                a = int(m.group(1), 16)
                if a not in out:
                    out[a] = dict(name=m.group(2), desc=m.group(3).strip(), line=n)
    return out


def parse_cal_crossref():
    out = {}
    with open(CAL_CROSSREF, encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            m = re.match(r"\s*0x([0-9A-Fa-f]{6})\s+(\S+)\s*(.*)$", line)
            if m:
                out.setdefault(int(m.group(1), 16), dict(label=m.group(2), line=n))
    return out


_HEX = re.compile(r"0x([0-9A-Fa-f]{4,8})\b")


def index_mentions(wanted):
    """address -> sorted list of corpus files that mention it.

    Coverage signal ONLY: it says the disassembly layer has looked at an
    address, not that what it concluded is right.
    """
    hits = defaultdict(set)
    files = []
    for d in (ANALYSIS, MAPS):
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if fn.endswith(".txt"):
                files.append(os.path.join(d, fn))
    for path in files:
        rel = os.path.relpath(path, REPO).replace("\\", "/")
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for m in _HEX.finditer(text):
            v = int(m.group(1), 16)
            if v in wanted:
                hits[v].add(rel)
    return {k: sorted(v) for k, v in hits.items()}, len(files)


# ==========================================================================
# 4.  Definition-side byte validation
# ==========================================================================

def _finite(v):
    return isinstance(v, (int, float)) and v == v and abs(v) != float("inf")


def check_bytes(read_fn, scaling, monotonic=False):
    """Decode and sanity-check.  Returns (ok, notes, out_of_range_count)."""
    notes = []
    try:
        vals = read_fn()
    except Exception as exc:                                  # noqa: BLE001
        return False, ["decode failed: %s" % exc], 0
    flat = []
    if isinstance(vals, list):
        for v in vals:
            flat.extend(v if isinstance(v, list) else [v])
    else:
        flat = [vals]
    nums = [v for v in flat if isinstance(v, (int, float))]
    if len(nums) != len(flat):
        return True, [], 0                                    # bloblist / enum
    bad = [v for v in nums if not _finite(v)]
    if bad:
        notes.append("%d of %d cells decode NaN/Inf" % (len(bad), len(nums)))
        return False, notes, 0
    oor = 0
    if scaling is not None and scaling.min is not None and scaling.max is not None:
        span = abs(scaling.max - scaling.min) or 1.0
        tol = span * 1e-4
        oor = sum(1 for v in nums if v < scaling.min - tol or v > scaling.max + tol)
    if monotonic and len(nums) > 1:
        if any(b < a for a, b in zip(nums, nums[1:])) and any(b > a for a, b in zip(nums, nums[1:])):
            notes.append("axis breakpoints are not monotonic")
            return False, notes, oor
    return True, notes, oor


# ==========================================================================
# 5.  Physical-quantity vocabulary (for the RAM feed cross-check)
# ==========================================================================

_QUANTITY = [
    ("rpm", r"\b(rpm|engine speed|revolution)"),
    ("load", r"(engine load|\bload\b|g/rev)"),
    ("coolant", r"(coolant|\bect\b)"),
    ("intake_air_temp", r"(intake (air )?temp|\biat\b)"),
    ("vehicle_speed", r"(vehicle speed|\bmph\b|\bkm/?h\b|\bspeed\b)"),
    ("pressure", r"(manifold pressure|\bmap\b|barometric|atmospheric|boost|\bpsi\b|\bbar\b|mmhg)"),
    ("airflow", r"(\bmaf\b|air ?flow|g/s)"),
    ("throttle", r"(throttle|\btps\b|accelerator|pedal)"),
    ("voltage", r"(voltage|\bvolt)"),
    ("time", r"(\btime\b|delay|counter|timer)"),
    ("gear", r"\bgear\b"),
]


def quantity_of(text):
    if not text:
        return None
    t = text.lower()
    for q, pat in _QUANTITY:
        if re.search(pat, t):
            return q
    return None


# ==========================================================================
# 6.  Build entities and classify
# ==========================================================================

class Entity(dict):
    pass


def interval_cover(spans):
    """Merge (lo,hi) spans; return sorted merged list and total bytes."""
    if not spans:
        return [], 0
    s = sorted(spans)
    out = [list(s[0])]
    for lo, hi in s[1:]:
        if lo <= out[-1][1]:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return [tuple(x) for x in out], sum(h - l for l, h in out)


def build(d, stock, rev, quiet=False):
    def say(*a):
        if not quiet:
            print(*a)

    say("  indexing ROM literal pool ...")
    lit = literal_index(stock)
    say("  scanning table descriptors from ROM bytes ...")
    descs = scan_descriptors(stock)
    say("    %d descriptors decoded (%d 1D, %d 2D)"
        % (len(descs), sum(1 for x in descs if x["dim"] == "1D"),
           sum(1 for x in descs if x["dim"] == "2D")))
    say("  tracing RAM -> table-lookup axis feeds ...")
    fr4, fr5, desc_consumers = trace_axis_feeds(stock)
    say("    %d RAM variables reach a lookup axis at %d call sites"
        % (len(fr4) + len(fr5),
           sum(sum(c.values()) for c in fr4.values()) + sum(sum(c.values()) for c in fr5.values())))

    ramref = parse_ram_reference()
    calref = parse_cal_crossref()
    holes, blocks = load_region_map()

    desc_by_data = defaultdict(list)
    desc_by_axis = defaultdict(list)
    for x in descs:
        desc_by_data[x["data"]].append(x)
        for a in x["axes"]:
            desc_by_axis[a].append(x)

    # ---- axis address -> definition-given name(s) ----
    # Two separate things: a DISPLAY label ("table / axis") and the physical
    # QUANTITY.  The quantity is taken from the axis element's own name only --
    # never from the table name, because table names carry parenthetical
    # qualifiers ("... Compensation (IAT)", "Tau Input A Rising Load") that would
    # otherwise decide the quantity of an axis that measures something else.
    axis_names = defaultdict(set)
    _axis_q_votes = defaultdict(Counter)
    for t in d.tables:
        for a in t.axes:
            if a.address is not None:
                axis_names[a.address].add("%s / %s" % (t.name, a.name))
                q = quantity_of(a.name)
                if q:
                    _axis_q_votes[a.address][q] += 1
    axis_q = {addr: sorted(v.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
              for addr, v in _axis_q_votes.items()}

    # ---- empirical envelope per physical quantity -----------------------
    # Built from the definitions themselves: for every axis the definition XMLs
    # NAME (e.g. "Engine Load", "Vehicle Speed"), read its raw big-endian float
    # breakpoints out of the ROM.  That gives, per quantity, the span the ROM
    # actually uses.  It is what lets an UNNAMED traced axis still contradict a
    # claimed identity -- e.g. a 0..120 span cannot be g/rev, because every
    # definition-named engine-load axis in this ROM tops out near 5.
    envelope = {}
    for ax_addr, q in sorted(axis_q.items()):
        for t in d.tables:
            for ax in t.axes:
                if ax.address != ax_addr or ax.scaling is None or ax.scaling.width != 4:
                    continue
                try:
                    bp = struct.unpack_from(">%df" % min(ax.elements or 0, 64),
                                            stock, ax_addr)
                except (struct.error, TypeError):
                    continue
                if not bp or not all(v == v and abs(v) < 1e9 for v in bp):
                    continue
                lo, hi = min(bp), max(bp)
                cur = envelope.get(q)
                envelope[q] = (min(cur[0], lo), max(cur[1], hi)) if cur else (lo, hi)
                break

    entities = []
    def_spans = []

    # ---------------- ROM entities from the definitions -------------------
    for t in d.tables:
        rows = [("table", t.name, t, None)]
        for a in t.axes:
            if not a.is_static:
                rows.append(("axis", "%s / %s" % (t.name, a.name), t, a))
        for kind, label, tbl, ax in rows:
            obj = ax if ax is not None else tbl
            addr = obj.address
            scaling = obj.scaling
            e = Entity(
                kind=kind, name=label, category=tbl.category,
                address=("0x%05X" % addr) if addr is not None else None,
                defs_source="project XML line %s" % tbl.line,
                declared=None, evidence=[], notes=[], flag=None, suspect_side=None,
            )
            if scaling is not None:
                e["declared"] = dict(
                    scaling=scaling.name, storagetype=scaling.storagetype,
                    toexpr=scaling.toexpr, units=scaling.units or None,
                    min=scaling.min, max=scaling.max,
                    raw_is_display=scaling.raw_is_display)
            else:
                e["declared"] = dict(scaling=obj.scaling_name, storagetype=None)

            # -- readability -------------------------------------------
            if ax is None:
                readable = tbl.readable
                why = None if readable else tbl._why_unreadable()
                width = scaling.width if scaling else 0
                cells = tbl.n_cells
                nbytes = tbl.byte_length
            else:
                readable = (addr is not None and scaling is not None
                            and (ax.elements or 0) > 0 and scaling.width > 0
                            and addr + ax.byte_length <= ROM_SIZE)
                why = ("scaling %r undefined" % ax.scaling_name if scaling is None
                       else "no address" if addr is None
                       else "no element count" if not ax.elements else "extent outside ROM")
                width = scaling.width if scaling else 0
                cells = ax.elements or 0
                nbytes = ax.byte_length
            e["geometry"] = dict(cells=cells, bytes_per_cell=width, byte_length=nbytes)

            if not readable:
                e["notes"].append("definition unreadable: %s" % why)
                e["flag"] = "DEFS-ONLY"
                entities.append(e)
                continue

            def_spans.append((addr, addr + nbytes))

            # -- byte validation, both ROMs ----------------------------
            # A patch table injected into the big 0xFF ROM hole (launch control
            # at 0xF1000+) does not exist in the factory ROM.  Reading 0xFF as a
            # float gives NaN, which is not a definition defect -- so the stock
            # check is skipped for those and the tuned rev carries the test.
            mono = kind == "axis"
            in_hole = any(lo <= addr < hi for lo, hi in holes)
            ok_r, n_r, oor_r = check_bytes(
                (lambda o=obj, b=rev: o.read(b)), scaling, mono)
            if in_hole:
                ok_s, n_s, oor_s = ok_r, [], oor_r
                e["notes"].append(
                    "address lies in a factory 0xFF ROM hole -- this is injected "
                    "patch data; validated against %s only" % REV_NAME)
            else:
                ok_s, n_s, oor_s = check_bytes(
                    (lambda o=obj, b=stock: o.read(b)), scaling, mono)
            e["bytes_ok"] = dict(stock=ok_s, rev=ok_r)
            for m in n_s:
                e["notes"].append("stock: " + m)
            for m in n_r:
                if m not in n_s:
                    e["notes"].append("%s: %s" % (REV_NAME, m))
            e["out_of_declared_range"] = dict(stock=oor_s, rev=oor_r)

            # -- D1 literal-pool dereference ---------------------------
            obs = deref_widths(stock, lit, addr)
            if obs:
                e["evidence"].append(dict(
                    source="D1 literal-pool dereference (re-derived from ROM bytes)",
                    detail=", ".join("%s x%d" % (k, v) for k, v in sorted(obs.items()))))
            # -- D2 descriptor -----------------------------------------
            dsc = desc_by_data.get(addr, []) + desc_by_axis.get(addr, [])
            if dsc:
                x = dsc[0]
                e["evidence"].append(dict(
                    source="D2 ROM table descriptor @0x%05X" % x["addr"],
                    detail="%s, %d cells x %d byte%s%s; spacing to the next known "
                           "table boundary implies %s bytes/cell"
                           % (x["dim"], x["count"], x["width"],
                              "" if x["width"] == 1 else "s",
                              " (axis pointer)" if addr in desc_by_axis else " (data pointer)",
                              x.get("implied_width") or "nothing")))
            # -- D5 Ghidra label ---------------------------------------
            if addr in calref:
                e["evidence"].append(dict(
                    source="D5 cal_crossref.txt:%d" % calref[addr]["line"],
                    detail="Ghidra label %s" % calref[addr]["label"]))

            # -- agreement ---------------------------------------------
            want = _ACCESS_CLASS.get(scaling.storagetype)
            contradiction = None
            if obs and want and want not in obs:
                # show BOTH readings, scaled, so the size of the error is visible
                seen_cls = sorted(obs, key=lambda k: -obs[k])[0]
                alt_fmt = {"float": ">f", "int32": ">i", "int16": ">h", "int8": ">b"}[seen_cls]
                try:
                    alt = struct.unpack_from(alt_fmt, stock, addr)[0]
                    alt_s = "%.6g" % alt
                except struct.error:
                    alt_s = "?"
                try:
                    dec = scaling.fmt(scaling.to_display(
                        scaling.decode(stock, addr, 1)[0]))
                except Exception:                                # noqa: BLE001
                    dec = "?"
                contradiction = ("ROM code dereferences 0x%05X as %s; declared "
                                 "storagetype %s (%s) is never used. The definition "
                                 "shows %s %s; read the way the code reads it (%s) "
                                 "the same bytes are %s"
                                 % (addr, "/".join(sorted(obs)), scaling.storagetype,
                                    scaling.name, dec, scaling.units or "(no units)",
                                    seen_cls, alt_s))
            if dsc and contradiction is None:
                x = next((y for y in dsc if y["data"] == addr), None)
                # A width disagreement is only raised when BOTH independent
                # descriptor signals -- the typecode field and the spacing to the
                # next table boundary -- point away from the declared width.  One
                # signal alone is recorded as evidence, not as a conflict.
                # DEFECT (c) fix: six of the eight lookup routines HARDCODE the
                # cell width and never read the descriptor's typecode field, so
                # their descriptors carry a dead 0x0000 typecode -- which decodes
                # as "4 bytes/cell, float".  Treating that as a width claim
                # manufactured false conflicts against correct uint16 definitions
                # (0xD106C Injector Latency_, 0xD3C2C Rough Correction Learning
                # Delay).  If every routine that consumes this descriptor is one
                # of the six, the typecode carries no information at all.
                _consumers = desc_consumers.get(x["addr"]) if x is not None else None
                _typecode_is_dead = bool(_consumers) and _consumers <= LOOKUP_WIDTH_HARDCODED
                if _typecode_is_dead and x is not None and x["width"] != width:
                    e["notes"].append(
                        "descriptor @0x%05X typecode implies %d byte(s)/cell, but "
                        "every routine that consumes it (%s) hardcodes the cell "
                        "width and never reads the typecode -- the field is dead, "
                        "so it is NOT evidence against the declared %s"
                        % (x["addr"], x["width"],
                           "/".join("0x%05X" % c for c in sorted(_consumers)),
                           scaling.storagetype))
                elif (x is not None and x["width"] != width
                        and x.get("implied_width") in (None, x["width"])):
                    contradiction = ("ROM descriptor @0x%05X says %d byte%s/cell "
                                     "(typecode%s); declared storagetype %s is %d"
                                     % (x["addr"], x["width"],
                                        "" if x["width"] == 1 else "s",
                                        ", and the spacing to the next table "
                                        "boundary agrees" if x.get("implied_width")
                                        else "; spacing inconclusive",
                                        scaling.storagetype, width))
                elif x is not None and x["width"] != width:
                    e["notes"].append(
                        "descriptor typecode implies %d byte(s)/cell but the "
                        "spacing to the next table boundary implies %d, and the "
                        "definition says %d -- unresolved, NOT counted as a conflict"
                        % (x["width"], x["implied_width"], width))
                elif x is not None and x["count"] != cells:
                    contradiction = ("ROM descriptor @0x%05X says %d cells; "
                                     "definition says %d"
                                     % (x["addr"], x["count"], cells))

            # -- axis-side descriptor agreement -------------------------
            # Every descriptor this script accepts was accepted BECAUSE its axis
            # breakpoints are 4-byte floats (axis + count*4 == data).  So for an
            # axis entity the descriptor independently attests both the element
            # count and a 4-byte float storagetype.
            axis_ok = False
            if kind == "axis" and contradiction is None:
                for y in dsc:
                    if addr not in y["axes"]:
                        continue
                    i = y["axes"].index(addr)
                    n = y.get("counts", [y["count"]])[i]
                    if n != cells:
                        contradiction = ("ROM descriptor @0x%05X carries %d "
                                         "breakpoints on this axis; the definition "
                                         "declares elements=%d"
                                         % (y["addr"], n, cells))
                        break
                    if width != 4:
                        contradiction = ("ROM descriptor @0x%05X addresses this axis "
                                         "as %d 4-byte float breakpoints; the "
                                         "definition declares storagetype %s (%d "
                                         "byte(s)/element)"
                                         % (y["addr"], n, scaling.storagetype, width))
                        break
                    axis_ok = True

            corroborated = bool(
                (obs and want and want in obs)
                or any(y["data"] == addr and y["width"] == width and y["count"] == cells
                       for y in dsc)
                or axis_ok)

            e["_addr"] = addr
            e["_contradiction"] = contradiction
            e["_corroborated"] = corroborated
            entities.append(e)

    # ---------------- ROM entities the descriptors know but defs do not ----
    merged, _ = interval_cover(def_spans)

    def covered(lo, hi):
        for a, b in merged:
            if lo < b and a < hi:
                return True
        return False

    seen_desc_data = set()
    for x in descs:
        lo = x["data"]
        hi = lo + x["count"] * x["width"]
        if lo in seen_desc_data or covered(lo, hi):
            continue
        seen_desc_data.add(lo)
        entities.append(Entity(
            kind="rom-block", name="descriptor data @0x%05X (desc 0x%05X)" % (lo, x["addr"]),
            category="(no definition)", address="0x%05X" % lo,
            defs_source=None, declared=None,
            geometry=dict(cells=x["count"], bytes_per_cell=x["width"],
                          byte_length=x["count"] * x["width"]),
            evidence=[dict(source="D2 ROM table descriptor @0x%05X" % x["addr"],
                           detail="%s, %d cells x %d byte%s, axis %s"
                                  % (x["dim"], x["count"], x["width"],
                                     "" if x["width"] == 1 else "s",
                                     ", ".join("0x%05X" % a for a in x["axes"])))],
            notes=["no <table> in either definition XML covers these bytes"],
            flag="DISASM-ONLY", suspect_side=None, _addr=lo,
            _contradiction=None, _corroborated=False))

    # ---------------- RAM entities ----------------------------------------
    ram_lit = {v for v in lit if RAM_LO <= v < RAM_HI}
    ram_addrs = sorted(set(ramref) | set(fr4) | set(fr5) | ram_lit)
    for a in ram_addrs:
        claim = ramref.get(a)
        e = Entity(
            kind="ram", name=(claim["name"] if claim else "(unnamed)"),
            category="RAM variable", address="0x%08X" % a,
            defs_source=None,
            declared=(dict(claimed_name=claim["name"], claimed_desc=claim["desc"],
                           source="ram_reference.txt:%d" % claim["line"])
                      if claim else None),
            geometry=None, evidence=[], notes=[], flag=None, suspect_side=None,
            _addr=a, _contradiction=None, _corroborated=False)

        obs = deref_widths(stock, lit, a)
        feeds_probe = a in fr4 or a in fr5
        if claim is None and not obs and not feeds_probe:
            # a 4-aligned ROM word that merely LOOKS like a RAM pointer (float
            # data, packed constants) with no instruction ever dereferencing it.
            # Not evidence of anything; excluded so UNMAPPED stays meaningful.
            continue
        if obs:
            e["evidence"].append(dict(
                source="D1 literal-pool dereference (re-derived from ROM bytes)",
                detail=", ".join("%s x%d" % (k, v) for k, v in sorted(obs.items()))))

        # FR4 indexes the descriptor's FIRST axis, FR5 the second.  Attributing
        # both axes to both inputs would blur "load x RPM" into a tie and hide
        # exactly the class of error this registry exists to catch.
        feeds = Counter()
        quants = Counter()
        named = []
        ranges = []
        for slot, table in ((0, fr4), (1, fr5)):
            for desc_addr, hits in table.get(a, {}).items():
                feeds[desc_addr] += hits
                x = _desc_loose_at(stock, desc_addr)
                if x is None or slot >= len(x["axes"]):
                    continue
                ax_addr = x["axes"][slot]
                n = x.get("counts", [x["count"]])[slot] if slot < len(x.get("counts", [])) \
                    else x["count"]
                try:
                    bp = struct.unpack_from(">%df" % min(n, 64), stock, ax_addr)
                    if all(v == v and abs(v) < 1e9 for v in bp):
                        ranges.append((min(bp), max(bp)))
                except struct.error:
                    pass
                q = axis_q.get(ax_addr)
                if q:
                    quants[q] += hits
                    lbl = "0x%05X %s" % (ax_addr, sorted(axis_names[ax_addr])[0])
                    if lbl not in named and len(named) < 6:
                        named.append(lbl)
        if feeds:
            rng = ""
            if ranges:
                rng = "; breakpoint span %.4g..%.4g" % (min(r[0] for r in ranges),
                                                        max(r[1] for r in ranges))
            e["evidence"].append(dict(
                source="D3 RAM -> table-lookup axis feed trace (re-derived)",
                detail="%d call sites into %d descriptors%s; definition-named axes: %s"
                       % (sum(feeds.values()), len(feeds), rng,
                          "; ".join(named) if named else "none of the axes are named "
                                                         "in the definition XMLs")))
        e["_ranges"] = ranges

        # -- contradiction tests --------------------------------------
        if claim:
            claim_text = "%s %s" % (claim["name"], claim["desc"])
            # the NAME is the identity claim; the description is prose that often
            # mentions other quantities in passing, so it is only a fallback.
            claim_q = quantity_of(claim["name"].replace("_", " ")) or quantity_of(claim["desc"])
            # (a) declared float vs an access history with no float in it
            #
            # Match the word only inside the parenthesised TYPE SLOT -- "(float)",
            # "(float, g/rev)" -- which is how every genuine claim in
            # ram_reference.txt is written.  A bare \bfloat\b also matched the word
            # inside CORRECTIVE prose ("NOT a float", "0 float accesses"), so every
            # address we had just corrected re-flagged itself as a conflict against
            # its own correction note.
            n_obs = sum(obs.values())
            if (re.search(r"\(\s*(?:[^)]*,\s*)?float\b", claim_text, re.I)
                    and n_obs >= 5 and "float" not in obs):
                e["_contradiction"] = (
                    "ram_reference.txt:%d calls this a float, but every one of the "
                    "%d code sites that dereference it uses %s -- 0 float accesses. "
                    "That contradicts the STORAGE WIDTH claim; it does not by "
                    "itself disprove the name (the address could be the base of a "
                    "byte-sized field in a struct whose float lives at an offset)."
                    % (claim["line"], n_obs, "/".join(sorted(obs))))
                e["suspect_side"] = ("disassembly (ram_reference.txt) -- storage "
                                     "width claim unsupported by any code site")
            # (b) traced axis quantity vs claimed quantity
            if quants and claim_q:
                top, n = sorted(quants.items(), key=lambda kv: (-kv[1], kv[0]))[0]
                total = sum(quants.values())
                if top != claim_q and n >= 5 and n / total >= 0.8:
                    e["_contradiction"] = (
                        "traced as the axis input to %d of %d definition-named "
                        "lookup axes, and those axes are %s axes -- but "
                        "ram_reference.txt:%d names it %r, i.e. a %s. The "
                        "definition XMLs name the axis; the ROM code chooses what "
                        "feeds it. Both sides here are re-derived from bytes."
                        % (n, total, top, claim["line"], claim["name"], claim_q))
                    e["suspect_side"] = ("disassembly (ram_reference.txt) -- the "
                                         "definition-named axis is the independent "
                                         "side")
                elif top == claim_q and n >= 3:
                    e["_corroborated"] = True
            # (c) unnamed traced axes: contradict the claim by SPAN instead.
            #     The envelope comes from the definitions + ROM bytes, so this is
            #     still a definition-vs-disassembly test, not a guess.
            if not quants and ranges and claim_q and claim_q in envelope:
                lo = min(r[0] for r in ranges)
                hi = max(r[1] for r in ranges)
                elo, ehi = envelope[claim_q]
                pad = 0.05 * (ehi - elo or 1.0)
                if hi > ehi + pad or lo < elo - pad:
                    fits = [q for q, (a0, b0) in envelope.items()
                            if lo >= a0 - 0.05 * (b0 - a0 or 1)
                            and hi <= b0 + 0.05 * (b0 - a0 or 1)]
                    e["_contradiction"] = (
                        "traced feeding %d lookup axes spanning %.4g..%.4g, but every "
                        "definition-named %s axis in this ROM spans only %.4g..%.4g. "
                        "ram_reference.txt:%d names it %r. %s"
                        % (sum(feeds.values()), lo, hi, claim_q, elo, ehi,
                           claim["line"], claim["name"],
                           ("A span that size fits the definition envelope for: %s."
                            % ", ".join(sorted(fits))) if fits else
                           "No definition-named quantity in this ROM has that span."))
                    e["suspect_side"] = ("disassembly (ram_reference.txt) -- the "
                                         "definition-derived axis envelope is the "
                                         "independent side")
        if quants and not claim:
            e["notes"].append(
                "feeds %s axes but is not named in ram_reference.txt"
                % sorted(quants.items(), key=lambda kv: (-kv[1], kv[0]))[0][0])
        e["_quants"] = dict(quants)
        entities.append(e)

    return entities, dict(lit=lit, descs=descs, holes=holes, blocks=blocks,
                          def_spans=merged, ramref=ramref, calref=calref)


def classify(entities, mentions):
    for e in entities:
        if e.get("flag") == "DEFS-ONLY":
            continue
        a = e.get("_addr")
        if a is not None and a in mentions:
            e["evidence"].append(dict(
                source="D6 disassembly corpus mentions",
                detail="%d file(s): %s" % (len(mentions[a]), ", ".join(mentions[a][:3])
                                           + (" ..." if len(mentions[a]) > 3 else ""))))
        if e.get("flag") == "DISASM-ONLY":
            continue

        if e["kind"] == "ram":
            if e["_contradiction"]:
                e["flag"] = "CONFLICT"
                e["notes"].append(e["_contradiction"])
            elif e["_corroborated"]:
                e["flag"] = "VERIFIED-BOTH"
                e["suspect_side"] = None
            elif e.get("declared"):
                e["flag"] = "DISASM-ONLY"
            else:
                e["flag"] = "UNMAPPED"
            continue

        # ROM entity backed by a definition
        if e["_contradiction"]:
            e["flag"] = "CONFLICT"
            e["suspect_side"] = ("definition XML (declared storagetype/geometry) -- "
                                 "the ROM's own code and descriptors are the "
                                 "independent side here")
            e["notes"].append(e["_contradiction"])
            continue
        ok = e.get("bytes_ok", {})
        if not (ok.get("stock") and ok.get("rev")):
            e["flag"] = "CONFLICT"
            e["suspect_side"] = "definition XML (geometry or storagetype)"
            continue
        oor = e.get("out_of_declared_range", {})
        if oor.get("stock"):
            e["flag"] = "BOUNDS-SUSPECT"
            e["suspect_side"] = "definition XML (declared min/max)"
            e["notes"].append("%d of %d factory-ROM cells fall outside the declared "
                              "min/max %s..%s" % (oor["stock"], e["geometry"]["cells"],
                                                  e["declared"].get("min"),
                                                  e["declared"].get("max")))
            continue
        if oor.get("rev"):
            e["notes"].append("%d cells exceed declared bounds in %s only -- treated "
                              "as a deliberate tune edit, not a definition defect"
                              % (oor["rev"], REV_NAME))
        e["flag"] = "VERIFIED-BOTH" if e["_corroborated"] else "VERIFIED-BYTES"
    return entities


def unmapped_bytes(ctx):
    """ROM data bytes claimed by neither a definition nor a descriptor."""
    holes = ctx["holes"]
    spans = list(ctx["def_spans"])
    for x in ctx["descs"]:
        spans.append((x["data"], x["data"] + x["count"] * x["width"]))
        for ax in x["axes"]:
            spans.append((ax, ax + 4))          # axis width unknown; 4 is generous
    merged, _ = interval_cover(spans)

    def is_hole(p):
        return any(lo <= p < hi for lo, hi in holes)

    claimed = [False] * ROM_SIZE
    for lo, hi in merged:
        for p in range(max(0, lo), min(ROM_SIZE, hi)):
            claimed[p] = True
    total = 0
    unmapped = 0
    desc_band = 0          # unmapped bytes that are descriptor STRUCTS, not cells
    per_block = []
    for lo, hi, kind in ctx["blocks"]:
        if kind not in ("float_data", "uint8_data", "mixed_data"):
            continue
        n = 0
        for p in range(lo, min(hi, ROM_SIZE)):
            if is_hole(p):
                continue
            total += 1
            if not claimed[p]:
                n += 1
                unmapped += 1
                if DESC_LO <= p < DESC_HI:
                    desc_band += 1
        if n:
            per_block.append((lo, hi, kind, n))
    per_block.sort(key=lambda x: -x[3])
    return total, unmapped, per_block, desc_band


# ==========================================================================
# 7.  Emit
# ==========================================================================

def build_payload(entities, ctx, mentions, n_corpus_files):
    total_data, unmapped, per_block, desc_band = unmapped_bytes(ctx)
    by_flag = Counter(e["flag"] for e in entities)
    by_kind = Counter((e["kind"], e["flag"]) for e in entities)
    by_cat = defaultdict(Counter)
    for e in entities:
        if e["kind"] in ("table", "axis"):
            by_cat[e["category"] or "(none)"][e["flag"]] += 1

    clean = []
    for e in entities:
        rec = {k: v for k, v in e.items()
               if not k.startswith("_") and v not in (None, [], {}, "")}
        rec.setdefault("flag", e["flag"])
        rec.setdefault("kind", e["kind"])
        rec.setdefault("name", e["name"])
        rec.setdefault("address", e["address"])
        clean.append(rec)
    clean.sort(key=lambda r: (FLAG_ORDER.index(r["flag"]), r["kind"],
                              r["address"] or "", r["name"]))

    return dict(
        schema_version=SCHEMA_VERSION,
        generated=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        generator="scripts/coverage_map.py",
        warning="GENERATED FILE -- regenerate, never hand-edit. "
                "python scripts/coverage_map.py",
        inputs=dict(
            definitions=[os.path.relpath(defs.BASE_XML, REPO).replace("\\", "/"),
                         os.path.relpath(defs.PROJECT_XML, REPO).replace("\\", "/")],
            roms=[os.path.relpath(STOCK_ROM, REPO).replace("\\", "/"),
                  os.path.relpath(REV_ROM, REPO).replace("\\", "/")],
            disassembly_corpus_files=n_corpus_files,
        ),
        taxonomy=TAXONOMY,
        totals=dict(
            entities=len(entities),
            by_flag={f: by_flag.get(f, 0) for f in FLAG_ORDER},
            by_kind_flag={"%s/%s" % k: v for k, v in sorted(by_kind.items())},
            descriptors_decoded=len(ctx["descs"]),
            rom_data_bytes_considered=total_data,
            rom_data_bytes_unmapped=unmapped,
            rom_data_bytes_unmapped_pct=round(100.0 * unmapped / total_data, 1) if total_data else 0.0,
            rom_unmapped_bytes_in_descriptor_band=desc_band,
        ),
        by_category={k: dict(v) for k, v in sorted(by_cat.items())},
        watchlist=[dict(address=r["address"], name=r["name"], flag=r["flag"],
                        note=n)
                   for r in clean for n in r.get("notes", [])
                   if "NOT counted as a conflict" in n],
        largest_unmapped_blocks=[dict(start="0x%05X" % lo, end="0x%05X" % hi,
                                      region=kind, unmapped_bytes=n)
                                 for lo, hi, kind, n in per_block[:25]],
        entities=clean,
    )


def render_md(p):
    L = []
    a = L.append
    a("# Verification status registry")
    a("")
    a("**GENERATED FILE — do not hand-edit.** Regenerate with:")
    a("")
    a("```")
    a("python scripts/coverage_map.py")
    a("```")
    a("")
    a("Machine-readable companion: [`verification-status.json`](verification-status.json) "
      "(schema v%d). Generated %s." % (p["schema_version"], p["generated"]))
    a("")
    a("Every flag below is recomputed from scratch on each run: the definition side "
      "from `scripts/defs.py` over both definition XMLs, the disassembly side "
      "re-derived from ROM bytes (literal-pool dereference back-trace, table "
      "descriptors decoded out of ROM, and a RAM→lookup-axis feed trace). No "
      "conclusion is read out of a derived file and trusted. Agreement across "
      "derived files is not evidence.")
    a("")

    # ---- taxonomy ----
    a("## 1. Flag taxonomy")
    a("")
    a("Exactly one flag per entity. The rules are evaluated in the order shown; the "
      "first that fires wins, so the ladder is total and unambiguous.")
    a("")
    for i, t in enumerate(p["taxonomy"], 1):
        a("### %d. `%s`" % (i, t["flag"]))
        a("")
        a("**Means.** %s" % t["means"])
        a("")
        a("**Evidence required to claim it.** %s" % t["evidence_required"])
        a("")
        a("**Invalidated by.** %s" % t["invalidated_by"])
        a("")

    # ---- coverage ----
    tot = p["totals"]
    a("## 2. Coverage")
    a("")
    a("%d entities: every addressed definition table and axis, every calibration "
      "block a ROM descriptor points at, and every RAM address either named in "
      "`ram_reference.txt` or referenced by a ROM literal pool." % tot["entities"])
    a("")
    a("| Flag | Entities | Share |")
    a("|---|---:|---:|")
    for f in FLAG_ORDER:
        n = tot["by_flag"][f]
        a("| `%s` | %d | %.1f%% |" % (f, n, 100.0 * n / tot["entities"]))
    a("")
    a("### By entity kind")
    a("")
    kinds = sorted({k.split("/")[0] for k in tot["by_kind_flag"]})
    a("| Kind | " + " | ".join("`%s`" % f for f in FLAG_ORDER) + " |")
    a("|---" * (len(FLAG_ORDER) + 1) + "|")
    for k in kinds:
        row = [tot["by_kind_flag"].get("%s/%s" % (k, f), 0) for f in FLAG_ORDER]
        a("| %s | " % k + " | ".join(str(x) for x in row) + " |")
    a("")
    a("`table` / `axis` are definition-backed. `rom-block` is a calibration block a "
      "ROM descriptor points at that no `<table>` covers. `ram` is a RAM variable — "
      "RAM is outside the ROM image, so no definition can ever cover it and the "
      "definition side contributes only indirectly, through the names of the axes a "
      "RAM variable is traced feeding.")
    a("")

    a("### Unmapped ROM bytes")
    a("")
    a("Bytes the region map classifies as data (not code, not a 0xFF hole) and that "
      "no definition extent and no descriptor extent claims:")
    a("")
    a("- data bytes considered: **%s**" % f"{tot['rom_data_bytes_considered']:,}")
    a("- unmapped: **%s (%.1f%%)**" % (f"{tot['rom_data_bytes_unmapped']:,}",
                                       tot["rom_data_bytes_unmapped_pct"]))
    a("- of which %s bytes lie inside the descriptor band `0x0A0000-0x0BE000` — "
      "those are descriptor STRUCTS and lookup-helper constants, not table cells, "
      "so they are unmapped by nature rather than by neglect. Excluding them, "
      "**%s of %s calibration data bytes (%.1f%%) are claimed by nothing**."
      % (f"{tot['rom_unmapped_bytes_in_descriptor_band']:,}",
         f"{tot['rom_data_bytes_unmapped'] - tot['rom_unmapped_bytes_in_descriptor_band']:,}",
         f"{tot['rom_data_bytes_considered'] - tot['rom_unmapped_bytes_in_descriptor_band']:,}",
         100.0 * (tot['rom_data_bytes_unmapped'] - tot['rom_unmapped_bytes_in_descriptor_band'])
         / max(1, tot['rom_data_bytes_considered'] - tot['rom_unmapped_bytes_in_descriptor_band'])))
    a("")
    if p["largest_unmapped_blocks"]:
        a("Largest unmapped data blocks:")
        a("")
        a("| Block | Region class | Unmapped bytes |")
        a("|---|---|---:|")
        for b in p["largest_unmapped_blocks"][:15]:
            a("| `%s`–`%s` | %s | %s |" % (b["start"], b["end"], b["region"],
                                            f"{b['unmapped_bytes']:,}"))
        a("")

    # ---- per category ----
    a("## 3. Per definition category")
    a("")
    a("| Category | " + " | ".join("`%s`" % f for f in FLAG_ORDER) + " | total |")
    a("|---" * (len(FLAG_ORDER) + 2) + "|")
    for cat, counts in sorted(p["by_category"].items(),
                              key=lambda kv: -sum(kv[1].values())):
        row = [counts.get(f, 0) for f in FLAG_ORDER]
        a("| %s | " % cat + " | ".join(str(x) for x in row) + " | %d |" % sum(row))
    a("")

    # ---- detail sections ----
    def section(flag, title, blurb, limit=None, collapse=False):
        rows = [e for e in p["entities"] if e["flag"] == flag]
        a("## %s" % title)
        a("")
        a("%s **%d entities.**" % (blurb, len(rows)))
        a("")
        if not rows:
            a("_None._")
            a("")
            return
        extra = {}
        if collapse:
            seen, uniq = {}, []
            for e in rows:
                k = e["address"]
                if k in seen:
                    extra[k] = extra.get(k, 0) + 1
                    continue
                seen[k] = e
                uniq.append(e)
            rows = uniq
            a("Collapsed by address: a shared axis (the ECT axis at `0xCC624` serves "
              "34 tables) would otherwise repeat once per consumer.")
            a("")
        shown = rows if limit is None else rows[:limit]
        for e in shown:
            if extra.get(e["address"]):
                e = dict(e, name="%s  (+%d more tables at this address)"
                                 % (e["name"], extra[e["address"]]))
            a("- **`%s`** — %s  \n  _%s_" % (e["address"], e["name"],
                                             e.get("category") or ""))
            for n in e.get("notes", []):
                a("  - %s" % n)
            if e.get("suspect_side"):
                a("  - **suspect side:** %s" % e["suspect_side"])
            for ev in e.get("evidence", []):
                if ev["source"].startswith("D6"):
                    continue
                a("  - evidence: %s — %s" % (ev["source"], ev["detail"]))
        if limit is not None and len(rows) > limit:
            a("")
            a("_… %d more; see `verification-status.json`._" % (len(rows) - limit))
        a("")

    section("CONFLICT", "4. `CONFLICT` — settle these from bytes",
            "Two independent sides make incompatible claims about the same address. "
            "Nothing downstream of these should be trusted until a human settles them "
            "from ROM bytes — and settles them in the right direction.")
    section("BOUNDS-SUSPECT", "5. `BOUNDS-SUSPECT` — editor will clamp",
            "The bytes are read correctly; the definition's declared min/max is "
            "contradicted by the factory ROM's own data. ECUFlash/RomRaider clamp on "
            "write, so these bounds can silently refuse a legitimate value.",
            collapse=True)
    section("DEFS-ONLY", "6. `DEFS-ONLY` — definition too incomplete to check",
            "A `<table>` exists but has no usable storagetype or address, so it "
            "cannot be decoded here and cannot be opened in a tuning editor either.")

    a("## 6b. Watchlist — width disagreements deliberately NOT called conflicts")
    a("")
    a("For these the descriptor's typecode field and the spacing to the next table "
      "boundary point at different cell widths, and the definition agrees with "
      "neither or with only one. Two weak signals disagreeing is not a conflict, so "
      "the flag ladder leaves these where the byte checks put them — but they are "
      "the best candidates for the next `0xC0BCC`-class find, so they are listed "
      "rather than buried.")
    a("")
    if p["watchlist"]:
        for w in p["watchlist"]:
            a("- **`%s`** — %s (currently `%s`)" % (w["address"], w["name"], w["flag"]))
            a("  - %s" % w["note"])
    else:
        a("_None._")
    a("")

    rows = [e for e in p["entities"] if e["flag"] == "DISASM-ONLY" and e["kind"] == "ram"]
    a("## 7. `DISASM-ONLY` — RAM identities resting on one source")
    a("")
    a("%d RAM variables are named only in `ram_reference.txt`, with no independent "
      "corroboration from the feed trace. Three of this project's four wrong-direction "
      "corrections were exactly this shape: a plausible name in one derived file, "
      "copied everywhere, never re-derived. The top entries by reference count are "
      "listed; the full set is in the JSON." % len(rows))
    a("")
    def _d1(e):
        return next((ev["detail"] for ev in e.get("evidence", [])
                     if ev["source"].startswith("D1")), "")

    def _n(e):
        return sum(int(x.split("x")[-1]) for x in _d1(e).split(", ") if "x" in x)

    rows.sort(key=lambda e: (-_n(e), e["address"]))
    a("| Address | Claimed name | Code access widths |")
    a("|---|---|---|")
    for e in rows[:30]:
        a("| `%s` | %s | %s |" % (e["address"], e["name"], _d1(e) or "—"))
    if len(rows) > 30:
        a("")
        a("_… %d more in the JSON._" % (len(rows) - 30))
    a("")

    a("## 8. How to use this before trusting an area")
    a("")
    a("1. Find the table, axis or RAM address in `verification-status.json` "
      "(`entities[].address`).")
    a("2. `VERIFIED-BOTH` — safe to reason from, including about identity.")
    a("3. `VERIFIED-BYTES` — safe to reason about *contents*, **not** about *meaning*. "
      "A wrong-identity error of the `0xC0BCC` class would not have been caught.")
    a("4. `BOUNDS-SUSPECT` — the value is right, the editor's limits are not. Do not "
      "conclude a value is out of spec because the tool clamped it.")
    a("5. `CONFLICT` — stop. Settle it from ROM bytes and record the result in "
      "`docs/corrections.md` before building anything on top.")
    a("6. `DEFS-ONLY` / `DISASM-ONLY` / `UNMAPPED` — there is no cross-check. State "
      "that in whatever you write, per rule 6 in `CLAUDE.md`.")
    a("")
    return "\n".join(L) + "\n"


# ==========================================================================
# 8.  main
# ==========================================================================

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="regenerate in memory and exit 1 if the on-disk registry "
                         "differs (proves it is not hand-maintained)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    def say(*a):
        if not args.quiet:
            print(*a)

    say("coverage_map.py -- regenerating verification status from scratch")
    d = defs.load()
    say("  definitions: %d project tables, %d addressed axes"
        % (len(d.tables), d.summary()["axes_addressed"]))
    stock = load_rom(STOCK_ROM)
    rev = load_rom(REV_ROM)

    entities, ctx = build(d, stock, rev, quiet=args.quiet)
    wanted = {e["_addr"] for e in entities if e.get("_addr") is not None}
    say("  indexing disassembly-corpus mentions of %d addresses ..." % len(wanted))
    mentions, n_files = index_mentions(wanted)
    say("    %d of %d addresses are mentioned somewhere in %d corpus files"
        % (len(mentions), len(wanted), n_files))
    classify(entities, mentions)

    payload = build_payload(entities, ctx, mentions, n_files)
    js = json.dumps(payload, indent=1, sort_keys=False) + "\n"
    md = render_md(payload)

    if args.check:
        bad = []
        for path, text in ((OUT_JSON, js), (OUT_MD, md)):
            if not os.path.exists(path):
                bad.append("%s missing" % path)
                continue
            cur = open(path, encoding="utf-8").read()
            cur = re.sub(r'"generated": "[^"]*"', "", cur)
            cur = re.sub(r"Generated \d{4}-\d\d-\d\d \d\d:\d\d", "", cur)
            new = re.sub(r'"generated": "[^"]*"', "", text)
            new = re.sub(r"Generated \d{4}-\d\d-\d\d \d\d:\d\d", "", new)
            if cur != new:
                bad.append("%s is stale or hand-edited" % path)
        if bad:
            print("STALE: " + "; ".join(bad))
            return 1
        print("registry is current")
        return 0

    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(js)
    with open(OUT_MD, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(md)

    t = payload["totals"]
    say("")
    say("  wrote %s" % os.path.relpath(OUT_MD, REPO))
    say("  wrote %s" % os.path.relpath(OUT_JSON, REPO))
    say("")
    say("  %-16s %s" % ("ENTITIES", t["entities"]))
    for f in FLAG_ORDER:
        say("  %-16s %5d  %5.1f%%" % (f, t["by_flag"][f],
                                      100.0 * t["by_flag"][f] / t["entities"]))
    say("  %-16s %s of %s data bytes (%.1f%%)"
        % ("UNMAPPED bytes", f"{t['rom_data_bytes_unmapped']:,}",
           f"{t['rom_data_bytes_considered']:,}", t["rom_data_bytes_unmapped_pct"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
