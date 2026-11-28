#!/usr/bin/env python3
"""Emulation check for ROM functions 0x03AF88..0x03B3DA (423 instructions, GBR 0xFFFF7C80)
and 0x03AB94..0x03AE5A (287 instructions, GBR 0xFFFF7C6C).

    python3 scripts/trace/emu_fns_03AF88_03AB94.py

Reference bin: rom/AE5L600L 20g rev 20.19c.bin  md5 92cae8275cd4f9b473a3a9e36efe6449
Second bin   : rom/ae5l600l.bin (stock)         md5 a8ea39d447f977e270e27ee670243c88
               (code, pools and pointer tables are byte-identical; it is run because the 20.19c
               table behind descriptor 0x0AD40C is flat, so only the stock bin exercises interpolation)

What it does
------------
Runs each function in scripts/sh2e_emu.py (every callee -- 0x022CF4, 0x0BE554, 0x0BE598, 0x0BE5D8,
0x0BE960, 0x0BE830 -- executed from ROM, nothing stubbed) and compares against a Python model written
from the bytes (disassembly/analysis/fns_03AF88_03AB94_trace.txt). Per case it asserts:

  * every output RAM cell, bit for bit
  * the exact SET of non-stack RAM bytes written (nothing else is touched)
  * the exact SET of RAM cells read before being written in the same call (inputs are poked WITHOUT
    marking them initialised, so each input read lands in emu.uninit_reads)
  * callee-saved state: r8-r14, r15, GBR, fr12-fr15 restored

Float arithmetic in the model: every fadd is computed exactly and rounded TOWARD ZERO (rz_add), the
SH7058 rounding the emulator implements (corrections item 106). The table value of 0x0AD40C is taken
from an emulator call of 0x0BE830 itself (bit-exact composition); 0x0BE830 is checked separately against
linear interpolation of desc_types.read_table() with a tolerance. In 0x03AF88 every float step is exact
(integers <= 1,048,560.5 < 2^24), so the model there is pure integer arithmetic.

Names here are neutral on purpose: nothing in this script establishes what any RAM cell physically is.

Review additions (2026-11-27, deciding read): pass_a_section2 (item A13: every branch of 0x03AF88 section 2
asserted on emulated RAM), the r6 / T / no-write check of 0x022CF4 in check_callees (item M2), the
[6624] < 10000 edge gate in seq_b (item M3) and check_phantom_writers (item M5: the find_writers hits at
0370B6 / 0373D6 / 037546 / 037552 are pool longs).
"""
import hashlib
import itertools
import math
import os
import random
import struct
import sys
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, 'scripts'))
import sh2e_emu as E          # noqa: E402
import desc_types as DT       # noqa: E402

BIN = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
ROM = open(BIN, 'rb').read()
assert hashlib.md5(ROM).hexdigest() == '92cae8275cd4f9b473a3a9e36efe6449', 'wrong reference bin'
STOCK_BIN = os.path.join(REPO, 'rom', 'ae5l600l.bin')
STOCK = open(STOCK_BIN, 'rb').read()
assert hashlib.md5(STOCK).hexdigest() == 'a8ea39d447f977e270e27ee670243c88', 'wrong stock bin'

FN_A, FN_B = 0x03AF88, 0x03AB94
FN_FLAG, FN_LOOKUP = 0x022CF4, 0x0BE830
DESC_B = 0x0AD40C

# ------------------------------------------------------------------ shared inputs (literal-pool addresses)
I6624 = 0xFFFF6624   # f32  (compared with the cal 0x0CC4EC/F0/F4 RPM thresholds)
I65FC = 0xFFFF65FC   # f32
I6350 = 0xFFFF6350   # f32  (0x03AB94: axis input of 0x0AD40C)
I65C0 = 0xFFFF65C0   # u8
I65C5 = 0xFFFF65C5   # u8   read by 0x022CF4
I5DB8 = 0xFFFF5DB8   # u8
I6155 = 0xFFFF6155   # u8
C7C9E = 0xFFFF7C9E   # u8   read by both (A: gbr+30, B: gbr+50)
# ------------------------------------------------------------------ 0x03AF88 only
I5E74 = 0xFFFF5E74   # u16
I8E46 = 0xFFFF8E46   # u8
I7EED = 0xFFFF7EED   # u8
I6810 = 0xFFFF6810   # u8
I615F = 0xFFFF615F   # u8
A7C80, A7C84, A7C86, A7C88, A7C8A = 0xFFFF7C80, 0xFFFF7C84, 0xFFFF7C86, 0xFFFF7C88, 0xFFFF7C8A
A7C8C, A7C8E, A7C90 = 0xFFFF7C8C, 0xFFFF7C8E, 0xFFFF7C90
A7C92, A7C94, A7C96, A7C98 = 0xFFFF7C92, 0xFFFF7C94, 0xFFFF7C96, 0xFFFF7C98
A7C9B, A7C9C, A7CAA = 0xFFFF7C9B, 0xFFFF7C9C, 0xFFFF7CAA
A_WORDS = (A7C80, A7C84, A7C86, A7C88, A7C8A, A7C8C, A7C8E, A7C90, A7C92, A7C94, A7C96, A7C98, A7CAA)
A_BYTES = (A7C9B, A7C9C)
# ------------------------------------------------------------------ 0x03AB94 only
I6634 = 0xFFFF6634   # f32
I5BE3 = 0xFFFF5BE3   # u8
I895C = 0xFFFF895C   # f32  added to the table value
I85D7 = 0xFFFF85D7   # u8
I8904 = 0xFFFF8904   # u8
I65BF = 0xFFFF65BF   # u8
B7CB4, B7CB5, B7CB6, B7CA1, B7CA2 = 0xFFFF7CB4, 0xFFFF7CB5, 0xFFFF7CB6, 0xFFFF7CA1, 0xFFFF7CA2
B7CA8, B7CB0, B7C82 = 0xFFFF7CA8, 0xFFFF7CB0, 0xFFFF7C82
B7C6C, B7C70, B7C74, B7C78, B7C7C = 0xFFFF7C6C, 0xFFFF7C70, 0xFFFF7C74, 0xFFFF7C78, 0xFFFF7C7C


def f2b(x):
    return E.f2b(x)


def b2f(b):
    return E.b2f(b)


def s8(v):
    v &= 0xFF
    return v - 0x100 if v & 0x80 else v


def s16(v):
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v


def calw(rom, a):
    return struct.unpack_from('>H', rom, a)[0]


def calf(rom, a):
    """cal float as BITS"""
    return struct.unpack_from('>I', rom, a)[0]


def fgt(xb, yb):
    """fcmp/gt: T = x > y; false when either is NaN"""
    return b2f(xb) > b2f(yb)


def rz_add(xb, yb):
    """fadd: exact sum rounded toward zero (FPSCR RM = 01). Operands/result as float32 BITS."""
    x, y = b2f(xb), b2f(yb)
    ieee = x + y
    if not (math.isfinite(x) and math.isfinite(y)):
        return f2b(ieee)
    q = Fraction(x) + Fraction(y)
    if q == 0:
        return f2b(ieee)          # signed zero by IEEE rules (x + -x = +0 under RZ)
    return E.rz_bits(q)


def bytes_of(a, n):
    return {a + i for i in range(n)}


def poke(e, a, n, v):
    """write RAM WITHOUT marking it initialised -> its first read shows up in uninit_reads"""
    o = a - E.RAM_LO
    e.ram[o:o + n] = (v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big')


def peek(e, a, n):
    o = a - E.RAM_LO
    return int.from_bytes(e.ram[o:o + n], 'big')


_rng = random.Random(0x03AF88)
CALLS = {'A': 0, 'B': 0}
SENT = {8: 0x88888888, 9: 0x99999999, 10: 0xAAAAAAAA, 11: 0xBBBBBBBB, 12: 0xCCCCCCCC, 13: 0xDDDDDDDD,
        14: 0xEEEEEEEE}
FSENT = {12: 0x3F8CCCCD, 13: 0x40133333, 14: 0x40566666, 15: 0x408CCCCD}
GBR_SENT = 0xFFFF1234


def fresh_call(e, entry, pokes):
    """clear tracking, poke (addr, size, value) inputs uninitialised, run, check callee-saved state"""
    e.init = bytearray(len(e.init))
    e.uninit_reads.clear()
    e.writes.clear()
    e.stack_low = E.STACK_TOP
    e.steps = 0
    for a, n, v in pokes:
        poke(e, a, n, v)
    regs = {i: _rng.getrandbits(32) for i in range(8)}
    regs.update(SENT)
    for i in range(12):
        e.FR[i] = _rng.getrandbits(32)
    for i, v in FSENT.items():
        e.FR[i] = v
    e.gbr = GBR_SENT
    assert e.call(entry, regs=regs) == 'return'
    for i, v in SENT.items():
        assert e.R[i] == v, f'r{i} not preserved'
    assert e.R[15] == E.STACK_TOP, 'r15 not restored'
    assert e.gbr == GBR_SENT, 'GBR not restored'
    for i, v in FSENT.items():
        assert e.FR[i] == v, f'fr{i} not preserved'


# =================================================================== 0x03AF88 model
# pointer-table triples (r4 source, 0xFFFF7C8E source, 0xFFFF7C90 source), each 4 longs indexed by band
PT = {
    # [5DB8] == 0
    (0, 'X'): (0x063BB0, 0x063C50, 0x063CF0),
    (0, 1): (0x063B70, 0x063C10, 0x063CB0),
    (0, 2): (0x063B80, 0x063C20, 0x063CC0),
    (0, 3): (0x063B90, 0x063C30, 0x063CD0),
    (0, 4): (0x063BA0, 0x063C40, 0x063CE0),
    # [5DB8] != 0
    (1, 'X'): (0x063C00, 0x063CA0, 0x063D40),
    (1, 1): (0x063BC0, 0x063C60, 0x063D00),
    (1, 2): (0x063BD0, 0x063C70, 0x063D10),
    (1, 3): (0x063BE0, 0x063C80, 0x063D20),
    (1, 4): (0x063BF0, 0x063C90, 0x063D30),
}


def band(rom, rpm_b):
    """r1: 0 below cal 0x0CC4EC, 1 below 0x0CC4F0, 2 below 0x0CC4F4, else (and NaN) 3"""
    if fgt(calf(rom, 0x0CC4EC), rpm_b):
        return 0
    if fgt(calf(rom, 0x0CC4F0), rpm_b):
        return 1
    if fgt(calf(rom, 0x0CC4F4), rpm_b):
        return 2
    return 3


def ptab_word(rom, table, idx):
    p = struct.unpack_from('>I', rom, table + 4 * idx)[0]
    return calw(rom, p)


def model_a(rom, c):
    """c: dict of inputs. Returns (out: {addr: value}, writes: set of bytes, reads: set of addresses,
    info: dict of intermediate values for printing)."""
    st = {a: c[a] for a in A_WORDS + A_BYTES}
    writes, reads = set(), set()
    reads |= {I6624, I65FC, I6350, I5E74, I65C0, I8E46, I7EED, I65C5, I5DB8, I6810, I6155, I615F, C7C9E}
    info = {'sec1': c[C7C9E] == 0, 'sel': None, 'band': None}
    written = set()

    def wr(a, n, v):
        st[a] = v & ((1 << (8 * n)) - 1)
        writes.update(bytes_of(a, n))
        written.add(a)

    def rd(a):
        if a not in written:
            reads.add(a)
        return st[a]

    r6 = 1 if c[I65C5] == 1 else 0
    if c[C7C9E] == 0:                                   # 3AFD6 tst / bt
        r4 = s16(rd(A7C8C))
        if c[I65C0] == 1:                               # 3AFE4 extu.b / cmp/eq #1
            r4 = s16(calw(rom, 0x0CBC9E))
            wr(A7C8E, 2, 0)
            wr(A7C90, 2, 0)
            info['sel'] = 'forced'
        else:
            r1 = band(rom, c[I6624])
            info['band'] = r1
            side = 0 if s8(c[I5DB8]) == 0 else 1        # 3B088 tst r5,r5
            key = None
            if r6 == 0 and c[I5E74] >= calw(rom, 0x0CBCC0):   # 3B098 / 3B154 cmp/ge on zero-extended words
                key = (side, 'X')
            elif c[I6810] in (1, 2, 3):
                key = (side, c[I6810])
            elif c[I6810] in (4, 5):
                key = (side, 4)
            if key is not None:
                t4, t8e, t90 = PT[key]
                r4 = s16(ptab_word(rom, t4, r1))
                wr(A7C8E, 2, ptab_word(rom, t8e, r1))
                wr(A7C90, 2, ptab_word(rom, t90, r1))
            info['sel'] = key
        if c[I8E46] == 1:                               # 3B202
            lo = calw(rom, 0x0CBC92)
            if (r4 & 0xFFFF) < lo:
                r4 = s16(lo)
        wr(A7C8C, 2, r4)
        if c[I6155] == 1 and s8(c[I615F]) == 0:         # 3B21A / 3B220
            for a, k in ((A7C84, 0x0C2220), (A7C86, 0x0C2222), (A7C88, 0x0C2224), (A7C8A, 0x0C2226)):
                wr(a, 2, calw(rom, k))
            wr(A7C9B, 1, 1)
        else:
            for a in (A7C84, A7C8A, A7C88, A7C86):
                wr(a, 2, 0)
            wr(A7C9B, 1, 0)
    # ---- section 2 (3B2EE)
    if s8(c[C7C9E]) == 1:
        r4f = 0
    else:
        wr(A7C80, 2, 0)
        wr(A7C9C, 1, 0)
        r4f = 1
    old92 = rd(A7C92)
    if rd(A7CAA) >= old92:                              # 3B304 cmp/hs on sign-extended words == unsigned u16
        wr(A7C9C, 1, 0)
        r4f = 1
    info['armed'] = False
    if r4f == 0:
        if (not fgt(calf(rom, 0x0CC4F8), c[I65FC]) and not fgt(calf(rom, 0x0CC4FC), c[I6350])
                and r6 == 1 and c[I7EED] == 1):
            wr(A7C80, 2, calw(rom, 0x0CBD92))
            wr(A7C9C, 1, 1)
            info['armed'] = True
    # ---- section 3 (3B338): every float step is exact, so integer arithmetic models it
    m = max(rd(A7C8C), rd(A7C80))
    wr(A7C92, 2, min(m + rd(A7C84), 0xFFFF))
    wr(A7C94, 2, min(min(m + rd(A7C8E), 0xFFFF) + rd(A7C86), 0xFFFF))
    t = min(m + rd(A7C90), 0xFFFF)
    wr(A7C96, 2, min(t + rd(A7C88), 0xFFFF))
    wr(A7C98, 2, min(t + rd(A7C8A), 0xFFFF))
    info['M'] = m
    out = {a: st[a] for a in written}
    return out, writes, reads, info


def run_a(rom, c, e=None):
    e = e or E.Emu(rom)
    pokes = [(I6624, 4, c[I6624]), (I65FC, 4, c[I65FC]), (I6350, 4, c[I6350]), (I5E74, 2, c[I5E74]),
             (I65C0, 1, c[I65C0]), (I8E46, 1, c[I8E46]), (I7EED, 1, c[I7EED]), (I65C5, 1, c[I65C5]),
             (I5DB8, 1, c[I5DB8]), (I6810, 1, c[I6810]), (I6155, 1, c[I6155]), (I615F, 1, c[I615F]),
             (C7C9E, 1, c[C7C9E])]
    pokes += [(a, 2, c[a]) for a in A_WORDS] + [(a, 1, c[a]) for a in A_BYTES]
    fresh_call(e, FN_A, pokes)
    CALLS['A'] += 1
    want, wset, rset, info = model_a(rom, c)
    got = {a: peek(e, a, 1 if a in A_BYTES else 2) for a in want}
    tag = ' '.join(f'{k:08X}={v:#x}' for k, v in c.items())
    assert got == want, f'A OUTPUT MISMATCH {tag}\n got {got}\n want {want}'
    assert set(e.writes) == wset, (f'A WRITE-SET MISMATCH {tag}\n got  {sorted(map(hex, e.writes))}'
                                   f'\n want {sorted(map(hex, wset))}')
    assert e.uninit_reads == rset, (f'A READ-SET MISMATCH {tag}\n got  {sorted(map(hex, e.uninit_reads))}'
                                    f'\n want {sorted(map(hex, rset))}')
    return got, info, e


def case_a(kw=None):
    c = {I6624: f2b(2000.0), I65FC: f2b(0.0), I6350: f2b(80.0), I5E74: 0, I65C0: 0, I8E46: 0, I7EED: 0,
         I65C5: 1, I5DB8: 0, I6810: 1, I6155: 0, I615F: 0, C7C9E: 0,
         A7C80: 0x1111, A7C84: 0x2222, A7C86: 0x3333, A7C88: 0x4444, A7C8A: 0x5555, A7C8C: 0x0123,
         A7C8E: 0x0456, A7C90: 0x0789, A7C92: 0x0100, A7C94: 0x6666, A7C96: 0x7777, A7C98: 0x0888,
         A7CAA: 0x0050, A7C9B: 0x5A, A7C9C: 0xA5}
    for k, v in (kw or {}).items():
        c[k] = v
    return c


# =================================================================== 0x03AB94 model
_lut = {}


def rom_lookup(rom, xb):
    k = (id(rom), xb)
    if k not in _lut:
        e = E.Emu(rom)
        e.call(FN_LOOKUP, regs={4: DESC_B}, fregs={4: b2f(xb)})
        _lut[k] = e.FR[0]
    return _lut[k]


def model_b(rom, c):
    st = {a: c[a] for a in (B7CB4, B7CB5, B7CB6, B7CA1, B7CA2, B7CA8, B7CB0, B7C82,
                            B7C6C, B7C70, B7C74, B7C78, B7C7C)}
    size = {B7CB4: 1, B7CB5: 1, B7CB6: 1, B7CA1: 1, B7CA2: 1, B7CA8: 2, B7CB0: 2, B7C82: 2,
            B7C6C: 4, B7C70: 4, B7C74: 4, B7C78: 4, B7C7C: 4}
    writes, written = set(), set()
    reads = {I6634, I6624, I65C0, I5BE3, I65FC, I6350, I895C, I65C5, I85D7, I6155, I8904, I65BF, I5DB8,
             C7C9E}
    info = {}

    def wr(a, v):
        st[a] = v & ((1 << (8 * size[a])) - 1)
        writes.update(bytes_of(a, size[a]))
        written.add(a)

    def rd(a):
        if a not in written:
            reads.add(a)
        return st[a]

    m = 1 if c[I65C5] == 1 else 0
    # block A (3ABEE)
    info['edgeA'] = False
    if not fgt(calf(rom, 0x0CC4CC), c[I6634]) and not fgt(calf(rom, 0x0CC4D0), c[I6624]):
        if rd(B7CB5) == 1 and s8(c[I65C0]) == 0:
            wr(B7CB4, 1)
            wr(B7CA8, 0)
            info['edgeA'] = True
    # block B (3AC16)
    if rd(B7CB4) == 1:
        if rd(B7CA8) < calw(rom, 0x0CBC9A):
            wr(B7CA8, min(rd(B7CA8) + 1, 0xFFFF))
            wr(B7CA1, 0)
        else:
            wr(B7CA8, 0)
            wr(B7CA1, 1)
            wr(B7CB4, 0)
    else:
        wr(B7CA1, 1)
    wr(B7CB5, c[I65C0])
    # block C (3AC5A)
    if s8(rd(B7CB6)) == 1 and s8(c[I65BF]) == 0:
        wr(B7CB0, calw(rom, 0x0CBC98))
    elif rd(B7CB0) != 0:
        wr(B7CB0, rd(B7CB0) - 1)
    wr(B7CB6, c[I65BF])
    # block D (3AC7C): adders
    zero = f2b(0.0)
    s = zero
    if c[I5BE3] == 1 or c[I65BF] == 1 or rd(B7CB0) != 0:
        s = rz_add(calf(rom, 0x0CC4B0), zero)
    if fgt(calf(rom, 0x0CC4B4), c[I65FC]):
        s = rz_add(s, calf(rom, 0x0CC4B8))
    if fgt(calf(rom, 0x0CC4BC), c[I6634]) and s8(rd(B7CA1)) == 1 and m == 1:
        s = rz_add(s, calf(rom, 0x0CC4C0))
    if c[I8904] == 1:
        s = rz_add(s, calf(rom, 0x0CC4C8))
    if c[I5BE3] == 0 and c[I5DB8] == 1 and c[I65BF] == 0 and rd(B7CB0) == 0:
        s = rz_add(s, calf(rom, 0x0CC4C4))
    wr(B7C7C, s)
    lut = rom_lookup(rom, c[I6350])
    thr = rz_add(rz_add(lut, c[I895C]), rd(B7C7C))
    wr(B7C78, thr)
    info['lut'] = lut
    # block F (3AD08)
    if s8(c[C7C9E]) == 1:
        wr(B7C82, 0)
    elif s8(c[I85D7]) == 0:
        wr(B7C82, 0xFFFF)
    else:
        wr(B7C82, min(rd(B7C82) + 1, 0xFFFF))
    v = rd(B7C82)
    wr(B7CA2, 1 if 0 < v < calw(rom, 0x0CBC9C) else 0)
    # block G (3AD3E)
    if s8(c[I6155]) == 0:
        lo, hi = 0x0CC4D4, 0x0CC4D8
    else:
        lo, hi = 0x0CC4DC, 0x0CC4E0
    if s8(c[I85D7]) == 0:
        wr(B7C70, calf(rom, lo))
    elif fgt(rd(B7C78), c[I6624]):
        wr(B7C70, calf(rom, hi))
    # block H (3AE0E)
    t = zero
    if c[I5BE3] == 1:
        t = rz_add(calf(rom, 0x0CC4E4), zero)
    if s8(rd(B7CA2)) == 1:
        t = rz_add(t, calf(rom, 0x0CC4E8))
    wr(B7C74, t)
    wr(B7C6C, rz_add(rd(B7C70), rd(B7C74)))
    out = {a: st[a] for a in written}
    return out, writes, reads, info, size


def run_b(rom, c, e=None):
    e = e or E.Emu(rom)
    pokes = [(I6634, 4, c[I6634]), (I6624, 4, c[I6624]), (I65C0, 1, c[I65C0]), (I5BE3, 1, c[I5BE3]),
             (I65FC, 4, c[I65FC]), (I6350, 4, c[I6350]), (I895C, 4, c[I895C]), (I65C5, 1, c[I65C5]),
             (I85D7, 1, c[I85D7]), (I6155, 1, c[I6155]), (I8904, 1, c[I8904]), (I65BF, 1, c[I65BF]),
             (I5DB8, 1, c[I5DB8]), (C7C9E, 1, c[C7C9E])]
    _, _, _, _, size = model_b(rom, c)
    pokes += [(a, n, c[a]) for a, n in size.items()]
    fresh_call(e, FN_B, pokes)
    CALLS['B'] += 1
    want, wset, rset, info, size = model_b(rom, c)
    got = {a: peek(e, a, size[a]) for a in want}
    tag = ' '.join(f'{k:08X}={v:#x}' for k, v in c.items())
    assert got == want, f'B OUTPUT MISMATCH {tag}\n got {got}\n want {want}'
    assert set(e.writes) == wset, (f'B WRITE-SET MISMATCH {tag}\n got  {sorted(map(hex, e.writes))}'
                                   f'\n want {sorted(map(hex, wset))}')
    assert e.uninit_reads == rset, (f'B READ-SET MISMATCH {tag}\n got  {sorted(map(hex, e.uninit_reads))}'
                                    f'\n want {sorted(map(hex, rset))}')
    return got, info, e


def case_b(kw=None):
    c = {I6634: f2b(20.0), I6624: f2b(2000.0), I65C0: 0, I5BE3: 0, I65FC: f2b(50.0), I6350: f2b(80.0),
         I895C: f2b(0.0), I65C5: 1, I85D7: 0, I6155: 0, I8904: 0, I65BF: 0, I5DB8: 0, C7C9E: 0,
         B7CB4: 0, B7CB5: 0, B7CB6: 0, B7CA1: 0x5A, B7CA2: 0xA5, B7CA8: 0, B7CB0: 0, B7C82: 0x0123,
         B7C6C: f2b(-1.0), B7C70: f2b(-2.0), B7C74: f2b(-3.0), B7C78: f2b(-4.0), B7C7C: f2b(-5.0)}
    for k, v in (kw or {}).items():
        c[k] = v
    return c


def fmt(b):
    return f'{b2f(b):.7g}'


# =================================================================== callee checks
def check_callees():
    n = 0
    for v in range(256):                     # 0x022CF4: r0 = (byte [0xFFFF65C5] == 1)
        e = E.Emu(ROM)
        e.ram_u8(I65C5, v)
        e.R[6] = 0x12345678
        e.T = 1 - (1 if v == 1 else 0)
        e.call(FN_FLAG)
        assert e.R[0] == (1 if v == 1 else 0), v
        # review item M2: the routine is not side-effect free in registers -- it leaves r6 = the
        # pool literal 0xFFFF65C5 (022CF4 mov.l) and T = the compare result (022CF8 cmp/eq #1).
        # It writes no RAM.
        assert e.R[6] == I65C5 and e.T == e.R[0] and not e.writes, (v, hex(e.R[6]), e.T, e.writes)
        n += 1
    worst = 0.0
    for rom, name in ((ROM, '20.19c'), (STOCK, 'stock')):
        t = DT.read_table(rom, DESC_B)
        assert t['dim'] == '1D' and t['typecode'] == 0x08 and t['fixed'] is None
        ax, vals = t['axes']['x'], t['values']
        xs = [-1e9, -100.0, -40.0, 110.0, 200.0, 1e9] + [ax[i] + (ax[i + 1] - ax[i]) * k
                                                         for i in range(len(ax) - 1) for k in (0, .3, .5, .9)]
        for x in xs:
            got = b2f(rom_lookup(rom, f2b(x)))
            want = E._interp(ax, vals, b2f(f2b(x)))
            worst = max(worst, abs(got - want))
            assert abs(got - want) <= 1e-3, (name, x, got, want)
            n += 1
        nan = b2f(rom_lookup(rom, 0x7FC00000))     # NaN -> last cell (axis search contract)
        assert nan == vals[-1], (name, nan)
        print(f'  0x0AD40C [{name}] axis {ax[0]:g}..{ax[-1]:g} ({len(ax)}), uint16 x {t["scale"]:g}: '
              f'values {vals[0]:g} .. {vals[-1]:g}; lookup(NaN) = {nan:g}')
    flat = DT.read_table(ROM, DESC_B)['values']
    assert all(v == 1000.0 for v in flat), 'expected the 20.19c table flat at 1000.0'
    print(f'callees: 0x022CF4 == (byte==1); 0x0BE830 on 0x0AD40C == clamped interpolation '
          f'({n} cases, worst {worst:.1e})')


# =================================================================== 0x03AF88 passes
def pass_a_grid():
    rpms = [f2b(x) for x in (0.0, 2249.9998, 2250.0, 2999.9998, 3000.0, 4499.9995, 4500.0, 8000.0)]
    rpms.append(0x7FC00000)                                       # NaN -> band 3
    n = runs = eq34 = 0
    seen_keys = set()
    for c9e in (0, 1, 2, 0xFF):
        for c0, side, sel, mode, w74, rpm in itertools.product((0, 1, 2), (0, 1, 0x80), (0, 1, 2, 3, 4, 5, 6, 0xFF),
                                                               (0, 1, 2), (37, 38, 0xFFFF), rpms):
            if (n % 3) and c9e != 0:
                n += 1
                continue
            c = case_a({C7C9E: c9e, I65C0: c0, I5DB8: side, I6810: sel, I65C5: mode, I5E74: w74,
                          I6624: rpm, I8E46: (0, 1)[n % 2], I6155: (0, 1, 1, 2)[n % 4],
                          I615F: (0, 0, 1, 0x80)[(n // 4) % 4], A7C8C: (0x0123, 0, 0xFFFF)[n % 3]})
            got, info, _ = run_a(ROM, c)
            if info['sel'] is not None:
                seen_keys.add(info['sel'])
            if info['sec1']:
                # [7C88] and [7C8A] are written together (625/625 or 0/0) -> output 3 == output 4, so the
                # tier-3 test of 0x03AE6C (03AEFC, after the tier-4 test against [7C98] at 03AEBC) cannot pass
                assert got[A7C88] == got[A7C8A] and got[A7C96] == got[A7C98], got
                eq34 += 1
            n += 1
            runs += 1
    assert len(seen_keys) == 11, seen_keys        # 10 pointer-table triples + forced
    print(f'A grid: {runs} cases (section 1 path x band x [5DB8] x [6810] x mode), all 11 selections reached; '
          f'output 3 == output 4 asserted on all {eq34} section-1 cases')


def pass_a_arm():
    n = 0
    armed = 0
    for c9e, vs, ect, mode, eed, aa, old92 in itertools.product(
            (0, 1, 2), (499.99997, 500.0, 600.0, float('nan')), (39.999996, 40.0, 90.0),
            (0, 1), (0, 1, 2), (0x0000, 0x0100, 0x00FF, 0xFFFF), (0x0100, 0x0000, 0x8000)):
        c = case_a({C7C9E: c9e, I65FC: f2b(vs), I6350: f2b(ect), I65C5: mode, I7EED: eed, A7CAA: aa,
                      A7C92: old92, A7C80: 0x0999})
        got, info, _ = run_a(ROM, c)
        armed += info['armed']
        n += 1
    assert armed > 0
    print(f'A arm grid: {n} cases ([7C9E] x [65FC] x [6350] x mode x [7EED] x [7CAA] vs old [7C92]), armed in {armed}')


def pass_a_section2():
    """review item A13: every branch of section 2 (03B2EE..03B336), asserted directly on emulated RAM.
    With [7C9E] == 1 and u16 [7CAA] >= old u16 [7C92], 03B308/03B30A clear [7C9C] and set r4 = 1, so
    the arm test is skipped and [7C80] is NOT written -- the two cells do not 'both keep' there."""
    arm_ok = {I65FC: f2b(600.0), I6350: f2b(90.0), I65C5: 1, I7EED: 1}
    n = 0
    # (1) [7C9E]==1, [7CAA] >= old [7C92] (unsigned): [7C9C] -> 0, [7C80] kept, even with every arm
    #     condition true.  (0x8000, 0x7FFF) checks the UNSIGNED sense of 03B304 cmp/hs.
    for aa, old92 in ((9, 9), (10, 9), (0xFFFF, 9), (0x8000, 0x7FFF)):
        c = case_a({C7C9E: 1, A7CAA: aa, A7C92: old92, A7C9C: 1, A7C80: 0x0999, **arm_ok})
        got, info, e = run_a(ROM, c)
        assert got[A7C9C] == 0 and A7C80 not in got and peek(e, A7C80, 2) == 0x0999 and not info['armed'], \
            (aa, old92, got)
        n += 1
    # (2) [7C9E]==1, [7CAA] < old [7C92], one arm condition fails: both keep their old values
    for f in ({I65FC: f2b(499.99997)}, {I6350: f2b(39.999996)}, {I65C5: 0}, {I7EED: 0}, {I7EED: 2}):
        kw = dict(arm_ok)
        kw.update(f)
        c = case_a({C7C9E: 1, A7CAA: 8, A7C92: 9, A7C9C: 0xA5, A7C80: 0x0999, **kw})
        got, info, e = run_a(ROM, c)
        assert A7C9C not in got and A7C80 not in got, (f, got)
        assert peek(e, A7C9C, 1) == 0xA5 and peek(e, A7C80, 2) == 0x0999, f
        n += 1
    # (2b) unsigned sense again: [7CAA] = 0x7FFF < old 0x8000 -> arm path reachable
    c = case_a({C7C9E: 1, A7CAA: 0x7FFF, A7C92: 0x8000, A7C9C: 0, A7C80: 0, **arm_ok})
    got, info, e = run_a(ROM, c)
    assert info['armed'] and got[A7C80] == 250 and got[A7C9C] == 1
    n += 1
    # (3) every condition holds: [7C80] = 250 (word 0x0CBD92), [7C9C] = 1
    for vs, ect in ((500.0, 40.0), (600.0, 90.0), (float('nan'), float('nan'))):   # NaN passes both tests
        kw = dict(arm_ok)
        kw.update({I65FC: f2b(vs), I6350: f2b(ect)})
        c = case_a({C7C9E: 1, A7CAA: 8, A7C92: 9, A7C9C: 0, A7C80: 0, **kw})
        got, info, e = run_a(ROM, c)
        assert info['armed'] and got[A7C80] == 250 and got[A7C9C] == 1, (vs, ect)
        n += 1
    # (4) [7C9E] != 1: both cleared, whatever [7CAA] and the arm conditions are
    for c9e in (0, 2, 0xFF):
        for aa in (8, 9):
            c = case_a({C7C9E: c9e, A7CAA: aa, A7C92: 9, A7C9C: 1, A7C80: 250, **arm_ok})
            got, info, e = run_a(ROM, c)
            assert got[A7C80] == 0 and got[A7C9C] == 0 and not info['armed'], (c9e, aa)
            n += 1
    print(f'A section 2: {n} cases -- [7C9E]==1 & [7CAA]>=old[7C92] clears [7C9C] only; [7CAA]<old & a failed '
          f'condition keeps both; all conditions arm; [7C9E]!=1 clears both')


def check_phantom_writers():
    """review item M5: find_writers lists 'writers' of 0xFFFF7C6C / 7C7C / 7C8C / 7C9C at 0370B6 / 0373D6 /
    037546 / 037552 (GBR 0xFFFF7A2C 'set @037012').  Each is the low half of a CAL-pointer pool long,
    loaded PC-relative by an instruction inside a census function."""
    import sh2e_disasm as D
    for loader, pool, val, hit in ((0x036ED4, 0x0370B4, 0x000CC290, 0x0370B6),
                                   (0x037252, 0x0373D4, 0x000CC294, 0x0373D6),
                                   (0x03749A, 0x037544, 0x000CC298, 0x037546),
                                   (0x0374BA, 0x037550, 0x000CC29C, 0x037552)):
        w = struct.unpack_from('>H', ROM, loader)[0]
        assert w >> 12 == 0xD and ((loader + 4) & ~3) + (w & 0xFF) * 4 == pool, hex(loader)
        assert struct.unpack_from('>I', ROM, pool)[0] == val and hit == pool + 2
        txt = D.decode(struct.unpack_from('>H', ROM, hit)[0], hit)[0]
        assert txt.startswith('mov.l r0,@(') and txt.endswith(',gbr)'), txt
    print('phantom writers: 0370B6 / 0373D6 / 037546 / 037552 are the low halves of pool longs 0x000CC290 / 94 / '
          '98 / 9C (loaded at 036ED4 / 037252 / 03749A / 0374BA), not stores')


def pass_a_sat():
    """section 3 arithmetic over 16-bit edges (section 1 skipped: [7C9E] = 1, so every word is an input)"""
    vals = (0, 1, 13, 250, 625, 0x7FFF, 0x8000, 0xFFF0, 0xFFFE, 0xFFFF)
    n = 0
    for a8c, a80, ext in itertools.product(vals, vals, vals):
        c = case_a({C7C9E: 1, A7C8C: a8c, A7C80: a80, A7C8E: ext, A7C90: vals[(n + 3) % 10],
                      A7C84: vals[(n + 5) % 10], A7C86: ext, A7C88: vals[(n + 7) % 10], A7C8A: vals[n % 10],
                      A7CAA: 0xFFFF})
        run_a(ROM, c)
        n += 1
    for _ in range(1500):
        c = case_a({C7C9E: 1, A7CAA: _rng.getrandbits(16), A7C92: _rng.getrandbits(16)})
        for a in (A7C8C, A7C80, A7C84, A7C86, A7C88, A7C8A, A7C8E, A7C90):
            c[a] = _rng.getrandbits(16)
        run_a(ROM, c)
        n += 1
    print(f'A saturation: {n} cases (sat16(max(a,b)+x) chains, 16-bit edges + random)')


def print_a_table():
    print('A: stock vs 20.19c, [5DB8]=0, mode([65C5]==1)=1, [6155]=0, [7C9E]=0  ->  [7C8C] [7C8E] [7C90] '
          '(then [7C92..98] = those + 0 with [7C80]=0)')
    for sel in (1, 2, 3, 4, 5):
        row = []
        for rpm in (1000.0, 2000.0, 2600.0, 3500.0, 5000.0):
            outs = []
            for rom in (STOCK, ROM):
                c = case_a({I6810: sel, I6624: f2b(rpm), A7C80: 0, A7C92: 0xFFFF, A7CAA: 0})
                got, info, _ = run_a(rom, c)
                outs.append(f'{got[A7C8C]}/{got[A7C8E]}/{got[A7C90]}')
            row.append(f'{rpm:>6.0f}: {outs[0]:>11} {outs[1]:>11}')
        print(f'  [6810]={sel}  ' + '  '.join(row))
    c = case_a({I65C0: 1, A7C80: 0})
    got, _, _ = run_a(ROM, c)
    print(f'  [65C0]=1 -> [7C8C]={got[A7C8C]} [7C8E]={got[A7C8E]} [7C90]={got[A7C90]}')
    c = case_a({I6155: 1, I615F: 0, A7C80: 0, I6810: 1, I6624: f2b(1000.0)})
    got, _, _ = run_a(ROM, c)
    print(f'  [6155]=1,[615F]=0, [6810]=1, 1000 -> [7C84..8A]={got[A7C84]},{got[A7C86]},{got[A7C88]},{got[A7C8A]} '
          f'[7C9B]={got[A7C9B]}  [7C92]={got[A7C92]} [7C94]={got[A7C94]} [7C96]={got[A7C96]} [7C98]={got[A7C98]}')
    c = case_a({C7C9E: 1, A7CAA: 0, A7C92: 0x0100, I65FC: f2b(500.0), I6350: f2b(40.0), I65C5: 1, I7EED: 1,
                  A7C8C: 44, A7C84: 0, A7C86: 0, A7C88: 0, A7C8A: 0, A7C8E: 0, A7C90: 0})
    got, info, _ = run_a(ROM, c)
    assert info['armed'] and got[A7C80] == 250 and got[A7C9C] == 1 and got[A7C92] == 250
    print(f'  armed: [7C9E]=1, [7CAA]<[7C92], [65FC]>=500, [6350]>=40, mode=1, [7EED]=1 -> [7C80]={got[A7C80]} '
          f'[7C9C]={got[A7C9C]}; M = max(44, 250) -> [7C92]={got[A7C92]}')


# =================================================================== 0x03AB94 passes
def pass_b_grid():
    n = 0
    hits = {'edgeA': 0}
    xs6634 = [f2b(x) for x in (-60.0, -50.0, 14.999999, 15.0, 30.0)]
    rpms = [f2b(x) for x in (0.0, 900.0, 1000.0, 1000.0001, 2000.0, 9999.999, 10000.0)]
    for b5, b4, a8, c0 in itertools.product((0, 1, 2), (0, 1, 3), (0, 1, 87, 88, 89, 0xFFFF), (0, 1, 0x80)):
        for k in range(4):
            c = case_b({B7CB5: b5, B7CB4: b4, B7CA8: a8, I65C0: c0,
                          I6634: xs6634[(n + k) % 5], I6624: rpms[(n + 3 * k) % 7]})
            got, info, _ = run_b(ROM, c)
            hits['edgeA'] += info['edgeA']
            n += 1
    for b6, bf, b0, be3, bdb, b04, vs in itertools.product((0, 1, 2), (0, 1, 2), (0, 1, 31, 0xFFFF), (0, 1, 2),
                                                          (0, 1, 2), (0, 1), (16.999998, 17.0, float('nan'))):
        c = case_b({B7CB6: b6, I65BF: bf, B7CB0: b0, I5BE3: be3, I5DB8: bdb, I8904: b04, I65FC: f2b(vs),
                      I6634: xs6634[n % 5], I65C5: (0, 1)[n % 2]})
        run_b(ROM, c)
        n += 1
    for c9e, d7, c82, s55, rpm, x5c in itertools.product((0, 1, 2), (0, 1, 0x80), (0, 1, 186, 187, 188, 0xFFFE, 0xFFFF),
                                                          (0, 1), (999.99994, 1000.0, 1300.0, 3000.0, float('nan')),
                                                          (0.0, -500.0, 300.0)):
        c = case_b({C7C9E: c9e, I85D7: d7, B7C82: c82, I6155: s55, I6624: f2b(rpm), I895C: f2b(x5c),
                      I5BE3: (0, 1)[n % 2], I65FC: f2b((10.0, 50.0)[(n // 2) % 2])})
        run_b(ROM, c)
        n += 1
    assert hits['edgeA'] > 0
    print(f'B grid: {n} cases (edge/timer, countdown/adders, counter/latch), block-A edge fired in {hits["edgeA"]}')


def pass_b_stock():
    n = 0
    for ect in (-50.0, -40.0, -35.0, 0.0, 5.0, 37.5, 45.0, 110.0, 150.0, float('nan')):
        for x5c in (0.0, 12.5, -100.0):
            c = case_b({I6350: f2b(ect), I895C: f2b(x5c), I85D7: 1, I6624: f2b(700.0), I65FC: f2b(50.0)})
            got, info, _ = run_b(STOCK, c)
            n += 1
    print(f'B stock bin: {n} cases over the interpolating table (lookup composed bit-exactly)')


def print_b_table():
    print('B: [7C7C] adders and [7C78] = lookup(0x0AD40C,[6350]) + [895C] + [7C7C]  (20.19c / stock)')
    rows = [('none (vs 50)', {}),
            ('[5BE3]=1', {I5BE3: 1}),
            ('[65FC]<17', {I65FC: f2b(5.0)}),
            ('[6634]<-50,[7CA1]=1,mode', {I6634: f2b(-60.0)}),
            ('[8904]=1', {I8904: 1}),
            ('all', {I5BE3: 1, I65FC: f2b(5.0), I6634: f2b(-60.0), I8904: 1})]
    for name, kw in rows:
        outs = []
        for rom in (ROM, STOCK):
            c = case_b(kw)
            got, info, _ = run_b(rom, c)
            outs.append(f'{fmt(got[B7C7C])} -> {fmt(got[B7C78])}')
        print(f'  {name:26s} 20.19c {outs[0]:>18}   stock {outs[1]:>18}')


def seq_b():
    """multi-call behaviour on one emulator: timer 0xFFFF7CA8/7CB4/7CA1, countdown 0xFFFF7CB0, counter 0xFFFF7C82"""
    e = E.Emu(ROM)
    st = case_b({I6634: f2b(20.0), I6624: f2b(10000.0), B7CB5: 1, I65C0: 0})
    trace = []
    for k in range(92):
        got, info, e = run_b(ROM, st, e)
        for a in got:
            st[a] = got[a]
        trace.append((st[B7CB4], st[B7CA8], st[B7CA1]))
    # call 1 sets the timer (edge) and counts it to 1; counts reach 88; the call that sees 88 clears it
    assert trace[0] == (1, 1, 0), trace[0]
    assert trace[86] == (1, 87, 0) and trace[87] == (1, 88, 0) and trace[88] == (0, 0, 1), trace[85:90]
    print(f'B sequence: falling edge of [65C0] (with [6634]>=15, [6624]>=10000) -> [7CA1]=0 for 88 calls, '
          f'then 1 (calls 1..88 count 1..88, call 89 clears)')
    # review item M3: the same edge with [6624] below 10000.0 (e.g. 6700, 9999.999) or [6634] below 15.0 is
    # ignored -- the timer does not start and [7CA1] stays 1 (03ABF2/03ABF4 and 03ABFC/03ABFE bt skip)
    for x6634, rpm in ((20.0, 6700.0), (20.0, 9999.999), (14.999999, 12000.0)):
        got, info, _ = run_b(ROM, case_b({I6634: f2b(x6634), I6624: f2b(rpm), B7CB5: 1, I65C0: 0, B7CB4: 0}))
        assert not info['edgeA'] and got[B7CA1] == 1 and B7CB4 not in got, (x6634, rpm, got)
    print('B edge gate: a [65C0] falling edge with [6624] < 10000.0 or [6634] < 15.0 does not start the timer')
    st = case_b({B7CB6: 1, I65BF: 0, B7CB0: 0})
    e = E.Emu(ROM)
    vals = []
    for k in range(34):
        got, info, e = run_b(ROM, st, e)
        for a in got:
            st[a] = got[a]
        vals.append((st[B7CB0], b2f(st[B7C7C])))
    assert vals[0] == (31, 300.0) and vals[30] == (1, 300.0) and vals[31] == (0, 0.0), vals[:3] + vals[29:33]
    print(f'B sequence: falling edge of [65BF] -> [7CB0]=31 then -1 per call; the 300 adder holds while it is '
          f'non-zero (31 calls)')
    st = case_b({C7C9E: 1, I85D7: 1})
    e = E.Emu(ROM)
    got, _, e = run_b(ROM, st, e)
    assert got[B7C82] == 0 and got[B7CA2] == 0
    st.update(got)
    st[C7C9E] = 0
    hist = []
    for k in range(190):
        got, _, e = run_b(ROM, st, e)
        st.update(got)
        hist.append((st[B7C82], st[B7CA2]))
    assert hist[0] == (1, 1) and hist[186] == (187, 1) and hist[187] == (188, 0), hist[185:189]
    print('B sequence: [7C9E]=1 zeroes [7C82]; then with [85D7]!=0 it counts +1/call and [7CA2]=1 for counts 1..187')


def seq_a():
    """two consecutive calls: section 2 compares [7CAA] with the [7C92] of the PREVIOUS call"""
    e = E.Emu(ROM)
    st = case_a({C7C9E: 1, A7C92: 0x0300, A7CAA: 0x0200, I65FC: f2b(600.0), I6350: f2b(90.0), I65C5: 1,
                   I7EED: 1, A7C8C: 44, A7C84: 0, A7C86: 0, A7C88: 0, A7C8A: 0, A7C8E: 0, A7C90: 0, A7C80: 0})
    got, info, e = run_a(ROM, st, e)
    assert info['armed'] and got[A7C92] == 250
    st.update(got)
    got, info, e = run_a(ROM, st, e)          # now [7CAA]=0x200 >= [7C92]=250: clear [7C9C], keep [7C80]
    assert not info['armed'] and got[A7C9C] == 0 and A7C80 not in got and got[A7C92] == 250
    print('A sequence: arm on call 1 ([7C80]=250, [7C9C]=1); call 2 sees [7CAA] >= the new [7C92] and clears '
          '[7C9C] only ([7C80] retained)')


def main():
    check_callees()
    check_phantom_writers()
    pass_a_grid()
    pass_a_arm()
    pass_a_section2()
    pass_a_sat()
    seq_a()
    print_a_table()
    pass_b_grid()
    pass_b_stock()
    seq_b()
    print_b_table()
    print(f'emulated calls: 0x03AF88 {CALLS["A"]}, 0x03AB94 {CALLS["B"]}, total {CALLS["A"] + CALLS["B"]}')
    print('ALL ASSERTIONS PASSED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
