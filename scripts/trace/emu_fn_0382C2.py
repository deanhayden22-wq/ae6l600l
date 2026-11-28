#!/usr/bin/env python3
"""Emulation check for ROM function 0x0382C2..0x03885E (593 instructions), traced in
disassembly/analysis/fn_0382C2_trace.txt.

    python3 scripts/trace/emu_fn_0382C2.py

Reference bin: rom/AE5L600L 20g rev 20.19c.bin  md5 92cae8275cd4f9b473a3a9e36efe6449

What it does
------------
Runs 0x0382C2 in scripts/sh2e_emu.py against a Python model written from the bytes and asserts,
per case:

  * every cell of the state block 0xFFFF7AF4..0xFFFF7B40, bit for bit
  * the exact SET of non-stack RAM bytes written (nothing outside the model is touched)
  * the exact SET of RAM cells read before being written in the same call (inputs are poked WITHOUT
    marking them initialised, so every input read lands in emu.uninit_reads)
  * r8-r14, r15, GBR and fr12-fr15 are restored
  * (stub passes) the exact ordered list of (descriptor, axis input) pairs passed to 0x0BE830

Passes
  0. callee / encoding facts: 0x022CF4 and 0x023E48 return (byte == 1) for all 256 bytes; the
     sign-extend-then-cmp/hs integer compares equal unsigned u8 / u16 compares (exhaustive monotonicity)
  1. REAL ROM, real callees: random grid.  Every table this function reads is all-zero in 20.19c and
     in stock, so this pass also asserts the as-shipped consequences (enabled output is +0.0 etc.)
  2. MODIFIED in-memory ROM copies (cal scalars set to test values; the file on disk is never written),
     0x0BE830 STUBBED with a per-descriptor linear function: proves which descriptor gets which input
     and where each result goes, every gain / threshold / step, every compare sense
  3. MODIFIED ROM with every table cell populated, real 0x0BE830: end-to-end composition
  4. the as-shipped bytes of rom/ae5l600l.bin (stock) give identical results to 20.19c
  5. sibling 0x03817C (the only writer found for the enable byte 0xFFFF7B38): with the shipped
     CBC7A = CBC7C = 0 it writes 0 for every tested input; a positive control on a modified ROM
     (only CBC7C = 0xFFFF) shows the same inputs DO reach 1
  6. the reset routine 0x038860 against a model
  8. stated properties on ordered (non-NaN) values: candidate clamp, one increment +0.0, each WINDUP
     arm, seeds, RAMP arms, dead band, and the decay's sign behaviour: the arm sign (>= 0 on the
     X > K380 arm, <= 0 on the other) for any K380, NO sign change when K380 >= 0, and sign changes
     counted (not forbidden) when K380 < 0
  9. NaN in the anti-windup: every test is a negated strict fcmp/gt, so NaN LO / HI / acc can reach
     SET; explicit cases plus a random check of the exact SET formula, and a count of the cases where
     the old "<= / >=" prose would have predicted KEEP.  Also the K380 < 0 counterexample to "never
     crosses 0": K380 = -1, K394 = -2, X_OUT = -0.5 -> +1.5, X_OUT = +-0 -> +2.0
 10. the store 0x022962..0x022972 (inside 0x022760, GBR 0xFFFF65AA): for all 256 values of ROM byte
     0x0C303F, [0xFFFF65C5] = [0xFFFF65B1] = (byte == 0xAA) ? 0 : 1, nothing else written; the shipped
     byte is 0x55 in 20.19c and stock
 11. sibling 0x03817C, the latches [0xFFFF7B3E] / [0xFFFF7B3F] (0x0381BC..0x0381FA): written 0 when
     [6254] != 1 / [726C] != 0, written 1 on the strict window test, otherwise NOT written; with the
     shipped K350 = 0.0 the [7B3E] set-test can never pass
  7. instruction coverage: every one of the 593 instructions of 0x0382C2 executed at least once

ROUNDING: models compute each fadd / fsub / fmul / fdiv exactly and round TOWARD ZERO (corrections
item 106); fmac is modelled FUSED (one rounding), as the emulator does -- fused-vs-unfused is NOT
settled by the ROM, and the FPU rounding mode in normal running is open-holes #11.  Nothing in the
trace rests on the last bit of a float; bit-exactness here is model-vs-emulator agreement only.

Names are neutral on purpose: nothing here establishes what any RAM cell physically is.
"""
import hashlib
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
import sh2e_disasm as D       # noqa: E402

BIN = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
STOCK = os.path.join(REPO, 'rom', 'ae5l600l.bin')
ROM = open(BIN, 'rb').read()
assert hashlib.md5(ROM).hexdigest() == '92cae8275cd4f9b473a3a9e36efe6449', 'wrong reference bin'
ROM_STOCK = open(STOCK, 'rb').read()

ENTRY, END = 0x0382C2, 0x038860
FN_MODE, FN_ZERO, FN_LUT = 0x022CF4, 0x023E48, 0x0BE830
SIB, RESET = 0x03817C, 0x038860

# ---- inputs outside the block (literal-pool resolved)
I6624, I6350, I8998, I89C4 = 0xFFFF6624, 0xFFFF6350, 0xFFFF8998, 0xFFFF89C4      # f32
I67EC = 0xFFFF67EC                                                              # u16
I6254, I65C5, I67FC, I647D, I726C, I7448 = (0xFFFF6254, 0xFFFF65C5, 0xFFFF67FC,
                                            0xFFFF647D, 0xFFFF726C, 0xFFFF7448)  # u8
I99A8, I99AC, I99B0 = 0xFFFF99A8, 0xFFFF99AC, 0xFFFF99B0                        # f32
# ---- the state block, GBR = 0xFFFF7AF4, r10 = 0xFFFF7B40
X_OUT = 0xFFFF7AF4   # r10-76  f32  output (the clamped value)
OFS = 0xFFFF7AF8     # r10-72  f32  input, subtracted from 0xFFFF6624
LO = 0xFFFF7AFC      # r10-68  f32  lower clamp bound
HI = 0xFFFF7B00      # r10-64  f32  upper clamp bound
DIFF = 0xFFFF7B04    # r10-60  f32  [6624] - [7AF8]
A_I1 = 0xFFFF7B08    # r10-56
A_I2 = 0xFFFF7B0C    # r10-52
A_CAND = 0xFFFF7B10  # r10-48
A_ACC = 0xFFFF7B14   # r10-44
B_I1 = 0xFFFF7B18    # r10-40
B_I2 = 0xFFFF7B1C    # r10-36
B_CAND = 0xFFFF7B20  # r10-32
B_ACC = 0xFFFF7B24   # r10-28
Q1 = 0xFFFF7B28      # r10-24
Q2 = 0xFFFF7B2C      # r10-20
Q3 = 0xFFFF7B30      # r10-16
RAMP = 0xFFFF7B34    # r10-12
EN = 0xFFFF7B38      # gbr+68 u8
CNT16 = 0xFFFF7B3A   # gbr+70 u16
CNT8 = 0xFFFF7B3C    # gbr+72 u8
PREV = 0xFFFF7B40    # gbr+76 u8

F32_CELLS = [X_OUT, OFS, LO, HI, DIFF, A_I1, A_I2, A_CAND, A_ACC, B_I1, B_I2, B_CAND, B_ACC,
             Q1, Q2, Q3, RAMP, I6624, I6350, I8998, I89C4, I99A8, I99AC, I99B0]
U16_CELLS = [CNT16, I67EC]
U8_CELLS = [EN, CNT8, PREV, I6254, I65C5, I67FC, I647D, I726C, I7448]
SIZE = {**{a: 4 for a in F32_CELLS}, **{a: 2 for a in U16_CELLS}, **{a: 1 for a in U8_CELLS}}
BLOCK = [X_OUT, OFS, LO, HI, DIFF, A_I1, A_I2, A_CAND, A_ACC, B_I1, B_I2, B_CAND, B_ACC,
         Q1, Q2, Q3, RAMP, EN, CNT16, CNT8, PREV]

# ---- descriptors (record addresses passed in r4 to 0x0BE830)
D_A_THR, D_A_LO1, D_A_LO2, D_A_HI = 0x0AD470, 0x0AD47C, 0x0AD488, 0x0AD494
D_B_THR, D_B_LO, D_B_HI, D_B_HIT = 0x0AD4A0, 0x0AD4AC, 0x0AD4B8, 0x0AD4C4
D_A_LOT, D_A_HIT, D_B_LOT = 0x0AC65C, 0x0AC670, 0x0AC684
D_RAMP, D_LO_N, D_LO_T, D_HI_N, D_HI_T = 0x0AC698, 0x0AC6AC, 0x0AC6C0, 0x0AC6D4, 0x0AC6E8
ALL_DESC = [D_A_THR, D_A_LO1, D_A_LO2, D_A_HI, D_B_THR, D_B_LO, D_B_HI, D_B_HIT,
            D_A_LOT, D_A_HIT, D_B_LOT, D_RAMP, D_LO_N, D_LO_T, D_HI_N, D_HI_T]

# ---- calibration scalars
K_CBFE, K_C84, K_C8A = 0x0CBBFE, 0x0CBC84, 0x0CBC8A          # u8, u16, u16
K368, K36C, K370, K374, K378, K37C, K380 = 0x0CC368, 0x0CC36C, 0x0CC370, 0x0CC374, 0x0CC378, 0x0CC37C, 0x0CC380
K384, K388, K38C, K390, K394, K398, K39C, K3A0 = (0x0CC384, 0x0CC388, 0x0CC38C, 0x0CC390,
                                                  0x0CC394, 0x0CC398, 0x0CC39C, 0x0CC3A0)
F_SCALARS = [K368, K36C, K370, K374, K378, K37C, K380, K384, K388, K38C, K390, K394, K398, K39C, K3A0]

ONE, MONE, PZERO, NZERO = 0x3F800000, 0xBF800000, 0x00000000, 0x80000000
f2b, b2f = E.f2b, E.b2f


# ================================================================ float model primitives
def arith(op, xb, yb):
    """fadd / fsub / fmul / fdiv: exact result rounded toward zero. xb, yb float32 bits."""
    x, y = b2f(xb), b2f(yb)
    f = {'+': lambda a, b: a + b, '-': lambda a, b: a - b,
         '*': lambda a, b: a * b, '/': lambda a, b: a / b}[op]
    if op == '/' and y == 0.0:
        raise AssertionError('unguarded divide by zero in model')
    ieee = f(x, y)
    if not (math.isfinite(x) and math.isfinite(y)):
        return f2b(ieee)
    q = f(Fraction(x), Fraction(y))
    return f2b(ieee) if q == 0 else E.rz_bits(q)


def fadd(a, b): return arith('+', a, b)
def fsub(a, b): return arith('-', a, b)       # a - b
def fmul(a, b): return arith('*', a, b)


def fmac(a, b, c):
    """a * b + c, rounded ONCE toward zero (fused -- the emulator's choice, not settled by the ROM)."""
    x, y, z = b2f(a), b2f(b), b2f(c)
    ieee = x * y + z
    if not (math.isfinite(x) and math.isfinite(y) and math.isfinite(z)):
        return f2b(ieee)
    q = Fraction(x) * Fraction(y) + Fraction(z)
    return f2b(ieee) if q == 0 else E.rz_bits(q)


def gt(a, b):
    """fcmp/gt b,a : T = (a > b); false when either is NaN."""
    return b2f(a) > b2f(b)


def clamp(x, lo, hi):               # 0x0BE56C contract
    if not gt(x, lo):
        return lo
    if gt(hi, x):
        return x
    return hi


def fmax(a, b): return a if gt(a, b) else b     # 0x0BE960
def fmin(a, b): return a if gt(b, a) else b     # 0x0BE970


def safe_div(a, b):                 # 0x0BE628
    if b2f(b) != 0.0:
        return arith('/', a, b)
    if b2f(a) == 0.0:
        return PZERO
    return 0x7F7FFFFF if b2f(a) > 0 else 0xFF7FFFFF


def sext(v, bits):
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


def cmp_hs_sext(a, b, bits):
    """mov.b/mov.w (sign-extend) both, then cmp/hs b,a : T = (a as u32) >= (b as u32)."""
    return (sext(a, bits) & 0xFFFFFFFF) >= (sext(b, bits) & 0xFFFFFFFF)


def rf(rom, a): return struct.unpack_from('>I', rom, a)[0]
def ru16(rom, a): return struct.unpack_from('>H', rom, a)[0]


# ================================================================ model of 0x0382C2
def model(c, rom, lut):
    """c: dict addr -> value (f32 BITS / ints).  lut(desc, xbits) -> bits.
    Returns (mem, reads, writes, calls)."""
    mem = dict(c)
    init, reads, writes, calls = set(), set(), set(), []

    def rd(a):
        if a not in init:
            reads.add(a)
        return mem[a]

    def wr(a, v):
        mem[a] = v
        init.add(a)
        writes.update(range(a, a + SIZE[a]))

    def L(d, x):
        calls.append((d, x))
        return lut(d, x)

    fr14 = rd(I6624); fr13 = rd(I6350); fr15 = rd(I8998); fr12 = rd(I89C4)
    r13 = rd(I67EC)
    r12 = rd(I6254)
    sp0 = 1 if rd(I65C5) == 1 else 0              # 0x022CF4
    sp4 = 1 if rd(I67FC) == 1 else 0              # 0x023E48
    r14 = rd(I647D)
    sp8, sp12, sp16 = rd(I99A8), rd(I99AC), rd(I99B0)
    fr14 = fsub(fr14, rd(OFS))                    # 038322 fsub fr9,fr14
    wr(DIFF, fr14)

    # ---------------- part A (0x038328 .. 0x0384FE)
    if rd(EN) == 1:
        fr0 = L(D_A_THR, fr13)
        if gt(fr15, fr0) and gt(fr12, rf(rom, K368)):
            sp20 = L(D_A_HI, rd(DIFF))
            fr0 = L(D_A_HIT, fr13)
            wr(A_I2, fmul(sp20, fr0))
            fr14 = PZERO
            wr(A_I1, fr14)
        else:
            d = D_A_LO2 if sp0 == 1 else D_A_LO1
            fr14 = L(d, rd(DIFF))
            fr0 = L(D_A_LOT, fr13)
            fr14 = fmul(fr14, fr0)
            wr(A_I1, fr14)
            fr14 = PZERO
            wr(A_I2, fr14)
        cnt = rd(CNT16)
        fr4 = rd(A_ACC)
        if cmp_hs_sext(cnt, ru16(rom, K_C84), 16):
            fr4 = fadd(fr4, rd(A_I1))
            fr4 = fadd(fr4, rd(A_I2))
        else:
            fr0 = fadd(rd(A_I1), rd(A_I2))
            fr4 = fmac(fr0, rf(rom, K36C), fr4)
        wr(A_CAND, clamp(fr4, MONE, ONE))
        if rd(PREV) == 0:
            wr(A_ACC, fmin(rd(X_OUT), fr14))
        elif gt(rf(rom, K370), rd(B_ACC)) and (r14 & 0xFF) != 1:
            # anti-windup 0x03849C .. 0x0384EC
            go = None
            if gt(rd(X_OUT), rd(LO)) and gt(rd(HI), rd(X_OUT)):
                go = 'set'
            if go is None and gt(rd(HI), rd(X_OUT)) and not gt(rd(A_ACC), rd(A_CAND)):
                go = 'set'
            if go is None:
                if not gt(rd(X_OUT), rd(LO)):
                    go = 'keep'
                elif gt(rd(A_CAND), rd(A_ACC)):
                    go = 'keep'
                else:
                    go = 'set'
            if go == 'set':
                wr(A_ACC, rd(A_CAND))
        else:
            wr(A_ACC, fr14)
    else:
        fr14 = PZERO
        for a in (A_I1, A_I2, A_CAND, A_ACC):
            wr(a, fr14)

    # ---------------- part B (0x038500 .. 0x03861C)
    if rd(EN) == 1:
        fr0 = L(D_B_THR, fr13)
        if gt(fr0, fr15) or gt(rf(rom, K374), fr12):
            sp28 = L(D_B_LO, rd(DIFF))
            fr0 = L(D_B_LOT, fr13)
            wr(B_I1, fmul(sp28, fr0))
            wr(B_I2, fr14)
        else:
            sp24 = L(D_B_HI, rd(DIFF))
            fr0 = L(D_B_HIT, fr13)
            wr(B_I2, fmul(sp24, fr0))
            wr(B_I1, fr14)
        cnt = rd(CNT16)
        fr4 = rd(B_ACC)
        if cmp_hs_sext(cnt, ru16(rom, K_C8A), 16):
            fr4 = fadd(fr4, rd(B_I1))
            fr4 = fadd(fr4, rd(B_I2))
        else:
            fr0 = fadd(rd(B_I1), rd(B_I2))
            fr4 = fmac(fr0, rf(rom, K378), fr4)
        wr(B_CAND, clamp(fr4, MONE, ONE))
        if rd(PREV) == 0:
            wr(B_ACC, fmax(rd(X_OUT), fr14))
        else:
            go = None
            if gt(rd(X_OUT), rd(LO)) and gt(rd(HI), rd(X_OUT)):
                go = 'set'
            if go is None and gt(rd(HI), rd(X_OUT)) and not gt(rd(B_ACC), rd(B_CAND)):
                go = 'set'
            if go is None:
                if not gt(rd(X_OUT), rd(LO)):
                    go = 'keep'
                elif gt(rd(B_CAND), rd(B_ACC)):
                    go = 'keep'
                else:
                    go = 'set'
            if go == 'set':
                wr(B_ACC, fmax(rd(B_CAND), fr14))
    else:
        for a in (B_I1, B_I2, B_CAND, B_ACC):
            wr(a, fr14)

    # ---------------- counter (0x03861E .. 0x03869A)
    if rd(I726C) == 0:
        v = min(rd(CNT8) + 1, 0xFF)               # 0x0BE53C
        wr(CNT8, v)
        r14 = 1 if cmp_hs_sext(rd(CNT8), rom[K_CBFE], 8) else 0
    else:
        r14 = 0
        wr(CNT8, 0)

    # ---------------- part E (0x03869C .. 0x038706)
    if rd(EN) == 1:
        if r14 == 1:
            wr(Q1, safe_div(fsub(sp16, sp8), f2b(4.0)))
            wr(Q2, fsub(sp12, sp8))
            wr(Q3, fsub(rd(Q1), rd(Q2)))
        t = L(D_RAMP, rd(Q3))
        cur = rd(RAMP)
        if gt(ONE, cur):
            v = fmin(cur, t)
            v = fadd(v, rf(rom, K37C))
            v = fmin(v, ONE)
            wr(RAMP, v)
        else:
            wr(RAMP, t)

    # ---------------- output (0x038708 .. 0x038842)
    if sp4 == 1:
        wr(X_OUT, fr14)
    elif rd(EN) == 1:
        sp32 = fmac(f2b(8.0), f2b(float(r13 & 0xFFFF)), fr14)     # 0x0BE598, exact
        sp36 = L(D_LO_N, sp32)
        sp40 = L(D_HI_N, sp32)
        sp44 = L(D_LO_T, fr13)
        fr0 = L(D_HI_T, fr13)
        wr(LO, fmul(sp36, sp44))
        wr(HI, fmul(sp40, fr0))
        if gt(fr14, rd(X_OUT)):
            fr8 = fmul(fadd(rd(A_ACC), rd(B_ACC)), rd(RAMP))
        else:
            fr8 = fadd(rd(A_ACC), rd(B_ACC))
        wr(X_OUT, clamp(fr8, rd(LO), rd(HI)))
    else:
        if sp0 == 1:
            f5, f7, f6, f9 = rf(rom, K388), rf(rom, K390), rf(rom, K398), rf(rom, K3A0)
        else:
            f5, f7, f6, f9 = rf(rom, K384), rf(rom, K38C), rf(rom, K394), rf(rom, K39C)
        x = rd(X_OUT)
        db = rf(rom, K380)
        if gt(x, db) or gt(db ^ 0x80000000, x):
            if rd(I7448) == 0 and r12 == 0:
                if gt(x, db):
                    wr(X_OUT, fmax(fsub(x, f6), fr14))
                else:
                    wr(X_OUT, fmin(fadd(x, f9), fr14))
            else:
                if gt(x, db):
                    wr(X_OUT, fmax(fsub(x, f5), fr14))
                else:
                    wr(X_OUT, fmin(fadd(x, f7), fr14))
        else:
            wr(X_OUT, fr14)
    wr(PREV, rd(EN))
    return mem, reads, writes, calls


# ================================================================ emulator harness
SENT = {8: 0x08080808, 9: 0x09090909, 10: 0x0A0A0A0A, 11: 0x0B0B0B0B,
        12: 0x0C0C0C0C, 13: 0x0D0D0D0D, 14: 0x0E0E0E0E}
FSENT = {12: 0x41C80000, 13: 0xC1C80000, 14: 0x42F60000, 15: 0xC2F60000}
GBR_SENT = 0xFFFF1234
_emus = {}
COVER = set()
_rng_regs = random.Random(0x382C2)


def emu_for(rom):
    k = id(rom)
    if k not in _emus:
        _emus[k] = E.Emu(rom)
    return _emus[k]


def poke(e, a, n, v):
    o = a - E.RAM_LO
    e.ram[o:o + n] = (v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big')


def peek(e, a, n):
    o = a - E.RAM_LO
    return int.from_bytes(e.ram[o:o + n], 'big')


def reset_emu(e):
    e.init = bytearray(len(e.init))
    e.uninit_reads.clear()
    e.writes.clear()
    e.stubs.clear()
    e.stack_low = E.STACK_TOP
    e.steps = 0
    e.ram = bytearray(len(e.ram))


_lut_cache = {}


def rom_lookup(rom, d, xb):
    k = (id(rom), d, xb)
    if k not in _lut_cache:
        e = E.Emu(rom)
        e.call(FN_LUT, regs={4: d}, fregs={4: b2f(xb)})
        _lut_cache[k] = e.FR[0]
    return _lut_cache[k]


def run(c, rom, stub_lut=None):
    """Run 0x0382C2 once and assert everything against the model. Returns the model memory."""
    e = emu_for(rom)
    reset_emu(e)
    for a, v in c.items():
        poke(e, a, SIZE[a], v)
    got_calls = []
    if stub_lut is not None:
        def _lut(m):
            got_calls.append((m.R[4], m.FR[4]))
            m.FR[0] = stub_lut(m.R[4], m.FR[4])
        e.stub(FN_LUT, fn=_lut)
        lut = stub_lut
    else:
        lut = lambda d, x: rom_lookup(rom, d, x)     # noqa: E731
    regs = {i: _rng_regs.getrandbits(32) for i in range(8)}
    regs.update(SENT)
    for i in range(12):
        e.FR[i] = _rng_regs.getrandbits(32)
    for i, v in FSENT.items():
        e.FR[i] = v
    e.gbr = GBR_SENT
    e.executed = set()
    assert e.call(ENTRY, regs=regs) == 'return'
    COVER.update(p for p in e.executed if ENTRY <= p < END)
    want, reads, writes, calls = model(c, rom, lut)
    tag = ' '.join(f'{a & 0xFFFF:04X}={v:#x}' for a, v in sorted(c.items()))
    for a in BLOCK:
        g = peek(e, a, SIZE[a])
        assert g == want[a], f'OUTPUT MISMATCH at {a:#x}: got {g:#x} want {want[a]:#x}\n{tag}'
    assert set(e.writes) == writes, (f'WRITE-SET MISMATCH\n got  {sorted(map(hex, e.writes))}'
                                     f'\n want {sorted(map(hex, writes))}\n{tag}')
    assert e.uninit_reads == reads, (f'READ-SET MISMATCH\n got  {sorted(map(hex, e.uninit_reads))}'
                                     f'\n want {sorted(map(hex, reads))}\n{tag}')
    for i, v in SENT.items():
        assert e.R[i] == v, f'r{i} not preserved'
    assert e.R[15] == E.STACK_TOP, 'r15 not restored'
    assert e.gbr == GBR_SENT, 'GBR not restored'
    for i, v in FSENT.items():
        assert e.FR[i] == v, f'fr{i} not preserved'
    if stub_lut is not None:
        assert got_calls == calls, f'CALL MISMATCH\n got  {got_calls}\n want {calls}\n{tag}'
    return want, reads, writes, calls


# ================================================================ case generator
FVALS = [0.0, -0.0, 0.25, -0.25, 0.5, -0.5, 1.0, -1.0, 1.5, -1.5, 3.0, -3.0, 0.125, -0.75,
         100.0, -40.0, 2500.0, 1e-3, 1e30, -1e30]
FSPECIAL = [math.inf, -math.inf, math.nan]


def fv(r, special=0.03):
    if r.random() < special:
        return f2b(r.choice(FSPECIAL))
    if r.random() < 0.3:
        return f2b(r.uniform(-2.0, 2.0))
    return f2b(r.choice(FVALS))


def make_case(r):
    c = {}
    for a in F32_CELLS:
        c[a] = fv(r)
    # clamp bounds and output placed relative to each other so every anti-windup arm is reached
    lo = r.choice([-1.0, -0.5, 0.0, 0.25, r.uniform(-1, 1)])
    hi = r.choice([lo + 0.5, lo + 1.0, lo, lo - 0.5, r.uniform(-1, 1)])
    x = r.choice([lo - 0.25, lo, (lo + hi) / 2, hi, hi + 0.25, 0.0, -0.0, r.uniform(-2, 2)])
    c[LO], c[HI], c[X_OUT] = f2b(lo), f2b(hi), f2b(x)
    c[RAMP] = f2b(r.choice([1.0, 0.0, 0.5, 1.25, 0.999, -0.5, r.uniform(-0.5, 1.5)]))
    c[A_ACC] = f2b(r.choice([0.0, -0.5, 0.5, -1.0, r.uniform(-1.2, 1.2)]))
    c[B_ACC] = f2b(r.choice([0.0, -0.5, 0.5, 1.0, r.uniform(-1.2, 1.2)]))
    c[EN] = r.choice([1, 1, 1, 0, 2, 0xFF, 0x81])
    c[PREV] = r.choice([0, 1, 1, 2, 0xFF])
    c[I65C5] = r.choice([0, 1, 2, 0xFF, 0x81])
    c[I67FC] = r.choice([0, 0, 0, 1, 2, 0x81])
    c[I647D] = r.choice([0, 1, 2, 0x81, 0xFF])
    c[I726C] = r.choice([0, 0, 1, 0x80])
    c[I7448] = r.choice([0, 1, 0x80])
    c[I6254] = r.choice([0, 0, 1, 0x80, 0xFF])
    c[CNT8] = r.choice([0, 1, 2, 0x7F, 0x80, 0xFE, 0xFF, r.randrange(256)])
    c[CNT16] = r.choice([0, 1, 2, 0x7FFF, 0x8000, 0x8001, 0xFFFE, 0xFFFF, r.randrange(65536)])
    c[I67EC] = r.choice([0, 1, 2, 0x7FFF, 0x8000, 0xFFFF, r.randrange(65536)])
    return c


def mrom(r, tables=False):
    """An in-memory ROM copy with test calibration (never written to disk)."""
    m = bytearray(ROM)
    for a in F_SCALARS:
        m[a:a + 4] = struct.pack('>I', f2b(r.choice([0.0, 0.25, 0.5, -0.25, 0.125, 1.0, 2.0,
                                                     r.uniform(-1.5, 1.5)])))
    m[K_CBFE] = r.choice([0, 1, 2, 0x7F, 0x80, 0xFE, 0xFF])
    for a in (K_C84, K_C8A):
        m[a:a + 2] = struct.pack('>H', r.choice([0, 1, 2, 0x7FFF, 0x8000, 0x8001, 0xFFFF]))
    if tables:
        # every data cell gets a value unique to its address; axes untouched
        for d in ALL_DESC:
            n = struct.unpack_from('>H', m, d)[0]
            tc = m[d + 2]
            dp = struct.unpack_from('>I', m, d + 8)[0]
            for i in range(n):
                if tc == 0:
                    m[dp + 4 * i:dp + 4 * i + 4] = struct.pack('>I', f2b(r.uniform(-1.0, 1.0)))
                else:
                    m[dp + i] = r.randrange(256)
    return bytes(m)


def make_stub(r):
    k = {d: (r.uniform(-0.8, 0.8), r.choice([0.0, 0.01, -0.01, 0.003])) for d in ALL_DESC}

    def lut(d, xb):
        a, b = k[d]
        x = b2f(xb)
        if x != x:
            x = 0.0
        x = max(-1e4, min(1e4, x))
        return f2b(a + b * x)
    return lut


# ================================================================ passes
def pass0():
    n = 0
    for fn, cell in ((FN_MODE, I65C5), (FN_ZERO, I67FC)):
        for v in range(256):
            e = E.Emu(ROM)
            e.ram_u8(cell, v)
            e.call(fn)
            assert e.R[0] == (1 if v == 1 else 0), (hex(fn), v)
            n += 1
    # sign-extend + unsigned compare == unsigned compare of the raw value: the map raw -> (sext(raw) as
    # u32) is strictly increasing over the whole raw range, so it preserves every >= comparison
    for bits in (8, 16):
        seq = [sext(v, bits) & 0xFFFFFFFF for v in range(1 << bits)]
        assert all(seq[i] < seq[i + 1] for i in range(len(seq) - 1)), bits
    print(f'pass 0: 0x022CF4 / 0x023E48 == (byte == 1) over 256 bytes each ({n} calls); '
          f'sext8 / sext16 then cmp/hs == unsigned compare (exhaustive monotonicity)')


def show(c, want):
    return (f'EN={c[EN]:#04x} PREV={c[PREV]:#04x} 65C5={c[I65C5]:#04x} 67FC={c[I67FC]:#04x} '
            f'x_in={b2f(c[X_OUT]):.6g} -> x_out={b2f(want[X_OUT]):.6g} ({want[X_OUT]:#010x}) '
            f'accA={b2f(want[A_ACC]):.6g} accB={b2f(want[B_ACC]):.6g} ramp={b2f(want[RAMP]):.6g}')


def pass1(N=1500):
    r = random.Random(1)
    shipped_en = 0
    for i in range(N):
        c = make_case(r)
        want, reads, writes, calls = run(c, ROM)
        if i < 6:
            print('  P1', show(c, want))
        # as-shipped consequences: every table read here is physically 0.0 (AC6AC / AC6D4 store raw 0x80
        # with scale 1/256 and bias -0.5, also 0.0), so both clamp bounds are +0.0
        if c[I67FC] == 1:
            assert want[X_OUT] == PZERO
        elif c[EN] == 1:
            assert want[LO] == PZERO and want[HI] == PZERO and want[X_OUT] == PZERO, show(c, want)
            for a in (A_I1, A_I2, B_I1, B_I2):
                assert want[a] == PZERO
            shipped_en += 1
        else:
            for a in (A_I1, A_I2, A_CAND, A_ACC, B_I1, B_I2, B_CAND, B_ACC):
                assert want[a] == PZERO
    # every lookup on the shipped ROM returns +0.0 (also the two raw-0x80, bias -0.5 records)
    for d in ALL_DESC:
        for x in (-1e30, -40.0, 0.0, 7.5, 15.0, 110.0, 1e30, math.nan):
            v = rom_lookup(ROM, d, f2b(x))
            assert v == PZERO, (hex(d), x, hex(v))
    print(f'pass 1: real ROM, real callees: {N} cases ({shipped_en} enabled, all with output +0.0 '
          f'and both bounds +0.0); all 16 lookups return +0.0 at every tested x')


def pass2(variants=8, N=500):
    r = random.Random(2)
    n = 0
    for v in range(variants):
        m = mrom(r)
        lut = make_stub(r)
        for i in range(N):
            c = make_case(r)
            want, reads, writes, calls = run(c, m, stub_lut=lut)
            if v == 0 and i < 4:
                print('  P2', show(c, want), f'lookups={len(calls)}')
            n += 1
    print(f'pass 2: {variants} modified-cal ROM copies x {N} cases, 0x0BE830 stubbed: {n} cases, '
          f'descriptor/input pairs, outputs, read/write sets exact')


def pass3(variants=4, N=300):
    r = random.Random(3)
    n = 0
    for v in range(variants):
        m = mrom(r, tables=True)
        for i in range(N):
            c = make_case(r)
            # axis inputs inside the table range so interpolation is exercised
            c[I6350] = f2b(r.uniform(-50.0, 120.0))
            c[I6624] = f2b(r.uniform(-2.0, 18.0))
            c[OFS] = f2b(r.choice([0.0, 1.0, -1.0]))
            c[I67EC] = r.randrange(3)
            want, reads, writes, calls = run(c, m)
            if v == 0 and i < 3:
                print('  P3', show(c, want))
            n += 1
    print(f'pass 3: {variants} ROM copies with every table cell populated, real 0x0BE830: {n} cases exact')


def pass4(N=300):
    r = random.Random(4)
    for i in range(N):
        c = make_case(r)
        a, _, _, _ = run(c, ROM)
        b, _, _, _ = run(c, ROM_STOCK)
        assert a == b
    print(f'pass 4: stock rom/ae5l600l.bin == 20.19c on {N} cases')


# ---------------- sibling 0x03817C: the only writer found for EN (0x03827E)
S_IN = dict(i6354=0xFFFF6354, i7fbc=0xFFFF7FBC, i895c=0xFFFF895C, i6624=0xFFFF6624, i65fc=0xFFFF65FC,
            i67ec=0xFFFF67EC, i6254=0xFFFF6254, i65c0=0xFFFF65C0, i67fc=0xFFFF67FC, i726c=0xFFFF726C,
            i7448=0xFFFF7448, i798c=0xFFFF798C, i3158=0xFFFF3158)


def sib_run(rom, vals, b3e=1, b3f=0):
    e = E.Emu(rom)
    for k, a in S_IN.items():
        n = 2 if k == 'i67ec' else (1 if k in ('i6254', 'i65c0', 'i67fc', 'i726c', 'i7448', 'i3158') else 4)
        poke(e, a, n, vals[k])
    poke(e, 0xFFFF7B3E, 1, b3e)
    poke(e, 0xFFFF7B3F, 1, b3f)
    e.call(SIB)
    assert (EN + 0) in e.writes            # written on every call
    return e.ram[EN - E.RAM_LO]


def sat_inputs(i67ec):
    """inputs that pass every 0x03817C test except, possibly, the 0xFFFF67EC window."""
    return dict(i6354=f2b(118.5), i7fbc=f2b(1.0), i895c=f2b(1000.0), i6624=f2b(2000.0),
                i65fc=f2b(-1.0), i67ec=i67ec, i6254=1, i65c0=0, i67fc=0, i726c=0, i7448=0,
                i798c=f2b(0.0), i3158=0)


def pass5():
    r = random.Random(5)
    # positive control: ONLY the window opened (CBC7C = 0xFFFF) -> the same inputs give EN = 1, so the
    # satisfying inputs pass every other test with the shipped values (incl. K360 = 0.0 > [65FC] = -1.0)
    m = bytearray(ROM)
    m[0x0CBC7C:0x0CBC7E] = b'\xFF\xFF'
    m = bytes(m)
    pos = sum(sib_run(m, sat_inputs(v)) == 1 for v in (0, 1, 2, 0x7FFF, 0x8000, 0xFFFE))
    assert pos == 6, pos
    assert sib_run(m, sat_inputs(0xFFFF)) == 0           # 0xFFFF is outside [0, 0xFFFF)
    # shipped ROM: identical satisfying inputs, every 0xFFFF67EC tested -> 0
    vals67 = [0, 1, 2, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF] + [r.randrange(65536) for _ in range(300)]
    for v in vals67:
        assert sib_run(ROM, sat_inputs(v)) == 0, v
        assert sib_run(ROM_STOCK, sat_inputs(v)) == 0, v
    # and fully random inputs
    for _ in range(300):
        vals = {k: (r.randrange(65536) if k == 'i67ec' else
                    r.randrange(256) if k in ('i6254', 'i65c0', 'i67fc', 'i726c', 'i7448', 'i3158') else fv(r, 0))
                for k in S_IN}
        assert sib_run(ROM, vals, r.randrange(256), r.randrange(256)) == 0
    print(f'pass 5: sibling 0x03817C writes EN = 0 on the shipped ROM: {len(vals67) * 2} runs with every '
          f'other test satisfied (stock + 20.19c) and 300 random runs; positive control with only '
          f'CBC7C = 0xFFFF reaches EN = 1 for 6 window values, 0 for 0xFFFF')


def pass6(N=200):
    r = random.Random(6)
    zeroed = [A_I2, A_I1, A_CAND, A_ACC, B_I1, B_I2, B_ACC, B_CAND, X_OUT]
    for i in range(N):
        e = E.Emu(ROM)
        f65f6 = r.choice([0, 1, 2, 0x81])
        en = r.randrange(256)
        poke(e, 0xFFFF65F6, 1, f65f6)
        poke(e, EN, 1, en)
        for a in zeroed + [RAMP]:
            poke(e, a, 4, r.getrandbits(32))
        poke(e, CNT8, 1, 0x55)
        poke(e, PREV, 1, 0x66)
        assert e.call(RESET) == 'return'
        if f65f6 == 1:
            for a in zeroed:
                assert peek(e, a, 4) == 0
            assert peek(e, RAMP, 4) == ONE and peek(e, CNT8, 1) == 0 and peek(e, PREV, 1) == en
            want_w = set()
            for a in zeroed + [RAMP]:
                want_w |= set(range(a, a + 4))
            want_w |= {CNT8, PREV}
            assert set(e.writes) == want_w
        else:
            assert set(e.writes) == set()
    print(f'pass 6: reset routine 0x038860: {N} cases (acts only when byte 0xFFFF65F6 == 1)')


def pass8(variants=6, N=400):
    """Stated properties, asserted on emulator-verified outputs (no NaN / inf inputs: ordered values only)."""
    r = random.Random(8)
    hits = dict(inside=0, at_lo=0, at_hi=0, inverted=0, deadband=0, decay_k380_nonneg=0,
                decay_k380_neg=0, ramp_rise=0, ramp_load=0)
    crossings_k380_neg = 0
    for v in range(variants):
        m = mrom(r)
        lut = make_stub(r)
        for i in range(N):
            c = make_case(r)
            for a in F32_CELLS:
                if not math.isfinite(b2f(c[a])):
                    c[a] = f2b(0.75)
            c[EN] = r.choice([1, 1, 1, 0])
            c[PREV] = r.choice([1, 1, 0])
            c[I67FC] = r.choice([0, 0, 0, 1])
            want, reads, writes, calls = run(c, m, stub_lut=lut)
            x, lo, hi = b2f(c[X_OUT]), b2f(c[LO]), b2f(c[HI])
            # (1) the accumulate-and-clamp step: CAND = clamp(ACC_old + inc, -1, 1)
            if c[EN] == 1:
                for acc, i1, i2, cand, kc, kg in ((A_ACC, A_I1, A_I2, A_CAND, K_C84, K36C),
                                                  (B_ACC, B_I1, B_I2, B_CAND, K_C8A, K378)):
                    s = fadd(want[i1], want[i2])
                    if c[CNT16] >= ru16(m, kc):
                        inc_sum = fadd(fadd(c[acc], want[i1]), want[i2])
                    else:
                        inc_sum = fmac(s, rf(m, kg), c[acc])
                    assert want[cand] == clamp(inc_sum, MONE, ONE)
                    assert -1.0 <= b2f(want[cand]) <= 1.0
                    # exactly one of the two increments is +0.0
                    assert want[i1] == PZERO or want[i2] == PZERO
            # (2) anti-windup on the accumulators (uses the PREVIOUS x / lo / hi)
            if c[EN] == 1 and c[PREV] != 0:
                for acc, cand, gate in ((A_ACC, A_CAND, b2f(rf(m, K370)) > b2f(c[B_ACC]) and c[I647D] != 1),
                                        (B_ACC, B_CAND, True)):
                    if not gate:
                        assert want[acc] == PZERO
                        continue
                    old, new = c[acc], want[cand]
                    setv = new if acc == A_ACC else fmax(new, PZERO)
                    if lo < x < hi:
                        assert want[acc] == setv; hits['inside'] += 1
                    elif x <= lo and hi > x:
                        assert want[acc] == (old if b2f(old) > b2f(new) else setv); hits['at_lo'] += 1
                    elif x >= hi and x > lo:
                        assert want[acc] == (old if b2f(new) > b2f(old) else setv); hits['at_hi'] += 1
                    else:
                        assert want[acc] == old; hits['inverted'] += 1
            # (3) first enabled call after a disabled one: ACC_A = min(x, 0), ACC_B = max(x, 0)
            if c[EN] == 1 and c[PREV] == 0:
                assert want[A_ACC] == fmin(c[X_OUT], PZERO) and want[B_ACC] == fmax(c[X_OUT], PZERO)
            # (4) the ramp cell
            if c[EN] == 1:
                t = calls[[d for d, _ in calls].index(D_RAMP)]
                tv = lut(*t)
                if b2f(c[RAMP]) < 1.0:
                    assert want[RAMP] == fmin(fadd(fmin(c[RAMP], tv), rf(m, K37C)), ONE); hits['ramp_rise'] += 1
                else:
                    assert want[RAMP] == tv; hits['ramp_load'] += 1
            # (5) disabled output: dead band, then a step floored / capped at +0.0.
            #     The ARM sign (o >= 0 on the X > K380 arm, o <= 0 on the other) holds for every K380.
            #     A SIGN CHANGE (x > 0 -> o < 0, or x < 0 -> o > 0) is forbidden only when K380 >= 0;
            #     with K380 < 0 it is possible (pass 9 shows one) and is only counted here.
            if c[EN] != 1 and c[I67FC] != 1:
                db = b2f(rf(m, K380))
                o = b2f(want[X_OUT])
                assert want[X_OUT] != NZERO              # max / min against +0.0 never return -0.0
                if not (x > db) and not (-db > x):
                    assert want[X_OUT] == PZERO; hits['deadband'] += 1
                else:
                    if x > db:
                        assert o >= 0.0
                    else:
                        assert o <= 0.0
                    crossed = (x > 0.0 and o < 0.0) or (x < 0.0 and o > 0.0)
                    if db >= 0.0:
                        assert not crossed, (x, db, o)
                        hits['decay_k380_nonneg'] += 1
                    else:
                        hits['decay_k380_neg'] += 1
                        crossings_k380_neg += crossed
            # (6) the previous-enable byte copies EN every call
            assert want[PREV] == c[EN]
    for k, n in hits.items():
        assert n > 0, f'property arm {k} never exercised'
    print(f'pass 8: stated properties hold on {variants * N} emulator-verified cases; arms hit: '
          + ', '.join(f'{k} {n}' for k, n in hits.items())
          + f'; sign changes seen with K380 < 0 (allowed, not asserted): {crossings_k380_neg}')


# ---------------- pass 9: NaN in the anti-windup, and the K380 < 0 counterexample
NAN_B = 0x7FC00000


def base_case():
    c = {a: PZERO for a in F32_CELLS}
    c.update({a: 0 for a in U16_CELLS})
    c.update({a: 0 for a in U8_CELLS})
    c[EN], c[PREV], c[RAMP] = 1, 1, ONE
    return c


def windup_set(x, lo, hi, acc, cand):
    """SET formula from the bytes: 0x0384A4..0x0384E2 (part A) / 0x0385BE..0x0385FC (part B)."""
    a, b = gt(x, lo), gt(hi, x)
    return (a and b) or (not a and b and not gt(acc, cand)) or (a and not b and not gt(cand, acc))


def windup_old_prose(x, lo, hi, acc, cand):
    """The trace's former '<= / >=' wording (wrong under NaN), kept only to count disagreements."""
    X, L, H, A, C = (b2f(v) for v in (x, lo, hi, acc, cand))
    if L < X < H:
        return True
    if X <= L and H > X:
        return C >= A
    if X >= H and X > L:
        return C <= A
    return False


def pass9(variants=4, N=400):
    # ---- explicit cases on the real ROM (all tables 0.0: I1 = I2 = +0.0, so CAND = clamp(ACC, -1, 1))
    ex = []
    c = base_case(); c[X_OUT], c[LO], c[HI], c[B_ACC] = f2b(0.3), NAN_B, f2b(0.5), f2b(-0.4)
    w, *_ = run(c, ROM); assert w[B_ACC] == PZERO; ex.append('LO=NaN: B_ACC -0.4 -> +0.0 (SET)')
    c = base_case(); c[X_OUT], c[LO], c[HI], c[B_ACC] = f2b(0.3), f2b(0.2), NAN_B, f2b(-0.4)
    w, *_ = run(c, ROM); assert w[B_ACC] == PZERO; ex.append('HI=NaN: B_ACC -0.4 -> +0.0 (SET)')
    for xv, tag in ((0.2, 'at LO'), (0.5, 'at HI')):
        c = base_case()
        c[X_OUT], c[LO], c[HI], c[A_ACC], c[B_ACC] = f2b(xv), f2b(0.2), f2b(0.5), NAN_B, f2b(-0.5)
        w, *_ = run(c, ROM)          # K370 = 0.0 > B_ACC = -0.5 opens part A's gate
        assert w[A_CAND] == MONE and w[A_ACC] == MONE
        ex.append(f'A_ACC=NaN {tag}: A_ACC NaN -> -1.0 (SET)')
    c = base_case(); c[X_OUT], c[LO], c[HI], c[A_ACC], c[B_ACC] = NAN_B, f2b(0.2), f2b(0.5), f2b(0.7), f2b(-0.5)
    w, *_ = run(c, ROM); assert w[A_ACC] == f2b(0.7) and w[B_ACC] == f2b(-0.5)
    ex.append('X_OUT=NaN: both KEEP')
    # ---- random: NaN injected into X_OUT / LO / HI / A_ACC / B_ACC; the SET formula must match
    r = random.Random(9)
    n = disagree = nan_set = 0
    for v in range(variants):
        m = mrom(r)
        lut = make_stub(r)
        for i in range(N):
            c = make_case(r)
            for a in F32_CELLS:
                if not math.isfinite(b2f(c[a])):
                    c[a] = f2b(0.75)
            for a in r.sample([X_OUT, LO, HI, A_ACC, B_ACC], r.choice([1, 1, 2])):
                c[a] = NAN_B
            c[EN], c[PREV], c[I67FC] = 1, r.choice([1, 2, 0xFF]), 0
            c[I647D] = r.choice([0, 2])
            want, *_ = run(c, m, stub_lut=lut)
            x, lo, hi = c[X_OUT], c[LO], c[HI]
            for acc, cand, gate in ((A_ACC, A_CAND, gt(rf(m, K370), c[B_ACC])), (B_ACC, B_CAND, True)):
                if not gate:
                    assert want[acc] == PZERO
                    continue
                s = windup_set(x, lo, hi, c[acc], want[cand])
                setv = want[cand] if acc == A_ACC else fmax(want[cand], PZERO)
                assert want[acc] == (setv if s else c[acc]), (hex(acc), hex(x), hex(lo), hex(hi))
                if s and any(b2f(q) != b2f(q) for q in (lo, hi, c[acc])):
                    nan_set += 1
                if s != windup_old_prose(x, lo, hi, c[acc], want[cand]):
                    disagree += 1
                if b2f(x) != b2f(x):
                    assert not s                      # NaN X_OUT is a guaranteed KEEP
            n += 1
    assert disagree > 0 and nan_set > 0
    # ---- K380 < 0: the disabled path CAN change sign (MODE != 1, flags clear -> down step K394)
    m = bytearray(ROM)
    m[K380:K380 + 4] = struct.pack('>I', f2b(-1.0))
    m[K394:K394 + 4] = struct.pack('>I', f2b(-2.0))
    m = bytes(m)
    for xin, xout in ((-0.5, 1.5), (0.0, 2.0), (-0.0, 2.0)):
        c = base_case(); c[EN] = 0; c[X_OUT] = f2b(xin)
        w, *_ = run(c, m)
        assert w[X_OUT] == f2b(xout), (xin, b2f(w[X_OUT]))
    # K380 = NaN: both band tests are false for every X_OUT -> +0.0
    m = bytearray(ROM)
    m[K380:K380 + 4] = struct.pack('>I', NAN_B)
    m[K394:K394 + 4] = struct.pack('>I', f2b(-2.0))
    m = bytes(m)
    for xin in (-0.5, 0.5, 100.0, -1e30, 0.0):
        c = base_case(); c[EN] = 0; c[X_OUT] = f2b(xin)
        w, *_ = run(c, m)
        assert w[X_OUT] == PZERO, xin
    print('pass 9: NaN anti-windup explicit cases (real ROM, emulator == model): ' + '; '.join(ex))
    print(f'        random NaN cases: {n}, SET formula exact on every accumulator update; '
          f'{nan_set} SETs with a NaN in LO / HI / acc; {disagree} updates where the old "<= / >=" '
          f'wording predicted the wrong arm')
    print('        K380 = -1.0, K394 = -2.0, EN = 0: X_OUT -0.5 -> +1.5 and +-0 -> +2.0 (sign change; '
          '+-0 outside the dead band); K380 = NaN: X_OUT -0.5 / 0.5 / 100 / -1e30 / 0 -> +0.0')


# ---------------- pass 10: the store to 0xFFFF65C5 at 0x022972 (fragment 0x022962..0x022972)
def pass10():
    for v in range(256):
        m = bytearray(ROM)
        m[0x0C303F] = v
        e = E.Emu(bytes(m))
        e.gbr = 0xFFFF65AA                     # set at 0x022774 by 0x022760 (fn_dump: GBR set once)
        e.call(0x022962, stop_at={0x022974})
        want = 0 if v == 0xAA else 1
        assert e.read_u8(0xFFFF65C5) == want and e.read_u8(0xFFFF65B1) == want, v
        assert set(e.writes) == {0xFFFF65C5, 0xFFFF65B1}, v
    assert ROM[0x0C303F] == 0x55 and ROM_STOCK[0x0C303F] == 0x55
    print('pass 10: 0x022962..0x022972 writes [65C5] = [65B1] = (ROM[0x0C303F] == 0xAA) ? 0 : 1 for all '
          '256 byte values, nothing else; shipped byte 0x55 (20.19c and stock) -> 1')


# ---------------- pass 11: sibling latches 0xFFFF7B3E / 0xFFFF7B3F (0x0381BC .. 0x0381FA)
B3E, B3F = 0xFFFF7B3E, 0xFFFF7B3F


def sib_latch(rom, vals, b3e, b3f):
    e = E.Emu(rom)
    for k, a in S_IN.items():
        n = 2 if k == 'i67ec' else (1 if k in ('i6254', 'i65c0', 'i67fc', 'i726c', 'i7448', 'i3158') else 4)
        poke(e, a, n, vals[k])
    poke(e, B3E, 1, b3e)
    poke(e, B3F, 1, b3f)
    e.call(SIB)
    return e.ram[B3E - E.RAM_LO], e.ram[B3F - E.RAM_LO], set(e.writes)


def pass11():
    r = random.Random(11)
    assert rf(ROM, 0x0CC350) == PZERO and rf(ROM_STOCK, 0x0CC350) == PZERO
    n = 0
    # [7B3E]: shipped K350 = 0.0 -> with [6254] == 1 never written, whatever [6624] vs [895C]
    for d in (0.0, 1.0, -1.0, 1e-6, -1e-6, 500.0, -500.0):
        for pre in (0, 1, 0x5A):
            v = sat_inputs(0); v['i6254'] = 1; v['i895c'] = f2b(1000.0); v['i6624'] = f2b(1000.0 + d)
            g3e, _, w = sib_latch(ROM, v, pre, 0)
            assert g3e == pre and B3E not in w, (d, pre)
            n += 1
    for b in (0, 2, 0x81, 0xFF):                 # [6254] != 1 -> written 0
        v = sat_inputs(0); v['i6254'] = b
        g3e, _, w = sib_latch(ROM, v, 0x5A, 0)
        assert g3e == 0 and B3E in w
        n += 1
    # positive control: K350 = 10.0 -> written 1 only strictly inside ([895C] - 10, [895C] + 10)
    m = bytearray(ROM); m[0x0CC350:0x0CC354] = struct.pack('>I', f2b(10.0)); m = bytes(m)
    for d, want in ((5.0, 1), (-5.0, 1), (0.0, 1), (10.0, None), (-10.0, None), (20.0, None)):
        v = sat_inputs(0); v['i6254'] = 1; v['i895c'] = f2b(1000.0); v['i6624'] = f2b(1000.0 + d)
        g3e, _, w = sib_latch(m, v, 0x5A, 0)
        if want is None:
            assert g3e == 0x5A and B3E not in w, d
        else:
            assert g3e == 1 and B3E in w, d
        n += 1
    # [7B3F]: [726C] != 0 -> 0; [726C] == 0 and [6624] > [895C] -> 1; else not written
    for t, d, want in ((0, 1.0, 1), (0, 0.0, None), (0, -1.0, None), (1, 1.0, 0), (0x80, -1.0, 0)):
        v = sat_inputs(0); v['i726c'] = t; v['i895c'] = f2b(1000.0); v['i6624'] = f2b(1000.0 + d)
        _, g3f, w = sib_latch(ROM, v, 0, 0x5A)
        if want is None:
            assert g3f == 0x5A and B3F not in w, (t, d)
        else:
            assert g3f == want and B3F in w, (t, d)
        n += 1
    # random, shipped ROM: [7B3E] is never WRITTEN as 1
    for _ in range(300):
        vals = {k: (r.randrange(65536) if k == 'i67ec' else
                    r.randrange(256) if k in ('i6254', 'i65c0', 'i67fc', 'i726c', 'i7448', 'i3158') else fv(r, 0.05))
                for k in S_IN}
        if r.random() < 0.5:
            vals['i6254'] = 1
            vals['i895c'] = vals['i6624']
        pre = r.choice([0, 0x5A, 0xFF])
        g3e, _, w = sib_latch(ROM, vals, pre, r.randrange(256))
        assert (g3e == 0 and B3E in w) or (g3e == pre and B3E not in w)
        n += 1
    print(f'pass 11: sibling 0x03817C latches: {n} runs -- [7B3E] / [7B3F] written 0 or 1 only as stated, '
          f'otherwise left unwritten; shipped K350 = 0.0 (20.19c and stock) never writes [7B3E] = 1')


def pass7():
    insns = set()
    pc = ENTRY
    # instruction addresses of 0x0382C2 = what the trace listing contains; collect them from fn_dump-style
    # recursive descent: decode linearly, skipping the three literal pools that sit inside the range
    pools = [(0x03836E, 0x038414), (0x038642, 0x038698)]
    while pc < END:
        if any(lo <= pc < hi for lo, hi in pools):
            pc += 2
            continue
        txt, _ = D.decode(int.from_bytes(ROM[pc:pc + 2], 'big'), pc)
        insns.add(pc)
        pc += 2
    assert len(insns) == 593, len(insns)
    missing = sorted(insns - COVER)
    assert not missing, 'not executed: ' + ' '.join(f'{p:06X}' for p in missing)
    print(f'pass 7: all {len(insns)} instructions of 0x0382C2 executed at least once')


def main():
    pass0()
    pass1()
    pass2()
    pass3()
    pass4()
    pass5()
    pass6()
    pass8()
    pass9()
    pass10()
    pass11()
    pass7()
    print('ALL PASSES OK')
    return 0


if __name__ == '__main__':
    sys.exit(main())
