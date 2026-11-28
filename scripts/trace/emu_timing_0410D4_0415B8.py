#!/usr/bin/env python3
"""Emulation check for ROM functions 0x0410D4..0x041572 (505 instructions, GBR 0xFFFF7FBC) and
0x0415B8..0x041800 (292 instructions, GBR 0xFFFF8000), plus the context facts their trace relies on.

    python3 scripts/trace/emu_timing_0410D4_0415B8.py

Reference bin: rom/AE5L600L 20g rev 20.19c.bin  md5 92cae8275cd4f9b473a3a9e36efe6449
Trace:         disassembly/analysis/timing_0410D4_0415B8_trace.txt

What it does
------------
Runs each function in scripts/sh2e_emu.py (real callees, from ROM) against a Python model written from
the bytes and asserts, per case:
  * every output RAM cell, bit for bit
  * the exact SET of non-stack RAM bytes written (nothing else is touched)
  * the exact SET of RAM cells read before being written in the same call (inputs are poked WITHOUT
    marking them initialised, so every input read lands in emu.uninit_reads)
  * callee-saved state: r8-r14 (r10-r14 for 0x0415B8), r15, GBR, fr12-fr15 restored

Two ROM images are used, both IN MEMORY (the file on disk is never written):
  REAL  the reference bin as it is
  UNIQ  a copy in which every table these two functions read holds data unique to that table and to its
        cell, and every calibration scalar they read holds a value unique to its address; the byte gates
        0x0D297B / 0x0D297D / 0x0D297F and the uint16 thresholds 0x0D29B6 / B8 / BA are flipped so the
        branches the real calibration never takes are executed too. Because the model reads every
        table and constant from the image it is given, a model that names the wrong descriptor or the
        wrong calibration address fails on UNIQ even where REAL happens to hold equal values.

Context checks (each against its own model):
  * 0x023E48 / 0x02F8EA / 0x022F92 return (byte == 1); 0x0299F0 returns 2 if byte != 0 else 0
  * 0x041030 (writes the upper clamp 0xFFFF7FC0 that 0x0410D4 uses)
  * 0x0418AC (writes 0xFFFF8008, a multiplier 0x0415B8 uses) and 0x0418FC (zeroes 0xFFFF8000 / 8004)
  * the sum 0x03F610..0x03F674 inside 0x03F368: the sign of each of its sixteen terms, and that
    its stack term @(8,r15) is the float at 0xFFFF7FBC (0x03F3BE..0x03F3C4)
  * every table lookup against desc_types.read_table() + plain (bi)linear interpolation, clamped

Review checks (third-reader repair, 2026-11-27; each row asserts EXPLICIT expected bits, not only the model):
  * check_edges_a      A3 / A6: NaN / -0 / negative / infinite H through the clamp; NaN / inf / edge X
                       through the latch window
  * check_rz_041030    A5: H with byte [67FC] == 1 for finite, overflowing and infinite factor products,
                       and whether round-to-nearest would overflow the same product (exact arithmetic)
  * check_flat_a       A21: the NINE records 0x0410D4 reads are single-valued in 20.19c and stock and the
                       ROM lookup returns one value for NaN / +-inf / +-1000 / in-range inputs
  * check_states24     B12: states 2 / 4 with negative, -0, NaN and infinite R
  * check_0x040A9C     the writer of byte 0xFFFF7FDC: 0x0D29C4 = 438 in 20.19c, 0 in stock, so the flag
                       can be 1 only in 20.19c
  * check_03F368_paths S1 / S2 / S3: whole-function runs of 0x03F368, one per path, perturbing [7FBC] and
                       [8000] and listing which RAM outputs change

ROUNDING (corrections item 106): every fadd / fsub / fmul in the models is the exact result rounded
TOWARD ZERO (rz_arith below, written independently of the emulator's arithmetic; only sh2e_emu.rz_bits
is shared). Inputs given as Python floats are converted to float32 with f2b (nearest): that is a choice
of input, not arithmetic. Nothing asserted here depends on the rounding mode except bit equality of the
model with the emulator, which both compute under the same (round-to-zero) assumption.

Names in this file are neutral on purpose: nothing here establishes what any RAM cell physically is.
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
STOCK_BIN = os.path.join(REPO, 'rom', 'ae5l600l.bin')
REAL = open(BIN, 'rb').read()
STOCK = open(STOCK_BIN, 'rb').read()
assert hashlib.md5(REAL).hexdigest() == '92cae8275cd4f9b473a3a9e36efe6449', 'wrong reference bin'

f2b, b2f = E.f2b, E.b2f
U32 = lambda img, a: struct.unpack_from('>I', img, a)[0]          # noqa: E731
U16 = lambda img, a: struct.unpack_from('>H', img, a)[0]          # noqa: E731

# ------------------------------------------------------------------ addresses (resolved from the pools)
FN_A, FN_B = 0x0410D4, 0x0415B8
FN_LUT1, FN_LUT1_U16, FN_LUT2 = 0x0BE830, 0x0BE8AC, 0x0BE8E4

# 0x0410D4 RAM (GBR = 0xFFFF7FBC; r1 = 0xFFFF7FF4 literal)
A_E, A_V, A_N, A_T, A_P = 0xFFFF6354, 0xFFFF65FC, 0xFFFF6624, 0xFFFF895C, 0xFFFF6634
A_C, A_M = 0xFFFF67EC, 0xFFFF8970
A_67FC, A_F10, A_F12, A_F9, A_726C = 0xFFFF67FC, 0xFFFF65C0, 0xFFFF85D7, 0xFFFF69E6, 0xFFFF726C
A_X, A_H = 0xFFFF7FBC, 0xFFFF7FC0               # r1-56, r1-52
A_7FF4, A_7FF5, A_7FF1, A_7FDC = 0xFFFF7FF4, 0xFFFF7FF5, 0xFFFF7FF1, 0xFFFF7FDC
A_7FE0, A_7FDA, A_7FD8 = 0xFFFF7FE0, 0xFFFF7FDA, 0xFFFF7FD8
A_Y = 0xFFFF7EE4
A_G = (0xFFFF7E9C, 0xFFFF7E98, 0xFFFF7E94, 0xFFFF7E90)   # order of the compares at 0x041204..0x04122E

# 0x0410D4 calibration
K_A = dict(k24=0x0D2B58, k28=0x0D2B60, k32=0x0D2B7C, d36=0x0AE054, d40=0x0AE07C, d13=0x0AE0B0)
K_B = dict(k24=0x0D2B5C, k28=0x0D2B64, k32=0x0D2B80, d36=0x0AE068, d40=0x0AE090, d13=0x0AE0C4)
C_F14_1, C_F15_1, C_F14_0, C_F15_0 = 0x0D2BBC, 0x0D2BC0, 0x0D2BA0, 0x0D2BA4
C_VTHR1, C_VTHR2 = 0x0D2BA8, 0x0D2B4C
C_DEC = {  # path -> (r11 == 1 constant, r11 != 1 constant)
    'v':  (0x0D2BC4, 0x0D2BB8),     # 0x041264
    'f12': (0x0D2BC8, 0x0D2BB0),    # 0x04152A
    'p10': (0x0D2BCC, 0x0D2BAC),    # 0x0412C4
    'p0':  (0x0D2BD0, 0x0D2BAC),    # 0x0412F6
    'q':  (0x0D2BD4, 0x0D2BB4),     # 0x0413CE
}
C_G7D, C_G7B = 0x0D297D, 0x0D297B
C_W_BA, C_W_B8, C_W_B6 = 0x0D29BA, 0x0D29B8, 0x0D29B6
C_B50, C_B54 = 0x0D2B50, 0x0D2B54
D_A4, D_40, D_34 = 0x0AE0A4, 0x0AE040, 0x0AE034
WIN = 0x3AB40000                   # pool 0x041394, 0.001373291015625

# 0x0415B8 RAM (GBR = 0xFFFF8000; r10 = 0xFFFF801C literal)
B_Q, B_E, B_V, B_W, B_TP, B_L, B_N = (0xFFFF78B0, 0xFFFF6354, 0xFFFF65FC, 0xFFFF6350, 0xFFFF62DC,
                                      0xFFFF63F8, 0xFFFF6624)
B_C2, B_67FC, B_F12, B_5BE3, B_65C1, B_9720 = 0xFFFF67EE, 0xFFFF67FC, 0xFFFF85D7, 0xFFFF5BE3, 0xFFFF65C1, 0xFFFF9720
B_OUT, B_R, B_K, B_8014, B_8018, B_801C, B_801E, B_801F = (0xFFFF8000, 0xFFFF8004, 0xFFFF8008, 0xFFFF8014,
                                                           0xFFFF8018, 0xFFFF801C, 0xFFFF801E, 0xFFFF801F)
B_S1, B_S2 = 0xFFFF8258, 0xFFFF81EC
# 0x0415B8 calibration
C_G7F, C_G7E = 0x0D297F, 0x0D297E
C_BF0, C_BF4, C_BF8, C_BFC, C_C00 = 0x0D2BF0, 0x0D2BF4, 0x0D2BF8, 0x0D2BFC, 0x0D2C00
D_0D8, D_0EC, D_488, D_DE0 = 0x0AE0D8, 0x0AE0EC, 0x0AE488, 0x0ADDE0
D_46C, D_450, D_4A4, D_4F8, D_4C0, D_4DC, D_DF4 = 0x0AE46C, 0x0AE450, 0x0AE4A4, 0x0AE4F8, 0x0AE4C0, 0x0AE4DC, 0x0ADDF4
K1024 = 0x3F83126E                 # pool 0x041854

TABLES_A = [K_A['d36'], K_A['d40'], K_A['d13'], K_B['d36'], K_B['d40'], K_B['d13'], D_A4, D_40, D_34]
TABLES_B = [D_0D8, D_0EC, D_488, D_DE0, D_46C, D_450, D_4A4, D_4F8, D_4C0, D_4DC, D_DF4]
CAL_F32 = ([K_A[k] for k in ('k24', 'k28', 'k32')] + [K_B[k] for k in ('k24', 'k28', 'k32')] +
           [C_F14_1, C_F15_1, C_F14_0, C_F15_0, C_VTHR1, C_VTHR2, C_B50, C_B54] +
           sorted({a for v in C_DEC.values() for a in v}) + [C_BF0, C_BF4, C_BF8, C_BFC, C_C00])
CAL_U8 = [C_G7D, C_G7B, C_G7F, C_G7E]
CAL_U16 = [C_W_BA, C_W_B8, C_W_B6]


def rz_arith(op, xb, yb):
    """fadd / fsub / fmul on float32 BITS: exact result rounded toward zero (overflow -> +/-FLT_MAX).
    Specials (inf / nan operands) and exact-zero results take the IEEE double result."""
    x, y = b2f(xb), b2f(yb)
    f = {'+': lambda a, b: a + b, '-': lambda a, b: a - b, '*': lambda a, b: a * b}[op]
    ieee = f(x, y)
    if not (math.isfinite(x) and math.isfinite(y)):
        return f2b(ieee)
    q = f(Fraction(x), Fraction(y))
    if q == 0:
        return f2b(ieee)
    return E.rz_bits(q)


def gt(ab, bb):
    """fcmp/gt: T = (a > b); false whenever either is NaN."""
    return b2f(ab) > b2f(bb)


# ------------------------------------------------------------------ table data, geometry
def desc_cells(img, d):
    """(data pointer, cell width, number of cells) of a record as the consuming wrapper reads it."""
    if DT.is_2d(img, d):
        return U32(img, d + 12), DT.TYPE_SIZES[img[d + 16]], U16(img, d) * U16(img, d + 2)
    w = 2 if d in (D_A4, D_34, D_0EC) else DT.TYPE_SIZES[img[d + 2]]   # fixed uint16 wrapper 0x0BE8AC
    return U32(img, d + 8), w, U16(img, d)


def make_uniq(g7d, g7b, g7f, g7e, salt):
    img = bytearray(REAL)
    for k, d in enumerate(TABLES_A + TABLES_B):
        dp, w, n = desc_cells(img, d)
        for i in range(n):
            if w == 1:
                img[dp + i] = (17 + salt + 23 * k + 5 * i) % 251 + 1
            else:
                # uint16: the thresholds (0x0AE0A4 / 0x0AE034 / 0x0AE0EC) stay in a range C can straddle
                v = (300 + 40 * k + 13 * i) if d in (D_A4, D_34, D_0EC) else (1000 + salt + 977 * k + 61 * i)
                struct.pack_into('>H', img, dp + 2 * i, v)
    vals = {}
    for j, a in enumerate(CAL_F32):
        vals[a] = None
    # thresholds and offsets keep their sign / scale so the branch structure stays exercisable
    base = {K_A['k24']: 3.0, K_A['k28']: -97.0, K_A['k32']: 6995.0, K_B['k24']: 7.0, K_B['k28']: -91.0,
            K_B['k32']: 6011.0, C_F14_1: -207.0, C_F15_1: -143.0, C_F14_0: -311.0, C_F15_0: -119.0,
            C_VTHR1: 509.0, C_VTHR2: 503.0, C_B50: 113.0, C_B54: 4.25,
            0x0D2BC4: 1.0625, 0x0D2BB8: 0.9375, 0x0D2BC8: 0.71875, 0x0D2BB0: 0.6875, 0x0D2BCC: 0.015625,
            0x0D2BAC: 0.01171875, 0x0D2BD0: 0.0234375, 0x0D2BD4: 0.02734375, 0x0D2BB4: 0.03125,
            C_BF0: 4.5, C_BF4: 0.75, C_BF8: 0.0390625, C_BFC: 0.8125, C_C00: 0.046875}
    for a, v in base.items():
        struct.pack_into('>f', img, a, v)
    img[C_G7D] = g7d
    img[C_G7B] = g7b
    img[C_G7F] = g7f
    img[C_G7E] = g7e
    struct.pack_into('>H', img, C_W_BA, 350)
    struct.pack_into('>H', img, C_W_B8, 330)
    struct.pack_into('>H', img, C_W_B6, 420)
    return bytes(img)


UNIQ = make_uniq(0xFF, 0x00, 0x00, 3, 0)      # gates flipped against REAL
UNIQ2 = make_uniq(0x00, 0xFF, 90, 2, 7)       # gates as REAL, divider 2, unique values


# ------------------------------------------------------------------ lookup oracles (ROM routines, per image)
class Luts:
    def __init__(self, img):
        self.img = img
        self.e = E.Emu(img)
        self.cache = {}

    def l1(self, d, xb):
        k = (1, d, xb)
        if k not in self.cache:
            self.e.steps = 0
            self.e.FR[4] = xb
            self.e.call(FN_LUT1, regs={4: d})
            self.cache[k] = self.e.FR[0]
        return self.cache[k]

    def l16(self, d, xb):
        k = (16, d, xb)
        if k not in self.cache:
            self.e.steps = 0
            self.e.FR[4] = xb
            self.e.call(FN_LUT1_U16, regs={4: d})
            self.cache[k] = self.e.R[0] & 0xFFFF
        return self.cache[k]

    def l2(self, d, ab, bb):
        k = (2, d, ab, bb)
        if k not in self.cache:
            self.e.steps = 0
            self.e.FR[4] = ab
            self.e.FR[5] = bb
            self.e.call(FN_LUT2, regs={4: d})
            self.cache[k] = self.e.FR[0]
        return self.cache[k]


LUTS = {id(REAL): Luts(REAL), id(UNIQ): Luts(UNIQ), id(UNIQ2): Luts(UNIQ2)}


def cf(img, a):
    return U32(img, a)


# ================================================================== model of 0x0410D4
def model_a(img, c):
    L = LUTS[id(img)]
    reads = {A_E, A_V, A_N, A_T, A_P, A_C, A_M, A_67FC, A_F10, A_F12, A_F9, A_726C, A_Y, A_G[0]}
    writes = set()
    out = {A_X: c['X'], A_7FF4: c['l7ff4'], A_7FF5: c['o7ff5'], A_7FF1: c['l7ff1'],
           A_7FE0: c['o7fe0'], A_7FDA: c['o7fda'], A_7FD8: c['o7fd8']}
    calls = []
    F1 = 1 if c['a67fc'] == 1 else 0            # r11 = 0x023E48 result
    F20 = 1 if c['a726c'] == 1 else 0           # 0x02F8EA result
    F9, F10, F12 = c['F9'], c['F10'], c['F12']
    k = K_B if c['M'] in (4, 7, 8) else K_A     # 0x04113E..0x04114A
    k24, k28, k32 = cf(img, k['k24']), cf(img, k['k28']), cf(img, k['k32'])
    L36, L40, L13 = L.l1(k['d36'], c['E']), L.l1(k['d40'], c['E']), L.l1(k['d13'], c['E'])
    calls += [('l1', k['d36'], c['E']), ('l1', k['d40'], c['E']), ('l1', k['d13'], c['E'])]
    fr14, fr15 = (cf(img, C_F14_1), cf(img, C_F15_1)) if F1 else (cf(img, C_F14_0), cf(img, C_F15_0))
    X = c['X']
    latch_written = False
    if F9 == 0:                                   # 0x0411D8..0x0411F6
        reads.add(A_X)
        w = b2f(WIN)
        if not ((-w > b2f(X)) or (b2f(X) > w)):
            out[A_7FF4] = 1
            writes.add(A_7FF4)
            latch_written = True
    out[A_7FE0] = c['Y']                          # 0x0411F8..0x041200
    writes |= {A_7FE0 + i for i in range(4)}
    allgt = True
    for j, a in enumerate(A_G):                    # 0x041202..0x041238
        reads.add(a)
        if not gt(c['g'][j], c['Y']):
            allgt = False
            break
    out[A_7FF5] = 0 if allgt else 1
    writes.add(A_7FF5)
    f1_written = False
    if F20 == 0 and F12 == 0:                      # 0x04123A..0x041248
        out[A_7FF1] = 1
        writes.add(A_7FF1)
        f1_written = True
    if not latch_written:
        reads.add(A_7FF4)
    if out[A_7FF4] == 1:                           # 0x04124A..0x041258
        out[A_X] = 0x00000000
        writes |= {A_X + i for i in range(4)}
        return out, reads, writes, calls, 'forced0'

    def upd(newx, tag):
        reads.add(A_X)
        reads.add(A_H)
        xf, hf = b2f(newx), b2f(c['H'])
        if not (xf > 0.0):                          # 0x0BE56C: low test first, low = fldi0 = +0.0
            r = 0x00000000
        elif hf > xf:
            r = newx
        else:
            r = c['H']
        out[A_X] = r
        writes.update(A_X + i for i in range(4))
        return out, reads, writes, calls, tag

    def dec(path):
        reads.add(A_X)
        return upd(rz_arith('-', X, cf(img, C_DEC[path][0 if F1 else 1])), 'dec_' + path)

    def inc(vb, tag):
        reads.add(A_X)
        return upd(rz_arith('+', X, vb), tag)

    if not gt(cf(img, C_VTHR1), c['V']):          # 0x04125A..0x04127E
        return dec('v')
    if F12 == 0:                                   # 0x041280..0x041288
        return dec('f12')
    if img[C_G7D] == 0xFF:                         # 0x04128A..0x0412A0
        if not f1_written:
            reads.add(A_7FF1)
        if out[A_7FF1] == 1:
            return dec('f12')
    if F10 == 1:                                   # 0x0412A2..0x0412C2
        if gt(rz_arith('+', c['T'], fr14), c['N']):
            return dec('p10')
        reads.add(A_7FDC)
        if c['f7fdc'] == 1:
            return dec('p10')
    elif F10 == 0:                                 # 0x0412D8..0x0412F4
        if img[C_G7B] != 0xFF or gt(rz_arith('+', c['T'], fr15), c['N']):
            return dec('p0')
    if F12 == 1 and F9 == 0:                        # 0x0413C4..0x0413E8
        return dec('q')
    C = c['C']
    if F1:                                          # 0x0413EA..0x041442
        v = L.l16(D_A4, c['E'])
        calls.append(('l16', D_A4, c['E']))
        out[A_7FDA] = v
        writes |= {A_7FDA, A_7FDA + 1}
        if C < U16(img, C_W_BA) or C >= v:
            return out, reads, writes, calls, 'hold_r11'
        if gt(rz_arith('+', c['T'], k32), c['N']):
            return out, reads, writes, calls, 'hold_r11'
        if F9 != 1:
            return out, reads, writes, calls, 'hold_r11'
        return inc(L13, 'inc_L13')
    # 0x041444..
    if F10 != 1 and img[C_G7B] != 0xFF:
        return out, reads, writes, calls, 'hold'
    if F12 != 1 or out[A_7FF5] != 0 or not gt(cf(img, C_VTHR2), c['V']):
        return out, reads, writes, calls, 'hold'
    reads.add(A_7FDC)
    if c['f7fdc'] != 0:
        return out, reads, writes, calls, 'hold'
    if (U16(img, C_W_B8) <= C < U16(img, C_W_B6) and not gt(rz_arith('+', c['T'], cf(img, C_B50)), c['N'])
            and not gt(cf(img, C_B54), c['P'])):
        calls.append(('l1', D_40, c['E']))
        return inc(L.l1(D_40, c['E']), 'inc_AE040')
    v = L.l16(D_34, c['E'])
    calls.append(('l16', D_34, c['E']))
    out[A_7FD8] = v
    writes |= {A_7FD8, A_7FD8 + 1}
    if C < U16(img, C_W_B8) or C >= v or F9 != 1:
        return out, reads, writes, calls, 'hold'
    if not gt(rz_arith('+', c['T'], k24), c['N']):
        return inc(L36, 'inc_L36')
    if not gt(rz_arith('+', c['T'], k28), c['N']):
        return inc(L40, 'inc_L40')
    return out, reads, writes, calls, 'hold'


# ------------------------------------------------------------------ running one case
SENT = {8: 0x08080808, 9: 0x09090909, 10: 0x0A0A0A0A, 11: 0x0B0B0B0B, 12: 0x0C0C0C0C,
        13: 0x0D0D0D0D, 14: 0x0E0E0E0E}
FSENT = {12: 0x41C80000, 13: 0xC1C80000, 14: 0x42F60000, 15: 0xC2F60000}
GBR_SENT = 0xFFFF1234
_rng = random.Random(0x410D4)
EMUS = {id(REAL): E.Emu(REAL), id(UNIQ): E.Emu(UNIQ), id(UNIQ2): E.Emu(UNIQ2)}


def poke(e, a, n, v):
    """Write RAM WITHOUT marking it initialised, so a later read is recorded."""
    o = a - E.RAM_LO
    e.ram[o:o + n] = (v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big')


def peek(e, a, n):
    o = a - E.RAM_LO
    return int.from_bytes(e.ram[o:o + n], 'big')


def fresh(e):
    e.init = bytearray(len(e.init))
    e.uninit_reads.clear()
    e.writes.clear()
    e.stubs.clear()
    e.stack_low = E.STACK_TOP
    e.steps = 0


def call_checked(e, entry, saved, tag):
    regs = {i: _rng.getrandbits(32) for i in range(8)}
    regs.update({i: SENT[i] for i in saved})
    for i in range(12):
        e.FR[i] = _rng.getrandbits(32)
    for i, v in FSENT.items():
        e.FR[i] = v
    e.gbr = GBR_SENT
    assert e.call(entry, regs=regs) == 'return', tag
    for i in saved:
        assert e.R[i] == SENT[i], f'r{i} not preserved {tag}'
    assert e.R[15] == E.STACK_TOP, 'r15 not restored ' + tag
    assert e.gbr == GBR_SENT, 'GBR not restored ' + tag
    for i, v in FSENT.items():
        assert e.FR[i] == v, f'fr{i} not preserved {tag}'


def run_a(img, c):
    e = EMUS[id(img)]
    fresh(e)
    for a, k in ((A_E, 'E'), (A_V, 'V'), (A_N, 'N'), (A_T, 'T'), (A_P, 'P'), (A_X, 'X'), (A_H, 'H'),
                 (A_Y, 'Y'), (A_7FE0, 'o7fe0')):
        poke(e, a, 4, c[k])
    for j, a in enumerate(A_G):
        poke(e, a, 4, c['g'][j])
    poke(e, A_C, 2, c['C'])
    poke(e, A_7FDA, 2, c['o7fda'])
    poke(e, A_7FD8, 2, c['o7fd8'])
    for a, k in ((A_M, 'M'), (A_67FC, 'a67fc'), (A_F10, 'F10'), (A_F12, 'F12'), (A_F9, 'F9'),
                 (A_726C, 'a726c'), (A_7FF4, 'l7ff4'), (A_7FF5, 'o7ff5'), (A_7FF1, 'l7ff1'),
                 (A_7FDC, 'f7fdc')):
        poke(e, a, 1, c[k])
    tag = 'A ' + ' '.join(f'{k}={v}' for k, v in c.items())
    call_checked(e, FN_A, (8, 9, 10, 11, 12, 13, 14), tag)
    got = {A_X: peek(e, A_X, 4), A_7FF4: peek(e, A_7FF4, 1), A_7FF5: peek(e, A_7FF5, 1),
           A_7FF1: peek(e, A_7FF1, 1), A_7FE0: peek(e, A_7FE0, 4), A_7FDA: peek(e, A_7FDA, 2),
           A_7FD8: peek(e, A_7FD8, 2)}
    want, reads, writes, _, path = model_a(img, c)
    assert got == want, f'OUTPUT MISMATCH {tag}\n got  {got}\n want {want}'
    assert set(e.writes) == writes, (f'WRITE-SET MISMATCH {tag}\n got  {sorted(map(hex, e.writes))}'
                                     f'\n want {sorted(map(hex, writes))}')
    assert e.uninit_reads == reads, (f'READ-SET MISMATCH {tag}\n got  {sorted(map(hex, e.uninit_reads))}'
                                     f'\n want {sorted(map(hex, reads))}')
    return got, path


def case_a(**kw):
    c = dict(E=f2b(20.0), V=f2b(0.0), N=f2b(800.0), T=f2b(800.0), P=f2b(10.0), C=0, M=0, a67fc=0, F10=0,
             F12=1, F9=1, a726c=1, X=f2b(2.0), H=f2b(5.0), l7ff4=0, o7ff5=0x55, l7ff1=0, f7fdc=0,
             Y=f2b(100.0), g=[f2b(200.0)] * 4, o7fe0=0x11223344, o7fda=0xABCD, o7fd8=0x1234)
    c.update(kw)
    return c


def grid_a(img, n_rand, label):
    w = b2f(WIN)
    wn = struct.unpack('>f', struct.pack('>I', WIN + 1))[0]
    Xs = [0.0, -0.0, w, -w, wn, -wn, 0.5, 2.0, 4.9, 6.0, -2.0, 1e30]
    Hs = [5.0, 0.0, 100.0, -1.0, 2.0]
    T = 800.0
    ks = [b2f(cf(img, a)) for a in (K_A['k24'], K_A['k28'], K_A['k32'], K_B['k24'], K_B['k28'], K_B['k32'],
                                    C_F14_1, C_F15_1, C_F14_0, C_F15_0, C_B50)]
    Ns = sorted({T + k + d for k in ks for d in (-0.5, 0.0, 0.5)} | {0.0, 10000.0})
    v1, v2 = b2f(cf(img, C_VTHR1)), b2f(cf(img, C_VTHR2))
    Vs = [0.0, v1 - 1.0, v1, v1 + 1.0, v2 - 1.0, v2, v2 + 1.0, float('nan')]
    p = b2f(cf(img, C_B54))
    Ps = [0.0, p - 0.25, p, p + 0.25]
    Es = [-50.0, -40.0, -15.0, 0.0, 25.0, 70.0, 75.0, 110.0, 130.0]
    L = LUTS[id(img)]
    Cs = sorted({0, 1, 65535, U16(img, C_W_BA), U16(img, C_W_B8), U16(img, C_W_B6), U16(img, C_W_B6) - 1,
                 U16(img, C_W_B8) - 1 if U16(img, C_W_B8) else 0} |
                {v + d for e_ in Es for d in (-1, 0) for v in (L.l16(D_A4, f2b(e_)), L.l16(D_34, f2b(e_)))
                 if 0 <= v + d <= 65535})
    Ys = [100.0, 200.0, 50.0]
    Gs = [150.0, 100.0, 99.0, 250.0]
    paths = {}
    n = 0

    examples = {}

    def one(c):
        nonlocal n
        got, path = run_a(img, c)
        paths[path] = paths.get(path, 0) + 1
        examples.setdefault(path, (c, got))
        n += 1

    # structured: every flag combination, two float draws each
    for a67fc, F9, F10, F12, a726c, l7ff4, l7ff1, f7fdc in itertools.product(
            (0, 1, 2), (0, 1, 2), (0, 1, 2), (0, 1, 2, 0x80), (0, 1), (0, 1, 2), (0, 1), (0, 1, 2)):
        if _rng.random() < 0.55:
            continue
        for _ in range(2):
            one(case_a(E=f2b(_rng.choice(Es)), V=f2b(_rng.choice(Vs)), N=f2b(_rng.choice(Ns)), T=f2b(T),
                       P=f2b(_rng.choice(Ps)), C=_rng.choice(Cs), M=_rng.choice((0, 4, 7, 8, 3, 0xFF)),
                       a67fc=a67fc, F10=F10, F12=F12, F9=F9, a726c=a726c, X=f2b(_rng.choice(Xs)),
                       H=f2b(_rng.choice(Hs)), l7ff4=l7ff4, l7ff1=l7ff1, f7fdc=f7fdc,
                       Y=f2b(_rng.choice(Ys)), g=[f2b(_rng.choice(Gs)) for _ in range(4)]))
    # random, biased toward the increment paths (latch clear, F12 == 1, F9 == 1, V low)
    for _ in range(n_rand):
        one(case_a(E=f2b(_rng.choice(Es)), V=f2b(_rng.choice(Vs[:1] * 3 + Vs)), N=f2b(_rng.choice(Ns)),
                   T=f2b(T), P=f2b(_rng.choice(Ps)), C=_rng.choice(Cs), M=_rng.choice((0, 4, 7, 8, 1)),
                   a67fc=_rng.choice((0, 0, 1)), F10=_rng.choice((0, 1, 1, 2)), F12=_rng.choice((1, 1, 1, 2, 0)),
                   F9=_rng.choice((1, 1, 0, 2)), a726c=_rng.choice((0, 1)), X=f2b(_rng.choice(Xs)),
                   H=f2b(_rng.choice(Hs)), l7ff4=_rng.choice((0, 0, 0, 1)), l7ff1=_rng.choice((0, 1)),
                   f7fdc=_rng.choice((0, 0, 1)), Y=f2b(_rng.choice(Ys)),
                   g=[f2b(_rng.choice(Gs[:1] * 4 + Gs)) for _ in range(4)]))
    # targeted: latch clear, F9 / F12 / F10 = 1, V low -- the increment branches (0x0413EA..0x041528)
    lo8, hi6 = U16(img, C_W_B8), U16(img, C_W_B6)
    Ci = Cs + [lo8, hi6 - 1, (lo8 + hi6) // 2, hi6, hi6 + 1]
    for _ in range(n_rand // 3):
        one(case_a(E=f2b(_rng.choice(Es)), V=f2b(_rng.choice((0.0, v2 - 1.0, v2))), N=f2b(_rng.choice(Ns)),
                   T=f2b(T), P=f2b(_rng.choice(Ps)), C=_rng.choice(Ci), M=_rng.choice((0, 4, 7, 8, 2)),
                   a67fc=_rng.choice((0, 0, 0, 1)), F10=1, F12=1, F9=_rng.choice((1, 1, 1, 2)), a726c=1,
                   X=f2b(_rng.choice((0.5, 2.0, 4.9, 6.0, 0.0))), H=f2b(_rng.choice(Hs)), l7ff4=0, l7ff1=0,
                   f7fdc=_rng.choice((0, 0, 0, 1)), Y=f2b(100.0), g=[f2b(150.0)] * 4))
    print(f'0x0410D4 [{label}]: {n} cases bit-exact (outputs, write-set, read-set, callee-saved)')
    for k_ in sorted(paths):
        c, got = examples[k_]
        print(f'    path {k_:10s} {paths[k_]:5d}   e.g. X={b2f(c["X"]):.6g} H={b2f(c["H"]):g} V={b2f(c["V"]):g} '
              f'N-T={b2f(c["N"]) - b2f(c["T"]):g} P={b2f(c["P"]):g} C={c["C"]} M={c["M"]} 67FC={c["a67fc"]} '
              f'F10={c["F10"]} F12={c["F12"]} F9={c["F9"]} 726C={c["a726c"]} 7FF4={c["l7ff4"]} 7FF1={c["l7ff1"]} '
              f'7FDC={c["f7fdc"]} -> X\'={b2f(got[A_X]):.6g} 7FF4={got[A_7FF4]} 7FF5={got[A_7FF5]} 7FF1={got[A_7FF1]}')
    return paths


def stub_pass_a():
    """Stub the lookups: prove which descriptor ADDRESS each call receives and that the axis input is
    the float at 0xFFFF6354, for the six (M, branch) combinations."""
    n = 0
    for M in (0, 4, 7, 8, 9):
        for a67fc, F10, F12, F9, f7fdc, C, N in ((1, 2, 1, 1, 0, 5, 9000.0), (0, 1, 1, 1, 0, 5, 9000.0),
                                                 (0, 1, 1, 1, 0, 50000, 9000.0)):
            c = case_a(M=M, a67fc=a67fc, F10=F10, F12=F12, F9=F9, f7fdc=f7fdc, C=C, N=f2b(N),
                       E=f2b(33.25), X=f2b(1.0), H=f2b(9.0), V=f2b(0.0), a726c=1)
            e = EMUS[id(REAL)]
            fresh(e)
            seen = []
            e.stub(FN_LUT1, fn=lambda m: (seen.append(('l1', m.R[4], m.FR[4])), m.FR.__setitem__(0, 0)))
            e.stub(FN_LUT1_U16, fn=lambda m: (seen.append(('l16', m.R[4], m.FR[4])),
                                              m.R.__setitem__(0, 60000)))
            for a, k in ((A_E, 'E'), (A_V, 'V'), (A_N, 'N'), (A_T, 'T'), (A_P, 'P'), (A_X, 'X'), (A_H, 'H'),
                         (A_Y, 'Y')):
                poke(e, a, 4, c[k])
            for j, a in enumerate(A_G):
                poke(e, a, 4, c['g'][j])
            poke(e, A_C, 2, c['C'])
            for a, k in ((A_M, 'M'), (A_67FC, 'a67fc'), (A_F10, 'F10'), (A_F12, 'F12'), (A_F9, 'F9'),
                         (A_726C, 'a726c'), (A_7FF4, 'l7ff4'), (A_7FF1, 'l7ff1'), (A_7FDC, 'f7fdc')):
                poke(e, a, 1, c[k])
            call_checked(e, FN_A, (8, 9, 10, 11, 12, 13, 14), 'stubA')
            k = K_B if M in (4, 7, 8) else K_A
            want = [('l1', k['d36'], c['E']), ('l1', k['d40'], c['E']), ('l1', k['d13'], c['E'])]
            want.append(('l16', D_A4, c['E']) if a67fc == 1 else
                        (('l1', D_40, c['E']) if C < 375 else ('l16', D_34, c['E'])))
            assert seen == want, (M, a67fc, C, seen, want)
            n += 1
    print(f'0x0410D4 stub pass: {n} cases; descriptor per call = '
          f'M in (4,7,8) -> 0AE068/0AE090/0AE0C4, else 0AE054/0AE07C/0AE0B0; then 0AE0A4 (r11=1) or '
          f'0AE040 / 0AE034 (r11!=1); every axis input = float [0xFFFF6354]')


# ================================================================== model of 0x0415B8
def model_b(img, c):
    L = LUTS[id(img)]
    reads = {B_Q, B_E, B_V, B_W, B_TP, B_L, B_N, B_C2, B_67FC, B_F12, B_5BE3, B_65C1, B_9720, B_801F, B_R,
             B_S1, B_S2}
    writes = {B_8014 + i for i in range(4)} | {B_801C, B_801C + 1} | {B_R + i for i in range(4)} | \
             {B_OUT + i for i in range(4)} | {B_801E, B_801F}
    out = {B_8018: c['o8018']}
    out[B_8014] = L.l1(D_0D8, c['E'])
    out[B_801C] = L.l16(D_0EC, c['E'])
    fr12 = c['R']
    cnt = c['cnt']
    if c['f65c1'] != 0 and img[C_G7F] == 90:        # 0x041644..0x04165A
        fr12, st, cnt, path = 0x00000000, 0, 0, 'reset'
    else:
        reads.add(B_801E)
        C2 = c['C2']
        fr14 = 0 if C2 == 0 else E.rz_bits(Fraction(b2f(K1024)) * C2)    # 0x0BE598, fused, + 0.0
        s28 = L.l2(D_488, c['TP'], fr14)
        s32 = L.l1(D_DE0, c['N'])
        flag = 1 if c['a67fc'] == 1 else 0
        cond = (gt(out[B_8014], c['Q']) and not (C2 >= out[B_801C]) and not gt(cf(img, C_BF0), c['V'])
                and c['F12'] == 0)
        if cond:
            st = 4 if flag else (2 if c['f5be3'] != 0 else 1)
        else:
            st = 5 if flag else 3
        cnt = min(cnt + 1, 255)                      # 0x0BE53C
        if st == c['prev'] and cnt < img[C_G7E]:
            path = f'st{st}_wait'
        else:
            cnt = 0
            path = f'st{st}'
            sel = c['a9720'] != 0                    # 0x0299F0 returns 2 / 0
            if st in (1, 2):
                d = D_4A4 if st == 2 else (D_46C if sel else D_450)
                v18 = L.l2(d, c['W'], c['L'])
                out[B_8018] = v18
                writes |= {B_8018 + i for i in range(4)}
                reads.add(B_K)
                fr12 = rz_arith('+', fr12, cf(img, C_BF4))
                p = rz_arith('*', v18, s28)
                p = rz_arith('*', p, s32)
                p = rz_arith('*', p, c['K'])
                fr12 = fr12 if gt(p, fr12) else p        # 0x0BE970(fr4 = fr12, fr5 = p)
            elif st == 4:
                d = D_4F8 if sel else D_4C0
                v18 = L.l2(d, c['W'], c['L'])
                out[B_8018] = v18
                writes |= {B_8018 + i for i in range(4)}
                s36 = L.l2(D_4DC, c['TP'], fr14)
                f0 = L.l1(D_DF4, c['N'])
                fr12 = rz_arith('+', fr12, cf(img, C_BFC))
                p = rz_arith('*', v18, s36)
                p = rz_arith('*', p, f0)
                fr12 = fr12 if gt(p, fr12) else p
            else:
                fr12 = rz_arith('-', fr12, cf(img, C_BF8 if st == 3 else C_C00))
                fr12 = fr12 if gt(fr12, 0) else 0x00000000   # 0x0BE960(fr4 = fr12, fr5 = +0.0)
    dd = rz_arith('-', c['S1'], c['S2'])
    dd = dd if gt(dd, 0) else 0x00000000
    out[B_R] = fr12
    o = rz_arith('-', fr12, dd)
    out[B_OUT] = o if gt(o, 0) else 0x00000000
    out[B_801E] = st
    out[B_801F] = cnt
    return out, reads, writes, path


def run_b(img, c):
    e = EMUS[id(img)]
    fresh(e)
    for a, k in ((B_Q, 'Q'), (B_E, 'E'), (B_V, 'V'), (B_W, 'W'), (B_TP, 'TP'), (B_L, 'L'), (B_N, 'N'),
                 (B_R, 'R'), (B_K, 'K'), (B_S1, 'S1'), (B_S2, 'S2'), (B_8018, 'o8018'), (B_OUT, 'oOut'),
                 (B_8014, 'o8014')):
        poke(e, a, 4, c[k])
    poke(e, B_C2, 2, c['C2'])
    poke(e, B_801C, 2, c['o801c'])
    for a, k in ((B_67FC, 'a67fc'), (B_F12, 'F12'), (B_5BE3, 'f5be3'), (B_65C1, 'f65c1'), (B_9720, 'a9720'),
                 (B_801E, 'prev'), (B_801F, 'cnt')):
        poke(e, a, 1, c[k])
    tag = 'B ' + ' '.join(f'{k}={v}' for k, v in c.items())
    call_checked(e, FN_B, (10, 11, 12, 13, 14), tag)
    want, reads, writes, path = model_b(img, c)
    got = {B_8018: peek(e, B_8018, 4), B_8014: peek(e, B_8014, 4), B_801C: peek(e, B_801C, 2),
           B_R: peek(e, B_R, 4), B_OUT: peek(e, B_OUT, 4), B_801E: peek(e, B_801E, 1),
           B_801F: peek(e, B_801F, 1)}
    assert got == want, f'OUTPUT MISMATCH {tag}\n got  {got}\n want {want}'
    assert set(e.writes) == writes, (f'WRITE-SET MISMATCH {tag}\n got  {sorted(map(hex, e.writes))}'
                                     f'\n want {sorted(map(hex, writes))}')
    assert e.uninit_reads == reads, (f'READ-SET MISMATCH {tag}\n got  {sorted(map(hex, e.uninit_reads))}'
                                     f'\n want {sorted(map(hex, reads))}')
    return got, path


def case_b(**kw):
    c = dict(Q=f2b(0.0), E=f2b(0.0), V=f2b(10.0), W=f2b(0.0), TP=f2b(10.0), L=f2b(0.5), N=f2b(2500.0), C2=10,
             a67fc=0, F12=0, f5be3=0, f65c1=0, a9720=0, prev=0, cnt=0, R=f2b(0.0), K=f2b(1.0), S1=f2b(0.0),
             S2=f2b(0.0), o8018=0x5A5A5A5A, oOut=0x12345678, o8014=0x0BADF00D, o801c=0x7777)
    c.update(kw)
    return c


def grid_b(img, n_rand, label):
    L = LUTS[id(img)]
    Es = [-50.0, -40.0, -15.0, 0.0, 25.0, 65.0, 69.9, 70.0, 75.0, 110.0, 130.0]
    Ws = [-40.0, 0.0, 15.0, 55.0, 65.0, 70.0, 72.5, 75.0, 80.0, 110.0]
    TPs = [0.0, 3.0, 6.3, 15.0, 25.0, 50.0, 80.0]
    Lds = [0.2, 0.27, 0.6, 1.0, 1.1, 1.3, 1.6]
    Nl = [400.0, 750.0, 1500.0, 2600.0, 4000.0]
    bf0 = b2f(cf(img, C_BF0))
    Vs = [0.0, bf0 - 0.5, bf0, bf0 + 0.5, 100.0, float('nan')]
    Rs = [0.0, -0.0, 0.01, 0.5, 3.0, 12.0, 30.0, -1.0]
    Ks = [1.0, 0.5, 0.0, 2.0]
    S = [(0.0, 0.0), (5.0, 1.0), (1.0, 5.0), (10.0, 10.0), (3.0, 0.5)]
    paths = {}
    n = 0

    def draw_c2(e_):
        v = L.l16(D_0EC, f2b(e_))
        return _rng.choice([0, 5, v - 1 if v else 0, v, v + 1, 200, 65535])

    def draw_q(e_):
        v = b2f(L.l1(D_0D8, f2b(e_)))
        return _rng.choice([v - 1.0, v, v + 1.0, 0.0, -1.0, 1e6])

    examples = {}

    def one(c):
        nonlocal n
        got, path = run_b(img, c)
        paths[path] = paths.get(path, 0) + 1
        examples.setdefault(path, (c, got))
        n += 1

    for a67fc, F12, f5be3, f65c1, a9720 in itertools.product((0, 1, 2), (0, 1, 0x80), (0, 1), (0, 1, 2), (0, 1)):
        for prev in (0, 1, 2, 3, 4, 5, 9):
            for cnt in (0, 1, 2, 3, 254, 255):
                if _rng.random() < 0.6:
                    continue
                e_ = _rng.choice(Es)
                s1, s2 = _rng.choice(S)
                one(case_b(Q=f2b(draw_q(e_)), E=f2b(e_), V=f2b(_rng.choice(Vs)), W=f2b(_rng.choice(Ws)),
                           TP=f2b(_rng.choice(TPs)), L=f2b(_rng.choice(Lds)), N=f2b(_rng.choice(Nl)),
                           C2=draw_c2(e_), a67fc=a67fc, F12=F12, f5be3=f5be3, f65c1=f65c1, a9720=a9720,
                           prev=prev, cnt=cnt, R=f2b(_rng.choice(Rs)), K=f2b(_rng.choice(Ks)), S1=f2b(s1),
                           S2=f2b(s2)))
    for _ in range(n_rand):
        e_ = _rng.choice(Es[:5] * 2 + Es)
        s1, s2 = _rng.choice(S)
        one(case_b(Q=f2b(draw_q(e_)), E=f2b(e_), V=f2b(_rng.choice(Vs)), W=f2b(_rng.choice(Ws)),
                   TP=f2b(_rng.choice(TPs)), L=f2b(_rng.choice(Lds)), N=f2b(_rng.choice(Nl)), C2=draw_c2(e_),
                   a67fc=_rng.choice((0, 0, 1)), F12=_rng.choice((0, 0, 1)), f5be3=_rng.choice((0, 1)),
                   f65c1=_rng.choice((0, 0, 0, 1)), a9720=_rng.choice((0, 1)), prev=_rng.choice((0, 1, 2, 3, 4, 5)),
                   cnt=_rng.choice((0, 1, 2, 3, 255)), R=f2b(_rng.choice(Rs)), K=f2b(_rng.choice(Ks)),
                   S1=f2b(s1), S2=f2b(s2)))
    print(f'0x0415B8 [{label}]: {n} cases bit-exact (outputs, write-set, read-set, callee-saved)')
    for k_ in sorted(paths):
        c, got = examples[k_]
        print(f'    path {k_:10s} {paths[k_]:5d}   e.g. E={b2f(c["E"]):g} Q={b2f(c["Q"]):g} C2={c["C2"]} V={b2f(c["V"]):g} '
              f'W={b2f(c["W"]):g} L={b2f(c["L"]):g} TP={b2f(c["TP"]):g} N={b2f(c["N"]):g} R={b2f(c["R"]):g} '
              f'K={b2f(c["K"]):g} S1-S2={b2f(c["S1"]) - b2f(c["S2"]):g} 67FC={c["a67fc"]} 85D7={c["F12"]} '
              f'5BE3={c["f5be3"]} 65C1={c["f65c1"]} 9720={c["a9720"]} prev={c["prev"]} cnt={c["cnt"]} -> '
              f'R\'={b2f(got[B_R]):.6g} OUT={b2f(got[B_OUT]):.6g} state={got[B_801E]} cnt={got[B_801F]} '
              f'8014={b2f(got[B_8014]):g} 801C={got[B_801C]}')
    return paths


# ================================================================== callees, lookups, context functions
def check_callees():
    n = 0
    for fn, a, f in ((0x023E48, 0xFFFF67FC, lambda v: 1 if v == 1 else 0),
                     (0x02F8EA, 0xFFFF726C, lambda v: 1 if v == 1 else 0),
                     (0x022F92, 0xFFFF65F6, lambda v: 1 if v == 1 else 0),
                     (0x0299F0, 0xFFFF9720, lambda v: 2 if v != 0 else 0),
                     (0x022CF4, 0xFFFF65C5, lambda v: 1 if v == 1 else 0),
                     (0x05EB32, 0xFFFF8F22, lambda v: 1 if v & 0x20 else 0)):
        for v in range(256):
            e = E.Emu(REAL)
            e.ram_u8(a, v)
            e.call(fn)
            assert e.R[0] == f(v), (hex(fn), v, e.R[0])
            n += 1
    print(f'callees: 0x023E48 / 0x02F8EA / 0x022F92 / 0x022CF4 = (byte == 1), 0x0299F0 = 2 if byte != 0 else 0, '
          f'0x05EB32 = bit 5 of byte ({n} cases, every byte value)')


def interp1(ax, vals, x):
    if x != x or x >= ax[-1]:
        return vals[-1]
    if x < ax[0]:
        return vals[0]
    for i in range(len(ax) - 1):
        if ax[i] <= x < ax[i + 1]:
            return vals[i] + (x - ax[i]) / (ax[i + 1] - ax[i]) * (vals[i + 1] - vals[i])
    return vals[-1]


def check_lookups():
    """Every table both functions read, against read_table() + textbook interpolation (tolerance)."""
    worst, n = 0.0, 0
    L = LUTS[id(REAL)]
    for d in TABLES_A + TABLES_B:
        t = DT.read_table(REAL, d)
        if t['dim'] == '1D':
            ax = t['axes']['x']
            xs = [ax[0] - 100.0, ax[-1] + 100.0] + [ax[i] + (ax[i + 1] - ax[i]) * k
                                                     for i in range(len(ax) - 1) for k in (0.0, 0.3, 0.75)]
            for x in xs:
                want = interp1(ax, t['values'], b2f(f2b(x)))
                if d in (D_A4, D_34, D_0EC):
                    got = float(L.l16(d, f2b(x)))
                    want = float(int(want))
                    assert abs(got - want) <= 1.0, (hex(d), x, got, want)    # truncation of a near-integer
                else:
                    got = b2f(L.l1(d, f2b(x)))
                    worst = max(worst, abs(got - want))
                    assert abs(got - want) <= 1e-4 * max(1.0, abs(want)), (hex(d), x, got, want)
                n += 1
        else:
            aa, bb = t['axes']['y'], t['axes']['x']      # read_table: 'y' = the +4 axis (fr4), 'x' = +8 (fr5)
            for x in [aa[0] - 50.0, aa[-1] + 50.0] + [aa[i] + (aa[i + 1] - aa[i]) * k
                                                      for i in range(len(aa) - 1) for k in (0.0, 0.5)]:
                for y in [bb[0] - 5.0, bb[-1] + 5.0] + [bb[i] + (bb[i + 1] - bb[i]) * k
                                                        for i in range(len(bb) - 1) for k in (0.0, 0.4)]:
                    xr, yr = b2f(f2b(x)), b2f(f2b(y))
                    rows = [interp1(aa, t['values'][j], xr) for j in range(len(bb))]
                    want = interp1(bb, rows, yr)
                    got = b2f(L.l2(d, f2b(x), f2b(y)))
                    worst = max(worst, abs(got - want))
                    assert abs(got - want) <= 1e-4 * max(1.0, abs(want)), (hex(d), x, y, got, want)
                    n += 1
    print(f'lookups: {len(TABLES_A + TABLES_B)} records, {n} points, ROM routine == read_table() interpolation '
          f'(worst {worst:.2e})')


def check_stock_identity():
    rng_ = []
    for d in TABLES_A + TABLES_B:
        dp, w, nn = desc_cells(REAL, d)
        rng_.append((d, 28))
        rng_.append((dp, w * nn))
        two = DT.is_2d(REAL, d)
        for off in ((4, 8) if two else (4,)):
            ap = U32(REAL, d + off)
            cnt = U16(REAL, d + (0 if off == 4 else 2)) if two else U16(REAL, d)
            rng_.append((ap, 4 * cnt))
    rng_ += [(a, 4) for a in CAL_F32] + [(a, 1) for a in CAL_U8] + [(a, 2) for a in CAL_U16]
    rng_ += [(0x0D2976, 1), (0x0D2B9C, 4), (0x0D2C04, 4), (0x0AE164, 20)]
    diff = [hex(a) for a, n in rng_ if REAL[a:a + n] != STOCK[a:a + n]]
    assert not diff, diff
    code = [(0x0410D4, 0x0415B8), (0x0415B8, 0x0418AC), (0x041030, 0x0410D4), (0x0418AC, 0x041954)]
    assert all(REAL[a:b] == STOCK[a:b] for a, b in code)
    print(f'stock vs 20.19c: {len(rng_)} calibration / table / axis ranges and the code 0x041030..0x041954 '
          f'are byte-identical')


def print_values():
    def f(a):
        return b2f(cf(REAL, a))
    print('calibration (20.19c == stock):')
    for a in CAL_F32 + [0x0D2B9C, 0x0D2C04]:
        print(f'    {a:06X} f32 {f(a):.9g}')
    for a in CAL_U8 + [0x0D2976]:
        print(f'    {a:06X} u8  {REAL[a]}')
    for a in CAL_U16:
        print(f'    {a:06X} u16 {U16(REAL, a)}')
    L = LUTS[id(REAL)]
    print('0x0410D4 tables at the [0xFFFF6354] input (warm-side values included):')
    for x in (-40.0, 0.0, 40.0, 70.0, 80.0, 110.0):
        row = [f'{b2f(L.l1(d, f2b(x))):.6g}' for d in (K_A['d36'], K_A['d40'], K_A['d13'], K_B['d36'],
                                                         K_B['d40'], K_B['d13'], D_40)]
        print(f'    x={x:6.1f}  0AE054 0AE07C 0AE0B0 0AE068 0AE090 0AE0C4 0AE040 = {" ".join(row)}  '
              f'0AE0A4={L.l16(D_A4, f2b(x))} 0AE034={L.l16(D_34, f2b(x))}')
    print('0x0415B8 gates at the [0xFFFF6354] input:')
    for x in (-40.0, 0.0, 20.0, 40.0, 60.0, 65.0, 69.0, 70.0, 80.0, 110.0):
        print(f'    x={x:6.1f}  0AE0D8 = {b2f(L.l1(D_0D8, f2b(x))):10.1f}   0AE0EC (uint16) = {L.l16(D_0EC, f2b(x))}')
    print('0x0415B8 targets at the [0xFFFF6350] input (first number = fr5 input [0xFFFF63F8]):')
    for d in (D_450, D_46C, D_4A4, D_4C0, D_4F8):
        for ld in (0.27, 1.1, 1.5):
            row = [f'{b2f(L.l2(d, f2b(w), f2b(ld))):.4g}' for w in (0.0, 40.0, 60.0, 65.0, 70.0, 75.0, 80.0, 110.0)]
            print(f'    {d:06X} L={ld:4.2f}  W=0,40,60,65,70,75,80,110 -> {" ".join(row)}')


def check_0x041030():
    """0x041030: [0xFFFF7FC0] = [7FB8]*[7FB0]*[7FC4]*[7FD4]*0.01, then * [0x0D2B9C] when [0xFFFF67FC]==1."""
    n = 0
    vals = [0.0, 1.0, 0.5, 3.0, 100.0, -2.0, 7.25]
    for a, b, cc, d, m in itertools.product(vals[:5], vals[1:4], (1.0, 0.25, 100.0), (1.0, 2.0, 50.0), (0, 1, 2)):
        e = E.Emu(REAL)
        for adr, v in ((0xFFFF7FB8, a), (0xFFFF7FB0, b), (0xFFFF7FC4, cc), (0xFFFF7FD4, d)):
            e.ram_f32(adr, v)
        e.ram_u8(0xFFFF67FC, m)
        e.call(0x041030)
        p = rz_arith('*', f2b(a), f2b(b))
        p = rz_arith('*', p, f2b(cc))
        p = rz_arith('*', p, f2b(d))
        p = rz_arith('*', p, 0x3C23D70A)
        if m == 1:
            p = rz_arith('*', p, cf(REAL, 0x0D2B9C))
        assert e.read_u32(0xFFFF7FC0) == p, (a, b, cc, d, m)
        assert set(e.writes) == {0xFFFF7FC0 + i for i in range(4)}
        n += 1
    print(f'0x041030: {n} cases, [0xFFFF7FC0] = product of four floats * 0.01, times [0x0D2B9C] = '
          f'{b2f(cf(REAL, 0x0D2B9C))} when byte [0xFFFF67FC] == 1')


def check_0x0418xx():
    n = 0
    for v8010, v800c, vin in itertools.product((0.0, 0.1, 0.3), (0.0, 0.05, 0.2), (0.0, 0.01, 0.5)):
        e = E.Emu(REAL)
        e.ram_f32(0xFFFF7BE4, vin)
        e.ram_f32(0xFFFF798C, 0.0)
        e.ram_f32(0xFFFF8010, v8010)
        e.ram_f32(0xFFFF800C, v800c)
        e.call(0x0418AC)
        assert e.read_f32(0xFFFF8008) == 1.0, (v8010, v800c, vin)     # descriptor 0x0AE164 is flat 1.0
        n += 1
    for flag in range(4):
        e = E.Emu(REAL)
        for a in (0xFFFF8000, 0xFFFF8004, 0xFFFF8008, 0xFFFF800C, 0xFFFF8010):
            e.ram_f32(a, 7.5)
        e.ram_u8(0xFFFF801E, 3)
        e.ram_u8(0xFFFF801F, 9)
        e.ram_u8(0xFFFF65F6, flag)
        e.call(0x0418FC)
        if flag == 1:
            assert [e.read_f32(a) for a in (0xFFFF8000, 0xFFFF8004, 0xFFFF8008, 0xFFFF800C, 0xFFFF8010)] == \
                [0.0, 0.0, 1.0, 0.0, 0.0]
            assert e.read_u8(0xFFFF801E) == 0 and e.read_u8(0xFFFF801F) == 0
        else:
            assert not e.writes
        n += 1
    print(f'0x0418AC / 0x0418FC: {n} cases; [0xFFFF8008] = 1.0 from flat table 0x0AE164; 0x0418FC zeroes '
          f'8000/8004/800C/8010, sets 8008 = 1.0, clears bytes 801E/801F iff byte [0xFFFF65F6] == 1')


def check_0x040970():
    """0x040970: when byte [0xFFFF65F6] == 1 it zeroes [0xFFFF7FBC] and clears bytes 7FDC / 7FF1 (and others);
    it never writes the latch byte 0xFFFF7FF4."""
    n = 0
    for flag in range(4):
        e = E.Emu(REAL)
        e.ram_f32(0xFFFF7FBC, 3.25)
        for a in (0xFFFF7FDC, 0xFFFF7FF1, 0xFFFF7FF4):
            e.ram_u8(a, 1)
        e.ram_u8(0xFFFF65F6, flag)
        e.ram_u8(0xFFFF90BE, 0x21)
        e.ram_u8(0xFFFF8E7E, 0x42)
        e.call(0x040970)
        if flag == 1:
            assert e.read_f32(0xFFFF7FBC) == 0.0 and e.read_u8(0xFFFF7FDC) == 0 and e.read_u8(0xFFFF7FF1) == 0
            want = ({0xFFFF7FBC + i for i in range(4)} | {0xFFFF7FDC, 0xFFFF7FF1, 0xFFFF7FF6, 0xFFFF7FEC,
                    0xFFFF7FE4, 0xFFFF7FE5, 0xFFFF7FFB, 0xFFFF7FFA, 0xFFFF7FF8, 0xFFFF7FF9, 0xFFFF7FFF,
                    0xFFFF7FFE, 0xFFFF7FFC, 0xFFFF7FFD})
            assert set(e.writes) == want, sorted(map(hex, e.writes))
        else:
            assert not e.writes
        assert e.read_u8(0xFFFF7FF4) == 1          # the latch survives
        n += 1
    print(f'0x040970: {n} cases; iff byte [0xFFFF65F6] == 1: [0xFFFF7FBC] = 0, bytes 7FDC / 7FF1 = 0; '
          f'byte 0xFFFF7FF4 is never written')


def check_sum():
    """0x03F3BE..0x03F3C4 stores the float at 0xFFFF7FBC into @(8,r15); 0x03F618..0x03F674 is a signed sum."""
    e = E.Emu(REAL)
    sp = E.STACK_TOP - 0x100
    e.ram_f32(0xFFFF7FBC, 6.5)
    assert e.call(0x03F3BE, regs={15: sp}, stop_at={0x03F3C6}) == 0x03F3C6
    assert e.read_f32(sp + 8) == 6.5
    terms = [('sp+4', None), (0xFFFF7F6C, None), (0xFFFF7F74, None), ('sp+8', None), (0xFFFF8000, None),
             (0xFFFF81EC, None), (0xFFFF8028, None), (0xFFFF8038, None), (0xFFFF803C, None), (0xFFFF805C, None),
             (0xFFFF8084, None), (0xFFFF80B4, None), (0xFFFF80C4, None), (0xFFFF80E8, None), (0xFFFF80F0, None),
             (0xFFFF7F0C, None)]
    signs = {}
    for t, _ in terms:
        e = E.Emu(REAL)
        for u, _ in terms:
            a = sp + int(u[3:]) if isinstance(u, str) else u
            e.ram_f32(a, 1.0 if u == t else 0.0)
        assert e.call(0x03F618, regs={15: sp}, stop_at={0x03F676}) == 0x03F676
        signs[t] = e.fr(6)
    print('timing sum 0x03F618..0x03F674 (fr6), each term alone = 1.0:')
    print('    ' + '  '.join(f'{(hex(t) if not isinstance(t, str) else t)}:{v:+.0f}' for t, v in signs.items()))
    assert signs['sp+8'] == -1.0 and signs[0xFFFF8000] == -1.0 and signs[0xFFFF81EC] == 1.0
    assert sorted(signs.values()) == [-1.0] * 5 + [1.0] * 11
    print('    -> [0xFFFF7FBC] (via @(8,r15)) and [0xFFFF8000] are both SUBTRACTED; [0xFFFF81EC] is added')


# ================================================================== multi-call scenarios (printed, asserted)
def scen_a():
    """Repeated calls of 0x0410D4 with the RAM carried over: ramp, hold, decay, then the latch."""
    e = EMUS[id(REAL)]
    fresh(e)
    st = case_a(E=f2b(80.0), V=f2b(0.0), N=f2b(1000.0), T=f2b(800.0), P=f2b(10.0), C=10, M=0, a67fc=0, F10=1,
                F12=1, F9=1, a726c=1, X=f2b(0.0), H=f2b(5.0), l7ff4=0, f7fdc=0, Y=f2b(100.0), g=[f2b(150.0)] * 4)
    for a, k in ((A_E, 'E'), (A_V, 'V'), (A_N, 'N'), (A_T, 'T'), (A_P, 'P'), (A_X, 'X'), (A_H, 'H'), (A_Y, 'Y')):
        e.ram_u32(a, st[k])
    for j, a in enumerate(A_G):
        e.ram_u32(a, st['g'][j])
    e.ram_u16(A_C, st['C'])
    for a, k in ((A_M, 'M'), (A_67FC, 'a67fc'), (A_F10, 'F10'), (A_F12, 'F12'), (A_F9, 'F9'), (A_726C, 'a726c'),
                 (A_7FF4, 'l7ff4'), (A_7FF1, 'l7ff1'), (A_7FDC, 'f7fdc')):
        e.ram_u8(a, st[k])
    traj = []

    def step(n):
        for _ in range(n):
            e.steps = 0
            e.call(FN_A)
            traj.append(e.read_f32(A_X))
    step(40)        # C = 10 < 375, N >= T+100, P >= 4.25..: +0.16 per call up to H = 5.0
    up = traj[-1]
    e.ram_u8(A_F12, 0)      # F12 = 0 -> -0.7 per call
    step(10)
    down = traj[-1]
    e.ram_u8(A_F9, 0)       # F9 = 0 with X == 0 -> latch
    step(1)
    latch = e.read_u8(A_7FF4)
    e.ram_u8(A_F12, 1)
    e.ram_u8(A_F9, 1)
    step(5)
    print(f'scenario 0x0410D4 (E = 80, warm side; tables are flat in E): +0.16/call to H: after 40 calls '
          f'X = {up:g}; F12 = 0: -0.7/call, X = {down:g}; F9 = 0 at X = 0 -> latch byte = {latch}; '
          f'afterwards X = {traj[-1]:g} with the ramp conditions restored')
    assert abs(traj[0] - 0.160003662109375) < 1e-9 and up == 5.0 and down == 0.0 and latch == 1 and traj[-1] == 0.0


def scen_b():
    """Repeated calls of 0x0415B8 with RAM carried over: cold ramp (state 1) and warm decay (state 3)."""
    e = EMUS[id(REAL)]
    fresh(e)
    vals = dict(Q=0.0, E=0.0, V=10.0, W=0.0, TP=15.0, L=0.27, N=2500.0, R=0.0, K=1.0, S1=0.0, S2=0.0)
    for a, k in ((B_Q, 'Q'), (B_E, 'E'), (B_V, 'V'), (B_W, 'W'), (B_TP, 'TP'), (B_L, 'L'), (B_N, 'N'), (B_R, 'R'),
                 (B_K, 'K'), (B_S1, 'S1'), (B_S2, 'S2')):
        e.ram_f32(a, vals[k])
    e.ram_u16(B_C2, 10)
    for a in (B_67FC, B_F12, B_5BE3, B_65C1, B_9720, B_801E, B_801F):
        e.ram_u8(a, 0)
    traj = []
    for _ in range(12):
        e.steps = 0
        e.call(FN_B)
        traj.append((e.read_u8(B_801E), e.read_f32(B_OUT)))
    cold = traj[-1][1]
    tgt = b2f(LUTS[id(REAL)].l2(D_450, f2b(0.0), f2b(0.27)))
    # warm: [0xFFFF6354] = 80 makes 0x0AE0D8 = 0 and 0x0AE0EC = 0, so the state-1 condition fails
    e.ram_f32(B_E, 80.0)
    e.ram_f32(B_W, 80.0)
    warm = []
    for _ in range(300):
        e.steps = 0
        e.call(FN_B)
        warm.append((e.read_u8(B_801E), e.read_f32(B_OUT)))
    n_to_zero = next(i for i, (_, v) in enumerate(warm) if v == 0.0) + 1
    print(f'scenario 0x0415B8 cold (6354 = 6350 = 0, C2 = 10, TP = 15, L = 0.27, N = 2500): state '
          f'{traj[0][0]}, OUT {traj[0][1]:g} -> {traj[4][1]:g} -> {cold:g} (target 0x0AE450 = {tgt:g}); '
          f'then 6354 = 6350 = 80: state {warm[0][0]}, -0.02/call, reaches 0 after {n_to_zero} calls')
    assert traj[0] == (1, 0.699999988079071) and cold == tgt
    assert all(s == 3 for s, _ in warm) and warm[-1][1] == 0.0


# ================================================================== review checks (third reader)
NAN, INF, NINF = 0x7FC00000, 0x7F800000, 0xFF800000
FLT_MAX = (2 - Fraction(1, 2 ** 23)) * 2 ** 127


def check_edges_a():
    """A3 / A6. Clamp rows on the V >= 510 path (x = X - 1.0) and latch rows (F9 = 0). Every row also goes
    through run_a, so the model, the write set and the read set are asserted as well."""
    one = f2b(1.0)
    rows = [  # (H, X) -> X'   on path dec_v: x = X - 1.0; X' = +0 if not (x > 0), x if H > x, else H
        (NAN, f2b(2.0), NAN), (NAN, f2b(-1.0), 0x00000000), (NAN, NAN, 0x00000000), (NAN, f2b(0.0), 0x00000000),
        (0x80000000, f2b(2.0), 0x80000000), (f2b(-1.0), f2b(2.0), f2b(-1.0)), (f2b(5.0), f2b(2.0), one),
        (INF, f2b(2.0), one), (f2b(1.0), f2b(2.0), one), (f2b(0.5), f2b(2.0), f2b(0.5))]
    for H, X, want in rows:
        got, path = run_a(REAL, case_a(V=f2b(510.0), X=X, H=H, F9=1))
        assert path == 'dec_v' and got[A_X] == want, (hex(H), hex(X), hex(got[A_X]), hex(want))
    wn = WIN + 1
    lrows = [(0x00000000, 1), (0x80000000, 1), (WIN, 1), (WIN | 0x80000000, 1), (NAN, 1),
             (wn, 0), (wn | 0x80000000, 0), (INF, 0), (NINF, 0)]
    for X, want in lrows:
        got, path = run_a(REAL, case_a(F9=0, X=X, l7ff4=0))
        assert got[A_7FF4] == want, (hex(X), got[A_7FF4])
        if want:
            assert path == 'forced0' and got[A_X] == 0
    print(f'review A3/A6: {len(rows)} clamp rows (NaN H passes through for x > 0; -0 / negative H returned; '
          f'x <= 0 or NaN -> +0) and {len(lrows)} latch rows (NaN X, +-0, +-w latch; +-(w+1ulp), +-inf do not)')


def check_rz_041030():
    """A5. H with byte [67FC] == 1 is product * 0.01 * 0.0. Finite factors give H = +-0 here only because
    the emulator rounds toward zero (overflow saturates to +-FLT_MAX); under round-to-nearest an exact
    first product above FLT_MAX + 2^103 (half an ulp at the top binade) rounds to +inf and inf * 0 = NaN."""
    cases = [((1e30, 1e30, 1.0, 1.0), 0x00000000, True), ((3.0e38, 10.0, 1.0, 1.0), 0x00000000, True),
             ((2.0, 3.0, 4.0, 5.0), 0x00000000, False), ((-2.0, 3.0, 4.0, 5.0), 0x80000000, False),
             ((float('inf'), 1.0, 1.0, 1.0), None, None)]
    for fac, want, rn_overflow in cases:
        e = E.Emu(REAL)
        for adr, v in zip((0xFFFF7FB8, 0xFFFF7FB0, 0xFFFF7FC4, 0xFFFF7FD4), fac):
            e.ram_u32(adr, f2b(v))
        e.ram_u8(0xFFFF67FC, 1)
        e.call(0x041030)
        h = e.read_u32(0xFFFF7FC0)
        if want is None:
            assert math.isnan(b2f(h)), hex(h)
            continue
        assert h == want, (fac, hex(h))
        exact = Fraction(b2f(f2b(fac[0]))) * Fraction(b2f(f2b(fac[1])))
        assert (exact > FLT_MAX + Fraction(2) ** 103) == rn_overflow, fac
    print('review A5: byte [67FC] == 1 -> H = +-0.0 for finite products; NaN for an infinite factor; '
          '(1e30,1e30,1,1) and (3e38,10,1,1) give 0.0 ONLY under round-toward-zero (exact first product '
          'exceeds the round-to-nearest overflow threshold, so RN would give +inf * 0 = NaN)')


def check_flat_a():
    """A21. 0x0410D4 reads NINE records; each is single-valued in both images and its lookup is constant."""
    assert len(TABLES_A) == 9 and len(set(TABLES_A)) == 9
    L = LUTS[id(REAL)]
    xs = (NAN, 0xFFC00000, INF, NINF, f2b(-1000.0), f2b(1000.0), f2b(-40.0), f2b(33.3), f2b(110.0))
    for d in TABLES_A:
        for img in (REAL, STOCK):
            dp, w, n = desc_cells(img, d)
            assert U32(img, d + 4) == 0x0D2FCC and n == 16
            assert len({img[dp + i * w:dp + (i + 1) * w] for i in range(n)}) == 1, hex(d)
        assert REAL[dp:dp + w * n] == STOCK[dp:dp + w * n]
        vals = {(L.l16(d, x) if d in (D_A4, D_34) else L.l1(d, x)) for x in xs}
        assert len(vals) == 1, (hex(d), vals)
    print('review A21: 9 records (0AE054 0AE07C 0AE0B0 0AE068 0AE090 0AE0C4 0AE0A4 0AE040 0AE034), 16 cells each, '
          'one raw value per record in 20.19c and stock; lookup constant for NaN / +-inf / +-1000 / in-range')


def check_states24():
    """B12. States 2 / 4 (all-zero targets): R' = R + 0.7 when that is < 0, else the zero target product."""
    k07 = cf(REAL, C_BF4)
    assert k07 == cf(REAL, C_BFC)
    n = 0
    for kw in (dict(f5be3=1), dict(a67fc=1)):
        st = 2 if 'f5be3' in kw else 4
        for R in (f2b(-1.0), f2b(-0.75), k07 | 0x80000000, f2b(-0.5), 0x80000000, f2b(3.0), NAN, INF, NINF):
            got, path = run_b(REAL, case_b(R=R, prev=0, cnt=0, **kw))
            s = rz_arith('+', R, k07)
            want = s if gt(0x00000000, s) else 0x00000000
            assert path == f'st{st}' and got[B_R] == want and got[B_OUT] == 0, (st, hex(R), hex(got[B_R]))
            n += 1
    assert run_b(REAL, case_b(R=f2b(-1.0), f5be3=1))[0][B_R] == 0xBE99999A        # -0.3, not 0
    print(f'review B12: {n} rows; states 2/4 give R\' = +0.0 for R >= -0.7 (and NaN, +inf), R + 0.7 for '
          f'R < -0.7 (R = -1 -> -0.3; -inf -> -inf); OUT = 0 in every row')


def check_0x040A9C():
    """Writer of byte 0xFFFF7FDC (called by 0x040918 just before 0x0410D4). flag = 1 iff byte [726C] != 1 and
    ((byte [65C5] != 1 and byte [7FEE] == 1 and u16 [7FE8] < u16 [0D29C2] and byte [65C0] == 1) or
     (byte [7FEF] == 1 and u16 [7FEA] < u16 [0D29C4]))."""
    assert REAL[0x040A9C:0x040AF6] == STOCK[0x040A9C:0x040AF6]
    for a, b in ((0x022CF4, 0x022D2C), (0x02F8EA, 0x02F90C)):
        assert REAL[a:b] == STOCK[a:b]
    alt = bytearray(REAL)
    struct.pack_into('>H', alt, 0x0D29C2, 300)
    alt = bytes(alt)
    ws = [0, 1, 299, 300, 437, 438, 439, 0x7FFF, 0x8000, 0xFFFF]
    ones = {}
    for nm, img in (('20.19c', REAL), ('stock', STOCK), ('0D29C2=300', alt)):
        n = k = 0
        for b726c, b65c5, b7fee, b7fef, b65c0, w8, wa in itertools.product((0, 1, 2), (0, 1), (0, 1, 2), (0, 1, 2),
                                                                              (0, 1, 2), ws, ws):
            e = E.Emu(img)
            for a, v in ((0xFFFF726C, b726c), (0xFFFF65C5, b65c5), (0xFFFF7FEE, b7fee), (0xFFFF7FEF, b7fef),
                         (0xFFFF65C0, b65c0), (0xFFFF7FDC, 0x77)):
                e.ram_u8(a, v)
            e.ram_u16(0xFFFF7FE8, w8)
            e.ram_u16(0xFFFF7FEA, wa)
            e.call(0x040A9C)
            want = 1 if (b726c != 1 and ((b65c5 != 1 and b7fee == 1 and w8 < U16(img, 0x0D29C2) and b65c0 == 1)
                                         or (b7fef == 1 and wa < U16(img, 0x0D29C4)))) else 0
            assert e.read_u8(0xFFFF7FDC) == want, (nm, b726c, b65c5, b7fee, b7fef, b65c0, w8, wa)
            assert set(e.writes) == {0xFFFF7FDC}
            n += 1
            k += want
        ones[nm] = (n, k)
    assert ones['stock'][1] == 0 and ones['20.19c'][1] > 0
    print(f'review 0x040A9C: u16 0x0D29C2 = {U16(REAL, 0x0D29C2)} / {U16(STOCK, 0x0D29C2)}, 0x0D29C4 = '
          f'{U16(REAL, 0x0D29C4)} / {U16(STOCK, 0x0D29C4)} (20.19c / stock); flag = 1 in '
          + ', '.join(f'{nm} {k} of {n}' for nm, (n, k) in ones.items()) + ' -- never in stock')


def check_03F368_paths():
    """S1 / S2 / S3. Whole runs of 0x03F368 on each path; which RAM outputs move when [7FBC] or [8000] is 1.0."""
    alt = bytearray(REAL)
    alt[0x0D2976] = 0
    alt = bytes(alt)
    base = {0xFFFF6624: 3000.0, 0xFFFF62F8: 0.5, 0xFFFF65FC: 1.0, 0xFFFF6350: 90.0, 0xFFFF7F68: 0.25,
            0xFFFF7F0C: 1.5, 0xFFFF7F6C: 0.125, 0xFFFF7F74: 0.375, 0xFFFF81DC: 2.0, 0xFFFF81E0: 3.0,
            0xFFFF81E4: 4.0, 0xFFFF81E8: 5.0, 0xFFFF7EC0: 50.0, 0xFFFF7EC4: 40.0, 0xFFFF7EE4: 10.0}
    tail = {0xFFFF7EA0, 0xFFFF7EA4, 0xFFFF7EA8, 0xFFFF7EAC}
    summ = {0xFFFF7EB0, 0xFFFF7EB4, 0xFFFF7EB8, 0xFFFF7EBC}
    paths = [  # name, bytes, floats, image, stop address that must be reached, want(7FBC), want(8000)
        ('[8F16]=3 -> 03F43C', {0xFFFF8F16: 3}, {}, REAL, 0x03F43C, tail, set()),
        ('[8F16]=1 -> 03F5C4', {0xFFFF8F16: 1}, {}, REAL, 0x03F468, tail, set()),
        ('chain 03F470 -> 03F5C4', {0xFFFF8F24: 1, 0xFFFF8F22: 0x20, 0xFFFF85D7: 1},
         {0xFFFF7F68: -1.0, 0xFFFF6624: 1000.0}, REAL, 0x03F494, tail, set()),
        ('chain 03F49A -> 03F5C4', {0xFFFF7F03: 1}, {0xFFFF6624: 800.0}, REAL, 0x03F4D6, tail, set()),
        ('[7D18]=1 -> 03F5DC', {0xFFFF7D18: 1}, {}, REAL, 0x03F5DC, tail, set()),
        ('sixteen-term sum 03F618', {}, {}, REAL, 0x03F618, tail | summ, summ),
        ('max form 03F6AC ([0D2976]=0)', {}, {}, alt, 0x03F6AC, tail | summ, summ),
    ]

    def run(img, b, f, extra, stop=None):
        e = E.Emu(img)
        for a, v in base.items():
            e.ram_f32(a, v)
        for a, v in f.items():
            e.ram_f32(a, v)
        for a, v in b.items():
            e.ram_u8(a, v)
        for a, v in extra.items():
            e.ram_f32(a, v)
        r = e.call(0x03F368, stop_at={stop} if stop else ())
        return r, dict(e.writes)

    def moved(a, b):
        return {k & ~3 for k in set(a) | set(b) if a.get(k) != b.get(k)}

    for name, b, f, img, stop, w_x, w_8 in paths:
        assert run(img, b, f, {}, stop)[0] == stop, name
        assert run(img, b, f, {}, 0x03F88E)[0] == 0x03F88E, name
        r0, w0 = run(img, b, f, {})
        assert r0 == 'return'
        _, wx = run(img, b, f, {0xFFFF7FBC: 1.0})
        _, w8 = run(img, b, f, {0xFFFF8000: 1.0})
        assert moved(w0, wx) == w_x and moved(w0, w8) == w_8, (name, sorted(map(hex, moved(w0, wx))),
                                                              sorted(map(hex, moved(w0, w8))))
        # [7FBC] is SUBTRACTED in the tail: +1.0 moves each unclamped tail output by exactly -1.0
        for a in sorted(tail):
            d = b2f(int.from_bytes(bytes(wx[a + i] for i in range(4)), 'big')) - \
                b2f(int.from_bytes(bytes(w0[a + i] for i in range(4)), 'big'))
            assert d == -1.0, (name, hex(a), d)
        print(f'review 0x03F368 {name:30s} reaches {stop:06X} and 03F88E; [7FBC] moves '
              f'{" ".join(f"{a:04X}"[-4:] for a in sorted(w_x))}; [8000] moves '
              f'{" ".join(f"{a:04X}"[-4:] for a in sorted(w_8)) or "nothing"}')


def main():
    check_stock_identity()
    print_values()
    check_callees()
    check_lookups()
    check_0x041030()
    check_0x0418xx()
    check_0x040970()
    check_sum()
    pa = grid_a(REAL, 1500, 'REAL')
    pu = grid_a(UNIQ, 2500, 'UNIQ')
    pu2 = grid_a(UNIQ2, 2000, 'UNIQ2')
    need = {'forced0', 'dec_v', 'dec_f12', 'dec_p10', 'dec_p0', 'dec_q', 'inc_L13', 'inc_AE040', 'inc_L36',
            'inc_L40', 'hold', 'hold_r11'}
    for pp in (pu, pu2):
        assert need <= set(pp), need - set(pp)
    assert need - {'inc_L13'} <= set(pa), need - set(pa)
    stub_pass_a()
    pb = grid_b(REAL, 1500, 'REAL')
    pv = grid_b(UNIQ, 2500, 'UNIQ')
    pv2 = grid_b(UNIQ2, 2000, 'UNIQ2')
    needb = {'st1', 'st2', 'st3', 'st4', 'st5', 'st1_wait', 'st3_wait'}
    assert needb <= set(pv), needb - set(pv)
    assert needb | {'reset'} <= set(pv2), needb | {'reset'} - set(pv2)
    assert 'reset' in pb and 'st1_wait' not in pb      # REAL: 0x0D297F == 90, divider 0x0D297E == 1
    scen_a()
    scen_b()
    check_edges_a()
    check_rz_041030()
    check_flat_a()
    check_states24()
    check_0x040A9C()
    check_03F368_paths()
    print('ALL CHECKS PASSED')


if __name__ == '__main__':
    main()
