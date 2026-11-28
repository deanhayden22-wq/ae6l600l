#!/usr/bin/env python3
"""Emulation check for ROM function 0x040AF6..0x041030 (568 instructions, GBR 0xFFFF7FB0), the writer of
the four factors of the clamp H = [0xFFFF7FC0] that bounds the integrator [0xFFFF7FBC], plus the context
facts its trace relies on.

    python3 scripts/trace/emu_timing_bound_040AF6.py

Reference bin: rom/AE5L600L 20g rev 20.19c.bin  md5 92cae8275cd4f9b473a3a9e36efe6449
Trace:         disassembly/analysis/timing_bound_040AF6_trace.txt

What it does
------------
check_main     runs 0x040AF6 in scripts/sh2e_emu.py (real callees, from ROM) against a Python model written
               from the bytes and asserts, per case: every output RAM cell bit for bit; the exact SET of
               non-stack RAM bytes written; the exact SET of RAM cells read before being written in the same
               call (inputs are poked WITHOUT marking them initialised); r8-r14, r15, GBR, fr12-fr15 restored.
               Four images, all IN MEMORY (nothing on disk is written):
                 REAL   the reference bin           STOCK  rom/ae5l600l.bin
                 UNIQ1  every table this function reads holds data unique to that table and cell, every
                        calibration scalar a value unique to its address, the u16 windows opened so every
                        branch the shipped calibration never takes is executed; byte [0x0D297C] = 90
                 UNIQ2  as UNIQ1 with other values, [0x0D297C] = 91 and the three eps pool words changed
               The model reads every table / constant from the image it is given, so naming the wrong
               descriptor or address fails on UNIQ even where REAL holds equal values.
check_real     the bottom-line facts on REAL and STOCK, asserted per case with explicit bits:
               [7FB0] == [7FB4]; [7FB4] = 20.0390625 iff byte [3158] == 1 or byte [90BE] == 1, else +0.0;
               [7FC4] = 1.0; [7FD0] = 1.0 (or +0.0 when byte [9707] != 0); [7FD4] = +0.0 iff byte
               [9707] != 0 else 1.0; [7FB8] = table 0x0ADD90 at [6354] (= 0x0ADDA4, identical bytes);
               then runs 0x041030 in the same machine and asserts H.
check_tables   decodes all 21 records from bytes in both bins (geometry, data, flatness), checks the ROM
               lookup against desc_types.read_table + linear interpolation, and that the flat tables return
               one value for NaN / +-inf / out-of-range inputs.
check_chain    whole-task runs of 0x040918 (0x040A9C, 0x040AF6, 0x041030, 0x0410D4), iterated: [7FBC]
               climbs to H when byte [90BE] == 1 and stays exactly 0 when [90BE] != 1 and [3158] != 1.
               These cases set byte [69E6] = 1, latch byte [7FF4] = 0 and [7FEF] = 0 BY CONSTRUCTION.
check_latch    (third-reader repair) the 0x0410D4 latch in the task, REAL and STOCK: one call with byte
               [69E6] = 0 at X = 0 sets [7FF4] and X stays 0.0 for 200 calls with every up condition met;
               from X = 1.0 with [69E6] = 0, -0.015 per call to +0.0, then latched.
check_window_b (third-reader repair) byte [7FDC] from 0x040A9C window B in the task: 20.19c ([0x0D29C4] =
               438) holds or steps down X where stock ([0x0D29C4] = 0) climbs or holds H.
check_writers  (third-reader repair) 0x026634 and 0x026698, the writers of byte [69E6]; 0x0409C0, the
               second writer of [7FED] / [7FE6] / [7FF0] and the writer of [7FEF] / [7FEA] -- exact cells,
               read sets and write sets.
check_context  0x0297D0 / 0x029A64 (all 256 bytes); 0x06114E (writer of byte 0xFFFF90BE); 0x0610E6 and
               0x06081C (writers of byte 0xFFFF90C4); 0x02F57E, 0x02F768, 0x02EE78 (writers of the u16
               pair 0xFFFF3158 whose high byte 0x040AF6 reads); 0x04004A (which side of the definition-
               named Cruise / Non-Cruise timing blend the weight 0xFFFF90A8, driven by [90BE], selects);
               0x04092A (the initialiser, the other writer of [7FD4] that find_writers reports -- a lower
               bound); 0x03A5E4 (a consumer that puts
               [0xFFFF6354] on the definition axis "Coolant Temperature").

ROUNDING: every fadd / fsub / fmul / fmac in the models is the exact result rounded TOWARD ZERO, written
independently of the emulator (only sh2e_emu.rz_bits is shared). No assertion depends on the rounding
mode except bit equality of model and emulator, which both compute under the same assumption.

Names here are neutral on purpose: nothing in this file establishes what any RAM cell physically is.
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
import desc_types as DT       # noqa: E402

BIN = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
STOCK_BIN = os.path.join(REPO, 'rom', 'ae5l600l.bin')
REAL = open(BIN, 'rb').read()
STOCK = open(STOCK_BIN, 'rb').read()
assert hashlib.md5(REAL).hexdigest() == '92cae8275cd4f9b473a3a9e36efe6449', 'wrong reference bin'

f2b, b2f = E.f2b, E.b2f
U32 = lambda img, a: struct.unpack_from('>I', img, a)[0]          # noqa: E731
U16 = lambda img, a: struct.unpack_from('>H', img, a)[0]          # noqa: E731
ONE, ZERO, NZERO = 0x3F800000, 0x00000000, 0x80000000
NAN, INF, NINF = 0x7FC00000, 0x7F800000, 0xFF800000

# ------------------------------------------------------------------ addresses (resolved from the pools)
FN, FN_H, FN_CHAIN = 0x040AF6, 0x041030, 0x040918
FN_LUT1, FN_LAG, FN_MAX = 0x0BE830, 0x0BEA40, 0x0BE960

A_E, A_N, A_Q, A_C = 0xFFFF6354, 0xFFFF6624, 0xFFFF6898, 0xFFFF67EC     # fr12, fr14, @r15, word -> r7
A_M, A_S, A_U, A_G = 0xFFFF8970, 0xFFFF90BE, 0xFFFF8E7E, 0xFFFF3158     # bytes -> r8, r14 (r11), r9 (r10), r12
A_P, A_D, A_F, A_V = 0xFFFF6210, 0xFFFF9707, 0xFFFF85D7, 0xFFFF65FC     # fr13, byte via 0x0297D0, byte, fr15
O = dict(B0=0xFFFF7FB0, B4=0xFFFF7FB4, B8=0xFFFF7FB8, C4=0xFFFF7FC4, C8=0xFFFF7FC8, CC=0xFFFF7FCC,
         D0=0xFFFF7FD0, D4=0xFFFF7FD4)                                  # floats, r13/r14 = 0xFFFF7FFC + disp
W = dict(E4=0xFFFF7FE4, E6=0xFFFF7FE6, F8=0xFFFF7FF8, FC=0xFFFF7FFC)    # words, gbr+52 / 54 / 72 / 76
B = dict(EC=0xFFFF7FEC, ED=0xFFFF7FED, F0=0xFFFF7FF0, F6=0xFFFF7FF6, FA=0xFFFF7FFA, FB=0xFFFF7FFB,
         FE=0xFFFF7FFE, FF=0xFFFF7FFF)                                  # bytes, gbr+60 61 64 70 74 75 78 79

C_G90 = 0x0D297C                                   # byte, compared with #90 at 0x040B60
C_BC, C_BE, C_C0, C_C6 = 0x0D29BC, 0x0D29BE, 0x0D29C0, 0x0D29C6         # u16
K84, K88, K8C, K90 = 0x0D2B84, 0x0D2B88, 0x0D2B8C, 0x0D2B90             # lag weights for [7FB0]
C_DC, C_E0, C_E4, C_E8, C_EC = 0x0D2BDC, 0x0D2BE0, 0x0D2BE4, 0x0D2BE8, 0x0D2BEC
P_EPS1, P_EPS2, P_EPS3 = 0x041078, 0x0410AC, 0x0410BC                   # mova pool words

T_FIRST = 0x0ADC3C
T16 = {  # (C >= [0D29BC], byte [90BE] == 1, byte [8E7E] == 1, byte [8970] in {4,7,8}) -> record
    (0, 1, 1, 1): 0x0ADC50, (0, 1, 1, 0): 0x0ADC64, (0, 1, 0, 1): 0x0ADC78, (0, 1, 0, 0): 0x0ADC8C,
    (0, 0, 1, 1): 0x0ADCA0, (0, 0, 1, 0): 0x0ADCB4, (0, 0, 0, 1): 0x0ADCC8, (0, 0, 0, 0): 0x0ADCDC,
    (1, 1, 1, 1): 0x0ADCF0, (1, 1, 1, 0): 0x0ADD04, (1, 1, 0, 1): 0x0ADD18, (1, 1, 0, 0): 0x0ADD2C,
    (1, 0, 1, 1): 0x0ADD40, (1, 0, 1, 0): 0x0ADD54, (1, 0, 0, 1): 0x0ADD68, (1, 0, 0, 0): 0x0ADD7C}
T_B8_A, T_B8_B, T_C4, T_D0 = 0x0ADD90, 0x0ADDA4, 0x0ADDB8, 0x0ADDCC
ALL_T = [T_FIRST] + sorted(T16.values()) + [T_B8_A, T_B8_B, T_C4, T_D0]
assert len(ALL_T) == 21
MSET = (4, 7, 8)


# ------------------------------------------------------------------ exact round-toward-zero arithmetic
def _rz_store(exact, fallback):
    if not math.isfinite(fallback) or fallback == 0.0:
        q = exact() if math.isfinite(fallback) else None
        if q is None or q == 0:
            return f2b(fallback)
        return E.rz_bits(q)
    q = exact()
    return E.rz_bits(q) if q != 0 else f2b(fallback)


def rz(op, xb, yb):
    x, y = b2f(xb), b2f(yb)
    f = {'+': lambda a, b: a + b, '-': lambda a, b: a - b, '*': lambda a, b: a * b}[op]
    if not (math.isfinite(x) and math.isfinite(y)):
        return f2b(f(x, y))
    return _rz_store(lambda: f(Fraction(x), Fraction(y)), f(x, y))


def rz_fmac(f0b, fmb, fnb):
    """fmac fr0,frm,frn: frn = fr0 * frm + frn, one rounding (toward zero)."""
    a, m, n = b2f(f0b), b2f(fmb), b2f(fnb)
    if not (math.isfinite(a) and math.isfinite(m) and math.isfinite(n)):
        return f2b(a * m + n)
    return _rz_store(lambda: Fraction(a) * Fraction(m) + Fraction(n), a * m + n)


def gt(ab, bb):
    """fcmp/gt FRm,FRn: T = (FRn > FRm), false if either is NaN. Here gt(n, m)."""
    return b2f(ab) > b2f(bb)


def lag(Ab, Bb, kb, eb):
    """0x0BEA40 contract (helpers_wrap trace): A if B is non-finite; A if eps > |A - r|; else r,
    r = A + (1 - k) * (B - A) with one fused rounding."""
    if (Bb & 0x7F800000) == 0x7F800000:
        return Ab
    d = rz('-', Bb, Ab)
    c = rz('-', ONE, kb)
    r = rz_fmac(c, d, Ab)
    e = rz('-', Ab, r) & 0x7FFFFFFF
    return Ab if gt(eb, e) else r


def max0(tb):
    """0x0BE960(fr4 = t, fr5 = +0.0): t if t > +0.0 else +0.0 (NaN -> +0.0)."""
    return tb if gt(tb, ZERO) else ZERO


# ------------------------------------------------------------------ images
def make_uniq(g90, salt, eps_change):
    img = bytearray(REAL)
    for k, d in enumerate(ALL_T):
        n, dp = U16(img, d), U32(img, d + 8)
        assert img[d + 2] == 0x04 and img[d + 3] == 0, hex(d)
        for i in range(n):
            img[dp + i] = (7 + salt + 11 * k + 3 * i) % 250 + 3
    img[C_G90] = g90
    for a, v in ((C_BC, 1000 + salt), (C_BE, 5 + salt % 3), (C_C0, 7 + salt % 2), (C_C6, 2000 + salt)):
        struct.pack_into('>H', img, a, v)
    for a, v in ((K84, 0.25), (K88, 0.375), (K8C, 0.625), (K90, 0.8125), (C_DC, -150.5), (C_E0, 0.5),
                 (C_E4, 30.0), (C_E8, 0.125), (C_EC, 120.0)):
        struct.pack_into('>f', img, a, v + salt / 64.0)
    if eps_change:
        for a, v in ((P_EPS1, 0.75), (P_EPS2, 0.0625), (P_EPS3, 0.03125)):
            struct.pack_into('>f', img, a, v)
    return bytes(img)


UNIQ1 = make_uniq(90, 0, False)
UNIQ2 = make_uniq(91, 9, True)
IMAGES = {'REAL': REAL, 'STOCK': STOCK, 'UNIQ1': UNIQ1, 'UNIQ2': UNIQ2}


class Luts:
    """ROM lookup 0x0BE830 as an oracle, per image (its contract is verified, helpers_wrap trace)."""
    def __init__(self, img):
        self.e = E.Emu(img)
        self.cache = {}

    def l1(self, d, xb):
        k = (d, xb)
        if k not in self.cache:
            self.e.steps = 0
            self.e.FR[4] = xb
            assert self.e.call(FN_LUT1, regs={4: d}) == 'return'
            self.cache[k] = self.e.FR[0]
        return self.cache[k]


LUTS = {id(img): Luts(img) for img in IMAGES.values()}


# ================================================================== model of 0x040AF6
def model(img, c):
    """c: input dict. Returns (out, reads, writes, path)."""
    L = LUTS[id(img)]
    cf = lambda a: U32(img, a)                                   # noqa: E731
    reads = {A_E, A_N, A_Q, A_C, A_M, A_S, A_U, A_G, A_P, A_D, A_F, A_V, B['F0']}
    writes = set()
    out = {}
    for k in O:
        out[O[k]] = c['o' + k]
    for k in W:
        out[W[k]] = c['w' + k]
    for k in B:
        out[B[k]] = c['b' + k]

    def wr(a, n, v):
        out[a] = v
        writes.update(a + i for i in range(n))

    def rd(a):
        """read a cell that may have been written earlier in this call"""
        if a not in writes:
            reads.add(a)
        return out[a]

    C, M, S, U, G = c['C'], c['M'], c['S'], c['U'], c['G']
    callee = 2 if c['D'] != 0 else 0                               # 0x0297D0
    mset = M in MSET
    # 1. [7FB4]: one of 17 flat-or-not 1-D records at [6624]          0x040B54..0x040D6C
    if img[C_G90] == 90 and G == 1:
        rec = T_FIRST
    else:
        rec = T16[(int(C >= U16(img, C_BC)), int(S == 1), int(U == 1), int(mset))]
    wr(O['B4'], 4, L.l1(rec, c['N']))
    path = [f'{rec:06X}']
    # 2. falling edge of byte [90BE]: arm byte [7FFA], zero word [7FF8]     0x040D68..0x040D7A
    if S == 0:
        if rd(B['FB']) == 1:
            wr(B['FA'], 1, 1)
            wr(W['F8'], 2, 0)
    wr(W['F8'], 2, min(rd(W['F8']) + 1, 0xFFFF))                   # 0x040D7C..0x040D86
    r14 = 1 if (rd(B['FA']) == 1 and out[W['F8']] <= U16(img, C_BE)) else 0
    wr(B['FB'], 1, S)                                              # 0x040D9E..0x040DA0
    # 3. word [7FE4] counts while C >= [0D29BC]; byte [7FEC] = that test   0x040DA2..0x040E14
    if C >= U16(img, C_BC):
        wr(W['E4'], 2, min(rd(W['E4']) + 1, 0xFFFF))
        wr(B['EC'], 1, 1)
    else:
        wr(W['E4'], 2, 0)
        wr(B['EC'], 1, 0)
    # 4. byte [7FED] := 1, word [7FE6] := 0 when [7FF0] not in set and [8970] in set   0x040E16..0x040E40
    if c['bF0'] not in MSET and mset:
        wr(B['ED'], 1, 1)
        wr(W['E6'], 2, 0)
    # 5. falling edge of byte [8E7E]: arm byte [7FFE], zero word [7FFC]     0x040E42..0x040E52
    if U == 0:
        if rd(B['FF']) == 1:
            wr(B['FE'], 1, 1)
            wr(W['FC'], 2, 0)
    wr(W['FC'], 2, min(rd(W['FC']) + 1, 0xFFFF))
    r4 = 1 if (rd(B['FE']) == 1 and out[W['FC']] <= U16(img, C_BE)) else 0
    wr(B['FF'], 1, U)
    # 6. [7FB0]: a lag toward [7FB4] with one of four weights, or a copy      0x040E78..0x040F22
    eps1 = cf(P_EPS1)
    k = None
    if out[B['EC']] == 1 and out[W['E4']] <= U16(img, C_BE):
        k = K88
    elif r14 == 1:
        k = K84
    elif rd(B['ED']) == 1 and rd(W['E6']) <= U16(img, C_C0):
        k = K8C
    elif r4 == 1:
        k = K90
    if k is None:
        wr(O['B0'], 4, out[O['B4']])
        path.append('copy')
    else:
        wr(O['B0'], 4, lag(out[O['B4']], rd(O['B0']), cf(k), eps1))
        path.append(f'lag{k:06X}')
    # 7. [7FB8], [7FC4], [7FC8], latch byte [7FF6]                          0x040F24..0x040F62
    wr(O['B8'], 4, L.l1(T_B8_B if mset else T_B8_A, c['E']))
    wr(O['C4'], 4, L.l1(T_C4, c['Q']))
    wr(O['C8'], 4, rz('-', c['P'], cf(C_DC)))
    if not gt(cf(C_EC), c['V']):
        wr(B['F6'], 1, 1)
    # 8. [7FCC], [7FD0], [7FD4]                                              0x040F64..0x041010
    if callee == 2:
        wr(O['D0'], 4, ZERO)
        wr(O['D4'], 4, lag(ZERO, rd(O['D4']), cf(C_E8), cf(P_EPS3)))
        path.append('D')
    elif C >= U16(img, C_C6) and c['F'] == 1 and rd(B['F6']) == 1:
        if gt(out[O['C8']], cf(C_E4)):
            wr(O['CC'], 4, out[O['C8']])
            path.append('gate_copy')
        else:
            wr(O['CC'], 4, max0(lag(out[O['C8']], rd(O['CC']), cf(C_E0), cf(P_EPS2))))
            path.append('gate_lag')
        wr(O['D0'], 4, L.l1(T_D0, out[O['CC']]))
        wr(O['D4'], 4, lag(out[O['D0']], rd(O['D4']), cf(C_E8), cf(P_EPS3)))
    else:
        wr(O['CC'], 4, out[O['C8']])
        wr(O['D0'], 4, L.l1(T_D0, out[O['CC']]))
        wr(O['D4'], 4, ONE)
        path.append('else')
    return out, reads, writes, '/'.join(path)


# ------------------------------------------------------------------ running one case
SENT = {8: 0x08080808, 9: 0x09090909, 10: 0x0A0A0A0A, 11: 0x0B0B0B0B, 12: 0x0C0C0C0C,
        13: 0x0D0D0D0D, 14: 0x0E0E0E0E}
FSENT = {12: 0x41C80000, 13: 0xC1C80000, 14: 0x42F60000, 15: 0xC2F60000}
GBR_SENT = 0xFFFF1234
EMUS = {id(img): E.Emu(img) for img in IMAGES.values()}
_rng = random.Random(0x040AF6)


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


def load_inputs(e, c):
    for a, k in ((A_E, 'E'), (A_N, 'N'), (A_Q, 'Q'), (A_P, 'P'), (A_V, 'V')):
        poke(e, a, 4, c[k])
    poke(e, A_C, 2, c['C'])
    for a, k in ((A_M, 'M'), (A_S, 'S'), (A_U, 'U'), (A_G, 'G'), (A_D, 'D'), (A_F, 'F')):
        poke(e, a, 1, c[k])
    for k in O:
        poke(e, O[k], 4, c['o' + k])
    for k in W:
        poke(e, W[k], 2, c['w' + k])
    for k in B:
        poke(e, B[k], 1, c['b' + k])


def read_outputs(e):
    got = {}
    for a in O.values():
        got[a] = peek(e, a, 4)
    for a in W.values():
        got[a] = peek(e, a, 2)
    for a in B.values():
        got[a] = peek(e, a, 1)
    return got


def run(img, c):
    e = EMUS[id(img)]
    fresh(e)
    load_inputs(e, c)
    tag = ' '.join(f'{k}={v:#x}' for k, v in c.items())
    call_checked(e, FN, (8, 9, 10, 11, 12, 13, 14), tag)
    got = read_outputs(e)
    want, reads, writes, path = model(img, c)
    assert got == want, (f'OUTPUT MISMATCH {tag}\n got  {[(hex(a), hex(v)) for a, v in got.items()]}'
                         f'\n want {[(hex(a), hex(v)) for a, v in want.items()]}')
    assert set(e.writes) == writes, (f'WRITE-SET MISMATCH {tag}\n got  {sorted(map(hex, e.writes))}'
                                     f'\n want {sorted(map(hex, writes))}')
    assert e.uninit_reads == reads, (f'READ-SET MISMATCH {tag}\n got  {sorted(map(hex, e.uninit_reads))}'
                                     f'\n want {sorted(map(hex, reads))}')
    return e, got, path


def base_case(**kw):
    c = dict(E=f2b(90.0), N=f2b(2000.0), Q=f2b(600.0), P=f2b(30.0), V=f2b(60.0), C=0, M=0, S=0, U=0, G=0,
             D=0, F=0, oB0=f2b(3.0), oB4=0x11111111, oB8=0x22222222, oC4=0x33333333, oC8=0x44444444,
             oCC=f2b(5.0), oD0=0x55555555, oD4=f2b(0.5), wE4=0, wE6=0, wF8=0x1234, wFC=0x2345,
             bEC=0x99, bED=0, bF0=0, bF6=0, bFA=0, bFB=0, bFE=0, bFF=0)
    c.update(kw)
    return c


def thr_vals(t):
    return sorted({0, max(t - 1, 0), t, min(t + 1, 0xFFFF), 0xFFFE, 0xFFFF})


def random_state(img, rng):
    be, c0 = U16(img, C_BE), U16(img, C_C0)
    ec = b2f(U32(img, C_EC))
    e4 = b2f(U32(img, C_E4))
    dc = b2f(U32(img, C_DC))
    floats = [0.0, 1.5, -3.0, 100.0, float('nan'), float('inf')]
    return dict(
        bFB=rng.choice([0, 1, 2]), bFA=rng.choice([0, 1, 2]), wF8=rng.choice(thr_vals(be)),
        wE4=rng.choice(thr_vals(be)), bF0=rng.choice([0, 4, 7, 8, 5, 0x84]), bED=rng.choice([0, 1, 2]),
        wE6=rng.choice(thr_vals(c0)), bFF=rng.choice([0, 1, 2]), bFE=rng.choice([0, 1, 2]),
        wFC=rng.choice(thr_vals(be)), bF6=rng.choice([0, 1, 2]), bEC=rng.choice([0, 1, 0x77]),
        D=rng.choice([0, 0, 1, 0x80]), F=rng.choice([0, 1, 1, 2]),
        E=f2b(rng.choice([-50.0, -40.0, 15.0, 30.0, 35.0, 40.0, 45.0, 70.0, 110.0, 130.0, float('nan')])),
        N=f2b(rng.choice([0.0, 800.0, 1000.0, 1200.0, 5000.0, float('nan')])),
        Q=f2b(rng.choice([0.0, 440.0, 600.0, 760.0, 900.0, float('nan')])),
        P=f2b(rng.choice([-200.0, -10.0, 0.0, 25.0, 100.0, e4 + dc, e4 + dc + 1.0, e4 + dc - 1.0,
                          float('nan')])),
        V=f2b(rng.choice([0.0, ec - 1.0, ec, ec + 1.0, float('nan'), float('inf'), float('-inf')])),
        oB0=f2b(rng.choice(floats)), oCC=f2b(rng.choice(floats)), oD4=f2b(rng.choice(floats)),
        oB4=rng.getrandbits(32), oB8=rng.getrandbits(32), oC4=rng.getrandbits(32), oC8=rng.getrandbits(32),
        oD0=rng.getrandbits(32))


STATS = {}


def note(key, path):
    STATS.setdefault(key, {})
    STATS[key][path] = STATS[key].get(path, 0) + 1


# ================================================================== checks
def check_main():
    total = 0
    for name, img in IMAGES.items():
        rng = random.Random({'REAL': 11, 'STOCK': 13, 'UNIQ1': 17, 'UNIQ2': 19}[name] * 7919)
        bc = U16(img, C_BC)
        Cs = sorted({0, max(bc - 1, 0), bc, 0xFFFF})
        n = 0
        for S in (0, 1, 2):
            for U in (0, 1, 2):
                for M in (0, 4, 7, 8, 3):
                    for G in (0, 1, 2):
                        for C in Cs:
                            for rep in range(2):
                                c = base_case(S=S, U=U, M=M, G=G, C=C)
                                c.update(random_state(img, rng))
                                e, got, path = run(img, c)
                                note(name, path.split('/', 1)[1])
                                n += 1
        # focused edges: counters / windows (deterministic grid)
        be, c0, c6 = U16(img, C_BE), U16(img, C_C0), U16(img, C_C6)
        for fb in (0, 1, 2):
            for fa in (0, 1, 2):
                for f8 in thr_vals(be):
                    c = base_case(S=0, bFB=fb, bFA=fa, wF8=f8, U=1, bFE=0)
                    run(img, c)
                    c = base_case(S=1, U=0, bFF=fb, bFE=fa, wFC=f8, bFA=0)
                    run(img, c)
                    n += 2
        for e6 in thr_vals(c0):
            for ed in (0, 1, 2):
                for f0 in (0, 4, 7, 8, 5):
                    for M in (0, 4):
                        run(img, base_case(bED=ed, wE6=e6, bF0=f0, M=M, bFA=0, bFE=0, U=1, S=1))
                        n += 1
        for C in thr_vals(c6) + [U16(img, C_BC)]:
            for e4 in thr_vals(be):
                for F in (0, 1, 2):
                    for f6 in (0, 1, 2):
                        for P in (-500.0, 0.0, 10.0, b2f(U32(img, C_E4)) + b2f(U32(img, C_DC)), float('nan')):
                            for occ in (0.0, -7.0, 50.0, float('nan'), float('inf')):
                                c = base_case(C=C, wE4=e4, F=F, bF6=f6, P=f2b(P), oCC=f2b(occ), U=1, S=1)
                                _, _, path = run(img, c)
                                note(name + '-gate', path.rsplit('/', 1)[1])
                                n += 1
        for V in (0.0, b2f(U32(img, C_EC)) - 1.0, b2f(U32(img, C_EC)), b2f(U32(img, C_EC)) + 1.0,
                  float('nan'), float('inf'), float('-inf')):
            for f6 in (0, 1):
                run(img, base_case(V=f2b(V), bF6=f6, U=1, S=1))
                n += 1
        for D in range(256):
            run(img, base_case(D=D, U=1, S=1, oD4=f2b(0.25)))
            n += 1
        print(f'  check_main {name:6s}: {n} whole-function runs, bit-exact, read and write sets exact')
        total += n
    for k in ('REAL', 'UNIQ1', 'UNIQ2', 'UNIQ1-gate', 'UNIQ2-gate', 'REAL-gate'):
        print(f'    paths {k:11s}', dict(sorted(STATS.get(k, {}).items())))
    for k in ('UNIQ1', 'UNIQ2'):
        seen = set(STATS[k])
        for need in ('copy', f'lag{K84:06X}', f'lag{K88:06X}', f'lag{K8C:06X}', f'lag{K90:06X}'):
            assert any(p.startswith(need) for p in seen), (k, need)
        for need in ('gate_copy', 'gate_lag', 'else', 'D'):
            assert any(p.endswith(need) for p in seen) or need in STATS[k + '-gate'], (k, need)
    for k in ('REAL', 'STOCK'):
        # u16 [0x0D29BE] = 0: the counters are >= 1 after their increment, so the K88 / K84 / K90 arms
        # can never be taken with the shipped calibration (K8C can, with [7FE6] == 0)
        for kk in (K84, K88, K90):
            assert all(not p.startswith(f'lag{kk:06X}') for p in STATS[k]), (k, hex(kk))
    return total


def interp_ref(img, d, x):
    t = DT.read_table(img, d)
    ax, v = t['axes']['x'], t['values']
    if x != x or x >= ax[-1]:
        return v[-1]
    if x < ax[0]:
        return v[0]
    for i in range(len(ax) - 1):
        if ax[i] <= x < ax[i + 1]:
            f = (x - ax[i]) / (ax[i + 1] - ax[i])
            return v[i] + f * (v[i + 1] - v[i])
    raise AssertionError


def check_tables():
    rows = []
    for img_name, img in (('REAL', REAL), ('STOCK', STOCK)):
        L = LUTS[id(img)]
        for d in ALL_T:
            assert U16(img, d) in (2, 6, 7, 16) and img[d + 2] == 0x04 and img[d + 3] == 0
            t = DT.read_table(img, d)
            assert t['typecode'] == 0x04 and t['fixed'] is None
            ax = t['axes']['x']
            xs = ([ax[0] - 100, ax[0], ax[-1], ax[-1] + 100, float('nan'), float('inf'), float('-inf')] +
                  [(ax[i] + ax[i + 1]) / 2 for i in range(len(ax) - 1)] + list(ax))
            for x in xs:
                got = b2f(L.l1(d, f2b(x)))
                want = interp_ref(img, d, x)
                assert abs(got - want) <= 1e-5 * max(1.0, abs(want)), (img_name, hex(d), x, got, want)
            if len(set(t['values'])) == 1:
                vals = {L.l1(d, f2b(x)) for x in xs}
                assert len(vals) == 1, (hex(d), vals)
            if img_name == 'REAL':
                rows.append((d, t))
    # the two bins are byte-identical in everything 0x040AF6 reads
    for d in ALL_T:
        n, ap, dp = U16(REAL, d), U32(REAL, d + 4), U32(REAL, d + 8)
        assert REAL[d:d + 20] == STOCK[d:d + 20]
        assert REAL[ap:ap + 4 * n] == STOCK[ap:ap + 4 * n] and REAL[dp:dp + n] == STOCK[dp:dp + n]
    for a, n in ((C_G90, 1), (C_BC, 2), (C_BE, 2), (C_C0, 2), (C_C6, 2), (K84, 16), (C_DC, 20),
                 (0x040AF6, 0x0410C4 - 0x040AF6)):
        assert REAL[a:a + n] == STOCK[a:a + n], hex(a)
    # explicit values (20.19c == stock)
    v = {d: DT.read_table(REAL, d)['values'] for d in ALL_T}
    hi = 57 * 0.3515625
    assert hi == 20.0390625
    for d in (T_FIRST, 0x0ADC50, 0x0ADC64, 0x0ADC78, 0x0ADC8C, 0x0ADCF0, 0x0ADD04, 0x0ADD18, 0x0ADD2C):
        assert v[d] == [hi, hi], hex(d)
    for d in (0x0ADCA0, 0x0ADCB4, 0x0ADCC8, 0x0ADCDC, 0x0ADD40, 0x0ADD54, 0x0ADD68, 0x0ADD7C):
        assert v[d] == [0.0, 0.0], hex(d)
    want8 = [100.0] * 8 + [115 * 0.78125, 109 * 0.78125, 102 * 0.78125] + [75.0] * 5
    assert v[T_B8_A] == want8 and v[T_B8_B] == want8
    assert REAL[0x0D338A:0x0D339A] == REAL[0x0D339A:0x0D33AA]
    assert v[T_C4] == [1.0] * 6 and v[T_D0] == [1.0] * 7
    assert DT.read_table(REAL, T_B8_A)['axes']['x'] == [-40.0 + 10 * i for i in range(16)]
    assert U32(REAL, T_B8_A + 4) == U32(REAL, T_B8_B + 4) == 0x0D2FCC
    assert DT.read_table(REAL, T_C4)['axes']['x'] == [440.0, 504.0, 568.0, 632.0, 696.0, 760.0]
    assert DT.read_table(REAL, T_D0)['axes']['x'] == [0.0, 5.0, 10.0, 15.0, 20.0, 25.0, 30.0]
    for d in [T_FIRST] + list(T16.values()):
        assert DT.read_table(REAL, d)['axes']['x'] == [800.0, 1200.0]
    cal = {C_G90: REAL[C_G90], C_BC: U16(REAL, C_BC), C_BE: U16(REAL, C_BE), C_C0: U16(REAL, C_C0),
           C_C6: U16(REAL, C_C6)}
    assert cal == {C_G90: 90, C_BC: 0xFFFF, C_BE: 0, C_C0: 0, C_C6: 0xFFFF}, cal
    fl = {a: b2f(U32(REAL, a)) for a in (K84, K88, K8C, K90, C_DC, C_E0, C_E4, C_E8, C_EC)}
    assert fl == {K84: 1.0, K88: 1.0, K8C: 1.0, K90: 1.0, C_DC: -160.0, C_E0: 1.0, C_E4: -1000.0,
                  C_E8: 1.0, C_EC: 1000.0}, fl
    assert (U32(REAL, P_EPS1), U32(REAL, P_EPS2), U32(REAL, P_EPS3)) == (0x3AB40000, 0x3A83126E, 0x3A000000)
    assert b2f(U32(REAL, 0x0D2B9C)) == 0.0 and U32(REAL, 0x0410CC) == 0x3C23D70A
    # definitions (scripts/defs.py, joined on the DATA pointer; axes on the axis pointer)
    import defs as DF
    dd = DF.load()
    for d in ALL_T:
        assert dd.at(U32(REAL, d + 8), include_axes=True) == [], hex(d)
        assert dd.at(U32(REAL, d + 4), include_axes=True) == [], hex(d)
    for a in (C_G90, C_BC, C_BE, C_C0, C_C6, K84, K88, K8C, K90, C_DC, C_E0, C_E4, C_E8, C_EC):
        assert dd.at(a, include_axes=True) == [], hex(a)
    nm = lambda p: [t.name for t in dd.at(p)]                                  # noqa: E731
    assert nm(0x0D4714) == ['Base Timing Primary Cruise'] and nm(0x0D48D4) == ['Base Timing Primary Non-Cruise']
    assert nm(0x0D4A94) == ['Base Timing Reference Cruise (AVCS related)']
    assert nm(0x0D4C54) == ['Base Timing Reference Non-Cruise (AVCS related)']
    assert [U32(REAL, r + 12) for r in (0x0AE31C, 0x0AE338, 0x0AE354, 0x0AE370)] == [0x0D4714, 0x0D48D4,
                                                                                      0x0D4A94, 0x0D4C54]
    assert nm(0x0CEE40) == ['Tip-in Enrichment Compensation D (ECT)']
    assert {a.name for a in dd.at(0x0CC664, include_axes=True)} == {'Coolant Temperature'}
    print('  definitions: no data or axis pointer of the 21 records and no scalar read is named; 0x04004A tables')
    print('    and the 0x0CC664 "Coolant Temperature" axis (record 0x0AD3C4) named as stated in the trace')
    print('  check_tables: 21 records decoded, equal in 20.19c and stock; ROM lookup = read_table + linear')
    print('    interpolation on', 21 * 2, 'record/bin pairs; flat tables single-valued incl. NaN / +-inf')
    for d, t in rows:
        print(f'    {d:06X} n={len(t["values"]):2d} axis {U32(REAL, d + 4):06X} data {U32(REAL, d + 8):06X} '
              f'x={t["axes"]["x"][0]:g}..{t["axes"]["x"][-1]:g} values {sorted(set(t["values"]))}')


def check_real():
    """Bottom-line facts on the shipped calibration, explicit bits, plus H from 0x041030."""
    n = 0
    hi = f2b(20.0390625)
    for name, img in (('REAL', REAL), ('STOCK', STOCK)):
        rng = random.Random(4242 + len(name))
        L = LUTS[id(img)]
        for S in (0, 1, 2, 0x81):
            for G in (0, 1, 2, 0x81):
                for D in (0, 1, 0x80):
                    for M in (0, 4, 7, 8, 5):
                        for f67 in (0, 1, 2):
                            for rep in range(3):
                                c = base_case(S=S, G=G, D=D, M=M, U=rng.choice([0, 1, 2]),
                                              C=rng.choice([0, 1, 0xFFFE, 0xFFFF]))
                                st = random_state(img, rng)
                                for k in ('D',):
                                    st.pop(k)
                                c.update(st)
                                e, got, _ = run(img, c)
                                assert got[O['B0']] == got[O['B4']], 'B0 != B4'
                                assert got[O['B4']] == (hi if (S == 1 or G == 1) else ZERO)
                                assert got[O['C4']] == ONE
                                assert got[O['D0']] == (ZERO if D else ONE)
                                assert got[O['D4']] == (ZERO if D else ONE)
                                xe = b2f(c['E'])
                                b8 = got[O['B8']]
                                assert b8 == L.l1(T_B8_A, c['E']) == L.l1(T_B8_B, c['E'])
                                if xe != xe or xe >= 70.0:
                                    assert b8 == f2b(75.0)
                                if xe <= 30.0:
                                    assert b8 == f2b(100.0)
                                # 0x041030 right after, same machine: H = [7FB8]*[7FB0]*[7FC4]*[7FD4]*0.01
                                poke(e, 0xFFFF67FC, 1, f67)
                                e.steps = 0
                                assert e.call(FN_H) == 'return'
                                h = peek(e, 0xFFFF7FC0, 4)
                                p = rz('*', rz('*', rz('*', rz('*', b8, got[O['B0']]), ONE), got[O['D4']]),
                                       0x3C23D70A)
                                if f67 == 1:
                                    p = rz('*', p, ZERO)
                                assert h == p, (hex(h), hex(p))
                                live = (S == 1 or G == 1) and D == 0 and f67 != 1
                                if live:
                                    assert 15.0 < b2f(h) <= 20.0390625, b2f(h)
                                else:
                                    assert b2f(h) == 0.0, b2f(h)
                                n += 1
    # the H range on the live condition, over the [6354] axis
    hs = []
    for x in [-40.0 + 5 * i for i in range(33)]:
        b8 = LUTS[id(REAL)].l1(T_B8_A, f2b(x))
        hs.append((x, b2f(rz('*', rz('*', rz('*', rz('*', b8, hi), ONE), ONE), 0x3C23D70A))))
    print(f'  check_real: {n} runs on REAL + STOCK (0x040AF6 then 0x041030): [7FB0] == [7FB4]; [7FB4] = 20.0390625')
    print('    iff byte [3158] == 1 or byte [90BE] == 1; [7FC4] = 1; [7FD4] = 0 iff byte [9707] != 0 else 1;')
    print('    H = 0 unless ([3158]==1 or [90BE]==1) and [9707]==0 and [67FC]!=1; then 15.0 < H <= 20.04')
    print('    H on the live condition vs [6354]:', ' '.join(f'{x:g}:{h:.4f}' for x, h in hs if x % 10 == 0))
    return n


A_F9, A_LATCH, A_F10, A_7FDC = 0xFFFF69E6, 0xFFFF7FF4, 0xFFFF65C0, 0xFFFF7FDC   # read by 0x0410D4
A_7FEF, A_7FEA = 0xFFFF7FEF, 0xFFFF7FEA                                          # read by 0x040A9C


class Chain:
    """Task 0x040918 (0x040A9C, 0x040AF6, 0x041030, then 0x0410D4) iterated on one image. RAM is zeroed,
    then the inputs below are set. Defaults: the 0x0410D4 branch-12 first-arm up conditions (timing
    trace) with byte [69E6] = 1, latch byte [7FF4] = 0, byte [65C0] = 0 and window B of 0x040A9C shut
    ([7FEF] = 0)."""
    def __init__(self, img):
        self.e = E.Emu(img)

    def setup(self, S, G, D, f67, E_=90.0, F9=1, X0=0.0, F10=0, b7FEF=0, w7FEA=0, latch=0):
        e = self.e
        e.ram = bytearray(len(e.ram))
        e.init = bytearray(len(e.init))
        e.writes.clear()
        e.uninit_reads.clear()
        vals_f = {A_E: E_, A_N: 2000.0, A_Q: 600.0, A_P: 30.0, A_V: 60.0,      # V < 510 (0x0410D4 step 5)
                  0xFFFF895C: 800.0, 0xFFFF6634: 10.0, 0xFFFF7EE4: 100.0,       # T, P, Y
                  0xFFFF7E9C: 200.0, 0xFFFF7E98: 200.0, 0xFFFF7E94: 200.0, 0xFFFF7E90: 200.0,
                  0xFFFF7FBC: X0}
        for a, v in vals_f.items():
            e.ram_f32(a, v)
        e.ram_u16(A_C, 100)                       # 0 <= C < 375 (0x0410D4 branch 12 first arm)
        e.ram_u16(A_7FEA, w7FEA)
        for a, v in {A_S: S, A_G: G, A_D: D, A_F: 1, A_M: 0, A_U: 0, 0xFFFF67FC: f67,
                     A_F10: F10, A_F9: F9, 0xFFFF726C: 0, A_LATCH: latch, 0xFFFF7FEE: 0,
                     A_7FEF: b7FEF, 0xFFFF65C5: 0}.items():
            e.ram_u8(a, v)

    def go(self, n, track=None):
        e = self.e
        xs, tr = [], []
        for _ in range(n):
            e.steps = 0
            e.R[15] = E.STACK_TOP
            assert e.call(FN_CHAIN) == 'return'
            xs.append(b2f(e.read(0xFFFF7FBC, 4)))
            if track is not None:
                tr.append(e.read(track, 1))
        if track is not None:
            return xs, b2f(e.read(0xFFFF7FC0, 4)), tr
        return xs, b2f(e.read(0xFFFF7FC0, 4))

    def u8(self, a):
        return self.e.read(a, 1)


def check_chain():
    """0x040918 iterated: the integrator [7FBC] against the bound, end to end through the ROM."""
    ch = Chain(REAL)
    e, setup, go = ch.e, ch.setup, ch.go

    setup(S=1, G=0, D=0, f67=0)
    xs, h = go(110)
    assert abs(h - 75 * 20.0390625 * 0.01) < 1e-4 and xs[0] > 0.0 and xs[-1] == h, (h, xs[:3], xs[-3:])
    step = xs[1] - xs[0]
    print(f'  check_chain: byte [90BE] = 1, [3158] = 0, [6354] = 90: H = {h:.6f}; [7FBC] climbs '
          f'{xs[0]:.4f}, {xs[1]:.4f}, ... (+{step:.4f}/call) and sits at H = {xs[-1]:.6f} after 110 calls')
    setup(S=0, G=1, D=0, f67=0, E_=20.0)
    xs, h = go(140)
    assert abs(h - 100 * 20.0390625 * 0.01) < 1e-4 and xs[-1] == h
    print(f'    byte [3158] = 1, [90BE] = 0, [6354] = 20: H = {h:.6f}, [7FBC] reaches {xs[-1]:.6f}')
    setup(S=0, G=0, D=0, f67=0)
    xs, h = go(40)
    assert h == 0.0 and all(x == 0.0 for x in xs)
    for s, g in ((2, 2), (0, 0x81), (0x81, 0)):
        setup(S=s, G=g, D=0, f67=0)
        xs, h = go(10)
        assert h == 0.0 and all(x == 0.0 for x in xs), (s, g)
    setup(S=1, G=0, D=1, f67=0)
    xs, h = go(40)
    assert h == 0.0 and all(x == 0.0 for x in xs)
    setup(S=1, G=0, D=0, f67=1)
    xs, h = go(40)
    assert h == 0.0 and all(x == 0.0 for x in xs)
    print('    [90BE] != 1 and [3158] != 1, or [9707] != 0, or [67FC] == 1: H = 0 and [7FBC] == 0.0 on every call')
    # a bound that drops: integrator at H, then [90BE] falls -> next update clamps to 0
    setup(S=1, G=0, D=0, f67=0)
    go(120)
    e.ram_u8(A_S, 0)
    xs, h = go(1)
    assert h == 0.0 and xs[0] == 0.0
    print('    [7FBC] at H, then [90BE] -> 0: the next call writes H = 0 and [7FBC] = 0.0 (clamp, up-step path)')
    print('    (every case above has byte [69E6] = 1, latch byte [7FF4] = 0 and [7FEF] = 0 BY CONSTRUCTION; see')
    print('     check_latch and check_window_b for what happens otherwise)')


def check_latch():
    """The 0x0410D4 latch (timing trace step 1 / 4): byte [7FF4] := 1 when byte [69E6] == 0 and |X| <= w;
    then X = +0.0 on every call. No up step is reachable with [69E6] == 0 (step 10 precedes branch 12)."""
    for name, img in (('REAL', REAL), ('STOCK', STOCK)):
        ch = Chain(img)
        # (a) one call with [69E6] = 0 at X = 0 latches; 200 calls with every up condition restored stay 0
        ch.setup(S=1, G=0, D=0, f67=0, F9=0)
        xs, h = ch.go(1)
        assert ch.u8(A_LATCH) == 1 and xs == [0.0] and 15.0 < h < 15.1, (name, xs, h)
        ch.e.ram_u8(A_F9, 1)
        xs, h = ch.go(200)
        assert all(x == 0.0 for x in xs) and ch.u8(A_LATCH) == 1 and 15.0 < h < 15.1, (name, max(xs), h)
        # control: the same machine state without the latch climbs (first call already > 0)
        ch.setup(S=1, G=0, D=0, f67=0, F9=1)
        xs, h = ch.go(3)
        assert 0.0 < xs[0] < xs[1] < xs[2] and ch.u8(A_LATCH) == 0, (name, xs)
        # (b) [69E6] = 0 from X = 1.0 (outside the window): step 10 takes 0.015 per call down to +0.0, the
        #     next call latches, and restoring [69E6] = 1 does not bring the integrator back
        ch.setup(S=1, G=0, D=0, f67=0, F9=0, X0=1.0)
        xs, h, lt = ch.go(80, track=A_LATCH)
        k = xs.index(0.0)
        dif = [a - b for a, b in zip([1.0] + xs[:k], xs[:k])]
        assert all(abs(d - 0.015) < 1e-5 for d in dif), (name, dif[:3], dif[-3:])
        assert lt[:k + 1] == [0] * (k + 1) and lt[k + 1] == 1 and all(lt[k + 1:]), (name, k, lt[k - 1:k + 3])
        ch.e.ram_u8(A_F9, 1)
        xs2, h2 = ch.go(200)
        assert all(x == 0.0 for x in xs2) and 15.0 < h2 < 15.1
        # (c) [69E6] = 0 with X inside the window but non-zero (0.001): latch, X forced to +0.0 at once
        ch.setup(S=1, G=0, D=0, f67=0, F9=0, X0=0.001)
        xs, h = ch.go(1)
        assert ch.u8(A_LATCH) == 1 and xs == [0.0], (name, xs)
        print(f'  check_latch {name}: one call with byte [69E6] = 0 at X = 0 sets [7FF4] = 1; the next 200 calls with')
        print(f'    [69E6] = 1, H = {h:.4f} and every up condition met give X = 0.0 on every call. From X = 1.0 with')
        print(f'    [69E6] = 0: -0.015 per call, X = +0.0 at call {k + 1}, latched at call {k + 2}; X = 0.001: latched at once.')


def check_window_b():
    """Byte [7FDC] (0x040A9C window B: byte [7FEF] == 1 and u16 [7FEA] < u16 [0x0D29C4]) in the task:
    [0x0D29C4] = 438 in 20.19c, 0 in stock."""
    assert U16(REAL, 0x0D29C4) == 438 and U16(STOCK, 0x0D29C4) == 0
    res = {}
    for name, img in (('REAL', REAL), ('STOCK', STOCK)):
        ch = Chain(img)
        for w in (0, 437, 438):
            ch.setup(S=1, G=0, D=0, f67=0, b7FEF=1, w7FEA=w)
            xs, h = ch.go(20)
            res[(name, w)] = (xs[-1], ch.u8(A_7FDC))
        # X at H, then byte [65C0] = 1 with window B open: step 8 takes 0.015 per call in 20.19c only
        ch.setup(S=1, G=0, D=0, f67=0)
        xs, h = ch.go(120)
        assert xs[-1] == h
        ch.e.ram_u8(A_F10, 1)
        ch.e.ram_u8(A_7FEF, 1)
        ch.e.ram_u16(A_7FEA, 0)
        xs, h2 = ch.go(10)
        res[(name, 'dec')] = (xs, h)
    assert res[('REAL', 0)] == (0.0, 1) and res[('REAL', 437)] == (0.0, 1)        # increments blocked
    assert res[('REAL', 438)][0] > 0.0 and res[('REAL', 438)][1] == 0
    for w in (0, 437, 438):
        assert res[('STOCK', w)][0] > 0.0 and res[('STOCK', w)][1] == 0              # never blocked in stock
    xs, h = res[('REAL', 'dec')]
    dif = [a - b for a, b in zip([h] + xs[:-1], xs)]
    assert all(abs(d - 0.015) < 1e-5 for d in dif), dif
    xs, h = res[('STOCK', 'dec')]
    assert all(x == h for x in xs)
    print('  check_window_b: byte [7FEF] = 1 with u16 [7FEA] = 0 / 437: in 20.19c [7FDC] = 1 and X stays 0.0 for 20')
    print('    calls (branch-12 increments blocked); [7FEA] = 438 climbs. In stock ([0x0D29C4] = 0) all three climb.')
    print('    X at H, then byte [65C0] = 1 with window B open: 20.19c steps X down 0.015 per call (step 8); stock')
    print('    holds X at H.')


def check_context():
    e = E.Emu(REAL)
    # 0x0297D0 / 0x029A64
    for v in range(256):
        e.ram_u8(A_D, v)
        e.steps = 0
        e.call(0x0297D0)
        assert e.R[0] == (2 if v else 0)
    e.steps = 0
    e.R[0] = 0x12345678
    e.call(0x029A64)
    assert e.R[0] == 0
    # 0x06114E: byte [90BE] and float [90A8]
    n = 0
    for g in (0, 1, 2, 3, 4, 5, 0xFF):
        img = bytearray(REAL)
        img[0x0D9AC4] = g
        ee = E.Emu(bytes(img))
        for a2e in (0, 1, 0x80):
            for a05 in (0, 1):
                for c4 in (0, 1, 2):
                    for t13 in (0, 1, 2):
                        for r in (0.0, 0.004, 0.5, 0.996, 1.0, 1.5, -0.5):
                            ee.ram_u8(0xFFFF972E, a2e)
                            ee.ram_u8(0xFFFF9705, a05)
                            ee.ram_u8(0xFFFF90C4, c4)
                            ee.ram_u8(0xFFFF9113, t13)
                            ee.ram_f32(0xFFFF90A8, r)
                            ee.steps = 0
                            ee.R[15] = E.STACK_TOP
                            assert ee.call(0x06114E) == 'return'
                            if a2e or a05:
                                want = 0
                            elif g < 1 or g > 4:
                                want = int(c4 == 1)
                            elif g == 1:
                                want = 1
                            elif g == 3:
                                want = int(t13 == 1)
                            elif g == 4:
                                want = int(t13 == 0)
                            else:
                                want = 0
                            assert ee.read(A_S, 1) == want, (g, a2e, a05, c4, t13)
                            step = U32(img, 0x0D9B44 if want else 0x0D9B40)
                            x = rz('-' if want else '+', f2b(r), step)
                            xr = ZERO if not gt(x, ZERO) else (x if gt(ONE, x) else ONE)
                            assert ee.read(0xFFFF90A8, 4) == xr, (r, hex(ee.read(0xFFFF90A8, 4)), hex(xr))
                            n += 1
    assert REAL[0x0D9AC4] == STOCK[0x0D9AC4] == 0
    assert REAL[0x06114E:0x061280] == STOCK[0x06114E:0x061280]
    print(f'  check_context: 0x0297D0 r0 = 2 iff byte [9707] != 0 (256 values); 0x029A64 r0 = 0;')
    print(f'    0x06114E: {n} runs over [0x0D9AC4] in 0..5, 0xFF: byte [90BE] as modelled; [0x0D9AC4] = 0 in both')
    print('    bins, so [90BE] = ([90C4] == 1) unless byte [972E] != 0 or byte [9705] != 0; [90A8] = clamp(')
    print('    [90A8] - [0x0D9B44] if [90BE] else + [0x0D9B40], 0, 1)')
    # 0x0610E6: byte [90C4]
    n = 0
    t8, ta, f2c = U16(REAL, 0x0D9AD8), U16(REAL, 0x0D9ADA), U32(REAL, 0x0D9B2C)
    for b2 in thr_vals(t8):
        for b4 in thr_vals(ta):
            for b0 in (0, 1, 0xFFFF):
                for fe in (0.0, 3.99, 4.0, 4.01, float('nan')):
                    e.ram_u16(0xFFFF90B2, b2)
                    e.ram_u16(0xFFFF90B4, b4)
                    e.ram_u16(0xFFFF90B0, b0)
                    e.ram_f32(0xFFFF90EC, fe)
                    e.steps = 0
                    e.R[15] = E.STACK_TOP
                    assert e.call(0x0610E6) == 'return'
                    want = int(b2 >= t8 and (gt(f2c, f2b(fe)) or b0 < 1) and b4 >= ta)
                    assert e.read(0xFFFF90C4, 1) == want
                    n += 1
    assert (t8, ta, b2f(f2c)) == (250, 375, 4.0)
    # 0x06081C: callees stubbed; it stores 1 to [90C4] and 0xFFFF to [90B2] / [90B4] unconditionally
    for v in (0, 1, 2):
        ee = E.Emu(REAL)
        ee.stub(0x061468, r0=v)
        ee.stub(0x061428, r0=0)
        ee.ram_u8(0xFFFF90C4, 0)
        ee.ram_f32(0xFFFF6350, 20.0)
        ee.ram_u8(0xFFFF65C0, 0)
        ee.R[15] = E.STACK_TOP
        assert ee.call(0x06081C) == 'return'
        assert ee.read(0xFFFF90C4, 1) == 1 and ee.read(0xFFFF90B2, 2) == 0xFFFF == ee.read(0xFFFF90B4, 2)
    print(f'    0x0610E6: {n} runs: [90C4] = 1 iff u16 [90B2] >= 250 and u16 [90B4] >= 375 and (4.0 > [90EC]')
    print('    or u16 [90B0] == 0); 0x06081C stores [90C4] = 1, [90B2] = [90B4] = 0xFFFF (callees stubbed)')
    # 0x02F57E: the only store of value 1 into the high byte of u16 [3158]
    n = 0
    thr_n = U32(REAL, 0x0CBDDC)
    thr_t = U16(REAL, 0x0CBC1E)
    for c2 in (0, 1, 2):
        for prev in (0, 1):
            for e50 in (0, 1):
                for a15a in (0x00FF, 0x01FE):
                    for a15c in (0x00FF, 0x01FE):
                        for nn in (0.0, b2f(thr_n), b2f(thr_n) + 1.0, float('nan')):
                            for w23c in (0, 0xFFFF):
                                for c6 in (0, max(thr_t - 1, 0), thr_t, 0xFFFF):
                                    for w in (20.0, 90.0):
                                        e.ram_u8(0xFFFF65C2, c2)
                                        e.ram_u8(0xFFFF72CF, prev)
                                        e.ram_u8(0xFFFF7E50, e50)
                                        e.ram_u16(0xFFFF315A, a15a)
                                        e.ram_u16(0xFFFF315C, a15c)
                                        e.ram_u16(0xFFFF3158, 0xABCD)
                                        e.ram_f32(A_N, nn)
                                        e.ram_f32(0xFFFF6350, w)
                                        e.ram_u16(0xFFFF223C, w23c)
                                        e.ram_u16(0xFFFF72C6, c6)
                                        e.steps = 0
                                        e.R[15] = E.STACK_TOP
                                        assert e.call(0x02F57E) == 'return'
                                        hi5a = 1 if e50 == 1 else a15a >> 8
                                        cnt = min(c6 + 1, 0xFFFF) if c2 == 1 else 0
                                        ee = E.Emu(REAL)
                                        ee.FR[4] = f2b(w)
                                        ee.call(0x0BE8AC, regs={4: 0x0AC8C4})
                                        lim = ee.R[0] & 0xFFFF
                                        set5c = (gt(f2b(nn), thr_n) or w23c >= lim or
                                                 (c2 == 1 and cnt >= thr_t))
                                        hi5c = 1 if set5c else a15c >> 8
                                        if c2 == 1 and prev == 0:
                                            want58 = 0x01FE if (hi5a == 1 and hi5c == 1) else 0x00FF
                                        else:
                                            want58 = 0xABCD
                                        assert e.read(0xFFFF3158, 2) == want58, (c2, prev, e50, a15a, a15c, nn,
                                                                                  w23c, c6, w)
                                        assert e.read(0xFFFF72C6, 2) == cnt
                                        assert e.read(0xFFFF72CF, 1) == c2
                                        n += 1
    print(f'    0x02F57E: {n} runs: u16 [3158] := 0x01FE (value 1) only when byte [65C2] == 1 and byte [72CF] == 0')
    print('    with the high bytes of [315A] and [315C] both 1 after this call\'s own stores, := 0x00FF on that')
    print('    edge otherwise, else untouched')
    # 0x02EE78 and 0x02F768: the other stores (value 0)
    e.ram_u16(0xFFFF3158, 0x01FE)
    e.R[15] = E.STACK_TOP
    e.steps = 0
    e.call(0x02EE78)
    assert [e.read(0xFFFF3158 + 2 * i, 2) for i in range(5)] == [0x00FF] * 5
    n = 0
    for bd in (0, 1):
        for c4 in (0, 1, 0x1000, 0xFFFE, 0xFFFF):
            for w in (20.0, 90.0):
                for bat in (5.0, 20.0):
                    ee = E.Emu(REAL)
                    ee.stub(0x00DCE4, r0=0)
                    for i in range(5):
                        ee.ram_u16(0xFFFF3158 + 2 * i, 0x01FE)
                    ee.ram_u8(0xFFFF65BD, bd)
                    ee.ram_u16(0xFFFF72C4, c4)
                    ee.ram_u8(0xFFFF72D2, 0)
                    ee.ram_u8(0xFFFF72D0, 0)
                    ee.ram_f32(0xFFFF6350, w)
                    ee.ram_f32(0xFFFF4130, bat)
                    ee.R[15] = E.STACK_TOP
                    assert ee.call(0x02F768) == 'return'
                    cnt = 0 if bd else min(c4 + 1, 0xFFFF)
                    e2 = E.Emu(REAL)
                    e2.FR[4] = f2b(w)
                    e2.call(0x0BE8AC, regs={4: 0x0AC8B8})
                    lim = e2.R[0] & 0xFFFF
                    clear = cnt >= lim or (cnt >= U16(REAL, 0x0CBC1C) and gt(U32(REAL, 0x0CC5F0), f2b(bat)))
                    got = ee.read(0xFFFF3158, 2)
                    assert got == (0x00FF if clear else 0x01FE), (bd, c4, w, bat, hex(got))
                    n += 1
    print(f'    0x02EE78 stores 0x00FF to all five words [3158]..[3160]; 0x02F768 ({n} runs, 0x00DCE4 stubbed)')
    print('    stores 0x00FF to [3158] when its counter [72C4] (counting while byte [65BD] == 0) reaches')
    print('    table 0x0AC8B8([6350]) or u16 [0x0CBC1C] with [0x0CC5F0] > [4130]')
    # 0x04004A: [90A8] is the weight of the Non-Cruise side of the timing blend (0x0401D6..0x0401EA).
    # In 20.19c the four tables give equal values here, so the Cruise pair is raised in an in-memory copy.
    img = bytearray(REAL)
    for rec in (0x0AE31C, 0x0AE354):                    # Base Timing Primary / Reference Cruise
        ny, nx, dp = REAL[rec + 1], REAL[rec + 3], U32(REAL, rec + 12)
        assert REAL[rec + 16] == 0x04
        for i in range(ny * nx):
            img[dp + i] = min(img[dp + i] + 17, 255)
    img = bytes(img)
    n = 0
    for w in (0.0, 0.25, 0.5, 1.0):
        for ld, rpm in ((0.8, 2000.0), (0.3, 3200.0), (1.6, 5000.0)):
            ee = E.Emu(img)
            for a, v in ((0xFFFF90A8, w), (0xFFFF63F8, ld), (0xFFFF6624, 3000.0), (0xFFFF679C, rpm),
                         (0xFFFF804C, rpm)):
                ee.ram_f32(a, v)
            ee.R[15] = E.STACK_TOP
            assert ee.call(0x04004A) == 'return'
            assert ee.read(0xFFFF7F3C, 4) == ZERO and ee.read(0xFFFF7F4C, 4) == f2b(rpm)
            lk = E.Emu(img)
            vals = {}
            for rec in (0x0AE31C, 0x0AE338):
                lk.FR[4], lk.FR[5] = f2b(ld), f2b(rpm)
                lk.call(0x0BE8E4, regs={4: rec})
                vals[rec] = lk.FR[0]
            assert vals[0x0AE31C] != vals[0x0AE338]
            assert ee.read(0xFFFF7F40, 4) == vals[0x0AE31C]          # Cruise side ([7F3C] = 0: no reference term)
            assert ee.read(0xFFFF7F44, 4) == vals[0x0AE338]          # Non-Cruise side
            want = rz_fmac(rz('-', ONE, f2b(w)), vals[0x0AE31C], rz('*', f2b(w), vals[0x0AE338]))
            assert ee.read(0xFFFF7F58, 4) == want
            if w == 0.0:
                assert want == vals[0x0AE31C]
            if w == 1.0:
                assert want == vals[0x0AE338]
            n += 1
    # 0x04092A (caller 0x047C40): the other writer of [7FD4] find_writers reports -- an initialiser
    for s, u, c0, f in ((0, 1, 1, 0), (1, 0, 0, 1), (2, 0x80, 0x7F, 0xFF)):
        ee = E.Emu(REAL)
        for a, v in ((A_S, s), (A_U, u), (0xFFFF65C0, c0), (A_F, f)):
            ee.ram_u8(a, v)
        ee.ram_f32(O['D4'], 0.0)
        ee.R[15] = E.STACK_TOP
        ee.gbr = GBR_SENT
        assert ee.call(0x04092A) == 'return' and ee.gbr == GBR_SENT
        want = {O['D4']: (4, ONE), 0xFFFF7FE8: (2, 0xFFFF), 0xFFFF7FEA: (2, 0xFFFF), W['E6']: (2, 0xFFFF),
                0xFFFF7FF2: (1, c0), 0xFFFF7FF3: (1, f), B['F0']: (1, 1), B['FB']: (1, s), W['F8']: (2, 0xFFFF),
                B['FF']: (1, u), W['FC']: (2, 0xFFFF)}
        for a, (nb, v) in want.items():
            assert ee.read(a, nb) == v, hex(a)
        assert set(ee.writes) == {a + i for a, (nb, v) in want.items() for i in range(nb)}
    print('    0x04092A: [7FD4] := 1.0, words [7FE6] [7FE8] [7FEA] [7FF8] [7FFC] := 0xFFFF, byte [7FF0] := 1,')
    print('    [7FFB] := [90BE], [7FFF] := [8E7E], [7FF2] := [65C0], [7FF3] := [85D7]; nothing else (write set exact)')
    # 0x03A5E4: [6354] is the x of record 0x0AD3C4, whose definition axis 0x0CC664 is "Coolant Temperature"
    lk = Luts(REAL)
    for x in (-50.0, -40.0, 0.0, 25.0, 70.0, 95.0, 110.0, 130.0, float('nan')):
        ee = E.Emu(REAL)
        ee.ram_f32(A_E, x)
        ee.ram_u8(0xFFFF7C9D, 0x5A)
        ee.R[15] = E.STACK_TOP
        assert ee.call(0x03A5E4) == 'return'
        v = lk.l1(0x0AD3C4, f2b(x))
        assert ee.read(0xFFFF7C34, 4) == v and ee.read(0xFFFF7C38, 4) == v
        assert ee.read(0xFFFF7C63, 1) == 0x5A and ee.read(0xFFFF7C62, 1) == REAL[0x0CBC07]
    assert U32(REAL, 0x0AD3C4 + 4) == 0x0CC664 and U32(REAL, 0x0AD3C4 + 8) == 0x0CEE40
    print('    0x03A5E4 (9 runs): [7C34] = [7C38] = lookup(0x0AD3C4, [6354]); 0x0AD3C4 axis 0x0CC664, data 0x0CEE40')
    print(f'    0x04004A ({n} runs, Cruise tables raised in memory): [7F58] = (1 - [90A8]) * [7F40] + [90A8] * [7F44];')
    print('    [7F40] from 0x0AE31C "Base Timing Primary Cruise", [7F44] from 0x0AE338 "... Non-Cruise":')
    print('    [90A8] = 0 selects Cruise, 1 Non-Cruise; 0x06114E drives [90A8] toward 0 while [90BE] == 1')


def _tracked_call(e, entry, inputs):
    """inputs: {addr: (nbytes, value)} poked WITHOUT marking initialised. Returns (writes, reads)."""
    fresh(e)
    for a, (nb, v) in inputs.items():
        poke(e, a, nb, v)
    e.R[15] = E.STACK_TOP
    e.gbr = GBR_SENT
    assert e.call(entry) == 'return' and e.gbr == GBR_SENT
    return set(e.writes), set(e.uninit_reads)


def check_writers():
    """The writers of byte [69E6] (read by 0x0410D4 as F9) and the second writer of 0x040AF6's state."""
    # 0x026634 (stub class 35 of stub_shapes_b_trace.txt): bytes [69E4] [69E5] [69E6] [69E7] := 1
    e = E.Emu(REAL)
    w, r = _tracked_call(e, 0x026634, {0xFFFF69E4 + i: (1, 0) for i in range(4)})
    assert w == {0xFFFF69E4 + i for i in range(4)} and r == set() and e.R[0] == 1
    assert all(e.read(0xFFFF69E4 + i, 1) == 1 for i in range(4))
    # 0x026698: byte [69E6] := 0 if [6350] > [0x0C34D0] or NOT (lut(0x0AAF5C, [6354]) > [63D4]); [69E7] the
    # same with [0x0C34D4]; otherwise each byte is left as it was (never set to 1 here)
    assert b2f(U32(REAL, 0x0C34D0)) == 70.0 and b2f(U32(REAL, 0x0C34D4)) == 60.0
    assert REAL[0x0C34D0:0x0C34D8] == STOCK[0x0C34D0:0x0C34D8]
    assert REAL[0x026698:0x026748] == STOCK[0x026698:0x026748]
    for a in (0x0AAF5C, 0x0C3954, 0x0C3994):
        assert REAL[a:a + 64] == STOCK[a:a + 64]
    assert DT.read_table(REAL, 0x0AAF5C)['values'] == [1240.0, 1170.0, 1100.0, 1040.0, 980.0, 570.0, 280.0,
                                                       266.0, 250.0] + [210.0] * 7
    L = Luts(REAL)
    n = 0
    for w6350 in (59.0, 60.0, 60.5, 69.0, 70.0, 70.5, float('nan')):
        for e6354 in (-40.0, 5.0, 45.0, 80.0, float('nan')):
            lut = L.l1(0x0AAF5C, f2b(e6354))
            for t in (b2f(lut) - 1.0, b2f(lut), b2f(lut) + 1.0, 0.0, float('nan')):
                for prior in (1, 0x55, 0):
                    ins = {0xFFFF6350: (4, f2b(w6350)), 0xFFFF6354: (4, f2b(e6354)), 0xFFFF63D4: (4, f2b(t)),
                           0xFFFF69E6: (1, prior), 0xFFFF69E7: (1, prior)}
                    wr, rd = _tracked_call(e, 0x026698, ins)
                    c6 = gt(f2b(w6350), U32(REAL, 0x0C34D0)) or not gt(lut, f2b(t))
                    c7 = gt(f2b(w6350), U32(REAL, 0x0C34D4)) or not gt(lut, f2b(t))
                    assert e.read(0xFFFF69E6, 1) == (0 if c6 else prior), (w6350, e6354, t, prior)
                    assert e.read(0xFFFF69E7, 1) == (0 if c7 else prior)
                    assert wr == ({0xFFFF69E6} if c6 else set()) | ({0xFFFF69E7} if c7 else set()), wr
                    assert rd == {0xFFFF6350, 0xFFFF6354, 0xFFFF63D4}, rd
                    n += 1
    print('  check_writers: 0x026634 sets bytes [69E4..69E7] := 1 (write set exact). 0x026698 (' + str(n) + ' runs):')
    print('    byte [69E6] := 0 iff [6350] > 70.0 ([0x0C34D0]) or NOT (lut(0x0AAF5C, [6354]) > [63D4]), else')
    print('    untouched; [69E7] the same with 60.0 ([0x0C34D4]); it never stores a non-zero value; reads exactly')
    print('    [6350] [6354] [63D4]. Code, table and both thresholds identical in stock.')
    # 0x0409C0 (caller 0x04907C): the incrementer of [7FE6] / [7FE8] / [7FEA] and the writer of [7FF0]
    n = 0
    ms = (4, 7, 8)
    rng = random.Random(0x0409C0)
    for m in (0, 4, 7, 8, 3, 0x84):
        for f0 in (0, 4, 7, 8, 5, 0x84):
            for c5 in (0, 1, 2):
                for t6c in (0, 1, 2):
                    for rep in range(6):
                        c0, d7 = rng.choice([0, 1, 2]), rng.choice([0, 1, 2])
                        f2, f3 = rng.choice([0, 1, 0x80]), rng.choice([0, 1, 0x80])
                        e6, e8, ea = (rng.choice([0, 5, 437, 438, 0xFFFE, 0xFFFF]) for _ in range(3))
                        ed, ee_, ef = rng.choice([0, 1, 2]), rng.choice([0, 1, 2]), rng.choice([0, 1, 2])
                        ins = {A_M: (1, m), 0xFFFF7FF0: (1, f0), 0xFFFF65C5: (1, c5), 0xFFFF726C: (1, t6c),
                               A_F10: (1, c0), A_F: (1, d7), 0xFFFF7FF2: (1, f2), 0xFFFF7FF3: (1, f3),
                               0xFFFF7FE6: (2, e6), 0xFFFF7FE8: (2, e8), A_7FEA: (2, ea),
                               0xFFFF7FED: (1, ed), 0xFFFF7FEE: (1, ee_), A_7FEF: (1, ef)}
                        wr, rd = _tracked_call(e, 0x0409C0, ins)
                        want = {0xFFFF7FED: ed, 0xFFFF7FEE: ee_, A_7FEF: ef}
                        reads = {A_M, 0xFFFF7FF0, 0xFFFF65C5, 0xFFFF726C, A_F10, A_F}
                        writes = {0xFFFF7FE6, 0xFFFF7FE7, 0xFFFF7FF0, 0xFFFF7FE8, 0xFFFF7FE9, 0xFFFF7FF2,
                                  A_7FEA, A_7FEA + 1, 0xFFFF7FF3}
                        # (1) [7FF0] not in set and M in set: [7FED] := 1, [7FE6] := 0; else [7FE6] += 1 (sat)
                        if f0 not in ms and m in ms:
                            want[0xFFFF7FED] = 1
                            writes.add(0xFFFF7FED)
                            want[0xFFFF7FE6] = 0
                        else:
                            reads.add(0xFFFF7FE6)
                            want[0xFFFF7FE6] = min(e6 + 1, 0xFFFF)
                        want[0xFFFF7FF0] = m
                        # (2) [65C5] == 1: [7FEE] := 0, [7FE8] := 0xFFFF; rising [65C0] (via [7FF2]) with
                        #     [726C] != 1 and [65C0] == 1: [7FEE] := 1, [7FE8] := 0; else [7FE8] += 1 (sat)
                        if c5 == 1:
                            want[0xFFFF7FEE] = 0
                            want[0xFFFF7FE8] = 0xFFFF
                            writes.add(0xFFFF7FEE)
                        else:
                            if t6c != 1:
                                reads.add(0xFFFF7FF2)
                            if t6c != 1 and f2 == 0 and c0 == 1:
                                want[0xFFFF7FEE] = 1
                                want[0xFFFF7FE8] = 0
                                writes.add(0xFFFF7FEE)
                            else:
                                reads.add(0xFFFF7FE8)
                                want[0xFFFF7FE8] = min(e8 + 1, 0xFFFF)
                        want[0xFFFF7FF2] = c0
                        # (3) [726C] == 1: [7FEF] := 0, [7FEA] := 0xFFFF; rising [85D7] (via [7FF3]):
                        #     [7FEF] := 1, [7FEA] := 0; else [7FEA] += 1 (sat)
                        if t6c == 1:
                            want[A_7FEF] = 0
                            want[A_7FEA] = 0xFFFF
                            writes.add(A_7FEF)
                        else:
                            reads.add(0xFFFF7FF3)
                            if f3 == 0 and d7 == 1:
                                want[A_7FEF] = 1
                                want[A_7FEA] = 0
                                writes.add(A_7FEF)
                            else:
                                reads.add(A_7FEA)
                                want[A_7FEA] = min(ea + 1, 0xFFFF)
                        want[0xFFFF7FF3] = d7
                        for a, v in want.items():
                            nb = 2 if a in (0xFFFF7FE6, 0xFFFF7FE8, A_7FEA) else 1
                            assert e.read(a, nb) == v, (hex(a), e.read(a, nb), v, ins)
                        assert wr == writes, (sorted(map(hex, wr ^ writes)), ins)
                        assert rd == reads, (sorted(map(hex, rd ^ reads)), ins)
                        n += 1
    assert REAL[0x0409C0:0x040A9C] == STOCK[0x0409C0:0x040A9C]
    print(f'  check_writers: 0x0409C0 ({n} runs, read and write sets exact): [7FF0] := M every call; [7FED] := 1')
    print('    and [7FE6] := 0 when [7FF0] not in {4,7,8} and M in it, else [7FE6] += 1 (saturating); [7FEF] := 1')
    print('    and [7FEA] := 0 on byte [85D7] == 1 with [7FF3] == 0 and [726C] != 1, [7FEF] := 0 and [7FEA] :=')
    print('    0xFFFF on [726C] == 1, else [7FEA] += 1; [7FF3] := [85D7]; [7FEE] / [7FE8] / [7FF2] likewise on')
    print('    [65C0], with [65C5] == 1 forcing [7FEE] := 0, [7FE8] := 0xFFFF.')


def main():
    check_tables()
    n = check_main()
    m = check_real()
    check_chain()
    check_latch()
    check_window_b()
    check_writers()
    check_context()
    print(f'ALL CHECKS PASSED ({n} + {m} whole-function runs of 0x040AF6)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
