#!/usr/bin/env python3
"""Emulation check for the coefficient writers, consumer and resets around logged AFC (0xFFFF76D4).

    python3 scripts/trace/emu_afc_coefficients.py

Reference bin: rom/AE5L600L 20g rev 20.19c.bin  md5 92cae8275cd4f9b473a3a9e36efe6449
Trace:         disassembly/analysis/afc_coefficients_trace.txt

Functions (all run in scripts/sh2e_emu.py against a Python model written from the bytes):
  0x031D88  [7474] = cal 0x0CBEBC / [6624] (guarded)
  0x031DB4  [7478] [747C] [7480] [7484] [7488] [76E8..76F4], byte [7700]   (r4 = 0x063978, r5 = 0)
  0x032042  [74A8] [74AC] [74B0] [74B4]                                    (r4 = 0x0639A0, r5 = 0x063978)
  0x031F98  Q0..Q6 = [748C..74A4]                                          (r4 = 0x063984)
  0x03286C  e(x): 1 - x + x*x/2 for x <= 0.35, else 1-D lookup 0x0ACE20 (side effect [76E4] = x)
  0x032892  P1, P2, P3 = [74BC] [74C0] [74C4]; returns P3
  0x0320AC  P0 = [74B8], P4[1..41] = [74CC..]                              (r4 = 0x0639B0, r5 = Q, r6 = 0x0639A0)
  0x03297A  [7704] [7708] [770C] = lag-filtered [76D4], or 1.0
  0x032AA8  reset of [7710..77B8] when byte [65F6] == 1 (LO = HI = 1.0)
  0x032958  reset [7704] = [7708] = [770C] = 1.0 when byte [65F6] == 1
  0x0331C6  [772C] = lookup 0x0ACE40 at [6350]; [7730] = clamp(1/((1+[7BE4])*[772C]), 0.5, 1.5)
  0x0330CA  [7724] = clamp(x + g, .5, 1.5); HI [7710] = rate-limited toward it, capped by [7730]
  0x033128  [7728] = clamp(x + g, .5, 1.5); LO [7714] = rate-limited toward it, capped by [7730]
  0x032B5E  HI target selection (mode byte), countdown byte [77B6], byte [77B8]
  0x032B10  gate; [7720] = [40C8]; 0x0331C6; 0x032B5E; tail 0x032E28 (stubbed: not decoded)
  0x034C54  reader of [7708]: window 0.95 < [7708] < 1.05 -> byte [787E] -= 1; bytes [787E]/[789E] upkeep

Passes
  A  image facts: pointer tables, every calibration value in all 20 bins (stock vs 20.19c),
     the only references to the entries, no branch into 0x0329B2 from outside 0x03297A
  B  per-function grids, bit-exact write set + values + input-read set against the model
  C  0x0320AC / 0x032892 for every dead-time byte 0..255 and the four branch shapes
  D  edges: the 2^-11 / 2^-16 divide guards, e(x) at 0.35, NaN, LO > HI, rate limits
  E  the live chain 0x031D1E (real callees) -> 0x032204 at operating points: the coefficients
     P0, P2, P4[k] it produces, and R8 under a constant error with [LO,HI] open vs pinned; both
     signs from equilibrium (first move (P2 - P0) e, calls to HI / below 1); the post-pinned
     control showing the old 10-call "rich" run was confounded by its history (review C20)
  F  every instruction address of the decoded functions executed (0x034C54 included)
  G  logged AFC in the 20.19c logs, and the getter 0x05D2C0 at its rounding edges (review C35)

Review repairs (third decode, 2026-11-27): dense e(x) scan (C6), W-branch cases of 0x031DB4 (C17),
equilibrium sign runs + confound control (C20), 0x034C54 model (C33), getter edges (C35),
non-integer Q2 in 0x0320AC and the net move of 0x0330CA / 0x033128 (reviewer's missed items).

ROUNDING: fadd/fsub/fmul/fdiv exact then rounded toward zero, fmac fused (corrections item 106),
as sh2e_emu does.  Only sh2e_emu.rz_bits/f2b/b2f are shared with the emulator; the table lookups
0x0BE830 / 0x0BE8E4 are run as ROM oracles (their contracts are verified in helpers_wrap_trace.txt).
No statement in the trace depends on the last bit of a float.  Names are neutral on purpose.
"""
import glob
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

BIN = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
ROM = open(BIN, 'rb').read()
assert hashlib.md5(ROM).hexdigest() == '92cae8275cd4f9b473a3a9e36efe6449', 'wrong reference bin'
STOCK = open(os.path.join(REPO, 'rom', 'ae5l600l.bin'), 'rb').read()

CHECKS = [0]


def ok(cond, msg):
    assert cond, msg
    CHECKS[0] += 1


# ---------------------------------------------------------------- float model
def F(b): return E.b2f(b)
def B(x): return E.f2b(x)


ONE, ZERO, HALF, ONE5, TWO = 0x3F800000, 0, 0x3F000000, 0x3FC00000, 0x40000000
EPS11, EPS13, EPS15, EPS16 = 0x3A000000, 0x39000000, 0x38000000, 0x37800000
FLT_MAX = 0x7F7FFFFF


def rz(op, xb, yb):
    x, y = F(xb), F(yb)
    ap = {'+': lambda a, b: a + b, '-': lambda a, b: a - b,
          '*': lambda a, b: a * b, '/': lambda a, b: a / b}[op]
    if op == '/' and y == 0.0:
        raise ValueError('unguarded divide')
    try:
        ieee = ap(x, y)
    except OverflowError:
        ieee = math.copysign(math.inf, x) * (math.copysign(1, y) if op in '*/' else 1)
    if not (math.isfinite(x) and math.isfinite(y)):
        return B(ieee)
    q = ap(Fraction(x), Fraction(y))
    return B(ieee) if q == 0 else E.rz_bits(q)


def fadd(x, y): return rz('+', x, y)
def fsub(x, y): return rz('-', x, y)
def fmul(x, y): return rz('*', x, y)
def fdiv(x, y): return rz('/', x, y)
def fneg(x): return x ^ 0x80000000


def fmac(a, b, c):
    fa, fb, fc = F(a), F(b), F(c)
    if math.isfinite(fa) and math.isfinite(fb) and math.isfinite(fc):
        q = Fraction(fa) * Fraction(fb) + Fraction(fc)
        return B(fa * fb + fc) if q == 0 else E.rz_bits(q)
    return B(fa * fb + fc)


def ffloat(i):
    i = i if i < 2**31 else i - 2**32
    return E.rz_bits(Fraction(i)) if i else 0


def ftrc(xb):
    f = F(xb)
    if f != f:
        return 0x80000000
    if f >= 2**31:
        return 0x7FFFFFFF
    if f < -2**31:
        return 0x80000000
    return int(f) & 0xFFFFFFFF


def outside(x, c, w):          # 0x0BE608: 1 when x < c-w or x > c+w; edges and NaN inside
    if F(fsub(c, w)) > F(x):
        return 1
    if F(x) > F(fadd(c, w)):
        return 1
    return 0


def sdiv(n, d):                # 0x0BE628
    if F(d) == 0.0:
        if F(n) == 0.0:
            return ZERO
        return FLT_MAX if F(n) > 0 else FLT_MAX | 0x80000000
    return fdiv(n, d)


def clamp(x, lo, hi):          # 0x0BE56C, low test first
    if not (F(x) > F(lo)):
        return lo
    if F(hi) > F(x):
        return x
    return hi


def fmin(a, b):                # 0x0BE970 (fr4 = a, fr5 = b): a if b > a else b
    return a if F(b) > F(a) else b


def lag(a, b, k, eps):         # 0x0BEA40: a = fr4 (new), b = fr5 (old)
    if (b & 0x7F800000) == 0x7F800000:
        return a
    d = fsub(b, a)
    r = fmac(fsub(ONE, k), d, a)
    if F(eps) > abs(F(fsub(a, r))):
        return a
    return r


_lut = {}


def lut1(rec, xb):
    k = (1, rec, xb)
    if k not in _lut:
        e = E.Emu(ROM)
        e.call(0x0BE830, regs={4: rec}, fregs={4: F(xb)})
        _lut[k] = e.FR[0]
    return _lut[k]


def lut2(rec, xb, yb):
    k = (2, rec, xb, yb)
    if k not in _lut:
        e = E.Emu(ROM)
        e.call(0x0BE8E4, regs={4: rec}, fregs={4: F(xb), 5: F(yb)})
        _lut[k] = e.FR[0]
    return _lut[k]


def cal(a, rom=ROM): return struct.unpack_from('>I', rom, a)[0]
def sx8(v): v &= 0xFF; return v - 256 if v & 0x80 else v


# ---------------------------------------------------------------- addresses
U0, U1, U2 = 0xFFFF7484, 0xFFFF7488, 0xFFFF7700           # table 0x063978
Q = [0xFFFF748C + 4 * i for i in range(7)]                  # table 0x063984
V = [0xFFFF74A8 + 4 * i for i in range(4)]                  # table 0x0639A0
P = [0xFFFF74B8, 0xFFFF74BC, 0xFFFF74C0, 0xFFFF74C4, 0xFFFF74C8]   # table 0x0639B0 (P4 = array base)
W = [0xFFFF7704, 0xFFFF7708, 0xFFFF770C]                    # table 0x063A04
T7474, T7478, T747C, T7480 = 0xFFFF7474, 0xFFFF7478, 0xFFFF747C, 0xFFFF7480
X76E4, X76E8, X76EC, X76F0, X76F4 = 0xFFFF76E4, 0xFFFF76E8, 0xFFFF76EC, 0xFFFF76F0, 0xFFFF76F4
RPM, AIR, C6350, D67EC, B6254, A40C8 = 0xFFFF6624, 0xFFFF63C4, 0xFFFF6350, 0xFFFF67EC, 0xFFFF6254, 0xFFFF40C8
HI, LO = 0xFFFF7710, 0xFFFF7714
R8, EN, G65F0, G65F6 = 0xFFFF76D4, 0xFFFF7448, 0xFFFF65F0, 0xFFFF65F6


def p4(k): return P[4] + 4 * k


# ---------------------------------------------------------------- model memory
class Mem:
    def __init__(self, init):
        self.m = dict(init)
        self.w = set()
        self.reads = set()

    def _rd(self, a, n):
        if any((a + i) not in self.w for i in range(n)):
            self.reads.add(a)
        return int.from_bytes(bytes(self.m.get(a + i, 0) for i in range(n)), 'big')

    def rf(self, a): return self._rd(a, 4)
    def rw(self, a): return self._rd(a, 2)
    def rb(self, a): return self._rd(a, 1)

    def wf(self, a, bits):
        for i in range(4):
            self.m[a + i] = (bits >> (8 * (3 - i))) & 0xFF
            self.w.add(a + i)

    def wb(self, a, v):
        self.m[a] = v & 0xFF
        self.w.add(a)


def init_f(d, a, bits):
    for i in range(4):
        d[a + i] = (bits >> (8 * (3 - i))) & 0xFF


def init_b(d, a, v): d[a] = v & 0xFF
def init_w(d, a, v): d[a] = (v >> 8) & 0xFF; d[a + 1] = v & 0xFF


# ---------------------------------------------------------------- models, in byte order
def m_e(M, x):                                 # 0x03286C
    if F(x) > F(0x3EB33333):                   # 032870 fcmp/gt fr8,fr4: T = x > 0.35 (0x3EB33333)
        M.wf(X76E4, x)                         # 032876
        return lut1(0x0ACE20, M.rf(X76E4))     # 03287E (slot reads it back), jmp 0x0BE830
    s = fmul(x, x)                             # 032882
    s = fdiv(s, TWO)                           # 032888
    return fadd(s, fsub(ONE, x))               # 03288C / 032890


def m_31D88(M):
    x = M.rf(RPM)
    if outside(x, ZERO, 0x3E480000):           # 0.1953125
        M.wf(T7474, fdiv(cal(0x0CBEBC), x))


def m_31DB4(M, r5=0):
    fr14 = M.rf(AIR); fr15 = M.rf(RPM); fr12 = M.rf(C6350)
    r11 = M.rw(D67EC); r14 = M.rb(B6254)
    fr13 = M.rf(T7474)
    fr8 = M.rf(A40C8) if (r5 & 0xFF) == 0 else ZERO
    if not (F(fr8) > F(cal(0x0CBEC0))):        # 031DF8 T = x > [CBEC0]; bt skips
        M.wb(U2, 1)
    elif F(fr8) > F(cal(0x0CBEC4)):            # 031E08 T = x > [CBEC4]
        M.wb(U2, 0)
    t = fmin(lut2(0x0AD620, fr14, fr15), 0x42200000)
    M.wf(T7478, t)
    M.wf(T747C, fmul(fr13, M.rf(T7478)))
    M.wf(X76E8, lut2(0x0AD848, fr14, fr15))
    M.wf(X76EC, lut1(0x0AC45C, fr12))
    M.wf(T7480, fmul(M.rf(X76E8), M.rf(X76EC)))
    tbl = (r14 & 0xFF) != 1 and M.rb(U2) != 0
    if tbl:
        M.wf(X76F0, lut2(0x0AD864, fr14, fr15))
        M.wf(X76F4, lut1(0x0AC484, fr12))
        g = lut1(0x0AC498, fmul(ffloat(r11 & 0xFFFF), 0x41000000))
        h = lut1(0x0AC4AC, fr15)
    else:
        M.wf(X76F0, lut1(0x0ACE0C, M.rf(T7480)))
        M.wf(X76F4, lut1(0x0AC470, fr12))
        g = h = ONE
    y = fmul(fmul(fmul(M.rf(X76F0), M.rf(X76F4)), g), h)
    M.wf(U0, y)
    M.wf(U1, fmul(M.rf(U0), fr13))


def m_32042(M):
    c = cal(0x0CBEC8)
    fr14 = M.rf(U1)
    M.wf(V[0], fmul(c, fr14))
    x0 = M.rf(V[0])
    M.wf(V[1], fmul(x0, TWO))
    fr15 = M.rf(V[1])
    e0 = m_e(M, x0)
    k = fmac(fneg(c), c, ONE)                  # 032080 fmac: 1 - c*c, one rounding
    k = fmul(k, fmul(fr14, fr14))
    k = fdiv(k, TWO)
    a = fmul(fmul(e0, fsub(ONE, k)), 0xC0000000)
    M.wf(V[2], a)
    M.wf(V[3], m_e(M, fr15))


def m_31F98(M):
    fr13 = M.rf(T7474); fr14 = M.rf(T7478); fr12 = M.rf(T747C); fr15 = M.rf(T7480)
    if outside(fr15, ZERO, EPS11):
        M.wf(Q[0], fdiv(fr13, fr15))
    M.wf(Q[1], m_e(M, M.rf(Q[0])))
    M.wf(Q[2], ffloat(ftrc(fr14) & 0xFF))
    fr12 = fmac(M.rf(Q[2]), fneg(fr13), fr12)
    M.wf(Q[3], fr12)
    if outside(fr15, ZERO, EPS11):
        M.wf(Q[4], fdiv(fsub(fr13, M.rf(Q[3])), fr15))
    M.wf(Q[5], fsub(ONE, m_e(M, M.rf(Q[4]))))
    fr9 = fsub(ONE, M.rf(Q[1]))
    M.wf(Q[6], fsub(fr9, M.rf(Q[5])))


def m_32892(M, d, a, b1, b2):
    if not (F(d) > 1.0):                       # 0328A2 T = d > 1
        idx = 1
    elif not (40.0 > F(d)):                    # 0328B0 T = 40 > d
        idx = 40
    else:
        idx = ftrc(d)
    M.wf(P[1], M.rf(p4(idx & 0xFF)))
    den = fmac(a, b1, b2)                      # 0328CA a*b1 + b2
    if outside(den, ZERO, EPS16):
        t = fmul(M.rf(P[1]), a)
        t = fmac(M.rf(P[0]), fneg(b2), t)
        t = fmul(t, fdiv(a, den))
        M.wf(P[2], t)
    if outside(a, ZERO, EPS11):
        M.wf(P[3], fdiv(fmul(M.rf(P[2]), b2), a))
    return M.rf(P[3])


def m_320AC(M):
    A = M.rf(V[2]); Bq = M.rf(V[3])
    q5 = M.rf(Q[5]); q6 = M.rf(Q[6]); q2 = M.rf(Q[2]); q1 = M.rf(Q[1])
    s = fadd(q5, q6)
    if outside(s, ZERO, EPS11):
        M.wf(P[0], fdiv(fadd(fadd(A, Bq), ONE), s))
    r10 = (ftrc(q2) + 3) & 0xFFFFFFFF
    c1 = fsub(fsub(fneg(ONE), A), q1)          # -1 - A - Q1
    ap1 = fadd(q1, ONE)                        # Q1 + 1
    amb = fsub(q1, Bq)                         # Q1 - B
    s16 = r10 & 0xFF
    r10 = (r10 - 1) & 0xFFFFFFFF
    shape = {}
    for k in range(1, 42):
        if k == 1:
            M.wf(p4(1), c1); shape[k] = 'c1'
        elif k == 2 and F(q2) > 1.0:
            M.wf(p4(2), fmac(M.rf(p4(1)), ap1, amb)); shape[k] = 'c2'
        elif k == 2:
            M.wf(p4(2), m_32892(M, q2, q1, q5, q6)); shape[k] = 'call'
        else:
            r2 = r10 if k < s16 else 0
            r0 = r2 & 0xFF
            if not (r0 > 1):
                M.wf(p4(k), ZERO); shape[k] = '0'
            elif r0 == 2:
                M.wf(p4(k), m_32892(M, q2, q1, q5, q6)); shape[k] = 'call'
            else:
                t = fmul(M.rf(p4(k - 2)), fneg(q1))
                M.wf(p4(k), fmac(M.rf(p4(k - 1)), ap1, t)); shape[k] = 'rec'
        r10 = ((r10 & 0xFF) - 1) & 0xFFFFFFFF
    return shape


def m_3297A(M, rom=ROM):
    b = M.rb(G65F0) & 0xFF
    if b not in [rom[a] for a in (0x0CBBD8, 0x0CBBD9, 0x0CBBDA, 0x0CBBDB)]:
        return
    fr14 = M.rf(R8)
    en = M.rb(EN) & 0xFF
    if en == 1:
        for w, k, eps in ((W[0], 0x0CBECC, EPS15), (W[1], 0x0CBED0, EPS15), (W[2], 0x0CBED4, EPS13)):
            r = lag(fr14, M.rf(w), cal(k, rom), eps)
            M.wf(w, clamp(r, HALF, ONE5))
    else:
        for w in W:
            M.wf(w, ONE)


def m_34C54(M, rom=ROM):                      # reader of [7708] (review C33): GBR = 0xFFFF787E inside
    a = M.rb(0xFFFF787E) & 0xFF
    if a > 0:                                  # 034C60 cmp/pl on the zero-extended byte
        b = sx8(M.rb(0xFFFF789E)) & 0xFFFFFFFF
        c = sx8(rom[0x0CBBEE]) & 0xFFFFFFFF
        if b >= c:                             # 034C6A cmp/hs r2,r0: T when r0 >= r2 (unsigned)
            M.wb(0xFFFF787E, 0)
        else:
            M.wb(0xFFFF789E, b + 1)
    else:
        M.wb(0xFFFF789E, 0)
    w = M.rf(0xFFFF7708)
    flag = False
    if sx8(M.rb(EN)) == 1 and sx8(M.rb(0xFFFF7453)) == 1:
        flag = F(w) > F(cal(0x0CC084, rom)) and F(cal(0x0CC088, rom)) > F(w)   # both strict
    if flag:
        a = M.rb(0xFFFF787E) & 0xFF
        if a > 0:
            M.wb(0xFFFF787E, a - 1)
    return flag


def m_32AA8(M):
    g = sx8(M.rb(G65F6)) == 1
    fr8 = M.rf(0xFFFF7348)
    if not g:
        return
    M.wf(0xFFFF7710, ONE); M.wf(0xFFFF7714, ONE); M.wf(0xFFFF771C, ONE)
    M.wf(0xFFFF7718, 0x3F400000)
    M.wb(0xFFFF77B8, 0); M.wb(0xFFFF77B6, 0)
    M.wf(0xFFFF77A8, ZERO)
    for k in range(29):
        M.wf(0xFFFF7734 + 4 * k, fr8)
    M.wf(0xFFFF772C, ONE); M.wf(0xFFFF7730, ONE)
    M.wf(0xFFFF7724, 0x3FA00000); M.wf(0xFFFF7728, 0x3F400000)


def m_32958(M):
    if sx8(M.rb(G65F6)) != 1:
        return
    M.wf(0xFFFF7704, ONE); M.wf(0xFFFF7708, ONE); M.wf(0xFFFF770C, ONE)


def m_33186(M):                                # contract from hole9_identity_trace.txt
    a = M.rf(AIR); h = M.rf(0xFFFF68D8)
    r = sdiv(ONE, M.rf(0xFFFF77C8))
    q = sdiv(fadd(a, h), a)
    t = fsub(fmul(r, q), M.rf(0xFFFF7BE4))
    return fadd(fneg(ONE), t)


def m_331C6(M):
    M.wf(0xFFFF772C, lut1(0x0ACE40, M.rf(C6350)))
    d = fmul(fadd(M.rf(0xFFFF7BE4), ONE), M.rf(0xFFFF772C))
    M.wf(0xFFFF7730, clamp(sdiv(ONE, d), HALF, ONE5))


def m_ratelim(M, x, tgt, cell, calk):          # 0x0330CA (tgt 7724, cell 7710) / 0x033128 (7728, 7714)
    M.wf(tgt, clamp(fadd(x, m_33186(M)), HALF, ONE5))
    c = cal(calk)
    hi_b = fadd(M.rf(cell), c)
    lo_b = fsub(M.rf(cell), c)
    z = clamp(M.rf(tgt), lo_b, hi_b)
    z = fmin(z, M.rf(0xFFFF7730))
    M.wf(cell, clamp(z, HALF, ONE5))


def m_32B5E(M, r2):
    r2 &= 0xFF
    cnt = M.rb(0xFFFF77B6)
    if cnt > 0:
        M.wb(0xFFFF77B6, cnt - 1)
        mode = 8
    else:
        mode = 0
        if sx8(M.rb(EN)) == 1: mode += 1
        if r2 == 1: mode += 2
        if sx8(M.rb(0xFFFF77B8)) == 1: mode += 4
        if sx8(M.rb(0xFFFF7828)) == 1: mode += 16
    if mode in (5, 21):
        M.wb(0xFFFF77B6, ROM[0x0CBBE0])
    elif mode in (3, 19):
        t = fmin(lut1(0x0AC4C0, M.rf(0xFFFF7720)), cal(0x0CBEDC))
        x = fmin(fadd(M.rf(0xFFFF770C), cal(0x0CBED8)), t)
        if mode == 3:
            M.wf(HI, clamp(x, HALF, ONE5))
        else:
            m_ratelim(M, x, 0xFFFF7724, HI, 0x0CBEE0)
    elif mode == 17:
        x = fmin(lut1(0x0AC4C0, M.rf(0xFFFF7720)), cal(0x0CBEDC))
        m_ratelim(M, x, 0xFFFF7724, HI, 0x0CBEE0)
    elif mode in (7, 23, 8):
        pass
    else:
        x = fmin(lut1(0x0AC4C0, M.rf(0xFFFF7720)), cal(0x0CBEDC))
        M.wf(HI, clamp(x, HALF, ONE5))
    M.wb(0xFFFF77B8, r2)
    return mode


# ---------------------------------------------------------------- emulator side
def poke(e, a, n, v):
    o = a - E.RAM_LO
    e.ram[o:o + n] = (v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big')


SENT_R = {8: 0x08080808, 9: 0x09090909, 10: 0x0A0A0A0A, 11: 0x0B0B0B0B, 12: 0x0C0C0C0C,
          13: 0x0D0D0D0D, 14: 0x0E0E0E0E}
SENT_F = {12: 12.25, 13: -13.5, 14: 14.75, 15: -15.125}
EXECUTED = set()
GBR0 = 0xFFFF1234


def run(entry, init, regs=None, fregs=None, stubs=None, rom=ROM):
    e = E.Emu(rom)
    for a, v in init.items():
        poke(e, a, 1, v)
    e.uninit_reads.clear()
    for a, s in (stubs or {}).items():
        e.stub(a, **s)
    rg = dict(SENT_R); rg.update(regs or {})
    fr = dict(SENT_F); fr.update(fregs or {})
    e.gbr = GBR0
    res = e.call(entry, regs=rg, fregs=fr)
    ok(res == 'return', f'{entry:#x} did not return')
    for k, v in SENT_R.items():
        if k not in (regs or {}):
            ok(e.R[k] == v, f'{entry:#x}: r{k} not restored')
    ok(e.R[15] == E.STACK_TOP, f'{entry:#x}: r15 not restored')
    for k, v in SENT_F.items():
        if k not in (fregs or {}):
            ok(e.fr(k) == v, f'{entry:#x}: fr{k} not restored')
    ok(e.gbr == GBR0, f'{entry:#x}: gbr not restored')
    EXECUTED.update(e.executed)
    return e


def compare(e, M, tag):
    got = set(e.writes)
    assert got == M.w, (f'WRITE-SET {tag}\n emu-only {sorted(map(hex, got - M.w))}\n'
                        f' model-only {sorted(map(hex, M.w - got))}')
    for a in M.w:
        assert e.ram[a - E.RAM_LO] == M.m[a], f'VALUE at {a:#x} {tag}: emu {e.ram[a - E.RAM_LO]:#x} model {M.m[a]:#x}'
    assert e.uninit_reads == M.reads, (f'READ-SET {tag}\n emu-only {sorted(map(hex, e.uninit_reads - M.reads))}\n'
                                       f' model-only {sorted(map(hex, M.reads - e.uninit_reads))}')
    CHECKS[0] += 1 + len(M.w)


def ef(e, a): return F(int.from_bytes(e.ram[a - E.RAM_LO:a - E.RAM_LO + 4], 'big'))
def mf(M, a): return F(int.from_bytes(bytes(M.m.get(a + i, 0) for i in range(4)), 'big'))


RNG = random.Random(0xAFC0)


def rf32(lo, hi): return B(RNG.uniform(lo, hi))


# ================================================================= pass A: image facts
def pass_a():
    print('== pass A: image facts')
    tbls = {0x063978: [U0, U1, U2], 0x063984: Q, 0x0639A0: V, 0x0639B0: P, 0x063A04: W}
    for base, cells in tbls.items():
        got = [struct.unpack_from('>I', ROM, base + 4 * i)[0] for i in range(len(cells))]
        ok(got == cells, f'table {base:#x}')
        print(f'   table {base:#08x} -> {", ".join(f"{c:#010x}" for c in cells)}')
    bins = sorted(glob.glob(os.path.join(REPO, 'rom', '*.bin')))
    ok(len(bins) == 20, 'expected 20 bins')
    cal_f = [0x0CBEBC, 0x0CBEC0, 0x0CBEC4, 0x0CBEC8, 0x0CBECC, 0x0CBED0, 0x0CBED4, 0x0CBED8, 0x0CBEDC,
             0x0CBEE0, 0x0CBF30, 0x0CC084, 0x0CC088]
    cal_b = [0x0CBBD8, 0x0CBBD9, 0x0CBBDA, 0x0CBBDB, 0x0CBBE0, 0x0CBBEE]
    recs = [0x0AD620, 0x0AD848, 0x0AC45C, 0x0AD864, 0x0AC484, 0x0AC498, 0x0AC4AC, 0x0ACE0C, 0x0AC470,
            0x0ACE20, 0x0ACE40, 0x0AC4C0]
    sys.path.insert(0, os.path.join(REPO, 'scripts'))
    import desc_types as dt
    spans = []
    for r in recs:
        d = dt.read_table(ROM, r)
        two = dt.is_2d(ROM, r)
        n4 = struct.unpack_from('>H', ROM, r)[0]
        n8 = struct.unpack_from('>H', ROM, r + 2)[0] if two else 1
        ax4 = struct.unpack_from('>I', ROM, r + 4)[0]
        ax8 = struct.unpack_from('>I', ROM, r + 8)[0] if two else None
        cells = struct.unpack_from('>I', ROM, r + (12 if two else 8))[0]
        w = dt.TYPE_SIZES[dt.typecode(ROM, r)]
        spans += [(r, r + (28 if two else 20)), (ax4, ax4 + 4 * n4), (cells, cells + w * n4 * n8)]
        if two:
            spans.append((ax8, ax8 + 4 * n8))
    code = [(0x031D88, 0x031F98 + 170), (0x031F98, 0x0321FC), (0x032042, 0x032204), (0x03286C, 0x032958),
            (0x032958, 0x032AA8), (0x032AA8, 0x032B10), (0x032B10, 0x032CEB), (0x0330CA, 0x033278),
            (0x034C54, 0x034CC8), (0x034E1C, 0x034E38), (0x05D2C0, 0x05D2DA), (0x05D57C, 0x05D588)]
    for b in bins:
        r = open(b, 'rb').read()
        if len(r) != len(ROM):
            continue
        for a in cal_f:
            ok(r[a:a + 4] == ROM[a:a + 4], f'{os.path.basename(b)} cal {a:#x}')
        for a in cal_b:
            ok(r[a] == ROM[a], f'{os.path.basename(b)} cal {a:#x}')
        for lo, hi in spans + code + [(0x063978, 0x063A1C)]:
            ok(r[lo:hi] == ROM[lo:hi], f'{os.path.basename(b)} {lo:#x}..{hi:#x}')
    print(f'   {len(bins)} bins: every calibration word, table record, axis, cell block, pointer table and '
          f'code range below identical to 20.19c (stock rom/ae5l600l.bin included)')
    for a in cal_b:
        print(f'   cal {a:#08x} u8  stock {STOCK[a]:3d}  20.19c {ROM[a]:3d}')
    for a in cal_f:
        print(f'   cal {a:#08x} f32 stock {F(cal(a, STOCK)):<10g} 20.19c {F(cal(a)):<10g} ({cal(a):#010x})')
    for r in recs:
        d = dt.read_table(ROM, r)
        vals = d['values']
        flat = [v for row in vals for v in row] if isinstance(vals[0], list) else vals
        print(f'   rec {r:#08x} {d["type_name"]:7s} {"2-D" if dt.is_2d(ROM, r) else "1-D"} '
              f'range {min(flat):.6g}..{max(flat):.6g}  (identical in stock)')
    # references to the entries
    for ent in (0x031F98, 0x0320AC, 0x03297A, 0x032AA8, 0x032892, 0x03286C, 0x032958, 0x032B5E,
                0x0330CA, 0x033128, 0x0331C6):
        longs = [i for i in range(0, len(ROM) - 3, 2) if struct.unpack_from('>I', ROM, i)[0] == ent]
        brs = []
        for pc in range(max(0, ent - 4200), min(len(ROM), ent + 4200), 2):
            w = struct.unpack_from('>H', ROM, pc)[0]
            if (w >> 12) in (0xA, 0xB):
                d = w & 0xFFF
                d = d - 0x1000 if d & 0x800 else d
                if pc + 4 + 2 * d == ent:
                    brs.append(pc)
        print(f'   entry {ent:#08x}: long occurs at {[hex(x) for x in longs]}  bra/bsr at {[hex(x) for x in brs]}')
    # 0x0329B2 reached only from 0x0329AA
    hits = []
    for pc in range(0x030000, 0x036000, 2):
        w = struct.unpack_from('>H', ROM, pc)[0]
        t = None
        if (w >> 12) in (0xA, 0xB):
            d = w & 0xFFF; d = d - 0x1000 if d & 0x800 else d; t = pc + 4 + 2 * d
        elif (w >> 8) in (0x89, 0x8B, 0x8D, 0x8F):
            d = w & 0xFF; d = d - 0x100 if d & 0x80 else d; t = pc + 4 + 2 * d
        if t == 0x0329B2:
            hits.append(pc)
    ok(hits == [0x0329AA], f'0x0329B2 branch sources {hits}')
    ok(not any(struct.unpack_from('>I', ROM, i)[0] == 0x0329B2 for i in range(0, len(ROM) - 3, 2)), 'long 0x0329B2')
    print('   0x0329B2 is reached only by the bra at 0x0329AA; the long 0x000329B2 occurs nowhere')


# ================================================================= pass B: grids
def chain_inputs(rpm, air, ect=90.0, x40c8=600.0, b6254=0, w67ec=0):
    d = {}
    init_f(d, RPM, B(rpm)); init_f(d, AIR, B(air)); init_f(d, C6350, B(ect))
    init_f(d, A40C8, B(x40c8)); init_b(d, B6254, b6254); init_w(d, D67EC, w67ec)
    return d


def pass_b():
    print('== pass B: per-function grids against the model')
    # 0x03286C e(x)
    xs = [0.0, -0.0, 0.1, 0.2, 0.3, 0.35, 0x3EB33334, 0.36, 0.4, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 5.0, 6.0, 8.0,
          -0.5, -3.0, float('nan'), float('inf')]
    for x in xs + [RNG.uniform(0, 7) for _ in range(150)]:
        xb = x if isinstance(x, int) else B(x)
        e = run(0x03286C, {}, fregs={4: F(xb)})
        M = Mem({}); r = m_e(M, xb)
        compare(e, M, f'e({F(xb)})')
        ok(e.FR[0] == r, f'e({F(xb)}) value')
    print('   0x03286C: 172 points bit-exact against the model; [76E4] written iff x > 0.35')
    # dense deviation scan (review C6): step 1e-3 on [0, 6] plus step 1e-5 on [1.450, 1.464], ROM routine on the
    # emulator, model value asserted equal at every point
    worst, wx, npts = 0.0, None, 0
    for x in [i * 1e-3 for i in range(6001)] + [1.45 + i * 1e-5 for i in range(1401)]:
        xb = B(x)
        e = E.Emu(ROM)
        e.call(0x03286C, fregs={4: F(xb)})
        ok(e.FR[0] == m_e(Mem({}), xb), f'dense e({F(xb)})')
        d = abs(F(e.FR[0]) - math.exp(-F(xb)))
        npts += 1
        if d > worst:
            worst, wx = d, F(xb)
    y1, y2 = F(lut1(0x0ACE20, B(1.0))), F(lut1(0x0ACE20, B(2.0)))
    xp = -math.log(y1 - y2)
    dp = y1 - (xp - 1.0) * (y1 - y2) - math.exp(-xp)       # chord of exp(-x) between the cells at x = 1 and 2
    print(f'   0x03286C dense: {npts} points, max |e(x) - exp(-x)| on [0,6] = {worst:.6f} at x = {wx:.5f}; '
          f'chord between cells {y1:.6f} (x=1) and {y2:.6f} (x=2) peaks at {dp:.6f}, x = {xp:.5f}')
    for x in (0.0, 0.1, 0.35, 0.36, 0.5, 1.0, 2.0, 6.0, 8.0, 50.0):
        M = Mem({}); print(f'      e({x:<4}) = {F(m_e(M, B(x))):.6f}   exp(-x) = {math.exp(-x):.6f}')
    ok(0.02857 < worst < 0.0286 and 1.455 < wx < 1.459, 'e(x) max deviation 0.02858 near x = 1.457')
    ok(abs(worst - dp) < 2e-6, 'the maximum is the chord between the x = 1 and x = 2 cells of 0x0ACE20')
    ok(F(m_e(Mem({}), B(6.0))) == 0.0 and F(m_e(Mem({}), B(50.0))) == 0.0, 'e(x >= 6) = 0 (last cell, axis clamps)')
    # 0x031D88
    for rpm in [0.0, 0.19, 0.1953125, 0x3E480001, 300.0, 800.0, 3000.0, 7000.0, -500.0, float('nan')]:
        rb = rpm if isinstance(rpm, int) else B(rpm)
        d = {}; init_f(d, RPM, rb); init_f(d, T7474, B(-9.0))
        e = run(0x031D88, d); M = Mem(d); m_31D88(M); compare(e, M, f'31D88 {F(rb)}')
    M = Mem(chain_inputs(3000.0, 20.0)); m_31D88(M)
    print(f'   0x031D88: 10 points incl. the 0.1953125 edge; [7474] = 30/[6624], e.g. 3000 -> {mf(M, T7474):.6g}')
    # 0x031DB4
    n = 0
    for rpm in (500.0, 650.0, 1000.0, 2500.0, 3600.0, 6000.0):
        for air in (2.0, 4.0, 15.0, 37.5, 80.0, 200.0):
            for x40 in (400.0, 500.0, 525.0, 550.0, 600.0):
                for b6254 in (0, 1, 2):
                    for u2 in (0, 1):
                        d = chain_inputs(rpm, air, RNG.uniform(-40, 120), x40, b6254, RNG.randrange(65536))
                        init_f(d, T7474, B(30.0 / rpm)); init_b(d, U2, u2)
                        e = run(0x031DB4, d, regs={4: 0x063978, 5: 0}); M = Mem(d); m_31DB4(M)
                        compare(e, M, f'31DB4 {rpm} {air} {x40} {b6254} {u2}'); n += 1
    for r5 in (1, 0x80, 0x100):
        d = chain_inputs(3000.0, 20.0); init_f(d, T7474, B(0.01)); init_b(d, U2, 0)
        e = run(0x031DB4, d, regs={4: 0x063978, 5: r5}); M = Mem(d); m_31DB4(M, r5); compare(e, M, f'31DB4 r5={r5}'); n += 1
    # constant vs table branch of W (review C17): W = 0x0ACE0C(TAU) * 0x0AC470([6350]) * 1.0 * 1.0 = 1.9 when
    # byte [6254] == 1 (cmp/eq #1 on the zero-extended byte) or byte [7700] == 0 after the hysteresis write
    for b6254, x40, want in ((1, 400.0, 1.9), (0x81, 400.0, None), (2, 400.0, None), (0, 600.0, 1.9), (0, 400.0, None)):
        d = chain_inputs(3000.0, 30.0, 90.0, x40, b6254, 0)
        init_f(d, T7474, B(0.01)); init_b(d, U2, 1)
        e = run(0x031DB4, d, regs={4: 0x063978, 5: 0}); M = Mem(d); m_31DB4(M); compare(e, M, f'31DB4 W {b6254} {x40}')
        n += 1
        w = ef(e, U0)
        if want is not None:
            ok(abs(w - want) < 1e-6 and ef(e, X76F4) == 1.0, f'constant-branch W at byte {b6254:#x}, [40C8] {x40}')
        else:
            ok(w == F(lut2(0x0AD864, B(30.0), B(3000.0))), f'table-branch W at byte {b6254:#x}, [40C8] {x40}')
        print(f'   0x031DB4 byte [6254] = {b6254:#04x}, [40C8] = {x40:<5g}: byte [7700] = {e.ram[U2 - E.RAM_LO]}, '
              f'[76F0] = {ef(e, X76F0):.6g}, [76F4] = {ef(e, X76F4):g}, W = [7484] = {w:.6g}')
    print(f'   0x031DB4: {n} cases (rpm x air x [40C8] x byte 6254 x byte 7700, r5 = 0/1/0x80/0x100, W branch cases)')
    # 0x032042
    for u1 in [0.0, 0.001, 0.01, 0.05, 0.1, 0.175, 0.2, 0.5, 1.0, 3.0, -0.1]:
        d = {}; init_f(d, U1, B(u1))
        e = run(0x032042, d, regs={4: 0x0639A0, 5: 0x063978}); M = Mem(d); m_32042(M); compare(e, M, f'32042 {u1}')
        if u1 in (0.01, 0.05, 0.2):
            print(f'   0x032042: U1 = {u1:<5} -> V0 {mf(M, V[0]):.6g} V1 {mf(M, V[1]):.6g} V2 {mf(M, V[2]):.6g} '
                  f'V3 {mf(M, V[3]):.6g}   (-2e(U1) = {-2 * F(m_e(Mem({}), B(u1))):.6g})')
    # 0x031F98
    n = 0
    for t in (0.0, 0.0001, 0.005, 0.01, 0.03, 0.06):
        for L in (0.0, 0.5, 1.0, 1.7, 4.9999997, 5.0, 9.3, 21.99, 40.0, 255.5, 300.0, -3.0):
            for tau in (0.0, 0.0004, 0.00048828125, 0x3A000001, 0.09, 0.2, 0.35, -0.2):
                tb = tau if isinstance(tau, int) else B(tau)
                d = {}
                init_f(d, T7474, B(t)); init_f(d, T7478, B(L)); init_f(d, T747C, B(t * L)); init_f(d, T7480, tb)
                for qq in Q:
                    init_f(d, qq, B(-7.0))
                e = run(0x031F98, d, regs={4: 0x063984}); M = Mem(d); m_31F98(M)
                compare(e, M, f'31F98 {t} {L} {F(tb)}'); n += 1
    print(f'   0x031F98: {n} cases incl. tau at and around the 2^-11 guard, L negative and > 255')


# ================================================================= pass C: 0x0320AC / 0x032892
def pass_c():
    print('== pass C: 0x0320AC / 0x032892 over every dead-time byte')
    shapes = {}
    for nbyte in range(256):
        for trial in range(3):
            d = {}
            q1 = rf32(0.3, 0.99); q5 = rf32(0.0, 0.3); q6 = rf32(0.0, 0.2)
            init_f(d, Q[1], q1); init_f(d, Q[2], ffloat(nbyte)); init_f(d, Q[5], q5); init_f(d, Q[6], q6)
            init_f(d, V[2], rf32(-2.0, -1.0)); init_f(d, V[3], rf32(0.2, 1.0))
            for k in range(4):
                init_f(d, P[k], B(-5.0 - k))
            for k in range(42):
                init_f(d, p4(k), B(100.0 + k))
            e = run(0x0320AC, d, regs={4: 0x0639B0, 5: 0x063984, 6: 0x0639A0}); M = Mem(d)
            sh = m_320AC(M); compare(e, M, f'320AC n={nbyte}')
            shapes.setdefault(tuple(sh[k] for k in range(1, 42)), []).append(nbyte)
    for sh, ns in sorted(shapes.items(), key=lambda kv: kv[1][0]):
        ns = sorted(set(ns))
        rng = f'{ns[0]}' if len(ns) == 1 else (f'{ns[0]}..{ns[-1]}' if ns[-1] - ns[0] + 1 == len(ns) else str(ns))
        s = ' '.join(sh[:8]) + (' ...' if len(sh) > 8 else '')
        calls = [k + 1 for k, x in enumerate(sh) if x == 'call']
        zero0 = next((k + 1 for k, x in enumerate(sh) if x == '0'), None)
        print(f'   n = {rng:<10} P4[1..8]: {s:<40} call at k = {calls}  first zero k = {zero0}')
    ok(len(shapes) == 42, f'{len(shapes)} distinct shapes')
    # guards and edges
    for q5, q6 in ((0.0, 0.0), (0.0002, 0.0002), (0.000244140625, 0.000244140625), (0.0003, 0.0002), (-0.3, 0.1)):
        d = {}
        init_f(d, Q[1], B(0.9)); init_f(d, Q[2], ffloat(6)); init_f(d, Q[5], B(q5)); init_f(d, Q[6], B(q6))
        init_f(d, V[2], B(-1.9)); init_f(d, V[3], B(0.9))
        for k in range(4):
            init_f(d, P[k], B(-5.0 - k))
        e = run(0x0320AC, d, regs={4: 0x0639B0, 5: 0x063984, 6: 0x0639A0}); M = Mem(d); m_320AC(M)
        compare(e, M, f'320AC guard {q5} {q6}')
    # non-integer Q2 (review missed item): 1 < Q2 < 2 gives n = 1 but takes the fmac branch at k = 2, so
    # 0x032892 is never called.  Unreachable from the live chain: 0x031F98 stores Q2 = float(byte).
    for q2, want_call in ((ONE, True), (0x3F800001, False), (B(1.5), False), (0x3FFFFFFF, False), (TWO, True),
                          (B(0.5), True), (B(2.5), True)):
        d = {}
        init_f(d, Q[1], B(0.9)); init_f(d, Q[2], q2); init_f(d, Q[5], B(0.06)); init_f(d, Q[6], B(0.04))
        init_f(d, V[2], B(-1.9)); init_f(d, V[3], B(0.9))
        for k in range(4):
            init_f(d, P[k], B(-5.0 - k))
        for k in range(42):
            init_f(d, p4(k), B(100.0 + k))
        e = run(0x0320AC, d, regs={4: 0x0639B0, 5: 0x063984, 6: 0x0639A0}); M = Mem(d)
        sh = m_320AC(M); compare(e, M, f'320AC Q2={F(q2)}')
        called = any(a in e.writes for a in range(P[1], P[1] + 12))
        ok(called == want_call and ('call' in sh.values()) == want_call, f'320AC Q2={F(q2)} call')
        print(f'   0x0320AC Q2 = {F(q2)!r:<20}: P4[1..4] {" ".join(sh[k] for k in range(1, 5))}  '
              f'0x032892 called: {called}')
    # 0x032892 alone: index paths and guards
    for dv in (0.0, 1.0, 1.5, 2.0, 7.9, 39.0, 39.99, 40.0, 41.0, 1e9, float('nan'), -3.0):
        for a, b1, b2 in ((0.9, 0.07, 0.03), (0.0, 0.0, 0.0), (0.0004, 0.1, 0.0), (0.5, 0.0, 1.0e-5), (0.9, -0.1, 0.09)):
            d = {}
            for k in range(4):
                init_f(d, P[k], B(-5.0 - k))
            for k in range(42):
                init_f(d, p4(k), B(100.0 + k))
            e = run(0x032892, d, regs={4: 0x0639B0}, fregs={4: dv, 5: a, 6: b1, 7: b2}); M = Mem(d)
            r = m_32892(M, B(dv), B(a), B(b1), B(b2)); compare(e, M, f'32892 {dv} {a} {b1} {b2}')
            ok(e.FR[0] == r, '32892 return')
    print('   0x032892: 60 direct cases (index 1 / trunc / 40 paths, NaN, both guards); 0x0320AC guard cases 5')


# ================================================================= pass D: consumer, resets, limits
def pass_d():
    print('== pass D: 0x03297A, the resets, the limit writers')
    n = 0
    for g in range(256):
        for en in (0, 1, 2, 0x81):
            d = {}
            init_b(d, G65F0, g); init_b(d, EN, en)
            init_f(d, R8, rf32(0.5, 1.5))
            for w in W:
                init_f(d, w, rf32(0.5, 1.5))
            if g in (0, 6, 12, 18) or en == 1 or RNG.random() < 0.05:
                e = run(0x03297A, d); M = Mem(d); m_3297A(M); compare(e, M, f'3297A g={g} en={en}'); n += 1
    edge = [(1.0, 1.0), (1.0, 1.00001), (1.2, 1.0), (0.4, 1.0), (1.6, 1.0), (1.0, float('nan')), (1.0, float('inf')),
            (float('nan'), 1.0), (1.4999, 1.5), (0.5, 0.5)]
    for r8, old in edge:
        d = {}; init_b(d, G65F0, 6); init_b(d, EN, 1); init_f(d, R8, B(r8))
        for w in W:
            init_f(d, w, B(old))
        e = run(0x03297A, d); M = Mem(d); m_3297A(M); compare(e, M, f'3297A edge {r8} {old}'); n += 1
    # the r5 != 0 arm of the body (0x0329CE): unreachable from the only entry (r5 = 0 at 0x0329AC); run directly
    d = {}; init_b(d, EN, 1); init_f(d, R8, B(1.3))
    for w in W:
        init_f(d, w, B(0.9))
    e = run(0x0329B2, d, regs={4: 0x063A04, 5: 1})
    ok(set(e.writes) == {w + i for w in W for i in range(4)} and all(ef(e, w) == 1.0 for w in W), '0329B2 r5=1')
    ok(e.uninit_reads == set(), '0329B2 r5=1 reads nothing')
    n += 1
    print(f'   0x03297A: {n} cases (all 256 gate bytes, EN in 0/1/2/0x81, snap and non-finite edges; '
          f'body entered directly with r5 = 1 -> three 1.0 writes, no RAM read)')
    # step response of the filters
    d = {}; init_b(d, G65F0, 0); init_b(d, EN, 1); init_f(d, R8, B(1.2))
    for w in W:
        init_f(d, w, ONE)
    M = Mem(d)
    steps = {}
    for i in range(1, 801):
        M.w.clear(); m_3297A(M)
        if i in (1, 10, 64, 128, 400, 800):
            steps[i] = [round(mf(M, w), 6) for w in W]
    print('   filter step 1.0 -> R8 = 1.2 (per call):', steps)
    # 0x034C54, the only reader of [7708] besides 0x03297A (review C33)
    n = hits = 0
    for c787e in (0, 1, 5, 0x90):
        for c789e in (0, 19, 20, 0x85):
            for en in (0, 1, 0x81):
                for b7453 in (0, 1):
                    for w1 in (0.9, 0.95, 0x3F733334, 1.0, 0x3F866665, 1.05, 1.2, float('nan')):   # 0.95/1.05 and the floats just inside
                        d = {}
                        init_b(d, 0xFFFF787E, c787e); init_b(d, 0xFFFF789E, c789e); init_b(d, EN, en)
                        init_b(d, 0xFFFF7453, b7453)
                        init_f(d, 0xFFFF7708, w1 if isinstance(w1, int) else B(w1))
                        e = run(0x034C54, d); M = Mem(d); flag = m_34C54(M); compare(e, M, f'34C54 {c787e} {c789e} {en} {b7453} {w1}')
                        n += 1; hits += flag
    ok(F(cal(0x0CC084)) == F(B(0.95)) and F(cal(0x0CC088)) == F(B(1.05)) and ROM[0x0CBBEE] == 20, '34C54 cal')
    print(f'   0x034C54: {n} cases ({hits} window hits): window 0.95 < [7708] < 1.05 strict, needs bytes [7448] == 1 and '
          f'[7453] == 1, then byte [787E] -= 1 if non-zero; before it, [789E] counts to cal byte 0x0CBBEE = 20 '
          f'while [787E] > 0, then [787E] = 0; [789E] = 0 when [787E] == 0')
    # 0x032AA8 / 0x032958
    for g in range(256):
        d = {}; init_b(d, G65F6, g); init_f(d, 0xFFFF7348, B(3.25))
        e = run(0x032AA8, d); M = Mem(d); m_32AA8(M); compare(e, M, f'32AA8 {g}')
        e = run(0x032958, d); M = Mem(d); m_32958(M); compare(e, M, f'32958 {g}')
    M = Mem({G65F6: 1}); m_32AA8(M)
    print('   0x032AA8 / 0x032958: all 256 bytes of [65F6]; body runs only for 0x01.  0x032AA8 writes:')
    print('     ' + ', '.join(f'{a:#x}={mf(M, a):g}' for a in (0xFFFF7710, 0xFFFF7714, 0xFFFF7718, 0xFFFF771C,
                                                              0xFFFF7724, 0xFFFF7728, 0xFFFF772C, 0xFFFF7730,
                                                              0xFFFF77A8)) +
          f', bytes 77B6/77B8 = 0, [7734..77A4] (29 floats) = [7348]')
    # 0x0331C6
    for ect in (-40.0, 20.0, 90.0, 130.0):
        for b in (0.0, -1.0, -0.5, 0.25, 1.0, float('nan')):
            d = {}; init_f(d, C6350, B(ect)); init_f(d, 0xFFFF7BE4, B(b))
            e = run(0x0331C6, d); M = Mem(d); m_331C6(M); compare(e, M, f'331C6 {ect} {b}')
    M = Mem({}); init = {}; init_f(init, C6350, B(90.0)); init_f(init, 0xFFFF7BE4, ZERO); M = Mem(init); m_331C6(M)
    print(f'   0x0331C6: 24 cases; with [7BE4] = 0: [772C] = {mf(M, 0xFFFF772C):.7g}, [7730] = {mf(M, 0xFFFF7730):.7g}')
    # 0x0330CA / 0x033128
    n = 0
    for entry, tgt, cell, k in ((0x0330CA, 0xFFFF7724, HI, 0x0CBEE0), (0x033128, 0xFFFF7728, LO, 0x0CBF30)):
        for x in (0.3, 0.75, 1.0, 1.1015625, 1.25, 2.0, float('nan')):
            for cur in (1.0, 0.6, 1.4, 0.5, 1.5):
                for cap in (1.0, 1.4285713, 0.6, 1.5):
                    for v77c8 in (1.0, 0.9, 1.1):
                        d = {}
                        init_f(d, cell, B(cur)); init_f(d, 0xFFFF7730, B(cap)); init_f(d, 0xFFFF77C8, B(v77c8))
                        init_f(d, AIR, B(20.0)); init_f(d, 0xFFFF68D8, B(RNG.choice([0.0, 0.5, -0.3])))
                        init_f(d, 0xFFFF7BE4, B(RNG.choice([0.0, 0.02, -0.03])))
                        e = run(entry, d, fregs={4: x}); M = Mem(d); m_ratelim(M, B(x), tgt, cell, k)
                        compare(e, M, f'{entry:#x} {x} {cur} {cap}'); n += 1
                        r = mf(M, cell)
                        ok(r <= cur + 0.25 + 1e-6, 'upward step <= 0.25')
                        ok(r >= min(cur - 0.25, max(F(B(cap)), 0.5)) - 1e-6, 'downward step <= 0.25 unless the cap is lower')
                        ok(r <= max(F(B(cap)), 0.5), 'capped by [7730] (floor 0.5)')
    print(f'   0x0330CA / 0x033128: {n} cases (old bound in [0.5, 1.5]); upward step <= 0.25 (cal 0x0CBEE0 / '
          f'0x0CBF30), downward <= 0.25 unless [7730] is lower, result <= max([7730], 0.5)')
    # the +-0.25 limit is applied BEFORE the min with [7730] and the final [0.5, 1.5] clamp (review missed item):
    # count the calls whose net move exceeds 0.25, and show the two mechanisms
    big = tot = 0
    for entry, tgt, cell, k in ((0x0330CA, 0xFFFF7724, HI, 0x0CBEE0), (0x033128, 0xFFFF7728, LO, 0x0CBF30)):
        for x in (0.3, 0.75, 1.0, 1.25, 2.0):
            for cur in (1.0, 0.6, 1.4, 0.5, 1.5, 0.1, 1.9):
                for cap in (1.0, 1.4285713, 0.6, 1.5):
                    d = {}
                    init_f(d, cell, B(cur)); init_f(d, 0xFFFF7730, B(cap)); init_f(d, 0xFFFF77C8, ONE)
                    init_f(d, AIR, B(20.0)); init_f(d, 0xFFFF68D8, ZERO); init_f(d, 0xFFFF7BE4, ZERO)
                    e = run(entry, d, fregs={4: x}); M = Mem(d); m_ratelim(M, B(x), tgt, cell, k)
                    compare(e, M, f'{entry:#x} net {x} {cur} {cap}')
                    r = ef(e, cell); tot += 1
                    if abs(r - cur) > 0.25 + 1e-6:
                        big += 1
                        if cur in (0.5, 0.6, 1.0, 1.4, 1.5):
                            ok(F(B(cap)) < cur - 0.25 and r == max(F(B(cap)), 0.5), 'in-range old bound: only the cap moves it > 0.25')
                    if (entry, x, cur, cap) == (0x0330CA, 2.0, 1.4, 0.6):
                        ok(r == F(B(0.6)), 'HI 1.4 -> 0.6 in one call when [7730] = 0.6')
                    if (entry, x, cur, cap) == (0x0330CA, 0.3, 0.1, 1.0):
                        ok(r == 0.5, 'old HI 0.1 -> 0.5 (final clamp) in one call')
    print(f'   net move > 0.25 in {big} of {tot} calls: with the old bound in [0.5, 1.5] only through the cap '
          f'(e.g. HI 1.4 -> 0.6 with [7730] = 0.6); an old bound outside [0.5, 1.5] is pulled in by the final clamp '
          f'(0.1 -> 0.5, 1.9 -> 1.5)')
    # 0x032B5E: every mode
    n = 0; seen = set()
    for cnt in (0, 1, 3):
        for en in (0, 1, 2):
            for r2 in (0, 1, 2):
                for prev in (0, 1):
                    for b7828 in (0, 1):
                        for x7720 in (0.0, 50.0, 100.0, 300.0):
                            d = {}
                            init_b(d, 0xFFFF77B6, cnt); init_b(d, EN, en); init_b(d, 0xFFFF77B8, prev)
                            init_b(d, 0xFFFF7828, b7828); init_f(d, 0xFFFF7720, B(x7720))
                            init_f(d, HI, B(1.05)); init_f(d, 0xFFFF770C, B(1.0)); init_f(d, 0xFFFF7730, B(1.3))
                            init_f(d, 0xFFFF77C8, ONE); init_f(d, AIR, B(20.0)); init_f(d, 0xFFFF68D8, ZERO)
                            init_f(d, 0xFFFF7BE4, ZERO)
                            e = run(0x032B5E, d, stubs={0x074A54: {'r0': r2}}); M = Mem(d)
                            mode = m_32B5E(M, r2); seen.add(mode)
                            compare(e, M, f'32B5E cnt={cnt} en={en} r2={r2} prev={prev} 7828={b7828}'); n += 1
    print(f'   0x032B5E: {n} cases, modes seen {sorted(seen)} (0x074A54 stubbed: its r0 is an input here)')
    for x in (0.0, 32.0, 64.0, 96.0, 256.0):
        print(f'      default-mode HI with [7720] = {x:<5}: {F(fmin(lut1(0x0AC4C0, B(x)), cal(0x0CBEDC))):.7g}')
    # 0x032B10 gate (0x032E28 stubbed)
    for g in range(256):
        d = {}; init_b(d, G65F0, g); init_f(d, A40C8, B(77.0)); init_f(d, C6350, B(90.0)); init_f(d, 0xFFFF7BE4, ZERO)
        init_b(d, 0xFFFF77B6, 1)
        e = run(0x032B10, d, stubs={0x032E28: {'r0': 0}, 0x074A54: {'r0': 0}})
        hit = g in (0, 6, 12, 18)
        ok((0xFFFF7720 in e.writes) == hit, f'32B10 gate {g}')
        if hit:
            ok(ef(e, 0xFFFF7720) == 77.0, '7720 = 40C8')
    print('   0x032B10: all 256 gate bytes; [7720] = [40C8] and the three callees only for 0x00/0x06/0x0C/0x12')


# ================================================================= pass E: live chain
def chain_emu(e, rpm, air, ect=90.0, x40c8=600.0, b6254=0, target=1.0, meas=1.0):
    for a, v in ((RPM, rpm), (AIR, air), (C6350, ect), (A40C8, x40c8), (0xFFFF77C8, target), (0xFFFF653C, meas)):
        e.ram_f32(a, v)
    e.ram_u8(B6254, b6254); e.ram_u16(D67EC, 0); e.ram_u8(G65F0, 0)
    e.gbr = GBR0
    e.steps = 0                                # the emulator's step counter is cumulative per Emu object
    res = e.call(0x031D1E, regs=dict(SENT_R), fregs=dict(SENT_F))
    ok(res == 'return', 'chain return')
    EXECUTED.update(e.executed)


EQ_POINTS = ((800.0, 4.0, 600.0), (1500.0, 10.0, 600.0), (2500.0, 20.0, 600.0), (3000.0, 30.0, 600.0),
             (3000.0, 30.0, 400.0), (4000.0, 60.0, 600.0), (6000.0, 120.0, 600.0))
EQ_MAX = 1500
LIVE_E = []


def pinned_emu():                              # LO = HI = 1.0 as 0x032AA8 leaves them, R8 = R12 = 1.0
    e = E.Emu(ROM)
    for a in range(0xFFFF7400, 0xFFFF7800, 4):
        e.ram_u32(a, 0)
    for a in (0xFFFF63C4, 0xFFFF6624, 0xFFFF93E4, 0xFFFF9418, 0xFFFF7904, 0xFFFF77D8, 0xFFFF781C, 0xFFFF77E4,
              0xFFFF77DC, 0xFFFF6540):
        e.ram_f32(a, 0.0)
    for a in (0xFFFF94B1, 0xFFFF94B9, 0xFFFF94B3):
        e.ram_u8(a, 0)
    e.ram_u8(EN, 1); e.ram_f32(LO, 1.0); e.ram_f32(HI, 1.0); e.ram_f32(0xFFFF76D4, 1.0); e.ram_f32(0xFFFF76FC, 1.0)
    return e


def equilibrium_emu(rpm, air, x40):            # pass E start state: warm-up at no error, then R8 = R12 = 1, history 0
    e = E.Emu(ROM)
    for a in range(0xFFFF7400, 0xFFFF7800, 4):
        e.ram_u32(a, 0)
    for a in (0xFFFF6540, 0xFFFF7448, 0xFFFF94B1, 0xFFFF94B9, 0xFFFF94B3):
        e.ram_u32(a & ~3, 0)
    e.ram_u8(EN, 1)
    e.ram_f32(LO, 0.75); e.ram_f32(HI, 1.25)
    e.ram_f32(0xFFFF76D4, 1.0); e.ram_f32(0xFFFF76FC, 1.0)
    for a in (0xFFFF63C4, 0xFFFF6624, 0xFFFF93E4, 0xFFFF9418, 0xFFFF7904, 0xFFFF77D8, 0xFFFF781C, 0xFFFF77E4,
              0xFFFF77DC):
        e.ram_f32(a, 0.0)
    chain_emu(e, rpm, air, x40c8=x40, target=1.0, meas=1.0)
    e.ram_f32(0xFFFF76D4, 1.0); e.ram_f32(0xFFFF76FC, 1.0)
    for k in range(41):
        e.ram_u32(0xFFFF7630 + 4 * k, 0)
    return e


def pass_e():
    print('== pass E: the live chain 0x031D1E -> 0x032204 (real callees, gate byte 0x00)')
    rows = []
    for rpm, air, x40 in ((800.0, 4.0, 600.0), (1500.0, 10.0, 600.0), (2500.0, 20.0, 600.0), (3000.0, 30.0, 600.0),
                          (3000.0, 30.0, 400.0), (4000.0, 60.0, 600.0), (6000.0, 120.0, 600.0)):
        e = E.Emu(ROM)
        for a in range(0xFFFF7400, 0xFFFF7800, 4):
            e.ram_u32(a, 0)
        for a in (0xFFFF6540, 0xFFFF7448, 0xFFFF94B1, 0xFFFF94B9, 0xFFFF94B3):
            e.ram_u32(a & ~3, 0)
        e.ram_u8(EN, 1)                        # EN = 1, F1 = F2 = 0 -> FLAG 0; R15 = 0 -> block C
        e.ram_f32(LO, 0.75); e.ram_f32(HI, 1.25)
        e.ram_f32(0xFFFF76D4, 1.0); e.ram_f32(0xFFFF76FC, 1.0)
        for a in (0xFFFF63C4, 0xFFFF6624, 0xFFFF93E4, 0xFFFF9418, 0xFFFF7904, 0xFFFF77D8, 0xFFFF781C, 0xFFFF77E4,
                  0xFFFF77DC):
            e.ram_f32(a, 0.0)
        chain_emu(e, rpm, air, x40c8=x40, target=1.0, meas=1.0)      # warm-up: R11 := R2, coefficients set
        e.ram_f32(0xFFFF76D4, 1.0); e.ram_f32(0xFFFF76FC, 1.0)       # R8 = R12 = 1.0, history R7 = 0
        for k in range(41):
            e.ram_u32(0xFFFF7630 + 4 * k, 0)
        q = [ef(e, a) for a in Q]; v = [ef(e, a) for a in V]
        n = int(q[2])
        p0, p2 = ef(e, P[0]), ef(e, P[2])
        p4v = [ef(e, p4(k)) for k in range(1, 42)]
        # constant error: target 1/1.0, measured 1/1.05 -> R1 - R0 = 1 - 1/1.05
        hist = []
        for i in range(300):
            chain_emu(e, rpm, air, x40c8=x40, target=1.0, meas=1.05)
            hist.append(ef(e, 0xFFFF76D4))
        rows.append((rpm, air, x40, ef(e, T7474), ef(e, T7478), ef(e, T7480), ef(e, U0), n, q[1], q[5], q[6], v[2], v[3],
                     p0, p2, p4v, hist))
    for (rpm, air, x40, t, L, tau, w, n, a, b1, b2, A, Bq, p0, p2, p4v, hist) in rows:
        nz = [k + 1 for k, x in enumerate(p4v[:40]) if x != 0.0]
        print(f'   rpm {rpm:<6g} [63C4] {air:<5g} [40C8] {x40:<4g}: T=[7474] {t:.6g}  L=[7478] {L:.6g}  '
              f'tau=[7480] {tau:.6g}  w=[7484] {w:.6g}  n={n}')
        print(f'      Q1 {a:.6g} Q5 {b1:.6g} Q6 {b2:.6g} | V2 {A:.6g} V3 {Bq:.6g} | P0 {p0:.6g}  P2 {p2:.6g}  '
              f'P4 nonzero k = {nz[0]}..{nz[-1]}  P4[1] {p4v[0]:.6g} P4[n+1] {p4v[n]:.6g}')
        print(f'      R8 after 1, 2, 5, 10, 20, 60, 150, 300 calls with 1/target - 1/measured = {1 - 1 / 1.05:.6f}: '
              f'{", ".join(f"{hist[i]:.6f}" for i in (0, 1, 4, 9, 19, 59, 149, 299))}')
        ok(p0 > 0, 'P0 positive')
        e1 = 1.0 - F(B(1.0 / 1.05))                     # R1 - R0 on the first error call (= -(R2 - R11))
        ok(abs((hist[0] - 1.0) - (p0 * e1 - p2 * e1)) < 2e-6, 'first increment = P0*e + P2*dR2 (empty history)')
        ok(hist[-1] > 1.0 and (hist[-1] > hist[-11] or hist[-1] == 1.25), 'R8 integrates a positive error upward')
        ok(all(0.75 <= x <= 1.25 for x in hist), 'R8 stays inside [LO, HI] = [0.75, 1.25]')
        ok(nz[-1] == n + 1 and nz[0] == 1, 'P4 support 1..n+1')
    # pinned: LO = HI = 1.0 as left by 0x032AA8
    e = pinned_emu()
    vals = []
    for i in range(30):
        chain_emu(e, 3000.0, 30.0, target=1.0, meas=1.0 if i == 0 else 0.8)
        vals.append(ef(e, 0xFFFF76D4))
    ok(all(x == 1.0 for x in vals), 'pinned')
    print(f'   LO = HI = 1.0 (the 0x032AA8 reset values), 30 calls (1 with no error, then 29 with error 1 - 1/0.8): '
          f'R8 = {sorted(set(vals))} on every call')
    # review C20: reopening the bounds after that pinned history and applying 0.95 for 10 calls gave 0.939768 --
    # but the same history followed by NO error (1.00) or a LEAN error (1.05) also ends below 1: the drop is the
    # stored history of the pinned calls, not the rich error.  The run is kept only as this control.
    after = {}
    for meas in (0.95, 1.00, 1.05):
        e = pinned_emu()
        for i in range(30):
            chain_emu(e, 3000.0, 30.0, target=1.0, meas=1.0 if i == 0 else 0.8)
        e.ram_f32(LO, 0.75); e.ram_f32(HI, 1.25)
        for i in range(10):
            chain_emu(e, 3000.0, 30.0, target=1.0, meas=meas)
        after[meas] = ef(e, 0xFFFF76D4)
    ok(after[1.00] < 1.0 and after[1.05] < 1.0, 'post-pinned drop is the history, not the error sign')
    print('   after that pinned history, bounds reopened to [0.75, 1.25], 10 calls at measured 0.95 / 1.00 / 1.05: '
          f'R8 = {after[0.95]:.6f} / {after[1.00]:.6f} / {after[1.05]:.6f} (all < 1: confounded, not a sign test)')
    # sign tests from equilibrium (R8 = R12 = 1, history 0, warm-up call at no error), each point, both signs
    print('   from equilibrium, constant measured 1.05 (lean) / 0.95 (rich) vs target 1.0, LO = 0.75, HI = 1.25:')
    for rpm, air, x40 in EQ_POINTS:
        res = {}
        for meas in (1.05, 0.95):
            e = equilibrium_emu(rpm, air, x40)
            p0, p2 = ef(e, P[0]), ef(e, P[2])
            h = []
            while len(h) < EQ_MAX:
                e.steps = 0
                chain_emu(e, rpm, air, x40c8=x40, target=1.0, meas=meas)
                h.append(ef(e, 0xFFFF76D4))
                if meas == 1.05 and h[-1] == 1.25:
                    break
                if meas == 0.95 and len(h) >= 300 and min(h) < 1.0:
                    break
            res[meas] = (p0, p2, h)
        p0, p2, hl = res[1.05]
        hr = res[0.95][2]
        e_r = F(B(1.0 / 0.95)) - 1.0                     # R0 step on the first rich call (R1 - R0 = -e_r)
        ok(abs((hr[0] - 1.0) - (p2 - p0) * e_r) < 2e-6, 'first rich increment = (P2 - P0) * e')
        ok((hr[0] > 1.0) == (p2 > p0), 'first rich move is upward exactly where P2 > P0')
        below = next((i + 1 for i, x in enumerate(hr) if x < 1.0), None)
        ok(below is not None, 'rich error takes R8 below 1 within the run')
        hi_at = len(hl) if hl[-1] == 1.25 else None
        LIVE_E.append((rpm, air, x40, p0, p2, hl[0], hi_at, hl[-1], len(hl), hr[0], max(hr), below, hr[299]))
        print(f'      rpm {rpm:<5g} [63C4] {air:<4g} [40C8] {x40:<4g} P0 {p0:.6g} P2 {p2:<10.6g} lean: R8[1] {hl[0]:.6f}, ' +
              (f'HI = 1.25 first at call {hi_at}' if hi_at else f'HI not reached, R8[{len(hl)}] = {hl[-1]:.6f}') +
              f' | rich: R8[1] {hr[0]:.6f}, '
              f'max {max(hr):.6f}, first < 1 at call {below}, R8[300] {hr[299]:.6f}')
    ok(sum(1 for r in LIVE_E if r[6] is not None) >= 6, 'lean error reaches HI at (nearly) every point')


# ================================================================= pass F: coverage
FUNCS = {0x031D88: 0x031DB4, 0x031DB4: 0x031EE2, 0x031F98: 0x032042, 0x032042: 0x0320AC, 0x0320AC: 0x0321F0,
         0x03286C: 0x032892, 0x032892: 0x032926, 0x032958: 0x03297A, 0x03297A: 0x032A5A, 0x032AA8: 0x032B10,
         0x032B10: 0x032B5A, 0x032B5E: 0x032C72, 0x0330CA: 0x033128, 0x033128: 0x033186, 0x0331C6: 0x033200,
         0x034C54: 0x034CC8}
DEAD = {  # addresses no reachable input executes (listed in the trace as dead)
}


def pass_f():
    print('== pass F: instruction coverage')
    sys.path.insert(0, os.path.join(REPO, 'scripts'))
    import sh2e_disasm as D
    total = miss = 0
    missing = {}
    for lo, hi in FUNCS.items():
        # walk the fn_dump-style instruction list: every 2-byte word from lo to hi that is not a pool word
        lines = [x for x in D.disasm(ROM, lo, hi)]
        pcs = [x[0] for x in lines]
        pool = set()
        for x in lines:
            txt = x[2]
            if '@(0x' in txt and ('mov.l' in txt or 'mov.w' in txt or 'mova' in txt):
                t = int(txt.split('@(0x')[1].split(')')[0], 16)
                pool.update(range(t, t + (2 if 'mov.w' in txt else 4)))
        code = [pc for pc in pcs if pc not in pool]
        m = [pc for pc in code if pc not in EXECUTED]
        total += len(code); miss += len(m)
        if m:
            missing[lo] = m
    for lo, m in missing.items():
        print(f'   {lo:#08x}: not executed {[hex(x) for x in m]}')
    print(f'   {total - miss} of {total} instruction addresses executed')
    return missing


# ================================================================= pass G: logged AFC (data, not bytes)
LOGS = ['logs/11-20 20.19c/1120 20.19c.csv', 'logs/7-29 20.19c/7-29 20.19c.csv']


def pass_g():
    print('== pass G: logged AFC in the 20.19c logs (skipped if a log is absent)')
    import csv
    # what a logged AFC value says about R8 (review C35): SSM id 0x009 is served by getter 0x05D2C0
    # (stub_tables_trace.txt, verified): byte = sat8(trunc(((R8 - 1) + 1) / 0.0078125 + 0.5)); the logger shows
    # (byte - 128) * 100 / 128 (logs/logcfg.txt, paramid 0x000009).  So a logged value pins R8 to +-1/256.
    cfg = open(os.path.join(REPO, 'logs', 'logcfg.txt')).read()
    ok('paramname = AFC\nparamid = 0x000009\nscalingrpn = x,128,-,100,*,128,/' in cfg, 'logcfg AFC scaling')
    b_lo = B(95.5 / 128); b_hi = B(96.5 / 128)
    for r8b, want in ((b_lo - 1, 95), (b_lo, 96), (B(0.75), 96), (b_hi - 1, 96), (b_hi, 97), (B(1.203125), 154),
                      (B(0.5), 64), (B(1.5), 192)):
        e = E.Emu(ROM); e.ram_u32(R8, r8b)
        ok(e.call(0x05D2C0) == 'return' and (e.R[0] & 0xFF) == want, f'getter 0x05D2C0 at R8 = {F(r8b)!r}')
    print('   getter 0x05D2C0: R8 in [95.5/128, 96.5/128) -> byte 96 -> AFC -25.0 %; R8 1.203125 -> 154 -> +20.3125 %; '
          'R8 0.5 / 1.5 -> 64 / 192 (-50 / +50 %)')
    for rel in LOGS:
        path = os.path.join(REPO, rel)
        if not os.path.exists(path):
            print(f'   {rel}: not present, skipped')
            continue
        by = {}
        with open(path, newline='') as fh:
            for row in csv.DictReader(fh):
                try:
                    v = float(row['AFC']); m = row.get('CL/OL', '?')
                except (KeyError, ValueError):
                    continue
                by.setdefault(m, []).append(v)
        allv = [v for vs in by.values() for v in vs]
        steps = {round(v / 0.78125, 3) % 1 for v in allv}
        ok(all(abs(x) < 1e-6 or abs(x - 1) < 1e-6 or abs(x - 0.0) < 0.0011 or abs(x - 1) < 0.0011 for x in steps),
           f'{rel}: every AFC value is a multiple of 100/128 (to the logger rounding)')
        ok(min(allv) >= -50.0 and max(allv) <= 50.0, 'inside the 0.5..1.5 outer clamp (+-50 %)')
        print(f'   {rel}: {len(allv)} rows, AFC {min(allv):+.4f} .. {max(allv):+.4f} % '
              f'(R8 to the nearest 1/128, via 0x05D2C0: {1 + min(allv) / 100:.6f} .. {1 + max(allv) / 100:.6f}); distinct values '
              f'{len(set(allv))}')
        for m in sorted(by, key=lambda x: (len(x), x)):
            vs = by[m]
            print(f'      CL/OL = {m:>3}: {len(vs):6d} rows  min {min(vs):+9.5f}  max {max(vs):+9.5f}  '
                  f'nonzero {sum(1 for v in vs if v != 0.0):6d}')


def main():
    pass_a()
    pass_b()
    pass_c()
    pass_d()
    pass_e()
    missing = pass_f()
    ok(not missing, 'coverage')
    pass_g()
    print(f'ALL PASSED: {CHECKS[0]} checks')


if __name__ == '__main__':
    main()
