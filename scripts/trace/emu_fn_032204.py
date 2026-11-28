#!/usr/bin/env python3
"""Emulation check for ROM function 0x032204..0x03286C (748 instructions) and its
only entry, the tail branch at 0x031D7A in 0x031D1E.

    python3 scripts/trace/emu_fn_032204.py

Reference bin: rom/AE5L600L 20g rev 20.19c.bin  md5 92cae8275cd4f9b473a3a9e36efe6449
Trace:         disassembly/analysis/fn_032204_trace.txt

What it does
------------
Runs 0x032204 in scripts/sh2e_emu.py against a Python model written from the
bytes and asserts, per case:

  * every RAM byte the call writes, bit for bit
  * the exact SET of non-stack RAM bytes written (nothing else is touched)
  * the exact SET of RAM cells read before being written in the same call
    (inputs are poked WITHOUT marking them initialised, so every input read
    lands in emu.uninit_reads -- that is the function's true input list)
  * callee-saved state r8-r14, r15, fr12-fr15 restored

Passes:
  A. the gate and the arguments: 0x031D1E for all 256 values of byte 0xFFFF65F0,
     callees stubbed; 0x032204 is reached with r4=0x0639C4 r5=0x0639B0
     r6=0x063984 r7=0 exactly when the byte equals one of cal 0x0CBBD8..0x0CBBDB
  B. calibration facts over all 20 bins under rom/: byte 0x0CBBDF = 0,
     float 0x0C5298 = 0.0, descriptor 0x0ABEE4 and its axes/data identical,
     the three pointer tables identical, the code bytes identical
  C. control grid on the LIVE configuration (real ROM, r7 = 0): the six
     selector bytes over {0,1,2}/{0,1,5}, 729 combinations, random floats
  D. the two configurations this calibration never runs, emulated so the
     trace can say what they would do: 0x0CBBDF = 1 (in-memory ROM copy,
     the file is never written) and r7 != 0 (direct call; the only caller
     passes r7 = 0)
  E. float edges: the +-2^-13 reciprocal windows, the clamp ends, the index
     rounding/clamp of the delay index (0x0CBBDF = 1 copy only), the tail
     window between the clamped result and its unclamped target
  F. the 2-D lookup 0x0BE8E4 on descriptor 0x0ABEE4 returns
     1966/65536 = 0.029998779296875 over a grid of finite axis inputs and
     over +-inf / NaN on either axis
  G. every one of the 748 instruction addresses is executed by A-E
  H. 0x031C9C (the other writer of the R cells) with the real 0x022F92, for
     all 256 values of byte 0xFFFF65F6: exact write set and values
  I. a 108-call sequence of 0x032204 on ONE emulator (state carried between
     calls, started by the real 0x031C9C): R7 indexing at the end of a call vs
     the start of the next, the v recurrence, R8_n = sat(R8_(n-1) + v_n), and
     which block transitions cut the history
  J. byte facts used by the COMPARISON / NOT ESTABLISHED sections: the FBKC
     function's GBR, every occurrence of the longs 0xFFFF76D4 / 0xFFFF7494, and
     the find_writers hits in 0xFFFF7570..0xFFFF7703 outside 0x031C9C being the
     low halves of literal-pool longs

ROUNDING. fadd/fsub/fmul/fdiv are modelled as the exact result rounded TOWARD
ZERO and fmac as fused (one rounding), as sh2e_emu does since corrections item
106. Only sh2e_emu.rz_bits/f2b/b2f are shared with the emulator; the control
flow, the order of operations and every helper (0x0BE56C 0x0BE5A8 0x0BE608
0x0BE628 0x0BE970) are modelled independently from their verified CONTRACT
sections. No claim in the trace depends on the last bit of a float.

Names here are neutral on purpose: nothing in this function establishes what
any of these RAM cells physically is.
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
ROM_X = bytearray(ROM)
ROM_X[0x0CBBDF] = 1               # in-memory copy only: the block this calibration never runs
ROM_X = bytes(ROM_X)

ENTRY, END = 0x032204, 0x03286C
CALLER = 0x031D1E
POOLS = [(0x03238C, 0x03238E), (0x03243A, 0x0324A8), (0x032734, 0x032754)]
TBL_R, TBL_P, TBL_Q = 0x0639C4, 0x0639B0, 0x063984
DESC = 0x0ABEE4
CAL_SEL, CAL_C = 0x0CBBDF, 0x0C5298

# ---- stack-parked direct RAM inputs (pool words 0x03243C..0x03249C), byte cells marked
X2D, Y2D = 0xFFFF63C4, 0xFFFF6624          # -> r15+184, r15+188 (2-D lookup axes A, B)
U0 = 0xFFFF653C                            # fr14 (r7 == 0)
V = 0xFFFF77C8                             # r15+192
A_ = 0xFFFF7904                            # r15+196
M1, M2 = 0xFFFF77D8, 0xFFFF781C            # r15+200, fr15
E_ = 0xFFFF77E4                            # r15+204
D0 = 0xFFFF77DC                            # fr13
EN = 0xFFFF7448                            # byte -> r15+208
LO, HI = 0xFFFF7714, 0xFFFF7710            # r15+212, r15+216 (clamp bounds)
S1, S2 = 0xFFFF93E4, 0xFFFF9418            # r15+220, r15+224
F1, F2, SEL = 0xFFFF94B1, 0xFFFF94B9, 0xFFFF94B3   # bytes: r12, r11, r15+228
D1, D2, D3 = 0xFFFF7800, 0xFFFF77F8, 0xFFFF7820    # read only when 0x0CBBDF == 1

# ---- pointer tables in ROM (resolved from the caller's r4/r5/r6)
R = [0xFFFF7570, 0xFFFF7574, 0xFFFF7578, 0xFFFF757C, 0xFFFF7624, 0xFFFF7628, 0xFFFF762C, 0xFFFF7630,
     0xFFFF76D4, 0xFFFF76D8, 0xFFFF76DC, 0xFFFF76F8, 0xFFFF76FC, 0xFFFF76E0, 0xFFFF7701, 0xFFFF7702]
P = [0xFFFF74B8, 0xFFFF74BC, 0xFFFF74C0, 0xFFFF74C4, 0xFFFF74C8]
Q = [0xFFFF748C, 0xFFFF7490, 0xFFFF7494, 0xFFFF7498, 0xFFFF749C, 0xFFFF74A0, 0xFFFF74A4]
R3N, R7N, P4N = 42, 41, 42                 # array lengths (R3: shift 41..1 + [n+1]; R7: 41; P4: init loop 42)

for base, tbl in ((TBL_R, R), (TBL_P, P), (TBL_Q, Q)):
    got = [struct.unpack_from('>I', ROM, base + 4 * i)[0] for i in range(len(tbl))]
    assert got == tbl, (hex(base), [hex(g) for g in got])

ZERO, ONE, HALF, ONE5, FORTY = 0x00000000, 0x3F800000, 0x3F000000, 0x3FC00000, 0x42200000
EPS = 0x39000000                           # 2^-13, pool 0x032484 / 0x032734 / 0x032938
LUT_CONST = 0.029998779296875              # 1966 / 65536
FLT_MAX = 0x7F7FFFFF


def F(b):
    return E.b2f(b)


def B(x):
    return E.f2b(x)


def rz(op, xb, yb):
    """One fadd/fsub/fmul/fdiv as the SH7058 computes it: exact, rounded toward zero."""
    x, y = F(xb), F(yb)
    ap = {'+': lambda a, b: a + b, '-': lambda a, b: a - b,
          '*': lambda a, b: a * b, '/': lambda a, b: a / b}[op]
    if op == '/' and y == 0.0:
        raise ValueError('unguarded divide: every divide in 0x032204 is guarded by 0x0BE608')
    ieee = ap(x, y)
    if not (math.isfinite(x) and math.isfinite(y)):
        return B(ieee)
    q = ap(Fraction(x), Fraction(y))
    return B(ieee) if q == 0 else E.rz_bits(q)


def fadd(x, y): return rz('+', x, y)
def fsub(x, y): return rz('-', x, y)          # x - y
def fdiv(x, y): return rz('/', x, y)          # x / y


def fmac(a, b, c):
    """fmac FR0,FRm,FRn: FRn = FR0*FRm + FRn, rounded once toward zero (fused)."""
    fa, fb, fc = F(a), F(b), F(c)
    if math.isfinite(fa) and math.isfinite(fb) and math.isfinite(fc):
        q = Fraction(fa) * Fraction(fb) + Fraction(fc)
        return B(fa * fb + fc) if q == 0 else E.rz_bits(q)
    return B(fa * fb + fc)


# ---- runtime-library helpers, modelled from their CONTRACT sections
def outside(x, c, w):                     # 0x0BE608: 1 when x < c-w or x > c+w (edges inside)
    if F(fsub(c, w)) > F(x):
        return 1
    if F(x) > F(fadd(c, w)):
        return 1
    return 0


def sdiv(n, d):                           # 0x0BE628
    if F(d) == 0.0:
        if F(n) == 0.0:
            return ZERO
        return FLT_MAX if F(n) > 0 else FLT_MAX | 0x80000000
    return fdiv(n, d)


def clamp(x, lo, hi):                     # 0x0BE56C: low test first
    if not (F(x) > F(lo)):
        return lo
    if F(hi) > F(x):
        return x
    return hi


def fmin(a, b):                           # 0x0BE970 (fr4 = a, fr5 = b): a if b > a else b
    return a if F(b) > F(a) else b


def to_u8(x):                             # 0x0BE5A8 with fr5 = 1.0 (scale), fr6 = 0.0 (offset)
    t = fdiv(fsub(x, ZERO), ONE)
    t = fadd(t, HALF)
    f = F(t)
    if f != f:
        v = -2**31
    elif f >= 2**31:
        v = 2**31 - 1
    elif f < -2**31:
        v = -2**31
    else:
        v = int(f)
    return 255 if v > 255 else (0 if v < 0 else v)


def sx8(v):
    v &= 0xFF
    return v - 256 if v & 0x80 else v


_lut = {}


def lut(xb, yb):
    """2-D lookup oracle: run the ROM routine 0x0BE8E4 itself on descriptor 0x0ABEE4."""
    k = (xb, yb)
    if k not in _lut:
        e = E.Emu(ROM)
        e.call(0x0BE8E4, regs={4: DESC}, fregs={4: F(xb), 5: F(yb)})
        _lut[k] = e.FR[0]
    return _lut[k]


# ---------------------------------------------------------------- the model
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
    def rb(self, a): return self._rd(a, 1)

    def wf(self, a, bits):
        for i in range(4):
            self.m[a + i] = (bits >> (8 * (3 - i))) & 0xFF
            self.w.add(a + i)

    def wb(self, a, v):
        self.m[a] = v & 0xFF
        self.w.add(a)


def cal_c(rom):
    return struct.unpack_from('>I', rom, CAL_C)[0]


def model(init, rom, r7):
    """Return the Mem after one call. Follows the byte order of accesses exactly."""
    M = Mem(init)
    st = {}
    st[184] = M.rf(X2D)                       # 032236..03223C
    st[188] = M.rf(Y2D)                       # 03223E..032248 (delay slot)
    if (r7 & 0xFF) == 0:                      # 032234 extu.b r7 ; 032244 tst ; bf/s taken when r7 != 0
        fr14 = M.rf(U0)
        st[192] = M.rf(V)
        st[196] = M.rf(A_)
        st[200] = M.rf(M1)
        fr15 = M.rf(M2)
        st[204] = M.rf(E_)
        fr13 = M.rf(D0)
        st[208] = M.rb(EN)
        st[212] = M.rf(LO)
        st[216] = M.rf(HI)
        st[220] = M.rf(S1)
        st[224] = M.rf(S2)
        r12 = M.rb(F1)
        r11 = M.rb(F2)
        st[228] = M.rb(SEL)
    else:                                     # 0322B2..0322E6: everything parked is zero
        fr13 = fr14 = fr15 = ZERO
        for k in (192, 196, 200, 204, 212, 216, 220, 224):
            st[k] = ZERO
        st[208] = st[228] = 0
        r11 = r12 = 0
    fr12 = M.rf(Q[2])                         # 0322E8 r1 = Q ; 0322EA fr12 = *Q[2]
    if outside(fr14, ZERO, EPS):              # 0322F4
        M.wf(R[0], sdiv(ONE, fr14))           # 032302..032308
    if sx8(rom[CAL_SEL]) == 1:                # 03230A mov.b (sign-extends) ; cmp/eq #1
        m = fmin(st[200], fr15)               # 03234C
        fr14 = m
        fr5 = M.rf(D1) ^ 0x80000000           # 032354 / 032356 fneg
        fr13 = fsub(fr13, M.rf(D2))           # 03235C fsub fr8,fr13
        d = fmin(fr13, fr5)                   # 032360
        d = fmin(d, M.rf(D3) ^ 0x80000000)    # 03236C (fneg in the delay slot)
        fr15 = fadd(st[196], fr14)            # 032374 / 032376
        fr15 = fsub(fr15, st[204])            # 03237C
        gt40 = F(fr12) > F(FORTY)             # 032382 fcmp/gt fr8,fr12: T = fr12 > 40
        fr15 = fadd(fr15, d)                  # 032386 delay slot, both ways
        n = 40 if gt40 else to_u8(fr12)       # 03238A / 032394
        fr9 = rz('*', M.rf(Q[1]), M.rf(R[4]))                     # 0323A2..0323A8
        fr9 = fmac(M.rf(R[3] + 4 * n), M.rf(Q[5]), fr9)           # 0323B0..0323B6
        fr9 = fmac(M.rf(R[3] + 4 * (n + 1)), M.rf(Q[6]), fr9)     # 0323B8..0323C6
        M.wf(R[4], fr9)                                           # 0323CA
        M.wf(R[5], fsub(st[192], fr15))                           # 0323D0..0323D8
        fr14 = fadd(M.rf(R[5]), M.rf(R[4]))                       # 0323DC..0323E4
        if outside(fr14, ZERO, EPS):
            M.wf(R[1], sdiv(ONE, fr14))                           # 0323F8..0323FE
        fr14 = fadd(M.rf(R[4]), ONE)                              # 032402..032408
        if outside(fr14, ZERO, EPS):
            r0v = M.rf(R[0])                                      # 032418..032420 -> r15+232
            M.wf(R[2], fsub(r0v, sdiv(ONE, fr14)))                # 032426..032434
        for k in range(41, 0, -1):                                # 0324A8..0324C2
            M.wf(R[3] + 4 * k, M.rf(R[3] + 4 * (k - 1)))
        M.wf(R[3], fr15)                                          # 0324C6
    else:
        if outside(st[192], ZERO, EPS):                           # 03231E
            M.wf(R[1], sdiv(ONE, st[192]))                        # 032332..032338
        M.wf(R[2], M.rf(R[0]))                                    # 03233A..032342
    # ---- join 0324C8
    if outside(M.rf(R[1]), ZERO, EPS):
        M.wf(R[6], sdiv(ONE, M.rf(R[1])))                         # 0324DA..0324E6
    r13 = r12 & 0xFF                                              # 0324E8
    r11u = r11 & 0xFF
    if r13 != 0 and r11u != 1:                                    # 0324EA / 0324F0
        prev = M.rb(R[14])                                        # 0324F4..0324F8
        r12 = st[228] & 0xFF                                      # 0324FA..032500
        if prev != r12:                                           # 032502 cmp/eq r2,r12
            M.wf(R[9], fadd(fadd(st[220], st[224]), cal_c(rom)))  # 032506..03251A
        t = lut(st[184], st[188])                                 # 03251C..032528
        r9v = M.rf(R[9])                                          # 032532 (delay slot)
        M.wf(R[10], fadd(r9v, t) if r12 == 0 else fsub(r9v, t))   # 032534 / 03253C
    else:
        M.wf(R[9], fadd(fadd(st[220], st[224]), cal_c(rom)))      # 032544..032558
        M.wf(R[10], ONE)                                          # 03255A..03255E
    stack = [M.rf(R[7] + 4 * k) for k in range(41)]               # 032560..032578
    flag = 1 if (r13 == 1 and r11u == 0) else 0                   # 03257A..03258A
    st[236] = flag
    en = st[208]
    if sx8(en) == 0:                                              # 032594 tst r7 ; bf taken when != 0
        for k in range(41):
            M.wf(R[7] + 4 * k, ZERO)                              # 0325A2..0325B2
        M.wf(R[12], ONE)
        M.wf(R[8], ONE)
    elif flag == 1:                                               # block A 0325C6..032672
        stack = [ZERO] * 41
        M.wf(R[12], ONE)
        acc = ZERO
        for k in range(1, 41):
            acc = fmac(M.rf(P[4] + 4 * k), stack[k], acc)
        acc = fmac(fsub(M.rf(R[2]), M.rf(R[11])), M.rf(P[2]), acc)
        acc = fmac(fsub(M.rf(R[1]), M.rf(R[0])), M.rf(P[0]), acc)
        st[240] = acc
        stack[0] = acc
        x = clamp(M.rf(R[10]), st[212], st[216])
        M.wf(R[8], clamp(x, HALF, ONE5))
        for k in range(40, 0, -1):
            M.wf(R[7] + 4 * k, stack[k - 1])
        M.wf(R[7], st[240])
    elif sx8(M.rb(R[15])) == 1:                                   # 032674..03267A ; block B 03267C..03272A
        stack = [ZERO] * 41
        M.wf(R[12], ONE)
        acc = ZERO
        for k in range(1, 41):
            acc = fmac(M.rf(P[4] + 4 * k), stack[k], acc)
        acc = fmac(fsub(M.rf(R[2]), M.rf(R[11])), M.rf(P[2]), acc)
        acc = fmac(fsub(M.rf(R[1]), M.rf(R[0])), M.rf(P[0]), acc)
        st[244] = acc
        stack[0] = acc
        x = clamp(fadd(M.rf(R[12]), acc), st[212], st[216])
        M.wf(R[8], clamp(x, HALF, ONE5))
        for k in range(40, 0, -1):
            M.wf(R[7] + 4 * k, stack[k - 1])
        M.wf(R[7], st[244])
    else:                                                         # block C 03272C..0327DE
        acc = ZERO
        for k in range(1, 41):
            acc = fmac(M.rf(R[7] + 4 * k), M.rf(P[4] + 4 * k), acc)
        acc = fmac(fsub(M.rf(R[2]), M.rf(R[11])), M.rf(P[2]), acc)
        acc = fmac(fsub(M.rf(R[1]), M.rf(R[0])), M.rf(P[0]), acc)
        M.wf(R[7], acc)
        x = clamp(fadd(M.rf(R[12]), M.rf(R[7])), st[212], st[216])
        M.wf(R[8], clamp(x, HALF, ONE5))
        for k in range(40, 0, -1):
            M.wf(R[7] + 4 * k, M.rf(R[7] + 4 * (k - 1)))
    # ---- tail 0327E0
    if sx8(en) == 1 and flag == 1:
        if outside(M.rf(R[8]), M.rf(R[10]), EPS):                 # 032808
            M.wb(R[13], 1)                                        # 03281E
    elif flag == 0:
        M.wb(R[13], 0)                                            # 03282E
    M.wf(R[11], M.rf(R[2]))                                       # 032836..03283C
    M.wf(R[12], M.rf(R[8]))                                       # 03283E..032844
    M.wb(R[14], st[228])                                          # 032846..03284C
    M.wb(R[15], flag)                                             # 03284E..032850
    return M


# ---------------------------------------------------------------- the emulator side
def poke(e, a, n, v):
    o = a - E.RAM_LO
    e.ram[o:o + n] = (v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big')


SENT_R = {8: 0x08080808, 9: 0x09090909, 10: 0x0A0A0A0A, 11: 0x0B0B0B0B, 12: 0x0C0C0C0C,
          13: 0x0D0D0D0D, 14: 0x0E0E0E0E}
SENT_F = {12: 12.25, 13: -13.5, 14: 14.75, 15: -15.125}
EXECUTED = set()


def run(init, rom=ROM, r7=0, tag=''):
    e = E.Emu(rom)
    for a, v in init.items():
        poke(e, a, 1, v)
    e.uninit_reads.clear()
    regs = {4: TBL_R, 5: TBL_P, 6: TBL_Q, 7: r7}
    regs.update(SENT_R)
    res = e.call(ENTRY, regs=regs, fregs=dict(SENT_F))
    assert res == 'return', tag
    for k, v in SENT_R.items():
        assert e.R[k] == v, f'r{k} not restored {tag}'
    assert e.R[15] == E.STACK_TOP, tag
    for k, v in SENT_F.items():
        assert e.fr(k) == v, f'fr{k} not restored {tag}'
    EXECUTED.update(p for p in e.executed if ENTRY <= p < END)
    M = model(init, rom, r7)
    got_w = set(e.writes)
    assert got_w == M.w, (f'WRITE-SET MISMATCH {tag}\n emu-only {sorted(map(hex, got_w - M.w))}'
                          f'\n model-only {sorted(map(hex, M.w - got_w))}')
    for a in M.w:
        assert e.ram[a - E.RAM_LO] == M.m[a], f'VALUE MISMATCH at {a:#x} {tag}'
    assert e.uninit_reads == M.reads, (f'READ-SET MISMATCH {tag}\n emu-only {sorted(map(hex, e.uninit_reads - M.reads))}'
                                       f'\n model-only {sorted(map(hex, M.reads - e.uninit_reads))}')
    return e, M


def f32(e_or_m, a):
    if isinstance(e_or_m, Mem):
        return F(int.from_bytes(bytes(e_or_m.m.get(a + i, 0) for i in range(4)), 'big'))
    return F(int.from_bytes(e_or_m.ram[a - E.RAM_LO:a - E.RAM_LO + 4], 'big'))


def u8(e, a):
    return e.ram[a - E.RAM_LO]


# ---------------------------------------------------------------- case construction
RNG = random.Random(0x032204)
PALETTE = [0.0, -0.0, 1.0, -1.0, 0.5, 1.5, 2.0, 0.25, 1e-3, -1e-3, 3.0, -2.5, 100.0, 1e-5]


def rnd():
    if RNG.random() < 0.25:
        return RNG.choice(PALETTE)
    return RNG.uniform(-3.0, 3.0)


def put_f(init, a, x):
    b = x if isinstance(x, int) else B(x)
    for i in range(4):
        init[a + i] = (b >> (8 * (3 - i))) & 0xFF


def base_case(**kw):
    """All inputs poked; floats random (deterministic), bytes from kw or 0."""
    init = {}
    for a in (X2D, Y2D, U0, V, A_, M1, M2, E_, D0, S1, S2, D1, D2, D3,
              Q[1], Q[2], Q[5], Q[6], P[0], P[2]):
        put_f(init, a, rnd())
    put_f(init, X2D, RNG.uniform(-10, 60))
    put_f(init, Y2D, RNG.uniform(-500, 7000))
    put_f(init, Q[2], RNG.uniform(-2, 43))
    for k in range(P4N):
        put_f(init, P[4] + 4 * k, RNG.uniform(-0.2, 0.2))
    for k in range(R3N):
        put_f(init, R[3] + 4 * k, rnd())
    for k in range(R7N):
        put_f(init, R[7] + 4 * k, RNG.uniform(-0.05, 0.05))
    for i in (0, 1, 2, 4, 5, 6, 8, 9, 10, 11, 12):
        put_f(init, R[i], rnd())
    put_f(init, R[12], RNG.uniform(0.4, 1.6))
    lo = RNG.uniform(0.3, 1.0)
    put_f(init, LO, lo)
    put_f(init, HI, lo + RNG.uniform(0.0, 0.9))
    for a in (EN, F1, F2, SEL, R[13], R[14], R[15]):
        init[a] = 0
    for name, a in (('en', EN), ('f1', F1), ('f2', F2), ('sel', SEL), ('r13', R[13]),
                    ('r14', R[14]), ('r15', R[15])):
        if name in kw:
            init[a] = kw[name] & 0xFF
    for a, x in kw.get('f', {}).items():
        put_f(init, a, x)
    return init


# ---------------------------------------------------------------- pass A: the gate and the arguments
def branch_refs(target, reach=4096):
    """Every bra/bsr (disp12) and bt/bf/bt.s/bf.s (disp8) word within reach whose target is `target`."""
    hits = []
    for pc in range(target - reach - 4, target + reach + 2, 2):
        w = struct.unpack_from('>H', ROM, pc)[0]
        if (w >> 12) in (0xA, 0xB):
            d = w & 0xFFF
            d = d - 0x1000 if d & 0x800 else d
            if pc + 4 + 2 * d == target:
                hits.append(pc)
        if (w >> 8) in (0x89, 0x8B, 0x8D, 0x8F):
            d = w & 0xFF
            d = d - 0x100 if d & 0x80 else d
            if pc + 4 + 2 * d == target:
                hits.append(pc)
    return hits


def long_occurrences(v):
    b = struct.pack('>I', v)
    out, i = [], ROM.find(b)
    while i >= 0:
        out.append(i)
        i = ROM.find(b, i + 1)
    return out


def pass_a():
    # E1: the only way in -- one branch word in reach, and no long equal to the entry anywhere
    assert branch_refs(ENTRY) == [0x031D7A], [hex(x) for x in branch_refs(ENTRY)]
    assert long_occurrences(ENTRY) == []
    want_gate = {ROM[a] for a in range(0x0CBBD8, 0x0CBBDC)}
    assert want_gate == {0x00, 0x06, 0x0C, 0x12}, want_gate
    hits = 0
    for v in range(256):
        e = E.Emu(ROM)
        calls = []

        def mk(addr):
            return lambda em: calls.append((addr, em.R[4], em.R[5], em.R[6]))
        for a in (0x031D88, 0x031DB4, 0x031F98, 0x032042, 0x0320AC):
            e.stub(a, fn=mk(a))
        poke(e, 0xFFFF65F0, 1, v)
        e.R[14] = 0x0E0E0E0E
        res = e.call(CALLER, regs={14: 0x0E0E0E0E}, stop_at={ENTRY})
        if v in want_gate:
            hits += 1
            assert res == ENTRY, v
            assert (e.R[4], e.R[5], e.R[6], e.R[7]) == (TBL_R, TBL_P, TBL_Q, 0), [hex(x) for x in e.R[4:8]]
            assert e.pr == E.RETURN_MAGIC and e.R[15] == E.STACK_TOP and e.R[14] == 0x0E0E0E0E   # tail call
            assert [c[0] for c in calls] == [0x031D88, 0x031DB4, 0x031F98, 0x032042, 0x0320AC]
            assert calls[1][1:3] == (0x063978, 0)
            assert calls[2][1] == 0x063984
            assert calls[3][1:3] == (0x0639A0, 0x063978)
            assert calls[4][1:4] == (0x0639B0, 0x063984, 0x0639A0)
        else:
            assert res == 'return' and calls == [], v
    print(f'A  gate: 0x032204 reached for {hits}/256 values of byte 0xFFFF65F0 '
          f'= {{0x00,0x06,0x0C,0x12}} (cal 0x0CBBD8..DB); r4=0x0639C4 r5=0x0639B0 r6=0x063984 r7=0; tail call; '
          f'only branch word in +-4 KB targeting 0x032204 is 0x031D7A; long 0x00032204 occurs 0 times')


# ---------------------------------------------------------------- pass B: calibration facts in all bins
def pass_b():
    bins = sorted(glob.glob(os.path.join(REPO, 'rom', '*.bin')))
    assert len(bins) == 20, len(bins)
    code = set()
    for b in bins:
        r = open(b, 'rb').read()
        assert r[CAL_SEL] == 0, b
        assert r[CAL_C:CAL_C + 4] == b'\x00\x00\x00\x00', b
        assert r[0x0CBBD8:0x0CBBDC] == bytes([0x00, 0x06, 0x0C, 0x12]), b
        code.add(hashlib.md5(r[0x031C9C:0x031F28] + r[0x032204:0x03293C] + r[0x063978:0x063A04]
                             + r[DESC:DESC + 28] + r[0x0C868C:0x0C86C0 + 84]
                             + r[0x022F92:0x022F9C] + r[0x022FF0:0x022FF4]).hexdigest())
    assert len(code) == 1, code
    print(f'B  {len(bins)} bins: 0x0CBBDF = 0, 0x0C5298 = 0.0, 0x0CBBD8..DB = 00 06 0C 12 in every bin; '
          f'code+pools of 0x031C9C/0x031D1E/0x032204/0x022F92, pointer tables, descriptor 0x0ABEE4 + axes + data '
          f'byte-identical')


# ---------------------------------------------------------------- pass F: the flat 2-D table
def pass_f():
    n = 0
    for x in (-1e6, -10.0, 0.0, 5.0, 10.0, 25.5, 49.99, 50.0, 60.0, 1e6):
        for y in (-1e6, -1.0, 0.0, 999.0, 1000.0, 3500.0, 6000.0, 6001.0, 1e7):
            assert F(lut(B(x), B(y))) == LUT_CONST, (x, y, F(lut(B(x), B(y))))
            n += 1
    nf = 0
    odd = [float('inf'), -float('inf'), float('nan'), -0.0, 0.0, 10.0, 50.0, 1000.0, 6000.0, -3e38, 3e38]
    for x in odd:
        for y in odd:
            assert F(lut(B(x), B(y))) == LUT_CONST, (x, y, F(lut(B(x), B(y))))
            nf += 1
    print(f'F  0x0BE8E4(0x0ABEE4): {n} finite (axisA, axisB) points incl. both clamp ends, and {nf} points '
          f'with +-inf / NaN / -0 / +-3e38 on either axis -> {LUT_CONST} every time')


# ---------------------------------------------------------------- pass C: live configuration control grid
def pass_c():
    counts = {}
    n = 0
    for en in (0, 1, 2):
        for f1 in (0, 1, 2):
            for f2 in (0, 1, 2):
                for sel in (0, 1, 5):
                    for r14 in (0, 1, 5):
                        for r15 in (0, 1, 2):
                            init = base_case(en=en, f1=f1, f2=f2, sel=sel, r14=r14, r15=r15, r13=7)
                            e, M = run(init, tag=f'C en={en} f1={f1} f2={f2} sel={sel} r14={r14} r15={r15}')
                            n += 1
                            flag = int(f1 == 1 and f2 == 0)
                            blk = 'Z' if en == 0 else ('A' if flag else ('B' if r15 == 1 else 'C'))
                            counts[blk] = counts.get(blk, 0) + 1
                            if counts[blk] == 1 or (blk == 'A' and en == 2 and counts[blk] < 30 and sel == 5 and r14 == 0 and r15 == 0):
                                print(f'   C sample block {blk}: EN={en} F1={f1} F2={f2} SEL={sel} prevSEL={r14} prevFLAG={r15}'
                                      f' R10in={init_f(init, R[10]):+.6f} R12in={init_f(init, R[12]):+.6f}'
                                      f' LO={init_f(init, LO):.6f} HI={init_f(init, HI):.6f}'
                                      f' -> R8={f32(e, R[8]):.6f} R9={f32(e, R[9]):+.6f} R10={f32(e, R[10]):+.6f}'
                                      f' R13={u8(e, R[13])} R14={u8(e, R[14])} R15={u8(e, R[15])}')
                            # contract assertions (independent of the model)
                            assert not (M.w & set(range(R[3], R[3] + 4 * R3N))), 'R3 written in live config'
                            assert not (M.w & set(range(R[4], R[4] + 8))), 'R4/R5 written in live config'
                            assert f32(e, R[2]) == f32(e, R[0]) or math.isnan(f32(e, R[0]))
                            assert e.ram[R[11] - E.RAM_LO:R[11] - E.RAM_LO + 4] == e.ram[R[2] - E.RAM_LO:R[2] - E.RAM_LO + 4]
                            assert e.ram[R[12] - E.RAM_LO:R[12] - E.RAM_LO + 4] == e.ram[R[8] - E.RAM_LO:R[8] - E.RAM_LO + 4]
                            assert u8(e, R[14]) == sel and u8(e, R[15]) == flag
                            r8 = f32(e, R[8])
                            assert 0.5 <= r8 <= 1.5
                            if en == 0:
                                assert r8 == 1.0 and all(f32(e, R[7] + 4 * k) == 0.0 for k in range(41))
                            else:
                                assert e.ram[R[7] - E.RAM_LO:R[7] - E.RAM_LO + 4] == e.ram[R[7] + 4 - E.RAM_LO:R[7] + 8 - E.RAM_LO]
                            if f1 == 0 or f2 == 1:
                                assert f32(e, R[10]) == 1.0
                            elif sel == 0:
                                assert f32(e, R[10]) == F(fadd(B(f32(e, R[9])), B(LUT_CONST)))
                            else:
                                assert f32(e, R[10]) == F(fsub(B(f32(e, R[9])), B(LUT_CONST)))
                            if flag == 0:
                                assert u8(e, R[13]) == 0
                            elif en != 1:
                                assert u8(e, R[13]) == 7
    print(f'C  live config (real ROM, r7=0): {n} control combinations, blocks {dict(sorted(counts.items()))}: '
          f'bit-exact vs model, exact write/read sets, callee-saved restored')


# ---------------------------------------------------------------- pass D: the configurations never run
def pass_d():
    n = 0
    for en in (0, 1, 2):
        for f1 in (0, 1):
            for f2 in (0, 1):
                for sel in (0, 3):
                    for r14 in (0, 3):
                        for r15 in (0, 1):
                            init = base_case(en=en, f1=f1, f2=f2, sel=sel, r14=r14, r15=r15, r13=7)
                            e, M = run(init, rom=ROM_X, tag='D cbbdf=1')
                            n += 1
                            # R3 delay line: shifted by one, newest at [0]
                            old = [init_f(init, R[3] + 4 * k) for k in range(R3N)]
                            new = [f32(e, R[3] + 4 * k) for k in range(R3N)]
                            assert new[1:] == old[:-1] or any(math.isnan(x) for x in old)
    r_range = set(range(0xFFFF7570, 0xFFFF7704))
    for r7 in (1, 0x80, 0xFF, 0x100, 0xFFFFFF00):
        for rom in (ROM, ROM_X):
            for en, f1, f2 in ((1, 1, 0), (0, 0, 0), (1, 0, 0)):
                init = base_case(en=en, f1=f1, f2=f2, sel=3, r14=3, r15=1, r13=7)
                e, M = run(init, rom=rom, r7=r7, tag=f'D r7={r7:#x}')
                n += 1
                if r7 & 0xFF:
                    # P-ZERO: S192..S228, fr13/fr14/fr15, r11/r12 zeroed -> L0 and block Z whatever the RAM holds
                    assert f32(e, R[8]) == 1.0 and f32(e, R[12]) == 1.0 and f32(e, R[10]) == 1.0
                    assert f32(e, R[9]) == 0.0
                    assert u8(e, R[13]) == 0 and u8(e, R[14]) == 0 and u8(e, R[15]) == 0
                    assert all(f32(e, R[7] + 4 * k) == 0.0 for k in range(41))
                    assert not (M.reads & {U0, V, A_, M1, M2, E_, D0, EN, LO, HI, S1, S2, F1, F2, SEL})
                    # ...but NOT everything is skipped: S184/S188 are loaded before the r7 test and
                    # [0xFFFF7494] is read through Q2 after the join; r12 = 0 forces L0, so the 2-D
                    # lookup (the only consumer of S184/S188) is never reached
                    x1 = {D1, D2, D3, Q[1], Q[5], Q[6]} if rom is ROM_X else set()   # X1's own reads
                    assert {a for a in e.uninit_reads if a not in r_range} == {X2D, Y2D, Q[2]} | x1, \
                        sorted(map(hex, {a for a in e.uninit_reads if a not in r_range}))
                    assert 0x0BE8E4 not in e.executed
                else:
                    assert U0 in M.reads and EN in M.reads     # r7 = 0x100 / 0xFFFFFF00 take the live path
    print(f'D  never-run configs: {n} cases (0x0CBBDF=1 copy; r7 in 0x01/0x80/0xFF on both ROMs: non-R reads are '
          f'exactly 0xFFFF63C4, 0xFFFF6624, 0xFFFF7494, 0x0BE8E4 not reached; r7 = 0x100 / 0xFFFFFF00 '
          f'behave as 0 -- extu.b): bit-exact vs model')


def init_f(init, a):
    return F(int.from_bytes(bytes(init[a + i] for i in range(4)), 'big'))


# ---------------------------------------------------------------- pass E: float edges
def pass_e():
    n = 0
    eps = F(EPS)
    up = F(EPS + 1)
    edge = [0.0, -0.0, eps, -eps, up, -up, F(EPS - 1), 2.0, -4.0, 1e30]
    # reciprocal windows: R0 from U0, R1 from V (live), R6 from R1
    for u in edge:
        for v in edge:
            init = base_case(en=0, f={U0: u, V: v})
            old = {i: init_f(init, R[i]) for i in (0, 1)}
            e, M = run(init, tag=f'E win u={u} v={v}')
            n += 1
            w0 = abs(u) > eps
            if v == 2.0:
                print(f'   E window: u0 = {u!r:<24} -> R0 written: {R[0] in M.w!s:<5}  R0 = {f32(e, R[0])!r}')
            assert (R[0] in M.w) == w0
            if w0:
                assert f32(e, R[0]) == F(fdiv(ONE, B(u)))
            assert (R[1] in M.w) == (abs(v) > eps)
            r1 = f32(e, R[1])
            assert (R[6] in M.w) == (abs(r1) > eps)
            if not w0:
                assert f32(e, R[0]) == old[0] or (math.isnan(old[0]))
    # clamp ends on all three live blocks and the tail window
    for blk in ('A', 'B', 'C'):
        for tgt in (-5.0, 0.0, 0.4999, 0.5, 0.75, 1.0, 1.25, 1.5, 1.5001, 9.0):
            for lo, hi in ((0.3, 1.8), (0.6, 1.2), (1.0, 1.0), (1.4, 0.7), (0.0, 0.0)):
                kw = dict(en=1, sel=0, r14=0, r13=5, f={LO: lo, HI: hi})
                if blk == 'A':
                    kw.update(f1=1, f2=0)
                elif blk == 'B':
                    kw.update(f1=0, f2=0, r15=1)
                else:
                    kw.update(f1=0, f2=0, r15=0)
                init = base_case(**kw)
                if blk == 'A':           # target is R10 = R9 + 0.03 (sel 0) with R9 kept (r14 == sel)
                    put_f(init, R[9], tgt - LUT_CONST)
                else:                    # B: 1 + acc ; C: R12 + acc with all coefficients zero
                    for k in range(P4N):
                        put_f(init, P[4] + 4 * k, 0.0)
                    put_f(init, P[0], 0.0)
                    put_f(init, P[2], 0.0)
                    put_f(init, R[12], tgt)
                e, M = run(init, tag=f'E clamp {blk} tgt={tgt} lo={lo} hi={hi}')
                n += 1
                r8 = f32(e, R[8])
                if blk == 'C':
                    want = F(clamp(clamp(B(tgt), B(lo), B(hi)), HALF, ONE5))
                    assert r8 == want, (tgt, lo, hi, r8, want)
                if blk == 'B':
                    assert r8 == F(clamp(clamp(ONE, B(lo), B(hi)), HALF, ONE5))
                assert 0.5 <= r8 <= 1.5
                if blk == 'A':           # tail: en == 1 and flag == 1 -> R13 = 1 when R8 is outside R10 +- 2^-13
                    r8b = B(r8)
                    r10b = B(f32(e, R[10]))
                    assert u8(e, R[13]) == (1 if outside(r8b, r10b, EPS) else 5)
                    assert r8 == F(clamp(clamp(r10b, B(lo), B(hi)), HALF, ONE5))     # R8 = sat(R10), v not added
    # 0x0BE56C itself with the bounds the wrong way round, and NaN inputs
    nan = float('nan')
    for lo, hi, x, want in ((1.25, 0.75, 0.5, 1.25), (1.25, 0.75, 0.75, 1.25), (1.25, 0.75, 1.0, 1.25),
                            (1.25, 0.75, 1.25, 1.25), (1.25, 0.75, 1.5, 0.75), (1.25, 0.75, 3.0, 0.75),
                            (1.25, 0.75, nan, 1.25), (0.5, 1.5, nan, 0.5), (0.5, 1.5, 0.4, 0.5), (0.5, 1.5, 2.0, 1.5)):
        em = E.Emu(ROM)
        em.call(0x0BE56C, fregs={4: x, 5: lo, 6: hi})
        assert F(em.FR[0]) == want, (lo, hi, x, F(em.FR[0]))
        assert F(clamp(B(x), B(lo), B(hi))) == want
        n += 1
    # NaN through the live blocks: a NaN R12 (block C) gives sat(LO); a NaN LO or HI gives 0.5
    for tag, lo, hi, r12 in (('x=NaN', 0.7, 1.3, nan), ('x=NaN LO>HI', 1.4, 0.7, nan),
                             ('LO=NaN', nan, 1.3, 1.0), ('HI=NaN', 0.7, nan, 1.0)):
        init = base_case(en=1, f1=0, f2=0, r15=0, sel=0, r14=0, r13=5, f={LO: lo, HI: hi})
        for k in range(P4N):
            put_f(init, P[4] + 4 * k, 0.0)
        put_f(init, P[0], 0.0)
        put_f(init, P[2], 0.0)
        put_f(init, R[12], r12)
        e, M = run(init, tag=f'E nan {tag}')
        n += 1
        r8 = f32(e, R[8])
        if tag.startswith('x=NaN'):
            assert r8 == min(max(F(B(lo)), 0.5), 1.5), (tag, r8)          # inner clamp returned LO
        else:
            assert r8 == 0.5, (tag, r8)
        print(f'   E NaN: block C, {tag:<12} LO={lo} HI={hi} R12={r12} -> R8 = {r8}')
    # delay index n on the 0x0CBBDF = 1 copy: which R3 cells feed R4
    for q2 in (-5.0, -0.5, 0.0, 0.49, 0.5, 1.5, 17.3, 39.49, 39.5, 40.0, 40.0001, 41.0, 1e9):
        init = base_case(en=0)
        for k in range(R3N):
            put_f(init, R[3] + 4 * k, float(k + 1))
        put_f(init, Q[2], q2)
        put_f(init, Q[1], 0.0)
        put_f(init, Q[5], 1.0)
        put_f(init, Q[6], 1000.0)
        e, M = run(init, rom=ROM_X, tag=f'E idx q2={q2}')
        n += 1
        want_n = 40 if q2 > 40 else max(0, min(255, int(q2 + 0.5)))
        print(f'   E delay index: [0xFFFF7494] = {q2:<10g} -> n = {want_n:2d}   R4 = R3[n] + 1000*R3[n+1] = {f32(e, R[4]):g}')
        assert f32(e, R[4]) == (want_n + 1) + 1000.0 * (want_n + 2), (q2, f32(e, R[4]), want_n)
    print(f'E  float edges: {n} cases (reciprocal windows at +-2^-13, clamp ends on blocks A/B/C, 0x0BE56C with '
          f'LO > HI and NaN, NaN through block C, delay index rounding/clamp 0..40): bit-exact vs model and contract asserts')


# ---------------------------------------------------------------- pass H: 0x031C9C, the other writer
INIT_FN = 0x031C9C


def pass_h():
    # callers: two literal jsr sites, no branch word in reach
    occ = long_occurrences(INIT_FN)
    assert occ == [0x0480C4, 0x04A0C0], [hex(x) for x in occ]
    for pool, ld in ((0x0480C4, 0x047F3E), (0x04A0C0, 0x049E8C)):
        w = struct.unpack_from('>H', ROM, ld)[0]
        assert (w >> 12) == 0xD and ((ld & ~3) + 4 + (w & 0xFF) * 4) == pool
        rn = (w >> 8) & 0xF
        assert struct.unpack_from('>H', ROM, ld + 2)[0] == (0x400B | (rn << 8))       # jsr @rn
    assert branch_refs(INIT_FN) == []
    want = {}
    for k in range(P4N):
        want[P[4] + 4 * k] = ZERO                 # 0x031CC2..0x031CD2  P4[0..41]
    for k in range(R3N):
        want[R[3] + 4 * k] = ZERO                 # 0x031CDA..0x031CEA  R3[0..41]
    for k in range(R7N):
        want[R[7] + 4 * k] = ZERO                 # 0x031CF4..0x031D02  R7[0..40]
    for i in (8, 12, 9, 10):
        want[R[i]] = ONE                          # 0x031CB4 / 0x031CB8 / 0x031D06 / 0x031D0A, base 0xFFFF7700
    ran = 0
    for b in range(256):
        e = E.Emu(ROM)
        poke(e, 0xFFFF65F6, 1, b)
        poke(e, SEL, 1, 0x5A)
        e.uninit_reads.clear()
        assert e.call(INIT_FN) == 'return'
        assert e.uninit_reads == {0xFFFF65F6, SEL}                     # 94B3 read in the bf/s slot, both ways
        ram_w = {a for a in e.writes if a < E.STACK_TOP - 0x100}
        if b != 1:
            assert ram_w == set(), b
            continue
        ran += 1
        exp = set()
        for a, v in want.items():
            exp.update(range(a, a + 4))
            assert e.ram[a - E.RAM_LO:a - E.RAM_LO + 4] == v.to_bytes(4, 'big'), hex(a)
        exp.update((R[13], R[14], R[15]))
        assert ram_w == exp, sorted(map(hex, ram_w ^ exp))
        assert (u8(e, R[13]), u8(e, R[14]), u8(e, R[15])) == (0, 0x5A, 0)      # R14 = byte [0xFFFF94B3]
    assert ran == 1
    print('H  0x031C9C (real 0x022F92): body runs only for byte [0xFFFF65F6] == 0x01 (256 values); then exactly '
          'P4[0..41] = R3[0..41] = R7[0..40] = 0, R8 = R9 = R10 = R12 = 1.0, R13 = 0, R14 = byte [0xFFFF94B3], '
          'R15 = 0; R0..R2, R4..R6, R11 untouched; callers: jsr at 0x047F40 and 0x049E8E only')


# ---------------------------------------------------------------- pass I: the recurrence across calls
def pass_i():
    rng = random.Random(30)
    e = E.Emu(ROM)

    def pf(a, x):
        poke(e, a, 4, B(x))

    def gf(a):
        return f32(e, a)
    poke(e, 0xFFFF65F6, 1, 1)
    poke(e, SEL, 1, 0)
    assert e.call(INIT_FN) == 'return'          # start from the init state (P4 is zeroed by it)
    p4 = [0.0] * P4N
    for k in range(1, 41):
        p4[k] = rng.uniform(-0.01, 0.01)
    p4[1], p4[2], p4[40] = 0.5, -0.25, 0.125
    for k in range(P4N):
        pf(P[4] + 4 * k, p4[k])
    pf(P[0], 1 / 16)
    pf(P[2], 1.0)
    pf(LO, 0.0)
    pf(HI, 2.0)
    for a, x in ((X2D, 20.0), (Y2D, 3000.0), (S1, 0.25), (S2, 0.5)):
        pf(a, x)
    for a in (A_, M1, M2, E_, D0, Q[2]):
        pf(a, 0.0)
    for i in (0, 1, 2, 11):
        pf(R[i], 1.0)
    drive = {'Z': (0, 0, 0), 'A': (1, 1, 0), 'F0': (1, 0, 0)}     # (EN, F1, F2)
    seq = ['F0'] * 45 + ['A', 'F0'] + ['F0'] * 44 + ['Z'] + ['F0'] * 12 + ['A', 'A', 'F0', 'F0']
    hist = [0.0] * 40              # the structural rule: R7[1..40] at the START of the next call
    prev_flag = 0
    blocks = []
    for i, s in enumerate(seq):
        en, f1, f2 = drive[s]
        poke(e, EN, 1, en)
        poke(e, F1, 1, f1)
        poke(e, F2, 1, f2)
        poke(e, SEL, 1, 0)
        pf(U0, rng.uniform(0.5, 2.0))
        pf(V, rng.uniform(0.5, 2.0))
        s7 = [gf(R[7] + 4 * k) for k in range(R7N)]
        s12, s8, s2 = gf(R[12]), gf(R[8]), gf(R[2])
        assert s12 == s8                        # R12 = the previous call's R8 (both 1.0 after the init)
        assert s7[1:] == hist, i                # start of call: R7[k] = v of k calls back (or 0, see rule)
        assert e.call(ENTRY, regs={4: TBL_R, 5: TBL_P, 6: TBL_Q, 7: 0}) == 'return'
        flag = int(f1 == 1 and f2 == 0)
        blk = 'Z' if en == 0 else ('A' if flag else ('B' if prev_flag == 1 else 'C'))
        e7 = [gf(R[7] + 4 * k) for k in range(R7N)]
        if blk == 'Z':
            assert all(x == 0.0 for x in e7) and gf(R[8]) == 1.0
            hist = [0.0] * 40
        else:
            v = e7[0]
            assert e7[1] == v                   # END of call: R7[1] is the CURRENT v, so R7[k] = v of k-1 calls back
            h = s7[1:] if blk == 'C' else [0.0] * 40
            want = sum(p4[k] * h[k - 1] for k in range(1, 41)) + 1.0 * (gf(R[2]) - s2) + (gf(R[1]) - gf(R[0])) / 16
            assert abs(v - want) <= 1e-5 * max(1.0, abs(want)), (i, blk, v, want)
            if blk == 'C':
                assert e7[2:] == s7[1:40]
                assert abs(gf(R[8]) - min(max(s12 + v, 0.5), 1.5)) <= 1e-6
                hist = [v] + hist[:39]
            else:
                assert e7[2:] == [0.0] * 39
                hist = [v] + [0.0] * 39
        blocks.append(blk)
        prev_flag = flag
    got = ''.join(blocks)
    assert got == 'C' * 45 + 'ABC' + 'C' * 43 + 'Z' + 'C' * 12 + 'AABC', got
    print(f'I  {len(seq)} chained calls from the 0x031C9C state ({got[:6]}..{got[-6:]}): first FLAG=0 call after the '
          f'init is C (R15 = 0); at the END of a call R7[0] = R7[1] = v; at the START of the next R7[k] = v of k calls '
          f'back while the calls in between were C; A/B leave [v, v, 0..], Z and the init zero it; '
          f'v = SUM P4[k] h_k + P2 dR2 + P0 (R1 - R0) and R8 = sat(R12 + v) hold')


# ---------------------------------------------------------------- pass J: byte facts for COMPARISON / N5 / N7
def pass_j():
    # the FBKC function 0x04438C sets GBR = 0xFFFF81F0 once; its gate bytes are GBR+90/68/69/91/92
    assert struct.unpack_from('>H', ROM, 0x0443A0)[0] == 0xD06E and struct.unpack_from('>H', ROM, 0x0443A2)[0] == 0x401E
    assert struct.unpack_from('>I', ROM, (0x0443A0 & ~3) + 4 + 0x6E * 4)[0] == 0xFFFF81F0
    for pc, w, cell in ((0x044446, 0xC45A, 0xFFFF824A), (0x044498, 0xC444, 0xFFFF8234), (0x04447C, 0xC445, 0xFFFF8235),
                        (0x0444A2, 0xC45B, 0xFFFF824B), (0x0444AC, 0xC45C, 0xFFFF824C)):
        assert struct.unpack_from('>H', ROM, pc)[0] == w and 0xFFFF81F0 + (w & 0xFF) == cell
    ldc_sites = [pc for pc in range(0x04438C, 0x0447EA, 2) if (struct.unpack_from('>H', ROM, pc)[0] & 0xF0FF) == 0x401E]
    assert ldc_sites == [0x0443A2], ldc_sites
    # the long 0xFFFF7494 occurs once: the Q-table slot read as a float at 0x0322EA
    assert long_occurrences(0xFFFF7494) == [TBL_Q + 8]
    # 0xFFFF76D4: 15 occurrences = the R-table slot + 14 pool longs, each loaded and READ by the next instruction
    occ = long_occurrences(0xFFFF76D4)
    assert len(occ) == 15 and TBL_R + 32 in occ
    readers = []
    for pool in occ:
        if pool == TBL_R + 32:
            continue
        lds = []
        for pc in range(pool - 1024 - 4, pool, 2):
            w = struct.unpack_from('>H', ROM, pc)[0]
            if (w >> 12) == 0xD and ((pc & ~3) + 4 + (w & 0xFF) * 4) == pool:
                lds.append(pc)
        assert lds, hex(pool)
        for pc in lds:
            rn = (struct.unpack_from('>H', ROM, pc)[0] >> 8) & 0xF
            nx = struct.unpack_from('>H', ROM, pc + 2)[0]
            assert (nx & 0xF00F) == 0xF008 and ((nx >> 4) & 0xF) == rn, (hex(pc), hex(nx))   # fmov.s @rn,frX
            readers.append(pc + 2)
    want_readers = [0x02450E, 0x030210, 0x0329C6, 0x032D76, 0x032E44, 0x05D2C4, 0x06986E, 0x0699C8, 0x071B12,
                    0x07317C, 0x07353A, 0x080572, 0x080EB4, 0x0857BC, 0x0A86E0]
    assert sorted(readers) == want_readers, [hex(x) for x in sorted(readers)]
    # find_writers hits in 0xFFFF7570..0xFFFF7703 outside 0x031C9C: each is the low half of a pool long
    # that a census function loads with mov.l (so data, not a store)
    for hit, gbr, pool, loader in ((0x02F956, 0xFFFF72B4, 0x02F954, 0x02F86A), (0x02F676, 0xFFFF72A0, 0x02F674, 0x02F4B8),
                                   (0x02F67E, 0xFFFF72A0, 0x02F67C, 0x02F4C8), (0x02F682, 0xFFFF72A0, 0x02F680, 0x02F4D6),
                                   (0x02F686, 0xFFFF72A0, 0x02F684, 0x02F4E4)):
        w = struct.unpack_from('>H', ROM, hit)[0]
        assert (w >> 8) == 0xC2 and R[3] <= gbr + 4 * (w & 0xFF) < R[8], hex(hit)      # mov.l r0,@(d,gbr) into R3/R7
        assert hit == pool + 2 and struct.unpack_from('>H', ROM, pool)[0] == 0x000A
        lw = struct.unpack_from('>H', ROM, loader)[0]
        assert (lw >> 12) == 0xD and ((loader & ~3) + 4 + (lw & 0xFF) * 4) == pool, hex(loader)
    print('J  FBKC 0x04438C: GBR = 0xFFFF81F0 (one ldc, 0x0443A2), gates 0xFFFF824A/8234/8235/824B/824C; long 0xFFFF7494 '
          'occurs only at 0x06398C (Q2); long 0xFFFF76D4: 15 occurrences, 15 literal reader sites + the R-table slot; '
          'the 5 non-0x031C9C find_writers hits in the R range are low halves of pool longs 0x000AC2xx')


# ---------------------------------------------------------------- pass G: instruction coverage
def pass_g():
    want = set()
    a = ENTRY
    while a < END:
        if any(lo <= a < hi for lo, hi in POOLS):
            a += 2
            continue
        want.add(a)
        a += 2
    assert len(want) == 748, len(want)
    missing = sorted(want - EXECUTED)
    assert not missing, [hex(x) for x in missing]
    assert not (EXECUTED - want), [hex(x) for x in sorted(EXECUTED - want)]
    print(f'G  coverage: all {len(want)} instruction addresses of 0x032204..0x03286C executed; no pool word executed')


def main():
    pass_a()
    pass_b()
    pass_f()
    pass_c()
    pass_d()
    pass_e()
    pass_g()
    pass_h()
    pass_i()
    pass_j()
    print('OK')


if __name__ == '__main__':
    main()
