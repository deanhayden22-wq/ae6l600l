#!/usr/bin/env python3
"""Emulation for disassembly/analysis/fn_01FE46_trace.txt (function programme batch 4).

    python3 scripts/trace/emu_fn_01FE46.py          # exit 0 = every assertion held

Runs the ROM's own code in scripts/sh2e_emu.py and compares it, write by write and byte by byte,
with models written from the listings of:

  0x01FE46 (whole body 0x01FE46..0x02035E, including the part the census files as 0x020012 --
           one stack frame, one epilogue at 0x020340)
  0x020678, 0x020726            (the clearers of bytes [641C] [641A] [641B])
  0x0203DC, 0x020426, 0x020580, 0x0205A4   (context: the writers of [63B4] / [6420] / [6424],
                                           a reader of [63C4], and the counters [6418] / [6419])

Passes
  P1  0x01FE46 single call, 6,000 random states + edge sweeps (stock / 20.19c / 20.19e):
      exact write set, every written byte, read set within the declared inputs, callee-saved regs.
  P2  MAF limit sweep: [63C4] = min(..., 0x0C3100) and the g/rev caps, printed for the three bins.
  P3  the [641C] latch over many calls on ONE emulator, interleaved with 0x020580 (the [6418] counter):
      set, hold for 13 counts, the four release conditions, and the frozen-rising engine-load cell.
  P4  the clearers over the coolant axis and every [65F6] byte value.
  P5  context functions (0x0203DC window max/min, 0x020426, 0x020580, 0x0205A4).
  P6  review settlement (added at the deciding review): the tuned inputs that differ between the bins
      (C6), the Cruise / Non-Cruise maps byte-identical (so the [90A8] blend is inert), the set and hold
      gates at their exact boundaries and with NaN (C22 / C24), the hold length for 1, 2, 3 and 13 calls
      of 0x020580 per 0x01FE46 call, and the -Inf airflow edge (lag returns NaN).
  P7  the two writers of byte [65F6]: 0x022F1C (copies byte [415C]) and 0x022DB0 (clears it).

The 1-D / 2-D lookups in the models call the ROM routines 0x0BE830 / 0x0BE8E4 (verified contracts,
helpers_interp_trace.txt); the critical-section pair 0x00317C / 0x003190 is stubbed (it executes
ldc sr, which the emulator refuses; contract in rtos_core_trace.txt: no RAM effect visible here).
Float arithmetic in the models is exact then rounded toward zero, fmac fused, as the emulator does;
no conclusion drawn from this script depends on the last bit of a float.
"""
import hashlib
import math
import os
import random
import struct
import sys
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import sh2e_emu as E          # noqa: E402

BIN = os.path.join(ROOT, 'rom', 'AE5L600L 20g rev 20.19c.bin')
ROM = open(BIN, 'rb').read()
assert hashlib.md5(ROM).hexdigest() == '92cae8275cd4f9b473a3a9e36efe6449', 'wrong reference bin'
STOCK = open(os.path.join(ROOT, 'rom', 'ae5l600l.bin'), 'rb').read()
REV_E = open(os.path.join(ROOT, 'rom', 'AE5L600L 20g rev 20.19e.bin'), 'rb').read()
BINS = (('stock', STOCK), ('20.19c', ROM), ('20.19e', REV_E))

FLT_MAX = struct.unpack('>f', b'\x7f\x7f\xff\xff')[0]
NAN, INF = float('nan'), float('inf')
EPS = 2.0 ** -14                      # 0x020398 = 0x38800000
CHECKS = 0


def ok(n=1):
    global CHECKS
    CHECKS += n


def A(x):
    return 0xFFFF0000 | x


def f32(x):
    return E.b2f(E.f2b(x))


def bits(x):
    return E.f2b(x) if x == x else 0x7FBFFFFF


def same(a, b):
    if a != a and b != b:
        return True
    return bits(a) == bits(b)


def rd_f(rom, a):
    return struct.unpack_from('>f', rom, a)[0]


# ------------------------------------------------------------ arithmetic: exact, then toward zero
def rz32(q):
    s = -1 if q < 0 else 1
    a = -q if q < 0 else q
    e = a.numerator.bit_length() - a.denominator.bit_length()
    while Fraction(2) ** e > a:
        e -= 1
    while Fraction(2) ** (e + 1) <= a:
        e += 1
    if e > 127:
        return s * FLT_MAX
    if e < -126:
        return math.copysign(0.0, s)
    m = math.floor(a * Fraction(2) ** (23 - e))
    return s * math.ldexp(m, e - 23)


def sgn(x):
    return math.copysign(1.0, x)


def f_add(a, b):
    if a != a or b != b or math.isinf(a) or math.isinf(b):
        return f32(a + b)
    q = Fraction(a) + Fraction(b)
    if q == 0:
        return -0.0 if (sgn(a) < 0 and sgn(b) < 0) else 0.0
    return rz32(q)


def f_sub(a, b):                      # fsub FRm,FRn : FRn - FRm  ->  f_sub(FRn, FRm)
    return f_add(a, -b)


def f_mul(a, b):
    if a != a or b != b or math.isinf(a) or math.isinf(b):
        return f32(a * b)
    q = Fraction(a) * Fraction(b)
    if q == 0:
        return math.copysign(0.0, sgn(a) * sgn(b))
    return rz32(q)


def f_div(a, b):
    if a != a or b != b or math.isinf(a) or math.isinf(b) or b == 0:
        try:
            return f32(a / b)
        except ZeroDivisionError:
            return NAN
    q = Fraction(a) / Fraction(b)
    if q == 0:
        return math.copysign(0.0, sgn(a) * sgn(b))
    return rz32(q)


def f_fmac(f0, fm, fn):               # fmac FR0,FRm,FRn : FRn = FR0*FRm + FRn, one rounding
    if any(v != v or math.isinf(v) for v in (f0, fm, fn)):
        return f32(f0 * fm + fn)
    q = Fraction(f0) * Fraction(fm) + Fraction(fn)
    if q == 0:
        if (f0 == 0 or fm == 0) and sgn(f0) * sgn(fm) < 0 and sgn(fn) < 0:
            return -0.0
        return 0.0
    return rz32(q)


# ------------------------------------------------------------ runtime-library CONTRACTS (verified)
def m_clamp(x, lo, hi):               # 0x0BE56C
    if not (x > lo):
        return lo
    if hi > x:
        return x
    return hi


def m_max(a, b):                      # 0x0BE960: a if a > b else b
    return a if a > b else b


def m_min(a, b):                      # 0x0BE970: a if b > a else b
    return a if b > a else b


def m_lag(a, b, k, eps):              # 0x0BEA40
    if math.isinf(b) or b != b:
        return a
    r = f_fmac(f_sub(1.0, k), f_sub(b, a), a)
    if eps > abs(f_sub(a, r)):
        return a
    return r


def m_fdiv0(a, b):                    # 0x0BE628
    if b != 0:
        return f_div(a, b)
    if a == 0:
        return 0.0
    return FLT_MAX if a > 0 else -FLT_MAX


def m_satadd8(a, b):                  # 0x0BE53C
    return min((a & 0xFF) + (b & 0xFF), 0xFF)


_LK = {}


def _lk(kind, rec, x, y, rom):
    key = (kind, rec, bits(x), None if y is None else bits(y), id(rom))
    if key not in _LK:
        e = E.Emu(rom)
        if kind == 'f1':
            e.call(0x0BE830, regs={4: rec}, fregs={4: x})
        else:
            e.call(0x0BE8E4, regs={4: rec}, fregs={4: x, 5: y})
        _LK[key] = e.fr(0)
    return _LK[key]


def lk1(rec, x, rom):
    return _lk('f1', rec, x, None, rom)


def lk2(rec, x4, x5, rom):
    return _lk('f2', rec, x4, x5, rom)


# ------------------------------------------------------------ emulator plumbing
def poke(e, a, data):
    """input value WITHOUT the init mark, so a read of it lands in e.uninit_reads (= the read set)"""
    o = a - E.RAM_LO
    e.ram[o:o + len(data)] = data


def setup_state(e, S):
    for a, (k, v) in S.items():
        if k == 'f':
            poke(e, a, struct.pack('>I', E.f2b(v)))
        elif k == 'b':
            poke(e, a, bytes([v & 0xFF]))
        elif k == 'w':
            poke(e, a, struct.pack('>H', v & 0xFFFF))
        else:
            raise ValueError(k)


SENT_R = {k: 0x1000 * k + 0x55 for k in range(8, 15)}
SENT_F = {12: 12.5, 13: -13.25, 14: 14.125, 15: -15.0625}


def new_emu(rom):
    e = E.Emu(rom)
    e.stub(0x00317C, r0=0)            # critical-section enter (ldc sr): r0 = previous mask
    e.stub(0x003190)                  # critical-section leave
    return e


def call(e, entry):
    e.steps = 0
    e.writes = {}
    rr = dict(SENT_R)
    e.gbr = 0xFFFF0ABC
    e.call(entry, regs=rr, fregs=dict(SENT_F))
    for k in range(8, 15):
        assert e.R[k] == rr[k], f'r{k} not restored by {entry:#x}'
    assert e.R[15] == E.STACK_TOP, f'r15 unbalanced by {entry:#x}'
    assert e.gbr == 0xFFFF0ABC, f'GBR not restored by {entry:#x}'
    for k, v in SENT_F.items():
        assert same(e.fr(k), v), f'fr{k} not restored by {entry:#x}'
    ok()


def expect_bytes(W):
    out = {}
    for a, (k, v) in W.items():
        if k == 'f':
            b = struct.pack('>I', E.f2b(v))
        elif k == 'b':
            b = bytes([v & 0xFF])
        else:
            b = struct.pack('>H', v & 0xFFFF)
        for i, x in enumerate(b):
            out[a + i] = x
    return out


def check_writes(e, W, ctx):
    want = expect_bytes(W)
    got = dict(e.writes)
    if set(got) != set(want):
        extra = sorted(set(got) - set(want))
        miss = sorted(set(want) - set(got))
        raise AssertionError(f'{ctx}: write set differs; emu-only {[hex(x) for x in extra[:12]]} '
                             f'model-only {[hex(x) for x in miss[:12]]}')
    for a in want:
        if got[a] != want[a]:
            base = a & ~3
            raise AssertionError(f'{ctx}: byte {a:#x} emu {got[a]:02x} model {want[a]:02x} '
                                 f'(cell {base:#x} emu {e.read_f32(base)!r})')
    ok()


# ============================================================ MODEL 0x01FE46 (01FE46..02035E)
F_IN = [0x620C, 0x6350, 0x6624, 0x65FC, 0x62E4, 0x62DC, 0x69F4, 0x73D0, 0x679C, 0x90A8, 0x6364, 0x6898,
        0x63F8, 0x6420, 0x6424, 0x63B4, 0x63DC, 0x63E4, 0x6414, 0x6400]
B_IN = [0x5E94, 0x7C9D, 0x65C0, 0x6254, 0x647C, 0x65C5, 0x641B, 0x6418, 0x6419, 0x641C, 0x9714, 0x726C]
W_IN = [0x67EC]
DECLARED_IN = {A(x) for x in F_IN + B_IN + W_IN}


def cal(rom):
    c = {a: rd_f(rom, a) for a in range(0x0C3100, 0x0C3160, 4)}
    c['A'] = rd_f(rom, 0x020384)       # pool word, mova'd at 020154 / 02017A ("Engine Load Limit A")
    for a in (0x0C302D, 0x0C302E, 0x0C302F, 0x0C3030, 0x0C3031):
        c[a] = rom[a]
    c[0x0C3052] = struct.unpack_from('>H', rom, 0x0C3052)[0]
    return c


def u8(v):
    return v & 0xFF


def m_01FE46(S, rom):
    """S: {addr: value}. Returns (W, trace) with W = {addr: (kind, value)} in write order."""
    K = cal(rom)
    g = lambda x: S[A(x)]                # noqa: E731
    W = {}
    cur = dict(S)

    def wf(x, v):
        W[A(x)] = ('f', v)
        cur[A(x)] = v

    def wb(x, v):
        W[A(x)] = ('b', v & 0xFF)
        cur[A(x)] = v & 0xFF

    c = lambda x: cur[A(x)]              # noqa: E731
    tr = {}
    MAP, ECT, RPM, VSS = g(0x620C), g(0x6350), g(0x6624), g(0x65FC)
    X62E4, PLATE, X69F4, X73D0 = g(0x62E4), g(0x62DC), g(0x69F4), g(0x73D0)
    X679C, BL, IAT, X6898 = g(0x679C), g(0x90A8), g(0x6364), g(0x6898)
    s44 = g(0x63F8)
    s32 = 2 if g(0x9714) != 0 else 0                     # 0x0298C8
    s36 = 1 if g(0x726C) == 1 else 0                     # 0x02F8EA
    # critical section 01FEFA-01FF1E
    wf(0x63B8, c(0x6420))
    wf(0x63BC, c(0x6424))
    wf(0x6424, c(0x63B4))
    wf(0x6420, c(0x6424))
    wf(0x63C0, f_mul(f_add(c(0x63B8), c(0x63BC)), 0.5))
    wf(0x63F0, lk2(0x0AAFE8, IAT, c(0x63C0), rom))
    air = f_fmac(c(0x63C0), c(0x63F0), f_mul(X69F4, K[0x0C3104]))
    tr['air'] = air
    wf(0x63C4, m_min(air, K[0x0C3100]))
    wf(0x6404, lk1(0x0AAE78, RPM, rom) if K[0x0C3144] > VSS else lk1(0x0AAE64, RPM, rom))
    cond = (not (K[0x0C3138] > ECT) and not (K[0x0C313C] > RPM) and not (K[0x0C3140] > PLATE)
            and not (c(0x6404) > X73D0) and (K[0x0C3148] > X62E4))
    flags = (u8(g(0x65C5)) == 1 or u8(g(0x5E94)) == 4 or u8(g(0x65C0)) == 1
             or (u8(g(0x5E94)) == 0 and K[0x0C302F] == 90))
    tr['set'] = cond and flags
    if cond and flags:
        wb(0x641C, 1)
        wb(0x641A, 1)
        tr['641C'] = 'set'
    else:
        wb(0x641A, 0)
        hold = ((K[0x0C314C] > X62E4) and not (K[0x0C3150] > RPM) and u8(g(0x7C9D)) != 1
                and u8(g(0x641B)) != 0)
        if hold:
            tr['641C'] = 'held'
        else:
            wb(0x641C, 0)
            tr['641C'] = 'cleared'
    # 020012
    if u8(c(0x641A)) == 1:
        wb(0x641B, 1)
    else:
        if K[0x0C3154] > PLATE:
            if u8(g(0x6418)) >= K[0x0C3030]:
                wb(0x641B, 0)
        else:
            if u8(g(0x6418)) >= K[0x0C3031]:
                wb(0x641B, 0)
    # 020110
    t_c = lk2(0x0AB004, MAP, RPM, rom)
    t_n = lk2(0x0AB020, MAP, RPM, rom)
    wf(0x63F4, f_fmac(f_sub(1.0, BL), t_c, f_mul(t_n, BL)))
    lim_a = K['A']
    if RPM > 0.1953125:
        wf(0x63E0, m_min(m_fdiv0(f_mul(c(0x63C4), 60.0), RPM), lim_a))
    if X679C > 0.1953125:
        wf(0x63DC, m_min(m_fdiv0(f_mul(c(0x63C4), 60.0), X679C), lim_a))
    wf(0x6428, lk1(0x0AAE14, RPM, rom))
    wf(0x642C, lk1(0x0AAE28, IAT, rom))
    wf(0x6430, lk1(0x0AAE3C, X6898, rom))
    wf(0x63EC, f_mul(f_mul(c(0x6428), c(0x642C)), c(0x6430)))
    wf(0x63E4, m_min(m_lag(c(0x63DC), c(0x63E4), K[0x0C310C], EPS), c(0x63EC)))
    wf(0x6408, f_mul(c(0x63E4), c(0x63F4)))
    if not (u8(g(0x6419)) >= K[0x0C302E]) and u8(g(0x6254)) == 1:
        wf(0x640C, f_sub(f_mul(MAP, K[0x0C3110]), K[0x0C3114]))
        wf(0x6410, m_clamp(m_fdiv0(c(0x640C), c(0x6408)), 1.0, K[0x0C3118]))
        wf(0x6414, c(0x6410))
        tr['6414'] = 'ratio'
    else:
        wf(0x6414, m_clamp(f_sub(c(0x6414), K[0x0C311C]), 1.0, K[0x0C3118]))
        tr['6414'] = 'decay'
    wf(0x63E8, f_mul(c(0x6408), c(0x6414)))
    # 02025C: engine-load cell [63F8]
    if s32 == 2:
        wf(0x63F8, m_max(f_sub(f_mul(MAP, K[0x0C312C]), K[0x0C3130]), 0.0))
        tr['load'] = 'map'
    elif s36 == 1 or not (g(0x67EC) >= K[0x0C3052]):
        wf(0x63F8, lk1(0x0AAE50, ECT, rom))
        tr['load'] = 'ect'
    elif u8(c(0x641C)) == 1 and f_sub(c(0x63DC), c(0x63F8)) > 0.0:
        wf(0x63F8, s44)
        tr['load'] = 'frozen'
    elif u8(c(0x641C)) == 1:
        wf(0x63F8, m_lag(c(0x63DC), c(0x63F8), K[0x0C3120], EPS))
        tr['load'] = 'falling'
    else:
        k = K[0x0C3128] if u8(g(0x647C)) == 1 else K[0x0C3124]
        wf(0x63F8, m_lag(c(0x63E8), c(0x63F8), k, EPS))
        tr['load'] = 'lag'
    wf(0x63FC, f_sub(c(0x63F8), s44))
    wf(0x6400, m_lag(c(0x63F8), c(0x6400), K[0x0C3134], EPS))
    return W, tr


def kinds_of(S):
    out = {}
    for a, v in S.items():
        x = a & 0xFFFF
        out[a] = ('f', v) if x in F_IN else (('w', v) if x in W_IN else ('b', v))
    return out


def run_01FE46(S, rom, ctx):
    e = new_emu(rom)
    setup_state(e, kinds_of(S))
    call(e, 0x01FE46)
    W, tr = m_01FE46(S, rom)
    check_writes(e, W, ctx)
    extra = set(e.uninit_reads) - DECLARED_IN
    assert not extra, f'{ctx}: undeclared inputs read {[hex(x) for x in sorted(extra)]}'
    ok()
    return e, W, tr


def rand_state(rnd):
    def pick(edges, lo, hi):
        return f32(rnd.choice(edges)) if rnd.random() < 0.6 else f32(rnd.uniform(lo, hi))
    S = {}
    S[A(0x620C)] = pick([0.0, 211.82, 760.0, 960.14, 1500.0], 0.0, 2000.0)
    S[A(0x6350)] = pick([-40.0, 69.999, 70.0, 90.0, 110.0], -45.0, 120.0)
    S[A(0x6624)] = pick([0.0, 0.1953125, 0.19532, 800.0, 2999.99, 3000.0, 4000.0, 4399.99, 4400.0, 4500.0,
                         7000.0], 0.0, 8000.0)
    S[A(0x65FC)] = pick([0.0, 49.999, 50.0, 120.0], 0.0, 200.0)
    S[A(0x62E4)] = pick([-10.0, -4.0001, -4.0, -3.999, -0.001, 0.0, 0.001, 5.0], -20.0, 20.0)
    S[A(0x62DC)] = pick([0.0, 1.4999, 1.5, 29.999, 30.0, 85.0], 0.0, 100.0)
    S[A(0x69F4)] = pick([0.0, 1.0, -1.0], -5.0, 20.0)
    S[A(0x73D0)] = pick([7.6, 9.9, 10.0, 10.6, 13.0, 31.99, 32.0], 0.0, 40.0)
    S[A(0x679C)] = pick([0.0, 0.1953125, 0.19532, 3000.0], 0.0, 8000.0)
    S[A(0x90A8)] = pick([0.0, 1.0, 0.5], 0.0, 1.0)
    S[A(0x6364)] = pick([-30.0, 0.0, 25.0, 80.0], -40.0, 90.0)
    S[A(0x6898)] = pick([500.0, 650.0, 800.0], 0.0, 1000.0)
    for x in (0x6420, 0x6424, 0x63B4):
        S[A(x)] = pick([0.0, 2.2, 150.0, 299.9, 300.0, 474.9, 475.0, 600.0], 0.0, 650.0)
    for x in (0x63F8, 0x63DC, 0x63E4, 0x6400):
        S[A(x)] = pick([0.0, 0.3, 1.0, 2.5, 3.9, 4.0, 8.0], 0.0, 9.0)
    S[A(0x6414)] = pick([1.0, 1.05, 2.3, 0.5], 0.0, 3.0)
    for x, ch in ((0x5E94, [0, 1, 4, 0x80]), (0x7C9D, [0, 1, 2]), (0x65C0, [0, 1, 0x81]),
                  (0x6254, [0, 1, 2]), (0x647C, [0, 1]), (0x65C5, [0, 1, 0xFF]), (0x641B, [0, 1, 0x80]),
                  (0x6418, [0, 12, 13, 255]), (0x6419, [0, 124, 125, 0xFF]), (0x641C, [0, 1, 2]),
                  (0x9714, [0, 1, 0x80]), (0x726C, [0, 1, 2])):
        S[A(x)] = rnd.choice(ch) if rnd.random() < 0.8 else rnd.randrange(256)
    S[A(0x67EC)] = rnd.choice([0, 1, 0x7FFF, 0xFFFF])
    return S


def base_state(**kw):
    """a warm cruise-at-boost state; keyword NAME=value overrides, NAME = hex address without 0x"""
    S = {A(0x620C): 1100.0, A(0x6350): 90.0, A(0x6624): 5000.0, A(0x65FC): 100.0, A(0x62E4): -6.0,
         A(0x62DC): 60.0, A(0x69F4): 0.0, A(0x73D0): 11.0, A(0x679C): 5000.0, A(0x90A8): 1.0,
         A(0x6364): 25.0, A(0x6898): 650.0, A(0x63F8): 2.0, A(0x6420): 250.0, A(0x6424): 230.0,
         A(0x63B4): 240.0, A(0x63DC): 2.0, A(0x63E4): 2.0, A(0x6414): 1.0, A(0x6400): 2.0,
         A(0x5E94): 0, A(0x7C9D): 0, A(0x65C0): 0, A(0x6254): 0, A(0x647C): 0, A(0x65C5): 1,
         A(0x641B): 0, A(0x6418): 0, A(0x6419): 200, A(0x641C): 0, A(0x9714): 0, A(0x726C): 0,
         A(0x67EC): 2000}
    for k, v in kw.items():
        S[A(int(k[1:], 16))] = v
    return S


def p1():
    print('P1  0x01FE46 single call: write set, written bytes, read set')
    rnd = random.Random(0x01FE46)
    paths = {}
    n = 0
    for name, rom in BINS:
        for i in range(2000):
            S = rand_state(rnd)
            _, W, tr = run_01FE46(S, rom, f'P1 {name} case {i}')
            key = (tr['641C'], tr['load'], tr['6414'])
            paths[key] = paths.get(key, 0) + 1
            n += 1
    # non-finite corners
    for name, rom in BINS:
        for x in (0x63B4, 0x6420, 0x6424, 0x69F4, 0x6624, 0x679C, 0x65FC, 0x62DC, 0x73D0, 0x62E4, 0x6350):
            for v in (NAN, INF, -INF):
                run_01FE46(base_state(**{f'x{x:04X}': v}), rom, f'P1 {name} {x:#x}={v}')
                n += 1
    print(f'    {n} single calls matched the model exactly; paths ([641C], load source, [6414]) seen:')
    for k in sorted(paths):
        print(f'      {k}: {paths[k]}')
    need = {('held', 'lag', 'decay'), ('cleared', 'lag', 'decay'), ('held', 'frozen', 'decay'),
            ('set', 'frozen', 'decay'), ('set', 'falling', 'decay'), ('cleared', 'map', 'decay'),
            ('cleared', 'ect', 'decay'), ('cleared', 'lag', 'ratio')}
    assert need <= set(paths), f'paths not exercised: {need - set(paths)}'
    # a SET call always leaves [641C] = 1, so the normal lag path cannot follow it in the same call
    assert not any(k[0] == 'set' and k[1] == 'lag' for k in paths)
    ok(2)


def p2():
    print('P2  MAF limit: [63C4] = min([63C0]*[63F0] + [69F4]*1.0, 0x0C3100); g/rev caps at 0x020384')
    print('    window max = min = M g/s, [69F4] = 0, IAT 25 C; RPM 6000, [679C] = 6000')
    print('    bin      0x0C3100  0x020384  0x0AAE14(6000) |  M -> [63C4]  [63E0]  [63DC]  [63E4]')
    for name, rom in BINS:
        K = cal(rom)
        for M in (100.0, 250.0, 299.0, 300.0, 350.0, 400.0, 474.0, 475.0, 500.0, 600.0):
            S = base_state(x63B4=M, x6420=M, x6424=M, x6624=6000.0, x679C=6000.0)
            e, W, tr = run_01FE46(S, rom, f'P2 {name} {M}')
            q = lambda x: e.read_f32(A(x))      # noqa: E731
            want = min(M, K[0x0C3100])
            assert q(0x63C4) == want
            ok()
            print(f'    {name:7s} {K[0x0C3100]:8.1f}  {K["A"]:8.3f}  {lk1(0x0AAE14, 6000.0, rom):8.4f}       '
                  f'| {M:5.0f} -> {q(0x63C4):7.2f}  {q(0x63E0):6.4f}  {q(0x63DC):6.4f}  {q(0x63E4):6.4f}')
    # the cap is on the SUM, after the IAT factor and the additive term
    for name, rom in BINS:
        K = cal(rom)
        for add in (-50.0, 0.0, 80.0, 400.0):
            S = base_state(x63B4=300.0, x6420=300.0, x6424=300.0, x69F4=add)
            e, W, tr = run_01FE46(S, rom, f'P2 add {name} {add}')
            assert e.read_f32(A(0x63C4)) == min(f32(300.0 + add), K[0x0C3100])
            ok()
    print('    cap applies to ([63C0]*[63F0] + [69F4]*0x0C3104): checked with [69F4] in -50, 0, 80, 400')
    # NaN airflow -> the cap value itself (0x0BE970 returns fr5 when fr5 > fr4 is false)
    for name, rom in BINS:
        e, W, tr = run_01FE46(base_state(x69F4=NAN), rom, 'P2 nan')
        assert e.read_f32(A(0x63C4)) == cal(rom)[0x0C3100]
        ok()
    print('    a NaN sum stores the cap value (0x0BE970 contract): checked in all three bins')


def p3():
    print('P3  the [641C] latch over many calls (one emulator; 0x020580 between calls counts [6418])')
    rom = ROM
    e = new_emu(rom)
    S = base_state(x73D0=9.0)                  # below [6404] -> not set
    setup_state(e, kinds_of(S))
    log = []

    def step(note, **kw):
        for k, v in kw.items():
            x = int(k[1:], 16)
            if x in F_IN:
                e.ram_f32(A(x), v)
            elif x in W_IN:
                e.ram_u16(A(x), v)
            else:
                e.ram_u8(A(x), v)
        before = {A(x): (e.read_f32(A(x)) if x in F_IN else (e.read_u16(A(x)) if x in W_IN else e.read_u8(A(x))))
                  for x in F_IN + B_IN + W_IN}
        call(e, 0x01FE46)
        W, tr = m_01FE46(before, rom)
        check_writes(e, W, f'P3 {note}')
        call(e, 0x020580)                      # [6418] := 0 if [641A] == 1 else sat+1
        want = 0 if e.read_u8(A(0x641A)) == 1 else m_satadd8(before[A(0x6418)], 1)
        assert e.read_u8(A(0x6418)) == want
        ok()
        log.append((note, e.read_u8(A(0x641C)), e.read_u8(A(0x641A)), e.read_u8(A(0x641B)),
                    e.read_u8(A(0x6418)), tr['load'], e.read_f32(A(0x63F8)), e.read_f32(A(0x63DC))))
        return tr

    step('below threshold')
    assert e.read_u8(A(0x641C)) == 0
    tr = step('[73D0] 11.0 >= [6404] 10.0', x73D0=11.0)
    assert tr['641C'] == 'set' and e.read_u8(A(0x641B)) == 1
    # set conditions drop ([73D0] below [6404]); latch holds while [641B] != 0
    held = 0
    for i in range(20):
        tr = step(f'cond off, call {i}', x73D0=9.0)
        if tr['641C'] == 'held':
            held += 1
        else:
            break
    print(f'    after the set condition lapses the latch held for {held} further calls '
          f'(0x0C3030 = 0x0C3031 = {rom[0x0C3030]}), then {tr["641C"]}')
    assert held == rom[0x0C3030] + 1 and tr['641C'] == 'cleared'
    ok()
    # release conditions while [641B] still 1
    for name, kw in (('RPM 2999', dict(x6624=2999.0)), ('[62E4] 0.0', dict(x62E4=0.0)),
                     ('[7C9D] 1', dict(x7C9D=1))):
        step('re-set', x73D0=11.0, x6624=5000.0, x62E4=-6.0, x7C9D=0)
        assert e.read_u8(A(0x641C)) == 1
        tr = step(f'release by {name}', x73D0=9.0, **kw)
        assert tr['641C'] == 'cleared', name
        ok()
        print(f'    release by {name}: [641C] cleared on the first call with the set condition off')
    # frozen rising load: latch set, MAF-derived [63DC] above [63F8] -> [63F8] unchanged
    step('re-set', x73D0=11.0, x6624=5000.0, x62E4=-6.0, x7C9D=0, x63F8=1.5)
    l0 = e.read_f32(A(0x63F8))
    tr = step('latched, airflow up', x73D0=11.0, x63B4=400.0, x6420=400.0, x6424=400.0)
    print(f'    latched, airflow raised: [63DC] {e.read_f32(A(0x63DC)):.4f} > [63F8] -> path {tr["load"]}, '
          f'[63F8] stays {e.read_f32(A(0x63F8)):.4f} (was {l0:.4f})')
    assert tr['load'] == 'frozen' and e.read_f32(A(0x63F8)) == l0
    ok()
    tr = step('latched, airflow down', x73D0=11.0, x63B4=60.0, x6420=60.0, x6424=60.0)
    print(f'    latched, airflow lowered: path {tr["load"]}, [63F8] = [63DC] = {e.read_f32(A(0x63F8)):.4f} '
          f'(0x0C3120 = {rd_f(rom, 0x0C3120)} -> no lag)')
    assert tr['load'] == 'falling' and e.read_f32(A(0x63F8)) == e.read_f32(A(0x63DC))
    ok()
    # unlatched: same step lags with k = 0.09
    e2 = new_emu(rom)
    setup_state(e2, kinds_of(base_state(x73D0=9.0, x63F8=1.5, x63B4=400.0, x6420=400.0, x6424=400.0)))
    call(e2, 0x01FE46)
    print(f'    unlatched, same airflow step: [63F8] 1.5 -> {e2.read_f32(A(0x63F8)):.4f} '
          f'(lag k = 0x0C3124 = {rd_f(rom, 0x0C3124):.4f} toward [63E8] = {e2.read_f32(A(0x63E8)):.4f})')
    assert e2.read_f32(A(0x63F8)) > 1.5
    ok()
    print('    call log: note | [641C] [641A] [641B] [6418] | load path, [63F8], [63DC]')
    for r in log:
        print(f'      {r[0]:28s} | {r[1]} {r[2]} {r[3]} {r[4]:3d} | {r[5]:7s} {r[6]:.4f} {r[7]:.4f}')
    # vehicle speed below 50: [6404] = 32.0 from 0x0AAE78, so [73D0] = 31.9 does not set
    for name, rom_ in BINS:
        e3, W, tr = run_01FE46(base_state(x65FC=49.9, x73D0=31.9), rom_, 'P3 slow')
        assert tr['641C'] != 'set' and same(e3.read_f32(A(0x6404)), lk1(0x0AAE78, 5000.0, rom_))
        e3, W, tr = run_01FE46(base_state(x65FC=49.9, x73D0=32.0), rom_, 'P3 slow 32')
        assert tr['641C'] == 'set'
        ok(2)
    print('    VSS < 50: threshold [6404] = 0x0AAE78 = 31.9995 (all three bins); 31.9 does not set, 32.0 does')
    # the 0x0AAE64 threshold over RPM at VSS >= 50 (gate RPM >= 4400 too)
    pts = []
    for rpm in (4400.0, 4500.0, 5000.0, 6000.0, 7000.0):
        pts.append((rpm, lk1(0x0AAE64, rpm, ROM)))
    print('    VSS >= 50: [6404] = 0x0AAE64(RPM) at the gate RPMs: ' +
          ', '.join(f'{r:.0f}->{v:.3f}' for r, v in pts))
    assert pts[0][1] == f32(13.0 - 3.0 * 400.0 / 500.0) or abs(pts[0][1] - 10.6) < 1e-3
    ok()


def p4():
    print('P4  clearers 0x020678 / 0x020726 over the coolant axis and every [65F6] byte')
    n = 0
    for name, rom in BINS:
        for ect in (-45.0, -40.0, -35.0, 0.0, 20.0, 69.9, 90.0, 110.0, 130.0, NAN):
            for b65F6 in range(256):
                if b65F6 not in (0, 1, 2, 0x80, 0xFF) and ect not in (90.0,):
                    continue
                v1 = lk1(0x0AAE00, ect, rom)
                v2 = lk1(0x0AAE50, ect, rom)
                # 0x020678
                e = new_emu(rom)
                setup_state(e, {A(0x6350): ('f', ect), A(0x65F6): ('b', b65F6)})
                call(e, 0x020678)
                W = {}
                for x in (0x63B4, 0x6434, 0x63B8, 0x63BC, 0x6420, 0x6424, 0x63C0, 0x63C4, 0x63D8, 0x63CC):
                    W[A(x)] = ('f', v1)
                for x in (0x63DC, 0x63E0, 0x63E4, 0x63E8, 0x63F8, 0x6400, 0x640C, 0x6408):
                    W[A(x)] = ('f', v2)
                for x, v in ((0x641C, 0), (0x641A, 0), (0x641B, 0), (0x6419, 0xFF), (0x6439, b65F6),
                             (0x6438, 0xFF)):
                    W[A(x)] = ('b', v)
                check_writes(e, W, f'P4 020678 {name} {ect} {b65F6}')
                assert set(e.uninit_reads) <= {A(0x6350), A(0x65F6)}
                # 0x020726
                e = new_emu(rom)
                setup_state(e, {A(0x6350): ('f', ect), A(0x65F6): ('b', b65F6)})
                call(e, 0x020726)
                W = {}
                if b65F6 == 1:
                    for x in (0x63B8, 0x63BC, 0x63C0, 0x63C4, 0x63CC):
                        W[A(x)] = ('f', v1)
                    for x in (0x63DC, 0x63E0, 0x63E4, 0x63E8, 0x63F8, 0x6400, 0x640C, 0x6408):
                        W[A(x)] = ('f', v2)
                    for x in (0x641C, 0x641A, 0x641B):
                        W[A(x)] = ('b', 0)
                check_writes(e, W, f'P4 020726 {name} {ect} {b65F6}')
                assert set(e.uninit_reads) <= {A(0x6350), A(0x65F6)}
                ok(2)
                n += 2
    print(f'    {n} calls matched; seeds (20.19c): ' + ', '.join(
        f'{t:.0f}C {lk1(0x0AAE00, t, ROM):.3f} / {lk1(0x0AAE50, t, ROM):.3f}' for t in (-40.0, 20.0, 90.0)))


def p5():
    print('P5  context functions 0x0203DC, 0x020426, 0x020580, 0x0205A4')
    rnd = random.Random(0x0203DC)
    n = 0
    for name, rom in BINS:
        for i in range(400):
            b = rnd.choice([0, 1, 2, 0xFF])
            v40B4, mx, mn = (f32(rnd.uniform(0, 500)) for _ in range(3))
            ect = f32(rnd.uniform(-40, 110))
            e = new_emu(rom)
            setup_state(e, {A(0x40B4): ('f', v40B4), A(0x6420): ('f', mx), A(0x6424): ('f', mn),
                            A(0x65F6): ('b', b), A(0x6350): ('f', ect)})
            call(e, 0x0203DC)
            W = {A(0x63B4): ('f', v40B4)}
            if b == 1:
                v = lk1(0x0AAE00, ect, rom)
                W[A(0x6420)] = ('f', v)
                W[A(0x6424)] = ('f', v)
            else:
                W[A(0x6420)] = ('f', m_max(mx, v40B4))
                W[A(0x6424)] = ('f', m_min(mn, v40B4))
            check_writes(e, W, f'P5 0203DC {name} {i}')
            # 0x020426
            cnt = rnd.choice([0, 6, 7, 8, 254, 255])
            a, s = f32(rnd.uniform(0, 500)), f32(rnd.uniform(0, 500))
            e = new_emu(rom)
            setup_state(e, {A(0x6438): ('b', cnt), A(0x63C4): ('f', a), A(0x6434): ('f', s)})
            call(e, 0x020426)
            c1 = m_satadd8(cnt, 1)
            if c1 >= rom[0x0C302D]:
                W = {A(0x6438): ('b', 0), A(0x63C8): ('f', f_sub(a, s)), A(0x6434): ('f', a)}
            else:
                W = {A(0x6438): ('b', c1)}
            check_writes(e, W, f'P5 020426 {name} {i}')
            # 0x020580
            fl, c = rnd.choice([0, 1, 2, 0xFF]), rnd.choice([0, 12, 13, 254, 255])
            e = new_emu(rom)
            setup_state(e, {A(0x641A): ('b', fl), A(0x6418): ('b', c)})
            call(e, 0x020580)
            check_writes(e, {A(0x6418): ('b', 0 if fl == 1 else m_satadd8(c, 1))}, f'P5 020580 {name} {i}')
            # 0x0205A4
            t, c, x = rnd.choice([0, 1, 2]), rnd.choice([0, 124, 125, 254, 255]), \
                f32(rnd.choice([0.0, 4999.99, 5000.0, 7000.0, rnd.uniform(0, 8000)]))
            e = new_emu(rom)
            setup_state(e, {A(0x726C): ('b', t), A(0x6419): ('b', c), A(0x6210): ('f', x)})
            call(e, 0x0205A4)
            if t == 1:
                w = 0xFF
            elif not (rd_f(rom, 0x0C3158) > x):
                w = 0
            else:
                w = m_satadd8(c, 1)
            check_writes(e, {A(0x6419): ('b', w)}, f'P5 0205A4 {name} {i}')
            n += 4
    print(f'    {n} calls matched (window max/min of [40B4] into [6420]/[6424]; [63C8] = 8-call change '
          f'of [63C4]; [6418] runs since [641A] = 1; [6419] runs with [6210] < 5000)')


def up(x):
    """next float32 above x (x finite)"""
    b = E.f2b(x)
    return E.b2f(b + 1) if x > 0 else (E.b2f(0x00000001) if x == 0 else E.b2f(b - 1))


def dn(x):
    """next float32 below x (x finite)"""
    b = E.f2b(x)
    return E.b2f(b - 1) if x > 0 else (E.b2f(0x80000001) if x == 0 else E.b2f(b + 1))


def p6():
    print('P6  review settlement (C6, C22, C24, Cruise == Non-Cruise, hold length vs rate, -Inf edge)')
    # ---- C6: which inputs of 0x01FE46 differ between the bins
    S, C, R = STOCK, ROM, REV_E
    d = [a for a in range(0x0C302D, 0x0C315C) if not (S[a] == C[a] == R[a])]
    assert d == [0x0C3101, 0x0C3102], d                      # only the MAF limit 0x0C3100 (300 -> 475)
    assert (rd_f(S, 0x0C3100), rd_f(C, 0x0C3100), rd_f(R, 0x0C3100)) == (300.0, 475.0, 475.0)
    assert (S[0x020384:0x020388].hex(), C[0x020384:0x020388].hex(), R[0x020384:0x020388].hex()) == \
        ('40800000', '41000000', '41000000')                  # Limit A pool word 4.0 -> 8.0
    rd = [0x0AAE14 + i for i in range(20) if not (S[0x0AAE14 + i] == C[0x0AAE14 + i] == R[0x0AAE14 + i])]
    assert rd == [0x0AAE20, 0x0AAE21], rd                     # Limit B scale field 2^-14 -> 2^-13
    assert (S[0x0C3608:0x0C360C].hex(), C[0x0C3608:0x0C360C].hex(), R[0x0C3608:0x0C360C].hex()) == \
        ('f99af99a', 'ffffffff', 'ffffffff')                  # Limit B data
    assert (lk1(0x0AAE14, 6000.0, S), lk1(0x0AAE14, 6000.0, C)) == (f32(0xF99A * 2.0 ** -14), f32(0xFFFF * 2.0 ** -13))
    same3 = lambda lo, hi: S[lo:hi] == C[lo:hi] == R[lo:hi]          # noqa: E731
    for rec in (0x0AAFE8, 0x0AAE64, 0x0AAE78, 0x0AAE28, 0x0AAE3C, 0x0AB004, 0x0AB020, 0x0AAE50, 0x0AAE00):
        n = 28 if C[rec + 3] else 20
        assert same3(rec, rec + n), f'record {rec:#x} differs'
    for lo, hi in ((0x0C3698, 0x0C36F8), (0x0C360C, 0x0C367C), (0x0C3530, 0x0C3570), (0x0C35E0, 0x0C3600),
                   (0x0C3678, 0x0C3698), (0x0C3B7C, 0x0C3B90), (0x0C3BB0, 0x0C3BD8)):
        assert same3(lo, hi), f'{lo:#x}..{hi:#x} differs'       # unchanged axes / data
    assert S[0x0C3B90:0x0C3BB0] != C[0x0C3B90:0x0C3BB0] == R[0x0C3B90:0x0C3BB0]   # MAF-comp +8 axis tuned
    for lo, hi in ((0x0C3BD8, 0x0C3D3C), (0x0C3CD8, 0x0C3E3C)):                      # load-comp axes + data
        assert S[lo:hi] != C[lo:hi] and C[lo:hi] == R[lo:hi]
    # whole function inputs: 20.19c and 20.19e identical in every byte checked above
    ok(12)
    print('    stock -> 20.19c: 0x0C3100 300 -> 475 (only CAL scalar in 0x0C302D..0x0C315B that differs), '
          'pool 0x020384 4.0 -> 8.0, 0x0AAE20 2^-14 -> 2^-13 with data 0xF99A -> 0xFFFF (Limit B 3.9 -> 7.99988), '
          '0x0AB004 / 0x0AB020 data + axes, 0x0AAFE8 +8 axis; 20.19c == 20.19e in all')
    # ---- Cruise and Non-Cruise maps byte-identical (record fields from +1, axes, data)
    for name, rom in BINS:
        assert rom[0x0AB004:0x0AB004 + 4] == rom[0x0AB020:0x0AB020 + 4]               # dimensions
        assert rom[0x0AB004 + 16:0x0AB004 + 28] == rom[0x0AB020 + 16:0x0AB020 + 28]   # typecode, scale, bias
        assert rom[0x0C3BD8:0x0C3C3C] == rom[0x0C3CD8:0x0C3D3C]                        # both axes
        assert rom[0x0C3C3C:0x0C3C3C + 154] == rom[0x0C3D3C:0x0C3D3C + 154]            # 11 x 14 uint8 data
        worst = 0
        for bl in (0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0):
            for mp, rpm in ((300.0, 2500.0), (760.0, 3333.0), (900.0, 2500.0), (900.0, 3333.0)):
                e, W, tr = run_01FE46(base_state(x90A8=f32(bl), x620C=mp, x6624=rpm), rom, f'P6 blend {name}')
                cru = lk2(0x0AB004, mp, rpm, rom)
                assert cru == lk2(0x0AB020, mp, rpm, rom)
                got = e.read_f32(A(0x63F4))
                if bl in (0.0, 1.0):
                    assert got == cru                  # exact: no rounding is involved at 0 and 1
                dif = abs(E.f2b(got) - E.f2b(cru))
                worst = max(worst, dif)
                assert dif <= 1
                ok(2)
        e, W, tr = run_01FE46(base_state(x90A8=NAN), rom, 'P6 blend NaN')
        assert e.read_f32(A(0x63F4)) != e.read_f32(A(0x63F4))
        ok()
        print(f'    {name}: 0x0AB004 == 0x0AB020 (axes, data, typecode / scale / bias); [63F4] = Cruise value '
              f'exactly at [90A8] 0 and 1, within {worst} ulp at 0.1..0.9; NaN [90A8] -> NaN')
    # the same byte identity in every AE5L600L image directly under rom/ (rom/reference/ holds other ROMs)
    imgs = 0
    for fn in sorted(os.listdir(os.path.join(ROOT, 'rom'))):
        pth = os.path.join(ROOT, 'rom', fn)
        if not fn.endswith('.bin') or not os.path.isfile(pth) or os.path.getsize(pth) != 0x100000:
            continue
        r = open(pth, 'rb').read()
        assert r[0x0AB004 + 4:0x0AB004 + 16] == bytes.fromhex('000c3bd8000c3c04000c3c3c'), fn
        assert r[0x0AB020 + 4:0x0AB020 + 16] == bytes.fromhex('000c3cd8000c3d04000c3d3c'), fn
        assert r[0x0AB004:0x0AB004 + 4] == r[0x0AB020:0x0AB020 + 4], fn
        assert r[0x0AB004 + 16:0x0AB004 + 28] == r[0x0AB020 + 16:0x0AB020 + 28], fn
        assert r[0x0C3BD8:0x0C3C3C] == r[0x0C3CD8:0x0C3D3C] and r[0x0C3C3C:0x0C3CD6] == r[0x0C3D3C:0x0C3DD6], fn
        imgs += 1
    assert imgs == 20, imgs
    ok()
    print(f'    Cruise == Non-Cruise (pointers, dims, typecode / scale / bias, axes, data) in all {imgs} images '
          f'directly under rom/')
    # ---- C22: each set gate alone at its boundary, one ulp inside, and NaN (base_state sets the latch)
    th = lk1(0x0AAE64, 5000.0, ROM)
    cases = [('x6350', 70.0, True), ('x6350', dn(70.0), False), ('x6350', NAN, True),
             ('x6624', 4400.0, True), ('x6624', dn(4400.0), False), ('x6624', NAN, True),
             ('x62DC', 30.0, True), ('x62DC', dn(30.0), False), ('x62DC', NAN, True),
             ('x73D0', th, True), ('x73D0', dn(th), False), ('x73D0', NAN, True),
             ('x62E4', -4.0, False), ('x62E4', dn(-4.0), True), ('x62E4', NAN, False),
             ('x65C5', 0x81, False), ('x5E94', 0x84, False)]
    for k, v, want in cases:
        kw = {k: v}
        if k == 'x5E94':
            kw['x65C5'] = 0
        e, W, tr = run_01FE46(base_state(**kw), ROM, f'P6 set {k}={v}')
        assert tr['set'] == want and (e.read_u8(A(0x641C)) == 1) == want, (k, v, want, tr)
        ok()
    for k, v in (('x5E94', 4), ('x65C0', 1)):
        e, W, tr = run_01FE46(base_state(x65C5=0, **{k: v}), ROM, f'P6 flag {k}')
        assert tr['set']
        ok()
    e, W, tr = run_01FE46(base_state(x6624=NAN), ROM, 'P6 6404 NaN rpm')
    v6404 = e.read_f32(A(0x6404))
    assert v6404 == v6404 and v6404 == lk1(0x0AAE64, 7500.0, ROM)   # NaN RPM -> last cell, finite
    ok()
    print('    set gates: [6350] 70 / [6624] 4400 / [62DC] 30 / [73D0] = [6404] set, one ulp below does not; '
          'NaN in any of those four SETS; [62E4] = -4.0 does not set, one ulp below does, NaN does not; '
          f'NaN RPM gives [6404] = last cell {v6404}')
    # ---- C24: hold gates (latch already 1, [641B] = 1, set condition off by [73D0] = 9.0)
    hold = dict(x73D0=9.0, x641C=1, x641B=1)
    for k, v, want in (('x62E4', 0.0, 'cleared'), ('x62E4', -0.0, 'cleared'), ('x62E4', -1e-30, 'held'),
                       ('x62E4', NAN, 'cleared'), ('x6624', 3000.0, 'held'), ('x6624', dn(3000.0), 'cleared'),
                       ('x6624', NAN, 'held'), ('x7C9D', 1, 'cleared'), ('x7C9D', 0x81, 'held'),
                       ('x641B', 0, 'cleared'), ('x641B', 0x80, 'held')):
        kw = dict(hold)
        kw[k] = v
        e, W, tr = run_01FE46(base_state(**kw), ROM, f'P6 hold {k}={v}')
        assert tr['641C'] == want, (k, v, tr)
        assert (A(0x641C) in e.writes) == (want == 'cleared')
        ok(2)
    print('    hold gates: [62E4] 0.0 / -0.0 / NaN clear, -1e-30 holds; RPM 3000 holds, one ulp below clears, '
          'NaN RPM HOLDS; [7C9D] 1 clears, 0x81 holds; [641B] 0 clears, 0x80 holds; a held call stores nothing '
          'to [641C]')
    # ---- hold length vs the number n of 0x020580 calls per 0x01FE46 call: ceil(13/n) + 1
    for n_per in (1, 2, 3, 13):
        e = new_emu(ROM)
        setup_state(e, kinds_of(base_state(x73D0=11.0)))
        call(e, 0x01FE46)
        assert e.read_u8(A(0x641C)) == 1
        for _ in range(n_per):
            call(e, 0x020580)
        held = 0
        for _ in range(60):
            e.ram_f32(A(0x73D0), 9.0)
            call(e, 0x01FE46)
            if e.read_u8(A(0x641C)) != 1:
                break
            held += 1
            for _ in range(n_per):
                call(e, 0x020580)
        assert ROM[0x0C3030] == ROM[0x0C3031] == 13
        want = -(-13 // n_per) + 1
        print(f'    0x020580 x{n_per} per 0x01FE46 call: latch held {held} calls after the last set call '
              f'(ceil(13/{n_per}) + 1 = {want})')
        assert held == want
        ok()
    # ---- -Inf airflow: the k = 1.0 lag of 0x0BEA40 returns NaN for A = -Inf (B finite)
    e, W, tr = run_01FE46(base_state(x69F4=-INF), ROM, 'P6 -Inf latched')
    q = lambda x: e.read_f32(A(x))       # noqa: E731
    assert tr['set'] and tr['load'] == 'falling'
    assert q(0x63C4) == -INF and q(0x63DC) == -INF and q(0x63E4) == q(0x63EC)
    assert all(q(x) != q(x) for x in (0x63F8, 0x63FC, 0x6400))
    e2, W, tr2 = run_01FE46(base_state(x69F4=-INF, x73D0=9.0), ROM, 'P6 -Inf unlatched')
    assert tr2['load'] == 'lag' and e2.read_f32(A(0x63F8)) == e2.read_f32(A(0x63F8))
    ok(4)
    print(f'    [69F4] = -Inf: [63C4] = [63DC] = -Inf, [63E4] = [63EC] = {q(0x63EC)}; latched (falling path) '
          f'[63F8] = [63FC] = [6400] = NaN; unlatched [63F8] stays finite ({e2.read_f32(A(0x63F8))})')


def p7():
    print('P7  the writers of byte [65F6]: 0x022F1C and 0x022DB0 (critical-section pair and 0x006FF6 stubbed)')
    seen = []

    def mk(rom):
        e = E.Emu(rom)
        e.stub(0x0BE81C)                  # critical-section enter (mask saved through r4; ldc sr)
        e.stub(0x0BE82C)                  # leave
        e.stub(0x006FF6, fn=lambda em: seen.append(em.R[4] & 0xFFFFFFFF))   # not followed; records r4
        return e
    n = 0
    for name, rom in BINS:
        for v in range(256):
            seen.clear()
            e = mk(rom)
            setup_state(e, {A(0x415C): ('b', v)})
            e.writes = {}
            e.call(0x022F1C)
            W = {A(0x65F6): ('b', v)}
            if v == 1:
                W[A(0x65F7)] = ('b', 0)
            check_writes(e, W, f'P7 022F1C {name} {v}')
            assert seen == ([0] if v == 1 else []), seen
            assert {a for a in e.uninit_reads if a < 0xFFFFB000} == {A(0x415C)}
            ok()
            n += 1
        for v in list(range(256)) + [0x1234, 0xFFFFFF05]:
            for w4154 in (0x00000040, 0x40000000, 0x80000003, 0xFFFFFFF0):   # >>2 exact in f32
                if w4154 != 0x00000040 and v not in (0, 6, 12, 18, 0x80):
                    continue
                e = mk(rom)
                poke(e, A(0x4154), struct.pack('>I', w4154))
                e.writes = {}
                e.call(0x022DB0, regs={4: v})
                u = v & 0xFF
                k = (u >= 6) + (u >= 12) + (u >= 18)
                ph = 2 if u < 6 else (1 if u < 12 else (0 if u < 18 else 3))
                s = struct.unpack('>i', struct.pack('>I', w4154))[0] >> 2
                W = {A(0x65F6): ('b', 0), A(0x65F0): ('b', u), A(0x65F1): ('b', (u - 6 * k) & 0xFF),
                     A(0x65F2): ('b', ph), A(0x65EC): ('f', f32(float(s)))}
                check_writes(e, W, f'P7 022DB0 {name} {v:#x} {w4154:#x}')
                assert {a for a in e.uninit_reads if a < 0xFFFFB000} <= {A(0x4154) + i for i in range(4)}
                ok()
                n += 1
    print(f'    {n} calls matched: 0x022F1C [65F6] = byte [415C], and when that is 1: [65F7] = 0 and a call of '
          f'0x006FF6 with r4 = 0; 0x022DB0 [65F6] = 0, [65F0] = u8 r4, [65F1] = u - 6*k (k = number of 6 / 12 / '
          f'18 passed), [65F2] = 2 / 1 / 0 / 3, [65EC] = float([4154] >> 2)')


def main():
    for name, rom in BINS:
        # code identical in the three bins except the pool word 0x020384 (Engine Load Limit A); the whole
        # 4-byte word is excluded, and within it only its high half differs
        for lo, hi in ((0x01FE46, 0x020384), (0x020388, 0x0207D0)):
            assert rom[lo:hi] == ROM[lo:hi], f'{name} code differs in {lo:#x}..{hi:#x}'
        assert rom[0x020386:0x020388] == b'\x00\x00'
        ok()
    print('code 0x01FE46..0x0207D0 identical in stock / 20.19c / 20.19e except the pool word 0x020384: ' +
          ', '.join(f'{n} {rd_f(r, 0x020384)}' for n, r in BINS))
    p1()
    p2()
    p3()
    p4()
    p5()
    p6()
    p7()
    print(f'PASS  {CHECKS} checks')
    return 0


if __name__ == '__main__':
    sys.exit(main())
