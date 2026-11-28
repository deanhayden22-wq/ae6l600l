#!/usr/bin/env python3
"""Emulation check for the FFB CL-side / per-cylinder addend trace (function programme batch 4).

    python3 scripts/trace/emu_ffb_cl_side.py

Reference bin: rom/AE5L600L 20g rev 20.19c.bin  md5 92cae8275cd4f9b473a3a9e36efe6449
Trace:         disassembly/analysis/ffb_cl_side_trace.txt

Each function is run in scripts/sh2e_emu.py against a Python model written from the fn_dump
listings. Per case the EXACT set of non-stack RAM bytes written and their values is asserted,
the RAM read before written must be a subset of the declared inputs, r8-r14 / r15 / GBR /
fr12-fr15 must come back, and over all cases every instruction address reachable from the
entry (function_census.reg_states CFG) must have executed.

  Q1  0x03043A -> 0x030454 (always) and 0x0304BE (only when bit 0 of r4 is clear): [7354]
  Q2  0x030754 -> 0x03076E (always) and 0x03082E (only when bit 0 of r4 is clear): [7374]
  Q3  0x03605A -> 0x036322 with its bsr 0x036978: the u16 counter [79C0] / [79C2]
  Q4  0x03757A -> 0x0375B8 -> bsr 0x037604, tail 0x037710: the per-cylinder addends [7A78+4i]
  Q5  context writers: 0x02EF56 ([726C] hysteresis), 0x02F550 ([7288]), 0x036962 ([79A0]),
      0x0376EC ([7AB0]) and 0x03757E (reset of [7A78..7A84]); and a DIFFERENTIAL run of
      0x03606C showing its OL target [7990] is scaled by [79A0] and does not read [79C0]
  Q6  calibration / table facts stock vs 20.19c vs 20.19e for every record and scalar used
  Q7  MULTI-CALL courses on one emulator (RAM persists): [7354] and [7374] seeded while
      [726C] = 1 and decaying after it falls, COUPLED to 0x023A94 (the [67EC] writer, run from
      ROM once per pass, both orders); the [7A78+4i] accumulation / decay and cap shrink; the
      reachable-range sweeps of the seeds over coolant, all flag paths and the AD594 / AD5CC factor

REVIEW HISTORY (2026-11-27). The first version held [67EC] = 1000 while [726C] = 1, which
0x023A94 prevents (023AA8 stores 0 to [67EC] whenever [726C] == 1). Q7 now runs 0x023A94 in
the same emulator; the seeded values, zero-call counts and maxima it prints replace the old
ones (0.5 / 0.10009765625 while seeded, open-gate call 217 / call 286, max 1.540802).

ROUNDING. fadd/fsub/fmul modelled as the exact result rounded TOWARD ZERO, fmac fused, as
sh2e_emu does (corrections items 106, 110). Table lookups in the models use the verified
runtime routines 0x0BE830 0x0BE8E4 0x0BE874 0x0BE8AC run in the emulator (cached); the other
helpers (0x0BE53C 0x0BE554 0x0BE56C 0x0BE608 0x0BE960 0x0BE970 0x0BEAB0) are modelled from
their verified CONTRACTs. No claim depends on the last bit of a float. Deterministic. Exit 0.
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
sys.path.insert(0, os.path.join(ROOT, 'scripts', 'mapping'))
import sh2e_emu as E            # noqa: E402
import desc_types as DT         # noqa: E402
import function_census as FC    # noqa: E402

BIN = os.path.join(ROOT, 'rom', 'AE5L600L 20g rev 20.19c.bin')
ROM = open(BIN, 'rb').read()
assert hashlib.md5(ROM).hexdigest() == '92cae8275cd4f9b473a3a9e36efe6449', 'wrong reference bin'
STOCK = open(os.path.join(ROOT, 'rom', 'ae5l600l.bin'), 'rb').read()
REV_E = open(os.path.join(ROOT, 'rom', 'AE5L600L 20g rev 20.19e.bin'), 'rb').read()

FLT_MAX = struct.unpack('>f', b'\x7f\x7f\xff\xff')[0]
NAN = float('nan')
CHECKS = 0
EXECUTED = set()


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


def rd_h(rom, a):
    return struct.unpack_from('>H', rom, a)[0]


def rd_l(rom, a):
    return struct.unpack_from('>I', rom, a)[0]


def s8(v):
    v &= 0xFF
    return v - 256 if v & 0x80 else v


# ---------------------------------------------------------------- rounding toward zero
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


def f_sub(a, b):               # fsub FRm,FRn : FRn = FRn - FRm  ->  f_sub(FRn, FRm)
    return f_add(a, -b)


def f_mul(a, b):
    if a != a or b != b or math.isinf(a) or math.isinf(b):
        return f32(a * b)
    q = Fraction(a) * Fraction(b)
    if q == 0:
        return math.copysign(0.0, sgn(a) * sgn(b))
    return rz32(q)


def f_fmac(f0, fm, fn):        # fmac FR0,FRm,FRn : FRn = FR0*FRm + FRn, one rounding
    if any(v != v or math.isinf(v) for v in (f0, fm, fn)):
        return f32(f0 * fm + fn)
    q = Fraction(f0) * Fraction(fm) + Fraction(fn)
    if q == 0:
        p_neg = sgn(f0) * sgn(fm) < 0
        if (f0 == 0 or fm == 0) and p_neg and sgn(fn) < 0:
            return -0.0
        return 0.0
    return rz32(q)


# ---------------------------------------------------------------- helper CONTRACTS (verified files)
def m_clamp(x, lo, hi):        # 0x0BE56C
    if not (x > lo):
        return lo
    if hi > x:
        return x
    return hi


def m_max(a, b):               # 0x0BE960
    return a if a > b else b


def m_min(a, b):               # 0x0BE970
    return a if b > a else b


def m_outside(x, c, w):        # 0x0BE608: 1 if x outside [c-w, c+w]
    lo = f_sub(c, w)
    if lo > x:
        return 1
    hi = f_add(c, w)
    if x > hi:
        return 1
    return 0


def m_absdiff(a, b):           # 0x0BEAB0
    return abs(f_sub(a, b))


def m_sat8(a, b):              # 0x0BE53C
    return min((a & 0xFF) + (b & 0xFF), 0xFF)


def m_sat16(a, b):             # 0x0BE554
    return min((a & 0xFFFF) + (b & 0xFFFF), 0xFFFF)


# ---------------------------------------------------------------- emulator plumbing
def poke(emu, a, data):
    o = a - E.RAM_LO
    emu.ram[o:o + len(data)] = data


def put(emu, a, kind, v):
    if kind == 'f':
        poke(emu, a, struct.pack('>I', E.f2b(v)))
    elif kind == 'b':
        poke(emu, a, bytes([v & 0xFF]))
    elif kind == 'w':
        poke(emu, a, struct.pack('>H', v & 0xFFFF))
    elif kind == 'l':
        poke(emu, a, struct.pack('>I', v & 0xFFFFFFFF))
    else:
        raise ValueError(kind)


_LK = {}


def _lk(kind, rec, x, y=None, rom=ROM):
    key = (kind, rec, bits(x), None if y is None else bits(y), id(rom))
    if key not in _LK:
        e = E.Emu(rom)
        if kind == 'f1':
            e.call(0x0BE830, regs={4: rec}, fregs={4: x})
            _LK[key] = e.fr(0)
        elif kind == 'f2':
            e.call(0x0BE8E4, regs={4: rec}, fregs={4: x, 5: y})
            _LK[key] = e.fr(0)
        elif kind == 'u8':
            e.call(0x0BE874, regs={4: rec}, fregs={4: x})
            _LK[key] = e.R[0] & 0xFF
        elif kind == 'u16':
            e.call(0x0BE8AC, regs={4: rec}, fregs={4: x})
            _LK[key] = e.R[0] & 0xFFFF
    return _LK[key]


def lk1(rec, x, rom=ROM):
    return _lk('f1', rec, x, rom=rom)


def lk2(rec, x4, x5, rom=ROM):
    return _lk('f2', rec, x4, x5, rom=rom)


def lku8(rec, x, rom=ROM):
    return _lk('u8', rec, x, rom=rom)


def lku16(rec, x, rom=ROM):
    return _lk('u16', rec, x, rom=rom)


SENT_R = {k: 0x1000 * k + 0x55 for k in range(8, 15)}
SENT_F = {12: 12.5, 13: -13.25, 14: 14.125, 15: -15.0625}


def new_emu(rom, S):
    """S is normalised IN PLACE (floats rounded to float32) so the model sees what RAM holds"""
    for a, (k, v) in list(S.items()):
        if k == 'f':
            S[a] = ('f', f32(float(v)))
    e = E.Emu(rom)
    for a, (k, v) in S.items():
        put(e, a, k, v)
    return e


def call(e, entry, regs=None):
    e.steps = 0
    e.writes = {}
    e.uninit_reads = set()
    rr = dict(SENT_R)
    rr.update(regs or {})
    e.gbr = 0xFFFF0ABC
    e.call(entry, regs=rr, fregs=dict(SENT_F))
    for k in range(8, 15):
        assert e.R[k] == rr[k], f'r{k} not restored by {entry:#x}'
    assert e.R[15] == E.STACK_TOP, f'r15 unbalanced by {entry:#x}'
    assert e.gbr == 0xFFFF0ABC, f'GBR not restored by {entry:#x}'
    for k, v in SENT_F.items():
        assert same(e.fr(k), v), f'fr{k} not restored by {entry:#x}'
    EXECUTED.update(e.executed)
    return e


def expect_bytes(W):
    out = {}
    for a, (k, v) in W.items():
        if k == 'f':
            b = struct.pack('>I', E.f2b(v))
        elif k == 'b':
            b = bytes([v & 0xFF])
        elif k == 'w':
            b = struct.pack('>H', v & 0xFFFF)
        else:
            raise ValueError(k)
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


def check_reads(e, S, ctx):
    """every RAM byte read before being written must belong to a declared input cell"""
    allowed = set()
    for a, (k, _) in S.items():
        n = {'f': 4, 'l': 4, 'w': 2, 'b': 1}[k]
        allowed.update(range(a, a + n))
    bad = [a for a in e.uninit_reads if not (e.stack_low - 64 <= a < E.STACK_TOP) and a not in allowed]
    assert not bad, f'{ctx}: undeclared reads {[hex(a) for a in sorted(bad)[:8]]}'
    ok()


def cur(W, S, a):
    return W[a][1] if a in W else S[a][1]


def cfg_pcs(entry):
    return {pc for (pc, role) in FC.reg_states(ROM, entry)}


def assert_coverage(entry, label):
    need = cfg_pcs(entry)
    miss = sorted(need - EXECUTED)
    assert not miss, f'{label}: not executed {[hex(x) for x in miss[:16]]}'
    ok()
    return len(need)


# ================================================================ Q1  [7354]
def m_030454(S, rom=ROM):
    W = {}
    E_ = S[A(0x6350)][1]
    if s8(S[A(0x726C)][1]) != 1:
        return W
    if S[A(0x90C1)][1] & 0xFF:                       # 030466 tst r2 (byte [90C1]); bf/s 030494
        if S[A(0x3158)][1] & 0xFF:
            W[A(0x7358)] = ('f', lk1(0x0AC95C, E_, rom))
        else:
            W[A(0x7358)] = ('f', f_mul(lk1(0x0AC948, E_, rom), S[A(0x7288)][1]))
    else:
        if S[A(0x3158)][1] & 0xFF:
            W[A(0x7358)] = ('f', lk1(0x0AC984, E_, rom))
        else:
            W[A(0x7358)] = ('f', f_mul(lk1(0x0AC970, E_, rom), S[A(0x7288)][1]))
    return W


def m_0304BE(S, rom=ROM):
    """S: state dict with every input; returns write dict"""
    W = {}
    g = lambda a: cur(W, S, A(a))             # noqa: E731
    rpm, c895C, E_, x6354, x6898 = (S[A(a)][1] for a in (0x6624, 0x895C, 0x6350, 0x6354, 0x6898))
    r14 = 1 if s8(S[A(0x67FC)][1]) == 1 else 0                      # 0x023E48
    r12 = S[A(0x67EC)][1] & 0xFFFF
    r10 = S[A(0x726C)][1] & 0xFF
    r11 = S[A(0x90C1)][1] & 0xFF
    if r14 == 1:
        b7368 = rom[0x0CBBD3]
        W[A(0x7368)] = ('b', b7368)
        W[A(0x7364)] = ('f', lk1(0x0AC3CC, E_, rom))
    else:
        b7368 = 1
        W[A(0x7368)] = ('b', 1)
        W[A(0x7364)] = ('f', 1.0)
    r13 = r10
    if (r13 == 1 and (S[A(0x7370)][1] & 0xFF) == 0) or r14 != 0:
        W[A(0x7369)] = ('b', 0)
    else:
        if not (rd_f(rom, 0x0CBE10) > x6354):
            if not (f_add(c895C, rd_f(rom, 0x0CBE14)) > rpm):
                if (S[A(0x3158)][1] & 0xFF) == 0:
                    W[A(0x7369)] = ('b', 1)
    d = f_sub(rpm, c895C)
    W[A(0x735C)] = ('f', d)
    W[A(0x7360)] = ('f', lk2(0x0AD5B0, d, E_, rom))
    nz = m_outside(S[A(0x7354)][1], 0.0, 2.0 ** -12)
    if nz == 0 and r13 == 0:
        W[A(0x7358)] = ('f', 0.0)
        W[A(0x7354)] = ('f', 0.0)
        W[A(0x736A)] = ('w', 0)
        W[A(0x736C)] = ('w', 0)
        W[A(0x7370)] = ('b', r10)
        return W
    w736E = lku16(0x0AC998, E_, rom)
    W[A(0x736E)] = ('w', w736E)
    if r12 > w736E and (S[A(0x7C9D)][1] & 0xFF) == 0:
        if r11 == 0:
            prod = (lku8(0x0AC3AC, E_, rom) * (b7368 & 0xFF)) & 0xFFFF
            w = m_sat16(S[A(0x736A)][1], 1)
            W[A(0x736A)] = ('w', w)
            W[A(0x736C)] = ('w', 0)
            if w >= prod:
                W[A(0x7358)] = ('f', f_mul(S[A(0x7358)][1], lk1(0x0AC3B8, E_, rom)))
                W[A(0x736A)] = ('w', 0)
        else:
            prod = (lku8(0x0AC3A0, E_, rom) * (b7368 & 0xFF)) & 0xFFFF
            w = m_sat16(S[A(0x736C)][1], 1)
            W[A(0x736C)] = ('w', w)
            W[A(0x736A)] = ('w', 0)
            if w >= prod:
                W[A(0x7358)] = ('f', f_mul(S[A(0x7358)][1], lk1(0x0AC3B8, E_, rom)))
                W[A(0x736C)] = ('w', 0)
    else:
        W[A(0x736A)] = ('w', 0)
        W[A(0x736C)] = ('w', 0)
    fr0 = lk2(0x0AD594, x6898, x6354, rom)
    fr8 = f_mul(g(0x7358), g(0x7364))
    fr0 = f_mul(fr0, fr8)
    if s8(g(0x7369)) == 1:
        fr0 = f_mul(fr0, g(0x7360))
    W[A(0x7354)] = ('f', fr0)
    W[A(0x7370)] = ('b', r10)
    return W


def m_03043A(S, r4, rom=ROM):
    W = m_030454(S, rom)
    if r4 & 1:
        return W
    S2 = dict(S)
    for a, kv in W.items():
        S2[a] = kv
    W2 = m_0304BE(S2, rom)
    out = dict(W)
    out.update(W2)
    return out


IN_0304 = {0x6624: 'f', 0x895C: 'f', 0x6350: 'f', 0x6354: 'f', 0x6898: 'f', 0x67FC: 'b', 0x67EC: 'w',
           0x726C: 'b', 0x90C1: 'b', 0x3158: 'b', 0x7C9D: 'b', 0x7370: 'b', 0x7354: 'f', 0x7358: 'f',
           0x736A: 'w', 0x736C: 'w', 0x7369: 'b', 0x7288: 'f'}


def rnd_flag(rnd):
    return rnd.choice([0, 0, 1, 1, 1, 2, 0x81])


def rand_0304(rnd):
    S = {}
    S[A(0x6624)] = ('f', rnd.choice([0.0, 250.0, 800.0, 3000.0, 6500.0, 12000.0, rnd.uniform(0, 9000)]))
    S[A(0x895C)] = ('f', rnd.choice([0.0, 500.0, -9000.0, rnd.uniform(-12000, 3000)]))
    S[A(0x6350)] = ('f', rnd.choice([-45.0, -40.0, -5.0, 25.0, 85.0, 90.0, 115.0, rnd.uniform(-45, 120)]))
    S[A(0x6354)] = ('f', rnd.choice([-35.0, -10.0, -5.0, -1.0, 0.0, 90.0, 119.0, 125.0, rnd.uniform(-40, 130)]))
    S[A(0x6898)] = ('f', rnd.choice([400.0, 504.0, 580.0, 700.0, 760.0, 800.0, rnd.uniform(450, 800)]))
    S[A(0x67FC)] = ('b', rnd_flag(rnd))
    S[A(0x67EC)] = ('w', rnd.choice([0, 37, 38, 39, 500, 0xFFFF, rnd.randrange(0, 70000) & 0xFFFF]))
    S[A(0x726C)] = ('b', rnd_flag(rnd))
    S[A(0x90C1)] = ('b', rnd_flag(rnd))
    S[A(0x3158)] = ('b', rnd.choice([0, 0, 0, 1]))
    S[A(0x7C9D)] = ('b', rnd.choice([0, 0, 0, 1]))
    S[A(0x7370)] = ('b', rnd_flag(rnd))
    S[A(0x7354)] = ('f', rnd.choice([0.0, 2.0 ** -12, -2.0 ** -12, 2.0 ** -11, 0.3, rnd.uniform(-0.01, 1.0)]))
    S[A(0x7358)] = ('f', rnd.choice([0.0, 0.5, 2.5, rnd.uniform(0, 3)]))
    S[A(0x736A)] = ('w', rnd.choice([0, 1, 2, 3, 0xFFFF, rnd.randrange(0, 40)]))
    S[A(0x736C)] = ('w', rnd.choice([0, 1, 2, 3, 0xFFFF, rnd.randrange(0, 40)]))
    S[A(0x7369)] = ('b', rnd.choice([0, 1, 2]))
    S[A(0x7288)] = ('f', rnd.choice([1.0, 0.5, rnd.uniform(0, 2)]))
    return S


def q1():
    rnd = random.Random(1001)
    n = 0
    for i in range(700):
        S = rand_0304(rnd)
        r4 = rnd.choice([0, 1, 2, 3, 0xFE, 0xFF])
        e = new_emu(ROM, S)
        call(e, 0x03043A, regs={4: r4})
        check_writes(e, m_03043A(S, r4), f'Q1 case {i} r4={r4}')
        check_reads(e, S, f'Q1 case {i}')
        n += 1
    # edge cases, each asserted separately
    base = rand_0304(random.Random(7))
    base.update({A(0x726C): ('b', 0), A(0x7354): ('f', 2.0 ** -12), A(0x67FC): ('b', 0), A(0x7C9D): ('b', 0),
                 A(0x67EC): ('w', 500), A(0x90C1): ('b', 0), A(0x7370): ('b', 0)})
    e = call(new_emu(ROM, base), 0x03043A, regs={4: 0})
    assert same(e.read_f32(A(0x7358)), 0.0) and same(e.read_f32(A(0x7354)), 0.0), \
        '[7354] = 2^-12 exactly is INSIDE the band: zeroing path'
    ok()
    b2 = dict(base)
    b2[A(0x7354)] = ('f', f32(2.0 ** -12 * 1.0000001))
    b2[A(0x7358)] = ('f', 0.25)
    e = call(new_emu(ROM, b2), 0x03043A, regs={4: 0})
    assert e.read_f32(A(0x7358)) > 0.0, 'just above 2^-12: not zeroed'
    ok()
    # bit 0 of r4 set: 0x0304BE not run, only 0x030454 (which writes nothing when [726C] != 1)
    e = call(new_emu(ROM, base), 0x03043A, regs={4: 1})
    assert not e.writes, 'r4 odd and [726C] == 0: no write at all'
    ok()
    print(f'Q1 0x03043A/0x030454/0x0304BE: {n} random cases + 3 edges, exact write sets and read sets')
    for ent, lab in ((0x03043A, '0x03043A'), (0x030454, '0x030454')):
        k = assert_coverage(ent, lab)
        print(f'   coverage {lab}: all {k} CFG addresses executed')


# ================================================================ Q2  [7374]
def m_03076E(S, rom=ROM):
    W = {}
    E_ = S[A(0x6350)][1]
    r6 = 1 if s8(S[A(0x65C5)][1]) == 1 else 0                       # 0x022CF4
    if s8(S[A(0x726C)][1]) != 1:
        return W
    if (S[A(0x3158)][1] & 0xFF) == 0:
        if r6 == 1:
            fr13 = lk1(0x0AC9CC, E_, rom)
            r4 = 0x0ACA30
        else:
            fr13 = lk1(0x0AC9B8, E_, rom)
            r4 = 0x0ACA1C
        fr12 = lk1(r4, E_, rom)
        k = S[A(0x7288)][1]
        W[A(0x7378)] = ('f', f_mul(lk1(0x0AC9A4, E_, rom), k))
        W[A(0x737C)] = ('f', f_mul(fr13, k))
        W[A(0x7380)] = ('f', f_mul(lk1(0x0ACA08, E_, rom), k))
        W[A(0x7384)] = ('f', f_mul(fr12, k))
    else:
        W[A(0x7378)] = ('f', lk1(0x0AC9E0, E_, rom))
        W[A(0x737C)] = ('f', lk1(0x0AC9F4, E_, rom))
        W[A(0x7380)] = ('f', lk1(0x0ACA44, E_, rom))
        W[A(0x7384)] = ('f', lk1(0x0ACA58, E_, rom))
    return W


def m_03082E(S, rom=ROM):
    W = {}
    g = lambda a: cur(W, S, A(a))             # noqa: E731
    E_, x6354, x6898 = (S[A(a)][1] for a in (0x6350, 0x6354, 0x6898))
    f67FC = 1 if s8(S[A(0x67FC)][1]) == 1 else 0                    # 0x023E48
    r14 = S[A(0x67EC)][1] & 0xFFFF
    r13 = s8(S[A(0x90C1)][1])
    g647C = 0 if s8(S[A(0x647C)][1]) == 1 else 2                    # 0x021016
    fr15, fr14 = S[A(0x7398)][1], S[A(0x739C)][1]
    w73A0 = lku16(0x0ACA6C, x6354, rom)
    W[A(0x73A0)] = ('w', w73A0)
    if f67FC != 1:
        for a in (0x7388, 0x738C, 0x7390, 0x7394):
            W[A(a)] = ('f', 1.0)
        fr15 = fr14 = 0.0
    else:
        W[A(0x7388)] = ('f', rd_f(rom, 0x0CBE18))
        W[A(0x738C)] = ('f', rd_f(rom, 0x0CBE1C))
        W[A(0x7390)] = ('f', lk1(0x0ACAF0, E_, rom))
        W[A(0x7394)] = ('f', lk1(0x0ACB04, E_, rom))
        if s8(S[A(0x73A2)][1]) == 0:
            fr15 = lk1(0x0ACB18, E_, rom)
            fr14 = lk1(0x0ACB2C, E_, rom)
    W[A(0x73A2)] = ('b', f67FC)
    if r14 > w73A0 and (S[A(0x7C9D)][1] & 0xFF) == 0:
        for cell, rec, fac in ((0x7378, 0x0ACA78, 0x7388), (0x737C, 0x0ACA8C, 0x738C),
                               (0x7380, 0x0ACAA0, 0x7388), (0x7384, 0x0ACAB4, 0x738C)):
            v = f_fmac(-lk1(rec, E_, rom), g(fac), S[A(cell)][1])
            W[A(cell)] = ('f', m_max(v, 0.0))
        fr15 = m_max(f_sub(fr15, lk1(0x0ACAC8, E_, rom)), 0.0)
        fr14 = m_max(f_sub(fr14, lk1(0x0ACADC, E_, rom)), 0.0)
    W[A(0x7398)] = ('f', fr15)
    W[A(0x739C)] = ('f', fr14)
    if r13 != 0 or g647C != 0:
        p0, p1 = g(0x7380), g(0x7384)
    else:
        p0, p1 = g(0x7378), g(0x737C)
    a = f_fmac(p0, g(0x7390), g(0x7398))
    b = f_fmac(p1, g(0x7394), g(0x739C))
    m = m_max(a, b)
    W[A(0x7374)] = ('f', f_mul(m, lk2(0x0AD5CC, x6898, x6354, rom)))
    return W


def m_030754(S, r4, rom=ROM):
    W = m_03076E(S, rom)
    if r4 & 1:
        return W
    S2 = dict(S)
    S2.update(W)
    out = dict(W)
    out.update(m_03082E(S2, rom))
    return out


def rand_0308(rnd):
    S = {}
    S[A(0x6350)] = ('f', rnd.choice([-45.0, -40.0, 0.0, 5.0, 60.0, 90.0, 115.0, rnd.uniform(-45, 120)]))
    S[A(0x6354)] = ('f', rnd.choice([-35.0, -10.0, -5.0, -1.0, 0.0, 90.0, rnd.uniform(-40, 130)]))
    S[A(0x6898)] = ('f', rnd.choice([400.0, 504.0, 600.0, 760.0, 800.0, rnd.uniform(450, 800)]))
    S[A(0x67FC)] = ('b', rnd_flag(rnd))
    S[A(0x67EC)] = ('w', rnd.choice([0, 1, 500, 0xFFFF, rnd.randrange(0, 0x10000)]))
    S[A(0x90C1)] = ('b', rnd_flag(rnd))
    S[A(0x647C)] = ('b', rnd_flag(rnd))
    S[A(0x65C5)] = ('b', rnd_flag(rnd))
    S[A(0x726C)] = ('b', rnd_flag(rnd))
    S[A(0x3158)] = ('b', rnd.choice([0, 0, 1]))
    S[A(0x7C9D)] = ('b', rnd.choice([0, 0, 0, 1]))
    S[A(0x73A2)] = ('b', rnd_flag(rnd))
    S[A(0x7288)] = ('f', rnd.choice([1.0, rnd.uniform(0, 2)]))
    for a in (0x7378, 0x737C, 0x7380, 0x7384):
        S[A(a)] = ('f', rnd.choice([0.0, 0.0002, 0.1, 0.85, rnd.uniform(-0.1, 1.0)]))
    for a in (0x7398, 0x739C):
        S[A(a)] = ('f', rnd.choice([0.0, 0.3, rnd.uniform(-0.2, 1)]))
    return S


def q2():
    rnd = random.Random(2002)
    n = 0
    for i in range(700):
        S = rand_0308(rnd)
        r4 = rnd.choice([0, 1, 2, 3, 0xFF])
        e = call(new_emu(ROM, S), 0x030754, regs={4: r4})
        check_writes(e, m_030754(S, r4), f'Q2 case {i} r4={r4}')
        check_reads(e, S, f'Q2 case {i}')
        n += 1
    print(f'Q2 0x030754/0x03076E/0x03082E: {n} random cases, exact write sets and read sets')
    for ent, lab in ((0x030754, '0x030754'), (0x03076E, '0x03076E')):
        k = assert_coverage(ent, lab)
        print(f'   coverage {lab}: all {k} CFG addresses executed')


# ================================================================ Q3  [79C0] counter
def m_036978(S, rom=ROM):
    W = {}
    rpm, x62DC, x7348 = S[A(0x6624)][1], S[A(0x62DC)][1], S[A(0x7348)][1]
    t1 = lk1(0x0AC5BC, rpm, rom)
    t2 = lk1(0x0AD0A4, rpm, rom)
    W[A(0x79CC)] = ('f', t1)
    W[A(0x79D0)] = ('f', t2)
    b_fe = S[A(0x79FE)][1]
    if not (x62DC > f_sub(t1, rd_f(rom, 0x0CC178))):
        b_fe = 1
        W[A(0x79FE)] = ('b', 1)
    elif x62DC > t1:
        b_fe = 0
        W[A(0x79FE)] = ('b', 0)
    b_ff = S[A(0x79FF)][1]
    if not (x7348 > f_sub(t2, rd_f(rom, 0x0CC174))):
        b_ff = 1
        W[A(0x79FF)] = ('b', 1)
    elif x7348 > t2:
        b_ff = 0
        W[A(0x79FF)] = ('b', 0)
    r0 = 1 if (s8(b_fe) == 1 and s8(b_ff) == 1) else 0
    return W, r0


def m_036322(S, rom=ROM):
    W, b79F3 = m_036978(S, rom)
    g = lambda a: cur(W, S, A(a))             # noqa: E731
    x = S[A(0x63C4)][1]
    W[A(0x79F3)] = ('b', b79F3)
    w79C4 = S[A(0x79C4)][1] & 0xFFFF
    goto = None
    if w79C4 == 0:
        W[A(0x79C2)] = ('w', 0xFFFF)
        goto = 'L3E0'
    elif b79F3 == 1:
        W[A(0x79C2)] = ('w', 0)
        if s8(S[A(0x7C68)][1]) == 1:
            goto = 'L410'
        else:
            w79EC = lku16(0x0AD0D0, x, rom)
            W[A(0x79EC)] = ('w', w79EC)
            c0 = S[A(0x79C0)][1] & 0xFFFF
            W[A(0x79C0)] = ('w', (c0 - w79EC) & 0xFFFF if c0 >= w79EC else 0)
            goto = 'L410'
    else:
        if (S[A(0x79F4)][1] & 0xFF) == 1:
            W[A(0x79C2)] = ('w', S[A(0x79C0)][1] & 0xFFFF)
            goto = 'L410'
        else:
            w79E8 = lku16(0x0AD0B8, x, rom)
            W[A(0x79E8)] = ('w', w79E8)
            c2 = S[A(0x79C2)][1] & 0xFFFF
            if c2 >= w79C4:
                W[A(0x79C2)] = ('w', m_sat16(c2, w79E8))
                goto = 'L3E0'
            else:
                W[A(0x79C2)] = ('w', m_sat16(c2, w79E8))
                W[A(0x79C0)] = ('w', W[A(0x79C2)][1])
                goto = 'L410'
    if goto == 'L3E0':
        w79EA = lku16(0x0AD0C4, x, rom)
        W[A(0x79EA)] = ('w', w79EA)
        c0 = g(0x79C0) & 0xFFFF
        W[A(0x79C0)] = ('w', (c0 - w79EA) & 0xFFFF if c0 >= w79EA else 0)
    c2 = g(0x79C2) & 0xFFFF
    W[A(0x79C8)] = ('b', 1 if (c2 > 0 and not (c2 >= w79C4)) else 0)
    W[A(0x79F4)] = ('b', b79F3)
    return W


def rand_0363(rnd):
    S = {}
    S[A(0x63C4)] = ('f', rnd.choice([0.0, 1.0, 5.5, 10.0, 20.0, rnd.uniform(0, 12)]))
    S[A(0x6624)] = ('f', rnd.choice([0.0, 2000.0, 5000.0, 6400.0, rnd.uniform(0, 7000)]))
    S[A(0x62DC)] = ('f', rnd.choice([0.0, 60.0, 64.0, 72.3, 80.0, rnd.uniform(0, 100)]))
    S[A(0x7348)] = ('f', rnd.choice([0.0, 4000.0, 6000.0, 6700.0, 8000.0, rnd.uniform(0, 8000)]))
    S[A(0x79FE)] = ('b', rnd_flag(rnd))
    S[A(0x79FF)] = ('b', rnd_flag(rnd))
    S[A(0x79C4)] = ('w', rnd.choice([0, 1, 50, 0xFFFF, rnd.randrange(0, 300)]))
    S[A(0x79C2)] = ('w', rnd.choice([0, 1, 49, 50, 51, 0xFFFF, 0xFFFE, rnd.randrange(0, 300)]))
    S[A(0x79C0)] = ('w', rnd.choice([0, 1, 0xFFFF, 0xFFFE, rnd.randrange(0, 0x10000)]))
    S[A(0x79F4)] = ('b', rnd_flag(rnd))
    S[A(0x7C68)] = ('b', rnd_flag(rnd))
    return S


def q3():
    rnd = random.Random(3003)
    n = 0
    for i in range(600):
        S = rand_0363(rnd)
        e = call(new_emu(ROM, S), 0x03605A)
        check_writes(e, m_036322(S), f'Q3 case {i}')
        check_reads(e, S, f'Q3 case {i}')
        n += 1
    # [79C0] is a WORD: every store to it in 0x036322 is mov.w (asserted through the write set: 2 bytes)
    print(f'Q3 0x03605A/0x036322/0x036978: {n} random cases, exact write sets and read sets')
    for ent, lab in ((0x03605A, '0x03605A'), (0x036978, '0x036978')):
        k = assert_coverage(ent, lab)
        print(f'   coverage {lab}: all {k} CFG addresses executed')


# ================================================================ Q4  [7A78+4i]
PTRS = [rd_l(ROM, 0x063B20 + 4 * i) for i in range(4)]


def m_037604(S, rom=ROM):
    W = {}
    x62F8, rpm, x620C, x6354, x6364, c895C = (S[A(a)][1] for a in (0x62F8, 0x6624, 0x620C, 0x6354, 0x6364,
                                                                   0x895C))
    w67EC = S[A(0x67EC)][1] & 0xFFFF
    bitA176 = S[A(0xA176)][1] & 1                                  # 0x02B28C
    d = m_absdiff(c895C, S[A(0x7AAC)][1])
    if rd_f(rom, 0x0CC2C0) > d:
        W[A(0x7AB1)] = ('b', 1)
        b7AB0 = S[A(0x7AB0)][1]
    else:
        W[A(0x7AB1)] = ('b', 0)
        W[A(0x7AB0)] = ('b', 0)
        b7AB0 = 0
    W[A(0x7AAC)] = ('f', c895C)
    cond = (w67EC >= rd_h(rom, 0x0CBC72) and not (w67EC > rd_h(rom, 0x0CBC74))
            and rd_f(rom, 0x0CC2B4) > x62F8 and rpm > rd_f(rom, 0x0CC2B8) and rd_f(rom, 0x0CC2BC) > x620C
            and (s8(rom[0x0CBBF8]) == 1 or bitA176 == 1)
            and not (rd_f(rom, 0x0CC23C) > x6354) and not (rd_f(rom, 0x0CC240) > x6364)
            and W[A(0x7AB1)][1] == 1 and (b7AB0 & 0xFF) >= rom[0x0CBBF9])
    W[A(0x7AA0)] = ('b', 1 if cond else 0)
    return W


def m_037710(S, c, rom=ROM):
    W = {}
    x99B4, rpm, x6540 = S[A(0x99B4)][1], S[A(0x6624)][1], S[A(0x6540)][1]
    s65C5 = 1 if s8(S[A(0x65C5)][1]) == 1 else 0                    # 0x022CF4
    if s8(S[A(0x6552)][1]) == 1:                                    # 0x021D9A
        gg = 2
    else:
        gg = 1 if s8(S[A(0x6553)][1]) == 1 else 0
    cnt = [S[A(0x7A98 + i)][1] & 0xFF for i in range(4)]
    low = [S[A(0x7A9C + i)][1] & 0xFF for i in range(4)]
    t1 = lk1(0x0AB880 if s65C5 == 1 else 0x0AB51C, rpm, rom)
    t2 = lk1(0x0AD464, rpm, rom)
    W[A(0x7AA4)] = ('f', t1)
    W[A(0x7AA8)] = ('f', t2)
    if (S[A(0x7AA0)][1] & 0xFF) == 0:
        cnt = [0] * 4
        low = [0] * 4
    else:
        if x99B4 > f_mul(t1, t2):
            cnt[c] = m_sat8(cnt[c], 1)
            low[c] = 0
        else:
            if low[c] > rom[0x0CBBFA]:
                cnt[c] = 0
            low[c] = m_sat8(low[c], 1)
    cap = []
    for i in range(4):
        if gg == 1 and not (x6540 > rd_f(rom, 0x0CC2C4)):
            v = m_max(f_sub(S[A(0x7A78 + 4 * i)][1], rd_f(rom, 0x0CC2CC)), rd_f(rom, 0x0CC2D0))
        else:
            v = rd_f(rom, 0x0CC2C8)
        W[A(0x7A88 + 4 * i)] = ('f', v)
        cap.append(v)
    if s8(S[A(0x7C18)][1]) == 1:
        for i in range(4):
            v = m_max(f_sub(S[A(0x7A78 + 4 * i)][1], rd_f(rom, 0x0CC2EC)), 0.0)
            W[A(0x7A78 + 4 * i)] = ('f', m_clamp(v, 0.0, cap[i]))
            W[A(0x7A98 + i)] = ('b', cnt[i])
            W[A(0x7A9C + i)] = ('b', low[i])
        return W
    r4 = 1
    for i in range(4):
        if cnt[i] >= rom[0x0CBBFB]:
            v = m_min(f_add(S[A(0x7A78 + 4 * i)][1], rd_f(rom, 0x0CC2E4)), rd_f(rom, PTRS[i]))
            W[A(0x7A78 + 4 * i)] = ('f', m_clamp(v, 0.0, cap[i]))
            cnt[i] = 0
            r4 = 0
        W[A(0x7A98 + i)] = ('b', cnt[i])
        W[A(0x7A9C + i)] = ('b', low[i])
    if r4 == 1:
        for i in range(4):
            v = m_max(f_sub(S[A(0x7A78 + 4 * i)][1], rd_f(rom, 0x0CC2E8)), 0.0)
            W[A(0x7A78 + 4 * i)] = ('f', m_clamp(v, 0.0, cap[i]))
    return W


CYL = {0: 0, 1: 2, 2: 1, 3: 3}


def m_0375B8(S, rom=ROM):
    b = S[A(0x9FC6)][1] & 0xFF
    if b not in CYL:
        return {}
    W = m_037604(S, rom)
    S2 = dict(S)
    S2.update(W)
    W2 = m_037710(S2, CYL[b], rom)
    out = dict(W)
    out.update(W2)
    return out


def rand_0375(rnd):
    S = {}
    S[A(0x9FC6)] = ('b', rnd.choice([0, 1, 2, 3, 0, 1, 2, 3, 4, 0xFF]))
    S[A(0x62F8)] = ('f', rnd.choice([0.0, 6.3, 6.2, 7.0, rnd.uniform(0, 8)]))
    S[A(0x6624)] = ('f', rnd.choice([250.0, 300.0, 301.0, 750.0, 1000.0, 1500.0, 2500.0, 4500.0,
                                     rnd.uniform(0, 5500)]))
    S[A(0x620C)] = ('f', rnd.choice([100.0, 499.0, 500.0, 900.0, rnd.uniform(0, 600)]))
    S[A(0x6354)] = ('f', rnd.choice([60.0, 70.0, 90.0, rnd.uniform(40, 120)]))
    S[A(0x6364)] = ('f', rnd.choice([-1.0, 0.0, 25.0, rnd.uniform(-10, 40)]))
    S[A(0x895C)] = ('f', rnd.choice([0.0, 1000.0, rnd.uniform(-500, 3000)]))
    S[A(0x7AAC)] = ('f', rnd.choice([0.0, 1000.0, 1099.0, rnd.uniform(-500, 3000)]))
    S[A(0x67EC)] = ('w', rnd.choice([74, 75, 1000, 7500, 7501, rnd.randrange(0, 0x10000)]))
    S[A(0xA176)] = ('b', rnd.randrange(0, 256))
    S[A(0x7AB0)] = ('b', rnd.choice([0, 37, 38, 200, 255]))
    S[A(0x99B4)] = ('f', rnd.choice([0.0, 10.0, 17.0, 40.0, 100.0, 1e5, rnd.uniform(0, 80)]))
    S[A(0x6540)] = ('f', rnd.choice([0.5, 0.75, 0.76, 1.0, rnd.uniform(0, 1.5)]))
    S[A(0x65C5)] = ('b', rnd_flag(rnd))
    S[A(0x6552)] = ('b', rnd.choice([0, 1, 1, 2]))
    S[A(0x6553)] = ('b', rnd.choice([0, 1, 1, 2]))
    S[A(0x7AA0)] = ('b', rnd.choice([0, 1, 1, 2]))      # 0x037604 rewrites it before 0x037710 reads it
    S[A(0x7C18)] = ('b', rnd.choice([0, 0, 0, 1, 2]))
    for i in range(4):
        S[A(0x7A78 + 4 * i)] = ('f', rnd.choice([0.0, 0.1, 0.2, 0.4, 0.8, 1.2, rnd.uniform(-0.2, 1.5)]))
        S[A(0x7A98 + i)] = ('b', rnd.choice([0, 1, 2, 3, 255]))
        S[A(0x7A9C + i)] = ('b', rnd.choice([0, 1, 2, 255]))
    if rnd.random() < 0.5:                 # open the 0x037604 gate in half the cases
        S[A(0x62F8)] = ('f', rnd.uniform(0, 6.2))
        S[A(0x6624)] = ('f', rnd.choice([750.0, 1000.0, 1500.0, 2500.0, 4500.0, rnd.uniform(301, 5500)]))
        S[A(0x620C)] = ('f', rnd.uniform(0, 499))
        S[A(0x6354)] = ('f', rnd.uniform(70, 120))
        S[A(0x6364)] = ('f', rnd.uniform(0, 40))
        S[A(0x67EC)] = ('w', rnd.randrange(75, 7501))
        S[A(0x7AAC)] = ('f', S[A(0x895C)][1] + rnd.choice([0.0, 50.0, -99.0]))
        S[A(0x7AB0)] = ('b', rnd.choice([38, 100, 255]))
    return S


def q4():
    rnd = random.Random(4004)
    n = 0
    for i in range(900):
        S = rand_0375(rnd)
        e = call(new_emu(ROM, S), 0x03757A)
        check_writes(e, m_0375B8(S), f'Q4 case {i}')
        S_decl = dict(S)
        if (S[A(0x9FC6)][1] & 0xFF) not in CYL:
            assert not e.writes, 'Q4: cylinder byte outside 0..3 -> no write'
            ok()
        check_reads(e, S_decl, f'Q4 case {i}')
        n += 1
    # dead in stock / 20.19c / 20.19e (byte 0x0CBBF8 = 1): the bit-0-of-[A176] alternative, on a ROM copy
    rom2 = bytearray(ROM)
    rom2[0x0CBBF8] = 0
    rom2 = bytes(rom2)
    for i in range(120):
        S = rand_0375(rnd)
        S[A(0x9FC6)] = ('b', i % 4)
        e = call(new_emu(rom2, S), 0x03757A)
        check_writes(e, m_0375B8(S, rom2), f'Q4 copy 0x0CBBF8=0 case {i}')
        n += 1
    print(f'Q4 0x03757A/0x0375B8/0x037604/0x037710: {n} random cases (120 on a copy with byte 0x0CBBF8 = 0), '
          f'exact write sets and read sets')
    print(f'   pointer table 0x063B20 -> {[hex(p) for p in PTRS]} = {[rd_f(ROM, p) for p in PTRS]} (per-cylinder caps)')
    for ent, lab in ((0x03757A, '0x03757A'), (0x037604, '0x037604')):
        k = assert_coverage(ent, lab)
        print(f'   coverage {lab}: all {k} CFG addresses executed')


# ================================================================ Q5  context writers
def m_02EF56(S, rom=ROM):
    W = {}
    E_, rpm = S[A(0x6350)][1], S[A(0x6624)][1]
    l7E4C = S[A(0x7E4C)][1] & 0xFFFFFFFF
    t = lk1(0x0AC804, E_, rom)
    W[A(0x72A8)] = ('f', t)
    b72A4 = lku8(0x0AC2A4, float(S[A(0x72A0)][1] & 0xFF), rom)
    W[A(0x72A4)] = ('b', b72A4)
    b72C8 = S[A(0x72C8)][1]
    if rpm > t:
        b72C8 = 0
        W[A(0x72C8)] = ('b', 0)
    elif not (rpm > f_sub(t, rd_f(rom, 0x0CBDB8))):
        b72C8 = 1
        W[A(0x72C8)] = ('b', 1)
    if (b72C8 & 0xFF) == 0 and l7E4C >= (b72A4 & 0xFF):
        W[A(0x726C)] = ('b', 0)
        W[A(0x726D)] = ('b', 0)
    else:
        W[A(0x726C)] = ('b', 1)
    return W


def q5():
    rnd = random.Random(5005)
    # 0x02EF56: [726C] hysteresis on [6624] (300 / 500 with the 20.19c tables)
    for i in range(300):
        S = {A(0x6350): ('f', rnd.uniform(-45, 120)),
             A(0x6624): ('f', rnd.choice([0.0, 299.0, 300.0, 301.0, 499.0, 500.0, 501.0, rnd.uniform(0, 1500)])),
             A(0x7E4C): ('l', rnd.choice([0, 1, 0xFFFFFFFF, rnd.randrange(0, 1 << 32)])),
             A(0x72A0): ('b', rnd.randrange(0, 256)),
             A(0x72C8): ('b', rnd.choice([0, 1, 2]))}
        e = call(new_emu(ROM, S), 0x02EF56)
        check_writes(e, m_02EF56(S), f'Q5 0x02EF56 case {i}')
        check_reads(e, S, f'Q5 0x02EF56 case {i}')
    for rpm, prev, want in ((300.0, 0, 1), (301.0, 0, 0), (499.0, 1, 1), (500.0, 1, 1), (501.0, 1, 0)):
        S = {A(0x6350): ('f', 90.0), A(0x6624): ('f', rpm), A(0x7E4C): ('l', 0), A(0x72A0): ('b', 0),
             A(0x72C8): ('b', prev)}
        e = call(new_emu(ROM, S), 0x02EF56)
        assert e.read_u8(A(0x726C)) == want, (rpm, prev)
        ok()
    print('Q5 0x02EF56 ([726C]): 300 random + 5 edge cases; [726C] = 1 at [6624] <= 300, 0 above 500, held between')
    # 0x02F550: [7288] = 0x0AC338([6350]) if byte [65C1] == 1 else 1.0; byte [726E] = 1 / 0
    for i in range(80):
        b = rnd.choice([0, 1, 2])
        x = rnd.uniform(-45, 120)
        S = {A(0x65C1): ('b', b), A(0x6350): ('f', x)}
        e = call(new_emu(ROM, S), 0x02F550)
        x = S[A(0x6350)][1]
        W = {A(0x7288): ('f', lk1(0x0AC338, x) if b == 1 else 1.0), A(0x726E): ('b', 1 if b == 1 else 0)}
        check_writes(e, W, f'Q5 0x02F550 case {i}')
        assert e.read_f32(A(0x7288)) == 1.0, '[7288] = 1.0 on both paths with the 20.19c table'
        ok()
    print('Q5 0x02F550 ([7288]): 80 cases; 1.0 on both paths (0x0AC338 is flat 1.0)')
    # 0x036962: [79A0] = 0x0AD0DC([6350])
    for x in [-50.0, -40.0, -10.0, 0.0, 30.0, 55.0, 60.0, 65.0, 90.0, 110.0, 130.0] + [rnd.uniform(-45, 120) for _ in range(40)]:
        S = {A(0x6350): ('f', x)}
        e = call(new_emu(ROM, S), 0x036962)
        x = S[A(0x6350)][1]
        check_writes(e, {A(0x79A0): ('f', lk1(0x0AD0DC, x))}, f'Q5 0x036962 x={x}')
        v = e.read_f32(A(0x79A0))
        assert 0.0 <= v <= 1.0, '[79A0] in [0, 1]'
        ok()
    print('Q5 0x036962 ([79A0]): 51 cases; [79A0] = 0x0AD0DC([6350]) in [0, 1.0]')
    # 0x0376EC: [7AB0] = sat8([7AB0] + 1) if byte [7AB1] == 1 else 0
    for b1 in (0, 1, 2, 0x81):
        for c in (0, 37, 254, 255):
            S = {A(0x7AB1): ('b', b1), A(0x7AB0): ('b', c)}
            e = call(new_emu(ROM, S), 0x0376EC)
            check_writes(e, {A(0x7AB0): ('b', m_sat8(c, 1) if s8(b1) == 1 else 0)}, f'Q5 0x0376EC {b1} {c}')
    print('Q5 0x0376EC ([7AB0]): 16 cases')
    # 0x03757E: when byte [65F6] == 1: [7A78..7A84] = 0, [7AAC] = [895C], [7AB1] = 0, [7AA0] = 0
    for b in (0, 1, 2):
        S = {A(0x65F6): ('b', b), A(0x895C): ('f', 1234.5)}
        e = call(new_emu(ROM, S), 0x03757E)
        W = {}
        if b == 1:
            for i in range(4):
                W[A(0x7A78 + 4 * i)] = ('f', 0.0)
            W[A(0x7AAC)] = ('f', 1234.5)
            W[A(0x7AB1)] = ('b', 0)
            W[A(0x7AA0)] = ('b', 0)
        check_writes(e, W, f'Q5 0x03757E {b}')
    print('Q5 0x03757E (reset): 3 cases')
    # 0x03606C differential: [79C0] is not read; [7990] scales exactly with [79A0]
    base = {A(0x6624): ('f', 3000.0), A(0x63F8): ('f', 1.6), A(0x3234): ('f', 0.0), A(0x62DC): ('f', 80.0),
            A(0x64D8): ('f', 0.0), A(0x8200): ('f', 0.0), A(0x7F6C): ('f', 0.0), A(0x79C2): ('w', 100),
            A(0x79C4): ('w', 50), A(0x79C6): ('b', 0), A(0x79F2): ('b', 0), A(0x798C): ('f', 0.0),
            A(0x7990): ('f', 0.0), A(0x79A0): ('f', 1.0), A(0x79E4): ('f', 0.0), A(0x79B8): ('f', 0.0),
            A(0x79BC): ('f', 0.0), A(0x79C0): ('w', 0)}
    outs = {}
    for c0 in (0, 1, 0x7FFF, 0xFFFF):
        S = dict(base)
        S[A(0x79C0)] = ('w', c0)
        e = call(new_emu(ROM, S), 0x03606C)
        assert A(0x79C0) not in e.uninit_reads and A(0x79C1) not in e.uninit_reads, '0x03606C reads [79C0]'
        outs[c0] = dict(e.writes)
        ok()
    assert all(o == outs[0] for o in outs.values()), '0x03606C output depends on [79C0]'
    ok()
    e1 = call(new_emu(ROM, base), 0x03606C)
    t1 = e1.read_f32(A(0x7990))
    assert t1 > 0.0, 'test point must give a non-zero OL target'
    for k in (0.0, 0.195, 0.5, 0.97, 1.0):
        S = dict(base)
        S[A(0x79A0)] = ('f', k)
        e = call(new_emu(ROM, S), 0x03606C)
        k = S[A(0x79A0)][1]
        assert same(e.read_f32(A(0x7990)), f_mul(t1, k)), ('[7990] = max(map, floors) * [79A0]', k)
        ok()
    print(f'Q5 0x03606C differential: [79C0] never read (4 values, identical writes); [7990] = {t1:.6f} * [79A0] '
          f'for [79A0] in 0 .. 1.0 (5 values, exact)')


# ================================================================ Q6  calibration facts
RECS = [0x0AC3CC, 0x0AD5B0, 0x0AC998, 0x0AC3AC, 0x0AC3B8, 0x0AC3A0, 0x0AD594, 0x0AC970, 0x0AC984,
        0x0AC948, 0x0AC95C, 0x0ACA6C, 0x0ACAF0, 0x0ACB04, 0x0ACB18, 0x0ACB2C, 0x0ACA78, 0x0ACA8C,
        0x0ACAA0, 0x0ACAB4, 0x0ACAC8, 0x0ACADC, 0x0AD5CC, 0x0AC9CC, 0x0ACA30, 0x0AC9B8, 0x0ACA1C,
        0x0AC9A4, 0x0ACA08, 0x0AC9E0, 0x0AC9F4, 0x0ACA44, 0x0ACA58, 0x0AD0D0, 0x0AD0B8, 0x0AD0C4,
        0x0AC5BC, 0x0AD0A4, 0x0AB880, 0x0AB51C, 0x0AD464, 0x0AC804, 0x0AC2A4, 0x0AC338, 0x0AD0DC]
F32S = [0x0CBE10, 0x0CBE14, 0x0CBE18, 0x0CBE1C, 0x0CC178, 0x0CC174, 0x0CC2C0, 0x0CC2B4, 0x0CC2B8,
        0x0CC2BC, 0x0CC23C, 0x0CC240, 0x0CC2C4, 0x0CC2C8, 0x0CC2CC, 0x0CC2D0, 0x0CC2E4, 0x0CC2E8,
        0x0CC2EC, 0x0CBDB8, 0x0CC2D4, 0x0CC2D8, 0x0CC2DC, 0x0CC2E0]
U8S = [0x0CBBD3, 0x0CBBF8, 0x0CBBF9, 0x0CBBFA, 0x0CBBFB]
U16S = [0x0CBC72, 0x0CBC74]
DIFF_OK = {0x0AD0DC, 0x0CC178, 0x0CC174}       # differ stock vs 20.19c (asserted below)


def tbl(rom, rec):
    t = DT.read_table(rom, rec)
    return t['values'], t['axes']


def q6():
    for rec in RECS:
        c, e = tbl(ROM, rec), tbl(REV_E, rec)
        s = tbl(STOCK, rec)
        assert c == e, f'{rec:#x}: 20.19c != 20.19e'
        if rec in DIFF_OK:
            assert c != s, f'{rec:#x} expected to differ from stock'
        else:
            assert c == s, f'{rec:#x}: 20.19c != stock'
        ok()
    for a in F32S:
        assert rd_f(ROM, a) == rd_f(REV_E, a)
        if a in DIFF_OK:
            assert rd_f(ROM, a) != rd_f(STOCK, a)
        else:
            assert rd_f(ROM, a) == rd_f(STOCK, a), hex(a)
        ok()
    for a in U8S:
        assert ROM[a] == REV_E[a] == STOCK[a], hex(a)
        ok()
    for a in U16S:
        assert rd_h(ROM, a) == rd_h(REV_E, a) == rd_h(STOCK, a), hex(a)
        ok()
    assert PTRS == [rd_l(STOCK, 0x063B20 + 4 * i) for i in range(4)] == [rd_l(REV_E, 0x063B20 + 4 * i) for i in range(4)]
    ok()
    # the facts the trace relies on
    v = lambda r: tbl(ROM, r)[0]          # noqa: E731
    flat = lambda r, x: all(abs(y - x) < 1e-9 for y in (v(r) if not isinstance(v(r)[0], list) else sum(v(r), [])))  # noqa: E731,E501
    assert flat(0x0AC3CC, 1.0) and flat(0x0AD5B0, 1.0) and flat(0x0AC998, 38) and flat(0x0AC3B8, 0.8984375)
    assert flat(0x0ACA6C, 0) and flat(0x0ACB04, 0) and flat(0x0ACB18, 0) and flat(0x0ACB2C, 0)
    for r in (0x0ACA8C, 0x0ACAB4, 0x0ACAC8, 0x0ACADC, 0x0AC9CC, 0x0ACA30, 0x0AC9B8, 0x0ACA1C, 0x0AC9F4, 0x0ACA58):
        assert flat(r, 0.0), hex(r)
    assert flat(0x0AC338, 1.0) and flat(0x0AC804, 500.0) and flat(0x0AC2A4, 0)
    assert flat(0x0AD0B8, 1) and flat(0x0AD0C4, 65535) and flat(0x0AD0D0, 65535)
    assert v(0x0AD594) == v(0x0AD5CC), 'the two pressure-type factor maps hold identical data'
    assert min(sum(v(0x0AD594), [])) == 1.0 and max(sum(v(0x0AD594), [])) == 1.8125
    assert max(v(0x0AD0DC)) == 1.0 and min(v(0x0AD0DC)) == 0.0
    assert ROM[0x0CBBD3] == 1 and rd_f(ROM, 0x0CBE18) == 1.0 and rd_f(ROM, 0x0CBE1C) == 1.0
    assert [rd_l(ROM, p) for p in PTRS] == [0x3F4CCCCC, 0, 0x3F199999, 0], [hex(rd_l(ROM, p)) for p in PTRS]
    ok(10)
    print(f'Q6 {len(RECS)} records, {len(F32S)} f32, {len(U8S)} u8, {len(U16S)} u16 scalars: 20.19c == 20.19e; '
          f'== stock except 0x0AD0DC (60 C cell 0.97 stock), 0x0CC178 (3.9 stock / 8.4), 0x0CC174 (256 / 756)')


# ================================================================ Q7  multi-call courses
# REVIEW (2026-11-27, deciding decode): the first version of these courses held word [67EC] = 1000 while
# byte [726C] = 1. That state is unreachable once 0x023A94 has run: 023A98 jsr 0x02F8EA (= ([726C] == 1)),
# 023AA8 mov.w r0,@(4,r1) with r1 = 0xFFFF67E8 -> [67EC] = 0 whenever [726C] == 1; otherwise
# [67EC] = sat16([67EC] + 1) (023AB8). 0x023A94 is the only [67EC] writer find_writers shows (023AA8, 023AB8),
# called in the straight call list of 0x04907C (049124). The courses below therefore run 0x023A94 (the ROM
# code, in the same emulator) once per pass, in both orders relative to the FFB writer, because the order and
# relative rates of 0x04907C and 0x04AA58 are not established.
def course_7354(E_=90.0, x6898=760.0, x6354=90.0, hold_calls=5, n=400, b90C1=0, b3158=0, r4seq=(0,),
                order='A', w67EC0=1000):
    S = {A(a): (k, 0) for a, k in IN_0304.items()}
    S.update({A(0x6624): ('f', 250.0), A(0x895C): ('f', 0.0), A(0x6350): ('f', E_), A(0x6354): ('f', x6354),
              A(0x6898): ('f', x6898), A(0x67EC): ('w', w67EC0), A(0x67E8): ('w', 0), A(0x726C): ('b', 1),
              A(0x90C1): ('b', b90C1), A(0x3158): ('b', b3158), A(0x7288): ('f', 1.0), A(0x7354): ('f', 0.0),
              A(0x7358): ('f', 0.0)})
    for a, (k, v) in list(S.items()):
        if k == 'f' and isinstance(v, int):
            S[a] = ('f', float(v))
    e = new_emu(ROM, S)
    out = []
    for i in range(n):
        if i == hold_calls:
            put(e, A(0x726C), 'b', 0)
        r4 = r4seq[i % len(r4seq)]
        if order == 'A':                       # 0x023A94 (task-9 pass) before the FFB writer
            call(e, 0x023A94)
            call(e, 0x03043A, regs={4: r4})
        else:                                  # the FFB writer first
            call(e, 0x03043A, regs={4: r4})
            call(e, 0x023A94)
        out.append((e.read_f32(A(0x7354)), e.read_f32(A(0x7358)), e.read_u16(A(0x67EC))))
    return out


def course_7374(E_=90.0, x6898=760.0, x6354=90.0, hold_calls=5, n=400, f67FC=0, b3158=0, order='A',
                w67EC0=1000):
    S = {A(0x6350): ('f', E_), A(0x6354): ('f', x6354), A(0x6898): ('f', x6898), A(0x67FC): ('b', f67FC),
         A(0x67EC): ('w', w67EC0), A(0x67E8): ('w', 0), A(0x90C1): ('b', 0), A(0x647C): ('b', 1),
         A(0x65C5): ('b', 0), A(0x726C): ('b', 1), A(0x3158): ('b', b3158), A(0x7C9D): ('b', 0),
         A(0x73A2): ('b', f67FC), A(0x7288): ('f', 1.0)}
    for a in (0x7378, 0x737C, 0x7380, 0x7384, 0x7398, 0x739C):
        S[A(a)] = ('f', 0.0)
    e = new_emu(ROM, S)
    out = []
    for i in range(n):
        if i == hold_calls:
            put(e, A(0x726C), 'b', 0)
        if order == 'A':
            call(e, 0x023A94)
            call(e, 0x030754, regs={4: 0})
        else:
            call(e, 0x030754, regs={4: 0})
            call(e, 0x023A94)
        out.append(e.read_f32(A(0x7374)))
    return out


def q7():
    # [7354]: warm, factor 1.0, coupled to 0x023A94 (call numbers count the first call with [726C] = 0 as 1)
    seed90 = lk1(0x0AC970, 90.0)
    assert same(seed90, 0.5), seed90
    res = {}
    for order in ('A', 'B'):
        c = course_7354(order=order)
        # after the first pass 0x023A94 holds [67EC] = 0, so no step while seeded: exactly seed * AD594
        assert all(same(v, 0.5) for v, _, _ in c[1:5]), (order, c[:5])
        assert all(w == 0 for _, _, w in c[0:5]), 'while [726C] == 1, 0x023A94 holds [67EC] = 0'
        # after the fall [7354] holds 0.5 until the gate zext [67EC] > 38 opens
        open_call = next(i for i in range(5, len(c)) if c[i][2] - (1 if order == 'B' else 0) > 38) - 4
        first = next(i for i in range(5, len(c)) if c[i][1] != c[i - 1][1]) - 4
        zero = next(i for i, (v, _, _) in enumerate(c) if v == 0.0) - 4
        assert all(same(v, 0.5) for v, _, _ in c[5:4 + first]), 'held at the seed until the first step'
        steps = sorted({i for i in range(5, zero + 4) if c[i][1] != c[i - 1][1]})
        assert {b - a for a, b in zip(steps, steps[1:])} == {3}, 'one x0.8984375 step every 3 calls at E 90'
        assert first - open_call + 1 == 3, (order, open_call, first)      # first step on open-gate call 3
        assert zero - open_call + 1 == 217, (order, open_call, zero)      # zero on open-gate call 217
        res[order] = (open_call, first, zero)
        ok(6)
    assert res['A'] == (39, 41, 255) and res['B'] == (40, 42, 256), res
    ok()
    print(f'Q7 [7354] warm (E 90, AD594 1.0), 0x023A94 run each pass: exactly 0.5 on every seeded call ([67EC] held '
          f'0, no step); after the fall 0.5 until zext [67EC] > 38 (gate opens on call {res["A"][0]} / '
          f'{res["B"][0]} after the fall, 0x023A94 first / last); x0.8984375 every 3 calls from open-gate call 3; '
          f'exactly 0 on open-gate call 217 (call {res["A"][2]} / {res["B"][2]} after the fall)')
    # the window: [67EC] still > 38 when [726C] is already 1 and the FFB writer runs before 0x023A94
    cw = course_7354(order='B', hold_calls=99, n=4, w67EC0=1000)
    assert all(same(v, 0.5) for v, _, _ in cw), 'r4 even, counter from 0: no step in the first call either'
    S = {A(a): (k, 0) for a, k in IN_0304.items()}
    S.update({A(0x6350): ('f', 90.0), A(0x6354): ('f', 90.0), A(0x6898): ('f', 760.0), A(0x6624): ('f', 250.0),
              A(0x67EC): ('w', 1000), A(0x726C): ('b', 1), A(0x7370): ('b', 1), A(0x736A): ('w', 2),
              A(0x7288): ('f', 1.0), A(0x7354): ('f', 0.5), A(0x7358): ('f', 0.5)})
    for a, (k, v) in list(S.items()):
        if k == 'f' and isinstance(v, int):
            S[a] = ('f', float(v))
    ew = call(new_emu(ROM, S), 0x03043A, regs={4: 0})
    cw2 = ew.read_f32(A(0x7354))
    assert same(cw2, f_mul(0.5, 0.8984375)), cw2
    ok(2)
    print(f'   window case (bytes allow it only before 0x023A94 has run with [726C] = 1): [67EC] = 1000, '
          f'[736A] = 2 -> {cw2:.6f} on that one call; re-seeded to 0.5 on the next')
    # the maximum factor
    c2 = course_7354(x6898=504.0, x6354=-5.0, n=8)
    assert same(c2[1][0], f_mul(1.8125, 0.5)), c2[1]
    ok()
    print(f'   with [6898] = 504, [6354] = -5 (AD594 = 1.8125): [7354] = {c2[1][0]:.6f} while seeded')
    # odd runner argument: 0x0304BE skipped on every other pass, 0x023A94 still runs every pass
    c3 = course_7354(r4seq=(0, 1), n=700)
    z3 = next(i for i, (v, _, _) in enumerate(c3) if v == 0.0) - 4
    assert z3 > 2 * 217, z3
    ok()
    print(f'   runner argument alternating even/odd: zero on call {z3} after the fall (0x0304BE runs every '
          f'other pass; the gate still opens on pass 39)')
    # the seed over coolant, all four ([90C1], [3158]) paths
    best = 0.0
    for E_ in [-40.0 + 2.5 * k for k in range(61)]:
        for b in (0, 1):
            for g3 in (0, 1):
                cc = course_7354(E_=E_, x6898=504.0, x6354=-5.0, n=2, b90C1=b, b3158=g3, hold_calls=99)
                best = max(best, cc[1][0])
    assert same(best, f_mul(1.8125, 2.5)), best
    ok()
    warm = {}
    for b in (0, 1):
        for g3 in (0, 1):
            warm[(b, g3)] = course_7354(n=2, b90C1=b, b3158=g3, hold_calls=99)[1][0]
    assert same(warm[(0, 0)], 0.5) and same(warm[(1, 0)], 0.5)
    assert same(warm[(0, 1)], 0.30078125) and same(warm[(1, 1)], 0.30078125), warm
    ok(2)
    print(f'   sweep E -40..110, both [90C1] and both [3158] paths, AD594 = 1.8125: max [7354] = {best:.5f} '
          f'(= 2.5 * 1.8125); warm (90 C, AD594 1.0): 0.5 with [3158] == 0, 0.30078125 with [3158] != 0')
    # [7374], coupled to 0x023A94
    s9a4 = lk1(0x0AC9A4, 90.0)
    assert same(s9a4, 0.10009765625), s9a4
    z7 = {}
    for order in ('A', 'B'):
        d = course_7374(order=order)
        assert all(same(v, s9a4) for v in d[1:5]), (order, d[:5])      # full seed, decay frozen ([67EC] = 0)
        zero7 = next(i for i, v in enumerate(d) if v == 0.0)
        lin = [d[i] - d[i + 1] for i in range(6, zero7 - 1)]
        assert all(abs(x - lk1(0x0ACA78, 90.0)) < 1e-6 for x in lin), 'linear decay at 0x0ACA78(E) per call'
        z7[order] = (d[5], zero7 - 4)
        ok(2)
    assert z7['A'][1] == 286 and z7['B'][1] == 287, z7
    assert same(z7['B'][0], s9a4) and z7['A'][0] < s9a4
    ok(2)
    print(f'Q7 [7374] warm (E 90, AD5CC 1.0, [67FC] != 1), 0x023A94 run each pass: exactly {s9a4} on every seeded '
          f'call ([67EC] = 0 freezes the decay); then -{lk1(0x0ACA78, 90.0):.8f} per call; 0 on call '
          f'{z7["A"][1]} / {z7["B"][1]} after the fall (0x023A94 first / last)')
    d2 = course_7374(f67FC=0, x6898=504.0, x6354=-5.0, n=3, hold_calls=99)
    d3 = course_7374(f67FC=1, x6898=504.0, x6354=-5.0, n=3, hold_calls=99)
    assert same(d2[1], f_mul(s9a4, 1.8125)) and same(d3[1], d2[1]), (d2, d3)
    ok()
    print(f'   AD5CC = 1.8125 ([6898] 504, [6354] -5): warm [7374] = {d2[1]:.9f} with [67FC] 0 or 1 '
          f'(0x0ACAF0(90) = {lk1(0x0ACAF0, 90.0)})')
    best7 = 0.0
    for E_ in [-40.0 + 2.5 * k for k in range(61)]:
        for f in (0, 1):
            for g3 in (0, 1):
                dd = course_7374(E_=E_, f67FC=f, b3158=g3, x6898=504.0, x6354=-5.0, n=2, hold_calls=99)
                best7 = max(best7, dd[1])
    assert same(best7, f_mul(lk1(0x0AC9A4, -40.0), 1.8125)) and same(lk1(0x0AC9A4, -40.0), 0.85009765625), best7
    ok()
    print(f'   sweep E -40..110, [67FC] 0/1, [3158] 0/1, AD5CC = 1.8125, decay frozen: max [7374] = {best7:.9f} '
          f'(= 0.85009765625 * 1.8125)')
    # [7A78+4i] cap shrink: 0x021D9A() == 1 and [6540] <= 0.75 -> [7A88+4i] = max(x - 0.025, 0.2)
    def shrink_case(shrink, x, step):
        S = {A(0x62F8): ('f', 0.0), A(0x6624): ('f', 1000.0), A(0x620C): ('f', 100.0), A(0x6354): ('f', 90.0),
             A(0x6364): ('f', 20.0), A(0x895C): ('f', 500.0), A(0x7AAC): ('f', 500.0),
             A(0x67EC): ('w', 1000 if step else 0), A(0xA176): ('b', 0), A(0x7AB0): ('b', 40),
             A(0x99B4): ('f', 100.0), A(0x6540): ('f', 0.5 if shrink else 1.0), A(0x65C5): ('b', 0),
             A(0x6552): ('b', 0), A(0x6553): ('b', 1 if shrink else 0), A(0x7AA0): ('b', 0), A(0x7C18): ('b', 0),
             A(0x9FC6): ('b', 0)}
        for i in range(4):
            S[A(0x7A78 + 4 * i)] = ('f', x)
            S[A(0x7A98 + i)] = ('b', 1 if (step and i == 0) else 0)
            S[A(0x7A9C + i)] = ('b', 0)
        e = call(new_emu(ROM, S), 0x03757A)
        check_writes(e, m_0375B8(S), f'Q7 shrink {shrink} x {x} step {step}')
        return [e.read_f32(A(0x7A78 + 4 * i)) for i in range(4)]
    r = shrink_case(True, 0.5, False)
    assert all(same(v, f32(0.475)) or abs(v - 0.475) < 1e-7 for v in r), r
    r = shrink_case(True, 0.5, True)
    assert abs(r[0] - 0.475) < 1e-7 and all(same(v, f32(0.5)) for v in r[1:]), r
    floor = rd_f(ROM, 0x0CC2D0)                   # 0x3E4CCCCC = 0.19999999
    r = shrink_case(True, 0.21, True)
    assert same(r[0], floor), r
    r = shrink_case(True, 0.1, True)
    assert same(r[0], floor), r
    r = shrink_case(True, 0.21, False)
    assert all(same(v, floor) for v in r), r
    r = shrink_case(False, 0.5, False)
    assert abs(r[0] - 0.4965) < 1e-7, r
    r = shrink_case(False, 0.5, True)
    assert same(r[0], rd_f(ROM, PTRS[0])), r
    ok(7)
    print('   [7A78+4i] with 0x021D9A() == 1 and [6540] <= 0.75 (cap shrink): no-step 0.5 -> 0.475, step (cyl 0) '
          '0.5 -> 0.475, 0.21 -> 0.19999999, 0.1 -> 0.19999999 (no-step 0.21 -> 0.19999999); without it 0.5 -> 0.4965 and step 0.5 -> 0.79999995; '
          'a call in which a cylinder steps stores no other cylinder')
    # [7A78+4i]: accumulation and decay through 0x03757A on one emulator
    S = {A(0x62F8): ('f', 0.0), A(0x6624): ('f', 1000.0), A(0x620C): ('f', 100.0), A(0x6354): ('f', 90.0),
         A(0x6364): ('f', 20.0), A(0x895C): ('f', 500.0), A(0x7AAC): ('f', 500.0), A(0x67EC): ('w', 1000),
         A(0xA176): ('b', 0), A(0x7AB0): ('b', 40), A(0x99B4): ('f', 100.0), A(0x6540): ('f', 1.0),
         A(0x65C5): ('b', 0), A(0x6552): ('b', 0), A(0x6553): ('b', 0), A(0x7AA0): ('b', 0), A(0x7C18): ('b', 0),
         A(0x9FC6): ('b', 0)}
    for i in range(4):
        S[A(0x7A78 + 4 * i)] = ('f', 0.0)
        S[A(0x7A98 + i)] = ('b', 0)
        S[A(0x7A9C + i)] = ('b', 0)
    e = new_emu(ROM, S)
    hist = []
    for k in range(40):
        put(e, A(0x9FC6), 'b', k % 4)
        call(e, 0x03757A)
        hist.append(tuple(e.read_f32(A(0x7A78 + 4 * i)) for i in range(4)))
    top = hist[-1]
    assert same(top[0], rd_f(ROM, PTRS[0])) and top[1] == 0.0 and same(top[2], rd_f(ROM, PTRS[2])) \
        and top[3] == 0.0, top
    ok()
    first = next(k for k, h in enumerate(hist) if h[0] > 0.0)
    put(e, A(0x99B4), 'f', 0.0)
    dec = []
    for k in range(400):
        put(e, A(0x9FC6), 'b', k % 4)
        call(e, 0x03757A)
        dec.append(e.read_f32(A(0x7A78)))
    z = next(k for k, v in enumerate(dec) if v == 0.0)
    ok()
    print(f'Q7 [7A78+4i] (gate open, [99B4] above threshold, cylinders cycled 0..3): first rise on call {first + 1}, '
          f'steps of +0.4; settles at {top[0]:.4f} / {top[1]} / {top[2]:.4f} / {top[3]} (caps 0.8 / 0 / 0.6 / 0); '
          f'with [99B4] = 0 [7A78] decays 0.0035 per call to 0 in {z + 1} calls')
    # gate closed: [7AB0] < 38 keeps [7AA0] = 0 and every counter at 0
    S37 = dict(S)
    S37[A(0x7AB0)] = ('b', 37)
    e = new_emu(ROM, S37)
    for k in range(12):
        put(e, A(0x9FC6), 'b', k % 4)
        call(e, 0x03757A)
    assert e.read_u8(A(0x7AA0)) == 0 and all(e.read_f32(A(0x7A78 + 4 * i)) == 0.0 for i in range(4))
    ok()
    print('   [7AB0] = 37 (< 38): [7AA0] stays 0 and no addend rises')


def main():
    q1()
    q2()
    q3()
    q4()
    q5()
    q6()
    q7()
    print(f'ALL PASS: {CHECKS} asserted checks')
    return 0


if __name__ == '__main__':
    sys.exit(main())
