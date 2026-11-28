#!/usr/bin/env python3
"""Emulation check for the FFB transient-residual trace (corrections item 109 follow-up).

    python3 scripts/trace/emu_ffb_residual.py

Reference bin: rom/AE5L600L 20g rev 20.19c.bin  md5 92cae8275cd4f9b473a3a9e36efe6449
Trace:         disassembly/analysis/ffb_residual_trace.txt

What it does
------------
Runs each function in scripts/sh2e_emu.py against a Python model written from the
fn_dump listings and asserts, per case, every RAM byte the call writes (the exact
SET of non-stack bytes and their values), that every RAM cell read before being
written is a declared input, and that r8-r14 / r15 / GBR / fr12-fr15 come back.

  P1  0x02FFE0 (the sum / per-cylinder products / clamps) on the live config
      (byte 0x0CBBD2 = 0) and on an in-memory ROM copy with 0x0CBBD2 = 90
      (the branch this calibration never takes), random + edge inputs
  P2  0x02FF8E / 0x02FFA2 / 0x02FF74 (the cells 0xFFFF733C and 0xFFFF7340 that
      0x02FFE0 and 0x0301E4 use), all byte combinations that matter
  P3  0x030C38 with its private callees 0x0312BC 0x0312DE 0x030F02 0x03110C and
      the getters 0x023E48 0x01CF5E 0x021016, random states over every branch;
      every instruction address of the five functions executed
  P4  calibration and table facts stock / 20.19c / 20.19e for everything P1/P3 read
  P5  reachable range of [0xFFFF73B4] with the 20.19c tables (model, validated in P3).
      The one-call sweep holds [7400] = 1.0 (steady_state settles [73E0]/[73E4]), so its
      maximum is CONDITIONAL; the best case is re-emulated with [7400] = 1.25 and 4.9502
  P6  writers of the other addends: 0x036B48 ([7A08]), 0x038C50/0x038D4C ([7B44..50]),
      0x036C48 ([7A14] and the counter [7A1C]; [67EC] threshold word 0x0CBC6E = 624) and
      the [798C] reset 0x03602A emulated; table/scalar facts for [7A14] [7A20] [7BCC]
      [7BA8] [73A4] [7BE4] [7A78..84]; the literal sites of 0xFFFF7A44 decoded as reads
  P7  the consumer 0x0301E4 (reads [730C..731C]) emulated against its model
  P8  MULTI-CALL runs of 0x030B68 + 0x030C38 in one emulator (RAM persists between calls):
      the [7400] seed / decay (seeded from [6354], held once [67EC] >= 13, 750 calls from
      1.25, 3600 calls from 4.9502), re-seeding while [67EC] < 13, the settled-shortcut
      precedence, the two-call response to a one-call [73B0] step and its T2 tail, and a
      ramp below the [73EC] deadband
  P9  call-site facts from fn_dump: which runner calls each addend writer (several are NOT
      called from 0x04AA58), and the reader 0x032CE8 of [73B4] emulated against its model
  P10 independent audit (own starting states): the 0x0312DE snap branch on a lift-then-tip-in
      against a ROM copy with 0x0CBE5C = 1000.0 (no snap), with the snap call cross-checked
      against m_030C38; a mixed-sign call ([73EC] > 0, [73D8] < 0) forcing [7400] = 1.0 with a
      live seed; the [67EC] < 13 re-seed path ignoring [73F0] < 0; 0x030B68 leaving the decay
      counter [7441] alone; the decay interval following the CURRENT [6354]; selector 2 and
      byte [3158] = 1; the [73D0] reader 0x01FE46 (01FF68..020012) that sets byte [641C];
      the CL-side masking inside max(OL, CL) of 0x02FFE0; a cold no-upper-bound case

REVISION 2026-11-27 (third, deciding decode after an adversarial review): P6 now asserts the
[67EC] threshold of 0x036C48 (the first version printed the constants but asserted none, so
"1250" passed); P8 and P9 are new; the P5 maximum is labelled conditional.
AUDIT 2026-11-27 (independent pass): P10 added; P1-P9 unchanged.

ROUNDING. fadd/fsub/fmul are modelled as the exact result rounded TOWARD ZERO and
fmac as fused, as sh2e_emu does (corrections item 106). Table lookups in the model
use the verified runtime routines (0x0BE830 0x0BE8E4 0x0BE874 0x0BE8AC) run in the
emulator, cached; every other helper (0x0BE56C 0x0BE960 0x0BE970 0x0BE608 0x0BEA40
0x0BEAB0 0x0BE53C 0x0BE628) is modelled from its verified CONTRACT. No claim in the
trace depends on the last bit of a float. Deterministic (fixed seeds). Exit 0 on pass.
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
import sh2e_disasm as D       # noqa: E402
import desc_types as DT       # noqa: E402

BIN = os.path.join(ROOT, 'rom', 'AE5L600L 20g rev 20.19c.bin')
ROM = open(BIN, 'rb').read()
assert hashlib.md5(ROM).hexdigest() == '92cae8275cd4f9b473a3a9e36efe6449', 'wrong reference bin'
STOCK = open(os.path.join(ROOT, 'rom', 'ae5l600l.bin'), 'rb').read()
REV_E = open(os.path.join(ROOT, 'rom', 'AE5L600L 20g rev 20.19e.bin'), 'rb').read()

FLT_MAX = struct.unpack('>f', b'\x7f\x7f\xff\xff')[0]
NAN, INF = float('nan'), float('inf')
CHECKS = 0


def ok(n=1):
    global CHECKS
    CHECKS += n


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


# ---------------------------------------------------------------- own rounding (toward zero)
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


def f_sub(a, b):                 # fsub FRm,FRn : FRn = FRn - FRm  ->  f_sub(FRn, FRm)
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


def f_fmac(f0, fm, fn):          # fmac FR0,FRm,FRn : FRn = FR0*FRm + FRn, one rounding
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
def m_clamp(x, lo, hi):          # 0x0BE56C
    if not (x > lo):
        return lo
    if hi > x:
        return x
    return hi


def m_max(a, b):                 # 0x0BE960: a if a > b else b
    return a if a > b else b


def m_min(a, b):                 # 0x0BE970: a if b > a else b
    return a if b > a else b


def m_outside(x, c, w):          # 0x0BE608: 1 if x < c-w or x > c+w
    lo = f_sub(c, w)
    if lo > x:
        return 1
    hi = f_add(c, w)
    if x > hi:
        return 1
    return 0


def m_lag(a, b, k, eps):         # 0x0BEA40: B non-finite -> A; r = A + (1-k)(B-A); snap if eps > |A-r|
    if math.isinf(b) or b != b:
        return a
    d = f_sub(b, a)
    one_k = f_sub(1.0, k)
    r = f_fmac(one_k, d, a)
    t = abs(f_sub(a, r))
    if eps > t:
        return a
    return r


def m_absdiff(a, b):             # 0x0BEAB0
    return abs(f_sub(a, b))


def m_satadd8(a, b):             # 0x0BE53C
    return min((a & 0xFF) + (b & 0xFF), 0xFF)


def m_fdiv0(a, b):               # 0x0BE628
    if b != 0:
        return f_div(a, b)
    if a == 0:
        return 0.0
    return FLT_MAX if a > 0 else -FLT_MAX


# ---------------------------------------------------------------- emulator plumbing
def poke(emu, a, data):
    o = a - E.RAM_LO
    emu.ram[o:o + len(data)] = data


def poke_f(emu, a, v):
    poke(emu, a, struct.pack('>I', E.f2b(v)))


def poke_b(emu, a, v):
    poke(emu, a, bytes([v & 0xFF]))


def poke_h(emu, a, v):
    poke(emu, a, struct.pack('>H', v & 0xFFFF))


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


def run(rom, entry, setup, regs=None):
    e = E.Emu(rom)
    setup(e)
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
    return e


def expect_bytes(W):
    """model write dict {addr: (kind, value)} -> {byte address: byte}"""
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
            # report the float that differs
            base = a & ~3
            raise AssertionError(f'{ctx}: byte {a:#x} emu {got[a]:02x} model {want[a]:02x} '
                                 f'(cell {base:#x} emu {e.read_f32(base)!r})')
    ok()


# ================================================================ P1 0x02FFE0
A = lambda x: 0xFFFF0000 | x          # noqa: E731
IN_02FFE0 = [0x7A20, 0x798C, 0x7B8C, 0x7BE4, 0x7A78, 0x7A7C, 0x7A80, 0x7A84, 0x7B44, 0x7B48, 0x7B4C,
             0x7B50, 0x73B4, 0x7A08, 0x7A14, 0x7AF4, 0x73A4, 0x7354, 0x7374, 0x7BA8, 0x7A44, 0x7BCC,
             0x7340]
K_CBBD2, K_CBE00, K_CBE04 = 0x0CBBD2, 0x0CBE00, 0x0CBE04


def m_02FFE0(I, rom):
    g = lambda a: I[A(a)]          # noqa: E731
    k00, k04 = rd_f(rom, K_CBE00), rd_f(rom, K_CBE04)
    s = g(0x73B4)
    for a in (0x7A08, 0x7A14, 0x7AF4, 0x7B8C):
        s = f_add(s, g(a))
    s = f_add(s, 1.0)
    fr0 = m_min(f_add(g(0x73A4), g(0x7BE4)), k00)
    fr15 = f_add(fr0, f_add(g(0x7354), g(0x7374)))
    if rom[K_CBBD2] == 90:
        fr0 = m_max(g(0x798C), g(0x7BA8))
        fr13 = f_add(f_sub(g(0x7A20), g(0x7A44)), g(0x7BCC))
        fr0 = f_add(fr0, fr13)
        s = f_add(s, fr15)
        s = f_add(s, fr0)
    else:
        fr0 = m_min(f_add(g(0x798C), g(0x7A20)), k04)
        fr0 = m_max(fr0, fr15)
        fr8 = f_add(f_add(g(0x7BCC), g(0x7BA8)), fr0)
        s = f_add(f_sub(s, g(0x7A44)), fr8)
    m = g(0x7340)
    common = f_mul(s, m)
    cyl = [f_mul(f_add(f_add(s, g(0x7B44 + 4 * i)), g(0x7A78 + 4 * i)), m) for i in range(4)]
    W = {A(0x730C): ('f', m_clamp(common, 0.0, 32.0))}
    for i in range(4):
        W[A(0x7310 + 4 * i)] = ('f', m_clamp(cyl[i], 0.0, 32.0))
    return W, s


def p1():
    print('P1  0x02FFE0: sum, per-cylinder products, [0, 32] clamps')
    rom90 = bytearray(ROM)
    rom90[K_CBBD2] = 90
    rom90 = bytes(rom90)
    rnd = random.Random(1109)
    edges = [0.0, -0.0, 1.0, -1.0, 0.25, 0.52, 0.5199999, 0.65, 0.6500001, 31.0, 32.0, 40.0, -40.0,
             1e-6, -1e-6, 0.046875, 0.0999756, 1e30, -1e30]
    n = 0
    seen = set()
    for rom, tag in ((ROM, 'live CBBD2=0'), (rom90, 'copy CBBD2=90')):
        for case in range(700):
            I = {}
            for a in IN_02FFE0:
                r = rnd.random()
                if r < 0.35:
                    v = rnd.choice(edges)
                elif r < 0.8:
                    v = rnd.uniform(-0.5, 0.8)
                else:
                    v = rnd.uniform(-40, 40)
                I[A(a)] = f32(v)
            if case % 7 == 0:
                I[A(0x7340)] = 1.0
            if case % 11 == 0:
                I[A(0x7340)] = f32(rnd.uniform(1.0, 1.2))
            W, s = m_02FFE0(I, rom)

            def setup(e, I=I):
                for a, v in I.items():
                    poke_f(e, a, v)
            e = run(rom, 0x02FFE0, setup)
            check_writes(e, W, f'P1 {tag} case {case}')
            assert e.uninit_reads <= set(I), f'P1 reads outside inputs {e.uninit_reads - set(I)}'
            if rom is ROM:
                # live read set: everything except [7A44] path is read on both branches
                assert e.uninit_reads == set(I), f'P1 live read set {sorted(set(I) - e.uninit_reads)}'
            seen |= e.executed
            n += 1
    code = [pc for pc in range(0x02FFE0, 0x030162, 2)]
    missing = [pc for pc in code if pc not in seen]
    assert not missing, f'P1 not executed: {[hex(x) for x in missing]}'
    # pointed checks of the formula at a hand case (live config)
    I = {A(a): 0.0 for a in IN_02FFE0}
    I[A(0x7340)] = 1.0
    I[A(0x73B4)] = 0.0625
    I[A(0x7B8C)] = 0.03125
    I[A(0x798C)] = 0.3359375
    W, s = m_02FFE0(I, ROM)
    e = run(ROM, 0x02FFE0, lambda e: [poke_f(e, a, v) for a, v in I.items()])
    check_writes(e, W, 'P1 hand')
    print(f'    hand case: 73B4=0.0625 7B8C=0.03125 798C=0.3359375 others 0, 7340=1 -> 730C = '
          f'{e.read_f32(A(0x730C))!r} (= 1 + 0.0625 + 0.03125 + 0.3359375 exactly: '
          f'{e.read_f32(A(0x730C)) == 1.4296875})')
    assert e.read_f32(A(0x730C)) == 1.4296875
    # clamps: sum far above / below
    I[A(0x73B4)] = 100.0
    e = run(ROM, 0x02FFE0, lambda e: [poke_f(e, a, v) for a, v in I.items()])
    assert e.read_f32(A(0x730C)) == 32.0
    I[A(0x73B4)] = -100.0
    e = run(ROM, 0x02FFE0, lambda e: [poke_f(e, a, v) for a, v in I.items()])
    assert e.read_f32(A(0x730C)) == 0.0
    print('    clamp: sum +100 -> 32.0, sum -100 -> 0.0 (asserted)')
    # the max() in the live branch: OL side vs CL side
    I = {A(a): 0.0 for a in IN_02FFE0}
    I[A(0x7340)] = 1.0
    for ol, cl, want in ((0.3359375, 0.0, 1.3359375), (0.0, 0.125, 1.125), (0.6, 0.0, 1.5199999809265137),
                         (0.25, 0.75, 1.6499999761581421)):
        I[A(0x798C)] = ol
        I[A(0x73A4)] = cl
        e = run(ROM, 0x02FFE0, lambda e: [poke_f(e, a, v) for a, v in I.items()])
        got = e.read_f32(A(0x730C))
        print(f'    798C={ol} 73A4={cl} -> 730C {got!r}')
        assert same(got, f32(want)), (ol, cl, got)
        ok()
    print(f'    {n} grid cases, both branches, every one of the {len(code)} addresses executed')


# ================================================================ P2 7340 / 733C writers
def p2():
    print('P2  0x02FF8E ([733C]), 0x02FFA2 / 0x02FF74 ([7340])')
    k08 = rd_f(ROM, 0x0CBE08)
    for b in range(256):
        e = run(ROM, 0x02FF8E, lambda e, b=b: poke_b(e, A(0x641C), b))
        want = 0.0 if b == 1 else k08
        check_writes(e, {A(0x733C): ('f', want)}, f'P2 733C b={b}')
    vals = set()
    for b24 in (0, 1, 2, 0x81, 0xFF):
        for b08 in range(256):
            def setup(e, b24=b24, b08=b08):
                poke_b(e, A(0x8F24), b24)
                poke_b(e, A(0x8F08), b08)
            e = run(ROM, 0x02FFA2, setup)
            s8 = b08 - 256 if b08 & 0x80 else b08
            if b24 == 1 and b08 != 0:
                q = m_fdiv0(f32(float(s8)), 100.0)
                want = m_clamp(f_add(q, 1.0), 1.0, rd_f(ROM, 0x030188))
            else:
                want = 1.0
            check_writes(e, {A(0x7340): ('f', want)}, f'P2 7340 {b24} {b08}')
            vals.add(want)
    e = run(ROM, 0x02FF74, lambda e: None)
    check_writes(e, {A(0x7340): ('f', 1.0)}, 'P2 02FF74')
    print(f'    [733C] = 0.0 if byte 641C == 1 else {k08}; [7340] in [{min(vals)}, {max(vals)}] '
          f'(1 + s8(8F08)/100 clamped [1, 1.2] when byte 8F24 == 1 and 8F08 != 0, else 1.0)')
    assert min(vals) == 1.0 and max(vals) == rd_f(ROM, 0x030188)
    assert rd_f(ROM, 0x030180) == 100.0 and struct.unpack_from('>I', ROM, 0x030188)[0] == 0x3F999999


# ================================================================ P3 0x030C38 and its tree
C = {}


def load_cal(rom):
    c = {}
    for a in (0x0CBE00, 0x0CBE04, 0x0CBE20, 0x0CBE24, 0x0CBE28, 0x0CBE2C, 0x0CBE30, 0x0CBE34, 0x0CBE38,
              0x0CBE3C, 0x0CBE40, 0x0CBE44, 0x0CBE48, 0x0CBE4C, 0x0CBE50, 0x0CBE54, 0x0CBE58, 0x0CBE5C,
              0x0CBE60):
        c[a] = rd_f(rom, a)
    for a in (0x0CBC26, 0x0CBC28, 0x0CBC2A, 0x0CBC2C):
        c[a] = rd_h(rom, a)
    for a in (0x0CBBD2, 0x0CBBD4, 0x0CBBD5):
        c[a] = rom[a]
    return c


F_IN = [0x6350, 0x6624, 0x63F8, 0x620C, 0x7408, 0x740C, 0x7410, 0x73D8, 0x73D0, 0x73D4, 0x73DC, 0x6354,
        0x73E0, 0x73E4]
B_IN = [0x67FC, 0x61F4, 0x6254, 0x65C0, 0x647C, 0x844F, 0x726C, 0x641C, 0x7C9D, 0x7C9A, 0x3158,
        0x7441, 0x7446]
H_IN = [0x67EC, 0x7442]


def m_030C38(S, rom):
    c = load_cal(rom)
    W = {}

    def g(a):
        a = A(a)
        return W[a][1] if a in W else S[a]

    def wf(a, v):
        W[A(a)] = ('f', v)

    def wb(a, v):
        W[A(a)] = ('b', v & 0xFF)

    def ww(a, v):
        W[A(a)] = ('w', v & 0xFFFF)

    E_ = S[A(0x6350)]
    rpm = S[A(0x6624)]
    cnt = S[A(0x67EC)] & 0xFFFF
    wf(0x7414, rpm)
    wb(0x7444, 1 if S[A(0x67FC)] == 1 else 0)                    # 0x023E48
    stk0 = 1 if (S[A(0x61F4)] & 2) else 0                         # 0x01CF5E
    r13 = S[A(0x6254)]
    sel = 0 if S[A(0x647C)] == 1 else 2                           # 0x021016
    r12 = S[A(0x65C0)]
    r10 = S[A(0x844F)]
    wb(0x7445, S[A(0x726C)])
    # 0x0312BC
    if c[0x0CBBD4] == 1:
        wf(0x73B0, S[A(0x63F8)])
    else:
        wf(0x73B0, f_mul(S[A(0x620C)], f32(0.01)))
    # history shift + newest
    wf(0x7410, S[A(0x740C)])
    wf(0x740C, S[A(0x7408)])
    wf(0x7408, g(0x73B0))
    # ---- 0x0312DE
    d = f_sub(g(0x7408), g(0x7410))
    if c[0x0CBE30] > d:
        th = lk1(0x0ACD34, g(0x7414), rom)
        ad = m_absdiff(d, 0.0)
        if th > ad:
            x = 0.0
        else:
            x = c[0x0CBE34] if c[0x0CBE34] > d else d
    else:
        x = c[0x0CBE30]
    wf(0x73EC, x)
    D_old = S[A(0x73D8)]
    r6 = lku16(0x0ACD48, E_, rom)
    hold = False
    if S[A(0x7C9D)] == 1 and (S[A(0x7442)] & 0xFFFF) >= r6:
        hold = True
    elif (S[A(0x7C9A)] & 0xFF) >= c[0x0CBBD5]:
        hold = True
    elif g(0x7445) == 1:
        hold = True
    if hold:
        a_new = b_new = g(0x73B0)
    else:
        ev = g(0x73EC)
        if not (0.0 > D_old):
            path = 'set' if c[0x0CBE58] > ev else 'filter'
        else:
            path = 'filter' if c[0x0CBE5C] > ev else 'set'
        if path == 'set':
            a_new = b_new = g(0x740C)
        else:
            b = g(0x73B0)
            eps = rd_f(rom, 0x031504)
            if 0.0 > f_sub(b, S[A(0x73D0)]):
                k1, k2 = c[0x0CBE3C], c[0x0CBE44]
            else:
                k1, k2 = c[0x0CBE38], c[0x0CBE40]
            a_new = m_lag(b, S[A(0x73D0)], k1, eps)
            b_new = m_lag(b, S[A(0x73D4)], k2, eps)
    wf(0x73D0, a_new)
    wf(0x73D4, b_new)
    v = f_sub(g(0x73B0), g(0x73D0))
    if not (c[0x0CBE4C] > v) and (c[0x0CBE48] > v):
        v = 0.0
    wf(0x73D8, v)
    v2 = f_sub(g(0x73B0), g(0x73D4))
    if not (c[0x0CBE54] > v2) and (c[0x0CBE50] > v2):
        v2 = 0.0
    wf(0x73DC, v2)
    # ---- 0x030F02
    r14b, r13b = S[A(0x844F)], S[A(0x641C)]
    wf(0x73E8, lk1(0x0AC41C, E_, rom) if g(0x7444) == 1 else 1.0)
    wf(0x7418, lk1(0x0ACC94 if r14b == 1 else 0x0ACCA8, g(0x73EC), rom))
    if 0.0 > g(0x73EC):
        wf(0x7424, lk1(0x0ACCD0, g(0x73B0), rom))
        if r13b == 1:
            wf(0x741C, lk1(0x0AC3F4, g(0x7414), rom))
            wf(0x73F0, f_mul(f_mul(g(0x7418), g(0x7424)), g(0x741C)))
        else:
            wf(0x73F0, f_mul(g(0x7418), g(0x7424)))
    else:
        wf(0x7420, lk1(0x0ACCBC, g(0x73B0), rom))
        wf(0x73F0, f_mul(f_mul(g(0x7418), g(0x7420)), g(0x73E8)))
    if 0.0 > g(0x73D8):
        wf(0x7430, lk1(0x0ACCF8, g(0x73B0), rom))
        if r13b == 1:
            wf(0x7428, lk1(0x0AC408, g(0x7414), rom))
            wf(0x73F4, f_mul(f_mul(f_mul(g(0x73D8), c[0x0CBE24]), g(0x7430)), g(0x7428)))
        else:
            wf(0x73F4, f_mul(f_mul(g(0x73D8), c[0x0CBE24]), g(0x7430)))
    else:
        wf(0x742C, lk1(0x0ACCE4, g(0x73B0), rom))
        wf(0x73F4, f_mul(f_mul(f_mul(g(0x73D8), c[0x0CBE20]), g(0x742C)), g(0x73E8)))
    if 0.0 > g(0x73DC):
        t = lk1(0x0ACD20, g(0x73B0), rom)
        wf(0x73F8, f_mul(t, f_mul(g(0x73DC), c[0x0CBE2C])))
    else:
        t = lk1(0x0ACD0C, g(0x73B0), rom)
        wf(0x73F8, f_mul(f_mul(t, f_mul(g(0x73DC), c[0x0CBE28])), g(0x73E8)))
    # ---- 0x03110C
    fr14 = S[A(0x6354)]
    wf(0x73FC, c[0x0CBE60] if g(0x7444) == 1 else 1.0)
    eps13 = 2.0 ** -13
    if (not m_outside(S[A(0x73E0)], 1.0, eps13) and not m_outside(S[A(0x73E4)], 0.0, eps13)
            and g(0x7445) == 0):
        wf(0x7400, 1.0)
        wb(0x7441, 0)
    else:
        wf(0x7434, lk1(0x0AC43C, fr14, rom))

        def mult(e0, e4):
            s = f_add(e0, e4)
            if sel == 2:
                return m_min(s, 8.0)
            return m_clamp(f_mul(s, g(0x7434)), 1.0, 8.0)
        if not (cnt >= c[0x0CBC28]):
            if S[A(0x3158)] == 1:
                wf(0x73E0, lk1(0x0ACDA4, fr14, rom))
                wf(0x73E4, lk1(0x0ACDB8, fr14, rom))
            else:
                wf(0x73E0, lk1(0x0ACD7C, fr14, rom))
                wf(0x73E4, lk1(0x0ACD90, fr14, rom))
            wf(0x7400, mult(g(0x73E0), g(0x73E4)))
            wb(0x7441, 0)
        else:
            if 0.0 > g(0x73F0) or 0.0 > g(0x73F4):
                wf(0x7400, 1.0)
            else:
                wf(0x7400, mult(g(0x73E0), g(0x73E4)))
            wb(0x7440, lku8(0x0AC430, fr14, rom))
            n = m_satadd8(S[A(0x7441)], 1)
            wb(0x7441, n)
            if n >= W[A(0x7440)][1]:
                wf(0x7438, lk1(0x0ACD54, fr14, rom))
                wf(0x73E0, m_max(f_fmac(-g(0x7438), g(0x73FC), g(0x73E0)), 1.0))
                wf(0x743C, lk1(0x0ACD68, fr14, rom))
                wf(0x73E4, m_max(f_fmac(-g(0x743C), g(0x73FC), g(0x73E4)), 0.0))
                wb(0x7441, 0)
    # ---- back in 0x030C38
    k_cc = lk1(0x0ACDCC, E_, rom)
    k_e0 = lk1(0x0ACDE0, E_, rom)
    if g(0x7445) == 1:
        wb(0x7446, 0)
    elif r13 == 0 or r12 == 0 or not (k_cc > g(0x73D8)) or not (k_e0 > g(0x73EC)):
        wb(0x7446, 1)
    thr = c[0x0CBC2C] if g(0x7446) == 0 else c[0x0CBC2A]
    ww(0x7404, thr)
    if not (cnt >= thr) or stk0 == 1:
        wf(0x73B4, 0.0)
        return W
    if 0.0 > g(0x73EC):
        wf(0x73B8, lk1(0x0ACB7C if sel == 2 else 0x0ACB90, E_, rom))
        wf(0x73C4, lk1(0x0ACBB8, rpm, rom))
    else:
        rec = (0x0ACB40 if r10 == 1 else 0x0ACB54) if sel == 2 else 0x0ACB68
        wf(0x73B8, lk1(rec, E_, rom))
        wf(0x73C4, lk1(0x0ACBA4, rpm, rom))
    if 0.0 > g(0x73D8):
        if sel == 2:
            wf(0x73BC, lk1(0x0ACBCC, E_, rom))
            rec2 = 0x0ACC44
        else:
            wf(0x73BC, lk1(0x0ACBE0, E_, rom))
            rec2 = 0x0ACC58
        wf(0x73C0, lk1(rec2, E_, rom))
        wf(0x73C8, lk1(0x0ACC08, rpm, rom))
        wf(0x73CC, lk1(0x0ACC80, rpm, rom))
    else:
        if sel == 2:
            wf(0x73BC, lk2(0x0AD7F4 if r10 == 1 else 0x0AD810, E_, g(0x73B0), rom))
            rec2 = 0x0ACC1C
        else:
            wf(0x73BC, lk2(0x0AD82C, E_, g(0x73B0), rom))
            rec2 = 0x0ACC30
        wf(0x73C0, lk1(rec2, E_, rom))
        wf(0x73C8, lk1(0x0ACBF4, rpm, rom))
        wf(0x73CC, lk1(0x0ACC6C, rpm, rom))
    t = f_mul(f_mul(g(0x73F4), g(0x73C8)), g(0x73BC))
    t = f_fmac(f_mul(g(0x73F0), g(0x73C4)), g(0x73B8), t)
    t = f_fmac(f_mul(g(0x73F8), g(0x73CC)), g(0x73C0), t)
    t = f_mul(t, g(0x7400))
    wf(0x73B4, t if cnt >= c[0x0CBC26] else m_max(t, 0.0))
    return W


def rand_state(rnd, rom=ROM):
    S = {}
    pick = rnd.random
    Es = [-50.0, -40.0, -5.0, 0.0, 25.0, 69.9, 79.9, 80.0, 90.0, 95.0, 110.0, 130.0]
    S[A(0x6350)] = f32(rnd.choice(Es) if pick() < 0.6 else rnd.uniform(-45, 120))
    S[A(0x6624)] = f32(rnd.choice([0.0, 750.0, 2000.0, 3600.0, 5200.0, 6500.0, 8000.0])
                       if pick() < 0.5 else rnd.uniform(0, 7500))
    S[A(0x63F8)] = f32(rnd.uniform(0.1, 3.0))
    S[A(0x620C)] = f32(rnd.choice([30.0, 100.0, 150.0, 300.0, 700.0, 1200.0, 2000.0])
                       if pick() < 0.5 else rnd.uniform(20, 1800))
    base = S[A(0x620C)] * 0.01
    for a in (0x7408, 0x740C, 0x7410):
        r = pick()
        S[A(a)] = f32(base + (rnd.choice([0.0, 0.05, -0.05, 0.1, -0.1, 0.5, -0.5, 1.5, -1.5, 12.0, -12.0])
                              if r < 0.5 else rnd.uniform(-2, 2)))
    for a in (0x73D0, 0x73D4):
        S[A(a)] = f32(base + (rnd.choice([0.0, 0.0001, 0.04, -0.04, 0.06, -0.06, 2.0, -2.0, 25.0])
                              if pick() < 0.5 else rnd.uniform(-5, 5)))
    S[A(0x73D8)] = f32(rnd.choice([0.0, -0.0, 0.5, -0.5, 0.7, -20.0, 3.0]) if pick() < 0.6
                       else rnd.uniform(-3, 3))
    S[A(0x73DC)] = f32(rnd.uniform(-1, 1))
    S[A(0x6354)] = f32(rnd.choice(Es) if pick() < 0.6 else rnd.uniform(-45, 120))
    S[A(0x73E0)] = f32(rnd.choice([1.0, 1.00005, 1.0002, 1.25, 2.2, 0.9]) if pick() < 0.6
                       else rnd.uniform(0.5, 3))
    S[A(0x73E4)] = f32(rnd.choice([0.0, 0.00005, -0.00005, 0.0002, 2.75, -0.5]) if pick() < 0.6
                       else rnd.uniform(-1, 3))
    S[A(0x67FC)] = rnd.choice([0, 1, 2, 0x81])
    S[A(0x61F4)] = rnd.choice([0, 1, 2, 3, 0xFD, 0xFF])
    S[A(0x6254)] = rnd.choice([0, 1, 1, 1, 0x80])
    S[A(0x65C0)] = rnd.choice([0, 1, 1, 1, 0x80])
    S[A(0x647C)] = rnd.choice([0, 1, 1, 2, 0x81])
    S[A(0x844F)] = rnd.choice([0, 1, 1, 2, 0x81])
    S[A(0x726C)] = rnd.choice([0, 0, 0, 1, 2, 0x81])
    S[A(0x641C)] = rnd.choice([0, 1, 2])
    S[A(0x7C9D)] = rnd.choice([0, 0, 0, 1, 2])
    S[A(0x7C9A)] = rnd.choice([0, 0, 1, 2, 3, 4, 0x80, 0xFF])
    S[A(0x3158)] = rnd.choice([0, 1, 2])
    S[A(0x7441)] = rnd.choice([0, 1, 7, 8, 13, 14, 15, 200, 254, 255])
    S[A(0x7446)] = rnd.choice([0, 1, 2])
    S[A(0x67EC)] = rnd.choice([0, 12, 13, 14, 24, 25, 26, 624, 625, 626, 874, 875, 876, 2000, 32767,
                               32768, 65535])
    S[A(0x7442)] = rnd.choice([0, 1, 100, 65535])
    return S


def setup_state(S):
    def f(e):
        for a, v in S.items():
            lo = a & 0xFFFF
            if lo in F_IN:
                poke_f(e, a, v)
            elif lo in B_IN:
                poke_b(e, a, v)
            elif lo in H_IN:
                poke_h(e, a, v)
            else:
                raise KeyError(hex(a))
    return f


TREE = [(0x030C38, 0x030F02), (0x030F02, 0x03107E), (0x03110C, 0x0312BC), (0x0312BC, 0x0312DE),
        (0x0312DE, 0x0314D6)]


def code_addrs():
    """instruction addresses of the five functions, exactly as fn_dump lists them (pool lines excluded)"""
    import re
    import subprocess
    out = []
    for lo, hi in TREE:
        txt = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'mapping', 'fn_dump.py'),
                              f'0x{lo:06X}'], capture_output=True, text=True, check=True).stdout
        for line in txt.splitlines():
            mm = re.match(r'^([0-9A-F]{6}): ', line)
            if mm:
                out.append(int(mm.group(1), 16))
    return out


def p3():
    print('P3  0x030C38 + 0x0312BC 0x0312DE 0x030F02 0x03110C (+ getters 0x023E48 0x01CF5E 0x021016)')
    rnd = random.Random(73)
    seen = set()
    n = 0
    path_hits = {}
    declared = None
    for case in range(1500):
        S = rand_state(rnd)
        # steer some cases into specific corners
        k = case % 10
        if k == 0:
            S[A(0x7C9D)], S[A(0x7C9A)], S[A(0x726C)] = 0, 0, 0
            S[A(0x67EC)] = 2000
            S[A(0x61F4)] = 0
        if k == 1:
            S[A(0x73E0)], S[A(0x73E4)], S[A(0x726C)] = 1.0, 0.0, 0
        if k == 2:
            S[A(0x67EC)] = rnd.choice([0, 5, 12])
        if k == 3:   # NaN / inf corners on the history and lag state
            S[A(0x7408)] = rnd.choice([NAN, INF, -INF, S[A(0x7408)]])
            S[A(0x73D0)] = rnd.choice([NAN, INF, S[A(0x73D0)]])
            S[A(0x73D8)] = rnd.choice([NAN, S[A(0x73D8)]])
        W = m_030C38(S, ROM)
        e = run(ROM, 0x030C38, setup_state(S))
        check_writes(e, W, f'P3 case {case}')
        assert e.uninit_reads <= set(S), f'P3 reads outside inputs {sorted(hex(x) for x in e.uninit_reads - set(S))}'
        seen |= e.executed
        tag = ('zero' if W[A(0x73B4)][1] == 0 else 'pos' if W[A(0x73B4)][1] > 0 else 'neg')
        path_hits[tag] = path_hits.get(tag, 0) + 1
        n += 1
    # the two branches this calibration cannot take, on an in-memory ROM copy (the file is never written):
    # byte 0x0CBBD4 = 1 ([73B0] = [63F8] instead of 0.01*[620C]) and a non-empty [73DC] deadband
    alt = bytearray(ROM)
    alt[0x0CBBD4] = 1
    alt[0x0CBE50:0x0CBE54] = struct.pack('>f', 0.05)
    alt[0x0CBE54:0x0CBE58] = struct.pack('>f', -0.05)
    alt = bytes(alt)
    for case in range(200):
        S = rand_state(rnd)
        S[A(0x73D4)] = f32(S[A(0x63F8)] + rnd.choice([0.0, 0.01, -0.01, 0.04, 0.2]))
        S[A(0x7C9D)], S[A(0x7C9A)], S[A(0x726C)] = 0, 0, 0
        W = m_030C38(S, alt)
        e = run(alt, 0x030C38, setup_state(S))
        check_writes(e, W, f'P3 alt case {case}')
        seen |= e.executed
        n += 1
    addrs = code_addrs()
    missing = [pc for pc in addrs if pc not in seen]
    assert not missing, f'P3 not executed: {[hex(x) for x in missing]}'
    print(f'    {n} cases (exact write set and values each), [73B4] outcomes {path_hits}; '
          f'all {len(addrs)} instruction addresses of the five functions executed')
    # targeted: [73B4] is written on EVERY call (asserted inside check_writes via the model dict)
    # targeted: the GBR value 0xFFFF73B0 and r8 = 0xFFFF7414 -> [r8-96] = 0xFFFF73B4
    assert struct.unpack_from('>I', ROM, 0x030DC0)[0] == 0xFFFF73B0
    assert struct.unpack_from('>I', ROM, 0x030DC4)[0] == 0xFFFF7414
    assert (0xFFFF7414 - 96) & 0xFFFFFFFF == 0xFFFF73B4
    ok(3)


# ================================================================ P4 calibration facts
RECS_C38 = [0x0ACB40, 0x0ACB54, 0x0ACB68, 0x0ACB7C, 0x0ACB90, 0x0ACBA4, 0x0ACBB8, 0x0ACBCC, 0x0ACBE0,
            0x0ACBF4, 0x0ACC08, 0x0ACC1C, 0x0ACC30, 0x0ACC44, 0x0ACC58, 0x0ACC6C, 0x0ACC80, 0x0AD7F4,
            0x0AD810, 0x0AD82C, 0x0ACDCC, 0x0ACDE0, 0x0AC41C, 0x0ACC94, 0x0ACCA8, 0x0ACCBC, 0x0ACCD0,
            0x0AC3F4, 0x0ACCE4, 0x0ACCF8, 0x0AC408, 0x0ACD0C, 0x0ACD20, 0x0AC43C, 0x0ACDA4, 0x0ACDB8,
            0x0ACD7C, 0x0ACD90, 0x0AC430, 0x0ACD54, 0x0ACD68, 0x0ACD34, 0x0ACD48]


def tbl(rom, rec):
    t = DT.read_table(rom, rec)
    return t['axes'], t['values']


def p4():
    print('P4  calibration: stock vs 20.19c vs 20.19e')
    cs, cc, ce = load_cal(STOCK), load_cal(ROM), load_cal(REV_E)
    for a in sorted(cc):
        assert cs[a] == cc[a] == ce[a], f'cal {a:#x} differs {cs[a]} {cc[a]} {ce[a]}'
    print('    scalars identical in all three: ' + ', '.join(f'{a:06X}={cc[a]!r}' for a in sorted(cc)))
    assert cc[0x0CBBD2] == 0 and cc[0x0CBBD4] == 0 and cc[0x0CBBD5] == 3
    assert cc[0x0CBE28] == 0.0 and cc[0x0CBE2C] == 0.0 and cc[0x0CBE50] == 0.0 and cc[0x0CBE54] == 0.0
    ok(3)
    diff = []
    for rec in RECS_C38:
        ts, tc, te = tbl(STOCK, rec), tbl(ROM, rec), tbl(REV_E, rec)
        assert tc == te, f'{rec:#x} differs 20.19c vs 20.19e'
        if ts != tc:
            diff.append(rec)
        ok()
    print(f'    {len(RECS_C38)} records read by the 0x030C38 tree: 20.19c == 20.19e for all; '
          f'stock differs only at {[hex(r) for r in diff]}')
    assert diff == [0x0ACB40, 0x0ACB54, 0x0ACB68]
    for rec in diff:
        print(f'      {rec:#08x} stock {[round(v, 4) for v in tbl(STOCK, rec)[1]]}')
        print(f'      {rec:#08x} 20.19c {[round(v, 4) for v in tbl(ROM, rec)[1]]}')
    # the three planes the code selects among are consecutive 16-cell uint16 arrays
    for rec, dp in ((0x0ACB40, 0x0CD6E6), (0x0ACB54, 0x0CD706), (0x0ACB68, 0x0CD726)):
        assert struct.unpack_from('>I', ROM, rec + 8)[0] == dp
        ok()
    # no record anywhere uses 0x0CCDCC (the definition's "Engine Load" Y axis) as an axis
    assert ROM.find(struct.pack('>I', 0x0CCDCC)) == -1
    print('    0x0CCDCC (definition Y axis of "Tau Input A Rising Load Activation") occurs nowhere as a long')
    ok()


# ================================================================ P5 bounds of [73B4]
def p5():
    print('P5  reachable range of [73B4] with the 20.19c tables')
    # term-1 factors
    E_grid = [-40.0, 0.0, 20.0, 40.0, 60.0, 70.0, 80.0, 90.0, 100.0, 110.0]
    x_grid = [i / 20.0 for i in range(-26, 27)] + [-10.0, 10.0]
    b_grid = [0.5, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0, 16.0, 20.0]
    rpm_grid = [0.0, 800.0, 1600.0, 2000.0, 2400.0, 3200.0, 4000.0, 6000.0, 8000.0]
    m7418 = max(lk1(0x0ACC94, x) for x in x_grid)
    n7418 = min(lk1(0x0ACC94, x) for x in x_grid)
    assert tbl(ROM, 0x0ACC94) == tbl(ROM, 0x0ACCA8)
    mBC = max(lk1(0x0ACCBC, b) for b in b_grid)
    print(f'    [7418] = ACC94/ACCA8([73EC]) in [{n7418}, {m7418}] (tables identical); '
          f'ACCBC([73B0]) in [{min(lk1(0x0ACCBC, b) for b in b_grid)}, {mBC}]')
    print('    tau A tables (selected by flags, interpolated on [6350]) at E = ' + str(E_grid))
    for rec, nm in ((0x0ACB40, 'ACB40 sel=2,844F=1'), (0x0ACB54, 'ACB54 sel=2,844F!=1'),
                    (0x0ACB68, 'ACB68 sel=0 (647C==1)')):
        print(f'      {nm:24s} ' + ' '.join(f'{lk1(rec, x):.4f}' for x in E_grid))
    # term-1 maximum over the warm region (E >= 80)
    warm = [80.0, 85.0, 90.0, 100.0, 110.0]
    t1max = {}
    for rec in (0x0ACB40, 0x0ACB54, 0x0ACB68):
        t1max[rec] = max(f_mul(f_mul(m7418, mBC), lk1(rec, x)) for x in warm)
    print(f'    term1 = [7418]*ACCBC*[73E8](=1.0)*ACBA4(=1.0)*tauA, max at E >= 80: '
          f'ACB40 {t1max[0x0ACB40]:.4f}  ACB54 {t1max[0x0ACB54]:.4f}  ACB68 {t1max[0x0ACB68]:.4f}')
    # smallest non-zero [7418]: deadband threshold ACD34(RPM)
    th = [lk1(0x0ACD34, r) for r in rpm_grid]
    print(f'    deadband |d[73B0]| < ACD34(RPM) -> [73EC] = 0; ACD34 over RPM {rpm_grid}: '
          f'{[round(v, 4) for v in th]}')
    print(f'    [7418] at d = 0.0600 / 0.0800 / 0.1000 / 0.2000 / 0.3000: ' +
          ' / '.join(f'{lk1(0x0ACC94, f32(x)):.4f}' for x in (0.06, 0.08, 0.1, 0.2, 0.3)))
    # term-2 factor at warm
    for rec in (0x0AD7F4, 0x0AD810, 0x0AD82C):
        assert tbl(ROM, rec) == tbl(ROM, 0x0AD82C)
    t2f = [lk2(0x0AD82C, x, b) for x in warm for b in b_grid]
    print(f'    term2 = [73D8]*0.02*ACCE4(=1)*[73E8](=1)*ACBF4(=1)*AD82C(E,[73B0]); AD82C at E >= 90: '
          f'{sorted(set(round(lk2(0x0AD82C, x, b), 4) for x in (90.0, 100.0, 110.0) for b in b_grid))}; '
          f'at E = 80: {sorted(set(round(lk2(0x0AD82C, 80.0, b), 4) for b in b_grid))}')
    assert all(lk2(0x0AD82C, x, b) == 1.0 for x in (90.0, 100.0, 110.0) for b in b_grid)
    # term 3 is identically zero for finite inputs (CBE28 = CBE2C = 0)
    assert rd_f(ROM, 0x0CBE28) == 0.0 and rd_f(ROM, 0x0CBE2C) == 0.0
    # [7400] when warm: seed (counter < 13) ACD7C/ACD90 or ACDA4/ACDB8
    for x in warm:
        assert lk1(0x0ACD90, x) == 0.0 and lk1(0x0ACDB8, x) == 0.0
    print(f'    [7400] seed tables are read at [6354] (NOT [6350]): ACD7C([6354] >= 80) = {lk1(0x0ACD7C, 80.0)}, '
          f'ACD90 = 0 there, AC43C = {lk1(0x0AC43C, 90.0)}; decrement ACD54 = {lk1(0x0ACD54, 90.0)} every '
          f'{lku8(0x0AC430, 90.0)} calls -> [7400] in [1.0, 1.25] only for a seed taken at [6354] >= 80; '
          f'seed at [6354] = 0: {f_add(lk1(0x0ACD7C, 0.0), lk1(0x0ACD90, 0.0))} (P8)')
    assert f_add(lk1(0x0ACD7C, 0.0), lk1(0x0ACD90, 0.0)) == 4.9501953125
    assert tbl(ROM, 0x0ACD7C) == tbl(ROM, 0x0ACDA4) and tbl(ROM, 0x0ACD90) == tbl(ROM, 0x0ACDB8)
    for rec in (0x0ACD7C, 0x0ACD90, 0x0ACDA4, 0x0ACDB8, 0x0AC430, 0x0ACD54, 0x0ACD68):
        assert struct.unpack_from('>I', ROM, rec + 4)[0] == 0x0CC664, hex(rec)   # not the 0x0CC624 axis
    assert struct.unpack_from('>I', ROM, 0x0AC43C + 4)[0] == 0x0CC624
    ok(3)
    # model sweep: the end-to-end [73B4] for a warm tip-in, with every gate open
    best = (0, None)
    for sel_bytes in ((1, 0), (0, 1), (0, 0)):          # (647C, 844F)
        for x in warm:
            for b in (1.0, 3.0, 5.0, 8.0):
                for dl in (0.1, 0.2, 0.3, 0.5, 1.0, 2.0):
                    S = steady_state(x, 3000.0, b)
                    S[A(0x647C)], S[A(0x844F)] = sel_bytes
                    S[A(0x620C)] = f32((b + dl) * 100.0)       # step of dl in [73B0] since last call
                    W = m_030C38(S, ROM)
                    v = W[A(0x73B4)][1]
                    if v > best[0]:
                        best = (v, (sel_bytes, x, b, dl))
    print(f'    model sweep (warm, gates open, one-call step dl in [73B0]): max [73B4] = {best[0]:.4f} at '
          f'(647C,844F)={best[1][0]} E={best[1][1]} [73B0]={best[1][2]} dl={best[1][3]}')
    # emulate the same best case to tie the sweep to the bytes
    (sb, x, b, dl) = best[1]
    S = steady_state(x, 3000.0, b)
    S[A(0x647C)], S[A(0x844F)] = sb
    S[A(0x620C)] = f32((b + dl) * 100.0)
    W = m_030C38(S, ROM)
    e = run(ROM, 0x030C38, setup_state(S))
    check_writes(e, W, 'P5 best')
    # a small tip-in that lands in the observed residual band
    for dl in (0.15, 0.2, 0.25):
        S = steady_state(90.0, 3000.0, 2.0)
        S[A(0x647C)], S[A(0x844F)] = 1, 0
        S[A(0x620C)] = f32((2.0 + dl) * 100.0)
        W = m_030C38(S, ROM)
        e = run(ROM, 0x030C38, setup_state(S))
        check_writes(e, W, f'P5 band dl={dl}')
        print(f'    E=90 RPM=3000 [73B0] 2.0 -> {2.0 + dl} in one call, 647C=1 (ACB68): '
              f'[73EC]={e.read_f32(A(0x73EC)):.4f} [73D8]={e.read_f32(A(0x73D8)):.4f} '
              f'[73B4]={e.read_f32(A(0x73B4)):.4f}')
    # The sweep above runs from steady_state, which settles [73E0] = 1.0 / [73E4] = 0.0, so [7400] = 1.0
    # by the 0x03110C shortcut. Its maximum is therefore CONDITIONAL on [7400] = 1.0. Re-emulate the best
    # case with the multiplier the seed tables can leave: 1.25 (0x0ACD7C at [6354] >= 80) and
    # 4.9501953 (0x0ACD7C(0) + 0x0ACD90(0)). [67EC] = 2000 -> decay path; a rise keeps [73F0], [73F4] >= 0,
    # so [7400] = M([73E0] + [73E4]) (min(., 8) on selector 2).
    assert best[1] == ((0, 1), 80.0, 1.0, 2.0), best
    res = []
    for e0, e4 in ((1.0, 0.0), (1.25, 0.0), (lk1(0x0ACD7C, 0.0), lk1(0x0ACD90, 0.0))):
        S = steady_state(80.0, 3000.0, 1.0)
        S[A(0x647C)], S[A(0x844F)] = 0, 1
        S[A(0x73E0)], S[A(0x73E4)] = e0, e4
        S[A(0x620C)] = f32(300.0)
        W = m_030C38(S, ROM)
        e = run(ROM, 0x030C38, setup_state(S))
        check_writes(e, W, f'P5 best x [7400] seed {e0}+{e4}')
        res.append((e.read_f32(A(0x7400)), e.read_f32(A(0x73B4))))
    print('    same best case with [7400] = ' +
          ', '.join(f'{m:.7g} -> [73B4] {v:.4f}' for m, v in res) + '  (emulated; the sweep max is NOT a bound)')
    assert res[0][0] == 1.0 and 1.30 < res[0][1] < 1.31
    assert res[1][0] == 1.25 and 1.63 < res[1][1] < 1.64
    assert res[2][0] == 4.9501953125 and 6.46 < res[2][1] < 6.48
    ok(3)


def steady_state(x, rpm, b):
    """a settled warm state: history and lag states equal b, decays complete, gates open"""
    S = {}
    S[A(0x6350)] = f32(x)
    S[A(0x6624)] = f32(rpm)
    S[A(0x63F8)] = 1.0
    S[A(0x620C)] = f32(b * 100.0)
    for a in (0x7408, 0x740C, 0x7410, 0x73D0, 0x73D4):
        S[A(a)] = f32(b)
    S[A(0x73D8)] = 0.0
    S[A(0x73DC)] = 0.0
    S[A(0x6354)] = f32(x)
    S[A(0x73E0)] = 1.0
    S[A(0x73E4)] = 0.0
    for a, v in ((0x67FC, 0), (0x61F4, 0), (0x6254, 1), (0x65C0, 1), (0x647C, 1), (0x844F, 0),
                 (0x726C, 0), (0x641C, 0), (0x7C9D, 0), (0x7C9A, 0), (0x3158, 0), (0x7441, 0),
                 (0x7446, 1)):
        S[A(a)] = v
    S[A(0x67EC)] = 2000
    S[A(0x7442)] = 0
    return S


# ================================================================ P6 other addends
def p6():
    print('P6  writers of the other addends')
    # --- [7A08]: 0x036B48 (r14 = 0xFFFF7A0C; [7A08] = r14-4; flags [7A0C], [7A10])
    k230 = rd_f(ROM, 0x0CC230)
    n = 0
    for prev in (0, 1, 2):
        for cur in (0, 1, 2, 0x81):
            for old in (0.0, 0.0004, 0.0005, 0.003, 0.2, 0.30078125, -0.1):
                for x in (-40.0, -10.0, 0.0, 5.0, 10.0, 90.0):
                    def setup(e, prev=prev, cur=cur, old=old, x=x):
                        poke_b(e, A(0x7A10), prev)
                        poke_b(e, A(0x7A0C), cur)
                        poke_f(e, A(0x7A08), f32(old))
                        poke_f(e, A(0x6350), f32(x))
                    e = run(ROM, 0x036B48, setup)
                    if prev == 0 and cur == 1:
                        want = lk1(0x0AC620, f32(x))
                    elif m_outside(f32(old), 0.0, f32(2.0 ** -11)) and cur == 1:
                        want = m_max(f_sub(f32(old), k230), 0.0)
                    else:
                        want = 0.0
                    check_writes(e, {A(0x7A08): ('f', want), A(0x7A10): ('b', cur)}, 'P6 7A08')
                    n += 1
    av = tbl(ROM, 0x0AC620)[1]
    assert max(av) == 0.30078125 and all(v == 0 for v, ax in zip(av, tbl(ROM, 0x0AC620)[0]['x']) if ax >= 10)
    print(f'    0x036B48: {n} cases. [7A08] = AC620([6350]) on a rising edge of byte 7A0C, then '
          f'max(v - {k230!r}, 0) per call while 7A0C == 1, else 0. AC620 max {max(av)}, 0 for E >= 10')
    # --- [7B44..50]: 0x038C50 / tail 0x038D4C
    k_rpm, k_ld = rd_f(ROM, 0x0CC3A4), rd_f(ROM, 0x0CC3B4)
    m = 0
    for rpm in (0.0, 899.0, 900.0, 3000.0):
        for ld in (0.1, 0.4999, 0.5, 1.5):
            def setup(e, rpm=rpm, ld=ld):
                poke_f(e, A(0x6624), f32(rpm))
                poke_f(e, A(0x63F8), f32(ld))
                for i in range(4):
                    poke_f(e, A(0x31BC + 8 * i), f32(0.01 * (i + 1)))
            e = run(ROM, 0x038C50, setup)
            W = {}
            if k_rpm > f32(rpm) and k_ld > f32(ld):
                k = lk1(0x0AC6FC, f32(rpm))
                W[A(0x7B68)] = ('f', k)
                for i in range(4):
                    W[A(0x7B44 + 4 * i)] = ('f', f_mul(f32(0.01 * (i + 1)), k))
            else:
                for i in range(4):
                    W[A(0x7B44 + 4 * i)] = ('f', 0.0)
            check_writes(e, W, 'P6 7B44')
            m += 1
    print(f'    0x038C50: {m} cases. [7B44+4i] = [31BC+8i]*AC6FC(RPM) only when RPM < {k_rpm} and '
          f'[63F8] < {k_ld}; else 0.0 (tail 0x038D4C)')
    # --- table / scalar facts used by the bound table
    facts = [
        ('[7A14] 0x036BF4 0.3/0.0 and caps', [rd_f(ROM, a) for a in (0x0CC234, 0x0CC238, 0x0CC23C, 0x0CC240,
                                                                     0x0CC244, 0x0CC248, 0x0CC258,
                                                                     0x0CC24C, 0x0CC250, 0x0CC254)]),
        ('[7A20] 0x036E60/0x036E86 values', [rd_f(ROM, a) for a in (0x0CC284, 0x0CC288, 0x0CC28C, 0x0CC290,
                                                                    0x0CC274, 0x0CC278, 0x0CC27C, 0x0CC280)]),
        ('[7BCC] 0x03988E values', [rd_f(ROM, a) for a in (0x0CC404, 0x0CC408, 0x0CC40C, 0x0CC410,
                                                           0x0CC414, 0x0CC418, 0x0CC41C)]),
        ('[7BA8] 0x03952C/0x03961C clamps', [rd_f(ROM, a) for a in (0x0CC3E8, 0x0CC3EC, 0x0CC3F0)]),
        ('[7BE4] 0x039F42 steps', [rd_f(ROM, a) for a in (0x0CC45C, 0x0CC460, 0x0CC464, 0x0CC468, 0x0CC46C,
                                                          0x0CC470, 0x0CC474, 0x0CC478, 0x0CC48C, 0x0CC490,
                                                          0x0CC494)]),
        ('[7A78..84] 0x037710 caps', [rd_f(ROM, a) for a in (0x0CC2C4, 0x0CC2C8, 0x0CC2CC, 0x0CC2D0,
                                                             0x0CC2D4, 0x0CC2D8, 0x0CC2DC, 0x0CC2E0,
                                                             0x0CC2E4, 0x0CC2E8, 0x0CC2EC)]),
    ]
    for nm, v in facts:
        print(f'    {nm}: {v}')
    for a in list(range(0x0CC230, 0x0CC2A0, 4)) + list(range(0x0CC2C4, 0x0CC2F0, 4)) + \
            list(range(0x0CC3A4, 0x0CC3C4, 4)) + list(range(0x0CC3E8, 0x0CC3F4, 4)) + \
            list(range(0x0CC404, 0x0CC420, 4)) + list(range(0x0CC45C, 0x0CC498, 4)):
        assert rd_f(STOCK, a) == rd_f(ROM, a) == rd_f(REV_E, a) or (a in (0x0CC16C, 0x0CC170)), hex(a)
    for rec in (0x0AC620, 0x0AC6FC, 0x0AD7A8, 0x0AC774, 0x0AC788, 0x0AC79C, 0x0AD604, 0x0AD5E8, 0x0AC3E0):
        assert tbl(STOCK, rec) == tbl(ROM, rec) == tbl(REV_E, rec), hex(rec)
    print('    every scalar and record above is identical in stock, 20.19c and 20.19e')
    u32 = lambda a: struct.unpack_from('>I', ROM, a)[0]          # noqa: E731
    assert [u32(a) for a in (0x0CC244, 0x0CC248, 0x0CC258)] == [0x3E999999, 0, 0x3E199999]
    assert [u32(a) for a in (0x0CC284, 0x0CC288, 0x0CC28C, 0x0CC290)] == [0x3DCCCCCC] * 2 + [0x3E4CCCCC] * 2
    assert [u32(a) for a in (0x0CC410, 0x0CC414, 0x0CC418, 0x0CC41C)] == [0x3E199999] * 4
    assert u32(0x0CC3E8) == 0x3CF5C28F and u32(0x0CC3EC) == 0 and u32(0x0CC3F0) == 0
    assert u32(0x0CC490) == 0 and u32(0x0CC494) == 0
    ok(5)
    # [7BE4] target ceiling: AD7A8 max, the other factors max 1.0
    assert max(max(r) for r in tbl(ROM, 0x0AD7A8)[1]) == 0.296875
    assert max(tbl(ROM, 0x0AC774)[1]) == 1.0 and max(tbl(ROM, 0x0AC788)[1]) == 1.0 and max(tbl(ROM, 0x0AC79C)[1]) == 1.0
    # [73A4] tables are zero at E >= 70
    for rec in (0x0AD604, 0x0AD5E8, 0x0AC3E0):
        t = DT.read_table(ROM, rec)
        if t['dim'] == '2D':
            ya = t['axes']['y']
            assert all(v == 0 for plane in t['values'] for v, y in zip(plane, ya) if y >= 70)
        else:
            assert all(v == 0 for v in t['values'])
    print('    [73A4]: AD604 / AD5E8 (definition "Min Primary Base Enrichment 1 Cruise / Non-Cruise") are 0 '
          'for E >= 70; AC3E0 is 0 everywhere')
    ok(3)
    # the four literal-pool sites of 0xFFFF7A44 are followed by an fmov.s @r2 READ
    sites = []
    for pc in range(0, 0xC0000, 2):
        w = struct.unpack_from('>H', ROM, pc)[0]
        if w >> 12 == 0xD:
            t = ((pc + 4) & ~3) + (w & 0xFF) * 4
            if t + 4 <= len(ROM) and struct.unpack_from('>I', ROM, t)[0] == 0xFFFF7A44:
                sites.append(pc)
    descr = []
    for pc in sites:
        n_reg = (struct.unpack_from('>H', ROM, pc)[0] >> 8) & 0xF
        nxt = struct.unpack_from('>H', ROM, pc + 2)[0]
        # fmov.s @Rm,FRn : 1111 nnnn mmmm 1000
        assert nxt >> 12 == 0xF and nxt & 0xF == 0x8 and ((nxt >> 4) & 0xF) == n_reg, hex(pc)
        descr.append(f'{pc:06X}: {nxt:04X}')
    assert [hex(p) for p in sites] == ['0x30082', '0x300b6', '0x33d30', '0x347fe', '0x857c2']
    print(f'    loads of the long 0xFFFF7A44 (all followed by fmov.s @rN,frX, a read): {descr}')
    ok()
    p6_7A14()
    p6_798C_reset()


def p6_7A14():
    """0x036C48 (reached by bra from 0x036C3C, which runner 0x049CF0 calls at 049EBE): [7A1C] counter and
    [7A14] = [7A18] or min([7A18], 0.15). The first version of this file said the [67EC] threshold was
    1250; the code reads word 0x0CBC6E = 624 (1250 is 0x0CBC70, the [7A20] gate in 0x036E86)."""
    for rom in (STOCK, ROM, REV_E):
        assert [rd_h(rom, a) for a in (0x0CBC6A, 0x0CBC6C, 0x0CBC6E, 0x0CBC70)] == [188, 11250, 624, 1250]
    u32 = lambda a: struct.unpack_from('>I', ROM, a)[0]          # noqa: E731
    u16 = lambda a: struct.unpack_from('>H', ROM, a)[0]          # noqa: E731
    assert u32(0x036E34) == 0x0CBC6E and u32(0x036E2C) == 0x0CBC6A and u32(0x036E54) == 0x0CBC6C
    assert u32(0x0370BC) == 0x0CBC70          # 0x036E86's [67EC] gate (036EE6)
    assert u32(0x036E10) == 0xFFFF7374        # 036C68: the CL-side addend [7374] is READ here
    assert (u16(0x036CD6), u16(0x036CD8), u16(0x036CDE)) == (0xD257, 0x6621, 0x3263)
    ok(5)
    thr, cap = rd_h(ROM, 0x0CBC6E), rd_h(ROM, 0x0CBC6A)
    k258 = rd_f(ROM, 0x0CC258)
    eps12 = rd_f(ROM, 0x036E20)
    assert eps12 == 2.0 ** -12
    rnd = random.Random(7414)
    cases = []
    for _ in range(500):
        cases.append(dict(b726C=rnd.choice([0, 0, 1, 2]), b65F6=rnd.choice([0, 0, 1, 2]),
                          b6552=rnd.choice([0, 1, 1, 2]), b6553=rnd.choice([0, 1]),
                          b85D7=rnd.choice([0, 0, 1, 0x80]),
                          c67EC=rnd.choice([0, 623, 624, 625, 1249, 1250, 11250, 65535]),
                          x7374=f32(rnd.choice([0.0, -0.0, 0.0002, 0.000244140625, 0.0003, -0.0003, 0.5, NAN])),
                          c7A1C=rnd.choice([0, 1, 186, 187, 188, 189, 500, 65534, 65535]),
                          x7A18=f32(rnd.choice([0.3, 0.2, 0.15, 0.1, 0.0]))))
    n = 0
    for c in cases:
        def setup(e, c=c):
            poke_b(e, A(0x726C), c['b726C'])
            poke_b(e, A(0x72A1), 0)
            poke_b(e, A(0x65F6), c['b65F6'])
            poke_b(e, A(0x6552), c['b6552'])
            poke_b(e, A(0x6553), c['b6553'])
            poke_b(e, A(0x85D7), c['b85D7'])
            poke_h(e, A(0x67EC), c['c67EC'])
            poke_h(e, A(0x7A1C), c['c7A1C'])
            poke_f(e, A(0x7374), c['x7374'])
            poke_f(e, A(0x7A18), c['x7A18'])
        e = run(ROM, 0x036C48, setup)
        W = {}
        if c['b726C'] != 1 and c['b65F6'] != 1:
            v = min(c['c7A1C'] + 1, 0xFFFF)                       # 0x0BE554 saturating u16 add
            if not m_outside(c['x7374'], 0.0, eps12) and c['b6552'] == 1:
                if not (v >= cap):
                    v = cap                                       # 036CB6-036CBA: max(v, 188)
            W[A(0x7A1C)] = ('w', v)
        if c['c67EC'] >= thr and c['b85D7'] == 0:
            W[A(0x7A14)] = ('f', m_min(c['x7A18'], k258))
        else:
            W[A(0x7A14)] = ('f', c['x7A18'])
        check_writes(e, W, f'P6 036C48 {c}')
        n += 1
    print(f'    0x036C48: {n} cases. [7A14] = min([7A18], {k258!r}) when u16 [67EC] >= {thr} (word 0x0CBC6E) and '
          f'byte [85D7] == 0, else [7A18]; word [7A1C] += 1 (saturating) unless byte [726C] == 1 or byte '
          f'[65F6] == 1, raised to at least {cap} when [7374] is within +-2^-12 of 0 and byte [6552] == 1')


def p6_798C_reset():
    """0x03602A (called by runner 0x04907C at 0491F8): the [798C] reset the first version did not list."""
    n = 0
    for b in (0, 1, 2, 0x81, 0xFF):
        def setup(e, b=b):
            poke_b(e, A(0x65F6), b)
        e = run(ROM, 0x03602A, setup)
        W = {}
        if b == 1:
            for a in (0x798C, 0x7990, 0x7994, 0x7998, 0x799C):
                W[A(a)] = ('f', 0.0)
            W[A(0x79F2)] = ('b', 0)
        check_writes(e, W, f'P6 03602A b={b}')
        n += 1
    assert struct.unpack_from('>I', ROM, 0x036284)[0] == 0xFFFF79F0 and (0xFFFF79F0 - 100) & 0xFFFFFFFF == 0xFFFF798C
    ok()
    print(f'    0x03602A: {n} cases. byte [65F6] == 1 -> [798C] [7990] [7994] [7998] [799C] = 0.0 and byte [79F2] = 0 '
          f'(03603E stores [0xFFFF79F0 - 100] = [798C]); otherwise no write')


# ================================================================ P7 consumer 0x0301E4
IN_0301E4 = [0x7348, 0x7AB4, 0x73A4, 0x7A08, 0x7BC4, 0x76D4, 0x7878, 0x7AE4, 0x730C, 0x7310, 0x7314,
             0x7318, 0x731C, 0x7B6C, 0x7B70, 0x7B74, 0x7B78, 0x733C]


def m_0301E4(I):
    g = lambda a: I[A(a)]          # noqa: E731
    hi = rd_f(ROM, 0x030374)
    lo = g(0x733C)
    X = f_mul(f_add(f_add(g(0x76D4), g(0x7878)), g(0x7AE4)), g(0x7348))
    fr13 = f_mul(X, g(0x730C))
    fr9 = f_mul(g(0x7AB4), X)
    fr12 = g(0x7BC4)
    cyl = []
    for c_, k in ((0x7310, 0x7B6C), (0x7314, 0x7B70), (0x7318, 0x7B74), (0x731C, 0x7B78)):
        cyl.append(f_mul(f_fmac(f_mul(g(c_), fr9), g(k), 0.0), fr12))
    fr14 = f_sub(f_sub(g(0x730C), g(0x73A4)), g(0x7A08))
    W = {}
    W[A(0x7320)] = ('f', m_clamp(f_mul(fr13, fr12), lo, hi))
    W[A(0x7344)] = ('f', m_clamp(fr13, lo, hi))
    W[A(0x7324)] = ('f', m_clamp(f_mul(f_fmac(fr13, g(0x7AB4), 0.0), fr12), lo, hi))
    W[A(0x7338)] = ('f', m_clamp(f_mul(f_fmac(f_mul(g(0x7348), g(0x7AB4)), fr14, 0.0), fr12), lo, hi))
    for i, a in enumerate((0x7328, 0x732C, 0x7330, 0x7334)):
        W[A(a)] = ('f', m_clamp(cyl[i], lo, hi))
    return W


def p7():
    print('P7  consumer 0x0301E4 (tail call of 0x02FF7C after 0x02FFE0)')
    rnd = random.Random(1301)
    for case in range(400):
        I = {}
        for a in IN_0301E4:
            I[A(a)] = f32(rnd.choice([0.0, 1.0, 0.5, 2.0, 1.3359375]) if rnd.random() < 0.3
                          else rnd.uniform(-2, 300))
        I[A(0x733C)] = rnd.choice([0.0, 300.0])
        if case % 9 == 0:
            I[A(0x7348)] = f32(rnd.uniform(1e3, 5e4))
        W = m_0301E4(I)
        e = run(ROM, 0x0301E4, lambda e, I=I: [poke_f(e, a, v) for a, v in I.items()])
        check_writes(e, W, f'P7 case {case}')
        assert e.uninit_reads <= set(I)
    print(f'    400 cases: [7344] = clamp(X*[730C], [733C], 262136), [7320] = clamp(X*[730C]*[7BC4]); '
          f'X = ([76D4]+[7878]+[7AE4])*[7348]; per cylinder [7328+4i] = clamp([7310+4i]*[7AB4]*X*[7B6C+4i]*[7BC4]); '
          f'[7338] uses ([730C] - [73A4] - [7A08]); upper bound {rd_f(ROM, 0x030374)}')


# ================================================================ P8 multi-call runs
def seq_call(e, entry):
    """one more call of entry on the SAME emulator: RAM persists from the previous calls"""
    e.steps = 0
    e.writes = {}
    rr = dict(SENT_R)
    e.gbr = 0xFFFF0ABC
    e.call(entry, regs=rr, fregs=dict(SENT_F))
    for k in range(8, 15):
        assert e.R[k] == rr[k]
    assert e.R[15] == E.STACK_TOP and e.gbr == 0xFFFF0ABC


def m_decay(e0, e4, n_calls, hold, st0, st4):
    """[7400] per call of 0x03110C from the seeds, no transient ([73F0], [73F4] >= 0), [7441] = 0 at the
    start, [7445] = 0, [67EC] >= 13 throughout; written from the 0x03110C listing (031146-0312AA)"""
    out = []
    cnt = 0
    for _ in range(n_calls):
        if not m_outside(e0, 1.0, 2.0 ** -13) and not m_outside(e4, 0.0, 2.0 ** -13):
            out.append(1.0)                     # settled shortcut (03114E-03117C)
            cnt = 0
            continue
        out.append(m_clamp(f_mul(f_add(e0, e4), 1.0), 1.0, 8.0))   # selector 0 path, [7434] = 1.0
        cnt = min(cnt + 1, 255)
        if cnt >= hold:
            e0 = m_max(f_fmac(-st0, 1.0, e0), 1.0)
            e4 = m_max(f_fmac(-st4, 1.0, e4), 0.0)
            cnt = 0
    return out


def p8():
    print('P8  multi-call runs (0x030B68 then 0x030C38 repeatedly on one emulator; RAM persists)')
    st0, st4 = lk1(0x0ACD54, 85.0), lk1(0x0ACD68, 85.0)
    assert lku8(0x0AC430, 0.0) == 15 and lku8(0x0AC430, 85.0) == 15 and lku8(0x0AC430, -20.0) == 8
    # --- seed and decay. (T0 = [6354] at the 0x030B68 call, T1 = [6354] = [6350] from call nT on,
    #     [67EC] = 0 before call n13, 2000 from it on)
    runs = {}
    for tag, T0, T1, nT, n13, N in (('warm', 85.0, 85.0, 0, 0, 760), ('cold', 0.0, 85.0, 100, 0, 3610),
                                     ('reseed', 0.0, 85.0, 100, 150, 200)):
        S = steady_state(85.0, 3000.0, 2.0)
        S[A(0x6354)] = S[A(0x6350)] = f32(T0)
        S[A(0x67EC)] = 0 if n13 else 2000
        e = E.Emu(ROM)
        setup_state(S)(e)
        seq_call(e, 0x030B68)
        seed = (e.read_f32(A(0x73E0)), e.read_f32(A(0x73E4)), e.read_f32(A(0x7400)))
        assert seed[0] == lk1(0x0ACD7C, f32(T0)) and seed[1] == lk1(0x0ACD90, f32(T0))
        hist = []
        for n in range(N):
            if n13 and n == n13:
                e.ram_u16(A(0x67EC), 2000)
            if nT and n == nT:
                e.ram_f32(A(0x6354), T1)
                e.ram_f32(A(0x6350), T1)
            seq_call(e, 0x030C38)
            hist.append(e.read_f32(A(0x7400)))
            assert e.read_f32(A(0x73B4)) == 0.0          # steady [73B0]: no transient
        runs[tag] = (seed, hist)
    seed, hist = runs['warm']
    want = m_decay(seed[0], seed[1], len(hist), 15, st0, st4)
    assert hist == want, 'P8 warm decay differs from the listing model'
    first1 = hist.index(1.0)
    print(f'    warm: seed at [6354] = 85 -> [73E0] {seed[0]} [73E4] {seed[1]}; [7400] = {hist[0]} at call 0, '
          f'{hist[500]:.4f} at 500, first exactly 1.0 at call {first1} (every call matches the model)')
    assert seed[2] == 1.25 and max(hist) == 1.25 and first1 == 750
    seed, hist = runs['cold']
    want = m_decay(seed[0], seed[1], len(hist), 15, st0, st4)
    assert hist == want, 'P8 cold decay differs from the listing model'
    first1 = hist.index(1.0)
    above = max(i for i, v in enumerate(hist) if v > 1.25)
    print(f'    cold: seed at [6354] = 0 -> [7400] = {hist[0]}; [6354] = [6350] = 85 from call 100; [7400] '
          f'{hist[100]:.4f} at 100, {hist[500]:.4f} at 500, {hist[1000]:.4f} at 1000, {hist[3000]:.4f} at 3000; '
          f'> 1.25 until call {above}; first exactly 1.0 at call {first1}')
    assert hist[0] == 4.9501953125 and 4.64 < hist[100] < 4.66 and first1 == 3600 and above >= 2800
    seed, hist = runs['reseed']
    print(f'    re-seed while [67EC] < 13: [7400] {hist[99]} at call 99 ([6354] = 0), {hist[100]} at call 100 '
          f'([6354] = 85): the seed is re-read at the CURRENT [6354] until [67EC] >= 13, then held')
    assert hist[99] == 4.9501953125 and hist[100] == 1.25 and hist[150] == 1.25 and hist[199] < 1.25
    ok(6)
    # --- the settled shortcut is tested BEFORE the [67EC] < 13 re-seed: a settled block is not re-seeded
    for b726C in (0, 1, 2):
        S = steady_state(85.0, 3000.0, 2.0)
        S[A(0x6354)] = 0.0
        S[A(0x67EC)] = 0
        S[A(0x726C)] = b726C
        W = m_030C38(S, ROM)
        e = run(ROM, 0x030C38, setup_state(S))
        check_writes(e, W, f'P8 shortcut precedence 726C={b726C}')
        reseeded = A(0x73E0) in W
        print(f'    settled [73E0] = 1, [73E4] = 0, [67EC] = 0, [6354] = 0, byte [726C] = {b726C}: '
              f'[7400] = {e.read_f32(A(0x7400))}, re-seeded = {reseeded}')
        assert reseeded == (b726C != 0)          # any non-zero [7445] (= [726C]) blocks the shortcut
    # --- two-call response to a one-call [73B0] step, and the T2 tail (warm, [7400] = 1)
    for dl, lo, hi in ((0.2, 95, 100), (0.25, 110, 117)):
        S = steady_state(90.0, 3000.0, 2.0)
        S[A(0x647C)], S[A(0x844F)] = 1, 0
        e = E.Emu(ROM)
        setup_state(S)(e)
        e.ram_f32(A(0x620C), f32((2.0 + dl) * 100.0))
        out = []
        for n in range(200):
            seq_call(e, 0x030C38)
            out.append((e.read_f32(A(0x73B4)), e.read_f32(A(0x73EC)), e.read_f32(A(0x73D8))))
        nz = [i for i, o in enumerate(out) if o[0] != 0.0]
        print(f'    step [73B0] 2.00 -> {2 + dl:.2f} held, E 90, RPM 3000, sel 0: [73B4] '
              f'{out[0][0]:.4f} {out[1][0]:.4f} {out[2][0]:.4f} ([73EC] {out[0][1]:.2f} {out[1][1]:.2f} '
              f'{out[2][1]:.2f}); non-zero on calls 0..{nz[-1]} ({len(nz)} calls, T2 tail)')
        assert abs(out[0][1] - dl) < 1e-5 and abs(out[1][1] - dl) < 1e-5
        assert out[2][1] == 0.0 and out[0][0] > 0.05 and out[1][0] > 0.05 and out[2][0] < 0.006
        assert nz == list(range(len(nz))) and lo <= len(nz) <= hi
        ok(3)
    # --- a ramp of +0.02 per call for 60 calls: [73EC] never leaves its deadband, T2 alone is non-zero
    S = steady_state(90.0, 3000.0, 2.0)
    S[A(0x647C)], S[A(0x844F)] = 1, 0
    e = E.Emu(ROM)
    setup_state(S)(e)
    b = 2.0
    mx = [0.0, 0.0]
    for n in range(200):
        if n < 60:
            b += 0.02
        e.ram_f32(A(0x620C), f32(b * 100.0))
        seq_call(e, 0x030C38)
        assert e.read_f32(A(0x73EC)) == 0.0
        mx[0] = max(mx[0], e.read_f32(A(0x73B4)))
        mx[1] = max(mx[1], e.read_f32(A(0x73D8)))
    print(f'    ramp +0.02 per call x 60 (E 90, RPM 3000): [73EC] = 0 on every call, max [73D8] {mx[1]:.3f}, '
          f'max [73B4] {mx[0]:.4f} (T2 only)')
    assert 0.015 < mx[0] < 0.017 and 0.79 < mx[1] < 0.82
    ok(2)


# ================================================================ P9 call sites and the reader 0x032CE8
def p9():
    print('P9  call-site facts (fn_dump) and the [73B4] reader 0x032CE8')
    import re
    import subprocess

    def dump(entry):
        return subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'mapping', 'fn_dump.py'),
                               f'0x{entry:06X}'], capture_output=True, text=True, check=True).stdout

    facts = {
        0x04AA58: [('04AAC2', '0x03043A'), ('04AAC8', '0x030754'), ('04AACE', '0x030C38'),
                   ('04AADA', '0x03606C'), ('04AAE0', '0x036AAE'), ('04AAE6', '0x039524'),
                   ('04AAF2', '0x038E64'), ('04AAFE', '0x038178'), ('04AB04', '0x038932'),
                   ('04AB0A', '0x039860'), ('04AB10', '0x039E16'), ('04AB16', '0x02FF7C')],
        0x049CF0: [('049EB8', '0x030ACC'), ('049EBE', '0x036C3C')],
        0x04A6FA: [('04A740', '0x036C40')],
        0x04A674: [('04A692', '0x036E86')],
        0x047C40: [('047EF8', '0x02FF74'), ('047F28', '0x030B68'), ('047F6A', '0x036BF4'), ('047F70', '0x036E60'),
                   ('047F94', '0x038E30')],
        0x04907C: [('0491F8', '0x03602A'), ('049216', '0x03816E'), ('049222', '0x039864'), ('049228', '0x039E0C'),
                   ('04925E', '0x030BCA')],
        0x04AED4: [('04AF02', '0x03757A')],
        0x04AF12: [('04AF40', '0x03757A')],
    }
    for entry, sites in facts.items():
        txt = dump(entry)
        for pc, tgt in sites:
            line = [ln for ln in txt.splitlines() if ln.startswith(pc + ': 420B  jsr')]
            assert line and ('-> ' + tgt) in line[0], (hex(entry), pc, tgt)
            ok()
    for entry, pc, word, tgt in ((0x036C3C, '036C3C', 'A004', 'bra 0x036C48'), (0x036C40, '036C40', 'A068', 'bra 0x036D14'),
                                 (0x039E0C, '039E0E', 'B007', 'bsr 0x039E20'), (0x039E16, '039E1C', 'A091', 'bra 0x039F42'),
                                 (0x03757A, '03757A', 'A01D', 'bra 0x0375B8'), (0x0375B8, '0375FA', 'A089', 'bra 0x037710'),
                                 (0x039864, '039864', 'A075', 'bra 0x039952'), (0x03816E, '038170', 'B376', 'bsr 0x038860'),
                                 (0x038E30, '038E32', 'B237', 'bsr 0x0392A4'), (0x0392A4, '0392B2', 'B007', 'bsr 0x0392C4')):
        txt = dump(entry)
        assert re.search(rf'^{pc}: {word}  {re.escape(tgt)}', txt, re.M), (pc, tgt)
        ok()
    print('    0x04AA58 calls 0x03043A 0x030754 0x030C38 0x03606C 0x036AAE 0x039524 0x038E64 0x038178 0x038932 '
          '0x039860 0x039E16 before 0x02FF7C (04AB16); NOT from 0x04AA58: 0x030ACC [73A4] and 0x036C48 [7A14] '
          '(0x049CF0), 0x036D14 [7A18] (0x04A6FA), 0x036E86 [7A20] (0x04A674), 0x036BF4 0x036E60 0x030B68 '
          '(0x047C40), 0x03602A [798C] 0x039E20 [7BE4] 0x030BCA (0x04907C), 0x037710 [7A78..] (0x04AED4/0x04AF12); '
          'resets 0x038860 [7AF4] and 0x039952 [7BCC] (0x04907C), 0x0392C4 [7B8C] via 0x0392A4 (0x047C40)')
    # 0x032CE8 reads [73B4] (032CF0/032CF2), [73E0], [73E4], [6350], [6354]; may reload word [77B0]
    assert struct.unpack_from('>I', ROM, 0x032EEC)[0] == 0xFFFF73B4
    assert struct.unpack_from('>HH', ROM, 0x032CF0) == (0xD27E, 0xF828)
    c = {a: rd_f(ROM, a) for a in (0x0CBEE4, 0x0CBEE8, 0x0CBEEC, 0x0CBEF0, 0x0CBEF4, 0x0CBEF8, 0x0CBEFC)}
    rel = rd_h(ROM, 0x0CBC2E)
    assert rel == 1250
    rnd = random.Random(3228)
    n = 0
    hits = 0
    for _ in range(400):
        I = {A(0x73B4): f32(rnd.choice([-0.1, -0.0999, 0.0, 0.0499, 0.05, 0.3, -1.0, NAN]) if rnd.random() < 0.5
                            else rnd.uniform(-0.3, 0.3)),
             A(0x73E0): f32(rnd.choice([1.0, 1.25, 0.5, -2.0])), A(0x73E4): f32(rnd.choice([0.0, 2.75, -1.0])),
             A(0x6350): f32(rnd.choice([-41.0, -40.0, 0.0, 90.0, 118.9, 119.0])),
             A(0x6354): f32(rnd.choice([-41.0, -40.0, 0.0, 90.0, 118.9, 119.0]))}
        w77 = rnd.choice([0, 1, 1250, 0x8000])

        def setup(e, I=I, w77=w77):
            for a, v in I.items():
                poke_f(e, a, v)
            poke_h(e, A(0x77B0), w77)
        e = run(ROM, 0x032CE8, setup)
        W = {}
        x = I[A(0x73B4)]
        if not (x > c[0x0CBEF8] and c[0x0CBEFC] > x):
            W[A(0x77B0)] = ('w', rel)
            w77 = rel
        s = f_add(I[A(0x73E0)], I[A(0x73E4)])
        r0 = int(not (c[0x0CBEE4] > s) and not (c[0x0CBEE8] > I[A(0x6350)]) and (c[0x0CBEEC] > I[A(0x6350)])
                 and not (c[0x0CBEF0] > I[A(0x6354)]) and (c[0x0CBEF4] > I[A(0x6354)]) and (w77 & 0xFFFF) > 0)
        check_writes(e, W, 'P9 032CE8')
        assert e.R[0] == r0, (I, w77, e.R[0], r0)
        hits += r0
        n += 1
    print(f'    0x032CE8: {n} cases ({hits} returning 1). word [77B0] = {rel} unless {c[0x0CBEF8]:.7g} < [73B4] < '
          f'{c[0x0CBEFC]:.7g}; r0 = 1 iff [73E0]+[73E4] >= {c[0x0CBEE4]}, {c[0x0CBEE8]} <= [6350] < {c[0x0CBEEC]}, '
          f'{c[0x0CBEF0]} <= [6354] < {c[0x0CBEF4]} and word [77B0] != 0')


# ================================================================ P10 independent audit (2026-11-27)
def audit_state(x=90.0, rpm=3000.0, b=2.0, sel0=True, b844F=0, e0=1.0, e4=0.0, c67EC=2000, latch=0,
                cnt=0, t6354=None):
    """the audit's own starting state (not steady_state): latch CLEAR, optional live seed / counter"""
    S = {}
    for a, v in ((0x6350, x), (0x6624, rpm), (0x63F8, 1.0), (0x620C, b * 100.0),
                 (0x6354, x if t6354 is None else t6354), (0x7408, b), (0x740C, b), (0x7410, b),
                 (0x73D0, b), (0x73D4, b), (0x73D8, 0.0), (0x73DC, 0.0), (0x73E0, e0), (0x73E4, e4)):
        S[A(a)] = f32(v)
    for a, v in ((0x67FC, 0), (0x61F4, 0), (0x6254, 1), (0x65C0, 1), (0x647C, 1 if sel0 else 0),
                 (0x844F, b844F), (0x726C, 0), (0x641C, 0), (0x7C9D, 0), (0x7C9A, 0), (0x3158, 0),
                 (0x7441, cnt), (0x7446, latch)):
        S[A(a)] = v
    S[A(0x67EC)] = c67EC
    S[A(0x7442)] = 0
    return S


def snapshot(e):
    """the 0x030C38 input set as it stands in a running emulator (for a model cross-check of one call)"""
    S = {}
    for a in F_IN:
        S[A(a)] = e.read_f32(A(a))
    for a in B_IN:
        S[A(a)] = e.read_u8(A(a))
    for a in H_IN:
        S[A(a)] = e.read_u16(A(a))
    return S


def course(rom, S, seq):
    e = E.Emu(rom)
    setup_state(S)(e)
    out = []
    for b in seq:
        e.ram_f32(A(0x620C), f32(b * 100.0))
        pre = snapshot(e)
        seq_call(e, 0x030C38)
        out.append(dict(pre=pre, b0=e.read_f32(A(0x73B0)), b4=e.read_f32(A(0x73B4)), ec=e.read_f32(A(0x73EC)),
                        d8=e.read_f32(A(0x73D8)), d0=e.read_f32(A(0x73D0)), d4=e.read_f32(A(0x73D4))))
    return out


def p10():
    print('P10 independent audit: paths and consumers the earlier passes did not exercise')
    # (a) lift then tip-in: 0x0312DE snaps [73D0] = [73D4] = [740C] when the PREVIOUS [73D8] < 0 and
    #     [73EC] >= 0.975 (0313F4-03141E). Compared against an in-memory copy with 0x0CBE5C = 1000.0, on
    #     which the snap cannot happen.
    nosnap = bytearray(ROM)
    nosnap[0x0CBE5C:0x0CBE60] = struct.pack('>f', 1000.0)
    nosnap = bytes(nosnap)
    for x in (90.0, 70.0):
        for hold, lo, hi in ((8, 1.5, 2.6), (4, 1.0, 2.2)):
            seq = [2.0] * 3 + [lo] * hold + [hi] * 300
            k = 3 + hold
            a = course(ROM, audit_state(x), seq)
            b = course(nosnap, audit_state(x), seq)
            assert a[k - 1]['d8'] < 0 and a[k]['ec'] >= 0.975
            assert a[k]['d0'] == a[k - 1]['b0'] and a[k]['d4'] == a[k - 1]['b0']      # snap to the previous [73B0]
            assert b[k]['d0'] != b[k - 1]['b0']                                     # copy: filter path
            W = m_030C38(a[k]['pre'], ROM)                                          # model of the snap call
            e = run(ROM, 0x030C38, setup_state(a[k]['pre']))
            check_writes(e, W, f'P10 snap call E={x} hold={hold}')
            sa, sb = sum(r['b4'] for r in a[k:]), sum(r['b4'] for r in b[k:])
            na, nb = sum(1 for r in a[k:] if r['b4']), sum(1 for r in b[k:] if r['b4'])
            print(f'    E {x:g}, [73B0] 2.0 -> {lo} for {hold} calls -> {hi}: [73EC] {a[k]["ec"]:.3f}, previous '
                  f'[73D8] {a[k - 1]["d8"]:+.3f}; snap: [73D8] {a[k]["d8"]:.4f}, [73B4] {a[k]["b4"]:.4f} '
                  f'{a[k + 1]["b4"]:.4f} {a[k + 2]["b4"]:.4f}, sum {sa:.3f} over {na} calls; no-snap copy: [73D8] '
                  f'{b[k]["d8"]:.4f}, [73B4] {b[k]["b4"]:.4f} {b[k + 1]["b4"]:.4f} {b[k + 2]["b4"]:.4f}, sum {sb:.3f} '
                  f'over {nb} calls')
            assert a[k]['d8'] > b[k]['d8'] + 0.25 and sa > sb and na > nb and a[k + 2]['b4'] > b[k + 2]['b4']
            ok(4)
    # (b) mixed sign: a positive [73EC] while [73D8] < 0 makes [73F4] < 0, so [7400] = 1.0 (0311F4-03123E)
    #     although the seed [73E0] is still above 1: the positive T1 is NOT multiplied by the seed.
    e = E.Emu(ROM)
    setup_state(audit_state(e0=1.25))(e)
    for b in [2.0] * 2 + [1.0] * 3 + [1.3]:
        e.ram_f32(A(0x620C), f32(b * 100.0))
        seq_call(e, 0x030C38)
    r = {a: e.read_f32(A(a)) for a in (0x73EC, 0x73D8, 0x73F0, 0x73F4, 0x73E0, 0x7400, 0x73B4)}
    print(f'    mixed sign: [73EC] {r[0x73EC]:+.3f} [73D8] {r[0x73D8]:+.4f} [73F0] {r[0x73F0]:+.4f} [73F4] '
          f'{r[0x73F4]:+.4f}; seed [73E0] {r[0x73E0]} yet [7400] = {r[0x7400]}; [73B4] {r[0x73B4]:+.5f}')
    assert r[0x73EC] > 0 and r[0x73F4] < 0 and r[0x73E0] > 1.0 and r[0x7400] == 1.0 and r[0x73B4] > 0
    ok()
    # (c) [67EC] < 13: the re-seed path (03118A-0311F2) does NOT test [73F0] / [73F4]: [7400] = M(seed) on a
    #     falling call. [73B4] is 0 there anyway (gate threshold 25 / 625). At 13 the same state gives 1.0.
    e = E.Emu(ROM)
    setup_state(audit_state(e0=1.25))(e)
    for b in (2.0, 2.0, 1.5):
        e.ram_f32(A(0x620C), f32(b * 100.0))
        seq_call(e, 0x030C38)
    e.ram_u16(A(0x67EC), 5)
    e.ram_f32(A(0x620C), f32(100.0))
    seq_call(e, 0x030C38)
    r5 = (e.read_f32(A(0x73F0)), e.read_f32(A(0x7400)), e.read_f32(A(0x73B4)))
    e.ram_u16(A(0x67EC), 13)
    e.ram_f32(A(0x620C), f32(50.0))
    seq_call(e, 0x030C38)
    r13 = (e.read_f32(A(0x73F0)), e.read_f32(A(0x7400)))
    print(f'    [67EC] = 5, falling ([73F0] {r5[0]:+.4f}): [7400] {r5[1]} (= the seed), [73B4] {r5[2]}; '
          f'[67EC] = 13, falling ([73F0] {r13[0]:+.4f}): [7400] {r13[1]}')
    assert r5[0] < 0 and r5[1] == 1.25 and r5[2] == 0.0 and r13[0] < 0 and r13[1] == 1.0
    ok()
    # (d) 0x030B68 leaves the decay counter [7441] alone: the decay course depends on its value at the seed.
    #     Selector 2 ([647C] != 1) and byte [3158] = 1 give the same course as selector 0 (the [7434] and
    #     alternate seed tables are identical in 20.19c).
    def decay(sel0, b3158=0, cnt=0, n=760):
        S = audit_state(sel0=sel0, t6354=85.0, cnt=cnt)
        S[A(0x3158)] = b3158
        e = E.Emu(ROM)
        setup_state(S)(e)
        seq_call(e, 0x030B68)
        h = []
        for _ in range(n):
            seq_call(e, 0x030C38)
            h.append(e.read_f32(A(0x7400)))
        return h
    h0, h10 = decay(True), decay(True, cnt=10)
    h2, h3 = decay(False, n=200), decay(False, 1, n=200)
    print(f'    [7441] = 0 at the seed: first [7400] = 1.0 at call {h0.index(1.0)}; [7441] = 10: call '
          f'{h10.index(1.0)}; selector 2 and byte [3158] = 1 match selector 0 over 200 calls')
    assert h0.index(1.0) == 750 and h10.index(1.0) == 740 and h2 == h3 == h0[:200]
    ok(2)
    # (d2) the seed is held whatever [6354] does, but the decay INTERVAL is the hold count 0x0AC430 at the
    #      CURRENT [6354] (031240-03125E): seed at [6354] = 0 (4.9502), then [6354] = [6350] = -30 from call 100
    S = audit_state(t6354=0.0)
    e = E.Emu(ROM)
    setup_state(S)(e)
    seq_call(e, 0x030B68)
    h = []
    for n in range(2000):
        if n == 100:
            e.ram_f32(A(0x6354), -30.0)
            e.ram_f32(A(0x6350), -30.0)
        seq_call(e, 0x030C38)
        h.append(e.read_f32(A(0x7400)))
    above = max(i for i, v in enumerate(h) if v > 1.25)
    print(f'    seed 4.9502 at [6354] = 0, then [6354] = -30 from call 100 (hold count {lku8(0x0AC430, -30.0)}): '
          f'[7400] {h[100]:.4f} at call 100, > 1.25 until call {above}, first 1.0 at call {h.index(1.0)} '
          f'(3600 when [6354] stays >= 0)')
    assert h[0] == 4.9501953125 and lku8(0x0AC430, -30.0) == 8 and above == 1564 and h.index(1.0) == 1965
    ok()
    # (e) 0x01FE46 (runner 0x04AA58 at 04AA80, BEFORE 0x030C38 at 04AACE) reads [73D0] at 01FE8E and sets
    #     byte [641C] = [641A] = 1 only when [73D0] >= [6404] = 0x0AAE64(RPM) (speed [65FC] >= 50) or
    #     0x0AAE78(RPM) (= 32.0, below 50), with the other gates open (01FF68-01FFE8). [641C] is the byte that
    #     sets [733C] = 0.0 (0x02FF8E) and adds the RPM factors [741C] / [7428] in 0x030F02.
    def fe46(d0, spd=60.0, rpm=5000.0, ect=90.0, tp=40.0, x62E4=-10.0, b65C0=1, b641C=0, b641B=0):
        e = E.Emu(ROM)
        for a, v in ((0x641C, b641C), (0x641B, b641B), (0x65C5, 0), (0x641A, 0)):
            poke_b(e, A(a), v)
        for off, v in ((4, ect), (8, tp), (12, d0)):
            poke_f(e, E.STACK_TOP + off, f32(v))
        e.gbr = 0xFFFF63B4
        assert e.call(0x01FF68, regs={12: 0, 13: 0, 14: b65C0}, fregs={15: spd, 12: rpm, 13: x62E4},
                      stop_at=(0x020012,)) == 0x020012
        return e.read_u8(A(0x641C)), e.read_u8(A(0x641A)), e.read_f32(A(0x6404))
    th = lk1(0x0AAE64, 5000.0)
    hi_, lo_ = fe46(th + 0.5), fe46(th - 0.5)
    keep = fe46(th - 0.5, b641C=1, b641B=1)
    slow = fe46(th + 0.5, spd=40.0)
    cold = fe46(th + 0.5, ect=60.0)
    print(f'    0x01FE46 tail: [6404] = {hi_[2]} at RPM 5000, speed >= 50; [73D0] = {th + 0.5} -> [641C] {hi_[0]}, '
          f'{th - 0.5} -> {lo_[0]} (held at 1 when already set and byte [641B] != 0: {keep[0]}); speed 40 -> '
          f'threshold {slow[2]:.4f}, [641C] {slow[0]}; [6350] 60 -> [641C] {cold[0]}')
    assert hi_[:2] == (1, 1) and lo_[:2] == (0, 0) and keep[0] == 1 and slow[0] == 0 and cold[0] == 0
    assert th == 10.0 and abs(slow[2] - 32.0) < 0.001
    for rom in (STOCK, REV_E):
        assert all(rom[a] == ROM[a] for a in range(0x0C3138, 0x0C3154)) and rom[0x0C302F] == ROM[0x0C302F]
        assert DT.read_table(rom, 0x0AAE64) == DT.read_table(ROM, 0x0AAE64)
        assert DT.read_table(rom, 0x0AAE78) == DT.read_table(ROM, 0x0AAE78)
    ok(3)
    # (f) 0x02FFE0: the CL-side addends (here [7374]) are inside max(OL, CL); [73B4] is outside it.
    def s730C(vals):
        I = {A(a): 0.0 for a in IN_02FFE0}
        I[A(0x7340)] = 1.0
        I.update({A(a): f32(v) for a, v in vals.items()})
        e = run(ROM, 0x02FFE0, lambda em: [poke_f(em, a, v) for a, v in I.items()])
        return e.read_f32(A(0x730C))
    s = [s730C({0x798C: 0.4}), s730C({0x798C: 0.4, 0x7374: 0.1}), s730C({0x798C: 0.4, 0x7374: 0.5}),
         s730C({0x798C: 0.4, 0x7374: 0.1, 0x73B4: 0.08})]
    print(f'    [798C] 0.4: [730C] = {s[0]} with [7374] 0, {s[1]} with 0.1, {s[2]} with 0.5; with [73B4] 0.08 '
          f'and [7374] 0.1: {s[3]}')
    assert s[0] == s[1] == f32(1.4) and abs(s[2] - 1.5) < 1e-6 and abs(s[3] - 1.48) < 1e-6
    ok()
    # (g) no upper bound, cold: E 40, selector 2 with [844F] = 1, seed at [6354] = 0, step 1.0 -> 3.0
    e = E.Emu(ROM)
    setup_state(audit_state(40.0, b=1.0, sel0=False, b844F=1, t6354=0.0))(e)
    seq_call(e, 0x030B68)
    e.ram_f32(A(0x620C), f32(300.0))
    seq_call(e, 0x030C38)
    v = (e.read_f32(A(0x7400)), e.read_f32(A(0x73D8)), e.read_f32(A(0x73B4)))
    print(f'    cold E 40, 844F plane, [6354] = 0 seed: [7400] {v[0]}, [73D8] {v[1]:.4f}, [73B4] {v[2]:.4f}')
    assert v[0] == 4.9501953125 and 15.9 < v[2] < 16.0
    ok()


def main():
    p1()
    p2()
    p3()
    p4()
    p5()
    p6()
    p7()
    p8()
    p9()
    p10()
    print(f'PASS  {CHECKS} checks')
    return 0


if __name__ == '__main__':
    sys.exit(main())
