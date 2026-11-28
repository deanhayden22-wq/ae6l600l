#!/usr/bin/env python3
"""emu_afl_learning.py -- emulation evidence for disassembly/analysis/afl_learning_trace.txt

How does A/F learning (AFL) learn?  This script runs, in scripts/sh2e_emu.py, the ROM code of the AFL
block called from 0x049CF0 -- 0x03452A and every function it calls -- plus the start-up validators of the
AFL cells and the second reader of [0xFFFF7484], 0x06847E, and compares each result with a MODEL written
here from the byte reading in the analysis file.

    python3 scripts/trace/emu_afl_learning.py        # prints tables, asserts, exit 0

Reference image: rom/AE5L600L 20g rev 20.19c.bin (md5 92cae8275cd4f9b473a3a9e36efe6449).
Deterministic (fixed seed).  Stock (rom/ae5l600l.bin) and 20.19e are read in section Z only.

  A  0x034D52  cell index [787F] and window flag [78A5] from [63C4]: every range edge +- 1 ulp, x [78A0]
  B  0x034B1C  [7878] update (snap / lag / two clamps) and the lag-in-progress byte [7885]; convergence run
  C  0x034884  one call vs model over random states (every written byte, the cell record, check words)
  D  0x034884 + 0x034B1C sequences: step every 41 calls (mode 1) / 17 calls (mode 0); vote thresholds;
     clamp; window aborts; the 63-call [78A9] gate; [78A0] hold; [77C8] near zero; what-if Limits edit
  E  0x0345A4  [78A3] and [7883]: all-pass base, every condition flipped at its edge, random
  F  0x034778  [78A4], [78AA] hysteresis, [7884]: base, edges, random
  G  0x03452A  whole (every callee from ROM) vs the composed models, random; end-to-end learning run
  H  0x0344BA / 0x0344EE / 0x034488  cell clear, cell validation (tamper tests), [7878] init
  I  0x034DD6 / 0x034DA6 / 0x034C54 / 0x034C18 / 0x034CEE / 0x034D2E / 0x034CC8  the counters
  J  0x06847E  vs model (random + edges) and its only caller 0x068304 run whole (arguments captured)
  K  review cases: K1 [77C8] NaN / inf / +-2^-13 (C11); K2 what 0x0344EE accepts (C32); K3 window states
     not produced by a reset, zero-filled bytes, 24,000-pass random walk (C42); K4 0x034488 with [787F] >= 4;
     K5 0x01FE46 run whole: the writer of [63FC]; K6 0x04793C: every failed check sets [5B8D] = 1;
     K7 cell values that freeze (G3 can never pass)
  L  independent audit: L1 a mid-window airflow-range change (whole passes): the window is NOT restarted while
     G3 holds, so the votes go to the cell current at the decision pass; L2 [65F6] = 1 in a whole pass gives
     [78A9] = 0; L3 the second call path of 0x048732 (cell clear): 0x047C40 calls it iff word [36BE] == 0x4055
     and byte [8EDC] == 0, 0x05D070 writes 0x4055, 0x05D032 writes 0xAA55; L4 the other readers of [7878]
     (0x02782C, 0x071AFA, 0x0A86FE, 0x05D2DA) against models; L5 the [6254] writer 0x01DA98
  Z  stock vs 20.19c vs 20.19e: code / struct / table bytes; the calibration scalars; 0x034D52 per bin

Stubs (each is an assumption, so each is stated):
  0x00317C / 0x003190   SR mask enter / leave used inside 0x0BDBCC / 0x0BDCB6 (emulator raises on ldc sr)
  0x0278D2              (section I only) the predicate of 0x034D2E, not decoded here: r0 forced 0 / 1 / 2
  0x03AB20, 0x06847E    (section J2 only) callee of 0x068304 not decoded / argument capture
  K6 only: the 25 checks 0x004BEC .. 0x02C034 called by 0x04793C (r0 forced 0, or 1 for the one under test)
           and its untested calls 0x05B5D8 0x05B690 0x0951F8 0x05B73C 0x05CB1C 0x087074 0x05940A 0x01CB1C
           0x004BCA (r0 = 0); 0x0BDBCC / 0x0BDCB6 / 0x0BE9A0 / 0x0BE980 / 0x01001C run from ROM.
  K5 runs 0x01FE46 with uninitialised RAM allowed (only the [63FC] store is asserted).
  L3 only: every callee of 0x047C40 before 0x047DAA (and on its [8EDC] != 0 arms before 0x0486E0) returns r0 = 0,
           0x006BC4 returns 0 / 2 / 0xFF, 0x048732 is captured (not run); 0x05D032's callees 0x08707C 0x097514
           0x0662C4 return r0 = 0.  Whether the real 0x00FACA returns is not established (it is reached only when
           bit 1 of 0x006BC4(17) is clear at both tests; with it set, 0x047D4E branches straight to 0x047D9C).
Everything else -- 0x022F92, 0x029BA4, 0x0297F4, 0x029804, 0x029824, 0x0582AC, 0x0BE53C, 0x0BE554,
0x0BE56C, 0x0BE608, 0x0BEAB0, 0x0BEA40, 0x0BE874, 0x0BE8AC, 0x0BDBCC, 0x0BDCB6, and in L 0x0BE960, 0x0BE970,
0x0BE5A8 -- runs from ROM.
"""
import hashlib
import math
import os
import random
import struct
import sys
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, os.path.join(REPO, 'scripts'))
import sh2e_emu as E          # noqa: E402
import desc_types as DT       # noqa: E402

ROM_PATH = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
STOCK_PATH = os.path.join(REPO, 'rom', 'ae5l600l.bin')
R19E_PATH = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19e.bin')
ROM = open(ROM_PATH, 'rb').read()
RNG = random.Random(20261127)
NCHECK = 0
STEPS = 0


def check(cond, msg):
    global NCHECK
    NCHECK += 1
    if not cond:
        raise AssertionError(msg)


def say(*a):
    print(*a)


# ------------------------------------------------------------------ float model (exact, then truncated)
def F(x):
    return E.b2f(E.f2b(x))


def _rz(exact, fallback):
    if not math.isfinite(fallback) or fallback == 0.0:
        q = exact() if math.isfinite(fallback) else None
        if q is None or q == 0:
            return F(fallback)
        return E.b2f(E.rz_bits(q))
    q = exact()
    return E.b2f(E.rz_bits(q)) if q != 0 else F(fallback)


def _fin(*v):
    return all(math.isfinite(x) for x in v)


def fadd(a, b):
    return _rz(lambda: Fraction(a) + Fraction(b), a + b) if _fin(a, b) else F(a + b)


def fsub(a, b):
    return _rz(lambda: Fraction(a) - Fraction(b), a - b) if _fin(a, b) else F(a - b)


def fdiv(a, b):
    if b == 0.0:
        return math.nan if (a == 0 or a != a) else math.copysign(math.inf, a) * math.copysign(1, b)
    return _rz(lambda: Fraction(a) / Fraction(b), a / b) if _fin(a, b) else F(a / b)


def fmac(f0, fm, fn):
    if _fin(f0, fm, fn):
        return _rz(lambda: Fraction(f0) * Fraction(fm) + Fraction(fn), f0 * fm + fn)
    return F(f0 * fm + fn)


def up1(x):
    b = E.f2b(x)
    return E.b2f(b + 1) if x >= 0 else E.b2f(b - 1)


def dn1(x):
    b = E.f2b(x)
    if x == 0:
        return -E.b2f(1)
    return E.b2f(b - 1) if x > 0 else E.b2f(b + 1)


# verified runtime-library contracts (helpers_*_trace.txt), as models
def clamp(x, lo, hi):                       # 0x0BE56C
    if not (x > lo):
        return lo
    if hi > x:
        return x
    return hi


def outside(x, c, w):                       # 0x0BE608
    if fsub(c, w) > x:
        return 1
    if x > fadd(c, w):
        return 1
    return 0


def absdiff(a, b):                          # 0x0BEAB0
    return abs(fsub(a, b))


def lag(A, B, k, eps):                      # 0x0BEA40
    if (E.f2b(B) & 0x7F800000) == 0x7F800000:
        return A
    d = fsub(B, A)
    r = fmac(fsub(1.0, k), d, A)
    if eps > abs(fsub(A, r)):
        return A
    return r


def s8(v):
    v &= 0xFF
    return v - 256 if v & 0x80 else v


def ck(bits):                               # REC8 check word (helpers_desc_read_trace.txt, 0x0BDBCC)
    hi, lo = bits >> 16, bits & 0xFFFF
    sx = lambda v: v - 0x10000 if v & 0x8000 else v   # noqa: E731
    return (~(sx(hi) + sx(lo))) & 0xFFFF


# ------------------------------------------------------------------ calibration
def cb(a, rom=ROM):
    return rom[a]


def cw(a, rom=ROM):
    return struct.unpack('>H', rom[a:a + 2])[0]


def cf(a, rom=ROM):
    return struct.unpack('>f', rom[a:a + 4])[0]


class Cal:
    def __init__(self, rom):
        g = lambda a: cf(a, rom)            # noqa: E731
        self.B = {a: rom[a] for a in range(0xCBBE4, 0xCBBEF)}
        self.W = {a: cw(a, rom) for a in (0xCBC40, 0xCBC42, 0xCBC44, 0xCBC46)}
        self.Fl = {a: g(a) for a in range(0xCC020, 0xCC094, 4)}
        self.J = {a: g(a) for a in (0xC5164, 0xC517C)}

    def __getitem__(self, a):
        for d in (self.B, self.W, self.Fl, self.J):
            if a in d:
                return d[a]
        raise KeyError(hex(a))


C = Cal(ROM)

# ------------------------------------------------------------------ RAM map used here
CELLS = 0xFFFF316C            # four REC8 records, stride 8 (struct 0x063A5C +24)
A7878, A787F, A78A0, A78A1, A78A3 = 0xFFFF7878, 0xFFFF787F, 0xFFFF78A0, 0xFFFF78A1, 0xFFFF78A3
A78A4, A78A5, A78A6, A78A9, A78AA = 0xFFFF78A4, 0xFFFF78A5, 0xFFFF78A6, 0xFFFF78A9, 0xFFFF78AA
A7881, A7882, A7883, A7884, A7885 = 0xFFFF7881, 0xFFFF7882, 0xFFFF7883, 0xFFFF7884, 0xFFFF7885
A78A7, A78A8 = 0xFFFF78A7, 0xFFFF78A8


def put(e, a, kind, v):
    if kind == 'u8':
        e.ram_u8(a, v & 0xFF)
    elif kind == 'u16':
        e.ram_u16(a, v & 0xFFFF)
    elif kind == 'u32':
        e.ram_u32(a, v & 0xFFFFFFFF)
    elif kind == 'f32':
        e.ram_f32(a, v)
    elif kind == 'rec':
        b = E.f2b(v)
        e.ram_u32(a, b)
        e.ram_u16(a + 4, ck(b))
        e.ram_u16(a + 6, ck(b))
    else:
        raise ValueError(kind)


def new_emu(rom=ROM):
    e = E.Emu(rom)
    e.stub(0x00317C, r0=0)
    e.stub(0x003190)
    return e


def run(entry, ram, regs=None, fregs=None, rom=ROM, e=None, stubs=None, allow_uninit=()):
    global STEPS
    if e is None:
        e = new_emu(rom)
    for k, v in (stubs or {}).items():
        e.stub(k, **v)
    for a, kind, v in ram:
        put(e, a, kind, v)
    e.writes = {}
    e.uninit_reads = set()
    e.steps = 0
    e.call(entry, regs=regs, fregs=fregs)
    STEPS += e.steps
    bad = {a for a in e.uninit_reads if a not in allow_uninit}
    check(not bad, f'{entry:06X}: uninitialised reads {sorted(hex(x) for x in bad)}')
    return e


def written(e):
    return set(e.writes)


def span(a, n):
    return set(range(a, a + n))


def rec_ok(e, a):
    b = e.read_u32(a)
    return e.read_u16(a + 4) == ck(b) and e.read_u16(a + 6) == ck(b)


def rand_f(lo, hi):
    return F(RNG.uniform(lo, hi))


# ================================================================== models
def m_034D52(x, a0, c=C):
    if a0 == 1:                                     # 034D5A cmp/eq #1 on the sign-extended byte
        return 0, 0
    flag = 1 if (not (c[0xCC070] > x)) and (c[0xCC080] > x) else 0
    if c[0xCC074] > x:
        idx = 0
    elif c[0xCC078] > x:
        idx = 1
    elif not (c[0xCC07C] > x):
        idx = 3
    else:
        idx = 2
    return flag, idx


def m_034B1C(cell, afl, a0, c=C):
    d = absdiff(afl, cell)
    if c[0xCC060] > d or a0 == 1:
        flag, x = 0, cell
    else:
        flag, x = 1, lag(cell, afl, c[0xCC06C], F(2.0 ** -11))
    y = clamp(x, c[0xCC064], c[0xCC068])
    y = clamp(y, -0.5, 0.5)
    return flag, y


def m_034884(st, c=C):
    """st: idx, cells[4], a0=[78A0], g84=[7884], n9=[78A9], afl=[7878], p6=[78A6], m1=[78A1],
    n81, n82, s40=[6540], t=[77C8], w0=[7704], ba8=[7BA8].  Returns (writes dict, info)."""
    w = {}
    cell = st['cells'][st['idx']]
    n9 = st['n9']
    if st['a0'] == 1:
        n9 = 0
        w['n9'] = 0
    if st['g84'] == 1:
        n9 = min(n9 + 1, 255)
    else:
        n9 = 0
    w['n9'] = n9

    def reset(why):
        w['n81'] = 0
        w['n82'] = 0x80
        return w, why

    if st['g84'] != 1:
        return reset('G1 [7884]!=1')
    if not (n9 >= c[0xCBBE7]):
        return reset('G2 [78A9]<63')
    if not (c[0xCC044] > absdiff(st['afl'], cell)):
        return reset('G3 |AFL-cell|')
    if st['p6'] != 0 and st['m1'] != 1:
        return reset('G4 [78A6]/[78A1]')
    dt = absdiff(st['s40'], st['t'])
    m, n81, n82 = st['m1'], st['n81'], st['n82']
    cond_a = n81 < c[0xCBBE8] and m == 1 and c[0xCC048] > dt
    if cond_a or (n81 < c[0xCBBE9] and m == 0):
        t = st['t']
        if not outside(t, 0.0, F(2.0 ** -13)):
            t = 1.0
        e_ = fadd(fadd(fsub(st['w0'], fdiv(1.0, t)), st['ba8']), 1.0)
        if not (c[0xCC058] > e_):
            w['n82'] = min(n82 + 1, 255)
            v = 'up'
        elif c[0xCC054] > e_:
            if n82 > 0:
                w['n82'] = n82 - 1
            v = 'down'
        else:
            v = 'none'
        w['n81'] = (n81 + 1) & 0xFF
        return w, 'sample ' + v
    if n81 < c[0xCBBE8] and m == 1 and not (c[0xCC048] > dt):
        return reset('abort dt')
    if m == 1:
        n, up, dn = c[0xCBBE8], c[0xCBBED], c[0xCBBEC]
    else:
        n, up, dn = c[0xCBBE9], c[0xCBBEB], c[0xCBBEA]
    if n81 != n:
        return w, 'idle'
    x = cell
    if n82 >= up:
        x = fadd(x, c[0xCC05C])
    elif n82 < dn:
        x = fsub(x, c[0xCC05C])
    w['cell'] = clamp(x, c[0xCC04C], c[0xCC050])
    return reset('decide')


def m_0345A4(st, c=C):
    p1 = 1 if (c[0xCC020] > st['788C'] and not outside(st['73A4'], 0.0, F(2.0 ** -8))
               and not outside(st['7354'], 0.0, F(2.0 ** -12)) and not outside(st['7374'], 0.0, F(2.0 ** -12))
               and not outside(st['7A14'], 0.0, F(2.0 ** -10)) and not outside(st['7A20'], 0.0, F(2.0 ** -8))
               and st['7D18'] == 0 and st['8F24'] == 0 and st['7BE2'] == 0) else 0
    p2 = 1 if (st['7448'] == 1 and st['78A7'] >= c[0xCBBE4] and st['A56A'] == 0 and st['ACE6'] == 0
               and st['94B1'] == 0 and st['7453'] == 1 and st['78A8'] >= c[0xCBBE5]
               and st['7324'] > st['733C'] and p1 == 1) else 0
    return p1, p2


def m_034778(st, c=C):
    a4 = 1 if ((not (c[0xCC024] > st['7888'])) and c[0xCC028] > st['7888']
               and c[0xCC02C] > absdiff(st['7890'], 0.0) and st['78A5'] == 1
               and (st['78A1'] == 0 or st['789C'] >= c[0xCBBE6])
               and not (st['7AB4'] > c[0xCC040])) else 0
    aa = st['78AA']
    if not (st['7A44'] > c[0xCC030]):
        aa = 1
    elif st['7A44'] > c[0xCC034]:
        aa = 0
    r = 2 if st['9709'] != 0 else 0                  # 0x0297F4
    g = 1 if (st['7883'] == 1 and r == 0
              and ((not outside(st['7894'], 0.0, F(2.0 ** -11))) or (aa == 1 and st['7898'] >= c[0xCBC40]))
              and a4 == 1) else 0
    return a4, aa, g


def m_034CC8(st, c=C):
    thr = c[0xCBC42] if c[0xCC08C] > st['6354'] else c[0xCBC44]
    return 1 if st['7898'] >= thr else 0


def rom_lookup(entry, rec, x, rom=ROM):
    e = run(entry, [], regs={4: rec}, fregs={4: x}, rom=rom)
    return e.R[0]


def m_034C18(st, rom=ROM):
    """returns new 787E (or None = unchanged), 789F, 789A"""
    load = (st['789F'] == 0 and st['7880'] == 1) or (st['789A'] != 0 and st['787C'] == 0)
    v = rom_lookup(0x0BE874, 0x0AC524, st['7874'], rom) & 0xFF if load else None
    return v, st['7880'], st['787C']


def m_034CEE(st, c=C, rom=ROM):
    v = None
    if st['789D'] != 0 and st['787E'] == 0:
        if c[0xCC090] > st['7874']:
            v = c[0xCBC46]
        else:
            v = rom_lookup(0x0BE8AC, 0x0ACEF0, st['7874'], rom) & 0xFFFF
    return v, st['787E']


# ================================================================== A
def sec_A():
    say('\n== A  0x034D52: AFL cell index [787F] and window flag [78A5] from [63C4] ==')
    xs = [0.0, -1.0, 1e30, -1e30, math.inf, -math.inf, math.nan, 3.0, 15.0, 30.0, 60.0, 100.0]
    for a in (0xCC070, 0xCC074, 0xCC078, 0xCC07C, 0xCC080):
        v = C[a]
        xs += [v, up1(v), dn1(v)]
    n = 0
    for x in xs:
        for a0 in (0, 1, 2, 0x81, 0xFF):
            e = run(0x034D52, [(0xFFFF63C4, 'f32', x), (A78A0, 'u8', a0)])
            fl, idx = m_034D52(F(x), a0)
            check(e.read_u8(A78A5) == fl and e.read_u8(A787F) == idx, f'A x={x} a0={a0}')
            check(written(e) == {A78A5, A787F}, 'A write set')
            n += 1
    for _ in range(3000):
        x = rand_f(-10, 120)
        a0 = RNG.choice((0, 0, 0, 1, 2))
        e = run(0x034D52, [(0xFFFF63C4, 'f32', x), (A78A0, 'u8', a0)])
        check((e.read_u8(A78A5), e.read_u8(A787F)) == m_034D52(x, a0), f'A rand {x}')
        n += 1
    say(f'   ranges (20.19c): idx0 < {C[0xCC074]} <= idx1 < {C[0xCC078]} <= idx2 < {C[0xCC07C]} <= idx3;'
        f'  [78A5]=1 iff {C[0xCC070]} <= x < {C[0xCC080]}')
    for x, a0 in ((5.99, 0), (6.0, 0), (22.9, 0), (23.0, 0), (39.9, 0), (40.0, 0), (1.5, 0), (80.0, 0), (15.0, 1),
                  (math.nan, 0)):
        e = run(0x034D52, [(0xFFFF63C4, 'f32', x), (A78A0, 'u8', a0)])
        say(f'   [63C4]={x:<6} [78A0]={a0} -> [787F]={e.read_u8(A787F)} [78A5]={e.read_u8(A78A5)}')
    say(f'   {n} cases, all match the model')


# ================================================================== B
def sec_B():
    say('\n== B  0x034B1C: [7878] = clamp(clamp(snap-or-lag(cell), Limits), -0.5, 0.5); [7885] ==')
    vals = [-0.6, -0.3, -0.25, -0.1, -0.0199, 0.0, 0.001, 0.0199, 0.02, 0.1, 0.25, 0.3, 0.6]
    n = 0
    cases = []
    for cell in vals:
        for d in (0.0, 0.0199, -0.0199, 0.02, -0.02, 0.05, -0.3, 0.7):
            for a0 in (0, 1):
                cases.append((F(cell), F(cell + d), a0))
    cases += [(F(0.1), math.nan, 0), (F(0.1), math.inf, 0), (F(0.1), -math.inf, 0), (math.nan, 0.0, 0)]
    for _ in range(3000):
        cell = rand_f(-0.4, 0.4)
        cases.append((cell, F(cell + RNG.choice((0.0, 0.01, 0.03, -0.03, RNG.uniform(-1, 1)))), RNG.choice((0, 0, 1))))
    for cell, afl, a0 in cases:
        idx = RNG.randrange(4)
        ram = [(CELLS + 8 * i, 'rec', (cell if i == idx else F(0.07 * i))) for i in range(4)]
        ram += [(A787F, 'u8', idx), (A7878, 'f32', afl), (A78A0, 'u8', a0)]
        e = run(0x034B1C, ram)
        fl, y = m_034B1C(cell, afl, a0)
        got = e.read_f32(A7878)
        check(e.read_u8(A7885) == fl and (E.f2b(got) == E.f2b(y)), f'B cell={cell} afl={afl} a0={a0}: {got} vs {y}')
        check(written(e) == span(A7878, 4) | {A7885}, 'B write set')
        n += 1
    # convergence: cell 0.1, AFL 0
    afl, k = 0.0, 0
    ram = [(CELLS + 8 * i, 'rec', F(0.1) if i == 1 else 0.0) for i in range(4)] + [(A787F, 'u8', 1), (A78A0, 'u8', 0)]
    e = new_emu()
    for a, kd, v in ram:
        put(e, a, kd, v)
    put(e, A7878, 'f32', 0.0)
    trace = []
    while True:
        k += 1
        run(0x034B1C, [], e=e)
        afl = e.read_f32(A7878)
        trace.append((k, afl, e.read_u8(A7885)))
        if afl == F(0.1):
            break
        check(k < 1000, 'B convergence')
    say(f'   convergence cell=0.1 from AFL=0: {k} calls; AFL after 1,2,3 calls = '
        f'{trace[0][1]:.6f} {trace[1][1]:.6f} {trace[2][1]:.6f}; last lag call {k - 1}: AFL={trace[-2][1]:.6f} '
        f'[7885]={trace[-2][2]}; call {k}: snap to cell, [7885]={trace[-1][2]}')
    check(trace[-1][2] == 0 and trace[-2][2] == 1, 'B snap flag')
    check(abs(trace[0][1] - 0.1 * C[0xCC06C]) < 1e-6, 'B first step = k*gap')
    # Limits clamp
    for cell, want in ((0.3, C[0xCC068]), (-0.3, C[0xCC064])):
        e = run(0x034B1C, [(CELLS + 8 * i, 'rec', F(cell)) for i in range(4)] +
                [(A787F, 'u8', 0), (A7878, 'f32', F(cell)), (A78A0, 'u8', 0)])
        check(e.read_f32(A7878) == want, 'B limits')
        say(f'   cell={cell:+.2f}, AFL=cell -> [7878]={e.read_f32(A7878):+.4f} (A/F Learning #1 Limits)')
    say(f'   {n} cases, all bit-exact against the model')


# ================================================================== C
def st_ram(st):
    ram = [(CELLS + 8 * i, 'rec', st['cells'][i]) for i in range(4)]
    ram += [(A787F, 'u8', st['idx']), (A78A0, 'u8', st['a0']), (A7884, 'u8', st['g84']), (A78A9, 'u8', st['n9']),
            (A7878, 'f32', st['afl']), (A78A6, 'u8', st['p6']), (A78A1, 'u8', st['m1']), (A7881, 'u8', st['n81']),
            (A7882, 'u8', st['n82']), (0xFFFF6540, 'f32', st['s40']), (0xFFFF77C8, 'f32', st['t']),
            (0xFFFF7704, 'f32', st['w0']), (0xFFFF7BA8, 'f32', st['ba8'])]
    return ram


def rand_st():
    cells = [rand_f(-0.3, 0.3) if RNG.random() < 0.8 else F(RNG.choice((0.0, 0.25, -0.25, 0.2495, -0.2495)))
             for _ in range(4)]
    idx = RNG.randrange(4)
    t = F(RNG.choice((1.0, 1.0, RNG.uniform(0.7, 1.3), 2.0 ** -13, -2.0 ** -13, up1(2.0 ** -13), 0.0,
                      RNG.uniform(-1e-4, 1e-4))))
    s40 = F(t + RNG.choice((0.0, 0.01, -0.049, 0.0499, 0.05, -0.05, 0.06, RNG.uniform(-0.1, 0.1))))
    return dict(cells=cells, idx=idx,
                a0=RNG.choice((0, 0, 0, 0, 1, 2)), g84=RNG.choice((1, 1, 1, 1, 0, 2)),
                n9=RNG.choice((62, 63, 64, 100, 255, 0, 1, RNG.randrange(256))),
                afl=F(cells[idx] + RNG.choice((0.0, 0.0, 0.0199, -0.0199, 0.02, -0.02, 0.05, RNG.uniform(-0.03, 0.03)))),
                p6=RNG.choice((0, 1, 1, 2)), m1=RNG.choice((0, 1, 1, 2)),
                n81=RNG.choice((0, 1, 15, 16, 17, 39, 40, 41, RNG.randrange(48), 255)),
                n82=RNG.choice((128, 112, 113, 114, 143, 144, 145, 0, 255, RNG.randrange(256))),
                s40=s40, t=t, w0=F(RNG.choice((1.0, 1.0101, 1.01, 0.99, 0.9899, RNG.uniform(0.8, 1.2)))),
                ba8=F(RNG.choice((0.0, 0.0, 0.005, -0.005, RNG.uniform(-0.05, 0.05)))))


def check_034884(st, e, tag):
    w, why = m_034884(st)
    check(e.read_u8(A78A9) == w['n9'], f'{tag} [78A9] {why}')
    exp = {A78A9}
    for key, a in (('n81', A7881), ('n82', A7882)):
        if key in w:
            check(e.read_u8(a) == w[key], f'{tag} {key}: rom {e.read_u8(a)} model {w[key]} ({why}) st={st}')
            exp.add(a)
    ca = CELLS + 8 * st['idx']
    if 'cell' in w:
        check(E.f2b(e.read_f32(ca)) == E.f2b(w['cell']) and rec_ok(e, ca), f'{tag} cell ({why})')
        exp |= span(ca, 8)
    check(written(e) == exp, f'{tag} write set {sorted(hex(a) for a in written(e))} vs {sorted(hex(a) for a in exp)} ({why})')
    return why


def sec_C():
    say('\n== C  0x034884: one call vs model, random states ==')
    whys = {}
    for i in range(12000):
        st = rand_st()
        e = run(0x034884, st_ram(st))
        why = check_034884(st, e, f'C#{i}')
        whys[why] = whys.get(why, 0) + 1
    for k in sorted(whys):
        say(f'   {k:<22} {whys[k]:6d}')
    for need in ('G1 [7884]!=1', 'G2 [78A9]<63', 'G3 |AFL-cell|', 'G4 [78A6]/[78A1]', 'sample up', 'sample down',
                 'sample none', 'abort dt', 'decide', 'idle'):
        check(whys.get(need, 0) > 0, f'C path not exercised: {need}')
    say('   12000 random states: every written byte, cell value and check words match the model')


# ================================================================== D
def base_seq(mode):
    return dict(cells=[0.0, 0.0, 0.0, 0.0], idx=1, a0=0, g84=1, n9=0, afl=0.0, p6=mode, m1=mode,
                n81=0, n82=0x80, s40=1.0, t=1.0, w0=1.0, ba8=0.0)


def seq(st, calls, w0_of=None, mut=None):
    """run 0x034884 then 0x034B1C per call (the order in 0x03452A), from one emulator; return cell history"""
    e = new_emu()
    for a, kd, v in st_ram(st):
        put(e, a, kd, v)
    hist = []
    for k in range(1, calls + 1):
        if w0_of:
            put(e, 0xFFFF7704, 'f32', F(w0_of(k)))
        if mut:
            mut(e, k)
        run(0x034884, [], e=e)
        run(0x034B1C, [], e=e)
        hist.append((k, e.read_f32(CELLS + 8 * st['idx']), e.read_f32(A7878), e.read_u8(A7881), e.read_u8(A7882)))
        put(e, A78A6, 'u8', e.read_u8(A78A1))       # what 0x03452A does at its top on the next call
    return hist, e


def changes(hist):
    out, prev = [], 0.0
    for k, c, _a, _n1, _n2 in hist:
        if c != prev:
            out.append((k, c))
            prev = c
    return out


def sec_D():
    say('\n== D  sequences of 0x034884 + 0x034B1C (one call = one 0x03452A pass) ==')
    # D1 mode 1, e = 1.05
    st = base_seq(1)
    hist, _ = seq(st, 63 + 41 * 6, w0_of=lambda k: 1.05)
    ch = changes(hist)
    say(f'   D1 mode 1 ([78A1]=1), e=1.05: cell changes at calls {[k for k, _ in ch]} -> {[round(c, 6) for _, c in ch]}')
    check([k for k, _ in ch] == [103 + 41 * i for i in range(6)], 'D1 period 41, first at 103')
    x = 0.0
    for _, c in ch:
        x = clamp(fadd(x, C[0xCC05C]), C[0xCC04C], C[0xCC050])
        check(c == x, 'D1 step value')
    check(all(a == c for _k, c, a, _n1, _n2 in hist), 'D1 AFL snaps to the cell every call')
    # D2 mode 0
    hist, _ = seq(base_seq(0), 63 + 17 * 6, w0_of=lambda k: 1.05)
    ch = changes(hist)
    say(f'   D2 mode 0 ([78A1]=0), e=1.05: cell changes at calls {[k for k, _ in ch]}')
    check([k for k, _ in ch] == [79 + 17 * i for i in range(6)], 'D2 period 17, first at 79')
    # D3 down, D4 neutral
    hist, _ = seq(base_seq(1), 63 + 41 * 3, w0_of=lambda k: 0.95)
    ch = changes(hist)
    say(f'   D3 mode 1, e=0.95: {[(k, round(c, 6)) for k, c in ch]}')
    check([round(c, 6) for _, c in ch] == [-0.001, -0.002, -0.003], 'D3 down steps')
    for w0 in (0.99, 1.0, 1.0099):
        hist, _ = seq(base_seq(1), 63 + 41 * 3, w0_of=lambda k, w0=w0: w0)
        check(changes(hist) == [], f'D4 neutral e={w0}')
    say('   D4 e in {0.99, 1.0, 1.0099}: no change in 186 calls (dead band [0.99, 1.01))')
    hist, _ = seq(base_seq(1), 63 + 41 * 2, w0_of=lambda k: 1.0100001)
    check(len(changes(hist)) == 2, 'D4 edge 1.01 votes up')

    # D5 vote thresholds, mode 1 (40 samples, calls 63..102, decision 103)
    def votes(u, d, mode):
        n = 40 if mode == 1 else 16
        pattern = ['u'] * u + ['d'] * d + ['n'] * (n - u - d)
        RNG.shuffle(pattern)
        wmap = {'u': 1.05, 'd': 0.95, 'n': 1.0}
        first = 63
        hist, _ = seq(base_seq(mode), first + n, w0_of=lambda k: wmap[pattern[k - first]] if first <= k < first + n else 1.0)
        return hist[-1][1]
    res = []
    for u, d in ((16, 0), (15, 0), (20, 4), (20, 5), (0, 16), (0, 15), (4, 20), (5, 20), (28, 12), (12, 28)):
        c = votes(u, d, 1)
        res.append((u, d, round(c, 6)))
        want = 0.001 if u - d >= 16 else (-0.001 if u - d <= -16 else 0.0)
        check(round(c, 6) == want, f'D5 u={u} d={d}')
    say(f'   D5 mode 1, 40 samples (up, down) -> cell: {res}')
    res = []
    for u, d in ((16, 0), (15, 0), (0, 16), (0, 15), (15, 1), (1, 15)):
        c = votes(u, d, 0)
        res.append((u, d, round(c, 6)))
        want = 0.001 if u - d >= 16 else (-0.001 if u - d <= -16 else 0.0)
        check(round(c, 6) == want, f'D6 u={u} d={d}')
    say(f'   D6 mode 0, 16 samples (up, down) -> cell: {res}  (unanimity needed)')
    # D7 clamp
    st = base_seq(1)
    st['cells'][1] = F(0.2495)
    st['afl'] = F(0.2495)
    hist, _ = seq(st, 63 + 41 * 3, w0_of=lambda k: 1.05)
    ch = changes([(0, 0.2495, 0, 0, 0)] + hist)
    say(f'   D7 clamp: 0.2495 -> {[(k, c) for k, c in ch[1:]]}; final {hist[-1][1]}')
    check(hist[-1][1] == C[0xCC050], 'D7 cell clamp 0.25')
    st = base_seq(1)
    st['cells'][1] = F(-0.2495)
    st['afl'] = F(-0.2495)
    hist, _ = seq(st, 63 + 41 * 3, w0_of=lambda k: 0.95)
    check(hist[-1][1] == C[0xCC04C], 'D7 cell clamp -0.25')

    # D8 window abort in mode 1 by dt >= 0.05 once (call 80)
    def m8(e, k):
        put(e, 0xFFFF6540, 'f32', F(1.06) if k == 80 else 1.0)
    hist, _ = seq(base_seq(1), 63 + 41 * 3, w0_of=lambda k: 1.05, mut=m8)
    ch = changes(hist)
    say(f'   D8 |[6540]-[77C8]|=0.06 at call 80 only: [7881] at 79/80/81 = {hist[78][3]}/{hist[79][3]}/{hist[80][3]};'
        f' changes {[k for k, _ in ch]}')
    check(hist[79][3] == 0 and hist[79][4] == 0x80 and [k for k, _ in ch] == [121, 162], 'D8 abort')

    def m8b(e, k):
        put(e, 0xFFFF6540, 'f32', F(1.06) if k == 80 else 1.0)
    hist, _ = seq(base_seq(0), 63 + 17 * 2, w0_of=lambda k: 1.05, mut=m8b)
    check([k for k, _ in changes(hist)] == [79, 96], 'D8 mode 0 ignores dt')
    say('   D8 mode 0: the same disturbance changes nothing (calls 79, 96 as in D2)')

    # D9 [7884] drop at call 150
    def m9(e, k):
        put(e, A7884, 'u8', 0 if k == 150 else 1)
    hist, _ = seq(base_seq(1), 400, w0_of=lambda k: 1.05, mut=m9)
    ks = [k for k, _ in changes(hist)]
    say(f'   D9 [7884]=0 at call 150 only: changes at {ks}')
    check(ks[:2] == [103, 144] and ks[2] == 150 + 63 + 40, 'D9 63-call re-arm')

    # D10 [78A0] = 1 throughout: [78A9] <= 1 -> nothing
    def m10(e, k):
        put(e, A78A0, 'u8', 1)
    hist, e = seq(base_seq(1), 300, w0_of=lambda k: 1.05, mut=m10)
    check(changes(hist) == [] and e.read_u8(A78A9) == 1, 'D10')
    say('   D10 [78A0]=1 every call: [78A9] stays 1, cell never changes (300 calls)')

    # D11 mode switch
    def m11(e, k):
        put(e, A78A1, 'u8', 1 if k < 90 else 0)
    hist, _ = seq(base_seq(1), 120, w0_of=lambda k: 1.05, mut=m11)
    say(f'   D11 [78A1] 1->0 at call 90: [7881] at 89/90 = {hist[88][3]}/{hist[89][3]}, changes '
        f'{[k for k, _ in changes(hist)]}')
    check(hist[88][3] == 27 and hist[89][3] == 0 and [k for k, _ in changes(hist)] == [107], 'D11 1->0 resets')

    def m11b(e, k):
        put(e, A78A1, 'u8', 0 if k < 70 else 1)
    st = base_seq(0)
    hist, _ = seq(st, 160, w0_of=lambda k: 1.05, mut=m11b)
    say(f'   D11 [78A1] 0->1 at call 70: [7881] at 69/70/71 = {hist[68][3]}/{hist[69][3]}/{hist[70][3]} (window continues)'
        f', changes {[k for k, _ in changes(hist)]}')
    check(hist[69][3] == hist[68][3] + 1 and [k for k, _ in changes(hist)] == [103, 144], 'D11 0->1 continues')

    # D12 [77C8] near zero
    for t, w0, want in ((2.0 ** -13, 1.05, 0.001), (-2.0 ** -13, 1.05, 0.001), (0.0, 1.05, 0.001),
                        (up1(2.0 ** -13), 1.05, -0.001), (1.0, 1.05, 0.001), (1.0 / 1.02, 1.05, 0.001),
                        (1.0 / 1.05, 1.05, 0.0)):
        st = base_seq(1)
        st['t'] = F(t)
        st['s40'] = F(t)
        hist, _ = seq(st, 63 + 41, w0_of=lambda k, w0=w0: w0)
        check(round(hist[-1][1], 6) == want, f'D12 t={t}')
    say('   D12 [77C8] in [-2^-13, 2^-13] is replaced by 1.0 (e = W0 + [7BA8]); just outside it 1/[77C8] is used'
        ' (2^-13+ulp: e ~ -8191 -> down vote); [77C8]=1/1.05, W0=1.05 -> e=1.0 -> no step')
    # D13 what-if: Limits max edited to 0.10 (in-memory ROM copy; NOT a bin on disk)
    rom2 = bytearray(ROM)
    rom2[0xCC068:0xCC06C] = struct.pack('>f', 0.10)
    rom2 = bytes(rom2)
    st = base_seq(1)
    st['cells'][1] = F(0.095)
    st['afl'] = F(0.095)
    e = E.Emu(rom2)
    e.stub(0x00317C, r0=0)
    e.stub(0x003190)
    for a, kd, v in st_ram(st):
        put(e, a, kd, v)
    put(e, 0xFFFF7704, 'f32', F(1.05))
    for k in range(1, 63 + 41 * 40):
        run(0x034884, [], e=e, rom=rom2)
        run(0x034B1C, [], e=e, rom=rom2)
        put(e, A78A6, 'u8', 1)
    cfin, afin = e.read_f32(CELLS + 8), e.read_f32(A7878)
    say(f'   D13 WHAT-IF (Limits max 0.10 in a copy): cell stops at {cfin:.6f}, [7878] held at {afin:.6f}'
        f' -- the cell can run at most ~0.02 past the Limits, then the G3 gate freezes it')
    check(afin == F(0.10) and 0.117 < cfin < 0.1215, 'D13')


# ================================================================== E
E_KEYS = [('8F24', 'u8'), ('788C', 'f32'), ('73A4', 'f32'), ('7354', 'f32'), ('7374', 'f32'), ('7A14', 'f32'),
          ('7A20', 'f32'), ('7D18', 'u8'), ('7BE2', 'u8'), ('A56A', 'u8'), ('ACE6', 'u8'), ('7448', 'u8'),
          ('94B1', 'u8'), ('7453', 'u8'), ('733C', 'f32'), ('7324', 'f32'), ('78A7', 'u8'), ('78A8', 'u8')]


def e_ram(st):
    return [(0xFFFF0000 | int(k, 16), kd, st[k]) for k, kd in E_KEYS]


def e_base():
    return {'8F24': 0, '788C': 30.0, '73A4': 0.0, '7354': 0.0, '7374': 0.0, '7A14': 0.0, '7A20': 0.0, '7D18': 0,
            '7BE2': 0, 'A56A': 0, 'ACE6': 0, '7448': 1, '94B1': 0, '7453': 1, '733C': 0.0, '7324': 1.0, '78A7': 200,
            '78A8': 200}


def sec_E():
    say('\n== E  0x0345A4: [78A3] (part 1) and [7883] (part 2, the fall-through at 0x034644) ==')
    flips = [('788C', [C[0xCC020], dn1(C[0xCC020]), 100.0, math.nan]),
             ('73A4', [2.0 ** -8, -2.0 ** -8, up1(2.0 ** -8), dn1(-2.0 ** -8), math.nan, 0.1]),
             ('7354', [2.0 ** -12, up1(2.0 ** -12), -up1(2.0 ** -12)]),
             ('7374', [2.0 ** -12, up1(2.0 ** -12), -up1(2.0 ** -12)]),
             ('7A14', [2.0 ** -10, up1(2.0 ** -10), -up1(2.0 ** -10)]),
             ('7A20', [2.0 ** -8, up1(2.0 ** -8), -up1(2.0 ** -8)]),
             ('7D18', [1, 0x80]), ('8F24', [1, 0xFF]), ('7BE2', [1]), ('A56A', [1]), ('ACE6', [1]),
             ('7448', [0, 2, 0x81]), ('94B1', [1]), ('7453', [0, 2]), ('78A7', [127, 128, 0, 255]),
             ('78A8', [127, 128]), ('7324', [0.0, -1.0, math.nan]), ('733C', [1.0, 2.0])]
    rows = []
    n = 0
    st = e_base()
    e = run(0x0345A4, e_ram(st))
    check((e.read_u8(A78A3), e.read_u8(A7883)) == (1, 1) == m_0345A4(st), 'E base')
    for key, vs in flips:
        for v in vs:
            st = e_base()
            st[key] = F(v) if isinstance(v, float) else v
            e = run(0x0345A4, e_ram(st))
            got = (e.read_u8(A78A3), e.read_u8(A7883))
            check(got == m_0345A4(st), f'E flip {key}={v}')
            check(written(e) == {A78A3, A7883}, 'E write set')
            rows.append(f'{key}={v:g}->{got[0]}{got[1]}' if isinstance(v, float) else f'{key}={v}->{got[0]}{got[1]}')
            n += 1
    for _ in range(6000):
        st = e_base()
        for key, kd in E_KEYS:
            if RNG.random() < 0.15:
                st[key] = RNG.choice((0, 1, 2, 127, 128, 255)) if kd == 'u8' else F(RNG.choice((
                    0.0, 1e-3, -1e-5, 2.0 ** -9, RNG.uniform(-2, 80))))
        e = run(0x0345A4, e_ram(st))
        check((e.read_u8(A78A3), e.read_u8(A7883)) == m_0345A4(st), 'E random')
        n += 1
    say('   flips (key=value -> [78A3][7883]): ' + ', '.join(rows))
    say(f'   {n} cases, all match the model')


# ================================================================== F
F_KEYS = [('7888', 'f32'), ('7890', 'f32'), ('7894', 'f32'), ('7898', 'u16'), ('78A5', 'u8'), ('78A1', 'u8'),
          ('789C', 'u8'), ('7AB4', 'f32'), ('9709', 'u8'), ('7A44', 'f32'), ('78AA', 'u8'), ('7883', 'u8')]


def f_ram(st):
    return [(0xFFFF0000 | int(k, 16), kd, st[k]) for k, kd in F_KEYS]


def f_base():
    return {'7888': 85.0, '7890': 0.0, '7894': 0.0, '7898': 100, '78A5': 1, '78A1': 1, '789C': 200, '7AB4': 0.0,
            '9709': 0, '7A44': 0.0, '78AA': 0, '7883': 1}


def sec_F():
    say('\n== F  0x034778: [78A4] (part 1), [78AA] hysteresis and [7884] (part 2, fall-through at 0x0347F0) ==')
    flips = [('7888', [C[0xCC024], dn1(C[0xCC024]), C[0xCC028], dn1(C[0xCC028]), math.nan]),
             ('7890', [dn1(C[0xCC02C]), C[0xCC02C], -dn1(C[0xCC02C])]),
             ('78A5', [0, 2]), ('78A1', [0, 2]), ('789C', [C[0xCBBE6], C[0xCBBE6] - 1]),
             ('7AB4', [C[0xCC040], up1(C[0xCC040]), math.nan]), ('9709', [1, 0x80]), ('7883', [0, 2]),
             ('7894', [2.0 ** -11, up1(2.0 ** -11), 0.5])]
    n, rows = 0, []
    st = f_base()
    e = run(0x034778, f_ram(st))
    check((e.read_u8(A78A4), e.read_u8(A78AA), e.read_u8(A7884)) == m_034778(st) == (1, 0, 1), 'F base')
    for key, vs in flips:
        for v in vs:
            st = f_base()
            st[key] = F(v) if isinstance(v, float) else v
            e = run(0x034778, f_ram(st))
            got = (e.read_u8(A78A4), e.read_u8(A78AA), e.read_u8(A7884))
            check(got == m_034778(st), f'F flip {key}={v}')
            rows.append(f'{key}={v:g}->{got}' if isinstance(v, float) else f'{key}={v}->{got}')
            n += 1
    # hysteresis of [78AA] and the [7894]/[7898] alternative
    hy = []
    for a44 in (-3.0, C[0xCC030], up1(C[0xCC030]), -1.5, C[0xCC034], up1(C[0xCC034]), 0.0, math.nan):
        for prev in (0, 1):
            st = f_base()
            st['7A44'], st['78AA'] = F(a44), prev
            e = run(0x034778, f_ram(st))
            got = (e.read_u8(A78A4), e.read_u8(A78AA), e.read_u8(A7884))
            check(got == m_034778(st), f'F hyst {a44} {prev}')
            hy.append(f'{a44:g}/{prev}->{got[1]}')
            n += 1
    for _ in range(6000):
        st = f_base()
        for key, kd in F_KEYS:
            if RNG.random() < 0.2:
                if kd == 'u8':
                    st[key] = RNG.choice((0, 1, 2, 77, 78, 255))
                elif kd == 'u16':
                    st[key] = RNG.choice((0, 28, 29, 30, 65535))
                else:
                    st[key] = F(RNG.choice((0.0, 1e-4, -0.0123, 74.9, 75.0, 95.0, -2.5, -1.5, RNG.uniform(-5, 120))))
        e = run(0x034778, f_ram(st))
        got = (e.read_u8(A78A4), e.read_u8(A78AA), e.read_u8(A7884))
        check(got == m_034778(st), f'F random {st}')
        check(written(e) <= {A78A4, A78AA, A7884} and {A78A4, A7884} <= written(e), 'F write set')
        n += 1
    say('   flips (key=value -> ([78A4],[78AA],[7884])): ' + ', '.join(rows))
    say('   [78AA] hysteresis ([7A44]/prev -> new): ' + ', '.join(hy))
    say(f'   {n} cases, all match the model')


# ================================================================== G
G_IN = [('65F6', 'u8'), ('6254', 'u8'), ('6350', 'f32'), ('6364', 'f32'), ('63FC', 'f32'), ('69FC', 'f32'),
        ('6A22', 'u16'), ('7D68', 'f32'), ('63C4', 'f32'), ('6354', 'f32'),
        ('8F24', 'u8'), ('73A4', 'f32'), ('7354', 'f32'), ('7374', 'f32'), ('7A14', 'f32'), ('7A20', 'f32'),
        ('7D18', 'u8'), ('7BE2', 'u8'), ('A56A', 'u8'), ('ACE6', 'u8'), ('7448', 'u8'), ('94B1', 'u8'),
        ('7453', 'u8'), ('733C', 'f32'), ('7324', 'f32'), ('78A7', 'u8'), ('78A8', 'u8'),
        ('789C', 'u8'), ('7AB4', 'f32'), ('9709', 'u8'), ('7A44', 'f32'), ('78AA', 'u8'),
        ('78A1', 'u8'), ('78A9', 'u8'), ('7878', 'f32'), ('7881', 'u8'), ('7882', 'u8'),
        ('6540', 'f32'), ('77C8', 'f32'), ('7704', 'f32'), ('7BA8', 'f32'),
        ('789F', 'u8'), ('789A', 'u16'), ('787C', 'u16'), ('787E', 'u8'), ('789D', 'u8')]


def g_base():
    return {'65F6': 0, '6254': 1, '6350': 85.0, '6364': 30.0, '63FC': 0.0, '69FC': 0.0, '6A22': 300, '7D68': 0.05,
            '63C4': 15.0, '6354': 20.0, '8F24': 0, '73A4': 0.0, '7354': 0.0, '7374': 0.0, '7A14': 0.0, '7A20': 0.0,
            '7D18': 0, '7BE2': 0, 'A56A': 0, 'ACE6': 0, '7448': 1, '94B1': 0, '7453': 1, '733C': 0.0, '7324': 1.0,
            '78A7': 200, '78A8': 200, '789C': 200, '7AB4': 0.0, '9709': 0, '7A44': -3.0, '78AA': 0, '78A1': 1,
            '78A9': 0, '7878': 0.0, '7881': 0, '7882': 0x80, '6540': 1.0, '77C8': 1.0, '7704': 1.05, '7BA8': 0.0,
            '789F': 0, '789A': 0, '787C': 0, '787E': 0, '789D': 0}


def g_ram(st, cells):
    return [(0xFFFF0000 | int(k, 16), kd, st[k]) for k, kd in G_IN] + \
           [(CELLS + 8 * i, 'rec', cells[i]) for i in range(4)]


def m_03452A(st, cells):
    """compose the per-function models in the order of 0x03452A; return expected RAM values"""
    out = {}
    p6 = st['78A1']
    m1 = st['6254']
    out['78A6'], out['78A1'] = p6, m1
    out['7888'], out['788C'], out['7890'], out['7894'] = st['6350'], st['6364'], st['63FC'], st['69FC']
    out['7898'] = st['6A22']
    a0 = 1 if st['65F6'] == 1 else 0
    out['78A0'] = a0
    fl, idx = m_034D52(st['63C4'], a0)
    out['78A5'], out['787F'] = fl, idx
    q = dict(st)
    q.update({'788C': st['6364']})
    p1, p2 = m_0345A4(q)
    out['78A3'], out['7883'] = p1, p2
    q.update({'7888': st['6350'], '7890': st['63FC'], '7894': st['69FC'], '7898': st['6A22'], '78A5': fl,
              '78A1': m1, '7883': p2})
    a4, aa, g = m_034778(q)
    out['78A4'], out['78AA'], out['7884'] = a4, aa, g
    s = dict(cells=list(cells), idx=idx, a0=a0, g84=g, n9=st['78A9'], afl=st['7878'], p6=p6, m1=m1,
             n81=st['7881'], n82=st['7882'], s40=st['6540'], t=st['77C8'], w0=st['7704'], ba8=st['7BA8'])
    w, why = m_034884(s)
    cells2 = list(cells)
    if 'cell' in w:
        cells2[idx] = w['cell']
    out['78A9'] = w['n9']
    out['7881'] = w.get('n81', st['7881'])
    out['7882'] = w.get('n82', st['7882'])
    f85, afl = m_034B1C(cells2[idx], st['7878'], a0)
    out['7885'], out['7878'] = f85, afl
    out['7874'] = st['7D68']
    out['7880'] = m_034CC8({'6354': st['6354'], '7898': st['6A22']})
    v7e, out['789F'], out['789A'] = m_034C18({'789F': st['789F'], '7880': out['7880'], '789A': st['789A'],
                                              '787C': st['787C'], '7874': st['7D68']})
    out['787E'] = v7e if v7e is not None else st['787E']
    v7c, out['789D'] = m_034CEE({'789D': st['789D'], '787E': out['787E'], '7874': st['7D68']})
    out['787C'] = v7c if v7c is not None else st['787C']
    return out, cells2, why


G_OUT = {'78A6': 'u8', '78A1': 'u8', '7888': 'f32', '788C': 'f32', '7890': 'f32', '7894': 'f32', '7898': 'u16',
         '78A0': 'u8', '78A5': 'u8', '787F': 'u8', '78A3': 'u8', '7883': 'u8', '78A4': 'u8', '78AA': 'u8',
         '7884': 'u8', '78A9': 'u8', '7881': 'u8', '7882': 'u8', '7885': 'u8', '7878': 'f32', '7874': 'f32',
         '7880': 'u8', '789F': 'u8', '789A': 'u16', '787E': 'u8', '789D': 'u8', '787C': 'u16'}


def rd(e, a, kd):
    return {'u8': e.read_u8, 'u16': e.read_u16, 'f32': e.read_f32}[kd](a)


def sec_G():
    say('\n== G  0x03452A whole (every callee from ROM) vs the composed models ==')
    allowed = set()
    for k, kd in G_OUT.items():
        allowed |= span(0xFFFF0000 | int(k, 16), {'u8': 1, 'u16': 2, 'f32': 4}[kd])
    for i in range(4):
        allowed |= span(CELLS + 8 * i, 8)
    whys = {}
    for i in range(2500):
        st = g_base()
        if RNG.random() < 0.6:
            st['78A9'] = RNG.choice((62, 63, 100, 255))
            st['7881'] = RNG.choice((15, 16, 39, 40, 41, RNG.randrange(42)))
            st['7882'] = RNG.choice((112, 113, 143, 144, 160, 100))
            st['6254'] = st['78A1'] = RNG.choice((0, 1, 1))
        for key, kd in G_IN:
            if RNG.random() < (0.12 if i % 2 else 0.03):
                if kd == 'u8':
                    st[key] = RNG.choice((0, 1, 2, 62, 63, 113, 144, 255))
                elif kd == 'u16':
                    st[key] = RNG.choice((0, 1, 28, 29, 87, 88, 243, 244, 65535))
                else:
                    st[key] = F(RNG.choice((0.0, 1.0, 1.05, 0.95, -1.0, 6.0, 23.0, 40.0, 80.0, 35.0, 70.0, 75.0,
                                            95.0, 0.2, RNG.uniform(-3, 100))))
        st['7878'] = F(RNG.choice((0.0, 0.0, 0.01, 0.03, -0.25)))
        cells = [F(RNG.choice((0.0, 0.0, 0.01, -0.02, 0.25))) for _ in range(4)]
        e = run(0x03452A, g_ram(st, cells))
        out, cells2, why = m_03452A(st, cells)
        whys[why] = whys.get(why, 0) + 1
        for k, kd in G_OUT.items():
            got = rd(e, 0xFFFF0000 | int(k, 16), kd)
            want = out[k]
            if kd == 'f32':
                check(E.f2b(got) == E.f2b(F(want)), f'G#{i} {k}: {got} vs {want}')
            else:
                check(got == want, f'G#{i} {k}: {got} vs {want} ({why})')
        for j in range(4):
            check(E.f2b(e.read_f32(CELLS + 8 * j)) == E.f2b(cells2[j]) and rec_ok(e, CELLS + 8 * j), f'G#{i} cell {j}')
        check(written(e) <= allowed, f'G#{i} stray writes {sorted(hex(a) for a in written(e) - allowed)}')
    say('   2500 random states: ' + ', '.join(f'{k}: {v}' for k, v in sorted(whys.items())))
    for need in ('decide', 'sample up', 'G1 [7884]!=1'):
        check(whys.get(need, 0) > 0, f'G path {need}')
    # end-to-end: realistic gate values, AFC lag W0 = 1.05, 20.19c ranges, cell 1 ([63C4] = 15 g/s-axis value)
    st = g_base()
    cells = [0.0] * 4
    e = new_emu()
    for a, kd, v in g_ram(st, cells):
        put(e, a, kd, v)
    first, ks = None, []
    prev = 0.0
    for k in range(1, 63 + 41 * 8 + 1):
        run(0x03452A, [], e=e)
        c = e.read_f32(CELLS + 8)
        if c != prev:
            ks.append(k)
            prev = c
        if first is None and e.read_u8(A7884) == 1:
            first = k
    say(f'   end-to-end (all gates passed, W0=1.05, [63C4]=15 -> cell 1): [7884]=1 from call {first}; cell 1 steps'
        f' at {ks}; cell={e.read_f32(CELLS + 8):.6f} [7878]={e.read_f32(A7878):.6f}; cells 0,2,3 untouched')
    check(ks == [103 + 41 * i for i in range(8)], 'G end-to-end period')
    check(all(e.read_f32(CELLS + 8 * j) == 0.0 for j in (0, 2, 3)), 'G other cells')
    check(e.read_f32(A7878) == e.read_f32(CELLS + 8), 'G AFL = cell')


# ================================================================== H
def sec_H():
    say('\n== H  cell clear 0x0344BA, cell validation 0x0344EE, [7878] init 0x034488 ==')
    ram = [(CELLS + 8 * i, 'u32', 0x3F800000 + i) for i in range(4)] + \
          [(CELLS + 8 * i + 4, 'u32', 0x12345678) for i in range(4)]
    e = run(0x0344BA, ram)
    check(written(e) == span(CELLS, 32), 'H1 write set')
    for i in range(4):
        check(e.read_u32(CELLS + 8 * i) == 0 and rec_ok(e, CELLS + 8 * i), f'H1 rec {i}')
    say(f'   H1 0x0344BA: writes exactly 0x{CELLS:08X}..0x{CELLS + 31:08X}: four records = 0.0 with valid checks'
        f' (check word of 0.0 = 0x{ck(0):04X})')
    r = run(0x0344EE, [], e=e).R[0]
    check(r == 0, 'H2 valid')
    for i in range(4):
        for how in ('value', 'ck4', 'ck6', 'both'):
            e2 = new_emu()
            for j in range(4):
                put(e2, CELLS + 8 * j, 'rec', F(0.01 * j))
            a = CELLS + 8 * i
            if how == 'value':
                put(e2, a, 'u32', e2.read_u32(a) ^ 0x00010000)
            if how in ('ck4', 'both'):
                put(e2, a + 4, 'u16', e2.read_u16(a + 4) ^ 1)
            if how in ('ck6', 'both'):
                put(e2, a + 6, 'u16', e2.read_u16(a + 6) ^ 1)
            e2 = run(0x0344EE, [], e=e2)
            want = 1 if how in ('value', 'both') else 0
            check(e2.R[0] == want, f'H2 rec {i} {how}')
            if want == 0:
                check(rec_ok(e2, a), f'H2 repaired {i} {how}')
    say('   H2 0x0344EE: returns 1 iff some record\'s CK(value) matches neither check word -- here a flipped value'
        ' bit (CK changes) or both check words damaged; one damaged check word is repaired (16 tamper cases);'
        ' K2 shows value changes it ACCEPTS (CK-preserving, NaN / inf with a matching CK)')
    rows = []
    for idx in range(4):
        for cell in (0.0, 0.1, 0.3, -0.3, math.nan):
            for m in (0, 1, 2):
                cells = [F(0.05 * j) for j in range(4)]
                cells[idx] = F(cell)
                e = run(0x034488, [(CELLS + 8 * j, 'rec', cells[j]) for j in range(4)] +
                        [(A787F, 'u8', idx), (0xFFFF6254, 'u8', m)])
                want = clamp(cells[idx], C[0xCC064], C[0xCC068])
                check(E.f2b(e.read_f32(A7878)) == E.f2b(want) and e.read_u8(A78A1) == m and e.read_u8(A78AA) == 1,
                      f'H3 {idx} {cell} {m}')
                check(written(e) == span(A7878, 4) | {A78A1, A78AA}, 'H3 write set')
        rows.append(idx)
    say('   H3 0x034488: [78A1]=[6254], [7878]=clamp(cell[[787F]], Limits) (NaN -> Limits min), [78AA]=1 (60 cases)')


# ================================================================== I
def sec_I():
    say('\n== I  counters: 0x034DD6, 0x034DA6, 0x034C54, 0x034C18, 0x034CEE, 0x034D2E, 0x034CC8 ==')
    n = 0
    for a48 in (0, 1, 2):
        for a53 in (0, 1, 2):
            for c7, c8 in ((0, 0), (127, 128), (254, 255), (255, 255)):
                e = run(0x034DD6, [(0xFFFF7448, 'u8', a48), (0xFFFF7453, 'u8', a53), (A78A7, 'u8', c7), (A78A8, 'u8', c8)])
                check(e.read_u8(A78A7) == (min(c7 + 1, 255) if a48 == 1 else 0) and
                      e.read_u8(A78A8) == (min(c8 + 1, 255) if a53 == 1 else 0), 'I1')
                n += 1
    for m in (0, 1, 2):
        for c68 in (0, 1):
            for v in (0, 77, 254, 255):
                e = run(0x034DA6, [(0xFFFF6254, 'u8', m), (0xFFFF7C68, 'u8', c68), (0xFFFF789C, 'u8', v)])
                want = (min(v + 1, 255) if c68 == 0 else v) if m == 1 else 0
                check(e.read_u8(0xFFFF789C) == want, 'I2')
                n += 1
    say('   I1 0x034DD6: [78A7]/[78A8] count calls while [7448]/[7453] == 1 (sat 255), else 0')
    say('   I2 0x034DA6: [789C] counts calls while [6254] == 1 and [7C68] == 0 (held while [7C68] != 0), 0 when [6254] != 1')
    # 0x034C54
    for v7e in (0, 1, 5, 255):
        for v9e in (0, 19, 20, 255):
            for w1 in (1.0, C[0xCC084], up1(C[0xCC084]), C[0xCC088], dn1(C[0xCC088]), 0.5, math.nan):
                for a48, a53 in ((1, 1), (0, 1), (1, 0)):
                    e = run(0x034C54, [(0xFFFF787E, 'u8', v7e), (0xFFFF789E, 'u8', v9e), (0xFFFF7708, 'f32', w1),
                                       (0xFFFF7448, 'u8', a48), (0xFFFF7453, 'u8', a53)])
                    x7e, x9e = v7e, v9e
                    if x7e > 0:
                        if x9e >= C[0xCBBEE]:
                            x7e = 0
                        else:
                            x9e = (x9e + 1) & 0xFF
                    else:
                        x9e = 0
                    if a48 == 1 and a53 == 1 and F(w1) > C[0xCC084] and C[0xCC088] > F(w1) and x7e > 0:
                        x7e -= 1
                    check(e.read_u8(0xFFFF787E) == x7e and e.read_u8(0xFFFF789E) == x9e, f'I3 {v7e} {v9e} {w1}')
                    n += 1
    say(f'   I3 0x034C54: while [787E] > 0, [789E] counts calls and forces [787E]=0 at {C[0xCBBEE]}; [787E] -= 1 per'
        f' call while [7448]==1, [7453]==1 and {C[0xCC084]:.2f} < [7708] < {C[0xCC088]:.2f}')
    # 0x034C18 / 0x034CEE / 0x034CC8
    for v9f in (0, 1):
        for v80 in (0, 1):
            for v9a in (0, 5):
                for v7c in (0, 3):
                    for x in (0.0, 0.05, 0.2, -1.0):
                        st = {'789F': v9f, '7880': v80, '789A': v9a, '787C': v7c, '7874': F(x)}
                        e = run(0x034C18, [(0xFFFF789F, 'u8', v9f), (0xFFFF7880, 'u8', v80), (0xFFFF789A, 'u16', v9a),
                                           (0xFFFF787C, 'u16', v7c), (0xFFFF7874, 'f32', F(x)), (0xFFFF787E, 'u8', 0xEE)])
                        v, a9f, a9a = m_034C18(st)
                        check(e.read_u8(0xFFFF787E) == (v if v is not None else 0xEE) and e.read_u8(0xFFFF789F) == a9f
                              and e.read_u16(0xFFFF789A) == a9a, 'I4')
                        n += 1
    for v9d in (0, 1, 5):
        for v7e in (0, 1):
            for x in (-1.0, -1e-30, 0.0, 0.03, 0.06, 0.2):
                st = {'789D': v9d, '787E': v7e, '7874': F(x)}
                e = run(0x034CEE, [(0xFFFF789D, 'u8', v9d), (0xFFFF787E, 'u8', v7e), (0xFFFF7874, 'f32', F(x)),
                                   (0xFFFF787C, 'u16', 0xBEEF)])
                v, a9d = m_034CEE(st)
                check(e.read_u16(0xFFFF787C) == (v if v is not None else 0xBEEF) and e.read_u8(0xFFFF789D) == a9d, 'I5')
                n += 1
    for r0 in (0, 1, 2, 0x101):
        for v in (0, 1, 2, 65535):
            e = run(0x034D2E, [(0xFFFF787C, 'u16', v)], stubs={0x0278D2: {'r0': r0}})
            check(e.read_u16(0xFFFF787C) == (v - 1 if (r0 & 0xFF) == 1 and v > 0 else v), 'I6')
            n += 1
    for x in (0.0, 34.9, 35.0, math.nan):
        for v in (87, 88, 243, 244):
            e = run(0x034CC8, [(0xFFFF6354, 'f32', F(x)), (0xFFFF7898, 'u16', v)])
            check(e.read_u8(0xFFFF7880) == m_034CC8({'6354': F(x), '7898': v}), 'I7')
            n += 1
    tab1 = [rom_lookup(0x0BE874, 0x0AC524, F(x)) for x in (0.0, 0.05, 0.2)]
    tab2 = [rom_lookup(0x0BE8AC, 0x0ACEF0, F(x)) for x in (0.0, 0.03125, 0.047, 0.0625, 0.2)]
    say(f'   I4/I5 0x034C18: [787E] := table 0x0AC524([7874]) = {tab1} on ([789F]==0 and [7880]==1) or'
        f' ([789A]!=0 and [787C]==0); 0x034CEE: [787C] := table 0x0ACEF0([7874]) = {tab2} (or {C[0xCBC46]} when'
        f' [7874] < {C[0xCC090]}) when [789D]!=0 and [787E]==0')
    say(f'   I6 0x034D2E: [787C] -= 1 while 0x0278D2() == 1;  I7 0x034CC8: [7880] = ([7898] >= ({C[0xCBC42]} if'
        f' [6354] < {C[0xCC08C]} else {C[0xCBC44]}))')
    say(f'   {n} cases, all match the models')


# ================================================================== J
STK = E.STACK_TOP - 8


def m_06847E(a, b, c, thr, dis, b36f4, w, g, cnt, b94ab, cc=C):
    D = 1 if b36f4 == 0xFF else (2 if b36f4 == 0xA5 else 0)
    if dis & 0xFF == 0:
        wv, gv = w, g
    else:
        wv, gv = 0.0, 0.0
    r10 = b
    if c & 0xFF != 0 and cc[0xC5164] > gv:
        if cnt >= (thr & 0xFFFF):
            r10 = 1
        cnt = min(cnt + 1, 0xFFFF)
    else:
        cnt = 0
    flag = 1 if (b94ab == 1 and (r10 & 0xFF) == 1 and (a & 0xFF) == 1 and (D == 2 or wv > cc[0xC517C])) else 0
    return flag, cnt


def run_06847E(a, b, c, thr, dis, b36f4, w, g, cnt, b94ab):
    ram = [(STK, 'u32', thr), (STK + 4, 'u32', dis), (0xFFFF36F4, 'u8', b36f4), (0xFFFF94AB, 'u8', b94ab),
           (0xFFFF9526, 'u16', cnt)]
    if dis & 0xFF == 0:
        ram += [(0xFFFF7484, 'f32', w), (0xFFFF7D68, 'f32', g)]
    return run(0x06847E, ram, regs={4: 0x097590, 5: a, 6: b, 7: c, 15: STK})


def sec_J():
    say('\n== J  0x06847E (second reader of [7484]) and its only caller 0x068304 ==')
    struct_fields = {o: struct.unpack('>I', ROM[0x097590 + o:0x097594 + o])[0] for o in (4, 92, 264)}
    say('   struct 0x097590: +4 -> 0x%08X  +92 -> 0x%08X  +264 -> 0x%08X' % (struct_fields[4], struct_fields[92],
                                                                         struct_fields[264]))
    check(struct_fields == {4: 0xFFFF94AB, 92: 0xFFFF94AD, 264: 0xFFFF9526}, 'J struct')
    n = 0
    cases = []
    for w in (4.5, up1(4.5), dn1(4.5), 1.9, 10.0, math.nan):
        for b36 in (0, 0xFF, 0xA5):
            for g in (C[0xC5164], dn1(C[0xC5164]), 0.0):
                for cnt, thr in ((0, 1), (1, 1), (0, 0), (65535, 1), (5, 6)):
                    cases.append((1, 0, 1, thr, 0, b36, F(w), F(g), cnt, 1))
    for _ in range(4000):
        cases.append((RNG.choice((0, 1, 2, 0x101)), RNG.choice((0, 1, 2)), RNG.choice((0, 1, 0x100)),
                      RNG.choice((0, 1, 2, 0x10001)), RNG.choice((0, 0, 0, 1, 0x100)), RNG.choice((0, 0xFF, 0xA5, 1)),
                      F(RNG.choice((4.5, 1.9, RNG.uniform(0, 9)))), F(RNG.choice((0.0, 0.1, 0.2, 0.3))),
                      RNG.choice((0, 1, 2, 65534, 65535)), RNG.choice((0, 1, 2))))
    for cs in cases:
        e = run_06847E(*cs)
        flag, cnt = m_06847E(*cs)
        check(e.read_u8(0xFFFF94AD) == flag and e.read_u16(0xFFFF9526) == cnt, f'J {cs}')
        check(written(e) == {0xFFFF94AD} | span(0xFFFF9526, 2), 'J write set')
        n += 1
    say(f'   J1 {n} cases match: [9526] counts calls while r7 != 0 and [7D68] < {C[0xC5164]:.2f} (sat 65535, else 0);'
        f' [94AD] = ([94AB]==1 and (r6 or [9526] >= thr) and r5 and (0x0582AC()==2 or [7484] > {C[0xC517C]}))')
    # W edge: 4.5 exactly does not pass
    e = run_06847E(1, 1, 0, 0, 0, 0, F(4.5), 0.0, 0, 1)
    e2 = run_06847E(1, 1, 0, 0, 0, 0, up1(4.5), 0.0, 0, 1)
    check(e.read_u8(0xFFFF94AD) == 0 and e2.read_u8(0xFFFF94AD) == 1, 'J W edge')
    say('   J1 edge: [7484]=4.5 -> [94AD]=0; 4.5+ulp -> 1 (other terms passing)')
    # J2 the caller: capture the arguments
    caps = []

    def cap(m):
        caps.append((m.R[4], m.R[5], m.R[6], m.R[7], m.read_u32(m.R[15]), m.read_u32(m.R[15] + 4)))
    for r_ab in (0, 1, 2):
        for b36 in (0, 0xA5):
            for rpm in (500.0, 2000.0, 20000.0):
                ram = [(0xFFFF69F0, 'f32', F(RNG.choice((0.0, 0.5)))), (0xFFFF63FC, 'f32', F(RNG.choice((0.0, 0.5)))),
                       (0xFFFF6624, 'f32', F(rpm)), (0xFFFF6A22, 'u16', RNG.choice((0, 30))),
                       (0xFFFF36F4, 'u8', b36), (0xFFFF94D2, 'u16', 3), (0xFFFF94D4, 'u16', 200),
                       (0xFFFF94D6, 'u16', 400), (0xFFFF9358, 'f32', F(50.0))]
                run(0x068304, ram, stubs={0x03AB20: {'r0': r_ab}, 0x06847E: {'fn': cap}})
                n += 1
    for r4, r5, r6, r7, s0, s1 in caps:
        check(r4 == 0x097590 and s1 == 0 and s0 in (0, cw(0xC48F6)) and r5 in (0, 1), 'J2 args')
    say(f'   J2 0x068304 run whole ({len(caps)} cases, 0x03AB20 stubbed): every call of 0x06847E has r4 = 0x097590,'
        f' second stack argument = 0 (so [7484] and [7D68] are always read), first = {sorted({c[4] for c in caps})}')


# ================================================================== Z
def sec_Z():
    say('\n== Z  stock vs 20.19c vs 20.19e ==')
    bins = {'stock': open(STOCK_PATH, 'rb').read(), '20.19c': ROM, '20.19e': open(R19E_PATH, 'rb').read()}
    spans = [(0x034488, 0x034EC8, 'AFL code + pools 0x034488..0x034EC7'), (0x068304, 0x0687FC, '0x068304/0x06847E + pools'),
             (0x063A5C, 0x063A9C, 'struct 0x063A5C'), (0x097590, 0x0976A0, 'struct 0x097590'),
             (0x022F92, 0x022FF4, '0x022F92 + pool'), (0x0297F4, 0x029808, '0x0297F4/0x029804'),
             (0x029824, 0x029828, '0x029824'), (0x029928, 0x02992C, 'pool 0x029928'), (0x029BA4, 0x029BA8, '0x029BA4'),
             (0x0582AC, 0x0582D2, '0x0582AC'), (0x058544, 0x058548, 'pool 0x058544'),
             (0x0BDBCC, 0x0BDD02, '0x0BDBCC..0x0BDD01'), (0x0BE53C, 0x0BE628, 'helpers 0x0BE53C..0x0BE627'),
             (0x0BE830, 0x0BE960, 'helpers 0x0BE830..0x0BE95F'), (0x0BEA40, 0x0BEAB8, 'helpers 0x0BEA40..0x0BEAB7')]
    for lo, hi, what in spans:
        same = len({bins[k][lo:hi] for k in bins}) == 1
        check(same, f'Z code differs: {what}')
    say(f'   {len(spans)} code / struct spans byte-identical in all three bins')
    for rec in (0x0AC524, 0x0ACEF0):
        t = [DT.read_table(bins[k], rec) for k in bins]
        check(all((x['axes'], x['values']) == (t[0]['axes'], t[0]['values']) for x in t), f'Z table {rec:06X}')
    say('   tables 0x0AC524 / 0x0ACEF0 identical in all three bins')
    diff = []
    cal = [(a, 'u8') for a in range(0xCBBE4, 0xCBBEF)] + [(a, 'u16') for a in (0xCBC40, 0xCBC42, 0xCBC44, 0xCBC46)] + \
          [(a, 'f32') for a in range(0xCC020, 0xCC094, 4)] + [(a, 'f32') for a in (0xC5164, 0xC5168, 0xC516C, 0xC517C)]
    for a, kd in cal:
        n = {'u8': 1, 'u16': 2, 'f32': 4}[kd]
        vs = [bins[k][a:a + n] for k in bins]
        if len(set(vs)) > 1:
            diff.append((a, [cf(a, bins[k]) for k in bins]))
    for a, vs in diff:
        say(f'   differs: 0x{a:06X}  stock {vs[0]:g}  20.19c {vs[1]:g}  20.19e {vs[2]:g}')
    check([a for a, _ in diff] == [0xCC074, 0xCC078, 0xCC07C], 'Z only the airflow ranges differ')
    check(bins['20.19c'][0xCC074:0xCC080] == bins['20.19e'][0xCC074:0xCC080], 'Z 19c == 19e ranges')
    for k in bins:
        ck_ = Cal(bins[k])
        row = []
        for x in (5.0, 5.8, 8.0, 12.0, 30.0, 45.0, 60.0):
            e = run(0x034D52, [(0xFFFF63C4, 'f32', F(x)), (A78A0, 'u8', 0)], rom=bins[k])
            check((e.read_u8(A78A5), e.read_u8(A787F)) == m_034D52(F(x), 0, ck_), f'Z {k} {x}')
            row.append(f'{x:g}->{e.read_u8(A787F)}')
        say(f'   {k:7s} [63C4] -> cell: ' + ' '.join(row))


# ================================================================== K (review: settles the disputed items)
def rec_put_bits(e, a, bits):
    e.ram_u32(a, bits & 0xFFFFFFFF)
    e.ram_u16(a + 4, ck(bits))
    e.ram_u16(a + 6, ck(bits))


def read_st(e, extra):
    st = dict(extra)
    st['cells'] = [e.read_f32(CELLS + 8 * i) for i in range(4)]
    st['idx'] = e.read_u8(A787F)
    st['a0'] = e.read_u8(A78A0)
    st['g84'] = e.read_u8(A7884)
    st['n9'] = e.read_u8(A78A9)
    st['afl'] = e.read_f32(A7878)
    st['p6'] = e.read_u8(A78A6)
    st['m1'] = e.read_u8(A78A1)
    st['n81'] = e.read_u8(A7881)
    st['n82'] = e.read_u8(A7882)
    st['s40'] = e.read_f32(0xFFFF6540)
    st['t'] = e.read_f32(0xFFFF77C8)
    st['w0'] = e.read_f32(0xFFFF7704)
    st['ba8'] = e.read_f32(0xFFFF7BA8)
    return st


def sec_K():
    say('\n== K  review cases (C11, C32, C42, [63FC] writer, start-up, one-way cell states) ==')
    # K1 (C11): the [77C8] substitution, NaN included; mode 1 never reaches it with a NaN / inf [77C8]
    rows = []
    for mode in (0, 1):
        for t in (math.nan, 2.0 ** -13, -2.0 ** -13, up1(2.0 ** -13), math.inf, -math.inf, 1.0):
            st = base_seq(mode)
            st.update(n9=100, w0=F(0.95), t=t, s40=F(t) if math.isfinite(t) else 1.0)
            e = run(0x034884, st_ram(st))
            why = check_034884(st, e, f'K1 mode {mode} t {t}')
            rows.append((mode, t, why))
    got = {(m, ('nan' if t != t else t)): w for m, t, w in rows}
    check(got[(0, 'nan')] == 'sample down', 'K1 NaN [77C8] replaced by 1.0 in mode 0 (e = W0 = 0.95 votes down)')
    check(got[(0, math.inf)] == 'sample up' and got[(0, -math.inf)] == 'sample up', 'K1 inf: 1/t = 0, e = W0 + 1')
    check(got[(0, 2.0 ** -13)] == got[(0, -2.0 ** -13)] == 'sample down', 'K1 edges replaced')
    check(got[(1, 'nan')] == got[(1, math.inf)] == got[(1, -math.inf)] == 'abort dt', 'K1 mode 1 NaN/inf dt aborts')
    say('   K1 W0=0.95: mode 0 [77C8]=NaN -> ' + got[(0, 'nan')] + ' (replaced by 1.0; a NaN e would vote up);'
        ' +-inf -> ' + got[(0, math.inf)] + ' (1/inf = 0); +-2^-13 -> replaced; 2^-13+ulp -> ' + got[(0, up1(2.0 ** -13))]
        + ';  mode 1 NaN / +-inf -> ' + got[(1, 'nan')] + ' (dt = |[6540]-[77C8]| not < 0.05)')
    # K2 (C32): what 0x0344EE accepts
    base = [E.f2b(F(0.01 * j)) for j in range(4)]
    b = 0x3C23D70A                                   # 0.01
    sw = ((b & 0xFFFF) << 16) | (b >> 16)            # halves swapped: same check word
    check(ck(b) == ck(sw), 'K2 swapped halves keep CK')
    cases = [('swapped halves 0x%08X (%g)' % (sw, E.b2f(sw)), [b, sw] + base[2:], None, 0),
             ('NaN 0x7FC00001 with matching CK', [0x7FC00001] + base[1:], None, 0),
             ('+inf with matching CK', [0x7F800000] + base[1:], None, 0),
             ('value +1 lsb, CK unchanged', base, lambda e: e.ram_u32(CELLS, e.read_u32(CELLS) + 1), 1),
             ('one check word damaged', base, lambda e: e.ram_u16(CELLS + 4, e.read_u16(CELLS + 4) ^ 1), 0),
             ('both check words damaged', base, lambda e: (e.ram_u16(CELLS + 4, e.read_u16(CELLS + 4) ^ 1),
                                                           e.ram_u16(CELLS + 6, e.read_u16(CELLS + 6) ^ 1)), 1)]
    for name, vals, tamper, want in cases:
        e = new_emu()
        for j, v in enumerate(vals):
            rec_put_bits(e, CELLS + 8 * j, v)
        if tamper:
            tamper(e)
        e = run(0x0344EE, [], e=e)
        check(e.R[0] == want, f'K2 {name}')
        say(f'   K2 0x0344EE {name:<40} -> r0 = {e.R[0]}' + ('  (record repaired)' if want == 0 and tamper else ''))
        if want == 0 and tamper:
            check(rec_ok(e, CELLS), 'K2 repaired')
    # K3 (C42): window states.  (a) not produced by a reset: held while G1-G4 pass
    st = g_base()
    st.update({'78A9': 200, '7881': 200, '7882': 7})
    e = new_emu()
    for a, kd, v in g_ram(st, [0.0] * 4):
        put(e, a, kd, v)
    for _ in range(500):
        run(0x03452A, [], e=e)
    check((e.read_u8(A7881), e.read_u8(A7882), e.read_u32(CELLS + 8), e.read_u8(A7884)) == (200, 7, 0, 1), 'K3a')
    say(f'   K3a [7881]=200 [7882]=7 [78A9]=200, every gate open, W0=1.05: 500 whole passes of 0x03452A ->'
        f' [7881]={e.read_u8(A7881)} [7882]={e.read_u8(A7882)} [78A9]={e.read_u8(A78A9)} cell 1 = {e.read_f32(CELLS + 8)}'
        ' (no reset, no step)')
    # (b) zero-filled window bytes: the first pass resets (G2: [78A9] <= 1 < 63; with [78A7] = 0 G1 fails too)
    for a7, why in ((200, 'G2'), (0, 'G1')):
        st = g_base()
        st.update({'78A9': 0, '7881': 0, '7882': 0, '78A7': a7, '78A8': a7})
        e = run(0x03452A, g_ram(st, [0.0] * 4))
        check(e.read_u8(A7881) == 0 and e.read_u8(A7882) == 0x80, f'K3b {why}')
    say('   K3b window bytes all 0 (a zero-fill reading of the reset): the first pass resets ([7882] := 128) via G2'
        ' (all gates open) or G1 ([78A7] = [78A8] = 0)')
    # (c) random walk from a reset state, mode byte in {0, 1, 2}: invariants
    paths, idle_modes = {}, set()
    for walk in range(6):
        e = new_emu()
        st0 = base_seq(1)
        for a, kd, v in st_ram(st0):
            put(e, a, kd, v)
        mode = 1
        for k in range(4000):
            r = RNG.random()
            if r < 0.02:
                mode = RNG.choice((0, 1, 2))
            put(e, A78A6, 'u8', e.read_u8(A78A1))
            put(e, A78A1, 'u8', mode)
            put(e, A7884, 'u8', 1 if RNG.random() < 0.995 else 0)
            put(e, 0xFFFF6540, 'f32', F(1.0 + (0.06 if RNG.random() < 0.01 else RNG.uniform(-0.04, 0.04))))
            put(e, 0xFFFF7704, 'f32', F(RNG.choice((1.05, 0.95, 1.0, 1.05, RNG.uniform(0.9, 1.1)))))
            st = read_st(e, {})
            e = run(0x034884, [], e=e)
            why = check_034884(st, e, f'K3c walk {walk} pass {k}')
            paths[why] = paths.get(why, 0) + 1
            if why == 'idle':
                idle_modes.add((st['p6'], st['m1']))
            n81, n82 = e.read_u8(A7881), e.read_u8(A7882)
            check(n81 <= 40 and 88 <= n82 <= 168, f'K3c invariant n81={n81} n82={n82}')
            check(mode != 0 or n81 <= 16, f'K3c mode 0 n81={n81}')
            run(0x034B1C, [], e=e)
    check(paths.get('idle', 0) > 0 and all(p == 0 and m not in (0, 1) for p, m in idle_modes), f'K3c idle {idle_modes}')
    say(f'   K3c 24,000 passes from a reset state, mode byte switching among 0/1/2: [7881] <= 40 (<= 16 in mode 0)'
        f' and 88 <= [7882] <= 168 always; "idle" exits only with (previous, current) mode = {sorted(idle_modes)};'
        f' paths {dict(sorted(paths.items()))}')
    # K4: 0x034488 indexes the cells with an unchecked [787F]
    for idx in (3, 4, 5, 255):
        e = new_emu()
        for j in range(4):
            put(e, CELLS + 8 * j, 'rec', F(0.01 * (j + 1)))
        if idx >= 4:
            put(e, CELLS + 8 * idx, 'f32', F(0.123))
        e = run(0x034488, [(A787F, 'u8', idx), (0xFFFF6254, 'u8', 1)], e=e)
        want = F(0.04) if idx == 3 else F(0.123)
        check(e.read_f32(A7878) == want, f'K4 idx {idx}')
    say('   K4 0x034488 with [787F] = 4 / 5 / 255 reads float [0xFFFF316C + 8*[787F]] (0xFFFF318C .. 0xFFFF3964)'
        ' and seeds [7878] from it')
    # K5: the writer of [63FC] -- 0x01FE46 run whole: [63FC] = [63F8](after) - [63F8](before)
    rng = random.Random(7)
    for i in range(300):
        e = new_emu()
        for a in range(0xFFFF63B4, 0xFFFF6440, 4):
            e.ram_f32(a, F(rng.choice((0.0, 1.0, rng.uniform(-2, 5), rng.uniform(0, 200)))))
        for a in (0xFFFF6624, 0xFFFF679C, 0xFFFF620C, 0xFFFF6350, 0xFFFF6364, 0xFFFF65FC, 0xFFFF62DC, 0xFFFF73D0,
                  0xFFFF62E4, 0xFFFF6898, 0xFFFF69F4, 0xFFFF40B4, 0xFFFF90A8):
            e.ram_f32(a, F(rng.uniform(0, 6000) if a == 0xFFFF6624 else rng.uniform(-5, 200)))
        for a in (0xFFFF9714, 0xFFFF726C, 0xFFFF647C, 0xFFFF6254, 0xFFFF6419, 0xFFFF641C, 0xFFFF641B, 0xFFFF6404):
            e.ram_u8(a, rng.choice((0, 1, 2)))
        old = e.read_f32(0xFFFF63F8)
        e.writes = {}
        e.uninit_reads = set()
        e.call(0x01FE46)
        new, d = e.read_f32(0xFFFF63F8), e.read_f32(0xFFFF63FC)
        check(E.f2b(d) == E.f2b(fsub(new, old)) and 0xFFFF63FC in e.writes, f'K5 #{i}')
    say('   K5 0x01FE46 run whole (300 random states, uninitialised reads allowed): [63FC] written every call and'
        ' equal to [63F8](after) - [63F8](before), bit-exact')
    # K6: 0x04793C -- every check failure sets r10 = 1, stored to byte [5B8D] by the tail 0x01001C
    checks = [0x004BEC, 0x0983B4, 0x09845C, 0x011E4C, 0x0128D8, 0x014274, 0x01429C, 0x018630, 0x01CA48, 0x02A7CC,
              0x02EDE4, 0x03E2B0, 0x03E868, 0x04BF88, 0x04F194, 0x058A9C, 0x0593F0, 0x05AE9E, 0x05CE10, 0x05CF5C,
              0x0614F4, 0x01382C, 0x05F810, 0x060548, 0x02C034]
    quiet = [0x05B5D8, 0x05B690, 0x0951F8, 0x05B73C, 0x05CB1C, 0x087074, 0x05940A, 0x01CB1C, 0x004BCA]

    def run_793c(fail=None, b36b8=0, w36be=0xAA55, w3d1a=0x00FF):
        stubs = {a: {'r0': (1 if a == fail else 0)} for a in checks}
        stubs.update({a: {'r0': 0} for a in quiet})
        e = run(0x04793C, [(0xFFFF36BE, 'u16', w36be), (0xFFFF36B8, 'u8', b36b8), (0xFFFF5B8D, 'u8', 0x77),
                           (0xFFFF3D1A, 'u16', w3d1a)],
                stubs=stubs, allow_uninit=set(range(0xFFFF3D00, 0xFFFF3D20)))
        return e.read_u8(0xFFFF5B8D)
    check(run_793c() == 0 and run_793c(w36be=0x4055) == 0 and run_793c(w3d1a=0x5AA5) == 0, 'K6 all pass')
    for a in checks:
        check(run_793c(fail=a) == 1, f'K6 {a:06X}')
    for w in (0x0000, 0x55AA, 0xAA54):
        check(run_793c(w36be=w) == 1, f'K6 36BE {w:04X}')
    check(run_793c(b36b8=0xA5) == 1 and run_793c(b36b8=0xA4) == 0, 'K6 36B8')
    check(run_793c(w3d1a=0x00FE) == 1 and run_793c(w3d1a=0x0000) == 1, 'K6 3D1A pair')
    say(f'   K6 0x04793C (callees stubbed): [5B8D] = 0 when every check passes ([36BE] 0xAA55 or 0x4055, word [3D1A]'
        f' a value:~value pair); = 1 when any one of the {len(checks)} called checks returns non-zero, when [36BE] is'
        ' 0x0000 / 0x55AA / 0xAA54, when byte [36B8] == 0xA5, or when word [3D1A] is not a value:~value pair')
    # K7: one-way cell states -- G3 can never pass, so nothing rewrites the cell
    res = []
    for bits, w0 in ((sw, 1.05), (0x7FC00001, 1.05), (E.f2b(F(0.3)), 0.95), (E.f2b(F(0.27)), 0.95),
                     (E.f2b(F(-0.28)), 1.05), (0x7F800000, 0.95), (E.f2b(F(0.2699)), 1.05), (E.f2b(F(0.26)), 0.95)):
        st = g_base()
        st['7704'] = F(w0)
        e = new_emu()
        for a, kd, v in g_ram(st, [0.0] * 4):
            put(e, a, kd, v)
        rec_put_bits(e, CELLS + 8, bits)
        start, nch, first = bits, 0, None
        for _ in range(1500):
            run(0x03452A, [], e=e)
            cur = e.read_u32(CELLS + 8)
            if cur != bits:
                nch += 1
                bits = cur
                first = E.b2f(cur) if first is None else first
        res.append((start, nch, first, E.b2f(bits), e.read_f32(A7878)))
    for start, nch, first, endv, afl in res:
        frozen = E.b2f(start) != E.b2f(start) or abs(E.b2f(start)) >= 0.27
        check((nch == 0) == frozen, f'K7 {start:08X}')
        if not frozen:
            check(first == 0.25, 'K7 the first write is the +-0.25 cell clamp')
    say('   K7 cell 1 (record valid) under 1,500 whole passes, every other gate open: ' +
        '; '.join(f'{E.b2f(s):g} -> ' + ('frozen' if n == 0 else f'first write {f1:g}, {n} writes, now {v:g}') +
                  f' ([7878] {a:g})' for s, n, f1, v, a in res))


# ================================================================== L (independent audit, 2026-11-27)
def fmul(a, b):
    return _rz(lambda: Fraction(a) * Fraction(b), a * b) if _fin(a, b) else F(a * b)


def max_(a, b):                             # 0x0BE960: fr4 if fr4 > fr5 else fr5
    return a if a > b else b


def min_(a, b):                             # 0x0BE970: fr4 if fr5 > fr4 else fr5
    return a if b > a else b


def l_run_pass(e, x_of_k, k):
    put(e, 0xFFFF63C4, 'f32', F(x_of_k(k)))
    run(0x03452A, [], e=e)


def l_window(cells, switch_at, x1=30.0, x2=15.0, w0=1.05, calls=63 + 41 * 2):
    """whole 0x03452A passes, every gate open, mode 1; [63C4] = x1 before pass switch_at and x2 from it"""
    st = g_base()
    st.update({'63C4': x1, '7704': F(w0), '7878': cells[2]})
    e = new_emu()
    for a, kd, v in g_ram(st, cells):
        put(e, a, kd, v)
    steps, at = [], {}
    prev = list(cells)
    for k in range(1, calls + 1):
        l_run_pass(e, lambda kk: x2 if kk >= switch_at else x1, k)
        cur = [e.read_f32(CELLS + 8 * j) for j in range(4)]
        if cur != prev:
            steps.append((k, [j for j in range(4) if cur[j] != prev[j]], cur))
            prev = cur
        at[k] = (e.read_u8(A787F), e.read_u8(A7881), e.read_u8(A7882), e.read_f32(A7878))
    return steps, at


def m_02782C(g, afl, a30, a34, b52, b53, c=C):
    """0x02782C with r4 = 0x06381C (+0 0xFFFF6A53, +4 0xFFFF6A00, +8 0xFFFF6A04) and r5 = 0 (caller 0x026FA8)"""
    if not (c.X[0xC4280] > g):                      # 02784C fcmp/gt fr14,fr9: T = 4e-6 > g
        b53 |= 0x80
    elif c.X[0xC427C] > g:                          # 02785E: T = 0.0 > g
        b53 &= 0x7F
    x = fmul(fadd(afl, 1.0), a30)                   # 02786C fadd fr9,fr8 / 027884 fmul fr9,fr8 (slot, always)
    if (b53 & 0x80) and (b52 & 0x20):
        x = fmul(x, a34)                            # 027892
    if outside(g, 0.0, F(2.0 ** -18)):
        y = min_(fdiv(x, fmul(g, 100.0)), 0.125)    # 0278B2 fmul, 0278B4 fdiv, 0x0BE970
    else:
        y = 0.125
    return b53, x, y


def m_071AFA(b65f6, b7449, a653c, a77c8, a76d4, afl, old97b4, c=C):
    if b65f6 == 1 or b7449 == 0:                    # 071B16 bt/s, 071B1E bt
        return 1.0, 1.0
    v = fadd(fadd(fsub(a653c, a77c8), a76d4), afl)  # 071B20 / 071B22 / 071B24
    m = max_(v, 0.0)                                # 0x0BE960
    return m, lag(m, old97b4, c.X[0xC50B4], F(2.0 ** -11))


def sec_L():
    say('\n== L  independent audit: window attribution, [65F6] in a whole pass, the 0x4055 clear path, other readers'
        ' of [7878], writers of [6254] ==')
    C.X = {a: cf(a) for a in (0xC4280, 0xC427C, 0xC50B4)}
    # L1 a range change does not restart the window: votes are credited to the cell current at the decision pass
    base, _ = l_window([0.0] * 4, 10 ** 9)
    check([(k, j) for k, j, _c in base[:2]] == [(103, [2]), (144, [2])], 'L1 control: 40 samples at 30 -> cell 2')
    st1, at1 = l_window([0.0] * 4, 103)
    check(at1[102][:3] == (2, 40, 168), 'L1 window full in range 2 at pass 102')
    check([(k, j) for k, j, _c in st1[:2]] == [(103, [1]), (144, [1])] and st1[0][2][1] == C[0xCC05C]
          and st1[0][2][2] == 0.0, 'L1 decision on the range-1 pass steps cell 1 with range-2 votes')
    st2, _ = l_window([0.0] * 4, 90)
    check([(k, j) for k, j, _c in st2[:1]] == [(103, [1])], 'L1 change at sample 28: no restart, cell 1 steps at 103')
    st3, _ = l_window([0.0, F(0.015), 0.0, 0.0], 103)
    check(st3[0][0] == 103 and st3[0][1] == [1] and st3[0][2][1] == fadd(F(0.015), C[0xCC05C]), 'L1 cells 0.015 apart')
    st4, at4 = l_window([0.0, F(0.05), 0.0, 0.0], 103)
    check(all(k > 103 + 40 for k, _j, _c in st4) and at4[103][1:3] == (0, 128), 'L1 cells 0.05 apart: G3 restarts')
    say('   L1 whole passes, gates open, W0=1.05, mode 1, [63C4]=30 (cell 2 in 20.19c) for passes 1..102 (40 samples, '
        '[7881]=40 [7882]=168 at pass 102):')
    say(f'      no change            -> steps {[(k, j) for k, j, _c in base[:2]]}  (cell index list per step)')
    say(f'      [63C4]=15 at pass 103 -> steps {[(k, j) for k, j, _c in st1[:2]]}: cell 1 takes the window collected in'
        ' range 2')
    say(f'      [63C4]=15 from pass 90 -> steps {[(k, j) for k, j, _c in st2[:2]]} (27 samples at 30, 13 at 15; no restart)')
    say(f'      cells 0 / 0.015       -> cell 1 {st3[0][2][1]:.6f} at pass {st3[0][0]} (|0.015| < 0.02: G3 passes)')
    say(f'      cells 0 / 0.05        -> pass 103 [7881]={at4[103][1]} [7882]={at4[103][2]} (G3 reset), first step'
        f' {st4[0][0] if st4 else None}')
    # L2 [65F6] == 1 in a WHOLE pass: [7884] = 0 the same pass, so [78A9] = 0 (D10's "<= 1" needs [7884] = 1)
    for n9 in (0, 62, 100, 255):
        st = g_base()
        st.update({'65F6': 1, '78A9': n9})
        e = run(0x03452A, g_ram(st, [0.0] * 4))
        check(e.read_u8(A7884) == 0 and e.read_u8(A78A9) == 0 and e.read_u8(A787F) == 0, f'L2 {n9}')
    say('   L2 [65F6]=1, every other gate open, [78A9] in {0, 62, 100, 255}: one whole pass -> [7884]=0, [78A9]=0,'
        ' [787F]=0')
    # L3 0x047C40 calls 0x048732 (-> 0x0344BA, the cell clear) iff word [36BE] == 0x4055 at its entry and [8EDC] == 0
    quiet = [0x006B5A, 0x0067DC, 0x05AA74, 0x0BEAB8, 0x05CD4A, 0x0BE81C, 0x006BF0, 0x0BE82C, 0x00FACA,
             0x02271C, 0x05AA9A, 0x05B1F6, 0x05CAD8, 0x05CA22, 0x05B0A0, 0x022724, 0x021F4A, 0x03E6B8, 0x03E6E0,
             0x09E178, 0x0A67CC, 0x05AEB8, 0x091368, 0x028200]
    n = 0
    for w36be in (0x4055, 0xAA55, 0x0000, 0x4054, 0x4155, 0xC055):
        for b8edc in (0x00, 0x01, 0xFF):
            for ev in (0x00, 0x02, 0xFF):
                e = new_emu()
                hit = []
                for a in quiet:
                    e.stub(a, r0=0)
                e.stub(0x006BC4, r0=ev)
                e.stub(0x048732, fn=lambda em, hit=hit: hit.append(em.pc))
                put(e, 0xFFFF36BE, 'u16', w36be)
                put(e, 0xFFFF8EDC, 'u8', b8edc)
                stop = e.call(0x047C40, stop_at=(0x047DAA, 0x0486E0))
                want = 1 if (w36be == 0x4055 and b8edc == 0) else 0
                check(len(hit) == want and stop == (0x047DAA if b8edc == 0 else 0x0486E0), f'L3 {w36be:04X} {b8edc} {ev}')
                n += 1
    e = run(0x05D070, [(0xFFFF36BE, 'u16', 0)])
    check(e.read_u16(0xFFFF36BE) == 0x4055 and written(e) == span(0xFFFF36BE, 2), 'L3 0x05D070 writes 0x4055')
    e = new_emu()
    for a in (0x08707C, 0x097514, 0x0662C4):
        e.stub(a, r0=0)
    e = run(0x05D032, [(0xFFFF36BE, 'u16', 0x4055), (0xFFFF3204, 'f32', 0.0)], e=e)
    check(e.read_u16(0xFFFF36BE) == 0xAA55, 'L3 0x05D032 writes 0xAA55')
    say(f'   L3 0x047C40 from entry to 0x047DAA / 0x0486E0 ({n} cases; its callees stubbed, 0x006BC4 -> 0 / 2 / 0xFF):'
        ' 0x048732 is called iff word [36BE] == 0x4055 and byte [8EDC] == 0; 0x05D070 writes word [36BE] = 0x4055,'
        ' 0x05D032 (called at 0x04863A on the same arm) writes 0xAA55')
    # L4 other readers of [7878]: 0x02782C, 0x071AFA, 0x0A86FE, 0x05D2DA against models
    n = 0
    for i in range(400):
        g = F(RNG.choice((0.0, -1e-6, 4e-6, 3.9e-6, 2.0 ** -18, 1e-5, 0.05, 0.12, -0.01, RNG.uniform(-0.01, 0.2))))
        afl = F(RNG.choice((0.0, 0.25, -0.25, 0.1, RNG.uniform(-0.5, 0.5))))
        a30, a34 = F(RNG.uniform(0.0, 0.35)), F(RNG.choice((1.0, RNG.uniform(0.8, 1.2))))
        b52, b53 = RNG.choice((0, 0x20, 0xFF, 0xDF)), RNG.choice((0, 0x80, 0xFF, 0x7F))
        e = run(0x02782C, [(0xFFFF7D68, 'f32', g), (A7878, 'f32', afl), (0xFFFF6A30, 'f32', a30),
                           (0xFFFF6A34, 'f32', a34), (0xFFFF6A52, 'u8', b52), (0xFFFF6A53, 'u8', b53)],
                regs={4: 0x06381C, 5: 0})
        wb53, x, y = m_02782C(g, afl, a30, a34, b52, b53)
        check(e.read_u8(0xFFFF6A53) == wb53 and E.f2b(e.read_f32(0xFFFF6A00)) == E.f2b(x)
              and E.f2b(e.read_f32(0xFFFF6A04)) == E.f2b(y), f'L4 02782C #{i}')
        check(written(e) <= span(0xFFFF6A00, 8) | {0xFFFF6A53}, 'L4 02782C write set')
        n += 1
    for i in range(300):
        args = (RNG.choice((0, 1, 2)), RNG.choice((0, 1, 0x80)), F(RNG.uniform(0.8, 1.2)), F(RNG.uniform(0.8, 1.2)),
                F(RNG.uniform(-0.1, 0.1)), F(RNG.choice((0.0, 0.25, -0.25, RNG.uniform(-0.3, 0.3)))),
                F(RNG.uniform(-0.1, 1.2)))
        b65f6, b7449, a653c, a77c8, a76d4, afl, old = args
        e = run(0x071AFA, [(0xFFFF65F6, 'u8', b65f6), (0xFFFF7449, 'u8', b7449), (0xFFFF653C, 'f32', a653c),
                           (0xFFFF77C8, 'f32', a77c8), (0xFFFF76D4, 'f32', a76d4), (A7878, 'f32', afl),
                           (0xFFFF97B4, 'f32', old), (0xFFFF97B0, 'f32', 0.0)])
        w0, w1 = m_071AFA(*args)
        check(E.f2b(e.read_f32(0xFFFF97B0)) == E.f2b(F(w0)) and E.f2b(e.read_f32(0xFFFF97B4)) == E.f2b(F(w1)),
              f'L4 071AFA #{i}')
        check(written(e) == span(0xFFFF97B0, 8), 'L4 071AFA write set')
        n += 1
    for afl in (0.0, 0.001, 0.0078125, 0.25, -0.25, -1.0, 0.99, 1.5, -1.5, math.nan):
        e = run(0x0A86FE, [(A7878, 'f32', F(afl))])
        want = run(0x0BE5A8, [], fregs={4: fmul(F(afl), 100.0), 5: 0.78125, 6: -100.0}).R[0] & 0xFF
        check(e.read_u8(0xFFFFAF76) == want and written(e) == {0xFFFFAF76}, f'L4 0A86FE {afl}')
        e = run(0x05D2DA, [(A7878, 'f32', F(afl))])
        want2 = run(0x0BE5A8, [], fregs={4: F(afl), 5: 0.0078125, 6: -1.0}).R[0] & 0xFF
        check(e.R[0] == want2 and not written(e), f'L4 05D2DA {afl}')
        n += 2
    e0 = run(0x05D2DA, [(A7878, 'f32', 0.0)]).R[0]
    e1 = run(0x05D2DA, [(A7878, 'f32', F(0.003))]).R[0]
    e8 = run(0x05D2DA, [(A7878, 'f32', F(0.004))]).R[0]
    e12 = run(0x05D2DA, [(A7878, 'f32', F(0.011))]).R[0]
    e13 = run(0x05D2DA, [(A7878, 'f32', F(0.012))]).R[0]
    check(e0 == e1 == 128 and e8 == 129 and e12 == 129 and e13 == 130, 'L4 05D2DA resolution 1/128')
    say(f'   L4 {n} cases bit-exact: 0x02782C [6A00] = (1 + [7878]) * [6A30] (* [6A34] when bit 7 of [6A53] and bit 5'
        ' of [6A52]), [6A04] = min([6A00] / (100*[7D68]), 0.125); 0x071AFA [97B0] = max([653C] - [77C8] + [76D4] +'
        ' [7878], 0), [97B4] = lag of it (k = 0.125); 0x0A86FE byte [AF76] and 0x05D2DA r0 = byte views of [7878]')
    say(f'      0x05D2DA byte = clamp(trunc(([7878] + 1) / 0.0078125 + 0.5), 0, 255): [7878] = 0 / 0.003 / 0.004 / 0.011 /'
        f' 0.012 -> {e0} / {e1} / {e8} / {e12} / {e13} (first change after 4 cell steps of 0.001, then every 7.8)')
    # L5 the writers of [6254] that find_writers reports store only 0 or 1
    e = run(0x01DA98, [])
    check(e.read_u8(0xFFFF6254) == 1, 'L5 0x01DA98 stores 1')
    say('   L5 0x01DA98 writes byte [6254] = 1 (and 6252 / 6253 / 6255 / 6259 = 1, word [6250] = cal 0x0C3078);'
        ' 0x01DBC2 stores r0 = 1 (slot of 0x01DBBC) or 0 (0x01DBC0) -- bytes')


def main():
    md5 = hashlib.md5(ROM).hexdigest()
    check(md5 == '92cae8275cd4f9b473a3a9e36efe6449', f'reference bin md5 {md5}')
    say('emu_afl_learning.py  rom AE5L600L 20g rev 20.19c.bin  md5 ' + md5)
    for s in (sec_A, sec_B, sec_C, sec_D, sec_E, sec_F, sec_G, sec_H, sec_I, sec_J, sec_K, sec_L, sec_Z):
        s()
    say(f'\nOK  {NCHECK} checks, {STEPS} emulated instructions')
    return 0


if __name__ == '__main__':
    sys.exit(main())
