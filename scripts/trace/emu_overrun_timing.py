#!/usr/bin/env python3
"""Emulation check for disassembly/analysis/overrun_timing_trace.txt: what the overrun fuel cut does to timing.

    python3 scripts/trace/emu_overrun_timing.py

Reference bin: rom/AE5L600L 20g rev 20.19c.bin  md5 92cae8275cd4f9b473a3a9e36efe6449
Also read    : rom/ae5l600l.bin (stock) and rom/AE5L600L 20g rev 20.19e.bin (latest flashed) for the
               calibration comparison (every cell this file names is asserted equal or listed as different).

Functions run in scripts/sh2e_emu.py with their callees executed from ROM:
  0x041BE4 (GBR 0xFFFF8020)  the [8020] / [8028] term            0x0419BA  its caller (bsr x3 + bra)
  0x041A02  [802C] gate       0x041A48  [802D] edge latch          0x041A7E  the [8024] mode machine
  0x041954  reset of the 0x8020 block   0x0419CC  counters [802E] / [8030]
  0x03AAA4  the any-cut byte [7C68]     0x03AB20  its getter         0x03AB06  its reset
  0x03F00C  the bounds [7EC0] [7EC4] [7EC8] [7EE4] that clamp the logged timing cell
  0x03EF58  the byte [7EED] that triggers [7EC8]
  0x03FBBC  the blend weight [7F10]      0x04004A tail 0x04024A..0x040284 (the [7F0C] blend)
  0x03F368  whole function (post-sum clamp chain into [7E90]; and, third decode, one run per path to show
            which paths carry [8028])                              0x05D37E  SSM getter of id 0x11
  third decode (2026-11-27, after an adversarial review; see REVIEW HISTORY in the analysis file):
  0x036322  [79C8] (0x036978 stubbed to force [79F3])     0x042ED8  [80B4]
  0x03ED56  [7ED0] / [7ECC], the LOAD value of the [7EC0] cap      the [7F09] latch of 0x03F00C over a sequence
  the ladder-lags-one-pass sequence of 0x0419BA (table value written on two calls)
Python models written from the bytes are compared per case on every output cell; for the small functions
also on the exact set of RAM bytes written and the set of RAM cells read.  Table lookups are compared to a
Python interpolation with tolerance 1e-4 (no claim depends on the last bit of a float; corrections item 110).
A reader scan (CFG constant propagation from every census function, as fn_dump does) re-derives the reader
lists of the cut bytes that the analysis file classifies; the lists are LOWER BOUNDS (a base register taken
from a stack slot is not followed).

Names are neutral on purpose: [xxxx] is RAM 0xFFFFxxxx.  Nothing here establishes what an input IS.
Deterministic (fixed RNG seed); exits 0 when every assertion holds; runs in well under 15 minutes.
"""
import hashlib
import json
import math
import os
import random
import struct
import sys
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, 'scripts'))
sys.path.insert(0, os.path.join(REPO, 'scripts', 'mapping'))
import sh2e_emu as E            # noqa: E402
import desc_types as DT         # noqa: E402

BIN = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
ROM = open(BIN, 'rb').read()
assert hashlib.md5(ROM).hexdigest() == '92cae8275cd4f9b473a3a9e36efe6449', 'wrong reference bin'
STOCK = open(os.path.join(REPO, 'rom', 'ae5l600l.bin'), 'rb').read()
assert hashlib.md5(STOCK).hexdigest() == 'a8ea39d447f977e270e27ee670243c88', 'wrong stock bin'
R19E = open(os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19e.bin'), 'rb').read()
assert hashlib.md5(R19E).hexdigest() == 'a249be081121f49f20ae0b32f079f114', 'wrong 20.19e bin'

f2b, b2f = E.f2b, E.b2f
M32 = 0xFFFFFFFF
RNG = random.Random(0x041BE4)
NCASES = {}
NAN = float('nan')


def A(x):
    return 0xFFFF0000 | x


def u8(rom, a):
    return rom[a]


def u16(rom, a):
    return struct.unpack_from('>H', rom, a)[0]


def f32(rom, a):
    return struct.unpack_from('>f', rom, a)[0]


def s8(v):
    v &= 0xFF
    return v - 0x100 if v & 0x80 else v


def fgt(x, y):
    """fcmp/gt FRm,FRn with FRn = x, FRm = y: T = (x > y); false when either is NaN"""
    return x > y


def rz(q, fallback):
    if not math.isfinite(fallback):
        return b2f(f2b(fallback))
    if q == 0:
        return b2f(f2b(fallback))
    return b2f(E.rz_bits(q))


def rz_add(x, y):
    if not (math.isfinite(x) and math.isfinite(y)):
        return x + y
    return rz(Fraction(x) + Fraction(y), x + y)


def rz_mul(x, y):
    if not (math.isfinite(x) and math.isfinite(y)):
        return x * y
    return rz(Fraction(x) * Fraction(y), x * y)


def rz_sub(x, y):
    return rz_add(x, -y)


def fmin(a, b):     # 0x0BE970: fr4 = a, fr5 = b -> a if b > a else b
    return a if fgt(b, a) else b


def fmax(a, b):     # 0x0BE960: a if a > b else b
    return a if fgt(a, b) else b


def clamp(x, lo, hi):   # 0x0BE56C
    if not fgt(x, lo):
        return lo
    if fgt(hi, x):
        return x
    return hi


def outside(x, c, w):   # 0x0BE608
    return 1 if (fgt(rz_sub(c, w), x) or fgt(x, rz_add(c, w))) else 0


def interp(rec, x, rom=ROM):
    t = DT.read_table(rom, rec)
    ax, vals = t['axes']['x'], t['values']
    if x <= ax[0]:
        return vals[0]
    if x >= ax[-1]:
        return vals[-1]
    for i in range(len(ax) - 1):
        if ax[i] <= x <= ax[i + 1]:
            return vals[i] + (vals[i + 1] - vals[i]) * (x - ax[i]) / (ax[i + 1] - ax[i])
    raise AssertionError


def close(a, b, tol=1e-4):
    if isinstance(a, float) and math.isnan(a):
        return isinstance(b, float) and math.isnan(b)
    return abs(a - b) <= tol * max(1.0, abs(b))


# ------------------------------------------------------------------ emulator harness
SENT = {8: 0x88888888, 9: 0x99999999, 10: 0xAAAAAAAA, 11: 0xBBBBBBBB, 12: 0xCCCCCCCC, 13: 0xDDDDDDDD,
        14: 0xEEEEEEEE}
FSENT = {12: 0x3F8CCCCD, 13: 0x40133333, 14: 0x40566666, 15: 0x408CCCCD}
GBR_SENT = 0xFFFF1234


def poke(e, a, n, v):
    """write RAM WITHOUT marking it initialised: its first read lands in uninit_reads"""
    o = a - E.RAM_LO
    e.ram[o:o + n] = (v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big')


def pokef(e, a, x):
    poke(e, a, 4, f2b(x))


def peek(e, a, n):
    o = a - E.RAM_LO
    return int.from_bytes(e.ram[o:o + n], 'big')


def peekf(e, a):
    return b2f(peek(e, a, 4))


def fresh(e):
    e.init = bytearray(len(e.init))
    e.ram = bytearray(len(e.ram))
    e.uninit_reads.clear()
    e.writes.clear()
    e.stack_low = E.STACK_TOP
    e.steps = 0


def run(e, entry, check_saved=True, regs_extra=None, stop_at=()):
    regs = {i: RNG.getrandbits(32) for i in range(8)}
    regs.update(SENT)
    if regs_extra:
        regs.update(regs_extra)
    for i in range(12):
        e.FR[i] = RNG.getrandbits(32)
    for i, v in FSENT.items():
        e.FR[i] = v
    e.gbr = GBR_SENT
    r = e.call(entry, regs=regs, stop_at=stop_at)
    if not stop_at:
        assert r == 'return'
    if check_saved and not stop_at:
        for i, v in SENT.items():
            assert e.R[i] == v, f'{entry:06X}: r{i} not preserved'
        assert e.R[15] == E.STACK_TOP, 'r15 not restored'
        assert e.gbr == GBR_SENT, 'GBR not restored'
        for i, v in FSENT.items():
            assert e.FR[i] == v, f'{entry:06X}: fr{i} not preserved'
    return r


def wset(cells):
    s = set()
    for a, n in cells:
        s |= {a + i for i in range(n)}
    return s


def count(k):
    NCASES[k] = NCASES.get(k, 0) + 1


def q32(c):
    """float inputs as the RAM holds them (float32 bits)"""
    return {k: (b2f(f2b(v)) if k.startswith('f') else v) for k, v in c.items()}


def qf(x):
    return b2f(f2b(x))


# ================================================================== calibration
def cals(rom):
    return dict(
        D2980=u8(rom, 0xD2980), D2981=u8(rom, 0xD2981), D2982=u8(rom, 0xD2982),
        D2C08=f32(rom, 0xD2C08), D2C0C=f32(rom, 0xD2C0C), D2C10=f32(rom, 0xD2C10), D2C14=f32(rom, 0xD2C14),
        D2C18=f32(rom, 0xD2C18), D2C1C=f32(rom, 0xD2C1C), D2C20=f32(rom, 0xD2C20), D2C24=f32(rom, 0xD2C24),
        D2C28=f32(rom, 0xD2C28), D29C8=u16(rom, 0xD29C8), D29CA=u16(rom, 0xD29CA))


def test_calibration():
    """every scalar and table this file names; 20.19c == stock == 20.19e unless listed"""
    c = cals(ROM)
    assert c == dict(D2980=1, D2981=0, D2982=4, D2C08=-20.0, D2C0C=0.0, D2C10=f32(ROM, 0xD2C10), D2C14=1.0,
                     D2C18=200.0, D2C1C=0.0, D2C20=0.0, D2C24=0.0, D2C28=0.0, D29C8=0, D29CA=0), c
    assert abs(c['D2C10'] - 0.7) < 1e-6
    same = [(0xD2980, 4), (0xD29C8, 4), (0xD2C08, 0x24),                 # 0x041BE4 / 0x041A02 / 0x041A7E
            (0x0ADE08, 20), (0x0D2F8C, 64), (0x0D3437, 16),               # record, ECT axis, data of 0x0ADE08
            (0x0AE170, 24), (0x0D3D30, 0x60),                              # 0x0AE170 / 0x0AE17C and their data
            (0xD2A40, 0x80), (0xD2979, 2), (0xD29AC, 2), (0xD29B0, 2),    # 0x03F00C / 0x03EF58 scalars
            (0x0ADA84, 0xA0), (0x0D3070, 0x120),                           # 0x03F00C records, axes and data
            (0xD2AC0, 0x18),                                               # 0x03FBBC scalars
            (0x0ADB4C, 0x50), (0x0D31A6, 0x40)]                            # idle base tables (0x040314)
    for a, n in same:
        assert ROM[a:a + n] == STOCK[a:a + n] == R19E[a:a + n], f'{a:06X}+{n} differs between bins'
    # third decode: code and scalars of 0x03F368 (paths), 0x036322 / 0x036978, 0x042ED8, 0x03ED56, 0x03F00C
    for a, b in ((0x03F368, 0x03FB88), (0x036322, 0x036554), (0x036978, 0x036A98), (0x042ED8, 0x042F48),
                 (0x03ED56, 0x03EFC8), (0x03F00C, 0x03F508), (0x05EB32, 0x05EB60), (0xD2974, 0xD2977),
                 (0xD29AE, 0xD29B0), (0xD2A08, 0xD2A40), (0xD2A90, 0xD2A9C), (0xD2CD0, 0xD2CD8)):
        assert ROM[a:b] == STOCK[a:b] == R19E[a:b], f'{a:06X}..{b:06X} differs between bins'
    for rec in (0x0ADAAC, 0x0ADAC0, 0x0ADAD4, 0x0ADAE8, 0x0AE514, 0x0AD0B8, 0x0AD0C4, 0x0AD0D0, 0x0AB69C):
        assert DT.read_table(ROM, rec) == DT.read_table(STOCK, rec) == DT.read_table(R19E, rec), hex(rec)
    # the ones that differ (printed, asserted)
    assert f32(ROM, 0xD2ADC) != f32(STOCK, 0xD2ADC) and f32(ROM, 0xD2ADC) == f32(R19E, 0xD2ADC)
    imc = DT.read_table(ROM, 0x0ADB38)['values']
    ims = DT.read_table(STOCK, 0x0ADB38)['values']
    ime = DT.read_table(R19E, 0x0ADB38)['values']
    assert imc == ime and imc != ims
    print('calibration: 0x0ADE08 (ECT axis 0x0D2F8C) =',
          [round(v, 4) for v in DT.read_table(ROM, 0x0ADE08)['values']])
    print('             0x0AE170 / 0x0AE17C all zero:', DT.read_table(ROM, 0x0AE170)['values'],
          DT.read_table(ROM, 0x0AE17C)['values'])
    print('             0x0D2C10 ramp = %.7g, 0x0D2C14 = %g, 0x0D2C28 = %g, 0x0D2C18 = %g, 0x0D2C1C = %g, '
          '0x0D2C20 = %g' % (c['D2C10'], c['D2C14'], c['D2C28'], c['D2C18'], c['D2C1C'], c['D2C20']))
    print('             idle-minimum record 0x0ADB38 (rpm axis): 20.19c', [round(v, 3) for v in imc])
    print('                                                 stock ', [round(v, 3) for v in ims])
    print('             0x0D2ADC: 20.19c %.5g  stock %.5g' % (f32(ROM, 0xD2ADC), f32(STOCK, 0xD2ADC)))
    count('calibration')


# ================================================================== 0x041BE4
I_1BE4 = dict(f6634=(A(0x6634), 4), f6350=(A(0x6350), 4), f6624=(A(0x6624), 4), f7C78=(A(0x7C78), 4),
              f8020=(A(0x8020), 4), f8024=(A(0x8024), 4),
              b5E94=(A(0x5E94), 1), b7C9A=(A(0x7C9A), 1), b6254=(A(0x6254), 1), b65C0=(A(0x65C0), 1),
              b65C5=(A(0x65C5), 1), b8032=(A(0x8032), 1), b8033=(A(0x8033), 1), b8034=(A(0x8034), 1),
              b8036=(A(0x8036), 1))


def model_1BE4(c, rom=ROM):
    k = cals(rom)
    rpm, t78 = c['f6624'], c['f7C78']
    r2 = 1 if (c['b65C5'] & 0xFF) == 1 else 0
    n32, n33 = c['b8032'] & 0xFF, c['b8033'] & 0xFF
    reads = {'f6634', 'f6350', 'f6624', 'f7C78', 'b5E94', 'b7C9A', 'b6254', 'b65C0', 'b65C5'}
    armed = False
    wr = {'f8020', 'f8028', 'b8034', 'b8036'}
    if fgt(t78, rpm):
        reads.add('b8034')
        if s8(c['b8034']) == 4:
            armed = True
            n32, n33 = k['D2981'], k['D2980']
            wr |= {'b8032', 'b8033'}
    if not armed:
        reads.add('b8032')
        if n32 > 0:
            n32 -= 1
            wr.add('b8032')
        else:
            reads.add('b8033')
            if n33 > 0:
                n33 -= 1
                wr.add('b8033')
    path = None
    if r2 == 0 and (c['b5E94'] & 0xFF) < k['D2982']:
        path = 'reset:5E94'
    elif (c['b6254'] & 0xFF) == 0:
        path = 'reset:6254'
    elif fgt(k['D2C08'], c['f6634']):
        path = 'reset:6634'
    elif fgt(k['D2C0C'], rpm):
        path = 'reset:rpm'
    if not path and 'b8032' not in wr:
        reads.add('b8032')                       # 041C80 reads it again (recorded only while unwritten)
    if not path and n32 == 0 and 'b8033' not in wr:
        reads.add('b8033')                       # 041C96
    if path:
        v20 = 0.0
        n32 = n33 = 0
        wr |= {'b8032', 'b8033'}
    elif n32 != 0:
        path, v20 = 'hold0', 0.0
    elif n33 != 0:
        path, v20 = 'table', interp(0x0ADE08, c['f6350'], rom)
    else:
        reads |= {'f8020', 'b8036'}
        x = rz_add(c['f8020'], k['D2C10'])
        if (c['b8036'] & 0xFF) == 0 and (c['b65C0'] & 0xFF) == 1:
            x = rz_mul(x, k['D2C14'])
            path = 'ramp*'
        else:
            path = 'ramp'
        v20 = fmin(x, 0.0)
    reads.add('f8024')
    v28 = fmin(v20, c['f8024'])
    out = {'f8020': v20, 'f8028': v28, 'b8032': n32, 'b8033': n33, 'b8034': c['b7C9A'] & 0xFF,
           'b8036': c['b65C0'] & 0xFF}
    return out, reads, path, armed, wr


O_CELLS = dict(f8020=(A(0x8020), 4), f8028=(A(0x8028), 4), b8032=(A(0x8032), 1), b8033=(A(0x8033), 1),
               b8034=(A(0x8034), 1), b8036=(A(0x8036), 1))


def run_1BE4(e, c, rom=ROM):
    fresh(e)
    for kk, (a, n) in I_1BE4.items():
        if kk.startswith('f'):
            pokef(e, a, c[kk])
        else:
            poke(e, a, n, c[kk])
    run(e, 0x041BE4)
    c = q32(c)
    out, reads, path, armed, wr = model_1BE4(c, rom)
    for kk, v in out.items():
        a, n = O_CELLS[kk]
        if kk.startswith('f'):
            got = peekf(e, a)
            ok = close(got, v) if path == 'table' and kk in ('f8020', 'f8028') else (
                f2b(got) == f2b(v) or (math.isnan(got) and math.isnan(v)))
        else:
            got = peek(e, a, n)
            ok = got == v
        assert ok, f'0x041BE4 {path}: {kk} = {got}, model {v}; case {c}'
    assert set(e.writes) == wset([O_CELLS[k] for k in wr]), (path, sorted(map(hex, e.writes)))
    want = {I_1BE4[r][0] for r in reads}
    assert e.uninit_reads == want, (path, sorted(map(hex, e.uninit_reads)), sorted(map(hex, want)))
    count('0x041BE4')
    return out, path, armed


def base_1BE4():
    return dict(f6634=10.0, f6350=90.0, f6624=2500.0, f7C78=1800.0, f8020=0.0, f8024=0.0, b5E94=10,
                b7C9A=0, b6254=1, b65C0=0, b65C5=0, b8032=0, b8033=0, b8034=0, b8036=0)


def test_1BE4(e):
    print('\n0x041BE4: grid (arm, counters, gates, ramp, table, min with [8024])')
    seen = {}
    # arm x counters
    for rpm in (1799.0, 1800.0, 1801.0, NAN):
        for t34 in (0, 1, 2, 3, 4, 0x84):
            for n32, n33 in ((0, 0), (1, 0), (0, 1), (2, 3), (0xFF, 0), (0, 0xFF)):
                c = base_1BE4()
                c.update(f6624=rpm, b8034=t34, b8032=n32, b8033=n33)
                out, path, armed = run_1BE4(e, c)
                seen[path] = seen.get(path, 0) + 1
                if t34 == 4 and rpm == 1799.0:
                    assert armed and out['b8032'] == 0 and out['b8033'] == 0 if path.startswith('reset') else armed
    # gates
    for b65C5 in (0, 1, 2):
        for b5E94 in (0, 3, 4, 5, 0xFF):
            for b6254 in (0, 1, 0x80):
                for f6634 in (-21.0, -20.0, -19.99, NAN):
                    for rpm in (-1.0, 0.0, 2500.0):
                        c = base_1BE4()
                        c.update(b65C5=b65C5, b5E94=b5E94, b6254=b6254, f6634=f6634, f6624=rpm, b8033=1)
                        out, path, _ = run_1BE4(e, c)
                        seen[path] = seen.get(path, 0) + 1
    # ramp and [65C0] edge, [8024] min
    for f20 in (-24.9609375, -20.0, -0.7, -0.5, 0.0, -0.0, 3.0):
        for b36, b65c0 in ((0, 0), (0, 1), (1, 1), (1, 0), (2, 1)):
            for f24 in (0.0, -5.0, 5.0, NAN):
                c = base_1BE4()
                c.update(f8020=f20, b8036=b36, b65C0=b65c0, f8024=f24)
                out, path, _ = run_1BE4(e, c)
                seen[path] = seen.get(path, 0) + 1
    # table across ECT
    tab = []
    for ect in [-50.0 + 5 * i for i in range(37)]:
        c = base_1BE4()
        c.update(f6350=ect, b8034=4, f6624=1799.0)
        out, path, _ = run_1BE4(e, c)
        assert path == 'table'
        tab.append((ect, out['f8020']))
    print('  armed run, [8020] = 0x0ADE08([6350]):', ', '.join('%g:%.3f' % t for t in tab[::3]))
    # random
    for _ in range(3000):
        c = dict(f6634=RNG.choice([-30.0, -20.0, 0.0, 50.0, NAN]), f6350=RNG.uniform(-50, 130),
                 f6624=RNG.choice([-5.0, 0.0, 900.0, 1799.0, 1800.0, 2500.0, NAN]),
                 f7C78=RNG.choice([1000.0, 1800.0, NAN]), f8020=RNG.choice([-25.0, -3.3, -0.1, 0.0, 2.0]),
                 f8024=RNG.choice([0.0, -1.0, 1.0]), b5E94=RNG.randrange(256), b7C9A=RNG.choice([0, 1, 2, 4]),
                 b6254=RNG.choice([0, 1, 2]), b65C0=RNG.choice([0, 1, 2]), b65C5=RNG.choice([0, 1]),
                 b8032=RNG.choice([0, 0, 1, 5]), b8033=RNG.choice([0, 1, 2]), b8034=RNG.choice([0, 4, 4, 1]),
                 b8036=RNG.choice([0, 1]))
        out, path, _ = run_1BE4(e, c)
        seen[path] = seen.get(path, 0) + 1
    print('  paths reached:', dict(sorted(seen.items())))
    for p in ('reset:5E94', 'reset:6254', 'reset:6634', 'reset:rpm', 'hold0', 'table', 'ramp', 'ramp*'):
        assert seen.get(p), p


# ================================================================== 0x041A02, 0x041A48, 0x041A7E, 0x0419CC, 0x041954
def run_small(e, entry, ins, outs, model, c):
    fresh(e)
    for kk, (a, n) in ins.items():
        if kk.startswith('f'):
            pokef(e, a, c[kk])
        else:
            poke(e, a, n, c[kk])
    run(e, entry)
    c = q32(c)
    out, reads = model(c)
    for kk, v in out.items():
        a, n = outs[kk]
        if kk.startswith('f'):
            got = peekf(e, a)
            assert f2b(got) == f2b(v) or close(got, v), f'{entry:06X}: {kk} {got} model {v}; {c}'
        else:
            got = peek(e, a, n)
            assert got == v, f'{entry:06X}: {kk} {got:#x} model {v:#x}; {c}'
    assert set(e.writes) == wset([outs[k] for k in out]), (hex(entry), sorted(map(hex, e.writes)))
    want = {ins[r][0] for r in reads}
    assert e.uninit_reads == want, (hex(entry), sorted(map(hex, e.uninit_reads)), sorted(map(hex, want)))
    count(f'0x{entry:06X}')
    return out


I_1A02 = dict(f6350=(A(0x6350), 4), f63F8=(A(0x63F8), 4), f6624=(A(0x6624), 4), b8E0D=(A(0x8E0D), 1),
              b8E09=(A(0x8E09), 1))
O_1A02 = dict(b802C=(A(0x802C), 1))


def model_1A02(c, rom=ROM):
    k = cals(rom)
    reads = set(I_1A02)
    g = (c['b8E09'] & 0xFF) == 0 or (c['b8E0D'] & 0xFF) == 1
    v = 1 if (g and fgt(c['f6350'], k['D2C18']) and fgt(k['D2C1C'], c['f63F8'])
              and fgt(k['D2C20'], c['f6624'])) else 0
    return {'b802C': v}, reads


I_1A48 = dict(f6624=(A(0x6624), 4), f7C78=(A(0x7C78), 4), b85D7=(A(0x85D7), 1), b7C9D=(A(0x7C9D), 1),
              b802D=(A(0x802D), 1), b8037=(A(0x8037), 1))
O_1A48 = dict(b802D=(A(0x802D), 1), b8037=(A(0x8037), 1))


def model_1A48(c):
    reads = {'f6624', 'f7C78', 'b85D7', 'b7C9D'}
    out = {'b8037': c['b7C9D'] & 0xFF}
    if s8(c['b85D7']) == 1:
        out['b802D'] = 0
    else:
        reads.add('b8037')
        if s8(c['b8037']) == 1 and (c['b7C9D'] & 0xFF) == 0:
            out['b802D'] = 0 if fgt(c['f7C78'], c['f6624']) else 1
    return out, reads


I_1A7E = dict(f6624=(A(0x6624), 4), f43FC=(A(0x43FC), 4), b7C9D=(A(0x7C9D), 1), b802C=(A(0x802C), 1),
              b802D=(A(0x802D), 1), w802E=(A(0x802E), 2), w8030=(A(0x8030), 2), b8035=(A(0x8035), 1),
              f8024=(A(0x8024), 4))
O_1A7E = dict(f8024=(A(0x8024), 4), b8035=(A(0x8035), 1))


def model_1A7E(c, rom=ROM):
    k = cals(rom)
    reads = {'f6624', 'f43FC', 'b7C9D', 'b802C'}
    t9d = c['b7C9D'] & 0xFF
    if (c['b802C'] & 0xFF) == 1:
        if t9d == 1:
            reads.add('w802E')
            if c['w802E'] >= k['D29C8'] and fgt(k['D2C24'], c['f43FC']):
                mode = 3
            else:
                reads.add('b8035')
                mode = c['b8035'] & 0xFF
        else:
            reads.add('b802D')
            if (c['b802D'] & 0xFF) == 1:
                reads.add('w8030')
                if c['w8030'] >= k['D29CA'] or not fgt(k['D2C24'], c['f43FC']):
                    mode = 1
                else:
                    reads.add('b8035')
                    mode = c['b8035'] & 0xFF
            else:
                mode = 2
    else:
        if t9d == 1:
            mode = 0
        else:
            reads.add('b802D')
            mode = 1 if (c['b802D'] & 0xFF) == 1 else 2
    if mode == 1:
        reads.add('f8024')
        v = fmin(rz_add(c['f8024'], interp(0x0AE17C, c['f6624'], rom)), 0.0)
    elif mode == 2:
        reads.add('f8024')
        v = fmin(rz_add(c['f8024'], interp(0x0AE170, c['f6624'], rom)), 0.0)
    elif mode == 3:
        v = k['D2C28']
    else:
        v, mode = 0.0, 0
    return {'f8024': v, 'b8035': mode}, reads


I_19CC = dict(b7C9D=(A(0x7C9D), 1), w802E=(A(0x802E), 2), w8030=(A(0x8030), 2))
O_19CC = dict(w802E=(A(0x802E), 2), w8030=(A(0x8030), 2))


def model_19CC(c):
    if s8(c['b7C9D']) == 1:
        return {'w802E': min(c['w802E'] + 1, 0xFFFF), 'w8030': 0}, {'b7C9D', 'w802E'}
    return {'w802E': 0, 'w8030': min(c['w8030'] + 1, 0xFFFF)}, {'b7C9D', 'w8030'}


I_1954 = dict(b65F6=(A(0x65F6), 1), b7C9A=(A(0x7C9A), 1), b65C0=(A(0x65C0), 1), f8020=(A(0x8020), 4),
              f8024=(A(0x8024), 4))
O_1954 = dict(f8020=(A(0x8020), 4), f8024=(A(0x8024), 4), f8028=(A(0x8028), 4), w802E=(A(0x802E), 2),
              w8030=(A(0x8030), 2), b8036=(A(0x8036), 1), b8032=(A(0x8032), 1), b8033=(A(0x8033), 1),
              b8034=(A(0x8034), 1), b8037=(A(0x8037), 1), b8035=(A(0x8035), 1), b802C=(A(0x802C), 1),
              b802D=(A(0x802D), 1))


def model_1954(c):
    reads = {'b65F6', 'b7C9A', 'b65C0'}
    if (c['b65F6'] & 0xFF) != 1:
        return {}, reads
    return {'f8020': 0.0, 'f8024': 0.0, 'f8028': 0.0, 'w802E': 0, 'w8030': 0xFFFF, 'b8036': c['b65C0'] & 0xFF,
            'b8032': 0, 'b8033': 0, 'b8034': c['b7C9A'] & 0xFF, 'b8037': 0, 'b8035': 0, 'b802C': 0,
            'b802D': 0}, reads


def test_small(e):
    print('\n0x041A02 / 0x041A48 / 0x041A7E / 0x0419CC / 0x041954 grids')
    ones = 0
    for f6350 in (90.0, 199.9, 200.0, 200.1, 250.0, NAN):
        for f63F8 in (-0.1, 0.0, 0.5, NAN):
            for f6624 in (-1.0, 0.0, 2500.0, NAN):
                for b8E09, b8E0D in ((0, 0), (1, 0), (1, 1), (0, 1), (2, 2)):
                    c = dict(f6350=f6350, f63F8=f63F8, f6624=f6624, b8E09=b8E09, b8E0D=b8E0D)
                    out = run_small(e, 0x041A02, I_1A02, O_1A02, model_1A02, c)
                    ones += out['b802C']
                    if out['b802C']:
                        assert f6350 > 200.0 and f63F8 < 0.0 and f6624 < 0.0
    print('  0x041A02: [802C] = 1 in %d cases, every one with [6350] > 200 AND [63F8] < 0 AND [6624] < 0' % ones)
    for rpm in (1799.0, 1800.0, 1801.0, NAN):
        for b85 in (0, 1, 2, 0x81):
            for b9d in (0, 1, 2):
                for b2d in (0, 1, 7):
                    for b37 in (0, 1, 2):
                        c = dict(f6624=rpm, f7C78=1800.0, b85D7=b85, b7C9D=b9d, b802D=b2d, b8037=b37)
                        run_small(e, 0x041A48, I_1A48, O_1A48, model_1A48, c)
    seen = {}
    for b2c in (0, 1, 2):
        for b9d in (0, 1, 2):
            for b2d in (0, 1):
                for w2e in (0, 1, 0xFFFF):
                    for w30 in (0, 1, 0xFFFF):
                        for f43 in (-1.0, 0.0, 1.0, NAN):
                            for b35 in (0, 1, 2, 3, 7):
                                for f24 in (0.0, -3.0, 2.0):
                                    c = dict(f6624=2500.0, f43FC=f43, b7C9D=b9d, b802C=b2c, b802D=b2d,
                                             w802E=w2e, w8030=w30, b8035=b35, f8024=f24)
                                    out = run_small(e, 0x041A7E, I_1A7E, O_1A7E, model_1A7E, c)
                                    seen[out['b8035']] = seen.get(out['b8035'], 0) + 1
    print('  0x041A7E: modes reached (shipped cal)', dict(sorted(seen.items())))
    assert set(seen) == {0, 1, 2, 3}
    # live code, dead calibration: patch 0x0D2C28 and the 0x0AE17C data on a copy
    pat = bytearray(ROM)
    pat[0xD2C28:0xD2C2C] = struct.pack('>f', -7.5)
    for i in range(6):
        pat[0xD3D78 + 4 * i:0xD3D7C + 4 * i] = struct.pack('>f', 1.0 + i)
    pat = bytes(pat)
    ep = E.Emu(pat)
    c = dict(f6624=2500.0, f43FC=-1.0, b7C9D=1, b802C=1, b802D=0, w802E=5, w8030=0, b8035=0, f8024=0.0)
    out = run_small(ep, 0x041A7E, I_1A7E, O_1A7E, lambda cc: model_1A7E(cc, pat), c)
    assert out == {'f8024': -7.5, 'b8035': 3}
    c.update(b7C9D=0, b802D=1, w8030=9, f8024=-7.5)
    out = run_small(ep, 0x041A7E, I_1A7E, O_1A7E, lambda cc: model_1A7E(cc, pat), c)
    assert out['b8035'] == 1 and close(out['f8024'], -5.0)       # -7.5 + table(2500) = -7.5 + 2.5
    print('  0x041A7E on a PATCHED copy ([0D2C28] = -7.5, 0x0AE17C data 1..6): mode 3 -> [8024] = -7.5; '
          'mode 1 -> -7.5 + 2.5 = %.3f (code live, shipped cal neutral)' % out['f8024'])
    for b9d in (0, 1, 2, 0x81):
        for w2e in (0, 1, 0xFFFE, 0xFFFF):
            for w30 in (0, 7, 0xFFFF):
                run_small(e, 0x0419CC, I_19CC, O_19CC, model_19CC, dict(b7C9D=b9d, w802E=w2e, w8030=w30))
    for b65F6 in (0, 1, 2):
        for b9a in (0, 4):
            for b65c0 in (0, 1):
                run_small(e, 0x041954, I_1954, O_1954, model_1954,
                          dict(b65F6=b65F6, b7C9A=b9a, b65C0=b65c0, f8020=-3.0, f8024=-1.0))
    # 0x022CF4 / 0x022F92 getters
    for fn, cell in ((0x022CF4, A(0x65C5)), (0x022F92, A(0x65F6))):
        for v in range(256):
            fresh(e)
            poke(e, cell, 1, v)
            run(e, fn, check_saved=False)
            assert e.R[0] == (1 if v == 1 else 0)
            count(f'0x{fn:06X}')
    print('  0x022CF4 = ([65C5] == 1), 0x022F92 = ([65F6] == 1): all 256 byte values')


# ================================================================== 0x0419BA sequences
def seq_state(e, s):
    fresh(e)
    for a, n, v in s:
        if n == 'f':
            pokef(e, a, v)
        else:
            poke(e, a, n, v)


def test_sequences():
    print('\n0x0419BA sequences (0x041A02, 0x041A48, 0x041A7E, 0x041BE4 executed from ROM, state carried)')
    e = E.Emu(ROM)

    def episode(name, cut_passes, exit_rpm, exit_tier, ect=90.0, t78=1800.0, after=45, tier_during=4):
        fresh(e)
        # state left by the reset 0x041954 ([65F6] == 1)
        poke(e, A(0x65F6), 1, 1)
        poke(e, A(0x7C9A), 1, 0)
        poke(e, A(0x65C0), 1, 0)
        run(e, 0x041954)
        for a, v in ((A(0x6634), 10.0), (A(0x6350), ect), (A(0x7C78), t78), (A(0x63F8), 0.25),
                     (A(0x43FC), 0.0)):
            e.ram_f32(a, v)
        for a, v in ((A(0x5E94), 10), (A(0x6254), 1), (A(0x65C5), 0), (A(0x8E09), 0), (A(0x8E0D), 0),
                     (A(0x85D7), 0)):
            e.ram_u8(a, v)
        e.ram_u8(A(0x65F6), 0)
        trace = []
        for p in range(cut_passes + after):
            if p < cut_passes:
                e.ram_f32(A(0x6624), 2500.0)
                e.ram_u8(A(0x7C9A), tier_during)
                e.ram_u8(A(0x7C9D), 1 if tier_during >= 1 else 0)
            else:
                e.ram_f32(A(0x6624), exit_rpm)
                e.ram_u8(A(0x7C9A), exit_tier)
                e.ram_u8(A(0x7C9D), 1 if exit_tier >= 1 else 0)
            e.writes.clear()
            run(e, 0x0419BA)
            trace.append((p, peekf(e, A(0x8020)), peekf(e, A(0x8024)), peekf(e, A(0x8028)),
                          peek(e, A(0x802C), 1), peek(e, A(0x8033), 1)))
            count('0x0419BA pass')
        return trace

    # rpm resume: tier 4 held at x >= [7C78], then x falls below [7C78] and the tier drops to 0
    tr = episode('rpm-resume', 30, 1790.0, 0)
    assert all(t[3] == 0.0 and t[2] == 0.0 and t[4] == 0 for t in tr[:30]), 'no retard during the counted cut'
    first = tr[30]
    tv = interp(0x0ADE08, 90.0)
    assert close(first[1], tv) and close(first[3], tv), first
    n_to_zero = next(i for i, t in enumerate(tr[30:]) if t[3] == 0.0)
    steps = [round(tr[30 + i][3], 4) for i in range(0, 6)]
    print('  rpm resume (tier 4 then x = 1790 < [7C78] = 1800, tier 0), ECT 90: [8028] during cut = 0.0;')
    print('    exit pass = %.4f, then %s ... reaches 0.0 after %d passes' % (first[3], steps[1:], n_to_zero))
    assert n_to_zero == 36
    for i in range(1, n_to_zero):
        d = tr[30 + i][3] - tr[30 + i - 1][3]
        assert abs(d - 0.7) < 1e-4 or tr[30 + i][3] == 0.0, (i, d)
    # pedal resume: x stays above [7C78] when the tier drops: no arm
    tr = episode('pedal-resume', 30, 2500.0, 0)
    assert all(t[3] == 0.0 for t in tr), 'pedal resume above [7C78]: [8028] stays 0'
    print('  pedal resume (tier 4 then tier 0 at x = 2500 >= [7C78]): [8028] = 0.0 on every pass')
    # synthetic: tier 4 held while x < [7C78] (only the IMMEDIATE ladder path or a negative band can do this)
    fresh(e)
    tr = episode('held-below', 20, 1790.0, 0, t78=3000.0)
    assert tr[0][3] == 0.0, 'first pass: previous tier [8034] is still 0 (left by the reset)'
    assert all(close(t[3], tv) for t in tr[1:21]), 'tier 4 held below [7C78]: table value held every pass'
    assert close(tr[21][3], rz_add(qf(tv), qf(0.7)), 1e-4)
    print('  synthetic: tier 4 held with x = 2500 < [7C78] = 3000: [8028] = %.4f on every cut pass, ramps after'
          % tr[5][3])
    # third decode: the ladder lags one pass -- tier still 4 on the first pass with x below [7C78]
    fresh(e)
    poke(e, A(0x65F6), 1, 1)
    poke(e, A(0x7C9A), 1, 0)
    poke(e, A(0x65C0), 1, 0)
    run(e, 0x041954)
    for a, v in ((A(0x6634), 10.0), (A(0x6350), 90.0), (A(0x7C78), 1800.0), (A(0x63F8), 0.25),
                 (A(0x43FC), 0.0)):
        e.ram_f32(a, v)
    for a, v in ((A(0x5E94), 10), (A(0x6254), 1), (A(0x65C5), 0), (A(0x8E09), 0), (A(0x8E0D), 0),
                 (A(0x85D7), 0), (A(0x65F6), 0)):
        e.ram_u8(a, v)
    lag = []
    for p, (rpm, tier) in enumerate([(2500.0, 4)] * 10 + [(1790.0, 4)] + [(1790.0, 0)] * 6):
        e.ram_f32(A(0x6624), rpm)
        e.ram_u8(A(0x7C9A), tier)
        e.ram_u8(A(0x7C9D), 1 if tier >= 1 else 0)
        run(e, 0x0419BA)
        lag.append(peekf(e, A(0x8028)))
        count('0x0419BA pass')
    assert all(v == 0.0 for v in lag[:10])
    assert close(lag[10], tv) and close(lag[11], tv), lag[10:13]
    assert close(lag[12], rz_add(qf(tv), qf(0.7))) and close(lag[13], rz_add(rz_add(qf(tv), qf(0.7)), qf(0.7)))
    print('  ladder one pass late (tier 4 on the first pass with x = 1790 < [7C78], tier 0 after): [8028] = %s'
          % ', '.join('%.2f' % v for v in lag[10:14]))
    print('    -> the table value is written on TWO calls (every call with previous tier 4 and [7C78] > x)')
    # ECT sweep of the exit value
    vals = []
    for ect in (0.0, 10.0, 30.0, 50.0, 70.0, 90.0, 110.0):
        tr = episode('ect', 3, 1790.0, 0, ect=ect, after=2)
        vals.append((ect, round(tr[3][3], 3)))
        assert close(tr[3][3], interp(0x0ADE08, ect))
    print('  exit value by ECT [6350]:', vals)
    # [8024] and [802C] never leave 0 with physical inputs
    print('  [8024] = 0.0 and [802C] = 0 on every pass of every sequence above')


# ================================================================== 0x03AAA4 / 0x03AB20 / 0x03AB06
CUT11 = [A(x) for x in (0x7C9D, 0x7CB8, 0x7CBC, 0x7CD5, 0x7CE5, 0x7CE8, 0x7CF4, 0x7CF9, 0x7D11, 0x7D2E, 0x7D48)]


def test_cutflag(e):
    print('\n0x03AAA4 / 0x03AB20 / 0x03AB06 ([7C68])')
    for i, a in enumerate(CUT11):
        for v in (0, 1, 2, 0x81):
            fresh(e)
            for b in CUT11:
                poke(e, b, 1, 0)
            poke(e, a, 1, v)
            run(e, 0x03AAA4, check_saved=False)
            got = peek(e, A(0x7C68), 1)
            assert got == (1 if v == 1 else 0), (hex(a), v, got)
            reads_expected = set(CUT11[:i + 1]) if v == 1 else set(CUT11)
            assert e.uninit_reads == reads_expected, (hex(a), sorted(map(hex, e.uninit_reads)))
            assert set(e.writes) == {A(0x7C68)}
            count('0x03AAA4')
    for _ in range(500):
        fresh(e)
        vals = [RNG.choice([0, 0, 0, 1, 2]) for _ in CUT11]
        for a, v in zip(CUT11, vals):
            poke(e, a, 1, v)
        run(e, 0x03AAA4, check_saved=False)
        assert peek(e, A(0x7C68), 1) == (1 if 1 in vals else 0)
        count('0x03AAA4')
    for v in range(256):
        fresh(e)
        poke(e, A(0x7C68), 1, v)
        run(e, 0x03AB20, check_saved=False)
        assert e.R[0] == (1 if v == 1 else 0)
        count('0x03AB20')
    for f6 in (0, 1, 2):
        fresh(e)
        poke(e, A(0x65F6), 1, f6)
        poke(e, A(0x7C68), 1, 1)
        run(e, 0x03AB06, check_saved=False)
        assert peek(e, A(0x7C68), 1) == (0 if f6 == 1 else 1)
        assert set(e.writes) == ({A(0x7C68)} if f6 == 1 else set())
        count('0x03AB06')
    print('  [7C68] = 1 iff any of the 11 bytes', ' '.join('%04X' % (a & 0xFFFF) for a in CUT11),
          '== 1; reads stop at the first 1; 0x03AB20 returns ([7C68] == 1); 0x03AB06 zeroes it on [65F6] == 1')


# ================================================================== 0x03F00C
I_F00C = dict(f62FC=(A(0x62FC), 4), f62F8=(A(0x62F8), 4), f65FC=(A(0x65FC), 4), f805C=(A(0x805C), 4),
              f6624=(A(0x6624), 4), f63F8=(A(0x63F8), 4), f7354=(A(0x7354), 4), f6350=(A(0x6350), 4),
              f6354=(A(0x6354), 4), f73E8=(A(0x73E8), 4), f620C=(A(0x620C), 4),
              b7F09=(A(0x7F09), 1), b8F16=(A(0x8F16), 1), b85D7=(A(0x85D7), 1), b65C0=(A(0x65C0), 1),
              b64F5=(A(0x64F5), 1), b7EED=(A(0x7EED), 1), b7C68=(A(0x7C68), 1), b7F05=(A(0x7F05), 1),
              b7EEA=(A(0x7EEA), 1), w7EFC=(A(0x7EFC), 2), f7EF0=(A(0x7EF0), 4), f7ECC=(A(0x7ECC), 4),
              f7EC0=(A(0x7EC0), 4), f7EC8=(A(0x7EC8), 4), b7EE8=(A(0x7EE8), 1), b7EE9=(A(0x7EE9), 1),
              b7F06=(A(0x7F06), 1), b7EEB=(A(0x7EEB), 1), b7F0B=(A(0x7F0B), 1))
O_F00C = dict(f7EC0=(A(0x7EC0), 4), b7F09=(A(0x7F09), 1), f7EF0=(A(0x7EF0), 4), b7F05=(A(0x7F05), 1),
              b7EE8=(A(0x7EE8), 1), b7EEB=(A(0x7EEB), 1), f7EC4=(A(0x7EC4), 4), b7F06=(A(0x7F06), 1),
              f7EC8=(A(0x7EC8), 4), b7F0B=(A(0x7F0B), 1), f7EE4=(A(0x7EE4), 4), f7EF4=(A(0x7EF4), 4),
              f7EF8=(A(0x7EF8), 4))
K6965 = b2f(0x428B4CCC)


def model_F00C(c, rom=ROM):
    g = lambda a: f32(rom, a)          # noqa: E731
    out, paths = {}, []
    r13 = c['b7F09'] & 0xFF
    if s8(c['b7F05']) == 1 and (c['b85D7'] & 0xFF) == 0:
        r13 = 1
    # ---- [7EC0]
    disable = ((c['b8F16'] & 0xFF) == 1 or (c['b85D7'] & 0xFF) == 1 or not fgt(g(0xD2A50), c['f62FC'])
               or not fgt(g(0xD2A54), c['f62F8']))
    if not disable and (c['b7EEA'] & 0xFF) == 1 and c['w7EFC'] >= u16(rom, 0xD29AC):
        if outside(c['f7EF0'], 0.0, 0.3515625) and not outside(c['f805C'], 0.0, 0.3515625):
            disable = True
    if not disable and fgt(c['f73E8'], g(0xD2A58)):
        disable = True
    if disable:
        out['f7EC0'] = K6965
        r13 = 0
        paths.append('EC0:off')
    elif (c['b7EEA'] & 0xFF) == 1 and r13 == 1:
        out['f7EC0'] = c['f7ECC']
        paths.append('EC0:load')
    else:
        step = g(0xD2A60) if fgt(g(0xD2A5C), c['f65FC']) else g(0xD2A64)
        out['f7EC0'] = fmin(rz_add(step, c['f7EC0']), K6965)
        paths.append('EC0:ramp')
    out['b7F09'] = r13
    out['f7EF0'] = c['f805C']
    out['b7F05'] = c['b85D7'] & 0xFF
    cut = 1 if (c['b7C68'] & 0xFF) == 1 else 0
    out['b7EE8'] = 0 if cut else min((c['b7EE8'] & 0xFF) + 1, 255)
    # ---- [7EEB] / [7EC4]
    eeb = c['b7EEB'] & 0xFF
    if (not fgt(g(0xD2A9C), c['f6624']) and not fgt(g(0xD2AA0), c['f63F8']) and cut == 1
            and (c['b7F06'] & 0xFF) == 0):
        eeb = 1
        paths.append('EEB:set')
    else:
        if ((s8(out['b7EE8']) & M32) >= (s8(u8(rom, 0xD2979)) & M32)
                or (s8(c['b7EE9']) & M32) >= (s8(u8(rom, 0xD297A)) & M32)):
            eeb = 0
    out['b7EEB'] = eeb
    if eeb == 1:
        out['f7EC4'] = interp(0x0ADAFC, float(out['b7EE8']), rom)
    else:
        out['f7EC4'] = K6965
    out['b7F06'] = cut
    # ---- [7EC8]
    r10 = c['b7EED'] & 0xFF
    if s8(c['b7F0B']) == 0 and r10 == 1:
        out['f7EC8'] = interp(0x0ADB10, c['f620C'], rom)
        paths.append('EC8:load')
    elif r10 == 0:
        out['f7EC8'] = fmax(rz_sub(c['f7EC8'], g(0xD2ABC)), 0.0)
        paths.append('EC8:decay')
    else:
        paths.append('EC8:hold')
    out['b7F0B'] = c['b7EED'] & 0xFF
    # ---- [7EE4]
    if (c['b8F16'] & 0xFF) == 1:
        out['f7EE4'] = -20.0
    elif (outside(c['f7354'], 0.0, b2f(0x39800000)) and (c['b65C0'] & 0xFF) == 1
          and fgt(g(0xD2A40), c['f6354'])):
        out['f7EE4'] = g(0xD2A44)
    elif (c['b64F5'] & 0xFF) == 1:
        out['f7EE4'] = -20.0
    else:
        out['f7EF4'] = interp(0x0ADA84, c['f6624'], rom)
        out['f7EF8'] = interp(0x0ADA98, c['f6350'], rom)
        out['f7EE4'] = fmax(out['f7EF4'], out['f7EF8'])
    return out, paths


def run_F00C(e, c, rom=ROM):
    fresh(e)
    for kk, (a, n) in I_F00C.items():
        if kk.startswith('f'):
            pokef(e, a, c[kk])
        else:
            poke(e, a, n, c[kk])
    run(e, 0x03F00C)
    c = q32(c)
    out, paths = model_F00C(c, rom)
    for kk, v in out.items():
        a, n = O_F00C[kk]
        if kk.startswith('f'):
            got = peekf(e, a)
            assert f2b(got) == f2b(v) or close(got, v), f'0x03F00C {paths}: {kk} = {got}, model {v}; {c}'
        else:
            got = peek(e, a, n)
            assert got == v, f'0x03F00C {paths}: {kk} = {got}, model {v}; {c}'
    want = wset([O_F00C[k] for k in out])
    assert set(e.writes) == want, (paths, sorted(map(hex, set(e.writes) ^ want)))
    count('0x03F00C')
    return out, paths


def base_F00C():
    return dict(f62FC=30.0, f62F8=30.0, f65FC=40.0, f805C=0.0, f6624=2500.0, f63F8=0.25, f7354=0.0, f6350=90.0,
                f6354=90.0, f73E8=0.0, f620C=300.0, b7F09=0, b8F16=0, b85D7=0, b65C0=0, b64F5=1, b7EED=0,
                b7C68=0, b7F05=0, b7EEA=0, w7EFC=0, f7EF0=0.0, f7ECC=K6965, f7EC0=K6965, f7EC8=0.0, b7EE8=0,
                b7EE9=0, b7F06=0, b7EEB=0, b7F0B=0)


def test_F00C(e):
    print('\n0x03F00C (bounds of the logged timing cell)')
    seen = {}
    # the cut byte alone: [7C68] 0/1 with every previous [7F06]; nothing timing-side moves except counters
    for cut in (0, 1, 2):
        for f06 in (0, 1):
            for ee8 in (0, 5, 255):
                c = base_F00C()
                c.update(b7C68=cut, b7F06=f06, b7EE8=ee8)
                out, paths = run_F00C(e, c)
                assert out['f7EC4'] == K6965 and out['b7EEB'] == 0
                assert out['f7EC8'] == 0.0
    print('  [7C68] alone (0/1/2, every previous [7F06], [7EE8] 0/5/255): [7EC4] = 69.65, [7EEB] = 0, [7EC8] = 0')
    # [7EC8] is triggered by [7EED], not by the cut byte
    tr = []
    c = base_F00C()
    c.update(b7EED=1, b7F0B=0, f620C=650.0)
    run_F00C(e, c)
    tr.append(peekf(e, A(0x7EC8)))
    c.update(b7F0B=1, f7EC8=tr[-1], f620C=200.0)
    run_F00C(e, c)
    tr.append(peekf(e, A(0x7EC8)))
    c.update(b7EED=0, f7EC8=tr[-1])
    run_F00C(e, c)
    tr.append(peekf(e, A(0x7EC8)))
    assert close(tr[0], interp(0x0ADB10, 650.0)) and tr[1] == tr[0] and tr[2] == 0.0
    print('  [7EC8]: rising edge of [7EED] loads 0x0ADB10([620C]) (650 -> %.3f), held while [7EED] == 1, '
          '-100 per call (-> 0) once it is 0' % tr[0])
    # [7EEB] can only be set with [6624] >= 12000 and [63F8] >= 5.0 on the cut's rising edge
    c = base_F00C()
    c.update(b7C68=1, b7F06=0, f6624=12000.0, f63F8=5.0)
    out, paths = run_F00C(e, c)
    assert out['b7EEB'] == 1 and close(out['f7EC4'], interp(0x0ADAFC, 0.0))
    c.update(b7F06=1, b7EEB=1, b7EE8=out['b7EE8'])
    out, paths = run_F00C(e, c)
    assert out['b7EEB'] == 0 and out['f7EC4'] == K6965
    print('  [7EEB] set only at [6624] >= 12000 and [63F8] >= 5.0 on the [7C68] rising edge -> [7EC4] = '
          '0x0ADAFC(0) = 0.039 for that one call, cleared the next (byte 0x0D2979 = 0)')
    # [7EE4] is -20 on every path with the shipped tables
    for f16 in (0, 1):
        for b64 in (0, 1):
            for b65c0 in (0, 1):
                for f7354 in (0.0, 0.001):
                    for f6354 in (-50.0, -39.0, 90.0):
                        for rpm in (300.0, 2500.0, 4000.0):
                            c = base_F00C()
                            c.update(b8F16=f16, b64F5=b64, b65C0=b65c0, f7354=f7354, f6354=f6354, f6624=rpm)
                            out, paths = run_F00C(e, c)
                            assert close(out['f7EE4'], -20.0)
    print('  [7EE4] = -20.0 on every path (0x0D2A44 = -20, 0x0ADA84 and 0x0ADA98 all -20)')
    # [7EC0] cap
    for f85 in (0, 1):
        for f05 in (0, 1):
            for eea in (0, 1):
                for e09 in (0, 1):
                    for spd in (5.0, 13.0, 20.0):
                        for ec0 in (5.0, 69.0, K6965):
                            for f3e8 in (0.0, 0.5):
                                c = base_F00C()
                                c.update(b85D7=f85, b7F05=f05, b7EEA=eea, b7F09=e09, f65FC=spd, f7EC0=ec0,
                                         f7ECC=12.0, f73E8=f3e8)
                                out, paths = run_F00C(e, c)
                                for p in paths:
                                    seen[p] = seen.get(p, 0) + 1
    for w in (0, 49, 50):
        for f0 in (0.0, 0.36, -0.4):
            for f5 in (0.0, 0.35, 0.36):
                c = base_F00C()
                c.update(b7EEA=1, w7EFC=w, f7EF0=f0, f805C=f5, b7F09=1)
                out, paths = run_F00C(e, c)
                for p in paths:
                    seen[p] = seen.get(p, 0) + 1
    for _ in range(2500):
        c = base_F00C()
        c.update(f62FC=RNG.choice([30.0, 120.0, 130.0]), f62F8=RNG.choice([30.0, 60.0, 70.0]),
                 f65FC=RNG.choice([0.0, 12.9, 13.0, 50.0]), f805C=RNG.choice([0.0, 0.3, 0.4, -0.5]),
                 f6624=RNG.choice([800.0, 2500.0, 12000.0]), f63F8=RNG.choice([0.2, 5.0]),
                 f7354=RNG.choice([0.0, 0.0002, 0.0003]), f6354=RNG.choice([-45.0, -39.0, 80.0]),
                 f73E8=RNG.choice([0.0, 0.1, -0.1]), f620C=RNG.uniform(0, 1600), b7F09=RNG.choice([0, 1]),
                 b8F16=RNG.choice([0, 1, 2]), b85D7=RNG.choice([0, 1]), b65C0=RNG.choice([0, 1]),
                 b64F5=RNG.choice([0, 1]), b7EED=RNG.choice([0, 1, 2]), b7C68=RNG.choice([0, 1]),
                 b7F05=RNG.choice([0, 1]), b7EEA=RNG.choice([0, 1]), w7EFC=RNG.choice([0, 50, 0xFFFF]),
                 f7EF0=RNG.choice([0.0, 0.5]), f7ECC=RNG.choice([10.0, 30.0]), f7EC0=RNG.uniform(0, 70),
                 f7EC8=RNG.choice([0.0, 7.0, 150.0]), b7EE8=RNG.randrange(256), b7EE9=RNG.randrange(256),
                 b7F06=RNG.choice([0, 1]), b7EEB=RNG.choice([0, 1]), b7F0B=RNG.choice([0, 1, 2]))
        out, paths = run_F00C(e, c)
        for p in paths:
            seen[p] = seen.get(p, 0) + 1
    print('  paths reached:', dict(sorted(seen.items())))
    for p in ('EC0:off', 'EC0:load', 'EC0:ramp', 'EC8:load', 'EC8:decay', 'EC8:hold', 'EEB:set'):
        assert seen.get(p), p


# ================================================================== 0x03EF58 ([7EED])
def test_EF58(e):
    print('\n0x03EF58 ([7EED], the trigger of [7EC8])')
    for b54 in (0, 1, 2):
        for wfe in (0, 99, 100, 101, 0xFFFF):
            for rpm in (-1.0, 0.0, 800.0):
                for eec in (0, 1, 2):
                    fresh(e)
                    poke(e, A(0x6254), 1, b54)
                    poke(e, A(0x7EFE), 2, wfe)
                    pokef(e, A(0x6624), rpm)
                    poke(e, A(0x7EEC), 1, eec)
                    run(e, 0x03EF58, check_saved=False)
                    w = min(wfe + 1, 0xFFFF) if b54 == 1 else 0
                    assert peek(e, A(0x7EFE), 2) == w
                    if b54 == 1 and w > u16(ROM, 0xD29B0):
                        v = 0
                    elif fgt(f32(ROM, 0xD2AB8), rpm):
                        v = 0
                    else:
                        v = 1 if eec == 1 else 0
                    assert peek(e, A(0x7EED), 1) == v, (b54, wfe, rpm, eec)
                    assert set(e.writes) == {A(0x7EFE), A(0x7EFF), A(0x7EED)}
                    count('0x03EF58')
    print('  [7EFE] = [6254] == 1 ? sat16(+1) : 0;  [7EED] = 0 if ([6254] == 1 and [7EFE] > 100) or '
          '0.0 > [6624], else ([7EEC] == 1).  No cut byte is read.')


# ================================================================== 0x03FBBC ([7F10])
def model_FBBC(k, b85, rpm, spd, rom=ROM):
    g = lambda a: f32(rom, a)          # noqa: E731
    at_end = (not outside(k, 0.0, 0.00390625)) or (not outside(k, 1.0, 0.00390625))
    if (b85 & 0xFF) == 1:
        if at_end:
            # 03FC06: x >= 0x0D2AC0 falls through to 03FC0E here because r14 == 1; 03FC12: x >= 0x0D2AC4 -> 0
            if (not fgt(g(0xD2AC4), rpm)) or (not fgt(g(0xD2AC8), spd)) or fgt(g(0xD2ACC), spd):
                return 0.0
        return clamp(rz_sub(k, g(0xD2AD0)), 0.0, 1.0)
    if at_end:
        if (not fgt(g(0xD2AC0), rpm) and (b85 & 0xFF) == 0) or (not fgt(g(0xD2AC8), spd)) or fgt(g(0xD2ACC), spd):
            return 1.0
    return clamp(rz_add(k, g(0xD2AD4)), 0.0, 1.0)


def test_FBBC(e):
    print('\n0x03FBBC ([7F10], weight of the 0x04004A blend)')
    for k in (0.0, 0.002, 0.004, 0.5, 0.996, 0.998, 1.0, 1.002, -0.1):
        for b85 in (0, 1, 2):
            for rpm in (2000.0, 6000.0, 7000.0, NAN):
                for spd in (-1.0, 0.0, 50.0, 199.9, 200.0, 250.0):
                    fresh(e)
                    pokef(e, A(0x7F10), k)
                    poke(e, A(0x85D7), 1, b85)
                    pokef(e, A(0x6624), rpm)
                    pokef(e, A(0x65FC), spd)
                    run(e, 0x03FBBC, check_saved=False)
                    got = peekf(e, A(0x7F10))
                    want = model_FBBC(qf(k), b85, qf(rpm), qf(spd))
                    assert f2b(got) == f2b(want), (k, b85, rpm, spd, got, want)
                    assert set(e.writes) == wset([(A(0x7F10), 4)])
                    count('0x03FBBC')
    # passes from 1 to 0 and back
    k, n = 1.0, 0
    while k > 0.0:
        k = model_FBBC(k, 1, 2500.0, 40.0)
        n += 1
    k2, n2 = 0.0, 0
    while k2 < 1.0:
        k2 = model_FBBC(k2, 0, 2500.0, 40.0)
        n2 += 1
    print('  [85D7] == 1: k -= 0.0156 per call (1 -> 0 in %d calls); [85D7] != 1: k += 0.0156 (0 -> 1 in %d calls);'
          % (n, n2))
    print('  immediate k = 0 / 1 only at an end of the range (rpm >= 6000, speed >= 200 or < 0)')
    assert n == 65 and n2 == 65


# ================================================================== 0x04004A tail: [7F0C]
def test_7F0C(e):
    print('\n0x04004A tail 0x04024A..0x040284 ([7F0C] = blend of [7F48] and [7F18] by k = [7F10])')
    for f48 in (35.0, 20.08, 10.0):
        for f18 in (20.08, 35.0):
            for k in (0.0, 0.001, 0.0156, 0.5, 1.0):
                fresh(e)
                pokef(e, A(0x7F48), f48)
                pokef(e, A(0x7F18), f18)
                pokef(e, A(0x7F10), k)
                run(e, 0x04024A, check_saved=False, regs_extra={12: 0xFFFF7F60}, stop_at=(0x040284,))
                got = peekf(e, A(0x7F0C))
                f48, f18, k = qf(f48), qf(f18), qf(k)
                if fgt(f48, f18) or not outside(k, 0.0, 0.00390625):
                    r = rz_add(f48, rz_mul(rz_sub(1.0, k), rz_sub(f18, f48)))
                    want = f48 if fgt(0.3515625, abs(rz_sub(f48, r))) else r
                else:
                    want = f48
                assert close(got, want), (f48, f18, k, got, want)
                count('0x04004A tail')
    print('  [7F48] > [7F18] or k ~ 0: [7F0C] = k*[7F48] + (1-k)*[7F18] (snap to [7F48] within 0.35); '
          'else [7F0C] = [7F48]')


# ================================================================== 0x03F368 whole: clamp chain into [7E90]
def run_F368(e, cells):
    fresh(e)
    for a, v in cells.items():
        pokef(e, a, v) if isinstance(v, float) else poke(e, a, 1, v)
    run(e, 0x03F368, check_saved=False)
    return [peekf(e, A(x)) for x in (0x7E90, 0x7E94, 0x7E98, 0x7E9C)], peekf(e, A(0x7EB0))


def test_F368(e):
    print('\n0x03F368 whole runs (sixteen-term path, [8F16] = 0, RAM zero): [7E90] against the clamp chain')
    base = {A(0x7EC0): K6965, A(0x7EC4): K6965, A(0x7EC8): 0.0, A(0x7EE4): -20.0}
    for f7f0c in (30.0, 20.08, -30.0, 80.0):
        for f8028 in (0.0, -10.0, -24.9609375):
            for ec0 in (K6965, 25.0):
                for ec8 in (0.0, 7.3828125):
                    cells = dict(base)
                    cells.update({A(0x7F0C): f7f0c, A(0x8028): f8028, A(0x7EC0): ec0, A(0x7EC8): ec8})
                    got, eb0 = run_F368(e, cells)
                    s = rz_add(f7f0c, f8028)
                    lim = clamp(clamp(s, -20.0, ec0), -20.0, K6965)
                    want = clamp(rz_sub(lim, ec8), -20.0, K6965)
                    for g in got:
                        assert close(g, want), (f7f0c, f8028, ec0, ec8, got, want)
                    count('0x03F368')
    print('  [7E90..7E9C] = clamp(clamp(clamp(S, -20, [7EC0]), -20, [7EC4]) - [7EC8], [7EE4], 69.65), '
          'S containing +[7F0C] and +[8028] (asserted on 48 whole runs)')
    # third decode: [7EC4] and [7EE4] varied too (the 48 runs above hold them at 69.65 / -20.0)
    n = 0
    for f7f0c in (30.0, 12.0, -30.0):
        for f8028 in (0.0, -24.9609375):
            for ec4 in (K6965, 25.0, 8.0):
                for ee4 in (-20.0, 10.0, 28.0):
                    for ec0 in (K6965, 18.0):
                        for ec8 in (0.0, 7.3828125):
                            cells = {A(0x7F0C): f7f0c, A(0x8028): f8028, A(0x7EC0): ec0, A(0x7EC4): ec4,
                                     A(0x7EC8): ec8, A(0x7EE4): ee4}
                            got, eb0 = run_F368(e, cells)
                            s = rz_add(f7f0c, f8028)
                            lim = clamp(clamp(s, -20.0, ec0), -20.0, ec4)
                            want = clamp(rz_sub(lim, ec8), ee4, K6965)
                            for g in got:
                                assert close(g, want), (f7f0c, f8028, ec0, ec4, ec8, ee4, got, want)
                            assert close(eb0, rz_sub(s, fmin(ec0, ec4))), (eb0, s, ec0, ec4)
                            n += 1
                            count('0x03F368')
    print('  third decode: %d more whole runs with [7EC4] in {69.65, 25, 8} and [7EE4] in {-20, 10, 28} also '
          'varied: formula holds for all four cells; [7EB0] = S - min([7EC0], [7EC4])' % n)


# ================================================================== 0x03F368: which paths carry [8028]
F368_BASE = {A(0x6624): 3000.0, A(0x62F8): 0.5, A(0x65FC): 1.0, A(0x6350): 90.0, A(0x7F68): 0.25,
             A(0x7F0C): 30.0, A(0x7F6C): 0.125, A(0x7F74): 0.375, A(0x81DC): 2.0, A(0x81E0): 3.0,
             A(0x81E4): 4.0, A(0x81E8): 5.0, A(0x7EC0): K6965, A(0x7EC4): K6965, A(0x7EE4): -20.0,
             A(0x7EC8): 0.0, A(0x7F1C): 22.0, A(0x7EDC): 12.0}


def test_F368_paths():
    """C25 (third decode): [8028] reaches [7E90..7E9C] only on the paths that read it (03F640 / 03F6BA)."""
    print('\n0x03F368 per path: does [8028] = -10 move [7E90..7E9C]?')
    alt = bytearray(ROM)
    alt[0x0D2976] = 0
    alt = bytes(alt)
    assert ROM[0x0D2976] == STOCK[0x0D2976] == R19E[0x0D2976] == 90
    paths = [  # name, bytes, floats, image, address that must be reached, [8028] reaches the cells?
        ('[8F16]=3 -> 03F43C', {A(0x8F16): 3}, {}, ROM, 0x03F43C, False),
        ('[8F16]=1 -> 03F468', {A(0x8F16): 1}, {}, ROM, 0x03F468, False),
        ('chain 03F470 -> 03F494', {A(0x8F24): 1, A(0x8F22): 0x20, A(0x85D7): 1},
         {A(0x7F68): -1.0, A(0x6624): 1000.0}, ROM, 0x03F494, False),
        ('chain 03F49A -> 03F4D6', {A(0x7F03): 1}, {A(0x6624): 800.0}, ROM, 0x03F4D6, False),
        ('[7D18]=1 -> 03F5DC', {A(0x7D18): 1}, {}, ROM, 0x03F5DC, False),
        ('sixteen-term sum 03F618', {}, {}, ROM, 0x03F618, True),
        ('sum, [8F16]=2 (adds [7EE0])', {A(0x8F16): 2}, {}, ROM, 0x03F7A0, True),
        ('max form 03F6AC ([0D2976]=0)', {}, {}, alt, 0x03F6AC, True),
    ]

    def go(img, b, f, f8028, stop=None):
        e = E.Emu(img)
        for a, v in F368_BASE.items():
            e.ram_f32(a, v)
        for a, v in f.items():
            e.ram_f32(a, v)
        for a, v in b.items():
            e.ram_u8(a, v)
        e.ram_f32(A(0x8028), f8028)
        r = e.call(0x03F368, stop_at={stop} if stop else ())
        return r, [peekf(e, A(x)) for x in (0x7E90, 0x7E94, 0x7E98, 0x7E9C)]

    for name, b, f, img, stop, carries in paths:
        assert go(img, b, f, 0.0, stop)[0] == stop, name
        assert go(img, b, f, 0.0, 0x03F88E)[0] == 0x03F88E, name
        r0, c0 = go(img, b, f, 0.0)
        r1, c1 = go(img, b, f, -10.0)
        assert r0 == r1 == 'return'
        d = [round(y - x, 4) for x, y in zip(c0, c1)]
        if carries:
            assert all(abs(v + 10.0) < 1e-4 for v in d), (name, c0, c1)
        else:
            assert all(v == 0.0 for v in d), (name, c0, c1)
        count('0x03F368 path')
        print('  %-30s reaches %06X; [7E90] %.4f -> %.4f with [8028] 0 -> -10  (%s)'
              % (name, stop, c0[0], c1[0], 'MOVES 1:1' if carries else 'no effect'))
    # pool 0x03F828 (= 0xFFFF8028) is loaded only at 03F640 and 03F6BA
    users = [pc for pc in range(0x03F368, 0x03FA8C, 2)
             if (struct.unpack_from('>H', ROM, pc)[0] >> 12) == 0xD
             and ((pc & ~3) + 4 + 4 * (struct.unpack_from('>H', ROM, pc)[0] & 0xFF)) == 0x03F828]
    assert users == [0x03F640, 0x03F6BA], [hex(u) for u in users]
    print('  pool 0x03F828 (0xFFFF8028) is loaded at %s only' % ', '.join('%06X' % u for u in users))


# ================================================================== 0x036322 ([79C8]) and 0x042ED8 ([80B4])
def test_36322():
    """C30 (third decode): [7C68] never changes [79C8] in the same call of 0x036322."""
    print('\n0x036322 ([79C8]; [79F3] forced through a stub of 0x036978)')
    seen = {}
    for f3 in (0, 1, 2):
        for c4 in (0, 1, 5):
            for f4 in (0, 1):
                for c0 in (0, 3, 9):
                    for c2 in (0, 2, 7, 0xFFFF):
                        outs = {}
                        for cut in (0, 1, 2):
                            e = E.Emu(ROM)
                            e.stub(0x036978, r0=f3)
                            e.ram_f32(A(0x63C4), 1.0)
                            e.ram_u16(A(0x79C4), c4)
                            e.ram_u16(A(0x79C0), c0)
                            e.ram_u16(A(0x79C2), c2)
                            e.ram_u8(A(0x79F4), f4)
                            e.ram_u8(A(0x7C68), cut)
                            e.call(0x036322)
                            outs[cut] = (peek(e, A(0x79C8), 1), peek(e, A(0x79C2), 2), peek(e, A(0x79C0), 2))
                            count('0x036322')
                        c8 = {o[0] for o in outs.values()}
                        assert len(c8) == 1, (f3, c4, f4, c0, c2, outs)          # [7C68] never changes [79C8]
                        v = c8.pop()
                        if c4 == 0 or f3 == 1:
                            assert v == 0, (f3, c4, f4, c0, c2, outs)
                            path = '79C4=0' if c4 == 0 else '79F3=1'
                        else:
                            path = '79F4=1 copy' if f4 == 1 else 'count'
                        if c4 != 0 and f3 == 1:
                            assert all(o[1] == 0 for o in outs.values())          # [79C2] = 0 either way
                            if outs[0][2] != outs[1][2]:
                                seen['7C68 changes only 79C0'] = seen.get('7C68 changes only 79C0', 0) + 1
                        seen[path + ' -> 79C8=%d' % v] = seen.get(path + ' -> 79C8=%d' % v, 0) + 1
    print('  outcomes:', dict(sorted(seen.items())))
    assert seen.get('7C68 changes only 79C0')
    assert seen.get('79F4=1 copy -> 79C8=1') and seen.get('count -> 79C8=1')
    print('  [79C8] = 0 whenever word [79C4] == 0 or [79F3] == 1, with or without [7C68]; [7C68] == 1 only skips '
          'the [79C0] update on the [79F3] == 1 branch')


def test_42ED8():
    """C30 (third decode): [80B4] is driven to 0.0 from any start, whatever [79C8] does."""
    print('\n0x042ED8 ([80B4])')
    e = E.Emu(ROM)
    starts = (-30.0, -0.3, -0.005, 0.0, 0.004, 0.4, 3.0, NAN)
    for c8 in (0, 1, 2):
        for v in starts:
            for x in (1000.0, 3000.0, 7000.0):
                for ld in (0.5, 2.0, 3.0):
                    fresh(e)
                    poke(e, A(0x79C8), 1, c8)
                    pokef(e, A(0x80B4), v)
                    pokef(e, A(0x6624), x)
                    pokef(e, A(0x63F8), ld)
                    run(e, 0x042ED8, check_saved=False)
                    got = peekf(e, A(0x80B4))
                    vq = qf(v)
                    want = fmax(rz_sub(vq, qf(0.5)), 0.0) if c8 == 1 else fmin(rz_add(vq, qf(0.01)), 0.0)
                    assert f2b(got) == f2b(want) or close(got, want), (c8, v, x, got, want)
                    assert set(e.writes) == wset([(A(0x80B4), 4)])
                    count('0x042ED8')
    # sequences with [79C8] random per call: converges to 0.0 and then stays there
    worst = 0
    for v in starts:
        val = v
        for k in range(400):
            fresh(e)
            poke(e, A(0x79C8), 1, RNG.choice([0, 1, 1, 2]))
            pokef(e, A(0x80B4), val)
            pokef(e, A(0x6624), 2500.0)
            pokef(e, A(0x63F8), 1.0)
            run(e, 0x042ED8, check_saved=False)
            val = peekf(e, A(0x80B4))
            count('0x042ED8')
            if val == 0.0:
                worst = max(worst, k + 1)
                break
        assert val == 0.0, (v, val)
        for k in range(20):
            fresh(e)
            poke(e, A(0x79C8), 1, RNG.choice([0, 1, 2]))
            pokef(e, A(0x80B4), 0.0)
            run(e, 0x042ED8, check_saved=False)
            assert peekf(e, A(0x80B4)) == 0.0
            count('0x042ED8')
    print('  [79C8] == 1: max([80B4] - 0.5, 0x0AE514 = 0); else min([80B4] + 0.01, 0.0).  0.0 is a fixed point of '
          'both branches; every start (NaN included) reached it (random [79C8] per call: within %d calls; the '
          'slowest case, a negative start with [79C8] != 1 every call, takes |start| / 0.01 calls)' % worst)


# ================================================================== 0x03ED56 ([7ECC]) and the [7F09] latch
def model_ED56(c, rom=ROM):
    if (c['b65C5'] & 0xFF) != 1 and c['w5E74'] >= u16(rom, 0xD29AE):
        d0 = K6965
    else:
        sel = c['b6810'] & 0xFF
        d0 = {1: lambda: interp(0x0ADAC0, c['f6624'], rom), 2: lambda: interp(0x0ADAD4, c['f6624'], rom),
              3: lambda: interp(0x0ADAE8, c['f6624'], rom), 4: lambda: f32(rom, 0xD2A90),
              5: lambda: f32(rom, 0xD2A94)}.get(sel, lambda: f32(rom, 0xD2A98))()
    return d0, fmax(d0, interp(0x0ADAAC, c['f6350'], rom))


def test_ED56(e):
    """missed item (third decode): 0x03ED56 is the second writer of [7ECC], the LOAD value of the [7EC0] cap."""
    print('\n0x03ED56 ([7ED0], [7ECC])')
    low = []
    for b65c5 in (0, 1):
        for w in (37, 38, 39):
            for sel in range(7):
                for x in (1500.0, 1600.0, 2400.0, 3300.0):
                    for ect in (20.0, 50.0, 65.0, 90.0):
                        c = dict(b65C5=b65c5, w5E74=w, b6810=sel, f6624=x, f6350=ect)
                        fresh(e)
                        poke(e, A(0x65C5), 1, b65c5)
                        poke(e, A(0x5E74), 2, w)
                        poke(e, A(0x6810), 1, sel)
                        pokef(e, A(0x6624), x)
                        pokef(e, A(0x6350), ect)
                        run(e, 0x03ED56)
                        d0, cc = model_ED56(c)
                        g0, gc = peekf(e, A(0x7ED0)), peekf(e, A(0x7ECC))
                        assert close(g0, d0) and close(gc, cc), (c, g0, gc, d0, cc)
                        assert set(e.writes) == wset([(A(0x7ED0), 4), (A(0x7ECC), 4)])
                        low.append((round(gc, 3), sel, x, ect))
                        count('0x03ED56')
    lo = min(low)
    print('  [7ED0] = 69.65 if [65C5] != 1 and word [5E74] >= word 0x0D29AE (38); else by byte [6810]: 1 -> '
          '0x0ADAC0(x), 2 -> 0x0ADAD4(x), 3 -> 0x0ADAE8(x), 4 -> 10.0, 5 -> 10.0, other -> 69.7')
    print('  [7ECC] = max([7ED0], 0x0ADAAC([6350])) (0x0ADAAC: 20.08 to 30, -20.0 from 70); lowest seen %.3f '
          '([6810] = %d, x = %g, [6350] = %g)' % lo)
    assert abs(lo[0] - interp(0x0ADAC0, 1500.0)) < 1e-3


def test_latch(e):
    """missed item (third decode): once [7F09] is set, [7EC0] is reloaded from [7ECC] on every call with
    [7EEA] == 1 until an OFF condition; a [7EEA] == 0 call ramps but keeps the latch."""
    print('\n0x03F00C [7F09] latch sequence (state carried call to call)')
    lowcap = interp(0x0ADAC0, 1600.0)
    c = base_F00C()
    c.update(b64F5=1, w7EFC=0)
    steps = [  # [85D7], [7EEA], [7ECC] written by 0x03ED56 before the call, expected path
        (1, 1, lowcap, 'EC0:off'),
        (0, 1, lowcap, 'EC0:load'),      # falling edge of [85D7]: latch set, [7EC0] = [7ECC]
        (0, 1, lowcap, 'EC0:load'),      # no edge any more: still reloaded (latch held)
        (0, 0, lowcap, 'EC0:ramp'),      # [7EEA] == 0: ramp +0.7, latch kept
        (0, 1, lowcap, 'EC0:load'),      # reloaded again
        (0, 1, 8.125, 'EC0:load'),       # 0x03ED56 moved [7ECC]: follows it
        (1, 1, 8.125, 'EC0:off'),        # [85D7] == 1: cap off, latch cleared
        (0, 0, 8.125, 'EC0:ramp'),       # edge with [7EEA] == 0: latch set, but ramp
        (0, 1, 8.125, 'EC0:load'),
    ]
    hist = []
    for b85, eea, ecc, want in steps:
        c.update(b85D7=b85, b7EEA=eea, f7ECC=ecc)
        out, paths = run_F00C(e, c)
        assert paths[0] == want, (b85, eea, ecc, paths)
        hist.append((paths[0][4:], round(out['f7EC0'], 4), out['b7F09']))
        for k in ('f7EC0', 'b7F09', 'f7EF0', 'b7F05', 'b7EE8', 'b7EEB', 'b7F06', 'b7F0B'):
            c[k] = out[k]
    assert hist[1][1] == hist[2][1] == hist[4][1] == round(qf(lowcap), 4)
    assert abs(hist[3][1] - (qf(lowcap) + 0.7)) < 1e-4 and hist[3][2] == 1 and hist[6] == ('off', round(K6965, 4), 0)
    print('  (path, [7EC0], [7F09]) per call:', hist)
    # the cap then holds the logged cell at [7ECC] on the sum path of 0x03F368
    got, _ = run_F368(e, {A(0x7F0C): 30.0, A(0x7EC0): qf(lowcap), A(0x7EC4): K6965, A(0x7EC8): 0.0,
                          A(0x7EE4): -20.0})
    assert all(close(g, qf(lowcap)) for g in got), got
    count('0x03F368')
    print('  with [7EC0] = [7ECC] = %.3f, a sum of 30.0 logs as [7E90] = %.3f (0x03F368 whole run)'
          % (lowcap, got[0]))


# ================================================================== 0x05D37E SSM getter id 0x11
def test_ssm(e):
    print('\n0x05D37E (SSM getter table 0x06423C entry 0x11)')
    assert struct.unpack_from('>I', ROM, 0x06423C + 4 * 0x11)[0] == 0x05D37E
    for x in (-70.0, -64.0, -5.0, 0.0, 12.5, 12.62, 20.0, 20.08, 24.96, 63.5, 64.0, 70.0):
        fresh(e)
        pokef(e, A(0x7E90), x)
        run(e, 0x05D37E, check_saved=False)
        q = (Fraction(x) + 64) / Fraction(1, 2) + Fraction(1, 2)
        want = 0 if q <= 0 else min(255, int(q))
        assert e.R[0] == want, (x, e.R[0], want)
        count('0x05D37E')
    print('  byte = clamp(trunc(([7E90] + 64) / 0.5 + 0.5), 0, 255): 20.08 -> %d (logs as 20.0), '
          '12.62 -> 153 (12.5)' % int((20.08 + 64) * 2 + 0.5))


# ================================================================== reader scan (lower bound)
def test_readers():
    print('\nreader scan of the cut bytes (CFG constant propagation from every census function; lower bound)')
    import function_census as fc
    cen = json.load(open(os.path.join(REPO, 'disassembly', 'maps', 'function_census.json')))['functions']
    ents = sorted(int(f['entry'], 16) for f in cen)
    import bisect
    targets = {A(x): set() for x in (0x7C9A, 0x7C9D, 0x7CB7, 0x7C9F, 0x7CA0, 0x7C68)}
    loads = {(0x6, 0): 1, (0x6, 1): 2, (0x6, 2): 4, (0x6, 4): 1, (0x6, 5): 2, (0x6, 6): 4}
    for entry in ents:
        st = fc.reg_states(ROM, entry)
        gbrs = {fc.single(s[(fc.u16(ROM, pc) >> 8) & 0xF]) for (pc, r), s in st.items()
                if (fc.u16(ROM, pc) >> 12) == 4 and (fc.u16(ROM, pc) & 0xFF) == 0x1E}
        gbr = next(iter(gbrs)) if len(gbrs) == 1 and None not in gbrs else None
        for (pc, role), s in st.items():
            w = fc.u16(ROM, pc)
            op, n, m, d4 = w >> 12, (w >> 8) & 0xF, (w >> 4) & 0xF, w & 0xF
            addrs = []
            if op == 0x6 and d4 in (0, 1, 2, 4, 5, 6) and s[m]:
                addrs = [(v, loads[(6, d4)]) for v in s[m]]
            elif op == 0x8 and n in (4, 5) and s[m]:
                sz = 1 if n == 4 else 2
                addrs = [((v + d4 * sz) & M32, sz) for v in s[m]]
            elif op == 0x5 and s[m]:
                addrs = [((v + d4 * 4) & M32, 4) for v in s[m]]
            elif op == 0x0 and d4 in (0xC, 0xD, 0xE) and s[m] and s[0]:
                sz = (1, 2, 4)[d4 - 0xC]
                addrs = [((v + r) & M32, sz) for v in s[m] for r in s[0]]
            elif op == 0xC and n in (4, 5, 6) and gbr is not None:
                sz = (1, 2, 4)[n - 4]
                addrs = [((gbr + (w & 0xFF) * sz) & M32, sz)]
            for a, sz in addrs:
                for t in targets:
                    if a <= t < a + sz:
                        targets[t].add(ents[bisect.bisect_right(ents, pc) - 1])
    want = {
        A(0x7C9A): {0x0312DE, 0x031A6A, 0x031C08, 0x03AE6C, 0x03B62C, 0x041954, 0x041BE4, 0x04F9D8, 0x084438},
        A(0x7CB7): {0x0250AA},
        A(0x7C9F): {0x071ABA, 0x077BC4, 0x07AB36},
        A(0x7CA0): set(),
    }
    for t, fs in targets.items():
        print('  [%04X] read in %d functions: %s' % (t & 0xFFFF, len(fs), ' '.join('%06X' % f for f in sorted(fs))))
    for t, fs in want.items():
        assert targets[t] == fs, (hex(t), sorted(map(hex, targets[t])))
    r9d = targets[A(0x7C9D)]
    assert {0x03AAA4, 0x041A48, 0x041A7E, 0x0419CC, 0x050A5A, 0x01FE46, 0x0304BE} <= r9d and len(r9d) == 32, \
        sorted(map(hex, r9d))
    # 0x03F00C reads [7C68] only through its callee 0x03AB20, so it is not in this list (see test_F00C)
    assert 0x03AB20 in targets[A(0x7C68)] and 0x036322 in targets[A(0x7C68)]
    count('reader scan')


def main():
    test_calibration()
    e = E.Emu(ROM)
    test_1BE4(e)
    test_small(e)
    test_sequences()
    test_cutflag(e)
    test_F00C(e)
    test_EF58(e)
    test_FBBC(e)
    test_7F0C(e)
    test_F368(e)
    test_F368_paths()
    test_36322()
    test_42ED8()
    test_ED56(e)
    test_latch(e)
    test_ssm(e)
    test_readers()
    print('\ncases:', dict(sorted(NCASES.items())))
    print('total %d emulated cases, all assertions hold' % sum(v for k, v in NCASES.items()
                                                            if k not in ('reader scan', 'calibration')))


if __name__ == '__main__':
    main()
