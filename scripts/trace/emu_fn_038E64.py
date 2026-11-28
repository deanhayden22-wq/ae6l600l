#!/usr/bin/env python3
"""Emulation check for ROM function 0x038E64..0x0392A4 (479 instructions) and its four
private callees 0x039316, 0x0393EA, 0x03949E, 0x0392C4 (+0x0392FC).

    python3 scripts/trace/emu_fn_038E64.py

Reference bin: rom/AE5L600L 20g rev 20.19c.bin  md5 92cae8275cd4f9b473a3a9e36efe6449

Runs the ROM bytes in scripts/sh2e_emu.py against a Python model written from the
listings in disassembly/analysis/fn_038E64_trace.txt and asserts, per case:
  * every output cell, bit for bit (0xFFFF7B7C..0xFFFF7BA0)
  * the exact SET of non-stack RAM bytes written
  * the exact SET of RAM cells read before being written (inputs are poked WITHOUT
    marking them initialised, so every input read lands in emu.uninit_reads)
  * callee-saved state restored (r8-r14, r15, GBR, fr12-fr15)

Parts
  P1  0x039316 alone: hysteresis bits of 0xFFFF7B9F / 0xFFFF7BA0, real ROM and a ROM
      copy with six DISTINCT thresholds (proves which constant pairs with which bit)
  P2  0x0393EA alone: bit7->bit6, bit5->bit4, bit3->bit2 copy, exhaustive per byte
  P3  0x03949E alone: zero window, hold, decay toward zero, clamp +-8
  P4  0x0392C4 alone: reset writes
  P5  0x038E64 single calls, real callees: gates, events, arithmetic
  P6  0x038E64 call sequences: hold / decay timing over many calls
  P7  0x038E64 with 0x0BE830 and 0x03949E STUBBED: which record is fed by which
      input, where each result lands, which counter / hold byte goes with which output
  P8  ROM copy with 0x0CC3E0 / 0x0CC3E4 non-zero: the multiplier M and where it enters
  P9  stock vs 20.19c: every byte this function's result depends on
  P10 0x0BE830 on the 20 records vs linear interpolation of desc_types.read_table()
  P11 reachable range of S with the 20.19c tables from a zeroed block
  P12 0x0209DC (not decoded in full): the five instructions that store to U0 / U1, and the value form of
      its two main-path stores (added at review, item C34)

Review (2026-11-27, third decode): P5 NaN cases split per state variable (C29), P5b records the
instruction behind every dead stack slot (C31), P12 added (C34).

Arithmetic in the model is exact (fractions.Fraction) rounded TOWARD ZERO with this
script's own rounding routine (rz32), the rounding the emulator implements (corrections
item 106). Table values in the model come from a direct emulator call of 0x0BE830
(verified runtime library); P10 checks those against interpolation. No claim here
depends on the last bit of a float beyond "the model and the emulator agree".
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
ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import sh2e_emu as E          # noqa: E402
import desc_types as DT       # noqa: E402

ROM_PATH = os.path.join(ROOT, 'rom', 'AE5L600L 20g rev 20.19c.bin')
STOCK_PATH = os.path.join(ROOT, 'rom', 'ae5l600l.bin')
MD5 = '92cae8275cd4f9b473a3a9e36efe6449'

ROM = open(ROM_PATH, 'rb').read()
assert hashlib.md5(ROM).hexdigest() == MD5, 'wrong reference bin'
STOCK = open(STOCK_PATH, 'rb').read()

# ---------------------------------------------------------------- addresses
X0, EIN, LIN, PIN, QIN = 0xFFFF6624, 0xFFFF6350, 0xFFFF63F8, 0xFFFF73E8, 0xFFFF7400
G1, G2, G3 = 0xFFFF7C68, 0xFFFF7D2E, 0xFFFF90BD
U0, U1 = 0xFFFF6458, 0xFFFF645C
A_, C_, B_, D_ = 0xFFFF7B7C, 0xFFFF7B80, 0xFFFF7B84, 0xFFFF7B88
S_, O1_, O2_, M_ = 0xFFFF7B8C, 0xFFFF7B90, 0xFFFF7B94, 0xFFFF7B98
N0_, N1_, N2_, F0_, F1_ = 0xFFFF7B9C, 0xFFFF7B9D, 0xFFFF7B9E, 0xFFFF7B9F, 0xFFFF7BA0
BLOCK = set(range(0xFFFF7B7C, 0xFFFF7BA1))           # 37 bytes

R_A_SEED, R_C_SEED, R_B_SEED, R_D_SEED = 0x0AC710, 0x0AC724, 0x0AC738, 0x0AC74C
R_L = {'aL': 0x0AD168, 'bL': 0x0AD190, 'cL': 0x0AD17C, 'dL': 0x0AD1A4}   # input L (fr13)
R_E = {'aE': 0x0AD1B8, 'bE': 0x0AD1E0, 'cE': 0x0AD1CC, 'dE': 0x0AD1F4,   # input E (fr12)
       'lo1': 0x0AD118, 'hi1': 0x0AD12C, 'lo2': 0x0AD140, 'hi2': 0x0AD154}
R_STEP = {'A': 0x0AD208, 'B': 0x0AD21C, 'C': 0x0AD230, 'D': 0x0AD244}    # input X0
ALL_RECS = ([R_A_SEED, R_C_SEED, R_B_SEED, R_D_SEED] + list(R_L.values()) +
            list(R_E.values()) + list(R_STEP.values()))
CAL_F = [0x0CC3C4, 0x0CC3C8, 0x0CC3CC, 0x0CC3D0, 0x0CC3D4, 0x0CC3D8, 0x0CC3DC, 0x0CC3E0, 0x0CC3E4]
CAL_B = [0x0CBBFF, 0x0CBC00, 0x0CBC01, 0x0CBC02]

FLT_MAX = struct.unpack('>f', b'\x7f\x7f\xff\xff')[0]
NAN = float('nan')
INF = float('inf')
EPS12 = 2.0 ** -12


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


# ---------------------------------------------------------------- own rounding
def rz32(q):
    """exact non-zero finite Fraction -> float32 value, rounded toward zero, DN flush."""
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


def f_mul(a, b):
    if a != a or b != b or math.isinf(a) or math.isinf(b):
        return f32(a * b)
    q = Fraction(a) * Fraction(b)
    if q == 0:
        return math.copysign(0.0, sgn(a) * sgn(b))
    return rz32(q)


def f_fmac(f0, fm, fn):
    """fmac FR0,FRm,FRn: FRn = FR0*FRm + FRn, rounded ONCE (the emulator's fused model)."""
    if any(v != v or math.isinf(v) for v in (f0, fm, fn)):
        return f32(f0 * fm + fn)
    q = Fraction(f0) * Fraction(fm) + Fraction(fn)
    if q == 0:
        p_neg = sgn(f0) * sgn(fm) < 0
        p_zero = (f0 == 0 or fm == 0)
        if p_zero and p_neg and sgn(fn) < 0:
            return -0.0
        return 0.0
    return rz32(q)


# ---------------------------------------------------------------- emulator plumbing
def poke(emu, a, data):
    """write RAM without marking it initialised, so the first read shows in uninit_reads"""
    o = a - E.RAM_LO
    emu.ram[o:o + len(data)] = data


def poke_f(emu, a, v):
    poke(emu, a, struct.pack('>I', E.f2b(v)))


def poke_b(emu, a, v):
    poke(emu, a, bytes([v & 0xFF]))


_LK = {}


def lookup(rec, x, rom=ROM):
    """value of the verified runtime routine 0x0BE830 (record rec, input x), from the emulator"""
    key = (rec, bits(x), id(rom))
    if key not in _LK:
        e = E.Emu(rom)
        e.call(0x0BE830, regs={4: rec}, fregs={4: x})
        _LK[key] = e.fr(0)
    return _LK[key]


class Frame:
    """emulator + sentinel callee-saved registers"""

    def __init__(self, rom=ROM):
        self.e = E.Emu(rom)
        self.saved = {}

    def run(self, entry, regs=None, fregs=None):
        e = self.e
        rr = {k: 0x1000 * k + 0x55 for k in range(8, 15)}
        rr.update(regs or {})
        ff = {12: 12.5, 13: -13.25, 14: 14.125, 15: -15.0625}
        ff.update(fregs or {})
        e.gbr = 0xFFFF0ABC
        e.call(entry, regs=rr, fregs=ff)
        for k in range(8, 15):
            assert e.R[k] == rr[k], f'r{k} not restored by {entry:#x}'
        assert e.R[15] == E.STACK_TOP, f'r15 unbalanced by {entry:#x}'
        assert e.gbr == 0xFFFF0ABC, f'GBR not restored by {entry:#x}'
        for k, v in ff.items():
            if k >= 12:
                assert same(e.fr(k), v), f'fr{k} not restored by {entry:#x}'
        return e


# ---------------------------------------------------------------- model, written from the listings
class Cal:
    def __init__(self, rom):
        self.rom = rom
        (self.K_GATE, self.T7_LO, self.T7_HI, self.T5_LO, self.T5_HI, self.T3_LO, self.T3_HI,
         self.K_P, self.K_Q) = [rd_f(rom, a) for a in CAL_F]
        self.H_A, self.H_B, self.H_C, self.H_D = [rom[a] for a in CAL_B]


def m_hyst(cal, x, f):
    """0x039316 for one byte: set bit when NOT (HI > x); else clear when (LO > x)"""
    for bit, lo, hi in ((0x80, cal.T7_LO, cal.T7_HI), (0x20, cal.T5_LO, cal.T5_HI),
                        (0x08, cal.T3_LO, cal.T3_HI)):
        if not (hi > x):
            f |= bit
        elif lo > x:
            f &= ~bit & 0xFF
    return f


def m_copy(f):
    """0x0393EA for one byte: bit6 := bit7, bit4 := bit5, bit2 := bit3"""
    f &= 0xBF
    if f & 0x80:
        f |= 0x40
    f &= 0xEF
    if f & 0x20:
        f |= 0x10
    f &= 0xFB
    if f & 0x08:
        f |= 0x04
    return f


def m_outside(x, c, w):            # runtime library 0x0BE608 contract
    if f_add(c, -w) > x:
        return 1
    if x > f_add(c, w):
        return 1
    return 0


def m_clamp(x, lo, hi):            # runtime library 0x0BE56C contract
    if not (x > lo):
        return lo
    if hi > x:
        return x
    return hi


def m_max(a, b):                   # 0x0BE960
    return a if a > b else b


def m_min(a, b):                   # 0x0BE970
    return a if b > a else b


def m_dec(cnt, hold, v, step):
    """0x03949E(r4 = cnt, r5 = hold, fr4 = v, fr5 = step)"""
    if not m_outside(v, 0.0, EPS12):
        return 0.0
    if (cnt & 0xFF) >= (hold & 0xFF):
        if v > 0.0:
            return m_max(f_add(v, -step), 0.0)
        return m_min(f_add(v, step), 0.0)
    return m_clamp(v, -8.0, 8.0)


def sat8(n):
    return min((n & 0xFF) + 1, 0xFF)


def m_main(cal, inp, st, lk=None, dec=None):
    """0x038E64. inp: dict of inputs. st: dict of state. Returns (new state, info)."""
    lk = lk or (lambda rec, x: lookup(rec, x, cal.rom))
    dec = dec or m_dec
    s = dict(st)
    info = {'path': None, 'ev': ''}
    f0 = m_hyst(cal, inp['u0'], s['f0'])
    f1 = m_hyst(cal, inp['u1'], s['f1'])
    if not (f0 & 0x02):
        f0 |= 0x02
        f0, f1 = m_copy(f0), m_copy(f1)
        info['init'] = True
    p1 = f_add(inp['p'], -1.0)
    q1 = f_add(inp['q'], -1.0)
    s['m'] = f_mul(f_fmac(p1, cal.K_P, 1.0), f_fmac(q1, cal.K_Q, 1.0))
    x0 = inp['x0']
    gate_ok = (cal.K_GATE > x0) and not ((inp['g1'] & 0xFF) == 1 and (inp['g2'] & 0xFF) == 0) \
        and (inp['g3'] & 0xFF) != 0
    if not gate_ok:
        info['path'] = 'reset'
        for k in ('a', 'b', 'c', 'd', 's', 'o1', 'o2', 'm'):
            s[k] = 0.0
        s['n0'] = s['n1'] = s['n2'] = 0xFF
        s['f0'], s['f1'] = m_copy(f0), m_copy(f1)
        return s, info
    info['path'] = 'main'
    a, b, c, d = s['a'], s['b'], s['c'], s['d']
    n0, n1, n2 = sat8(s['n0']), sat8(s['n1']), sat8(s['n2'])
    if any((f & 0x80) and not (f & 0x40) for f in (f0, f1)):
        b = 0.0
        d = 0.0
        a = lk(R_A_SEED, x0)
        c = lk(R_C_SEED, x0)
        n0 = 0
        info['ev'] += '7'
    if any((f & 0x10) and not (f & 0x20) for f in (f0, f1)):
        d = 0.0
        a = 0.0
        c = 0.0
        b = lk(R_B_SEED, x0)
        n1 = 0
        info['ev'] += '5'
    if any((f & 0x04) and not (f & 0x08) for f in (f0, f1)):
        d = lk(R_D_SEED, x0)
        n2 = 0
        info['ev'] += '3'
    s['n0'], s['n1'], s['n2'] = n0, n1, n2
    L, Ein = inp['l'], inp['e']
    t = {k: lk(r, L) for k, r in R_L.items()}
    t.update({k: lk(r, Ein) for k, r in R_E.items()})
    st_ = {k: lk(r, x0) for k, r in R_STEP.items()}
    m = s['m']
    o1 = f_fmac(f_mul(f_mul(c, t['cL']), t['cE']), m, f_mul(f_mul(a, t['aL']), t['aE']))
    s['o1'] = m_clamp(o1, t['lo1'], t['hi1'])
    o2 = f_fmac(f_mul(f_mul(d, t['dL']), t['dE']), m, f_mul(f_mul(b, t['bL']), t['bE']))
    s['o2'] = m_clamp(o2, t['lo2'], t['hi2'])
    s['s'] = f_add(s['o1'], s['o2'])
    s['a'] = dec(n0, cal.H_A, a, st_['A'])
    s['b'] = dec(n1, cal.H_B, b, st_['B'])
    s['c'] = dec(n0, cal.H_C, c, st_['C'])
    s['d'] = dec(n2, cal.H_D, d, st_['D'])
    s['f0'], s['f1'] = m_copy(f0), m_copy(f1)
    info['pre'] = (a, b, c, d)
    return s, info


ST_ADDR = {'a': A_, 'c': C_, 'b': B_, 'd': D_, 's': S_, 'o1': O1_, 'o2': O2_, 'm': M_}
ST_BYTE = {'n0': N0_, 'n1': N1_, 'n2': N2_, 'f0': F0_, 'f1': F1_}
IN_F = {'x0': X0, 'e': EIN, 'l': LIN, 'p': PIN, 'q': QIN, 'u0': U0, 'u1': U1}
IN_B = {'g1': G1, 'g2': G2, 'g3': G3}


def load(fr, inp, st):
    e = fr.e
    for k, a in IN_F.items():
        poke_f(e, a, inp[k])
    for k, a in IN_B.items():
        poke_b(e, a, inp[k])
    for k, a in ST_ADDR.items():
        poke_f(e, a, st[k])
    for k, a in ST_BYTE.items():
        poke_b(e, a, st[k])


def unload(e):
    s = {k: e.read_f32(a) for k, a in ST_ADDR.items()}
    s.update({k: e.read_u8(a) for k, a in ST_BYTE.items()})
    return s


def run_main(inp, st, rom=ROM, stubs=None):
    fr = Frame(rom)
    load(fr, inp, st)
    for a, fn in (stubs or {}).items():
        fr.e.stub(a, fn=fn)
    e = fr.run(0x038E64)
    return unload(e), e


def check_state(got, want, ctx):
    for k in list(ST_ADDR) + list(ST_BYTE):
        if k in ST_ADDR:
            ok = same(got[k], want[k])
        else:
            ok = got[k] == want[k]
        assert ok, f'{ctx}: {k} emu {got[k]!r} model {want[k]!r}'


READS_COMMON = {X0, EIN, LIN, PIN, QIN, G1, G2, G3, U0, U1, F0_, F1_}
READS_MAIN = READS_COMMON | {A_, C_, B_, D_, N0_, N1_, N2_}

CHECKS = 0


def ok():
    global CHECKS
    CHECKS += 1


# ================================================================ P1
def p1():
    print('P1  0x039316 hysteresis bits')
    cal = Cal(ROM)
    print(f'    thresholds 20.19c: bit7 set >= {cal.T7_HI} clear < {cal.T7_LO}; '
          f'bit5 set >= {cal.T5_HI} clear < {cal.T5_LO}; bit3 set >= {cal.T3_HI} clear < {cal.T3_LO}')
    xs = [f32(v) for v in (-INF, -1.0, 0.0, 9.0, 9.4999, 9.5, 9.75, 9.9999, 10.0, 10.0001, 50.0, 79.4999,
                           79.5, 79.75, 79.9999, 80.0, 80.0001, 3600.0, INF)] + [NAN]
    fbytes = [0x00, 0xFF, 0xA8, 0x57, 0x02, 0xFD, 0x80, 0x28]
    n = 0
    for rom, tag in ((ROM, 'real'), (None, 'distinct')):
        if rom is None:
            b = bytearray(ROM)
            for a, v in zip(CAL_F[1:7], (1.0, 2.0, 3.0, 4.0, 5.0, 6.0)):
                struct.pack_into('>f', b, a, v)
            rom = bytes(b)
            xs2 = [f32(v) for v in (0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0, 5.5, 6.0, 6.5)]
        else:
            xs2 = xs
        cal_r = Cal(rom)
        for x in xs2:
            for y in xs2[::2] + [xs2[-1]]:
                for f in fbytes:
                    g = (f * 7 + 3) & 0xFF
                    fr = Frame(rom)
                    poke_f(fr.e, U0, x)
                    poke_f(fr.e, U1, y)
                    poke_b(fr.e, F0_, f)
                    poke_b(fr.e, F1_, g)
                    e = fr.run(0x039316)
                    w0, w1 = m_hyst(cal_r, x, f), m_hyst(cal_r, y, g)
                    assert e.read_u8(F0_) == w0 and e.read_u8(F1_) == w1, (tag, x, y, f)
                    assert set(e.writes) <= {F0_, F1_}
                    assert e.uninit_reads <= {U0, U1, F0_, F1_}
                    n += 1
                    ok()
    # the distinct-threshold copy, printed: which constant moves which bit
    b = bytearray(ROM)
    for a, v in zip(CAL_F[1:7], (1.0, 2.0, 3.0, 4.0, 5.0, 6.0)):
        struct.pack_into('>f', b, a, v)
    rd = bytes(b)
    print('    distinct-threshold ROM copy (C8=1 CC=2 D0=3 D4=4 D8=5 DC=6), byte 0x00 / 0xFF in:')
    for x in (0.5, 1.5, 2.0, 3.5, 4.0, 5.5, 6.0):
        r = []
        for f in (0x00, 0xFF):
            fr = Frame(rd)
            poke_f(fr.e, U0, x)
            poke_f(fr.e, U1, x)
            poke_b(fr.e, F0_, f)
            poke_b(fr.e, F1_, f)
            e = fr.run(0x039316)
            r.append(f'{e.read_u8(F0_):02X}/{e.read_u8(F1_):02X}')
        print(f'      x={x:<4} from 00 -> {r[0]}   from FF -> {r[1]}')
    # asserted rows (real ROM)
    rows = [(9.4999, 0x80, 0x00), (9.5, 0x80, 0x80), (9.9999, 0x00, 0x00), (10.0, 0x00, 0x80),
            (79.4999, 0xA8, 0x80), (79.5, 0x28, 0xA8), (79.5, 0x00, 0x80), (80.0, 0x00, 0xA8), (NAN, 0x00, 0xA8)]
    for x, fin, fout in rows:
        fr = Frame(ROM)
        poke_f(fr.e, U0, f32(x))
        poke_f(fr.e, U1, f32(x))
        poke_b(fr.e, F0_, fin)
        poke_b(fr.e, F1_, fin)
        e = fr.run(0x039316)
        assert e.read_u8(F0_) == fout and e.read_u8(F1_) == fout, (x, fin, e.read_u8(F0_))
        ok()
    print(f'    {n} grid cases + {len(rows)} asserted rows: OK (NaN SETS all three bits)')


# ================================================================ P2
def p2():
    print('P2  0x0393EA previous-state copy')
    n = 0
    for f in range(256):
        for g in (0x00, 0xFF, 0xA8, 0x54, (f * 37 + 11) & 0xFF):
            for (x, y) in ((f, g), (g, f)):
                fr = Frame()
                poke_b(fr.e, F0_, x)
                poke_b(fr.e, F1_, y)
                e = fr.run(0x0393EA)
                assert e.read_u8(F0_) == m_copy(x) and e.read_u8(F1_) == m_copy(y), (x, y)
                assert set(e.writes) == {F0_, F1_}
                n += 1
                ok()
    print(f'    {n} byte pairs (every value of each byte): OK; both bytes always written; bits 0,1,3,5,7 kept')


# ================================================================ P3
def p3():
    print('P3  0x03949E zero window / hold / decay / clamp')
    up, dn = E.b2f(E.f2b(EPS12) + 1), E.b2f(E.f2b(EPS12) - 1)     # float32 neighbours of 2^-12
    vals = [0.0, -0.0, EPS12, -EPS12, up, -up, dn, -dn, 0.001, -0.001, 0.035, -0.035, 0.1, -0.1, 1.0, -1.0, 7.9, -7.9,
            8.0, -8.0, 9.0, -9.0, 1e30, -1e30, INF, -INF, NAN]
    vals = [f32(v) for v in vals]
    steps = [f32(v) for v in (0.0, 0.0001220703125, 0.000244140625, 0.1, 1.0, -0.1, 10.0)]
    cnts = [0, 1, 3, 4, 5, 7, 8, 9, 254, 255]
    holds = [0, 4, 8, 255]
    n = 0
    for v in vals:
        for st in steps:
            for c in cnts:
                for h in holds:
                    fr = Frame()
                    e = fr.run(0x03949E, regs={4: c | 0xABCD00, 5: h | 0x777700}, fregs={4: v, 5: st})
                    want = m_dec(c, h, v, st)
                    assert same(e.fr(0), want), (v, st, c, h, e.fr(0), want)
                    assert not e.writes
                    n += 1
                    ok()
    t1, t05, t035 = f32(0.1), f32(0.05), f32(0.035)
    nx = E.b2f(E.f2b(EPS12) + 1)
    rows = [  # (cnt, hold, v, step) -> want, written out by hand from the MECHANISM
        (0, 0, EPS12, t1, 0.0), (0, 0, nx, 0.0, nx),
        (3, 4, -t035, t1, -t035), (4, 4, -t035, t1, 0.0), (4, 4, t035, t1, 0.0),
        (8, 8, 0.0234375, 0.000732421875, 0.0234375 - 0.000732421875),
        (7, 8, 0.0234375, 0.000732421875, 0.0234375), (0, 4, 9.0, t1, 8.0), (0, 4, -9.0, t1, -8.0),
        (255, 255, 9.0, t1, f_add(9.0, -t1)), (4, 4, t05, -t1, f_add(t05, t1)),
        (9, 8, NAN, t1, 0.0)]
    for c, h, v, st, w in rows:
        e = Frame().run(0x03949E, regs={4: c, 5: h}, fregs={4: v, 5: st})
        assert same(e.fr(0), w), (c, h, v, st, e.fr(0), w)
        ok()
    print(f'    {n} grid cases + {len(rows)} asserted rows: OK')
    print('    |v| <= 2^-12 (edges included) or NaN -> 0; cnt >= hold -> toward 0 by step, never past 0;')
    print('    cnt < hold -> clamp(v, -8, 8); a NEGATIVE step moves AWAY from 0 (not bounded)')


# ================================================================ P4
def p4():
    print('P4  0x0392C4 reset')
    rnd = random.Random(4)
    for i in range(50):
        fr = Frame()
        for a in ST_ADDR.values():
            poke_f(fr.e, a, f32(rnd.uniform(-100, 100)))
        for a in (N0_, N1_, N2_, F0_, F1_):
            poke_b(fr.e, a, rnd.randrange(256))
        f_before = (fr.e.read_u8(F0_), fr.e.read_u8(F1_))
        e = fr.run(0x0392C4)
        for a in ST_ADDR.values():
            assert e.read_u32(a) == 0, hex(a)          # +0.0 bit pattern
        for a in (N0_, N1_, N2_):
            assert e.read_u8(a) == 0xFF
        assert (e.read_u8(F0_), e.read_u8(F1_)) == f_before
        assert set(e.writes) == set(range(0xFFFF7B7C, 0xFFFF7B9F))
        ok()
    print('    50 random pre-states: 0xFFFF7B7C..7B98 = +0.0 (8 floats), 7B9C/7B9D/7B9E = 0xFF, 7B9F/7BA0 untouched: OK')


# ================================================================ helpers for P5-P8
def base_inp(**kw):
    d = dict(x0=1500.0, e=70.0, l=0.6, p=1.0, q=1.0, u0=5.0, u1=5.0, g1=0, g2=0, g3=1)
    d.update(kw)
    return {k: (f32(v) if isinstance(v, float) else v) for k, v in d.items()}


def base_st(**kw):
    d = dict(a=0.0, b=0.0, c=0.0, d=0.0, s=0.0, o1=0.0, o2=0.0, m=0.0, n0=0, n1=0, n2=0, f0=0x02, f1=0x02)
    d.update(kw)
    return {k: (f32(v) if isinstance(v, float) else v) for k, v in d.items()}


def one(inp, st, rom=ROM, ctx=''):
    cal = Cal(rom)
    got, e = run_main(inp, st, rom)
    want, info = m_main(cal, inp, st)
    check_state(got, want, ctx)
    assert set(e.writes) == BLOCK, (ctx, sorted(hex(a) for a in set(e.writes) ^ BLOCK))
    exp_reads = READS_MAIN if info['path'] == 'main' else READS_COMMON
    assert e.uninit_reads == exp_reads, (ctx, sorted(hex(a) for a in e.uninit_reads ^ exp_reads))
    ok()
    return got, info


# ================================================================ P5
def p5():
    print('P5  0x038E64 single calls, real callees')
    n = 0
    # gates
    gate_rows = []
    for x0 in (0.0, -5.0, 800.0, 2000.0, 3599.9998, 3600.0, 3600.0002, 1e9, INF, NAN):
        for g1 in (0, 1, 2, 0x81):
            for g2 in (0, 1, 0x80):
                for g3 in (0, 1, 0xFF):
                    inp = base_inp(x0=x0, g1=g1, g2=g2, g3=g3, u0=50.0)
                    st = base_st(a=0.5, b=0.25, c=-0.5, d=0.125, n0=7, n1=8, n2=9, f0=0x02, f1=0x02)
                    got, info = one(inp, st, ctx=f'gate {x0} {g1} {g2} {g3}')
                    exp = 'main' if (x0 < 3600.0 and not (g1 == 1 and g2 == 0) and g3 != 0) else 'reset'
                    assert info['path'] == exp, (x0, g1, g2, g3, info)
                    if exp == 'reset':
                        assert all(got[k] == 0.0 for k in ST_ADDR) and (got['n0'], got['n1'], got['n2']) == (255,) * 3
                    gate_rows.append(info['path'])
                    n += 1
    print(f'    gates: {n} cases, main {gate_rows.count("main")} reset {gate_rows.count("reset")}: OK')
    print('      main iff X0 < 3600.0 (NaN -> reset) AND NOT (byte 7C68 == 1 AND byte 7D2E == 0) AND byte 90BD != 0')
    # first call (bit1 clear): bits copied first -> no event on that call
    inp = base_inp(u0=100.0, u1=100.0)
    got, info = one(inp, base_st(f0=0x00, f1=0x00, a=0.3), ctx='init')
    assert info['ev'] == '' and got['f0'] == 0xFE and got['f1'] == 0xFC, (info, got)
    print('    bit1 of 7B9F clear: bit1 set, bits copied BEFORE the edge tests -> no event that call: OK')
    # events and arithmetic over a grid
    rnd = random.Random(5)
    evc = {}
    m = 0
    flag_pairs = [(0x02 | a, b) for a in (0x00, 0x80, 0xC0, 0x40, 0x10, 0x30, 0x20, 0x04, 0x0C, 0x08, 0xD4, 0xFE & ~0x01)
                  for b in (0x00, 0x80, 0x10, 0x04, 0xC0, 0x3C)]
    xs = [700.0, 800.0, 1000.0, 1600.0, 2111.0, 3200.0, 3599.0]
    for (f0, f1) in flag_pairs:
        for x0 in xs[::2]:
            for us in ((5.0, 5.0), (9.7, 9.7), (50.0, 5.0), (79.7, 50.0), (100.0, 100.0)):
                inp = base_inp(x0=x0, e=f32(rnd.uniform(-50, 100)), l=f32(rnd.uniform(0.1, 1.4)),
                               u0=us[0], u1=us[1])
                st = base_st(a=f32(rnd.choice([0.0, rnd.uniform(-0.05, 0.05), rnd.uniform(-10, 10)])),
                             b=f32(rnd.uniform(-0.05, 0.05)), c=f32(rnd.uniform(-0.05, 0.05)),
                             d=f32(rnd.choice([0.0, rnd.uniform(-0.05, 0.05)])),
                             n0=rnd.choice([0, 3, 4, 7, 8, 254, 255]), n1=rnd.randrange(256),
                             n2=rnd.randrange(256), f0=f0, f1=f1)
                got, info = one(inp, st, ctx=f'grid {f0:02X} {f1:02X} {x0} {us}')
                evc[info['ev']] = evc.get(info['ev'], 0) + 1
                m += 1
    print(f'    flag / input grid: {m} cases, event sets seen {dict(sorted(evc.items()))}: OK')
    # wide float inputs, including extremes, on the main path with every event
    k = 0
    for x0 in (-INF, -1e9, 799.0, 800.0, 3200.0, 3200.5):
        for ev in ((0x80, 0x00), (0x10, 0x00), (0x04, 0x00), (0x94, 0x00), (0x80, 0x14)):
            for ee in (-1e9, -40.0, 41.0, 60.0, 1e9, NAN):
                for ll in (-1.0, 0.25, 1.3, 1e9, NAN):
                    inp = base_inp(x0=x0, e=ee, l=ll, u0=50.0 if ev[0] & 0x80 else 5.0,
                                   u1=50.0 if ev[1] & 0x80 else 5.0)
                    st = base_st(a=-9.0, b=9.0, c=1e30, d=-1e30, n0=2, n1=2, n2=2,
                                 f0=0x02 | (ev[0] & 0x80) | ((ev[0] & 0x14)), f1=0x02 | ev[1])
                    one(inp, st, ctx=f'wide {x0} {ev} {ee} {ll}')
                    k += 1
    print(f'    extreme inputs (+-inf / 1e9 / NaN axes, |state| up to 1e30): {k} cases: OK')
    # NaN lookup input -> the LAST cell of every record (runtime library behaviour, printed)
    for rec in ALL_RECS:
        assert same(lookup(rec, NAN), DT.read_table(ROM, rec)['values'][-1]) or \
            abs(lookup(rec, NAN) - DT.read_table(ROM, rec)['values'][-1]) < 1e-6, hex(rec)
        ok()
    # NaN in the state: only the product that uses the NaN working copy is NaN, clamp 0x0BE56C returns its
    # LOW bound for it (!(NaN > lo)); dec() flushes the NaN to 0.0. A and C feed O1 only, B and D feed O2
    # only (review item C29: the original wording "O1 = lo1 / O2 = lo2" was true only for a NaN in both).
    inp = base_inp(e=70.0, l=0.6, x0=1600.0)
    lo1, lo2 = lookup(R_E['lo1'], inp['e']), lookup(R_E['lo2'], inp['e'])
    st0 = dict(a=-0.03, b=0.0, c=0.02, d=-0.02, n0=9, n1=9, n2=9)
    ref, _ = one(inp, base_st(**st0), ctx='nan ref')
    assert not same(ref['o1'], lo1) and not same(ref['o2'], lo2)
    for k, out, other in (('a', 'o1', 'o2'), ('c', 'o1', 'o2'), ('b', 'o2', 'o1'), ('d', 'o2', 'o1')):
        got, info = one(inp, base_st(**dict(st0, **{k: NAN})), ctx=f'nan state {k}')
        assert info['ev'] == ''
        assert same(got[out], lo1 if out == 'o1' else lo2), (k, got[out])
        assert same(got[other], ref[other]), (k, got[other], ref[other])
        assert got[k] == 0.0 and E.f2b(got[k]) == 0, (k, got[k])
    got, info = one(inp, base_st(**dict(st0, a=NAN, d=NAN)), ctx='nan state a+d')
    assert same(got['o1'], lo1) and same(got['o2'], lo2) and got['a'] == 0.0 and got['d'] == 0.0
    # a NaN working copy that an event overwrites never reaches the products
    for k, f0, ev in (('a', 0x82, '7'), ('b', 0x82, '7'), ('c', 0x82, '7'), ('d', 0x82, '7'),
                      ('a', 0x12, '5'), ('c', 0x12, '5'), ('d', 0x12, '5'), ('d', 0x06, '3')):
        i2 = dict(inp, u0=f32(50.0) if f0 & 0x80 else f32(5.0))
        got, info = one(i2, base_st(**dict(st0, f0=f0, **{k: NAN})), ctx=f'nan overwritten {k} {ev}')
        assert info['ev'] == ev, (k, info)
        assert not same(got['o1'], lo1) and not same(got['o2'], lo2), (k, ev, got['o1'], got['o2'])
    # a non-finite P or Q makes M NaN (0.0 * inf and NaN * 0.0 are NaN): BOTH outputs take the low bound
    # on every main-path call, even with A = B = C = D = 0 (the NaN M multiplies a zero C / D term)
    for p, q in ((NAN, 1.0), (INF, 1.0), (1.0, -INF), (1.0, NAN)):
        got, info = one(base_inp(p=p, q=q, e=70.0), base_st(n0=9, n1=9, n2=9), ctx=f'nan M {p} {q}')
        assert got['m'] != got['m'] and info['path'] == 'main'
        assert same(got['o1'], lo1) and same(got['o2'], lo2) and same(got['s'], f_add(lo1, lo2))
    print('    NaN lookup input -> last cell (all 20 records). NaN in A or C -> O1 = lo1 only; NaN in B or D ->')
    print(f'      O2 = lo2 only; that state is stored as +0.0; an event that re-seeds / zeroes the working copy')
    print(f'      first hides it. NaN / inf P or Q -> M = NaN -> O1 = lo1, O2 = lo2, S = {f_add(lo1, lo2):.7f}: OK')


# ================================================================ P5b
def p5b():
    print('P5b stack frame of 0x038E64: which slots are read, and which instruction writes each dead slot')
    import sh2e_disasm as DIS
    F = E.STACK_TOP - 44 - 168
    R_ALL, W_ALL = set(), set()
    W_PC = {}
    ncalls = 0
    for ev in ((0x80, 0x00), (0x10, 0x00), (0x04, 0x00), (0x00, 0x00), (0x94, 0x00), (0x00, 0x94),
               (0x40, 0x00), (0x30, 0x0C)):
        for us in (5.0, 9.7, 50.0, 85.0):
            for x0 in (1500.0, 4000.0):                  # 4000.0: reset path
                inp = base_inp(u0=us, u1=us, x0=x0)
                st = base_st(f0=0x02 | ev[0], f1=0x02 | ev[1], a=0.02, c=0.01, d=-0.02, n0=5, n1=5, n2=5)
                fr = Frame()
                load(fr, inp, st)
                e = fr.e
                o_r, o_w = e.read, e.write

                def rd(a, n, o_r=o_r):
                    a2 = a & 0xFFFFFFFF
                    if F <= a2 < F + 168:
                        R_ALL.add((a2 - F, n))
                    return o_r(a, n)

                def wr(a, n, v, o_w=o_w, e=e):
                    a2 = a & 0xFFFFFFFF
                    if F <= a2 < F + 168:
                        W_ALL.add((a2 - F, n))
                        W_PC.setdefault(a2 - F, set()).add(e.pc)
                    return o_w(a, n, v)
                e.read, e.write = rd, wr
                fr.run(0x038E64)
                ncalls += 1
    want_r = {(0, 4), (4, 4), (8, 4), (12, 1), (16, 1), (20, 1)} | {(o, 4) for o in range(72, 133, 4)}
    dead = {(o, 1) for o in range(24, 69, 4)} | {(o, 4) for o in range(136, 165, 4)}
    assert R_ALL == want_r, sorted(R_ALL ^ want_r)
    assert W_ALL == want_r | dead, sorted(W_ALL ^ (want_r | dead))
    # the instruction behind each dead slot (none of these stores sits in a delay slot, so e.pc is the store)
    want_pc = {24: 0x038F5C, 28: 0x038F6A, 32: 0x038F78, 36: 0x038F86, 40: 0x038FB6, 44: 0x038FC6,
               48: 0x038FD4, 52: 0x038FE2, 56: 0x03900A, 60: 0x03901C, 64: 0x03902A, 68: 0x039038,
               136: 0x038F1E, 140: 0x038F32, 144: 0x038F4A, 148: 0x039208,
               152: 0x039212, 156: 0x039232, 160: 0x039250, 164: 0x03926E}
    for off, pc in want_pc.items():
        assert W_PC[off] == {pc}, (off, W_PC[off])
        txt = DIS.decode(int.from_bytes(ROM[pc:pc + 2], 'big'), pc)[0]
        cls = txt.split()[0]
        want_cls = 'mov.b' if off <= 68 else ('fmov.s' if off == 148 else 'mov.l')
        assert cls == want_cls, (off, txt)
    ok()
    print(f'    {ncalls} calls (8 flag patterns x 4 U values x main / reset path)')
    print('    read: +0 +4 +8 (floats), +12 +16 +20 (bytes), +72..+132 (16 floats)')
    print('    written and NEVER read (dead spills): +24..+68, 12 mov.b copies of the flag bytes;')
    print('      +136..+164, 8 four-byte slots: seven mov.l counter copies (+136/140/144/152/156/160/164)')
    print('      and ONE fmov.s float spill of the A working copy (+148, 039208): OK')


# ================================================================ P6
def p6():
    print('P6  0x038E64 call sequences (real callees, 20.19c tables)')
    cal = Cal(ROM)
    total = 0
    # sequence: U0 low, then crosses 10.0 (bit7 rising), stays; later crosses 80 and falls below 79.5
    u0_seq = [5.0, 5.0, 12.0] + [12.0] * 12 + [85.0, 85.0, 70.0] + [70.0] * 30 + [5.0, 5.0, 12.0, 12.0]
    for x0 in (800.0, 1600.0, 2400.0):
        inp_base = dict(x0=x0, e=70.0, l=0.6)
        st = base_st(f0=0x02, f1=0x02, n0=255, n1=255, n2=255)
        rows = []
        for i, u in enumerate(u0_seq):
            inp = base_inp(u0=u, **inp_base)
            got, info = one(inp, st, ctx=f'seq {x0} {i}')
            rows.append((i, u, info['ev'], got['n0'], got['n1'], got['n2'], got['a'], got['c'], got['d'], got['s']))
            st = got
            total += 1
        if x0 == 1600.0:
            print(f'    X0 = {x0}, E = 70, L = 0.6, U1 = 5 (byte 7BA0 never moves); holds A/B/C/D = '
                  f'{cal.H_A}/{cal.H_B}/{cal.H_C}/{cal.H_D}')
            print('     call  U0     ev   n0  n1  n2   A(7B7C)      C(7B80)      D(7B88)      S(7B8C)')
            for r in rows[:22] + rows[-6:]:
                print(f'     {r[0]:3d}  {r[1]:5.1f}  {r[2]:3s} {r[3]:3d} {r[4]:3d} {r[5]:3d}  '
                      f'{r[6]: .6f}  {r[7]: .6f}  {r[8]: .6f}  {r[9]: .7f}')
        # contract checks on the sequence: A held for counter 0..3, zero at 4; C held 0..7 then linear
        ev_i = [r[0] for r in rows if '7' in r[2]]
        assert ev_i, 'no rising-edge event'
        i0 = ev_i[0]
        a_seed = lookup(R_A_SEED, f32(x0))
        c_seed = lookup(R_C_SEED, f32(x0))
        for j in range(4):
            assert same(rows[i0 + j][6], a_seed if abs(a_seed) > EPS12 else 0.0), (x0, j)
        assert rows[i0 + 4][6] == 0.0
        for j in range(8):
            assert same(rows[i0 + j][7], c_seed)
        assert rows[i0 + 8][7] < c_seed
        ok()
    # U1 drives the same events through byte 7BA0
    st = base_st(n0=255, n1=255, n2=255)
    for i, u in enumerate([5.0, 12.0, 12.0, 85.0, 50.0, 50.0]):
        got, info = one(base_inp(u0=5.0, u1=u), st, ctx=f'seqU1 {i}')
        if i == 1:
            assert info['ev'] == '7'
        if i == 4:
            assert info['ev'] == '53', info
        st = got
        total += 1
    # the reset path consumes edges: edge occurring while gated out never fires later
    st = base_st(n0=255, n1=255, n2=255)
    got, info = one(base_inp(u0=5.0), st, ctx='g0')
    got, info = one(base_inp(u0=50.0, g3=0), got, ctx='g1')
    assert info['path'] == 'reset' and got['f0'] & 0xC0 == 0xC0
    got, info = one(base_inp(u0=50.0), got, ctx='g2')
    assert info['ev'] == '' and got['a'] == 0.0
    total += 3
    print(f'    {total} sequential calls: OK (A held while n0 = 0..{cal.H_A - 1} then decays; C held n0 = 0..{cal.H_C - 1};')
    print('      D decays from the event call (hold 0); an edge that happens on a reset-path call is lost)')


# ================================================================ P7
def p7():
    print('P7  stubbed 0x0BE830 and 0x03949E: wiring')
    names = {r: i + 1 for i, r in enumerate(ALL_RECS)}
    log = []

    def lk_val(rec, x):
        return f32(names[rec] / 8.0 + 0.5)        # unique per record, independent of x

    def stub_lookup(e):
        rec, x = e.R[4], e.fr(4)
        log.append(('lk', rec, bits(x)))
        e.set_fr(0, lk_val(rec, x))

    declog = []

    def stub_dec(e):
        declog.append((e.R[4] & 0xFF, e.R[5] & 0xFF, bits(e.fr(4)), bits(e.fr(5))))
        e.set_fr(0, f32(1000.0 + len(declog)))

    for ev in ((0x80, 0x00), (0x10, 0x00), (0x04, 0x00), (0x00, 0x00), (0x94, 0x00), (0x00, 0x94)):
        log.clear()
        declog.clear()
        inp = base_inp(x0=1234.5, e=37.25, l=0.6875, u0=5.0, u1=5.0)
        st = base_st(a=0.25, b=-0.375, c=0.625, d=-0.875, n0=10, n1=20, n2=30,
                     f0=0x02 | ev[0], f1=0x02 | ev[1])
        fr = Frame()
        load(fr, inp, st)
        fr.e.stub(0x0BE830, fn=stub_lookup)
        fr.e.stub(0x03949E, fn=stub_dec)
        fr.e.stub(0x039316, fn=lambda e: None)          # keep the flag bytes exactly as poked
        e = fr.run(0x038E64)
        got = unload(e)
        # model with the same stubs
        calls = []

        def dec_capture(cnt, hold, v, step):
            calls.append((cnt, hold, bits(v), bits(step)))
            return f32(1000.0 + len(calls))
        cal = Cal(ROM)
        # 0x039316 stubbed: feed the model inputs that leave the bytes unchanged
        want, info = m_main(cal, dict(inp, u0=f32(9.75), u1=f32(9.75)), st,
                            lk=lk_val, dec=dec_capture)
        # (9.75 lies inside the bit7 band and below both bit5/bit3 bands; none of the poked
        #  bytes has bit5 or bit3 set, so the model's hysteresis leaves them unchanged too)
        check_state(got, want, f'stub {ev}')
        assert declog == calls, (declog, calls)
        src = {bits(inp['x0']): 'X0', bits(inp['e']): 'E', bits(inp['l']): 'L'}
        seen = [(f'{r:06X}', src[b]) for _, r, b in log]
        if ev == (0x94, 0x00):
            print('    lookup order, record <- input (event bits 7,4,2 set in 7B9F, i.e. all three events):')
            for i in range(0, len(seen), 5):
                print('      ' + '  '.join(f'{r}<-{s}' for r, s in seen[i:i + 5]))
        if ev in ((0x94, 0x00), (0x00, 0x00)):
            print(f'    0x03949E calls, event bits {ev[0]:02X}/{ev[1]:02X}, counters in 10/20/30 '
                  '(r4 counter, r5 hold byte, fr4 value, fr5 step):')
            for (c, h, v, s_), dst in zip(declog, ('7B7C', '7B84', '7B80', '7B88')):
                print(f'      r4={c:3d} r5={h} fr4={E.b2f(v): .4f} fr5={E.b2f(s_):.4f}  -> {dst}')
            print(f'      results stored: 7B7C={got["a"]} 7B84={got["b"]} 7B80={got["c"]} 7B88={got["d"]}')
        ok()
    print('    6 event combinations: emulator = model with the same stubs; argument capture equal: OK')


# ================================================================ P8
def p8():
    print('P8  ROM copy with K_P = 0x0CC3E0, K_Q = 0x0CC3E4 non-zero: M and where it enters')
    b = bytearray(ROM)
    struct.pack_into('>f', b, 0x0CC3E0, 0.5)
    struct.pack_into('>f', b, 0x0CC3E4, 0.25)
    rom = bytes(b)
    n = 0
    for p, q in ((1.0, 1.0), (1.2, 0.8), (3.0, 0.0), (-1.0, 5.0), (0.0, 0.0)):
        for ev in ((0x80, 0x00), (0x04, 0x00), (0x84, 0x00)):
            inp = base_inp(p=p, q=q, x0=1000.0, u0=50.0)
            st = base_st(f0=0x02 | ev[0], f1=0x02 | ev[1], n0=3, n1=3, n2=3, a=0.02, b=0.0, c=0.01, d=-0.02)
            got, info = one(inp, st, rom=rom, ctx=f'P8 {p} {q} {ev}')
            want_m = f_mul(f_fmac(f_add(f32(p), -1.0), 0.5, 1.0), f_fmac(f_add(f32(q), -1.0), 0.25, 1.0))
            assert same(got['m'], want_m)
            n += 1
    # M is written BEFORE the gate, then zeroed by the reset path
    got, info = one(base_inp(p=1.2, x0=4000.0), base_st(), rom=rom, ctx='P8 reset')
    assert got['m'] == 0.0 and info['path'] == 'reset'
    # on the real ROM, M = 1.0 for any finite P, Q
    for p, q in ((1.0, 1.0), (1e30, -1e30), (0.0, 7.0)):
        got, _ = one(base_inp(p=p, q=q), base_st(), ctx='P8 real')
        assert got['m'] == 1.0
    print(f'    {n} cases with K_P=0.5, K_Q=0.25: M = (1 + K_P*(P-1)) * (1 + K_Q*(Q-1)): OK;')
    print('    M multiplies ONLY the C and D terms; reset path leaves M = 0; real ROM (K_P = K_Q = 0.0): M = 1.0')


# ================================================================ P9
def p9():
    print('P9  stock vs 20.19c')
    diffs = []
    for rec in ALL_RECS:
        cnt = struct.unpack_from('>h', ROM, rec)[0]
        ax, dp = struct.unpack_from('>II', ROM, rec + 4)
        w = DT.TYPE_SIZES[ROM[rec + 2]]
        for lo, hi in ((rec, rec + 20), (ax, ax + 4 * cnt), (dp, dp + w * cnt)):
            if ROM[lo:hi] != STOCK[lo:hi]:
                diffs.append(hex(lo))
    for a in CAL_F:
        if ROM[a:a + 4] != STOCK[a:a + 4]:
            diffs.append(hex(a))
    for a in CAL_B:
        if ROM[a] != STOCK[a]:
            diffs.append(hex(a))
    if ROM[0x038E64:0x0392A4] != STOCK[0x038E64:0x0392A4] or ROM[0x0392A4:0x039524] != STOCK[0x0392A4:0x039524]:
        diffs.append('code')
    assert not diffs, diffs
    ok()
    print('    20 records + their axes + data, 9 float scalars, 4 hold bytes, code 0x038E64..0x039523: identical')


# ================================================================ P10
def p10():
    print('P10 0x0BE830 on the 20 records vs desc_types.read_table interpolation')
    n = 0
    for rec in ALL_RECS:
        t = DT.read_table(ROM, rec)
        ax = list(t['axes'].values())[0]
        vals = t['values']
        assert struct.unpack_from('>h', ROM, rec)[0] == 7 and ROM[rec + 2] in (0x04, 0x08)
        assert DT.fixed_type(rec) is None
        for i, x in enumerate(ax):
            assert abs(lookup(rec, f32(x)) - vals[i]) <= 1e-6 * max(1.0, abs(vals[i])), (hex(rec), x)
            n += 1
        for x in (ax[0] - 1000.0, -INF):
            assert abs(lookup(rec, f32(x)) - vals[0]) <= 1e-6, hex(rec)
            n += 1
        for x in (ax[-1] + 1000.0, INF):
            assert abs(lookup(rec, f32(x)) - vals[-1]) <= 1e-6, hex(rec)
            n += 1
        for i in range(6):
            x = (ax[i] + ax[i + 1]) / 2
            want = (vals[i] + vals[i + 1]) / 2
            assert abs(lookup(rec, f32(x)) - want) <= 1e-5, (hex(rec), x)
            n += 1
        ok()
    print(f'    {n} lookups: breakpoints exact to 1e-6, clamp outside the axis, midpoints linear: OK')
    print('    tables (20.19c = stock):')
    for rec in ALL_RECS:
        t = DT.read_table(ROM, rec)
        ax = list(t['axes'].values())[0]
        print(f'      {rec:06X} {t["type_name"]:6s} axis {ax[0]:g}..{ax[-1]:g}  ' +
              ' '.join(f'{v:.6g}' for v in t['values']))


# ================================================================ P11
def p11():
    print('P11 reachable range of S (0xFFFF7B8C) with the 20.19c tables, from a zeroed block')
    tv = {r: DT.read_table(ROM, r)['values'] for r in ALL_RECS}
    c_max = max(tv[R_C_SEED]) * max(tv[R_L['cL']]) * max(tv[R_E['cE']])
    a_min = min(tv[R_A_SEED]) * max(tv[R_L['aL']]) * max(tv[R_E['aE']])
    d_min = min(tv[R_D_SEED]) * max(tv[R_L['dL']]) * max(tv[R_E['dE']])
    print(f'    table bound: C term <= {c_max:.6f}, A term >= {a_min:.6f}, D term >= {d_min:.6f}; '
          f'hi1 = {lookup(R_E["hi1"], 0.0):.7f}')
    hi = -1.0
    lo = 1.0
    argmax = None
    n = 0
    for x0 in (700.0, 800.0, 1000.0, 1200.0, 1600.0, 2000.0, 2400.0, 3200.0, 3500.0):
        for ee in (-50.0, -40.0, -20.0, 0.0, 40.0, 50.0, 60.0, 100.0):
            for ll in (0.1, 0.3, 0.5, 0.7, 0.9, 1.5):
                for f0 in (0x02, 0xFE):                 # 0x02 + U0=50: EVENT 7; 0xFE + U0=50: EVENTS 5,3
                    got, info = one(base_inp(x0=x0, e=ee, l=ll, u0=50.0, u1=5.0),
                                    base_st(f0=f0, f1=0x02), ctx=f'P11 {x0} {ee} {ll} {f0:02X}')
                    assert info['ev'] == ('7' if f0 == 0x02 else '53')
                    if got['s'] > hi:
                        hi, argmax = got['s'], (x0, ee, ll)
                    lo = min(lo, got['s'])
                    n += 1
    assert hi <= c_max + 1e-9 and hi < 0.0999 and lo >= a_min + d_min - 1e-9
    print(f'    {n} event calls over an X0 x E x L grid: max S = {hi:.7f} at X0, E, L = {argmax}; '
          f'min S = {lo:.7f}')
    print('    -> the +0.0999756 upper clamp of O1 is NOT reachable from a zeroed block with these tables')
    # by construction the state can only shrink after its seed: check over a long run at the max point
    st = base_st(n0=255, n1=255, n2=255)
    smax = -1.0
    for i in range(60):
        u = 50.0 if (i % 20) >= 2 else 5.0
        got, info = one(base_inp(x0=800.0, e=-40.0, l=0.7, u0=u, u1=u), st, ctx=f'P11 seq {i}')
        smax = max(smax, got['s'])
        st = got
    assert smax <= hi + 1e-12
    print(f'    60-call run at the max point with repeated rising edges: max S = {smax:.7f}: OK')


# ================================================================ P12
def p12():
    """0x0209DC (NOT decoded in full here): which of its instructions store to U0 / U1 (0xFFFF6458 /
    0xFFFF645C), and the value form of the two main-path stores. Review item C34: the first version of this
    trace listed only 020CEA / 020CF2 / 020CFC (the r11 == 2 branch) because find_writers reports only those."""
    print('P12 0x0209DC: the stores to U0 / U1 (0xFFFF6458 / 0xFFFF645C)')
    rnd = random.Random(12)
    win =struct.unpack('>f', ROM[0x020D74:0x020D78])[0]           # 0x3AFA0000 = 0.0019073486
    assert ROM[0x020D74:0x020D78] == bytes.fromhex('3AFA0000')
    assert ROM[0x02102C:0x021030] == bytes.fromhex('3AFA0000')
    # e.pc during a delay-slot store is the BRANCH's pc: 020CE8 bra -> slot 020CEA, 020CFA bra -> slot 020CFC
    slot_of = {0x020CE8: 0x020CEA, 0x020CFA: 0x020CFC}
    sites = {}
    n_form = n_keep = 0
    for i in range(400):
        e = E.Emu(ROM)
        e.stub(0x00317C, r0=0)          # critical-section enter (rtos_core contract), SR not emulated
        e.stub(0x003190)                # critical-section leave
        for a in range(0xFFFF6458, 0xFFFF6498):
            e.ram[a - E.RAM_LO] = rnd.randrange(256) if rnd.random() < 0.3 else 0
        same_pair = rnd.random() < 0.2
        for a in (0xFFFF44A8, 0xFFFF44AC, 0xFFFF4130, 0xFFFF6624, 0xFFFF21AC, 0xFFFF21B4, 0xFFFF21BC,
                  0xFFFF21C4, U0, U1):
            v = rnd.choice([0.0, rnd.uniform(-5, 5), rnd.uniform(0, 100), 50.0])
            struct.pack_into('>f', e.ram, a - E.RAM_LO, f32(v))
        if same_pair:
            e.ram[0xFFFF21BC - E.RAM_LO:0xFFFF21C0 - E.RAM_LO] = e.ram[0xFFFF21AC - E.RAM_LO:0xFFFF21B0 - E.RAM_LO]
            e.ram[0xFFFF21C4 - E.RAM_LO:0xFFFF21C8 - E.RAM_LO] = e.ram[0xFFFF21B4 - E.RAM_LO:0xFFFF21B8 - E.RAM_LO]
        for a in (0xFFFF21B0, 0xFFFF21B8, 0xFFFF21C0, 0xFFFF21C8):
            struct.pack_into('>I', e.ram, a - E.RAM_LO, rnd.randrange(1 << 32))
        for a in (0xFFFF9716, 0xFFFF9717, 0xFFFF9719, 0xFFFF90BB, 0xFFFF90BC):
            e.ram[a - E.RAM_LO] = rnd.choice([0, 1, 2, 3])
        old = {U0: e.read_u32(U0), U1: e.read_u32(U1)}
        log = []
        o_w = e.write

        def wr(a, n, v, o_w=o_w, e=e, log=log):
            a2 = a & 0xFFFFFFFF
            if U0 <= a2 < U1 + 4:
                sp = e.R[15]
                log.append((slot_of.get(e.pc, e.pc), a2, n, v, e.fr(12), e.fr(13), e.fr(15),
                            e.read_f32(sp), e.read_f32(sp + 4), e.read_f32(sp + 28), e.R[11]))
            return o_w(a, n, v)
        e.write = wr
        e.call(0x0209DC)
        for (pc, a, n, v, f12, f13, f15, s0, s4, s28, r11) in log:
            sites.setdefault((pc, a), 0)
            sites[(pc, a)] += 1
            assert n == 4
            val = E.b2f(v)
            if pc in (0x020CEA, 0x020CF2, 0x020CFC):
                assert r11 == 2, r11
                if pc == 0x020CEA:
                    assert v == 0                      # +0.0
                if pc == 0x020CF2:
                    assert val == 100.0
            if pc == 0x020D7E:
                assert r11 != 2
                span = f_add(f13, -f15)
                if abs(span) > 0.002:
                    want = max((s0 - f15) / span * 100.0, 0.0)
                    assert abs(val - want) <= 1e-4 * max(1.0, abs(want)), (val, want)
                    n_form += 1
                elif abs(span) < 0.0019:
                    assert v == old[U0]
                    n_keep += 1
            if pc == 0x020DB6:
                assert r11 != 2
                span = f_add(s28, -f12)
                if abs(span) > 0.002:
                    want = max((s4 - f12) / span * 100.0, 0.0)
                    assert abs(val - want) <= 1e-4 * max(1.0, abs(want)), (val, want)
                    n_form += 1
                elif abs(span) < 0.0019:
                    assert v == old[U1]
                    n_keep += 1
        ok()
    want_sites = {(0x020CEA, U1), (0x020CF2, U1), (0x020CFC, U0), (0x020D7E, U0), (0x020DB6, U1)}
    assert set(sites) == want_sites, sorted(sites)
    print(f'    400 random RAM states: stores to 0xFFFF6458..0xFFFF645F come ONLY from')
    for (pc, a), c in sorted(sites.items()):
        print(f'      {pc:06X} -> {a:#010x}  x{c}')
    print(f'    main stores: U0 = max(([F+0] - fr15)/(fr13 - fr15)*100, 0), U1 = max(([F+4] - fr12)/([F+28] - fr12)*100, 0)')
    print(f'      when the span is outside +-{win:.7f} ({n_form} cases), else the old value ({n_keep} cases);')
    print('      r11 == 2 branch: U1 = 0.0 or 100.0, then U0 = U1: OK')


def main():
    p1()
    p2()
    p3()
    p4()
    p5()
    p5b()
    p6()
    p7()
    p8()
    p9()
    p10()
    p11()
    p12()
    print(f'ALL PASSED: {CHECKS} asserted cases')
    return 0


if __name__ == '__main__':
    sys.exit(main())
