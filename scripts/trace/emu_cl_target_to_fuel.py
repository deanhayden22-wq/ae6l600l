#!/usr/bin/env python3
"""Emulation check for disassembly/analysis/cl_target_to_fuel_trace.txt:
does the closed-loop lambda target 0xFFFF77C8 reach fuelling through 0x032B10 and its callees?

    python3 scripts/trace/emu_cl_target_to_fuel.py

Reference bin: rom/AE5L600L 20g rev 20.19c.bin  md5 92cae8275cd4f9b473a3a9e36efe6449

Functions run in scripts/sh2e_emu.py, each against a Python model written from the bytes:
  0x032B10 (37 insns)  gate on byte [65F0]; [7720] = [40C8]; calls 0x0331C6, 0x032B5E, tail 0x032E28
  0x032B5E (138)       mode byte from four flags + a down-counter; writes [7710] (UPPER bound of [76D4])
  0x032E28 (226)       r4 = ROM table 0x063A10; writes [7714] (LOWER bound of [76D4]) and its helpers
  0x0330CA (47)        [7724] / [7710] from x + K, K = 0x033186() (which divides by [77C8])
  0x033128 (47)        [7728] / [7714] from x + K
  callees: 0x0331C6 (29), 0x032CE8 (53), 0x032D52 (107), 0x0278D2 (6), 0x074A54 (23)
  context: 0x03308E (30, the timer decrements), 0x032AA8 (52, the reset writer of the same cells),
           0x030378 (24, [7348] = [63F8] x "Injector Flow Scaling"), 0x0301E4 (172, the reader of [76D4]
           that multiplies it by [7348]), 0x03297A (112) and 0x032958 (17), the writers of [770C] that
           0x032B5E reads in MODE 3 / 19 (added at the third review), 0x0332A2 (the [65F6] == 1 reset of
           [77C8], write set only)

Per case the script asserts, bit for bit: every model output cell, the exact SET of non-stack RAM bytes
written, the exact SET of RAM cells read before being written in the call (inputs are poked without
marking them initialised), r8-r14 / r15 / GBR / fr12-fr15 restored.

Passes
  A  callee facts: 0x0278D2 and 0x074A54 exhaustive over the byte; table breakpoints = raw * scale
  B  0x0331C6, 0x0330CA, 0x033128 on grids incl. NaN / 0 / crossed bounds
  C  0x032CE8, 0x032D52 on grids
  D  0x032B5E over every mode (all 16 flag combinations x counter) and random floats
  E  0x032E28 on random grids, including [7348] = 0 / 2.0 / NaN and every gate
  F  0x032B10 end to end (gate byte 0..255, chained calls on one RAM image)
  G  0x0BE830 / 0x0BE8AC STUBBED with a per-descriptor function: which descriptor gets which input
  H  modified in-memory ROM copies (file never written): positive controls for paths the shipped
     calibration makes dead (G2 = 1, [77B4] loaded non-zero, byte 0x0F8A84 != 0)
  I  ON THE EMULATOR (two RAM images per case differing only in [77C8], incl. negative / 0 / NaN / inf):
     [77C8] changes a call's outputs only when 0x033186 runs, i.e. MODE 17/19 or the TRACK branch, and
     then only [7724] [7710] [7728] [7714]; monotonicity of 0x0330CA / 0x033128 in [77C8] for R > 0
     holds unless the two values straddle zero (L1 < 0 <= L2), where it fails (counterexamples
     counted); shipped ranges of [7710] / [7714] / [7730]; [7730] does NOT cap the default-mode [7710]
  J  0x03308E, 0x032AA8, 0x030378, 0x0301E4 against models
  K  stock bin: every byte these functions read (code, pools, cal, descriptors, tables) is identical
  L  instruction coverage of the five entries and their callees (+ 0x03297A, 0x032958)
  M  edge rows of 0x0330CA / 0x033128 on the emulator: [77C8] = 0 with R > 0 / R = 0 / R < 0, NaN
     [7710], NaN x / [7BE4] (third review, C18)
  N  chained calls on ONE RAM image: a [7710] built from 1/[77C8] in MODE 19 persists through MODE 5
     and MODE 8 with byte [7828] = 0, and through a gate-fail call; [7714] is rewritten on every gated
     call (third review, C39)
  O  0x03297A and 0x032958 (writers of [770C]) against a model; every store lands in [0.5, 1.5]; with
     such a [770C], MODE 3 stores the default value and MODE 19 passes the same x as MODE 17
  P  NaN / edge rows of the gates: NaN [7BCC] loads [77B4]; NaN sum passes G1; NaN [65FC] / [6364] /
     [76D4] pass G2 (third review, C23 / C28 / C29)
  Q  byte facts: the 03445A "store" to [7828] is pool data; the 0x063A04 / 0x063A10 / 0x063A2C table
     words; the 0x04A94C call order; 0x0332A2 writes [77C8] = 1.0 and not byte [7828]

ROUNDING: models compute each fadd/fsub/fmul/fdiv exactly and round TOWARD ZERO, fmac FUSED, as the
emulator does (corrections item 106).  Nothing in the trace rests on the last bit of a float.
Names are neutral: nothing here establishes what any RAM cell physically is.
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

BIN = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
STOCK = os.path.join(REPO, 'rom', 'ae5l600l.bin')
ROM = open(BIN, 'rb').read()
assert hashlib.md5(ROM).hexdigest() == '92cae8275cd4f9b473a3a9e36efe6449', 'wrong reference bin'
ROM_STOCK = open(STOCK, 'rb').read()
f2b, b2f = E.f2b, E.b2f

# ------------------------------------------------------------------ addresses
F32 = {}
U8 = {}
U16 = {}


def f(a):
    F32[a] = 4
    return a


def b(a):
    U8[a] = 1
    return a


def w(a):
    U16[a] = 2
    return a


A40C8, A7720, A772C, A7730, A6350, A7BE4, A77C8, A63C4, A68D8 = map(f, (
    0xFFFF40C8, 0xFFFF7720, 0xFFFF772C, 0xFFFF7730, 0xFFFF6350, 0xFFFF7BE4, 0xFFFF77C8, 0xFFFF63C4, 0xFFFF68D8))
A770C, A7710, A7714, A7718, A771C, A7724, A7728, A76D4, A7BCC, A63F8, A7348, A77A8, A77AC = map(f, (
    0xFFFF770C, 0xFFFF7710, 0xFFFF7714, 0xFFFF7718, 0xFFFF771C, 0xFFFF7724, 0xFFFF7728, 0xFFFF76D4,
    0xFFFF7BCC, 0xFFFF63F8, 0xFFFF7348, 0xFFFF77A8, 0xFFFF77AC))
A73B4, A73E0, A73E4, A6354, A65FC, A6364, A6624 = map(f, (
    0xFFFF73B4, 0xFFFF73E0, 0xFFFF73E4, 0xFFFF6354, 0xFFFF65FC, 0xFFFF6364, 0xFFFF6624))
A7704, A7708 = map(f, (0xFFFF7704, 0xFFFF7708))           # 0x03297A slots +0 / +4 (table 0x063A04)
ARR = [f(0xFFFF7734 + 4 * k) for k in range(29)]          # 0x7734..0x77A4 (reset fills 29)
A65F0, A98F4, A77B6, A7448, A77B8, A7828, A6254, A77B7, A77B9, A77BA, A77BB, A6A29, AA56A, AACE6, A65F6 = map(b, (
    0xFFFF65F0, 0xFFFF98F4, 0xFFFF77B6, 0xFFFF7448, 0xFFFF77B8, 0xFFFF7828, 0xFFFF6254, 0xFFFF77B7,
    0xFFFF77B9, 0xFFFF77BA, 0xFFFF77BB, 0xFFFF6A29, 0xFFFFA56A, 0xFFFFACE6, 0xFFFF65F6))
A77B0, A77B2, A77B4 = map(w, (0xFFFF77B0, 0xFFFF77B2, 0xFFFF77B4))
# 0x0301E4 block
P0301E4_F = [f(a) for a in (0xFFFF7AB4, 0xFFFF73A4, 0xFFFF7A08, 0xFFFF7BC4, 0xFFFF7878, 0xFFFF7AE4,
                            0xFFFF730C, 0xFFFF7310, 0xFFFF7314, 0xFFFF7318, 0xFFFF731C, 0xFFFF7B6C,
                            0xFFFF7B70, 0xFFFF7B74, 0xFFFF7B78, 0xFFFF733C, 0xFFFF7320, 0xFFFF7344,
                            0xFFFF7324, 0xFFFF7338, 0xFFFF732C, 0xFFFF7330, 0xFFFF7334, 0xFFFF7328)]
SIZE = {**F32, **U8, **U16}

# ------------------------------------------------------------------ ROM constants
D_AC4C0, D_AC4D4, D_ACE34, D_ACE40 = 0x0AC4C0, 0x0AC4D4, 0x0ACE34, 0x0ACE40
FN_LUT, FN_LUT16 = 0x0BE830, 0x0BE8AC
FN_CS_IN, FN_CS_OUT = 0x00317C, 0x003190
TBL = 0x063A10


def cal(rom, a):
    return struct.unpack_from('>I', rom, a)[0]


def cal16(rom, a):
    return struct.unpack_from('>H', rom, a)[0]


PZERO, ONE, TWO, NEG1 = 0, f2b(1.0), f2b(2.0), f2b(-1.0)
K05, K15, W15 = f2b(0.5), f2b(1.5), f2b(2.0 ** -15)
K131072, K262136 = f2b(131072.0), f2b(262136.0)
FLT_MAX, NFLT_MAX = 0x7F7FFFFF, 0xFF7FFFFF


# ------------------------------------------------------------------ float model primitives
def arith(op, xb, yb):
    x, y = b2f(xb), b2f(yb)
    fn = {'+': lambda p, q: p + q, '-': lambda p, q: p - q,
          '*': lambda p, q: p * q, '/': lambda p, q: p / q}[op]
    if op == '/' and y == 0.0:
        raise AssertionError('unguarded divide by zero in model')
    if not (math.isfinite(x) and math.isfinite(y)):
        try:
            return f2b(fn(x, y))
        except ZeroDivisionError:
            raise
    q = fn(Fraction(x), Fraction(y))
    return f2b(fn(x, y)) if q == 0 else E.rz_bits(q)


def fadd(p, q): return arith('+', p, q)
def fsub(p, q): return arith('-', p, q)
def fmul(p, q): return arith('*', p, q)


def fmac(p, q, r):
    x, y, z = b2f(p), b2f(q), b2f(r)
    ieee = x * y + z
    if not (math.isfinite(x) and math.isfinite(y) and math.isfinite(z)):
        return f2b(ieee)
    v = Fraction(x) * Fraction(y) + Fraction(z)
    return f2b(ieee) if v == 0 else E.rz_bits(v)


def gt(p, q):                       # fcmp/gt q,p : T = (p > q)
    return b2f(p) > b2f(q)


def clamp(x, lo, hi):               # 0x0BE56C, low test first
    if not gt(x, lo):
        return lo
    if gt(hi, x):
        return x
    return hi


def fmax(p, q): return p if gt(p, q) else q     # 0x0BE960
def fmin(p, q): return p if gt(q, p) else q     # 0x0BE970 (fr5 on tie / NaN)


def safe_div(p, q):                 # 0x0BE628
    if b2f(q) != 0.0:
        return arith('/', p, q)
    if b2f(p) == 0.0:
        return PZERO
    return FLT_MAX if b2f(p) > 0 else NFLT_MAX


def outside(x, c, wd):              # 0x0BE608: 1 = outside [c-w, c+w]
    if gt(fsub(c, wd), x):
        return 1
    if gt(x, fadd(c, wd)):
        return 1
    return 0


def neg(x): return x ^ 0x80000000
def sx8(v): return v - 256 if v & 0x80 else v


# ------------------------------------------------------------------ lookups (verified library, run in the emulator)
_lut_cache = {}


def rom_lookup(rom, d, xb):
    k = (id(rom), d, xb)
    if k not in _lut_cache:
        e = E.Emu(rom)
        e.call(FN_LUT, regs={4: d}, fregs={4: b2f(xb)})
        _lut_cache[k] = e.FR[0]
    return _lut_cache[k]


def rom_lookup16(rom, d, xb):
    k = (id(rom), d, xb, 16)
    if k not in _lut_cache:
        e = E.Emu(rom)
        e.call(FN_LUT16, regs={4: d}, fregs={4: b2f(xb)})
        _lut_cache[k] = e.R[0] & 0xFFFF
    return _lut_cache[k]


def rom_lag(new, old, k, eps):
    """0x0BEA40 (verified, helpers_wrap_trace.txt) run in the emulator on raw float bits."""
    e = E.Emu(ROM)
    e.FR[4], e.FR[5], e.FR[6], e.FR[7] = new, old, k, eps
    e.call(0x0BEA40)
    return e.FR[0]


# ------------------------------------------------------------------ the model
class Mem:
    def __init__(self, init, rom, lut=None, lut16=None):
        self.m = dict(init)
        self.rom = rom
        self.reads = set()
        self.written = set()        # byte addresses
        self.calls = []
        self.lut = lut or (lambda d, x: rom_lookup(rom, d, x))
        self.lut16 = lut16 or (lambda d, x: rom_lookup16(rom, d, x))

    def rd(self, a):
        n = SIZE[a]
        if not all((a + i) in self.written for i in range(n)):
            self.reads.add(a)
        return self.m[a]

    def wr(self, a, v):
        n = SIZE[a]
        self.m[a] = v & ((1 << (8 * n)) - 1)
        self.written.update(range(a, a + n))

    def L(self, d, xb):
        self.calls.append((d, xb))
        return self.lut(d, xb)

    def L16(self, d, xb):
        self.calls.append((d, xb))
        return self.lut16(d, xb)

    def c(self, a): return cal(self.rom, a)


def m_033186(M):                    # hole9_identity_trace.txt CONTRACT (verified)
    t1 = safe_div(ONE, M.rd(A77C8))
    a = M.rd(A63C4)
    s = fadd(a, M.rd(A68D8))
    t2 = safe_div(s, a)
    p = fsub(fmul(t1, t2), M.rd(A7BE4))
    return fadd(NEG1, p)


def m_0330CA(M, x, out=A7724, bound=A7710, dcal=0x0CBEE0):
    k = m_033186(M)
    M.wr(out, clamp(fadd(x, k), K05, K15))
    d = M.c(dcal)
    hi = fadd(M.rd(bound), d)
    lo = fsub(M.rd(bound), d)
    v = clamp(M.rd(out), lo, hi)
    v = fmin(v, M.rd(A7730))
    M.wr(bound, clamp(v, K05, K15))


def m_033128(M, x):
    m_0330CA(M, x, out=A7728, bound=A7714, dcal=0x0CBF30)


def m_0331C6(M):
    M.wr(A772C, M.L(D_ACE40, M.rd(A6350)))
    den = fmul(fadd(M.rd(A7BE4), ONE), M.rd(A772C))
    M.wr(A7730, clamp(safe_div(ONE, den), K05, K15))


def m_032B5E(M):
    cur = M.rd(A98F4) & 0xFF
    M.wr(A98F4, 0)
    cnt = M.rd(A77B6)
    if cnt != 0:
        mode = 8
        M.wr(A77B6, (cnt - 1) & 0xFF)
    else:
        mode = 1 if sx8(M.rd(A7448)) == 1 else 0
        if cur == 1:
            mode += 2
        if sx8(M.rd(A77B8)) == 1:
            mode += 4
        if sx8(M.rd(A7828)) == 1:
            mode += 16
    if mode in (5, 21):
        M.wr(A77B6, M.rom[0x0CBBE0])
    elif mode in (7, 23, 8):
        pass
    else:
        m1 = fmin(M.L(D_AC4C0, M.rd(A7720)), M.c(0x0CBEDC))
        if mode in (3, 19):
            m1 = fmin(fadd(M.rd(A770C), M.c(0x0CBED8)), m1)
        if mode in (17, 19):
            m_0330CA(M, m1)
        else:
            M.wr(A7710, clamp(m1, K05, K15))
    M.wr(A77B8, cur)
    return mode


def m_032CE8(M):
    f9, f6, f8 = M.rd(A6350), M.rd(A6354), M.rd(A73B4)
    if not (gt(f8, M.c(0x0CBEF8)) and gt(M.c(0x0CBEFC), f8)):
        M.wr(A77B0, cal16(M.rom, 0x0CBC2E))
    s = fadd(M.rd(A73E0), M.rd(A73E4))
    if gt(M.c(0x0CBEE4), s) or gt(M.c(0x0CBEE8), f9) or not gt(M.c(0x0CBEEC), f9) \
            or gt(M.c(0x0CBEF0), f6) or not gt(M.c(0x0CBEF4), f6):
        return 0
    return 1 if M.rd(A77B0) != 0 else 0


def m_032D52(M):
    f15, f12, f14 = M.rd(A65FC), M.rd(A6364), M.rd(A6624)
    r6 = 1 if (M.rd(A6A29) & 0x80) else 0
    r5, r4, f8 = M.rd(AA56A), M.rd(AACE6), M.rd(A76D4)
    if not gt(M.c(0x0CBF18), f14):
        M.wr(A77B9, 1)
    elif gt(M.c(0x0CBF14), f14):
        M.wr(A77B9, 0)
    if not gt(M.c(0x0CBF20), f14):
        M.wr(A77BA, 0)
    elif gt(M.c(0x0CBF1C), f14):
        M.wr(A77BA, 1)
    if r6 == 0 and sx8(M.rd(A77BB)) == 1:
        M.wr(A77B2, cal16(M.rom, 0x0CBC30))
    ok = (r5 == 0 and r4 == 0)
    res = 0
    if M.rd(A77B2) != 0 and not gt(f15, M.c(0x0CBF0C)) and not gt(M.c(0x0CBF10), f12) \
            and sx8(M.rd(A77B9)) == 1 and sx8(M.rd(A77BA)) == 1 and ok \
            and not gt(f8, M.c(0x0CBF24)) and M.rd(A7828) == 0:
        res = 1
    M.wr(A77BB, r6)
    return res


def m_032E28(M):
    en = M.rd(A7448)
    afc, f12, f13 = M.rd(A76D4), M.rd(A7BCC), M.rd(A63F8)
    g1 = m_032CE8(M)
    g2 = m_032D52(M)
    b7828, b6254 = M.rd(A7828), M.rd(A6254)
    f9 = M.rd(A7348)
    n = M.rom[0x0CBBE1]
    if gt(TWO, f9):
        q = TWO
    else:
        q = arith('/', M.rd(ARR[n]), f9)
    M.wr(A771C, q)
    for k in range(n, 0, -1):
        M.wr(ARR[k], M.rd(ARR[k - 1]))
    M.wr(ARR[0], f9)
    if en == 0 or gt(M.c(0x0CBF04), M.rd(A771C)) or not gt(M.c(0x0CBF08), M.rd(A771C)) \
            or b6254 == 1 or b7828 == 1:
        M.wr(A77B7, 0)
    elif g1 != 1 or gt(afc, M.c(0x0CBF00)):
        pass
    else:
        M.wr(A77B7, 1)
    inside = outside(f12, PZERO, W15) == 0
    if inside and outside(M.rd(A77A8), PZERO, W15) != 0:
        M.wr(A77B4, M.L16(D_ACE34, f13))
    M.wr(A77AC, M.L(D_AC4D4, M.rd(A7720)))
    f14 = fmax(M.rd(A77AC), M.c(0x0CBF28))
    path = None
    if inside and M.rd(A77B4) != 0:
        f14 = fmax(f14, M.c(0x0CBF38))
        path = 'HOLD95'
    elif M.rd(A77B7) != 0 or g2 != 0:
        path = 'RAMP'
        p = neg(fmul(M.rd(A771C), fsub(ONE, f14)))
        M.wr(A7718, clamp(fmac(p, M.c(0x0CBF2C), ONE), K05, K15))
        v = clamp(M.rd(A7718), f14, M.c(0x0CBF34))
        M.wr(A7714, clamp(v, K05, K15))
    elif en == 1 and b7828 == 1:
        path = 'TRACK'
        m_033128(M, f14)
    else:
        path = 'BASE'
    if path in ('HOLD95', 'BASE'):
        M.wr(A7714, clamp(f14, K05, K15))
    M.wr(A77A8, f12)
    return path, g1, g2


def m_032B10(M):
    sel = M.rd(A65F0)
    v = M.rd(A40C8)
    if sel not in tuple(M.rom[0x0CBBD8 + i] for i in range(4)):
        return None
    M.wr(A7720, v)
    m_0331C6(M)
    mode = m_032B5E(M)
    return mode, m_032E28(M)


def m_03308E(M):
    for a in (A77B4, A77B0, A77B2):
        v = M.rd(a)
        if v != 0:
            M.wr(a, v - 1)


def m_032AA8(M):
    v = M.rd(A7348)
    if M.rd(A65F6) != 1:
        return
    for a in (A7710, A7714, A771C):
        M.wr(a, ONE)
    M.wr(A7718, f2b(0.75))
    M.wr(A77B8, 0)
    M.wr(A77B6, 0)
    M.wr(A77A8, PZERO)
    for k in range(29):
        M.wr(ARR[k], v)
    M.wr(A772C, ONE)
    M.wr(A7730, ONE)
    M.wr(A7724, f2b(1.25))
    M.wr(A7728, f2b(0.75))


def m_03297A(M):
    """0x03297A: gate on byte [65F0] as 0x032B10; r4 = 0x063A04 (+0 7704, +4 7708, +8 770C), r5 = 0."""
    sel = M.rd(A65F0)
    if sel not in tuple(M.rom[0x0CBBD8 + i] for i in range(4)):
        return None
    new = M.rd(A76D4)                         # 0329C6 (r5 = 0 path; 0329CE/0329D0 unreachable)
    en = M.rd(A7448)                          # 0329CC, extu.b at 0329D2
    if en == 1:
        for slot, kc, eps in ((A7704, 0x0CBECC, W15), (A7708, 0x0CBED0, W15), (A770C, 0x0CBED4, f2b(2.0 ** -13))):
            M.wr(slot, clamp(rom_lag(new, M.rd(slot), M.c(kc), eps), K05, K15))
        return 'lag'
    for slot in (A7704, A7708, A770C):        # 032A44 / 032A48 / 032A4C
        M.wr(slot, ONE)
    return 'one'


def m_032958(M):
    if M.rd(A65F6) != 1:                      # 0x022F92: byte [65F6] == 1
        return
    for slot in (A7704, A7708, A770C):        # 03296C / 032970 / 032972 (r2 = 0xFFFF770C, -8 / -4 / 0)
        M.wr(slot, ONE)


def m_030378(M):
    x = M.rd(A63F8)
    k = M.c(0x0CBE0C)
    v = fmul(x, k) if M.rom[0x0F8A84] == 0 else fmul(k, PZERO)
    M.wr(A7348, clamp(v, PZERO, K131072))


def m_0301E4(M):
    g = lambda a: M.rd(a)  # noqa: E731
    s0, s4 = g(A7348), g(0xFFFF7AB4)
    f1, f5, f12 = g(0xFFFF73A4), g(0xFFFF7A08), g(0xFFFF7BC4)
    c = fmul(fadd(fadd(g(A76D4), g(0xFFFF7878)), g(0xFFFF7AE4)), s0)
    f13 = fmul(c, g(0xFFFF730C))
    f9 = fmul(s4, c)
    f0 = fmul(g(0xFFFF7310), f9)
    f6 = fmul(g(0xFFFF7314), f9)
    f7 = fmul(g(0xFFFF7318), f9)
    f4 = fmul(g(0xFFFF731C), f9)
    s8 = fmul(fmac(f0, g(0xFFFF7B6C), PZERO), f12)
    s12 = fmul(fmac(f6, g(0xFFFF7B70), PZERO), f12)
    s16 = fmul(fmac(f7, g(0xFFFF7B74), PZERO), f12)
    s20 = fmul(fmac(f4, g(0xFFFF7B78), PZERO), f12)
    f14 = fsub(fsub(g(0xFFFF730C), f1), f5)
    lo = lambda: g(0xFFFF733C)  # noqa: E731
    M.wr(0xFFFF7320, clamp(fmul(f13, f12), lo(), K262136))
    M.wr(0xFFFF7344, clamp(f13, lo(), K262136))
    M.wr(0xFFFF7324, clamp(fmul(fmac(f13, s4, PZERO), f12), lo(), K262136))
    M.wr(0xFFFF7338, clamp(fmul(fmac(fmul(s0, s4), f14, PZERO), f12), lo(), K262136))
    M.wr(0xFFFF7328, clamp(s8, lo(), K262136))      # r13-28
    M.wr(0xFFFF732C, clamp(s12, lo(), K262136))     # r13-24
    M.wr(0xFFFF7330, clamp(s16, lo(), K262136))     # r13-20
    M.wr(0xFFFF7334, clamp(s20, lo(), K262136))     # r13-16
    return c


# ------------------------------------------------------------------ emulator harness
SENT = {8: 0x88888888, 9: 0x99999999, 10: 0xAAAAAAAA, 11: 0xBBBBBBBB, 12: 0xCCCCCCCC,
        13: 0xDDDDDDDD, 14: 0xEEEEEEEE}
FSENT = {12: 0x41400000, 13: 0x41500000, 14: 0x41600000, 15: 0x41700000}
GBR_SENT = 0xFFFF1234
COVER = set()
_rng_regs = random.Random(7)


def poke(e, a, n, v):
    o = a - E.RAM_LO
    e.ram[o:o + n] = (v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big')


def peek(e, a, n):
    o = a - E.RAM_LO
    return int.from_bytes(e.ram[o:o + n], 'big')


def run(entry, model, init, rom=ROM, regs=None, fregs=None, stub_lut=None, stub_lut16=None):
    """Run entry once in the emulator and the model; assert outputs, write set, read set, preservation."""
    e = E.Emu(rom)
    for a, v in init.items():
        poke(e, a, SIZE[a], v)
    e.stub(FN_CS_IN, r0=0)            # critical section enter / leave (raise on ldc sr in the emulator)
    e.stub(FN_CS_OUT)
    got_calls = []
    if stub_lut is not None:
        def _l(m):
            got_calls.append((m.R[4], m.FR[4]))
            m.FR[0] = stub_lut(m.R[4], m.FR[4])
        e.stub(FN_LUT, fn=_l)
    if stub_lut16 is not None:
        def _l16(m):
            got_calls.append((m.R[4], m.FR[4]))
            m.R[0] = stub_lut16(m.R[4], m.FR[4])
        e.stub(FN_LUT16, fn=_l16)
    r = {i: _rng_regs.getrandbits(32) for i in range(8)}
    r.update(SENT)
    r.update(regs or {})
    for i in range(12):
        e.FR[i] = _rng_regs.getrandbits(32)
    for i, v in FSENT.items():
        e.FR[i] = v
    for i, v in (fregs or {}).items():
        e.FR[i] = v
    e.gbr = GBR_SENT
    assert e.call(entry, regs=r) == 'return'
    COVER.update(e.executed)
    M = Mem(init, rom, lut=stub_lut, lut16=stub_lut16)
    ret = model(M)
    tag = ' '.join(f'{a & 0xFFFF:04X}={v:#x}' for a, v in sorted(init.items()))
    for a in sorted(x for x in SIZE if any((x + i) in M.written for i in range(SIZE[x]))):
        g = peek(e, a, SIZE[a])
        assert g == M.m[a], f'{entry:06X} OUTPUT {a:#x}: emu {g:#x} model {M.m[a]:#x}\n{tag}'
    assert set(e.writes) == M.written, (f'{entry:06X} WRITE SET\n emu   {sorted(map(hex, e.writes))}'
                                        f'\n model {sorted(map(hex, M.written))}\n{tag}')
    assert e.uninit_reads == M.reads, (f'{entry:06X} READ SET\n emu   {sorted(map(hex, e.uninit_reads))}'
                                       f'\n model {sorted(map(hex, M.reads))}\n{tag}')
    for i, v in SENT.items():
        if i not in (regs or {}):
            assert e.R[i] == v, f'{entry:06X} r{i} not preserved'
    assert e.R[15] == E.STACK_TOP and e.gbr == GBR_SENT
    for i, v in FSENT.items():
        assert e.FR[i] == v, f'{entry:06X} fr{i} not preserved'
    if stub_lut is not None or stub_lut16 is not None:
        assert got_calls == M.calls, f'{entry:06X} CALLS\n emu   {got_calls}\n model {M.calls}\n{tag}'
    return M, ret, e


# ------------------------------------------------------------------ inputs
FV = [0.0, -0.0, 0.25, 0.5, 0.75, 0.85, 0.9, 0.95, 1.0, 1.05, 1.1, 1.2, 1.25, 1.5, 2.0, 3.0, -1.0,
      -0.1, 0.05, 1e-5, 2.0 ** -15, -(2.0 ** -15), 3e-5, 100.0, -40.0, 119.0, 10000.0, 12500.0, 14000.0,
      64.0, 128.0, 300.0, 4000.0, 131072.0]


def fv(r, special=0.02, pool=FV):
    x = r.random()
    if x < special:
        return f2b(r.choice([math.inf, -math.inf, math.nan]))
    if x < 0.55:
        return f2b(r.choice(pool))
    return f2b(r.uniform(-2.0, 3.0))


def bv(r):
    return r.choice([0, 1, 1, 1, 2, 0x80, 0xFF, 0x7F])


def fill(r, cells):
    d = {}
    for a in cells:
        if a in F32:
            d[a] = fv(r)
        elif a in U8:
            d[a] = bv(r)
        else:
            d[a] = r.choice([0, 0, 1, 2, 1250, 0xFFFF])
    return d


ALL_IN = [A40C8, A6350, A7BE4, A77C8, A63C4, A68D8, A770C, A7710, A7714, A76D4, A7BCC, A63F8, A7348,
          A77A8, A73B4, A73E0, A73E4, A6354, A65FC, A6364, A6624, A98F4, A77B6, A7448, A77B8, A7828,
          A6254, A77B7, A77B9, A77BA, A77BB, A6A29, AA56A, AACE6, A77B0, A77B2, A77B4, A65F0] + ARR[:21]


def case(r):
    c = fill(r, ALL_IN)
    # make the interesting gates hit often
    if r.random() < 0.6:
        c[A7448] = 1
    if r.random() < 0.5:
        c[A7828] = r.choice([0, 1])
    if r.random() < 0.5:
        c[A77B6] = 0
    if r.random() < 0.4:
        c[A7348] = f2b(r.uniform(2.0, 5000.0))
        for k in range(21):
            c[ARR[k]] = f2b(r.uniform(2.0, 5000.0))
    if r.random() < 0.3:
        c[A7BCC] = r.choice([PZERO, f2b(1e-6), f2b(1.0)])
        c[A77A8] = r.choice([PZERO, f2b(1.0)])
    if r.random() < 0.5:
        c[A6350] = f2b(r.uniform(-40, 125))
        c[A6354] = f2b(r.uniform(-40, 125))
        c[A73B4] = f2b(r.uniform(-0.2, 0.1))
        c[A73E0] = f2b(r.uniform(-1, 2))
    return c


# ------------------------------------------------------------------ passes
def passA():
    for v in range(256):
        e = E.Emu(ROM)
        poke(e, A6A29, 1, v)
        e.call(0x0278D2)
        assert e.R[0] == (1 if v & 0x80 else 0)
        e = E.Emu(ROM)
        poke(e, A98F4, 1, v)
        e.stub(FN_CS_IN, r0=0x30)
        e.stub(FN_CS_OUT)
        e.call(0x074A54, regs={4: 0})
        assert e.R[0] == (v | 0xFFFFFF00 if v & 0x80 else v) and peek(e, A98F4, 1) == 0
        assert set(e.writes) == {A98F4}
    # table breakpoints: lookup at each axis value == raw cell * scale (scales are powers of two)
    for d, scale in ((D_AC4C0, 1 / 128), (D_AC4D4, 1 / 128), (D_ACE40, 2.0 ** -16)):
        n = struct.unpack_from('>H', ROM, d)[0]
        ax, dp, tc = cal(ROM, d + 4), cal(ROM, d + 8), ROM[d + 2]
        for i in range(n):
            x = cal(ROM, ax + 4 * i)
            raw = ROM[dp + i] if tc == 4 else cal16(ROM, dp + 2 * i)
            assert rom_lookup(ROM, d, x) == f2b(raw * scale), (hex(d), i)
    # non-finite inputs: NaN and +inf give the LAST cell, -inf the first (so the shipped ranges hold for any input)
    for d, first, last in ((D_AC4C0, 1.25, 1.1015625), (D_AC4D4, 0.75, 0.953125),
                           (D_ACE40, 45875 / 65536, 45875 / 65536)):
        assert rom_lookup(ROM, d, f2b(math.nan)) == f2b(last) and rom_lookup(ROM, d, f2b(math.inf)) == f2b(last)
        assert rom_lookup(ROM, d, f2b(-math.inf)) == f2b(first)
        for x in (-1e30, -100.0, 300.0, 1e30):
            v = b2f(rom_lookup(ROM, d, f2b(x)))
            assert min(first, last) <= v <= max(first, last)
    # ACE34 (uint16 wrapper 0x0BE8AC): every cell 0 in 20.19c and stock -> r0 = 0 for any input
    for x in FV + [math.nan, math.inf, -math.inf]:
        assert rom_lookup16(ROM, D_ACE34, f2b(x)) == 0 and rom_lookup16(ROM_STOCK, D_ACE34, f2b(x)) == 0
    print('A  0x0278D2 / 0x074A54 exhaustive (256 each); AC4C0 / AC4D4 / ACE40 breakpoints = raw*scale, NaN / +inf -> last cell; '
          'ACE34 lookups all 0')
    print('   AC4C0 cells', [round(b2f(rom_lookup(ROM, D_AC4C0, f2b(32.0 * i))), 6) for i in range(9)])
    print('   AC4D4 cells', [round(b2f(rom_lookup(ROM, D_AC4D4, f2b(32.0 * i))), 6) for i in range(9)])
    print('   ACE40 cells', b2f(rom_lookup(ROM, D_ACE40, f2b(0.0))), '(all 16 = 45875/65536)')


def passB(N=1500):
    r = random.Random(11)
    cells_k = [A77C8, A63C4, A68D8, A7BE4]
    for i in range(N):
        c = fill(r, cells_k + [A6350, A7710, A7714, A7730])
        if i % 3 == 0:
            c[A77C8] = f2b(r.choice([0.75, 0.85, 1.0, 1.05, 1.2, 1.25, 0.0]))
            c[A63C4] = f2b(r.uniform(0.1, 3.0))
            c[A68D8] = f2b(r.uniform(-0.2, 0.2))
            c[A7BE4] = f2b(r.uniform(0.0, 0.3))
            c[A7710] = f2b(r.uniform(0.5, 1.5))
            c[A7714] = f2b(r.uniform(0.5, 1.5))
            c[A7730] = f2b(r.uniform(0.5, 1.5))
        x = fv(r)
        run(0x0330CA, lambda M: m_0330CA(M, x), {a: c[a] for a in cells_k + [A7710, A7730]}, fregs={4: x})
        run(0x033128, lambda M: m_033128(M, x), {a: c[a] for a in cells_k + [A7714, A7730]}, fregs={4: x})
        run(0x0331C6, m_0331C6, {A6350: c[A6350], A7BE4: c[A7BE4]})
    # explicit rows
    rows = []
    for l8, xx in ((1.0, 1.25), (1.2, 1.25), (0.85, 1.25), (1.0, 1.1015625), (1.2, 1.1015625)):
        c = {A77C8: f2b(l8), A63C4: ONE, A68D8: PZERO, A7BE4: PZERO, A7710: f2b(1.25), A7730: f2b(1.4)}
        M, _, _ = run(0x0330CA, lambda M: m_0330CA(M, f2b(xx)), c, fregs={4: f2b(xx)})
        rows.append((l8, xx, b2f(M.m[A7724]), b2f(M.m[A7710])))
    print(f'B  0x0330CA / 0x033128 / 0x0331C6: {N} cases each, bit-exact incl. write / read sets')
    for l8, xx, a, h in rows:
        print(f'   [77C8]={l8:<5} x={xx:<10} [7710]old=1.25 [7730]=1.4 -> [7724]={a:.7f} [7710]={h:.7f}')


def passC(N=2000):
    r = random.Random(12)
    for _ in range(N):
        c = case(r)
        run(0x032CE8, m_032CE8, {a: c[a] for a in (A6350, A6354, A73B4, A73E0, A73E4, A77B0)})
        run(0x032D52, m_032D52, {a: c[a] for a in (A65FC, A6364, A6624, A6A29, AA56A, AACE6, A76D4,
                                                   A77B9, A77BA, A77BB, A77B2, A7828)})
    print(f'C  0x032CE8 / 0x032D52: {N} cases each, bit-exact incl. write / read sets')


def passD(N=200):
    r = random.Random(13)
    modes = {}
    for cnt in (0, 1, 5):
        for bits in range(16):
            for _ in range(N // 16 + 1):
                c = case(r)
                c[A77B6] = cnt
                c[A7448] = 1 if bits & 1 else r.choice([0, 2, 0xFF])
                c[A98F4] = 1 if bits & 2 else r.choice([0, 2, 0x81])
                c[A77B8] = 1 if bits & 4 else r.choice([0, 3])
                c[A7828] = 1 if bits & 8 else r.choice([0, 0xFF])
                c[A7730] = fv(r)
                ins = {a: c[a] for a in (A98F4, A77B6, A7448, A77B8, A7828, A770C, A7710, A77C8, A63C4,
                                         A68D8, A7BE4, A7730)}
                ins[A7720] = c[A40C8]
                M, mode, e = run(0x032B5E, m_032B5E, ins)
                modes[mode] = modes.get(mode, 0) + 1
                if cnt:                                  # CNT != 0: MODE 8 whatever the flags, [7710] untouched
                    assert mode == 8 and A7710 not in e.writes and peek(e, A77B6, 1) == cnt - 1
                if mode in (5, 7, 8, 21, 23):            # hold MODEs never write [7710]
                    assert not any((A7710 + i) in e.writes for i in range(4))
    assert set(modes) == {0, 1, 2, 3, 4, 5, 6, 7, 8, 16, 17, 18, 19, 20, 21, 22, 23}, modes
    print(f'D  0x032B5E: {sum(modes.values())} cases over all 17 reachable mode codes {sorted(modes)}')


def passE(N=3000):
    r = random.Random(14)
    paths = {}
    for _ in range(N):
        c = case(r)
        ins = {a: c[a] for a in ALL_IN if a not in (A65F0, A40C8, A98F4, A77B6, A77B8, A770C, A7710)}
        ins[A7720] = c[A40C8]
        ins[A7730] = f2b(r.uniform(0.5, 1.5))
        M, (path, g1, g2), _ = run(0x032E28, m_032E28, ins, regs={4: TBL})
        paths[(path, g1, g2)] = paths.get((path, g1, g2), 0) + 1
    for k in (('HOLD95', 0, 0), ('RAMP', 1, 0), ('TRACK', 0, 0), ('BASE', 0, 0)):
        assert any(p == k[0] for p, _, _ in paths), k
    print(f'E  0x032E28: {N} cases, paths {sorted((k, v) for k, v in paths.items())}')


def passF(N=600):
    r = random.Random(15)
    hits = 0
    for sel in range(256):
        c = case(r)
        c[A65F0] = sel
        M, ret, _ = run(0x032B10, m_032B10, c)
        assert (ret is not None) == (sel in (0, 6, 12, 18))
        hits += ret is not None
    for _ in range(N):
        c = case(r)
        c[A65F0] = r.choice([0, 6, 12, 18])
        c[A7730] = f2b(1.0)
        run(0x032B10, m_032B10, c)
    # chained: one RAM image, 40 consecutive calls with the decrement routine between them
    e = E.Emu(ROM)
    e.stub(FN_CS_IN, r0=0)
    e.stub(FN_CS_OUT)
    st = case(r)
    st.update({A65F0: 0, A7448: 1, A7828: 1, A77B6: 0, A77B0: 0, A77B2: 0, A77B4: 0, A7730: ONE})
    for a, v in st.items():
        poke(e, a, SIZE[a], v)
    mem = dict(st)
    for k in range(40):
        mem[A40C8] = f2b(8.0 * k)
        poke(e, A40C8, 4, mem[A40C8])
        e.writes.clear()
        e.call(0x032B10, regs={15: E.STACK_TOP})
        M = Mem(mem, ROM)
        m_032B10(M)
        mem = M.m
        for a in SIZE:
            if a in mem:
                assert peek(e, a, SIZE[a]) == mem[a], (k, hex(a))
        e.call(0x03308E)
        M = Mem(mem, ROM)
        m_03308E(M)
        mem = M.m
    print(f'F  0x032B10: gate byte 0..255 ({hits} pass: 0x00 0x06 0x0C 0x12), {N} random end-to-end, '
          '40 chained calls with 0x03308E between them')


def lin(d, xb):
    """Stub table: a distinct exact function of x per descriptor."""
    x = b2f(xb)
    if not math.isfinite(x):
        return f2b(1.0)
    k = {D_AC4C0: 1.0, D_AC4D4: 0.5, D_ACE40: 0.25}[d]
    return f2b(max(-1e6, min(1e6, 0.75 + k * x / 512.0)))


def lin16(d, xb):
    x = b2f(xb)
    return 7 if not math.isfinite(x) else int(abs(x)) % 5


def passG(N=1500):
    r = random.Random(16)
    for _ in range(N):
        c = case(r)
        c[A65F0] = 0
        run(0x032B10, m_032B10, c, stub_lut=lin, stub_lut16=lin16)
    print(f'G  stubbed lookups: {N} end-to-end cases; ordered (descriptor, input) calls match: '
          'ACE40 <- [6350], AC4C0 <- [7720], ACE34 <- [63F8], AC4D4 <- [7720]')


def mrom(patch):
    m = bytearray(ROM)
    for a, v in patch.items():
        m[a:a + len(v)] = v
    return bytes(m)


def passH(N=800):
    r = random.Random(17)
    # G2 = 1 needs [77B2] != 0 (reload 0x0CBC30 = 0), [65FC] <= 0x0CBF0C (0.0), [76D4] <= 0x0CBF24 (0.0)
    rom_g2 = mrom({0x0CBC30: b'\x00\x05', 0x0CBF0C: struct.pack('>f', 300.0), 0x0CBF24: struct.pack('>f', 2.0)})
    seen = 0
    for _ in range(N):
        c = case(r)
        c.update({A7828: 0, A6A29: 0, A77BB: 1, A6624: f2b(11500.0), A77B9: 1, A77BA: 1, AA56A: 0,
                  AACE6: 0, A6364: f2b(120.0), A65FC: f2b(10.0), A76D4: f2b(1.0)})
        ins = {a: c[a] for a in ALL_IN if a not in (A65F0, A40C8, A98F4, A77B6, A77B8, A770C, A7710)}
        ins[A7720] = c[A40C8]
        ins[A7730] = ONE
        M, (path, g1, g2), _ = run(0x032E28, m_032E28, ins, rom=rom_g2, regs={4: TBL})
        seen += g2
        if g2 and M.m[A77B4] == 0:
            assert path == 'RAMP'
    assert seen > 0
    # ACE34 non-zero: [77B4] loaded and the HOLD95 branch taken
    rom_34 = mrom({0x0CDF1C + 2 * i: b'\x00\x09' for i in range(16)})
    held = 0
    for _ in range(N // 2):
        c = case(r)
        c.update({A7BCC: PZERO, A77A8: ONE})
        ins = {a: c[a] for a in ALL_IN if a not in (A65F0, A40C8, A98F4, A77B6, A77B8, A770C, A7710)}
        ins[A7720] = c[A40C8]
        ins[A7730] = ONE
        M, (path, _, _), _ = run(0x032E28, m_032E28, ins, rom=rom_34, regs={4: TBL})
        assert M.m[A77B4] == 9 and path == 'HOLD95'
        held += 1
    # byte 0x0F8A84 != 0 -> [7348] = 0
    rom_f8 = mrom({0x0F8A84: b'\x01'})
    for x in (0.0, 1.0, 2.5, -1.0):
        M, _, _ = run(0x030378, m_030378, {A63F8: f2b(x)}, rom=rom_f8)
        assert M.m[A7348] == PZERO
    print(f'H  positive controls on in-memory ROM copies: G2 = 1 in {seen} cases (0x0CBC30 = 5, '
          f'0x0CBF0C = 300, 0x0CBF24 = 2); ACE34 = 9 -> [77B4] = 9, HOLD95 in {held}; byte 0x0F8A84 = 1 '
          '-> [7348] = 0')


L8_POOL = [0.85, 1.0, 1.05, 1.2, 0.9, 1.1, 1.25, 0.75, -1.0, -0.5, 0.0, -0.0, 1e-30, -1e-30, 2.0,
           math.nan, math.inf, -math.inf]


def ram_cells_differ(e1, e2, skip):
    """Cells (from SIZE) whose bytes differ between two emulator images, among bytes either wrote."""
    out = set()
    for a, n in SIZE.items():
        if a in skip:
            continue
        o = a - E.RAM_LO
        if not any((a + i) in e1.writes or (a + i) in e2.writes for i in range(n)):
            continue
        if bytes(e1.ram[o:o + n]) != bytes(e2.ram[o:o + n]):
            out.add(a)
    return out


def passI(N=1500):
    r = random.Random(18)
    dep, indep, used = 0, 0, 0
    for _ in range(N):
        c = case(r)
        c[A65F0] = r.choice([0, 6, 12, 18])
        v1, v2 = r.sample(L8_POOL, 2)
        if f2b(v1) == f2b(v2):
            continue
        c[A77C8] = f2b(v1)
        c2 = dict(c)
        c2[A77C8] = f2b(v2)
        M1, ret1, e1 = run(0x032B10, m_032B10, c)          # each run is also checked bit-exact against the model
        M2, ret2, e2 = run(0x032B10, m_032B10, c2)
        mode, path = ret1[0], ret1[1][0]
        uses = mode in (17, 19) or path == 'TRACK'
        assert (0x033186 in e1.executed) == uses == (0x033186 in e2.executed), (mode, path)
        diff = ram_cells_differ(e1, e2, {A77C8})
        if not uses:
            assert not diff and set(e1.writes) == set(e2.writes), (mode, path, diff)
            indep += 1
        else:
            used += 1
            assert diff <= {A7724, A7710, A7728, A7714}, diff
            dep += bool(diff)
    assert dep > 0 and indep > 0
    # monotonicity of 0x0330CA / 0x033128 in [77C8], ON THE EMULATOR, R = ([63C4] + [68D8]) / [63C4] > 0
    mono, straddle, straddle_raise = 0, 0, 0
    pool = [0.0, -0.0, 1e-30, -1e-30, 0.75, 1.25, -0.75, -1.25]
    for i in range(N):
        a63 = r.uniform(0.1, 3.0)
        base = {A63C4: f2b(a63), A68D8: f2b(r.uniform(-0.09, 0.3) * a63), A7BE4: f2b(r.uniform(0.0, 0.3)),
                A7710: f2b(r.uniform(0.5, 1.5)), A7714: f2b(r.uniform(0.5, 1.5)), A7730: f2b(r.uniform(0.5, 1.5))}
        x = f2b(r.uniform(0.4, 1.6))
        l1, l2 = sorted((r.choice(pool) if r.random() < 0.3 else r.uniform(-2.0, 2.0),
                         r.choice(pool) if r.random() < 0.3 else r.uniform(-2.0, 2.0)))
        if f2b(l1) == f2b(l2):
            continue
        outs = []
        for lv in (l1, l2):
            ins = {**base, A77C8: f2b(lv)}
            Ma, _, _ = run(0x0330CA, lambda M: m_0330CA(M, x), {a: ins[a] for a in
                           (A77C8, A63C4, A68D8, A7BE4, A7710, A7730)}, fregs={4: x})
            Mb, _, _ = run(0x033128, lambda M: m_033128(M, x), {a: ins[a] for a in
                           (A77C8, A63C4, A68D8, A7BE4, A7714, A7730)}, fregs={4: x})
            outs.append([b2f(Ma.m[A7724]), b2f(Ma.m[A7710]), b2f(Mb.m[A7728]), b2f(Mb.m[A7714])])
        raised = any(q > p for p, q in zip(outs[0], outs[1]))
        if l1 < 0 <= l2:
            straddle += 1
            straddle_raise += raised
        else:
            assert not raised, (l1, l2, outs)
            mono += 1
    assert straddle_raise > 0
    # the reviewer's sign-change rows (R = 1, x = 1.0, old [7710] = 1.0, [7730] = 1.5)
    rows = []
    for lo_, hi_ in ((-1.0, 1.0), (-0.5, 0.75), (-1e-30, 0.0)):
        pr = []
        for lv in (lo_, hi_):
            ins = {A77C8: f2b(lv), A63C4: ONE, A68D8: PZERO, A7BE4: PZERO, A7710: ONE, A7730: K15}
            M, _, _ = run(0x0330CA, lambda M: m_0330CA(M, ONE), ins, fregs={4: ONE})
            pr.append((round(b2f(M.m[A7724]), 7), round(b2f(M.m[A7710]), 7)))
        assert pr[1][0] > pr[0][0]
        rows.append((lo_, hi_, pr))
    # shipped ranges with the real tables: default-mode [7710] and BASE [7714]
    hi = set()
    lo = set()
    for k in range(0, 300):
        x = f2b(k * 1.0 - 20.0)
        hi.add(b2f(clamp(fmin(rom_lookup(ROM, D_AC4C0, x), cal(ROM, 0x0CBEDC)), K05, K15)))
        lo.add(b2f(clamp(fmax(rom_lookup(ROM, D_AC4D4, x), cal(ROM, 0x0CBF28)), K05, K15)))
    assert min(hi) == 1.1015625 and max(hi) == 1.25 and min(lo) == 0.75 and max(lo) == 0.953125
    t7730 = []
    for be4 in (0.0, 0.1, 0.296875):
        M, _, _ = run(0x0331C6, m_0331C6, {A6350: f2b(20.0), A7BE4: f2b(be4)})
        t7730.append(b2f(M.m[A7730]))
    # [7730] is not a cap of the default-mode [7710]: MODE 1, [40C8] = 0 -> [7710] = 1.25 > [7730]
    c = case(r)
    c.update({A65F0: 0, A40C8: PZERO, A7BE4: f2b(0.296875), A6350: f2b(20.0), A7448: 1, A98F4: 0, A77B8: 0,
              A7828: 0, A77B6: 0})
    M, ret, _ = run(0x032B10, m_032B10, c)
    assert ret[0] == 1 and b2f(M.m[A7710]) == 1.25 and b2f(M.m[A7730]) < 1.1016
    print(f'I  on the emulator: [77C8] changes a call only when 0x033186 runs (MODE 17/19 or TRACK): {indep} '
          f'pairs identical, {used} with 0x033186 ({dep} differ, only in [7724] [7710] [7728] [7714])')
    print(f'   monotone in [77C8] for R > 0: {mono} non-straddling pairs never raise any of [7724] [7710] [7728] '
          f'[7714]; {straddle_raise} of {straddle} pairs with L1 < 0 <= L2 raise one')
    for lo_, hi_, pr in rows:
        print(f'   sign change [77C8] {lo_} -> {hi_}: ([7724], [7710]) {pr[0]} -> {pr[1]}')
    print(f'   shipped: default-mode [7710] in [{min(hi)}, {max(hi)}]; BASE [7714] in [{min(lo)}, {max(lo)}]; '
          f'[7730] at [7BE4] = 0 / 0.1 / 0.296875: {[round(t, 7) for t in t7730]}')
    print(f'   MODE 1 with [7BE4] = 0.296875: [7710] = {b2f(M.m[A7710])} > [7730] = {b2f(M.m[A7730]):.7f} '
          '(no [7730] cap outside 0x0330CA / 0x033128)')


def passJ(N=600):
    r = random.Random(19)
    for _ in range(N):
        c = {A77B0: r.choice([0, 1, 2, 0xFFFF, 0x8000]), A77B2: r.choice([0, 1, 7]),
             A77B4: r.choice([0, 1, 0x7FFF])}
        run(0x03308E, m_03308E, c)
        c = {A7348: fv(r), A65F6: r.choice([0, 1, 2, 0x81])}
        run(0x032AA8, m_032AA8, c)
        run(0x030378, m_030378, {A63F8: fv(r)})
        c = {a: fv(r) for a in P0301E4_F + [A76D4, A7348]}
        if r.random() < 0.7:
            c[0xFFFF733C] = PZERO
        run(0x0301E4, m_0301E4, c)
    # proportionality of 0x0301E4 outputs to ([76D4] + [7878] + [7AE4]) * [7348]
    c = {a: f2b(1.0) for a in P0301E4_F}
    c.update({0xFFFF733C: PZERO, 0xFFFF7878: PZERO, 0xFFFF7AE4: PZERO, 0xFFFF73A4: PZERO, 0xFFFF7A08: PZERO})
    out = []
    for afc in (0.5, 1.0, 1.5):
        c[A76D4] = f2b(afc)
        c[A7348] = f2b(1000.0)
        M, _, _ = run(0x0301E4, m_0301E4, dict(c))
        out.append(tuple(b2f(M.m[a]) for a in (0xFFFF7344, 0xFFFF7320, 0xFFFF7338)))
    assert out[0][0] == 500.0 and out[1][0] == 1000.0 and out[2][0] == 1500.0
    assert out[0][2] == out[1][2] == out[2][2]          # [7338] does not depend on [76D4]
    m = []
    for x in (0.0, 1.0, 26.0, 26.7, 30.0):
        M, _, _ = run(0x030378, m_030378, {A63F8: f2b(x)})
        m.append(b2f(M.m[A7348]))
    assert m == [0.0, 4916.0, 127816.0, 131072.0, 131072.0]
    print(f'J  0x03308E / 0x032AA8 / 0x030378 / 0x0301E4: {N} cases each bit-exact')
    print(f'   0x0301E4 with [76D4] = 0.5 / 1.0 / 1.5, [7348] = 1000, other factors 1, sums 0: [7344] = '
          f'{[o[0] for o in out]}; [7338] = {[o[2] for o in out]} (independent of [76D4])')
    print(f'   0x030378 [63F8] = 0 / 1 / 26 / 26.7 / 30 -> [7348] = {m}  (x 4916.0 = raw "Injector Flow '
          'Scaling", clamped at 131072)')


def passK():
    rng = [(0x032AA8, 0x033278), (0x0CBBD8, 0x0CBBE2), (0x0CBC2E, 0x0CBC32), (0x0CBED8, 0x0CBF3C),
           (0x0AC4C0, 0x0AC4E8), (0x0ACE34, 0x0ACE54), (0x0CCAB0, 0x0CCB10), (0x0CDEDC, 0x0CDF5C),
           (0x0CC624, 0x0CC664), (0x063A10, 0x063A2C), (0x074A54, 0x074CF0), (0x0278D2, 0x027918),
           (0x0301E4, 0x0303C0), (0x0CBE0C, 0x0CBE10), (0x0F8A84, 0x0F8A85), (0x0BE4FA, 0x0BEC80),
           (0x003170, 0x0031A0), (0x032958, 0x032AA8), (0x0CBECC, 0x0CBED8), (0x063A04, 0x063A30),
           (0x0332A2, 0x033304), (0x033400, 0x033410), (0x04A94C, 0x04AA30), (0x034420, 0x03446C),
           (0x033590, 0x033640), (0x022F92, 0x022FA0)]
    for a, z in rng:
        assert ROM[a:z] == ROM_STOCK[a:z], hex(a)
    print(f'K  stock rom/ae5l600l.bin: all {len(rng)} ranges read here are byte-identical to 20.19c')


def passL():
    want = {0x032B10: 0x032B5A, 0x032B5E: 0x032C72, 0x032E28: 0x03308E, 0x0330CA: 0x033128,
            0x033128: 0x033186, 0x0331C6: 0x033200, 0x032CE8: 0x032D52, 0x032D52: 0x032E28,
            0x0278D2: 0x0278DE, 0x074A54: 0x074A82, 0x03308E: 0x0330CA, 0x032AA8: 0x032B10,
            0x030378: 0x0303A8, 0x0301E4: 0x03033C, 0x03297A: 0x032A5A, 0x032958: 0x03297A}
    pool = set(range(0x032EE2, 0x032F84))       # literal pool inside 0x032E28
    pool |= {0x0329CE, 0x0329D0}                # 0x03297A r5 != 0 arm: r5 = 0 is set in the bra slot 0329AC
    tot = 0
    for s, z in want.items():
        pcs = [p for p in range(s, z, 2) if p not in pool]
        miss = [p for p in pcs if p not in COVER]
        assert not miss, (hex(s), [hex(p) for p in miss])
        tot += len(pcs)
    print(f'L  coverage: all {tot} reachable instructions of the 16 functions executed (0x03297A\'s 0329CE / '
          '0329D0 are unreachable from its only entry)')


def passM():
    """C18: edge rows of 0x0330CA (and the same shape 0x033128) on the emulator."""
    rows = []
    #        [63C4] [68D8]  [7BE4]     x            [7724] expected   note
    spec = [(1.0, 0.0, 0.0, 1.25, 1.5, 'R = 1'),
            (2.0, 0.0, 0.0, 1.0, 1.5, 'R = 1'),
            (-1.0, 0.0, 0.0, 1.0, 1.5, 'R = 1 ([63C4] < 0)'),
            (1.0, -1.0, 0.0, 1.25, 0.5, 'R = 0: clamp(x - 1 - [7BE4])'),
            (1.0, -1.0, 0.0, 2.0, 1.0, 'R = 0: clamp(x - 1 - [7BE4])'),
            (1.0, -1.0, 0.0, 2.75, 1.5, 'R = 0: clamp(x - 1 - [7BE4])'),
            (1.0, -2.0, 0.0, 1.25, 0.5, 'R = -1'),
            (1.0, 0.0, math.inf, 1.25, 0.5, '[7BE4] = +inf'),
            (1.0, 0.0, math.nan, 1.25, 0.5, '[7BE4] = NaN'),
            (1.0, 0.0, 0.0, -math.inf, 0.5, 'x = -inf'),
            (1.0, 0.0, 0.0, math.nan, 0.5, 'x = NaN')]
    for a63, a68, be4, xx, want, note in spec:
        for l8 in (0.0, -0.0):
            ins = {A77C8: f2b(l8), A63C4: f2b(a63), A68D8: f2b(a68), A7BE4: f2b(be4), A7710: ONE, A7730: K15}
            M, _, _ = run(0x0330CA, lambda M: m_0330CA(M, f2b(xx)), ins, fregs={4: f2b(xx)})
            assert b2f(M.m[A7724]) == want, (a63, a68, be4, xx, l8, b2f(M.m[A7724]))
            ins2 = {A77C8: f2b(l8), A63C4: f2b(a63), A68D8: f2b(a68), A7BE4: f2b(be4), A7714: ONE, A7730: K15}
            M2, _, _ = run(0x033128, lambda M: m_033128(M, f2b(xx)), ins2, fregs={4: f2b(xx)})
            assert M2.m[A7728] == M.m[A7724]
        rows.append((a63, a68, be4, xx, want, note))
    # NaN old bound -> min returns [7730] -> clamp([7730], 0.5, 1.5)
    for c30 in (1.3, 0.2, 2.0):
        ins = {A77C8: ONE, A63C4: ONE, A68D8: PZERO, A7BE4: PZERO, A7710: f2b(math.nan), A7730: f2b(c30)}
        M, _, _ = run(0x0330CA, lambda M: m_0330CA(M, ONE), ins, fregs={4: ONE})
        assert M.m[A7710] == clamp(f2b(c30), K05, K15)
    print(f'M  0x0330CA / 0x033128 with [77C8] = +0.0 and -0.0 (1/[77C8] = +FLT_MAX), {len(rows)} rows each:')
    for a63, a68, be4, xx, want, note in rows:
        print(f'   [63C4]={a63:<4} [68D8]={a68:<4} [7BE4]={be4:<4} x={xx:<5} -> [7724] = [7728] = {want}   ({note})')
    print('   NaN old [7710] -> [7710] = clamp([7730], 0.5, 1.5) for [7730] = 1.3 / 0.2 / 2.0')


def chain_emu():
    e = E.Emu(ROM)
    e.stub(FN_CS_IN, r0=0)
    e.stub(FN_CS_OUT)
    return e


def passN():
    """C39: a 1/[77C8]-built [7710] persists into calls with byte [7828] == 0; [7714] does not."""
    res = {}
    for l8 in (0.85, 1.2):
        e = chain_emu()
        st = {A40C8: 48.0, A6350: 20.0, A7BE4: 0.0, A77C8: l8, A63C4: 1.0, A68D8: 0.0, A770C: 1.0,
              A7710: 1.25, A7714: 0.9, A76D4: 1.0, A7BCC: 1.0, A77A8: 1.0, A63F8: 1.0, A7348: 100.0,
              A73B4: 0.0, A73E0: 0.0, A73E4: 0.0, A6354: 20.0, A65FC: 50.0, A6364: 20.0, A6624: 3000.0}
        for a, v in st.items():
            poke(e, a, 4, f2b(v))
        for k in range(21):
            poke(e, ARR[k], 4, f2b(100.0))
        for a, v in {A65F0: 0, A7448: 1, A77B6: 0, A77B8: 0, A6254: 0, A77B7: 0, A77B9: 0, A77BA: 1,
                     A77BB: 0, A6A29: 0x80, AA56A: 0, AACE6: 0}.items():
            poke(e, a, 1, v)
        for a in (A77B0, A77B2, A77B4):
            poke(e, a, 2, 0)
        out = []
        # call 1 MODE 19 (rising edge, [7828] = 1); 2 MODE 5 (falling edge, [7828] = 0); 3 gate fail ([65F0] = 1);
        # 4 MODE 8 (counter); 5 MODE 1 (default, overwrites)
        for cur, f28, gate in ((1, 1, 0), (0, 0, 0), (0, 0, 1), (0, 0, 0), (0, 0, 0)):
            poke(e, A98F4, 1, cur)
            poke(e, A7828, 1, f28)
            poke(e, A65F0, 1, gate)
            e.executed.clear()
            e.writes.clear()
            assert e.call(0x032B10, regs={15: E.STACK_TOP}) == 'return'
            out.append((b2f(peek(e, A7710, 4)), b2f(peek(e, A7714, 4)), peek(e, A77B6, 1),
                        0x033186 in e.executed, 0x033128 in e.executed, bool(e.writes)))
        res[l8] = out
    a, b_ = res[0.85], res[1.2]
    assert a[0][3] and b_[0][3] and not any(x[3] for x in a[1:]) and not any(x[3] for x in b_[1:])
    for k in (0, 1, 2, 3):
        assert a[k][0] != b_[k][0]                       # [7710] still depends on [77C8] after calls 2-4
    assert a[4][0] == b_[4][0]                            # call 5 (MODE 1) overwrites with the table value
    assert a[0][1] != b_[0][1] and a[1][1] == b_[1][1]    # [7714]: TRACK in call 1, rewritten by BASE in call 2
    assert not a[2][5] and not b_[2][5]                   # gate fail: nothing written
    print('N  chained 0x032B10 calls on one RAM image ([7448] = 1; calls: MODE 19 [7828]=1, MODE 5 [7828]=0, '
          'gate fail, MODE 8, MODE 1):')
    for l8, out in res.items():
        print(f'   [77C8]={l8:<5} [7710] = {[round(x[0], 7) for x in out]}  [7714] = {[round(x[1], 7) for x in out]}'
              f'  0x033186 ran {[x[3] for x in out]}')
    print('   -> the MODE 19 [7710] persists through MODE 5, a gate-fail call and MODE 8 with byte [7828] = 0; '
          'MODE 1 overwrites it; [7714] is rewritten by every gated call')


def passO(N=800):
    r = random.Random(20)
    paths = {}
    vals = set()
    for _ in range(N):
        c = {A65F0: r.choice([0, 6, 12, 18, 18, 1, 0x86]), A76D4: fv(r, special=0.1),
             A7448: r.choice([1, 1, 1, 0, 2, 0x81]), A7704: fv(r, special=0.1), A7708: fv(r, special=0.1),
             A770C: fv(r, special=0.1)}
        M, p, _ = run(0x03297A, m_03297A, c)
        paths[p] = paths.get(p, 0) + 1
        if p is not None:
            for a in (A7704, A7708, A770C):
                v = b2f(M.m[a])
                assert 0.5 <= v <= 1.5, (hex(a), v)
                vals.add(M.m[a])
    for v in range(0, 256, 17):
        run(0x032958, m_032958, {A65F6: v})
    run(0x032958, m_032958, {A65F6: 1})
    # with [770C] in [0.5, 1.5]: MODE 3 == MODE 1 and MODE 19 == MODE 17 (same [7710] / [7724])
    same = 0
    for _ in range(N // 2):
        c = case(r)
        c.update({A77B6: 0, A7448: 1, A77B8: 0, A770C: f2b(r.uniform(0.5, 1.5)), A7730: fv(r)})
        if r.random() < 0.2:
            c[A770C] = r.choice([K05, K15, ONE])
        res = {}
        for cur, f28 in ((0, 0), (1, 0), (0, 1), (1, 1)):
            ins = {a: c[a] for a in (A77B6, A7448, A77B8, A770C, A7710, A77C8, A63C4, A68D8, A7BE4, A7730)}
            ins.update({A98F4: cur, A7828: f28, A7720: c[A40C8]})
            M, mode, _ = run(0x032B5E, m_032B5E, ins)
            res[mode] = (M.m.get(A7710), M.m.get(A7724))
        assert res[3] == res[1] and res[19] == res[17], res
        same += 1
    # control: [770C] = -7.0 (no writer stores it) makes MODE 3 differ from MODE 1
    ins = {A77B6: 0, A7448: 1, A77B8: 0, A770C: f2b(-7.0), A7710: ONE, A77C8: ONE, A63C4: ONE, A68D8: PZERO,
           A7BE4: PZERO, A7730: ONE, A7828: 0, A7720: PZERO}
    M3, _, _ = run(0x032B5E, m_032B5E, {**ins, A98F4: 1})
    M1, _, _ = run(0x032B5E, m_032B5E, {**ins, A98F4: 0})
    assert b2f(M3.m[A7710]) == 1.0 and b2f(M1.m[A7710]) == 1.25
    print(f'O  0x03297A: {N} cases bit-exact incl. write / read sets, paths {sorted(paths.items(), key=str)}; every '
          'stored [7704] / [7708] / [770C] in [0.5, 1.5] (NaN / inf inputs included); 0x032958 over [65F6]')
    print(f'   with [770C] in [0.5, 1.5]: MODE 3 stores what MODE 1 stores and MODE 19 what MODE 17 stores '
          f'({same} cases); control [770C] = -7.0 -> MODE 3 [7710] = 1.0 vs MODE 1 1.25')


def passP():
    """C23 / C28 / C29: NaN and edge rows of the gates."""
    rom_34 = mrom({0x0CDF1C + 2 * i: b'\x00\x09' for i in range(16)})
    r = random.Random(21)
    tested = []
    nxt = f2b(2.0 ** -15) + 1
    for b7cc, a8, want in ((math.nan, 1.0, 9), (2.0 ** -15, 1.0, 9), (-(2.0 ** -15), 1.0, 9),
                           (b2f(nxt), 1.0, None), (0.0, math.nan, None), (0.0, 2.0 ** -15, None),
                           (0.0, -1.0, 9)):
        c = case(r)
        ins = {a: c[a] for a in ALL_IN if a not in (A65F0, A40C8, A98F4, A77B6, A77B8, A770C, A7710)}
        ins.update({A7720: c[A40C8], A7730: ONE, A7BCC: f2b(b7cc), A77A8: f2b(a8), A77B4: 0x1234})
        for rom, w in ((rom_34, want), (ROM, None if want is None else 0)):
            M, (path, _, _), e = run(0x032E28, m_032E28, ins, rom=rom, regs={4: TBL})
            loaded = A77B4 in e.writes
            assert loaded == (want is not None), (b7cc, a8)
            if loaded:
                assert M.m[A77B4] == w
                if rom is rom_34:
                    assert path == 'HOLD95'               # NaN [7BCC] also takes HOLD95 (032FD8 same test)
        tested.append((b7cc, a8, want is not None))
    # G1 rows (0x032CE8): sum / [6350] / [73B4]
    g1 = []
    base = {A6350: f2b(20.0), A6354: f2b(20.0), A73B4: PZERO, A73E0: PZERO, A73E4: PZERO, A77B0: 7}
    for k, v, want in ((A73E0, math.nan, 1), (A73E0, -0.0, 1), (A73E0, -1e-30, 0), (A6350, -40.0, 1),
                       (A6350, 119.0, 0), (A6350, math.nan, 0), (A6354, math.nan, 0), (A6354, 118.99, 1)):
        M, g, _ = run(0x032CE8, m_032CE8, {**base, k: f2b(v)})
        assert g == want, (hex(k), v, g)
        g1.append((f'{k & 0xFFFF:04X}', v, g))
    for v, rel in ((b2f(cal(ROM, 0x0CBEF8)), True), (b2f(cal(ROM, 0x0CBEFC)), True), (math.nan, True),
                   (0.0, False)):
        M, _, e = run(0x032CE8, m_032CE8, {**base, A73B4: f2b(v)})
        assert (A77B0 in e.writes) == rel and (not rel or M.m[A77B0] == 1250)
    # G2 rows (0x032D52): every gate passing, then NaN in each float gate
    base2 = {A65FC: PZERO, A6364: f2b(119.0), A6624: f2b(11500.0), A6A29: 0x80, AA56A: 0, AACE6: 0,
             A76D4: PZERO, A77B9: 0, A77BA: 0, A77BB: 1, A77B2: 5, A7828: 0}
    g2 = []
    for k, v, want in ((None, None, 1), (A65FC, math.nan, 1), (A6364, math.nan, 1), (A76D4, math.nan, 1),
                       (A65FC, 1e-30, 0), (A6364, 118.99, 0), (A76D4, 1e-30, 0), (A7828, 0x80, 0),
                       (A7828, 1, 0), (A77B2, 0, 0)):
        ins = dict(base2)
        if k is not None:
            ins[k] = f2b(v) if k in F32 else v
        M, g, _ = run(0x032D52, m_032D52, ins)
        assert g == want, (k, v, g)
        g2.append(('all pass' if k is None else f'{k & 0xFFFF:04X}', v, g))
    print('P  [77B4] load (rows [7BCC], [77A8], loaded?):', tested)
    print('   G1 rows (cell, value, G1):', g1, '; [73B4] = -0.1 / 0.05 cal words and NaN reload 1250, 0.0 does not')
    print('   G2 rows (cell, value, G2):', g2)


def passQ():
    w = lambda a: cal(ROM, a)  # noqa: E731
    # the find_writers hit "03445A mov.b r0,@(8,gbr)" is the low half of the pool long at 0x034458
    assert ROM[0x034420:0x034424] == bytes.fromhex('000B4F17')          # 0x0343CE: rts / ldc.l @r15+,gbr
    assert [w(0x034424 + 4 * i) for i in range(18)][:3] == [0x000CBFF4, 0x000CBFF8, 0x000BE970]
    assert w(0x034458) == 0x000CC008 and struct.unpack_from('>H', ROM, 0x03445A)[0] == 0xC008
    # the three real store sites of byte [7828] (GBR 0xFFFF77BC + 108) in 0x033460
    for a in (0x03359A, 0x033616, 0x033638):
        assert struct.unpack_from('>H', ROM, a)[0] == 0xC06C
    # tables
    t = [w(0x063A04 + 4 * i) for i in range(11)]
    assert t == [0xFFFF7704, 0xFFFF7708, 0xFFFF770C, 0xFFFF7714, 0xFFFF7718, 0xFFFF771C, 0xFFFF7734,
                 0xFFFF77A8, 0xFFFF77B4, 0xFFFF77B7, 0xFFFF77C8]
    assert w(0x032A78) == 0x00063A04 and w(0x032CAC) == 0x00063A10 and w(0x033424) == 0x00063A2C
    cnt = {v: 0 for v in (0x00063A04, 0x00063A10, 0x00063A2C, 0xFFFF770C)}
    for i in range(0, len(ROM) - 3, 2):
        v = w(i)
        if v in cnt:
            cnt[v] += 1
    assert cnt == {0x00063A04: 1, 0x00063A10: 1, 0x00063A2C: 1, 0xFFFF770C: 3}, cnt
    # 0x04A94C call order: 0x033304, 0x032B10, 0x031D1E, 0x03297A (pool longs of the jsr sites 04A98C..04A99E)
    assert [w(a) for a in (0x04AA18, 0x04AA1C, 0x04AA20, 0x04AA24)] == [0x033304, 0x032B10, 0x031D1E, 0x03297A]
    # 0x0332A2 ([65F6] == 1): writes [77C8] = 1.0, never byte [7828]
    for v in (1, 0, 2):
        e = E.Emu(ROM)
        poke(e, A65F6, 1, v)
        poke(e, A7828, 1, 0x5A)
        poke(e, A77C8, 4, f2b(0.85))
        e.call(0x0332A2)
        if v == 1:
            assert peek(e, A77C8, 4) == ONE and all((A77C8 + i) in e.writes for i in range(4))
        else:
            assert not e.writes
        assert A7828 not in e.writes and peek(e, A7828, 1) == 0x5A
    print('Q  03445A is the low half of pool long 0x000CC008 (0x0343CE ends at 034422); byte [7828] store sites '
          '03359A / 033616 / 033638 (C06C); tables 0x063A04 (3 slots) | 0x063A10 (7 slots) | 0x063A2C begins '
          '0xFFFF77C8; 0x04A94C calls 0x033304, 0x032B10, 0x031D1E, 0x03297A in that order; 0x0332A2 writes '
          '[77C8] = 1.0 only when [65F6] == 1 and never byte [7828]')


def main():
    passA()
    passB()
    passC()
    passD()
    passE()
    passF()
    passG()
    passH()
    passI()
    passJ()
    passK()
    passM()
    passN()
    passO()
    passP()
    passQ()
    passL()
    print('ALL PASSES OK')
    return 0


if __name__ == '__main__':
    sys.exit(main())
