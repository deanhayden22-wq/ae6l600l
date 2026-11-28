#!/usr/bin/env python3
"""Emulation check for disassembly/analysis/injector_path_trace.txt:
from 0x0301E4's outputs [0xFFFF7320]..[0xFFFF7344] to the injector pulse register.

    python3 scripts/trace/emu_injector_path.py

Reference bin: rom/AE5L600L 20g rev 20.19c.bin  md5 92cae8275cd4f9b473a3a9e36efe6449
(stock rom/ae5l600l.bin and rom/AE5L600L 20g rev 20.19e.bin compared in pass Q).

Every function is run in scripts/sh2e_emu.py against a Python model written from its bytes.
Per case the script asserts every model output cell bit for bit and, where stated, the exact set
of non-stack RAM bytes written.  Callees from the verified runtime library (0x0BE830 / 0x0BE8E4 /
0x0BE944 lookups, 0x0BEA40 lag, 0x0BE654 divide) run for real inside the emulator; the model
obtains their values by running them on their own (their CONTRACTs are verified).  Critical-
section helpers (0x00317C / 0x003190 / 0x0BE81C / 0x0BE82C) are stubbed: the emulator raises on
ldc sr.  On-chip peripheral addresses (0xFFFFF000..) are served by an MMIO map and every write
there is captured (class PEmu).

Passes
  A  0x02EFD2 (237)  per-cylinder copy / decaying floor -> [7290+4j]
  B  0x038DC0 (40)   four 2-D lookups on ([7324], [6624]) -> [7B6C] [7B70] [7B74] [7B78];
                     axis assignment cross-checked against an independent bilinear interpolation
  C  0x0397AC (37)   [7BC4] = clamp(T(AC760, [7344]), 0.5, 1.5) under two gates, else 1.0
  D  0x037D74 (47)   [7ABC] from AD71C (all zero) under four byte gates; positive control on a
                     modified in-memory ROM copy; the S4 tail of 0x037B74 (excerpt 037BD6..037C40)
  E  0x04BDAA (137)  flags [8374] [8375] [8368] [8369] from [7D94] x [6624]; the [7328] load is dead
  F  0x03D0B8 (104)  [7324]/[7338] - [7878] - [7AE4] -> [7D58], three lags -> [7D5C] [7D60] [7D64]
  G  0x03D582 (89)   record rec+24 = trunc([7290+4ch] * [7DA4] / 0.25)  (mode 1) or from 0x02F9E0
  H  0x03D648 (34)   [7D94+4j] = 0.25 * rec_j+20 ; [7D84+4j] = that + [734C]  (0 if rec+1 != 0)
  I  0x03D68C (6)    [7DA4] = 1.0
  J  0x0303C0 (36)   u16 [7350] = Injector Latency(AD7E0) at ([4130], [6210]); [4280] = it; [734C] = it/4
  K  0x05D478 (11)   SSM index-32 getter: byte = clamp(trunc([7D84]/256 + 0.5), 0, 255)
  L  0x03D4F6 (12) + 0x02F8EA (5): mode 0 if byte [726C] == 1, else 2 -> table 0x063DFC -> rec+0
  M  0x00A4E0 (40) + 0x011848 (22): u16 [0xFFFFF640 + 2k] = min(w, 0xFFFF) (written twice);
                     [4294 + 28k] = w - 0xFFFF when w > 0xFFFF else 0
  N  0x009F72 (238)  arming: compare [0xFFFFF444 + 2k]; width (rec+0 + [4280]) >> 4 (status clear)
  O  0x009B2C (104)  driver record rec+0 = P, +4 start angle, +8 span; arms through 0x009F72 when < 35
  P  0x03DFC8 (121)  handler: rec+24 -> rec+20 -> 0x009B2C / 0x009C38 (callees stubbed, arguments compared)
  N2 0x009F72 targeted: compare-move boundary (diff 0x7FFF / 0x8000) and wrap ([F440] = 0xFFFE); the status-set
                     branch writes the compare register once ([F440] - 1); the offset cap tests the LOW 16 bits;
                     a negative (P + L) gives register 0xFFFF and overflow 0xFFFF0000
  R  end to end, every function REAL: 0x0301E4 -> 0x02EFD2 (COPY) -> 0x03D68C -> 0x03D582 -> 0x03DFC8 (idle
                     sub-record) -> 0x009B2C -> 0x009F72 (status clear) -> 0x00A4E0 -> 0x011848, S4 != 1 included;
                     PW edges at the 0xFFFF register limit and the 262136 clamp ceiling (overflow 167 / 785)
  S  the scheduler's record state: S1 0x03DB16 (every record gets 0x03D582 + handler B, suppressed or not);
                     S2 0x03DE6E and S3 0x03DD8E (a changed [7D80] bit / MODE is applied at once, under
                     conditions); S4 0x03D856 per-record loop with its callees as logged no-ops (re-arm, skips,
                     refresh calls); S5 0x03E0FA reads long [0x0CBDB4], never [42F4]
  T  0x037E70 ([7AC0]: the steps 0x0CC32C / 0x0CC330 are 0.0, so it holds); 0x037B74 run whole: [7AC4], [7AC8],
                     [7ABC] are 0.0 and S4 = 1.0 unless [7AC0] holds +inf
  U  initialisers: 0x02F83E (latch [72D1] := 0, [726C] := 1, flags := 1) and 0x009860 (width registers, [4280],
                     [42F4] := 0)
  V  independent audit, inputs no earlier pass used: V1 0x02EFD2 FLOOR path floors RELEASED channels too while any
                     flag is 1; V2 0x02EF0C (task-9 runner 0x04907C at 0491B0) calls 0x02F83E only for byte [65F6] == 1;
                     V3 0x0345A4 second body: byte [7883] needs [7324] > [733C] (strict); V4 0x03CD00 initialises
                     [7D58..7D64] = 1.0; V5 two passes in 0x04AA58 order, 0x038DC0 / 0x0397AC / 0x0301E4 real, F != 1
                     and the [733C] clamp through to the register; V6 0x02FF8E: [733C] = 0.0 iff byte [641C] == 1 else 300.0
  Q  bins: every code byte of these functions and every calibration byte they read is compared in
     stock / 20.19c / 20.19e; instruction coverage per entry

ROUNDING: models compute each fadd/fsub/fmul/fdiv exactly and round TOWARD ZERO, fmac FUSED, as the
emulator does (corrections items 106 / 110).  No statement in the trace rests on the last bit.
Names are neutral: nothing here establishes what a RAM cell physically is.
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
import desc_types as T        # noqa: E402

BIN = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
ROM = open(BIN, 'rb').read()
assert hashlib.md5(ROM).hexdigest() == '92cae8275cd4f9b473a3a9e36efe6449', 'wrong reference bin'
ROM_STOCK = open(os.path.join(REPO, 'rom', 'ae5l600l.bin'), 'rb').read()
ROM_E = open(os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19e.bin'), 'rb').read()
f2b, b2f = E.f2b, E.b2f
M32 = 0xFFFFFFFF
random.seed(20261127)
CHECKS = [0]
COVER = {}


def ok(cond, msg):
    CHECKS[0] += 1
    if not cond:
        raise AssertionError(msg)


# ------------------------------------------------------------------ emulator with MMIO capture
class PEmu(E.Emu):
    def __init__(self, rom=ROM):
        super().__init__(rom)
        self.mmio_writes = []

    def write(self, a, n, v):
        a &= M32
        if 0xFFFFE000 <= a <= 0xFFFFFFFF:
            self.mmio_writes.append((a, n, v & ((1 << (8 * n)) - 1)))
            self.mmios[a] = v
            return
        super().write(a, n, v)


def cover(e, name):
    COVER.setdefault(name, set()).update(e.executed)


# ------------------------------------------------------------------ float model primitives
def arith(op, xb, yb):
    x, y = b2f(xb), b2f(yb)
    fn = {'+': lambda p, q: p + q, '-': lambda p, q: p - q,
          '*': lambda p, q: p * q, '/': lambda p, q: p / q}[op]
    if not (math.isfinite(x) and math.isfinite(y)):
        if op == '/' and y == 0.0:
            return f2b(math.copysign(math.inf, x) if x == x else math.nan)
        return f2b(fn(x, y))
    if op == '/' and y == 0.0:
        raise AssertionError('model divide by zero')
    q = fn(Fraction(x), Fraction(y))
    return f2b(fn(x, y)) if q == 0 else E.rz_bits(q)


def fadd(p, q): return arith('+', p, q)
def fsub(p, q): return arith('-', p, q)
def fmul(p, q): return arith('*', p, q)
def fdiv(p, q): return arith('/', p, q)


def fmac(p, q, r):                  # p*q + r, fused
    x, y, z = b2f(p), b2f(q), b2f(r)
    if not (math.isfinite(x) and math.isfinite(y) and math.isfinite(z)):
        return f2b(x * y + z)
    v = Fraction(x) * Fraction(y) + Fraction(z)
    return f2b(x * y + z) if v == 0 else E.rz_bits(v)


def ffloat(i):                      # float fpul (signed 32)
    i = i - (1 << 32) if i & 0x80000000 else i
    return E.rz_bits(Fraction(i)) if i else 0


def ftrc(xb):
    x = b2f(xb)
    if x != x:
        return 0x80000000
    if x >= 2 ** 31:
        return 0x7FFFFFFF
    if x < -2 ** 31:
        return 0x80000000
    return int(x) & M32


def gt(p, q):                       # fcmp/gt q,p : T = (p > q)
    return b2f(p) > b2f(q)


def clamp(x, lo, hi):               # 0x0BE56C (verified): low test first
    if not gt(x, lo):
        return lo
    if gt(hi, x):
        return x
    return hi


def fmax(p, q):                     # 0x0BE960 (verified): fr5 when fr4 is not greater
    return p if gt(p, q) else q


def outside(x, c, wd):              # 0x0BE608 (verified): 1 = outside [c-w, c+w]
    if gt(fsub(c, wd), x):
        return 1
    if gt(x, fadd(c, wd)):
        return 1
    return 0


def sx8(v): return v - 256 if v & 0x80 else v
def sx16(v): return v - 65536 if v & 0x8000 else v


def u32(rom, a): return struct.unpack_from('>I', rom, a)[0]
def u16(rom, a): return struct.unpack_from('>H', rom, a)[0]


ONE, ZERO, TWO = f2b(1.0), 0, f2b(2.0)
K05, K15, K025 = f2b(0.5), f2b(1.5), f2b(0.25)


# ------------------------------------------------------------------ verified library, run on its own
_cache = {}


def lut1(d, xb, rom=ROM):
    k = ('1', id(rom), d, xb)
    if k not in _cache:
        e = E.Emu(rom)
        e.call(0x0BE830, regs={4: d}, fregs={4: b2f(xb)})
        _cache[k] = e.FR[0]
    return _cache[k]


def lut2(d, xb, yb, rom=ROM):
    k = ('2', id(rom), d, xb, yb)
    if k not in _cache:
        e = E.Emu(rom)
        e.call(0x0BE8E4, regs={4: d}, fregs={4: b2f(xb), 5: b2f(yb)})
        _cache[k] = e.FR[0]
    return _cache[k]


def lut2u16(d, xb, yb, rom=ROM):
    k = ('2u', id(rom), d, xb, yb)
    if k not in _cache:
        e = E.Emu(rom)
        e.call(0x0BE944, regs={4: d}, fregs={4: b2f(xb), 5: b2f(yb)})
        _cache[k] = e.R[0] & 0xFFFF
    return _cache[k]


def lag(new, old, kk, eps):
    e = E.Emu(ROM)
    e.FR[4], e.FR[5], e.FR[6], e.FR[7] = new, old, kk, eps
    e.call(0x0BEA40)
    return e.FR[0]


def q16div(a, b):
    e = E.Emu(ROM)
    e.call(0x0BE654, regs={4: a, 5: b})
    return e.R[0]


def interp(axis, x):                # independent: clamp at both ends, linear between
    if x <= axis[0]:
        return 0, 0.0
    if x >= axis[-1]:
        return len(axis) - 2, 1.0
    for i in range(len(axis) - 1):
        if axis[i] <= x <= axis[i + 1]:
            return i, (x - axis[i]) / (axis[i + 1] - axis[i])


def bilinear(rom, d, x, y):
    t = T.read_table(rom, d)
    ax = t['axes']
    # record +4 axis pointer and +8 axis pointer
    pa, pb = u32(rom, d + 4), u32(rom, d + 8)
    na, nb = u16(rom, d), u16(rom, d + 2)
    A = [struct.unpack_from('>f', rom, pa + 4 * i)[0] for i in range(na)]
    B = [struct.unpack_from('>f', rom, pb + 4 * i)[0] for i in range(nb)]
    vals = t['values']             # rows indexed by the +8 axis (desc_types layout), columns by +4
    if len(vals) != nb:
        vals = [list(r) for r in zip(*vals)]
    i, fa = interp(A, x)
    j, fb = interp(B, y)
    v00, v01 = vals[j][i], vals[j][i + 1]
    v10, v11 = vals[j + 1][i], vals[j + 1][i + 1]
    return (v00 * (1 - fa) + v01 * fa) * (1 - fb) + (v10 * (1 - fa) + v11 * fa) * fb, ax


# ------------------------------------------------------------------ RAM addresses
def F(n): return 0xFFFF0000 | n


A7290 = [F(0x7290 + 4 * j) for j in range(4)]
A7328 = [F(0x7328 + 4 * j) for j in range(4)]
A726F = [F(0x726F + j) for j in range(4)]
A728C, A7274, A72DC, A6354 = F(0x728C), F(0x7274), F(0x72DC), F(0x6354)
A726C, A72D1, A7306, A3158, A90C1 = F(0x726C), F(0x72D1), F(0x7306), F(0x3158), F(0x90C1)
A6624, A7324, A7B6C = F(0x6624), F(0x7324), [F(0x7B6C + 4 * j) for j in range(4)]
A7344, A7BC4, A7BC8 = F(0x7344), F(0x7BC4), F(0x7BC8)
A7320, A7ACC, A7ABC, A7AB8 = F(0x7320), F(0x7ACC), F(0x7ABC), F(0x7AB8)
A7AD0, A7AD2, A7ADD, A7ADE = F(0x7AD0), F(0x7AD2), F(0x7ADD), F(0x7ADE)
A7A14, A7D94, A4130, A6210 = F(0x7A14), F(0x7D94), F(0x4130), F(0x6210)
A7328_ = F(0x7328)
A8358, A835C, A8360, A8374, A8375, A8368, A8369 = (F(0x8358), F(0x835C), F(0x8360), F(0x8374),
                                                     F(0x8375), F(0x8368), F(0x8369))
A7AE4, A7338, A7878, A7448 = F(0x7AE4), F(0x7338), F(0x7878), F(0x7448)
A7D58 = [F(0x7D58 + 4 * j) for j in range(4)]
A7DA4, REC0 = F(0x7DA4), F(0x7DA8)
A7D84 = [F(0x7D84 + 4 * j) for j in range(4)]
A7D94_ = [F(0x7D94 + 4 * j) for j in range(4)]
A734C, A7350, A4280, A42F4 = F(0x734C), F(0x7350), F(0x4280), F(0x42F4)
A4284, A4294 = F(0x4284), F(0x4294)
A4154, A416C, A4158, A4168 = F(0x4154), F(0x416C), F(0x4158), F(0x4168)
A7E50, A7E54, A429B = F(0x7E50), F(0x7E54), F(0x429B)
P_F440, P_F666, P_F66A, P_F66C = 0xFFFFF440, 0xFFFFF666, 0xFFFFF66A, 0xFFFFF66C
P_CMP = [0xFFFFF444 + 2 * k for k in range(4)]
P_WID = [0xFFFFF640 + 2 * k for k in range(4)]
FV = [0.0, -0.0, 1.0, 299.0, 300.0, 312.5, 450.0, 600.0, 999.9, 1000.0, 3000.0, 8000.0, 16000.0,
      20000.0, 262136.0, -5.0, math.inf, math.nan]


def rec(j): return REC0 + 40 * j


def nonstack(e):
    return {a for a in e.writes if not (0xFFFFBC00 <= a <= 0xFFFFBFFF)}


def cells(*specs):
    out = set()
    for a, n in specs:
        out.update(range(a, a + n))
    return out


# ================================================================== A  0x02EFD2
D_DECAY = {(0, 0, 1): 0x0AC840, (0, 0, 0): 0x0AC890, (0, 1, 1): 0x0AC854, (0, 1, 0): 0x0AC8A4,
           (1, 0, 1): 0x0AC818, (1, 0, 0): 0x0AC868, (1, 1, 1): 0x0AC82C, (1, 1, 0): 0x0AC87C}


def m_02EFD2(S):
    """S: dict address -> value (bytes as int 0..255, floats as bits). Returns (out dict, writes)."""
    o = {}
    W = set()

    def wb(a, v):
        o[a] = v & 0xFF
        W.add(a)

    def wf(a, v):
        o[a] = v
        W.update(range(a, a + 4))

    def g(a):
        return o[a] if a in o else S[a]
    if sx8(S[A7306]) == 1:
        wb(A72D1, 1)
    if S[A726C] != 0:
        wf(A728C, S[A72DC])
        for j in range(4):
            wf(A7290[j], g(A728C))
            wb(A726F[j], 1)
        return o, W
    if any(sx8(S[A726F[j]]) == 1 for j in range(4)):
        r5 = 1 if S[A90C1] != 0 else 0
        r6 = 1 if S[A3158] != 0 else 0
        d = D_DECAY[(r5, r6, 1 if g(A72D1) == 1 else 0)]
        wf(A7274, lut1(d, S[A6354]))
        wf(A728C, fmax(fmul(S[A728C], g(A7274)), ZERO))
        for j in range(4):
            p = S[A7328[j]]
            if gt(p, g(A728C)):
                wb(A726F[j], 0)
                wf(A7290[j], p)
            else:
                wf(A7290[j], g(A728C))
        return o, W
    for j in range(4):
        wf(A7290[j], S[A7328[j]])
    return o, W


def pass_A():
    n = 0
    path = {'reset': 0, 'floor': 0, 'copy': 0}
    flagsets = [(0, 0, 0, 0), (1, 0, 0, 0), (0, 0, 0, 1), (1, 1, 1, 1), (2, 0, 0, 0), (0xFF, 0, 0, 0)]
    for b726C in (0, 1, 2, 0xFF):
        for fl in flagsets:
            for b7306 in (0, 1, 2):
                for b90C1, b3158 in ((0, 0), (0, 1), (1, 0), (1, 1)):
                    for b72D1 in (0, 1, 2):
                        for _ in range(3):
                            S = {A726C: b726C, A7306: b7306, A90C1: b90C1, A3158: b3158, A72D1: b72D1}
                            for j in range(4):
                                S[A726F[j]] = fl[j]
                                S[A7328[j]] = f2b(random.choice(FV[:15] + [random.uniform(0, 20000)]))
                            S[A6354] = f2b(random.choice([-40.0, -25.0, 0.0, 5.0, 37.5, 90.0, 120.0]))
                            S[A728C] = f2b(random.choice([0.0, 500.0, 3000.0, 12000.0, -10.0]))
                            S[A72DC] = f2b(random.choice([0.0, 4000.0, 8000.0]))
                            e = PEmu()
                            for a, v in S.items():
                                if a in (A726C, A7306, A90C1, A3158, A72D1) or a in A726F:
                                    e.ram_u8(a, v)
                                else:
                                    e.ram_u32(a, v)
                            e.call(0x02EFD2)
                            cover(e, '0x02EFD2')
                            o, W = m_02EFD2(S)
                            for a, v in o.items():
                                got = e.read_u8(a) if (a in A726F or a == A72D1) else e.read_u32(a)
                                ok(got == v, f'02EFD2 {a:08X}: emu {got:#x} model {v:#x} case {S}')
                            ok(nonstack(e) == W, f'02EFD2 write set {sorted(nonstack(e) ^ W)}')
                            ok(not e.uninit_reads, f'02EFD2 uninit {e.uninit_reads}')
                            path['reset' if b726C else ('floor' if any(sx8(x) == 1 for x in fl) else 'copy')] += 1
                            n += 1
    # the shipped decay tables (factor per call, by [6354])
    print(f'A  0x02EFD2: {n} cases (paths {path}); write set exact; no uninitialised reads')
    for k, d in sorted(D_DECAY.items()):
        v = [round(b2f(lut1(d, f2b(x))), 6) for x in (-40.0, 0.0, 20.0, 40.0, 90.0)]
        print(f'     decay table {d:#08x} (byte[90C1]!=0, byte[3158]!=0, [72D1]==1) = {k}: '
              f'factor at -40/0/20/40/90 = {v}')
    # latch: [72D1] is never cleared by 0x02EFD2
    e = PEmu()
    for a in (A726C, A7306, A90C1, A3158):
        e.ram_u8(a, 0)
    e.ram_u8(A72D1, 1)
    for j in range(4):
        e.ram_u8(A726F[j], 0)
        e.ram_u32(A7328[j], f2b(1000.0))
    e.ram_u32(A6354, f2b(90.0)); e.ram_u32(A728C, 0); e.ram_u32(A72DC, 0)
    e.call(0x02EFD2)
    ok(e.read_u8(A72D1) == 1, '72D1 latch')
    print('     byte [72D1]: set to 1 when byte [7306] == 1, never cleared by 0x02EFD2 (latch)')


# ================================================================== B  0x038DC0
D_PIPWC = [0x0AD738, 0x0AD754, 0x0AD770, 0x0AD78C]


def pass_B():
    n = 0
    xs = [0.0, 999.0, 1000.0, 1250.0, 2000.0, 2500.0, 7777.0, 16000.0, 17000.0, -1.0, math.nan]
    ys = [0.0, 700.0, 750.0, 1200.0, 2600.0, 3000.0, 6000.0, 7000.0, math.nan]
    for x in xs:
        for y in ys:
            e = PEmu()
            e.ram_f32(A7324, x); e.ram_f32(A6624, y)
            e.call(0x038DC0)
            cover(e, '0x038DC0')
            for j in range(4):
                want = lut2(D_PIPWC[j], f2b(x), f2b(y))
                ok(e.read_u32(A7B6C[j]) == want, f'038DC0 [{A7B6C[j]:08X}] x={x} y={y}')
                if x == x and y == y:
                    bl, _ = bilinear(ROM, D_PIPWC[j], x, y)
                    ok(abs(b2f(want) - bl) < 1e-5, f'038DC0 axis assignment {j} x={x} y={y}: {b2f(want)} vs {bl}')
            ok(nonstack(e) == cells(*[(a, 4) for a in A7B6C]), '038DC0 write set')
            ok(not e.uninit_reads, '038DC0 uninit')
            n += 1
    print(f'B  0x038DC0: {n} cases; [7B6C+4j] = 0x0BE8E4(D_j, fr4=[7324] on the +4 axis 1000..16000, '
          f'fr5=[6624] on the +8 axis 700..6000); matches an independent bilinear model')
    for j, d in enumerate(D_PIPWC):
        t = T.read_table(ROM, d)
        flat = [v for r in t['values'] for v in r]
        print(f'     {d:#08x} -> [{A7B6C[j]:08X}]: factor range {min(flat):.7g} .. {max(flat):.7g}')


# ================================================================== C  0x0397AC
def pass_C():
    n = 0
    c1, c2 = u32(ROM, 0x0CC3FC), u32(ROM, 0x0CC400)
    for rpm in (0.0, 3999.0, 4000.0, 4000.5, 6000.0, math.nan):
        for x in (0.0, 250.0, 300.0, 325.0, 450.0, 599.0, 600.0, 601.0, 700.0, -3.0, math.nan):
            for old in (0.0, 1.0):
                e = PEmu()
                e.ram_f32(A6624, rpm); e.ram_f32(A7344, x); e.ram_f32(A7BC8, old); e.ram_f32(A7BC4, 7.0)
                e.call(0x0397AC)
                cover(e, '0x0397AC')
                if gt(c1, f2b(rpm)) and gt(c2, f2b(x)):
                    v = lut1(0x0AC760, f2b(x))
                    ok(e.read_u32(A7BC8) == v, '0397AC 7BC8')
                    ok(e.read_u32(A7BC4) == clamp(v, K05, K15), '0397AC 7BC4')
                    ok(nonstack(e) == cells((A7BC4, 8)), '0397AC write set gated')
                else:
                    ok(e.read_u32(A7BC4) == ONE, '0397AC else 1.0')
                    ok(nonstack(e) == cells((A7BC4, 4)), '0397AC write set else')
                n += 1
    print(f'C  0x0397AC: {n} cases; gates [0x0CC3FC]={b2f(c1)} > [6624] and [0x0CC400]={b2f(c2)} > [7344] '
          f'(both strict, NaN fails)')
    print('     T(AC760) at 0 / 300 / 350 / 400 / 450 / 500 / 550 / 599 =', [round(b2f(lut1(0x0AC760, f2b(x))), 7) for x in
                                         (0.0, 300.0, 350.0, 400.0, 450.0, 500.0, 550.0, 599.0)])


# ================================================================== D  0x037D74 (+ 0x037B74 tail)
def run_037D74(rom, b, f7320, f7AB8):
    e = PEmu(rom)
    e.ram_u8(A7AD0, b[0]); e.ram_u8(A7AD2, b[1]); e.ram_u8(A7ADD, b[2]); e.ram_u8(A7ADE, b[3])
    e.ram_f32(A7320, f7320); e.ram_f32(A7AB8, f7AB8); e.ram_f32(A7ABC, 9.0); e.ram_f32(A7ACC, 9.0)
    e.call(0x037D74)
    return e


def pass_D():
    n = 0
    mod = bytearray(ROM)
    for i in range(32):                 # positive control: AD71C data 0x0D0740 made non-zero
        mod[0x0D0740 + i] = (0x80 + 7 * i) & 0xFF
    mod = bytes(mod)
    for b in [(0, 0, 2, 2), (0, 0, 1, 2), (0, 0, 2, 1), (1, 0, 2, 2), (0, 1, 2, 2), (0, 0, 255, 255),
              (0, 0, 0x80, 2), (0xFF, 0, 2, 2), (0, 0, 3, 7)]:
        for x in (0.0, 1.5, 7.0, 15.0, 3000.0):
            for y in (0.0, 0.5, 1.0):
                gate = b[0] == 0 and b[1] == 0 and b[2] >= 2 and b[3] >= 2
                for rom in (ROM, mod):
                    e = run_037D74(rom, b, x, y)
                    if rom is ROM:
                        cover(e, '0x037D74')
                    if gate:
                        ok(e.read_u32(A7ACC) == f2b(x), '037D74 7ACC')
                        ok(e.read_u32(A7ABC) == lut2(0x0AD71C, f2b(x), f2b(y), rom), '037D74 7ABC')
                        ok(nonstack(e) == cells((A7ACC, 4), (A7ABC, 4)), '037D74 ws')
                    else:
                        ok(e.read_u32(A7ABC) == 0, '037D74 else 0')
                        ok(nonstack(e) == cells((A7ABC, 4)), '037D74 ws else')
                    if rom is ROM:
                        ok(e.read_u32(A7ABC) in (0, 0x80000000), 'shipped AD71C gives 0')
                    n += 1
    e1 = run_037D74(mod, (0, 0, 2, 2), 3.0, 0.0)
    e2 = run_037D74(mod, (0, 0, 2, 2), 9.0, 1.0)
    ok(e1.read_u32(A7ABC) != e2.read_u32(A7ABC), 'positive control moves')
    print(f'D  0x037D74: {n} cases; [7ABC] = T2(AD71C, [7320], [7AB8]) when bytes [7AD0]==0, [7AD2]==0, '
          f'[7ADD]>=2, [7ADE]>=2 (unsigned), else 0.0; shipped AD71C -> 0.0 always; control on a modified copy moves it')
    # 0x037B74 excerpt: S4 = [7AB4]
    A7AB4, A7AC0, A7AC4, A7AC8, A7AD4 = F(0x7AB4), F(0x7AC0), F(0x7AC4), F(0x7AC8), F(0x7AD4)
    cc = u32(ROM, 0x0CC2F0)
    m = 0
    for st in [(0, 0, 0), (2, 0, 0), (0, 2, 0), (0, 0, 2), (1, 1, 1)]:
        for b0, b2 in ((0, 0), (1, 0), (0, 1)):
            for rpm in (0.0, b2f(cc) - 1.0, b2f(cc), 7000.0):
                for p in [(0.0, 1.0, 1.0, 1.0), (0.5, 0.2, 1.0, 1.0), (0.0, math.inf, 1.0, 1.0),
                          (2.0, 2.0, 2.0, 2.0), (-3.0, 1.0, 1.0, 1.0)]:
                    e = PEmu()
                    e.gbr = 0xFFFF7AB4
                    e.ram_u8(A7AD0, b0); e.ram_u8(A7AD2, b2)
                    e.ram_f32(A7AD4, rpm)
                    for a, v in zip((F(0x7ABC), A7AC0, A7AC4, A7AC8), p):
                        e.ram_f32(a, v)
                    e.ram_f32(A7AB4, 9.0)
                    for k, v in enumerate(st):
                        e.ram_u8(E.STACK_TOP + 4 * k, v)
                    e.call(0x037BD6, regs={13: 0xFFFF7AD8}, stop_at={0x037C48})
                    skip = (2 in st) or b0 == 1 or not gt(cc, f2b(rpm)) or b2 == 1
                    if skip:
                        want = ONE
                    else:
                        fr0 = fmul(fmul(f2b(p[0]), f2b(p[1])), f2b(p[2]))
                        want = clamp(fmac(fr0, f2b(p[3]), ONE), K05, K15)
                    ok(e.read_u32(A7AB4) == want, f'037B74 S4 {st} {b0} {b2} {rpm} {p}')
                    m += 1
    print(f'     0x037B74 excerpt 037BD6..037C46: {m} cases; [7AB4] = clamp(1 + [7ABC]*[7AC0]*[7AC4]*[7AC8], 0.5, 1.5)'
          f' unless a 2-flag / byte [7AD0]==1 / !([0x0CC2F0]={b2f(cc)} > [7AD4]) / byte [7AD2]==1, then 1.0;'
          f' [7ABC] = 0 gives 1.0 (with [7AC0] = inf the product is NaN -> 0.5)')


# ================================================================== E  0x04BDAA
def m_04BDAA(S, rom=ROM):
    o = {}
    c = lambda a: u32(rom, a)  # noqa: E731
    if outside(S[A7A14], ZERO, f2b(2.0 ** -10)) == 0:
        o[A8358] = ZERO
    else:
        o[A8358] = c(0x0D6024)
    fr15 = fmul(fmul(fmul(S[A7D94], c(0x0D6028)), S[A6624]), u32(rom, 0x04BF64))
    o[A835C] = fr15
    r = lag(fr15, S[A8360], c(0x0D602C), f2b(0.01))
    o[A8360] = fadd(r, o[A8358])
    fr14 = o[A8360]
    b74, b75 = S[A8374], S[A8375]
    for d, key in ((0x0AE774, 'b74'), (0x0AE788, 'b75')):
        t = lut2(d, S[A4130], S[A6210], rom)
        if not gt(t, fr14):
            v = 1
        elif gt(fsub(t, c(0x0D6020)), fr14):
            v = 0
        else:
            v = b74 if key == 'b74' else b75
        if key == 'b74':
            b74 = v
        else:
            b75 = v
    o[A8374], o[A8375] = b74, b75
    mode = sx8(rom[0x0D6010])
    if mode == 1:
        a, b = 1, 1
    elif mode == 2:
        a, b = 0, 1
    elif mode == 3:
        a, b = 1, 0
    elif b74 == 1:
        a, b = 1, 1
    elif b75 == 1:
        a, b = 0, 1
    else:
        a, b = 1, 0
    o[A8368], o[A8369] = a, b
    return o


def pass_E():
    n = 0
    roms = {'shipped': ROM}
    for mv in (1, 2, 3):
        mm = bytearray(ROM); mm[0x0D6010] = mv; roms[f'D6010={mv}'] = bytes(mm)
    for name, rom in roms.items():
        for a14 in (0.0, 0.0009765625, 0.001, -0.002, 0.3):
            for d94 in (0.0, 2000.0, 8000.0):
                for rpm in (800.0, 3000.0, 6500.0):
                    for bat, man in ((7.0, -760.0), (10.0, 0.0), (13.5, 500.0)):
                        for old in (0.0, 30.0, 95.0):
                            for bb in ((0, 0), (1, 1), (0, 1)):
                                S = {A7A14: f2b(a14), A7D94: f2b(d94), A6624: f2b(rpm), A4130: f2b(bat),
                                     A6210: f2b(man), A8360: f2b(old), A8374: bb[0], A8375: bb[1]}
                                res = []
                                for f7328 in (0.0, 12345.0):
                                    e = PEmu(rom)
                                    for a, v in S.items():
                                        if a in (A8374, A8375):
                                            e.ram_u8(a, v)
                                        else:
                                            e.ram_u32(a, v)
                                    e.ram_f32(A7328_, f7328)
                                    e.call(0x04BDAA)
                                    if rom is ROM:
                                        cover(e, '0x04BDAA')
                                    o = m_04BDAA(S, rom)
                                    for a, v in o.items():
                                        got = e.read_u8(a) if a in (A8374, A8375, A8368, A8369) else e.read_u32(a)
                                        ok(got == v, f'04BDAA {name} {a:08X} {got:#x} vs {v:#x} {S}')
                                    ok(nonstack(e) == cells((A8358, 12), (A8368, 2), (A8374, 2)), '04BDAA ws')
                                    res.append(dict(e.writes))
                                    n += 1
                                ok(res[0] == res[1], '04BDAA: [7328] has no effect')
    m = 0
    lo = 2.0 ** -10
    nxt = b2f(f2b(lo) + 1)
    for mv in (4, 0xFF, 0x81, 0x7F):
        mm = bytearray(ROM); mm[0x0D6010] = mv; rom = bytes(mm)
        for a14 in (0.0, lo, -lo, nxt, -nxt, math.nan):
            for bb in ((0, 0), (1, 1), (0, 1), (1, 0)):
                S = {A7A14: f2b(a14), A7D94: f2b(4000.0), A6624: f2b(3000.0), A4130: f2b(13.5),
                     A6210: f2b(0.0), A8360: f2b(30.0), A8374: bb[0], A8375: bb[1]}
                outs = []
                for r in (rom, ROM):
                    e = PEmu(r)
                    for a, v in S.items():
                        (e.ram_u8 if a in (A8374, A8375) else e.ram_u32)(a, v)
                    e.ram_f32(A7328_, 0.0)
                    e.call(0x04BDAA)
                    o = m_04BDAA(S, r)
                    for a, v in o.items():
                        got = e.read_u8(a) if a in (A8374, A8375, A8368, A8369) else e.read_u32(a)
                        ok(got == v, f'04BDAA D6010={mv:#x} {a:08X}')
                    outs.append(dict(e.writes))
                    want8358 = ZERO if (a14 != a14 or abs(a14) <= lo) else u32(ROM, 0x0D6024)
                    ok(e.read_u32(A8358) == want8358, f'04BDAA window a14={a14}')
                ok(outs[0] == outs[1], f'04BDAA: byte 0x0D6010 = {mv:#x} behaves exactly as 0')
                m += 1
    print(f'E  0x04BDAA: {n} cases (shipped + byte 0x0D6010 = 1/2/3 on copies); every output independent of [7328] '
          f'(the fmov.s @r2,fr9 at 04BDC6 is a dead load); {m} more: 0x0D6010 = 4 / 0xFF / 0x81 / 0x7F behave exactly as 0'
          f' (sign-extended cmp/eq #1/#2/#3); [8358] = 0.0 for [7A14] = +-2^-10 exactly and NaN, 90.0 one ulp outside')


# ================================================================== F  0x03D0B8
def pass_F():
    n = 0
    eps = f2b(2.0 ** -15)
    k1, k2, k3 = u32(ROM, 0x0CC53C), u32(ROM, 0x0CC540), u32(ROM, 0x0CC544)
    for b48 in (0, 1, 2, 0x81):
        for v38 in (0.0, 3.9, 4.0, 4.5, 1000.0, math.nan):
            for v24 in (0.0, 4.0, 1000.0, 1500.0, 3000.0):
                for v78, ve4 in ((0.0, 0.0), (0.05, -0.02), (1.0, 0.5)):
                    olds = [f2b(random.choice([0.0, 1.0, 1.2, 0.8])) for _ in range(4)]
                    e = PEmu()
                    e.ram_u8(A7448, b48)
                    e.ram_f32(A7338, v38); e.ram_f32(A7324, v24); e.ram_f32(A7878, v78); e.ram_f32(A7AE4, ve4)
                    for a, v in zip(A7D58, olds):
                        e.ram_u32(a, v)
                    e.call(0x03D0B8)
                    cover(e, '0x03D0B8')
                    if b48 == 1:
                        if gt(f2b(4.0), f2b(v38)):
                            x = TWO
                        else:
                            q = fdiv(f2b(v24), f2b(v38))
                            x = clamp(fsub(q, fadd(f2b(v78), f2b(ve4))), ZERO, TWO)
                        want = [x, lag(x, olds[1], k1, eps), lag(x, olds[2], k2, eps), lag(x, olds[3], k3, eps)]
                    else:
                        want = [ONE] * 4
                    for a, v in zip(A7D58, want):
                        ok(e.read_u32(a) == v, f'03D0B8 {a:08X} b48={b48} v38={v38} v24={v24}')
                    ok(nonstack(e) == cells((A7D58[0], 16)), '03D0B8 ws')
                    n += 1
    print(f'F  0x03D0B8: {n} cases; lag weights k = {b2f(k1)} / {b2f(k2)} / {b2f(k3)} (0x0CC53C/40/44), snap 2^-15;'
          f' ROM pointer table 0x063DC8 = {[hex(u32(ROM, 0x063DC8 + 4 * i)) for i in range(4)]}')


# ================================================================== G  0x03D582
def pass_G():
    n = 0
    seen = []
    for mode in (0, 1, 2, 0xFF):
        for ch in (0, 1, 2, 3, 4, 9):
            for da4 in (1.0, 0.5, 1.25):
                vals = [f2b(random.choice([0.0, 312.5, 1000.25, 4096.0, 262136.0, 12345.678])) for _ in range(4)]
                fr0 = f2b(random.choice([0.0, 777.77, 2500.0]))
                r = rec(1)
                e = PEmu()
                e.ram_u8(r, mode); e.ram_u8(r + 12, ch); e.ram_u16(r + 4, 0x1234)
                e.ram_u32(r + 24, 0xDEADBEEF); e.ram_u8(r + 36, 0x55)
                e.ram_f32(A7DA4, da4)
                for j in range(4):
                    e.ram_u32(A7290[j], vals[j])
                e.stub(0x02F9E0, fn=lambda em: (seen.append(em.R[4]), em.FR.__setitem__(0, fr0)))
                e.call(0x03D582, regs={4: r})
                cover(e, '0x03D582')
                if mode == 0:
                    x = fdiv(fmul(fr0, f2b(da4)), K025)
                    ok(e.read_u32(r + 24) == ftrc(x), '03D582 mode0')
                    ok(seen[-1] == 0x1234, '03D582 r4 = u16 rec+4')
                    ok(e.read_u8(r + 36) == 0, '03D582 +36')
                    ws = cells((r + 24, 4), (r + 36, 1))
                elif mode == 1:
                    if ch <= 3:
                        x = fdiv(fmul(vals[ch], f2b(da4)), K025)
                        ok(e.read_u32(r + 24) == ftrc(x), f'03D582 mode1 ch{ch}')
                        ws = cells((r + 24, 4), (r + 36, 1))
                    else:
                        ok(e.read_u32(r + 24) == 0xDEADBEEF, '03D582 ch>3 no store')
                        ws = cells((r + 36, 1))
                    ok(e.read_u8(r + 36) == 0, '03D582 +36 m1')
                else:
                    ws = set()
                ok(nonstack(e) == ws, f'03D582 ws mode {mode} ch {ch}')
                n += 1
    print(f'G  0x03D582: {n} cases; mode 1: rec+24 = trunc([7290 + 4*ch] * [7DA4] / 0.25), ch = byte rec+12 in 0..3'
          f' (no store for ch > 3); mode 0: from 0x02F9E0(u16 rec+4); both clear byte rec+36; other modes write nothing')


# ================================================================== H  0x03D648 / I 0x03D68C
def pass_H():
    n = 0
    for _ in range(60):
        e = PEmu()
        lat = f2b(random.choice([673.25, 806.25, 3147.0, 0.0]))
        e.ram_u32(A734C, lat)
        flags, counts = [], []
        for j in range(4):
            fl = random.choice([0, 0, 1, 2])
            c = random.choice([0, 1, 4000, 12345, 1048544, 0x7FFFFFFF])
            e.ram_u8(rec(j) + 1, fl); e.ram_u32(rec(j) + 20, c)
            flags.append(fl); counts.append(c)
        e.call(0x03D648)
        cover(e, '0x03D648')
        for j in range(4):
            if flags[j] == 0:
                v = fmul(ffloat(counts[j]), K025)
                ok(e.read_u32(A7D94_[j]) == v, '03D648 7D94')
                ok(e.read_u32(A7D84[j]) == fadd(v, lat), '03D648 7D84')
            else:
                ok(e.read_u32(A7D94_[j]) == 0 and e.read_u32(A7D84[j]) == 0, '03D648 zero')
        ok(nonstack(e) == cells((A7D84[0], 16), (A7D94_[0], 16)), '03D648 ws')
        n += 1
    print(f'H  0x03D648: {n} cases; [7D94+4j] = 0.25 * float(s32 rec_j+20), [7D84+4j] = that + [734C] when byte rec_j+1 == 0,'
          f' else both 0.0')
    for v in (0.0, -1000.0, math.nan):
        e = PEmu(); e.ram_f32(A6210, v); e.ram_f32(A7DA4, 5.0)
        e.call(0x03D68C)
        cover(e, '0x03D68C')
        ok(e.read_u32(A7DA4) == ONE and nonstack(e) == cells((A7DA4, 4)), '03D68C')
    print('I  0x03D68C: [7DA4] = 1.0 on every call; its [6210] load is unused')


# ================================================================== J  0x0303C0
def pass_J():
    n = 0
    for bat in (0.0, 6.5, 7.75, 9.0, 12.0, 13.9, 14.0, 14.4, 16.5, 18.0, math.nan):
        for man in (-1000.0, -500.0, 0.0, 750.0, 2000.0):
            e = PEmu()
            e.ram_f32(A4130, bat); e.ram_f32(A6210, man)
            e.stub(0x00317C, r0=0x00F0); e.stub(0x003190)
            e.call(0x0303C0)
            cover(e, '0x0303C0')
            raw = lut2u16(0x0AD7E0, f2b(bat), f2b(man))
            ok(e.read_u16(A7350) == raw, '0303C0 7350')
            ok(e.read_u32(A4280) == raw, '0303C0 4280 zero-extended')
            ok(e.read_u32(A734C) == fmul(K025, ffloat(raw)), '0303C0 734C')
            ok(nonstack(e) == cells((A7350, 2), (A4280, 4), (A734C, 4)), '0303C0 ws')
            n += 1
    lat = [lut2u16(0x0AD7E0, f2b(b), 0) for b in (6.5, 9.0, 11.5, 14.0, 16.5)]
    print(f'J  0x0303C0: {n} cases; u16 [7350] = [4280] = 0x0BE944(AD7E0, [4130], [6210]); [734C] = 0.25 * that;'
          f' raw at 6.5/9/11.5/14/16.5 = {lat} = {[round(x * 0.00025, 5) for x in lat]} ms (definition scaling x*.00025)')
    rows = T.read_table(ROM, 0x0AD7E0)['values']
    ok(all(r == rows[0] for r in rows), 'latency flat across the [6210] axis')


# ================================================================== K  0x05D478, L 0x03D4F6
def pass_K():
    n = 0
    for x in (0.0, 127.9, 128.0, 255.9, 256.0, 1000.0, 3147.0, 20000.0, 65280.0, 65408.0, 100000.0, -300.0):
        e = PEmu(); e.ram_f32(A7D84[0], x)
        e.call(0x05D478)
        cover(e, '0x05D478')
        want = max(0, min(255, int(x / 256.0 + 0.5)))      # trunc toward zero, then clamp
        ok(e.R[0] == want, f'05D478 {x}: {e.R[0]} vs {want}')
        n += 1
    print(f'K  0x05D478: {n} cases; r0 = clamp(trunc([7D84]/256 + 0.5), 0, 255); logcfg scaling x*256/1000 ms')
    for b in (0, 1, 2, 0xFF):
        e = PEmu(); e.ram_u8(A726C, b)
        e.call(0x03D4F6)
        cover(e, '0x03D4F6')
        ok(e.R[0] == (0 if b == 1 else 2), '03D4F6')
        ok(ROM[0x063DFC + e.R[0]] == (0 if b == 1 else 1), '063DFC')
    print('L  0x03D4F6: r0 = 0 when byte [726C] == 1 else 2; byte 0x063DFC[r0] = 0 / 1 = record mode')


# ================================================================== M  0x00A4E0 + 0x011848
def pass_M():
    n = 0
    for k in range(4):
        for w in (0, 1, 1000, 0xFFFE, 0xFFFF, 0x10000, 0x10001, 66320, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF):
            e = PEmu()
            e.stub(0x0BE81C); e.stub(0x0BE82C)
            e.ram_u32(A4294 + 28 * k, 0x5A5A5A5A)
            e.call(0x00A4E0, regs={4: k, 5: w})
            cover(e, '0x00A4E0+0x011848')
            reg = min(w, 0xFFFF)
            ok(e.mmio_writes == [(P_WID[k], 2, reg), (P_WID[k], 2, reg)], f'00A4E0 mmio {e.mmio_writes}')
            ok(e.read_u32(A4294 + 28 * k) == ((w - 0xFFFF) & M32 if w > 0xFFFF else 0), '00A4E0 overflow')
            n += 1
    print(f'M  0x00A4E0/0x011848: {n} cases; u16 [0xFFFFF640 + 2k] = min(w, 0xFFFF), stored twice (0x011848);'
          f' [4294 + 28k] = w - 0xFFFF if w > 0xFFFF else 0 (UNSIGNED compare: a negative w, e.g. 0xFFFFFFFF, gives'
          f' 0xFFFF and w - 0xFFFF); register pointer from ROM table 0x011A7C + 12k')


# ================================================================== N  0x009F72
def m_009F72(k, S, mm):
    """S: driver record fields + globals; mm: mmio values. Returns (rec updates, mmio writes list, calls)."""
    r = {}
    wr = []
    calls = []
    base = A4284 + 28 * k
    mask = 1 << k
    r5 = (S['416C'] & M32) >> 4
    ang = S['+4']
    if gt(ZERO, ang):
        r['+20'] = r5 & 0xFFFF
    else:
        fr2 = fdiv(fmul(ffloat(S['4154']), ang), f2b(30.0))
        r2 = ftrc(fr2)
        r4 = (r2 - (1 << 32) if r2 & 0x80000000 else r2) >> 4
        if (r4 & 0xFFFF) > 0x7FFF:
            r4 = 0x7FFF
        r['+20'] = (r5 + r4) & 0xFFFF
    r['+12'] = S['+0']
    cnt = sx16(mm[P_F440])
    wr.append((P_CMP[k], 2, (cnt + 0xFFFF) & 0xFFFF))
    wr.append((P_F66A, 2, (~mask) & 0xFFFF))
    p12 = r['+12'] - (1 << 32) if r['+12'] & 0x80000000 else r['+12']
    lat = S['4280'] - (1 << 32) if S['4280'] & 0x80000000 else S['4280']
    if (mm[P_F666] & mask) == 0:
        w = ((p12 + lat) >> 4) & M32
        r4 = (cnt + 3) & M32
        if ((sx16(r['+20']) - r4) & 0xFFFF) >= 0x8000:
            r['+20'] = r4 & 0xFFFF
        wr.append((P_CMP[k], 2, r['+20']))
        calls.append(('A4E0', k, w))
        r['+22'] = 0
        return r, wr, calls, 'clear'
    rem = (mm[P_WID[k]] + S['4294']) & M32
    d = (sx16(r['+20']) - cnt) & 0xFFFF
    if d >= 0x8000:
        d = 0
    if d > rem:
        calls.append(('E6E4', 0xFFFFF66C, mask, 1))
        r['+24'] = 1
        return r, wr, calls, 'late'
    if S['+22'] == 1:
        r12 = ((p12 >> 4) + rem) & M32
    else:
        r12 = (p12 + lat) >> 4
        d2 = (sx16(r['+20']) - cnt) & 0xFFFF
        if d2 < 0x8000:
            r12 = (r12 + d2) & M32
        else:
            r5b = (-d2) & 0xFFFF
            r12 = (r12 - r5b) & M32 if (r12 & M32) >= r5b else 0
    calls.append(('A4E0', k, r12 & M32))
    wr.append((P_F666, 2, mask))
    r['+22'] = 0
    return r, wr, calls, 'active'


def pass_N():
    n = 0
    paths = {}
    for k in range(4):
        for st in (0, 1 << k, 0xF):
            for _ in range(25):
                S = {'416C': random.choice([0x1000, 0x12340, 0x7FFF0]),
                     '4154': random.choice([0x4000, 0x20000, 0x80000]),
                     '+4': f2b(random.choice([-5.0, 0.0, 3.5, 20.0, 34.9])),
                     '+0': random.choice([0, 1600, 3200, 40000, 1048544]),
                     '4280': random.choice([2693, 3225, 12588]),
                     '4294': random.choice([0, 5]),
                     '+22': random.choice([0, 1])}
                mm = {P_F440: random.choice([0x0000, 0x1234, 0xFFF0, 0x8000]), P_F666: st, P_F66A: 0,
                      P_WID[k]: random.choice([0, 100, 0x8000]), P_F66C: 0}
                e = PEmu()
                for a, v in mm.items():
                    e.mmio(a, v)
                for a in P_CMP:
                    e.mmio(a, 0)
                base = A4284 + 28 * k
                e.ram_u32(A416C, S['416C']); e.ram_u32(A4154, S['4154']); e.ram_u32(A4280, S['4280'])
                e.ram_u32(base + 0, S['+0']); e.ram_u32(base + 4, S['+4']); e.ram_u32(base + 12, 0)
                e.ram_u16(base + 20, 0); e.ram_u8(base + 22, S['+22']); e.ram_u8(base + 24, 0x77)
                e.ram_u32(A4294 + 28 * k, S['4294'])
                calls = []
                e.stub(0x0BE81C); e.stub(0x0BE82C)
                e.stub(0x00E6E4, fn=lambda em: calls.append(('E6E4', em.R[4], em.R[5] & 0xFFFF, em.R[6])))
                real_a4e0 = []
                e.stub(0x00A4E0, fn=lambda em: real_a4e0.append(('A4E0', em.R[4] & 0xFF, em.R[5])))
                e.call(0x009F72, regs={4: k})
                cover(e, '0x009F72')
                r, wr, mc, path = m_009F72(k, S, mm)
                paths[path] = paths.get(path, 0) + 1
                ok(e.read_u16(base + 20) == r['+20'], f'009F72 +20 {path}')
                ok(e.read_u32(base + 12) == r['+12'], '009F72 +12')
                if '+22' in r:
                    ok(e.read_u8(base + 22) == r['+22'], '009F72 +22')
                if '+24' in r:
                    ok(e.read_u8(base + 24) == 1, '009F72 +24')
                ok(e.mmio_writes == wr, f'009F72 mmio {path}: {e.mmio_writes} vs {wr}')
                got = [c for c in calls + real_a4e0]
                ok(sorted(got) == sorted(mc), f'009F72 calls {path}: {got} vs {mc}')
                n += 1
    print(f'N  0x009F72: {n} cases {paths}; status bit clear: compare [F444+2k] <- [F440]-1, then <- rec+20 (moved to'
          f' [F440]+3 if already passed); width -> 0x00A4E0(k, (rec+0 + [4280]) >> 4)')


def run_009F72(k, S, mm, wid=0):
    e = PEmu()
    for a, v in mm.items():
        e.mmio(a, v)
    for a in P_CMP:
        e.mmio(a, 0)
    e.mmio(P_WID[k], wid)
    base = A4284 + 28 * k
    e.ram_u32(A416C, S['416C']); e.ram_u32(A4154, S['4154']); e.ram_u32(A4280, S['4280'])
    e.ram_u32(base + 0, S['+0']); e.ram_u32(base + 4, S['+4']); e.ram_u32(base + 12, 0)
    e.ram_u16(base + 20, 0); e.ram_u8(base + 22, S.get('+22', 0)); e.ram_u8(base + 24, 0)
    e.ram_u32(A4294 + 28 * k, S.get('4294', 0))
    e.stub(0x0BE81C); e.stub(0x0BE82C); e.stub(0x00E6E4)
    e.call(0x009F72, regs={4: k})
    cover(e, '0x009F72')
    return e, base


def pass_N2():
    """Targeted cases: the compare-move boundary and wrap, the status-set branch, the low-16-bit offset cap, and a
    negative (counts + latency)."""
    k = 1
    base_S = {'4154': 0x10000, '+4': f2b(-1.0), '+0': 3200, '4280': 2693}
    cmpw = lambda e: [v for (a, nb, v) in e.mmio_writes if a == P_CMP[k]]   # noqa: E731
    # compare moved iff ((drec+20 - ([F440]+3)) mod 2^16) >= 0x8000; drec+20 = [416C] >> 4 here (start < 0)
    f440 = 0x1000
    for diff, moved in ((0x7FFF, False), (0x8000, True), (0x0000, False), (0xFFFF, True)):
        S = dict(base_S, **{'416C': ((f440 + 3 + diff) & 0xFFFF) << 4})
        e, base = run_009F72(k, S, {P_F440: f440, P_F666: 0, P_F66A: 0})
        want = (f440 + 3) & 0xFFFF if moved else (f440 + 3 + diff) & 0xFFFF
        ok(cmpw(e) == [(f440 - 1) & 0xFFFF, want] and e.read_u16(base + 20) == want, f'N2 boundary diff {diff:#x}')
    # wrap: [F440] = 0xFFFE, drec+20 = 0 -> first write 0xFFFD, then moved to [F440] + 3 = 0x0001
    S = dict(base_S, **{'416C': 0})
    e, base = run_009F72(k, S, {P_F440: 0xFFFE, P_F666: 0, P_F66A: 0})
    ok(cmpw(e) == [0xFFFD, 0x0001], f'N2 wrap {cmpw(e)}')
    # status bit SET: exactly one compare write ([F440] - 1); drec+20 is never written to the register
    for wid in (0, 0x40, 0x8000):
        S = dict(base_S, **{'416C': 0x12340})
        e, base = run_009F72(k, S, {P_F440: 0x0100, P_F666: 1 << k, P_F66A: 0}, wid)
        ok(cmpw(e) == [0x00FF], f'N2 status set: compare writes {cmpw(e)}')
    # low-16-bit cap: trunc([4154] * start / 30) >> 4 = 0x12345 -> low half 0x2345 <= 0x7FFF -> NOT capped
    for off, capped in ((0x12345, False), (0x8000, True), (0x7FFF, False), (0x18000, True)):
        S = dict(base_S, **{'416C': 0x1000, '4154': off << 4, '+4': f2b(30.0)})
        e, base = run_009F72(k, S, {P_F440: 0x0100, P_F666: 0, P_F66A: 0})
        add = 0x7FFF if capped else off
        want = (0x100 + add) & 0xFFFF
        if ((want - 0x103) & 0xFFFF) >= 0x8000:
            want = 0x103
        ok(e.read_u16(base + 20) == want, f'N2 cap off={off:#x}: {e.read_u16(base + 20):#x} vs {want:#x}')
    # negative counts + latency: P = 0xFFFFFFF0, L = 0 -> w = -1 -> register 0xFFFF twice, overflow 0xFFFF0000
    S = dict(base_S, **{'416C': 0x1000, '+0': 0xFFFFFFF0, '4280': 0})
    e, base = run_009F72(k, S, {P_F440: 0x0100, P_F666: 0, P_F66A: 0})        # 0x00A4E0 / 0x011848 real here
    ok([v for (a, nb, v) in e.mmio_writes if a == P_WID[k]] == [0xFFFF, 0xFFFF], 'N2 negative: register 0xFFFF')
    ok(e.read_u32(A4294 + 28 * k) == 0xFFFF0000, 'N2 negative: overflow cell 0xFFFF0000')
    e2 = PEmu()
    e2.stub(0x0BE81C); e2.stub(0x0BE82C)
    e2.call(0x00A4E0, regs={4: k, 5: 0xFFFFFFFF})
    ok([v for (a, nb, v) in e2.mmio_writes] == [0xFFFF, 0xFFFF] and e2.read_u32(A4294 + 28 * k) == 0xFFFF0000,
       'N2 negative width')
    print('N2 0x009F72 targeted: compare moved at diff 0x8000 / 0xFFFF, kept at 0x7FFF / 0; wrap [F440] = 0xFFFE -> '
          'writes 0xFFFD then 0x0001; status bit SET -> one compare write ([F440] - 1) only; offset cap tests the LOW 16 '
          'bits (0x12345 added unclamped, 0x18000 capped); a negative (P + L) >> 4 = -1 gives register 0xFFFF and '
          'overflow 0xFFFF0000')


# ================================================================== O  0x009B2C
def pass_O():
    n = 0
    armed = 0
    for k in range(4):
        for P in (0, 4000, 40000, 1048544):
            for A in (-100.0, 0.0, 10.0, 100.0, 400.0, 700.0):
                for flag in (0, 1):
                    S = {'4158': random.choice([0x10000, 0x40000, 0x200000]), '42F4': 0x7850,
                         '4280': random.choice([2693, 12588]), '4168': f2b(random.choice([0.0, 40.0]))}
                    e = PEmu()
                    e.ram_u32(A4158, S['4158']); e.ram_u32(A42F4, S['42F4']); e.ram_u32(A4280, S['4280'])
                    e.ram_u32(A4168, S['4168'])
                    base = A4284 + 28 * k
                    for off in (0, 4, 8):
                        e.ram_u32(base + off, 0x11111111)
                    e.ram_u8(base + 23, 0x33)
                    called = []
                    e.stub(0x00317C, r0=0); e.stub(0x003190)
                    e.stub(0x009F72, fn=lambda em: called.append(em.R[4]))
                    e.call(0x009B2C, regs={4: k, 5: P, 6: flag}, fregs={4: A})
                    cover(e, '0x009B2C')
                    span = fdiv(fmul(ffloat((S['4280'] + S['42F4'] + P) & M32), f2b(180.0)), ffloat(S['4158']))
                    a = fsub(f2b(A), S['4168'])
                    if gt(f2b(-60.0), a):
                        a1 = fadd(a, f2b(720.0))
                    elif gt(f2b(660.0), a):
                        a1 = a
                    else:
                        a1 = fadd(a, f2b(-720.0))
                    st = fsub(a1, span)
                    if flag != 0 and gt(ZERO, st):
                        ok(e.read_u32(base) == 0x11111111 and not called, '009B2C skip')
                    else:
                        ok(e.read_u32(base) == P, '009B2C +0')
                        ok(e.read_u32(base + 8) == span, '009B2C +8')
                        ok(e.read_u32(base + 4) == st, '009B2C +4')
                        if gt(f2b(35.0), st):
                            ok(called == [k] and e.read_u8(base + 23) == 0, '009B2C armed')
                            armed += 1
                        else:
                            ok(not called and e.read_u8(base + 23) == 2, '009B2C pending')
                    n += 1
    print(f'O  0x009B2C: {n} cases ({armed} armed at once); rec+0 = P, rec+8 = (P + [4280] + [42F4]) * 180 / [4158],'
          f' rec+4 = wrap(A - [4168]) - rec+8; 0x009F72(k) when rec+4 < 35 (byte +23 = 0) else byte +23 = 2;'
          f' [42F4] enters only the angle span, never the width')


# ================================================================== P  0x03DFC8
def pass_P():
    n = 0
    for b7, b1, b20, b2, b429 in [(1, 0, 0, 0, 0), (0, 0, 0, 0, 0), (0, 0, 0, 1, 0), (0, 1, 0, 0, 0),
                                  (0, 1, 1, 0, 0), (0, 1, 1, 0, 1), (0, 0, 1, 0, 0), (0, 2, 0, 0, 0)]:
        for r11 in (0x00100000, 0x01000000, 0x02000000):
            for s12 in (0x00080000, 0x01800000):
                for e54 in (0, 5, 23):
                    j = 2
                    r = rec(j)
                    sub = r + 16
                    k = 2
                    P = random.choice([4000, 1048544])
                    e = PEmu()
                    e.ram_u8(r + 7, b7); e.ram_u8(r + 2, b2); e.ram_u8(r + 6, 9)
                    e.ram_u8(sub + 0, k); e.ram_u8(sub + 1, b1); e.ram_u8(sub + 20, b20)
                    e.ram_u32(sub + 4, 0xAAAAAAAA); e.ram_u32(sub + 8, P); e.ram_u32(sub + 12, s12)
                    e.ram_u8(A429B + 28 * k, b429); e.ram_u8(A7E54, e54); e.ram_u8(A7E50, 0)
                    e.ram_u32(A4158, 0x00400000); e.ram_u32(A4280, 3225)
                    calls = []
                    e.stub(0x009B2C, fn=lambda em: calls.append(('9B2C', em.R[4], em.R[5], em.FR[4], em.R[6])))
                    e.stub(0x009C38, fn=lambda em: calls.append(('9C38', em.R[4], em.R[5])))
                    e.stub(0x009D48, fn=lambda em: calls.append(('9D48', em.R[4])))
                    e.call(0x03DFC8, regs={4: r, 5: r11})
                    cover(e, '0x03DFC8')
                    want = []
                    s1, s4 = b1, 0xAAAAAAAA
                    if b7 != 0:
                        r2 = 2
                    else:
                        if sx8(b1) == 1:
                            if b20 == 0:
                                s4 = P
                                want.append(('9C38', k, P))
                            elif b429 != 0:
                                want.append(('9D48', k)); s1 = 0
                            else:
                                want.append(('9C38', k, 0)); s1 = 2
                        elif b1 == 0 and b20 == 0:
                            go = True
                            if b2 != 0:
                                q = q16div((P + u32(ROM, 0x0CBDB4) + 3225) & M32, 0x00400000)
                                r0 = (180 * q + s12) & M32
                                if not ((r11 - (1 << 32) if r11 & 0x80000000 else r11) >=
                                        (r0 - (1 << 32) if r0 & 0x80000000 else r0)):
                                    s1, go = 2, False
                            if go:
                                s4 = P
                                r4 = s12 - r11
                                if r4 > 0:
                                    r4 = 0
                                a = (e54 * 30 << 16) - r4 + (-(10 << 16))
                                if a >= 720 << 16:
                                    a -= 720 << 16
                                elif a < 0:
                                    a += 720 << 16
                                want.append(('9B2C', k, P, fdiv(ffloat(a & M32), f2b(65536.0)), 0))
                                s1 = 1
                        r2 = 1
                    ok(calls == want, f'03DFC8 calls {calls} vs {want}')
                    ok(e.read_u8(sub + 1) == (s1 & 0xFF), '03DFC8 sub+1')
                    ok(e.read_u32(sub + 4) == s4, '03DFC8 sub+4 (rec+20) = rec+24')
                    ok(e.read_u8(r + 2) == r2 and e.read_u8(r + 6) == 0, '03DFC8 rec+2 / rec+6')
                    ok(e.read_u8(A7E50) == (1 if b7 == 0 else 0), '03DFC8 7E50')
                    n += 1
    print(f'P  0x03DFC8: {n} cases; rec+20 := rec+24 then 0x009B2C(k = byte rec+16, r5 = rec+20, fr4 = angle, r6 = 0)'
          f' (idle sub-record) or 0x009C38(k, rec+20) (sub+1 == 1, in-flight); byte rec+7 != 0 skips')


# ================================================================== R  end to end, every function real
def chain_from_7290(e, j, lat, f440=0x0100, r416C=0x1000, r4154=0x10000):
    """From PW_j = [7290+4j] already in RAM: 0x03D68C, 0x03D582 (MODE 1), then handler A 0x03DFC8 on an idle
    sub-record, which calls 0x009B2C -> 0x009F72 -> 0x00A4E0 -> 0x011848, all REAL.  Stubbed: only the
    critical-section pairs 0x00317C/0x003190 and 0x0BE81C/0x0BE82C (the emulator raises on ldc sr).
    The angle cells are set so that 0x009B2C arms at once (start < 35 deg); returns (counts, mmio writes)."""
    r = rec(j)
    e.call(0x03D68C)                                   # [7DA4] = 1.0
    e.ram_u8(r + 0, 1); e.ram_u8(r + 2, 0); e.ram_u8(r + 7, 0); e.ram_u8(r + 12, j)
    e.ram_u8(r + 16, j); e.ram_u8(r + 17, 0); e.ram_u8(r + 36, 0x55)
    e.call(0x03D582, regs={4: r})                      # rec+24 = counts; byte rec+36 (= sub+20) = 0
    cnt = e.read_u32(r + 24)
    r11 = 0x00400000
    e.ram_u32(r + 28, r11)                             # sub+12 == r11 -> 0x03DD4E angle = 30*[7E54] - 10 = 20 deg
    e.ram_u8(A7E54, 1); e.ram_u8(A7E50, 0)
    e.ram_u32(A4158, 0x7FFFFFFF); e.ram_u32(A42F4, u32(ROM, 0x0CBDB4)); e.ram_u32(A4280, lat)
    e.ram_f32(A4168, 0.0); e.ram_u32(A416C, r416C); e.ram_u32(A4154, r4154)
    base = A4284 + 28 * j
    e.ram_u8(base + 22, 0); e.ram_u8(base + 23, 0x33); e.ram_u32(A4294 + 28 * j, 0x5A5A5A5A)
    e.mmio(P_F440, f440); e.mmio(P_F666, 0); e.mmio(P_F66A, 0)
    e.stub(0x00317C, r0=0); e.stub(0x003190); e.stub(0x0BE81C); e.stub(0x0BE82C)
    e.mmio_writes = []
    e.call(0x03DFC8, regs={4: r, 5: r11})
    return cnt, base


def check_chain(e, j, pw, cnt, base, lat, f440, r416C, r4154, tag):
    c = ftrc(fdiv(fmul(pw, ONE), K025))
    ok(cnt == c, f'{tag}: counts {cnt} vs {c}')
    ok(e.read_u32(rec(j) + 20) == cnt, f'{tag}: rec+20 = rec+24 (0x03DFC8)')
    ok(e.read_u32(base) == cnt and e.read_u8(base + 23) == 0, f'{tag}: driver +0 = counts, armed at once')
    w = ((s32(cnt) + lat) >> 4) & M32
    reg = min(w, 0xFFFF)
    S = {'416C': r416C, '4154': r4154, '+4': e.read_u32(base + 4), '+0': cnt, '4280': lat, '4294': 0, '+22': 0}
    _, wr, calls, path = m_009F72(j, S, {P_F440: f440, P_F666: 0, P_WID[j]: 0})
    ok(path == 'clear' and calls == [('A4E0', j, w)], f'{tag}: 0x009F72 path {path}')
    ok(e.mmio_writes == wr + [(P_WID[j], 2, reg), (P_WID[j], 2, reg)],
       f'{tag}: peripheral writes {e.mmio_writes} vs {wr} + width {reg:#x} twice')
    ok(e.read_u32(A4294 + 28 * j) == ((w - 0xFFFF) & M32 if w > 0xFFFF else 0), f'{tag}: overflow cell')
    return w, reg


def pass_R():
    n = 0
    s4seen = set()
    for _ in range(240):
        e = PEmu()
        S4v = random.choice([1.0, 0.75, 1.3, 0.5])
        ins = {0xFFFF7348: random.uniform(0, 131072), 0xFFFF7AB4: S4v, 0xFFFF73A4: random.choice([0.0, 0.1]),
               0xFFFF7A08: random.choice([0.0, -0.05]), 0xFFFF7BC4: random.choice([1.0, 1.1015625]),
               0xFFFF76D4: random.uniform(0.75, 1.25), 0xFFFF7878: random.uniform(-0.1, 0.1),
               0xFFFF7AE4: random.choice([0.0, 0.03, -0.02]), 0xFFFF730C: random.uniform(0.5, 1.5),
               0xFFFF733C: random.choice([0.0, 300.0])}
        for i in range(4):
            ins[0xFFFF7310 + 4 * i] = random.uniform(0.5, 1.5)
            ins[0xFFFF7B6C + 4 * i] = random.choice([0.9140625, 1.0, 1.0859375])
        for a, v in ins.items():
            e.ram_f32(a, v)
        e.call(0x0301E4)
        for a in (A726C, A7306, A90C1, A3158, A72D1):
            e.ram_u8(a, 0)
        for jj in range(4):
            e.ram_u8(A726F[jj], 0)
        e.ram_f32(A6354, 90.0); e.ram_f32(A728C, 0.0); e.ram_f32(A72DC, 0.0)
        e.call(0x02EFD2)                               # COPY path: [7290+4j] = [7328+4j]
        j = random.randrange(4)
        lat = random.choice([2693, 3225, 4499, 12588])
        f440 = random.choice([0x0100, 0x8000, 0xFFF0])
        cnt, base = chain_from_7290(e, j, lat, f440)
        # model, end to end (0x0301E4 verified CONTRACT, 0x02EFD2 COPY path)
        C = fmul(fadd(fadd(f2b(ins[0xFFFF76D4]), f2b(ins[0xFFFF7878])), f2b(ins[0xFFFF7AE4])), f2b(ins[0xFFFF7348]))
        fr9 = fmul(f2b(S4v), C)
        x = fmul(f2b(ins[0xFFFF7310 + 4 * j]), fr9)
        x = fmac(x, f2b(ins[0xFFFF7B6C + 4 * j]), ZERO)
        x = fmul(x, f2b(ins[0xFFFF7BC4]))
        pw = clamp(x, f2b(ins[0xFFFF733C]), f2b(262136.0))
        ok(e.read_u32(A7290[j]) == pw, 'R: [7290+4j] = clamped per-cylinder product')
        w, reg = check_chain(e, j, pw, cnt, base, lat, f440, 0x1000, 0x10000, 'R')
        tot = 4 * Fraction(b2f(pw)) + lat
        if tot <= 0xFFFFF:
            ok(0 <= tot - 16 * reg < 16, f'R: 16*reg within [4PW+L-16, 4PW+L]: {tot} {reg}')
        s4seen.add(S4v)
        n += 1
    ok(s4seen == {1.0, 0.75, 1.3, 0.5}, 'R: S4 != 1 exercised')
    # edges: PW injected at [7328+4j] (COPY path), around the 0xFFFF register limit and the 262136 clamp ceiling
    edge = []
    for lat in (2693, 12588):
        for pwv in (0.0, 0.2, 0.25, 1000.25, 258996.0, 258996.25, 258997.0, 261470.0, 261470.5, 261471.0, 262136.0):
            e = PEmu()
            for a in (A726C, A7306, A90C1, A3158, A72D1):
                e.ram_u8(a, 0)
            for jj in range(4):
                e.ram_u8(A726F[jj], 0)
                e.ram_f32(A7328[jj], pwv)
            e.ram_f32(A6354, 90.0); e.ram_f32(A728C, 0.0); e.ram_f32(A72DC, 0.0)
            e.call(0x02EFD2)
            j = 2
            cnt, base = chain_from_7290(e, j, lat)
            w, reg = check_chain(e, j, f2b(pwv), cnt, base, lat, 0x0100, 0x1000, 0x10000, 'R-edge')
            tot = 4 * Fraction(pwv) + lat
            if tot <= 0xFFFFF:
                ok(0 <= tot - 16 * reg < 16 and e.read_u32(A4294 + 28 * j) == 0, 'R-edge: within 16, no overflow')
            else:
                ok(reg == 0xFFFF and e.read_u32(A4294 + 28 * j) == w - 0xFFFF, 'R-edge: saturated, excess kept')
            edge.append((lat, pwv, reg, e.read_u32(A4294 + 28 * j)))
            n += 1
    sat = {(l, p): (r, o) for (l, p, r, o) in edge if p == 262136.0}
    ok(sat == {(2693, 262136.0): (0xFFFF, 167), (12588, 262136.0): (0xFFFF, 785)}, f'R: ceiling {sat}')
    print(f'R  end to end: {n} cases; REAL 0x0301E4 -> 0x02EFD2 (COPY) -> 0x03D68C -> 0x03D582 (MODE 1) -> 0x03DFC8 (idle'
          f' sub-record) -> 0x009B2C -> 0x009F72 (status clear) -> 0x00A4E0 -> 0x011848, S4 in {sorted(s4seen)}:'
          f' u16 [0xFFFFF640+2j] = min((trunc(4*PW_j) + [4280]) >> 4, 0xFFFF), written twice after the two compare'
          f' writes; 0 <= 4*PW + L - 16*register < 16 while 4*PW + L <= 0xFFFFF; at the 262136 ceiling the register'
          f' is 0xFFFF with {sat[(2693, 262136.0)][1]} / {sat[(12588, 262136.0)][1]} left in [4294+28j] for L = 2693 / 12588')
    print('     edges (L, PW, register, overflow):', [(l, p, hex(r), o) for (l, p, r, o) in edge if p >= 258996.0])


# ================================================================== S  the scheduler's record state
PHASE = [u32(ROM, 0x063E20 + 4 * j) for j in range(4)]          # 0, 360, 180, 540 deg (Q16.16)
HB = {0: u32(ROM, 0x063E0C), 1: u32(ROM, 0x063E1C)}              # handler B by MODE: 0x03E26E / 0x03E0BA
HA = {0: u32(ROM, 0x063E08), 1: u32(ROM, 0x063E18)}              # handler A by MODE: 0x03E168 / 0x03DFC8
A7E48, A7E51, A7E52, A7E55, A4167, A7D80 = F(0x7E48), F(0x7E51), F(0x7E52), F(0x7E55), F(0x4167), F(0x7D80)


def s32(v): return v - (1 << 32) if v & 0x80000000 else v


def dist(r4, r5):                   # 0x03DD80: r5 - r4, + 720<<16 unless > 0 (signed)
    v = (r5 - r4) & M32
    if not s32(v) > 0:
        v = (v + 0x02D00000) & M32
    return v


def tooth_angle(t):                 # 30 * (t, or t - 24 once when t >= 24) degrees, Q16.16
    t = t - 24 if t >= 24 else t
    return ((30 * t) << 16) & M32


def sched_emu(recs, glob, rets, rom=ROM):
    """An emulator holding four scheduler records, the 0xFFFF7E48 block and [429B + 28k], with logging
    stubs for every callee of 0x03D856 / 0x03DB16 / 0x03DD8E / 0x03DE6E that this pass does not run."""
    e = PEmu(rom)
    log = []
    for j, r in enumerate(recs):
        b = rec(j)
        for off in (0, 1, 2, 3, 6, 7, 12, 16, 17, 36):
            e.ram_u8(b + off, r.get(off, 0))
        e.ram_u16(b + 4, r.get(4, 0))
        e.ram_u32(b + 8, PHASE[j])
        for off in (20, 24, 28, 32):
            e.ram_u32(b + off, r.get(off, 0x1000 * (j + 1) + off))
        e.ram_u8(b + 37, 0)
        e.ram_u8(A429B + 28 * r.get(16, j), r.get('429B', 0))
    e.ram_u16(A7E48, glob.get('7E48', 0)); e.ram_u32(F(0x7E4C), 0)
    e.ram_u8(A7E51, glob.get('7E51', 0)); e.ram_u16(A7E52, glob.get('7E52', 0))
    e.ram_u8(A7E54, glob.get('7E54', 0)); e.ram_u8(A7E55, glob.get('7E55', 0))
    e.ram_u8(A726C, glob.get('726C', 0)); e.ram_u16(A7D80, glob.get('7D80', 0))
    e.ram_u8(A4167, glob.get('4167', 0))
    e.stub(0x03D582, fn=lambda em: log.append(('582', em.R[4])))
    e.stub(0x03D50E, fn=lambda em: log.append(('50E', em.R[4])))
    e.stub(0x009D48, fn=lambda em: log.append(('D48', em.R[4] & 0xFF)))
    for mode in (0, 1):
        e.stub(HB[mode], fn=lambda em, m=mode: (log.append(('B%d' % m, em.R[4], em.R[5])),
                                                em.R.__setitem__(0, rets[(em.R[4] - REC0) // 40])))
        e.stub(HA[mode], fn=lambda em, m=mode: log.append(('A%d' % m, em.R[4], em.R[5])))
    e.stub(0x03DB16, fn=lambda em: log.append(('DB16',)))
    e.stub(0x03DD8E, fn=lambda em: log.append(('DD8E', em.R[4], em.R[5] & 0xFF)))
    e.stub(0x03DE6E, fn=lambda em: log.append(('DE6E', em.R[4], em.R[5] & 0xFFFF)))
    return e, log


def rand_rec(j):
    return {0: random.choice([0, 1]), 1: random.choice([0, 1, 1, 2]), 2: random.choice([0, 0, 1, 1, 2]),
            3: random.choice([0, 1]), 6: random.choice([0, 1, 1, 2]), 7: random.choice([0, 1]), 12: j, 16: j,
            17: random.choice([0, 1, 1, 2]), 4: random.choice([0, 7, 0xFFFF]), '429B': random.choice([0, 0, 1])}


def m_03DB16(recs, glob, rets):
    """0x03DB16 model: returns (log, record byte expectations, globals)."""
    log, exp = [], []
    r10 = tooth_angle(glob['4167'])
    m = 0 if glob['726C'] == 1 else 2
    for j, r in enumerate(recs):
        x = {}
        b = rec(j)
        d = dist(r10, PHASE[j])
        x[7] = 0
        mode = ROM[0x063DFC + m]
        x[0] = mode
        x[1] = 1 if glob['7D80'] & (1 << r[12]) else 0
        x[3] = 0
        log += [('582', b), ('50E', b), ('D48', r[16])]
        x[17] = 0
        x[28] = r.get(32, 0x1000 * (j + 1) + 32)               # sub+12 := sub+16
        log.append(('B%d' % mode, b, d))
        x[2] = 0 if sx8(rets[j] & 0xFF) == 1 else 2
        exp.append(x)
    return log, exp, {'7E51': m, '7E52': glob['7D80']}


def m_03DE6E(recs, r9, mask, rets):
    log, exp = [], []
    for j, r in enumerate(recs):
        x = {}
        b = rec(j)
        bit = mask & (1 << r[12])
        if sx8(r[1]) == 1:
            if bit:
                exp.append(x); continue
            unsup = True
        else:
            if r[1] != 0 or not bit:
                exp.append(x); continue
            unsup = False
        d = dist(r9, PHASE[j])
        if s32(d) < 0:
            exp.append(x); continue
        r2 = sx8(r[2])
        if unsup:
            if r2 == 1:
                x[1] = 0
            elif r2 == 0:
                log.append(('B%d' % r[0], b, d))
                if sx8(rets[j] & 0xFF) == 1:
                    x[1] = 0
                else:
                    x[2] = 2
        else:
            if r2 == 1:
                s1 = sx8(r[17])
                okk = not ((s1 == 1 and r['429B'] == 0) or s1 == 2)
                if okk:
                    log.append(('D48', r[16]))
                    x[2] = 0
                    x[1] = 1
            elif r2 == 0:
                x[1] = 1
        exp.append(x)
    return log, exp


def m_03DD8E(recs, r9, newmode, rets):
    log, exp = [], []
    for j, r in enumerate(recs):
        x = {}
        b = rec(j)
        if sx8(r[0]) == sx8(newmode):
            exp.append(x); continue
        d = dist(r9, PHASE[j])
        if not s32(d) > s32(u32(ROM, 0x063E04 + 16 * newmode)):
            exp.append(x); continue
        r2 = sx8(r[2])
        if r2 == 1:
            log.append(('B%d' % r[0], b, d))
            if sx8(rets[j] & 0xFF) != 1:
                exp.append(x); continue
            s1 = sx8(r[17])
            if (s1 == 1 and r['429B'] == 0) or s1 == 2:
                exp.append(x); continue
            log.append(('D48', r[16]))
            x[17] = 0
            x[2] = 0
            x[0] = newmode
        elif r2 == 0:
            x[0] = newmode
        exp.append(x)
    return log, exp


def m_03D856(recs, glob, arg):
    """0x03D856 model with 0x03DB16 / 0x03DD8E / 0x03DE6E / 0x03D50E / 0x03D582 / handler A as logged no-ops."""
    log, exp = [], [dict() for _ in recs]
    g = dict(glob)
    step = arg - g['7E54']
    if step < 0:
        step += 24
    g['7E54'] = arg
    r10 = tooth_angle(arg)
    if step != 1:
        log.append(('DB16',))
    m = 0 if g['726C'] == 1 else 2
    if m != g['7E51']:
        log.append(('DD8E', r10, ROM[0x063DFC + m]))
        g['7E51'] = m
    if g['7D80'] != g['7E52']:
        log.append(('DE6E', r10, g['7D80']))
        g['7E52'] = g['7D80']
    for j, r0 in enumerate(recs):
        r = dict(r0)
        x = exp[j]
        b = rec(j)
        r1 = dist(r10, PHASE[j])
        if s32(r1) >= 0x02D00000:
            x[17] = r[17] = 0
            x[2] = r[2] = 0
            x[7] = r[7] = 0
            x[0] = r[0] = ROM[0x063DFC + g['7E51']]
            x[1] = r[1] = 1 if g['7E52'] & (1 << r[12]) else 0
            x[3] = r[3] = 0
        lim100, lim720 = u32(ROM, 0x063E04 + 16 * sx8(r[0])), u32(ROM, 0x063E00 + 16 * sx8(r[0]))
        if r[2] == 0:
            if r['429B'] != 0:
                continue
            if not s32(r1) > s32(lim100):
                x[2] = 2
                continue
            if s32(r1) > s32(lim720):
                continue
            if r[3] == 0:
                g['7E48'] = min(g['7E48'] + 1, 0xFFFF)
                x[4] = g['7E48']
                x[3] = 1
            if r[1] != 0:
                continue
            log.append(('50E', b))
            x[28] = r.get(32, 0x1000 * (j + 1) + 32)
            log.append(('582', b))
            log.append(('A%d' % sx8(r[0]), b, r1))
        elif sx8(r[2]) == 1:
            if r[1] != 0 or sx8(r[6]) != 1:
                continue
            log.append(('582', b))
            log.append(('A%d' % sx8(r[0]), b, r1))
    return log, exp, g


def check_recs(e, recs, exp, tag):
    for j, r in enumerate(recs):
        b = rec(j)
        for off in (0, 1, 2, 3, 6, 7, 17):
            want = exp[j].get(off, r.get(off, 0))
            ok(e.read_u8(b + off) == want, f'{tag} rec{j}+{off}: {e.read_u8(b + off)} vs {want}')
        ok(e.read_u16(b + 4) == exp[j].get(4, r.get(4, 0)), f'{tag} rec{j}+4')
        ok(e.read_u32(b + 28) == exp[j].get(28, r.get(28, 0x1000 * (j + 1) + 28)), f'{tag} rec{j}+28 (sub+12)')


def pass_S():
    # S1  0x03DB16: every record gets 0x03D582 and handler B, whatever its suppression byte
    n1 = 0
    sup_seen = 0
    for _ in range(150):
        recs = [rand_rec(j) for j in range(4)]
        glob = {'4167': random.randrange(48), '726C': random.choice([0, 1, 2]), '7D80': random.randrange(0x10000),
                '7E51': 7, '7E52': 0x5555}
        rets = [random.choice([0, 1, 0x101, 0xFF]) for _ in range(4)]
        e, log = sched_emu(recs, glob, rets)
        e.stubs.pop(0x03DB16)
        e.call(0x03DB16)
        cover(e, '0x03DB16')
        mlog, exp, g = m_03DB16(recs, glob, rets)
        ok(log == mlog, f'03DB16 calls {log} vs {mlog}')
        check_recs(e, recs, exp, '03DB16')
        ok(e.read_u8(A7E51) == g['7E51'] and e.read_u16(A7E52) == g['7E52'], '03DB16 7E51/7E52')
        sup_seen += sum(1 for x in exp if x[1] == 1)
        n1 += 1
    print(f'S1 0x03DB16: {n1} cases ({sup_seen} records with the suppression byte set): for EVERY record rec+0 := '
          f'0x063DFC[0x03D4F6()], rec+1 := bit rec+12 of u16 [7D80], then 0x03D582(rec), 0x03D50E(rec), 0x009D48(k), '
          f'sub+1 := 0, handler B = long 0x063E0C + 16*MODE ({HB[0]:#x} / {HB[1]:#x}) (rec, distance), rec+2 := 0 if it '
          f'returns 1 else 2')
    # S2  0x03DE6E: a changed [7D80] bit is applied at once, under conditions
    n2 = 0
    applied = 0
    for _ in range(400):
        recs = [rand_rec(j) for j in range(4)]
        rets = [random.choice([0, 1]) for _ in range(4)]
        mask = random.randrange(0x10)
        r9 = tooth_angle(random.randrange(24))
        e, log = sched_emu(recs, {}, rets)
        e.stubs.pop(0x03DE6E)
        e.call(0x03DE6E, regs={4: r9, 5: mask})
        cover(e, '0x03DE6E')
        mlog, exp = m_03DE6E(recs, r9, mask, rets)
        ok(log == mlog, f'03DE6E calls {log} vs {mlog}')
        check_recs(e, recs, exp, '03DE6E')
        applied += sum(1 for x in exp if 1 in x)
        n2 += 1
    print(f'S2 0x03DE6E: {n2} cases ({applied} immediate rec+1 changes): bit newly SET with rec+1 == 0 -> rec+1 = 1 '
          f'when rec+2 == 0, or rec+2 == 1 and the sub-record is not (state 1 with [429B+28k] == 0) and not state 2 '
          f'(then 0x009D48(k), rec+2 = 0); bit newly CLEAR with rec+1 == 1 -> rec+1 = 0 when rec+2 == 1, or rec+2 == 0 '
          f'and handler B returns 1 (else rec+2 = 2)')
    # S3  0x03DD8E: a changed MODE is applied at once, under conditions
    n3 = 0
    applied = 0
    for _ in range(400):
        recs = [rand_rec(j) for j in range(4)]
        rets = [random.choice([0, 1]) for _ in range(4)]
        newmode = random.choice([0, 1])
        r9 = tooth_angle(random.randrange(24))
        e, log = sched_emu(recs, {}, rets)
        e.stubs.pop(0x03DD8E)
        e.call(0x03DD8E, regs={4: r9, 5: newmode})
        cover(e, '0x03DD8E')
        mlog, exp = m_03DD8E(recs, r9, newmode, rets)
        ok(log == mlog, f'03DD8E calls {log} vs {mlog}')
        check_recs(e, recs, exp, '03DD8E')
        applied += sum(1 for x in exp if 0 in x)
        n3 += 1
    print(f'S3 0x03DD8E: {n3} cases ({applied} immediate MODE changes): a record whose rec+0 differs takes the new MODE '
          f'when its distance > [0x063E04 + 16*MODE] = 100 deg and rec+2 == 0, or rec+2 == 1, handler B of the OLD mode '
          f'returns 1 and the sub-record is not (state 1 with [429B+28k] == 0) and not state 2 (0x009D48(k), sub+1 = 0, '
          f'rec+2 = 0)')
    # S4  0x03D856 (callees as logged no-ops): re-arm, skips, refresh calls
    n4 = 0
    stats = {'rearm': 0, 'run': 0, 'db16': 0, 'dd8e': 0, 'de6e': 0}
    for _ in range(500):
        recs = [rand_rec(j) for j in range(4)]
        arg = random.randrange(48)
        prev = random.choice([(arg - 1) % 24, (arg - 1) % 24, random.randrange(24)])
        glob = {'7E48': random.choice([0, 5, 0xFFFF]), '7E51': random.choice([0, 2]), '7E52': random.choice([0, 3, 0xF]),
                '7E54': prev, '7E55': 0, '726C': random.choice([0, 1]), '7D80': random.choice([0, 3, 0xF])}
        rets = [0] * 4
        e, log = sched_emu(recs, glob, rets)
        e.call(0x03D856, regs={4: arg})
        cover(e, '0x03D856')
        mlog, exp, g = m_03D856(recs, glob, arg)
        ok(log == mlog, f'03D856 calls {log} vs {mlog} glob {glob} arg {arg}')
        check_recs(e, recs, exp, '03D856')
        ok(e.read_u8(A7E54) == arg and e.read_u16(A7E48) == g['7E48'], '03D856 7E54 / 7E48')
        ok(e.read_u8(A7E51) == g['7E51'] and e.read_u16(A7E52) == g['7E52'], '03D856 7E51 / 7E52')
        stats['rearm'] += sum(1 for x in exp if 0 in x and 7 in x)
        stats['run'] += sum(1 for c in log if c[0] in ('A0', 'A1'))
        stats['db16'] += ('DB16',) in log
        stats['dd8e'] += any(c[0] == 'DD8E' for c in log)
        stats['de6e'] += any(c[0] == 'DE6E' for c in log)
        n4 += 1
    print(f'S4 0x03D856: {n4} cases {stats}: per record, re-arm (rec+0/+1/+2/+3/+7, sub+1 refreshed) only when '
          f'0x03DD80 gives >= 720<<16 (tooth angle == record phase); rec+2 == 0: skip while [429B+28k] != 0, '
          f'rec+2 := 2 when distance <= 100 deg, skip if suppressed AFTER the [7E48] count; rec+2 == 1: needs rec+1 == 0 '
          f'and rec+6 == 1; 0x03DB16 when the tooth step != 1; 0x03DD8E / 0x03DE6E when [726C]-mode / [7D80] changed')
    # S5  0x03E0FA reads the calibration long 0x0CBDB4 and [4280], never [42F4]
    for s8 in (4000, 1048544):
        for p4158 in (0x10000, 0x400000):
            e = PEmu()
            sub = rec(1) + 16
            e.ram_u8(sub, 1); e.ram_u32(sub + 8, s8); e.ram_u32(sub + 12, 0x00500000)
            e.ram_u32(A4280, 3225); e.ram_u32(A4158, p4158)
            e.ram_u32(A42F4, 0x11111111)
            e.call(0x03E0FA, regs={4: sub})
            cover(e, '0x03E0FA')
            q = q16div((s8 + u32(ROM, 0x0CBDB4) + 3225) & M32, p4158)
            ok(e.R[0] == (180 * q + 0x00500000) & M32, '03E0FA')
            e2 = PEmu()                     # [42F4] left uninitialised: a read of it would be recorded
            e2.ram_u8(sub, 1); e2.ram_u32(sub + 8, s8); e2.ram_u32(sub + 12, 0x00500000)
            e2.ram_u32(A4280, 3225); e2.ram_u32(A4158, p4158)
            e2.call(0x03E0FA, regs={4: sub})
            ok(e2.R[0] == e.R[0], '03E0FA independent of [42F4]')
            ok(not any(A42F4 <= a < A42F4 + 4 for a in e2.uninit_reads), '03E0FA never reads [42F4]')
    print('S5 0x03E0FA: r0 = sub+12 + 180 * 0x0BE654(sub+8 + long [0x0CBDB4] + [4280], [4158]); result unchanged when '
          '[42F4] is varied (it reads the calibration long directly, via 0x03D634)')


# ================================================================== T  0x037E70 / 0x037B74 whole: S4
def pass_T():
    A7AB4, A7AC0, A7AC4, A7AC8 = F(0x7AB4), F(0x7AC0), F(0x7AC4), F(0x7AC8)
    c2c, c30 = u32(ROM, 0x0CC32C), u32(ROM, 0x0CC330)
    for rom in (ROM, ROM_STOCK, ROM_E):
        ok(u32(rom, 0x0CC32C) == 0 and u32(rom, 0x0CC330) == 0, '0x0CC32C / 0x0CC330 = 0.0 in all bins')
        ok(rom[0x0CCE68:0x0CCE78] == bytes(16) and rom[0x0CCE58:0x0CCE68] == bytes(16), 'AC648 / AC634 data zero')
    n = 0
    seen = set()
    for b7AD0 in (0, 1, 2):
        for b7ADC in (0, 1, 2):
            for b7AD1 in (0, 1):
                for b7AD3 in (0, 1):
                    for b7AD2 in (0, 1, 2):
                        for old in (0.0, 0.25, 1.0, 1.5, -2.0, math.inf, -math.inf, math.nan):
                            e = PEmu()
                            for a, v in ((F(0x7AD0), b7AD0), (F(0x7ADC), b7ADC), (F(0x7AD1), b7AD1), (F(0x7AD3), b7AD3),
                                         (F(0x7AD2), b7AD2)):
                                e.ram_u8(a, v)
                            e.ram_f32(A7AC0, old)
                            e.call(0x037E70)
                            cover(e, '0x037E70')
                            ob = f2b(old)
                            if b7AD0 == 1:
                                want, path = ZERO, 'zero'
                            elif b7ADC == 1:
                                if (b7AD1 == 1 and b7AD0 == 0) or (b7AD3 == 1 and b7AD2 == 0):
                                    want, path = ONE, 'one'
                                else:
                                    s = fadd(ob, c2c)
                                    want, path = (s if gt(ONE, s) else ONE), 'min'
                            else:
                                if b7AD3 == 1 and b7AD2 == 0:
                                    want, path = ZERO, 'zero'
                                else:
                                    s = fsub(ob, c30)
                                    want, path = (s if gt(s, ZERO) else ZERO), 'max'
                            seen.add(path)
                            ok(e.read_u32(A7AC0) == want, f'037E70 {path} old={old}: {e.read_u32(A7AC0):#x} vs {want:#x}')
                            ok(nonstack(e) == cells((A7AC0, 4)), '037E70 write set')
                            n += 1
    ok(seen == {'zero', 'one', 'min', 'max'}, 'all four paths of 0x037E70')
    print(f'T  0x037E70: {n} cases; [7AC0] := 0.0 / 1.0 / min([7AC0] + [0x0CC32C], 1.0) / max([7AC0] - [0x0CC330], 0.0);'
          f' both steps are 0.0 in all three bins, so it HOLDS (a NaN becomes 1.0 or 0.0; +inf survives the max path,'
          f' -inf the min path); its only writer found')
    # 0x037B74 run whole: [7AC4] = T(AC634, [6624]) and [7AC8] = T(AC648, [6350]) are 0.0; S4 = 1.0 unless [7AC0] = inf
    m = 0
    for rpm in (0.0, 800.0, 3000.0, 6500.0, 9999.0):
        for ect in (-40.0, 0.0, 40.0, 90.0, 130.0):
            for old7AC0, b7ADC in ((0.0, 1), (1.0, 0), (0.5, 0), (math.inf, 0), (math.inf, 1), (math.nan, 0)):
                e = PEmu()
                e.ram_u8(A726C, 0); e.ram_u8(F(0x7C68), 0)
                e.ram_f32(A6624, rpm); e.ram_f32(F(0x6350), ect)
                e.stub(0x0297C0, r0=0); e.stub(0x0297A0, r0=0); e.stub(0x0297B0, r0=0); e.stub(0x0299EC, r0=0)
                e.stub(0x037DD2)
                for a, v in ((F(0x7ADC), b7ADC), (F(0x7AD1), 0), (F(0x7AD3), 0), (A7ADD, 2), (A7ADE, 2)):
                    e.ram_u8(a, v)
                e.ram_f32(A7AC0, old7AC0); e.ram_f32(A7320, 3000.0); e.ram_f32(A7AB8, 0.0)
                e.call(0x037B74)
                cover(e, '0x037B74')
                ok(e.read_u32(A7AC4) in (0, 0x80000000) and e.read_u32(A7AC8) in (0, 0x80000000), '7AC4 / 7AC8 zero')
                ok(e.read_u32(F(0x7ABC)) in (0, 0x80000000), '7ABC zero')
                v7AC0 = b2f(e.read_u32(A7AC0))
                want = K05 if math.isinf(v7AC0) else ONE
                ok(e.read_u32(A7AB4) == want, f'037B74 S4 rpm={rpm} ect={ect} 7AC0={old7AC0}->{v7AC0}')
                m += 1
    print(f'   0x037B74 run whole ({m} cases; 0x0297C0/A0/B0, 0x0299EC, 0x037DD2 stubbed): [7AC4] = [7AC8] = [7ABC] = 0.0'
          f' at every [6624] / [6350]; S4 = [7AB4] = 1.0, except 0.5 when [7AC0] holds +inf (0 * inf = NaN, clamp -> lo)')


# ================================================================== U  initialisers on the path
def pass_U():
    # 0x02F83E (reached at init: 0x00DF14 -> 0x047C40 at 047F04 -> 0x02EF08 -> bra 0x02F85E -> bsr 0x02F83E at 02F888)
    e = PEmu()
    e.stub(0x02F22A)
    for a in (A726C, A72D1, F(0x72C8)) + tuple(A726F):
        e.ram_u8(a, 0x5A)
    e.call(0x02F83E)
    cover(e, '0x02F83E')
    ok(e.read_u8(A726C) == 1 and e.read_u8(F(0x72C8)) == 1 and all(e.read_u8(a) == 1 for a in A726F), '02F83E ones')
    ok(e.read_u8(A72D1) == 0, '02F83E clears the [72D1] latch')
    ok(nonstack(e) == cells((A726C, 1), (F(0x72C8), 1), (A72D1, 1), (A726F[0], 4)), '02F83E write set')
    # 0x009860 (called by 0x00DF14 at 00DFFE, before 0x047C40 at 00E10A)
    e = PEmu()
    calls = []
    e.stub(0x00E6E4, fn=lambda em: calls.append((em.R[4], em.R[5] & 0xFFFF, em.R[6])))
    e.stub(0x0BE81C); e.stub(0x0BE82C)
    e.mmio(0xFFFFF459, 0xFF); e.mmio(0xFFFFF458, 0xFF)
    for k in range(4):
        e.mmio(P_WID[k], 0x1234)
    e.ram_u32(A4280, 12588); e.ram_u32(A42F4, 30800)
    e.call(0x009860)
    cover(e, '0x009860')
    wid = [(a, v) for (a, nb, v) in e.mmio_writes if a in P_WID]
    ok(wid == [(P_WID[k], 0) for k in range(4) for _ in (0, 1)], f'009860 width writes {wid}')
    ok(e.read_u32(A4280) == 0 and e.read_u32(A42F4) == 0, '009860 zeroes [4280] and [42F4]')
    ok(all(e.read_u8(A4284 + 28 * k + 23) == 0 and e.read_u8(A4284 + 28 * k + 24) == 0 for k in range(4)),
       '009860 drec bytes +23 / +24')
    ok(calls[:4] == [(P_F66C, 1 << k, 0) for k in range(4)], f'009860 0x00E6E4 calls {calls}')
    print('U  0x02F83E: bytes [726C] [72C8] [726F..7272] := 1, latch [72D1] := 0 (its caller chain from the init routine'
          ' 0x00DF14 is by bytes); 0x009860: width registers 0xFFFFF640+2k := 0 (twice each, via 0x011848), [4280] := 0,'
          ' [42F4] := 0, drec bytes +23 / +24 := 0 -- before 0x047C40 writes the latency and 30800')


# ================================================================== V  independent audit (inputs no earlier pass used)
def run_02EFD2(state):
    e = PEmu()
    for a, v in state.items():
        if a in (A726C, A7306, A90C1, A3158, A72D1) or a in A726F:
            e.ram_u8(a, v)
        else:
            e.ram_u32(a, v)
    e.call(0x02EFD2)
    cover(e, '0x02EFD2')
    return e


def m_0345A4_body2(S):
    """0x034644.. entered by fall-through with r4 = 0x063A5C, r5 = 0: byte @long[0x063A5C] = [7883]."""
    ok_ = (S['7448'] == 1 and S['78A7'] >= ROM[0x0CBBE4] and S['A56A'] == 0 and S['ACE6'] == 0 and S['94B1'] == 0
           and S['7453'] == 1 and S['78A8'] >= ROM[0x0CBBE5] and gt(S['7324'], S['733C']) and S['78A3'] == 1)
    return 1 if ok_ else 0


def pass_V():
    n = 0
    # V1  0x02EFD2: on the FLOOR path every channel is compared with [728C], released (flag 0) or not
    refl = 0
    for _ in range(200):
        fl = [random.choice([0, 1]) for _ in range(4)]
        if 1 not in fl:
            fl[random.randrange(4)] = 1
        S = {A726C: 0, A7306: 0, A90C1: random.choice([0, 1]), A3158: random.choice([0, 1]), A72D1: random.choice([0, 1]),
             A6354: f2b(random.choice([-40.0, 20.0, 90.0])), A728C: f2b(random.uniform(500.0, 9000.0)), A72DC: 0}
        for j in range(4):
            S[A726F[j]] = fl[j]
            S[A7328[j]] = f2b(random.uniform(300.0, 9000.0))
        e = run_02EFD2(S)
        fl_ = e.read_u32(A728C)
        for j in range(4):
            own = S[A7328[j]]
            want = own if gt(own, fl_) else fl_
            ok(e.read_u32(A7290[j]) == want, 'V1 every channel floored while any flag is 1')
            if fl[j] == 0 and not gt(own, fl_):
                refl += 1
                ok(e.read_u32(A7290[j]) == fl_ and e.read_u8(A726F[j]) == 0, 'V1 released channel floored again')
        n += 1
    ok(refl > 0, 'V1 re-floor case exercised')
    # the deterministic row quoted in the trace
    S = {A726C: 0, A7306: 0, A90C1: 0, A3158: 0, A72D1: 0, A6354: f2b(90.0), A728C: f2b(5000.0), A72DC: 0}
    for j, (f, p) in enumerate(zip((0, 1, 1, 1), (1000.0, 6000.0, 6000.0, 6000.0))):
        S[A726F[j]] = f
        S[A7328[j]] = f2b(p)
    e = run_02EFD2(S)
    row = (b2f(e.read_u32(A728C)), [b2f(e.read_u32(a)) for a in A7290], [e.read_u8(a) for a in A726F])
    ok(row[1][0] == row[0] and row[1][1:] == [6000.0] * 3 and row[2] == [0, 0, 0, 0], f'V1 row {row}')
    for j in range(4):
        S[A726F[j]] = 0
    e = run_02EFD2(S)
    ok(b2f(e.read_u32(A7290[0])) == 1000.0, 'V1 with all flags 0 the same pulse is copied')
    # V2  0x02EF0C (task-9 runner 0x04907C at 0491B0): 0x02F83E runs when byte [65F6] == 1
    ok(u32(ROM, 0x0493D0) == 0x0002EF0C and u16(ROM, 0x0491AE) == 0xD288 and u16(ROM, 0x0491B0) == 0x420B,
       'V2 0x04907C calls 0x02EF0C at 0491B0')
    from sh2e_disasm import decode
    br = [pc for pc in range(0x0490E8, 0x0491B2, 2)
          if decode(u16(ROM, pc), pc)[0].split()[0] in ('bt', 'bf', 'bt/s', 'bf/s', 'bra', 'braf', 'jmp', 'rts', 'rte')]
    ok(br == [] and u16(ROM, 0x04908E) == 0x892B, 'V2 0490E8 ([8EDC] == 0) runs straight to 0491B0')
    hit = []
    for v in range(256):
        e = PEmu()
        e.stub(0x02F22A); e.stub(0x02F57E); e.stub(0x02F6E0)
        e.ram_u8(F(0x65F6), v)
        for a in (A726C, A72D1, F(0x72C8)) + tuple(A726F):
            e.ram_u8(a, 0x5A)
        e.call(0x02EF0C)
        cover(e, '0x02EF0C')
        if v == 1:
            ok(e.read_u8(A726C) == 1 and e.read_u8(F(0x72C8)) == 1 and e.read_u8(A72D1) == 0
               and all(e.read_u8(a) == 1 for a in A726F), 'V2 [65F6] == 1 -> 0x02F83E')
            ok(nonstack(e) == cells((A726C, 1), (F(0x72C8), 1), (A72D1, 1), (A726F[0], 4)), 'V2 write set')
            hit.append(v)
        else:
            ok(nonstack(e) == set(), f'V2 [65F6] = {v}: nothing written')
        n += 1
    ok(hit == [1], 'V2 only 1')
    # V3  0x0345A4 second body: byte [7883] needs [7324] > [733C] (034756 F695: T = fr6 > fr9), strict, NaN fails
    ok(u32(ROM, 0x063A5C) == 0xFFFF7883 and u32(ROM, 0x063A60) == 0xFFFF78A7 and u32(ROM, 0x063A64) == 0xFFFF78A8,
       'V3 pointer table 0x063A5C')
    up = f2b(300.0) + 1
    pairs = [(f2b(300.0), f2b(300.0)), (up, f2b(300.0)), (f2b(299.0), f2b(300.0)), (f2b(5000.0), f2b(300.0)),
             (f2b(math.nan), f2b(300.0)), (0, 0), (f2b(1e-30), 0), (f2b(-1.0), 0), (f2b(math.inf), f2b(300.0))]
    for p7324, p733C in pairs:
        for tog in [None, '7448', '78A7', 'A56A', 'ACE6', '94B1', '7453', '78A8', '78A3']:
            S = {'7448': 1, '78A7': 0x80, 'A56A': 0, 'ACE6': 0, '94B1': 0, '7453': 1, '78A8': 0xFF, '78A3': 1,
                 '7324': p7324, '733C': p733C}
            if tog:
                S[tog] = {'7448': 2, '78A7': 0x7F, 'A56A': 1, 'ACE6': 0x80, '94B1': 1, '7453': 0, '78A8': 0x7F,
                          '78A3': 0x81}[tog]
            e = PEmu()
            e.stub(0x029BA4)
            for k in ('7448', '78A7', 'A56A', 'ACE6', '94B1', '7453', '78A8', '78A3'):
                e.ram_u8(F(int(k, 16)), S[k])
            e.ram_u32(A7324, S['7324']); e.ram_u32(F(0x733C), S['733C']); e.ram_u8(F(0x7883), 0x5A)
            e.call(0x034644, regs={4: 0x063A5C, 5: 0})
            cover(e, '0x0345A4b2')
            ok(e.read_u8(F(0x7883)) == m_0345A4_body2(S), f'V3 [7883] {S}')
            ok(nonstack(e) == {F(0x7883)}, 'V3 write set')
            n += 1
    # V4  0x03CD00 (caller 0x047C40): the initial values of 0x03D0B8's cells
    for v in (0, 1, 2):
        e = PEmu()
        e.ram_u8(F(0x65F6), v)
        e.call(0x03CD00)
        cover(e, '0x03CD00')
        ok(all(e.read_u32(a) == ONE for a in A7D58) and e.read_u32(F(0x7D70)) == u32(ROM, 0x0CC56C)
           and e.read_u16(F(0x7D74)) == 0xFFFF and e.read_u8(F(0x7D7D)) == (1 if v == 1 else 0), 'V4 0x03CD00')
        ok(nonstack(e) == cells((A7D58[0], 16), (F(0x7D70), 6), (F(0x7D7D), 1)), 'V4 write set')
        n += 1
    # V6  0x02FF8E (called at 02FF7E, just before 0x0301E4): [733C] = 0.0 iff byte [641C] == 1, else [0x0CBE08]
    ok(b2f(u32(ROM, 0x0CBE08)) == 300.0, 'V6 0x0CBE08 = 300.0')
    for v in range(256):
        e = PEmu()
        e.ram_u8(F(0x641C), v)
        e.call(0x02FF8E)
        cover(e, '0x02FF8E')
        ok(e.read_u32(F(0x733C)) == (0 if v == 1 else f2b(300.0)) and nonstack(e) == cells((F(0x733C), 4)), 'V6')
        n += 1
    # V5  two 0x04AA58-order passes, every function REAL: 0x0301E4, then 0x038DC0 and 0x0397AC on its outputs,
    #     0x0301E4 again (so trims and F come from the previous pass), 0x02EFD2 COPY, the driver chain.
    #     Small pulses: F != 1 (rpm < 4000, [7344] < 600) and the [733C] = 300 clamp; rpm = 4000 exactly -> F = 1.
    fseen, clamped = set(), 0
    for _ in range(60):
        e = PEmu()
        rpm = random.choice([700.0, 800.0, 1500.0, 2500.0, 3999.0, 4000.0, 5000.0])
        lo = random.choice([0.0, 300.0])
        ins = {0xFFFF7348: random.uniform(150.0, 1200.0), 0xFFFF7AB4: 1.0, 0xFFFF73A4: 0.0, 0xFFFF7A08: 0.0,
               0xFFFF76D4: random.uniform(0.9, 1.1), 0xFFFF7878: random.uniform(-0.05, 0.05), 0xFFFF7AE4: 0.0,
               0xFFFF730C: random.uniform(0.2, 1.2), 0xFFFF733C: lo, 0xFFFF6624: rpm, 0xFFFF7BC4: 1.0}
        for i in range(4):
            ins[0xFFFF7310 + 4 * i] = random.uniform(0.2, 1.2)
            ins[0xFFFF7B6C + 4 * i] = 1.0
        for a, v in ins.items():
            e.ram_f32(a, v)
        e.call(0x0301E4)
        p1_7324, p1_7344 = e.read_u32(A7324), e.read_u32(A7344)
        e.call(0x038DC0); e.call(0x0397AC)
        cover(e, '0x038DC0'); cover(e, '0x0397AC')
        trims = [e.read_u32(a) for a in A7B6C]
        Fv = e.read_u32(A7BC4)
        e.call(0x0301E4)
        for a in (A726C, A7306, A90C1, A3158, A72D1):
            e.ram_u8(a, 0)
        for jj in range(4):
            e.ram_u8(A726F[jj], 0)
        e.ram_f32(A6354, 90.0); e.ram_f32(A728C, 0.0); e.ram_f32(A72DC, 0.0)
        e.call(0x02EFD2)
        j = random.randrange(4)
        lat = random.choice([2693, 6857, 12588])
        cnt, base = chain_from_7290(e, j, lat)
        exp_tr = [lut2(d, p1_7324, f2b(rpm)) for d in (0x0AD738, 0x0AD754, 0x0AD770, 0x0AD78C)]
        expF = clamp(lut1(0x0AC760, p1_7344), K05, K15) if (gt(f2b(4000.0), f2b(rpm)) and gt(f2b(600.0), p1_7344)) else ONE
        C = fmul(fadd(fadd(f2b(ins[0xFFFF76D4]), f2b(ins[0xFFFF7878])), ZERO), f2b(ins[0xFFFF7348]))
        x = fmac(fmul(f2b(ins[0xFFFF7310 + 4 * j]), fmul(ONE, C)), exp_tr[j], ZERO)
        pw = clamp(fmul(x, expF), f2b(lo), f2b(262136.0))
        ok(trims == exp_tr and Fv == expF, 'V5 trims and F from the previous pass outputs')
        ok(e.read_u32(A7290[j]) == pw, 'V5 PW')
        check_chain(e, j, pw, cnt, base, lat, 0x0100, 0x1000, 0x10000, 'V5')
        fseen.add(Fv != ONE)
        clamped += pw == f2b(lo)
        n += 1
    ok(fseen == {True, False}, 'V5 F != 1 and F == 1 both exercised')
    print(f'V  audit: {n} cases.  V1 0x02EFD2 FLOOR path: every channel gets [7328+4j] if > [728C] else [728C], flag 0 or'
          f' not ({refl} released channels floored again; row flags (0,1,1,1), pulses 1000/6000 x3, [728C] 5000 at'
          f' 90 deg -> PW_0 = {row[0]:.5f}); V2 0x02EF0C (from task-9 runner 0x04907C at 0491B0, straight line from'
          f' 0490E8 when byte [8EDC] == 0): 0x02F83E runs only for byte [65F6] == 1 (all 256 values); V3 0x0345A4'
          f' second body: byte [7883] = 1 only if all nine terms hold, incl. [7324] > [733C] strict (equal -> 0, one ulp'
          f' above -> 1, NaN -> 0); V4 0x03CD00: [7D58..7D64] := 1.0; V6 0x02FF8E: [733C] = 0.0 iff byte [641C] == 1,'
          f' else 300.0; V5 two real passes: trims and F from the previous pass, F != 1 and the [733C] clamp'
          f' ({clamped} clamped) through to the register')


# ================================================================== Q  bins + coverage
FUNCS = {'0x02F83E': (0x02F83E, 0x02F85E), '0x009860': (0x009860, 0x00993C), '0x03DB16': (0x03DB16, 0x03DBF4), '0x03DE6E': (0x03DE6E, 0x03DFBE), '0x03DD8E': (0x03DD8E, 0x03DE6E),
         '0x03D856': (0x03D856, 0x03DB16), '0x037E70': (0x037E70, 0x037F00), '0x03E0FA': (0x03E0FA, 0x03E13A),
         '0x037B74': (0x037B74, 0x037C52),
         '0x02EFD2': (0x02EFD2, 0x02F22A), '0x038DC0': (0x038DC0, 0x038E10), '0x0397AC': (0x0397AC, 0x0397F6),
         '0x037D74': (0x037D74, 0x037DD2), '0x04BDAA': (0x04BDAA, 0x04BF56), '0x03D0B8': (0x03D0B8, 0x03D21A),
         '0x03D582': (0x03D582, 0x03D634), '0x03D648': (0x03D648, 0x03D68C), '0x03D68C': (0x03D68C, 0x03D698),
         '0x0303C0': (0x0303C0, 0x030408), '0x05D478': (0x05D478, 0x05D48E), '0x03D4F6': (0x03D4F6, 0x03D50E),
         '0x00A4E0+0x011848': (0x00A4E0, 0x00A55E), '0x009F72': (0x009F72, 0x00A1A6),
         '0x009B2C': (0x009B2C, 0x009BFC), '0x03DFC8': (0x03DFC8, 0x03E0BA),
         '0x02EF0C': (0x02EF0C, 0x02EF26), '0x03CD00': (0x03CD00, 0x03CD34), '0x02FF8E': (0x02FF8E, 0x02FFA2)}
EXTRA_CODE = [(0x011848, 0x011874), (0x02F8EA, 0x02F8F4), (0x009E44, 0x009E50), (0x03D640, 0x03D648),
              (0x03D708, 0x03D7F0), (0x00A55E, 0x00A586), (0x02F9E0, 0x02FA24), (0x07D620, 0x07D9F8),
              (0x03DD4E, 0x03DD80), (0x03DCB6, 0x03DD32), (0x03DC46, 0x03DCB6),
              (0x009EA0, 0x009F1C), (0x03D634, 0x03D640), (0x02F85E, 0x02F8A6),
              (0x03DD80, 0x03DD8E), (0x03D4F0, 0x03D4F6), (0x037DD2, 0x037E70), (0x02EF56, 0x02EFD2),
              # audit: run REAL in passes R / V, or read for the audit findings
              (0x0301E4, 0x030378), (0x02FF7C, 0x0301E4), (0x0345A4, 0x034778), (0x03452A, 0x034592),
              (0x03CD34, 0x03CD4A), (0x03CF42, 0x03CF56), (0x022F92, 0x022F9C), (0x049086, 0x0491B4)]
CAL = [(0x0CC3FC, 8), (0x0CC53C, 12), (0x0D6010, 1), (0x0D6020, 16), (0x0CBDB4, 8), (0x0CC2F0, 4),
       (0x063DC8, 0xB0), (0x011A7C, 48), (0x0CBE0C, 4), (0x0CC32C, 8),
       (0x0CBE08, 4), (0x063A5C, 12), (0x0CBBE4, 2), (0x0CC56C, 4)]
DESCS = [0x0AD738, 0x0AD754, 0x0AD770, 0x0AD78C, 0x0AC760, 0x0AD71C, 0x0AE774, 0x0AE788, 0x0AD7E0,
         0x0AC840, 0x0AC890, 0x0AC854, 0x0AC8A4, 0x0AC818, 0x0AC868, 0x0AC82C, 0x0AC87C, 0x0AC634, 0x0AC648]


def desc_extent(rom, d):
    t = T.read_table(rom, d)
    out = [(d, 28 if t['dim'] == '2D' else 20)]
    if t['dim'] == '2D':
        na, nb = u16(rom, d), u16(rom, d + 2)
        w = T.TYPE_SIZES[t['typecode']] if hasattr(T, 'TYPE_SIZES') else 4
        out += [(u32(rom, d + 4), 4 * na), (u32(rom, d + 8), 4 * nb), (u32(rom, d + 12), w * na * nb)]
    else:
        na = u16(rom, d)
        w = T.TYPE_SIZES[t['typecode']] if hasattr(T, 'TYPE_SIZES') else 4
        out += [(u32(rom, d + 4), 4 * na), (u32(rom, d + 8), w * na)]
    return out


def pass_Q():
    ranges = [v for v in FUNCS.values()] + EXTRA_CODE + CAL
    for d in DESCS:
        ranges += desc_extent(ROM, d)
    diffs = {'stock': 0, '20.19e': 0}
    total = 0
    for lo, hi_or_n in ranges:
        hi = hi_or_n if hi_or_n > lo else lo + hi_or_n
        for a in range(lo, hi):
            total += 1
            if ROM_STOCK[a] != ROM[a]:
                diffs['stock'] += 1
            if ROM_E[a] != ROM[a]:
                diffs['20.19e'] += 1
    ok(diffs == {'stock': 0, '20.19e': 0}, f'bins differ: {diffs}')
    print(f'Q  {total} bytes (code of {len(FUNCS) + len(EXTRA_CODE)} functions, calibration scalars, ROM tables,'
          f' {len(DESCS)} descriptors with axes and data): identical in stock / 20.19c / 20.19e')
    cens = {}
    import json
    with open(os.path.join(REPO, 'disassembly', 'maps', 'function_census.json')) as fh:
        for fn in json.load(fh)['functions']:
            cens[int(fn['entry'], 16)] = fn['insns']
    for name, (lo, hi) in FUNCS.items():
        ex = {a for a in COVER.get(name, set()) if lo <= a < hi}
        if name.startswith('0x00A4E0'):
            ex |= {a for a in COVER.get(name, set()) if 0x011848 <= a < 0x011874}
            tot = cens[0x00A4E0] + cens[0x011848]
        else:
            tot = cens[lo]
        print(f'     coverage {name}: {len(ex)} of {tot} instructions executed')


def main():
    pass_A(); pass_B(); pass_C(); pass_D(); pass_E(); pass_F(); pass_G(); pass_H()
    pass_J(); pass_K(); pass_M(); pass_N(); pass_N2(); pass_O(); pass_P(); pass_R(); pass_S(); pass_T(); pass_U()
    pass_V(); pass_Q()
    print(f'ALL PASSES OK -- {CHECKS[0]} assertions')
    return 0


if __name__ == '__main__':
    sys.exit(main())
