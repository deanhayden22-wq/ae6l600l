#!/usr/bin/env python3
"""emu_hole9_identity.py -- emulation evidence for disassembly/analysis/hole9_identity_trace.txt

Open-hole #9 follow-up: what 0xFFFF77BC / 0xFFFF77C8 are, what feeds them, and
which sign of the disabled trim 0xFFFF7904 is richer.

    python3 scripts/trace/emu_hole9_identity.py          # prints tables, asserts, exit 0

Reference image: rom/AE5L600L 20g rev 20.19c.bin (md5 92cae8275cd4f9b473a3a9e36efe6449).
Deterministic (fixed seed). Every section runs ROM code in scripts/sh2e_emu.py and
compares the result with a MODEL written in this file from the byte reading in the
analysis file. Float models round every arithmetic step TOWARD ZERO, as the
emulator does (FPSCR.RM = 01, corrections item 106); comparisons are BIT-EXACT
unless a tolerance is stated. Tolerances appear only where a model is compared with
an independent oracle (definition-XML display values, plain interpolation).

  A  0x0299F0 and 0x022F92 (the two byte predicates 0x033460 / 0x0332A2 call)
  B  0x033460: the factor formula (B1 random, B1b unclamped, B7 summation order), every branch (B2),
     SPECIAL (B3), STEP (B4, B8 inverted clamp), the [7BDC] x S clamp sweep against the closed-form
     range (B5), NaN (B6)
  C  0x0332A2: the [0xFFFF65F6] == 1 reset and its write set
  D  0x033658: the hand-over offset [0xFFFF77CC] = [0xFFFF6540] - [0xFFFF77C8]
  E  0x033186 / 0x03A196: the two consumers that divide by [0xFFFF77C8]
  F  addend writers: 0x0339E4 (77D4), 0x033CC0 (77DC), 0x033F9E (77F8),
     0x03439E (781C), 0x0343CE (7820) -- including the definition-XML oracle
     for the two tables that set the SIGN convention
  G  0x058902 / 0x021A3C: [0xFFFF8DE4] and [0xFFFF653C] / [0xFFFF6540] against
     the definition tables "Front Oxygen Sensor Scaling" and "... Compensation
     (Atm. Pressure)"
  H  the sign demonstration: +/- [0xFFFF7904] through 0x033460 in AFR terms, at the [7BDC]
     values 0x0399EE / 0x039D1C can store (1.05, 0.95, 0.8499756), and the SPECIAL exit's
     independence from [7904]
  I  0x0040D4: [0xFFFF4050] is the word read at peripheral 0xFFFFF834
  J  0x039F42 / 0x039E20: every live path that writes [0xFFFF7BE4]; never < 0; the
     0x03A196 clamp path is not executed ([0x0CBC06] = 0x01; counterfactual with 0x00)
  K  0x0399EE / 0x039D1C: every write of [0xFFFF7BDC] is bounded by [0x0CBF40] = 1.05; floor
     0x3F599800 (table 0x0AD348) is below [0x0CBF3C]
  L  0x021D7C (second writer of [6540]), 0x0342A8 ([7814]/[7818]), 0x0043EE ([4090] only when
     byte [40AD] == 12), the 0x021A3C byte gate [0x0C0354] (counterfactual with 0xFF)
  M  AUDIT (independent pass): 0x0340A0, the writer of [7810] (M1) and its effect on the SPECIAL
     exit (M2); the reachable range of [6540] in 20.19c and stock (M3) and of [77C8] (M4); the
     0x033658 / 0x0342A8 captures at their worst case (M5); stock vs 20.19c over every table and
     cal range read (M6, also reads rom/ae5l600l.bin); byte [7BEC] cleared by 0x039E6E (M7)

Stubs (stated, because a stub is an assumption):
  0x0BE81C / 0x0BE82C   interrupt-mask enter/leave (emulator raises on ldc sr); r0 = 0
  0x022CF4, 0x02F8EA, 0x0582AC, 0x02BE2C, 0x023E48   unread predicates; r0 chosen per case
Counterfactual ROM copies (J, L, M7) patch one cal value in memory to show a gate's sense
(M5 uses a counterfactual RAM value instead); the reference image itself is never modified.
"""
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
import desc_types as T        # noqa: E402
import defs as DEFS           # noqa: E402

ROM_PATH = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
ROM = open(ROM_PATH, 'rb').read()
RNG = random.Random(20261127)
FLT_MAX = struct.unpack('>f', bytes.fromhex('7F7FFFFF'))[0]
NCHECK = 0


def check(cond, msg):
    global NCHECK
    NCHECK += 1
    if not cond:
        raise AssertionError(msg)


def f32(x):
    return E.b2f(E.f2b(x))


def bits(x):
    return E.f2b(x)


def calf(a):
    return struct.unpack('>f', ROM[a:a + 4])[0]


def calw(a):
    return struct.unpack('>H', ROM[a:a + 2])[0]


# ---------------------------------------------------------------- float32 RZ model
def _rz(q, fallback):
    if q == 0:
        return fallback
    return E.b2f(E.rz_bits(q))


def fadd(a, b):
    if not (math.isfinite(a) and math.isfinite(b)):
        return a + b
    return _rz(Fraction(a) + Fraction(b), a + b)


def fsub(a, b):
    return fadd(a, -b)


def fmul(a, b):
    if not (math.isfinite(a) and math.isfinite(b)):
        return a * b
    return _rz(Fraction(a) * Fraction(b), a * b)


def fdiv(a, b):
    return _rz(Fraction(a) / Fraction(b), a / b)


def m_min(fr4, fr5):            # 0x0BE970: fr5 > fr4 ? fr4 : fr5
    return fr4 if fr5 > fr4 else fr5


def m_max(fr4, fr5):            # 0x0BE960: fr4 > fr5 ? fr4 : fr5
    return fr4 if fr4 > fr5 else fr5


def m_clamp(x, lo, hi):         # 0x0BE56C
    if not (x > lo):
        return lo
    if hi > x:
        return x
    return hi


def m_div(a, b):                # 0x0BE628
    if b == 0:
        if a == 0:
            return 0.0
        return FLT_MAX if a > 0 else -FLT_MAX
    return fdiv(a, b)


def m_absdiff(a, b):            # 0x0BEAB0
    return abs(fsub(a, b))


def m_lag(new, old, k, eps):    # 0x0BEA40 contract: r = new + (1-k)(old-new), snap |r-new| < eps
    return None                 # not modelled bit-exactly here; compared by tolerance


# ---------------------------------------------------------------- emulator wrapper
class EmuIO(E.Emu):
    """Emulator with writable peripheral space (for 0x0040D4)."""

    def __init__(self, rom):
        super().__init__(rom)
        self.pwrites = []

    def read(self, a, n):
        a &= 0xFFFFFFFF
        if a in (0xFFFFF818, 0xFFFFF838, 0xFFFFF858) and n == 1:
            return (self.mmios.get(a, 0) | 0x80) & 0xFF      # conversion-end flag always set
        return super().read(a, n)

    def write(self, a, n, v):
        a &= 0xFFFFFFFF
        if 0xFFFFE000 <= a <= 0xFFFFFFFF:
            self.mmios[a] = v & ((1 << (8 * n)) - 1)
            self.pwrites.append((a, n, v & ((1 << (8 * n)) - 1)))
            return
        return super().write(a, n, v)


def emu():
    e = EmuIO(ROM)
    e.stub(0x0BE81C, r0=0)
    e.stub(0x0BE82C, r0=0)
    return e


def written(e):
    """Set of 4-byte-aligned float slots / byte addresses written (non-stack)."""
    return set(e.writes.keys())


# ================================================================ A
def section_A():
    print('A  0x0299F0 / 0x022F92')
    for v in range(256):
        e = emu(); e.ram_u8(0xFFFF9720, v)
        e.call(0x0299F0)
        want = 2 if v != 0 else 0
        check(e.R[0] == want, f'0299F0 [9720]={v}: r0={e.R[0]}')
        e = emu(); e.ram_u8(0xFFFF65F6, v)
        e.call(0x022F92)
        check(e.R[0] == (1 if v == 1 else 0), f'022F92 [65F6]={v}: r0={e.R[0]}')
    print('   0x0299F0: r0 = 2 if byte[0xFFFF9720] != 0 else 0      (256 values)')
    print('   0x022F92: r0 = 1 if byte[0xFFFF65F6] == 1 else 0      (256 values)')


# ================================================================ B
ADD = {   # addend RAM -> name used in the model
    0xFFFF7904: 'p7904', 0xFFFF77CC: 'a77CC', 0xFFFF77D8: 'a77D8', 0xFFFF781C: 'a781C',
    0xFFFF77E4: 'a77E4', 0xFFFF77F4: 'a77F4', 0xFFFF7800: 'a7800', 0xFFFF77DC: 'a77DC',
    0xFFFF77D4: 'a77D4', 0xFFFF77F8: 'a77F8', 0xFFFF7820: 'a7820',
}
OTHER_F = {0xFFFF63C4: 'f63C4', 0xFFFF68D8: 'f68D8', 0xFFFF6574: 'f6574', 0xFFFF7BE4: 'f7BE4',
           0xFFFF68D0: 'f68D0', 0xFFFF7BDC: 'f7BDC', 0xFFFF7810: 'f7810', 0xFFFF7818: 'f7818',
           0xFFFF77BC: 'old77BC', 0xFFFF77C0: 'old77C0', 0xFFFF77C4: 'old77C4', 0xFFFF77C8: 'old77C8'}
BYTES = {0xFFFF8E7E: 'b8E7E', 0xFFFF7BEC: 'b7BEC', 0xFFFF8E46: 'b8E46', 0xFFFF85D7: 'b85D7',
         0xFFFF9720: 'b9720', 0xFFFF7828: 'b7828', 0xFFFF7829: 'b7829'}
WORDS = {0xFFFF785C: 'w785C', 0xFFFF785E: 'w785E'}


def model_S(s):
    """S, the sum 0x033460 forms before its two clamps (0334B8-033508)."""
    m1 = m_min(s['a77D8'], s['a781C'])                                   # 0334C0
    acc = s['p7904']                                                     # 0334C6
    acc = fadd(acc, s['a77CC'])                                          # 0334CC
    acc = fadd(acc, m1)                                                  # 0334CE
    acc = fsub(acc, s['a77E4'])                                          # 0334D4
    acc = fadd(acc, calf(0xCBF4C))                                       # 0334DA
    acc = fadd(acc, s['a77F4'])                                          # 0334E0
    acc = fadd(acc, 1.0)                                                 # 0334E4
    fr5 = -s['a7800']                                                    # 0334EA
    fr4 = fsub(s['a77DC'], s['a77D4'])                                   # 0334F4
    fr4 = fsub(fr4, s['a77F8'])                                          # 0334FC (slot)
    m3 = m_min(-s['a7820'], m_min(fr4, fr5))                             # 0334FA, 033504..033506
    return fadd(acc, m3)                                                 # 033508


def model_033460(s):
    """Model from the 0x033460 listing. Returns (outputs dict addr->value, branch name)."""
    old = s['old77BC']
    m1 = m_min(s['a77D8'], s['a781C'])                                   # 0334C0
    acc = s['p7904']                                                     # 0334C6
    acc = fadd(acc, s['a77CC'])                                          # 0334CC
    acc = fadd(acc, m1)                                                  # 0334CE
    acc = fsub(acc, s['a77E4'])                                          # 0334D4
    acc = fadd(acc, calf(0xCBF4C))                                       # 0334DA
    acc = fadd(acc, s['a77F4'])                                          # 0334E0
    acc = fadd(acc, 1.0)                                                 # 0334E4
    fr5 = -s['a7800']                                                    # 0334EA
    fr4 = fsub(s['a77DC'], s['a77D4'])                                   # 0334F4
    fr4 = fsub(fr4, s['a77F8'])                                          # 0334FC (slot)
    m2 = m_min(fr4, fr5)
    m3 = m_min(-s['a7820'], m2)                                          # 033504..033506
    acc = fadd(acc, m3)                                                  # 033508
    assert bits(acc) == bits(model_S(s)) or (acc != acc and model_S(s) != model_S(s))
    c1 = m_clamp(acc, calf(0xCBF3C), s['f7BDC'])                         # 033514
    c2 = m_clamp(c1, 1.25 * 0 + f32(0.75), 1.25)                         # 033520
    out = {0xFFFF77BC: c2}
    A = s['b8E7E']
    to_copy = False
    if A == 1:
        if (calf(0xCBF60) > s['f6574'] and calf(0xCBF64) > s['f7BE4'] and s['b8E46'] == 1
                and s['w785C'] >= calw(0xCBC32)):
            to_copy = True
        elif (calf(0xCBF68) > s['f68D0'] and calf(0xCBF64) > s['f7BE4'] and s['b8E46'] == 1
              and s['b85D7'] == 1 and s['w785E'] >= calw(0xCBC34)):
            to_copy = True
    if not to_copy and s['b9720'] != 0:      # 0x0299F0 returned 2
        to_copy = True
    if to_copy:
        out.update({0xFFFF77C4: c2, 0xFFFF77C8: c2, 0xFFFF7828: 0, 0xFFFF7829: 0})
        return out, 'copy'
    if A == 1:
        if s['b7BEC'] != 0:
            out.update({0xFFFF77C4: c2, 0xFFFF77C8: c2, 0xFFFF7828: 0})
            return out, 'copy2'
        x = fadd(fadd(s['f7810'], s['f7818']), 1.0)
        c0 = m_clamp(x, calf(0xCBF50), calf(0xCBF54))
        q = m_div(s['f63C4'], fadd(s['f63C4'], s['f68D8']))
        out.update({0xFFFF77C0: c0, 0xFFFF77C4: fmul(c0, q), 0xFFFF77C8: c0,
                    0xFFFF7828: 1, 0xFFFF7829: 1})
        return out, 'special'
    d = m_absdiff(s['old77C4'], old)
    if calf(0xCBF44) > d and calf(0xCBF48) > s['f7BE4']:
        out.update({0xFFFF77C4: c2, 0xFFFF77C8: c2, 0xFFFF7828: 0})
        return out, 'copy2'
    st = m_clamp(fadd(s['old77C4'], calf(0xCBF5C)), calf(0xCBF58), c2)
    out.update({0xFFFF77C4: st, 0xFFFF77C8: st, 0xFFFF7828: 1, 0xFFFF7829: 1})
    return out, 'step'


def run_033460(s):
    e = emu()
    for a, k in list(ADD.items()) + list(OTHER_F.items()):
        e.ram_f32(a, s[k])
    for a, k in BYTES.items():
        e.ram_u8(a, s[k])
    for a, k in WORDS.items():
        e.ram_u16(a, s[k])
    e.call(0x033460)
    return e


def base_state():
    s = {k: 0.0 for k in list(ADD.values()) + list(OTHER_F.values())}
    s.update({k: 0 for k in BYTES.values()})
    s.update({k: 0 for k in WORDS.values()})
    s.update({'f63C4': 3.0, 'f68D8': 1.0, 'f7BDC': 1.2, 'f6574': 5.0, 'f7BE4': 0.5,
              'f68D0': 5.0, 'old77BC': 1.0, 'old77C0': 1.0, 'old77C4': 1.0, 'old77C8': 1.0,
              'b7828': 0xAA, 'b7829': 0xAA})
    return s


def compare_033460(s, tag):
    e = run_033460(s)
    want, br = model_033460(s)
    for a, v in want.items():
        if a in (0xFFFF7828, 0xFFFF7829):
            got = e.read_u8(a)
            check(got == v, f'{tag}: byte {a:08X} got {got} want {v} ({br})')
        else:
            got = e.read_f32(a)
            check(bits(got) == bits(v), f'{tag}: {a:08X} got {got!r} want {v!r} ({br})')
    # write set: exactly the model's addresses (bytes for floats: 4 each)
    exp = set()
    for a in want:
        exp |= {a} if a in (0xFFFF7828, 0xFFFF7829) else {a, a + 1, a + 2, a + 3}
    check(written(e) == exp, f'{tag}: write set {sorted(hex(x) for x in written(e) - exp)} '
                             f'missing {sorted(hex(x) for x in exp - written(e))} ({br})')
    if 0xFFFF7829 not in want:
        check(e.read_u8(0xFFFF7829) == s['b7829'], f'{tag}: 7829 changed on {br}')
    return br, want, e


def section_B():
    print('B  0x033460')
    # B1 formula over a random grid (copy path so 77BC is the only float that matters)
    vals = [-0.4, -0.25, -0.1, -0.03125, -0.0, 0.0, 0.0078125, 0.05, 0.1, 0.2, 0.35]
    n = 0
    for _ in range(1500):
        s = base_state()
        for k in ADD.values():
            s[k] = f32(RNG.choice(vals) if RNG.random() < 0.5 else RNG.uniform(-0.3, 0.3))
        s['f7BDC'] = f32(RNG.choice([0.8, 0.85, 1.0, 1.1, 1.2, 1.3, 2.0]))
        s['b9720'] = 1                     # copy path
        compare_033460(s, 'B1'); n += 1
    print(f'   B1 factor formula, {n} random addend sets, bit-exact against model_033460 (copy path)')
    # B1b small addends (random sign / exponent) so S stays inside (0.85, 1.25): no clamp hides the sum
    n = unclamped = 0
    for _ in range(1500):
        s = base_state()
        for k in ADD.values():
            s[k] = f32(RNG.choice((-1, 1)) * RNG.randint(1, 2 ** 20) * 2.0 ** RNG.randint(-46, -28))
        s['f7BDC'] = 1.25
        s['b9720'] = 1
        br, want, e = compare_033460(s, 'B1b')
        S = model_S(s)
        if calf(0xCBF3C) < S < 1.25:
            check(bits(e.read_f32(0xFFFF77BC)) == bits(S), 'B1b unclamped: [77BC] == S')
            unclamped += 1
        n += 1
    check(unclamped == n, f'B1b: {n - unclamped} sets were clamped')
    print(f'   B1b {n} random small-addend sets, none clamped: [77BC] == S bit-exact')
    # B7 summation order: two addends of 5*2^-26 summed BEFORE the 1.0 (0334CC, then 0334E4) give
    # 1 + 2^-23 under RZ; adding each to 1.0 separately would give 1.0. Emulator-model consistency only:
    # the order itself is read from the instruction sequence, not from the last bit.
    s = base_state(); s.update({'b9720': 1, 'p7904': 5 * 2.0 ** -26, 'a77CC': 5 * 2.0 ** -26, 'f7BDC': 1.25})
    br, want, e = compare_033460(s, 'B7 order')
    got = e.read_f32(0xFFFF77BC)
    alt = fadd(fadd(1.0, 5 * 2.0 ** -26), 5 * 2.0 ** -26)
    check(bits(got) == bits(1.0 + 2.0 ** -23) and bits(alt) != bits(got), f'B7 order {got!r} {alt!r}')
    print(f'   B7 order: [7904]=[77CC]=5*2^-26 -> [77BC]={got!r}; 1.0-first order would give {alt!r}')
    # B2 every branch
    seen = {}
    grid = []
    for A in (0, 1, 2):
        for b9720 in (0, 1):
            for b7BEC in (0, 1):
                for blk in ('none', 'b1', 'b2', 'b1fail_last', 'b2fail_last'):
                    for near in (True, False):
                        for f7BE4 in (0.5, 150.0):
                            grid.append((A, b9720, b7BEC, blk, near, f7BE4))
    for (A, b9720, b7BEC, blk, near, f7BE4) in grid:
        s = base_state()
        s.update({'b8E7E': A, 'b9720': b9720, 'b7BEC': b7BEC, 'f7BE4': f7BE4,
                  'p7904': 0.03125, 'a77DC': -0.0625, 'f7810': 0.0625, 'f7818': -0.03125,
                  'old77C4': 0.96875 if near else 7.0})
        if blk in ('b1', 'b1fail_last'):    # [CBF60]=0 > [6574], [CBF64]=0 > [7BE4], [8E46]=1
            s.update({'f6574': -1.0, 'f7BE4': -1.0, 'b8E46': 1,
                      'w785C': 0xFFFF if blk == 'b1' else 0xFFFE})
        if blk in ('b2', 'b2fail_last'):
            s.update({'f68D0': -1.0, 'f7BE4': -1.0, 'b8E46': 1, 'b85D7': 1,
                      'w785E': 0xFFFF if blk == 'b2' else 0xFFFE})
        br, want, e = compare_033460(s, f'B2 {A},{b9720},{b7BEC},{blk},{near},{f7BE4}')
        seen[br] = seen.get(br, 0) + 1
    check(set(seen) == {'copy', 'copy2', 'special', 'step'}, f'branches {seen}')
    print(f'   B2 branch grid {len(grid)} cases, all four exits reached: {seen}')
    # B2b: the block conditions need u16 == 0xFFFF in this calibration
    check(calw(0xCBC32) == 0xFFFF and calw(0xCBC34) == 0xFFFF, 'CBC32/34')
    check(calf(0xCBF60) == 0.0 and calf(0xCBF64) == 0.0 and calf(0xCBF68) == 0.0, 'CBF60/64/68')
    print('   B2b cal: [CBF60]=[CBF64]=[CBF68]=0.0, u16[CBC32]=u16[CBC34]=0xFFFF '
          '(blocks need [6574]<0 or [68D0]<0, [7BE4]<0, counter == 65535;')
    print('       the grid feeds [7BE4]=-1.0 to exercise them; section J: no writer stores [7BE4] < 0)')
    # B3 special path: 77C4 = 77C0 * 63C4/(63C4+68D8), 77C8 = 77C0
    s = base_state(); s.update({'b8E7E': 1, 'b7BEC': 0, 'f7810': 0.5, 'f7818': 0.25,
                                'f63C4': 3.0, 'f68D8': 1.0})
    br, want, e = compare_033460(s, 'B3a')
    check(br == 'special' and e.read_f32(0xFFFF77C0) == f32(calf(0xCBF54)), 'B3a clamp hi')
    s['f63C4'] = 0.0; s['f68D8'] = 0.0
    br, want, e = compare_033460(s, 'B3b')
    check(e.read_f32(0xFFFF77C4) == 0.0, 'B3b 0/0 -> 0')
    print(f'   B3 special path: [77C0]=clamp(1+[7810]+[7818],{calf(0xCBF50):.6g},{calf(0xCBF54):.6g}) '
          f'-> {e.read_f32(0xFFFF77C0):.6g}; [77C8]=[77C0]; [77C4]=[77C0]*[63C4]/([63C4]+[68D8]); 0/0 -> 0')
    # B4 step path: 77C4 = clamp(77C4 + 1.0, 0.9, new77BC)
    rows = []
    for old77C4 in (-5.0, 0.0, 0.5, 0.85, 0.95, 1.2, 9.0):
        for p in (-0.3, 0.0, 0.2):
            s = base_state(); s.update({'b8E7E': 0, 'old77C4': old77C4, 'old77BC': 20.0, 'p7904': p})
            br, want, e = compare_033460(s, f'B4 {old77C4},{p}')
            rows.append((old77C4, p, br, e.read_f32(0xFFFF77BC), e.read_f32(0xFFFF77C8)))
    for r in rows[:9]:
        print(f'   B4 old77C4={r[0]:6.3g} p7904={r[1]:5.2g} -> {r[2]:5s} 77BC={r[3]:.6g} 77C8={r[4]:.6g}')
    # B5 the two clamps over a [7BDC] x S sweep, against the closed-form range statement
    lo = calf(0xCBF3C)
    tmin = T.read_table(ROM, 0xAD348)['values'][0]          # 0.8499755859375 < lo
    b7bdc_vals = (0.70, 0.75, 0.80, 0.849, tmin, lo, 0.9, 0.95, calf(0xCBF40), 1.3, float('nan'))
    p_vals = (-0.5, -0.26, -0.2, -0.151, -0.15, -0.149, -0.1, 0.0, 0.04, 0.06, 0.2, 0.3, float('nan'))
    seen = {}
    for b in b7bdc_vals:
        outs = set()
        prev = None
        for p in p_vals:
            s = base_state(); s.update({'b9720': 1, 'p7904': f32(p), 'f7BDC': f32(b)})
            br, want, e = compare_033460(s, f'B5 {b},{p}')
            S, v = model_S(s), e.read_f32(0xFFFF77BC)
            if b != b:                                   # [7BDC] = NaN
                exp = lo if not (S > lo) else f32(0.75)
                check(bits(v) == bits(exp), f'B5 NaN hi: {v}')
            elif f32(b) >= lo:
                check(lo <= v <= min(f32(b), 1.25), f'B5 range {b},{p}: {v}')
                if S == S and prev is not None:
                    check(v >= prev, f'B5 monotone {b},{p}')
                if S == S:
                    prev = v
            else:
                exp = lo if not (S > lo) else max(f32(b), f32(0.75))
                check(bits(v) == bits(exp), f'B5 inverted {b},{p}: {v} want {exp}')
            outs.add(v)
        seen[b] = sorted(outs, key=lambda x: (x != x, x))
    for b in b7bdc_vals:
        print(f'   B5 [7BDC]={b!r:>20} -> [77BC] takes {[f"{x:.7g}" for x in seen[b]]}')
    check(set(seen[0.80]) == {f32(0.80), lo}, 'B5 0.80')
    check(set(seen[0.70]) == {f32(0.75), lo}, 'B5 0.70')
    check(set(seen[tmin]) == {tmin, lo}, 'B5 tmin: S > 0.85 LOWERS [77BC] to [7BDC]')
    print('   B5 closed form: [7BDC] >= [CBF3C] -> [CBF3C] <= [77BC] <= min([7BDC],1.25), monotone in S;')
    print('      [7BDC] < [CBF3C] -> [CBF3C] if S <= [CBF3C] else max([7BDC],0.75); [7BDC]=NaN -> 0.75 if S > [CBF3C]')
    # B8 STEP clamp inverts when x = [77C4]+1.0 <= [CBF58] (0.9) and the new [77BC] < 0.9
    s = base_state(); s.update({'b8E7E': 0, 'old77BC': 1.0, 'old77C4': -4.5, 'p7904': f32(-0.14),
                                'f7BDC': calf(0xCBF40)})
    br, want, e = compare_033460(s, 'B8')
    check(br == 'step' and e.read_f32(0xFFFF77C8) == calf(0xCBF58) > e.read_f32(0xFFFF77BC), 'B8 inversion')
    print(f'   B8 STEP, [77C4]=-4.5 (|d|=5.5 >= 5), new [77BC]={e.read_f32(0xFFFF77BC):.7g} -> '
          f'[77C8]={e.read_f32(0xFFFF77C8):.7g} (> new [77BC]: the clamp low bound wins)')
    # B6 NaN (EMU-MODEL: false compare takes the low bound)
    s = base_state(); s.update({'b9720': 1, 'p7904': float('nan')})
    br, want, e = compare_033460(s, 'B6 NaN')
    check(e.read_f32(0xFFFF77BC) == f32(calf(0xCBF3C)), 'B6')
    print(f'   B6 [7904]=NaN -> [77BC]={e.read_f32(0xFFFF77BC):.7g} (low bound [CBF3C], EMU-MODEL)')


# ================================================================ C
def section_C():
    print('C  0x0332A2')
    for v in (0, 1, 2, 0xFF):
        e = emu()
        e.ram_u8(0xFFFF65F6, v); e.ram_u8(0xFFFF8E7E, 0x5A)
        e.call(0x0332A2)
        if v == 1:
            for a in (0xFFFF77C8, 0xFFFF77C0, 0xFFFF77C4, 0xFFFF77BC, 0xFFFF780C):
                check(e.read_f32(a) == 1.0, f'C {a:08X}')
            for a in (0xFFFF7810, 0xFFFF7804, 0xFFFF7808, 0xFFFF7814, 0xFFFF7818, 0xFFFF7820):
                check(bits(e.read_f32(a)) == 0, f'C0 {a:08X}')
            for a, w in ((0xFFFF7864, 0), (0xFFFF7865, 0), (0xFFFF7871, 0x5A), (0xFFFF7872, 0)):
                check(e.read_u8(a) == w, f'Cb {a:08X}')
            exp = set()
            for a in (0xFFFF77C8, 0xFFFF77C0, 0xFFFF77C4, 0xFFFF77BC, 0xFFFF7810, 0xFFFF7804,
                      0xFFFF7808, 0xFFFF780C, 0xFFFF7814, 0xFFFF7818, 0xFFFF7820):
                exp |= {a, a + 1, a + 2, a + 3}
            exp |= {0xFFFF7864, 0xFFFF7865, 0xFFFF7871, 0xFFFF7872}
            check(written(e) == exp, f'C write set {sorted(hex(x) for x in written(e) ^ exp)}')
        else:
            check(written(e) == set(), f'C no-write {v}')
    print('   [65F6]==1: 77BC=77C0=77C4=77C8=780C=1.0; 7804,7808,7810,7814,7818,7820=0.0;')
    print('              bytes 7864=0 7865=0 7871=[8E7E] 7872=0 -- exactly these 48 bytes written')
    print('   [65F6]!=1 (0,2,255): nothing written')


# ================================================================ D
def section_D():
    print('D  0x033658 (r4=0x063A3C, r5=0x063A2C, r6=0 as passed by 0x033304)')
    rows = []
    for d6540, d77C8, ect, b7864, b782A, p in (
            (1.0, 1.0, 90.0, 0, 0, 'edge, |d|<1'),
            (2.0, 0.9, 90.0, 0, 0, 'edge, |d|>=1, ECT<140'),
            (2.0, 0.9, 150.0, 0, 0, 'edge, |d|>=1, ECT>=140, 782A=0'),
            (1.75, 0.75, 90.0, 0, 0, 'edge, |d|=1.0 exactly'),
            (1.75, 0.7500001, 90.0, 0, 0, 'edge, |d| just under 1.0'),
            (1.2, 1.0, 90.0, 1, 0, 'no edge (7864=1)')):
        e = emu()
        e.stub(0x022CF4, r0=0)
        e.ram_f32(0xFFFF6350, ect); e.ram_u8(0xFFFF6254, 0); e.ram_u8(0xFFFF65C0, 0)
        e.ram_f32(0xFFFF6540, d6540); e.ram_u8(0xFFFF7448, 1)
        e.ram_f32(0xFFFF77C8, d77C8); e.ram_f32(0xFFFF77CC, 0.5)
        e.ram_u8(0xFFFF7828, 0); e.ram_u8(0xFFFF782A, b782A); e.ram_u8(0xFFFF7864, b7864)
        e.ram_u8(0xFFFF7869, 0); e.ram_u8(0xFFFF786A, 0)
        e.ram_u16(0xFFFF7858, 0); e.ram_u16(0xFFFF785A, 0)
        e.call(0x033658, regs={4: 0x063A3C, 5: 0x063A2C, 6: 0})
        got = e.read_f32(0xFFFF77CC)
        diff = fsub(f32(d6540), f32(d77C8))
        if b7864 == 0:
            if not (calf(0xCBF6C) > abs(diff)) and calf(0xCBF70) > ect:
                want = diff
            elif not (calf(0xCBF6C) > abs(diff)) and b782A == 0 and ROM[0xCBBE2] == 0xFF:
                want = diff
            else:
                want = 0.0
            check(bits(got) == bits(want), f'D {p}: {got} want {want}')
            check(e.read_u8(0xFFFF782A) == 1, f'D {p}: 782A')
        rows.append((p, got))
        check(e.read_u8(0xFFFF7864) == 1, f'D {p}: 7864 = [7448]')
    for p, g in rows:
        print(f'   {p:34s} -> [77CC]={g:.7g}')
    print(f'   cal [CBF6C]={calf(0xCBF6C):g} [CBF70]={calf(0xCBF70):g} [CBBE2]=0x{ROM[0xCBBE2]:02X}: '
          'the capture fires only when |[6540]-[77C8]| >= 1.0')


# ================================================================ E
def model_033186(s):
    a = m_div(1.0, s['77C8'])
    r = m_div(fadd(s['63C4'], s['68D8']), s['63C4'])
    v = fsub(fmul(a, r), s['7BE4'])
    return fadd(-1.0, v)


def model_03A196(fr4, fr5, fr6, fr7, s):
    a = m_div(1.0, fr4)
    r = m_div(fadd(s['63C4'], s['68D8']), s['63C4'])
    v = fmul(fmul(fmul(a, r), fr5), fr6)
    return fsub(v, fr7)


def section_E():
    print('E  0x033186 / 0x03A196')
    n = 0
    for c8 in (0.75, 0.9, 1.0, 1.1, 1.25, 0.0):
        for a, b in ((3.0, 0.0), (2.5, 0.5), (1.7, 0.3), (0.0, 1.0)):
            for be4 in (0.0, 0.02, -0.1):
                s = {'77C8': f32(c8), '63C4': f32(a), '68D8': f32(b), '7BE4': f32(be4)}
                e = emu()
                e.ram_f32(0xFFFF77C8, s['77C8']); e.ram_f32(0xFFFF63C4, s['63C4'])
                e.ram_f32(0xFFFF68D8, s['68D8']); e.ram_f32(0xFFFF7BE4, s['7BE4'])
                e.call(0x033186)
                w = model_033186(s)
                check(bits(e.fr(0)) == bits(w), f'E1 {s}: {e.fr(0)} {w}')
                check(written(e) == set(), 'E1 writes')
                e = emu()
                e.ram_f32(0xFFFF63C4, s['63C4']); e.ram_f32(0xFFFF68D8, s['68D8'])
                e.call(0x03A196, fregs={4: s['77C8'], 5: f32(1.1), 6: f32(0.9), 7: 1.0})
                w = model_03A196(s['77C8'], f32(1.1), f32(0.9), 1.0, s)
                check(bits(e.fr(0)) == bits(w), f'E2 {s}: {e.fr(0)} {w}')
                n += 1
    print(f'   0x033186: fr0 = -1 + ((1/[77C8]) * (([63C4]+[68D8])/[63C4]) - [7BE4])   {n} cases bit-exact')
    print(f'   0x03A196: fr0 = (1/fr4)*(([63C4]+[68D8])/[63C4])*fr5*fr6 - fr7           {n} cases bit-exact')
    s = {'77C8': 1.0, '63C4': 3.0, '68D8': 0.0, '7BE4': 0.0}
    lo, hi = model_033186(dict(s, **{'77C8': f32(1.05)})), model_033186(dict(s, **{'77C8': f32(0.95)}))
    check(lo < 0 < hi, 'E monotone')
    print(f'   [68D8]=0, [7BE4]=0: [77C8]=1.05 -> {lo:+.6f}, [77C8]=0.95 -> {hi:+.6f} '
          '(a larger [77C8] lowers the term)')


# ================================================================ F
def interp1(ax, vals, x):
    if x <= ax[0]:
        return vals[0]
    if x >= ax[-1]:
        return vals[-1]
    for i in range(len(ax) - 1):
        if ax[i] <= x <= ax[i + 1]:
            if ax[i + 1] == ax[i]:
                return vals[i]
            t = (x - ax[i]) / (ax[i + 1] - ax[i])
            return vals[i] + t * (vals[i + 1] - vals[i])
    return vals[-1]


def section_F():
    print('F  addend writers')
    d = DEFS.load()
    # F1 0x0339E4 -> 77D4, table AD89C (Non-Cruise ECT) when [90BE] != 1, AD880 (Cruise) when == 1
    tn = d.get('CL Fueling Target Compensation Imm. Non-Cruise (ECT)')
    tc = d.get('CL Fueling Target Compensation Imm. Cruise (ECT)')
    disp_n, disp_c = tn.read(ROM), tc.read(ROM)
    tdn, tdc = T.read_table(ROM, 0xAD89C), T.read_table(ROM, 0xAD880)
    ectax = tdn['axes']['y']; loadn, loadc = tdn['axes']['x'], tdc['axes']['x']
    nchk = 0
    for cruise, td, disp, loadax in ((0, tdn, disp_n, loadn), (1, tdc, disp_c, loadc)):
        for i, ect in enumerate(ectax):
            for j, ld in enumerate(loadax):
                for t6354 in (100.0, 130.0):
                    e = emu()
                    e.ram_f32(0xFFFF6354, t6354); e.ram_f32(0xFFFF6350, ect); e.ram_f32(0xFFFF63F8, ld)
                    e.ram_u8(0xFFFF90BE, cruise)
                    e.call(0x0339E4)
                    v77D0 = e.read_f32(0xFFFF77D0); v77D4 = e.read_f32(0xFFFF77D4)
                    check(abs(v77D0 - (-disp[j][i] / 14.7)) < 2e-5,
                          f'F1 cruise={cruise} ect={ect} load={ld}: {v77D0} vs defs {disp[j][i]}')
                    if calf(0xCBF9C) > t6354:
                        check(bits(v77D4) == bits(v77D0), 'F1 gate open')
                    else:
                        check(v77D4 == 0.0, 'F1 gate closed')
                    nchk += 1
    print(f'   0x0339E4: [77D0] = table(ECT=[6350], load=[63F8]); at all {nchk} breakpoint cases')
    print('             [77D0] == -(definition display AFR points)/14.7 for "CL Fueling Target')
    print('             Compensation Imm. Non-Cruise (ECT)" ([90BE]!=1) / "... Imm. Cruise (ECT)" ([90BE]==1)')
    print(f'             [77D4] = [77D0] if [CBF9C]={calf(0xCBF9C):g} > [6354] else 0')
    # F2 0x033CC0 -> 77DC, table A (AD8B8) when [984D]==0 and 0x022CF4()==1; B (AD8F0) when [984D]!=0
    ta, tb = d.get('CL Fueling Target Compensation A (Load)'), d.get('CL Fueling Target Compensation B (Load)')
    da, db = ta.read(ROM), tb.read(ROM)
    nchk = 0
    for desc, disp, b984D, r022 in ((0xAD8B8, da, 0, 1), (0xAD8F0, db, 1, 1)):
        td = T.read_table(ROM, desc)
        for i, ld in enumerate(td['axes']['y']):
            for j, rpm in enumerate(td['axes']['x']):
                e = emu(); e.stub(0x022CF4, r0=r022)
                e.ram_f32(0xFFFF6624, rpm); e.ram_f32(0xFFFF63F8, ld); e.ram_u8(0xFFFF984D, b984D)
                e.call(0x033CC0, regs={4: 0x063A44, 5: 0})
                v = e.read_f32(0xFFFF77DC)
                check(abs(v - disp[j][i] / 14.7) < 2e-5, f'F2 {desc:X} {ld} {rpm}: {v} vs {disp[j][i]}')
                check(written(e) == {0xFFFF77DC, 0xFFFF77DD, 0xFFFF77DE, 0xFFFF77DF}, 'F2 writes')
                nchk += 1
    for b984D, r022, want in ((0, 0, 0xAD8D4), (1, 0, 0xAD90C)):
        td = T.read_table(ROM, want)
        ld, rpm = td['axes']['y'][3], td['axes']['x'][4]
        e = emu(); e.stub(0x022CF4, r0=r022)
        e.ram_f32(0xFFFF6624, rpm); e.ram_f32(0xFFFF63F8, ld); e.ram_u8(0xFFFF984D, b984D)
        e.call(0x033CC0, regs={4: 0x063A44, 5: 0})
        # desc_types 2-D values are indexed [+8 axis][+4 axis] = [rpm][load]
        check(abs(e.read_f32(0xFFFF77DC) - td['values'][4][3]) < 1e-6, f'F2 unnamed {want:X}')
    print(f'   0x033CC0: [77DC] = table(load=[63F8], rpm=[6624]); at all {nchk} breakpoints of the')
    print('             named tables [77DC] == +(display AFR points)/14.7 of "CL Fueling Target')
    print('             Compensation A (Load)" ([984D]==0, 0x022CF4()==1) / "... B (Load)" ([984D]!=0)')
    print('             unnamed siblings 0x0AD8D4 / 0x0AD90C when 0x022CF4() != 1')
    print('   => in 0x033460 the two enter as +[77DC] - [77D4]: BOTH add their DISPLAYED AFR points/14.7')
    # F3 0x033F9E -> 77F8
    for spd in (-1.0, 0.0, 50.0):
        for r0 in (0, 2):
            e = emu(); e.stub(0x0582AC, r0=r0); e.ram_f32(0xFFFF65FC, spd)
            e.call(0x033F9E)
            want = 0.0 if calf(0xCBFEC) > spd else (calf(0xCBFF0) if r0 == 2 else 0.0)
            check(bits(e.read_f32(0xFFFF77F8)) == bits(want), 'F3')
    print(f'   0x033F9E: [77F8] = ([CBFEC]={calf(0xCBFEC):g} > [65FC]) ? 0 : (0x0582AC()==2 ? '
          f'[CBFF0]={calf(0xCBFF0):g} : 0)  -> 0.0 always in this calibration')
    # F4 0x03439E -> 781C
    for r5 in (0, 1):
        for r0 in (0, 1):
            e = emu(); e.stub(0x02BE2C, r0=r0); e.stub(0x02BE38, r0=r0)
            e.call(0x03439E, regs={4: 0xFFFF781C, 5: r5})
            want = calf(0xCC010) if r0 == 1 else 0.0
            check(bits(e.read_f32(0xFFFF781C)) == bits(want), 'F4')
    print(f'   0x03439E: [781C] = (predicate==1) ? [CC010]={calf(0xCC010):g} : 0  -> 0.0 always')
    # F5 0x0343CE -> 7820
    for ped in (180.0, 195.0, 210.0):
        for c2, c4 in ((0, 5), (3, 5), (5, 5), (3, 2)):
            for prev in (0, 1):
                e = emu(); e.ram_f32(0xFFFF64D8, ped); e.ram_u16(0xFFFF79C2, c2); e.ram_u16(0xFFFF79C4, c4)
                e.ram_u8(0xFFFF7872, prev)
                e.call(0x0343CE)
                flag = 1 if not (calf(0xCC014) > ped) else (0 if calf(0xCC018) > ped else prev)
                check(e.read_u8(0xFFFF7872) == flag, 'F5 flag')
                want = calf(0xCC01C) if (0 < c2 < c4 and flag == 1) else 0.0
                check(bits(e.read_f32(0xFFFF7820)) == bits(want), 'F5')
    print(f'   0x0343CE: hysteresis [7872] on [64D8] (set when !([CC014]={calf(0xCC014):g} > x), clear when '
          f'[CC018]={calf(0xCC018):g} > x);')
    print(f'             [7820] = (0 < u16[79C2] < u16[79C4] and [7872]==1) ? [CC01C]={calf(0xCC01C):g} : 0 '
          '-> 0.0 always')


# ================================================================ G
def section_G():
    print('G  0x058902 / 0x021A3C -- what [6540] is')
    d = DEFS.load()
    sc = d.get('Front Oxygen Sensor Scaling'); disp = sc.read(ROM)
    td = T.read_table(ROM, 0xAF468); ax = td['axes']['x']
    for i, ma in enumerate(ax):
        e = emu(); e.ram_f32(0xFFFF40E0, ma)
        e.call(0x058902)
        v = e.read_f32(0xFFFF8DE4)
        check(abs(v * 14.7 - disp[i]) < 1e-3, f'G1 {ma}: {v * 14.7} vs {disp[i]}')
    print(f'   0x058902: [8DE4] = table 0x0AF468(x=[40E0]); x 14.7 equals "Front Oxygen Sensor Scaling"')
    print(f'             (AFR) at all {len(ax)} breakpoints; axis = definition axis "Front Oxygen Sensor" (mA)')
    cp = d.get('Front Oxygen Sensor Compensation (Atm. Pressure)'); cdisp = cp.read(ROM)
    tc = T.read_table(ROM, 0xAAE8C); cax = tc['axes']['x']
    rows = []
    for i, atm in enumerate(cax):
        for lam in (0.80, 1.0, 1.10, 1.30):
            e = emu()
            e.stub(0x02F8EA, r0=1)                          # take the no-lag branch
            e.ram_u8(0xFFFF5C44, 1); e.ram_f32(0xFFFF6898, atm); e.ram_f32(0xFFFF8DE4, lam)
            e.ram_u8(0xFFFF65F6, 0); e.ram_u8(0xFFFF6555, 0)
            for a in (0xFFFF653C, 0xFFFF6540, 0xFFFF6544, 0xFFFF6548, 0xFFFF654C):
                e.ram_f32(a, 1.0)
            e.call(0x021A3C)
            got = e.read_f32(0xFFFF653C)
            want_afr = (lam * 14.7 - 14.7) * cdisp[i] + 14.7     # the definition's own formula
            want = min(max(want_afr / 14.7, 0.75), 2.0)
            check(abs(got - want) < 2e-5, f'G2 atm={atm} lam={lam}: {got} vs {want}')
            check(bits(e.read_f32(0xFFFF6540)) == bits(got), 'G2 no-lag copy')
            rows.append((atm, lam, got))
    print('   0x021A3C (no-lag branch): [653C] = clamp(1 + ([8DE4]-1)*T_0AAE8C([6898]), 0.75, 2.0)')
    print(f'             = the definition text "((Front O2 AFR - 14.7) x Compensation) + 14.7" / 14.7 '
          f'({len(rows)} cases); [6540] = [653C] on this branch')
    # lag branch: [6540] = lag of [653C] with k=[C3184]
    e = emu(); e.stub(0x02F8EA, r0=0)
    e.ram_u8(0xFFFF5C44, 1); e.ram_f32(0xFFFF6898, cax[-1]); e.ram_f32(0xFFFF8DE4, 1.2)
    e.ram_u8(0xFFFF65F6, 0); e.ram_u8(0xFFFF6555, 0)
    for a in (0xFFFF653C, 0xFFFF6540, 0xFFFF6544, 0xFFFF6548, 0xFFFF654C):
        e.ram_f32(a, 1.0)
    e.call(0x021A3C)
    k = calf(0xC3184)
    check(abs(e.read_f32(0xFFFF6540) - (1.2 + (1 - k) * (1.0 - 1.2))) < 1e-5, 'G3 lag')
    print(f'   0x021A3C (lag branch): [6540] = [653C] + (1-k)([6540]old-[653C]), k=[C3184]={k:g}: '
          f'1.0 -> {e.read_f32(0xFFFF6540):.6g} toward 1.2')
    e = emu(); e.stub(0x02F8EA, r0=0)
    e.ram_u8(0xFFFF5C44, 1); e.ram_f32(0xFFFF6898, cax[-1]); e.ram_f32(0xFFFF8DE4, 1.2)
    e.ram_u8(0xFFFF65F6, 1); e.ram_u8(0xFFFF6555, 0)
    for a in (0xFFFF653C, 0xFFFF6540, 0xFFFF6544, 0xFFFF6548, 0xFFFF654C):
        e.ram_f32(a, 0.5)
    e.call(0x021A3C)
    for a in (0xFFFF653C, 0xFFFF6540, 0xFFFF6544, 0xFFFF6548, 0xFFFF654C):
        check(e.read_f32(a) == 1.0, 'G4')
    print('   0x021A3C ([65F6]==1): 653C, 6540, 6544, 6548, 654C = 1.0 (the same trigger as 0x0332A2)')


# ================================================================ H
def section_H():
    print('H  sign: [7904] through 0x033460, all other addends 0, COPY exit; [7BDC] at values 0x039D1C can store')
    tmin = T.read_table(ROM, 0xAD348)['values'][0]
    for b in (calf(0xCBF40), calf(0xCC450), tmin):
        row = []
        for p in (-0.10, -0.05, 0.0, 0.05, 0.10):
            s = base_state(); s.update({'b9720': 1, 'p7904': f32(p), 'f7BDC': b})
            br, want, e = compare_033460(s, f'H {b},{p}')
            row.append(e.read_f32(0xFFFF77C8))
        print(f'   [7BDC]={b:.7g}: [7904] -0.10..+0.10 -> [77C8] x14.7 = '
              + '  '.join(f'{v * 14.7:.3f}' for v in row))
        if b == calf(0xCBF40):
            check(bits(row[3]) == bits(calf(0xCBF40)) and bits(row[4]) == bits(calf(0xCBF40)), 'H cap 1.05')
            check(row[0] < row[1] < row[2] < row[3], 'H sign')
    # SPECIAL exit: [77C8] = [77C0], independent of [7904]
    got = set()
    for p in (-0.10, 0.0, 0.10):
        s = base_state(); s.update({'b8E7E': 1, 'b7BEC': 0, 'b9720': 0, 'p7904': f32(p),
                                    'f7810': 0.0625, 'f7818': 0.0, 'f7BDC': calf(0xCBF40)})
        br, want, e = compare_033460(s, f'H special {p}')
        check(br == 'special', 'H special branch')
        got.add(bits(e.read_f32(0xFFFF77C8)))
    check(len(got) == 1, 'H special: [77C8] depends on [7904]')
    print('   SPECIAL exit ([8E7E]==1, [7BEC]==0, no COPY): [77C8] identical for [7904] = -0.10, 0, +0.10')


# ================================================================ I
def section_I():
    print('I  0x0040D4 -- peripheral result-word copy (block naming needs the SH7058 register map)')
    e = emu()
    for i in range(0, 0x60, 2):
        e.mmios[0xFFFFF800 + i] = 0x1000 + i
    for a in (0xFFFFF818, 0xFFFFF819, 0xFFFFF838, 0xFFFFF839, 0xFFFFF858, 0xFFFFF859):
        e.mmios[a] = 0
    e.call(0x0040D4)
    m = {}
    for k in range(12):
        m[0xFFFF4024 + 2 * k] = 0xFFFFF800 + 2 * k
    for k in range(12):
        m[0xFFFF403C + 2 * k] = 0xFFFFF820 + 2 * k
    for k in range(8):
        m[0xFFFF4054 + 2 * k] = 0xFFFFF840 + 2 * k
    for ram, per in m.items():
        check(e.read_u16(ram) == (0x1000 + per - 0xFFFFF800), f'I {ram:08X}<-{per:08X}')
    check(e.read_u16(0xFFFF4050) == 0x1034, 'I 4050')
    exp = set(range(0xFFFF4024, 0xFFFF4064)) | {0xFFFF40A4, 0xFFFF40A9, 0xFFFF40AA}
    check(written(e) == exp, f'I write set {sorted(hex(x) for x in written(e) ^ exp)}')
    check((e.read_u8(0xFFFF40A4), e.read_u8(0xFFFF40A9), e.read_u8(0xFFFF40AA)) == (2, 0, 0xFF), 'I bytes')
    pw = [(a, v) for a, n, v in e.pwrites if n == 1]
    print('   RAM 0xFFFF4024..403A <- words 0xFFFFF800..F816; 403C..4052 <- F820..F836; 4054..4062 <- F840..F84E')
    print(f'   [0xFFFF4050] <- word at 0xFFFFF834 (asserted); byte writes to control regs: '
          + ', '.join(f'{a & 0xFFFF:04X}={v:02X}' for a, v in pw))


# ================================================================ J
J_IN_F = {0xFFFF6350: 'f6350', 0xFFFF8E38: 'f8E38', 0xFFFF77C8: 'f77C8', 0xFFFF6574: 'f6574',
          0xFFFF68D0: 'f68D0', 0xFFFF7BE4: 'f7BE4'}
J_IN_B = {0xFFFF8E7E: 'b8E7E', 0xFFFF8E69: 'b8E69', 0xFFFF85D7: 'b85D7', 0xFFFF7C18: 'b7C18',
          0xFFFF7BEC: 'b7BEC'}


def run_039F42(s, rom=None):
    e = E.Emu(rom or ROM)
    for a, k in J_IN_F.items():
        e.ram_f32(a, s[k])
    for a, k in J_IN_B.items():
        e.ram_u8(a, s[k])
    e.ram_u16(0xFFFF67EC, s['w67EC'])
    e.call(0x039F42)
    return e


def model_039F42(s, e):
    """[7BE4] after one call, live paths (byte [0x0CBC06] != 0). P2 uses the table outputs the ROM
    stored at [7BF0]..[7BFC] (the lookups are runtime-library calls)."""
    old = s['f7BE4']
    if s['b7C18'] == 1:
        return 'P1', m_max(fsub(old, calf(0xCC478)), 0.0)
    if s['b8E7E'] == 1:
        if s['b7BEC'] == 0:
            p = e.read_f32(0xFFFF7BF0)
            for a in (0xFFFF7BF4, 0xFFFF7BF8, 0xFFFF7BFC):
                p = fmul(p, e.read_f32(a))
            check(bits(e.read_f32(0xFFFF7BE8)) == bits(p), 'J [7BE8] product')
            return 'P2', m_min(fadd(old, calf(0xCC45C)), p)
        return 'P3', m_max(fsub(old, calf(0xCC474)), calf(0xCC470))
    if s['b8E69'] != 0:
        return ('P4', m_max(fsub(old, calf(0xCC46C)), 0.0)) if s['b85D7'] != 0 else \
               ('P5', m_max(fsub(old, calf(0xCC464)), 0.0))
    return ('P6', m_max(fsub(old, calf(0xCC468)), 0.0)) if s['b85D7'] != 0 else \
           ('P7', m_max(fsub(old, calf(0xCC460)), 0.0))


def section_J():
    print('J  0x039F42 / 0x039E20 -- the writers of [0xFFFF7BE4] (gates both COPY blocks of 0x033460)')
    check(ROM[0xCBC06] == 0x01, 'CBC06')
    seen = {}
    pmax = max(v for row in T.read_table(ROM, 0xAD7A8)['values'] for v in row)   # 0.296875
    for i in range(3000):
        s = {'f6350': f32(RNG.uniform(-50, 130)), 'f8E38': f32(RNG.uniform(-40, 70)),
             'f77C8': f32(RNG.uniform(0.7, 1.3)), 'f6574': f32(RNG.uniform(-20, 320)),
             'f68D0': f32(RNG.uniform(-20, 320)), 'w67EC': RNG.randint(0, 3000),
             'f7BE4': f32(RNG.choice([0.0, 0.01, 0.03, 0.2, 0.296875, 0.5, RNG.uniform(0, 0.6)])),
             'b8E7E': RNG.choice([0, 1, 2]), 'b8E69': RNG.choice([0, 1]), 'b85D7': RNG.choice([0, 1]),
             'b7C18': RNG.choice([0, 0, 0, 1]), 'b7BEC': RNG.choice([0, 1])}
        e = run_039F42(s)
        path, want = model_039F42(s, e)
        got = e.read_f32(0xFFFF7BE4)
        check(bits(got) == bits(want), f'J {path} {s}: {got!r} want {want!r}')
        check(not (got < 0.0), f'J {path}: [7BE4] < 0')
        check(got <= max(s['f7BE4'], pmax), f'J {path}: [7BE4] above max(old, {pmax})')
        check(0x03A11C not in e.executed and 0x03A196 not in e.executed, 'J dead block executed')
        check(0.0 <= e.read_f32(0xFFFF7BF0) <= pmax and e.read_f32(0xFFFF7BF4) == 1.0, 'J table range')
        if path == 'P2':
            check(0.0 <= e.read_f32(0xFFFF7BF8) <= 1.0 and 0.0 <= e.read_f32(0xFFFF7BFC) <= 1.0, 'J P2 tables')
        seen[path] = seen.get(path, 0) + 1
    check(set(seen) == {'P1', 'P2', 'P3', 'P4', 'P5', 'P6', 'P7'}, f'J paths {seen}')
    print(f'   3000 random cases, all seven live paths {dict(sorted(seen.items()))}: bit-exact; [7BE4] never < 0;')
    print(f'   [7BE4] <= max(old, {pmax}); 0x03A11C / 0x03A196 never executed ([0x0CBC06] = 0x01)')
    # one call from 0 on P2 with every table at a non-zero cell
    s = {'f6350': 50.0, 'f8E38': 20.0, 'f77C8': 1.0, 'f6574': 100.0, 'f68D0': 100.0, 'w67EC': 2000,
         'f7BE4': 0.0, 'b8E7E': 1, 'b8E69': 0, 'b85D7': 0, 'b7C18': 0, 'b7BEC': 0}
    e = run_039F42(s)
    check(e.read_f32(0xFFFF7BE8) > calf(0xCC45C) and bits(e.read_f32(0xFFFF7BE4)) == bits(calf(0xCC45C)), 'J ramp')
    print(f'   P2 from [7BE4]=0 with [7BE8]={e.read_f32(0xFFFF7BE8):.6g}: [7BE4] -> {e.read_f32(0xFFFF7BE4):.7g} '
          f'(= [0x0CC45C]); the clamp path is not involved')
    # counterfactual: byte 0x0CBC06 = 0 reaches 0x03A196 and clamps to [[CC490],[CC494]] = [0,0]
    rom0 = bytearray(ROM); rom0[0xCBC06] = 0
    e = run_039F42(s, bytes(rom0))
    check(0x03A196 in e.executed and e.read_f32(0xFFFF7BE4) == 0.0, 'J counterfactual')
    print('   counterfactual ROM with byte 0x0CBC06 = 0: 0x03A196 runs and [7BE4] = 0.0 (the dead clamp path)')
    # 0x039E20
    for v in (0, 1, 2):
        e = E.Emu(ROM); e.ram_u8(0xFFFF65F6, v); e.ram_f32(0xFFFF7BE4, 0.25)
        e.call(0x039E20)
        if v == 1:
            check(bits(e.read_f32(0xFFFF7BE4)) == 0, 'J 039E20')
            check(written(e) == {0xFFFF7BE4, 0xFFFF7BE5, 0xFFFF7BE6, 0xFFFF7BE7, 0xFFFF7C04, 0xFFFF7C05,
                                 0xFFFF7C06}, 'J 039E20 write set')
        else:
            check(written(e) == set(), 'J 039E20 no write')
    print('   0x039E20: byte [65F6]==1 -> [7BE4] = +0.0, bytes [7C04..7C06] = 0; otherwise writes nothing')


# ================================================================ K
def model_039D1C(d8, dc, b0, b1, b2, t):
    """(new [7BD8], new [7BDC], new byte [7BE2]) from the 0x039D1C listing; t = T_0x0AD348([6364])."""
    hi = calf(0xCBF40)
    if b0 == 1 and b1 == 1 and b2 != 1:                        # 039D30-039D56
        return calf(0xCC450), m_min(calf(0xCC450), hi), 1
    if not (calf(0xCC44C) > d8):                               # 039D60 fcmp/gt fr6,fr9; 039D64-039D76
        return hi, m_min(hi, hi), 0
    if b2 != 1:
        return d8, dc, b2
    if b0 == 1:
        if b1 != 1:
            return d8, dc, b2
        n = m_max(fsub(d8, calf(0xCC454)), t)                  # 039D8A-039DA4
        return n, m_min(n, hi), b2
    n = fadd(d8, calf(0xCC458))                                # 039DA6-039DAE
    return n, m_min(n, hi), b2


def lookup(desc, x):
    e = E.Emu(ROM)
    e.call(0x0BE830, regs={4: desc}, fregs={4: x})
    return e.fr(0)


def section_K():
    print('K  0x0399EE / 0x039D1C -- the writers of [0xFFFF7BDC] (upper clamp of [77BC])')
    hi = calf(0xCBF40)
    e = E.Emu(ROM); e.ram_f32(0xFFFF7BDC, 0.3); e.call(0x0399EE)
    check(bits(e.read_f32(0xFFFF7BDC)) == bits(hi) and bits(e.read_f32(0xFFFF7BD8)) == bits(hi), 'K 0399EE')
    print(f'   0x0399EE: [7BDC] = [0x0CBF40] = {hi:.7g}; [7BD8] = [7BDC]')
    tmin = T.read_table(ROM, 0xAD348)['values'][0]
    check(bits(lookup(0xAD348, -40.0)) == bits(tmin) and tmin < calf(0xCBF3C), 'K tmin')
    n = 0
    for d8 in (0.80, tmin, 0.9, 0.97, 0.9795, f32(0.98), 0.99, hi, float('nan')):
        for dc in (0.5, hi):
            for x in (-40.0, 0.0, 10.0, 15.0, 20.0, 110.0):
                t = lookup(0xAD348, x)
                for b0 in (0, 1):
                    for b1 in (0, 1):
                        for b2 in (0, 1):
                            e = E.Emu(ROM)
                            e.ram_f32(0xFFFF7BD8, d8); e.ram_f32(0xFFFF7BDC, dc); e.ram_f32(0xFFFF6364, x)
                            e.ram_u8(0xFFFF7BE0, b0); e.ram_u8(0xFFFF7BE1, b1); e.ram_u8(0xFFFF7BE2, b2)
                            e.call(0x039D1C)
                            w8, wc, w2 = model_039D1C(f32(d8), f32(dc), b0, b1, b2, t)
                            g8, gc = e.read_f32(0xFFFF7BD8), e.read_f32(0xFFFF7BDC)
                            check(bits(g8) == bits(w8) and bits(gc) == bits(wc) and e.read_u8(0xFFFF7BE2) == w2,
                                  f'K {d8},{dc},{x},{b0}{b1}{b2}: {g8},{gc} want {w8},{wc}')
                            check(gc <= hi or (bits(gc) == bits(f32(dc)) and dc <= hi), 'K upper')
                            n += 1
    print(f'   0x039D1C: {n} cases bit-exact; every store is [0x0CBF40], min(x, [0x0CBF40]) or the old value')
    # random walk from the 0x0399EE value: [7BDC] stays in [Tmin, 1.05]
    e0 = E.Emu(ROM); e0.call(0x0399EE)
    d8, dc, b2 = e0.read_f32(0xFFFF7BD8), e0.read_f32(0xFFFF7BDC), 0
    lo_seen, hi_seen = dc, dc
    for i in range(2500):
        x = f32(RNG.uniform(-45, 115)); b0 = RNG.choice([0, 1, 1]); b1 = RNG.choice([0, 1, 1])
        e = E.Emu(ROM)
        e.ram_f32(0xFFFF7BD8, d8); e.ram_f32(0xFFFF7BDC, dc); e.ram_f32(0xFFFF6364, x)
        e.ram_u8(0xFFFF7BE0, b0); e.ram_u8(0xFFFF7BE1, b1); e.ram_u8(0xFFFF7BE2, b2)
        e.call(0x039D1C)
        d8, dc, b2 = e.read_f32(0xFFFF7BD8), e.read_f32(0xFFFF7BDC), e.read_u8(0xFFFF7BE2)
        check(tmin <= dc <= hi and tmin <= d8, f'K walk {i}: [7BDC]={dc} [7BD8]={d8}')
        lo_seen, hi_seen = min(lo_seen, dc), max(hi_seen, dc)
    check(lo_seen == tmin, 'K walk reached the table minimum')
    print(f'   random walk of 2500 calls from the 0x0399EE state: [7BDC] in [{lo_seen:.7g}, {hi_seen:.7g}];'
          f' the floor {tmin!r} is below [0x0CBF3C] = {calf(0xCBF3C)!r}')


# ================================================================ L
def model_0342A8(f6540, f77C8, b7448, b7865, b7828, f7814, f7818):
    out = {}
    r6 = 0xFF
    if b7448 != 1:                                               # 0342C2 bf/s 0x034322
        if b7828 == 1:
            out[0xFFFF7814] = 0.0
        r6 = 4
    elif b7865 != 0:                                             # 0342CA bf 0x034302
        if not (calf(0xCC004) > f7818):
            r6 = 2
        elif calf(0xCC008) > f7818:
            r6 = 3
        else:
            r6 = 4
    elif b7828 == 1:                                             # 0342D4
        d = fsub(f6540, f77C8)
        out[0xFFFF7814] = 0.0 if calf(0xCC000) > m_absdiff(d, 0.0) else d
        r6 = 1
    if r6 == 1:
        out[0xFFFF7818] = out[0xFFFF7814]; out[0xFFFF782A] = 1
    elif r6 == 2:
        out[0xFFFF7818] = m_max(fsub(f7818, calf(0xCC00C)), 0.0)
    elif r6 == 3:
        out[0xFFFF7818] = m_min(fadd(f7818, calf(0xCC00C)), 0.0)
    elif r6 == 4:
        out[0xFFFF7818] = 0.0
    out[0xFFFF7865] = b7448
    return out


def section_L():
    print('L  0x021D7C (second [6540] writer), 0x0342A8 ([7814]/[7818]), 0x0043EE ([4090]), 0x021A3C gate')
    e = E.Emu(ROM); e.ram_u8(0xFFFF6554, 0x5A)
    for a in (0xFFFF653C, 0xFFFF6540, 0xFFFF6544, 0xFFFF6548, 0xFFFF654C):
        e.ram_f32(a, 0.5)
    e.call(0x021D7C)
    exp = {0xFFFF655A}
    for a in (0xFFFF653C, 0xFFFF6540, 0xFFFF6544, 0xFFFF6548, 0xFFFF654C):
        check(e.read_f32(a) == 1.0, 'L 021D7C'); exp |= {a, a + 1, a + 2, a + 3}
    check(e.read_u8(0xFFFF655A) == 0x5A and written(e) == exp, 'L 021D7C write set')
    print('   0x021D7C: [653C]=[6540]=[6544]=[6548]=[654C]=1.0, byte [655A] = byte [6554]; nothing else')
    n = 0
    for b7448 in (0, 1):
        for b7865 in (0, 1):
            for b7828 in (0, 1):
                for d in (0.5, 1.99, 2.0, 2.5, -2.5):
                    for f7818 in (-25.0, -3.0, -0.5, 0.0, 5.0, 19.9, 20.0, 25.0, float('nan')):
                        e = E.Emu(ROM)
                        e.ram_f32(0xFFFF6540, f32(1.0 + d)); e.ram_f32(0xFFFF77C8, 1.0)
                        e.ram_u8(0xFFFF7448, b7448); e.ram_u8(0xFFFF7865, b7865); e.ram_u8(0xFFFF7828, b7828)
                        e.ram_f32(0xFFFF7814, 7.0); e.ram_f32(0xFFFF7818, f7818); e.ram_u8(0xFFFF782A, 0)
                        e.call(0x0342A8)
                        want = model_0342A8(f32(1.0 + d), 1.0, b7448, b7865, b7828, 7.0, f32(f7818))
                        expw = set()
                        for a, v in want.items():
                            if a in (0xFFFF782A, 0xFFFF7865):
                                check(e.read_u8(a) == v, f'L 0342A8 byte {a:08X}'); expw.add(a)
                            else:
                                check(bits(e.read_f32(a)) == bits(v), f'L 0342A8 {a:08X} {e.read_f32(a)} {v}')
                                expw |= {a, a + 1, a + 2, a + 3}
                        check(written(e) == expw, f'L 0342A8 write set {b7448}{b7865}{b7828} {d} {f7818}')
                        n += 1
    print(f'   0x0342A8: {n} cases bit-exact incl. write set. Capture needs byte [7448]==1, [7865]==0, [7828]==1;')
    print(f'             then [7818] in [[CC008]={calf(0xCC008):g}, [CC004]={calf(0xCC004):g}) -> 0, >= 20 -> '
          f'max(x-{calf(0xCC00C):g},0), < 0 -> min(x+{calf(0xCC00C):g},0)')
    for v in (0, 1, 2, 4, 8, 12, 13, 255):
        e = EmuIO(ROM)
        for i in range(0, 0x18, 2):
            e.mmios[0xFFFFF820 + i] = 0x2000 + i
        e.ram_u8(0xFFFF40AD, v)
        e.call(0x0043EE)
        k = {12: 12, 8: 8, 4: 4, 1: 1}.get(v, 0)
        exp = set(range(0xFFFF407C, 0xFFFF407C + 2 * k))
        check(written(e) == exp, f'L 0043EE {v}: {sorted(hex(x) for x in written(e) ^ exp)}')
        if v == 12:
            check(e.read_u16(0xFFFF4090) == 0x2014, 'L 0043EE F834 -> 4090')
    print('   0x0043EE: byte [40AD] = 12/8/4/1 copies 12/8/4/1 words from 0xFFFFF820 to 0xFFFF407C; '
          '[4090] <- F834 only when 12')
    # 0x021A3C byte gate: counterfactual ROM with byte 0x0C0354 = 0xFF takes the lag path even when [65F6]==1
    check(ROM[0xC0354] == 0x00, 'C0354')
    for rom, tag in ((ROM, '20.19c'), (bytes(ROM[:0xC0354]) + b'\xff' + bytes(ROM[0xC0355:]), 'C0354=FF')):
        e = E.Emu(rom); e.stub(0x02F8EA, r0=0)
        e.ram_u8(0xFFFF5C44, 1); e.ram_f32(0xFFFF6898, 101.3); e.ram_f32(0xFFFF8DE4, 1.2)
        e.ram_u8(0xFFFF65F6, 1); e.ram_u8(0xFFFF6555, 0)
        for a in (0xFFFF653C, 0xFFFF6540, 0xFFFF6544, 0xFFFF6548, 0xFFFF654C):
            e.ram_f32(a, 0.5)
        e.call(0x021A3C)
        v = e.read_f32(0xFFFF6540)
        if tag == '20.19c':
            check(v == 1.0, 'L 021A3C gate 20.19c')
        else:
            check(v != 1.0 and v > 0.5, 'L 021A3C gate counterfactual')
        print(f'   0x021A3C with byte [65F6]==1, ROM {tag}: [6540] = {v:.6g}')


# ================================================================ M (independent audit, 2026-11-27)
STOCK_PATH = os.path.join(REPO, 'rom', 'ae5l600l.bin')
STOCK = open(STOCK_PATH, 'rb').read()


def fmac(a, b, c):                   # FMAC FR0,FRm,FRn: FRn = FR0*FRm + FRn, one rounding (RZ)
    if not all(math.isfinite(x) for x in (a, b, c)):
        return a * b + c
    return _rz(Fraction(a) * Fraction(b) + Fraction(c), a * b + c)


def lut1(desc, x, rom=None):
    e = E.Emu(rom or ROM)
    e.call(0x0BE830, regs={4: desc}, fregs={4: x})
    return e.fr(0)


def lut2(desc, x4, x5, rom=None):
    e = E.Emu(rom or ROM)
    e.call(0x0BE8E4, regs={4: desc}, fregs={4: x4, 5: x5})
    return e.fr(0)


M_IN_F = {0xFFFF6624: 'f6624', 0xFFFF6350: 'f6350', 0xFFFF63F8: 'f63F8', 0xFFFF68DC: 'f68DC',
          0xFFFF78B0: 'f78B0', 0xFFFF65FC: 'f65FC', 0xFFFF780C: 'f780C'}
M_IN_B = {0xFFFF8E7E: 'b8E7E', 0xFFFF85D7: 'b85D7', 0xFFFF7871: 'b7871'}


def model_0340A0(s, rom=None):
    """0x0340A0 from its listing: returns {addr: value} of every RAM cell it writes."""
    rom = rom or ROM
    cf = lambda a: struct.unpack('>f', rom[a:a + 4])[0]      # noqa: E731
    A = s['b8E7E']
    if A != 1:                                                       # 0340DC bt/s; 0340E0 bra 0x03427E
        return {0xFFFF7810: 0.0, 0xFFFF7804: 0.0, 0xFFFF7808: 0.0, 0xFFFF7871: A}
    t = {0xFFFF7838: lut1(0xACEA0, s['f6350'], rom), 0xFFFF783C: lut1(0xACEB4, s['f68DC'], rom),
         0xFFFF7840: lut1(0xAC4FC, s['f78B0'], rom), 0xFFFF7844: lut2(0xAD928, s['f63F8'], s['f6624'], rom),
         0xFFFF7848: lut1(0xACEC8, s['f6350'], rom), 0xFFFF784C: lut1(0xACEDC, s['f68DC'], rom),
         0xFFFF7850: lut1(0xAC510, s['f78B0'], rom)}
    p04 = fmul(fadd(t[0xFFFF7838], t[0xFFFF783C]), t[0xFFFF7840])                     # 034132-034144
    p08 = fmul(fadd(fadd(t[0xFFFF7844], t[0xFFFF7848]), t[0xFFFF784C]), t[0xFFFF7850])  # 034146-03415E
    on = s['b85D7'] == 1 and cf(0xCBFF4) > s['f65FC']               # 034176 / 034234 fcmp/gt fr9,fr8
    if s['b7871'] == 0:                                              # 034164 tst; 034166 bf/s
        c = 1.0 if on else 0.0                                       # 03417A fldi1 / 034182 fldi0
    elif on:
        c = m_min(fadd(s['f780C'], cf(0xCBFF8)), 1.0)                # 034238-03424C
    else:
        c = m_max(fsub(s['f780C'], cf(0xCBFFC)), 0.0)                # 03424E-034260
    r = fmac(fsub(1.0, c), p08, fmul(p04, c))                        # 034262-03427C
    out = dict(t)
    out.update({0xFFFF7804: p04, 0xFFFF7808: p08, 0xFFFF780C: c, 0xFFFF7810: r, 0xFFFF7871: A})
    return out


def run_0340A0(s, e=None, rom=None):
    e = e or E.Emu(rom or ROM)
    for a, k in M_IN_F.items():
        e.ram_f32(a, s[k])
    for a, k in M_IN_B.items():
        e.ram_u8(a, s[k])
    e.call(0x0340A0)
    return e


def max_6540(rom):
    """Largest / smallest [6540] that 0x058902 -> 0x021A3C (copy branch) can produce, over the axis
    breakpoints, midpoints and out-of-range points of both tables."""
    ax = T.read_table(rom, 0xAF468)['axes']['x']; cax = T.read_table(rom, 0xAAE8C)['axes']['x']
    xs = [ax[0] - 100.0] + list(ax) + [ax[-1] + 100.0] + [(a + b) / 2 for a, b in zip(ax, ax[1:])]
    ps = [cax[0] - 100.0] + list(cax) + [cax[-1] + 100.0] + [(a + b) / 2 for a, b in zip(cax, cax[1:])]
    hi = lo = None
    for x in xs:
        for p in ps:
            e = E.Emu(rom); e.stub(0x02F8EA, r0=1)
            e.ram_f32(0xFFFF40E0, f32(x)); e.call(0x058902)
            e.ram_u8(0xFFFF5C44, 1); e.ram_f32(0xFFFF6898, f32(p)); e.ram_u8(0xFFFF65F6, 0)
            e.ram_u8(0xFFFF6555, 0)
            e.call(0x021A3C)
            v = e.read_f32(0xFFFF6540)
            hi = v if hi is None or v > hi else hi
            lo = v if lo is None or v < lo else lo
    return lo, hi


def section_M():
    print('M  AUDIT: 0x0340A0 (writer of [7810]), the SPECIAL exit in this calibration, the [6540] / [77C8]')
    print('   bounds that make the [77CC] and [7814] captures unreachable, stock vs 20.19c')
    # M1 0x0340A0 contract, bit-exact incl. write set
    n = 0
    seen = set()
    for A in (0, 1, 2):
        for prev in (0, 1):
            for b85 in (0, 1):
                for spd in (0.0, 3.9, 4.0, 60.0):
                    for c0 in (0.0, 0.3, 1.0):
                        s = {'f6624': f32(RNG.uniform(500, 6500)), 'f6350': f32(RNG.uniform(-45, 120)),
                             'f63F8': f32(RNG.uniform(0.1, 1.8)), 'f68DC': f32(RNG.uniform(0.4, 1.6)),
                             'f78B0': f32(RNG.uniform(-100, 11000)), 'f65FC': spd, 'f780C': c0,
                             'b8E7E': A, 'b85D7': b85, 'b7871': prev}
                        e = run_0340A0(s)
                        want = model_0340A0(s)
                        exp = set()
                        for a, v in want.items():
                            if a == 0xFFFF7871:
                                check(e.read_u8(a) == v, f'M1 byte 7871 A={A}'); exp.add(a)
                            else:
                                check(bits(e.read_f32(a)) == bits(v), f'M1 {a:08X} {e.read_f32(a)!r} {v!r} {s}')
                                exp |= {a, a + 1, a + 2, a + 3}
                        check(written(e) == exp, f'M1 write set {sorted(hex(x) for x in written(e) ^ exp)}')
                        if A == 1:
                            # 20.19c tables: [7804] = 0.20001220703125, [7808] = 0.0 at any input
                            check(bits(e.read_f32(0xFFFF7804)) == bits(0.20001220703125)
                                  and bits(e.read_f32(0xFFFF7808)) == 0, 'M1 20.19c products')
                            check(e.read_f32(0xFFFF780C) in (0.0, 1.0), 'M1 [780C] binary')
                            seen.add((e.read_f32(0xFFFF780C), e.read_f32(0xFFFF7810)))
                        n += 1
    check(seen == {(0.0, 0.0), (1.0, 0.20001220703125)}, f'M1 seen {seen}')
    print(f'   M1 0x0340A0: {n} cases bit-exact incl. write set. A = byte[8E7E] != 1 -> [7804]=[7808]=[7810]=0;')
    print('      A == 1 -> [7810] = [7804]*[780C] + (1-[780C])*[7808] (fmac), [780C] = 0/1 on the first A==1 call,')
    print(f'      then +-[CBFF8]={calf(0xCBFF8):g}/[CBFFC]={calf(0xCBFFC):g} within [0,1]; "on" = byte[85D7]==1 and '
          f'[CBFF4]={calf(0xCBFF4):g} > [65FC]')
    print(f'      20.19c/stock tables: [7804] = 0.20001220703125, [7808] = 0 -> [7810] in {sorted(x[1] for x in seen)}')
    # M2 composition: 0x0340A0 then 0x033460 SPECIAL exit -> [77C8] in {1.0, 1.2}
    got = {}
    for b85 in (0, 1):
        for spd in (0.0, 3.9, 4.0, 60.0):
            for prev in (0, 1):
                for p in (-0.10, 0.0, 0.10):
                    s = {'f6624': 2500.0, 'f6350': 85.0, 'f63F8': 0.5, 'f68DC': 1.0, 'f78B0': 3000.0,
                         'f65FC': spd, 'f780C': 0.0 if prev else 0.5, 'b8E7E': 1, 'b85D7': b85, 'b7871': prev}
                    e = run_0340A0(s)
                    st = base_state(); st.update({'b8E7E': 1, 'b7BEC': 0, 'b9720': 0, 'p7904': f32(p),
                                                  'f7810': e.read_f32(0xFFFF7810), 'f7818': 0.0,
                                                  'f7BDC': calf(0xCBF40)})
                    br, want, e2 = compare_033460(st, f'M2 {b85} {spd} {prev} {p}')
                    check(br == 'special', 'M2 branch')
                    v = e2.read_f32(0xFFFF77C8)
                    on = b85 == 1 and calf(0xCBFF4) > spd
                    check(bits(v) == bits(calf(0xCBF54) if on else 1.0), f'M2 [77C8]={v!r} on={on}')
                    got[on] = v
    print(f'   M2 0x0340A0 -> 0x033460 SPECIAL ([7818]=0): [77C8] = {got[True]!r} (x14.7 = {got[True] * 14.7:.2f}) when '
          f'byte[85D7]==1 and [65FC] < {calf(0xCBFF4):g}, else {got[False]!r}; independent of [7904]')
    # M3 the [6540] range in both bins
    lo19, hi19 = max_6540(ROM)
    los, his = max_6540(STOCK)
    check(abs(hi19 - 1.7586088) < 1e-6 and abs(his - 1.5310320) < 1e-6 and lo19 == 0.75 and los == 0.75, 'M3 range')
    print(f'   M3 [6540] reachable through 0x058902 -> 0x021A3C: 20.19c [{lo19:.7g}, {hi19:.7g}], stock [{los:.7g}, {his:.7g}]')
    print('      (front-O2 scaling max 1.3793103 x atm compensation max 2.0 (20.19c) / 1.4 (stock)); the lag path')
    e = E.Emu(ROM); e.stub(0x02F8EA, r0=0)
    for a in (0xFFFF653C, 0xFFFF6540, 0xFFFF6544, 0xFFFF6548, 0xFFFF654C):
        e.ram_f32(a, f32(hi19))
    e.ram_u8(0xFFFF5C44, 1); e.ram_u8(0xFFFF65F6, 0); e.ram_u8(0xFFFF6555, 0)
    e.ram_f32(0xFFFF6898, T.read_table(ROM, 0xAAE8C)['axes']['x'][0])
    e.ram_f32(0xFFFF8DE4, max(T.read_table(ROM, 0xAF468)['values']))
    for i in range(20):
        e.call(0x021A3C)
        check(e.read_f32(0xFFFF6540) <= hi19, 'M3 lag stays <= max')
    print(f'      (lag of L and the old value) cannot exceed it: 20 lag calls from {hi19:.7g} stay <= {hi19:.7g}')
    # M4 [77C8] lower bound over every 0x033460 exit: >= Tmin once [7BDC] is a stored value, >= 0.75 always
    tmin = T.read_table(ROM, 0xAD348)['values'][0]
    low_stored = low_any = 9.0
    for i in range(3000):
        s = base_state()
        for k in ADD.values():
            s[k] = f32(RNG.uniform(-2.0, 2.0))
        stored = i % 2 == 0
        s.update({'b8E7E': RNG.choice([0, 1, 1]), 'b7BEC': RNG.choice([0, 1]), 'b9720': RNG.choice([0, 0, 1]),
                  'old77C4': RNG.choice([f32(RNG.uniform(-50, 50)), float('nan'), float('inf'), -float('inf')]),
                  'old77BC': f32(RNG.uniform(0.75, 1.25)), 'f7810': RNG.choice([0.0, 0.20001220703125]),
                  'f7818': 0.0, 'f63C4': f32(RNG.uniform(0, 5)), 'f68D8': f32(RNG.uniform(0, 5)),
                  'f7BDC': f32(RNG.uniform(tmin, calf(0xCBF40))) if stored else
                  RNG.choice([f32(RNG.uniform(-5, 5)), float('nan'), 0.0])})
        br, want, e = compare_033460(s, f'M4 {i}')
        v = e.read_f32(0xFFFF77C8)
        check(0.75 <= v <= 1.25, f'M4 [77C8]={v!r} outside [0.75, 1.25] ({br})')
        low_any = min(low_any, v)
        if stored:
            check(v >= tmin, f'M4 [77C8]={v!r} < Tmin with a stored [7BDC] ({br})')
            low_stored = min(low_stored, v)
    print(f'   M4 3000 random 0x033460 calls (all exits, [77C4] incl. +-inf / NaN): [77C8] always in [0.75, 1.25];')
    print(f'      with [7BDC] a stored value (in [{tmin!r}, 1.05]) min seen {low_stored!r} >= {tmin!r}')
    # M5 the two captures at their worst case
    d_max = fsub(f32(hi19), tmin)
    check(d_max < calf(0xCBF6C) and d_max < calf(0xCC000), 'M5 bound')
    rows = []
    for d6540, d77C8, tag in ((f32(hi19), tmin, 'worst case 20.19c'),
                              (fadd(tmin, 1.0), tmin, 'counterfactual [6540] = [77C8] + 1.0')):
        e = emu(); e.stub(0x022CF4, r0=0)
        e.ram_f32(0xFFFF6350, 20.0); e.ram_u8(0xFFFF6254, 0); e.ram_u8(0xFFFF65C0, 0)
        e.ram_f32(0xFFFF6540, d6540); e.ram_u8(0xFFFF7448, 1)
        e.ram_f32(0xFFFF77C8, d77C8); e.ram_f32(0xFFFF77CC, 0.0)
        e.ram_u8(0xFFFF7828, 0); e.ram_u8(0xFFFF782A, 0); e.ram_u8(0xFFFF7864, 0)
        e.call(0x033658, regs={4: 0x063A3C, 5: 0x063A2C, 6: 0})
        rows.append((tag, e.read_f32(0xFFFF77CC)))
    check(rows[0][1] == 0.0 and rows[1][1] >= 1.0, f'M5 0x033658 {rows}')
    e = E.Emu(ROM)
    e.ram_f32(0xFFFF6540, f32(hi19)); e.ram_f32(0xFFFF77C8, 0.75)
    e.ram_u8(0xFFFF7448, 1); e.ram_u8(0xFFFF7865, 0); e.ram_u8(0xFFFF7828, 1)
    e.ram_f32(0xFFFF7814, 7.0); e.ram_f32(0xFFFF7818, 7.0)
    e.call(0x0342A8)
    check(bits(e.read_f32(0xFFFF7814)) == 0 and bits(e.read_f32(0xFFFF7818)) == 0, 'M5 0x0342A8')
    for tag, v in rows:
        print(f'   M5 0x033658 edge, {tag:38s}: [77CC] = {v!r}')
    print(f'      max([6540]) - Tmin = {d_max:.7g} < [CBF6C] = 1.0 (and < [CC000] = 2.0): neither capture can fire;')
    print('      0x0342A8 at [6540] = max, [77C8] = 0.75 (largest |d| of all): [7814] = [7818] = 0')
    # the counterfactual capture would not give a bumpless target: the sum is clamped at [7BDC]
    s = base_state(); s.update({'b9720': 1, 'a77CC': rows[1][1], 'f7BDC': calf(0xCBF40)})
    br, want, e = compare_033460(s, 'M5 pin')
    check(bits(e.read_f32(0xFFFF77BC)) == bits(calf(0xCBF40)), 'M5 pinned at [7BDC]')
    print(f'      with that counterfactual [77CC] = {rows[1][1]:.7g}, 0x033460 gives [77BC] = {e.read_f32(0xFFFF77BC):.7g} '
          '= [7BDC] (pinned at the ceiling, not [6540] + ...)')
    # M6 stock vs 20.19c over every cal word and table this file's functions read
    same_tables = (0xAD89C, 0xAD880, 0xAD8D4, 0xAD90C, 0xACEA0, 0xACEB4, 0xAC4FC, 0xAD928, 0xACEC8, 0xACEDC,
                   0xAC510, 0xAD35C, 0xAD348, 0xAD7A8, 0xAC774, 0xAC788, 0xAC79C, 0xACE6C, 0xACE8C, 0xAD63C,
                   0xAD658, 0xAC4E8, 0xAF468)
    for a in same_tables:
        t1, t2 = T.read_table(ROM, a), T.read_table(STOCK, a)
        check(t1['values'] == t2['values'] and t1['axes'] == t2['axes'], f'M6 table {a:X} differs')
    for lo_, hi_ in ((0xCBF3C, 0xCC020), (0xCC44C, 0xCC498), (0xCBBD8, 0xCBBE4), (0xCBC06, 0xCBC07),
                     (0xCBC32, 0xCBC38), (0xC0354, 0xC0355), (0xC3184, 0xC3190), (0xCBBDF, 0xCBBE0)):
        check(ROM[lo_:hi_] == STOCK[lo_:hi_], f'M6 cal {lo_:X}..{hi_:X} differs')
    diff = {}
    for a in (0xAD8B8, 0xAD8F0, 0xAAE8C):
        t1, t2 = T.read_table(ROM, a), T.read_table(STOCK, a)
        if t1['dim'] == '1D':
            cells = [(i, x, y) for i, (x, y) in enumerate(zip(t1['values'], t2['values'])) if x != y]
        else:
            cells = [((i, j), x, y) for i, (r1, r2) in enumerate(zip(t1['values'], t2['values']))
                     for j, (x, y) in enumerate(zip(r1, r2)) if x != y]
        diff[a] = cells
    check(len(diff[0xAD8B8]) == 8 and len(diff[0xAD8F0]) == 4 and len(diff[0xAAE8C]) == 1, f'M6 diff counts')
    check(all(x < y for c in (diff[0xAD8B8], diff[0xAD8F0]) for _, x, y in c), 'M6 20.19c cells lower')
    print(f'   M6 stock vs 20.19c: {len(same_tables)} tables and the cal ranges read here are byte-identical; three tables differ:')
    for a, nm in ((0xAD8B8, 'CL Fueling Target Compensation A (Load)'), (0xAD8F0, '... B (Load)'),
                  (0xAAE8C, 'Front Oxygen Sensor Compensation (Atm. Pressure)')):
        lo_d = min(x - y for _, x, y in diff[a]); hi_d = max(x - y for _, x, y in diff[a])
        print(f'      {a:06X} {nm}: {len(diff[a])} cells, 20.19c - stock in [{lo_d:+.6f}, {hi_d:+.6f}]')
    # M7 0x039E6E (runs just before 0x039F42, from 0x039E16): byte [7BEC] is cleared on every call
    check(calf(0xCC488) == 0.0 and calf(0xCC480) == 0.0 and calf(0xCC484) == 0.0, 'M7 cal')
    n = 0
    for i in range(400):
        e = E.Emu(ROM); e.stub(0x023E48, r0=RNG.choice([0, 1]))
        e.ram_f32(0xFFFF653C, f32(RNG.uniform(0.75, hi19)) if i % 4 else RNG.choice([0.75, 1.0, f32(hi19)]))
        e.ram_f32(0xFFFF6354, f32(RNG.uniform(-40, 120))); e.ram_f32(0xFFFF63C4, f32(RNG.uniform(-1, 5)))
        e.ram_u16(0xFFFF67EC, RNG.randint(0, 0xFFFF)); e.ram_u8(0xFFFF7448, RNG.choice([0, 1]))
        e.ram_u8(0xFFFF8E7E, RNG.choice([0, 1])); e.ram_f32(0xFFFF7BE4, f32(RNG.uniform(0, 200)))
        e.ram_u8(0xFFFF7BEC, 1); e.ram_u8(0xFFFF7C05, RNG.choice([0, 1])); e.ram_u8(0xFFFF7C06, RNG.choice([0, 1]))
        e.ram_u16(0xFFFF7C02, RNG.randint(0, 0xFFFF))
        e.call(0x039E6E)
        check(e.read_u8(0xFFFF7BEC) == 0, 'M7 [7BEC] not cleared')
        check(e.read_u8(0xFFFF7C04) == 0 and e.read_u8(0xFFFF7C05) == 0, 'M7 [7C04]/[7C05] set')
        n += 1
    rom1 = bytearray(ROM); rom1[0xCC488:0xCC48C] = bytes.fromhex('40000000')      # 2.0 > [653C]
    e = E.Emu(bytes(rom1)); e.stub(0x023E48, r0=1)
    e.ram_f32(0xFFFF653C, 1.0); e.ram_u8(0xFFFF7BEC, 1); e.ram_u8(0xFFFF7C06, 1)
    e.call(0x039E6E)
    check(e.read_u8(0xFFFF7BEC) == 1, 'M7 counterfactual')
    print(f'   M7 0x039E6E: {n} random calls with byte [7BEC] = 1 beforehand and [653C] in [0.75, {hi19:.7g}]: [7BEC] = 0')
    print(f'      every time (039F0C fcmp/gt fr15,fr8: T = [CC488] = {calf(0xCC488):g} > [653C], never; 039F14 stores 0);')
    print('      counterfactual [CC488] = 2.0: [7BEC] keeps its old value. So with byte [8E7E] == 1 and [9720] == 0,')
    print('      0x033460 takes SPECIAL, never COPY2, once 0x039E16 has run')


def main():
    for sec in (section_A, section_B, section_C, section_D, section_E, section_F, section_G,
                section_H, section_I, section_J, section_K, section_L, section_M):
        sec()
    print(f'ALL OK  ({NCHECK} assertions)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
