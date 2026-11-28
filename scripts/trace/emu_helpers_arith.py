#!/usr/bin/env python3
"""Emulation check for the runtime helper library 0x0BE4FA..0x0BE81B (2026-11-27).

    python3 scripts/trace/emu_helpers_arith.py            # prints tables, exits 0 when every contract holds
    python3 scripts/trace/emu_helpers_arith.py --quiet    # summary lines only

Companion of disassembly/analysis/helpers_arith_trace.txt.  Each of the 13 leaf
helpers is executed by scripts/sh2e_emu.py on the reference bin over a grid that
includes the edges, and every result is asserted against a model written from
the BYTES (not from any label):

  0BE4FA  step lookup   r0 = u8 values[i], i = highest index with NOT(thr[i] > fr4), else values[0]
  0BE524  r0 = sat_s32(r4 + r5)
  0BE53C  r0 = min(u8(r4) + u8(r5), 0xFF)
  0BE554  r0 = min(u16(r4) + u16(r5), 0xFFFF)
  0BE56C  fr0 = fr5 if NOT(fr4 > fr5) else (fr4 if fr6 > fr4 else fr6)
  0BE588  fr0 = fr4 * float(u8(r4))  + fr5
  0BE598  fr0 = fr4 * float(u16(r4)) + fr5
  0BE5A8  r0 = clamp(trunc((fr4 - fr6) / fr5 + 0.5), 0, 0xFF)
  0BE5D8  r0 = clamp(trunc((fr4 - fr6) / fr5 + 0.5), 0, 0xFFFF)
  0BE608  r0 = 1 if (fr5 - fr6) > fr4 or fr4 > (fr5 + fr6) else 0
  0BE628  fr0 = fr4 / fr5, or 0 / +-FLT_MAX when fr5 == 0
  0BE654  r0 = saturating signed (r4 << 16) / r5
  0BE800  r0 = 1 if NOT(fr5 > fr4); 0 if (fr5 - fr6) > fr4; else r4 unchanged

WHAT THIS DOES AND DOES NOT PROVE
* Every call is made twice with two different "poison" patterns in every register
  that is not a declared input.  Identical outputs prove the routine reads nothing
  but its declared inputs on the paths exercised; the registers that come back
  changed are the observed clobber set.
* The float model is exact rational arithmetic rounded to float32, in a stated mode.
  WHICH MODE THE FIRMWARE EXPECTS IS DECIDED FROM ROM BYTES (t_selftest, run first):
  the ECU's own CPU self-test at 0x058696..0x0586DE executes fmac, fmul and fdiv on
  inexact operands and demands bit-equality with ROM constants 0x0587E8 / 0x0587EC.
  In exact arithmetic only TRUNCATION (round toward zero) satisfies those compares;
  round-to-nearest fails three of them.  Every emulated float result is asserted
  BIT-EXACT against the model in CHIP_MODE = 'RZ' (each operation rounded once
  toward zero; fmac fused: f0*fm + fn exact, then one truncation) -- what the chip
  does.  t_selftest also measures which model the emulator matches on the self-test
  operands and fails unless it is CHIP_MODE.  (Until 2026-11-27 scripts/sh2e_emu.py
  rounded to NEAREST and failed the ECU's test; corrections item 106 fixed it.  This
  script was written against that emulator and asserted in whatever mode it
  measured; it now asserts the chip's mode and nothing else.)
  The round-to-nearest model ('RN', ALT_MODE) is evaluated BESIDE the assertion, never
  asserted: it counts how many grid results a nearest-rounding model -- the old
  emulator, or Python float arithmetic -- would get wrong.
  Limits of that byte evidence: the self-test's inexact cases are fmac/fmul/fdiv on
  POSITIVE operands; fadd/fsub are only exercised exactly; a fused and an unfused
  truncating fmac both give the expected constant.  So "fadd/fsub truncate too" and
  "toward zero rather than toward minus infinity" are extensions, and fused-vs-
  unfused is open (the emulator is fused; the script counts where an unfused
  truncating fmac would differ).
* The counts of grid cases where round-to-nearest gives a different answer are
  properties of THE GRID (how many inputs it happens to place on a rounding edge),
  not rates.  The script prints them for two different grids per routine to make
  that visible.
* Rows marked EMU-MODEL (fdiv by zero, ftrc of Inf/NaN, NaN compares) depend on FPU
  special-case behaviour the emulator models from the manual; they are asserted
  only against the emulator's own stated model.  One of them has byte support: the
  same self-test (0x058712..0x05873A) requires 0.0/0.0 to compare unordered and to
  set FPSCR bit 6.  The emulator does not model FPSCR flags and fails that check --
  the only one of the self-test's failed-check stores it reaches (asserted).
"""
import hashlib
import os
import random
import struct
import sys
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, 'scripts'))
import sh2e_emu as E  # noqa: E402

BIN = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
MD5 = '92cae8275cd4f9b473a3a9e36efe6449'
ROM = open(BIN, 'rb').read()
QUIET = '--quiet' in sys.argv
M32 = 0xFFFFFFFF
INF = float('inf')
NAN = float('nan')
FLT_MAX_BITS = 0x7F7FFFFF

random.seed(20261127)
TOTAL = {}          # entry -> emulated call count (each grid case = 2 poisoned runs)
STATS = {}          # entry -> grid counts quoted in helpers_arith_trace.txt
CLOBBER = {}        # entry -> set of register names observed changed
FAIL = []


def out(*a):
    if not QUIET:
        print(*a)


def s32(x):
    x &= M32
    return x - (1 << 32) if x >> 31 else x


def fb(f):
    """python float -> float32 bits (round to nearest)."""
    return struct.unpack('>I', struct.pack('>f', f))[0]


def bf(b):
    return struct.unpack('>f', struct.pack('>I', b & M32))[0]


# ----------------------------------------------------------------------------
# exact float32 model.  A value is a Fraction (finite), +-INF or NAN.
# ----------------------------------------------------------------------------
def val(bits):
    f = bf(bits)
    if f != f:
        return NAN
    if f in (INF, -INF):
        return f
    return Fraction(f)


def is_special(v):
    return isinstance(v, float)


def rnd(q, mode):
    """Round an exact rational to float32.  mode 'RN' nearest-even, 'RZ' toward zero,
    'RA' away from zero (used only to show that rounding UP fails the ROM self-test).
    Underflow below the smallest normal flushes to zero (SH-2E has no denormals)."""
    if is_special(q):
        return q
    if q == 0:
        return Fraction(0)
    neg = q < 0
    a = -q if neg else q
    e = a.numerator.bit_length() - a.denominator.bit_length()
    if Fraction(2) ** e > a:
        e -= 1
    if e < -126:
        return Fraction(0)
    scaled = a / (Fraction(2) ** (e - 23))
    m = scaled.numerator // scaled.denominator
    rem = scaled - m
    if mode == 'RN':
        if rem > Fraction(1, 2) or (rem == Fraction(1, 2) and (m & 1)):
            m += 1
    elif mode == 'RA':
        if rem > 0:
            m += 1
    if m == 1 << 24:
        m = 1 << 23
        e += 1
    if e > 127:
        if mode in ('RN', 'RA'):
            return -INF if neg else INF
        m, e = (1 << 24) - 1, 127
    r = Fraction(m) * (Fraction(2) ** (e - 23))
    return -r if neg else r


def f_add(a, b, mode):
    if is_special(a) or is_special(b):
        return float(a) + float(b)
    return rnd(a + b, mode)


def f_sub(a, b, mode):
    if is_special(a) or is_special(b):
        return float(a) - float(b)
    return rnd(a - b, mode)


def f_div(a, b, mode, b_neg_zero=False):
    """EMU-MODEL for b == 0: x/0 = +-Inf, 0/0 = NaN (exceptions disabled)."""
    if is_special(a) or is_special(b):
        return NAN
    if b == 0:
        if a == 0:
            return NAN
        return -INF if (a < 0) != b_neg_zero else INF
    return rnd(a / b, mode)


def f_gt(a, b):
    """fcmp/gt: T = a > b, false when unordered."""
    if (is_special(a) and a != a) or (is_special(b) and b != b):
        return False
    return a > b


def f_trc(a):
    """ftrc: truncate toward zero, saturating.  EMU-MODEL for Inf/NaN/out of range."""
    if is_special(a):
        if a != a:
            return 0x80000000
        return 0x7FFFFFFF if a > 0 else 0x80000000
    if a >= 2 ** 31:
        return 0x7FFFFFFF
    if a < -2 ** 31:
        return 0x80000000
    n = abs(a.numerator) // a.denominator
    return (-n if a < 0 else n) & M32


def same_float(emu_bits, model):
    """emulator float32 bits vs model value; +0 and -0 compare equal."""
    e = bf(emu_bits)
    if is_special(model):
        if model != model:
            return e != e
        return e == model
    return e == e and e not in (INF, -INF) and Fraction(e) == model


# ----------------------------------------------------------------------------
# the harness: run with two poison patterns, demand identical outputs
# ----------------------------------------------------------------------------
POISON = (0xA5A50000, 0x3C3C0000)
FPOISON = (fb(1234.5), fb(-0.0078125))
EMU = E.Emu(ROM)


def run(entry, regs=None, fregs=None, outs=('r0',), setup=None):
    """regs: {n: value}; fregs: {n: float32 BITS}.  Returns dict of outputs."""
    regs = regs or {}
    fregs = fregs or {}
    results = []
    for k in range(2):
        emu = EMU
        for i in range(15):
            emu.R[i] = (POISON[k] + i * 0x0101) & M32
        for i in range(16):
            emu.FR[i] = FPOISON[k] ^ (i << 8)
        emu.fpul = POISON[k] ^ 0xFFFF
        emu.T = k
        emu.Q, emu.M, emu.S = k, 1 - k, k            # div1 state bits are poisoned too
        emu.mach = emu.macl = 0
        emu.steps = 0
        for n, v in regs.items():
            emu.R[n] = v & M32
        for n, v in fregs.items():
            emu.FR[n] = v & M32
        if setup:
            setup(emu)
        before_r = list(emu.R)
        before_f = list(emu.FR)
        before_fpul = emu.fpul
        emu.uninit_reads.clear()
        how = emu.call(entry, max_steps=20000)
        assert how == 'return', (hex(entry), how)
        assert not emu.uninit_reads, ('uninitialised RAM read', hex(entry), emu.uninit_reads)
        assert emu.R[15] == E.STACK_TOP, 'stack pointer moved'
        assert not emu.writes, ('the routine wrote memory', hex(entry), emu.writes)
        cl = CLOBBER.setdefault(entry, set())
        for i in range(15):
            if emu.R[i] != before_r[i]:
                cl.add('r%d' % i)
        for i in range(16):
            if emu.FR[i] != before_f[i]:
                cl.add('fr%d' % i)
        if emu.fpul != before_fpul:
            cl.add('fpul')
        res = {}
        for o in outs:
            res[o] = emu.FR[int(o[2:])] if o.startswith('fr') else emu.R[int(o[1:])]
        results.append(res)
        TOTAL[entry] = TOTAL.get(entry, 0) + 1
    assert results[0] == results[1], ('output depends on a non-input register', hex(entry), regs, fregs, results)
    return results[0]


def check(entry, cond, msg):
    if not cond:
        FAIL.append('%06X: %s' % (entry, msg))
        print('  ** CONTRACT VIOLATION %06X: %s' % (entry, msg))


def header(entry, title):
    out('')
    out('=' * 100)
    out('%06X  %s' % (entry, title))
    out('=' * 100)


def fx(bits):
    f = bf(bits)
    return '%08X(%.9g)' % (bits, f)


def step32(bits, k):
    """float32 bits k steps away in VALUE order (k > 0 = larger value); normal, non-zero input assumed."""
    for _ in range(abs(k)):
        bits = nextafter32(bits, k > 0)
    return bits


def nextafter32(bits, up):
    f = bf(bits)
    if f == 0:
        return 0x00800000 if up else 0x80800000       # smallest NORMAL: the emulator flushes denormals
    if (f > 0) == up:
        return bits + 1
    return bits - 1


def u32(a):
    return struct.unpack('>I', ROM[a:a + 4])[0]


def steps_apart(a, b):
    """Number of float32 values between two finite model values (0 = same value)."""
    def order(v):
        bits = fb(float(v))
        return -(bits & 0x7FFFFFFF) if bits >> 31 else bits
    if is_special(a) or is_special(b):
        return 0 if a == b else 1 << 31
    return abs(order(a) - order(b))


# ----------------------------------------------------------------------------
# WHICH ROUNDING DOES THE FIRMWARE EXPECT?  The ROM's own FPU self-test decides.
#
#   058696  r0 = 0x0587DC, r6 = 4            05869A  fmov.s @(r0,r6),fr1   fr1 = [0x0587E0] = A
#   05869C-0586A0  fr2 = fr3 = fr4 = A       0586A2  fadd fr3,fr4          fr4 = A + A        (exact)
#   0586A6  fr5 = [0x0587E4] = B             0586A8  fcmp/eq fr4,fr5 / bt  else r14 = 0xAAAAAAAA
#   0586B0  fr0 = A   0586B2 fldi1 fr2   0586B4 fr1 = 1.0   0586B6 fr6 = B
#   0586B8  fmac fr0,fr6,fr2                 fr2 = A * B + 1.0             (INEXACT)
#   0586BC  fr5 = [0x0587E8] = C             0586BE  fcmp/eq fr2,fr5 / bt  else r14 = 0xAAAAAAAA
#   0586C6  fmul fr3,fr4                     fr4 = B * A                   (INEXACT)
#   0586C8  fsub fr1,fr5                     fr5 = C - 1.0                 (exact)
#   0586CA  fcmp/eq fr4,fr5 / bt             else r14 = 0xAAAAAAAA
#   0586D2  fdiv fr3,fr4                     fr4 = (B * A) / A             (INEXACT)
#   0586D6  fr5 = [0x0587EC] = D             0586D8  fcmp/eq fr4,fr5 / bt  else r14 = 0xAAAAAAAA
#
# r14 = 0x55555555 on entry (0x0585A6) and is returned in r0 (0x058770); the caller
# 0x07EF4A treats anything else as a failure.
# ----------------------------------------------------------------------------
CHIP_MODE = 'RZ'     # the mode the firmware's self-test constants require (asserted in t_selftest).
                     # EVERY emulated float result is asserted bit-exact against the model in this mode.
ALT_MODE = 'RN'      # round-to-nearest: evaluated beside the assertion, never asserted -- what the
                     # pre-item-106 emulator and Python float arithmetic would give
EMU_MODE = None      # the model the EMULATOR matches on the self-test operands, measured in t_selftest;
                     # t_selftest fails unless it is CHIP_MODE


def t_selftest():
    global EMU_MODE
    header(0x058696, "the ROM's own FPU self-test: which rounding do its expected constants require?")
    A, B, C, Dq = u32(0x0587E0), u32(0x0587E4), u32(0x0587E8), u32(0x0587EC)
    out('ROM constants  A=[0587E0]=%s  B=[0587E4]=%s  C=[0587E8]=%s  D=[0587EC]=%s' % (fx(A), fx(B), fx(C), fx(Dq)))
    check(0x058696, (A, B, C, Dq) == (0x414CCCCC, 0x41CCCCCC, 0x43A45708, 0x41CCCCCA), 'self-test constants changed')
    a, b, c, d = val(A), val(B), val(C), val(Dq)
    check(0x058696, a + a == b, 'fadd check is not exact')                    # so it cannot discriminate a rounding mode
    check(0x058696, rnd(c - 1, 'RZ') == c - 1, 'C - 1.0 is not exact')
    pred = {}
    out('%-4s %-22s %-22s %-22s %-22s %s' % ('mode', 'fmac fused', 'fmac unfused', 'fmul', 'fdiv (of that product)', 'passes the three compares'))
    for mode, name in (('RN', 'nearest-even'), ('RZ', 'toward zero'), ('RA', 'away from zero')):
        fused = rnd(a * b + 1, mode)
        unfused = rnd(rnd(a * b, mode) + 1, mode)
        prod = rnd(b * a, mode)
        quo = rnd(prod / a, mode)
        ok = (fused == c or unfused == c) and prod == c - 1 and quo == d
        pred[mode] = (fused, unfused, prod, quo, ok)
        out('%-4s %-22s %-22s %-22s %-22s %s   (%s)' % (mode, fx(fb(float(fused))), fx(fb(float(unfused))), fx(fb(float(prod))),
                                                       fx(fb(float(quo))), 'PASS' if ok else 'FAIL', name))
    out('fdiv taken alone, on the product the ROM demands (C - 1.0 = %s): nearest %s, toward zero %s, ROM wants %s' % (
        fx(fb(float(c - 1))), fx(fb(float(rnd((c - 1) / a, 'RN')))), fx(fb(float(rnd((c - 1) / a, 'RZ')))), fx(Dq)))
    # ASSERTED: the exact table quoted in helpers_arith_trace.txt (fused fmac, unfused fmac, fmul, chained fdiv)
    quoted = {'RN': (0x43A45709, 0x43A45709, 0x43A3D709, 0x41CCCCCC),
              'RZ': (0x43A45708, 0x43A45708, 0x43A3D708, 0x41CCCCCA),
              'RA': (0x43A45709, 0x43A45709, 0x43A3D709, 0x41CCCCCD)}
    for mode, want in quoted.items():
        have = tuple(fb(float(v)) for v in pred[mode][:4])
        check(0x058696, have == want, 'self-test table row %s: %s' % (mode, ' '.join('%08X' % v for v in have)))
    check(0x058696, fb(float(rnd((c - 1) / a, 'RN'))) == 0x41CCCCCB and fb(float(c - 1)) == 0x43A3D708, 'fdiv-alone row')
    # ASSERTED (exact rational arithmetic on ROM bytes): only truncation satisfies the firmware's own compares
    check(0x058696, pred['RZ'][4], 'truncation does not pass the ROM self-test')
    check(0x058696, pred['RZ'][0] == c and pred['RZ'][1] == c, 'fused and unfused truncating fmac no longer agree')
    check(0x058696, not pred['RN'][4] and pred['RN'][0] != c and pred['RN'][1] != c and pred['RN'][2] != c - 1 and pred['RN'][3] != d,
          'round-to-nearest was expected to fail fmac, fmul and fdiv')
    check(0x058696, rnd((c - 1) / a, 'RN') != d and rnd((c - 1) / a, 'RZ') == d, 'fdiv alone does not discriminate')
    check(0x058696, not pred['RA'][4], 'rounding away from zero was expected to fail')
    # what does the project emulator do with the same instructions?
    got = {}
    for stop, key, reg in ((0x0586BE, 'fmac', 2), (0x0586CA, 'fmul', 4), (0x0586D8, 'fdiv', 4), (0x0586E0, 'end', 4)):
        e = E.Emu(ROM)
        e.R[14] = 0x55555555
        how = e.call(0x058696, stop_at={stop})
        assert how == stop, (hex(stop), how)
        got[key] = e.FR[reg]
        got[key + '_r14'] = e.R[14]
    out('emulator       fmac -> %s   fmul -> %s   fdiv -> %s   r14 at 0x0586E0 = %08X' % (
        fx(got['fmac']), fx(got['fmul']), fx(got['fdiv']), got['end_r14']))
    for mode in ('RN', 'RZ'):
        f, u, p_, q_, _ = pred[mode]
        if same_float(got['fmul'], p_) and same_float(got['fdiv'], q_) and (same_float(got['fmac'], f) or same_float(got['fmac'], u)):
            EMU_MODE = mode
    check(0x058696, EMU_MODE is not None, 'the emulator matches neither rounding model on the self-test operands')
    check(0x058696, EMU_MODE == CHIP_MODE, 'the emulator does not implement what the chip does: it matches %s, the ROM demands %s' % (
        EMU_MODE, CHIP_MODE))
    passes = got['end_r14'] == 0x55555555
    check(0x058696, passes, 'emulator fails the arithmetic checks 0x058696..0x0586DE (r14 = %08X at 0x0586E0)' % got['end_r14'])
    # the WHOLE self-test, stepped: which of its failed-check stores does the emulator execute?  The stores are
    # found from bytes: every mov.l @(disp,PC),r14 in the body 0x0585B0..0x058782 whose pool word is 0x0587A8
    # (= 0xAAAAAAAA).  Only those an executed path reaches are reported, so a data word that happens to decode
    # that way could not create a hit.
    # The word scan also matches 0x0585B4 (DE7C), which is NOT an instruction: 0x0585B0 A001 = bra 0x0585B6 jumps
    # over it (fn_dump 0x0585B0 prints it as a pool long).  It is dropped, leaving the 31 decoded stores.
    fail_stores = []
    for pc in range(0x0585B0, 0x058784, 2):
        w = struct.unpack('>H', ROM[pc:pc + 2])[0]
        if (w & 0xFF00) == 0xDE00 and ((pc + 4) & ~3) + (w & 0xFF) * 4 == 0x0587A8:
            fail_stores.append(pc)
    check(0x058594, ROM[0x0585B0:0x0585B4] == b'\xA0\x01\x00\x09' and 0x0585B4 in fail_stores, 'bra over 0x0585B4 changed')
    fail_stores.remove(0x0585B4)
    check(0x058594, u32(0x0587A8) == 0xAAAAAAAA and len(fail_stores) == 31 and 0x05873A in fail_stores and 0x0586C4 in fail_stores,
          'self-test fail-store scan changed: %d' % len(fail_stores))
    e = E.Emu(ROM)
    e.R[15], e.pr, e.pc = E.STACK_TOP, E.RETURN_MAGIC, 0x058594
    hit = []
    while e.pc != E.RETURN_MAGIC and e.steps < 100000:
        if e.pc in fail_stores:
            hit.append(e.pc)
        e.step()
    out('emulator       whole self-test 0x058594 returns r0 = %08X (0x55555555 = pass), FPSCR left = %08X' % (e.R[0], e.fpscr))
    out('               of the %d failed-check stores in the body it executes: %s' % (
        len(fail_stores), ' '.join('%06X' % a for a in hit) or 'none'))
    check(0x058594, e.pc == E.RETURN_MAGIC and e.R[0] in (0x55555555, 0xAAAAAAAA), 'whole self-test run did not return a verdict')
    # ASSERTED: the one check the emulator fails is 0x05873A, FPSCR bit 6 after 0.0/0.0 -- flag bits are not modelled
    check(0x058594, hit == [0x05873A] and e.R[0] == 0xAAAAAAAA,
          'expected exactly one failed check, the FPSCR bit-6 test at 0x05873A; got %s' % ['%06X' % a for a in hit])
    out('=> the firmware expects TRUNCATION from fmac/fmul/fdiv (byte evidence); the emulator implements %s and %s the arithmetic checks.' % (
        'round-to-nearest' if EMU_MODE == 'RN' else 'truncation', 'PASSES' if passes else 'FAILS (r14 = 0xAAAAAAAA)'))
    out('   Its whole-routine verdict is still 0xAAAAAAAA, from 0x05873A alone (FPSCR bit 6 after 0/0: the emulator models no flag bits).')
    out('   Every emulated float result below is asserted BIT-EXACT against the exact model in mode %s (fmac fused);' % CHIP_MODE)
    out('   the round-to-nearest model is evaluated beside it, never asserted.')
    # the fill loop 0x058654..0x058694 leaves fr0..fr15 = 0.0 (three passes), which is what makes 0x058712 a 0.0/0.0
    e = E.Emu(ROM)
    e.R[14] = 0x55555555
    for i in range(16):
        e.FR[i] = 0x3F800000
    e.call(0x058654, stop_at={0x058696})
    check(0x058654, all(x == 0 for x in e.FR) and e.R[0] == 0x0587BC and e.R[14] == 0x55555555,
          'fill loop: expected three passes ending with fr0..fr15 = 0.0')
    out('fill loop 0x058654..0x058694: r0 walked 0x0587B0 -> %06X (three longs), fr0..fr15 all %08X on exit' % (e.R[0], e.FR[15]))
    # 0x058712 fdiv fr10,fr11 = 0.0/0.0; the ROM demands unordered compares and FPSCR bit 6
    e = E.Emu(ROM)
    e.R[14] = 0x55555555
    e.FR[3], e.FR[10], e.FR[11] = A, 0, 0
    e.call(0x058712, stop_at={0x05872C})
    cmp_ok = e.R[14] == 0x55555555
    e.call(0x05872C, stop_at={0x05873C})
    out('EMU-MODEL  0.0/0.0 at 0x058712 -> fr11 = %08X; the three "unordered" compares the ROM demands: %s; FPSCR bit 6 check: %s' % (
        e.FR[11], 'pass' if cmp_ok else 'FAIL', 'pass' if e.R[14] == 0x55555555 else 'FAIL (the emulator does not model FPSCR flag bits)'))
    check(0x058712, cmp_ok, 'emulator 0/0 is not unordered')


# ----------------------------------------------------------------------------
# 0BE524  saturating signed 32-bit add
# ----------------------------------------------------------------------------
def t_sat_add_s32():
    ent = 0x0BE524
    header(ent, 'r0 = sat_s32(r4 + r5)')
    edge = [0, 1, 2, -1, -2, 0x7FFFFFFF, 0x7FFFFFFE, 0x40000000, 0x3FFFFFFF, -0x80000000, -0x7FFFFFFF,
            -0x40000000, -0x40000001, 0x7FFF, 0x8000, 0xFFFF, 0x10000, -0x8000, -0x10000, 123456789, -987654321]
    cases = [(a, b) for a in edge for b in edge]
    cases += [(s32(random.getrandbits(32)), s32(random.getrandbits(32))) for _ in range(1500)]
    for a, b in cases:
        r = run(ent, {4: a, 5: b})['r0']
        exact = a + b
        exp = max(-2 ** 31, min(2 ** 31 - 1, exact))
        check(ent, s32(r) == exp, 'a=%d b=%d got %08X want %d' % (a, b, r, exp))
    out('%12s %12s -> %-10s %s' % ('r4', 'r5', 'r0', 'note'))
    rows = [(0, 0), (1, -1), (5, 7), (-5, -7), (0x7FFFFFFE, 1), (0x7FFFFFFF, 0), (0x7FFFFFFF, 1), (1, 0x7FFFFFFF),
            (0x40000000, 0x3FFFFFFF), (0x40000000, 0x40000000), (0x7FFFFFFF, 0x7FFFFFFF), (-0x7FFFFFFF, -1), (-0x80000000, 0),
            (-0x80000000, -1), (-1, -0x80000000), (-0x40000000, -0x40000000), (-0x40000000, -0x40000001),
            (-0x80000000, -0x80000000), (0x7FFFFFFF, -0x80000000), (-0x80000000, 0x7FFFFFFF)]
    for a, b in rows:
        r = run(ent, {4: a, 5: b})['r0']
        exact = a + b
        check(ent, s32(r) == max(-2 ** 31, min(2 ** 31 - 1, exact)), 'row a=%d b=%d got %08X' % (a, b, r))
        note = 'max+1 and beyond -> 7FFFFFFF' if exact > 2 ** 31 - 1 else 'below min -> 80000000' if exact < -2 ** 31 else ''
        out('%12d %12d -> %08X   %s' % (a, b, r, note))
    out('cases %d: all equal to max(-2^31, min(2^31-1, r4+r5)); positive overflow -> 7FFFFFFF, negative -> 80000000' % (len(cases) + len(rows)))


# ----------------------------------------------------------------------------
# 0BE53C / 0BE554  saturating unsigned 8- and 16-bit add
# ----------------------------------------------------------------------------
def t_sat_add_u8():
    ent = 0x0BE53C
    header(ent, 'r0 = min((r4 & 0xFF) + (r5 & 0xFF), 0xFF)')
    n = 0
    for a in range(256):                       # exhaustive in the low bytes
        for b in range(256):
            r = run(ent, {4: a, 5: b})['r0']
            check(ent, r == min(a + b, 255), 'a=%d b=%d got %08X' % (a, b, r))
            n += 1
    hi = [(0xFFFFFF00, 0xFFFFFF00), (0x12345600 | 0x80, 0xDEADBE00 | 0x7E), (0xFFFFFFFF, 0x00000100),
          (0x00000100, 0x00000100), (0x80000001, 0x7FFFFF01), (0xFFFFFFFE, 0xFFFFFF01), (0xFFFFFF7F, 0xFFFFFF80)]
    out('%-10s %-10s -> %-10s' % ('r4', 'r5', 'r0'))
    for a, b in [(0, 0), (1, 1), (254, 0), (254, 1), (255, 0), (255, 1), (128, 127), (128, 128), (255, 255)] + hi:
        r = run(ent, {4: a, 5: b})['r0']
        check(ent, r == min((a & 0xFF) + (b & 0xFF), 255), 'a=%08X b=%08X got %08X' % (a, b, r))
        out('%08X   %08X   -> %08X' % (a, b, r))
        n += 1
    for _ in range(2000):                      # upper 24 bits are ignored
        a, b = random.getrandbits(32), random.getrandbits(32)
        r = run(ent, {4: a, 5: b})['r0']
        check(ent, r == min((a & 0xFF) + (b & 0xFF), 255), 'a=%08X b=%08X got %08X' % (a, b, r))
        n += 1
    out('cases %d (all 65,536 byte pairs + 2,000 with random upper bits): r0 = min(u8+u8, 255), upper 24 bits of r4/r5 ignored, r0 upper bits zero' % n)


def t_sat_add_u16():
    ent = 0x0BE554
    header(ent, 'r0 = min((r4 & 0xFFFF) + (r5 & 0xFFFF), 0xFFFF)')
    edge = [0, 1, 2, 0xFF, 0x100, 0x7FFF, 0x8000, 0x8001, 0xFFFE, 0xFFFF, 0x1234, 0xEDCB, 0xEDCC, 0xFF00, 0x00FF]
    cases = [(a, b) for a in edge for b in edge]
    cases += [(random.getrandbits(16), random.getrandbits(16)) for _ in range(3000)]
    cases += [(random.getrandbits(32), random.getrandbits(32)) for _ in range(3000)]
    cases += [(0xFFFF0000, 0xFFFF0000), (0x00010000, 0x00010000), (0xFFFFFFFF, 0xFFFF0001), (0x8000FFFE, 0x7FFF0001),
              (0xFFFFFFFE, 0x00010000), (0xABCD8000, 0x12348000), (0xABCD7FFF, 0x12348000)]
    out('%-10s %-10s -> %-10s' % ('r4', 'r5', 'r0'))
    show = {(0, 0), (0xFFFE, 0), (0xFFFE, 1), (0xFFFE, 2), (0xFFFF, 0), (0xFFFF, 1), (0xFFFF, 0xFFFF), (0x8000, 0x7FFF),
            (0x8000, 0x8000), (0x1234, 0xEDCB), (0x1234, 0xEDCC), (0xFFFF0000, 0xFFFF0000), (0x00010000, 0x00010000),
            (0xFFFFFFFF, 0xFFFF0001), (0x8000FFFE, 0x7FFF0001), (0xFFFFFFFE, 0x00010000), (0xABCD8000, 0x12348000),
            (0xABCD7FFF, 0x12348000)}
    for a, b in cases:
        r = run(ent, {4: a, 5: b})['r0']
        check(ent, r == min((a & 0xFFFF) + (b & 0xFFFF), 0xFFFF), 'a=%08X b=%08X got %08X' % (a, b, r))
        if (a, b) in show:
            out('%08X   %08X   -> %08X' % (a, b, r))
            show.discard((a, b))
    out('cases %d: r0 = min(u16+u16, 65535), upper 16 bits of r4/r5 ignored, r0 upper bits zero' % len(cases))


# ----------------------------------------------------------------------------
# 0BE56C  float clamp
# ----------------------------------------------------------------------------
FGRID = [0.0, -0.0, 1.0, -1.0, 0.5, -0.5, 1.0000001, 0.99999994, 2.0, 3.0, 10.0, -10.0, 100.0, 255.0, 256.0, 65535.0,
         -65536.0, 1e-30, -1e-30, 1e30, -1e30, 3.4028234663852886e38, -3.4028234663852886e38, 14.7, 6700.0, -40.0]
FGRID_B = sorted(set(fb(f) for f in FGRID))


def t_clamp():
    ent = 0x0BE56C
    header(ent, 'fr0 = fr5 if NOT(fr4 > fr5) else (fr4 if fr6 > fr4 else fr6)      [x=fr4, lo=fr5, hi=fr6]')
    n = 0
    inv = 0
    for x in FGRID_B:
        for lo in FGRID_B:
            for hi in FGRID_B:
                r = run(ent, fregs={4: x, 5: lo, 6: hi}, outs=('fr0', 'fr7'))
                vx, vlo, vhi = bf(x), bf(lo), bf(hi)
                exp = lo if not (vx > vlo) else (x if vhi > vx else hi)      # BIT-exact: the routine only moves
                check(ent, r['fr0'] == exp, 'x=%s lo=%s hi=%s got %08X want %08X' % (fx(x), fx(lo), fx(hi), r['fr0'], exp))
                check(ent, r['fr7'] == r['fr0'], 'fr7 != fr0')
                if vlo <= vhi:
                    check(ent, bf(r['fr0']) == max(vlo, min(vx, vhi)), 'not a clamp for lo<=hi')
                else:
                    inv += 1
                n += 1
    out('%-22s %-22s %-22s -> %s' % ('fr4 x', 'fr5 lo', 'fr6 hi', 'fr0'))
    for x, lo, hi in [(5.0, 0.0, 10.0), (-1.0, 0.0, 10.0), (11.0, 0.0, 10.0), (0.0, 0.0, 10.0), (10.0, 0.0, 10.0),
                      (-0.0, 0.0, 10.0), (0.0, -0.0, 10.0), (5.0, 10.0, 0.0), (-5.0, 10.0, 0.0), (15.0, 10.0, 0.0),
                      (10.0, 10.0, 0.0), (10.000001, 10.0, 0.0), (3.0, 3.0, 3.0)]:
        r = run(ent, fregs={4: fb(x), 5: fb(lo), 6: fb(hi)}, outs=('fr0',))['fr0']
        fx_, flo, fhi = bf(fb(x)), bf(fb(lo)), bf(fb(hi))
        check(ent, r == (fb(lo) if not (fx_ > flo) else (fb(x) if fhi > fx_ else fb(hi))), 'row x=%r lo=%r hi=%r got %08X' % (x, lo, hi, r))
        tag = '' if lo <= hi else '   <- lo > hi: result is fr5 when x <= fr5, otherwise fr6'
        out('%-22s %-22s %-22s -> %s%s' % (fx(fb(x)), fx(fb(lo)), fx(fb(hi)), fx(r), tag))
    out('cases %d (of which %d have lo > hi): bit-exact; for lo <= hi it equals max(lo, min(x, hi))' % (n, inv))
    # unordered inputs: emulator models fcmp/gt as false.  Printed only.
    r = run(ent, fregs={4: 0x7FC00000, 5: fb(1.0), 6: fb(2.0)}, outs=('fr0',))['fr0']
    out('EMU-MODEL  x = NaN(7FC00000), lo 1, hi 2 -> %s   (a false fcmp/gt returns fr5)' % fx(r))
    check(ent, r == fb(1.0), 'NaN row')


# ----------------------------------------------------------------------------
# 0BE588 / 0BE598  integer -> float with scale and offset
# ----------------------------------------------------------------------------
def t_scale(ent, bits):
    mask = (1 << bits) - 1
    header(ent, 'fr0 = fr4 * float(r4 & 0x%X) + fr5      [raw=r4, scale=fr4, offset=fr5]' % mask)
    scales = [1.0, 0.0, -1.0, 0.5, 0.01, 0.1, 0.0078125, 1.8, 0.003921569, 0.00001525902, 14.7, -0.3515625, 1e-30, 3e33]
    offs = [0.0, -0.0, 32.0, -40.0, 0.5, -128.0, 1e-3, 100.3, -1e30]
    if bits == 8:
        raws = list(range(256))
    else:
        raws = sorted(set([0, 1, 2, 127, 128, 255, 256, 257, 0x7FFF, 0x8000, 0x8001, 0xFFFE, 0xFFFF] +
                          [random.getrandbits(16) for _ in range(120)]))
    n = 0
    eq = {'fused RN': 0, 'unfused RN': 0, 'fused RZ': 0, 'unfused RZ': 0}
    fz_vs_uz = far = worst = 0
    worst_case = None
    for sc in scales:
        for of in offs:
            for raw in raws:
                # upper bits of r4 must be ignored
                rr = raw | (random.getrandbits(32 - bits) << bits)
                r = run(ent, {4: rr}, {4: fb(sc), 5: fb(of)}, outs=('fr0', 'fr5'))
                a, b = val(fb(sc)), val(fb(of))
                exact = a * raw + b                  # float(r4) is exact: the integer is at most 0xFFFF
                cand = {'fused RN': rnd(exact, 'RN'), 'unfused RN': f_add(rnd(a * raw, 'RN'), b, 'RN'),
                        'fused RZ': rnd(exact, 'RZ'), 'unfused RZ': f_add(rnd(a * raw, 'RZ'), b, 'RZ')}
                # ASSERTED BIT-EXACT: fr0 is fr4*raw+fr5 computed exactly and truncated ONCE (fused fmac, mode
                # CHIP_MODE).  Truncation is what the firmware expects (t_selftest); fused is the emulator's
                # stated fmac -- no byte decides fused-vs-unfused, so the unfused model is counted beside it.
                check(ent, same_float(r['fr0'], cand['fused ' + CHIP_MODE]),
                      'raw=%X scale=%r off=%r got %s want %s' % (rr, sc, of, fx(r['fr0']), fx(fb(float(cand['fused ' + CHIP_MODE])))))
                check(ent, r['fr5'] == r['fr0'], 'fr5 != fr0')
                for k, v in cand.items():
                    eq[k] += same_float(r['fr0'], v)
                fz_vs_uz += cand['fused RZ'] != cand['unfused RZ']
                # an UNFUSED fmac rounds the product first; when the offset then cancels most of it, that one
                # product-ulp is many ulps of the small result.  Measure how far apart the two truncating models get.
                gap = steps_apart(cand['fused RZ'], cand['unfused RZ'])
                far += gap > 1
                if gap > worst:
                    worst, worst_case = gap, (raw, sc, of, cand['fused RZ'], cand['unfused RZ'])
                n += 1
    out('%-10s %-22s %-22s -> %s' % ('r4', 'fr4 scale', 'fr5 offset', 'fr0'))
    rows = [(0, 1.0, 0.0), (1, 1.0, 0.0), (mask, 1.0, 0.0), (mask + 1, 1.0, 0.0), (0xFFFFFF00 | 0x80 if bits == 8 else 0xFFFF8000, 1.0, 0.0),
            (0x80000000 | mask, 1.0, 0.0), (0xFFFFFFFF, 1.0, 0.0), (100, 0.5, -40.0), (mask, 0.0, 7.0), (mask, -1.0, 0.0),
            (3, 0.1, 0.0), (200, 0.0078125, 0.0)]
    for raw, sc, of in rows:
        r = run(ent, {4: raw}, {4: fb(sc), 5: fb(of)}, outs=('fr0',))['fr0']
        # not every row is exact (3 * 0.1 is not): the expected value is the fused truncation, as on the grid
        check(ent, same_float(r, rnd(val(fb(sc)) * (raw & mask) + val(fb(of)), CHIP_MODE)), 'row %X got %s' % (raw, fx(r)))
        out('%08X   %-22s %-22s -> %s' % (raw, fx(fb(sc)), fx(fb(of)), fx(r)))
    out('cases %d: fr0 is fr4 * (r4 & 0x%X) + fr5, exact then truncated once (fused fmac), BIT-EXACT in every case; the integer' % (n, mask))
    out('          is ZERO-extended (never negative); the upper %d bits of r4 are ignored' % (32 - bits))
    out('          the emulator result equals: %s (of %d)' % (', '.join('%s in %d' % kv for kv in eq.items()), n))
    check(ent, eq['fused RZ'] == n, 'emulator is not the fused truncation in every grid case')
    out('          GRID COUNT, not a rate: a round-to-nearest fmac would differ from the truncated result in %d (fused) / %d (unfused) of %d;' % (
        n - eq['fused RN'], n - eq['unfused RN'], n))
    out('          a fused and an unfused truncating fmac differ from each other in %d of %d -- that part is NOT ESTABLISHED' % (fz_vs_uz, n))
    out('          they are more than ONE float32 step apart in %d cases; worst %d steps at raw=%d scale=%r offset=%r (fused %.9g, unfused %.9g):' % (
        far, worst, worst_case[0], worst_case[1], worst_case[2], float(worst_case[3]), float(worst_case[4])))
    out('          cancellation between product and offset -- "last ulp" does NOT bound the fused/unfused question')
    STATS[ent] = dict(n=n, eq=dict(eq), fz_vs_uz=fz_vs_uz, far=far, worst=worst)


# ----------------------------------------------------------------------------
# 0BE5A8 / 0BE5D8  float -> unsigned integer with scale and offset, rounded, clamped
# ----------------------------------------------------------------------------
def model_f2u(x, sc, of, top, mode, sc_bits):
    d = f_sub(x, of, mode)
    q = f_div(d, sc, mode, b_neg_zero=(sc_bits == 0x80000000))
    s = f_add(q, Fraction(1, 2), mode)
    i = s32(f_trc(s))
    return top if i > top else (0 if i < 0 else i)


def t_f2u(ent, top):
    header(ent, 'r0 = clamp(trunc((fr4 - fr6) / fr5 + 0.5), 0, %d)      [x=fr4, scale=fr5, offset=fr6]' % top)
    scales = [1.0, 0.5, 0.01, 0.1, 0.0078125, 1.8, 0.003921569, 14.7, -1.0, -0.5, 1e-30, 3e33, 100.0]
    offs = [0.0, -0.0, 32.0, -40.0, 0.5, 100.3]
    xs = [0.0, -0.0, 0.25, 0.49, 0.5, 0.51, 1.0, 1.49, 1.5, 2.5, -0.49, -0.5, -0.51, -1.0, -1.5, -100.0, 126.5, 127.5,
          254.4, 254.5, 255.0, 255.4, 255.5, 256.0, 300.0, 1000.0, 32767.5, 65534.4, 65534.5, 65535.0, 65535.5,
          65536.0, 70000.0, 1e9, 3e9, -3e9, 1e30, -1e30, 3.4028234663852886e38, -3.4028234663852886e38]
    xs += [random.uniform(-10, top + 10) for _ in range(60)]
    n = dz = 0
    for sc in scales:
        for of in offs:
            for x in xs:
                xb, sb, ob = fb(x), fb(sc), fb(of)
                r = run(ent, fregs={4: xb, 5: sb, 6: ob})['r0']
                exp = model_f2u(val(xb), val(sb), val(ob), top, CHIP_MODE, sb)
                check(ent, r == exp, 'x=%r scale=%r off=%r got %d want %d' % (x, sc, of, r, exp))
                dz += model_f2u(val(xb), val(sb), val(ob), top, ALT_MODE, sb) != exp
                n += 1
    ngrid = n
    # dense sweep through the whole output range at scale 1, offset 0: half-way cases round UP
    for k in range(0, top + 2, 1 if top == 255 else 257):
        for frac in (0.0, 0.25, 0.5, 0.75):
            xb = fb(k + frac)
            r = run(ent, fregs={4: xb, 5: fb(1.0), 6: fb(0.0)})['r0']
            exp = min(top, int(k + frac + 0.5))
            check(ent, r == exp, 'sweep x=%r got %d want %d' % (k + frac, r, exp))
            n += 1
    out('%-22s %-22s %-22s -> %-6s %s' % ('fr4 x', 'fr5 scale', 'fr6 offset', 'r0', 'note'))
    rows = [(0.0, 1.0, 0.0, ''), (0.49, 1.0, 0.0, ''), (0.5, 1.0, 0.0, 'half rounds up'), (1.5, 1.0, 0.0, 'half rounds up'),
            (2.5, 1.0, 0.0, 'half rounds up (not to even)'), (-0.4, 1.0, 0.0, ''), (-0.5, 1.0, 0.0, ''), (-1.5, 1.0, 0.0, 'negative -> 0'),
            (-1e30, 1.0, 0.0, 'negative -> 0'), (top - 0.6, 1.0, 0.0, ''), (top - 0.5, 1.0, 0.0, ''), (float(top), 1.0, 0.0, ''),
            (top + 0.4, 1.0, 0.0, ''), (top + 0.5, 1.0, 0.0, 'max+0.5 -> max'), (top + 1.0, 1.0, 0.0, 'max+1 -> max'),
            (3e9, 1.0, 0.0, 'ftrc saturates, then clamp'), (3.4028234663852886e38, 1.0, 0.0, 'FLT_MAX'),
            (10.0, 0.5, 0.0, '(10-0)/0.5'), (10.0, 0.5, 4.0, '(10-4)/0.5: offset is SUBTRACTED before the divide'),
            (10.0, 4.0, 0.5, '(10-0.5)/4 = 2.375: fr5 divides, fr6 subtracts'), (10.0, -1.0, 0.0, 'negative scale -> negative -> 0'),
            (-10.0, -1.0, 0.0, '')]
    for x, sc, of, note in rows:
        r = run(ent, fregs={4: fb(x), 5: fb(sc), 6: fb(of)})['r0']
        check(ent, r == model_f2u(val(fb(x)), val(fb(sc)), val(fb(of)), top, CHIP_MODE, fb(sc)), 'row x=%r' % x)
        out('%-22s %-22s %-22s -> %-6d %s' % (fx(fb(x)), fx(fb(sc)), fx(fb(of)), r, note))
    # rounding-mode edge: the largest float below 0.5
    # 0x3EFFFFFF + 0.5 = 1 - 2^-25 is an exact tie: nearest-even takes it to 1.0, truncation to 0x3F7FFFFF.
    # The step that decides it is the FADD, which the ROM self-test does not exercise inexactly.
    r = run(ent, fregs={4: 0x3EFFFFFF, 5: fb(1.0), 6: fb(0.0)})['r0']
    rn = model_f2u(val(0x3EFFFFFF), val(fb(1.0)), Fraction(0), top, 'RN', fb(1.0))
    rz = model_f2u(val(0x3EFFFFFF), val(fb(1.0)), Fraction(0), top, 'RZ', fb(1.0))
    out('%-22s %-22s %-22s -> %-6d %s' % (fx(0x3EFFFFFF), fx(fb(1.0)), fx(0), r,
                                         'ROUNDING EDGE: emulator gives %d; truncating model %d, nearest model %d' % (r, rz, rn))
        )
    check(ent, rn == 1 and rz == 0 and r == rz, 'rounding edge row changed')
    # divide by zero: emulator model only
    for x, sc_bits, note in [(5.0, 0x00000000, 'x/+0 = +Inf -> max'), (-5.0, 0x00000000, 'x/+0 = -Inf -> 0'),
                             (0.0, 0x00000000, '0/0 = NaN -> ftrc 80000000 -> 0'), (5.0, 0x80000000, 'x/-0 = -Inf -> 0'),
                             (-5.0, 0x80000000, 'x/-0 = +Inf -> max')]:
        r = run(ent, fregs={4: fb(x), 5: sc_bits, 6: fb(0.0)})['r0']
        exp = model_f2u(val(fb(x)), Fraction(0), Fraction(0), top, CHIP_MODE, sc_bits)
        check(ent, r == exp, 'div0 row x=%r' % x)
        out('%-22s %-22s %-22s -> %-6d EMU-MODEL %s' % (fx(fb(x)), fx(sc_bits), fx(0), r, note))
        n += 1
    out('cases %d: r0 == clamp(trunc(((fr4-fr6)/fr5)+0.5), 0, %d) with each of the three float steps truncated (mode %s)' % (n, top, CHIP_MODE))
    out('          GRID COUNT, not a rate: %d of the %d scale/offset/x grid cases give a different integer under round-to-nearest' % (dz, ngrid))
    STATS[ent] = dict(n=n, grid=ngrid, dz=dz)


# ----------------------------------------------------------------------------
# 0BE608  outside-window test
# ----------------------------------------------------------------------------
def model_window(vx, vc, vw, mode):
    return int(f_gt(f_sub(vc, vw, mode), vx) or f_gt(vx, f_add(vc, vw, mode)))


def t_window():
    ent = 0x0BE608
    header(ent, 'r0 = 1 if (fr5 - fr6) > fr4 or fr4 > (fr5 + fr6) else 0      [x=fr4, centre=fr5, half-width=fr6]')
    n = dz = 0
    neg = neg0 = neg0_rn = zero_w = 0
    neg0_examples = []
    for x in FGRID_B:
        for c in FGRID_B:
            for w in FGRID_B:
                r = run(ent, fregs={4: x, 5: c, 6: w})['r0']
                vx, vc, vw = val(x), val(c), val(w)
                exp = model_window(vx, vc, vw, CHIP_MODE)
                check(ent, r == exp, 'x=%s c=%s w=%s got %d want %d' % (fx(x), fx(c), fx(w), r, exp))
                alt = model_window(vx, vc, vw, ALT_MODE)
                dz += alt != exp
                if vw < 0:                                   # NEGATIVE half-width
                    neg += 1
                    neg0 += r == 0                           # the emulator (asserted == the truncating model)
                    if alt == 0:                             # round-to-nearest returns 0 for some
                        neg0_rn += 1
                        if len(neg0_examples) < 4:
                            neg0_examples.append('x=c=%s w=%s' % (fx(x), fx(w)))
                        # the only way to get 0: |w| vanishes in the rounding of centre -/+ width, and x == centre
                        check(ent, vx == vc and f_sub(vc, vw, ALT_MODE) == vc and f_add(vc, vw, ALT_MODE) == vc,
                              'nearest model: negative width returned 0 away from x == centre: x=%s c=%s w=%s' % (fx(x), fx(c), fx(w)))
                if vw == 0:                                  # ZERO half-width (+0 or -0): 0 only when x == centre
                    zero_w += 1
                    check(ent, r == int(vx != vc), 'zero width: x=%s c=%s got %d' % (fx(x), fx(c), r))
                n += 1
    out('%-22s %-22s %-22s -> %s  %s' % ('fr4 x', 'fr5 centre', 'fr6 half-width', 'r0', 'note'))
    rows = [(10.0, 10.0, 2.0, 0, 0, 'inside'), (8.0, 10.0, 2.0, 0, 0, 'on lower edge: INSIDE (0)'), (12.0, 10.0, 2.0, 0, 0, 'on upper edge: INSIDE (0)'),
            (7.9999995, 10.0, 2.0, 1, 1, 'one ulp below lower edge'), (12.000001, 10.0, 2.0, 1, 1, 'one ulp above upper edge'),
            (0.0, 10.0, 2.0, 1, 1, 'below'), (100.0, 10.0, 2.0, 1, 1, 'above'), (10.0, 10.0, 0.0, 0, 0, 'zero width, x == centre'),
            (10.000001, 10.0, 0.0, 1, 1, 'zero width, x != centre'), (10.0, 10.0, -1.0, 1, 1, 'negative width, limits cross: 1'),
            (9.5, 10.0, -1.0, 1, 1, 'negative width, limits cross: 1'),
            (10.0, 10.0, -1e-30, 0, 1, 'NEGATIVE width ABSORBED in rounding: nearest 0, truncation 1'),
            (10.0, 10.0, -4.7e-7, 0, 1, 'NEGATIVE width below half an ulp of 10: nearest 0, truncation 1'),
            (10.0, 10.0, -4.8e-7, 1, 1, 'NEGATIVE width just above half an ulp of 10: 1'),
            (-10.0, -10.0, -1e-30, 0, 1, 'same, negative centre: nearest 0, truncation 1'),
            (-10.0, -10.0, 2.0, 0, 0, ''), (-13.0, -10.0, 2.0, 1, 1, '')]
    for x, c, w, want_rn, want_rz, note in rows:
        r = run(ent, fregs={4: fb(x), 5: fb(c), 6: fb(w)})['r0']
        vx, vc, vw = val(fb(x)), val(fb(c)), val(fb(w))
        check(ent, model_window(vx, vc, vw, 'RN') == want_rn and model_window(vx, vc, vw, 'RZ') == want_rz,
              'row x=%r c=%r w=%r: models give %d/%d, stated %d/%d' % (x, c, w, model_window(vx, vc, vw, 'RN'),
                                                                     model_window(vx, vc, vw, 'RZ'), want_rn, want_rz))
        check(ent, r == want_rz, 'row x=%r c=%r w=%r got %d' % (x, c, w, r))
        out('%-22s %-22s %-22s -> %d   %s' % (fx(fb(x)), fx(fb(c)), fx(fb(w)), r, note))
        n += 1
    r = run(ent, fregs={4: 0x7FC00000, 5: fb(10.0), 6: fb(2.0)})['r0']
    out('EMU-MODEL  x = NaN, centre 10, width 2 -> %d   (both fcmp/gt false: "inside")' % r)
    check(ent, r == 0, 'NaN row')
    n += 1
    out('cases %d: r0 in {0,1}; 1 = OUTSIDE [fr5-fr6, fr5+fr6], both edges count as inside' % n)
    out('          zero half-width (%d grid cases): 0 exactly when x == centre' % zero_w)
    out('          NEGATIVE half-width (%d grid cases): emulator (= truncating model) 1 in %d, 0 in %d.' % (neg, neg - neg0, neg0))
    out('          Round-to-nearest model: 0 in %d, every one with x == centre and centre-/+width both rounding back to centre' % neg0_rn)
    out('          (e.g. %s).' % '; '.join(neg0_examples[:2]))
    out('          GRID COUNT, not a rate: %d of the %d grid verdicts differ under round-to-nearest' % (dz, len(FGRID_B) ** 3))
    check(ent, neg0 == 0, 'a negative width returned 0 on the grid (truncation cannot land back on the centre)')
    STATS[ent] = dict(n=n, grid=len(FGRID_B) ** 3, dz=dz, neg=neg, neg0=neg0, neg0_rn=neg0_rn)


# ----------------------------------------------------------------------------
# 0BE628  protected float divide
# ----------------------------------------------------------------------------
def model_safe_div(a_bits, b_bits, mode):
    """Returns ('bits', n) for the substituted results, ('val', v) for a real divide."""
    va, vb = val(a_bits), val(b_bits)
    if vb == 0:
        if va == 0:
            return 'bits', 0x00000000
        return 'bits', FLT_MAX_BITS if va > 0 else 0xFF7FFFFF
    return 'val', rnd(va / vb, mode)


def t_safe_div():
    ent = 0x0BE628
    header(ent, 'fr0 = fr4 / fr5;  fr5 == 0: 0 when fr4 == 0, +FLT_MAX when fr4 > 0, -FLT_MAX otherwise')
    n = dz = nq = 0

    def one(a, b):
        r = run(ent, fregs={4: a, 5: b}, outs=('fr0', 'fr6'))
        kind, exp = model_safe_div(a, b, CHIP_MODE)
        if kind == 'bits':
            check(ent, r['fr0'] == exp, 'a=%s b=%s got %08X want %08X' % (fx(a), fx(b), r['fr0'], exp))
            d = 0
        else:
            check(ent, same_float(r['fr0'], exp), 'a=%s b=%s got %s' % (fx(a), fx(b), fx(r['fr0'])))
            d = int(model_safe_div(a, b, ALT_MODE)[1] != exp)
        check(ent, r['fr6'] == r['fr0'], 'fr6 != fr0')
        return r['fr0'], kind, d

    for a in FGRID_B:
        for b in FGRID_B:
            _, kind, d = one(a, b)
            nq += kind == 'val'
            dz += d
            n += 1
    ngrid, nqgrid, dzgrid = n, nq, dz
    out('%-22s %-22s -> %s  %s' % ('fr4 num', 'fr5 den', 'fr0', 'note'))
    for a, b, note in [(fb(6.0), fb(3.0), ''), (fb(1.0), fb(3.0), ''), (fb(-1.0), fb(3.0), ''), (fb(0.0), fb(3.0), ''),
                       (fb(0.0), fb(0.0), '0/0 -> +0.0'), (0x80000000, fb(0.0), '-0/0 -> +0.0'), (fb(0.0), 0x80000000, '0/-0 -> +0.0'),
                       (fb(5.0), fb(0.0), '+/0 -> +FLT_MAX'), (fb(-5.0), fb(0.0), '-/0 -> -FLT_MAX'),
                       (fb(5.0), 0x80000000, '+/-0 -> +FLT_MAX (sign of the zero divisor is ignored)'),
                       (fb(-5.0), 0x80000000, '-/-0 -> -FLT_MAX'), (fb(1e-30), fb(0.0), 'tiny +/0 -> +FLT_MAX'),
                       (fb(1e30), fb(1e-30), 'overflow of a non-zero divide is NOT protected: truncation saturates at FLT_MAX (nearest would give +Inf)'),
                       (fb(1e-30), fb(1e30), 'underflow -> 0')]:
        r, _, _ = one(a, b)
        out('%-22s %-22s -> %-22s %s' % (fx(a), fx(b), fx(r), note))
        if a == fb(1e30):
            check(ent, r == FLT_MAX_BITS, 'overflow row: expected the round-toward-zero saturation 7F7FFFFF, got %08X' % r)
        n += 1
    # a second, different grid: random non-dyadic operands.  The share round-to-nearest would change is a property of the grid.
    rq = rd = 0
    rng = random.Random(628)                       # its own generator: the other tests' random grids stay as they were
    for _ in range(300):
        a = fb(rng.uniform(-1000.0, 1000.0))
        b = fb(rng.choice((-1, 1)) * rng.uniform(0.001, 1000.0))
        _, kind, d = one(a, b)
        rq += kind == 'val'
        rd += d
        n += 1
    out('cases %d: quotient equals fr4/fr5 truncated (mode %s) for fr5 != 0, bit-exact; zero-divisor results are bit-exact' % (n, CHIP_MODE))
    out('          GRID COUNTS, not rates: a round-to-nearest quotient differs in %d of the %d real divides of the 26 x 26 grid,' % (dzgrid, nqgrid))
    out('          and in %d of %d random non-dyadic divides' % (rd, rq))
    r = run(ent, fregs={4: 0x7FC00000, 5: fb(0.0)}, outs=('fr0',))['fr0']
    out('EMU-MODEL  NaN / 0 -> %s   (fr4 == 0 false, fr4 > 0 false: the "negative" arm)' % fx(r))
    check(ent, r == 0xFF7FFFFF, 'NaN/0 row')
    STATS[ent] = dict(n=n, grid=nqgrid, dz=dzgrid, rand=rq, rand_dz=rd)


# ----------------------------------------------------------------------------
# 0BE800  float comparator with hysteresis and a pass-through state
# ----------------------------------------------------------------------------
def model_hyst(vx, vt, vh, p, mode):
    if not f_gt(vt, vx):
        return 1
    return 0 if f_gt(f_sub(vt, vh, mode), vx) else p


def t_hyst():
    ent = 0x0BE800
    header(ent, 'r0 = 1 if NOT(fr5 > fr4); 0 if (fr5 - fr6) > fr4; else r4      [x=fr4, threshold=fr5, hysteresis=fr6, previous=r4]')
    n = dz = 0
    prevs = [0xDEADBEEF, 0]
    for x in FGRID_B:
        for t in FGRID_B:
            for h in FGRID_B:
                vx, vt, vh = val(x), val(t), val(h)
                for p in prevs:
                    r = run(ent, {4: p}, {4: x, 5: t, 6: h})['r0']
                    exp = model_hyst(vx, vt, vh, p, CHIP_MODE)
                    check(ent, r == exp, 'x=%s t=%s h=%s prev=%X got %X want %X' % (fx(x), fx(t), fx(h), p, r, exp))
                    dz += model_hyst(vx, vt, vh, p, ALT_MODE) != exp
                    if vh <= 0 and f_gt(vt, vx):             # zero or negative width: x < threshold always clears
                        check(ent, r == 0, 'non-positive width did not clear: x=%s t=%s h=%s' % (fx(x), fx(t), fx(h)))
                    n += 1
    ngrid = n
    out('%-22s %-22s %-22s %-10s -> %-10s %s' % ('fr4 x', 'fr5 threshold', 'fr6 hysteresis', 'r4 prev', 'r0', 'note'))
    for x, t, h, p, want, note in [(11.0, 10.0, 2.0, 0, 1, 'x > thr -> 1'), (10.0, 10.0, 2.0, 0, 1, 'x == thr -> 1 (>= sets)'),
                                   (9.999999, 10.0, 2.0, 0, 0, 'band: returns r4'), (9.0, 10.0, 2.0, 0, 0, 'band: returns r4'),
                                   (9.0, 10.0, 2.0, 1, 1, 'band: returns r4'), (9.0, 10.0, 2.0, 0xDEADBEEF, 0xDEADBEEF, 'band: r4 returned UNMASKED'),
                                   (8.0, 10.0, 2.0, 1, 1, 'x == thr - hyst: still band (returns r4)'),
                                   (7.9999995, 10.0, 2.0, 1, 0, 'x < thr - hyst -> 0'), (0.0, 10.0, 2.0, 1, 0, 'x < thr - hyst -> 0'),
                                   (9.0, 10.0, 0.0, 1, 0, 'zero hysteresis: x < thr -> 0'), (9.0, 10.0, -5.0, 1, 0, 'NEGATIVE hysteresis: x < thr -> 0'),
                                   (12.0, 10.0, -5.0, 0, 1, 'NEGATIVE hysteresis: x >= thr -> 1 (first test wins)'),
                                   (1599.9999, 1600.0, 100.0, 0, 0, 'the 0x046A68 call: thr 1600, width 1600-1500; below thr, prev 0 -> 0'),
                                   (1600.0, 1600.0, 100.0, 0, 1, 'the 0x046A68 call: x == 1600 sets'),
                                   (1500.0, 1600.0, 100.0, 1, 1, 'the 0x046A68 call: x == 1500 holds'),
                                   (1499.9999, 1600.0, 100.0, 1, 0, 'the 0x046A68 call: x < 1500 clears')]:
        r = run(ent, {4: p}, {4: fb(x), 5: fb(t), 6: fb(h)})['r0']
        # every row here is exact in both rounding modes (the subtraction is exact), so one expected value serves
        check(ent, model_hyst(val(fb(x)), val(fb(t)), val(fb(h)), p, 'RN') == want == model_hyst(val(fb(x)), val(fb(t)), val(fb(h)), p, 'RZ'),
              'row x=%r t=%r h=%r: stated %X is not what the models give' % (x, t, h, want))
        check(ent, r == want, 'row x=%r t=%r h=%r prev=%X got %X want %X' % (x, t, h, p, r, want))
        out('%-22s %-22s %-22s %08X   -> %08X   %s' % (fx(fb(x)), fx(fb(t)), fx(fb(h)), p, r, note))
        n += 1
    out('cases %d: exact in mode %s; GRID COUNT, not a rate: %d of the %d grid verdicts differ under round-to-nearest' % (n, CHIP_MODE, dz, ngrid))
    r = run(ent, {4: 0}, {4: 0x7FC00000, 5: fb(10.0), 6: fb(2.0)})['r0']
    out('EMU-MODEL  x = NaN -> %d   (a false fcmp/gt at 0BE800 falls into the "set" arm)' % r)
    check(ent, r == 1, 'NaN row')
    STATS[ent] = dict(n=n + 1, grid=ngrid, dz=dz)


# ----------------------------------------------------------------------------
# A SECOND GRID for the four routines whose INTEGER verdict can turn on a rounding edge:
# inputs placed deliberately on and next to the limit each routine computes (as either
# mode rounds it).  The share of verdicts that round-to-nearest would change is far higher
# here than on the broad grids above -- which is the point: those shares describe a grid,
# not the routine.
# ----------------------------------------------------------------------------
def t_edges():
    header(0x0BE5A8, 'EDGE-TARGETED GRIDS for 0BE5A8 / 0BE5D8 / 0BE608 / 0BE800 (asserted in mode %s, round-to-nearest model beside it)' % (CHIP_MODE,))
    cs = [fb(v) for v in (10.0, -10.0, 14.7, 100.3, 1600.0, 0.3, -40.0, 6700.0, 255.0, 1e-3)]
    ws = [fb(v) for v in (0.1, 0.3, 2.7, 1e-3, 33.3, 0.7, 1e-6, 123.456)]
    # 0BE608: x on and beside centre -/+ width as each mode rounds it
    ent = 0x0BE608
    n = d = 0
    for c in cs:
        for w in ws:
            vc, vw = val(c), val(w)
            xs = set()
            for lim in (f_sub(vc, vw, 'RN'), f_sub(vc, vw, 'RZ'), f_add(vc, vw, 'RN'), f_add(vc, vw, 'RZ')):
                if lim != 0:
                    xs.update(step32(fb(float(lim)), k) for k in (-2, -1, 0, 1, 2))
            for x in sorted(xs):
                r = run(ent, fregs={4: x, 5: c, 6: w})['r0']
                exp = model_window(val(x), vc, vw, CHIP_MODE)
                check(ent, r == exp, 'edge x=%s c=%s w=%s got %d want %d' % (fx(x), fx(c), fx(w), r, exp))
                d += model_window(val(x), vc, vw, ALT_MODE) != exp
                n += 1
    out('0BE608  %5d edge cases, %4d verdicts differ under round-to-nearest' % (n, d))
    STATS[ent].update(edge=n, edge_dz=d)
    # 0BE800: x on and beside threshold - width
    ent = 0x0BE800
    n = d = 0
    for t in cs:
        for h in ws:
            vt, vh = val(t), val(h)
            xs = set()
            for lim in (f_sub(vt, vh, 'RN'), f_sub(vt, vh, 'RZ'), vt):
                if lim != 0:
                    xs.update(step32(fb(float(lim)), k) for k in (-2, -1, 0, 1, 2))
            for x in sorted(xs):
                for p in (0, 1):
                    r = run(ent, {4: p}, {4: x, 5: t, 6: h})['r0']
                    exp = model_hyst(val(x), vt, vh, p, CHIP_MODE)
                    check(ent, r == exp, 'edge x=%s t=%s h=%s p=%d got %X want %X' % (fx(x), fx(t), fx(h), p, r, exp))
                    d += model_hyst(val(x), vt, vh, p, ALT_MODE) != exp
                    n += 1
    out('0BE800  %5d edge cases, %4d verdicts differ under round-to-nearest' % (n, d))
    STATS[ent].update(edge=n, edge_dz=d)
    # 0BE5A8 / 0BE5D8: x beside the value where (x - off)/scale + 0.5 crosses an integer
    for ent, top in ((0x0BE5A8, 255), (0x0BE5D8, 65535)):
        n = d = 0
        ks = [0, 1, 2, 3, 7, 100, 127, 128, 200, 254, 255, 256] + ([] if top == 255 else [1000, 4097, 32767, 32768, 65534, 65535, 65536])
        for sc in (0.1, 0.01, 1.8, 0.0078125, 14.7, 0.003921569, 1.0, 0.3515625):
            for of in (0.0, -40.0, 32.0, 0.5, 100.3):
                sb, ob = fb(sc), fb(of)
                for k in ks:
                    x0 = fb(float(val(ob) + val(sb) * (Fraction(k) - Fraction(1, 2))))
                    if bf(x0) == 0:
                        continue
                    for j in (-2, -1, 0, 1, 2):
                        xb = step32(x0, j)
                        r = run(ent, fregs={4: xb, 5: sb, 6: ob})['r0']
                        exp = model_f2u(val(xb), val(sb), val(ob), top, CHIP_MODE, sb)
                        check(ent, r == exp, 'edge x=%s scale=%r off=%r got %d want %d' % (fx(xb), sc, of, r, exp))
                        d += model_f2u(val(xb), val(sb), val(ob), top, ALT_MODE, sb) != exp
                        n += 1
        out('%06X  %5d edge cases, %4d integer results differ under round-to-nearest' % (ent, n, d))
        STATS[ent].update(edge=n, edge_dz=d)


# ----------------------------------------------------------------------------
# 0BE654  saturating signed (r4 << 16) / r5
# ----------------------------------------------------------------------------
def tz_div(n, d):
    q = abs(n) // abs(d)
    return -q if (n < 0) != (d < 0) else q


def model_q16(a, b):
    """a, b signed 32-bit.  Returns (r0 as unsigned 32, path)."""
    if a == 0:
        return 0, 'zero dividend'
    if b == 0:
        return (0x7FFFFFFF, 'div0 +') if a > 0 else (0x80000000, 'div0 -')
    if a == -2 ** 31 and b == -1:
        return 0x7FFFFFFF, 'INT_MIN/-1'
    q = tz_div(a, b)
    if q > 0x7FFF:
        return 0x7FFFFFFF, 'SAT+'
    if q < -0x8000:
        return 0x80000000, 'SAT-'
    full = tz_div(a << 16, b)
    if full < -2 ** 31:
        return full & M32, 'WRAP (unguarded: integer quotient == -32768 with a remainder)'
    return full & M32, ''


def t_q16():
    ent = 0x0BE654
    header(ent, 'r0 = saturating signed (r4 << 16) / r5, truncated toward zero')
    edge = [0, 1, -1, 2, -2, 3, -3, 7, 10, -10, 255, 256, 0x7FFF, 0x8000, 0x8001, -0x7FFF, -0x8000, -0x8001, 0xFFFF,
            0x10000, 0x10001, -0x10000, -0x10001, 98303, 98304, -98304, -98305, -98306, -98307, 0x7FFFFFFF, 0x7FFFFFFE,
            -0x80000000, -0x7FFFFFFF, 0x40000000, -0x40000000, 0x12345678, -0x12345678, 1000, -1000, 65535 * 3, 100000]
    cases = [(a, b) for a in edge for b in edge]
    for _ in range(4000):
        k = random.randrange(5)
        if k == 0:
            a, b = s32(random.getrandbits(32)), s32(random.getrandbits(32))
        elif k == 1:
            a, b = s32(random.getrandbits(32)), random.randint(-70000, 70000)
        elif k == 2:
            a, b = random.randint(-70000, 70000), random.randint(-70000, 70000)
        elif k == 3:                                   # ratio near +-32768
            b = random.randint(-3000, 3000) or 7
            a = s32(b * random.choice((32767, 32768, -32768, -32769)) + random.randint(-abs(b), abs(b)))
        else:
            a, b = random.randint(-2 ** 20, 2 ** 20), s32(random.getrandbits(32))
        cases.append((a, b))
    paths = {}
    wraps = []
    for a, b in cases:
        r = run(ent, {4: a, 5: b})['r0']
        exp, path = model_q16(a, b)
        check(ent, r == exp, 'a=%d b=%d got %08X want %08X (%s)' % (a, b, r, exp, path))
        paths[path] = paths.get(path, 0) + 1
        if path.startswith('WRAP'):
            wraps.append((a, b, r))
    out('%12s %12s -> %-10s %12s  %s' % ('r4', 'r5', 'r0', 'as signed', 'note'))
    rows = [(0, 0), (0, 5), (5, 0), (-5, 0), (-2 ** 31, 0), (-2 ** 31, -1), (-2 ** 31, 1), (2 ** 31 - 1, 1), (1, 1), (-1, 1), (1, -1),
            (1, 3), (-1, 3), (1, -3), (-1, -3), (-3, 2), (3, -2), (1, 0x10000), (1, 0x10001), (1, 2 ** 31 - 1), (1, -2 ** 31),
            (2 ** 31 - 1, -2 ** 31), (-2 ** 31, -2 ** 31), (32767, 1), (32768, 1), (-32768, 1), (-32769, 1), (98303, 3), (98304, 3),
            (-98304, 3), (-98305, 3), (-98306, 3), (-98307, 3), (-65537, 2), (2 ** 31 - 1, 0x10000), (2 ** 31 - 1, 0xFFFF)]
    for a, b in rows:
        r = run(ent, {4: a, 5: b})['r0']
        exp, path = model_q16(a, b)
        check(ent, r == exp, 'row a=%d b=%d got %08X want %08X' % (a, b, r, exp))
        out('%12d %12d -> %08X   %12d  %s' % (a, b, r, s32(r), path))
    out('cases %d; paths exercised: %s' % (len(cases) + len(rows), ', '.join('%s=%d' % (k or 'normal', v) for k, v in sorted(paths.items()))))
    out('WRAP band (trunc(r4/r5) == -32768 with a non-zero remainder) returned the low 32 bits of the true quotient,')
    out('a POSITIVE number, in all %d such grid cases; first few: %s' % (
        len(wraps), ', '.join('(%d,%d)->%08X' % w for w in wraps[:4])))
    check(ent, len(wraps) > 20 and all(not (r >> 31) for _, _, r in wraps), 'wrap band expectation')


# ----------------------------------------------------------------------------
# 0BE4FA  step lookup through a {count, thresholds*, values*} record
# ----------------------------------------------------------------------------
def model_step(n, thr_bits, vals, x_bits):
    x = bf(x_bits)
    i = n - 1
    while i >= 0:
        if not (bf(thr_bits[i]) > x):
            return vals[i]
        i -= 1
    return vals[0]


def t_step():
    ent = 0x0BE4FA
    header(ent, 'r0 = u8 values[i], i = highest index with NOT(thr[i] > fr4); values[0] when every thr[i] > fr4      [record=r4, x=fr4]')
    n = 0
    # (a) the two records the ROM itself passes (found at the two call sites 0x02F4AC and 0x07A22A)
    for rec in (0x0AC2B0, 0x0AB328):
        cnt = struct.unpack('>h', ROM[rec:rec + 2])[0]
        pthr, pval = struct.unpack('>II', ROM[rec + 4:rec + 12])
        thr = [struct.unpack('>I', ROM[pthr + 4 * i:pthr + 4 * i + 4])[0] for i in range(cnt)]
        vals = list(ROM[pval:pval + cnt])
        out('ROM record %06X: count=%d  thresholds@%06X  values@%06X' % (rec, cnt, pthr, pval))
        out('   thresholds %s' % ' '.join('%g' % bf(t) for t in thr))
        out('   values     %s' % ' '.join('%d' % v for v in vals))
        xs = set()
        for t in thr:
            xs.update((t, nextafter32(t, True), nextafter32(t, False)))
        xs.update(fb(v) for v in (-1e30, 1e30, 0.0, -0.0, 5.0, 849.99, 850.0, 9999.0, -41.0, -3.0, -2.999, 115.0))
        row = []
        for xb in sorted(xs, key=bf):
            r = run(ent, {4: rec}, {4: xb})['r0']
            exp = model_step(cnt, thr, vals, xb)
            check(ent, r == exp, 'rec %06X x=%s got %d want %d' % (rec, fx(xb), r, exp))
            row.append('%.9g->%d' % (bf(xb), r))
            n += 1
        for i in range(0, len(row), 6):
            out('   ' + '  '.join(row[i:i + 6]))
    # (b) synthetic records in RAM: count edges, non-monotonic thresholds, values above 0x7F
    base, pthr, pval = 0xFFFF1000, 0xFFFF1100, 0xFFFF1200

    def mk(cnt_word, thr, vals):
        def setup(emu):
            emu.ram_u16(base, cnt_word & 0xFFFF)
            emu.ram_u16(base + 2, 0xEEEE)
            emu.ram_u32(base + 4, pthr)
            emu.ram_u32(base + 8, pval)
            for i, t in enumerate(thr):
                emu.ram_u32(pthr + 4 * i, fb(t))
            for i, v in enumerate(vals):
                emu.ram_u8(pval + i, v)
        return setup

    out('synthetic records (in RAM):')
    out('   %-7s %-28s %-22s %-10s -> %s  %s' % ('count', 'thresholds', 'values', 'x', 'r0', 'note'))
    syn = [
        (4, [10.0, 20.0, 30.0, 40.0], [0x11, 0x80, 0xFF, 0x7F], [5.0, 10.0, 15.0, 20.0, 29.999, 30.0, 40.0, 1e9, -1e9],
         'values are ZERO-extended bytes'),
        (1, [10.0], [0xC8], [5.0, 10.0, 11.0], 'count 1: always values[0]'),
        (0, [10.0], [0xAB], [5.0, 50.0], 'count 0: loop skipped, values[0] still read and returned'),
        (-1, [10.0], [0xAB], [5.0, 50.0], 'count 0xFFFF (signed -1): same as count 0'),
        (4, [10.0, 40.0, 20.0, 30.0], [1, 2, 3, 4], [5.0, 15.0, 25.0, 35.0, 45.0],
         'NON-monotonic thresholds: the scan is from the TOP, first NOT-greater wins'),
        (3, [10.0, 10.0, 10.0], [7, 8, 9], [9.0, 10.0], 'equal thresholds: highest index wins'),
    ]
    for cnt, thr, vals, xs, note in syn:
        for x in xs:
            r = run(ent, {4: base}, {4: fb(x)}, setup=mk(cnt, thr, vals))['r0']
            exp = model_step(cnt, [fb(t) for t in thr], vals, fb(x))
            check(ent, r == exp, 'synthetic cnt=%d x=%r got %X want %X' % (cnt, x, r, exp))
            out('   %-7d %-28s %-22s %-10g -> %02X  %s' % (cnt, thr, ['%02X' % v for v in vals], x, r, note))
            n += 1
    # unordered input: the emulator models fcmp/gt as false, so the FIRST threshold tried (the top one) "passes"
    for rec in (0x0AC2B0, 0x0AB328):
        cnt = struct.unpack('>h', ROM[rec:rec + 2])[0]
        pval = struct.unpack('>I', ROM[rec + 8:rec + 12])[0]
        r = run(ent, {4: rec}, {4: 0x7FC00000})['r0']
        check(ent, r == ROM[pval + cnt - 1], 'NaN row rec %06X got %d' % (rec, r))
        out('EMU-MODEL  record %06X, x = NaN(7FC00000) -> %d   (the TOP bin: a false fcmp/gt at i = count-1 ends the scan)' % (rec, r))
        n += 1
    out('cases %d: exact' % n)


# The clobber sets stated in helpers_arith_trace.txt (union over every path exercised).
EXPECT_CLOBBER = {
    0x0BE4FA: 'r0 r2 r4 r5 r6 r7 fr8',
    0x0BE524: 'r0 r5',
    0x0BE53C: 'r0 r3 r4 r5',
    0x0BE554: 'r0 r4 r5',
    0x0BE56C: 'fr0 fr7',
    0x0BE588: 'r4 fr0 fr3 fr5 fpul',
    0x0BE598: 'r4 fr0 fr3 fr5 fpul',
    0x0BE5A8: 'r0 r4 r5 fr2 fr3 fr4 fpul',
    0x0BE5D8: 'r0 r4 r5 fr2 fr3 fr4 fpul',
    0x0BE608: 'r0 r4 fr3',
    0x0BE628: 'r0 fr0 fr3 fr6',
    0x0BE654: 'r0 r1 r3 r4 r6 r7',
    0x0BE800: 'r0 r5 fr5',
}


# ----------------------------------------------------------------------------
def main():
    got = hashlib.md5(ROM).hexdigest()
    assert got == MD5, 'reference bin md5 %s != %s' % (got, MD5)
    print('reference bin  %s  md5 %s  OK' % (os.path.basename(BIN), got))
    t_selftest()
    t_step()
    t_sat_add_s32()
    t_sat_add_u8()
    t_sat_add_u16()
    t_clamp()
    t_scale(0x0BE588, 8)
    t_scale(0x0BE598, 16)
    t_f2u(0x0BE5A8, 255)
    t_f2u(0x0BE5D8, 65535)
    t_window()
    t_safe_div()
    t_q16()
    t_hyst()
    t_edges()
    print('')
    for ent, want in EXPECT_CLOBBER.items():
        check(ent, CLOBBER.get(ent, set()) == set(want.split()), 'clobber set %s != stated %s' % (sorted(CLOBBER.get(ent, ())), want))
    print('SUMMARY  (emulated calls = 2 poisoned runs per grid case; clobbers = registers observed changed on return;')
    print('          every call also asserted: returns through PR, r15 unchanged, no memory written, no uninitialised RAM read)')
    for ent in sorted(TOTAL):
        cl = sorted(CLOBBER.get(ent, ()), key=lambda s: (s[0] != 'r', s.startswith('fp'), int(''.join(c for c in s if c.isdigit()) or 99)))
        print('  %06X  calls %7d  clobbers %s' % (ent, TOTAL[ent], ' '.join(cl)))
    print('float rounding: the ROM self-test (0x058696..0x0586DE) requires TRUNCATION of fmac/fmul/fdiv; the emulator implements %s;' % (
        'round-to-nearest and FAILS those checks' if EMU_MODE == 'RN' else 'truncation and passes them'))
    print('                every float result above is asserted bit-exact in mode %s (fmac fused); "dz" counts = where round-to-nearest differs' % CHIP_MODE)
    print('grid counts quoted in the trace (properties of the grids, not rates):')
    for ent in sorted(STATS):
        print('  %06X  %s' % (ent, '  '.join('%s=%s' % kv for kv in STATS[ent].items())))
    notes = sorted(EMU.notes)
    print('emulator notes: %s' % ('; '.join(notes) if notes else 'none'))
    if FAIL:
        print('FAILED: %d contract violations' % len(FAIL))
        for f in FAIL[:40]:
            print('   ' + f)
        return 1
    print('ALL CONTRACTS HOLD: %d emulated calls, 0 violations' % sum(TOTAL.values()))
    return 0


if __name__ == '__main__':
    sys.exit(main())
