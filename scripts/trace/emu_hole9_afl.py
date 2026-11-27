#!/usr/bin/env python3
"""emu_hole9_afl.py -- emulation evidence for disassembly/analysis/hole9_afl_trace.txt

Open-hole #9: the float pair at ROM 0x0357C8 / 0x0357CC (stock +0.5 / -0.5,
every flashed rev 0.0 / 0.0) that function 0x0355B8 passes to the clamp helper
0x0BE56C before storing the result through struct 0x063A88 +76 -> RAM 0xFFFF7904.

    python3 scripts/trace/emu_hole9_afl.py            # prints tables, asserts, exit 0
    python3 scripts/trace/emu_hole9_afl.py --quick    # smaller random grid

WHAT IS RUN, AND AGAINST WHAT
  Every section runs ROM code in scripts/sh2e_emu.py and compares the result
  with a model written in this file from the byte reading in the analysis file.
  The model is float32-exact: same rounding points as the instruction stream,
  each one rounded TOWARD ZERO as the chip does (FPSCR.RM = 01, corrections
  item 106; see fadd/fsub/fmul/fdiv/fmac below). Comparisons are BIT-EXACT
  unless a tolerance is stated; the only tolerances are against interp(), an
  independent interpolation that does not model 0x0BE830's instruction stream.

  ROM images
    TUNED   rom/AE5L600L 20g rev 20.19c.bin as flashed  (0x0357C8/CC = 0.0 / 0.0)
    SBND    the same image with ONLY 0x0357C8/CC restored to +0.5 / -0.5
    SBND2   SBND with 0x035FFC/0x036000 also restored to +0.5 / -0.5
    STOCK   rom/ae5l600l.bin (used to prove SBND2 == stock for this module)

  0  the images: module diff stock/tuned, twenty calibration ranges equal in
     stock, 20.19c and every flashed bin under rom/
  A  helpers 0x0BE56C / 0x0BE960 / 0x0BE970 / 0x0BEA40 (argument order, NaN),
     0x0BE554 / 0x0BE53C (saturating adds), 0x0BE608 (band test)
  B  0x0355B8 over a grid, TUNED vs SBND, against model_355B8(); asserts WHEN
     the stock outer clamp changes the value (claim C18)
  C  0x0353BC over a grid, against model_353BC() (independent interpolation)
  D  0x034EF4 whole chain (the scheduler entry): D0 siblings, D1b state init
     does not write, D2 / D2b gating of 0xFFFF7912 at exact thresholds and NaN
     (claim C22), D3 reload, D4 init, D5 a multi-tick trajectory TUNED vs SBND
  E  consumers of 0xFFFF7904: E1 0x033460 (additive term), E1b 0x0332A2 (the
     other writer of 77BC..77C8), E2/E2b scaled exports, E2c 0x06665E (whole
     function, write set), E2d 0x0668B4 / 0x066904 (the other readers of the
     copy, claim C31), E2e the remaining loaders of table 0x097520 (bytes),
     E3 the 0x03580C chain: 0x0358A0, 0x0359A4 (whole function), 0x035DE4,
     0x035E2C, 0x035E64
  F  0x035F48: the SECOND zeroed pair 0x035FFC / 0x036000 -> 0xFFFF318C
  G  the other stores to 0xFFFF318C (0x035E88 init rewrite, 0x0357E8 reset), the
     record check 0x0357F0 / 0x0BDCB6, 0x0357D0; G4 when 0x03580C runs its
     body (claim C24)
  H  lifecycle: leftover 0xFFFF318C, init, three periodic passes of
     0x034EF4 + 0x03580C, init again -- tuned vs both pairs restored
  I  reach of the stock module (claim C49)
  J  0x00C5FC, the writer of the regulated input 0xFFFF43FC

WHAT THE EMULATOR CANNOT RUN HERE
  0x00317C / 0x003190 execute `ldc r4,sr` (interrupt-mask save/restore); the
  emulator raises on ldc sr, so both are stubbed (r0 = 0). They touch no data
  this trace cares about; that statement is from bytes, not from emulation.
  fmac is rounded once (fused, toward zero) in the emulator (flagged in
  emu.notes); the model does the same, so a fused/unfused difference on silicon
  would not show up here. The ROM self-test settles the rounding mode, not that.
"""
import glob
import math
import os
import random
import re
import struct
import sys
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, os.path.join(REPO, 'scripts'))
import sh2e_emu as E          # noqa: E402
import desc_types as T        # noqa: E402
import sh2e_disasm as D       # noqa: E402

TUNED_PATH = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
STOCK_PATH = os.path.join(REPO, 'rom', 'ae5l600l.bin')
QUICK = '--quick' in sys.argv

TUNED = open(TUNED_PATH, 'rb').read()
STOCK = open(STOCK_PATH, 'rb').read()


def patched(img, pairs):
    b = bytearray(img)
    for addr, val in pairs:
        b[addr:addr + 4] = struct.pack('>f', val)
    return bytes(b)


SBND = patched(TUNED, [(0x0357C8, 0.5), (0x0357CC, -0.5)])
SBND2 = patched(SBND, [(0x035FFC, 0.5), (0x036000, -0.5)])

# Every ROM range (outside the module's own code) that the functions run in this
# script read. Section 0 asserts each is identical in stock, in 20.19c and in
# every flashed bin under rom/.
CAL_RANGES = (
    (0x0CC090, 0x0CC16C, 'scalars 0xCC090..0xCC168 (gate, gains, step sizes and limits)'),
    (0x0CBBEF, 0x0CBBF2, 'bytes 0xCBBEF..0xCBBF1 (period of 0x03580C, counts in 0x0359A4)'),
    (0x0CBC48, 0x0CBC5A, 'words 0xCBC48..0xCBC58 (counter thresholds)'),
    (0x0C5054, 0x0C506C, 'scalars 0xC5054..0xC5068 (init rewrite of 0xFFFF318C)'),
    (0x0CCBF0, 0x0CCD30, 'axes/data of descriptors 0xAC530..0xAC594'),
    (0x0CE188, 0x0CE580, 'axes/data of descriptors 0xACF14..0xAD07C'),
    (0x0CC664, 0x0CC6A4, 'axis of descriptor 0xAD054'),
    (0x0D1B44, 0x0D1BCC, 'axes/data of descriptor 0xAD944'),
    (0x0D25C0, 0x0D2970, 'axes/data of descriptors 0xADA5C, 0xADA70'),
    (0x0AC530, 0x0AC5A8, 'descriptor records 0xAC530..0xAC594'),
    (0x0ACF14, 0x0AD090, 'descriptor records 0xACF14..0xAD07C'),
    (0x0AD944, 0x0AD958, 'descriptor record 0xAD944'),
    (0x0ADA5C, 0x0ADA84, 'descriptor records 0xADA5C, 0xADA70'),
    (0x063A88, 0x063B20, 'pointer tables 0x063A88 (30 longs) and 0x063B00 (8 longs)'),
    (0x097520, 0x097580, 'pointer tables 0x097520, 0x097560 (consumer 0x06665E)'),
    (0x0C50C8, 0x0C5100, 'scalars 0xC50C8..0xC50FC (consumers 0x06665E, 0x0668B4, 0x066904)'),
    (0x0C478C, 0x0C478D, 'byte 0xC478C (consumers 0x0668B4, 0x066904)'),
    (0x0C48DC, 0x0C48E0, 'words 0xC48DC, 0xC48DE (consumer 0x06665E)'),
    (0x0CBBDF, 0x0CBBE0, 'byte 0xCBBDF (switch in consumer 0x032204)'),
    (0x0CBF3C, 0x0CBF60, 'scalars 0xCBF3C..0xCBF5C (consumer 0x033460)'),
)

# ---- struct 0x063A88: pointer table, resolved from ROM bytes -----------------
STRUCT = 0x063A88
P = {off: struct.unpack_from('>I', TUNED, STRUCT + off)[0] for off in range(0, 120, 4)}
A_TGT, A_K, A_SKIP, A_KP, A_KI = P[0], P[4], P[8], P[12], P[16]
A_PLO, A_PHI, A_WLO_T, A_WLO_ALT, A_WLO, A_WHI = P[20], P[24], P[28], P[32], P[36], P[40]
A_E, A_EF, A_LPF, A_ELO, A_EHI = P[44], P[48], P[52], P[56], P[60]
A_P, A_IT, A_TOT, A_OUT, A_INTEG, A_L0 = P[64], P[68], P[72], P[76], P[80], P[84]
A_CUR, A_PREV, A_LIMLO, A_LIMHI = P[88], P[92], P[96], P[100]
A_CNT, A_EN, A_HYS, A_MODE = P[104], P[108], P[112], P[116]
A_MAF, A_LRN = 0xFFFF63CC, 0xFFFF318C

EXPECT = {0: 0xFFFF78B8, 4: 0xFFFF78BC, 8: 0xFFFF78C0, 12: 0xFFFF78C4, 16: 0xFFFF78C8,
          20: 0xFFFF78CC, 24: 0xFFFF78D0, 28: 0xFFFF78D4, 32: 0xFFFF78D8, 36: 0xFFFF78DC,
          40: 0xFFFF78E0, 44: 0xFFFF78E4, 48: 0xFFFF78E8, 52: 0xFFFF78EC, 56: 0xFFFF78F0,
          60: 0xFFFF78F4, 64: 0xFFFF78F8, 68: 0xFFFF78FC, 72: 0xFFFF7900, 76: 0xFFFF7904,
          80: 0xFFFF7908, 84: 0xFFFF790C, 88: 0xFFFF78B4, 92: 0xFFFF792C, 96: 0xFFFF7930,
          100: 0xFFFF7934, 104: 0xFFFF7910, 108: 0xFFFF7912, 112: 0xFFFF7913, 116: 0xFFFF7941}

CHECKS = 0


def ok(cond, msg):
    global CHECKS
    CHECKS += 1
    if not cond:
        raise AssertionError(msg)


# ---- float32 helpers ---------------------------------------------------------
def f32(x):
    return E.b2f(E.f2b(x))


def bits(x):
    return E.f2b(x)


def same(a, b):
    """bit-exact float32 equality (NaN == NaN, +0 != -0)."""
    if a != a and b != b:
        return True
    return bits(a) == bits(b)


def romf(img, a):
    return struct.unpack_from('>f', img, a)[0]


# ---- single-precision arithmetic AS THE CHIP DOES IT --------------------------
# The SH7058 FPU runs with FPSCR = 0x00040001: RM = 01, round TOWARD ZERO, and
# DN = 1, denormals flushed (reset code 00FA42 / 00FA44; the ROM's own FPU
# self-test at 0x058696 demands truncated results; corrections item 106). Every
# model in this file therefore does its fadd / fsub / fmul / fdiv / fmac here:
# the EXACT rational result (fractions.Fraction), truncated once to float32 by
# sh2e_emu.rz_bits() (overflow -> FLT_MAX, denormal -> signed zero). fmac is
# fused: f0*fm + fn exact, one rounding. The sign of an exact zero result and
# Inf/NaN propagation follow IEEE, which are the same in both rounding modes
# for these operations, so they are taken from the double result.
# Python float arithmetic (round-to-nearest, in double) is used ONLY to build test
# INPUTS, which reach the emulator through f2b (nearest) -- f32() above.
def _op32(*xs):
    for x in xs:
        if not same(x, f32(x)):
            raise AssertionError('model operand %r is not a float32 value' % (x,))


def _rz(q, dbl):
    """q = exact result (Fraction) of finite operands; dbl = the double result."""
    if q == 0:
        return f32(dbl)                             # exact zero: IEEE sign rules
    return E.b2f(E.rz_bits(q))


def fadd(a, b):
    _op32(a, b)
    if math.isfinite(a) and math.isfinite(b):
        return _rz(Fraction(a) + Fraction(b), a + b)
    return f32(a + b)


def fsub(a, b):
    """a - b (fsub FRm,FRn computes FRn - FRm: here a = FRn, b = FRm)."""
    _op32(a, b)
    if math.isfinite(a) and math.isfinite(b):
        return _rz(Fraction(a) - Fraction(b), a - b)
    return f32(a - b)


def fmul(a, b):
    _op32(a, b)
    if math.isfinite(a) and math.isfinite(b):
        return _rz(Fraction(a) * Fraction(b), a * b)
    return f32(a * b)


def fdiv(a, b):
    """a / b (fdiv FRm,FRn computes FRn / FRm: here a = FRn, b = FRm)."""
    _op32(a, b)
    if b == 0.0:
        if a != a or a == 0.0:
            return float('nan')
        return math.copysign(math.inf, a) * math.copysign(1.0, b)
    if math.isfinite(a) and math.isfinite(b):
        return _rz(Fraction(a) / Fraction(b), a / b)
    return f32(a / b)


def fmac(f0, fm, fn):
    """fmac FR0,FRm,FRn: FRn = FR0*FRm + FRn, fused (one rounding toward zero)."""
    _op32(f0, fm, fn)
    if math.isfinite(f0) and math.isfinite(fm) and math.isfinite(fn):
        return _rz(Fraction(f0) * Fraction(fm) + Fraction(fn), f0 * fm + fn)
    return f32(f0 * fm + fn)


# ---- models of the helpers (from the byte reading) ---------------------------
def clamp(x, lo, hi):
    """0x0BE56C(fr4=x, fr5=lo, fr6=hi). NOT (x > lo) -> lo ; NOT (hi > x) -> hi ; else x."""
    if not (x > lo):
        return lo
    if not (hi > x):
        return hi
    return x


def fmax(a, b):
    """0x0BE960(fr4=a, fr5=b): a if a > b else b."""
    return a if a > b else b


def fmin(a, b):
    """0x0BE970(fr4=a, fr5=b): a if b > a else b."""
    return a if b > a else b


def lpf(new, old, k, eps):
    """0x0BEA40(fr4=new, fr5=old, fr6=k, fr7=eps)."""
    if (bits(old) & 0x7F800000) == 0x7F800000:      # old is Inf/NaN -> new
        return new
    d = fsub(old, new)                              # 0BEA4C fsub fr4,fr5
    c = fsub(1.0, k)                                # 0BEA4E fldi1 fr0 ; 0BEA50 fsub fr6,fr0
    r = fmac(c, d, new)                             # 0BEA54 fmac fr0,fr5,fr6 (fused)
    if eps > abs(fsub(new, r)):                     # 0BEA58 fsub fr6,fr5 ; fabs ; fcmp/gt fr5,fr7
        return new
    return r


def interp(img, desc, x):
    """Independent 1-D lookup: clamp to the axis ends, linear in between.

    Deliberately NOT a model of 0x0BE830's instruction sequence (that is the
    subject of the helpers_interp trace), so it is computed in double and every
    comparison against it carries a stated tolerance (1e-7 .. 2e-6, unchanged
    since the round-to-nearest version). Everything else in this file is
    compared bit-exactly against round-toward-zero models."""
    t = T.read_table(img, desc)
    ax, v = t['axes']['x'], t['values']
    if x != x or x <= ax[0]:
        return v[0]
    if x >= ax[-1]:
        return v[-1]
    for i in range(len(ax) - 1):
        if ax[i] <= x <= ax[i + 1]:
            return v[i] + (v[i + 1] - v[i]) * (x - ax[i]) / (ax[i + 1] - ax[i])
    raise AssertionError('interp')


def new_emu(img):
    """A fresh emulator with NO RAM initialised. Every input a test needs must be
    written explicitly; emu.uninit_reads then names anything that was forgotten.
    (The first version of this script zeroed 0xFFFF7700..0xFFFF7A00 here, which
    made its 'no uninitialised read' assertions blind inside the module's own RAM
    block. That blanket zeroing is gone.)"""
    emu = E.Emu(img)
    emu.stub(0x00317C, r0=0)       # ldc sr inside: see module docstring
    emu.stub(0x003190, r0=0)
    return emu


def nextdown(x):
    """the float32 just below x (toward -inf)."""
    b = E.f2b(x)
    if b == 0x00000000:
        return E.b2f(0x80800000)                    # no denormals on the SH-2E
    return E.b2f(b - 1 if not (b & 0x80000000) else b + 1)


def nextup(x):
    """the float32 just above x (toward +inf)."""
    b = E.f2b(x)
    if b == 0x80000000:
        return E.b2f(0x00800000)
    return E.b2f(b + 1 if not (b & 0x80000000) else b - 1)


def u16(img, a):
    return struct.unpack_from('>H', img, a)[0]


def sat16(x):
    """0x0BE554(r4 = x, r5 = 1): min(x + 1, 0xFFFF)."""
    return min((x & 0xFFFF) + 1, 0xFFFF)


def sat8(x):
    """0x0BE53C(r4 = x, r5 = 1): min(x + 1, 0xFF)."""
    return min((x & 0xFF) + 1, 0xFF)


def outside(x, c, tol):
    """0x0BE608(fr4 = x, fr5 = c, fr6 = tol): 1 when (c - tol) > x or x > (c + tol), else 0."""
    return 1 if (fsub(c, tol) > x) or (x > fadd(c, tol)) else 0


# =============================================================================
# 0. the images
# =============================================================================
def section_images():
    print('== 0. images ' + '=' * 60)
    ok(P == EXPECT, 'struct 0x063A88 does not resolve as documented')
    print('struct 0x063A88 resolves to the 30 documented RAM addresses (+76 -> 0x%08X)' % P[76])
    diffs = [a for a in range(0x034EC8, 0x036008) if TUNED[a] != STOCK[a]]
    print('stock vs tuned, bytes differing in 0x034EC8..0x036007:',
          ', '.join('0x%06X %02X->%02X' % (a, STOCK[a], TUNED[a]) for a in diffs))
    ok(diffs == [0x0357C8, 0x0357CC, 0x035FFC, 0x036000], 'unexpected module diff')
    for a, s in ((0x0357C8, 0.5), (0x0357CC, -0.5), (0x035FFC, 0.5), (0x036000, -0.5)):
        ok(romf(STOCK, a) == s and romf(TUNED, a) == 0.0 and TUNED[a:a + 4] == b'\0\0\0\0',
           'bounds at %06X' % a)
    ok(SBND2[0x034EC8:0x036008] == STOCK[0x034EC8:0x036008], 'SBND2 != stock in module')
    print('SBND2[0x034EC8..0x036007] == STOCK: True  (the module code is otherwise identical)')
    for lo, hi, what in CAL_RANGES:
        ok(TUNED[lo:hi] == STOCK[lo:hi], 'calibration differs %06X (%s)' % (lo, what))
    print('every ROM range the module and the consumers decoded here read is identical stock/tuned:')
    for lo, hi, what in CAL_RANGES:
        print('    0x%06X..0x%06X  %s' % (lo, hi - 1, what))
    # every flashed rev in rom/: the four clamp longs, the module code, the same ranges
    bins = sorted(glob.glob(os.path.join(REPO, 'rom', 'AE5L600L 20g rev *.bin')))
    ok(len(bins) >= 1, 'no flashed bins found')
    for path in bins:
        img = open(path, 'rb').read()
        tag = os.path.basename(path)
        for a in (0x0357C8, 0x0357CC, 0x035FFC, 0x036000):
            ok(img[a:a + 4] == b'\0\0\0\0', '%s: clamp long %06X not zero' % (tag, a))
        ok(img[0x034EC8:0x036008] == TUNED[0x034EC8:0x036008], '%s: module code differs from 20.19c' % tag)
        for lo, hi, what in CAL_RANGES:
            ok(img[lo:hi] == TUNED[lo:hi], '%s: %s differs from 20.19c' % (tag, what))
    print('%d flashed bins in rom/ (%s .. %s): the four clamp longs are 00000000 in every one,'
          % (len(bins), os.path.basename(bins[0]).split('rev ')[1][:-4],
             os.path.basename(bins[-1]).split('rev ')[1][:-4]))
    print('  0x034EC8..0x036007 is byte-identical to 20.19c, and so is every range listed above')


# =============================================================================
# A. helpers
# =============================================================================
def section_helpers():
    print('\n== A. helpers ' + '=' * 59)
    nan, inf = float('nan'), float('inf')
    vals = [-inf, -1e30, -0.75, -0.5, -0.25, -0.0, 0.0, 1e-30, 0.25, 0.5, 0.75, 1e30, inf, nan]
    n = 0
    for x in vals:
        for lo, hi in ((-0.5, 0.5), (0.0, 0.0), (0.5, -0.5), (nan, 0.5), (-0.5, nan)):
            emu = E.Emu(TUNED)
            emu.call(0x0BE56C, fregs={4: x, 5: lo, 6: hi})
            ok(same(emu.fr(0), clamp(x, lo, hi)), 'BE56C %r %r %r' % (x, lo, hi))
            if lo == 0.0 and hi == 0.0:
                ok(emu.FR[0] == 0, 'clamp(x,0,0) must be +0.0 bits for x=%r' % x)
            n += 1
        for y in vals:
            for entry, fn in ((0x0BE960, fmax), (0x0BE970, fmin)):
                emu = E.Emu(TUNED)
                emu.call(entry, fregs={4: x, 5: y})
                ok(same(emu.fr(0), fn(x, y)), '%06X %r %r' % (entry, x, y))
                n += 1
    for new in (-0.3, 0.0, 0.0216, 0.7, nan):
        for old in (-0.2, 0.0, 0.0215999, 0.69, inf, nan):
            for k in (0.0, 0.1, 0.25, 1.0):
                emu = E.Emu(TUNED)
                emu.call(0x0BEA40, fregs={4: new, 5: old, 6: k, 7: romf(TUNED, 0x0357A8)})
                ok(same(emu.fr(0), lpf(f32(new), f32(old), f32(k), romf(TUNED, 0x0357A8))),
                   'BEA40 %r %r %r' % (new, old, k))
                n += 1
    # the integer/compare helpers the gate and the 0x03580C chain lean on
    m = 0
    for x in (0, 1, 30, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF):
        emu = E.Emu(TUNED)
        emu.call(0x0BE554, regs={4: x, 5: 1})
        ok(emu.R[0] == sat16(x), 'BE554 %x' % x)
        emu = E.Emu(TUNED)
        emu.call(0x0BE554, regs={4: 0xFFFF0000 | x, 5: 1})      # sign-extended word in r4
        ok(emu.R[0] == sat16(x), 'BE554 sext %x' % x)
        m += 2
    for x in (0, 1, 0x7F, 0x80, 0xFE, 0xFF):
        emu = E.Emu(TUNED)
        emu.call(0x0BE53C, regs={4: x, 5: 1})
        ok(emu.R[0] == sat8(x), 'BE53C %x' % x)
        m += 1
    tol = romf(TUNED, 0x035A64)
    for x in (0.0, -0.0, tol, nextup(tol), nextdown(tol), -tol, nextdown(-tol), nextup(-tol), 1.0, -1.0, nan):
        emu = E.Emu(TUNED)
        emu.call(0x0BE608, fregs={4: x, 5: 0.0, 6: tol})
        ok(emu.R[0] == outside(f32(x), 0.0, tol), 'BE608 %r' % x)
        m += 1
    print('0x0BE554(r4,1) = min(u16(r4)+1, 0xFFFF)   0x0BE53C(r4,1) = min(u8(r4)+1, 0xFF)')
    print('0x0BE608(x, c, tol) = 1 when (c-tol) > x or x > (c+tol), else 0 (0 for NaN)')
    print('  %d integer / band-test helper cases (0x0BE554, 0x0BE53C, 0x0BE608)' % m)
    print('0x0BE56C(fr4=x, fr5=lo, fr6=hi) = lo if !(x>lo) else hi if !(hi>x) else x')
    print('0x0BE960 = max(fr4,fr5)   0x0BE970 = min(fr4,fr5)   0x0BEA40 = k*new+(1-k)*old, snap<eps')
    print('  0x0BE56C with lo=hi=0.0 returns +0.0 (bits 00000000) for every x incl. NaN/Inf/-0.0')
    print('  %d helper cases bit-exact' % n)


# =============================================================================
# B. 0x0355B8
# =============================================================================
IN_B = ('cur', 'prev', 'tgt', 'K', 'kp', 'ki', 'plo', 'phi', 'wlo', 'whi', 'skip',
        'ef', 'integ', 'it', 'L', 'maf', 'out0')
ADDR_B = {'cur': A_CUR, 'prev': A_PREV, 'tgt': A_TGT, 'K': A_K, 'kp': A_KP, 'ki': A_KI,
          'plo': A_PLO, 'phi': A_PHI, 'wlo': A_WLO, 'whi': A_WHI, 'skip': A_SKIP,
          'ef': A_EF, 'integ': A_INTEG, 'it': A_IT, 'L': A_LRN, 'maf': A_MAF, 'out0': A_OUT}
OUT_B = (A_E, A_EF, A_LPF, A_ELO, A_EHI, A_P, A_IT, A_TOT, A_OUT, A_INTEG, A_PREV,
         A_LIMLO, A_LIMHI)


def run_355B8(img, c):
    emu = new_emu(img)
    for k in IN_B:
        emu.ram_f32(ADDR_B[k], c[k])
    emu.ram_u8(A_EN, c['en'])
    emu.ram_u8(A_MODE, c['mode'])
    r = emu.call(0x0355B8)
    ok(r == 'return', 'did not return')
    ok(not emu.uninit_reads, 'uninit reads %s' % sorted(map(hex, emu.uninit_reads)))
    return {a: emu.read_f32(a) for a in OUT_B}, emu


def model_355B8(c, lo1, hi1, b_hi, b_lo):
    """b_hi = ROM 0x0357C8 (-> fr6), b_lo = ROM 0x0357CC (-> fr5)."""
    f = {k: f32(c[k]) for k in IN_B}
    o = {A_EF: f['ef'], A_LPF: 0.0, A_ELO: 0.0, A_EHI: 0.0, A_P: 0.0, A_IT: f['it'],
         A_TOT: 0.0, A_OUT: f['out0'], A_INTEG: f['integ'], A_LIMLO: 0.0, A_LIMHI: 0.0}
    e = fsub(fmul(fsub(f['prev'], f['tgt']), f['K']), fsub(f['cur'], f['tgt']))   # 0x0355E0..0x0355F4
    o[A_E] = e
    o[A_PREV] = f['cur']
    if c['en'] != 1:
        o[A_EF] = e
        return o
    filt = lpf(e, f['ef'], romf(TUNED, 0x0CC10C), romf(TUNED, 0x0357A8))
    o[A_LPF], o[A_ELO], o[A_EHI] = filt, lo1, hi1
    e2 = fmin(filt, hi1) if 0.0 > e else fmax(filt, lo1)
    o[A_EF] = e2
    p = clamp(fmul(e2, f['kp']), f['plo'], f['phi'])
    o[A_P] = p
    s = fadd(f['integ'], e2)
    it = fmul(f['ki'], s)
    tot = fadd(fadd(p, it), f['skip'])
    o[A_TOT] = tot
    limlo = fsub(f['L'], f['wlo'])
    limhi = fadd(f['whi'], f['L'])
    o[A_LIMLO], o[A_LIMHI] = limlo, limhi
    if (tot > limlo) and (limhi > tot):
        o[A_INTEG], o[A_IT] = s, it
    inner = clamp(tot, limlo, limhi)
    o[A_OUT] = clamp(inner, b_lo, b_hi)
    o['inner'] = inner
    return o


def base_case():
    return dict(cur=0.60, prev=0.62, tgt=0.70, K=0.98, kp=-1.25, ki=-0.001, plo=-0.02,
                phi=0.02, wlo=0.02, whi=0.02, skip=0.0001, ef=0.0, integ=0.0, it=0.0,
                L=0.01, maf=12.0, out0=0.123, en=1, mode=0)


def grid_B():
    nan, inf = float('nan'), float('inf')
    cases = []

    def add(tag, **kw):
        c = base_case()
        c.update(kw)
        c['tag'] = tag
        cases.append(c)

    add('base')
    add('disabled en=0', en=0)
    add('disabled en=2', en=2)
    add('disabled en=255', en=255)
    add('mode=1 tables', mode=1)
    add('mode=2 (not 1)', mode=2)
    add('E<0 branch', cur=0.80, prev=0.78)
    add('E==0', cur=0.70, prev=0.70)
    add('hits upper window', integ=-60.0)
    add('hits lower window', integ=60.0)
    add('exactly at upper window', kp=0.0, ki=0.0, skip=0.03, L=0.01, whi=0.02)
    add('exactly at lower window', kp=0.0, ki=0.0, skip=-0.01, L=0.01, wlo=0.02)
    add('window inverted lo>hi', wlo=-0.05, whi=-0.05)
    add('L=+0.45 (window above 0)', L=0.45, integ=-460.0)
    add('L=-0.45 (window below 0)', L=-0.45, integ=440.0)
    add('L=+0.60 > stock bound', L=0.60, integ=-600.0)
    add('L=-0.60 < stock bound', L=-0.60, integ=600.0)
    add('window 0.46..0.53, total above', L=0.48, wlo=0.02, whi=0.05, integ=-560.0)
    add('window 0.46..0.53, total inside', L=0.48, wlo=0.02, whi=0.05, integ=-470.0)
    add('window -0.53..-0.46, total below', L=-0.48, wlo=0.05, whi=0.02, integ=560.0)
    add('wide window, big +', wlo=5.0, whi=5.0, skip=2.0)
    add('wide window, big -', wlo=5.0, whi=5.0, skip=-2.0)
    add('wide window, +0.5 exactly', wlo=5.0, whi=5.0, kp=0.0, ki=0.0, skip=0.5, L=0.0)
    add('wide window, -0.5 exactly', wlo=5.0, whi=5.0, kp=0.0, ki=0.0, skip=-0.5, L=0.0)
    add('P clamp low', kp=-100.0)
    add('P clamp high', kp=100.0)
    add('cur NaN', cur=nan)
    add('cur +Inf', cur=inf)
    add('prev -Inf', prev=-inf)
    add('L NaN', L=nan)
    add('filter state Inf', ef=inf)
    add('filter state NaN', ef=nan)
    add('all zero', cur=0.0, prev=0.0, tgt=0.0, K=0.0, kp=0.0, ki=0.0, plo=0.0, phi=0.0,
        wlo=0.0, whi=0.0, skip=0.0, L=0.0)
    add('maf below axis', maf=-5.0)
    add('maf above axis', maf=500.0)
    rng = random.Random(9)
    for i in range(300 if QUICK else 1500):
        c = base_case()
        c.update(cur=rng.uniform(0, 1), prev=rng.uniform(0, 1), tgt=rng.uniform(0.5, 0.8),
                 K=rng.choice((0.98, 0.995, 0.0, 1.0, rng.uniform(0, 1))),
                 kp=rng.choice((-1.25, 0.0, rng.uniform(-2, 2))),
                 ki=rng.choice((-0.001, rng.uniform(-0.01, 0.01))),
                 plo=rng.uniform(-0.03, 0.0), phi=rng.uniform(0.0, 0.03),
                 wlo=rng.choice((0.003, 0.03, 0.07, rng.uniform(0, 0.8))),
                 whi=rng.choice((0.007, 0.03, rng.uniform(0, 0.8))),
                 skip=rng.uniform(-0.002, 0.002), ef=rng.uniform(-0.6, 0.6),
                 integ=rng.uniform(-700, 700), it=rng.uniform(-0.5, 0.5),
                 L=rng.choice((0.0, 0.01, -0.01, rng.uniform(-0.7, 0.7))),
                 maf=rng.uniform(-5, 90), out0=rng.uniform(-1, 1),
                 en=rng.choice((1, 1, 1, 0, 2)), mode=rng.choice((0, 1, 2)))
        c['tag'] = 'rnd%d' % i
        cases.append(c)
    return cases


def section_B():
    print('\n== B. 0x0355B8  TUNED (0x0357C8/CC = 0/0) vs SBND (+0.5/-0.5) ' + '=' * 9)
    cases = grid_B()
    hdr = '%-28s %2s %2s %12s %12s %12s %12s | %12s %12s' % (
        'case', 'en', 'md', 'E 78E4', 'total 7900', 'lim_lo 7930', 'lim_hi 7934',
        '7904 SBND', '7904 TUNED')
    print(hdr)
    n_en = n_dis = n_differ = 0
    maxabs = 0.0
    bind = {'binding cases in this grid': 0, 'window straddles 0': 0, 'window wholly beyond +-0.5': 0,
            'window reaches past +-0.5 on one side only': 0, 'inner is NaN': 0}
    bind_rows = []
    for c in cases:
        ot, _ = run_355B8(TUNED, c)
        os_, _ = run_355B8(SBND, c)
        maf = f32(c['maf'])
        d_lo = 0x0AD004 if c['mode'] == 1 else 0x0AD02C
        d_hi = 0x0AD018 if c['mode'] == 1 else 0x0AD040
        if c['en'] == 1:
            ok(abs(ot[A_ELO] - interp(TUNED, d_lo, maf)) < 1e-6, 'lo table %s' % c['tag'])
            ok(abs(ot[A_EHI] - interp(TUNED, d_hi, maf)) < 1e-6, 'hi table %s' % c['tag'])
        mt = model_355B8(c, ot[A_ELO], ot[A_EHI], 0.0, 0.0)
        ms = model_355B8(c, os_[A_ELO], os_[A_EHI], 0.5, -0.5)
        for a in OUT_B:
            ok(same(ot[a], mt[a]), 'TUNED %s @%08X emu %r model %r' % (c['tag'], a, ot[a], mt[a]))
            ok(same(os_[a], ms[a]), 'SBND %s @%08X emu %r model %r' % (c['tag'], a, os_[a], ms[a]))
            if a != A_OUT:      # the zeroing changes NOTHING but 0xFFFF7904
                ok(same(ot[a], os_[a]), 'side effect differs %s @%08X' % (c['tag'], a))
        if c['en'] == 1:
            n_en += 1
            ok(bits(ot[A_OUT]) == 0, 'TUNED enabled must give +0.0: %s -> %r' % (c['tag'], ot[A_OUT]))
            ok(same(os_[A_OUT], clamp(ms['inner'], -0.5, 0.5)), 'SBND out %s' % c['tag'])
            if not (os_[A_OUT] != os_[A_OUT]):
                ok(-0.5 <= os_[A_OUT] <= 0.5, 'SBND out of +-0.5 %s' % c['tag'])
                maxabs = max(maxabs, abs(os_[A_OUT]))
            if not same(os_[A_OUT], ot[A_OUT]):
                n_differ += 1
            # WHEN does the stock outer clamp change the value? (disputed claim C18)
            inner = ms['inner']
            binds = not same(os_[A_OUT], inner)
            want_bind = (inner != inner) or (inner < -0.5) or (inner > 0.5)
            ok(binds == want_bind, 'outer clamp binds iff inner is NaN or outside +-0.5: %s' % c['tag'])
            if binds:
                lo_, hi_ = ms[A_LIMLO], ms[A_LIMHI]
                bind['binding cases in this grid'] += 1
                if inner != inner:
                    bind['inner is NaN'] += 1
                    ok(same(os_[A_OUT], -0.5), 'NaN inner must give the lower bound')
                elif lo_ < 0.0 < hi_:
                    bind['window straddles 0'] += 1
                elif lo_ >= 0.5 or hi_ <= -0.5:
                    bind['window wholly beyond +-0.5'] += 1
                else:
                    bind['window reaches past +-0.5 on one side only'] += 1
                if not c['tag'].startswith('rnd'):
                    bind_rows.append((c['tag'], os_[A_TOT], lo_, hi_, inner, os_[A_OUT]))
        else:
            n_dis += 1
            ok(same(ot[A_OUT], f32(c['out0'])) and same(os_[A_OUT], f32(c['out0'])),
               'disabled must leave 7904 alone: %s' % c['tag'])
        if not c['tag'].startswith('rnd') or c['tag'] in ('rnd0', 'rnd1', 'rnd2', 'rnd3'):
            print('%-28s %2d %2d %12.6g %12.6g %12.6g %12.6g | %12.6g %12.6g' % (
                c['tag'], c['en'], c['mode'], ot[A_E], os_[A_TOT], os_[A_LIMLO], os_[A_LIMHI],
                os_[A_OUT], ot[A_OUT]))
    print('%d cases: %d enabled ([7912]==1), %d disabled' % (len(cases), n_en, n_dis))
    print('  enabled : TUNED 0xFFFF7904 == +0.0 in %d/%d; SBND == clamp(clamp(total,7930,7934),-0.5,+0.5)'
          % (n_en, n_en))
    print('            SBND differs from TUNED in %d/%d; max |SBND| = %.6g' % (n_differ, n_en, maxabs))
    print('            (the %d/%d figure is a property of THIS grid, not of the routine)' % (n_differ, n_en))
    print('  stock outer clamp: it returns something other than inner = clamp(total,7930,7934)')
    print('  exactly when inner is NaN (-> -0.5), inner < -0.5 or inner > 0.5 (asserted on all %d):' % n_en)
    for k in ('binding cases in this grid', 'window straddles 0', 'window wholly beyond +-0.5',
              'window reaches past +-0.5 on one side only', 'inner is NaN'):
        print('      %-44s %d' % (k, bind[k]))
    ok(bind['window straddles 0'] > 0, 'need a binding case whose window straddles zero')
    ok(bind['window wholly beyond +-0.5'] > 0, 'need a binding case whose window is wholly beyond')
    ok(bind['inner is NaN'] > 0, 'need a NaN case')
    print('      hand-picked rows where it binds:  total / window / inner -> stored')
    for tag, tot, lo_, hi_, inner, out in bind_rows:
        print('      %-32s %10.6g  [%9.6g, %9.6g]  %10.6g -> %+.4f' % (tag, tot, lo_, hi_, inner, out))
    print('  disabled: 0xFFFF7904 untouched in both images in %d/%d' % (n_dis, n_dis))
    print('  every other output (78E4 78E8 78EC 78F0 78F4 78F8 78FC 7900 7908 792C 7930 7934)')
    print('  is bit-identical between the two images in all %d cases' % len(cases))


# =============================================================================
# C. 0x0353BC
# =============================================================================
OUT_C = (A_KP, A_KI, A_PLO, A_PHI, A_WLO_T, A_WLO_ALT, A_WLO, A_WHI)


def model_353BC(c):
    air, maf = f32(c['air']), f32(c['maf'])
    if c['en'] != 1:
        return None
    r = lambda a: romf(TUNED, a)      # noqa: E731
    i = lambda d, x: interp(TUNED, d, x)   # noqa: E731
    o = {}
    if c['mode'] == 0:
        o[A_KP] = r(0x0CC0FC) * i(0x0AC558, air) * i(0x0AC56C, maf)
        o[A_KI] = r(0x0CC0B0)
        o[A_PLO], o[A_PHI] = i(0x0ACF3C, air), i(0x0ACF50, air)
        if c['f782B'] == 0:
            o[A_WLO_T], o[A_WHI] = i(0x0ACF64, maf), i(0x0ACF78, maf)
        else:
            o[A_WLO_T], o[A_WHI] = i(0x0ACFDC, maf), i(0x0ACFF0, maf)
    else:
        o[A_KP] = r(0x0CC100) * i(0x0AC580, air) * i(0x0AC594, maf)
        o[A_KI] = r(0x0CC104)
        o[A_PLO], o[A_PHI] = i(0x0ACF8C, air), i(0x0ACFA0, air)
        if c['f782B'] == 0:
            o[A_WLO_T], o[A_WHI] = i(0x0ACFB4, maf), i(0x0ACFC8, maf)
        else:
            o[A_WLO_T], o[A_WHI] = i(0x0ACFDC, maf), i(0x0ACFF0, maf)
    o[A_WLO_ALT] = r(0x0CC108) if (c['a3ae'] & 0x10) else 0.0
    o[A_WLO] = max(o[A_WLO_T], o[A_WLO_ALT])
    return o


def section_C():
    print('\n== C. 0x0353BC  gains and limits ' + '=' * 40)
    print('%3s %4s %4s %4s %9s %6s | %10s %10s %10s %10s %10s %10s %10s' % (
        'en', 'mode', '782B', 'A3AE', '78B0', '63CC', 'Kp 78C4', 'Ki 78C8', 'Plo 78CC',
        'Phi 78D0', 'wlo 78D4', 'WLO 78DC', 'WHI 78E0'))
    n = 0
    for en in (1, 0, 2):
        for mode in (0, 1, 2):
            for f782b in (0, 1, 0x80):
                for a3ae in (0x00, 0x10, 0xEF, 0xFF):
                    for air in (0.0, 25000.0, 35000.0, 76800.0, 200000.0):
                        for maf in (0.0, 4.0, 12.0, 22.0, 37.5, 80.0):
                            c = dict(en=en, mode=mode, f782B=f782b, a3ae=a3ae, air=air, maf=maf)
                            emu = new_emu(TUNED)
                            sentinel = 0.111
                            for a in OUT_C:
                                emu.ram_f32(a, sentinel)
                            emu.ram_u8(A_EN, en)
                            emu.ram_u8(A_MODE, mode)
                            emu.ram_u8(0xFFFF782B, f782b)
                            emu.ram_u8(0xFFFFA3AE, a3ae)
                            emu.ram_f32(0xFFFF78B0, air)
                            emu.ram_f32(0xFFFF7920, maf)
                            ok(emu.call(0x0353BC) == 'return', 'return')
                            ok(not emu.uninit_reads, 'uninit %s' % sorted(map(hex, emu.uninit_reads)))
                            ok(emu.R[15] == E.STACK_TOP, 'stack balance')
                            m = model_353BC(c)
                            got = {a: emu.read_f32(a) for a in OUT_C}
                            if m is None:
                                ok(all(same(got[a], f32(sentinel)) for a in OUT_C),
                                   '[7912]!=1 must write nothing')
                            else:
                                for a in OUT_C:
                                    ok(abs(got[a] - m[a]) < 2e-6,
                                       '353BC %r @%08X emu %r model %r' % (c, a, got[a], m[a]))
                            n += 1
                            if air == 35000.0 and maf == 12.0 and a3ae in (0x00, 0x10) \
                                    and f782b in (0, 1) and en == 1:
                                print('%3d %4d %4d 0x%02X %9.0f %6.1f | %10.6f %10.6f %10.6f '
                                      '%10.6f %10.6f %10.6f %10.6f' % (
                                          en, mode, f782b, a3ae, air, maf, got[A_KP], got[A_KI],
                                          got[A_PLO], got[A_PHI], got[A_WLO_T], got[A_WLO], got[A_WHI]))
    print('%d cases match model_353BC (tolerance 2e-6; lookups by independent interpolation)' % n)
    print('  [7912] != 1 -> nothing written;  [7941] == 0 vs != 0 selects the table set;')
    print('  [782B] == 0 vs != 0 selects the window tables;  [A3AE] bit4 selects 78D8 = 0 / [CC108]')


# =============================================================================
# D. 0x034EF4 whole chain
# =============================================================================
# State the 0x034EF4 chain can read BEFORE writing it on a pass, and that the init
# pair 0x0357D0 / 0x034EC8 does not write either. Found by running init and a
# pass with no RAM pre-set (section D1b asserts which of them each path reads).
CHAIN_STATE_NOT_INIT = {0xFFFF78E8: 4, 0xFFFF78FC: 4, 0xFFFF7910: 2, 0xFFFF7913: 1, 0xFFFF7940: 1}
# The same for the 0x03580C chain (0x0358A0 / 0x0359A4 / 0x035DE4 / 0x035E2C / 0x035E64).
LEARN_STATE_NOT_INIT = {0xFFFF7948: 2, 0xFFFF7951: 1, 0xFFFF7952: 1, 0xFFFF7988: 2,
                        0xFFFF794A: 2, 0xFFFF794E: 1, 0xFFFF794F: 1}
# ... and state the same chain reads before writing that init DOES write
CHAIN_STATE_INIT = {0xFFFF78B0: 4, 0xFFFF78B4: 4, 0xFFFF78B8: 4, 0xFFFF792C: 4, 0xFFFF7908: 4,
                    0xFFFF790C: 4}


def cold(emu, table):
    """zero the listed state, as after a RAM clear (whether the ECU clears RAM at
    reset is NOT established by this trace)."""
    for a, n in table.items():
        (emu.ram_u8 if n == 1 else emu.ram_u16 if n == 2 else emu.ram_u32)(a, 0)


def chain_emu(img):
    emu = new_emu(img)
    cold(emu, CHAIN_STATE_NOT_INIT)
    cold(emu, CHAIN_STATE_INIT)
    z8 = (0xFFFF984D, 0xFFFF6A28, 0xFFFF94B1, 0xFFFF9711, 0xFFFF7BE2, 0xFFFF6254,
          0xFFFF726C, 0xFFFFA3AE)
    for a in z8:
        emu.ram_u8(a, 0)
    emu.ram_u8(0xFFFF7448, 1)
    emu.ram_u8(0xFFFF63A4, 1)
    emu.ram_u8(0xFFFF7453, 1)
    emu.ram_u8(0xFFFF782B, 0)
    emu.ram_f32(0xFFFF63CC, 12.0)
    emu.ram_f32(0xFFFF6624, 2500.0)
    emu.ram_f32(0xFFFF63F8, 0.5)
    emu.ram_f32(0xFFFF6350, 85.0)
    emu.ram_f32(0xFFFF63D4, 6000.0)
    emu.ram_f32(0xFFFF6354, 85.0)
    emu.ram_f32(0xFFFF6368, 20.0)
    emu.ram_f32(0xFFFF77C8, 1.0)
    emu.ram_f32(0xFFFF43FC, 0.60)
    emu.ram_f32(0xFFFF65FC, 50.0)
    emu.ram_u32(0xFFFF318C, 0)
    emu.ram_u32(0xFFFF3190, 0)
    return emu


def section_siblings():
    """The six small callees of 0x034EF4 that produce the inputs of 0x0355B8."""
    print('\n== D0. siblings called by 0x034EF4 (inputs of 0x0355B8) ' + '=' * 17)
    r = lambda a: romf(TUNED, a)                 # noqa: E731
    n = 0
    # 0x0351FA: 78B4 = lpf([43FC], [78B4], [CC0C4], eps)
    for new in (0.0, 0.1, 0.6, 0.8, 1.2):
        for old in (0.0, 0.59, 0.6, 0.9):
            emu = new_emu(TUNED)
            emu.ram_f32(0xFFFF43FC, new)
            emu.ram_f32(A_CUR, old)
            emu.call(0x0351FA)
            ok(same(emu.read_f32(A_CUR), lpf(f32(new), f32(old), r(0x0CC0C4), r(0x03546C))), '351FA')
            n += 1
    # 0x03528A: speed hysteresis flag 7940, 78AC
    for spd in (0.0, 9.9, 10.0, 10.1, 20.0, 30.0, 30.1, 80.0):
        for f0 in (0, 1):
            for b6254 in (0, 1, 2):
                emu = new_emu(TUNED)
                emu.ram_f32(0xFFFF65FC, spd)
                emu.ram_u8(0xFFFF7940, f0)
                emu.ram_u8(0xFFFF6254, b6254)
                emu.ram_f32(0xFFFF78AC, 9.0)
                emu.gbr = 0x12345678
                emu.call(0x03528A)
                ok(emu.gbr == 0x12345678, 'gbr restored')
                s = f32(spd)
                flag = f0
                if not (s > r(0x0CC0E0)):
                    flag = 1
                elif s > r(0x0CC0E4):
                    flag = 0
                ok(emu.read_u8(0xFFFF7940) == flag, '3528A flag spd=%r' % spd)
                want = r(0x0CC0DC) if (b6254 == 1 or flag == 1) else interp(TUNED, 0x0AC544, s)
                ok(abs(emu.read_f32(0xFFFF78AC) - want) < 1e-6, '3528A 78AC')
                n += 1
    # 0x035218: 7924 = lookup(AC530, 7920); 78B8 per mode
    for mode in (0, 1, 2):
        for maf in (0.0, 12.0, 60.0):
            for old in (0.0, 0.5, 0.699, 0.7, 1.5):
                for off in (0.0, 0.2, 0.9, -0.9):
                    emu = new_emu(TUNED)
                    emu.ram_f32(0xFFFF7920, maf)
                    emu.ram_u8(A_MODE, mode)
                    emu.ram_f32(A_TGT, old)
                    emu.ram_f32(0xFFFF78AC, off)
                    emu.call(0x035218)
                    t = emu.read_f32(0xFFFF7924)
                    ok(abs(t - interp(TUNED, 0x0AC530, f32(maf))) < 1e-6, '35218 7924')
                    if mode == 1:
                        want = lpf(t, f32(old), r(0x0CC0D4), r(0x035488))
                    else:
                        want = clamp(lpf(fadd(r(0x0CC0D0), f32(off)), f32(old), r(0x0CC0D8),
                                         r(0x035488)), r(0x0CC0C8), r(0x0CC0CC))
                    ok(same(emu.read_f32(A_TGT), want), '35218 78B8 mode=%d' % mode)
                    n += 1
    # 0x0352DE: hysteresis flag 7913
    for tgt in (0.7,):
        for cur in (0.5, 0.6951, 0.6953, 0.699, 0.7, 0.71):
            for f0 in (0, 1):
                emu = new_emu(TUNED)
                emu.ram_f32(A_TGT, tgt)
                emu.ram_f32(A_CUR, cur)
                emu.ram_u8(A_HYS, f0)
                emu.call(0x0352DE)
                t, c = f32(tgt), f32(cur)
                flag = f0
                if not (t > c):
                    flag = 1
                elif fsub(t, r(0x0CC0E8)) > c:
                    flag = 0
                ok(emu.read_u8(A_HYS) == flag, '352DE cur=%r' % cur)
                n += 1
    # 0x035318: accumulator 78B0
    for acc in (0.0, 100.0, 76790.0, 76800.0):
        for maf in (-5.0, 0.0, 12.0, 30.0):
            for hold in (0, 1):
                emu = new_emu(TUNED)
                emu.ram_f32(0xFFFF78B0, acc)
                emu.ram_f32(0xFFFF63CC, maf)
                emu.ram_u8(0xFFFF726C, hold)
                emu.call(0x035318)
                want = f32(acc) if hold else clamp(fadd(f32(acc), f32(maf)), 0.0, r(0x0354D0))
                ok(same(emu.read_f32(0xFFFF78B0), want), '35318')
                n += 1
    # 0x035340: 78BC (K) and 78C0 (signed step)
    for mode in (0, 1, 2):
        for hys in (0, 1, 2):
            for maf in (0.0, 12.0, 45.0):
                emu = new_emu(TUNED)
                emu.ram_u8(A_MODE, mode)
                emu.ram_u8(A_HYS, hys)
                emu.ram_f32(0xFFFF63CC, maf)
                emu.call(0x035340)
                if mode == 0:
                    k = r(0x0CC0EC) if hys == 1 else r(0x0CC0F0)
                    st = interp(TUNED, 0x0ACF14, f32(maf))
                else:
                    k = r(0x0CC0F4) if hys == 1 else r(0x0CC0F8)
                    st = interp(TUNED, 0x0ACF28, f32(maf))
                st = st if hys == 1 else -st
                ok(same(emu.read_f32(A_K), k), '35340 K')
                ok(abs(emu.read_f32(A_SKIP) - st) < 1e-6, '35340 skip')
                n += 1
    print('0x0351FA  [78B4] = lpf(new=[43FC], old=[78B4], k=[CC0C4]=%.2f)' % r(0x0CC0C4))
    print('0x03528A  [7940] = 1 if !([65FC] > %.0f), 0 if [65FC] > %.0f, else held;' % (r(0x0CC0E0), r(0x0CC0E4)))
    print('          [78AC] = [CC0DC]=%.1f if ([6254]==1 or [7940]==1) else lookup(0xAC544,[65FC])' % r(0x0CC0DC))
    print('0x035218  [7924] = lookup(0xAC530,[7920]); [78B8] = lpf([7924]) if [7941]==1')
    print('          else clamp(lpf([CC0D0]=%.2f + [78AC]), %.1f, %.1f)' % (r(0x0CC0D0), r(0x0CC0C8), r(0x0CC0CC)))
    print('0x0352DE  [7913] = 1 if !([78B8] > [78B4]); 0 if ([78B8]-%.4f) > [78B4]; else held' % r(0x0CC0E8))
    print('0x035318  [78B0] = clamp([78B0]+[63CC], 0, %.0f) unless byte [726C] != 0' % r(0x0354D0))
    print('0x035340  [78BC] = [CC0EC]/[CC0F0] (mode 0) or [CC0F4]/[CC0F8]; [78C0] = +/-lookup(0xACF14 or 0xACF28,[63CC])')
    print('  %d sibling cases match' % n)


def externals(emu):
    """every input the 0x034EF4 chain takes from OUTSIDE the module, set so that the gate opens"""
    for a in (0xFFFF984D, 0xFFFF6A28, 0xFFFF94B1, 0xFFFF9711, 0xFFFF7BE2, 0xFFFF6254,
              0xFFFF726C, 0xFFFFA3AE, 0xFFFF782B):
        emu.ram_u8(a, 0)
    for a in (0xFFFF7448, 0xFFFF63A4, 0xFFFF7453):
        emu.ram_u8(a, 1)
    for a, v in ((0xFFFF63CC, 12.0), (0xFFFF6624, 2500.0), (0xFFFF63F8, 0.5), (0xFFFF6350, 85.0),
                 (0xFFFF63D4, 6000.0), (0xFFFF6354, 85.0), (0xFFFF6368, 20.0), (0xFFFF77C8, 1.0),
                 (0xFFFF43FC, 0.60), (0xFFFF65FC, 50.0)):
        emu.ram_f32(a, v)
    emu.ram_u32(0xFFFF318C, 0)
    emu.ram_u32(0xFFFF3190, 0xFFFFFFFF)


def externals_learn(emu):
    """the extra outside inputs of the 0x03580C chain, set so that byte [7950] can become 1"""
    for a in (0xFFFF69F0, 0xFFFF63FC, 0xFFFF63C4, 0xFFFF7D68):
        emu.ram_f32(a, 0.0)
    emu.ram_u16(0xFFFF6A22, 0)
    for a in (0xFFFF8F24, 0xFFFFA824, 0xFFFFA825, 0xFFFF9709):
        emu.ram_u8(a, 0)


def section_D_state():
    """D1b: which module state does init (0x0357D0 then 0x034EC8) NOT write, although a
    later pass reads it before writing it? Run with NO RAM pre-set and read emu.uninit_reads."""
    print('state read before it is written, with no RAM pre-set (strict; nothing is zeroed):')
    emu = new_emu(TUNED)
    externals(emu)
    emu.call(0x034EF4)
    got = set(emu.uninit_reads)
    ok(emu.read_u8(A_EN) == 1, 'pass enabled')
    ok(got == {0xFFFF78B0, 0xFFFF78B4, 0xFFFF78B8, 0xFFFF78E8, 0xFFFF7908, 0xFFFF790C, 0xFFFF7910,
               0xFFFF792C}, 'pass without init: %s' % sorted(map(hex, got)))
    print('  0x034EF4 alone (enabled pass):       %s' % ' '.join('%04X' % (a & 0xFFFF) for a in sorted(got)))
    emu = new_emu(TUNED)
    externals(emu)
    emu.call(0x0357D0)
    emu.call(0x034EC8)
    ok(not emu.uninit_reads, 'init reads only outside inputs and [318C]: %s' % sorted(map(hex, emu.uninit_reads)))
    emu.call(0x034EF4)
    got = set(emu.uninit_reads)
    ok(got == {0xFFFF78E8, 0xFFFF7910}, 'init + enabled pass: %s' % sorted(map(hex, got)))
    print('  init, then 0x034EF4 (enabled pass):  %s   <- NOT written by init' %
          ' '.join('%04X' % (a & 0xFFFF) for a in sorted(got)))
    emu = new_emu(TUNED)
    externals(emu)
    emu.ram_f32(0xFFFF65FC, 20.0)             # between [CC0E0] = 10 and [CC0E4] = 30: flag byte [7940] held
    emu.ram_f32(0xFFFF43FC, 0.697)            # inside the 0.0048 band below the setpoint: byte [7913] held
    emu.call(0x0357D0)
    emu.call(0x034EC8)
    emu.ram_f32(A_PREV, 0.699)                # total lands outside the window: the hold path reads [78FC]
    emu.ram_f32(A_INTEG, 900.0)
    emu.call(0x034EF4)
    got = set(emu.uninit_reads)
    ok(got == set(CHAIN_STATE_NOT_INIT), 'init + pass, held flags: %s' % sorted(map(hex, got)))
    print('  same, speed 20, [43FC] in the band, total outside the window: %s' %
          ' '.join('%04X' % (a & 0xFFFF) for a in sorted(got)))
    emu = new_emu(TUNED)
    externals(emu)
    externals_learn(emu)
    emu.call(0x0357D0)
    emu.call(0x034EC8)
    emu.call(0x034EF4)
    emu.uninit_reads.clear()
    emu.call(0x03580C)
    got = set(emu.uninit_reads)
    ok(emu.read_u8(0xFFFF7950) == 1, 'byte [7950] set on this pass')
    ok(got == {0xFFFF7948, 0xFFFF7951, 0xFFFF7952, 0xFFFF7988}, '0x03580C after init: %s' % sorted(map(hex, got)))
    print('  init, 0x034EF4, then 0x03580C:       %s   <- NOT written by init' %
          ' '.join('%04X' % (a & 0xFFFF) for a in sorted(got)))
    print('  (word [794A] and bytes [794E] [794F] are read only once word [7988] >= %d; the reset block' %
          u16(TUNED, 0x0CBC4C))
    print('   0x035DB4 writes them on every earlier call. Whether RAM is cleared at reset is not established.)')


GATE_F = (('f6624', 0xFFFF6624), ('f63F8', 0xFFFF63F8), ('f6350', 0xFFFF6350), ('f63D4', 0xFFFF63D4),
          ('f6354', 0xFFFF6354), ('f6368', 0xFFFF6368), ('f77C8', 0xFFFF77C8), ('f790C', 0xFFFF790C))
GATE_B = (('b6A28', 0xFFFF6A28), ('b7448', 0xFFFF7448), ('b94B1', 0xFFFF94B1), ('b9711', 0xFFFF9711),
          ('b63A4', 0xFFFF63A4), ('b7453', 0xFFFF7453), ('b7BE2', 0xFFFF7BE2))


def gate_base():
    return dict(f6624=2500.0, f63F8=0.5, f6350=85.0, f63D4=6000.0, f6354=85.0, f6368=20.0, f77C8=1.0,
                f790C=0.0, L=0.0, b6A28=0, b7448=1, b94B1=0, b9711=0, b63A4=1, b7453=1, b7BE2=0, cnt=0)


def run_gate(img, s):
    """0x034F94 alone: the latch of the inputs, the reload block and the twelve-condition gate."""
    emu = new_emu(img)
    for k, a in GATE_F:
        emu.ram_f32(a, s[k])
    for k, a in GATE_B:
        emu.ram_u8(a, s[k])
    emu.ram_u32(0xFFFF318C, E.f2b(s['L']))
    emu.ram_u32(0xFFFF3190, 0x11112222)
    emu.ram_u16(A_CNT, s['cnt'])
    ok(emu.call(0x034F94) == 'return', 'gate return')
    ok(not emu.uninit_reads, 'gate uninit %s' % sorted(map(hex, emu.uninit_reads)))
    ok(emu.R[15] == E.STACK_TOP, 'gate stack')
    return emu


def model_gate(img, s, tbl):
    """tbl = the 2-D lookup the routine stored at 0xFFFF793C. Returns (enable, count, L, reloaded)."""
    r = lambda a: romf(img, a)               # noqa: E731
    g = lambda k: f32(s[k])                  # noqa: E731
    L = f32(s['L'])
    if s['b6A28'] == 1:                                           # 0x03503E
        y = clamp(g('f790C'), r(0x036000), r(0x035FFC))           # 0x035F48
        if y == y:                                                # 0x0BDBCC refuses a NaN
            L = y
    d = fsub(g('f77C8'), L)                                       # 0x035078, AFTER the reload block
    en = (s['b7448'] == 1 and s['b94B1'] == 0                     # 0x035074, 0x035080
          and (r(0x0CC094) > g('f6624'))                          # 0x035092
          and not (r(0x0CC098) > d)                               # 0x03509E
          and (r(0x0CC09C) > d)                                   # 0x0350AA
          and not (r(0x0CC0A0) > g('f63F8'))                      # 0x0350BA
          and not (r(0x0CC0A4) > g('f6350'))                      # 0x0350CA
          and s['b9711'] == 0 and s['b63A4'] == 1                 # 0x0350D4, 0x0350DE
          and not (tbl > g('f63D4'))                              # 0x0350EE
          and s['b7453'] == 1 and s['b7BE2'] == 0)                # 0x0350F4, 0x0350FC
    return (1 if en else 0), (sat16(s['cnt']) if en else 0), L


def check_gate(img, s, tag, want=None):
    emu = run_gate(img, s)
    tbl = emu.read_f32(0xFFFF793C)
    en, cnt, L = model_gate(img, s, tbl)
    ok(emu.read_u8(A_EN) == en, '%s: byte [7912] = %d, model %d' % (tag, emu.read_u8(A_EN), en))
    ok(emu.read_u16(A_CNT) == cnt, '%s: word [7910] = %d, model %d' % (tag, emu.read_u16(A_CNT), cnt))
    ok(want is None or en == want, '%s: expected enable %r, got %d' % (tag, want, en))
    ok(same(emu.read_f32(0xFFFF7914), f32(s['f6624'])) and same(emu.read_f32(0xFFFF7918), f32(s['f63F8']))
       and same(emu.read_f32(0xFFFF791C), f32(s['f6350'])) and same(emu.read_f32(0xFFFF7938), f32(s['f63D4']))
       and emu.read_u8(0xFFFF7928) == s['b6A28'], '%s: latched copies' % tag)
    ok(same(emu.read_f32(0xFFFF318C), L), '%s: [318C] %r model %r' % (tag, emu.read_f32(0xFFFF318C), L))
    if s['b6A28'] == 1:
        ok(same(emu.read_f32(A_OUT), f32(s['f790C'])) and same(emu.read_f32(0xFFFF7944), f32(s['f790C'])),
           '%s: reload copies [790C] to [7904] and [7944]' % tag)
        ok(same(emu.read_f32(A_INTEG), fdiv(L, romf(img, 0x0CC0B0))), '%s: reload [7908]' % tag)
    else:
        ok(not ({A_OUT, 0xFFFF7944, 0xFFFF318C, A_INTEG} & set(a & ~3 for a in emu.writes)),
           '%s: no reload, so 7904 / 7944 / 318C / 7908 are not written' % tag)
    return en, emu


def section_D_gate():
    """D2b: the gate, at its exact thresholds and one float either side, with NaNs and odd
    byte values (the first version tested 1e-4 away from the thresholds and no NaN)."""
    print('gate in 0x034F94 alone, exact thresholds (model asserted on every row, both images):')
    r = lambda a: romf(TUNED, a)             # noqa: E731
    nan = float('nan')
    c6000, c895, c1036, c015, cm40 = r(0x0CC094), r(0x0CC098), r(0x0CC09C), r(0x0CC0A0), r(0x0CC0A4)
    emu = run_gate(TUNED, gate_base())
    tbl = emu.read_f32(0xFFFF793C)            # the 2-D lookup at [6354] = 85, [6368] = 20
    rows = [
        ('all conditions met', {}, 1),
        ('[6624] = 6000 exactly            (6000 > x false)', dict(f6624=c6000), 0),
        ('[6624] one float below 6000', dict(f6624=nextdown(c6000)), 1),
        ('[6624] = NaN', dict(f6624=nan), 0),
        ('d = 0.895 exactly                (0.895 > d false)', dict(f77C8=c895), 1),
        ('d one float below 0.895', dict(f77C8=nextdown(c895)), 0),
        ('d = 1.036 exactly                (1.036 > d false)', dict(f77C8=c1036), 0),
        ('d one float below 1.036', dict(f77C8=nextdown(c1036)), 1),
        ('d = NaN  ([77C8] NaN)', dict(f77C8=nan), 0),
        ('[63F8] = 0.15 exactly            (0.15 > x false)', dict(f63F8=c015), 1),
        ('[63F8] one float below 0.15', dict(f63F8=nextdown(c015)), 0),
        ('[63F8] = NaN                     -> gate stays OPEN', dict(f63F8=nan), 1),
        ('[6350] = -40 exactly             (-40 > x false)', dict(f6350=cm40), 1),
        ('[6350] one float below -40', dict(f6350=nextdown(cm40)), 0),
        ('[6350] = NaN                     -> gate stays OPEN', dict(f6350=nan), 1),
        ('[63D4] = lookup exactly          (lookup > x false)', dict(f63D4=tbl), 1),
        ('[63D4] one float below the lookup', dict(f63D4=nextdown(tbl)), 0),
        ('[63D4] = NaN                     -> gate stays OPEN', dict(f63D4=nan), 1),
    ]
    for k, good, bad in (('b7448', 1, (0, 2, 0x80, 0x81, 0xFF)), ('b94B1', 0, (1, 0x80)),
                         ('b9711', 0, (1, 0x80)), ('b63A4', 1, (0, 2, 0x81)),
                         ('b7453', 1, (0, 2, 0x81)), ('b7BE2', 0, (1, 0x80))):
        for v in bad:
            rows.append(('byte [%s] = 0x%02X' % (k[1:], v), {k: v}, 0))
    rows += [('count 0x7FFF -> 0x8000', dict(cnt=0x7FFF), 1), ('count 0xFFFE -> 0xFFFF', dict(cnt=0xFFFE), 1),
             ('count 0xFFFF stays 0xFFFF (saturates)', dict(cnt=0xFFFF), 1),
             ('count 0x1234, gate shut -> 0', dict(cnt=0x1234, b7448=0), 0)]
    n = 0
    for tag, ch, want in rows:
        got = {}
        for name, img in (('TUNED', TUNED), ('SBND2', SBND2)):
            s = gate_base()
            s.update(ch)
            got[name], emu = check_gate(img, s, tag, want)
            cnt = emu.read_u16(A_CNT)
            n += 1
        print('  %-58s byte [7912] = %d   word [7910] = 0x%04X' % (tag, got['TUNED'], cnt))
    # d uses L as it is AFTER the reload block
    s = gate_base()
    s.update(L=0.02, f790C=0.02, f77C8=f32(c895 + 0.01))
    e0, _ = check_gate(TUNED, s, 'no reload, L = 0.02', 0)
    s.update(b6A28=1)
    e1, emu = check_gate(TUNED, s, 'reload, tuned: L -> 0.0', 1)
    ok(bits(emu.read_f32(0xFFFF318C)) == 0, 'tuned reload stores +0.0')
    e2, emu = check_gate(SBND2, s, 'reload, stock bounds: L stays 0.02', 0)
    print('  [77C8] = 0.895 + 0.01, [318C] = [790C] = 0.02:  no reload -> %d ; reload, tuned -> %d ; '
          'reload, stock bounds -> %d   (d is taken after the reload)' % (e0, e1, e2))
    rng = random.Random(22)
    for i in range(300 if QUICK else 1500):
        s = gate_base()
        s.update(f6624=rng.choice((2500.0, 2500.0, 5999.99, 6000.0, 7000.0)),
                 f63F8=rng.choice((0.5, 0.5, 0.15, 0.1499, nan)), f6350=rng.choice((85.0, 85.0, -40.0, -40.01, nan)),
                 f63D4=rng.choice((6000.0, 6000.0, tbl, nextdown(tbl), 100.0, nan)),
                 f77C8=rng.choice((1.0, 1.0, c895, nextdown(c895), c1036, nextdown(c1036), rng.uniform(0.85, 1.08))),
                 L=rng.choice((0.0, 0.0, 0.02, -0.03, rng.uniform(-0.06, 0.06))),
                 f790C=rng.choice((0.0, 0.0125, -0.03, 0.7, -0.7)), b6A28=rng.choice((0, 0, 0, 1)),
                 cnt=rng.choice((0, 5, 0xFFFF)))
        for k in ('b7448', 'b94B1', 'b9711', 'b63A4', 'b7453', 'b7BE2'):
            if rng.random() < 0.05:
                s[k] = rng.choice((0, 1, 2, 0x81))
        for img in (TUNED, SBND2):
            check_gate(img, s, 'rnd%d' % i)
            n += 1
    print('  %d gate runs match the model (enable byte, count, latched copies, reload block)' % (n + 3))


def model_init_34F28(img, L):
    """0x034EC8 -> 0x034F28 from the bytes, for L = [318C] (a float32).
    Returns ([7904], [7908]). 0x0BE628 is fr4 / fr5 by one fdiv when fr5 != 0;
    both divisors here are non-zero ROM constants."""
    r = lambda a: romf(img, a)               # noqa: E731
    if not (r(0x0CC0AC) > L):                # 0x034F3A
        step = r(0x0CC0B8)
    elif not (r(0x0C5054) > L):              # 0x034F44
        step = r(0x0CC0B8)
    elif r(0x0CC0A8) > L:                    # 0x034F4C
        step = r(0x0CC0B4)
    elif r(0x0C5060) > L:                    # 0x034F54
        step = r(0x0CC0B4)
    else:
        step = 0.0
    out = fadd(fdiv(step, r(0x0CC0BC)), L)   # 0x034F68 jsr 0x0BE628 ; 0x034F6C fadd fr14,fr0
    return out, fdiv(out, r(0x0CC0B0))       # 0x034F7C jsr 0x0BE628


def model_35E88(img, L):
    """0x035E88 from the bytes, for L = [318C] (a float32). Returns (new [318C], [7944])."""
    r = lambda a: romf(img, a)               # noqa: E731
    if r(0x0CC0AC) > L:                                                  # 0x035E98 bt/s
        if r(0x0CC0A8) > L:                                              # 0x035EDA
            if r(0x0C5060) > L:                                          # 0x035EE2
                L = fadd(fdiv(r(0x0C5068), r(0x0CC0C0)), r(0x0C5060))    # 0x035EEE, 0x035EF6
            out = fadd(fdiv(r(0x0CC0B4), r(0x0CC0BC)), L)                # 0x035F0A, 0x035F0E
        else:
            out = L                                                      # 0x035F18
    else:
        if not (r(0x0C5054) > L):                                        # 0x035EA2
            L = fadd(fdiv(r(0x0C505C), r(0x0CC0C0)), r(0x0C5054))        # 0x035EAE, 0x035EB6
        out = fadd(fdiv(r(0x0CC0B8), r(0x0CC0BC)), L)                    # 0x035ECA, 0x035ECE
    return L, out


def section_D():
    print('\n== D. 0x034EF4 chain ' + '=' * 52)
    # D1: the entry's own two stores, and the tail into 0x0355B8
    emu = chain_emu(TUNED)
    emu.ram_f32(0xFFFF63CC, 33.25)
    emu.ram_u8(0xFFFF984D, 0x5A)
    ok(emu.call(0x034EF4) == 'return', 'chain return')
    ok(not emu.uninit_reads, 'uninit reads: %s' % sorted(map(hex, emu.uninit_reads)))
    ok(emu.R[15] == E.STACK_TOP, 'stack balance')
    ok(same(emu.read_f32(0xFFFF7920), 33.25), '[7920] = [63CC]')
    ok(emu.read_u8(0xFFFF7941) == 0x5A, '[7941] = [984D]')
    for e in (0x034F94, 0x0351FA, 0x03528A, 0x035218, 0x0352DE, 0x035318, 0x035340, 0x0353BC,
              0x0355B8):
        ok(e in emu.executed, 'callee %06X not executed' % e)
    print('0x034EF4: [7920]=[63CC], [7941]=byte[984D]; runs 0x034F94 0x0351FA 0x03528A 0x035218')
    print('          0x0352DE 0x035318 0x035340 0x0353BC then tails into 0x0355B8; returns; r15 balanced')

    # D2: gating of 0xFFFF7912 (set in 0x034F94), one condition broken at a time
    gates = [
        ('all conditions met', {}, 1),
        ('[7448] != 1', {'u8': {0xFFFF7448: 0}}, 0),
        ('[94B1] != 0', {'u8': {0xFFFF94B1: 1}}, 0),
        ('[6624] == 6000 (needs < [CC094]=6000)', {'f': {0xFFFF6624: 6000.0}}, 0),
        ('[6624] == 5999.9', {'f': {0xFFFF6624: 5999.9}}, 1),
        ('[77C8]-[318C] = 0.8949 (needs >= [CC098]=0.895)', {'f': {0xFFFF77C8: 0.8949}}, 0),
        ('[77C8]-[318C] = 0.8951', {'f': {0xFFFF77C8: 0.8951}}, 1),
        ('[77C8]-[318C] = 1.0361 (needs < [CC09C]=1.036)', {'f': {0xFFFF77C8: 1.0361}}, 0),
        ('[77C8]-[318C] = 1.0359', {'f': {0xFFFF77C8: 1.0359}}, 1),
        ('[63F8] = 0.149 (needs >= [CC0A0]=0.15)', {'f': {0xFFFF63F8: 0.149}}, 0),
        ('[6350] = -41 (needs >= [CC0A4]=-40)', {'f': {0xFFFF6350: -41.0}}, 0),
        ('[9711] != 0 (0x029888 returns 2)', {'u8': {0xFFFF9711: 1}}, 0),
        ('[63A4] != 1 (0x01FD7C returns 0)', {'u8': {0xFFFF63A4: 0}}, 0),
        ('[63D4] = 100 < table 0xAD944', {'f': {0xFFFF63D4: 100.0}}, 0),
        ('[7453] != 1', {'u8': {0xFFFF7453: 0}}, 0),
        ('[7BE2] != 0', {'u8': {0xFFFF7BE2: 1}}, 0),
    ]
    print('gating of 0xFFFF7912 (struct +108), decided in 0x034F94:')
    for tag, ch, want in gates:
        res = {}
        for name, img in (('TUNED', TUNED), ('SBND', SBND)):
            emu = chain_emu(img)
            emu.ram_f32(A_OUT, 0.0321)          # pre-existing value of 0xFFFF7904
            for a, v in ch.get('u8', {}).items():
                emu.ram_u8(a, v)
            for a, v in ch.get('f', {}).items():
                emu.ram_f32(a, v)
            emu.call(0x034EF4)
            ok(not emu.uninit_reads, 'uninit %s' % sorted(map(hex, emu.uninit_reads)))
            ok(emu.read_u8(A_EN) == want, '%s: [7912] %d want %d' % (tag, emu.read_u8(A_EN), want))
            res[name] = emu.read_f32(A_OUT)
            if want == 0:
                ok(same(res[name], 0.0321), '%s: disabled must keep 7904' % tag)
                ok(emu.read_u16(A_CNT) == 0, 'counter reset')
            else:
                ok(emu.read_u16(A_CNT) == 1, 'counter +1')
        if want == 1:
            ok(bits(res['TUNED']) == 0, 'TUNED enabled -> 0')
        print('  %-50s [7912]=%d  7904: SBND %+.6f  TUNED %+.6f' % (tag, want, res['SBND'], res['TUNED']))

    section_D_state()
    section_D_gate()

    # D3: the [6A28]==1 path writes 0xFFFF7904 = [790C] BEFORE 0x0355B8 runs
    print('byte [6A28]==1 path (0x035042..0x035070): 7904 := [790C], 0xFFFF318C := clamp([790C], 0x036000, 0x035FFC)')
    for name, img in (('TUNED', TUNED), ('SBND', SBND), ('SBND2', SBND2)):
        for en_ok in (0, 1):
            emu = chain_emu(img)
            emu.ram_u8(0xFFFF6A28, 1)
            emu.ram_f32(A_L0, 0.0125)
            emu.ram_f32(A_OUT, 0.0321)
            emu.ram_f32(0xFFFF318C, 0.02)
            emu.ram_f32(0xFFFF77C8, 1.0)
            if not en_ok:
                emu.ram_u8(0xFFFF7448, 0)
            emu.call(0x034EF4)
            ok(emu.read_u8(0xFFFF7928) == 1, '[7928] copy of [6A28]')
            out, lrn = emu.read_f32(A_OUT), emu.read_f32(0xFFFF318C)
            exp_lrn = 0.0125 if name == 'SBND2' else 0.0
            ok(same(lrn, f32(exp_lrn)), '%s learned %r' % (name, lrn))
            if not en_ok:
                ok(same(out, f32(0.0125)), '%s: 7904 must be [790C] when the loop is off' % name)
            elif name == 'TUNED':
                ok(bits(out) == 0, 'TUNED enabled -> 0')
            ck = emu.read_u16(0xFFFF3190)
            w = E.f2b(lrn)
            ok(ck == (~((w >> 16) + (w & 0xFFFF))) & 0xFFFF and emu.read_u16(0xFFFF3192) == ck,
               'checksum words')
            print('  %-6s loop %s : 7904 = %+.6f   0xFFFF318C = %+.6f   0xFFFF7908 = %+.4f' % (
                name, 'ON ' if en_ok else 'OFF', out, lrn, emu.read_f32(A_INTEG)))

    # D4: init 0x034EC8 -> 0x034F28 (third writer of 7904)
    print('init 0x034EC8 -> 0x034F28: 7904 := [318C] + step/[CC0BC], 7908 := 7904/[CC0B0], 790C := [318C]')
    for L in (0.0, 0.005, 0.0099, 0.01, 0.02, 0.2, -0.005, -0.0101, -0.2):
        emu = chain_emu(TUNED)
        emu.ram_f32(0xFFFF318C, L)
        ok(emu.call(0x034EC8) == 'return', 'init return')
        Lf = f32(L)
        want, want_i = model_init_34F28(TUNED, Lf)
        ok(same(emu.read_f32(A_OUT), want), 'init 7904 L=%r got %r want %r' % (L, emu.read_f32(A_OUT), want))
        ok(same(emu.read_f32(A_L0), Lf), 'init 790C')
        ok(same(emu.read_f32(A_INTEG), want_i), 'init 7908')
        ok(same(emu.read_f32(A_TGT), romf(TUNED, 0x0CC0D0)), 'init 78B8')
        ok(same(emu.read_f32(A_CUR), f32(0.60)) and same(emu.read_f32(A_PREV), f32(0.60)), 'init 78B4/792C')
        print('  [318C] = %+.4f -> 7904 = %+.4f  7908 = %+9.3f  790C = %+.4f' % (
            L, emu.read_f32(A_OUT), emu.read_f32(A_INTEG), emu.read_f32(A_L0)))

    # D5: trajectory. Same inputs into both images, 0xFFFF43FC stepped.
    print('trajectory: init, then 0x034EF4 per tick; 0xFFFF43FC = 0.60 for 40 ticks, 0.80 for 40, 0.60 for 40')
    print('  (0xFFFF77C8 held at 1.0, so the loop stays enabled; this is NOT a closed-loop plant model)')
    emus = {'TUNED': chain_emu(TUNED), 'SBND': chain_emu(SBND)}
    for emu in emus.values():
        emu.call(0x034EC8)
    print('  %4s %6s | %10s %10s %10s %10s | %10s' % ('tick', '43FC', 'E 78E4', 'total 7900',
                                                     '7908', '7904 SBND', '7904 TUNED'))
    peak = 0.0
    for t in range(120):
        v = 0.80 if 40 <= t < 80 else 0.60
        row = {}
        for name, emu in emus.items():
            emu.ram_f32(0xFFFF43FC, v)
            emu.call(0x034EF4)
            ok(emu.read_u8(A_EN) == 1, 'enabled in trajectory')
            row[name] = emu.read_f32(A_OUT)
        ok(bits(row['TUNED']) == 0, 'TUNED trajectory must stay 0')
        for a in (A_E, A_EF, A_TOT, A_INTEG, A_CUR, A_TGT):
            ok(same(emus['TUNED'].read_f32(a), emus['SBND'].read_f32(a)), 'state diverged %08X' % a)
        peak = max(peak, abs(row['SBND']))
        if t in (0, 1, 2, 5, 10, 20, 39, 40, 41, 42, 45, 50, 60, 79, 80, 81, 85, 100, 119):
            s = emus['SBND']
            print('  %4d %6.2f | %10.6f %10.6f %10.4f %+10.6f | %+10.6f' % (
                t, v, s.read_f32(A_E), s.read_f32(A_TOT), s.read_f32(A_INTEG), row['SBND'], row['TUNED']))
    ok(peak > 0.001, 'SBND trajectory should move')
    print('  SBND peak |7904| = %.6f ; TUNED identically +0.0 ; internal state identical in both' % peak)


# =============================================================================
# E. consumers of 0xFFFF7904
# =============================================================================
def section_E():
    print('\n== E. consumers of 0xFFFF7904 ' + '=' * 43)
    # E1: 0x033460 -> 0xFFFF77BC
    def run_33460(x, hi=1.25, extra=None):
        emu = new_emu(TUNED)
        # every float and byte this path of 0x033460 reads, set explicitly
        for a in (0xFFFF63C4, 0xFFFF68D8, 0xFFFF6574, 0xFFFF68D0, 0xFFFF7BE4,
                  0xFFFF77BC, 0xFFFF77C4, 0xFFFF77CC, 0xFFFF77D4, 0xFFFF77D8, 0xFFFF77DC,
                  0xFFFF77E4, 0xFFFF77F4, 0xFFFF77F8, 0xFFFF7800, 0xFFFF781C, 0xFFFF7820):
            emu.ram_f32(a, 0.0)
        for a in (0xFFFF8E7E, 0xFFFF7BEC, 0xFFFF8E46, 0xFFFF85D7, 0xFFFF9720):
            emu.ram_u8(a, 0)
        emu.ram_f32(0xFFFF7BDC, hi)
        emu.ram_f32(0xFFFF7904, x)
        for a, v in (extra or {}).items():
            emu.ram_f32(a, v)
        ok(emu.call(0x033460) == 'return', '33460 return')
        ok(not emu.uninit_reads, '33460 uninit %s' % sorted(map(hex, emu.uninit_reads)))
        return emu.read_f32(0xFFFF77BC)

    def model_33460(x, hi, ex):
        g = lambda a: f32(ex.get(a, 0.0))        # noqa: E731
        s = fadd(f32(x), g(0xFFFF77CC))
        s = fadd(s, fmin(g(0xFFFF77D8), g(0xFFFF781C)))
        s = fsub(s, g(0xFFFF77E4))
        s = fadd(s, romf(TUNED, 0x0CBF4C))
        s = fadd(s, g(0xFFFF77F4))
        s = fadd(s, 1.0)
        a = fmin(fsub(fsub(g(0xFFFF77DC), g(0xFFFF77D4)), g(0xFFFF77F8)), -g(0xFFFF7800))
        a = fmin(-g(0xFFFF7820), a)
        s = fadd(s, a)
        s = clamp(s, romf(TUNED, 0x0CBF3C), f32(hi))
        return clamp(s, 0.75, 1.25)

    print('0x033460: [77BC] = clamp(clamp(1.0 + [7904] + other terms, [CBF3C]=%.2f, [7BDC]), 0.75, 1.25)'
          % romf(TUNED, 0x0CBF3C))
    print('  %10s %10s | %10s' % ('[7904]', '[7BDC]', '[77BC]'))
    for x in (-0.5, -0.2, -0.1, -0.03, -0.007, 0.0, 0.003, 0.03, 0.1, 0.2, 0.26, 0.5):
        for hi in (1.25, 1.02):
            got = run_33460(x, hi)
            ok(same(got, model_33460(x, hi, {})), '33460 x=%r hi=%r got %r' % (x, hi, got))
            if hi == 1.25:
                print('  %+10.4f %10.2f | %10.6f' % (x, hi, got))
    ex = {0xFFFF77CC: 0.01, 0xFFFF77D8: -0.02, 0xFFFF781C: 0.5, 0xFFFF77E4: 0.004,
          0xFFFF77F4: -0.003, 0xFFFF77DC: 0.2, 0xFFFF77D4: 0.05, 0xFFFF77F8: 0.02,
          0xFFFF7800: 0.0, 0xFFFF7820: 0.001}
    for x in (-0.03, 0.0, 0.02):
        got = run_33460(x, 1.25, ex)
        ok(same(got, model_33460(x, 1.25, ex)), '33460 extra x=%r' % x)
    d = run_33460(0.02) - run_33460(0.0)
    ok(abs(d - 0.02) < 1e-6, 'unit slope')
    print('  slope d[77BC]/d[7904] = 1 inside the clamps (0.02 -> %+.6f); other terms verified with non-zero inputs' % d)

    # E2: scaled exports
    def call(entry, x):
        emu = new_emu(TUNED)
        emu.ram_f32(0xFFFF7904, x)
        emu.ram_u8(0xFFFFAF83, 0)
        ok(emu.call(entry) == 'return', 'ret')
        return emu

    def sat(v, top):
        if v != v:
            return 0
        t = int(math.trunc(v)) if abs(v) < 2 ** 31 else (top + 1 if v > 0 else -1)
        return max(0, min(top, t))

    print('scaled exports (0x0BE5A8: u8 = sat(trunc((x-off)/scale+0.5), 0..255))')
    print('  %10s | %12s %14s' % ('[7904]', '0x05DCFA r0', '0x0A892E [AF83]'))
    for x in (-0.5, -0.06, -0.05, -0.01, 0.0, 0.0004, 0.01, 0.1, 0.1492, 0.2, 0.5):
        r0 = call(0x05DCFA, x).R[0]
        # 0x0BE5A8: fsub fr6,fr4 ; fdiv fr5,fr4 ; fadd 0.5 ; ftrc (each fadd/fsub/fdiv rounds toward zero)
        w1 = sat(fadd(fdiv(fsub(f32(x), romf(TUNED, 0x05DDDC)), romf(TUNED, 0x05DDE0)), 0.5), 255)
        ok(r0 == w1, '5DCFA x=%r got %d want %d' % (x, r0, w1))
        b = call(0x0A892E, x).read_u8(0xFFFFAF83)
        w2 = sat(fadd(fdiv(fsub(fmul(f32(x), 100.0), -100.0), 0.78125), 0.5), 255)   # 0x0A8938 fmul first
        ok(b == w2, 'A892E x=%r got %d want %d' % (x, b, w2))
        print('  %+10.4f | %12d %14d' % (x, r0, b))
    ok(call(0x05DCFA, 0.0).R[0] == 64 and call(0x0A892E, 0.0).read_u8(0xFFFFAF83) == 128, 'zero codes')
    print('  TUNED steady state (7904 = 0.0): 0x05DCFA returns 64, 0xFFFFAF83 = 128 (0x80)')

    # E2b: 0x0243B6, partial run 0x024528..0x024548 (two of its many conversions).
    # Registers the function set up earlier are preset from its own bytes:
    #   0243C8 ldc r0,gbr (=0xFFFF683C), 0243EE r13 = 0x0BE5D8, 0244F6 fr15 = [0x0246D0].
    print('0x0243B6 (partial 0x024528..0x024548): word [0xFFFF685C] = sat16(trunc(([7904]+0.5)/2^-16+0.5))')
    for x in (-0.6, -0.5, -0.25, 0.0, 0.0125, 0.25, 0.49999, 0.5, 0.6):
        emu = new_emu(TUNED)
        emu.ram_f32(0xFFFF7904, x)
        emu.ram_f32(0xFFFF7878, 0.0)
        emu.ram_u16(0xFFFF685A, 0)
        emu.ram_u16(0xFFFF685C, 0)
        emu.gbr = 0xFFFF683C
        r = emu.call(0x024528, regs={13: 0x0BE5D8}, fregs={15: romf(TUNED, 0x0246D0)},
                     stop_at={0x024548})
        ok(r == 0x024548, 'partial run stop')
        got = emu.read_u16(0xFFFF685C)
        want = sat(fadd(fdiv(fsub(f32(x), -0.5), romf(TUNED, 0x0246F0)), 0.5), 65535)   # 0x0BE5D8
        ok(got == want, '243B6 x=%r got %d want %d' % (x, got, want))
        print('  [7904] = %+8.5f -> 0x%04X (%d)' % (x, got, got))

    # E1b: the OTHER writer of 0xFFFF77BC / 77C0 / 77C4 / 77C8 -- 0x0332A2
    print('0x0332A2: when byte [0xFFFF65F6] == 1 it writes 1.0 to 77BC, 77C0, 77C4, 77C8 (and clears neighbours)')
    for flag in (0, 1, 2, 0x81):
        emu = new_emu(TUNED)
        emu.ram_u8(0xFFFF65F6, flag)
        emu.ram_u8(0xFFFF8E7E, 0x5A)
        emu.gbr = 0x12345678
        ok(emu.call(0x0332A2) == 'return', '332A2 return')
        ok(not emu.uninit_reads, '332A2 uninit %s' % sorted(map(hex, emu.uninit_reads)))
        ok(emu.gbr == 0x12345678, '332A2 gbr restored')
        wr = sorted(set(a & ~3 for a in emu.writes if a < 0xFFFF7864)) + \
            sorted(a for a in emu.writes if a >= 0xFFFF7864)
        if flag == 1:
            for a in (0xFFFF77BC, 0xFFFF77C0, 0xFFFF77C4, 0xFFFF77C8, 0xFFFF780C):
                ok(same(emu.read_f32(a), 1.0), '332A2 %08X = 1.0' % a)
            for a in (0xFFFF7804, 0xFFFF7808, 0xFFFF7810, 0xFFFF7814, 0xFFFF7818, 0xFFFF7820):
                ok(bits(emu.read_f32(a)) == 0, '332A2 %08X = 0.0' % a)
            ok(emu.read_u8(0xFFFF7864) == 0 and emu.read_u8(0xFFFF7865) == 0
               and emu.read_u8(0xFFFF7871) == 0x5A and emu.read_u8(0xFFFF7872) == 0, '332A2 bytes')
            ok(wr == [0xFFFF77BC, 0xFFFF77C0, 0xFFFF77C4, 0xFFFF77C8, 0xFFFF7804, 0xFFFF7808,
                      0xFFFF780C, 0xFFFF7810, 0xFFFF7814, 0xFFFF7818, 0xFFFF7820,
                      0xFFFF7864, 0xFFFF7865, 0xFFFF7871, 0xFFFF7872], '332A2 write set %s' % list(map(hex, wr)))
        else:
            ok(not emu.writes, '332A2 must write nothing when byte [65F6] != 1')
        print('  byte [65F6] = 0x%02X -> %s' % (flag, 'writes 1.0 to 77BC/77C0/77C4/77C8/780C, 0.0 to 7804/7808/7810/7814/7818/7820'
                                              if flag == 1 else 'no RAM written'))

    section_E_window()
    section_E_learn()


# ---- E2c..E2e: the window comparison 0x06665E and its two siblings -----------
T520 = {off: struct.unpack_from('>I', TUNED, 0x097520 + off)[0] for off in range(0, 40, 4)}
T560 = {off: struct.unpack_from('>I', TUNED, 0x097560 + off)[0] for off in range(0, 12, 4)}


def model_6665E(s):
    """0x06665E from the byte reading. s holds every input; returns (byte 9356, byte 932C)."""
    r = lambda a: romf(TUNED, a)             # noqa: E731
    g = lambda k: f32(s[k])                  # noqa: E731
    b9356 = 0
    if (s['r584D2'] & 0xFF) == 1 and s['w67EC'] >= u16(TUNED, 0x0C48DC) \
            and not (r(0x0C50DC) > g('f6350')) and not (r(0x0C50E0) > g('f65FC')) \
            and not (r(0x0C50E4) > g('f63C4')) and (r(0x0C50E8) > abs(fsub(g('f63FC'), 0.0))):
        b9356 = 1
    res = 0
    r5 = s['r582D2'] & 0xFF
    r5 = r5 - 256 if r5 & 0x80 else r5
    if b9356 == 1 and r5 == 1 and s['b7449'] == 1 and s['en'] == 1:
        x, out, tgt = g('f43FC'), g('out'), g('f78B8')
        reach = (tgt > fadd(x, r(0x0C50C8))) or not (fadd(tgt, r(0x0C50CC)) > x)
        blocked = False
        if reach:
            if (out > fadd(g('f9314'), r(0x0C50D0))) and not (r(0x0C50D4) > x) \
                    and (g('f9318') > fadd(out, r(0x0C50D0))) and (r(0x0C50D8) > x):
                blocked = True
        if not blocked:
            v, q = g('f40C8'), g('f77DC')
            good = (not (r(0x0C50F0) > v)) and (r(0x0C50F4) > v) and s['b7464'] == 0 \
                and (not (r(0x0C50F8) > q)) and (r(0x0C50FC) > q)
            if good and outside(g('f69F0'), 0.0, romf(TUNED, 0x0669DC)):
                good = (r(0x0C50EC) > g('f7D68')) and (s['w6A22'] >= u16(TUNED, 0x0C48DE))
            res = 1 if good else 0
    return b9356, res


def run_6665E(s):
    emu = new_emu(TUNED)
    emu.stub(0x0584D2, r0=s['r584D2'])      # r0 = 1 iff byte [0xFFFFAE0A] == 1 (5 instructions, read from bytes)
    emu.stub(0x0582D2, r0=s['r582D2'])      # a wrapper around 0x0A6728 (not decoded here)
    for k, a in (('f6350', 0xFFFF6350), ('f65FC', 0xFFFF65FC), ('f63C4', 0xFFFF63C4), ('f63FC', 0xFFFF63FC),
                 ('f43FC', 0xFFFF43FC), ('out', 0xFFFF7904), ('f40C8', 0xFFFF40C8), ('f7D68', 0xFFFF7D68),
                 ('f78B8', 0xFFFF78B8), ('f77DC', 0xFFFF77DC), ('f69F0', 0xFFFF69F0),
                 ('f9314', 0xFFFF9314), ('f9318', 0xFFFF9318)):
        emu.ram_f32(a, s[k])
    emu.ram_u16(0xFFFF67EC, s['w67EC'])
    emu.ram_u16(0xFFFF6A22, s['w6A22'])
    emu.ram_u8(0xFFFF7912, s['en'])
    emu.ram_u8(0xFFFF7449, s['b7449'])
    emu.ram_u8(0xFFFF7464, s['b7464'])
    emu.gbr = 0x12345678
    ok(emu.call(0x06665E) == 'return', '6665E return')
    ok(not emu.uninit_reads, '6665E uninit %s' % sorted(map(hex, emu.uninit_reads)))
    ok(emu.gbr == 0x12345678 and emu.R[15] == E.STACK_TOP, '6665E gbr/stack')
    return emu


def section_E_window():
    ok(T520[4] == 0xFFFF9340 and T520[8] == 0xFFFF9314 and T520[12] == 0xFFFF9318 and T520[0] == 0xFFFF933C,
       'table 0x097520')
    ok(T560[0] == 0xFFFF932C and T560[4] == 0xFFFF932D and T560[8] == 0xFFFF932E, 'table 0x097560')
    rng = random.Random(31)
    r = lambda a: romf(TUNED, a)             # noqa: E731
    eps = r(0x0C50D0)

    def base():
        # [43FC] = 0.45 is more than [C50C8] = 0.2 below the setpoint copy [934C] = 0.7,
        # so the run reaches the two tests on the [7904] copy at 0x0667D0
        return dict(r584D2=1, r582D2=1, w67EC=8000, f6350=80.0, f65FC=40.0, f63C4=10.0, f63FC=0.0,
                    f43FC=0.45, out=0.0, f40C8=10.0, f7D68=0.0, f78B8=0.7, f77DC=0.0, f69F0=0.0,
                    f9314=-0.01, f9318=0.02, w6A22=100, en=1, b7449=1, b7464=0)

    cases = []

    def add(tag, want, **kw):
        c = base()
        c.update(kw)
        cases.append((tag, c, want))

    # the two tests on the [7904] copy, at and one float either side of each edge
    # edges as the chip computes them: [9314] + eps and [7904] + eps are single fadds (toward zero)
    lo_edge = fadd(f32(-0.01), eps)
    x_hi = f32(0.02)
    cand = f32(0.02 - eps)                  # a starting guess (an input); the two loops settle it
    while fadd(cand, eps) >= x_hi:
        cand = nextdown(cand)
    while fadd(nextup(cand), eps) < x_hi:
        cand = nextup(cand)
    ok(fadd(cand, eps) < x_hi <= fadd(nextup(cand), eps), 'upper-edge probe')
    add('[7904] = 0 inside the window, [43FC] = 0.45', 0)
    add('[7904] == [9314]+0.0003 exactly (not above the lower edge)', 1, out=lo_edge)
    add('[7904] one float above [9314]+0.0003', 0, out=nextup(lo_edge))
    add('[7904]+0.0003 one float below [9318]', 0, out=cand)
    add('[7904]+0.0003 == [9318] or above (not below the upper edge)', 1, out=nextup(cand))
    add('[7904] = -0.05 (below the window)', 1, out=-0.05)
    add('[7904] = +0.05 (above the window)', 1, out=0.05)
    add('[7904] = NaN', 1, out=float('nan'))
    add('[43FC] = 0.2 exactly  (0.2 > x is false)', 0, f43FC=r(0x0C50D4))
    add('[43FC] one float below 0.2', 1, f43FC=nextdown(r(0x0C50D4)))
    add('[43FC] = 0.7 exactly, [78B8] = 0.55  (0.7 > x is false)', 1, f43FC=r(0x0C50D8), f78B8=0.55)
    add('[43FC] one float below 0.7, [78B8] = 0.55', 0, f43FC=nextdown(r(0x0C50D8)), f78B8=0.55)
    add('[43FC] = 0.65, [78B8] = 0.7: within 0.2 below / 0.1 above -> [7904] tests bypassed', 1, f43FC=0.65)
    add('byte [7912] = 0', 0, en=0)
    add('byte [7912] = 2', 0, en=2)
    add('0x0582D2 returns 0', 0, r582D2=0)
    add('0x0584D2 returns 0', 0, r584D2=0)
    for i in range(300 if QUICK else 1500):
        c = base()
        c.update(r584D2=rng.choice((1, 1, 1, 0)), r582D2=rng.choice((1, 1, 1, 0, 0xFF)),
                 w67EC=rng.choice((7499, 7500, 9000)), f6350=rng.choice((69.9, 70.0, 90.0)),
                 f65FC=rng.choice((19.9, 20.0, 60.0)), f63C4=rng.choice((5.9, 6.0, 20.0)),
                 f63FC=rng.choice((0.0, 0.0199, -0.0199, 0.021, -0.5)),
                 f43FC=rng.choice((0.1, 0.2, 0.45, 0.5, 0.65, 0.69, 0.7, 0.85, rng.uniform(0, 1))),
                 out=rng.uniform(-0.05, 0.05), f40C8=rng.choice((-1.0, 0.0, 10.0, 49.9, 50.0)),
                 f7D68=rng.choice((0.0, 0.19, 0.2, 0.5)), f78B8=rng.choice((0.7, 0.68, 0.9)),
                 f77DC=rng.choice((-1.0, -1.01, 0.0, 0.99, 1.0)), f69F0=rng.choice((0.0, 0.0002, 0.001, -0.3)),
                 f9314=rng.uniform(-0.04, 0.0), f9318=rng.uniform(0.0, 0.04), w6A22=rng.choice((18, 19, 500)),
                 en=rng.choice((1, 1, 1, 0)), b7449=rng.choice((1, 1, 1, 0)), b7464=rng.choice((0, 0, 0, 1)))
        if i % 3 == 0:          # a third of the random cases keep every precondition met
            c.update(r584D2=1, r582D2=1, w67EC=9000, f6350=90.0, f65FC=60.0, f63C4=20.0, f63FC=0.0,
                     f40C8=10.0, f77DC=0.0, f69F0=0.0, en=1, b7449=1, b7464=0)
        cases.append(('rnd%d' % i, c, None))
    want_writes = set()
    for a in (0xFFFF933C, 0xFFFF9340, 0xFFFF9344, 0xFFFF9348, 0xFFFF934C, 0xFFFF9350):
        want_writes |= {a, a + 1, a + 2, a + 3}
    want_writes |= {0xFFFF9354, 0xFFFF9355, 0xFFFF9356, 0xFFFF932C}
    n1 = n0 = 0
    print('0x06665E: copies, then one result byte [0xFFFF932C]; model of the whole function')
    for tag, c, want in cases:
        emu = run_6665E(c)
        b9356, res = model_6665E(c)
        ok(want is None or res == want, '6665E directed case %s: model %d want %r' % (tag, res, want))
        ok(same(emu.read_f32(0xFFFF9340), f32(c['out'])), '[9340] = [7904] %s' % tag)
        ok(same(emu.read_f32(0xFFFF933C), f32(c['f43FC'])), '[933C] = [43FC]')
        ok(same(emu.read_f32(0xFFFF9344), f32(c['f40C8'])) and same(emu.read_f32(0xFFFF9348), f32(c['f7D68']))
           and same(emu.read_f32(0xFFFF934C), f32(c['f78B8'])) and same(emu.read_f32(0xFFFF9350), f32(c['f77DC'])),
           'copies %s' % tag)
        ok(emu.read_u8(0xFFFF9354) == c['b7449'] and emu.read_u8(0xFFFF9355) == c['b7464'], 'byte copies')
        ok(emu.read_u8(0xFFFF9356) == b9356, '[9356] %s: %d want %d' % (tag, emu.read_u8(0xFFFF9356), b9356))
        ok(emu.read_u8(0xFFFF932C) == res, '[932C] %s: %d want %d' % (tag, emu.read_u8(0xFFFF932C), res))
        ok(set(emu.writes) == want_writes, '6665E write set %s' % sorted(map(hex, set(emu.writes) ^ want_writes)))
        n1 += res
        n0 += 1 - res
        if not tag.startswith('rnd'):
            print('  %-82s byte [932C] = %d' % (tag, res))
    print('  %d cases match (%d give 1, %d give 0); RAM written by the function on every run:' % (len(cases), n1, n0))
    print('  floats 933C 9340 9344 9348 934C 9350, bytes 9354 9355 9356 and the result byte 932C -- nothing else')

    # E2d: 0x0668B4 and 0x066904 read the SAME copy (0xFFFF9340) again
    thr = TUNED[0x0C478C]
    n = 0
    seen = {(e, v): 0 for e in (0x0668B4, 0x066904) for v in (0, 1, 'kept')}
    grid = []
    for b932C in (0, 1, 2):
        for b9320 in (0, thr - 1, thr, thr + 1, 0x80, 0xFF):
            for out, e14, e18 in ((0.0, -0.01, 0.02), (0.05, -0.01, 0.02), (-0.05, -0.01, 0.02),
                                  (lo_edge, -0.01, 0.02), (nextup(lo_edge), -0.01, 0.02),
                                  (cand, -0.01, 0.02), (nextup(cand), -0.01, 0.02),
                                  (float('nan'), -0.01, 0.02)):
                for x in (0.1, nextdown(r(0x0C50D4)), r(0x0C50D4), 0.5, nextdown(r(0x0C50D8)), r(0x0C50D8), 0.9):
                    grid.append((b932C, b9320, out, e14, e18, x))
    for entry, dst in ((0x0668B4, 0xFFFF932D), (0x066904, 0xFFFF932E)):
        for b932C, b9320, out, e14, e18, x in grid:
            for prev in (0, 1):
                emu = new_emu(TUNED)
                emu.ram_u8(0xFFFF932C, b932C)
                emu.ram_u8(0xFFFF9320, b9320)
                emu.ram_f32(0xFFFF9340, out)
                emu.ram_f32(0xFFFF9314, e14)
                emu.ram_f32(0xFFFF9318, e18)
                emu.ram_f32(0xFFFF933C, x)
                emu.ram_u8(dst, prev)
                ok(emu.call(entry) == 'return', 'ret')
                ok(not emu.uninit_reads, 'uninit %s' % sorted(map(hex, emu.uninit_reads)))
                o, lo14, hi18, xx = f32(out), f32(e14), f32(e18), f32(x)
                if b932C != 1:
                    want = 0
                elif not (b9320 >= thr):
                    want = 'kept'
                elif entry == 0x0668B4:
                    want = 1 if (hi18 > fadd(o, eps)) and (r(0x0C50D8) > xx) else 0
                else:
                    want = 1 if (o > fadd(lo14, eps)) and not (r(0x0C50D4) > xx) else 0
                got = emu.read_u8(dst)
                ok(got == (prev if want == 'kept' else want), '%06X %r' % (entry, (b932C, b9320, out, x, prev)))
                ok(set(emu.writes) <= {dst}, '%06X writes only its own byte' % entry)
                ok((dst in emu.writes) == (want != 'kept'), 'write/no write')
                seen[(entry, want)] += 1
                n += 1
    print('0x0668B4: byte [932D] = 0 if byte [932C] != 1; unchanged if byte [9320] < %d;' % thr)
    print('          else 1 iff [9318] > [9340]+%.4f and %.1f > [933C]' % (eps, r(0x0C50D8)))
    print('0x066904: byte [932E] = 0 if byte [932C] != 1; unchanged if byte [9320] < %d;' % thr)
    print('          else 1 iff [9340] > [9314]+%.4f and not (%.1f > [933C])' % (eps, r(0x0C50D4)))
    print('  %d cases match; outcomes %s' % (n, {('%06X' % k[0], k[1]): v for k, v in seen.items()}))
    ok(all(v > 0 for v in seen.values()), 'every outcome exercised')

    # E2e: who else could read the copy? (from bytes, not emulated) The literal 0xFFFF9340
    # occurs once in the ROM, as slot +4 of the table 0x097520. Every PC-relative mov.l that
    # loads the table base is found by scanning the whole image; the code each loader reaches
    # is decoded and every @(disp,Rn) / @(r0,Rn) whose Rn can hold the base is collected.
    lit = struct.pack('>I', 0xFFFF9340)
    ok([a for a in range(0, len(TUNED) - 3, 4) if TUNED[a:a + 4] == lit] == [0x097524],
       'literal 0xFFFF9340 occurs only as table slot 0x097524')
    pools = [a for a in range(0, len(TUNED) - 3, 4) if TUNED[a:a + 4] == struct.pack('>I', 0x00097520)]
    loaders = []
    for a in range(0, len(TUNED) - 1, 2):
        w = struct.unpack_from('>H', TUNED, a)[0]
        if (w >> 12) == 0xD and (((a + 4) & ~3) + (w & 0xFF) * 4) in pools:
            loaders.append((a, (w >> 8) & 0xF))
    ok([a for a, _ in loaders] == [0x066770, 0x0668B6, 0x066906, 0x066D50, 0x066E1C, 0x066EBC, 0x066F94],
       'loaders of 0x00097520: %s' % [hex(a) for a, _ in loaders])
    ok(all(rn == 4 for _, rn in loaders), 'every loader puts the base in r4')
    # (range, registers that hold the base there). 0x066D20 / 0x066DEC pass r4 to 0x066D5E /
    # 0x066E2E (bsr), which copy it to r14; 0x066EBC copies it to r14, 0x066F94 to r13.
    others = ((0x066D20, 0x066D5E, ('r4',)), (0x066D5E, 0x066DEC, ('r4', 'r14')),
              (0x066DEC, 0x066E2A, ('r4',)), (0x066E2E, 0x066EBC, ('r4', 'r14')),
              (0x066EBC, 0x066F5E, ('r4', 'r14')), (0x066F94, 0x06702A, ('r4', 'r13')))
    used = set()
    for lo, hi, regs in others:
        for pc, w, txt, _d in D.disasm(TUNED, lo, hi):
            for m in re.finditer(r'@\((\d+),(r\d+)\)', txt):
                if m.group(2) in regs and txt.startswith('mov.l'):
                    used.add(int(m.group(1)))
                    ok(int(m.group(1)) >= 40, '%06X reads table slot +%s: %s' % (pc, m.group(1), txt))
            ok(not re.search(r'@\(r0,(%s)\)' % '|'.join(regs), txt), '%06X indexed table access: %s' % (pc, txt))
    ok(used == {40, 44, 48, 52, 56, 60}, 'slots used by the other four loaders: %s' % sorted(used))
    reads4 = [pc for lo, hi in ((0x06677A, 0x066880), (0x0668B4, 0x066904), (0x066904, 0x066954))
              for pc, w, txt, _d in D.disasm(TUNED, lo, hi) if re.match(r'mov\.l @\(4,r(4|14)\),', txt)]
    ok(reads4 == [0x0667D0, 0x0667EE, 0x0668D2, 0x066922], 'slot +4 loads: %s' % [hex(a) for a in reads4])
    print('  E2e: 0xFFFF9340 occurs once (slot 0x097524); the table base has 7 loaders; the four outside')
    print('       0x06665E/0x0668B4/0x066904 reach code that uses slots %s only; slot +4 is loaded at'
          % sorted(used))
    print('       0x0667D0, 0x0667EE, 0x0668D2, 0x066922 -> the copy has exactly four reads (bytes, not emulated)')

    # E2f: 0x032204 keeps a stack copy of 7904 but only reads it when byte [0xCBBDF]==1
    ok(TUNED[0x0CBBDF] == 0 and STOCK[0x0CBBDF] == 0, '[CBBDF]')
    print('0x032204: its only read of the 7904 copy (0x032374) is behind `[0x0CBBDF]==1`; '
          'byte is 0x%02X tuned / 0x%02X stock (from bytes, not emulated)'
          % (TUNED[0x0CBBDF], STOCK[0x0CBBDF]))


# ---- E3: the 0x03580C chain: 0x0358A0, 0x0359A4, 0x035DE4, 0x035E2C, 0x035E64 --
SITES = {1: 0x035C2A, 2: 0x035C4A, 3: 0x035C82, 4: 0x035CB0, 5: 0x035D06, 6: 0x035DAC}
SITE_TXT = {1: 'min(L+[CC150], [CC158]=+0.05)', 2: 'max(L-[CC150], [CC154]=-0.05)',
            3: 'clamp(L-[CC160], 0, +0.05)', 4: 'clamp(L+[CC15C], -0.05, 0)',
            5: 'min(L+[CC144], [CC140]=+0.06)', 6: 'max(L-[CC144], [CC13C]=-0.06)'}


def model_359A4(s, img, k1, k2, a, b):
    """0x0359A4 from the byte reading. k1/k2 are the two 1-D lookups, a/b the two
    2-D lookups (taken from the run; each is checked against its table separately).
    Returns the new state and 'Lreg', the value handed to 0x035F48 in fr4."""
    r = lambda ad: romf(img, ad)             # noqa: E731
    o = dict(f7944=f32(s['f7944']), w794A=s['w794A'], w794C=s['w794C'], b794E=s['b794E'],
             b794F=s['b794F'], site=None)
    L = f32(s['L'])
    x44 = f32(s['f7944'])
    if s['b7950'] == 1:                                                   # 0x035AC2
        k = k1 if s['hys'] == 1 else k2                                   # 0x035AC8
        x44 = lpf(f32(s['out']), x44, k, r(0x035D24))
        o['f7944'] = x44
    reset = (s['b7950'] != 1                                              # 0x035AEE
             or not (s['w7988'] >= u16(img, 0x0CBC4C))                    # 0x035AFE
             or (r(0x0CC130) > f32(s['f7958']))                           # 0x035B0E
             or s['b798A'] != 0                                           # 0x035B18
             or s['w794A'] >= u16(img, 0x0CBC56))                         # 0x035B28
    if reset:                                                             # 0x035DB4
        o.update(w794A=0, w794C=0x0200, b794E=0, b794F=0, Lreg=L)
        return o
    wA = sat16(s['w794A'])                                                # 0x035B38
    wC, bE, bF = s['w794C'], s['b794E'], s['b794F']
    D = fsub(x44, L)                                                      # 0x035B44
    site = None
    if s['b824'] == 1 or s['b825'] == 1:                                  # 0x035B4C, 0x035B56 -> 0x035CB8
        if not (r(0x0CC138) > D):                                         # 0x035CBC
            wC = sat16(wC)
        elif r(0x0CC134) > D:                                             # 0x035CD6
            if wC > 0:
                wC -= 1
        if wC >= u16(img, 0x0CBC50):                                      # 0x035CF6
            L, site = fmin(fadd(L, r(0x0CC144)), r(0x0CC140)), 5
        elif not (wC >= u16(img, 0x0CBC4E)):                              # 0x035D9C
            L, site = fmax(fsub(L, r(0x0CC144)), r(0x0CC13C)), 6
    else:
        a2 = fadd(a, r(0x0CC148))                                         # 0x035B8A
        b2 = fadd(b, r(0x0CC14C))                                         # 0x035B98
        if not (b > D):                                                   # 0x035BA6
            wC = sat16(wC)
        elif a > D:                                                       # 0x035BC0
            if wC > 0:
                wC -= 1
        if not (b2 > x44):                                                # 0x035BE0
            bE = sat8(bE)
        elif a2 > x44:                                                    # 0x035BFE
            bF = sat8(bF)
        if wC >= u16(img, 0x0CBC54):                                      # 0x035C1A
            L, site = fmin(fadd(L, r(0x0CC150)), r(0x0CC158)), 1
        elif not (wC >= u16(img, 0x0CBC52)):                              # 0x035C3A
            L, site = fmax(fsub(L, r(0x0CC150)), r(0x0CC154)), 2
        elif wA == u16(img, 0x0CBC56):                                    # 0x035C5A
            if not (0.0 > L) and not (bE >= img[0x0CBBF0]):               # 0x035C64, 0x035C70
                L, site = clamp(fsub(L, r(0x0CC160)), 0.0, r(0x0CC158)), 3
            elif (0.0 > L) and not (bF >= img[0x0CBBF1]):                 # 0x035C8A, 0x035C9A
                L, site = clamp(fadd(L, r(0x0CC15C)), r(0x0CC154), 0.0), 4
    o.update(w794A=wA, w794C=wC, b794E=bE, b794F=bF, site=site, Lreg=L)
    return o


S359 = (('out', 0xFFFF7904, 'f'), ('b824', 0xFFFFA824, 'b'), ('b825', 0xFFFFA825, 'b'),
        ('hys', 0xFFFF7913, 'b'), ('f7970', 0xFFFF7970, 'f'), ('b7950', 0xFFFF7950, 'b'),
        ('f7944', 0xFFFF7944, 'f'), ('w7988', 0xFFFF7988, 'w'), ('f7958', 0xFFFF7958, 'f'),
        ('b798A', 0xFFFF798A, 'b'), ('w794A', 0xFFFF794A, 'w'), ('w794C', 0xFFFF794C, 'w'),
        ('b794E', 0xFFFF794E, 'b'), ('b794F', 0xFFFF794F, 'b'), ('f796C', 0xFFFF796C, 'f'),
        ('f7964', 0xFFFF7964, 'f'))


def load_359(emu, s):
    for k, a, t in S359:
        (emu.ram_f32 if t == 'f' else emu.ram_u8 if t == 'b' else emu.ram_u16)(a, s[k])
    emu.ram_u32(0xFFFF318C, E.f2b(s['L']))
    emu.ram_u16(0xFFFF3190, 0x1111)
    emu.ram_u16(0xFFFF3192, 0x2222)


def check_359A4(img, s, tag):
    emu = new_emu(img)
    load_359(emu, s)
    ok(emu.call(0x0359A4) == 'return', '359A4 return')
    ok(not emu.uninit_reads, '359A4 uninit %s' % sorted(map(hex, emu.uninit_reads)))
    ok(emu.R[15] == E.STACK_TOP, '359A4 stack')
    k1, k2 = emu.read_f32(0xFFFF7974), emu.read_f32(0xFFFF7978)
    ok(abs(k1 - interp(img, 0x0AD068, f32(s['f7970']))) < 1e-7, 'k1 lookup')
    ok(abs(k2 - interp(img, 0x0AD07C, f32(s['f7970']))) < 1e-7, 'k2 lookup')
    if 0x035B5E in emu.executed:              # the branch that does the two 2-D lookups
        a, b = emu.read_f32(0xFFFF797C), emu.read_f32(0xFFFF7980)
        ok(same(a, romf(img, 0x0D2618)) and same(b, romf(img, 0x0D27F0)), '2-D lookups are their constant cell')
    else:
        a, b = romf(img, 0x0D2618), romf(img, 0x0D27F0)
    m = model_359A4(s, img, k1, k2, a, b)
    ok(same(emu.read_f32(0xFFFF7944), m['f7944']), '%s [7944] %r want %r' % (tag, emu.read_f32(0xFFFF7944), m['f7944']))
    ok(emu.read_u16(0xFFFF794A) == m['w794A'] and emu.read_u16(0xFFFF794C) == m['w794C'], '%s counters' % tag)
    ok(emu.read_u8(0xFFFF794E) == m['b794E'] and emu.read_u8(0xFFFF794F) == m['b794F'], '%s byte counters' % tag)
    stored = clamp(m['Lreg'], romf(img, 0x036000), romf(img, 0x035FFC))
    ok(same(emu.read_f32(0xFFFF318C), stored), '%s [318C] %r want %r' % (tag, emu.read_f32(0xFFFF318C), stored))
    w = E.f2b(stored)
    ck = (~((w >> 16) + (w & 0xFFFF))) & 0xFFFF
    ok(emu.read_u16(0xFFFF3190) == ck and emu.read_u16(0xFFFF3192) == ck, '%s checksum words' % tag)
    for n, pc in SITES.items():
        ok((pc in emu.executed) == (m['site'] == n), '%s site %d' % (tag, n))
    ok(0x035F48 in emu.executed and 0x035DE0 in emu.executed, 'every path leaves through 0x035DE0 -> 0x035F48')
    return m, emu


def rnd_359(rng, wide):
    L = rng.choice((0.0, 0.05, -0.05, 0.06, -0.06, 0.0495, -0.0495, 0.0499, 0.0595, -0.0597,
                    rng.uniform(-0.06, 0.06), rng.uniform(-0.06, 0.06), rng.uniform(-0.002, 0.002),
                    rng.uniform(-0.5, 0.5) if wide else rng.uniform(-0.06, 0.06)))
    return dict(
        out=rng.uniform(-0.13, 0.09), b824=rng.choice((0, 0, 1, 2)), b825=rng.choice((0, 0, 1, 0x81)),
        hys=rng.choice((0, 1, 2)), f7970=rng.uniform(-5, 80), L=L, b7950=rng.choice((1, 1, 1, 1, 0, 2)),
        f7944=rng.choice((L, L + 0.013, L - 0.01, rng.uniform(-0.1, 0.1), L + rng.uniform(-0.03, 0.03))),
        w7988=rng.choice((0, 30, 31, 32, 500, 0x8000, 0xFFFF)), f7958=rng.choice((2.0, 7.99, 8.0, 9.0, 30.0)),
        b798A=rng.choice((0, 0, 0, 0, 1)), w794A=rng.choice((0, 1, 100, 154, 155, 155, 155, 156, 157, 0xFFFF)),
        w794C=rng.choice((0, 1, 100, 355, 356, 357, 358, 512, 666, 667, 668, 669, 900, 0xFFFE, 0xFFFF)),
        b794E=rng.choice((0, 0, 1, 2, 254, 255)), b794F=rng.choice((0, 0, 1, 2, 254, 255)),
        f796C=rng.uniform(0, 3), f7964=rng.uniform(0, 4500))


def section_E_learn():
    print('0x0359A4 (whole function): filter [7904] -> [7944], vote counters, step L, store through 0x035F48')
    rng = random.Random(49)
    hits = {k: 0 for k in list(SITES) + [None]}
    n = 0
    maxstep_in = maxstep_05 = 0.0
    for name, img in (('SBND2', SBND2), ('TUNED', TUNED)):
        for i in range(500 if QUICK else 2500):
            s = rnd_359(rng, wide=True)
            m, emu = check_359A4(img, s, '%s rnd%d' % (name, i))
            hits[m['site']] += 1
            n += 1
            if name == 'TUNED':
                ok(bits(emu.read_f32(0xFFFF318C)) == 0, 'TUNED: every exit stores +0.0')
                continue
            Li, Lo = f32(s['L']), emu.read_f32(0xFFFF318C)
            if abs(Li) <= romf(img, 0x0CC140):
                ok(abs(Lo) <= romf(img, 0x0CC140), 'stock: |L| <= 0.06 is preserved (%r -> %r)' % (Li, Lo))
                d = abs(f32(Lo - Li))          # harness measurement of the step, not a chip model
                if abs(Li) <= romf(img, 0x0CC158):
                    maxstep_in = max(maxstep_in, d)
                    ok(d <= 0.000501, 'stock: |L| <= 0.05 moves by at most one step (%r -> %r)' % (Li, Lo))
                else:
                    maxstep_05 = max(maxstep_05, d)
            else:
                ok(abs(Lo) <= abs(Li), 'stock: |L| > 0.06 never grows (%r -> %r)' % (Li, Lo))
    # directed: the two 'decay toward zero' sites, which random states rarely reach
    # [794E] counts calls with [7944] >= 0.013 and [794F] calls with [7944] < -0.01 (absolute,
    # not relative to L); a non-zero count vetoes the decay of that sign.
    for L, x44, bE, bF, want in ((0.02, 0.011, 0, 0, 3), (0.0, 0.0, 0, 0, 3), (0.0003, 0.0, 0, 0, 3),
                                 (0.02, 0.011, 1, 0, None), (0.02, 0.02, 0, 0, None),
                                 (-0.02, -0.009, 0, 0, 4), (-0.0003, 0.0, 0, 0, 4),
                                 (-0.02, -0.009, 0, 1, None), (-0.02, -0.0105, 0, 0, None),
                                 (-0.0, 0.0, 0, 0, 3), (float('nan'), 0.0, 0, 0, 3)):
        for name, img in (('SBND2', SBND2), ('TUNED', TUNED)):
            # filter input == filter state, so [7944] stays at x44 through the call
            s = dict(out=x44, b824=0, b825=0, hys=0, f7970=12.0, L=L, b7950=1, f7944=x44,
                     w7988=100, f7958=9.0, b798A=0, w794A=155, w794C=512, b794E=bE, b794F=bF,
                     f796C=1.0, f7964=2000.0)
            m, emu = check_359A4(img, s, '%s decay L=%r' % (name, L))
            ok(m['site'] == want, 'decay site L=%r [7944]=%r bE=%d bF=%d: %r' % (L, x44, bE, bF, m['site']))
            hits[m['site']] += 1
            n += 1
    print('  %d states (stock module and tuned) match the model bit-exactly; step-site hits:' % n)
    for k in (1, 2, 3, 4, 5, 6):
        print('    site %d  0x%06X  L = %-32s %5d' % (k, SITES[k], SITE_TXT[k], hits[k]))
    print('    no step                                               %5d' % hits[None])
    ok(all(hits[k] > 0 for k in SITES), 'every step site exercised')
    print('  stock module: |L| <= 0.06 in -> |L| <= 0.06 out; |L| <= 0.05 moves by <= 0.0005 (max seen %.6f);'
          % maxstep_in)
    print('  0.05 < |L| <= 0.06 can be pulled in by up to 0.01 in one call (max seen %.6f); |L| > 0.06 never grows'
          % maxstep_05)

    # the period: one vote per call, 156 calls, then one reset call
    for name, img in (('SBND2', SBND2),):
        for bias, path_b, want_site, dL in ((+0.02, 0, 1, +1), (-0.02, 0, 2, -1), (0.0, 0, 3, -1),
                                           (+0.02, 1, 5, +1), (-0.02, 1, 6, -1)):
            emu = new_emu(img)
            L0 = 0.01
            s = dict(out=L0 + bias, b824=path_b, b825=0, hys=0, f7970=12.0, L=L0, b7950=1, f7944=L0 + bias,
                     w7988=100, f7958=9.0, b798A=0, w794A=0, w794C=0x0200, b794E=0, b794F=0,
                     f796C=1.0, f7964=2000.0)
            load_359(emu, s)
            steps = []
            for call in range(1, 315):
                emu.ram_f32(0xFFFF7904, emu.read_f32(0xFFFF318C) + bias)      # keep [7904] - L = bias
                emu.ram_f32(0xFFFF7944, emu.read_f32(0xFFFF318C) + bias)
                before = emu.read_f32(0xFFFF318C)
                emu.executed.clear()
                emu.call(0x0359A4)
                after = emu.read_f32(0xFFFF318C)
                if not same(before, after):
                    steps.append((call, [k for k, pc in SITES.items() if pc in emu.executed][0]))
            ok(steps == [(156, want_site), (313, want_site)],
               'period %s bias %+.2f path_b %d: %r' % (name, bias, path_b, steps))
            ok(abs(emu.read_f32(0xFFFF318C) - (L0 + 2 * dL * romf(img, 0x0CC150))) < 1e-7, 'two steps')
            print('  stock, [7944]-L held at %+.2f, byte [A824]=%d, 314 calls: L steps on calls %s (site %d)'
                  % (bias, path_b, [c for c, _ in steps], want_site))

    # 0x0358A0: byte [7950]
    rng = random.Random(8)
    r = lambda a: romf(TUNED, a)             # noqa: E731

    def base():
        return dict(cnt=5, b9709=0, en=1, b782B=0, f7D68=0.0, b984D=0, f7958=12.0, f7954=85.0, f795C=0.0,
                    f7960=0.0, f7964=2000.0, w7984=100, b798B=0, f7968=50.0, b7952=0)

    def model_358A0(s):
        g = lambda k: f32(s[k])              # noqa: E731
        if s['en'] != 1 or not (s['cnt'] >= u16(TUNED, 0x0CBC48)):
            return 0
        if not (r(0x0CC110) > g('f7958')) or (r(0x0CC114) > g('f7958')) or (r(0x0CC118) > g('f7954')):
            return 0
        if s['b9709'] != 0 or s['b782B'] != 0 or s['b984D'] != 0:
            return 0
        if outside(g('f795C'), 0.0, r(0x035A64)):
            if not (r(0x0CC11C) > g('f7D68')) or not (s['w7984'] >= u16(TUNED, 0x0CBC4A)):
                return 0
        if not (r(0x0CC120) > g('f7960')) or (r(0x0CC124) > g('f7964')) or not (r(0x0CC128) > g('f7964')):
            return 0
        if s['b798B'] != 0 or not (r(0x0CC12C) > g('f7968')) or s['b7952'] != 0:
            return 0
        return 1

    cases = [('all met', base())]
    for k, vals in (('en', (0, 2)), ('b9709', (1,)), ('b782B', (1,)), ('b984D', (1,)), ('b798B', (1,)),
                    ('b7952', (1,)), ('f7958', (r(0x0CC110), nextdown(r(0x0CC110)), r(0x0CC114), nextdown(r(0x0CC114)))),
                    ('f7954', (r(0x0CC118), nextdown(r(0x0CC118)))), ('f7960', (r(0x0CC120), nextdown(r(0x0CC120)))),
                    ('f7964', (r(0x0CC124), nextdown(r(0x0CC124)), r(0x0CC128), nextdown(r(0x0CC128)))),
                    ('f7968', (r(0x0CC12C), nextdown(r(0x0CC12C)))), ('f795C', (0.5,)), ('cnt', (0, 0xFFFF))):
        for v in vals:
            c = base()
            c[k] = v
            cases.append(('%s = %r' % (k, v), c))
    for f7d68, w in ((0.05, 20), (0.05, 19), (r(0x0CC11C), 20), (nextdown(r(0x0CC11C)), 20)):
        c = base()
        c.update(f795C=0.5, f7D68=f7d68, w7984=w)
        cases.append(('[795C]=0.5 [7D68]=%r w7984=%d' % (f7d68, w), c))
    for i in range(200 if QUICK else 800):
        c = base()
        for k in ('en', 'b9709', 'b782B', 'b984D', 'b798B', 'b7952'):
            if rng.random() < 0.06:
                c[k] = 1 - c[k]
        c.update(f7958=rng.choice((12.0, 12.0, 7.0, 26.0)), f7954=rng.choice((85.0, 85.0, 60.0)),
                 f795C=rng.choice((0.0, 0.0, 0.3)), f7D68=rng.choice((0.0, 0.1)), w7984=rng.choice((100, 3)),
                 f7960=rng.choice((0.0, 0.0, 0.03)), f7964=rng.choice((2000.0, 2000.0, 900.0, 3500.0)),
                 f7968=rng.choice((50.0, 50.0, 400.0)))
        cases.append(('rnd%d' % i, c))
    n1 = 0
    for tag, c in cases:
        emu = new_emu(TUNED)
        emu.ram_u16(0xFFFF7910, c['cnt'])
        emu.ram_u8(0xFFFF9709, c['b9709'])
        emu.ram_u8(0xFFFF7912, c['en'])
        emu.ram_u8(0xFFFF782B, c['b782B'])
        emu.ram_f32(0xFFFF7D68, c['f7D68'])
        emu.ram_u8(0xFFFF984D, c['b984D'])
        for k, a in (('f7958', 0xFFFF7958), ('f7954', 0xFFFF7954), ('f795C', 0xFFFF795C), ('f7960', 0xFFFF7960),
                     ('f7964', 0xFFFF7964), ('f7968', 0xFFFF7968)):
            emu.ram_f32(a, c[k])
        emu.ram_u16(0xFFFF7984, c['w7984'])
        emu.ram_u8(0xFFFF798B, c['b798B'])
        emu.ram_u8(0xFFFF7952, c['b7952'])
        ok(emu.call(0x0358A0) == 'return', '358A0 return')
        ok(not emu.uninit_reads, '358A0 uninit %s' % sorted(map(hex, emu.uninit_reads)))
        ok(emu.read_u8(0xFFFF7950) == model_358A0(c), '358A0 %s: %d' % (tag, emu.read_u8(0xFFFF7950)))
        ok(set(emu.writes) == {0xFFFF7950}, '358A0 writes only byte [7950]')
        n1 += emu.read_u8(0xFFFF7950)
    print('0x0358A0: byte [7950] = 1 iff byte[7912]==1, 25 > [7958] >= 8 (not 8 > x), not (70 > [7954]),')
    print('          bytes [9709] [782B] [984D] [798B] [7952] all 0, 0.02 > [7960], 3000 > [7964] and')
    print('          not (1000 > [7964]), 300 > [7968], and ([795C] within +-0.000244 of 0, or')
    print('          0.06 > [7D68] and word [7984] >= 20): %d cases match (%d give 1)' % (len(cases), n1))

    # 0x035DE4 / 0x035E2C / 0x035E64: the readers of the filtered copy [7944]
    n = 0
    hi_c, lo_c, cnt_c = r(0x0CC164), r(0x0CC168), u16(TUNED, 0x0CBC58)
    for x44 in (0.0, 0.03, -0.13, 0.5, -0.5, nextdown(hi_c), hi_c, 50.0, nextup(lo_c), lo_c, -3.0, float('nan')):
        for en in (0, 1, 2):
            for b7951 in (0, 1, 2):
                for w in (0, 1, cnt_c - 1, cnt_c, 0x8000, 0xFFFF):
                    emu = new_emu(TUNED)
                    emu.ram_f32(0xFFFF7944, x44)
                    emu.ram_u8(0xFFFF7912, en)
                    emu.ram_u8(0xFFFF7951, b7951)
                    emu.ram_u16(0xFFFF7948, w)
                    ok(emu.call(0x035DE4) == 'return', '35DE4 ret')
                    ok(not emu.uninit_reads, '35DE4 uninit')
                    x = f32(x44)
                    want = 0 if b7951 == 1 else (sat16(w) if (en == 1 and not (hi_c > x)) else w)
                    ok(emu.read_u16(0xFFFF7948) == want, '35DE4 %r' % ((x44, en, b7951, w),))
                    ok(set(emu.writes) <= {0xFFFF7948, 0xFFFF7949}, '35DE4 writes only word [7948]')
                    n += 1
                    for b6a28 in (0, 1):
                        for b7952 in (0, 1):
                            emu = new_emu(TUNED)
                            emu.ram_f32(0xFFFF7944, x44)
                            emu.ram_u16(0xFFFF7948, w)
                            emu.ram_u8(0xFFFF6A28, b6a28)
                            emu.ram_u8(0xFFFF7951, b7951)
                            emu.ram_u8(0xFFFF7952, b7952)
                            ok(emu.call(0x035E2C) == 'return', '35E2C ret')
                            ok(not emu.uninit_reads, '35E2C uninit')
                            w51, w52 = b7951, b7952
                            if w >= cnt_c and not (x > lo_c):
                                w51 = w52 = 1
                            elif b6a28 == 1:
                                w52 = 0
                            ok(emu.read_u8(0xFFFF7951) == w51 and emu.read_u8(0xFFFF7952) == w52,
                               '35E2C %r' % ((x44, w, b6a28, b7951, b7952),))
                            n += 1
    print('0x035DE4: word [7948] = 0 if byte [7951] == 1; else +1 (sat.) when byte [7912] == 1 and not (%.0f > [7944])' % hi_c)
    print('0x035E2C: bytes [7951] = [7952] = 1 when word [7948] >= %d and not ([7944] > %.0f);' % (cnt_c, lo_c))
    print('          otherwise byte [7952] = 0 when byte [6A28] == 1.   %d cases match' % n)
    print('  no finite value satisfies both tests in one pass; a NaN in [7944] satisfies both')
    for b7950 in (0, 1, 2):
        for w in (0, 5, 0xFFFE, 0xFFFF):
            emu = new_emu(TUNED)
            emu.ram_u8(0xFFFF7950, b7950)
            emu.ram_u16(0xFFFF7988, w)
            emu.gbr = 0x12345678
            emu.call(0x035E64)
            ok(emu.read_u16(0xFFFF7988) == (sat16(w) if b7950 == 1 else 0) and emu.gbr == 0x12345678, '35E64')
    print('0x035E64: word [7988] = min([7988]+1, 0xFFFF) when byte [7950] == 1, else 0')


# =============================================================================
# F. 0x035F48 -- the second zeroed pair
# =============================================================================
def section_F():
    print('\n== F. 0x035F48(r4=flag, fr4=x): 0xFFFF318C := clamp(x, [0x036000], [0x035FFC]) when (r4&0xFF)==0')
    print('  %10s | %12s %12s' % ('x', '318C SBND2', '318C TUNED'))
    for x in (-0.7, -0.5, -0.2, -0.01, 0.0, 0.004, 0.2, 0.5, 0.7):
        row = {}
        for name, img in (('SBND2', SBND2), ('TUNED', TUNED)):
            emu = new_emu(img)
            emu.ram_u32(0xFFFF318C, E.f2b(0.33))
            emu.ram_u32(0xFFFF3190, 0)
            ok(emu.call(0x035F48, regs={4: 0}, fregs={4: x}) == 'return', '35F48 return')
            row[name] = emu.read_f32(0xFFFF318C)
            w = E.f2b(row[name])
            ck = (~((w >> 16) + (w & 0xFFFF))) & 0xFFFF
            ok(emu.read_u16(0xFFFF3190) == ck and emu.read_u16(0xFFFF3192) == ck, 'checksum')
            emu2 = new_emu(img)
            emu2.ram_u32(0xFFFF318C, E.f2b(0.33))
            emu2.ram_u32(0xFFFF3190, 0)
            emu2.call(0x035F48, regs={4: 1}, fregs={4: x})
            ok(same(emu2.read_f32(0xFFFF318C), f32(0.33)), 'r4!=0 must not store')
        ok(same(row['SBND2'], clamp(f32(x), -0.5, 0.5)), 'SBND2 %r' % x)
        ok(bits(row['TUNED']) == 0, 'TUNED 318C must be +0.0')
        print('  %+10.4f | %+12.4f %+12.4f' % (x, row['SBND2'], row['TUNED']))
    print('  TUNED: every store through 0x035F48 writes +0.0 to 0xFFFF318C (and its two checksum words)')


def section_G():
    """Functions decoded to test existing labels: the other stores to 0xFFFF318C."""
    print('\n== G. other stores to 0xFFFF318C; record check ' + '=' * 26)
    r = lambda a: romf(TUNED, a)                 # noqa: E731

    def cks(v):
        w = E.f2b(v)
        return (~((w >> 16) + (w & 0xFFFF))) & 0xFFFF

    def rec(emu, v, c1=None, c2=None):
        emu.ram_u32(0xFFFF318C, E.f2b(v))
        emu.ram_u16(0xFFFF3190, cks(v) if c1 is None else c1)
        emu.ram_u16(0xFFFF3192, cks(v) if c2 is None else c2)

    # G1: 0x035E88 (called by 0x0357D0 at init). NOT clamped by 0x035FFC/0x036000.
    print('0x035E88 (init): rewrites [318C] when it is >= [C5054] or < [C5060]; seeds [7944]')
    print('  %10s | %12s %12s' % ('[318C] in', '[318C] out', '[7944] out'))
    shown = (0.0, 0.005, 0.0099, 0.01, 0.02, 0.0279, 0.028, 0.2, -0.005, -0.0101, -0.02, -0.0241, -0.3)
    rngL = random.Random(3)
    extra = [0.5, -0.5, 0.06, -0.06, r(0x0C5054), nextdown(r(0x0C5054)), r(0x0C5060), nextdown(r(0x0C5060)),
             r(0x0CC0AC), nextdown(r(0x0CC0AC)), r(0x0CC0A8), nextdown(r(0x0CC0A8)), 1e30, -1e30,
             float('inf'), float('-inf'), float('nan')] + [rngL.uniform(-0.6, 0.6) for _ in range(200)]
    out_lo, out_hi = 9.0, -9.0
    for L in shown + tuple(extra):
        emu = new_emu(TUNED)
        rec(emu, L)
        ok(emu.call(0x035E88) == 'return', '35E88 return')
        Lf, out = model_35E88(TUNED, f32(L))
        ok(same(emu.read_f32(0xFFFF318C), Lf), '35E88 L=%r -> %r want %r' % (L, emu.read_f32(0xFFFF318C), Lf))
        ok(same(emu.read_f32(0xFFFF7944), out), '35E88 7944 L=%r' % L)
        got_L = emu.read_f32(0xFFFF318C)
        if L == L:                              # (a NaN record was given no valid checksum by rec())
            ok(emu.read_u16(0xFFFF3190) == cks(Lf) and emu.read_u16(0xFFFF3192) == cks(Lf), '35E88 checksum')
        ok(not emu.uninit_reads, '35E88 uninit %s' % sorted(map(hex, emu.uninit_reads)))
        out_lo, out_hi = min(out_lo, got_L), max(out_hi, got_L)
        if L in shown:
            print('  %+10.4f | %+12.4f %+12.4f' % (L, got_L, emu.read_f32(0xFFFF7944)))
    ok(out_lo >= -0.0280001 and out_hi <= 0.0380001, '35E88 output range [%r, %r]' % (out_lo, out_hi))
    print('  %d inputs incl. +-0.5, +-1e30, +-Inf and NaN: [318C] always leaves in [%.4f, %.4f]'
          % (len(shown) + len(extra), out_lo, out_hi))
    print('  (a NaN or +Inf fails "0.028 > L" and is rewritten to 0.038; -Inf to -0.028)')

    # G2: 0x0357D0
    emu = new_emu(TUNED)
    rec(emu, 0.0)
    emu.ram_u8(0xFFFF7986, 0)
    emu.ram_u16(0xFFFF794C, 0)
    ok(emu.call(0x0357D0) == 'return', '357D0 return')
    ok(emu.read_u8(0xFFFF7986) == 0xFF and emu.read_u16(0xFFFF794C) == 0x0200, '357D0 effects')
    ok(0x035E88 in emu.executed, '357D0 calls 35E88')
    print('0x0357D0: calls 0x035E88, then byte [7986] = 0xFF, word [794C] = 0x0200')

    # G3: 0x0BDCB6 / 0x0357F0 (record check), 0x0357E8 (reset)
    for tag, c1, c2, want in (('both checksum words right', None, None, 0),
                              ('first wrong, second right', 0x1234, None, 0),
                              ('first right, second wrong', None, 0x1234, 0),
                              ('both wrong', 0x1234, 0x4321, 1)):
        emu = new_emu(TUNED)
        rec(emu, 0.0125, c1, c2)
        ok(emu.call(0x0357F0) == 'return', '357F0 return')
        ok(emu.R[0] == want, '357F0 %s: r0=%d' % (tag, emu.R[0]))
        ok(same(emu.read_f32(0xFFFF318C), f32(0.0125)), 'value untouched')
        if want == 0:
            ok(emu.read_u16(0xFFFF3190) == cks(0.0125) and emu.read_u16(0xFFFF3192) == cks(0.0125),
               'repaired')
        else:
            ok(emu.read_u16(0xFFFF3190) == 0x1234 and emu.read_u16(0xFFFF3192) == 0x4321, 'left alone')
        print('0x0357F0 (0x0BDCB6 on 0xFFFF318C), %-26s -> r0 = %d' % (tag, emu.R[0]))
    emu = new_emu(TUNED)
    rec(emu, 0.0125)
    ok(emu.call(0x0357E8) == 'return', '357E8 return')
    ok(emu.read_u32(0xFFFF318C) == 0 and emu.read_u16(0xFFFF3190) == 0xFFFF
       and emu.read_u16(0xFFFF3192) == 0xFFFF, '357E8 reset')
    print('0x0357E8: [318C] = 0.0, checksum words 0xFFFF 0xFFFF')


def learn_inputs(emu, vals=None):
    v = dict(f63CC=12.0, f6350=85.0, f69F0=0.0, f63FC=0.0, w6A22=0x0123, b6254=0, f6624=2500.0,
             f65FC=50.0, f63F8=0.5, b8F24=0, f63C4=3.0)
    v.update(vals or {})
    for k, a in (('f63CC', 0xFFFF63CC), ('f6350', 0xFFFF6350), ('f69F0', 0xFFFF69F0), ('f63FC', 0xFFFF63FC),
                 ('f6624', 0xFFFF6624), ('f65FC', 0xFFFF65FC), ('f63F8', 0xFFFF63F8), ('f63C4', 0xFFFF63C4)):
        emu.ram_f32(a, v[k])
    emu.ram_u16(0xFFFF6A22, v['w6A22'])
    emu.ram_u8(0xFFFF6254, v['b6254'])
    emu.ram_u8(0xFFFF8F24, v['b8F24'])
    return v


def section_G4():
    """0x03580C: when does it run its body (and with it 0x0359A4)?  (disputed claim C24)"""
    print('0x03580C: body (latches, 0x0358A0, 0x0359A4, 0x035DE4, 0x035E2C) runs iff byte [7986] >= byte [CBBEF] = %d'
          % TUNED[0x0CBBEF])

    def cks(v):
        w = E.f2b(v)
        return (~((w >> 16) + (w & 0xFFFF))) & 0xFFFF

    latches = {0xFFFF7954: 'f6350', 0xFFFF7958: 'f63CC', 0xFFFF795C: 'f69F0', 0xFFFF7964: 'f6624',
               0xFFFF7968: 'f65FC', 0xFFFF796C: 'f63F8', 0xFFFF7970: 'f63C4'}
    for name, img in (('TUNED', TUNED), ('SBND2', SBND2)):
        for b7986 in (0, 1, 2, 0x7F, 0x80, 0xFF):
            emu = new_emu(img)
            v = learn_inputs(emu, dict(f63FC=-0.004))
            for a in (0xFFFF7D68, 0xFFFF7904):
                emu.ram_f32(a, 0.0)
            for a in (0xFFFF9709, 0xFFFF782B, 0xFFFF984D, 0xFFFFA824, 0xFFFFA825, 0xFFFF7913, 0xFFFF6A28,
                      0xFFFF7951, 0xFFFF7952):
                emu.ram_u8(a, 0)
            emu.ram_u8(0xFFFF7912, 1)
            emu.ram_u16(0xFFFF7910, 5)
            emu.ram_u16(0xFFFF7948, 0)
            emu.ram_u16(0xFFFF7988, 0)
            emu.ram_f32(0xFFFF7944, 0.01)
            emu.ram_u8(0xFFFF7950, 0x55)                # sentinel: only the body rewrites it
            emu.ram_u32(0xFFFF318C, E.f2b(0.02))
            emu.ram_u16(0xFFFF3190, cks(0.02))
            emu.ram_u16(0xFFFF3192, cks(0.02))
            emu.ram_u8(0xFFFF7986, b7986)
            emu.gbr = 0x12345678
            ran = []
            for call in (1, 2):
                emu.executed.clear()
                emu.writes.clear()
                ok(emu.call(0x03580C) == 'return', '3580C return')
                ok(emu.gbr == 0x12345678 and emu.R[15] == E.STACK_TOP, '3580C gbr/stack')
                body = 0x035820 in emu.executed
                ok(body == (0x0359A4 in emu.executed) == (0x0358A0 in emu.executed)
                   == (0x035DE4 in emu.executed) == (0x035E2C in emu.executed), 'body is all-or-nothing')
                ok(0x035E64 in emu.executed, 'the tail 0x035E64 runs on every call')
                ran.append(body)
                ok(emu.read_u8(0xFFFF7986) == 1, 'byte [7986] is 1 after every call')
                if call == 1:
                    ok(body == (b7986 >= img[0x0CBBEF]), 'body runs iff [7986] >= [CBBEF] (unsigned)')
                    if not body:
                        ok(set(emu.writes) == {0xFFFF7986, 0xFFFF7988, 0xFFFF7989},
                           'skipped call writes only [7986] and word [7988]: %s' % sorted(map(hex, emu.writes)))
                        ok(same(emu.read_f32(0xFFFF318C), 0.02), 'skipped call leaves [318C] alone')
                        ok(emu.read_u8(0xFFFF7950) == 0x55, 'skipped call leaves byte [7950] alone')
                else:
                    ok(body, 'the call after any call runs the body')
                if body:
                    for a, k in latches.items():
                        ok(same(emu.read_f32(a), f32(v[k])), 'latch %08X' % a)
                    ok(same(emu.read_f32(0xFFFF7960), abs(f32(v['f63FC']))), 'latch |[63FC]|')
                    ok(emu.read_u16(0xFFFF7984) == v['w6A22'] and emu.read_u8(0xFFFF798A) == v['b6254']
                       and emu.read_u8(0xFFFF798B) == v['b8F24'], 'integer latches')
                    ok(same(emu.read_f32(0xFFFF318C), 0.0 if name == 'TUNED' else f32(0.02)),
                       '%s: [318C] after the body' % name)
            ok(not emu.uninit_reads, '3580C uninit %s' % sorted(map(hex, emu.uninit_reads)))
            if name == 'TUNED':
                print('  byte [7986] = 0x%02X on entry: call 1 %s 0x0359A4, call 2 %s it'
                      % (b7986, 'RUNS' if ran[0] else 'SKIPS', 'runs' if ran[1] else 'skips'))
    print('  byte [7986] has three stores in the ROM: 0x0357DA (0xFF, init), 0x03588A (0), 0x035896 (+1, sat.)')
    print('  -> the only call that skips is one entered with [7986] == 0, i.e. before 0x0357D0 or any')
    print('     earlier call of 0x03580C has run since that byte was cleared')


def section_H():
    """Lifecycle: a non-zero 0xFFFF318C left in RAM, two inits, the periodic pair
    0x034EF4 + 0x03580C in dispatcher order (0x049ED0, 0x049ED6)."""
    print('\n== H. lifecycle with a leftover [318C] = 0.02 ' + '=' * 27)

    def cks(v):
        w = E.f2b(v)
        return (~((w >> 16) + (w & 0xFFFF))) & 0xFFFF

    def boot(img, loop_on):
        emu = new_emu(img)
        externals(emu)
        externals_learn(emu)
        cold(emu, CHAIN_STATE_NOT_INIT)        # state init does not write: as after a RAM clear
        cold(emu, LEARN_STATE_NOT_INIT)
        emu.ram_u8(A_EN, 0)
        if not loop_on:
            emu.ram_u8(0xFFFF7448, 0)
        emu.ram_u32(0xFFFF318C, E.f2b(0.02))
        emu.ram_u16(0xFFFF3190, cks(0.02))
        emu.ram_u16(0xFFFF3192, cks(0.02))
        return emu

    def init(emu):                      # order in 0x047C40: 0x047F52 then 0x047F58
        emu.call(0x0357D0)
        emu.call(0x034EC8)

    def show(tag, emu):
        print('  %-22s [318C] %+.4f  [790C] %+.4f  [7904] %+.6f  [7944] %+.6f  en=%d' % (
            tag, emu.read_f32(0xFFFF318C), emu.read_f32(A_L0), emu.read_f32(A_OUT),
            emu.read_f32(0xFFFF7944), emu.read_u8(A_EN)))

    for name, img in (('TUNED', TUNED), ('SBND2', SBND2)):
        L_init = model_35E88(img, f32(0.02))[0]          # 0x035E88 leaves 0.02 alone
        ok(same(L_init, f32(0.02)), 'init keeps [318C] = 0.02')
        out_init = model_init_34F28(img, L_init)[0]      # 0x034F28: L + [CC0B8]/[CC0BC], toward zero
        for loop_on in (True, False):
            print('%s, loop %s:' % (name, 'enabled' if loop_on else 'never enabled (byte [7448] = 0)'))
            emu = boot(img, loop_on)
            init(emu)
            show('after init 1', emu)
            ok(same(emu.read_f32(A_OUT), out_init), 'init 1 out')
            for t in range(3):
                emu.call(0x034EF4)
                ok(emu.read_u8(A_EN) == (1 if loop_on else 0), 'gate')
                out_mid = emu.read_f32(A_OUT)
                emu.executed.clear()             # the set is cumulative: clear it, or the check below is vacuous
                emu.call(0x03580C)
                ok(0x0359A4 in emu.executed, '0x0359A4 runs on this pass')
                ok(same(emu.read_f32(A_OUT), out_mid), '0x03580C does not write 7904')
                show('after pass %d' % (t + 1), emu)
                if name == 'TUNED':
                    ok(bits(emu.read_f32(0xFFFF318C)) == 0, 'TUNED: [318C] = 0 after the first pass')
                    if loop_on:
                        ok(bits(emu.read_f32(A_OUT)) == 0, 'TUNED loop on: 7904 = 0')
                    else:
                        ok(same(emu.read_f32(A_OUT), out_init),
                           'TUNED loop off: 7904 keeps its init value')
                else:
                    ok(same(emu.read_f32(0xFFFF318C), f32(0.02)), 'SBND2: [318C] kept')
            ok(not emu.uninit_reads, 'uninit %s' % sorted(map(hex, emu.uninit_reads)))
            init(emu)
            show('after init 2', emu)
            if name == 'TUNED':
                ok(bits(emu.read_f32(A_OUT)) == 0 and bits(emu.read_f32(A_L0)) == 0
                   and bits(emu.read_f32(0xFFFF7944)) == 0, 'TUNED: everything 0 after init 2')
            else:
                ok(same(emu.read_f32(A_OUT), out_init), 'SBND2 init 2')
    print('  TUNED: [318C] is 0.0 after the first 0x03580C pass that runs its body; from the')
    print('  next init on [790C], [7944] and all three writers of [7904] give 0.0. With the loop')
    print('  never enabled the init value of [7904] survives until that next init.')

    # the one exception to "every pass": the periodic pair entered WITHOUT init, byte [7986] = 0
    emu = boot(TUNED, True)
    for a, n in dict(CHAIN_STATE_INIT).items():
        emu.ram_u32(a, 0)
    emu.ram_u8(0xFFFF7986, 0)
    emu.ram_u16(0xFFFF794C, 0)
    emu.ram_f32(0xFFFF7944, 0.0)
    emu.ram_u8(0xFFFF7950, 0)
    got = []
    for t in range(2):
        emu.call(0x034EF4)
        emu.executed.clear()
        emu.call(0x03580C)
        got.append((0x0359A4 in emu.executed, emu.read_f32(0xFFFF318C)))
    ok(got[0][0] is False and same(got[0][1], f32(0.02)), 'no init, [7986] = 0: first pass skips, [318C] kept')
    ok(got[1][0] is True and bits(got[1][1]) == 0, 'second pass runs and stores 0.0')
    print('  TUNED, NO init, byte [7986] = 0: pass 1 skips 0x0359A4 ([318C] stays %+.4f), pass 2 runs it ([318C] = %.1f)'
          % (got[0][1], got[1][1]))


# =============================================================================
# I. how far can the stock module go?  (disputed claim C49)
# =============================================================================
def section_I():
    print('\n== I. stock module (both pairs restored): reach of [318C] and [7904] ' + '=' * 5)
    r = lambda a: romf(SBND2, a)             # noqa: E731
    wlo_max = max(max(T.read_table(SBND2, d)['values']) for d in (0x0ACF64, 0x0ACFB4, 0x0ACFDC))
    wlo_max = max(wlo_max, r(0x0CC108))
    whi_max = max(max(T.read_table(SBND2, d)['values']) for d in (0x0ACF78, 0x0ACFC8, 0x0ACFF0))
    print('  window widths from the tables: below L at most %.6f (incl. [CC108]), above L at most %.6f'
          % (wlo_max, whi_max))
    ok(abs(wlo_max - 0.07) < 1e-6 and abs(whi_max - 0.03) < 2e-5, 'window maxima')
    lim = r(0x0CC140)
    # I1: one enabled pass of the whole 0x034EF4 chain from random internal state, |L| <= 0.06
    rng = random.Random(77)
    lo_seen, hi_seen = 9.0, -9.0
    n = 0
    for i in range(150 if QUICK else 700):
        emu = new_emu(SBND2)
        externals(emu)
        L = rng.choice((0.0, lim, -lim, 0.038, -0.028, rng.uniform(-lim, lim)))
        emu.ram_u32(0xFFFF318C, E.f2b(L))
        emu.ram_f32(0xFFFF77C8, f32(1.0 + L))                 # d = 1.0 -> the gate is open
        emu.ram_f32(0xFFFF63CC, rng.uniform(-5, 90))
        emu.ram_f32(0xFFFF43FC, rng.uniform(0.0, 1.0))
        emu.ram_f32(0xFFFF65FC, rng.choice((5.0, 20.0, 50.0)))
        emu.ram_u8(0xFFFF984D, rng.choice((0, 0, 1, 2)))
        emu.ram_u8(0xFFFF782B, rng.choice((0, 0, 1)))
        emu.ram_u8(0xFFFFA3AE, rng.choice((0x00, 0x10)))
        emu.ram_u8(0xFFFF726C, rng.choice((0, 1)))
        for a in (A_CUR, A_PREV):
            emu.ram_f32(a, rng.uniform(0.0, 1.0))
        emu.ram_f32(A_TGT, rng.uniform(0.5, 0.8))
        emu.ram_f32(A_EF, rng.uniform(-0.6, 0.6))
        emu.ram_f32(A_INTEG, rng.uniform(-900, 900))
        emu.ram_f32(A_IT, rng.uniform(-0.5, 0.5))
        emu.ram_f32(0xFFFF78B0, rng.uniform(0, 76800))
        emu.ram_f32(A_L0, L)
        emu.ram_u16(A_CNT, rng.choice((0, 7)))
        emu.ram_u8(A_HYS, rng.choice((0, 1)))
        emu.ram_u8(0xFFFF7940, rng.choice((0, 1)))
        ok(emu.call(0x034EF4) == 'return', 'I1 return')
        ok(not emu.uninit_reads, 'I1 uninit %s' % sorted(map(hex, emu.uninit_reads)))
        ok(emu.read_u8(A_EN) == 1, 'I1 enabled')
        Lf, out = f32(L), emu.read_f32(A_OUT)
        wlo, whi = emu.read_f32(A_WLO), emu.read_f32(A_WHI)
        ok(0.0 <= wlo <= wlo_max + 1e-6 and 0.0 <= whi <= whi_max + 1e-6, 'I1 widths %r %r' % (wlo, whi))
        ok(fsub(Lf, wlo) <= out <= fadd(whi, Lf), 'I1: [7904] inside its window (%r)' % out)   # 0x0356C2..0x0356DA
        ok(same(out, emu.read_f32(A_TOT)) or same(out, emu.read_f32(A_LIMLO)) or same(out, emu.read_f32(A_LIMHI)),
           'I1: the +-0.5 clamp changed nothing')
        lo_seen, hi_seen = min(lo_seen, out), max(hi_seen, out)
        n += 1
    ok(lo_seen >= -(lim + wlo_max) - 1e-6 and hi_seen <= lim + whi_max + 1e-6, 'I1 range')
    print('  %d enabled passes of 0x034EF4 from random state with |L| <= %.2f: [7904] in [%.4f, %.4f];'
          % (n, lim, lo_seen, hi_seen))
    print('  bound by arithmetic: [-(%.2f+%.2f), +(%.2f+%.2f)]; the outer +-0.5 clamp never changed the value'
          % (lim, wlo_max, lim, whi_max))
    # I2: a short closed run of both periodic calls after init
    emu = new_emu(SBND2)
    externals(emu)
    externals_learn(emu)
    cold(emu, CHAIN_STATE_NOT_INIT)
    cold(emu, LEARN_STATE_NOT_INIT)
    emu.ram_u8(A_EN, 0)
    emu.ram_u32(0xFFFF318C, E.f2b(0.3))                      # a stored value init must pull in
    emu.call(0x0357D0)
    emu.call(0x034EC8)
    L0 = emu.read_f32(0xFFFF318C)
    ok(same(L0, model_35E88(SBND2, f32(0.3))[0]), 'init pulls 0.3 in to 0.028 + 0.01 (toward zero)')
    ok(abs(L0 - 0.038) < 1e-8, 'that is 0.038 to float32 precision')
    emu.ram_f32(0xFFFF7944, f32(L0 + 0.03))                  # seed the slow filter so the vote counter moves
    Lmin = Lmax = L0
    omin = omax = emu.read_f32(A_OUT)
    passes = 120 if QUICK else 420
    nsteps = 0
    for t in range(passes):
        emu.ram_f32(0xFFFF43FC, 0.80 if (t // 40) % 2 else 0.55)
        emu.ram_f32(0xFFFF77C8, f32(1.0 + emu.read_f32(0xFFFF318C)))
        before = emu.read_f32(0xFFFF318C)
        emu.call(0x034EF4)
        emu.call(0x03580C)
        Lc, oc = emu.read_f32(0xFFFF318C), emu.read_f32(A_OUT)
        nsteps += 0 if same(before, Lc) else 1
        ok(abs(f32(Lc - before)) <= 0.000501, 'I2: at most one 0.0005 step per pass')   # measurement
        Lmin, Lmax, omin, omax = min(Lmin, Lc), max(Lmax, Lc), min(omin, oc), max(omax, oc)
    ok(not emu.uninit_reads, 'I2 uninit %s' % sorted(map(hex, emu.uninit_reads)))
    ok(-lim <= Lmin and Lmax <= lim and omin >= -(lim + wlo_max) and omax <= lim + whi_max, 'I2 ranges')
    print('  init from a stored 0.3 (-> %.3f), [7944] then seeded 0.03 above it; %d passes of' % (L0, passes))
    print('  0x034EF4 + 0x03580C with [43FC] toggling 0.55 / 0.80 every 40 passes:')
    print('  [318C] in [%.4f, %.4f] (%d step(s)), [7904] in [%.4f, %.4f]' % (Lmin, Lmax, nsteps, omin, omax))


# =============================================================================
# J. where the regulated input 0xFFFF43FC comes from
# =============================================================================
def section_J():
    print('\n== J. 0x00C5FC: [0xFFFF43FC] = u16 [0xFFFF4050] * 5/65536 ' + '=' * 15)
    k = romf(TUNED, 0x00C658)
    ok(E.f2b(k) == 0x38A00000 and k == 5.0 / 65536.0, 'scale is exactly 5/65536')
    for w in (0x0000, 0x0001, 0x2400, 0x8000, 0x8F5C, 0xFFC0, 0xFFFF):
        emu = new_emu(TUNED)
        emu.ram_u16(0xFFFF4050, w)
        ok(emu.call(0x00C5FC) == 'return', 'C5FC return')
        ok(not emu.uninit_reads, 'C5FC uninit')
        ok(set(a & ~3 for a in emu.writes) == {0xFFFF43FC}, 'C5FC writes only [43FC]')
        got = emu.read_f32(0xFFFF43FC)
        ok(got == w * 5.0 / 65536.0, 'C5FC %04X -> %r' % (w, got))
        print('  word [4050] = 0x%04X -> [43FC] = %.6f' % (w, got))
    print('  the word is zero-extended (extu.w), so the range is 0 .. %.5f' % (0xFFFF * 5.0 / 65536.0))


def main():
    section_images()
    section_helpers()
    section_B()
    section_C()
    section_siblings()
    section_D()
    section_E()
    section_F()
    section_G()
    section_G4()
    section_H()
    section_I()
    section_J()
    print('\nALL CHECKS PASSED (%d assertions)' % CHECKS)
    return 0


if __name__ == '__main__':
    sys.exit(main())
