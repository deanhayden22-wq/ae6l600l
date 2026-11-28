#!/usr/bin/env python3
"""emu_helpers_interp.py -- emulation oracle for the table-interpolation internals
0x0BEACC..0x0BEDB7 (five 1-D float-fraction handlers, two 1-D integer-fraction
handlers, five 2-D handlers, the float and the integer axis search, and the 2-D
axis-search pair), written from a BLIND byte reading (2026-11-27) and repaired the
same day after an adversarial review (see REVIEW HISTORY in the trace file).

    python3 scripts/trace/emu_helpers_interp.py            # prints tables, exits 0
    python3 scripts/trace/emu_helpers_interp.py --quiet    # summary lines only

Companion of disassembly/analysis/helpers_interp_trace.txt.

WHAT IT DOES
  Part A  direct calls of each of the 15 entries with synthetic tables in emulator
          RAM.  Bytes after each synthetic table are left UNINITIALISED, so a read
          past the last element shows up in emu.uninit_reads and fails the run.
          A7 compares the EXACT set of registers each entry changes (fpul, mach,
          macl included) on each path.
  Part B  the public wrappers 0x0BE830 / 0x0BE8E4 / 0x0BE874 / 0x0BE8AC / 0x0BE88C /
          0x0BE8C4 / 0x0BE928 / 0x0BE944 on every REAL record this script can find
          mechanically, over inputs below, on, between and above the breakpoints.
  Part C  int8 / int16 (typecodes 0x0C / 0x10): no real record uses them, so the
          wrappers are driven with synthetic records in RAM.
  Part D  two existing claims put to the test (a "step lookup" reading of 0x0BEB6C; the
          cell width of records that reach a fixed-type wrapper with type byte 0x00).
  Part E  whole-ROM scans the trace cites: every long equal to one of the 15 entries,
          every bsr to one of them, the checksum-table record that explains the long
          at 0x0FFBC8, a structural search for any int8 / int16 typed record, and
          every load of FPSCR.
  Part R  ROUNDING.  The stock emulator rounds every float result TOWARD ZERO and
          rounds fmac once (scripts/sh2e_emu.py since 2026-11-27, corrections item
          106: reset loads FPSCR = 0x00040001 and the ROM's FPU self-test at
          0x058696 demands truncated results).  Here the same ROM bytes are executed
          under three other float arithmetics (nearest with fmac rounded once -- what
          the emulator did before item 106; nearest with the fmac product rounded
          first; toward zero with the product rounded first) and the results are
          compared.
  Part F  join with the definition XMLs (scripts/defs.py): storage type and X / Y axis
          of every definition-named record.           REPORT ONLY, never fails the run.
  Part G  two derived artefacts compared with the consumers found here
          (descriptor_map.txt, verification-status.json).  REPORT ONLY.

HOW REAL RECORDS ARE FOUND (find_records)
  Set-valued constant propagation over the whole ROM, seeded with "nothing known" at
  every function entry of disassembly/maps/function_census.json EXCEPT the census entries
  that the code before them falls into (census splits inside one function; 30 of them in
  the 5,146-entry census regenerated 2026-11-27, 33 in the 5,151-entry one before it --
  every count of call sites and records this script prints is the same with both; see
  continuations()):
    * registers: PC-relative literal loads, mov #imm, register copies, add #imm, mova;
    * stack slots addressed through r15 (the compiler parks the wrapper address there
      and reloads it: 01588E mov.l r2,@r15 ... 0158C4 mov.l @r15,r2);
    * both arms of a conditional select are kept (the value is a SET);
    * the two `braf` switch tables (0x012D9C, 0x03C194) are followed;
    * r0-r7 are forgotten after every call, r8-r14 are kept.
  The first version reset at EVERY census entry and so lost six call sites behind the
  split 0x01FE46 -> 0x020000 -> 0x020012 (r11 and a stack slot loaded before it).
  A second pass also follows a long stored to and reloaded from a GBR-relative RAM
  cell (0BBD3C mov.l r0,@(32,gbr) ... 0BBDC4 mov.l @(32,gbr),r0), ASSUMING the callees
  in between do not rewrite the cell.  Its extra records are reported separately.
  A candidate that is not structurally a record is dropped by valid() -- none is.
  Completeness of the CALL SITES is checked by a MAY-hold pass (MayFlow: union at joins,
  an unknown path contributes nothing, values restricted to the eight wrapper addresses),
  which does not depend on where the census puts entries: every jsr/jmp at which some
  path holds a wrapper address must be counted.  It is not a proof for code the census
  does not reach, or for a wrapper address that passes through RAM.
  Still NOT found: records whose pointer comes out of a ROM pointer table or a
  structure field (27 call sites; the non-quiet run lists them).

TWO KINDS OF CHECK, kept apart on purpose
  MODEL     a Python transcription of the byte reading, compared BIT-EXACTLY with
            the emulator running the ROM bytes under the same float arithmetic.  It
            proves the reading describes what the code does.
  TEXTBOOK  statements that do not depend on the transcription: at a breakpoint
            the result is the stored cell; below the first / above the last
            breakpoint the result is the first / last cell (clamp, never
            extrapolation); the 2-D cell for (index on the +4 axis, index on the +8
            axis) is data[i8 * count0 + i4] and NOT data[i4 * count1 + i8].

  The MODEL computes every float operation on exact rationals (fractions.Fraction) and
  rounds it toward zero with this script's own round_bits(); the emulator rounds with
  sh2e_emu.rz_bits().  The two roundings are separate code, so the bit-exact MODEL
  checks also cross-check them.  fmac is modelled fused (f0*fm + fn exact, one rounding),
  as the emulator does.

KNOWN LIMIT  "bit-exact" means exact against the emulator's arithmetic.  The rounding
DIRECTION is the chip's (item 106).  NOT settled: whether the chip's fmac rounds the
product before the add (the ROM self-test passes either way), and whether the
FPSCR = 0 that the self-test itself writes at 0x05873E (and does not restore) is ever
in force when these routines run.  Part R measures how much each alternative would
matter: interior float results move in the last few bits and the integer results of
the four ftrc wrappers move by one count at some inputs.  Clamp, breakpoint, storage
order and signedness do not depend on it.
"""
import collections
import json
import math
import os
import re
import sys
from fractions import Fraction as Fr

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, 'scripts'))
import sh2e_emu as E  # noqa: E402

BIN = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
ROM = open(BIN, 'rb').read()
CENSUS = os.path.join(REPO, 'disassembly', 'maps', 'function_census.json')
QUIET = '--quiet' in sys.argv
M32 = 0xFFFFFFFF

# entries under test ---------------------------------------------------------
F1 = {0x0BEACC: 'f32', 0x0BEB20: 'u8', 0x0BEB6C: 'u16', 0x0BEAE4: 'i8', 0x0BEB00: 'i16'}
I1 = {0x0BEB40: 'u8', 0x0BEB90: 'u16'}
F2 = {0x0BEBC0: 'f32', 0x0BEC4C: 'u8', 0x0BEC78: 'u16', 0x0BEBF0: 'i8', 0x0BEC1C: 'i16'}
SEARCH_F, SEARCH_I, SEARCH_2D = 0x0BECA8, 0x0BECDC, 0x0BED98
WIDTH = {'f32': 4, 'u8': 1, 'u16': 2, 'i8': 1, 'i16': 2}
TC_NAME = {0x00: 'f32', 0x04: 'u8', 0x08: 'u16', 0x0C: 'i8', 0x10: 'i16'}
W_1D, W_2D = 0x0BE830, 0x0BE8E4
W_1D_U8, W_1D_U16 = 0x0BE874, 0x0BE8AC
W_1DI_U8, W_1DI_U16 = 0x0BE88C, 0x0BE8C4
W_2D_U8, W_2D_U16 = 0x0BE928, 0x0BE944
WRAPPERS = (W_1D, W_2D, W_1D_U8, W_1D_U16, W_1DI_U8, W_1DI_U16, W_2D_U8, W_2D_U16)
FIXED = {W_1D_U8: 'u8', W_1D_U16: 'u16', W_1DI_U8: 'u8', W_1DI_U16: 'u16', W_2D_U8: 'u8', W_2D_U16: 'u16'}
TWO_D = (W_2D, W_2D_U8, W_2D_U16)

emu = E.Emu(ROM)
SYN = {}                       # python-side mirror of everything written to RAM
checks = {'model': 0, 'textbook': 0}
TOTAL = [0, 0]                 # instructions emulated, calls made


def say(*a):
    if not QUIET:
        print(*a)


# ------------------------------------------------------------------ memory
def rd(a, n):
    """Model-side read: ROM bytes, or the mirror of synthetic RAM. Never the emulator."""
    if a + n <= 0x100000:
        return int.from_bytes(ROM[a:a + n], 'big')
    return int.from_bytes(bytes(SYN[a + i] for i in range(n)), 'big')


def sx(v, bits):
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


def f32(x):
    return E.b2f(E.f2b(x))


def rf(a):
    return E.b2f(rd(a, 4))


def poke(a, n, v):
    emu.write(a, n, v & ((1 << (8 * n)) - 1))
    for i, b in enumerate((v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big')):
        SYN[a + i] = b


def poke_f(a, f):
    poke(a, 4, E.f2b(f))


def cell(kind, a):
    if kind == 'f32':
        return rf(a)
    if kind == 'u8':
        return rd(a, 1)
    if kind == 'u16':
        return rd(a, 2)
    if kind == 'i8':
        return sx(rd(a, 1), 8)
    if kind == 'i16':
        return sx(rd(a, 2), 16)
    raise ValueError(kind)


def nxt(f, up):
    """Adjacent float32."""
    b = E.f2b(f)
    if f == 0.0:
        return E.b2f(0x00800000 if up else 0x80800000)
    if (f > 0) == up:
        b += 1
    else:
        b -= 1
    return E.b2f(b)


# ------------------------------------------------------------------ float arithmetic variants
class Dbl:
    """Python float arithmetic: compute in double, round the RESULT to float32 to NEAREST;
    fmac rounded once.  This is what scripts/sh2e_emu.py did BEFORE corrections item 106
    (2026-11-27).  It is not the chip's arithmetic; it is kept only as an implementation of
    round-to-nearest that is independent of round_bits() (Part R, R0), and for the
    non-finite cases Exact passes through."""
    name = 'nearest, fmac rounded once [python double arithmetic]'

    @staticmethod
    def add(a, b):
        return f32(a + b)

    @staticmethod
    def sub(a, b):
        return f32(a - b)

    @staticmethod
    def mul(a, b):
        return f32(a * b)

    @staticmethod
    def div(a, b):
        if b == 0.0:
            return math.nan if a == 0 else math.copysign(math.inf, a) * math.copysign(1, b)
        return f32(a / b)

    @staticmethod
    def mac(f0, fm, fn):
        return f32(f0 * fm + fn)

    @staticmethod
    def i2f(i):
        return f32(float(i))


def round_bits(q, toward_zero):
    """Exact rational -> float32 bits, rounded toward zero or to nearest-even.  A result
    below the normal range is flushed to zero, as E.f2b does."""
    if q == 0:
        return 0
    sign = 0x80000000 if q < 0 else 0
    a = -q if q < 0 else q
    e = a.numerator.bit_length() - a.denominator.bit_length()
    if a < Fr(2) ** e:
        e -= 1                                   # 2^e <= a < 2^(e+1)
    s = a / Fr(2) ** (e - 23)                    # 2^23 <= s < 2^24
    m = s.numerator // s.denominator
    if not toward_zero:
        rem = s - m
        if rem > Fr(1, 2) or (rem == Fr(1, 2) and m & 1):
            m += 1
            if m == 1 << 24:
                m, e = 1 << 23, e + 1
    if e > 127:
        return sign | (0x7F7FFFFF if toward_zero else 0x7F800000)
    if e < -126:
        return sign
    return sign | ((e + 127) << 23) | (m - (1 << 23))


class Exact:
    """Float32 arithmetic on exact rationals with an explicit rounding direction, and an
    fmac that rounds once (fused) or rounds the product first."""

    def __init__(self, toward_zero, fused):
        self.tz, self.fused = toward_zero, fused
        self.name = (('toward zero' if toward_zero else 'nearest') + ', fmac '
                     + ('rounded once' if fused else 'product rounded first'))

    def _r(self, q, ieee):
        """q is exact; `ieee` (the double result) only supplies the sign of an exact zero."""
        if q == 0:
            return ieee if ieee == 0 else 0.0
        return E.b2f(round_bits(q, self.tz))

    @staticmethod
    def _fin(*xs):
        return all(x == x and x not in (math.inf, -math.inf) for x in xs)

    def add(self, a, b):
        return self._r(Fr(a) + Fr(b), a + b) if self._fin(a, b) else Dbl.add(a, b)

    def sub(self, a, b):
        return self._r(Fr(a) - Fr(b), a - b) if self._fin(a, b) else Dbl.sub(a, b)

    def mul(self, a, b):
        return self._r(Fr(a) * Fr(b), a * b) if self._fin(a, b) else Dbl.mul(a, b)

    def div(self, a, b):
        if not self._fin(a, b) or b == 0.0:
            return Dbl.div(a, b)
        return self._r(Fr(a) / Fr(b), a / b)

    def mac(self, f0, fm, fn):
        if not self._fin(f0, fm, fn):
            return Dbl.mac(f0, fm, fn)
        p = Fr(f0) * Fr(fm)
        if not self.fused:
            p = Fr(self._r(p, f0 * fm))
        return self._r(p + Fr(fn), f0 * fm + fn)

    def i2f(self, i):
        return self._r(Fr(i), float(i))


DBL = Dbl()
RZ = Exact(True, True)         # the chip's arithmetic as the stock emulator models it (item 106)
AR = RZ                        # the arithmetic the MODEL uses; switched by with_ar()


def with_ar(ar, fn, *a):
    global AR
    old, AR = AR, ar
    try:
        return fn(*a)
    finally:
        AR = old


class EmuX(E.Emu):
    """The stock emulator (same decoder, same integer core, same cross-check against
    sh2e_disasm) with fadd / fsub / fmul / fdiv / fmac / float computed by `ar`."""

    def __init__(self, rom, ar):
        super().__init__(rom)
        self.ar = ar

    def _fpu(self, w, pc, R, n, m, d4):
        F, ar = self.FR, self.ar
        if d4 in (0x0, 0x1, 0x2, 0x3, 0xE):
            fn, fm = E.b2f(F[n]), E.b2f(F[m])
            if d4 == 0x0:
                F[n] = E.f2b(ar.add(fn, fm))
                return 'fadd'
            if d4 == 0x1:
                F[n] = E.f2b(ar.sub(fn, fm))
                return 'fsub'
            if d4 == 0x2:
                F[n] = E.f2b(ar.mul(fn, fm))
                return 'fmul'
            if d4 == 0x3:
                F[n] = E.f2b(ar.div(fn, fm))
                return 'fdiv'
            F[n] = E.f2b(ar.mac(E.b2f(F[0]), fm, fn))
            return 'fmac'
        if d4 == 0xD and m == 0x2:
            F[n] = E.f2b(ar.i2f(E.s32(self.fpul)))
            return 'float'
        return super()._fpu(w, pc, R, n, m, d4)


# ------------------------------------------------------------------ MODEL (the byte reading)
def m_search_f(n, ap, x):
    """0x0BECA8: r0=count, r1=axis (float32[]), fr0=x -> (index, fraction)."""
    last = rf(ap + 4 * (n - 1))
    if not (last > x):                    # 0BECAE fcmp/gt fr0,fr1 ; 0BECB0 bf/s
        return n - 1, 0.0
    i = n - 1
    while True:
        if i == 0:                        # 0BECB4 bt/s (T from tst r0,r0)
            return 0, 0.0
        i -= 1
        a = rf(ap + 4 * i)
        if not (a > x):                   # 0BECBA fcmp/gt fr0,fr1 ; 0BECBC bt/s loops while axis[i] > x
            break
    num = AR.sub(x, a)                    # 0BECC0 fsub fr1,fr0
    den = AR.sub(rf(ap + 4 * (i + 1)), a)  # 0BECC8 fsub fr1,fr2
    return i, AR.div(num, den)            # 0BECCA fdiv fr2,fr0


def m_search_i(n, ap, x):
    """0x0BECDC: r0=count, r1=axis (int32[]), r2=x (signed) -> (index, 0.32 fraction)."""
    x = sx(x, 32)
    if x >= sx(rd(ap + 4 * (n - 1), 4), 32):      # 0BECE2 cmp/ge r3,r2 ; bt/s
        return n - 1, 0
    i = n - 1
    while True:
        if i == 0:
            return 0, 0
        i -= 1
        a = sx(rd(ap + 4 * i, 4), 32)
        if not (a > x):                           # 0BECEE cmp/gt r2,r3 ; bt/s loops while axis[i] > x
            break
    num = (x - a) & M32
    den = (sx(rd(ap + 4 * (i + 1), 4), 32) - a) & M32
    return i, ((num << 32) // den) & M32          # div0u + 32 x (rotcl r1 ; div1 r3,r2) + rotcl r1


def m_cell_f(kind, a):
    """A cell as the float-fraction handlers load it: fmov.s, or integer load + float fpul."""
    return rf(a) if kind == 'f32' else AR.i2f(cell(kind, a))


def m_interp_f(kind, dp, idx, frac):
    """0x0BEACC/0BEB20/0BEB6C/0BEAE4/0BEB00: r0=index, r1=data, fr0=fraction -> fr2."""
    w = WIDTH[kind]
    d0 = m_cell_f(kind, dp + idx * w)
    if frac == 0.0:                                # fcmp/eq fr0,fr2 (fr2 = 0.0) ; bt/s rts
        return d0
    d1 = m_cell_f(kind, dp + (idx + 1) * w)
    return AR.mac(frac, AR.sub(d1, d0), d0)        # fsub fr2,fr1 ; fmac fr0,fr1,fr2


def m_interp_i(kind, dp, idx, q):
    """0x0BEB40/0BEB90: r0=index, r1=data, r2=0.32 fraction -> r0 (unsigned integer)."""
    w = WIDTH[kind]
    d0 = cell(kind, dp + idx * w)
    if q == 0:
        return d0
    d1 = cell(kind, dp + (idx + 1) * w)
    if d1 > d0:                                    # cmp/gt r0,r1 ; bf/s
        return d0 + (((d1 - d0) * q) >> 32)
    return d0 - (((d0 - d1) * q) >> 32)


def m_interp_2d(kind, dp, n0, ix, iy, fx, fy):
    """0x0BEBC0/0BEC4C/0BEC78/0BEBF0/0BEC1C:
    r0=count of the FIRST axis, r1=data, r2=index on first axis, r3=index on second
    axis, fr0=fraction on first axis, fr1=fraction on second axis -> fr2."""
    w = WIDTH[kind]
    row = dp + n0 * w * iy                          # muls.w r0,r3 ; add r3,r1
    v0 = m_interp_f(kind, row, ix, fx)
    if fy == 0.0:
        return v0
    v1 = m_interp_f(kind, row + n0 * w, ix, fx)
    return AR.mac(fy, AR.sub(v1, v0), v0)           # fsub fr4,fr2 ; fmac fr0,fr2,fr4


def m_w1d(desc, x):
    n = sx(rd(desc, 2), 16)
    tc = rd(desc + 2, 1)
    i, fr = m_search_f(n, rd(desc + 4, 4), x)
    raw = m_interp_f(TC_NAME[tc], rd(desc + 8, 4), i, fr)
    if tc == 0:
        return raw
    return AR.mac(rf(desc + 12), raw, rf(desc + 16))   # 0BE856 fmac fr0,fr2,fr1


def m_w2d(desc, x, y):
    n0, n1 = sx(rd(desc, 2), 16), sx(rd(desc + 2, 2), 16)
    tc = rd(desc + 16, 1)
    ix, fx = m_search_f(n0, rd(desc + 4, 4), x)
    iy, fy = m_search_f(n1, rd(desc + 8, 4), y)
    raw = m_interp_2d(TC_NAME[tc], rd(desc + 12, 4), n0, ix, iy, fx, fy)
    if tc == 0:
        return raw
    return AR.mac(rf(desc + 20), raw, rf(desc + 24))   # 0BE908 fmac fr0,fr2,fr1


def m_trunc(f, mask):
    if f != f:
        v = 0x80000000
    elif f >= 2 ** 31:
        v = 0x7FFFFFFF
    elif f < -2 ** 31:
        v = 0x80000000
    else:
        v = int(f) & M32
    return v & mask


def m_fixed_1d(d, kind, mask, x):
    """0x0BE874 / 0x0BE8AC: search, handler, ftrc, mask."""
    i, fr = m_search_f(rd(d, 2), rd(d + 4, 4), x)
    return m_trunc(m_interp_f(kind, rd(d + 8, 4), i, fr), mask)


def m_fixed_2d(d, kind, mask, x, y):
    """0x0BE928 / 0x0BE944."""
    n0, n1 = rd(d, 2), rd(d + 2, 2)
    ix, fx = m_search_f(n0, rd(d + 4, 4), x)
    iy, fy = m_search_f(n1, rd(d + 8, 4), y)
    return m_trunc(m_interp_2d(kind, rd(d + 12, 4), n0, ix, iy, fx, fy), mask)


# ------------------------------------------------------------------ emulator helpers
def run(entry, regs=None, fregs=None, em=None, allow_uninit=False):
    em = em or emu
    em.uninit_reads.clear()
    em.steps = 0                          # the emulator's step limit is cumulative
    r = em.call(entry, regs=regs, fregs=fregs, max_steps=100_000)
    TOTAL[0] += em.steps
    TOTAL[1] += 1
    assert r == 'return', (hex(entry), r)
    if not allow_uninit:
        assert not em.uninit_reads, ('read of uninitialised RAM', hex(entry),
                                     sorted(hex(a) for a in em.uninit_reads))


def fbits(n):
    return emu.FR[n]


def same_f(bits, model):
    """Bit-exact, except any-NaN == any-NaN."""
    m = E.f2b(model)
    if model != model:
        f = E.b2f(bits)
        return f != f
    return bits == m


def ok(kind, cond, *ctx):
    checks[kind] += 1
    if not cond:
        raise AssertionError((kind,) + ctx)


# ================================================================== PART 0: dispatch tables
def part0():
    say('=== PART 0  dispatch tables read from ROM ===')
    want1 = {0x00: 0x0BEACC, 0x04: 0x0BEB20, 0x08: 0x0BEB6C, 0x0C: 0x0BEAE4, 0x10: 0x0BEB00}
    want2 = {0x00: 0x0BEBC0, 0x04: 0x0BEC4C, 0x08: 0x0BEC78, 0x0C: 0x0BEBF0, 0x10: 0x0BEC1C}
    for tc in sorted(want1):
        h1, h2 = rd(0x0BE860 + tc, 4), rd(0x0BE914 + tc, 4)
        say(f'  typecode 0x{tc:02X}: 1-D @0x{0x0BE860 + tc:06X} -> 0x{h1:06X}   '
            f'2-D @0x{0x0BE914 + tc:06X} -> 0x{h2:06X}')
        ok('textbook', h1 == want1[tc] and h2 == want2[tc], tc)
    # the word after each table is a function prologue, so each has exactly 5 entries
    ok('textbook', rd(0x0BE874, 2) == 0x4F22 and rd(0x0BE928, 2) == 0x4F12)


# ================================================================== PART A: direct calls
RAM_AXIS, RAM_DATA, RAM_DESC = 0xFFFF1000, 0xFFFF1400, 0xFFFF1800


def fresh():
    """Forget every synthetic byte: later reads of them count as uninitialised."""
    for a in list(SYN):
        emu.init[a - E.RAM_LO] = 0
    SYN.clear()


def put_axis_f(vals, base=RAM_AXIS):
    for i, v in enumerate(vals):
        poke_f(base + 4 * i, v)
    return base


def put_axis_i(vals, base=RAM_AXIS):
    for i, v in enumerate(vals):
        poke(base + 4 * i, 4, v)
    return base


def put_data(kind, vals, base=RAM_DATA):
    w = WIDTH[kind]
    for i, v in enumerate(vals):
        if kind == 'f32':
            poke_f(base + 4 * i, v)
        else:
            poke(base + w * i, w, v)
    return base


def a_search_f():
    say('\n=== PART A1  0x0BECA8 float axis search: r0=count r1=axis fr0=x -> r0=index fr0=fraction ===')
    cases = [
        ('ascending 4', [10.0, 20.0, 40.0, 80.0],
         [-1e30, 0.0, nxt(10.0, False), 10.0, nxt(10.0, True), 15.0, 20.0, 30.0, 39.999, 40.0, 70.0,
          nxt(80.0, False), 80.0, nxt(80.0, True), 1e30, math.inf, -math.inf, math.nan]),
        ('single element', [5.0], [4.0, 5.0, 6.0]),
        ('two elements', [-3.0, 3.0], [-4.0, -3.0, 0.0, 3.0, 4.0]),
        ('duplicate breakpoint', [0.0, 10.0, 10.0, 20.0], [5.0, 10.0, 15.0]),
        ('negative axis', [-40.0, -10.0, 0.0, 25.0], [-50.0, -40.0, -25.0, -10.0, -5.0, 0.0, 12.5, 25.0, 26.0]),
    ]
    for name, axis, xs in cases:
        fresh()
        ap = put_axis_f(axis)
        say(f'  axis {name}: {axis}')
        for x in xs:
            run(SEARCH_F, regs={0: len(axis), 1: ap}, fregs={0: x})
            idx, fr = emu.R[0], emu.fr(0)
            mi, mf = m_search_f(len(axis), ap, f32(x))
            ok('model', idx == mi and same_f(fbits(0), mf), name, x, idx, fr, mi, mf)
            say(f'    x={x!r:>24} -> index {idx}  fraction {fr!r}')
            # textbook
            n = len(axis)
            if x != x:
                ok('textbook', idx == n - 1 and fr == 0.0, 'nan', name)
            elif x < axis[0]:
                ok('textbook', idx == 0 and fr == 0.0, 'below', name, x)
            elif x >= axis[-1]:
                ok('textbook', idx == n - 1 and fr == 0.0, 'above', name, x)
            else:
                ok('textbook', 0 <= idx < n - 1 and 0.0 <= fr < 1.0, 'inside', name, x)
                ok('textbook', axis[idx] <= x < axis[idx + 1], 'bracket', name, x)
                ok('textbook', abs(axis[idx] + fr * (axis[idx + 1] - axis[idx]) - x)
                   <= 1e-5 * max(1.0, abs(x)), 'reconstruct', name, x)
    say('  (no read past the last axis element in any case: emu.uninit_reads stayed empty)')
    # the fraction can ROUND to exactly 1.0 when the span dwarfs the gap to the next breakpoint
    fresh()
    ap = put_axis_f([-1e8, 1.0])
    x = nxt(1.0, False)
    run(SEARCH_F, regs={0: 2, 1: ap}, fregs={0: x})
    say(f'  axis [-1e8, 1.0], x={x!r} (one float below 1.0) -> index {emu.R[0]} fraction {emu.fr(0)!r} '
        f'(x-axis[0] and the span both round to 1e8)')
    ok('model', (emu.R[0], emu.fr(0)) == m_search_f(2, ap, x), 'fraction 1.0')
    ok('textbook', emu.R[0] == 0 and emu.fr(0) == 1.0, 'fraction 1.0')
    for ar in (Exact(True, True), Exact(False, True)):      # the same holds when rounding to nearest
        ok('textbook', with_ar(ar, m_search_f, 2, ap, x) == (0, 1.0), 'fraction 1.0', ar.name)
    # count 0 is NOT guarded: the first load is axis[-1]
    fresh()
    poke_f(RAM_AXIS, 0.0)                              # the long BEFORE the "axis"
    run(SEARCH_F, regs={0: 0, 1: RAM_AXIS + 4}, fregs={0: 1.0})
    say(f'  count 0, x=1.0, long before the axis = 0.0 -> index 0x{emu.R[0]:08X} fraction {emu.fr(0)!r} '
        f'(axis[-1] was read; no guard)')
    ok('textbook', emu.R[0] == 0x3FFFFFFF and emu.fr(0) == 0.0, 'count 0')
    # ... and when axis[-1] > x the scan does NOT stop there: it keeps stepping DOWN memory until
    # it meets a long that is not greater than x (0BECB2 tst r0,r0 is false for offset 0xFFFFFFFC)
    fresh()
    for k, v in enumerate((1.0, 3.0, 7.0)):            # the three longs BEFORE the "axis"
        poke_f(RAM_AXIS + 4 * k, v)
    run(SEARCH_F, regs={0: 0, 1: RAM_AXIS + 12}, fregs={0: 5.0})
    say(f'  count 0, longs before the axis = 1.0, 3.0, 7.0, x=5.0 -> index 0x{emu.R[0]:08X} fraction '
        f'{emu.fr(0)!r}  (7.0 > x, so axis[-2] = 3.0 was read too: fraction (5-3)/(7-3))')
    ok('textbook', emu.R[0] == 0x3FFFFFFE and emu.fr(0) == 0.5, 'count 0 runaway')
    run(SEARCH_F, regs={0: 0, 1: RAM_AXIS + 12}, fregs={0: 0.5}, allow_uninit=True)
    say(f'  same, x=0.5 -> index 0x{emu.R[0]:08X}; uninitialised reads at '
        f'{sorted(hex(a) for a in emu.uninit_reads)} (it walked past all three)')
    ok('textbook', emu.R[0] == 0x3FFFFFFC and (RAM_AXIS - 4) in emu.uninit_reads, 'count 0 runaway 2')


def a_search_i():
    say('\n=== PART A2  0x0BECDC integer axis search: r0=count r1=axis(int32[]) r2=x -> r0=index r1=0.32 fraction ===')
    cases = [
        ('ascending 4', [10, 20, 40, 80], [-2 ** 31, -5, 9, 10, 11, 15, 19, 20, 30, 39, 40, 79, 80, 81, 2 ** 31 - 1]),
        ('single element', [5], [4, 5, 6]),
        ('signed axis', [-100, -10, 0, 1000], [-101, -100, -55, -10, -1, 0, 1, 500, 999, 1000, 1001]),
        ('wide', [-0x70000000, 0x70000000], [-0x70000001, -0x70000000, -1, 0, 1, 0x6FFFFFFF, 0x70000000]),
        ('axis above 0x7FFFFFFF as unsigned', [0, 0x40000000, 0x7FFFFFFF], [0x3FFFFFFF, 0x40000000, 0x7FFFFFFE]),
    ]
    for name, axis, xs in cases:
        fresh()
        ap = put_axis_i(axis)
        say(f'  axis {name}: {axis}')
        for x in xs:
            run(SEARCH_I, regs={0: len(axis), 1: ap, 2: x})
            idx, q = emu.R[0], emu.R[1]
            mi, mq = m_search_i(len(axis), ap, x)
            ok('model', (idx, q) == (mi, mq), name, x, idx, hex(q), mi, hex(mq))
            say(f'    x={x:>12} -> index {idx}  fraction 0x{q:08X} (= {q / 2 ** 32:.9f})')
            n = len(axis)
            if x < axis[0]:
                ok('textbook', idx == 0 and q == 0, 'below', name, x)
            elif x >= axis[-1]:
                ok('textbook', idx == n - 1 and q == 0, 'above', name, x)
            else:
                ok('textbook', axis[idx] <= x < axis[idx + 1], 'bracket', name, x)
                ok('textbook', q == ((x - axis[idx]) << 32) // (axis[idx + 1] - axis[idx]), 'floor', name, x)
    # x is compared SIGNED: 0x80000000 is below an axis that starts at 0
    fresh()
    ap = put_axis_i([0, 100])
    run(SEARCH_I, regs={0: 2, 1: ap, 2: 0x80000000})
    ok('textbook', (emu.R[0], emu.R[1]) == (0, 0), 'signed compare')
    say('  x=0x80000000 on axis [0,100] -> index 0 fraction 0 (compared signed; unsigned it would be above the axis)')
    # count 0: same absence of a guard as 0x0BECA8, same walk down memory
    fresh()
    for k, v in enumerate((1, 3, 7)):
        poke(RAM_AXIS + 4 * k, 4, v)
    run(SEARCH_I, regs={0: 0, 1: RAM_AXIS + 12, 2: 9})
    ok('textbook', (emu.R[0], emu.R[1]) == (0x3FFFFFFF, 0), 'count 0 clamp')
    run(SEARCH_I, regs={0: 0, 1: RAM_AXIS + 12, 2: 5})
    ok('textbook', (emu.R[0], emu.R[1]) == (0x3FFFFFFE, 0x80000000), 'count 0 runaway')
    say(f'  count 0, longs before the axis = 1, 3, 7: x=9 -> index 0x3FFFFFFF fraction 0 ; '
        f'x=5 -> index 0x{emu.R[0]:08X} fraction 0x{emu.R[1]:08X} (axis[-2] was read)')


def a_interp_f():
    say('\n=== PART A3  1-D float-fraction handlers: r0=index r1=data fr0=fraction -> fr2 ===')
    sets = {
        'f32': [1.5, -2.25, 100.0, 100.0, -1e6],
        'u8': [0x00, 0x7F, 0x80, 0xFF, 0x10],
        'i8': [0x00, 0x7F, 0x80, 0xFF, 0x10],
        'u16': [0x0000, 0x7FFF, 0x8000, 0xFFFF, 0x0100],
        'i16': [0x0000, 0x7FFF, 0x8000, 0xFFFF, 0x0100],
    }
    for entry, kind in sorted(F1.items()):
        fresh()
        vals = sets[kind]
        dp = put_data(kind, vals)
        shown = [cell(kind, dp + i * WIDTH[kind]) for i in range(len(vals))]
        say(f'  0x{entry:06X} ({kind}) data as the handler reads it: {shown}')
        for idx in range(len(vals)):
            for fr in (0.0, -0.0, 0.25, 0.5, nxt(1.0, False)):
                if idx == len(vals) - 1 and fr != 0.0:
                    continue                           # would read past the table
                run(entry, regs={0: idx, 1: dp}, fregs={0: fr})
                got = emu.fr(2)
                ok('model', same_f(fbits(2), m_interp_f(kind, dp, idx, f32(fr))), hex(entry), idx, fr, got)
                if fr == 0.0:
                    ok('textbook', got == float(shown[idx]), 'cell', hex(entry), idx)
                else:
                    lo, hi = sorted((float(shown[idx]), float(shown[idx + 1])))
                    ok('textbook', lo - 1e-3 * max(1, abs(lo)) <= got <= hi + 1e-3 * max(1, abs(hi)),
                       'between', hex(entry), idx, fr, got)
                    exp = shown[idx] + fr * (shown[idx + 1] - shown[idx])
                    ok('textbook', abs(got - exp) <= 1e-5 * max(1.0, abs(exp), abs(shown[idx])),
                       'linear', hex(entry), idx, fr, got, exp)
                if fr in (0.0, 0.5):
                    say(f'    index {idx} fraction {fr} -> {got!r}')
        # signedness, stated directly
        if kind in ('u8', 'i8'):
            run(entry, regs={0: 2, 1: dp}, fregs={0: 0.0})
            ok('textbook', emu.fr(2) == (128.0 if kind == 'u8' else -128.0), 'sign', kind)
        if kind in ('u16', 'i16'):
            run(entry, regs={0: 2, 1: dp}, fregs={0: 0.0})
            ok('textbook', emu.fr(2) == (32768.0 if kind == 'u16' else -32768.0), 'sign', kind)
    say('  (fraction 0 at the LAST index never reads the element after it: uninit_reads empty)')


def a_interp_i():
    say('\n=== PART A4  1-D integer-fraction handlers: r0=index r1=data r2=0.32 fraction -> r0 ===')
    sets = {'u8': [10, 200, 200, 3, 0xFF, 0x80], 'u16': [1000, 60000, 60000, 7, 0xFFFF, 0x8000]}
    for entry, kind in sorted(I1.items()):
        fresh()
        vals = sets[kind]
        dp = put_data(kind, vals)
        say(f'  0x{entry:06X} ({kind}) data: {vals}')
        for idx in range(len(vals)):
            for q in (0, 1, 0x40000000, 0x80000000, 0xC0000000, 0xFFFFFFFF):
                if idx == len(vals) - 1 and q:
                    continue
                run(entry, regs={0: idx, 1: dp, 2: q})
                got = emu.R[0]
                ok('model', got == m_interp_i(kind, dp, idx, q), hex(entry), idx, hex(q), got)
                if q == 0:
                    ok('textbook', got == vals[idx], 'cell')
                else:
                    d0, d1 = vals[idx], vals[idx + 1]
                    # truncation is toward the LEFT cell d0 in both directions
                    exp = d0 + ((d1 - d0) * q >> 32) if d1 > d0 else d0 - ((d0 - d1) * q >> 32)
                    ok('textbook', got == exp and min(d0, d1) <= got <= max(d0, d1), 'trunc', idx, hex(q))
                if q in (0, 0x80000000, 0xFFFFFFFF):
                    say(f'    index {idx} fraction 0x{q:08X} -> {got}')
    # a descending pair at fraction 0xFFFFFFFF stays one count short of the right cell... or not?
    fresh()
    dp = put_data('u8', [200, 3])
    run(0x0BEB40, regs={0: 0, 1: dp, 2: 0xFFFFFFFF})
    say(f'  u8 [200,3] fraction 0xFFFFFFFF -> {emu.R[0]}  (200 - floor(197 * 0.99999999977) = 200 - 196)')
    ok('textbook', emu.R[0] == 4, 'descending rounding')
    fresh()
    dp = put_data('u8', [3, 200])
    run(0x0BEB40, regs={0: 0, 1: dp, 2: 0xFFFFFFFF})
    say(f'  u8 [3,200] fraction 0xFFFFFFFF -> {emu.R[0]}  (3 + floor(197 * 0.99999999977) = 3 + 196)')
    ok('textbook', emu.R[0] == 199, 'ascending rounding')


def a_interp_2d():
    say('\n=== PART A5  2-D handlers: r0=count of first axis, r1=data, r2=index on first axis, '
        'r3=index on second axis, fr0/fr1=fractions -> fr2 ===')
    n0, n1 = 3, 4                                  # deliberately not square
    for entry, kind in sorted(F2.items()):
        fresh()
        if kind == 'f32':
            vals = [100.0 * j + i + 0.5 for j in range(n1) for i in range(n0)]
        elif kind in ('u8', 'i8'):
            vals = [(40 * j + 7 * i + (0x80 if kind == 'i8' and j == 3 else 0)) & 0xFF
                    for j in range(n1) for i in range(n0)]
        else:
            vals = [(4000 * j + 7 * i + (0x8000 if kind == 'i16' and j == 3 else 0)) & 0xFFFF
                    for j in range(n1) for i in range(n0)]
        dp = put_data(kind, vals)
        w = WIDTH[kind]
        c = [float(cell(kind, dp + k * w)) for k in range(n0 * n1)]
        say(f'  0x{entry:06X} ({kind}) 3 x 4 grid, linear memory order: {c}')
        for iy in range(n1):
            for ix in range(n0):
                for fx, fy in ((0.0, 0.0), (0.5, 0.0), (0.0, 0.5), (0.5, 0.5), (0.25, 0.75)):
                    if (ix == n0 - 1 and fx) or (iy == n1 - 1 and fy):
                        continue
                    run(entry, regs={0: n0, 1: dp, 2: ix, 3: iy}, fregs={0: fx, 1: fy})
                    got = emu.fr(2)
                    ok('model', same_f(fbits(2), m_interp_2d(kind, dp, n0, ix, iy, fx, fy)),
                       hex(entry), ix, iy, fx, fy, got)
                    a = c[iy * n0 + ix]
                    if fx == 0.0 and fy == 0.0:
                        ok('textbook', got == a, 'cell order', hex(entry), ix, iy, got, a)
                        ok('textbook', ix * n1 + iy == iy * n0 + ix or got != c[ix * n1 + iy],
                           'other order excluded', ix, iy)
                    elif fy == 0.0:
                        ok('textbook', got == (a + c[iy * n0 + ix + 1]) / 2, 'first-axis neighbour', ix, iy)
                    elif fx == 0.0:
                        ok('textbook', got == (a + c[(iy + 1) * n0 + ix]) / 2, 'second-axis neighbour', ix, iy)
        run(entry, regs={0: n0, 1: dp, 2: 1, 3: 2}, fregs={0: 0.0, 1: 0.0})
        say(f'    index(first)=1 index(second)=2 fractions 0 -> {emu.fr(2)!r} = linear element 2*3+1 = 7')
        run(entry, regs={0: n0, 1: dp, 2: 2, 3: 3}, fregs={0: 0.0, 1: 0.0})
        say(f'    last corner (2,3) fractions 0 -> {emu.fr(2)!r} = element 11, nothing read after it')


def a_search_2d():
    say('\n=== PART A6  0x0BED98: r4=record fr4=first input fr5=second input -> '
        'r2,fr0 = index,fraction on the +4 axis ; r3,fr1 = index,fraction on the +8 axis ===')
    fresh()
    ax0 = put_axis_f([0.0, 10.0, 20.0], RAM_AXIS)
    ax1 = put_axis_f([100.0, 200.0, 400.0, 800.0], RAM_AXIS + 0x40)
    poke(RAM_DESC, 2, 3)
    poke(RAM_DESC + 2, 2, 4)
    poke(RAM_DESC + 4, 4, ax0)
    poke(RAM_DESC + 8, 4, ax1)
    for x, y in ((-5.0, 50.0), (0.0, 100.0), (5.0, 300.0), (15.0, 150.0), (20.0, 800.0), (25.0, 900.0), (12.5, 799.0)):
        run(SEARCH_2D, regs={4: RAM_DESC}, fregs={4: x, 5: y})
        ix, fx = m_search_f(3, ax0, x)
        iy, fy = m_search_f(4, ax1, y)
        ok('model', emu.R[2] == ix and emu.R[3] == iy and same_f(fbits(0), fx) and same_f(fbits(1), fy)
           and same_f(fbits(3), fx), x, y)
        say(f'    fr4={x:>6} fr5={y:>6} -> r2={emu.R[2]} fr0={emu.fr(0)!r:<22} r3={emu.R[3]} fr1={emu.fr(1)!r}')
        ok('textbook', emu.R[4] == RAM_DESC, 'r4 preserved')


def clobbers():
    """EXACT sets, per path.  A subset test cannot fail on a missing clobber, so this one compares
    with ==.  Watched: r0-r14, fr0-fr15, mach, macl, fpul.  Not watched: T, pr, r15."""
    say('\n=== PART A7  registers changed by each entry -- exact sets, per path '
        '(sentinels in everything that is not an input; fpul / mach / macl watched) ===')
    FPUL0 = 0x5EED5EED

    def probe(entry, regs, fregs=()):
        fresh_regs = {k: (0xA5A50000 + k) for k in range(15)}
        fresh_regs.update(regs)
        ff = {k: 1000.0 + k for k in range(16)}
        ff.update(dict(fregs))
        emu.mach, emu.macl, emu.fpul = 0x11111111, 0x22222222, FPUL0
        run(entry, regs=fresh_regs, fregs=ff)
        ch = {f'r{k}' for k in range(15) if emu.R[k] != (fresh_regs[k] & M32)}
        ch |= {f'fr{k}' for k in range(16) if emu.FR[k] != E.f2b(ff[k])}
        if emu.mach != 0x11111111:
            ch.add('mach')
        if emu.macl != 0x22222222:
            ch.add('macl')
        if emu.fpul != FPUL0:
            ch.add('fpul')
        return ch

    fresh()
    ap = put_axis_f([10.0, 20.0, 40.0, 80.0])
    api = put_axis_i([10, 20, 40, 80], RAM_AXIS + 0x80)
    data = {
        'f32': put_data('f32', [1.5, 2.5, 4.5, 8.5, 16.5, 32.5, 64.5, 128.5, 3.5, 5.5, 7.5, 9.5], RAM_DATA),
        'u8': put_data('u8', [10, 200, 30, 250, 50, 60, 70, 80, 90, 100, 110, 120], RAM_DATA + 0x100),
        'u16': put_data('u16', [1000, 60000, 3000, 65000, 5000, 6000, 7000, 8000, 9000, 10000, 11000, 12000],
                        RAM_DATA + 0x200),
    }
    data['i8'], data['i16'] = data['u8'], data['u16']
    poke(RAM_DESC, 2, 4)
    poke(RAM_DESC + 2, 2, 4)
    poke(RAM_DESC + 4, 4, ap)
    poke(RAM_DESC + 8, 4, ap)
    rows = [
        (SEARCH_F, 'interior', probe(SEARCH_F, {0: 4, 1: ap}, {0: 30.0}), 'r0 fr0 fr1 fr2'),
        (SEARCH_F, 'clamp high', probe(SEARCH_F, {0: 4, 1: ap}, {0: 100.0}), 'r0 fr0 fr1'),
        (SEARCH_F, 'clamp low', probe(SEARCH_F, {0: 4, 1: ap}, {0: 5.0}), 'r0 fr0 fr1'),
        (SEARCH_I, 'interior', probe(SEARCH_I, {0: 4, 1: api, 2: 30}), 'r0 r1 r2 r3'),
        (SEARCH_I, 'clamp high', probe(SEARCH_I, {0: 4, 1: api, 2: 100}), 'r0 r1 r3'),
        (SEARCH_I, 'clamp low', probe(SEARCH_I, {0: 4, 1: api, 2: 5}), 'r0 r1 r3'),
    ]
    for e, kind in sorted(F1.items()):
        fp = '' if kind == 'f32' else ' fpul'
        rows.append((e, 'fraction != 0', probe(e, {0: 1, 1: data[kind]}, {0: 0.5}), 'r0 r1 fr1 fr2' + fp))
        rows.append((e, 'fraction == 0', probe(e, {0: 1, 1: data[kind]}, {0: 0.0}), 'r0 r1 fr2' + fp))
    for e, kind in sorted(I1.items()):
        rows.append((e, 'fraction != 0', probe(e, {0: 0, 1: data[kind], 2: 0x80000000}), 'r0 r1 r3 mach macl'))
        rows.append((e, 'fraction == 0', probe(e, {0: 0, 1: data[kind], 2: 0}), 'r0 r1'))
    for e, kind in sorted(F2.items()):
        fp = '' if kind == 'f32' else ' fpul'
        rows.append((e, 'both fractions != 0', probe(e, {0: 3, 1: data[kind], 2: 1, 3: 1}, {0: 0.5, 1: 0.25}),
                     'r0 r1 r3 fr0 fr1 fr2 fr3 fr4 macl' + fp))
        rows.append((e, 'fraction1 == 0', probe(e, {0: 3, 1: data[kind], 2: 1, 3: 1}, {0: 0.5, 1: 0.0}),
                     'r0 r1 r3 fr1 fr2 fr3 fr4 macl' + fp))
    rows.append((SEARCH_2D, 'both interior', probe(SEARCH_2D, {4: RAM_DESC}, {4: 30.0, 5: 30.0}),
                 'r0 r1 r2 r3 fr0 fr1 fr2 fr3'))

    def order(s):
        return sorted(s, key=lambda n: (n[0] != 'r', n[:2] != 'fr', int(n.lstrip('fr')) if n[-1].isdigit() else 99, n))

    for e, path, ch, want in rows:
        say(f'  0x{e:06X} {path:<20} {" ".join(order(ch))}')
        ok('textbook', ch == set(want.split()), 'clobber set', hex(e), path, sorted(ch), want)
    fp_yes = sorted(e for e, _, ch, _ in rows if 'fpul' in ch)
    fp_no = sorted(set(e for e, _, _, _ in rows) - set(fp_yes))
    print('  A7: fpul is written by ' + ' '.join(f'0x{e:06X}' for e in sorted(set(fp_yes)))
          + ' ; not by ' + ' '.join(f'0x{e:06X}' for e in fp_no))


# ================================================================== record discovery
def u16(a):
    return int.from_bytes(ROM[a:a + 2], 'big')


def u32(a):
    return int.from_bytes(ROM[a:a + 4], 'big')


def s8(v):
    return v - 0x100 if v & 0x80 else v


def s12(v):
    return v - 0x1000 if v & 0x800 else v


def gpr_writes(w):
    """General registers an instruction word writes (forms tracked as constants are handled
    before this is asked)."""
    n, m, op, lo = (w >> 8) & 15, (w >> 4) & 15, w >> 12, w & 15
    if op == 0x0:
        if lo in (0xC, 0xD, 0xE, 0x2, 0xA) or (w & 0xF0FF) == 0x0029:
            return {n}                               # indexed loads, stc, sts, movt
        return set()
    if op == 0x2:
        return {n} if lo in (4, 5, 6, 9, 0xA, 0xB, 0xD) else set()
    if op == 0x3:
        return {n} if lo in (4, 8, 0xA, 0xB, 0xC, 0xE, 0xF) else set()
    if op == 0x4:
        if lo == 0xF:
            return {n, m}                            # mac.w
        if (w & 0xFF) in (0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x18, 0x19, 0x28, 0x29, 0x20, 0x21, 0x24, 0x25, 0x10):
            return {n}                               # shifts, rotates, dt
        return {n} if lo in (2, 3, 6, 7) else set()  # sts.l/stc.l @-Rn, lds.l/ldc.l @Rn+
    if op in (0x5, 0x7, 0x9, 0xD, 0xE):
        return {n}
    if op == 0x6:
        return {n, m} if lo in (4, 5, 6) else {n}
    if op == 0x8:
        return {0} if ((w >> 8) & 15) in (4, 5) else set()
    if op == 0xC:
        return {0} if ((w >> 8) & 15) in (4, 5, 6, 7, 9, 0xA, 0xB) else set()
    if op == 0xF:
        if lo == 9:
            return {m}                               # fmov.s @Rm+,FRn
        if lo == 0xB:
            return {n}                               # fmov.s FRm,@-Rn
    return set()


class Flow:
    """Set-valued constant propagation.  State at an instruction:
         regs   16 entries, each a frozenset of possible constants or None (unknown)
         sp     r15 relative to the value at the function entry, or None
         slots  {sp-relative offset: frozenset} for longs stored through r15
         esc    True once r15 has been copied to another register (slots then untrusted)
         gs     {GBR offset: frozenset} for longs stored with mov.l r0,@(d,gbr)   [optional]
    Joins take the union of sets (None wins); a set larger than CAP becomes None."""
    CAP = 12

    def __init__(self, entries, track_gbr):
        self.track_gbr = track_gbr
        self.IN = {}
        self.sites = {}             # pc -> (target set | None, r4 set after the delay slot | None, kind)
        self.braf = {}
        self.braf_unresolved = []
        self._run(entries)

    # -- transfer
    def step(self, w, pc, state):
        regs, sp, slots, esc, gsl = state
        n, m, op, lo, hi = (w >> 8) & 15, (w >> 4) & 15, w >> 12, w & 15, (w >> 8) & 0xFF
        r = list(regs)
        if hi in (0xC0, 0xC1, 0xC2, 0xC6, 0xCD, 0xCE, 0xCF) or (w & 0xF0FF) in (0x401E, 0x4017):
            gs = dict(gsl)
            d = w & 0xFF
            if hi == 0xC2:                           # mov.l r0,@(d*4,gbr)
                if regs[0] is None or not self.track_gbr:
                    gs.pop(4 * d, None)
                else:
                    gs[4 * d] = regs[0]
                return (regs, sp, slots, esc, tuple(sorted(gs.items())))
            if hi == 0xC6:                           # mov.l @(d*4,gbr),r0
                r[0] = gs.get(4 * d)
                return (tuple(r), sp, slots, esc, gsl)
            if hi == 0xC0:                           # mov.b r0,@(d,gbr)
                gs.pop(d & ~3, None)
                return (regs, sp, slots, esc, tuple(sorted(gs.items())))
            if hi == 0xC1:                           # mov.w r0,@(d*2,gbr)
                gs.pop((2 * d) & ~3, None)
                return (regs, sp, slots, esc, tuple(sorted(gs.items())))
            if hi in (0xCD, 0xCE, 0xCF) or (w & 0xF0FF) == 0x401E:
                return (regs, sp, slots, esc, ())    # and.b/xor.b/or.b @(r0,gbr) ; ldc Rn,gbr
            gsl = ()                                 # ldc.l @Rn+,gbr: falls through for the Rn update
        sl = dict(slots)
        if sp is not None and not esc:
            done = True
            if op == 0x2 and n == 15 and lo == 2:                 # mov.l Rm,@r15
                self._set(sl, sp, regs[m])
            elif op == 0x1 and n == 15:                           # mov.l Rm,@(d,r15)
                self._set(sl, sp + 4 * lo, regs[m])
            elif op == 0x2 and n == 15 and lo == 6:               # mov.l Rm,@-r15
                sp -= 4
                self._set(sl, sp, regs[m])
            elif op == 0x2 and n == 15 and lo in (4, 5):          # mov.b/w Rm,@-r15
                sp -= lo - 3
                sl.pop(sp & ~3, None)
            elif op == 0x4 and n == 15 and lo in (2, 3):          # sts.l / stc.l ..,@-r15
                sp -= 4
                sl.pop(sp, None)
            elif op == 0xF and n == 15 and lo == 0xB:             # fmov.s FRm,@-r15
                sp -= 4
                sl.pop(sp, None)
            elif op == 0x6 and m == 15 and lo == 2:               # mov.l @r15,Rn
                r[n] = sl.get(sp)
            elif op == 0x5 and m == 15:                           # mov.l @(d,r15),Rn
                r[n] = sl.get(sp + 4 * lo)
            elif op == 0x6 and m == 15 and lo == 6 and n != 15:   # mov.l @r15+,Rn
                r[n] = sl.get(sp)
                sp += 4
            elif op == 0x6 and m == 15 and lo in (4, 5) and n != 15:   # mov.b/w @r15+,Rn
                r[n] = None
                sp += lo - 3
            elif op == 0x4 and n == 15 and lo in (6, 7):          # lds.l / ldc.l @r15+
                sp += 4
            elif op == 0xF and m == 15 and lo == 9:               # fmov.s @r15+,FRn
                sp += 4
            elif op == 0x7 and n == 15:                           # add #imm,r15
                sp += s8(w & 0xFF)
            elif op == 0x2 and n == 15 and lo in (0, 1):          # mov.b/w Rm,@r15
                sl.pop(sp, None)
            elif (w & 0xFE00) == 0x8000 and m == 15:              # mov.b/w r0,@(d,r15)
                sl.pop((sp + lo * (2 if w & 0x0100 else 1)) & ~3, None)
            elif op == 0xF and n == 15 and lo == 0xA:             # fmov.s FRm,@r15
                sl.pop(sp, None)
            elif (op == 0xF and n == 15 and lo == 7) or (op == 0x0 and n == 15 and lo in (4, 5, 6)):
                c = regs[0]                                       # ..,@(r0,r15)
                if c is None or len(c) != 1:
                    sl.clear()
                else:
                    sl.pop((sp + sx(next(iter(c)), 32)) & ~3, None)
            else:
                done = False
            if done:
                for k in [k for k in sl if k < sp]:               # below the stack pointer: dead
                    del sl[k]
                return (tuple(r), sp, tuple(sorted(sl.items())), esc, gsl)
        if op == 0xD:
            la = ((pc + 4) & ~3) + (w & 0xFF) * 4
            r[n] = frozenset([u32(la)]) if la + 4 <= len(ROM) else None
        elif op == 0x9:
            r[n] = frozenset([sx(u16(pc + 4 + (w & 0xFF) * 2), 16) & M32])
        elif op == 0xE:
            r[n] = frozenset([s8(w & 0xFF) & M32])
        elif op == 0x6 and lo == 3:
            if m == 15:
                esc, r[n] = True, None
                sl.clear()
            else:
                r[n] = regs[m]
        elif op == 0x7:
            r[n] = None if regs[n] is None else frozenset((v + s8(w & 0xFF)) & M32 for v in regs[n])
        elif hi == 0xC7:
            r[0] = frozenset([((pc + 4) & ~3) + (w & 0xFF) * 4])
        else:
            for x in gpr_writes(w):
                r[x] = None
        if r[15] is not None or 15 in gpr_writes(w):              # r15 changed in a way not followed
            r[15], sp = None, None
            sl.clear()
        return (tuple(r), sp, tuple(sorted(sl.items())), esc, gsl)

    @staticmethod
    def _set(sl, off, v):
        if v is None:
            sl.pop(off, None)
        else:
            sl[off] = v

    def join(self, a, b):
        if a == b:
            return a
        ra, spa, sla, ea, ga = a
        rb, spb, slb, eb, gb = b
        regs = tuple(None if x is None or y is None or len(x | y) > self.CAP else x | y for x, y in zip(ra, rb))

        def both(p, q):
            p, q = dict(p), dict(q)
            return tuple(sorted((k, p[k] | q[k]) for k in p.keys() & q.keys() if len(p[k] | q[k]) <= self.CAP))

        esc = ea or eb
        if spa is None or spa != spb or esc:
            return (regs, spa if spa == spb else None, (), esc, both(ga, gb))
        return (regs, spa, both(sla, slb), esc, both(ga, gb))

    @staticmethod
    def after_call(state):
        regs, sp, slots, esc, g = state
        return (tuple([None] * 8) + regs[8:], sp, slots, esc, g)

    def switch_targets(self, pc):
        """braf r0 preceded by  mova tbl,r0 / mov.w @(r0,Rm),r0 ; the entry count comes from
        mov #imm,Rk / cmp/hi Rk,Rm  (T = Rm > Rk -> default) a few instructions earlier."""
        if u16(pc) != 0x0023 or (u16(pc - 4) & 0xFF00) != 0xC700 or (u16(pc - 2) & 0xFF0F) != 0x000D:
            return None
        idx = (u16(pc - 2) >> 4) & 15
        tbl = (pc & ~3) + (u16(pc - 4) & 0xFF) * 4
        count = None
        for b in range(pc - 6, pc - 26, -2):
            w = u16(b)
            if (w & 0xF00F) == 0x3006 and ((w >> 8) & 15) == idx:
                k = (w >> 4) & 15
                for c in range(b - 2, b - 10, -2):
                    if (u16(c) & 0xFF00) == (0xE000 | (k << 8)):
                        count = (u16(c) & 0xFF) + 1
                        break
                break
        if count is None or count > 64:
            return None
        return [pc + 4 + sx(u16(tbl + 2 * i), 16) for i in range(count)]

    def _run(self, entries):
        IN, work = self.IN, collections.deque()
        top = (tuple([None] * 16), 0, (), False, ())

        def push(pc, st):
            if pc < 0 or pc + 2 > len(ROM) or pc & 1:
                return
            if pc not in IN:
                IN[pc] = st
                work.append(pc)
            else:
                new = self.join(IN[pc], st)
                if new != IN[pc]:
                    IN[pc] = new
                    work.append(pc)

        for e in entries:
            push(e, top)
        while work:
            pc = work.popleft()
            st = IN[pc]
            w = u16(pc)
            op = w >> 12
            if (w & 0xF0FF) == 0x400B:                   # jsr @Rn
                s2 = self.step(u16(pc + 2), pc + 2, st)
                self.sites[pc] = (st[0][(w >> 8) & 15], s2[0][4], 'jsr')
                push(pc + 4, self.after_call(s2))
            elif (w & 0xF0FF) == 0x402B:                 # jmp @Rn
                s2 = self.step(u16(pc + 2), pc + 2, st)
                self.sites[pc] = (st[0][(w >> 8) & 15], s2[0][4], 'jmp')
            elif op == 0xB:                              # bsr
                s2 = self.step(u16(pc + 2), pc + 2, st)
                self.sites[pc] = (frozenset([pc + 4 + s12(w & 0xFFF) * 2]), s2[0][4], 'bsr')
                push(pc + 4, self.after_call(s2))
            elif (w & 0xF0FF) == 0x0003:                 # bsrf
                s2 = self.step(u16(pc + 2), pc + 2, st)
                self.sites[pc] = (None, s2[0][4], 'bsrf')
                push(pc + 4, self.after_call(s2))
            elif op == 0xA:                              # bra
                s2 = self.step(u16(pc + 2), pc + 2, st)
                tgt = pc + 4 + s12(w & 0xFFF) * 2
                self.sites[pc] = (frozenset([tgt]), s2[0][4], 'bra')
                push(tgt, s2)
            elif (w & 0xF0FF) == 0x0023:                 # braf
                tb = self.switch_targets(pc)
                if tb is None:
                    self.braf_unresolved.append(pc)
                else:
                    self.braf[pc] = tb
                    s2 = self.step(u16(pc + 2), pc + 2, st)
                    for t in tb:
                        push(t, s2)
            elif w in (0x000B, 0x002B):                  # rts / rte
                pass
            elif (w & 0xFF00) in (0x8900, 0x8B00):       # bt / bf
                push(pc + 4 + s8(w & 0xFF) * 2, st)
                push(pc + 2, st)
            elif (w & 0xFF00) in (0x8D00, 0x8F00):       # bt/s / bf/s
                s2 = self.step(u16(pc + 2), pc + 2, st)
                push(pc + 4 + s8(w & 0xFF) * 2, s2)
                push(pc + 4, s2)
            else:
                push(pc + 2, self.step(w, pc, st))

    def calls_of(self, wrapper):
        """[(pc, r4 set | None, kind)] for every site whose target set contains the wrapper."""
        return [(pc, r4, k) for pc, (tg, r4, k) in sorted(self.sites.items()) if tg and wrapper in tg]


class MayFlow(Flow):
    """MAY-hold variant of Flow, used only as a completeness check on the call sites.
    The value of a register / stack slot / GBR cell is the SET OF WRAPPER ADDRESSES it may hold
    on SOME path (None = no wrapper).  A join is the union and an unknown path contributes
    nothing, so a census entry seeded with "nothing known" cannot hide a constant that arrives
    from the code before it.  The lattice is the subsets of the eight wrapper addresses, finite,
    so the fixpoint terminates.  The transfer function is Flow.step, then filtered."""

    @staticmethod
    def _f(x):
        if x is None:
            return None
        y = frozenset(x) & frozenset(WRAPPERS)
        return y or None

    def __init__(self, entries):
        super().__init__(entries, track_gbr=False)

    def step(self, w, pc, state):
        regs, sp, slots, esc, g = super().step(w, pc, state)
        f = self._f
        return (tuple(f(x) for x in regs), sp, tuple((k, f(v)) for k, v in slots if f(v)), esc,
                tuple((k, f(v)) for k, v in g if f(v)))

    def join(self, a, b):
        if a == b:
            return a
        def empty(s):
            return all(x is None for x in s[0]) and not s[2] and not s[4]
        if empty(b):
            return a
        if empty(a):
            return b
        ra, spa, sla, ea, ga = a
        rb, spb, slb, eb, gb = b

        def u(x, y):
            return y if x is None else x if y is None else x | y

        def both(p, q):
            p, q = dict(p), dict(q)
            return tuple(sorted((k, u(p.get(k), q.get(k))) for k in p.keys() | q.keys()))
        regs = tuple(u(x, y) for x, y in zip(ra, rb))
        if spa != spb:
            return (regs, None, (), ea or eb, both(ga, gb))
        return (regs, spa, both(sla, slb), ea or eb, both(ga, gb))


def in_rom(a, n):
    return 0x1000 <= a and a + n <= 0x100000


def valid(wrapper, d):
    if not in_rom(d, 28) or d & 1:
        return False
    n0 = rd(d, 2)
    if not 1 <= n0 <= 256:
        return False
    if wrapper in (W_1D, W_1D_U8, W_1D_U16, W_1DI_U8, W_1DI_U16):
        ap, dp = rd(d + 4, 4), rd(d + 8, 4)
        if wrapper == W_1D:
            tc = rd(d + 2, 1)
            if tc not in TC_NAME or rd(d + 3, 1) != 0:
                return False
            w = WIDTH[TC_NAME[tc]]
        else:
            w = 1 if wrapper in (W_1D_U8, W_1DI_U8) else 2
        return in_rom(ap, 4 * n0) and in_rom(dp, w * n0)
    n1 = rd(d + 2, 2)
    if not 1 <= n1 <= 256:
        return False
    if wrapper == W_2D:
        tc = rd(d + 16, 1)
        if tc not in TC_NAME:
            return False
        w = WIDTH[TC_NAME[tc]]
    else:
        w = 1 if wrapper == W_2D_U8 else 2
    return (in_rom(rd(d + 4, 4), 4 * n0) and in_rom(rd(d + 8, 4), 4 * n1)
            and in_rom(rd(d + 12, 4), w * n0 * n1))


def is_delayed(w):
    """rts, rte, jmp, jsr, braf, bsrf, bra, bsr, bt/s, bf/s: the next word is a delay slot."""
    return (w in (0x000B, 0x002B) or (w & 0xF0FF) in (0x402B, 0x400B, 0x0023, 0x0003)
            or (w >> 12) in (0xA, 0xB) or (w & 0xFF00) in (0x8D00, 0x8F00))


def is_uncond(w):
    """rts, rte, jmp, braf, bra: nothing falls through after the delay slot."""
    return w in (0x000B, 0x002B) or (w & 0xF0FF) in (0x402B, 0x0023) or (w >> 12) == 0xA


def continuations(flow, census):
    """Census entries that the code before them FALLS INTO (flow.IN reaches the previous
    instruction and it is not a delayed branch; or the word before is the delay slot of a
    conditional / call branch) and that nothing calls (no bsr / jsr / jmp of flow resolves to
    them, census evidence is not call / vector / table / tailjmp).  Such an address is a
    census split inside one function, not a function entry: seeding "nothing known" there
    throws away registers and stack slots set before the split.  Found the hard way:
    0x01FE46 falls into 0x020000 (census 'ptr', from the coincidental constant 0x00020000)
    and on into 0x020012 (census 'tailbra'); six wrapper calls beyond them use r11 / a stack
    slot loaded before the split (trace REVIEW HISTORY, E9)."""
    IN = flow.IN
    called = set()
    for pc, (tg, _, k) in flow.sites.items():
        if k in ('bsr', 'jsr', 'jmp') and tg:
            called |= tg
    out = {}
    for f in census:
        e, ev = int(f['entry'], 16), f['evidence']
        if e in called or ev in ('call', 'vector', 'table', 'tailjmp'):
            continue
        p, q = e - 2, e - 4
        if (p in IN and not is_delayed(u16(p))) or (q in IN and is_delayed(u16(q)) and not is_uncond(u16(q))):
            out[e] = ev
    return out


def find_records():
    """Returns (good, info): good[wrapper] = sorted valid records (register/stack pass plus the
    GBR-cell pass), info = everything the later parts and the report need."""
    census = json.load(open(CENSUS))['functions']
    entries = sorted(int(f['entry'], 16) for f in census)
    reset_all = Flow(entries, track_gbr=False)            # "nothing known" at every census entry
    cont = continuations(reset_all, census)
    seeds = [e for e in entries if e not in cont]
    strict = Flow(seeds, track_gbr=False)
    wide = Flow(seeds, track_gbr=True)
    print(f'PART B record discovery: constant propagation from {len(seeds)} of the {len(entries)} census '
          f'function entries ({len(cont)} census entries are fall-through continuations and are NOT reset: '
          + ', '.join(f'{k} {v}' for k, v in sorted(collections.Counter(cont.values()).items())) + '); '
          f'{len(strict.IN)} instruction addresses reached; switch tables followed at '
          + ', '.join(f'0x{p:06X} ({len(t)} entries)' for p, t in sorted(strict.braf.items()))
          + (f'; UNRESOLVED braf at {[hex(p) for p in strict.braf_unresolved]}' if strict.braf_unresolved else ''))
    ok('textbook', set(reset_all.IN) <= set(strict.IN), 'not resetting continuations lost reached code')
    # not resetting can only ADD knowledge: every call site of the reset-everywhere pass is still a
    # call site, with the same wrapper and an r4 set that is the same or was unknown before
    gained = {}
    for w in WRAPPERS:
        a = {pc: r4 for pc, r4, _ in reset_all.calls_of(w)}
        b = {pc: r4 for pc, r4, _ in strict.calls_of(w)}
        ok('textbook', set(a) <= set(b), 'continuation pass lost a call site', hex(w), sorted(set(a) - set(b)))
        ok('textbook', all(a[pc] is None or a[pc] == b[pc] for pc in a), 'continuation pass changed an r4', hex(w))
        gained[w] = sorted(set(b) - set(a))
    say('  continuations not reset: ' + ' '.join(f'{e:06X}({v})' for e, v in sorted(cont.items())))
    # the split that cost six call sites (trace E9): both continuations are recognised, and the six
    # sites with their records are exactly what not resetting them adds
    ok('textbook', cont.get(0x020000) == 'ptr' and cont.get(0x020012) == 'tailbra', 'E9 continuations', cont)
    ok('textbook', gained[W_2D] == [0x020116, 0x020120] and gained[W_1D] == [0x020188, 0x020198, 0x0201A6, 0x020310]
       and not any(gained[w] for w in WRAPPERS if w not in (W_1D, W_2D)), 'E9 sites', gained)
    e9 = {pc: r4 for pc, r4, _ in strict.calls_of(W_2D) + strict.calls_of(W_1D) if pc in gained[W_1D] + gained[W_2D]}
    ok('textbook', e9 == {0x020116: {0x0AB004}, 0x020120: {0x0AB020}, 0x020188: {0x0AAE14}, 0x020198: {0x0AAE28},
                          0x0201A6: {0x0AAE3C}, 0x020310: {0x0AAE50}}, 'E9 records', e9)
    ok('textbook', not strict.braf_unresolved and len(strict.braf) == 2, 'braf')
    multi = [pc for pc, (tg, _, _) in strict.sites.items() if tg and len(tg) > 1 and tg & set(WRAPPERS)]
    ok('textbook', not multi, 'a call site with more than one possible wrapper', multi)
    good, info = {}, {'strict': {}, 'gbr_only': {}, 'sites': {}, 'unres': {}, 'flow': strict, 'where': {}}
    dropped = []
    for w in WRAPPERS:
        cs, cw = strict.calls_of(w), dict((pc, r4) for pc, r4, _ in wide.calls_of(w))
        ok('textbook', set(pc for pc, _, _ in cs) == set(cw), 'the two passes disagree on call sites', hex(w))
        vs = set().union(*[r4 for _, r4, _ in cs if r4]) if cs else set()
        vw = set().union(*[r4 for r4 in cw.values() if r4]) if cw else set()
        dropped += [(w, v) for v in sorted(vw) if not valid(w, v)]
        info['strict'][w] = sorted(v for v in vs if valid(w, v))
        info['gbr_only'][w] = sorted(v for v in vw - vs if valid(w, v))
        info['sites'][w] = cs
        info['unres'][w] = [pc for pc, r4 in sorted(cw.items()) if r4 is None]
        for pc, r4 in cw.items():
            for v in r4 or ():
                info['where'].setdefault((w, v), []).append(pc)
        good[w] = sorted(info['strict'][w] + info['gbr_only'][w])
        kinds = collections.Counter(k for _, _, k in cs)
        n_s = sum(1 for _, r4, _ in cs if r4)
        n_w = sum(1 for r4 in cw.values() if r4)
        print(f'  wrapper 0x{w:06X}: {len(cs)} call sites ({", ".join(f"{v} {k}" for k, v in sorted(kinds.items()))}); '
              f'r4 constant at {n_s}, +{n_w - n_s} through a GBR cell, {len(cs) - n_w} not constant; '
              f'records {len(info["strict"][w])} + {len(info["gbr_only"][w])} = {len(good[w])}'
              + (f'; {len(gained[w])} of the sites only because continuations are not reset: '
                 + ' '.join(f'{pc:06X}' for pc in gained[w]) if gained[w] else ''))
    info['gained'] = gained
    info['cont'] = cont
    print(f'  totals: {sum(len(v) for v in info["sites"].values())} call sites; '
          f'{sum(len(v) for v in info["strict"].values())} records by register/stack propagation, '
          f'+{sum(len(v) for v in info["gbr_only"].values())} through a GBR cell = '
          f'{sum(len(v) for v in good.values())}; constants reaching r4 that are NOT structurally a record: '
          f'{len(dropped)}')
    ok('textbook', not dropped, 'non-record constants', dropped)
    seen = collections.Counter(v for w in WRAPPERS for v in good[w])
    ok('textbook', max(seen.values()) == 1, 'a record reaches two different wrappers')
    cnts = [rd(v, 2) for w in WRAPPERS for v in good[w]] + [rd(v + 2, 2) for w in TWO_D for v in good[w]]
    print(f'  count words of all {sum(len(v) for v in good.values())} records: min {min(cnts)}, max {max(cnts)} '
          f'(no record with a count below 1)')
    ok('textbook', min(cnts) >= 1, 'count below 1')
    # completeness of the call-site side: every literal-pool long that holds a wrapper address is
    # loaded by reached code, and the constant never leaves registers / stack slots
    lit_loads = collections.Counter()
    for pc in strict.IN:
        ww = u16(pc)
        if (ww >> 12) == 0xD:
            la = ((pc + 4) & ~3) + (ww & 0xFF) * 4
            if la + 4 <= len(ROM) and u32(la) in WRAPPERS:
                lit_loads[la] += 1
    longs = [a for a in range(0, len(ROM) - 3, 2) if u32(a) in WRAPPERS]
    orphan = [a for a in longs if a not in lit_loads]
    print(f'  {len(longs)} longs in the ROM equal a wrapper address; all are literal-pool entries loaded by reached '
          f'code: {not orphan}' + (f'  NOT loaded: {[hex(a) for a in orphan]}' if orphan else ''))
    ok('textbook', not orphan, 'wrapper address outside a reached literal pool', orphan)
    # The first version checked "no unresolved jsr/jmp in a census function that loads a wrapper
    # address".  That test is blind across a census split: 0x01FE46 loads r11 = 0x0BE8E4 and the
    # two jsr @r11 at 020116 / 020120 sit past the split, in census function 0x020012.  Replaced by
    # a MAY-hold pass that does not depend on census entries at all (see MayFlow).
    n_blind = sum(1 for tg, _, k in strict.sites.values() if tg is None and k in ('jsr', 'jmp'))
    may = MayFlow(entries)
    counted = set(pc for w in WRAPPERS for pc, _, _ in strict.calls_of(w))
    may_sites = sorted(pc for pc, (tg, _, k) in may.sites.items() if tg and k in ('jsr', 'jmp'))
    missed = [pc for pc in may_sites if pc not in counted]
    print(f'  jsr/jmp sites whose target is not a constant: {n_blind}.  MAY-hold pass: {len(may_sites)} jsr/jmp '
          f'sites at which some path holds a wrapper address in the target register; not counted above: '
          f'{len(missed)}' + (f' {[hex(pc) for pc in missed]}' if missed else '')
          + f'; counted above but not by the may pass (it drops stack slots at a store through an '
          f'unknown r0 index): {len(counted - set(may_sites))}')
    ok('textbook', not missed, 'a site that may call a wrapper is not counted', missed)
    ok('textbook', all(len(may.sites[pc][0]) == 1 for pc in may_sites), 'a site that may call two wrappers')
    info['may_n'] = len(may_sites)
    # where r4 is not a constant: say what it is instead
    src = collections.Counter()
    bases = set()
    for w in WRAPPERS:
        for pc in info['unres'][w]:
            for b in [pc + 2] + list(range(pc - 2, pc - 40, -2)):
                ww = u16(b)
                if ((ww >> 8) & 15) == 4 and ((ww >> 12) in (0xD, 0xE, 0x5) or ((ww >> 12) == 0 and (ww & 15) == 0xE)
                                               or ((ww >> 12) == 6 and (ww & 15) in (2, 3, 6))):
                    st = strict.IN.get(b, strict.IN[pc])
                    if (ww >> 12) == 0 and st[0][(ww >> 4) & 15]:
                        src['indexed ROM pointer table'] += 1
                        bases |= set(st[0][(ww >> 4) & 15])
                    elif (ww >> 12) == 6 and (ww & 15) == 3:
                        src['copy of a register loaded from RAM'] += 1
                    else:
                        src['load through a pointer that is not a constant'] += 1
                    break
            else:
                src['?'] += 1
    print(f'  call sites whose r4 is not a constant: {sum(src.values())}: '
          + '; '.join(f'{v} {k}' for k, v in sorted(src.items()))
          + ('; pointer-table bases ' + ' '.join(f'0x{b:06X}' for b in sorted(bases)) if bases else ''))
    for w in WRAPPERS:
        if info['unres'][w]:
            say(f'    0x{w:06X}: ' + ' '.join(f'{pc:06X}' for pc in info['unres'][w]))
    info['unres_n'] = sum(src.values())
    return good, info


def strictly_up(vals):
    return all(b > a for a, b in zip(vals, vals[1:])) and all(v == v for v in vals)


def grid_f(axis, mids=True):
    """Inputs below, on, between and above the breakpoints of a float axis."""
    a0, an = axis[0], axis[-1]
    xs = [f32(a0 - max(1.0, abs(a0))), nxt(a0, False)]
    for i, a in enumerate(axis):
        xs.append(a)
        if mids and i + 1 < len(axis):
            xs.append(f32((a + axis[i + 1]) / 2))
            xs.append(f32(a + (axis[i + 1] - a) * 0.3))
    xs += [nxt(an, True), f32(an + max(1.0, abs(an))), -1e30, 1e30]
    return xs


def b_typed_1d(recs):
    say('\n=== PART B1  0x0BE830 (typed 1-D wrapper) on real records: r4=record fr4=x -> fr0 ===')
    by = {}
    n_calls = n_break = n_clamp = n_mid = non_mono = 0
    shown = set()
    for d in recs:
        n, tc = rd(d, 2), rd(d + 2, 1)
        kind = TC_NAME[tc]
        ap, dp = rd(d + 4, 4), rd(d + 8, 4)
        axis = [rf(ap + 4 * i) for i in range(n)]
        raw = [float(cell(kind, dp + i * WIDTH[kind])) for i in range(n)]
        if tc:
            sc, bi = rf(d + 12), rf(d + 16)
            phys = [AR.mac(sc, f32(r), bi) for r in raw]
        else:
            phys = [f32(r) for r in raw]
        # rounding scale of the record: |scale*raw| + |bias| (results near 0 are differences of these)
        mag = max([abs(r) for r in raw] + [1e-30]) * (abs(rf(d + 12)) if tc else 1.0) + (abs(rf(d + 16)) if tc else 0.0)
        mono = strictly_up(axis)
        non_mono += not mono
        if not mono:
            print(f'  note: record 0x{d:06X} axis 0x{ap:06X} is not strictly increasing: {axis}')
        by[kind] = by.get(kind, 0) + 1
        show = kind not in shown
        if show:
            shown.add(kind)
            say(f'  example {kind}: record 0x{d:06X} count {n} axis 0x{ap:06X} data 0x{dp:06X}'
                + (f' scale {rf(d + 12)!r} bias {rf(d + 16)!r}' if tc else ' (no scale/bias applied)'))
            say(f'    axis {axis}')
            say(f'    cells {phys}')
        for x in grid_f(axis):
            run(W_1D, regs={4: d}, fregs={4: x})
            n_calls += 1
            got = emu.fr(0)
            ok('model', same_f(fbits(0), m_w1d(d, x)), hex(d), x, got)
            if show:
                say(f'    x={x!r:>24} -> {got!r}')
            if not mono:
                continue
            if x < axis[0]:
                ok('textbook', same_f(fbits(0), phys[0]), 'clamp low', hex(d), x, got, phys[0])
                n_clamp += 1
            elif x >= axis[-1]:
                ok('textbook', same_f(fbits(0), phys[-1]), 'clamp high', hex(d), x, got, phys[-1])
                n_clamp += 1
            elif x in axis:
                ok('textbook', same_f(fbits(0), phys[axis.index(x)]), 'breakpoint', hex(d), x)
                n_break += 1
            else:
                i = max(k for k in range(n) if axis[k] <= x)
                lo, hi = sorted((phys[i], phys[i + 1]))
                tol = 1e-5 * mag
                ok('textbook', lo - tol <= got <= hi + tol, 'between cells', hex(d), x, got, lo, hi)
                t = (x - axis[i]) / (axis[i + 1] - axis[i])
                exp = phys[i] + t * (phys[i + 1] - phys[i])
                ok('textbook', abs(got - exp) <= tol, 'linear', hex(d), x, got, exp)
                n_mid += 1
    print(f'  B1: {len(recs)} records {by}; {n_calls} calls; textbook: {n_break} breakpoint, {n_clamp} clamp, '
          f'{n_mid} interior; {non_mono} records with a non-increasing axis (model check only)')
    return by


def b_typed_2d(recs):
    say('\n=== PART B2  0x0BE8E4 (typed 2-D wrapper) on real records: r4=record fr4=x fr5=y -> fr0 ===')
    by = {}
    n_calls = n_break = n_clamp = n_mid = non_mono = 0
    order_tables = order_cells = 0
    shown = set()
    for d in recs:
        n0, n1, tc = rd(d, 2), rd(d + 2, 2), rd(d + 16, 1)
        kind = TC_NAME[tc]
        w = WIDTH[kind]
        a0p, a1p, dp = rd(d + 4, 4), rd(d + 8, 4), rd(d + 12, 4)
        ax0 = [rf(a0p + 4 * i) for i in range(n0)]
        ax1 = [rf(a1p + 4 * i) for i in range(n1)]

        def phys(k, tc=tc, kind=kind, dp=dp, w=w, d=d):
            r = f32(float(cell(kind, dp + k * w)))
            return AR.mac(rf(d + 20), r, rf(d + 24)) if tc else r

        mag = (max([abs(float(cell(kind, dp + k * w))) for k in range(n0 * n1)] + [1e-30])
               * (abs(rf(d + 20)) if tc else 1.0) + (abs(rf(d + 24)) if tc else 0.0))
        mono = strictly_up(ax0) and strictly_up(ax1)
        non_mono += not mono
        by[kind] = by.get(kind, 0) + 1
        show = kind not in shown
        if show:
            shown.add(kind)
            say(f'  example {kind}: record 0x{d:06X} count0 {n0} count1 {n1} axis@+4 0x{a0p:06X} '
                f'axis@+8 0x{a1p:06X} data 0x{dp:06X}'
                + (f' scale {rf(d + 20)!r} bias {rf(d + 24)!r}' if tc else ' (no scale/bias applied)'))
        # 1. every breakpoint pair: settles the storage order cell by cell
        diff_here = 0
        for j in range(n1):
            for i in range(n0):
                run(W_2D, regs={4: d}, fregs={4: ax0[i], 5: ax1[j]})
                n_calls += 1
                ok('model', same_f(fbits(0), m_w2d(d, ax0[i], ax1[j])), hex(d), i, j)
                if mono:
                    ok('textbook', same_f(fbits(0), phys(j * n0 + i)), 'cell = data[i8*count0+i4]', hex(d), i, j)
                    n_break += 1
                    alt = i * n1 + j
                    if alt != j * n0 + i and E.f2b(phys(alt)) != fbits(0):
                        diff_here += 1
        if diff_here:
            order_tables += 1
            order_cells += diff_here
        # 2. edges and interior points
        xs = [f32(ax0[0] - max(1.0, abs(ax0[0]))), f32(ax0[-1] + max(1.0, abs(ax0[-1])))]
        ys = [f32(ax1[0] - max(1.0, abs(ax1[0]))), f32(ax1[-1] + max(1.0, abs(ax1[-1])))]
        for x in xs:
            for y in ys:
                run(W_2D, regs={4: d}, fregs={4: x, 5: y})
                n_calls += 1
                ok('model', same_f(fbits(0), m_w2d(d, x, y)), hex(d), x, y)
                if mono:
                    i = 0 if x < ax0[0] else n0 - 1
                    j = 0 if y < ax1[0] else n1 - 1
                    ok('textbook', same_f(fbits(0), phys(j * n0 + i)), 'corner clamp', hex(d), x, y)
                    n_clamp += 1
                if show:
                    say(f'    x={x!r:>12} y={y!r:>12} -> {emu.fr(0)!r}   (out-of-range corner)')
        pts_x, pts_y = interior_2d(ax0, ax1)
        for x in pts_x + xs:
            for y in pts_y + ys:
                run(W_2D, regs={4: d}, fregs={4: x, 5: y})
                n_calls += 1
                got = emu.fr(0)
                ok('model', same_f(fbits(0), m_w2d(d, x, y)), hex(d), x, y, got)
                if mono and x in pts_x and y in pts_y:
                    i = max(k for k in range(n0) if ax0[k] <= x)
                    j = max(k for k in range(n1) if ax1[k] <= y)
                    c = [phys(j * n0 + i), phys(j * n0 + i + 1), phys((j + 1) * n0 + i), phys((j + 1) * n0 + i + 1)]
                    tx = (x - ax0[i]) / (ax0[i + 1] - ax0[i])
                    ty = (y - ax1[j]) / (ax1[j + 1] - ax1[j])
                    exp = (c[0] * (1 - tx) + c[1] * tx) * (1 - ty) + (c[2] * (1 - tx) + c[3] * tx) * ty
                    ok('textbook', abs(got - exp) <= 2e-5 * mag, 'bilinear', hex(d), x, y, got, exp)
                    n_mid += 1
                    if show and x == pts_x[0] and y == pts_y[0]:
                        say(f'    x={x!r:>12} y={y!r:>12} -> {got!r}   (bilinear of cells {c})')
    print(f'  B2: {len(recs)} records {by}; {n_calls} calls; textbook: {n_break} breakpoint cells, '
          f'{n_clamp} corner clamps, {n_mid} interior bilinear; {non_mono} records with a non-increasing axis')
    print(f'      storage order: in {order_tables} records ({order_cells} cells) the OTHER order '
          f'data[i4*count1+i8] gives a different value, so the check discriminates there')
    ok('textbook', order_tables > 0, 'order check never discriminated')
    return by


def interior_2d(ax0, ax1):
    n0, n1 = len(ax0), len(ax1)
    pts_x = [f32((ax0[i] + ax0[i + 1]) / 2) for i in range(0, n0 - 1, max(1, (n0 - 1) // 4))]
    pts_y = [f32(ax1[j] + (ax1[j + 1] - ax1[j]) * 0.3) for j in range(0, n1 - 1, max(1, (n1 - 1) // 4))]
    return pts_x, pts_y


def b_fixed_1d(recs_u8, recs_u16):
    say('\n=== PART B3  0x0BE874 (u8) / 0x0BE8AC (u16): r4=record fr4=x -> r0 = trunc(interpolated raw cell) ===')
    tot = 0
    tc_seen = {}
    for wrapper, recs, kind, mask in ((W_1D_U8, recs_u8, 'u8', 0xFF), (W_1D_U16, recs_u16, 'u16', 0xFFFF)):
        first = True
        for d in recs:
            n, ap, dp = rd(d, 2), rd(d + 4, 4), rd(d + 8, 4)
            tc_seen.setdefault((wrapper, rd(d + 2, 1)), []).append(d)
            axis = [rf(ap + 4 * i) for i in range(n)]
            raw = [cell(kind, dp + i * WIDTH[kind]) for i in range(n)]
            mono = strictly_up(axis)
            if first:
                say(f'  example 0x{wrapper:06X}: record 0x{d:06X} count {n} byte+2=0x{rd(d + 2, 1):02X} '
                    f'axis {axis} cells {raw}')
            for x in grid_f(axis):
                run(wrapper, regs={4: d}, fregs={4: x})
                tot += 1
                ok('model', emu.R[0] == m_fixed_1d(d, kind, mask, x), hex(d), x, emu.R[0])
                if first:
                    say(f'    x={x!r:>24} -> {emu.R[0]}')
                if mono:
                    if x < axis[0]:
                        ok('textbook', emu.R[0] == raw[0], 'clamp low', hex(d))
                    elif x >= axis[-1]:
                        ok('textbook', emu.R[0] == raw[-1], 'clamp high', hex(d))
                    elif x in axis:
                        ok('textbook', emu.R[0] == raw[axis.index(x)], 'breakpoint', hex(d))
            first = False
    print(f'  B3: {len(recs_u8)} u8 records, {len(recs_u16)} u16 records, {tot} calls')
    for (wrapper, tc), ds in sorted(tc_seen.items()):
        print(f'      0x{wrapper:06X}: {len(ds)} records carry byte+2 = 0x{tc:02X}'
              + ('' if tc == (0x04 if wrapper == W_1D_U8 else 0x08) else
                 f'  <-- NOT the cell type the wrapper uses; e.g. 0x{ds[0]:06X}'))
    return tc_seen


def b_int_axis(recs_u8, recs_u16):
    say('\n=== PART B4  0x0BE88C (u8) / 0x0BE8C4 (u16): r4=record r5=x (int) -> r0 ; axis is int32[] ===')
    tot = 0
    for wrapper, recs, kind in ((W_1DI_U8, recs_u8, 'u8'), (W_1DI_U16, recs_u16, 'u16')):
        for d in recs:
            n, ap, dp = rd(d, 2), rd(d + 4, 4), rd(d + 8, 4)
            axis = [sx(rd(ap + 4 * i, 4), 32) for i in range(n)]
            raw = [cell(kind, dp + i * WIDTH[kind]) for i in range(n)]
            say(f'  0x{wrapper:06X} record 0x{d:06X} count {n} axis 0x{ap:06X} {axis} cells {raw}')
            xs = [axis[0] - 1000, axis[0] - 1]
            for i, a in enumerate(axis):
                xs.append(a)
                if i + 1 < n:
                    xs += [a + 1, (a + axis[i + 1]) // 2, axis[i + 1] - 1]
            xs += [axis[-1] + 1, axis[-1] + 1000, -2 ** 31, 2 ** 31 - 1]
            mono = strictly_up(axis)
            line = []
            for x in xs:
                emu.mach, emu.macl = 0x13572468, 0x24681357
                run(wrapper, regs={4: d, 5: x})
                tot += 1
                i, q = m_search_i(n, ap, x)
                ok('model', emu.R[0] == m_interp_i(kind, dp, i, q), hex(d), x, emu.R[0])
                ok('textbook', (emu.mach, emu.macl) == (0x13572468, 0x24681357), 'mach/macl restored')
                line.append(f'{x}->{emu.R[0]}')
                if mono:
                    if x < axis[0]:
                        ok('textbook', emu.R[0] == raw[0], 'clamp low')
                    elif x >= axis[-1]:
                        ok('textbook', emu.R[0] == raw[-1], 'clamp high')
                    elif x in axis:
                        ok('textbook', emu.R[0] == raw[axis.index(x)], 'breakpoint')
                    else:
                        k = max(m for m in range(n) if axis[m] <= x)
                        ok('textbook', min(raw[k], raw[k + 1]) <= emu.R[0] <= max(raw[k], raw[k + 1]), 'between')
            say('    ' + '  '.join(line))
    print(f'  B4: {len(recs_u8)} u8 records, {len(recs_u16)} u16 records, {tot} calls')


def b_fixed_2d(recs_u8, recs_u16):
    say('\n=== PART B5  0x0BE928 (u8) / 0x0BE944 (u16): r4=record fr4=x fr5=y -> r0 = trunc(interpolated raw cell) ===')
    tot = 0
    seen = {}
    for wrapper, recs, kind, mask in ((W_2D_U8, recs_u8, 'u8', 0xFF), (W_2D_U16, recs_u16, 'u16', 0xFFFF)):
        for d in recs:
            n0, n1 = rd(d, 2), rd(d + 2, 2)
            a0p, a1p, dp = rd(d + 4, 4), rd(d + 8, 4), rd(d + 12, 4)
            seen.setdefault((wrapper, rd(d + 16, 1)), []).append(d)
            ax0 = [rf(a0p + 4 * i) for i in range(n0)]
            ax1 = [rf(a1p + 4 * i) for i in range(n1)]
            w = WIDTH[kind]
            mono = strictly_up(ax0) and strictly_up(ax1)
            say(f'  0x{wrapper:06X} record 0x{d:06X} count0 {n0} count1 {n1} byte+16=0x{rd(d + 16, 1):02X} '
                f'data 0x{dp:06X}')
            for y in grid_f(ax1, mids=False) + [f32((ax1[0] + ax1[-1]) / 2.1)]:
                for x in grid_f(ax0, mids=False) + [f32((ax0[0] + ax0[-1]) / 2.1)]:
                    run(wrapper, regs={4: d}, fregs={4: x, 5: y})
                    tot += 1
                    ok('model', emu.R[0] == m_fixed_2d(d, kind, mask, x, y), hex(d), x, y, emu.R[0])
                    if mono and (x in ax0 or x < ax0[0] or x >= ax0[-1]) and (y in ax1 or y < ax1[0] or y >= ax1[-1]):
                        i = 0 if x < ax0[0] else n0 - 1 if x >= ax0[-1] else ax0.index(x)
                        j = 0 if y < ax1[0] else n1 - 1 if y >= ax1[-1] else ax1.index(y)
                        ok('textbook', emu.R[0] == cell(kind, dp + (j * n0 + i) * w), 'cell/clamp', hex(d), i, j)
    print(f'  B5: {len(recs_u8)} u8 records, {len(recs_u16)} u16 records, {tot} calls')
    for (wrapper, tc), ds in sorted(seen.items()):
        print(f'      0x{wrapper:06X}: {len(ds)} records carry byte+16 = 0x{tc:02X}'
              + ('' if tc == (0x04 if wrapper == W_2D_U8 else 0x08) else
                 f'  <-- NOT the cell type the wrapper uses; e.g. 0x{ds[0]:06X}'))
    return seen


# ================================================================== PART C: int8 / int16 through the wrappers
def part_c(by1, by2):
    say('\n=== PART C  typecodes 0x0C (int8) / 0x10 (int16) through the typed wrappers, synthetic records ===')
    print(f'  real typed records by cell type: 1-D {by1}, 2-D {by2}  '
          f'(int8/int16 present: {bool(set(by1) & {"i8", "i16"} or set(by2) & {"i8", "i16"})})')
    for tc, kind in ((0x0C, 'i8'), (0x10, 'i16'), (0x04, 'u8'), (0x08, 'u16'), (0x00, 'f32')):
        fresh()
        axis = [0.0, 10.0, 20.0, 40.0]
        ap = put_axis_f(axis)
        if kind == 'f32':
            vals = [-1.0, 2.0, 5.0, -8.0]
        elif WIDTH[kind] == 1:
            vals = [0x00, 0xFF, 0x80, 0x7F]
        else:
            vals = [0x0000, 0xFFFF, 0x8000, 0x7FFF]
        dp = put_data(kind, vals)
        poke(RAM_DESC, 2, 4)
        poke(RAM_DESC + 2, 1, tc)
        poke(RAM_DESC + 3, 1, 0)
        poke(RAM_DESC + 4, 4, ap)
        poke(RAM_DESC + 8, 4, dp)
        poke_f(RAM_DESC + 12, 0.5)
        poke_f(RAM_DESC + 16, 3.0)
        outs = []
        for x in (-5.0, 0.0, 5.0, 10.0, 15.0, 20.0, 30.0, 40.0, 50.0):
            run(W_1D, regs={4: RAM_DESC}, fregs={4: x})
            ok('model', same_f(fbits(0), m_w1d(RAM_DESC, x)), kind, x)
            outs.append(f'{x}->{emu.fr(0)!r}')
        say(f'  1-D typecode 0x{tc:02X} ({kind}) cells {[cell(kind, dp + i * WIDTH[kind]) for i in range(4)]} '
            f'scale 0.5 bias 3.0: ' + '  '.join(outs))
        run(W_1D, regs={4: RAM_DESC}, fregs={4: 10.0})
        c1 = cell(kind, dp + WIDTH[kind])
        ok('textbook', emu.fr(0) == (c1 if tc == 0 else 0.5 * c1 + 3.0), 'scale/bias and sign', kind, emu.fr(0))
        # 2-D: 2 x 3 grid
        fresh()
        ax0 = put_axis_f([0.0, 10.0], RAM_AXIS)
        ax1 = put_axis_f([0.0, 100.0, 200.0], RAM_AXIS + 0x40)
        if kind == 'f32':
            vals = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0]
        elif WIDTH[kind] == 1:
            vals = [1, 2, 0x83, 0x84, 5, 6]
        else:
            vals = [1, 2, 0x8003, 0x8004, 5, 6]
        dp = put_data(kind, vals)
        poke(RAM_DESC, 2, 2)
        poke(RAM_DESC + 2, 2, 3)
        poke(RAM_DESC + 4, 4, ax0)
        poke(RAM_DESC + 8, 4, ax1)
        poke(RAM_DESC + 12, 4, dp)
        poke(RAM_DESC + 16, 1, tc)
        poke(RAM_DESC + 17, 1, 0)
        poke(RAM_DESC + 18, 2, 0)
        poke_f(RAM_DESC + 20, 2.0)
        poke_f(RAM_DESC + 24, -1.0)
        cells = [cell(kind, dp + k * WIDTH[kind]) for k in range(6)]
        outs = []
        for j, y in enumerate((0.0, 100.0, 200.0)):
            for i, x in enumerate((0.0, 10.0)):
                run(W_2D, regs={4: RAM_DESC}, fregs={4: x, 5: y})
                ok('model', same_f(fbits(0), m_w2d(RAM_DESC, x, y)), kind, x, y)
                c = cells[j * 2 + i]
                ok('textbook', emu.fr(0) == (c if tc == 0 else 2.0 * c - 1.0), '2-D order/sign/scale', kind, i, j)
                outs.append(f'({x},{y})->{emu.fr(0)!r}')
        for x, y in ((5.0, 50.0), (-1.0, 250.0), (11.0, -1.0)):
            run(W_2D, regs={4: RAM_DESC}, fregs={4: x, 5: y})
            ok('model', same_f(fbits(0), m_w2d(RAM_DESC, x, y)), kind, x, y)
            outs.append(f'({x},{y})->{emu.fr(0)!r}')
        say(f'  2-D typecode 0x{tc:02X} ({kind}) 2 x 3 cells {cells} scale 2.0 bias -1.0: ' + '  '.join(outs))
    # r4 on return from the typed wrappers (it is advanced on the scaled path only)
    fresh()
    ap = put_axis_f([0.0, 10.0])
    dp = put_data('u8', [1, 2])
    for tc, exp in ((0x04, 16), (0x00, 0)):
        poke(RAM_DESC, 2, 2)
        poke(RAM_DESC + 2, 1, tc)
        poke(RAM_DESC + 4, 4, ap)
        poke(RAM_DESC + 8, 4, dp if tc else ap)
        poke_f(RAM_DESC + 12, 1.0)
        poke_f(RAM_DESC + 16, 0.0)
        run(W_1D, regs={4: RAM_DESC}, fregs={4: 0.0})
        ok('textbook', emu.R[4] - RAM_DESC == exp, 'r4 after 0x0BE830', tc, emu.R[4] - RAM_DESC)
        say(f'  0x0BE830 typecode 0x{tc:02X}: r4 on return = record + {emu.R[4] - RAM_DESC}')


# ================================================================== PART D: existing claims put to the test
def part_d(good, info):
    say('\n=== PART D  existing claims tested (see COMPARISON section of the trace file) ===')
    # D1. disassembly/analysis/cl_ol_ramp_analysis.txt:69-72 calls 0x0BEB6C "a FLOOR/STEP lookup
    #     (NOT linear interpolation)". Record 0x0AD090: axis 0..8000 step 1000, uint16 cells
    #     100,100,100,100,100,50,50,37,37, scale 2^-15.  A step lookup would return 100 at 4500.
    d = 0x0AD090
    cells = [rd(rd(d + 8, 4) + 2 * i, 2) for i in range(rd(d, 2))]
    ok('textbook', rd(d + 2, 1) == 0x08 and cells == [100, 100, 100, 100, 100, 50, 50, 37, 37], 'D1 record')
    outs = []
    for x, want in ((4000.0, 100.0), (4250.0, 87.5), (4500.0, 75.0), (5000.0, 50.0), (6500.0, 43.5), (7000.0, 37.0)):
        run(W_1D, regs={4: d}, fregs={4: x})
        raw = emu.fr(0) * 32768.0
        outs.append(f'{x:.0f}->{raw:g}')
        ok('textbook', raw == want, 'D1 linear, not step', x, raw, want)
    print(f'  D1: record 0x0AD090 through 0x0BE830, result * 32768: {"  ".join(outs)}  -> LINEAR between cells')
    # D2. records passed to a fixed-type wrapper whose type byte is 0x00: the cell width is the
    #     wrapper's, and the bytes right after the wrapper-width extent belong to something else.
    all_ptrs = set()
    for w in WRAPPERS:
        for r in good[w]:
            all_ptrs.add(rd(r + 4, 4))
            all_ptrs.add(rd(r + 8, 4))
            if w in TWO_D:
                all_ptrs.add(rd(r + 12, 4))
    n = n_tight = n_gbr = 0
    per = []
    dead = {}
    for w in (W_1D_U8, W_1D_U16, W_1DI_U8, W_1DI_U16, W_2D_U8, W_2D_U16):
        two, width = w in TWO_D, WIDTH[FIXED[w]]
        here = []
        for r in good[w]:
            if rd(r + (16 if two else 2), 1) != 0:
                continue
            n += 1
            here.append(r)
            dead[r] = w
            via_gbr = r in info['gbr_only'][w]
            n_gbr += via_gbr
            cnt = rd(r, 2) * (rd(r + 2, 2) if two else 1)
            dp = rd(r + (12 if two else 8), 4)
            # does any pointer field of a record found by this script land inside the 4-byte-cell
            # extent but at or after the wrapper-width extent?  Then the float32 reading overlaps it.
            tight = any(dp + cnt * width <= p < dp + cnt * 4 for p in all_ptrs)
            n_tight += tight
            say(f'    record 0x{r:06X} -> wrapper 0x{w:06X} at ' + ' '.join(f'{p:06X}' for p in info["where"][(w, r)])
                + f': {cnt} cells x {width} byte(s) at 0x{dp:06X}'
                + ('   [through a GBR cell]' if via_gbr else '')
                + ('   (a 4-byte reading overlaps another record)' if tight else ''))
        per.append(f'{len(here)} via 0x{w:06X}')
        print(f'      0x{w:06X}: ' + ' '.join(f'{r:06X}' for r in here))
    n8 = sum(1 for r, w in dead.items() if FIXED[w] == 'u8')
    print(f'  D2: {n} records reach a fixed-type wrapper with type byte 0x00 ({", ".join(per)}; {n8} uint8, '
          f'{n - n8} uint16; {n - n_gbr} by register/stack propagation, {n_gbr} through the GBR cell at 0x0BBDCA); '
          f'for {n_tight} of them a float32 reading (4 bytes/cell) would run into another record\'s axis or data')
    ok('textbook', (n, n_gbr, n8) == (46, 2, 9) and n_tight > 0, 'D2', n, n_gbr, n8, n_tight)
    # every call site of the six fixed-type wrappers has its r4 resolved, so this list is complete for them
    ok('textbook', all(not info['unres'][w] for w in FIXED), 'fixed-type wrapper site with unknown r4')
    # the two GBR-cell records: the only calls between the store and the reload are 0x0BE830 and
    # 0x0BEAB0, and 0x0BEAB0 is four instructions without a store
    ok('textbook', [u16(a) for a in range(0x0BEAB0, 0x0BEAB8, 2)] == [0xF451, 0xF45D, 0x000B, 0xF04C], '0x0BEAB0')
    ok('textbook', info['where'][(W_1D_U16, 0x0AC26C)] == [0x0BBDCA] and info['where'][(W_1D_U16, 0x0AB458)] == [0x0BBDCA])
    info['dead'] = dead


# ================================================================== PART E: whole-ROM scans
def part_e(info):
    print('PART E  whole-ROM scans')
    flow = info['flow']
    entries15 = sorted(list(F1) + list(I1) + list(F2) + [SEARCH_F, SEARCH_I, SEARCH_2D])
    # E1. every long (any even address) equal to one of the 15 entries
    slots = {0x0BE860 + tc: h for tc, h in zip((0, 4, 8, 12, 16), (0x0BEACC, 0x0BEB20, 0x0BEB6C, 0x0BEAE4, 0x0BEB00))}
    slots.update({0x0BE914 + tc: h for tc, h in zip((0, 4, 8, 12, 16), (0x0BEBC0, 0x0BEC4C, 0x0BEC78, 0x0BEBF0, 0x0BEC1C))})
    found = {a: u32(a) for a in range(0, len(ROM) - 3, 2) if u32(a) in entries15}
    extra = {a: v for a, v in found.items() if a not in slots}
    print(f'  E1: longs equal to one of the 15 entries: {len(found)}; the ten handler-table slots, plus '
          + ', '.join(f'0x{a:06X} = 0x{v:08X}' for a, v in sorted(extra.items())))
    ok('textbook', all(found.get(a) == v for a, v in slots.items()) and extra == {0x0FFBC8: 0x000BEB00}, 'E1', extra)
    hi8 = [a for a, v in found.items() if v in (0x0BEAE4, 0x0BEB00, 0x0BEBF0, 0x0BEC1C)]
    ok('textbook', sorted(hi8) == [0x0BE86C, 0x0BE870, 0x0BE920, 0x0BE924, 0x0FFBC8], 'int8/int16 handler longs')
    # E2. 0x0FFBC8 is the START field of record 6 of the ECU checksum table (17 records of
    #     (start, end, stored) at 0x0FFB80; a record passes when sum(longs start..end) + stored
    #     == 0x5AA5A55A -- scripts/rom_checksum.py)
    idx, rem = divmod(0x0FFBC8 - 0x0FFB80, 12)
    s, e, c = u32(0x0FFBC8), u32(0x0FFBCC), u32(0x0FFBD0)
    tot = (sum(u32(a) for a in range(s, e, 4)) + c) & M32
    print(f'  E2: 0x0FFBC8 = 0x0FFB80 + {idx}*12 + {rem}: record {idx} = (0x{s:06X}, 0x{e:06X}, 0x{c:08X}); '
          f'sum of longs 0x{s:06X}..0x{e:06X} + stored = 0x{tot:08X}')
    ok('textbook', (idx, rem, s, e, tot) == (6, 0, 0x0BEB00, 0x0BF5FF, 0x5AA5A55A), 'checksum record 6')
    # E3. every bsr (in reached code) whose target is one of the 15 entries, and every jsr / jmp
    #     whose register holds one
    bsr = collections.defaultdict(list)
    other = []
    for pc, (tg, _, kind) in sorted(flow.sites.items()):
        for t in tg or ():
            if t in entries15:
                (bsr[t].append(pc) if kind == 'bsr' else other.append((pc, kind, t)))
    want = {0x0BEACC: [0x0BEBD0, 0x0BEBDE], 0x0BEAE4: [0x0BEBFE, 0x0BEC0C], 0x0BEB00: [0x0BEC2C, 0x0BEC3A],
            0x0BEB20: [0x0BE87E, 0x0BEC5A, 0x0BEC68], 0x0BEB40: [0x0BE89C], 0x0BEB6C: [0x0BE8B6, 0x0BEC88, 0x0BEC96],
            0x0BEB90: [0x0BE8D4], 0x0BEC4C: [0x0BE932], 0x0BEC78: [0x0BE94E],
            SEARCH_F: [0x0BE836, 0x0BE87A, 0x0BE8B2, 0x0BED9E, 0x0BEDAA], SEARCH_I: [0x0BE896, 0x0BE8CE],
            SEARCH_2D: [0x0BE8E8, 0x0BE92C, 0x0BE948]}
    for t in entries15:
        say(f'    0x{t:06X}: bsr from ' + (' '.join(f'{p:06X}' for p in bsr.get(t, [])) or '(none: table slot only)'))
    print(f'  E3: bsr sites to the 15 entries: {sum(len(v) for v in bsr.values())}, all inside 0x0BE830..0x0BEDB7; '
          f'jsr/jmp/bra to them: {len(other)}.  0x0BEB40 and 0x0BEB90 have exactly one caller each '
          f'(0BE89C, 0BE8D4) and no pointer anywhere')
    ok('textbook', dict(bsr) == want and not other, 'E3', {hex(k): [hex(p) for p in v] for k, v in bsr.items()}, other)
    # E4. is there ANY typed record with typecode 0x0C / 0x10 in the ROM?  Structural search at every
    #     even address, independent of call sites.
    def asc(p, n):
        v = [E.b2f(u32(p + 4 * i)) for i in range(n)]
        return all(x == x and abs(x) < 1e30 for x in v) and all(b > a for a, b in zip(v, v[1:]))

    def cand(types, need_axis):
        one, two = [], []
        for d in range(0, len(ROM) - 28, 2):
            n0 = u16(d)
            if not 1 <= n0 <= 256:
                continue
            if ROM[d + 2] in types and ROM[d + 3] == 0:
                ap, dp, w = u32(d + 4), u32(d + 8), WIDTH[TC_NAME[ROM[d + 2]]]
                if in_rom(ap, 4 * n0) and in_rom(dp, w * n0) and ap % 4 == 0 and (not need_axis or (n0 >= 2 and asc(ap, n0))):
                    one.append(d)
            n1 = u16(d + 2)
            if 1 <= n1 <= 256 and ROM[d + 16] in types:
                a0, a1, dp, w = u32(d + 4), u32(d + 8), u32(d + 12), WIDTH[TC_NAME[ROM[d + 16]]]
                if (in_rom(a0, 4 * n0) and in_rom(a1, 4 * n1) and in_rom(dp, w * n0 * n1) and a0 % 4 == 0
                        and a1 % 4 == 0 and (not need_axis or (n0 >= 2 and n1 >= 2 and asc(a0, n0) and asc(a1, n1)))):
                    two.append(d)
        return one, two

    loose = cand((0x0C, 0x10), False)
    strict = cand((0x0C, 0x10), True)
    ctrl = cand((0x04, 0x08), True)
    print(f'  E4: positions that are structurally a typed record with typecode 0x0C/0x10: pointers in ROM '
          f'{len(loose[0])} 1-D + {len(loose[1])} 2-D ({", ".join(f"0x{d:06X}" for d in loose[0] + loose[1])}: '
          f'a literal pool, its "axis" 0x{u32(0x03B79C + 4):06X} is not ascending); with ascending axes '
          f'{len(strict[0])} + {len(strict[1])}.  Control, same test with 0x04/0x08: {len(ctrl[0])} + {len(ctrl[1])}')
    ok('textbook', strict == ([], []) and loose == ([0x03B79C], []) and len(ctrl[0]) > 400 and len(ctrl[1]) > 100, 'E4')
    # E5. every load of FPSCR in reached code, with the constant loaded
    loads = []
    for pc in sorted(flow.IN):
        w = u16(pc)
        if (w & 0xF0FF) == 0x406A:                   # lds Rn,fpscr
            v = flow.IN[pc][0][(w >> 8) & 15]
            loads.append((pc, 'lds', None if v is None else sorted(v)))
        elif (w & 0xF0FF) == 0x4066:                 # lds.l @Rn+,fpscr
            loads.append((pc, 'lds.l', None))
    lds = [(pc, v) for pc, k, v in loads if k == 'lds']
    pops = [pc for pc, k, _ in loads if k == 'lds.l']
    print('  E5: FPSCR loads in reached code: '
          + '; '.join(f'{pc:06X} lds = ' + ('?' if v is None else '/'.join(f'0x{x:08X}' for x in v)) for pc, v in lds)
          + f'; {len(pops)} lds.l @r15+,fpscr (restores of a saved value) at ' + ' '.join(f'{p:06X}' for p in pops))
    ok('textbook', lds == [(0x00FA44, [0x00040001]), (0x05873E, [0x00000000])], 'FPSCR loads', lds)
    ok('textbook', all(((u16(p) >> 8) & 15) == 15 for p in pops), 'fpscr pop not from the stack')
    print('      RM field (bits 1-0): 01 at 0x00FA44, 00 at 0x05873E; bits 11-7 are 0 in both values.')


# ================================================================== PART R: rounding
def part_r(good):
    print('PART R  the same ROM bytes under four float arithmetics '
          '(stock = toward zero, fmac rounded once: the chip\'s direction, item 106)')
    alts = [Exact(False, True), Exact(False, False), Exact(True, False)]
    ems = [EmuX(ROM, ar) for ar in alts]
    ref = alts[0]
    fixed1 = ([(W_1D_U8, d, 'u8', 0xFF) for d in good[W_1D_U8]]
              + [(W_1D_U16, d, 'u16', 0xFFFF) for d in good[W_1D_U16]])
    fixed2 = ([(W_2D_U8, d, 'u8', 0xFF) for d in good[W_2D_U8]]
              + [(W_2D_U16, d, 'u16', 0xFFFF) for d in good[W_2D_U16]])

    def axis_of(d, off=4, cnt=0):
        p = rd(d + off, 4)
        return [rf(p + 4 * i) for i in range(rd(d + cnt, 2))]

    def few_1d(axis):
        xs = [axis[0], nxt(axis[0], False), f32(axis[-1] + 1.0)]
        if len(axis) > 1:
            xs += [f32(axis[0] + (axis[1] - axis[0]) * 0.3), f32((axis[-2] + axis[-1]) / 2)]
        return xs

    # R0. the toward-zero arm of the exact-rational layer is the MODEL of parts A-E, bit-exact against
    #     the stock emulator (sh2e_emu.rz_bits) there.  Its round-to-nearest arm has no such check, so
    #     it must reproduce an independent implementation of nearest -- Python's double arithmetic
    #     rounded to float32 (Dbl) -- otherwise the two nearest alternatives below cannot be trusted.
    #     Plus a direct check of round_bits(toward zero) against sh2e_emu.rz_bits at the edges.
    n0 = bad0 = 0
    for w, d, kind, mask in fixed1:
        for x in grid_f(axis_of(d)):
            n0 += 1
            bad0 += with_ar(ref, m_fixed_1d, d, kind, mask, x) != with_ar(DBL, m_fixed_1d, d, kind, mask, x)
    for d in good[W_1D]:
        for x in grid_f(axis_of(d)):
            n0 += 1
            bad0 += E.f2b(with_ar(ref, m_w1d, d, x)) != E.f2b(with_ar(DBL, m_w1d, d, x))
    print(f'  R0: exact-rational arithmetic set to nearest / rounded once vs python double arithmetic '
          f'rounded to nearest: {n0} inputs, {bad0} differences')
    ok('textbook', bad0 == 0, 'R0', bad0)
    edge = [Fr(1), Fr(-1), Fr(6, 10), Fr(-6, 10), Fr(1, 3), Fr(2) ** 128, -Fr(2) ** 128, Fr(2) ** -127,
            -Fr(2) ** -127, Fr(2) ** -126, Fr(2 ** 24 - 1, 2 ** 24) * Fr(2) ** 128, Fr(2 ** 25 - 1, 2),
            Fr(123456789, 1000), Fr(-987654321, 7)]
    edge += [Fr(E.b2f(b)) * Fr(k, 7) for b in (0x3F800001, 0x4B7FFFFF, 0x00800000, 0x7F7FFFFF) for k in (3, 6, 8, 13)]
    bad_rz = [q for q in edge if round_bits(q, True) != E.rz_bits(q)]
    print(f'  R0: round_bits(toward zero) vs sh2e_emu.rz_bits on {len(edge)} edge values (overflow, flush, '
          f'mantissa carry, tie-like): {len(bad_rz)} differences')
    ok('textbook', not bad_rz, 'R0 rz_bits', bad_rz)

    # R1. ROM code executed under each alternative == the transcription under that alternative
    for ar, em in zip(alts, ems):
        m0, t0, c0 = checks['model'], checks['textbook'], TOTAL[1]
        for w, d, kind, mask in fixed1:
            axis = axis_of(d)
            raw = [cell(kind, rd(d + 8, 4) + i * WIDTH[kind]) for i in range(len(axis))]
            mono = strictly_up(axis)
            for x in grid_f(axis):
                run(w, regs={4: d}, fregs={4: x}, em=em)
                ok('model', em.R[0] == with_ar(ar, m_fixed_1d, d, kind, mask, x), ar.name, hex(d), x)
                if mono and (x < axis[0] or x >= axis[-1] or x in axis):
                    i = 0 if x < axis[0] else len(axis) - 1 if x >= axis[-1] else axis.index(x)
                    ok('textbook', em.R[0] == raw[i], 'cell/clamp', ar.name, hex(d), x)
        for w, d, kind, mask in fixed2:
            ax0, ax1 = axis_of(d), axis_of(d, 8, 2)
            for y in few_1d(ax1):
                for x in few_1d(ax0):
                    run(w, regs={4: d}, fregs={4: x, 5: y}, em=em)
                    ok('model', em.R[0] == with_ar(ar, m_fixed_2d, d, kind, mask, x, y), ar.name, hex(d), x, y)
        for d in good[W_1D]:
            for x in few_1d(axis_of(d)):
                run(W_1D, regs={4: d}, fregs={4: x}, em=em)
                ok('model', same_f(em.FR[0], with_ar(ar, m_w1d, d, x)), ar.name, hex(d), x)
        for d in good[W_2D]:
            ax0, ax1 = axis_of(d), axis_of(d, 8, 2)
            px, py = interior_2d(ax0, ax1)
            for x, y in ((px[0], py[0]), (px[-1], py[-1]), (ax0[0], ax1[-1])) if px and py else ((ax0[0], ax1[-1]),):
                run(W_2D, regs={4: d}, fregs={4: x, 5: y}, em=em)
                ok('model', same_f(em.FR[0], with_ar(ar, m_w2d, d, x, y)), ar.name, hex(d), x, y)
        print(f'  R1: [{ar.name}] {TOTAL[1] - c0} calls of the six float-path wrappers on real records: '
              f'{checks["model"] - m0} bit-exact against the transcription, '
              f'{checks["textbook"] - t0} cell / clamp checks')

    # R2. integer results of the four ftrc wrappers on a k/60 grid inside every interval, through the
    #     transcriptions (validated in B and R1); every difference is then re-run on the ROM code
    def confirm(w, regs_f, base, t, v):
        run(w, regs={4: regs_f[0]}, fregs=regs_f[1])
        ok('model', emu.R[0] == base, 'R2 confirm stock', hex(regs_f[0]))
        run(w, regs={4: regs_f[0]}, fregs=regs_f[1], em=ems[t])
        ok('model', ems[t].R[0] == v, 'R2 confirm', alts[t].name, hex(regs_f[0]))

    tot1, diff1, big, ex = 0, [0, 0, 0], 0, []
    recs1 = 0
    for w, d, kind, mask in fixed1:
        axis = axis_of(d)
        if len(axis) < 2 or not strictly_up(axis):
            continue
        recs1 += 1
        for k in range(len(axis) - 1):
            for j in range(1, 60):
                x = f32(axis[k] + (axis[k + 1] - axis[k]) * j / 60)
                base = m_fixed_1d(d, kind, mask, x)
                tot1 += 1
                for t, ar in enumerate(alts):
                    v = with_ar(ar, m_fixed_1d, d, kind, mask, x)
                    if v != base:
                        diff1[t] += 1
                        big = max(big, abs(v - base))
                        confirm(w, (d, {4: x}), base, t, v)
                        if t in (0, 2) and sum(e.startswith(f'[{ar.name}]') for e in ex) < 3:
                            # t=0 tells nearest from toward zero; t=2 tells fused fmac from product-first
                            ex.append(f'[{ar.name}] 0x{w:06X} record 0x{d:06X} x={x!r}: stock {base} -> {v}')
    print(f'  R2: 0x0BE874 / 0x0BE8AC, {tot1} inputs (k/60 inside every interval of {recs1} records): the integer '
          f'result differs from the stock emulator\'s in {diff1[0]} [{alts[0].name}], {diff1[1]} [{alts[1].name}], '
          f'{diff1[2]} [{alts[2].name}]; largest difference {big} count')
    for e in ex:
        say('      e.g. ' + e)
    ok('textbook', big == 1 and diff1[0] > 0, 'R2', big, diff1)
    # the reviewer's witness, on the ROM code itself: record 0x0AB2A4 at x = -14.0.  The exact value
    # is 121; toward zero (the chip) returns it, nearest returns 120.
    d, x = 0x0AB2A4, -14.0
    run(W_1D_U8, regs={4: d}, fregs={4: x})
    stock = emu.R[0]
    res = []
    for ar, em in zip(alts, ems):
        run(W_1D_U8, regs={4: d}, fregs={4: x}, em=em)
        res.append(em.R[0])
    axis = axis_of(d)
    cells = [rd(rd(d + 8, 4) + i, 1) for i in range(len(axis))]
    print(f'      witness: record 0x0AB2A4 (axis {axis}, cells {cells}) at x = -14.0 through 0x0BE874: stock emulator '
          f'{stock}; {alts[0].name} {res[0]}; {alts[1].name} {res[1]}; {alts[2].name} {res[2]}; '
          f'exact value {cells[0]} + 0.6*({cells[1]} - {cells[0]}) = '
          f'{float(Fr(cells[0]) + Fr(6, 10) * (cells[1] - cells[0]))!r}')
    ok('textbook', (stock, res[0], res[1], res[2]) == (121, 120, 120, 121) and axis[:2] == [-20.0, -10.0]
       and Fr(cells[0]) + Fr(6, 10) * (cells[1] - cells[0]) == 121, 'witness', stock, res)
    tot2, diff2, big2 = 0, [0, 0, 0], 0
    for w, d, kind, mask in fixed2:
        ax0, ax1 = axis_of(d), axis_of(d, 8, 2)
        if not (strictly_up(ax0) and strictly_up(ax1)):
            continue
        for b in range(len(ax1) - 1):
            for a in range(len(ax0) - 1):
                for jy in range(1, 5):
                    for jx in range(1, 5):
                        x = f32(ax0[a] + (ax0[a + 1] - ax0[a]) * jx / 5)
                        y = f32(ax1[b] + (ax1[b + 1] - ax1[b]) * jy / 5)
                        base = m_fixed_2d(d, kind, mask, x, y)
                        tot2 += 1
                        for t, ar in enumerate(alts):
                            v = with_ar(ar, m_fixed_2d, d, kind, mask, x, y)
                            if v != base:
                                diff2[t] += 1
                                big2 = max(big2, abs(v - base))
                                confirm(w, (d, {4: x, 5: y}), base, t, v)
    print(f'      0x0BE928 / 0x0BE944, {tot2} inputs (fifths inside every cell of {len(fixed2)} records): differs in '
          f'{diff2[0]}, {diff2[1]}, {diff2[2]} (same order); largest difference {big2} count')
    ok('textbook', big2 <= 1, 'R2 2-D', big2)

    # R3. float results of the two typed wrappers at interior inputs: how many bit patterns move
    def magnitude(d, two):
        """|scale| * max|raw cell| + |bias|: the size of the numbers the record produces."""
        tc = rd(d + (16 if two else 2), 1)
        kind = TC_NAME[tc]
        n = rd(d, 2) * (rd(d + 2, 2) if two else 1)
        dp = rd(d + (12 if two else 8), 4)
        top = max(abs(float(cell(kind, dp + k * WIDTH[kind]))) for k in range(n))
        off = 20 if two else 12
        return (top * abs(rf(d + off)) + abs(rf(d + off + 4))) if tc else top

    for label, recs, two in (('0x0BE830', good[W_1D], False), ('0x0BE8E4', good[W_2D], True)):
        tot, diff, far, conf = 0, [0, 0, 0], [0.0, 0.0, 0.0], [0, 0, 0]
        for d in recs:
            mag = magnitude(d, two) or 1.0
            if two:
                ax0, ax1 = axis_of(d), axis_of(d, 8, 2)
                if not (strictly_up(ax0) and strictly_up(ax1)):
                    continue
                px, py = interior_2d(ax0, ax1)
                pts = [(x, y) for x in px for y in py]
            else:
                axis = axis_of(d)
                if not strictly_up(axis):
                    continue
                pts = [(x,) for x in grid_f(axis) if axis[0] < x < axis[-1] and x not in axis]
            fn, entry = (m_w2d, W_2D) if two else (m_w1d, W_1D)
            for p in pts:
                base = E.f2b(fn(d, *p))
                tot += 1
                for t, ar in enumerate(alts):
                    v = E.f2b(with_ar(ar, fn, d, *p))
                    if v != base:
                        diff[t] += 1
                        far[t] = max(far[t], abs(E.b2f(v) - E.b2f(base)) / mag)
                        if conf[t] < 40:                 # a sample of the differences, on the ROM code
                            conf[t] += 1
                            fr = {4: p[0], 5: p[1]} if two else {4: p[0]}
                            run(entry, regs={4: d}, fregs=fr)
                            ok('model', emu.FR[0] == base, 'R3 stock', hex(d), p)
                            run(entry, regs={4: d}, fregs=fr, em=ems[t])
                            ok('model', ems[t].FR[0] == v, 'R3', alts[t].name, hex(d), p)
        print(f'  R3: {label}, {tot} interior inputs on real records: the float result differs in bits from the '
              f'stock emulator\'s in '
              + ', '.join(f'{diff[t]} (largest {far[t]:.1e} of the record\'s magnitude) [{alts[t].name}]'
                          for t in range(3)))
        ok('textbook', max(far) < 1e-5, 'R3 difference larger than rounding', far)


# ================================================================== PART F: definitions (report only)
def part_f(good):
    print('PART F  definition XMLs joined on the DATA pointer (report only; no assertion)')
    try:
        import defs
        dd = defs.load()
    except Exception as exc:                             # noqa: BLE001
        print(f'  skipped: scripts/defs.py could not load the definitions ({exc})')
        return
    st_kind = {'uint8': 'u8', 'uint16': 'u16', 'float': 'f32', 'int8': 'i8', 'int16': 'i16'}

    def code_kind(w, r):
        return FIXED[w] if w in FIXED else TC_NAME[rd(r + (16 if w in TWO_D else 2), 1)]

    one = collections.Counter()
    two = collections.Counter()
    notes, stubs = [], []
    for w in WRAPPERS:
        for r in good[w]:
            dp = rd(r + (12 if w in TWO_D else 8), 4)
            for t in dd.at(dp):
                if getattr(t, 'address', None) != dp or getattr(t, 'scaling', None) is None:
                    continue
                if not t.readable:                       # an entry scripts/defs.py itself cannot read
                    stubs.append(f'0x{dp:06X} {t.name!r} ({t.scaling.storagetype}, no geometry) -- code: record '
                                 f'0x{r:06X}, {code_kind(w, r)} cells')
                    continue
                c = two if w in TWO_D else one
                c['named'] += 1
                c['fixed-type wrapper'] += w in FIXED
                same = st_kind.get(t.scaling.storagetype) == code_kind(w, r)
                c['storagetype agrees'] += same
                if not same:
                    notes.append(f'storagetype {t.scaling.storagetype} vs code {code_kind(w, r)}: 0x{r:06X} {t.name!r}')
                if w in TWO_D:
                    xa, ya = t.x_axis, t.y_axis
                    if xa is None or ya is None or xa.address is None or ya.address is None:
                        c['axis not addressed'] += 1
                    elif (xa.address, ya.address) == (rd(r + 4, 4), rd(r + 8, 4)):
                        c['X = +4 and Y = +8'] += 1
                    elif (xa.address, ya.address) == (rd(r + 8, 4), rd(r + 4, 4)):
                        c['X = +8 and Y = +4'] += 1
                        notes.append(f'axes swapped: 0x{r:06X} {t.name!r}')
                    else:
                        c['axes elsewhere'] += 1
                else:
                    ax = [a for a in t.axes if a.address is not None]
                    if ax:
                        c['axis = +4' if ax[0].address == rd(r + 4, 4) else 'axis elsewhere'] += 1
    print(f'  1-D records with a definition on the data pointer: {dict(one)}')
    print(f'  2-D records with a definition on the data pointer: {dict(two)}')
    for n in notes[:12]:
        print('    ' + n)
    for n in stubs:
        print('    unreadable definition entry on a record\'s data address: ' + n)


# ================================================================== PART G: derived artefacts (report only)
def part_g(good, info):
    print('PART G  derived artefacts compared with the consumers found here (report only; no assertion)')
    typed = set(good[W_1D]) | set(good[W_2D])
    dead = info['dead']
    path = os.path.join(REPO, 'disassembly', 'maps', 'descriptor_map.txt')
    try:
        rows = re.findall(r'^\s*\d+\s+0x([0-9A-Fa-f]{6})\s+[12]D\s+\S+\s+(\w+)', open(path).read(), re.M)
    except OSError as exc:
        rows = []
        print(f'  descriptor_map.txt not readable ({exc})')
    if rows:
        f32rows = [int(a, 16) for a, t in rows if t == 'float32']
        in_typed = [a for a in f32rows if a in typed]
        in_dead = [a for a in f32rows if a in dead]
        missing = sorted(set(dead) - set(int(a, 16) for a, _ in rows))
        n8 = sum(1 for a in in_dead if FIXED[dead[a]] == 'u8')
        print(f'  descriptor_map.txt: {len(rows)} rows, {len(f32rows)} typed float32: {len(in_typed)} reach a typed '
              f'wrapper (float32 stands), {len(in_dead)} reach a fixed-type wrapper ({n8} uint8, {len(in_dead) - n8} '
              f'uint16 by code), {len(f32rows) - len(in_typed) - len(in_dead)} have no consumer found here; '
              f'dead-typecode records with no row at all: {[f"0x{a:06X}" for a in missing]}')
        say('    float32 rows that are 1- or 2-byte by code: ' + ' '.join(f'{a:06X}' for a in sorted(in_dead)))
    path = os.path.join(REPO, 'docs', 'verification-status.json')
    try:
        ents = json.load(open(path))['entities']
    except (OSError, ValueError, KeyError) as exc:
        print(f'  verification-status.json not readable ({exc})')
        return
    wrong = over = 0
    seen = set()
    by_addr = collections.defaultdict(list)
    for e in ents:
        if isinstance(e.get('address'), str):
            try:
                by_addr[int(e['address'], 16)].append(e)
            except ValueError:
                pass
        m = re.search(r'\(desc 0x([0-9A-Fa-f]+)\)', e.get('name', ''))
        g = e.get('geometry') or {}
        if e.get('kind') != 'rom-block' or not m or 'bytes_per_cell' not in g:
            continue
        r = int(m.group(1), 16)
        if r in dead:
            seen.add(r)
            w = WIDTH[FIXED[dead[r]]]
            if g['bytes_per_cell'] != w:
                wrong += 1
                over += g.get('cells', 0) * (g['bytes_per_cell'] - w)
    named, none = [], []
    for r in sorted(set(dead) - seen):
        dp = rd(r + (12 if dead[r] in TWO_D else 8), 4)
        (named if any(e.get('kind') == 'table' for e in by_addr.get(dp, [])) else none).append(r)
    print(f'  verification-status.json: {len(seen)} of the {len(dead)} dead-typecode records have a rom-block entity; '
          f'{wrong} of those state a cell width the consuming wrapper does not use ({over} bytes over-claimed); '
          f'{len(named)} are definition-named table entities ({" ".join(f"0x{r:06X}" for r in named)}); '
          f'{len(none)} have no entity on their data address ({" ".join(f"0x{r:06X}" for r in none)})')


def main():
    part0()
    a_search_f()
    a_search_i()
    a_interp_f()
    a_interp_i()
    a_interp_2d()
    a_search_2d()
    clobbers()
    na = dict(checks)
    print(f'PART A (direct calls, synthetic tables): {na["model"]} model checks, {na["textbook"]} textbook checks')

    good, info = find_records()
    by1 = b_typed_1d(good[W_1D])
    by2 = b_typed_2d(good[W_2D])
    b_fixed_1d(good[W_1D_U8], good[W_1D_U16])
    b_int_axis(good[W_1DI_U8], good[W_1DI_U16])
    b_fixed_2d(good[W_2D_U8], good[W_2D_U16])
    part_c(by1, by2)
    part_d(good, info)
    part_e(info)
    for kind in ('f32', 'u8', 'u16'):
        assert by1.get(kind) and by2.get(kind), f'no real {kind} record exercised'
    ab = (checks['model'], checks['textbook'], TOTAL[1], TOTAL[0])
    print(f'PARTS 0-E: {ab[0]} bit-exact model checks, {ab[1]} textbook checks, {ab[2]} emulated calls, '
          f'{ab[3]} instructions emulated (stock emulator arithmetic: toward zero, fmac rounded once)')
    part_r(good)
    part_f(good)
    part_g(good, info)
    print(f'TOTAL: {checks["model"]} bit-exact model checks, {checks["textbook"]} textbook checks, '
          f'{TOTAL[1]} emulated calls, {TOTAL[0]} instructions emulated, 0 failures')
    print('emulator notes:')
    for n in sorted(emu.notes):
        print('  ' + n)
    return 0


if __name__ == '__main__':
    sys.exit(main())
