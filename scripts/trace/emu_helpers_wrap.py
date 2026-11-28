#!/usr/bin/env python3
"""Emulation checks for disassembly/analysis/helpers_wrap_trace.txt.

    python3 scripts/trace/emu_helpers_wrap.py            # prints tables, exits 0 when every contract holds
    python3 scripts/trace/emu_helpers_wrap.py --quiet    # summary lines only
    python3 scripts/trace/emu_helpers_wrap.py --numbers  # also print the QUOTED table (see below)

Runtime helper library B, every function entry in 0x0BE81C..0x0BEACB of
"rom/AE5L600L 20g rev 20.19c.bin" (md5 92cae8275cd4f9b473a3a9e36efe6449):

    0BE81C 0BE82C                    interrupt-mask raise / SR restore
    0BE830 0BE874 0BE88C 0BE8AC 0BE8C4      1-D table wrappers
    0BE8E4 0BE928 0BE944                    2-D table wrappers
    0BE960 0BE970                    float larger / smaller
    0BE980 0BE990 0BE9A0 0BE9B0      value+complement check / build
    0BE9C0 0BEA98                    saturating 16.16 multiply, saturating subtract
    0BEA40 0BEA6C                    first-order lag, float and integer
    0BEAB0 0BEAB8                    |a-b|, busy-wait

HOW TO READ IT
Each section states a contract as a small Python MODEL written from the bytes
(the listing in the analysis file), runs the ROM routine in scripts/sh2e_emu.py
over a grid, and asserts the two agree BIT FOR BIT.  For the float-returning
table wrappers there is a second, independent oracle: desc_types.read_table()
plus plain linear / bilinear interpolation of the PHYSICAL values (tolerance
compare, because the ROM interpolates raw cells and scales afterwards).

ROUNDING: THE MODELS DO WHAT THE CHIP DOES.  Reset loads FPSCR = 0x00040001
(RM = 01, round TOWARD ZERO; DN = 1) and the ROM's own FPU self-test
(0x0586A2..0x0586DA) compares against truncated results (section N).  Every
model below therefore computes each FPU result EXACTLY (fractions.Fraction) and
truncates it to float32 with this script's own to_bits(q, 'rz') -- not with
sh2e_emu's rounding routine -- and fmac is FUSED (one rounding).  sh2e_emu has
done the same since corrections item 106 (before that it rounded to nearest and
this script modelled that).  Section N measures what the other choices would
change: round-to-nearest (the old emulator) and an unfused fmac.  Whether the
chip's fmac is fused is NOT settled by the self-test; that is the one rounding
question left open.  Test INPUTS written as Python floats are converted to
float32 with f32() (nearest), exactly as sh2e_emu loads them: that is the
choice of input, not arithmetic.

WHERE THE TABLE RECORDS COME FROM (section S).  Two sweeps, merged:
  method 1  find_call_sites(): forward dataflow, strict (first pass of this trace);
  method 2  pool_sites() + make_resolver(): follow each loaded helper address
            forward to its jsr / jmp, then walk backward from the call to the
            literals that reach r4 (third pass).
Method 1 must never find a literal that method 2 does not (asserted).  BOTH ARE
LOWER BOUNDS: a record that reaches a wrapper through a ROM pointer table, a
GBR slot or the stack is invisible to a literal sweep (two such call sites are
decoded and asserted in section S).

NUMBERS.  Every count the analysis file quotes is registered with quoted() and
compared with the QUOTED table below; a difference fails the run.

Section O reads two files besides the ROM, for comparison only: the definition
XMLs through scripts/defs.py (which record pointer is the definition's X axis)
and disassembly/maps/descriptor_map.txt, a derived file (which rows it types
float32).  Neither feeds any contract.  No label, doc or function census is read.
desc_types.read_table() is used as the tolerance oracle (sections C, F) and is
compared on the integer-wrapper records (sections D, H); since corrections item
106 it reads disassembly/maps/fixed_type_records.json for those records.  That
comparison feeds no contract either.

WHAT THE EMULATOR CANNOT RUN
`ldc Rn,sr` raises in sh2e_emu.  0x0BE81C is therefore emulated up to its rts
(0x0BE828) with the SR value injected, and the final `ldc r5,sr` /
0x0BE82C's `ldc r4,sr` are established from the decoded bytes only.
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
import sh2e_disasm as D       # noqa: E402
import desc_types as T        # noqa: E402

ROM_PATH = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
ROM_MD5 = '92cae8275cd4f9b473a3a9e36efe6449'
M32 = 0xFFFFFFFF
QUIET = '--quiet' in sys.argv
RESULTS = []                  # (section, ok, detail)
# Every number helpers_wrap_trace.txt quotes from this script.  quoted() registers what the run computes and
# main() fails when one differs, so the prose cannot drift from the script.  Regenerate with --numbers.
QUOTED = {
    'sites_0BE830': 680,
    'lit_sites_0BE830': 657,
    'records_0BE830': 673,
    'm1_records_0BE830': 629,
    'sites_0BE874': 22,
    'lit_sites_0BE874': 22,
    'records_0BE874': 23,
    'm1_records_0BE874': 23,
    'sites_0BE88C': 1,
    'lit_sites_0BE88C': 1,
    'records_0BE88C': 1,
    'm1_records_0BE88C': 1,
    'sites_0BE8AC': 47,
    'lit_sites_0BE8AC': 46,
    'records_0BE8AC': 45,
    'm1_records_0BE8AC': 44,
    'sites_0BE8C4': 6,
    'lit_sites_0BE8C4': 6,
    'records_0BE8C4': 5,
    'm1_records_0BE8C4': 5,
    'sites_0BE8E4': 193,
    'lit_sites_0BE8E4': 171,
    'records_0BE8E4': 187,
    'm1_records_0BE8E4': 183,
    'sites_0BE928': 1,
    'lit_sites_0BE928': 1,
    'records_0BE928': 1,
    'm1_records_0BE928': 1,
    'sites_0BE944': 6,
    'lit_sites_0BE944': 6,
    'records_0BE944': 5,
    'm1_records_0BE944': 5,
    'sites_0BEAB8': 12,
    'sites_0BEA40': 162,
    'sites_0BEA6C': 11,
    'unreached_sites': 17,
    'only2_0BE81C': 24,
    'only2_0BE82C': 27,
    'only2_0BE830': 37,
    'only2_0BE874': 0,
    'only2_0BE88C': 0,
    'only2_0BE8AC': 1,
    'only2_0BE8C4': 0,
    'only2_0BE8E4': 4,
    'only2_0BE928': 0,
    'only2_0BE944': 0,
    'only2_0BEA40': 4,
    'only2_0BEA6C': 0,
    'only2_0BEAB8': 1,
    'nolit_sites_0BE830': 23,
    'nolit_0BE830_copy_r0,r4': 7,
    'nolit_0BE830_indexed_@(r0,Rm),r4': 13,
    'nolit_0BE830_load_@(d,Rm),r4': 3,
    'nolit_sites_0BE8E4': 22,
    'nolit_0BE8E4_copy_r0,r4': 13,
    'nolit_0BE8E4_indexed_@(r0,Rm),r4': 8,
    'nolit_0BE8E4_load_@(d,Rm),r4': 1,
    'nolit_sites_0BE8AC': 1,
    'nolit_0BE8AC_copy_r0,r4': 1,
    'A_cases': 240,
    'A_lowered': 36,
    'sites_0BE81C': 355,
    'sites_0BE82C': 348,
    'r5_E0_reaches': 355,
    'r5_E0_only': 350,
    'slot_mov_r15_r4': 124,
    'slot_extu_b_r5': 91,
    'slot_pop_r4': 185,
    'slot_disp_r4': 145,
    'slot_nop': 18,
    'C_tc_00': 159,
    'C_tc_04': 187,
    'C_tc_08': 327,
    'C_tc_0C': 0,
    'C_tc_10': 0,
    'C_points': 29804,
    'C_oracle_records': 669,
    'C_oracle_points': 29791,
    'D_points_0BE874': 1441,
    'D_byte2_0BE874_00': 7,
    'D_byte2_0BE874_04': 16,
    'D_points_0BE8AC': 2050,
    'D_byte2_0BE8AC_00': 25,
    'D_byte2_0BE8AC_08': 20,
    'D_records': 68,
    'D_facevalue_differ_exact': 67,
    'D_facevalue_differ_1e6': 56,
    'E_points_0BE88C': 30,
    'E_points_0BE8C4': 103,
    'F_tc_00': 30,
    'F_tc_04': 74,
    'F_tc_08': 83,
    'F_tc_0C': 0,
    'F_tc_10': 0,
    'F_points': 13209,
    'F_oracle_records': 187,
    'F_oracle_points': 13209,
    'G_points_0BE928': 81,
    'G_points_0BE944': 351,
    'H_n_0BE830 byte+2 == 0': 159,
    'H_at_0BE830 byte+2 == 0': 147,
    'H_n_0BE830 byte+2 != 0': 514,
    'H_at_0BE830 byte+2 != 0': 501,
    'H_n_0BE874/8AC/88C/8C4': 74,
    'H_at_0BE874/8AC/88C/8C4': 72,
    'H_n_0BE8E4 byte+16 == 0': 30,
    'H_at_0BE8E4 byte+16 == 0': 27,
    'H_n_0BE8E4 byte+16 != 0': 156,
    'H_at_0BE8E4 byte+16 != 0': 153,
    'H_n_0BE928/944': 6,
    'H_at_0BE928/944': 5,
    'H_int_records': 80,
    'H_int_byte0': 44,
    'H_int_nofit': 42,
    'L_cases_0BEA40': 6200,
    'N_fpscr_lookalikes': 11,
    'N_fpscr_pops': 6,
    'N_fpscr_pushes': 6,
    'N_int_points': 13467,
    'N_int_rn_differ': 7,
    'N_int_rz_split_differ': 0,
    'N_f_points': 7852,
    'N_f_rn_differ': 522,
    'N_f_rz_split_differ': 155,
    'O_1d_records': 747,
    'O_2d_records': 193,
    'O_xy_defs': 57,
    'O_storagetype_defs': 5,
    'O_map_rows': 1094,
    'O_map_rows_no_site': 155,
    'O_map_f32_rows': 326,
    'O_map_f32_dispatch': 189,
    'O_map_f32_int': 44,
    'O_map_f32_none': 93,
    'O_map_a1': 44,
    'O_map_a2': 36,
}
NAN = float('nan')
INF = float('inf')


def say(*a):
    if not QUIET:
        print(*a)


def record(name, ok, detail=''):
    RESULTS.append((name, bool(ok), detail))
    print(('PASS  ' if ok else 'FAIL  ') + name + (('   ' + detail) if detail else ''))


QUOTE_LOG = []                # (name, value) of every number helpers_wrap_trace.txt quotes from this script


def quoted(name, value):
    """Register a number the analysis file quotes.  main() fails if it differs from QUOTED[name]."""
    QUOTE_LOG.append((name, value))
    return value


def f32(x):
    """Convert a Python float INPUT (or a value read out of the ROM) to float32: nearest, denormals flushed --
    exactly how sh2e_emu's fregs= / ram_f32 load a test value.  NOT FPU arithmetic: see fadd .. fmac below."""
    return E.b2f(E.f2b(x))


def bits(x):
    return E.f2b(x)


def s32(x):
    return E.s32(x)


def sat32(v):
    return max(-2**31, min(2**31 - 1, v))


def ftrc(f):
    """FTRC as the emulator implements it: toward zero, saturating, NaN -> 0x80000000."""
    if f != f:
        return 0x80000000
    if f >= 2**31:
        return 0x7FFFFFFF
    if f < -2**31:
        return 0x80000000
    return int(f) & M32


def same_float(got_bits, want):
    if want != want:
        return (got_bits & 0x7F800000) == 0x7F800000 and (got_bits & 0x007FFFFF) != 0
    return got_bits == bits(want)


# ----------------------------------------------------------------------------
# EXACT float32 arithmetic in a chosen rounding mode (Fractions), independent of sh2e_emu.
# ----------------------------------------------------------------------------
def frac_of(b):
    """exact value of a finite float32 bit pattern; denormals read as zero (as the emulator and DN=1 do)"""
    e = (b >> 23) & 0xFF
    if e == 0:
        return Fraction(0)
    v = Fraction((b & 0x7FFFFF) | 0x800000) * Fraction(2) ** (e - 150)
    return -v if b >> 31 else v


def to_bits(x, mode):
    """exact Fraction -> float32 bits.  mode 'rz' truncates toward zero, 'rn' rounds to nearest even.
    A result too small to be normal flushes to signed zero (DN = 1).  Too large: 'rz' gives FLT_MAX (truncation
    never reaches infinity), 'rn' gives infinity."""
    if x == 0:
        return 0
    sign = 0x80000000 if x < 0 else 0
    x = abs(x)
    e = x.numerator.bit_length() - x.denominator.bit_length()
    if Fraction(2) ** e > x:
        e -= 1                                           # now 2^e <= x < 2^(e+1)
    scaled = x / Fraction(2) ** (e - 23)                 # in [2^23, 2^24)
    m = scaled.numerator // scaled.denominator
    rem = scaled - m
    if mode == 'rn' and (rem > Fraction(1, 2) or (rem == Fraction(1, 2) and m & 1)):
        m += 1
        if m == 1 << 24:
            m, e = m >> 1, e + 1
    if e + 127 <= 0:
        return sign
    if e + 127 >= 0xFF:
        return sign | (0x7F7FFFFF if mode == 'rz' else 0x7F800000)
    return sign | ((e + 127) << 23) | (m & 0x7FFFFF)


def rnd(x, mode):
    return frac_of(to_bits(x, mode))


# ----------------------------------------------------------------------------
# FPU ARITHMETIC AS THE CHIP DOES IT -- the arithmetic every model below uses.
# FPSCR = 0x00040001 from reset (00FA42 / 00FA44): RM = 01 round TOWARD ZERO, DN = 1.  Each result is computed
# exactly and truncated by to_bits(q, 'rz') above.  Operands are float32 values held as Python floats.
# ----------------------------------------------------------------------------
def _fpu(exact, fallback, *ops):
    """One FPU result.  An Inf or NaN operand: the IEEE result is Inf or NaN, never rounded, and the double
    result `fallback` is it.  An exact zero: its sign follows the IEEE rules (x + -x = +0 in this mode too),
    which the double result follows.  Otherwise the exact value, truncated toward zero."""
    if not all(math.isfinite(v) for v in ops):
        return f32(fallback)
    q = exact()
    if q == 0:
        return f32(fallback)
    return E.b2f(to_bits(q, 'rz'))


def fsub(a, b):
    """a - b   (`fsub FRm,FRn` computes FRn - FRm)"""
    return _fpu(lambda: Fraction(a) - Fraction(b), a - b, a, b)


def fmul(a, b):
    return _fpu(lambda: Fraction(a) * Fraction(b), a * b, a, b)


def fdiv(a, b):
    """a / b   (`fdiv FRm,FRn` computes FRn / FRm)"""
    if b == 0.0:                                     # x/0: Inf of the combined sign; 0/0 and NaN/0: NaN
        return NAN if a == 0.0 or a != a else math.copysign(INF, a) * math.copysign(1.0, b)
    return _fpu(lambda: Fraction(a) / Fraction(b), a / b, a, b)


def fmac(f0, fm, fn):
    """`fmac FR0,FRm,FRn` = FR0*FRm + FRn, FUSED: computed exactly and rounded ONCE toward zero.  The ROM's
    self-test does not say whether the chip rounds the product first; section N measures what that would change."""
    return _fpu(lambda: Fraction(f0) * Fraction(fm) + Fraction(fn), f0 * fm + fn, f0, fm, fn)


def ffloat(v):
    """`float fpul,FRn` of a signed 32-bit integer: exact below 2^24, truncated toward zero above"""
    return E.b2f(to_bits(Fraction(v), 'rz')) if v else 0.0


# ----------------------------------------------------------------------------
# MODELS -- each is the contract stated in helpers_wrap_trace.txt
# ----------------------------------------------------------------------------
def search_f(axis, x):
    """0x0BECA8: (index, fraction) on a float32 axis.  Scans DOWN from the top."""
    n = len(axis)
    if not (axis[n - 1] > x):              # 0BECAE fcmp/gt fr0,fr1 : T = axis[n-1] > x ; bf/s -> top
        return n - 1, 0.0
    i = n - 1
    while True:
        if i == 0:                         # 0BECB4 bt/s : ran off the bottom
            return 0, 0.0
        i -= 1
        if not (axis[i] > x):              # 0BECBA fcmp/gt fr0,fr1 ; bt/s loops while axis[i] > x
            break
    num = fsub(x, axis[i])                 # 0BECC0 fsub fr1,fr0 : x - axis[i]
    den = fsub(axis[i + 1], axis[i])       # 0BECC8 fsub fr1,fr2 : axis[i+1] - axis[i]
    return i, fdiv(num, den)               # 0BECCA fdiv fr2,fr0


def lerp_f(c0, c1, frac):
    """Element handlers 0BEACC/0BEB20/0BEB6C/0BEAE4/0BEB00: cell i+1 is not read when frac == 0.
    Integer cells go through `float fpul` first, which is exact for 8- and 16-bit cells."""
    c0 = float(c0)
    if frac == 0.0:
        return f32(c0)
    return fmac(frac, fsub(float(c1()), c0), c0)   # fsub fr2,fr1 ; fmac fr0,fr1,fr2 (fused, toward zero)


def post_scale(raw, tc, scale, bias):
    if tc == 0:                            # 0BE84A / 0BE8FC tst ; bt/s : typecode 0 skips the fmac
        return raw
    return fmac(scale, raw, bias)          # 0BE856 fmac fr0,fr2,fr1 : scale*raw + bias


def model_1d_raw(axis, cells, x):
    i, fr = search_f(axis, x)
    return lerp_f(cells[i], lambda: cells[i + 1], fr)


def model_2d_raw(ax_a, ax_b, cells, x, y):
    """cells is flat; cell(iA, iB) = cells[iB * nA + iA]  (axis A = fr4 = record +4, count at +0)."""
    na = len(ax_a)
    ia, fa = search_f(ax_a, x)
    ib, fb = search_f(ax_b, y)
    r0 = ib * na
    v0 = lerp_f(cells[r0 + ia], lambda: cells[r0 + ia + 1], fa)
    if fb == 0.0:                          # 0BEBD6 fcmp/eq : second row is not read
        return v0
    r1 = r0 + na
    v1 = lerp_f(cells[r1 + ia], lambda: cells[r1 + ia + 1], fa)
    return fmac(fb, fsub(v1, v0), v0)      # 0BEBE4 fsub fr4,fr2 ; 0BEBE6 fmac fr0,fr2,fr4


def search_i(axis, x):
    """0x0BECDC: signed 32-bit axis, fraction as an unsigned 0.32 fixed-point number."""
    n = len(axis)
    if x >= axis[n - 1]:                   # 0BECE2 cmp/ge r3,r2 : T = x >= axis[n-1] (signed)
        return n - 1, 0
    i = n - 1
    while True:
        if i == 0:
            return 0, 0
        i -= 1
        if not (axis[i] > x):              # 0BECEE cmp/gt r2,r3 : T = axis[i] > x (signed)
            break
    dx = (x - axis[i]) & M32
    span = (axis[i + 1] - axis[i]) & M32
    return i, ((dx << 32) // span) & M32   # div0u + 32 x div1


def lerp_i(c0, c1, frac):
    """0x0BEB40 / 0x0BEB90: integer cells, truncation of the DELTA magnitude."""
    if frac == 0:
        return c0
    if c1 > c0:
        return c0 + (((c1 - c0) * frac) >> 32)
    return c0 - (((c0 - c1) * frac) >> 32)


# ----------------------------------------------------------------------------
# ROM access and record discovery
# ----------------------------------------------------------------------------
FMT = {0x00: ('>f', 4), 0x04: ('>B', 1), 0x08: ('>H', 2), 0x0C: ('>b', 1), 0x10: ('>h', 2)}


def u16(rom, a):
    return (rom[a] << 8) | rom[a + 1]


def u32(rom, a):
    return struct.unpack_from('>I', rom, a)[0]


def fl(rom, a):
    return f32(struct.unpack_from('>f', rom, a)[0])


def cells_at(rom, dp, count, tc):
    fmt, w = FMT[tc]
    out = [struct.unpack_from(fmt, rom, dp + i * w)[0] for i in range(count)]
    return [f32(v) for v in out] if tc == 0 else out


WRAPPERS = (0x0BE830, 0x0BE874, 0x0BE88C, 0x0BE8AC, 0x0BE8C4, 0x0BE8E4, 0x0BE928, 0x0BE944)
AUX_TARGETS = (0x0BE81C, 0x0BE82C, 0x0BEAB8, 0x0BEA40, 0x0BEA6C)
AUX_SITES = {}                # filled by find_call_sites: {target: [(call pc, {reg: literals}, delay-slot word)]}


def written(w):
    """General registers an instruction writes (every SH-2E form that can change Rn, Rm or r0)."""
    op, n, m, d4 = w >> 12, (w >> 8) & 15, (w >> 4) & 15, w & 15
    if op == 0x0:
        if d4 in (0x2, 0xA, 0xC, 0xD, 0xE) or (d4 == 0x9 and m == 2):
            return {n}                     # stc / sts / indexed loads / movt
        return {n, m} if d4 == 0xF else set()
    if op == 0x2:
        return {n} if d4 in (4, 5, 6, 9, 0xA, 0xB, 0xD) else set()
    if op == 0x3:
        return {n} if d4 in (4, 8, 0xA, 0xB, 0xC, 0xE, 0xF) else set()
    if op == 0x4:
        if (w & 0xFF) in (0x11, 0x15, 0x0B, 0x2B, 0x1B, 0x0E, 0x1E, 0x2E, 0x0A, 0x1A, 0x2A, 0x5A, 0x6A):
            return set()                   # cmp/pz cmp/pl jsr jmp tas ldc lds
        return {n, m} if d4 == 0xF else {n}
    if op == 0x6:
        return {n, m} if d4 in (4, 5, 6) else {n}
    if op in (0x5, 0x7, 0x9, 0xD, 0xE):
        return {n}
    if op == 0x8:
        return {0} if n in (4, 5) else set()
    if op == 0xC:
        return {0} if n in (4, 5, 6, 7, 9, 0xA, 0xB) else set()
    if op == 0xF:
        return {m} if d4 == 0x9 else ({n} if d4 == 0xB else set())
    return set()


def find_call_sites(rom, extra_entries=()):
    """METHOD 1.  ({wrapper: [(call pc, tuple of the literals r4 can hold there)]}, visited, entries, aux)
    -- a small forward dataflow.

    A first sweep that trusted any earlier `mov.l literal,r4` in the same function produced a false record
    (0x0ABCBC "passed" to 0x0BE830 at 0x0BC4D0, where r4 really comes from `mov.l @(496,gbr),r0`), so:

      * the state maps a register to the SET of literals it can hold; every instruction that writes a
        register (see written()) forgets it; a call forgets r0-r7;
      * at a branch target the state is the MERGE of the states of all its sources (conditional branches,
        bra, fall-through): a register survives only if every source has it, and then holds the union.
        That resolves the common "load record A / bf skip / load record B / skip: jsr" select.  If any
        source is a backward branch, or the address is a bsr target or is named by any aligned long in the
        image (a possible function entry), the state is emptied instead;
      * after rts / bra / jmp the sweep is DEAD until the next label, so literal pools are not decoded;
        labels are branch targets of words the sweep itself executes (iterated to a fixed point) plus every
        aligned long in the image that could be a code address;
      * `loose` (linear, survives labels) is used only as a second way to recognise `jsr @Rn` whose Rn was
        loaded with a wrapper address before a label.
      * `extu.b` / `extu.w` of a register that holds a known constant is folded (the common way the callers
        build 0x00E0 is `mov #-32,r5 ; extu.b r5,r5`);
      * `extra_entries` are more addresses where execution can start with unknown registers: the case labels
        of `braf` jump tables (switch_targets) -- no branch instruction names them.
    r4 literal sets are empty when the record is not a compile-time literal on every path to the call.
    This method is deliberately strict; what it finds is a LOWER BOUND (see sweep()).
    """
    lo, hi = 0x400, 0x0C0000
    # every aligned long anywhere in the image that could be a code address: literal pools, vector and
    # task tables.  Extra members only make the sweep more conservative (they empty the state).
    ptr_entries = {v for v in (u32(rom, a) for a in range(0, len(rom), 4)) if lo <= v < hi and not v & 1}

    def collect(pcs):
        srcs, entries = {}, set()
        for pc in pcs:
            w = u16(rom, pc)
            op = w >> 12
            if op in (0xA, 0xB):
                d = w & 0xFFF
                t = pc + 4 + (d - 0x1000 if d & 0x800 else d) * 2
                if op == 0xA:
                    srcs.setdefault(t, []).append(pc)
                else:
                    entries.add(t)
            elif op == 0x8 and ((w >> 8) & 15) in (0x9, 0xB, 0xD, 0xF):
                d = w & 0xFF
                srcs.setdefault(pc + 4 + (d - 0x100 if d & 0x80 else d) * 2, []).append(pc)
        return srcs, entries | ptr_entries | set(extra_entries)

    def apply(w, pc, st):
        op, n, m = w >> 12, (w >> 8) & 15, (w >> 4) & 15
        if op == 0xD:
            st[n] = frozenset([u32(rom, ((pc + 4) & ~3) + (w & 0xFF) * 4)])
        elif op == 0x9:                                  # mov.w @(disp,PC),Rn : sign-extended constant
            v = u16(rom, pc + 4 + (w & 0xFF) * 2)
            st[n] = frozenset([(v - 0x10000 if v & 0x8000 else v) & M32])
        elif op == 0xE:                                  # mov #imm,Rn
            v = w & 0xFF
            st[n] = frozenset([(v - 0x100 if v & 0x80 else v) & M32])
        elif (w & 0xF00F) == 0x6003:
            if m in st:
                st[n] = st[m]
            else:
                st.pop(n, None)
        elif (w & 0xF00F) in (0x600C, 0x600D):           # extu.b / extu.w Rm,Rn of a known constant
            mask = 0xFF if (w & 0xF) == 0xC else 0xFFFF
            if m in st:
                st[n] = frozenset(v & mask for v in st[m])
            else:
                st.pop(n, None)
        else:
            for r in written(w):
                st.pop(r, None)

    def merge(states):
        keys = set(states[0])
        for st in states[1:]:
            keys &= set(st)
        out = {}
        for k in keys:
            u = frozenset().union(*[st[k] for st in states])
            if len(u) <= 16:
                out[k] = u
        return out

    def run(srcs, entries):
        visited = set()
        out = {t: [] for t in WRAPPERS}
        aux = {t: [] for t in AUX_TARGETS}
        state, loose, dead, pending = {}, {}, True, {}
        pc = lo
        while pc < hi:
            if pc in entries:
                state, dead = {}, False
                pending.pop(pc, None)
            elif pc in srcs:
                inc = pending.pop(pc, []) + ([] if dead else [state])
                want = len(srcs[pc]) + (0 if dead else 1)
                state = merge(inc) if inc and len(inc) == want else {}
                dead = False
            if dead:
                pc += 2
                continue
            w = u16(rom, pc)
            visited.add(pc)
            op, n = w >> 12, (w >> 8) & 15
            is_bsr = op == 0xB
            is_jsr = (w & 0xF0FF) == 0x400B
            if is_bsr or is_jsr or (w & 0xF0FF) == 0x0003:              # bsr / jsr / bsrf
                if is_bsr:
                    d = w & 0xFFF
                    t = pc + 4 + (d - 0x1000 if d & 0x800 else d) * 2
                elif is_jsr:
                    c = state.get(n)
                    t = next(iter(c)) if c and len(c) == 1 else loose.get(n)
                else:
                    t = None
                apply(u16(rom, pc + 2), pc + 2, state)                   # the delay slot runs before the callee
                if t in out:
                    out[t].append((pc, tuple(sorted(state.get(4, ())))))
                elif t in aux:
                    aux[t].append((pc, {r: tuple(sorted(v)) for r, v in state.items() if r in (4, 5, 6)},
                                   u16(rom, pc + 2)))
                for r in range(8):                                       # r0-r7 do not survive a call
                    state.pop(r, None)
                    loose.pop(r, None)
                pc += 4
                continue
            if w == 0x000B or (w & 0xF0FF) in (0x402B, 0x0023):         # rts / jmp / braf
                state, loose, dead = {}, {}, True
                pc += 4
                continue
            if op == 0xA:                                                # bra: slot, hand the state to the target
                apply(u16(rom, pc + 2), pc + 2, state)
                d = w & 0xFFF
                t = pc + 4 + (d - 0x1000 if d & 0x800 else d) * 2
                if t > pc:
                    pending.setdefault(t, []).append(dict(state))
                state, loose, dead = {}, {}, True
                pc += 4
                continue
            if op == 0x8 and n in (0x9, 0xB, 0xD, 0xF):                  # bt / bf / bt/s / bf/s
                d = w & 0xFF
                t = pc + 4 + (d - 0x100 if d & 0x80 else d) * 2
                if n in (0xD, 0xF):
                    w2 = u16(rom, pc + 2)
                    apply(w2, pc + 2, state)
                    if (w2 >> 12) == 0xD:
                        loose[(w2 >> 8) & 15] = u32(rom, ((pc + 6) & ~3) + (w2 & 0xFF) * 4)
                    else:
                        for r in written(w2):
                            loose.pop(r, None)
                if t > pc:
                    pending.setdefault(t, []).append(dict(state))
                pc += 4 if n in (0xD, 0xF) else 2
                continue
            apply(w, pc, state)
            if op == 0xD:
                loose[n] = u32(rom, ((pc + 4) & ~3) + (w & 0xFF) * 4)
            elif (w & 0xF00F) == 0x6003 and ((w >> 4) & 15) in loose:
                loose[n] = loose[(w >> 4) & 15]
            else:
                for r in written(w):
                    loose.pop(r, None)
            pc += 2
        return out, visited, aux

    # Labels are taken only from words the sweep itself treats as instructions, iterated from the
    # over-approximation "every word is an instruction" down to a fixed point, so branch-shaped words in
    # literal pools stop creating labels (and stop blocking the merge at real ones).
    srcs, entries = collect(range(lo, hi, 2))
    for _ in range(12):
        out, visited, aux = run(srcs, entries)
        live = set(visited)
        for pc in visited:                       # delay slots execute too
            w = u16(rom, pc)
            if (w >> 12) in (0xA, 0xB) or w == 0x000B or (w & 0xF0FF) in (0x400B, 0x402B, 0x0003, 0x0023) \
                    or ((w >> 12) == 0x8 and ((w >> 8) & 15) in (0xD, 0xF)):
                live.add(pc + 2)
        s2, e2 = collect(sorted(live))
        if s2 == srcs and e2 == entries:
            break
        srcs, entries = s2, e2
    return out, visited, entries, aux

# ----------------------------------------------------------------------------
# METHOD 2 -- written for the third (deciding) pass, independent of method 1.
#   pool_sites():     WHERE a helper is called.  Start at every `mov.l @(disp,PC),Rn` whose pool long is the
#                     helper address and follow that register forward through the code (copies, both arms of
#                     every branch, across calls for r8-r14) to each `jsr @Rn`.  Needs no labels, so it also
#                     finds calls through a register loaded hundreds of instructions earlier.
#   make_resolver():  WHAT is passed.  From a call site walk BACKWARD over every predecessor (fall-through,
#                     branch sources, case labels) to the instructions that last wrote the argument register.
#                     The result is the set of literals that REACH the call on at least one path, plus None
#                     when some path leaves the value unknown.
# Both sweeps are LOWER BOUNDS: a record passed through a pointer table, a GBR slot or the stack is not found.
# ----------------------------------------------------------------------------
def _t12(w, pc):
    d = w & 0xFFF
    return pc + 4 + (d - 0x1000 if d & 0x800 else d) * 2


def _t8(w, pc):
    d = w & 0xFF
    return pc + 4 + (d - 0x100 if d & 0x80 else d) * 2


def _is_jsr(w):
    return (w & 0xF0FF) == 0x400B


def _is_call(w):
    return _is_jsr(w) or (w >> 12) == 0xB or (w & 0xF0FF) == 0x0003          # jsr / bsr / bsrf


def _is_cond(w):
    return (w >> 12) == 8 and ((w >> 8) & 15) in (0x9, 0xB, 0xD, 0xF)        # bt / bf / bt/s / bf/s


def _is_conds(w):
    return (w >> 12) == 8 and ((w >> 8) & 15) in (0xD, 0xF)


def _is_end(w):
    return w in (0x000B, 0x002B) or (w & 0xF0FF) in (0x402B, 0x0023) or (w >> 12) == 0xA   # rts rte jmp braf bra


def _has_slot(w):
    return _is_call(w) or _is_end(w) or _is_conds(w)


def _lit(rom, w, pc):
    """the constant a PC-relative or immediate load puts in Rn, else None"""
    op = w >> 12
    if op == 0xD:
        return u32(rom, ((pc + 4) & ~3) + (w & 0xFF) * 4)
    if op == 0x9:
        v = u16(rom, pc + 4 + (w & 0xFF) * 2)
        return (v - 0x10000 if v & 0x8000 else v) & M32
    if op == 0xE:
        v = w & 0xFF
        return (v - 0x100 if v & 0x80 else v) & M32
    return None


SWEEP_LO, SWEEP_HI = 0x400, 0x0C0000


def switch_targets(rom):
    """{braf pc: [case label, ...]} for the jump-table idiom
           mov #N,Rk ; cmp/hi Rk,Rm ; bt/s default ; ... ; shll Rm ; mova table,r0 ; mov.w @(r0,Rm),r0 ; braf r0
    The table holds N+1 words; a case label is (braf pc + 4) + word.  Two sites in this ROM (0x012D9C, 0x03C194).
    """
    out = {}
    for pc in range(SWEEP_LO, SWEEP_HI, 2):
        if u16(rom, pc) != 0x0023:                                   # braf r0
            continue
        w1, w2 = u16(rom, pc - 2), u16(rom, pc - 4)
        if (w1 & 0xFF0F) != 0x000D or (w2 >> 8) != 0xC7:             # mov.w @(r0,Rm),r0 ; mova @(disp,PC),r0
            continue
        rm = (w1 >> 4) & 15
        table = ((pc - 4 + 4) & ~3) + (w2 & 0xFF) * 4
        count = None
        for q in range(pc - 6, pc - 40, -2):                         # cmp/hi Rk,Rm with Rk = mov #N
            w = u16(rom, q)
            if (w & 0xF00F) == 0x3006 and ((w >> 8) & 15) == rm:
                rk = (w >> 4) & 15
                for q2 in range(q - 2, q - 12, -2):
                    w3 = u16(rom, q2)
                    if (w3 >> 12) == 0xE and ((w3 >> 8) & 15) == rk:
                        count = (w3 & 0xFF) + 1
                        break
                break
        if count:
            out[pc] = [pc + 4 + sext16(u16(rom, table + 2 * i)) for i in range(count)]
    return out


def sext16(v):
    return v - 0x10000 if v & 0x8000 else v


def sp_effect(w):
    """What one instruction does to the stack through r15, or None when it does not touch r15 / the frame.
        ('store', off, Rm)   mov.l Rm,@(off,r15)        ('load', off, Rn)   mov.l @(off,r15),Rn
        ('push', Rm|None)    @-r15 (None: not a general register)       ('pop', Rn|None)    @r15+
        ('add', imm)         add #imm,r15               ('smash', off, size)  byte / word store into the frame
        ('lost',)            any other write of r15
    """
    n, m, d = (w >> 8) & 15, (w >> 4) & 15, w & 15
    if (w & 0xFF0F) == 0x2F02:
        return ('store', 0, m)
    if (w & 0xFF00) == 0x1F00:
        return ('store', d * 4, m)
    if (w & 0xF0FF) == 0x60F2:
        return ('load', 0, n)
    if (w & 0xF0F0) == 0x50F0:
        return ('load', d * 4, n)
    if (w & 0xFF00) == 0x7F00:
        return ('add', (w & 0xFF) - 0x100 if w & 0x80 else w & 0xFF)
    if (w & 0xFF0F) == 0x2F06:
        return ('push', m)
    if (w & 0xF0FF) == 0x60F6:
        return ('pop', n)
    if (w & 0xFF0F) in (0x4F02, 0x4F03) or (w & 0xFF0F) == 0xFF0B:   # sts.l / stc.l / fmov.s FRm,@-r15
        return ('push', None)
    if (w & 0xFF0F) in (0x4F06, 0x4F07) or (w & 0xF0FF) == 0xF0F9:   # lds.l / ldc.l / fmov.s @r15+,FRn
        return ('pop', None)
    if (w & 0xFFF0) == 0x80F0:
        return ('smash', d, 1)
    if (w & 0xFFF0) == 0x81F0:
        return ('smash', d * 2, 2)
    if (w & 0xFF0F) in (0x2F00, 0x2F01):
        return ('smash', 0, 1 if (w & 15) == 0 else 2)
    if 15 in written(w):
        return ('lost',)
    return None


def pool_sites(rom, target):
    """call sites of `target` (METHOD 2): (set of `jsr @Rn` pcs, set of `jmp @Rn` pcs, set of `bsr` pcs).

    The helper address is followed through registers AND through longs parked in the stack frame
    (mov.l Rm,@(d,r15) ... mov.l @(d,r15),Rn), with the slot offsets kept relative to the moving r15.
    """
    jsr, jmp, bsr, seen = set(), set(), set(), set()

    def step(w, pc, regs, slots):
        sp = sp_effect(w)
        if sp:
            k = sp[0]
            if k == 'store':
                return regs, (slots | {sp[1]}) if sp[2] in regs else (slots - {sp[1]})
            if k == 'load':
                return (regs | {sp[2]}) if sp[1] in slots else (regs - {sp[2]}), slots
            if k == 'add':
                return regs - {15}, frozenset(o - sp[1] for o in slots if o - sp[1] >= 0)
            if k == 'push':
                moved = {o + 4 for o in slots}
                return regs, frozenset(moved | {0}) if sp[1] in regs else frozenset(moved)
            if k == 'pop':
                r2 = regs if sp[1] is None else ((regs | {sp[1]}) if 0 in slots else (regs - {sp[1]}))
                return r2, frozenset(o - 4 for o in slots if o >= 4)
            if k == 'smash':
                return regs, frozenset(o for o in slots if not (o <= sp[1] < o + 4 or o < sp[1] + sp[2] <= o + 4))
            return regs - written(w), frozenset()                   # r15 rewritten: the frame is lost
        if (w >> 12) == 0xD and _lit(rom, w, pc) == target:
            return regs | {(w >> 8) & 15}, slots
        if (w & 0xF00F) == 0x6003:                                   # mov Rm,Rn
            n, m = (w >> 8) & 15, (w >> 4) & 15
            return (regs | {n} if m in regs else regs - {n}), slots
        return regs - written(w), slots

    def walk(pc0, regs0):
        work = [(pc0, frozenset(regs0), frozenset())]
        while work:
            pc, regs, slots = work.pop()
            while (regs or slots) and SWEEP_LO <= pc < SWEEP_HI and (pc, regs, slots) not in seen:
                seen.add((pc, regs, slots))
                w = u16(rom, pc)
                if _is_call(w):
                    if _is_jsr(w) and ((w >> 8) & 15) in regs:      # the target is read before the slot runs
                        jsr.add(pc)
                    regs, slots = step(u16(rom, pc + 2), pc + 2, regs, slots)
                    regs = frozenset(r for r in regs if r >= 8)      # r0-r7 do not survive the callee;
                    slots = frozenset(slots)                         # the caller's frame does
                    pc += 4
                elif (w & 0xF0FF) == 0x402B:                         # jmp @Rn: a tail call if Rn holds it
                    if ((w >> 8) & 15) in regs:
                        jmp.add(pc)
                    break
                elif w in (0x000B, 0x002B) or (w & 0xF0FF) == 0x0023:
                    break
                elif (w >> 12) == 0xA:
                    regs, slots = step(u16(rom, pc + 2), pc + 2, regs, slots)
                    regs, slots = frozenset(regs), frozenset(slots)
                    pc = _t12(w, pc)
                elif _is_cond(w):
                    if _is_conds(w):
                        regs, slots = step(u16(rom, pc + 2), pc + 2, regs, slots)
                        regs, slots = frozenset(regs), frozenset(slots)
                        work.append((_t8(w, pc), regs, slots))
                        pc += 4
                    else:
                        work.append((_t8(w, pc), regs, slots))
                        pc += 2
                else:
                    regs, slots = step(w, pc, regs, slots)
                    regs, slots = frozenset(regs), frozenset(slots)
                    pc += 2

    for pc in range(SWEEP_LO, SWEEP_HI, 2):
        w = u16(rom, pc)
        if (w >> 12) == 0xD and _lit(rom, w, pc) == target:
            walk(pc + 2, {(w >> 8) & 15})
        elif (w >> 12) == 0xB and _t12(w, pc) == target:
            bsr.add(pc)
    return jsr, jmp, bsr


def pool_words(rom, code):
    """even addresses that instructions in `code` read as PC-relative literals (mov.l / mova: 4 bytes, mov.w: 2)"""
    out = set()
    for pc in code:
        w = u16(rom, pc)
        if (w >> 12) == 0xD or (w >> 8) == 0xC7:
            a = ((pc + 4) & ~3) + (w & 0xFF) * 4
            out.update((a, a + 2))
        elif (w >> 12) == 0x9:
            out.add(pc + 4 + (w & 0xFF) * 2)
    return out


def make_resolver(rom, code, entries, case_srcs):
    """resolve(pc, reg) -> set of the constants `reg` can hold when the callee of the call at pc starts.

    None in the set means: on some path the value is not a constant the walk can see (it was computed, loaded
    from memory, is caller-saved across a call, or the path starts at a function entry / unreached code).
    `code` is the set of addresses taken as instructions, `entries` the addresses where execution may start
    with unknown registers, `case_srcs` {case label: [braf pc]}.
    Folded: mov #imm / mov.w / mov.l PC-relative literals, mov Rm,Rn copies, extu.b / extu.w masks, and a
    long parked in the stack frame and reloaded (mov.l Rm,@(d,r15) ... mov.l @(d,r15),Rn).
    r8-r14 and frame slots are followed back across calls (callee-saved by the compiler's convention, and a
    callee does not write its caller's frame unless handed a pointer into it); r0-r7 are not.

    `code` comes from method 1's linear sweep, which never reaches a function that no branch, bsr or aligned
    pointer names.  When the walk steps back onto such a word it takes the straight-line run from the nearest
    preceding unconditional transfer (rts / bra / jmp + slot) up to that point as instructions (`added`
    collects them), stopping at any word that known code reads as a PC-relative literal.  A word in that run
    that is really data could still give a false constant; every record is checked for plausibility and
    against the model afterwards, and the helper arguments are asserted.
    """
    srcs = {}
    added = set()
    pool = pool_words(rom, code)

    def note_src(pc):
        w = u16(rom, pc)
        if (w >> 12) == 0xA:
            srcs.setdefault(_t12(w, pc), []).append(pc)
        elif _is_cond(w):
            srcs.setdefault(_t8(w, pc), []).append(pc)

    for pc in code:
        note_src(pc)

    def extend(cur):
        q = cur - 2
        while q > SWEEP_LO and not _is_end(u16(rom, q)) and q not in pool:
            q -= 2
        for a in range(q + 2 if q in pool else q + 4, cur, 2):
            if a not in code:
                code.add(a)
                added.add(a)
                note_src(a)

    def effect(w, pc, r):
        """What the instruction w did to the tracked thing r: a register number, or ('s', off) = the long at
        @(off,r15) with r15 taken AFTER the instruction.  None = untouched; ('copy', thing, mask) = it now
        holds what `thing` held BEFORE the instruction."""
        op, n, m = w >> 12, (w >> 8) & 15, (w >> 4) & 15
        sp = sp_effect(w)
        if isinstance(r, tuple):                                     # a stack slot
            off = r[1]
            if sp is None:
                return None
            k = sp[0]
            if k == 'store':
                return ('copy', sp[2], M32) if sp[1] == off else None
            if k == 'load':
                return None
            if k == 'add':
                return ('copy', ('s', off + sp[1]), M32) if off + sp[1] >= 0 else ('unk',)
            if k == 'push':
                if off == 0:
                    return ('copy', sp[1], M32) if sp[1] is not None else ('unk',)
                return ('copy', ('s', off - 4), M32)
            if k == 'pop':
                return ('copy', ('s', off + 4), M32)
            if k == 'smash':
                return ('unk',) if (off <= sp[1] < off + 4 or off < sp[1] + sp[2] <= off + 4) else None
            return ('unk',)
        if sp and sp[0] in ('load', 'pop') and sp[-1] == r:          # reloaded from the frame
            return ('copy', ('s', sp[1] if sp[0] == 'load' else 0), M32)
        if n == r and op in (0xD, 0x9, 0xE):
            return ('lit', _lit(rom, w, pc))
        if n == r and (w & 0xF00F) == 0x6003:
            return ('copy', m, M32)
        if n == r and (w & 0xF00F) == 0x600C:
            return ('copy', m, 0xFF)
        if n == r and (w & 0xF00F) == 0x600D:
            return ('copy', m, 0xFFFF)
        return ('unk',) if r in written(w) else None

    def resolve(pc, reg, budget=20000):
        out, seen, work = set(), set(), []

        def through(w, wpc, r, mask, nxt):
            e = effect(w, wpc, r)
            if e is None:
                work.append((nxt, r, mask))
            elif e[0] == 'lit':
                out.add(e[1] & mask)
            elif e[0] == 'copy':
                work.append((nxt, e[1], mask & e[2]))
            else:
                out.add(None)

        through(u16(rom, pc + 2), pc + 2, reg, M32, pc)             # the delay slot runs before the callee
        while work:
            cur, r, mask = work.pop()                                # value of r just BEFORE the instruction at cur
            if (cur, r, mask) in seen:
                continue
            seen.add((cur, r, mask))
            budget -= 1
            if budget <= 0:
                out.add(None)
                break
            npred = 0
            if cur in entries:
                out.add(None)                                        # a caller or a computed jump may arrive here
                npred += 1
            for s in case_srcs.get(cur, ()):                         # braf r0 ; slot
                npred += 1
                through(u16(rom, s + 2), s + 2, r, mask, s)
            for s in srcs.get(cur, ()):
                npred += 1
                sw = u16(rom, s)
                if (sw >> 12) == 0xA or _is_conds(sw):
                    through(u16(rom, s + 2), s + 2, r, mask, s)
                else:
                    work.append((s, r, mask))
            prev, pp = cur - 2, cur - 4
            if prev not in code:
                extend(cur)
            ppw = u16(rom, pp)
            if pp in code and _has_slot(ppw):                        # prev is the delay slot of pp
                if not _is_end(ppw):
                    npred += 1
                    if _is_call(ppw) and not isinstance(r, tuple) and r <= 7:
                        out.add(None)                                # caller-saved: the callee may have changed it
                    else:
                        through(u16(rom, prev), prev, r, mask, pp)
            elif prev in code:
                npred += 1
                pw = u16(rom, prev)
                if _is_cond(pw) and not _is_conds(pw):
                    work.append((prev, r, mask))
                else:
                    through(pw, prev, r, mask, prev)
            if not npred:
                out.add(None)                                        # nothing the sweep knows leads here
        return out
    resolve.added = added
    return resolve


SWEEP = {}                    # filled by sweep(): everything the sections need about call sites


def sweep(rom):
    """Run both methods and merge them.  Returns {wrapper: [(call pc, tuple of literals reaching r4)]}.

    A literal is kept when EITHER method finds it; method 1 must never find one that method 2 does not
    (checked in main).  SWEEP also carries, per helper, the call sites, which method found them, whether the
    walk saw an unknown path, and the r4/r5/r6 constants at the auxiliary helpers' call sites.
    """
    cases = switch_targets(rom)
    case_labels = {t for ts in cases.values() for t in ts}
    case_srcs = {}
    for b, ts in cases.items():
        for t in set(ts):
            case_srcs.setdefault(t, []).append(b)
    out1, visited, entries, aux1 = find_call_sites(rom, extra_entries=case_labels)
    code = set(visited)
    for pc in visited:
        if _has_slot(u16(rom, pc)):
            code.add(pc + 2)
    targets = WRAPPERS + AUX_TARGETS
    m2 = {t: pool_sites(rom, t) for t in targets}
    unreached = sorted(pc for t in targets for pc in m2[t][0] if pc not in code)
    code0 = frozenset(code)                               # method 1's map, before the resolver extends it
    resolve = make_resolver(rom, code, entries | case_labels, case_srcs)
    sites, full, only2, conflicts, aux = {}, {}, {}, [], {}
    for t in WRAPPERS:
        f1 = dict(out1[t])
        rows = []
        for pc in sorted(set(f1) | m2[t][0] | m2[t][1] | m2[t][2]):     # jsr, jmp (tail call), bsr
            r = resolve(pc, 4)
            lits2 = {v for v in r if v is not None}
            lits1 = set(f1.get(pc, ()))
            if not lits1 <= lits2:
                conflicts.append((t, pc, sorted(lits1), sorted(lits2)))
            rows.append((pc, tuple(sorted(lits1 | lits2))))
            full[(t, pc)] = bool(r) and None not in r
        sites[t] = rows
        only2[t] = sorted(set(m2[t][0] | m2[t][1] | m2[t][2]) - set(f1))
    for t in AUX_TARGETS:
        f1 = {pc: regs for pc, regs, _ in aux1[t]}
        rows = []
        for pc in sorted(set(f1) | m2[t][0] | m2[t][2]):
            regs = {}
            for reg in (4, 5, 6):
                r = resolve(pc, reg)
                lits1 = set(f1.get(pc, {}).get(reg, ()))
                lits2 = {v for v in r if v is not None}
                if not lits1 <= lits2:
                    conflicts.append((t, pc, sorted(lits1), sorted(lits2)))
                if r and None not in r:
                    regs[reg] = tuple(sorted(lits2))
            rows.append((pc, regs, u16(rom, pc + 2)))
        aux[t] = rows
        only2[t] = sorted(set(m2[t][0] | m2[t][2]) - set(f1))
    AUX_SITES.clear()
    AUX_SITES.update(aux)
    SWEEP.clear()
    SWEEP.update(dict(sites=sites, full=full, only2=only2, conflicts=conflicts, method1=out1, aux1=aux1,
                      tail_jumps={t: sorted(m2[t][1]) for t in targets}, cases=cases, unreached=unreached,
                      code=code, code0=code0, entries=entries | case_labels, resolve=resolve,
                      m1_records={t: sorted({r for _, rs in out1[t] for r in rs}) for t in WRAPPERS}))
    return sites


def records_of(sites, entry):
    """every literal r4 can hold at a call site of `entry`"""
    return sorted({r for _, rs in sites[entry] for r in rs})


def plausible_rec(rom, rec, two_d):
    if not (0x080000 <= rec < 0x0FFFE0):
        return False
    ptrs = [u32(rom, rec + 4), u32(rom, rec + 8)] + ([u32(rom, rec + 12)] if two_d else [])
    counts = [u16(rom, rec)] + ([u16(rom, rec + 2)] if two_d else [])
    return all(0x400 <= p < 0x0FFF00 for p in ptrs) and all(1 <= c <= 255 for c in counts)


def sample_points(axis):
    """below, every breakpoint, 3 interior points of every cell, above."""
    span = (axis[-1] - axis[0]) or 1.0
    pts = [axis[0] - 0.1 * span]
    for i, a in enumerate(axis):
        pts.append(a)
        if i + 1 < len(axis):
            d = axis[i + 1] - a
            pts += [a + 0.25 * d, a + 0.5 * d, a + 0.9 * d]
    pts.append(axis[-1] + 0.1 * span)
    return [f32(p) for p in pts]


def coarse_points(axis):
    """a smaller set for the 2-D grids: below, first, an interior point of the first, middle and last cell, last, above."""
    n = len(axis)
    span = (axis[-1] - axis[0]) or 1.0
    pts = [axis[0] - 0.1 * span, axis[0]]
    for i in sorted({0, (n - 1) // 2, max(0, n - 2)}):
        if i + 1 < n:
            d = axis[i + 1] - axis[i]
            pts += [axis[i] + 0.3 * d, axis[i + 1]]
    pts += [axis[-1], axis[-1] + 0.1 * span]
    return sorted({f32(p) for p in pts})


def normal(v):
    return v == 0.0 or 1e-30 < abs(v) < 1e7


def lin(axis, vals, x):
    """The independent oracle: plain clamp + linear interpolation in doubles."""
    if x <= axis[0]:
        return vals[0]
    if x >= axis[-1]:
        return vals[-1]
    for i in range(len(axis) - 1):
        if axis[i] <= x <= axis[i + 1]:
            f = (x - axis[i]) / (axis[i + 1] - axis[i])
            return vals[i] + f * (vals[i + 1] - vals[i])
    raise AssertionError


# ----------------------------------------------------------------------------
# Synthetic records in emulator RAM (lets the edge cases and the typecodes the
# ROM never uses be exercised, and lets "this field is never read" be PROVEN:
# a field left uninitialised shows up in emu.uninit_reads if it is touched).
# ----------------------------------------------------------------------------
RAM_REC = 0xFFFF2000
RAM_AX_A = 0xFFFF2100
RAM_AX_B = 0xFFFF2200
RAM_DATA = 0xFFFF2400


def put_cells(emu, dp, cells, tc):
    fmt, w = FMT[tc]
    for i, v in enumerate(cells):
        raw = struct.pack(fmt, v)
        for j, b in enumerate(raw):
            emu.ram_u8(dp + i * w + j, b)


def synth_1d(emu, axis, cells, cell_tc, tc_byte=None, scale=None, bias=None, int_axis=False):
    emu.ram_u16(RAM_REC, len(axis))
    if tc_byte is not None:
        emu.ram_u8(RAM_REC + 2, tc_byte)
    emu.ram_u32(RAM_REC + 4, RAM_AX_A)
    emu.ram_u32(RAM_REC + 8, RAM_DATA)
    if scale is not None:
        emu.ram_f32(RAM_REC + 12, scale)
        emu.ram_f32(RAM_REC + 16, bias)
    for i, a in enumerate(axis):
        if int_axis:
            emu.ram_u32(RAM_AX_A + 4 * i, a & M32)
        else:
            emu.ram_f32(RAM_AX_A + 4 * i, a)
    put_cells(emu, RAM_DATA, cells, cell_tc)


def synth_2d(emu, ax_a, ax_b, cells, cell_tc, tc_byte=None, scale=None, bias=None):
    emu.ram_u16(RAM_REC, len(ax_a))
    emu.ram_u16(RAM_REC + 2, len(ax_b))
    emu.ram_u32(RAM_REC + 4, RAM_AX_A)
    emu.ram_u32(RAM_REC + 8, RAM_AX_B)
    emu.ram_u32(RAM_REC + 12, RAM_DATA)
    if tc_byte is not None:
        emu.ram_u8(RAM_REC + 16, tc_byte)
    if scale is not None:
        emu.ram_f32(RAM_REC + 20, scale)
        emu.ram_f32(RAM_REC + 24, bias)
    for i, a in enumerate(ax_a):
        emu.ram_f32(RAM_AX_A + 4 * i, a)
    for i, a in enumerate(ax_b):
        emu.ram_f32(RAM_AX_B + 4 * i, a)
    put_cells(emu, RAM_DATA, cells, cell_tc)


# ============================================================================
def words_are(rom, pairs):
    """[(address, word)] -> True when the ROM holds exactly those words"""
    return all(u16(rom, a) == w for a, w in pairs)


def sec_sweep(rom, sites):
    say('\n==== S. the call-site sweep: two methods, merged.  Every count here is a LOWER BOUND ====')
    say('   helper      call sites  (method 1 / only method 2)   r4 literal on >=1 path   no unknown path   records   (method 1)')
    S = SWEEP
    for t in WRAPPERS:
        two = t in (0x0BE8E4, 0x0BE928, 0x0BE944)
        rows = sites[t]
        recs = [r for r in records_of(sites, t) if plausible_rec(rom, r, two)]
        nlit = sum(1 for _, rs in rows if rs)
        nfull = sum(1 for pc, _ in rows if S['full'][(t, pc)])
        say(f'   0x{t:06X}   {len(rows):5}       ({len(S["method1"][t]):3} / {len(S["only2"][t]):2})'
            f'                {nlit:5}                 {nfull:5}          {len(recs):5}     ({len(S["m1_records"][t])})'
            + (f'   incl. tail jump at {", ".join("0x%06X" % a for a in S["tail_jumps"][t])}' if S['tail_jumps'][t] else ''))
        quoted(f'sites_{t:06X}', len(rows))
        quoted(f'lit_sites_{t:06X}', nlit)
        quoted(f'records_{t:06X}', len(recs))
        quoted(f'm1_records_{t:06X}', len(S['m1_records'][t]))
    for t in AUX_TARGETS[2:]:
        say(f'   0x{t:06X}   {len(AUX_SITES[t]):5}       ({len(S["aux1"][t]):3} / {len(S["only2"][t]):2})')
        quoted(f'sites_{t:06X}', len(AUX_SITES[t]))
    say(f'   call sites in code the linear sweep never reached (found by method 2 only): '
        + ', '.join(f'0x{a:06X}' for a in S['unreached']))
    quoted('unreached_sites', len(S['unreached']))
    for t in sorted(S['only2']):                         # call sites only method 2 finds, per helper
        quoted(f'only2_{t:06X}', len(S['only2'][t]))
    record('the two sweep methods never disagree: every literal method 1 finds at a site, method 2 finds too',
           not S['conflicts'], f'{len(S["conflicts"])} conflicts')
    # every record that is implausible as a record would be a sweep error
    imp = [(t, r) for t in WRAPPERS for r in records_of(sites, t)
           if not plausible_rec(rom, r, t in (0x0BE8E4, 0x0BE928, 0x0BE944))]
    record('every literal the sweep finds in r4 at a wrapper call is a well-formed record (pointers in ROM, counts 1..255)',
           not imp, f'{len(imp)} ill-formed')

    def r4_at(t, pc):
        return set(dict(sites[t]).get(pc, ()))

    # sites the first two passes argued about, decoded by hand for the third pass and asserted here
    named = [
        (0x0BE830, 0x02FCAE, {0x0AC8D0, 0x0AC8E4, 0x0AC8F8, 0x0AC90C, 0x0AC920, 0x0AC934}, 'six-way select 02FC84..02FCAA'),
        (0x0BE830, 0x012E3C, {0x0AA7C4, 0x0AA7E4, 0x0AA7F8}, 'three case labels of the braf jump table at 0x012DF0'),
        (0x0BE830, 0x03130A, {0x0ACD34}, '031304 D428'),
        (0x0BE830, 0x050148, {0x0AEA30}, 'r13 literal copied in the slot 05014A'),
        (0x0BE830, 0x050156, {0x0AEA44}, 'r14 literal copied in the slot 050158'),
        (0x0BE830, 0x03287C, {0x0ACE20}, 'TAIL JUMP: 032878 D432 ; 03287A D233 ; 03287C 422B jmp @r2'),
        (0x0BE8E4, 0x013A20, {0x0AA9F0}, '013A1C D433'),
        (0x0BE8E4, 0x020116, {0x0AB004}, 'jsr @r11, r11 loaded at 01FF38'),
        (0x0BE8E4, 0x020120, {0x0AB020}, 'jsr @r11, r11 loaded at 01FF38'),
        (0x0BE8E4, 0x02B998, {0x0ABF54, 0x0ABF70}, 'bt/s select at 02B990'),
    ]
    ok = True
    for t, pc, want, why in named:
        got = r4_at(t, pc)
        ok &= got == want
        say(f'   0x{pc:06X} -> 0x{t:06X}  r4 = {{{", ".join("0x%06X" % r for r in sorted(got))}}}   ({why})'
            + ('' if got == want else '   <-- MISMATCH'))
    record('the disputed call sites pass exactly the records the bytes show (10 sites, 19 records)', ok)
    record('switch at 0x012D9C: mova 0x012DF0 ; mov.w @(r0,r2),r0 ; braf r0 ; 9 entries; case labels include '
           '0x012E12, 0x012E20, 0x012E38 (the three r4 loads)',
           words_are(rom, [(0x012D8E, 0xE508), (0x012D90, 0x3256), (0x012D98, 0xC715), (0x012D9A, 0x002D), (0x012D9C, 0x0023),
                           (0x012E12, 0xD498), (0x012E14, 0xA011), (0x012E20, 0xD496), (0x012E22, 0xA00A),
                           (0x012E38, 0xD492), (0x012E3A, 0xD293), (0x012E3C, 0x420B)])
           and len(S['cases'].get(0x012D9C, ())) == 9
           and {0x012E12, 0x012E20, 0x012E38} <= set(S['cases'][0x012D9C]))

    # records that do NOT arrive as a literal: how r4 is produced at those call sites
    say('   call sites where no literal reaches r4 -- the instruction that last writes r4 (slot first, then straight back):')
    for t in (0x0BE830, 0x0BE8E4, 0x0BE8AC):
        hist = {}
        nolit = [pc for pc, rs in sites[t] if not rs]
        for pc in nolit:
            m = '?'
            for q in [pc + 2] + list(range(pc - 2, pc - 24, -2)):
                w = u16(rom, q)
                if 4 in written(w):
                    m = D.decode(w, q)[0]
                    break
            kind = ('indexed load  mov.l @(r0,Rm),r4' if m.startswith('mov.l @(r0,') else
                    'copy of r0    mov r0,r4' if m == 'mov r0,r4' else
                    'copy          mov Rm,r4' if m.startswith('mov r') else
                    'load          mov.l @(d,Rm),r4' if m.startswith('mov.l @(') else
                    'load          mov.l @Rm,r4' if m.startswith('mov.l @') else m)
            hist[kind] = hist.get(kind, 0) + 1
        say(f'      0x{t:06X}: {len(nolit)} sites: ' + '; '.join(f'{k} x{v}' for k, v in sorted(hist.items(), key=lambda kv: -kv[1])))
        quoted(f'nolit_sites_{t:06X}', len(nolit))
        for k, v in sorted(hist.items()):
            quoted(f'nolit_{t:06X}_{k.split()[0]}_{k.split()[-1]}', v)
    record('a helper address PARKED IN THE STACK FRAME: 036396 D669 r6 = 0x000BE8AC ; 036398 2F62 mov.l r6,@r15 ; '
           '0363E0 D45B r4 = 0x000AD0C4 ; 0363E2 62F2 mov.l @r15,r2 ; 0363E4 420B jsr @r2',
           words_are(rom, [(0x036396, 0xD669), (0x036398, 0x2F62), (0x0363E0, 0xD45B), (0x0363E2, 0x62F2), (0x0363E4, 0x420B)])
           and _lit(rom, 0xD669, 0x036396) == 0x0BE8AC and r4_at(0x0BE8AC, 0x0363E4) == {0x0AD0C4},
           'method 2 follows it; neither earlier pass did')
    # two decoded examples of the non-literal routes
    tbl = [u32(rom, 0x06403C + 12 * i) for i in range(4)]
    record('a ROM POINTER TABLE feeds 0BE830: 05013A D682 r6 = 0x000BE830 ; 05013C DA85 r10 = 0x0006403C ; '
           '0501EA 04AE mov.l @(r0,r10),r4 ; 0501EC 460B jsr @r6',
           words_are(rom, [(0x05013A, 0xD682), (0x05013C, 0xDA85), (0x0501E8, 0x60B3), (0x0501EA, 0x04AE), (0x0501EC, 0x460B)])
           and _lit(rom, 0xD682, 0x05013A) == 0x0BE830 and _lit(rom, 0xDA85, 0x05013C) == 0x06403C
           and all(plausible_rec(rom, r, False) for r in tbl),
           'first records in the table: ' + ', '.join(f'0x{r:06X}' for r in tbl))
    record('a GBR SLOT feeds 0BE830 at 0x0BC4D0: 0BC4C2 D07D r0 = 0x000AB6E8 ; 0BC4C4 C27C mov.l r0,@(496,gbr) ; '
           '0BC4CE C67C mov.l @(496,gbr),r0 ; 0BC4D0 420B jsr @r2 ; 0BC4D2 6403 mov r0,r4',
           words_are(rom, [(0x0BC4C2, 0xD07D), (0x0BC4C4, 0xC27C), (0x0BC4C6, 0xD07D), (0x0BC4C8, 0xC28E), (0x0BC4CA, 0xD27D),
                           (0x0BC4CC, 0xF4FC), (0x0BC4CE, 0xC67C), (0x0BC4D0, 0x420B), (0x0BC4D2, 0x6403)])
           and _lit(rom, 0xD07D, 0x0BC4C2) == 0x0AB6E8 and _lit(rom, 0xD27D, 0x0BC4CA) == 0x0BE830
           and u16(rom, 0x0AB6E8) == 2 and rom[0x0AB6E8 + 2] == 0 and not r4_at(0x0BE830, 0x0BC4D0),
           'record 0x0AB6E8: 2 points, byte +2 = 0x00; the literal sweep cannot see it')


# ============================================================================
def sec_critical(rom):
    say('\n==== A. 0x0BE81C / 0x0BE82C  interrupt-mask raise and SR restore ====')
    say('   SR in      r5 in       -> *r4 (saved)  r0          r5 at rts (= value `ldc r5,sr` loads)   mask field')
    slot = 0xFFFF3000
    bad = n = 0
    lowered = []                                       # (sr, r5) where the mask field of the loaded value went DOWN
    srs = [0x000, 0x001, 0x0F0, 0x0F1, 0x3F3, 0x0E0, 0x0E1, 0x070, 0x010, 0x302, 0x0A0, 0x2D1]
    r5s = [0x00, 0x10, 0x60, 0x70, 0x80, 0xA0, 0xD0, 0xE0, 0xE1, 0xEF, 0xF0, 0xF1, 0xFF, 0x100, 0x10F, 0x1A0, 0x1E0,
           0x3F3, 0x80000000, 0xFFFFFFFF]
    show = {(0x000, 0xE0), (0x0F0, 0xE0), (0x0F1, 0xE0), (0x0E0, 0xE0), (0x070, 0xE0), (0x3F3, 0xF0), (0x0A0, 0x60),
            (0x0A0, 0xA0), (0x0A0, 0xD0), (0x001, 0xE1), (0x302, 0x3F3), (0x0F0, 0x100), (0x0F0, 0x1E0),
            (0x0E0, 0x1A0), (0x0F0, 0x80000000), (0x2D1, 0x00), (0x010, 0xFFFFFFFF), (0x0E0, 0xEF)}
    for sr in srs:
        for r5 in r5s:
            emu = E.Emu(rom)
            emu.sr = (lambda v=sr: v)                  # inject SR for `stc sr,r0`
            emu.ram_u32(slot, 0xDEADBEEF)
            st = emu.call(0x0BE81C, regs={4: slot, 5: r5}, stop_at={0x0BE828})
            assert st == 0x0BE828
            old = sr & 0xF0
            want_r5 = r5 if (r5 & M32) >= old else old   # 0BE820 cmp/hs r0,r5 : T = r5 >= r0 unsigned
            ok = (emu.read_u32(slot) == old and emu.R[0] == old and emu.R[5] == want_r5 and emu.R[4] == slot)
            n += 1
            bad += not ok
            if (emu.R[5] & 0xF0) < old:
                lowered.append((sr, r5))
            if (sr, r5) in show:
                say(f'   0x{sr:03X}      0x{r5:08X}  -> 0x{emu.read_u32(slot):08X}      0x{emu.R[0]:08X}  0x{emu.R[5]:08X}'
                    f'                              0x{old:02X} -> 0x{emu.R[5] & 0xF0:02X}'
                    + ('   LOWERED' if (emu.R[5] & 0xF0) < old else ''))
    quoted('A_cases', n)
    record('0BE81C: *r4 = r0 = SR & 0xF0 ; value loaded into SR = (r5 >= (SR&0xF0) unsigned, all 32 bits) ? r5 : SR&0xF0',
           bad == 0, f'{n} cases, {bad} mismatches (emulated to 0x0BE828; SR injected)')
    # The mask FIELD (bits 7..4) can only go down when r5 has bits above bit 7: then r5 wins the 32-bit compare
    # whatever its bits 7..4 are.  With r5 < 0x100 the field never goes down.
    quoted('A_lowered', len(lowered))
    record('0BE81C: the mask field of the value loaded is LOWER than the old field in some cases, and only when '
           'r5 >= 0x100 (never for r5 < 0x100)',
           len(lowered) > 0 and all(r5 >= 0x100 for _, r5 in lowered)
           and (0x0F0, 0x100) in lowered and (0x0F0, 0x1E0) in lowered and (0x0F0, 0x80000000) in lowered,
           f'{len(lowered)} of {n} cases lower it, e.g. SR=0x0F0 r5=0x100 loads 0x100 (field 0xF0 -> 0x00)')
    # the two instructions the emulator refuses: established from the decode only
    d = [D.decode(u16(rom, a), a)[0] for a in (0x0BE828, 0x0BE82A, 0x0BE82C, 0x0BE82E)]
    say('   decoded, not emulated:', '0BE828', d[0], '| 0BE82A', d[1], '| 0BE82C', d[2], '| 0BE82E', d[3])
    record('0BE828/0BE82A = rts ; ldc r5,sr   and   0BE82C/0BE82E = rts ; ldc r4,sr  (decode)',
           d == ['rts', 'ldc r5,sr', 'rts', 'ldc r4,sr'])
    # how the pair is called (byte statistics from the call-site sweep; usage, not contract)
    enter, leave = AUX_SITES[0x0BE81C], AUX_SITES[0x0BE82C]
    resolve = SWEEP['resolve']
    reach = [resolve(pc, 5) for pc, _, _ in enter]
    others = sorted({v for r in reach for v in r if v not in (None, 0xE0)})
    n_any = sum(1 for r in reach if 0xE0 in r)
    n_full = sum(1 for r in reach if r == {0xE0})
    n_sp = sum(1 for _, _, sl in enter if sl == 0x64F3)              # mov r15,r4 in the delay slot
    n_ext = sum(1 for _, _, sl in enter if sl == 0x655C)             # extu.b r5,r5 in the delay slot
    n_pop = sum(1 for _, _, sl in leave if sl == 0x64F2)             # mov.l @r15,r4 in the delay slot
    n_disp = sum(1 for _, _, sl in leave if (sl & 0xFFF0) == 0x54F0 and (sl & 0xF))    # mov.l @(d,r15),r4, d != 0
    n_nop = sum(1 for _, _, sl in leave if sl == 0x0009)
    say(f'   call sites of 0x0BE81C: {len(enter)} ({len(SWEEP["only2"][0x0BE81C])} found only by method 2); '
        f'0x00E0 reaches r5 at {n_any} of them, at {n_full} with no unknown path; other constants: '
        f'{[hex(v) for v in others] or "none"}')
    say(f'      delay slot is `mov r15,r4` at {n_sp}, `extu.b r5,r5` at {n_ext} (the mov #-32,r5 ; extu.b idiom)')
    say(f'   call sites of 0x0BE82C: {len(leave)} ({len(SWEEP["only2"][0x0BE82C])} found only by method 2); delay slot is '
        f'`mov.l @r15,r4` at {n_pop}, `mov.l @(4..,r15),r4` at {n_disp}, `nop` at {n_nop}, other at '
        f'{len(leave) - n_pop - n_disp - n_nop}')
    quoted('sites_0BE81C', len(enter))
    quoted('sites_0BE82C', len(leave))
    quoted('r5_E0_reaches', n_any)
    quoted('r5_E0_only', n_full)
    quoted('slot_mov_r15_r4', n_sp)
    quoted('slot_extu_b_r5', n_ext)
    quoted('slot_pop_r4', n_pop)
    quoted('slot_disp_r4', n_disp)
    quoted('slot_nop', n_nop)
    record('0x00E0 is the ONLY constant that reaches r5 at any call site of 0BE81C, and it reaches every one',
           not others and n_any == len(enter), f'{n_any} of {len(enter)} sites; {n_full} with no unknown path')
    try:
        E.Emu(rom).call(0x0BE82C, regs={4: 0xF0})
        refused = False
    except E.EmuError as e:
        refused = 'SR' in str(e)
    record('emulator refuses `ldc Rn,sr` (so 0BE82C and the last instruction of 0BE81C are byte-reasoned)', refused)


# ============================================================================
def sec_search(rom):
    say('\n==== B. callees used by every wrapper: 0x0BECA8 (float axis) and 0x0BECDC (integer axis) ====')
    axis = [f32(v) for v in (-10.0, 0.0, 2.5, 2.75, 100.0)]
    base = 0xFFFF2100
    say('   0BECA8 on axis', axis)
    say('   x              -> r0 (index)  fr0 (fraction)')
    bad = n = 0
    xs = [-INF, -11.0, -10.0, -9.999, -5.0, 0.0, 1.0, 2.5, 2.6, 2.75, 50.0, 99.999, 100.0, 101.0, INF, NAN, -0.0]
    for x in xs:
        emu = E.Emu(rom)
        for i, a in enumerate(axis):
            emu.ram_f32(base + 4 * i, a)
        emu.call(0x0BECA8, regs={0: len(axis), 1: base}, fregs={0: x})
        wi, wf = search_f(axis, f32(x))
        ok = emu.R[0] == wi and emu.FR[0] == bits(wf) and not emu.uninit_reads
        n += 1
        bad += not ok
        say(f'   {x!r:14} -> {emu.R[0]:<11}  {emu.fr(0)!r}')
    for nn in (1, 2, 3, 7):                                  # short axes, random probes
        rnd = random.Random(nn)
        ax = sorted({f32(rnd.uniform(-500, 500)) for _ in range(nn)})
        for _ in range(60):
            x = f32(rnd.choice(ax + [rnd.uniform(-600, 600)]))
            emu = E.Emu(rom)
            for i, a in enumerate(ax):
                emu.ram_f32(base + 4 * i, a)
            emu.call(0x0BECA8, regs={0: len(ax), 1: base}, fregs={0: x})
            wi, wf = search_f(ax, x)
            n += 1
            bad += not (emu.R[0] == wi and emu.FR[0] == bits(wf) and not emu.uninit_reads)
    record('0BECA8: x >= axis[n-1] or NaN -> (n-1, 0) ; x < axis[0] -> (0, 0) ; else largest i with axis[i] <= x, '
           'frac = (x-axis[i])/(axis[i+1]-axis[i])', bad == 0, f'{n} cases, {bad} mismatches')

    iaxis = [-1000, -3, 0, 16, 66, 197, 0x7FFFFFF0]
    say('   0BECDC on signed-long axis', iaxis)
    say('   x            -> r0 (index)  r1 (fraction, 0.32 unsigned)')
    bad = n = 0
    rnd = random.Random(5)
    xs = [-2**31, -1001, -1000, -999, -4, -3, -2, 0, 1, 15, 16, 17, 65, 66, 100, 196, 197, 198, 2**31 - 17, 2**31 - 16, 2**31 - 1]
    xs += [rnd.randint(-1200, 400) for _ in range(150)] + [rnd.randint(-2**31, 2**31 - 1) for _ in range(150)]
    for k, x in enumerate(xs):
        emu = E.Emu(rom)
        for i, a in enumerate(iaxis):
            emu.ram_u32(base + 4 * i, a & M32)
        emu.call(0x0BECDC, regs={0: len(iaxis), 1: base, 2: x & M32})
        wi, wf = search_i(iaxis, x)
        ok = emu.R[0] == wi and emu.R[1] == wf and not emu.uninit_reads
        n += 1
        bad += not ok
        if k < 21:
            say(f'   {x:<12} -> {emu.R[0]:<11}  0x{emu.R[1]:08X} ({emu.R[1] / 2**32:.6f})')
    record('0BECDC: signed compares, same clamp rule; frac = floor(((x-axis[i]) << 32) / (axis[i+1]-axis[i]))',
           bad == 0, f'{n} cases, {bad} mismatches')


# ============================================================================
def run_1d_float(rom, emu, rec, x):
    emu.call(0x0BE830, regs={4: rec}, fregs={4: x})
    return emu.FR[0]


def sec_1d_float(rom, sites):
    say('\n==== C. 0x0BE830  1-D lookup, float result ====')
    table = [u32(rom, 0x0BE860 + 4 * i) for i in range(5)]
    say('   dispatch table of longs at 0x0BE860:', ' '.join(f'[+0x{4 * i:02X}]=0x{v:06X}' for i, v in enumerate(table)))
    record('0BE860 table = 0BEACC, 0BEB20, 0BEB6C, 0BEAE4, 0BEB00 (indexed by the raw typecode byte)',
           table == [0x0BEACC, 0x0BEB20, 0x0BEB6C, 0x0BEAE4, 0x0BEB00])

    recs = [r for r in records_of(sites, 0x0BE830) if plausible_rec(rom, r, False) and rom[r + 2] in FMT]
    by_tc = {}
    emu = E.Emu(rom)
    exact_bad = exact_n = orc_bad = orc_n = orc_tabs = 0
    worst = ''
    for rec in recs:
        n, tc = u16(rom, rec), rom[rec + 2]
        axis = [fl(rom, u32(rom, rec + 4) + 4 * i) for i in range(n)]
        cells = cells_at(rom, u32(rom, rec + 8), n + 1, tc)       # +1: model may name cell i+1 only when frac != 0
        scale, bias = fl(rom, rec + 12), fl(rom, rec + 16)
        by_tc[tc] = by_tc.get(tc, 0) + 1
        mono = all(axis[i] < axis[i + 1] for i in range(n - 1))
        pts = sample_points(axis) if mono else [axis[0], axis[-1]]
        phys = None
        if mono:
            t = T.read_table(rom, rec) if not T.is_2d(rom, rec) else None
            if t and all(normal(v) for v in t['axes']['x'] + t['values']):
                phys = t
                orc_tabs += 1
        for x in pts:
            got = run_1d_float(rom, emu, rec, x)
            want = post_scale(model_1d_raw(axis, cells, x), tc, scale, bias)
            exact_n += 1
            if not same_float(got, want):
                exact_bad += 1
                worst = worst or f'0x{rec:06X} x={x}: emu {E.b2f(got)} model {want}'
            if phys:
                o = lin(phys['axes']['x'], phys['values'], x)
                orc_n += 1
                tol = 1e-4 * max(1.0, abs(o), max(abs(v) for v in phys['values']))
                if not abs(E.b2f(got) - o) <= tol:
                    orc_bad += 1
                    worst = worst or f'0x{rec:06X} x={x}: emu {E.b2f(got)} read_table oracle {o}'
    names = ', '.join(f'typecode 0x{k:02X}: {v}' for k, v in sorted(by_tc.items()))
    say(f'   records the sweep finds passed to 0x0BE830 by literal: {len(recs)}  ({names})')
    for k in (0x00, 0x04, 0x08, 0x0C, 0x10):
        quoted(f'C_tc_{k:02X}', by_tc.get(k, 0))
    quoted('C_points', exact_n)
    quoted('C_oracle_records', orc_tabs)
    quoted('C_oracle_points', orc_n)
    record('0BE830 == model on every record the sweep finds passed to it (bit-exact; FPU results truncated, fmac fused)',
           exact_bad == 0 and exact_n > 5000, f'{len(recs)} records, {exact_n} points, {exact_bad} mismatches {worst}')
    record('0BE830 == desc_types.read_table() + linear interpolation of physical values (tolerance)',
           orc_bad == 0 and orc_n > 5000, f'{orc_tabs} records, {orc_n} points, {orc_bad} mismatches')

    # one worked record per typecode, printed
    for want_tc in (0x00, 0x04, 0x08):
        rec = next(r for r in recs if rom[r + 2] == want_tc and 4 <= u16(rom, r) <= 8
                   and len(set(cells_at(rom, u32(rom, r + 8), u16(rom, r), want_tc))) >= 4)
        n = u16(rom, rec)
        axis = [fl(rom, u32(rom, rec + 4) + 4 * i) for i in range(n)]
        cells = cells_at(rom, u32(rom, rec + 8), n, want_tc)
        say(f'   record 0x{rec:06X}  n={n} typecode=0x{want_tc:02X}  axis@0x{u32(rom, rec + 4):06X} data@0x{u32(rom, rec + 8):06X}'
            + ('' if want_tc == 0 else f'  scale={fl(rom, rec + 12)!r} bias={fl(rom, rec + 16)!r}'))
        say(f'      axis  {axis}')
        say(f'      cells {cells}')
        for x in (axis[0] - 1.0, axis[0], f32((axis[1] + axis[2]) / 2), axis[-1], axis[-1] + 1.0, NAN):
            say(f'      fr4={x!r:12} -> fr0={E.b2f(run_1d_float(rom, emu, rec, x))!r}')

    # ---- synthetic records: every typecode, the skip, and which fields are read
    axis = [f32(v) for v in (10.0, 20.0, 40.0, 80.0)]
    synth = {
        0x00: [f32(v) for v in (1.5, -2.25, 1000.0, 3.0)],
        0x04: [0, 200, 255, 17],
        0x08: [0, 40000, 65535, 300],
        0x0C: [-128, -1, 127, 5],
        0x10: [-32768, -1, 32767, 5],
    }
    say('   synthetic RAM record, axis', axis, ' scale=0.5 bias=3.0 present in every record')
    say('   typecode cells                              x=5    x=10   x=15      x=20   x=30      x=60       x=80   x=99   scale/bias')
    bad = n = 0
    for tc, cells in synth.items():
        row = []
        for x in (5.0, 10.0, 15.0, 20.0, 30.0, 60.0, 80.0, 99.0):
            emu = E.Emu(rom)
            synth_1d(emu, axis, cells, tc, tc_byte=tc, scale=0.5, bias=3.0)
            emu.call(0x0BE830, regs={4: RAM_REC}, fregs={4: x})
            want = post_scale(model_1d_raw(axis, cells, f32(x)), tc, f32(0.5), f32(3.0))
            n += 1
            bad += not (same_float(emu.FR[0], want) and not emu.uninit_reads)
            row.append(emu.fr(0))
        say(f'   0x{tc:02X}     {str(cells):34} ' + ' '.join(f'{v:<8.6g}' for v in row)
            + ('  SKIPPED' if tc == 0 else '  applied'))
    record('0BE830 synthetic: 0x00 float32 raw (scale/bias skipped), 0x04 uint8, 0x08 uint16, 0x0C int8, 0x10 int16, '
           'others = scale*raw+bias', bad == 0, f'{n} cases, {bad} mismatches')

    # typecode 0 with the +12/+16 words and byte +3 left UNINITIALISED: proves they are not read
    emu = E.Emu(rom)
    synth_1d(emu, axis, synth[0x00], 0x00, tc_byte=0x00)
    emu.call(0x0BE830, regs={4: RAM_REC}, fregs={4: 30.0})
    ok0 = not emu.uninit_reads and emu.R[4] == RAM_REC
    # typecode 4 with scale/bias missing: the read must be reported
    emu2 = E.Emu(rom)
    synth_1d(emu2, axis, synth[0x04], 0x04, tc_byte=0x04)
    emu2.call(0x0BE830, regs={4: RAM_REC}, fregs={4: 30.0})
    ok4 = emu2.uninit_reads == {RAM_REC + 12, RAM_REC + 16} and emu2.R[4] == RAM_REC + 16
    say(f'   typecode 0x00, +12/+16 uninitialised: uninit reads = {sorted(emu.uninit_reads)}  r4 after = rec+{emu.R[4] - RAM_REC}')
    say(f'   typecode 0x04, +12/+16 uninitialised: uninit reads = {[hex(a - RAM_REC) for a in sorted(emu2.uninit_reads)]} (record offsets)  r4 after = rec+{emu2.R[4] - RAM_REC}')
    record('0BE830 reads record +12 and +16 ONLY when the typecode byte is non-zero; byte +3 is never read', ok0 and ok4)

    # the top clamp reads cell n-1 only (cell n does not exist in RAM here)
    emu = E.Emu(rom)
    synth_1d(emu, axis, synth[0x08], 0x08, tc_byte=0x08, scale=1.0, bias=0.0)
    emu.call(0x0BE830, regs={4: RAM_REC}, fregs={4: 80.0})
    record('0BE830 at x >= axis[n-1] reads cell n-1 only (no read past the end of the data)',
           not emu.uninit_reads and emu.fr(0) == 300.0)
    return recs


# ============================================================================
def sec_1d_int(rom, sites):
    say('\n==== D. 0x0BE874 (uint8 cells) / 0x0BE8AC (uint16 cells)  1-D lookup, integer result in r0 ====')
    emu = E.Emu(rom)
    all_recs = {}
    for entry, tc, mask in ((0x0BE874, 0x04, 0xFF), (0x0BE8AC, 0x08, 0xFFFF)):
        recs = [r for r in records_of(sites, entry) if plausible_rec(rom, r, False)]
        tcb = {}
        bad = n = 0
        worst = ''
        for rec in recs:
            cnt = u16(rom, rec)
            tcb[rom[rec + 2]] = tcb.get(rom[rec + 2], 0) + 1
            axis = [fl(rom, u32(rom, rec + 4) + 4 * i) for i in range(cnt)]
            cells = cells_at(rom, u32(rom, rec + 8), cnt + 1, tc)
            mono = all(axis[i] < axis[i + 1] for i in range(cnt - 1))
            for x in (sample_points(axis) if mono else [axis[0], axis[-1]]):
                emu.call(entry, regs={4: rec}, fregs={4: x})
                want = ftrc(model_1d_raw(axis, cells, x)) & mask
                n += 1
                if emu.R[0] != want:
                    bad += 1
                    worst = worst or f'0x{rec:06X} x={x}: emu {emu.R[0]} model {want}'
        all_recs[entry] = recs
        say(f'   0x{entry:06X}: {len(recs)} records at call sites; byte at record+2 is '
            + ', '.join(f'0x{k:02X} in {v}' for k, v in sorted(tcb.items())))
        quoted(f'D_points_{entry:06X}', n)
        for k, v in sorted(tcb.items()):
            quoted(f'D_byte2_{entry:06X}_{k:02X}', v)
        record(f'{entry:06X} == trunc(interp of {"uint8" if tc == 4 else "uint16"} cells) & 0x{mask:X} on every record '
               f'passed to it (bit-exact)', bad == 0 and n > 300, f'{len(recs)} records, {n} points, {bad} mismatches {worst}')

    # The same records read AT FACE VALUE -- cells typed by the byte at +2, +12/+16 applied when that byte is
    # non-zero -- which is what desc_types.read_table() did until corrections item 106.  Computed here from the
    # bytes, so the comparison no longer depends on desc_types; read_table() itself is compared after it.
    def face_value(rec):
        n, b2 = u16(rom, rec), rom[rec + 2]
        fmt, w = FMT[b2]
        dp = u32(rom, rec + 8)
        vals = [struct.unpack_from(fmt, rom, dp + i * w)[0] for i in range(n)]
        if b2:
            sc, bi = struct.unpack_from('>f', rom, rec + 12)[0], struct.unpack_from('>f', rom, rec + 16)[0]
            vals = [v * sc + bi for v in vals]
        return vals

    say('   the same records read AT FACE VALUE (cells typed by the byte at +2, +12/+16 applied when it is non-zero; what')
    say('   desc_types.read_table() did before corrections item 106) and through read_table() as it is now:')
    say('   record    wrapper  byte+2  raw cells the wrapper reads        r0 at axis[0]   face value [:3]          read_table() [:3]')
    differ_exact = differ_tol = shown = 0
    near_nonzero = []                                    # records within 1e-6 whose cells are NOT all zero
    rt_match = 0
    rt_fixed = 0
    for entry, tc in ((0x0BE874, 0x04), (0x0BE8AC, 0x08)):
        for rec in all_recs[entry]:
            cnt = u16(rom, rec)
            cells = cells_at(rom, u32(rom, rec + 8), cnt, tc)
            axis0 = fl(rom, u32(rom, rec + 4))
            emu.call(entry, regs={4: rec}, fregs={4: axis0})
            vals = face_value(rec)
            same_exact = all(v == c for v, c in zip(vals, cells))
            same_tol = all(abs(v - c) < 1e-6 for v, c in zip(vals, cells))
            differ_exact += not same_exact
            differ_tol += not same_tol
            if same_tol and any(cells):
                near_nonzero.append(rec)
            try:
                rt = T.read_table(rom, rec)['values']
            except Exception as e:                                   # noqa: BLE001
                rt = [f'({type(e).__name__})']
            rt_match += rt == cells
            fx = T.fixed_type(rec)
            rt_fixed += bool(fx) and fx.get('cell_typecode') == tc and f'0x{entry:06X}' in fx.get('consumers', {})
            if (rom[rec + 2] == 0 and shown < 6) or (rec in (0x0AC2D0, 0x0AAEA0)):
                shown += 1
                say(f'   0x{rec:06X}  {entry:06X}   0x{rom[rec + 2]:02X}    {str(cells[:5]):34} {emu.R[0]:<14}  '
                    + f'{str([float(f"{v:.4g}") if isinstance(v, float) else v for v in vals[:3]]):24} {rt[:3]}')
    tot = len(all_recs[0x0BE874]) + len(all_recs[0x0BE8AC])
    say(f'   face value vs the raw cells the wrapper reads, {tot} records: differs EXACTLY on {differ_exact}, by more than '
        f'1e-6 on {differ_tol}; the {tot - differ_tol} within 1e-6 all have all-zero cells: {not near_nonzero}')
    say(f'   read_table() now: equal to the wrapper\'s cells on {rt_match} of {tot}; fixed_type() names this wrapper and its '
        f'cell type for {rt_fixed} of {tot}  (asserted for all six integer-result wrappers in section H)')
    quoted('D_records', tot)
    quoted('D_facevalue_differ_exact', differ_exact)
    quoted('D_facevalue_differ_1e6', differ_tol)
    record('reading these records at face value (byte at +2 for the cell type, +12/+16 applied) does not reproduce the '
           'cells the integer-result wrappers read: it differs on most records, and every record it matches within '
           '1e-6 has all-zero cells', differ_tol > tot // 2 and differ_exact >= differ_tol and not near_nonzero,
           f'exact: {differ_exact} of {tot} differ; >1e-6: {differ_tol} of {tot}')

    # which fields are read: typecode byte and +12/+16 left uninitialised
    axis = [f32(v) for v in (10.0, 20.0, 40.0, 80.0)]
    ok = True
    say('   synthetic record with byte +2, byte +3, +12 and +16 UNINITIALISED:')
    for entry, tc, cells in ((0x0BE874, 0x04, [0, 200, 255, 17]), (0x0BE8AC, 0x08, [0, 40000, 65535, 300])):
        outs = []
        for x in (5.0, 10.0, 15.0, 25.0, 30.0, 79.0, 80.0, 99.0, NAN):
            emu2 = E.Emu(rom)
            synth_1d(emu2, axis, cells, tc)
            emu2.call(entry, regs={4: RAM_REC}, fregs={4: x})
            want = ftrc(model_1d_raw(axis, cells, f32(x))) & (0xFF if tc == 4 else 0xFFFF)
            ok &= emu2.R[0] == want and not emu2.uninit_reads and emu2.R[4] == RAM_REC
            outs.append(emu2.R[0])
        say(f'      {entry:06X} cells {cells}: x=5,10,15,25,30,79,80,99,NaN -> {outs}   uninit reads: none')
    record('0BE874 / 0BE8AC read record +0 (word), +4, +8 only: no typecode dispatch, no scale, no bias', ok)

    # truncation, and the 8/16-bit mask on a cell pattern the wrapper would mis-size
    emu2 = E.Emu(rom)
    synth_1d(emu2, [f32(0.0), f32(1.0)], [10, 11], 0x04)
    outs = []
    for x in (0.0, 0.5, 0.99, 0.999999, 1.0):
        emu2.call(0x0BE874, regs={4: RAM_REC}, fregs={4: x})
        outs.append(emu2.R[0])
    emu2 = E.Emu(rom)
    synth_1d(emu2, [f32(0.0), f32(1.0)], [11, 10], 0x04)
    outs2 = []
    for x in (0.0, 0.01, 0.5, 0.99, 1.0):
        emu2.call(0x0BE874, regs={4: RAM_REC}, fregs={4: x})
        outs2.append(emu2.R[0])
    say(f'      truncation: cells [10,11] x=0,.5,.99,.999999,1 -> {outs} ; cells [11,10] x=0,.01,.5,.99,1 -> {outs2}')
    record('0BE874 truncates the interpolated float toward zero (10.99 -> 10 ; 10.99 on a falling pair -> 10)',
           outs == [10, 10, 10, 10, 11] and outs2 == [11, 10, 10, 10, 10])
    return all_recs


# ============================================================================
def sec_1d_intaxis(rom, sites):
    say('\n==== E. 0x0BE88C (uint8 cells) / 0x0BE8C4 (uint16 cells)  1-D lookup on a SIGNED-LONG axis, input in r5 ====')
    emu = E.Emu(rom)
    for entry, tc, mask in ((0x0BE88C, 0x04, 0xFF), (0x0BE8C4, 0x08, 0xFFFF)):
        recs = [r for r in records_of(sites, entry) if plausible_rec(rom, r, False)]
        bad = n = 0
        for rec in recs:
            cnt = u16(rom, rec)
            axis = [s32(u32(rom, u32(rom, rec + 4) + 4 * i)) for i in range(cnt)]
            cells = cells_at(rom, u32(rom, rec + 8), cnt + 1, tc)
            say(f'   0x{entry:06X} record 0x{rec:06X} n={cnt} byte+2=0x{rom[rec + 2]:02X}  axis(longs)={axis}  cells={cells[:cnt]}')
            xs = set()
            for i, a in enumerate(axis):
                xs |= {a - 1, a, a + 1}
                if i + 1 < cnt:
                    d = axis[i + 1] - a
                    xs |= {a + d // 4, a + d // 2, a + (9 * d) // 10}
            xs |= {-2**31, 2**31 - 1, axis[0] - 1000, axis[-1] + 1000}
            outs = []
            for x in sorted(xs):
                if not -2**31 <= x < 2**31:
                    continue
                emu.mach, emu.macl = 0x11112222, 0x33334444
                emu.call(entry, regs={4: rec, 5: x & M32})
                i, fr = search_i(axis, x)
                want = lerp_i(cells[i], cells[i + 1], fr) & mask
                n += 1
                bad += not (emu.R[0] == want and emu.mach == 0x11112222 and emu.macl == 0x33334444)
                outs.append((x, emu.R[0]))
            say('      r5 -> r0: ' + ' '.join(f'{x}->{v}' for x, v in outs[:16]) + (' ...' if len(outs) > 16 else ''))
        quoted(f'E_points_{entry:06X}', n)
        record(f'{entry:06X} == model on every record passed to it; MACH/MACL preserved', bad == 0 and n > 20,
               f'{len(recs)} records, {n} points, {bad} mismatches')

    # synthetic: rising and falling cells, truncation direction, and unread fields
    axis = [-100, 0, 3, 1000]
    ok = True
    for entry, tc, cells, mask in ((0x0BE88C, 0x04, [250, 10, 11, 0], 0xFF), (0x0BE8C4, 0x08, [60000, 10, 11, 0], 0xFFFF)):
        outs = []
        for x in (-2**31, -101, -100, -99, -50, -1, 0, 1, 2, 3, 4, 500, 999, 1000, 2**31 - 1):
            emu2 = E.Emu(rom)
            synth_1d(emu2, axis, cells, tc, int_axis=True)
            emu2.call(entry, regs={4: RAM_REC, 5: x & M32})
            i, fr = search_i(axis, x)
            want = lerp_i(cells[i], cells[i + 1] if i + 1 < len(cells) else 0, fr) & mask
            ok &= emu2.R[0] == want and not emu2.uninit_reads
            outs.append((x, emu2.R[0]))
        say(f'   synthetic {entry:06X} axis {axis} cells {cells}: ' + ' '.join(f'{x}->{v}' for x, v in outs))
    record('0BE88C / 0BE8C4 synthetic: clamp both ends, delta magnitude truncated (rising: floor; falling: toward '
           'cell i), byte +2 / +12 / +16 never read', ok)


# ============================================================================
def run_2d(rom, emu, entry, rec, x, y):
    emu.call(entry, regs={4: rec}, fregs={4: x, 5: y})


def sec_2d(rom, sites):
    say('\n==== F. 0x0BE8E4  2-D lookup, float result ====')
    table = [u32(rom, 0x0BE914 + 4 * i) for i in range(5)]
    say('   dispatch table of longs at 0x0BE914:', ' '.join(f'[+0x{4 * i:02X}]=0x{v:06X}' for i, v in enumerate(table)))
    record('0BE914 table = 0BEBC0, 0BEC4C, 0BEC78, 0BEBF0, 0BEC1C (indexed by the raw typecode byte at record+16)',
           table == [0x0BEBC0, 0x0BEC4C, 0x0BEC78, 0x0BEBF0, 0x0BEC1C])
    recs = [r for r in records_of(sites, 0x0BE8E4) if plausible_rec(rom, r, True) and rom[r + 16] in FMT]
    emu = E.Emu(rom)
    by_tc = {}
    exact_bad = exact_n = orc_bad = orc_n = orc_tabs = 0
    worst = ''
    for rec in recs:
        na, nb, tc = u16(rom, rec), u16(rom, rec + 2), rom[rec + 16]
        ax_a = [fl(rom, u32(rom, rec + 4) + 4 * i) for i in range(na)]
        ax_b = [fl(rom, u32(rom, rec + 8) + 4 * i) for i in range(nb)]
        cells = cells_at(rom, u32(rom, rec + 12), na * nb + na + 1, tc)
        scale, bias = fl(rom, rec + 20), fl(rom, rec + 24)
        by_tc[tc] = by_tc.get(tc, 0) + 1
        mono = all(ax_a[i] < ax_a[i + 1] for i in range(na - 1)) and all(ax_b[i] < ax_b[i + 1] for i in range(nb - 1))
        pa = coarse_points(ax_a) if mono else [ax_a[0], ax_a[-1]]
        pb = coarse_points(ax_b) if mono else [ax_b[0], ax_b[-1]]
        phys = None
        if mono and T.is_2d(rom, rec):
            t = T.read_table(rom, rec)
            flat = [v for plane in t['values'] for v in plane]
            if all(normal(v) for v in t['axes']['x'] + t['axes']['y'] + flat):
                phys = t
                orc_tabs += 1
        for x in pa:
            for y in pb:
                run_2d(rom, emu, 0x0BE8E4, rec, x, y)
                got = emu.FR[0]
                want = post_scale(model_2d_raw(ax_a, ax_b, cells, x, y), tc, scale, bias)
                exact_n += 1
                if not same_float(got, want):
                    exact_bad += 1
                    worst = worst or f'0x{rec:06X} ({x},{y}): emu {E.b2f(got)} model {want}'
                if phys:
                    # read_table: axes["y"] is the +4 axis (count byte +1), axes["x"] the +8 axis (count byte +3),
                    # values[p][i] with p along +8 and i along +4.
                    col = [lin(phys['axes']['y'], plane, x) for plane in phys['values']]
                    o = lin(phys['axes']['x'], col, y)
                    orc_n += 1
                    mx = max(abs(v) for plane in phys['values'] for v in plane)
                    if not abs(E.b2f(got) - o) <= 1e-4 * max(1.0, abs(o), mx):
                        orc_bad += 1
                        worst = worst or f'0x{rec:06X} ({x},{y}): emu {E.b2f(got)} read_table oracle {o}'
    names = ', '.join(f'typecode 0x{k:02X}: {v}' for k, v in sorted(by_tc.items()))
    say(f'   records the sweep finds passed to 0x0BE8E4 by literal: {len(recs)}  ({names})')
    for k in (0x00, 0x04, 0x08, 0x0C, 0x10):
        quoted(f'F_tc_{k:02X}', by_tc.get(k, 0))
    quoted('F_points', exact_n)
    quoted('F_oracle_records', orc_tabs)
    quoted('F_oracle_points', orc_n)
    record('0BE8E4 == model on every record the sweep finds passed to it (bit-exact; FPU results truncated, fmac fused)',
           exact_bad == 0 and exact_n > 3000, f'{len(recs)} records, {exact_n} points, {exact_bad} mismatches {worst}')
    record('0BE8E4 == desc_types.read_table() + bilinear interpolation of physical values (tolerance)',
           orc_bad == 0 and orc_n > 3000, f'{orc_tabs} records, {orc_n} points, {orc_bad} mismatches')

    # synthetic: orientation, every typecode, skip, unread fields
    s_ax_a = [f32(v) for v in (0.0, 10.0, 20.0)]        # fr4, count at +0, pointer at +4
    s_ax_b = [f32(v) for v in (100.0, 200.0)]           # fr5, count at +2, pointer at +8
    say('   synthetic: axis A (fr4, +0/+4) =', s_ax_a, ' axis B (fr5, +2/+8) =', s_ax_b)
    synth = {
        0x00: [f32(v) for v in (1.0, 2.0, 3.0, 11.0, 12.0, 13.5)],
        0x04: [1, 2, 3, 11, 12, 255],
        0x08: [1, 2, 3, 1100, 1200, 65535],
        0x0C: [-1, -2, -3, 11, 12, -128],
        0x10: [-1, -2, -3, 1100, 1200, -32768],
    }
    probes = [(0.0, 100.0), (10.0, 100.0), (20.0, 100.0), (0.0, 200.0), (20.0, 200.0), (5.0, 100.0), (0.0, 150.0),
              (15.0, 175.0), (-5.0, 50.0), (25.0, 250.0), (NAN, 100.0), (0.0, NAN)]
    bad = n = 0
    say('   typecode cells (flat, in memory order)            ' + '  '.join(f'({a:g},{b:g})' for a, b in probes))
    for tc, cells in synth.items():
        row = []
        for x, y in probes:
            emu2 = E.Emu(rom)
            synth_2d(emu2, s_ax_a, s_ax_b, cells, tc, tc_byte=tc, scale=0.5, bias=3.0)
            emu2.mach, emu2.macl = 0x55556666, 0x77778888
            emu2.call(0x0BE8E4, regs={4: RAM_REC}, fregs={4: x, 5: y})
            want = post_scale(model_2d_raw(s_ax_a, s_ax_b, cells, f32(x), f32(y)), tc, f32(0.5), f32(3.0))
            n += 1
            bad += not (same_float(emu2.FR[0], want) and not emu2.uninit_reads
                        and emu2.mach == 0x55556666 and emu2.macl == 0x77778888)
            row.append(emu2.fr(0))
        say(f'   0x{tc:02X}     {str(cells):40} ' + '  '.join(f'{v:<9.6g}' for v in row))
    record('0BE8E4 synthetic: cell(iA,iB) = data[iB*countA + iA]; fr4 -> axis at +4 (count +0); fr5 -> axis at +8 '
           '(count +2); typecode 0 raw, others scale*raw+bias; MACH/MACL preserved', bad == 0, f'{n} cases, {bad} mismatches')
    emu2 = E.Emu(rom)
    synth_2d(emu2, s_ax_a, s_ax_b, synth[0x00], 0x00, tc_byte=0x00)
    emu2.call(0x0BE8E4, regs={4: RAM_REC}, fregs={4: 15.0, 5: 175.0})
    ok0 = not emu2.uninit_reads and emu2.R[4] == RAM_REC
    emu3 = E.Emu(rom)
    synth_2d(emu3, s_ax_a, s_ax_b, synth[0x08], 0x08, tc_byte=0x08)
    emu3.call(0x0BE8E4, regs={4: RAM_REC}, fregs={4: 15.0, 5: 175.0})
    ok8 = emu3.uninit_reads == {RAM_REC + 20, RAM_REC + 24} and emu3.R[4] == RAM_REC + 24
    say(f'   typecode 0x00 with +20/+24 uninitialised: uninit reads {sorted(emu2.uninit_reads)} ; '
        f'typecode 0x08: record offsets {[hex(a - RAM_REC) for a in sorted(emu3.uninit_reads)]}')
    record('0BE8E4 reads record +20 and +24 ONLY when the byte at +16 is non-zero', ok0 and ok8)

    say('\n==== G. 0x0BE928 (uint8 cells) / 0x0BE944 (uint16 cells)  2-D lookup, integer result in r0 ====')
    emu = E.Emu(rom)
    for entry, tc, mask in ((0x0BE928, 0x04, 0xFF), (0x0BE944, 0x08, 0xFFFF)):
        recs = [r for r in records_of(sites, entry) if plausible_rec(rom, r, True)]
        bad = n = 0
        for rec in recs:
            na, nb = u16(rom, rec), u16(rom, rec + 2)
            ax_a = [fl(rom, u32(rom, rec + 4) + 4 * i) for i in range(na)]
            ax_b = [fl(rom, u32(rom, rec + 8) + 4 * i) for i in range(nb)]
            cells = cells_at(rom, u32(rom, rec + 12), na * nb + na + 1, tc)
            for x in coarse_points(ax_a):
                for y in coarse_points(ax_b):
                    run_2d(rom, emu, entry, rec, x, y)
                    want = ftrc(model_2d_raw(ax_a, ax_b, cells, x, y)) & mask
                    n += 1
                    bad += emu.R[0] != want
            run_2d(rom, emu, entry, rec, ax_a[0], ax_b[0])
            say(f'   0x{entry:06X} record 0x{rec:06X} {na}x{nb}  byte+16=0x{rom[rec + 16]:02X}  first cells {cells[:6]}  '
                f'r0 at (axisA[0],axisB[0]) = {emu.R[0]}')
        quoted(f'G_points_{entry:06X}', n)
        record(f'{entry:06X} == trunc(bilinear interp of {"uint8" if tc == 4 else "uint16"} cells) & 0x{mask:X} on every '
               f'record passed to it (bit-exact)', bad == 0 and n > 30, f'{len(recs)} records, {n} points, {bad} mismatches')
    ok = True
    for entry, tc, cells, mask in ((0x0BE928, 0x04, synth[0x04], 0xFF), (0x0BE944, 0x08, synth[0x08], 0xFFFF)):
        outs = []
        for x, y in probes:
            emu2 = E.Emu(rom)
            synth_2d(emu2, s_ax_a, s_ax_b, cells, tc)                  # byte +16, +20, +24 uninitialised
            emu2.call(entry, regs={4: RAM_REC}, fregs={4: x, 5: y})
            want = ftrc(model_2d_raw(s_ax_a, s_ax_b, cells, f32(x), f32(y))) & mask
            ok &= emu2.R[0] == want and not emu2.uninit_reads
            outs.append(emu2.R[0])
        say(f'   synthetic {entry:06X} cells {cells}: {outs}')
    record('0BE928 / 0BE944 read record +0, +2 (words), +4, +8, +12 only: byte +16, +20, +24 never read', ok)


# ============================================================================
def sec_record_layout(rom, sites):
    say('\n==== H. record length, measured from the spacing of records that are actually passed to a wrapper ====')
    recs = {}
    for entry in WRAPPERS:
        two = entry in (0x0BE8E4, 0x0BE928, 0x0BE944)
        for r in records_of(sites, entry):
            if plausible_rec(rom, r, two):
                recs.setdefault(r, entry)
    order = sorted(recs)
    say(f'   {len(order)} distinct records in address order; the last one (0x{order[-1]:06X}) has no successor and is '
        'not in the histogram')
    classes = [
        ('0BE830 byte+2 == 0', lambda e, b: e == 0x0BE830 and b == 0, 12),
        ('0BE830 byte+2 != 0', lambda e, b: e == 0x0BE830 and b != 0, 20),
        ('0BE874/8AC/88C/8C4', lambda e, b: e in (0x0BE874, 0x0BE8AC, 0x0BE88C, 0x0BE8C4), 12),
        ('0BE8E4 byte+16 == 0', lambda e, b: e == 0x0BE8E4 and b == 0, 20),
        ('0BE8E4 byte+16 != 0', lambda e, b: e == 0x0BE8E4 and b != 0, 28),
        ('0BE928/944', lambda e, b: e in (0x0BE928, 0x0BE944), 20),
    ]
    ok = True
    for name, pred, want in classes:
        h = {}
        for i, r in enumerate(order[:-1]):
            entry = recs[r]
            two = entry in (0x0BE8E4, 0x0BE928, 0x0BE944)
            if pred(entry, rom[r + 16] if two else rom[r + 2]):
                gap = order[i + 1] - r
                h[gap] = h.get(gap, 0) + 1
        tot = sum(h.values())
        top = sorted(h.items(), key=lambda kv: -kv[1])
        say(f'   {name:22} records {tot:4}  smallest gap {min(h):3}  at exactly {want}: {h.get(want, 0):4}   other gaps: '
            + ', '.join(f'{g} x{c}' for g, c in top if g != want))
        quoted(f'H_n_{name}', tot)
        quoted(f'H_at_{name}', h.get(want, 0))
        ok &= min(h) == want and top[0][0] == want
    record('record spacing: the smallest AND the most common gap is 12 bytes (1-D, byte+2 == 0 via 0BE830, and every '
           'record of 0BE874/0BE8AC/0BE88C/0BE8C4), 20 bytes (1-D scaled; 2-D byte+16 == 0; 2-D via 0BE928/0BE944), '
           '28 bytes (2-D scaled)', ok)

    # ---- the records handed to the six integer-result wrappers (the table in the header of the analysis file)
    int_wrappers = (0x0BE874, 0x0BE88C, 0x0BE8AC, 0x0BE8C4, 0x0BE928, 0x0BE944)
    # every axis / cell pointer target of every record found: "the next thing in the ROM after this table's cells"
    targets = set()
    for r, entry in recs.items():
        two = entry in (0x0BE8E4, 0x0BE928, 0x0BE944)
        targets.update(u32(rom, r + o) for o in ((4, 8, 12) if two else (4, 8)))
    tsorted = sorted(targets)
    n0 = nint = nofit = 0
    room_ok = True
    say('   records handed to the six integer-result wrappers ("would not fit": 4-byte cells would run past the next')
    say('   axis / cell pointer target of any record the sweep found):')
    say(';   record    wrapper  byte   shape   cells read as  cell pointer  bytes  call sites')
    ncalls = {}
    for entry in int_wrappers:
        for _, rs in sites[entry]:
            for r in rs:
                ncalls[r] = ncalls.get(r, 0) + 1
    for r in sorted(r for r, e in recs.items() if e in int_wrappers):
        entry = recs[r]
        two = entry in (0x0BE928, 0x0BE944)
        w = 1 if entry in (0x0BE874, 0x0BE88C, 0x0BE928) else 2
        ncell = u16(rom, r) * (u16(rom, r + 2) if two else 1)
        dp = u32(rom, r + 12 if two else r + 8)
        byte = rom[r + 16] if two else rom[r + 2]
        nxt = next((t for t in tsorted if t > dp), None)
        room_ok &= nxt is None or dp + ncell * w <= nxt
        fits = nxt is None or dp + ncell * 4 <= nxt
        nint += 1
        n0 += byte == 0
        nofit += byte == 0 and not fits
        shape = f'{u16(rom, r)}x{u16(rom, r + 2)}' if two else f'{u16(rom, r)}'
        note = '' if byte else ('   <-- byte says float32' + ('' if fits else ' (would not fit)'))
        say(f';   0x{r:06X}  {entry:06X}   0x{byte:02X}   {shape:<7} {"uint8" if w == 1 else "uint16":<14} 0x{dp:06X}      '
            f'{ncell * w:<6} {ncalls.get(r, 0)}{note}')
    say(f'   {nint} records; typecode-position byte is 0x00 on {n0}; float32 cells would not fit on {nofit} of those')
    quoted('H_int_records', nint)
    quoted('H_int_byte0', n0)
    quoted('H_int_nofit', nofit)
    record('integer-result wrappers are passed records whose typecode-position byte is 0x00 (cells are still uint8/uint16)',
           n0 >= 40 and nint >= 70, f'{n0} of {nint}')
    record('for every one of those records the cells, at the width the WRAPPER reads, end before the next axis / cell '
           'pointer target', room_ok)
    # desc_types.read_table() on the same records (compared, never trusted).  Until corrections item 106 it typed
    # them by the byte (section D measures what that gave); it now consults fixed_type_records.json.
    rt_ok = rt_n = 0
    for r in sorted(r for r, e in recs.items() if e in int_wrappers):
        entry = recs[r]
        two = entry in (0x0BE928, 0x0BE944)
        tc = 0x04 if entry in (0x0BE874, 0x0BE88C, 0x0BE928) else 0x08
        ncell = u16(rom, r) * (u16(rom, r + 2) if two else 1)
        cells = cells_at(rom, u32(rom, r + 12 if two else r + 8), ncell, tc)
        fx = T.fixed_type(r)
        try:
            t = T.read_table(rom, r)
        except Exception:                                            # noqa: BLE001
            t = None
        ok = (t is not None and bool(fx) and fx.get('cell_typecode') == tc and f'0x{entry:06X}' in fx.get('consumers', {})
              and t['scale'] is None and t['bias'] is None)
        if ok and two:
            ok = [v for plane in t['values'] for v in plane] == cells   # values[p][i]: p along +8, i along +4 = memory order
        elif ok:
            ok = t['values'] == cells
            if entry in (0x0BE88C, 0x0BE8C4):                          # signed-long axis
                ok &= t['axes']['x'] == [s32(u32(rom, u32(rom, r + 4) + 4 * i)) for i in range(u16(rom, r))]
        rt_n += 1
        rt_ok += ok
    say(f'   desc_types.read_table() on these {rt_n} records: wrapper\'s cell type, cells in memory order, no scale/bias'
        f' (and the signed-long axis for 0BE88C / 0BE8C4) on {rt_ok}')
    record('desc_types.read_table(), as changed by corrections item 106, reads every record handed to an integer-result '
           'wrapper with that wrapper\'s cell type and no scale/bias (int32 axis for 0BE88C / 0BE8C4): cells equal',
           rt_ok == rt_n == nint, f'{rt_ok} of {rt_n}')
    for r in sorted(r for r, e in recs.items() if e in (0x0BE88C, 0x0BE8C4)):
        ax = u32(rom, r + 4)
        say(f';   0x{r:06X}  axis 0x{ax:06X}  longs ' + ', '.join(str(s32(u32(rom, ax + 4 * i))) for i in range(u16(rom, r))))


# ============================================================================
def sec_minmax(rom):
    say('\n==== I. 0x0BE960 / 0x0BE970  larger / smaller of fr4, fr5 ====')
    vals = [-INF, -1e30, -2.5, -1.0, -0.0, 0.0, 1e-30, 1.0, 1.0000001, 2.5, 6700.0, 1e30, INF, NAN]
    emu = E.Emu(rom)
    bad960 = bad970 = n = 0
    say('   fr4            fr5            0BE960 -> fr0      0BE970 -> fr0')
    for a in vals:
        for b in vals:
            fa, fb = f32(a), f32(b)
            emu.call(0x0BE960, fregs={4: a, 5: b})
            g960, s960 = emu.FR[0], emu.FR[6]
            emu.call(0x0BE970, fregs={4: a, 5: b})
            g970, s970 = emu.FR[0], emu.FR[6]
            w960 = fa if fa > fb else fb          # 0BE960 fcmp/gt fr5,fr4 : T = fr4 > fr5 -> fr4, else fr5
            w970 = fa if fb > fa else fb          # 0BE970 fcmp/gt fr4,fr5 : T = fr5 > fr4 -> fr4, else fr5
            n += 1
            bad960 += not (g960 == bits(w960) or (w960 != w960 and same_float(g960, NAN))) or s960 != g960
            bad970 += not (g970 == bits(w970) or (w970 != w970 and same_float(g970, NAN))) or s970 != g970
            if not (fa != fa or fb != fb):
                bad960 += E.b2f(g960) != max(fa, fb)
                bad970 += E.b2f(g970) != min(fa, fb)
            if (a, b) in ((1.0, 2.5), (2.5, 1.0), (-2.5, -1.0), (6700.0, 6700.0), (0.0, -0.0), (-0.0, 0.0),
                          (-INF, 1.0), (1.0, INF)) or (a != a and b == 1.0) or (a == 1.0 and b != b):
                say(f'   {a!r:14} {b!r:14} {E.b2f(g960)!r:18} {E.b2f(g970)!r}')
    record('0BE960 returns the LARGER of fr4, fr5 (max); a NaN in either input returns fr5; fr6 = fr0 on exit',
           bad960 == 0, f'{n} pairs, {bad960} mismatches')
    record('0BE970 returns the SMALLER of fr4, fr5 (min); a NaN in either input returns fr5; fr6 = fr0 on exit',
           bad970 == 0, f'{n} pairs, {bad970} mismatches')


# ============================================================================
def sec_complement(rom):
    say('\n==== J. 0x0BE9A0 / 0x0BE9B0 build value+complement ; 0x0BE980 / 0x0BE990 check it ====')
    emu = E.Emu(rom)
    bad = n = 0
    for hi in (0x00000000, 0xFFFFFF00, 0x12345600, 0x00000100):
        for v in range(256):
            emu.call(0x0BE9A0, regs={4: hi | v})
            n += 1
            bad += emu.R[0] != ((v << 8) | (~v & 0xFF))
    say('   0BE9A0: r4=0x00 -> 0x%04X  r4=0x01 -> 0x%04X  r4=0x5A -> 0x%04X  r4=0xFF -> 0x%04X  r4=0x12345678 -> 0x%08X'
        % tuple(emu.call(0x0BE9A0, regs={4: v}) and emu.R[0] for v in (0, 1, 0x5A, 0xFF, 0x12345678)))
    record('0BE9A0: r0 = ((r4 & 0xFF) << 8) | (~r4 & 0xFF), upper 16 bits zero (exhaustive in the low byte)',
           bad == 0, f'{n} cases')
    bad = n = 0
    rnd = random.Random(1)
    for v in [0, 1, 0x5A5A, 0xFFFF, 0x8000, 0x7FFF, 0x12345678, 0xFFFFFFFF, 0xFFFF0000] + [rnd.getrandbits(32) for _ in range(400)]:
        emu.call(0x0BE9B0, regs={4: v})
        n += 1
        bad += emu.R[0] != (((v & 0xFFFF) << 16) | (~v & 0xFFFF))
    say('   0BE9B0: r4=0x0000 -> 0x%08X  r4=0x0001 -> 0x%08X  r4=0x5A5A -> 0x%08X  r4=0x12345678 -> 0x%08X'
        % tuple(emu.call(0x0BE9B0, regs={4: v}) and emu.R[0] for v in (0, 1, 0x5A5A, 0x12345678)))
    record('0BE9B0: r0 = ((r4 & 0xFFFF) << 16) | (~r4 & 0xFFFF)', bad == 0, f'{n} cases')

    slot = 0xFFFF3000
    bad = zero = 0
    for w in range(65536):                                    # exhaustive
        emu.ram_u16(slot, w)
        emu.call(0x0BE980, regs={4: slot})
        hi, lo = w >> 8, w & 0xFF
        want = (0xFF - lo - hi) & 0xFF
        bad += emu.R[0] != want
        if emu.R[0] == 0:
            zero += 1
            bad += hi != (~lo & 0xFF)
    say(f'   0BE980 over all 65,536 words: r0 == 0 on {zero} of them (exactly the words hi == ~lo)')
    for w in (0x00FF, 0x5AA5, 0xFF00, 0x0000, 0x5AA4, 0x5BA5, 0xFFFF):
        emu.ram_u16(slot, w)
        emu.call(0x0BE980, regs={4: slot})
        say(f'      word 0x{w:04X} -> r0 = 0x{emu.R[0]:02X}')
    record('0BE980: r0 = (0xFF - lo - hi) & 0xFF of the word at @r4 ; zero iff hi == ~lo (exhaustive)',
           bad == 0 and zero == 256)
    # round trip with 0BE9A0
    bad = 0
    for v in range(256):
        emu.call(0x0BE9A0, regs={4: v})
        emu.ram_u16(slot, emu.R[0])
        emu.call(0x0BE980, regs={4: slot})
        bad += emu.R[0] != 0
        for bit in range(16):                                 # any single-bit corruption is detected
            emu.ram_u16(slot, (((v << 8) | (~v & 0xFF)) ^ (1 << bit)))
            emu.call(0x0BE980, regs={4: slot})
            bad += emu.R[0] == 0
    record('0BE980(0BE9A0(v)) == 0 for every v; every single-bit flip of the stored word gives non-zero', bad == 0,
           '256 values x 16 bit flips')
    bad = n = 0
    cases = [0x0000FFFF, 0x5A5AA5A5, 0xFFFF0000, 0, 0xFFFFFFFF, 0x12345678, 0x1234EDCB, 0x1234EDCA, 0x8000_7FFF]
    cases += [rnd.getrandbits(32) for _ in range(2000)]
    cases += [((v & 0xFFFF) << 16) | (~v & 0xFFFF) for v in [rnd.getrandbits(16) for _ in range(500)]]
    for L in cases:
        emu.ram_u32(slot, L)
        emu.call(0x0BE990, regs={4: slot})
        hi, lo = L >> 16, L & 0xFFFF
        n += 1
        bad += emu.R[0] != ((0xFFFF - lo - hi) & 0xFFFF)
        bad += (emu.R[0] == 0) != (hi == (~lo & 0xFFFF))
    for L in (0x0000FFFF, 0x5A5AA5A5, 0x1234EDCB, 0x1234EDCA, 0x00000000):
        emu.ram_u32(slot, L)
        emu.call(0x0BE990, regs={4: slot})
        say(f'      long 0x{L:08X} -> r0 = 0x{emu.R[0]:04X}')
    record('0BE990: r0 = (0xFFFF - lo16 - hi16) & 0xFFFF of the long at @r4 ; zero iff hi16 == ~lo16', bad == 0, f'{n} cases')


# ============================================================================
def sec_fixed(rom):
    say('\n==== K. 0x0BE9C0 saturating signed 16.16 multiply ; 0x0BEA98 saturating signed subtract ====')
    emu = E.Emu(rom)
    rnd = random.Random(7)
    edge = [0, 1, -1, 0x10000, -0x10000, 0x8000, -0x8000, 0x7FFFFFFF, -0x80000000, 0x7FFF0000, 0x00018000, 3, -3,
            0xFFFF, -0xFFFF, 0x12345678, -0x12345678, 0x00B504F3, 0x40000000, -0x40000000]
    pairs = [(a, b) for a in edge for b in edge]
    pairs += [(rnd.randint(-2**31, 2**31 - 1), rnd.randint(-2**31, 2**31 - 1)) for _ in range(600)]
    pairs += [(rnd.randint(-2**20, 2**20), rnd.randint(-2**20, 2**20)) for _ in range(600)]
    bad = 0
    say('   r4           r5           -> r0           (as 16.16: a * b = result)')
    for k, (a, b) in enumerate(pairs):
        emu.mach, emu.macl = 0xCAFEBABE, 0x0BADF00D
        emu.call(0x0BE9C0, regs={4: a & M32, 5: b & M32})
        want = sat32((a * b) >> 16) & M32
        bad += not (emu.R[0] == want and emu.mach == 0xCAFEBABE and emu.macl == 0x0BADF00D)
        if (a, b) in ((0x10000, 0x10000), (0x18000, 0x18000), (-0x10000, 0x8000), (1, 1), (-1, 1), (0x7FFFFFFF, 0x7FFFFFFF),
                      (-0x80000000, 0x7FFFFFFF), (-0x80000000, -0x80000000), (0x7FFF0000, 0x10000), (0x40000000, 0x18000),
                      (3, 0x8000), (-3, 0x8000), (0x00B504F3, 0x00B504F3)):
            say(f'   0x{a & M32:08X}   0x{b & M32:08X}   -> 0x{emu.R[0]:08X}   ({a / 65536:.5f} * {b / 65536:.5f} = {s32(emu.R[0]) / 65536:.5f})')
    record('0BE9C0: r0 = sat32( (s64)r4 * (s64)r5 >> 16 ), arithmetic shift (floor), MACH/MACL preserved',
           bad == 0, f'{len(pairs)} pairs, {bad} mismatches')

    pairs = [(a, b) for a in edge for b in edge] + [(rnd.randint(-2**31, 2**31 - 1), rnd.randint(-2**31, 2**31 - 1)) for _ in range(1000)]
    bad = 0
    say('   r4           r5           -> r0  (0BEA98)')
    for a, b in pairs:
        emu.call(0x0BEA98, regs={4: a & M32, 5: b & M32})
        bad += emu.R[0] != (sat32(a - b) & M32)
        if (a, b) in ((0, 1), (1, 0), (0x7FFFFFFF, -1), (-0x80000000, 1), (0x7FFFFFFF, -0x80000000), (-0x80000000, 0x7FFFFFFF),
                      (-0x80000000, -0x80000000), (0x12345678, -0x12345678), (0, -0x80000000)):
            say(f'   0x{a & M32:08X}   0x{b & M32:08X}   -> 0x{emu.R[0]:08X}')
    record('0BEA98: r0 = sat32(r4 - r5) (signed; 0x7FFFFFFF on positive overflow, 0x80000000 on negative)',
           bad == 0, f'{len(pairs)} pairs, {bad} mismatches')


# ============================================================================
def model_lag_f(a, b, k, eps):
    a, b, k, eps = f32(a), f32(b), f32(k), f32(eps)  # the inputs, loaded as sh2e_emu loads them
    if (bits(b) & 0x7F800000) == 0x7F800000:          # 0BEA48 cmp/eq : fr5 is Inf or NaN
        return a
    d = fsub(b, a)                                    # 0BEA4C fsub fr4,fr5
    w = fsub(1.0, k)                                  # 0BEA50 fsub fr6,fr0
    r = fmac(w, d, a)                                 # 0BEA54 fmac fr0,fr5,fr6
    if eps > abs(fsub(a, r)):                         # 0BEA58 fsub ; 0BEA5A fabs ; 0BEA5C fcmp/gt fr5,fr7
        return a
    return r


def sec_lag(rom):
    say('\n==== L. 0x0BEA40  float first-order lag with snap ; 0x0BEA6C  integer first-order lag ====')
    emu = E.Emu(rom)
    rnd = random.Random(11)
    cases = []
    for a in (0.0, 1.0, -1.0, 100.0, 6700.0, 1e-3, -250.5, INF, -INF, NAN):
        for b in (0.0, 1.0, 99.0, 100.0, 100.001, -40.0, 7000.0, INF, -INF, NAN):
            for k in (0.0, 0.001907349, 0.05, 0.5, 1.0, 1.5, -0.5):
                for eps in (0.0, 1e-6, 0.001907349, 0.5, 1000.0, NAN):
                    cases.append((a, b, k, eps))
    cases += [(rnd.uniform(-1e4, 1e4), rnd.uniform(-1e4, 1e4), rnd.random(), rnd.choice((0.0, 1e-3, 0.1, 5.0))) for _ in range(2000)]
    bad = 0
    say('   fr4 (A)     fr5 (B)     fr6 (k)       fr7 (eps)    -> fr0')
    for a, b, k, eps in cases:
        emu.call(0x0BEA40, fregs={4: a, 5: b, 6: k, 7: eps})
        want = model_lag_f(a, b, k, eps)
        bad += not same_float(emu.FR[0], want)
        if (a, b, k, eps) in ((100.0, 0.0, 0.05, 0.0), (100.0, 0.0, 0.0, 0.0), (100.0, 0.0, 1.0, 0.0), (100.0, 99.0, 0.5, 0.0),
                              (100.0, 99.0, 0.5, 0.5), (100.0, 99.0, 0.5, 1000.0), (100.0, 100.001, 0.05, 0.001907349),
                              (100.0, 0.0, 1.5, 0.0), (100.0, 0.0, -0.5, 0.0), (100.0, 0.0, 0.05, 1000.0)) \
                or (a == 100.0 and b != b and k == 0.05 and eps == 0.0) or (a == 100.0 and b == INF and k == 0.05 and eps == 0.0) \
                or (a == INF and b == 0.0 and k == 0.05 and eps == 0.0) or (a != a and b == 0.0 and k == 0.05 and eps == 0.0) \
                or (a == 100.0 and b == 99.0 and k == 0.5 and eps != eps):
            say(f'   {a!r:10}  {b!r:10}  {k!r:12}  {eps!r:11}  -> {emu.fr(0)!r}')
    quoted('L_cases_0BEA40', len(cases))
    record('0BEA40: r = fr4 + (1-fr6)*(fr5-fr4); fr5 Inf/NaN -> fr4; fr7 > |fr4-r| -> fr4; else r  (bit-exact)',
           bad == 0, f'{len(cases)} cases, {bad} mismatches')
    # fr4 infinite with fr5 finite: the exponent test does not look at fr4, so the arithmetic runs.
    #   k <  1: (1-k) > 0, (1-k)*(B-A) is the opposite infinity, + A = NaN
    #   k == 1: 0 * Inf = NaN
    #   k >  1: (1-k) < 0, (1-k)*(B-A) is the SAME infinity as A, + A = A; then |A - r| is NaN, the compare is false
    say('   fr4 infinite, fr5 finite:   A      B     k      eps  -> fr0')
    ok = True
    for a, b, k, eps, want in ((INF, 0.0, 0.05, 0.0, NAN), (INF, 0.0, 1.0, 0.0, NAN), (INF, 0.0, 2.0, 0.0, INF),
                               (INF, 5.0, 1.5, 0.0, INF), (-INF, 0.0, 3.0, 0.0, -INF), (-INF, 0.0, 0.5, 0.0, NAN),
                               (INF, 0.0, 2.0, 1000.0, INF), (100.0, NAN, 0.05, 0.0, 100.0), (100.0, INF, 0.05, 0.0, 100.0)):
        emu.call(0x0BEA40, fregs={4: a, 5: b, 6: k, 7: eps})
        ok &= same_float(emu.FR[0], want)
        say(f'                            {a!r:6} {b!r:5} {k!r:5} {eps!r:6} -> {emu.fr(0)!r}')
    record('0BEA40 with fr4 = +/-Inf and fr5 finite: NaN when fr6 <= 1, fr4 itself when fr6 > 1; fr5 Inf/NaN returns fr4', ok)
    # iterating with fr5 := previous result converges on fr4 and then snaps exactly
    y, steps = 0.0, 0
    while steps < 5000:
        emu.call(0x0BEA40, fregs={4: 100.0, 5: y, 6: 0.05, 7: 0.01})
        y = emu.fr(0)
        steps += 1
        if y == 100.0:
            break
    say(f'   iterating B := result with A=100, k=0.05, eps=0.01 from B=0: reaches exactly 100.0 after {steps} calls')
    record('0BEA40 iterated (fr5 := previous fr0) converges on fr4 and snaps to it exactly', y == 100.0 and 100 < steps < 400,
           f'{steps} calls')

    def model_lag_i(a, b, k):
        kk = fmul(ffloat(k & 0xFFFF), float(frac_of(0x3B800000)))  # 0BEA72 extu.w ; 0BEA76 float ; 0BEA78 fmul 1/256
        w = fsub(1.0, kk)                                        # 0BEA7A fsub fr3,fr1
        d = fsub(ffloat(s32(b)), ffloat(s32(a)))                 # 0BEA7E / 0BEA82 float (truncates above 2^24) ; 0BEA84
        return (a + ftrc(fmul(w, d))) & M32                      # 0BEA86 fmul ; 0BEA88 ftrc ; 0BEA8C add

    c256 = E.b2f(u32(rom, 0x0BEA94))
    record('constant at 0x0BEA94 is 0x3B800000 = 1/256', u32(rom, 0x0BEA94) == 0x3B800000 and c256 == 1 / 256)
    cases = []
    for a in (0, 1, -1, 100, -100, 1000, 65535, 32767, -32768, 0x7FFFFFFF, -0x80000000, 16777217):
        for b in (0, 1, -1, 99, 101, -100, 2000, 65535, -32768, 0x7FFFFFFF, -0x80000000):
            for k in (0, 1, 13, 64, 128, 255, 256, 257, 512, 0xFFFF, 0x10000, 0x10080):
                cases.append((a, b, k))
    cases += [(rnd.randint(-70000, 70000), rnd.randint(-70000, 70000), rnd.randint(0, 300)) for _ in range(2000)]
    bad = 0
    say('   r4 (A)   r5 (B)   r6 (k/256)  -> r0')
    for a, b, k in cases:
        emu.call(0x0BEA6C, regs={4: a & M32, 5: b & M32, 6: k & M32})
        bad += emu.R[0] != model_lag_i(a & M32, b & M32, k)
        if (a, b, k) in ((100, 0, 0), (100, 0, 64), (100, 0, 128), (100, 0, 255), (100, 0, 256), (100, 0, 512), (100, 99, 128),
                         (100, 101, 128), (-100, 0, 64), (100, 0, 0x10080), (0, 1, 1), (0, -1, 1), (1000, 2000, 13)):
            say(f'   {a:<8} {b:<8} {k:<11} -> {s32(emu.R[0])}')
    record('0BEA6C: r0 = r4 + trunc( (1 - (r6 & 0xFFFF)/256) * (float(r5) - float(r4)) )  (bit-exact, float32 steps)',
           bad == 0, f'{len(cases)} cases, {bad} mismatches')


# ============================================================================
def sec_misc(rom):
    say('\n==== M. 0x0BEAB0  |fr4 - fr5| ; 0x0BEAB8  busy-wait ====')
    emu = E.Emu(rom)
    vals = [-INF, -1e30, -2.5, -0.0, 0.0, 1.0, 2.5, 6700.0, 1e30, INF, NAN]
    bad = n = 0
    for a in vals:
        for b in vals:
            emu.call(0x0BEAB0, fregs={4: a, 5: b})
            want = abs(fsub(f32(a), f32(b)))               # fsub fr5,fr4 ; fabs fr4
            n += 1
            bad += not same_float(emu.FR[0], want) or emu.FR[4] != emu.FR[0]
    emu.call(0x0BEAB0, fregs={4: 1.0, 5: 2.5})
    x1 = emu.fr(0)
    emu.call(0x0BEAB0, fregs={4: 2.5, 5: 1.0})
    say(f'   0BEAB0: (1.0, 2.5) -> {x1!r} ; (2.5, 1.0) -> {emu.fr(0)!r}')
    record('0BEAB0: fr0 = fr4 = |fr4 - fr5|', bad == 0, f'{n} pairs')

    bad = 0
    say('   0BEAB8: r4 in   -> instructions executed  r5 at exit   r0 (unchanged from 0x12345678)')
    for r4 in (0, 1, 2, 3, 10, 300, 1000, 0x20000000, 0x20000001, 0xE0000000):
        emu = E.Emu(rom)
        emu.call(0x0BEAB8, regs={4: r4, 0: 0x12345678})
        lim = (r4 * 8) & M32
        want_steps = 5 + 2 + (3 * lim if lim else 0)       # mov,shll2,shll,cmp/hs,bt | loop of add,cmp/hs,bf | rts,nop
        ok = emu.R[5] == lim and emu.R[4] == lim and emu.R[0] == 0x12345678 and emu.steps == want_steps
        bad += not ok
        say(f'           0x{r4:08X} -> {emu.steps:<22} 0x{emu.R[5]:08X}   0x{emu.R[0]:08X}')
    record('0BEAB8: counts r5 from 0 up to (r4*8 mod 2^32), 3 instructions per count; returns nothing (r0 untouched); '
           'r4*8 == 0 returns at once', bad == 0)
    args = {}
    for _, st, _ in AUX_SITES[0x0BEAB8]:
        for v in st.get(4, ()) or ('?',):
            args[v] = args.get(v, 0) + 1
    say(f'   call sites of 0x0BEAB8: {len(AUX_SITES[0x0BEAB8])}; r4 = '
        + ', '.join(f'{k} x{v}' for k, v in sorted(args.items(), key=lambda kv: str(kv[0]))))
    for pc, st, _ in AUX_SITES[0x0BEAB8]:
        say(f'      0x{pc:06X}  r4 = {st.get(4, "?")}')
    record('0BEAB8 has 12 call sites, r4 a constant at every one: 300 x3, 2000 x3, 6 x2, 2, 40, 1800, 10000',
           {pc: st.get(4) for pc, st, _ in AUX_SITES[0x0BEAB8]} ==
           {0x005FEA: (6,), 0x006086: (6,), 0x0068AC: (2,), 0x006F50: (10000,), 0x008C30: (1800,), 0x00E7EC: (40,),
            0x00FA92: (2000,), 0x00FB4C: (2000,), 0x0108EE: (300,), 0x0118C6: (300,), 0x0118D4: (300,), 0x047D54: (2000,)})
    # caller 0x0118AC: set bit 15 of the word at 0xFFFFF738, wait 300; clear it, wait 300 (both stores in the jsr slots)
    record('caller 0x0118AC: or 0x8000 into the word at 0xFFFFF738 (stored in the slot of the first call, r4 = 300), then '
           'and 0x7FFF (stored in the slot of the second call, r4 = 300)',
           words_are(rom, [(0x0118BA, 0x9E16), (0x0118BC, 0xD30E), (0x0118BE, 0x62E1), (0x0118C0, 0x223B), (0x0118C2, 0x9413),
                           (0x0118C4, 0xD10D), (0x0118C6, 0x410B), (0x0118C8, 0x2E21), (0x0118CA, 0x930D), (0x0118CC, 0x62E1),
                           (0x0118CE, 0x2239), (0x0118D0, 0x940C), (0x0118D2, 0xD10A), (0x0118D4, 0x410B), (0x0118D6, 0x2E21)])
           and _lit(rom, 0x9E16, 0x0118BA) == 0xFFFFF738 and _lit(rom, 0xD30E, 0x0118BC) == 0x8000
           and _lit(rom, 0x930D, 0x0118CA) == 0x7FFF and _lit(rom, 0x9413, 0x0118C2) == 300
           and _lit(rom, 0xD10D, 0x0118C4) == 0x0BEAB8)


# ============================================================================
# The 1-D lookup in a CHOSEN rounding mode (frac_of / to_bits / rnd are defined at the top of this file).
# Section N runs it in the chip's mode and in the two alternatives, to measure what each would change.
def exact_1d(axis, cells, x, mode, fused, tc=0, scale=None, bias=None):
    """The 1-D lookup in exact arithmetic with every FPU result rounded in `mode`.  axis, cells, x: Fractions.
    fused: fmac rounds once; otherwise the product is rounded, then the sum.  tc != 0 applies scale and bias
    (0x0BE830); the integer-result wrappers have none.  Returns the exact value of the float32 result."""
    def mac(a, b, c):
        return rnd(a * b + c, mode) if fused else rnd(rnd(a * b, mode) + c, mode)
    n = len(axis)
    if not axis[n - 1] > x:
        raw = cells[n - 1]
    else:
        i = n - 1
        while True:
            if i == 0:
                frac = Fraction(0)
                break
            i -= 1
            if not axis[i] > x:
                frac = rnd(rnd(x - axis[i], mode) / rnd(axis[i + 1] - axis[i], mode), mode)
                break
        raw = cells[i] if frac == 0 else mac(frac, rnd(cells[i + 1] - cells[i], mode), cells[i])
    return raw if tc == 0 else mac(scale, raw, bias)


def sec_rounding(rom, sites):
    say('\n==== N. the FPU rounding mode: what "bit-exact" above does and does not mean ====')
    # --- every instruction that loads FPSCR from a register
    code = SWEEP['code0']                                 # method 1's code map (over-inclusive: see below)
    ref = pool_words(rom, code)                           # words a PC-relative load in that code reads
    lds = [pc for pc in range(SWEEP_LO, SWEEP_HI, 2) if (u16(rom, pc) & 0xF0FF) == 0x406A]
    in_code = [pc for pc in lds if pc in code and pc not in ref]
    stray = [pc for pc in lds if pc not in in_code]
    say(f'   words 0x4n6A (lds Rn,fpscr) in 0x000400..0x0BFFFF: {len(lds)}; instructions: '
        + ', '.join(f'0x{pc:06X}' for pc in in_code))
    for pc in stray:
        say(f'      not an instruction: 0x{pc:06X} is half of the long 0x{u32(rom, pc & ~3):08X} at 0x{pc & ~3:06X}'
            + ('  (a literal-pool long that code loads)' if pc in ref else
               '  (not reached by the sweep; not referenced as a pool long)'))
    pops = sorted(pc for pc in code if (u16(rom, pc) & 0xF0FF) == 0x4066 and pc not in ref)
    pushes = sorted(pc for pc in code if (u16(rom, pc) & 0xF0FF) == 0x4062 and pc not in ref)
    say(f'   lds.l @Rn+,fpscr in code: {", ".join("0x%06X" % a for a in pops)}   sts.l fpscr,@-Rn in code: '
        f'{", ".join("0x%06X" % a for a in pushes)}')
    v1 = _lit(rom, u16(rom, 0x00FA42), 0x00FA42)
    v2 = _lit(rom, u16(rom, 0x05873C), 0x05873C)
    record('FPSCR is loaded from a register at exactly two places: 00FA42 D2A1 / 00FA44 426A with 0x00040001 '
           '(RM field, bits 1..0, = 01) and 05873C D21E / 05873E 426A with 0; bits 11..7 are zero in both',
           in_code == [0x00FA44, 0x05873E]
           and words_are(rom, [(0x00FA42, 0xD2A1), (0x00FA44, 0x426A), (0x05873C, 0xD21E), (0x05873E, 0x426A)])
           and v1 == 0x00040001 and v2 == 0 and not (v1 | v2) & 0xF80,
           f'{len(stray)} look-alike words are data: {sum(1 for pc in stray if pc in ref)} are halves of literal-pool '
           f'longs that code loads, {sum(1 for pc in stray if pc not in ref)} sit where the sweep finds no code')
    quoted('N_fpscr_lookalikes', len(stray))
    quoted('N_fpscr_pops', len(pops))
    quoted('N_fpscr_pushes', len(pushes))

    # --- the ROM's own FPU self-test: which rounding mode produces the constants it compares against?
    x = frac_of(u32(rom, 0x0587E0))
    c2x, cmac, cdiv = u32(rom, 0x0587E4), u32(rom, 0x0587E8), u32(rom, 0x0587EC)
    say(f'   self-test constants: 0x0587E0 = 0x{u32(rom, 0x0587E0):08X} (x)   0x0587E4 = 0x{c2x:08X}   0x0587E8 = 0x{cmac:08X}'
        f'   0x0587EC = 0x{cdiv:08X}')
    res = {}
    for mode in ('rz', 'rn'):
        two = to_bits(x + x, mode)                                   # 0586A2 fadd fr3,fr4
        mac_f = to_bits(x * frac_of(c2x) + 1, mode)                  # 0586B8 fmac fr0,fr6,fr2 : x * 2x + 1.0
        mac_s = to_bits(rnd(x * frac_of(c2x), mode) + 1, mode)
        mul = to_bits(frac_of(two) * x, mode)                        # 0586C6 fmul fr3,fr4 : 2x * x
        sub = to_bits(frac_of(cmac) - 1, mode)                       # 0586C8 fsub fr1,fr5 : expected - 1.0
        div = to_bits(frac_of(mul) / x, mode)                        # 0586D2 fdiv fr3,fr4
        res[mode] = (two == c2x, mac_f == cmac, mac_s == cmac, mul == sub, div == cdiv)
        say(f'   {"round toward zero" if mode == "rz" else "round to nearest "}: fadd 0x{two:08X}  fmac 0x{mac_f:08X} (fused) '
            f'0x{mac_s:08X} (product rounded first)  fmul 0x{mul:08X} vs 0x{sub:08X}  fdiv 0x{div:08X}')
    record('the ROM FPU self-test (0586A2..0586DA) expects ROUND-TOWARD-ZERO results: exact arithmetic truncated gives '
           '0x43A45708 / equal / 0x41CCCCCA at its fmac, fmul and fdiv checks; rounded to nearest gives none of the three',
           res['rz'] == (True, True, True, True, True) and res['rn'] == (True, False, False, False, False)
           and words_are(rom, [(0x0586A2, 0xF430), (0x0586B8, 0xF26E), (0x0586BE, 0xF524), (0x0586C6, 0xF432),
                               (0x0586C8, 0xF511), (0x0586CA, 0xF544), (0x0586D2, 0xF433), (0x0586D8, 0xF544)]),
           'the fmac check passes fused or not, so it does not say which the chip does')
    # --- what sh2e_emu does with the same code
    emu = E.Emu(rom)
    fails = []
    for start, fail_at, ok_at in ((0x058696, 0x0586AE, 0x0586B0), (0x0586B0, 0x0586C4, 0x0586C6),
                                  (0x0586C6, 0x0586D0, 0x0586D2), (0x0586D2, 0x0586DE, 0x0586E0)):
        st = emu.call(start, stop_at={fail_at, ok_at})
        if st == fail_at:
            fails.append(fail_at)
    say('   sh2e_emu run over 058696..0586E0 reaches the failure load (mov.l 0xAAAAAAAA,r14) at: '
        + (', '.join(f'0x{a:06X}' for a in fails) or 'none'))
    record('sh2e_emu passes all four self-test checks: it truncates, as the chip does (corrections item 106; before '
           'that it rounded to nearest and failed at 0586C4, 0586D0, 0586DE)', not fails,
           'fails at ' + ', '.join(f'0x{a:06X}' for a in fails) if fails else 'passes all four')

    # --- what the alternatives would change: round to nearest (the emulator before item 106) and an unfused fmac.
    #     The chip's mode is ('rz', fused); the other two keys are what this section measures against it.
    emu = E.Emu(rom)
    alts = (('rn', True), ('rz', False))
    diff = {k: 0 for k in alts}
    model_bad = npts = 0
    examples = []
    for entry, tc, mask in ((0x0BE874, 0x04, 0xFF), (0x0BE8AC, 0x08, 0xFFFF)):
        for rec in [r for r in records_of(sites, entry) if plausible_rec(rom, r, False)]:
            cnt = u16(rom, rec)
            ab = [u32(rom, u32(rom, rec + 4) + 4 * i) for i in range(cnt)]
            axis = [frac_of(b) for b in ab]
            cells = [Fraction(c) for c in cells_at(rom, u32(rom, rec + 8), cnt, tc)]
            if not all(axis[i] < axis[i + 1] for i in range(cnt - 1)):
                continue
            a0, a1 = E.b2f(ab[0]), E.b2f(ab[-1])
            for j in range(201):
                xf = f32(a0 + (a1 - a0) * j / 200)
                emu.call(entry, regs={4: rec}, fregs={4: xf})
                xq = frac_of(bits(xf))
                npts += 1
                model_bad += emu.R[0] != int(exact_1d(axis, cells, xq, 'rz', True)) & mask
                for key in alts:
                    v = int(exact_1d(axis, cells, xq, key[0], key[1])) & mask
                    if v != emu.R[0]:
                        diff[key] += 1
                        if key == ('rn', True) and len(examples) < 4:
                            examples.append(f'0x{rec:06X} x={xf!r}: truncating (chip, sh2e_emu) {emu.R[0]}, '
                                            f'round-to-nearest {v}')
    say(f'   0BE874 / 0BE8AC, 201 evenly spaced inputs across each axis, {npts} points:')
    say(f'      r0 from exact arithmetic TRUNCATED, fmac fused (the chip) != sh2e_emu at {model_bad} points')
    say(f'      r0 rounded to NEAREST instead (the emulator before item 106) differs at {diff[("rn", True)]} points; '
        f'truncated with the product rounded before the add differs at {diff[("rz", False)]}')
    for e in examples:
        say('         ' + e)
    quoted('N_int_points', npts)
    quoted('N_int_rn_differ', diff[('rn', True)])
    quoted('N_int_rz_split_differ', diff[('rz', False)])
    record('the exact truncating model (fused fmac) reproduces sh2e_emu on the integer-result wrappers at every point, '
           'and round-to-nearest returns a different COUNT at a few inputs',
           model_bad == 0 and diff[('rn', True)] > 0,
           f'{npts} points; round-to-nearest changes r0 at {diff[("rn", True)]}, an unfused fmac at {diff[("rz", False)]}')
    # the two inputs the reviewer quoted
    ex = []
    for rec, entry, tc, mask, xf in ((0x0AB2A4, 0x0BE874, 0x04, 0xFF, -14.0), (0x0AC450, 0x0BE874, 0x04, 0xFF, 3700.0)):
        cnt = u16(rom, rec)
        axis = [frac_of(u32(rom, u32(rom, rec + 4) + 4 * i)) for i in range(cnt)]
        cells = [Fraction(c) for c in cells_at(rom, u32(rom, rec + 8), cnt, tc)]
        emu.call(entry, regs={4: rec}, fregs={4: xf})
        xq = frac_of(bits(xf))
        ex.append((rec, xf, emu.R[0], int(exact_1d(axis, cells, xq, 'rz', True)) & mask,
                   int(exact_1d(axis, cells, xq, 'rz', False)) & mask, int(exact_1d(axis, cells, xq, 'rn', True)) & mask))
        say(f'      record 0x{rec:06X} x = {xf}: sh2e_emu {ex[-1][2]}, truncating {ex[-1][3]} (fused) / {ex[-1][4]} '
            f'(split), round-to-nearest {ex[-1][5]}')
    record('the two inputs quoted in review: record 0x0AB2A4 at -14.0 gives 121 and record 0x0AC450 at 3700.0 gives 29 '
           '(emulator == truncating, fused or not); round to nearest gives one count less at both (120, 28)',
           [e[2:] for e in ex] == [(121, 121, 121, 120), (29, 29, 29, 28)],
           ', '.join(f'{e[2]} vs {e[5]}' for e in ex))
    # float results of 0x0BE830: last-bit differences
    recs = [r for r in records_of(sites, 0x0BE830) if plausible_rec(rom, r, False) and rom[r + 2] in FMT]
    nf = dn = dzs = mb = 0
    for rec in recs[::4]:                                            # every fourth record keeps this under 10 s
        cnt, tc = u16(rom, rec), rom[rec + 2]
        ab = [u32(rom, u32(rom, rec + 4) + 4 * i) for i in range(cnt)]
        axis = [frac_of(b) for b in ab]
        if not all(axis[i] < axis[i + 1] for i in range(cnt - 1)):
            continue
        fmt, wdt = FMT[tc]
        dp = u32(rom, rec + 8)
        cells = ([frac_of(u32(rom, dp + 4 * i)) for i in range(cnt)] if tc == 0 else
                 [Fraction(struct.unpack_from(fmt, rom, dp + i * wdt)[0]) for i in range(cnt)])
        scale, bias = frac_of(u32(rom, rec + 12)), frac_of(u32(rom, rec + 16))
        for xf in sample_points([E.b2f(b) for b in ab]):
            emu.call(0x0BE830, regs={4: rec}, fregs={4: xf})
            got = emu.FR[0]
            xq = frac_of(bits(xf))
            nf += 1
            mb += (to_bits(exact_1d(axis, cells, xq, 'rz', True, tc, scale, bias), 'rz') ^ got) & 0x7FFFFFFF != 0
            dn += (to_bits(exact_1d(axis, cells, xq, 'rn', True, tc, scale, bias), 'rn') ^ got) & 0x7FFFFFFF != 0
            dzs += (to_bits(exact_1d(axis, cells, xq, 'rz', False, tc, scale, bias), 'rz') ^ got) & 0x7FFFFFFF != 0
    say(f'   0BE830, every fourth record, {nf} points: exact TRUNCATED, fmac fused != sh2e_emu at {mb}; round-to-nearest '
        f'differs at {dn}, truncated with the product rounded first at {dzs} -- last-bit differences in fr0')
    quoted('N_f_points', nf)
    quoted('N_f_rn_differ', dn)
    quoted('N_f_rz_split_differ', dzs)
    record('0BE830: the exact truncating model (fused fmac) reproduces sh2e_emu at every point; round-to-nearest changes '
           'the last bit of fr0 at a sizeable share of inputs, an unfused fmac at fewer',
           mb == 0 and dn > 0 and 0 < dzs < dn, f'{nf} points; round-to-nearest differs at {dn}, unfused fmac at {dzs}')


# ============================================================================
def sec_joins(rom, sites):
    say('\n==== O. scans and joins the analysis file quotes ====')
    # --- 0x0BEA3C
    longs = [a for a in range(0, len(rom) - 3, 2) if u32(rom, a) == 0x000BEA3C]
    br = []
    for pc in range(0, SWEEP_HI, 2):
        w = u16(rom, pc)
        if (w >> 12) in (0xA, 0xB) and _t12(w, pc) == 0x0BEA3C:
            br.append(pc)
        elif _is_cond(w) and _t8(w, pc) == 0x0BEA3C:
            br.append(pc)
    record('0x0BEA3C (000B 0009 = rts ; nop) is named by no long at any even offset of the image and by no '
           'bra / bsr / bt / bf', words_are(rom, [(0x0BEA3C, 0x000B), (0x0BEA3E, 0x0009)]) and not longs and not br,
           f'{len(longs)} longs, {len(br)} branches')
    # --- the words in the assigned range that are not instructions of any function
    filler = [(0x0BE85E, 0x0009), (0x0BE8AA, 0x0000), (0x0BE8E2, 0x0000), (0x0BE98E, 0x0000), (0x0BE99E, 0x0000),
              (0x0BEA32, 0x0009), (0x0BEA3C, 0x000B), (0x0BEA3E, 0x0009), (0x0BEA92, 0x0000), (0x0BEAAA, 0x0009)]
    pool = [(0x0BE860, 0x000BEACC), (0x0BE864, 0x000BEB20), (0x0BE868, 0x000BEB6C), (0x0BE86C, 0x000BEAE4),
            (0x0BE870, 0x000BEB00), (0x0BE914, 0x000BEBC0), (0x0BE918, 0x000BEC4C), (0x0BE91C, 0x000BEC78),
            (0x0BE920, 0x000BEBF0), (0x0BE924, 0x000BEC1C), (0x0BEA34, 0x7FFFFFFF), (0x0BEA38, 0x80000000),
            (0x0BEA68, 0x7F800000), (0x0BEA94, 0x3B800000), (0x0BEAAC, 0x7FFFFFFF)]
    record('non-instruction words in 0x0BE81C..0x0BEACB: 10 filler words and 15 table / pool longs, as listed in the '
           'analysis file', words_are(rom, filler) and all(u32(rom, a) == v for a, v in pool))
    record('caller 0x006628: 0066E6 000B rts ; 0066E8 6EF6 mov.l @r15+,r14 is its delay slot ; the 16-bit pool word '
           '00E0 that 00662C 955D loads is at 0x0066EA',
           words_are(rom, [(0x00662C, 0x955D), (0x0066E6, 0x000B), (0x0066E8, 0x6EF6), (0x0066EA, 0x00E0)])
           and 0x00662C + 4 + 0x5D * 2 == 0x0066EA)

    # --- byte +3 as a 1-D / 2-D discriminator (a statement about the DATA: no wrapper tests it)
    one = {r for t in (0x0BE830, 0x0BE874, 0x0BE88C, 0x0BE8AC, 0x0BE8C4) for r in records_of(sites, t)
           if plausible_rec(rom, r, False)}
    two = {r for t in (0x0BE8E4, 0x0BE928, 0x0BE944) for r in records_of(sites, t) if plausible_rec(rom, r, True)}
    z1 = sum(1 for r in one if rom[r + 3] == 0)
    z2 = sum(1 for r in two if rom[r + 3] != 0)
    say(f'   records passed to a 1-D wrapper: {len(one)}, byte +3 == 0 on {z1};  to a 2-D wrapper: {len(two)}, '
        f'byte +3 != 0 on {z2};  in both sets: {len(one & two)}')
    quoted('O_1d_records', len(one))
    quoted('O_2d_records', len(two))
    record('byte +3 is 0 on every record passed to a 1-D wrapper and non-zero on every record passed to a 2-D wrapper '
           '(for 2-D it is the low byte of the count word at +2 that 0BEDA6 8541 reads)',
           z1 == len(one) and z2 == len(two) and not (one & two) and u16(rom, 0x0BEDA6) == 0x8541)

    # --- definitions: which record pointer is the definition's X axis and which its Y axis
    try:
        import defs
        d = defs.load()
    except Exception as e:                                           # noqa: BLE001
        d = None
        say(f'   definitions not loaded ({type(e).__name__}: {e}); the X/Y join is skipped')
    if d is not None:
        n_def = n_xy = n_yx = 0
        ex = ''
        for r in sorted(two):
            for t in d.at(u32(rom, r + 12)):
                xa, ya = t.x_axis, t.y_axis
                if xa is None or ya is None or xa.address is None or ya.address is None:
                    continue
                n_def += 1
                if xa.address == u32(rom, r + 4) and ya.address == u32(rom, r + 8):
                    n_xy += 1
                    if r == 0x0AA9B8:
                        ex = (f'0x{r:06X} "{t.name}": X = {xa.name} at 0x{xa.address:06X} ({xa.elements}) = record+4, '
                              f'Y = {ya.name} at 0x{ya.address:06X} ({ya.elements}) = record+8')
                elif xa.address == u32(rom, r + 8) and ya.address == u32(rom, r + 4):
                    n_yx += 1
        say(f'   2-D records whose cell pointer has a definition with two addressed axes: {n_def}; definition X axis = '
            f'record+4 and Y axis = record+8 on {n_xy}; the other way round on {n_yx}')
        if ex:
            say('      ' + ex)
        quoted('O_xy_defs', n_def)
        record('definition X axis = the pointer at record+4 (searched with fr4, contiguous); definition Y axis = the '
               'pointer at record+8 (fr5, stride) -- on every 2-D record that has a definition',
               n_def > 20 and n_xy == n_def and n_yx == 0, f'{n_xy} of {n_def}')
        # storagetype of the definitions that sit on integer-wrapper records whose byte says float32
        say('   definitions at the cell pointer of integer-wrapper records whose typecode-position byte is 0x00:')
        okst = True
        nst = 0
        for entry, width in ((0x0BE874, 'uint8'), (0x0BE88C, 'uint8'), (0x0BE8AC, 'uint16'), (0x0BE8C4, 'uint16'),
                             (0x0BE928, 'uint8'), (0x0BE944, 'uint16')):
            twod = entry in (0x0BE928, 0x0BE944)
            for r in records_of(sites, entry):
                if not plausible_rec(rom, r, twod) or (rom[r + 16] if twod else rom[r + 2]):
                    continue
                for t in d.at(u32(rom, r + 12 if twod else r + 8)):
                    st = t.scaling.storagetype if t.scaling else None
                    nst += 1
                    okst &= st == width
                    say(f'      0x{u32(rom, r + 12 if twod else r + 8):06X} {st}  (record 0x{r:06X}, via 0x{entry:06X})  "{t.name}"')
        quoted('O_storagetype_defs', nst)
        record('where such a record has a definition, the definition storagetype is the WRAPPER\'s cell type, not float32',
               okst and nst > 0, f'{nst} definitions')

    # --- disassembly/maps/descriptor_map.txt (a derived file: compared, never trusted)
    path = os.path.join(REPO, 'disassembly', 'maps', 'descriptor_map.txt')
    if not os.path.exists(path):
        say('   descriptor_map.txt not present; its joins are skipped')
        return
    rows = {}
    with open(path) as fh:
        for ln, line in enumerate(fh, 1):
            f = line.split()
            if len(f) >= 7 and f[0].isdigit() and f[1].startswith('0x') and f[2] in ('1D', '2D'):
                rows[int(f[1], 16)] = (ln, f[2], f[4], f[5])              # line, dim, type, scale
    passed = {}                                                           # record -> wrapper
    for t in WRAPPERS:
        for r in records_of(sites, t):
            if plausible_rec(rom, r, t in (0x0BE8E4, 0x0BE928, 0x0BE944)):
                passed.setdefault(r, t)
    intw = (0x0BE874, 0x0BE88C, 0x0BE8AC, 0x0BE8C4, 0x0BE928, 0x0BE944)
    a1 = sorted(rows[r][0] for r, t in passed.items() if t in intw and r in rows and rows[r][2] == 'float32')
    a2 = sorted(rows[r][0] for r, t in passed.items() if t in (0x0BE874, 0x0BE8AC) and r in rows and rows[r][3] != '--')
    f32rows = [r for r, v in rows.items() if v[2] == 'float32']
    f_dispatch = sum(1 for r in f32rows if passed.get(r) in (0x0BE830, 0x0BE8E4))
    f_int = sum(1 for r in f32rows if passed.get(r) in intw)
    f_none = sum(1 for r in f32rows if r not in passed)
    norow = sorted(r for r in passed if r not in rows)
    say(f'   descriptor_map.txt: {len(rows)} rows.  Rows the sweep finds passed to a wrapper: {sum(1 for r in rows if r in passed)}; '
        f'rows with no literal call site: {sum(1 for r in rows if r not in passed)}')
    say(f'   rows typed float32: {len(f32rows)} = {f_dispatch} passed to 0BE830/0BE8E4 + {f_int} passed to an integer-cell '
        f'wrapper + {f_none} with no literal call site')
    say(f'   A1 lines (typed float32, consumed as uint8/uint16), {len(a1)}: ' + ' '.join(map(str, a1)))
    say(f'   A2 lines (scale printed for a record of 0BE874/0BE8AC), {len(a2)}: ' + ' '.join(map(str, a2)))
    say(f'   records passed to a wrapper that have no row: ' + ', '.join(f'0x{r:06X}' for r in norow))
    quoted('O_map_rows', len(rows))
    quoted('O_map_rows_no_site', sum(1 for r in rows if r not in passed))
    quoted('O_map_f32_rows', len(f32rows))
    quoted('O_map_f32_dispatch', f_dispatch)
    quoted('O_map_f32_int', f_int)
    quoted('O_map_f32_none', f_none)
    quoted('O_map_a1', len(a1))
    quoted('O_map_a2', len(a2))
    record('descriptor_map.txt types as float32 records whose consuming wrapper reads uint8 / uint16 cells, and prints '
           'a scale for records of 0BE874 / 0BE8AC, which read none', len(a1) > 30 and len(a2) > 20,
           f'{len(a1)} + {len(a2)} rows')
    record('record 0x0ABF70 (11 x 1, typecode 0x08, passed to 0BE8E4 at 0x02B998) has no row in descriptor_map.txt; its '
           'neighbours 0x0ABF54 and 0x0ABF8C do',
           0x0ABF70 in norow and 0x0ABF54 in rows and 0x0ABF8C in rows and u16(rom, 0x0ABF70) == 11
           and u16(rom, 0x0ABF72) == 1 and rom[0x0ABF70 + 16] == 0x08)


# ============================================================================
def main():
    rom = open(ROM_PATH, 'rb').read()
    md5 = hashlib.md5(rom).hexdigest()
    print(f'ROM {os.path.basename(ROM_PATH)}  md5 {md5}')
    if md5 != ROM_MD5:
        print('FAIL  wrong reference bin')
        return 1
    sites = sweep(rom)
    sec_sweep(rom, sites)
    sec_critical(rom)
    sec_search(rom)
    sec_1d_float(rom, sites)
    sec_1d_int(rom, sites)
    sec_1d_intaxis(rom, sites)
    sec_2d(rom, sites)
    sec_record_layout(rom, sites)
    sec_minmax(rom)
    sec_complement(rom)
    sec_fixed(rom)
    sec_lag(rom)
    sec_misc(rom)
    sec_rounding(rom, sites)
    sec_joins(rom, sites)
    if '--numbers' in sys.argv:                           # print the table to paste into QUOTED
        print('QUOTED = {')
        for name, value in QUOTE_LOG:
            print(f'    {name!r}: {value!r},')
        print('}')
    wrong = [(n, v, QUOTED.get(n)) for n, v in QUOTE_LOG if QUOTED.get(n) != v]
    stale = sorted(set(QUOTED) - {n for n, _ in QUOTE_LOG})
    record('every number helpers_wrap_trace.txt quotes from this script is the number the script computes',
           not wrong and not stale, f'{len(QUOTE_LOG)} numbers'
           + (''.join(f'; {n}: computed {v}, quoted {q}' for n, v, q in wrong[:8]))
           + (f'; quoted but not computed: {stale[:6]}' if stale else ''))
    fails = [r for r in RESULTS if not r[1]]
    print(f'\n{len(RESULTS) - len(fails)} of {len(RESULTS)} contract checks passed')
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
