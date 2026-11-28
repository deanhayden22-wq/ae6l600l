#!/usr/bin/env python3
"""Mechanical classification + emulation of the two diagnostic stub tables.

    python3 scripts/trace/emu_stub_tables.py            # everything, asserts, exit 0
    python3 scripts/trace/emu_stub_tables.py --csv      # only the ';'-prefixed index map
    python3 scripts/trace/emu_stub_tables.py --classes  # only the pattern-class table

Companion to disassembly/analysis/stub_tables_trace.txt (2026-11-27; repaired the same day
after an adversarial review -- every review item is marked "review" below).

WHAT IT PROVES (each is an assert; the script exits 0 only if all hold)
  A. TABLE GEOMETRY   0x06423C holds 848 code pointers ("getters"), 0x064F7C the next
     848 ("setters").  They are adjacent, which is why a pointer-run scanner reports
     one run of 1696 at 0x06423C.  Every index check in the callers is `< 848`.
  B. CLASSES          every distinct target is decoded to its end, a signature is built
     with literals / immediates / displacements masked, and targets are grouped.
     review: extent() no longer stops at an address it first saw as a delay slot.
  C. GETTERS          a small symbolic evaluator turns each straight-line getter into a
     formula over RAM/ROM; the formula is then checked against scripts/sh2e_emu.py on
     seeded-random RAM.  Branching getters are probed with the emulator instead: every
     input byte is swept over 0..255 and the composed bit model is checked on random
     mixes.  Two getters (0x05DEF8, 0x05DA88) have hand-read models (SPECIAL).
     No getter writes RAM.  288 indices read RAM, 560 return a constant.
     review: r4 -- all 848 indices x 7 values with every other register scrambled, plus a
     static pass over every path with callees inlined: only 0x05DCAE / 0x05DCCE read it.
     review: index 0x009 is sat8(((x - 1) + 1) / 0.0078125); that is NOT always
     sat8(x / 0.0078125) (x - 1 is truncated toward zero onto a 2^-24 grid).  Settle pass:
     every float32 within 2^-24 of the 256 rounding boundaries is run -- exactly 576 inputs
     differ, all with 0 < x < 0.5, less than 2^-24 below a boundary, ROM one count higher.
     (The first version said 319 / "at most 2^-25": it modelled round-to-nearest, which is
     not what the FPU does -- see ARITHMETIC below and corrections item 106.)
     review: NaN / +-Inf / beyond-int32 inputs are run too, under the EMULATOR's ftrc rule.
  D. SETTERS          emulated for v = 0..255; the RAM writes must equal the stated effect.
  E. HELPERS          0x0BE5A8 / 0x0BE5D8 / 0x0BE598 / 0x0BE588 / 0x0BE9A0 / 0x05850E /
     0x058518 / 0x02E7D8 / 0x02E7E2 / 0x05F2FC (and, under SPECIAL, 0x0BE980 / 0x0BE608)
     against Python models.
  F. DISPATCH SITES   0x05F718, 0x05F758, 0x05F316 (two paths), 0x05F08C (0xA8 / 0xB8
     branches, and 0x05F08C + 0x05F316 end to end), 0x09CAEA (incl. the mode byte swept
     over 0..255 through the real 0x003BF4), 0x09A710, 0x09A628, 0x09A3AC; getter/setter
     pairing.  The handlers are run twice: with their I/O helpers stubbed, and
     review: with the transport helpers RUN FOR REAL (0x09D052 -> 0x09CD50, 0x09CFEE ->
     0x09CCF8, 0x09D084 -> 0x09CC44, 0x098686, 0x09CABE; only 0x00DCE4 is stubbed).  The
     three ring routines are also checked directly against Python models.
     review: the FF / F2 / F4 path of 0x09A3AC reads any address 0xFFFF0000..0xFFFFFFFF
     (0xFFFFEC0A is read; an F4 at 0xFFFFFFFE wraps into ROM 0) and stores up to 336 reply
     bytes from 0xFFFFB3F4 with no bound (23 x F4 reach u16[0xFFFFB44C], 24 reach
     u8[0xFFFFB450], 25 reach the ring header at 0xFFFFB454).
  G. CROSS-CHECKS     the definition XML's <ecuid> equals the bytes indices 1..5 return
     (asserted when the XML is present); logs/logcfg.txt parameters are listed next to
     their getter formulas and as "logged = slope * RAM input + intercept".  review: there
     are 20 of them, not 19, and Throttle (id 0x015) is NOT inverted by its rpn (slope
     1.25).  Asserted only for the logcfg.txt with the sha256 below -- the file is user-edited.

ARITHMETIC (re-done 2026-11-27, corrections item 106)
  Every Python model of an FPU step (f_add / f_sub / f_mul / f_div / f_mac / f_float) is the
  chip's: computed exactly and truncated TOWARD ZERO to float32 (FPSCR = 0x00040001, RM = 01,
  DN = 1; the ROM's own FPU self-test at 0x058696 demands truncated results).  fmac is FUSED
  (one truncation), as scripts/sh2e_emu.py implements it; the self-test does not settle fused
  vs unfused, and 7 of the 80 0x0BE588 / 0x0BE598 cases in E depend on it (none of the getters
  do: every stub that calls those helpers passes c = 0).  Test inputs written as Python floats
  are converted to the NEAREST float32 (r32 / f2b) -- a choice of input, not arithmetic.  The
  script was first written against an emulator that rounded to nearest; the only results that
  moved are the index 0x009 counts in C (rounding_edges) -- every formula, constant, index-map
  row and dispatch result is unchanged.

WHAT THE EMULATOR CANNOT RUN HERE
  * 0x0BE81C / 0x0BE82C (`ldc ..,sr`) are stubbed in every run; their contract is read
    from bytes only.
  * 0x00DCE4 (reached by `jmp` from 0x09CABE) is stubbed: it indexes an OS-level table and
    makes an unresolved indirect call.  Its arguments are captured, nothing more.
  * peripheral reads return 0 (or a value planted by the test) and are logged; peripheral
    writes are logged.  0xFFFFC000..0xFFFFDFFF is unmapped in the emulator: a read there
    raises, which is how the FF C0 00 case is shown to ADDRESS it, not what it returns.
  * ftrc of NaN / infinity / a value outside int32 follows scripts/sh2e_emu.py (NaN and
    negative overflow -> 0x80000000, positive overflow -> 0x7FFFFFFF).  Not checked
    against silicon; every statement that depends on it says so.
"""
import collections
import hashlib
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
import sh2e_emu as E                      # noqa: E402
from sh2e_disasm import decode            # noqa: E402

ROM_PATH = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
ROM_MD5 = '92cae8275cd4f9b473a3a9e36efe6449'
GET, SET, N = 0x06423C, 0x064F7C, 848
M32 = 0xFFFFFFFF
RAM_LO, RAM_HI = 0xFFFF0000, 0xFFFFBFFF
STACK_LO = 0xFFFFBD00                     # emulator stack lives just under 0xFFFFBF00

rom = open(ROM_PATH, 'rb').read()
assert hashlib.md5(rom).hexdigest() == ROM_MD5, 'wrong reference bin'


def W(a): return struct.unpack('>H', rom[a:a + 2])[0]
def L(a): return struct.unpack('>I', rom[a:a + 4])[0]


def sext(v, bits):
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


CHECKS = []


def check(cond, what):
    CHECKS.append(what)
    if not cond:
        raise AssertionError(what)


# =====================================================================================
# A. table geometry
# =====================================================================================
A = [L(GET + 4 * i) for i in range(N)]
B = [L(SET + 4 * i) for i in range(N)]


def is_code_ptr(v):
    return 0x05D000 <= v < 0x05EA00 and v % 2 == 0


def geometry():
    check(GET + 4 * N == SET, 'getter table ends exactly where the setter table starts')
    check(all(is_code_ptr(v) for v in A), 'all 848 getter entries point into 0x05D000..0x05EA00')
    check(all(is_code_ptr(v) for v in B), 'all 848 setter entries point into 0x05D000..0x05EA00')
    check(not is_code_ptr(L(GET - 4)), 'long before 0x06423C is not a stub pointer')
    check(not is_code_ptr(L(SET + 4 * N)), 'long after the setter table (0x065CBC) is not a stub pointer')
    refs = {t: [o for o in range(0, len(rom) - 3, 2) if rom[o:o + 4] == struct.pack('>I', t)]
            for t in (GET, SET)}
    check(refs[GET] == [0x05F7EC, 0x09A4E4, 0x09A744], 'ROM words equal to 0x06423C: 3 pool slots')
    check(refs[SET] == [0x05F800, 0x09A73C], 'ROM words equal to 0x064F7C: 2 pool slots')
    check(not (set(A) & set(B)), 'no stub is used both as getter and as setter')
    return refs


# =====================================================================================
# B. extents, signatures, classes
# =====================================================================================
def extent(entry):
    """Every instruction address reachable from entry without leaving through rts/jmp.

    `seen` is the result (instructions, delay slots included); `walked` is the set of
    addresses linear decoding has STARTED from.  They must be separate: an address
    first recorded as a delay slot can later be a branch target (0x09A45A is the delay
    slot of `bra` at 0x09A458 AND the target of `bf` at 0x09A442), and a walker that
    tests `pc not in seen` never decodes on from it.  The first version of this script
    did exactly that and returned 140 instead of 151 instructions for 0x09A3AC -- the
    same blind spot function_census.json had there (review 2026-11-27; fn_dump and the
    census regenerated later that day now give 151 too)."""
    seen, walked, work = set(), set(), [entry]
    while work:
        pc = work.pop()
        while pc not in walked:
            txt, _ = decode(W(pc), pc)
            mn = txt.split()[0]
            if 'INVALID' in txt or mn == '.word':
                raise RuntimeError(f'data decoded as code at {pc:06X}: {txt}')
            walked.add(pc)
            seen.add(pc)
            if mn in ('bt', 'bf', 'bt/s', 'bf/s'):
                work.append(int(txt.split()[1], 16))
                if mn.endswith('/s'):
                    seen.add(pc + 2)
                    pc += 4
                else:
                    pc += 2
                continue
            if mn == 'bra':
                seen.add(pc + 2)
                work.append(int(txt.split()[1], 16))
                break
            if mn in ('rts', 'jmp', 'rte', 'braf'):
                seen.add(pc + 2)
                break
            if mn in ('jsr', 'bsr', 'bsrf'):
                seen.add(pc + 2)
                pc += 4
                continue
            pc += 2
    return sorted(seen)


def lit_class(v):
    if RAM_LO <= v <= RAM_HI:
        return 'RAM'
    if v >= 0xFFFFE000:
        return 'PERIPH'
    if v < 0x100000:
        return 'ROM'
    return 'CONST'


def signature(entry, ext):
    """Instruction pattern with pool literals, immediates, displacements masked.
    A jsr/jmp keeps its RESOLVED target: which helper is called is part of the pattern."""
    sig, regs = [], {}
    for pc in ext:
        txt, _ = decode(W(pc), pc)
        mn = txt.split()[0]
        m = re.match(r'mov\.l @\((0x[0-9A-F]+)\),(r\d+)', txt)
        if m:
            v = L(int(m.group(1), 16))
            regs[m.group(2)] = v
            sig.append(f'mov.l @(POOL:{lit_class(v)}),{m.group(2)}')
            continue
        m = re.match(r'mov\.w @\((0x[0-9A-F]+)\),(r\d+)', txt)
        if m:
            regs.pop(m.group(2), None)
            sig.append(f'mov.w @(POOL),{m.group(2)}')
            continue
        if mn == 'mova':
            sig.append('mova @(POOL),r0')
            continue
        m = re.match(r'(jsr|jmp) @(r\d+)', txt)
        if m:
            v = regs.get(m.group(2))
            sig.append(f'{m.group(1)} ' + (f'0x{v:06X}' if v is not None else '?'))
            continue
        if mn in ('bt', 'bf', 'bt/s', 'bf/s', 'bra', 'bsr'):
            sig.append(f'{mn} {int(txt.split()[1], 16) - pc:+d}')
            continue
        t = re.sub(r'#-?\d+', '#IMM', txt)
        t = re.sub(r'@\(\d+,(r\d+|gbr)\)', r'@(DISP,\1)', t)
        sig.append(t)
    return tuple(sig)


TARGETS = sorted(set(A) | set(B))
EXT = {t: extent(t) for t in TARGETS}
SIG = {t: signature(t, EXT[t]) for t in TARGETS}
_groups = collections.defaultdict(list)
for _t in TARGETS:
    _groups[SIG[_t]].append(_t)
IDX_A, IDX_B = collections.defaultdict(list), collections.defaultdict(list)
for _i, _t in enumerate(A):
    IDX_A[_t].append(_i)
for _i, _t in enumerate(B):
    IDX_B[_t].append(_i)
# class id: getters first, then setters, each by first member address -> stable ids
CLASSES = sorted(_groups.items(), key=lambda kv: (kv[1][0] in IDX_B, kv[1][0]))
CLS_OF = {}
for _n, (_s, _mem) in enumerate(CLASSES):
    for _t in _mem:
        CLS_OF[_t] = _n


GSET = set(A)


def cname(t):
    return ("G" if t in GSET else "S") + f"{CLS_OF[t]:02d}"


def call_targets(entry):
    """Resolved jsr / jmp / bsr targets of the function at entry (literal-loaded registers only)."""
    out, regs = set(), {}
    for pc in extent(entry):
        txt, _ = decode(W(pc), pc)
        m = re.match(r'mov\.l @\((0x[0-9A-F]+)\),(r\d+)', txt)
        if m:
            regs[m.group(2)] = L(int(m.group(1), 16))
            continue
        m = re.match(r'(jsr|jmp) @(r\d+)', txt)
        if m:
            if m.group(2) not in regs:
                raise RuntimeError(f'unresolved {txt} at {pc:06X}')
            out.add(regs[m.group(2)])
        elif txt.split()[0] == 'bsr':
            out.add(int(txt.split()[1], 16))
    return out


def callee_sweep(check_file=True):
    """Every function any of the 224 stubs can reach by a call, transitively.  The analysis file must
    carry a listed section for each one (the first version missed 0x02E7D8 and 0x02E7E2).  The file
    is only consulted in the full run, so --csv can regenerate the map block for a file being built."""
    allc, todo = set(), [c for t in TARGETS for c in call_targets(t)]
    while todo:
        c = todo.pop()
        if c not in allc:
            allc.add(c)
            todo += list(call_targets(c))
    check(len(allc) == 30 and {0x02E7D8, 0x02E7E2} <= allc, 'the 224 stubs call 30 distinct functions (transitively)')
    path = os.path.join(REPO, 'disassembly', 'analysis', 'stub_tables_trace.txt')
    if not check_file:
        return sorted(allc), None
    try:
        listed = {int(x, 16) for x in re.findall(r'^==== FUNCTION (0x[0-9A-F]{6}) ', open(path).read(), re.M)}
    except OSError:
        return sorted(allc), None
    missing = sorted(allc - listed)
    check(not missing, f'every stub callee has a listed section in stub_tables_trace.txt (missing: {[hex(x) for x in missing]})')
    return sorted(allc), missing


# =====================================================================================
# symbolic evaluator for straight-line stubs
# =====================================================================================
class Unsupported(Exception):
    pass


HELPER_SAT8, HELPER_SAT16 = 0x0BE5A8, 0x0BE5D8
HELPER_U16F, HELPER_U8F = 0x0BE598, 0x0BE588


def r32(f):
    """Python float -> nearest float32.  ONLY for converting test INPUTS / constants / decimal
    text; never for arithmetic -- the chip's FPU does not round to nearest (see f_add below)."""
    return E.b2f(E.f2b(f))


# ---- the chip's single-precision arithmetic, as a model independent of the emulator's
# instruction semantics.  The SH7058 runs with FPSCR = 0x00040001 (RM = 01 round TOWARD ZERO,
# DN = 1), and the ROM's own FPU self-test at 0x058696 demands truncated results (corrections
# item 106).  So every inexact fadd / fsub / fmul / fdiv / fmac / float is computed EXACTLY
# (Fraction) and truncated to float32 by sh2e_emu.rz_bits (overflow -> +-FLT_MAX, denormal
# result -> signed zero).  fmac is fused: f0*fm + fn exact, one truncation.  Exact zeros and
# non-finite operands follow IEEE (the rounding mode does not change them; x - x = +0 in RZ).
# Operands are float32 VALUES (b2f-flushed); a Python double is never an intermediate result.
def _rz(q, fallback):
    if q == 0:
        return r32(fallback)                  # exact zero: IEEE sign rule, same in every mode
    return E.b2f(E.rz_bits(q))


def _fin(*a):
    return all(math.isfinite(x) for x in a)


def f_add(a, b):
    return _rz(Fraction(a) + Fraction(b), a + b) if _fin(a, b) else r32(a + b)


def f_sub(a, b):
    return _rz(Fraction(a) - Fraction(b), a - b) if _fin(a, b) else r32(a - b)


def f_mul(a, b):
    return _rz(Fraction(a) * Fraction(b), a * b) if _fin(a, b) else r32(a * b)


def f_div(a, b):
    if b == 0.0:                               # never reached by the stubs (scale != 0 is asserted)
        return math.nan if a == 0.0 or a != a else math.copysign(math.inf, a) * math.copysign(1.0, b)
    return _rz(Fraction(a) / Fraction(b), a / b) if _fin(a, b) else r32(a / b)


def f_mac(f0, fm, fn):
    """fmac fr0,frm,frn: frn = fr0*frm + frn, rounded ONCE toward zero (fused -- sh2e_emu's rule;
    the ROM self-test does not settle fused vs unfused)."""
    if _fin(f0, fm, fn):
        return _rz(Fraction(f0) * Fraction(fm) + Fraction(fn), f0 * fm + fn)
    return r32(f0 * fm + fn)


def f_float(i):
    """float fpul,frn: signed int32 -> float32, truncated toward zero above 2^24."""
    return _rz(Fraction(i), 0.0)


def C(v): return ('c', v & M32)
def FC(f): return ('fc', r32(f))
def isc(e): return e[0] == 'c'


def bound(e):
    k = e[0]
    if k == 'c':
        return e[1]
    if k == 'm':
        return M32 if (e[2] or e[1] == 4) else (1 << (8 * e[1])) - 1
    if k == 'zx':
        return min((1 << e[1]) - 1, bound(e[2]))
    if k == 'shr':
        return bound(e[1]) >> e[2]
    if k == 'shl':
        b = bound(e[1]) << e[2]
        return b if b <= M32 else M32
    if k == 'sat':
        return e[1]
    if k == 'add':
        b = bound(e[1]) + bound(e[2])
        return b if b <= M32 else M32
    return M32


def mk_mem(n, signed, addr, st):
    if isc(addr) and addr[1] < 0x100000:            # ROM is immutable: fold, remember
        v = int.from_bytes(rom[addr[1]:addr[1] + n], 'big')
        st.rom_reads.append((addr[1], n, v))
        return C(sext(v, 8 * n) if signed else v)
    return ('m', n, signed, addr)


def mk_zx(bits, x):
    if isc(x):
        return C(x[1] & ((1 << bits) - 1))
    if x[0] == 'm' and x[1] * 8 == bits:
        return ('m', x[1], False, x[3])
    if x[0] == 'm' and x[1] * 8 > bits and bits == 8 and isc(x[3]):
        return ('m', 1, False, C(x[3][1] + x[1] - 1))          # big-endian low byte
    if x[0] == 'shr' and bits == 8 and x[1][0] == 'm' and isc(x[1][3]) and x[2] % 8 == 0 \
            and (not x[1][2] or x[1][1] == 4) and x[2] // 8 < x[1][1]:
        return ('m', 1, False, C(x[1][3][1] + x[1][1] - 1 - x[2] // 8))
    if bound(x) < (1 << bits):
        return x
    return ('zx', bits, x)


def mk_sx(bits, x):
    if isc(x):
        return C(sext(x[1], bits))
    if x[0] == 'shl' and x[2] >= bits:
        return C(0)
    if x[0] == 'm' and x[1] * 8 == bits:
        return ('m', x[1], True, x[3])
    return ('sx', bits, x)


def mk_add(x, y):
    if isc(x) and isc(y):
        return C(x[1] + y[1])
    if isc(x):
        x, y = y, x
    if isc(y) and y[1] == 0:
        return x
    return ('add', x, y)


def mk_shl(x, k):
    return C(x[1] << k) if isc(x) else ('shl', x, k)


def mk_shr(x, k):
    return C(x[1] >> k) if isc(x) else ('shr', x, k)


def mk_swapw(x):
    if isc(x):
        return C((x[1] << 16) | (x[1] >> 16))
    if bound(x) < 0x10000:
        return ('shl', x, 16)
    return ('swapw', x)


def mk_xtrct(m, n):                       # Rn = Rm<<16 | Rn>>16
    if isc(m) and isc(n):
        return C((m[1] << 16) | (n[1] >> 16))
    if isc(m) and (m[1] & 0xFFFF) == 0 and n[0] == 'shl' and n[2] == 16 and bound(n[1]) < 0x10000:
        return n[1]
    return ('xtrct', m, n)


def mk_f(op, *a):
    if all(x[0] == 'fc' for x in a):
        return FC(ev((op,) + a, None))
    return (op,) + a


def ev(e, mem):
    """Numeric value of an expression.  mem(addr, n) -> unsigned big-endian value."""
    k = e[0]
    if k == 'c':
        return e[1]
    if k == 'fc':
        return e[1]
    if k == 'm':
        v = mem(ev(e[3], mem) & M32, e[1])
        return (sext(v, 8 * e[1]) & M32) if e[2] else v
    if k == 'fm':
        return E.b2f(mem(ev(e[1], mem) & M32, 4))
    if k == 'zx':
        return ev(e[2], mem) & ((1 << e[1]) - 1)
    if k == 'sx':
        return sext(ev(e[2], mem), e[1]) & M32
    if k == 'add':
        return (ev(e[1], mem) + ev(e[2], mem)) & M32
    if k == 'shl':
        return (ev(e[1], mem) << e[2]) & M32
    if k == 'shr':
        return ev(e[1], mem) >> e[2]
    if k == 'swapw':
        v = ev(e[1], mem)
        return ((v << 16) | (v >> 16)) & M32
    if k == 'xtrct':
        return ((ev(e[1], mem) << 16) | (ev(e[2], mem) >> 16)) & M32
    if k == 'not':
        return ~ev(e[1], mem) & M32
    if k == 'i2f':
        return f_float(sext(ev(e[1], mem), 32))
    if k == 'fneg':
        return -ev(e[1], mem)
    if k == 'fadd':
        return f_add(ev(e[1], mem), ev(e[2], mem))
    if k == 'fsub':
        return f_sub(ev(e[1], mem), ev(e[2], mem))
    if k == 'fmul':
        return f_mul(ev(e[1], mem), ev(e[2], mem))
    if k == 'fmac':                       # c + a*b, rounded once toward zero (fused: sh2e_emu's rule)
        return f_mac(ev(e[1], mem), ev(e[2], mem), ev(e[3], mem))
    if k == 'sat':
        return sat_model(ev(e[2], mem), ev(e[3], mem), ev(e[4], mem), e[1])
    raise KeyError(k)


def sat_model(x, off, scale, maxv):
    """0x0BE5A8 (maxv 255) / 0x0BE5D8 (maxv 65535):  clamp(trunc((x-off)/scale + 0.5), 0, maxv).

    The helpers clamp the INTEGER that ftrc produces (cmp/gt, cmp/pz), so what a NaN, an
    infinity or a value outside int32 returns depends on ftrc's own saturation.  The rule
    used here is the one scripts/sh2e_emu.py implements (NaN and < -2^31 -> 0x80000000,
    >= 2^31 -> 0x7FFFFFFF): NaN and negative overflow give 0, positive overflow gives maxv.
    That rule is the EMULATOR's; it has not been checked against silicon.

    Each of the three FPU steps (fsub, fdiv, fadd 0.5) truncates toward zero, as the chip does.
    A consequence worth knowing: for 0 <= y = (x - off)/scale < 2^23, trunc(rz(y + 0.5)) is
    EXACTLY floor(y + 0.5) -- an exact sum just below an integer n can never be rounded up to n
    (round-to-nearest could), so "+ 0.5, ftrc" is an exact round-half-up of the fdiv result."""
    v = f_add(f_div(f_sub(x, off), scale), 0.5)
    if v != v or v < -2.0 ** 31:
        return 0                          # ftrc -> 0x80000000 (negative) -> clamped to 0
    if v >= 2.0 ** 31:
        return maxv                       # ftrc -> 0x7FFFFFFF -> clamped to maxv
    r = int(v)                            # ftrc truncates toward zero
    return maxv if r > maxv else (r if r >= 0 else 0)


def gnum(f):
    """shortest decimal that round-trips to the same float32"""
    if f == int(f) and abs(f) < 1e7:
        return str(int(f))
    for p in range(1, 10):
        t = f'{f:.{p}g}'
        if r32(float(t)) == f:
            return t
    return repr(f)


def fmt(e):
    k = e[0]
    if k == 'c':
        return f'0x{e[1]:X}' if e[1] > 9 else str(e[1])
    if k == 'fc':
        return gnum(e[1])
    if k == 'm':
        a = f'{e[3][1]:08X}' if isc(e[3]) else fmt(e[3])
        return f"{'s' if e[2] else 'u'}{8 * e[1]}[{a}]"
    if k == 'fm':
        a = f'{e[1][1]:08X}' if isc(e[1]) else fmt(e[1])
        return f'f32[{a}]'
    if k == 'zx':
        return f'({fmt(e[2])} & 0x{(1 << e[1]) - 1:X})'
    if k == 'sx':
        return f'sext{e[1]}({fmt(e[2])})'
    if k == 'add':
        return f'({fmt(e[1])} + {fmt(e[2])})'
    if k == 'shl':
        return f'({fmt(e[1])} << {e[2]})'
    if k == 'shr':
        return f'({fmt(e[1])} >> {e[2]})'
    if k == 'i2f':
        return f'float({fmt(e[1])})'
    if k == 'fneg':
        return f'-{fmt(e[1])}'
    if k == 'fadd' and e[2][0] == 'fc' and e[2][1] < 0:
        return f'({fmt(e[1])} - {gnum(-e[2][1])})'
    if k in ('fadd', 'fsub', 'fmul'):
        return f"({fmt(e[1])} {'+-*'[('fadd', 'fsub', 'fmul').index(k)]} {fmt(e[2])})"
    if k == 'fmac':
        prod = f'{fmt(e[1])}*{fmt(e[2])}'
        return prod if e[3] == ('fc', 0.0) else f'({fmt(e[3])} + {prod})'
    if k == 'sat':
        x = fmt(e[2])
        off, sc = e[3], e[4]
        has_off = not (off[0] == 'fc' and off[1] == 0.0)
        has_sc = not (sc[0] == 'fc' and sc[1] == 1.0)
        if has_off:
            x = f'{x} + {gnum(-off[1])}' if off[0] == 'fc' and off[1] < 0 else f'{x} - {fmt(off)}'
            if has_sc:
                x = f'({x})'
        if has_sc:
            x = f'{x} / {fmt(sc)}'
        return f"sat{'8' if e[1] == 255 else '16'}({x})"
    return f'{k}({", ".join(fmt(x) for x in e[1:])})'


def leaves(e, out=None):
    """RAM reads in an expression: [(addr, kind)]"""
    out = [] if out is None else out
    if e[0] == 'm':
        if isc(e[3]):
            out.append((e[3][1], f"{'s' if e[2] else 'u'}{8 * e[1]}"))
        else:
            leaves(e[3], out)
    elif e[0] == 'fm':
        if isc(e[1]):
            out.append((e[1][1], 'f32'))
        else:
            leaves(e[1], out)
    else:
        for x in e[1:]:
            if isinstance(x, tuple):
                leaves(x, out)
    return out


class SymState:
    def __init__(self, r4):
        self.R = [None] * 16
        self.F = [None] * 16
        self.R[4] = r4
        self.sp = 0
        self.stack = {}
        self.rom_reads = []
        self.calls = []
        self.used_r4 = False


def sym_run(st, pc, depth=0):
    """Symbolically execute straight-line code from pc to its rts. Raises Unsupported."""
    R, F = st.R, st.F

    def g(i):
        if R[i] is None:
            raise Unsupported(f'r{i} read before set at {pc:06X}')
        if i == 4 and depth == 0 and st.r4_live:
            st.used_r4 = True
        return R[i]

    def gf(i):
        if F[i] is None:
            raise Unsupported(f'fr{i} read before set at {pc:06X}')
        return F[i]

    def setr(i, v):
        if i == 4:
            st.r4_live = False
        R[i] = v

    def one(pc):
        w = W(pc)
        n, m, d4, d8, op = (w >> 8) & 15, (w >> 4) & 15, w & 15, w & 0xFF, w >> 12
        mn = decode(w, pc)[0].split()[0]

        def need(x):
            if mn != x:
                raise RuntimeError(f'decoder disagreement at {pc:06X}: {mn} vs {x}')
        if w == 0x0009:
            return
        if op == 0xD:
            need('mov.l'); setr(n, C(L(((pc + 4) & ~3) + d8 * 4))); return
        if op == 0x9:
            need('mov.w'); setr(n, C(sext(W(pc + 4 + d8 * 2), 16))); return
        if (w >> 8) == 0xC7:
            need('mova'); setr(0, C(((pc + 4) & ~3) + d8 * 4)); return
        if op == 0xE:
            need('mov'); setr(n, C(sext(d8, 8))); return
        if op == 0x6:
            if d4 == 3: need('mov'); setr(n, g(m)); return
            if d4 in (0, 1, 2):
                need(('mov.b', 'mov.w', 'mov.l')[d4])
                sz = (1, 2, 4)[d4]
                if m == 15:
                    key = st.sp
                    if (key, sz) not in st.stack:
                        raise Unsupported(f'stack read of unknown slot at {pc:06X}')
                    v = st.stack[(key, sz)]
                    setr(n, mk_sx(8 * sz, v) if sz < 4 else v)
                else:
                    setr(n, mk_mem(sz, sz < 4, g(m), st))
                return
            if d4 == 0xC: need('extu.b'); setr(n, mk_zx(8, g(m))); return
            if d4 == 0xD: need('extu.w'); setr(n, mk_zx(16, g(m))); return
            if d4 == 0xE: need('exts.b'); setr(n, mk_sx(8, g(m))); return
            if d4 == 0xF: need('exts.w'); setr(n, mk_sx(16, g(m))); return
            if d4 == 0x9: need('swap.w'); setr(n, mk_swapw(g(m))); return
            if d4 == 0x7:
                need('not'); x = g(m); setr(n, C(~x[1]) if isc(x) else ('not', x)); return
        if op == 0x2:
            if d4 == 0xD: need('xtrct'); setr(n, mk_xtrct(g(m), g(n))); return
            if d4 == 0 and n == 15:
                need('mov.b'); st.stack[(st.sp, 1)] = mk_zx(8, g(m)); return
        if op == 0x0:
            if d4 in (0xC, 0xD, 0xE):
                need(('mov.b', 'mov.w', 'mov.l')[d4 - 0xC])
                sz = (1, 2, 4)[d4 - 0xC]
                setr(n, mk_mem(sz, sz < 4, mk_add(g(0), g(m)), st)); return
        if (w >> 8) == 0x84:
            need('mov.b'); setr(0, mk_mem(1, True, mk_add(g(m), C(d4)), st)); return
        if (w >> 8) == 0x85:
            need('mov.w'); setr(0, mk_mem(2, True, mk_add(g(m), C(d4 * 2)), st)); return
        if op == 0x5:
            need('mov.l'); setr(n, mk_mem(4, False, mk_add(g(m), C(d4 * 4)), st)); return
        if op == 0x3 and d4 == 0xC:
            need('add'); setr(n, mk_add(g(n), g(m))); return
        if op == 0x7:
            need('add')
            if n == 15:
                st.sp += sext(d8, 8)
            else:
                setr(n, mk_add(g(n), C(sext(d8, 8))))
            return
        if op == 0x4:
            if d8 in (0x22, 0x26) and n == 15:      # sts.l pr,@-r15 / lds.l @r15+,pr
                need('sts.l' if d8 == 0x22 else 'lds.l'); return
            sh = {0x00: ('shll', 1, 'l'), 0x08: ('shll2', 2, 'l'), 0x18: ('shll8', 8, 'l'),
                  0x28: ('shll16', 16, 'l'), 0x01: ('shlr', 1, 'r'), 0x09: ('shlr2', 2, 'r'),
                  0x19: ('shlr8', 8, 'r'), 0x29: ('shlr16', 16, 'r')}.get(d8)
            if sh:
                need(sh[0])
                setr(n, (mk_shl if sh[2] == 'l' else mk_shr)(g(n), sh[1])); return
        if op == 0xF:
            if d4 == 0x8: need('fmov.s'); F[n] = fmem(g(m)); return
            if d4 == 0x6: need('fmov.s'); F[n] = fmem(mk_add(g(0), g(m))); return
            if d4 == 0xC: need('fmov'); F[n] = gf(m); return
            if d8 == 0x8D: need('fldi0'); F[n] = FC(0.0); return
            if d8 == 0x9D: need('fldi1'); F[n] = FC(1.0); return
            if d8 == 0x4D: need('fneg'); F[n] = mk_f('fneg', gf(n)); return
            if d4 == 0x0: need('fadd'); F[n] = mk_f('fadd', gf(n), gf(m)); return
            if d4 == 0x1: need('fsub'); F[n] = mk_f('fsub', gf(n), gf(m)); return
            if d4 == 0x2: need('fmul'); F[n] = mk_f('fmul', gf(n), gf(m)); return
        raise Unsupported(f'{pc:06X}: {decode(w, pc)[0]}')

    def fmem(addr):
        if isc(addr) and addr[1] < 0x100000:
            return FC(E.b2f(L(addr[1])))             # pool float
        return ('fm', addr)

    while True:
        w = W(pc)
        txt = decode(w, pc)[0]
        mn = txt.split()[0]
        if mn == 'rts':
            one(pc + 2)
            return
        if mn in ('jsr', 'bsr'):
            if mn == 'jsr':
                tr = g((w >> 8) & 15)
                if not isc(tr):
                    raise Unsupported('computed jsr')
                tgt = tr[1]
            else:
                tgt = int(txt.split()[1], 16)
            one(pc + 2)                               # delay slot
            st.calls.append(tgt)
            if tgt in (HELPER_SAT8, HELPER_SAT16):
                R[0] = ('sat', 255 if tgt == HELPER_SAT8 else 65535, gf(4), gf(6), gf(5))
                R[4] = R[5] = None
                F[2] = F[3] = F[4] = None
            elif tgt in (HELPER_U16F, HELPER_U8F):
                x = mk_zx(16 if tgt == HELPER_U16F else 8, g(4))
                F[0] = mk_f('fmac', gf(4), ('i2f', x), gf(5))
                F[3] = F[5] = None
                R[4] = None
            else:
                if depth >= 2:
                    raise Unsupported('call depth')
                sym_run(st, tgt, depth + 1)
            pc += 4
            continue
        if mn in ('bt', 'bf', 'bt/s', 'bf/s', 'bra', 'jmp', 'braf', 'bsrf', 'rte'):
            raise Unsupported(f'{pc:06X}: {txt}')
        one(pc)
        pc += 2


def sym_getter(entry, idx):
    st = SymState(C(idx))
    st.r4_live = True
    sym_run(st, entry)
    if st.R[0] is None:
        raise Unsupported('r0 not set')
    return mk_zx(8, st.R[0]), st


# =====================================================================================
# emulator with read/write logging and a peripheral scratch map
# =====================================================================================
class Emu2(E.Emu):
    def __init__(self):
        super().__init__(rom)
        self.rlog = []
        self.periph = {}
        self.plog = []
        self.init[:] = b'\x01' * len(self.init)       # inputs come from rlog, not uninit_reads
        self.srlog = []
        # 0x0BE81C / 0x0BE82C end in `ldc ..,sr`, which the emulator refuses: stub them.
        self.stub(0x0BE81C, fn=self._sr_enter)
        self.stub(0x0BE82C, fn=self._sr_leave)

    def _sr_enter(self, em):
        self.srlog.append(('0BE81C', em.R[4], em.R[5]))
        E.Emu.write(self, em.R[4], 4, 0x000000B0)     # pretend the previous SR & 0xF0 was 0xB0
        self.writes.pop(em.R[4], None)

    def _sr_leave(self, em):
        self.srlog.append(('0BE82C', em.R[4]))

    def read(self, a, n):
        a &= M32
        if a >= 0xFFFFE000:
            self.rlog.append(('P', a, n))
            return self.periph.get(a, 0) & ((1 << (8 * n)) - 1)
        if RAM_LO <= a <= RAM_HI:
            if a < STACK_LO:
                self.rlog.append(('R', a, n))
        elif a < 0x100000 and not (0x05D000 <= a < 0x05EA00) and abs(a - self.pc) > 0x400:
            self.rlog.append(('O', a, n))
        return super().read(a, n)

    def write(self, a, n, v):
        a &= M32
        if a >= 0xFFFFE000:
            self.periph[a] = v & ((1 << (8 * n)) - 1)
            self.plog.append((a, n, v & ((1 << (8 * n)) - 1)))
            return
        super().write(a, n, v)

    def fill(self, byte):
        self.ram[:] = bytes([byte]) * len(self.ram)

    def poke(self, a, n, v):
        o = a - RAM_LO
        self.ram[o:o + n] = (v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big')

    def peek(self, a, n):
        o = a - RAM_LO
        return int.from_bytes(self.ram[o:o + n], 'big')

    def ram_writes(self):
        """non-stack RAM bytes written since construction: {addr: byte}"""
        return {a: v for a, v in self.writes.items() if a < STACK_LO}


def run_getter(entry, idx, setup=None, r4=None):
    e = Emu2()
    if setup:
        setup(e)
    e.call(entry, regs={4: idx if r4 is None else r4, 0: 0xDEAD0000})
    return e.R[0] & 0xFF, e


# ---- static check: which instructions read the value r4 had on ENTRY -------------------
_R4_RW2 = {'add', 'sub', 'and', 'or', 'xor', 'addc', 'subc', 'addv', 'subv', 'div1', 'xtrct'}       # op Rm,Rn: Rn read+written
_R4_RD2 = {'cmp/eq', 'cmp/ge', 'cmp/gt', 'cmp/hi', 'cmp/hs', 'cmp/str', 'tst', 'mul.l', 'muls.w', 'mulu.w',
           'dmuls.l', 'dmulu.l'}                                                                    # both only read
_R4_RW1 = {'shll', 'shlr', 'shal', 'shar', 'shll2', 'shlr2', 'shll8', 'shlr8', 'shll16', 'shlr16', 'rotl', 'rotr',
           'rotcl', 'rotcr', 'dt'}                                                                  # op Rn: read+written
_R4_RD1 = {'cmp/pl', 'cmp/pz', 'jsr', 'jmp', 'lds', 'ldc', 'braf', 'bsrf'}                          # op Rn: read
_R4_WR = {'mov', 'mov.b', 'mov.w', 'mov.l', 'extu.b', 'extu.w', 'exts.b', 'exts.w', 'neg', 'negc', 'not',
          'swap.b', 'swap.w', 'movt', 'sts', 'stc'}                                                 # last operand written


def _r4_use(txt):
    """(reads r4, writes r4) for one disassembled instruction."""
    parts = txt.split(None, 1)
    mn, ops = parts[0], (parts[1] if len(parts) > 1 else '').replace('fr4', 'FRx')
    if 'r4' not in ops:
        return False, False
    oo, depth, cur = [], 0, ''
    for ch in ops:
        depth += (ch == '(') - (ch == ')')
        if ch == ',' and depth == 0:
            oo.append(cur)
            cur = ''
        else:
            cur += ch
    oo.append(cur)
    rd = wr = False
    for i, op in enumerate(oo):
        if 'r4' not in op:
            continue
        if op != 'r4':                                # r4 inside a memory operand: an address read
            rd = True
            wr |= op in ('@r4+', '@-r4')
        elif mn in _R4_RD1:
            rd = True
        elif mn in _R4_RW1:
            rd = wr = True
        elif i < len(oo) - 1 or mn in _R4_RD2:        # source register / compare operand
            rd = True
        elif mn in _R4_RW2:
            rd = wr = True
        elif mn in _R4_WR:
            wr = True
        else:
            raise RuntimeError(f'static r4 pass: unclassified instruction {txt!r}')
    return rd, wr


def static_r4_reads(entry):
    """Addresses of the instructions that can read the value r4 held when `entry` was called.
    Depth-first over every path; a jsr/bsr/jmp to a literal target is followed INTO the callee
    (r4 is the first argument register), and a path stops once r4 has been overwritten."""
    hits, seen, work = set(), set(), [(entry, ())]
    while work:
        pc, stack = work.pop()
        lit = {}
        while (pc, stack) not in seen:
            seen.add((pc, stack))
            txt = decode(W(pc), pc)[0]
            mn = txt.split()[0]
            dead = False

            def step(p):
                t = decode(W(p), p)[0]
                m = re.match(r'mov\.l @\((0x[0-9A-F]+)\),(r\d+)', t)
                if m:
                    lit[m.group(2)] = L(int(m.group(1), 16))
                rd, wr = _r4_use(t)
                if rd:
                    hits.add(p)
                return wr
            if mn in ('bt', 'bf'):
                work.append((int(txt.split()[1], 16), stack))
                pc += 2
                continue
            if mn in ('bt/s', 'bf/s'):
                dead = step(pc + 2)
                if not dead:
                    work.append((int(txt.split()[1], 16), stack))
                    pc += 4
                    continue
                break
            if mn == 'bra':
                if step(pc + 2):
                    break
                pc = int(txt.split()[1], 16)
                continue
            if mn == 'rts':
                if step(pc + 2) or not stack:
                    break
                pc, stack = stack[-1], stack[:-1]
                continue
            if mn in ('jsr', 'bsr', 'jmp'):
                dead = step(pc)                       # jsr @r4 would be a read
                tgt = int(txt.split()[1], 16) if mn == 'bsr' else lit.get(txt.split('@')[1])
                if tgt is None:
                    raise RuntimeError(f'static r4 pass: unresolved {txt} at {pc:06X}')
                if dead or step(pc + 2):
                    break
                if mn != 'jmp':
                    stack = stack + (pc + 4,)
                pc, lit = tgt, {}
                continue
            if step(pc):
                break
            pc += 2
    return sorted(hits)


RNG = random.Random(20261127)
F32_POOL =[0.0, 1.0, -1.0, 0.5, 0.2499, 14.7, 100.0, 127.5, 128.0, 255.0, 256.0, 1000.0,
            6700.0, -40.0, 39.9, 1e6, -1e6, 0.0078125, 3.3, 12.9]


def rand_f32():
    r = RNG.random()
    if r < 0.4:
        return RNG.choice(F32_POOL)
    if r < 0.7:
        return RNG.uniform(-2.0, 4.0)
    if r < 0.9:
        return RNG.uniform(-300.0, 300.0)
    return RNG.uniform(-1000.0, 70000.0)


def verify_symbolic(entry, idx, expr, trials=12):
    lv = leaves(expr)
    for t in range(trials):
        vals = {}
        for a, kind in lv:
            if kind == 'f32':
                vals[a] = (4, E.f2b(rand_f32()))
            else:
                nb = int(kind[1:]) // 8
                vals[a] = (nb, RNG.choice([0, 1, 0x7F, 0x80, 0xFF]) * (0x01010101 & ((1 << (8 * nb)) - 1))
                           if t < 3 else RNG.getrandbits(8 * nb))
        bg = RNG.choice([0x00, 0x5A, 0xFF])

        def setup(e):
            e.fill(bg)
            for a, (nb, v) in vals.items():
                e.poke(a, nb, v)
        got, e = run_getter(entry, idx, setup)
        want = ev(expr, lambda a, n: e.peek(a, n) if a >= RAM_LO else int.from_bytes(rom[a:a + n], 'big'))
        if got != want:
            return False, (vals, got, want)
    return True, None


def probe_dynamic(entry, idx):
    """Emulator probing of a branching getter.

    1. discover the RAM bytes it reads (several fills, then one-hot rounds);
    2. sweep every single-byte input over all 256 values with the others at 0 and record
       which output bits flip relative to the all-zero output (`base`);
    3. check the compositional model  out = base XOR (xor of per-input effects)  on random
       assignments.  Inputs wider than a byte are left to the hand analysis."""
    inputs = collections.OrderedDict()
    periph = set()
    other = set()                                      # ROM data reads outside the stub region

    def discover(setup):
        _, e = run_getter(entry, idx, setup)
        new = False
        for k, a, n in e.rlog:
            if k == 'R' and (a, n) not in inputs:
                inputs[(a, n)] = True
                new = True
            if k == 'P':
                periph.add(a)
            if k == 'O':
                other.add(a)
        return new

    for fillv in (0x00, 0x01, 0xFF, 0x80, 0x02):
        discover(lambda e, v=fillv: e.fill(v))
    for _ in range(3):                                 # one-hot rounds may expose more
        grew = False
        for (a, n) in list(inputs):
            for v in (1, 0xFF):
                def setup(e, a=a, n=n, v=v):
                    e.fill(0)
                    e.poke(a, n, v * (0x01010101 & ((1 << (8 * n)) - 1)))
                grew |= discover(setup)
        if not grew:
            break

    def out_with(assign):
        def setup(e):
            e.fill(0)
            for (a, n), v in assign.items():
                e.poke(a, n, v)
        return run_getter(entry, idx, setup)[0]

    base = out_with({})
    eff = {}
    for (a, n) in inputs:
        if n != 1:
            eff[(a, n)] = None
            continue
        eff[(a, n)] = [out_with({(a, n): v}) ^ base for v in range(256)]
    modelled = all(v is not None for v in eff.values())
    ok = modelled
    if modelled:
        for _ in range(200):
            assign = {k: RNG.choice((0, 1, 1, 2, 0x80, 0xFF, RNG.getrandbits(8))) for k in inputs}
            want = base
            for k, v in assign.items():
                want ^= eff[k][v]
            if out_with(assign) != want:
                ok = False
                break
    return {'inputs': list(inputs), 'periph': sorted(periph), 'other': sorted(other), 'base': base, 'eff': eff,
            'model_ok': ok}


def classify_effect(d):
    """d[v] = output bits flipped when the byte is v (others 0).  Returns [(cond, mask)]."""
    nz = {m for m in d if m}
    if not nz:
        return []
    if len(nz) == 1:
        m = nz.pop()
        hit = [v for v in range(256) if d[v]]
        if hit == [1]:
            return [('==1', m)]
        if hit == list(range(1, 256)):
            return [('!=0', m)]
    # bit-linear?  effect(v) = xor of effect(1<<i) over the set bits of v
    lin = all(d[v] == __import__('functools').reduce(lambda x, i: x ^ d[1 << i], [i for i in range(8) if v >> i & 1], 0)
              for v in range(256))
    if lin:
        return [(f'.b{i}', d[1 << i]) for i in range(7, -1, -1) if d[1 << i]]
    return [('?', 0)]


def describe_dynamic(p):
    per_bit = collections.defaultdict(list)
    opaque = []
    for (a, n), d in p['eff'].items():
        if d is None:
            opaque.append(f'{a:08X}/{n}')
            continue
        cl = classify_effect(d)
        if not cl:
            opaque.append(f'{a:08X}/1(read, no effect seen)')
        for cond, mk in cl:
            if cond == '?':
                opaque.append(f'{a:08X}/1(effect not classified)')
                continue
            term = f'u8[{a:08X}]{cond}' if cond.startswith('.') else f'(u8[{a:08X}]{cond})'
            for k in range(8):
                if mk >> k & 1:
                    per_bit[k].append(term)
    parts = []
    for k in range(7, -1, -1):
        b = p['base'] >> k & 1
        if per_bit[k]:
            t = ' ^ '.join(per_bit[k])
            parts.append(f'b{k}=' + (f'!{t}' if b and len(per_bit[k]) == 1 else (f'1 ^ {t}' if b else t)))
        elif b:
            parts.append(f'b{k}=1')
    s = ('bits ' + ' '.join(parts)) if parts else 'bits: all 0 for every input tried'
    if opaque:
        s += ' | other inputs: ' + ' '.join(opaque)
    if p['periph']:
        s += ' | periph reads: ' + ' '.join(f'{a:08X}' for a in p['periph'])
    if p['eff']:
        s += ' | ' + ('bit model verified (256-value sweep per input + 200 random mixes)' if p['model_ok']
                      else 'NOT fully modelled by the bit model - see SPECIAL checks')
    return s


# =====================================================================================
# C. all getters
# =====================================================================================
GET_INFO = {}           # idx -> dict(kind, text, leaves, rom)


def analyse_getters():
    dyn_cache = {}
    n_sym = n_dyn = 0
    r4_dependent = set()
    for idx, tgt in enumerate(A):
        try:
            expr, st = sym_getter(tgt, idx)
            ok, why = verify_symbolic(tgt, idx, expr)
            check(ok, f'getter[{idx:#05x}] @{tgt:06X}: formula {fmt(expr)} matches emulator ({why})')
            if st.used_r4:
                r4_dependent.add(tgt)
            romr = [(a, n, v) for a, n, v in st.rom_reads]
            text = fmt(expr)
            if not isc(expr) and not leaves(expr):
                text += f' = 0x{ev(expr, None):02X}'
            GET_INFO[idx] = dict(kind='const' if not leaves(expr) else 'formula', text=text, expr=expr,
                                 leaves=leaves(expr), rom=romr, calls=st.calls)
            sat = _find_sat(expr)
            if sat is not None:
                # the scale every stub hands to 0x0BE5A8 / 0x0BE5D8 is a non-zero constant, so the helper's
                # fdiv never divides by zero (sh2e_emu.py returns Inf for NaN / 0, which would be wrong)
                check(sat[4][0] == 'fc' and sat[4][1] != 0.0 and sat[3][0] == 'fc',
                      f'getter[{idx:#05x}]: scale and offset passed to the saturating helper are constants, scale != 0')
            # every fmac a getter reaches (0x0BE598) has addend fr5 = 0, so its result is rz(k * float(raw))
            # whether fmac is fused or not -- the getter formulas do not depend on that unsettled rule
            check(all(f[3] == ('fc', 0.0) for f in _fmacs(expr)),
                  f'getter[{idx:#05x}]: every fmac it reaches has a zero addend (fused vs unfused cannot matter)')
            n_sym += 1
        except Unsupported:
            if tgt not in dyn_cache:
                dyn_cache[tgt] = probe_dynamic(tgt, idx)
            p = dyn_cache[tgt]
            if tgt in SPECIAL_GETTERS:
                GET_INFO[idx] = dict(kind='dynamic', text=SPECIAL_GETTERS[tgt][0], expr=None,
                                     leaves=SPECIAL_GETTERS[tgt][2], rom=[], calls=[], probe=p)
            elif not p['inputs'] and not p['periph'] and not p['other']:
                # a stub outside the symbolic evaluator's instruction set that reads NOTHING (no
                # RAM, no peripheral, no ROM data): its result cannot vary.  Index 0x0DF / stub
                # 0x05DEC6 (straight-line `and #imm` on a stack byte) is the only one; the first
                # version of this script tallied it "dynamic" and so counted 559 constants.
                outs = {run_getter(tgt, idx, lambda e, v=v: e.fill(v))[0] for v in (0x00, 0x01, 0x02, 0x5A, 0x80, 0xFF)}
                check(outs == {p['base']}, f'getter {tgt:06X}: reads nothing and returns 0x{p["base"]:02X} on every RAM fill')
                GET_INFO[idx] = dict(kind='const', text=f'0x{p["base"]:02X} (emulated; reads no RAM)',
                                     expr=None, leaves=[], rom=[], calls=[], probe=p)
            else:
                check(p['model_ok'], f'getter {tgt:06X}: bit model verified')
                GET_INFO[idx] = dict(kind='dynamic', text=describe_dynamic(p), expr=None,
                                     leaves=[(a, f'u{8 * n}' if n == 1 else f'{n}B') for a, n in p['inputs']],
                                     rom=[], calls=[], probe=p)
            n_dyn += 1
    # r4 independence, dynamically, for every distinct getter
    pat = bytes((i * 7 + 3) & 0xFF for i in range(0xC000))
    for tgt in sorted(set(A)):
        idx = IDX_A[tgt][0]
        o1, o2 = set(), set()
        for r4 in (idx, 0, 0x8E, 0x34F):
            o1.add(run_getter(tgt, idx, lambda e: e.fill(0x01), r4=r4)[0])
            o2.add(run_getter(tgt, idx, lambda e: e.ram.__setitem__(slice(None), pat), r4=r4)[0])
        if len(o1) > 1 or len(o2) > 1:
            r4_dependent.add(tgt)
    # ... and again for EVERY index, with a wider r4 set and every other input register
    # scrambled (r0-r3, r5-r14, fr0-fr15, GBR, MACH/MACL, T): the result may depend on r4 only.
    dyn_dep = set()
    for idx, tgt in enumerate(A):
        outs = set()
        for r4 in (idx, 0, 0x8E, 0x34F, 0xFFFF, 0xFFFFFFFF, idx ^ 0x155):
            e = Emu2()
            e.ram[:] = pat
            regs = {i: RNG.getrandbits(32) for i in (0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14)}
            regs[4] = r4
            e.gbr, e.mach, e.macl, e.T = RNG.getrandbits(32), RNG.getrandbits(32), RNG.getrandbits(32), RNG.getrandbits(1)
            e.call(tgt, regs=regs, fregs={i: RNG.uniform(-1e6, 1e6) for i in range(16)})
            outs.add(e.R[0] & 0xFF)
        if len(outs) > 1:
            dyn_dep.add(tgt)
    check(dyn_dep == {0x05DCAE, 0x05DCCE},
          'all 848 indices x 7 values of r4 with every other register scrambled: only 0x05DCAE / 0x05DCCE change')
    # ... and statically: the only instructions that read the ENTRY value of r4 (callees inlined)
    static = {t: static_r4_reads(t) for t in sorted(set(A))}
    static = {t: h for t, h in static.items() if h}
    check(static == {0x05DCAE: [0x05DCB0], 0x05DCCE: [0x05DCD0]},
          'static pass: entry r4 is read only at 0x05DCB0 (stub 0x05DCAE) and 0x05DCD0 (stub 0x05DCCE)')
    for tgt in sorted(set(A)):
        idx = IDX_A[tgt][0]
        for fillv in (0x00, 0x01, 0xFF):
            _, e = run_getter(tgt, idx, lambda e, v=fillv: e.fill(v))
            check(not e.ram_writes() and not e.plog and not any(k == 'P' for k, a, n in e.rlog),
                  f'getter {tgt:06X}: writes no RAM outside its stack frame and touches no peripheral')
    check(r4_dependent == {0x05DCAE, 0x05DCCE},
          f'only getters 0x05DCAE and 0x05DCCE depend on r4 (got {sorted(map(hex, r4_dependent))})')
    return n_sym, n_dyn


# =====================================================================================
# D. setters
# =====================================================================================
SET_INFO = {}


def _pair(b):
    return {0: b & 0xFF, 1: ~b & 0xFF}


def _m_none(v):
    return {}


SPECIAL_SETTERS = {
    # stub: (text, model(v) -> {addr: byte})   -- read from the listings, asserted below for v = 0..255
    0x05E7FA: ('u8[FFFF83AC] = v; u16[FFFF341A] = ((v & 1) << 8) | (~(v & 1) & 0xFF)   (via 0x04E876)',
               lambda v: {0xFFFF83AC: v, 0xFFFF341A: v & 1, 0xFFFF341B: ~(v & 1) & 0xFF}),
    0x05E844: ('if v & 2: u8[FFFF7235] = 1 (0x02E364);  if v & 1: u8[FFFF7234] = 1, u8[FFFF7236] = 0xAA (0x02E34E)'
               ' else: u8[FFFF7234] = 0, u8[FFFF7236] = 0 (0x02E35A)',
               lambda v: {**({0xFFFF7235: 1} if v & 2 else {}),
                          **({0xFFFF7234: 1, 0xFFFF7236: 0xAA} if v & 1 else {0xFFFF7234: 0, 0xFFFF7236: 0})}),
    0x05E8A2: ('u8[FFFF8E94] = v, between 0BE81C(sp, 0xE0) and 0BE82C(saved)   (tail-jump to 0x05AA30)',
               lambda v: {0xFFFF8E94: v}),
}


def analyse_setters():
    for tgt in sorted(set(B)):
        res = {}
        for v in range(256):
            e = Emu2()
            e.fill(0x00)
            e.call(tgt, regs={4: v})
            res[v] = e.ram_writes()
            check(not e.plog, f'setter {tgt:06X}: no peripheral write')
        calls = [int(x.split('0x')[1], 16) for x in SIG[tgt] if x.startswith(('jsr 0x', 'jmp 0x'))]
        addrs = sorted({a for v in res for a in res[v]})
        if tgt in SPECIAL_SETTERS:
            text, model = SPECIAL_SETTERS[tgt]
            check(all(res[v] == model(v) for v in res), f'setter {tgt:06X}: {text} for v = 0..255')
        elif not addrs:
            text = 'no RAM write'
        elif len(addrs) == 1 and all(res[v] == {addrs[0]: v} for v in res):
            text = f'u8[{addrs[0]:08X}] = v'
        elif len(addrs) == 2 and addrs[1] == addrs[0] + 1 and \
                all(res[v] == {addrs[0]: v, addrs[1]: (~v) & 0xFF} for v in res):
            text = f'u16[{addrs[0]:08X}] = (v << 8) | (~v & 0xFF)'
        elif len(addrs) == 4 and addrs == list(range(addrs[0], addrs[0] + 4)) and \
                all(bytes(res[v][a] for a in addrs) == struct.pack('>f', float(v)) for v in res):
            text = f'f32[{addrs[0]:08X}] = float(v)'
        else:
            raise AssertionError(f'setter {tgt:06X}: effect not modelled')
        CHECKS.append(f'setter {tgt:06X}: {text} for v = 0..255')
        if calls and tgt not in SPECIAL_SETTERS:
            text += '   (calls ' + ' '.join(f'0x{c:06X}' for c in calls) + ')'
        SET_INFO[tgt] = dict(text=text, writes=res, calls=calls)
    e = Emu2(); e.fill(0); e.call(0x05E8A2, regs={4: 0x1234})
    check(e.srlog == [('0BE81C', E.STACK_TOP - 12, 0xE0), ('0BE82C', 0xB0)] and e.ram_writes() == {0xFFFF8E94: 0x34},
          'setter 05E8A2: write of (r4 & 0xFF) is bracketed by 0BE81C(sp, 0xE0) / 0BE82C(saved)')
    # sign-extended r4 (what 0x05F78E passes for v >= 0x80) changes nothing
    for tgt in sorted(set(B)):
        for v in (0x80, 0xA5, 0xFF):
            e1 = Emu2(); e1.fill(0); e1.call(tgt, regs={4: v})
            e2 = Emu2(); e2.fill(0); e2.call(tgt, regs={4: sext(v, 8) & M32})
            check(e1.ram_writes() == e2.ram_writes(), f'setter {tgt:06X}: r4 = v and r4 = sext8(v) write the same')


# =====================================================================================
# special (hand-read) models for the two getters the bit model cannot express
# =====================================================================================
def _g_e0(mem):
    hi, lo = mem(0xFFFF8F0C, 1), mem(0xFFFF8F0D, 1)
    return hi if lo == (~hi & 0xFF) else 0


def _g_66(mem):
    x = E.b2f(mem(0xFFFF9094, 4))
    return (0x80 if mem(0xFFFF6A54, 1) == 1 else 0) | (0x40 if (x < -0.390625 or x > 0.390625) else 0) | \
        (0x20 if mem(0xFFFF90BB, 1) == 1 else 0)


SPECIAL_GETTERS = {
    0x05DEF8: ('u8[FFFF8F0C] if u8[FFFF8F0D] == (~u8[FFFF8F0C] & 0xFF) else 0   (via 0x05DF04, 0x0BE980)', _g_e0,
               [(0xFFFF8F0C, 'u8'), (0xFFFF8F0D, 'u8')]),
    0x05DA88: ('b7=(u8[FFFF6A54]==1) b6=(f32[FFFF9094] < -0.390625 or > 0.390625) b5=(u8[FFFF90BB]==1)   '
               '(via 0x0BE608, 0x061496)', _g_66,
               [(0xFFFF6A54, 'u8'), (0xFFFF9094, 'f32'), (0xFFFF90BB, 'u8')]),
}


def special_getters():
    n = 0
    for tgt, (text, model, lv) in SPECIAL_GETTERS.items():
        idx = IDX_A[tgt][0]
        for t in range(400):
            vals = {}
            for a, kind in lv:
                if kind == 'f32':
                    vals[a] = (4, E.f2b(RNG.choice([0.0, 0.390625, -0.390625, 0.39062503, -0.39062503, 0.39, -0.39,
                                                    1.0, -1.0, 100.0, RNG.uniform(-1, 1)])))
                else:
                    vals[a] = (1, RNG.choice([0, 1, 1, 2, 0x5A, 0xA5, 0xFE, 0xFF, RNG.getrandbits(8)]))
            if tgt == 0x05DEF8 and t % 2:
                vals[0xFFFF8F0D] = (1, ~vals[0xFFFF8F0C][1] & 0xFF)

            def setup(e):
                e.fill(0)
                for a, (nb, v) in vals.items():
                    e.poke(a, nb, v)
            got, e = run_getter(tgt, idx, setup)
            check(got == model(e.peek), f'getter {tgt:06X}: {text}')
            n += 1
    # the two helpers they rely on
    for w in list(range(0, 0x10000, 257)) + [0x00FF, 0xFF00, 0xA55A, 0x5AA5, 0x0100, 0x7F80, 0x807F, 0x1234]:
        e = Emu2(); e.fill(0); e.poke(0xFFFF6000, 2, w)
        e.call(0x0BE980, regs={4: 0xFFFF6000})
        check((e.R[0] == 0) == ((w & 0xFF) == (~(w >> 8) & 0xFF)) and e.R[0] < 256,
              '0BE980(ptr) == 0 exactly when u8[ptr+1] == ~u8[ptr]')
        n += 1
    for x in (-2.0, -0.390626, -0.390625, -0.39, 0.0, 0.39, 0.390625, 0.390626, 2.0, 5.0, 4.6, 5.4, 4.5, 5.5):
        for c, hw in ((0.0, 0.390625), (5.0, 0.5)):
            e = Emu2()
            e.call(0x0BE608, fregs={4: x, 5: c, 6: hw})
            want = int(r32(x) < f_sub(c, hw) or r32(x) > f_add(c, hw))      # 0BE60A fsub, 0BE614 fadd
            check(e.R[0] == want, f'0BE608(x={x}, centre={c}, half={hw}) == {want}')
            n += 1
    return n


def _next_f32(f, n):
    """the float32 n representable steps above (n > 0) or below (n < 0) f; f must be > 0"""
    return E.b2f(E.f2b(f) + n)


def rounding_edges():
    """Index 0x009 (stub 0x05D2C0) adds -1 to the value (0x05D2CA fadd) and then passes -1 as
    the helper's offset (0x0BE5AA fsub, x' = (x - 1) - (-1)).  The pair does NOT cancel
    exactly.  Why, and where -- every FPU step truncates TOWARD ZERO (FPSCR RM = 01, corrections
    item 106; this pass was first written against a round-to-nearest emulator, see the trace):
      * x in (0, 0.5): x - 1 lies in (-1, -0.5], where floats are 2^-24 apart; truncation
        toward zero shrinks the magnitude, i.e. rounds x - 1 UP onto that grid.  The second
        step is exact (Sterbenz: both operands within a factor 2).  So
        x' = ceil(x * 2^24) / 2^24 exactly: x' = x + d, 0 <= d < 2^-24, never below x.
      * x in [0.5, 2]: x - 1 is exact (Sterbenz), x' = x.  Every boundary (cnt - 0.5) *
        0.0078125 is below 2, and for x <= 0 or x > 2 both forms saturate the same way.
    Both forms are then an EXACT round-half-up of their input / k (k = 2^-7, so the fdiv is
    exact, and "+ 0.5, ftrc" under truncation is exactly floor(y + 0.5) -- see sat_model).
    So the ROM is one count higher exactly when b - 2^-24 < x < b for a boundary b < 0.5
    (b = (2cnt - 1) / 256, cnt = 1..64, every b a multiple of 2^-24).  The number of float32
    in that open interval is 2^-24 / ulp(below b) - 1:
        cnt 1: 255   2: 63   3-4: 31 each   5-8: 15 each   9-16: 7 each   17-32: 3 each
        33-64: 1 each             = 255 + 63 + 62 + 60 + 56 + 48 + 32 = 576.
    Probed (settle pass, 2026-11-27; re-run under round-toward-zero the same day):
      W  EVERY float32 within 2^-24 of each of the 256 boundaries (1536 inputs) -- so the
         count of differing inputs is complete, not a sample;
      P  the first version's grid: 40 floats either side of each boundary plus the
         neighbourhood of 0 (20817 inputs).  It is NOT complete: below the count-1
         boundary floats are 2^-32 apart and differences reach 255 floats down."""
    k = 0.0078125
    K = Fraction(1, 128)

    def rom_009(x):
        e = Emu2()
        e.fill(0)
        e.poke(0xFFFF76D4, 4, E.f2b(x))
        e.call(0x05D2C0, regs={4: 9})
        return e.R[0] & 0xFF

    def judge(x, got, bnd_exact):
        """returns 1 if the ROM result differs from sat8(x / k); asserts the double-step model"""
        xp = f_add(x, -1.0)                                     # 0x05D2CA fadd fr6,fr4 (fr6 = -1)
        check(got == sat_model(xp, -1.0, k, 255),
              'index 0x009 == sat8(((x - 1) + 1) / 0.0078125), each step truncated toward zero')
        if 0.0 < x < 0.5:
            check(Fraction(f_sub(xp, -1.0)) == Fraction(math.ceil(Fraction(x) * 2 ** 24), 2 ** 24),
                  "0 < x < 0.5: x' = (x - 1) - (-1) is exactly x rounded UP to a multiple of 2^-24")
        simple = sat_model(x, 0.0, k, 255)
        if x >= 0.0:
            check(simple == min(255, math.floor(Fraction(x) / K + Fraction(1, 2))),
                  'x >= 0: sat8(x / 0.0078125) under truncation is exactly min(255, floor(x / k + 0.5))')
        if got == simple:
            return 0
        check(0.0 < x < 0.5 and got == simple + 1 and 0.0 < bnd_exact - x < 2.0 ** -24,
              'index 0x009 vs sat8(x / k): differs only for 0 < x < 0.5, less than 2^-24 BELOW a boundary, ROM one count higher')
        return 1

    # W: complete window
    nw = dw = 0
    example = None
    per_cnt = collections.Counter()
    for cnt in range(1, 257):
        bexact = (cnt - 0.5) * k
        lo, hi = E.f2b(r32(bexact - 2.0 ** -24)), E.f2b(r32(bexact + 2.0 ** -24))
        for bits in range(lo, hi + 1):
            x = E.b2f(bits)
            got = rom_009(x)
            nw += 1
            d = judge(x, got, bexact)
            dw += d
            per_cnt[cnt] += d
            if d and example is None:
                example = (x, got, sat_model(x, 0.0, k, 255))
    check(nw == 1536, f'complete window: {nw} float32 inputs within 2^-24 of the 256 boundaries')
    check(dw == 576, f'index 0x009 differs from sat8(x / 0.0078125) for exactly {dw} float32 inputs (all of them in the window)')
    want_cnt = {}
    for cnt in range(1, 257):
        b = Fraction(2 * cnt - 1, 256)
        e2 = 0
        while Fraction(2) ** e2 >= b:
            e2 -= 1
        while Fraction(2) ** (e2 + 1) < b:
            e2 += 1                                          # now 2^e2 < b <= 2^(e2+1): spacing below b is 2^(e2-23)
        want_cnt[cnt] = int(Fraction(1, 2 ** 24) / Fraction(2) ** (e2 - 23)) - 1 if b < Fraction(1, 2) else 0
    check(dict(per_cnt) == want_cnt and sum(want_cnt.values()) == 576,
          'per boundary: 2^-24 / ulp(below b) - 1 differing inputs (255, 63, 31, 31, 15 x4, 7 x8, 3 x16, 1 x32; 0 above 0.5)')
    below1 = [u for u in range(1, 300)
              if rom_009(_next_f32(0.5 * k, -u)) != sat_model(_next_f32(0.5 * k, -u), 0.0, k, 255)]
    check(below1 == list(range(1, 256)),
          'count-1 boundary: the inputs 1 .. 255 floats below it differ (255 of the 576); 256 floats = 2^-24')

    # P: the first version's grid (the count the reviewer reproduced)
    n = dp = 0
    for cnt in range(0, 257):
        bnd = r32((cnt - 0.5) * k)
        for u in range(-40, 41):
            x = _next_f32(bnd, u) if bnd > 0 else r32(u * k / 64.0)
            got = rom_009(x)
            n += 1
            dp += judge(x, got, (cnt - 0.5) * k)
            # the neighbour at index 0x00A has no such double step
            if cnt and u in (-1, 0, 1):
                y = _next_f32(bnd, u)
                e = Emu2()
                e.fill(0)
                e.poke(0xFFFF7878, 4, E.f2b(r32(y - 1.0)))
                e.call(0x05D2DA, regs={4: 10})
                check((e.R[0] & 0xFF) == sat_model(r32(y - 1.0), -1.0, k, 255),
                      'index 0x00A == sat8((x + 1) / 0.0078125) at the rounding boundaries')
    check(n == 20817 and dp == 338, f'first-version grid: {dp} of {n} probes differ (the 40-float window misses some)')
    # beyond 40 floats below the count-1 boundary there are still differences
    x41 = _next_f32(0.5 * k, -41)
    check(rom_009(x41) == 1 and sat_model(x41, 0.0, k, 255) == 0,
          'x 41 floats below the count-1 boundary still differs (outside the first-version grid)')
    return nw, dw, n, dp, example


EXTREME_F32 = [float('nan'), float('inf'), float('-inf'), 3.4e38, -3.4e38, 2.0 ** 31, -3.0e9, 1e10, -1e10]


def extreme_floats():
    """Every formula getter with a float input, re-run with NaN / +-Inf / +-3.4e38 / values
    outside int32 in its float inputs.  This checks the FORMULA STRUCTURE under those values
    with the emulator's ftrc rule (see sat_model); it says nothing about what silicon returns."""
    n = 0
    done = set()
    for idx in range(N):
        g = GET_INFO[idx]
        fl = [a for a, k in g['leaves'] if k == 'f32']
        if g['kind'] != 'formula' or not fl or (A[idx], tuple(fl)) in done:
            continue
        done.add((A[idx], tuple(fl)))
        for v in EXTREME_F32:
            for which in [fl] + ([[a] for a in fl] if len(fl) > 1 else []):
                def setup(e, which=which, v=v):
                    e.fill(0)
                    for a in fl:
                        e.poke(a, 4, E.f2b(1.5))
                    for a in which:
                        e.poke(a, 4, E.f2b(v))
                got, e = run_getter(A[idx], idx, setup)
                want = ev(g['expr'], lambda a, k: e.peek(a, k) if a >= RAM_LO else int.from_bytes(rom[a:a + k], 'big'))
                check(got == want, f'getter[{idx:#05x}] with float input {v!r}: formula still matches the emulator')
                n += 1
    for v in EXTREME_F32:                               # the one dynamic getter with a float input
        def setup(e, v=v):
            e.fill(0)
            e.poke(0xFFFF9094, 4, E.f2b(v))
        got, e = run_getter(0x05DA88, 0x66, setup)
        check(got == _g_66(e.peek), f'getter 05DA88 with f32[FFFF9094] = {v!r}')
        n += 1
    return n


# =====================================================================================
# E. helpers
# =====================================================================================
def helpers():
    n = 0
    xs = [-1e6, -300.0, -41.0, -40.0, -39.51, -39.5, -0.6, -0.5, -0.49, 0.0, 0.49, 0.5, 0.51, 1.0, 1.49, 1.5,
          127.5, 254.4, 254.5, 255.0, 255.5, 256.0, 1000.0, 16383.6, 16383.8, 65534.5, 65535.4, 70000.0, 1e6]
    for helper, maxv in ((HELPER_SAT8, 255), (HELPER_SAT16, 65535)):
        for off in (0.0, -40.0, -1.0, 64.0, 2.5):
            for scale in (1.0, 0.25, 0.0078125, 0.01, 2.0, 0.39215687, 0.005):
                for x in xs:
                    e = Emu2()
                    e.call(helper, fregs={4: x, 5: scale, 6: off})
                    want = sat_model(r32(x), r32(off), r32(scale), maxv)
                    check(e.R[0] == want, f'{helper:06X}(x={x},scale={scale},off={off}) = {want}')
                    n += 1
    for helper, bits in ((HELPER_U16F, 16), (HELPER_U8F, 8)):
        for raw in (0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF, 0x12345):
            for k, c in ((1.0, 0.0), (0.00390625, 0.0), (0.005, -1.0), (2.0, 3.5)):
                e = Emu2()
                e.call(helper, regs={4: raw}, fregs={4: k, 5: c})
                # 0x0BE590 / 0x0BE5A0: fmac fr0,fr3,fr5 -- k * float(raw) + c rounded ONCE toward zero.
                # 7 of these 80 cases (k = 0.005, c = -1) differ if fmac were unfused (fmul, fadd):
                # fused is the emulator's rule and is NOT settled by the ROM self-test.
                want = f_mac(r32(k), f_float(raw & ((1 << bits) - 1)), r32(c))
                check(e.fr(0) == want, f'{helper:06X}(raw={raw:#x},k={k},c={c}) = {want}')
                n += 1
    for b in range(256):
        e = Emu2()
        e.call(0x0BE9A0, regs={4: b | 0xABCD00})
        check(e.R[0] == ((b << 8) | (~b & 0xFF)), '0BE9A0 packs byte and its complement')
        n += 1
    for k in (0, 1, 0x1F, 0x80, 0xFF):
        for helper, base, mul in ((0x05850E, 0xFFFFAD52, 1), (0x058518, 0xFFFF3B06, 2)):
            e = Emu2()
            e.fill(0)
            e.poke(base + mul * k, 1, 0xC3)
            e.call(helper, regs={4: k | 0x5500})
            check(e.R[0] == 0xC3, f'{helper:06X}(k={k}) reads u8[{base:08X} + {mul}*k]')
            n += 1
    # NaN / infinities / beyond int32 through the two saturating helpers (emulator ftrc rule)
    for helper, maxv in ((HELPER_SAT8, 255), (HELPER_SAT16, 65535)):
        for x in EXTREME_F32:
            for off, scale in ((0.0, 1.0), (-1.0, 0.0078125), (64.0, 0.5)):
                e = Emu2()
                e.call(helper, fregs={4: x, 5: scale, 6: off})
                want = sat_model(r32(x), r32(off), r32(scale), maxv)
                check(e.R[0] == want, f'{helper:06X}(x={x!r},scale={scale},off={off}) = {want} (emulator ftrc rule)')
                n += 1
    # 0x003BF4 (the shift 0x09CAEA uses for its mode mask): r0 << r1 for 0 <= r1 <= 31, 0 for r1 >= 32,
    # r0 unchanged for r1 < 0 (signed); r2 preserved.  Computed jmp into a ladder of `shll r0`.
    for cnt in list(range(-3, 45)) + [0x80, 0xFF, -128]:
        for v in (1, 0x80000001, 0x12345678, 0xFFFFFFFF):
            e = Emu2()
            e.call(0x003BF4, regs={0: v, 1: cnt & M32, 2: 0xCAFEBABE})
            want = v if cnt < 0 else ((v << cnt) & M32 if cnt < 32 else 0)
            check(e.R[0] == want and e.R[2] == 0xCAFEBABE, f'003BF4(r0={v:#x}, r1={cnt}) = {want:#x}')
            n += 1
    # the two one-flag readers getter 0x05E2EA (index 0x120) calls: r0 = (u8[addr] == 1)
    for helper, addr in ((0x02E7D8, 0xFFFF7234), (0x02E7E2, 0xFFFF7235)):
        for v in range(256):
            e = Emu2()
            e.fill(0)
            e.poke(addr, 1, v)
            e.call(helper, regs={0: 0xDEAD0000})
            check(e.R[0] == int(v == 1) and not e.ram_writes(), f'{helper:06X}: r0 = (u8[{addr:08X}] == 1)')
            n += 1
    # 0x05F2FC (called by the parser 0x05F08C on its 0xA0 and 0xA8 branches):
    # bit 15 of the flags word := bit 0 of u8[0xFFFF8F42]; the other 15 bits are kept
    for v in range(256):
        for fl in (0x0000, 0xFFFF, 0x1234, 0x8000, 0x7FFF):
            e = Emu2()
            e.fill(0)
            e.poke(0xFFFF8F42, 1, v)
            e.poke(FLAGS, 2, fl)
            e.call(0x05F2FC)
            check(e.peek(FLAGS, 2) == ((fl & 0x7FFF) | ((v & 1) << 15)) and set(e.ram_writes()) <= {FLAGS, FLAGS + 1},
                  '05F2FC: flags bit 15 = bit 0 of u8[FFFF8F42], nothing else changes')
            n += 1
    return n


# =====================================================================================
# F. dispatch sites
# =====================================================================================
FLAGS, IDXW, POS, OUT, PTR, VALB = 0xFFFF9048, 0xFFFF8F28, 0xFFFF8F3B, 0xFFFF903C, 0xFFFF9044, 0xFFFF8F3C
UBREG = 0xFFFFEC0A


def seeded(e):
    e.fill(0)
    for i in range(0, 0xBD00):
        e.ram[i] = (i * 73 + 41) & 0xFF
    # make the float inputs used by the sampled getters sane
    for a, kind in SAMPLE_F32:
        e.poke(a, 4, E.f2b(37.25))


SAMPLE_F32 = []
SAMPLE_IDX = [0x000, 0x001, 0x006, 0x008, 0x00E, 0x00F, 0x01C, 0x060, 0x061, 0x08E, 0x0AE, 0x10F, 0x1C5, 0x200,
              0x203, 0x34F]


def direct_get(idx, r4=None):
    return run_getter(A[idx], idx, seeded, r4=r4)[0]


def site_05F718():
    rows = []
    for idx in SAMPLE_IDX:
        for pos, flags in ((0, 0x0040), (3, 0x1050)):
            e = Emu2()
            seeded(e)
            e.poke(FLAGS, 2, flags); e.poke(IDXW, 2, idx); e.poke(POS, 1, pos)
            e.poke(OUT, 4, 0x11223344)
            e.call(0x05F718)
            got = e.peek(OUT + pos, 1)
            want = direct_get(idx)
            check(got == want, f'05F718 flags={flags:#06x} idx={idx:#05x}: out[{pos}] == getter[idx](r4=idx)')
            check(e.peek(FLAGS, 2) == flags & ~0x40, '05F718 clears flag bit 6 and nothing else')
            rows.append((idx, pos, flags, got))
    # direct-memory path and the 0xFF default
    for flags, want in ((0x0010, 0x5A), (0x0000, 0xFF), (0x0020, 0xFF), (0x0080, 0xFF)):
        e = Emu2()
        seeded(e)
        e.poke(FLAGS, 2, flags); e.poke(IDXW, 2, 0x08); e.poke(POS, 1, 2)
        e.poke(PTR, 4, 0xFFFF6000); e.poke(0xFFFF6000, 1, 0x5A)
        e.call(0x05F718)
        check(e.peek(OUT + 2, 1) == want, f'05F718 flags={flags:#06x}: out == {want:#04x}')
        check(e.peek(FLAGS, 2) == flags, '05F718 leaves flags alone when bit 6 is clear')
        rows.append(('-', 2, flags, want))
    return rows


def site_05F758():
    rows = []
    setter_cases = [(i, B[i]) for i in (0x000, 0x060, 0x083, 0x070, 0x06F, 0x008, 0x0DD)]
    for idx, tgt in setter_cases:
        for flags in (0x0040, 0x00C0):
            e = Emu2()
            e.fill(0)
            e.periph[UBREG] = 0x0000
            e.poke(FLAGS, 2, flags); e.poke(IDXW, 2, idx); e.poke(VALB, 1, 0xA5)
            e.call(0x05F758)
            wr = {a: v for a, v in e.ram_writes().items()}
            ref = Emu2(); ref.fill(0); ref.call(tgt, regs={4: sext(0xA5, 8) & M32})
            check(wr == ref.ram_writes(), f'05F758 idx={idx:#05x}: same RAM writes as setter[idx](r4=sext8(0xA5))')
            check(e.peek(FLAGS, 2) == flags, '05F758 does not modify the flags word')
            pw = [v for a, n, v in e.plog if a == UBREG]
            check(pw == ([1, 0] if flags & 0x80 else [0]), f'05F758 periph {UBREG:08X} writes {pw} for flags {flags:#06x}')
            check(e.srlog[0] == ('0BE81C', E.STACK_TOP - 12 - 8, 0xE0) and e.srlog[-1] == ('0BE82C', 0xB0),
                  '05F758 brackets the write with 0BE81C(sp,0xE0) / 0BE82C(saved)')
            rows.append((idx, tgt, flags, ' '.join(f'{a:08X}={v:02X}' for a, v in sorted(wr.items())) or '-'))
    # direct-memory write path (bit 5) and nothing (no bits)
    for flags, want in ((0x0020, 0xA5), (0x0000, 0x00), (0x0010, 0x00)):
        e = Emu2(); e.fill(0)
        e.poke(FLAGS, 2, flags); e.poke(IDXW, 2, 0x60); e.poke(VALB, 1, 0xA5); e.poke(PTR, 4, 0xFFFF6001)
        e.call(0x05F758)
        check(e.peek(0xFFFF6001, 1) == want and set(e.ram_writes()) <= {0xFFFF6001},
              f'05F758 flags={flags:#06x}: u8[ptr] == {want:#04x}, no other RAM write')
        rows.append(('-', 0, flags, f'FFFF6001={e.peek(0xFFFF6001, 1):02X}'))
    return rows


def site_05F316():
    rows = []
    # ---- flag 0x0400: write-then-read-back of one table index
    for idx, val in ((0x060, 0x37), (0x000, 0x81), (0x083, 0x10), (0x008, 0x22), (0x34F, 0x01)):
        e = Emu2(); seeded(e)
        e.poke(FLAGS, 2, 0x0400)
        e.poke(0xFFFF8F43, 1, idx >> 8); e.poke(0xFFFF8F44, 1, idx & 0xFF); e.poke(0xFFFF8F45, 1, val)
        e.poke(POS, 1, 1)
        e.call(0x05F316)
        ref = Emu2(); seeded(ref); ref.call(B[idx], regs={4: sext(val, 8) & M32})
        ref2 = Emu2(); ref2.ram[:] = ref.ram; ref2.call(A[idx], regs={4: idx})
        check(e.peek(IDXW, 2) == idx and e.peek(VALB, 1) == val, '05F316/0x0400 latches index word and value byte')
        check(e.peek(OUT + 1, 1) == ref2.R[0] & 0xFF,
              f'05F316/0x0400 idx={idx:#05x}: out[pos] == getter[idx] evaluated AFTER setter[idx](val)')
        check(e.peek(FLAGS, 2) == 0x0400, '05F316/0x0400: bit 6 set then cleared again by 05F718')
        rows.append(('0400', idx, val, e.peek(OUT + 1, 1)))
    # ---- flag 0x1000: list of 3-byte addresses, table for addr < 848, memory otherwise
    reqs = [0x000008, 0x00000E, 0xFF6000, 0x00034F]
    e = Emu2(); seeded(e)
    e.poke(FLAGS, 2, 0x1000)
    e.poke(0xFFFF8F38, 1, 0)                         # running address counter
    e.poke(0xFFFF8F3A, 1, len(reqs) + 1)             # count + 1
    e.poke(0xFFFF8F42, 1, 0x00)                      # request byte whose bit 1 forces the memory path
    for i, a in enumerate(reqs):
        e.poke(0xFFFF8F43 + 3 * i, 3, a)
    e.poke(0xFFFF6000, 1, 0x5A)
    e.poke(0xFFFF8F0B, 1, 0x00)
    e.call(0x05F316)
    want = [direct_get(0x008), direct_get(0x00E), 0x5A, direct_get(0x34F)]
    got = [e.peek(OUT + i, 1) for i in range(4)]
    check(got == want, f'05F316/0x1000: out[0..3] == {want} (table, table, RAM byte, table)')
    rows.append(('1000', 'addr list', ' '.join(f'{a:06X}' for a in reqs), ' '.join(f'{v:02X}' for v in got)))
    # same request with bit 1 of 0xFFFF8F42 set: the table is bypassed even for addr < 848
    e = Emu2(); seeded(e)
    e.poke(FLAGS, 2, 0x1000); e.poke(0xFFFF8F38, 1, 0); e.poke(0xFFFF8F3A, 1, 2)
    e.poke(0xFFFF8F42, 1, 0x02); e.poke(0xFFFF8F43, 3, 0x000008)
    e.call(0x05F316)
    check(e.peek(PTR, 4) == 0x00000008, '05F316/0x1000 with 0xFFFF8F42 bit 1 set: addr 0x000008 is NOT a table index')
    rows.append(('1000', 'bit1 set', '000008', f'ptr={e.peek(PTR, 4):08X} out0={e.peek(OUT, 1):02X}'))
    return rows


def site_09A710():
    rows = []
    for v in (0x60, 0x00, 0x5F, 0x61, 0x34F, 0x6000, 0x10060):
        e = Emu2()
        e.call(0x09A710, regs={4: v})
        want = 0 if v == 0x60 else 1
        check(e.R[0] == want, f'09A710({v:#x}) == {want}')
        rows.append((v, e.R[0]))
    check(L(0x09CA0C) == 0x60, 'whitelist 0x09CA0C has the single entry 0x00000060')
    return rows


def site_09CAEA():
    """Service dispatcher: record tables 0x09B778 / 0x09B88C of {id byte, 3 pad, handler, mask}."""
    rows = []

    def recs(base):
        out, a = [], base
        while rom[a] != 0xFF:
            out.append((rom[a], L(a + 4), L(a + 8)))
            a += 12
        return out
    full, reduced = recs(0x09B778), recs(0x09B88C)
    check(dict((i, h) for i, h, m in full).get(0xA8) == 0x09A3AC and dict((i, h) for i, h, m in full).get(0xB8) == 0x09A628,
          'table 0x09B778: id 0xA8 -> 0x09A3AC, id 0xB8 -> 0x09A628')
    check(0xA8 not in [i for i, h, m in reduced] and dict((i, h) for i, h, m in reduced).get(0xB8) == 0x09A628,
          'table 0x09B88C: has id 0xB8 -> 0x09A628 and no id 0xA8')
    cases = [(0xA8, 7, 1, 0, (0x09A3AC, 0)), (0xB8, 4, 1, 0, (0x09A628, 0)), (0xA8, 7, 0, 0, (None, 1)),
             (0xB8, 4, 0, 0, (0x09A628, 0)), (0xA8, 7, 1, 1, (None, 2)), (0x55, 7, 1, 0, (None, 1))]
    for sid, ln, arg3, mode, (want_h, want_r) in cases:
        e = Emu2(); e.fill(0); e.poke(0xFFFFB450, 1, mode)
        seen = []
        for h in {h for _, h, _ in full}:
            e.stub(h, fn=lambda em, h=h: seen.append((h, em.R[4], em.R[5])))
        e.call(0x09CAEA, regs={4: sid, 5: ln, 6: arg3})
        check(e.R[0] == want_r and seen == ([(want_h, ln, arg3)] if want_h else []),
              f'09CAEA(id={sid:#04x}, len={ln}, arg3={arg3}) mode byte {mode}: handler {want_h}, returns {want_r}')
        rows.append((f'id={sid:02X} len={ln} arg3={arg3} u8[FFFFB450]={mode}',
                     f'handler={seen[0][0]:06X}(r4={seen[0][1]}, r5={seen[0][2]})' if seen else 'no handler', f'r0={e.R[0]}'))
    return rows, full, reduced


def pairing():
    """Every setter that writes RAM writes a location the getter at the SAME index reads."""
    rows = []
    for i in range(N):
        t = B[i]
        if t == 0x05E76A:
            continue
        wr = sorted({a for v in SET_INFO[t]['writes'] for a in SET_INFO[t]['writes'][v]})
        rd = set()
        for a, k in GET_INFO[i]['leaves']:
            nb = {'u8': 1, 's8': 1, 'u16': 2, 's16': 2, 'u32': 4, 'f32': 4}.get(k, 1)
            rd |= set(range(a, a + nb))
        if wr:
            check(bool(set(wr) & rd), f'index {i:#05x}: setter {t:06X} writes RAM that getter {A[i]:06X} reads')
        rows.append((i, t, A[i], bool(wr), sorted(set(wr) & rd) == wr))
    return rows


def io_stubs(e, req, log):
    def fetch(em):
        log.append(('09D052', em.R[4] & 0xFF, em.R[5]))
        for i, b in enumerate(req):
            em.write(em.R[5] + i, 1, b)

    def put(em):
        n = em.R[6] & 0xFFFF
        a = em.R[5]
        data = bytes(em.read(a + i, 1) for i in range(n))
        log.append(('09CFEE', em.R[4] & 0xFF, a, data.hex()))

    def nak(em):
        log.append(('098686', em.R[4] & 0xFF, em.R[5] & 0xFF, em.R[6] & 0xFF))

    def send(em):
        log.append(('09CABE',) + tuple(em.read(em.R[4] + 4 * i, 4) for i in range(4)))
    e.stub(0x09D052, fn=fetch)
    e.stub(0x09CFEE, fn=put)
    e.stub(0x098686, fn=nak)
    e.stub(0x09CABE, fn=send)


def site_09A628():
    rows = []
    cases = [
        ('len 3', 3, [0, 0, 0x60, 0x37], ('nak', 0x13)),
        ('len 5', 5, [0, 0, 0x60, 0x37], ('nak', 0x13)),
        ('idx 0x350', 4, [0, 3, 0x50, 0x37], ('nak', 0x22)),
        ('idx 0x010060', 4, [1, 0, 0x60, 0x37], ('nak', 0x22)),
        ('idx 0x008 (not whitelisted)', 4, [0, 0, 0x08, 0x37], ('nak', 0x22)),
        ('idx 0x000 (has a setter, not whitelisted)', 4, [0, 0, 0x00, 0x37], ('nak', 0x22)),
        ('idx 0x060 v=0x37', 4, [0, 0, 0x60, 0x37], ('ok', 0x37)),
        ('idx 0x060 v=0x00', 4, [0, 0, 0x60, 0x00], ('ok', 0x00)),
        ('idx 0x060 v=0xFF', 4, [0, 0, 0x60, 0xFF], ('ok', 0xFF)),
    ]
    for name, ln, req, (kind, arg) in cases:
        e = Emu2(); e.fill(0); log = []
        io_stubs(e, req, log)
        e.call(0x09A628, regs={4: ln})
        wr = e.ram_writes()
        if kind == 'nak':
            check(log[-1] == ('098686', 0xB8, arg, 2), f'09A628 {name}: 098686(0xB8, {arg:#04x}, 2)')
            check(not wr, f'09A628 {name}: no RAM written')
        else:
            idx = (req[0] << 16) | (req[1] << 8) | req[2]
            ref = Emu2(); ref.fill(0); ref.call(B[idx], regs={4: arg})
            sw = ref.ram_writes()
            check({a: v for a, v in wr.items() if a not in (0xFFFFB44C, 0xFFFFB44D)} == sw,
                  f'09A628 {name}: RAM writes == setter[idx](v) plus the reply-length word')
            check(e.peek(0xFFFFB44C, 2) == 2, '09A628 ok: u16[FFFFB44C] = 2')
            puts = [x for x in log if x[0] == '09CFEE']
            check(puts[0][1] == 0xB8 and puts[0][3] == f'f8{arg:02x}', f'09A628 {name}: reply bytes F8 {arg:02X}')
            check(puts[1][1:] == (0xB8, 0x09B770, rom[0x09B770:0x09B778].hex()), '09A628 ok: second put is 8 bytes of ROM 0x09B770')
            check(log[-1] == ('09CABE', 0xB8, 2, 0, 0), '09A628 ok: 09CABE({0xB8, 2, 0, 0})')
        rows.append((name, ln, bytes(req).hex(), log[-1], ' '.join(f'{a:08X}={v:02X}' for a, v in sorted(wr.items())) or '-'))
    # a forced read-back mismatch: make getter[0x60] return something else by stubbing it
    e = Emu2(); e.fill(0); log = []
    io_stubs(e, [0, 0, 0x60, 0x37], log)
    e.stub(A[0x60], r0=0x36)
    e.call(0x09A628, regs={4: 4})
    check(log[-1] == ('098686', 0xB8, 0x22, 2), '09A628: read-back != value -> 098686(0xB8, 0x22, 2)')
    rows.append(('idx 0x060, getter forced to 0x36', 4, '00006037', log[-1], 'setter ran'))
    # the read-back getter is called with r4 = 0, not the index
    seen = {}
    e = Emu2(); e.fill(0); log = []
    io_stubs(e, [0, 0, 0x60, 0x37], log)
    e.stub(A[0x60], fn=lambda em: seen.update(r4=em.R[4]), r0=0x37)
    seen2 = {}
    e.stub(B[0x60], fn=lambda em: seen2.update(r4=em.R[4]))
    e.call(0x09A628, regs={4: 4})
    check(seen == {'r4': 0} and seen2 == {'r4': 0x37}, '09A628: setter gets r4 = value byte (zero-extended), read-back getter gets r4 = 0')
    return rows


def site_09A3AC():
    rows = []
    BUF, OUTB = 0xFFFFB2F6, 0xFFFFB3F4

    def run(req, ln=None):
        e = Emu2(); seeded(e); log = []
        e.poke(0xFFFF6000, 4, 0x5A6B7C8D)
        io_stubs(e, req, log)
        e.call(0x09A3AC, regs={4: len(req) if ln is None else ln})
        return e, log

    # three table indices
    idxs = [0x008, 0x00E, 0x00F, 0x08E, 0x34F]
    req = [0x00] + [b for i in idxs for b in (0, i >> 8, i & 0xFF)]
    e, log = run(req)
    want = [direct_get(i) for i in idxs]
    got = [e.peek(OUTB + i, 1) for i in range(len(idxs))]
    check(log[0] == ('09D052', 0xA8, BUF), '09A3AC fetches the request with 09D052(0xA8, 0xFFFFB2F6)')
    check(got == want, f'09A3AC table read: bytes at FFFFB3F4.. == getter[idx](r4=idx) for {[hex(i) for i in idxs]}')
    check(e.peek(0xFFFFB3F3, 1) == 0xE8 and e.peek(0xFFFFB2F4, 2) == len(idxs) + 1, '09A3AC ok: E8 at FFFFB3F3, length word n+1')
    check(log[-1] == ('09CABE', 0xA8, len(idxs) + 1, 0, 0), '09A3AC ok: 09CABE({0xA8, n+1, 0, 0})')
    rows.append(('table x5', bytes(req).hex(), ' '.join(f'{v:02X}' for v in got), log[-1]))
    # index out of range
    for a in (0x000350, 0x010008, 0x7F0008, 0x800008, 0xF30008):
        req = [0x00, a >> 16, (a >> 8) & 0xFF, a & 0xFF]
        e, log = run(req)
        check(log[-1] == ('098686', 0xA8, 0x12, 2), f'09A3AC addr {a:06X}: 098686(0xA8, 0x12, 2)')
        rows.append((f'addr {a:06X}', bytes(req).hex(), '-', log[-1]))
    # top byte FF / F2 / F4 bypasses the table: 1 / 2 / 4 bytes at 0xFFFFxxxx (here an address in RAM;
    # site_09A3AC_tagged shows the address is not limited to RAM and the reply is not bounded)
    for top, nb in ((0xFF, 1), (0xF2, 2), (0xF4, 4)):
        req = [0x00, top, 0x60, 0x00]
        e, log = run(req)
        got = [e.peek(OUTB + i, 1) for i in range(nb)]
        check(got == [0x5A, 0x6B, 0x7C, 0x8D][:nb], f'09A3AC addr {top:02X}6000: {nb} byte(s) of RAM FFFF6000')
        check(e.peek(0xFFFFB2F4, 2) == nb + 1, f'09A3AC addr {top:02X}6000: length word {nb + 1}')
        rows.append((f'addr {top:02X}6000', bytes(req).hex(), ' '.join(f'{v:02X}' for v in got), log[-1]))
    # bad length (must be 1 + 3n, 4..253)
    for ln in (3, 5, 6, 254):
        e, log = run([0x00, 0, 0, 8, 0, 0, 8], ln=ln)
        check(log[-1] == ('098686', 0xA8, 0x13, 2), f'09A3AC length {ln}: 098686(0xA8, 0x13, 2)')
        rows.append((f'len {ln}', '-', '-', log[-1]))
    # ... and the request is fetched BEFORE the length is judged (jsr at 0x09A402, test at 0x09A406):
    # 0x09D052 is called with r6 = min(len, 253) for valid and invalid lengths alike
    for ln, want in ((3, 3), (5, 5), (7, 7), (253, 253), (254, 253), (0x1234, 253), (0, 0)):
        e = Emu2(); seeded(e); got = {}
        io_stubs(e, [0x00, 0, 0, 8, 0, 0, 8], [])
        e.stub(0x09D052, fn=lambda em: got.update(r4=em.R[4], r5=em.R[5], r6=em.R[6]))
        e.call(0x09A3AC, regs={4: ln})
        check(got == {'r4': 0xA8, 'r5': BUF, 'r6': want}, f'09A3AC len {ln}: 09D052(0xA8, FFFFB2F6, {want}) is called whatever the length')
    # the byte before the items is never examined: any value gives the same reply
    ref = None
    for b in (0x00, 0x01, 0x02, 0x80, 0xFF):
        e, log = run([b, 0x00, 0x00, 0x08, 0xFF, 0x60, 0x00])
        got = (e.peek(OUTB, 2), log[-1])
        ref = ref or got
        check(got == ref and log[-1][0] == '09CABE', f'09A3AC first request byte {b:#04x}: same reply as for 0x00')
    return rows


def site_09A3AC_tagged():
    """The FF / F2 / F4 path of 0x09A3AC is bounded neither in the address it reads nor in
    the number of bytes it stores (review finding; the first version said "RAM")."""
    rows = []
    OUTB = 0xFFFFB3F4

    def run(req, prep=None):
        e = Emu2(); seeded(e); log = []
        e.poke(0xFFFF6000, 4, 0x5A6B7C8D)
        if prep:
            prep(e)
        io_stubs(e, req, log)
        err = None
        try:
            e.call(0x09A3AC, regs={4: len(req)})
        except E.EmuError as ex:
            err = str(ex)
        return e, log, err

    def periph(e):
        e.periph.update({0xFFFFEC0A: 0xC3, 0xFFFFEC0B: 0x3C, 0xFFFFFFFE: 0x11, 0xFFFFFFFF: 0x22})

    # (1) the address is 0xFFFF0000 | (b1 << 8) | b2 for ANY b1: on-chip register space included
    e, log, err = run([0x00, 0xFF, 0xEC, 0x0A], periph)
    check(err is None and ('P', 0xFFFFEC0A, 1) in e.rlog and e.peek(OUTB, 1) == 0xC3,
          '09A3AC item FF EC 0A: one byte is READ FROM 0xFFFFEC0A (above RAM, on-chip register space) and returned')
    rows.append(('FF EC 0A', 'read of FFFFEC0A', f'{e.peek(OUTB, 1):02X}'))
    e, log, err = run([0x00, 0xF2, 0xEC, 0x0A], periph)
    check(err is None and [x for x in e.rlog if x[0] == 'P'] == [('P', 0xFFFFEC0A, 1), ('P', 0xFFFFEC0B, 1)]
          and e.peek(OUTB, 2) == 0xC33C, '09A3AC item F2 EC 0A: two BYTE reads, 0xFFFFEC0A then 0xFFFFEC0B')
    rows.append(('F2 EC 0A', 'reads of FFFFEC0A, FFFFEC0B', f'{e.peek(OUTB, 2):04X}'))
    # (2) b1 = 0xC0: first address above RAM (0xFFFFC000) -- the emulator has nothing mapped there
    e, log, err = run([0x00, 0xFF, 0xC0, 0x00])
    check(err is not None and '0xffffc000' in err and '09A44C' in err,
          '09A3AC item FF C0 00: the read at 0x09A44C addresses 0xFFFFC000 (unmapped in the emulator)')
    rows.append(('FF C0 00', 'read of FFFFC000', 'emulator: ' + err))
    # (3) no upper bound either: F4 at 0xFFFFFFFE runs past the top of the address space into ROM 0
    e, log, err = run([0x00, 0xF4, 0xFF, 0xFE], periph)
    check(err is None and bytes(e.peek(OUTB + i, 1) for i in range(4)) == bytes([0x11, 0x22, rom[0], rom[1]]),
          '09A3AC item F4 FF FE: bytes from 0xFFFFFFFE, 0xFFFFFFFF, 0x00000000, 0x00000001 (r1 post-increment wraps)')
    rows.append(('F4 FF FE', 'FFFFFFFE FFFFFFFF 00000000 00000001', bytes(e.peek(OUTB + i, 1) for i in range(4)).hex()))
    # (4) the store pointer r10 is never compared with anything: n x F4 stores 4n bytes from 0xFFFFB3F4
    for nitems, last, hit in ((22, 0xFFFFB44B, ''), (23, 0xFFFFB44F, 'u16[FFFFB44C]'), (24, 0xFFFFB453, 'u8[FFFFB450]'),
                              (25, 0xFFFFB457, 'u16[FFFFB454], u16[FFFFB456]'), (84, 0xFFFFB543, 'ring data')):
        def prep(e):
            for a in range(OUTB, OUTB + 0x200):
                e.poke(a, 1, 0xEE)
        e, log, err = run([0x00] + [0xF4, 0x60, 0x00] * nitems, prep)
        wr = sorted(a for a in e.ram_writes() if a >= OUTB)
        check(err is None and wr == list(range(OUTB, last + 1)) and
              all(e.peek(a, 1) == (0x5A, 0x6B, 0x7C, 0x8D)[(a - OUTB) % 4] for a in wr),
              f'09A3AC {nitems} x F4: {4 * nitems} reply bytes stored at FFFFB3F4..{last:08X}')
        check(e.peek(0xFFFFB2F4, 2) == 4 * nitems + 1 and log[-1] == ('09CABE', 0xA8, 4 * nitems + 1, 0, 0),
              f'09A3AC {nitems} x F4: reply length word {4 * nitems + 1} (not limited to a byte)')
        check((e.peek(0xFFFFB44C, 2) != 0xEEEE) == (nitems >= 23) and (e.peek(0xFFFFB450, 1) != 0xEE) == (nitems >= 24)
              and (e.peek(0xFFFFB454, 4) != 0xEEEEEEEE) == (nitems >= 25),
              f'09A3AC {nitems} x F4: overwrites {hit or "nothing beyond 0xFFFFB44B"}')
        rows.append((f'{nitems} x F4', f'FFFFB3F4..{last:08X}', hit or '-'))
    # (5) the largest request the length rule admits: 253 bytes = 84 items
    check(run([0x00] + [0xF4, 0x60, 0x00] * 84)[1][-1][0] == '09CABE' and
          run([0x00] + [0xF4, 0x60, 0x00] * 85)[1][-1] == ('098686', 0xA8, 0x13, 2),
          '09A3AC: 84 items (len 253) accepted, 85 items (len 256) refused')
    # (6) the untagged (table) path stores exactly one byte per item: 84 items -> FFFFB3F4..FFFFB447
    e, log, err = run([0x00] + [0x00, 0x00, 0x08] * 84)
    wr = sorted(a for a in e.ram_writes() if a >= OUTB)
    check(wr == list(range(OUTB, OUTB + 84)), '09A3AC 84 table items: 84 reply bytes, FFFFB3F4..FFFFB447')
    return rows


def site_05F08C():
    """The request parser of the second path, branches 0xA8 / 0xB8 / unknown."""
    rows = []
    CLR = 0x0001 | 0x0008 | 0x0100 | 0x0200 | 0x0400 | 0x0800 | 0x1000

    def run(service, n40, data, flags):
        e = Emu2(); e.fill(0)
        e.poke(0xFFFF8F41, 1, service); e.poke(0xFFFF8F40, 1, n40)
        for i, b in enumerate(data):
            e.poke(0xFFFF8F42 + i, 1, b)
        e.poke(FLAGS, 2, flags)
        e.gbr = 0x12345678
        e.call(0x05F08C)
        check(e.gbr == 0x12345678, '05F08C restores GBR')
        return e
    # 0xA8: bit 12 set; bit 15 := bit 0 of the byte before the items (via 0x05F2FC); count byte
    for pad in range(256):
        for n40, fl in ((4, 0x0000), (7, 0xFFFF), (0x0D, 0x8048)):
            e = run(0xA8, n40, [pad, 0, 0, 8], fl)
            want = ((fl & ~CLR) & 0x7FFF) | ((pad & 1) << 15) | 0x1000
            check(e.peek(FLAGS, 2) == want, f'05F08C/0xA8 pad={pad:#04x}: flags == {want:#06x} (bit 15 = pad bit 0, bit 12 set)')
            cnt = int((n40 - 2) / 3) + 1
            check(e.peek(0xFFFF8F3A, 1) == cnt and e.peek(0xFFFF8F36, 1) == 0xE8 and e.peek(0xFFFF8F34, 1) == cnt + 4,
                  f'05F08C/0xA8 u8[FFFF8F40]={n40}: count byte {cnt}, reply id 0xE8, u8[FFFF8F34] = count + 4')
    rows.append(('A8', 'pad 0..255 x 3 (count, flags) cases', 'flags bit15 = pad bit0, bit12 = 1'))
    # 0xB8: only the bound
    for idx, ok in ((0x000060, True), (0x000000, True), (0x00034F, True), (0x000350, False), (0x010060, False),
                    (0xFF0060, False)):
        for fl in (0x0000, 0xFFFF):
            e = run(0xB8, 5, [idx >> 16, (idx >> 8) & 0xFF, idx & 0xFF, 0x37], fl)
            want = ((fl & ~CLR) & 0x7FFF) | (0x0400 if ok else 0x0001)
            check(e.peek(FLAGS, 2) == want, f'05F08C/0xB8 index {idx:#08x}: flags == {want:#06x}')
            if ok:
                check(e.peek(0xFFFF8F3A, 1) == 2 and e.peek(0xFFFF8F36, 1) == 0xF8 and e.peek(0xFFFF8F34, 1) == 6,
                      '05F08C/0xB8 accepted: count byte 2, reply id 0xF8')
        rows.append(('B8', f'index {idx:06X}', 'accepted (flag 0x0400)' if ok else 'refused (flag 0x0001)'))
    e = run(0x55, 5, [0, 0, 0x60, 0x37], 0xFFFE)
    check(e.peek(FLAGS, 2) == ((0xFFFE & ~CLR) & 0x7FFF) | 1, '05F08C unknown service: flags |= 1, bit 15 cleared')
    # parser + executor end to end: a 0xB8 request for an index that has a setter but is NOT in the
    # 0x09CA0C whitelist is carried out on this path
    for idx, val in ((0x083, 0x10), (0x000, 0x81), (0x060, 0x37)):
        e = Emu2(); e.fill(0)
        e.poke(0xFFFF8F41, 1, 0xB8)
        for i, b in enumerate((0, idx >> 8, idx & 0xFF, val)):
            e.poke(0xFFFF8F42 + i, 1, b)
        e.call(0x05F08C)
        e.call(0x05F316)
        ref = Emu2(); ref.fill(0); ref.call(B[idx], regs={4: sext(val, 8) & M32})
        check(ref.ram_writes() and all(e.peek(a, 1) == v for a, v in ref.ram_writes().items()),
              f'05F08C + 05F316, request B8 {idx:06X} {val:02X}: the RAM setter[{idx:#05x}] writes is written')
        rows.append(('B8 end to end', f'index {idx:03X} value {val:02X}',
                     ' '.join(f'{a:08X}={v:02X}' for a, v in sorted(ref.ram_writes().items()))))
    return rows


RING, RING_REC, RING_DATA, RING_ID = 0xFFFFB454, 608, 601, 0xFFFFB6DF


def ring_seed(e, payload, rd, sid, ch=0):
    """Put `payload` into channel `ch` as the unread part of its ring and bind the channel to `sid`."""
    b = RING + RING_REC * ch
    for i, v in enumerate(payload):
        e.poke(b + 6 + (rd + i) % RING_DATA, 1, v)
    mark = (rd + len(payload) - 1) % RING_DATA
    e.poke(b + 2, 2, rd)
    e.poke(b + 4, 2, mark)
    e.poke(b, 2, (mark + 1) % RING_DATA)
    e.poke(RING_ID + 2 * ch, 1, sid)
    return (mark + 1) % RING_DATA


def ring_get(e, start, n, ch=0):
    b = RING + RING_REC * ch
    return bytes(e.peek(b + 6 + (start + i) % RING_DATA, 1) for i in range(n))


def transport():
    """The transport helpers the first version of this script stubbed, run for real.

    channel record at 0xFFFFB454 + 608*n = { u16 write index, u16 read index, u16 mark,
    601 data bytes };  u8[0xFFFFB6DF + 2n] = id the channel is bound to (only n = 0 is scanned).
      0x09D052(id, dst, cnt) -> 0x09CD50(n, dst, cnt): copy cnt bytes out at the read index
      0x09CFEE(id, src, cnt) -> 0x09CCF8(n, src, cnt): append cnt bytes at the write index
      0x09D084(id)           -> 0x09CC44(n):           write index = mark + 1
    Only 0x00DCE4 (the jmp target of 0x09CABE) stays stubbed."""
    rows = []
    n = 0

    # ---- the three leaf routines against Python models
    def model_read(st, cnt):
        out = []
        for _ in range(cnt):
            if st['mark'] + 1 == st['rd'] or (st['mark'] >= 600 and st['rd'] == 0):
                out.append(0)
            else:
                out.append(st['data'][st['rd']])
                st['rd'] += 1
                if st['rd'] >= RING_DATA:
                    st['rd'] = 0
        return out

    def model_write(st, src):
        for b in src:
            if st['mark'] == st['wr']:
                continue
            st['data'][st['wr']] = b
            st['wr'] += 1
            if st['wr'] >= RING_DATA:
                st['wr'] = 0

    def load(e, st, ch):
        b = RING + RING_REC * ch
        e.poke(b, 2, st['wr']); e.poke(b + 2, 2, st['rd']); e.poke(b + 4, 2, st['mark'])
        e.ram[b + 6 - RAM_LO:b + 6 + RING_DATA - RAM_LO] = bytes(st['data'])

    def same(e, st, ch):
        b = RING + RING_REC * ch
        return (e.peek(b, 2), e.peek(b + 2, 2), e.peek(b + 4, 2)) == (st['wr'], st['rd'], st['mark']) and \
            bytes(e.ram[b + 6 - RAM_LO:b + 6 + RING_DATA - RAM_LO]) == bytes(st['data'])

    for ch in (0, 1):
        for wr, rd, mark, cnt in ((10, 0, 9, 4), (10, 0, 9, 10), (10, 0, 9, 14), (5, 598, 4, 9), (0, 595, 600, 8),
                                  (0, 0, 600, 3), (300, 300, 299, 5), (7, 3, 2, 4), (20, 15, 30, 40)):
            st = dict(wr=wr, rd=rd, mark=mark, data=[(i * 37 + 11) & 0xFF for i in range(RING_DATA)])
            e = Emu2(); e.fill(0); load(e, st, ch)
            e.call(0x09CD50, regs={4: ch, 5: 0xFFFF6000, 6: cnt})
            want = model_read(st, cnt)
            check(list(e.ram[0x6000:0x6000 + cnt]) == want and same(e, st, ch),
                  f'09CD50(ch={ch}, cnt={cnt}) from (wr={wr}, rd={rd}, mark={mark}) matches the ring read model')
            n += 1
            st = dict(wr=wr, rd=rd, mark=mark, data=[0] * RING_DATA)
            src = [(i * 5 + 1) & 0xFF for i in range(cnt)]
            e = Emu2(); e.fill(0); load(e, st, ch)
            for i, b in enumerate(src):
                e.poke(0xFFFF6000 + i, 1, b)
            e.call(0x09CCF8, regs={4: ch, 5: 0xFFFF6000, 6: cnt})
            model_write(st, src)
            check(same(e, st, ch), f'09CCF8(ch={ch}, cnt={cnt}) from (wr={wr}, rd={rd}, mark={mark}) matches the ring write model')
            n += 1
            e = Emu2(); e.fill(0); load(e, st, ch)
            e.call(0x09CC44, regs={4: ch})
            st['wr'] = 0 if st['mark'] >= 600 else st['mark'] + 1
            check(same(e, st, ch), f'09CC44(ch={ch}): write index = mark + 1 (0 when mark >= 600)')
            n += 1
    # ---- the id gate of the three wrappers: nothing happens unless u8[0xFFFFB6DF] == id
    for bound_id, ask in ((0xA8, 0xA8), (0xA8, 0xB8), (0x00, 0xA8)):
        e = Emu2(); e.fill(0)
        ring_seed(e, [1, 2, 3, 4], 0, bound_id)
        e.poke(0xFFFF6000, 4, 0xEEEEEEEE)
        e.call(0x09D052, regs={4: ask, 5: 0xFFFF6000, 6: 4})
        check(e.peek(0xFFFF6000, 4) == (0x01020304 if bound_id == ask else 0xEEEEEEEE),
              f'09D052(id={ask:#04x}) with channel bound to {bound_id:#04x}: ' + ('4 bytes copied' if bound_id == ask else 'nothing copied'))
        e = Emu2(); e.fill(0)
        w0 = ring_seed(e, [1, 2, 3, 4], 0, bound_id)
        e.poke(0xFFFF6000, 4, 0xA1B2C3D4)
        e.call(0x09CFEE, regs={4: ask, 5: 0xFFFF6000, 6: 4})
        check(e.peek(RING, 2) == (w0 + 4 if bound_id == ask else w0), f'09CFEE(id={ask:#04x}) with channel bound to {bound_id:#04x}')
        e = Emu2(); e.fill(0)
        ring_seed(e, [1, 2, 3, 4], 0, bound_id)
        e.poke(RING, 2, 77)
        e.call(0x09D084, regs={4: ask})
        check(e.peek(RING, 2) == (4 if bound_id == ask else 77), f'09D084(id={ask:#04x}) with channel bound to {bound_id:#04x}')
        n += 3
    tail = rom[0x09B770:0x09B778]

    def handler(entry, sid, req, ln=None, rd=17, pre=None):
        e = Emu2(); seeded(e)
        e.poke(0xFFFF6000, 4, 0x5A6B7C8D)
        w0 = ring_seed(e, req, rd, sid)
        sub = []
        e.stub(0x00DCE4, fn=lambda em: sub.append((em.R[4], em.R[5]) + tuple(em.read(em.R[6] + 4 * i, 4) for i in range(4))))
        if pre:
            pre(e)
        e.call(entry, regs={4: len(req) if ln is None else ln})
        w1 = e.peek(RING, 2)
        return e, ring_get(e, w0, (w1 - w0) % RING_DATA), sub, e.peek(RING + 2, 2)

    # ---- 0x09A3AC with the real transport
    idxs = [0x008, 0x00E, 0x00F, 0x08E, 0x34F]
    req = [0x00] + [b for i in idxs for b in (0, i >> 8, i & 0xFF)] + [0xFF, 0x60, 0x00, 0xF2, 0x60, 0x00, 0xF4, 0x60, 0x00]
    e, reply, sub, rd1 = handler(0x09A3AC, 0xA8, req)
    want = bytes([0xE8] + [direct_get(i) for i in idxs] + [0x5A, 0x5A, 0x6B, 0x5A, 0x6B, 0x7C, 0x8D])
    check(reply == want + tail, '09A3AC, real transport: ring gets E8 + data (5 table bytes, then 1 / 2 / 4 RAM bytes) + 8 bytes of ROM 0x09B770')
    check(sub == [(2, 1, 0xA8, len(want), 0, 0)] and rd1 == 17 + len(req),
          '09A3AC, real transport: 00DCE4(2, 1, &{0xA8, length, 0, 0}); the whole request is consumed')
    rows.append(('09A3AC ok', bytes(req).hex(), reply.hex()))
    for a, code in ((0x000350, 0x12), (0x800008, 0x12)):
        e, reply, sub, rd1 = handler(0x09A3AC, 0xA8, [0x00, 0x00, 0x00, 0x08, a >> 16, (a >> 8) & 0xFF, a & 0xFF])
        check(reply == bytes([0x7F, 0xA8, code]) + tail and sub == [(2, 1, 0xA8, 3, 8, 0)],
              f'09A3AC, real transport, item {a:06X}: reply 7F A8 {code:02X} + 8 bytes; 00DCE4(2, 1, &{{0xA8, 3, 8, 0}})')
        rows.append((f'09A3AC item {a:06X}', '-', reply.hex()))
    for ln in (3, 5, 6, 254):
        req = [0x00] + [0x00, 0x00, 0x08] * 84
        e, reply, sub, rd1 = handler(0x09A3AC, 0xA8, req, ln=ln)
        check(reply == bytes([0x7F, 0xA8, 0x13]) + tail, f'09A3AC, real transport, length {ln}: reply 7F A8 13 + 8 bytes')
        check(rd1 == 17 + min(ln, 253), f'09A3AC, real transport, length {ln}: min(len, 253) request bytes are consumed although the length is refused')
        rows.append((f'09A3AC len {ln}', f'read index advanced by {rd1 - 17}', reply.hex()))
    # ---- 0x09A628 with the real transport
    for name, ln, req, want in (('len 3', 3, [0, 0, 0x60, 0x37], (0x7F, 0xB8, 0x13)),
                                ('len 5', 5, [0, 0, 0x60, 0x37], (0x7F, 0xB8, 0x13)),
                                ('idx 0x350', 4, [0, 3, 0x50, 0x37], (0x7F, 0xB8, 0x22)),
                                ('idx 0x008', 4, [0, 0, 0x08, 0x37], (0x7F, 0xB8, 0x22)),
                                ('idx 0x000', 4, [0, 0, 0x00, 0x37], (0x7F, 0xB8, 0x22)),
                                ('idx 0x060 v=0x37', 4, [0, 0, 0x60, 0x37], (0xF8, 0x37)),
                                ('idx 0x060 v=0xFF', 4, [0, 0, 0x60, 0xFF], (0xF8, 0xFF))):
        e, reply, sub, rd1 = handler(0x09A628, 0xB8, req, ln=ln)
        ok = want[0] == 0xF8
        check(reply == bytes(want) + tail and sub == [(2, 1, 0xB8, 2, 0, 0) if ok else (2, 1, 0xB8, 3, 8, 0)],
              f'09A628, real transport, {name}: reply {bytes(want).hex()} + 8 bytes')
        check(rd1 == 17 + (4 if ln == 4 else 0), f'09A628, real transport, {name}: request bytes consumed = {4 if ln == 4 else 0}'
              ' (a wrong length is refused WITHOUT fetching the request)')
        if ok:
            check(e.peek(0xFFFF36BE, 1) == want[1], '09A628, real transport: u8[FFFF36BE] = value')
        rows.append((f'09A628 {name}', bytes(req).hex(), reply.hex()))
    return n, rows


def site_09CAEA_mode():
    """Every non-zero value of the mode byte u8[0xFFFFB450] makes 0x09CAEA refuse every id that
    is in the selected table (all record masks are 1), through the real shift helper 0x003BF4."""
    def recs(base):
        out, a = [], base
        while rom[a] != 0xFF:
            out.append((rom[a], L(a + 4), L(a + 8)))
            a += 12
        return out
    full, reduced = recs(0x09B778), recs(0x09B88C)
    check(all(m == 1 for _, _, m in full + reduced), 'every record mask in 0x09B778 and 0x09B88C is 0x00000001')
    for mode in range(256):
        for sid, sel in ((0xA8, 1), (0xB8, 1), (0xB8, 0), (0x55, 1)):
            e = Emu2(); e.fill(0); e.poke(0xFFFFB450, 1, mode)
            seen = []
            for h in {h for _, h, _ in full}:
                e.stub(h, fn=lambda em, h=h: seen.append(h))
            e.call(0x09CAEA, regs={4: sid, 5: 4, 6: sel})
            want = 1 if sid == 0x55 else (0 if mode == 0 else 2)
            check(e.R[0] == want and bool(seen) == (want == 0),
                  f'09CAEA(id={sid:#04x}, sel={sel}) with u8[FFFFB450] = {mode:#04x}: r0 = {want}')
    return 256 * 4


# =====================================================================================
# output
# =====================================================================================
def xcheck_definitions():
    """The definition XML's <ecuid> against the ROM bytes that indices 1..5 return."""
    path = os.path.join(REPO, 'definitions', 'AE5L600L 2013 USDM Impreza WRX MT.xml')
    try:
        m = re.search(r'<ecuid>([0-9A-Fa-f]{10})</ecuid>', open(path, errors='replace').read())
    except OSError:
        return None
    if not m:
        return None
    got = bytes(ev(GET_INFO[i]['expr'], None) for i in range(1, 6)).hex().upper()
    check(got == m.group(1).upper(), f'getters[1..5] return the definition ecuid {m.group(1)} (got {got})')
    return m.group(1).upper(), got, [a for i in range(1, 6) for a, n, v in GET_INFO[i]['rom']]


def xcheck_logcfg():
    """Informational only (logs/logcfg.txt is user-edited): each logger parameter whose id is a table index."""
    path = os.path.join(REPO, 'logs', 'logcfg.txt')
    rows = []
    try:
        lines = open(path, errors='replace').read().split('\n')
    except OSError:
        return rows
    cur = None
    for n, ln in enumerate(lines, 1):
        m = re.match(r'\s*(\w+)\s*=\s*(.*?)\s*$', ln.split(';')[0])
        if not m:
            continue
        k, v = m.group(1), m.group(2)
        if k == 'paramname':
            cur = {'name': v, 'line': n}
            rows.append(cur)
        elif cur is not None and k in ('paramid', 'databits', 'scalingrpn'):
            cur[k] = v
    out = []
    for p in rows:
        pid = p.get('paramid', '')
        if not pid.lower().startswith('0x'):
            continue
        v = int(pid, 16)
        if v >= N:
            continue
        t = GET_INFO[v]['text']
        if p.get('databits') == '16':
            t += '  ||  next index: ' + GET_INFO[v + 1]['text']
        out.append((p['line'], p['name'], v, p.get('databits', '8'), p.get('scalingrpn', ''), A[v], t))
    return out


LOGCFG_SHA256 = 'f7b633eb68862255183c4eff165a53947c09521ccd8d7c6e27e020ac57a8b6ba'      # logs/logcfg.txt as of 2026-11-27


def _affine(e):
    """(slope, intercept, leaf) of a float expression in its single RAM leaf; rounding ignored."""
    k = e[0]
    if k == 'fc':
        return 0.0, e[1], None
    if k in ('fm', 'm'):
        return 1.0, 0.0, e
    if k == 'i2f':
        return _affine(e[1])
    if k == 'zx':
        return _affine(e[2])
    if k == 'fneg':
        s, c, lf = _affine(e[1])
        return -s, -c, lf
    if k in ('fadd', 'fsub'):
        (s1, c1, l1), (s2, c2, l2) = _affine(e[1]), _affine(e[2])
        if l1 is not None and l2 is not None and l1 != l2:
            raise ValueError('two RAM inputs')
        sg = 1.0 if k == 'fadd' else -1.0
        return s1 + sg * s2, c1 + sg * c2, l1 if l1 is not None else l2
    if k == 'fmul':
        (s1, c1, l1), (s2, c2, l2) = _affine(e[1]), _affine(e[2])
        if l1 is not None and l2 is not None:
            raise ValueError('product of two RAM inputs')
        return (s1 * c2, c1 * c2, l1) if l2 is None else (s2 * c1, c2 * c1, l2)
    if k == 'fmac':                                     # e[3] + e[1] * e[2]
        s, c, lf = _affine(('fmul', e[1], e[2]))
        s3, c3, l3 = _affine(e[3])
        if l3 is not None:
            raise ValueError('fmac addend is a RAM input')
        return s, c + c3, lf
    raise ValueError(k)


def _fmacs(e, out=None):
    out = [] if out is None else out
    if e[0] == 'fmac':
        out.append(e)
    for x in e[1:]:
        if isinstance(x, tuple):
            _fmacs(x, out)
    return out


def _find_sat(e):
    if e[0] == 'sat':
        return e
    for x in e[1:]:
        if isinstance(x, tuple):
            r = _find_sat(x)
            if r:
                return r
    return None


def _rpn_affine(rpn):
    """A logger scalingrpn as (a, b) with value = a*x + b, or None when it is not affine in x."""
    st = []
    for tok in rpn.split(','):
        tok = tok.strip()
        if tok == 'x':
            st.append((1.0, 0.0))
        elif tok in '+-*/' and len(tok) == 1:
            (a2, b2), (a1, b1) = st.pop(), st.pop()
            if tok == '+':
                st.append((a1 + a2, b1 + b2))
            elif tok == '-':
                st.append((a1 - a2, b1 - b2))
            elif tok == '*':
                if a1 and a2:
                    return None
                st.append((a1 * b2 + a2 * b1, b1 * b2))
            else:
                if a2:
                    return None
                st.append((a1 / b2, b1 / b2))
        else:
            st.append((0.0, float(tok)))
    return st[0] if len(st) == 1 else None


def logcfg_composites():
    """For each logger parameter whose id is a table index: logged value as a function of the RAM
    input, i.e. the parameter's scalingrpn applied to the getter's formula with rounding and
    saturation ignored.  slope 1 / intercept 0 means the rpn is the exact inverse of the getter."""
    out = []
    for ln, name, v, bits, rpn, stub, t in xcheck_logcfg():
        sat = _find_sat(GET_INFO[v]['expr']) if GET_INFO[v].get('expr') else None
        ra = _rpn_affine(rpn)
        if sat is None or ra is None:
            out.append((ln, name, v, bits, rpn, None, None, None))
            continue
        s, c, lf = _affine(sat[2])
        off, scale = sat[3][1], sat[4][1]
        cs, cc = s / scale, (c - off) / scale           # count = cs * input + cc
        leaf = fmt(lf)
        out.append((ln, name, v, bits, rpn, ra[0] * cs, ra[0] * cc + ra[1], leaf))
    return out


def check_logcfg(comp):
    """Assert the comparison ONLY for the logcfg.txt this trace was written against (sha256 below);
    the file is user-edited, so any other content is listed and not asserted."""
    path = os.path.join(REPO, 'logs', 'logcfg.txt')
    try:
        h = hashlib.sha256(open(path, 'rb').read()).hexdigest()
    except OSError:
        return 'absent'
    if h != LOGCFG_SHA256:
        return 'different file (not asserted)'
    by = {name: (sl, ic) for ln, name, v, bits, rpn, sl, ic, leaf in comp}
    check(len(comp) == 20, 'logcfg.txt has 20 ssm parameters whose id is a table index (< 848)')
    ident = sorted(n for n, (sl, ic) in by.items() if sl is not None and abs(sl - 1) < 1e-6 and abs(ic) < 1e-5)
    check(ident == sorted(['EGT', 'RPM', 'Timing', 'MAF', 'Accelerator', 'IAM', 'FLKC', 'avcs']),
          f'logcfg: the rpn is the exact inverse of the getter for {ident}')
    want = {'AFR': (14.7, 0.0), 'AFC': (100.0, -100.0), 'AFL': (100.0, 0.0), 'MPH': (0.621371192, 0.0),
            'IAT': (1.8, 32.0), 'ECT': (1.8, 32.0), 'IPW': (0.001, 0.0), 'MAF(V)': (5.0 / 65536.0, 0.0),
            'ATM(psi)': (37.0 / 255.0 / 7.5006347, 0.0), 'MAP': (0.145 / 7.5006347, 0.0),
            'wgdc': (100.0 / 255.0 / 0.392, 0.0), 'Throttle': (1.25, 0.0)}
    for name, (sl, ic) in want.items():
        check(abs(by[name][0] - sl) < 2e-6 * max(1.0, abs(sl)) and abs(by[name][1] - ic) < 1e-4,
              f'logcfg {name}: logged = {sl:.7g} * input + {ic:g}')
    check(abs(by['Throttle'][0] - 1.25) < 1e-6 and abs(by['Accelerator'][0] - 1.0) < 1e-6,
          'logcfg Throttle (id 0x015) is NOT inverted by its rpn: logged = 1.25 * f32[FFFF62D4]; Accelerator (0x029) is')
    check(L(0x05D5C4) == 0x3EA0A0A0 and L(0x05D604) == 0x3EC8C8C8 and
          E.f2b(80.0 / 255.0) == 0x3EA0A0A1 and E.f2b(100.0 / 255.0) == 0x3EC8C8C9,
          'pool scale of index 0x015 is 80/255 and of index 0x029 is 100/255, each one float32 step below the NEAREST value')
    check(E.rz_bits(Fraction(80, 255)) == L(0x05D5C4) and E.rz_bits(Fraction(100, 255)) == L(0x05D604),
          '... and each is exactly 80/255 resp. 100/255 truncated toward zero -- the FPU\'s own rounding mode')
    return 'asserted'


def print_classes(out=print):
    out(f'{len(CLASSES)} pattern classes over {len(TARGETS)} distinct stubs '
        f'({len(set(A))} getters, {len(set(B))} setters)')
    out('class  stubs  idx   insns  first    pattern (literals/immediates/displacements masked)')
    for n, (sig, mem) in enumerate(CLASSES):
        t = mem[0]
        nidx = sum(len(IDX_A[x]) + len(IDX_B[x]) for x in mem)
        pat = ' | '.join(sig) if len(sig) <= 22 else ' | '.join(sig[:10]) + f' | ... ({len(sig)} insns)'
        out(f'{cname(t)}    {len(mem):4d}  {nidx:4d}  {len(sig):4d}   {t:06X}   {pat}')


def csv_lines():
    """The index map as ';'-prefixed CSV-style lines for the analysis file."""
    o = []
    o.append('; --- GETTER MAP: table 0x06423C, 848 entries. Columns:')
    o.append(';     index ; table slot ; stub ; class ; kind ; returned byte ; RAM inputs ; ROM data read')
    o.append('; "returned byte" is what the callers keep (r0 & 0xFF). Notation: u8/s16/u32/f32[ADDR] = big-endian')
    o.append('; read at ADDR; satN(x) = clamp(trunc(x + 0.5), 0, 2^N-1) as computed by 0x0BE5A8 / 0x0BE5D8.')
    default = [i for i in range(N) if A[i] == 0x05D1D0]
    zero = [i for i in range(N) if A[i] == 0x05D1CA]

    def ranges(xs):
        r, s = [], None
        for x in xs:
            if s is None:
                s = p = x
            elif x == p + 1:
                p = x
            else:
                r.append((s, p)); s = p = x
        if s is not None:
            r.append((s, p))
        return ' '.join(f'{a:03X}' if a == b else f'{a:03X}-{b:03X}' for a, b in r)
    o.append(f'; DEFAULT stub 0x05D1D0 (returns ROM u8[064239] = 0x{rom[0x64239]:02X}) fills {len(default)} indices:')
    rr = ranges(default).split(' ')
    for i in range(0, len(rr), 14):
        o.append(';     ' + ' '.join(rr[i:i + 14]))
    o.append(f'; ZERO stub 0x05D1CA (returns ROM u8[064238] = 0x{rom[0x64238]:02X}) fills {len(zero)} indices: ' + ranges(zero))
    o.append('; every other index:')
    for i in range(N):
        t = A[i]
        if t in (0x05D1D0, 0x05D1CA):
            continue
        g = GET_INFO[i]
        ins = ' '.join(f'{a:08X}:{k}' for a, k in g['leaves']) or '-'
        romr = ' '.join(f'{a:06X}={v:0{2 * n}X}' for a, n, v in g['rom']) or '-'
        o.append(f'; {i:03X} ; {GET + 4 * i:06X} ; {t:06X} ; {cname(t)} ; {g["kind"]} ; {g["text"]} ; {ins} ; {romr}')
    o.append(';')
    o.append('; --- SETTER MAP: table 0x064F7C, 848 entries. Columns:')
    o.append(';     index ; table slot ; stub ; class ; effect for value byte v (emulated) ; getter at the same index')
    nulls = [i for i in range(N) if B[i] == 0x05E76A]
    o.append(f'; NULL stub 0x05E76A (rts / nop) fills {len(nulls)} indices: every index not listed below.')
    for i in range(N):
        t = B[i]
        if t == 0x05E76A:
            continue
        o.append(f'; {i:03X} ; {SET + 4 * i:06X} ; {t:06X} ; {cname(t)} ; {SET_INFO[t]["text"]} ; {A[i]:06X} {GET_INFO[i]["text"]}')
    return o


def main():
    only_csv = '--csv' in sys.argv
    only_classes = '--classes' in sys.argv
    quiet = only_csv or only_classes
    say = (lambda *a: None) if quiet else print

    refs = geometry()
    say('== A. geometry ==')
    say(f'getter table 0x{GET:06X}..0x{GET + 4 * N:06X}  {N} entries, {len(set(A))} distinct stubs')
    say(f'setter table 0x{SET:06X}..0x{SET + 4 * N:06X}  {N} entries, {len(set(B))} distinct stubs')
    say('pool slots holding 0x06423C:', [f'{x:06X}' for x in refs[GET]],
        ' 0x064F7C:', [f'{x:06X}' for x in refs[SET]])
    say(f'stub code spans 0x{TARGETS[0]:06X}..0x{max(EXT[TARGETS[-1]]) + 2:06X}; '
        f'{sum(len(EXT[t]) for t in TARGETS)} instructions in {len(TARGETS)} stubs')
    say()
    if only_classes or not quiet:
        (print if only_classes else say)('== B. pattern classes ==')
        print_classes(print if only_classes else say)
        say()
    if only_classes:
        return 0

    check(len(extent(0x09A3AC)) == 151 and {0x09A45C, 0x09A466, 0x09A46E, 0x09A474} <= set(extent(0x09A3AC)),
          'extent(0x09A3AC) = 151 instructions and includes 0x09A45C..0x09A46E and 0x09A474 (delay slot that is also a branch target)')
    check(sum(len(EXT[t]) for t in TARGETS) == 2357, 'the 224 stubs hold 2357 instructions')

    callees, missing = callee_sweep(check_file=not quiet)
    say(f'callee sweep: the stubs reach {len(callees)} distinct callees; '
        + ('analysis file not found' if missing is None else 'each has a listed section in the analysis file'))
    say()

    nh = helpers()
    say(f'== E. helpers == {nh} cases match the Python models')
    say('  0BE5A8(fr4=x, fr5=scale, fr6=off) -> r0 = clamp(trunc((x-off)/scale + 0.5), 0, 255)')
    say('  0BE5D8(fr4=x, fr5=scale, fr6=off) -> r0 = clamp(trunc((x-off)/scale + 0.5), 0, 65535)')
    say('     NaN / +-Inf / beyond int32: 0 for NaN and negative overflow, the maximum for positive overflow')
    say('     -- that is the ftrc rule of scripts/sh2e_emu.py, NOT checked against silicon')
    say('  0BE598(r4=u16 raw, fr4=k, fr5=c)  -> fr0 = c + k*float(raw & 0xFFFF)')
    say('  0BE588(r4=u8 raw,  fr4=k, fr5=c)  -> fr0 = c + k*float(raw & 0xFF)')
    say('  0BE9A0(r4=b)                      -> r0 = (b<<8) | (~b & 0xFF)')
    say('  05850E(r4=k) -> r0 = u8[FFFFAD52 + k];   058518(r4=k) -> r0 = u8[FFFF3B06 + 2k]')
    say('  02E7D8() -> r0 = (u8[FFFF7234] == 1);    02E7E2() -> r0 = (u8[FFFF7235] == 1)')
    say('  05F2FC() -> u16[FFFF9048] bit 15 := bit 0 of u8[FFFF8F42]')
    say('  003BF4(r0=v, r1=n) -> r0 = v << n for 0 <= n <= 31, 0 for n >= 32, v for n < 0')
    say()

    n_sym, n_dyn = analyse_getters()
    kinds = collections.Counter(g['kind'] for g in GET_INFO.values())
    say(f'== C. getters == {n_sym} indices evaluated symbolically and confirmed by emulation, '
        f'{n_dyn} indices probed dynamically; kinds: {dict(kinds)}')
    n_ram = sum(1 for g in GET_INFO.values() if g['leaves'])
    check(n_ram == 288 and kinds['const'] == 560 and N - n_ram == 560,
          '288 getter indices read RAM; the other 560 return a constant')
    say(f'  {n_ram} indices read RAM ({len({a for g in GET_INFO.values() for a, k in g["leaves"]})} distinct addresses); '
        f'{N - n_ram} return a constant')
    say('  r4: all 848 indices x 7 values of r4 with every other register scrambled -> only 05DCAE / 05DCCE change;')
    say('      static pass -> the entry value of r4 is read only at 05DCB0 and 05DCD0 (mov r4,r6)')
    ns = special_getters()
    say(f'  hand-read models for {[f"{t:06X}" for t in SPECIAL_GETTERS]} and helpers 0BE980 / 0BE608: {ns} cases match')
    nw, dw, ne, nd, ex = rounding_edges()
    say(f'  index 0x009 (stub 05D2C0): every float32 within 2^-24 of the 256 rounding boundaries ({nw} inputs)')
    say(f'      plus the first-version grid ({ne} inputs): always == sat8(((x - 1) + 1) / 0.0078125);')
    say(f'      differs from the simplified sat8(x / 0.0078125) for exactly {dw} inputs (grid: {nd}), all with')
    say(f'      0 < x < 0.5, less than 2^-24 below a boundary, ROM one count higher; e.g. x = {ex[0]!r}: ROM {ex[1]}, simplified {ex[2]}')
    say('      (every FPU step truncated toward zero, FPSCR RM = 01; the first version modelled round-to-nearest: 319 / grid 231)')
    nx = extreme_floats()
    say(f'  NaN / +-Inf / +-3.4e38 / beyond-int32 float inputs: {nx} runs, every formula still matches the emulator')
    say('      (emulator ftrc rule; not a statement about silicon)')
    analyse_setters()
    say(f'== D. setters == {len(SET_INFO)} distinct stubs emulated')
    for t in sorted(SET_INFO):
        say(f'  {t:06X} {cname(t)} idx {",".join(f"{i:03X}" for i in IDX_B[t][:4])}{"..." if len(IDX_B[t]) > 4 else ""}: {SET_INFO[t]["text"]}')
    say()

    global SAMPLE_F32
    SAMPLE_F32 = sorted({(a, k) for i in SAMPLE_IDX for a, k in GET_INFO[i]['leaves'] if k == 'f32'})
    say('== F. dispatch sites ==')
    say('-- 0x05F718 (getter dispatch):  idx  pos  flags -> out byte')
    for r in site_05F718():
        say('   ', ' '.join(f'{x:#06x}' if isinstance(x, int) else str(x) for x in r))
    say('-- 0x05F758 (setter dispatch):  idx  stub  flags -> RAM writes')
    for r in site_05F758():
        say('   ', ' '.join(f'{x:#06x}' if isinstance(x, int) else str(x) for x in r))
    say('-- 0x05F316 (flag 0x0400 write path, flag 0x1000 address-list path)')
    for r in site_05F316():
        say('   ', ' '.join(f'{x:#06x}' if isinstance(x, int) else str(x) for x in r))
    say('-- 0x09CAEA (service dispatcher)')
    rows, full, reduced = site_09CAEA()
    say('    table 0x09B778 ids:', ' '.join(f'{i:02X}' for i, h, m in full))
    say('    table 0x09B88C ids:', ' '.join(f'{i:02X}' for i, h, m in reduced))
    for r in rows:
        say('   ', ' | '.join(r))
    pr = pairing()
    say(f'-- getter/setter pairing: {sum(1 for r in pr if r[3])} RAM-writing setter indices all write a location their '
        f'getter reads; {sum(1 for r in pr if r[3] and r[4])} write ONLY such locations; '
        f'{sum(1 for r in pr if not r[3])} setter indices write nothing')
    say('-- 0x09A710 (write whitelist):  r4 -> r0')
    for r in site_09A710():
        say('   ', ' '.join(f'{x:#x}' for x in r))
    say('-- 0x09A628 (service 0xB8)')
    for r in site_09A628():
        say('   ', ' | '.join(str(x) for x in r))
    say('-- 0x09A3AC (service 0xA8)')
    for r in site_09A3AC():
        say('   ', ' | '.join(str(x) for x in r))
    say('-- 0x09A3AC, tagged items FF / F2 / F4: no bound on the address read or on the bytes stored')
    for r in site_09A3AC_tagged():
        say('   ', ' | '.join(str(x) for x in r))
    say('-- 0x05F08C (request parser of the second path)')
    for r in site_05F08C():
        say('   ', ' | '.join(str(x) for x in r))
    nm = site_09CAEA_mode()
    say(f'-- 0x09CAEA, mode byte u8[FFFFB450] swept 0..255 ({nm} runs): 0 -> handler runs; any other value -> r0 = 2 for')
    say('   every id in the selected table (all record masks are 1), r0 = 1 for an id that is not in it')
    nt, rows = transport()
    say(f'-- transport helpers run for real (only 0x00DCE4 stubbed): {nt} leaf / gate cases match the ring model')
    say('   record at 0xFFFFB454 = { u16 write index, u16 read index, u16 mark, 601 data bytes }; u8[FFFFB6DF] = bound id')
    for r in rows:
        say('   ', ' | '.join(str(x) for x in r))
    say()

    xd = xcheck_definitions()
    say('== G. cross-checks against in-repo artefacts ==')
    if xd:
        say(f'  definitions <ecuid> {xd[0]} == bytes returned by indices 0x001..0x005 (ROM '
            + ' '.join(f'{a:06X}' for a in xd[2]) + ')')
    for idx, x, want in ((0x015, 80.0, 255), (0x015, 79.9, 255), (0x015, 79.8, 254), (0x015, 40.0, 128),
                         (0x029, 100.0, 255), (0x029, 80.0, 204)):
        a = GET_INFO[idx]['leaves'][0][0]
        got = run_getter(A[idx], idx, lambda e, a=a, x=x: (e.fill(0), e.poke(a, 4, E.f2b(x))))[0]
        check(got == want, f'getter[{idx:#05x}] returns {want} for an input of {x}')
    say('  index 0x015 returns 255 at f32[FFFF62D4] = 80.0 (scale 80/255); index 0x029 returns 255 at 100.0 (scale 100/255)')
    comp = logcfg_composites()
    state = check_logcfg(comp)
    say(f'  logs/logcfg.txt: {len(comp)} parameters whose id is a table index  [{state}]')
    for ln, name, v, bits, rpn, stub, t in xcheck_logcfg():
        say(f'    logcfg.txt:{ln:<4d} {name:<12s} id 0x{v:03X} bits {bits:<2s} rpn {rpn:<26s} -> {stub:06X}  {t}')
    say('  the same parameters as "logged value = slope * RAM input + intercept" (rpn applied to the getter formula,')
    say('  rounding and saturation ignored); slope 1 / intercept 0 = the rpn inverts the getter exactly:')
    for ln, name, v, bits, rpn, sl, ic, leaf in comp:
        if sl is None:
            say(f'    {name:<12s} id 0x{v:03X}  (not affine / not a formula getter)')
        else:
            tag = 'inverse' if abs(sl - 1) < 1e-6 and abs(ic) < 1e-5 else ''
            say(f'    {name:<12s} id 0x{v:03X}  logged = {sl:.8g} * {leaf} + {ic:.6g}   {tag}')
    say()

    if only_csv:
        print('\n'.join(csv_lines()))
        return 0
    say('== index map (same block as in the analysis file) ==')
    for ln in csv_lines():
        say(ln)
    say()
    print(f'ALL {len(CHECKS)} CHECKS PASSED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
