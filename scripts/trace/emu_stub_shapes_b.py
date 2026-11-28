#!/usr/bin/env python3
"""Small-function shape classes 30..126 of disassembly/maps/stub_classes.json -- re-decode, prove, emulate.

    python3 scripts/trace/emu_stub_shapes_b.py            # every class, prints inputs -> outputs, asserts, exit 0
    python3 scripts/trace/emu_stub_shapes_b.py --quiet    # one summary line per class
    python3 scripts/trace/emu_stub_shapes_b.py --map      # only the ';' member -> parameter lines
    python3 scripts/trace/emu_stub_shapes_b.py --class 37 # one class

Companion to disassembly/analysis/stub_shapes_b_trace.txt (2026-11-27).
Reference bin "rom/AE5L600L 20g rev 20.19c.bin", md5 92cae8275cd4f9b473a3a9e36efe6449 (asserted).

SCOPE
Every class with id 30..126 and at least two members in disassembly/maps/stub_classes.json
(97 classes, 295 functions).  stub_classes.json is the INPUT (the grouping to be tested); nothing in it
is trusted: each member is re-decoded here from ROM bytes with this script's own masking rule.

WHAT IS ASSERTED, PER MEMBER
  1. SHAPE.  The member's words, decoded from ROM over its census extent, reduce to exactly the class
     example's masked shape (every PC-relative literal, mova target, immediate, struct displacement
     and bra/bsr target masked; everything else -- registers, opcodes, bt/bf displacements -- exact).
     A member that does not is reported and dropped.  None is.
  2. PARAMETERS.  The masked fields, resolved from bytes (literal value, mova target and the float32
     stored there, sign-extended immediate, displacement IN BYTES, absolute branch target), are bound
     to the class's parameter names and printed as the member map.
  3. CONTRACT.  The member is run in scripts/sh2e_emu.py from its entry, on RAM filled with a
     deterministic pseudo-random pattern, over cases chosen to take BOTH outcomes of every compare.
     Every call target outside the member is a recording stub (or, in REAL mode, the runtime-library
     routine itself, see below).  The run must agree with the class model EXACTLY on:
       - the set of RAM bytes written (outside the stack) and their values,
       - register-space reads and writes (>= 0xFFFFC000), in order, with size and value,
       - the sequence of calls: target, call-vs-tail (PR at the callee = return address inside the
         member, or the caller's own return address), and the argument registers the model names,
       - r0 / fr0 / other result registers the model names, r15 balanced,
       - no instruction executed outside the member (stub mode) or outside member + library (REAL).
  4. REAL MODE, for members whose callee is a runtime-library routine with a verified contract
     (disassembly/analysis/helpers_*_trace.txt, corrections item 107): 0x0BE5A8, 0x0BE5D8, 0x0BE9A0,
     0x0BE9B0, 0x0BE830, 0x0BDB80.  The routine is executed for real and the model composes the
     library contract.  For 0x0BE5A8 / 0x0BE5D8 the model is EXACT rational arithmetic and a case is
     only used where float32 rounding of the intermediate steps cannot move the integer result
     (checked per case; no claim here depends on the last bit of a float).  For 0x0BE830 the oracle
     is desc_types.read_table() + linear interpolation, compared to 1e-5 relative.
     0x0BDBCC, 0x00317C and 0x003190 load SR (ldc), which the emulator refuses: always stubbed.

DATA DECODED AS CODE / NOT FUNCTIONS (reported, not emulated as functions)
  * classes 74 and 125 (0x0BE914 0x0BE918 0x0BE91C 0x0BE920 0x0BE924): five LONGS, the code
    pointers of the 2-D cell handlers, indexed by the 2-D lookup 0x0BE8E4.  Asserted below.  Their
    census extent and masked shape are checked like every other member (all 295 are shape-tested).
  * class 78 (0x003DA4, 0x003E38): interior labels of the variable right-shift routines 0x003CB4
    (arithmetic) and 0x003E14 (logical).  0x003DA4 is the shift-31 entry of the 32-byte SIGNED offset
    table 0x003C94..0x003CB3 (byte address = pool word 0x003CAC + r1 - 24) used by the computed jmp at
    0x003CD2, reached only for a negative value.  0x003E38 is the bt target at 0x003E1E (count >= 32),
    but 0x003E14 has NO detected entry (no pointer, no branch, no mov.w literal): 0x003CB4 enters it at
    0x003E20 (jmp at 0x003CDE), after the bt.  Both whole routines are emulated over counts -2..40.

ENTRY PATHS PROVEN FROM BYTES
  * class 30: each member's address sits in the table at 0x0FFC50 (the VBR literal at 0x00FCC4), and
    an exact 32-bit search of the whole ROM finds it nowhere else.
  * classes 32 33 57 58 59 83 84 85 86 87 88 (34 members): exactly one per-vector interrupt stub
    (slot u32[0x0FFC50 + 4v]) dispatches to each member.  Every stub is the 24 bytes at 0x00207C + 24k:
    2F06 D004 4F22 400B 2F16 D101 412B 402A, then the member long at stub+16 and 0x00002B8C at
    stub+20.  It pushes r0 / PR / r1, calls 0x002B8C (jsr at stub+6), loads the member (stub+10) and
    enters it with jmp @r1 at stub+12 and lds r0,pr in the slot.  0x002B8C is straight-line and ends
    r0 = u32[0x002BD0] = 0x00002BD4 (rtos_core_trace.txt contract; bytes re-checked here), so every
    member is entered with PR = 0x002BD4 and its tail-call target returns THERE (emulated through the
    stub with 0x002B8C stubbed, because it loads SR).  For 32 33 83 84 88 (19 members) the code passed
    in r4 to 0x00E774 equals that vector number (asserted).

EXTRA WRITER / CONSUMER CHECKS (reviewer items, decided from bytes)
  * 0x01FDD4: f32[0xFFFF63B0] = 0x0BEA40(A = f32[0xFFFF4130], B = f32[0xFFFF63B0], k = 0.5,
    eps = f32 0x39A00000), run with 0x0BEA40 REAL on exact cases.
  * 0x027D66 calls 0x027D78 (class 100, writes u8[0xFFFF6A84]) then 0x027D86, which sets
    GBR = 0xFFFF6A84 and tests mov.b @(0,gbr) == 1 (bytes asserted).

ARITHMETIC: sh2e_emu computes each FPU step exactly and truncates toward zero (corrections item 106).
The models here do not depend on that: see REAL MODE above.
"""
import argparse
import hashlib
import json
import math
import os
import struct
import sys
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, 'scripts'))
import sh2e_emu as E                     # noqa: E402
from sh2e_disasm import decode           # noqa: E402
import desc_types as DT                  # noqa: E402

ROMP = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
MD5 = '92cae8275cd4f9b473a3a9e36efe6449'
M32 = 0xFFFFFFFF
STACK_TOP = E.STACK_TOP
RET = E.RETURN_MAGIC
F1 = 0x3F800000          # 1.0
FM1 = 0xBF800000         # -1.0
F0 = 0x00000000

with open(ROMP, 'rb') as fh:
    ROM = fh.read()
assert hashlib.md5(ROM).hexdigest() == MD5, 'wrong reference bin'
with open(os.path.join(REPO, 'disassembly', 'maps', 'stub_classes.json')) as fh:
    ALLCLASSES = json.load(fh)
with open(os.path.join(REPO, 'disassembly', 'maps', 'function_census.json')) as fh:
    CENSUS = {f['entry']: f for f in json.load(fh)['functions']}

CHECKS = [0]


def check(cond, msg):
    CHECKS[0] += 1
    if not cond:
        raise AssertionError(msg)


def u8(a): return ROM[a]
def u16(a): return (ROM[a] << 8) | ROM[a + 1]
def u32(a): return struct.unpack('>I', ROM[a:a + 4])[0]
def rl(a): return u32(a)                          # float32 BITS stored in ROM at a
def sx8(v): v &= 0xFF; return v - 0x100 if v & 0x80 else v
def sx16(v): v &= 0xFFFF; return v - 0x10000 if v & 0x8000 else v
def bf(b): return E.b2f(b)
def fb(f): return E.f2b(f)


def ffmt(b):
    f = bf(b)
    return f'{f:.9g} ({b:08X})'


# =====================================================================================
# 1. SHAPE: this script's own masking rule
# =====================================================================================
def shape(pc, w):
    """(masked word, parameter or None). Parameter = (kind, value, extra)."""
    op, sub = w >> 12, (w >> 8) & 0xF
    if op == 0xD:
        a = ((pc + 4) & ~3) + (w & 0xFF) * 4
        return w & 0xFF00, ('L', u32(a), a)
    if op == 0x9:
        a = pc + 4 + (w & 0xFF) * 2
        return w & 0xFF00, ('W', sx16(u16(a)) & M32, a)
    if op in (0xE, 0x7):
        return w & 0xFF00, ('I', sx8(w), None)
    if op in (0xA, 0xB):
        d = w & 0xFFF
        d = d - 0x1000 if d & 0x800 else d
        return w & 0xF000, ('B', pc + 4 + 2 * d, None)
    if op == 0x8:
        if sub in (0x0, 0x4):
            return w & 0xFFF0, ('D', w & 0xF, None)
        if sub in (0x1, 0x5):
            return w & 0xFFF0, ('D', (w & 0xF) * 2, None)
        if sub == 0x8:
            return w & 0xFF00, ('I', sx8(w), None)
        return w, None                                   # bt / bf / bt/s / bf/s: exact
    if op == 0xC:
        if sub == 0x7:
            a = ((pc + 4) & ~3) + (w & 0xFF) * 4
            return w & 0xFF00, ('A', a, u32(a))
        if sub in (0x8, 0x9, 0xA, 0xB):
            return w & 0xFF00, ('U', w & 0xFF, None)
        return w & 0xFF00, ('G', w & 0xFF, None)
    if op in (0x1, 0x5):
        return w & 0xFFF0, ('D', (w & 0xF) * 4, None)
    return w, None


def body(entry, n):
    out = []
    for i in range(n):
        pc = entry + 2 * i
        w = u16(pc)
        m, p = shape(pc, w)
        out.append((pc, w, decode(w, pc)[0], m, p))
    return out


ILLEGAL = ('fsqrt', 'fschg', 'frchg', 'movi20', 'movu', '.word', 'fcnvsd', 'fcnvds')


# =====================================================================================
# 2. emulator with register-space logging and call recording
# =====================================================================================
class Emu3(E.Emu):
    def __init__(self, seed):
        super().__init__(ROM)
        x = (seed * 2654435761 + 12345) & M32
        buf = bytearray(len(self.ram))
        for i in range(0, len(buf), 4):
            x = (x * 1103515245 + 12345) & M32
            buf[i:i + 4] = x.to_bytes(4, 'big')
        self.ram[:] = buf
        self.init[:] = b'\x01' * len(self.init)
        self.preads, self.pwrites, self.pvals, self.calls = [], [], {}, []

    def read(self, a, n):
        a &= M32
        if a >= 0xFFFFC000:
            self.preads.append((a, n))
            return self.pvals.get(a, 0) & ((1 << (8 * n)) - 1)
        return super().read(a, n)

    def write(self, a, n, v):
        a &= M32
        if a >= 0xFFFFC000:
            self.pwrites.append((a, n, v & ((1 << (8 * n)) - 1)))
            return
        super().write(a, n, v)

    def poke(self, a, n, v):
        o = a - E.RAM_LO
        self.ram[o:o + n] = (v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big')

    def peek(self, a, n):
        o = a - E.RAM_LO
        return int.from_bytes(self.ram[o:o + n], 'big')


class Mem:
    """Reader over the state BEFORE the run (RAM snapshot + ROM)."""
    def __init__(self, ram):
        self.ram = bytes(ram)

    def rd(self, a, n):
        a &= M32
        if a + n <= 0x100000:
            return int.from_bytes(ROM[a:a + n], 'big')
        o = a - E.RAM_LO
        return int.from_bytes(self.ram[o:o + n], 'big')

    def u8(self, a): return self.rd(a, 1)
    def s8(self, a): return sx8(self.rd(a, 1))
    def u16(self, a): return self.rd(a, 2)
    def s16(self, a): return sx16(self.rd(a, 2))
    def u32(self, a): return self.rd(a, 4)
    def fb(self, a): return self.rd(a, 4)


class Inp:
    def __init__(self, mem, regs, fregs, rets, real, entry):
        self.m, self.R, self.FR, self.rets, self.real, self.entry = mem, regs, fregs, rets, real, entry

    def ret(self, t):
        return self.rets.get(t, (0x5A5A0000 | (t & 0xFFFF), 0x40490FDB))   # default stub return


class X:
    """Expected effects."""
    def __init__(self):
        self.w, self.pr, self.pw, self.calls = [], [], [], []
        self.regs, self.fregs = {}, {}
        self.end = 'ret'
        self.approx = []          # (addr, float, rel tol): a float32 store compared within tolerance
        self.stack = []           # (addr, n, value): stack bytes checked directly

    def st(self, a, n, v): self.w.append((a & M32, n, v & ((1 << (8 * n)) - 1)))
    def call(self, t, kind, **chk): self.calls.append((t, kind, chk))
    def r(self, k, v): self.regs[k] = v & M32
    def f(self, k, b): self.fregs[k] = b & M32


# =====================================================================================
# 3. runtime-library models (contracts of disassembly/analysis/helpers_*_trace.txt)
# =====================================================================================
def frac(b):
    f = bf(b)
    check(math.isfinite(f), 'non-finite input to an exact model')
    return Fraction(f)


def representable(q):
    try:
        return Fraction(struct.unpack('>f', struct.pack('>f', float(q)))[0]) == q
    except OverflowError:
        return False


def lib_sat(xb, scb, offb, top):
    """0x0BE5A8 (top 255) / 0x0BE5D8 (top 65535): clamp(trunc((x - off)/sc + 0.5), 0, top).
    Returns (value, ok): ok is False when float32 rounding of the steps COULD change the result."""
    x, sc, off = frac(xb), frac(scb), frac(offb)
    a = x - off
    q = a / sc
    s = q + Fraction(1, 2)
    exact = representable(a) and representable(q) and representable(s)
    t = math.floor(s) if s >= 0 else math.ceil(s)     # ftrc: toward zero
    if not exact:
        # truncation of three float32 steps moves s by < 2^-21 relative: unsafe only near an integer
        dist = abs(s - round(s))
        if dist <= abs(s) * Fraction(1, 1 << 20) + Fraction(1, 1 << 40):
            return None, False
    return max(0, min(top, t)), True


def lib_pair8(v): return ((v & 0xFF) << 8) | (~v & 0xFF)
def lib_pair16(v): return ((v & 0xFFFF) << 16) | (~v & 0xFFFF)


def lib_lookup1d(rec, xb):
    t = DT.read_table(ROM, rec)
    ax, vals = t['axes']['x'], t['values']
    x = bf(xb)
    if x != x or x >= ax[-1]:
        return vals[-1]
    if x < ax[0]:
        return vals[0]
    i = max(k for k in range(len(ax)) if ax[k] <= x)
    if i == len(ax) - 1 or ax[i + 1] == ax[i]:
        return vals[i]
    f = (x - ax[i]) / (ax[i + 1] - ax[i])
    return vals[i] + f * (vals[i + 1] - vals[i])


LIB_REAL = {0x0BE5A8, 0x0BE5D8, 0x0BE9A0, 0x0BE9B0, 0x0BE830, 0x0BDB80}
LIB_RANGE = (0x0BD000, 0x0BF000)


# =====================================================================================
# 4. the classes.  Each: names (one per masked field, in order), one-line contract,
#    targets(p) = addresses stubbed, cases(p) -> list of case dicts, model(p, I, X).
#    case keys: ram [(a,n,v)], regs {k:v}, fr {k:bits}, pv {periph:v}, rets {t:(r0,fr0)}, stop set
# =====================================================================================
K = {}


def cls(cid, names, contract, targets=lambda p: set(), real=False, stop=lambda p: set()):
    def deco(fn):
        K[cid] = dict(names=names.split(), contract=contract, targets=targets, real=real,
                      stop=stop, model=fn, cases=None)
        return fn
    return deco


def cases(cid):
    def deco(fn):
        K[cid]['cases'] = fn
        return fn
    return deco


BYTES = [0x00, 0x01, 0x02, 0x7F, 0x80, 0xFF]


def byte_cases(a, vals=BYTES):
    return [dict(ram=[(a, 1, v)]) for v in vals]


def one(**kw):
    return [dict(**kw)]


# ---- 30: vector handler: r4 = code; call F; spin ------------------------------------------------
@cls(30, 'W F LOOP', 'r4 = W; call F; then branch-to-self forever (never returns)',
     targets=lambda p: {p['F']}, stop=lambda p: {p['LOOP']})
def m30(p, I, x):
    check(p['LOOP'] == I.entry + 6, 'bra target is its own address')
    x.call(p['F'], 'call', r4=p['W'])
    x.end = 'loop'


cases(30)(lambda p: one())


# ---- 31: tail-call F(r4 = A, fr4 = 0.0) ---------------------------------------------------------
@cls(31, 'A F', 'tail-call F with r4 = A, fr4 = 0.0', targets=lambda p: {p['F']})
def m31(p, I, x):
    x.call(p['F'], 'tail', r4=p['A'], fr4=F0)
    x.r(0, I.ret(p['F'])[0])


cases(31)(lambda p: [dict(rets={p['F']: (0, 0)}), dict(rets={p['F']: (1, 0)})])


# ---- 32: read16 P (discarded); write16 P = K; tail-call G(r4 = C) --------------------------------
@cls(32, 'P K C G', 'u16 read of P (value left in r3); u16[P] = K; tail-call G with r4 = C',
     targets=lambda p: {p['G']})
def m32(p, I, x):
    x.pr.append((p['P'], 2))
    x.pw.append((p['P'], 2, p['K'] & 0xFFFF))
    x.call(p['G'], 'tail', r4=p['C'], r3=sx16(I.pv) & M32)


cases(32)(lambda p: [dict(pv={p['P']: v}) for v in (0x0000, 0xFFFF, 0x8001, 0x1234)])


# ---- 33: u8[P] = (u8[P] & M) | K; tail-call G(r4 = C) --------------------------------------------
@cls(33, 'P M K C G', 'u8[P] = (u8[P] & M) | K; tail-call G with r4 = C', targets=lambda p: {p['G']})
def m33(p, I, x):
    x.pr.append((p['P'], 1))
    x.pw.append((p['P'], 1, (I.pv & p['M']) | p['K']))
    x.call(p['G'], 'tail', r4=p['C'])


cases(33)(lambda p: [dict(pv={p['P']: v}) for v in (0x00, 0xFF, 0x5A, 0x07, 0xC0)])


# ---- 34: long[A] = F(r4 = V) (F = 0x0BE9B0, build value:~value) ----------------------------------
@cls(34, 'F V A', 'r0 = F(r4 = V); u32[A] = r0; return r0', targets=lambda p: {p['F']}, real=True)
def m34(p, I, x):
    if I.real:
        r = lib_pair16(p['V'])
    else:
        x.call(p['F'], 'call', r4=p['V'] & M32)
        r = I.ret(p['F'])[0]
    x.st(p['A'], 4, r)
    x.r(0, r)


cases(34)(lambda p: [dict(rets={p['F']: (0x12345678, 0)}), dict(rets={p['F']: (0xFFFF0000, 0)})])


# ---- 35: four byte stores of V at A, A+D1, A+D2, A+D3 --------------------------------------------
@cls(35, 'V A D1 D2 D3', 'u8[A] = u8[A+D1] = u8[A+D2] = u8[A+D3] = V; r0 = V')
def m35(p, I, x):
    for d in (0, p['D1'], p['D2'], p['D3']):
        x.st(p['A'] + d, 1, p['V'])
    x.r(0, p['V'])


cases(35)(lambda p: one())


# ---- 36 / 93: float copy ------------------------------------------------------------------------
def m_fcopy(p, I, x):
    x.st(p['B'], 4, I.m.fb(p['A']))


cls(36, 'A B', 'f32[B] = f32[A] (bit copy through fr8)')(m_fcopy)
cases(36)(lambda p: [dict(ram=[(p['A'], 4, b)]) for b in (0x3F800000, 0xC2C80000, 0x7FC00000, 0x00000000)])
cls(93, 'A B', 'f32[B] = f32[A] (bit copy through fr9)')(m_fcopy)
cases(93)(lambda p: [dict(ram=[(p['A'], 4, b)]) for b in (0x3F800000, 0xC2C80000, 0x7FC00000)])


# ---- float -> int conversions through 0x0BE5A8 / 0x0BE5D8 ----------------------------------------
def sat_cases(p, xa, offb, scb, top):
    """x values around every edge of clamp(trunc((x-off)/sc + 0.5), 0, top)."""
    off, sc = bf(offb), bf(scb)
    ks = [-3, -1, -0.5, -0.25, 0, 0.25, 0.49, 0.5, 0.51, 1, 1.5, 7.25, 100.5,
          top - 1, top - 0.5, top - 0.25, top, top + 0.5, top + 3, top * 4]
    out = []
    for k in ks:
        xb = fb(off + sc * k)
        out.append(dict(ram=[(xa, 4, xb)]) if xa is not None else dict())
    return out


def sat_model(p, I, x, F, xb, offb, scb, top, mask, extu):
    if I.real:
        v, ok = lib_sat(xb, scb, offb, top)
        if not ok:
            return False
        r = v
    else:
        x.call(F, 'call', fr4=xb, fr5=scb, fr6=offb)
        r = I.ret(F)[0]
    x.r(0, (r & mask) if extu else r)
    return r


SAT_RETS = lambda F: [dict(rets={F: (0x12345678, 0)})]


@cls(37, 'X F OFF SC', 'r0 = F(fr4 = f32[X], fr6 = f32@OFF, fr5 = f32@SC) & 0xFF  (F = 0x0BE5A8)',
     targets=lambda p: {p['F']}, real=True)
def m37(p, I, x):
    return sat_model(p, I, x, p['F'], I.m.fb(p['X']), rl(p['OFF']), rl(p['SC']), 255, 0xFF, True)


cases(37)(lambda p: sat_cases(p, p['X'], rl(p['OFF']), rl(p['SC']), 255))


@cls(38, 'F OFF', 'r0 = F(fr4 = 0.0, fr6 = f32@OFF, fr5 = 1.0) & 0xFF: a constant  (F = 0x0BE5A8)',
     targets=lambda p: {p['F']}, real=True)
def m38(p, I, x):
    return sat_model(p, I, x, p['F'], F0, rl(p['OFF']), F1, 255, 0xFF, True)


cases(38)(lambda p: one())


@cls(51, 'X F OFF', 'r0 = F(fr4 = f32[X], fr6 = f32@OFF, fr5 = 1.0) & 0xFF  (F = 0x0BE5A8)',
     targets=lambda p: {p['F']}, real=True)
def m51(p, I, x):
    return sat_model(p, I, x, p['F'], I.m.fb(p['X']), rl(p['OFF']), F1, 255, 0xFF, True)


cases(51)(lambda p: sat_cases(p, p['X'], rl(p['OFF']), F1, 255))


@cls(52, 'X F SC', 'r0 = F(fr4 = f32[X], fr6 = 0.0, fr5 = f32@SC) & 0xFFFF  (F = 0x0BE5D8)',
     targets=lambda p: {p['F']}, real=True)
def m52(p, I, x):
    return sat_model(p, I, x, p['F'], I.m.fb(p['X']), F0, rl(p['SC']), 65535, 0xFFFF, True)


cases(52)(lambda p: sat_cases(p, p['X'], F0, rl(p['SC']), 65535))


@cls(53, 'F', 'r0 = F(fr4 = 0.0, fr6 = 0.0, fr5 = 1.0) & 0xFF = 0  (F = 0x0BE5A8)',
     targets=lambda p: {p['F']}, real=True)
def m53(p, I, x):
    return sat_model(p, I, x, p['F'], F0, F0, F1, 255, 0xFF, True)


cases(53)(lambda p: one())


@cls(68, 'X F', 'r0 = F(fr4 = f32[X], fr6 = 0.0, fr5 = 1.0) & 0xFF  (F = 0x0BE5A8)',
     targets=lambda p: {p['F']}, real=True)
def m68(p, I, x):
    return sat_model(p, I, x, p['F'], I.m.fb(p['X']), F0, F1, 255, 0xFF, True)


cases(68)(lambda p: sat_cases(p, p['X'], F0, F1, 255))


@cls(69, 'F OFF SC', 'r0 = F(fr4 = 0.0, fr6 = f32@OFF, fr5 = f32@SC) & 0xFF: a constant  (F = 0x0BE5A8)',
     targets=lambda p: {p['F']}, real=True)
def m69(p, I, x):
    return sat_model(p, I, x, p['F'], F0, rl(p['OFF']), rl(p['SC']), 255, 0xFF, True)


cases(69)(lambda p: one())


@cls(113, 'X F SC', 'r0 = F(fr4 = f32[X], fr6 = -1.0, fr5 = f32@SC) & 0xFF  (F = 0x0BE5A8)',
     targets=lambda p: {p['F']}, real=True)
def m113(p, I, x):
    return sat_model(p, I, x, p['F'], I.m.fb(p['X']), FM1, rl(p['SC']), 255, 0xFF, True)


cases(113)(lambda p: sat_cases(p, p['X'], FM1, rl(p['SC']), 255))


@cls(114, 'F SC', 'r0 = F(fr4 = 0.0, fr6 = -1.0, fr5 = f32@SC) & 0xFF: a constant  (F = 0x0BE5A8)',
     targets=lambda p: {p['F']}, real=True)
def m114(p, I, x):
    return sat_model(p, I, x, p['F'], F0, FM1, rl(p['SC']), 255, 0xFF, True)


cases(114)(lambda p: one())


@cls(45, 'X F SC O', 'r0 = F(fr4 = f32[X], fr6 = 0.0, fr5 = f32@SC); u16[O] = r0  (F = 0x0BE5D8)',
     targets=lambda p: {p['F']}, real=True)
def m45(p, I, x):
    r = sat_model(p, I, x, p['F'], I.m.fb(p['X']), F0, rl(p['SC']), 65535, M32, False)
    if r is False:
        return False
    x.st(p['O'], 2, r)


cases(45)(lambda p: sat_cases(p, p['X'], F0, rl(p['SC']), 65535))


@cls(73, 'X F OFF O', 'r0 = F(fr4 = f32[X], fr6 = f32@OFF, fr5 = 1.0); u8[O] = r0  (F = 0x0BE5A8)',
     targets=lambda p: {p['F']}, real=True)
def m73(p, I, x):
    r = sat_model(p, I, x, p['F'], I.m.fb(p['X']), rl(p['OFF']), F1, 255, M32, False)
    if r is False:
        return False
    x.st(p['O'], 1, r)


cases(73)(lambda p: sat_cases(p, p['X'], rl(p['OFF']), F1, 255))


# ---- 39: dead stack byte, r0 = 0 ----------------------------------------------------------------
@cls(39, 'S1 V S2', 'r0 = V (0); one byte below the caller\'s r15 (at r15-4) set to V; r15 restored')
def m39(p, I, x):
    check(p['S1'] == -4 and p['S2'] == 4, 'frame of 4 bytes')
    x.r(0, p['V'])
    x.stack.append((STACK_TOP - 4, 1, p['V'] & 0xFF))


cases(39)(lambda p: one())


# ---- 40 / 50 / 95: byte copy ----------------------------------------------------------------------
@cls(40, 'A B', 'u8[B] = u8[A]; r2 = s8[A]')
def m40(p, I, x):
    x.st(p['B'], 1, I.m.u8(p['A']))
    x.r(2, I.m.s8(p['A']))


cases(40)(lambda p: byte_cases(p['A']))


@cls(50, 'A B', 'u8[B] = u8[A]; r6 = s8[A]')
def m50(p, I, x):
    x.st(p['B'], 1, I.m.u8(p['A']))
    x.r(6, I.m.s8(p['A']))


cases(50)(lambda p: byte_cases(p['A']))


@cls(95, 'C B', 'u8[B] = u8[C] (C is ROM); r2 = s8[C]')
def m95(p, I, x):
    x.st(p['B'], 1, I.m.u8(p['C']))
    x.r(2, I.m.s8(p['C']))


cases(95)(lambda p: one())


# ---- 41: r0 = (s8[A] == K) ? V1 : V0 --------------------------------------------------------------
@cls(41, 'A K V0 V1', 'r0 = V1 if u8[A] == K else V0')
def m41(p, I, x):
    x.r(0, p['V1'] if I.m.s8(p['A']) == p['K'] else p['V0'])


cases(41)(lambda p: byte_cases(p['A']))


# ---- 42: if (F() & 0xFF) == 0 tail-call G else return F() ----------------------------------------
@cls(42, 'F G', 'r = F(); if (r & 0xFF) == 0: tail-call G (r0 = r at G) else return r',
     targets=lambda p: {p['F'], p['G']})
def m42(p, I, x):
    r = I.ret(p['F'])[0]
    x.call(p['F'], 'call')
    if r & 0xFF == 0:
        x.call(p['G'], 'tail', r0=r)
        x.r(0, I.ret(p['G'])[0])
    else:
        x.r(0, r)


cases(42)(lambda p: [dict(rets={p['F']: (v, 0)}) for v in (0, 0x100, 1, 0xFF, 0x80)])


# ---- 43 / 67 / 112: r0 = s8 of a ROM byte ---------------------------------------------------------
def m_romb(p, I, x):
    x.r(0, I.m.s8(p['C']))


cls(43, 'C', 'r0 = s8[C] (C in ROM calibration)')(m_romb)
cases(43)(lambda p: one())
cls(67, 'C', 'r0 = s8[C] (C in ROM)')(m_romb)
cases(67)(lambda p: one())
cls(112, 'C', 'r0 = s8[C] (C in ROM, odd address)')(m_romb)
cases(112)(lambda p: one())


# ---- 44: u16[A] = F(r4 & 0xFF) (F = 0x0BE9A0) ---------------------------------------------------
@cls(44, 'F A', 'r0 = F(r4 = r4 & 0xFF); u16[A] = r0  (F = 0x0BE9A0)', targets=lambda p: {p['F']}, real=True)
def m44(p, I, x):
    if I.real:
        r = lib_pair8(I.R[4] & 0xFF)
    else:
        x.call(p['F'], 'call', r4=I.R[4] & 0xFF)
        r = I.ret(p['F'])[0]
    x.st(p['A'], 2, r)
    x.r(0, r)


cases(44)(lambda p: [dict(regs={4: v}) for v in (0, 0x5A, 0xFF, 0x12345680)])


# ---- 46: u8[A] = V ----------------------------------------------------------------------------------
@cls(46, 'A V', 'u8[A] = V')
def m46(p, I, x):
    x.st(p['A'], 1, p['V'])


cases(46)(lambda p: one())


# ---- 47: F(A1, 0.0); tail F2(A2, 0.0) ----------------------------------------------------------------
@cls(47, 'A1 F A2 F2', 'call F with r4 = A1, fr4 = 0.0; tail-call F2 with r4 = A2, fr4 = 0.0',
     targets=lambda p: {p['F'], p['F2']})
def m47(p, I, x):
    x.call(p['F'], 'call', r4=p['A1'], fr4=F0)
    x.call(p['F2'], 'tail', r4=p['A2'], fr4=F0)


cases(47)(lambda p: one())


# ---- 48: u16[A] = F(V); u8[B] = V2 -------------------------------------------------------------------
@cls(48, 'F V A V2 B', 'r0 = F(r4 = V); u16[A] = r0; u8[B] = V2  (F = 0x0BE9A0)', targets=lambda p: {p['F']},
     real=True)
def m48(p, I, x):
    if I.real:
        r = lib_pair8(p['V'] & M32)
    else:
        x.call(p['F'], 'call', r4=p['V'] & M32)
        r = I.ret(p['F'])[0]
    x.st(p['A'], 2, r)
    x.st(p['B'], 1, p['V2'])
    x.r(0, r)


cases(48)(lambda p: [dict(rets={p['F']: (0xABCD1234, 0)})])


# ---- 49: r = F() & 0xFF; if r == K tail-call G else return r ----------------------------------------
@cls(49, 'F K G', 'r = F() & 0xFF; if r == K: tail-call G (r0 = r) else return r',
     targets=lambda p: {p['F'], p['G']})
def m49(p, I, x):
    r = I.ret(p['F'])[0] & 0xFF
    x.call(p['F'], 'call')
    if r == (p['K'] & M32):
        x.call(p['G'], 'tail', r0=r)
        x.r(0, I.ret(p['G'])[0])
    else:
        x.r(0, r)


cases(49)(lambda p: [dict(rets={p['F']: (v, 0)}) for v in (1, 0x101, 0, 2, 0xFF)])


# ---- 54 / 118 / 122: call F, then fall through into F ---------------------------------------------
@cls(54, 'R1 F R2', 'call F with r4 = R1, then fall through into F (the next function) with r4 = R2',
     targets=lambda p: {p['F']})
def m54(p, I, x):
    check(p['F'] == I.entry + 12, 'bsr target is the address right after the member')
    x.call(p['F'], 'call', r4=p['R1'])
    x.call(p['F'], 'tail', r4=p['R2'])


cases(54)(lambda p: one())


@cls(118, 'R1 F V1 R2 V2', 'call F(r4 = R1, r5 = V1), then fall through into F(r4 = R2, r5 = V2)',
     targets=lambda p: {p['F']})
def m118(p, I, x):
    check(p['F'] == I.entry + 14, 'bsr target is the address right after the member')
    x.call(p['F'], 'call', r4=p['R1'], r5=p['V1'] & M32)
    x.call(p['F'], 'tail', r4=p['R2'], r5=p['V2'] & M32)


cases(118)(lambda p: one())


@cls(122, 'V1 F U1 V2 U2', 'call F(r4 = U1, r5 = V1), then fall through into F(r4 = U2, r5 = V2)',
     targets=lambda p: {p['F']})
def m122(p, I, x):
    check(p['F'] == I.entry + 14, 'bsr target is the address right after the member')
    x.call(p['F'], 'call', r4=p['U1'] & M32, r5=p['V1'] & M32)
    x.call(p['F'], 'tail', r4=p['U2'] & M32, r5=p['V2'] & M32)


cases(122)(lambda p: one())


# ---- 55: if (u8[r4 + D] & 7) == 0 tail-jump J(r4 = R4, r5 = R5, r6 = R6) else return ------------
@cls(55, 'D M R6 R4 J R5', 'b = u8[r4 + D]; if (b & M) == 0 (M = 0xFFFFFF07, so b & 7): tail-jump J with '
     'r4 = R4, r5 = R5, r6 = R6; else return; r0 = b either way', targets=lambda p: {p['J']})
def m55(p, I, x):
    b = I.m.u8(I.R[4] + p['D'])
    if b & p['M'] == 0:
        x.call(p['J'], 'tail', r4=p['R4'], r5=p['R5'] & M32, r6=p['R6'], r0=b)
        x.r(0, I.ret(p['J'])[0])
    else:
        x.r(0, b)


cases(55)(lambda p: [dict(regs={4: 0xFFFF9000}, ram=[(0xFFFF9001, 1, v)])
                     for v in (0x00, 0x08, 0xF8, 0x01, 0x04, 0x07, 0xFF)])


# ---- 56 / 109 / 116: call F; tail-call G ------------------------------------------------------------
def m_ftg(p, I, x):
    x.call(p['F'], 'call')
    x.call(p['G'], 'tail')
    x.r(0, I.ret(p['G'])[0])


for _c in (56, 109, 116):
    cls(_c, 'F G', 'call F; tail-call G (no arguments set)', targets=lambda p: {p['F'], p['G']})(m_ftg)
    cases(_c)(lambda p: one())


# ---- 57: read16 P; write16 P = K; tail-jump G(r4 = P) ---------------------------------------------
@cls(57, 'P K G', 'u16 read of P (left in r3); u16[P] = K; tail-call G with r4 = P',
     targets=lambda p: {p['G']})
def m57(p, I, x):
    x.pr.append((p['P'], 2))
    x.pw.append((p['P'], 2, p['K'] & 0xFFFF))
    x.call(p['G'], 'tail', r4=p['P'], r2=p['K'], r3=p['G'])


cases(57)(lambda p: [dict(pv={p['P']: v}) for v in (0x0000, 0xFFFF)])


# ---- 58: read16 P; write16 P = K; tail-jump G(r4 = V) ---------------------------------------------
@cls(58, 'P K G V', 'u16 read of P; u16[P] = K & 0xFFFF; tail-call G with r4 = V', targets=lambda p: {p['G']})
def m58(p, I, x):
    x.pr.append((p['P'], 2))
    x.pw.append((p['P'], 2, p['K'] & 0xFFFF))
    x.call(p['G'], 'tail', r4=p['V'] & M32)


cases(58)(lambda p: [dict(pv={p['P']: v}) for v in (0x0000, 0xFFFF)])


# ---- 59: u8[P] &= M; tail-jump G(r3 = P) -----------------------------------------------------------
@cls(59, 'P M G', 'u8[P] = u8[P] & M; tail-call G with r3 = P', targets=lambda p: {p['G']})
def m59(p, I, x):
    x.pr.append((p['P'], 1))
    x.pw.append((p['P'], 1, I.pv & p['M']))
    x.call(p['G'], 'tail', r3=p['P'])


cases(59)(lambda p: [dict(pv={p['P']: v}) for v in (0x00, 0xFF, 0x80, 0x7F)])


# ---- 60: r = F(); u8[A] = V; return r ---------------------------------------------------------------
@cls(60, 'F V A', 'r = F(); u8[A] = V; return r', targets=lambda p: {p['F']})
def m60(p, I, x):
    x.call(p['F'], 'call')
    x.st(p['A'], 1, p['V'])
    x.r(0, I.ret(p['F'])[0])


cases(60)(lambda p: one())


# ---- 61: u16[A] = V ---------------------------------------------------------------------------------
@cls(61, 'V A', 'u16[A] = V & 0xFFFF')
def m61(p, I, x):
    x.st(p['A'], 2, p['V'])


cases(61)(lambda p: one())


# ---- 62: u8[A + D] = u8[A]; r0 = s8[A] ----------------------------------------------------------------
@cls(62, 'A D', 'u8[A+D] = u8[A]; r0 = s8[A]')
def m62(p, I, x):
    x.st(p['A'] + p['D'], 1, I.m.u8(p['A']))
    x.r(0, I.m.s8(p['A']))


cases(62)(lambda p: byte_cases(p['A']))


# ---- 63: f32[A] = 1.0 --------------------------------------------------------------------------------
@cls(63, 'A', 'f32[A] = 1.0')
def m63(p, I, x):
    x.st(p['A'], 4, F1)


cases(63)(lambda p: one())


# ---- 64: u8[A] = u8[A + D] = V -------------------------------------------------------------------------
@cls(64, 'V A D', 'u8[A] = u8[A+D] = V & 0xFF; r0 = V (sign-extended)')
def m64(p, I, x):
    x.st(p['A'], 1, p['V'])
    x.st(p['A'] + p['D'], 1, p['V'])
    x.r(0, p['V'])


cases(64)(lambda p: one())


# ---- 65 / 101: if u8[A] == 0 tail-call G else return ---------------------------------------------------
def m_zg(p, I, x):
    if I.m.s8(p['A']) == 0:
        x.call(p['G'], 'tail')
        x.r(0, I.ret(p['G'])[0])


cls(65, 'A G', 'if u8[A] == 0: tail-call G; else return', targets=lambda p: {p['G']})(m_zg)
cases(65)(lambda p: byte_cases(p['A']))
cls(101, 'A G', 'if u8[A] == 0: tail-call G; else return', targets=lambda p: {p['G']})(m_zg)
cases(101)(lambda p: byte_cases(p['A']))


# ---- 66 / 100: u8[B] = (u8[A] == K) -----------------------------------------------------------------
def m_eqflag(p, I, x):
    x.st(p['B'], 1, 1 if I.m.s8(p['A']) == p['K'] else 0)


cls(66, 'A K B', 'u8[B] = 1 if u8[A] == K else 0')(m_eqflag)
cases(66)(lambda p: byte_cases(p['A']))
cls(100, 'A K B', 'u8[B] = 1 if u8[A] == K else 0')(m_eqflag)
cases(100)(lambda p: byte_cases(p['A']))


# ---- 70: if u8[A] == K: u8[B] = V --------------------------------------------------------------------
@cls(70, 'A K V B', 'if u8[A] == K: u8[B] = V')
def m70(p, I, x):
    if I.m.s8(p['A']) == p['K']:
        x.st(p['B'], 1, p['V'])


cases(70)(lambda p: byte_cases(p['A'], (0, 1, 2, 0x81, 0xFF)))


# ---- 71: u8[A] = r4; u8[A+D] = r5 -------------------------------------------------------------------
@cls(71, 'A D', 'u8[A] = r4 & 0xFF; u8[A+D] = r5 & 0xFF; r0 = r5')
def m71(p, I, x):
    x.st(p['A'], 1, I.R[4])
    x.st(p['A'] + p['D'], 1, I.R[5])
    x.r(0, I.R[5])


cases(71)(lambda p: [dict(regs={4: 0x123456AB, 5: 0xFEDCBA01}), dict(regs={4: 0, 5: 0xFF})])


# ---- 72: u16[A] = V1; u8[A+D] = V2 ------------------------------------------------------------------
@cls(72, 'V1 A V2 D', 'u16[A] = V1; u8[A+D] = V2; r0 = V2')
def m72(p, I, x):
    x.st(p['A'], 2, p['V1'])
    x.st(p['A'] + p['D'], 1, p['V2'])
    x.r(0, p['V2'])


cases(72)(lambda p: one())


# ---- 75: r15 = SP; jmp @r4 --------------------------------------------------------------------------
@cls(75, 'SP', 'r15 = SP; jump to the address in r4 (r4 is the argument; nothing returns here)',
     targets=lambda p: {0x0F0000})
def m75(p, I, x):
    x.call(I.R[4], 'tail', r15=p['SP'])


cases(75)(lambda p: one(regs={4: 0x0F0000}))


# ---- 76: busy-wait ------------------------------------------------------------------------------------
@cls(76, 'V0 V1', 'n = (r4 << 3) mod 2^32; count r5 from 0 up to n (n iterations); r4 = n, r5 = n; r0 untouched')
def m76(p, I, x):
    n = (I.R[4] << 3) & M32
    x.r(4, n)
    x.r(5, n)
    x.r(0, I.R[0])


cases(76)(lambda p: [dict(regs={4: v, 0: 0xC0FFEE}) for v in (0, 1, 2, 7, 0x20000000, 0x20000001)])


# ---- 77: p = F(r4, r5 = R5); return u8[p + D] & M ---------------------------------------------------
@cls(77, 'F R5 D M', 'q = F(r4 unchanged, r5 = R5); r0 = u8[q + D] & M', targets=lambda p: {p['F']})
def m77(p, I, x):
    q = I.ret(p['F'])[0]
    x.call(p['F'], 'call', r4=I.R[4], r5=p['R5'] & M32)
    x.r(0, I.m.u8(q + p['D']) & p['M'])
    x.r(4, q)


cases(77)(lambda p: [dict(regs={4: 0x11}, rets={p['F']: (0xFFFF9100, 0)}, ram=[(0xFFFF9101, 1, v)])
                     for v in (0x00, 0x0F, 0xF3, 0xFF)])


# ---- 78: fragment: r0 = V; pop r2; return -----------------------------------------------------------
@cls(78, 'V', 'FRAGMENT (not a function): r0 = V; r2 = long popped from @r15; return')
def m78(p, I, x):
    x.r(0, p['V'])
    x.r(2, 0xDEADBEEF)


cases(78)(lambda p: one(regs={15: STACK_TOP - 4}, ram=[(STACK_TOP - 4, 4, 0xDEADBEEF)]))


# ---- 79: F(sext8(r4)); tail G(sext8(r4)) --------------------------------------------------------------
@cls(79, 'S1 F S2 G', 'b = sext8(r4); call F(r4 = b); tail-call G(r4 = b)', targets=lambda p: {p['F'], p['G']})
def m79(p, I, x):
    check(p['S1'] == -4 and p['S2'] == 4, '4-byte frame')
    b = sx8(I.R[4]) & M32
    x.call(p['F'], 'call', r4=b)
    x.call(p['G'], 'tail', r4=b)


cases(79)(lambda p: [dict(regs={4: v}) for v in (0x12345605, 0x80, 0xFF, 0)])


# ---- 80: u8[A + (r4 & 0xFF)] = V --------------------------------------------------------------------
@cls(80, 'A V', 'u8[A + (r4 & 0xFF)] = V')
def m80(p, I, x):
    x.st(p['A'] + (I.R[4] & 0xFF), 1, p['V'])


cases(80)(lambda p: [dict(regs={4: v}) for v in (0, 1, 0x7F, 0xFF, 0x12345603)])


# ---- 81: u8[A] = r4 ---------------------------------------------------------------------------------
@cls(81, 'A', 'u8[A] = r4 & 0xFF')
def m81(p, I, x):
    x.st(p['A'], 1, I.R[4])


cases(81)(lambda p: [dict(regs={4: v}) for v in (0, 0x1FF, 0x80)])


# ---- 82: tail G(r4 = P, r5 = V) --------------------------------------------------------------------
@cls(82, 'P G V', 'tail-call G with r4 = P, r5 = V', targets=lambda p: {p['G']})
def m82(p, I, x):
    x.call(p['G'], 'tail', r4=p['P'], r5=p['V'] & M32)


cases(82)(lambda p: one())


# ---- 83 / 84: u32[P] &= M; tail G(r4 = C) ---------------------------------------------------------
def m_and32(p, I, x):
    x.pr.append((p['P'], 4))
    x.pw.append((p['P'], 4, I.pv & (p['M'] & M32)))
    x.call(p['G'], 'tail', r4=p['C'] & M32)


cls(83, 'P M G C', 'u32[P] = u32[P] & M (M = 0xFFFFFFFD: clear bit 1); tail-call G with r4 = C',
    targets=lambda p: {p['G']})(m_and32)
cases(83)(lambda p: [dict(pv={p['P']: v}) for v in (0xFFFFFFFF, 0x00000002, 0x12345678)])
cls(84, 'M P G C', 'u32[P] = u32[P] & M (M = 0xFFFFFFFD: clear bit 1); tail-call G with r4 = C',
    targets=lambda p: {p['G']})(m_and32)
cases(84)(lambda p: [dict(pv={p['P']: v}) for v in (0xFFFFFFFF, 0x00000002, 0x12345678)])


# ---- 85: read16 P; write16 P = K; F(V); tail G -----------------------------------------------------
@cls(85, 'P K F V G', 'u16 read of P; u16[P] = K; call F(r4 = V); tail-call G', targets=lambda p: {p['F'], p['G']})
def m85(p, I, x):
    x.pr.append((p['P'], 2))
    x.pw.append((p['P'], 2, p['K'] & 0xFFFF))
    x.call(p['F'], 'call', r4=p['V'] & M32)
    x.call(p['G'], 'tail')


cases(85)(lambda p: [dict(pv={p['P']: v}) for v in (0x0000, 0xFFFF)])


# ---- 86 / 87: u8[P] = (u8[P] & M) | K; tail G(r4 = P) ------------------------------------------------
def m_rmw_g(p, I, x):
    x.pr.append((p['P'], 1))
    x.pw.append((p['P'], 1, (I.pv & p['M']) | p['K']))
    x.call(p['G'], 'tail', r4=p['P'])


cls(86, 'P M G K', 'u8[P] = (u8[P] & M) | K; tail-call G with r4 = P', targets=lambda p: {p['G']})(m_rmw_g)
cases(86)(lambda p: [dict(pv={p['P']: v}) for v in (0x00, 0xFF, 0x3D)])
cls(87, 'P M K G', 'u8[P] = (u8[P] & M) | K; tail-call G with r4 = P', targets=lambda p: {p['G']})(m_rmw_g)
cases(87)(lambda p: [dict(pv={p['P']: v}) for v in (0x00, 0xFF, 0x3D)])


# ---- 88: u16[P] = K; tail G(r4 = C) ------------------------------------------------------------------
@cls(88, 'K P C G', 'u16[P] = K & 0xFFFF (no read); tail-call G with r4 = C', targets=lambda p: {p['G']})
def m88(p, I, x):
    x.pw.append((p['P'], 2, p['K'] & 0xFFFF))
    x.call(p['G'], 'tail', r4=p['C'])


cases(88)(lambda p: one())


# ---- 89 / 103 / 106: readers -----------------------------------------------------------------------
@cls(89, 'A', 'r0 = s16[A]')
def m89(p, I, x):
    x.r(0, I.m.s16(p['A']))


cases(89)(lambda p: [dict(ram=[(p['A'], 2, v)]) for v in (0x0000, 0x7FFF, 0x8000, 0xFFFF)])


@cls(103, 'A', 'fr0 = f32[A]')
def m103(p, I, x):
    x.f(0, I.m.fb(p['A']))


cases(103)(lambda p: [dict(ram=[(p['A'], 4, b)]) for b in (0x3F800000, 0xFF800000, 0x7FC00000)])


@cls(106, 'A', 'r0 = u32[A]')
def m106(p, I, x):
    x.r(0, I.m.u32(p['A']))


cases(106)(lambda p: [dict(ram=[(p['A'], 4, v)]) for v in (0, 0xFFFFFFFF, 0x12345678)])


# ---- 90: tail G(r4 = R4, r5 = R5, r6 = R6) -----------------------------------------------------------
@cls(90, 'R5 G R6 R4', 'tail-call G with r4 = R4, r5 = R5, r6 = R6', targets=lambda p: {p['G']})
def m90(p, I, x):
    x.call(p['G'], 'tail', r4=p['R4'] & M32, r5=p['R5'], r6=p['R6'] & M32)


cases(90)(lambda p: one())


# ---- 91: tail G(r4 = A, r5 = R5) ---------------------------------------------------------------------
@cls(91, 'A G R5', 'tail-call G with r4 = A, r5 = R5 (= 0)', targets=lambda p: {p['G']}, real=True)
def m91(p, I, x):
    if I.real and p['G'] == 0x0BDB80:
        x.st(p['A'], 2, p['R5'])
        x.st(p['A'] + 2, 2, ~p['R5'])
        x.r(0, 0)
    else:
        x.call(p['G'], 'tail', r4=p['A'], r5=p['R5'] & M32)


cases(91)(lambda p: one())


# ---- 92: u8[B] = !(C > f32[X]) ------------------------------------------------------------------------
@cls(92, 'X C XK B', 'u8[B] = 0 if (f32@C > f32[X]) else 1  (fcmp/gt; NaN gives 1); r0 = same')
def m92(p, I, x):
    xv, cv = bf(I.m.fb(p['X'])), bf(rl(p['C']))
    t = 1 if (cv > xv) else 0                  # Python: comparisons with NaN are False
    r = t ^ p['XK']
    x.st(p['B'], 1, r)
    x.r(0, r)


def c92(p):
    c = rl(p['C'])
    vals = [c - 1, c, c + 1, 0x00000000, 0xC1200000, 0x7F7FFFFF, 0x7FC00000]
    return [dict(ram=[(p['X'], 4, v & M32)]) for v in vals]


cases(92)(c92)


# ---- 94: u8[A+D] = (u8[A] & K) != 0 -------------------------------------------------------------------
@cls(94, 'A K XK D', 'u8[A+D] = 1 if (u8[A] & K) != 0 else 0; r0 = same')
def m94(p, I, x):
    t = 1 if (I.m.u8(p['A']) & p['K']) == 0 else 0
    r = t ^ p['XK']
    x.st(p['A'] + p['D'], 1, r)
    x.r(0, r)


cases(94)(lambda p: byte_cases(p['A'], (0x00, 0xFF, p['K'], 0xFF ^ p['K'])))


# ---- 96 / 102: f32[B] = lookup1D(R, f32[X]) --------------------------------------------------------
def m_lookup(p, I, x):
    xb = I.m.fb(p['X'])
    if I.real:
        x.approx.append((p['B'], lib_lookup1d(p['R'], xb), 1e-5))
    else:
        x.call(p['F'], 'call', r4=p['R'], fr4=xb)
        x.st(p['B'], 4, I.ret(p['F'])[1])


def c_lookup(p):
    ax = DT.read_table(ROM, p['R'])['axes']['x']
    xs = [ax[0] - 5, ax[0], (ax[0] + ax[1]) / 2, ax[len(ax) // 2], ax[-1], ax[-1] + 7]
    return [dict(ram=[(p['X'], 4, fb(v))], rets={p['F']: (0, 0x3F400000)}) for v in xs]


cls(96, 'X R F B', 'fr0 = F(r4 = R, fr4 = f32[X]); f32[B] = fr0  (F = 0x0BE830, 1-D lookup)',
    targets=lambda p: {p['F']}, real=True)(m_lookup)
cases(96)(c_lookup)
cls(102, 'X R F B', 'fr0 = F(r4 = R, fr4 = f32[X]); f32[B] = fr0  (F = 0x0BE830, 1-D lookup)',
    targets=lambda p: {p['F']}, real=True)(m_lookup)
cases(102)(c_lookup)


# ---- 97: f32[B+OFF] = f32[A]; f32[B] = f32[C] ---------------------------------------------------------
@cls(97, 'A B OFF C', 'f32[B+OFF] = f32[A]; then f32[B] = f32[C]  (OFF = -4)')
def m97(p, I, x):
    check(not ({p['C'] + i for i in range(4)} & {p['B'] + p['OFF'] + i for i in range(4)}), 'no overlap')
    x.st(p['B'] + p['OFF'], 4, I.m.fb(p['A']))
    x.st(p['B'], 4, I.m.fb(p['C']))


cases(97)(lambda p: [dict(ram=[(p['A'], 4, 0x3F800000), (p['C'], 4, 0xC0000000)])])


# ---- 98: tail F(r4 = A, fr4 = f32[C]) ------------------------------------------------------------------
@cls(98, 'A F C', 'tail-call F with r4 = A, fr4 = f32[C] (C in ROM calibration)', targets=lambda p: {p['F']})
def m98(p, I, x):
    x.call(p['F'], 'tail', r4=p['A'], fr4=rl(p['C']))


cases(98)(lambda p: one())


# ---- 99: zero three floats --------------------------------------------------------------------------
@cls(99, 'A O1 O2', 'f32[A+O1] = 0.0; f32[A+O2] = f32[A+O1] (= 0.0); f32[A] = 0.0  (O1 = -8, O2 = -12)')
def m99(p, I, x):
    x.st(p['A'] + p['O1'], 4, F0)
    x.st(p['A'] + p['O2'], 4, F0)
    x.st(p['A'], 4, F0)


cases(99)(lambda p: one())


# ---- 104: u8[A+D] = (u8[A] < N) -------------------------------------------------------------------------
@cls(104, 'A N XK D', 'u8[A+D] = 1 if u8[A] < N else 0 (cmp/hs on the SIGN-extended byte); r0 = same')
def m104(p, I, x):
    r2 = I.m.s8(p['A']) & M32
    t = 1 if r2 >= (p['N'] & M32) else 0
    r = t ^ p['XK']
    x.st(p['A'] + p['D'], 1, r)
    x.r(0, r)


cases(104)(lambda p: byte_cases(p['A'], (0, 7, 8, 9, 0x7F, 0x80, 0xFF)))


# ---- 105: u8[B] = (u8[A] == K) ? V1 : V0; tail G --------------------------------------------------------
@cls(105, 'A K V0 V1 B G', 'u8[B] = V1 if u8[A] == K else V0; tail-call G', targets=lambda p: {p['G']})
def m105(p, I, x):
    x.st(p['B'], 1, p['V1'] if I.m.s8(p['A']) == p['K'] else p['V0'])
    x.call(p['G'], 'tail')


cases(105)(lambda p: byte_cases(p['A'], (0, 1, 2, 0xFF)))


# ---- 107: F1(); F2(); u16[A] = V ------------------------------------------------------------------------
@cls(107, 'F1 F2 V A', 'call F1; call F2; u16[A] = V & 0xFFFF', targets=lambda p: {p['F1'], p['F2']})
def m107(p, I, x):
    x.call(p['F1'], 'call')
    x.call(p['F2'], 'call')
    x.st(p['A'], 2, p['V'])


cases(107)(lambda p: one())


# ---- 108: u8[A] = (u8[A] & M) | K ------------------------------------------------------------------
@cls(108, 'A M K', 'u8[A] = (u8[A] & M) | K')
def m108(p, I, x):
    x.st(p['A'], 1, (I.m.u8(p['A']) & p['M']) | p['K'])


cases(108)(lambda p: byte_cases(p['A'], (0x00, 0xFF, 0x0F, 0xF0)))


# ---- 110: u8[A] = u8[A+D1] = u8[A+D2] = r4 -----------------------------------------------------------
@cls(110, 'A D1 D2', 'u8[A] = u8[A+D1] = u8[A+D2] = r4 & 0xFF; r0 = r4')
def m110(p, I, x):
    for d in (0, p['D1'], p['D2']):
        x.st(p['A'] + d, 1, I.R[4])
    x.r(0, I.R[4])


cases(110)(lambda p: [dict(regs={4: v}) for v in (0, 0x1FF, 0xA5)])


# ---- 111: critical section around u8[A] += INC ------------------------------------------------------
@cls(111, 'EN MASK A INC LV', 'm = EN(r4 = MASK); u8[A] = u8[A] + INC (mod 256); tail-call LV(r4 = m)',
     targets=lambda p: {p['EN'], p['LV']})
def m111(p, I, x):
    m = I.ret(p['EN'])[0]
    x.call(p['EN'], 'call', r4=p['MASK'] & M32)
    x.st(p['A'], 1, I.m.u8(p['A']) + p['INC'])
    x.call(p['LV'], 'tail', r4=m)


cases(111)(lambda p: [dict(rets={p['EN']: (m, 0)}, ram=[(p['A'], 1, v)])
                      for m, v in ((0x00, 0x00), (0xF0, 0xFF), (0x10, 0x7F))])


# ---- 115: f32[A+OFF] = f32[A] = 1.0 ----------------------------------------------------------------
@cls(115, 'A OFF', 'f32[A+OFF] = 1.0; f32[A] = 1.0  (OFF = -4)')
def m115(p, I, x):
    x.st(p['A'] + p['OFF'], 4, F1)
    x.st(p['A'], 4, F1)


cases(115)(lambda p: one())


# ---- 117: u32[A] = F(r4 & 0xFFFF) (F = 0x0BE9B0) ------------------------------------------------------
@cls(117, 'F A', 'r0 = F(r4 = r4 & 0xFFFF); u32[A] = r0  (F = 0x0BE9B0)', targets=lambda p: {p['F']}, real=True)
def m117(p, I, x):
    if I.real:
        r = lib_pair16(I.R[4] & 0xFFFF)
    else:
        x.call(p['F'], 'call', r4=I.R[4] & 0xFFFF)
        r = I.ret(p['F'])[0]
    x.st(p['A'], 4, r)
    x.r(0, r)


cases(117)(lambda p: [dict(regs={4: v}) for v in (0, 0x5A5A, 0xFFFF, 0x12348001)])


# ---- 119 / 120 / 121: constant byte runs ------------------------------------------------------------
@cls(119, 'V A D1 D2 D3', 'u8[A] = u8[A+D1] = u8[A+D2] = u8[A+D3] = V; r0 = V')
def m119(p, I, x):
    for d in (0, p['D1'], p['D2'], p['D3']):
        x.st(p['A'] + d, 1, p['V'])
    x.r(0, p['V'])


cases(119)(lambda p: one())


@cls(120, 'V0 A D1 D2 D3 V1 D4 D5 D6 D7', 'u8[A], u8[A+D1..D3] = V0; u8[A+D4..D7] = V1; r0 = V1')
def m120(p, I, x):
    for d in (0, p['D1'], p['D2'], p['D3']):
        x.st(p['A'] + d, 1, p['V0'])
    for d in (p['D4'], p['D5'], p['D6'], p['D7']):
        x.st(p['A'] + d, 1, p['V1'])
    x.r(0, p['V1'])


cases(120)(lambda p: one())


@cls(121, 'V A D', 'u8[A+D] = V; u8[A] = V; r0 = V')
def m121(p, I, x):
    x.st(p['A'] + p['D'], 1, p['V'])
    x.st(p['A'], 1, p['V'])
    x.r(0, p['V'])


cases(121)(lambda p: one())


# ---- 123: v = u16[A+D]; F(v); tail G(v) -------------------------------------------------------------
@cls(123, 'A D F G', 'v = u16[A+D]; call F(r4 = v); tail-call G(r4 = v); r14 preserved',
     targets=lambda p: {p['F'], p['G']})
def m123(p, I, x):
    v = I.m.u16(p['A'] + p['D'])
    x.call(p['F'], 'call', r4=v, r14=v)
    x.call(p['G'], 'tail', r4=v, r14=I.R[14], r15=STACK_TOP)


cases(123)(lambda p: [dict(regs={14: 0x0BADF00D}, ram=[(p['A'] + p['D'], 2, v)]) for v in (0, 0x8001, 0xFFFF)])


# ---- 124: if u8[A] != u8[B] tail G else return ---------------------------------------------------------
@cls(124, 'A B G', 'if u8[A] != u8[B]: tail-call G (r5 = B); else return', targets=lambda p: {p['G']})
def m124(p, I, x):
    if I.m.s8(p['A']) != I.m.s8(p['B']):
        x.call(p['G'], 'tail', r5=p['B'])


cases(124)(lambda p: [dict(ram=[(p['A'], 1, a), (p['B'], 1, b)])
                      for a, b in ((0, 0), (5, 5), (0xFF, 0xFF), (0, 1), (0x80, 0x7F))])


# ---- 126: u32[A] = K ------------------------------------------------------------------------------------
@cls(126, 'K A', 'u32[A] = K')
def m126(p, I, x):
    x.st(p['A'], 4, p['K'])


cases(126)(lambda p: one())


# ---- 74 / 125: DATA -------------------------------------------------------------------------------------
DATA_CLASSES = {74, 125}
FRAGMENT_CLASSES = {78}


# =====================================================================================
# 5. driver
# =====================================================================================
def run_case(entry, n, p, kdef, case, real, seed):
    em = Emu3(seed)
    for (a, sz, v) in case.get('ram', []):
        em.poke(a, sz, v)
    em.pvals.update(case.get('pv', {}))
    for k in range(16):
        em.R[k] = (0x11110000 * (k + 1) + 0x1111 * k) & M32
        em.FR[k] = 0x40000000 + k * 0x100000
    for k, v in case.get('regs', {}).items():
        em.R[k] = v & M32
    for k, v in case.get('fr', {}).items():
        em.FR[k] = v & M32
    regs0 = list(em.R)
    regs0[15] = case.get('regs', {}).get(15, STACK_TOP)
    fr0 = list(em.FR)
    snapshot = bytes(em.ram)
    rets = case.get('rets', {})
    targets = set(kdef['targets'](p))
    stubbed = {t for t in targets if not (real and t in LIB_REAL)}

    def mkstub(t):
        def fn(e):
            e.calls.append((t, e.pr, list(e.R), list(e.FR)))
            r0, f0 = rets.get(t, (0x5A5A0000 | (t & 0xFFFF), 0x40490FDB))
            e.R[0] = r0 & M32
            e.FR[0] = f0 & M32
        return fn
    for t in stubbed:
        em.stub(t, fn=mkstub(t))
    stop = kdef['stop'](p)
    res = em.call(entry, regs={15: regs0[15]}, stop_at=stop, max_steps=2_000_000)
    end = 'ret' if res == 'return' else 'loop'
    if end == 'loop':
        pc0 = em.pc
        em.step()
        em.step()
        check(em.pc == pc0, f'{entry:06X}: branch-to-self does not return to {pc0:06X}')
    lo, hi = entry, entry + 2 * n
    for pc in em.executed:
        inside = lo <= pc < hi or (real and LIB_RANGE[0] <= pc < LIB_RANGE[1])
        check(inside, f'{entry:06X}: executed {pc:06X} outside the member')
    obs = dict(end=end, writes=dict(em.writes), preads=list(em.preads), pwrites=list(em.pwrites),
               calls=list(em.calls), R=list(em.R), FR=list(em.FR), em=em)
    I = Inp(Mem(snapshot), regs0, fr0, rets, real, entry)
    I.pv = case.get('pv', {}).get(p.get('P'), 0)
    return obs, I


def compare(entry, cid, p, kdef, case, real, obs, I):
    x = X()
    ok = kdef['model'](p, I, x)
    if ok is False:
        return None                                   # case unusable for an exact claim (see lib_sat)
    tag = f'{entry:06X} class {cid} case {case} real={real}'
    # RAM writes
    want = {}
    for (a, nb, v) in x.w:
        for i in range(nb):
            want[a + i] = (v >> (8 * (nb - 1 - i))) & 0xFF
    got = dict(obs['writes'])
    for (a, f, tol) in x.approx:
        bts = [got.pop(a + i, None) for i in range(4)]
        check(None not in bts, f'{tag}: float store at {a:08X} missing')
        g = bf(int.from_bytes(bytes(bts), 'big'))
        check(abs(g - f) <= tol * max(1.0, abs(f)), f'{tag}: lookup {g} vs oracle {f}')
    check(got == want, f'{tag}: RAM writes {sorted((hex(k), v) for k, v in got.items())} != '
                       f'{sorted((hex(k), v) for k, v in want.items())}')
    for (a, nb, v) in x.stack:
        check(obs['em'].peek(a, nb) == v, f'{tag}: stack byte {a:08X}')
    check(obs['preads'] == x.pr, f'{tag}: register reads {obs["preads"]} != {x.pr}')
    check(obs['pwrites'] == x.pw, f'{tag}: register writes {obs["pwrites"]} != {x.pw}')
    # calls
    check(len(obs['calls']) == len(x.calls), f'{tag}: {len(obs["calls"])} calls, model {len(x.calls)}')
    for (t, pr, R, FR), (wt, kind, chk) in zip(obs['calls'], x.calls):
        check(t == wt, f'{tag}: call to {t:06X}, model {wt:06X}')
        if kind == 'tail':
            check(pr == RET, f'{tag}: {t:06X} reached with PR {pr:08X}, not the caller\'s return address')
            if 'r15' not in chk:
                check(R[15] == STACK_TOP, f'{tag}: stack not balanced at the tail call')
        else:
            check(entry < pr <= entry + 64, f'{tag}: {t:06X} called with PR {pr:08X}')
        for k, v in chk.items():
            if k.startswith('fr'):
                check(FR[int(k[2:])] == v, f'{tag}: {k} = {FR[int(k[2:])]:08X} at {t:06X}, model {v:08X}')
            else:
                check(R[int(k[1:])] == v & M32, f'{tag}: {k} = {R[int(k[1:])]:08X} at {t:06X}, model {v & M32:08X}')
    check(obs['end'] == x.end, f'{tag}: end {obs["end"]} != {x.end}')
    for k, v in x.regs.items():
        check(obs['R'][k] == v, f'{tag}: r{k} = {obs["R"][k]:08X}, model {v:08X}')
    for k, v in x.fregs.items():
        check(obs['FR'][k] == v, f'{tag}: fr{k} = {obs["FR"][k]:08X}, model {v:08X}')
    if obs['end'] == 'ret' and cid not in FRAGMENT_CLASSES and not x.calls:
        check(obs['R'][15] == STACK_TOP, f'{tag}: r15 not restored')
    if cid in FRAGMENT_CLASSES:
        check(obs['R'][15] == I.R[15] + 4, f'{tag}: fragment pops exactly one long')
    return x


def fmt_obs(obs, x):
    parts = []
    if obs['writes']:
        ws = sorted(obs['writes'].items())
        runs, cur = [], None
        for a, v in ws:
            if cur and a == cur[0] + len(cur[1]):
                cur[1].append(v)
            else:
                cur = [a, [v]]
                runs.append(cur)
        parts.append('W ' + ' '.join(f'{a:08X}={bytes(v).hex()}' for a, v in runs))
    if obs['pwrites']:
        parts.append('PW ' + ' '.join(f'{a:08X}/{n}={v:X}' for a, n, v in obs['pwrites']))
    for (t, pr, R, FR), (wt, kind, chk) in zip(obs['calls'], x.calls):
        a = ','.join(f'{k}={FR[int(k[2:])]:08X}' if k.startswith('fr') else f'{k}={R[int(k[1:])]:X}'
                     for k in chk)
        parts.append(f'{kind}->{t:06X}({a})')
    for k in sorted(x.regs):
        parts.append(f'r{k}={obs["R"][k]:X}')
    for k in sorted(x.fregs):
        parts.append(f'fr{k}={obs["FR"][k]:08X}')
    if obs['end'] == 'loop':
        parts.append('spins')
    return ' '.join(parts) if parts else '(no effect)'


def fmt_case(case):
    s = []
    for a, n, v in case.get('ram', []):
        s.append(f'{a:08X}/{n}={v:X}' + (f'({bf(v):.6g})' if n == 4 and (v >> 23) & 0xFF not in (0, 0xFF) else ''))
    for a, v in case.get('pv', {}).items():
        s.append(f'P{a:08X}={v:X}')
    for k, v in case.get('regs', {}).items():
        s.append(f'r{k}={v:X}')
    for t, (r0, f0) in case.get('rets', {}).items():
        s.append(f'{t:06X}->r0={r0:X}')
    return ' '.join(s) if s else '-'


def params_of(b, names):
    vals = [q for (_, _, _, _, q) in b if q is not None]
    check(len(vals) == len(names), f'{len(vals)} masked fields, names {names}')
    return {nm: q[1] for nm, q in zip(names, vals)}, vals


def describe_param(nm, q):
    k, v, extra = q
    if k == 'A':
        return f'{nm}=@{v:06X}:{ffmt(extra)}'
    if k in ('I',):
        return f'{nm}={v}'
    if k == 'D':
        return f'{nm}=+{v}'
    if k == 'U':
        return f'{nm}={v:#04x}'
    return f'{nm}={v:#x}'


def data_classes(members_by_class, quiet):
    """74 / 125: prove the five words pairs are LONGS indexed by 0x0BE8E4, not code."""
    longs = [u32(0x0BE914 + 4 * i) for i in range(5)]
    want = [0x0BEBC0, 0x0BEC4C, 0x0BEC78, 0x0BEBF0, 0x0BEC1C]
    check(longs == want, 'the five longs at 0x0BE914')
    # who loads 0x0BE914: a PC-relative literal or mova inside 0x0BE8E4..0x0BE914
    refs = []
    for pc in range(0x0BE8E4, 0x0BE914, 2):
        w = u16(pc)
        m, q = shape(pc, w)
        if q and q[0] == 'L' and q[1] == 0x0BE914:
            refs.append((pc, 'literal', q[2]))
        if q and q[0] == 'A' and q[1] == 0x0BE914:
            refs.append((pc, 'mova', q[1]))
    check(refs, 'a reference to 0x0BE914 inside 0x0BE8E4')
    for e in sorted(members_by_class[74] + members_by_class[125]):
        check((e - 0x0BE914) % 4 == 0 and 0x0BE914 <= e < 0x0BE928, f'{e:06X} inside the long table')
        if not quiet:
            print(f'  {e:06X}: long {u32(e):08X} = code pointer (index {(e - 0x0BE914) // 4} -> typecode '
                  f'{4 * ((e - 0x0BE914) // 4):#04x}); NOT a function')
    if not quiet:
        for pc, how, a in refs:
            print(f'  referenced from {pc:06X} ({how}, pool {a:06X})')
    return refs


BRANCH_MN = {'bt', 'bf', 'bt/s', 'bf/s', 'bra', 'bsr', 'braf', 'bsrf', 'jmp', 'jsr', 'rts', 'rte'}


_REFIDX = []


def _ref_index(code_hi=0x0C0000):
    """target -> [(kind, site)] for every 2-aligned 32-bit long in ROM, every bra / bsr / bt / bf / bt/s /
    bf/s target and every mov.w @(disp,PC) word in 0..code_hi (built once)."""
    if not _REFIDX:
        idx = {}
        for a in range(0, len(ROM) - 3, 2):
            idx.setdefault(u32(a), []).append(('long', a))
        for a in range(0, code_hi, 2):
            w = u16(a)
            op = w >> 12
            if op in (0xA, 0xB):
                d = w & 0xFFF
                d = d - 0x1000 if d & 0x800 else d
                idx.setdefault(a + 4 + 2 * d, []).append(('bra/bsr', a))
            elif op == 0x8 and ((w >> 8) & 0xF) in (0x9, 0xB, 0xD, 0xF):
                idx.setdefault(a + 4 + 2 * sx8(w), []).append(('bt/bf', a))
            elif op == 0x9:
                v = u16(a + 4 + (w & 0xFF) * 2)
                if v < 0x8000:                               # sign-extends to a low ROM address
                    idx.setdefault(v, []).append(('mov.w', a))
        _REFIDX.append(idx)
    return _REFIDX[0]


def refs_to(t):
    """Every static reference to address t: an exact 32-bit long anywhere in ROM (2-aligned), a
    bra / bsr / bt / bf / bt/s / bf/s whose target is t, and a mov.w @(disp,PC) whose word is t."""
    return sorted(_ref_index().get(t, []), key=lambda r: r[1])


def asr32(v, n):
    s = v - (1 << 32) if v & 0x80000000 else v
    return (s >> n) & M32


def shift_run(entry, r0, r1, mark):
    em = E.Emu(ROM)
    res = em.call(entry, regs={0: r0, 1: r1 & M32, 2: 0xCAFEF00D}, max_steps=200)
    check(res == 'return', f'{entry:06X} r0={r0:08X} r1={r1}: did not return')
    check(em.R[2] == 0xCAFEF00D and em.R[15] == STACK_TOP, f'{entry:06X}: r2 / r15 not restored')
    return em.R[0], mark in em.executed


SHIFT_VALS = (0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x12345678, 0xDEADBEEF, 0x00008000, 0xFFFF0000)


def fragments(quiet):
    """78: 0x003DA4 is the shift-31 entry of 0x003CB4's signed offset table; 0x003E38 is a bt target
    inside 0x003E14, which has no detected entry (0x003CB4 jumps to its interior 0x003E20)."""
    base = u32(0x003CE8)
    check(base == 0x003D32 and u32(0x003CE4) == 0x003CAC, 'pool words of the computed jmp at 0x003CD2')
    # 003CC6 D207 r2 = 0x3CAC; 003CC8 71E8 add #-24,r1; 003CCA 312C add r2,r1; 003CCC 6210 mov.b @r1,r2 (SIGNED);
    # 003CCE D106 r1 = 0x3D32; 003CD0 312C add r2,r1; 003CD2 412B jmp @r1
    check([u16(0x003CC6 + 2 * i) for i in range(7)] == [0xD207, 0x71E8, 0x312C, 0x6210, 0xD106, 0x312C, 0x412B],
          'index path 0x003CC6..0x003CD2')
    tbl = 0x003CAC - 24                                   # byte address = 0x003C94 + shift count
    targets = [base + sx8(ROM[tbl + i]) for i in range(32)]
    check(targets[31] == 0x003DA4 and targets.count(0x003DA4) == 1 and 0x003CAC + 7 == tbl + 31,
          '0x003DA4 is the shift-31 entry (byte 0x003CB3 = 0x003CAC + 7)')
    check(u16(0x003E1E) == 0x890B and 0x003E1E + 4 + 2 * 0x0B == 0x003E38, 'bt 0x003E38 at 0x003E1E')
    check(u16(0x003CB4) == 0x2F26 and u16(0x003E14) == 0x2F26, 'both routines open with mov.l r2,@-r15')
    # 0x003CB4 reaches 0x003E14 only at its interior 0x003E20
    check(u16(0x003CDC) == 0xD203 and u32(0x003CEC) == 0x003E20 and u16(0x003CDE) == 0x422B,
          '003CDC r2 = 0x003E20; 003CDE jmp @r2')
    check(u32(0x003E34) == 0x003DF4 and u32(0x003E30) == 0x003E3E, 'pool words of the jmp at 0x003E2A')
    t2 = [0x003E3E + sx8(ROM[0x003DF4 + i]) for i in range(32)]
    check(all(ROM[0x003DF4 + i] < 0x80 for i in range(32)) and 0x003E38 not in t2,
          '0x003E14 table offsets all >= 0: 0x003E38 is not a table target')
    r14 = refs_to(0x003E14)
    check(r14 == [], f'no static reference to 0x003E14 ({r14})')
    # a long read by mov.l must be 4-aligned (SH-2E address error otherwise); 2-mod-4 matches are data
    r20 = [r for r in refs_to(0x003E20) if r[0] != 'long' or r[1] % 4 == 0]
    check(r20 == [('long', 0x003CEC)], f'0x003E20 is reached through the pool long 0x003CEC only ({r20})')
    # whole-routine emulation
    n = 0
    for r0 in SHIFT_VALS:
        for r1 in range(-2, 41):
            got, hit = shift_run(0x003CB4, r0, r1, 0x003DA4)
            want = r0 if r1 < 0 else asr32(r0, min(r1, 31))
            check(got == want, f'0x003CB4 r0={r0:08X} r1={r1}: {got:08X} != asr {want:08X}')
            check(hit == (bool(r0 & 0x80000000) and r1 == 31), f'0x003CB4 r0={r0:08X} r1={r1}: 0x003DA4 use')
            got, hit = shift_run(0x003E14, r0, r1, 0x003E38)
            want = r0 if r1 < 0 else (0 if r1 >= 32 else r0 >> r1)
            check(got == want, f'0x003E14 r0={r0:08X} r1={r1}: {got:08X} != lsr {want:08X}')
            check(hit == (r1 >= 32), f'0x003E14 r0={r0:08X} r1={r1}: 0x003E38 use')
            n += 2
    if not quiet:
        print('  0x003CD2 jmp @r1: target = 0x003D32 + s8[0x003C94 + count] -> ' +
              ' '.join(f'{t:06X}' for t in targets))
        print('  0x003DA4 = count-31 entry, reached only with r0 < 0 (r0 >= 0 and count > 8 jmp to 0x003E20)')
        print('  0x003E1E bt 0x003E38 (count >= 32) inside 0x003E14; no static reference to 0x003E14; '
              '0x003E20 via pool long 0x003CEC (jmp at 0x003CDE)')
        print(f'  emulated {n} runs: 0x003CB4 = arithmetic r0 >> r1 (r1 >= 32: sign fill; r1 < 0: unchanged), '
              '0x003DA4 executed exactly when r0 < 0 and r1 = 31; 0x003E14 (entered at its first word) = '
              'logical r0 >> r1 (r1 >= 32: 0), 0x003E38 executed exactly when r1 >= 32')
    return n


def vectors(entries):
    vbr = u32(0x00FCC4)
    check(vbr == 0x000FFC50, 'literal loaded into VBR at 0x00FA40')
    check(u16(0x00FA3E) == 0xD2A1 and u16(0x00FA40) == 0x422E, 'mov.l @(0x00FCC4),r2 / ldc r2,vbr')
    out = {}
    for e in entries:
        out[e] = [(a - vbr) // 4 for a in range(vbr, 0x100000, 4) if u32(a) == e]
        # nowhere else: every exact 32-bit occurrence of the member address is a slot of that table
        anywhere = [a for k, a in refs_to(e) if k == 'long']
        check(anywhere == [vbr + 4 * v for v in out[e]], f'{e:06X}: a long outside 0x0FFC50 ({anywhere})')
        check(all(k == 'long' for k, _ in refs_to(e)), f'{e:06X}: a branch reaches it')
        # and not in the address-0 table (used while VBR = 0, e.g. after 0x001350 ldc r2,vbr with r2 = 0)
        check(all(u32(4 * v) != e for v in range(256)), f'{e:06X} in the address-0 table')
    return vbr, out


IRQ_CLASSES = {32, 33, 57, 58, 59, 83, 84, 85, 86, 87, 88}
CODE_IS_VECTOR = {32, 33, 83, 84, 88}         # classes that pass r4 = C to 0x00E774
STUB_WORDS = [0x2F06, 0xD004, 0x4F22, 0x400B, 0x2F16, 0xD101, 0x412B, 0x402A]
PROLOGUE = 0x002B8C
PR_EXIT = None                                # set in main() from prologue_r0(): 0x002BD4


def prologue_r0():
    """0x002B8C (contract in rtos_core_trace.txt) re-checked: no branch before its rts at 0x002BC6, and
    the last r0 write is 0x002BC4 mov.l @(0x002BD0),r0 with u32[0x002BD0] = 0x00002BD4 (slot = nop)."""
    for pc in range(PROLOGUE, 0x002BC6, 2):
        mn = decode(u16(pc), pc)[0].split()[0].lower()
        check(mn not in BRANCH_MN, f'{pc:06X}: branch {mn} inside 0x002B8C')
    check(u16(0x002BC4) == 0xD002 and ((0x002BC4 + 4) & ~3) + 2 * 4 == 0x002BD0, '002BC4 mov.l @(0x002BD0),r0')
    check(u16(0x002BC6) == 0x000B and u16(0x002BC8) == 0x0009, '002BC6 rts / 002BC8 nop')
    check(u32(0x002BD0) == 0x00002BD4, 'u32[0x002BD0] = 0x00002BD4')
    return u32(0x002BD0)


def irq_vectors(entry):
    """Vectors v whose slot u32[0x0FFC50 + 4v] holds a 24-byte stub with the fixed code words and
    u32[stub + 16] == entry.  The two pool loads are re-resolved PC-relative and checked."""
    out = []
    for v in range((0x100000 - 0x0FFC50) // 4):
        stub = u32(0x0FFC50 + 4 * v)
        if stub & 1 or stub + 24 > 0x100000:
            continue
        if [u16(stub + 2 * k) for k in range(8)] != STUB_WORDS:
            continue
        lit_r1 = ((stub + 10 + 4) & ~3) + (u16(stub + 10) & 0xFF) * 4      # D101 at stub+10
        lit_r0 = ((stub + 2 + 4) & ~3) + (u16(stub + 2) & 0xFF) * 4        # D004 at stub+2
        if u32(lit_r1) == entry:
            check(lit_r1 == stub + 16 and lit_r0 == stub + 20 and u32(lit_r0) == PROLOGUE,
                  f'stub {stub:06X}: member at +16, 0x002B8C at +20')
            check((stub - 0x00207C) % 24 == 0 and 0x00207C <= stub < 0x00207C + 24 * 118,
                  f'stub {stub:06X} is one of the 118 at 0x00207C + 24k')
            out.append((v, stub))
    return out


def irq_entry(e, p, kdef, stub, pr_exit, seed):
    """Run the STUB (not the member) with 0x002B8C stubbed to its contract (r0 = 0x002BD4) and the
    member's callees recorded.  Returns the list of (target, PR, r15) at each callee."""
    em = Emu3(seed)
    seen = []

    def pro(emu):
        seen.append((PROLOGUE, emu.pr, emu.R[15]))
        emu.R[0] = pr_exit
    em.stub(PROLOGUE, fn=pro)
    for t in kdef['targets'](p):
        em.stub(t, fn=lambda emu, t=t: seen.append((t, emu.pr, emu.R[15])))
    res = em.call(stub, stop_at={pr_exit}, max_steps=200)
    check(res == pr_exit, f'{e:06X}: stub {stub:06X} run did not end at {pr_exit:06X}')
    check(e in em.executed, f'{e:06X}: member not entered from stub {stub:06X}')
    check(seen[0] == (PROLOGUE, stub + 10, STACK_TOP - 12), f'{e:06X}: 0x002B8C call from stub {seen[0]}')
    tail = seen[-1]
    check(tail[0] == p['G'] and tail[1] == pr_exit and tail[2] == STACK_TOP - 12,
          f'{e:06X}: tail target {tail[0]:06X} PR {tail[1]:08X} r15 {tail[2]:08X}')
    for t, pr, _ in seen[1:-1]:
        check(e < pr <= e + 64, f'{e:06X}: inner call {t:06X} returns into the member ({pr:06X})')
    return seen


def lag_writer(quiet):
    """Reviewer item: 0x01FDD4 is the second writer of 0xFFFF63B0 (find_writers.py lists 01FDF0 and
    01FDFA).  Run with 0x0BEA40 REAL on exactly representable cases."""
    e = 0x01FDD4
    check(u32(0x01FDFC) == 0x0BEA40 and u32(0x01FE08) == 0xFFFF63B0 and u32(0x01FE0C) == 0xFFFF4130,
          '0x01FDD4 pool words')
    check(rl(0x01FE00) == 0x39A00000 and rl(0x01FE04) == 0x3F000000, 'eps 0x39A00000 at 0x01FE00, k 0.5 at 0x01FE04')
    check(bf(0x39A00000) == 10 * 2.0 ** -15, 'eps = 10 * 2^-15')
    A12 = fb(12.0)
    rows = [(A12, fb(14.0), fb(13.0), 'k = 0.5: halfway'),
            (fb(14.0), A12, fb(13.0), 'halfway, other side'),
            (A12, fb(12.0 + 2.0 ** -11), A12, 'snap: |A - r| = 2^-12 < eps'),
            (A12, fb(12.0 + 2.0 ** -10), fb(12.0 + 2.0 ** -11), 'no snap: |A - r| = 2^-11 > eps'),
            (A12, 0x7FC00000, A12, 'B = NaN -> A'),
            (A12, 0x7F800000, A12, 'B = +Inf -> A'),
            (F0, F0, F0, 'all zero')]
    for i, (a, b, want, why) in enumerate(rows):
        em = Emu3(0x1FDD4 + i)
        em.poke(0xFFFF4130, 4, a)
        em.poke(0xFFFF63B0, 4, b)
        res = em.call(e, max_steps=500)
        check(res == 'return', '0x01FDD4 returns')
        for pc in em.executed:
            check(e <= pc < 0x01FDF2 or 0x0BEA40 <= pc < 0x0BEA68, f'0x01FDD4 executed {pc:06X}')
        w = dict(em.writes)
        got = int.from_bytes(bytes(w.get(0xFFFF63B0 + k, 0) for k in range(4)), 'big')
        check(set(w) == {0xFFFF63B0 + k for k in range(4)} and got == want,
              f'0x01FDD4 {why}: wrote {sorted(w)} {got:08X}, want {want:08X}')
        if not quiet:
            print(f'  0x01FDD4 A=f32[FFFF4130]={a:08X} B=f32[FFFF63B0]={b:08X} -> f32[FFFF63B0]={got:08X}  ({why})')
    return len(rows)


def gbr_consumer(quiet):
    """Reviewer item: 0xFFFF6A84 is the GBR base of 0x027D86, which tests the byte class 100 wrote."""
    check(u16(0x027D68) == 0xB006 and 0x027D68 + 4 + 2 * 6 == 0x027D78, '027D68 bsr 0x027D78')
    check(u16(0x027D6C) == 0xB00B and 0x027D6C + 4 + 2 * 0x0B == 0x027D86, '027D6C bsr 0x027D86')
    check(u16(0x027D8A) == 0xD054 and ((0x027D8A + 4) & ~3) + 0x54 * 4 == 0x027EDC
          and u32(0x027EDC) == 0xFFFF6A84, '027D8A r0 = u32[0x027EDC] = 0xFFFF6A84')
    check(u16(0x027D8C) == 0x401E, '027D8C ldc r0,gbr')
    check(u16(0x027D80) == 0xD656 and ((0x027D80 + 4) & ~3) + 0x56 * 4 == 0x027EDC, '027D80 r6 = same pool long')
    check([u16(0x027DB2), u16(0x027DB4), u16(0x027DB6)] == [0xC400, 0x8801, 0x8B34],
          '027DB2 mov.b @(0,gbr),r0 / cmp/eq #1,r0 / bf 0x027E22')
    # no ldc Rm,gbr (0x4m1E) / ldc.l @Rm+,gbr (0x4m17) between, nor in the two callees 0x0BE980 / 0x0BE9A0
    for pc in list(range(0x027D8E, 0x027DB2, 2)) + list(range(0x0BE980, 0x0BE9C0, 2)):
        check((u16(pc) & 0xF0FF) not in (0x401E, 0x4017), f'{pc:06X}: GBR reloaded before 0x027DB2')
    check(u32(0x027ECC) == 0x0BE980 and u32(0x027EA8) == 0x0BE9A0, 'callees between: 0x0BE980, 0x0BE9A0')
    if not quiet:
        print('  0x027D66: bsr 0x027D78 (class 100: u8[0xFFFF6A84] = (u8[0xFFFF8CAA] == 1)) then bsr 0x027D86; '
              '0x027D86: GBR = 0xFFFF6A84, mov.b @(0,gbr) == 1 else bf 0x027E22')
    return 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--map', action='store_true')
    ap.add_argument('--class', dest='only', type=int)
    a = ap.parse_args()
    quiet = a.quiet or a.map

    sel = [c for c in ALLCLASSES if 30 <= c['id'] <= 126 and c['members'] >= 2]
    check(len(sel) == 97 and sum(c['members'] for c in sel) == 295, 'scope: 97 classes, 295 functions')
    check(sum(c['members'] for c in sel if c['id'] in IRQ_CLASSES) == 34, 'interrupt-handler classes: 34 members')
    check(sum(c['members'] for c in sel if c['id'] in CODE_IS_VECTOR) == 19, 'r4 = vector classes: 19 members')
    members_by_class = {c['id']: [int(f['entry'], 16) for f in c['functions']] for c in sel}
    maplines = []
    totals = dict(members=0, dropped=0, cases=0, real=0, skipped=0, shaped=0, irq=0, code_is_vector=0,
                  shift_runs=0)
    global PR_EXIT
    PR_EXIT = prologue_r0()
    for c in sel:
        cid = c['id']
        if a.only is not None and cid != a.only:
            continue
        ex = int(c['example'], 16)
        n = c['insns']
        exb = body(ex, n)
        template = [m for (_, _, _, m, _) in exb]
        if not quiet:
            print(f'\n=== class {cid}: {c["members"]} members, {n} insns, example {ex:06X}')
        if cid in DATA_CLASSES:
            if not quiet:
                print('  DATA: 2-D cell-handler pointer table at 0x0BE914 (see 0x0BE8E4)')
            refs = data_classes(members_by_class, quiet)
            for f in c['functions']:
                e = int(f['entry'], 16)
                # the same census-extent and shape checks as every other member (they are data all the same)
                cen = CENSUS[f['entry']]
                check(int(cen['end'], 16) - e == 2 * n and cen['insns'] == n, f'{e:06X}: census extent')
                check([m for (_, _, _, m, _) in body(e, n)] == template, f'{e:06X}: shape differs from example')
                check(len(cen['callers']) == f['callers'] == 0, f'{e:06X}: census orphan')
                totals['shaped'] += 1
                maplines.append(f';   class {cid:3d}  {e:06X}  DATA long {u32(e):08X}  (2-D handler for typecode '
                                f'{4 * ((e - 0x0BE914) // 4):#04x}; table read by 0x0BE8E4 via {refs[0][0]:06X})')
                totals['dropped'] += 1
            continue
        kdef = K[cid]
        if not quiet:
            print(f'  contract: {kdef["contract"]}')
        vec = None
        if cid == 30:
            vbr, vec = vectors(members_by_class[30])
        if cid in FRAGMENT_CLASSES:
            totals['shift_runs'] += fragments(quiet)
        for f in c['functions']:
            e = int(f['entry'], 16)
            cen = CENSUS[f['entry']]
            check(int(cen['end'], 16) - e == 2 * n and cen['insns'] == n, f'{e:06X}: census extent')
            b = body(e, n)
            # the shape proof
            mt = [m for (_, _, _, m, _) in b]
            if mt != template:
                print(f'  DROPPED {e:06X}: shape differs from example')
                totals['dropped'] += 1
                continue
            for (pc, w, txt, _, _) in b:
                check(not txt.split()[0].lower().startswith(ILLEGAL), f'{pc:06X}: {txt} is not SH-2E code')
            check(len(cen['callers']) == f['callers'], f'{e:06X}: caller count')
            p, qs = params_of(b, kdef['names'])
            totals['members'] += 1
            totals['shaped'] += 1
            desc = '  '.join(describe_param(nm, q) for nm, q in zip(kdef['names'], qs))
            extra = ''
            if vec is not None:
                extra = f'  vectors {vec[e]}'
            if cid in IRQ_CLASSES:
                iv = irq_vectors(e)
                check(len(iv) == 1, f'{e:06X}: exactly one interrupt stub dispatches to it ({iv})')
                # and nothing else reaches it: its only static reference is the stub's member long
                check(refs_to(e) == [('long', iv[0][1] + 16)] and cen['callers'] == [f'0x{iv[0][1]:06X}'],
                      f'{e:06X}: references {refs_to(e)}, census callers {cen["callers"]}')
                totals['irq'] += 1
                if cid in CODE_IS_VECTOR:
                    check(p['C'] & M32 == iv[0][0], f'{e:06X}: r4 code {p["C"]} == its vector {iv[0][0]}')
                    totals['code_is_vector'] += 1
                seen = irq_entry(e, p, kdef, iv[0][1], PR_EXIT, seed=e ^ 0x5A5A)
                if not quiet:
                    print(f'    via stub {iv[0][1]:06X}: ' + '  '.join(
                        f'{t:06X}(PR={pr:06X},r15=TOP{r15 - STACK_TOP:+d})' for t, pr, r15 in seen))
                extra = f'  irq vector {iv[0][0]} via stub {iv[0][1]:06X}'
            line = f';   class {cid:3d}  {e:06X}  callers {f["callers"]}  {desc}{extra}'
            maplines.append(line)
            if not quiet:
                print(f'  {e:06X}  {desc}{extra}')
            modes = [False, True] if kdef['real'] else [False]
            for real in modes:
                if real and not (set(kdef['targets'](p)) & LIB_REAL):
                    continue
                for ci, case in enumerate(kdef['cases'](p)):
                    obs, I = run_case(e, n, p, kdef, case, real, seed=e + ci)
                    x = compare(e, cid, p, kdef, case, real, obs, I)
                    if x is None:
                        totals['skipped'] += 1
                        if not quiet:
                            print(f'    {"REAL" if real else "stub"} {fmt_case(case):46s} -> (skipped: rounding could decide)')
                        continue
                    totals['cases'] += 1
                    totals['real'] += real
                    if not quiet:
                        print(f'    {"REAL" if real else "stub"} {fmt_case(case):46s} -> {fmt_obs(obs, x)}')
        if a.quiet:
            print(f'class {cid:3d}: {c["members"]} members OK  -- {kdef["contract"]}')
    if a.map:
        print('\n'.join(maplines))
        return
    extra_runs = 0
    if a.only is None:
        if not quiet:
            print('\n=== reviewer items: other writer of 0xFFFF63B0, GBR consumer of 0xFFFF6A84')
        extra_runs += lag_writer(quiet)
        gbr_consumer(quiet)
        check(totals['shaped'] == 295 and totals['irq'] == 34 and totals['code_is_vector'] == 19,
              f'totals {totals}')
    print(f'\nmembers proven and emulated: {totals["members"]}   dropped as data: {totals["dropped"]}   '
          f'shape-tested: {totals["shaped"]}   interrupt-stub entries: {totals["irq"]} '
          f'(r4 = vector: {totals["code_is_vector"]})\n'
          f'cases: {totals["cases"]} ({totals["real"]} with the library routine run for real)   '
          f'cases skipped (rounding could decide): {totals["skipped"]}   shift-routine runs: '
          f'{totals["shift_runs"]}   0x01FDD4 runs: {extra_runs}   checks: {CHECKS[0]}')
    print('ALL CONTRACTS HOLD')


if __name__ == '__main__':
    main()
