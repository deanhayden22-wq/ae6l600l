#!/usr/bin/env python3
"""Emulation check for ROM function 0x042506..0x0429D2 (508 instructions) and the
sibling / writer facts its trace relies on.

    python3 scripts/trace/emu_fn_042506.py

Reference bin: rom/AE5L600L 20g rev 20.19c.bin  md5 92cae8275cd4f9b473a3a9e36efe6449

What it does
------------
Runs the function in scripts/sh2e_emu.py against a Python model written from
the bytes (disassembly/analysis/fn_042506_trace.txt) and asserts, per case:

  * every output RAM cell, bit for bit           (0xFFFF805C/8060/8064/8070/8074)
  * the exact SET of non-stack RAM bytes written (nothing else is touched)
  * the exact SET of RAM cells read before being written in the same call
    (inputs are poked WITHOUT marking them initialised, so every input read
    lands in emu.uninit_reads -- that is the function's true input list)
  * callee-saved state: r8-r14, r15, GBR, fr12-fr15 are restored

Passes on 0x042506 itself:
  A. real callees (0x022CF4, 0x0BE960, 0x0BE830 run from ROM), control grid
  B. real callees, float grid on the arithmetic core, plus overflow cases
     (nothing in the code bounds the product: OUT saturates at -/+FLT_MAX, the
     round-toward-zero overflow result; an infinite factor gives an infinite OUT)
  C. callees STUBBED and their arguments captured: proves which descriptor
     ADDRESS is passed for each (mode, selector) pair, that the lookup input
     is the value 0x0BE960 returned, and that the results land where stated
  D. an in-memory ROM copy in which every float of the array region
     0x0D3DA0..0x0D43BF holds a value unique to its address: proves which
     array ADDRESS is read for each (mode, A side, selector, counter).
     Passes A-C check the array by VALUE on the real ROM, where several of the
     18 arrays hold identical cells; pass D closes that gap. (The file on disk
     is never written.)

The model takes its table value from a direct emulator call of 0x0BE830 with
the descriptor the model selected, so the composition is checked bit-exactly;
0x0BE830 itself is checked separately against linear interpolation of
desc_types.read_table() and for saturation outside the axis (-1e9, -inf, +1e9,
+inf, NaN), 0x0BE960 against max(), 0x022CF4 against (byte == 1).

ROUNDING (2026-11-27, corrections item 106). Every arithmetic model here -- the
product (fmul x3), the hysteresis width and threshold (fsub), the selector ratio
(fdiv x2), B = X[n] - X[n-2] (fsub) -- computes the exact result and rounds it
TOWARD ZERO (rz_arith), which is what the SH7058 does: reset loads FPSCR =
0x00040001 and the ROM's own FPU self-test demands truncated results. The
script was first written against an emulator that rounded to nearest; its
float models then used Python double arithmetic and passed with it. Test INPUTS
given as Python floats are still converted with f2b (nearest): that is a choice
of input, not arithmetic. fmac (inside 0x0BE830 only) is fused in the emulator,
which the self-test does not settle; check_fmac_sensitivity bounds the effect.

Added by the settling pass (review items A25 / A34 / A35 and what was missed):
  * 0x0BE800, the hysteresis helper, against a model
  * 0x042368 (the sibling that owns F bit1 and W bit 0x0200) against a model:
    outputs, write-set (W is written on EVERY call) and read-set
  * which bits of F and W the three siblings 0x041EEE, 0x04209A, 0x042368 change
  * the call chain 0x042368 -> 0x04248C -> 0x042506 as the runner 0x04907C
    orders it: when the enable bit can be set, for how many calls it lasts, and
    the most negative OUT that is reachable (NOT the arithmetic bound -31.20)
  * the same chain with 0x04209A in front: at most 24 consecutive calls take
    the product path
  * 0x023EB8 and 0x024094, the writers of the selector 0xFFFF6810, against a
    model of every path

Added by the re-check of the settling pass (an edge neither earlier decode tried):
  * a NaN B on the call that sets the enable bit: 0x0BE800 treats it as "at or
    above hi" (fcmp/gt is false for unordered operands), so the bit is set; the
    peak becomes NaN; on the next call 0x0BE960 returns B (NaN > B is false),
    so the peak can drop to 0.0 and OUT reaches -31.201171875 after all. The
    -30.67 floor therefore needs "B is not NaN on the setting call" as a premise.
  * why that premise holds whenever the history cells of B are finite: the 2-D
    lookup 0x0BE8E4 returns a finite value for NaN / +-inf inputs, and the
    writer 0x01F5F2 gives a finite B from finite history with NaN inputs
  * 0x023EB8 with a NaN ratio (either input NaN) stores sel = 1

Names in this file are neutral on purpose: nothing here establishes what any
of these RAM cells physically is.
"""
import hashlib
import itertools
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
import desc_types as DT       # noqa: E402

BIN = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
ROM = open(BIN, 'rb').read()
assert hashlib.md5(ROM).hexdigest() == '92cae8275cd4f9b473a3a9e36efe6449', 'wrong reference bin'

ENTRY = 0x042506
FN_FLAG, FN_MAX, FN_LOOKUP = 0x022CF4, 0x0BE960, 0x0BE830

# ---- RAM cells (all resolved from literal pools / GBR=0xFFFF805C / r12=0xFFFF8080)
IN_A = 0xFFFF6624       # f32, compared against cal 0x0D2C94
IN_B = 0xFFFF62F4       # f32, peak-held into 0xFFFF8070
IN_SEL = 0xFFFF6810     # u8 selector 1..5 / other
IN_MODE = 0xFFFF65C5    # u8, read by 0x022CF4, mode = (byte == 1)
FLG8 = 0xFFFF8075       # u8, bit 1 = enable                 (gbr+25)
FLG16 = 0xFFFF8080      # u16, bits 0x0002 0x0004 0x1000 0x2000 0x4000 (gbr+36)
CTR = 0xFFFF8074        # u8 counter                         (gbr+24)
PEAK = 0xFFFF8070       # f32  r12-16
LUT = 0xFFFF8060        # f32  r12-32
STEP = 0xFFFF8064       # f32  r12-28
FAC_A = 0xFFFF806C      # f32  r12-20  (input, written elsewhere)
FAC_B = 0xFFFF8068      # f32  r12-24  (input, written elsewhere)
OUT = 0xFFFF805C        # f32  r12-36 == GBR base

CAL_THRESH = 0x0D2C94   # f32 3000.0
CAL_FORCE = 0x0D2C90    # f32 0.0

# selector -> 4-float array base; index = counter
ARR_M0 = ({1: 0x0D3DA0, 2: 0x0D3E00, 3: 0x0D3E60, 4: 0x0D3EC0, 5: 0x0D3F20}, 0x0D3F80)
ARR_M1_LO = ({1: 0x0D3DC0, 2: 0x0D3E20, 3: 0x0D3E80, 4: 0x0D3EE0, 5: 0x0D3F40}, 0x0D3FA0)
ARR_M1_HI = ({1: 0x0D3DE0, 2: 0x0D3E40, 3: 0x0D3EA0, 4: 0x0D3F00, 5: 0x0D3F60}, 0x0D3FC0)
# selector -> 1-D descriptor
DESC_M1 = ({1: 0x0ADE58, 2: 0x0ADE80, 3: 0x0ADEA8, 4: 0x0ADED0, 5: 0x0ADEF8}, 0x0ADF20)
DESC_M0 = ({1: 0x0ADE44, 2: 0x0ADE6C, 3: 0x0ADE94, 4: 0x0ADEBC, 5: 0x0ADEE4}, 0x0ADF0C)
ALL_DESC = sorted(list(DESC_M0[0].values()) + [DESC_M0[1]] + list(DESC_M1[0].values()) + [DESC_M1[1]])


def f2b(x):
    return E.f2b(x)


def b2f(b):
    return E.b2f(b)


def rom_f32_bits(a):
    return struct.unpack_from('>I', ROM, a)[0]


def bytes4(a):
    return {a, a + 1, a + 2, a + 3}


def rz_arith(op, xb, yb):
    """One single-precision fadd / fsub / fmul / fdiv as the SH7058 computes it: the exact result rounded
    TOWARD ZERO to float32 (FPSCR = 0x00040001 from reset, RM = 01, DN = 1; corrections item 106).

    Written independently of the emulator's arithmetic; only sh2e_emu.rz_bits (exact rational -> float32
    bits, truncated, overflow -> +/-FLT_MAX, denormal -> signed zero) is shared. Operands are float32 BITS;
    b2f flushes denormal operands to signed zero (DN = 1). Infinite / NaN operands and exact-zero results
    involve no rounding, so the IEEE result (computed in double) is used for them; a double cannot overflow
    or underflow on a product / quotient of two float32 values, so the double is never a wrong special.
    """
    x, y = b2f(xb), b2f(yb)
    if op == '/' and y == 0.0:
        raise ValueError('divide by zero: no model needed, every divide here is guarded')
    apply = {'+': lambda a, b: a + b, '-': lambda a, b: a - b,
             '*': lambda a, b: a * b, '/': lambda a, b: a / b}[op]
    ieee = apply(x, y)
    if not (math.isfinite(x) and math.isfinite(y)):
        return f2b(ieee)
    q = apply(Fraction(x), Fraction(y))
    if q == 0:
        return f2b(ieee)                 # exact zero: sign by the IEEE rules (+0 for x - x under RZ)
    return E.rz_bits(q)


def fmul_bits(xb, yb):
    """fmul FRm,FRn: exact product, rounded once toward zero (overflow saturates at +/-FLT_MAX)."""
    return rz_arith('*', xb, yb)


def fsub_bits(xb, yb):
    """fsub FRm,FRn: FRn = FRn - FRm, exact difference rounded toward zero."""
    return rz_arith('-', xb, yb)


def fdiv_bits(xb, yb):
    """fdiv FRm,FRn: FRn = FRn / FRm, exact quotient rounded toward zero (FRm != 0)."""
    return rz_arith('/', xb, yb)


# ---------------------------------------------------------------- lookup oracle (bit-exact, via ROM routine)
_lut_cache = {}


def rom_lookup_bits(desc, xbits):
    k = (desc, xbits)
    if k not in _lut_cache:
        e = E.Emu(ROM)
        e.call(FN_LOOKUP, regs={4: desc}, fregs={4: b2f(xbits)})
        _lut_cache[k] = e.FR[0]
    return _lut_cache[k]


# ---------------------------------------------------------------- the model
def model(c, stub=None):
    """c: dict of input values (floats as BITS). Returns (outputs, reads, writes).

    stub: None for real callees, else dict(mode_r0=, max_bits=, lut_bits=) -- the
    values the stubbed callees will return.
    """
    F, W, ctr = c['F'], c['W'], c['ctr']
    out = {CTR: ctr, PEAK: c['peak'], LUT: c['lut'], STEP: c['step'], OUT: c['out']}
    reads = {IN_A, IN_B, IN_SEL, FLG8}
    if stub is None:
        reads.add(IN_MODE)
        mode = 1 if c['mode'] == 1 else 0
    else:
        mode = 1 if (stub['mode_r0'] & 0xFF) == 1 else 0
    writes = set()
    en = bool(F & 2)
    sel = c['sel']                       # extu.b: 0..255
    calls = []

    # --- counter (0x04252C..0x04255C)
    if not en:
        out[CTR] = 0
        writes.add(CTR)
    else:
        reads.add(FLG16)
        if (W & 4) and (W & 2):
            reads.add(CTR)
            if ctr < 3:                  # cmp/ge r5,r6 on the ZERO-extended byte
                out[CTR] = (ctr + 1) & 0xFF
                writes.add(CTR)

    # --- step factor (0x04255E..0x0427DA)
    if en:
        reads.add(CTR)                   # (already initialised if it was just written; see run())
        if mode == 1:
            # fcmp/gt fr14,fr8 : T = (cal > A); T=1 -> "LO" family
            arr = ARR_M1_LO if b2f(rom_f32_bits(CAL_THRESH)) > b2f(c['A']) else ARR_M1_HI
        else:
            arr = ARR_M0
        base = arr[0].get(sel, arr[1])
        out[STEP] = rom_f32_bits(base + 4 * out[CTR])
        writes |= bytes4(STEP)

    # --- peak hold + table (0x0427DC..0x04296A)
    if en:
        reads.add(PEAK)
        if stub is None:
            p, b = b2f(c['peak']), b2f(c['B'])
            out[PEAK] = c['peak'] if p > b else c['B']      # 0x0BE960: fr4 > fr5 ? fr4 : fr5
        else:
            out[PEAK] = stub['max_bits']
        calls.append(('max', c['peak'], c['B']))
        d = DESC_M1 if mode == 1 else DESC_M0
        desc = d[0].get(sel, d[1])
        out[LUT] = rom_lookup_bits(desc, out[PEAK]) if stub is None else stub['lut_bits']
        calls.append(('lookup', desc, out[PEAK]))
        writes |= bytes4(LUT)
    else:
        out[PEAK] = 0
    writes |= bytes4(PEAK)

    # --- output (0x04296C..0x0429C0)
    if not en:
        out[OUT] = 0
        writes |= bytes4(OUT)
    elif W & 0x1000:
        out[OUT] = rom_f32_bits(CAL_FORCE)
        writes |= bytes4(OUT)
    elif W & 0x2000:
        out[OUT] = 0
        writes |= bytes4(OUT)
    elif W & 0x4000:
        reads |= {FAC_A, FAC_B}
        v = fmul_bits(out[LUT], out[STEP])
        v = fmul_bits(v, c['facA'])
        v = fmul_bits(v, c['facB'])
        out[OUT] = v
        writes |= bytes4(OUT)
    # else: OUT left as it was
    return out, reads, writes, calls


# ---------------------------------------------------------------- running one case
_emu = E.Emu(ROM)
_rng = random.Random(0x42506)
SENT = {8: 0x08080808, 9: 0x09090909, 10: 0x0A0A0A0A, 11: 0x0B0B0B0B,
        12: 0x0C0C0C0C, 13: 0x0D0D0D0D, 14: 0x0E0E0E0E}
FSENT = {12: 0x41C80000, 13: 0xC1C80000, 14: 0x42F60000, 15: 0xC2F60000}
GBR_SENT = 0xFFFF1234


def poke(e, a, n, v):
    """Write RAM WITHOUT marking it initialised, so a later read is recorded."""
    o = a - E.RAM_LO
    e.ram[o:o + n] = (v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big')


def run(c, stub=None):
    e = _emu
    e.init = bytearray(len(e.init))          # nothing is "initialised": every input read is recorded
    e.uninit_reads.clear()
    e.writes.clear()
    e.stubs.clear()
    e.stack_low = E.STACK_TOP
    e.steps = 0                              # the step limit is cumulative per Emu object
    poke(e, IN_A, 4, c['A']); poke(e, IN_B, 4, c['B'])
    poke(e, IN_SEL, 1, c['sel']); poke(e, IN_MODE, 1, c['mode'])
    poke(e, FLG8, 1, c['F']); poke(e, FLG16, 2, c['W']); poke(e, CTR, 1, c['ctr'])
    poke(e, PEAK, 4, c['peak']); poke(e, LUT, 4, c['lut']); poke(e, STEP, 4, c['step'])
    poke(e, FAC_A, 4, c['facA']); poke(e, FAC_B, 4, c['facB']); poke(e, OUT, 4, c['out'])
    calls = []
    if stub is not None:
        e.stub(FN_FLAG, fn=lambda m: m.R.__setitem__(0, stub['mode_r0'] & E.M32))

        def _max(m):
            calls.append(('max', m.FR[4], m.FR[5]))
            m.FR[0] = stub['max_bits']

        def _lut(m):
            calls.append(('lookup', m.R[4], m.FR[4]))
            m.FR[0] = stub['lut_bits']
        e.stub(FN_MAX, fn=_max)
        e.stub(FN_LOOKUP, fn=_lut)
    regs = {i: _rng.getrandbits(32) for i in range(8)}      # garbage in every argument register
    regs.update(SENT)
    for i in range(12):
        e.FR[i] = _rng.getrandbits(32)
    for i, v in FSENT.items():
        e.FR[i] = v
    e.gbr = GBR_SENT
    assert e.call(ENTRY, regs=regs) == 'return'
    got = {CTR: e.ram[CTR - E.RAM_LO]}
    for a in (PEAK, LUT, STEP, OUT):
        got[a] = int.from_bytes(e.ram[a - E.RAM_LO:a - E.RAM_LO + 4], 'big')
    want, reads, writes, mcalls = model(c, stub)
    tag = ' '.join(f'{k}={v:#x}' for k, v in c.items())
    assert got == want, f'OUTPUT MISMATCH {tag}\n got  {got}\n want {want}'
    assert set(e.writes) == writes, (f'WRITE-SET MISMATCH {tag}\n got  {sorted(map(hex, e.writes))}'
                                     f'\n want {sorted(map(hex, writes))}')
    assert e.uninit_reads == reads, (f'READ-SET MISMATCH {tag}\n got  {sorted(map(hex, e.uninit_reads))}'
                                     f'\n want {sorted(map(hex, reads))}')
    for i, v in SENT.items():
        assert e.R[i] == v, f'r{i} not preserved {tag}'
    assert e.R[15] == E.STACK_TOP, 'r15 not restored'
    assert e.gbr == GBR_SENT, 'GBR not restored'
    for i, v in FSENT.items():
        assert e.FR[i] == v, f'fr{i} not preserved {tag}'
    if stub is not None:
        assert calls == mcalls, f'CALL MISMATCH {tag}\n got  {calls}\n want {mcalls}'
    return got


def case(**kw):
    c = dict(F=2, W=0x4000, ctr=0, mode=0, sel=1, A=f2b(2000.0), B=f2b(0.0), peak=f2b(0.0),
             lut=0x42C80000, step=0x42C80000, facA=f2b(1.0), facB=f2b(1.0), out=0x42F6E979)
    c.update(kw)
    return c


def fmt(bits):
    return f'{b2f(bits):.7g}'


# ================================================================ callee checks
def check_callees():
    n = 0
    # 0x022CF4: r0 = (int8 [0xFFFF65C5] == 1)
    for v in range(256):
        e = E.Emu(ROM)
        e.ram_u8(IN_MODE, v)
        e.call(FN_FLAG)
        assert e.R[0] == (1 if v == 1 else 0), v
        n += 1
    # 0x0BE960: fr0 = fr4 > fr5 ? fr4 : fr5
    vals = [-100.0, -0.5, -0.0, 0.0, 0.5, 12.5, 87.5, 1e6]
    for a, b in itertools.product(vals, vals):
        e = E.Emu(ROM)
        e.call(FN_MAX, fregs={4: a, 5: b})
        assert e.FR[0] == (f2b(a) if a > b else f2b(b)), (a, b)
        n += 1
    # 0x0BE830 on the 12 descriptors vs linear interpolation, clamped at both ends.
    # A tolerance on purpose: the reference is a double-precision textbook interpolation, not a bit model of
    # 0x0BE830's own sequence (fdiv, the uint8 cell reader, an fmac whose fusedness the ROM self-test does not
    # settle). Nothing below rests on it: the model of 0x042506 takes every table value from the routine
    # itself (rom_lookup_bits), so the composition is checked to the bit. At these test points the exact
    # interpolation happens to be a float32 value and the routine returns it exactly (worst error printed).
    worst = 0.0
    for d in ALL_DESC:
        t = DT.read_table(ROM, d)
        ax, vals_ = t['axes']['x'], t['values']
        xs = [-10.0, 0.0, 87.5, 100.0, 1000.0] + [ax[i] + (ax[i + 1] - ax[i]) * k
                                                   for i in range(len(ax) - 1) for k in (0.0, 0.25, 0.5, 0.9)]
        for x in xs:
            got = b2f(rom_lookup_bits(d, f2b(x)))
            want = E._interp(ax, vals_, b2f(f2b(x)))
            worst = max(worst, abs(got - want))
            assert abs(got - want) <= 1e-4 * max(1.0, abs(want)), (hex(d), x, got, want)
            n += 1
    print(f'callees: 0x022CF4 == (byte==1), 0x0BE960 == max, 0x0BE830 == clamped linear interpolation '
          f'({n} cases, worst lookup error {worst:.2e})')


# ================================================================ pass A: control grid
def pass_a():
    As = [f2b(x) for x in (0.0, 2999.9998, 3000.0, 3000.0002, 7000.0)]
    Bs = [f2b(x) for x in (-5.0, 0.0, 6.25, 12.5, 50.0, 87.5, 100.0)]
    Ps = [f2b(x) for x in (0.0, 3.0, 10.0, 60.0, 200.0, -1.0)]
    Fa = [f2b(x) for x in (1.0, 0.5, 0.296875, -2.0, 0.0)]
    Fb = [f2b(x) for x in (1.0, 0.75, 3.0)]
    bits = (0x0002, 0x0004, 0x1000, 0x2000, 0x4000)
    Ws = []
    for k in range(32):
        w = sum(b for i, b in enumerate(bits) if k >> i & 1)
        Ws += [w, w | 0x8FF9]                 # with every OTHER bit clear, then set
    n = 0
    for F in (0x02, 0xFF):
        for W, ctr, mode, sel in itertools.product(Ws, (0, 1, 2, 3, 4, 0xFF), (0, 1, 2),
                                                   (0, 1, 2, 3, 4, 5, 6, 0xFF)):
            run(case(F=F, W=W, ctr=ctr, mode=mode, sel=sel, A=As[n % 5], B=Bs[n % 7], peak=Ps[n % 6],
                     facA=Fa[n % 5], facB=Fb[n % 3]))
            n += 1
    for F in (0x00, 0xFD):
        for W, ctr in itertools.product(Ws, (0, 1, 2, 3, 4, 0xFF)):
            run(case(F=F, W=W, ctr=ctr, mode=n % 3, sel=n % 8, A=As[n % 5], B=Bs[n % 7], peak=Ps[n % 6],
                     facA=Fa[n % 5], facB=Fb[n % 3]))
            n += 1
    print(f'pass A (real callees, control grid): {n} cases OK')
    return n


# ================================================================ pass B: float grid on the arithmetic core
def pass_b():
    n = 0
    for mode, sel, ctr in itertools.product((0, 1), (1, 2, 3, 4, 5, 6), (0, 1, 2, 3)):
        for A, B, P, fa, fb in itertools.product((2999.0, 3000.0), (0.0, 3.125, 12.5, 40.0, 95.0),
                                                 (0.0, 6.25, 50.0), (1.0, 0.3984375), (1.0, 1.5)):
            run(case(F=2, W=0x4000, ctr=ctr, mode=mode, sel=sel, A=f2b(A), B=f2b(B), peak=f2b(P),
                     facA=f2b(fa), facB=f2b(fb)))
            n += 1
    # random
    r = random.Random(1)
    for _ in range(3000):
        run(case(F=r.choice((0, 2, 2, 2, 0xFF)), W=r.getrandbits(16), ctr=r.choice((0, 1, 2, 3)),
                 mode=r.choice((0, 1)), sel=r.randrange(8), A=f2b(r.uniform(0, 8000)),
                 B=f2b(r.uniform(-10, 110)), peak=f2b(r.uniform(-10, 110)),
                 facA=f2b(r.uniform(0, 2)), facB=f2b(r.uniform(0, 2)), out=r.getrandbits(31) & 0x7F7FFFFF))
        n += 1
    # nothing in the function bounds the product: with large foreign factors it overflows. Rounding toward
    # zero, an overflowing fmul gives +/-FLT_MAX (0x7F7FFFFF), never infinity, and FLT_MAX * 3e38 overflows
    # again to FLT_MAX: OUT saturates at the format's largest finite value, not at anything the code sets.
    for fa, fb, want in ((3.0e38, 3.0e38, 0xFF7FFFFF), (-3.0e38, 3.0e38, 0x7F7FFFFF)):
        g = run(case(F=2, W=0x4000, ctr=0, mode=1, sel=1, A=f2b(2000.0), B=f2b(1.56), facA=f2b(fa), facB=f2b(fb)))
        assert g[OUT] == want, hex(g[OUT])
        n += 1
    # an infinite foreign factor (no rounding involved) does give an infinite OUT
    for fa, want in ((float('inf'), 0xFF800000), (float('-inf'), 0x7F800000)):
        g = run(case(F=2, W=0x4000, ctr=0, mode=1, sel=1, A=f2b(2000.0), B=f2b(1.56), facA=f2b(fa)))
        assert g[OUT] == want, hex(g[OUT])
        n += 1
    print(f'pass B (real callees, float grid + random + overflow to +/-FLT_MAX, infinite factor to +/-inf): '
          f'{n} cases OK')
    return n


# ================================================================ pass C: stubbed callees, arguments captured
def pass_c():
    n = 0
    for mode_r0, sel, W, F in itertools.product((0, 1, 2, 0xFF), (0, 1, 2, 3, 4, 5, 6, 0x81, 0xFF),
                                                (0x0000, 0x4000, 0x4006, 0x1000, 0x2000, 0xFFFF),
                                                (0, 2)):
        for A in (2999.9998, 3000.0):
            run(case(F=F, W=W, sel=sel, ctr=n % 4, A=f2b(A), B=f2b(7.0), peak=f2b(5.0)),
                stub=dict(mode_r0=mode_r0, max_bits=f2b(33.0), lut_bits=f2b(-11.0)))
            n += 1
    print(f'pass C (callees stubbed, arguments captured): {n} cases OK')
    return n


# ================================================================ pass D: array ADDRESS, unique-cell ROM copy
def pass_d():
    lo, hi = 0x0D3DA0, 0x0D3FC0 + 0x400            # 18 arrays + everything a counter of 0xFF can reach
    rom = bytearray(ROM)
    for a in range(lo, hi, 4):
        struct.pack_into('>f', rom, a, 1000.0 + (a - lo) // 4)     # exact in float32, unique per address
    e = E.Emu(bytes(rom))
    n = 0
    for mode, A, sel, ctr in itertools.product((0, 1, 2), (2999.9998, 3000.0), (0, 1, 2, 3, 4, 5, 6, 0xFF),
                                               (0, 1, 2, 3, 4, 0xFF)):
        e.init = bytearray(len(e.init))
        e.writes.clear()
        e.steps = 0
        e.stack_low = E.STACK_TOP
        c = case(F=2, W=0x4000, ctr=ctr, mode=mode, sel=sel, A=f2b(A))
        poke(e, IN_A, 4, c['A']); poke(e, IN_B, 4, c['B']); poke(e, IN_SEL, 1, sel); poke(e, IN_MODE, 1, mode)
        poke(e, FLG8, 1, 2); poke(e, FLG16, 2, 0x4000); poke(e, CTR, 1, ctr)
        poke(e, PEAK, 4, 0); poke(e, FAC_A, 4, c['facA']); poke(e, FAC_B, 4, c['facB'])
        assert e.call(ENTRY) == 'return'
        arr = (ARR_M1_LO if 3000.0 > b2f(c['A']) else ARR_M1_HI) if mode == 1 else ARR_M0
        base = arr[0].get(sel, arr[1])
        want = f2b(1000.0 + (base + 4 * ctr - lo) // 4)
        got = int.from_bytes(e.ram[STEP - E.RAM_LO:STEP - E.RAM_LO + 4], 'big')
        assert got == want, f'ARRAY ADDRESS mode={mode} A={A} sel={sel} ctr={ctr}: got {b2f(got)} want {b2f(want)}'
        n += 1
    print(f'pass D (unique-cell ROM copy, array address by (mode, A side, sel, counter)): {n} cases OK')
    return n


# ================================================================ settling pass: siblings and writers
FN_HYST, FN_ENABLE, FN_FAC, FN_WOWNER, FN_F0 = 0x0BE800, 0x042368, 0x04248C, 0x04209A, 0x041EEE
CNT_EN = 0xFFFF8078      # u16: calls with F bit1 set       (stores 042390 / 042396, both in 0x042368)
CNT_W4 = 0xFFFF8076      # u16: calls with W bit 0x4000 set (stores 042292 / 042296, both in 0x04209A)
CAL_HI1, CAL_LO1 = 0x0D2C6C, 0x0D2C64       # mode == 1 pair, 1.56 / 0.537
CAL_HI0, CAL_LO0 = 0x0D2C68, 0x0D2C60       # mode != 1 pair, same values in this bin
CAL_MAXEN, CAL_MAXW4 = 0x0D29D4, 0x0D29D6    # u16 88, u16 25


def rom_f32(a):
    return struct.unpack_from('>f', ROM, a)[0]


def rom_u16(a):
    return struct.unpack_from('>H', ROM, a)[0]


def f32(x):
    return b2f(f2b(x))


def hyst(state, x, hi, width):
    """0x0BE800: 0BE800 fcmp/gt fr4,fr5 (T = hi > x); 0BE80A fsub fr6,fr5; 0BE80C fcmp/gt fr4,fr5."""
    if not hi > x:                   # x >= hi, or unordered
        return 1
    if b2f(fsub_bits(f2b(hi), f2b(width))) > x:      # 0BE80A fsub, rounded toward zero
        return 0
    return state


def width_of(hi, lo):
    """0423A6 / 0423D0: fsub fr8,fr6 -> width = hi - lo, rounded toward zero (exact for this bin's pair)."""
    return b2f(fsub_bits(f2b(hi), f2b(lo)))


def check_lookup_saturation():
    n = 0
    for d in ALL_DESC:
        t = DT.read_table(ROM, d)
        first, last = f2b(t['values'][0]), f2b(t['values'][-1])
        for x in (-1e9, float('-inf'), -1.0, -0.0, 0.0):
            assert rom_lookup_bits(d, f2b(x)) == first, (hex(d), x)
            n += 1
        for x in (87.5, 88.0, 1e9, float('inf'), float('nan')):       # NaN: fcmp/gt is false -> last cell
            assert rom_lookup_bits(d, f2b(x)) == last, (hex(d), x)
            n += 1
    print(f'0x0BE830 saturates outside the 0..87.5 axis (first cell below, last cell above and for NaN): {n} cases OK')


def check_hysteresis_helper():
    n = 0
    hi, lo = rom_f32(CAL_HI1), rom_f32(CAL_LO1)
    width = width_of(hi, lo)
    # both fsubs are exact for 1.56 / 0.537, so the off threshold is lo to the bit (whatever the rounding mode)
    assert Fraction(width) == Fraction(hi) - Fraction(lo), 'hi - lo is inexact in float32'
    assert fsub_bits(f2b(hi), f2b(width)) == f2b(lo), 'hi - (hi - lo) is not bit-equal to lo in float32'
    below_hi, below_lo = b2f(f2b(hi) - 1), b2f(f2b(lo) - 1)
    for st in (0, 1, 7):
        for x in (-1.0, 0.0, below_lo, lo, 0.54, 1.0, below_hi, hi, 1.57, 1e9, float('nan')):
            e = E.Emu(ROM)
            e.call(FN_HYST, regs={4: st}, fregs={4: x, 5: hi, 6: width})
            assert e.R[0] == hyst(st, f32(x), hi, width), (st, x, e.R[0])
            n += 1
    print(f'0x0BE800 == hysteresis(state, x, hi, width): 1 at x >= hi, 0 at x < hi - width, else state '
          f'({n} cases; hi {hi:.7g}, hi - width {lo:.7g})')


def model_enable(F, W, c78, c76, bbits, mode):
    """0x042368. Returns (F', W', [0xFFFF8078]', write-set)."""
    wr = {FLG16, FLG16 + 1}                            # W is stored on every path (042438)
    if F & 2:                                          # 04237C: calls-with-bit1-set counter
        if c78 != 0xFFFF:                              # 042384-042388: saturates at 0xFFFF
            c78 = (c78 + 1) & 0xFFFF
            wr |= {CNT_EN, CNT_EN + 1}
    else:
        c78 = 0
        wr |= {CNT_EN, CNT_EN + 1}
    hi, lo = (rom_f32(CAL_HI1), rom_f32(CAL_LO1)) if mode == 1 else (rom_f32(CAL_HI0), rom_f32(CAL_LO0))
    r = hyst(1 if W & 0x0200 else 0, b2f(bbits), hi, width_of(hi, lo))
    W = (W | 0x0200) if r == 1 else (W & 0xFDFF)
    ok = bool(F & 1) and c78 < rom_u16(CAL_MAXEN) and c76 < rom_u16(CAL_MAXW4) and not ((W & 4) and not (W & 2))
    if ok:
        if W & 0x0200:                                 # 042464-04246C; when clear NOTHING is changed
            F |= 2
            wr.add(FLG8)
    else:                                              # 042476-042482
        F &= 0xFD
        wr.add(FLG8)
        W &= 0xFFFE
    return F, W, c78, wr


def check_enable_logic():
    e = E.Emu(ROM)
    lo, hi = rom_f32(CAL_LO1), rom_f32(CAL_HI1)
    Bs = [0.0, 0.5, b2f(f2b(lo) - 1), lo, 0.54, 1.0, b2f(f2b(hi) - 1), hi, 2.0, -1.0, float('nan')]
    n = 0
    reads = set()
    for F, mode, c78, c76, W in itertools.product((0, 1, 2, 3, 0xFC, 0xFD, 0xFE, 0xFF), (0, 1, 2),
                                                  (0, 1, 86, 87, 88, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF),
                                                  (0, 24, 25, 0x8000, 0xFFFF),
                                                  (0x0000, 0x0002, 0x0004, 0x0006, 0x0200, 0x0207, 0xFFFF, 0x7001)):
        bb = f2b(Bs[n % len(Bs)])
        e.init = bytearray(len(e.init)); e.uninit_reads.clear(); e.writes.clear()
        e.stack_low = E.STACK_TOP; e.steps = 0
        poke(e, FLG8, 1, F); poke(e, FLG16, 2, W); poke(e, CNT_EN, 2, c78); poke(e, CNT_W4, 2, c76)
        poke(e, IN_B, 4, bb); poke(e, IN_MODE, 1, mode)
        assert e.call(FN_ENABLE) == 'return'
        o = E.RAM_LO
        got = (e.ram[FLG8 - o], int.from_bytes(e.ram[FLG16 - o:FLG16 - o + 2], 'big'),
               int.from_bytes(e.ram[CNT_EN - o:CNT_EN - o + 2], 'big'))
        wF, wW, wc, wwr = model_enable(F, W, c78, c76, bb, mode)
        tag = f'F={F:#x} W={W:#x} c78={c78:#x} c76={c76:#x} B={Bs[n % len(Bs)]} mode={mode}'
        assert got == (wF, wW, wc), f'0x042368 OUTPUT {tag}: got {got} want {(wF, wW, wc)}'
        assert set(e.writes) == wwr, f'0x042368 WRITE-SET {tag}: {sorted(map(hex, e.writes))}'
        assert (F ^ got[0]) & 0xFD == 0 and (W ^ got[1]) & 0xFDFE == 0     # only F bit1; only W 0x0200 / 0x0001
        reads |= e.uninit_reads
        n += 1
    assert reads == {IN_B, IN_MODE, FLG8, CNT_W4, CNT_EN, FLG16}, sorted(map(hex, reads))
    print(f'0x042368 == model (F bit1 set/clear rules, W bit 0x0200 hysteresis of B, W bit0 clear; '
          f'W stored on every call): {n} cases OK')


def check_flag_owners():
    """Which bits of F and W the two other siblings can change (random inputs, real callees)."""
    r = random.Random(11)
    e = E.Emu(ROM)

    def reset():
        e.init = bytearray(len(e.init)); e.uninit_reads.clear(); e.writes.clear()
        e.stack_low = E.STACK_TOP; e.steps = 0
    o = E.RAM_LO
    seen = 0
    for _ in range(1500):                                   # 0x041EEE
        reset()
        F, W = r.getrandbits(8), r.getrandbits(16)
        poke(e, FLG8, 1, F); poke(e, FLG16, 2, W)
        poke(e, IN_A, 4, f2b(r.uniform(0, 7000))); poke(e, 0xFFFF65FC, 4, f2b(r.uniform(0, 200)))
        poke(e, 0xFFFF6350, 4, f2b(r.uniform(-40, 120))); poke(e, 0xFFFF73E8, 4, f2b(r.uniform(-5, 100)))
        poke(e, 0xFFFF5E74, 2, r.getrandbits(16)); poke(e, 0xFFFF64F5, 1, r.choice((0, 0, 1)))
        poke(e, 0xFFFF64F4, 1, r.choice((0, 0, 1))); poke(e, 0xFFFF65C0, 1, r.choice((0, 0, 1)))
        poke(e, IN_MODE, 1, r.choice((0, 1)))
        poke(e, 0xFFFF807A, 2, r.choice((0, 1, 5, 50, 500, 0xFFFF))); poke(e, 0xFFFF807C, 2, r.choice((0, 1, 5, 50, 0xFFFF)))
        assert e.call(FN_F0) == 'return'
        F2, W2 = e.ram[FLG8 - o], int.from_bytes(e.ram[FLG16 - o:FLG16 - o + 2], 'big')
        assert (F ^ F2) & 0xFE == 0 and (W ^ W2) & 0xFEFF == 0, (hex(F), hex(F2), hex(W), hex(W2))
        assert {FLG8, FLG16, FLG16 + 1} <= set(e.writes)
        seen |= (W ^ W2)
    assert seen == 0x0100
    seen = 0
    for _ in range(2500):                                   # 0x04209A
        reset()
        F, W = r.getrandbits(8), r.getrandbits(16)
        poke(e, FLG8, 1, F); poke(e, FLG16, 2, W); poke(e, IN_MODE, 1, r.choice((0, 1)))
        poke(e, IN_A, 4, f2b(r.uniform(0, 7000))); poke(e, CNT_W4, 2, r.choice((0, 1, 24, 25, 0xFFFF)))
        for a in (0xFFFF804C, 0xFFFF8050, 0xFFFF8054, 0xFFFF8058):
            poke(e, a, 4, f2b(r.uniform(0, 7000)))
        assert e.call(FN_WOWNER) == 'return'
        W2 = int.from_bytes(e.ram[FLG16 - o:FLG16 - o + 2], 'big')
        assert (W ^ W2) & ~0xF807 & 0xFFFF == 0, (hex(W), hex(W2))
        assert FLG8 not in e.writes and {FLG16, FLG16 + 1} <= set(e.writes)
        c76 = int.from_bytes(e.ram[CNT_W4 - o:CNT_W4 - o + 2], 'big')
        assert (c76 == 0) == (not W2 & 0x4000) or c76 == 0xFFFF       # zero exactly when 0x4000 is clear
        seen |= (W ^ W2)
    assert seen & 0x7006 == 0x7006, hex(seen)
    print(f'flag owners: 0x041EEE changes only F bit0 and W bit 0x0100; 0x04209A never writes F and changes only '
          f'W bits within 0xF807 (seen {seen:#06x}); [0xFFFF8076] is 0 exactly when W bit 0x4000 is clear after it')


def _chain_emu(F=1, W=0x4000, sel=1, A=2000.0, fac=1.0):
    e = E.Emu(ROM)
    for a in range(0xFFFF804C, 0xFFFF8084, 4):
        e.ram_u32(a, 0)
    e.ram_u8(IN_MODE, 1); e.ram_u8(FLG8, F); e.ram_u16(FLG16, W); e.ram_f32(IN_A, A); e.ram_u8(IN_SEL, sel)
    e.ram_f32(FAC_A, fac); e.ram_u8(0xFFFF6254, 0); e.ram_f32(IN_B, 0.0)
    return e


def _chain_pass(e, b, fns=(FN_ENABLE, FN_FAC, ENTRY)):
    """One pass of the runner's order (0492CE-0492DC): 0x042368, 0x04248C, 0x042506."""
    e.ram_f32(IN_B, b)
    for fn in fns:
        e.steps = 0
        assert e.call(fn) == 'return'
    return dict(F=e.read_u8(FLG8), W=e.read_u16(FLG16), c78=e.read_u16(CNT_EN), c76=e.read_u16(CNT_W4),
                peak=e.read_f32(PEAK), lut=e.read_f32(LUT), step=e.read_f32(STEP), out=e.read_f32(OUT),
                outbits=e.read_u32(OUT), lutbits=e.read_u32(LUT), stepbits=e.read_u32(STEP),
                fabits=e.read_u32(FAC_A), fbbits=e.read_u32(FAC_B), fb=e.read_f32(FAC_B))


def _product_bits(r):
    """0429A0-0429BA as the chip computes it: ((table * step) * [806C]) * [8068], each fmul rounded toward zero."""
    return fmul_bits(fmul_bits(fmul_bits(r['lutbits'], r['stepbits']), r['fabits']), r['fbbits'])


def _quoted(x, text):
    """The figure exactly as fn_042506_trace.txt quotes it, to the decimals it quotes."""
    k = len(text.split('.')[1])
    assert f'{x:.{k}f}' == text, f'trace quotes {text}, value is {x!r} ({x:.{k}f})'


def check_chain():
    lo, hi = rom_f32(CAL_LO1), rom_f32(CAL_HI1)
    n = 0
    print()
    print('chain 0x042368 -> 0x04248C -> 0x042506 (mode byte 1, sel 1, A 2000, F bit0 preset, W 0x4000, [806C] 1.0):')
    print('  B           | F    W      [8078] peak        table      step  OUT')
    e = _chain_emu()
    for b in (0.0, 1.0, 1.55, b2f(f2b(hi) - 1)):
        r = _chain_pass(e, b); n += 1
        assert not r['F'] & 2 and r['outbits'] == 0, (b, r)
        print(f"  {b:<11.9g} | {r['F']:#04x} {r['W']:#06x} {r['c78']:<6} {r['peak']:<11.9g} {r['lut']:<10.7g} {r['step']:<5.4g} {r['out']:.7g}")
    r = _chain_pass(e, hi); n += 1                       # the hysteresis bit turns on in this pass
    print(f"  {hi:<11.9g} | {r['F']:#04x} {r['W']:#06x} {r['c78']:<6} {r['peak']:<11.9g} {r['lut']:<10.7g} {r['step']:<5.4g} {r['out']:.7g}")
    assert r['F'] & 2 and r['W'] & 0x0200 and r['peak'] == hi and r['fb'] == 1.0
    assert r['lutbits'] == rom_lookup_bits(DESC_M1[0][1], f2b(hi)) and r['step'] == 1.25, r
    assert r['outbits'] == _product_bits(r), r                       # bit-exact, round toward zero
    _quoted(r['lut'], '-23.7324'); _quoted(r['out'], '-29.6655')
    first_out = r['out']
    en_calls = 1
    while True:                                          # B back at 0: how long does bit1 stay set?
        r = _chain_pass(e, 0.0); n += 1
        if not r['F'] & 2:
            break
        assert r['peak'] == hi and r['out'] == first_out            # the peak is held, OUT repeats
        en_calls += 1
        assert en_calls < 1000
    assert en_calls == rom_u16(CAL_MAXEN) == 88 and r['c78'] == 88 and r['outbits'] == 0 and r['peak'] == 0.0
    print(f'  B = 0 afterwards: bit1 stays set for {en_calls} calls in all (peak held at {hi:.7g}); '
          f'the next call clears it and zeroes OUT')

    # the lowest B that can coincide with a set: hysteresis bit already on (bit0 was clear), B at the lower threshold
    for b, want_set in ((lo, True), (0.54, True), (b2f(f2b(lo) - 1), False)):
        e = _chain_emu(F=0)
        _chain_pass(e, 2.0)                              # W bit 0x0200 on; bit0 clear, so no enable
        r0 = _chain_pass(e, b)
        assert not r0['F'] & 2
        e.ram_u8(FLG8, e.read_u8(FLG8) | 1)              # what 0x041EEE does at 042076-04207E
        r = _chain_pass(e, b); n += 3
        assert bool(r['F'] & 2) == want_set, (b, r)
        print(f"  hysteresis already on, B = {b:.9g}: F {r['F']:#04x}  peak {r['peak']:.9g}  table {r['lut']:.7g}  OUT {r['out']:.7g}")
        if want_set:
            assert r['lutbits'] == rom_lookup_bits(DESC_M1[0][1], f2b(b)) and r['outbits'] == _product_bits(r), r
        if b == lo:
            floor = r['out']
            _quoted(r['lut'], '-24.53805'); _quoted(floor, '-30.6726')
        elif want_set:
            _quoted(r['out'], '-30.6696')
    # sweep: starting with bit1 clear, the peak is never below the lower threshold while bit1 is set
    rnd = random.Random(3)
    minpeak, minout = 1e9, 0.0
    for _ in range(150):
        e = _chain_emu(F=rnd.choice((0, 1)), W=0x4000 | rnd.choice((0, 0x0200)), sel=rnd.choice((1, 1, 1, 2, 3, 4, 5, 6)),
                       A=rnd.choice((2000.0, 3500.0)))
        for _k in range(40):
            if rnd.random() < 0.1:
                e.ram_u8(FLG8, e.read_u8(FLG8) ^ 1)
            b = rnd.choice((0.0, -3.0, 0.3, lo, 0.6, 1.0, hi, 5.0, 20.0, rnd.uniform(-2, 3)))
            r = _chain_pass(e, b); n += 1
            if r['F'] & 2:
                assert r['peak'] >= lo, r
                minpeak, minout = min(minpeak, r['peak']), min(minout, r['out'])
            else:
                assert r['outbits'] == 0 and r['peak'] == 0.0
    assert minpeak >= lo and minout >= floor
    print(f'  sweep ({150 * 40} passes from bit1 clear): min peak while bit1 set {minpeak:.9g}, min OUT {minout:.7g} '
          f'(arithmetic bound -24.9609375 * 1.25 = -31.201171875 is never reached with a finite B)')

    # with 0x04209A in front (it owns W bit 0x4000 and the counter [0xFFFF8076])
    rnd = random.Random(5)
    maxrun = maxen = total = 0
    for _ in range(60):
        e = _chain_emu(F=1, W=0, sel=rnd.choice((1, 1, 2, 3, 4, 5)))
        rpm = rnd.uniform(800, 3500)
        run_ = enrun = 0
        for _k in range(120):
            rpm = max(500.0, rpm + rnd.choice((-40, -10, 0, 0, 5, 15, 30, 60, 120)))
            e.ram_f32(IN_A, rpm)
            if rnd.random() < 0.03:
                e.ram_u8(FLG8, e.read_u8(FLG8) ^ 1)
            r = _chain_pass(e, rnd.choice((0.0, 0.0, 0.3, 0.8, 1.6, 3.0, 10.0, 30.0)),
                            fns=(FN_WOWNER, FN_ENABLE, FN_FAC, ENTRY))
            total += 1
            assert r['out'] >= floor, r
            minout = min(minout, r['out'])
            if r['F'] & 2:
                assert r['c76'] < 25 and r['c78'] < 88 and r['peak'] >= lo, r
                enrun += 1
            else:
                enrun = 0
            if r['F'] & 2 and r['W'] & 0x4000:
                assert 1 <= r['c76'] <= 24, r
                run_ += 1
            else:
                run_ = 0
            maxrun, maxen = max(maxrun, run_), max(maxen, enrun)
    assert maxrun <= 24 and maxen <= 88
    assert minout == floor
    _quoted(minout, '-30.6726')
    n += total
    print(f'  with 0x04209A in front ({total} passes, random walk of A): longest run with bit1 and W bit 0x4000 both set '
          f'= {maxrun} (bound 24 = ROM[0x0D29D6] - 1), longest run with bit1 set = {maxen} (bound 88); '
          f'min OUT over both sweeps {minout:.7g}')
    print('  (both sweeps use finite B only: see check_nan_edge for what a NaN B does)')
    return n


def check_fmac_sensitivity():
    """How much the quoted chain figures depend on fmac being FUSED, which the ROM self-test does not settle.

    The emulator rounds fmac once (fused, toward zero). This probe re-runs 0x0BE830 with fmac computed as a
    multiply and an add, each rounded toward zero (unfused), and compares. It is a sensitivity bound, not a
    model of the chip: whichever of the two the SH7058 does, the figures quoted in the trace must hold.
    It reaches into the emulator's private FPU dispatcher (_fpu), so it breaks loudly if that changes.
    """
    class _Unfused(E.Emu):
        def _fpu(self, w, pc, R, n, m, d4):
            if d4 == 0xE:                                  # fmac fr0,FRm,FRn
                self.FR[n] = rz_arith('+', rz_arith('*', self.FR[0], self.FR[m]), self.FR[n])
                return 'fmac'
            return super()._fpu(w, pc, R, n, m, d4)

    def unfused_lookup(desc, xbits):
        u = _Unfused(ROM)
        u.call(FN_LOOKUP, regs={4: desc}, fregs={4: b2f(xbits)})
        return u.FR[0]

    n = ndiff = worst = 0
    for d in ALL_DESC:
        for k in range(0, 360):                          # x = 0 .. 89.75 in steps of 0.25, plus the odd points
            for x in (k * 0.25, k * 0.25 + 0.0123):
                xb = f2b(x)
                a, b = rom_lookup_bits(d, xb), unfused_lookup(d, xb)
                assert (a ^ b) & 0x80000000 == 0 or a & 0x7FFFFFFF == b & 0x7FFFFFFF == 0, (hex(d), x)
                ulps = abs((a & 0x7FFFFFFF) - (b & 0x7FFFFFFF))
                if ulps:                                 # only where neighbouring cells differ: the D1 ramp
                    assert d in DESC_M1[0].values() and 0.0 < x < 12.5, (hex(d), x)
                ndiff += ulps != 0
                worst = max(worst, ulps)
                n += 1
    assert (ndiff, worst) == (480, 2), (ndiff, worst)    # the figures fn_042506_trace.txt quotes
    lo, hi = rom_f32(CAL_LO1), rom_f32(CAL_HI1)
    # -24.53805 is quoted to 5 decimals because its 4th straddles a rounding boundary: fused -24.5380497,
    # unfused -24.5380516 (the trace's earlier "-24.5381" was a hand rounding of the printed -24.53805)
    for x, q_lut, q_out in ((hi, '-23.7324', '-29.6655'), (lo, '-24.53805', '-30.6726'), (0.54, None, '-30.6696')):
        for lut in (rom_lookup_bits(DESC_M1[0][1], f2b(x)), unfused_lookup(DESC_M1[0][1], f2b(x))):
            if q_lut:
                _quoted(b2f(lut), q_lut)
            _quoted(b2f(fmul_bits(lut, f2b(1.25))), q_out)
        n += 2
    print(f'fmac fused vs unfused (both toward zero) in 0x0BE830 on the 12 descriptors: {ndiff} of {n - 6} lookups '
          f'differ, by at most {worst} ulp; the quoted -23.7324 / -29.6655, -24.53805 / -30.6726 and -30.6696 '
          f'hold under both')
    return n


def check_nan_edge():
    """The floor -30.67 assumes B is not NaN on the call that sets F bit1.

    0BE800 fcmp/gt fr4,fr5: T = (hi > B) is FALSE for a NaN B -> result 1 (hysteresis on), so the
    bit can be set; 0BE960 fcmp/gt fr5,fr4: T = (peak > B) is FALSE for a NaN peak -> B is returned,
    so the NaN peak is replaced by the next B, which can be 0 or below.
    """
    n = 0
    print()
    print('edge: a NaN B on the setting call (chain 0x042368 -> 0x04248C -> 0x042506, mode 1, sel 1, A 2000):')
    e = _chain_emu(F=1)
    r = _chain_pass(e, float('nan')); n += 1
    assert r['F'] & 2 and r['W'] & 0x0200 and r['peak'] != r['peak'], r
    assert r['outbits'] == f2b(-15.1171875 * 1.25), r                  # NaN lookup -> last cell
    print(f"  B = NaN : F {r['F']:#04x}  peak {r['peak']}  table {r['lut']:.7g}  OUT {r['out']:.7g}")
    for b in (0.0, -1.0, 0.0):
        r = _chain_pass(e, b); n += 1
        assert r['F'] & 2 and r['peak'] == 0.0, r                          # max(NaN, 0) = 0, then max(0, -1) = 0
        assert r['outbits'] == f2b(-24.9609375 * 1.25), r                 # -31.201171875 IS reached
        print(f"  B = {b:<4}: F {r['F']:#04x}  peak {r['peak']:.7g}  table {r['lut']:.7g}  OUT {r['out']:.9g}")
    # a +inf B also sets the bit, but then the peak stays +inf: no lower value
    e = _chain_emu(F=1)
    r1 = _chain_pass(e, float('inf')); r2 = _chain_pass(e, 0.0); n += 2
    assert r1['F'] & 2 and r2['peak'] == float('inf') and r2['outbits'] == f2b(-15.1171875 * 1.25)
    # a -inf B leaves the hysteresis off: no set
    e = _chain_emu(F=1)
    r = _chain_pass(e, float('-inf')); n += 1
    assert not r['F'] & 2 and r['outbits'] == 0
    print('  +inf B sets the bit and the peak stays +inf (OUT -18.896); -inf B does not set it')

    # why a NaN B needs non-finite history: the 2-D lookup is finite for any input
    vals = (float('nan'), float('inf'), float('-inf'), -1e30, 1e30, 0.0, 2000.0, 9.3)
    for a, b in itertools.product(vals, vals):
        ee = E.Emu(ROM)
        ee.call(0x0BE8E4, regs={4: 0x0AB058}, fregs={4: a, 5: b})
        x = b2f(ee.FR[0])
        assert x == x and abs(x) != float('inf') and 0.0 <= x <= 100.0, (a, b, x)
        n += 1
    for a, b in ((float('nan'), 5.0), (2000.0, float('nan')), (float('inf'), float('-inf')), (float('nan'), float('nan'))):
        ee = E.Emu(ROM)
        for cell in (0xFFFF6344, 0xFFFF6348, 0xFFFF62FC):
            ee.ram_f32(cell, 10.0)
        ee.ram_f32(IN_A, a); ee.ram_f32(0xFFFF62DC, b)
        assert ee.call(0x01F5F2) == 'return'
        bb = ee.read_f32(IN_B)
        assert bb == bb and abs(bb) != float('inf'), (a, b, bb)
        n += 1
    print(f'  0x0BE8E4 on 0x0AB058 returns 0..100 for NaN / +-inf / huge inputs (64 cases); 0x01F5F2 with finite '
          f'history and NaN / inf inputs gives a finite B (4 cases)')

    # 0x023EB8 with a NaN ratio: every fcmp/gt of the ladder is false -> 1
    for rpm, spd in ((float('nan'), 40.0), (2000.0, float('nan'))):
        ee = E.Emu(ROM)
        for a in (0xFFFF65C0, 0xFFFF9704, 0xFFFF5E93, 0xFFFF5F03, 0xFFFF5FB8):
            ee.ram_u8(a, 0)
        ee.ram_u8(IN_MODE, 1); ee.ram_f32(IN_A, rpm); ee.ram_f32(0xFFFF65FC, spd)
        assert ee.call(0x023EB8) == 'return'
        assert (ee.read_u8(IN_SEL), ee.read_u8(IN_SEL + 1)) == (1, 1), (rpm, spd)
        n += 1
    print('  0x023EB8: a NaN [0xFFFF6624] or [0xFFFF65FC] gives ([0xFFFF6810], [0xFFFF6811]) = (1, 1)')
    return n


SEL_SETS = {'A': 0x0C3474, 'B': 0x0C3488, 'C': 0x0C349C}


def model_sel(c):
    """0x023EB8. Returns (sel or None when not written, [0xFFFF6811], threshold set)."""
    setn = 'A' if c['b5F03'] == 1 else ('B' if c['b5FB8'] == 1 else 'C')
    t = struct.unpack_from('>5f', ROM, SEL_SETS[setn])
    if c['mode'] == 0:                                   # 023F56: tst r2,r2 -- "non-zero", not "== 1"
        v = c['b5E93']
        if v > 7:
            return None, None, setn
        if v == 7:
            return 1, 1, setn
        if v in (0, 6):
            return 6, 0, setn
        return v, v, setn
    if c['b65C0'] == 1 or c['b9704'] != 0:               # 023F7A / 023F80 (0x0297A0 returns 2 for a non-zero byte)
        return 6, 0, setn
    rpm, spd = f32(c['rpm']), f32(c['spd'])
    if 0.1953125 > rpm:                                  # 023F8C
        return 5, 6, setn
    # 023F94 / 023F9E: two calls of 0x0BE628, which is a plain fdiv once fr5 != 0 (0BE646-0BE648); the
    # 0.1953125 guard above keeps rpm / 1000 non-zero. Each quotient is rounded toward zero.
    q1 = fdiv_bits(f2b(rpm), f2b(1000.0))
    ratio = b2f(fdiv_bits(f2b(spd), q1))
    for i in range(4):
        if not ratio > t[i]:
            return i + 1, i + 1, setn
    if not ratio > t[4]:
        return 5, 5, setn
    return 5, 6, setn                                    # above the 200.0 rung: sel is still 5


def check_sel_writers():
    e = E.Emu(ROM)
    o = E.RAM_LO
    ratios = [0.0, 5.0, 13.4, 13.42, 18.0, 18.05, 23.5, 23.6, 32.5, 32.6, 100.0, 199.9, 200.0, 200.1, 1000.0]
    n = 0
    for mode, b5E93, b65C0, b9704, b5F03, b5FB8 in itertools.product((0, 1, 2, 0xFF), (0, 1, 2, 3, 4, 5, 6, 7, 8, 0x80, 0xFF),
                                                                   (0, 1, 2), (0, 1, 0xFF), (0, 1), (0, 1)):
        for rpm in (0.0, 0.19, 0.1953125, 800.0, 3000.0):
            rr = ratios[n % len(ratios)]
            c = dict(mode=mode, b5E93=b5E93, b65C0=b65C0, b9704=b9704, b5F03=b5F03, b5FB8=b5FB8, rpm=rpm,
                     spd=rr * (rpm / 1000.0) if rpm > 0 else 50.0)
            e.init = bytearray(len(e.init)); e.writes.clear(); e.stack_low = E.STACK_TOP; e.steps = 0
            poke(e, 0xFFFF9704, 1, b9704); poke(e, 0xFFFF5E93, 1, b5E93); poke(e, 0xFFFF5F03, 1, b5F03)
            poke(e, 0xFFFF5FB8, 1, b5FB8); poke(e, IN_MODE, 1, mode); poke(e, 0xFFFF65C0, 1, b65C0)
            poke(e, IN_A, 4, f2b(c['rpm'])); poke(e, 0xFFFF65FC, 4, f2b(c['spd']))
            poke(e, IN_SEL, 1, 0x77); poke(e, IN_SEL + 1, 1, 0x66)
            assert e.call(0x023EB8) == 'return'
            sel, nb, setn = model_sel(c)
            got = (e.ram[IN_SEL - o], e.ram[IN_SEL + 1 - o])
            if sel is None:
                assert got == (0x77, 0x66) and IN_SEL not in e.writes, (c, got)
            else:
                assert got == (sel, nb), (c, got, sel, nb)
            thr = struct.unpack_from('>5f', ROM, SEL_SETS[setn])
            assert tuple(b2f(int.from_bytes(e.ram[0xFFFF6814 + 4 * i - o:0xFFFF6818 + 4 * i - o], 'big'))
                         for i in range(5)) == thr, c
            n += 1
    print()
    print(f'0x023EB8 == model on every path ({n} cases). mode byte non-zero, [0xFFFF65C0] = 0, [0xFFFF9704] = 0, A = 2000:')
    print('  ratio      -> ([0xFFFF6810], [0xFFFF6811])')
    for rr in (0.0, 13.4, 13.42, 18.0, 18.05, 23.5, 23.6, 32.5, 32.6, 199.0, 200.0, 200.1, 1000.0):
        ee = E.Emu(ROM)
        for a in (0xFFFF9704, 0xFFFF5E93, 0xFFFF5F03, 0xFFFF5FB8, 0xFFFF65C0):
            ee.ram_u8(a, 0)
        ee.ram_u8(IN_MODE, 1); ee.ram_f32(IN_A, 2000.0); ee.ram_f32(0xFFFF65FC, rr * 2.0)
        ee.call(0x023EB8)
        got = (ee.read_u8(IN_SEL), ee.read_u8(IN_SEL + 1))
        want = (5, 6) if rr > 200.0 else (5, 5) if rr > 32.5434 else (4, 4) if rr > 23.5448 else \
            (3, 3) if rr > 18.0483 else (2, 2) if rr > 13.4159 else (1, 1)
        assert got == want, (rr, got)
        print(f'  {rr:<10} -> {got}')
    # above the 200.0 rung and below 0.1953125 on A the selector is 5, and 6 goes only to the neighbour byte
    # the second writer: stores 6 unconditionally, sets [0xFFFF6812] = 1 and loads threshold set B
    ee = E.Emu(ROM)
    ee.ram_u8(IN_SEL, 3)
    assert ee.call(0x024094) == 'return' and not ee.uninit_reads
    assert ee.read_u8(IN_SEL) == 6 and ee.read_u8(IN_SEL + 2) == 1
    assert tuple(ee.read_f32(0xFFFF6814 + 4 * i) for i in range(5)) == struct.unpack_from('>5f', ROM, SEL_SETS['B'])
    assert set(ee.writes) == {IN_SEL, IN_SEL + 2} | set(range(0xFFFF6814, 0xFFFF6828))
    for v in range(256):                                  # 0x0297A0: 2 for a non-zero byte, else 0
        ee = E.Emu(ROM); ee.ram_u8(0xFFFF9704, v); ee.call(0x0297A0)
        assert ee.R[0] == (2 if v else 0)
    print('0x024094 stores 6 to 0xFFFF6810 unconditionally (+ [0xFFFF6812] = 1, threshold set B); '
          '0x0297A0 returns 2 for a non-zero byte [0xFFFF9704], else 0')
    print('threshold sets in this bin:', ', '.join(f'{k} 0x{a:06X} = ' + '/'.join(f'{x:.3f}' for x in
          struct.unpack_from('>5f', ROM, a)) for k, a in SEL_SETS.items()))
    return n


# ================================================================ printed tables
def show():
    print()
    print('4-float arrays indexed by the counter [0xFFFF8074] (value stored to 0xFFFF8064):')
    for name, arr in (('mode!=1          ', ARR_M0), ('mode==1, A< 3000', ARR_M1_LO), ('mode==1, A>=3000', ARR_M1_HI)):
        for sel in (1, 2, 3, 4, 5, 'other'):
            base = arr[0].get(sel, arr[1])
            v = struct.unpack_from('>4f', ROM, base)
            print(f'  {name} sel={sel!s:5} 0x{base:06X}: ' + ', '.join(f'{x:.4g}' for x in v))
    print()
    print('descriptors (input = peak-held [0xFFFF8070]; value stored to 0xFFFF8060):')
    for name, d in (('mode!=1', DESC_M0), ('mode==1', DESC_M1)):
        for sel in (1, 2, 3, 4, 5, 'other'):
            a = d[0].get(sel, d[1])
            t = DT.read_table(ROM, a)
            print(f'  {name} sel={sel!s:5} 0x{a:06X}: ' + ', '.join(f'{x:.4f}' for x in t['values']))
    print()
    print('single calls with F and W FORCED by the test (see the chain check for what the sibling 0x042368 allows),')
    print('F=[0xFFFF8075] W=[0xFFFF8080], prior OUT=123.456, facA=facB=1.0, peak_in=0:')
    print('  F    W      ctr mode sel A      B     | ctr\' step     peak\'    lut        OUT')
    rows = [
        dict(F=0, W=0x4006, ctr=2, mode=1, sel=1, A=2000.0, B=50.0),
        dict(F=2, W=0x0000, ctr=0, mode=1, sel=1, A=2000.0, B=50.0),
        dict(F=2, W=0x4000, ctr=0, mode=1, sel=1, A=2000.0, B=0.0),
        dict(F=2, W=0x4000, ctr=0, mode=1, sel=1, A=2000.0, B=6.25),
        dict(F=2, W=0x4000, ctr=0, mode=1, sel=1, A=2000.0, B=50.0),
        dict(F=2, W=0x4000, ctr=0, mode=1, sel=1, A=3000.0, B=50.0),
        dict(F=2, W=0x4000, ctr=1, mode=1, sel=1, A=2000.0, B=50.0),
        dict(F=2, W=0x4006, ctr=1, mode=1, sel=1, A=2000.0, B=50.0),
        dict(F=2, W=0x4006, ctr=3, mode=1, sel=1, A=2000.0, B=50.0),
        dict(F=2, W=0x4000, ctr=0, mode=1, sel=4, A=2000.0, B=50.0),
        dict(F=2, W=0x4000, ctr=0, mode=1, sel=5, A=2000.0, B=50.0),
        dict(F=2, W=0x4000, ctr=0, mode=1, sel=6, A=2000.0, B=50.0),
        dict(F=2, W=0x4000, ctr=0, mode=1, sel=6, A=3000.0, B=50.0),
        dict(F=2, W=0x4000, ctr=0, mode=0, sel=1, A=2000.0, B=50.0),
        dict(F=2, W=0x4000, ctr=0, mode=0, sel=2, A=2000.0, B=50.0),
        dict(F=2, W=0x4000, ctr=0, mode=0, sel=3, A=2000.0, B=50.0),
        dict(F=2, W=0x4000, ctr=1, mode=0, sel=3, A=2000.0, B=50.0),
        dict(F=2, W=0x4000, ctr=0, mode=0, sel=6, A=2000.0, B=50.0),
        dict(F=2, W=0x5000, ctr=0, mode=1, sel=1, A=2000.0, B=50.0),
        dict(F=2, W=0x6000, ctr=0, mode=1, sel=1, A=2000.0, B=50.0),
        dict(F=2, W=0x7000, ctr=0, mode=1, sel=1, A=2000.0, B=50.0),
    ]
    for r in rows:
        c = case(F=r['F'], W=r['W'], ctr=r['ctr'], mode=r['mode'], sel=r['sel'], A=f2b(r['A']),
                 B=f2b(r['B']), out=f2b(123.456))
        g = run(c)
        print(f"  {r['F']:#04x} {r['W']:#06x} {r['ctr']}   {r['mode']}    {r['sel']}   {r['A']:6.0f} {r['B']:5.2f} |"
              f" {g[CTR]}    {fmt(g[STEP]):8} {fmt(g[PEAK]):8} {fmt(g[LUT]):10} {fmt(g[OUT])}")

    print()
    print('consecutive calls (state carried in RAM), mode==1 sel=1 A=2000, facA=facB=1.0:')
    print('  call F    W      B     | ctr  step   peak   lut        OUT')
    seq = [(2, 0x4000, 5.0), (2, 0x4000, 20.0), (2, 0x4000, 10.0), (2, 0x4006, 10.0), (2, 0x4006, 10.0),
           (2, 0x4006, 10.0), (2, 0x4006, 10.0), (2, 0x0006, 10.0), (0, 0x4006, 10.0), (2, 0x4000, 2.0)]
    st = dict(ctr=0, peak=0, lut=0, step=0, out=0)
    for i, (F, W, B) in enumerate(seq, 1):
        g = run(case(F=F, W=W, ctr=st['ctr'], mode=1, sel=1, A=f2b(2000.0), B=f2b(B), peak=st['peak'],
                     lut=st['lut'], step=st['step'], out=st['out']))
        st = dict(ctr=g[CTR], peak=g[PEAK], lut=g[LUT], step=g[STEP], out=g[OUT])
        print(f'  {i:<4} {F:#04x} {W:#06x} {B:5.1f} | {g[CTR]}    {fmt(g[STEP]):6} {fmt(g[PEAK]):6} '
              f'{fmt(g[LUT]):10} {fmt(g[OUT])}')
    # the sequence above encodes these contract points; assert them explicitly
    assert st['ctr'] == 0 and b2f(st['peak']) == 2.0


# ================================================================ follow-up: the writers of two inputs
def check_mode_writer():
    """0x022962..0x022972 (inside 0x022760, GBR 0xFFFF65AA): the only store to 0xFFFF65C5 that was found.

    It stores (ROM byte 0x0C303F == 0xAA) ? 0 : 1 -- a calibration option byte, not a live state.
    The bin holds 0x55 there, so the byte is 1 and 0x022CF4 returns 1. Checked on the real bin
    and on in-memory copies with that one byte changed (the file on disk is never written).
    """
    print()
    print('writer of the mode byte 0xFFFF65C5 (fragment 0x022962..0x022972):')
    print('  ROM[0x0C303F]  [0xFFFF65C5]  [0xFFFF65B1]  0x022CF4 returns')
    for patch, want in ((None, 1), (0xAA, 0), (0x00, 1), (0x5A, 1), (0xFF, 1)):
        rom = bytearray(ROM)
        if patch is not None:
            rom[0x0C303F] = patch
        e = E.Emu(bytes(rom))
        e.gbr = 0xFFFF65AA
        assert e.call(0x022962, stop_at={0x022974}) == 0x022974
        got = e.read_u8(IN_MODE)
        assert got == want and e.read_u8(0xFFFF65B1) == want, (patch, got)
        assert not e.uninit_reads, 'the fragment read RAM: it should depend on the ROM byte only'
        e.call(FN_FLAG)
        assert e.R[0] == want
        tag = '(this bin)' if patch is None else '(patched copy)'
        print(f'  0x{rom[0x0C303F]:02X} {tag:15} {got}             {e.read_u8(0xFFFF65B1)}             {e.R[0]}')
    assert ROM[0x0C303F] == 0x55


def check_b_writer():
    """0x01F5F2 (26 instructions): the only store to 0xFFFF62F4 that was found.

    X = lookup2D(desc 0x0AB058, y = [0xFFFF6624], x = [0xFFFF62DC]);  B = X[n] - X[n-2].
    """
    def x_of(a, b):
        e = E.Emu(ROM)
        e.call(0x0BE8E4, regs={4: 0x0AB058}, fregs={4: a, 5: b})
        return e.FR[0]
    # which argument is which axis: y axis 800..4000 takes fr4, x axis 0..25.3 takes fr5
    assert abs(b2f(x_of(2000.0, 9.3)) - 39.0472) < 1e-3
    assert abs(b2f(x_of(4000.0, 4.1)) - 8.3221) < 1e-3
    e = E.Emu(ROM)
    for a in (0xFFFF6344, 0xFFFF6348, 0xFFFF62FC, IN_B):
        e.ram_f32(a, 0.0)
    hist = [0, 0]                           # X[n-2], X[n-1] as bits
    print()
    print('writer of B = 0xFFFF62F4 (function 0x01F5F2), consecutive calls:')
    print('  [6624]  [62DC] | X=[62FC]   B=[62F4]   (B must equal X[n] - X[n-2])')
    for a, b in ((2000.0, 0.0), (2000.0, 9.3), (2000.0, 13.4), (2400.0, 13.4), (2400.0, 25.3),
                 (3200.0, 4.1), (3200.0, 4.1), (3200.0, 4.1), (800.0, 0.0)):
        e.ram_f32(IN_A, a)
        e.ram_f32(0xFFFF62DC, b)
        e.steps = 0
        e.writes.clear()
        assert e.call(0x01F5F2) == 'return'
        x = x_of(a, b)
        want_b = fsub_bits(x, hist[0])           # 01F61C fsub fr9,fr8: X[n] - X[n-2], rounded toward zero
        assert e.read_u32(0xFFFF62FC) == x
        assert e.read_u32(IN_B) == want_b, (a, b)
        assert e.read_u32(0xFFFF6348) == hist[0] and e.read_u32(0xFFFF6344) == hist[1]
        assert set(e.writes) == bytes4(0xFFFF62FC) | bytes4(IN_B) | bytes4(0xFFFF6344) | bytes4(0xFFFF6348)
        print(f'  {a:6.0f}  {b:5.1f}  | {b2f(x):9.4f}  {b2f(want_b):9.4f}')
        hist = [hist[1], x]
    assert not e.uninit_reads


def main():
    print(f'function 0x{ENTRY:06X}  bin {os.path.basename(BIN)}')
    check_callees()
    check_lookup_saturation()
    n = pass_a() + pass_b() + pass_c()
    nd = pass_d()
    show()
    check_mode_writer()
    check_b_writer()
    print()
    check_hysteresis_helper()
    check_enable_logic()
    check_flag_owners()
    nc = check_chain()
    print()
    nf = check_fmac_sensitivity()
    ns = check_sel_writers()
    nn = check_nan_edge()
    print()
    print(f'ALL OK: {n} emulated calls of 0x042506 matched the model on outputs, write-set, read-set and preserved '
          f'registers; {nd} unique-cell array-address cases, {nc} chain passes, {ns} selector-writer cases and '
          f'{nn} NaN / infinity edge cases matched as well; {nf} fmac-sensitivity lookups. Arithmetic models '
          f'round toward zero (FPSCR 0x00040001), as the chip does')
    if _emu.notes:
        print('emulator notes:', '; '.join(sorted(_emu.notes)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
