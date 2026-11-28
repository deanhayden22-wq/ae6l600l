#!/usr/bin/env python3
"""Emulation check for the overrun ladder: sequencer 0x03AE5A, counter writer 0x03B3DA (GBR 0xFFFF7C6C),
rung comparator 0x03AE6C (GBR 0xFFFF7C92), tail 0x03B62C, and the call chain that sets their rate.

    python3 scripts/trace/emu_overrun_ladder.py

Reference bin: rom/AE5L600L 20g rev 20.19c.bin  md5 92cae8275cd4f9b473a3a9e36efe6449
Second bin   : rom/ae5l600l.bin (stock)         md5 a8ea39d447f977e270e27ee670243c88

Every function runs in scripts/sh2e_emu.py with its callees executed from ROM (0x029AA0, 0x05EB3E,
0x0BE554, 0x0BE608, 0x022CF4, 0x0BE8AC, 0x02F8EA, 0x0BE830, 0x0BE970, and 0x03AF88 in the sequence
test). Only these are stubbed:
  * 0x00317C / 0x003190 (critical-section enter / leave: the emulator raises on ldc sr), when 0x03D2FC runs;
  * 0x03D2FC itself in the per-function tests of 0x03AE6C (so the write set is 0x03AE6C's own);
  * 0x00FDB4 / 0x002EDC / 0x0107B6 / 0x0107F4 in the rate test (recorded, not executed).
Python models written from the bytes (disassembly/analysis/overrun_ladder_trace.txt) are compared per case
on every output cell, the exact set of RAM bytes written, the exact set of RAM inputs read, and the
callee-saved registers. Some grids run on a modified in-memory ROM copy (cal bytes 0x0CBC0A / 0x0CBC96 /
0x0CBC92 changed) to reach branches the shipped calibration never takes; those cases are labelled.

Review round (2026-11-27, third decode): added the window precondition cases of 0x03B3DA (negative or NaN
[7C6C]), the lift table on BOTH [5DB8] sides and both bins, the adds-on lift in both bins, the arm timing of
0x041BE4 interleaved with 0x03AE5A (detected by stopping at the arm, 0x041C2E), and the two gate writers
0x023A94 / 0x0218F6 against byte models.

Names are neutral on purpose. Nothing here establishes what any input RAM cell physically is.
Deterministic (fixed RNG seed); exits 0 when every assertion holds.
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
import desc_types as DT       # noqa: E402

BIN = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
ROM = open(BIN, 'rb').read()
assert hashlib.md5(ROM).hexdigest() == '92cae8275cd4f9b473a3a9e36efe6449', 'wrong reference bin'
STOCK = open(os.path.join(REPO, 'rom', 'ae5l600l.bin'), 'rb').read()
assert hashlib.md5(STOCK).hexdigest() == 'a8ea39d447f977e270e27ee670243c88', 'wrong stock bin'

SEQ, CMPR, CNTW, TAIL, RUNGS, COMB = 0x03AE5A, 0x03AE6C, 0x03B3DA, 0x03B62C, 0x03AF88, 0x03D2FC

# ---- RAM cells named only by address (inputs of 0x03B3DA)
R6624 = 0xFFFF6624; R67EC = 0xFFFF67EC; R5E96 = 0xFFFF5E96; R85D7 = 0xFFFF85D7; R64F5 = 0xFFFF64F5
R5E98 = 0xFFFF5E98; R5FB6 = 0xFFFF5FB6; R5FB7 = 0xFFFF5FB7; R972E = 0xFFFF972E; R5D85 = 0xFFFF5D85
R8F24 = 0xFFFF8F24; R5D86 = 0xFFFF5D86; R5E68 = 0xFFFF5E68; R8F22 = 0xFFFF8F22
# ---- the ladder block
C7C6C = 0xFFFF7C6C; C7C78 = 0xFFFF7C78; C7C92 = 0xFFFF7C92; C7C94 = 0xFFFF7C94; C7C96 = 0xFFFF7C96
C7C98 = 0xFFFF7C98; C7C9A = 0xFFFF7C9A; C7C9B = 0xFFFF7C9B; C7C9D = 0xFFFF7C9D; C7C9E = 0xFFFF7C9E
C7C9F = 0xFFFF7C9F; C7CA0 = 0xFFFF7CA0; C7CA3 = 0xFFFF7CA3; C7CA4 = 0xFFFF7CA4; C7CA5 = 0xFFFF7CA5
C7CA6 = 0xFFFF7CA6; C7CA7 = 0xFFFF7CA7; C7CAA = 0xFFFF7CAA; C7CAC = 0xFFFF7CAC; C7CAE = 0xFFFF7CAE
C7CB2 = 0xFFFF7CB2; C7CB7 = 0xFFFF7CB7; C7D80 = 0xFFFF7D80
# ---- inputs of 0x03AE6C
R65C5 = 0xFFFF65C5; R65D0 = 0xFFFF65D0; R8E46 = 0xFFFF8E46
DESC = 0x0AD400

# 0x03D2FC flag bytes (launch_closure_trace.txt contract): six "all" bytes and four groups of six
D2FC_ALL = (0xFFFF7CB8, 0xFFFF7CBC, 0xFFFF7CD5, 0xFFFF7CE8, 0xFFFF7CF4, 0xFFFF7D48)
D2FC_GRP = ((0xFFFF7CA3, 0xFFFF7CE1, 0xFFFF7CFA, 0xFFFF7D14, 0xFFFF7D2F, 0xFFFF7D4D),
            (0xFFFF7CA4, 0xFFFF7CE2, 0xFFFF7CFB, 0xFFFF7D15, 0xFFFF7D30, 0xFFFF7D4E),
            (0xFFFF7CA5, 0xFFFF7CE3, 0xFFFF7CFC, 0xFFFF7D16, 0xFFFF7D31, 0xFFFF7D4F),
            (0xFFFF7CA6, 0xFFFF7CE4, 0xFFFF7CFD, 0xFFFF7D17, 0xFFFF7D32, 0xFFFF7D50))
D2FC_BITS = (0xFFFFA17E, 0xFFFFA17F, 0xFFFFA180, 0xFFFFA181)

f2b, b2f = E.f2b, E.b2f
_rng = random.Random(0x03AE6C)
NCASES = {}


def s8(v):
    v &= 0xFF
    return v - 0x100 if v & 0x80 else v


def s16(v):
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v


def calw(rom, a):
    return struct.unpack_from('>H', rom, a)[0]


def fgt(xb, yb):
    """fcmp/gt FRm,FRn with FRn = x, FRm = y: T = x > y, false if either is NaN"""
    return b2f(xb) > b2f(yb)


def rz_add(xb, yb):
    x, y = b2f(xb), b2f(yb)
    if not (math.isfinite(x) and math.isfinite(y)):
        return f2b(x + y)
    q = Fraction(x) + Fraction(y)
    if q == 0:
        return f2b(x + y)
    return E.rz_bits(q)


def poke(e, a, n, v):
    """write RAM WITHOUT marking it initialised: its first read lands in uninit_reads"""
    o = a - E.RAM_LO
    e.ram[o:o + n] = (v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big')


def peek(e, a, n):
    o = a - E.RAM_LO
    return int.from_bytes(e.ram[o:o + n], 'big')


def bset(a, n):
    return {a + i for i in range(n)}


SENT = {8: 0x88888888, 9: 0x99999999, 10: 0xAAAAAAAA, 11: 0xBBBBBBBB, 12: 0xCCCCCCCC, 13: 0xDDDDDDDD,
        14: 0xEEEEEEEE}
FSENT = {12: 0x3F8CCCCD, 13: 0x40133333, 14: 0x40566666, 15: 0x408CCCCD}
GBR_SENT = 0xFFFF1234


def fresh_call(e, entry, pokes, regs_extra=None):
    e.init = bytearray(len(e.init))
    e.uninit_reads.clear()
    e.writes.clear()
    e.stack_low = E.STACK_TOP
    e.steps = 0
    for a, n, v in pokes:
        poke(e, a, n, v)
    regs = {i: _rng.getrandbits(32) for i in range(8)}
    regs.update(SENT)
    if regs_extra:
        regs.update(regs_extra)
    for i in range(12):
        e.FR[i] = _rng.getrandbits(32)
    for i, v in FSENT.items():
        e.FR[i] = v
    e.gbr = GBR_SENT
    assert e.call(entry, regs=regs) == 'return'
    for i, v in SENT.items():
        assert e.R[i] == v, f'r{i} not preserved'
    assert e.R[15] == E.STACK_TOP, 'r15 not restored'
    assert e.gbr == GBR_SENT, 'GBR not restored'
    for i, v in FSENT.items():
        assert e.FR[i] == v, f'fr{i} not preserved'


def patched(rom, edits):
    b = bytearray(rom)
    for a, data in edits:
        b[a:a + len(data)] = data
    return bytes(b)


# ============================================================ 0x03B3DA model
B3DA_IN = ((R6624, 4), (R67EC, 2), (R5E96, 1), (R85D7, 1), (R64F5, 1), (R5E98, 1), (R5FB6, 1),
           (R5FB7, 1), (R972E, 1), (R5D85, 1), (R8F24, 1), (R5D86, 1), (R5E68, 4), (R8F22, 1),
           (C7C78, 4), (C7C6C, 4), (C7C9E, 1), (C7CAC, 2), (C7CAE, 2), (C7C98, 2), (C7CAA, 2), (C7CA0, 1))


def model_b3da(rom, c):
    """returns (outputs {addr: (size, value)}, write byte set, read address set, path name)"""
    cbc0a, cbc94, cbc96 = rom[0x0CBC0A], calw(rom, 0x0CBC94), calw(rom, 0x0CBC96)
    out, reads = {}, set()
    reads |= {R6624, R67EC, R5E96, R85D7, R64F5, R5E98, R5FB6, R5FB7, R972E, R5D85, R8F24, R5D86,
              R5E68, R8F22, C7C78, C7C6C}
    rpm = c[R6624]
    # [7CA7]  03B442..03B46A
    s = rz_add(c[C7C78], c[C7C6C])                 # fadd fr9,fr8 : fr8 = [7C78] + [7C6C]
    if not fgt(s, rpm):                            # fcmp/gt fr14,fr8 ; bf -> 1
        a7 = 1
    elif fgt(c[C7C78], rpm):                       # fcmp/gt fr14,fr8 (fr8 = [7C78]) ; bt -> 0
        a7 = 0
    else:
        reads.add(C7C9E)
        a7 = 1 if (c[C7C9E] & 0xFF) == 1 else 0
    out[C7CA7] = (1, a7)
    # [7CAC] / [7CAE]  03B46C..03B496
    b85, b64 = c[R85D7] & 0xFF, c[R64F5] & 0xFF
    if b85 == 1:
        reads.add(C7CAC)
        cac = min(c[C7CAC] + 1, 0xFFFF)
    else:
        cac = 0
    if b64 == 1:
        reads.add(C7CAE)
        cae = min(c[C7CAE] + 1, 0xFFFF)
    else:
        cae = 0
    out[C7CAC] = (2, cac)
    out[C7CAE] = (2, cae)
    # G (r14)  03B498..03B4D6
    if s8(cbc0a) == -128:
        g = 1 if (b64 == 1 and cae >= cbc96) else 0
    else:
        g = 1 if (b85 == 1 and cac >= cbc96) else 0
    # r2 = 0x0BE608([5E68], 0.0, 1.0)
    x = c[R5E68]
    r2 = 1 if (fgt(f2b(-1.0), x) or fgt(x, f2b(1.0))) else 0
    f029 = 2 if (c[R972E] & 0xFF) else 0           # 0x029AA0
    f05e = 1 if (c[R8F22] & 0x10) else 0           # 0x05EB3E
    b5e96 = c[R5E96] & 0xFF
    path = None
    if (c[R5FB6] & 0xFF) == 1:
        path = 'clear:5FB6'
    elif (c[R5FB7] & 0xFF) == 1:
        path = 'clear:5FB7'
    elif (c[R8F24] & 0xFF) == 1 and f05e == 1:
        path = 'clear:8F24'
    elif b5e96 == 2 and s8(c[R5D85]) == 1 and r2 != 0:
        path = 'clear:5E96=2'
    elif g == 1 and b5e96 == 1 and s8(c[R5D85]) == 1 and s8(c[R5D86]) == 0 and r2 == 0:
        path = 'immediate'
        reads.add(C7C98)
        out[C7C9E] = (1, 1)
        out[C7CAA] = (2, c[C7C98])
    elif (c[R67EC] >= cbc94) and a7 == 1 and g == 1 and (c[R5E98] & 0xFF) == 0 and f029 == 0:
        path = 'count'
        reads.add(C7CAA)
        out[C7C9E] = (1, 1)
        out[C7CAA] = (2, min(c[C7CAA] + 1, 0xFFFF))
        out[C7CA0] = (1, 0)
    elif g == 0:
        path = 'clear:G=0'
    else:
        path = 'drop'
        out[C7C9E] = (1, 0)
        out[C7CAA] = (2, 0)
        if a7 == 0:
            out[C7CA0] = (1, 1)
    if path.startswith('clear'):
        out[C7C9E] = (1, 0)
        out[C7CAA] = (2, 0)
    writes = set()
    for a, (n, _) in out.items():
        writes |= bset(a, n)
    return out, writes, reads, path


def run_b3da(e, rom, c):
    fresh_call(e, CNTW, [(a, n, c[a]) for a, n in B3DA_IN])
    out, writes, reads, path = model_b3da(rom, c)
    for a, (n, v) in out.items():
        got = peek(e, a, n)
        assert got == v, f'0x03B3DA {path}: [{a:08X}] = {got:#x}, model {v:#x}; case {c}'
    assert set(e.writes) == writes, f'0x03B3DA write set {sorted(map(hex, e.writes))} != {sorted(map(hex, writes))}'
    assert e.uninit_reads == reads, (f'0x03B3DA read set {sorted(map(hex, e.uninit_reads))} != '
                                     f'{sorted(map(hex, reads))} ({path})')
    NCASES['0x03B3DA'] = NCASES.get('0x03B3DA', 0) + 1
    return out, path


def base_b3da():
    """a counting-path state: every gate open"""
    return {R6624: f2b(2000.0), R67EC: 1000, R5E96: 0, R85D7: 0, R64F5: 1, R5E98: 0, R5FB6: 0,
            R5FB7: 0, R972E: 0, R5D85: 0, R8F24: 0, R5D86: 0, R5E68: f2b(0.0), R8F22: 0,
            C7C78: f2b(1000.0), C7C6C: f2b(200.0), C7C9E: 0, C7CAC: 0, C7CAE: 0, C7C98: 119,
            C7CAA: 10, C7CA0: 0x5A}


def test_b3da():
    print('==== 0x03B3DA counter writer ====')
    for tag, rom in (('20.19c', ROM), ('stock', STOCK)):
        e = E.Emu(rom)
        # (1) single-factor grid around the counting-path state, printed
        print(f'-- {tag}: one input changed from the counting-path state (cal 0x0CBC0A = {rom[0x0CBC0A]:#04x},'
              f' 0x0CBC94 = {calw(rom, 0x0CBC94)}, 0x0CBC96 = {calw(rom, 0x0CBC96)})')
        variants = [('base', {}),
                    ('[5FB6]=1', {R5FB6: 1}), ('[5FB7]=1', {R5FB7: 1}),
                    ('[8F24]=1,[8F22]=0x10', {R8F24: 1, R8F22: 0x10}), ('[8F24]=1,[8F22]=0', {R8F24: 1}),
                    ('[8F24]=0,[8F22]=0x10', {R8F22: 0x10}),
                    ('[5E96]=2,[5D85]=1,[5E68]=1.5', {R5E96: 2, R5D85: 1, R5E68: f2b(1.5)}),
                    ('[5E96]=2,[5D85]=1,[5E68]=0', {R5E96: 2, R5D85: 1}),
                    ('[5E96]=1,[5D85]=1', {R5E96: 1, R5D85: 1}),
                    ('[5E96]=1,[5D85]=1,[5D86]=1', {R5E96: 1, R5D85: 1, R5D86: 1}),
                    ('[5E96]=1,[5D85]=1,[5E68]=-1.0', {R5E96: 1, R5D85: 1, R5E68: f2b(-1.0)}),
                    ('[5E96]=1,[5D85]=1,[5E68]=-1.0000001', {R5E96: 1, R5D85: 1, R5E68: 0xBF800001}),
                    ('[5E96]=1,[5D85]=1,[5E68]=NaN', {R5E96: 1, R5D85: 1, R5E68: 0x7FC00000}),
                    ('[5E96]=1,[5D85]=1,[64F5]=0', {R5E96: 1, R5D85: 1, R64F5: 0}),
                    ('[67EC]=749', {R67EC: 749}), ('[67EC]=750', {R67EC: 750}), ('[67EC]=0x8000', {R67EC: 0x8000}),
                    ('[5E98]=1', {R5E98: 1}), ('[5E98]=0x80', {R5E98: 0x80}), ('[972E]=1', {R972E: 1}),
                    ('[64F5]=0', {R64F5: 0}), ('[64F5]=2', {R64F5: 2}), ('[85D7]=1', {R85D7: 1}),
                    ('rpm=1199.9999', {R6624: f2b(1199.9999)}), ('rpm=1200', {R6624: f2b(1200.0)}),
                    ('rpm=1100,[7C9E]=1', {R6624: f2b(1100.0), C7C9E: 1}),
                    ('rpm=1100,[7C9E]=0', {R6624: f2b(1100.0), C7C9E: 0}),
                    ('rpm=999,[7C9E]=1', {R6624: f2b(999.0), C7C9E: 1}),
                    ('rpm=1000,[7C9E]=1', {R6624: f2b(1000.0), C7C9E: 1}),
                    ('rpm=NaN', {R6624: 0x7FC00000}),
                    ('[7CAA]=0xFFFF', {C7CAA: 0xFFFF}), ('[7CAE]=0xFFFF', {C7CAE: 0xFFFF}),
                    ('[7CAC]=0xFFFE,[85D7]=1', {C7CAC: 0xFFFE, R85D7: 1})]
        for name, ch in variants:
            c = base_b3da()
            c.update(ch)
            out, path = run_b3da(e, rom, c)
            ca0 = out.get(C7CA0, (1, None))[1]
            print(f'   {name:38s} -> path {path:12s} [7CA7]={out[C7CA7][1]} [7C9E]={out[C7C9E][1]} '
                  f'[7CAA]={out[C7CAA][1]:5d} [7CAC]={out[C7CAC][1]:5d} [7CAE]={out[C7CAE][1]:5d} '
                  f'[7CA0]={"kept" if ca0 is None else ca0}')
        # contract spot checks (shipped cal: 0x0CBC0A = 0x80 selects the [64F5] / [7CAE] branch, 0x0CBC96 = 0)
        c = base_b3da(); out, path = run_b3da(e, rom, c)
        assert path == 'count' and out[C7CAA][1] == 11 and out[C7C9E][1] == 1 and out[C7CA0][1] == 0
        c = base_b3da(); c[R85D7] = 1; c[R64F5] = 0; out, path = run_b3da(e, rom, c)
        assert path == 'clear:G=0', 'shipped cal: [85D7] alone must not open the gate'
        c = base_b3da(); c.update({R5E96: 1, R5D85: 1}); out, path = run_b3da(e, rom, c)
        assert path == 'immediate' and out[C7CAA][1] == 119 and C7CA0 not in out
        c = base_b3da(); c.update({R6624: f2b(999.0), C7C9E: 1}); out, path = run_b3da(e, rom, c)
        assert path == 'drop' and out[C7CA7][1] == 0 and out[C7CA0][1] == 1 and out[C7CAA][1] == 0
        c = base_b3da(); c.update({R6624: f2b(1100.0), C7C9E: 0}); out, path = run_b3da(e, rom, c)
        assert path == 'drop' and out[C7CA7][1] == 0, 'entry needs rpm >= [7C78] + [7C6C]'
        c = base_b3da(); c.update({R6624: f2b(1100.0), C7C9E: 1}); out, path = run_b3da(e, rom, c)
        assert path == 'count' and out[C7CA7][1] == 1, 'hold needs only rpm >= [7C78]'
        c = base_b3da(); c[R67EC] = 749; out, path = run_b3da(e, rom, c)
        assert path == 'drop' and C7CA0 not in out, '[67EC] < 750 drops without touching [7CA0] when [7CA7] = 1'
        # window precondition (review C37): [7CA7] = 1 whenever !(sum > x), WITHOUT testing [7C78]
        print('   window precondition: [7CA7] when [7C78] > x')
        for name, ch, want in (('[7C78]=1500 [7C6C]=-600 x=1000 [7C9E]=0', {C7C78: f2b(1500.0), C7C6C: f2b(-600.0),
                                                                          R6624: f2b(1000.0)}, 1),
                               ('[7C78]=1500 [7C6C]=NaN  x=1000 [7C9E]=0', {C7C78: f2b(1500.0), C7C6C: 0x7FC00000,
                                                                          R6624: f2b(1000.0)}, 1),
                               ('[7C78]=NaN  [7C6C]=200  x=1000 [7C9E]=0', {C7C78: 0x7FC00000, C7C6C: f2b(200.0),
                                                                          R6624: f2b(1000.0)}, 1),
                               ('[7C78]=1000 [7C6C]=0    x=999  [7C9E]=1', {C7C78: f2b(1000.0), C7C6C: f2b(0.0),
                                                                          R6624: f2b(999.0), C7C9E: 1}, 0),
                               ('[7C78]=1000 [7C6C]=200  x=999  [7C9E]=1', {C7C78: f2b(1000.0), C7C6C: f2b(200.0),
                                                                          R6624: f2b(999.0), C7C9E: 1}, 0)):
            c = base_b3da(); c.update(ch)
            out, path = run_b3da(e, rom, c)
            assert out[C7CA7][1] == want, name
            print(f'     {name} -> [7CA7]={out[C7CA7][1]} path {path}')
        # (2) random states, every byte input drawn from a small set that hits each compare
        for _ in range(3000):
            c = {R6624: f2b(_rng.choice([500.0, 999.0, 1000.0, 1100.0, 1199.0, 1200.0, 3000.0])),
                 R67EC: _rng.choice([0, 749, 750, 751, 0x7FFF, 0x8000, 0xFFFF]),
                 R5E96: _rng.choice([0, 1, 2, 3, 0xFF]), R85D7: _rng.choice([0, 1, 2, 0x81]),
                 R64F5: _rng.choice([0, 1, 2, 0x81]), R5E98: _rng.choice([0, 0, 1, 0x80]),
                 R5FB6: _rng.choice([0, 0, 0, 1, 2]), R5FB7: _rng.choice([0, 0, 0, 1, 2]),
                 R972E: _rng.choice([0, 0, 1, 0xFF]), R5D85: _rng.choice([0, 1, 1, 2]),
                 R8F24: _rng.choice([0, 0, 1]), R5D86: _rng.choice([0, 0, 1, 0x80]),
                 R5E68: f2b(_rng.choice([0.0, 1.0, -1.0, 1.0000001, -1.5, 0.5])),
                 R8F22: _rng.choice([0, 0x10, 0xEF, 0xFF]),
                 C7C78: f2b(_rng.choice([1000.0, 1100.0])), C7C6C: f2b(_rng.choice([0.0, 200.0, 1000.0])),
                 C7C9E: _rng.choice([0, 1, 2]), C7CAC: _rng.choice([0, 1, 0xFFFE, 0xFFFF]),
                 C7CAE: _rng.choice([0, 1, 0xFFFE, 0xFFFF]), C7C98: _rng.choice([0, 119, 788, 0xFFFF]),
                 C7CAA: _rng.choice([0, 1, 118, 0xFFFE, 0xFFFF]), C7CA0: _rng.choice([0, 1, 0x5A])}
            run_b3da(e, rom, c)
    # (3) modified ROM: 0x0CBC0A != 0x80 selects the [85D7] / [7CAC] branch; 0x0CBC96 = 5 makes the hold count bite
    for edits, tag in (([(0x0CBC0A, b'\x00'), (0x0CBC96, b'\x00\x05')], 'MODIFIED ROM 0x0CBC0A=0x00 0x0CBC96=5'),
                       ([(0x0CBC96, b'\x00\x05')], 'MODIFIED ROM 0x0CBC96=5')):
        rom = patched(ROM, edits)
        e = E.Emu(rom)
        print(f'-- {tag}')
        for b85, b64, cac, cae in ((1, 0, 3, 0), (1, 0, 4, 0), (0, 1, 0, 3), (0, 1, 0, 4), (1, 1, 4, 4)):
            c = base_b3da()
            c.update({R85D7: b85, R64F5: b64, C7CAC: cac, C7CAE: cae})
            out, path = run_b3da(e, rom, c)
            print(f'   [85D7]={b85} [64F5]={b64} old [7CAC]={cac} old [7CAE]={cae} -> new [7CAC]={out[C7CAC][1]} '
                  f'[7CAE]={out[C7CAE][1]}  path {path}')
        for _ in range(1500):
            c = base_b3da()
            c.update({R85D7: _rng.choice([0, 1]), R64F5: _rng.choice([0, 1]), C7CAC: _rng.choice([0, 3, 4, 5, 0xFFFF]),
                      C7CAE: _rng.choice([0, 3, 4, 5, 0xFFFF]), R5E96: _rng.choice([0, 1, 2]),
                      R5D85: _rng.choice([0, 1]), C7C9E: _rng.choice([0, 1]),
                      R6624: f2b(_rng.choice([999.0, 1100.0, 1300.0]))})
            run_b3da(e, rom, c)


# ============================================================ 0x03AE6C model
AE6C_IN = ((R6624, 4), (R65C5, 1), (R65D0, 1), (R8E46, 1), (C7CB2, 2), (C7C9E, 1), (C7CAA, 2),
           (C7C92, 2), (C7C94, 2), (C7C96, 2), (C7C98, 2))
TIER_BYTES = {0: (0, 0, 0, 0, 0), 1: (1, 1, 0, 0, 0), 2: (2, 1, 1, 0, 0), 3: (3, 1, 1, 1, 0), 4: (4, 1, 1, 1, 1)}


def lut_value(e_lut, rpm_bits):
    """0x0BE8AC(r4 = 0x0AD400, fr4 = rpm) -> r0, executed from ROM"""
    e_lut.uninit_reads.clear()
    e_lut.R[4] = DESC
    e_lut.FR[4] = rpm_bits
    assert e_lut.call(0x0BE8AC, regs={4: DESC}, fregs=None) == 'return'
    return e_lut.R[0] & 0xFFFF


def model_ae6c(rom, c, lut):
    cbc90, cbc92 = calw(rom, 0x0CBC90), calw(rom, 0x0CBC92)
    reads = {R6624, R65C5, R65D0, R8E46, C7C9E}
    flag = 1 if (c[R65C5] & 0xFF) == 1 else 0
    r14 = c[R65D0] & 0xFF
    if r14 == 1:
        reads.add(C7CB2)
        cb2 = min(c[C7CB2] + 1, 0xFFFF)
    else:
        cb2 = 0
    route = None
    if (c[C7C9E] & 0xFF) == 0:
        tier, route = 0, '[7C9E]=0'
    else:
        cnt = c[C7CAA]
        reads |= {C7CAA, C7C98}
        if cnt >= c[C7C98]:
            tier, route = 4, 'cnt>=[7C98]'
        elif flag == 1 and cnt > cbc90 and r14 == 1 and cb2 >= lut and (s8(c[R8E46]) == 0 or s16(cbc92) == 0):
            tier, route = 4, 'second route'
        else:
            reads.add(C7C96)
            if cnt >= c[C7C96]:
                tier, route = 3, 'cnt>=[7C96]'
            else:
                reads.add(C7C94)
                if cnt >= c[C7C94]:
                    tier, route = 2, 'cnt>=[7C94]'
                else:
                    reads.add(C7C92)
                    tier, route = (1, 'cnt>=[7C92]') if cnt >= c[C7C92] else (0, 'cnt<[7C92]')
    t = TIER_BYTES[tier]
    out = {C7CB2: (2, cb2), C7C9A: (1, t[0]), C7CA3: (1, t[1]), C7CA4: (1, t[2]), C7CA5: (1, t[3]),
           C7CA6: (1, t[4]), C7C9D: (1, 1 if tier else 0), C7CB7: (1, 1 if tier >= 4 else 0)}
    writes = set()
    for a, (n, _) in out.items():
        writes |= bset(a, n)
    return out, writes, reads, route


def run_ae6c(e, e_lut, rom, c):
    reached = []
    e.stub(COMB, fn=lambda em: reached.append(True))
    fresh_call(e, CMPR, [(a, n, c[a]) for a, n in AE6C_IN])
    lut = lut_value(e_lut, c[R6624])
    out, writes, reads, route = model_ae6c(rom, c, lut)
    for a, (n, v) in out.items():
        got = peek(e, a, n)
        assert got == v, f'0x03AE6C {route}: [{a:08X}] = {got:#x}, model {v:#x}; case {c}'
    assert set(e.writes) == writes, f'0x03AE6C write set {sorted(map(hex, e.writes))}'
    assert e.uninit_reads == reads, f'0x03AE6C read set {sorted(map(hex, e.uninit_reads))} != {sorted(map(hex, reads))}'
    assert reached == [True], '0x03AE6C must end in exactly one jump to 0x03D2FC'
    NCASES['0x03AE6C'] = NCASES.get('0x03AE6C', 0) + 1
    return out, route, lut


def base_ae6c():
    return {R6624: f2b(2000.0), R65C5: 1, R65D0: 0, R8E46: 0, C7CB2: 0, C7C9E: 1, C7CAA: 0,
            C7C92: 44, C7C94: 75, C7C96: 100, C7C98: 119}


def test_ae6c():
    print('==== 0x03AE6C rung comparator ====')
    for tag, rom in (('20.19c', ROM), ('stock', STOCK)):
        e, e_lut = E.Emu(rom), E.Emu(rom)
        t = DT.read_table(rom, DESC)
        print(f'-- {tag}: record 0x0AD400 axis {t["axes"]["x"]} cells {t["values"]} (u16 via 0x0BE8AC);'
              f' 0x0CBC90 = {calw(rom, 0x0CBC90)}, 0x0CBC92 = {calw(rom, 0x0CBC92)}')
        # lookup: exact at axis points, clamped beyond both ends, monotone between 3000 and 4000
        for x, v in zip(t['axes']['x'], t['values']):
            assert lut_value(e_lut, f2b(x)) == v
        assert lut_value(e_lut, f2b(0.0)) == t['values'][0] and lut_value(e_lut, f2b(9000.0)) == t['values'][-1]
        mids = [lut_value(e_lut, f2b(3000.0 + 100.0 * k)) for k in range(11)]
        assert all(a >= b for a, b in zip(mids, mids[1:])) and mids[0] == 63 and mids[-1] == 38
        print(f'   lookup 3000..4000 step 100: {mids}')
        # ladder walk with distinct rungs 44 / 75 / 100 / 119 (tier 3 reachable only because [7C96] < [7C98] here)
        print('   [7CAA] walk, rungs 44/75/100/119, [7C9E]=1:')
        prev = None
        for cnt in list(range(0, 130)) + [0xFFFF]:
            c = base_ae6c(); c[C7CAA] = cnt
            out, route, _ = run_ae6c(e, e_lut, rom, c)
            tier = out[C7C9A][1]
            if tier != prev:
                print(f'     [7CAA]={cnt:5d} -> tier {tier} ({route}) [7CA3..A6]='
                      f'{[out[a][1] for a in (C7CA3, C7CA4, C7CA5, C7CA6)]} [7C9D]={out[C7C9D][1]} [7CB7]={out[C7CB7][1]}')
                prev = tier
        # [7C96] == [7C98] (what 0x03AF88 always produces): tier 3 never appears
        for cnt in range(0, 130):
            c = base_ae6c(); c[C7CAA] = cnt; c[C7C96] = 119
            out, _, _ = run_ae6c(e, e_lut, rom, c)
            assert out[C7C9A][1] != 3
        # [7C9E] = 0 zeroes everything whatever the count
        c = base_ae6c(); c.update({C7C9E: 0, C7CAA: 0xFFFF})
        out, route, _ = run_ae6c(e, e_lut, rom, c)
        assert out[C7C9A][1] == 0 and out[C7C9D][1] == 0
        # second tier-4 route: [7CAA] > 625 and [65D0] held for >= lookup(rpm) calls ([8E46] irrelevant while 0x0CBC92 = 0)
        print('   second route (rungs 669/744/788/788, as with the 625 adds):')
        for rpm, cnt, cb2_old, b65d0, b8e46 in ((2000.0, 625, 100, 1, 0), (2000.0, 626, 100, 1, 0), (2000.0, 626, 62, 1, 0),
                                                (2000.0, 626, 61, 1, 0), (5000.0, 626, 37, 1, 0), (5000.0, 626, 36, 1, 0),
                                                (2000.0, 626, 100, 0, 0), (2000.0, 626, 100, 1, 1)):
            c = {R6624: f2b(rpm), R65C5: 1, R65D0: b65d0, R8E46: b8e46, C7CB2: cb2_old, C7C9E: 1, C7CAA: cnt,
                 C7C92: 669, C7C94: 744, C7C96: 788, C7C98: 788}
            out, route, lut = run_ae6c(e, e_lut, rom, c)
            print(f'     rpm {rpm:6.0f} lut {lut:2d} [7CAA]={cnt} old [7CB2]={cb2_old:3d} [65D0]={b65d0} [8E46]={b8e46}'
                  f' -> new [7CB2]={out[C7CB2][1]:3d} tier {out[C7C9A][1]} ({route})')
        c = {R6624: f2b(2000.0), R65C5: 1, R65D0: 1, R8E46: 0, C7CB2: 62, C7C9E: 1, C7CAA: 626,
             C7C92: 669, C7C94: 744, C7C96: 788, C7C98: 788}
        assert run_ae6c(e, e_lut, rom, c)[0][C7C9A][1] == 4
        c[R65C5] = 0
        assert run_ae6c(e, e_lut, rom, c)[0][C7C9A][1] == 0, 'second route needs the 0x022CF4 flag'
        # random grid
        for _ in range(3000):
            c = {R6624: f2b(_rng.choice([0.0, 1000.0, 2500.0, 3000.0, 3500.0, 4000.0, 8000.0, 9000.0])),
                 R65C5: _rng.choice([0, 1, 2]), R65D0: _rng.choice([0, 1, 2, 0x81]), R8E46: _rng.choice([0, 1, 0x80]),
                 C7CB2: _rng.choice([0, 37, 38, 62, 63, 0xFFFE, 0xFFFF]), C7C9E: _rng.choice([0, 1, 2, 0x80]),
                 C7CAA: _rng.choice([0, 43, 44, 74, 75, 99, 100, 118, 119, 625, 626, 627, 0xFFFF]),
                 C7C92: _rng.choice([44, 669, 0xFFFF]), C7C94: _rng.choice([75, 744, 0xFFFF]),
                 C7C96: _rng.choice([100, 119, 788, 0xFFFF]), C7C98: _rng.choice([119, 788, 0xFFFF, 0])}
            run_ae6c(e, e_lut, rom, c)
    # modified ROM: 0x0CBC92 != 0 makes [8E46] matter on the second route
    rom = patched(ROM, [(0x0CBC92, b'\x00\x01')])
    e, e_lut = E.Emu(rom), E.Emu(rom)
    print('-- MODIFIED ROM 0x0CBC92 = 1 (second route now needs [8E46] = 0)')
    for b8e46 in (0, 1):
        c = {R6624: f2b(2000.0), R65C5: 1, R65D0: 1, R8E46: b8e46, C7CB2: 100, C7C9E: 1, C7CAA: 626,
             C7C92: 669, C7C94: 744, C7C96: 788, C7C98: 788}
        out, route, _ = run_ae6c(e, e_lut, rom, c)
        print(f'     [8E46]={b8e46} -> tier {out[C7C9A][1]} ({route})')
    for _ in range(800):
        c = base_ae6c()
        c.update({R65D0: 1, C7CB2: 100, C7CAA: _rng.choice([625, 626, 700]), R8E46: _rng.choice([0, 1, 0x80]),
                  C7C92: 669, C7C94: 744, C7C96: 788, C7C98: 788})
        run_ae6c(e, e_lut, rom, c)


# ============================================================ 0x03D2FC fed by the tier bytes
def crit_stubs(e):
    e.stub(0x00317C, r0=0)
    e.stub(0x003190, r0=None)


def clear_d2fc(e):
    for a in D2FC_ALL + sum(D2FC_GRP, ()) + D2FC_BITS:
        e.ram_u8(a, 0)


def test_tier_to_mask():
    print('==== 0x03AE6C -> 0x03D2FC: tier -> word [7D80] (critical-section calls stubbed) ====')
    for tag, rom in (('20.19c', ROM), ('stock', STOCK)):
        e = E.Emu(rom)
        crit_stubs(e)
        for cnt, want_tier in ((0, 0), (44, 1), (75, 2), (100, 3), (119, 4)):
            clear_d2fc(e)
            vals = base_ae6c(); vals[C7CAA] = cnt
            for a, n in AE6C_IN:
                {1: e.ram_u8, 2: e.ram_u16, 4: e.ram_u32}[n](a, vals[a])
            e.ram_u16(C7D80, 0x5A5A)
            assert e.call(CMPR, regs=dict(SENT)) == 'return'
            tier, mask = e.read_u8(C7C9A), e.read_u16(C7D80)
            assert tier == want_tier and mask == (0xF if tier == 4 else (1 << tier) - 1), (tier, hex(mask))
            print(f'   {tag}: [7CAA]={cnt:3d} -> tier {tier} -> [7D80] = {mask:#06x}')
            NCASES['tier->mask'] = NCASES.get('tier->mask', 0) + 1


# ============================================================ 0x03B62C
def test_b62c():
    print('==== 0x03B62C tail ====')
    e = E.Emu(ROM)
    vals = (0, 1, 2, 3, 4, 0x80, 0xFF)
    for b9b in vals:
        for b9e in vals:
            for b9a in vals:
                fresh_call(e, TAIL, [(C7C9B, 1, b9b), (C7C9E, 1, b9e), (C7C9A, 1, b9a)])
                want = 1 if (b9b == 1 and b9e == 1 and b9a != 4) else 0
                assert peek(e, C7C9F, 1) == want
                assert set(e.writes) == {C7C9F}
                reads = {C7C9B}
                if b9b == 1:
                    reads.add(C7C9E)
                    if b9e == 1:
                        reads.add(C7C9A)
                assert e.uninit_reads == reads
                NCASES['0x03B62C'] = NCASES.get('0x03B62C', 0) + 1
    print('   [7C9F] = ([7C9B] == 1 and [7C9E] == 1 and [7C9A] != 4): asserted for 343 byte triples')
    for b9a in (0, 1, 2, 3, 4):
        fresh_call(e, TAIL, [(C7C9B, 1, 1), (C7C9E, 1, 1), (C7C9A, 1, b9a)])
        print(f'     [7C9B]=1 [7C9E]=1 [7C9A]={b9a} -> [7C9F]={peek(e, C7C9F, 1)}')


# ============================================================ the whole sequencer over time
SEQ_INPUTS_U8 = {0xFFFF65C0: 0, 0xFFFF8E46: 0, 0xFFFF7EED: 0, 0xFFFF65C5: 1, 0xFFFF5DB8: 0, 0xFFFF6810: 1,
                 0xFFFF6155: 0, 0xFFFF615F: 0, R5E96: 0, R85D7: 0, R64F5: 0, R5E98: 0, R5FB6: 0, R5FB7: 0,
                 R972E: 0, R5D85: 0, R8F24: 0, R5D86: 0, R8F22: 0, R65D0: 0,
                 C7C9E: 0, 0xFFFF7C9B: 0, 0xFFFF7C9C: 0, C7CA0: 1,
                 # inputs of 0x041BE4 (arm-timing test only; 0x03AE5A never reads them)
                 0xFFFF5E94: 0, 0xFFFF6254: 0, 0xFFFF8032: 0, 0xFFFF8033: 0, 0xFFFF8034: 0, 0xFFFF8036: 0}
SEQ_INPUTS_U16 = {0xFFFF5E74: 0, R67EC: 1000, C7CAA: 0, C7CAC: 0xFFFF, C7CAE: 0xFFFF, C7CB2: 0,
                  C7C92: 0xFFFF, C7C94: 0xFFFF, C7C96: 0xFFFF, C7C98: 0xFFFF,
                  0xFFFF7C80: 0, 0xFFFF7C84: 0, 0xFFFF7C86: 0, 0xFFFF7C88: 0, 0xFFFF7C8A: 0,
                  0xFFFF7C8C: 0, 0xFFFF7C8E: 0, 0xFFFF7C90: 0}
SEQ_INPUTS_F32 = {R6624: 2000.0, 0xFFFF65FC: 50.0, 0xFFFF6350: 90.0, R5E68: 0.0, C7C78: 1000.0, C7C6C: 200.0,
                  0xFFFF6634: 0.0, 0xFFFF8020: 0.0, 0xFFFF8024: 0.0}


def seq_emu(rom, over_u8=None, over_f32=None):
    e = E.Emu(rom)
    crit_stubs(e)
    clear_d2fc(e)
    u8 = dict(SEQ_INPUTS_U8); u8.update(over_u8 or {})
    f32 = dict(SEQ_INPUTS_F32); f32.update(over_f32 or {})
    for a, v in u8.items():
        e.ram_u8(a, v)
    for a, v in SEQ_INPUTS_U16.items():
        e.ram_u16(a, v)
    for a, v in f32.items():
        e.ram_f32(a, v)
    return e


def seq_pass(e):
    assert e.call(SEQ, regs=dict(SENT)) == 'return'
    for i, v in SENT.items():
        assert e.R[i] == v
    return e.read_u8(C7C9A)


def run_lift(rom, rpm, gear, adds=False, b65d0=0, max_pass=900, side=0):
    """pass 0: gate closed ([64F5]=0) so 0x03AF88 builds the rungs; from pass 1 every counting-path condition
    holds. side = byte [5DB8] (0x03AF88's side select). Returns (rungs, {tier: first pass index at which it
    appears}, sequence of tiers, emulator)."""
    e = seq_emu(rom, {0xFFFF6810: gear, 0xFFFF6155: 1 if adds else 0, R65D0: b65d0, 0xFFFF5DB8: side}, {R6624: rpm})
    assert seq_pass(e) == 0
    rungs = tuple(e.read_u16(a) for a in (C7C92, C7C94, C7C96, C7C98))
    e.ram_u8(R64F5, 1)
    first, seen = {}, []
    for k in range(1, max_pass + 1):
        tier = seq_pass(e)
        assert e.read_u16(C7CAA) == min(k, 0xFFFF) and e.read_u8(C7C9E) == 1
        assert tuple(e.read_u16(a) for a in (C7C92, C7C94, C7C96, C7C98)) == rungs, 'rungs frozen while [7C9E] = 1'
        assert tier != 3
        mask = e.read_u16(C7D80)
        assert mask == (0xF if tier == 4 else (1 << tier) - 1)
        if tier not in first:
            first[tier] = k
        seen.append(tier)
        if tier == 4:
            break
    return rungs, first, seen, e


def test_sequence():
    print('==== 0x03AE5A sequence (0x03B3DA -> 0x03AF88 -> 0x03AE6C -> 0x03D2FC, then 0x03B62C) ====')
    # (a) counting path then resume, 20.19c, rpm 2000, selector [6810] = 1
    rungs, first, seen, e = run_lift(ROM, 2000.0, 1)
    print(f'   20.19c rpm 2000 [6810]=1: rungs {rungs}; first pass at tier 1/2/4 = '
          f'{first.get(1)}/{first.get(2)}/{first.get(4)}')
    assert rungs == (44, 119, 163, 163) and first == {0: 1, 1: 44, 2: 119, 4: 163}
    for k in range(5):
        assert seq_pass(e) == 4
    e.ram_f32(R6624, 1100.0)            # below [7C78] + [7C6C] = 1200 but not below [7C78] = 1000: held
    assert seq_pass(e) == 4 and e.read_u8(C7CA7) == 1
    e.ram_f32(R6624, 999.0)             # below [7C78]: dropped in the same pass
    assert seq_pass(e) == 0
    assert e.read_u8(C7C9E) == 0 and e.read_u16(C7CAA) == 0 and e.read_u8(C7CA0) == 1 and e.read_u16(C7D80) == 0
    print('   held at rpm 1100 (>= [7C78] = 1000, < 1200); rpm 999 -> tier 0 in the same pass, [7CA0] = 1, [7D80] = 0')
    # re-entry needs rpm >= [7C78] + [7C6C] again
    e.ram_f32(R6624, 1100.0)
    assert seq_pass(e) == 0 and e.read_u8(C7CA7) == 0
    e.ram_f32(R6624, 1200.0)
    assert seq_pass(e) == 0 and e.read_u16(C7CAA) == 1
    print('   re-entry: rpm 1100 does not restart the count; rpm 1200 does ([7CAA] = 1)')
    # pedal-gate break: one pass with [64F5] = 0 clears the count
    e.ram_u8(R64F5, 0)
    seq_pass(e)
    assert e.read_u16(C7CAA) == 0 and e.read_u8(C7C9E) == 0
    print('   one pass with [64F5] = 0 -> [7CAA] = 0, [7C9E] = 0')
    # (b) immediate path: tier 4 on the first pass
    e = seq_emu(ROM, {R5E96: 1, R5D85: 1})
    assert seq_pass(e) == 0
    e.ram_u8(R64F5, 1)
    assert seq_pass(e) == 4 and e.read_u16(C7CAA) == 163 and e.read_u16(C7D80) == 0xF
    e.ram_f32(R6624, 500.0)             # below [7C78]: the immediate path does not test [7CA7]
    assert seq_pass(e) == 4
    print('   immediate path ([5E96]=1 [5D85]=1 [5D86]=0 |[5E68]|<=1): tier 4 on pass 1, [7CAA] = [7C98] = 163,'
          ' still tier 4 at rpm 500')
    # (c) adds active ([6155]=1 [615F]=0): with and without the second route, BOTH bins (review C35)
    for tag, rom, want in (('20.19c', ROM, (669, 744, 788, 788)), ('stock', STOCK, (669, 713, 763, 763))):
        rungs, first, _, _ = run_lift(rom, 2000.0, 1, adds=True)
        print(f'   {tag} x 2000 sel 1, adds on, [65D0]=0: rungs {rungs}; first pass at tier 1/2/4 = '
              f'{first.get(1)}/{first.get(2)}/{first.get(4)}')
        assert rungs == want and first[1] == want[0] and first[2] == want[1] and first[4] == want[3]
        rungs, first, seen, _ = run_lift(rom, 2000.0, 1, adds=True, b65d0=1)
        print(f'   {tag} x 2000 sel 1, adds on, [65D0]=1 from pass 0: tier 4 first at pass {first.get(4)},'
              f' tiers seen {sorted(set(seen))}')
        assert first[4] == 626 and 1 not in first and 2 not in first and sorted(set(seen)) == [0, 4]
    # (d) [7C9F] from 0x03B62C during the add case: 1 while counting and tier != 4
    e = seq_emu(ROM, {0xFFFF6155: 1})
    seq_pass(e)
    e.ram_u8(R64F5, 1)
    seq_pass(e)
    assert e.read_u8(C7C9F) == 1 and e.read_u8(0xFFFF7C9B) == 1
    print('   [6155]=1: [7C9B] = 1 and [7C9F] = 1 while counting below tier 4')
    # (e) lift-to-cut table, both bins, BOTH sides of [5DB8] (review C33: side 1 was not covered)
    table = {}
    for side in (0, 1):
        print(f'   counts (= 0x03AE5A passes) from the first qualifying pass to tier 1 / 2 / 4, [5DB8]={side},'
              f' adds off:')
        print('     rpm    sel | 20.19c  t1  t2  t4 | stock   t1  t2  t4')
        for rpm in (1500.0, 2000.0, 2100.0, 2400.0, 2600.0, 2700.0, 2900.0, 3500.0, 5000.0):
            for gear in (1, 2, 3, 4, 5):
                row = []
                for rom in (ROM, STOCK):
                    rungs, first, _, _ = run_lift(rom, rpm, gear, side=side)
                    row.append((first.get(1), first.get(2), first.get(4)))
                    assert first.get(1) == rungs[0] and first.get(4) == rungs[3]
                    assert first.get(2) == (rungs[1] if rungs[1] < rungs[3] else None)
                    NCASES['sequence lifts'] = NCASES.get('sequence lifts', 0) + 1
                table[(side, rpm, gear)] = row
                fmt = lambda t: ' '.join(f'{x if x is not None else "-":>3}' for x in t)
                print(f'     {rpm:5.0f}  {gear}   |        {fmt(row[0])} |         {fmt(row[1])}')
    # selectors 4 and 5 share one table set
    for (side, rpm, gear), row in table.items():
        if gear == 5:
            assert row == table[(side, rpm, 4)]

    def shorter(side, rpm, gear):
        """indices k (t1, t2, t4) where 20.19c reaches the tier SOONER than stock"""
        a, b = table[(side, rpm, gear)]
        return [k for k in range(3) if a[k] is not None and b[k] is not None and a[k] < b[k]]
    # side 0: the 20.19c band-edge edit never shortens a rung (any x, any selector)
    assert all(not shorter(0, rpm, g) for (s, rpm, g) in table if s == 0)
    # side 1, x in [2500, 3000): rung 1 shorter for every selector, all three rungs for selectors 2 and 3
    for rpm in (2600.0, 2700.0, 2900.0):
        for g in (1, 2, 3, 4, 5):
            assert 0 in shorter(1, rpm, g), (rpm, g)
        assert shorter(1, rpm, 2) == [0, 1, 2] and shorter(1, rpm, 3) == [0, 1, 2]
        assert shorter(1, rpm, 1) == [0] and shorter(1, rpm, 4) == [0]
    # side 1 outside [2500, 3000): never shorter
    assert all(not shorter(1, rpm, g) for (s, rpm, g) in table if s == 1 and not 2500.0 <= rpm < 3000.0)
    # either side, x outside both moved ranges [1800, 2250) and [2500, 3000): identical counts in both bins
    for (s, rpm, g), row in table.items():
        if not (1800.0 <= rpm < 2250.0 or 2500.0 <= rpm < 3000.0):
            assert row[0] == row[1], (s, rpm, g, row)
    print('   side 0: 20.19c never reaches a tier sooner than stock;  side 1, x in 2500..3000: 20.19c reaches tier 1'
          ' sooner for every selector and all three tiers sooner for selectors 2 and 3')


# ============================================================ 0x041BE4 arm timing against the 0x03AE5A sequence
ARM_ENTRY, ARM_PC = 0x041BE4, 0x041C2E      # 041C2E is the first instruction of the arm (after 041C2C bf)
R8032, R8033, R8034 = 0xFFFF8032, 0xFFFF8033, 0xFFFF8034


def run_041be4(e):
    """run 0x041BE4 from ROM; True if it executed the arm (pc reached 0x041C2E)"""
    r = e.call(ARM_ENTRY, regs=dict(SENT), stop_at=(ARM_PC,))
    armed = (r == ARM_PC)
    if armed:
        while e.pc != E.RETURN_MAGIC:
            e.step()
    else:
        assert r == 'return'
    for i, v in SENT.items():
        assert e.R[i] == v
    NCASES['0x041BE4 runs'] = NCASES.get('0x041BE4 runs', 0) + 1
    return armed


def test_arm_timing():
    print('==== 0x041BE4 arm vs the 0x03AE5A sequence (20.19c, x 2000, sel 1, [5DB8]=0, [7C78]=1000) ====')
    # (a) order A = 0x03AE5A, B = 0x041BE4 in each step; count path
    e = seq_emu(ROM, {0xFFFF6810: 1})
    seq_pass(e); assert not run_041be4(e)
    e.ram_u8(R64F5, 1)
    while True:
        tier = seq_pass(e)
        assert not run_041be4(e), 'no arm while x >= [7C78]'
        if tier == 4:
            break
    for _ in range(3):
        assert seq_pass(e) == 4 and not run_041be4(e)
    assert e.read_u8(R8034) == 4
    e.ram_f32(R6624, 999.0)
    assert seq_pass(e) == 0
    assert e.read_u8(C7C9A) == 0 and e.read_u8(R8034) == 4
    assert run_041be4(e), 'first 0x041BE4 run after the drop pass arms ([8034] = 4 from its previous run)'
    assert e.read_u8(R8034) == 0
    assert seq_pass(e) == 0 and not run_041be4(e)
    print('   order 0x03AE5A then 0x041BE4: no arm while tier 4 is held at x >= [7C78]; x = 999 -> 0x03AE5A drops'
          ' to tier 0, THEN 0x041BE4 arms (it tests [8034] = 4 from its previous run, current [7C9A] = 0); next run'
          ' does not')
    # (b) order B then A at the drop: arms twice
    e = seq_emu(ROM, {0xFFFF6810: 1})
    seq_pass(e); run_041be4(e)
    e.ram_u8(R64F5, 1)
    while seq_pass(e) != 4:
        run_041be4(e)
    assert not run_041be4(e)
    e.ram_f32(R6624, 999.0)
    assert run_041be4(e) and e.read_u8(C7C9A) == 4          # tier still 4: [8034] = 4
    assert seq_pass(e) == 0
    assert run_041be4(e) and e.read_u8(C7C9A) == 0          # [8034] = 4 stored by the run before
    assert seq_pass(e) == 0 and not run_041be4(e)
    print('   x falls below [7C78] before the 0x03AE5A pass: 0x041BE4 arms with tier 4 still set AND again on the'
          ' run after the drop')
    # (c) synthetic negative band ([7C6C] = -600, never produced by 0x03AB94): count-path tier 4 held below [7C78]
    e = seq_emu(ROM, {0xFFFF6810: 1}, {C7C78: 1500.0, C7C6C: -600.0, R6624: 2000.0})
    seq_pass(e); run_041be4(e)
    e.ram_u8(R64F5, 1)
    while seq_pass(e) != 4:
        assert not run_041be4(e)
    run_041be4(e)
    e.ram_f32(R6624, 1000.0)                                 # below [7C78] = 1500, above sum = 900
    for _ in range(3):
        assert seq_pass(e) == 4 and e.read_u8(C7CA7) == 1
        assert run_041be4(e)
    print('   synthetic [7C78] = 1500, [7C6C] = -600, x = 1000: count-path tier 4 held ([7CA7] = 1) and the arm'
          ' fires on every run -- the exclusion needs [7C6C] >= 0')
    # (d) immediate path below [7C78]: arms on every run while held
    e = seq_emu(ROM, {R5E96: 1, R5D85: 1})
    seq_pass(e); run_041be4(e)
    e.ram_u8(R64F5, 1)
    assert seq_pass(e) == 4; run_041be4(e)
    e.ram_f32(R6624, 500.0)
    for _ in range(3):
        assert seq_pass(e) == 4 and run_041be4(e)
    print('   immediate path, x = 500: tier 4 held and the arm fires on every run')


# ============================================================ the two gate writers 0x023A94 / 0x0218F6
R726C, R67E8 = 0xFFFF726C, 0xFFFF67E8
R6155, R65CA, R64D8, R653B, R64F0, R64F6 = 0xFFFF6155, 0xFFFF65CA, 0xFFFF64D8, 0xFFFF653B, 0xFFFF64F0, 0xFFFF64F6


def check_out(e, tag, out, writes, reads):
    for a, (n, v) in out.items():
        got = peek(e, a, n)
        assert got == v, f'{tag}: [{a:08X}] = {got:#x}, model {v:#x}'
    assert set(e.writes) == writes, f'{tag}: write set {sorted(map(hex, e.writes))}'
    assert e.uninit_reads == reads, f'{tag}: read set {sorted(map(hex, e.uninit_reads))} != {sorted(map(hex, reads))}'


def model_18f6(rom, c):
    lo_a, hi_a = (0x0C3444, 0x0C344C) if (c[R65CA] & 0xFF) == 1 else (0x0C3448, 0x0C3450)
    lo, hi = struct.unpack_from('>I', rom, lo_a)[0], struct.unpack_from('>I', rom, hi_a)[0]
    reads = {R6155, R85D7, R65CA, R64D8}
    out = {}
    if fgt(lo, c[R64D8]):                       # 02192A fcmp/gt fr6,fr8: lo > [64D8]
        b = 1; out[R653B] = (1, 1)
    elif fgt(hi, c[R64D8]):                     # 021936 fcmp/gt fr8,fr9: hi > [64D8] -> kept
        reads.add(R653B); b = c[R653B] & 0xFF
    else:                                       # [64D8] >= hi, or NaN
        b = 0; out[R653B] = (1, 0)
    if b == 1:
        reads.add(R64F0); f0 = min(c[R64F0] + 1, 0xFFFF)
    else:
        f0 = 0
    out[R64F0] = (2, f0)
    if (c[R6155] & 0xFF) == 1:
        v5 = v6 = c[R85D7] & 0xFF
    elif b == 1:
        v5, v6 = (1 if f0 >= calw(rom, 0x0C30B0) else 0), 1
    else:
        v5 = v6 = 0
    out[R64F5] = (1, v5)
    out[R64F6] = (1, v6)
    writes = set()
    for a, (n, _) in out.items():
        writes |= bset(a, n)
    return out, writes, reads


def test_gate_writers():
    print('==== gate writers 0x023A94 ([67EC], [67E8]) and 0x0218F6 ([653B] [64F0] [64F5] [64F6]) ====')
    for tag, rom in (('20.19c', ROM), ('stock', STOCK)):
        e = E.Emu(rom)
        for b726c in (0, 1, 2, 0x81, 0xFF):
            for w67ec in (0, 1, 749, 0xFFFE, 0xFFFF):
                for w67e8 in (0, 5, 0xFFFF):
                    fresh_call(e, 0x023A94, [(R726C, 1, b726c), (R67EC, 2, w67ec), (R67E8, 2, w67e8)])
                    if b726c == 1:
                        out, reads = {R67EC: (2, 0)}, {R726C}
                    else:
                        out = {R67EC: (2, min(w67ec + 1, 0xFFFF)), R67E8: (2, min(w67e8 + 1, 0xFFFF))}
                        reads = {R726C, R67EC, R67E8}
                    writes = set()
                    for a, (n, _) in out.items():
                        writes |= bset(a, n)
                    check_out(e, '0x023A94', out, writes, reads)
                    NCASES['0x023A94'] = NCASES.get('0x023A94', 0) + 1
        fresh_call(e, 0x023A94, [(R726C, 1, 1), (R67EC, 2, 500), (R67E8, 2, 77)])
        assert peek(e, R67EC, 2) == 0 and peek(e, R67E8, 2) == 77 and set(e.writes) == bset(R67EC, 2)
        print(f'   {tag}: 0x023A94 [726C] == 1 -> [67EC] = 0 and [67E8] NOT written; else both sat16 + 1'
              f' (75 cases)')
        fvals = [0.0, 0.0005, 0.001, 0.1, 0.252, 0.2519999, 0.5, -1.0, float('nan')]
        for _ in range(1500):
            c = {R6155: _rng.choice([0, 1, 2, 0x81]), R85D7: _rng.choice([0, 1, 2, 0x81]),
                 R65CA: _rng.choice([0, 1, 2]), R64D8: f2b(_rng.choice(fvals)),
                 R653B: _rng.choice([0, 1, 2, 0x81]), R64F0: _rng.choice([0, 1, 2, 3, 0xFFFE, 0xFFFF])}
            fresh_call(e, 0x0218F6, [(R6155, 1, c[R6155]), (R85D7, 1, c[R85D7]), (R65CA, 1, c[R65CA]),
                                     (R64D8, 4, c[R64D8]), (R653B, 1, c[R653B]), (R64F0, 2, c[R64F0])])
            out, writes, reads = model_18f6(rom, c)
            check_out(e, '0x0218F6', out, writes, reads)
            NCASES['0x0218F6'] = NCASES.get('0x0218F6', 0) + 1
        # explicit: [64F6] on each path, NaN clears [653B]
        for name, c, want in (('[6155]=1 [85D7]=0x81', {R6155: 1, R85D7: 0x81, R65CA: 0, R64D8: f2b(0.0), R653B: 0,
                                                       R64F0: 0}, (1, 0x81, 0x81)),
                              ('[64D8]=0.0 [64F0]=2', {R6155: 0, R85D7: 0, R65CA: 0, R64D8: f2b(0.0), R653B: 0,
                                                      R64F0: 2}, (1, 1, 1)),
                              ('[64D8]=0.0 [64F0]=1', {R6155: 0, R85D7: 0, R65CA: 1, R64D8: f2b(0.0), R653B: 0,
                                                      R64F0: 1}, (1, 0, 1)),
                              ('[64D8]=NaN [653B]=1', {R6155: 0, R85D7: 0, R65CA: 0, R64D8: 0x7FC00000, R653B: 1,
                                                      R64F0: 9}, (0, 0, 0))):
            fresh_call(e, 0x0218F6, [(a, {R64D8: 4, R64F0: 2}.get(a, 1), v) for a, v in c.items()])
            got = (peek(e, R653B, 1), peek(e, R64F5, 1), peek(e, R64F6, 1))
            assert got == want, (name, got)
            print(f'   {tag}: 0x0218F6 {name:24s} -> [653B]={got[0]} [64F5]={got[1]:#x} [64F6]={got[2]:#x}')


# ============================================================ rate: 0x010D10 and the chain to 0x03AE5A
def test_rate():
    print('==== call rate: handler 0x00F518 -> 0x010D10 -> 0x00FDB4(3) -> 0x00FF1E -> task 9 -> 0x00E448 ====')
    rom = ROM
    # bytes of the chain
    assert calw(rom, 0x00F530) == 0xD34A and struct.unpack_from('>I', rom, 0x00F65C)[0] == 0x010D10
    assert struct.unpack_from('>I', rom, 0x011BD4 + 4 * 3)[0] == 0x00FF1E
    assert calw(rom, 0x00FF2E) == 0x430B and calw(rom, 0x00FF30) == 0xE409          # jsr @r3 ; mov #9,r4
    assert struct.unpack_from('>I', rom, 0x003F84 + 16 * 9 + 8)[0] == 0x00E448
    assert struct.unpack_from('>I', rom, 0x00E600)[0] == 0x04907C and calw(rom, 0x00E46A) == 0x420B
    assert struct.unpack_from('>I', rom, 0x0493D4)[0] == 0x03AB90 and calw(rom, 0x0491B6) == 0x420B
    assert calw(rom, 0x03AB90) == 0xA163 and 0x03AB90 + 4 + 2 * 0x163 == SEQ
    # no branch between 0x0490E8 and the jsr at 0x0491B6 (every word is mov.l @(d,pc),r2 / jsr @r2 / nop)
    for pc in range(0x0490E8, 0x0491B8, 2):
        w = calw(rom, pc)
        assert (w & 0xFF00) == 0xD200 or w in (0x420B, 0x0009), hex(pc)
    # CMT setup words: 0x00C0 -> [0xFFFFF718], 2499 -> [0xFFFFF71C], 0 -> [0xFFFFF71A], bit 1 of [0xFFFFF710]
    assert calw(rom, 0x010DC4) == 0x00C0 and calw(rom, 0x010DC6) == 0xF718
    assert calw(rom, 0x010DC8) == 0x09C3 and calw(rom, 0x010DCA) == 0xF71C and calw(rom, 0x010DCC) == 0xF71A
    # emulate 0x010D10: which activation indices it hands to 0x00FDB4, per call
    e = E.Emu(rom)
    rec = []
    e.stub(0x00FDB4, fn=lambda em: rec.append((em.R[4] & 0xFF, em.R[5])))
    e.ram_u8(0xFFFF5BBE, 0)
    per_call = []
    for k in range(64):
        rec.clear()
        assert e.call(0x010D10, regs=dict(SENT)) == 'return'
        per_call.append([r for r, _ in rec])
        assert all(r5 == 0 for _, r5 in rec)
    n3 = [k for k, idx in enumerate(per_call) if 3 in idx]
    n1 = [k for k, idx in enumerate(per_call) if 1 in idx]
    assert all(0 in idx for idx in per_call)
    assert n3 == list(range(4, 64, 8)) and n1 == list(range(2, 64, 4))
    print(f'   64 calls of 0x010D10: index 0 every call; index 1 at calls {n1[:4]}... (every 4th);'
          f' index 3 at calls {n3} (every 8th)')
    # 0x00FDB4(r4 = 3) reaches 0x00FF1E, which activates task id 9
    e = E.Emu(rom)
    crit_stubs(e)
    ids = []
    e.stub(0x002EDC, r0=0, fn=lambda em: ids.append(em.R[4]))
    e.stub(0x0107B6, r0=0)
    e.stub(0x0107F4, r0=0)
    assert e.call(0x00FDB4, regs={4: 3, 5: 0, 14: 0xEEEEEEEE}) == 'return'
    assert ids == [9], ids
    print('   0x00FDB4(r4 = 3) -> table 0x011BD4[3] = 0x00FF1E -> 0x002EDC(r4 = 9); task record 9 entry 0x00E448')
    NCASES['rate'] = 64 + 1


def main():
    test_b3da()
    test_ae6c()
    test_tier_to_mask()
    test_b62c()
    test_sequence()
    test_arm_timing()
    test_gate_writers()
    test_rate()
    print('==== summary ====')
    for k, v in NCASES.items():
        print(f'   {k}: {v} emulated cases')
    print('ALL ASSERTIONS HOLD')
    return 0


if __name__ == '__main__':
    sys.exit(main())
