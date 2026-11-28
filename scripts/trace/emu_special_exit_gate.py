#!/usr/bin/env python3
"""emu_special_exit_gate.py -- emulation evidence for disassembly/analysis/special_exit_gate_trace.txt

When does 0x033460 take its SPECIAL exit?  It needs byte [0xFFFF8E7E] == 1 and byte
[0xFFFF9720] == 0.  This script runs, in scripts/sh2e_emu.py, the ROM code that writes
those two bytes and the code that writes the inputs of the [8E7E] request term, and
compares every result with a MODEL written here from the byte reading in the analysis file.

    python3 scripts/trace/emu_special_exit_gate.py        # prints tables, asserts, exit 0

Reference image: rom/AE5L600L 20g rev 20.19c.bin (md5 92cae8275cd4f9b473a3a9e36efe6449).
Deterministic (fixed seed).  Stock image rom/ae5l600l.bin is read only for section Z.

  A  getters 0x0281DC, 0x0582AC, 0x05EAAE, 0x05EAD2, 0x058524 (exhaustive over their bytes)
  B  0x05A8B8 edge-event helper (grid)
  C  0x05A498: model vs ROM over 40,000 random states + edge grids (every written byte,
     the two port-bit calls, the two event calls)
  D  0x05A498 sequences: the request term r5 held 1 then dropped (set, minimum on time,
     clear); diagnostic blink (46-call half period); sticky [8E7E] when the latches are 0;
     D5 the CLEAR taken WITH r5 = 1 ([A733] = [A734] = 1, r14); D6 2,000 random normal-mode
     sequences: 0 -> 1 only on an r5 = 1 call, [8E7E] == ([8E7F]==1 || [8E80]==1) after every
     call, and [8E7E] = 0 from the 4th call after the last r5 = 1 call on
  E  0x028210: [9720] over [AD44] x each of the 17 status bits (whole function run)
  F  0x059FB4 ([8E64]), 0x059AE2 ([8E45], [8E50]; [7FBC] = NaN included), 0x0594F8 / 0x05979C /
     0x05951C ([8E38] snapshot), 0x059C3A ([8E46]), 0x05A3F6 ([8E6A]), 0x059862 ([8E44])
  G  0x05951C and 0x059F94 (the two dispatchers; callees stubbed): copies and call order
  R  0x028210 control flow: reaching definitions of r14 / r1 / r4 at the [9720] gate, predecessors of the two
     store arms, and every store into the frame slots @0 / @36..@52 (CFG over all reachable nodes);
     no store of 0x028210 or of its four callees has a base other than r15 / GBR; 5 of the 17 bits are
     read from frame slots at the gate, 12 from the array 0xFFFFAD52 directly
  S  0x047C40 control flow: its call to 0x0594F8 (0x048296) is reached only through the taken
     "bt 0x047D40" at 0x047C6E (byte [8EDC] == 0) and lies on every path from 0x047D40 to the return
  W  whole-image store scan (function_census.reg_states over all 5,146 census functions):
     every resolved store to bytes 0xFFFF8E7E / 0xFFFF9720 and the GBR-relative stores whose base
     comes from a caller or an enclosing function
  Z  stock vs 20.19c: every calibration byte read here; DTC-enable bytes 0x09A770 + k; the DTC record
     table 0x09A834..0x09B76F (records 0..194: the 20-byte layout holds through record 194 and breaks
     at 0x09B770); (AUDIT) the code bytes of every function in the file and the cal / descriptor bytes
     of 0x05A066 / 0x05A26E
  --- added by the AUDIT pass (see REVIEW HISTORY / AUDIT in the analysis file) ---
  V  task gates: 0x049CF0 (-> 0x05951C, 0x059F94), 0x04A03E (-> 0x028210) and 0x04A94C (-> 0x033304 ->
     0x033460) run their long call list only when byte [8EDC] == 0 (every callee stubbed and recorded,
     [8EDC] over 7 values), and each long arm is straight-line (CFG: no branch, one exit)
  H  0x05A218 ([8E66] / [8E67]), 0x05A066 ([8E65] and its hysteresis bytes) and 0x05A26E ([8E68] /
     [8E69] / [8E7C]): model vs ROM, write sets
  K  0x059F94 run whole from ROM: necessary conditions of an r5 = 1 call; [8E66] == 1 blocks BOTH, and with
     both output latches 0 no normal-mode call sets [8E7E]
  X  0x05A498 with every byte non-boolean (2, 0x7F, 0x80, 0x81, 0xFE, 0xFF) and counters at the sign
     boundary, against the section-C model

Stubs (a stub is an assumption, so each is stated):
  0x00317C / 0x003190, 0x0BE81C / 0x0BE82C   SR mask enter/leave (emulator raises on ldc sr); r0 = 0
  0x00E6E4   port-word set/clear (writes on-chip register 0xFFFFF754, unmapped here); calls recorded
  0x00DCE4   event dispatch (not decoded here); calls recorded with r4, r5
  (the byte predicates 0x022F92, 0x0297B0, 0x0297C0, 0x0297D0, 0x0298C8 run from ROM; their bytes are set)
  section G only: every bsr target of the two dispatchers (recorded, no effect)
  section V only: every census callee of the three task functions (recorded, r0 = 0)
Everything else (0x0BE53C, 0x0BE554, 0x0BE830, 0x0299F0, the getters) runs from ROM.
"""
import itertools
import math
import os
import random
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, os.path.join(REPO, 'scripts'))
import sh2e_emu as E          # noqa: E402

ROM_PATH = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
STOCK_PATH = os.path.join(REPO, 'rom', 'ae5l600l.bin')
ROM = open(ROM_PATH, 'rb').read()
RNG = random.Random(20261127)
NCHECK = 0


def check(cond, msg):
    global NCHECK
    NCHECK += 1
    if not cond:
        raise AssertionError(msg)


def f32(x):
    return E.b2f(E.f2b(x))


def calf(a, rom=ROM):
    return struct.unpack('>f', rom[a:a + 4])[0]


def calw(a, rom=ROM):
    return struct.unpack('>H', rom[a:a + 2])[0]


def say(*a):
    print(*a)


PORT = 0xFFFFF754


def ecall(e, entry, regs=None):
    e.steps = 0
    return e.call(entry, regs=regs)


def emu():
    e = E.Emu(ROM)
    e.port = []
    e.events = []
    for a in (0x00317C, 0x003190, 0x0BE81C, 0x0BE82C):
        e.stub(a, r0=0)
    e.stub(0x00E6E4, fn=lambda m: m.port.append((m.R[4], m.R[5] & 0xFFFF, 1 if (m.R[6] & 0xFFFF) else 0)))
    e.stub(0x00DCE4, fn=lambda m: m.events.append((m.R[4] & 0xFF, m.R[5] & 0xFFFF)), r0=0)
    return e


# ====================================================================== A  getters
def sec_A():
    say('\n==== A. getters ====')
    e = emu()
    # 0x0281DC: 1 if [96A8]==1, else 2 if [96A9]==1, else 0
    vals = (0, 1, 2, 0x81, 0xFF)
    for a, b in itertools.product(vals, vals):
        e.ram_u8(0xFFFF96A8, a); e.ram_u8(0xFFFF96A9, b)
        ecall(e, 0x0281DC)
        want = 1 if a == 1 else (2 if b == 1 else 0)
        check(e.R[0] == want, f'0281DC {a} {b}')
    say('  0x0281DC  [96A8],[96A9] in {0,1,2,0x81,0xFF}^2: r0 = 1 if [96A8]==1 else 2 if [96A9]==1 else 0   (25 cases)')
    # 0x0582AC: [36F4] -> 0:0, 0xFF:1, 0xA5:2, else 0
    for v in range(256):
        e.ram_u8(0xFFFF36F4, v)
        ecall(e, 0x0582AC)
        check(e.R[0] == {0xFF: 1, 0xA5: 2}.get(v, 0), f'0582AC {v}')
    say('  0x0582AC  [36F4] all 256: r0 = 1 for 0xFF, 2 for 0xA5, else 0')
    for v in range(256):
        e.ram_u8(0xFFFF8F1E, v); ecall(e, 0x05EAAE); check(e.R[0] == (v & 1), f'05EAAE {v}')
        e.ram_u8(0xFFFF8F21, v); ecall(e, 0x05EAD2); check(e.R[0] == (v >> 7), f'05EAD2 {v}')
        e.ram_u8(0xFFFFAD44, v); ecall(e, 0x058524); check(e.R[0] == (v - 256 if v & 0x80 else v) & 0xFFFFFFFF, f'058524 {v}')
    say('  0x05EAAE = bit0 of [8F1E]; 0x05EAD2 = bit7 of [8F21]; 0x058524 = sign-extended [AD44]   (256 each)')
    for ent, cell in ((0x0297B0, 0xFFFF9705), (0x0297C0, 0xFFFF9706), (0x0297D0, 0xFFFF9707), (0x0298C8, 0xFFFF9714),
                      (0x0299F0, 0xFFFF9720)):
        for v in range(256):
            e.ram_u8(cell, v); ecall(e, ent); check(e.R[0] == (2 if v else 0), f'{ent:x} {v}')
    for v in range(256):
        e.ram_u8(0xFFFF65F6, v); ecall(e, 0x022F92); check(e.R[0] == (1 if v == 1 else 0), f'022F92 {v}')
    say('  0x0297B0 / 0x0297C0 / 0x0297D0 / 0x0298C8 / 0x0299F0 = 2 if byte [9705] / [9706] / [9707] / [9714] / [9720] '
        '!= 0 else 0; 0x022F92 = ([65F6] == 1)   (256 each)')


# ====================================================================== B  0x05A8B8
def m_05A8B8(r4, r5, latch):
    """returns (new latch, event or None)"""
    if r4 & 0xFF:
        return 0, None
    r5 &= 0xFF
    if r5 == 1:
        if latch == 0:
            return 1, 5
        return latch, None
    if r5 == 0 and latch == 1:
        return 0, 6
    return latch, None


def sec_B():
    say('\n==== B. 0x05A8B8 ====')
    e = emu()
    rows = []
    for r4, r5, latch in itertools.product((0, 1, 2, 0x80), (0, 1, 2, 0xFF), (0, 1, 2, 0xFF)):
        e.events.clear()
        e.ram_u8(0xFFFF8E8B, latch)
        ecall(e, 0x05A8B8, regs={4: r4, 5: r5, 6: 0xFFFF8E8B})
        nl, ev = m_05A8B8(r4, r5, latch)
        got = e.read_u8(0xFFFF8E8B)
        check(got == nl, f'05A8B8 latch {r4} {r5} {latch}: {got} vs {nl}')
        check(e.events == ([] if ev is None else [(0, ev)]), f'05A8B8 event {r4} {r5} {latch}: {e.events}')
        if r4 in (0, 1) and r5 in (0, 1) and latch in (0, 1):
            rows.append(f'r4={r4} r5={r5} latch {latch}->{got} events {e.events}')
    for r in rows:
        say('  ' + r)
    say('  64 cases asserted')


# ====================================================================== C  0x05A498
G = 0xFFFF8E64
BYTES_IN = [0xFFFF65A9, 0xFFFF8E46, 0xFFFF8E45, 0xFFFF96A8, 0xFFFF96A9, 0xFFFF8F1E, 0xFFFF8F21,
            0xFFFFA733, 0xFFFFA734, 0xFFFF36F4, 0xFFFFA760, 0xFFFFA761, 0xFFFF8E47,
            0xFFFF8E64, 0xFFFF8E65, 0xFFFF8E68, 0xFFFF8E77, 0xFFFF8E7E, 0xFFFF8E7F, 0xFFFF8E80,
            0xFFFF8E88, 0xFFFF8E89, 0xFFFF8E8A, 0xFFFF8E8B, 0xFFFF8E8C, 0xFFFF8E8D, 0xFFFF8E8E,
            0xFFFF8E8F, 0xFFFF8E90, 0xFFFF8E91, 0xFFFF8E92, 0xFFFF8E93]
WORDS_IN = [0xFFFF8E82, 0xFFFF8E84, 0xFFFF8E86]
CAL_BE = calw(0x0D93BE)


def m_05A498(s, cal=CAL_BE):
    """s: dict addr -> value (bytes, and the three u16 counters).  Returns (out, port, events, path)."""
    o = dict(s)
    diag = 1 if s[0xFFFF96A8] == 1 else (2 if s[0xFFFF96A9] == 1 else 0)
    b0 = s[0xFFFF8F1E] & 1
    b7 = s[0xFFFF8F21] >> 7
    D = {0xFF: 1, 0xA5: 2}.get(s[0xFFFF36F4], 0)
    edge = False
    if s[0xFFFF8E90] == 0 and s[0xFFFF8E7F] == 1:
        edge = True; o[0xFFFF8E82] = 0
    else:
        o[0xFFFF8E82] = min(s[0xFFFF8E82] + 1, 0xFFFF)
    if s[0xFFFF8E91] == 0 and s[0xFFFF8E80] == 1:
        edge = True; o[0xFFFF8E84] = 0
    else:
        o[0xFFFF8E84] = min(s[0xFFFF8E84] + 1, 0xFFFF)
    o[0xFFFF8E86] = 0 if edge else min(s[0xFFFF8E86] + 1, 0xFFFF)
    r8 = s[0xFFFF8E92] == 1 and o[0xFFFF8E82] >= cal
    r12 = s[0xFFFF8E93] == 1 and o[0xFFFF8E84] >= cal
    r14 = (s[0xFFFF8E92] == 1 or s[0xFFFF8E93] == 1) and o[0xFFFF8E86] >= cal
    o[0xFFFF8E90] = s[0xFFFF8E7F]
    o[0xFFFF8E91] = s[0xFFFF8E80]
    o[0xFFFF8E77] = s[0xFFFF8E7E]
    r5 = (s[0xFFFF8E46] == 1 and s[0xFFFF8E64] == 1 and s[0xFFFF8E45] == 1
          and s[0xFFFF8E65] == 0 and s[0xFFFF8E68] == 0)
    o[0xFFFF8E89] = 0
    A733, A734, A760, A761 = s[0xFFFFA733], s[0xFFFFA734], s[0xFFFFA760], s[0xFFFFA761]
    if diag == 1 and (b0 or b7):
        path = 'P1'
        v = (1 if b0 else 0) | (2 if b7 else 0)
        o[0xFFFF8E89] = v
        if s[0xFFFF8E8D] == 0 or v != s[0xFFFF8E8A]:
            o[0xFFFF8E88] = 0; o[0xFFFF8E8E] = 0; o[0xFFFF8E8F] = 0
        else:
            c = min(s[0xFFFF8E88] + 1, 255)
            o[0xFFFF8E88] = c
            if c >= 46:
                o[0xFFFF8E88] = 0
                o[0xFFFF8E8E] = 1 if (v & 1 and s[0xFFFF8E8E] == 0) else 0
                o[0xFFFF8E8F] = 1 if (v & 2 and s[0xFFFF8E8F] == 0) else 0
        o[0xFFFF8E7F] = o[0xFFFF8E8E]
        o[0xFFFF8E80] = o[0xFFFF8E8F]
        o[0xFFFF8E7E] = 1 if (o[0xFFFF8E7F] == 1 or o[0xFFFF8E80] == 1) else 0
        o[0xFFFF8E8D] = 1
    else:
        act = None
        if D == 2:
            path = 'P2-test'
            if A760 == 1 and A761 == 1:
                act = 'both'
            elif A760 == 1 and r12:
                act = '7F'
            elif A761 == 1 and r8:
                act = '80'
            elif A760 != 0:
                act = None
            elif A761 == 0:
                act = 'clear' if r14 else None
        elif diag == 1:
            path = 'P2-diag'
            if s[0xFFFF8E47] == 1:
                act = 'both'
            elif r14:
                act = 'clear'
        else:
            path = 'P2-normal'
            if r14 and not r5:
                act = 'clear'
            elif not r5:
                act = None
            elif A733 == 0 and A734 == 0:
                act = 'both'
            elif r14 and A733 == 1 and A734 == 1:
                act = 'clear'
            elif r8 and A733 == 1:
                act = '80'
            elif r12 and A734 == 1:
                act = '7F'
        if act == 'both':
            o[0xFFFF8E7F] = 1; o[0xFFFF8E80] = 1; o[0xFFFF8E7E] = 1
        elif act == '7F':
            o[0xFFFF8E7F] = 1; o[0xFFFF8E80] = 0; o[0xFFFF8E7E] = 1
        elif act == '80':
            o[0xFFFF8E7F] = 0; o[0xFFFF8E80] = 1; o[0xFFFF8E7E] = 1
        elif act == 'clear':
            o[0xFFFF8E7F] = 0; o[0xFFFF8E80] = 0; o[0xFFFF8E7E] = 0
        path += ':' + str(act)
        o[0xFFFF8E8D] = 0
    if o[0xFFFF8E7F] == 1:
        o[0xFFFF8E92] = 1
    if o[0xFFFF8E80] == 1:
        o[0xFFFF8E93] = 1
    port = [(PORT, 0x20, 1 if o[0xFFFF8E7F] == 1 else 0), (PORT, 0x40, 1 if o[0xFFFF8E80] == 1 else 0)]
    o[0xFFFF8E8A] = o[0xFFFF8E89]
    events = []
    nl, ev = m_05A8B8(s[0xFFFF65A9], o[0xFFFF8E7F], s[0xFFFF8E8B])
    o[0xFFFF8E8B] = nl
    if ev:
        events.append((0, ev))
    nl, ev = m_05A8B8(s[0xFFFF65A9], o[0xFFFF8E80], s[0xFFFF8E8C])
    o[0xFFFF8E8C] = nl
    if ev:
        events.append((0, ev))
    return o, port, events, path


def load(e, s):
    for a in BYTES_IN:
        e.ram_u8(a, s[a])
    for a in WORDS_IN:
        e.ram_u16(a, s[a])


def readback(e, s):
    o = {}
    for a in BYTES_IN:
        o[a] = e.read_u8(a)
    for a in WORDS_IN:
        o[a] = e.read_u16(a)
    return o


def run_05A498(e, s):
    load(e, s)
    e.port.clear(); e.events.clear(); e.writes.clear()
    ecall(e, 0x05A498)
    return readback(e, s), list(e.port), list(e.events)


SMALL = (0, 1, 2, 0x80, 0xFF)


def rand_state():
    s = {}
    for a in BYTES_IN:
        s[a] = RNG.choice((0, 1, 1, 1, 0, 2, 0xFF, RNG.randrange(256)))
    s[0xFFFF36F4] = RNG.choice((0, 0, 0xFF, 0xA5, 0xA5, RNG.randrange(256)))
    s[0xFFFF8F1E] = RNG.randrange(256)
    s[0xFFFF8F21] = RNG.randrange(256)
    s[0xFFFF8E88] = RNG.choice((0, 44, 45, 46, 47, 254, 255, RNG.randrange(256)))
    for a in WORDS_IN:
        s[a] = RNG.choice((0, 1, 2, 3, 4, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF, RNG.randrange(65536)))
    return s


WRITTEN = {0xFFFF8E77, 0xFFFF8E7E, 0xFFFF8E7F, 0xFFFF8E80, 0xFFFF8E82, 0xFFFF8E84, 0xFFFF8E86,
           0xFFFF8E88, 0xFFFF8E89, 0xFFFF8E8A, 0xFFFF8E8B, 0xFFFF8E8C, 0xFFFF8E8D, 0xFFFF8E8E,
           0xFFFF8E8F, 0xFFFF8E90, 0xFFFF8E91, 0xFFFF8E92, 0xFFFF8E93}


def sec_C():
    say('\n==== C. 0x05A498 model vs ROM ====')
    e = emu()
    paths = {}
    for i in range(40000):
        s = rand_state()
        got, port, ev = run_05A498(e, s)
        want, wport, wev, path = m_05A498(s)
        paths[path] = paths.get(path, 0) + 1
        for a in got:
            check(got[a] == want[a], f'case {i} {path}: [{a:08X}] rom {got[a]} model {want[a]}  state {s}')
        check(port == wport, f'case {i} port {port} vs {wport}')
        check(ev == wev, f'case {i} events {ev} vs {wev}')
        # write set: only the cells in WRITTEN (plus stack) are written
        ws = {a & ~0 for a in e.writes}
        stray = {a for a in ws if not (a in WRITTEN or (a - 1) in WRITTEN)}
        check(not stray, f'case {i} stray writes {sorted(hex(a) for a in stray)}')
    for p in sorted(paths):
        say(f'  {p:22s} {paths[p]:6d}')
    say('  40,000 random states: every byte of the write set, both port calls and both event calls bit-exact')
    # counter edges against the u16 calibration (3): 2 / 3 / 0x7FFF / 0x8000 / 0xFFFF, sign extension
    base = {a: 0 for a in BYTES_IN}
    base.update({a: 0 for a in WORDS_IN})
    n = 0
    for c82, c86, l92 in itertools.product((1, 2, 3, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF), (1, 2, 3, 0x8000, 0xFFFF), (0, 1)):
        s = dict(base)
        s[0xFFFF8E82] = c82; s[0xFFFF8E86] = c86; s[0xFFFF8E92] = l92
        s[0xFFFF8E7F] = 1; s[0xFFFF8E90] = 1
        s[0xFFFFA733] = 1; s[0xFFFFA734] = 0
        for a in (0xFFFF8E46, 0xFFFF8E64, 0xFFFF8E45):
            s[a] = 1
        got, port, ev = run_05A498(e, s)
        want = m_05A498(s)[0]
        check(got == want, f'edge {c82} {c86} {l92}')
        n += 1
    say(f'  counter edges (u16 cal {CAL_BE}, values 1..0xFFFF incl. 0x8000 sign boundary): {n} cases')
    # exhaustive over the P2-normal decision inputs with counters fixed
    n = 0
    for r5bits in itertools.product((0, 1), repeat=5):
        for A733, A734, l92, l93, ok in itertools.product((0, 1, 2), (0, 1, 2), (0, 1), (0, 1), (0, 1)):
            s = dict(base)
            s[0xFFFF8E46], s[0xFFFF8E64], s[0xFFFF8E45] = r5bits[0], r5bits[1], r5bits[2]
            s[0xFFFF8E65], s[0xFFFF8E68] = r5bits[3], r5bits[4]
            s[0xFFFFA733], s[0xFFFFA734] = A733, A734
            s[0xFFFF8E92], s[0xFFFF8E93] = l92, l93
            cnt = 5 if ok else 1
            s[0xFFFF8E82] = s[0xFFFF8E84] = s[0xFFFF8E86] = cnt
            s[0xFFFF8E7E] = 1
            got = run_05A498(e, s)[0]
            want = m_05A498(s)[0]
            check(got == want, f'P2 grid {r5bits} {A733} {A734}')
            n += 1
    say(f'  P2-normal decision grid (5 request bits x A733 x A734 x latches x counters): {n} cases')


# ====================================================================== D  sequences
def fresh_state():
    s = {a: 0 for a in BYTES_IN}
    s.update({a: 0 for a in WORDS_IN})
    return s


def seq(e, s, n, mutate=None):
    hist = []
    for k in range(n):
        if mutate:
            mutate(k, s)
        got, port, ev = run_05A498(e, s)
        want = m_05A498(s)[0]
        check(got == want, f'seq step {k}')
        hist.append((got[0xFFFF8E7E], got[0xFFFF8E7F], got[0xFFFF8E80], got[0xFFFF8E86], port, ev))
        s.update(got)
    return hist


def sec_D():
    say('\n==== D. 0x05A498 sequences (state carried call to call) ====')
    e = emu()
    # D1 request term r5 = 1 for 2 calls, then 0
    s = fresh_state()

    def mut(k, st):
        on = 1 if k < 2 else 0
        st[0xFFFF8E46] = st[0xFFFF8E64] = st[0xFFFF8E45] = on
    h = seq(e, s, 9, mut)
    say('  D1 r5 = 1 for calls 0-1, then 0 ([A733] = [A734] = 0, normal mode):')
    for k, (b7e, b7f, b80, c86, port, ev) in enumerate(h):
        say(f'     call {k}: r5={1 if k < 2 else 0} -> [8E7E]={b7e} [8E7F]={b7f} [8E80]={b80} [8E86]={c86} port {[(hex(m), v) for _, m, v in port]} events {ev}')
    check([x[0] for x in h] == [1, 1, 1, 1, 0, 0, 0, 0, 0], 'D1 8E7E timeline')
    # D2 r5 = 1 for one call, latches clear: [8E7E] held 1 until 8E86 >= 3 (min on time = cal 3 calls after the edge)
    s = fresh_state()

    def mut2(k, st):
        on = 1 if k == 0 else 0
        st[0xFFFF8E46] = st[0xFFFF8E64] = st[0xFFFF8E45] = on
    h = seq(e, s, 6, mut2)
    say('  D2 r5 = 1 for call 0 only: [8E7E] = ' + ' '.join(str(x[0]) for x in h))
    check([x[0] for x in h] == [1, 1, 1, 1, 0, 0], 'D2 timeline')
    # D3 sticky: [8E7E] = 1 with latches 0 and r5 = 0: never cleared (no write)
    s = fresh_state()
    s[0xFFFF8E7E] = 1
    h = seq(e, s, 50)
    check(all(x[0] == 1 for x in h), 'D3 sticky')
    say('  D3 [8E7E] = 1, [8E7F] = [8E80] = [8E92] = [8E93] = 0, r5 = 0, normal mode: stays 1 for 50 calls (never written)')
    # D4 diagnostic blink: [96A8] = 1, [8F1E] bit0 = 1
    s = fresh_state()
    s[0xFFFF96A8] = 1
    s[0xFFFF8F1E] = 1
    h = seq(e, s, 200)
    runs = []
    cur, ln = h[0][0], 0
    for x in h:
        if x[0] == cur:
            ln += 1
        else:
            runs.append((cur, ln)); cur, ln = x[0], 1
    runs.append((cur, ln))
    say(f'  D4 diag [96A8] = 1 and [8F1E] bit0 = 1, 200 calls: [8E7E] runs (value, length) = {runs}')
    check(runs[:4] == [(0, 46), (1, 46), (0, 46), (1, 46)], 'D4 blink')
    # D5 the CLEAR taken while r5 = 1: [A733] = [A734] = 0 at call 0 (BOTH), then [A733] = [A734] = 1 with r5 = 1
    # throughout.  The clear fires once r14 = 1 ([8E86] >= 3 after the rising edge seen at call 1), through
    # 0x05A7B8..0x05A7CA (r14 == 1, [A733] == 1, [A734] == 1) -> 0x05A7CC, not through the r5 == 0 test 0x05A796.
    s = fresh_state()
    sites = []

    def mut5(k, st):
        st[0xFFFF8E46] = st[0xFFFF8E64] = st[0xFFFF8E45] = 1
        st[0xFFFFA733] = st[0xFFFFA734] = 0 if k == 0 else 1
    h = []
    for k in range(7):
        mut5(k, s)
        e.executed.clear()
        got, port, ev = run_05A498(e, s)
        want = m_05A498(s)[0]
        check(got == want, f'D5 step {k}')
        sites.append(tuple(pc for pc in (0x05A798, 0x05A7B4, 0x05A7B8, 0x05A7C4, 0x05A7CC, 0x05A7D4, 0x05A802)
                           if pc in e.executed))
        h.append((got[0xFFFF8E7E], got[0xFFFF8E7F], got[0xFFFF8E80], got[0xFFFF8E86]))
        s.update(got)
    say('  D5 r5 = 1 on every call; [A733] = [A734] = 0 at call 0, then 1 (normal mode):')
    for k, ((b7e, b7f, b80, c86), st_) in enumerate(zip(h, sites)):
        say(f'     call {k}: [8E7E]={b7e} [8E7F]={b7f} [8E80]={b80} [8E86]={c86}  store/branch sites executed '
            f'{" ".join("%06X" % p for p in st_)}')
    check([x[0] for x in h] == [1, 1, 1, 1, 0, 0, 0], 'D5 timeline')
    # 0x05A798 executed = the r5 == 0 clear test (bt 0x05A7CC at 0x05A796) fell through; 0x05A7C4 executed = r14 == 1
    # and [A733] == 1 passed (0x05A7BC / 0x05A7C2 fell through), so 0x05A7CC was reached from 0x05A7CA
    check(all(p in sites[4] for p in (0x05A798, 0x05A7B8, 0x05A7C4, 0x05A7CC, 0x05A7D4)), 'D5 clear path')
    check(all(0x05A798 in x for x in sites), 'D5 r5==0 clear never taken')
    # D6 random normal-mode sequences (diag != 1, D != 2), state carried, start from all-zero RAM
    nseq, ncalls = 0, 0
    for _ in range(2000):
        s = fresh_state()
        s[0xFFFF36F4] = RNG.choice((0, 0xFF, 0x11))
        s[0xFFFF96A9] = RNG.choice((0, 1))
        L = RNG.randrange(0, 16)                     # last call with r5 = 1 (or none if r5 never 1)
        ever = False
        last = None
        for k in range(24):
            r5 = (RNG.random() < 0.6) if k <= L else False
            for a in (0xFFFF8E46, 0xFFFF8E64, 0xFFFF8E45):
                s[a] = 1 if r5 else RNG.choice((0, 1, 2))
            if not r5:
                s[0xFFFF8E46] = 0
            s[0xFFFF8E65] = 0 if r5 else RNG.choice((0, 1))
            s[0xFFFF8E68] = 0 if r5 else RNG.choice((0, 1))
            s[0xFFFFA733] = RNG.choice((0, 1, 2))
            s[0xFFFFA734] = RNG.choice((0, 1, 2))
            s[0xFFFF8F1E] = RNG.randrange(256)
            s[0xFFFF8F21] = RNG.randrange(256)
            prev = s[0xFFFF8E7E]
            got, port, ev = run_05A498(e, s)
            want, _, _, path = m_05A498(s)
            check(got == want, 'D6 model')
            check(path.startswith('P2-normal'), f'D6 mode {path}')
            check(got[0xFFFF8E7E] == (1 if (got[0xFFFF8E7F] == 1 or got[0xFFFF8E80] == 1) else 0), 'D6 invariant')
            if prev == 0 and got[0xFFFF8E7E] == 1:
                check(r5, 'D6 set without r5')
            if r5:
                ever = True
                last = k
            if last is not None and k >= last + 4:
                check(got[0xFFFF8E7E] == 0, f'D6 still 1 at call {k}, last r5 call {last}')
            if not ever:
                check(got[0xFFFF8E7E] == 0, 'D6 set before any r5')
            s.update(got)
            ncalls += 1
        nseq += 1
    say(f'  D6 {nseq} random normal-mode sequences ({ncalls} calls, [A733] [A734] in 0..2, r5 random up to a last call): '
        f'[8E7E] 0 -> 1 only on r5 = 1 calls; [8E7E] == ([8E7F]==1 || [8E80]==1) after every call; [8E7E] = 0 from the '
        f'4th call after the last r5 = 1 call on')
    say('  store sites of [8E7E] executed in sections C/D: 0x05A6F0 (P1), 0x05A7D4 (clear), 0x05A802 (set)')


# ====================================================================== E  0x028210 -> [9720]
REC = 0x09A834
GATE_AD52 = [0x0886, 0x0872, 0x08D6, 0x08FE, 0x09B2, 0x099E, 0x0F02, 0x08C2, 0x08AE, 0x089A,
             0x098A, 0x0976, 0x0962, 0x094E, 0x093A]
GATE_3836 = [0x085E, 0x0EEE]


def rec_fields(off):
    k = (off - 2) // 20
    a = REC + 20 * k
    return k, ROM[a + 2], ROM[a + 3], (ROM[a + 4] << 8) | ROM[a + 5]


def run_028210(e, ad44, setcell=None):
    e.ram_u8(0xFFFFAD44, ad44)
    # zero both status arrays over the index range used
    for i in range(0x100):
        e.ram_u8(0xFFFFAD52 + i, 0)
    for i in range(0x200):
        e.ram_u8(0xFFFF3836 + i, 0)
    if setcell:
        a, m = setcell
        e.ram_u8(a, m)
    e.ram_u8(0xFFFF9720, 0x5A)
    ecall(e, 0x028210)
    return e.read_u8(0xFFFF9720)


def sec_E():
    say('\n==== E. 0x028210: byte [9720] ====')
    e = emu()
    rows = []
    for off in GATE_AD52 + GATE_3836:
        k, idx, mask, code = rec_fields(off)
        cell = (0xFFFFAD52 + idx) if off in GATE_AD52 else (0xFFFF3836 + 2 * idx)
        res = []
        for ad44 in (0, 1, 2, 0xFF):
            res.append(run_028210(e, ad44, (cell, mask)))
        # the same cell with every OTHER bit set does not count
        other = run_028210(e, 1, (cell, 0xFF ^ mask))
        rows.append(f'  record {k:3d} (+2 idx 0x{idx:02X} +3 mask 0x{mask:02X} +4 code {code:04X}) cell 0x{cell:08X}: '
                    f'[9720] for [AD44]=0/1/2/FF -> {res}; other bits only -> {other}')
        check(res == [0, 1, 0, 0], f'9720 rec {k}: {res}')
        # other bits of the same byte can belong to other gate records: only assert when none of them is listed
        others_listed = [o for o in GATE_AD52 + GATE_3836 if o != off and rec_fields(o)[1] == idx
                         and ((o in GATE_AD52) == (off in GATE_AD52))]
        if not others_listed:
            check(other == 0, f'9720 rec {k} other bits {other}')
    for r in rows:
        say(r)
    for ad44 in (0, 1, 2, 0xFF):
        check(run_028210(e, ad44) == 0, 'no bits')
    say('  no status bit set: [9720] = 0 for [AD44] = 0, 1, 2, 0xFF')
    # every byte of AD52 0x30..0x5F fully set except the listed bits: still 0
    e.ram_u8(0xFFFFAD44, 1)
    listed = {}
    for off in GATE_AD52:
        _, idx, mask, _ = rec_fields(off)
        listed[idx] = listed.get(idx, 0) | mask
    for i in range(0x100):
        e.ram_u8(0xFFFFAD52 + i, 0xFF ^ listed.get(i, 0))
    listed3 = {}
    for off in GATE_3836:
        _, idx, mask, _ = rec_fields(off)
        listed3[idx] = listed3.get(idx, 0) | mask
    for i in range(0x100):
        e.ram_u8(0xFFFF3836 + 2 * i, 0xFF ^ listed3.get(i, 0))
        e.ram_u8(0xFFFF3836 + 2 * i + 1, 0xFF)
    e.ram_u8(0xFFFF9720, 0x5A)
    ecall(e, 0x028210)
    check(e.read_u8(0xFFFF9720) == 0, 'complement')
    say('  [AD44] = 1, every OTHER bit of both arrays set (indices 0..0xFF): [9720] = 0')


# ====================================================================== F  upstream writers
def sec_F():
    say('\n==== F. writers of the request-term inputs ====')
    e = emu()
    V_ON, V_DN, T7D = calf(0x0D93EC), calf(0x0D93F0), calf(0x0D93F4)
    B0 = ROM[0x0D93B0]
    # ---- 0x059FB4
    n = 0
    for v, old78, e46, t68, old7d, c76, r9720 in itertools.product(
            (8.8, f32(8.9), 8.95, 10.8, f32(10.9), 11.0, float('nan')), (0, 1), (0, 1, 2), (59.0, 60.0, 61.0),
            (0, 1), (0, 9, 10, 255), (0, 1)):
        e.ram_f32(0xFFFF4130, v); e.ram_f32(0xFFFF68E4, t68)
        e.ram_u8(0xFFFF8E78, old78); e.ram_u8(0xFFFF8E46, e46); e.ram_u8(0xFFFF8E7D, old7d)
        e.ram_u8(0xFFFF8E76, c76); e.ram_u8(0xFFFF9720, r9720); e.ram_u8(0xFFFF8E64, 0x5A)
        ecall(e, 0x059FB4)
        if not (V_ON > v):
            w78 = 1
        elif f32(V_ON - V_DN) > v:
            w78 = 0
        else:
            w78 = old78
        if e46 == 1:
            w7d = 1 if not (t68 > T7D) else old7d
            w76 = min(c76 + 1, 255)
        else:
            w7d, w76 = 0, 0
        w64 = 1 if (w78 == 1 and r9720 == 0 and (w7d == 1 or (e46 == 1 and w76 >= B0))) else 0
        check((e.read_u8(0xFFFF8E78), e.read_u8(0xFFFF8E7D), e.read_u8(0xFFFF8E76), e.read_u8(0xFFFF8E64))
              == (w78, w7d, w76, w64), f'059FB4 {v} {old78} {e46} {t68} {old7d} {c76} {r9720}')
        n += 1
    say(f'  0x059FB4 [8E64] = [8E78]&&[9720]==0&&([8E7D]||([8E46]==1&&[8E76]>={B0})); [8E78] hysteresis on [4130] '
        f'(on >= {V_ON:.4g}, off < {f32(V_ON - V_DN):.4g}; NaN -> 1): {n} cases')
    # ---- 0x059AE2
    lo, hi = calf(0x0D93E0), calf(0x0D93E4)
    n = 0
    nan_pass = []
    for x, d7, fbc, a366, ect in itertools.product((-0.5, -0.0, 0.0, 30.0, 59.99, 60.0, 70.0, float('nan')),
                                                  (0, 1, 0x80), (-1.0, 0.0, 1.0, float('nan')), (0, 1, 2),
                                                  (-40.0, 20.0, 110.0)):
        e.ram_f32(0xFFFF8E38, x); e.ram_u8(0xFFFF85D7, d7); e.ram_f32(0xFFFF7FBC, fbc)
        e.ram_u8(0xFFFF366A, a366); e.ram_f32(0xFFFF6350, ect); e.ram_u8(0xFFFF8E45, 0x5A)
        ecall(e, 0x059AE2)
        t50 = e.read_f32(0xFFFF8E50)
        check(t50 == 0.0, f'059AE2 table {ect} {t50}')
        want = 1 if ((not (lo > x)) and (hi > x) and (d7 == 0 or not (t50 > fbc)) and a366 == 1) else 0
        check(e.read_u8(0xFFFF8E45) == want, f'059AE2 {x} {d7} {fbc} {a366}')
        if math.isnan(fbc) and d7 != 0 and x == 30.0 and a366 == 1:
            nan_pass.append(e.read_u8(0xFFFF8E45))
        n += 1
    check(nan_pass and all(v == 1 for v in nan_pass), f'059AE2 NaN [7FBC] {nan_pass}')
    say(f'  0x059AE2 [8E45] = !({lo} > [8E38]) && ({hi} > [8E38]) && ([85D7]==0 || !([8E50] > [7FBC])) && [366A]==1; '
        f'[8E50] = table 0x0AF4F0([6350]) = 0.0: {n} cases')
    say(f'           [7FBC] = NaN with [85D7] != 0, [8E38] = 30.0, [366A] = 1 -> [8E45] = {sorted(set(nan_pass))} '
        f'({len(nan_pass)} cases): NaN passes the [7FBC] term (fcmp/gt false)')
    # ---- 0x0594F8 / 0x05979C / 0x05951C: [8E38] snapshot
    for v, b65f6 in itertools.product((-10.0, 25.0, 95.0), (0, 1, 2)):
        e.ram_u8(0xFFFF65F6, b65f6)
        e.ram_f32(0xFFFF4144, v); ecall(e, 0x0594F8)
        check(e.read_f32(0xFFFF8E38) == f32(v) and e.read_u16(0xFFFF8E3C) == 0xFFFF
              and e.read_u8(0xFFFF8E61) == (1 if b65f6 == 1 else 0), '0594F8')
    say('  0x0594F8 [8E38] = [4144], [8E3C] = 0xFFFF, [8E61] = 0x022F92() = ([65F6] == 1)   (9 cases)')
    for s5b, s5c, flag in itertools.product((0, 1, 2), (0, 1), (0, 1, 0x80)):
        e.ram_u8(0xFFFF9705, flag)
        e.ram_f32(0xFFFF4144, 33.0); e.ram_f32(0xFFFF8E38, -1.0)
        e.ram_u8(0xFFFF8E5B, s5b); e.ram_u8(0xFFFF8E5C, s5c)
        ecall(e, 0x05979C)
        if s5b == 1 and s5c == 0:
            want = 33.0 if flag == 0 else 70.0
        else:
            want = -1.0
        check(e.read_f32(0xFFFF8E38) == want, f'05979C {s5b} {s5c} {flag}')
    say('  0x05979C [8E38] := [4144] (or 70.0 when byte [9705] != 0, via 0x0297B0) only when [8E5B]==1 and [8E5C]==0   (18 cases)')
    # ---- 0x059C3A: [8E46]
    BC = calw(0x0D93BC)
    n = 0
    for (e46, c56, d96, d36, a75f, e47, e44, e6a, e65, e68, e45, z25c, a9, s60) in (
            tuple(RNG.choice(c) for c in ((0, 1, 2), (0, BC - 2, BC - 1, BC, 0xFFFF), (0, 1, 0), (0, 0, 0xA5, 0xFF),
                                          (0, 1), (0, 1), (0, 1, 2), (0, 1), (0, 1, 2), (0, 1, 2), (0, 1), (0, 1, 7),
                                          (0, 0, 1), (0, 1, 2)))
            for _ in range(20000)):
        e.port.clear(); e.events.clear()
        for a, v in ((0xFFFF8E46, e46), (0xFFFF96A8, d96), (0xFFFF96A9, 0), (0xFFFF36F4, d36), (0xFFFFA75F, a75f),
                     (0xFFFF8E47, e47), (0xFFFF8E44, e44), (0xFFFF8E6A, e6a), (0xFFFF8E65, e65), (0xFFFF8E68, e68),
                     (0xFFFF8E45, e45), (0xFFFF225C, z25c), (0xFFFF65A9, a9), (0xFFFF8E60, s60)):
            e.ram_u8(a, v)
        e.ram_u16(0xFFFF8E56, c56)
        ecall(e, 0x059C3A)
        w56 = min(c56 + 1, 0xFFFF) if e46 == 1 else 0
        rc = e46 == 1 and w56 >= BC
        D = {0xFF: 1, 0xA5: 2}.get(d36, 0)
        diag = 1 if d96 == 1 else 0
        new = e46

        def setchk():
            if e44 != 1:
                return e46
            if z25c == 0 or e68 == 1:
                return 1
            if e65 != 0:
                return e46
            return 1 if e45 == 1 else e46
        if D == 2:
            new = 1 if a75f == 1 else (0 if rc else e46)
        elif diag == 1:
            new = 1 if e47 == 1 else (0 if rc else e46)
        elif rc:
            if e44 != 1 or e6a == 1:
                new = 0
            elif e65 == 0 or e68 == 1:
                new = setchk()
            else:
                new = 0
        else:
            new = setchk()
        if a9 != 0:
            w60, wev = 0, []
        elif new == 1 and s60 == 0:
            w60, wev = 1, [(0, 5)]
        elif new == 0 and s60 == 1:
            w60, wev = 0, [(0, 6)]
        else:
            w60, wev = s60, []
        got = (e.read_u8(0xFFFF8E46), e.read_u16(0xFFFF8E56), e.read_u8(0xFFFF8E60), e.port, e.events)
        want = (new, w56, w60, [(PORT, 0x10, 1 if new == 1 else 0)], wev)
        check(got == want, f'059C3A {got} vs {want}')
        n += 1
    say(f'  0x059C3A [8E46] (port bit 0x10, on-time [8E56] vs u16 cal {BC}): {n} random cases')
    # ---- 0x05A3F6: [8E6A]
    n = 0
    for ed, e45, ec, a66, z25c in itertools.product((0, 1, 2), (0, 1, 2), (0, 1, 2), (0, 1, 2), (0, 1, 2)):
        for a, v in ((0xFFFF68ED, ed), (0xFFFF8E45, e45), (0xFFFF68EC, ec), (0xFFFF3666, a66), (0xFFFF225C, z25c)):
            e.ram_u8(a, v)
        ecall(e, 0x05A3F6)
        want = 1 if ((ed == 1 and e45 == 0) or ec == 1 or (a66 == 1 and z25c == 1)) else 0
        check(e.read_u8(0xFFFF8E6A) == want, '05A3F6')
        n += 1
    say(f'  0x05A3F6 [8E6A] = ([68ED]==1&&[8E45]==0) || [68EC]==1 || ([3666]==1&&[225C]==1): {n} cases (exhaustive 0..2)')
    # ---- 0x059862: [8E44]
    C0, C4, C8, CC, D0 = (calf(a) for a in (0x0D93C0, 0x0D93C4, 0x0D93C8, 0x0D93CC, 0x0D93D0))
    n = 0
    for _ in range(20000):
        v = RNG.choice((8.8, 8.95, 10.95, f32(10.9), float('nan')))
        t = RNG.choice((2.9, 3.0, 50.0, 119.9, 120.0, float('nan')))
        old58, old44, e46, z25c, a66, bd, s5b, s166 = (RNG.choice(c) for c in (
            (0, 1), (0, 1, 2), (0, 1), (0, 1), (0, 1), (0, 1, 2), (0, 1, 2), (0, 1)))
        # predicate bytes: [65F6] (0x022F92: == 1), [9705] [9706] [9714] [9707] (0x0297B0/C0, 0x0298C8, 0x0297D0: != 0)
        pb = [RNG.choice((0, 0, 0, 0, 1, 2, 0x80)) for _ in range(5)]
        preds = [1 if pb[0] == 1 else 0] + [2 if x else 0 for x in pb[1:]]
        r9720 = RNG.choice((0, 0, 0, 1))
        for addr, val in zip((0xFFFF65F6, 0xFFFF9705, 0xFFFF9706, 0xFFFF9714, 0xFFFF9707), pb):
            e.ram_u8(addr, val)
        for a, val in ((0xFFFF8E58, old58), (0xFFFF8E44, old44), (0xFFFF8E46, e46), (0xFFFF225C, z25c),
                       (0xFFFF3666, a66), (0xFFFF65BD, bd), (0xFFFF8E5B, s5b), (0xFFFF4166, s166),
                       (0xFFFF9720, r9720)):
            e.ram_u8(a, val)
        e.ram_f32(0xFFFF4130, v); e.ram_f32(0xFFFF682C, t)
        ecall(e, 0x059862)
        if not (C0 > v):
            w58 = 1
        elif f32(C0 - C4) > v:
            w58 = 0
        else:
            w58 = old58
        lo = CC if z25c == 0 else C8
        ok = (w58 == 1 and not (lo > t) and (D0 > t) and not (a66 != 0 and z25c != 0) and r9720 == 0
              and all(p == 0 for p in preds) and bd == 1)
        r13 = old44
        if not ok:
            r13 = 0
        else:
            if s5b == 0:
                r13 = 1
            if e46 == 0:
                if s166 == 0 or s5b == 1:
                    r13 = 0
        check((e.read_u8(0xFFFF8E58), e.read_u8(0xFFFF8E44)) == (w58, r13), f'059862 {v} {t} {preds}')
        n += 1
    say(f'  0x059862 [8E44]: window {C8:g}/{CC:g} <= [682C] < {D0:g}, [8E58] hysteresis on [4130] (on >= {C0:.4g}, off < '
        f'{f32(C0 - C4):.4g}), [65F6]!=1, [9705] [9706] [9714] [9707] == 0, [9720]==0, [65BD]==1, [8E5B]/[4166]/[8E46] terms: {n} random cases')


# ====================================================================== G  dispatchers
def sec_G():
    say('\n==== G. dispatchers 0x05951C and 0x059F94 ====')
    e = emu()
    order = []
    seen = {}
    t1 = (0x05979C, 0x0597D4, 0x059564, 0x0596F8, 0x059862, 0x0599FE, 0x059AE2, 0x059B42, 0x059C3A, 0x059DB4)
    for a in t1:
        e.stub(a, fn=(lambda a: (lambda m: (order.append(a), seen.setdefault(a, m.read_u8(0xFFFF8E5B)))))(a))
    for v65c2, old5b, v48, v49 in itertools.product((0, 1, 2), (0, 1), (0, 7), (0, 9)):
        order.clear(); seen.clear()
        e.ram_u8(0xFFFF65C2, v65c2); e.ram_u8(0xFFFF8E5B, old5b); e.ram_u8(0xFFFF8E48, v48); e.ram_u8(0xFFFF8E49, v49)
        ecall(e, 0x05951C)
        check(tuple(order) == t1, f'05951C order {order}')
        check(seen[0x05979C] == v65c2, '05951C [8E5B] before 05979C')
        check((e.read_u8(0xFFFF8E5B), e.read_u8(0xFFFF8E5C), e.read_u8(0xFFFF8E5D), e.read_u8(0xFFFF8E5E))
              == (v65c2, v65c2, v48, v49), '05951C copies')
    say('  0x05951C: [8E5B] := [65C2] before 0x05979C; callees in order ' + ' '.join(f'{a:06X}' for a in t1)
        + '; then [8E5C] := [8E5B], [8E5D] := [8E48], [8E5E] := [8E49]   (24 cases)')
    order2 = []
    t2 = (0x05A3F6, 0x059FB4, 0x05A218, 0x05A066, 0x05A26E, 0x05A498)
    for a in t2:
        e.stub(a, fn=(lambda a: (lambda m: order2.append(a)))(a))
    for v in (0, 1, 0x80):
        order2.clear()
        e.ram_u8(0xFFFF8E65, v)
        ecall(e, 0x059F94)
        check(tuple(order2) == t2 and e.read_u8(0xFFFF8E7B) == v, '059F94')
    say('  0x059F94: [8E7B] := [8E65]; then ' + ' '.join(f'{a:06X}' for a in t2) + ' (0x05A498 by tail branch)   (3 cases)')


# ====================================================================== R  0x028210 control flow
def sec_R():
    say('\n==== R. 0x028210 control flow around the [9720] gate ====')
    sys.path.insert(0, os.path.join(REPO, 'scripts', 'mapping'))
    import collections
    import function_census as fc

    def u16(a):
        return struct.unpack_from('>H', ROM, a)[0]
    entry = 0x028210

    def succ_of(pc):
        w = u16(pc)
        kind, tgt, delay = fc.flow_of(w, pc)
        if kind == 'bad':
            return kind, []
        if delay:
            nxt = pc + 4
            if kind in ('call', 'icall'):
                return kind, [nxt]
            if kind == 'cond':
                return kind, [tgt, nxt]
            if kind == 'jump':
                return kind, [tgt]
            return kind, []
        if kind == 'cond':
            return kind, [tgt, pc + 2]
        return kind, [pc + 2]

    def rdef(reg):
        ins = {entry: frozenset(['ENTRY'])}
        q = collections.deque([entry])
        while q:
            pc = q.popleft()
            st = ins[pc]
            kind, nx = succ_of(pc)
            out = frozenset([pc]) if reg in fc.writes(u16(pc)) else st
            w = u16(pc)
            if fc.flow_of(w, pc)[2]:                       # delay slot executes before the transfer
                if reg in fc.writes(u16(pc + 2)):
                    out = frozenset([pc + 2])
            for n in nx:
                old = ins.get(n)
                new = out if old is None else old | out
                if new != old:
                    ins[n] = new
                    q.append(n)
        return ins
    i14 = rdef(14)
    check(i14[0x0294C2] == frozenset([0x02927E]), f'r14 defs {i14[0x0294C2]}')
    i1, i4 = rdef(1), rdef(4)
    check(i1[0x0294D8] == frozenset([0x0294CC]) and i4[0x0294D8] == frozenset([0x0294CE]), 'r1/r4 defs')
    preds = collections.defaultdict(set)
    for pc in i14:
        for n in succ_of(pc)[1]:
            preds[n].add(pc)
    p4e = preds[0x02964E]
    check(len(p4e) == 17 and all(0x0294C2 <= p <= 0x029642 for p in p4e), f'preds 2964E {sorted(map(hex, p4e))}')
    check(preds[0x029644] == {0x0294C8, 0x029642}, f'preds 29644 {preds[0x029644]}')
    say(f'  reachable nodes {len(i14)}; r14 at 0x0294C2 defined only at 0x02927E; r1 / r4 at 0x0294D8 only at '
        f'0x0294CC / 0x0294CE')
    say(f'  0x02964E ([9720] := 1) has {len(p4e)} predecessors, all in 0x0294C2..0x029642; 0x029644 ([9720] := 0) '
        f'only 0x0294C8 and 0x029642')
    # frame stores: @r15 (byte) and @(r0,r15) with r0 a constant, over every reachable node
    st = fc.reg_states(ROM, entry)
    slot_writers = collections.defaultdict(set)
    unknown = []
    for (pc, role), R in st.items():
        w = u16(pc)
        op, n, d4 = w >> 12, (w >> 8) & 15, w & 15
        if op == 0x2 and n == 15 and d4 in (0, 1, 2):
            slot_writers[0].add(pc)
        elif op == 0x0 and n == 15 and d4 in (4, 5, 6):
            if R[0] is None:
                unknown.append(pc)
            else:
                for v in R[0]:
                    slot_writers[v].add(pc)
        elif op == 0x8 and n == 0 and ((w >> 4) & 15) == 15:
            slot_writers[d4].add(pc)
        elif op == 0x1 and n == 15:
            slot_writers[d4 * 4].add(pc)
    check(not unknown, f'unresolved frame stores {unknown}')
    want = {0: {0x028224}, 36: {0x02832A}, 40: {0x028346}, 44: {0x028362}, 48: {0x028380}, 52: {0x02839E}}
    for k, v in want.items():
        check(slot_writers[k] == v, f'slot {k}: {sorted(map(hex, slot_writers[k]))}')
    say('  frame slot writers: @0 0x028224, @36 0x02832A, @40 0x028346, @44 0x028362, @48 0x028380, @52 0x02839E '
        '(no other store into those slots; every indexed frame store has a constant r0)')
    # stores whose base is neither r15 nor GBR: none in 0x028210, and its four callees store nothing at all
    def store_base(w):
        op, n, m, d4 = w >> 12, (w >> 8) & 15, (w >> 4) & 15, w & 15
        if op == 0x2 and d4 in (0, 1, 2, 4, 5, 6):
            return n
        if op == 0x0 and d4 in (4, 5, 6):
            return n
        if op == 0x8 and n in (0, 1):
            return m
        if op == 0x1:
            return n
        if op == 0xC and n in (0, 1, 2, 0xD, 0xE, 0xF):
            return 'gbr'
        if op == 0x4 and (w & 0xFF) == 0x1B:
            return n
        if op == 0xF and d4 in (0xA, 0xB, 0x7):
            return n
        if op == 0x4 and (w & 0xF) in (2, 3) and ((w >> 4) & 0xF) in (0, 1, 2, 5, 6):
            return n
        return None
    other = sorted(pc for (pc, role) in st if store_base(u16(pc)) not in (None, 15, 'gbr'))
    check(not other, f'0x028210 stores off another base: {[hex(p) for p in other]}')
    callees = {}
    for (pc, role) in st:
        w = u16(pc)
        if (w & 0xF0FF) == 0x400B:
            R = st[(pc, role)]
            v = R[(w >> 8) & 15]
            check(v is not None and len(v) == 1, f'unresolved jsr {pc:x}')
            callees[pc] = next(iter(v))
    check(sorted(set(callees.values())) == [0x020FF6, 0x021006, 0x0582AC, 0x058524], f'callees {callees}')
    for c in sorted(set(callees.values())):
        cs = fc.reg_states(ROM, c)
        bad = [pc for (pc, role) in cs if store_base(u16(pc)) is not None]
        check(not bad, f'callee {c:x} stores {bad}')
    say('  0x028210: no store whose base is not r15 or GBR; its callees 0x020FF6 0x021006 0x0582AC 0x058524 '
        '(jsr 0x028FF6 / 0x028FFC / 0x02841C / 0x028220) contain no store')
    # which gate tests read the array live and which read a frame slot sampled at entry
    live = sorted(pc for (pc, role) in st if 0x0294C2 <= pc <= 0x029642 and u16(pc) & 0xF00F == 0x000C
                  and (u16(pc) >> 4) & 15 == 1)
    frame = sorted(pc for (pc, role) in st if 0x0294C2 <= pc <= 0x029642 and u16(pc) & 0xF0FF == 0x00FC)
    check(len(live) == 12 and len(frame) == 5, f'gate reads live {len(live)} frame {len(frame)}')
    say(f'  gate 0x0294C2..0x029642: {len(live)} status bytes read live "mov.b @(r0,r1)" (r1 = 0xFFFFAD52): '
        + ' '.join('%06X' % p for p in live))
    say(f'                           {len(frame)} read from frame slots "mov.b @(r0,r15)" (sampled at 0x02832A..0x02839E): '
        + ' '.join('%06X' % p for p in frame))


# ====================================================================== S  0x047C40 -> 0x0594F8
def sec_S():
    say('\n==== S. 0x047C40: when is 0x0594F8 ([8E38] := [4144]) called ====')
    sys.path.insert(0, os.path.join(REPO, 'scripts', 'mapping'))
    import function_census as fc

    def u16(a):
        return struct.unpack_from('>H', ROM, a)[0]

    def succ(pc):
        w = u16(pc)
        kind, tgt, delay = fc.flow_of(w, pc)
        if kind == 'bad':
            return []
        if delay:
            if kind in ('call', 'icall'):
                return [pc + 4]
            if kind == 'cond':
                return [tgt, pc + 4]
            if kind == 'jump':
                return [tgt]
            return []
        if kind == 'cond':
            return [tgt, pc + 2]
        return [pc + 2]

    def reach(start, cut_edge=None, cut_node=None):
        seen = {start}
        q = [start]
        while q:
            pc = q.pop()
            for n in succ(pc):
                if (pc, n) == cut_edge or n == cut_node:
                    continue
                if n not in seen:
                    seen.add(n)
                    q.append(n)
        return seen
    E0, SITE, GATE, ARM, EPI = 0x047C40, 0x048296, 0x047C6E, 0x047D40, 0x0486E0
    st = fc.reg_states(ROM, E0)
    jt = st[(SITE, None)][2]
    check(u16(SITE) == 0x420B and jt == frozenset([0x0594F8]), f'048296 target {jt}')
    check(st[(0x047C68, None)][2] == frozenset([0xFFFF8EDC]), 'pool 0xFFFF8EDC')
    allr = reach(E0)
    check(SITE in allr and EPI in allr, 'reach')
    check(SITE not in reach(E0, cut_edge=(GATE, ARM)), 'site reachable without the taken bt')
    check(EPI not in reach(ARM, cut_node=SITE), 'epilogue reachable from 0x047D40 around the call')
    conds = sorted(pc for pc in allr if fc.flow_of(u16(pc), pc)[0] == 'cond')
    check(conds == [0x047C6E, 0x047C76, 0x047D4E, 0x047D66, 0x047DA4], f'conds {conds}')
    ncall = sum(1 for pc in allr if fc.flow_of(u16(pc), pc)[0] in ('call', 'icall'))
    check(ncall == 294, f'calls {ncall}')
    # both [8EDC] != 0 arms end in bra 0x0486E0 (epilogue) without passing 0x048296
    for arm in (0x047C78, 0x047CA0):
        check(SITE not in reach(arm), f'arm {arm:x}')
    say('  0x047C66..0x047C6E: r2 = extu.b byte [0xFFFF8EDC]; tst r2,r2 (T when 0); bt 0x047D40')
    say('  jsr @r2 at 0x048296 -> 0x0594F8: unreachable once the edge 0x047C6E -> 0x047D40 is removed;')
    say('  every path from 0x047D40 to the epilogue 0x0486E0 passes 0x048296 (callees assumed to return);')
    say('  the [8EDC] != 0 arms 0x047C78 / 0x047CA0 reach the epilogue without it.  0x047C40: 294 calls, conditional '
        'branches ' + ' '.join('0x%06X' % c for c in conds))


# ====================================================================== W  whole-image store scan
OTHER_WRITERS = {
    0xFFFF8E45: {0x059B34}, 0xFFFF8E46: {0x059D04, 0x059D26}, 0xFFFF8E64: {0x05A056}, 0xFFFF8E65: {0x05A17E},
    0xFFFF8E68: {0x05A3D2, 0x05A3DA}, 0xFFFF8E44: {0x0599E4}, 0xFFFF8E38: {0x059512, 0x0597C2, 0x0597CA},
    0xFFFF8E6A: {0x05A42A, 0x05A432}, 0xFFFF8E92: {0x05A810}, 0xFFFF8E93: {0x05A81A}, 0xFFFF8E5B: {0x05952A},
    0xFFFF8E5C: {0x059552}, 0xFFFF8E56: {0x059C96}, 0xFFFF8E76: {0x05A022}, 0xFFFF8E78: {0x059FE4, 0x059FF4},
    0xFFFF8E7D: {0x05A00A, 0x05A00E}, 0xFFFF8E58: {0x0598C8, 0x0598D8},
    # AUDIT: the bytes of 0x05A218 / 0x05A066 / 0x05A26E and the 0x059F94 copy
    0xFFFF8E66: {0x05A252}, 0xFFFF8E67: {0x05A264}, 0xFFFF8E69: {0x05A3DE}, 0xFFFF8E7C: {0x05A2F4, 0x05A31C},
    0xFFFF8E79: {0x05A0D8, 0x05A0EA}, 0xFFFF8E7A: {0x05A0F8, 0x05A10A}, 0xFFFF8E7B: {0x059F9E},
    0xFFFF8E74: {0x05A122, 0x05A126},
}


def sec_W():
    say('\n==== W. whole-image store scan ====')
    sys.path.insert(0, os.path.join(REPO, 'scripts', 'mapping'))
    import json
    import function_census as fc
    funcs = [json.loads(l.strip().rstrip(',')) for l in open(os.path.join(REPO, 'disassembly', 'maps', 'function_census.json'))
             if l.startswith('{"entry"')]
    byentry = {int(f['entry'], 16): f for f in funcs}
    M32 = 0xFFFFFFFF

    def u16(a):
        return struct.unpack_from('>H', ROM, a)[0]

    def store(w):
        op, n, m, d4 = w >> 12, (w >> 8) & 15, (w >> 4) & 15, w & 15
        if op == 0x2 and d4 in (0, 1, 2):
            return (1 << d4, n, 0, False)
        if op == 0x2 and d4 in (4, 5, 6):
            return (1 << (d4 - 4), n, -(1 << (d4 - 4)), False)
        if op == 0x0 and d4 in (4, 5, 6):
            return (1 << (d4 - 4), n, 0, True)
        if op == 0x8 and n == 0:
            return (1, m, d4, False)
        if op == 0x8 and n == 1:
            return (2, m, d4 * 2, False)
        if op == 0x1:
            return (4, n, d4 * 4, False)
        if op == 0xC and n in (0, 1, 2):
            return (1 << n, 'gbr', (w & 0xFF) << n, False)
        if op == 0xC and n in (0xD, 0xE, 0xF):
            return (1, 'gbr', 0, True)
        if op == 0x4 and (w & 0xFF) == 0x1B:
            return (1, n, 0, False)
        if op == 0xF and d4 == 0xA:
            return (4, n, 0, False)
        if op == 0xF and d4 == 0xB:
            return (4, n, -4, False)
        if op == 0xF and d4 == 0x7:
            return (4, n, 0, True)
        return None
    targets = (0xFFFF8E7E, 0xFFFF9720)
    hits = {t: set() for t in targets}
    gbr_of = {}
    unres_reg = 0
    unres_gbr = []
    resolved_pcs = {}
    sizes = {}

    def covers(pc, a, t):
        return a <= t < a + sizes[pc]
    for f in funcs:
        ent = int(f['entry'], 16)
        st = fc.reg_states(ROM, ent)
        gb = set()
        for (pc, role), R in st.items():
            w = u16(pc)
            if (w & 0xF0FF) == 0x401E:
                v = R[(w >> 8) & 15]
                gb |= ({None} if v is None else set(v))
        gbr_of[ent] = gb
        for (pc, role), R in st.items():
            s = store(u16(pc))
            if s is None:
                continue
            size, base, disp, idx = s
            if base == 15:
                continue
            if base == 'gbr':
                if len(gb) != 1 or None in gb:
                    unres_gbr.append((pc, ent, size, disp, idx))
                    continue
                bv = gb
            else:
                bv = R[base]
                if bv is None:
                    unres_reg += 1
                    continue
            if idx:
                if R[0] is None:
                    if base == 'gbr':
                        unres_gbr.append((pc, ent, size, disp, idx))
                    else:
                        unres_reg += 1
                    continue
                addrs = {(b + x + disp) & M32 for b in bv for x in R[0]}
            else:
                addrs = {(b + disp) & M32 for b in bv}
            sizes[pc] = size
            for a in addrs:
                resolved_pcs.setdefault(pc, set()).add(a)
                for t in targets:
                    if a <= t < a + size:
                        hits[t].add(pc)
    check(hits[0xFFFF8E7E] == {0x05A6F0, 0x05A7D4, 0x05A802}, f'8E7E writers {hits[0xFFFF8E7E]}')
    check(hits[0xFFFF9720] == {0x02964C, 0x029650}, f'9720 writers {hits[0xFFFF9720]}')
    say('  resolved stores covering byte 0xFFFF8E7E: ' + ' '.join(f'0x{p:06X}' for p in sorted(hits[0xFFFF8E7E])))
    say('  resolved stores covering byte 0xFFFF9720: ' + ' '.join(f'0x{p:06X}' for p in sorted(hits[0xFFFF9720])))
    for t, want in sorted(OTHER_WRITERS.items()):
        got = {pc for pc, aset in resolved_pcs.items() if any(a <= t < a + 4 and covers(pc, a, t) for a in aset)}
        check(got == want, f'writers of {t:08X}: {sorted(map(hex, got))}')
    say('  single-writer bytes asserted: ' + '; '.join(f'[{t & 0xFFFF:04X}] ' + '/'.join(f'{p:06X}' for p in sorted(w))
                                                        for t, w in sorted(OTHER_WRITERS.items())))

    # GBR-relative stores whose function inherits GBR: resolve through census callers (6 levels),
    # or through any other census function in which the same pc resolved
    def caller_gbr(ent, depth=0, seen=None):
        seen = seen if seen is not None else set()
        if ent in seen or depth > 6 or ent not in byentry:
            return {None}
        seen.add(ent)
        g = {int(x, 16) for x in byentry[ent]['gbr']}
        if g:
            return g
        out = set()
        for c in byentry[ent]['callers']:
            out |= caller_gbr(int(c, 16), depth + 1, seen)
        return out or {None}
    bad = []
    left = 0
    for pc, ent, size, disp, idx in unres_gbr:
        if pc in resolved_pcs:
            continue                      # same instruction resolved inside an enclosing function
        gs = caller_gbr(ent)
        if None in gs:
            left += 1
            bad.append((pc, ent))
            continue
        for g in gs:
            for t in targets:
                if idx:
                    if g <= t <= g + 255:
                        bad.append((pc, ent))
                elif g + disp <= t < g + disp + size:
                    bad.append((pc, ent))
    check(not bad, f'unresolved GBR stores that could reach a target: {[(hex(a), hex(b)) for a, b in bad]}')
    say(f'  {len(unres_gbr)} GBR-relative stores not resolved inside their own function: each resolved through the '
        f'census callers or an enclosing function; none reaches either byte')
    say(f'  {unres_reg} stores with a base register the CFG propagation does not resolve (stack-loaded or computed): '
        f'NOT excluded -- the writer lists are a lower bound for those')


# ====================================================================== Z  stock vs 20.19c
def sec_Z():
    say('\n==== Z. stock vs 20.19c ====')
    stock = open(STOCK_PATH, 'rb').read()
    # the DTC record table: 20-byte records whose +12..+15 is 0x0009EF10 or 0x0002BE1x and whose +16..+19 is
    # 0x01000000 or 0; that holds for records 0..194 and fails at record 195 (0x09B770), after which the bytes are
    # 8 zero bytes and 12-byte entries {long, ROM pointer, 1} from 0x09B778
    def u32(a):
        return struct.unpack_from('>I', ROM, a)[0]
    nrec = 0
    while (u32(REC + 20 * nrec + 12) in (0x0009EF10, 0x0002BE10, 0x0002BE1A)
           and u32(REC + 20 * nrec + 16) in (0x01000000, 0)):
        nrec += 1
    check(nrec == 195, f'record layout holds for {nrec} records')
    end = REC + 20 * nrec
    check(end == 0x09B770 and u32(end) == 0 and u32(end + 4) == 0 and u32(end + 12) == 0x000989A4, 'record 195 bytes')
    for j in range(9):
        a = 0x09B778 + 12 * j
        check(u32(a + 8) == 1 and 0x090000 <= u32(a + 4) < REC and (u32(a) & 0x00FFFFFF) == 0, f'12-byte entry {j}')
    check(ROM[REC + 20 * 194 + 2] == 0x1D and ROM[REC + 20 * 194 + 3] == 0x01, 'record 194 +2/+3 (read at 0x0282B4)')
    say(f'  DTC record layout (+12..+15 = 0009EF10 / 0002BE1x, +16..+19 = 01000000 / 0) holds for records 0..{nrec - 1} '
        f'(0x{REC:06X}..0x{end - 1:06X}); record {nrec} at 0x{end:06X} = '
        f'{ROM[end:end + 20].hex(" ", 4)} breaks it; 0x09B778.. = 12-byte entries {{long, ptr, 1}} (9 checked)')
    check(struct.unpack_from('>H', ROM, 0x0282B4)[0] == 0x95AC and struct.unpack_from('>H', ROM, 0x028410)[0] == 0x0F2A,
          '0x0282B4 mov.w 0x0F2A')
    say(f'  0x0282B4 (in 0x028210) reads record 194: 95AC mov.w @(0x028410) = 0x0F2A = 20*194 + 2; its +2 = 0x1D, +3 = 0x01')
    spans = [(0x0D93B0, 0x0D9400), (0x0D9400, 0x0D9450), (0x0AF4F0, 0x0AF504), (REC, end),
             # AUDIT: 0x05A066 descriptors 0x0AF51C / 0x0AF530 (records, axes, data) and 0x05A26E's two u16 cells
             (0x0AF51C, 0x0AF544), (0x0D9510, 0x0D95A0), (0x0C306A, 0x0C3070)]
    for lo, hi in spans:
        d = [a for a in range(lo, hi) if ROM[a] != stock[a]]
        say(f'  0x{lo:06X}..0x{hi - 1:06X}: {len(d)} differing bytes')
        check(not d, f'diff {lo:x}')
    say(f'  u16 [0x0D93BE] = {calw(0x0D93BE)} (min on time, calls), u16 [0x0D93BC] = {calw(0x0D93BC)}, '
        f'u8 [0x0D93B0] = {ROM[0x0D93B0]}, f32 [0x0D93E0] = {calf(0x0D93E0)}, [0x0D93E4] = {calf(0x0D93E4)}')
    say('  DTC-enable bytes 0x09A770 + record (definition "(Pxxxx) ..." tables, scaling "PXXXX enable" 00 = disabled):')
    for off in GATE_AD52 + GATE_3836:
        k, idx, mask, code = rec_fields(off)
        a = 0x09A770 + k
        say(f'     record {k:3d} code {code:04X}  0x{a:06X}: 20.19c {ROM[a]:02X}  stock {stock[a]:02X}')
        check(stock[a] == 1, 'stock enable')
        check(ROM[a] == (1 if code in (0x2257, 0x2258) else 0), '20.19c enable')
    # the definition join: the table the project XML defines at 0x09A770 + record names the code in +4..+5
    sys.path.insert(0, os.path.join(REPO, 'scripts'))
    import defs as DEFS
    d = DEFS.load()
    joined = 0
    for off in GATE_AD52 + GATE_3836:
        k, idx, mask, code = rec_fields(off)
        ts = d.at(0x09A770 + k)
        if code in (0x2257, 0x2258):
            check(ts == [], f'no definition expected at {0x09A770 + k:x}')
            continue
        check(len(ts) == 1 and ts[0].name.startswith('(P%04X)' % code) and ts[0].scaling_name == 'PXXXX enable',
              f'definition join record {k}: {ts}')
        joined += 1
        say(f'     0x{0x09A770 + k:06X} -> "{ts[0].name}"')
    say(f'  definition join: {joined} of 17 records -- the table at 0x09A770 + record is named with the same P-code as '
        f'the record +4..+5 field; records 191/192 (2257, 2258) have no definition')
    # AUDIT: the code bytes (census extent) of every function this file decodes or cites for control flow
    nf = nb = 0
    for ent in AUDIT_CODE:
        f = CENSUS_BY_ENTRY[ent]
        lo, hi = ent, int(f['end'], 16)
        d = [a for a in range(lo, hi) if ROM[a] != stock[a]]
        check(not d, f'code diff {ent:06X}')
        nf += 1
        nb += hi - lo
    for lo, hi in AUDIT_POOLS:
        d = [a for a in range(lo, hi) if ROM[a] != stock[a]]
        check(not d, f'pool diff {lo:06X}')
        nb += hi - lo
    say(f'  code: {nf} functions (census extents) and {len(AUDIT_POOLS)} literal-pool spans, {nb} bytes: 0 differing '
        f'(every function decoded or cited here is byte-identical in stock and 20.19c)')


# ====================================================================== AUDIT sections (V, H, K, X)
RNG_AU = random.Random(20261128)
CENSUS_BY_ENTRY = {}
for _l in open(os.path.join(REPO, 'disassembly', 'maps', 'function_census.json')):
    if _l.startswith('{"entry"'):
        import json as _json
        _d = _json.loads(_l.strip().rstrip(','))
        CENSUS_BY_ENTRY[int(_d['entry'], 16)] = _d
AUDIT_CODE = [0x05A498, 0x05A8B8, 0x059F94, 0x0281DC, 0x0582AC, 0x05EAAE, 0x05EAD2, 0x058524, 0x028210,
              0x059FB4, 0x059AE2, 0x0594F8, 0x05979C, 0x05951C, 0x059C3A, 0x059862, 0x05A3F6, 0x05A218,
              0x05A066, 0x05A26E, 0x0297B0, 0x0297C0, 0x0297D0, 0x0298C8, 0x022F92, 0x0299F0, 0x03AB20,
              0x049CF0, 0x04A03E, 0x04A94C, 0x033460, 0x033304, 0x047C40]
AUDIT_POOLS = [(0x05A434, 0x05A498), (0x05A198, 0x05A218), (0x05A908, 0x05A928), (0x059E78, 0x059EB4),
               (0x059B88, 0x059B94), (0x059BDC, 0x059C00), (0x0596BC, 0x0596D4), (0x059914, 0x059970)]


def _w16(a):
    return struct.unpack_from('>H', ROM, a)[0]


def _s8(v):
    return v - 0x100 if v & 0x80 else v


def _s12(v):
    return v - 0x1000 if v & 0x800 else v


def cfg(entry):
    """Instruction-level CFG from entry, from opcode bits only.  jsr / bsr / bsrf are assumed to return.
    Returns (nodes, edges, exits, branches, call_sites)."""
    nodes, edges, exits, branches, calls = set(), {}, set(), [], []
    slot_succ = {}
    work = [entry]
    while work:
        pc = work.pop()
        if pc in nodes:
            continue
        nodes.add(pc)
        w = _w16(pc)
        if pc in slot_succ:
            succ = slot_succ[pc]
        else:
            succ = [pc + 2]
            if (w & 0xFF00) in (0x8900, 0x8B00):                       # bt / bf
                succ = [pc + 2, pc + 4 + 2 * _s8(w & 0xFF)]
                branches.append(pc)
            elif (w & 0xFF00) in (0x8D00, 0x8F00):                     # bt/s / bf/s
                slot_succ[pc + 2] = [pc + 4, pc + 4 + 2 * _s8(w & 0xFF)]
                branches.append(pc)
            elif (w >> 12) == 0xA:                                     # bra
                slot_succ[pc + 2] = [pc + 4 + 2 * _s12(w & 0xFFF)]
                branches.append(pc)
            elif (w >> 12) == 0xB or (w & 0xF0FF) in (0x400B, 0x0003):  # bsr / jsr / bsrf
                slot_succ[pc + 2] = [pc + 4]
                calls.append(pc)
            elif (w & 0xF0FF) == 0x402B or w in (0x000B, 0x002B):      # jmp / rts / rte
                slot_succ[pc + 2] = []
                exits.add(pc)
            elif (w & 0xF0FF) == 0x0023:                               # braf
                slot_succ[pc + 2] = []
                branches.append(pc)
                exits.add(pc)
        edges[pc] = succ
        work.extend(succ)
    return nodes, edges, exits, branches, calls


def jsr_literal(site):
    """The literal a jsr @Rn calls: the nearest preceding mov.l @(disp,pc),Rn within 8 instructions."""
    n = (_w16(site) >> 8) & 0xF
    for back in range(2, 18, 2):
        v = _w16(site - back)
        if (v >> 12) == 0xD and ((v >> 8) & 0xF) == n:
            return struct.unpack_from('>I', ROM, ((site - back + 4) & ~3) + 4 * (v & 0xFF))[0]
    return None


def sec_V():
    say('\n==== V. (AUDIT) task gates on byte [8EDC] ====')
    tasks = [(0x049CF0, [0x05951C, 0x059F94], 0x049E14), (0x04A03E, [0x028210], 0x04A244),
             (0x04A94C, [0x033304], 0x04A958)]
    for t, targets, arm in tasks:
        callees = [int(c, 16) for c in CENSUS_BY_ENTRY[t]['callees']]
        for v in (0, 1, 2, 0x7F, 0x80, 0xFE, 0xFF):
            e = E.Emu(ROM)
            log = []
            for c in callees:
                e.stub(c, fn=(lambda m, c=c: log.append(c)), r0=0)
            e.ram_u8(0xFFFF8EDC, v)
            ecall(e, t, regs={4: 0})
            hit = [c for c in targets if c in log]
            if v == 0:
                check(hit == targets, f'{t:06X} [8EDC] = 0 reaches {hit}')
                if t == 0x049CF0:
                    i = log.index(0x05951C)
                    check(log[i + 1] == 0x059F94 and log.count(0x05951C) == 1 and log.count(0x059F94) == 1,
                          '0x05951C immediately before 0x059F94, once each')
            else:
                check(hit == [], f'{t:06X} [8EDC] = {v:#x} reaches {hit}')
            if v in (0, 1, 0xFF):
                say(f'  0x{t:06X} [8EDC] = 0x{v:02X}: {len(log):3d} callee calls; reaches '
                    f'{" ".join(f"0x{x:06X}" for x in hit) or "none of " + " ".join(f"0x{x:06X}" for x in targets)}')
        nodes, edges, exits, branches, calls = cfg(arm)
        check(not branches and len(exits) == 1, f'{t:06X} arm 0x{arm:06X}: branches {branches} exits {exits}')
        lit = {s: jsr_literal(s) for s in calls}
        sites = sorted(s for s, x in lit.items() if x in targets)
        check(len(sites) == len(targets), f'{t:06X} static target sites {sites}')
        n2, e2, x2, b2, c2 = cfg(t)
        say(f'     arm 0x{arm:06X}: {len(nodes)} instructions, {len(calls)} calls, no branch, one exit '
            f'(0x{min(exits):06X}); target call site(s) {" ".join(f"0x{s:06X}" for s in sites)}; '
            f'whole function: branches only at {" ".join(f"0x{b:06X}" for b in sorted(b2))}')
    say('  => 0x05951C runs immediately before 0x059F94 (so 0x05A498 sees this pass\'s [8E45] / [8E46]), and '
        '0x05A498, 0x028210 and 0x033460 run only on passes with byte [8EDC] == 0')


CAL_AU = {'BA': calw(0x0D93BA), 'B8': calw(0x0D93B8), 'B4': calw(0x0D93B4), 'B2': ROM[0x0D93B2],
          'B1': ROM[0x0D93B1], 'F8': calf(0x0D93F8), 'FC': calf(0x0D93FC),
          'S': calw(0x0C306A) + calw(0x0C306E)}


def _fsub(a, b):
    """f32 a - b rounded toward zero, as the emulator computes it (model matching only; no claim rests on
    the last bit)."""
    from fractions import Fraction
    if not (abs(a) < float('inf') and abs(b) < float('inf')):
        return f32(a - b)
    q = Fraction(a) - Fraction(b)
    return E.b2f(E.rz_bits(q)) if q != 0 else 0.0


def m_05A218(s):
    o = {}
    if not (s['8E3E'] - s['3660']) > CAL_AU['BA']:
        if s['A733'] == 1 or s['A734'] == 1:
            o['8E66'] = 1
        if s['A733'] == 1 and s['A734'] == 1:
            o['8E67'] = 1
    return o


def m_05A066(s, t6c, t70):
    """t6c / t70: the two table values for [6624], read back (the lookup helper is verified elsewhere)."""
    o = {'8E6C': t6c, '8E70': t70}
    fr15 = _fsub(f32(s['2200']), f32(s['620C']))
    c63 = f32(s['63C4'])
    a79 = s['8E79']
    if t6c > c63:
        if _fsub(t6c, CAL_AU['F8']) > c63:
            a79 = 0
    else:
        a79 = 1
    a7a = s['8E7A']
    if fr15 > t70:
        if fr15 > _fsub(t70, -CAL_AU['FC']):
            a7a = 0
    else:
        a7a = 1
    o['8E79'], o['8E7A'] = a79, a7a
    r14 = 1 if s['7C68'] == 1 else 0
    o['8E74'] = min(s['8E74'] + 1, 0xFFFF) if r14 else 0
    if a79 == 1 or (r14 and o['8E74'] >= CAL_AU['B8']) or a7a == 1:
        v = 1
    elif s['8E66'] == 0 and not (s['8E3E'] - s['3660']) > CAL_AU['BA'] and CAL_AU['B1'] == 0:
        v = 1
    elif s['8E66'] == 1 and s['A733'] == 0 and s['A734'] == 0:
        v = 1
    else:
        v = 1 if s['8E6A'] == 1 else 0
    o['8E65'] = v
    return o


def m_05A26E(s):
    """s['8E65'] = the value 0x05A066 has just written; s['8E7B'] = the value 0x059F94 copied before it."""
    o = {}
    a7c = s['8E7C']
    if s['8E46'] == 0:
        a7c = 0
    elif s['8E65'] == 1 and s['8E7B'] == 0 and (s['365C'] >= CAL_AU['B4'] or s['3664'] >= CAL_AU['B2']):
        a7c = 1
    o['8E7C'] = a7c
    A733, A734, ED = s['A733'], s['A734'], s['68ED']
    r12, r5 = s['8E3C'] - s['365C'], s['8E3E'] - s['3660']

    def res(v68, v69=0):
        o['8E68'], o['8E69'] = v68, v69
        return o
    if s['225C'] == 0:
        return res(1)
    if ED == 1 and (A733 == 0 or A734 == 0):
        return res(0)
    if s['8E44'] == 0 or s['8E6A'] == 1:
        return res(0)
    if not r12 > CAL_AU['S']:
        return res(1)
    if not r5 > CAL_AU['S'] and CAL_AU['B1'] != 0:
        return res(1)
    if s['8E66'] == 1 and s['8E67'] == 0 and A733 == 0 and A734 == 0 and ED == 0:
        return res(1)
    if a7c == 1:
        return res(1)
    if s['8E45'] == 0 and s['8E44'] == 1:
        return res(1)
    if A733 == 1 and A734 == 1:
        return res(1, 1)
    if s['8E66'] == 1 and ED == 0 and s['8E67'] == 1 and A733 == 0 and A734 == 0:
        return res(1, 1)
    return res(0)


AU_ADDR = {'8E3C': (0xFFFF8E3C, 2), '8E3E': (0xFFFF8E3E, 2), '365C': (0xFFFF365C, 2), '3660': (0xFFFF3660, 2),
           '8E74': (0xFFFF8E74, 2), 'A733': (0xFFFFA733, 1), 'A734': (0xFFFFA734, 1), '8E66': (0xFFFF8E66, 1),
           '8E67': (0xFFFF8E67, 1), '8E65': (0xFFFF8E65, 1), '8E7B': (0xFFFF8E7B, 1), '8E46': (0xFFFF8E46, 1),
           '8E44': (0xFFFF8E44, 1), '8E45': (0xFFFF8E45, 1), '68ED': (0xFFFF68ED, 1), '8E6A': (0xFFFF8E6A, 1),
           '225C': (0xFFFF225C, 1), '3664': (0xFFFF3664, 1), '8E7C': (0xFFFF8E7C, 1), '7C68': (0xFFFF7C68, 1),
           '8E79': (0xFFFF8E79, 1), '8E7A': (0xFFFF8E7A, 1), '8E68': (0xFFFF8E68, 1), '8E69': (0xFFFF8E69, 1),
           '6624': (0xFFFF6624, 'f'), '63C4': (0xFFFF63C4, 'f'), '2200': (0xFFFF2200, 'f'),
           '620C': (0xFFFF620C, 'f'), '8E6C': (0xFFFF8E6C, 'f'), '8E70': (0xFFFF8E70, 'f')}


def au_put(e, s):
    for k, v in s.items():
        a, n = AU_ADDR[k]
        (e.ram_u8 if n == 1 else e.ram_u16 if n == 2 else e.ram_f32)(a, v)


def au_get(e, k):
    a, n = AU_ADDR[k]
    return e.read_u8(a) if n == 1 else (e.read_u16(a) if n == 2 else e.read_f32(a))


def au_b():
    return RNG_AU.choice((0, 1, 1, 1, 0, 2, 0x80, 0xFF))


def au_w():
    return RNG_AU.choice((0, 1, 76, 77, 78, 79, 312, 313, 314, 3124, 3125, 3126, 0x7FFF, 0x8000, 0xFFFF,
                          RNG_AU.randrange(65536)))


def sec_H():
    say('\n==== H. (AUDIT) 0x05A218 / 0x05A066 / 0x05A26E: model vs ROM ====')
    e = emu()
    W = {0xFFFF8E66, 0xFFFF8E67}
    for i in range(20000):
        s = {k: au_w() for k in ('8E3E', '3660')}
        s.update({k: au_b() for k in ('A733', 'A734', '8E66', '8E67')})
        if RNG_AU.random() < 0.5:
            s['3660'] = RNG_AU.randrange(0, 2000)
            s['8E3E'] = (s['3660'] + RNG_AU.choice((-1, 0, 76, 77, 78, 79, 80))) & 0xFFFF
        au_put(e, s)
        e.writes.clear()
        ecall(e, 0x05A218)
        want = dict(s)
        want.update(m_05A218(s))
        for k in ('8E66', '8E67'):
            check(au_get(e, k) == want[k], f'0x05A218 case {i} {k} {s}')
        check(not {a for a in e.writes if a not in W}, f'0x05A218 stray writes {i}')
    say('  0x05A218: 20,000 states (difference at 76..80 around u16 [0x0D93BA] = 78; bytes 0/1/2/0x80/0xFF): '
        '[8E66] [8E67] bit-exact, only those two bytes written')
    W = {0xFFFF8E65, 0xFFFF8E79, 0xFFFF8E7A, 0xFFFF8E74, 0xFFFF8E75} | set(range(0xFFFF8E6C, 0xFFFF8E74))
    nan = float('nan')
    for i in range(30000):
        s = {k: au_b() for k in ('A733', 'A734', '8E66', '8E6A', '7C68', '8E79', '8E7A')}
        s.update({k: au_w() for k in ('8E3E', '3660', '8E74')})
        s['6624'] = RNG_AU.choice((500.0, 1000.0, 1250.0, 1500.0, 2750.0, 3000.0, 4250.0, 5500.0, 7000.0))
        s['63C4'] = RNG_AU.choice((0.0, 20.0, 25.0, 25.0018310546875, 25.5, 29.0, 30.0, 30.0018310546875, 30.5,
                                   50.0, nan))
        s['620C'] = RNG_AU.choice((0.0, 50.0, 100.0, 101.3, 150.0, 300.0))
        s['2200'] = s['620C'] + RNG_AU.choice((-400.0, -370.0, -369.0, -320.0, -269.0, -219.0, -119.0, -69.0, -19.0,
                                               0.0, 31.0, 81.0, 82.0, 100.0, nan))
        au_put(e, s)
        e.writes.clear()
        ecall(e, 0x05A066)
        t6c, t70 = au_get(e, '8E6C'), au_get(e, '8E70')
        for k, v in m_05A066(s, t6c, t70).items():
            g = au_get(e, k)
            check(g == v or (g != g and v != v), f'0x05A066 case {i} {k}: rom {g} model {v} {s}')
        check(t6c == 30.0018310546875, f'[8E6C] = {t6c}')
        check(not {a for a in e.writes if a not in W}, f'0x05A066 stray writes {i}')
    say('  0x05A066: 30,000 states ([63C4] on and around 25.0018 / 30.0018 and NaN; [2200] - [620C] across '
        '[8E70] and [8E70] + 100 and NaN; u16 [8E74] around 313): [8E65] [8E79] [8E7A] [8E74] bit-exact; '
        '[8E6C] = 30.0018310546875 always; writes only [8E65] [8E6C] [8E70] [8E74] [8E79] [8E7A]')
    W = {0xFFFF8E68, 0xFFFF8E69, 0xFFFF8E7C}
    seen = {}
    for i in range(40000):
        s = {k: au_b() for k in ('A733', 'A734', '8E66', '8E67', '8E65', '8E7B', '8E46', '8E44', '8E45', '68ED',
                                 '8E6A', '225C', '3664', '8E7C')}
        s.update({k: au_w() for k in ('8E3C', '365C', '8E3E', '3660')})
        if RNG_AU.random() < 0.5:
            s['365C'] = RNG_AU.choice((0, 100, 3124, 3125, 3126, 60000))
            s['8E3C'] = (s['365C'] + RNG_AU.choice((-1, 0, 76, 77, 78, 200))) & 0xFFFF
            s['3660'] = RNG_AU.choice((0, 100, 1000))
            s['8E3E'] = (s['3660'] + RNG_AU.choice((-1, 0, 76, 77, 78, 200))) & 0xFFFF
        au_put(e, s)
        e.writes.clear()
        ecall(e, 0x05A26E)
        want = m_05A26E(s)
        for k, v in want.items():
            check(au_get(e, k) == v, f'0x05A26E case {i} {k}: rom {au_get(e, k)} model {v} {s}')
        check(not {a for a in e.writes if a not in W}, f'0x05A26E stray writes {i}')
        key = (want['8E68'], want['8E69'])
        seen[key] = seen.get(key, 0) + 1
        if s['225C'] == 0:
            check(want['8E68'] == 1 and want['8E69'] == 0, '[225C] == 0')
    say(f'  0x05A26E: 40,000 states: [8E68] [8E69] [8E7C] bit-exact, only those three written; ([8E68], [8E69]) '
        f'= (0,0) {seen.get((0, 0), 0)}, (1,0) {seen.get((1, 0), 0)}, (1,1) {seen.get((1, 1), 0)}; every state with '
        f'[225C] == 0 gives [8E68] = 1')


def k_run(e, s, ks, kw, kf):
    load(e, s)
    for a, v in ks.items():
        e.ram_u8(a, v)
    for a, v in kw.items():
        e.ram_u16(a, v)
    for a, v in kf.items():
        e.ram_f32(a, v)
    e.port.clear(); e.events.clear()
    ecall(e, 0x059F94)


K_BYTES = [0xFFFF68ED, 0xFFFF68EC, 0xFFFF3666, 0xFFFF225C, 0xFFFF9720, 0xFFFF8E78, 0xFFFF8E7D, 0xFFFF8E76,
           0xFFFF8E66, 0xFFFF8E67, 0xFFFF7C68, 0xFFFF8E79, 0xFFFF8E7A, 0xFFFF3664, 0xFFFF8E7C, 0xFFFF8E44,
           0xFFFF8E6A, 0xFFFF8E7B]
K_WORDS = [0xFFFF8E3C, 0xFFFF365C, 0xFFFF8E3E, 0xFFFF3660, 0xFFFF8E74]


def k_state():
    s = {a: RNG_AU.choice((0, 1, 1, 1, 0, 2, 0xFF)) for a in BYTES_IN}
    s.update({a: RNG_AU.choice((0, 1, 2, 3, 4, 0xFFFF)) for a in WORDS_IN})
    return s


def sec_K():
    say('\n==== K. (AUDIT) 0x059F94 run whole from ROM: what an r5 = 1 call needs ====')
    e = emu()
    sets = n225 = n6a = 0
    for i in range(30000):
        s = k_state()
        ks = {a: RNG_AU.choice((0, 1, 1, 2, 0xFF)) for a in K_BYTES}
        kw = {a: RNG_AU.choice((0, 50, 100, 200, 3125, 60000)) for a in K_WORDS}
        kf = {0xFFFF4130: RNG_AU.choice((8.0, 9.5, 12.0)), 0xFFFF68E4: RNG_AU.choice((30.0, 70.0)),
              0xFFFF6624: RNG_AU.choice((1000.0, 3000.0)), 0xFFFF63C4: RNG_AU.choice((10.0, 27.0, 40.0)),
              0xFFFF2200: 100.0, 0xFFFF620C: RNG_AU.choice((0.0, 100.0, 300.0))}
        if RNG_AU.random() < 0.4:          # bias toward states where a set can happen
            s.update({0xFFFF8E46: 1, 0xFFFF8E45: 1, 0xFFFF96A8: 0, 0xFFFF36F4: 0, 0xFFFF8E7E: 0,
                      0xFFFF8E7F: 0, 0xFFFF8E80: 0})
            ks.update({0xFFFF9720: 0, 0xFFFF68EC: 0, 0xFFFF7C68: 0})
            kf.update({0xFFFF4130: 12.0, 0xFFFF68E4: 30.0, 0xFFFF63C4: 10.0, 0xFFFF620C: 0.0})
        k_run(e, s, ks, kw, kf)
        b = e.read_u8
        if ks[0xFFFF225C] == 0:
            check(b(0xFFFF8E68) == 1, 'K: [225C] == 0 but [8E68] != 1')
            n225 += 1
        if b(0xFFFF8E6A) == 1:
            check(b(0xFFFF8E65) == 1, 'K: [8E6A] == 1 but [8E65] != 1')
            n6a += 1
        normal = s[0xFFFF96A8] != 1 and s[0xFFFF36F4] != 0xA5
        if normal and s[0xFFFF8E7E] == 0 and b(0xFFFF8E7E) == 1:
            sets += 1
            check(ks[0xFFFF225C] != 0 and ks[0xFFFF9720] == 0, 'K: set with [225C] == 0 or [9720] != 0')
            check(b(0xFFFF8E6A) == 0 and b(0xFFFF8E79) == 0 and b(0xFFFF8E7A) == 0, 'K: set with 6A / 79 / 7A')
            check(b(0xFFFF8E46) == 1 and b(0xFFFF8E45) == 1 and b(0xFFFF8E64) == 1 and b(0xFFFF8E65) == 0
                  and b(0xFFFF8E68) == 0, 'K: set without the r5 bytes')
            check(ks[0xFFFF68EC] != 1 and not (ks[0xFFFF3666] == 1 and ks[0xFFFF225C] == 1), 'K: set with 6A inputs')
    check(sets > 100, f'only {sets} sets: the necessary conditions would be vacuous')
    say(f'  30,000 states: [225C] == 0 -> [8E68] = 1 in all {n225}; [8E6A] == 1 -> [8E65] = 1 in all {n6a}')
    say(f'  {sets} normal-mode calls took [8E7E] 0 -> 1; on every one: [225C] != 0, [9720] == 0, [8E6A] == 0 '
        f'([68EC] != 1, not ([3666] == 1 and [225C] == 1)), [8E79] == 0, [8E7A] == 0, and [8E46] = [8E45] = '
        f'[8E64] = 1, [8E65] = [8E68] = 0 as 0x05A498 read them')
    both = blocked = on = 0
    for i in range(30000):
        s = k_state()
        s.update({0xFFFF96A8: RNG_AU.choice((0, 2)), 0xFFFF36F4: RNG_AU.choice((0, 0xFF, 0x12)), 0xFFFF8E7E: 0,
                  0xFFFF8E7F: 0, 0xFFFF8E80: 0, 0xFFFF8E46: 1, 0xFFFF8E45: 1})
        ks = {a: RNG_AU.choice((0, 1, 1, 2)) for a in K_BYTES}
        ks.update({0xFFFF9720: 0, 0xFFFF68EC: 0, 0xFFFF7C68: 0, 0xFFFF8E79: 0, 0xFFFF8E7A: 0})
        kw = {a: RNG_AU.choice((0, 50, 200, 3125, 60000)) for a in K_WORDS}
        kf = {0xFFFF4130: 12.0, 0xFFFF68E4: 30.0, 0xFFFF6624: 3000.0, 0xFFFF63C4: 10.0, 0xFFFF2200: 100.0,
              0xFFFF620C: 0.0}
        mode = i % 3
        if mode == 0:
            ks[0xFFFF8E66] = 1
            s[0xFFFF8E92] = s[0xFFFF8E93] = 0
        elif mode == 1:
            ks[0xFFFF8E66] = 1
            s[0xFFFF8E92] = s[0xFFFF8E93] = 1
            s[0xFFFF8E82] = s[0xFFFF8E84] = s[0xFFFF8E86] = 5
        k_run(e, s, ks, kw, kf)
        b = e.read_u8
        f7f, f80, f7e = b(0xFFFF8E7F), b(0xFFFF8E80), b(0xFFFF8E7E)
        if f7f == 1 and f80 == 1:
            both += 1
            check(b(0xFFFF8E66) != 1 and b(0xFFFFA733) == 0 and b(0xFFFFA734) == 0, 'BOTH with [8E66] == 1')
        if mode == 0:
            check(f7e == 0, '[8E66] == 1 with both latches 0 set [8E7E]')
            blocked += 1
        elif mode == 1 and f7e == 1:
            on += 1
            check(not (f7f == 1 and f80 == 1), 'BOTH with [8E66] == 1')
    check(both > 50 and on > 50, f'reachability {both} {on}')
    say(f'  normal mode, 30,000 states: {both} BOTH actions, every one with [8E66] != 1 and [A733] = [A734] = 0; '
        f'{blocked} calls with [8E66] = 1 and [8E92] = [8E93] = 0: [8E7E] never set; {on} ON20 / ON40 sets with '
        f'[8E66] = 1 and both latches set (so [8E66] blocks BOTH only)')


def sec_X():
    say('\n==== X. (AUDIT) 0x05A498 with non-boolean bytes and counters at the sign boundary ====')
    e = emu()
    for i in range(20000):
        s = {a: RNG_AU.choice((2, 0x80, 0xFE, 0xFF, 1, 0, 0x7F, 0x81)) for a in BYTES_IN}
        s[0xFFFF36F4] = RNG_AU.choice((0xA5, 0xFF, 0x25, 0xA4, 0))
        for a in WORDS_IN:
            s[a] = RNG_AU.choice((2, 3, 0x7FFE, 0x7FFF, 0x8000, 0x8001, 0xFFFE, 0xFFFF))
        got = run_05A498(e, s)[0]
        check(got == m_05A498(s)[0], f'X case {i}')
    say('  20,000 states, every byte in {0,1,2,0x7F,0x80,0x81,0xFE,0xFF}, [36F4] in {0,0x25,0xA4,0xA5,0xFF}, '
        'counters in {2,3,0x7FFE..0x8001,0xFFFE,0xFFFF}: ROM == section-C model on every written byte')


def main():
    sec_A()
    sec_B()
    sec_C()
    sec_D()
    sec_E()
    sec_F()
    sec_G()
    sec_R()
    sec_S()
    sec_W()
    sec_Z()
    sec_V()
    sec_H()
    sec_K()
    sec_X()
    say(f'\nOK: {NCHECK} assertions')
    return 0


if __name__ == '__main__':
    sys.exit(main())
