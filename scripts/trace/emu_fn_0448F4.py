#!/usr/bin/env python3
"""emu_fn_0448F4.py -- emulation evidence for disassembly/analysis/fn_0448F4_trace.txt

    python3 scripts/trace/emu_fn_0448F4.py        # prints tables, asserts, exits 0
    python3 scripts/trace/emu_fn_0448F4.py E I    # only the named sections (Z needs all to be meaningful)

Reference image: rom/AE5L600L 20g rev 20.19c.bin (md5 92cae8275cd4f9b473a3a9e36efe6449).
Stock rom/ae5l600l.bin and rom/AE5L600L 20g rev 20.19e.bin are read only in sections Z and I.
Deterministic (fixed seed).  Runs in about 3 minutes.

Revised 2026-11-27 after an adversarial review (REVIEW HISTORY of the analysis file):
B2 now tests the IEEE -0.1f / +0.1f (0xBDCCCCCD / 0x3DCCCCCD) next to the stored words
0xBDCCCCCC / 0x3DCCCCCC, and NaN for G15 / G16 / G17; A asserts that 0x0457F4 writes
[8253] on every call; B6 shows the prior [8253] never matters; E runs the consumer
0x04438C over its early exits and side paths; Z checks every EXECUTED instruction and
every pool word it loads (not a hand list); I recounts the definition-named axes that
[6350] / [6624] feed.

0x0448F4 (421 instructions, GBR 0xFFFF81F8, called from task 0x04AA58) is run in
scripts/sh2e_emu.py against a MODEL written from the byte reading in the analysis
file.  Per case the script asserts:
  * byte [0xFFFF8234] (written every call), byte [8249] (cleared when [798C] is not > 0),
    bytes [824D] / [8253] (the two hysteresis callees), bit for bit
  * the exact SET of non-stack RAM bytes written
  * the exact SET of RAM cells read: inputs are poked WITHOUT marking them initialised,
    so every input read lands in emu.uninit_reads -- that is the function's input list

Sections
  A  callees: 0x0298C8 / 0x029848 / 0x02F8FE / 0x01CF2E over all 256 byte values;
     0x0457D2 ([824D] on f32 [6624] vs [0x0D2F6C] / [0x0D2F70]) and 0x0457F4 ([8253] on
     f32 [79A8] vs [0x0CC220] / [0x0CC21C]) over value grids incl. float neighbours of
     each limit, NaN and +-inf, from every previous byte value 0 / 1 / 7
  B  0x0448F4 whole: B1 baseline (every gate clear -> 0); B2 each gate alone, with the
     float32 neighbours of every threshold; B3 every byte input over all 256 values on
     the baseline; B4 30,000 random states perturbed from the baseline + 6,000 states
     with every input random (model vs ROM, write set, read set); B5 instruction coverage
  C  in-memory ROM copies (the file is never written): byte [0x0D2997] != 90 (the
     [79C8] / [822C] pair is skipped), byte [0x0D299A] = 90 (the [8253] tail becomes
     live), float [0x0D2DBC] = 1.5 (the [653C] gate fires inside its writer's range)
  D  the writers this file relies on, emulated: 0x044D12 (u16 [8240], u8 [8249]
     counters), 0x044CEA (u8 [822C] counter), 0x044DB0 ([81F8] = L - lag(L)),
     0x044E04 (byte [822D] = 0 every call while [0x0D299B] = 0; 10 / 95 / 98 appear in
     a copy with [0x0D299B] = 1), 0x045970 ([826C] = 0.0 from the all-zero table
     0x0AE664; [8258] = blend of the two KC-advance-max tables by [90A8], overwritten every
     call -- independent of its prior value, no drift, also in a [0x0D299B] = 1 copy), 0x0459F6
     ([8268] never written while [0x0D299B] = 0), 0x045A3E / 0x0467AE ([8277] / [829E]
     = AND of four window bytes), 0x044300 (init: [822C] = 255, [8253] = 0)
  S  sequence: 0x044D12 then 0x0448F4 per step, [798C] > 0 from a cleared counter,
     every other gate clear: [8234] = 1 for exactly 62 steps, 0 from the 63rd on;
     [798C] -> 0 clears it
  E  consumer one level down: 0x04438C (the FBKC routine) run whole from ROM.  E1: its
     RPM / load windows open, no exit or side path: [81F0] steps by -[0x0D2DCC] only when
     [8234] = 1 and the knock byte [81BA] = 1, and relaxes by +[0x0D2DC0] toward 0 when
     [8234] = 0.  E2: one change at a time -- the head exits (bit 6 of [61F4], [7E76],
     [7F10], [824A], [970E], [9718], [824C] -> [8235]), [81BB], [7BE2] (blocks A / B),
     the side paths ([726E], [653C], bit 0 of [3244] with [8278]), the RPM window
     ([824B]) and the delayed recovery ([8224] >= 70).  0x044296 forms
     [81EC] = [81F0] + [8260] + [828C]
  Z  stock vs 20.19c vs 20.19e: the bytes of EVERY instruction executed by A-E (and every
     literal-pool word those instructions load), every calibration scalar read, the
     ranges of the three tables 0x045970 reads; definition names at the data pointers used
  I  identity recount: coverage_map.trace_axis_feeds (read-only) joined to the definition
     axes on the descriptor's axis pointer for the fr4 / fr5 slot -- how many lookups of
     [6350] / [6624] land on axes named "Coolant Temperature" / "Engine Speed"

Stubs: only the critical-section pair 0x00317C / 0x003190, and only in section E (the
[726E] side path of 0x04438C reaches 0x045F0A -> 0x0BDBCC, and the emulator raises on
"ldc sr"; rtos_core_trace.txt: the pair changes the SR mask only).  Every other callee
(0x0298C8, 0x029848, 0x02F8FE, 0x01CF2E, 0x0457D2, 0x0457F4, 0x0BE608, 0x0BE53C, 0x0BEA40,
0x0BE8E4, 0x0BE960, 0x0BE970, ...) runs from ROM.

ROUNDING: the model compares float32 values exactly; the only float arithmetic in
0x0448F4 is centre -/+ half-width inside 0x0BE608 for (0, 0.3515625), (0, 2^-8),
(0, 2^-7), (1, 2^-16), (0, 2^-16) -- all exact in float32 (asserted), so no verdict
here depends on the rounding mode.  Section D's lag check is approximate on purpose.
"""
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
E_PATH = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19e.bin')
ROM = open(ROM_PATH, 'rb').read()
RNG = random.Random(20261127)
NCHECK = 0
ENTRY = 0x0448F4
NAN = float('nan')
INF = float('inf')

# Every instruction address executed by any run of the SHIPPED image (section Z compares
# those bytes across the three bins).  Runs on in-memory ROM copies are not recorded.
EXECUTED_SHIPPED = set()
_orig_call = E.Emu.call


def _tracking_call(self, *a, **k):
    r = _orig_call(self, *a, **k)
    if self.rom is ROM or getattr(self, 'rom', None) == ROM:
        EXECUTED_SHIPPED.update(self.executed)
    return r


E.Emu.call = _tracking_call


def check(cond, msg):
    global NCHECK
    NCHECK += 1
    if not cond:
        raise AssertionError(msg)


def say(*a):
    print(*a)


def f32(x):
    return E.b2f(E.f2b(x))


TINY = 1.1754943508222875e-38   # 2^-126, the smallest NORMAL float32


def nu(x):
    """next float32 above x (x finite).  Above 0 it returns 2^-126: the SH-2E FPU has no
    denormals (DN = 1, sh2e_emu flushes them to signed zero), so the next usable value is
    the smallest normal."""
    b = E.f2b(x)
    if x == 0.0:
        return TINY
    return E.b2f(b + 1) if x > 0 else E.b2f(b - 1)


def nd(x):
    """next float32 below x (x finite); below 0 it returns -2^-126 (see nu)."""
    b = E.f2b(x)
    if x == 0.0:
        return -TINY
    return E.b2f(b - 1) if x > 0 else E.b2f(b + 1)


def calf(a, rom=ROM):
    return struct.unpack('>f', rom[a:a + 4])[0]


def calw(a, rom=ROM):
    return struct.unpack('>H', rom[a:a + 2])[0]


def calb(a, rom=ROM):
    return rom[a]


def patched(changes):
    r = bytearray(ROM)
    for a, bs in changes.items():
        r[a:a + len(bs)] = bs
    return bytes(r)


# ---------------------------------------------------------------- inputs
# (address, kind, baseline value, edge values).  Baseline = every gate clear.
C_ECT = calf(0x0D2E08)      # 60.0
C_KCA = calf(0x0D2EDC)      # 3.8
C_LO81 = calf(0x0D2E10)     # 0xBDCCCCCC = -0.099999994 (NOT the float32 nearest -0.1)
C_HI81 = calf(0x0D2E14)     # 0x3DCCCCCC = +0.099999994 (NOT the float32 nearest +0.1)
M01F = E.b2f(0xBDCCCCCD)    # the IEEE float32 nearest -0.1 (-0.1000000015), one step below C_LO81
P01F = E.b2f(0x3DCCCCCD)    # the IEEE float32 nearest +0.1 (+0.1000000015), one step above C_HI81
C_RPMLO = calf(0x0D2F6C)    # 1500
C_RPMHI = calf(0x0D2F70)    # 1600
C_V79LO = calf(0x0CC21C)    # 10000
C_V79HI = calf(0x0CC220)    # 10000
W1 = 0.3515625
W2 = 0.00390625
W3 = 0.0078125
W4 = 1.52587890625e-05      # 2^-16

INPUTS = [
    (0xFFFF9714, 'b', 0, [0, 1, 2, 0x80, 0xFF]),
    (0xFFFF970D, 'b', 0, [0, 1, 2, 0x80, 0xFF]),
    (0xFFFF6350, 'f', 90.0, [C_ECT, nd(C_ECT), nu(C_ECT), -40.0, 0.0, NAN, INF, -INF]),
    (0xFFFF803C, 'f', 0.0, [W1, nu(W1), -W1, nd(-W1), nd(W1), 1.0, -5.0, NAN]),
    (0xFFFF7A20, 'f', 0.0, [W2, nu(W2), -W2, nd(-W2), 0.1, 0.2, NAN]),
    (0xFFFF5BE2, 'b', 0, [0, 1, 2, 0xFF]),
    (0xFFFF8240, 'w', 100, [0, 12, 13, 14, 0x7FFF, 0x8000, 0xFFFF]),
    (0xFFFF3244, 'b', 1, [0, 1, 2, 3, 0xFE, 0xFF]),
    (0xFFFF8277, 'b', 1, [0, 1, 2, 0xFF]),
    (0xFFFF8258, 'f', 5.0, [C_KCA, nd(C_KCA), nu(C_KCA), 0.0, 7.3828125, NAN]),
    (0xFFFF829E, 'b', 1, [0, 1, 2, 0xFF]),
    (0xFFFF6624, 'f', 3000.0, [C_RPMLO, nd(C_RPMLO), C_RPMHI, nd(C_RPMHI), 1550.0, 0.0, 7000.0, NAN]),
    (0xFFFF824D, 'b', 0, [0, 1, 2, 0xFF]),
    (0xFFFF65F3, 'b', 1, [0, 1, 2, 3, 4, 5, 0xFF]),
    (0xFFFF7E90, 'f', 10.0, [0.0, -0.0, nd(0.0), -5.0, 5.0, NAN]),
    (0xFFFF7E94, 'f', 10.0, [0.0, -0.0, nd(0.0), -5.0, 5.0, NAN]),
    (0xFFFF7E98, 'f', 10.0, [0.0, -0.0, nd(0.0), -5.0, 5.0, NAN]),
    (0xFFFF7E9C, 'f', 10.0, [0.0, -0.0, nd(0.0), -5.0, 5.0, NAN]),
    (0xFFFF9124, 'b', 0, [0, 1, 2, 0xFF]),
    (0xFFFF9125, 'b', 0, [0, 1, 2, 0xFF]),
    (0xFFFF36E8, 'b', 1, [0, 1, 2, 0xFF]),
    (0xFFFF81F8, 'f', 0.0, [C_LO81, nd(C_LO81), nu(C_LO81), C_HI81, nd(C_HI81), nu(C_HI81), M01F, P01F,
                            NAN]),
    (0xFFFF7D18, 'b', 0, [0, 1, 2, 0xFF]),
    (0xFFFF79C8, 'b', 0, [0, 1, 2, 0xFF]),
    (0xFFFF822C, 'b', 200, [0, 37, 38, 39, 0x7F, 0x80, 0xFF]),
    (0xFFFF822D, 'b', 0, [0, 10, 95, 98, 1, 0xFF]),
    (0xFFFF826C, 'f', 0.0, [W1, nd(W1), nu(W1), 1.0, NAN]),
    (0xFFFF8268, 'f', 0.0, [W1, nd(W1), nu(W1), 1.0, NAN]),
    (0xFFFF8214, 'f', 0.0, [W3, nu(W3), -W3, nd(-W3), 1.0, NAN]),
    (0xFFFF7BE2, 'b', 0, [0, 1, 2, 0xFF]),
    (0xFFFF726E, 'b', 0, [0, 1, 2, 0xFF]),
    (0xFFFF8F24, 'b', 0, [0, 1, 2, 0xFF]),
    (0xFFFF653C, 'f', 1.0, [2.0, nu(2.0), nd(2.0), 0.75, NAN]),
    (0xFFFF90A8, 'f', 0.0, [0.0, 1.0, W4, nu(W4), 1.0 - W4, nd(1.0 - W4), 0.5, 0.008, -0.0, 1.5,
                            -0.5, NAN]),
    (0xFFFF61F4, 'b', 0, [0, 0x20, 0xDF, 0xFF, 0x10]),
    (0xFFFF798C, 'f', 0.0, [0.0, -0.0, nu(0.0), 0.1, -0.1, NAN]),
    (0xFFFF8249, 'b', 0, [0, 62, 63, 64, 0x7F, 0x80, 0xFF]),
    (0xFFFF79A8, 'f', 0.0, [C_V79HI, nd(C_V79HI), 20000.0, NAN, INF]),
    (0xFFFF8253, 'b', 0, [0, 1, 2]),
]
ADDR = {a: (k, b, ed) for a, k, b, ed in INPUTS}
BASE = {a: b for a, k, b, ed in INPUTS}
# cells the function must read on every path from the baseline
ALWAYS_READ = {0xFFFF6624, 0xFFFF6350, 0xFFFF9714, 0xFFFF970D, 0xFFFF7A20, 0xFFFF653C, 0xFFFF90A8,
               0xFFFF5BE2, 0xFFFF9124, 0xFFFF9125, 0xFFFF7D18, 0xFFFF65F3, 0xFFFF3244, 0xFFFF826C,
               0xFFFF81F8, 0xFFFF822C, 0xFFFF36E8, 0xFFFF79C8, 0xFFFF726E, 0xFFFF7BE2, 0xFFFF8F24,
               0xFFFF61F4, 0xFFFF798C, 0xFFFF79A8, 0xFFFF803C, 0xFFFF8214}


def poke(e, a, kind, v):
    """write an input WITHOUT marking it initialised (so the read is recorded)."""
    o = a - E.RAM_LO
    if kind == 'b':
        e.ram[o] = v & 0xFF
    elif kind == 'w':
        e.ram[o:o + 2] = (v & 0xFFFF).to_bytes(2, 'big')
    else:
        e.ram[o:o + 4] = E.f2b(v).to_bytes(4, 'big')


def run(state, rom=ROM):
    e = E.Emu(rom)
    for a, v in state.items():
        poke(e, a, ADDR[a][0], v)
    e.steps = 0
    r = e.call(ENTRY)
    check(r == 'return', 'did not return')
    out = {
        0xFFFF8234: e.ram[0xFFFF8234 - E.RAM_LO],
        0xFFFF8249: e.ram[0xFFFF8249 - E.RAM_LO],
        0xFFFF824D: e.ram[0xFFFF824D - E.RAM_LO],
        0xFFFF8253: e.ram[0xFFFF8253 - E.RAM_LO],
    }
    reads = {a & ~0 for a in e.uninit_reads}
    writes = {a for a in e.writes if not (E.STACK_TOP - 0x200 <= a < E.STACK_TOP)}
    return out, reads, writes, e


def out_window(x, c, w):
    lo, hi = c - w, c + w
    check(f32(lo) == lo and f32(hi) == hi, 'window limits not exact in float32')
    return 1 if (lo > x or x > hi) else 0


def model(s, rom=ROM):
    """the contract of 0x0448F4, written from the bytes (see the analysis file)."""
    b = lambda a: s[a] & 0xFF
    f = lambda a: s[a]
    out = {}
    # 0x0457D2: [824D] hysteresis on [6624]
    x = f(0xFFFF6624)
    if calf(0x0D2F6C, rom) > x:
        d = 1
    elif not (calf(0x0D2F70, rom) > x):
        d = 0
    else:
        d = b(0xFFFF824D)
    out[0xFFFF824D] = d
    # 0x0457F4: [8253] on [79A8]
    v = f(0xFFFF79A8)
    if not (calf(0x0CC220, rom) > v):
        e53 = 1
    elif calf(0x0CC21C, rom) > v:
        e53 = 0
    else:
        e53 = b(0xFFFF8253)
    out[0xFFFF8253] = e53
    # [8249] cleared when [798C] is not > 0
    p = f(0xFFFF798C)
    out[0xFFFF8249] = b(0xFFFF8249) if p > 0.0 else 0
    # fr13 selected by [65F3]
    k = b(0xFFFF65F3)
    fr13 = {1: f(0xFFFF7E90), 2: f(0xFFFF7E94), 3: f(0xFFFF7E98), 4: f(0xFFFF7E9C)}.get(k, 0.0)
    r11 = b(0xFFFF3244) & 1
    r13 = 1 if (b(0xFFFF9124) == 1 or b(0xFFFF9125) == 1 or b(0xFFFF36E8) == 0) else 0
    w = f(0xFFFF90A8)
    r14 = 1 if (out_window(w, 1.0, W4) and out_window(w, 0.0, W4)) else 0
    g = []
    g.append(b(0xFFFF9714) != 0)                                         # G1
    g.append(b(0xFFFF970D) != 0)                                         # G2
    g.append(calf(0x0D2E08, rom) > f(0xFFFF6350))                        # G3
    g.append(out_window(f(0xFFFF803C), 0.0, W1) == 1)                    # G4
    g.append(out_window(f(0xFFFF7A20), 0.0, W2) == 1)                    # G5
    g.append(b(0xFFFF5BE2) == 1 and not ((s[0xFFFF8240] & 0xFFFF) > calw(0x0D29E0, rom)))   # G6
    g.append(r11 == 0 and (b(0xFFFF8277) == 0 or calf(0x0D2EDC, rom) > f(0xFFFF8258)))     # G7
    g.append(r11 == 1 and b(0xFFFF829E) == 0)                            # G8
    g.append(d == 1 and not (calf(0x0D2E0C, rom) > fr13))                # G9
    g.append(r13 == 1)                                                   # G10
    g.append(calf(0x0D2E10, rom) > f(0xFFFF81F8))                        # G11
    g.append(not (calf(0x0D2E14, rom) > f(0xFFFF81F8)))                  # G12
    g.append(b(0xFFFF7D18) == 1)                                         # G13
    g.append(calb(0x0D2997, rom) == 90 and
             (b(0xFFFF79C8) == 1 or b(0xFFFF822C) < calb(0x0D2998, rom)))  # G14
    m = b(0xFFFF822D)
    g.append(m == 10 and not (W1 > f(0xFFFF826C)))                       # G15
    g.append(m == 98 and not (W1 > f(0xFFFF8268)))                       # G16
    g.append(m in (0, 95) and not (W1 > f(0xFFFF826C)) and out_window(f(0xFFFF8214), 0.0, W3) == 1)  # G17
    g.append(b(0xFFFF7BE2) == 1)                                         # G18
    g.append(b(0xFFFF726E) == 1)                                         # G19
    g.append(f(0xFFFF653C) > calf(0x0D2DBC, rom))                        # G20
    g.append(r14 == 1)                                                   # G21
    g.append(b(0xFFFF8F24) == 1)                                         # G22
    g.append((b(0xFFFF61F4) & 0x20) != 0)                                # G23
    if any(g):
        res = 1
    elif not (p > 0.0):
        res = 0
    elif not (b(0xFFFF8249) >= calb(0x0D2999, rom)):
        res = 1
    elif e53 == 1 and calb(0x0D299A, rom) == 90:
        res = 1
    else:
        res = 0
    out[0xFFFF8234] = res
    return out, g


def compare(state, rom=ROM, tag=''):
    got, reads, writes, e = run(state, rom)
    want, g = model(state, rom)
    for a in want:
        check(got[a] == want[a], f'{tag} {a:08X}: ROM {got[a]} model {want[a]} state {fmt(state)}')
    allowed = {0xFFFF8234, 0xFFFF824D, 0xFFFF8253, 0xFFFF8249}
    check(writes <= allowed, f'{tag} unexpected writes {sorted(hex(a) for a in writes - allowed)}')
    check(0xFFFF8234 in writes, f'{tag} [8234] not written')
    check((0xFFFF8249 in writes) == (not (state[0xFFFF798C] > 0.0)), f'{tag} [8249] write rule')
    ins = set()
    for a in reads:
        for base in ADDR:
            n = {'b': 1, 'w': 2, 'f': 4}[ADDR[base][0]]
            if base <= a < base + n:
                ins.add(base)
                break
        else:
            check(False, f'{tag} read of an undeclared RAM cell {a:08X}')
    return got, want, g, ins, e


def fmt(state):
    return {hex(a): v for a, v in state.items() if v != BASE[a] or (isinstance(v, float) and v != v)}


# ================================================================= A  callees
def sec_A():
    say('\n==== A. callees ====')
    for entry, cell, rule in ((0x0298C8, 0xFFFF9714, lambda v: 2 if v else 0),
                              (0x029848, 0xFFFF970D, lambda v: 2 if v else 0),
                              (0x02F8FE, 0xFFFF726E, lambda v: 1 if v == 1 else 0),
                              (0x01CF2E, 0xFFFF61F4, lambda v: 1 if v & 0x20 else 0)):
        for v in range(256):
            e = E.Emu(ROM)
            e.ram_u8(cell, v)
            e.call(entry)
            check(e.R[0] == rule(v), f'{entry:06X} {v}')
            check(not e.writes, f'{entry:06X} writes')
    say('  0x0298C8 r0 = 2 if byte [9714] != 0 else 0; 0x029848 same on [970D]; 0x02F8FE r0 = 1 iff [726E] == 1;')
    say('  0x01CF2E r0 = 1 iff bit 5 (0x20) of [61F4] is set.  All 256 values each, no RAM written.')
    # 0x0457D2
    xs = [0.0, nd(C_RPMLO), C_RPMLO, nu(C_RPMLO), 1550.0, nd(C_RPMHI), C_RPMHI, nu(C_RPMHI), 7000.0,
          -1.0, NAN, INF, -INF]
    rows = []
    for x in xs:
        for prev in (0, 1, 7):
            e = E.Emu(ROM)
            e.ram_u8(0xFFFF824D, prev)
            e.call(0x0457D2, fregs={4: x})
            want = 1 if C_RPMLO > x else (0 if not (C_RPMHI > x) else prev)
            got = e.read_u8(0xFFFF824D)
            check(got == want, f'0457D2 {x} {prev}')
            check(set(e.writes) <= {0xFFFF824D}, '0457D2 writes')
            check((0xFFFF824D in e.writes) == (C_RPMLO > x or not (C_RPMHI > x)), '0457D2 write rule')
        rows.append(f'{x:g}->{"1" if C_RPMLO > x else ("0" if not (C_RPMHI > x) else "held")}')
    say(f'  0x0457D2 [824D] on fr4 (limits {C_RPMLO:g}/{C_RPMHI:g}): ' + ', '.join(rows))
    vs = [0.0, nd(C_V79HI), C_V79HI, nu(C_V79HI), 20000.0, -1.0, NAN, INF, -INF]
    rows = []
    for v in vs:
        for prev in (0, 1, 7):
            e = E.Emu(ROM)
            e.ram_u8(0xFFFF8253, prev)
            e.ram_f32(0xFFFF79A8, v)
            e.call(0x0457F4)
            want = 1 if not (C_V79HI > v) else (0 if C_V79LO > v else prev)
            check(e.read_u8(0xFFFF8253) == want, f'0457F4 {v} {prev}')
            check(set(e.writes) <= {0xFFFF8253}, '0457F4 writes')
            # equal limits (10000 / 10000): one of the two stores always runs
            check(C_V79LO == C_V79HI and 0xFFFF8253 in e.writes, f'0457F4 did not write [8253] for {v}')
        rows.append(f'{v:g}->{1 if not (C_V79HI > v) else 0}')
    say(f'  0x0457F4 [8253] on [79A8] (limits {C_V79LO:g}/{C_V79HI:g}, equal as shipped -> no held band, '
        '[8253] written on every call): ' + ', '.join(rows))


# ================================================================= B  whole function
GATE_NAMES = ['G1 [9714]!=0', 'G2 [970D]!=0', 'G3 [6350]<60', 'G4 |[803C]|>0.3515625',
              'G5 |[7A20]|>2^-8', 'G6 [5BE2]==1 & [8240]<=13', 'G7 bit0([3244])==0 & ([8277]==0 | [8258]<3.8)',
              'G8 bit0([3244])==1 & [829E]==0', 'G9 [824D]==1 & fr13>=0', 'G10 [9124]==1|[9125]==1|[36E8]==0',
              'G11 [81F8]<0xBDCCCCCC', 'G12 !([81F8]<0x3DCCCCCC)', 'G13 [7D18]==1',
              'G14 [79C8]==1 | [822C]<38',
              'G15 [822D]==10 & !(W>[826C])', 'G16 [822D]==98 & !(W>[8268])',
              'G17 [822D] in {0,95} & !(W>[826C]) & |[8214]|>2^-7', 'G18 [7BE2]==1', 'G19 [726E]==1',
              'G20 [653C]>2.0', 'G21 [90A8] not within 2^-16 of 0 or 1', 'G22 [8F24]==1',
              'G23 bit5([61F4])', ]


def sec_B():
    say('\n==== B. 0x0448F4 whole function vs model ====')
    executed = set()
    got, want, g, ins, e = compare(dict(BASE), tag='B1')
    executed |= e.executed
    check(got[0xFFFF8234] == 0 and not any(g), 'baseline must give 0')
    check(ALWAYS_READ <= ins, f'B1 inputs not read: {sorted(hex(a) for a in ALWAYS_READ - ins)}')
    say(f'  B1 baseline: [8234] = 0; cells read on the baseline path: {len(ins)}')
    # B2: each gate alone, with edges
    cases = [
        ({0xFFFF9714: 1}, 1), ({0xFFFF9714: 0x80}, 1), ({0xFFFF970D: 2}, 1),
        ({0xFFFF6350: nd(C_ECT)}, 1), ({0xFFFF6350: C_ECT}, 0), ({0xFFFF6350: NAN}, 0), ({0xFFFF6350: -INF}, 1),
        ({0xFFFF803C: W1}, 0), ({0xFFFF803C: nu(W1)}, 1), ({0xFFFF803C: -W1}, 0), ({0xFFFF803C: nd(-W1)}, 1),
        ({0xFFFF803C: NAN}, 0),
        ({0xFFFF7A20: W2}, 0), ({0xFFFF7A20: nu(W2)}, 1), ({0xFFFF7A20: 0.1}, 1), ({0xFFFF7A20: nd(-W2)}, 1),
        ({0xFFFF5BE2: 1, 0xFFFF8240: 13}, 1), ({0xFFFF5BE2: 1, 0xFFFF8240: 14}, 0),
        ({0xFFFF5BE2: 1, 0xFFFF8240: 0}, 1), ({0xFFFF5BE2: 2, 0xFFFF8240: 0}, 0),
        ({0xFFFF5BE2: 1, 0xFFFF8240: 0xFFFF}, 0),
        ({0xFFFF3244: 0, 0xFFFF8277: 0}, 1), ({0xFFFF3244: 0, 0xFFFF8277: 2}, 0),
        ({0xFFFF3244: 0, 0xFFFF8258: nd(C_KCA)}, 1), ({0xFFFF3244: 0, 0xFFFF8258: C_KCA}, 0),
        ({0xFFFF3244: 0, 0xFFFF8258: NAN}, 0), ({0xFFFF3244: 0, 0xFFFF829E: 0}, 0),
        ({0xFFFF3244: 1, 0xFFFF829E: 0}, 1), ({0xFFFF3244: 3, 0xFFFF829E: 2}, 0),
        ({0xFFFF3244: 1, 0xFFFF8277: 0, 0xFFFF8258: 0.0}, 0),
        ({0xFFFF6624: nd(C_RPMLO)}, 1), ({0xFFFF6624: C_RPMLO}, 0), ({0xFFFF6624: 1550.0, 0xFFFF824D: 1}, 1),
        ({0xFFFF6624: 1550.0, 0xFFFF824D: 0}, 0), ({0xFFFF6624: nd(C_RPMHI), 0xFFFF824D: 1}, 1),
        ({0xFFFF6624: C_RPMHI, 0xFFFF824D: 1}, 0),
        ({0xFFFF6624: 1000.0, 0xFFFF7E90: nd(0.0)}, 0), ({0xFFFF6624: 1000.0, 0xFFFF7E90: -0.0}, 1),
        ({0xFFFF6624: 1000.0, 0xFFFF7E90: NAN}, 1), ({0xFFFF6624: 1000.0, 0xFFFF65F3: 0}, 1),
        ({0xFFFF6624: 1000.0, 0xFFFF65F3: 3, 0xFFFF7E90: -1.0, 0xFFFF7E94: -1.0, 0xFFFF7E98: -1.0,
          0xFFFF7E9C: 5.0}, 0),
        ({0xFFFF6624: 1000.0, 0xFFFF65F3: 4, 0xFFFF7E90: -1.0, 0xFFFF7E94: -1.0, 0xFFFF7E98: -1.0,
          0xFFFF7E9C: 5.0}, 1),
        ({0xFFFF9124: 1}, 1), ({0xFFFF9125: 1}, 1), ({0xFFFF36E8: 0}, 1), ({0xFFFF36E8: 0x80}, 0),
        ({0xFFFF9124: 2, 0xFFFF9125: 0xFF}, 0),
        ({0xFFFF81F8: C_LO81}, 0), ({0xFFFF81F8: nd(C_LO81)}, 1), ({0xFFFF81F8: nd(C_HI81)}, 0),
        ({0xFFFF81F8: C_HI81}, 1), ({0xFFFF81F8: NAN}, 1),
        # review C14: the IEEE -0.1f lies BELOW the stored lower word, so it fires G11;
        # the IEEE +0.1f lies above the stored upper word, so it fires G12.
        ({0xFFFF81F8: M01F}, 1), ({0xFFFF81F8: P01F}, 1), ({0xFFFF81F8: nu(C_LO81)}, 0),
        ({0xFFFF7D18: 1}, 1), ({0xFFFF7D18: 2}, 0),
        ({0xFFFF79C8: 1}, 1), ({0xFFFF822C: 37}, 1), ({0xFFFF822C: 38}, 0), ({0xFFFF822C: 0x80}, 0),
        ({0xFFFF822D: 10, 0xFFFF826C: W1}, 1), ({0xFFFF822D: 10, 0xFFFF826C: nd(W1)}, 0),
        ({0xFFFF822D: 98, 0xFFFF8268: W1}, 1), ({0xFFFF822D: 98, 0xFFFF8268: nd(W1)}, 0),
        ({0xFFFF822D: 0, 0xFFFF826C: W1, 0xFFFF8214: nu(W3)}, 1),
        ({0xFFFF822D: 0, 0xFFFF826C: W1, 0xFFFF8214: W3}, 0),
        ({0xFFFF822D: 95, 0xFFFF826C: W1, 0xFFFF8214: nd(-W3)}, 1),
        ({0xFFFF822D: 1, 0xFFFF826C: W1, 0xFFFF8214: 1.0}, 0),
        ({0xFFFF822D: 0, 0xFFFF826C: nd(W1), 0xFFFF8214: 1.0}, 0),
        # review C17: the three [822D] gates are "not (0.3515625 > x)", so NaN passes each;
        # a NaN in [8214] makes 0x0BE608 return 0 (inside), so G17 then fails.
        ({0xFFFF822D: 10, 0xFFFF826C: NAN}, 1), ({0xFFFF822D: 98, 0xFFFF8268: NAN}, 1),
        ({0xFFFF822D: 0, 0xFFFF826C: NAN, 0xFFFF8214: 1.0}, 1),
        ({0xFFFF822D: 95, 0xFFFF826C: NAN, 0xFFFF8214: 1.0}, 1),
        ({0xFFFF822D: 0, 0xFFFF826C: W1, 0xFFFF8214: NAN}, 0),
        ({0xFFFF7BE2: 1}, 1), ({0xFFFF726E: 1}, 1), ({0xFFFF726E: 2}, 0),
        ({0xFFFF653C: 2.0}, 0), ({0xFFFF653C: nu(2.0)}, 1),
        ({0xFFFF90A8: 1.0}, 0), ({0xFFFF90A8: W4}, 0), ({0xFFFF90A8: nu(W4)}, 1), ({0xFFFF90A8: 1.0 - W4}, 0),
        ({0xFFFF90A8: nd(1.0 - W4)}, 1), ({0xFFFF90A8: 0.5}, 1), ({0xFFFF90A8: NAN}, 0),
        ({0xFFFF90A8: -0.5}, 1), ({0xFFFF90A8: 1.5}, 1),
        ({0xFFFF8F24: 1}, 1), ({0xFFFF61F4: 0x20}, 1), ({0xFFFF61F4: 0xDF}, 0),
        ({0xFFFF798C: nu(0.0), 0xFFFF8249: 62}, 1), ({0xFFFF798C: nu(0.0), 0xFFFF8249: 63}, 0),
        ({0xFFFF798C: 0.1, 0xFFFF8249: 0xFF}, 0), ({0xFFFF798C: 0.1, 0xFFFF8249: 0x80}, 0),
        ({0xFFFF798C: -0.0, 0xFFFF8249: 5}, 0), ({0xFFFF798C: NAN, 0xFFFF8249: 5}, 0),
        ({0xFFFF798C: 0.1, 0xFFFF8249: 63, 0xFFFF79A8: 20000.0}, 0),
    ]
    for ch, want_res in cases:
        st = dict(BASE)
        st.update(ch)
        got, want, g, ins, e = compare(st, tag='B2')
        executed |= e.executed
        check(got[0xFFFF8234] == want_res, f'B2 {fmt(st)} expected {want_res} got {got[0xFFFF8234]}')
    say(f'  B2 single-gate cases incl. float32 neighbours of each limit: {len(cases)} (expected value asserted)')
    check(E.f2b(C_LO81) == 0xBDCCCCCC and E.f2b(C_HI81) == 0x3DCCCCCC, 'G11 / G12 calibration words')
    check(M01F < C_LO81 and P01F > C_HI81, 'IEEE +-0.1f lie outside the stored words')
    say(f'     G11 / G12 words: [0x0D2E10] = 0x{E.f2b(C_LO81):08X} ({C_LO81!r}), [0x0D2E14] = 0x{E.f2b(C_HI81):08X}'
        f' ({C_HI81!r})')
    say('     [81F8] = 0xBDCCCCCC (the stored word) -> 0; 0xBDCCCCCD (IEEE -0.1f) -> 1 (G11); 0x3DCCCCCC -> 1;'
        ' 0x3DCCCCCD (IEEE +0.1f) -> 1; NaN -> 1 (G12)')
    say('     G15 / G16 / G17 with NaN in [826C] / [8268] -> 1; G17 with NaN in [8214] -> 0')
    n = 0
    for a, kind, base, edges in INPUTS:
        if kind != 'b':
            continue
        for v in range(256):
            st = dict(BASE)
            st[a] = v
            got, want, g, ins, e = compare(st, tag='B3')
            executed |= e.executed
            n += 1
    say(f'  B3 every byte input over all 256 values on the baseline: {n} runs')
    ones = 0
    counts = [0] * 23
    for i in range(30000):
        st = dict(BASE)
        for a, kind, base, edges in INPUTS:
            if RNG.random() < 0.12:
                st[a] = RNG.choice(edges)
        got, want, g, ins, e = compare(st, tag='B4')
        executed |= e.executed
        ones += got[0xFFFF8234]
        for j, x in enumerate(g):
            counts[j] += bool(x)
    for i in range(6000):
        st = {}
        for a, kind, base, edges in INPUTS:
            st[a] = RNG.choice(edges + [base])
        got, want, g, ins, e = compare(st, tag='B4r')
        executed |= e.executed
        ones += got[0xFFFF8234]
    say(f'  B4 36,000 random states (30,000 perturbed + 6,000 fully random): model == ROM on all four bytes,')
    say(f'     write set and read set; [8234] = 1 in {ones} of them.  Gate hit counts (perturbed set):')
    for j, nm in enumerate(GATE_NAMES):
        check(counts[j] > 0, f'gate {nm} never exercised')
    say('     ' + ', '.join(f'G{j + 1}:{c}' for j, c in enumerate(counts)))
    body = [a for a in range(ENTRY, 0x044CEA, 2)]
    pools = set(range(0x044A60, 0x044B0C, 2))
    insns = [a for a in body if a not in pools]
    check(len(insns) == 421, f'instruction count {len(insns)}')
    missing = [a for a in insns if a not in executed]
    check(not missing, f'not executed: {[hex(a) for a in missing]}')
    say(f'  B5 all {len(insns)} instructions of 0x0448F4..0x044CE8 executed by B1-B4')
    # B6 (review, missed item): 0x0457F4 runs at 0x0449E6, before the tail reads [8253] at 0x044CAE, and
    # with equal limits it writes [8253] on every call -- so the byte's prior value never matters.
    r90 = patched({0x0D299A: b'\x5a'})
    vals = [0.0, nd(C_V79HI), C_V79HI, 20000.0, NAN, INF]
    for rom, tag in ((ROM, 'shipped'), (r90, 'copy 0x0D299A=90')):
        for v in vals:
            res = set()
            for prior in (0, 1, 0x5A, 0xFF):
                st = dict(BASE)
                st.update({0xFFFF798C: 0.1, 0xFFFF8249: 63, 0xFFFF79A8: v, 0xFFFF8253: prior})
                got, reads, writes, e = run(st, rom)
                check(0xFFFF8253 in writes, f'B6 {tag} [8253] not written for [79A8] = {v}')
                res.add((got[0xFFFF8234], got[0xFFFF8253]))
            check(len(res) == 1, f'B6 {tag} prior [8253] matters for [79A8] = {v}: {res}')
    say('  B6 [8253] prior in {0, 1, 0x5A, 0xFF} x [79A8] in {0, 10000-, 10000, 20000, NaN, inf}, with the tail')
    say('     reached ([798C] > 0, [8249] = 63): identical [8234] and [8253], and [8253] always written -- in the')
    say('     shipped image and in a copy with [0x0D299A] = 90.  The pre-call [8253] is not an effective input.')


# ================================================================= C  ROM copies
def sec_C():
    say('\n==== C. in-memory ROM copies (calibration levers the shipped bins do not pull) ====')
    r1 = patched({0x0D2997: b'\x00'})
    for ch, want_res in (({0xFFFF79C8: 1}, 0), ({0xFFFF822C: 0}, 0), ({0xFFFF822C: 0, 0xFFFF7D18: 1}, 1)):
        st = dict(BASE); st.update(ch)
        got, want, g, ins, e = compare(st, rom=r1, tag='C1')
        check(got[0xFFFF8234] == want_res, 'C1')
    say('  C1 [0x0D2997] = 0 (not 90): [79C8] == 1 and [822C] < 38 no longer set [8234]')
    r2 = patched({0x0D299A: b'\x5a'})
    for ch, want_res in (({0xFFFF798C: 0.1, 0xFFFF8249: 63, 0xFFFF79A8: 20000.0}, 1),
                         ({0xFFFF798C: 0.1, 0xFFFF8249: 63, 0xFFFF79A8: nd(C_V79HI)}, 0),
                         ({0xFFFF798C: 0.0, 0xFFFF8249: 63, 0xFFFF79A8: 20000.0}, 0)):
        st = dict(BASE); st.update(ch)
        got, want, g, ins, e = compare(st, rom=r2, tag='C2')
        check(got[0xFFFF8234] == want_res, f'C2 {ch}')
    say('  C2 [0x0D299A] = 90: with [798C] > 0 and [8249] >= 63, [79A8] >= 10000 sets [8234] (dead as shipped)')
    r3 = patched({0x0D2DBC: struct.pack('>f', 1.5)})
    for ch, want_res in (({0xFFFF653C: 1.6}, 1), ({0xFFFF653C: 1.5}, 0)):
        st = dict(BASE); st.update(ch)
        got, want, g, ins, e = compare(st, rom=r3, tag='C3')
        check(got[0xFFFF8234] == want_res, 'C3')
    say('  C3 [0x0D2DBC] = 1.5: [653C] = 1.6 sets [8234] (as shipped 2.0 = the writer\'s upper clamp, never exceeded)')


# ================================================================= D  writers
def sec_D():
    say('\n==== D. writers of inputs, emulated ====')
    # 0x044D12
    for b5 in (0, 1, 2, 0xFF):
        for w0 in (0, 1, 13, 0xFFFE, 0xFFFF):
            for p in (0.0, -0.0, nu(0.0), 0.5, -1.0, NAN):
                for c0 in (0, 1, 62, 63, 0xFE, 0xFF):
                    e = E.Emu(ROM)
                    e.ram_u8(0xFFFF5BE2, b5); e.ram_u16(0xFFFF8240, w0); e.ram_f32(0xFFFF798C, p)
                    e.ram_u8(0xFFFF8249, c0)
                    e.call(0x044D12)
                    ww = 0 if b5 == 0 else (w0 if w0 == 0xFFFF else w0 + 1)
                    cc = min(c0 + 1, 255) if p > 0.0 else 0
                    check(e.read_u16(0xFFFF8240) == ww, '044D12 8240')
                    check(e.read_u8(0xFFFF8249) == cc, '044D12 8249')
                    check(set(e.writes) <= {0xFFFF8240, 0xFFFF8241, 0xFFFF8249}, '044D12 writes')
    say('  0x044D12: u16 [8240] = 0 if [5BE2] == 0 else min([8240] + 1, 0xFFFF); '
        'u8 [8249] = min([8249] + 1, 255) if [798C] > 0 else 0   (720 cases)')
    # 0x044CEA
    for c8 in (0, 1, 2, 0xFF):
        for c0 in (0, 1, 37, 38, 0xFE, 0xFF):
            e = E.Emu(ROM)
            e.ram_u8(0xFFFF79C8, c8); e.ram_u8(0xFFFF822C, c0)
            e.call(0x044CEA)
            check(e.read_u8(0xFFFF822C) == (0 if c8 == 1 else min(c0 + 1, 255)), '044CEA')
            check(set(e.writes) <= {0xFFFF822C}, '044CEA writes')
    say('  0x044CEA: u8 [822C] = 0 if [79C8] == 1 else min([822C] + 1, 255)   (24 cases)')
    # 0x044DB0
    k = calf(0x0D2E18)
    mx = 0.0
    for L in (0.0, 0.3, 1.0, 2.5, 4.0):
        for old in (0.0, 0.3, 1.0, 2.5, 4.0, L + 1e-5):
            e = E.Emu(ROM)
            e.ram_f32(0xFFFF63F8, L); e.ram_f32(0xFFFF81F4, old)
            e.call(0x044DB0)
            lag = e.read_f32(0xFFFF81F4)
            hp = e.read_f32(0xFFFF81F8)
            ref = L if abs(L - (L + (1 - k) * (old - L))) < 2 ** -14 else L + (1 - k) * (old - L)
            check(abs(lag - ref) <= 1e-6 * max(1.0, abs(ref)), f'044DB0 lag {L} {old} {lag} {ref}')
            check(abs(hp - (L - lag)) <= 1e-6, '044DB0 hp')
            check(abs(hp - (1 - k) * (L - old)) <= 2e-6 or abs(L - old) * (1 - k) < 2 ** -14, '044DB0 hp form')
            mx = max(mx, abs(hp))
            check(set(e.writes) <= set(range(0xFFFF81F4, 0xFFFF81FC)), '044DB0 writes')
    say(f'  0x044DB0: [81F4] = lag([63F8], old [81F4], k = [0x0D2E18] = {k:g}, snap 2^-14); '
        f'[81F8] = [63F8] - [81F4] = {1 - k:g} * ([63F8] - old [81F4])  (30 cases, approximate on purpose)')
    # 0x044E04: [822D] = 0 every call with D299B = 0
    seen = set()
    for i in range(3000):
        e = E.Emu(ROM)
        for a in range(0xFFFF8200, 0xFFFF8260):
            e.ram_u8(a, RNG.choice((0, 1, 2, 0x5A, 0xFF, RNG.randrange(256))))
        for a in (0xFFFF6350, 0xFFFF6898, 0xFFFF3234, 0xFFFF8210):
            e.ram_f32(a, RNG.choice((-40.0, 0.0, 50.0, 90.0, 119.5, 120.0, 900.0, 1000.0, NAN)))
        for a in (0xFFFF726E, 0xFFFF3244, 0xFFFFAD44):
            e.ram_u8(a, RNG.randrange(256))
        e.call(0x044E04)
        check(e.read_u8(0xFFFF822D) == 0, '044E04 822D != 0 with D299B = 0')
    rp = patched({0x0D299B: b'\x01'})
    for i in range(3000):
        e = E.Emu(rp)
        for a in range(0xFFFF8200, 0xFFFF8260):
            e.ram_u8(a, RNG.choice((0, 1, 2, 0xFF, RNG.randrange(256))))
        for a in (0xFFFF6350, 0xFFFF6898, 0xFFFF3234):
            e.ram_f32(a, RNG.choice((-40.0, 0.0, 50.0, 90.0, 1000.0)))
        e.ram_f32(0xFFFF8210, RNG.choice((50.0, 119.5, 120.0)))
        e.ram_u8(0xFFFF726E, RNG.choice((0, 1))); e.ram_u8(0xFFFF3244, RNG.choice((0, 1)))
        e.ram_u8(0xFFFFAD44, RNG.choice((0, 1)))
        e.call(0x044E04)
        seen.add(e.read_u8(0xFFFF822D))
    check(seen <= {0, 10, 95, 98} and {0, 95} <= seen, f'044E04 copy values {seen}')
    say(f'  0x044E04: [822D] = 0 in 3,000 random states with [0x0D299B] = 0 (shipped); a copy with [0x0D299B] = 1 '
        f'gives {sorted(seen)}\n            (10 / 98 also need [0x0D299D] / [0x0D299E] above 0, both 0 as shipped; not exercised)')
    # 0x045970
    for L in (0.0, 0.27, 1.0, 2.0, 2.56, 4.0, 5.0, NAN):
        for N in (0.0, 800.0, 3000.0, 7600.0, 9000.0):
            for w in (0.0, 0.5, 1.0):
                e = E.Emu(ROM)
                e.ram_f32(0xFFFF63F8, L); e.ram_f32(0xFFFF7F4C, N); e.ram_f32(0xFFFF90A8, w)
                for a in (0xFFFF8214, 0xFFFF8204, 0xFFFF821C, 0xFFFF8218):
                    e.ram_f32(a, 1.0)
                e.call(0x045970)
                v = e.read_f32(0xFFFF826C)
                check(v == 0.0, f'045970 826C {L} {N} {w} -> {v}')
                kc = e.read_f32(0xFFFF8258)
                check(0.0 <= kc <= 7.3828125, f'045970 8258 range {kc}')
                check(set(e.writes) <= set(range(0xFFFF8258, 0xFFFF825C)) | set(range(0xFFFF826C, 0xFFFF8270)),
                      f'045970 writes {sorted(hex(a) for a in e.writes)}')
    # [8258] blend: w = 0 equals the Cruise table, w = 1 the Non-Cruise table
    for L, N in ((1.0, 3000.0), (2.0, 4000.0), (0.5, 1200.0)):
        vals = []
        for w in (0.0, 1.0, 0.25):
            e = E.Emu(ROM)
            e.ram_f32(0xFFFF63F8, L); e.ram_f32(0xFFFF7F4C, N); e.ram_f32(0xFFFF90A8, w)
            e.call(0x045970)
            vals.append(e.read_f32(0xFFFF8258))
        ea = E.Emu(ROM); ea.call(0x0BE8E4, regs={4: 0x0AE680}, fregs={4: L, 5: N}); A = ea.fr(0)
        eb = E.Emu(ROM); eb.call(0x0BE8E4, regs={4: 0x0AE69C}, fregs={4: L, 5: N}); B = eb.fr(0)
        check(vals[0] == A and vals[1] == B, '045970 blend ends')
        check(abs(vals[2] - (0.75 * A + 0.25 * B)) <= 1e-5, '045970 blend middle')
    say('  0x045970: [826C] = 0.0 for 120 (load, [7F4C], [90A8]) points incl. NaN (table 0x0AE664 all zero); '
        '[8258] = (1 - [90A8]) * T(0x0AE680) + [90A8] * T(0x0AE69C) on ([63F8], [7F4C]); only [8258] and [826C] written')
    # NOT an accumulator (corrections item 80 says "fr9 = previous value ... fmac accumulates"): the result
    # does not depend on the old [8258], does not grow over repeated calls, and stays the blend even in a
    # ROM copy with [0x0D299B] = 1 (the product branch is then taken, but its gain [826C] is 0.0).
    rp = patched({0x0D299B: b'\x01'})
    for rom, tag in ((ROM, 'shipped'), (rp, 'copy 0x0D299B=1')):
        outs = set()
        for prior in (0.0, 99.0, -5.0, 7.0):
            e = E.Emu(rom)
            e.ram_f32(0xFFFF63F8, 2.0); e.ram_f32(0xFFFF7F4C, 4000.0); e.ram_f32(0xFFFF90A8, 0.25)
            for a in (0xFFFF8214, 0xFFFF8204, 0xFFFF821C, 0xFFFF8218):
                e.ram_f32(a, 3.0)
            e.ram_f32(0xFFFF8258, prior)
            seq = []
            for i in range(5):
                e.call(0x045970)
                seq.append(e.read_f32(0xFFFF8258))
            check(len(set(seq)) == 1, f'045970 {tag} drifts over calls {seq}')
            outs.add(seq[0])
        check(len(outs) == 1, f'045970 {tag} depends on the prior [8258]: {outs}')
    say('  0x045970: [8258] is the same for prior [8258] in {0, 99, -5, 7} and over 5 repeated calls, in the shipped')
    say('            image and in a copy with [0x0D299B] = 1 -- it is overwritten, not accumulated (contradicts item 80)')
    # 0x0459F6: no write of 8268 with D299B = 0
    for v in (0.0, 1.0, 5.0):
        e = E.Emu(ROM)
        e.ram_f32(0xFFFF8258, v); e.ram_f32(0xFFFF3234, 0.5); e.ram_f32(0xFFFF63F8, 1.0); e.ram_f32(0xFFFF7F4C, 3000.0)
        e.ram_f32(0xFFFF8268, 9.0)
        e.call(0x0459F6)
        check(set(e.writes) == set(range(0xFFFF8260, 0xFFFF8264)), f'0459F6 writes {sorted(hex(a) for a in e.writes)}')
        check(abs(e.read_f32(0xFFFF8260) - v * 0.5) < 1e-6 and e.read_f32(0xFFFF8268) == 9.0, '0459F6 values')
    say('  0x0459F6: with [0x0D299B] = 0 it writes only [8260] = [8258] * [3234]; [8268] is never written')
    # 0x045A3E / 0x0467AE window ANDs
    for entry, cell, rlim, llim in ((0x045A3E, 0xFFFF8277, (1800.0, 6550.0), (1.0, 3.95)),
                                    (0x0467AE, 0xFFFF829E, (1600.0, 6300.0), (1.3, 3.45))):
        for rpm in (500.0, rlim[0] - 1.0, rlim[0] + 1.0, 4000.0, rlim[1] - 1.0, rlim[1] + 100.0):
            for load in (0.5, llim[0] - 0.01, llim[0] + 0.01, 2.0, llim[1] - 0.01, llim[1] + 0.1):
                for prev in (0, 1):
                    e = E.Emu(ROM)
                    e.ram_f32(0xFFFF6624, rpm); e.ram_f32(0xFFFF63F8, load)
                    base = cell + (0x10 if cell == 0xFFFF8277 else 0x0F)
                    for i in range(4):
                        e.ram_u8(base + i, prev)
                    e.call(entry)
                    inside = rlim[0] <= rpm < rlim[1] and llim[0] <= load < llim[1]
                    if inside:
                        check(e.read_u8(cell) == 1, f'{entry:06X} inside {rpm} {load}')
                    elif not (rlim[0] - 100.0 <= rpm <= rlim[1] + 50.0) or not (llim[0] - 0.05 <= load <= llim[1] + 0.05):
                        check(e.read_u8(cell) == 0, f'{entry:06X} outside {rpm} {load}')
    say('  0x045A3E: [8277] = 1 inside the RPM 1800..6550 / load 1.0..3.95 window (0x045F9A, hysteresis bands');
    say('            1700/1800, 6550/6600, 0.95/1.0, 3.95/4.0); 0x0467AE: [829E] the same on 1600..6300 / 1.3..3.45')
    # 0x044300 init
    e = E.Emu(ROM)
    e.ram_f32(0xFFFF6364, 25.0)
    e.call(0x044300)
    check(e.read_u8(0xFFFF822C) == 0xFF and e.read_u8(0xFFFF8253) == 0 and e.read_u8(0xFFFF8248) == 2, '044300')
    check(e.read_f32(0xFFFF8210) == 25.0, '044300 8210')
    say('  0x044300 (init list 0x047C40): [822C] = 255, [8248] = 2, [8253] = 0, [8210] = [6364]')


# ================================================================= S  sequence
def sec_S():
    say('\n==== S. sequence 0x044D12 then 0x0448F4, [798C] > 0, every other gate clear ====')
    e = E.Emu(ROM)
    st = dict(BASE)
    st[0xFFFF798C] = 0.2
    st[0xFFFF8249] = 0
    for a, v in st.items():
        k = ADDR[a][0]
        if k == 'b':
            e.ram_u8(a, v)
        elif k == 'w':
            e.ram_u16(a, v)
        else:
            e.ram_f32(a, v)
    seq = []
    for i in range(70):
        e.steps = 0
        e.call(0x044D12)
        e.steps = 0
        e.call(ENTRY)
        seq.append(e.read_u8(0xFFFF8234))
    first0 = seq.index(0)
    check(first0 == 62 and all(seq[:62]) and not any(seq[62:]), f'sequence {seq}')
    e.ram_f32(0xFFFF798C, 0.0)
    e.call(0x044D12); e.call(ENTRY)
    check(e.read_u8(0xFFFF8249) == 0 and e.read_u8(0xFFFF8234) == 0, 'reset')
    e.ram_f32(0xFFFF798C, 0.2)
    e.call(0x044D12); e.call(ENTRY)
    check(e.read_u8(0xFFFF8234) == 1, 'restart')
    say(f'  [8234] per step: 1 x {first0}, then 0 (step {first0 + 1} sees [8249] = 63); [798C] = 0 clears [8249]; '
        'the next positive step gives 1 again')


# ================================================================= E  consumer
FBKC_BASE = {
    # every RAM input of 0x04438C that a decision depends on, set explicitly (E1 baseline):
    # window open, no head exit, no side path, blocks A / B / C not selected.
    ('f', 0xFFFF63F8): 2.0,      # load -> 0x0456E0: [824A] = 0 (not below 0.95)
    ('f', 0xFFFF6624): 3000.0,   # engine speed -> 0x04578C: [824B] = [824C] = 1 (1200..6000)
    ('f', 0xFFFF7F10): 1.0,      # inside 1 +- 2^-8 (0x0BE608 at 0x044416 -> 0)
    ('f', 0xFFFF653C): 1.0,      # not > [0x0D2DBC] = 2.0 (side path 0x044674)
    ('b', 0xFFFF61F4): 0x00,     # bit 6 clear: 0x01CF22 -> 0 (head exit 0x04441C)
    ('b', 0xFFFF726E): 0,        # 0x02F8FE -> 0 (side path 0x044650)
    ('b', 0xFFFF970E): 0,        # 0x029858 -> 0 (head exit 0x044454)
    ('b', 0xFFFF9718): 0,        # 0x02997C -> 0 (head exit 0x044468)
    ('b', 0xFFFF7E76): 0,        # head exit 0x044430
    ('b', 0xFFFF3244): 1,        # bit 0 set: side path 0x04468A off
    ('b', 0xFFFF8278): 0,
    ('b', 0xFFFF7BE2): 0,        # blocks A / B need it == 1
    ('b', 0xFFFF81BB): 0,        # block A / main-block 0.0 step need it == 1
    ('b', 0xFFFF8237): 0,        # block C needs it == 1 (with [81BA] = 0)
    ('b', 0xFFFF824B): 1, ('b', 0xFFFF824C): 1, ('b', 0xFFFF824A): 0,   # rewritten at the head anyway
    ('w', 0xFFFF8224): 0,        # delayed-recovery counter (needs >= [0x0D29DE] = 70)
    ('f', 0xFFFF81FC): -7.0,     # restored into [81F0] when [824C] != 1 (via [8235] = 0)
}


def fbkc_run(k8234, knock, f0, **over):
    """run 0x04438C from ROM on FBKC_BASE + overrides (keys like b_61F4 / f_7F10 / w_8224)."""
    e = E.Emu(ROM)
    # The [726E] side path reaches 0x045F0A -> 0x0BDBCC, which enters / leaves a critical section;
    # the emulator raises on "ldc sr", so the verified pair (rtos_core_trace.txt: SR mask only, no RAM)
    # is stubbed here and nowhere else.
    e.stub(0x00317C, r0=0)
    e.stub(0x003190)
    st = dict(FBKC_BASE)
    for key, v in over.items():
        kind, a = key.split('_')
        st[(kind, 0xFFFF0000 | int(a, 16))] = v
    for (kind, a), v in st.items():
        {'f': e.ram_f32, 'b': e.ram_u8, 'w': e.ram_u16}[kind](a, v)
    e.ram_u8(0xFFFF8234, k8234); e.ram_u8(0xFFFF81BA, knock); e.ram_f32(0xFFFF81F0, f0)
    r = e.call(0x04438C)
    check(r == 'return', '04438C did not return')
    return e.read_f32(0xFFFF81F0), e


def sec_E():
    say('\n==== E. consumer 0x04438C (the FBKC routine) and 0x044296 ====')
    step = calf(0x0D2DCC); floor_ = calf(0x0D2DC8); rel = calf(0x0D2DC0)
    stepB = calf(0x0D2DDC); stepA = calf(0x0D2DE4); step0 = calf(0x0D2DE8); rel2 = calf(0x0D2DD0)
    getv1 = calf(0x0D2DC4); getv2 = calf(0x0D2DD4); mul35 = calf(0x0D2DD8); cadd = calf(0x0D2DE0)
    check((step, stepB, stepA, step0) == (calf(0x0D2DCC), calf(0x0D2DCC), 0.0, 0.0), 'step constants')
    check(rel == rel2 and getv1 == getv2 == -5.0 and mul35 == 1.0 and cadd == 0.0, 'other constants')
    check(E.f2b(floor_) == 0x413CCCCC and E.f2b(step) == 0x3FB33333 and E.f2b(rel) == 0x3EB33333, 'words')
    check(calw(0x0D29DE) == 70 and calb(0x0D2995) == 0, 'counter limits')
    # E1: the shipped baseline
    rows = []
    for f0 in (0.0, -2.0, -11.0, f32(-11.8)):
        for knock in (0, 1):
            for k in (0, 1):
                v, e = fbkc_run(k, knock, f0)
                if k == 1 and knock == 1:
                    want = max(f32(f0 - step), -floor_)
                    check(abs(v - want) < 1e-5, f'E knock step {f0} {v} {want}')
                elif k == 1:
                    check(v == f0, f'E 8234=1 quiet, counter 0 -> unchanged {f0} {v}')
                else:
                    want = min(f32(f0 + rel), 0.0)
                    check(abs(v - want) < 1e-5, f'E relax {f0} {v} {want}')
                rows.append(f'[81F0]={f0:g} knock={knock} [8234]={k} -> {v:.4g}')
    say('  E1 baseline: window open (load 2.0, RPM 3000), no head exit, no side path, [81BB] = [7BE2] = 0:')
    for r in rows:
        say('    ' + r)
    say(f'     [8234] = 1 and [81BA] = 1: [81F0] -= [0x0D2DCC] = {step!r} (0x3FB33333), floored at')
    say(f'     -[0x0D2DC8] = -{floor_!r} (0x413CCCCC); [8234] = 0: [81F0] = min([81F0] + [0x0D2DC0] = {rel!r}, 0)')
    # E2: one change at a time from E1, [81F0] = -2.0.  (label, [8234], [81BA], overrides, expected)
    x = -2.0
    stp = max(f32(x - step), -floor_)                    # -3.4
    rlx = min(f32(x + rel), 0.0)                         # -1.65
    cases = [
        ('E1 knock step',                          1, 1, {}, stp),
        ('[81BB] = 1 (main block, step [0x0D2DE8] = 0.0)', 1, 1, {'b_81BB': 1}, x),
        ('[7BE2] = 1, [81BB] = 1 (block A, step [0x0D2DE4] = 0.0)', 1, 1, {'b_7BE2': 1, 'b_81BB': 1}, x),
        ('[7BE2] = 1, [81BB] = 0 (block B, step [0x0D2DDC] = 1.4)', 1, 1, {'b_7BE2': 1}, stp),
        ('[7BE2] = 1 with [8234] = 0 (no block)',  0, 1, {'b_7BE2': 1}, rlx),
        ('bit0 [3244] = 0, [8278] = 1, [8234] = 1 (side relax, then step)', 1, 1,
         {'b_3244': 0, 'b_8278': 1}, max(f32(rlx - step), -floor_)),
        ('bit0 [3244] = 0, [8278] = 1, [8234] = 0 (relaxed ONCE, tail skipped)', 0, 1,
         {'b_3244': 0, 'b_8278': 1}, rlx),
        ('bit0 [3244] = 0, [8278] = 0, [8234] = 1 (side path off)', 1, 1, {'b_3244': 0}, stp),
        ('[7E76] = 1, [8234] = 1 (head exit 0x0447A6)', 1, 1, {'b_7E76': 1}, rlx),
        ('[7E76] = 1, [8234] = 0',                 0, 1, {'b_7E76': 1}, rlx),
        ('[7F10] = 1.01, [8234] = 1 (head exit)',  1, 1, {'f_7F10': 1.01}, rlx),
        ('[7F10] = 1 + 2^-8 (inside), [8234] = 1', 1, 1, {'f_7F10': 1.0 + 2 ** -8}, stp),
        ('load 0.5 -> [824A] = 1, [8234] = 1 (head exit)', 1, 1, {'f_63F8': 0.5}, rlx),
        ('bit 6 of [61F4] set, [8234] = 1 (head exit: 0.0)', 1, 1, {'b_61F4': 0x40}, 0.0),
        ('bit 5 of [61F4] set only, [8234] = 1',   1, 1, {'b_61F4': 0x20}, stp),
        ('[970E] = 1, [8234] = 1 (head exit: [0x0D2DC4])', 1, 1, {'b_970E': 1}, getv1),
        ('[970E] = 1, [8234] = 0',                 0, 0, {'b_970E': 1}, getv1),
        ('[9718] = 1, [8234] = 1 (head exit: [0x0D2DD4])', 1, 1, {'b_9718': 1}, getv2),
        ('RPM 7000 -> [824C] = 0 -> [8235] = 0 (head exit: [81FC] * 1.0)', 1, 1, {'f_6624': 7000.0}, -7.0),
        ('RPM 7000, [8234] = 0',                   0, 1, {'f_6624': 7000.0}, -7.0),
        ('RPM 1000 -> [824B] = 0, [8234] = 1 (main block skipped, tail relax)', 1, 1, {'f_6624': 1000.0}, rlx),
        ('[726E] = 1, [8234] = 0 (side path sets sp+16: no relax)', 0, 1, {'b_726E': 1}, x),
        ('[726E] = 1, [8234] = 1',                 1, 1, {'b_726E': 1}, stp),
        ('[653C] = 2.5, [8234] = 0 (side path sets sp+16: no relax)', 0, 1, {'f_653C': 2.5}, x),
        ('[8234] = 1, [81BA] = 0, [8224] = 70 (delayed recovery)', 1, 0, {'w_8224': 70}, rlx),
        ('[8234] = 1, [81BA] = 0, [8224] = 69',    1, 0, {'w_8224': 69}, x),
        ('[8234] = 1, [81BA] = 0, [8237] = 1 (block C: x if x < 0)', 1, 0, {'b_8237': 1}, x),
    ]
    say('  E2 one change from E1, [81F0] = -2.0 before the call:')
    for label, k, kn, over, want in cases:
        v, e = fbkc_run(k, kn, x, **over)
        check(abs(v - want) < 1e-5, f'E2 {label}: got {v} want {want}')
        say(f'    {label:<66} -> {v:.6g}')
    # block C with a positive [81F0]: clamps to 0
    v, e = fbkc_run(1, 0, 0.5, b_8237=1)
    check(v == 0.0, f'E2 block C positive {v}')
    say(f'    {"[8234] = 1, [81BA] = 0, [8237] = 1, [81F0] = +0.5 (block C)":<66} -> {v:.6g}')
    say('     So [8234] gates the knock step only on the path with no head exit, [81BB] != 1 and the RPM window')
    say('     open; with [8234] = 0 the head exits still set 0.0 / -5.0 / [81FC] or relax, as with [8234] = 1.')
    for k6254, g1, g2 in ((1, 0, 0), (0, 0, 0), (0, 1, 0), (0, 0, 1), (0, 0xFF, 0x80)):
        e = E.Emu(ROM)
        e.ram_u8(0xFFFF6254, k6254)
        e.ram_u8(0xFFFF970E, g1)          # 0x029858: 2 if byte [970E] != 0
        e.ram_u8(0xFFFF9718, g2)          # 0x02997C: 2 if byte [9718] != 0
        e.ram_f32(0xFFFF81F0, -2.0); e.ram_f32(0xFFFF8260, 3.0); e.ram_f32(0xFFFF828C, -0.5)
        e.call(0x044296)
        v = e.read_f32(0xFFFF81EC)
        if k6254 == 1:
            check(v == 0.0, '044296 6254')
        elif g1 == 0 and g2 == 0:
            check(v == 0.5, f'044296 sum {v}')
        else:
            check(v == -2.0, f'044296 FBKC only {v}')
        check(set(e.writes) == set(range(0xFFFF81EC, 0xFFFF81F0)), '044296 writes')
    say('  0x044296: [81EC] = 0 if byte [6254] == 1; else [81F0] + [8260] + [828C] when bytes [970E] and [9718]')
    say('            are both 0 (getters 0x029858 / 0x02997C return 0), else [81F0] alone   (5 cases)')


# ================================================================= Z  bins
def sec_Z():
    say('\n==== Z. stock / 20.19c / 20.19e ====')
    roms = {'stock': open(STOCK_PATH, 'rb').read(), '20.19c': ROM, '20.19e': open(E_PATH, 'rb').read()}
    # (review: the earlier hand list omitted routines the script runs.)  Compare the bytes of EVERY
    # instruction executed on the shipped image by sections A-E, and every pool word those
    # instructions load (mov.l / mov.w @(disp,PC), mova).
    check(len(EXECUTED_SHIPPED) > 1000, f'too few executed instructions recorded: {len(EXECUTED_SHIPPED)}')
    pools = set()
    for pc in EXECUTED_SHIPPED:
        w = struct.unpack_from('>H', ROM, pc)[0]
        if w >> 12 == 0xD:
            pools.add((((pc + 4) & ~3) + (w & 0xFF) * 4, 4))
        elif w >> 12 == 0x9:
            pools.add((pc + 4 + (w & 0xFF) * 2, 2))
        elif w >> 8 == 0xC7:
            pools.add((((pc + 4) & ~3) + (w & 0xFF) * 4, 4))
    for pc in EXECUTED_SHIPPED:
        check(roms['stock'][pc:pc + 2] == ROM[pc:pc + 2] == roms['20.19e'][pc:pc + 2], f'code differs {pc:06X}')
    for a, n in pools:
        check(roms['stock'][a:a + n] == ROM[a:a + n] == roms['20.19e'][a:a + n], f'pool word differs {a:06X}')
    # which census functions those instructions belong to (for the record)
    fns = []
    try:
        import json
        cen = []
        for line in open(os.path.join(REPO, 'disassembly', 'maps', 'function_census.json')):
            line = line.strip().rstrip(',')
            if line.startswith('{"entry"'):
                r = json.loads(line)
                cen.append((int(r['entry'], 16), int(r['end'], 16)))
        for a, b in cen:
            if any(a <= pc < b for pc in EXECUTED_SHIPPED):
                fns.append(a)
    except (OSError, ValueError):
        pass
    say(f'  {len(EXECUTED_SHIPPED)} executed instruction words and {len(pools)} pool words they load: identical in')
    say(f'  stock / 20.19c / 20.19e.  They lie in {len(fns)} census functions:')
    for i in range(0, len(fns), 8):
        say('    ' + ' '.join(f'0x{a:06X}' for a in fns[i:i + 8]))
    for a in (0x0448F4, 0x045A3E, 0x045F9A, 0x046A4A, 0x0467AE, 0x0BEA40, 0x0BE8E4, 0x044300, 0x044326,
              0x04438C, 0x0456E0, 0x04578C, 0x04581A, 0x01CF22, 0x029858, 0x02997C):
        check(a in fns, f'routine 0x{a:06X} not among the executed functions')
    cals = [(0x0D2E08, 'f'), (0x0D29E0, 'w'), (0x0D2EDC, 'f'), (0x0D2E0C, 'f'), (0x0D2E10, 'f'), (0x0D2E14, 'f'),
            (0x0D2997, 'b'), (0x0D2998, 'b'), (0x0D2DBC, 'f'), (0x0D2999, 'b'), (0x0D299A, 'b'), (0x0D2F6C, 'f'),
            (0x0D2F70, 'f'), (0x0CC21C, 'f'), (0x0CC220, 'f'), (0x0D299B, 'b'), (0x0D2E18, 'f'), (0x0D2DC0, 'f'),
            (0x0D2DC8, 'f'), (0x0D2DCC, 'f'), (0x0D2DD0, 'f')]
    rows = []
    for a, t in cals:
        vals = []
        for nm, r in roms.items():
            vals.append(calf(a, r) if t == 'f' else (calw(a, r) if t == 'w' else calb(a, r)))
        check(vals[0] == vals[1] == vals[2], f'cal {a:06X} differs {vals}')
        if t == 'f' and f32(float(f'{vals[1]:.6g}')) != vals[1]:
            rows.append(f'0x{a:06X}=0x{E.f2b(vals[1]):08X}({vals[1]:.9g})')   # quote the word, not a rounding
        else:
            rows.append(f'0x{a:06X}={vals[1]:g}')
    say('  calibration scalars (identical in all three): ' + ', '.join(rows))
    # the three tables 0x045970 reads: the all-zero gain table is identical; the two KC Advance Max maps
    # differ between stock and the tuned revs (so [8258], and G7, differ in VALUE across bins)
    import desc_types as DT
    for a, lo_hi in ((0x0AE664, {'stock': (0.0, 0.0), '20.19c': (0.0, 0.0), '20.19e': (0.0, 0.0)}),
                     (0x0AE680, {'stock': (0.0, 7.03125), '20.19c': (0.0, 7.3828125), '20.19e': (0.0, 7.3828125)}),
                     (0x0AE69C, {'stock': (0.0, 7.03125), '20.19c': (0.0, 7.3828125), '20.19e': (0.0, 7.3828125)})):
        for nm, r in roms.items():
            v = DT.read_table(r, a)['values']
            flat = [c for row in v for c in (row if isinstance(row, (list, tuple)) else [row])]
            check((min(flat), max(flat)) == lo_hi[nm], f'table {a:06X} {nm} range {min(flat)}..{max(flat)}')
    say('  table ranges: 0x0AE664 0..0 in all three; 0x0AE680 / 0x0AE69C 0..7.03125 stock, 0..7.3828125 in'
        ' 20.19c and 20.19e')
    # consumer 0x04438C: the step / relax / floor / exit constants are identical; its window and its
    # delayed-recovery count are TUNED (stock differs from 20.19c / 20.19e, which agree)
    for a in (0x0D2DC4, 0x0D2DD4, 0x0D2DD8, 0x0D2DDC, 0x0D2DE0, 0x0D2DE4, 0x0D2DE8):
        vals = [calf(a, r) for r in roms.values()]
        check(vals[0] == vals[1] == vals[2], f'consumer cal {a:06X} differs {vals}')
    # (stock, tuned) as float32 BITS: stock 0x0D2DA8 is 0x3F4CCCCC (0.79999995), not the float nearest 0.8
    tuned = {0x0D2DA4: (0x3F400000, 0x3F733333), 0x0D2DA8: (0x3F4CCCCC, 0x3F800000),
             0x0D2DAC: (0x44960000, 0x44898000), 0x0D2DB0: (0x44A28000, 0x44960000),
             0x0D2DB4: (0x45C4E000, 0x45BB8000), 0x0D2DB8: (0x45C80000, 0x45BEA000)}
    for a, (s, t) in tuned.items():
        bs, bc, be = (struct.unpack_from('>I', r, a)[0] for r in (roms['stock'], ROM, roms['20.19e']))
        check(bs == s and bc == be == t, f'tuned {a:06X}: {bs:08X} {bc:08X} {be:08X}')
    check(calw(0x0D29DE, roms['stock']) == 125 and calw(0x0D29DE) == calw(0x0D29DE, roms['20.19e']) == 70, 'D29DE')
    say('  consumer constants 0x0D2DBC..0x0D2DE8 (steps, relax, floor, exit values): identical in all three.')
    say('  TUNED (stock -> 20.19c = 20.19e): [824A] limits 0x0D2DA4 / 0x0D2DA8 0.75 / 0x3F4CCCCC (0.79999995)'
        ' -> 0x3F733333 (0.95) / 1.0;')
    say('  [824B] / [824C] limits 0x0D2DAC..0x0D2DB8 1200 / 1300 / 6300 / 6400 -> 1100 / 1200 / 6000 / 6100;')
    say('  u16 0x0D29DE (delayed-recovery count) 125 -> 70')
    # the window constants behind [8277] / [829E] (G7 / G8): Rough tuned in six cells, Fine in its upper load pair
    win = {0x0D2EBC: (1500.0, 1700.0), 0x0D2EC0: (1600.0, 1800.0), 0x0D2EC4: (5500.0, 6550.0),
           0x0D2EC8: (5600.0, 6600.0), 0x0D2ECC: (0.95, 0.95), 0x0D2ED0: (1.0, 1.0), 0x0D2ED4: (2.95, 3.95),
           0x0D2ED8: (3.0, 4.0), 0x0D2F6C: (1500.0, 1500.0), 0x0D2F70: (1600.0, 1600.0),
           0x0D2F74: (6300.0, 6300.0), 0x0D2F78: (6400.0, 6400.0), 0x0D2F7C: (1.25, 1.25), 0x0D2F80: (1.3, 1.3),
           0x0D2F84: (2.95, 3.45), 0x0D2F88: (3.0, 3.5)}
    for a, (s, t) in win.items():
        vs, vc, ve = (calf(a, r) for r in (roms['stock'], ROM, roms['20.19e']))
        check(abs(vs - s) < 1e-6 * max(1.0, s) and vc == ve and abs(vc - t) < 1e-6 * max(1.0, t),
              f'window {a:06X}: {vs} {vc} {ve}')
    say('  Rough / Fine Correction windows (0x0D2EBC..0x0D2ED8, 0x0D2F6C..0x0D2F88): 20.19c = 20.19e; stock Rough')
    say('  1500 / 1600 / 5500 / 5600, 0.95 / 1.0 / 2.95 / 3.0 (tuned 1700 / 1800 / 6550 / 6600, .. / 3.95 / 4.0);')
    say('  stock Fine upper load pair 2.95 / 3.0 (tuned 3.45 / 3.5); the other Fine cells identical')
    for a in (0x0AE664,):
        for nm, r in roms.items():
            c1, c2 = struct.unpack_from('>HH', r, a)
            dp = struct.unpack_from('>I', r, a + 12)[0]
            n = c1 * c2
            check(all(x == 0 for x in r[dp:dp + n]), f'0AE664 data not zero in {nm}')
    say('  descriptor 0x0AE664 (15x18 uint8, data 0x0D5768): every cell 0 in all three bins')
    try:
        import defs
        d = defs.load()
        names = {a: [t.name for t in d.at(a)] for a in (0x0D2EDC, 0x0D2F6C, 0x0D5904, 0x0D5AC4, 0x0D2EBC,
                                                         0x0D2F7C, 0x0D2DA4, 0x0D2DAC, 0x0D2E08, 0x0D5768)}
        check(names[0x0D2EDC] == ['Rough Correction Minimum KC Advance Map Value'], 'defs D2EDC')
        check(names[0x0D2F6C] == ['Fine Correction Range (RPM)'], 'defs D2F6C')
        check(names[0x0D5904] == ['Knock Correction Advance Max Cruise'], 'defs D5904')
        check(names[0x0D5AC4] == ['Knock Correction Advance Max Non-Cruise'], 'defs D5AC4')
        check(names[0x0D2E08] == [] and names[0x0D5768] == [], 'defs unnamed')
        for a, v in names.items():
            say(f'  definition at 0x{a:06X}: {v if v else "(none)"}')
    except ImportError:
        say('  (defs.py not importable -- definition names not re-checked)')


# ================================================================= I  identities
def sec_I():
    """review C42: recount the definition-named axes [6350] / [6624] feed.  coverage_map is imported and
    only its pure trace function is called (nothing is written)."""
    say('\n==== I. identity recount for [6350] / [6624] (definition axis names) ====')
    try:
        import coverage_map as CM
        import defs
    except ImportError as ex:
        say(f'  (coverage_map / defs not importable: {ex}) -- not re-checked')
        return
    d = defs.load()
    want = {0xFFFF6350: ('Coolant Temperature', 147, 100), 0xFFFF6624: ('Engine Speed', 116, 35)}
    for nm, path in (('stock', STOCK_PATH), ('20.19c', ROM_PATH)):
        buf = open(path, 'rb').read()
        fr4, fr5, _ = CM.trace_axis_feeds(buf)
        for ram, (axis_name, tot_w, named_w) in want.items():
            tot = named = 0
            for slot, table in ((0, fr4), (1, fr5)):
                for desc, hits in table.get(ram, {}).items():
                    tot += hits
                    x = CM._desc_loose_at(buf, desc)
                    if x is None or slot >= len(x['axes']):
                        continue
                    names = {getattr(t, 'name', None) for t in d.at(x['axes'][slot], include_axes=True)}
                    if axis_name in names:
                        named += hits
            check((tot, named) == (tot_w, named_w), f'I {nm} {ram:08X}: {named} of {tot}')
            say(f'  {nm:6}  [{ram & 0xFFFF:04X}]: {named} of {tot} lookup call sites have the axis it feeds named'
                f' "{axis_name}" (exact name, descriptor axis pointer of the fr4 / fr5 slot)')


SECTIONS = {'A': sec_A, 'B': sec_B, 'C': sec_C, 'D': sec_D, 'S': sec_S, 'E': sec_E, 'Z': sec_Z, 'I': sec_I}


def main():
    names = [a.upper() for a in sys.argv[1:]] or list(SECTIONS)
    for n in names:
        SECTIONS[n]()
    say(f'\nALL CHECKS PASSED ({NCHECK} assertions)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
