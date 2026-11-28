#!/usr/bin/env python3
"""Emulation check for the byte 0xFFFF8EDC (the gate that freezes task 0x04AA58).

    python3 scripts/trace/emu_revlim_freeze_gate.py

Reference bin: rom/AE5L600L 20g rev 20.19c.bin  md5 92cae8275cd4f9b473a3a9e36efe6449
Trace:         disassembly/analysis/revlim_freeze_gate_trace.txt

Each pass runs ROM code in scripts/sh2e_emu.py against a Python model written
from the bytes, prints inputs -> outputs, and asserts.

  A. 0x05CC9A  validated read of word 0xFFFF8ECC, all 65,536 words
  B. 0x05CB1C  the writer: 12 V-sources x 256 x 256 (V = 1) / sampled (V != 1)
  C. 0x05CBC8  the scrubber, all 65,536 words x 2 shadow bytes, plus the
               reader-visible byte before / after for post-reset-like words
  D. 0x05B690  writer of word 0xFFFF8ECC: all 256 values of external reg 17 x 5
  E. 0x05B73C  writer of byte 0xFFFF8EEE and word 0xFFFF3694 (the two compared)
  F. 0x05B5D8  writer of byte 0xFFFF8EDA, with the real 0x05CBF6 / 0x00C8E8 and
               0x006BC4 stubbed as a register file (also one that changes between
               the two tries); plus the necessary conditions proven over the full
               input space of the model
  G. 0x04793C  from its entry to 0x047968 (after 0x05CB1C returns): end to end,
               with the real 0x0951F8 / 0x0582AC / 0x09148E (byte 0xFFFFACF6)
  H. 0x010124  warm / cold start decision, event 16 (-> 0x04793C) or 18; and
               0x0100E4 then 0x010124 as task 10 runs them (5B8D zeroed first)
  I. 0x010198  event 17 and the 0xAA55 marker
  J. 0x01001C  byte 0xFFFF5B8D := r4 (0x04793C's tail)
  K. 0x00FDB4  event 16 reaches 0x04793C through 0x00DCE4 / 0x00E502; 17, 18;
               event 15 reaches the bare rts 0x00E4FE; 0x010D58's posts for
               every value of byte 0xFFFF5BBF; the two orphan posters' ids
  L. the 28 readers: first call (or return) for gate byte 0x00 / 0x01 / 0xA5 / 0xFF,
     with zeroed and with random RAM; 0x04907C run to its return for gate 0xFF /
     0x01 / 0xA5 and every value of byte 0xFFFF8320
  M. static: every resolved store / load / pointer argument covering 0xFFFF8EDC
     over all 5,146 census functions (CFG constant propagation), plus the
     writers of the inputs; call sites; the 0x00DCE4 table arguments; every
     resolved store and PC-relative literal in 0xFFFFEC00..0xFFFFECFF;
     reachability facts; cal bytes across all bins
  N. kernel start: 0x00387C (the autostart list) emulated for both list
     indexes; the bytes of the path 0x00FA34 -> 0x00FA5A -> 0x003324(0) ->
     0x0036C4 -> 0x00387C and of the task end 0x0035A4

    python3 scripts/trace/emu_revlim_freeze_gate.py B L    # selected passes only

Stubs: 0x0BE81C / 0x0BE82C (critical-section pair; the emulator refuses ldc sr)
are replaced by their verified contract (old mask 0 stored at @r4).  0x006BC4
(the external-device read, see trace) is replaced by a register file.  Pass-local
stubs: H 0x00FDB4 (records the event; for 16 it writes byte 0xFFFF5B8D as
0x04793C's tail would) and the RAM test 0x010448; I 0x00FDB4; K the final
handlers 0x04793C / 0x048732 / 0x01076A / 0x004BCA, and 0x00FDB4 inside
0x010D58; L the three calls 0x047C40 makes before its gate read and the five
calls of 0x04907C's 0xFF path; N 0x003206 (records the id queued).  Everything
else executed is ROM code.  No claim depends on the last bit of a float: every
float compared is an integer-valued multiple of 60 or a product checked against
the emulator's own round-toward-zero rz_bits.

Names here are neutral: nothing below establishes what these cells physically are.
"""
import glob
import hashlib
import json
import os
import struct
import sys
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, 'scripts'))
sys.path.insert(0, os.path.join(REPO, 'scripts', 'mapping'))
import sh2e_emu as E            # noqa: E402
import function_census as fc    # noqa: E402

BIN = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
ROM = open(BIN, 'rb').read()
assert hashlib.md5(ROM).hexdigest() == '92cae8275cd4f9b473a3a9e36efe6449', 'wrong reference bin'

GATE, GATE_SH = 0xFFFF8EDC, 0xFFFF8EED
W8ECC, SH8EF6 = 0xFFFF8ECC, 0xFFFF8EF6
CNT, LIM = 0xFFFF3694, 0xFFFF8EEE
NCHECK = 0


def ok(cond, msg):
    global NCHECK
    NCHECK += 1
    if not cond:
        raise AssertionError(msg)


def u8(a): return ROM[a]
def u32(a): return struct.unpack('>I', ROM[a:a + 4])[0]
def f32(a): return struct.unpack('>f', ROM[a:a + 4])[0]
def sx8(v): v &= 0xFF; return v - 0x100 if v & 0x80 else v
def build16(v): v &= 0xFF; return (v << 8) | (~v & 0xFF)
def consistent(w): return ((w >> 8) & 0xFF) == ((~w) & 0xFF)


def new_emu():
    e = E.Emu(ROM)

    def crit_enter(em):
        em.write(em.R[4], 4, 0)
        em.R[0] = 0
    e.stub(0x0BE81C, fn=crit_enter)
    e.stub(0x0BE82C, fn=lambda em: None)
    return e


def fresh(e):
    e.writes.clear()
    e.uninit_reads.clear()
    e.steps = 0


def run(e, entry, regs=None, stop_at=()):
    g0 = e.gbr
    res = e.call(entry, regs=regs, stop_at=stop_at)
    if res == 'return':
        ok(e.gbr == g0, f'{entry:06X}: GBR not restored')
    return res


def nonstack_writes(e):
    return {a for a in e.writes if not (0xFFFFB000 <= a < E.STACK_TOP)}


# ---------------------------------------------------------------- A
def model_cc9a(w, sh):
    if consistent(w):
        return (w >> 8) & 0xFF, (w >> 8) & 0xFF
    return sh, sh


def pass_a():
    e = new_emu()
    n = 0
    for w in range(65536):
        sh = (w * 37 + 11) & 0xFF
        fresh(e)
        e.ram_u16(W8ECC, w)
        e.ram_u8(SH8EF6, sh)
        run(e, 0x05CC9A)
        v, sh2 = model_cc9a(w, sh)
        ok((e.R[0] & 0xFF) == v, f'A {w:04X}: r0 {e.R[0]:08X} want {v:02X}')
        ok(e.read_u8(SH8EF6) == sh2, f'A {w:04X}: shadow')
        ok(e.read_u16(W8ECC) == w, f'A {w:04X}: word changed')
        want_w = {SH8EF6} if consistent(w) else set()
        ok(nonstack_writes(e) == want_w, f'A {w:04X}: write set {sorted(nonstack_writes(e))}')
        n += 1
    for w in (0x00FF, 0x01FE, 0xA55A, 0xFF00, 0x0000, 0x0101, 0xFFFF):
        sh = (w * 37 + 11) & 0xFF
        print(f'  A  word8ECC={w:04X} shadow={sh:02X} -> V={model_cc9a(w, sh)[0]:02X}')
    print(f'A  0x05CC9A: {n} words, r0 = high byte when word is value:~value, else shadow 0xFFFF8EF6')


# ---------------------------------------------------------------- B
def model_cb1c(v, cnt, lim):
    if (v & 0xFF) != 1:
        return 0x00
    return 0xFF if (cnt & 0xFF) >= (lim & 0xFF) else 0xA5


def pass_b():
    e = new_emu()
    sources = [(build16(0), 0x33), (build16(1), 0x00), (build16(2), 0x01), (build16(0x80), 0x01),
               (build16(0xA5), 0x01), (build16(0xFF), 0x01),
               (0x0000, 0x00), (0x0000, 0x01), (0x0101, 0x01), (0xFFFF, 0x02), (0x01FF, 0x01), (0x00FE, 0x01)]
    n = 0
    seen = {}
    for w, sh in sources:
        v = model_cc9a(w, sh)[0]
        pairs = [(c, l) for c in range(256) for l in range(256)] if v == 1 else \
                [(c, l) for c in (0, 1, 4, 5, 0x7F, 0x80, 0xFF) for l in (0, 1, 5, 0x7F, 0x80, 0xFF)]
        for c, l in pairs:
            fresh(e)
            e.ram_u16(W8ECC, w)
            e.ram_u8(SH8EF6, sh)
            e.ram_u16(CNT, (c << 8) | 0x5C)          # only the high byte is read
            e.ram_u8(LIM, l)
            e.ram_u16(GATE, 0x1234)
            e.ram_u8(GATE_SH, 0x77)
            run(e, 0x05CB1C)
            g = model_cb1c(v, c, l)
            ok(e.read_u16(GATE) == build16(g), f'B w={w:04X} sh={sh:02X} c={c} l={l}: word {e.read_u16(GATE):04X}')
            ok(e.read_u8(GATE_SH) == g, f'B shadow 8EED {e.read_u8(GATE_SH):02X} want {g:02X}')
            want_w = {GATE, GATE + 1, GATE_SH} | ({SH8EF6} if consistent(w) else set())
            ok(nonstack_writes(e) == want_w, f'B write set {sorted(map(hex, nonstack_writes(e)))}')
            seen.setdefault((v, g), 0)
            seen[(v, g)] += 1
            n += 1
    for (c, l) in ((0, 0), (4, 5), (5, 5), (6, 5), (0x80, 0x7F), (0x7F, 0x80), (0xFF, 0xFF)):
        print(f'  B  V=1 cnt3694={c:02X} lim8EEE={l:02X} -> 8EDC word {build16(model_cb1c(1, c, l)):04X}')
    print(f'  B  V=0/2/80/A5/FF -> 8EDC word {build16(0):04X} for every cnt/lim')
    ok(set(seen) == {(1, 0xFF), (1, 0xA5), (0, 0), (2, 0), (0x80, 0), (0xA5, 0), (0xFF, 0)}, f'B outcomes {seen}')
    print(f'B  0x05CB1C: {n} cases; V==1 -> 0xFF if cnt>=lim (unsigned bytes) else 0xA5; V!=1 -> 0x00')


# ---------------------------------------------------------------- C
def pass_c():
    e = new_emu()
    n = 0
    for w in range(65536):
        for sh in (0x5A, (w & 0xFF) ^ 0x33):
            fresh(e)
            e.ram_u16(GATE, w)
            e.ram_u8(GATE_SH, sh)
            run(e, 0x05CBC8)
            if consistent(w):
                ok(e.read_u16(GATE) == w and e.read_u8(GATE_SH) == (w >> 8), f'C {w:04X}/{sh:02X} consistent')
                ok(nonstack_writes(e) == {GATE_SH}, 'C write set (consistent)')
            else:
                ok(e.read_u16(GATE) == build16(sh) and e.read_u8(GATE_SH) == sh, f'C {w:04X}/{sh:02X} repair')
                ok(nonstack_writes(e) == {GATE, GATE + 1}, 'C write set (repair)')
            n += 1
    for w, sh in ((0xFF00, 0x00), (0x00FF, 0xA5), (0x0000, 0x00), (0x0000, 0xA5), (0xA55A, 0xFF), (0x1234, 0xFF)):
        out = w if consistent(w) else build16(sh)
        print(f'  C  word={w:04X} shadow={sh:02X} -> word {out:04X} shadow {out >> 8:02X}')
    # the byte the 28 readers see, before and after one scrub, for words that are not a
    # 0x05CB1C result (a post-reset or damaged word): the scrub decides it when the word is
    # inconsistent, and keeps a consistent word whatever its value
    for w, sh, want_w, want_b in ((0xA500, 0x00, 0x00FF, 0x00), (0xAAAA, 0xAA, 0xAA55, 0xAA),
                                  (0x0000, 0x00, 0x00FF, 0x00), (0xAA55, 0x33, 0xAA55, 0xAA),
                                  (0x00FF, 0xA5, 0x00FF, 0x00), (0x5555, 0xFF, 0xFF00, 0xFF)):
        fresh(e)
        e.ram_u16(GATE, w)
        e.ram_u8(GATE_SH, sh)
        run(e, 0x05CBC8)
        ok(e.read_u16(GATE) == want_w and e.read_u8(GATE) == want_b, f'C reader byte {w:04X}/{sh:02X}')
        print(f'  C  reader byte: word={w:04X} shadow={sh:02X}: byte 8EDC {w >> 8:02X} -> {want_b:02X} '
              f'(word {want_w:04X}, shadow {e.read_u8(GATE_SH):02X})')
        n += 1
    print(f'C  0x05CBC8: {n} cases (all 65,536 words x 2 shadow bytes + 6); consistent word kept and copied to shadow, else rebuilt from shadow')


# ---------------------------------------------------------------- external-device stub
def ext_stub(e, regs, log):
    def fn(em):
        r = em.R[4] & 0xFF
        log.append(r)
        em.R[0] = sx8(regs[r]) & 0xFFFFFFFF
    e.stub(0x006BC4, fn=fn)


# ---------------------------------------------------------------- D
def model_b690(reg17, b8eda):
    e8 = 1 if (reg17 & 2) else (2 if b8eda == 1 else 0)
    x = 1 if e8 == 2 else 0
    return e8, build16(x), x


def pass_d():
    e = new_emu()
    n = 0
    for reg17 in range(256):
        for b8eda in (0, 1, 2, 0x80, 0xFF):
            log = []
            ext_stub(e, {17: reg17}, log)
            fresh(e)
            e.gbr = 0x13579BDF
            e.ram_u8(0xFFFF8EDA, b8eda)
            run(e, 0x05B690)
            e8, w, x = model_b690(reg17, b8eda)
            ok(log == [17], f'D reg reads {log}')
            ok(e.read_u8(0xFFFF8EE8) == e8, f'D {reg17:02X}/{b8eda:02X}: 8EE8 {e.read_u8(0xFFFF8EE8)} want {e8}')
            ok(e.read_u16(W8ECC) == w and e.read_u8(SH8EF6) == x, 'D 8ECC / 8EF6')
            ok(nonstack_writes(e) == {0xFFFF8EE8, W8ECC, W8ECC + 1, SH8EF6}, 'D write set')
            n += 1
    for reg17, b in ((0x00, 1), (0x00, 0), (0x02, 1), (0xFD, 1), (0xFF, 1), (0x01, 2)):
        e8, w, x = model_b690(reg17, b)
        print(f'  D  reg17={reg17:02X} 8EDA={b:02X} -> 8EE8={e8} word8ECC={w:04X} (V={x})')
    print(f'D  0x05B690: {n} cases; V := 1 iff (reg17 & 2) == 0 and byte 8EDA == 1')


# ---------------------------------------------------------------- E
CAL_LIM = (u8(0x0C47BF), u8(0x0C47C0), u8(0x0C47C1))
CAL_T1, CAL_T2 = f32(0x0C5658), f32(0x0C565C)


def model_b73c(v, acf6, cnt, b36a2, b36a6, e8, f8eb0):
    lim = CAL_LIM[2] if b36a6 else (CAL_LIM[1] if b36a2 else CAL_LIM[0])
    if e8 == 1 and lim < 2:
        lim = 2
    c = cnt
    if v == 1 and acf6 == 0:
        c = min(cnt + 1, 255)
    f = None
    if e8 == 1:
        step = 60000.0 if CAL_T1 > 60000.0 else CAL_T1
        f = f8eb0 + step * min(float(c), float((lim - 1) & 0xFF))
    return lim, c, f


def pass_e():
    e = new_emu()
    n = 0
    for vw, vsh in ((build16(0), 0), (build16(1), 0), (0x0000, 1), (build16(2), 0)):
        v = model_cc9a(vw, vsh)[0]
        for acf6 in (0, 1):
            for cnt in (0, 1, 3, 4, 5, 7, 8, 9, 0x7F, 0x80, 0xFE, 0xFF):
                for b36a2 in (0, 1):
                    for b36a6 in (0, 1):
                        for e8 in (0, 1, 2):
                            for f8eb0 in (0.0, 7200.0):
                                fresh(e)
                                e.ram_u16(W8ECC, vw)
                                e.ram_u8(SH8EF6, vsh)
                                e.ram_u8(0xFFFFACF6, acf6)
                                e.ram_u16(CNT, build16(cnt))
                                e.ram_u16(0xFFFF36A2, (b36a2 << 8) | 0x99)
                                e.ram_u16(0xFFFF36A6, (b36a6 << 8) | 0x99)
                                e.ram_u8(0xFFFF8EE8, e8)
                                e.ram_f32(0xFFFF8EB0, f8eb0)
                                e.ram_f32(0xFFFF8EBC, -1.0)
                                run(e, 0x05B73C)
                                lim, c, f = model_b73c(v, acf6, cnt, b36a2, b36a6, e8, f8eb0)
                                tag = f'E V={v} acf6={acf6} cnt={cnt} a2={b36a2} a6={b36a6} e8={e8}'
                                ok(e.read_u8(LIM) == lim, f'{tag}: 8EEE {e.read_u8(LIM)} want {lim}')
                                ok(e.read_u16(CNT) == build16(c), f'{tag}: 3694 {e.read_u16(CNT):04X} want {build16(c):04X}')
                                if f is None:
                                    ok(e.read_f32(0xFFFF8EBC) == -1.0, f'{tag}: 8EBC written')
                                else:
                                    ok(e.read_f32(0xFFFF8EBC) == f, f'{tag}: 8EBC {e.read_f32(0xFFFF8EBC)} want {f}')
                                want_w = {LIM, CNT, CNT + 1} | ({SH8EF6} if consistent(vw) else set()) | \
                                         ({0xFFFF8EBC + i for i in range(4)} if e8 == 1 else set())
                                ok(nonstack_writes(e) == want_w, f'{tag}: write set')
                                n += 1
    for args in ((1, 0, 3, 0, 0, 2, 0.0), (1, 0, 4, 0, 0, 2, 0.0), (1, 1, 4, 0, 0, 2, 0.0), (0, 0, 4, 0, 0, 0, 0.0),
                 (1, 0, 0xFF, 0, 0, 2, 0.0), (1, 0, 3, 1, 0, 2, 0.0), (1, 0, 3, 0, 1, 2, 0.0), (0, 0, 7, 0, 0, 1, 7200.0)):
        lim, c, f = model_b73c(*args)
        print(f'  E  V={args[0]} ACF6={args[1]} cnt={args[2]:02X} 36A2={args[3]} 36A6={args[4]} 8EE8={args[5]} '
              f'-> 8EEE={lim} cnt\'={c:02X}' + (f' 8EBC={f}' if f is not None else ''))
    print(f'E  0x05B73C: {n} cases; cal lim {CAL_LIM}, cal floats {CAL_T1} / {CAL_T2}')


# ---------------------------------------------------------------- F
S60 = 60.0
S002 = E.b2f(0x3B03126E)          # the literal at 0x05CCE4


def fmul_rz(a, b):
    if a == 0.0 or b == 0.0:
        return 0.0
    return E.b2f(E.rz_bits(Fraction(a) * Fraction(b)))


def model_c8e8(regs):
    w_de = (((regs[21] & 0xFF) << 2) + (regs[22] & 3)) & 0xFFFF
    t = ((regs[23] & 0xFF) << 2) + (regs[24] & 3)
    w_e0 = 0 if (t & 0xFFFF) >= 1023 else t + 1
    flag = 1 if regs[20] & 0x20 else 0
    return w_de, w_e0, flag


def model_b5d8(regs, F, cnt, b3692):
    w_de, w_e0, flag = model_c8e8(regs)
    s = S002 if flag else S60
    A = fmul_rz(float(w_e0), s)
    B = fmul_rz(float(w_de), s) if b3692 == 1 else 0.0

    def inside(x, c):
        return not ((c - 60.0) > x or x > (c + 60.0))
    ef1 = 1 if (inside(A, F) and inside(B, F)) else 0
    L = CAL_T2 if cnt >= ((CAL_LIM[2] - 1) & 0xFF) else CAL_T1
    if L > 60000.0:
        L = 60000.0
    eda = 1 if (ef1 == 1 and inside(F, L)) else 0
    return dict(w_de=w_de, w_e0=w_e0, flag=flag, A=A, B=B, ef1=ef1, eda=eda, L=L)


def regs_for(w_de, w_e0_target, flag):
    """register file giving word 8EDE = w_de and word 8EE0 = w_e0_target (1..1023)."""
    t = w_e0_target - 1
    return {20: 0x20 if flag else 0x00, 21: (w_de >> 2) & 0xFF, 22: w_de & 3,
            23: (t >> 2) & 0xFF, 24: t & 3, 17: 0}


def pass_f():
    e = new_emu()
    n = 0
    Fs = (3539.0, 3540.0, 3600.0, 3660.0, 3661.0, 5339.0, 5340.0, 5400.0, 5460.0, 5461.0, 1.0, 0.0)
    for F in Fs:
        for cnt in (0, 7, 8, 9, 0xFF):
            for b3692 in (0, 1, 2):
                for w_de, w_e0, flag in ((60, 60, 0), (59, 61, 0), (58, 60, 0), (62, 62, 0), (57, 60, 0),
                                         (90, 90, 0), (89, 91, 0), (60, 60, 1), (1022, 1023, 1), (0, 1, 0)):
                    regs = regs_for(w_de, w_e0, flag)
                    log = []
                    ext_stub(e, regs, log)
                    fresh(e)
                    e.ram_f32(0xFFFF3674, F)
                    e.ram_u16(CNT, build16(cnt))
                    e.ram_u16(0xFFFF3692, (b3692 << 8) | 0x44)
                    run(e, 0x05B5D8)
                    m = model_b5d8(regs, F, cnt, b3692)
                    tag = f'F F={F} cnt={cnt} 3692={b3692} wde={w_de} we0={w_e0} flag={flag}'
                    ok(e.read_u16(0xFFFF8EDE) == m['w_de'] and e.read_u16(0xFFFF8EE0) == m['w_e0'], f'{tag}: words')
                    ok(e.read_u8(0xFFFF8EE2) == m['flag'], f'{tag}: flag')
                    ok(e.read_f32(0xFFFF8EA8) == m['A'] and e.read_f32(0xFFFF8EB0) == m['B'], f'{tag}: A/B')
                    ok(e.read_u8(0xFFFF8EF1) == m['ef1'], f'{tag}: 8EF1 {e.read_u8(0xFFFF8EF1)} want {m["ef1"]}')
                    ok(e.read_u8(0xFFFF8EDA) == m['eda'], f'{tag}: 8EDA {e.read_u8(0xFFFF8EDA)} want {m["eda"]}')
                    tries = 1 if m['ef1'] else 2
                    ok(log == [22, 21, 24, 23, 20] * tries, f'{tag}: reg reads {log}')
                    n += 1
    for F, cnt, b, wde, we0, fl in ((3600.0, 0, 1, 60, 60, 0), (3661.0, 0, 1, 60, 60, 0), (5400.0, 8, 1, 90, 90, 0),
                                    (5400.0, 7, 1, 90, 90, 0), (3600.0, 0, 0, 60, 60, 0), (3600.0, 0, 1, 60, 60, 1)):
        m = model_b5d8(regs_for(wde, we0, fl), F, cnt, b)
        print(f'  F  F={F} cnt={cnt} 3692={b} w8EDE={wde} w8EE0={we0} reg20bit5={fl} -> A={m["A"]} B={m["B"]} '
              f'L={m["L"]} 8EF1={m["ef1"]} 8EDA={m["eda"]}')
    # necessary conditions, over the whole input space of the model (every register value):
    # 8EDA == 1 needs reg20 bit5 == 0, byte 3692 == 1, and 60*w in [3480, 3720] or [5280, 5520] for both words
    sat = set()
    for flag in (0, 1):
        for w in range(0, 1024):
            v = fmul_rz(float(w), S002 if flag else S60)
            for L in (CAL_T1, CAL_T2):
                for F in (L - 60.0, L + 60.0):     # F may sit anywhere in [L-60, L+60]; v must be within 60 of F
                    if not ((F - 60.0) > v or v > (F + 60.0)):
                        sat.add((flag, w))
    ws = sorted(w for f_, w in sat if f_ == 0)
    ok(all(f_ == 0 for f_, w in sat), 'F: a word scaled by 0.002 can satisfy the window')
    ok(ws == list(range(58, 63)) + list(range(88, 93)), f'F: satisfying words {ws}')
    print(f'  F  words that can pass the +-60 windows: scale 60 only, w in {ws}; scale 0.002 never (max {fmul_rz(1023.0, S002):.4f})')
    # the second try with DIFFERENT register values (the loop 0x05B608..0x05B638): a register
    # file that returns try-1 values on the first pass and try-2 values on the second
    for F, cnt, t1, t2 in ((3600.0, 0, (60, 70, 0), (60, 60, 0)), (3600.0, 0, (70, 60, 0), (59, 61, 0)),
                           (5400.0, 8, (90, 95, 0), (90, 90, 0)), (3600.0, 0, (60, 60, 0), (70, 70, 0)),
                           (3600.0, 0, (60, 70, 0), (70, 60, 0)), (3600.0, 0, (60, 60, 1), (60, 60, 0)),
                           (5400.0, 0, (60, 70, 0), (90, 90, 0))):
        regs_l = [regs_for(*t1), regs_for(*t2)]
        log = []
        k = [0]

        def seq(em, regs_l=regs_l, log=log, k=k):
            r = em.R[4] & 0xFF
            if r == 22:
                k[0] += 1
            log.append(r)
            em.R[0] = sx8(regs_l[min(k[0], 2) - 1][r]) & 0xFFFFFFFF
        e.stub(0x006BC4, fn=seq)
        fresh(e)
        e.ram_f32(0xFFFF3674, F)
        e.ram_u16(CNT, build16(cnt))
        e.ram_u16(0xFFFF3692, 0x0144)
        run(e, 0x05B5D8)
        m1 = model_b5d8(regs_l[0], F, cnt, 1)
        m = m1 if m1['ef1'] else model_b5d8(regs_l[1], F, cnt, 1)
        tries = 1 if m1['ef1'] else 2
        tag = f'F seq F={F} cnt={cnt} {t1} {t2}'
        ok(log == [22, 21, 24, 23, 20] * tries, f'{tag}: reads {log}')
        ok(e.read_f32(0xFFFF8EA8) == m['A'] and e.read_f32(0xFFFF8EB0) == m['B'], f'{tag}: A/B')
        ok(e.read_u8(0xFFFF8EF1) == m['ef1'] and e.read_u8(0xFFFF8EDA) == m['eda'], f'{tag}: 8EF1/8EDA')
        print(f'  F  two tries: F={F} cnt={cnt} try1 (w8EDE, w8EE0, bit5)={t1} try2={t2} -> tries {tries}, '
              f'A={m["A"]} B={m["B"]} 8EF1={m["ef1"]} 8EDA={m["eda"]}')
        n += 1
    print(f'F  0x05B5D8: {n} cases; 8EDA := 1 iff A, B within +-60 of F (first or second try) and F within +-60 of {CAL_T1}/{CAL_T2}')


# ---------------------------------------------------------------- G
def model_0951f8(b36f4, b34d8, v, acf6):
    """0x0951F8 -> 0x0582AC (0 / 1 / 2 for byte 36F4 = other / 0xFF / 0xA5) -> 0x09148E unless 2."""
    r = 1 if b36f4 == 0xFF else (2 if b36f4 == 0xA5 else 0)
    if r in (0, 1) and v == 1 and b34d8 not in (0, 20):
        return 1
    return acf6


def pass_g():
    n = 0
    rows = []
    combos = ((0x00, 7), (0xFF, 7), (0xA5, 7), (0x33, 7), (0x00, 0), (0x00, 20))
    for reg17 in (0x00, 0x02, 0xFD, 0xFF):
        for F in (3540.0, 3600.0, 3661.0, 5400.0):
            for cnt in (0, 3, 4, 7, 8, 0xFF):
                for acf6 in (0, 1):
                    for wde in (60, 61, 90, 70):
                        for b36f4, b34d8 in combos:
                            e = new_emu()
                            regs = regs_for(wde, wde, 0)
                            regs[17] = reg17
                            log = []
                            ext_stub(e, regs, log)
                            e.ram_f32(0xFFFF3674, F)
                            e.ram_u16(CNT, build16(cnt))
                            e.ram_u16(0xFFFF3692, 0x0100)
                            e.ram_u8(0xFFFFACF6, acf6)
                            e.ram_u16(0xFFFF36A2, 0)
                            e.ram_u16(0xFFFF36A6, 0)
                            e.ram_u8(0xFFFF36F4, b36f4)
                            e.ram_u8(0xFFFF34D8, b34d8)
                            e.ram_u16(W8ECC, 0)                 # zero-filled RAM: inconsistent word
                            e.ram_u8(SH8EF6, 0)
                            e.ram_u16(GATE, 0)
                            e.ram_u8(GATE_SH, 0)
                            res = e.call(0x04793C, stop_at=(0x047968,))
                            ok(res == 0x047968, 'G did not reach 0x047968')
                            ok(0x09148E in e.executed or b36f4 == 0xA5, 'G 0x09148E not reached')
                            m = model_b5d8(regs, F, cnt, 1)
                            e8, w8, v = model_b690(reg17, m['eda'])
                            acf6p = model_0951f8(b36f4, b34d8, v, acf6)
                            lim, c, _ = model_b73c(v, acf6p, cnt, 0, 0, e8, 0.0)
                            g = model_cb1c(v, c, lim)
                            tag = f'G reg17={reg17:02X} F={F} cnt={cnt} acf6={acf6} 36F4={b36f4:02X} 34D8={b34d8}'
                            ok(e.read_u8(0xFFFFACF6) == acf6p, f'{tag}: ACF6 {e.read_u8(0xFFFFACF6)} want {acf6p}')
                            ok(e.read_u16(GATE) == build16(g), f'{tag}: gate {e.read_u16(GATE):04X}')
                            ok(e.read_u16(CNT) == build16(c), f'{tag}: counter')
                            rows.append((reg17, F, cnt, acf6, wde, m['eda'], v, c, lim, g, b36f4, b34d8, acf6p))
                            n += 1
    for r in rows:
        if r[10] == 0xA5 and r[1] == 3600.0 and r[4] == 60 and r[3] == 0 and r[2] in (0, 3, 4, 0xFF) or \
           (r[10] == 0xA5 and r[0] == 0 and r[4] == 70 and r[2] == 0 and r[3] == 0 and r[1] == 3600.0):
            print(f'  G  reg17={r[0]:02X} F={r[1]} cnt={r[2]:02X} ACF6={r[3]} 36F4=A5 w8EDE=w8EE0={r[4]} -> 8EDA={r[5]} V={r[6]} '
                  f'cnt\'={r[7]:02X} lim={r[8]} 8EDC={r[9]:02X}')
    for r in rows:
        if r[0] == 0 and r[1] == 3600.0 and r[4] == 60 and r[3] == 0 and r[2] == 4:
            print(f'  G  0x0951F8: 36F4={r[10]:02X} 34D8={r[11]:2d} V={r[6]} ACF6 0 -> {r[12]}: cnt 04 -> {r[7]:02X}, lim {r[8]}, '
                  f'8EDC={r[9]:02X}')
    ok({r[9] for r in rows} == {0x00, 0xA5, 0xFF}, 'G outcomes')
    ok(all(r[9] == 0 for r in rows if r[0] & 2), 'G: reg17 bit 1 set must give 0')
    blocked = [r for r in rows if r[6] == 1 and r[3] == 0 and r[12] == 1]
    ok(blocked and all(r[7] == r[2] for r in blocked), 'G: ACF6 set inside the call must block the increment')
    ok({r[12] for r in rows if r[6] == 1 and r[3] == 0} == {0, 1}, 'G: both ACF6 outcomes with V == 1')
    print(f'G  0x04793C..0x047968 end to end: {n} cases, all ROM code but 0x006BC4; 0x0951F8 sets ACF6 := 1 '
          f'(blocking the CNT increment) when 36F4 != 0xA5, V == 1 and 34D8 not in (0, 20)')


# ---------------------------------------------------------------- H
def pass_h():
    n = 0
    for w2000 in (0xAA55, 0x55AA, 0x0000, 0xAA54, 0xFFFF):
        for b in (0, 1, 2, 0xFF):
            for r10 in (0, 1):
                for rt in (0, 1):
                    e = new_emu()
                    ev, tests = [], []

                    def post(em, r10=r10, ev=ev):
                        ev.append((em.R[4] & 0xFFFF, em.R[5]))
                        if (em.R[4] & 0xFFFF) == 16:
                            em.write(0xFFFF5B8D, 1, r10)     # what 0x04793C's tail 0x01001C does
                    e.stub(0x00FDB4, fn=post)

                    def test(em, rt=rt, tests=tests):
                        tests.append((em.R[4], em.R[5]))
                        em.R[0] = rt
                    e.stub(0x010448, fn=test)
                    for a in range(0xFFFF2000, 0xFFFF4000, 4):
                        e.ram_u32(a, 0xA5A5A5A5)
                    e.ram_u32(0xFFFF4000, 0x5A5A5A5A)
                    e.ram_u16(0xFFFF2000, w2000)
                    e.ram_u8(0xFFFF5B8D, b)
                    e.ram_u8(0xFFFF5B88, 0)
                    run(e, 0x010124)
                    bb = b if w2000 == 0xAA55 else 1
                    want_ev = []
                    if bb == 0:
                        want_ev.append((16, 0))
                        bb = r10
                    cold = bb == 1
                    if cold:
                        want_ev.append((18, 0))
                    ok(ev == want_ev, f'H {w2000:04X}/{b}/{r10}/{rt}: events {ev} want {want_ev}')
                    ok(e.read_u8(0xFFFF5B8D) == bb, 'H 5B8D')
                    if cold:
                        ok(tests == [(0xFFFF2000, 0xFFFF3FFF)], f'H test args {tests}')
                        ok(e.read_u16(0xFFFF2000) == 0x55AA, 'H marker')
                        ok(all(e.read_u32(a) == 0 for a in range(0xFFFF2004, 0xFFFF4000, 4)) and e.read_u16(0xFFFF2002) == 0,
                           'H clear')
                        ok(e.read_u32(0xFFFF4000) == 0x5A5A5A5A, 'H clear overran')
                        ok(e.read_u8(0xFFFF5B88) == (1 if rt else 0), 'H 5B88')
                    else:
                        ok(tests == [] and e.read_u16(0xFFFF2000) == w2000 and e.read_u32(0xFFFF2004) == 0xA5A5A5A5, 'H warm')
                    n += 1
                    if r10 == 0 and rt == 0 and (b in (0, 1) or (w2000 == 0xAA55 and b == 2)):
                        print(f'  H  word2000={w2000:04X} 5B8D={b} (0x04793C ok) -> events {[x[0] for x in ev]} '
                              f'{"COLD: 0xFFFF2000..3FFF cleared, marker 55AA" if cold else ("warm" if ev else "nothing")}')
    print(f'H  0x010124: {n} cases; event 16 (0x04793C) iff word 0xFFFF2000 == 0xAA55 and byte 0xFFFF5B8D == 0; '
          f'cold path iff 5B8D == 1 at the re-read; marker present with 5B8D not in (0, 1): nothing')
    # task 10 runs 0x0100E4 (0x00DF28) and then 0x010124 (0x00DF80 -> 0x00E51C -> 0x00E520) with
    # nothing but calls in between: the straight-line check first, then the two in sequence
    for pc in range(0x00DF14, 0x00DF82, 2):
        w = struct.unpack('>H', ROM[pc:pc + 2])[0]
        kind = fc.flow_of(w, pc)[0]
        ok(kind in ('seq', 'call', 'icall'), f'H task 10 {pc:06X}: {kind}')
    st = fc.reg_states(ROM, 0x00DF14)
    ok(st[(0x00DF28, None)][1] == frozenset({0x0100E4}), 'H 0x00DF28 -> 0x0100E4')
    ok(fc.flow_of(0xB2CC, 0x00DF80)[:2] == ('call', 0x00E51C), 'H 0x00DF80 bsr 0x00E51C')
    for w2000 in (0xAA55, 0x55AA, 0x0000, 0xAA54):
        for b in (0, 1, 2, 0x80, 0xFF):
            for r10 in (0, 1):
                e = new_emu()
                ev = []

                def post(em, r10=r10, ev=ev):
                    ev.append(em.R[4] & 0xFFFF)
                    if (em.R[4] & 0xFFFF) == 16:
                        em.write(0xFFFF5B8D, 1, r10)
                e.stub(0x00FDB4, fn=post)
                e.stub(0x010448, r0=0)
                e.ram_u16(0xFFFF2000, w2000)
                for a in (0xFFFF5B88, 0xFFFF5B8B, 0xFFFF5B8C):
                    e.ram_u8(a, 0x77)
                e.ram_u8(0xFFFF5B8D, b)
                run(e, 0x0100E4)
                ok(nonstack_writes(e) == {0xFFFF5B88, 0xFFFF5B8B, 0xFFFF5B8C, 0xFFFF5B8D} and
                   all(e.read_u8(a) == 0 for a in (0xFFFF5B88, 0xFFFF5B8B, 0xFFFF5B8C, 0xFFFF5B8D)), 'H 0x0100E4')
                run(e, 0x010124)
                want = ([16] + ([18] if r10 else [])) if w2000 == 0xAA55 else [18]
                ok(ev == want, f'H task-10 order {w2000:04X}/{b}/{r10}: {ev} want {want}')
                n += 1
                if b == 2 and r10 == 0:
                    print(f'  H  0x0100E4 then 0x010124: word2000={w2000:04X} 5B8D was {b} -> events {ev}')
    print('H  task 10: 0x0100E4 zeroes 5B8D / 5B8C / 5B8B / 5B88 first, so event 16 depends on the marker word alone')


def pass_ij():
    n = 0
    for b in range(256):
        e = new_emu()
        ev = []
        e.stub(0x00FDB4, fn=lambda em, ev=ev: ev.append(em.R[4] & 0xFFFF))
        e.ram_u16(0xFFFF2000, 0x55AA)
        e.ram_u8(0xFFFF5B8D, b)
        run(e, 0x010198)
        ok(ev == ([17] if b == 1 else []), 'I events')
        ok(e.read_u16(0xFFFF2000) == (0xAA55 if b == 1 else 0x55AA), 'I marker')
        n += 1
    print(f'I  0x010198: {n} cases; byte 5B8D == 1 -> event 17 then word 0xFFFF2000 := 0xAA55')
    for r4 in (0, 1, 0x1FF, 0xFFFFFF00):
        e = new_emu()
        run(e, 0x01001C, regs={4: r4})
        ok(e.read_u8(0xFFFF5B8D) == (r4 & 0xFF) and nonstack_writes(e) == {0xFFFF5B8D}, 'J')
        print(f'  J  r4={r4:08X} -> byte 0xFFFF5B8D = {r4 & 0xFF:02X}')
    print('J  0x01001C: byte 0xFFFF5B8D := r4')


# ---------------------------------------------------------------- K
def pass_k():
    for ev, stubs, want in ((16, (0x04793C,), [0x04793C]), (17, (0x048732,), [0x048732]),
                            (18, (0x004BCA, 0x01076A), [0x01076A, 0x004BCA])):
        e = new_emu()
        hit = []
        for s in stubs:
            e.stub(s, fn=lambda em, s=s: hit.append(s))
        run(e, 0x00FDB4, regs={4: ev, 5: 0})
        ok(hit == want, f'K event {ev}: {hit}')
        via = {16: 0x00E502, 17: 0x00E508, 18: 0x00E50E}[ev]
        ok(via in e.executed and 0x00DCE4 in e.executed, f'K event {ev} path')
        print(f'  K  0x00FDB4(r4={ev}) -> 0x00DCE4(1, {ev - 15}) -> 0x{via:06X} -> {[hex(x) for x in hit]}')
    rows = [(struct.unpack('>H', ROM[a:a + 2])[0], struct.unpack('>H', ROM[a + 2:a + 4])[0], u32(a + 4))
            for a in range(0x011C10, 0x011C10 + 8 * 5, 8)]
    ok(rows[1] == (0xFFFF, 0x0000, 0x00E502), f'K row 1 {rows[1]}')
    ok(rows[0] == (0xFFFF, 0x0001, 0x00E4FE), f'K row 0 {rows[0]}')
    ok(u32(0x011B9C) == 0x011C10 and u32(0x00DE08) == 0x011B98, 'K table pointers')
    print('K  rows of 0x011C10 (word, word, handler): ' + ', '.join(f'({a:04X},{b:04X},{c:06X})' for a, b, c in rows))
    # event 15 (row 0) with argument 16: reaches the bare rts 0x00E4FE, nothing else
    ok(ROM[0x00E4FE:0x00E502] == bytes.fromhex('000B0009'), 'K 0x00E4FE bytes')
    for arg in (13, 16, 19):
        e = new_emu()
        for s in (0x04793C, 0x048732, 0x01076A, 0x004BCA):
            e.stub(s, fn=lambda em, s=s: (_ for _ in ()).throw(AssertionError(f'K event 15 reached {s:06X}')))
        run(e, 0x00FDB4, regs={4: 15, 5: arg})
        ok(0x00E4FE in e.executed and 0x00E502 not in e.executed and not nonstack_writes(e), f'K event 15 arg {arg}')
    print('  K  0x00FDB4(r4=15, r5=13/16/19) -> 0x00DCE4(1, 0) -> 0x00E4FE (rts / nop); no RAM write')
    # 0x010D58: every value of byte 0xFFFF5BBF
    args15, ids2 = set(), set()
    for init in range(256):
        e = new_emu()
        posts = []
        e.stub(0x00FDB4, fn=lambda em, posts=posts: posts.append((em.R[4] & 0xFFFF, em.R[5] & 0xFFFF)))
        e.ram_u8(0xFFFF5BBF, init)
        e.ram_u16(0xFFFF5BBC, 0x9999)
        run(e, 0x010D58)
        b = (init + 1) & 0xFF
        want = [(5, 0)]
        for i in range(7):
            if (b >> i) & 1:
                want += [(15, ROM[0x011CAF + i]), (ROM[0x011CA8 + i], 0)]
                break
        ok(posts == want, f'K 0x010D58 5BBF={init:02X}: {posts} want {want}')
        ok(e.read_u8(0xFFFF5BBF) == b and e.read_u16(0xFFFF5BBC) == 12, 'K 0x010D58 writes')
        for i_, (a, r5) in enumerate(posts):
            if a == 15:
                args15.add(r5)
                ids2.add(posts[i_ + 1][0])
        ok(all(a != 16 for a, _ in posts), 'K 0x010D58 posts id 16')
    ok(args15 == set(range(13, 20)) and ids2 == set(range(6, 13)), f'K 0x010D58 {args15} {ids2}')
    print(f'  K  0x010D58 over all 256 values of byte 5BBF: posts 5, then (15, arg) with arg in {sorted(args15)} '
          f'and an id in {sorted(ids2)}; id 16 never posted')
    # the two orphan posters: one pass of a loop whose bounds are the same literal; id = ROM long 0
    for at, lit_pc, ptr_pc, tbl, cmp_pc, cmp_w in ((0x010EC4, 0x010F2C, 0x010EC8, 0x011CB8, 0x010EFC, 0x3E96),
                                                   (0x010FFC, 0x011060, 0x011000, 0x011CC0, 0x01102A, 0x3EC6)):
        ws = struct.unpack('>4H', ROM[at:at + 8])
        ok(ws[1] == 0x6E43 and ws[3] in (0x6943, 0x6C43), f'K orphan {at:06X}: r14 and the bound from one literal')
        ok(struct.unpack('>H', ROM[cmp_pc:cmp_pc + 2])[0] == cmp_w and
           struct.unpack('>H', ROM[cmp_pc - 2:cmp_pc])[0] == 0x7E02, f'K orphan {cmp_pc:06X} loop step')
        ok(u32(((ptr_pc + 4) & ~3) + 4 * (ROM[ptr_pc + 1])) == tbl and u32(tbl) == 0, f'K orphan id long {tbl:06X}')
    print(f'  K  0x010E12 / 0x010F4C: one loop pass each; id = long [0x011CB8] = {u32(0x011CB8)}, '
          f'long [0x011CC0] = {u32(0x011CC0)}')


# ---------------------------------------------------------------- L
READERS = [0x047C40, 0x048DB8, 0x048E16, 0x04907C, 0x049A7A, 0x049BA4, 0x049CF0, 0x04A03E, 0x04A420, 0x04A674,
           0x04A6C6, 0x04A6FA, 0x04A94C, 0x04AA58, 0x04AE6A, 0x04AE7C, 0x04AE82, 0x04AED4, 0x04AF12, 0x04AF50,
           0x04AF88, 0x04AF9A, 0x04AFB2, 0x04AFC4, 0x04AFEA, 0x04AFFC, 0x04B0FC, 0x04B124]
PRE = {0x047C40: (0x006B5A, 0x0067DC, 0x05AA74)}
# expected (first call target or 'R' for return) for gate 0x00 / 0x01 / 0xA5 / 0xFF
WANT_L = {
    0x047C40: (0x006BC4, 0x02271C, 0x02271C, 0x022724),
    0x048DB8: (0x058902, 'R', 'R', 'R'), 0x048E16: (0x058918, 0x022720, 0x022720, 0x022728),
    0x04907C: (0x058800, 'R', 'R', 0x072F54), 0x049A7A: (0x04C402, 'R', 'R', 'R'),
    0x049BA4: (0x01FA9C, 'R', 'R', 'R'), 0x049CF0: (0x01F7E0, 0x05AB44, 0x05AB44, 0x021F66),
    0x04A03E: (0x0209DC, 0x05C874, 0x05C874, 0x00317C), 0x04A420: (0x01F6E0, 'R', 'R', 0x027918),
    0x04A674: (0x025FEC, 'R', 'R', 'R'), 0x04A6C6: (0x025D4A, 'R', 'R', 'R'),
    0x04A6FA: (0x023ACE, 'R', 'R', 0x095370), 0x04A94C: (0x043750, 'R', 'R', 'R'),
    0x04AA58: (0x022E36, 'R', 'R', 'R'), 0x04AE6A: (0x0A8518, 'R', 'R', 'R'), 0x04AE7C: ('R', 'R', 'R', 'R'),
    0x04AE82: (0x044132, 'R', 'R', 'R'), 0x04AED4: (0x0758DE, 'R', 'R', 'R'), 0x04AF12: (0x075C4A, 'R', 'R', 'R'),
    0x04AF50: (0x061850, 'R', 'R', 'R'), 0x04AF88: (0x03DC46, 'R', 'R', 'R'), 0x04AF9A: (0x03DCB6, 'R', 'R', 'R'),
    0x04AFB2: (0x023016, 'R', 'R', 'R'), 0x04AFC4: (0x02262C, 'R', 'R', 'R'), 0x04AFEA: (0x01BFEC, 'R', 'R', 'R'),
    0x04AFFC: (0x016776, 'R', 'R', 'R'), 0x04B0FC: (0x006334, 'R', 'R', 'R'), 0x04B124: (0x00631E, 'R', 'R', 'R'),
}


LAST_R4 = [None]
LAST_RAM = [None]
B8320 = 0xFFFF8320
F907C = (0x072F54, 0x0825E4, 0x084E76, 0x095A9A, 0x095E62)


def first_call(entry, gate, seed=None):
    e = new_emu()
    if seed is not None:                         # random RAM everywhere (stack included)
        import random
        rnd = random.Random(seed)
        e.ram[:] = bytes(rnd.getrandbits(8) for _ in range(len(e.ram)))
        e.init[:] = b'\x01' * len(e.init)
    for s in PRE.get(entry, ()):
        e.stub(s, r0=0)
    e.ram_u8(GATE, gate)
    LAST_RAM[0] = e.read_u8(B8320)               # byte 0xFFFF8320 before the run
    e.R[15] = E.STACK_TOP
    e.R[4] = 0xFFFF9000
    e.R[5] = 0
    e.pr = E.RETURN_MAGIC
    e.pc = entry
    for _ in range(5000):
        if e.pc == E.RETURN_MAGIC:
            return 'R', nonstack_writes(e)
        if e.pc in e.stubs:
            r0, fr0, fn = e.stubs[e.pc]
            if fn:
                fn(e)
            if r0 is not None:
                e.R[0] = r0
            e.pc = e.pr
            continue
        w = e.fetch(e.pc)
        n = (w >> 8) & 15
        tgt = None
        if (w & 0xF0FF) in (0x400B, 0x402B):
            tgt = e.R[n]
        elif (w >> 12) == 0xB:
            d = w & 0xFFF
            tgt = e.pc + 4 + 2 * (d - 0x1000 if d & 0x800 else d)
        if tgt is not None and tgt not in e.stubs:
            LAST_R4[0] = e.R[4]
            return tgt, nonstack_writes(e)
        e.step()
    raise AssertionError(f'L {entry:06X}: no call or return')


def pass_l():
    n = 0
    ret_gates = []
    for r in READERS:
        got = []
        for g in (0x00, 0x01, 0xA5, 0xFF):
            t, wr = first_call(r, g)
            got.append(t)
            if r == 0x049CF0 and g in (0x01, 0xA5):
                ok(t == 0x05AB44 and LAST_R4[0] == 1, f'L 0x049CF0 gate {g:02X}: r4 at the jmp {LAST_R4[0]}')
            if t == 'R' and g:
                ok(not wr, f'L {r:06X} gate {g:02X}: wrote {sorted(map(hex, wr))} before returning')
            n += 1
        ok(tuple(got) == WANT_L[r], f'L {r:06X}: {got}')
        if got[1:] == ['R', 'R', 'R']:
            ret_gates.append(r)
        print(f'  L  {r:06X}: ' + '  '.join(f'{g:02X}->' + (x if x == "R" else f'{x:06X}') for g, x in zip((0, 1, 0xA5, 0xFF), got)))
    ok(len(ret_gates) == 21 and 0x04AA58 in ret_gates, f'L return gates {len(ret_gates)}')
    # 0x04AA58: every non-zero value returns without a call or a non-stack write
    for g in range(1, 256):
        t, wr = first_call(0x04AA58, g)
        ok(t == 'R' and not wr, f'L 0x04AA58 gate {g:02X}')
        n += 1
    print('  L  0x049CF0 with gate 0x01 / 0xA5: jmp 0x05AB44 with r4 = 1 (0x049D0C); with 0xFF it calls 0x021F66 first')
    # the non-zero gates again with random RAM: every first action reproduces except 0x04907C at 0xFF,
    # whose first action depends on the low nibble of byte 0xFFFF8320.  (Gate 0x00 is not repeated: there
    # the readers run their bodies, whose first action can depend on RAM -- e.g. 0x04AF50 reads @r4 --
    # so the 0x00 column is a zeroed-RAM observation only.)
    nibble = {0: 0, 1: 0}
    for seed in (11, 22, 33, 44):
        for r in READERS:
            for k, g in ((1, 0x01), (2, 0xA5), (3, 0xFF)):
                t, wr = first_call(r, g, seed)
                want = WANT_L[r][k]
                if r == 0x04907C and g == 0xFF:
                    want = 0x072F54 if (LAST_RAM[0] & 0x0F) == 0 else 'R'
                    if t == 'R':
                        ok(wr == {B8320}, f'L random {seed} 0x04907C FF: wrote {sorted(map(hex, wr))}')
                    nibble[1 if t == 'R' else 0] += 1
                ok(t == want, f'L random seed {seed} {r:06X} gate {g:02X}: {t} want {want}')
                if t == 'R' and g and r != 0x04907C:
                    ok(not wr, f'L random {r:06X} gate {g:02X}: wrote {sorted(map(hex, wr))}')
                n += 1
    print(f'  L  random RAM (4 seeds): all 28 x 3 non-zero-gate first actions as with zeroed RAM, except 0x04907C at 0xFF '
          f'({nibble[0]} runs called 0x072F54, {nibble[1]} returned after writing 0xFFFF8320 only)')
    # 0x04907C to its return: gate 0xFF / 0x01 / 0xA5 x every value of byte 0xFFFF8320
    for g in (0xFF, 0x01, 0xA5):
        for v in range(256):
            e = new_emu()
            seen = []
            for s in F907C:
                e.stub(s, fn=lambda em, s=s, seen=seen: seen.append(s))
            e.ram_u8(GATE, g)
            e.ram_u8(B8320, v)
            run(e, 0x04907C)
            if g == 0xFF:
                ok(seen == (list(F907C) if (v & 0x0F) == 0 else []), f'L 0x04907C FF 8320={v:02X}: calls {seen}')
                ok(e.read_u8(B8320) == (v + 1) & 0xFF and nonstack_writes(e) == {B8320}, f'L 0x04907C FF 8320={v:02X}')
            else:
                ok(seen == [] and not nonstack_writes(e), f'L 0x04907C {g:02X} 8320={v:02X}')
            n += 1
    print('  L  0x04907C gate FF: byte 0xFFFF8320 += 1 on every call; 0x072F54, 0x0825E4, 0x084E76, 0x095A9A, 0x095E62 '
          'called only when (8320 & 0x0F) == 0 (16 of 256 values); gate 01 / A5: returns, no write')
    print(f'L  {n} runs; {len(ret_gates)} readers return at once for every non-zero value, 0x04AA58 among them '
          f'(all 255 non-zero values checked); 3 return for 0x01/0xA5 but take another path for 0xFF '
          f'(0x04907C 0x04A420 0x04A6FA); 4 take other paths for every non-zero value (0x047C40 0x048E16 0x049CF0 0x04A03E)')


# ---------------------------------------------------------------- M
CALLEES = {0x05CB1C: [(0x047964, 'icall')], 0x05CBC8: [(0x048710, 'icall')], 0x04793C: [(0x00E504, 'ijump')],
           0x00E51C: [(0x00DF80, 'call')], 0x010124: [(0x00E520, 'icall')], 0x010198: [(0x00E104, 'icall')],
           0x01001C: [(0x047B62, 'ijump')], 0x00E502: [], 0x0486EE: [(0x00E266, 'icall')],
           0x010E12: [], 0x010F4C: [], 0x010022: [], 0x00FDB4: None,
           # kernel start and the task-10 order (pass N, pass H)
           0x00387C: [(0x0036F4, 'icall')], 0x0036C4: [(0x00334C, 'ijump')], 0x003324: [(0x00FAC2, 'icall')],
           0x00FA5A: [(0x00FA52, 'call')], 0x00FA34: [], 0x003206: [(0x002F18, 'icall'), (0x0038C0, 'icall')],
           0x0100E4: [(0x00DF28, 'icall')],
           # the byte 0xFFFFACF6 path inside 0x04793C (pass G)
           0x0951F8: [(0x047958, 'icall')], 0x09148E: [(0x09520C, 'ijump')]}
# 0x00FDB4: only the id-16 post is asserted (below), not the full call-site list
FDB4_UNKNOWN = [(0x010D9E, '0x010D58'), (0x010EF2, '0x010E12'), (0x011024, '0x010F4C')]


def store_of(w):
    op = w >> 12; n = (w >> 8) & 15; m = (w >> 4) & 15; d = w & 15
    if op == 2 and d in (0, 1, 2): return (1 << d, n, 0, False, False, False)
    if op == 2 and d in (4, 5, 6): return (1 << (d - 4), n, -(1 << (d - 4)), False, False, True)
    if op == 1: return (4, n, d * 4, False, False, False)
    if op == 8 and n == 0: return (1, m, d, False, False, False)
    if op == 8 and n == 1: return (2, m, d * 2, False, False, False)
    if op == 0 and d in (4, 5, 6): return (1 << (d - 4), n, 0, True, False, False)
    if op == 0xC and n in (0, 1, 2): return (1 << n, None, (w & 0xFF) << n, False, True, False)
    if op == 0xC and n in (0xD, 0xE, 0xF): return (1, None, 0, True, True, False)
    if op == 0xF and d == 0xA: return (4, n, 0, False, False, False)
    if op == 0xF and d == 0xB: return (4, n, -4, False, False, True)
    if op == 0xF and d == 0x7: return (4, n, 0, True, False, False)
    if op == 4 and (w & 0xFF) in (0x02, 0x12, 0x22, 0x52, 0x62, 0x03, 0x13, 0x23): return (4, n, -4, False, False, True)
    if op == 4 and (w & 0xFF) == 0x1B: return (1, n, 0, False, False, False)
    return None


def load_of(w):
    op = w >> 12; n = (w >> 8) & 15; m = (w >> 4) & 15; d = w & 15
    if op == 6 and d in (0, 1, 2, 4, 5, 6): return (1 << (d & 3), m, 0, False, False)
    if op == 5: return (4, m, d * 4, False, False)
    if op == 8 and n == 4: return (1, m, d, False, False)
    if op == 8 and n == 5: return (2, m, d * 2, False, False)
    if op == 0 and d in (0xC, 0xD, 0xE): return (1 << (d - 0xC), m, 0, True, False)
    if op == 0xC and n in (4, 5, 6): return (1 << (n - 4), None, (w & 0xFF) << (n - 4), False, True)
    if op == 0xC and n in (0xC, 0xD, 0xE, 0xF): return (1, None, 0, True, True)
    if op == 0xF and d in (8, 9): return (4, m, 0, False, False)
    if op == 0xF and d == 6: return (4, m, 0, True, False)
    return None


def pass_m():
    cen = json.load(open(os.path.join(REPO, 'disassembly', 'maps', 'function_census.json')))['functions']
    stores, loads, args = [], [], []
    callsites = {}
    fdb4 = []
    dce4 = []
    n_st = n_unres = 0
    for f in cen:
        ent = int(f['entry'], 16)
        gb = [int(x, 16) for x in f['gbr']]
        st = fc.reg_states(ROM, ent)
        for (pc, role), R in st.items():
            if pc < 0 or pc + 2 > len(ROM):
                continue
            w = struct.unpack('>H', ROM[pc:pc + 2])[0]
            kind, ktgt, _ = fc.flow_of(w, pc)
            if role is None and kind in ('call', 'jump', 'icall', 'ijump'):
                if kind in ('call', 'jump'):
                    tg = {ktgt}
                elif ktgt is not None and R[ktgt] is not None:
                    tg = set(R[ktgt])
                else:
                    tg = set()
                for t_ in tg:
                    if t_ in CALLEES:
                        callsites.setdefault(t_, set()).add((pc, kind))
                    if t_ == 0x00FDB4:
                        a4 = fc.call_args(ROM, st, pc)
                        fdb4.append((pc, f['entry'], None if a4 is None or a4[4] is None else frozenset(a4[4])))
                    if t_ == 0x00DCE4:
                        a4 = fc.call_args(ROM, st, pc)
                        dce4.append((pc, None if a4 is None or a4[4] is None else frozenset(a4[4]),
                                     None if a4 is None or a4[5] is None else frozenset(a4[5])))
            if kind in ('call', 'icall') and role is None:
                a = fc.call_args(ROM, st, pc)
                if a:
                    for r in (4, 5, 6, 7):
                        if a[r] is not None:
                            for v in a[r]:
                                args.append((pc, f['entry'], r, v))
            for tab, dec in ((stores, store_of), (loads, load_of)):
                s = dec(w)
                if s is None:
                    continue
                size, bn, disp, ur0, isg = s[:5]
                if tab is stores:
                    if s[5] and bn == 15:
                        continue
                    n_st += 1
                bases = (set(gb) if gb else None) if isg else R[bn]
                offs = {0}
                if ur0:
                    offs = set(R[0]) if R[0] is not None else None
                if bases is None or offs is None:
                    if tab is stores:
                        n_unres += 1
                    continue
                for b in bases:
                    for o in offs:
                        tab.append((pc, f['entry'], size, (b + o + disp) & 0xFFFFFFFF))

    def covering(tab, lo, hi):
        return sorted({(pc, fn, sz, a) for pc, fn, sz, a in tab if a <= hi and a + sz - 1 >= lo})
    wr = covering(stores, GATE, GATE + 1)
    ok([(p, s, a) for p, _, s, a in wr] == [(0x05CB50, 2, GATE), (0x05CBE6, 2, GATE)], f'M writers {wr}')
    rd = covering(loads, GATE, GATE + 1)
    rd_fns = sorted({int(fn, 16) for p, fn, s, a in rd})
    ok(all(s == 1 and a == GATE for p, fn, s, a in rd), 'M every resolved read of 8EDC/8EDD is a byte read of 8EDC')
    ok(rd_fns == sorted(READERS + [0x05CB1C, 0x05CBC8]), f'M reader functions {[hex(x) for x in rd_fns]}')
    ar = sorted({(p, r) for p, fn, r, v in args if v == GATE})
    ok(ar == [(0x05CBCE, 4)], f'M pointer args {ar}')
    print(f'M  {n_st} stores examined, {n_unres} with base/index not statically known')
    print(f'M  resolved stores covering 0xFFFF8EDC..8EDD: {[(hex(p), fn, s) for p, fn, s, a in wr]}')
    print(f'M  resolved loads: {len(rd)} sites in {len(rd_fns)} functions, all byte reads of 0xFFFF8EDC; '
          f'pointer argument 0xFFFF8EDC only at {[(hex(p), "r%d" % r) for p, r in ar]} (-> 0x0BE980, read-only)')
    for lo, hi, want in ((W8ECC, W8ECC + 1, [0x05B6C8]), (0xFFFF8EDA, 0xFFFF8EDA, [0x05B676]),
                         (0xFFFF8EE8, 0xFFFF8EE8, [0x05B6B6]), (LIM, LIM, [0x05B796, 0x05B7A8]),
                         (SH8EF6, SH8EF6, [0x05B6CC, 0x05CCB6]), (GATE_SH, GATE_SH, [0x05CB5A, 0x05CBEE]),
                         (CNT, CNT, [0x05B27E, 0x05B7EA, 0x05C998]), (0xFFFF8EF1, 0xFFFF8EF1, [0x05B62E, 0x05B63A]),
                         (0xFFFF2000, 0xFFFF2001, [0x010028, 0x01018A, 0x0101B2]),
                         (0xFFFF5B8D, 0xFFFF5B8D, [0x010020, 0x0100EA, 0x01013A]),
                         (0xFFFFACF6, 0xFFFFACF6, [0x0914AE])):
        got = sorted({p for p, fn, s, a in covering(stores, lo, hi)})
        ok(got == want, f'M writers of {lo:08X}: {[hex(x) for x in got]}')
        print(f'  M  resolved writers of {lo:08X}..{hi:08X}: {[hex(x) for x in got]}')
    posts16 = sorted({pc for pc, fn, r4 in fdb4 if r4 is not None and 16 in {x & 0xFFFF for x in r4}})
    unknown = sorted({(pc, fn) for pc, fn, r4 in fdb4 if r4 is None})
    ok(posts16 == [0x010148], f'M id-16 posts {[hex(x) for x in posts16]}')
    # 0x00DCE4: only 0x00FDE0 (inside 0x00FDB4) passes table 1; every other resolved site passes 0 or 2
    t1 = sorted({pc for pc, r4, r5 in dce4 if r4 is not None and 1 in r4})
    other = {x for pc, r4, r5 in dce4 if pc != 0x00FDE0 and r4 is not None for x in r4}
    ok(t1 == [0x00FDE0] and other <= {0, 2} and all(r4 is not None for pc, r4, r5 in dce4),
       f'M 0x00DCE4 table args {t1} {other}')
    print(f'  M  0x00DCE4: {len({pc for pc, _, _ in dce4})} resolved call sites; table 1 only at 0x00FDE0; '
          f'the others pass table {sorted(other)}')
    # every (table, row) a resolved call reaches: first word 0xFFFF (direct call) or 0..3 (0x00F870 row,
    # whose activation id is word +4 of row [0x011BA4 + 8*first] = 1..4 -- never 10)
    pairs = {(t, r) for pc, r4, r5 in dce4 if pc != 0x00FDE0 and r5 is not None for t in r4 for r in r5}
    ok(all(r5 is not None for pc, r4, r5 in dce4 if pc != 0x00FDE0), 'M 0x00DCE4 row args')
    pairs |= {(1, (x & 0xFFFF) - 15) for pc, fn, r4 in fdb4 if r4 is not None for x in r4 if (x & 0xFFFF) >= 15}
    firsts = {}
    for t, r in sorted(pairs):
        fw = h16(u32(0x011B98 + 4 * t) + 8 * r)
        firsts[(t, r)] = fw
        ok(fw == 0xFFFF or fw <= 3, f'M row ({t},{r}) first word {fw:04X}')
    ids = sorted({h16(0x011BA4 + 8 * fw + 4) for fw in firsts.values() if fw != 0xFFFF})
    ok(ids and set(ids) <= {1, 2, 3, 4}, f'M 0x00F870 ids {ids}')
    print(f'  M  {len(pairs)} (table, row) pairs reached by resolved posts / calls: first words '
          f'{sorted({f"{v:X}" for v in firsts.values()})}; ids 0x00F870 can activate from them: {ids}')
    # 0xFFFFEC00..0xFFFFECFF: every resolved store, and every PC-relative literal in the image
    ec = sorted({(pc, fn, sz, a) for pc, fn, sz, a in stores if a <= 0xFFFFECFF and a + sz - 1 >= 0xFFFFEC00})
    hi = [(pc, fn, a) for pc, fn, sz, a in ec if a >= 0xFFFFECB0]
    in_398 = sorted((pc, a) for pc, fn, a in hi if fn == '0x010398')
    ok(in_398 == [(0x0103BC, 0xFFFFECB0), (0x0103D8, 0xFFFFECC0), (0x0103DE, 0xFFFFECC4), (0x0103E4, 0xFFFFECCE),
                  (0x0103EA, 0xFFFFECCC), (0x010402, 0xFFFFECC8), (0x010414, 0xFFFFECCC), (0x010432, 0xFFFFECCC)],
       f'M 0x010398 register stores {in_398}')
    out = sorted((pc, a) for pc, fn, a in hi if fn != '0x010398')
    ok(out == [(0x00129E, 0xFFFFECB0), (0x00B07E, 0xFFFFECB0), (0x00B9FE, 0xFFFFECB0), (0x00E816, 0xFFFFECB0),
               (0x00E940, 0xFFFFECCC),
               (0x00E94E, 0xFFFFECDC), (0x00E95C, 0xFFFFECEC), (0x00E96A, 0xFFFFECFC)], f'M EC stores elsewhere {out}')
    for pc in (0x00E940, 0x00E94E, 0x00E95C, 0x00E96A):     # each: r1 = u32[P] & -3 (bit 1 cleared)
        ok(struct.unpack('>3H', ROM[pc - 4:pc + 2]) == (0x6132, 0x2129, 0x2312), f'M {pc:06X} and-mask store')
        win = ROM[pc - 8:pc]
        ok(b'\xe2\xfd' in win, f'M {pc:06X}: mov #-3 before the store')
    lits = []
    for pc in range(0, len(ROM) - 1, 2):
        w = struct.unpack('>H', ROM[pc:pc + 2])[0]
        if (w >> 12) == 9:
            v = struct.unpack('>h', ROM[pc + 4 + 2 * (w & 0xFF):pc + 6 + 2 * (w & 0xFF)])[0] & 0xFFFFFFFF
        elif (w >> 12) == 0xD:
            a = ((pc + 4) & ~3) + 4 * (w & 0xFF)
            if a + 4 > len(ROM):
                continue
            v = u32(a)
        else:
            continue
        if 0xFFFFECC0 <= v <= 0xFFFFECFF and (v & 0xF) < 0xC:
            lits.append((pc, v))
    ok(lits == [(0x0103D6, 0xFFFFECC0), (0x0103DC, 0xFFFFECC4), (0x0103FC, 0xFFFFECC8)], f'M EC literals {lits}')
    print(f'  M  0xFFFFECB0..ECFF: 0x010398 stores {[(hex(p), hex(a)) for p, a in in_398]}; elsewhere only '
          f'{[(hex(p), hex(a)) for p, a in out]} (the ECxC ones clear bit 1); a PC-relative literal of '
          f'0xFFFFECC0..ECCB / ECD0..ECDB / ECE0..ECEB / ECF0..ECFB occurs only at {[hex(p) for p, v in lits]}')
    ok(unknown == FDB4_UNKNOWN, f'M 0x00FDB4 sites with unknown id {[(hex(a), f) for a, f in unknown]}')
    print(f'  M  calls / jumps to 0x00FDB4: {len(set(fdb4))}; constant id 16 only at {[hex(x) for x in posts16]}; '
          f'id not constant at {[(hex(a), f) for a, f in unknown]}')
    for t_, want in sorted(CALLEES.items()):
        got = sorted(callsites.get(t_, set()))
        if want is None:
            continue
        ok(got == want, f'M call sites of {t_:06X}: {[(hex(a), k) for a, k in got]}')
        print(f'  M  every resolved call / jump to 0x{t_:06X}: {[(hex(a), k) for a, k in got]}')
    # reachability
    def longs(v):
        b = struct.pack('>I', v)
        out, i = [], 0
        while True:
            i = ROM.find(b, i)
            if i < 0:
                return out
            out.append(i)
            i += 1
    for v, want in ((0x05CB1C, [0x047B88]), (0x04793C, [0x00E640]), (0x00E502, [0x011C1C]),
                    (0x010124, [0x00E650]), (0x010E12, []), (0x010F4C, []), (0x010022, []), (0x05CBC8, [0x0488A0])):
        ok(longs(v) == want, f'M longs {v:06X}: {[hex(x) for x in longs(v)]}')
        print(f'  M  aligned or not, the long 0x{v:08X} occurs at {[hex(x) for x in longs(v)]}')
    ok(list(ROM[0x011CA8:0x011CAF]) == list(range(6, 13)) and list(ROM[0x011CAF:0x011CB6]) == list(range(13, 20)),
       'M id bytes')
    ok(u32(0x011CDC) == 0xFFFF2000 and u32(0x011CE0) == 0xFFFF3FFF and u32(0x011CE4) == 0xFFFF4000
       and u32(0x011CE8) == 0xFFFFBF9F and u32(0x0FFFF8) == 0x00FA34, 'M range longs')
    # task 10 activation: the seven constant ids at 0x002EDC call sites, and the rows of 0x011BA4
    ids = []
    for site, want_id in ((0x00FE6C, 7), (0x00FE9E, 8), (0x00FEFC, 11), (0x00FF2E, 9), (0x00FF60, 12),
                          (0x00FF94, 5), (0x00FFD0, 6)):
        w = struct.unpack('>H', ROM[site + 2:site + 4])[0]
        ok(w >> 8 == 0xE4 and (w & 0xFF) == want_id, f'M activation id at {site:06X}')
        ids.append(want_id)
    rows = [struct.unpack('>H', ROM[a + 4:a + 6])[0] for a in range(0x011BA4, 0x011BC4, 8)]
    ok(rows == [1, 2, 3, 4], f'M 0x011BA4 rows {rows}')
    ok(u32(0x003F84 + 16 * 10 + 8) == 0x00DF14, 'M task 10 entry')
    print(f'  M  constant ids passed to 0x002EDC: {ids}; ids in rows of 0x011BA4 (used by 0x00F870): {rows}; '
          f'task 10 entry {u32(0x003F84 + 16 * 10 + 8):#08x}')
    # calibration across every bin under rom/
    bins = sorted(glob.glob(os.path.join(REPO, 'rom', '*.bin')))
    vals = set()
    for b in bins:
        r = open(b, 'rb').read()
        if len(r) != len(ROM):
            continue
        vals.add((r[0x0C47BF:0x0C47C2], r[0x0C5658:0x0C5660], r[0x05CB1C:0x05CB5C], r[0x05B5D8:0x05B7FA],
                  r[0x05CBC8:0x05CCC0]))
    ok(len(vals) == 1, 'M cal/code differs between bins')
    print(f'  M  cal 0x0C47BF..C1 = {CAL_LIM}, f32 0x0C5658 = {CAL_T1}, 0x0C565C = {CAL_T2}; identical (with the code '
          f'0x05B5D8..0x05B7FA, 0x05CB1C..0x05CB5C, 0x05CBC8..0x05CCC0) in all {len(bins)} bins')


# ---------------------------------------------------------------- N
KCB = 0xFFFF1288


def h16(a): return struct.unpack('>H', ROM[a:a + 2])[0]


def pass_n():
    n = 0
    # the autostart lists: count word [0x00408C + 2*k] and list pointer [0x004088 + 4*k], k = byte [KCB+1]
    ok(u32(0x004088) == 0x004084 and h16(0x00408C) == 2 and h16(0x004084) == 0 and h16(0x004086) == 10,
       'N list for index 0')
    ok(h16(0x00408E) == 0, 'N count for index 1')
    for k in (0, 1):
        e = new_emu()
        q = []
        e.stub(0x003206, fn=lambda em, q=q: q.append((em.R[4], em.R[5] & 0xFFFF, em.R[6] & 0xFF)))
        e.ram_u8(KCB + 1, k)
        for tid in range(13):
            e.ram_u32(u32(0x003F84 + 16 * tid + 4), 0x04000003)      # RAM record: byte +3 = 3
        run(e, 0x00387C, regs={4: KCB})
        want = [(KCB, 0, ROM[0x003F84 + 2]), (KCB, 10, ROM[0x003F84 + 16 * 10 + 2])] if k == 0 else []
        ok(q == want, f'N 0x00387C index {k}: {q} want {want}')
        dec = sorted(tid for tid in range(13) if e.read_u8(u32(0x003F84 + 16 * tid + 4) + 3) != 3)
        ok(dec == ([0, 10] if k == 0 else []), f'N 0x00387C index {k}: byte +3 decremented for {dec}')
        print(f'  N  0x00387C with byte [KCB+1] = {k}: 0x003206 called for (id, ready index) '
              f'{[(t, i) for _, t, i in q]}; RAM record byte +3 decremented for ids {dec}')
        n += 1
    # the only path to it: 0x00FA34 (long at 0x0FFFF8) bsr 0x00FA5A; 0x00FAC2 jsr 0x003324 with r4 = 0
    ok(u32(0x0FFFF8) == 0x00FA34 and fc.flow_of(h16(0x00FA52), 0x00FA52)[:2] == ('call', 0x00FA5A), 'N reset entry')
    ok(h16(0x00FAC2) == 0x420B and h16(0x00FAC4) == 0xE400 and u32(0x00FD00) == 0x003324, 'N 0x00FAC2 r4 = 0')
    # 0x003324: r4 = exts.b r4; returns 0 unless r4 < byte [0x003F1C] (cmp/hs r0,r4: T when r4 >= r0);
    # then nothing writes r4 before jmp 0x0036C4
    ok(ROM[0x003F1C] == 1 and h16(0x00332A) == 0x3402 and h16(0x00332C) == 0x8B01, 'N 0x003324 bound')
    for pc in range(0x003332, 0x003350, 2):
        ok(4 not in fc.writes(h16(pc)), f'N 0x003324 writes r4 at {pc:06X}')
    ok(u32(0x003360) == 0x0036C4 and h16(0x00334C) == 0x402B, 'N jmp 0x0036C4')
    # 0x0036C4: 0x0036C6 r0 = r4; nothing writes r0 before 0x0036D2 mov.b r0,@(1,r14); r14 = KCB
    ok(h16(0x0036C6) == 0x6043 and h16(0x0036D2) == 0x80E1 and u32(0x003734) == KCB, 'N KCB+1 := r4')
    for pc in range(0x0036C8, 0x0036D2, 2):
        ok(0 not in fc.writes(h16(pc)), f'N r0 written at {pc:06X}')
    ok(h16(0x0036F4) == 0x420B and h16(0x0036F6) == 0x64E3 and u32(0x00374C) == 0x00387C, 'N 0x0036F4 jsr 0x00387C')
    # 0x0035A4 (every task entry ends in it): byte +0 of the running task's RAM record := 0, ring entry removed
    ok(h16(0x0035A8) == 0x5DE5 and h16(0x0035D0) == 0xE200 and h16(0x0035D4) == 0x2D20 and
       h16(0x0035CC) == 0x430B and u32(0x0035F0) == 0x003274, 'N 0x0035A4')
    for pc in range(0x0035AA, 0x0035D4, 2):
        ok(13 not in fc.writes(h16(pc)), f'N r13 written at {pc:06X}')
    print('  N  0x00FA34 -> 0x00FA5A -> 0x00FAC2 0x003324(r4 = 0) -> 0x00334C jmp 0x0036C4 -> 0x0036D2 byte [KCB+1] := 0 '
          '-> 0x0036F4 0x00387C(KCB): ids 0 and 10 queued; byte [0x003F1C] = 1 lets r4 = 0 through')
    print(f'N  kernel start: {n} emulated runs of 0x00387C, path bytes asserted')


def main():
    passes = dict(A=pass_a, B=pass_b, C=pass_c, D=pass_d, E=pass_e, F=pass_f, G=pass_g, H=pass_h, IJ=pass_ij,
                  K=pass_k, L=pass_l, M=pass_m, N=pass_n)
    pick = [a.upper() for a in sys.argv[1:]] or list(passes)     # default: every pass
    for k in pick:
        passes[k]()
    print(f'ALL PASSES OK  ({NCHECK} assertions)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
