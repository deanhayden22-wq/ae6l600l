#!/usr/bin/env python3
"""Shape proof + emulation of small-function shape classes 0..29 (983 functions).

    python3 scripts/trace/emu_stub_shapes_a.py            # prove + emulate + assert, exit 0;
                                                          # prints the summary and the ';' member map
    python3 scripts/trace/emu_stub_shapes_a.py --quiet    # summary lines only

Companion to disassembly/analysis/stub_shapes_a_trace.txt (2026-11-27).

INPUT
  disassembly/maps/stub_classes.json classes 0..29 gives the MEMBER LISTS only (it is a
  claim: that these functions share one shape).  disassembly/maps/function_census.json gives
  each member's extent and its caller list.  Nothing else is read from any derived file; no
  label is read at all.

WHAT IT PROVES (each is an assert; exit 0 only if all hold)
  A. SHAPE.  Every member is re-decoded from ROM bytes with scripts/sh2e_disasm.py over its
     census extent.  Each word is masked by this script's OWN rule (PC-relative displacement,
     8-bit immediate, bra/bsr displacement, mova / GBR / logic-immediate displacement, 4-bit
     struct displacement -- conditional-branch displacements are kept as structure) and the
     literal each PC-relative load reads is reduced to RAM / PERIPH / LOW (< 0x100000) /
     OTHER.  The masked tuple must equal the class example's.  A member that differs is
     REPORTED and REMOVED (none is, at the time of writing).  The extent must be contiguous:
     census end - entry == 2 * insns.
  B. PARAMETERS.  The masked fields are read back per member (literal values, immediates,
     branch targets, the float a mova reads, displacements) and named per class.
  C. EMULATION.  Every surviving member is run in scripts/sh2e_emu.py (subclassed here only
     to log peripheral reads/writes -- the base emulator raises on them) against a Python
     model of the class contract written from the example's decode.  Inputs exercise both
     outcomes of every compare: all 256 values of every byte a member tests; both planted
     values of every peripheral read; random register state on entry (seeded, deterministic)
     so a dependence on an unset register would show.  Callees are STUBBED (recorded) except
     the two library leaves 0x0BE9A0 and 0x0BE5A8, which are RUN for real.
  D. CROSS-CHECK (bytes only).  For the 118 interrupt stubs (class 1), the vector slot
     0x000FFC50 + 4*v that holds each stub's address is found (exactly one each); the
     118 slots lie inside v = 64..231 but do NOT fill it -- the other 50 slots in that
     range are asserted to hold 0x0000E852 (47) or 0x00F3F2 / 0x00F460 / 0x00F6E6
     (v = 184 / 186 / 224).  For the handler classes (13 / 15 / 22 / 27 / 28) the r4 number
     passed to 0x00E774 is compared with the slot number of the stub that jumps to it.
  E. REVIEW CHECKS (added when the adversarial review was decided, 2026-11-27).  Facts
     about NON-members that the trace's comparison section now relies on: 0x05850E and
     0x05DCAE (r4-indexed reads of 0xFFFFAD52), 0x055FB8 (second writer of 0xFFFF3474),
     0x0281DC (13-instruction two-byte reader), the 0x004CCA / 0x009106 call literals, and
     the 17 bytes of 0xFFFF9704..0xFFFF9742 that no class-7 member reads.

  Since the review the tests also assert: T / S / Q / M / FPUL / fr0-fr15 unchanged where a
  contract says "nothing changes" (classes 0, 2, 6, 9); every RAM read (logged, stack
  included) for classes 9, 14, 25; the library clobbers of 0x0BE9A0 / 0x0BE5A8 (classes
  9, 14, 25); and, for the call chains (4 / 12 / 17 / 23), stubbed callees that LEAVE new
  random r0-r14 / fr0-fr15 / T, so "the next callee receives what the previous one left"
  is exercised rather than vacuous.

WHAT IT CANNOT SHOW
  * What any RAM byte or peripheral register MEANS.  Addresses only.
  * The behaviour of the callees it stubs (0x002B8C, 0x00E774, the bsr / bra / jmp targets).
  * ftrc of NaN / Inf / out-of-int32 values: no input here reaches them.
  * Float results are compared only where the exact rational result is > 1e-3 away from a
    rounding boundary of 0x0BE5A8.  That guard is NOT a last-bit guard at large magnitude
    (at x/C ~ 1e6 a float32 ulp is ~0.06), but every such input clamps to 255, so no
    asserted r0 depends on the last bit of a float; fr2 / fr4 are compared to 1e-6 relative
    and FPUL exactly only below |x/C| = 1e5.
"""
import hashlib
import json
import math
import os
import random
import struct
import sys
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, 'scripts'))
import sh2e_emu as E                     # noqa: E402
from sh2e_disasm import decode           # noqa: E402

ROM_PATH = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
ROM_MD5 = '92cae8275cd4f9b473a3a9e36efe6449'
CLASSES_JSON = os.path.join(REPO, 'disassembly', 'maps', 'stub_classes.json')
CENSUS_JSON = os.path.join(REPO, 'disassembly', 'maps', 'function_census.json')
CLASS_IDS = range(0, 30)

M32 = 0xFFFFFFFF
RAM_LO, RAM_HI = 0xFFFF0000, 0xFFFFC000
PERIPH_LO = 0xFFFFE000
S = E.STACK_TOP
MAGIC = E.RETURN_MAGIC
VBR_TABLE = 0x000FFC50          # vector table base (0x00FA40 ldc ..,vbr; rtos_core_trace CONTRACT)
LIB_PAIR = 0x0BE9A0             # library: r0 = (v << 8) | (~v & 0xFF)   (helpers_wrap_trace)
LIB_F2U8 = 0x0BE5A8             # library: r0 = clamp(trunc((fr4-fr6)/fr5 + 0.5), 0, 255)
TRAP = 0x00E774


# --------------------------------------------------------------------------- bytes
with open(ROM_PATH, 'rb') as _fh:
    ROM = _fh.read()
assert hashlib.md5(ROM).hexdigest() == ROM_MD5, 'reference bin md5 mismatch'


def u16(a):
    return int.from_bytes(ROM[a:a + 2], 'big')


def u32(a):
    return int.from_bytes(ROM[a:a + 4], 'big')


def sx(v, bits):
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


def f32(bits):
    return struct.unpack('>f', struct.pack('>I', bits))[0]


def aclass(v):
    v &= M32
    if RAM_LO <= v < RAM_HI:
        return 'RAM'
    if v >= PERIPH_LO:
        return 'PERIPH'
    if v < 0x100000:
        return 'LOW'
    return 'OTHER'


def lit_l_addr(pc, w):
    return ((pc + 4) & ~3) + (w & 0xFF) * 4


def lit_w_addr(pc, w):
    return pc + 4 + (w & 0xFF) * 2


def br12(pc, w):
    return pc + 4 + sx(w & 0xFFF, 12) * 2


# --------------------------------------------------------------------------- A. shape
def mask(pc, w):
    """(masked word, literal class) -- this script's own masking rule."""
    op, sub = w >> 12, (w >> 8) & 0xF
    if op == 0xD:
        return w & 0xFF00, aclass(u32(lit_l_addr(pc, w)))
    if op == 0x9:
        return w & 0xFF00, aclass(sx(u16(lit_w_addr(pc, w)), 16))
    if op in (0xE, 0x7, 0xC):
        return w & 0xFF00, None
    if op in (0xA, 0xB):
        return w & 0xF000, None
    if op == 0x8:
        if sub in (0x0, 0x1, 0x4, 0x5):
            return w & 0xFFF0, None
        if sub == 0x8:
            return w & 0xFF00, None
        return w, None                     # bt / bf / bt/s / bf/s: structure, kept
    if op in (0x1, 0x5):
        return w & 0xFFF0, None
    return w, None


def params_seq(entry, n):
    """The masked fields, in instruction order, as (kind, value)."""
    out = []
    for i in range(n):
        pc = entry + 2 * i
        w = u16(pc)
        op, sub = w >> 12, (w >> 8) & 0xF
        if op == 0xD:
            out.append(('L', u32(lit_l_addr(pc, w))))
        elif op == 0x9:
            out.append(('W', sx(u16(lit_w_addr(pc, w)), 16) & M32))
        elif op in (0xE, 0x7):
            out.append(('I', sx(w & 0xFF, 8)))
        elif op in (0xA, 0xB):
            out.append(('B', br12(pc, w)))
        elif op == 0xC and sub == 0x7:
            a = lit_l_addr(pc, w)
            out.append(('F', (a, u32(a))))
        elif op == 0xC:
            out.append(('U', w & 0xFF))     # tst / and / xor / or #imm: zero-extended
        elif op == 0x8 and sub == 0x8:
            out.append(('I', sx(w & 0xFF, 8)))   # cmp/eq #imm: sign-extended
        elif op == 0x8 and sub in (0x0, 0x4):
            out.append(('D', w & 0xF))           # byte displacement
        elif op == 0x8 and sub in (0x1, 0x5):
            out.append(('D', (w & 0xF) * 2))
        elif op in (0x1, 0x5):
            out.append(('D', (w & 0xF) * 4))
    return out


# names of the parameters, per class, in the order params_seq yields them
NAMES = {
    0: ['T'], 1: ['K2B8C', 'H'], 2: [], 3: ['K'], 4: ['A', 'B'], 5: ['K', 'M', 'X'],
    6: ['I'], 7: ['K', 'A', 'B'], 8: ['I', 'K'], 9: ['F', 'I', 'K'], 10: ['K', 'I'],
    11: ['T'], 12: ['A', 'B', 'C'], 13: ['P', 'V', 'T', 'N'], 14: ['K', 'F', 'C'],
    15: ['P', 'V', 'N', 'T'], 16: ['D', 'D2'], 17: ['A', 'B', 'C', 'D'], 18: ['K'],
    19: ['K'], 20: ['T'], 21: ['K'], 22: ['P', 'V', 'N', 'T'],
    23: ['A', 'B', 'C', 'D', 'E'], 24: ['I', 'K'], 25: ['F', 'C'], 26: ['A', 'B'],
    27: ['P', 'V', 'ADD', 'T', 'N'], 28: ['N', 'T'], 29: ['I', 'K', 'D'],
}


def load_members():
    with open(CLASSES_JSON) as fh:
        classes = json.load(fh)
    with open(CENSUS_JSON) as fh:
        census = {int(f['entry'], 16): f for f in json.load(fh)['functions']}
    out = {}
    for c in classes:
        if c['id'] in CLASS_IDS:
            out[c['id']] = c
    return out, census


def shape_of(entry, n):
    return tuple(mask(entry + 2 * i, u16(entry + 2 * i)) for i in range(n))


# --------------------------------------------------------------------------- emulator
class Emu(E.Emu):
    """sh2e_emu.Emu with peripheral space (>= 0xFFFFE000) logged instead of raising,
    and every RAM read logged (address, size) in ram_reads -- stack reads included."""

    def __init__(self, rom, pvals=None):
        super().__init__(rom)
        self.pvals = dict(pvals or {})
        self.preads, self.pwrites = [], []
        self.ram_reads = []

    def read(self, a, n):
        a &= M32
        if a >= PERIPH_LO:
            if n > 1 and a % n:
                raise E.EmuError(f'misaligned peripheral read {a:#x}')
            self.preads.append((a, n))
            return self.pvals.get(a, 0) & ((1 << (8 * n)) - 1)
        if RAM_LO <= a < RAM_HI:
            self.ram_reads.append((a, n))
        return super().read(a, n)

    def write(self, a, n, v):
        a &= M32
        if a >= PERIPH_LO:
            if n > 1 and a % n:
                raise E.EmuError(f'misaligned peripheral write {a:#x}')
            self.pwrites.append((a, n, v & ((1 << (8 * n)) - 1)))
            return
        return super().write(a, n, v)


def rand_regs(rng):
    regs = {k: rng.getrandbits(32) for k in range(15)}
    fregs = {k: rng.uniform(-1e4, 1e4) for k in range(16)}
    return regs, fregs


def fresh(rng, pvals=None):
    """A new emulator with random r0-r14 / fr0-fr15 (applied by call()) and random
    T / S / Q / M / FPUL set here, so a test can tell whether a flag was changed."""
    emu = Emu(ROM, pvals)
    regs, fregs = rand_regs(rng)
    emu.T, emu.S, emu.Q, emu.M = (rng.getrandbits(1) for _ in range(4))
    emu.fpul = rng.getrandbits(32)
    return emu, regs, fregs


def flags(emu):
    """Everything besides r0-r15 / PR that a 'nothing changes' claim covers."""
    return (emu.T, emu.S, emu.Q, emu.M, emu.fpul, emu.gbr, emu.mach, emu.macl, tuple(emu.FR))


def recorder(log):
    def fn(emu):
        log.append(dict(pc=emu.pc, pr=emu.pr, r15=emu.R[15], R=list(emu.R),
                        top=emu.read_u32(emu.R[15]) if emu.R[15] < S else None,
                        flags=flags(emu)))
    return fn


def no_ram_writes(emu, allowed=()):
    bad = sorted(set(emu.writes) - set(allowed))
    assert not bad, f'unexpected RAM writes {[hex(a) for a in bad]}'


def stack_only_reads(emu):
    """True if every RAM read was of the stack area the function itself pushed."""
    return all(S - 64 <= a < S for a, _ in emu.ram_reads)


# --------------------------------------------------------------------------- C. tests
# each returns the number of emulated cases; asserts on any mismatch

def t_bra(e, p, rng):                                    # class 0
    T = p['T']
    emu, regs, fregs = fresh(rng)
    if T == e:                                           # bra to itself
        emu.R[15] = S
        for k, v in regs.items():
            emu.R[k] = v
        for k, v in fregs.items():
            emu.set_fr(k, v)
        before = flags(emu)
        emu.pr, emu.pc = MAGIC, e
        for _ in range(40):
            emu.step()
            assert emu.pc == e, f'{e:06X}: self-loop left to {emu.pc:06X}'
        assert emu.R[:15] == [regs[k] for k in range(15)]
        assert flags(emu) == before and emu.pr == MAGIC
        no_ram_writes(emu)
        assert not emu.ram_reads
        return 1
    log = []
    emu.stub(T, fn=recorder(log))
    before = (emu.T, emu.S, emu.Q, emu.M, emu.fpul, emu.gbr, emu.mach, emu.macl)
    assert emu.call(e, regs, fregs) == 'return'
    assert len(log) == 1 and log[0]['pc'] == T and log[0]['pr'] == MAGIC and log[0]['r15'] == S
    assert log[0]['R'][:15] == [regs[k] for k in range(15)]
    # T, S, Q, M, FPUL, GBR, MACH, MACL and fr0-fr15 as on entry (fregs applied by call())
    assert log[0]['flags'][:8] == before
    assert list(log[0]['flags'][8]) == [E.f2b(fregs[k]) for k in range(16)]
    assert emu.steps == 2
    no_ram_writes(emu)
    assert not emu.ram_reads
    return 1


def t_isr_stub(e, p, rng):                               # class 1
    assert p['K2B8C'] == 0x002B8C
    H = p['H']
    n = 0
    for r0ret in (0x002BD4, 0x00012344):                 # 0x002BD4 per 0x002B8C's contract
        emu, regs, fregs = fresh(rng)
        log = []
        emu.stub(0x002B8C, r0=r0ret, fn=recorder(log))
        assert emu.call(e, regs, fregs, stop_at={H}) == H
        assert len(log) == 1
        c = log[0]
        assert c['pr'] == e + 10, f'{e:06X}: PR at 0x002B8C = {c["pr"]:#x}'
        assert c['r15'] == S - 12
        assert c['R'][1] == regs[1] and c['R'][0] == 0x002B8C
        assert emu.read_u32(S - 4) == regs[0]            # pushed r0
        assert emu.read_u32(S - 8) == MAGIC              # pushed PR
        assert emu.read_u32(S - 12) == regs[1]           # pushed r1 (jsr delay slot)
        assert emu.pr == r0ret and emu.R[0] == r0ret     # PR = value 0x002B8C returned
        assert emu.R[1] == H and emu.R[15] == S - 12
        assert all(emu.R[k] == regs[k] for k in range(2, 15))
        no_ram_writes(emu)
        assert not emu.preads and not emu.pwrites
        n += 1
    return n


def t_rts_nop(e, p, rng):                                # class 2
    emu, regs, fregs = fresh(rng)
    before = flags(emu)[:8]
    assert emu.call(e, regs, fregs) == 'return'
    assert emu.R[:15] == [regs[k] for k in range(15)] and emu.steps == 2
    assert [emu.FR[k] for k in range(16)] == [E.f2b(fregs[k]) for k in range(16)]
    assert flags(emu)[:8] == before
    no_ram_writes(emu)
    assert not emu.ram_reads
    return 1


BYTES_SAMPLE = (0x00, 0x01, 0x02, 0x7F, 0x80, 0x81, 0xFE, 0xFF, 0x5A, 0xA5)


def t_ld_s8(e, p, rng):                                  # class 3
    K = p['K']
    for b in BYTES_SAMPLE:
        emu, regs, fregs = fresh(rng)
        emu.ram_u8(K, b)
        assert emu.call(e, regs, fregs) == 'return'
        assert emu.R[0] == sx(b, 8) & M32 and emu.R[2] == K
        assert all(emu.R[k] == regs[k] for k in range(15) if k not in (0, 2))
        no_ram_writes(emu)
        assert not emu.uninit_reads
    return len(BYTES_SAMPLE)


def chain(e, p, rng, calls, tail):                       # classes 4 / 12 / 17 / 23
    """Each stubbed callee records what it receives, then LEAVES NEW random values in
    r0-r14, fr0-fr15 and T (r15 kept, as any callee must).  The first callee must see
    the caller's state; every later one -- the tail target included -- must see exactly
    what the previous callee left, i.e. the member adds no set-up of its own."""
    targets = [p[k] for k in calls] + [p[tail]]
    emu, regs, fregs = fresh(rng)
    log = []
    rec = recorder(log)

    def callee(emu):
        rec(emu)
        emu.R[:15] = [rng.getrandbits(32) for _ in range(15)]
        emu.FR = [rng.getrandbits(32) for _ in range(16)]
        emu.T = rng.getrandbits(1)
        log[-1]['left'] = (list(emu.R[:15]), list(emu.FR), emu.T)

    for t in set(targets):
        emu.stub(t, fn=callee)
    t_entry = emu.T
    assert emu.call(e, regs, fregs) == 'return'
    assert [c['pc'] for c in log] == targets, f'{e:06X}: order {[hex(c["pc"]) for c in log]}'
    for i, c in enumerate(log[:-1]):
        assert c['pr'] == e + 6 + 4 * i                  # bsr at e+2+4i, slot, return after
        assert c['r15'] == S - 4 and c['top'] == MAGIC   # caller's PR saved on the stack
    for i, c in enumerate(log):
        if i == 0:
            want_r = [regs[k] for k in range(15)]
            want_f = [E.f2b(fregs[k]) for k in range(16)]
            want_t = t_entry
        else:
            want_r, want_f, want_t = log[i - 1]['left']
        assert c['R'][:15] == want_r, f'{e:06X}: registers at callee {i}'
        assert list(c['flags'][8]) == want_f and c['flags'][0] == want_t
    last = log[-1]
    assert last['pr'] == MAGIC and last['r15'] == S       # tail: PR and r15 restored
    no_ram_writes(emu)
    return 1


def t_bit(e, p, rng):                                    # class 5
    K, M, X = p['K'], p['M'], p['X']
    for b in range(256):
        emu, regs, fregs = fresh(rng)
        emu.ram_u8(K, b)
        assert emu.call(e, regs, fregs) == 'return'
        want = int((sx(b, 8) & M) == 0) ^ X
        assert emu.R[0] == want, f'{e:06X}: b={b:#x} r0={emu.R[0]:#x} want {want}'
        assert emu.T == int((b & M) == 0)
        no_ram_writes(emu)
    return 256


def t_const(e, p, rng):                                  # class 6
    emu, regs, fregs = fresh(rng)
    before = flags(emu)[:8]
    assert emu.call(e, regs, fregs) == 'return'
    assert emu.R[0] == p['I'] & M32
    assert all(emu.R[k] == regs[k] for k in range(1, 15))
    assert flags(emu)[:8] == before
    assert [emu.FR[k] for k in range(16)] == [E.f2b(fregs[k]) for k in range(16)]
    no_ram_writes(emu)
    assert not emu.ram_reads
    return 1


def t_nzsel(e, p, rng):                                  # class 7
    K, A, B = p['K'], p['A'], p['B']
    for b in range(256):
        emu, regs, fregs = fresh(rng)
        emu.ram_u8(K, b)
        assert emu.call(e, regs, fregs) == 'return'
        want = (A if b != 0 else B) & M32
        assert emu.R[0] == want, f'{e:06X}: b={b:#x} r0={emu.R[0]:#x}'
        no_ram_writes(emu)
    return 256


def t_st_imm(e, p, rng, ireg):                           # classes 8 / 24
    K, I = p['K'], p['I']
    emu, regs, fregs = fresh(rng)
    emu.ram_u8(K, (~I) & 0xFF)
    assert emu.call(e, regs, fregs) == 'return'
    assert emu.read_u8(K) == I & 0xFF
    assert emu.R[ireg] == I & M32
    no_ram_writes(emu, {K})
    assert set(emu.writes) == {K}
    return 1


def t_pair(e, p, rng):                                   # class 9 (0x0BE9A0 RUN)
    assert p['F'] == LIB_PAIR
    K, I = p['K'], p['I']
    assert K % 2 == 0
    for _ in range(3):
        emu, regs, fregs = fresh(rng)
        before = flags(emu)[:8]
        assert emu.call(e, regs, fregs) == 'return'
        reads = list(emu.ram_reads)                      # before this test's own read_u16
        v = I & 0xFF
        want = (v << 8) | (~v & 0xFF)
        assert emu.read_u16(K) == want and emu.R[0] == want
        assert emu.R[15] == S
        # clobbers: r4 = the pair (0x0BE9AA/0x0BE9A8), r3 = v << 8 (0x0BE9A0/A2),
        # r2 = K (the library's r2 = ~v & 0xFF is overwritten by the K load)
        assert emu.R[4] == want and emu.R[3] == v << 8 and emu.R[2] == K
        assert all(emu.R[k] == regs[k] for k in range(15) if k not in (0, 2, 3, 4))
        assert flags(emu)[:8] == before                  # T, FPUL ... unchanged
        assert [emu.FR[k] for k in range(16)] == [E.f2b(fregs[k]) for k in range(16)]
        assert all(S - 64 <= a < S for a, _ in reads)    # no RAM input: only the PR pop
        no_ram_writes(emu, {K, K + 1})
    return 3


def t_eq(e, p, rng):                                     # class 10
    K, I = p['K'], p['I']
    for b in range(256):
        emu, regs, fregs = fresh(rng)
        emu.ram_u8(K, b)
        assert emu.call(e, regs, fregs) == 'return'
        assert emu.R[0] == int(sx(b, 8) == I), f'{e:06X}: b={b:#x}'
        no_ram_writes(emu)
    return 256


def t_jmp(e, p, rng, reg):                               # classes 11 / 20
    T = p['T']
    emu, regs, fregs = fresh(rng)
    log = []
    emu.stub(T, fn=recorder(log))
    assert emu.call(e, regs, fregs) == 'return'
    assert len(log) == 1 and log[0]['pc'] == T and log[0]['pr'] == MAGIC and log[0]['r15'] == S
    assert log[0]['R'][reg] == T
    assert all(log[0]['R'][k] == regs[k] for k in range(15) if k != reg)
    no_ram_writes(emu)
    return 1


def t_periph(e, p, rng, cls):                            # classes 13 / 15 / 22 / 27 / 28
    T = p['T']
    n = 0
    for planted in (0x0000, 0xFFFF, 0x1234):
        P = p.get('P')
        pv = {}
        if P is not None:
            pv = {P: planted, (P + 2) & M32: planted ^ 0x00FF}
        emu, regs, fregs = fresh(rng, pv)
        assert emu.call(e, regs, fregs, stop_at={T}) == T
        assert emu.pr == MAGIC and emu.R[15] == S
        no_ram_writes(emu)
        if cls == 13:
            V = p['V']
            assert emu.preads == [(P, 2)] and emu.pwrites == [(P, 2, V & 0xFFFF)]
            assert emu.R[3] == sx(planted, 16) & M32 and emu.R[2] == V & M32
            assert emu.R[4] == p['N'] & M32
            changed = (2, 3, 4)
        elif cls in (15, 22):
            V = p['V']
            assert emu.preads == [(P, 2)] and emu.pwrites == [(P, 2, V & 0xFFFF)]
            assert emu.R[3] == sx(planted, 16) & M32 and emu.R[2] == V & M32
            assert emu.R[4] == p['N'] & M32
            changed = (2, 3, 4)
        elif cls == 27:
            V, P2 = p['V'], (P + p['ADD']) & M32
            assert emu.preads == [(P, 2), (P2, 2)]
            assert emu.pwrites == [(P, 2, V & 0xFFFF), (P2, 2, V & 0xFFFF)]
            assert emu.R[3] == sx(planted, 16) & M32
            assert emu.R[2] == sx(planted ^ 0x00FF, 16) & M32
            assert emu.R[5] == V & M32 and emu.R[4] == p['N'] & M32
            changed = (2, 3, 4, 5)
        elif cls == 28:
            assert not emu.preads and not emu.pwrites
            assert emu.R[4] == p['N'] & M32
            changed = (4,)
        assert all(emu.R[k] == regs[k] for k in range(15) if k not in changed)
        n += 1
    return n


def f2u8_model(x, scale, offset=0.0):
    """clamp(trunc((x - offset)/scale + 0.5), 0, 255) on exact rationals, plus the
    distance of (x - offset)/scale + 0.5 from the nearest integer."""
    q = (Fraction(x) - Fraction(offset)) / Fraction(scale) + Fraction(1, 2)
    t = math.trunc(q)
    dist = abs(q - round(q))
    return max(0, min(255, t)), dist


KS = (0, 1, 2, 10, 100, 127, 128, 200, 254, 255, 256, 1000)


def edge_rule(k, frac):
    """The class-14 edge statement as repaired after review: (k+0.25)C -> k for
    0 <= k <= 255, (k+0.75)C -> k+1 for 0 <= k <= 254, anything with x/C > 254.5 -> 255."""
    if frac == 0.25:
        return k if k <= 255 else 255
    return k + 1 if k <= 254 else 255


def t_f2u(e, p, rng):                                    # class 14 (0x0BE5A8 RUN)
    assert p['F'] == LIB_F2U8
    K, C = p['K'], f32(p['C'][1])
    assert math.isfinite(C) and C > 0
    xs = [(-C * 1000, 0), (-C * 10, 0), (-C, 0), (-C * 0.25, 0), (-0.0, 0), (0.0, 0)]
    for k in KS:
        xs += [(C * (k + 0.25), edge_rule(k, 0.25)), (C * (k + 0.75), edge_rule(k, 0.75))]
    xs += [(C * 254.4, 254), (C * 254.6, 255)]           # either side of the clamp onset 254.5
    xs += [(C * 1e6, 255)]
    n = 0
    for x, stated in xs:
        x = f32(E.f2b(x))                                # the float32 actually planted
        want, dist = f2u8_model(x, C)
        if dist < 1e-3:
            continue
        assert want == stated, f'{e:06X}: model {want} vs stated edge rule {stated}'
        q = Fraction(x) / Fraction(C) + Fraction(1, 2)
        emu, regs, fregs = fresh(rng)
        emu.ram_f32(K, x)
        assert emu.call(e, regs, fregs) == 'return'
        assert emu.R[0] == want, f'{e:06X}: x={x!r} C={C!r} r0={emu.R[0]} want {want}'
        assert emu.R[15] == S
        # clobbers left by 0x0BE5A8 (helpers_arith CONTRACT; re-checked here):
        assert emu.R[4] == emu.R[0]                      # 0BE5CE mov r4,r0
        assert emu.R[5] == 255                           # 0BE5AC mov.w -> 0x00FF
        assert emu.R[2] == LIB_F2U8                      # this member's own r2 load
        assert emu.fr(3) == 0.5                          # 0BE5B0 fmov.s @r0 (0x3F000000)
        assert emu.FR[5] == p['C'][1] and emu.FR[6] == 0  # fr5 = C, fr6 = +0.0
        # fr4 = x/C, fr2 = x/C + 0.5 -- compared to 1e-6 relative only (no last-bit claim)
        assert abs(emu.fr(4) - float(q - Fraction(1, 2))) <= 1e-6 * max(1.0, abs(float(q)))
        assert abs(emu.fr(2) - float(q)) <= 1e-6 * max(1.0, abs(float(q)))
        tr = E.s32(emu.fpul)                             # FPUL = ftrc(fr2) BEFORE the clamp
        if abs(q) < 1e5:
            assert tr == math.trunc(q), f'{e:06X}: fpul {tr} vs {math.trunc(q)}'
        else:
            assert abs(tr - math.trunc(q)) <= 1
        assert emu.T == int(tr >= 0)                     # 0BE5BA cmp/gt, 0BE5C4 cmp/pz
        assert all(emu.R[k] == regs[k] for k in range(15) if k not in (0, 2, 4, 5))
        assert all(emu.FR[k] == E.f2b(fregs[k]) for k in range(16) if k not in (2, 3, 4, 5, 6))
        assert sorted(set(a for a, _ in emu.ram_reads if not S - 64 <= a < S)) == [K]
        no_ram_writes(emu)
        n += 1
    return n


def t_copy_chain(e, p, rng):                             # class 16
    D = p['D']
    assert D == p['D2']
    SRC, DST = 0xFFFF9000, 0xFFFF9100                    # scratch RAM chosen for the test
    nl = D // 4 + 1                                      # longs copied: offsets D, D-4, .. 0
    emu, regs, fregs = fresh(rng)
    src = [rng.getrandbits(32) for _ in range(18)]
    for j in range(18):
        emu.ram_u32(SRC + 4 * j, src[j])
        emu.ram_u32(DST + 4 * j, 0xDEADBEEF)
    saved_r3 = rng.getrandbits(32)
    emu.ram_u32(S - 4, saved_r3)                         # r3 pushed by the dispatcher
    regs.update({1: DST, 2: SRC, 15: S - 4})
    assert emu.call(e, regs, fregs) == 'return'
    for j in range(18):
        want = src[j] if j < nl else 0xDEADBEEF
        assert emu.read_u32(DST + 4 * j) == want, f'{e:06X}: long {j}'
    assert emu.R[3] == saved_r3 and emu.R[15] == S and emu.R[0] == src[0]
    assert emu.steps == 2 * nl + 2
    no_ram_writes(emu, set(range(DST, DST + 4 * nl)))
    return 1


def t_st_r4(e, p, rng, kreg):                            # classes 18 / 21
    K = p['K']
    vals = (0, 1, 0x7F, 0x80, 0xFF, 0x1FF, 0x12345678, 0xFFFFFF00)
    for v in vals:
        emu, regs, fregs = fresh(rng)
        emu.ram_u8(K, (~v) & 0xFF)
        regs[4] = v
        assert emu.call(e, regs, fregs) == 'return'
        assert emu.read_u8(K) == v & 0xFF and emu.R[kreg] == K
        assert all(emu.R[k] == regs[k] for k in range(15) if k != kreg)
        no_ram_writes(emu, {K})
    return len(vals)


def t_ld_u8(e, p, rng):                                  # class 19
    K = p['K']
    for b in BYTES_SAMPLE:
        emu, regs, fregs = fresh(rng)
        emu.ram_u8(K, b)
        assert emu.call(e, regs, fregs) == 'return'
        assert emu.R[0] == b and emu.R[2] == sx(b, 8) & M32 and emu.R[6] == K
        no_ram_writes(emu)
    return len(BYTES_SAMPLE)


def t_zero_f2u(e, p, rng):                               # class 25 (0x0BE5A8 RUN)
    assert p['F'] == LIB_F2U8
    C = f32(p['C'][1])
    assert math.isfinite(C) and C > 0
    for _ in range(4):
        emu, regs, fregs = fresh(rng)
        assert emu.call(e, regs, fregs) == 'return'
        assert emu.R[0] == 0 and emu.R[15] == S
        # no RAM input: nothing was planted, nothing uninitialised was read, and the only
        # RAM reads are the function's own PR push/pop on the stack
        assert not emu.uninit_reads and stack_only_reads(emu)
        assert not emu.preads
        # clobbers: r4 = 0, r5 = 255, r2 = 0x0BE5A8, fr2 = fr3 = 0.5, fr4 = +0.0 (0/C),
        # fr5 = C, fr6 = +0.0, FPUL = 0, T = 1 (cmp/pz on 0 at 0BE5C4)
        assert emu.R[4] == 0 and emu.R[5] == 255 and emu.R[2] == LIB_F2U8
        assert emu.FR[2] == E.f2b(0.5) and emu.FR[3] == E.f2b(0.5)
        assert emu.FR[4] == 0 and emu.FR[5] == p['C'][1] and emu.FR[6] == 0
        assert emu.fpul == 0 and emu.T == 1
        assert all(emu.R[k] == regs[k] for k in range(15) if k not in (0, 2, 4, 5))
        assert all(emu.FR[k] == E.f2b(fregs[k]) for k in range(16) if k not in (2, 3, 4, 5, 6))
        no_ram_writes(emu)
    return 4


def t_wcopy(e, p, rng):                                  # class 26
    A, B = p['A'], p['B']
    assert A % 2 == 0 and B % 2 == 0
    nxt = e + 8
    vals = (0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFF, 0x5AA5)
    for v in vals:
        emu, regs, fregs = fresh(rng)
        emu.ram_u16(A, v)
        emu.ram_u16(B, v ^ 0xFFFF)
        assert emu.call(e, regs, fregs, stop_at={nxt}) == nxt
        assert emu.read_u16(B) == v and emu.read_u16(A) == v
        assert emu.R[2] == sx(v, 16) & M32 and emu.R[3] == A and emu.R[1] == B
        assert emu.pr == MAGIC and emu.R[15] == S
        assert all(emu.R[k] == regs[k] for k in range(15) if k not in (1, 2, 3))
        no_ram_writes(emu, {B, B + 1})
    return len(vals)


def t_st2(e, p, rng):                                    # class 29
    K, I, D = p['K'], p['I'], p['D']
    emu, regs, fregs = fresh(rng)
    emu.ram_u8(K, 0x5A)
    emu.ram_u8(K + D, 0x5A)
    assert emu.call(e, regs, fregs) == 'return'
    assert emu.read_u8(K) == I & 0xFF and emu.read_u8(K + D) == I & 0xFF
    assert emu.R[0] == I & M32 and emu.R[6] == K
    no_ram_writes(emu, {K, K + D})
    assert set(emu.writes) == {K, K + D}
    return 1


TESTS = {
    0: t_bra, 1: t_isr_stub, 2: t_rts_nop, 3: t_ld_s8,
    4: lambda e, p, r: chain(e, p, r, ['A'], 'B'),
    5: t_bit, 6: t_const, 7: t_nzsel,
    8: lambda e, p, r: t_st_imm(e, p, r, 2),
    9: t_pair, 10: t_eq,
    11: lambda e, p, r: t_jmp(e, p, r, 3),
    12: lambda e, p, r: chain(e, p, r, ['A', 'B'], 'C'),
    13: lambda e, p, r: t_periph(e, p, r, 13),
    14: t_f2u,
    15: lambda e, p, r: t_periph(e, p, r, 15),
    16: t_copy_chain,
    17: lambda e, p, r: chain(e, p, r, ['A', 'B', 'C'], 'D'),
    18: lambda e, p, r: t_st_r4(e, p, r, 6),
    19: t_ld_u8,
    20: lambda e, p, r: t_jmp(e, p, r, 2),
    21: lambda e, p, r: t_st_r4(e, p, r, 2),
    22: lambda e, p, r: t_periph(e, p, r, 22),
    23: lambda e, p, r: chain(e, p, r, ['A', 'B', 'C', 'D'], 'E'),
    24: lambda e, p, r: t_st_imm(e, p, r, 6),
    25: t_zero_f2u, 26: t_wcopy,
    27: lambda e, p, r: t_periph(e, p, r, 27),
    28: lambda e, p, r: t_periph(e, p, r, 28),
    29: t_st2,
}

# parameter constraints asserted per class (address classes, alignment, fixed values)
RAM_KEYS = {3: 'K', 5: 'K', 7: 'K', 8: 'K', 9: 'K', 10: 'K', 14: 'K', 18: 'K', 19: 'K',
            21: 'K', 24: 'K', 29: 'K'}


def check_params(cid, e, p):
    if cid in RAM_KEYS:
        assert aclass(p[RAM_KEYS[cid]]) == 'RAM', f'{e:06X}: {p}'
    if cid == 26:
        assert aclass(p['A']) == 'RAM' and aclass(p['B']) == 'RAM'
    if cid in (13, 15, 22, 27):
        assert aclass(p['P']) == 'PERIPH' and p['P'] % 2 == 0
    if cid in (13, 15, 22, 27, 28):
        assert p['T'] == TRAP, f'{e:06X}: tail target {p["T"]:#x}'
    if cid in (11, 20, 0, 4, 12, 17, 23):
        for k, v in p.items():
            if k in ('T', 'A', 'B', 'C', 'D', 'E'):
                assert v < 0xC0000 and v % 2 == 0, f'{e:06X}: {k}={v:#x}'


# --------------------------------------------------------------------------- D. vectors
def vector_slots():
    """stub entry -> vector number v such that long[0x0FFC50 + 4v] == entry."""
    out = {}
    for v in range(256):
        a = VBR_TABLE + 4 * v
        if a + 4 > len(ROM):
            break
        out.setdefault(u32(a), []).append(v)
    return out


NONSTUB_DIRECT = {184: 0x00F3F2, 186: 0x00F460, 224: 0x00F6E6}
NONSTUB_E852 = 0x0000E852


def check_vector_range(stub_slots, handlers):
    """The 118 stub slots lie INSIDE 64..231 but do not fill it.  Returns the lines for
    the summary; asserts the exact contents of the 50 slots in range that hold no stub."""
    last_v = (len(ROM) - VBR_TABLE) // 4 - 1
    assert last_v == 235                                 # 0x0FFC50 + 4*235 + 4 == 0x100000
    assert len(stub_slots) == 118 and len(set(stub_slots.values())) == 118
    assert min(stub_slots.values()) == 64 and max(stub_slots.values()) == 231
    used = set(stub_slots.values())
    gaps = [v for v in range(64, 232) if v not in used]
    assert len(gaps) == 50
    e852 = [v for v in gaps if u32(VBR_TABLE + 4 * v) == NONSTUB_E852]
    direct = {v: u32(VBR_TABLE + 4 * v) for v in gaps if v not in e852}
    assert len(e852) == 47 and direct == NONSTUB_DIRECT
    # none of the four non-stub entries is the handler H of any class-1 stub
    assert not (set(NONSTUB_DIRECT.values()) | {0x00E852}) & set(handlers)
    # the three direct entries push r7, r6, r5 ... themselves (2F76 2F66 2F56 at entry)
    for a in NONSTUB_DIRECT.values():
        assert [u16(a), u16(a + 2), u16(a + 4)] == [0x2F76, 0x2F66, 0x2F56]
    # 0x00E852: mov.l -> r4 = 0x00010000; bra 0x00E774; nop
    assert u16(0x00E852) == 0xD41B and u32(lit_l_addr(0x00E852, 0xD41B)) == 0x00010000
    assert br12(0x00E854, u16(0x00E854)) == TRAP and u16(0x00E856) == 0x0009
    lines = ['vector slots 64..231: 118 hold a class-1 stub (one each), 47 hold 0x0000E852,',
             '  3 hold 0x00F3F2 / 0x00F460 / 0x00F6E6 (v = 184 / 186 / 224); slots holding 0x0000E852:']
    for i in range(0, len(e852), 16):
        lines.append('    ' + ' '.join(str(v) for v in e852[i:i + 16]))
    return lines


# --------------------------------------------------------------------------- E. review checks
def review_checks(rng, params):
    """Non-member facts settled while deciding the review (each asserted)."""
    out = []
    # R1. 0x05850E: r0 = zero-extended byte[0xFFFFAD52 + (r4 & 0xFF)], one RAM byte read.
    base = 0xFFFFAD52
    table = [rng.getrandbits(8) for _ in range(256)]
    n = 0
    for r4 in (0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x1FF, 0x12345678, 0xFFFFFF80) + \
            tuple(rng.getrandbits(32) for _ in range(40)):
        emu, regs, fregs = fresh(rng)
        for i, b in enumerate(table):
            emu.ram_u8(base + i, b)
        regs[4] = r4
        assert emu.call(0x05850E, regs, fregs) == 'return'
        idx = r4 & 0xFF
        assert emu.R[0] == table[idx] and emu.ram_reads == [(base + idx, 1)]
        no_ram_writes(emu)
        n += 1
    out.append(f'R1 0x05850E: r0 = u8[0xFFFFAD52 + (r4 & 0xFF)], {n} cases')
    # R1b. 0x05DCAE: k = ROM byte[0x065C2E + (r4 & 0xFFFF)] (0x065CBC + sext16(0xFF72)),
    #      then 0x05850E (RUN) with r4 = k: r0 = u8[0xFFFFAD52 + k].
    assert u32(0x05DDBC) == 0x00065CBC and sx(u16(0x05DD70), 16) == -142
    n = 0
    for r4 in tuple(range(0, 0x200, 7)) + (0xFFFF, 0x10000, 0x1008E, 0xABCD1234) + \
            tuple(rng.getrandbits(32) for _ in range(40)):
        emu, regs, fregs = fresh(rng)
        for i, b in enumerate(table):
            emu.ram_u8(base + i, b)
        regs[4] = r4
        assert emu.call(0x05DCAE, regs, fregs) == 'return'
        k = ROM[0x065C2E + (r4 & 0xFFFF)]
        assert emu.R[0] == table[k], f'05DCAE r4={r4:#x}'
        assert [a for a, _ in emu.ram_reads if not S - 64 <= a < S] == [base + k]
        no_ram_writes(emu)
        n += 1
    out.append(f'R1 0x05DCAE: r0 = u8[0xFFFFAD52 + ROM u8[0x065C2E + (r4 & 0xFFFF)]], {n} cases')
    # R2. 0x055FB8 (census function, caller 0x04907C) stores pair(1) = 0x01FE to word
    #     0xFFFF3474 iff all four (a == 1 or b == 1) pairs hold; otherwise writes nothing.
    pairs = [(0xFFFF2F48, 0xFFFFA5DF), (0xFFFF2566, 0xFFFF6ACE),
             (0xFFFF2568, 0xFFFF6ACF), (0xFFFF2E3E, 0xFFFFA38F)]
    cells = [c for pr in pairs for c in pr]
    combos = [[(m >> i) & 1 for i in range(8)] for m in range(256)]
    combos += [[rng.choice((0, 1, 2, 0x81, 0xFF)) for _ in range(8)] for _ in range(256)]
    stores = 0
    for vals in combos:
        emu, regs, fregs = fresh(rng)
        for c, v in zip(cells, vals):
            emu.ram_u8(c, v)
        emu.ram_u16(0xFFFF3474, 0x5A5A)
        assert emu.call(0x055FB8, regs, fregs) == 'return' and emu.R[15] == S
        cond = all(vals[2 * i] == 1 or vals[2 * i + 1] == 1 for i in range(4))
        if cond:
            assert emu.read_u16(0xFFFF3474) == 0x01FE
            assert set(emu.writes) == {0xFFFF3474, 0xFFFF3475}
            stores += 1
        else:
            assert not emu.writes and emu.read_u16(0xFFFF3474) == 0x5A5A
        assert not emu.uninit_reads
    out.append(f'R2 0x055FB8: word[0xFFFF3474] = 0x01FE iff the 4 pair conditions hold, '
               f'{len(combos)} cases ({stores} stores)')
    # the class-9 writer 0x056022 stores 0x00FF (asserted in t_pair); together:
    assert params[0x056022][1]['K'] == 0xFFFF3474 and params[0x056022][1]['I'] == 0
    # R3. 0x0281DC (13 insns): r0 = 1 if byte[96A8] == 1, else 2 if byte[96A9] == 1, else 0;
    #     byte[96A9] is read only when byte[96A8] != 1.
    n = 0
    cases = [(b0, b1) for b0 in range(256) for b1 in (0, 1, 0x81)]
    cases += [(b0, b1) for b1 in range(256) for b0 in (0, 2, 0xFF)]
    for b0, b1 in cases:
        emu, regs, fregs = fresh(rng)
        emu.ram_u8(0xFFFF96A8, b0)
        emu.ram_u8(0xFFFF96A9, b1)
        assert emu.call(0x0281DC, regs, fregs) == 'return'
        want = 1 if b0 == 1 else (2 if b1 == 1 else 0)
        assert emu.R[0] == want, f'0281DC {b0:#x} {b1:#x}'
        rd = [a for a, _ in emu.ram_reads]
        assert rd == ([0xFFFF96A8] if b0 == 1 else [0xFFFF96A8, 0xFFFF96A9])
        no_ram_writes(emu)
        n += 1
    out.append(f'R3 0x0281DC: two-byte reader, returns 1 / 2 / 0, {n} cases')
    # R4. 0x004CCA / 0x009106 are rts; nop and are the targets of 0x00E1B0's literals;
    #     0x004CCE / 0x00910A (the described bodies) are the targets of 0x00E2FC's.
    assert u16(0x004CCA) == 0x000B and u16(0x004CCC) == 0x0009
    assert u16(0x009106) == 0x000B and u16(0x009108) == 0x0009
    assert u32(0x00E2E8) == 0x00004CCA and u32(0x00E2E0) == 0x00009106
    assert u32(0x00E404) == 0x00004CCE and u32(0x00E40C) == 0x0000910A
    assert u16(0x004CCE) == 0x4F22 and u16(0x00910C) >> 12 == 0xD
    assert u32(lit_l_addr(0x00910C, u16(0x00910C))) == 0xFFFF4272
    out.append('R4 0x004CCA / 0x009106 = rts; nop (0x00E1B0 literals); bodies 0x004CCE / '
               '0x00910A (0x00E2FC literals)')
    # R5. class-7 coverage of 0xFFFF9704..0xFFFF9742: 46 readers, 17 bytes read by none.
    ks = {p['K'] for cid, p, _ in params.values() if cid == 7}
    gap = [a for a in range(0xFFFF9704, 0xFFFF9743) if a not in ks]
    assert len(ks) == 46 and len(gap) == 17
    assert [a & 0xFFFF for a in gap] == [0x9725, 0x9726, 0x9727, 0x9728, 0x9729, 0x972A,
                                         0x972B, 0x9730, 0x9731, 0x9732, 0x9733, 0x9734,
                                         0x9738, 0x9739, 0x973A, 0x973F, 0x9740]
    out.append('R5 class 7: 46 readers in 0xFFFF9704..0xFFFF9742, 17 bytes read by none: '
               + ' '.join(f'{a & 0xFFFF:04X}' for a in gap))
    return out


# --------------------------------------------------------------------------- formatting
def h(v, w=6):
    return f'0x{v & M32:0{w}X}'


def fmt_params(cid, e, p, extra):
    if cid == 0:
        return f'T={h(p["T"])}' + ('  (bra to itself: endless loop)' if p['T'] == e else '')
    if cid == 1:
        return f'H={h(p["H"])}  vec={extra.get("vec")}'
    if cid in (2,):
        return ''
    if cid in (3, 18, 19, 21):
        return f'K={h(p["K"], 8)}'
    if cid in (4, 12, 17, 23):
        ks = [k for k in NAMES[cid]]
        return '  '.join(f'{k}={h(p[k])}' for k in ks)
    if cid == 5:
        return f'K={h(p["K"], 8)}  M=0x{p["M"]:02X}  X={p["X"]}'
    if cid == 6:
        return f'I={p["I"]}'
    if cid == 7:
        return f'K={h(p["K"], 8)}  A={p["A"]}  B={p["B"]}'
    if cid in (8, 24):
        return f'K={h(p["K"], 8)}  I={p["I"]} (byte 0x{p["I"] & 0xFF:02X})'
    if cid == 9:
        v = p['I'] & 0xFF
        return f'K={h(p["K"], 8)}  I={p["I"]}  stored word 0x{(v << 8) | (~v & 0xFF):04X}'
    if cid == 10:
        return f'K={h(p["K"], 8)}  I={p["I"]}'
    if cid in (11, 20):
        return f'T={h(p["T"])}'
    if cid == 13:
        return (f'P={h(p["P"], 8)}  V=0x{p["V"] & 0xFFFF:04X}  N={p["N"]}  '
                f'T={h(p["T"])}  {extra.get("via", "")}')
    if cid in (15, 22):
        return (f'P={h(p["P"], 8)}  V=0x{p["V"] & 0xFFFF:04X}  N={p["N"]}  '
                f'T={h(p["T"])}  {extra.get("via", "")}')
    if cid == 27:
        return (f'P={h(p["P"], 8)}  P+{p["ADD"]}={h(p["P"] + p["ADD"], 8)}  '
                f'V=0x{p["V"] & 0xFFFF:04X}  N={p["N"]}  T={h(p["T"])}  {extra.get("via", "")}')
    if cid == 28:
        return f'N={p["N"]}  T={h(p["T"])}  {extra.get("via", "")}'
    if cid == 14:
        return f'K={h(p["K"], 8)}  C={f32(p["C"][1])!r} (0x{p["C"][1]:08X} @ {h(p["C"][0])})'
    if cid == 25:
        return f'C={f32(p["C"][1])!r} (0x{p["C"][1]:08X} @ {h(p["C"][0])})'
    if cid == 16:
        return f'D={p["D"]}  copies {p["D"] // 4 + 1} longs  (offsets {p["D"]}..0 step -4)'
    if cid == 26:
        return f'A={h(p["A"], 8)} -> B={h(p["B"], 8)}  falls through to {h(e + 8)}'
    if cid == 29:
        return f'K={h(p["K"], 8)}  K+{p["D"]}={h(p["K"] + p["D"], 8)}  I={p["I"]}'
    return repr(p)


def callers_str(f):
    cs = f['callers']
    if not cs:
        return 'callers 0'
    head = ','.join(c[2:] if c.startswith('0x') else c for c in cs[:3])
    more = f'+{len(cs) - 3}' if len(cs) > 3 else ''
    return f'callers {len(cs)} [{head}{more}]'


# --------------------------------------------------------------------------- main
def main():
    quiet = '--quiet' in sys.argv
    want_map = '--map' in sys.argv
    classes, census = load_members()
    assert sorted(classes) == list(CLASS_IDS)
    vec = vector_slots()
    rng = random.Random(20261127)

    total_members = total_cases = 0
    removed = []
    params = {}                                          # entry -> (cid, p)
    report = []
    for cid in CLASS_IDS:
        c = classes[cid]
        ex = int(c['example'], 16)
        n = c['insns']
        ref = shape_of(ex, n)
        kinds_ref = [k for k, _ in params_seq(ex, n)]
        assert len(kinds_ref) == len(NAMES[cid]), f'class {cid}: {kinds_ref}'
        assert c['members'] == len(c['functions'])
        survivors = []
        for f in c['functions']:
            e = int(f['entry'], 16)
            cf = census[e]
            ok = (cf['insns'] == n and int(cf['end'], 16) - e == 2 * n
                  and shape_of(e, n) == ref
                  and [k for k, _ in params_seq(e, n)] == kinds_ref)
            for i in range(n):                           # no data decoded as code
                txt = decode(u16(e + 2 * i), e + 2 * i)[0]
                if txt.startswith('.word') or 'INVALID' in txt:
                    ok = False
            if not ok:
                removed.append((cid, e))
                continue
            survivors.append((e, cf))
        cases = 0
        for e, cf in survivors:
            p = dict(zip(NAMES[cid], [v for _, v in params_seq(e, n)]))
            check_params(cid, e, p)
            cases += TESTS[cid](e, p, rng)
            params[e] = (cid, p, cf)
        total_members += len(survivors)
        total_cases += cases
        report.append((cid, len(c['functions']), len(survivors), cases, ex, n))

    # D. vector cross-check
    handler_via = {}
    for e, (cid, p, cf) in params.items():
        if cid == 1:
            vs = vec.get(e, [])
            assert len(vs) == 1, f'stub {e:06X}: vector slots {vs}'
            p['_vec'] = vs[0]
            handler_via[p['H']] = (e, vs[0])
    assert len(handler_via) == 118                       # the 118 handlers H are distinct
    vec_lines = check_vector_range({e: p['_vec'] for e, (cid, p, cf) in params.items()
                                    if cid == 1}, handler_via)
    n_xcheck = 0
    for e, (cid, p, cf) in params.items():
        if cid in (13, 15, 22, 27, 28):
            assert e in handler_via, f'handler {e:06X} reached by no class-1 stub'
            stub, v = handler_via[e]
            assert p['N'] == v, f'handler {e:06X}: r4={p["N"]} but stub {stub:06X} is vector {v}'
            p['_via'] = f'via stub {h(stub)} = vector {v}'
            n_xcheck += 1
    rev_lines = review_checks(rng, params)

    print('emu_stub_shapes_a: shape classes 0..29 of disassembly/maps/stub_classes.json')
    print(f'  reference bin md5 {ROM_MD5}')
    for cid, nm, ns, cases, ex, n in report:
        print(f'  class {cid:2d}: {nm:3d} members, {ns:3d} match the shape of {h(ex)} '
              f'({n} insns), {cases:6d} emulated cases')
    print(f'  members proved and emulated: {total_members}   removed: {len(removed)} '
          f'{[(c, h(e)) for c, e in removed]}')
    print(f'  emulated cases: {total_cases}')
    print(f'  handlers whose r4 equals the vector number of their stub: {n_xcheck}')
    for line in vec_lines:
        print(f'  {line}')
    print('  review checks (non-members, asserted):')
    for line in rev_lines:
        print(f'    {line}')
    assert total_members == 983 and not removed

    if not quiet or want_map:
        for cid in CLASS_IDS:
            print(f'; ---- class {cid} member map ----')
            for e in sorted(x for x, v in params.items() if v[0] == cid):
                _, p, cf = params[e]
                extra = {'vec': p.get('_vec'), 'via': p.get('_via', '')}
                print(f';   {h(e)}  {callers_str(cf):34s} {fmt_params(cid, e, p, extra)}'.rstrip())
    print('ALL ASSERTIONS PASSED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
