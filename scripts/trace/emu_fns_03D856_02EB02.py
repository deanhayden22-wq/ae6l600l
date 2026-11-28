#!/usr/bin/env python3
"""Emulation check for disassembly/analysis/fns_03D856_02EB02_trace.txt (2026-11-27).

    python3 scripts/trace/emu_fns_03D856_02EB02.py           # prints case tables, exits 0 when every contract holds
    python3 scripts/trace/emu_fns_03D856_02EB02.py --quiet   # summary lines only

Self-contained: opens rom/AE5L600L 20g rev 20.19c.bin (md5 checked); the stock bin and 20.19e are
loaded only to show the code and tables these functions use are byte-identical and to re-run a
reduced grid on them.  Deterministic (fixed seeds, fixed grids).  Float inputs are chosen so every
float32 operation in the paths exercised is EXACT (asserted in the oracle), so nothing here depends
on the rounding mode or on fused-vs-unfused fmac.

ORACLES (written from the step-1 reading of the bytes, not from any doc or label):

  0x03D856(r4)  per-call angle scheduler over four 40-byte records at 0xFFFF7DA8, state at
                0xFFFF7E48.  oracle_03D856() below is the full contract.
  callees       0x03DD80 dist, 0x03D4F6 mode, 0x02F8A6 step pick, 0x03D50E pending angle,
                0x03D582 pending duration, 0x02F9E0 duration model, 0x03DD4E angle helper,
                0x03E26E / 0x03E0BA / 0x03E0FA check functions, 0x03DD8E mode change,
                0x03DE6E mask change, 0x03DB16 resync, 0x03E168 / 0x03DFC8 fire functions.
  0x02EB02      one pass of a six-word serial-EEPROM write-back state machine (GBR 0xFFFF7244);
                oracle_02EB02() is the full contract; session tests drive it pass by pass
                against a device model that decodes the command words built by 0x006B5A.
  0x02E8C0      the phase dispatcher that calls 0x02EB02 (and its pair-check prologue).

Stubs: peripheral drivers (0x009C38 0x009D48 0x009A72 0x009B2C), the serial transfer routines
(0x006884 0x0067DC 0x0067A6 0x006828), and, in the BODY tests, the callees that have their own test
here.  In the body tests 0x02FCBA / 0x02FB1C are stubbed with a chosen fr0; they are 3-instruction
getters of f32 [0xFFFF72FC] / [0xFFFF72EC] that ignore r4 (test_review checks that from ROM).
Every stub logs its arguments; logs are compared exactly.

REVIEW SETTLEMENT (third decode, same date): test_review re-runs every disputed item from the bytes,
test_q_bytes runs the divide instructions themselves, and test_tree_03D856 runs the WHOLE call tree
of 0x03D856 from ROM (only the four drivers stubbed; 0x03DB16 / 0x03DD8E / 0x03DE6E / fire / check
functions / 0x03E0FA / the getters all real) against oracle_03D856(tree=...), which composes the
callee models -- so the write set, the "never writes +8 / +12 / +16 / pads" statement, the resync ->
mode / mask handler interaction and the cal long 0x0CBDB4 read are checked on the tree, not the body.
"""
import hashlib
import math
import os
import random
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import sh2e_emu as E  # noqa: E402

QUIET = '--quiet' in sys.argv
TUNED = os.path.join(ROOT, 'rom', 'AE5L600L 20g rev 20.19c.bin')
STOCK = os.path.join(ROOT, 'rom', 'ae5l600l.bin')
LATEST = os.path.join(ROOT, 'rom', 'AE5L600L 20g rev 20.19e.bin')
MD5 = {TUNED: '92cae8275cd4f9b473a3a9e36efe6449', STOCK: 'a8ea39d447f977e270e27ee670243c88',
       LATEST: 'a249be081121f49f20ae0b32f079f114'}
M32 = 0xFFFFFFFF

# ---- addresses (all from literal pools; see the trace file) ----
S = 0xFFFF7E48            # state block: +0 w counter, +4 l, +8 b, +9 b mode idx, +10 w mask copy, +12 b last arg, +13 b init req
REC = 0xFFFF7DA8          # four 40-byte records
STAT = 0xFFFF429B         # per hardware channel byte, stride 28
MASK = 0xFFFF7D80         # word read through 0x03D4F0
F726C = 0xFFFF726C
A7280 = 0xFFFF7280
T7290 = 0xFFFF7290
K7DA4 = 0xFFFF7DA4
STEPF = 0xFFFF72B4        # four floats
STEPB = 0xFFFF72D3        # three bytes
F72E0, F72E4, F72E8, F72F4, F7300 = 0xFFFF72E0, 0xFFFF72E4, 0xFFFF72E8, 0xFFFF72F4, 0xFFFF7300
SEG4167 = 0xFFFF4167
R4280, R4158 = 0xFFFF4280, 0xFFFF4158
FULL = 0x02D00000         # 720 << 16
HALF = 0x00B40000         # 180 << 16
D30 = 0x001E0000          # 30 << 16
FIRE0, CHK0, FIRE1, CHK1 = 0x03E168, 0x03E26E, 0x03DFC8, 0x03E0BA

checks = 0
fails = []


def check(cond, msg):
    global checks
    checks += 1
    if not cond:
        fails.append(msg)
        if len(fails) < 30:
            print('FAIL:', msg)


def say(*a):
    if not QUIET:
        print(*a)


def s32(x):
    x &= M32
    return x - (1 << 32) if x & 0x80000000 else x


def sb(x):
    x &= 0xFF
    return x - 256 if x & 0x80 else x


def f2b(f):
    return struct.unpack('>I', struct.pack('>f', f))[0]


def b2f(b):
    return struct.unpack('>f', struct.pack('>I', b & M32))[0]


def x32(v):
    """Assert v is exactly a float32 (so no rounding was involved) and return it."""
    if math.isnan(v):
        return v
    r = b2f(f2b(v))
    assert r == v, f'inexact float32 step {v!r}'
    return v


def load(path):
    rom = open(path, 'rb').read()
    h = hashlib.md5(rom).hexdigest()
    assert h == MD5[path], f'{path}: md5 {h}'
    return rom


def u16(rom, a):
    return struct.unpack('>H', rom[a:a + 2])[0]


def u32(rom, a):
    return struct.unpack('>I', rom[a:a + 4])[0]


class Mem:
    """Oracle memory: bytes the case initialised; reading anything else raises (read-set check)."""

    def __init__(self, init):
        self.b = dict(init)
        self.w = set()

    def r8(self, a):
        return self.b[a & M32]

    def r16(self, a):
        return (self.r8(a) << 8) | self.r8(a + 1)

    def r32(self, a):
        return (self.r16(a) << 16) | self.r16(a + 2)

    def rf(self, a):
        return b2f(self.r32(a))

    def w8(self, a, v):
        self.b[a & M32] = v & 0xFF
        self.w.add(a & M32)

    def w16(self, a, v):
        self.w8(a, v >> 8)
        self.w8(a + 1, v)

    def w32(self, a, v):
        self.w16(a, (v >> 16) & 0xFFFF)
        self.w16(a + 2, v & 0xFFFF)


class Init(dict):
    def p8(self, a, v):
        self[a & M32] = v & 0xFF

    def p16(self, a, v):
        self.p8(a, v >> 8)
        self.p8(a + 1, v)

    def p32(self, a, v):
        self.p16(a, (v >> 16) & 0xFFFF)
        self.p16(a + 2, v & 0xFFFF)

    def pf(self, a, f):
        self.p32(a, f2b(f))


def new_emu(rom, init):
    emu = E.Emu(rom)
    for a, v in init.items():
        emu.ram_u8(a, v)
    return emu


def compare(tag, emu, m, elog, olog):
    ew = set(emu.writes)
    check(ew == m.w, f'{tag}: write set differs: emu-only {sorted(hex(a) for a in ew - m.w)[:8]} '
                     f'oracle-only {sorted(hex(a) for a in m.w - ew)[:8]}')
    for a in ew & m.w:
        check(emu.writes[a] == m.b[a], f'{tag}: byte {a:#x} emu {emu.writes[a]:#04x} oracle {m.b[a]:#04x}')
    check(elog == olog, f'{tag}: call log differs\n  emu    {elog}\n  oracle {olog}')
    check(not emu.uninit_reads, f'{tag}: emulator read uninitialised RAM {sorted(hex(a) for a in emu.uninit_reads)[:8]}')


# =====================================================================================
# callee models (each one has its own emulator test below)
# =====================================================================================
def dist(a, t):                                   # 0x03DD80
    d = (t - a) & M32
    if not s32(d) > 0:                            # cmp/pl r5: T when r5 > 0
        d = (d + FULL) & M32
    return d


def mode_03D4F6(m):                               # 0x03D4F6 -> 0x02F8EA
    return 0 if sb(m.r8(F726C)) == 1 else 2


def step_02F8A6(m, n):                            # 0x02F8A6 (n = extu.w)
    for i in range(3):                            # cmp/hi r6,r4: T when n > b (unsigned)
        if not n > m.r8(STEPB + i):
            return m.rf(STEPF + 4 * i)
    return m.rf(STEPF + 12)


def clamp_BE56C(x, lo, hi):
    if not x > lo:
        return lo
    if hi > x:
        return x
    return hi


def dur_02F9E0(m, n, A, B, log):                  # 0x02F9E0
    log.append(('FCBA', n))
    log.append(('FB1C', n))
    p = x32(A * m.rf(F72E0))
    p = x32(p * m.rf(F72E4))
    p = x32(p * B)
    p = x32(p * m.rf(F72F4))
    r = x32(m.rf(F7300) + x32(p * m.rf(F72E8)))
    return clamp_BE56C(r, 0.0, 262136.0)


def call_03D50E(m, r):                            # pending angle  rec+32
    b0 = sb(m.r8(r))
    if b0 == 0:
        f = step_02F8A6(m, m.r16(r + 4))
        m.w32(r + 32, int(x32(f * 65536.0)) & M32)
    elif b0 == 1:
        v = x32(11796480.0 + x32(m.rf(A7280) * 65536.0))
        m.w32(r + 32, int(v) & M32)


def call_03D582(m, r, A, B, log):                 # pending duration rec+24, clears rec+36
    b0 = sb(m.r8(r))
    if b0 == 0:
        f = dur_02F9E0(m, m.r16(r + 4), A, B, log)
        v = x32(x32(f * m.rf(K7DA4)) / 0.25)
        m.w32(r + 24, int(v) & M32)
        m.w8(r + 36, 0)
    elif b0 == 1:
        ch = m.r8(r + 12)
        if ch <= 3:
            v = x32(x32(m.rf(T7290 + 4 * ch) * m.rf(K7DA4)) / 0.25)
            m.w32(r + 24, int(v) & M32)
        m.w8(r + 36, 0)


def q_code(n):
    """Integer model of 0x03D93E..0x03D958 exactly as the instructions do it (dmuls.l / swap.w / ...)."""
    M = s32(0xB60B60B7)
    mach = (n * M) >> 32                          # dmuls.l r11,r1 ; sts mach,r6 (floor of the 64-bit product / 2^32)
    r6 = (mach + n) & M32                         # add r11,r6
    r2 = ((r6 << 16) | (r6 >> 16)) & M32          # swap.w
    r2 = s32(r2 & 0xFFFF if not r2 & 0x8000 else (r2 & 0xFFFF) | 0xFFFF0000)  # exts.w
    r2 = (r2 << 1) & M32                          # shal
    r2 = (r2 & M32) >> 8                          # shlr8
    r2 = r2 & 0xFFFF
    r2 = r2 - 0x10000 if r2 & 0x8000 else r2      # exts.w
    r0 = 1 if r2 < 0 else 0                       # rotl ; and #1  (sign bit)
    return (r2 + r0 + 1) & M32


# =====================================================================================
# 0x03D856 oracle
# =====================================================================================
def oracle_03D856(rom, m, arg, A, B, tree=None):
    """tree=None: the body alone (0x03DB16 / 0x03DD8E / 0x03DE6E / fire functions are stubbed and logged).
    tree=list: the whole call tree -- the callee models below are composed in, with the real check
    functions (chk_real, which runs the 0x03E0FA model) and only the four drivers left as stubs; the
    callee logs go to that list."""
    log = []
    sub = tree

    def chk(fn, r):                               # the models log ('CHK', fn, r, d) just before asking
        return chk_real(rom, m, fn, r, sub[-1][3])
    seg = arg & 0xFF
    delta = seg - m.r8(S + 12)
    if delta < 0:
        delta += 24
    m.w8(S + 12, seg)
    s = seg - 24 if seg >= 24 else seg
    ang = ((s * 15) << 17) & M32
    if sb(m.r8(S + 13)) == 1:
        m.w8(S + 13, 0); m.w8(S + 9, 0); m.w16(S + 10, 0); m.w16(S, 0); m.w32(S + 4, 0)
        for k in range(4):
            r = REC + 40 * k
            for o in (0, 1, 6, 7, 3, 2):
                m.w8(r + o, 0)
            m.w16(r + 4, 0)
            m.w32(r + 20, 0); m.w32(r + 24, 0); m.w32(r + 28, FULL); m.w32(r + 32, FULL)
            m.w8(r + 36, 0); m.w8(r + 17, 0)
        for k in range(4):
            r = REC + 40 * k
            r11 = s32(dist(ang, m.r32(r + 8)))
            call_03D50E(m, r)
            r14 = max(0, s32(m.r32(r + 32)))
            if r11 >= r14 and r11 < FULL:
                m.w16(S, min(m.r16(S) + 1, 0xFFFF))
                n = r11 - r14
                q = q_code(n)
                assert q == n // HALF + 1
                m.w16(r + 4, q & 0xFFFF)
                m.w8(r + 3, 1)
                m.w8(r + 2, 0)
            else:
                m.w16(r + 4, 0)
                m.w8(r + 3, 0)
                m.w8(r + 2, 2)
    else:
        if delta != 1:
            log.append(('DB16',))
            if tree is not None:
                model_DB16(rom, m, A, B, chk, sub)   # writes S+9 / S+10 itself (0x03DB4A / 0x03DB4E)
    mm = mode_03D4F6(m)
    if mm != m.r8(S + 9):
        nm = sb(rom[0x063DFC + mm]) & M32
        log.append(('DD8E', ang, nm))
        if tree is not None:
            model_DD8E(rom, m, ang, nm, chk, sub)
        m.w8(S + 9, mm)
    k16 = m.r16(MASK)
    if k16 != m.r16(S + 10):
        log.append(('DE6E', ang, k16))
        if tree is not None:
            model_DE6E(rom, m, ang, k16, chk, sub)
        m.w16(S + 10, k16)
    for k in range(4):
        r = REC + 40 * k
        d = dist(ang, m.r32(r + 8))
        ds = s32(d)
        if ds >= FULL:
            m.w8(r + 17, 0)
            m.w8(r + 2, 0)
            m.w8(r + 7, 0)
            m.w8(r, rom[0x063DFC + m.r8(S + 9)])
            bit = u16(rom, 0x063DDC + 2 * m.r8(r + 12))
            m.w8(r + 1, 1 if (m.r16(S + 10) & bit) else 0)
            m.w8(r + 3, 0)
        T = 0x063E00 + 16 * sb(m.r8(r))
        st = sb(m.r8(r + 2))
        if st == 0:
            if m.r8(STAT + 28 * m.r8(r + 16)) != 0:
                continue
            if not ds > s32(u32(rom, T + 4)):
                m.w8(r + 2, 2)
                continue
            if ds > s32(u32(rom, T)):
                continue
            if m.r8(r + 3) == 0:
                m.w16(S, min(m.r16(S) + 1, 0xFFFF))
                m.w16(r + 4, m.r16(S))
                m.w8(r + 3, 1)
            if m.r8(r + 1) != 0:
                continue
            call_03D50E(m, r)
            m.w32(r + 28, m.r32(r + 32))
        elif st == 1:
            if m.r8(r + 1) != 0:
                continue
            if sb(m.r8(r + 6)) != 1:
                continue
        else:
            continue
        call_03D582(m, r, A, B, log)
        fn = u32(rom, T + 8)
        log.append(('FIRE', fn, r, d))
        if tree is not None:
            model_fire(rom, m, fn, r, d, (lambda r=r: e0fa_model(rom, m, r + 16)), sub)
    return log


def e0fa_model(rom, m, sub):
    """0x03E0FA(sub = rec+16): 180 * Q16div(rec+24 + cal long [0x0CBDB4] + [4280], [4158]) + rec+28 (mul.l low
    32 bits).  Only the positive, unsaturated domain is modelled; the tree cases stay inside it (asserted)."""
    cal = s32(u32(rom, 0x0CBDB4))
    t = s32(m.r32(sub + 8) + cal + m.r32(R4280))
    dv = s32(m.r32(R4158))
    assert t > 0 and dv > 0 and t // dv <= 32767, (t, dv)
    q = t * 65536 // dv
    return (q * 180 + m.r32(sub + 12)) & M32


def chk_real(rom, m, fn, r, d):
    """The two check functions with 0x03E0FA modelled (not stubbed): 0x03E26E / 0x03E0BA."""
    if fn == CHK0:
        return 1 if s32(d) >= s32(m.r32(r + 32)) else 0
    assert fn == CHK1
    if not s32(d) > s32(m.r32(r + 32)):
        return 0
    return 1 if s32(d) >= s32(e0fa_model(rom, m, r + 16)) else 0


def put_inputs_common(I, rng):
    """Float and byte inputs read by 0x03D50E / 0x03D582 / 0x02F8A6 / 0x02F9E0."""
    I.p8(F726C, rng.choice([0, 1, 1, 2, 0xFF]))
    I.pf(A7280, rng.randrange(-80, 241) / 4.0)
    for ch in range(4):
        I.pf(T7290 + 4 * ch, rng.randrange(0, 1 << 18) / 4.0)
    I.pf(K7DA4, rng.choice([1.0, 1.0, 1.0, 2.0, 0.5]))
    for i in range(4):
        I.pf(STEPF + 4 * i, rng.choice([0.0, 5.0, 90.5, 180.0, 360.0, 400.25, -10.0]))
    for i in range(3):
        I.p8(STEPB + i, rng.choice([0, 1, 2, 3, 5, 10, 200, 255]))
    for a in (F72E0, F72E4, F72F4, F72E8):
        I.pf(a, rng.choice([1.0, 1.0, 0.5, 1.5, 2.0, 0.0]))
    I.pf(F7300, rng.choice([0.0, 256.5, -100.0, 300000.0, 600.0]))


def rand_state_03D856(rng):
    I = Init()
    I.p16(S, rng.choice([0, 1, 5, 0xFFFE, 0xFFFF, rng.randrange(65536)]))
    I.p32(S + 4, rng.randrange(1 << 32))
    I.p8(S + 8, rng.randrange(256))
    I.p8(S + 9, rng.choice([0, 2]))
    I.p16(S + 10, rng.choice([0, 0, 0xFFFF, 1, 2, 4, 8, 0xF, rng.randrange(65536)]))
    prev = rng.randrange(48)
    I.p8(S + 12, prev)
    I.p8(S + 13, rng.choice([0, 0, 0, 0, 1, 2, 0x81]))
    used = set()
    for k in range(4):
        r = REC + 40 * k
        I.p8(r, rng.choice([0, 1]))
        I.p8(r + 1, rng.choice([0, 0, 1]))
        I.p8(r + 2, rng.choice([0, 0, 1, 1, 2, 3]))
        I.p8(r + 3, rng.choice([0, 1]))
        I.p16(r + 4, rng.choice([0, 1, 3, 7, 0xFFFF, rng.randrange(300)]))
        I.p8(r + 6, rng.choice([0, 1, 1, 2]))
        I.p8(r + 7, rng.choice([0, 1]))
        c = rng.random()
        if c < 0.6:
            t = [0, 360, 180, 540][k] << 16
        elif c < 0.85:
            t = (rng.randrange(24) * 30) << 16
        else:
            t = rng.randrange(FULL)
        I.p32(r + 8, t)
        I.p8(r + 12, k if rng.random() < 0.85 else rng.randrange(16))
        hw = k if rng.random() < 0.8 else rng.randrange(8)
        used.add(hw)
        I.p8(r + 16, hw)
        I.p8(r + 17, rng.choice([0, 1, 2]))
        I.p32(r + 20, rng.randrange(1 << 20))
        I.p32(r + 24, rng.randrange(1 << 20))
        I.p32(r + 28, (rng.randrange(721)) << 16)
        I.p32(r + 32, (rng.randrange(721)) << 16)
        I.p8(r + 36, rng.choice([0, 0, 1]))
    for hw in used:
        I.p8(STAT + 28 * hw, rng.choice([0, 0, 0, 1, 0x80]))
    msk = rng.choice([I[S + 10] << 8 | I[S + 11]] * 3 + [0, 1, 0xFFFF, rng.randrange(65536)])
    I.p16(MASK, msk)
    put_inputs_common(I, rng)
    c = rng.random()
    if c < 0.55:
        arg = (prev + 1) % 48 if prev != 23 else 24
    elif c < 0.9:
        arg = rng.randrange(48)
    else:
        arg = rng.randrange(256)
    A = rng.choice([0.0, 8.0, 1024.0, 4096.0, 50176.0, 99328.0])
    B = rng.choice([1.0, 0.5, 1.5, 2.0])
    return I, arg, A, B


def stub_common_03D856(emu, log, A, B, handlers=True, rec_calls=True):
    def rec(name, regs=(), ret=None, fr0=None):
        def fn(e):
            log.append((name,) + tuple(e.R[i] for i in regs))
            if ret is not None:
                e.R[0] = ret
            if fr0 is not None:
                e.set_fr(0, fr0)
        return fn
    emu.stub(0x02FCBA, fn=rec('FCBA', (4,), fr0=A))
    emu.stub(0x02FB1C, fn=rec('FB1C', (4,), fr0=B))
    if rec_calls:
        emu.stub(0x03DB16, fn=rec('DB16'))
        emu.stub(0x03DD8E, fn=rec('DD8E', (4, 5)))
        emu.stub(0x03DE6E, fn=rec('DE6E', (4, 5)))
    if handlers:
        for h in (FIRE0, FIRE1):
            emu.stub(h, fn=(lambda h: (lambda e: log.append(('FIRE', h, e.R[4], e.R[5]))))(h))


def test_03D856(rom, ncase, seed, tag):
    say(f'\n== 0x03D856 against oracle_03D856: {ncase} seeded states ({tag}) ==')
    rng = random.Random(seed)
    stats = {'init': 0, 'db16': 0, 'dd8e': 0, 'de6e': 0, 'fire': 0, 'q': set()}
    shown = 0
    for i in range(ncase):
        I, arg, A, B = rand_state_03D856(rng)
        m = Mem(I)
        olog = oracle_03D856(rom, m, arg, A, B)
        emu = new_emu(rom, I)
        elog = []
        stub_common_03D856(emu, elog, A, B)
        emu.call(0x03D856, {4: arg})
        compare(f'03D856[{tag} {i}]', emu, m, elog, olog)
        if sb(I[S + 13]) == 1:
            stats['init'] += 1
            for k in range(4):
                stats['q'].add(m.r16(REC + 40 * k + 4))
        for e in olog:
            if e[0] == 'DB16':
                stats['db16'] += 1
            elif e[0] == 'DD8E':
                stats['dd8e'] += 1
            elif e[0] == 'DE6E':
                stats['de6e'] += 1
            elif e[0] == 'FIRE':
                stats['fire'] += 1
        if shown < 6 and any(e[0] == 'FIRE' for e in olog):
            shown += 1
            say(f'  case {i}: arg={arg} prev={I[S + 12]} init={I[S + 13]} -> calls ' +
                ', '.join(e[0] if e[0] != 'FIRE' else f'FIRE {e[1]:06X} rec {e[2] - REC:#04x} d={s32(e[3]) / 65536:g}'
                          for e in olog if e[0] in ('DB16', 'DD8E', 'DE6E', 'FIRE')))
    say(f'  coverage: init path {stats["init"]}, resync calls {stats["db16"]}, mode-change calls {stats["dd8e"]}, '
        f'mask-change calls {stats["de6e"]}, fire calls {stats["fire"]}, init-path counts seen {sorted(stats["q"])}')
    check(stats['init'] > 20 and stats['db16'] > 20 and stats['dd8e'] > 20 and stats['de6e'] > 20 and
          stats['fire'] > 100, f'{tag}: coverage too thin {stats}')


def test_03D856_crafted(rom):
    """Hand-built cases that pin the edge behaviours the trace file states in words."""
    say('\n== 0x03D856 crafted edges ==')

    def base():
        I = Init()
        I.p16(S, 0); I.p32(S + 4, 0); I.p8(S + 8, 0); I.p8(S + 9, 2); I.p16(S + 10, 0)
        I.p8(S + 12, 11); I.p8(S + 13, 0)
        for k in range(4):
            r = REC + 40 * k
            for o in (0, 1, 2, 3, 6, 7, 17, 36):
                I.p8(r + o, 0)
            I.p8(r, 1)
            I.p8(r + 2, 2)
            I.p16(r + 4, 0)
            I.p32(r + 8, [0, 360, 180, 540][k] << 16)
            I.p8(r + 12, k); I.p8(r + 16, k)
            I.p32(r + 20, 0); I.p32(r + 24, 0); I.p32(r + 28, FULL); I.p32(r + 32, FULL)
            I.p8(STAT + 28 * k, 0)
        I.p16(MASK, 0)
        I.p8(F726C, 0)
        I.pf(A7280, 10.0); I.pf(K7DA4, 1.0)
        for ch in range(4):
            I.pf(T7290 + 4 * ch, 1000.0 + ch)
        for i in range(4):
            I.pf(STEPF + 4 * i, 90.0)
        for i in range(3):
            I.p8(STEPB + i, 5)
        for a in (F72E0, F72E4, F72F4, F72E8):
            I.pf(a, 1.0)
        I.pf(F7300, 0.0)
        return I

    def run(I, arg, note, expect):
        m = Mem(I)
        olog = oracle_03D856(rom, m, arg, 0.0, 1.0)
        emu = new_emu(rom, I)
        elog = []
        stub_common_03D856(emu, elog, 0.0, 1.0)
        emu.call(0x03D856, {4: arg})
        compare(f'crafted {note}', emu, m, elog, olog)
        fires = [(e[2] - REC) // 40 for e in elog if e[0] == 'FIRE']
        say(f'  {note}: arg {arg} -> fired channels {fires}; states ' +
            str([emu.read_u8(REC + 40 * k + 2) for k in range(4)]))
        expect(emu, fires, elog)

    # 1. arg 12 after 11 (delta 1): channel 1 (target 360) is at distance 720 -> re-armed AND fired in the same call
    I = base()
    run(I, 12, 'target reached', lambda e, f, l: check(f == [1] and e.read_u8(REC + 40 + 2) == 0 and
                                                         e.read_u32(REC + 40 + 24) == 4004 and
                                                         e.read_u32(REC + 40 + 32) == 190 << 16 and
                                                         e.read_u32(REC + 40 + 28) == 190 << 16, 'crafted 1'))
    # 1b. same with the channel's cut bit set in the mask copy: re-armed, rec+1 = 1, NOT fired
    I = base(); I.p16(S + 10, 2); I.p16(MASK, 2)
    run(I, 12, 'target reached, bit 1 set', lambda e, f, l: check(f == [] and e.read_u8(REC + 40 + 1) == 1 and
                                                                    e.read_u8(REC + 40 + 2) == 0, 'crafted 1b'))
    # 2. armed channel whose distance is <= 100 deg: state 2 (missed), no fire
    I = base(); I.p32(REC + 40 + 8, (12 * 30 + 90) << 16); I.p8(REC + 40 + 2, 0)
    run(I, 12, 'armed, d=90', lambda e, f, l: check(f == [] and e.read_u8(REC + 40 + 2) == 2, 'crafted 2'))
    # 2b. d exactly 100 deg -> still state 2 (needs d > 100)
    I = base(); I.p32(REC + 40 + 8, (12 * 30 + 100) << 16); I.p8(REC + 40 + 2, 0)
    run(I, 12, 'armed, d=100', lambda e, f, l: check(f == [] and e.read_u8(REC + 40 + 2) == 2, 'crafted 2b'))
    # 2c. d = 100 deg + 1 lsb -> fires
    I = base(); I.p32(REC + 40 + 8, ((12 * 30 + 100) << 16) + 1); I.p8(REC + 40 + 2, 0)
    run(I, 12, 'armed, d=100+2^-16', lambda e, f, l: check(f == [1], 'crafted 2c'))
    # 3. hardware status byte non-zero: armed channel waits (no state change, no fire)
    I = base(); I.p8(STAT + 28 * 1, 1)
    run(I, 12, 'target reached, status busy', lambda e, f, l: check(f == [] and e.read_u8(REC + 40 + 2) == 0, 'crafted 3'))
    # 4. state 1 fires again only with rec+6 == 1 and rec+1 == 0
    I = base()
    for k in range(4):
        I.p8(REC + 40 * k + 2, 1)
        I.p8(REC + 40 * k + 6, 1 if k == 2 else 0)
    I.p32(REC + 40 + 8, 0x01000000)
    run(I, 12, 'state 1, rec+6 only on ch2', lambda e, f, l: check(f == [2], 'crafted 4'))
    # 5. delta != 1 -> 0x03DB16 first
    I = base()
    run(I, 14, 'skip (delta 3)', lambda e, f, l: check(l[0] == ('DB16',), 'crafted 5'))
    # 6. delta wraps through 24: prev 23 -> arg 0 is delta 1 (no resync); prev 47 -> arg 0 is delta -47+24 != 1
    I = base(); I.p8(S + 12, 23)
    run(I, 0, 'prev 23 -> 0', lambda e, f, l: check(('DB16',) not in l, 'crafted 6a'))
    I = base(); I.p8(S + 12, 47)
    run(I, 0, 'prev 47 -> 0', lambda e, f, l: check(('DB16',) in l, 'crafted 6b'))
    # 7. arg 36 is reduced to 12 (same angle as arg 12)
    I = base(); I.p8(S + 12, 35)
    run(I, 36, 'arg 36 (>=24)', lambda e, f, l: check(f == [1], 'crafted 7'))
    # 8. init request: counts q = floor((d - max(0,step0)) / 180) + 1 ; S+0 counts the windows
    I = base(); I.p8(S + 13, 1); I.p8(S + 12, 5); I.pf(STEPF, 0.0)
    run(I, 6, 'init at arg 6 (180 deg), step0 = 0', lambda e, f, l: check(
        [e.read_u16(REC + 40 * k + 4) for k in range(4)] == [4, 2, 4, 3] and e.read_u16(S) == 4 and
        ('DD8E', 180 << 16, 1) in l and len([x for x in l if x[0] == 'FIRE']) == 4, 'crafted 8'))
    # 8b. init with step0 = 360 deg: channels whose distance < 360 get state 2, count 0
    I = base(); I.p8(S + 13, 1); I.p8(S + 12, 5); I.pf(STEPF, 360.0)
    run(I, 6, 'init at arg 6, step0 = 360', lambda e, f, l: check(
        [e.read_u16(REC + 40 * k + 4) for k in range(4)] == [2, 0, 3, 1] and
        [e.read_u8(REC + 40 * k + 2) for k in range(4)][1] == 2 and e.read_u16(S) == 3, 'crafted 8b'))
    # 9. S+0 saturates at 0xFFFF
    I = base(); I.p16(S, 0xFFFF)
    run(I, 12, 'counter at 0xFFFF', lambda e, f, l: check(e.read_u16(S) == 0xFFFF and
                                                           e.read_u16(REC + 40 + 4) == 0xFFFF, 'crafted 9'))


def test_q_division():
    """Prove q_code(n) == n // (180<<16) + 1 for every n in [0, 720<<16) without enumerating 47M values:
    g(n) = floor(n*M/2^32) + n is non-decreasing (each step adds 1 + {-1 or 0} because -1 < M/2^32 < 0), so
    g(n) >> 23 is non-decreasing; it is then enough that the quotient is right on both sides of each step."""
    say('\n== magic-number division at 0x03D93E ==')
    M = s32(0xB60B60B7)
    check(-(1 << 32) < M < 0, 'magic in (-2^32, 0)')
    for k in range(1, 4):
        for n in (k * HALF - 2, k * HALF - 1, k * HALF, k * HALF + 1):
            check(q_code(n) == n // HALF + 1, f'q at {n:#x}')
    for n in (0, 1, FULL - 1):
        check(q_code(n) == n // HALF + 1, f'q at {n:#x}')
    rng = random.Random(7)
    for _ in range(20000):
        n = rng.randrange(FULL)
        check(q_code(n) == n // HALF + 1, f'q at {n:#x}')
    say('  q(n) = floor(n / 180deg) + 1 on [0, 720deg): checked at all step edges and 20,000 samples; '
        'monotonicity from the magic number range')


def test_q_bytes(rom):
    """The ROM instructions 0x03D93E..0x03D958 themselves (not the integer model): run from 0x03D93E with
    r11 = n and stop at 0x03D95A, where r2 = q."""
    say('\n== the divide instructions 0x03D93E..0x03D958 run from ROM ==')
    pts = [0, 1, FULL - 1] + [k * HALF + j for k in range(1, 4) for j in (-2, -1, 0, 1)]
    rng = random.Random(9)
    pts += [rng.randrange(FULL) for _ in range(3000)]
    for n in pts:
        emu = E.Emu(rom)
        emu.call(0x03D93E, {11: n}, stop_at=(0x03D95A,))
        check(emu.R[2] == n // HALF + 1 and emu.R[2] == q_code(n), f'q bytes at {n:#x}: {emu.R[2]}')
    say(f'  {len(pts)} values of n (all step edges + 3,000 samples): r2 = floor(n / 180deg) + 1 = q_code(n)')


# =====================================================================================
# callee tests
# =====================================================================================
def test_small_callees(rom):
    say('\n== small callees ==')
    # 0x03DD80
    pts = [0, 1, HALF, FULL - 1, FULL, 0x7FFFFFFF, M32]
    for a in pts:
        for t in pts:
            emu = E.Emu(rom)
            emu.call(0x03DD80, {4: a, 5: t})
            check(emu.R[0] == dist(a, t), f'03DD80({a:#x},{t:#x})')
    emu = E.Emu(rom); emu.call(0x03DD80, {4: HALF, 5: HALF})
    say(f'  0x03DD80(180deg, 180deg) = {s32(emu.R[0]) / 65536:g} deg (equal angles give 720, never 0)')
    check(emu.R[0] == FULL, 'dist equal = 720')
    # 0x03D4F6
    for v in range(256):
        I = Init(); I.p8(F726C, v)
        emu = new_emu(rom, I); emu.call(0x03D4F6)
        check(emu.R[0] == (0 if v == 1 else 2), f'03D4F6 byte {v}')
    say('  0x03D4F6: r0 = 0 when byte [0xFFFF726C] == 1, else 2 (all 256 values)')
    # 0x02F8A6
    for bps in ((0, 0, 0), (2, 5, 9), (10, 3, 200), (255, 255, 255)):
        for n in list(range(0, 12)) + [199, 200, 201, 254, 255, 256, 0xFFFF]:
            I = Init()
            for i in range(3):
                I.p8(STEPB + i, bps[i])
            for i in range(4):
                I.pf(STEPF + 4 * i, 100.0 + i)
            emu = new_emu(rom, I); emu.call(0x02F8A6, {4: n})
            m = Mem(I)
            check(emu.fr(0) == step_02F8A6(m, n), f'02F8A6 n={n} bps={bps}')
            check(not emu.writes and not emu.uninit_reads, '02F8A6 writes nothing / reads only the 7 cells')
    say('  0x02F8A6: fr0 = [72B4] if n<=b0 elif n<=b1 [72B8] elif n<=b2 [72BC] else [72C0] (unsigned compares)')
    # 0x03D50E / 0x03D582 / 0x02F9E0
    rng = random.Random(11)
    for i in range(400):
        I = Init()
        put_inputs_common(I, rng)
        r = REC
        I.p8(r, rng.choice([0, 1, 2, 0x80, 0xFF]))
        I.p16(r + 4, rng.choice([0, 1, 4, 6, 11, 300, 0xFFFF]))
        I.p8(r + 12, rng.choice([0, 1, 2, 3, 4, 200]))
        I.p32(r + 24, 0x12345678); I.p32(r + 32, 0x9ABCDEF0); I.p8(r + 36, 7)
        A = rng.choice([0.0, 8.0, 1024.0, 4096.0, 50176.0, 99328.0])
        B = rng.choice([1.0, 0.5, 1.5, 2.0])
        for entry in (0x03D50E, 0x03D582):
            m = Mem(I); olog = []
            if entry == 0x03D50E:
                call_03D50E(m, r)
            else:
                call_03D582(m, r, A, B, olog)
            emu = new_emu(rom, I); elog = []
            stub_common_03D856(emu, elog, A, B, handlers=False, rec_calls=False)
            emu.call(entry, {4: r})
            compare(f'{entry:06X}[{i}]', emu, m, elog, olog)
    # explicit clamp edges of 0x02F9E0
    for (c7300, A, want) in ((-1.0, 0.0, 0.0), (0.0, 0.0, 0.0), (0.25, 0.0, 0.25), (262135.75, 0.0, 262135.75),
                             (262136.0, 0.0, 262136.0), (262140.0, 0.0, 262136.0), (float('nan'), 0.0, 0.0)):
        I = Init()
        for a in (F72E0, F72E4, F72F4, F72E8):
            I.pf(a, 1.0)
        I.pf(F7300, c7300)
        emu = new_emu(rom, I); elog = []
        stub_common_03D856(emu, elog, A, 1.0, handlers=False, rec_calls=False)
        emu.call(0x02F9E0, {4: 3})
        check(emu.fr(0) == want, f'02F9E0 clamp {c7300} -> {emu.fr(0)}')
    say('  0x02F9E0: fr0 = clamp([7300] + F(n)*[72E0]*[72E4]*G(n)*[72F4]*[72E8], 0, 262136); NaN -> 0 (checked)')
    say('  0x03D50E / 0x03D582: 400 seeded records x {mode 0,1,2,0x80,0xFF} x channel byte, against the models')
    # 0x03DD4E
    for b in list(range(0, 48)) + [255]:
        for r4 in (0, -(10 << 16), -(400 << 16), 5 << 16, FULL):
            I = Init(); I.p8(S + 12, b)
            emu = new_emu(rom, I); emu.call(0x03DD4E, {4: r4 & M32})
            want = (((b * 15) << 17) - r4 + s32(0xFFF60000)) & M32
            if s32(want) >= FULL:
                want = (want - FULL) & M32
            elif s32(want) < 0:
                want = (want + FULL) & M32
            check(emu.R[0] == want, f'03DD4E b={b} r4={r4}')
    say('  0x03DD4E(r4): r0 = 30*[7E54] - 10 - r4 (deg, 16.16), folded once into [0,720)')


def chk_model(rom, m, fn, r, d, fa_vals, log):
    """Models of the two check functions (table +12): 0x03E26E (mode 0) and 0x03E0BA (mode 1)."""
    if fn == CHK0:
        return 1 if s32(d) >= s32(m.r32(r + 32)) else 0
    assert fn == CHK1
    if not s32(d) > s32(m.r32(r + 32)):
        return 0
    v = fa_vals(r + 16)
    log.append(('E0FA', r + 16))
    return 1 if s32(d) >= s32(v) else 0


def test_check_fns(rom):
    say('\n== check functions 0x03E26E / 0x03E0BA / 0x03E0FA ==')
    rng = random.Random(21)
    for i in range(600):
        I = Init()
        r = REC + 40 * rng.randrange(4)
        I.p32(r + 32, rng.choice([0, 1, 100 << 16, 360 << 16, FULL, rng.randrange(FULL)]))
        d = rng.choice([0, 1, 100 << 16, 360 << 16, (360 << 16) + 1, FULL, rng.randrange(FULL)])
        ret = rng.choice([0, 1 << 16, 360 << 16, FULL, rng.randrange(FULL)])
        for fn in (CHK0, CHK1):
            m = Mem(I); olog = []
            want = chk_model(rom, m, fn, r, d, lambda s: ret, olog)
            emu = new_emu(rom, I); elog = []
            emu.stub(0x03E0FA, fn=lambda e: (elog.append(('E0FA', e.R[4])), e.R.__setitem__(0, ret)))
            emu.call(fn, {4: r, 5: d})
            check((emu.R[0] & 0xFF) == want and elog == olog and not emu.writes, f'check {fn:06X} case {i}')
    # 0x03E0FA with the verified 0x0BE654 contract
    cal = s32(u32(rom, 0x0CBDB4))
    for (dur, a4280, a4158, ang) in ((0, 0, 0x10000, 0), (1000, 0, 0x7850, 5 << 16), (0x10000 - cal, 0, 0x10000, 0),
                                     (3 * 0x20000 - cal, 0, 0x20000, 30 << 16), (100, 50, 0, 0), (-cal, 0, 0, 7)):
        I = Init(); r = REC
        I.p32(r + 24, dur & M32); I.p32(r + 28, ang & M32); I.p32(R4280, a4280); I.p32(R4158, a4158)
        emu = new_emu(rom, I); emu.call(0x03E0FA, {4: r + 16})
        t = s32(dur + cal + a4280)
        if t == 0:
            q = 0
        elif a4158 == 0:
            q = 0x7FFFFFFF if t > 0 else -0x80000000
        else:
            q = abs(t) * 65536 // abs(a4158) * (1 if (t > 0) == (a4158 > 0) else -1)
            if abs(t) // abs(a4158) > 32767:
                q = 0x7FFFFFFF if (t > 0) == (a4158 > 0) else -0x80000000
        want = ((q * 180) + ang) & M32
        check(emu.R[0] == want, f'03E0FA dur={dur} 4158={a4158}: {emu.R[0]:#x} vs {want:#x}')
    say(f'  0x03E0FA(sub): r0 = 180 * Q16div(rec+24 + cal[0x0CBDB4] ({cal}) + [4280], [4158]) + rec+28 (6 cases); '
        '0x03E26E / 0x03E0BA: 600 cases each')


def model_DD8E(rom, m, ang, r5, chkret, log):
    nm = sb(r5 & 0xFF)
    for k in range(4):
        r = REC + 40 * k
        if sb(m.r8(r)) == nm:
            continue
        d = dist(ang, m.r32(r + 8))
        if not s32(d) > s32(u32(rom, 0x063E04 + 16 * nm)):
            continue
        st = sb(m.r8(r + 2))
        if st == 1:
            fn = u32(rom, 0x063E00 + 16 * sb(m.r8(r)) + 12)
            log.append(('CHK', fn, r, d))
            ok = 0
            if sb(chkret(fn, r)) == 1:
                b17 = sb(m.r8(r + 17))
                ok = 0 if (b17 == 1 and m.r8(STAT + 28 * m.r8(r + 16)) == 0) or b17 == 2 else 1
            if ok:
                log.append(('D48', m.r8(r + 16)))
                m.w8(r + 17, 0)
                m.w8(r + 2, 0)
                m.w8(r, nm)
        elif st == 0:
            m.w8(r, nm)


def model_DE6E(rom, m, ang, k16, chkret, log):
    for k in range(4):
        r = REC + 40 * k
        bit = u16(rom, 0x063DDC + 2 * m.r8(r + 12))
        bit = bit - 0x10000 if bit & 0x8000 else bit
        r5 = k16 & bit & M32
        b1 = sb(m.r8(r + 1))
        if b1 == 1:
            r14 = r5 & 0xFFFF
            if r14 != 0:
                continue
        else:
            if b1 != 0:
                continue
            r14 = r5 & 0xFFFF
            if r14 == 0:
                continue
        d = dist(ang, m.r32(r + 8))
        if s32(d) < 0:
            continue
        T = 0x063E00 + 16 * sb(m.r8(r))
        st = sb(m.r8(r + 2))
        if r14 == 0:
            if st == 1:
                m.w8(r + 1, 0)
            elif st == 0:
                fn = u32(rom, T + 12)
                log.append(('CHK', fn, r, d))
                if sb(chkret(fn, r)) == 1:
                    m.w8(r + 1, 0)
                else:
                    m.w8(r + 2, 2)
        else:
            if st == 1:
                b17 = sb(m.r8(r + 17))
                ok = 0 if (b17 == 1 and m.r8(STAT + 28 * m.r8(r + 16)) == 0) or b17 == 2 else 1
                if ok:
                    log.append(('D48', m.r8(r + 16)))
                    m.w8(r + 2, 0)
                    m.w8(r + 1, 1)
            elif st == 0:
                m.w8(r + 1, 1)


def model_DB16(rom, m, A, B, chkret, log):
    seg = m.r8(SEG4167)
    s = seg - 24 if seg >= 24 else seg
    ang = ((s * 15) << 17) & M32
    m.w8(S + 9, mode_03D4F6(m))
    m.w16(S + 10, m.r16(MASK))
    for k in range(4):
        r = REC + 40 * k
        d = dist(ang, m.r32(r + 8))
        m.w8(r + 7, 0)
        m.w8(r, rom[0x063DFC + m.r8(S + 9)])
        bit = u16(rom, 0x063DDC + 2 * m.r8(r + 12))
        m.w8(r + 1, 1 if (m.r16(S + 10) & bit) else 0)
        m.w8(r + 3, 0)
        call_03D582(m, r, A, B, log)
        call_03D50E(m, r)
        log.append(('D48', m.r8(r + 16)))
        m.w8(r + 17, 0)
        m.w32(r + 28, m.r32(r + 32))
        fn = u32(rom, 0x063E0C + 16 * sb(m.r8(r)))
        log.append(('CHK', fn, r, d))
        m.w8(r + 2, 0 if sb(chkret(fn, r)) == 1 else 2)


def test_handlers(rom):
    say('\n== 0x03DD8E (mode change) / 0x03DE6E (mask change) / 0x03DB16 (resync) against their models ==')
    rng = random.Random(31)
    for i in range(900):
        I, arg, A, B = rand_state_03D856(rng)
        I.p8(SEG4167, rng.choice([0, 6, 12, 18, 23, 24, 30, 47, rng.randrange(48)]))
        ang = ((rng.randrange(24) * 15) << 17)
        rets = {}
        for k in range(4):
            rets[REC + 40 * k] = rng.choice([0, 1, 1, 2, 0x101])

        def chkret(fn, r):
            return rets[r]

        def stubs(emu, elog):
            def mk(fn):
                return lambda e: (elog.append(('CHK', fn, e.R[4], e.R[5])), e.R.__setitem__(0, rets[e.R[4]]))
            emu.stub(CHK0, fn=mk(CHK0)); emu.stub(CHK1, fn=mk(CHK1))
            emu.stub(0x009D48, fn=lambda e: elog.append(('D48', e.R[4])))
            emu.stub(0x02FCBA, fn=lambda e: (elog.append(('FCBA', e.R[4])), e.set_fr(0, A)))
            emu.stub(0x02FB1C, fn=lambda e: (elog.append(('FB1C', e.R[4])), e.set_fr(0, B)))
        newmode = rng.choice([0, 1, 1, 0])
        m = Mem(I); olog = []
        model_DD8E(rom, m, ang, newmode, chkret, olog)
        emu = new_emu(rom, I); elog = []; stubs(emu, elog)
        emu.call(0x03DD8E, {4: ang, 5: newmode})
        compare(f'03DD8E[{i}]', emu, m, elog, olog)
        k16 = rng.choice([0, 1, 2, 4, 8, 0xF, 0xFFFF, rng.randrange(65536)])
        m = Mem(I); olog = []
        model_DE6E(rom, m, ang, k16, chkret, olog)
        emu = new_emu(rom, I); elog = []; stubs(emu, elog)
        emu.call(0x03DE6E, {4: ang, 5: k16})
        compare(f'03DE6E[{i}]', emu, m, elog, olog)
        m = Mem(I); olog = []
        model_DB16(rom, m, A, B, chkret, olog)
        emu = new_emu(rom, I); elog = []; stubs(emu, elog)
        emu.call(0x03DB16)
        compare(f'03DB16[{i}]', emu, m, elog, olog)
    say('  900 seeded states each (check returns 0 / 1 / 2 / 0x101 per record): write sets, values and call logs equal')


def model_fire(rom, m, fn, r, d, fa_val, log):
    """fa_val: the value 0x03E0FA returns (int), or a thunk computing it (the tree oracle passes one,
    so the 0x03E0FA model only runs when the bytes call it)."""
    if fn == FIRE0:
        r10 = r11 = 0
        if m.r8(r + 7) != 0:
            m.w8(r + 2, 2)
            m.w8(r + 6, 0)
            return
        sub = r + 16
        b17 = sb(m.r8(sub + 1))
        if b17 == 1:
            if m.r8(sub + 20) == 0:
                m.w32(sub + 4, m.r32(sub + 8))
                log.append(('C38', m.r8(sub), m.r32(sub + 4)))
            elif m.r8(STAT + 28 * m.r8(sub)) != 0:
                log.append(('D48', m.r8(sub)))
                m.w8(sub + 1, 0)
            else:
                log.append(('C38', m.r8(sub), 0))
                m.w8(sub + 1, 2)
        elif b17 == 0 and m.r8(sub + 20) == 0:
            r6 = s32(d - m.r32(sub + 12))
            if r6 >= D30:
                r10 = 1
            elif sb(m.r8(r + 2)) != 0 and not s32(d) >= s32(m.r32(sub + 12)):
                m.w8(sub + 1, 2)
            else:
                m.w32(sub + 4, m.r32(sub + 8))
                a = angle_DD4E(m, 0)
                log.append(('A72', m.r8(sub), m.r32(sub + 4), x32(x32(float(s32(a))) / 65536.0)))
                r11 = 1
                m.w8(sub + 1, 1)
        m.w8(r + 2, 1)
        if r11 == 1:
            v = s32(m.r32(S + 4)) + 1
            m.w32(S + 4, min(v, 0x7FFFFFFF) & M32)
            m.w8(S + 8, 1)
        m.w8(r + 6, r10)
        return
    assert fn == FIRE1
    if m.r8(r + 7) != 0:
        m.w8(r + 2, 2)
        m.w8(r + 6, 0)
        return
    sub = r + 16
    b17 = sb(m.r8(sub + 1))
    if b17 == 1:
        if m.r8(sub + 20) == 0:
            m.w32(sub + 4, m.r32(sub + 8))
            log.append(('C38', m.r8(sub), m.r32(sub + 4)))
        elif m.r8(STAT + 28 * m.r8(sub)) != 0:
            log.append(('D48', m.r8(sub)))
            m.w8(sub + 1, 0)
        else:
            log.append(('C38', m.r8(sub), 0))
            m.w8(sub + 1, 2)
    elif b17 == 0 and m.r8(sub + 20) == 0:
        go = True
        if sb(m.r8(r + 2)) != 0:
            log.append(('E0FA', sub))
            fv = fa_val() if callable(fa_val) else fa_val
            if not s32(d) >= s32(fv):
                m.w8(sub + 1, 2)
                go = False
        if go:
            m.w32(sub + 4, m.r32(sub + 8))
            r4 = s32(m.r32(sub + 12) - d)
            if r4 > 0:
                r4 = 0
            a = angle_DD4E(m, r4)
            log.append(('B2C', m.r8(sub), m.r32(sub + 4), 0, x32(x32(float(s32(a))) / 65536.0)))
            m.w8(sub + 1, 1)
    m.w8(S + 8, 1)
    m.w8(r + 2, 1)
    m.w8(r + 6, 0)


def angle_DD4E(m, r4):
    b = m.r8(S + 12)
    v = (((b * 15) << 17) - r4 + s32(0xFFF60000)) & M32
    if s32(v) >= FULL:
        v = (v - FULL) & M32
    elif s32(v) < 0:
        v = (v + FULL) & M32
    return v


def test_fire_fns(rom):
    say('\n== fire functions 0x03E168 (mode 0) / 0x03DFC8 (mode 1) against their models ==')
    rng = random.Random(41)
    seen = {}
    for i in range(1500):
        I, arg, A, B = rand_state_03D856(rng)
        r = REC + 40 * rng.randrange(4)
        I.p32(r + 28, (rng.randrange(721)) << 16)
        ang28 = s32(I[r + 28] << 24 | I[r + 29] << 16 | I[r + 30] << 8 | I[r + 31])
        dd = {}
        for fn, fine in ((FIRE0, (-1, 0, 1, D30 - 1, D30)), (FIRE1, (-65536, 0, 65536, D30 - 65536, D30))):
            d = rng.choice([FULL, (rng.randrange(1, 721)) << 16])
            if rng.random() < 0.3:
                d = (ang28 + rng.choice(fine)) & M32
            dd[fn] = d
        for fn in (FIRE0, FIRE1):
            d = dd[fn]
            fa_val = rng.choice([0, d, (d + 1) & M32, (d - 1) & M32, FULL])
            m = Mem(I); olog = []
            model_fire(rom, m, fn, r, d, fa_val, olog)
            emu = new_emu(rom, I); elog = []
            emu.stub(0x009C38, fn=lambda e: elog.append(('C38', e.R[4], e.R[5])))
            emu.stub(0x009D48, fn=lambda e: elog.append(('D48', e.R[4])))
            emu.stub(0x009A72, fn=lambda e: elog.append(('A72', e.R[4], e.R[5], e.fr(4))))
            emu.stub(0x009B2C, fn=lambda e: elog.append(('B2C', e.R[4], e.R[5], e.R[6], e.fr(4))))
            emu.stub(0x03E0FA, fn=lambda e: (elog.append(('E0FA', e.R[4])), e.R.__setitem__(0, fa_val)))
            emu.call(fn, {4: r, 5: d})
            compare(f'fire {fn:06X}[{i}]', emu, m, elog, olog)
            for e in olog:
                seen[(fn, e[0])] = seen.get((fn, e[0]), 0) + 1
    say('  driver-call coverage: ' + ', '.join(f'{fn:06X}:{k} x{v}' for (fn, k), v in sorted(seen.items())))
    check(all(seen.get(k, 0) > 10 for k in ((FIRE0, 'C38'), (FIRE0, 'D48'), (FIRE0, 'A72'), (FIRE1, 'C38'),
                                             (FIRE1, 'D48'), (FIRE1, 'B2C'), (FIRE1, 'E0FA'))), 'fire coverage')


# =====================================================================================
# 0x02EB02 -- one pass, and whole sessions
# =====================================================================================
G = 0xFFFF7244
LOCK = 0xFFFF6C48
VOLT = 0xFFFF4130
DATA = 0xFFFF7246
FLAGS = 0xFFFF725D


def cmd_06B5A(rom, op, addr, data):
    t = rom[0x0C0080]
    mask = u16(rom, 0x01193C + 2 * t)
    mask = mask - 0x10000 if mask & 0x8000 else mask
    a = (addr & mask) & 0xFFFF
    return (u32(rom, 0x01190C + 4 * t) + u32(rom, 0x011914 + 20 * t + 4 * (op & 0xFF)) + (a << 16) +
            (data & 0xFFFF)) & M32


def oracle_02EB02(rom, m, busy, readback):
    log = []
    V = m.rf(VOLT)
    if sb(m.r8(G + 22)) != 90:
        m.w8(G + 23, 0)
        while (sb(m.r8(G + 23)) & M32) < 6 and m.r8(FLAGS + m.r8(G + 23)) == 0:
            m.w8(G + 23, m.r8(G + 23) + 1)
        m.w8(G + 35, 0); m.w8(G + 24, 0); m.w8(G + 22, 90); m.w8(G + 0, 0)
    lk = sb(m.r8(LOCK))
    if lk != 0 and lk != -18:
        m.w8(G + 20, 0)
        return log
    log.append(('BUSY',))
    m.w8(G + 38, busy)
    finish = abort = False
    if sb(m.r8(G + 38)) == 1:
        m.w8(G + 20, min(m.r8(G + 20) + 1, 255))
        if m.r8(G + 20) > 6:
            finish = True
        else:
            return log
    else:
        m.w8(G + 20, 0)
        if sb(m.r8(G + 24)) == 3 or m.r8(G + 24) == 2 or 6.0 > V:
            abort = True
    if abort:
        log.append(('SEND2', cmd_06B5A(rom, 4, 0, 0)))
        finish = True
    if finish:
        m.w8(LOCK, 0); m.w8(G + 32, 1); m.w8(G + 22, 0)
        if 6.0 > V:
            m.w8(G + 33, 1)
        return log
    m.w8(G + 21, m.r8(G + 21) + 1)
    m.w8(LOCK, 0xEE)
    log.append(('SEND2', cmd_06B5A(rom, 1, 0, 0)))
    if m.r8(G + 35) == 1:
        log.append(('READ', cmd_06B5A(rom, 0, m.r16(G + 14), 0)))
        m.w16(G + 18, readback)
        if m.r16(G + 18) == m.r16(G + 16):
            m.w8(G + 0, 0)
            if m.r8(G + 23) >= 6:
                m.w8(G + 24, 2)
                return log
        else:
            m.w8(G + 0, min(m.r8(G + 0) + 1, 255))
            if m.r8(G + 24) == 1 and m.r8(G + 0) >= rom[0x0C472C]:
                m.w8(G + 24, 3)
                return log
            log.append(('SEND4', cmd_06B5A(rom, 2, m.r16(G + 14), m.r16(G + 16))))
            m.w8(G + 24, 1)
            return log
    m.w8(G + 24, 0)
    if m.r8(G + 23) >= 6:
        return log
    k = m.r8(G + 23)
    m.w16(G + 16, m.r16(DATA + 2 * k))
    m.w16(G + 14, k + 483)
    log.append(('SEND4', cmd_06B5A(rom, 2, m.r16(G + 14), m.r16(G + 16))))
    m.w8(G + 35, 1)
    while True:
        m.w8(G + 23, m.r8(G + 23) + 1)
        if m.r8(G + 23) >= 6:
            return log
        if m.r8(FLAGS + m.r8(G + 23)) != 0:
            return log


def stub_eeprom(emu, log, busy, readback):
    emu.stub(0x006884, fn=lambda e: (log.append(('BUSY',)), e.R.__setitem__(0, busy)))
    emu.stub(0x0067DC, fn=lambda e: log.append(('SEND2', e.R[4])))
    emu.stub(0x006828, fn=lambda e: log.append(('SEND4', e.R[4])))
    emu.stub(0x0067A6, fn=lambda e: (log.append(('READ', e.R[4])), e.R.__setitem__(0, readback)))


def eb02_state(rng):
    I = Init()
    for a in range(G, G + 39):
        I.p8(a, 0)
    I.p8(G + 22, rng.choice([90, 90, 90, 0, 0x5B]))
    for k in range(6):
        I.p8(FLAGS + k, rng.choice([0, 0, 1, 0xFF]))
        I.p16(DATA + 2 * k, rng.randrange(65536))
    I.p8(G + 23, rng.choice([0, 1, 2, 3, 4, 5, 6]))
    I.p8(G + 24, rng.choice([0, 0, 1, 1, 2, 3, 4]))
    I.p8(G + 35, rng.choice([0, 1, 1, 2]))
    I.p8(G + 0, rng.choice([0, 1, 2, 3, 4, 0xFF]))
    I.p8(G + 20, rng.choice([0, 1, 5, 6, 7, 0xFF]))
    I.p8(G + 21, rng.choice([0, 0x7F, 0xFF]))
    I.p16(G + 14, rng.choice([483, 485, 488]))
    I.p16(G + 16, rng.randrange(65536))
    I.p8(LOCK, rng.choice([0, 0, 0xEE, 0xEE, 1, 0x80, 0x12]))
    I.pf(VOLT, rng.choice([12.5, 6.0, 6.000000476837158, 5.999999523162842, 0.0, -1.0, float('nan'), 14.0]))
    busy = rng.choice([0, 0, 0, 1, 2])
    rb = rng.choice([I[G + 16] << 8 | I[G + 17]] * 2 + [rng.randrange(65536)])
    return I, busy, rb


def test_02EB02_pass(rom, ncase, seed, tag):
    say(f'\n== 0x02EB02 one pass against oracle_02EB02: {ncase} seeded states ({tag}) ==')
    rng = random.Random(seed)
    outcomes = {}
    for i in range(ncase):
        I, busy, rb = eb02_state(rng)
        m = Mem(I)
        olog = oracle_02EB02(rom, m, busy, rb)
        emu = new_emu(rom, I)
        elog = []
        stub_eeprom(emu, elog, busy, rb)
        emu.call(0x02EB02)
        compare(f'02EB02[{tag} {i}]', emu, m, elog, olog)
        key = tuple(e[0] for e in olog)
        outcomes[key] = outcomes.get(key, 0) + 1
    say('  call-sequence outcomes: ' + '; '.join(f'{"/".join(k) or "(none)"} x{v}' for k, v in sorted(outcomes.items())))
    check(len(outcomes) >= 6, 'outcome coverage')


class Eeprom:
    """Device model: decodes the 93Cxx-format command words (type byte [0x0C0080] = 1: start bit 28,
    opcode bits 27..26, address bits 25..16, data 15..0) the routine sends."""

    def __init__(self, bad=None):
        self.mem = {}
        self.ew = False
        self.trace = []
        self.bad = bad or {}

    def send2(self, c):
        assert c >> 28 == 1, hex(c)
        op, a = (c >> 26) & 3, (c >> 16) & 0x3FF
        if op == 0 and a >> 8 == 3:
            self.ew = True; self.trace.append('EWEN')
        elif op == 0 and a >> 8 == 0:
            self.ew = False; self.trace.append('EWDS')
        else:
            raise AssertionError(f'unexpected 2-byte command {c:#x}')

    def send4(self, c):
        op, a, dta = (c >> 26) & 3, (c >> 16) & 0x3FF, c & 0xFFFF
        assert c >> 28 == 1 and op == 1, hex(c)
        self.trace.append(f'WRITE {a}={dta:#06x}')
        if self.ew:
            self.mem[a] = dta ^ self.bad.get(a, 0)

    def read(self, c):
        op, a = (c >> 26) & 3, (c >> 16) & 0x3FF
        assert c >> 28 == 1 and op == 2, hex(c)
        self.trace.append(f'READ {a}')
        return self.mem.get(a, 0xFFFF)


def run_session(rom, flags, data, volt, bad=None, busy_seq=None, passes=40, lock=0):
    I = Init()
    for a in range(G, G + 39):
        I.p8(a, 0)
    for k in range(6):
        I.p8(FLAGS + k, flags[k])
        I.p16(DATA + 2 * k, data[k])
    I.p8(LOCK, lock)
    I.pf(VOLT, volt)
    emu = new_emu(rom, I)
    dev = Eeprom(bad)
    n = 0

    def busy(e):
        b = busy_seq[n] if busy_seq and n < len(busy_seq) else 0
        dev.trace.append('BUSY' if b else 'ready')
        e.R[0] = b
    emu.stub(0x006884, fn=busy)
    emu.stub(0x0067DC, fn=lambda e: dev.send2(e.R[4]))
    emu.stub(0x006828, fn=lambda e: dev.send4(e.R[4]))
    emu.stub(0x0067A6, fn=lambda e: e.R.__setitem__(0, dev.read(e.R[4])))
    for n in range(passes):
        emu.call(0x02EB02)
        if emu.read_u8(G + 32) == 1:
            break
    return emu, dev, n + 1


def test_02EB02_sessions(rom):
    say('\n== 0x02EB02 whole sessions against a device model ==')
    data = [0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666]
    emu, dev, n = run_session(rom, [1, 0, 1, 0, 0, 1], data, 12.0)
    say(f'  flags 1,0,1,0,0,1, 12 V: done after {n} passes; device: {dev.trace}')
    check(dev.mem == {483: 0x1111, 485: 0x3333, 488: 0x6666}, 'session writes items 0,2,5 to 483,485,488')
    check(emu.read_u8(G + 32) == 1 and emu.read_u8(LOCK) == 0 and emu.read_u8(G + 22) == 0 and
          emu.read_u8(G + 33) == 0 and dev.trace[-1] == 'EWDS', 'normal finish: EWDS, lock 0, [7264]=1, [725A]=0')
    emu, dev, n = run_session(rom, [1] * 6, data, 12.0)
    check(dev.mem == {483 + k: data[k] for k in range(6)} and emu.read_u8(G + 32) == 1, 'all six items')
    say(f'  all six flags: {n} passes, EEPROM words 483..488 = {[hex(dev.mem[483 + k]) for k in range(6)]}')
    # verify failure on address 485 every time: three writes, then give up with state 3, then EWDS
    emu, dev, n = run_session(rom, [1, 0, 1, 0, 0, 1], data, 12.0, bad={485: 0x0100})
    w485 = sum(1 for t in dev.trace if t.startswith('WRITE 485'))
    say(f'  bad cell 485: {w485} writes to 485, state byte [725C]={emu.read_u8(G + 24)}, done after {n} passes; '
        f'items after 485 written: {sorted(a for a in dev.mem if a > 485)}')
    check(w485 == 3 and emu.read_u8(G + 32) == 1 and 488 not in dev.mem and emu.read_u8(G + 24) == 3,
          'retry limit: 3 writes (cal 0x0C472C = 3) then abort; later items not written')
    # busy forever: finish after the 7th consecutive busy pass, without EWDS
    emu, dev, n = run_session(rom, [1] * 6, data, 12.0, busy_seq=[1] * 50)
    say(f'  device busy every pass: done after {n} passes, commands sent {[t for t in dev.trace if t not in ("BUSY", "ready")]}')
    check(n == 7 and emu.read_u8(G + 32) == 1 and emu.read_u8(LOCK) == 0 and not dev.mem and
          'EWDS' not in dev.trace, 'busy timeout: 7 passes, no command')
    # low voltage at start: abort at once with EWDS and set [7265]
    emu, dev, n = run_session(rom, [1] * 6, data, 5.5)
    say(f'  [4130] = 5.5: done after {n} pass(es), device {dev.trace}, [7265]={emu.read_u8(G + 33)}')
    check(n == 1 and dev.trace == ['ready', 'EWDS'] and emu.read_u8(G + 33) == 1, 'low value abort')
    emu, dev, n = run_session(rom, [1] * 6, data, 6.0)
    check(dev.mem and emu.read_u8(G + 33) == 0, 'exactly 6.0 is not low')
    # no flag set: never finishes (EWEN every pass)
    emu, dev, n = run_session(rom, [0] * 6, data, 12.0, passes=50)
    say(f'  no flag set: after {n} passes [7264]={emu.read_u8(G + 32)}; device saw {dev.trace.count("EWEN")} EWEN, '
        f'{sum(1 for t in dev.trace if t.startswith("WRITE"))} WRITE')
    check(n == 50 and emu.read_u8(G + 32) == 0 and dev.trace.count('EWEN') == 50 and emu.read_u8(LOCK) == 0xEE,
          'no-flag session does not terminate by itself and holds the lock')
    # foreign lock owner: nothing happens
    emu, dev, n = run_session(rom, [1] * 6, data, 12.0, passes=5, lock=0x12)
    check(dev.trace == [] and emu.read_u8(G + 32) == 0 and emu.read_u8(LOCK) == 0x12, 'foreign lock: back off')
    say(f'  lock byte 0x12 (another owner): {n} passes, device untouched, lock unchanged')
    # command words
    t = rom[0x0C0080]
    words = {op: cmd_06B5A(rom, op, 0x1E5, 0xBEEF) for op in range(5)}
    say(f'  0x006B5A with type byte [0x0C0080]={t}: ' + ', '.join(f'op{op}={w:#010x}' for op, w in words.items()))
    for op in range(5):
        emu = E.Emu(rom)
        emu.call(0x006B5A, {4: op, 5: 0x1E5, 6: 0xBEEF})
        check(emu.R[0] == words[op], f'006B5A op {op}')
    check(words == {0: 0x19E5BEEF, 1: 0x14E5BEEF, 2: 0x15E5BEEF, 3: 0x12E5BEEF, 4: 0x11E5BEEF},
          f'command words {words}')
    check((cmd_06B5A(rom, 1, 0, 0), cmd_06B5A(rom, 4, 0, 0), cmd_06B5A(rom, 0, 483, 0), cmd_06B5A(rom, 2, 488, 0x1234))
          == (0x13000000, 0x10000000, 0x19E30000, 0x15E81234), 'EWEN / EWDS / READ 483 / WRITE 488 words')


def test_02E8C0(rom):
    say('\n== 0x02E8C0 (caller): when 0x02EB02 runs ==')
    rows = []
    for g8E98 in (0, 1, 0xFF):
        for p in range(5):
            for prev in (0, 1):
                for pair_ok in (True, False):
                    I = Init()
                    I.p8(0xFFFF8E98, g8E98)
                    for j in range(4):
                        I.p8(0xFFFF7263 + j, 1 if j < p else 0)
                    I.p8(0xFFFF7269, prev)
                    I.p8(0xFFFF7268, 0x5A)
                    I.p16(0xFFFF3154, 0x3CC3 if pair_ok else 0x3C00)
                    emu = new_emu(rom, I)
                    log = []
                    for a, nm in ((0x02E968, 'E968'), (0x02EB02, 'EB02'), (0x02ED88, 'ED88')):
                        emu.stub(a, fn=(lambda nm: (lambda e: log.append(nm)))(nm))
                    emu.stub(0x00DCE4, fn=lambda e: log.append(f'DCE4({e.R[4]},{e.R[5]})'))
                    emu.call(0x02E8C0)
                    want = []
                    if sb(g8E98) != 0 and prev == 0:
                        want.append('DCE4(0,5)')
                    if sb(g8E98) != 0:
                        want.append(['E968', 'EB02', 'ED88', 'DCE4(0,6)', None][p])
                    want = [w for w in want if w]
                    check(log == want, f'02E8C0 8E98={g8E98} phase={p} prev={prev}: {log} vs {want}')
                    check(emu.read_u8(0xFFFF7269) == g8E98, '7269 := 8E98')
                    if sb(g8E98) != 0 and p == 3:
                        check(emu.read_u8(0xFFFF7266) == 1, '7266 set after DCE4(0,6)')
                    if pair_ok:
                        check(emu.read_u8(0xFFFF7268) == 0x3C and emu.read_u16(0xFFFF3154) == 0x3CC3, 'pair ok -> copy')
                    else:
                        check(emu.read_u16(0xFFFF3154) == 0x5AA5 and emu.read_u8(0xFFFF7268) == 0x5A, 'pair bad -> rebuild')
                    if g8E98 == 1 and prev == 0 and pair_ok:
                        rows.append(f'phase bytes 7263..7266 = {[1 if j < p else 0 for j in range(4)]} -> {log}')
    for r in rows:
        say('  ' + r)


def test_task5_neighbours(rom):
    """0x03D708 (init: the power-on values of the records), and in the 0x04A94C chain 0x03D552 (rec+6),
    0x03D68C ([7DA4] = 1.0) and 0x03D648 (exports rec+20 per channel)."""
    say('\n== 0x03D708 (record init) / 0x03D552 / 0x03D68C / 0x03D648 ==')
    I = Init()
    emu = new_emu(rom, I)
    log = []
    emu.stub(0x009E44, fn=lambda e: log.append(('9E44', e.R[4])))
    emu.call(0x03D708)
    for k in range(4):
        r = REC + 40 * k
        got = (emu.read_u8(r), emu.read_u8(r + 1), emu.read_u8(r + 2), emu.read_u8(r + 3), emu.read_u16(r + 4),
               emu.read_u8(r + 6), emu.read_u8(r + 7), emu.read_u32(r + 8), emu.read_u8(r + 12), emu.read_u8(r + 16),
               emu.read_u8(r + 17), emu.read_u32(r + 20), emu.read_u32(r + 24), emu.read_u32(r + 28),
               emu.read_u32(r + 32), emu.read_u8(r + 36))
        want = (0, 0, 0, 0, 0, 0, 0, u32(rom, 0x063E20 + 4 * k), k, rom[0x063E30 + k], 0, 0, 0, FULL, FULL, 0)
        check(got == want, f'03D708 record {k}: {got}')
    check(emu.read_u16(S) == 0 and emu.read_u32(S + 4) == 0 and emu.read_u8(S + 8) == 0 and emu.read_u8(S + 9) == 0
          and emu.read_u16(S + 10) == 0 and emu.read_u8(S + 13) == 1, '03D708 state block')
    check(log == [('9E44', u32(rom, 0x0CBDB4))], f'03D708 -> 0x03D640 -> 0x009E44 with r4 = cal long: {log}')
    wr = set(emu.writes)
    expect = set()
    for k in range(4):
        r = REC + 40 * k
        for o in list(range(0, 9)) + [9, 10, 11, 12] + list(range(16, 18)) + list(range(20, 37)):
            expect.add(r + o)
    expect |= {S + j for j in (0, 1, 4, 5, 6, 7, 8, 9, 10, 11, 13)}
    check(wr == expect, f'03D708 write set: extra {sorted(hex(a) for a in wr - expect)[:6]} missing {sorted(hex(a) for a in expect - wr)[:6]}')
    say('  0x03D708: rec k = {0..0, +8 = 0x063E20[k] (0/360/180/540 deg), +12 = k, +16 = 0x063E30[k] (0..3), '
        '+28 = +32 = 720 deg}; [7E55] = 1 (init request for the next 0x03D856 call); S+0/+4/+8/+9/+10 = 0')
    for v in (0, 1, 2, 0xFF):
        I = Init(); I.p8(F726C, v)
        for k in range(4):
            I.p8(REC + 40 * k + 6, 7)
        emu = new_emu(rom, I); emu.call(0x03D552)
        check([emu.read_u8(REC + 40 * k + 6) for k in range(4)] == ([1] * 4 if v == 1 else [7] * 4), f'03D552 {v}')
    I = Init(); I.pf(0xFFFF6210, 123.0); I.pf(K7DA4, 5.0)
    emu = new_emu(rom, I); emu.call(0x03D68C)
    check(emu.read_f32(K7DA4) == 1.0 and set(emu.writes) == {K7DA4 + j for j in range(4)}, '03D68C')
    rng = random.Random(61)
    for i in range(100):
        I = Init(); I.pf(0xFFFF734C, rng.choice([0.0, 250.5, -12.0]))
        for k in range(4):
            I.p8(REC + 40 * k + 1, rng.choice([0, 1]))
            I.p32(REC + 40 * k + 20, rng.randrange(1 << 22))
        emu = new_emu(rom, I); emu.call(0x03D648)
        for k in range(4):
            r = REC + 40 * k
            l20 = I[r + 20] << 24 | I[r + 21] << 16 | I[r + 22] << 8 | I[r + 23]
            off = struct.unpack('>f', bytes(I[0xFFFF734C + j] for j in range(4)))[0]
            if I[r + 1] == 0:
                v = x32(l20 * 0.25)
                check(emu.read_f32(0xFFFF7D94 + 4 * k) == v and emu.read_f32(0xFFFF7D84 + 4 * k) == x32(v + off), '03D648')
            else:
                check(emu.read_f32(0xFFFF7D94 + 4 * k) == 0.0 and emu.read_f32(0xFFFF7D84 + 4 * k) == 0.0, '03D648 cut')
    say('  0x03D552: rec+6 := 1 on all four records only when byte [726C] == 1; 0x03D68C: [7DA4] := 1.0 always;')
    say('  0x03D648: [7D94+4k] = rec_k+20 * 0.25 and [7D84+4k] = that + [734C], both 0.0 when rec_k+1 != 0')


def test_phase_neighbours(rom):
    """0x02EA98 (builds the six words), 0x02E968 (phase A: compare, set the flags 0x02EB02 consumes) and
    0x02ED88 (phase C: records the outcome) -- decoded only to state when and on what 0x02EB02 runs."""
    say('\n== 0x02EA98 / 0x02E968 / 0x02ED88 (the phases around 0x02EB02) ==')
    rng = random.Random(51)
    for i in range(300):
        I = Init()
        I.p16(0xFFFF24E8, rng.randrange(65536)); I.p16(0xFFFF24EC, rng.randrange(65536))
        I.p8(0xFFFF24F0, rng.randrange(256))
        for a in range(G, G + 39):
            I.p8(a, 0)
        I.p8(G + 20, rng.choice([0, 5, 6, 7, 0x80]))
        I.p8(LOCK, rng.choice([0, 0, 0, 0xEE, 1]))
        I.pf(VOLT, rng.choice([12.0, 5.0, 6.0]))
        x = rng.choice([0, 0, 0, 1, 0x100])
        busy = rng.choice([0, 0, 0, 1])
        good = (I[0xFFFF24E8] << 8 | I[0xFFFF24E9], I[0xFFFF24EC] << 8 | I[0xFFFF24ED], 0, 0, I[0xFFFF24F0] << 8)
        good = good + (((0xAA55 - sum(good)) & 0xFFFF),)
        eep = {483 + k: (good[k] if rng.random() < 0.7 else rng.randrange(65536)) for k in range(6)}
        # ---- 0x02EA98 ----
        emu = new_emu(rom, I); log = []
        emu.stub(0x00317C, fn=lambda e: (log.append(('ENTER', e.R[4])), e.R.__setitem__(0, 0x30)))
        emu.stub(0x003190, fn=lambda e: log.append(('LEAVE', e.R[4])))
        emu.stub(0x06E7F6, fn=lambda e: e.R.__setitem__(0, x))
        emu.call(0x02EA98)
        if x & 0xFF == 0:
            words = [emu.read_u16(DATA + 2 * k) for k in range(6)]
            check(tuple(words) == good and sum(words) & 0xFFFF == 0xAA55 and emu.R[0] == 0, f'02EA98 words {i}')
        else:
            check(not emu.writes and emu.R[0] == 1, f'02EA98 refused {i}')
        check(log == [('ENTER', 16), ('LEAVE', 0x30)], f'02EA98 section {log}')
        # ---- 0x02E968 ----
        emu = new_emu(rom, I); log = []
        emu.stub(0x006884, fn=lambda e: e.R.__setitem__(0, busy))
        emu.stub(0x00317C, fn=lambda e: e.R.__setitem__(0, 0x30))
        emu.stub(0x003190, fn=lambda e: None)
        emu.stub(0x06E7F6, fn=lambda e: e.R.__setitem__(0, x))
        emu.stub(0x0067A6, fn=lambda e: (log.append((e.R[4] >> 16) & 0x3FF), e.R.__setitem__(0, eep[(e.R[4] >> 16) & 0x3FF])))
        emu.call(0x02E968)
        V = struct.unpack('>f', bytes(I[VOLT + j] for j in range(4)))[0]
        if I[LOCK] != 0:
            check(emu.read_u8(G + 20) == 0 and emu.read_u8(G + 31) == 0, f'02E968 lock {i}')
        elif busy == 1:
            n = min(I[G + 20] + 1, 255)
            check(emu.read_u8(G + 20) == n, '02E968 busy count')
            check(emu.read_u8(G + 31) == emu.read_u8(G + 32) == (1 if n > 6 else 0) and
                  emu.read_u8(G + 33) == (1 if n > 6 and 6.0 > V else 0), f'02E968 busy {i}')
        elif x & 0xFF:
            check((emu.read_u8(G + 31), emu.read_u8(G + 32), emu.read_u8(G + 33)) == (1, 1, 1), f'02E968 build fail {i}')
        else:
            flags = [emu.read_u8(FLAGS + k) for k in range(6)]
            check(flags == [0 if eep[483 + k] == good[k] else 1 for k in range(6)] and log == list(range(483, 489)),
                  f'02E968 flags {i}')
            check(emu.read_u8(G + 31) == 1 and emu.read_u8(G + 32) == (0 if any(flags) else 1) and
                  emu.read_u8(G + 24) == (0 if any(flags) else 2), f'02E968 skip-B {i}')
    say('  0x02EA98: words = [24E8], [24EC], 0, 0, [24F0]<<8, (0xAA55 - sum) -- 16-bit sum of the six = 0xAA55 (300 cases)')
    say('  0x02E968: flag k = (EEPROM word 483+k != word k); no difference -> [7264] = 1 (0x02EB02 skipped), [725C] = 2')
    for (b726A, b7258, st, want) in ((1, 7, 0, 1), (1, 6, 0, None), (0, 9, 3, 1), (0, 0, 2, 0), (0, 0, 1, None),
                                     (1, 0x80, 2, 1), (0, 0, 0, None)):
        I = Init()
        for a in range(G, G + 39):
            I.p8(a, 0)
        I.p8(G + 38, b726A); I.p8(G + 20, b7258); I.p8(G + 24, st); I.p8(G + 0, 3); I.p16(0xFFFF3154, 0x1234)
        emu = new_emu(rom, I)
        emu.call(0x02ED88)
        if want is None:
            check(emu.read_u16(0xFFFF3154) == 0x1234 and emu.read_u8(G + 0) == 3, f'02ED88 no-op {b726A},{b7258},{st}')
        else:
            check(emu.read_u8(G + 36) == want and emu.read_u16(0xFFFF3154) == (0x01FE if want else 0x00FF) and
                  emu.read_u8(G + 0) == 0, f'02ED88 {b726A},{b7258},{st}')
        check(emu.read_u8(G + 33) == 1, '02ED88 sets 7265')
    say('  0x02ED88: busy-timeout or state 3 -> [7268] = 1, word [3154] = 0x01FE; state 2 -> [7268] = 0, [3154] = 0x00FF')


def test_identity(roms):
    say('\n== byte identity of the code and tables across stock / 20.19c / 20.19e ==')
    spans = [(0x02E8C0, 0x02EDE4), (0x03D4F0, 0x03E2B0), (0x063DD0, 0x063E3C), (0x006828, 0x006BC4),
             (0x02F8A6, 0x02FA68), (0x04A94C, 0x04AA58), (0x011900, 0x011940), (0x0C0080, 0x0C0081),
             (0x0C472C, 0x0C472D), (0x0CBDB4, 0x0CBDB8), (0x0BE4FA, 0x0BEDB8), (0x049A7A, 0x049BA4),
             (0x00E486, 0x00E4BA), (0x00FE22, 0x00FED4), (0x0303C0, 0x03042C), (0x0AD7E0, 0x0AD7F4),
             # added at review: the two getters, 0x04AE82 / 0x00E5BC, 0x047C40 with its pool, and the three
             # 1-D tables 0x02F974 reads (records 0x0AC34C..0x0AC387, axes and data 0x0CC840..0x0CC8C0)
             (0x02FB1C, 0x02FB68), (0x02FCBA, 0x02FCF0), (0x04AE82, 0x04B090), (0x00E5BC, 0x00E6C4),
             (0x047C40, 0x048830), (0x0AC34C, 0x0AC388), (0x0CC840, 0x0CC8C1)]
    for lo, hi in spans:
        same = all(r[lo:hi] == roms[0][lo:hi] for r in roms)
        check(same, f'span {lo:06X}..{hi:06X} identical')
    say(f'  {len(spans)} spans identical in all three bins; cal byte 0x0C472C = {roms[0][0x0C472C]}, '
        f'type byte 0x0C0080 = {roms[0][0x0C0080]}, cal long 0x0CBDB4 = {u32(roms[0], 0x0CBDB4):#x}')
    say('  tables: 0x063DFC = ' + ' '.join(f'{b:02X}' for b in roms[0][0x063DFC:0x063E00]) +
        '; 0x063E00 rec0 = ' + ' '.join(f'{u32(roms[0], 0x063E00 + 4 * i):08X}' for i in range(4)) +
        '; rec1 = ' + ' '.join(f'{u32(roms[0], 0x063E10 + 4 * i):08X}' for i in range(4)) +
        '; 0x063E20 = ' + ' '.join(f'{u32(roms[0], 0x063E20 + 4 * i) >> 16}' for i in range(4)) + ' deg')


# =====================================================================================
# REVIEW SETTLEMENT (third decode, 2026-11-27).  Every disputed item re-run from the bytes; the
# call tree of 0x03D856 is run UNSTUBBED except the four drivers 0x009A72 / 0x009B2C / 0x009C38 /
# 0x009D48 (peripheral writes), against oracle_03D856(tree=...).
# =====================================================================================
GETF, GETG = 0xFFFF72FC, 0xFFFF72EC        # read by 0x02FCBA / 0x02FB1C
DRIVERS = (0x009A72, 0x009B2C, 0x009C38, 0x009D48)
NEVER = (8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 19, 37, 38, 39)   # record offsets no tree function writes


def stub_drivers(emu, log):
    emu.stub(0x009C38, fn=lambda e: log.append(('C38', e.R[4], e.R[5])))
    emu.stub(0x009D48, fn=lambda e: log.append(('D48', e.R[4])))
    emu.stub(0x009A72, fn=lambda e: log.append(('A72', e.R[4], e.R[5], e.fr(4))))
    emu.stub(0x009B2C, fn=lambda e: log.append(('B2C', e.R[4], e.R[5], e.R[6], e.fr(4))))


def trace_reads(emu, log, addrs):
    """Log every read of the given addresses (ROM or RAM) into log as ('READ', addr)."""
    orig = emu.read

    def rd(a, n):
        if (a & M32) in addrs:
            log.append(('READ', a & M32))
        return orig(a, n)
    emu.read = rd


def tree_cells(I, rng, A, B):
    """Cells only the unstubbed tree reads: the two getters, 0x03DB16's step byte, 0x03E0FA's inputs."""
    I.pf(GETF, A)
    I.pf(GETG, B)
    I.p8(SEG4167, rng.choice([0, 6, 12, 18, 23, 24, 30, 47, rng.randrange(48)]))
    I.p32(R4280, rng.choice([0, 7, 1000]))
    I.p32(R4158, rng.choice([0x1000, 0x7850, 0x20000, 0x100000]))


def run_tree(rom, I, arg, A, B, reads=()):
    m = Mem(I)
    sub = []
    olog = oracle_03D856(rom, m, arg, A, B, tree=sub)
    emu = new_emu(rom, I)
    elog = []
    stub_drivers(emu, elog)
    if reads:
        trace_reads(emu, elog, set(reads))
    emu.call(0x03D856, {4: arg})
    return m, olog, sub, emu, elog


def test_tree_03D856(rom, ncase, seed, tag):
    say(f'\n== 0x03D856 WHOLE CALL TREE (only the four drivers stubbed): {ncase} seeded states ({tag}) ==')
    rng = random.Random(seed)
    st = {'init': 0, 'db16': 0, 'db16_hid': 0, 'fire': 0, 'calread': 0, 'calread_db16': 0}
    for i in range(ncase):
        I, arg, A, B = rand_state_03D856(rng)
        for k in range(4):                        # targets on a 1/4-degree grid: keeps every float step exact
            I.p32(REC + 40 * k + 8, rng.randrange(FULL // 16384) * 16384)
            for o in (13, 14, 15, 18, 19, 37, 38, 39):
                I.p8(REC + 40 * k + o, 0xA5)       # poison the pad bytes
        tree_cells(I, rng, A, B)
        m, olog, sub, emu, elog = run_tree(rom, I, arg, A, B, reads=(0x0CBDB4,))
        ew = set(emu.writes)
        check(ew == m.w, f'tree[{tag} {i}]: write set differs: emu-only {sorted(hex(a) for a in ew - m.w)[:8]} '
                         f'oracle-only {sorted(hex(a) for a in m.w - ew)[:8]}')
        for a in ew & m.w:
            check(emu.writes[a] == m.b[a], f'tree[{tag} {i}]: byte {a:#x} emu {emu.writes[a]:#04x} oracle {m.b[a]:#04x}')
        check(not emu.uninit_reads, f'tree[{tag} {i}]: uninitialised read {sorted(hex(a) for a in emu.uninit_reads)[:6]}')
        drv = [e for e in elog if e[0] in ('A72', 'B2C', 'C38', 'D48')]
        odrv = [e for e in sub if e[0] in ('A72', 'B2C', 'C38', 'D48')]
        check(drv == odrv, f'tree[{tag} {i}]: driver calls differ\n  emu    {drv}\n  oracle {odrv}')
        bad = [a for a in ew for k in range(4) for o in NEVER if a == REC + 40 * k + o]
        check(not bad, f'tree[{tag} {i}]: wrote a record offset in {NEVER}: {[hex(a) for a in bad]}')
        if sb(I[S + 13]) == 1:
            st['init'] += 1
        if ('DB16',) in olog:
            st['db16'] += 1
            m0 = Mem(I)                           # what the body alone would have done after a stubbed resync
            body = oracle_03D856(rom, m0, arg, A, B)
            if any(e[0] in ('DD8E', 'DE6E') for e in body) and not any(e[0] in ('DD8E', 'DE6E') for e in olog):
                st['db16_hid'] += 1
        st['fire'] += sum(1 for e in olog if e[0] == 'FIRE')
        if any(e[0] == 'READ' for e in elog):
            st['calread'] += 1
            if ('DB16',) in olog:
                st['calread_db16'] += 1
    say(f'  init path {st["init"]}, resync {st["db16"]} (in {st["db16_hid"]} of them a stubbed resync would have been '
        f'followed by 0x03DD8E / 0x03DE6E and the real one was not), fire calls {st["fire"]}; cal long 0x0CBDB4 read '
        f'in {st["calread"]} calls ({st["calread_db16"]} of them resync calls)')
    say(f'  never written by the tree: record offsets {NEVER} (pads poisoned 0xA5, +8 / +12 / +16 included)')
    check(st['init'] > 10 and st['db16_hid'] > 10 and st['calread'] > 10 and st['calread_db16'] > 5,
          f'{tag}: tree coverage too thin {st}')


def review_base(rng=None):
    """A quiet four-record state (all in state 2, mode 1, status 0) plus every cell the whole tree reads."""
    I = Init()
    I.p16(S, 0); I.p32(S + 4, 0); I.p8(S + 8, 0); I.p8(S + 9, 2); I.p16(S + 10, 0)
    I.p8(S + 12, 11); I.p8(S + 13, 0)
    for k in range(4):
        r = REC + 40 * k
        for o in range(40):
            I.p8(r + o, 0xA5 if o in (13, 14, 15, 18, 19, 37, 38, 39) else 0)
        I.p8(r, 1); I.p8(r + 2, 2)
        I.p32(r + 8, [0, 360, 180, 540][k] << 16)
        I.p8(r + 12, k); I.p8(r + 16, k)
        I.p32(r + 28, FULL); I.p32(r + 32, FULL)
        I.p8(STAT + 28 * k, 0)
    I.p16(MASK, 0); I.p8(F726C, 0)
    I.pf(A7280, 10.0); I.pf(K7DA4, 1.0)
    for ch in range(4):
        I.pf(T7290 + 4 * ch, 1000.0 + ch)
    for i in range(4):
        I.pf(STEPF + 4 * i, 90.0)
    for i in range(3):
        I.p8(STEPB + i, 5)
    for a in (F72E0, F72E4, F72F4, F72E8):
        I.pf(a, 1.0)
    I.pf(F7300, 0.0)
    I.pf(GETF, 0.0); I.pf(GETG, 1.0)
    I.p8(SEG4167, 12); I.p32(R4280, 0); I.p32(R4158, 0x7850)
    return I


def test_review(rom):
    say('\n== REVIEW SETTLEMENT: the disputed items, from the bytes ==')
    rd = lambda e, a, n=1: e.read(a, n)           # noqa: E731

    # A5 -- init at angle 0, step0 = 0: init sets counts, the main loop runs in the same call
    I = review_base(); I.p8(S + 13, 1); I.p8(S + 12, 23); I.pf(STEPF, 0.0)
    m, olog, sub, emu, elog = run_tree(rom, I, 0, 0.0, 1.0)
    cnt = [rd(emu, REC + 40 * k + 4, 2) for k in range(4)]
    sts = [rd(emu, REC + 40 * k + 2) for k in range(4)]
    pads = [a for a in emu.writes for k in range(4) for o in NEVER if a == REC + 40 * k + o]
    say(f'  A5  init at angle 0, [72B4] = 0: counts {cnt}, S+0 = {rd(emu, S, 2)}, states {sts}, record offsets '
        f'{NEVER} written: {len(pads)}; calls {[e[0] for e in olog]}')
    check(cnt == [4, 3, 2, 4] and rd(emu, S, 2) == 4 and not pads and m.w == set(emu.writes), 'A5 init at angle 0')
    # A5 -- the init clear alone: stop at 0x03D8F2 (end of the clear loop) and list what it wrote
    emu2 = new_emu(rom, I)
    emu2.call(0x03D856, {4: 0}, stop_at=(0x03D8F2,))
    offs = sorted({(a - REC) % 40 for a in emu2.writes if REC <= a < REC + 160})
    sw = sorted(a - S for a in emu2.writes if S <= a < S + 16)
    say(f'  A5  clear loop 0x03D8B2..0x03D8F0 writes record offsets {offs} and S offsets {sw}')
    check(offs == [0, 1, 2, 3, 4, 5, 6, 7, 17, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36]
          and sw == [0, 1, 4, 5, 6, 7, 9, 10, 11, 12, 13], 'A5 clear-loop write set')

    # A10 -- armed, d = 50, status byte non-zero: nothing changes
    I = review_base(); I.p32(REC + 40 + 8, (12 * 30 + 50) << 16); I.p8(REC + 40 + 2, 0); I.p8(STAT + 28, 7)
    m, olog, sub, emu, elog = run_tree(rom, I, 12, 0.0, 1.0)
    say(f'  A10 armed, d = 50, status byte 7: state {rd(emu, REC + 42)}, S+0 {rd(emu, S, 2)}, fires '
        f'{[e for e in olog if e[0] == "FIRE"]}')
    check(rd(emu, REC + 42) == 0 and rd(emu, S, 2) == 0 and not any(e[0] == 'FIRE' for e in olog), 'A10 status first')
    # A10 -- d > 720<<16 (needs a target outside [0, 720)): re-armed by 0x03D9FA, then no count, no fire
    I = review_base(); I.p32(REC + 40 + 8, (12 * 30 + 800) << 16); I.p8(REC + 40 + 2, 0)
    m, olog, sub, emu, elog = run_tree(rom, I, 12, 0.0, 1.0)
    check(rd(emu, REC + 42) == 0 and rd(emu, S, 2) == 0 and not any(e[0] == 'FIRE' for e in olog), 'A10 d > 720')

    # A11 -- cut record in state 0: counted only with status 0, 100 < d <= 720 and rec+3 == 0; never fired
    I = review_base(); r = REC + 40
    I.p16(S, 9); I.p16(S + 10, 2); I.p16(MASK, 2)
    I.p32(r + 8, (12 * 30 + 200) << 16); I.p8(r + 2, 0); I.p8(r + 1, 1); I.p8(r + 3, 0); I.p32(r + 32, 0x12340000)
    m, olog, sub, emu, elog = run_tree(rom, I, 12, 0.0, 1.0)
    say(f'  A11 cut, uncounted, d = 200: S+0 9 -> {rd(emu, S, 2)}, rec+4 {rd(emu, r + 4, 2)}, rec+3 {rd(emu, r + 3)}, '
        f'rec+32 {rd(emu, r + 32, 4):#x}, fires {[e for e in olog if e[0] == "FIRE"]}')
    check(rd(emu, S, 2) == 10 and rd(emu, r + 4, 2) == 10 and rd(emu, r + 3) == 1 and rd(emu, r + 32, 4) == 0x12340000
          and not any(e[0] == 'FIRE' for e in olog) and not elog, 'A11 cut counted once')
    I.p8(r + 3, 1); I.p16(r + 4, 3)
    m, olog, sub, emu, elog = run_tree(rom, I, 12, 0.0, 1.0)
    check(rd(emu, S, 2) == 9 and rd(emu, r + 4, 2) == 3 and not elog, 'A11 cut already counted: unchanged')

    # A15 -- the TREE reads cal long 0x0CBDB4 (0x03E0FA -> 0x03D634): mode-1 state-1 re-fire, and a resync
    I = review_base()
    for k in range(4):
        I.p8(REC + 40 * k + 2, 1); I.p8(REC + 40 * k + 6, 1)
    I.p32(REC + 24, 500)
    m, olog, sub, emu, elog = run_tree(rom, I, 12, 0.0, 1.0, reads=(0x0CBDB4,))
    seq = [e[0] if e[0] != 'B2C' else f'B2C({e[1]})' for e in elog]
    say(f'  A15 mode-1 records in state 1 with rec+6 = 1, one 0x03D856(12) call: {seq}')
    check(('READ', 0x0CBDB4) in elog and m.w == set(emu.writes), 'A15 re-fire reads the cal long')
    I = review_base()
    for k in range(4):
        I.p8(REC + 40 * k + 2, 0); I.p32(REC + 40 * k + 32, 0)
    m, olog, sub, emu, elog = run_tree(rom, I, 20, 0.0, 1.0, reads=(0x0CBDB4,))
    n_cal = sum(1 for e in elog if e == ('READ', 0x0CBDB4))
    say(f'  A15 resync (prev 11 -> arg 20, mode 1): 0x03DB16 ran, cal long read {n_cal} times')
    check(('DB16',) in olog and n_cal > 0, 'A15 resync reads the cal long')

    # A17 / missed item 1 -- 0x02FCBA / 0x02FB1C ignore r4: the mode-0 duration does not depend on n
    vals = {}
    for n in (0, 1, 5, 6, 200, 0xFFFF):
        I = Init()
        I.p8(REC, 0); I.p16(REC + 4, n)
        for i in range(3):
            I.p8(STEPB + i, (5, 10, 15)[i])
        I.pf(F7300, 1.0); I.pf(F72E0, 0.5); I.pf(F72E4, 2.0); I.pf(F72F4, 4.0); I.pf(F72E8, 1.5)
        I.pf(GETF, 8.0); I.pf(GETG, 0.75); I.pf(K7DA4, 1.0)
        emu = new_emu(rom, I)
        emu.call(0x03D582, {4: REC})
        vals[n] = rd(emu, REC + 24, 4)
        check(not emu.uninit_reads, 'A17 0x03D582 reads only initialised cells')
    say(f'  A17 0x03D582 unstubbed, mode 0: rec+24 by event number n {vals}; '
        f'model trunc((1 + 8*0.5*2*0.75*4*1.5) / 0.25) = {int((1 + 8 * 0.5 * 2 * 0.75 * 4 * 1.5) / 0.25)}')
    check(set(vals.values()) == {148}, 'A17 duration independent of n')
    for a, cell in ((0x02FCBA, GETF), (0x02FB1C, GETG)):
        for r4 in (0, 7, 0xFFFF, M32):
            I = Init(); I.pf(cell, 3.5)
            emu = new_emu(rom, I); emu.call(a, {4: r4})
            check(emu.fr(0) == 3.5 and not emu.writes and not emu.uninit_reads, f'getter {a:06X}')

    # missed item 7 -- 0x02F974: gates, writes, and [72DC] independent of [7E4C]
    outs = set()
    for c7e4c in (0, 1, 0x7FFFFFFE, 0x7FFFFFFF, M32):
        I = Init()
        I.p8(0xFFFF65F1, 0); I.p8(F726C, 1); I.p32(S + 4, c7e4c)
        I.pf(0xFFFF620C, 50.0); I.pf(0xFFFF64D8, 20.0); I.pf(0xFFFF6364, 30.0)
        I.pf(F72F4, 1.0); I.pf(F7300, 0.0); I.pf(GETF, 8.0); I.pf(GETG, 1.0)
        emu = new_emu(rom, I); emu.call(0x02F974)
        outs.add(tuple(rd(emu, a, 4) for a in (0xFFFF72DC, F72E0, F72E4, F72E8)))
        check(set(emu.writes) == {a + j for a in (0xFFFF72DC, F72E0, F72E4, F72E8) for j in range(4)}
              and not emu.uninit_reads, '02F974 write set')
    say(f'  0x02F974 ([65F1] = 0, [726C] = 1): [72DC] / [72E0] / [72E4] / [72E8] over five [7E4C] values: '
        f'{[[hex(v) for v in o] for o in outs]}')
    check(len(outs) == 1, '02F974 result independent of [7E4C]')
    for g65f1, g726c in ((1, 1), (0x80, 1), (0, 0), (0, 2)):
        I = Init(); I.p8(0xFFFF65F1, g65f1); I.p8(F726C, g726c)
        emu = new_emu(rom, I); emu.call(0x02F974)
        check(not emu.writes, f'02F974 gated off ({g65f1}, {g726c})')

    # A19 -- 0x03DD4E folds ONCE and uses the unreduced byte [7E54]
    got = {}
    for b, r4 in ((0, 0), (23, 0), (24, 0), (47, 0), (255, 0), (0, -(30 << 16))):
        I = Init(); I.p8(S + 12, b)
        emu = new_emu(rom, I); emu.call(0x03DD4E, {4: r4 & M32})
        got[(b, r4 >> 16)] = s32(emu.R[0]) / 65536
    say(f'  A19 0x03DD4E (byte [7E54], r4 deg) -> deg: {got}')
    check(got == {(0, 0): 710, (23, 0): 680, (24, 0): 710, (47, 0): 680, (255, 0): 6920, (0, -30): 20}, 'A19 fold once')

    # A20 -- 0x03E168 'too early' edge and saturation; 0x03DFC8 skips [7E50] only when rec+7 != 0
    for dd, want_prog in ((D30, False), (D30 - 1, True)):
        I = Init(); r = REC
        for o in range(40):
            I.p8(r + o, 0)
        I.p8(r + 16, 2); I.p32(r + 28, 100 << 16); I.p32(r + 24, 777)
        I.p32(S + 4, 0x7FFFFFFE); I.p8(S + 8, 0); I.p8(S + 12, 5)
        emu = new_emu(rom, I); log = []; stub_drivers(emu, log)
        emu.call(FIRE0, {4: r, 5: (100 << 16) + dd})
        prog = any(e[0] == 'A72' for e in log)
        say(f'  A20 0x03E168 d - rec+28 = {dd / 65536:.6f} deg: programmed {prog}, [7E4C] {rd(emu, S + 4, 4):#x}, '
            f'[7E50] {rd(emu, S + 8)}, rec+6 {rd(emu, r + 6)}, rec+2 {rd(emu, r + 2)}')
        if want_prog:
            check(prog and rd(emu, S + 4, 4) == 0x7FFFFFFF and rd(emu, S + 8) == 1 and rd(emu, r + 6) == 0, 'A20 programs')
        else:
            check(not prog and (S + 4) not in emu.writes and (S + 8) not in emu.writes and rd(emu, r + 6) == 1
                  and rd(emu, r + 2) == 1, 'A20 too early')
    for b7, b17, want50 in ((1, 0, False), (0, 2, True), (0, 0, True)):
        I = Init(); r = REC
        for o in range(40):
            I.p8(r + o, 0)
        I.p8(r + 7, b7); I.p8(r + 17, b17); I.p8(r + 16, 1); I.p32(r + 28, 0); I.p8(S + 12, 5)
        I.p32(S + 4, 0x55); I.p8(S + 8, 0)
        emu = new_emu(rom, I); log = []; stub_drivers(emu, log)
        emu.stub(0x03E0FA, fn=lambda e: e.R.__setitem__(0, 0))
        emu.call(FIRE1, {4: r, 5: 300 << 16})
        check(((S + 8) in emu.writes) == want50 and (S + 4) not in emu.writes, f'A20 0x03DFC8 rec+7 {b7} b17 {b17}')
        if b17 == 2:
            check(not log, 'A20 b17 2: no driver call')

    # A22 / missed items 3-4 -- 0x03D708 leaves the pads; 0x03DBFC / 0x03DBF4
    I = Init()
    for k in range(4):
        for o in (13, 14, 15, 18, 19, 37, 38, 39):
            I.p8(REC + 40 * k + o, 0xA5)
    emu = new_emu(rom, I); emu.stub(0x009E44, fn=lambda e: None); emu.call(0x03D708)
    check(all(rd(emu, REC + 40 * k + o) == 0xA5 for k in range(4) for o in (13, 14, 15, 18, 19, 37, 38, 39)),
          'A22 0x03D708 leaves the pad bytes')
    I = Init()
    for k in range(4):
        I.p8(REC + 40 * k + 16, (3, 1, 0, 2)[k])
    I.p16(S, 0x1234); I.p32(S + 4, 0x55); I.p8(S + 8, 1); I.p8(S + 13, 0)
    emu = new_emu(rom, I); log = []; stub_drivers(emu, log); emu.call(0x03DBFC)
    say(f'  0x03DBFC: driver calls {log}; S+0 {rd(emu, S, 2)}, S+4 {rd(emu, S + 4, 4)}, S+8 {rd(emu, S + 8)}; '
        f'writes {sorted(hex(a) for a in emu.writes)}')
    check(log == [('D48', 3), ('D48', 1), ('D48', 0), ('D48', 2)] and
          set(emu.writes) == {S, S + 1, S + 4, S + 5, S + 6, S + 7, S + 8}, '0x03DBFC')
    emu = new_emu(rom, Init()); emu.call(0x03DBF4)
    check(set(emu.writes) == {S + 13} and rd(emu, S + 13) == 1, '0x03DBF4')
    # 0x04AE82: [8EDC] gate, then r4 == 1 -> ... 0x03DBF4, else ... 0x03DBFC (mutually exclusive)
    for g, r4 in ((0, 1), (0, 0), (0, 2), (1, 1), (0xFF, 0)):
        I = Init(); I.p8(0xFFFF8EDC, g)
        emu = new_emu(rom, I); log = []
        for a in (0x0303C0, 0x046C88, 0x0475A8, 0x03DBF4, 0x044132, 0x0475B0, 0x03DBFC, 0x06F0C2):
            emu.stub(a, fn=(lambda a: (lambda e: log.append(a)))(a))
        emu.call(0x04AE82, {4: r4})
        want = [] if g else ([0x0303C0, 0x046C88, 0x0475A8, 0x03DBF4, 0x06F0C2] if r4 == 1 else
                             [0x044132, 0x0475B0, 0x03DBFC, 0x06F0C2])
        check(log == want, f'0x04AE82 gate {g} r4 {r4}: {[hex(a) for a in log]}')
    say('  0x04AE82: [8EDC] != 0 -> nothing; r4 == 1 -> 0x0303C0, 0x046C88, 0x0475A8, 0x03DBF4; else 0x044132, '
        '0x0475B0, 0x03DBFC; then tail 0x06F0C2(r4)')

    # missed item 5 -- after a resync the real 0x03DB16 has written S+9 / S+10: no 0x03DD8E / 0x03DE6E that pass
    I = review_base(); I.p8(S + 9, 0); I.p16(S + 10, 0); I.p16(MASK, 3)
    m0 = Mem(I)
    body = oracle_03D856(rom, m0, 20, 0.0, 1.0)
    emu = new_emu(rom, I); log = []; stub_drivers(emu, log)
    emu.stub(0x03DD8E, fn=lambda e: log.append(('DD8E',)))
    emu.stub(0x03DE6E, fn=lambda e: log.append(('DE6E',)))
    emu.call(0x03D856, {4: 20})
    say(f'  M5  0x03D856(20) after 11, saved index 0 / mask 0, [726C] = 0, mask 3: stubbed-resync body would call '
        f'{[e[0] for e in body if e[0] in ("DD8E", "DE6E")]}; real 0x03DB16 -> calls '
        f'{[e[0] for e in log if e[0] in ("DD8E", "DE6E")]}, S+9 {rd(emu, S + 9)}, S+10 {rd(emu, S + 10, 2)}')
    check(not any(e[0] in ('DD8E', 'DE6E') for e in log) and rd(emu, S + 9) == 2 and rd(emu, S + 10, 2) == 3 and
          any(e[0] == 'DD8E' for e in body), 'M5 resync suppresses mode / mask handlers')

    # 0x047C40: 0x03D708 (jsr at 0x04864C) is reached only on the [8EDC] == 0 branch (static CFG walk)
    sys.path.insert(0, os.path.join(ROOT, 'scripts'))
    import sh2e_disasm as D

    def succ(pc):
        w = u16(rom, pc)
        txt, _ = D.decode(w, pc)
        op = txt.split()[0]
        tgt = int(txt.split()[1], 16) if op in ('bra', 'bt', 'bf', 'bt/s', 'bf/s') else None
        if op == 'bra':
            return [('slot', pc + 2, tgt)]
        if op in ('bt/s', 'bf/s'):
            return [('slot', pc + 2, tgt), ('slot', pc + 2, pc + 4)]
        if op in ('bt', 'bf'):
            return [tgt, pc + 2]
        if op in ('rts', 'jmp', 'braf', 'rte'):
            return [('slot', pc + 2, None)]
        return [pc + 2]                           # jsr / bsr return; everything else falls through

    def walk(start, stop=None):
        seen, exits, todo = set(), 0, [start]
        while todo:
            pc = todo.pop()
            if pc in seen or pc == stop:
                continue
            seen.add(pc)
            for s in succ(pc):
                if isinstance(s, tuple):
                    seen.add(s[1])
                    if s[2] is None:
                        exits += 1
                    else:
                        todo.append(s[2])
                else:
                    todo.append(s)
        return seen, exits
    gate_nz, _ = walk(0x047C70)
    gate_z, exits_z = walk(0x047D40, stop=0x04864C)
    say(f'  0x047C40: from the [8EDC] != 0 successor 0x047C70, 0x04864C reachable: {0x04864C in gate_nz}; '
        f'from 0x047D40 every path reaches 0x04864C before any exit: {exits_z == 0}')
    check(0x04864C not in gate_nz and exits_z == 0 and u32(rom, 0x048828) == 0x03D708, '0x047C40 init path')

    # B2 -- session start runs before the lock test; 0xEE only on a ready, non-aborting pass
    I = Init()
    for a in range(G, G + 39):
        I.p8(a, 0x33)
    for k in range(6):
        I.p8(FLAGS + k, (0, 0, 1, 0, 1, 0)[k])
    I.p8(G + 22, 0); I.p8(LOCK, 0x12); I.pf(VOLT, 12.0)
    emu = new_emu(rom, I); log = []; stub_eeprom(emu, log, 0, 0)
    emu.call(0x02EB02)
    w = {a - G: emu.writes[a] for a in emu.writes if G <= a < G + 39}
    say(f'  B2  foreign lock 0x12, marker 0: serial calls {log}; GBR-block writes {w}; lock {rd(emu, LOCK):#x}')
    check(not log and w == {0: 0, 20: 0, 22: 0x5A, 23: 2, 24: 0, 35: 0} and LOCK not in emu.writes,
          'B2 session start before the lock test')
    for busy, V in ((1, 12.0), (0, 5.0)):
        I = Init()
        for a in range(G, G + 39):
            I.p8(a, 0)
        I.p8(G + 22, 0x5A); I.p8(FLAGS, 1); I.p8(LOCK, 0); I.pf(VOLT, V)
        emu = new_emu(rom, I); log = []; stub_eeprom(emu, log, busy, 0)
        emu.call(0x02EB02)
        check(rd(emu, LOCK) == 0 and ('SEND2', 0x13000000) not in log, f'B2 no 0xEE: busy {busy} V {V}')
    # B7 -- no flag set: V < 6.0 or 7 busy passes still end the session
    data = [0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666]
    emu, dev, n = run_session(rom, [0] * 6, data, 5.0)
    check(n == 1 and emu.read_u8(G + 32) == 1 and dev.trace == ['ready', 'EWDS'], 'B7 no flag, V 5.0')
    emu, dev, n = run_session(rom, [0] * 6, data, 12.0, busy_seq=[1] * 50)
    check(n == 7 and emu.read_u8(G + 32) == 1, 'B7 no flag, busy')
    say('  B7  no flag: V = 5.0 -> 1 pass, EWDS, [7264] = 1; 7 busy passes -> finish; ready and V >= 6 -> EWEN each pass')
    # B10 -- phase C: busy wins over state 2; 0x02E8C0 copies OR rebuilds
    I = Init()
    for a in range(G, G + 39):
        I.p8(a, 0)
    I.p8(G + 38, 1); I.p8(G + 20, 7); I.p8(G + 24, 2); I.p16(0xFFFF3154, 0x1234)
    emu = new_emu(rom, I); emu.call(0x02ED88)
    check(rd(emu, G + 36) == 1 and rd(emu, 0xFFFF3154, 2) == 0x01FE, 'B10 busy timeout wins over state 2')
    for word, byte, want_w, want_b in ((0x0102, 1, 0x01FE, 1), (0x00FF, 7, 0x00FF, 0), (0x01FE, 0, 0x01FE, 1)):
        I = Init(); I.p16(0xFFFF3154, word); I.p8(0xFFFF7268, byte); I.p8(0xFFFF8E98, 0); I.p8(0xFFFF7269, 0)
        emu = new_emu(rom, I); emu.call(0x02E8C0)
        check(rd(emu, 0xFFFF3154, 2) == want_w and rd(emu, 0xFFFF7268) == want_b, f'B10 02E8C0 {word:#06x}/{byte}')
    say('  B10 0x02ED88: busy flag 1 and count 7 with state 2 -> 1 / 0x01FE; 0x02E8C0: word 0x0102 (bad) + byte 1 -> '
        'word rebuilt 0x01FE, byte kept; word 0x00FF (good) -> byte := 0x00')


def main():
    tuned, stock, latest = load(TUNED), load(STOCK), load(LATEST)
    test_identity([tuned, stock, latest])
    test_q_division()
    test_q_bytes(tuned)
    test_small_callees(tuned)
    test_check_fns(tuned)
    test_03D856_crafted(tuned)
    test_03D856(tuned, 2500, 1, '20.19c')
    test_03D856(stock, 300, 2, 'stock')
    test_03D856(latest, 300, 3, '20.19e')
    test_handlers(tuned)
    test_fire_fns(tuned)
    test_02EB02_pass(tuned, 6000, 5, '20.19c')
    test_02EB02_pass(stock, 500, 6, 'stock')
    test_02EB02_sessions(tuned)
    test_02E8C0(tuned)
    test_phase_neighbours(tuned)
    test_task5_neighbours(tuned)
    test_review(tuned)
    test_tree_03D856(tuned, 1500, 71, '20.19c')
    test_tree_03D856(stock, 200, 72, 'stock')
    print(f'\n{checks} checks, {len(fails)} failures')
    if fails:
        for f in fails[:40]:
            print('  FAIL', f)
        sys.exit(1)


if __name__ == '__main__':
    main()
