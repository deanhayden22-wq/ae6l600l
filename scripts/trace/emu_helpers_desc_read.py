#!/usr/bin/env python3
"""Emulation check for the helper cluster 0x0BDB30..0x0BDD9B (and its callees).

    python3 scripts/trace/emu_helpers_desc_read.py

Companion to disassembly/analysis/helpers_desc_read_trace.txt.  Every contract
stated there is asserted here against scripts/sh2e_emu.py running the bytes of
"rom/AE5L600L 20g rev 20.19c.bin".  Exits 0 only if every assertion holds.

WHAT IS EXECUTED AND WHAT IS MODELLED  (changed in the 2026-11-27 repair)
* Everything is executed instruction by instruction, including the two callees
  0x00317C / 0x003190 and, where reached, 0x003664 and 0x003440.  Nothing in the
  mask path is a stub any more.
* sh2e_emu refuses `ldc Rm,sr` and reports a fixed interrupt mask.  SREmu below
  subclasses it with exactly one addition: SR is a real register (bits M, Q,
  I3..I0, S, T; every other bit reads 0) and `ldc Rm,sr` loads it.  Every other
  instruction is the stock emulator's, and each one is still cross-checked
  against sh2e_disasm.
* The harness LOGS: each entry into 0x00317C / 0x003190 (with r4 and a snapshot
  of the record), each SR load (pc, value, snapshot), and each read / write of
  the record (offset, size, interrupt mask at that instant).  So "mask -> touch
  the record -> unmask" and the access order are asserted, not assumed.
* The task switch itself is NOT emulated.  0x003440 is run up to its `bra
  0x0034B4` and the frame it pushed is inspected; the scheduler beyond that
  (0x0034B4 -> 0x0035FC) and the resume routines are bytes only.  One sub-test
  replaces 0x003664 by a stub that destroys every register 0x003440 does not
  save -- that stub is a MODEL of "something else ran"; it is used only to show
  that no helper result depends on those registers.

SECTIONS (the analysis file cites them by number)
  0  0x00317C / 0x003190 / 0x003664 natively; the frame 0x003440 pushes
  1  0x0BDBCC   2  0x0BDB92   3  0x0BDCB6 and 0x0BDC6A   4  0x0BDB30
  5  0x0BDB6E / 0x0BDC0E / 0x0BDB80 / 0x0BDC3C
  6  0x0BDD0C / 0x0BDD1C / 0x0BDD5A / 0x0BDD6E / 0x0BDD78 / 0x0BDD88
  7  write order of the two writers, stepped; every intermediate record state
     fed back through the validators and the reader; the bad-+6 rule
  8  the mask-0 exit: every masked helper through 0x003664 (no-switch exits
     natively, switch exit up to 0x0034B4, and the clobber model); fr8
  9  SR on return: I field restored, S / Q / M / T
"""
import os
import random
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, os.path.join(REPO, 'scripts'))
import sh2e_emu as E  # noqa: E402

BIN = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
rom = open(BIN, 'rb').read()

M32 = 0xFFFFFFFF
REC = 0xFFFF2050          # any long-aligned RAM address will do; this one is a real record
MASK_ENTER, MASK_LEAVE, DISPATCH, CTX_SAVE, SCHED = 0x00317C, 0x003190, 0x003664, 0x003440, 0x0034B4
KERNEL = 0xFFFF1288       # literal at 0x0031A8 and 0x0036B4
TCB = 0xFFFF1300          # test value for long @(24,KERNEL): the record 0x003190 / 0x003440 look at
TCB2 = 0xFFFF1340         # test value for long @(4,TCB)
SR_BITS = 0x3F3           # M Q I3 I2 I1 I0 . . S T
FLAGS = 0x303             # M | Q | S | T

random.seed(0xAE5600)
checks = 0


def ok(cond, msg):
    global checks
    checks += 1
    if not cond:
        raise AssertionError(msg)


def s32(x):
    x &= M32
    return x - (1 << 32) if x & 0x80000000 else x


def s16(x):
    x &= 0xFFFF
    return x - 0x10000 if x & 0x8000 else x


def is_nan_bits(b):
    return (b & 0x7F800000) == 0x7F800000 and (b & 0x007FFFFF) != 0


def cksum(v):
    """The 16-bit check word used by every 8-byte record in this cluster."""
    return ~(((v >> 16) & 0xFFFF) + (v & 0xFFFF)) & 0xFFFF


# --------------------------------------------------------------------------
# sh2e_emu + a real SR
# --------------------------------------------------------------------------
class SREmu(E.Emu):
    """Stock emulator plus: SR as a register, `ldc Rm,sr`, and logging."""

    def __init__(self, rom_bytes):
        super().__init__(rom_bytes)
        self.imask = 0xF0
        self.events = []         # ('enter'|'leave', pc, r4, snap) / ('ldc', pc, value, snap)
        self.acc = []            # ('r'|'w', offset in record, size, I field at that instant)
        self.snap_addr, self.snap_len = REC, 8
        self.watch = {MASK_ENTER: 'enter', MASK_LEAVE: 'leave'}

    def snap(self):
        o = self.snap_addr - E.RAM_LO
        return bytes(self.ram[o:o + self.snap_len])

    def sr(self):
        return self.T | (self.S << 1) | (self.Q << 8) | (self.M << 9) | self.imask

    def set_sr(self, v):
        v &= SR_BITS
        self.T, self.S, self.Q, self.M, self.imask = v & 1, (v >> 1) & 1, (v >> 8) & 1, (v >> 9) & 1, v & 0xF0

    def _exec(self, w, pc, slot, R, n, m, d4, d8, op):
        if (w & 0xF0FF) == 0x400E:                      # ldc Rm,sr  (Rm is the "n" field)
            v = R[n] & M32
            self.set_sr(v)
            self.events.append(('ldc', pc, v, self.snap()))
            return 'ldc'
        return super()._exec(w, pc, slot, R, n, m, d4, d8, op)

    def step(self):
        k = self.watch.get(self.pc)
        if k:
            self.events.append((k, self.pc, self.R[4] & M32, self.snap()))
        super().step()

    def _log(self, kind, a, n):
        a &= M32
        if self.snap_addr <= a < self.snap_addr + self.snap_len:
            self.acc.append((kind, a - self.snap_addr, n, self.imask))

    def read(self, a, n):
        self._log('r', a, n)
        return super().read(a, n)

    def write(self, a, n, v):
        self._log('w', a, n)
        return super().write(a, n, v)


RIGS = []
SENT_R = {8: 0x08080808, 9: 0x09090909, 10: 0x0A0A0A0A, 11: 0x0B0B0B0B,
          12: 0x0C0C0C0C, 13: 0x0D0D0D0D, 14: 0x0E0E0E0E}
SENT_F = {12: 0x41C00000, 13: 0x41D00000, 14: 0x41E00000, 15: 0x41F00000}


class Rig:
    """One emulator.  By default byte @(1, long @0xFFFF12A0) is 1, so a helper
    entered at mask 0 leaves through the plain rts of 0x003190."""

    def __init__(self):
        RIGS.append(self)
        self.emu = SREmu(rom)
        self.kernel(flag=1)

    def kernel(self, flag=1, lock=0xF0, cur=7, nxt=7, state=0, tcb_type=4):
        e = self.emu
        e.ram_u32(KERNEL + 24, TCB)          # 003196 / 00369A
        e.ram_u8(TCB + 0, tcb_type)          # 00345C
        e.ram_u8(TCB + 1, flag)              # 003198
        e.ram_u32(TCB + 4, TCB2)             # 00345A
        e.ram_u8(TCB2, 0)                    # 00346E writes here
        e.ram_u32(KERNEL + 16, lock)         # 00366E
        e.ram_u16(KERNEL + 4, cur)           # 003672
        e.ram_u16(KERNEL + 6, nxt)           # 003676
        e.ram_u32(KERNEL + 8, state)         # 00367E
        e.ram_u32(KERNEL + 12, 0)            # 003470 writes here

    @property
    def log(self):
        return self.emu.events

    def put(self, addr, data):
        for i, b in enumerate(data):
            self.emu.ram_u8(addr + i, b)

    def rec(self, v, c4, c6, addr=REC):
        self.put(addr, struct.pack('>IHH', v & M32, c4 & 0xFFFF, c6 & 0xFFFF))

    def get(self, addr=REC, n=8):
        return bytes(self.emu.ram[addr - E.RAM_LO:addr - E.RAM_LO + n])

    def arm(self, sr, fr4_bits=None):
        e = self.emu
        e.events, e.acc = [], []
        e.set_sr(sr)
        if fr4_bits is not None:
            e.FR[4] = fr4_bits & M32
        for k, v in SENT_R.items():
            e.R[k] = v
        for k, v in SENT_F.items():
            e.FR[k] = v
        e.macl, e.mach, e.gbr = 0x5A5A1234, 0x6B6B4321, 0xFFFF8000

    def call(self, entry, regs=None, fr4_bits=None, sr=0xF0 | FLAGS, stop_at=()):
        """Run entry to its rts.  Callee-saved state must come back untouched."""
        e = self.emu
        self.arm(sr, fr4_bits)
        r = e.call(entry, regs=regs or {}, stop_at=stop_at)
        if r != 'return':
            return r
        for k, v in SENT_R.items():
            ok(e.R[k] == v, f'{entry:06X} clobbered callee-saved r{k}')
        for k, v in SENT_F.items():
            ok(e.FR[k] == v, f'{entry:06X} clobbered fr{k}')
        ok(e.macl == 0x5A5A1234 and e.mach == 0x6B6B4321, f'{entry:06X} clobbered mac')
        ok(e.gbr == 0xFFFF8000, f'{entry:06X} changed gbr')
        ok(e.R[15] == E.STACK_TOP, f'{entry:06X} unbalanced stack')
        return e.R[0]


def masked_window(rig, initial, final, entry, old_mask, exit_pc=0x0031A6):
    """The mask is taken BEFORE the record is touched and released AFTER the last
    write; every access to the record happens at I >= 1; SR.I comes back as it
    was and M, Q, S, T come back 0 (0x003190 loads SR with old SR & 0xF0)."""
    e = rig.emu
    ev = e.events
    want = ['enter'] + (['ldc'] if old_mask < 0x10 else []) + ['leave', 'ldc']
    ok([k for k, *_ in ev] == want, f'{entry:06X}: mask events {[(k, hex(p)) for k, p, *_ in ev]}')
    ok(ev[0][2] == 16 and ev[0][3] == initial, f'{entry:06X}: 0x317C needs r4=16 and an untouched record')
    if old_mask < 0x10:
        ok(ev[1][1] == 0x003188 and ev[1][2] == 0x10 and ev[1][3] == initial,
           f'{entry:06X}: the raise must be SR=0x10 at 003188, before any access')
    lv, rs = ev[-2], ev[-1]
    ok(lv[2] == old_mask and lv[3] == final, f'{entry:06X}: 0x3190 needs r4=saved mask {old_mask:#x} and a complete record')
    ok(rs[1] == exit_pc and rs[2] == old_mask and rs[3] == final, f'{entry:06X}: restore SR={old_mask:#x} at {exit_pc:06X}')
    ok(all(i >= 0x10 for *_, i in e.acc), f'{entry:06X}: record accessed with the mask at 0')
    ok(e.sr() == old_mask, f'{entry:06X}: SR on return is {e.sr():#05x}, expected {old_mask:#04x} (I restored; M Q S T = 0)')


FLOATS = [0x00000000, 0x80000000, 0x3F800000, 0xBF800000, 0x416B3333, 0x7149F2CA,
          0x8DA24260, 0x7F800000, 0xFF800000, 0x7F7FFFFF, 0x00800000, 0x12345678,
          0x0000FFFF, 0xFF7E0001, 0x80008000, 0x7F7F7FFF]      # 0x0000FFFF is a denormal
NANS = [0x7FC00000, 0x7F800001, 0x7FBFFFFF, 0xFFFFFFFF, 0xFFC00000, 0xFFFF0000, 0x7FFFFFFF,
        0xFFFE0001, 0x7FFF7FFF]
MASKS = [0x00, 0x10, 0x70, 0xF0]
MASKED = [0x0BDB30, 0x0BDB92, 0x0BDBCC, 0x0BDC0E, 0x0BDC3C, 0x0BDC6A, 0x0BDCB6]


def run_to(emu, stops, limit=20000):
    """Continue from the current pc (no register reset) until a pc in stops."""
    n = 0
    while emu.pc not in stops:
        emu.step()
        n += 1
        if n > limit:
            raise AssertionError(f'did not reach {[hex(s) for s in stops]}')
    return emu.pc


# --------------------------------------------------------------------------
# 0. the callees, natively
# --------------------------------------------------------------------------
def sec0():
    print('== 0. 0x00317C / 0x003190 / 0x003664 natively (SR modelled), 0x003440 frame ==')
    rig = Rig()
    e = rig.emu
    n = 0
    for mask in range(0x00, 0x100, 0x10):
        for fl in (0x000, 0x001, 0x002, 0x100, 0x200, 0x303):
            for r4 in (0x00, 0x10, 0x20, 0x70, 0xF0, 0x100, 0x1F3, 0xFFFFFFFF):
                e.events = []
                e.set_sr(mask | fl)
                e.call(MASK_ENTER, regs={4: r4})
                ok(e.R[0] == mask and e.R[5] == 0xF0, '317C returns old SR & 0xF0, r5 = 0xF0')
                if r4 > mask:                       # cmp/hi r0,r4: unsigned, strict
                    ok(e.sr() == (r4 & SR_BITS), '317C raise: SR = r4 (whole register)')
                    ok([(k, p) for k, p, *_ in e.events] == [('enter', MASK_ENTER), ('ldc', 0x003188)], '317C raise path')
                else:
                    ok(e.sr() == ((mask | fl) & ~1), '317C no raise: only T changes (cmp/hi leaves T=0)')
                    ok([(k, p) for k, p, *_ in e.events] == [('enter', MASK_ENTER)], '317C must not write SR')
                n += 1
    print(f'  317C: {n} cases -> r0 = SR & 0xF0; SR = r4 iff r4 >u (SR & 0xF0), else SR untouched but for T=0')
    print('        with r4 = 0x10: mask 0 -> SR = 0x010 (I=1, M Q S T = 0); mask >= 0x10 -> no SR write')
    n = 0
    for r4 in (0x10, 0x70, 0xF0, 0x3F3, 0x00):
        for flag in (0, 1, 2, 0xFF):
            rig.kernel(flag=flag)
            e.events = []
            e.set_sr(0xF0 | FLAGS)
            r0_in = 0x77665544
            r = e.call(MASK_LEAVE, regs={4: r4, 0: r0_in}, stop_at={DISPATCH})
            ok(e.sr() == (r4 & SR_BITS), '3190: SR = r4 on every exit')
            if r4 != 0:
                ok(r == 'return' and e.R[0] == r0_in, '3190 r4 != 0: rts, r0 untouched')
                ok(e.events[-1][1] == 0x0031A6, '3190 rts exit loads SR at 0031A6')
            elif flag == 1:
                ok(r == 'return' and e.R[0] == 1, '3190 r4 == 0, byte == 1: rts with r0 = the byte')
                ok(e.events[-1][1] == 0x0031A6, '3190 rts exit loads SR at 0031A6')
            else:
                ok(r == DISPATCH and e.pr == E.RETURN_MAGIC and e.R[6] == DISPATCH,
                   '3190 r4 == 0, byte != 1: jmp 0x003664 with PR unchanged')
                ok(e.events[-1][1] == 0x0031A2, '3190 tail exit loads SR at 0031A2')
            n += 1
    print(f'  3190: {n} cases -> SR = r4 on all exits; r4 != 0 or byte@(1,[FFFF12A0]) == 1 -> rts; else jmp 0x003664')

    # 0x003664, the two exits that do not switch
    n = 0
    for lock in (0x00, 0x10, 0xF0):
        for cur, nxt, state, why in [(7, 7, 0, 'word +4 == word +6'), (7, 9, 0x1000, 'bit 0x1000 of long +8 set'),
                                     (0xFFFF, 0xFFFF, 0, 'word +4 == word +6'), (7, 9, 0x1100, 'bit 0x1000 of long +8 set')]:
            for sr_in in (0x000, 0x0F0, 0x303):
                rig.kernel(flag=0, lock=lock, cur=cur, nxt=nxt, state=state)
                rig.arm(sr_in)
                e.FR[8] = 0x42F60000
                r = e.call(DISPATCH, regs={0: 0x55, 4: 0x44, 5: 0x55, 6: 0x66}, stop_at={CTX_SAVE})
                ok(r == 'return', f'3664 must not switch when {why}')
                ok(e.R[0] == 0, '3664 returns r0 = 0')
                ok(e.sr() == (sr_in & SR_BITS), '3664 restores the SR it was entered with (ldc r13,sr)')
                ok([p for k, p, *_ in e.events if k == 'ldc'] == [0x003670, 0x0036A4], '3664 SR loads')
                ok(e.events[0][2] == lock, '3664 first loads SR from long @(16, 0xFFFF1288)')
                ok(e.R[13] == SENT_R[13] and e.R[14] == SENT_R[14] and e.R[15] == E.STACK_TOP, '3664 preserves r13 r14')
                ok(e.FR[8] == 0x42F60000, '3664 no-switch exit does not touch fr8')
                ok(e.read_u32(KERNEL + 8) == state, '3664 no-switch exit does not write long +8')
                n += 1
    print(f'  3664: {n} no-switch cases (word@+4 == word@+6, or bit 0x1000 of long@+8 set) -> rts, r0 = 0, SR as entered')

    # 0x003664 switching: reaches 0x003440; frame that 0x003440 pushes
    for tcb_type in (4, 0, 12):
        rig.kernel(flag=0, lock=0xF0, cur=7, nxt=9, state=0, tcb_type=tcb_type)
        rig.arm(0x000)
        for i in range(8):
            e.R[i] = 0xA0A0A000 | i               # caller-saved integer registers
        for i in range(12):
            e.FR[i] = 0xF0F0F000 | i              # caller-saved FP registers
        e.fpul = 0xFEEDF00D
        r = e.call(DISPATCH, stop_at={CTX_SAVE})
        ok(r == CTX_SAVE, '3664 must reach 0x003440 when the words differ and bit 0x1000 is clear')
        ok(e.R[4] == KERNEL and e.R[5] == 0 and e.R[6] == TCB, '3440 args: r4 = 0xFFFF1288, r5 = entry SR, r6 = long @(24,r4)')
        ok(e.read_u32(KERNEL + 8) == 0x0100, '00367C..003686: long @(8, 0xFFFF1288) := 0x0100')
        ok(e.pr == 0x0036A0, 'return address of the jsr at 00369C')
        sp_in = e.R[15]
        r13_in, r14_in = e.R[13], e.R[14]         # 0x003664 itself moved r13 := SR and r14 := 0xFFFF1288
        run_to(e, {SCHED})
        frame = [e.read_u32(a) for a in range(sp_in - 4, e.R[15] - 4, -4)]   # in push order
        want = [0, 0x0036A0, None, SENT_R[8], SENT_R[9], SENT_R[10], SENT_R[11], SENT_R[12],
                0xFFFF8000, r13_in, 0x6B6B4321, r14_in, 0x5A5A1234]
        if tcb_type == 4:
            want += [SENT_F[12], SENT_F[13], SENT_F[14], SENT_F[15]]
        ok(len(frame) == len(want), f'3440 frame is {len(frame)} longs, expected {len(want)}')
        for got, w in zip(frame, want):
            ok(w is None or got == w, f'3440 frame: {got:08X} vs {w}')
        lost = [0xA0A0A000 | i for i in range(8)] + [0xF0F0F000 | i for i in range(12)] + [0xFEEDF00D]
        ok(not (set(frame) & set(lost)), '3440 saved a caller-saved register')
        ok(e.read_u32(KERNEL + 12) == e.R[15], '003470: long @(12, 0xFFFF1288) := r15')
        ok(e.read_u8(TCB2) == 4, '00346E: byte @(0, long @(4,r6)) := 4')
        e.uninit_reads.discard(sp_in - 12)        # the 4-byte gap 003444 leaves unwritten
        print(f'  3440 (byte@(0,r6) = {tcb_type:2d}): pushes {len(frame)} longs = SR, pr, gap, r8-r12, gbr, r13, mach, r14, macl'
              + (', fr12-fr15' if tcb_type == 4 else '') + '; r0-r7, fr0-fr11, fpul are not saved')
    rig.kernel(flag=1)


# --------------------------------------------------------------------------
# 1. 0x0BDBCC  store float + check words (NaN refused)
# --------------------------------------------------------------------------
def sec_bdbcc():
    print('== 1. 0x0BDBCC(r4=rec, fr4=value) ==')
    print('  fr4 bits    old mask | r0 | record after (value / +4 / +6)')
    rig = Rig()
    e = rig.emu
    for bits in FLOATS:
        for m in MASKS:
            rig.rec(0x11111111, 0x2222, 0x3333)
            before = rig.get()
            r0 = rig.call(0x0BDBCC, regs={4: REC}, fr4_bits=bits, sr=m | FLAGS)
            want = struct.pack('>IHH', bits, cksum(bits), cksum(bits))
            ok(r0 == 0, f'BDBCC r0 for {bits:08X}')
            ok(rig.get() == want, f'BDBCC record for {bits:08X}')
            masked_window(rig, before, want, 0x0BDBCC, m)
            ok([a[:3] for a in e.acc] == [('w', 4, 2), ('w', 0, 4), ('w', 6, 2)], 'BDBCC: three stores, no read of the record')
            if m == 0:
                g = rig.get()
                print(f'  {bits:08X}    {m:#04x}     | {r0}  | {g[0:4].hex().upper()} / {g[4:6].hex().upper()} / {g[6:8].hex().upper()}')
    for bits in NANS:
        ok(is_nan_bits(bits), 'test vector is a NaN')
        for m in MASKS:
            rig.rec(0x11111111, 0x2222, 0x3333)
            before = rig.get()
            r0 = rig.call(0x0BDBCC, regs={4: REC}, fr4_bits=bits, sr=m | FLAGS)
            ok(r0 == 1, f'BDBCC NaN {bits:08X} must return 1')
            ok(rig.get() == before and e.acc == [], 'BDBCC NaN must not touch the record')
            ok(rig.log == [], 'BDBCC NaN must not call 0x317C / 0x3190 nor load SR')
            ok(e.sr() == (m | (FLAGS & ~1)), 'BDBCC NaN path: SR untouched but for T=0 from the fcmp/eq')
        print(f'  {bits:08X}    any      | {r0}  | untouched, 0x317C/0x3190 not called   (NaN)')
    for _ in range(400):
        bits = random.getrandbits(32)
        rig.rec(random.getrandbits(32), random.getrandbits(16), random.getrandbits(16))
        before = rig.get()
        r0 = rig.call(0x0BDBCC, regs={4: REC}, fr4_bits=bits, sr=random.choice(MASKS))
        if is_nan_bits(bits):
            ok(r0 == 1 and rig.get() == before and rig.log == [], f'BDBCC random NaN {bits:08X}')
        else:
            ok(r0 == 0 and rig.get() == struct.pack('>IHH', bits, cksum(bits), cksum(bits)),
               f'BDBCC random {bits:08X}')
    print('  + 400 random bit patterns: same contract')


# --------------------------------------------------------------------------
# 2. 0x0BDB92  store long + check words (no NaN test)
# --------------------------------------------------------------------------
def sec_bdb92():
    print('== 2. 0x0BDB92(r4=rec, r5=long) ==')
    rig = Rig()
    vals = FLOATS + NANS + [0xA5A5A5A5, 0x0000003C, 0xFFFFFFFE]
    for v in vals:
        for m in MASKS:
            rig.rec(0x11111111, 0x2222, 0x3333)
            before = rig.get()
            r0 = rig.call(0x0BDB92, regs={4: REC, 5: v}, sr=m | FLAGS)
            want = struct.pack('>IHH', v, cksum(v), cksum(v))
            ok(r0 == 0 and rig.get() == want, f'BDB92 {v:08X}')
            masked_window(rig, before, want, 0x0BDB92, m)
            ok([a[:3] for a in rig.emu.acc] == [('w', 4, 2), ('w', 0, 4), ('w', 6, 2)], 'BDB92: three stores')
    for v in (0xA5A5A5A5, 0x00000000, 0x7FC00000):
        print(f'  r5={v:08X} -> r0=0, record = {v:08X} / {cksum(v):04X} / {cksum(v):04X}')
    print(f'  {len(vals)} values x {len(MASKS)} masks; NaN bit patterns are stored like any other long')


# --------------------------------------------------------------------------
# 3. 0x0BDCB6 / 0x0BDC6A  validate (+ refresh both check words)
# --------------------------------------------------------------------------
def sec_validate(entry, is_float):
    name = 'float' if is_float else 'long'
    print(f'== 3. 0x{entry:06X}(r4=rec)  validate {name} record ==')
    print('  value     +4    +6    | r0 | record after')
    rig = Rig()
    e = rig.emu
    vals = FLOATS + NANS
    for v in vals:
        good = cksum(v)
        for tag, c4, c6 in [('both ok', good, good), ('+4 ok', good, good ^ 0x0001),
                            ('+6 ok', good ^ 0x8000, good), ('none', good ^ 0x0100, good ^ 0x0001),
                            ('none', (good + 1) & 0xFFFF, (good - 1) & 0xFFFF),
                            ('none', good ^ 0xFFFF, good ^ 0xFFFF)]:
            for m in MASKS:
                rig.rec(v, c4, c6)
                before = rig.get()
                e.FR[8] = 0x42280000
                r0 = rig.call(entry, regs={4: REC}, sr=m | FLAGS)
                valid = (c4 == good) or (c6 == good)
                want = struct.pack('>IHH', v, good, good) if valid else before
                ok(r0 == (0 if valid else 1), f'{entry:06X} r0 {v:08X} {tag}')
                ok(rig.get() == want, f'{entry:06X} record {v:08X} {tag}')
                masked_window(rig, before, want, entry, m)
                # the value is read ONCE (one 32-bit load); +6 is read only if +4 failed
                acc = [a[:3] for a in e.acc]
                exp = [('r', 0, 4), ('r', 4, 2)] + ([] if c4 == good else [('r', 6, 2)]) + \
                      ([('w', 4, 2), ('w', 6, 2)] if valid else [])
                ok(acc == exp, f'{entry:06X} access order {acc}')
                if is_float:
                    # direct-return exits only (flag byte = 1 here); see section 8 for the other exit
                    ok(e.FR[8] == v, f'{entry:06X} leaves the float in fr8 when 0x3190 returns directly')
                else:
                    ok(e.FR[8] == 0x42280000, f'{entry:06X} must not touch fr8')
                if v in (0x416B3333, 0x7FC00000) and m == 0:
                    g = rig.get()
                    print(f'  {v:08X}  {c4:04X}  {c6:04X}  | {r0}  | {g[0:4].hex().upper()} / {g[4:6].hex().upper()} / {g[6:8].hex().upper()}   ({tag})')
    # constant-fill memory: every fill byte.  Only 0x55 passes (CK(0x55555555) = 0x5555).
    passing = []
    for fill in range(256):
        rig.put(REC, bytes([fill]) * 8)
        r0 = rig.call(entry, regs={4: REC}, sr=0)
        ok(rig.get() == bytes([fill]) * 8, f'{entry:06X} fill {fill:#x}: record unchanged either way')
        if r0 == 0:
            passing.append(fill)
        vv = fill * 0x01010101
        ok((r0 == 0) == (cksum(vv) == (vv & 0xFFFF)), f'{entry:06X} fill {fill:#x} vs the rule')
    ok(passing == [0x55], f'{entry:06X}: fill bytes that validate: {passing}')
    print('  record = 8 x 0x00 -> r0=1, 8 x 0xFF -> r0=1, 8 x 0xAA -> r0=1, 8 x 0x55 -> r0=0 (VALID, value 0x55555555)')
    print('  all 256 constant fills tried: 0x55 is the only one that validates')
    n = 0
    for _ in range(600):
        v = random.getrandbits(32)
        c4 = cksum(v) if random.random() < 0.4 else random.getrandbits(16)
        c6 = cksum(v) if random.random() < 0.4 else random.getrandbits(16)
        rig.rec(v, c4, c6)
        before = rig.get()
        r0 = rig.call(entry, regs={4: REC}, sr=random.choice(MASKS))
        valid = cksum(v) in (c4, c6)
        ok(r0 == (0 if valid else 1), f'{entry:06X} random')
        ok(rig.get() == (struct.pack('>IHH', v, cksum(v), cksum(v)) if valid else before), f'{entry:06X} random rec')
        n += 1
    print(f'  + {n} random records: r0 = 0 iff ~(hi16+lo16) equals the word at +4 OR at +6')


# --------------------------------------------------------------------------
# 4. 0x0BDB30  read float, caller's default when both check words fail
# --------------------------------------------------------------------------
def sec_bdb30():
    print('== 4. 0x0BDB30(r4=rec, fr4=default) -> fr0 ==')
    print('  value     +4    +6    default  | fr0 bits')
    rig = Rig()
    e = rig.emu
    for v in FLOATS + NANS:
        good = cksum(v)
        for dflt in (0x41200000, 0x7FC00000, 0x00000000):
            for tag, c4, c6 in [('both ok', good, good), ('+4 ok', good, good ^ 0x0001),
                                ('+6 ok', good ^ 0x8000, good), ('none', good ^ 0x0100, good ^ 0x0001)]:
                for m in MASKS:
                    rig.rec(v, c4, c6)
                    before = rig.get()
                    e.FR[0] = 0x12121212
                    r0 = rig.call(0x0BDB30, regs={4: REC}, fr4_bits=dflt, sr=m | FLAGS)
                    valid = (c4 == good) or (c6 == good)
                    ok(e.FR[0] == (v if valid else dflt), f'BDB30 fr0 {v:08X} {tag}')
                    ok(rig.get() == before, 'BDB30 never writes the record (no repair)')
                    masked_window(rig, before, before, 0x0BDB30, m)
                    # the value is read TWICE: two 16-bit reads for the check, then a separate
                    # 32-bit read for the result (only when a check word matched)
                    acc = [a[:3] for a in e.acc]
                    exp = [('r', 0, 2), ('r', 2, 2), ('r', 4, 2)] + ([] if c4 == good else [('r', 6, 2)]) + \
                          ([('r', 0, 4)] if valid else [])
                    ok(acc == exp, f'BDB30 access order {acc}')
                    # r0 is not a result: last check word read (sign-extended), or the flag byte at mask 0
                    last = c4 if c4 == good else c6
                    ok(r0 == (1 if m == 0 else s16(last) & M32), f'BDB30 r0 = {r0:#x}')
                    if v == 0x416B3333 and dflt == 0x41200000 and m == 0:
                        print(f'  {v:08X}  {c4:04X}  {c6:04X}  {dflt:08X} | {e.FR[0]:08X}   ({tag})')
    for fill in range(256):
        rig.put(REC, bytes([fill]) * 8)
        rig.call(0x0BDB30, regs={4: REC}, fr4_bits=0x41200000, sr=0)
        ok(e.FR[0] == (0x55555555 if fill == 0x55 else 0x41200000), f'BDB30 on fill {fill:#x}')
    print('  NaN stored with a matching check word is returned as-is; a NaN default is returned as-is')
    print('  reads: word +0, word +2, word +4, [word +6], then long +0 again (two looks at the value)')
    print('  8 x 0x55 reads back as 0x55555555 (valid); every other constant fill gives the default')


# --------------------------------------------------------------------------
# 5. byte / word complement pairs
# --------------------------------------------------------------------------
def sec_pairs():
    print('== 5. 0x0BDB6E / 0x0BDC0E (byte + ~byte), 0x0BDB80 / 0x0BDC3C (word + ~word) ==')
    rig = Rig()
    e = rig.emu
    P = 0xFFFF2060
    e.snap_addr, e.snap_len = P, 4
    for b in range(256):
        for hi in (0, 0xABCDEF00, 0xFFFFFF00):
            rig.put(P, b'\x55\x55\x55\x55')
            r0 = rig.call(0x0BDB6E, regs={4: P, 5: hi | b}, sr=0x00 | FLAGS)
            ok(r0 == 0 and rig.get(P, 4) == bytes([b, ~b & 0xFF, 0x55, 0x55]), f'BDB6E {b:#x}')
            ok(rig.log == [], 'BDB6E does not mask interrupts')
            ok(e.sr() == FLAGS and [a[:3] for a in e.acc] == [('w', 0, 2)], 'BDB6E: one word store at mask 0, SR untouched')
        r0 = rig.call(0x0BDC0E, regs={4: P}, sr=0)
        ok(r0 == 0, 'BDC0E accepts what BDB6E wrote')
    print('  BDB6E: all 256 byte values (with junk in r5[31:8]) -> [p]=b, [p+1]=~b, r0=0, no masking, SR untouched')
    n = 0
    for b0 in range(256):
        for b1 in {~b0 & 0xFF, b0, 0x00, 0xFF} | {(~b0 & 0xFF) ^ (1 << k) for k in range(8)}:
            rig.put(P, bytes([b0, b1, 0x77, 0x77]))
            before = rig.get(P, 4)
            for m in (0x00, 0xF0):
                r0 = rig.call(0x0BDC0E, regs={4: P}, sr=m | FLAGS)
                ok(r0 == (0 if b1 == (~b0 & 0xFF) else 1), f'BDC0E {b0:#x},{b1:#x}')
                ok(rig.get(P, 4) == before, 'BDC0E is read-only')
                masked_window(rig, before, before, 0x0BDC0E, m)
                n += 1
    print(f'  BDC0E: {n} cases -> r0 = 0 iff [p] == ~[p+1] (8 bits), else 1; read-only; masked')
    words = [0x0000, 0x0001, 0x00FF, 0x0100, 0x7FFF, 0x8000, 0xA5A5, 0xFFFE, 0xFFFF] + \
            [random.getrandbits(16) for _ in range(200)]
    for wv in words:
        for hi in (0, 0x12340000, 0xFFFF0000):
            rig.put(P, b'\x55\x55\x55\x55')
            r0 = rig.call(0x0BDB80, regs={4: P, 5: hi | wv}, sr=0x00 | FLAGS)
            ok(r0 == 0 and rig.get(P, 4) == struct.pack('>HH', wv, ~wv & 0xFFFF), f'BDB80 {wv:#x}')
            ok(rig.log == [], 'BDB80 does not mask interrupts')
            ok(e.sr() == FLAGS and [a[:3] for a in e.acc] == [('w', 0, 4)], 'BDB80: one long store at mask 0, SR untouched')
        r0 = rig.call(0x0BDC3C, regs={4: P}, sr=0)
        ok(r0 == 0, 'BDC3C accepts what BDB80 wrote')
    print(f'  BDB80: {len(words)} word values -> [p]=w, [p+2]=~w, r0=0, no masking, SR untouched')
    n = 0
    for w0 in words:
        for w1 in {~w0 & 0xFFFF, w0, 0, 0xFFFF} | {(~w0 & 0xFFFF) ^ (1 << k) for k in range(16)}:
            rig.put(P, struct.pack('>HH', w0, w1))
            before = rig.get(P, 4)
            for m in (0x00, 0xF0):
                r0 = rig.call(0x0BDC3C, regs={4: P}, sr=m | FLAGS)
                ok(r0 == (0 if w1 == (~w0 & 0xFFFF) else 1), f'BDC3C {w0:#x},{w1:#x}')
                ok(rig.get(P, 4) == before, 'BDC3C is read-only')
                masked_window(rig, before, before, 0x0BDC3C, m)
                n += 1
    print(f'  BDC3C: {n} cases -> r0 = 0 iff [p] == ~[p+2] (16 bits), else 1; read-only; masked')
    for fill in range(256):
        rig.put(P, bytes([fill]) * 4)
        ok(rig.call(0x0BDC0E, regs={4: P}, sr=0) == 1, 'constant-fill byte pair is invalid')
        ok(rig.call(0x0BDC3C, regs={4: P}, sr=0) == 1, 'constant-fill word pair is invalid')
    print('  every constant fill (all 256 byte values) fails both pair checks -- b == ~b is impossible')


# --------------------------------------------------------------------------
# 6. the integer arithmetic leaves
# --------------------------------------------------------------------------
def ref_bdd0c(a, b):
    return max((a & 0xFFFF) - (b & 0xFFFF), 0)


def ref_bdd1c(a, b, k):
    a &= 0xFFFF; b &= 0xFFFF; k &= 0xFFFF
    if k == 0:
        return b
    w = (0x10000 - k) & 0xFFFF
    if b >= a:
        return a + (((b - a) * w) >> 16)
    return a - (((a - b) * w) >> 16)


def ref_bdd5a(x, hi, lo):
    if s32(x) >= s32(hi):
        return hi & M32
    return (x if s32(x) > s32(lo) else lo) & M32


def ref_bdd6e(a, b):
    return b & M32 if (a & M32) > (b & M32) else a & M32


def ref_bdd78(a, b):
    return a & M32 if (a & 0xFFFF) >= (b & 0xFFFF) else b & M32


def ref_bdd88(a, b):
    return (a - b) & M32 if s32(a) > s32(b) else (b - a) & M32


def sec_arith():
    print('== 6. integer leaves 0x0BDD0C / 0x0BDD1C / 0x0BDD5A / 0x0BDD6E / 0x0BDD78 / 0x0BDD88 ==')
    rig = Rig()

    def call(entry, regs):
        r0 = rig.call(entry, regs=regs, sr=0x00 | FLAGS)
        ok(rig.log == [] and rig.emu.acc == [], f'{entry:06X} is a leaf: no mask call, no SR load')
        ok(rig.emu.sr() & ~1 == FLAGS & ~1, f'{entry:06X} leaves I, M, Q, S alone')
        return r0
    W = [0, 1, 2, 0x7FFF, 0x8000, 0x8001, 0xFFFE, 0xFFFF, 0x1234, 0xA000]
    L = [0, 1, 2, 0x7FFF, 0x8000, 0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000, 0x80000001,
         0xFFFF8000, 0xFFFFFFFE, 0xFFFFFFFF, 0x12345678]
    n = 0
    for a in W:
        for b in W:
            for hi in (0, 0xDEAD0000):
                r0 = call(0x0BDD0C, {4: hi | a, 5: hi | b})
                ok(r0 == ref_bdd0c(a, b), f'BDD0C {a:#x},{b:#x}')
                n += 1
    for _ in range(500):
        a, b = random.getrandbits(32), random.getrandbits(32)
        ok(call(0x0BDD0C, {4: a, 5: b}) == ref_bdd0c(a, b), 'BDD0C random'); n += 1
    print(f'  BDD0C(r4,r5) = max(u16(r4) - u16(r5), 0)                      {n} cases')
    for a, b in [(5, 3), (3, 5), (0, 0xFFFF), (0xFFFF, 0), (0x8000, 0x8000)]:
        print(f'      {a:#06x},{b:#06x} -> {call(0x0BDD0C, {4: a, 5: b}):#06x}')

    n = 0
    K = [0, 1, 2, 0x0100, 0x1000, 0x7FFF, 0x8000, 0x8001, 0xC000, 0xFFFE, 0xFFFF]
    for a in W:
        for b in W:
            for k in K:
                r0 = call(0x0BDD1C, {4: 0x55550000 | a, 5: 0xAAAA0000 | b, 6: 0x77770000 | k})
                ok(r0 == ref_bdd1c(a, b, k), f'BDD1C {a:#x},{b:#x},{k:#x}: {r0:#x}')
                ok(0 <= r0 <= 0xFFFF and min(a, b) <= r0 <= max(a, b), 'BDD1C result lies between a and b')
                n += 1
    for _ in range(3000):
        a, b, k = (random.getrandbits(32) for _ in range(3))
        ok(call(0x0BDD1C, {4: a, 5: b, 6: k}) == ref_bdd1c(a, b, k), 'BDD1C random'); n += 1
    print(f'  BDD1C(r4=a,r5=b,r6=k) = k==0 ? b : a +/- ((|b-a| * (0x10000-k)) >> 16)   {n} cases, macl preserved')
    for a, b, k in [(1000, 2000, 0), (1000, 2000, 0x8000), (2000, 1000, 0x8000), (1000, 2000, 0xFFFF),
                    (1000, 2000, 1), (0, 0xFFFF, 0xC000), (0xFFFF, 0, 0xC000), (1000, 1001, 0x8000)]:
        print(f'      a={a:5d} b={b:5d} k={k:#06x} -> {call(0x0BDD1C, {4: a, 5: b, 6: k}):5d}')

    n = 0
    for x in L:
        for hi in L:
            for lo in L:
                ok(call(0x0BDD5A, {4: x, 5: hi, 6: lo}) == ref_bdd5a(x, hi, lo), f'BDD5A {x:#x},{hi:#x},{lo:#x}')
                n += 1
    for _ in range(1500):
        x, hi, lo = (random.getrandbits(32) for _ in range(3))
        ok(call(0x0BDD5A, {4: x, 5: hi, 6: lo}) == ref_bdd5a(x, hi, lo), 'BDD5A random'); n += 1
    print(f'  BDD5A(r4=x,r5=hi,r6=lo) = x>=hi ? hi : (x>lo ? x : lo)   signed 32-bit   {n} cases')
    for x, hi, lo in [(5, 10, 0), (15, 10, 0), (-5, 10, 0), (40000, 0x7FFF, -32768), (-40000, 0x7FFF, -32768),
                      (5, 0, 10), (-5, 0, 10), (10, 10, 10)]:
        r0 = call(0x0BDD5A, {4: x & M32, 5: hi & M32, 6: lo & M32})
        print(f'      x={x:6d} hi={hi:6d} lo={lo:6d} -> {s32(r0):6d}')

    n = 0
    for a in L:
        for b in L:
            ok(call(0x0BDD6E, {4: a, 5: b}) == ref_bdd6e(a, b), f'BDD6E {a:#x},{b:#x}')
            ok(call(0x0BDD78, {4: a, 5: b}) == ref_bdd78(a, b), f'BDD78 {a:#x},{b:#x}')
            ok(call(0x0BDD88, {4: a, 5: b}) == ref_bdd88(a, b), f'BDD88 {a:#x},{b:#x}')
            n += 1
    for _ in range(1500):
        a, b = random.getrandbits(32), random.getrandbits(32)
        ok(call(0x0BDD6E, {4: a, 5: b}) == ref_bdd6e(a, b), 'BDD6E random')
        ok(call(0x0BDD78, {4: a, 5: b}) == ref_bdd78(a, b), 'BDD78 random')
        ok(call(0x0BDD88, {4: a, 5: b}) == ref_bdd88(a, b), 'BDD88 random')
        n += 1
    print(f'  BDD6E(r4,r5) = unsigned-32 min                                {n} cases')
    print(f'      0xFFFFFFFF,1 -> {call(0x0BDD6E, {4: M32, 5: 1}):#x}   (so -1 is NOT below 1: unsigned)')
    print(f'  BDD78(r4,r5) = u16(r4) >= u16(r5) ? r4 : r5  (whole register returned)   {n} cases')
    print(f'      0x00018000,0x00027FFF -> {call(0x0BDD78, {4: 0x00018000, 5: 0x00027FFF}):#010x}')
    print(f'      0x0000FFFF,0x00010000 -> {call(0x0BDD78, {4: 0x0000FFFF, 5: 0x00010000}):#010x}')
    print(f'  BDD88(r4,r5) = signed r4>r5 ? r4-r5 : r5-r4  (mod 2^32)        {n} cases')
    for a, b in [(7, 3), (3, 7), (-3, 7), (0x7FFFFFFF, -0x80000000), (5, 5)]:
        print(f'      {a:11d},{b:11d} -> {call(0x0BDD88, {4: a & M32, 5: b & M32}):#010x}')


# --------------------------------------------------------------------------
# 7. write order, and what a reader sees at each intermediate state
# --------------------------------------------------------------------------
def stepped(rig, entry, regs, fr4_bits=None):
    """Run entry one instruction at a time; return [(pc, record after)] for
    every instruction (a delayed branch counts with its slot) that changed it."""
    emu = rig.emu
    rig.arm(0x000, fr4_bits)
    emu.R[15] = E.STACK_TOP
    for k, v in regs.items():
        emu.R[k] = v & M32
    emu.pr = E.RETURN_MAGIC
    emu.pc = entry
    changes = []
    while emu.pc != E.RETURN_MAGIC:
        before, pc = emu.snap(), emu.pc
        emu.step()
        if emu.snap() != before:
            changes.append((pc, emu.snap()))
    return changes


def sec_order():
    print('== 7. write order of 0x0BDBCC / 0x0BDB92 and the intermediate states ==')
    rig = Rig()
    cases = [(0x416B3333, 0x3F800000), (0x00000000, 0xBF800000), (0x00010002, 0x00020001),
             (0x12345678, 0x9ABCDEF0), (0x7FFF8000, 0x80007FFF)]
    for entry, validator, pcs, kind in [(0x0BDBCC, 0x0BDCB6, [0x0BDBF4, 0x0BDBF6, 0x0BDBFA], 'float'),
                                        (0x0BDB92, 0x0BDC6A, [0x0BDBB4, 0x0BDBB6, 0x0BDBBA], 'long')]:
        for old, new in cases:
            co, cn = cksum(old), cksum(new)
            rig.rec(old, co, co)
            if kind == 'float':
                ch = stepped(rig, entry, {4: REC}, fr4_bits=new)
            else:
                ch = stepped(rig, entry, {4: REC, 5: new})
            want = [struct.pack('>IHH', old, cn, co), struct.pack('>IHH', new, cn, co),
                    struct.pack('>IHH', new, cn, cn)]
            got = [(pc, st) for pc, st in ch]
            # a step that rewrites identical bytes is not seen as a change
            exp = [(pc, st) for (pc, st), prev in zip(zip(pcs, want), [struct.pack('>IHH', old, co, co)] + want)
                   if st != prev]
            ok(got == exp, f'{entry:06X} write order {old:08X}->{new:08X}: {[(hex(a), b.hex()) for a, b in got]}')
            ok([k for k, *_ in rig.log] == ['enter', 'ldc', 'leave', 'ldc'], 'mask events around the stepped run')
            # every state an interruption could leave behind validates, and yields old or new
            states = [struct.pack('>IHH', old, co, co)] + want
            yields = [old, old, new, new]
            for st, y in zip(states, yields):
                rig.put(REC, st)
                r0 = rig.call(validator, regs={4: REC}, sr=0)
                ok(r0 == 0, f'{validator:06X} rejects intermediate state {st.hex()}')
                ok(rig.get() == struct.pack('>IHH', y, cksum(y), cksum(y)), 'validator refreshes to the surviving value')
                rig.put(REC, st)
                rig.call(0x0BDB30, regs={4: REC}, fr4_bits=0x7149F2CA, sr=0)
                ok(rig.emu.FR[0] == y, f'BDB30 on intermediate state {st.hex()}')
            if (old, new) == cases[0]:
                print(f'  0x{entry:06X} {old:08X} -> {new:08X}: record after each writing instruction')
                print(f'      start            {states[0].hex().upper()}   validates, value {old:08X}')
                for (pc, st), y in zip(got, yields[1:]):
                    print(f'      after {pc:06X}     {st.hex().upper()}   validates, value {y:08X}')
    print('  order is +4 check word, then value, then +6 check word (in the jsr 0x3190 delay slot);')
    print('  from a record whose +6 word is good, all four states validate and read back as old or new')

    # What if the +6 word was ALREADY bad when the write started?  Then state 1 is
    # (old, CK(new), bad): valid iff CK(old) == CK(new).  Not "always invalid".
    pairs = cases + [(random.getrandbits(32), random.getrandbits(32)) for _ in range(300)]
    pairs += [(v, ((v & 0xFFFF) << 16) | (v >> 16)) for v in (0x12345678, 0x00010002, 0xC2480000)]   # halves swapped: same CK
    pairs += [(v, (v + 0x0001FFFF) & M32) for v in (0x00000001, 0x40000000)]                           # +1 high, -1 low: same CK
    same = diff = 0
    shown = set()
    for old, new in pairs:
        co, cn = cksum(old), cksum(new)
        for bad in {co ^ 1, co ^ 0x8000, (co + 0x1234) & 0xFFFF} - {co}:
            for fn in (0x0BDCB6, 0x0BDC6A):
                rig.rec(old, cn, bad)
                r0 = rig.call(fn, regs={4: REC}, sr=0)
                ok(r0 == (0 if co == cn else 1), f'bad +6: {old:08X}->{new:08X} through {fn:06X} gave {r0}')
                if co == cn:
                    ok(rig.get() == struct.pack('>IHH', old, co, co), 'it validates as the OLD value and is repaired')
            rig.rec(old, cn, bad)
            rig.call(0x0BDB30, regs={4: REC}, fr4_bits=0x7149F2CA, sr=0)
            ok(rig.emu.FR[0] == (old if co == cn else 0x7149F2CA), 'BDB30 on bad-+6 state 1')
            # states 2 and 3 are valid as the new value whatever +6 held
            rig.rec(new, cn, bad)
            ok(rig.call(0x0BDCB6, regs={4: REC}, sr=0) == 0, 'state 2 (new value, new +4) is valid whatever +6 holds')
        if co == cn:
            same += 1
        else:
            diff += 1
        key = co == cn
        if key not in shown:
            shown.add(key)
            print(f'  +6 already bad, state "old {old:08X} + new +4 {cn:04X}": CK(old)={co:04X} -> '
                  + ('VALID as the old value' if key else 'invalid (r0=1)'))
    ok(same >= 5 and diff >= 300, 'both kinds of pair exercised')
    print(f'  rule asserted on {same} pairs with CK(new) == CK(old) (valid) and {diff} pairs with CK(new) != CK(old) (invalid)')


# --------------------------------------------------------------------------
# 8. the mask-0 exit through 0x003664
# --------------------------------------------------------------------------
def helper_args(entry, v, c4, c6, rig):
    if entry in (0x0BDC0E, 0x0BDC3C):
        return {4: REC}, None
    if entry == 0x0BDB92:
        return {4: REC, 5: 0x9ABCDEF0}, None
    if entry == 0x0BDBCC:
        return {4: REC}, 0x3F800000
    if entry == 0x0BDB30:
        return {4: REC}, 0x41200000
    return {4: REC}, None


def helper_result(entry, e):
    """what the caller is meant to look at"""
    if entry == 0x0BDB30:
        return ('fr0', e.FR[0])
    return ('r0', e.R[0])


def sec_dispatch():
    print('== 8. masked helpers entered at mask 0 with byte@(1,[FFFF12A0]) != 1: the 0x003664 exit ==')
    V = 0x416B3333
    for entry in MASKED:
        # reference: the direct-return exit
        ref = Rig()
        ref.rec(V, cksum(V), cksum(V) ^ 1)
        regs, f4 = helper_args(entry, V, 0, 0, ref)
        ref.call(entry, regs=regs, fr4_bits=f4, sr=0x000)
        want_res, want_rec = helper_result(entry, ref.emu), ref.get()

        # (a) 0x003664 natively, no switch pending: word +4 == word +6
        rig = Rig()
        e = rig.emu
        rig.kernel(flag=0, cur=7, nxt=7)
        rig.rec(V, cksum(V), cksum(V) ^ 1)
        before = rig.get()
        e.FR[8] = 0x42280000
        r = rig.call(entry, regs=regs, fr4_bits=f4, sr=0x000 | FLAGS)
        ok(helper_result(entry, e) == want_res and rig.get() == want_rec, f'{entry:06X} via 3664 no-switch: same result')
        ks = [(k, p) for k, p, *_ in e.events]
        ok(ks == [('enter', MASK_ENTER), ('ldc', 0x003188), ('leave', MASK_LEAVE), ('ldc', 0x0031A2),
                  ('ldc', 0x003670), ('ldc', 0x0036A4)], f'{entry:06X} SR loads on the 3664 path: {ks}')
        ok(e.events[0][3] == before and e.events[2][3] == want_rec, f'{entry:06X}: record untouched before, complete at leave')
        ok(all(i >= 0x10 for *_, i in e.acc), f'{entry:06X}: record accessed at mask 0')
        ok(e.sr() == 0x000, f'{entry:06X}: SR = 0 on return through 3664')
        if entry == 0x0BDCB6:
            ok(e.FR[8] == V, '0BDCB6: fr8 survives the NO-switch exit of 3664')
        if entry == 0x0BDB30:
            ok(e.R[0] == 0, '0BDB30: r0 = 0 after the 3664 exit (0036A6)')

        # (b) switch pending: runs natively into 0x003440; the helper has finished with the
        #     record, and (0BDCB6) the float is in fr8 but not in the frame 0x003440 pushes
        rig = Rig()
        e = rig.emu
        rig.kernel(flag=0, cur=7, nxt=9, state=0)
        rig.rec(V, cksum(V), cksum(V) ^ 1)
        e.FR[8] = 0x42280000
        r = rig.call(entry, regs=regs, fr4_bits=f4, sr=0x000 | FLAGS, stop_at={CTX_SAVE})
        ok(r == CTX_SAVE, f'{entry:06X}: switch path reaches 0x003440')
        ok(rig.get() == want_rec, f'{entry:06X}: record is complete before the switch')
        sp_in = e.R[15]
        run_to(e, {SCHED})
        frame = [e.read_u32(a) for a in range(sp_in - 4, e.R[15] - 4, -4)]
        e.uninit_reads.discard(sp_in - 12)
        ok(len(frame) == 17, f'{entry:06X}: 0x003440 frame of 17 longs (TCB byte 4)')
        if entry == 0x0BDCB6:
            ok(e.FR[8] == V, '0BDCB6: fr8 holds the record float when the context is saved')
            ok(V not in frame, '0BDCB6: ... and that float is NOT in the saved frame')

        # (c) MODEL: something else ran.  0x003664 replaced by a stub that destroys every
        #     register 0x003440 does not save, then returns r0 = 0 as 0036A6 does.
        rig = Rig()
        e = rig.emu
        rig.kernel(flag=0)

        def other_task(emu):
            for i in range(8):
                emu.R[i] = 0xDEAD0000 | i
            for i in range(12):
                emu.FR[i] = 0xDEADF000 | i
            emu.fpul = 0xDEADBEEF
            emu.T = 1
            emu.R[0] = 0
        e.stub(DISPATCH, fn=other_task)
        rig.rec(V, cksum(V), cksum(V) ^ 1)
        e.FR[8] = 0x42280000
        rig.call(entry, regs=regs, fr4_bits=f4, sr=0x000 | FLAGS)
        ok(helper_result(entry, e) == want_res and rig.get() == want_rec,
           f'{entry:06X}: result does not depend on r0-r7 / fr0-fr11 surviving 0x003664')
        if entry == 0x0BDCB6:
            ok(e.FR[8] == 0xDEADF008, '0BDCB6: fr8 is NOT the record float after the modelled switch')
        print(f'  0x{entry:06X}: no-switch exit = same result, SR=0; switch exit reaches 0x003440 with the record complete;'
              ' result survives a clobber of r0-r7/fr0-fr11')
    print('  0x0BDCB6: fr8 == record float on the direct and no-switch exits; on the switch exit it is live in fr8')
    print('            when 0x003440 saves the context, is not in the saved frame, and is lost in the clobber model')


# --------------------------------------------------------------------------
# 9. SR on return
# --------------------------------------------------------------------------
def sec_sr():
    print('== 9. SR on return (entered with M=Q=S=T=1) ==')
    V = 0x416B3333
    for entry in MASKED:
        out = []
        for m in MASKS:
            rig = Rig()
            rig.rec(V, cksum(V), cksum(V))
            regs, f4 = helper_args(entry, V, 0, 0, rig)
            rig.call(entry, regs=regs, fr4_bits=f4, sr=m | FLAGS)
            ok(rig.emu.sr() == m, f'{entry:06X} at mask {m:#x}: SR = {rig.emu.sr():#05x}')
            out.append(f'{m | FLAGS:#05x}->{rig.emu.sr():#05x}')
        print(f'  0x{entry:06X}: ' + '  '.join(out) + '   (I kept; M Q S T cleared)')
    rig = Rig()
    rig.rec(V, 0, 0)
    rig.call(0x0BDBCC, regs={4: REC}, fr4_bits=0x7FC00000, sr=0x70 | FLAGS)
    ok(rig.emu.sr() == (0x70 | 0x302), 'BDBCC NaN: M Q S kept, T = 0')
    print(f'  0x0BDBCC with a NaN: {0x70 | FLAGS:#05x}->{rig.emu.sr():#05x}   (no SR load; T=0 from fcmp/eq)')
    for entry, regs in [(0x0BDB6E, {4: REC, 5: 1}), (0x0BDB80, {4: REC, 5: 1})]:
        rig.call(entry, regs=regs, sr=0x70 | FLAGS)
        ok(rig.emu.sr() == (0x70 | FLAGS), f'{entry:06X} does not touch SR')
    print('  0x0BDB6E / 0x0BDB80: SR unchanged (no compare, no SR load)')


def main():
    sec0()
    sec_bdbcc()
    sec_bdb92()
    sec_validate(0x0BDCB6, True)
    sec_validate(0x0BDC6A, False)
    sec_bdb30()
    sec_pairs()
    sec_arith()
    sec_order()
    sec_dispatch()
    sec_sr()
    for rig in RIGS:
        ok(rig.emu.uninit_reads == set(), f'uninitialised RAM read: {sorted(hex(a) for a in rig.emu.uninit_reads)[:4]}')
        ok(rig.emu.notes == set(), f'emulator semantics note raised: {rig.emu.notes}')
    print(f'no uninitialised RAM was read by any of the {len(RIGS)} rigs; no emulator semantics note was raised')
    print(f'\nALL {checks} ASSERTIONS HOLD')
    return 0


if __name__ == '__main__':
    sys.exit(main())
