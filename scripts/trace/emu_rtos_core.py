#!/usr/bin/env python3
"""Emulation and static check for disassembly/analysis/rtos_core_trace.txt (2026-11-27, repaired after review).

    python3 scripts/trace/emu_rtos_core.py          # prints tables, exits 0 if every assert holds (about 35 s)

Entries exercised:  0x00317C  0x003190  0x00E6E4  0x002B8C
and, because the four cannot be understood alone, the code they hand control to:
    0x00207C..  the 118 interrupt entry stubs      0x002BD4  common interrupt exit
    0x003664    deferred task switch               0x003440 / 0x00379C  voluntary context save / resume
    0x0037A0    resume of an interrupt-preempted task
    0x0031B0    ready-structure initialiser        0x003206  make-ready (queue an id, raise byte [KCB+0])
    0x002EDC    the activation service that calls 0x003206 and, if nothing forbids it, switches at once
    0x0034CC    the scan that rewrites byte [KCB+0] and word [KCB+6]
    0x0BE81C / 0x0BE82C, 0x00E6C4..0x00E744 (siblings of 0x00E6E4), 0x010800 -> 0x010B2A
    the 90 trap handlers, each run up to 0x00E774 with its peripheral writes logged

WHAT THE STOCK EMULATOR CANNOT DO, AND WHAT THIS SCRIPT ADDS
scripts/sh2e_emu.py raises on `ldc Rn,sr` and on `rte`, and its sr() reports a fixed
interrupt mask of 0xF. All four entries write SR, so none of them runs on the stock
emulator. This script subclasses it (class SREmu) and adds exactly three things:
    * an I3..I0 field, so SR = M<<9 | Q<<8 | I<<4 | S<<1 | T  (SH-2 SR layout),
    * `ldc Rn,sr`   : SR := Rn & 0x3F3   (only M,Q,I3-I0,S,T exist on the SH-2),
    * `rte`         : PC := @r15, SR := @(4,r15) & 0x3F3, r15 += 8, then the delay slot.
Everything else -- every other instruction, and the cross-check of every executed
instruction against scripts/sh2e_disasm.py -- is the stock emulator. The three
additions are this script's own model of the CPU, NOT covered by sh2e_emu --selftest.
Interrupt ACCEPTANCE is not modelled at all: a test that starts at an interrupt stub
builds the exception frame by hand (SR then PC pushed, I := the accepted level).
class PEmu adds one more thing for the trap handlers only: accesses at or above
0xFFFFC000 (on-chip registers) do not raise; reads return 0 and writes are logged.

STATIC PART (test_sites)  -- rewritten after review
The first version found call sites with scripts/mapping/function_census.resolve_reg. That
resolver walks backwards in ADDRESS order, gives up after 400 instructions and treats
literal-pool words as instructions (the pool long 0x000BE9A0 at 0x0A1FA8 contains 0xE9A0,
which decodes as `mov #-96,r9`). Every count it produced except 0x002B8C was low.
It is not used any more. Instead:
  1. CODE MAP.  Recursive descent along direct edges (bt/bf/bra/bsr) from every function
     entry. The ENTRY LIST is the only thing taken from disassembly/maps/function_census.json
     (rebuilt from bytes with function_census.Census when the file is absent). A pool word is
     never an instruction.
  2. DATAFLOW.  Forward, whole image, meet over all direct edges. A value is a small set of
     constants, a stack address r15+k, or unknown. Long slots addressed through r15 are tracked.
     A call clobbers r0-r7 and keeps r8-r14 (the Renesas C convention). How far each count
     leans on that convention is measured separately (test_convention): a greatest fixed point
     of the call targets proven to restore r8-r14 and r15 at every exit, and the sites that
     still resolve when only those may sit between the literal load and the call.
  3. COMPLETENESS.  Every aligned long equal to a target is read by a PC-relative load in the
     code map; no word outside the code map decodes as such a load except literal-pool words
     of reached code; no register holding a target address is stored anywhere but in a stack
     slot that the same dataflow follows; every indirect transfer the dataflow could NOT
     resolve is classified and none takes a target literal.
Function counts ("239 functions") use the census entry list as function boundaries. That list
contains at least one false entry (0x008000, an integer constant taken for a pointer, which
splits 0x007FDC); the counts are stated as "census functions" for that reason.

Nothing here reads a label, a doc or an analysis file. Addresses are literals taken
from the ROM bytes by the trace.
"""
import hashlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, os.path.join(REPO, 'scripts'))
import sh2e_emu as E  # noqa: E402

ROM_PATH = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
ROM_MD5 = '92cae8275cd4f9b473a3a9e36efe6449'
M32 = 0xFFFFFFFF
SR_BITS = 0x3F3

KCB = 0xFFFF1288            # literal at pool 0x002BCC / 0x0031A8 / 0x002C40 / 0x0036B4
EXIT = 0x002BD4             # literal at pool 0x002BD0
DISPATCH = 0x0035FC         # literal at pool 0x002CE8
DEFERRED = 0x003664         # literal at pool 0x0031AC
SWITCH_OUT = 0x003440       # literal at pool 0x0036C0
TASK_TABLE = 0x003F84       # literal at pool 0x003650
VBR = 0x000FFC50            # literal at pool 0x00FCC4, loaded into VBR at 0x00FA40
PC_INT = 0x000FE000         # fake "interrupted PC" (erased ROM; never executed: it is a stop address)
FAKE_CFG = 0xFFFF9000       # RAM stand-in for a task config record
FAKE_TCB = 0xFFFF9020       # RAM stand-in for a task state record
SCRATCH = 0xFFFF9100

CHECKS = [0]


def ok(cond, msg):
    CHECKS[0] += 1
    if not cond:
        raise AssertionError(msg)


class SREmu(E.Emu):
    """sh2e_emu.Emu plus an interrupt-mask field, `ldc Rn,sr` and `rte` (see module docstring)."""

    def __init__(self, rom):
        super().__init__(rom)
        self.imask = 0
        self.sr_log = []                      # (pc, value SR was set to)

    def sr(self):
        return self.T | (self.S << 1) | (self.imask << 4) | (self.Q << 8) | (self.M << 9)

    def set_sr(self, v):
        v &= SR_BITS
        self.T, self.S = v & 1, (v >> 1) & 1
        self.imask = (v >> 4) & 15
        self.Q, self.M = (v >> 8) & 1, (v >> 9) & 1

    def _exec(self, w, pc, slot, R, n, m, d4, d8, op):
        if (w & 0xF0FF) == 0x400E:            # ldc Rn,sr
            self.set_sr(R[n])
            self.sr_log.append((pc, self.sr()))
            return 'ldc'
        if w == 0x002B:                       # rte
            newpc = self.read(R[15], 4)
            R[15] = (R[15] + 4) & M32
            self.set_sr(self.read(R[15], 4))
            R[15] = (R[15] + 4) & M32
            self.sr_log.append((pc, self.sr()))
            return ('rte', ('delay', newpc))
        return super()._exec(w, pc, slot, R, n, m, d4, d8, op)


def load_rom():
    with open(ROM_PATH, 'rb') as fh:
        rom = fh.read()
    ok(hashlib.md5(rom).hexdigest() == ROM_MD5, 'reference bin md5 mismatch')
    return rom


def u32(rom, a):
    return struct.unpack('>I', rom[a:a + 4])[0]


def u16(rom, a):
    return struct.unpack('>H', rom[a:a + 2])[0]


def sext8(v):
    v &= 0xFF
    return v - 256 if v & 0x80 else v


# ------------------------------------------------------------------------------------
# 0x00317C   raise-only interrupt mask
# ------------------------------------------------------------------------------------
def model_317c(sr, r4):
    cur = sr & 0xF0
    if (r4 & M32) > cur:                      # cmp/hi r0,r4 : T = (r4 > r0) unsigned
        return cur, r4 & SR_BITS
    return cur, sr & ~1                       # T was overwritten with 0 by the compare


def test_317c(rom):
    print('== 0x00317C  r0 = SR & 0xF0 ; SR := r4 only if r4 >u (SR & 0xF0) ==')
    print('   SR_in   r4_in      -> r0     SR_out  raised')
    srs = [0x000, 0x001, 0x010, 0x011, 0x090, 0x0B0, 0x0E0, 0x0F0, 0x0F1, 0x302, 0x3F3]
    r4s = [0x00, 0x01, 0x0F, 0x10, 0x11, 0x90, 0xA0, 0xB0, 0xE0, 0xF0, 0xF1, 0x100, 0x1F0,
           0x3F3, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]
    n = 0
    for sr in srs:
        for r4 in r4s:
            emu = SREmu(rom)
            emu.set_sr(sr)
            res = emu.call(0x00317C, regs={4: r4, 0: 0xDEAD0000, 5: 0x55555555})
            want_r0, want_sr = model_317c(sr, r4)
            ok(res == 'return', '317C did not return')
            ok(emu.R[0] == want_r0, f'317C r0 sr={sr:#x} r4={r4:#x}: {emu.R[0]:#x} != {want_r0:#x}')
            ok(emu.sr() == want_sr, f'317C SR sr={sr:#x} r4={r4:#x}: {emu.sr():#x} != {want_sr:#x}')
            ok(emu.R[5] == 0xF0, '317C r5 is not the 0x00F0 mask word')
            ok(emu.R[4] == r4 & M32, '317C changed r4')
            ok(emu.R[15] == E.STACK_TOP and not emu.writes and not emu.uninit_reads,
               '317C touched memory')
            raised = bool(emu.sr_log)
            ok(raised == ((r4 & M32) > (sr & 0xF0)), '317C raise decision')
            if raised:
                ok(emu.sr_log == [(0x003188, r4 & SR_BITS)], '317C SR write site')
            n += 1
            if (sr, r4) in ((0x000, 0x10), (0x010, 0x10), (0x090, 0x10), (0x010, 0x90), (0x0E0, 0xB0),
                            (0x0F0, 0xF0), (0x001, 0x00), (0x000, 0x01), (0x0F0, 0x100), (0x302, 0xE0),
                            (0x3F3, 0xFFFFFFFF), (0x000, 0x80000000)):
                print(f'   {sr:#05x}   {r4:#010x} -> {emu.R[0]:#04x}   {emu.sr():#05x}   {raised}')
    print(f'   {n} cases agree with the model')
    # the four levels the ROM's own call sites pass, from mask 0
    for lvl in (0x10, 0x90, 0xB0, 0xE0):
        emu = SREmu(rom)
        emu.set_sr(0)
        emu.call(0x00317C, regs={4: lvl})
        ok(emu.R[0] == 0 and emu.sr() == lvl, 'call-site level')
    return n


# ------------------------------------------------------------------------------------
# 0x003190   restore mask, deferred task switch when it returns to zero
# ------------------------------------------------------------------------------------
def kcb_init(emu, hi=0xFF, cur=0, nxt=0, nest=0, sp=0xFFFF1100, lock=0xB0, tcb=FAKE_TCB,
             cfg=FAKE_CFG, cfg_b0=4, cfg_b1=0, tcb_state=0, tcb_prio=0):
    emu.ram_u8(KCB + 0, hi)
    emu.ram_u8(KCB + 1, 0)
    emu.ram_u16(KCB + 2, 0)
    emu.ram_u16(KCB + 4, cur)
    emu.ram_u16(KCB + 6, nxt)
    emu.ram_u32(KCB + 8, nest)
    emu.ram_u32(KCB + 12, sp)
    emu.ram_u32(KCB + 16, lock)
    emu.ram_u32(KCB + 20, tcb)
    emu.ram_u32(KCB + 24, cfg)
    if cfg == FAKE_CFG:
        emu.ram_u8(FAKE_CFG + 0, cfg_b0)
        emu.ram_u8(FAKE_CFG + 1, cfg_b1)
        emu.ram_u16(FAKE_CFG + 2, 0)
        emu.ram_u32(FAKE_CFG + 4, FAKE_TCB)
    if tcb == FAKE_TCB:
        emu.ram_u8(FAKE_TCB + 0, tcb_state)
        emu.ram_u8(FAKE_TCB + 1, tcb_prio)
        emu.ram_u16(FAKE_TCB + 2, 0)
        emu.ram_u32(FAKE_TCB + 4, 0)


def test_3190(rom):
    print('== 0x003190  SR := r4 ; if r4 == 0 and byte[[KCB+24]+1] != 1 -> tail-jump 0x003664 ==')
    print('   SR_in  r4_in       cfg.b1 -> outcome            SR     r0')
    n = 0
    for sr in (0x0F0, 0x010, 0x0E1, 0x000):
        for r4 in (0x00, 0x01, 0x10, 0x90, 0xB0, 0xE0, 0xF0, 0x100, 0x400, 0xFFFFFC0C, 0xFFFFFFFF):
            for b1 in (0x00, 0x01, 0x02, 0x7F, 0x81, 0xFF):
                emu = SREmu(rom)
                kcb_init(emu, cfg_b1=b1)
                emu.set_sr(sr)
                res = emu.call(0x003190, regs={4: r4, 0: 0xDEAD0000}, stop_at={DEFERRED})
                ok(emu.sr() == r4 & SR_BITS, f'3190 SR r4={r4:#x}: {emu.sr():#x}')
                if r4 & M32:
                    # T of `tst r4,r4` is 0, bf taken: nothing is read
                    ok(res == 'return', '3190 nonzero r4 must just return')
                    ok(emu.R[0] == 0xDEAD0000, '3190 nonzero r4 changed r0')
                    ok(not emu.uninit_reads and emu.sr_log == [(0x0031A6, r4 & SR_BITS)], '3190 path A')
                    outcome = 'rts'
                elif b1 == 1:
                    ok(res == 'return' and emu.R[0] == 1, '3190 zero r4, cfg.b1==1 must return')
                    ok(emu.sr_log == [(0x0031A6, 0)], '3190 path B')
                    outcome = 'rts (cfg.b1==1)'
                else:
                    ok(res == DEFERRED, '3190 zero r4 must reach 0x003664')
                    ok(emu.pr == E.RETURN_MAGIC, '3190 must TAIL-jump (PR untouched)')
                    ok(emu.sr_log == [(0x0031A2, 0)], '3190 path C')
                    ok(emu.R[0] == sext8(b1) & M32 and emu.R[5] == KCB and emu.R[6] == DEFERRED,
                       '3190 path C registers')
                    outcome = 'jmp 0x003664'
                ok(not emu.writes, '3190 wrote memory')
                n += 1
                if sr == 0x0F0 and r4 in (0x00, 0x10, 0x400, 0xFFFFFC0C) and b1 in (0, 1, 0xFF):
                    print(f'   {sr:#05x}  {r4:#010x}  {b1:#04x}   -> {outcome:<18} {emu.sr():#05x}  {emu.R[0]:#x}')
    print(f'   {n} cases agree')

    # with the ROM's real task records: byte +1 is 0x00 in all 13, so r4 == 0 always reaches 0x003664
    for i in range(13):
        rec = TASK_TABLE + 16 * i
        ok(rom[rec + 1] == 0, f'task record {i} byte+1')
        emu = SREmu(rom)
        kcb_init(emu, cfg=rec)
        emu.set_sr(0x10)
        ok(emu.call(0x003190, regs={4: 0}, stop_at={DEFERRED}) == DEFERRED, 'real record reaches 0x3664')
    print('   all 13 ROM task records (0x003F84 + 16*i): byte+1 == 0x00 -> r4 == 0 always reaches 0x003664')

    # 0x003664 itself
    print('   0x003664:  cur  next  [KCB+8]     -> outcome')
    m = 0
    for cur, nxt, nest, want in ((3, 3, 0, 'ret'), (3, 5, 0x1000, 'ret'), (3, 5, 0x1100, 'ret'),
                                 (3, 5, 0, 'switch'), (0xFFFF, 2, 0, 'switch'), (3, 5, 0x100, 'switch'),
                                 (7, 7, 0x1000, 'ret')):
        emu = SREmu(rom)
        kcb_init(emu, cur=cur, nxt=nxt, nest=nest)
        emu.set_sr(0)
        res = emu.call(0x003190, regs={4: 0, 13: 0x13131313, 14: 0x14141414}, stop_at={SWITCH_OUT})
        if want == 'ret':
            ok(res == 'return' and emu.R[0] == 0, '3664 no-switch must return 0')
            ok(emu.sr() == 0 and emu.read_u32(KCB + 8) == nest, '3664 no-switch state')
            ok(emu.sr_log == [(0x0031A2, 0), (0x003670, 0xB0), (0x0036A4, 0)], '3664 no-switch SR trail')
            ok(emu.R[13] == 0x13131313 and emu.R[14] == 0x14141414, '3664 callee-saved')
        else:
            ok(res == SWITCH_OUT, '3664 must reach 0x003440')
            ok(emu.read_u32(KCB + 8) == 0x100, '3664 sets [KCB+8] = 0x100')
            ok(emu.R[4] == KCB and emu.R[5] == 0 and emu.R[6] == FAKE_CFG, '3664 -> 0x3440 arguments')
            ok(emu.sr() & 0xF0 == 0xB0, '3664 runs the switch at the kernel lock level')
            ok(0x00300E not in emu.executed, 'hook 0x300E must not run: [0x3F2C] is 0')
        m += 1
        print(f'              {cur:#06x} {nxt:#06x} {nest:#010x} -> {"rts r0=0, SR restored" if want == "ret" else "jsr 0x003440 (r4=KCB r5=SR_in r6=[KCB+24])"}')
    ok(u32(rom, 0x003F2C) == 0, '[0x3F2C]')
    return n + m + 13


# ------------------------------------------------------------------------------------
# 0x00E6E4 and its five siblings
# ------------------------------------------------------------------------------------
def test_e6e4(rom):
    print('== 0x00E6E4  under SR=0x00E0:  word@r4 := (r6&0xFFFF) ? word|r5 : word&~r5 ; SR restored ==')
    print('   word    r5          r6          SR_in -> word    SR_out  SR trail')
    n = 0
    words = (0x0000, 0xFFFF, 0x8000, 0x1234, 0x00FF)
    masks = (0x0001, 0x0004, 0x0800, 0x8000, 0xFFFF8000, 0x0016, 0x0000, 0xFFFFFFFF, 0x00010000)
    r6s = (0, 1, 2, 0x8000, 0xFFFF, 0x10000, 0xFFFF0000, 0xFFFFFFFF)
    for sr in (0x000, 0x0F0, 0x0E0, 0x011, 0x3F3):
        for word in words:
            for r5 in masks:
                for r6 in r6s:
                    emu = SREmu(rom)
                    emu.ram_u16(SCRATCH - 2, 0xA5A5)
                    emu.ram_u16(SCRATCH, word)
                    emu.ram_u16(SCRATCH + 2, 0x5A5A)
                    emu.set_sr(sr)
                    res = emu.call(0x00E6E4, regs={4: SCRATCH, 5: r5, 6: r6, 0: 0xDEAD0000})
                    setp = (r6 & 0xFFFF) != 0
                    want = (word | r5) & 0xFFFF if setp else word & ~r5 & 0xFFFF
                    ok(res == 'return', 'E6E4 did not return')
                    ok(emu.read_u16(SCRATCH) == want, f'E6E4 word={word:#x} r5={r5:#x} r6={r6:#x}')
                    ok(emu.read_u16(SCRATCH - 2) == 0xA5A5 and emu.read_u16(SCRATCH + 2) == 0x5A5A,
                       'E6E4 wrote outside the word')
                    ok(set(emu.writes) == {SCRATCH, SCRATCH + 1}, 'E6E4 write set')
                    ok(emu.sr() == sr, 'E6E4 must restore SR exactly')
                    ok(emu.sr_log == [(0x00E6E8, 0xE0), (0x00E702 if setp else 0x00E6FA, sr)], 'E6E4 SR trail')
                    ok(emu.R[0] == 0xDEAD0000 and emu.R[2] == sr and emu.R[4] == SCRATCH, 'E6E4 registers')
                    ok(emu.R[15] == E.STACK_TOP, 'E6E4 stack')
                    n += 1
                    if sr in (0x000, 0x0F0) and word == 0x1234 and r5 in (0x0800, 0xFFFF8000) \
                            and r6 in (0, 1, 0x10000):
                        print(f'   {word:#06x}  {r5:#010x}  {r6:#010x}  {sr:#05x} -> {want:#06x}  {emu.sr():#05x}   '
                              f'{[hex(v) for _, v in emu.sr_log]}')
    print(f'   {n} cases agree  (note SR_in 0xF0: the mask is LOWERED to 0xE0 for the update)')

    print('   siblings:  entry     width  lock   op')
    sib = ((0x00E6C4, 1, True, 'setclr'), (0x00E6E4, 2, True, 'setclr'), (0x00E704, 1, False, 'setclr'),
           (0x00E71C, 2, False, 'setclr'), (0x00E734, 1, True, 'xor'), (0x00E744, 2, True, 'xor'))
    m = 0
    for entry, width, lock, opn in sib:
        full = (1 << (8 * width)) - 1
        for word in (0x0000, 0x1234 & full, full, 0x80):
            for r5 in (0x01, 0x80, 0x8000, 0xFFFFFF00, 0x16):
                for r6 in (0, 1, 0x10000):
                    emu = SREmu(rom)
                    emu.ram_u32(SCRATCH - 4, 0xA5A5A5A5)
                    emu.ram_u32(SCRATCH, 0x5A5A5A5A)
                    emu.write(SCRATCH, width, word)
                    emu.writes.clear()
                    emu.set_sr(0x0F1)
                    emu.call(entry, regs={4: SCRATCH, 5: r5, 6: r6})
                    if opn == 'xor':
                        want = (word ^ r5) & full
                    else:
                        want = (word | r5) & full if r6 & 0xFFFF else word & ~r5 & full
                    ok(emu.read(SCRATCH, width) == want, f'sibling {entry:#x}')
                    ok(len(emu.writes) == width, f'sibling {entry:#x} width')
                    if lock:
                        ok(emu.sr() == 0x0F1 and emu.sr_log[0][1] == 0xE0 and len(emu.sr_log) == 2,
                           f'sibling {entry:#x} lock')
                    else:
                        ok(not emu.sr_log, f'sibling {entry:#x} must not write SR')
                    m += 1
        print(f'              {entry:#08x}  {width}      {"0xE0" if lock else "none":<5}  '
              f'{"set/clear by r6" if opn == "setclr" else "toggle (r6 unused)"}')
    return n + m


# ------------------------------------------------------------------------------------
# 0x0BE81C / 0x0BE82C   the save/raise/restore pair wrapped round every decoded 0xE6E4 call
# ------------------------------------------------------------------------------------
def test_be81c(rom):
    print('== 0x0BE81C  *r4 := SR & 0xF0 ; SR := (r5 >=u SR&0xF0) ? r5 : SR & 0xF0     0x0BE82C  SR := r4 ==')
    n = 0
    for sr in (0x000, 0x001, 0x010, 0x0B0, 0x0E0, 0x0E1, 0x0F0, 0x3F3):
        for r5 in (0x00, 0x10, 0xB0, 0xE0, 0xF0, 0x100):
            emu = SREmu(rom)
            emu.ram_u32(SCRATCH, 0x77777777)
            emu.set_sr(sr)
            emu.call(0x0BE81C, regs={4: SCRATCH, 5: r5})
            cur = sr & 0xF0
            ok(emu.read_u32(SCRATCH) == cur and emu.R[0] == cur, 'BE81C saved mask')
            ok(emu.sr() == ((r5 & SR_BITS) if r5 >= cur else cur), 'BE81C SR')
            emu.call(0x0BE82C, regs={4: emu.read_u32(SCRATCH)})
            ok(emu.sr() == cur, 'BE82C restore')
            n += 1
    print(f'   {n} cases agree')
    return n


# ------------------------------------------------------------------------------------
# 0x002B8C   interrupt entry, and 0x002BD4 the exit it hands back
# ------------------------------------------------------------------------------------
def ctx_regs(seed=0):
    regs = {i: (0x11110000 * 0 + 0xC0DE0000 + (i << 8) + seed) & M32 for i in range(15)}
    return regs


def ctx_fregs_bits(seed=0):
    return [0x40000000 + (i << 16) + seed for i in range(16)]


def test_2b8c_direct(rom):
    print('== 0x002B8C  direct call: [KCB+8] += 1 under SR=[KCB+16]; push r2..r7, fr0..fr10, fpscr, fr11, fpul; r0 := 0x002BD4 ==')
    print('   SR_in  [KCB+8]_in  -> [KCB+8]_out  r0        SR_out  SR trail          r15')
    n = 0
    for sr in (0x010, 0x050, 0x0B0, 0x0F0, 0x0D1):
        for nest in (0, 1, 2, 0x80000000, 0x100, 0x1000, 0xFFFFFFFF):
            emu = SREmu(rom)
            kcb_init(emu, nest=nest)
            regs = ctx_regs()
            for i, b in enumerate(ctx_fregs_bits()):
                emu.FR[i] = b
            emu.fpscr, emu.fpul = 0x00040001, 0x0F0F0F0F
            emu.set_sr(sr)
            res = emu.call(0x002B8C, regs=regs)
            ok(res == 'return', '2B8C did not return')
            ok(emu.R[0] == EXIT, '2B8C must return 0x002BD4 in r0')
            ok(u32(rom, 0x002BD0) == EXIT, 'pool word 0x2BD0')
            ok(emu.R[1] == KCB and emu.R[2] == sr, '2B8C r1/r2')
            ok(emu.read_u32(KCB + 8) == (nest + 1) & M32, '2B8C nest counter')
            ok(emu.sr() == sr, '2B8C must leave SR as it found it')
            ok(emu.sr_log == [(0x002B94, 0xB0), (0x002B9C, sr)], '2B8C SR trail')
            ok(emu.R[15] == E.STACK_TOP - 80, '2B8C pushes exactly 20 longs')
            fb = ctx_fregs_bits()
            want = [regs[2], regs[3], regs[4], regs[5], regs[6], regs[7]] + fb[0:11] + \
                   [0x00040001, fb[11], 0x0F0F0F0F]
            got = [emu.read_u32(E.STACK_TOP - 4 * (k + 1)) for k in range(20)]
            ok(got == want, '2B8C frame layout')
            ok(all(emu.R[i] == regs[i] for i in range(3, 15)), '2B8C changed r3..r14')
            ok(emu.FR == fb, '2B8C changed an FP register')
            ok(set(a & ~3 for a in emu.writes) == {KCB + 8}, '2B8C wrote RAM other than [KCB+8]')
            n += 1
            if sr in (0x050, 0x0F0) and nest in (0, 1, 0x80000000):
                print(f'   {sr:#05x}  {nest:#010x}  -> {emu.read_u32(KCB + 8):#010x}   {emu.R[0]:#08x}  {emu.sr():#05x}   '
                      f'{[hex(v) for _, v in emu.sr_log]}  top-{E.STACK_TOP - emu.R[15]}')
    print(f'   {n} cases agree  (note SR_in 0xF0: the mask is LOWERED to 0xB0 around the increment)')
    return n


def isr_roundtrip(rom, stub, handler, *, nest, sr_int, level, hi, cfg_b0=4, cfg_b1=0, tcb_prio=0,
                  nxt=5, stop):
    """Enter at an interrupt stub with a hand-built exception frame; run until `stop`."""
    emu = SREmu(rom)
    kcb_init(emu, hi=hi, cur=3, nxt=nxt, nest=nest, cfg_b0=cfg_b0, cfg_b1=cfg_b1, tcb_prio=tcb_prio,
             tcb_state=0x55)
    regs = ctx_regs()
    for i, b in enumerate(ctx_fregs_bits()):
        emu.FR[i] = b
    emu.fpscr, emu.fpul = 0x00040001, 0x0F0F0F0F
    emu.gbr, emu.mach, emu.macl = 0xFFFF7000, 0x0A0A0A0A, 0x0B0B0B0B
    sp0 = E.STACK_TOP - 0x40
    emu.ram_u32(sp0 - 4, sr_int)              # the CPU pushes SR, then PC
    emu.ram_u32(sp0 - 8, PC_INT)
    regs[15] = sp0 - 8
    emu.set_sr((sr_int & ~0xF0) | (level << 4))
    seen = {}

    def handler_body(e):
        seen['pr'] = e.pr
        seen['nest'] = e.read_u32(KCB + 8)
        seen['sr'] = e.sr()
        seen['r15'] = e.R[15]
        for i in range(8):                    # a C handler may clobber r0-r7, fr0-fr11, fpul, fpscr
            e.R[i] = 0xBAD00000 + i
        for i in range(12):
            e.FR[i] = 0x7F000000 + i
        e.fpul, e.fpscr = 0xBADBADBA, 0x00040000

    emu.stub(handler, fn=handler_body)
    res = emu.call(stub, regs=regs, stop_at=stop)
    return emu, res, regs, sp0, seen


def test_isr(rom):
    print('== stub -> 0x002B8C -> handler -> 0x002BD4:  full interrupt round trip ==')
    stubs = find_stubs(rom)
    stub, handler = stubs[0]
    ok(stub == 0x00207C and handler == 0x00E8D8, 'first stub')

    print('   plain exit (rte to the interrupted code, everything restored):')
    print('   [KCB+8]     SR_int  KCB.b0  cfg.b1  run.prio -> reached')
    plain = [
        # nest,        sr_int, hi,   cfg_b1, prio   why it must not switch
        (1,            0x000,  3,    0,      0),    # still nested
        (0,            0x010,  3,    0,      0),    # interrupted code had I != 0
        (0,            0x0E1,  3,    0,      0),
        (0x1000,       0x000,  3,    0,      0),    # flag bits in the counter
        (0,            0x000,  0xFF, 0,      0),    # nothing ready
        (0,            0x000,  3,    1,      0),    # config byte +1 == 1
        (0,            0x000,  2,    0,      2),    # ready priority not higher
        (0,            0x000,  2,    0,      3),
        (0x80000000,   0x000,  0xFF, 0,      0),    # idle, nothing ready
    ]
    n = 0
    for nest, sr_int, hi, b1, prio in plain:
        emu, res, regs, sp0, seen = isr_roundtrip(rom, stub, handler, nest=nest, sr_int=sr_int, level=7,
                                                  hi=hi, cfg_b1=b1, tcb_prio=prio,
                                                  stop={PC_INT, DISPATCH})
        ok(seen['pr'] == EXIT, 'handler must be entered with PR = 0x002BD4')
        ok(seen['nest'] == (nest + 1) & M32, 'handler sees the incremented counter')
        ok(seen['sr'] == ((sr_int & ~0xF0) | 0x70), 'handler runs at the accepted level')
        ok(seen['r15'] == sp0 - 8 - 92, 'stub (3) + 0x2B8C (20) push 23 longs before the handler')
        ok(res == PC_INT, f'plain exit expected for {nest:#x},{sr_int:#x},{hi:#x},{b1},{prio}')
        ok(emu.sr() == sr_int & SR_BITS, 'rte restores the interrupted SR')
        ok(emu.R[15] == sp0, 'rte pops the exception frame')
        ok(all(emu.R[i] == regs[i] for i in range(15)), 'r0..r14 restored')
        ok(emu.FR == ctx_fregs_bits(), 'fr0..fr15 restored')
        ok(emu.fpscr == 0x00040001 and emu.fpul == 0x0F0F0F0F and emu.pr == E.RETURN_MAGIC,
           'fpscr/fpul/pr restored')
        ok(emu.read_u32(KCB + 8) == nest, 'counter back to its entry value')
        ok(emu.read_u8(FAKE_TCB) == 0x55, 'task state untouched')
        n += 1
        print(f'   {nest:#010x}  {sr_int:#05x}   {hi:#04x}    {b1}       {prio}        -> rte, context intact')

    print('   preemption (control leaves through jmp 0x0035FC instead of rte):')
    print('   [KCB+8]     SR_int  KCB.b0  run.prio  cfg.b0 -> frame saved  [KCB+8]  task.state')
    for hi, prio, b0 in ((3, 2, 4), (1, 0, 4), (4, 0, 4), (0x7F, 0x7E, 4), (3, 2, 0)):
        emu, res, regs, sp0, seen = isr_roundtrip(rom, stub, handler, nest=0, sr_int=0x000, level=7,
                                                  hi=hi, cfg_b0=b0, tcb_prio=prio,
                                                  stop={PC_INT, DISPATCH})
        ok(res == DISPATCH, 'preemption expected')
        ok(emu.R[4] == KCB and emu.R[5] == 5, 'dispatcher gets r4 = KCB, r5 = word [KCB+6]')
        ok(emu.read_u32(KCB + 8) == 0x100, '[KCB+8] := 0x100')
        ok(emu.read_u8(FAKE_TCB) == 12, 'task state byte := 12')
        ok(emu.read_u32(KCB + 12) == emu.R[15], '[KCB+12] := saved stack pointer')
        ok(emu.sr() == 0xB0, 'dispatcher entered at the kernel lock level')
        fb = ctx_fregs_bits()
        frame = [E.RETURN_MAGIC] + [regs[i] for i in (7, 6, 5, 4, 3, 2, 1)]
        if b0 == 4:
            frame += [0x0F0F0F0F, fb[11], 0x00040001] + [fb[i] for i in range(10, -1, -1)] + \
                     [fb[15], fb[14], fb[13], fb[12]]
        frame += [0x0B0B0B0B, regs[14], 0x0A0A0A0A, regs[13], 0xFFFF7000, regs[12], regs[11], regs[10],
                  regs[9], regs[8], regs[0], PC_INT, 0x000]
        got = [emu.read_u32(emu.R[15] + 4 * k) for k in range(len(frame))]
        ok(got == frame, f'saved context layout (cfg.b0={b0})')
        ok(emu.R[15] + 4 * len(frame) == sp0, 'saved frame ends at the interrupted stack pointer')
        ok(0x00300E not in emu.executed, 'hook not configured')
        n += 1
        print(f'   0x00000000  0x000   {hi:#04x}    {prio:#04x}      {b0}      -> {len(frame)} longs    '
              f'{emu.read_u32(KCB + 8):#x}    {emu.read_u8(FAKE_TCB)}')
        if b0 == 4:
            # and the matching resume routine (state 12 -> table 0x4090[(12-4)/4] = 0x0037A0) undoes it
            ok(u32(rom, 0x004090 + 12 - 4) == 0x0037A0, 'resume table entry for state 12')
            emu.sr_log.clear()
            emu.stubs.clear()
            for i in range(15):
                emu.R[i] = 0x99990000 + i
            emu.FR = [0x7E000000 + i for i in range(16)]
            res = emu.call(0x0037A0, regs={4: emu.read_u32(KCB + 12), 15: 0xFFFF9800}, stop_at={PC_INT})
            ok(res == PC_INT and emu.R[15] == sp0 and emu.sr() == 0, 'resume returns to the interrupted code')
            ok(all(emu.R[i] == regs[i] for i in range(15)) and emu.FR == fb, 'resume restores r0..r14, fr0..fr15')
            ok(emu.gbr == 0xFFFF7000 and emu.mach == 0x0A0A0A0A and emu.macl == 0x0B0B0B0B, 'resume gbr/mac')

    print('   idle preemption ([KCB+8] bit 31 set: the stack is abandoned, not saved):')
    emu, res, regs, sp0, seen = isr_roundtrip(rom, stub, handler, nest=0x80000000, sr_int=0x000, level=7,
                                              hi=1, stop={PC_INT, DISPATCH})
    ok(res == DISPATCH, 'idle preemption expected')
    ok(emu.R[15] == u32(rom, 0x003F44) == 0xFFFF11C8, 'r15 := [0x003F44]')
    ok(emu.read_u32(KCB + 8) == 0x100 and emu.R[4] == KCB and emu.R[5] == 5 and emu.sr() == 0xB0,
       'idle preemption state')
    ok(emu.read_u8(FAKE_TCB) == 0x55, 'idle path does not touch a task state byte')
    n += 1
    print(f'   0x80000000  0x000   0x01    -         -      -> none        {emu.read_u32(KCB + 8):#x}    r15={emu.R[15]:#x}')

    # every one of the 118 stubs behaves the same; only the handler differs
    for stub, handler in stubs:
        emu, res, regs, sp0, seen = isr_roundtrip(rom, stub, handler, nest=1, sr_int=0x040, level=9,
                                                  hi=0xFF, stop={PC_INT, DISPATCH})
        ok(res == PC_INT and seen['pr'] == EXIT and seen['nest'] == 2, f'stub {stub:#x}')
        ok(all(emu.R[i] == regs[i] for i in range(15)) and emu.R[15] == sp0 and emu.sr() == 0x040,
           f'stub {stub:#x} context')
        n += 1
    print(f'   all {len(stubs)} stubs: handler entered with PR=0x002BD4, context restored by rte')
    return n


def find_stubs(rom):
    """The 118 stubs, found by their 16 invariant bytes; returns [(stub, handler)]."""
    pat = bytes.fromhex('2F06D0044F22400B2F16D101412B402A')
    out, a = [], 0
    while True:
        a = rom.find(pat, a)
        if a < 0:
            break
        ok(u32(rom, a + 20) == 0x002B8C, f'stub {a:#x} second pool word')
        out.append((a, u32(rom, a + 16)))
        a += 2
    return out


def test_vectors(rom):
    print('== vector table at VBR = 0x000FFC50 ==')
    ok(u32(rom, 0x00FCC4) == VBR and u16(rom, 0x00FA3E) == 0xD2A1 and u16(rom, 0x00FA40) == 0x422E,
       'VBR literal and the ldc r2,vbr that loads it')
    stubs = find_stubs(rom)
    ok(len(stubs) == 118, 'stub count')
    ok([s for s, _ in stubs] == [0x00207C + 24 * i for i in range(118)], 'stubs are contiguous, 24 bytes each')
    ok(len({h for _, h in stubs}) == 118, 'every stub has its own handler')
    by_stub = dict(stubs)
    vec_of = {}
    for v in range((0x100000 - VBR) // 4):
        t = u32(rom, VBR + 4 * v)
        if t in by_stub:
            ok(t not in vec_of, 'a stub is installed in two vectors')
            vec_of[t] = v
    ok(len(vec_of) == 118, 'every stub is installed in exactly one vector')
    ok(min(vec_of.values()) == 64 and max(vec_of.values()) == 231, 'stub vectors span 64..231')
    # handlers that fall straight into the common trap pass their own vector number in r4
    trap = 0
    for stub, handler in stubs:
        a, r4 = handler, None
        for _ in range(14):
            w = u16(rom, a)
            if (w >> 12) == 8 and ((w >> 8) & 0xF) in (9, 0xB, 0xD, 0xF):
                break                                    # conditional branch: not a straight-line trap
            if w == 0x000B or ((w >> 12) == 4 and (w & 0xFF) == 0x2B):
                break
            if (w >> 12) == 0xA:
                d = w & 0xFFF
                d -= 0x1000 if d & 0x800 else 0
                if a + 4 + 2 * d == 0x00E774:
                    s = u16(rom, a + 2)
                    if s >> 8 == 0xE4:
                        r4 = s & 0xFF
                    elif s >> 8 == 0x94:
                        r4 = u16(rom, a + 2 + 4 + (s & 0xFF) * 2)
                    ok(r4 == vec_of[stub], f'trap handler {handler:#x} passes {r4}, vector is {vec_of[stub]}')
                    trap += 1
                break
            if w >> 8 == 0xE4:
                r4 = w & 0xFF
            elif w >> 8 == 0x94:
                r4 = u16(rom, a + 4 + (w & 0xFF) * 2)
            a += 2
    ok(trap == 90, 'count of straight-line trap handlers')
    print(f'   118 stubs 0x00207C..0x002B74 (24 bytes each) installed in vectors 64..231, one vector each')
    print(f'   {trap} of the 118 handlers run straight into bra 0x00E774 with r4 == their own vector number')
    print('   first four:  vector  slot      stub      handler')
    for stub, handler in stubs[:4]:
        print(f'                {vec_of[stub]:>3}     {VBR + 4 * vec_of[stub]:#08x}  {stub:#08x}  {handler:#08x}')
    return 118


# ------------------------------------------------------------------------------------
# 0x010800 -> 0x010B2A   what the structure at 0xFFFF2060 / 0xFFFF2064 is
# ------------------------------------------------------------------------------------
def test_log(rom):
    print('== 0x010800(r4 = 16-bit code, r5 = 32-bit datum) -> 0x010B2A:  the structure at 0xFFFF2060.. ==')
    emu = SREmu(rom)
    for a in range(0xFFFF2060, 0xFFFF20A8, 4):
        emu.ram_u32(a, 0)
    kcb_init(emu)
    emu.set_sr(0x000)

    def count():
        w = emu.read_u16(0xFFFF2060)
        return (w >> 8) if (w >> 8) == (~w & 0xFF) else None

    def slot(i):
        a = 0xFFFF2064 + 12 * i
        w = emu.read_u32(a)
        code = (w >> 16) if (w >> 16) == (~w & 0xFFFF) else None
        return code, emu.read_u32(a + 4), emu.read_u8(a + 8)

    seq = [(0x4000, 64), (0x4000, 65), (0x1700, 0x11), (0x4000, 66), (0x1600, 1), (0x1000, 2), (0x0123, 3),
           (0x0456, 4), (0x0456, 5), (0x1700, 6)]
    print('   call  code    datum       -> count  slots (code:datum:hits)                          last')
    k = 0
    for code, datum in seq:
        emu.sr_log.clear()
        emu.executed.clear()
        res = emu.call(0x010800, regs={4: code, 5: datum})
        ok(res == 'return', '10800 did not return')
        ok(0x00E6E4 not in emu.executed, '0x00E6E4 is not on the 0x010800 path')
        ok(emu.sr() == 0x000, '10800 restores the mask')
        ok(emu.sr_log[0] == (0x0BE82A, 0xE0), '10800 first raises the mask to 0xE0 through 0x0BE81C')
        ok(DEFERRED not in emu.executed, 'inside the 0xE0 section 0x3190 never reaches 0x3664')
        lw = emu.read_u32(0xFFFF20A0)
        ok((lw >> 16) == code and (lw & 0xFFFF) == (~code & 0xFFFF), 'last-code word is code:~code')
        ok(emu.read_u32(0xFFFF20A4) == datum, 'last-datum long')
        k += 1
        slots = [slot(i) for i in range(count())]
        txt = ' '.join(f'{c:04X}:{d:X}:{h}' for c, d, h in slots)
        print(f'   {k:>2}    {code:#06x}  {datum:#010x}  -> {count()}      {txt:<48} {lw >> 16:04X}:{emu.read_u32(0xFFFF20A4):X}')
    ok(count() == 5, 'the table holds at most 5 records')
    ok([slot(i) for i in range(5)] == [(0x4000, 64, 3), (0x1700, 0x11, 2), (0x1600, 1, 1), (0x1000, 2, 1),
                                       (0x0123, 3, 1)], 'final table')
    # hit counter saturates at 255
    for _ in range(300):
        emu.call(0x010800, regs={4: 0x1600, 5: 9})
    ok(slot(2) == (0x1600, 1, 255), 'hit counter saturates at 0xFF and the first datum is kept')
    print('   record = {code:~code word pair, datum long, hit byte}, 12 bytes; first datum kept; hits saturate at 255;')
    print('   a 6th distinct code is not stored, only the "last" pair at 0xFFFF20A0/0xFFFF20A4 changes')
    return k + 300


# ------------------------------------------------------------------------------------
# 0x0034CC   what byte [KCB+0] (compared by the interrupt exit at 0x002C2E) holds
# ------------------------------------------------------------------------------------
def test_scan(rom):
    print('== 0x0034CC  byte [KCB+0] := highest set index in the 16-byte map at 0xFFFF12B8, 0xFF if empty ==')
    MAP = 0xFFFF12B8
    ok(u32(rom, 0x003590) == MAP, 'map literal')

    def run(bits):
        emu = SREmu(rom)
        kcb_init(emu)
        for k in range(16):
            emu.ram_u8(MAP + k, 0)
        for i in bits:
            emu.ram_u8(MAP + (i >> 3), emu.read_u8(MAP + (i >> 3)) | (1 << (i & 7)))
        # stop right after the store at 0x003570; the id lookup that follows needs kernel tables
        return emu, emu.call(0x0034CC, regs={4: KCB}, stop_at={0x003572})

    n = 0
    for i in range(128):
        emu, res = run([i])
        ok(res == 0x003572 and emu.read_u8(KCB) == i, f'single bit {i}')
        n += 1
    seed = 12345
    for _ in range(400):
        bits = []
        for _ in range(1 + seed % 5):
            seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
            bits.append((seed >> 8) % 128)
        emu, res = run(bits)
        ok(res == 0x003572 and emu.read_u8(KCB) == max(bits), f'bits {bits}')
        n += 1
    emu, res = run([])
    ok(res == 'return' and emu.read_u8(KCB) == 0xFF and emu.read_u16(KCB + 6) == 0xFFFF, 'empty map')
    n += 1
    print(f'   {n} cases agree: index i = bit (i & 7) of byte 0xFFFF12B8 + (i >> 3); empty map -> byte 0xFF, word [KCB+6] = 0xFFFF')
    return n


# ------------------------------------------------------------------------------------
# the mask pairs do not keep M, Q, S, T
# ------------------------------------------------------------------------------------
def test_pairs(rom):
    print('== the bracket pairs return with SR = (entry SR) & 0xF0: M, Q, S and T are NOT preserved ==')
    print('   pair                  SR_in  level -> SR inside  SR after')
    n = 0
    for sr in (0x000, 0x001, 0x002, 0x003, 0x013, 0x0B1, 0x0F3, 0x102, 0x201, 0x303, 0x3F3):
        for lvl in (0x10, 0x90, 0xB0, 0xE0):
            # 0x00317C(level) ... 0x003190(value 0x00317C returned)
            emu = SREmu(rom)
            kcb_init(emu, cur=3, nxt=3)                  # nothing due: 0x003664 returns at once
            emu.set_sr(sr)
            emu.call(0x00317C, regs={4: lvl})
            saved, inside = emu.R[0], emu.sr()
            ok(saved == sr & 0xF0, 'pair: 0x00317C returns only the mask field')
            ok(inside == (lvl if lvl > (sr & 0xF0) else sr & ~1), 'pair: SR inside the section')
            res = emu.call(0x003190, regs={4: saved})
            ok(res == 'return' and emu.sr() == sr & 0xF0, f'317C/3190 pair from {sr:#x}: SR {emu.sr():#x}')
            n += 1
            if sr in (0x013, 0x303) and lvl in (0x10, 0xE0):
                print(f'   0x00317C / 0x003190   {sr:#05x}  {lvl:#04x}  -> {inside:#05x}      {emu.sr():#05x}')
            # 0x0BE81C(&save, level) ... 0x0BE82C(save)
            emu = SREmu(rom)
            emu.ram_u32(SCRATCH, 0x77777777)
            emu.set_sr(sr)
            emu.call(0x0BE81C, regs={4: SCRATCH, 5: lvl})
            inside = emu.sr()
            ok(inside == max(lvl, sr & 0xF0), 'pair: 0x0BE81C leaves M = Q = S = T = 0 on both paths')
            emu.call(0x0BE82C, regs={4: emu.read_u32(SCRATCH)})
            ok(emu.sr() == sr & 0xF0, f'BE81C/BE82C pair from {sr:#x}: SR {emu.sr():#x}')
            n += 1
            if sr in (0x013, 0x303) and lvl == 0xE0:
                print(f'   0x0BE81C / 0x0BE82C   {sr:#05x}  {lvl:#04x}  -> {inside:#05x}      {emu.sr():#05x}')
    # the reviewer's case: 0x010800 entered with SR = 0x013 comes back with SR = 0x010
    emu = SREmu(rom)
    for a in range(0xFFFF2060, 0xFFFF20A8, 4):
        emu.ram_u32(a, 0)
    kcb_init(emu)
    emu.set_sr(0x013)
    ok(emu.call(0x010800, regs={4: 0x5000, 5: 1}) == 'return' and emu.sr() == 0x010, '0x010800 from SR 0x013')
    print('   0x010800              0x013          -> returns with SR = 0x010 (S and T gone)')
    # by contrast 0x00E6E4 puts back the exact entry SR (asserted over 1,800 cases in test_e6e4)
    return n + 1


# ------------------------------------------------------------------------------------
# the 90 trap handlers: how many register writes each makes before bra 0x00E774
# ------------------------------------------------------------------------------------
class PEmu(SREmu):
    """SREmu that tolerates on-chip register access: reads give 0, writes are logged."""

    def __init__(self, rom):
        super().__init__(rom)
        self.pwrites = []
        self.preads = []

    def read(self, a, n):
        a &= M32
        if a >= 0xFFFFC000:
            self.preads.append((a, n))
            return 0
        return super().read(a, n)

    def write(self, a, n, v):
        a &= M32
        if a >= 0xFFFFC000:
            self.pwrites.append((a, n, v & ((1 << (8 * n)) - 1)))
            return None
        return super().write(a, n, v)


TRAP_TWO_WRITES = [96, 104, 108, 109, 110, 111, 112, 113, 114, 115, 116]
TRAP_NO_WRITE = [202, 203, 206, 207, 210, 211, 214, 215, 218]


def test_traps(rom):
    print('== the trap handlers, each emulated from its entry to 0x00E774 (register reads give 0) ==')
    stubs = find_stubs(rom)
    vec_of = {}
    for v in range((0x100000 - VBR) // 4):
        vec_of.setdefault(u32(rom, VBR + 4 * v), v)
    by_count = {}
    ram_touched = 0
    for stub, handler in stubs:
        emu = PEmu(rom)
        emu.set_sr(0x070)
        try:
            res = emu.call(handler, stop_at={0x00E774}, max_steps=40)
        except E.EmuError:
            continue                                  # a real handler: calls, loops or needs state
        if res != 0x00E774:
            continue
        v = vec_of[stub]
        ok(emu.R[4] == v, f'trap handler {handler:#x} reaches 0x00E774 with r4 = {emu.R[4]}, vector {v}')
        ok(emu.sr() == 0x070 and not emu.sr_log, 'a trap handler does not touch SR before 0x00E774')
        ram_touched += bool(emu.writes)
        by_count.setdefault(len(emu.pwrites), []).append((v, handler, emu.pwrites))
    n = sum(len(x) for x in by_count.values())
    ok(n == 90, f'{n} handlers run straight into 0x00E774')
    ok({k: len(x) for k, x in by_count.items()} == {1: 70, 2: 11, 0: 9}, 'register writes per trap handler')
    ok(sorted(v for v, _, _ in by_count[2]) == TRAP_TWO_WRITES, 'vectors whose trap handler makes two writes')
    ok(sorted(v for v, _, _ in by_count[0]) == TRAP_NO_WRITE, 'vectors whose trap handler makes no write')
    ok(ram_touched == 0, 'no trap handler writes RAM before 0x00E774')
    print(f'   {n} handlers reach 0x00E774 with r4 == their own vector number; none writes RAM or SR first')
    print('   register writes before the branch:  one x70,  two x11,  none x9')
    for v, h, pw in sorted(by_count[2])[:3]:
        print(f'      vector {v:>3} handler {h:#08x}: ' + ', '.join(f'[{a:#010x}] := {val:#06x}' for a, _, val in pw))
    print(f'      two writes: vectors {TRAP_TWO_WRITES}')
    print(f'      no write:   vectors {TRAP_NO_WRITE}')
    return n


# ------------------------------------------------------------------------------------
# what makes a switch "due": 0x0031B0 (initialise), 0x003206 (make ready), 0x002EDC (activate)
# ------------------------------------------------------------------------------------
READY_MAP = 0xFFFF12B8          # literal at pool 0x0032FC / 0x003590
RING = 0xFFFF1230               # literal at pool 0x0032F8
CFG_INDEX = 0x004080            # literal at pool 0x0032F4: long table indexed by byte [KCB+1]


def ready_table(rom):
    """The five 8-byte rows {word first slot, word last slot, long -> head/tail record}."""
    base = u32(rom, CFG_INDEX)
    top = sext8(rom[0x004054])
    return [(u16(rom, base + 8 * i), u16(rom, base + 8 * i + 2), u32(rom, base + 8 * i + 4))
            for i in range(top + 1)]


def kernel_ready_init(rom, emu):
    kcb_init(emu)                                   # byte [KCB+1] = 0
    for a in range(RING, KCB, 2):
        emu.ram_u16(a, 0x5555)
    for a in range(READY_MAP, READY_MAP + 16, 4):
        emu.ram_u32(a, 0xA5A5A5A5)
    emu.ram_u32(KCB + 32, 0xDEADBEEF)
    emu.ram_u32(KCB + 36, 0xDEADBEEF)
    emu.writes.clear()
    res = emu.call(0x0031B0, regs={4: KCB, 14: 0x14141414})
    ok(res == 'return' and emu.R[14] == 0x14141414, '0x0031B0 returns and keeps r14')


def test_ready(rom):
    print('== 0x0031B0 / 0x003206 / 0x0034CC / 0x002EDC: the writers of byte [KCB+0] and word [KCB+6] ==')
    rows = ready_table(rom)
    ok(rows == [(0x00, 0x01, 0xFFFF1272), (0x02, 0x07, 0xFFFF1276), (0x08, 0x13, 0xFFFF127A),
                (0x14, 0x19, 0xFFFF127E), (0x1A, 0x20, 0xFFFF1282)], 'ready table at 0x004058')
    ok(rom[0x003594:0x00359C] == bytes(1 << k for k in range(8)), 'bit table at 0x003594')
    n = 0

    # ---- 0x0031B0
    emu = SREmu(rom)
    kernel_ready_init(rom, emu)
    ok(emu.read_u8(KCB) == 0xFF and emu.read_u16(KCB + 6) == 0xFFFF, '0x0031B0: byte [KCB+0], word [KCB+6]')
    ok(emu.read_u32(KCB + 32) == u32(rom, CFG_INDEX) == 0x004058 and emu.read_u32(KCB + 36) == RING,
       '0x0031B0: [KCB+32], [KCB+36]')
    ok(all(emu.read_u32(READY_MAP + 4 * k) == 0 for k in range(4)), '0x0031B0 clears the four map longs')
    want = {KCB, KCB + 6, KCB + 7} | set(range(KCB + 32, KCB + 40)) | set(range(READY_MAP, READY_MAP + 16))
    for _, _, rec in rows:
        ok(emu.read_u16(rec) == 0xFFFF and emu.read_u16(rec + 2) == 0x5555, '0x0031B0: head := 0xFFFF, tail untouched')
        want |= {rec, rec + 1}
    ok(set(emu.writes) == want, '0x0031B0 write set')
    ok(not emu.sr_log, '0x0031B0 does not touch SR')
    n += 1
    print('   0x0031B0(r4 = KCB): byte [KCB+0] := 0xFF, word [KCB+6] := 0xFFFF, [KCB+32] := [0x004080 + 4*byte[KCB+1]]')
    print('                       = 0x004058, [KCB+36] := 0xFFFF1230, map 0xFFFF12B8..C7 := 0, five head words := 0xFFFF')

    # ---- 0x003206 against a model
    head = [0xFFFF] * 5
    tail = [None] * 5
    ring = {}
    hi, nxt, mapbits = 0xFF, 0xFFFF, 0

    def reset():
        nonlocal hi, nxt, mapbits
        head[:] = [0xFFFF] * 5
        tail[:] = [None] * 5
        ring.clear()
        hi, nxt, mapbits = 0xFF, 0xFFFF, 0

    def model(ident, idx):
        nonlocal hi, nxt, mapbits
        first, last, _ = rows[idx]
        if head[idx] == 0xFFFF:                       # 003214 cmp/eq #-1,r0 ; 003216 bf (T=0 -> not empty)
            head[idx] = tail[idx] = first
            mapbits |= 1 << idx
            ring[first] = ident
            if idx > sext8(hi):                       # 003244 cmp/gt r2,r6 : T = r6 > r2 signed
                hi, nxt = idx, ident
                return 1
            return 0
        tail[idx] = first if tail[idx] == last else tail[idx] + 1   # 003258 cmp/eq r0,r3 ; 00325A bf
        ring[tail[idx]] = ident
        return 0

    print('   0x003206(r4 = KCB, r5 = id, r6 = index):   id idx -> r0  byte[KCB+0]  word[KCB+6]  map   ring of that index')
    seq = [(5, 1), (6, 1), (7, 3), (2, 3), (9, 0), (3, 0), (4, 0), (1, 4), (8, 2), (10, 4), (11, 1), (12, 1),
           (1, 1), (2, 1), (3, 1), (4, 1), (6, 2)]
    for ident, idx in seq:
        emu.sr_log.clear()
        res = emu.call(0x003206, regs={4: KCB, 5: ident, 6: idx})
        want_r0 = model(ident, idx)
        ok(res == 'return' and emu.R[0] == want_r0, f'0x003206({ident},{idx}) r0')
        ok(emu.read_u8(KCB) == hi and emu.read_u16(KCB + 6) == nxt, f'0x003206({ident},{idx}) KCB')
        ok(emu.read_u32(READY_MAP) == mapbits << 24 and
           all(emu.read_u32(READY_MAP + 4 * k) == 0 for k in (1, 2, 3)), '0x003206 map')
        for i, (first, last, rec) in enumerate(rows):
            ok(emu.read_u16(rec) == head[i], '0x003206 head word')
            if tail[i] is not None:
                ok(emu.read_u16(rec + 2) == tail[i], '0x003206 tail word')
        for slot, v in ring.items():
            ok(emu.read_u16(RING + 2 * slot) == v, '0x003206 ring slot')
        ok(not emu.sr_log and emu.R[15] == E.STACK_TOP, '0x003206 touches neither SR nor the stack')
        n += 1
        first, last, _ = rows[idx]
        print(f'      {ident:>2}  {idx}  -> {want_r0}   {hi:#04x}         {nxt:#06x}       {mapbits:#04x}  '
              f'slots {first}..{last}: head {head[idx]} tail {tail[idx]}')
    # no overflow check: index 1 has six slots (2..7) and was given seven ids; the seventh overwrote the head
    ok(ring[2] == 3 and head[1] == 2 and tail[1] == 3, 'ring of index 1 wrapped onto its head')

    # ---- 0x0034CC run to the end on the same state: it recomputes the same two fields
    emu.ram_u8(KCB, 0x00)
    emu.ram_u16(KCB + 6, 0x0000)
    emu.sr_log.clear()
    emu.set_sr(0x0B0)
    res = emu.call(0x0034CC, regs={4: KCB})
    top = max(i for i in range(5) if head[i] != 0xFFFF)
    ok(res == 'return' and emu.read_u8(KCB) == top == 4, '0x0034CC: highest ready index')
    ok(emu.read_u16(KCB + 6) == ring[head[top]] == 1, '0x0034CC: word [KCB+6] := ring[head of that index]')
    ok(emu.sr_log == [(0x0034CE, 0x000), (0x0034D2, 0x0B0), (0x003586, 0x000), (0x00358C, 0x0B0)],
       '0x0034CC opens SR to 0 for one instruction at its start and at its end')
    n += 1
    print(f'   0x0034CC on that state: byte [KCB+0] = {emu.read_u8(KCB)}, word [KCB+6] = {emu.read_u16(KCB + 6)} '
          f'(= ring[head]); SR trail {[hex(v) for _, v in emu.sr_log]}')

    # ---- 0x003274(KCB, index): take the head id off a ring; the third writer of word [KCB+6]
    ok(rom[0x00359C:0x0035A4] == bytes(0xFF ^ (1 << k) for k in range(8)), 'mask table at 0x00359C')
    emu = SREmu(rom)
    kernel_ready_init(rom, emu)
    reset()

    def leave(idx):
        nonlocal hi, nxt, mapbits
        first, last, _ = rows[idx]
        if head[idx] == tail[idx]:                    # 003288 cmp/eq r0,r2 ; 00328A bf/s (T=0 -> more than one)
            head[idx] = 0xFFFF
            mapbits &= ~(1 << idx)
            if sext8(hi) != idx:                      # 0032AE cmp/eq r3,r14 ; 0032B0 bf
                return 0
            ready = [i for i in range(5) if head[i] != 0xFFFF]      # the scan 0x0034CC
            hi, nxt = (max(ready), ring[head[max(ready)]]) if ready else (0xFF, 0xFFFF)
            return 1
        head[idx] = first if head[idx] == last else head[idx] + 1    # 0032C0 cmp/eq r0,r3 ; 0032C2 bf
        if sext8(hi) != idx:                          # 0032D2 cmp/eq r3,r14 ; 0032D4 bt
            return 0
        nxt = ring[head[idx]]
        return 1

    print('   0x003274(r4 = KCB, r5 = index):   op        -> r0  byte[KCB+0]  word[KCB+6]  map')
    script = [('in', 5, 1), ('in', 6, 1), ('in', 7, 3), ('in', 2, 3), ('in', 1, 4), ('out', 4), ('out', 1),
              ('out', 3), ('in', 9, 0), ('in', 3, 0), ('out', 0), ('in', 4, 0), ('out', 0), ('out', 3),
              ('out', 0), ('out', 1)]
    for op in script:
        if op[0] == 'in':
            res = emu.call(0x003206, regs={4: KCB, 5: op[1], 6: op[2]})
            want_r0 = model(op[1], op[2])
        else:
            res = emu.call(0x003274, regs={4: KCB, 5: op[1], 14: 0x14141414})
            want_r0 = leave(op[1])
            ok(emu.R[14] == 0x14141414, '0x003274 keeps r14')
        ok(res == 'return' and emu.R[0] == want_r0, f'{op}: r0 = {emu.R[0]}, model {want_r0}')
        ok(emu.read_u8(KCB) == hi and emu.read_u16(KCB + 6) == nxt, f'{op}: KCB')
        ok(emu.read_u32(READY_MAP) == mapbits << 24, f'{op}: map')
        for i, (_, _, rec) in enumerate(rows):
            ok(emu.read_u16(rec) == head[i], f'{op}: head word of index {i}')
        n += 1
        if op[0] == 'out':
            print(f'      leave index {op[1]}          -> {want_r0}   {hi:#04x}         {nxt:#06x}       {mapbits:#04x}')
    ok(hi == 0xFF and nxt == 0xFFFF and mapbits == 0, 'everything taken off again')

    # ---- 0x002EDC(id): the caller of 0x003206 that the 0x00317C / 0x003190 bracket is built round
    def scene(sr, nest, budget, run_b1=0):
        e = SREmu(rom)
        kernel_ready_init(rom, e)
        rec3 = TASK_TABLE + 16 * 3                   # running task: ROM record 3, priority index 2
        ok(rom[rec3 + 2] == 2 and u32(rom, rec3 + 4) == 0xFFFF11E0, 'ROM record 3')
        ok(rom[TASK_TABLE + 16 * 7 + 2] == 3 and u32(rom, TASK_TABLE + 16 * 7 + 4) == 0xFFFF1200, 'ROM record 7')
        for a in (0xFFFF11E0, 0xFFFF1200):
            e.ram_u32(a, 0)
            e.ram_u32(a + 4, 0)
        e.ram_u8(0xFFFF11E0 + 1, 2)
        e.ram_u8(0xFFFF1200 + 3, budget)
        e.call(0x003206, regs={4: KCB, 5: 3, 6: 2})  # task 3 is the one that is ready and running
        e.ram_u16(KCB + 4, 3)
        e.ram_u32(KCB + 8, nest)
        e.ram_u32(KCB + 20, 0xFFFF11E0)
        if run_b1:
            e.ram_u8(FAKE_CFG, 4)
            e.ram_u8(FAKE_CFG + 1, run_b1)
            e.ram_u32(FAKE_CFG + 4, 0xFFFF11E0)
            e.ram_u32(KCB + 24, FAKE_CFG)
        else:
            e.ram_u32(KCB + 24, rec3)
        e.sr_log.clear()
        e.writes.clear()
        e.executed.clear()
        e.set_sr(sr)
        return e

    print('   0x002EDC(r4 = 7):  SR_in  [KCB+8]  budget -> outcome')
    # (a) inside a mask section: queued, flagged, NOT switched
    for sr, nest in ((0x010, 0), (0x0E0, 0), (0x000, 1), (0x000, 0x100)):
        e = scene(sr, nest, 1)
        res = e.call(0x002EDC, regs={4: 7}, stop_at={SWITCH_OUT})
        ok(res == 'return' and e.R[0] == 0, '0x002EDC returns 0 when it may not switch')
        ok(e.read_u8(KCB) == 3 and e.read_u16(KCB + 6) == 7 and e.read_u16(KCB + 4) == 3, 'switch made due')
        ok(e.read_u8(0xFFFF1200 + 3) == 0 and e.read_u32(KCB + 8) == nest, 'budget used, counter untouched')
        ok(e.sr() == sr and e.sr_log == [(0x002EFE, 0x0B0), (0x002F54, sr)], '0x002EDC SR trail (no switch)')
        n += 1
        print(f'                       {sr:#05x}  {nest:#06x}   1      -> r0 = 0, byte [KCB+0] = 3, word [KCB+6] = 7 '
              f'!= word [KCB+4] = 3: switch DUE, not taken')
    # (b) mask 0, nothing nested: switches at once
    e = scene(0x000, 0, 1)
    res = e.call(0x002EDC, regs={4: 7}, stop_at={SWITCH_OUT})
    ok(res == SWITCH_OUT and e.R[4] == KCB and e.R[5] == 0 and e.R[6] == TASK_TABLE + 48, '0x002EDC -> 0x003440')
    ok(e.read_u32(KCB + 8) == 0x100 and e.sr() & 0xF0 == 0xB0, '0x002EDC switch path state')
    n += 1
    print('                       0x000  0x0000   1      -> jsr 0x003440 at once ([KCB+8] := 0x100)')
    # (c) running task's ROM record byte +1 != 0: no switch even at mask 0
    e = scene(0x000, 0, 1, run_b1=1)
    ok(e.call(0x002EDC, regs={4: 7}, stop_at={SWITCH_OUT}) == 'return' and e.read_u16(KCB + 6) == 7,
       '0x002EDC with record byte +1 != 0')
    n += 1
    # (d) budget byte 0: nothing queued, returns 4
    e = scene(0x010, 0, 0)
    res = e.call(0x002EDC, regs={4: 7}, stop_at={SWITCH_OUT})
    ok(res == 'return' and e.R[0] == 4 and e.read_u8(KCB) == 2 and e.read_u16(KCB + 6) == 3, '0x002EDC budget 0')
    ok(0x003206 not in e.executed and e.sr() & ~1 == 0x010, '0x002EDC budget 0 calls nothing')
    n += 1
    print('                       0x010  0x0000   0      -> r0 = 4, nothing queued (RAM record byte +3 was 0)')

    # ---- end to end: due inside the section, taken by 0x003190(0), resumed through the table routine
    e = scene(0x0E0, 0, 1)
    ok(e.call(0x002EDC, regs={4: 7}) == 'return', 'activate inside the section')
    regs = ctx_regs()
    for i, b in enumerate(ctx_fregs_bits()):
        e.FR[i] = b
    e.gbr, e.mach, e.macl = 0xFFFF7000, 0x0A0A0A0A, 0x0B0B0B0B
    e.sr_log.clear()
    regs[4] = 0                                       # what 0x00317C returned when the section was opened at mask 0
    res = e.call(0x003190, regs=regs, stop_at={0x0034B4})
    ok(res == 0x0034B4, '0x003190(0) with a switch due must reach the dispatcher hand-off 0x0034B4')
    ok(e.sr_log == [(0x0031A2, 0x000), (0x003670, 0x0B0)], 'SR trail up to the context save')
    ok(e.read_u32(KCB + 8) == 0x100 and e.read_u8(0xFFFF11E0) == 4 and e.read_u32(KCB + 12) == e.R[15],
       'voluntary save: [KCB+8], state byte 4, [KCB+12]')
    fb = ctx_fregs_bits()
    frame = [fb[15], fb[14], fb[13], fb[12], 0x0B0B0B0B, KCB, 0x0A0A0A0A, 0x000, 0xFFFF7000,
             regs[12], regs[11], regs[10], regs[9], regs[8]]
    got = [e.read_u32(e.R[15] + 4 * k) for k in range(len(frame))]
    ok(got == frame, 'voluntary save frame (r13 = entry SR and r14 = KCB are 0x003664 locals)')
    ok(e.read_u32(e.R[15] + 4 * 15) == 0x0036A0 and e.read_u32(e.R[15] + 4 * 16) == 0x000, 'saved PC / SR')
    # something else runs; then the dispatcher picks the routine for state 4: [0x004090 + 4 - byte0]
    ok(u32(rom, 0x004090 + 4 - rom[TASK_TABLE + 48]) == 0x00379C, 'resume routine for state 4')
    sp = e.read_u32(KCB + 12)
    for i in range(15):
        e.R[i] = 0x99990000 + i
    e.FR = [0x7E000000 + i for i in range(16)]
    e.gbr, e.mach, e.macl = 1, 2, 3
    e.set_sr(0x0B0)
    e.R[4] = sp
    res = cont(e, 0x00379C)
    ok(res == 'return' and e.R[0] == 0 and e.sr() == 0x000, 'resumed 0x003190(0) returns r0 = 0 with SR = 0')
    ok(all(e.R[i] == regs[i] for i in range(8, 15)) and e.R[15] == E.STACK_TOP, 'r8..r14 and r15 restored')
    ok(e.FR[12:16] == fb[12:16] and e.gbr == 0xFFFF7000 and e.mach == 0x0A0A0A0A and e.macl == 0x0B0B0B0B,
       'fr12..fr15, GBR, MACH, MACL restored')
    n += 1
    print('   end to end: 0x002EDC(7) at SR 0x0E0 -> due;  0x003190(0) -> 0x003664 -> 0x003440 (saved, state 4);')
    print('               resume through [0x004090] = 0x00379C -> back in the caller with r0 = 0, r8..r14 intact')
    return n


def cont(emu, pc, stop_at=(), max_steps=200_000):
    """Keep running an Emu from pc WITHOUT the register / stack reset that Emu.call does."""
    emu.pc = pc
    stop_at = set(stop_at)
    start = emu.steps
    while True:
        if emu.pc == E.RETURN_MAGIC:
            return 'return'
        if emu.pc in stop_at:
            return emu.pc
        if emu.steps - start >= max_steps:
            raise E.EmuError(f'step limit at pc {emu.pc:06X}')
        emu.step()


# ====================================================================================
# STATIC PART
# ====================================================================================
def sx(v, b):
    v &= (1 << b) - 1
    return v - (1 << b) if v >> (b - 1) else v


def flow(w, pc):
    """(kind, target, delayed).  kind: seq cond jump call icall ijump comp ret bad"""
    op = w >> 12
    if w in (0x000B, 0x002B):
        return 'ret', None, True
    if op == 8 and ((w >> 8) & 15) in (9, 0xB, 0xD, 0xF):
        return 'cond', pc + 4 + 2 * sx(w, 8), ((w >> 8) & 15) in (0xD, 0xF)
    if op == 0xA:
        return 'jump', pc + 4 + 2 * sx(w, 12), True
    if op == 0xB:
        return 'call', pc + 4 + 2 * sx(w, 12), True
    if op == 4 and (w & 0xFF) == 0x0B:
        return 'icall', (w >> 8) & 15, True
    if op == 4 and (w & 0xFF) == 0x2B:
        return 'ijump', (w >> 8) & 15, True
    if op == 0 and (w & 0xFF) in (0x03, 0x23):
        return 'comp', (w >> 8) & 15, True               # bsrf / braf
    bad = _INVALID.get(w)
    if bad is None:
        bad = _INVALID[w] = E.D.decode(w, 0)[0].startswith('.word')
    return ('bad' if bad else 'seq'), None, False


_INVALID = {}                                          # word -> not an SH-2E instruction (per sh2e_disasm)


def walk(rom, start, code, limit=40000):
    """Instructions reached from start along direct edges. (ok, {pc: word})."""
    vis, work, ok_ = {}, [start], True
    while work:
        pc = work.pop()
        while True:
            if pc in vis or pc in code:
                break
            if pc & 1 or not (0 <= pc < 0x100000 - 2) or len(vis) > limit:
                ok_ = False
                break
            w = u16(rom, pc)
            kind, tgt, delayed = flow(w, pc)
            if kind == 'bad':
                ok_ = False
                break
            vis[pc] = w
            if delayed:
                dw = u16(rom, pc + 2)
                if flow(dw, pc + 2)[0] != 'seq':
                    ok_ = False
                    break
                vis[pc + 2] = dw
            nxt = pc + (4 if delayed else 2)
            if kind in ('seq', 'call', 'icall'):
                pc = nxt
            elif kind == 'cond':
                work.append(tgt)
                pc = nxt
            elif kind == 'jump':
                pc = tgt
            else:
                break
    return ok_, vis


def seed_entries(rom):
    """Function entries: the census list. Only ADDRESSES are taken from it."""
    path = os.path.join(REPO, 'disassembly', 'maps', 'function_census.json')
    if os.path.exists(path):
        import json
        with open(path) as fh:
            return {int(f['entry'], 16) for f in json.load(fh)['functions']}, 'function_census.json'
    sys.path.insert(0, os.path.join(REPO, 'scripts', 'mapping'))
    import function_census as fc
    c = fc.Census(rom)
    c.lit_addrs = set()
    c.known_data = {d + o for d in fc.descriptor_addresses(rom) for o in range(0, 20, 2)}
    c.descend(c.seed_vectors())
    c.refresh_literals()
    c.seed_pointers()
    c.refresh_literals()
    c.seed_orphans()
    c.split_tail_branches()
    return set(c.entries), 'function_census.Census (rebuilt from bytes)'


def build_code(rom, seeds):
    code, entries = {}, set()
    for e in sorted(seeds):
        ok_, vis = walk(rom, e, code)
        if ok_:
            entries.add(e)
            code.update(vis)
    return code, entries


# ---- value lattice: None = unknown; ('sp', k) = r15 at entry + k (k None: somewhere in the frame);
# ---- frozenset of up to KMAX constants
KMAX = 6


def meet(a, b):
    if a is None or b is None:
        return None
    if a == b:
        return a
    if isinstance(a, tuple) or isinstance(b, tuple):
        return ('sp', None) if isinstance(a, tuple) and isinstance(b, tuple) else None
    u = a | b
    return u if len(u) <= KMAX else None


def un(f, a):
    if a is None:
        return None
    if isinstance(a, tuple):
        return ('sp', None)
    return frozenset(f(x) & M32 for x in a)


def bi(f, a, b):
    if isinstance(a, tuple) or isinstance(b, tuple):
        return ('sp', None)                          # anything computed from a frame address stays "in the frame"
    if a is None or b is None:
        return None
    r = frozenset(f(x, y) & M32 for x in a for y in b)
    return r if len(r) <= KMAX else None


def const(v):
    return frozenset((v & M32,))


class St:
    __slots__ = ('R', 'sp', 'slots')

    def __init__(self, R=None, sp=0, slots=None):
        self.R = list(R) if R is not None else [None] * 16
        self.sp = sp
        self.slots = dict(slots) if slots else {}

    def copy(self):
        return St(self.R, self.sp, self.slots)

    def key(self):
        return (tuple(self.R), self.sp, tuple(sorted(self.slots.items())))


def meet_st(a, b):
    c = St()
    c.R = [meet(x, y) for x, y in zip(a.R, b.R)]
    c.R[15] = None
    if a.sp is None or b.sp is None or a.sp != b.sp:
        c.sp = None
    else:
        c.sp = a.sp
        for k in a.slots.keys() & b.slots.keys():
            v = meet(a.slots[k], b.slots[k])
            if v is not None:
                c.slots[k] = v
    return c


def step(rom, s, w, pc):
    """Transfer function of one non-branch instruction (also used for delay slots)."""
    R = s.R
    op, n, m, d = w >> 12, (w >> 8) & 15, (w >> 4) & 15, w & 15
    lo8 = w & 0xFF

    def getr(i):
        return ('sp', s.sp) if i == 15 else R[i]

    def setr(i, v):
        if i == 15:
            if isinstance(v, tuple) and v[1] is not None:
                s.sp = v[1]
            else:
                s.sp = None
                s.slots.clear()
        else:
            R[i] = v

    def store(addr, size, val):
        if addr is None:
            return                                   # a pointer not derived from r15: assumed not to alias the frame
        if isinstance(addr, tuple):
            if addr[1] is None:
                s.slots.clear()
            elif size == 4 and addr[1] % 4 == 0:
                if val is None:
                    s.slots.pop(addr[1], None)
                else:
                    s.slots[addr[1]] = val
            else:
                s.slots.pop(addr[1] & ~3, None)

    def load(addr, size):
        if addr is None:
            return None
        if isinstance(addr, tuple):
            return s.slots.get(addr[1]) if (addr[1] is not None and size == 4) else None
        out = set()
        for a in addr:                               # a constant address inside the ROM reads the ROM
            if a + size > 0x100000:
                return None
            v = int.from_bytes(rom[a:a + size], 'big')
            out.add((sx(v, 8 * size) if size < 4 else v) & M32)
        return frozenset(out)

    def addv(a, k):
        if a is None:
            return None
        if isinstance(a, tuple):
            return ('sp', None if a[1] is None else a[1] + k)
        return frozenset((x + k) & M32 for x in a)

    def one(v):
        return v is not None and not isinstance(v, tuple) and len(v) == 1

    def add2(a, b):
        if isinstance(a, tuple) and one(b):
            return addv(a, sx(next(iter(b)), 32))
        if isinstance(b, tuple) and one(a):
            return addv(b, sx(next(iter(a)), 32))
        if isinstance(a, tuple) or isinstance(b, tuple):
            return ('sp', None)                      # a frame address plus something unknown: anywhere in the frame
        return bi(lambda x, y: x + y, a, b)

    if op == 0xE:
        setr(n, const(sx(lo8, 8)))
    elif op == 0x9:
        setr(n, const(sx(u16(rom, pc + 4 + lo8 * 2), 16)))
    elif op == 0xD:
        setr(n, const(u32(rom, ((pc + 4) & ~3) + lo8 * 4)))
    elif op == 0x7:
        setr(n, addv(getr(n), sx(lo8, 8)))
    elif op == 0x6:
        if d == 3:
            setr(n, getr(m))
        elif d == 0xC:
            setr(n, un(lambda x: x & 0xFF, getr(m)))
        elif d == 0xD:
            setr(n, un(lambda x: x & 0xFFFF, getr(m)))
        elif d == 0xE:
            setr(n, un(lambda x: sx(x, 8), getr(m)))
        elif d == 0xF:
            setr(n, un(lambda x: sx(x, 16), getr(m)))
        elif d == 7:
            setr(n, un(lambda x: ~x, getr(m)))
        elif d == 0xB:
            setr(n, un(lambda x: -x, getr(m)))
        elif d == 8:
            setr(n, un(lambda x: (x & 0xFFFF0000) | ((x & 0xFF) << 8) | ((x >> 8) & 0xFF), getr(m)))
        elif d == 9:
            setr(n, un(lambda x: ((x & 0xFFFF) << 16) | (x >> 16), getr(m)))
        elif d in (0, 1, 2):
            setr(n, load(getr(m), 1 << d))
        elif d in (4, 5, 6):
            v = load(getr(m), 1 << (d - 4))
            setr(m, addv(getr(m), 1 << (d - 4)))
            setr(n, v)
        else:
            setr(n, None)
    elif op == 0x2:
        if d in (0, 1, 2):
            store(getr(n), 1 << d, getr(m))
        elif d in (4, 5, 6):
            v = getr(m)
            setr(n, addv(getr(n), -(1 << (d - 4))))
            store(getr(n), 1 << (d - 4), v)
        elif d == 9:
            setr(n, bi(lambda x, y: x & y, getr(n), getr(m)))
        elif d == 0xA:
            setr(n, bi(lambda x, y: x ^ y, getr(n), getr(m)))
        elif d == 0xB:
            setr(n, bi(lambda x, y: x | y, getr(n), getr(m)))
        elif d == 0xD:
            setr(n, None)
    elif op == 0x1:
        store(addv(getr(n), d * 4), 4, getr(m))
    elif op == 0x5:
        setr(n, load(addv(getr(m), d * 4), 4))
    elif op == 0x8:
        if n == 0:
            store(addv(getr(m), d), 1, R[0])
        elif n == 1:
            store(addv(getr(m), d * 2), 2, R[0])
        elif n == 4:
            R[0] = load(addv(getr(m), d), 1)
        elif n == 5:
            R[0] = load(addv(getr(m), d * 2), 2)
    elif op == 0x3:
        if d == 0xC:
            setr(n, add2(getr(n), getr(m)))
        elif d == 8:
            a, b = getr(n), getr(m)
            if isinstance(a, tuple) and one(b):
                setr(n, addv(a, -sx(next(iter(b)), 32)))
            else:
                setr(n, bi(lambda x, y: x - y, a, b))
        elif d not in (0, 2, 3, 5, 6, 7, 0xD):
            setr(n, None)
    elif op == 0x4:
        if lo8 in (0x0B, 0x2B, 0x0E, 0x1E, 0x2E, 0x0A, 0x1A, 0x2A, 0x5A, 0x6A, 0x11, 0x15, 0x1B):
            pass
        elif lo8 in (0x00, 0x20):
            setr(n, un(lambda x: x << 1, getr(n)))
        elif lo8 == 0x08:
            setr(n, un(lambda x: x << 2, getr(n)))
        elif lo8 == 0x18:
            setr(n, un(lambda x: x << 8, getr(n)))
        elif lo8 == 0x28:
            setr(n, un(lambda x: x << 16, getr(n)))
        elif lo8 == 0x01:
            setr(n, un(lambda x: x >> 1, getr(n)))
        elif lo8 == 0x09:
            setr(n, un(lambda x: x >> 2, getr(n)))
        elif lo8 == 0x19:
            setr(n, un(lambda x: x >> 8, getr(n)))
        elif lo8 == 0x29:
            setr(n, un(lambda x: x >> 16, getr(n)))
        elif (lo8 & 0x0F) in (2, 3):                 # sts.l / stc.l X,@-Rn
            setr(n, addv(getr(n), -4))
            store(getr(n), 4, None)
        elif (lo8 & 0x0F) in (6, 7):                 # lds.l / ldc.l @Rn+,X
            setr(n, addv(getr(n), 4))
        elif (lo8 & 0x0F) == 0x0F:                   # mac.w @Rm+,@Rn+
            setr(n, None)
            setr(m, None)
        else:
            setr(n, None)
    elif op == 0x0:
        if d in (4, 5, 6):
            store(add2(getr(n), R[0]), 1 << (d - 4), getr(m))
        elif d in (0xC, 0xD, 0xE):
            setr(n, load(add2(getr(m), R[0]), 1 << (d - 0xC)))
        elif d in (2, 0xA) or (d == 9 and m == 2):
            setr(n, None)                            # stc / sts / movt
        elif d == 0xF:
            setr(n, None)
            setr(m, None)
    elif op == 0xC:
        if n in (4, 5, 6):
            R[0] = None
        elif n == 7:
            R[0] = const(((pc + 4) & ~3) + lo8 * 4)
        elif n == 9:
            R[0] = un(lambda x: x & lo8, R[0])
        elif n == 0xA:
            R[0] = un(lambda x: x ^ lo8, R[0])
        elif n == 0xB:
            R[0] = un(lambda x: x | lo8, R[0])
    elif op == 0xF:
        if d == 9:                                   # fmov.s @Rm+,FRn
            setr(m, addv(getr(m), 4))
        elif d == 0xB:                               # fmov.s FRm,@-Rn
            setr(n, addv(getr(n), -4))
            store(getr(n), 4, None)
        elif d == 0xA:                               # fmov.s FRm,@Rn
            store(getr(n), 4, None)
        elif d == 7:                                 # fmov.s FRm,@(R0,Rn)
            store(add2(getr(n), R[0]), 4, None)
    return s


ONE_LONG_AT_R4 = frozenset((0x0BE81C,))             # 0BE824: 2402 mov.l r0,@r4 is its only store
NO_FRAME_WRITE = frozenset((0x00317C, 0x003190, 0x0BE82C, 0x00E6E4))


def after_call(s, tgt, keeps=None):
    """State after a call returns. r0-r7 die. A stack address handed over in r4-r7 lets the callee
    write the frame from there up, except for the callees whose bytes say otherwise.
    keeps: None = every callee keeps r8-r14 (the convention); a set = only those callees do."""
    one = tgt is not None and not isinstance(tgt, tuple) and len(tgt) == 1
    t = next(iter(tgt)) if one else None
    if t in ONE_LONG_AT_R4:
        v = s.R[4]
        if isinstance(v, tuple):
            if v[1] is None:
                s.slots.clear()
            else:
                s.slots.pop(v[1], None)
    elif not (t in NO_FRAME_WRITE and not isinstance(s.R[4], tuple)):
        for i in range(4, 8):
            v = s.R[i]
            if isinstance(v, tuple):
                if v[1] is None:
                    s.slots.clear()
                else:
                    for k in [k for k in s.slots if k >= v[1]]:
                        del s.slots[k]
    for i in range(8):
        s.R[i] = None
    if keeps is not None:
        known = tgt is not None and not isinstance(tgt, tuple)
        if not (known and all(x in keeps for x in tgt)):
            for i in range(8, 15):
                s.R[i] = None
    return s


def dataflow(rom, code, entries, keeps=None):
    """state[pc] = what is known just before the instruction at pc, for every instruction that is
    not only a delay slot. Function entries, and anything no direct edge reaches, start unknown."""
    state, work = {}, []

    def push(pc, s):
        if pc not in code:
            return
        old = state.get(pc)
        if old is None:
            state[pc] = s.copy()
            work.append(pc)
        else:
            new = meet_st(old, s)
            if new.key() != old.key():
                state[pc] = new
                work.append(pc)

    for e in entries:
        push(e, St())
    pending = sorted(code)
    idx = 0
    while True:
        while work:
            pc = work.pop()
            s = state[pc].copy()
            w = code[pc]
            kind, tgt, delayed = flow(w, pc)
            if kind == 'seq':
                push(pc + 2, step(rom, s, w, pc))
                continue
            ctgt = s.R[tgt] if kind == 'icall' else (const(tgt) if kind == 'call' else None)
            if delayed:
                s = step(rom, s, code[pc + 2], pc + 2)
            nxt = pc + (4 if delayed else 2)
            if kind == 'cond':
                push(tgt, s)
                push(nxt, s)
            elif kind == 'jump':
                push(tgt, s)
            elif kind in ('call', 'icall'):
                push(nxt, after_call(s, ctgt, keeps))
        while idx < len(pending) and (pending[idx] in state or is_slot(code, pending[idx])):
            idx += 1
        if idx >= len(pending):
            return state
        push(pending[idx], St())


def is_slot(code, a):
    return a - 2 in code and flow(code[a - 2], a - 2)[2]


def state_at(rom, code, state, pc):
    """State before the instruction at pc, delay slots included (a branch changes no register)."""
    if not is_slot(code, pc):
        return state[pc]
    return meet_st(state[pc - 2], state[pc]) if pc in state else state[pc - 2]


def at_call(rom, code, state, pc):
    """(value of the register a jsr/jmp goes through, state when control transfers)."""
    s = state[pc].copy()
    w = code[pc]
    tgt = s.R[(w >> 8) & 15] if (w >> 12) == 4 else None
    return tgt, step(rom, s, code[pc + 2], pc + 2)


def sites_of(rom, code, state, target):
    """Every transfer to target in the code map: [(pc, kind)], kind in jsr jmp bsr bra bcc."""
    out = []
    for pc in sorted(code):
        w = code[pc]
        kind, tgt, _ = flow(w, pc)
        if kind in ('icall', 'ijump') and pc in state:
            if state[pc].R[tgt] == frozenset((target,)):
                out.append((pc, 'jsr' if kind == 'icall' else 'jmp'))
        elif kind in ('call', 'jump', 'cond') and tgt == target:
            out.append((pc, {'call': 'bsr', 'jump': 'bra', 'cond': 'bcc'}[kind]))
    return out


S317_NOT_IN_FIRST_CENSUS = [0x0A1FB8, 0x0A1FF6, 0x0A201E, 0x0A205C, 0x0A2084, 0x0A20C2, 0x0A20F2, 0x0A2130,
                            0x0A2166, 0x0A21A4, 0x0A21DA, 0x0A5480, 0x0A54C0, 0x0A54F0, 0x0A5530, 0x0A5558,
                            0x0A5598, 0x0A55C8, 0x0A5608, 0x0A563C, 0x0A567C, 0x0A56B0]
S319_NOT_IN_FIRST_CENSUS = [0x0A20B6, 0x0A2124, 0x0A2198, 0x0A21D2, 0x0A220C,           # jsr @r13
                            0x0A54B4, 0x0A5524, 0x0A558C, 0x0A55FC, 0x0A5670, 0x0A56E4]  # through @(40,r15)
SE6_NOT_IN_FIRST_CENSUS = [0x059064, 0x05A872]                                           # through a stack slot
B81_NOT_IN_FIRST_CENSUS = [0x00944C, 0x009466, 0x0094C4, 0x0094DE, 0x00952C, 0x00955A]
B82_NOT_IN_FIRST_CENSUS = [0x00EC42, 0x00EC86]
S317_R4_FROM_BTS_SLOT = [0x0A1F24, 0x0A1FB8, 0x0A201E, 0x0A2084, 0x0A20F2, 0x0A2166, 0x0A21DA,
                         0x0A53EA, 0x0A5480, 0x0A54F0, 0x0A5558, 0x0A55C8, 0x0A563C, 0x0A56B0]
SE6_OUTSIDE_A_SECTION = [0x007040, 0x007200, 0x007220, 0x007228, 0x007230, 0x00728A, 0x007358,
                         0x00988E, 0x009904, 0x00990C, 0x009914, 0x00991C, 0x00A7C2]
E6_ADDRESSES = {0xFFFFF42E: 4, 0xFFFFF462: 4, 0xFFFFF482: 19, 0xFFFFF630: 4, 0xFFFFF66C: 11, 0xFFFFF6EA: 6,
                0xFFFFF738: 4, 0xFFFFF74E: 16, 0xFFFFF754: 32, 0xFFFFF75C: 5, 0xFFFFF75E: 12, 0xFFFFF76C: 19}
LOG_SITES = {                  # call site of 0x010800: (kind, code(s) in r4, goes on to 0x00FBA4?)
    0x00B02A: ('jsr', {0x5000}, False), 0x00B2D8: ('jsr', {0x5000}, False),
    0x00B812: ('jsr', {0x5100}, True), 0x00B82E: ('jsr', {0x5100}, True),
    0x00B960: ('jsr', {0x6000}, True), 0x00B97E: ('jsr', {0x6000}, True),
    0x00B9B4: ('jsr', {0x5000}, False), 0x00B9F8: ('jsr', {0x5000}, False),
    0x00BA20: ('jsr', {0x5000}, False), 0x00BA56: ('jsr', {0x5000}, False),
    0x00E788: ('jsr', {0x4000}, True), 0x00E7B0: ('jsr', None, True),
    0x00E81C: ('jsr', {0x8000}, False), 0x01009A: ('jsr', {0x7100}, False),
    0x01027E: ('jmp', {0x7100}, False), 0x0106B2: ('jmp', {0x7000, 0x7010}, False),
    0x0106DC: ('jmp', {0x7100, 0x7110}, False), 0x0107E2: ('bsr', {0x2000}, True),
    0x010A02: ('bsr', {0x2000}, True), 0x010AA0: ('bra', {0x9000}, False),
    0x010B1A: ('bsr', {0x2100, 0x2200, 0x2300}, True),
}
HALT = 0x00FBA4


def literal_readers(code):
    """{literal address: [pc of the PC-relative load]} for mov.l and mov.w, and the set of pool words."""
    longs, words, pool = {}, {}, set()
    for pc, w in code.items():
        if (w >> 12) == 0xD:
            a = ((pc + 4) & ~3) + (w & 0xFF) * 4
            longs.setdefault(a, []).append(pc)
            pool.update((a, a + 2))
        elif (w >> 12) == 0x9:
            a = pc + 4 + (w & 0xFF) * 2
            words.setdefault(a, []).append(pc)
            pool.add(a)
    return longs, words, pool


def test_sites(rom):
    import bisect
    from collections import Counter
    print('== static call-site census: code map + whole-image dataflow (see the module docstring) ==')
    seeds, src = seed_entries(rom)
    for a in list(range(0, 0x38, 4)) + list(range(VBR, 0x100000, 4)):
        v = u32(rom, a)
        if 0x40 <= v < 0x100000 and not v & 1:
            seeds.add(v)
    code, entries = build_code(rom, seeds)
    ents = sorted(entries)

    def owner(pc):
        return ents[bisect.bisect_right(ents, pc) - 1]

    state = dataflow(rom, code, entries)
    longs, words, pool = literal_readers(code)
    print(f'   entry list from {src}: {len(entries)} entries walk cleanly, {len(seeds) - len(entries)} rejected;')
    print(f'   code map {len(code)} instructions')
    ok(len(code) > 280000, 'code map size')

    # the root cause of the first census's undercount, in two words of the ROM
    ok(u32(rom, 0x0A1FA8) == 0x000BE9A0 and u16(rom, 0x0A1FAA) == 0xE9A0 and 0x0A1FAA not in code and
       0x0A1FAA in pool and E.D.decode(0xE9A0, 0x0A1FAA)[0] == 'mov #-96,r9',
       'pool word 0x0A1FAA looks like a write of r9 and is not an instruction')

    T = {'317C': 0x00317C, '3190': 0x003190, 'E6E4': 0x00E6E4, '2B8C': 0x002B8C, 'BE81C': 0x0BE81C,
         'BE82C': 0x0BE82C}
    S = {k: sites_of(rom, code, state, v) for k, v in T.items()}
    kinds = {k: dict(Counter(kd for _, kd in v)) for k, v in S.items()}
    ok(kinds['317C'] == {'jsr': 404}, f"0x00317C sites {kinds['317C']}")
    ok(kinds['3190'] == {'jsr': 270, 'jmp': 112}, f"0x003190 sites {kinds['3190']}")
    ok(kinds['E6E4'] == {'jsr': 136}, f"0x00E6E4 sites {kinds['E6E4']}")
    ok(kinds['2B8C'] == {'jsr': 118} and [a for a, _ in S['2B8C']] == [0x002082 + 24 * i for i in range(118)],
       '0x002B8C sites')
    ok(kinds['BE81C'] == {'jsr': 355} and kinds['BE82C'] == {'jsr': 348}, '0x0BE81C / 0x0BE82C sites')
    A = {k: [a for a, _ in v] for k, v in S.items()}
    for name, missed in (('317C', S317_NOT_IN_FIRST_CENSUS), ('3190', S319_NOT_IN_FIRST_CENSUS),
                         ('E6E4', SE6_NOT_IN_FIRST_CENSUS), ('BE81C', B81_NOT_IN_FIRST_CENSUS),
                         ('BE82C', B82_NOT_IN_FIRST_CENSUS)):
        ok(set(missed) <= set(A[name]), f'sites the first census missed must be found ({name})')
    ok(len(A['317C']) - len(S317_NOT_IN_FIRST_CENSUS) == 382 and len(A['3190']) - len(S319_NOT_IN_FIRST_CENSUS) == 371
       and len(A['E6E4']) - 2 == 134 and len(A['BE81C']) - 6 == 349 and len(A['BE82C']) - 2 == 346,
       'old counts + missed sites = new counts')
    print(f"   0x00317C: {len(A['317C'])} sites (all jsr)        0x003190: {len(A['3190'])} sites (270 jsr + 112 jmp tail calls)")
    print(f"   0x00E6E4: {len(A['E6E4'])} sites (all jsr)        0x002B8C: {len(A['2B8C'])} sites (one per stub, at stub+6)")
    print(f"   0x0BE81C: {len(A['BE81C'])} sites (all jsr)        0x0BE82C: {len(A['BE82C'])} sites (all jsr)")

    # no direct branch (bsr / bra / bt / bf) anywhere in the code map goes to any of these
    for t in (0x00317C, 0x003190, 0x00E6E4, 0x002B8C, 0x0BE81C, 0x0BE82C, 0x003664, 0x002BD4, 0x0035FC,
              0x002D10, 0x002DE4):
        direct = [pc for pc, w in code.items() if flow(w, pc)[0] in ('call', 'jump', 'cond') and flow(w, pc)[1] == t]
        ok(not direct, f'direct branch to {t:#x} at {direct}')

    # functions (census entries as boundaries)
    f317 = {owner(a) for a in A['317C']}
    f319 = {owner(a) for a in A['3190']}
    fe6 = {owner(a) for a in A['E6E4']}
    ok(len(f317) == 239 and f317 == f319, 'the same 239 census functions call 0x00317C and 0x003190')
    ok(len(fe6) == 65, 'census functions that call 0x00E6E4')
    ok(0x008AC4 in f317 and u16(rom, 0x008AC8) == 0xD339 and u32(rom, 0x008BB0) == 0x0000317C and
       u16(rom, 0x008AD0) == 0x430B, 'function 0x008AC4 calls 0x00317C (008AC8: D339 / 008AD0: 430B)')
    print(f'   census functions calling 0x00317C: {len(f317)}; calling 0x003190: {len(f319)}; same set: {f317 == f319}; '
          f'calling 0x00E6E4: {len(fe6)}')

    # arguments
    lv = Counter()
    for a in A['317C']:
        v = at_call(rom, code, state, a)[1].R[4]
        ok(v is not None and not isinstance(v, tuple) and len(v) == 1, f'r4 at {a:#x} is one constant on every path')
        lv[next(iter(v))] += 1
    ok(dict(lv) == {0x10: 365, 0x90: 25, 0xE0: 8, 0xB0: 6}, f'r4 passed to 0x00317C: {dict(lv)}')
    print('   r4 passed to 0x00317C:', ', '.join(f'{k:#04x} x{n}' for k, n in sorted(lv.items())), ' (none unresolved)')
    slot_only = []
    for a in A['317C']:
        preds = [pc for pc, w in code.items() if (w >> 8) in (0x8D, 0x8F) and pc + 4 + 2 * sx(w, 8) == a]
        p = a - 2
        falls = p in code and not (is_slot(code, p) and flow(code[p - 2], p - 2)[0] in ('jump', 'ret', 'ijump'))
        if preds and not falls:
            ok(all(code[pc + 2] == 0xE410 for pc in preds), f'delay slot feeding {a:#x} is mov #16,r4')
            slot_only.append(a)
    ok(slot_only == S317_R4_FROM_BTS_SLOT, '0x00317C sites reached only through a bt/s whose slot is mov #16,r4')

    ad = Counter()
    for a in A['E6E4']:
        v = at_call(rom, code, state, a)[1].R[4]
        ok(v is not None and not isinstance(v, tuple) and len(v) == 1, f'0x00E6E4 r4 at {a:#x}')
        ad[next(iter(v))] += 1
    ok(dict(ad) == E6_ADDRESSES, '0x00E6E4 r4 distribution')
    ok(all(0xFFFFF400 <= v <= 0xFFFFF7FF for v in ad), 'every 0x00E6E4 target is in 0xFFFFF400..0xFFFFF7FF')
    for a, want in ((0x059064, 0xFFFFF75E), (0x05A872, 0xFFFFF754)):
        ok(at_call(rom, code, state, a)[1].R[4] == const(want), f'r4 at the stack-slot site {a:#x}')
    ok(at_call(rom, code, state, 0x059064)[1].R[5] == const(0x20) and
       at_call(rom, code, state, 0x05A872)[1].R[5] == const(0x40), 'r5 at the two stack-slot sites')
    # 8 of the 32 uses of 0xFFFFF754 take r4 from the INDEXED slot @(r0,r15), r0 = 64, of function 0x05AEB8:
    # 05AEEA: 94C1 mov.w (=0xF754) / 05AEEC: E040 mov #64,r0 / 05AEEE: 0F46 mov.l r4,@(r0,r15), each site
    # reloading with 04FE mov.l @(r0,r15),r4 (at 0x05B082 in the delay slot, r0 = r5 = 64 from 05B080: 6053).
    # The only callee handed an address in the frame is 0x0BE81C (r15+0..60, below the slot); 0x009DEE gets
    # 0..3, 0x006BC4 / 0x006BF0 get 17, 0x00C70C / 0x004AB2 get 0, 0x0080C6 / 0x005C2E only fr4 = fr14.
    # So nothing else can write the slot (the dataflow's own rule; these lines anchor it in bytes).
    ok(u16(rom, 0x05AEEA) == 0x94C1 and u16(rom, 0x05B070) == 0xF754 and u16(rom, 0x05AEEC) == 0xE040 and
       u16(rom, 0x05AEEE) == 0x0F46, '0x05AEB8 parks 0xFFFFF754 at @(64,r15)')
    idx_sites = [0x05AF20, 0x05AF38, 0x05AF4E, 0x05AF64, 0x05AFFE, 0x05B04A, 0x05B060, 0x05B082]
    def reloads(a):         # 04FE within the two instructions before the call, or in its delay slot
        return 0x04FE in (u16(rom, a - 4), u16(rom, a - 2), u16(rom, a + 2))
    for a in idx_sites:
        ok(a in A['E6E4'] and owner(a) == 0x05AEB8 and reloads(a) and
           at_call(rom, code, state, a)[1].R[4] == const(0xFFFFF754), f'indexed-slot site {a:#x}')
    ok(u16(rom, 0x05B080) == 0x6053 and u16(rom, 0x05B07E) == 0xE540 and u16(rom, 0x05B084) == 0x04FE,
       'r0 = r5 = 64 before 0x05B082, reload in its delay slot')
    in_fn = [a for a in A['E6E4'] if owner(a) == 0x05AEB8]
    ok(len(in_fn) == 15 and [a for a in in_fn if reloads(a)] == idx_sites,
       '0x05AEB8: 15 sites of 0x00E6E4, of which exactly these 8 reload r4 from the indexed slot')
    print('   r4 passed to 0x00E6E4 (address of the 16-bit word), none unresolved:')
    print('      ' + '  '.join(f'{k:#010x} x{n}' for k, n in sorted(ad.items())[:6]))
    print('      ' + '  '.join(f'{k:#010x} x{n}' for k, n in sorted(ad.items())[6:]))
    ok(all(at_call(rom, code, state, a)[1].R[5] == const(0xE0) for a in A['BE81C']),
       'every 0x0BE81C site passes r5 = 0xE0')
    print('   r5 passed to 0x0BE81C: 0xe0 at all 355 sites')

    # ---- completeness
    n_long = {}
    for name, t in T.items():
        lits = [a for a in range(0, 0x100000, 4) if u32(rom, a) == t]
        ok(all(a in longs for a in lits), f'a long equal to {t:#x} is read by no code')
        ok(not [a for a in range(2, 0x100000 - 4, 4) if u32(rom, a) == t], f'{t:#x} at an odd word boundary')
        ok(not [a for a in words if t < 0x8000 and u16(rom, a) == t], f'16-bit literal load of {t:#x}')
        n_long[name] = len(lits)
        fl = {owner(pc) for a in lits for pc in longs[a]}
        ok(fl == {owner(a) for a in A[name]}, f'every function that loads {t:#x} has a counted site and vice versa')
    ok(n_long == {'317C': 176, '3190': 176, 'E6E4': 50, '2B8C': 118, 'BE81C': 127, 'BE82C': 128}, f'{n_long}')
    stray = []
    for a in range(0x40, 0xC0000, 2):
        w = u16(rom, a)
        if a not in code and (w >> 12) == 0xD:
            x = ((a + 4) & ~3) + (w & 0xFF) * 4
            if x + 4 <= 0x100000 and u32(rom, x) in T.values():
                stray.append(a)
    ok(len(stray) == 9 and all(a in pool for a in stray),
       'words outside the code map that decode as a load of a target literal are all pool words')
    stores = []
    for pc in sorted(code):
        w = code[pc]
        op, n, m, d = w >> 12, (w >> 8) & 15, (w >> 4) & 15, w & 15
        if (op == 2 and d in (2, 6)) or op == 1 or (op == 0 and d == 6):
            v = state_at(rom, code, state, pc).R[m] if m != 15 else None
            if v is not None and not isinstance(v, tuple) and len(v) == 1 and next(iter(v)) in T.values():
                stores.append((pc, n, next(iter(v))))
    ok(stores == [(0x059028, 15, 0xE6E4), (0x05903A, 15, 0xE6E4), (0x05A836, 15, 0xE6E4), (0x05A846, 15, 0xE6E4),
                  (0x0A53A0, 15, 0x3190), (0x0A5426, 15, 0x3190)],
       'a target address is stored to memory only in these six r15-relative slots')
    unres = Counter()
    order = sorted(code)
    for pc in order:
        w = code[pc]
        kind, reg, _ = flow(w, pc)
        if kind in ('icall', 'ijump') and pc in state and \
                (state[pc].R[reg] is None or isinstance(state[pc].R[reg], tuple)):
            i = bisect.bisect_left(order, pc) - 1
            how = 'no write found'
            while i >= 0 and pc - order[i] < 6000:
                a = order[i]
                probe = St([frozenset((0x77000000 + k,)) for k in range(16)])
                before = probe.R[reg]
                step(rom, probe, code[a], a)
                if probe.R[reg] != before:
                    x = code[a]
                    if (x >> 12) == 0xD:
                        v = u32(rom, ((a + 4) & ~3) + (x & 0xFF) * 4)
                        ok(v not in T.values(), f'unresolved transfer at {pc:#x} takes target literal {v:#x}')
                        how = 'literal (not a target)'
                    elif (x >> 12) in (5, 6, 0):
                        how = 'loaded from memory'
                    else:
                        how = 'computed'
                    break
                i -= 1
            unres[how] += 1
    # 53 since the item-106 census: the 54th was the jsr @r1 (r1 = 0xFFFFFFD2) inside
    # 0x011954, a data seed the corrected census rejects (data_signature).
    ok(dict(unres) == {'loaded from memory': 74, 'literal (not a target)': 53, 'computed': 3, 'no write found': 1},
       f'unresolved indirect transfers: {dict(unres)}')
    print(f"   completeness: {n_long['317C']} / {n_long['3190']} / {n_long['E6E4']} / {n_long['BE81C']} / {n_long['BE82C']} "
          'pool longs, each read by code that has a counted site;')
    print('      no load of a target literal outside the code map (9 look-alikes are pool words); a target address is')
    print('      stored only in six stack slots the dataflow follows; of 132 indirect transfers left unresolved,')
    print(f'      {dict(unres)} -- none can be one of the targets')

    # ---- how far the counts lean on "a callee keeps r8-r14"
    test_convention(rom, code, entries, state, A, owner)

    # ---- 0x00E6E4 inside 0x0BE81C ... 0x0BE82C
    calls = [pc for pc in order if flow(code[pc], pc)[0] in ('call', 'icall')]
    b1, b2 = set(A['BE81C']), set(A['BE82C'])
    nearest = 0
    for a in A['E6E4']:
        i = bisect.bisect_left(calls, a)
        nearest += (i > 0 and i + 1 < len(calls) and calls[i - 1] in b1 and calls[i + 1] in b2)
    ok(nearest == 74, f'nearest-call test: {nearest}')
    depth, work = {}, []

    def dpush(pc, ds):
        if pc in code and not ds <= depth.get(pc, frozenset()):
            depth[pc] = depth.get(pc, frozenset()) | ds
            ok(len(depth[pc]) < 8, 'depth sets stay small')
            work.append(pc)

    for e in entries:
        dpush(e, frozenset((0,)))
    while work:
        pc = work.pop()
        ds = depth[pc]
        kind, tgt, delayed = flow(code[pc], pc)
        nxt = pc + (4 if delayed else 2)
        if kind == 'seq':
            dpush(pc + 2, ds)
        elif kind == 'cond':
            dpush(tgt, ds)
            dpush(nxt, ds)
        elif kind == 'jump':
            if tgt not in entries:
                dpush(tgt, ds)
        elif kind in ('call', 'icall'):
            dpush(nxt, frozenset(x + (pc in b1) - (pc in b2) for x in ds))
    dd = Counter(tuple(sorted(depth[a])) for a in A['E6E4'])
    ok(dict(dd) == {(1,): 117, (2,): 6, (0,): 13}, f'section depth at the 0x00E6E4 sites: {dict(dd)}')
    ok([a for a in A['E6E4'] if depth[a] == frozenset((0,))] == SE6_OUTSIDE_A_SECTION, 'sites outside a section')
    ok(depth[0x005538] == frozenset((1,)) and 0x005502 in b1 and 0x00550C in b1 and 0x005518 in b2 and
       0x00555E in b2, '0x005538 lies inside the outer section 0x005502 .. 0x00555E')
    print(f'   0x00E6E4 sites inside a 0x0BE81C section of their own function, on every path: 123 of {len(A["E6E4"])}')
    print('      (117 at depth 1, 6 at depth 2); 13 are at depth 0. "Nearest call before is 0x0BE81C and nearest')
    print(f'      call after is 0x0BE82C" holds for only {nearest}, because sections nest (e.g. 0x005538).')

    # ---- 0x010800 is called from 21 places: after 9 the caller goes on to the endless loop at 0x00FBA4,
    #      after 8 it carries on and cannot reach it, 4 are tail transfers (asserted below)
    L = sites_of(rom, code, state, 0x010800)
    ok(len(L) == 21 and {a: k for a, k in L} == {a: v[0] for a, v in LOG_SITES.items()}, '0x010800 sites')
    for a, (kind, codes, halts) in LOG_SITES.items():
        v = at_call(rom, code, state, a)[1].R[4]
        ok((v is None and codes is None) or v == frozenset(codes or ()), f'code passed to 0x010800 at {a:#x}')
        # everything the function can still do after the call returns (direct edges, calls stepped over)
        seen, todo, goes = set(), ([a + 4] if kind in ('jsr', 'bsr') else []), False
        while todo:
            pc = todo.pop()
            if pc in seen or pc not in code:
                continue
            seen.add(pc)
            k, tgt, delayed = flow(code[pc], pc)
            if k in ('icall', 'ijump') and state[pc].R[tgt] == const(HALT):
                goes = True
            if k == 'cond':
                todo += [tgt, pc + (4 if delayed else 2)]
            elif k == 'jump':
                todo.append(tgt)
            elif k in ('seq', 'call', 'icall'):
                todo.append(pc + (4 if delayed else 2))
        ok(goes == halts, f'what follows the 0x010800 call at {a:#x}')
    ok(u16(rom, 0x00FBB6) == 0xAFFE, '0x00FBA4 ends in bra-to-self at 0x00FBB6')
    ok(sites_of(rom, code, state, 0x010B2A) == [(0x010816, 'bsr')] and
       not [a for a in range(0, 0x100000 - 2, 2) if u32(rom, a) == 0x00010B2A], '0x010B2A is entered only from 0x010816')
    ok(sites_of(rom, code, state, 0x003274) == [(0x0035CC, 'jsr')], '0x003274 has one reachable call site')
    ok(Counter(k for k, _, _ in LOG_SITES.values()) == {'jsr': 14, 'jmp': 3, 'bsr': 3, 'bra': 1} and
       sum(h for _, _, h in LOG_SITES.values()) == 9, '0x010800 site classes')
    print('   0x010800: 21 sites. After 9 of them the same function transfers to 0x00FBA4 (0x00E788, 0x00E7B0,')
    print('      0x00B812, 0x00B82E, 0x00B960, 0x00B97E, 0x0107E2, 0x010A02, 0x010B1A). After 8 it carries on and')
    print('      cannot reach 0x00FBA4 (0x00B02A, 0x00B2D8, 0x00B9B4, 0x00B9F8, 0x00BA20, 0x00BA56: code 0x5000;')
    print('      0x00E81C: 0x8000; 0x01009A: 0x7100). 4 are tail transfers (0x01027E, 0x0106B2, 0x0106DC, 0x010AA0).')

    # ---- single-reference facts the trace leans on
    def longs_equal(v):
        return [a for a in range(0, 0x100000, 4) if u32(rom, a) == v]

    def anywhere(v):
        return [a for a in range(0, 0x100000 - 2, 2) if u32(rom, a) == v]

    ok(longs_equal(0x00003664) == [0x0031AC], '0x3664 is referenced by one literal')
    ok(longs_equal(0x00002BD4) == [0x002BD0], '0x2BD4 is referenced by one literal')
    ok(longs_equal(0x000035FC) == [0x002CE8, 0x0034C8], '0x35FC is referenced by two literals')
    for t in (0x002D10, 0x002DE4):
        ok(not anywhere(t) and t not in code and not [a for a in words if u16(rom, a) == t],
           f'{t:#x}: no long, no 16-bit literal load, not in the code map')
    blk = [a for a in range(0, 0xC0000, 4) if 0xFFFF2060 <= u32(rom, a) <= 0xFFFF20AB]
    ok(blk == [0x10838, 0x10844, 0x10848, 0x10854, 0x10978, 0x10BA8, 0x10BB0, 0x10C6C, 0x10C74, 0x10C7C,
               0x10C80], 'literals that point into 0xFFFF2060..0xFFFF20AB')
    # stores of any form whose destination the dataflow resolves into the KCB, and the opcode shapes
    # `mov.l Rm,@(8,Rn)` / `mov.l Rm,@(16,Rn)` in the kernel range whatever their base
    def dests(pc):
        w = code[pc]
        op, n, m, d = w >> 12, (w >> 8) & 15, (w >> 4) & 15, w & 15
        R = state_at(rom, code, state, pc).R
        if op == 2 and d in (0, 1, 2):
            base, off = n, 0
        elif op == 2 and d in (4, 5, 6):
            base, off = n, -(1 << (d - 4))
        elif op == 1:
            base, off = n, 4 * d
        elif op == 8 and n in (0, 1):
            base, off = m, d * (n + 1)
        else:
            return ()
        v = R[base] if base != 15 else None
        if v is None or isinstance(v, tuple):
            return ()
        return [(x + off) & M32 for x in v]

    lock = [pc for pc in order if any(KCB + 16 <= x < KCB + 20 for x in dests(pc))]
    nest = [pc for pc in order if any(KCB + 8 <= x < KCB + 12 for x in dests(pc))]
    ok(lock == [0x0036D0], 'resolved stores to [KCB+16]')
    unref = lambda a: 0x002D10 <= a < 0x002DC8 or 0x002DE4 <= a < 0x002EBE    # noqa: E731
    ok(nest == [0x002B9A, 0x002C08, 0x002C4C, 0x002CF4, 0x002F36, 0x002FB2, 0x002FC8, 0x002FD4, 0x002FEA,
                0x002FF6, 0x00300C, 0x003018, 0x00302E, 0x0030D6, 0x0030E6, 0x003140, 0x003152, 0x003348,
                0x0035C4, 0x003686], 'resolved stores to [KCB+8]')
    k8 = [a for a in range(0x002B8C, 0x003A20, 2) if (u16(rom, a) & 0xF00F) == 0x1002 and (a in code or unref(a))]
    ok([a for a in k8 if a not in nest] == [0x002D20, 0x002E26, 0x002E66, 0x002E8C, 0x002EAC, 0x003486, 0x003624],
       'mov.l Rm,@(8,Rn) in the kernel range that the dataflow does not resolve')
    k16 = [a for a in range(0x002B8C, 0x003A20, 2) if (u16(rom, a) & 0xF00F) == 0x1004 and (a in code or unref(a))]
    ok(k16 == [0x0036D0], 'mov.l Rm,@(16,Rn) in the kernel range 0x002B8C..0x003A1F')
    k1000 = [a for a in range(0x002000, 0x004100, 2)
             if (a in code or unref(a)) and (u16(rom, a) >> 12) == 9 and
             u16(rom, a + 4 + (u16(rom, a) & 0xFF) * 2) == 0x1000]
    ok(k1000 == [0x002D1C, 0x002E3E, 0x00367C], 'loads of the constant 0x1000 in 0x002000..0x0040FF')
    # writers of byte [KCB+0] and word [KCB+6] through a KCB pointer, kernel range, by opcode shape
    kb = [a for a in range(0x002B8C, 0x003A20, 2) if (a in code or unref(a)) and
          ((u16(rom, a) & 0xFF0F) == 0x8103)]
    ok(kb == [0x002DBA, 0x0031C8, 0x00324C, 0x0032E6, 0x0034FA, 0x003584], 'mov.w r0,@(6,Rn) in the kernel range')
    # the 13-record table at 0x003F84 against the callers of 0x0035A4
    recs = [u32(rom, TASK_TABLE + 16 * i + 8) for i in range(13)]
    ok(recs == [0xE1B0, 0xDD52, 0xDDAC, 0xDE38, 0xDE92, 0xE486, 0xE4BA, 0xE2FC, 0xE3B2, 0xE448, 0xDF14,
                0xE3E4, 0xE4E6], 'entry addresses in the 0x3F84 records')
    ok([u32(rom, TASK_TABLE + 16 * i + 4) for i in range(13)] == [0xFFFF11C8 + 8 * i for i in range(13)],
       'RAM record pointers in the 0x3F84 records')
    s35 = sites_of(rom, code, state, 0x0035A4)
    ok(len(s35) == 12 and {owner(a) for a, _ in s35} == set(recs) - {0xE1B0},
       'the functions that reach 0x35A4 are the table entries other than id 0')
    ok([a for a, _ in sites_of(rom, code, state, 0x003206)] == [0x002F18, 0x0038C0] and
       [a for a, _ in sites_of(rom, code, state, 0x0031B0)] == [0x0036E8] and
       len(sites_of(rom, code, state, 0x002EDC)) == 8, 'callers of 0x003206 / 0x0031B0 / 0x002EDC')
    ident = b'Copyright 1999 Hitachi,Ltd.Ho7058 Operating System, Version 1.0.00.000'
    ok(rom[0x003374:0x003374 + len(ident)] == ident and set(rom[0x003374 + len(ident):0x00343E]) == {0x20} and
       not any(a in code for a in range(0x003374, 0x003440, 2)), 'the text at 0x003374')
    print(f'   0x003374..0x00343F is not code: "{ident.decode()}" padded with spaces')
    print('   0x0035A4 is reached from exactly 12 functions = the entry addresses of table ids 1..12')
    print('   0x003206 is called at 0x002F18 and 0x0038C0; 0x0031B0 at 0x0036E8; 0x002EDC at 8 sites')
    print('   literals: 0x003664 only at 0x0031AC; 0x002BD4 only at 0x002BD0; no reference of any kind to')
    print('   0x002D10 or 0x002DE4; 11 pool words point into 0xFFFF2060..0xFFFF20AB')
    return sum(len(v) for v in A.values()) + len(L)


CONVENTION_RESIDUE = {
    '317C': (366, [0x01D31C, 0x0210DA, 0x04907C, 0x04F206, 0x04F368]),
    '3190': (340, [0x01D31C, 0x0210DA, 0x04907C, 0x04F206, 0x04F368]),
    'E6E4': (136, []),
    'BE81C': (350, [0x00DD52, 0x00DDAC, 0x00DE38, 0x00DE92, 0x010E12]),
    'BE82C': (346, [0x00FACA, 0x010E12]),
}


def test_convention(rom, code, entries, state, A, owner):
    """Which call targets provably hand r8-r14 and r15 back, and which sites need no more than that."""
    TOK = 0x5A5A5A00
    targets = set()
    for pc, w in code.items():
        kind, t, _ = flow(w, pc)
        if kind == 'call':
            targets.add(t)
        elif kind == 'icall' and pc in state:
            v = state[pc].R[t]
            if v is not None and not isinstance(v, tuple):
                targets |= {x for x in v if x in code}

    def restores(entry, good):
        st, work = {}, []

        def push(pc, s):
            if pc not in code:
                return
            old = st.get(pc)
            if old is None:
                st[pc] = s.copy()
                work.append(pc)
            else:
                new = meet_st(old, s)
                if new.key() != old.key():
                    st[pc] = new
                    work.append(pc)

        s0 = St()
        for i in range(8, 15):
            s0.R[i] = frozenset((TOK + i,))
        push(entry, s0)
        while work:
            pc = work.pop()
            s = st[pc].copy()
            w = code[pc]
            kind, tgt, delayed = flow(w, pc)
            if kind == 'seq':
                push(pc + 2, step(rom, s, w, pc))
                continue
            ctgt = s.R[tgt] if kind in ('icall', 'ijump') else (const(tgt) if kind == 'call' else None)
            if delayed:
                s = step(rom, s, code[pc + 2], pc + 2)
            nxt = pc + (4 if delayed else 2)
            if kind == 'cond':
                push(tgt, s)
                push(nxt, s)
            elif kind == 'jump':
                push(tgt, s)
            elif kind in ('call', 'icall'):
                push(nxt, after_call(s, ctgt, good))
            else:
                intact = s.sp == 0 and all(s.R[i] == frozenset((TOK + i,)) for i in range(8, 15))
                if kind == 'ijump':                   # a tail call is fine if the callee is good too
                    known = ctgt is not None and not isinstance(ctgt, tuple)
                    intact = intact and known and all(x in good for x in ctgt)
                elif kind != 'ret':
                    intact = False
                if not intact:
                    return False
        return True

    # 0x003190 tail-jumps into the context switch and is not a normal function. That it comes back with
    # r8-r14 intact on BOTH paths is emulated in test_3190 (no switch) and test_ready (switch + resume).
    forced = {0x003190}
    good = set(targets)
    rounds = 0
    while True:
        nxt = {e for e in good if e in forced or restores(e, good)}
        rounds += 1
        if nxt == good:
            break
        good = nxt
    ok(len(targets) == 3819 and len(good) == 3072, f'call targets {len(targets)}, proven to restore {len(good)}')
    ok({0x00317C, 0x0BE81C, 0x0BE82C, 0x00E6E4, 0x0BE9A0, 0x010800} <= good and 0x0BCEA4 not in good,
       'membership of the proven set')
    strict = dataflow(rom, code, entries, keeps=good)
    for name, (want, fns) in CONVENTION_RESIDUE.items():
        t = {'317C': 0x00317C, '3190': 0x003190, 'E6E4': 0x00E6E4, 'BE81C': 0x0BE81C, 'BE82C': 0x0BE82C}[name]
        got = {a for a, _ in sites_of(rom, code, strict, t)}
        ok(got <= set(A[name]) and len(got) == want, f'{name}: {len(got)} sites need no unproven callee')
        ok(sorted({owner(a) for a in set(A[name]) - got}) == fns, f'{name}: functions holding the residue')
    print(f'   convention check: {len(good)} of {len(targets)} call targets provably restore r8-r14 and r15 at every exit')
    print(f'      (greatest fixed point, {rounds} rounds). With ONLY those allowed between load and call:')
    print('      0x00317C 366 of 404, 0x003190 340 of 382, 0x00E6E4 136 of 136, 0x0BE81C 350 of 355, 0x0BE82C 346 of 348.')
    print('      The rest sit in 0x01D31C, 0x0210DA, 0x04907C, 0x04F206, 0x04F368 (0x00317C / 0x003190),')
    print('      0x00DD52, 0x00DDAC, 0x00DE38, 0x00DE92, 0x010E12, 0x00FACA (0x0BE81C / 0x0BE82C) and rest on the convention.')
    return len(good)


def main():
    rom = load_rom()
    emulated = 0
    for test in (test_317c, test_3190, test_pairs, test_e6e4, test_be81c, test_vectors, test_traps,
                 test_2b8c_direct, test_isr, test_log, test_scan, test_ready):
        emulated += test(rom)
    static = test_sites(rom)
    print(f'\nALL OK: {emulated} emulated cases, {static} call sites classified, {CHECKS[0]} assertions, '
          f'reference bin md5 {ROM_MD5}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
