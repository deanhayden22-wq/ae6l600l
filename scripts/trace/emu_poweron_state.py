#!/usr/bin/env python3
"""Emulation check for the power-on RAM state (reset path, reset DMA, RAM test, boot watchdog).

    python3 scripts/trace/emu_poweron_state.py          # all passes (about 3 minutes)
    python3 scripts/trace/emu_poweron_state.py C G      # selected passes

Reference bin: rom/AE5L600L 20g rev 20.19c.bin  md5 92cae8275cd4f9b473a3a9e36efe6449
Trace:         disassembly/analysis/poweron_state_trace.txt

Each pass runs ROM code in scripts/sh2e_emu.py, prints inputs -> outputs and asserts
the contract written in the trace.  Exit 0 only when every assertion holds.

  A. static bytes: reset vectors, the hand-over words (0x001000, 0x002000, 0x002004,
     0x0FFFF8, 0x0FFFFC), the RAM-range table 0x011CC8..0x011CE8, the pattern table
     0x011C88, the retry byte 0x0C4730, VBR vector 224 (WDT ITI) = 0x00F6E6
  B. the DMAC channel-0 setting 0x001F0128 decoded field by field with the bit
     tables of the SH7058 hardware manual (REJ09B0046-0300H, section 10.2.4)
  C. the whole reset path, power-on vector 0x000C0C -> 0x003324 (the kernel start),
     with interrupt ACCEPTANCE OFF (the WDT counts, its ITI is never taken), over 8
     initial RAM images x boot marker 0xFFFFBFFC absent / present x word 0xFFFF2000 =
     0xAA55 / not (32 runs); final RAM compared byte by byte with the starting image;
     stack pointer at each stage; every WDT register write and the TCSR read at
     0x010884; the IPR writes; the lowest SP at which an ITI would be accepted
  D. 0x010448 (RAM test) alone: every region the ROM tests, perfect RAM -> exact
     final contents and write extent; the other SDSR class; stuck-at faults ->
     failure, report address, number of attempts
  E. 0x010290 with 0x010448 replaced by a scribbling stub: result bits for every
     pass/fail combination, byte 0xFFFF5B89, preservation of 0xFFFF0000..0xFFFF1FFF,
     the DMA always programmed
  F. 0x010124 (warm / cold, verified contract in revlim_freeze_gate_trace.txt) run
     on the post-reset image: what the cold path does to 0xFFFF2000..0xFFFF3FFF
  G. the reset path with the WDT interval-timer interrupt ACCEPTED (vector 224,
     priority IPRL bits 7-4): 0xFFFF0004 = number of ITIs taken; where the ISR frames
     land; residue left in 0xFFFF0020..0xFFFF1FFF; region A still zero; and the
     boot-watchdog expiry (183 ITIs -> 0x010800(0x2100, 0) -> 0x00FBA4, no kernel start)
  H. 0x010448 on ranges the ROM never passes: when it writes past `end`
  I. 0x0007E0's argument test is on (r4 & 0xFFFF), not on the sign of r4
  J. a stuck RAM bit in range A on the full reset path: the 0x010800 log record lands
     in 0xFFFF2060..0xFFFF20A7
  Z. every ROM byte executed or read in the runs above is identical in all 1 MB bins

Hardware model (inputs, stated in the trace).  The emulator's SR is extended so that
ldc Rn,sr / ldc Rn,vbr / rte execute.  Peripheral space 0xFFFFC000.. is a byte register
file (reads return the last value written, 0 before) except:
  * WDT, manual 13.2: TCSR / TCNT written by word to 0xFFFFEC10 with key 0xA5 / 0x5A,
    RSTCSR by word to 0xFFFFEC12; TCSR / TCNT / RSTCSR read by byte at 0xFFFFEC10 /
    EC11 / EC13; TCSR bits 4,3 and RSTCSR bits 4..0 read 1; TME = 0 clears TCNT; OVF
    is cleared only by writing 0 after reading 1.  TCNT advances once every
    `ipt * divider / 512` instructions (divider from the CKS table, 13.2.2): the ratio
    of CPU instructions to WDT clocks is a MODEL INPUT, not a ROM fact.  Watchdog-timer
    mode (WT/IT = 1) raises (never used on this path).
  * Interrupts (manual 7.4 / 6.x): only the WDT ITI is modelled.  When OVF = 1 and
    IPRL bits 7-4 > SR.I, at an instruction boundary (never between a delayed branch
    and its slot) SR then PC are pushed, SR.I := the priority, PC := [VBR + 224 * 4].
  * ICR 0xFFFFED18 reads 0x8000 (the loop at 0x000C48 waits for bit 15), H-UDI SDSR
    0xFFFFF7C2 reads 0x0B01 (manual 19.3.2), HCAN GSR 0xFFFFD002 / 0xFFFFD802 read
    0x0008.  No CAN message is ever pending.
  * The DMAC is modelled from the manual's CHCR / DMAOR / DMATCR descriptions
    (auto-request only; other request sources raise); the transfer completes at the
    write that starts it (DMA duration is not modelled).
  * RAM is perfect (every write reads back) except where a pass injects a stuck bit.

Names here are neutral: nothing below establishes what any cell physically is.
"""
import glob
import hashlib
import os
import random
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, 'scripts'))
import sh2e_emu as E            # noqa: E402

BIN = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
ROM = open(BIN, 'rb').read()
assert hashlib.md5(ROM).hexdigest() == '92cae8275cd4f9b473a3a9e36efe6449', 'wrong reference bin'
M32 = 0xFFFFFFFF

A_LO, A_HI = 0xFFFF4000, 0xFFFFBF9F          # tested destructively, then DMA-filled
B_LO, B_HI = 0xFFFF0000, 0xFFFF001F          # tested with save / restore (masked)
C_LO, C_HI = 0xFFFF0020, 0xFFFF1FFF          # tested with save / restore
P_LO, P_HI = 0xFFFF2000, 0xFFFF3FFF          # not touched at reset (0x010124 cold path only)
K_LO, K_HI = 0xFFFFBFA0, 0xFFFFBFFF          # boot-block area above the application range
KERNEL_START = 0x003324
HALT_SPIN = 0x00FBB6                         # 0x00FBA4's endless loop
APP_SP = 0xFFFF12DC
ISR_DEPTH = 0x6C                             # 100-byte frame + 0x011880's pr push and add #-4
CELLS = {0xFFFF8EDC: 1, 0xFFFF8EDD: 1, 0xFFFF8EED: 1, 0xFFFF8ECC: 2, 0xFFFF8EF6: 1,
         0xFFFF7FF4: 1, 0xFFFF7FBC: 4, 0xFFFF69E6: 1, 0xFFFF7A44: 4, 0xFFFF8E66: 1}
DIV = {0: 2, 1: 64, 2: 128, 3: 256, 4: 512, 5: 1024, 6: 4096, 7: 8192}   # manual 13.2.2 CKS table
TCSR_A, TCNT_A, RSTCSR_W, RSTCSR_R = 0xFFFFEC10, 0xFFFFEC11, 0xFFFFEC12, 0xFFFFEC13
IPRL = 0xFFFFED16
COVER = set()                                # ROM bytes executed or read, for pass Z


def L(a): return struct.unpack('>I', ROM[a:a + 4])[0]


class Sys(E.Emu):
    """sh2e_emu with an SR, a peripheral register file, a WDT, the ITI and a DMAC (manual models)."""

    def __init__(self, rom=ROM, ipt=None, irq=False):
        super().__init__(rom)
        self.imask = 15
        self.per = {}
        self.log = []                 # (pc, kind, addr, size, value); kinds rw / dw / pw / pr / sr
        self.hooks = {0xFFFFED18: lambda s, n: 0x8000 if n == 2 else 0x80,
                      0xFFFFF7C2: lambda s, n: 0x0B01 if n == 2 else 0x0B,
                      0xFFFFD002: lambda s, n: 0x0008,
                      0xFFFFD802: lambda s, n: 0x0008}
        self.dma = []
        self.fault = {}               # addr -> (and_mask, or_mask) applied on RAM reads (stuck bits)
        # WDT (manual 13.2) and the ITI
        self.ipt, self.irq = ipt, irq
        self.tcsr, self.tcnt, self.rstcsr = 0x18, 0, 0x1F
        self.ovf_seen = False
        self.sub = 0
        self.wdt_writes = []          # (pc, addr, value, tcsr after)
        self.tcsr_reads = []          # (pc, value)
        self.iti = []                 # [pc at acceptance, SP before entry, lowest stack byte written, step, other writes]
        self.in_isr = False
        self.min_sp_accept = M32      # lowest SP < 0xFFFF4000 at a boundary where a pending ITI would be taken
        self.min_sp_accept_a = M32    # the same for SP in 0xFFFF4000..0xFFFFBF9F (range-C phase, SP 0xFFFFBF9C)
        self.calls_10800 = []         # (r4 & 0xFFFF, r5)
        self.sp_at = {}               # first-visit SP per instruction boundary pc
        self.first_step = {}
        self.rom_reads = set()

    def sr(self):
        return self.T | (self.S << 1) | (self.imask << 4) | (self.Q << 8) | (self.M << 9)

    def set_sr(self, v):
        self.T, self.S, self.imask = v & 1, (v >> 1) & 1, (v >> 4) & 15
        self.Q, self.M = (v >> 8) & 1, (v >> 9) & 1

    # ---- instruction boundary: WDT count, ITI acceptance (manual 7.4 steps 3, 6, 7)
    def step(self):
        pc = self.pc
        if pc not in self.sp_at:
            self.sp_at[pc] = self.R[15]
            self.first_step[pc] = self.steps
        if pc == 0x010800:
            self.calls_10800.append((self.R[4] & 0xFFFF, self.R[5]))
        if self.ipt and self.tcsr & 0x20:
            self.sub += 1
            if self.sub >= max(1, self.ipt * DIV[self.tcsr & 7] // 512):
                self.sub = 0
                self.tcnt = (self.tcnt + 1) & 0xFF
                if self.tcnt == 0:
                    if self.tcsr & 0x40:
                        raise E.EmuError('watchdog-timer-mode overflow not modelled')
                    if not self.tcsr & 0x80:
                        self.ovf_seen = False
                    self.tcsr |= 0x80
        prio = (self.pget(IPRL, 2) >> 4) & 15
        if prio > self.imask:
            if self.R[15] < A_LO:
                self.min_sp_accept = min(self.min_sp_accept, self.R[15])
            elif self.R[15] < K_LO:
                self.min_sp_accept_a = min(self.min_sp_accept_a, self.R[15])
        if self.irq and self.tcsr & 0x80 and prio > self.imask:
            sp = self.R[15]
            self.iti.append([pc, sp, sp, self.steps, set()])
            self.in_isr = True
            self.write((sp - 4) & M32, 4, self.sr())
            self.write((sp - 8) & M32, 4, pc)
            self.R[15] = (sp - 8) & M32
            self.imask = prio
            self.pc = self.read(self.vbr + 224 * 4, 4)
        super().step()

    def execute(self, w, pc, slot):
        if (w & 0xF0FF) == 0x400E:                       # ldc Rn,sr
            self.executed.add(pc)
            self.set_sr(self.R[(w >> 8) & 15])
            self.log.append((pc, 'sr', 0, 0, self.sr()))
            return None
        if (w & 0xF0FF) == 0x402E:                       # ldc Rn,vbr
            self.executed.add(pc)
            self.vbr = self.R[(w >> 8) & 15]
            return None
        if w == 0x002B:                                  # rte: PC from @SP, SR from @(SP+4)
            self.executed.add(pc)
            sp = self.R[15]
            ret, srv = self.read(sp, 4), self.read(sp + 4, 4)
            self.R[15] = (sp + 8) & M32
            self.set_sr(srv)
            self.in_isr = False
            return ('delay', ret)
        return super().execute(w, pc, slot)

    def pget(self, a, n):
        return int.from_bytes(bytes(self.per.get(a + i, 0) for i in range(n)), 'big')

    def pput(self, a, n, v):
        for i in range(n):
            self.per[a + i] = (v >> (8 * (n - 1 - i))) & 0xFF

    def read(self, a, n):
        a &= M32
        if a < E.ROM_END:
            self.rom_reads.update(range(a, a + n))
        if TCSR_A <= a <= RSTCSR_R:
            if n != 1 or a == RSTCSR_W:
                raise E.EmuError(f'WDT read {a:#x} size {n} (manual 13.2.4: byte reads at EC10 / EC11 / EC13)')
            if a == TCSR_A:
                v = self.tcsr | 0x18
                if v & 0x80:
                    self.ovf_seen = True
                self.tcsr_reads.append((self.pc, v))
            elif a == TCNT_A:
                v = self.tcnt
            else:
                v = self.rstcsr | 0x1F
            self.log.append((self.pc, 'pr', a, n, v))
            return v
        if a >= 0xFFFFC000:
            if n > 1 and a % n:
                raise E.EmuError(f'misaligned peripheral read {a:#x}')
            v = self.hooks[a](self, n) if a in self.hooks else self.pget(a, n)
            self.log.append((self.pc, 'pr', a, n, v))
            return v
        v = super().read(a, n)
        for i in range(n):
            if a + i in self.fault:
                andm, orm = self.fault[a + i]
                sh = 8 * (n - 1 - i)
                v = (v & ~(0xFF << sh)) | ((((v >> sh) & andm) | orm) << sh)
        return v

    def write(self, a, n, v):
        a &= M32
        v &= (1 << (8 * n)) - 1
        if TCSR_A <= a <= RSTCSR_R:
            if n != 2 or a not in (TCSR_A, RSTCSR_W):
                raise E.EmuError(f'WDT write {a:#x} size {n} (manual 13.2.4: word writes to EC10 / EC12)')
            hi, lo = v >> 8, v & 0xFF
            if a == TCSR_A and hi == 0xA5:
                ovf = self.tcsr & 0x80
                if not lo & 0x80 and self.ovf_seen:
                    ovf, self.ovf_seen = 0, False
                self.tcsr = ovf | (lo & 0x67) | 0x18
                if not self.tcsr & 0x20:
                    self.tcnt, self.sub = 0, 0
            elif a == TCSR_A and hi == 0x5A:
                self.tcnt = lo
            elif a == RSTCSR_W and hi == 0x5A:
                self.rstcsr = (self.rstcsr & 0x80) | (lo & 0x60) | 0x1F
            elif a == RSTCSR_W and v == 0xA500:
                self.rstcsr &= 0x7F
            else:
                raise E.EmuError(f'WDT write {v:#06x} to {a:#x} not modelled')
            self.wdt_writes.append((self.pc, a, v, self.tcsr))
            self.log.append((self.pc, 'pw', a, n, v))
            return
        if a >= 0xFFFFC000:
            if n > 1 and a % n:
                raise E.EmuError(f'misaligned peripheral write {a:#x}')
            self.pput(a, n, v)
            self.log.append((self.pc, 'pw', a, n, v))
            self.dmac_check()
            return
        if a < E.ROM_END or not self._ram(a, n):
            raise E.EmuError(f'{n}-byte write to {a:#010x} (pc {self.pc:06X})')
        if self.in_isr:
            rec = self.iti[-1]
            if rec[1] - 0x400 <= a < rec[1]:
                rec[2] = min(rec[2], a)                  # the ISR's stack frame
            else:
                rec[4].add((a, n))                       # any other RAM write in the ISR
        self.log.append((self.pc, 'rw', a, n, v))
        o = a - E.RAM_LO
        self.ram[o:o + n] = v.to_bytes(n, 'big')
        self.init[o:o + n] = b'\x01' * n

    def cover(self):
        COVER.update(self.rom_reads)
        for p in self.executed:
            COVER.update((p, p + 1))

    # ---- DMAC, from REJ09B0046-0300H section 10.2 (Table 10.1, CHCR 10.2.4, DMAOR 10.2.5)
    def dmac_check(self):
        dmaor = self.pget(0xFFFFECB0, 2)
        for ch, base in enumerate((0xFFFFECC0, 0xFFFFECD0, 0xFFFFECE0, 0xFFFFECF0)):
            chcr = self.pget(base + 0xC, 4)
            # transfer enabled: DE = 1, DME = 1, TE = 0, NMIF = 0, AE = 0 (section 10.3.1)
            if chcr & 1 and dmaor & 1 and not chcr & 2 and not dmaor & 6:
                self.run_dma(ch, base, chcr)

    def run_dma(self, ch, base, chcr):
        f = chcr_fields(chcr)
        if f['RS'] != 0x1F:
            raise E.EmuError(f'DMA ch{ch}: request source {f["RS"]:#x} not modelled')
        if f['SM'] == 3 or f['DM'] == 3 or f['TS'] == 3:
            raise E.EmuError(f'DMA ch{ch}: prohibited setting {chcr:#x}')
        size = {0: 1, 1: 2, 2: 4}[f['TS']]
        step = {0: 0, 1: size, 2: -size}
        sar, dar = self.pget(base, 4), self.pget(base + 4, 4)
        cnt = self.pget(base + 8, 4) & 0xFFFFFF or 1 << 24          # 0 = 16,777,216 transfers
        self.dma.append(dict(ch=ch, sar=sar, dar=dar, cnt=cnt, size=size, chcr=chcr, pc=self.pc))
        for _ in range(cnt):
            v = E.Emu.read(self, sar, size)                         # dual address: read then write
            if not self._ram(dar, size):
                raise E.EmuError(f'DMA destination {dar:#x} outside RAM')
            o = dar - E.RAM_LO
            self.ram[o:o + size] = v.to_bytes(size, 'big')
            self.init[o:o + size] = b'\x01' * size
            self.log.append((self.pc, 'dw', dar, size, v))
            sar, dar = (sar + step[f['SM']]) & M32, (dar + step[f['DM']]) & M32
        self.pput(base, 4, sar)
        self.pput(base + 4, 4, dar)
        self.pput(base + 8, 4, 0)
        self.pput(base + 0xC, 4, chcr | 2)                          # TE := 1


def chcr_fields(v):
    """CHCR0-3 bit fields, manual section 10.2.4."""
    return dict(DI=(v >> 28) & 1, RO=(v >> 24) & 1, RS=(v >> 16) & 0x1F, SM=(v >> 12) & 3,
                DM=(v >> 8) & 3, TS=(v >> 4) & 3, TM=(v >> 3) & 1, IE=(v >> 2) & 1,
                TE=(v >> 1) & 1, DE=v & 1, reserved=v & 0xEEE0CCC0)


def fill_image(kind, seed=0):
    if kind == 'random':
        rng = random.Random(seed)
        return bytearray(rng.randrange(256) for _ in range(E.RAM_HI - E.RAM_LO + 1))
    b = {'zero': 0x00, 'ones': 0xFF, 'x5a': 0x5A, 'xa5': 0xA5}[kind]
    return bytearray([b]) * (E.RAM_HI - E.RAM_LO + 1)


def put32(img, a, v):
    img[a - E.RAM_LO:a - E.RAM_LO + 4] = (v & M32).to_bytes(4, 'big')


def put16(img, a, v):
    img[a - E.RAM_LO:a - E.RAM_LO + 2] = (v & 0xFFFF).to_bytes(2, 'big')


def ranges(addrs):
    out = []
    for a in sorted(addrs):
        if out and a == out[-1][1] + 1:
            out[-1][1] = a
        else:
            out.append([a, a])
    return out


def fmt_ranges(addrs):
    return ', '.join(f'{lo:#x}..{hi:#x}' for lo, hi in ranges(addrs))


FAILS = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)
        raise AssertionError(msg)


# =====================================================================================
def pass_A():
    print('== A. static bytes')
    vec = [L(a) for a in (0, 4, 8, 12)]
    print(f'  vectors: power-on PC {vec[0]:#x} SP {vec[1]:#x}; manual-reset PC {vec[2]:#x} SP {vec[3]:#x}')
    check(vec == [0x0C0C, 0xFFFFBFA0, 0x0C0C, 0xFFFFBFA0], 'A vectors')
    COVER.update(range(0x0, 0x10))                    # read by the hardware at reset, not by the emulator
    hand = {a: L(a) for a in (0x1000, 0x2000, 0x2004, 0xFFFF8, 0xFFFFC)}
    print('  hand-over words: ' + ', '.join(f'[{a:#07x}]={v:#010x}' for a, v in hand.items()))
    check(hand[0x1000] == 0x127C and hand[0x2000] == 0xFFFF204C and hand[0xFFFF8] == 0xFA34
          and hand[0xFFFFC] == 0x2004 and hand[0x2004] != M32, 'A hand-over words')
    tab = {a: L(a) for a in range(0x11CC8, 0x11CEC, 4)}
    print('  range table: ' + ', '.join(f'[{a:#x}]={v:#010x}' for a, v in tab.items()))
    check([tab[a] for a in range(0x11CCC, 0x11CEC, 4)] ==
          [0xFFFF0000, 0xFFFF001F, 0xFFFF0020, 0xFFFF1FFF, 0xFFFF2000, 0xFFFF3FFF, 0xFFFF4000, 0xFFFFBF9F]
          and tab[0x11CC8] == APP_SP, 'A range table')
    pat = [L(0x11C88 + 4 * i) for i in range(8)]
    print('  pattern table 0x011C88: ' + ' '.join(f'{p:08X}' for p in pat))
    check(pat == [0xA55A5AA5, 0x5AA5A55A] * 4, 'A pattern table')
    print(f'  retry byte [0x0C4730] = {ROM[0xC4730]}')
    check(ROM[0xC4730] == 2, 'A retry byte')
    v224 = [L(0x0FFC50 + 4 * v) for v in range(224, 228)]
    print(f'  VBR 0x0FFC50: vector 224 (WDT ITI, manual Table 7.3) -> {v224[0]:#x}; 225..227 -> '
          + ', '.join(hex(x) for x in v224[1:]) + f' (vector 0 -> {L(0x0FFC50):#x})')
    check(v224[0] == 0xF6E6 and v224[1:] == [L(0x0FFC50)] * 3, 'A vector 224')


def pass_B():
    print('== B. CHCR0 value 0x001F0128 and the other DMAC stores, manual section 10.2')
    f = chcr_fields(0x001F0128)
    print('  fields:', ', '.join(f'{k}={v:#x}' for k, v in f.items()))
    check(f['reserved'] == 0 and f['DI'] == 0 and f['RO'] == 0, 'B reserved bits')
    check(f['RS'] == 0x1F, 'B RS4-RS0 = 11111 = auto-request (manual p.172 table)')
    check(f['SM'] == 0, 'B SM1,SM0 = 00 source address fixed')
    check(f['DM'] == 1, 'B DM1,DM0 = 01 destination address incremented (+4 for 32-bit)')
    check(f['TS'] == 2, 'B TS1,TS0 = 10 longword')
    check(f['TM'] == 1 and f['IE'] == 0 and f['TE'] == 0 and f['DE'] == 0, 'B TM burst, IE 0, TE 0, DE 0')
    low = chcr_fields(0x0128)
    print('  word 0x0128 to 0xFFFFECCE (low half first, upper half held, note 2 of Table 10.1):',
          f'RS={low["RS"]} SM={low["SM"]} DM={low["DM"]} TS={low["TS"]} TM={low["TM"]} DE={low["DE"]}')
    cnt = ((0xFFFFBF9F - 0xFFFF4000 + 1) >> 2) & 0x00FFFFFF
    print(f'  DMATCR0 = ((0xFFFFBF9F - 0xFFFF4000 + 1) >> 2) & 0xFFFFFF = {cnt:#x};'
          f' last destination long {0xFFFF4000 + 4 * (cnt - 1):#x}')
    check(cnt == 0x1FE8 and 0xFFFF4000 + 4 * cnt - 1 == A_HI, 'B count')
    run = (0x001F0128 & 0xFFFFFFF9) | 1
    print(f'  0x01040C..0x010414 (and #-7, or #1): CHCR0 {run:#010x} -> DE=1, TE=0, IE=0')
    check(run == 0x001F0129, 'B start value')


# =====================================================================================
def run_reset(img, label, ipt=2, irq=False, fault=None, stops=(KERNEL_START,), want=KERNEL_START):
    e = Sys(ipt=ipt, irq=irq)
    e.ram[:] = img
    e.init[:] = b'\x01' * len(e.init)
    if fault:
        e.fault.update(fault)
    r = e.call(0x000C0C, regs={15: L(4)}, stop_at=set(stops), max_steps=6_000_000)
    e.cover()
    check(r == want, f'{label}: stopped at {r}, expected {want:#x}')
    return e


def wdt_tail(e):
    """WDT register writes from 0x00B2AA on: (pc, addr, value, TCSR after)."""
    i = next(i for i, x in enumerate(e.wdt_writes) if x[0] >= 0x00B2AA)
    return e.wdt_writes[i:]


ACCEPT = {}


def pass_C():
    print('== C. reset path 0x000C0C -> 0x003324, interrupt acceptance OFF, 8 images x boot marker x 0xFFFF2000 marker')
    images = [('random', s) for s in range(1, 5)] + [('zero', 0), ('ones', 0), ('x5a', 0), ('xa5', 0)]
    executed_ref = {}
    stack_lows = set()
    accept_sps = set()
    n = 0
    for kind, seed in images:
        for boot_marker in (False, True):
            for warm in (False, True):
                img = fill_image(kind, seed)
                if boot_marker:
                    put32(img, 0xFFFFBFFC, 0x5AA5A55A)
                elif img[0xBFFC:0xC000] == b'\x5a\xa5\xa5\x5a':
                    put32(img, 0xFFFFBFFC, 0)
                put16(img, 0xFFFF2000, 0xAA55 if warm else 0x1234)
                before = bytes(img)
                label = f'{kind}{seed} boot_marker={int(boot_marker)} [2000]={0xAA55 if warm else 0x1234:#06x}'
                e = run_reset(img, label)
                n += 1
                after = bytes(e.ram)
                ram = lambda a: after[a - E.RAM_LO]   # noqa: E731
                r32 = lambda a: int.from_bytes(after[a - E.RAM_LO:a - E.RAM_LO + 4], 'big')  # noqa: E731
                lo_stack = e.stack_low                 # lowest SP seen: the application stack
                check(0xFFFF1000 < lo_stack < APP_SP, f'{label}: stack low {lo_stack:#x}')
                stack_lows.add(lo_stack)
                accept_sps.add((e.min_sp_accept, e.min_sp_accept_a))
                changed = [E.RAM_LO + i for i in range(len(after)) if after[i] != before[i]]
                outside = [a for a in changed if not (A_LO <= a <= A_HI)]
                # ---- assertions: the contract
                check(all(b == 0 for b in after[A_LO - E.RAM_LO:A_HI - E.RAM_LO + 1]), f'{label}: region A not zero')
                check(len(e.dma) == 1 and e.dma[0]['sar'] == A_LO and e.dma[0]['dar'] == A_LO and
                      e.dma[0]['cnt'] == 0x1FE8 and e.dma[0]['size'] == 4 and e.dma[0]['pc'] == 0x010414,
                      f'{label}: DMA programming')
                check(e.R[4] == 0, f'{label}: r4 at the kernel start')
                allowed_P = {0xFFFF204C}
                allowed_B = set(range(0xFFFF0000, 0xFFFF0009))
                allowed_C = set(range(lo_stack, APP_SP))
                allowed_K = ({0xFFFFBFAC, 0xFFFFBFAD, 0xFFFFBFB8, 0xFFFFBFB9, 0xFFFFBFBA, 0xFFFFBFBB}
                             | set(range(0xFFFFBFE4, 0xFFFFC000)) | ({0xFFFFBFA8} if not boot_marker else set()))
                bad = [a for a in outside if a not in allowed_P | allowed_B | allowed_C | allowed_K]
                check(not bad, f'{label}: unexpected changes {[hex(a) for a in bad[:8]]}')
                check(ram(0xFFFF204C) == 0x88, f'{label}: 0xFFFF204C')
                check(r32(0xFFFF0000) == 183 and r32(0xFFFF0004) == 0 and ram(0xFFFF0008) == 0, f'{label}: 0xFFFF0000..8')
                check(after[0xFFFFBFE4 - E.RAM_LO:0xFFFFC000 - E.RAM_LO] ==
                      bytes(8) + b'\xaa' + bytes(3) + bytes(8) + b'\xaa' + bytes(3) + b'\x5a\xa5\xa5\x5a',
                      f'{label}: boot area 0xFFFFBFE4..BFFF')
                check(ram(0xFFFFBFAC) == 0 and ram(0xFFFFBFAD) == 0x88 and
                      after[0xFFFFBFB8 - E.RAM_LO:0xFFFFBFBC - E.RAM_LO] == bytes(4), f'{label}: 0xFFFFBFAC..BFBB')
                wrote_bfa8 = any(k == 'rw' and a == 0xFFFFBFA8 for pc, k, a, sz, v in e.log)
                check(wrote_bfa8 == (not boot_marker), f'{label}: 0xFFFFBFA8 written iff the boot marker is absent')
                if not boot_marker:
                    check(ram(0xFFFFBFA8) == 0, f'{label}: 0xFFFFBFA8')
                else:
                    check(ram(0xFFFFBFA8) == before[0xFFFFBFA8 - E.RAM_LO], f'{label}: 0xFFFFBFA8 kept')
                check(all(after[a - E.RAM_LO] == before[a - E.RAM_LO] for a in range(P_LO, P_HI + 1) if a != 0xFFFF204C),
                      f'{label}: 0xFFFF2000..3FFF changed')
                check(all(after[a - E.RAM_LO] == before[a - E.RAM_LO] for a in range(0xFFFF0009, 0xFFFF0020)),
                      f'{label}: 0xFFFF0009..001F changed')
                check(all(after[a - E.RAM_LO] == before[a - E.RAM_LO]
                          for a in list(range(C_LO, lo_stack)) + list(range(APP_SP, C_HI + 1))),
                      f'{label}: region C outside the stack window changed')
                for c, sz in CELLS.items():
                    check(int.from_bytes(after[c - E.RAM_LO:c - E.RAM_LO + sz], 'big') == 0, f'{label}: cell {c:#x}')
                # stack pointer at each stage (P2): first visit of each pc
                sps = {p: e.sp_at.get(p) for p in (0x00127C, 0x0012C0, 0x001008, 0x00FA34, 0x0040CA, 0x00FA4E)}
                check(sps == {0x00127C: 0xFFFFBFA0, 0x0012C0: 0xFFFFBFA0, 0x001008: 0xFFFFBFA0,
                              0x00FA34: 0xFFFFBF7C, 0x0040CA: 0xFFFFBF7C, 0x00FA4E: APP_SP}, f'{label}: stage SPs {sps}')
                # WDT (A3): 0x00B2AA stops it, 0x010C52(4) sets CKS 4 with TME 0, 0x010884 reads 0x1C, 0x010942 restarts
                tail = wdt_tail(e)
                check([(pc, a, t) for pc, a, v, t in tail] ==
                      [(0x00B2B8, TCSR_A, tail[0][3]), (0x00B2BE, RSTCSR_W, tail[1][3]), (0x00B2C2, TCSR_A, 0x18),
                       (0x010C5C, TCSR_A, 0x18), (0x010C66, TCSR_A, 0x1C), (0x01094C, TCSR_A, 0x3C)]
                      and not tail[0][3] & 0x20 and [v for pc, a, v, t in tail[1:]] ==
                      [0x5A1F, 0xA518, 0xA518, 0xA51C, 0xA53C], f'{label}: WDT writes {tail}')
                check([v for pc, v in e.tcsr_reads if pc == 0x010884] == [0x1C], f'{label}: TCSR at 0x010884')
                check(any(pc == 0x001338 for pc, a, v, t in e.wdt_writes), f'{label}: 0x001332 ran')
                # IPR writes: 0x00AE1C zeroes IPRA..IPRL, 0x00AE50 sets IPRL 7-4 := 14, 0x00AE1C zeroes again
                ipr = [(pc, a, v) for pc, k, a, sz, v in e.log if k == 'pw' and 0xFFFFED00 <= a <= 0xFFFFED17]
                check([x[0] for x in ipr] == [0x00AE20, 0x00AE24, 0x00AE28, 0x00AE2C, 0x00AE30, 0x00AE34, 0x00AE38,
                                              0x00AE3C, 0x00AE40, 0x00AE44, 0x00AE48, 0x00AE4C, 0x00AE5A] +
                      [0x00AE20, 0x00AE24, 0x00AE28, 0x00AE2C, 0x00AE30, 0x00AE34, 0x00AE38, 0x00AE3C, 0x00AE40,
                       0x00AE44, 0x00AE48, 0x00AE4C] and ipr[12] == (0x00AE5A, IPRL, 0x00E0)
                      and all(v == 0 for pc, a, v in ipr[:12] + ipr[13:]), f'{label}: IPR writes {ipr}')
                check(e.pget(IPRL, 2) == 0 and e.imask == 13, f'{label}: IPRL / SR.I at the kernel start')
                # the reset path never reads the 0xFFFF2000 marker: same instructions either way
                key = (kind, seed, boot_marker)
                if warm:
                    check(e.executed == executed_ref[key], f'{label}: path depends on 0xFFFF2000')
                else:
                    executed_ref[key] = set(e.executed)
                # post-DMA RAM writes (what can still change region A before the kernel start)
                i_dma = max(i for i, x in enumerate(e.log) if x[1] == 'dw')
                post = sorted({(pc, a) for pc, k, a, sz, v in e.log[i_dma + 1:] if k == 'rw' and A_LO <= a <= A_HI})
                if n == 1:
                    print(f'  {label}: {e.steps} steps; changed outside A: {fmt_ranges(outside)}')
                    print('    region A writes after the DMA (pc, addr): '
                          + ', '.join(f'({pc:06X},{a:#x})' for pc, a in post))
                    print(f'    0xFFFF0000 = {r32(0xFFFF0000)}, 0xFFFF0004 = {r32(0xFFFF0004)}, 0xFFFF0008 = {ram(0xFFFF0008)};'
                          f' 0xFFFF204C = {ram(0xFFFF204C):#x}; 0xFFFF5B89 = {ram(0xFFFF5B89)}; 0xFFFF5B6C = {ram(0xFFFF5B6C)}')
                    print('    boot area 0xFFFFBFA0..BFFF: ' + after[K_LO - E.RAM_LO:].hex())
                    dm = e.dma[0]
                    print(f'    DMA: ch{dm["ch"]} SAR {dm["sar"]:#x} DAR {dm["dar"]:#x} count {dm["cnt"]:#x} size {dm["size"]}'
                          f' CHCR {dm["chcr"]:#x} started at pc {dm["pc"]:06X}')
                    sr_writes = [(pc, v) for pc, k, a, sz, v in e.log if k == 'sr' and pc in (0x00FA3C, 0x00FA82)]
                    print('    SR loads on the path: ' + ', '.join(f'{pc:06X}:I={(v >> 4) & 15}' for pc, v in sr_writes))
                    print('    SP at first visit: ' + ', '.join(f'{p:06X}:{s:#x}' for p, s in sps.items()))
                    print('    WDT writes from 0x00B2AA (pc, addr, value, TCSR after): '
                          + ', '.join(f'({pc:06X},{a & 0xFFFF:04X},{v:04X},{t:02X})' for pc, a, v, t in tail)
                          + f'; TCSR read at 0x010884 = {[hex(v) for pc, v in e.tcsr_reads if pc == 0x010884]}')
                    print(f'    IPR writes: {len(ipr)}, IPRL := {ipr[12][2]:#06x} at {ipr[12][0]:06X}; '
                          f'lowest SP where a pending ITI would be taken (SP < 0xFFFF4000): {e.min_sp_accept:#x}')
                # 0x00FBBE stores in rts's delay slot; the log carries the rts pc 0x00FBBC
                check(set(post) <= {(0x010352, 0xFFFF5B89), (0x00FBBC, 0xFFFF5B6C)}, f'{label}: post-DMA writes {post}')
    check(len(accept_sps) == 1, f'C accept SPs {accept_sps}')
    ACCEPT['sp'], ACCEPT['sp_a'] = accept_sps.pop()
    check(ACCEPT['sp'] == 0xFFFF1268 and ACCEPT['sp_a'] == 0xFFFFBF44,
          f'C lowest acceptable SPs {ACCEPT["sp"]:#x} {ACCEPT["sp_a"]:#x}')
    print(f'  {n} runs: region A all zero at the kernel start; cells {", ".join(hex(c) for c in CELLS)} = 0;'
          f' stack window low end(s) {sorted(hex(s) for s in stack_lows)}; lowest SP at which an ITI would be'
          f' accepted {ACCEPT["sp"]:#x} -> deepest ISR write {ACCEPT["sp"] - ISR_DEPTH:#x}; in range A (C phase)'
          f' {ACCEPT["sp_a"]:#x} -> {ACCEPT["sp_a"] - ISR_DEPTH:#x}')


# =====================================================================================
def pass_D():
    print('== D. 0x010448 RAM test')
    regions = [(A_LO, A_HI, APP_SP), (B_LO, B_HI, APP_SP), (C_LO, C_HI, 0xFFFFBF9C), (P_LO, P_HI, APP_SP)]
    for lo, hi, sp in regions:
        for cls_val in (0x0B01, 0x5001):
            e = Sys()
            rng = random.Random(lo ^ cls_val)
            e.ram[:] = bytearray(rng.randrange(256) for _ in range(len(e.ram)))
            e.init[:] = b'\x01' * len(e.init)
            e.hooks[0xFFFFF7C2] = lambda s, n, v=cls_val: v if n == 2 else v >> 8
            before = bytes(e.ram)
            reports = []
            e.stub(0x010800, fn=lambda em, rep=reports: rep.append((em.R[4] & 0xFFFF, em.R[5])))
            r = e.call(0x010448, regs={4: lo, 5: hi, 15: sp})
            e.cover()
            check(r == 'return', 'D return')
            r0 = e.R[0] & 0xFF
            stride, block, top = (16, 0x1000, 0xFFFFB000) if cls_val == 0x0B01 else (32, 0x4000, 0xFFFF8000)
            base = top
            while base > lo:
                base -= block
            heads = [lo] + list(range(base + block, hi + 1, block))
            words = {}
            for a in range(lo, hi + 1, 4):
                words[a] = 0x5AA5A55A
            npat = stride // 4
            for h in heads:
                for i in range(npat):
                    words[h + 4 * i] = L(0x11C88 + 4 * i)
            got_ok = all(int.from_bytes(e.ram[a - E.RAM_LO:a - E.RAM_LO + 4], 'big') == v for a, v in words.items())
            touched = sorted({a for pc, k, a, sz, v in e.log if k == 'rw'})
            outside = [a for a in touched if not (lo <= a <= hi) and not (sp - 0x200 <= a < sp)]
            unchanged_out = all(e.ram[i] == before[i] for i in range(len(before))
                                if not (lo <= E.RAM_LO + i <= hi) and not (sp - 0x200 <= E.RAM_LO + i < sp))
            print(f'  [{lo:#x},{hi:#x}] SDSR {cls_val:#06x}: r0={r0} stride {stride} block {block:#x} heads '
                  f'{[hex(h) for h in heads]} final pattern ok={got_ok} writes outside region+stack={len(outside)}'
                  f' reports={reports} steps={e.steps}')
            check(r0 == 0 and got_ok and not outside and unchanged_out and not reports,
                  f'D perfect RAM {lo:#x} {cls_val:#x}')
    # faults
    for lo, hi, sp, bad in ((A_LO, A_HI, APP_SP, 0xFFFF8EDC), (A_LO, A_HI, APP_SP, 0xFFFFBF9F),
                            (C_LO, C_HI, 0xFFFFBF9C, 0xFFFF0020), (P_LO, P_HI, APP_SP, 0xFFFF3000)):
        for andm, orm in ((0xFE, 0x00), (0xFF, 0x80)):
            e = Sys()
            e.init[:] = b'\x01' * len(e.init)
            e.fault[bad] = (andm, orm)
            reports = []
            e.stub(0x010800, fn=lambda em, rep=reports: rep.append((em.R[4] & 0xFFFF, em.R[5])))
            r = e.call(0x010448, regs={4: lo, 5: hi, 15: sp})
            r0 = e.R[0] & 0xFF
            code = 0x7000 if 0xFFFF0000 <= (bad & ~3) <= 0xFFFFBF9F else 0x7010
            attempts = sum(1 for pc, k, a, sz, v in e.log if k == 'rw' and pc == 0x0104AA)
            print(f'  fault at {bad:#x} (and {andm:#04x} or {orm:#04x}) in [{lo:#x},{hi:#x}]: r0={r0} attempts={attempts}'
                  f' reports={[(hex(c), hex(a)) for c, a in reports]}')
            check(r == 'return' and r0 == 1, 'D fault detected')
            check(reports and all(c == code for c, a in reports) and all(a == bad & ~3 for c, a in reports),
                  'D report code / address')
            check(attempts == 2, f'D two attempts ([0x0C4730] = 2), got {attempts}')


# =====================================================================================
def pass_E():
    print('== E. 0x010290 with a scribbling stub for 0x010448')
    for fa in (0, 1):
        for fb in (0, 1):
            for fc in (0, 1):
                e = Sys()
                rng = random.Random(fa * 4 + fb * 2 + fc)
                e.ram[:] = bytearray(rng.randrange(256) for _ in range(len(e.ram)))
                e.init[:] = b'\x01' * len(e.init)
                before = bytes(e.ram)
                calls = []

                def test(em, calls=calls, res={A_LO: fa, B_LO: fb, C_LO: fc}):
                    lo, hi = em.R[4], em.R[5]
                    calls.append((lo, hi, em.R[15], em.imask))
                    for a in range(lo, hi + 1):                    # scribble the whole region
                        em.write(a, 1, 0xEE)
                    em.R[0] = res[lo]
                e.imask = 13                                       # as set at 0x00FA82
                e.stub(0x010448, fn=test)
                r = e.call(0x010290, regs={15: APP_SP - 0x40})
                e.cover()
                check(r == 'return', 'E return')
                want = fa and 1 or (8 * fb + 2 * fc)
                got = e.ram[0xFFFF5B89 - E.RAM_LO]
                bc_ok = all(e.ram[i] == before[i] for i in range(0x2000)
                            if not (APP_SP - 0x80 <= E.RAM_LO + i < APP_SP))
                a_zero = all(b == 0 for i, b in enumerate(e.ram[A_LO - E.RAM_LO:A_HI - E.RAM_LO + 1])
                             if A_LO + i != 0xFFFF5B89)
                print(f'  A fail={fa} B fail={fb} C fail={fc}: tests '
                      f'{[(hex(lo), hex(hi), hex(sp), "I=%d" % im) for lo, hi, sp, im in calls]}'
                      f' -> 0xFFFF5B89 = {got} (want {want}); 0xFFFF0000..1FFF restored={bc_ok}; A zero={a_zero}; dma={len(e.dma)}')
                check(got == want and a_zero and len(e.dma) == 1, 'E result / fill')
                check(bc_ok or fa, 'E restore')
                exp_calls = [(A_LO, A_HI)] + ([] if fa else [(B_LO, B_HI), (C_LO, C_HI)])
                check([(lo, hi) for lo, hi, sp, im in calls] == exp_calls, 'E test order')
                check([im for lo, hi, sp, im in calls] == [13] + ([] if fa else [14, 13]), 'E mask: B test at I=14')
                if not fa:
                    check(calls[2][2] == 0xFFFFBF9C and calls[0][2] < APP_SP and calls[1][2] < APP_SP,
                          'E stack moved to the top of A for C only')
                    check(int.from_bytes(e.ram[0xFFFFBF9C - E.RAM_LO:0xFFFFBFA0 - E.RAM_LO], 'big') == 0,
                          'E saved-SP slot 0xFFFFBF9C zeroed by the DMA')


# =====================================================================================
def pass_F():
    print('== F. 0x010124 on the post-reset image (contract from revlim_freeze_gate_trace.txt)')
    for marker in (0xAA55, 0x1234):
        for res16 in (0, 1):
            e = Sys()
            rng = random.Random(marker + res16)
            e.ram[:] = bytearray(rng.randrange(256) for _ in range(len(e.ram)))
            e.init[:] = b'\x01' * len(e.init)
            for a in range(A_LO, A_HI + 1):
                e.ram[a - E.RAM_LO] = 0
            e.ram[0xFFFF2000 - E.RAM_LO:0xFFFF2002 - E.RAM_LO] = marker.to_bytes(2, 'big')
            before = bytes(e.ram)
            events = []

            def post(em, ev=events, res16=res16):
                ev.append(em.R[4] & 0xFFFF)
                if em.R[4] & 0xFFFF == 16:
                    em.write(0xFFFF5B8D, 1, res16)                 # 0x04793C's tail (0x01001C)
            e.stub(0x00FDB4, fn=post)
            r = e.call(0x010124, regs={15: APP_SP - 0x40})
            check(r == 'return', 'F return')
            region = bytes(e.ram[P_LO - E.RAM_LO:P_HI - E.RAM_LO + 1])
            cold = (marker != 0xAA55) or res16 == 1
            if cold:
                ok = region[:2] == b'\x55\xaa' and all(b == 0 for b in region[2:])
            else:
                ok = region == before[P_LO - E.RAM_LO:P_HI - E.RAM_LO + 1]
            print(f'  [0xFFFF2000]={marker:#06x}, event-16 result 5B8D={res16}: events {events};'
                  f' 0xFFFF2000..3FFF {"cleared, [2000]=0x55AA" if cold else "untouched"} ok={ok}')
            check(ok, 'F region')
            check(events == ([16] if marker == 0xAA55 else []) + ([18] if cold else []), 'F events')


# =====================================================================================
def accept_sp():
    if 'sp' not in ACCEPT:
        e = run_reset(fill_image('random', 9), 'accept-bound probe')
        ACCEPT['sp'], ACCEPT['sp_a'] = e.min_sp_accept, e.min_sp_accept_a
    return ACCEPT['sp']


def pass_G():
    print('== G. reset path with the WDT ITI accepted (vector 224, IPRL bits 7-4 = 14 > I = 13)')
    bound = accept_sp() - ISR_DEPTH
    cases = [('random', 3, True, 40), ('random', 3, False, 8), ('random', 5, True, 120),
             ('x5a', 0, False, 60), ('random', 7, True, 25)]
    deep_residue = in_A_frames = a_test_hits = 0
    for kind, seed, boot_marker, ipt in cases:
        img = fill_image(kind, seed)
        put32(img, 0xFFFFBFFC, 0x5AA5A55A if boot_marker else 0)
        put16(img, 0xFFFF2000, 0xAA55)
        before = bytes(img)
        label = f'{kind}{seed} boot_marker={int(boot_marker)} ipt={ipt}'
        e = run_reset(img, label, ipt=ipt, irq=True)
        after = bytes(e.ram)
        r32 = lambda a: int.from_bytes(after[a - E.RAM_LO:a - E.RAM_LO + 4], 'big')  # noqa: E731
        changed = [E.RAM_LO + i for i in range(len(after)) if after[i] != before[i]]
        in_c = [a for a in changed if C_LO <= a <= C_HI]
        open_step = e.first_step[0x00FA84]
        check(e.iti and all(st > open_step for pc, sp, low, st, ow in e.iti), f'{label}: ITIs only after 0x00FA82')
        check(not any(0x0102C2 <= pc <= 0x010300 for pc, sp, low, st, ow in e.iti), f'{label}: ITI inside the B section')
        check(r32(0xFFFF0004) == len(e.iti), f'{label}: 0xFFFF0004 {r32(0xFFFF0004)} != ITIs {len(e.iti)}')
        check(r32(0xFFFF0000) == 183 and after[8] == 0, f'{label}: 0xFFFF0000 / 0008')
        check(all(low == sp - ISR_DEPTH for pc, sp, low, st, ow in e.iti), f'{label}: ISR depth')
        check(all(ow == {(0xFFFF0004, 4)} for pc, sp, low, st, ow in e.iti), f'{label}: ISR writes outside its frame')
        check(all(b == 0 for b in after[A_LO - E.RAM_LO:A_HI - E.RAM_LO + 1]), f'{label}: region A not zero')
        check(all(after[a - E.RAM_LO] == before[a - E.RAM_LO] for a in range(P_LO, P_HI + 1) if a != 0xFFFF204C),
              f'{label}: 0xFFFF2000..3FFF changed')
        check(all(after[a - E.RAM_LO] == before[a - E.RAM_LO] for a in range(0xFFFF0009, 0xFFFF0020)),
              f'{label}: 0xFFFF0009..001F changed')
        check(all(bound <= a < APP_SP for a in in_c), f'{label}: C change below the bound {fmt_ranges(in_c)}')
        check(e.pget(IPRL, 2) == 0 and len(e.dma) == 1, f'{label}: IPRL / DMA')
        deep_residue += any(a < 0xFFFF125C for a in in_c)
        in_A_frames += any(sp >= A_LO for pc, sp, low, st, ow in e.iti)
        check(all(low >= ACCEPT['sp_a'] - ISR_DEPTH for pc, sp, low, st, ow in e.iti if sp >= A_LO),
              f'{label}: ISR frame in A below the bound')
        a_test_hits += any(0x0105AA <= pc < 0x010668 and sp < A_LO for pc, sp, low, st, ow in e.iti)
        where = sorted({(pc, sp) for pc, sp, low, st, ow in e.iti})
        print(f'  {label}: kernel start after {e.steps} steps; ITIs {len(e.iti)} = [0xFFFF0004] {r32(0xFFFF0004)};'
              f' changed in 0xFFFF0020..1FFF: {fmt_ranges(in_c)}')
        print('    ITI (pc, SP before entry), first 8 distinct: '
              + ', '.join(f'({pc:06X},{sp:#x})' for pc, sp in where[:8])
              + f'; deepest ISR write {min(low for pc, sp, low, st, ow in e.iti):#x}')
    check(deep_residue and in_A_frames and a_test_hits, 'G coverage: residue below 0xFFFF125C, frames in A, ITI in the A test')
    print(f'  bound for ISR residue in 0xFFFF0020..1FFF: lowest acceptable SP {accept_sp():#x} - {ISR_DEPTH:#x} = {bound:#x}')
    # boot-watchdog expiry: 183 ITIs before 0x00AE4E clears IPRL
    img = fill_image('random', 11)
    put32(img, 0xFFFFBFFC, 0x5AA5A55A)
    e = run_reset(img, 'expiry ipt=2', ipt=2, irq=True, stops=(KERNEL_START, HALT_SPIN), want=HALT_SPIN)
    r32 = lambda a: int.from_bytes(e.ram[a - E.RAM_LO:a - E.RAM_LO + 4], 'big')  # noqa: E731
    print(f'  expiry ipt=2: stopped at {HALT_SPIN:06X} (0x00FBA4 spin) after {e.steps} steps; ITIs {len(e.iti)};'
          f' [0xFFFF0004] = {r32(0xFFFF0004)}; 0x010800 calls {[(hex(c), hex(d)) for c, d in e.calls_10800]};'
          f' SR.I = {e.imask}; 0x003324 reached: {KERNEL_START in e.executed}')
    check(len(e.iti) == 183 and r32(0xFFFF0004) == 183 and e.calls_10800[-1] == (0x2100, 0) and e.imask == 15
          and KERNEL_START not in e.executed and e.pget(0xFFFFF590, 4) == 0, 'G expiry')


# =====================================================================================
def pass_H():
    print('== H. 0x010448 on ranges the ROM never passes (class 0: stride 16, block 0x1000)')

    def inside_predicted(lo, hi, stride=16, block=0x1000, top=0xFFFFB000):
        n = hi + 1 - lo
        base = top
        while base > lo:
            base -= block
        heads = [h for h in range(base + block, hi + 1, block) if h < hi]
        return n % stride == 0 and n >= stride and all(hi + 1 - h >= stride for h in heads)

    def outside_writes(lo, hi):
        e = Sys()
        e.init[:] = b'\x01' * len(e.init)
        e.stub(0x010800, fn=lambda em: None)
        r = e.call(0x010448, regs={4: lo, 5: hi, 15: APP_SP})
        check(r == 'return' and e.R[0] & 0xFF == 0, 'H return')
        return sorted({a & ~3 for pc, k, a, sz, v in e.log
                       if k == 'rw' and not (lo <= a <= hi) and not (APP_SP - 0x200 <= a < APP_SP)})

    fixed = [((0xFFFF6000, 0xFFFF6017), [0xFFFF6018, 0xFFFF601C]),
             ((0xFFFF6000, 0xFFFF7007), [0xFFFF7008, 0xFFFF700C]),
             ((0xFFFF6004, 0xFFFF6FFF), [0xFFFF7000]),
             ((0xFFFF600C, 0xFFFF700B), [0xFFFF700C])]
    for (lo, hi), want in fixed:
        got = outside_writes(lo, hi)
        print(f'  [{lo:#x},{hi:#x}] length {hi + 1 - lo:#x}: longs written past the range {[hex(a) for a in got]}')
        check(got == want, f'H {lo:#x}..{hi:#x}: {got}')
    rng = random.Random(4)
    agree = 0
    trial = [(0xFFFF6000, 0xFFFF600F), (0xFFFF6004, 0xFFFF6013), (0xFFFF6FF4, 0xFFFF7003)]
    for _ in range(40):
        lo = 0xFFFF6000 + 4 * rng.randrange(0x400)
        trial.append((lo, lo + 4 * rng.randrange(4, 0x600) - 1))
    for lo, hi in trial:
        pred = inside_predicted(lo, hi)
        got = outside_writes(lo, hi)
        check(pred == (not got), f'H prediction {lo:#x}..{hi:#x}: predicted inside={pred}, outside {got}')
        agree += 1
    for lo, hi in ((A_LO, A_HI), (B_LO, B_HI), (C_LO, C_HI), (P_LO, P_HI)):
        check(inside_predicted(lo, hi) and inside_predicted(lo, hi, 32, 0x4000, 0xFFFF8000), f'H ROM range {lo:#x}')
    print(f'  rule "length a multiple of the stride (>= 1 stride) and every block head h < end has end + 1 - h >='
          f' stride" <=> no write outside: {agree} ranges (3 fixed + 40 random) agree; the four ROM ranges satisfy it for both strides')


# =====================================================================================
def pass_I():
    print('== I. 0x0007E0: the argument test is (r4 & 0xFFFF) != 0')
    e = Sys()
    e.init[:] = b'\x01' * len(e.init)
    r = e.call(0x0007E0, regs={4: 0x00010000, 15: 0xFFFFBFA0}, stop_at={0x000804})
    print(f'  r4 = 0x00010000: stopped at {r}, r0 = {e.R[0]}, 0x000804 reached: {0x000804 in e.executed}')
    check(r == 'return' and e.R[0] == 1 and 0x000804 not in e.executed, 'I 0x10000')
    e = Sys()
    e.init[:] = b'\x01' * len(e.init)
    r = e.call(0x0007E0, regs={4: 0xFFFFFFFF, 15: 0xFFFFBFA0}, stop_at={0x000804})
    print(f'  r4 = 0xFFFFFFFF: stopped at {r:#08x} (loop entered, r10 = {e.R[10]:#x})')
    check(r == 0x000804 and e.R[10] == 0xFFFF, 'I -1')


# =====================================================================================
def pass_J():
    print('== J. stuck bit in range A on the full reset path (acceptance off)')
    img = fill_image('random', 21)
    put32(img, 0xFFFFBFFC, 0x5AA5A55A)
    before = bytes(img)
    e = run_reset(img, 'fault 0xFFFF8EDC and 0xFE', fault={0xFFFF8EDC: (0xFE, 0x00)})
    after = bytes(e.ram)
    in_p = [E.RAM_LO + i for i in range(P_LO - E.RAM_LO, P_HI - E.RAM_LO + 1) if after[i] != before[i]]
    wrote_p = sorted({a for pc, k, a, sz, v in e.log if k == 'rw' and P_LO <= a <= P_HI})
    print(f'  0xFFFF5B89 = {after[0xFFFF5B89 - E.RAM_LO]}; 0x010800 calls {[(hex(c), hex(d)) for c, d in e.calls_10800]};'
          f' writes in 0xFFFF2000..3FFF: {fmt_ranges(wrote_p)}')
    check(after[0xFFFF5B89 - E.RAM_LO] == 1 and e.calls_10800 and all(c == 0x7000 for c, d in e.calls_10800),
          'J result / reports')
    check(all(a == 0xFFFF204C or 0xFFFF2060 <= a <= 0xFFFF20A7 for a in wrote_p + in_p)
          and any(0xFFFF2060 <= a <= 0xFFFF20A7 for a in wrote_p), 'J log extent')


# =====================================================================================
def pass_Z():
    bins = sorted(glob.glob(os.path.join(REPO, 'rom', '*.bin')))
    imgs = [open(b, 'rb').read() for b in bins]
    imgs = [d for d in imgs if len(d) == len(ROM)]
    addrs = sorted(COVER)
    diff = [a for a in addrs if any(d[a] != ROM[a] for d in imgs)]
    print(f'== Z. {len(addrs)} ROM bytes executed or read in the passes run ({fmt_ranges(addrs)[:160]}...):'
          f' identical in {len(imgs) - len({i for i, d in enumerate(imgs) if any(d[a] != ROM[a] for a in addrs)})}'
          f' of {len(imgs)} 1 MB bins; differing bytes {len(diff)}')
    check(addrs and not diff, f'Z bytes differ: {[hex(a) for a in diff[:8]]}')


PASSES = dict(A=pass_A, B=pass_B, C=pass_C, D=pass_D, E=pass_E, F=pass_F, G=pass_G, H=pass_H, I=pass_I,
              J=pass_J, Z=pass_Z)

if __name__ == '__main__':
    sel = [a.upper() for a in sys.argv[1:]] or list(PASSES)
    for k in sel:
        try:
            PASSES[k]()
        except AssertionError:
            pass
    print('ALL PASSES OK' if not FAILS else f'FAILURES: {FAILS}')
    sys.exit(0 if not FAILS else 1)
