#!/usr/bin/env python3
"""SH-2E (SH7058) instruction-level emulator -- flash-safety gate 8 of docs/pipeline-plan.md.

    python3 scripts/sh2e_emu.py --selftest          # validate against the oracles below

    import sh2e_emu as E
    emu = E.Emu(open(bin, 'rb').read())
    emu.ram_f32(0xFFFF6624, 4000.0)
    emu.stub(0x022CF4, r0=0)                      # replace a callee
    emu.call(0x03B668, stop_at={0x03D2FC})
    emu.read_u8(0xFFFF7CB9)

WHY A HAND-WRITTEN EMULATOR, AND WHY TO BELIEVE IT
Ghidra's p-code emulator is not installed here, and it decodes SH-2A, a superset.
This one executes only SH-2E. Its decoder is separate from scripts/sh2e_disasm.py
(it works from bit fields, not text), and **every executed instruction is
cross-checked against sh2e_disasm**. A disagreement between the two stops the run.
It is validated (--selftest) against oracles that do not depend on it:

  1. the ECU's own checksum routine 0x01002A vs scripts/rom_checksum.py, on all
     bins and on a mutated bin (loops, loads, compare, branch, delay slots)
  2. float_clamp_range 0x0BE56C vs a Python clamp over a grid (FPU compare)
  3. table_lookup 0x0BE830 vs linear interpolation of desc_types.read_table()
     over many 1-D descriptors of every cell type (FPU arithmetic, dispatch,
     bsr/jsr, integer->float, fmac)
  4. the ROM's divide 0x0BE654 vs Python over 1,013 cases (div0s/div1/rotcl/subc/
     addc). It is a SATURATING SIGNED 16.16 FIXED-POINT divide, (a<<16)/b
     truncated -- not the "32-bit unsigned divide" its Ghidra label says
     (corrections item 102)

SEMANTICS NOTES (each is a place it could differ from silicon)
* Single-precision results are computed in double and rounded to float32. For
  fadd/fsub/fmul/fdiv that is correctly rounded. fmac is rounded once (fused),
  which the SH-2E may not do -- it is flagged when executed (emu.notes).
* Denormal inputs/outputs flush to signed zero (the SH-2E FPU has no denormals).
* A PC-relative load in a delay slot uses the slot's own address as PC.
* Any access outside ROM (0x000000-0x0FFFFF) and on-chip RAM (0xFFFF0000-0xFFFFBFFF)
  raises, unless mapped with emu.mmio(). Misaligned word/long access raises
  (address error on the chip). A write to ROM raises.
* Reading RAM nobody initialised is allowed but recorded (emu.uninit_reads):
  those are the inputs a test forgot to set.
* mac.l / mac.w / trapa / sleep / rte / ldc sr raise: unexpected in patch-sized code.
"""
import math
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import sh2e_disasm as D  # noqa: E402

M32 = 0xFFFFFFFF
ROM_END = 0x100000
RAM_LO, RAM_HI = 0xFFFF0000, 0xFFFFBFFF
RETURN_MAGIC = 0x7FFFFFF0          # PR on entry; reaching it means the call returned
STACK_TOP = 0xFFFFBF00


class EmuError(Exception):
    pass


def s32(x):
    x &= M32
    return x - 0x100000000 if x & 0x80000000 else x


def sext(x, bits):
    x &= (1 << bits) - 1
    return x - (1 << bits) if x >> (bits - 1) else x


def f2b(f):
    """float -> float32 bits, rounding and flushing denormals."""
    if f != f:
        return 0x7FBFFFFF
    try:
        b = struct.unpack('>I', struct.pack('>f', f))[0]
    except OverflowError:
        b = 0xFF800000 if f < 0 else 0x7F800000
    if (b & 0x7F800000) == 0 and (b & 0x007FFFFF):
        b &= 0x80000000
    return b


def b2f(b):
    if (b & 0x7F800000) == 0:
        b &= 0x80000000
    return struct.unpack('>f', struct.pack('>I', b & M32))[0]


class Emu:
    def __init__(self, rom, trace=False):
        if len(rom) != ROM_END:
            raise EmuError(f'ROM is {len(rom):#x} bytes')
        self.rom = bytes(rom)
        self.ram = bytearray(RAM_HI - RAM_LO + 1)
        self.init = bytearray(RAM_HI - RAM_LO + 1)
        self.R = [0] * 16
        self.FR = [0] * 16                  # float32 BITS
        self.pc = 0
        self.pr = 0
        self.gbr = self.vbr = 0
        self.mach = self.macl = 0
        self.fpul = 0
        self.fpscr = 0x00040001
        self.T = self.S = self.Q = self.M = 0
        self.stubs = {}
        self.mmios = {}
        self.uninit_reads = set()
        self.writes = {}
        self.notes = set()
        self.steps = 0
        self.trace = trace
        self.executed = set()
        self.stack_low = STACK_TOP

    # ---------------- memory ----------------
    def mmio(self, addr, value):
        self.mmios[addr] = value

    def _ram(self, a, n):
        return RAM_LO <= a and a + n - 1 <= RAM_HI

    def read(self, a, n):
        a &= M32
        if n > 1 and a % n:
            raise EmuError(f'misaligned {n}-byte read at {a:#010x} (pc {self.pc:06X})')
        if a + n <= ROM_END:
            return int.from_bytes(self.rom[a:a + n], 'big')
        if self._ram(a, n):
            o = a - RAM_LO
            if not all(self.init[o:o + n]):
                self.uninit_reads.add(a)
            return int.from_bytes(self.ram[o:o + n], 'big')
        if a in self.mmios:
            return self.mmios[a] & ((1 << (8 * n)) - 1)
        raise EmuError(f'{n}-byte read of unmapped {a:#010x} (pc {self.pc:06X})')

    def write(self, a, n, v):
        a &= M32
        if n > 1 and a % n:
            raise EmuError(f'misaligned {n}-byte write at {a:#010x} (pc {self.pc:06X})')
        if a < ROM_END:
            raise EmuError(f'write to ROM {a:#08x} (pc {self.pc:06X})')
        if not self._ram(a, n):
            raise EmuError(f'{n}-byte write to unmapped {a:#010x} (pc {self.pc:06X})')
        o = a - RAM_LO
        self.ram[o:o + n] = (v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big')
        self.init[o:o + n] = b'\x01' * n
        if not (self.stack_low - 64 <= a < STACK_TOP):
            for i in range(n):
                self.writes[a + i] = self.ram[o + i]

    # convenience for tests
    def ram_u8(self, a, v): self.write(a, 1, v); self.writes.pop(a, None)
    def ram_u16(self, a, v): self.write(a, 2, v); [self.writes.pop(a + i, None) for i in range(2)]
    def ram_u32(self, a, v): self.write(a, 4, v); [self.writes.pop(a + i, None) for i in range(4)]
    def ram_f32(self, a, f): self.ram_u32(a, f2b(f))
    def read_u8(self, a): return self.read(a, 1)
    def read_u16(self, a): return self.read(a, 2)
    def read_u32(self, a): return self.read(a, 4)
    def read_f32(self, a): return b2f(self.read(a, 4))

    def fr(self, n): return b2f(self.FR[n])
    def set_fr(self, n, f): self.FR[n] = f2b(f)

    def stub(self, addr, r0=None, fr0=None, fn=None):
        """Replace the function at addr: set r0/fr0 (or run fn(emu)) and return."""
        self.stubs[addr] = (r0, fr0, fn)

    # ---------------- running ----------------
    def call(self, entry, regs=None, fregs=None, stop_at=(), max_steps=5_000_000):
        """Run from entry until it returns (PR magic) or reaches a pc in stop_at."""
        self.R[15] = STACK_TOP
        for k, v in (regs or {}).items():
            self.R[k] = v & M32
        for k, v in (fregs or {}).items():
            self.set_fr(k, v)
        self.pr = RETURN_MAGIC
        self.pc = entry
        stop_at = set(stop_at)
        while True:
            if self.pc == RETURN_MAGIC:
                return 'return'
            if self.pc in stop_at:
                return self.pc
            if self.pc in self.stubs:
                r0, fr0, fn = self.stubs[self.pc]
                if fn:
                    fn(self)
                if r0 is not None:
                    self.R[0] = r0 & M32
                if fr0 is not None:
                    self.set_fr(0, fr0)
                self.pc = self.pr
                continue
            if self.steps >= max_steps:
                raise EmuError(f'step limit {max_steps} at pc {self.pc:06X}')
            self.step()

    def fetch(self, pc):
        if pc >= ROM_END or pc & 1:
            raise EmuError(f'fetch from {pc:#010x}')
        return int.from_bytes(self.rom[pc:pc + 2], 'big')

    def step(self):
        pc = self.pc
        w = self.fetch(pc)
        res = self.execute(w, pc, slot=False)
        self.steps += 1
        if res is None:
            self.pc = pc + 2
            return
        kind, target = res
        if kind == 'now':                    # bt / bf taken, no delay slot
            self.pc = target
            return
        # delayed branch: run the slot, then jump
        sw = self.fetch(pc + 2)
        sres = self.execute(sw, pc + 2, slot=True)
        self.steps += 1
        if sres is not None:
            raise EmuError(f'branch in delay slot at {pc + 2:06X}')
        self.pc = target

    def _check(self, w, pc, mn):
        txt, _ = D.decode(w, pc)
        ref = txt.split()[0]
        if ref != mn:
            raise EmuError(f'decoder disagreement at {pc:06X} ({w:04X}): emulator {mn!r}, sh2e_disasm {txt!r}')

    # ---------------- the instruction set ----------------
    def execute(self, w, pc, slot):
        R, n, m = self.R, (w >> 8) & 15, (w >> 4) & 15
        d4, d8, op = w & 15, w & 0xFF, w >> 12
        self.executed.add(pc)
        mn = self._exec(w, pc, slot, R, n, m, d4, d8, op)
        name = mn[0] if isinstance(mn, tuple) else mn
        self._check(w, pc, name)
        if self.trace:
            print(f'{pc:06X} {w:04X} {D.decode(w, pc)[0]}')
        if R[15] < self.stack_low:
            self.stack_low = R[15]
        return mn[1] if isinstance(mn, tuple) else None

    def _pcrel_l(self, pc, d8): return ((pc + 4) & ~3) + d8 * 4
    def _pcrel_w(self, pc, d8): return pc + 4 + d8 * 2

    def _exec(self, w, pc, slot, R, n, m, d4, d8, op):
        rd = self.read
        wr = self.write
        if w == 0x0009: return 'nop'
        if w == 0x000B: return ('rts', ('delay', self.pr))
        if w == 0x0008: self.T = 0; return 'clrt'
        if w == 0x0018: self.T = 1; return 'sett'
        if w == 0x0028: self.mach = self.macl = 0; return 'clrmac'
        if w == 0x0048: self.S = 0; return 'clrs'
        if w == 0x0058: self.S = 1; return 'sets'
        if w == 0x0019: self.M = self.Q = self.T = 0; return 'div0u'
        if w in (0x001B, 0x002B):
            raise EmuError(f'{pc:06X}: sleep/rte not supported')
        if op == 0x0:
            if d4 == 0x4: wr(R[0] + R[n], 1, R[m]); return 'mov.b'
            if d4 == 0x5: wr(R[0] + R[n], 2, R[m]); return 'mov.w'
            if d4 == 0x6: wr(R[0] + R[n], 4, R[m]); return 'mov.l'
            if d4 == 0x7: self.macl = (R[n] * R[m]) & M32; return 'mul.l'
            if d4 == 0xC: R[n] = sext(rd(R[0] + R[m], 1), 8) & M32; return 'mov.b'
            if d4 == 0xD: R[n] = sext(rd(R[0] + R[m], 2), 16) & M32; return 'mov.w'
            if d4 == 0xE: R[n] = rd(R[0] + R[m], 4); return 'mov.l'
            if d4 == 0xF: raise EmuError(f'{pc:06X}: mac.l not supported')
            if d4 == 0x3:
                if m == 0: self.pr = pc + 4; return ('bsrf', ('delay', (pc + 4 + R[n]) & M32))
                if m == 2: return ('braf', ('delay', (pc + 4 + R[n]) & M32))
            if d4 == 0xA:
                src = {0: self.mach, 1: self.macl, 2: self.pr, 5: self.fpul, 6: self.fpscr}.get(m)
                if src is not None:
                    R[n] = src & M32; return 'sts'
            if d4 == 0x2:
                src = {0: self.sr(), 1: self.gbr, 2: self.vbr}.get(m)
                if src is not None:
                    R[n] = src & M32; return 'stc'
            if d4 == 0x9 and m == 2: R[n] = self.T; return 'movt'
            raise EmuError(f'{pc:06X}: undecodable {w:04X}')
        if op == 0x1: wr(R[n] + d4 * 4, 4, R[m]); return 'mov.l'
        if op == 0x2:
            if d4 == 0: wr(R[n], 1, R[m]); return 'mov.b'
            if d4 == 1: wr(R[n], 2, R[m]); return 'mov.w'
            if d4 == 2: wr(R[n], 4, R[m]); return 'mov.l'
            if d4 in (4, 5, 6):
                sz = {4: 1, 5: 2, 6: 4}[d4]
                v = R[m]
                R[n] = (R[n] - sz) & M32
                wr(R[n], sz, v); return {4: 'mov.b', 5: 'mov.w', 6: 'mov.l'}[d4]
            if d4 == 7:
                self.Q, self.M = R[n] >> 31, R[m] >> 31; self.T = self.Q ^ self.M; return 'div0s'
            if d4 == 8: self.T = int((R[n] & R[m]) == 0); return 'tst'
            if d4 == 9: R[n] &= R[m]; return 'and'
            if d4 == 0xA: R[n] ^= R[m]; return 'xor'
            if d4 == 0xB: R[n] |= R[m]; return 'or'
            if d4 == 0xC:
                x = R[n] ^ R[m]
                self.T = int(any(((x >> s) & 0xFF) == 0 for s in (0, 8, 16, 24))); return 'cmp/str'
            if d4 == 0xD: R[n] = ((R[m] << 16) | (R[n] >> 16)) & M32; return 'xtrct'
            if d4 == 0xE: self.macl = (R[n] & 0xFFFF) * (R[m] & 0xFFFF) & M32; return 'mulu.w'
            if d4 == 0xF: self.macl = (sext(R[n], 16) * sext(R[m], 16)) & M32; return 'muls.w'
            raise EmuError(f'{pc:06X}: undecodable {w:04X}')
        if op == 0x3:
            a, b = R[n], R[m]
            if d4 == 0: self.T = int(a == b); return 'cmp/eq'
            if d4 == 2: self.T = int(a >= b); return 'cmp/hs'
            if d4 == 3: self.T = int(s32(a) >= s32(b)); return 'cmp/ge'
            if d4 == 4: self._div1(n, m); return 'div1'
            if d4 == 5: p = a * b; self.mach, self.macl = (p >> 32) & M32, p & M32; return 'dmulu.l'
            if d4 == 6: self.T = int(a > b); return 'cmp/hi'
            if d4 == 7: self.T = int(s32(a) > s32(b)); return 'cmp/gt'
            if d4 == 8: R[n] = (a - b) & M32; return 'sub'
            if d4 == 0xA:
                r = a - b - self.T; self.T = int(r < 0); R[n] = r & M32; return 'subc'
            if d4 == 0xB:
                r = s32(a) - s32(b); self.T = int(r < -2**31 or r >= 2**31); R[n] = r & M32; return 'subv'
            if d4 == 0xC: R[n] = (a + b) & M32; return 'add'
            if d4 == 0xD:
                p = s32(a) * s32(b); self.mach, self.macl = (p >> 32) & M32, p & M32; return 'dmuls.l'
            if d4 == 0xE:
                r = a + b + self.T; self.T = int(r > M32); R[n] = r & M32; return 'addc'
            if d4 == 0xF:
                r = s32(a) + s32(b); self.T = int(r < -2**31 or r >= 2**31); R[n] = r & M32; return 'addv'
            raise EmuError(f'{pc:06X}: undecodable {w:04X}')
        if op == 0x4:
            k = w & 0xFF
            x = R[n]
            if k == 0x00: self.T = x >> 31; R[n] = (x << 1) & M32; return 'shll'
            if k == 0x01: self.T = x & 1; R[n] = x >> 1; return 'shlr'
            if k == 0x04: self.T = x >> 31; R[n] = ((x << 1) | self.T) & M32; return 'rotl'
            if k == 0x05: self.T = x & 1; R[n] = (x >> 1) | (self.T << 31); return 'rotr'
            if k == 0x08: R[n] = (x << 2) & M32; return 'shll2'
            if k == 0x09: R[n] = x >> 2; return 'shlr2'
            if k == 0x10: R[n] = (x - 1) & M32; self.T = int(R[n] == 0); return 'dt'
            if k == 0x11: self.T = int(s32(x) >= 0); return 'cmp/pz'
            if k == 0x15: self.T = int(s32(x) > 0); return 'cmp/pl'
            if k == 0x18: R[n] = (x << 8) & M32; return 'shll8'
            if k == 0x19: R[n] = x >> 8; return 'shlr8'
            if k == 0x20: self.T = x >> 31; R[n] = (x << 1) & M32; return 'shal'
            if k == 0x21: self.T = x & 1; R[n] = (x >> 1) | (x & 0x80000000); return 'shar'
            if k == 0x24:
                t = x >> 31; R[n] = ((x << 1) | self.T) & M32; self.T = t; return 'rotcl'
            if k == 0x25:
                t = x & 1; R[n] = (x >> 1) | (self.T << 31); self.T = t; return 'rotcr'
            if k == 0x28: R[n] = (x << 16) & M32; return 'shll16'
            if k == 0x29: R[n] = x >> 16; return 'shlr16'
            push = {0x02: lambda: self.mach, 0x12: lambda: self.macl, 0x22: lambda: self.pr,
                    0x52: lambda: self.fpul, 0x62: lambda: self.fpscr}
            if k in push:
                R[n] = (x - 4) & M32; wr(R[n], 4, push[k]()); return 'sts.l'
            pop = {0x06: 'mach', 0x16: 'macl', 0x26: 'pr', 0x56: 'fpul', 0x66: 'fpscr'}
            if k in pop:
                v = rd(x, 4); R[n] = (x + 4) & M32; setattr(self, pop[k], v); return 'lds.l'
            lds = {0x0A: 'mach', 0x1A: 'macl', 0x2A: 'pr', 0x5A: 'fpul', 0x6A: 'fpscr'}
            if k in lds:
                setattr(self, lds[k], x); return 'lds'
            if k == 0x13: R[n] = (x - 4) & M32; wr(R[n], 4, self.gbr); return 'stc.l'
            if k == 0x03: R[n] = (x - 4) & M32; wr(R[n], 4, self.sr()); return 'stc.l'
            if k == 0x23: R[n] = (x - 4) & M32; wr(R[n], 4, self.vbr); return 'stc.l'
            if k == 0x17: self.gbr = rd(x, 4); R[n] = (x + 4) & M32; return 'ldc.l'
            if k == 0x1E: self.gbr = x; return 'ldc'
            if k in (0x07, 0x0E): raise EmuError(f'{pc:06X}: write to SR not supported')
            if k == 0x0B: self.pr = pc + 4; return ('jsr', ('delay', x))
            if k == 0x2B: return ('jmp', ('delay', x))
            if k == 0x1B:
                b = rd(x, 1); self.T = int(b == 0); wr(x, 1, b | 0x80); return 'tas.b'
            if d4 == 0xF: raise EmuError(f'{pc:06X}: mac.w not supported')
            raise EmuError(f'{pc:06X}: undecodable {w:04X}')
        if op == 0x5: R[n] = rd(R[m] + d4 * 4, 4); return 'mov.l'
        if op == 0x6:
            x = R[m]
            if d4 in (0, 1, 2):
                sz = 1 << d4; R[n] = sext(rd(x, sz), 8 * sz) & M32
                return ['mov.b', 'mov.w', 'mov.l'][d4]
            if d4 == 3: R[n] = x; return 'mov'
            if d4 in (4, 5, 6):
                sz = 1 << (d4 - 4); v = sext(rd(x, sz), 8 * sz) & M32
                R[m] = (x + sz) & M32; R[n] = v
                return ['mov.b', 'mov.w', 'mov.l'][d4 - 4]
            if d4 == 7: R[n] = (~x) & M32; return 'not'
            if d4 == 8: R[n] = (x & 0xFFFF0000) | ((x & 0xFF) << 8) | ((x >> 8) & 0xFF); return 'swap.b'
            if d4 == 9: R[n] = ((x << 16) | (x >> 16)) & M32; return 'swap.w'
            if d4 == 0xA:
                r = -x - self.T; self.T = int(r < 0); R[n] = r & M32; return 'negc'
            if d4 == 0xB: R[n] = (-x) & M32; return 'neg'
            if d4 == 0xC: R[n] = x & 0xFF; return 'extu.b'
            if d4 == 0xD: R[n] = x & 0xFFFF; return 'extu.w'
            if d4 == 0xE: R[n] = sext(x, 8) & M32; return 'exts.b'
            if d4 == 0xF: R[n] = sext(x, 16) & M32; return 'exts.w'
        if op == 0x7: R[n] = (R[n] + sext(d8, 8)) & M32; return 'add'
        if op == 0x8:
            sub = n
            if sub == 0x0: wr(R[m] + d4, 1, R[0]); return 'mov.b'
            if sub == 0x1: wr(R[m] + d4 * 2, 2, R[0]); return 'mov.w'
            if sub == 0x4: R[0] = sext(rd(R[m] + d4, 1), 8) & M32; return 'mov.b'
            if sub == 0x5: R[0] = sext(rd(R[m] + d4 * 2, 2), 16) & M32; return 'mov.w'
            if sub == 0x8: self.T = int(R[0] == (sext(d8, 8) & M32)); return 'cmp/eq'
            tgt = pc + 4 + sext(d8, 8) * 2
            if sub == 0x9: return ('bt', ('now', tgt) if self.T else None)
            if sub == 0xB: return ('bf', ('now', tgt) if not self.T else None)
            if sub == 0xD: return ('bt/s', ('delay', tgt) if self.T else ('delay', pc + 4))
            if sub == 0xF: return ('bf/s', ('delay', tgt) if not self.T else ('delay', pc + 4))
            raise EmuError(f'{pc:06X}: undecodable {w:04X}')
        if op == 0x9:
            if slot: self.notes.add(f'{pc:06X}: PC-relative load in delay slot')
            R[n] = sext(rd(self._pcrel_w(pc, d8), 2), 16) & M32; return 'mov.w'
        if op == 0xA: return ('bra', ('delay', pc + 4 + sext(w & 0xFFF, 12) * 2))
        if op == 0xB:
            self.pr = pc + 4; return ('bsr', ('delay', pc + 4 + sext(w & 0xFFF, 12) * 2))
        if op == 0xC:
            sub, g = n, self.gbr
            if sub == 0x0: wr(g + d8, 1, R[0]); return 'mov.b'
            if sub == 0x1: wr(g + d8 * 2, 2, R[0]); return 'mov.w'
            if sub == 0x2: wr(g + d8 * 4, 4, R[0]); return 'mov.l'
            if sub == 0x3: raise EmuError(f'{pc:06X}: trapa')
            if sub == 0x4: R[0] = sext(rd(g + d8, 1), 8) & M32; return 'mov.b'
            if sub == 0x5: R[0] = sext(rd(g + d8 * 2, 2), 16) & M32; return 'mov.w'
            if sub == 0x6: R[0] = rd(g + d8 * 4, 4); return 'mov.l'
            if sub == 0x7:
                if slot: self.notes.add(f'{pc:06X}: mova in delay slot')
                R[0] = self._pcrel_l(pc, d8); return 'mova'
            if sub == 0x8: self.T = int((R[0] & d8) == 0); return 'tst'
            if sub == 0x9: R[0] &= d8; return 'and'
            if sub == 0xA: R[0] ^= d8; return 'xor'
            if sub == 0xB: R[0] |= d8; return 'or'
            a = (g + R[0]) & M32
            b = rd(a, 1)
            if sub == 0xC: self.T = int((b & d8) == 0); return 'tst.b'
            if sub == 0xD: wr(a, 1, b & d8); return 'and.b'
            if sub == 0xE: wr(a, 1, b ^ d8); return 'xor.b'
            if sub == 0xF: wr(a, 1, b | d8); return 'or.b'
        if op == 0xD:
            if slot: self.notes.add(f'{pc:06X}: PC-relative load in delay slot')
            R[n] = rd(self._pcrel_l(pc, d8), 4); return 'mov.l'
        if op == 0xE: R[n] = sext(d8, 8) & M32; return 'mov'
        if op == 0xF:
            return self._fpu(w, pc, R, n, m, d4)
        raise EmuError(f'{pc:06X}: undecodable {w:04X}')

    def _fpu(self, w, pc, R, n, m, d4):
        F = self.FR
        fn, fm = b2f(F[n]), b2f(F[m])
        if d4 == 0x0: self.set_fr(n, fn + fm); return 'fadd'
        if d4 == 0x1: self.set_fr(n, fn - fm); return 'fsub'
        if d4 == 0x2: self.set_fr(n, fn * fm); return 'fmul'
        if d4 == 0x3:
            if fm == 0.0:
                self.set_fr(n, math.copysign(math.inf, fn) * math.copysign(1, fm) if fn != 0 else math.nan)
            else:
                self.set_fr(n, fn / fm)
            return 'fdiv'
        if d4 == 0x4: self.T = int(fn == fm); return 'fcmp/eq'
        if d4 == 0x5: self.T = int(fn > fm); return 'fcmp/gt'
        if d4 == 0x6: F[n] = self.read(R[0] + R[m], 4); return 'fmov.s'
        if d4 == 0x7: self.write(R[0] + R[n], 4, F[m]); return 'fmov.s'
        if d4 == 0x8: F[n] = self.read(R[m], 4); return 'fmov.s'
        if d4 == 0x9: F[n] = self.read(R[m], 4); R[m] = (R[m] + 4) & M32; return 'fmov.s'
        if d4 == 0xA: self.write(R[n], 4, F[m]); return 'fmov.s'
        if d4 == 0xB: R[n] = (R[n] - 4) & M32; self.write(R[n], 4, F[m]); return 'fmov.s'
        if d4 == 0xC: F[n] = F[m]; return 'fmov'
        if d4 == 0xE:
            self.notes.add(f'{pc:06X}: fmac (rounded once here; check the SH-2E manual if a result is marginal)')
            self.set_fr(n, b2f(F[0]) * fm + fn); return 'fmac'
        if d4 == 0xD:
            if m == 0x0: F[n] = self.fpul; return 'fsts'
            if m == 0x1: self.fpul = F[n]; return 'flds'
            if m == 0x2: self.set_fr(n, float(s32(self.fpul))); return 'float'
            if m == 0x3:
                if fn != fn:
                    v = 0x80000000
                elif fn >= 2**31:
                    v = 0x7FFFFFFF
                elif fn < -2**31:
                    v = 0x80000000
                else:
                    v = int(fn) & M32
                self.fpul = v; return 'ftrc'
            if m == 0x4: F[n] ^= 0x80000000; return 'fneg'
            if m == 0x5: F[n] &= 0x7FFFFFFF; return 'fabs'
            if m == 0x8: F[n] = 0; return 'fldi0'
            if m == 0x9: F[n] = 0x3F800000; return 'fldi1'
        raise EmuError(f'{pc:06X}: {w:04X} is not an SH-2E FPU instruction')

    def sr(self):
        return self.T | (self.S << 1) | (self.Q << 8) | (self.M << 9) | 0xF0

    def _div1(self, n, m):
        R = self.R
        old_q = self.Q
        self.Q = (R[n] >> 31) & 1
        tmp2 = R[m]
        R[n] = ((R[n] << 1) | self.T) & M32
        tmp0 = R[n]
        if old_q == 0:
            if self.M == 0:
                R[n] = (R[n] - tmp2) & M32
                tmp1 = int(R[n] > tmp0)
                self.Q = tmp1 if self.Q == 0 else int(tmp1 == 0)
            else:
                R[n] = (R[n] + tmp2) & M32
                tmp1 = int(R[n] < tmp0)
                self.Q = int(tmp1 == 0) if self.Q == 0 else tmp1
        else:
            if self.M == 0:
                R[n] = (R[n] + tmp2) & M32
                tmp1 = int(R[n] < tmp0)
                self.Q = tmp1 if self.Q == 0 else int(tmp1 == 0)
            else:
                R[n] = (R[n] - tmp2) & M32
                tmp1 = int(R[n] > tmp0)
                self.Q = int(tmp1 == 0) if self.Q == 0 else tmp1
        self.T = int(self.Q == self.M)


# ---------------------------------------------------------------- selftest
REPO = os.path.dirname(HERE)


def _selftest_checksum(results):
    import glob
    import rom_checksum as CK
    bins = sorted(glob.glob(os.path.join(REPO, 'rom', '*.bin')))
    for path in bins[:3] + [None]:
        if path is None:
            rom = bytearray(open(bins[0], 'rb').read()); rom[0x0C0000] ^= 1; rom = bytes(rom); name = 'mutated'
        else:
            rom = open(path, 'rb').read(); name = os.path.basename(path)
        py_ok = not CK.check(rom)[0]
        statuses = []
        for idx in range(CK.RECORDS):
            emu = Emu(rom)
            failed = []
            emu.stub(0x0106B6, fn=lambda e: failed.append('0x0106B6'))
            emu.stub(0x010800, fn=lambda e: failed.append('0x010800'))
            emu.call(0x01002A, regs={4: idx})
            statuses.append(emu.R[0] & 0xFF)
        ecu_ok = all(s == 0 for s in statuses)
        results.append((f'checksum routine 0x01002A, {name}', ecu_ok == py_ok,
                        f'ECU says {"valid" if ecu_ok else "INVALID"}, rom_checksum.py says {"valid" if py_ok else "INVALID"}'))


def _selftest_clamp(results):
    emu0 = Emu(open(os.path.join(REPO, 'rom', 'ae5l600l.bin'), 'rb').read())
    bad = 0
    vals = [-1e6, -2.5, -0.5, -0.0, 0.0, 0.25, 0.5, 1.0, 3.75, 1e6]
    for x in vals:
        for lo in vals:
            for hi in vals:
                if lo > hi:
                    continue
                emu = Emu(emu0.rom)
                emu.call(0x0BE56C, fregs={4: x, 5: lo, 6: hi})
                want = lo if x <= lo else (hi if x >= hi else x)
                if emu.fr(0) != want:
                    bad += 1
    results.append(('float_clamp_range 0x0BE56C, 550 cases', bad == 0, f'{bad} mismatches'))


def _interp(axis, vals, x):
    if x <= axis[0]:
        return vals[0]
    if x >= axis[-1]:
        return vals[-1]
    for i in range(len(axis) - 1):
        if axis[i] <= x <= axis[i + 1]:
            f = (x - axis[i]) / (axis[i + 1] - axis[i])
            return vals[i] + f * (vals[i + 1] - vals[i])


def _selftest_lookup(results):
    import desc_types as T
    sys.path.insert(0, os.path.join(HERE, 'mapping'))
    rom = open(os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19d.bin'), 'rb').read()
    import table_triage as TT          # descriptor census (descriptor_map.txt), filtered below

    def normal(v):
        return v == 0.0 or 1e-30 < abs(v) < 1e7

    descs = []
    for a in TT.descriptor_candidates():
        try:
            if T.is_2d(rom, a) or T.typecode(rom, a) not in T.TYPE_SIZES:
                continue
            n = int.from_bytes(rom[a:a + 2], 'big')
            if not 2 <= n <= 64:
                continue
            t = T.read_table(rom, a)
            ax = t['axes']['x']
            if all(ax[i] < ax[i + 1] for i in range(n - 1)) and all(normal(v) for v in ax + t['values']):
                descs.append(a)
        except Exception:
            pass
    by_type, tested, bad, worst = {}, 0, 0, ''
    for a in descs:
        t = T.read_table(rom, a)
        if by_type.get(t['typecode'], 0) >= 40:
            continue
        by_type[t['typecode']] = by_type.get(t['typecode'], 0) + 1
        ax, vals = t['axes']['x'], t['values']
        span = ax[-1] - ax[0]
        for x in [ax[0] - span * 0.1, ax[0]] + [ax[i] + (ax[i + 1] - ax[i]) * k for i in range(len(ax) - 1)
                                                 for k in (0.25, 0.5, 0.9)] + [ax[-1], ax[-1] + span * 0.1]:
            x = b2f(f2b(x))
            emu = Emu(rom)
            emu.call(0x0BE830, regs={4: a}, fregs={4: x})
            got, want = emu.fr(0), _interp(ax, vals, x)
            tested += 1
            tol = 1e-4 * max(1.0, abs(want), max(abs(v) for v in vals))
            if not abs(got - want) <= tol:
                bad += 1
                worst = worst or f'{a:#x} x={x}: emu {got} vs oracle {want}'
    results.append((f'table_lookup 0x0BE830, {sum(by_type.values())} descriptors '
                    f'({", ".join(f"{T.TYPE_NAMES[k]} {v}" for k, v in sorted(by_type.items()))}), {tested} points',
                    bad == 0 and tested > 0, f'{bad} mismatches {worst}'))


def _selftest_div(results):
    import random
    rom = open(os.path.join(REPO, 'rom', 'ae5l600l.bin'), 'rb').read()
    rnd = random.Random(1)
    cases = [(7, 2), (-7, 2), (7, -2), (-7, -2), (0, 5), (0, 0), (5, 0), (-5, 0), (-2**31, -1),
             (2**31 - 1, 1), (-2**31, 1), (100, 7), (1, 3), (-1, 3)]
    cases += [(rnd.randint(-2**31, 2**31 - 1), rnd.choice([rnd.randint(-2**31, 2**31 - 1), rnd.randint(-300, 300) or 1]))
              for _ in range(500)]
    cases += [(rnd.randint(-70000, 70000), rnd.randint(1, 2**20) * rnd.choice([1, -1])) for _ in range(500)]

    def want(a, b):
        if b == 0:
            return 0 if a == 0 else (2**31 - 1 if a > 0 else -2**31)
        q = abs(a * 65536) // abs(b)
        q = q if (a < 0) == (b < 0) else -q
        return max(-2**31, min(2**31 - 1, q))
    bad = 0
    for a, b in cases:
        e = Emu(rom)
        e.call(0x0BE654, regs={4: a, 5: b})
        bad += s32(e.R[0]) != want(a, b)
    results.append((f'divide 0x0BE654 (saturating signed Q16.16), {len(cases)} cases', bad == 0, f'{bad} mismatches'))


def selftest():
    results = []
    for f in (_selftest_clamp, _selftest_div, _selftest_checksum, _selftest_lookup):
        try:
            f(results)
        except EmuError as e:
            results.append((f.__name__, False, f'EmuError: {e}'))
    ok = True
    for name, passed, detail in results:
        print(f'{"pass" if passed else "FAIL"}  {name}  ({detail})')
        ok &= passed
    print('selftest: ' + ('pass' if ok else 'FAIL'))
    return 0 if ok else 1


if __name__ == '__main__':
    if '--selftest' in sys.argv:
        sys.exit(selftest())
    print(__doc__)
