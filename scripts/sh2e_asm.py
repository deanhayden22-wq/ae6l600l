#!/usr/bin/env python3
"""Minimal two-pass SH-2E assembler for patch code -- with a mandatory round trip.

    import sh2e_asm as A
    code = A.assemble('''
        VALET:  mov.l   @(P_STATE),r2
                bra     DONE
                nop
        DONE:   rts
                nop
                .align  4
        P_STATE: .long  0xFFFF3FD0
                .float  4000.0
    ''', origin=0x0F1060)
    code.bytes, code.labels

WHY IT EXISTS, AND WHY IT CAN BE TRUSTED NARROWLY
`scripts/patch_rom.py` had a hand assembler and is quarantined (MerpMod, untrusted).
This one encodes only the forms listed in ENC, and every instruction it emits is
decoded back by scripts/sh2e_disasm.py and compared operand by operand
(PC-relative targets included). A disagreement is an error, never a warning. The
real gates still run afterwards: patch_lint.py (legality, convention) and
patch_emulate.py (behaviour). This file only removes typing mistakes.

Syntax: one instruction per line; `LABEL:` prefix; `;` comments. PC-relative loads
and branches take a label (or hex). Directives: .align N, .long X, .word X,
.float X, .byte X. Immediates are decimal or 0x hex; #-91 style for signed.
"""
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import sh2e_disasm as D  # noqa: E402


class AsmError(Exception):
    pass


def _r(s):
    m = re.fullmatch(r'r(\d{1,2})', s)
    if not m or int(m.group(1)) > 15:
        raise AsmError(f'not a general register: {s}')
    return int(m.group(1))


def _fr(s):
    m = re.fullmatch(r'fr(\d{1,2})', s)
    if not m or int(m.group(1)) > 15:
        raise AsmError(f'not an FPU register: {s}')
    return int(m.group(1))


def _imm(s):
    s = s.lstrip('#')
    return int(s, 0)


def _ops(s):
    out, depth, cur = [], 0, ''
    for ch in s:
        depth += ch == '('
        depth -= ch == ')'
        if ch == ',' and depth == 0:
            out.append(cur.strip())
            cur = ''
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def encode(mn, ops, pc, sym):
    """Return the 16-bit word for one instruction at pc. sym resolves labels."""
    def target(o):
        o = o.strip()
        m = re.fullmatch(r'@\((.+)\)', o)
        o = m.group(1) if m else o
        if o in sym:
            return sym[o]
        try:
            return int(o, 0)
        except ValueError:
            raise AsmError(f'unknown label {o}')

    def disp(t, scale, bits, base):
        d, rem = divmod(t - base, scale)
        if rem:
            raise AsmError(f'target {t:#x} not {scale}-aligned from {base:#x}')
        lo, hi = (0, (1 << bits) - 1) if bits == 8 and scale == 4 and mn in ('mov.l', 'mova') else \
                 (-(1 << (bits - 1)), (1 << (bits - 1)) - 1)
        if mn in ('mov.w',) and scale == 2 and bits == 8:
            lo, hi = 0, 255
        if not lo <= d <= hi:
            raise AsmError(f'{mn} target {t:#x} out of range from {pc:#x}')
        return d & ((1 << bits) - 1)

    o = ops
    if mn == 'nop' and not o: return 0x0009
    if mn == 'rts' and not o: return 0x000B
    if mn == 'mov' and o[0].startswith('#'):
        v = _imm(o[0])
        if not -128 <= v <= 127: raise AsmError(f'mov #imm out of range: {v}')
        return 0xE000 | _r(o[1]) << 8 | (v & 0xFF)
    if mn == 'mov' and len(o) == 2: return 0x6003 | _r(o[1]) << 8 | _r(o[0]) << 4
    if mn == 'add' and o[0].startswith('#'):
        v = _imm(o[0])
        if not -128 <= v <= 127: raise AsmError('add #imm out of range')
        return 0x7000 | _r(o[1]) << 8 | (v & 0xFF)
    if mn == 'cmp/eq' and o[0].startswith('#'):
        if o[1] != 'r0': raise AsmError('cmp/eq #imm needs r0')
        v = _imm(o[0])
        if not -128 <= v <= 127: raise AsmError('cmp/eq #imm out of range')
        return 0x8800 | (v & 0xFF)
    if mn == 'dt': return 0x4010 | _r(o[0]) << 8
    if mn in ('mov.l', 'mov.w') and re.fullmatch(r'@\([^,]+\)', o[0]) and o[1].startswith('r'):
        t = target(o[0])
        if mn == 'mov.l':
            return 0xD000 | _r(o[1]) << 8 | disp(t, 4, 8, (pc + 4) & ~3)
        return 0x9000 | _r(o[1]) << 8 | disp(t, 2, 8, pc + 4)
    if mn == 'mova':
        if o[1] != 'r0': raise AsmError('mova needs r0')
        return 0xC700 | disp(target(o[0]), 4, 8, (pc + 4) & ~3)
    m = re.fullmatch(r'@\((\d+),(r\d+)\)', o[0]) if o else None
    if m and mn in ('mov.b', 'mov.w') and o[1] == 'r0':           # @(disp,Rm),R0
        d, rm = int(m.group(1)), _r(m.group(2))
        sc = 1 if mn == 'mov.b' else 2
        if d % sc or not 0 <= d // sc <= 15: raise AsmError('displacement out of range')
        return (0x8400 if mn == 'mov.b' else 0x8500) | rm << 4 | d // sc
    m = re.fullmatch(r'@\((\d+),(r\d+)\)', o[1]) if len(o) == 2 else None
    if m and mn in ('mov.b', 'mov.w') and o[0] == 'r0':           # R0,@(disp,Rn)
        d, rn = int(m.group(1)), _r(m.group(2))
        sc = 1 if mn == 'mov.b' else 2
        if d % sc or not 0 <= d // sc <= 15: raise AsmError('displacement out of range')
        return (0x8000 if mn == 'mov.b' else 0x8100) | rn << 4 | d // sc
    if mn in ('mov.b', 'mov.w', 'mov.l') and len(o) == 2:
        sz = {'mov.b': 0, 'mov.w': 1, 'mov.l': 2}[mn]
        if re.fullmatch(r'@r\d+', o[0]):
            return 0x6000 | _r(o[1]) << 8 | _r(o[0][1:]) << 4 | sz
        if re.fullmatch(r'@r\d+', o[1]):
            return 0x2000 | _r(o[1][1:]) << 8 | _r(o[0]) << 4 | sz
    if mn in ('bt', 'bf', 'bt/s', 'bf/s'):
        sub = {'bt': 0x8900, 'bf': 0x8B00, 'bt/s': 0x8D00, 'bf/s': 0x8F00}[mn]
        return sub | disp(target(o[0]), 2, 8, pc + 4)
    if mn in ('bra', 'bsr'):
        return (0xA000 if mn == 'bra' else 0xB000) | disp(target(o[0]), 2, 12, pc + 4)
    if mn in ('jmp', 'jsr'):
        return (0x402B if mn == 'jmp' else 0x400B) | _r(o[0].lstrip('@')) << 8
    if mn in ('fldi0', 'fldi1'): return (0xF08D if mn == 'fldi0' else 0xF09D) | _fr(o[0]) << 8
    if mn == 'fmov':
        return 0xF00C | _fr(o[1]) << 8 | _fr(o[0]) << 4
    if mn == 'fmov.s':
        if re.fullmatch(r'@r\d+', o[0]): return 0xF008 | _fr(o[1]) << 8 | _r(o[0][1:]) << 4
        if re.fullmatch(r'@r\d+', o[1]): return 0xF00A | _r(o[1][1:]) << 8 | _fr(o[0]) << 4
    fp = {'fadd': 0, 'fsub': 1, 'fmul': 2, 'fdiv': 3, 'fcmp/eq': 4, 'fcmp/gt': 5}
    if mn in fp: return 0xF000 | _fr(o[1]) << 8 | _fr(o[0]) << 4 | fp[mn]
    two = {'cmp/eq': 0x3000, 'cmp/hs': 0x3002, 'cmp/ge': 0x3003, 'cmp/hi': 0x3006, 'cmp/gt': 0x3007,
           'sub': 0x3008, 'add': 0x300C, 'tst': 0x2008, 'and': 0x2009, 'xor': 0x200A, 'or': 0x200B}
    if mn in two and len(o) == 2 and o[0].startswith('r'):
        return two[mn] | _r(o[1]) << 8 | _r(o[0]) << 4
    raise AsmError(f'unsupported instruction: {mn} {",".join(o)}')


class Code:
    def __init__(self, origin, data, labels, listing):
        self.origin, self.bytes, self.labels, self.listing = origin, data, labels, listing

    @property
    def end(self):
        return self.origin + len(self.bytes)


def _lines(src):
    for raw in src.split('\n'):
        line = raw.split(';', 1)[0].strip()
        label = None
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$', line)
        if m:
            label, line = m.group(1), m.group(2).strip()
        yield label, line


def _size(line, pc):
    if not line:
        return 0
    mn = line.split()[0]
    if mn == '.align':
        n = int(line.split()[1], 0)
        return (-pc) % n
    return {'.long': 4, '.float': 4, '.word': 2, '.byte': 1}.get(mn, 2)


def assemble(src, origin):
    sym, pc = {}, origin
    for label, line in _lines(src):           # pass 1: addresses
        if label:
            if label in sym:
                raise AsmError(f'duplicate label {label}')
            sym[label] = pc
        pc += _size(line, pc)
    out, pc, listing = bytearray(), origin, []
    for label, line in _lines(src):           # pass 2: encode + round trip
        if not line:
            continue
        mn, rest = (line.split(None, 1) + [''])[:2]
        ops = _ops(rest)
        if mn == '.align':
            pad = _size(line, pc)
            out += b'\xff' * pad                  # padding stays erased-flash 0xFF
            pc += pad
            continue
        if mn in ('.long', '.float', '.word', '.byte'):
            v = ops[0]
            if mn == '.float':
                b = struct.pack('>f', float(v))
            else:
                n = sym[v] if v in sym else int(v, 0)
                b = n.to_bytes({'.long': 4, '.word': 2, '.byte': 1}[mn], 'big')
            out += b
            listing.append((pc, b.hex(), line))
            pc += len(b)
            continue
        if pc & 1:
            raise AsmError(f'instruction at odd address {pc:#x}')
        w = encode(mn, ops, pc, sym)
        txt, _ = D.decode(w, pc)
        _roundtrip(mn, ops, txt, pc, sym)
        out += w.to_bytes(2, 'big')
        listing.append((pc, f'{w:04X}', txt))
        pc += 2
    return Code(origin, bytes(out), sym, listing)


def _norm(s):
    return s.replace(' ', '').lower()


def _roundtrip(mn, ops, txt, pc, sym):
    """The decoder must print back exactly what was written (labels resolved)."""
    want = []
    for o in ops:
        m = re.fullmatch(r'@\(([A-Za-z_][A-Za-z0-9_]*)\)', o)
        if m:
            o = f'@(0x{sym[m.group(1)]:06X})'
        elif o in sym:
            o = f'0x{sym[o]:06X}'
        elif re.fullmatch(r'#0x[0-9a-fA-F]+', o):
            o = f'#{int(o[1:], 16)}'
        elif re.fullmatch(r'0x[0-9a-fA-F]+', o):
            o = f'0x{int(o, 16):06X}'
        elif re.fullmatch(r'@\(0x[0-9a-fA-F]+\)', o):
            o = f'@(0x{int(o[2:-1], 16):06X})'
        want.append(o)
    expect = _norm(mn + ' ' + ','.join(want))
    if _norm(txt) != expect:
        raise AsmError(f'round trip failed at {pc:06X}: wrote "{mn} {",".join(ops)}", '
                       f'sh2e_disasm reads "{txt}"')
