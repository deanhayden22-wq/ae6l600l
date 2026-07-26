#!/usr/bin/env python3
"""
Repair committed disassembly text in place, using ROM bytes as the authority.

Rewrites only the lines that scripts/verify_disasm_v2.py flags, preserving each
file's column layout and any hand-written annotation. Derived annotations that
were computed from a wrong decode (e.g. "; CALL @ 0xFFFFFFE4" produced by
reading `jsr @rN` as `jsr @r0`) are recomputed rather than carried forward.

For JSR/JMP it back-traces the target register to the literal-pool load that
filled it, so `jsr @r2` gains "; -> 0x000BE56C" naming the real callee. That is
the whole point of the repair: the call graph in knock_flkc_analysis.txt was
wrong at 95 sites, and simply correcting the register text would leave it
unreadable.

Usage:
    python scripts/repair_disasm.py --dry-run disassembly/analysis/foo.txt
    python scripts/repair_disasm.py disassembly/analysis/foo.txt
    python scripts/repair_disasm.py --all --dry-run
"""
import argparse
import glob
import os
import re
import struct
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sh2e_disasm import decode  # noqa: E402
from verify_disasm_v2 import LINE, normalize, resolve_pcrel, PCREL, SYMBOLIC  # noqa: E402

# splits "  43A1E: 450B  jsr    @r0        ; CALL @ 0xFFFFFFE4"
PARTS = re.compile(
    r'^(?P<indent>\s*)(?P<addr>(?:0x)?[0-9A-Fa-f]{5,6})(?P<sep>\s*:\s*)'
    r'(?P<word>[0-9A-Fa-f]{4})(?P<gap>\s+)(?P<body>.*)$')

# annotations that were COMPUTED from the (wrong) decode and must not survive
DERIVED_CMT = re.compile(r';\s*(CALL\s*@|->\s*0x|=\s*0x[0-9A-Fa-f]+\s*$)', re.I)


def rom_word(rom, a):
    return (rom[a] << 8) | rom[a + 1] if a + 1 < len(rom) else None


def trace_reg(rom, addr, reg, back=24):
    """Find what literal was loaded into `reg` shortly before `addr`.

    Handles the dominant idiom: MOV.L @(disp,PC),Rn from a literal pool.
    Returns the 32-bit value, or None if it cannot be established.
    """
    a = addr - 2
    stop = max(0, addr - back * 2)
    while a >= stop:
        w = rom_word(rom, a)
        if w is None:
            return None
        if (w >> 12) == 0xD and ((w >> 8) & 0xF) == reg:      # mov.l @(d,PC),Rn
            pool = ((a + 4) & ~3) + (w & 0xFF) * 4
            if pool + 3 < len(rom):
                return struct.unpack_from('>I', rom, pool)[0]
            return None
        # register overwritten by something we cannot follow -> give up
        if (w >> 12) == 0x6 and ((w >> 8) & 0xF) == reg and (w & 0xF) == 0x3:
            return None                                        # mov Rm,Rn
        if (w >> 12) == 0xE and ((w >> 8) & 0xF) == reg:
            return None                                        # mov #imm,Rn
        a -= 2
    return None


def annotate(rom, addr, word, truth, symbols):
    """Build a trailing comment for instructions whose target is worth naming."""
    m = re.match(r'(jsr|jmp)\s+@r(\d+)$', truth)
    if not m:
        return ''
    val = trace_reg(rom, addr, int(m.group(2)))
    if val is None:
        return ''
    name = symbols.get(val & 0xFFFFFFFF)
    return f'  ; -> 0x{val:06X}' + (f' ({name})' if name else '')


def load_symbols():
    """Address -> name, from the Ghidra import script (single source of truth)."""
    syms = {}
    p = 'disassembly/ghidra/ImportAE5L600L.java'
    if not os.path.exists(p):
        return syms
    for m in re.finditer(r'label(?:Comment)?\(0x([0-9A-Fa-f]+)L?,\s*"([^"]+)"',
                         open(p, encoding='utf-8', errors='replace').read()):
        syms.setdefault(int(m.group(1), 16), m.group(2))
    return syms


def repair_file(path, rom, symbols, dry_run):
    lines = open(path, encoding='utf-8', errors='replace').read().split('\n')
    changed, stats = 0, Counter()
    for i, ln in enumerate(lines):
        lm = LINE.match(ln)
        if not lm:
            continue
        addr, word = int(lm.group(1), 16), int(lm.group(2), 16)
        text = lm.group(3)
        if addr + 1 >= len(rom) or rom_word(rom, addr) != word:
            continue
        truth, _ = decode(word, addr)
        cands = (text, resolve_pcrel(text, addr, word),
                 PCREL.sub(lambda mm: f'@(0x{int(mm.group(1), 16):06X})', text))
        if any(normalize(c) == normalize(truth) for c in cands):
            continue
        if SYMBOLIC.search(normalize(text)):
            stats['left: symbolic label'] += 1
            continue
        if not normalize(text):
            stats['left: prose replaced instruction (needs human)'] += 1
            continue

        pm = PARTS.match(ln)
        if not pm:
            stats['left: unrecognised layout'] += 1
            continue

        # keep a hand-written comment, drop one derived from the bad decode
        cmt = ''
        if ';' in pm.group('body'):
            raw = pm.group('body')[pm.group('body').index(';'):]
            if not DERIVED_CMT.search(raw):
                cmt = '  ' + raw.strip()
        if not cmt:
            cmt = annotate(rom, addr, word, truth, symbols)

        mnem, _, ops = truth.partition(' ')
        # pad to 6 then ALWAYS a space -- 7-character mnemonics (cmp/str,
        # dmulu.l, dmuls.l, fcmp/eq, fcmp/gt) would otherwise run straight into
        # their operands, e.g. "cmp/strr11,r10"
        body = f'{mnem:<6} {ops}' if ops else mnem
        lines[i] = (pm.group('indent') + pm.group('addr') + pm.group('sep') +
                    pm.group('word') + pm.group('gap') + body + cmt)
        changed += 1
        stats['repaired'] += 1

    if changed and not dry_run:
        open(path, 'w', encoding='utf-8', newline='').write('\n'.join(lines))
    return changed, stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('paths', nargs='*')
    ap.add_argument('--all', action='store_true')
    ap.add_argument('--rom', default='rom/ae5l600l.bin')
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()

    rom = open(args.rom, 'rb').read()
    symbols = load_symbols()
    paths = args.paths or (glob.glob('disassembly/**/*.txt', recursive=True)
                           if args.all else [])
    if not paths:
        ap.error('give a path or --all')

    total = Counter()
    for p in sorted(set(paths)):
        n, st = repair_file(p, rom, symbols, args.dry_run)
        total.update(st)
        if n:
            print(f'{"[dry-run] " if args.dry_run else ""}{p}: {n} line(s) repaired')
    print('\nsummary:')
    for k, v in total.most_common():
        print(f'  {v:6d}  {k}')
    print(f'\nsymbols loaded: {len(symbols)}')


if __name__ == '__main__':
    main()
