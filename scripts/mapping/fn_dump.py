#!/usr/bin/env python3
"""Dump one function as a verifier-format listing with mechanical annotations.

    python scripts/mapping/fn_dump.py 0x0353BC                # blind (default)
    python scripts/mapping/fn_dump.py 0x0353BC --labels       # add label CLAIMS
    python scripts/mapping/fn_dump.py 0x0BE53C --end 0x0BE554
    python scripts/mapping/fn_dump.py 0x0353BC --tables       # decode its tables

WHY
Every operand error in docs/corrections.md came from a listing somebody typed or
re-derived by hand. This prints the listing from the canonical decoder so a
trace starts from lines that already pass scripts/verify_disasm_v2.py, and the
effort goes into SEMANTICS.

WHAT THE ANNOTATIONS ARE
Everything after ';' is computed from bytes: the literal a PC-relative load
reads and what address class it falls in, the float a `mova`/`fmov.s` pair
reads, the resolved target of `jsr @Rn`, the absolute address of a GBR-relative
access when the function sets GBR exactly once. Nothing is a name unless
--labels is given, and those are CLAIMS (CLAUDE.md rule 7) printed as
`[claim: name TAG]`.

Literal-pool words are printed as `; pool` comment lines, never in instruction
format -- 2,515 pool words printed as instructions by older *_raw.txt files are
why "instructions traced" was overcounted.
"""
import argparse
import bisect
import json
import math
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, '..'))
import function_census as fc            # noqa: E402
from sh2e_disasm import decode          # noqa: E402
import desc_types as T                  # noqa: E402

CENSUS = os.path.join(fc.REPO, 'disassembly', 'maps', 'function_census.json')


def f32(v):
    return struct.unpack('>f', struct.pack('>I', v))[0]


def plausible_float(v):
    if v in (0, 0x80000000):
        return True
    f = f32(v)
    return math.isfinite(f) and 1e-7 < abs(f) < 1e8


def classify(v, descs):
    if fc.RAM_LO <= v < fc.RAM_HI:
        return 'RAM'
    if v >= fc.PERIPH_LO:
        return 'PERIPH'
    if v in descs:
        return 'DESC'
    if fc.CAL_LO <= v < fc.ROM_SIZE:
        return 'CAL'
    if fc.CODE_LO <= v < fc.CAL_LO and not (v & 1):
        return 'ROM'
    return 'const'


def describe_desc(rom, a):
    try:
        t = T.read_table(rom, a)
    except Exception as e:                                  # noqa: BLE001
        return f'DESC 0x{a:06X} (undecodable: {e})'
    if t['dim'] == '2D':
        shape = f"{len(t['axes']['y'])}x{len(t['axes']['x'])}"
        flat = [v for row in t['values'] for v in row]
    else:
        shape = f"x{len(t['axes']['x'])}"
        flat = t['values']
    fx = t.get('fixed')
    how = ''
    if fx is not None:
        how = (f" (cell type set by wrapper {'/'.join(fx['consumers'])}, typecode byte "
               f"0x{fx['typecode_byte']:02X} not read; axis {fx['axis']})")
    return (f"DESC 0x{a:06X} {t['dim']} {t['type_name']} {shape} "
            f"data {min(flat):.6g}..{max(flat):.6g}{how}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('entry', type=lambda s: int(s, 16))
    ap.add_argument('--end', type=lambda s: int(s, 16))
    ap.add_argument('--rom', default=fc.DEFAULT_ROM)
    ap.add_argument('--labels', action='store_true',
                    help='append existing label names as CLAIMS')
    ap.add_argument('--tables', action='store_true',
                    help='print axes and data of every descriptor referenced')
    args = ap.parse_args()

    with open(args.rom, 'rb') as fh:
        rom = fh.read()
    descs = fc.descriptor_addresses(rom)
    labels = fc.java_labels() if args.labels else {}

    end = args.end
    if end is None and os.path.exists(CENSUS):
        with open(CENSUS) as fh:
            ents = sorted(int(f['entry'], 16) for f in json.load(fh)['functions'])
        i = bisect.bisect_right(ents, args.entry)
        end = ents[i] if i < len(ents) else None
    if end is None:
        end = args.entry + 0x1000

    c = fc.Census(rom)
    c.lit_addrs = set()
    _, visited, _ = c.walk(args.entry, commit=False, limit=20000)
    body = sorted(a for a in visited if args.entry <= a < end)
    if not body:
        sys.exit(f'nothing decodes at 0x{args.entry:06X}')
    last = body[-1]
    code = {a: visited[a] for a in body}
    lits = fc.own_literals(code)

    # register values by CFG constant propagation (corrections item 106: the
    # address-order walk named the wrong callee where a jsr is a branch target)
    states = fc.reg_states(rom, args.entry)

    def reg_at(a, r):
        """frozenset of constants r can hold at a, or None."""
        st = states.get((a, None))
        if st is not None:
            return st[r]
        v = fc.resolve_reg(rom, a, r, args.entry)
        return None if v is None else frozenset((v,))

    gbr_vals = set()
    for a in body:
        w = code[a]
        if (w >> 12) == 0x4 and (w & 0xFF) == 0x1E:
            gbr_vals.add(fc.single(reg_at(a, (w >> 8) & 0xF)))
    gbr = next(iter(gbr_vals)) if len(gbr_vals) == 1 and None not in gbr_vals else None

    def claim(a):
        if a in labels:
            n, tag = labels[a]
            return f' [claim: {n} {tag or "?"}]'
        return ''

    print(f'; function 0x{args.entry:06X}..0x{last + 2:06X}  '
          f'{len(body)} instructions  rom {os.path.basename(args.rom)}')
    if gbr is not None:
        print(f'; GBR is set once in this function: 0x{gbr:08X}{claim(gbr)}')
    elif gbr_vals:
        print('; GBR is set more than once or from a non-literal -- gbr offsets NOT resolved')
    used_desc = []
    prev = None
    for a in body:
        if prev is not None and a != prev + 2:
            for p in range(prev + 2, a, 4 if not (prev + 2) & 3 else 2):
                if p + 4 <= len(rom) and not (p & 3):
                    v = fc.u32(rom, p)
                    note = classify(v, descs)
                    extra = f' f32 {f32(v):.7g}' if note == 'const' and plausible_float(v) else ''
                    print(f';   pool 0x{p:06X}: .long 0x{v:08X}  {note}{extra}{claim(v)}')
                else:
                    print(f';   pool 0x{p:06X}: .word 0x{fc.u16(rom, p):04X}')
        prev = a
        w = code[a]
        text, _ = decode(w, a)
        op = w >> 12
        note = ''
        if op == 0xD:
            t = fc.lit_target(a, w)
            v = fc.u32(rom, t)
            k = classify(v, descs)
            note = f'= 0x{v:08X} {k}'
            if k == 'DESC':
                used_desc.append(v)
            elif k == 'const' and plausible_float(v) and v > 0xFFFF:
                note += f' (f32 {f32(v):.7g})'
            note += claim(v)
        elif op == 0x9:
            v = fc.u16(rom, a + 4 + (w & 0xFF) * 2)
            sv = v - 0x10000 if v & 0x8000 else v
            note = f'= 0x{v:04X} ({sv})'
            if sv < 0:
                note += f' -> 0x{sv & 0xFFFFFFFF:08X} {classify(sv & 0xFFFFFFFF, descs)}{claim(sv & 0xFFFFFFFF)}'
        elif (w >> 8) == 0xC7:
            t = fc.lit_target(a, w)
            v = fc.u32(rom, t)
            note = f'-> 0x{t:06X}: long 0x{v:08X}'
            if plausible_float(v):
                note += f' f32 {f32(v):.7g}'
        elif op == 0x4 and (w & 0xFF) in (0x0B, 0x2B):
            vs = reg_at(a, (w >> 8) & 0xF)
            if vs is not None:
                note = '-> ' + ' or '.join(f'0x{v:06X}{claim(v)}' for v in sorted(vs))
            else:
                tab = fc.dispatch_table(rom, a, (w >> 8) & 0xF, args.entry)
                note = (f'-> table 0x{tab[0]:06X} x{len(tab[1])}' if tab
                        else '-> target NOT statically resolved')
        elif op == 0xB or op == 0xA:
            d = w & 0xFFF
            d = d - 0x1000 if d & 0x800 else d
            note = claim(a + 4 + d * 2).strip()
        elif op == 0x4 and (w & 0xFF) == 0x1E:
            v = fc.single(reg_at(a, (w >> 8) & 0xF))
            note = f'GBR = 0x{v:08X}{claim(v)}' if v is not None else 'GBR = (not a literal)'
        elif op == 0xC and gbr is not None and ((w >> 8) & 0xF) in (0, 1, 2, 4, 5, 6):
            sub = (w >> 8) & 0xF
            scale = {0: 1, 4: 1, 1: 2, 5: 2, 2: 4, 6: 4}[sub]
            t = (gbr + (w & 0xFF) * scale) & 0xFFFFFFFF
            note = f'gbr+{(w & 0xFF) * scale} = 0x{t:08X}{claim(t)}'
        line = f'{a:06X}: {w:04X}  {text}'
        print(f'{line:44s}; {note}' if note else line)

    # trailing pool
    tail = sorted(p for p in lits if p > last and p < last + 0x400)
    seen = set()
    for p in tail:
        p4 = p & ~3
        if p4 in seen or p4 in code:
            continue
        seen.add(p4)
        v = fc.u32(rom, p4)
        note = classify(v, descs)
        extra = f' f32 {f32(v):.7g}' if note == 'const' and plausible_float(v) else ''
        print(f';   pool 0x{p4:06X}: .long 0x{v:08X}  {note}{extra}{claim(v)}')

    if used_desc:
        print(';')
        print('; descriptors referenced (geometry and data decoded from bytes):')
        for a in sorted(set(used_desc)):
            print(f';   {describe_desc(rom, a)}')
            if args.tables:
                t = T.read_table(rom, a)
                for k, ax in t['axes'].items():
                    print(f';     axis {k}: ' + ', '.join(f'{v:.6g}' for v in ax))
                rows = t['values'] if t['dim'] == '2D' else [t['values']]
                for r in rows:
                    print(';     ' + ', '.join(f'{v:.6g}' for v in r))


if __name__ == '__main__':
    main()
