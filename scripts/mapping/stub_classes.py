#!/usr/bin/env python3
"""Group small functions by instruction SHAPE, so they are classified, not read.

    python scripts/mapping/stub_classes.py                 # summary, top classes
    python scripts/mapping/stub_classes.py --max 12 --top 40
    python scripts/mapping/stub_classes.py --json out.json
    python scripts/mapping/stub_classes.py --show 0x029878  # class of one function

WHY
A third of the ROM's functions (1,649 of 5,151) are 12 instructions or fewer and
together are 3.5% of the code. Reading them one at a time is the worst trade in
the whole programme. Most are a handful of shapes stamped out with different
constants: load an address, test a bit, return 0/1. This tool finds the shapes.

HOW
Each instruction word is reduced to its shape: every field that is a constant
rather than structure (PC-relative displacement, immediate, GBR/struct
displacement, branch distance to a call) is masked, and each PC-relative literal
is replaced by its address class (RAM / PERIPH / DESC / CAL / ROM / const). Two
functions with the same shape tuple differ only in constants.

A class is a SHAPE, not a meaning. Decode one member with fn_dump.py, state what
the shape does, and the class's member list gives every (function -> constant)
pair mechanically. Reads disassembly/maps/function_census.json; run
function_census.py first.
"""
import argparse
import collections
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, '..'))
import function_census as fc            # noqa: E402
from sh2e_disasm import decode          # noqa: E402

CENSUS = os.path.join(fc.REPO, 'disassembly', 'maps', 'function_census.json')


def lit_class(v, descs):
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


def shape_of(rom, pc, w, descs):
    """(masked word, literal class or None, constant or None)."""
    op = w >> 12
    sub = (w >> 8) & 0xF
    if op == 0xD:
        v = fc.u32(rom, fc.lit_target(pc, w))
        return w & 0xFF00, lit_class(v, descs), v
    if op == 0x9:
        v = fc.u16(rom, pc + 4 + (w & 0xFF) * 2)
        return w & 0xFF00, 'w16', v
    if op in (0xE, 0x7):
        return w & 0xFF00, 'imm', w & 0xFF
    if op in (0xA, 0xB):
        return w & 0xF000, None, None
    if op == 0x8:
        if sub in (0x0, 0x1, 0x4, 0x5):
            return w & 0xFFF0, 'disp', w & 0xF
        if sub == 0x8:
            return w & 0xFF00, 'imm', w & 0xFF
        return w, None, None                       # conditional branches: keep
    if op == 0xC:
        if sub == 0x7:
            return w & 0xFF00, 'mova', fc.u32(rom, fc.lit_target(pc, w))
        return w & 0xFF00, 'd8', w & 0xFF
    if op in (0x1, 0x5):
        return w & 0xFFF0, 'disp', w & 0xF
    return w, None, None


def function_shape(rom, f, descs):
    lo, hi = int(f['entry'], 16), int(f['end'], 16)
    c = fc.Census(rom)
    c.lit_addrs = set()
    _, visited, _ = c.walk(lo, commit=False, limit=400)
    body = sorted(a for a in visited if lo <= a < hi)
    shape, consts = [], []
    for a in body:
        m, k, v = shape_of(rom, a, visited[a], descs)
        shape.append((m, k))
        if k is not None:
            consts.append((k, v))
    return tuple(shape), consts, body, visited


def render(rom, f):
    lo, hi = int(f['entry'], 16), int(f['end'], 16)
    c = fc.Census(rom)
    c.lit_addrs = set()
    _, visited, _ = c.walk(lo, commit=False, limit=400)
    out = []
    for a in sorted(x for x in visited if lo <= x < hi):
        out.append(f'    {a:06X}: {visited[a]:04X}  {decode(visited[a], a)[0]}')
    return '\n'.join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--rom', default=fc.DEFAULT_ROM)
    ap.add_argument('--max', type=int, default=12, help='largest function, in instructions')
    ap.add_argument('--top', type=int, default=25)
    ap.add_argument('--json')
    ap.add_argument('--show', type=lambda s: int(s, 16))
    args = ap.parse_args()

    with open(args.rom, 'rb') as fh:
        rom = fh.read()
    with open(CENSUS) as fh:
        funcs = json.load(fh)['functions']
    descs = fc.descriptor_addresses(rom)

    small = [f for f in funcs if f['insns'] <= args.max]
    classes = collections.defaultdict(list)
    for f in small:
        shape, consts, body, _ = function_shape(rom, f, descs)
        if len(body) != f['insns']:
            continue                               # shared tail / partial walk: skip
        classes[shape].append((f, consts))

    ranked = sorted(classes.items(), key=lambda kv: -len(kv[1]))
    n_funcs = sum(len(v) for v in classes.values())
    multi = [(s, m) for s, m in ranked if len(m) >= 2]
    print(f'functions of <= {args.max} instructions : {len(small)}')
    print(f'  classified (walk matches census)   : {n_funcs}')
    print(f'  distinct shapes                    : {len(classes)}')
    print(f'  shapes with >= 2 members           : {len(multi)}  covering '
          f'{sum(len(m) for _, m in multi)} functions')
    for n in (5, 10, 25, 50, 100):
        print(f'  top {n:3d} shapes cover               : {sum(len(m) for _, m in ranked[:n])}')

    if args.show is not None:
        for i, (shape, members) in enumerate(ranked):
            if any(int(f['entry'], 16) == args.show for f, _ in members):
                print(f'\nclass #{i}: {len(members)} members')
                print(render(rom, members[0][0]))
                for f, consts in members:
                    print('  ' + f['entry'] + '  ' + ' '.join(
                        f'{k}={v:#x}' for k, v in consts))
                break
        return

    print()
    for i, (shape, members) in enumerate(ranked[:args.top]):
        f0 = members[0][0]
        callers = sum(len(f['callers']) for f, _ in members)
        kinds = collections.Counter(k for k, _ in members[0][1])
        print(f'#{i:<3d} {len(members):4d} functions, {f0["insns"]:2d} insns each, '
              f'{callers:5d} call sites, constants: {dict(kinds)}   e.g. {f0["entry"]}')
        print(render(rom, f0))

    if args.json:
        out = []
        for i, (shape, members) in enumerate(ranked):
            out.append(dict(
                id=i, members=len(members), insns=members[0][0]['insns'],
                example=members[0][0]['entry'],
                functions=[dict(entry=f['entry'], callers=len(f['callers']),
                                consts=[[k, v] for k, v in consts])
                           for f, consts in members]))
        with open(args.json, 'w', newline='\n') as fh:
            json.dump(out, fh, indent=1)
            fh.write('\n')
        print(f'\nwrote {args.json}')


if __name__ == '__main__':
    main()
