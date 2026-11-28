#!/usr/bin/env python3
"""Records whose cell type is set by the WRAPPER that consumes them, not by the typecode byte.

    python scripts/mapping/fixed_type_records.py            # summary + conflicts
    python scripts/mapping/fixed_type_records.py --json disassembly/maps/fixed_type_records.json

WHY (corrections item 106)
The table library has two kinds of entry point. The TYPED wrappers 0x0BE830 (1-D)
and 0x0BE8E4 (2-D) read the typecode byte (+2 / +16) and dispatch on it. The
FIXED-TYPE wrappers never read it: the cell width is decided by WHICH wrapper is
called --

    0x0BE874  1-D, uint8 cells,  float32 axis      0BE87E: B14F  bsr 0x0BEB20
    0x0BE8AC  1-D, uint16 cells, float32 axis      0BE8B6: B159  bsr 0x0BEB6C
    0x0BE88C  1-D, uint8 cells,  INT32 axis, integer input in r5
    0x0BE8C4  1-D, uint16 cells, INT32 axis, integer input in r5
    0x0BE928  2-D, uint8 cells
    0x0BE944  2-D, uint16 cells
    0x0BE4FA  step lookup: float32 thresholds, uint8 values, NOT interpolated

46 records reach a fixed-type wrapper with 0x00 in the type byte. Read at face
value they decode as float32 (record 0x0AB2A4: count 4, data 0x0C5824, next
record's axis at 0x0C5828 -- four BYTES of data, not sixteen). desc_types.read_table
consults the JSON this writes, so the override is derived from code, not typed in.

HOW
Every call site of each wrapper (function_census call graph, which resolves
`jsr @Rn` by CFG constant propagation), r4 as the callee sees it (after the delay
slot). Records that reach a wrapper through MEMORY (a GBR slot, a stack slot)
are invisible to register propagation; those are listed in VIA_MEMORY with the
bytes that prove them, and the script re-checks each one's bytes on every run.
"""
import argparse
import collections
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, '..'))
import function_census as fc      # noqa: E402

OUT = os.path.join(fc.REPO, 'disassembly', 'maps', 'fixed_type_records.json')

# consumer -> (dim, cell typecode it implies, axis kind)
CONSUMERS = {
    0x0BE874: ('1D', 0x04, 'float32'),
    0x0BE8AC: ('1D', 0x08, 'float32'),
    0x0BE88C: ('1D', 0x04, 'int32'),
    0x0BE8C4: ('1D', 0x08, 'int32'),
    0x0BE928: ('2D', 0x04, 'float32'),
    0x0BE944: ('2D', 0x08, 'float32'),
    0x0BE4FA: ('1D', 0x04, 'float32-step'),
}
TYPED = (0x0BE830, 0x0BE8E4)

# Records that reach a fixed-type wrapper through memory, not a register.
# Each entry: record -> (consumer, site, [(addr, word)] that must match the ROM).
VIA_MEMORY = {
    # 0x0BBCF8 sets GBR once (0BBD12 D05D mov.l -> 0xFFFF9758 / 0BBD14 401E ldc r0,gbr),
    # parks a record pointer in @(32,gbr) = RAM 0xFFFF9778, and reloads it for the
    # call:  0BBDC2 D540 r5 = 0x0BE8AC / 0BBDC4 C608 mov.l @(32,gbr),r0 /
    #        0BBDC6 6403 mov r0,r4 / 0BBDCA 450B jsr @r5
    0x0AC26C: (0x0BE8AC, 0x0BBDCA, [(0x0BBD12, 0xD05D), (0x0BBD14, 0x401E), (0x0BBD3A, 0xD055),
                                    (0x0BBD3C, 0xC208), (0x0BBDC4, 0xC608), (0x0BBDC6, 0x6403),
                                    (0x0BBDCA, 0x450B)]),   # 0BBD3A D055 r0 = 0x0AC26C / 0BBD3C C208 store
    0x0AB458: (0x0BE8AC, 0x0BBDCA, [(0x0BBD12, 0xD05D), (0x0BBD14, 0x401E), (0x0BBD6A, 0xD04D),
                                    (0x0BBD6C, 0xC208), (0x0BBDC4, 0xC608), (0x0BBDC6, 0x6403),
                                    (0x0BBDCA, 0x450B)]),   # 0BBD6A D04D r0 = 0x0AB458 / 0BBD6C C208 store
    # The WRAPPER address is parked in the stack slot @r15 on both arms and the
    # call reloads it: 036340 D27E r2 = 0x0BE8AC / 036344 2F22 mov.l r2,@r15 [slot];
    # 036396 D669 r6 = 0x0BE8AC / 036398 2F62 mov.l r6,@r15; then
    # 0363E0 D45B r4 = 0x0AD0C4 / 0363E2 62F2 mov.l @r15,r2 / 0363E4 420B jsr @r2.
    0x0AD0C4: (0x0BE8AC, 0x0363E4, [(0x036340, 0xD27E), (0x036344, 0x2F22), (0x036396, 0xD669),
                                    (0x036398, 0x2F62), (0x0363E0, 0xD45B), (0x0363E2, 0x62F2),
                                    (0x0363E4, 0x420B)]),
}


def resolve_sites(rom, c):
    """{record: {consumer: [sites]}} for every register-resolved call site."""
    out = collections.defaultdict(lambda: collections.defaultdict(list))
    unresolved = collections.defaultdict(list)
    ents = sorted(c.entries)
    import bisect
    for pc, tgts in c.calls.items():
        for t in tgts:
            if t not in CONSUMERS and t not in TYPED:
                continue
            i = bisect.bisect_right(ents, pc) - 1
            e = ents[i]
            st = c.rs.get(e) or fc.reg_states(rom, e)
            args = fc.call_args(rom, st, pc)
            r4 = args[4] if args is not None else None
            if r4 is None or not all(0x0A0000 <= x < 0x0C0000 for x in r4):
                unresolved[t].append(pc)
                continue
            for x in r4:              # a join of literal loads: every one is consumed
                out[x][t].append(pc)
    return out, unresolved


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--rom', default=fc.DEFAULT_ROM)
    ap.add_argument('--json')
    args = ap.parse_args()
    rom = open(args.rom, 'rb').read()
    c = fc.census(rom)
    recs, unresolved = resolve_sites(rom, c)

    fixed, conflicts = {}, []
    for r, by in sorted(recs.items()):
        fx = [t for t in by if t in CONSUMERS]
        ty = [t for t in by if t in TYPED]
        if not fx:
            continue
        kinds = {CONSUMERS[t] for t in fx}
        if len(kinds) > 1 or ty:
            conflicts.append((r, {f'0x{t:06X}': [f'0x{p:06X}' for p in by[t]] for t in by}))
            continue
        dim, tc, axis = kinds.pop()
        byte = rom[r + (16 if dim == '2D' else 2)]
        fixed[r] = dict(dim=dim, cell_typecode=tc, axis=axis, typecode_byte=byte,
                        consumers={f'0x{t:06X}': [f'0x{p:06X}' for p in sorted(by[t])] for t in fx},
                        via='register')
    for r, (t, site, words) in VIA_MEMORY.items():
        bad = [(a, w) for a, w in words if fc.u16(rom, a) != w]
        if bad:
            sys.exit(f'VIA_MEMORY record 0x{r:06X}: bytes changed at {[hex(a) for a, _ in bad]}')
        dim, tc, axis = CONSUMERS[t]
        fixed.setdefault(r, dict(dim=dim, cell_typecode=tc, axis=axis,
                                 typecode_byte=rom[r + (16 if dim == '2D' else 2)],
                                 consumers={f'0x{t:06X}': [f'0x{site:06X}']}, via='memory'))

    for r, (t, site, _) in VIA_MEMORY.items():
        if site in unresolved.get(t, []):
            unresolved[t].remove(site)
    dead = {r: v for r, v in fixed.items() if v['typecode_byte'] != v['cell_typecode']}
    print(f'records consumed by fixed-type wrappers: {len(fixed)}')
    print(f'  ... whose typecode byte disagrees with the wrapper: {len(dead)}')
    for t in CONSUMERS:
        n = sum(1 for v in fixed.values() if f'0x{t:06X}' in v['consumers'])
        d = sum(1 for v in dead.values() if f'0x{t:06X}' in v['consumers'])
        print(f'  0x{t:06X} {CONSUMERS[t]}: {n} records, {d} with a dead typecode, '
              f'{len(unresolved.get(t, []))} call sites with r4 unresolved {[hex(p) for p in unresolved.get(t, [])][:6]}')
    if conflicts:
        print(f'CONFLICTS (record reaches wrappers of different types): {len(conflicts)}')
        for r, by in conflicts:
            print(f'  0x{r:06X} {by}')
    if args.json:
        with open(args.json, 'w', newline='\n') as fh:
            json.dump(dict(
                doc='Records whose cell type is set by the consuming wrapper (corrections item 106). '
                    'Generated by scripts/mapping/fixed_type_records.py -- do not hand-edit.',
                rom=os.path.basename(args.rom),
                consumers={f'0x{t:06X}': list(v) for t, v in CONSUMERS.items()},
                records={f'0x{r:06X}': v for r, v in sorted(fixed.items())},
                conflicts=[[f'0x{r:06X}', by] for r, by in conflicts],
                unresolved_sites={f'0x{t:06X}': [f'0x{p:06X}' for p in v] for t, v in unresolved.items()},
            ), fh, indent=1)
            fh.write('\n')
        print(f'wrote {args.json}')


if __name__ == '__main__':
    main()
