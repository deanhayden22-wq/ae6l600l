#!/usr/bin/env python3
"""Name the members of the small-function shape classes from their own parameters.

    python scripts/mapping/stub_member_names.py            # report
    python scripts/mapping/stub_member_names.py --apply    # merge into decoded_labels.json

Batch 2 of the function programme (corrections item 108) proved every member of the
127 shape classes of disassembly/maps/stub_classes.json: each member was re-decoded,
shape-matched against its class example and emulated against the parametrised
contract, by scripts/trace/emu_stub_shapes_a.py / _b.py. Their member maps are
printed verbatim in disassembly/analysis/stub_shapes_a_trace.txt (lines
";   0xADDR  callers N [..]  K=0x...") and stub_shapes_b_trace.txt (lines
";   class  N  ADDR  callers N  K=0x..."). This tool turns each map line into a label
whose name is the class contract with the member's own parameters filled in:

    class 3  r0 = sext8(byte [K])      0x029BA8  K=0xFFFF979E   ->  get_s8_979E
    class 10 r0 = (byte [K] == I)      ...       K=0xFFFF65B1 I=1 -> is_65B1_eq1

RULES
  * Only members WITHOUT an existing label get one (any labelComment/label at the
    address in ImportAE5L600L.java, or a record already in decoded_labels.json). A
    member that already has a name keeps it; contradicted names were dealt with by
    item 108 one by one.
  * Only classes with a template below are named. A class without one is skipped and
    reported -- a forced name is worse than none.
  * RAM addresses are written as their low 16 bits (0xFFFF5B6C -> 5B6C), ROM
    addresses as six hex digits. A name says what the code DOES with the address, not
    what the address MEANS.
Records carry item 108 and kind "function"; sync_decoded_labels.py applies them.
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, '..', '..'))
A_FILE = os.path.join(REPO, 'disassembly', 'analysis', 'stub_shapes_a_trace.txt')
B_FILE = os.path.join(REPO, 'disassembly', 'analysis', 'stub_shapes_b_trace.txt')
JAVA = os.path.join(REPO, 'disassembly', 'ghidra', 'ImportAE5L600L.java')
SPEC = os.path.join(REPO, 'disassembly', 'maps', 'decoded_labels.json')


def ad(x):
    v = int(x, 16)
    return f'{v & 0xFFFF:04X}' if v >= 0xFFFF0000 else f'{v:06X}'


def num(x):
    v = int(x, 0)
    return f'm{-v}' if v < 0 else str(v)


def hx(x):
    return f'{int(x, 16):X}'


def irq(p, raw):
    m = re.search(r'irq vector (\d+)', raw)
    return int(m.group(1)) if m else (int(p['C'], 0) if 'C' in p else None)


def chain(p, keys):
    ks = [k for k in keys if k in p]
    return f'chain{len(ks)}_{ad(p[ks[0]])}_{ad(p[ks[-1]])}'


# class id -> f(params, raw text, member address) -> name or None
T = {
    0: lambda p, r, a: f'spin_forever_{a:06X}' if int(p['T'], 16) == a else f'thunk_to_{ad(p["T"])}',
    1: lambda p, r, a: f'isr_entry_v{p["vec"]}',
    2: lambda p, r, a: f'empty_fn_{a:06X}',
    3: lambda p, r, a: f'get_s8_{ad(p["K"])}',
    4: lambda p, r, a: f'call_{ad(p["A"])}_then_{ad(p["B"])}',
    5: lambda p, r, a: f'test_{ad(p["K"])}_m{int(p["M"], 16):02X}',
    6: lambda p, r, a: f'ret{num(p["I"])}_{a:06X}',
    7: lambda p, r, a: f'sel_{ad(p["K"])}_nz_{num(p["A"])}_{num(p["B"])}',
    8: lambda p, r, a: f'set_{ad(p["K"])}_{num(p["I"])}',
    9: lambda p, r, a: f'setpair_{ad(p["K"])}_{num(p["I"])}',
    10: lambda p, r, a: f'is_{ad(p["K"])}_eq{num(p["I"])}',
    11: lambda p, r, a: f'jmp_to_{ad(p["T"])}',
    12: lambda p, r, a: chain(p, 'ABC'),
    13: lambda p, r, a: f'irq_v{p["N"]}_ack_halt',
    14: lambda p, r, a: f'f2u8_{ad(p["K"])}',
    15: lambda p, r, a: f'irq_v{p["N"]}_ack_halt',
    16: lambda p, r, a: f'copy_{int(p["D"]) // 4 + 1}longs',
    17: lambda p, r, a: chain(p, 'ABCD'),
    18: lambda p, r, a: f'put_{ad(p["K"])}',
    19: lambda p, r, a: f'get_u8_{ad(p["K"])}',
    20: lambda p, r, a: f'jmp_to_{ad(p["T"])}',
    21: lambda p, r, a: f'put_{ad(p["K"])}',
    22: lambda p, r, a: f'irq_v{p["N"]}_ack_halt',
    23: lambda p, r, a: chain(p, 'ABCDE'),
    24: lambda p, r, a: f'set_{ad(p["K"])}_FF',
    25: lambda p, r, a: f'ret0_{a:06X}',
    26: lambda p, r, a: f'copyw_{ad(p["A"])}_{ad(p["B"])}_fallthru',
    27: lambda p, r, a: f'irq_v{p["N"]}_ack_halt',
    28: lambda p, r, a: f'irq_v{p["N"]}_halt',
    29: lambda p, r, a: f'set2_{ad(p["K"])}_{num(p["I"])}',
    30: lambda p, r, a: f'exc_trap_{hx(p["W"])}_halt',
    31: lambda p, r, a: f'zero_rec_{ad(p["A"])}',
    32: lambda p, r, a: f'irq_v{irq(p, r)}_ack_halt',
    33: lambda p, r, a: f'irq_v{irq(p, r)}_ack_halt',
    34: lambda p, r, a: f'initpair_{ad(p["A"])}',
    35: lambda p, r, a: f'set4_{ad(p["A"])}_{num(p["V"])}',
    36: lambda p, r, a: f'copyf_{ad(p["A"])}_{ad(p["B"])}',
    37: lambda p, r, a: f'f2u8_{ad(p["X"])}',
    38: lambda p, r, a: f'ret_const_{a:06X}',
    39: lambda p, r, a: f'ret0_{a:06X}',
    40: lambda p, r, a: f'copyb_{ad(p["A"])}_{ad(p["B"])}',
    41: lambda p, r, a: f'sel_{ad(p["A"])}_eq{num(p["K"])}',
    42: lambda p, r, a: f'call_{ad(p["F"])}_tail_{ad(p["G"])}_if0',
    43: lambda p, r, a: f'get_rom_s8_{a:06X}',
    44: lambda p, r, a: f'putpair_{ad(p["A"])}',
    45: lambda p, r, a: f'f2u16_{ad(p["X"])}_to_{ad(p["O"])}',
    46: lambda p, r, a: f'set_{ad(p["A"])}_{num(p["V"])}',
    47: lambda p, r, a: f'zero_rec2_{ad(p["A1"])}',
    48: lambda p, r, a: f'init_{ad(p["A"])}_{ad(p["B"])}',
    49: lambda p, r, a: f'call_{ad(p["F"])}_tail_{ad(p["G"])}_if{num(p["K"])}',
    50: lambda p, r, a: f'copyb_{ad(p["A"])}_{ad(p["B"])}',
    51: lambda p, r, a: f'f2u8_{ad(p["X"])}',
    52: lambda p, r, a: f'f2u16_{ad(p["X"])}',
    53: lambda p, r, a: f'ret0_{a:06X}',
    54: lambda p, r, a: f'call_{ad(p["F"])}_twice_{a:06X}',
    # interrupt handlers that tail-call a real routine (not the fatal trap)
    57: lambda p, r, a: f'irq_v{irq(p, r)}_ack_to_{ad(p["G"])}',
    58: lambda p, r, a: f'irq_v{irq(p, r)}_ack_to_{ad(p["G"])}',
    59: lambda p, r, a: f'irq_v{irq(p, r)}_ack_to_{ad(p["G"])}',
    83: lambda p, r, a: f'irq_v{irq(p, r)}_ack_halt',
    84: lambda p, r, a: f'irq_v{irq(p, r)}_ack_halt',
    85: lambda p, r, a: f'irq_v{irq(p, r)}_ack_to_{ad(p["G"])}',
    86: lambda p, r, a: f'irq_v{irq(p, r)}_ack_to_{ad(p["G"])}',
    87: lambda p, r, a: f'irq_v{irq(p, r)}_ack_to_{ad(p["G"])}',
    88: lambda p, r, a: f'irq_v{irq(p, r)}_ack_halt',
    89: lambda p, r, a: f'getw_{ad(p["A"])}',
    103: lambda p, r, a: f'getf_{ad(p["A"])}',
    106: lambda p, r, a: f'getl_{ad(p["A"])}',
}

PARAM = re.compile(r'([A-Za-z][A-Za-z0-9]*)=(-?0x[0-9A-Fa-f]+|[+-]?\d+)')


def members():
    """(class, address, params, raw, source file, class description) for every map line."""
    out = []
    cls, desc = None, {}
    for line in open(A_FILE):
        m = re.match(r'\s+(\d+)\s+\d+ x\s+\d+ insns\s+e\.g\. 0x[0-9A-F]+\s+(.*)$', line)
        if m:
            desc[int(m.group(1))] = m.group(2).strip()
        m = re.search(r'-- CLASS (\d+),', line)
        if line.startswith('==== FUNCTION') and m:
            cls = int(m.group(1))
        m = re.match(r';\s+0x([0-9A-F]{6})\s+callers\s+\d+\s+(?:\[[^\]]*\])?\s*(.*)$', line)
        if m and cls is not None:
            raw = m.group(2).strip()
            out.append((cls, int(m.group(1), 16), dict(PARAM.findall(raw)), raw, A_FILE, desc.get(cls, '')))
    cls, last, bdesc = None, None, {}
    for line in open(B_FILE):
        m = re.search(r'CLASS (\d+): \d+ members', line)
        if line.startswith('==== FUNCTION') and m:
            last = int(m.group(1))
        m = re.match(r'CONTRACT\s+(.*)$', line)
        if m and last is not None and last not in bdesc:
            bdesc[last] = m.group(1).strip()
        m = re.match(r';\s+class\s+(\d+)\s+([0-9A-F]{6})\s+callers\s+\d+\s*(.*)$', line)
        if m:
            c, raw = int(m.group(1)), m.group(3).strip()
            out.append((c, int(m.group(2), 16), dict(PARAM.findall(raw)), raw, B_FILE, bdesc.get(c, '')))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--apply', action='store_true')
    args = ap.parse_args()

    java = open(JAVA, encoding='utf-8').read()
    labelled = {int(m.group(1), 16) for m in re.finditer(r'label(?:Comment)?\(\s*(0x[0-9A-Fa-f]+)L?\s*,', java)}
    spec = json.load(open(SPEC))
    have = {int(r['address'], 16) for r in spec['records']}
    # names this tool wrote on an earlier run are not "existing labels"
    mine = {int(r['address'], 16) for r in spec['records'] if r.get('cluster', '').startswith('stub_members')}

    recs, skipped_cls, skipped_err = {}, {}, []
    allm = members()
    for c, a, p, raw, src, desc in allm:
        if (a in labelled or a in have) and a not in mine:
            continue
        f = T.get(c)
        if f is None:
            skipped_cls[c] = skipped_cls.get(c, 0) + 1
            continue
        try:
            name = f(p, raw, a)
        except (KeyError, ValueError, TypeError) as e:
            skipped_err.append((c, f'0x{a:06X}', raw, repr(e)))
            continue
        if not name or 'None' in name:
            skipped_err.append((c, f'0x{a:06X}', raw, 'no name'))
            continue
        d = re.sub(r'\s+', ' ', desc)
        if len(d) > 200:
            d = d[:197].rsplit(' ', 1)[0] + ' ...'
        comment = (f'Shape class {c}: {d} Member parameters: {re.sub(chr(32) + "+", " ", raw)}. '
                   f'Shape-matched and emulated per member.')
        recs[a] = dict(address=f'0x{a:06X}', kind='function', name=name, comment=comment,
                       trace=os.path.relpath(src, REPO), item=108,
                       cluster='stub_members_' + ('a' if src == A_FILE else 'b'), decoded_name=name)
    # unique names (several identical members share a template)
    by = {}
    for a, r in recs.items():
        by.setdefault(r['name'], []).append(a)
    taken = {r['name'] for r in spec['records'] if int(r['address'], 16) not in recs}
    for n, al in by.items():
        if len(al) > 1 or n in taken:
            for a in al:
                recs[a]['name'] = f'{n}_{a:06X}' if not n.endswith(f'{a:06X}') else n

    print(f'members in the maps: {len(allm)}; named: {len(recs)}; already labelled (kept): '
          f'{sum(1 for c, a, *_ in allm if (a in labelled or a in have) and a not in mine)}')
    print(f'skipped (no template), by class: {dict(sorted(skipped_cls.items()))}')
    for e in skipped_err:
        print('  could not name:', e)
    for a in sorted(recs)[:12]:
        print(f'   0x{a:06X}  {recs[a]["name"]}')
    if not args.apply:
        print('\n(report only; --apply merges into decoded_labels.json, then run sync_decoded_labels.py --apply)')
        return
    keep = [r for r in spec['records'] if not r.get('cluster', '').startswith('stub_members')]
    allr = {int(r['address'], 16): r for r in keep}
    allr.update(recs)
    spec['records'] = [allr[a] for a in sorted(allr)]
    json.dump(spec, open(SPEC, 'w'), indent=1)
    print('wrote', SPEC, len(spec['records']), 'records')


if __name__ == '__main__':
    main()
