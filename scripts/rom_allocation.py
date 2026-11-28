#!/usr/bin/env python3
"""The ROM/RAM allocation registry (docs/allocation.json): validate it, audit bins against it,
list free ROM, and check a new patch's claims.

    python3 scripts/rom_allocation.py --audit rom/AE5L600L*.bin   # every off-table change is claimed?
    python3 scripts/rom_allocation.py --free                      # free 0xFF runs, minus claims
    python3 scripts/rom_allocation.py --check-claims plan.json    # a new patch's ranges collide?

--audit is the registry's proof: for each bin, every byte that differs from the base
(stock) must lie in a definition-XML table or axis, the checksum table, or a registry
claim. An unclaimed changed byte is a FAIL -- either the registry is incomplete or the
bin carries a change nobody has accounted for. Either way, do not flash it.

--check-claims takes {"rom": [{"start","end"}...], "ram": [{"start","end"}...]} (the
claims a plan proposes) and fails on overlap with an existing claim, a never-touch
range, a definition table, non-0xFF base bytes (for kind injected-code), or RAM outside
0xFFFF0000-0xFFFFBFFF.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import defs  # noqa: E402
import rom_checksum as CK  # noqa: E402

REGISTRY = os.path.join(REPO, 'docs', 'allocation.json')
ROM_SIZE = 0x100000
RAM_LO, RAM_HI = 0xFFFF0000, 0xFFFFBFFF
MIN_FREE = 64


def h(x):
    return int(x, 16) if isinstance(x, str) else int(x)


def load_registry(path=REGISTRY):
    reg = json.load(open(path))
    for c in reg['rom'] + reg['never_touch']:
        c['s'], c['e'] = h(c['start']), h(c['end'])
    for c in reg['ram']['claims']:
        c['s'], c['e'] = h(c['start']), h(c['end'])
    return reg


def live(claims):
    return [c for c in claims if not c.get('retired')]


def table_mask():
    """1 where a definition table or axis lives, 2 for the checksum table."""
    d = defs.load()
    m = bytearray(ROM_SIZE)
    for t in d.tables:
        spans = []
        if t.address is not None and t.end_address:
            spans.append((t.address, t.end_address))
        for ax in (t.x_axis, t.y_axis):
            if ax is not None and ax.address is not None and ax.byte_length:
                spans.append((ax.address, ax.address + ax.byte_length))
        for s, e in spans:
            for a in range(max(0, s), min(e, ROM_SIZE)):
                m[a] = 1
    for a in range(CK.TABLE, CK.TERMINATOR_AT + 4):
        m[a] = 2
    return m


def overlaps(a, b):
    return a['s'] <= b['e'] and b['s'] <= a['e']


def validate(reg):
    probs = []
    rom = live(reg['rom'])
    for i, a in enumerate(rom):
        if a['s'] > a['e']:
            probs.append(f"{a['id']}: start after end")
        for b in rom[i + 1:]:
            if overlaps(a, b):
                probs.append(f"{a['id']} overlaps {b['id']}")
        for n in reg['never_touch']:
            if overlaps(a, n):
                probs.append(f"{a['id']} overlaps never-touch {n['start']}-{n['end']}")
    ram = live(reg['ram']['claims'])
    for i, a in enumerate(ram):
        if not (RAM_LO <= a['s'] <= a['e'] <= RAM_HI):
            probs.append(f"RAM claim {a.get('id')} outside on-chip RAM")
        for b in ram[i + 1:]:
            if overlaps(a, b):
                probs.append(f"RAM claim {a.get('id')} overlaps {b.get('id')}")
    return probs


def runs(addrs, gap=4):
    out = []
    for a in addrs:
        if out and a - out[-1][1] <= gap:
            out[-1][1] = a
        else:
            out.append([a, a])
    return out


def audit(reg, bins, quiet):
    base = open(os.path.join(REPO, reg['base']), 'rb').read()
    mask = table_mask()
    claimed = bytearray(ROM_SIZE)
    for c in live(reg['rom']):
        for a in range(c['s'], c['e'] + 1):
            claimed[a] = 1
    failed = 0
    for path in bins:
        rom = open(path, 'rb').read()
        if len(rom) != ROM_SIZE:
            print(f'FAIL {path}: size {len(rom):#x}'); failed += 1; continue
        stray = [a for a in range(ROM_SIZE) if rom[a] != base[a] and not mask[a] and not claimed[a]]
        bad_nt = [a for n in reg['never_touch'] for a in range(n['s'], n['e'] + 1)
                  if rom[a] != base[a] and mask[a] != 2]
        if stray or bad_nt:
            failed += 1
            print(f'FAIL {path}')
            for s, e in runs(stray):
                print(f'  unclaimed change {s:#08x}-{e:#08x}')
            for s, e in runs(bad_nt):
                print(f'  NEVER-TOUCH changed {s:#08x}-{e:#08x}')
        elif not quiet:
            print(f'ok   {path}')
    print(f'{len(bins) - failed} of {len(bins)} bins fully accounted for')
    return 1 if failed else 0


def free(reg, rom_path):
    rom = open(rom_path, 'rb').read()
    taken = bytearray(ROM_SIZE)
    for c in live(reg['rom']) + reg['never_touch']:
        for a in range(c['s'], c['e'] + 1):
            taken[a] = 1
    out, a = [], 0
    while a < ROM_SIZE:
        if rom[a] == 0xFF and not taken[a]:
            s = a
            while a < ROM_SIZE and rom[a] == 0xFF and not taken[a]:
                a += 1
            if a - s >= MIN_FREE:
                out.append((s, a - 1))
        else:
            a += 1
    total = 0
    for s, e in out:
        cov = [i for i, o, cs, ce, c in CK.records(rom) if cs != ce and cs <= e and s <= ce]
        print(f'{s:#08x}-{e:#08x}  {e - s + 1:7d} B  checksum record(s) {cov}')
        total += e - s + 1
    print(f'{total} bytes free in {len(out)} run(s) of >= {MIN_FREE} B (0xFF in {os.path.basename(rom_path)}, unclaimed)')
    print('Free here means "0xFF and unclaimed", not "nothing jumps here": gate 6 still needs the reader scan.')
    return 0


def check_claims(reg, plan_path):
    plan = json.load(open(plan_path))
    base = open(os.path.join(REPO, reg['base']), 'rb').read()
    mask = table_mask()
    probs = []
    for c in plan.get('rom', []):
        c['s'], c['e'] = h(c['start']), h(c['end'])
        tag = c.get('id', f"{c['start']}-{c['end']}")
        for o in live(reg['rom']):
            if overlaps(c, o):
                if c.get('amends') == o['id'] and o['s'] <= c['s'] and c['e'] <= o['e']:
                    continue                        # an edit inside another patch's claim, declared
                probs.append(f'{tag} overlaps registry claim {o["id"]}'
                             + (' (declare "amends": "%s" if it edits that patch)' % o['id']))
        for n in reg['never_touch']:
            if overlaps(c, n):
                probs.append(f'{tag} overlaps never-touch {n["start"]}-{n["end"]}')
        if any(mask[a] for a in range(c['s'], c['e'] + 1)):
            probs.append(f'{tag} overlaps a definition table/axis or the checksum table')
        if c.get('kind') == 'injected-code' and any(base[a] != 0xFF for a in range(c['s'], c['e'] + 1)):
            probs.append(f'{tag} is injected-code but the base is not 0xFF there')
    for c in plan.get('ram', []):
        c['s'], c['e'] = h(c['start']), h(c['end'])
        tag = c.get('id', f"{c['start']}-{c['end']}")
        if not (RAM_LO <= c['s'] <= c['e'] <= RAM_HI):
            probs.append(f'{tag} is outside on-chip RAM 0xFFFF0000-0xFFFFBFFF')
        for o in live(reg['ram']['claims']):
            if overlaps(c, o):
                probs.append(f'{tag} overlaps RAM claim {o.get("id")}')
        if not c.get('evidence'):
            probs.append(f'{tag} has no "evidence" that the RAM is unused')
        elif str(c['evidence']).upper().startswith('PLACEHOLDER'):
            probs.append(f'{tag} is a PLACEHOLDER, not evidence: settle it before this patch can pass')
    for p in probs:
        print('FAIL ' + p)
    print('claims clear' if not probs else f'{len(probs)} problem(s)')
    return 1 if probs else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--audit', nargs='+', metavar='BIN')
    ap.add_argument('--free', nargs='?', const=os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19d.bin'), metavar='BIN')
    ap.add_argument('--check-claims', metavar='PLAN_JSON')
    ap.add_argument('--quiet', action='store_true')
    a = ap.parse_args()
    reg = load_registry()
    probs = validate(reg)
    if probs:
        print('REGISTRY INVALID'); [print('  ' + p) for p in probs]
        return 1
    if a.audit:
        return audit(reg, a.audit, a.quiet)
    if a.free:
        return free(reg, a.free)
    if a.check_claims:
        return check_claims(reg, a.check_claims)
    print(f"registry valid: {len(live(reg['rom']))} ROM claims, {len(reg['never_touch'])} never-touch ranges, "
          f"{len(live(reg['ram']['claims']))} RAM claims")
    return 0


if __name__ == '__main__':
    sys.exit(main())
