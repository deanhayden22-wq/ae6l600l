"""Check every "address = value" statement in the docs against the ROM on the car.

    python scripts/doc_value_check.py --rev 20.19c            # subsystem docs + memory notes
    python scripts/doc_value_check.py --rev 20.19c --all      # also tune-state / open-issues
    python scripts/doc_value_check.py --rev 20.19c --md       # also write the report file

--rev is REQUIRED. There is no default: say which ROM is on the car.

WHY THIS EXISTS
The 2026-10-11 claim audit (corrections.md item 98) found seven numbers in
boost-control.md and knock.md that are the STOCK ROM's values, written as if
they described the tune. No model is needed to catch that -- only reading the
address. This does it for every doc, with no API and no cost.

WHAT IT READS AS A STATEMENT
  * a markdown table row with an address in one cell and a number in the next
  * inline `0xADDR = number`
The number is compared with what the address holds as float32, uint16, int16,
uint8 and int8, and with the definition-file display value where the address
is a defined table. It only needs to match one of them.

  ok        matches the chosen rev
  STOCK     does not match the chosen rev, DOES match stock   <- the item-98 class
  OLD-REV   matches some other rev in rom/, not the chosen one and not stock
  NO-MATCH  matches no rev in any encoding. Read the line: the number may not
            be a value at all, or may be in units this script does not know.

A statement that is deliberately about another rev ("stock: 1800") will be
flagged. That is why tune-state.md and open-issues.md are skipped unless --all.
Nothing here edits a doc.
"""
import argparse
import glob
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, '..'))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, 'analysis'))
import defs                       # noqa: E402
from rev_order import REV_ORDER   # noqa: E402
from rom_diff import resolve_bin  # noqa: E402

MEMORY_DIR = os.path.expanduser(
    os.path.join('~', '.claude', 'projects', 'C--Users-Dean-Documents-GitHub-ae6l600l', 'memory'))
HISTORY_DOCS = {'tune-state.md', 'open-issues.md', 'closed-issues.md', 'corrections.md',
                'verification-status.md', 'open-holes.md', 'analysis-plan.md'}
REPORT = os.path.join(REPO, 'docs', 'exploration', 'doc_value_check.md')

ADDR = r'`?(?:0x)([0-9A-Fa-f]{5,8})`?'
NUM = r'[-−+]?\d[\d,]*\.?\d*(?:[eE][-+]?\d+)?'


def parse_number(cell):
    """(value, decimals) if the cell is essentially one number, else None."""
    s = cell.strip().strip('*`_ ').replace('−', '-')
    m = re.fullmatch(r'(' + NUM.replace(r'−', '') + r')f?\s*(?:%|deg|°|psi|ms|rpm|RPM)?', s)
    if not m:
        return None
    txt = m.group(1).replace(',', '')
    try:
        v = float(txt)
    except ValueError:
        return None
    dec = len(txt.split('.')[1]) if '.' in txt and 'e' not in txt.lower() else 0
    return v, dec


def statements(text):
    """Yield (line number, address, value, decimals, line)."""
    for n, line in enumerate(text.split('\n'), 1):
        if line.lstrip().startswith('|'):
            cells = [c for c in line.strip().strip('|').split('|')]
            for i, c in enumerate(cells[:-1]):
                m = re.fullmatch(r'\s*\**' + ADDR + r'\**\s*', c)
                num = parse_number(cells[i + 1]) if m else None
                if m and num:
                    yield n, int(m.group(1), 16), num[0], num[1], line.strip()
            continue
        for m in re.finditer(ADDR + r'\s*=\s*\**(' + NUM + r')f?\b', line):
            num = parse_number(m.group(2))
            if num:
                yield n, int(m.group(1), 16), num[0], num[1], line.strip()


def candidates(rom, addr, table):
    """Every plausible reading of the value at addr."""
    out = {}
    if addr + 4 <= len(rom):
        f = struct.unpack_from('>f', rom, addr)[0]
        if f == f and abs(f) < 1e9:
            out['float32'] = f
    if addr + 2 <= len(rom):
        out['uint16'] = struct.unpack_from('>H', rom, addr)[0]
        out['int16'] = struct.unpack_from('>h', rom, addr)[0]
    out['uint8'] = rom[addr]
    out['int8'] = struct.unpack_from('>b', rom, addr)[0]
    if table is not None:
        try:
            v = table.read(rom)
            while isinstance(v, (list, tuple)) and v:
                v = v[0]
            if isinstance(v, (int, float)):
                out['display'] = float(v)
        except Exception:
            pass
    return out


def matches(claim, dec, cands):
    tol = 0.5 * 10 ** (-dec) + 1e-4 * abs(claim) + 1e-9
    return [k for k, v in cands.items() if abs(v - claim) <= tol]


def best(cands):
    if 'display' in cands:
        return 'display %.6g' % cands['display']
    f = cands.get('float32')
    if f is not None and (f == 0 or 1e-4 < abs(f) < 1e7):
        return 'float32 %.6g' % f
    return 'uint16 %d / uint8 %d' % (cands.get('uint16', -1), cands['uint8'])


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--rev', required=True, help='the rev on the car, e.g. 20.19c')
    ap.add_argument('--all', action='store_true',
                    help='also check tune-state.md, open-issues.md and other history docs')
    ap.add_argument('--md', action='store_true', help='write docs/exploration/doc_value_check.md')
    ap.add_argument('--show-ok', action='store_true')
    args = ap.parse_args()

    car = resolve_bin(args.rev)
    if not car:
        sys.exit('no ROM file found for rev "%s" in rom/' % args.rev)
    roms = {}
    for r in REV_ORDER:
        p = resolve_bin(r)
        if p and r != 'garn_base':
            roms[r] = open(p, 'rb').read()
    roms.setdefault(args.rev, open(car, 'rb').read())
    print('ROM ON THE CAR (you said): rev %s = %s' % (args.rev, os.path.basename(str(car))))
    print('compared against %d revs in rom/: %s' % (len(roms), ', '.join(roms)))

    d = defs.load()
    by_addr = {t.address: t for t in d.tables if isinstance(getattr(t, 'address', None), int)}

    files = [f for f in sorted(glob.glob(os.path.join(REPO, 'docs', '*.md')))
             if args.all or os.path.basename(f) not in HISTORY_DOCS]
    files += sorted(glob.glob(os.path.join(MEMORY_DIR, '*.md')))
    rows, counts = [], {'ok': 0, 'STOCK': 0, 'OLD-REV': 0, 'NO-MATCH': 0}
    for f in files:
        name = os.path.relpath(f, REPO) if f.startswith(REPO) else 'memory/' + os.path.basename(f)
        text = open(f, encoding='utf-8', errors='replace').read()
        for n, addr, val, dec, line in statements(text):
            if not (0x400 <= addr < 0x100000):
                continue
            t = by_addr.get(addr)
            now = candidates(roms[args.rev], addr, t)
            if matches(val, dec, now):
                status, where = 'ok', ''
            else:
                hit = [r for r, rom in roms.items() if matches(val, dec, candidates(rom, addr, t))]
                if 'stock' in hit:
                    status = 'STOCK'
                elif hit:
                    status = 'OLD-REV'
                else:
                    status = 'NO-MATCH'
                where = ', '.join(hit)
            counts[status] += 1
            rows.append((status, name, n, addr, val, best(now), where,
                         t.name if t is not None else '', line))

    print('\n%d statements checked in %d files: %d ok, %d STOCK, %d OLD-REV, %d NO-MATCH\n'
          % (len(rows), len(files), counts['ok'], counts['STOCK'], counts['OLD-REV'],
             counts['NO-MATCH']))
    order = {'STOCK': 0, 'OLD-REV': 1, 'NO-MATCH': 2, 'ok': 3}
    rows.sort(key=lambda r: (order[r[0]], r[1], r[2]))
    for status, name, n, addr, val, cur, where, tname, line in rows:
        if status == 'ok' and not args.show_ok:
            continue
        print('%-8s %s:%d  0x%05X  doc says %g, rev %s has %s%s%s' % (
            status, name, n, addr, val, args.rev, cur,
            ('  [matches: %s]' % where) if where else '',
            ('  (%s)' % tname) if tname else ''))

    if args.md:
        os.makedirs(os.path.dirname(REPORT), exist_ok=True)
        L = ['# Doc values checked against rev %s' % args.rev, '',
             '> Generated by `scripts/doc_value_check.py --rev %s`. ROM file: `%s`.'
             % (args.rev, os.path.basename(str(car))),
             '> A flagged row is a line to READ, not a proven error: a statement that is',
             '> deliberately about another rev is flagged too.', '',
             '%d statements in %d files: %d ok, **%d STOCK**, %d OLD-REV, %d NO-MATCH.'
             % (len(rows), len(files), counts['ok'], counts['STOCK'], counts['OLD-REV'],
                counts['NO-MATCH']), '',
             '| Status | Where | Address | Doc says | Rev %s has | Also matches | Definition name |'
             % args.rev, '|---|---|---|---|---|---|---|']
        for status, name, n, addr, val, cur, where, tname, line in rows:
            if status != 'ok':
                L.append('| %s | %s:%d | 0x%05X | %g | %s | %s | %s |' % (
                    status, name.replace('\\', '/'), n, addr, val, cur, where or '-', tname or '-'))
        with open(REPORT, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write('\n'.join(L) + '\n')
        print('\nwrote: %s' % os.path.relpath(REPORT, REPO))
    return 1 if counts['STOCK'] or counts['OLD-REV'] else 0


if __name__ == '__main__':
    sys.exit(main())
