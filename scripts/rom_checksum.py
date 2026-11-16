#!/usr/bin/env python3
"""Validate (and, into a NEW file, repair) the AE5L600L checksum table.

    python3 scripts/rom_checksum.py rom/*.bin              # verify; exit 1 if any bin fails
    python3 scripts/rom_checksum.py --quiet rom/*.bin      # one summary line
    python3 scripts/rom_checksum.py --covers 0x0F1000 rom/ae5l600l.bin
    python3 scripts/rom_checksum.py --fix out.bin in.bin   # write in.bin with sums recomputed to out.bin
    python3 scripts/rom_checksum.py --selftest             # positive + negative controls on rom/

THE RULE -- decoded from ROM bytes, not taken from a tuning tool (2026-11-15)
The table is 17 records of (start, end, stored) big-endian longs at 0xFFB80,
followed by 0xFFFFFFFF at 0xFFC4C. The ECU checks one record like this
(routine 0x01002A; 0x0101BA and the one ending 0x087EDA are the same rule):

    010030 mov.l @(0x010104),r2       ; r2 = 0x000FFB80          table base
    010040..046                       ; r4 = base + idx*12
    010048 mov.l @r4,r14              ; start
    01004A mov.l @(4,r4),r12          ; end
    01004E bsr 0x010668               ; range-shape check (below); nonzero -> fail
    010064 mov.l @r14+,r2 / cmp/hs r12,r14 / bf/s / add r2,r13
                                      ; r13 = sum of longs from start while ptr < end
    01006C mov.l @(0x01010C),r0       ; 0x000FFB88 = base + 8      stored field
    01007A mov.l @(r0,r2),r1 / add r1,r13
    010078 mov.l @(0x010110),r3       ; 0x5AA5A55A
    01007E cmp/eq r3,r13              ; pass iff  sum + stored == 0x5AA5A55A (mod 2^32)

Range-shape check 0x010668 returns 1 (fail) unless: start is 4-aligned, start <= end,
and (end & 3) == 3 or start == end. An unused record is (0, 0, 0x5AA5A55A): zero longs
summed, so stored must equal the magic.

PROOF: every bin in rom/ (19, stock + 20.8 .. 20.19d, all flashed and driven) passes
all 17 records. --selftest re-runs that and also flips one byte in each used range of
each bin and requires a failure.

NOT ESTABLISHED: what the ECU does on a mismatch (the fail path stores 1 to
0xFFFF5B8C and calls 0x0106B6 / 0x010800 -- not traced). 0x000000-0x001FFF and
0x0FFAF8-0x0FFFFF are covered by NO record in any bin here: corruption there is not
caught by this check, which is why the patch linter treats them as never-touch.
"""
import argparse
import glob
import os
import struct
import sys

TABLE = 0x0FFB80
RECORDS = 17
REC = 12
TERMINATOR_AT = TABLE + RECORDS * REC        # 0x0FFC4C
MAGIC = 0x5AA5A55A
ROM_SIZE = 0x100000
M32 = 0xFFFFFFFF

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def records(rom):
    for i in range(RECORDS):
        o = TABLE + i * REC
        s, e, c = struct.unpack('>III', rom[o:o + REC])
        yield i, o, s, e, c


def shape_ok(s, e):
    """Replicates 0x010668 (returns True where the ECU's helper returns 0)."""
    if s & 3:
        return False
    if s > e:
        return False
    return (e & 3) == 3 or s == e


def word_sum(rom, s, e):
    """Replicates the 0x010064 loop: longs at s, s+4, ... while the pointer < e."""
    total, p = 0, s
    while p < e:
        total += struct.unpack('>I', rom[p:p + 4])[0]
        p += 4
    return total & M32


def required(rom, s, e):
    return (MAGIC - word_sum(rom, s, e)) & M32


def check(rom):
    """Return (problems, used_ranges). problems is a list of strings; empty = valid."""
    probs, used = [], []
    if len(rom) != ROM_SIZE:
        return [f'size {len(rom):#x}, expected {ROM_SIZE:#x}'], used
    for i, o, s, e, c in records(rom):
        if not shape_ok(s, e):
            probs.append(f'record {i} @{o:#07x}: range {s:#x}-{e:#x} fails the 0x010668 shape check')
            continue
        if e >= ROM_SIZE:
            probs.append(f'record {i} @{o:#07x}: end {e:#x} outside ROM')
            continue
        if (word_sum(rom, s, e) + c) & M32 != MAGIC:
            probs.append(f'record {i} @{o:#07x}: {s:#07x}-{e:#07x} stored {c:#010x}, '
                         f'needs {required(rom, s, e):#010x}')
        if s != e:
            used.append((s, e))
    term = struct.unpack('>I', rom[TERMINATOR_AT:TERMINATOR_AT + 4])[0]
    if term != 0xFFFFFFFF:
        probs.append(f'terminator at {TERMINATOR_AT:#07x} is {term:#010x}, expected 0xFFFFFFFF')
    for s, e in used:
        if s <= TERMINATOR_AT + 3 and e >= TABLE:
            probs.append(f'range {s:#x}-{e:#x} covers the checksum table itself')
    return probs, used


def fix(rom):
    """Return a copy with every used record's stored sum recomputed. Ranges are not changed."""
    out = bytearray(rom)
    for i, o, s, e, c in records(rom):
        if s == e or not shape_ok(s, e):
            continue
        struct.pack_into('>I', out, o + 8, required(out, s, e))
    return bytes(out)


def selftest():
    bins = sorted(glob.glob(os.path.join(REPO, 'rom', '*.bin')))
    if not bins:
        print('no bins in rom/'); return 1
    bad = 0
    for path in bins:
        rom = open(path, 'rb').read()
        probs, used = check(rom)
        if probs:
            print(f'POSITIVE CONTROL FAILED {os.path.basename(path)}: {probs}'); bad += 1
            continue
        if fix(rom) != rom:
            print(f'FIX NOT IDEMPOTENT {os.path.basename(path)}'); bad += 1
        for s, e in used:
            mid = (s + (e - s) // 2) & ~3
            mutated = bytearray(rom); mutated[mid] ^= 0x01
            if not check(bytes(mutated))[0]:
                print(f'NEGATIVE CONTROL MISSED {os.path.basename(path)} flip @{mid:#x}'); bad += 1
            if check(fix(bytes(mutated)))[0]:
                print(f'FIX DID NOT REPAIR {os.path.basename(path)} flip @{mid:#x}'); bad += 1
    print(f'selftest: {len(bins)} bins, {"FAIL" if bad else "pass"} ({bad} problem(s))')
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('bins', nargs='*')
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--covers', type=lambda x: int(x, 0), help='list records whose range covers ADDR')
    ap.add_argument('--fix', metavar='OUT', help='write the first bin with sums recomputed to OUT (never in place)')
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args()

    if a.selftest:
        return selftest()
    if not a.bins:
        ap.error('no bins given')

    if a.fix:
        src = a.bins[0]
        if os.path.abspath(a.fix) == os.path.abspath(src):
            ap.error('--fix never writes in place')
        if os.path.abspath(a.fix).startswith(os.path.join(REPO, 'rom') + os.sep):
            ap.error('--fix never writes into rom/')
        out = fix(open(src, 'rb').read())
        probs, _ = check(out)
        if probs:
            print('still invalid after fix (a range is malformed, not a sum):'); [print('  ' + p) for p in probs]
            return 1
        open(a.fix, 'wb').write(out)
        print(f'wrote {a.fix}: all {RECORDS} records valid')
        return 0

    failed = 0
    for path in a.bins:
        rom = open(path, 'rb').read()
        if a.covers is not None:
            hits = [f'record {i} {s:#07x}-{e:#07x}' for i, o, s, e, c in records(rom)
                    if s != e and s <= a.covers <= e]
            print(f'{os.path.basename(path)}: {a.covers:#x} covered by ' + (', '.join(hits) or 'NO record'))
            continue
        probs, used = check(rom)
        if probs:
            failed += 1
            print(f'FAIL {path}')
            for p in probs:
                print('  ' + p)
        elif not a.quiet:
            print(f'ok   {path}  ({len(used)} used records)')
    if a.covers is None:
        print(f'{len(a.bins) - failed} of {len(a.bins)} bins valid' if a.quiet or failed else '')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
