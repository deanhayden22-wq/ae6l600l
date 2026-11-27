#!/usr/bin/env python3
"""Apply labels for DECODED functions and re-settled RAM cells to the Ghidra import.

    python scripts/mapping/sync_decoded_labels.py            # report only
    python scripts/mapping/sync_decoded_labels.py --apply    # rewrite the two .java files

INPUT: disassembly/maps/decoded_labels.json -- one record per address whose meaning
was settled by a byte-level trace (a batch of the function programme,
docs/analysis-plan.md Part 1). Each record:

    {"address": "0x0BE800", "kind": "function" | "ram" | "rom",
     "name": "float_hysteresis_comparator",
     "comment": "one-line contract, from the trace",
     "trace": "disassembly/analysis/helpers_arith_trace.txt",
     "item": 107}

WHAT IT DOES TO ImportAE5L600L.java (address-keyed, matched on the PARSED address --
the same address is written 0xAD090, 0x0AD090L, 0x000AD090 in that file; text-keyed
edits have silently missed labels four times, corrections item 93):
  1. Removes EVERY existing `count += labelComment(ADDR, ...)` / `count += label(ADDR, ...)`
     statement at a record's address. Those names were claims; the record is the
     decoded replacement. (Several addresses carried two contradictory labels:
     0x00317C had interrupt_priority_set AND irq_level_set.)
  2. Writes one statement per record into a managed block placed LAST in run(), so its
     name is the primary label and its comment the one that sticks (labelComment =
     createLabel(..., primary=true) + setEOLComment; the last call wins).

AND TO RetireStaleLabels.java: every removed (address, name) whose name differs from
the record's goes into a managed drop() block, because deleting a statement does not
unlabel a program that was already imported (CLAUDE.md, "labels are ADDITIVE").

Idempotent: re-running produces the same files. A removed statement is recorded in
the managed retire block, so a second run still retires it.
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, '..', '..'))
JAVA = os.path.join(REPO, 'disassembly', 'ghidra', 'ImportAE5L600L.java')
RETIRE = os.path.join(REPO, 'disassembly', 'ghidra', 'RetireStaleLabels.java')
SPEC = os.path.join(REPO, 'disassembly', 'maps', 'decoded_labels.json')

BEGIN = '        // >>> BEGIN decoded labels (sync_decoded_labels.py) -- do not hand-edit >>>'
END = '        // <<< END decoded labels <<<'
ANCHOR = '        printf("ImportAE5L600L: Applied %d labels/comments.\\n", count);'

R_BEGIN = '        // >>> BEGIN retired by sync_decoded_labels.py -- do not hand-edit >>>'
R_END = '        // <<< END retired by sync_decoded_labels.py <<<'

STMT = re.compile(r'^[ \t]*count \+= label(?:Comment)?\(\s*(0x[0-9A-Fa-f]+)L?\s*,\s*"([^"]*)"', re.M)


def statement_end(text, i):
    """Index just past the `);` that ends the statement starting at i (string-aware)."""
    j = text.index('(', i) + 1
    depth, in_str = 1, False
    while j < len(text):
        c = text[j]
        if in_str:
            if c == '\\':
                j += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                k = text.index(';', j) + 1
                if k < len(text) and text[k] == '\n':
                    k += 1
                return k
        j += 1
    raise ValueError(f'unterminated statement at {i}')


def strip_block(text, begin, end):
    if begin not in text:
        return text, ''
    a = text.index(begin)
    b = text.index(end, a) + len(end)
    if b < len(text) and text[b] == '\n':
        b += 1
    return text[:a] + text[b:], text[a:b]


def jstr(s):
    return s.replace('\\', '\\\\').replace('"', '\\"')


def wrap(comment, width=96):
    """Java string concatenation across lines."""
    words, lines, cur = comment.split(' '), [], ''
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            lines.append(cur + ' ')
            cur = w
        else:
            cur = f'{cur} {w}' if cur else w
    lines.append(cur)
    out = '            "' + jstr(lines[0]) + '"'
    for ln in lines[1:]:
        out += '\n            + "' + jstr(ln) + '"'
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--apply', action='store_true')
    args = ap.parse_args()

    spec = json.load(open(SPEC))['records']
    recs = {int(r['address'], 16): r for r in spec}

    java = open(JAVA, encoding='utf-8').read()
    java, _ = strip_block(java, BEGIN, END)
    retire_src = open(RETIRE, encoding='utf-8').read()
    retire_src, old_block = strip_block(retire_src, R_BEGIN, R_END)
    retired = set()
    for m in re.finditer(r'drop\((0x[0-9A-Fa-f]+)L, "([^"]+)"\)', old_block):
        retired.add((int(m.group(1), 16), m.group(2)))

    # 1. remove existing statements at record addresses
    removed = []
    out, pos = [], 0
    for m in STMT.finditer(java):
        a = int(m.group(1), 16)
        if a not in recs or m.start() < pos:
            continue
        line_start = java.rfind('\n', 0, m.start()) + 1
        end = statement_end(java, m.start())
        out.append(java[pos:line_start])
        pos = end
        removed.append((a, m.group(2)))
    out.append(java[pos:])
    java = ''.join(out)
    for a, n in removed:
        if n != recs[a]['name']:
            retired.add((a, n))

    # 2. managed block, last in run()
    if ANCHOR not in java:
        sys.exit('anchor printf not found in ImportAE5L600L.java')
    lines = [BEGIN,
             '        // One label per address whose meaning a byte-level trace settled (function',
             '        // programme, docs/analysis-plan.md Part 1). Placed last so these names are',
             '        // primary. Source: disassembly/maps/decoded_labels.json.']
    for a in sorted(recs):
        r = recs[a]
        tag = '[DECODED]' if r['kind'] == 'function' else '[TRACED]'
        c = f"{tag} {r['comment']} Trace: {os.path.basename(r['trace'])} (corrections item {r['item']})."
        lit = f'0x{a:08X}L'
        lines.append(f'        count += labelComment({lit}, "{jstr(r["name"])}",\n{wrap(c)});')
    lines.append(END)
    block = '\n'.join(lines) + '\n\n'
    java = java.replace(ANCHOR, block + ANCHOR, 1)

    # 3. retire block
    rl = [R_BEGIN,
          '        // Names removed from ImportAE5L600L.java because a decoded trace replaced',
          '        // them (disassembly/maps/decoded_labels.json; corrections item 107 onward).']
    for a, n in sorted(retired):
        rl.append(f'        n += drop(0x{a:08X}L, "{jstr(n)}");')
    rl.append(R_END)
    r_block = '\n'.join(rl) + '\n'
    m = re.search(r'\n([ \t]*)println\(\s*"Removed', retire_src) or re.search(r'\n[ \t]*println\(', retire_src)
    anchor_i = retire_src.rfind('\n', 0, m.start() + 1) + 1 if m else None
    if anchor_i is None:
        sys.exit('no println anchor in RetireStaleLabels.java')

    print(f'records: {len(recs)}  ({sum(1 for r in recs.values() if r["kind"] == "function")} functions)')
    print(f'existing statements removed at record addresses: {len(removed)}')
    print(f'names retired (managed block total): {len(retired)}')
    for a, n in sorted(retired):
        print(f'   0x{a:06X}  {n}  ->  {recs.get(a, {}).get("name", "?")}')
    if not args.apply:
        print('\n(report only; --apply writes both files)')
        return
    retire_src = retire_src[:anchor_i] + r_block + retire_src[anchor_i:]
    total = len(re.findall(r'^\s*n \+= drop\(', retire_src, re.M))
    retire_src = re.sub(r'removed " \+ n \+ " of \d+ stale', f'removed " + n + " of {total} stale', retire_src)
    open(JAVA, 'w', encoding='utf-8', newline='\n').write(java)
    open(RETIRE, 'w', encoding='utf-8', newline='\n').write(retire_src)
    print('wrote', JAVA, 'and', RETIRE)


if __name__ == '__main__':
    main()
