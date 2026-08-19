"""Find files that may be stale because a CORRECTION landed after they were written.

    python scripts/doc_coherence.py              # report
    python scripts/doc_coherence.py --strict     # exit 1 if anything is flagged
    python scripts/doc_coherence.py --file X     # just one file

THE PROBLEM THIS SOLVES
Every claim in this repo is about an ADDRESS. When a corrections.md item settles
an address, every other file that mentions that address may now be wrong -- and
nothing connects them, so the stale one sits there looking authoritative. That
has happened repeatedly:

  * docs/knock.md called 0xAE6D4 "the threshold-shaped lookup" for months after
    item 82 established it is a dimensionless sigma multiplier
  * docs/ol-fueling.md repeated an OL-enrichment reading that item 95 disproved
  * CLAUDE.md carried "2 CONFLICT" after both were fixed

Saying "let's make sure everything is updated" does not catch these. This does,
mechanically.

HOW IT WORKS
1. Parse docs/corrections.md into items: number, date, and every ROM/RAM address
   the item mentions.
2. Keep the INVALIDATING ones -- headings saying CORRECTS, RETRACTED, WRONG,
   SUPERSEDES, FIXED, RESOLVED. Those are the items that make earlier prose wrong.
   Take only the addresses in the HEADING -- the SUBJECT of the correction. An
   address mentioned in passing in the body is not what the item re-settled, and
   matching on those buries the signal (it flagged 82 files on the first run).
3. For every tracked file, take its last git commit date.
4. Flag any file that mentions an address which an invalidating item touched
   AFTER that file was last changed.

A flag is a QUESTION, not a verdict: "this file talks about an address that was
re-settled after you last touched it -- go look." Clear it by checking the file
and, if it is fine, touching it in the same commit that adds the correction.
"""
import argparse
import collections
import glob
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, '..'))
CORRECTIONS = os.path.join(REPO, 'docs', 'corrections.md')

# Files whose claims can go stale. corrections.md and open-holes.md are the
# ledgers themselves, so they are excluded.
# Prose people read as CURRENT. Analysis files under disassembly/analysis/ are
# dated point-in-time records and are deliberately NOT tracked -- add --all to
# include them.
TRACKED = ['docs/*.md', 'CLAUDE.md']
TRACKED_ALL = TRACKED + ['disassembly/analysis/*.txt']
EXCLUDE = {'docs/corrections.md', 'docs/open-holes.md', 'docs/analysis-plan.md',
           'docs/README.md'}

INVALIDATING = re.compile(
    r'CORRECT|RETRACT|WRONG|SUPERSED|\bFIXED\b|RESOLVED|NOT\b|CLOSES', re.I)
ADDR = re.compile(r'\b(?:0x)?((?:FFFF[0-9A-Fa-f]{4})|(?:0[0-9A-Fa-f]{5})|(?:[0-9A-F]{5,6}))\b')
DATE = re.compile(r'(20\d\d)-(\d\d)-(\d\d)')


def norm(tok):
    """Normalise an address token to a comparable int, or None."""
    try:
        v = int(tok, 16)
    except ValueError:
        return None
    if 0xFFFF0000 <= v <= 0xFFFFFFFF:
        return v
    if 0x1000 <= v < 0x100000:
        return v
    return None


def parse_corrections():
    """-> list of (item_no, date, heading, set_of_addresses) for invalidating items."""
    text = open(CORRECTIONS, encoding='utf-8', errors='replace').read()
    items = []
    parts = re.split(r'\n## (\d+)\.', text)
    for i in range(1, len(parts) - 1, 2):
        no = int(parts[i])
        body = parts[i + 1]
        heading = body.split('\n', 1)[0]
        if not INVALIDATING.search(heading):
            continue
        m = DATE.search(heading) or DATE.search(body[:4000])
        date = '-'.join(m.groups()) if m else '0000-00-00'
        # SUBJECT addresses only: what the heading is about.
        addrs = {a for a in (norm(t) for t in ADDR.findall(heading)) if a}
        if addrs:
            items.append((no, date, heading.strip(), addrs))
    return items


def ubiquitous(items, files):
    """Addresses so common they cannot localise anything (ECT, RPM, load...)."""
    seen = collections.Counter()
    for rel in files:
        body = open(os.path.join(REPO, rel), encoding='utf-8', errors='replace').read()
        for a in {x for x in (norm(t) for t in ADDR.findall(body)) if x}:
            seen[a] += 1
    limit = max(6, len(files) // 4)
    return {a for a, c in seen.items() if c >= limit}


def git_date(path):
    try:
        out = subprocess.run(['git', 'log', '-1', '--format=%ad', '--date=short', '--', path],
                             cwd=REPO, capture_output=True, text=True, timeout=30)
        return (out.stdout or '').strip() or '0000-00-00'
    except Exception:
        return '0000-00-00'


def tracked_files(only=None, everything=False):
    files = []
    for pat in (TRACKED_ALL if everything else TRACKED):
        for f in glob.glob(os.path.join(REPO, pat)):
            rel = os.path.relpath(f, REPO).replace('\\', '/')
            if rel in EXCLUDE:
                continue
            if only and only not in rel:
                continue
            files.append(rel)
    return sorted(files)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--strict', action='store_true', help='exit 1 if anything is flagged')
    ap.add_argument('--file', help='check one file (substring match)')
    ap.add_argument('--all', action='store_true',
                    help='also check disassembly/analysis/*.txt (dated records)')
    args = ap.parse_args()

    items = parse_corrections()
    files = tracked_files(args.file, args.all)
    ubiq = ubiquitous(items, files)
    print('invalidating corrections items with a subject address: %d' % len(items))
    print('files checked: %d   ubiquitous addresses ignored: %d'
          % (len(files), len(ubiq)))

    flags = collections.defaultdict(list)
    for rel in files:
        fdate = git_date(rel)
        body = open(os.path.join(REPO, rel), encoding='utf-8', errors='replace').read()
        mentioned = {a for a in (norm(t) for t in ADDR.findall(body)) if a}
        if not mentioned:
            continue
        for no, idate, heading, addrs in items:
            if idate <= fdate:
                continue
            hit = (mentioned & addrs) - ubiq
            if hit:
                flags[rel].append((no, idate, heading, sorted(hit)[:4]))

    if not flags:
        print('\nNo file mentions an address re-settled after it was last changed.')
        return 0

    print('\n%d file(s) may be stale:\n' % len(flags))
    for rel in sorted(flags):
        print('%s  (last changed %s)' % (rel, git_date(rel)))
        for no, idate, heading, hit in sorted(flags[rel])[:6]:
            print('    item %-3s %s  %s' % (no, idate, heading[:72]))
            print('        shared: %s' % ', '.join('0x%X' % a for a in hit))
        if len(flags[rel]) > 6:
            print('    ... and %d more item(s)' % (len(flags[rel]) - 6))
        print()
    print('A flag is a QUESTION, not a verdict. Check the file; if it is already')
    print('correct, touch it in the commit that adds the correction so the dates align.')
    return 1 if args.strict else 0


if __name__ == '__main__':
    sys.exit(main())
