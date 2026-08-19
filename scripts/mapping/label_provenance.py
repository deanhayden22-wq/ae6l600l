"""Classify every Ghidra label by how much evidence stands behind it.

    python scripts/mapping/label_provenance.py            # report
    python scripts/mapping/label_provenance.py --apply    # stamp the class into
                                                          # each label's comment

WHY THIS EXISTS
A Ghidra label is asserted as fact. Nothing in the listing distinguishes a name
proven by decoding bytes from one somebody guessed, so a session that does not
re-derive everything from scratch treats them alike -- and then builds a
conclusion on a guess. That has happened repeatedly:

  * 106 labels asserted an ISR dispatch table that does not exist (item 91)
  *   5 put float/descriptor names on six-instruction byte flag readers (item 92)
  *   "ol_enrichment_accum" drove an inference that the consumer trace then
      contradicted (item 95)
  * 48 invented "Map Switching *" names have zero support in the definition XMLs

corrections.md records every fix, but it is 95 items long and nobody reads it
before trusting a label in the listing. This tool moves the warning to where the
wrong conclusion actually forms: the comment attached to the label.

THE THREE CLASSES
  TRACED      the address appears in a verifier-checked file under
              disassembly/analysis/. Bytes were decoded and machine-checked
              against the ROM. Strongest available.
  CITED       appears in docs/corrections.md but in no analysis file. Somebody
              reasoned about it and wrote it down; no byte-level check.
  UNVERIFIED  appears in neither. The name is the ONLY artefact. Treat as a
              hypothesis, never as a premise.

None of these means the NAME is right -- TRACED means the address was decoded,
not that the identity was proven. See CLAUDE.md on VERIFIED-BOTH for the same
distinction on the table side.
"""
import argparse
import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, '..', '..'))
JAVA = os.path.join(REPO, 'disassembly', 'ghidra', 'ImportAE5L600L.java')
ANALYSIS = os.path.join(REPO, 'disassembly', 'analysis', '*.txt')
CORRECTIONS = os.path.join(REPO, 'docs', 'corrections.md')

TAGS = ('[TRACED]', '[CITED]', '[UNVERIFIED]')


def corpora():
    traced = ''
    for f in glob.glob(ANALYSIS):
        traced += open(f, encoding='utf-8', errors='replace').read().upper()
    cited = open(CORRECTIONS, encoding='utf-8', errors='replace').read().upper()
    return traced, cited


def classify(addr, traced, cited):
    forms = ('%06X' % addr, '%08X' % addr, '%05X' % addr)
    if any(f in traced for f in forms):
        return 'TRACED'
    if any(f in cited for f in forms):
        return 'CITED'
    return 'UNVERIFIED'


CALL = re.compile(r'labelComment\((0x[0-9A-Fa-f]+)L?,\s*"([^"]+)",\s*\n?\s*"')


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--apply', action='store_true',
                    help='stamp the class into each comment (idempotent)')
    args = ap.parse_args()

    src = open(JAVA, encoding='utf-8', errors='replace').read()
    traced, cited = corpora()

    counts = {'TRACED': 0, 'CITED': 0, 'UNVERIFIED': 0}
    seen = {}
    for m in re.finditer(r'labelComment\((0x[0-9A-Fa-f]+)L?,\s*"([^"]+)"', src):
        a = int(m.group(1), 16)
        if a not in seen:
            seen[a] = classify(a, traced, cited)
    for c in seen.values():
        counts[c] += 1

    total = len(seen)
    print('labelled addresses: %d' % total)
    for k in ('TRACED', 'CITED', 'UNVERIFIED'):
        print('  %-11s %5d  %4.0f%%' % (k, counts[k], 100.0 * counts[k] / total))
    print()
    print('UNVERIFIED means the name is the only artefact -- no decoded trace and')
    print('no mention in corrections.md. Treat those as hypotheses.')

    if not args.apply:
        print('\n(report only; pass --apply to stamp the class into each comment)')
        return

    # Stamp the class as the first token of the comment. Idempotent: an existing
    # tag is replaced, so re-running after new analysis upgrades the class.
    def repl(m):
        a = int(m.group(1), 16)
        tag = '[%s] ' % seen.get(a, 'UNVERIFIED')
        return m.group(0) + tag

    out, n = CALL.subn(repl, src)
    for t in TAGS:
        out = out.replace(t + ' ' + t + ' ', t + ' ')
        out = re.sub(re.escape(t) + r' (' + '|'.join(re.escape(x) for x in TAGS) + r') ',
                     t + ' ', out)
    open(JAVA, 'w', encoding='utf-8').write(out)
    print('\nstamped %d label comments' % n)


if __name__ == '__main__':
    main()
