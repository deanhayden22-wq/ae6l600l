#!/usr/bin/env python3
"""
Verify committed disassembly text against actual ROM bytes -- OPERANDS INCLUDED.

Replaces scripts/verify_disassembly.py, which was blind to the bug classes it
existed to catch:
  * it skipped any line whose mnemonic started with '.' (line 691), so every FPU
    instruction a producing script had failed to decode and emitted as
    ".word 0xNNNN" was silently discarded;
  * its own decoder folded LDS/STS FPUL (m=5) and FPSCR (m=6) into the PR case
    (line 109), so it could not detect that error even in principle.

It also only ever compared mnemonics. Every error actually found in this repo on
2026-07-26 was in the OPERANDS -- wrong displacement field width, wrong register
field, missing '& ~3' on PC-relative targets, inverted fmov.s direction. A
mnemonic-only comparison passes all of them.

Usage:
    python scripts/verify_disasm_v2.py                  # whole corpus
    python scripts/verify_disasm_v2.py disassembly/analysis/knock_flkc_analysis.txt
    python scripts/verify_disasm_v2.py --rom "rom/AE5L600L 20g rev 20.19b.bin"
    python scripts/verify_disasm_v2.py --quiet          # summary only
"""
import argparse
import glob
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sh2e_disasm import decode  # noqa: E402

# "  043A1E: 450B  jsr @r0  ; CALL @ 0xFFFFFFE4"
LINE = re.compile(r'^\s*(?:0x)?([0-9A-Fa-f]{5,6})\s*:\s*([0-9A-Fa-f]{4})\s+(\S.*?)\s*$')

REG = re.compile(r'\br(\d+)\b', re.I)
FREG = re.compile(r'\bfr(\d+)\b', re.I)
# Capture the 0x INSIDE the group -- otherwise "0x15" and "21" (the same value)
# normalize to "15" and "21" and register as a false mismatch. The bare-hex
# alternative catches branch targets written without a prefix ("bsr 03735A").
NUM = re.compile(r'(?<![\w])(0x[0-9A-Fa-f]+|[0-9A-Fa-f]{5,6}|\d+)(?![\w])', re.I)
# Known, deliberate non-errors: (basename, line). Keep this SHORT and justify
# every entry -- it is the one place a real bug could hide by being whitelisted.
ACCEPTED = {
    # A worked reasoning passage that computes the PC-relative target wrongly,
    # notices, and corrects itself to 0x05ACF0 two lines down. Repairing the line
    # would delete the reasoning trail, which is the valuable part.
    ('clol_gap_closure.txt', 414),
}

# operands written as a symbol rather than an address ("bf skip", "@pool")
SYMBOLIC = re.compile(r'@pool|\b(?:bra|bsr|bt|bf|bt/s|bf/s|jmp|jsr)\s+[a-z_][a-z0-9_]*\s*$', re.I)
# trailing "[symbol_name]" annotations the analysis files append to branches
ANNOT = re.compile(r'\[[^\]]*\]')
# our decoder tags impossible encodings; the files just write ".word 0xNNNN"
INVAL = re.compile(r'\s*\((?:INVALID-SH2E|invalid-sh2e)\)\s*')


PCREL = re.compile(r'@\(\s*(?:0x)?([0-9A-Fa-f]+)\s*,\s*pc\s*\)', re.I)


def resolve_pcrel(text, addr, word):
    """Rewrite the '@(disp,PC)' notation to the resolved target address.

    Both renderings are legitimate; the analysis files mostly use the raw
    displacement while this project's decoder prints the target. Without this,
    every PC-relative load would register as a false mismatch.

    MOV.L @(disp,PC),Rn  (0xDnnn) -> ((PC & ~3) + 4 + disp)   [disp already *4]
    MOVA  @(disp,PC),R0  (0xC7nn) -> ((PC & ~3) + 4 + disp)
    MOV.W @(disp,PC),Rn  (0x9nnn) -> (PC + 4 + disp)          [no ~3 mask]
    """
    m = PCREL.search(text)
    if not m:
        return text
    disp = int(m.group(1), 16)
    op = word >> 12
    if op == 0xD or (word >> 8) == 0xC7:
        target = ((addr + 4) & ~3) + disp
    elif op == 0x9:
        target = addr + 4 + disp
    else:
        return text
    # Some files write the ALREADY-RESOLVED address but keep the ",PC" suffix.
    # Detect that: a true displacement is small, and resolving an already-
    # resolved address overshoots the 1MB ROM.
    if target >= 0x100000 and 0x1000 <= disp < 0x100000:
        target = disp
    return PCREL.sub(f'@(0x{target:06X})', text)


def normalize(text):
    """Canonical form so formatting differences do not register as errors."""
    t = text.split(';')[0]                    # drop trailing comment
    t = INVAL.sub('', t)
    t = ANNOT.sub('', t)
    t = t.lower().strip()
    t = t.replace('\t', ' ')
    t = re.sub(r'\s+', ' ', t)
    t = t.replace(', ', ',').replace(' ,', ',')
    t = re.sub(r'@\s+', '@', t)
    # "fpu_0xFFFF" / "unk_0xNNNN" are just "this is not a decoded instruction"
    t = re.sub(r'^(fpu|unk|unknown)_0x([0-9a-f]{4})$', r'.word 0x\2', t)

    # numeric literals -> decimal, so 0x15 == 21 compares equal.
    # Bare tokens of >=5 digits are branch/address targets written without the
    # 0x prefix (e.g. "bsr 037492"), so read those as hex. Real displacements
    # and immediates on this ISA are at most 3 digits, so there is no overlap.
    def num(m):
        s = m.group(1)
        try:
            if s.lower().startswith('0x'):
                return str(int(s, 16))
            return str(int(s, 16) if len(s) >= 5 else int(s))
        except ValueError:
            return m.group(0)
    t = NUM.sub(num, t)
    return t


def classify(file_text, truth_text):
    f, r = file_text, truth_text
    if SYMBOLIC.search(f):
        return 'SYMBOLIC (label used instead of address - not an error)'
    if f.startswith('.'):
        return 'DROPPED (real instruction emitted as .word)'
    fm = f.split()[0] if f.split() else ''
    rm = r.split()[0] if r.split() else ''
    if r.startswith('.word'):
        return 'DATA-AS-CODE (impossible on SH-2E)'
    if fm != rm:
        return 'WRONG MNEMONIC'
    if 'fmov' in rm and ('@' in f) != ('@' in r):
        return 'WRONG OPERANDS (fmov direction)'
    if re.search(r'@\(\d+,', f) and re.search(r'@\(\d+,', r):
        return 'WRONG OPERANDS (displacement)'
    if REG.findall(f) != REG.findall(r):
        return 'WRONG OPERANDS (register field)'
    return 'WRONG OPERANDS (other)'


def main():
    # analysis files contain non-cp1252 characters; the Windows console default
    # would raise UnicodeEncodeError partway through the report
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument('paths', nargs='*')
    ap.add_argument('--rom', default='rom/ae5l600l.bin')
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--strict', action='store_true',
                    help='count symbolic labels and accepted exceptions as failures')
    ap.add_argument('--max-show', type=int, default=40)
    args = ap.parse_args()

    rom = open(args.rom, 'rb').read()
    paths = args.paths or (glob.glob('disassembly/**/*.txt', recursive=True))

    checked = agree = skipped_rev = 0
    findings = []
    comment_only = []
    for path in sorted(set(paths)):
        try:
            lines = open(path, encoding='utf-8', errors='replace').read().split('\n')
        except OSError:
            continue
        for i, ln in enumerate(lines):
            m = LINE.match(ln)
            if not m:
                continue
            addr, word, text = int(m.group(1), 16), int(m.group(2), 16), m.group(3)
            if addr + 1 >= len(rom):
                continue
            if ((rom[addr] << 8) | rom[addr + 1]) != word:
                skipped_rev += 1          # line quotes a different ROM rev
                continue
            checked += 1
            truth, _ = decode(word, addr)
            # A PC-relative operand may be written as "@(disp,PC)" or as the
            # already-resolved "@(target,PC)". Both are legitimate renderings,
            # so accept either rather than reporting a spurious mismatch.
            candidates = (text,
                          resolve_pcrel(text, addr, word),
                          PCREL.sub(lambda mm: f'@(0x{int(mm.group(1), 16):06X})', text))
            if any(normalize(c) == normalize(truth) for c in candidates):
                agree += 1
                continue
            # a line that is only a comment carries no disassembly to check
            if not normalize(text):
                comment_only.append((path, i + 1, addr, word, truth))
                continue
            findings.append((path, i + 1, addr, word, text.strip(), truth,
                             classify(normalize(resolve_pcrel(text, addr, word)),
                                      normalize(truth))))

    print(f"ROM      : {args.rom}")
    print(f"checked  : {checked} instruction lines")
    print(f"agree    : {agree}  ({100.0*agree/max(1,checked):.2f}%)")
    print(f"mismatch : {len(findings)}")
    print(f"skipped  : {skipped_rev} (bytes differ from this ROM -- other rev)")
    print(f"comment-only lines where an instruction was replaced by prose: {len(comment_only)}")
    if comment_only and not args.quiet:
        for path, ln, addr, word, truth in comment_only[:8]:
            print(f"    {os.path.basename(path)}:{ln}  0x{addr:06X} {word:04X} -> {truth}")
    if findings:
        print("\nby class:")
        for k, v in Counter(f[6] for f in findings).most_common():
            print(f"  {v:6d}  {k}")
        print("\nby file:")
        for k, v in Counter(f[0] for f in findings).most_common(15):
            print(f"  {v:6d}  {k}")
        if not args.quiet:
            print("\ndetail:")
            for path, ln, addr, word, text, truth, cls in findings[:args.max_show]:
                print(f"  {os.path.basename(path)}:{ln}  0x{addr:06X} {word:04X}")
                print(f"      file : {text[:100]}")
                print(f"      truth: {truth[:100]}   [{cls}]")
            if len(findings) > args.max_show:
                print(f"  ... +{len(findings)-args.max_show} more")

    # Exit code means "something REGRESSED", not "something was found".
    #
    # The corpus has a known, deliberate baseline of non-errors:
    #   * SYMBOLIC  - a file writes `bf skip` or `@pool` instead of an address.
    #                 Legitimate style, not a decode error.
    #   * ACCEPTED  - a worked reasoning passage that states a wrong value, then
    #                 catches itself and lands on the right one two lines later.
    #                 The trail is worth more than the tidy line.
    # Returning nonzero for those made the tool unusable in a `&&` chain and
    # trained the reader to ignore its exit code. Use --strict for the old
    # count-everything behaviour.
    regressions = [f for f in findings
                   if not f[6].startswith('SYMBOLIC')
                   and (os.path.basename(f[0]), f[1]) not in ACCEPTED]
    if args.strict:
        regressions = findings
    if regressions:
        print(f"\nREGRESSION: {len(regressions)} finding(s) outside the accepted baseline")
    else:
        print(f"\nbaseline clean ({len(findings)} accepted non-error(s): "
              f"{sum(1 for f in findings if f[6].startswith('SYMBOLIC'))} symbolic, "
              f"{len(findings) - sum(1 for f in findings if f[6].startswith('SYMBOLIC'))} accepted)")
    return 1 if regressions else 0


if __name__ == '__main__':
    sys.exit(main())
