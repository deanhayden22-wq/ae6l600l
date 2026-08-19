#!/usr/bin/env python3
"""Report addresses that docs/corrections.md discusses but Ghidra never sees.

Findings in this project land in prose. Prose is not replayed into Ghidra --
disassembly/ghidra/ImportAE5L600L.java is. Anything named only in corrections.md
is lost on the next re-import, and the two layers drift silently, which is the
failure mode most of corrections.md is about.

This is a REPORT, not a gate on correctness: plenty of addresses are cited in
passing and do not deserve a label. It exists so the decision is deliberate.

  python scripts/check_label_sync.py            # report
  python scripts/check_label_sync.py --item 74  # one correction item
"""
import os
import re
import sys

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
CORR = os.path.join(REPO, "docs", "corrections.md")
JAVA = os.path.join(REPO, "disassembly", "ghidra", "ImportAE5L600L.java")

ROM_TOP = 0x100000
RAM_LO, RAM_HI = 0xFFFF0000, 0xFFFFBFFF


def labelled():
    src = open(JAVA, encoding="utf-8", errors="replace").read()
    return {int(m.group(1), 16)
            for m in re.finditer(r'label(?:Comment)?\(\s*0x([0-9A-Fa-f]+)L?\s*,', src)}


def items():
    """corrections.md split into (number, title, body)."""
    text = open(CORR, encoding="utf-8", errors="replace").read()
    parts = re.split(r"^## (\d+)\.\s*(.*)$", text, flags=re.M)
    out = []
    for i in range(1, len(parts), 3):
        out.append((int(parts[i]), parts[i + 1].strip(), parts[i + 2]))
    return out


def addrs(body):
    found = set()
    for m in re.finditer(r"0x([0-9A-Fa-f]{4,8})", body):
        v = int(m.group(1), 16)
        if v < ROM_TOP or RAM_LO <= v <= RAM_HI:
            found.add(v)
    return found


def main():
    want = None
    if "--item" in sys.argv:
        want = int(sys.argv[sys.argv.index("--item") + 1])
    have = labelled()
    total_missing = 0
    for num, title, body in items():
        if want is not None and num != want:
            continue
        missing = sorted(a for a in addrs(body) if a not in have)
        if not missing:
            continue
        total_missing += len(missing)
        print(f"\nitem {num}. {title[:70]}")
        for a in missing:
            print(f"    0x{a:08X}  not labelled in ImportAE5L600L.java")
    print(f"\n{total_missing} address(es) discussed in corrections.md carry no Ghidra label.")
    print("Not all of them should -- decide per address, then add the ones that")
    print("matter to ImportAE5L600L.java in the SAME commit as the prose.")


if __name__ == "__main__":
    main()
