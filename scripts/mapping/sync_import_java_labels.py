#!/usr/bin/env python3
"""
Sync the descriptor labels in disassembly/ghidra/ImportAE5L600L.java against
disassembly/maps/descriptor_labels.txt.

Replaces update_import_java.py for the descriptor-label job. That script was
INSERT-ONLY (it appended a block before the final printf), so re-running it
duplicated every label; it also had every path wrong. See corrections.md item 60.

Design, and why it is this way
------------------------------
ADDRESS-KEYED AND ADDITIVE, never a wholesale rewrite:

  * An address already present in the java is LEFT EXACTLY AS IT IS. 123 of the
    existing entries are hand-annotated `labelComment(...)` calls carrying
    "RR: <table name>" prose and multi-line comments that no generator can
    reproduce. A block replace would destroy them.
  * Only addresses MISSING from the java are added, into one clearly delimited
    block that this script owns and rewrites in place on every run.
  * Addresses present in the java but absent from descriptor_labels.txt are
    reported and LEFT ALONE -- never deleted. As of 2026-08-16 there are 16:
    8 RAM workspaces whose names merely begin with "desc_", and 8 ROM addresses
    (0xAF238..0xAF318) whose +4 field is 0x08000000, i.e. not descriptors at
    all. Deleting a label is a judgement call for a human, not a sync script.

Because the managed block is delimited and regenerated, the script is
IDEMPOTENT: running it twice produces the same file.

Usage
-----
    python scripts/mapping/sync_import_java_labels.py            # report only
    python scripts/mapping/sync_import_java_labels.py --apply    # write
"""
import os
import re
import sys

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
JAVA = os.path.join(REPO, "disassembly", "ghidra", "ImportAE5L600L.java")
LABELS = os.path.join(REPO, "disassembly", "maps", "descriptor_labels.txt")

BEGIN = "        // >>> BEGIN generated descriptor labels (sync_import_java_labels.py) >>>"
END = "        // <<< END generated descriptor labels <<<"

# insert before this marker if the managed block does not exist yet
ANCHOR = "        // FUEL INJECTION TIMING ANALYSIS"

LABEL_RE = re.compile(r'count \+= label(?:Comment)?\(0x([0-9A-Fa-f]+)L?, "(desc_[^"]+)"')
FILE_RE = re.compile(r'\s*count \+= label\(0x([0-9A-Fa-f]+)L, "([^"]+)"\);')


def read_labels():
    out = {}
    with open(LABELS, encoding="utf-8", errors="replace") as f:
        for ln in f:
            m = FILE_RE.match(ln)
            if m:
                out[int(m.group(1), 16)] = m.group(2)
    return out


def strip_block(java):
    """Remove a previously generated block INCLUDING the blank line after it.

    Without swallowing that trailing newline the file gains one blank line per
    run and the script stops being idempotent -- verified by running --apply
    three times and comparing md5.
    """
    if BEGIN in java and END in java:
        i = java.index(BEGIN)
        j = java.index(END) + len(END)
        while j < len(java) and java[j] in "\r\n":
            j += 1
        return java[:i] + java[j:]
    return java


def main():
    java = open(JAVA, encoding="utf-8", errors="surrogateescape").read()
    want = read_labels()

    base = strip_block(java)                      # ignore our own prior output
    have = {int(a, 16) for a, _ in LABEL_RE.findall(base)}

    missing = sorted(set(want) - have)
    orphan = sorted(have - set(want))

    print(f"descriptor_labels.txt : {len(want)}")
    print(f"java (hand + inherited): {len(have)}")
    print(f"to ADD                 : {len(missing)}")
    print(f"in java, not a descriptor (left alone): {len(orphan)}")
    for a in orphan:
        print(f"    {a:08X}")

    if not missing:
        print("\nnothing to add.")
        return
    if "--apply" not in sys.argv:
        print("\n(report only -- pass --apply to write)")
        return

    lines = [BEGIN,
             "        // Addresses missing from the hand-maintained labels above.",
             "        // Regenerated in place; do not hand-edit inside these markers.",
             f"        // {len(missing)} labels, from disassembly/maps/descriptor_labels.txt"]
    lines += [f'        count += label(0x{a:07X}L, "{want[a]}");' for a in missing]
    lines.append(END)
    block = "\n".join(lines) + "\n"

    if ANCHOR not in base:
        sys.exit("anchor comment not found -- refusing to guess an insertion point")
    idx = base.index(ANCHOR)
    # step back to the start of the comment banner above the anchor
    start = base.rfind("        // ===", 0, idx)
    if start == -1:
        start = idx
    out = base[:start] + block + "\n" + base[start:]
    open(JAVA, "w", encoding="utf-8", errors="surrogateescape").write(out)
    print(f"\nwrote {len(missing)} labels into the managed block in {JAVA}")


if __name__ == "__main__":
    main()
