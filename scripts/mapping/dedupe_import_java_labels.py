#!/usr/bin/env python3
"""
Resolve addresses in ImportAE5L600L.java that carry more than one desc_* label.

Ghidra applies every label() call, so an address with two names ends up with two
symbols and an arbitrary primary. As of 2026-08-16 there were 61 such addresses
(corrections.md item 68). They are not factual disagreements -- nobody is wrong
about what the table is -- they are two naming passes colliding.

Policy, applied per group
-------------------------
A. GENERATED + HAND  (52 addresses)
   e.g. desc_1D_ECT_u8_16_AC484  +  desc_avcs_run_time_corr
   Keep the HAND name: it carries meaning and usually an "RR: <table>" comment.
   Delete the generated statement. Its geometry is NOT copied into the
   survivor's comment -- see the note in main(); descriptor_map.txt already
   holds that, regenerated from ROM, and a hand-frozen second copy is the drift
   failure mode this repo keeps getting bitten by.

B. TWO HAND NAMES, ECT warm-up quartet (0xADBC4..0xADC00)
   desc_timing_ect_corr_N  vs  desc_ect_warmup_1D_modeNN
   Keep the MODE-BIT name -- it encodes the throttle x engine-running selector
   state, which is what you would search for. The index name does not say which
   condition selects the table.

C. TWO HAND NAMES, final-timing set (0xAE54C..0xAE5BC)
   desc_ign_timing_modeN  vs  desc_final_timing_X
   Equivalent information; keep desc_final_timing_* because it says what the
   table IS rather than which slot it occupies.

This is the first DESTRUCTIVE edit in the descriptor sweep -- it deletes label
statements. Everything else has been additive or in-place correction. Run with
--apply only deliberately; git is the undo.

Naturally idempotent: after a successful run no address has two labels, so a
second run finds nothing to do.

Usage
-----
    python scripts/mapping/dedupe_import_java_labels.py            # report
    python scripts/mapping/dedupe_import_java_labels.py --apply
"""
import os
import re
import sys
from collections import defaultdict

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
sys.path.insert(0, os.path.join(REPO, "scripts"))
from desc_types import read_table  # noqa: E402

JAVA = os.path.join(REPO, "disassembly", "ghidra", "ImportAE5L600L.java")
ROM = os.path.join(REPO, "rom", "AE5L600L 20g rev 20.19c.bin")

GENERATED = re.compile(r"^desc_\dD_.*_(?:f32|u8|u16|i8|i16)_")
START = re.compile(r"^\s*count \+= (label|labelComment)\(0x([0-9A-Fa-f]+)L?, \"(desc_[^\"]+)\"")

# explicit per-group choices for the two-hand-name cases
PREFER_SUFFIX = ("_mode00", "_mode01", "_mode10", "_mode11")   # group B winners
PREFER_PREFIX = ("desc_final_timing_",)                        # group C winners


def statements(lines):
    """Yield (start_idx, end_idx_exclusive, form, addr, name) for each label call."""
    for i, ln in enumerate(lines):
        m = START.match(ln)
        if not m:
            continue
        j = i
        while j < len(lines) and not lines[j].rstrip().endswith(");"):
            j += 1
        yield i, j + 1, m.group(1), int(m.group(2), 16), m.group(3)


def geometry(rom, addr):
    try:
        t = read_table(rom, addr)
    except Exception:
        return None
    if t["dim"] == "2D":
        return f"{t['type_name']} 2D {len(t['axes']['y'])}x{len(t['axes']['x'])}"
    return f"{t['type_name']} 1D {len(t['axes']['x'])}pt"


def pick_loser(names):
    """Return the names to DELETE for a duplicated address."""
    gen = [n for n in names if GENERATED.match(n)]
    hand = [n for n in names if not GENERATED.match(n)]
    if gen and len(hand) == 1:
        return gen                                    # group A
    if len(hand) == 2 and not gen:
        keep = [n for n in hand if n.startswith(PREFER_PREFIX)]
        if len(keep) == 1:
            return [n for n in hand if n != keep[0]]  # group C
    if len(hand) == 2 and gen:
        keep = [n for n in hand if n.endswith(PREFER_SUFFIX)]
        if len(keep) == 1:
            return gen + [n for n in hand if n != keep[0]]   # group B
    return None                                       # unhandled -> report


def main():
    rom = open(ROM, "rb").read()
    lines = open(JAVA, encoding="utf-8", errors="surrogateescape").read().split("\n")
    stmts = list(statements(lines))
    by_addr = defaultdict(list)
    for s in stmts:
        by_addr[s[3]].append(s)
    dups = {a: v for a, v in by_addr.items() if len(v) > 1}

    print(f"duplicated addresses: {len(dups)}")
    drop_idx, kept, unhandled = set(), {}, []
    for a, v in sorted(dups.items()):
        names = [s[4] for s in v]
        losers = pick_loser(names)
        if losers is None:
            unhandled.append((a, names))
            continue
        for s in v:
            if s[4] in losers:
                drop_idx.update(range(s[0], s[1]))
            else:
                kept[a] = s

    print(f"  resolvable      : {len(dups) - len(unhandled)}")
    print(f"  UNHANDLED       : {len(unhandled)}")
    for a, names in unhandled:
        print(f"     {a:06X}: {names}")
    print(f"  statements to delete: {len({i for i in drop_idx})} line(s)")

    if "--apply" not in sys.argv:
        print("\n(report only -- pass --apply to write)")
        return

    # DELIBERATELY NOT annotating survivors with the descriptor geometry.
    #
    # The first draft folded "1D uint8 16pt" into each survivor's comment so the
    # generated name's type info would not be "lost". On reflection that is the
    # wrong call for this repo: geometry is already held authoritatively in
    # disassembly/maps/descriptor_map.txt and descriptor_labels.txt, both
    # REGENERATED FROM ROM. Copying it into a Java comment creates a
    # hand-frozen fifth copy that silently drifts -- which is precisely the
    # failure mode that produced corrections items 39, 43 and 60 (one typecode
    # map copy-pasted into five scripts, all five wrong). Nothing is lost by
    # omitting it; look the geometry up where it is derived.
    text = "\n".join(ln for i, ln in enumerate(lines) if i not in drop_idx)
    open(JAVA, "w", encoding="utf-8", errors="surrogateescape").write(text)
    print(f"\napplied. {len(dups) - len(unhandled)} address(es) de-duplicated; "
          f"geometry intentionally not copied (see note in source).")


if __name__ == "__main__":
    main()
