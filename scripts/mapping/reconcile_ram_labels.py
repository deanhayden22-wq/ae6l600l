#!/usr/bin/env python3
"""
Harvest every RAM-address -> label claim across the derived artifacts, group
them, and rank the CONFLICTS by how much they matter.

Why
---
Brief #2's D5 found "446 addresses carrying two or more distinct labels" with a
crude regex, and correctly said most of it is prose noise. This does the harvest
properly and ranks what is left, so a writer-based reconciliation can be spent
on the addresses that actually carry weight.

Ranking inputs
--------------
  * how many DISTINCT labels the address carries
  * whether it appears in a PRIORITY subsystem file (fueling, boost, AVCS,
    knock, CL/OL) rather than the diagnostic/DTC tail
  * its flag in docs/verification-status.json -- an address already
    VERIFIED-BOTH needs no adjudication, one that is DISASM-ONLY does

What it is NOT
--------------
This tool reports CLAIMS IN CONFLICT. It does not adjudicate them. Resolution is
writer-based (scripts/mapping/find_writers.py) plus the definition-axis method,
per CLAUDE.md rule 1 and the lesson of corrections items 40 and 45. Do not
promote a label just because it appears more often -- the majority label has
been the wrong one before (0xFFFF4130, item 45).

Usage
-----
    python scripts/mapping/reconcile_ram_labels.py                # ranked report
    python scripts/mapping/reconcile_ram_labels.py --all          # include the tail
    python scripts/mapping/reconcile_ram_labels.py --addr FFFF6254
"""
import glob
import json
import os
import re
import sys
from collections import defaultdict

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")

PRIORITY = ("fuel", "boost", "avcs", "knock", "flkc", "fbkc", "cl_ol", "clol",
            "tau", "maf", "injec", "timing", "ignition", "accel", "tipin")

# A label claim looks like:  FFFF6254  maf_current      /  =0xFFFF65C0 (throttle_position)
# Require an identifier-ish token so prose ("speed compare in the same list") is
# not harvested as a name.
IDENT = r"[A-Za-z][A-Za-z0-9_]{2,40}"
PATTERNS = [
    re.compile(r"0x(FFFF[0-9A-Fa-f]{4})[ \t]*\((" + IDENT + r")\)"),
    # NOTE: [ \t] not \s -- \s matches NEWLINES, which paired an address with
    # the label on the FOLLOWING line and manufactured false conflicts
    # (e.g. "fuel_enrichment_A @ FFFF76D4" / next line "fuel_enrichment_B @ ...").
    re.compile(r"\b(FFFF[0-9A-Fa-f]{4})[ \t]{2,}(" + IDENT + r")\b"),
    re.compile(r"\b(FFFF[0-9A-Fa-f]{4})[ \t]+(" + IDENT + r")[ \t]*\((?:u8|u16|float|byte|word)\)"),
]

# tokens that are prose, not names
# single-word names that ARE real labels in this codebase
WORD_OK = {"rpm", "iat", "ect", "maf", "map", "tps", "baro", "vss", "afr",
           "knock", "timing", "load", "throttle", "gear", "torque"}

STOP = {"RAM", "ROM", "the", "and", "for", "was", "not", "is", "in", "at", "to",
        "loaded", "read", "reads", "write", "writes", "byte", "word", "float",
        "value", "from", "into", "with", "see", "note", "this", "that", "same",
        "u8", "u16", "int8", "int16", "float32", "speed", "compare"}


def norm(label):
    return label.strip().strip("_").lower()


def harvest():
    claims = defaultdict(lambda: defaultdict(set))   # addr -> label -> {files}
    files = (glob.glob(os.path.join(REPO, "disassembly", "analysis", "*.txt")) +
             glob.glob(os.path.join(REPO, "disassembly", "maps", "*.txt")))
    # Artifact FILENAME stems leak out of prose ("... see fuel_pump_analysis")
    # and were being harvested as labels. Reject them.
    filestems = {os.path.splitext(os.path.basename(f))[0].lower() for f in files}
    filestems |= {st.replace("_analysis", "").replace("_raw", "").replace("_trace", "")
                  for st in list(filestems)}

    def looks_like_a_label(lab):
        """Real labels in this project are snake_case identifiers.

        Requiring an underscore removes essentially all prose capture ("when",
        "mov", "loaded", "does") at the cost of a handful of single-word names.
        Those are recovered by the WORD_OK allow-list below.
        """
        if "_" in lab and len(lab) >= 5:
            return True
        return lab.lower() in WORD_OK

    for f in files:
        base = os.path.basename(f)
        try:
            text = open(f, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for pat in PATTERNS:
            for m in pat.finditer(text):
                addr = int(m.group(1), 16) | 0xFFFF0000
                lab = m.group(2)
                if lab in STOP or norm(lab) in STOP:
                    continue
                if not looks_like_a_label(lab):
                    continue
                nl = norm(lab)
                if nl in filestems or any(st.endswith(nl) for st in filestems):
                    continue
                # a label ending in an artifact-kind suffix is a filename, not a name
                if nl.endswith(("_analysis", "_raw", "_trace", "_report",
                                "_review", "_scout", "_map")):
                    continue
                claims[addr][norm(lab)].add(base)
    return claims


def load_flags():
    p = os.path.join(REPO, "docs", "verification-status.json")
    try:
        d = json.load(open(p, encoding="utf-8"))
    except OSError:
        return {}
    ents = d.get("entities", d if isinstance(d, list) else [])
    out = {}
    for e in ents:
        a = str(e.get("address", "")).lower().replace("0x", "")
        if a.startswith("ffff"):
            out[int(a, 16)] = (e.get("name"), e.get("flag"))
    return out


def main():
    claims = harvest()
    flags = load_flags()
    show_all = "--all" in sys.argv
    if "--addr" in sys.argv:
        a = int(sys.argv[sys.argv.index("--addr") + 1], 16) | 0xFFFF0000
        print(f"{a:08X}  registry: {flags.get(a)}")
        for lab, fs in sorted(claims.get(a, {}).items(), key=lambda kv: -len(kv[1])):
            print(f"   {lab:34s} {len(fs)} file(s): {', '.join(sorted(fs))}")
        return

    conflicts = {a: c for a, c in claims.items() if len(c) > 1}
    ranked = []
    for a, c in conflicts.items():
        allfiles = set().union(*c.values())
        prio = sum(1 for f in allfiles if any(k in f.lower() for k in PRIORITY))
        name, flag = flags.get(a, (None, None))
        # an address the registry already settles from BOTH sides needs no work
        weight = (prio > 0) * 10 + len(c) + (3 if flag in (None, "DISASM-ONLY", "UNMAPPED") else 0)
        ranked.append((weight, prio, a, c, name, flag))
    ranked.sort(key=lambda r: (-r[0], -r[1], r[2]))

    print(f"addresses with a label claim : {len(claims)}")
    print(f"addresses with 2+ DISTINCT labels : {len(conflicts)}")
    prio_conf = [r for r in ranked if r[1] > 0]
    print(f"  of those, touching a priority subsystem : {len(prio_conf)}")
    print("\nRanked conflicts (priority subsystems first). Resolution is "
          "writer-based -- this tool only reports.\n")
    for weight, prio, a, c, name, flag in (ranked if show_all else prio_conf):
        print(f"{a:08X}  registry={name or '-'} [{flag or 'unflagged'}]  ({len(c)} labels)")
        for lab, fs in sorted(c.items(), key=lambda kv: -len(kv[1])):
            print(f"     {lab:32s} <- {', '.join(sorted(fs))}")
    if not show_all:
        print(f"\n({len(ranked) - len(prio_conf)} further conflicts in the "
              f"diagnostic/DTC tail; re-run with --all to see them.)")


if __name__ == "__main__":
    main()
