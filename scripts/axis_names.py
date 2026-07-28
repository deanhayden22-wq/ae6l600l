#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Generate disassembly/maps/axis_names.txt -- a REPO-OWNED supplement naming the
descriptor axes that the ECUFlash definition XMLs leave unnamed.

WHY THIS EXISTS
---------------
`definitions/*.xml` are owned by ECUFlash, which rewrites them on save.  Repo-side
edits are lost and cause silent divergence (docs/corrections.md items 24/25/26 were
all reverted for exactly that reason).  So axis naming that this project derives
lives HERE instead, in a file the repo owns.

The axis-name method (docs/corrections.md item 9) is: trace a RAM variable to the
table-lookup axis it feeds, then read that axis's NAME out of the definitions.  Its
binding limit is that the XMLs name only ~160 distinct descriptor axis addresses out
of 997, so ~60 traced RAM variables reach ONLY unnamed axes and the method has
nothing to vote on.  This file closes part of that gap from ROM bytes.

EVIDENCE, NOT AUTHORITY
-----------------------
Every record carries a confidence.  Only `high` records are corroborated twice
(settled RAM feeder AND an envelope that agrees).  Definition XML names always win
where both exist; this file is consulted only for addresses the XMLs do not name.

Regenerate:  python scripts/axis_names.py
"""

import collections
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import defs                      # noqa: E402
import coverage_map as cm        # noqa: E402

STOCK = os.path.join(ROOT, "rom", "ae5l600l.bin")
REV = os.path.join(ROOT, "rom", "AE5L600L 20g rev 20.19c.bin")
OUT = os.path.join(ROOT, "disassembly", "maps", "axis_names.txt")


# --------------------------------------------------------------------------
# Settled RAM identities.  Every one of these is recorded in docs/corrections.md
# with address: bytes -> mnemonic proof.  Nothing else counts as "settled".
# --------------------------------------------------------------------------
#   addr -> (definition-vocabulary axis name, quantity token, corrections item)
SETTLED = {
    0xFFFF6624: ("Engine Speed",               "rpm",             "item 9 / 24"),
    0xFFFF7F4C: ("Engine Speed",               "rpm",             "item 22"),
    0xFFFF6350: ("Coolant Temperature",        "coolant",         "item 12 (side by side with 6364)"),
    0xFFFF6364: ("Intake Temperature",         "intake_air_temp", "item 12"),
    0xFFFF63F8: ("Engine Load",                "load",            "item 9"),
    0xFFFF65FC: ("Vehicle Speed",              "vehicle_speed",   "item 8 / 9"),
    0xFFFF620C: ("Manifold Pressure",          "pressure",        "item 9"),
    0xFFFF6898: ("Atmospheric Pressure",       "pressure",        "item 11"),
    0xFFFF4130: ("Battery Volts",              "voltage",         "item 10"),
    0xFFFF62DC: ("Throttle Plate Opening Angle", "throttle",      "item 13"),
    0xFFFF64D8: ("Accelerator Pedal Angle",    "throttle",        "item 13"),
    0xFFFF8558: ("Requested Torque",           "torque",          "item 22"),
    0xFFFF5CA0: ("Boost Error",                "pressure",        "item 22"),
    0xFFFF62E4: ("Throttle Angle Change",      "throttle",        "item 22"),
    0xFFFF7324: ("Last Calculated Base Pulse Width", "pulsewidth", "item 22"),
}

# Held-back / medium-confidence RAM identities (corrections item 23).  Present so a
# record can SAY what fed it, but they never promote a record to `high`.
UNSETTLED_NOTE = {
    0xFFFF4150: "medium (item 23): one 'Ignition Dwell / Engine Speed' hit",
    0xFFFF6634: "medium (item 23): 'Idle Speed Stability A / Engine Speed Delta'",
    0xFFFF89C8: "medium (item 23): 'Idle Speed Stability A / Idle Speed Error'",
    0xFFFF63C0: "medium (item 23): 'MAF Compensation (IAT) / Mass Airflow'",
    0xFFFF63C4: "UNRESOLVED (item 23): three-way split, nothing supports 'ect_compensation'",
    0xFFFF63CC: "UNRESOLVED (item 23): one hit, 'Smoothed MAF' X axis 0xD9280",
    0xFFFF5FFC: "UNRESOLVED (item 23): float x22, 12 unnamed axes, 'io_state_register' is wrong",
    0xFFFFA198: "UNRESOLVED (item 23): 36 hits, all RPM-shaped, zero named",
    0xFFFF69F0: "RETRACTED (item 23): the 'real IAT' claim no longer stands",
}

# Envelope signatures.  Bands were taken from the DEFINITION-NAMED axis population
# in this ROM (measured, not assumed):
#   rpm      55 axes  -50 .. 10000        load    29 axes   0.2 .. 3
#   iat      11 axes  -40 .. 120          coolant  4 axes  -30 .. 70
#   pressure 12 axes -1000 .. 1000        throttle 5 axes     0 .. 100
#   airflow   3 axes  0.9 .. 290          voltage  1 axis     8 .. 16
QUANT_UNITS = {
    "rpm": "RPM", "load": "g/rev", "coolant": "deg C", "intake_air_temp": "deg C",
    "temperature": "deg C", "vehicle_speed": "km/h", "pressure": "raw (x.01933677 = psi abs)",
    "airflow": "g/s", "throttle": "% / deg", "voltage": "V", "torque": "Nm",
    "pulsewidth": "us", "ratio": "-", "time": "counts",
}


def envelope_verdict(q, lo, hi, n, mono):
    """agree / neutral / contradict -- is `q` compatible with this envelope?"""
    if q == "rpm":
        if hi < 300 or lo < -60:
            return "contradict"
        return "agree" if (mono and lo >= 0 and 2000 <= hi <= 9000) else "neutral"
    if q == "load":
        if hi > 8 or lo < -0.1:
            return "contradict"
        return "agree" if (0 <= lo and 0.5 <= hi <= 5.5) else "neutral"
    if q in ("coolant", "intake_air_temp", "temperature"):
        if lo < -60 or hi > 200:
            return "contradict"
        return "agree" if (lo <= -20 and 20 <= hi <= 130) else "neutral"
    if q == "vehicle_speed":
        if lo < -1 or hi > 400:
            return "contradict"
        return "agree" if (mono and lo >= 0 and 40 <= hi <= 320) else "neutral"
    if q == "pressure":
        if hi > 2000 or lo < -1100:
            return "contradict"
        return "agree" if 150 <= hi <= 1600 else "neutral"
    if q == "voltage":
        if hi > 30 or lo < -1:
            return "contradict"
        return "agree" if (lo >= 5 and 8 <= hi <= 21) else "neutral"
    if q == "throttle":
        if hi > 130 or lo < -5:
            return "contradict"
        return "agree" if (lo >= 0 and 30 <= hi <= 105) else "neutral"
    if q == "torque":
        if hi > 600 or lo < -1:
            return "contradict"
        return "agree" if 100 <= hi <= 400 else "neutral"
    if q == "pulsewidth":
        if hi > 40000:
            return "contradict"
        return "agree" if 500 <= hi <= 20000 else "neutral"
    if q == "airflow":
        if hi > 400 or lo < -1:
            return "contradict"
        return "neutral"
    return "neutral"


# The canonical Subaru load breakpoint run.  Appears verbatim on 29 definition-named
# "Engine Load" axes, so its presence on an unnamed axis is a real signature.
LOAD_SIG = (0.2, 0.31070000529289246, 0.42140001058578491)


def envelope_only(bp, lo, hi, n, mono):
    """(name, quantity, why) or None -- what the envelope alone will support."""
    if n >= 2 and lo <= -25 and 20 <= hi <= 130 and mono:
        return ("Temperature", "temperature",
                "envelope %.4g..%.4g deg C; matches the coolant/intake band, "
                "but ECT and IAT are indistinguishable on envelope alone" % (lo, hi))
    if (n >= 3 and mono and lo >= 0 and 2000 <= hi <= 9000
            and all(abs(v / 25.0 - round(v / 25.0)) < 1e-3 for v in bp)):
        return ("Engine Speed", "rpm",
                "envelope %.0f..%.0f, monotonic, every breakpoint a multiple of 25; "
                "no other quantity in this ROM reaches 2000-9000 in that step pattern"
                % (lo, hi))
    if n >= 3 and mono and abs(bp[0] - LOAD_SIG[0]) < 1e-4 and abs(bp[1] - LOAD_SIG[1]) < 1e-5:
        return ("Engine Load", "load",
                "breakpoints open 0.2, 0.3107, 0.4214 -- the canonical Subaru load run, "
                "verbatim on 29 definition-named 'Engine Load' axes in this ROM")
    if n >= 3 and mono and lo >= 5 and 8 <= hi <= 21:
        return ("Battery Volts", "voltage",
                "envelope %.4g..%.4g V; sensor voltages in this ROM start at 0, "
                "a floor above 5 V is the battery band" % (lo, hi))
    return None


def main():
    stock = cm.load_rom(STOCK)
    rev = cm.load_rom(REV) if os.path.exists(REV) else None
    d = defs.load()

    descs = cm.scan_descriptors(stock)
    axis_use = collections.defaultdict(list)
    for x in descs:
        for i, a in enumerate(x["axes"]):
            axis_use[a].append((x, i))

    named = collections.defaultdict(set)
    for t in d.tables:
        for a in t.axes:
            if a.address is not None:
                named[a.address].add("%s / %s" % (t.name, a.name))

    fr4, fr5, _consumers = cm.trace_axis_feeds(stock)
    desc_feed = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
    for ram, ctr in fr4.items():
        for dsc, k in ctr.items():
            desc_feed[dsc][0][ram] += k
    for ram, ctr in fr5.items():
        for dsc, k in ctr.items():
            desc_feed[dsc][1][ram] += k

    def rdf(buf, a, n):
        return [struct.unpack_from(">f", buf, a + 4 * i)[0] for i in range(n)]

    recs = []
    for ax in sorted(axis_use):
        if ax in named:
            continue
        uses = axis_use[ax]
        n = max(u[0]["counts"][u[1]] for u in uses)
        bp = rdf(stock, ax, n)
        finite = all(v == v and abs(v) != float("inf") for v in bp)
        denorm = any(v != 0 and abs(v) < 1e-30 for v in bp)
        lo, hi = (min(bp), max(bp)) if finite else (float("nan"), float("nan"))
        mono = finite and all(bp[i] <= bp[i + 1] for i in range(len(bp) - 1))
        changed = rev is not None and rev[ax:ax + 4 * n] != stock[ax:ax + 4 * n]

        feeders = collections.Counter()
        for dsc, slot in uses:
            for r, k in desc_feed.get(dsc["addr"], {}).get(slot, {}).items():
                feeders[r] += k

        ev = []
        name = quant = None
        conf = "unresolved"

        if not finite or denorm:
            ev.append("breakpoints are not plausible float32 (denormal/NaN) -- this "
                      "'axis' is probably not a float breakpoint array; region "
                      "boundary suspect")
        else:
            settled_votes = collections.Counter()
            for r, k in feeders.items():
                if r in SETTLED:
                    settled_votes[SETTLED[r][1]] += k
            agree = [q for q in settled_votes
                     if envelope_verdict(q, lo, hi, n, mono) == "agree"]
            neutral = [q for q in settled_votes
                       if envelope_verdict(q, lo, hi, n, mono) == "neutral"]
            contra = [q for q in settled_votes
                      if envelope_verdict(q, lo, hi, n, mono) == "contradict"]

            if len(set(agree)) == 1 and not contra:
                quant = agree[0]
                name = next(v[0] for v in SETTLED.values() if v[1] == quant)
                # prefer the exact name of the highest-voting settled feeder
                best = max((r for r in feeders if r in SETTLED and SETTLED[r][1] == quant),
                           key=lambda r: feeders[r])
                name = SETTLED[best][0]
                conf = "high"
                ev.append("settled RAM feeder 0x%08X (%s, corrections %s) is passed as "
                          "this axis's lookup input at %d call site(s)"
                          % (best, SETTLED[best][0], SETTLED[best][2], feeders[best]))
                ev.append("envelope %.4g..%.4g AGREES with %s" % (lo, hi, quant))
            elif len(set(agree)) > 1:
                ev.append("two settled feeders of different quantities (%s) both fit the "
                          "envelope -- not resolvable here" % ", ".join(sorted(set(agree))))
            elif contra:
                best = max((r for r in feeders if r in SETTLED), key=lambda r: feeders[r])
                ev.append("settled feeder 0x%08X (%s) CONTRADICTS envelope %.4g..%.4g -- "
                          "most likely a stale FR-register tag carried across a basic "
                          "block by the linear trace (corrections item 23); NOT named"
                          % (best, SETTLED[best][0], lo, hi))
            elif neutral:
                best = max((r for r in feeders if r in SETTLED and SETTLED[r][1] in neutral),
                           key=lambda r: feeders[r])
                quant = SETTLED[best][1]
                name = SETTLED[best][0]
                conf = "medium"
                ev.append("settled RAM feeder 0x%08X (%s, corrections %s) at %d site(s); "
                          "envelope %.4g..%.4g is compatible but not distinctive"
                          % (best, name, SETTLED[best][2], feeders[best], lo, hi))
            else:
                eo = envelope_only(bp, lo, hi, n, mono)
                if eo:
                    name, quant, why = eo
                    conf = "medium"
                    ev.append(why)
                    ev.append("no settled RAM feeder -- envelope evidence only")

        for r, k in sorted(feeders.items(), key=lambda kv: -kv[1]):
            if r in UNSETTLED_NOTE:
                ev.append("fed by 0x%08X x%d -- %s" % (r, k, UNSETTLED_NOTE[r]))
            elif r not in SETTLED:
                ev.append("fed by 0x%08X x%d (RAM identity not settled)" % (r, k))
        if not feeders:
            ev.append("no RAM feeder reached this axis in the D3 trace")
        if changed:
            ev.append("BREAKPOINTS DIFFER between stock and 20.19c -- this axis is tuned")
        if len({u[0]["counts"][u[1]] for u in uses}) > 1:
            ev.append("element count differs between descriptors sharing this axis "
                      "(%s) -- shared-prefix axis, the larger count is used"
                      % ",".join(str(u[0]["counts"][u[1]]) for u in uses))

        recs.append(dict(
            addr=ax, n=n, lo=lo, hi=hi, name=name or "-", quant=quant or "-",
            conf=conf,
            desc=",".join("0x%05X:%d" % (u[0]["addr"], u[1]) for u in uses[:6]),
            feed=",".join("0x%08X" % r for r, _ in feeders.most_common(4)) or "-",
            ev="; ".join(ev),
            bp=bp))

    write(recs, len(axis_use), len(named), len(descs))
    counts = collections.Counter(r["conf"] for r in recs)
    print("axes total %d | named by XML %d | unnamed %d" %
          (len(axis_use), sum(1 for a in axis_use if a in named), len(recs)))
    print("supplement: " + ", ".join("%s=%d" % kv for kv in sorted(counts.items())))
    print("wrote " + OUT)
    return 0


HEADER = """\
# axis_names.txt -- repo-owned supplement naming ROM descriptor axes
# ==================================================================
# GENERATED FILE.  Regenerate with `python scripts/axis_names.py`; never hand-edit.
# Derived from rom/ae5l600l.bin bytes (stock) on every run.
#
# WHY THIS FILE EXISTS
# --------------------
# The axis-name method that settled the core RAM identities (docs/corrections.md
# item 9) reads an axis's NAME out of definitions/*.xml.  Those XMLs are owned by
# ECUFlash, which rewrites them on save -- repo-side edits are lost and the two
# copies silently diverge, which is why the definition edits in corrections items
# 24, 25 and 26 were all reverted.  So naming this project derives from ROM bytes
# is recorded HERE, in a file the repo owns, and never in the XMLs.
#
# THE GAP THIS CLOSES
# -------------------
# {n_desc} descriptors decoded from ROM bytes reference {n_axis} distinct axis
# addresses.  The definition XMLs name only {n_named} of them.  Every unnamed axis is
# a lost vote for the RAM->axis method, and roughly 60 traced RAM variables reach
# ONLY unnamed axes, so for those the method has nothing to say.
#
# STATUS: EVIDENCE-RANKED, NOT AUTHORITATIVE
# ------------------------------------------
# Definition XML names ALWAYS outrank this file.  Consult it only for axis
# addresses the XMLs do not name.  Read the confidence column before using a row:
#
#   high        Two independent sources agree: a RAM variable whose identity is
#               SETTLED in docs/corrections.md is traced being passed as this
#               axis's lookup input, AND the breakpoint envelope agrees with that
#               quantity.  Reason from these, including about identity.
#   medium      One source only -- either a settled feeder with an envelope that is
#               merely compatible, or an envelope signature with no feeder at all.
#               Usable as a hypothesis; do NOT settle a RAM identity from it.
#   low         Weak/suggestive only.
#   unresolved  No usable signal, or the feeder and the envelope CONTRADICT each
#               other.  Deliberately left unnamed.  A wrong rename is worse than an
#               honest gap.
#
# WHAT COUNTS AS A SETTLED FEEDER
# -------------------------------
# Only the RAM identities proved from ROM bytes in docs/corrections.md items 8-13
# and 22.  Identities held back as medium in item 23 (0xFFFF4150, 0xFFFF6634,
# 0xFFFF89C8, 0xFFFF63C0, 0xFFFF63C4, 0xFFFF63CC, 0xFFFF5FFC, 0xFFFFA198) never
# promote a row above medium; they are reported in the evidence column so the
# reverse inference (name the axis -> settle the RAM var) stays visible.
#
# KNOWN LIMITS
# ------------
#  * The D3 feed trace in scripts/coverage_map.py is a LINEAR sweep, not
#    control-flow aware.  An FR tag can survive a basic-block boundary and be
#    attributed to the wrong lookup.  That is why a feeder that contradicts the
#    envelope demotes a row to `unresolved` instead of overriding the envelope.
#  * Envelope bands were measured from the definition-NAMED axis population of this
#    ROM, not assumed: rpm 55 axes -50..10000; load 29 axes 0.2..3; intake temp 11
#    axes -40..120; coolant 4 axes -30..70; pressure 12 axes -1000..1000; throttle
#    5 axes 0..100; airflow 3 axes 0.9..290; voltage 1 axis 8..16.
#  * `temperature` means coolant-or-intake: the two are indistinguishable on
#    envelope alone (both run -40..110 in this ROM) and are only separated by a
#    settled feeder.  It is NOT a token scripts/coverage_map.py's quantity_of()
#    emits; treat it as matching either.
#  * Breakpoints are read as big-endian float32, which is what the descriptor
#    acceptance rule in coverage_map.py already proves for every axis listed.
#
# HOW TO CONSUME THIS FILE
# ------------------------
# Records are the lines that start with `0x`, pipe-delimited, 10 fields:
#
#   1 axis_addr   hex, the descriptor axis pointer
#   2 elements    breakpoint count (max, where descriptors share a prefix)
#   3 min         first/min breakpoint value, raw
#   4 max         last/max breakpoint value, raw
#   5 name        PROPOSED axis name, in definition-XML vocabulary, or `-`
#   6 quantity    token, aligned with coverage_map.quantity_of() output, or `-`
#   7 confidence  high | medium | low | unresolved
#   8 descriptors comma-separated `descriptor_addr:slot` (slot 0 = FR4 input)
#   9 feeders     comma-separated RAM addresses traced feeding this axis
#  10 evidence    prose; `;`-separated clauses
#
# Fields never contain `|`.  Parse with `line.split('|')` and strip.
#
# INTEGRATION POINT for scripts/coverage_map.py
# ---------------------------------------------
# In build(), the axis naming maps are assembled at the block beginning
# `axis_names = defaultdict(set)` / `_axis_q_votes` (search for
# `# ---- axis address -> definition-given name(s) ----`).  After that loop over
# d.tables completes, merge this file for addresses NOT already present:
#
#     for r in read_axis_names():                  # confidence in ('high',)
#         if r.addr not in axis_names:             # XML always wins
#             axis_names[r.addr].add('(supplement) ' + r.name)
#             axis_q.setdefault(r.addr, r.quantity)
#
# Gate on confidence == 'high' for the contradiction tests (b) and (c); `medium`
# may be surfaced in evidence text but must not flag a CONFLICT on its own.
# The AXIS_QUANTITY_ENVELOPE table built just below that block should be extended
# from `high` rows only.
#
# ------------------------------------------------------------------------------
"""


def write(recs, n_axis, n_named, n_desc):
    order = {"high": 0, "medium": 1, "low": 2, "unresolved": 3}
    counts = collections.Counter(r["conf"] for r in recs)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(HEADER.format(n_desc=n_desc, n_axis=n_axis, n_named=n_named))
        f.write("# SUMMARY: %d unnamed descriptor axes; %d high, %d medium, %d low,"
                " %d unresolved.\n" % (len(recs), counts["high"], counts["medium"],
                                       counts["low"], counts["unresolved"]))
        f.write("# %d of %d axis addresses are named by the definition XMLs.\n"
                % (n_named, n_axis))
        f.write("#\n# axis_addr | elem | min | max | name | quantity | conf |"
                " descriptors | feeders | evidence\n")
        for conf in ("high", "medium", "low", "unresolved"):
            sub = [r for r in recs if r["conf"] == conf]
            if not sub:
                continue
            f.write("\n# ==== %s (%d) %s\n" % (conf.upper(), len(sub), "=" * 40))
            for r in sorted(sub, key=lambda x: x["addr"]):
                f.write("0x%05X | %d | %s | %s | %s | %s | %s | %s | %s | %s\n" % (
                    r["addr"], r["n"],
                    "%.6g" % r["lo"] if r["lo"] == r["lo"] else "nan",
                    "%.6g" % r["hi"] if r["hi"] == r["hi"] else "nan",
                    r["name"], r["quant"], r["conf"], r["desc"], r["feed"], r["ev"]))
    _ = order


if __name__ == "__main__":
    sys.exit(main())
