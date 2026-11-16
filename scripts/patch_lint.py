#!/usr/bin/env python3
"""Patch linter: flash-safety gates 1-5 of docs/pipeline-plan.md, mechanically.

    python3 scripts/patch_lint.py SPEC.json BASE.bin PATCHED.bin [--allow-table-edits]
    python3 scripts/patch_lint.py --live          # lint the two patches already on the car
    python3 scripts/patch_lint.py --explore 0x0F1000 BIN   # walk code from an entry, print it

Gates (every one must pass; exit 1 on any FAIL):
  1 byte-diff whitelist  every byte that differs BASE -> PATCHED is inside a range the spec
                         claims, the checksum table, or (only with --allow-table-edits) a
                         definition table/axis.
  2 checksum             PATCHED passes scripts/rom_checksum.py.
  3 never-touch          no never-touch range of docs/allocation.json differs (checksum sums
                         excepted, they are gate 2's business).
  4 SH-2E legality       recursive descent from every declared entry: every reachable word
                         decodes as SH-2E (no .INVALID, no pref/SH-2A forms); no branch or
                         trapa in a delay slot; every literal load reads inside the declared
                         region and never from a reachable instruction; every branch target
                         is inside the region or a declared exit; jmp @Rn must resolve.
  5 convention           stack depth 0 at every rts/exit and consistent at every merge;
                         kind "call": r8-r14, fr12-fr15, gbr, fpscr written only if pushed,
                         pr pushed if the code calls out; kind "detour": every register
                         written is in the spec's "clobbers" list.
WARN (does not fail): a PC-relative load in a delay slot (its PC base differs on SH-2;
check by hand), dynamic calls (jsr @Rn with Rn not a literal).

SPEC (JSON):
  {"id": "...",
   "claims": ["<allocation.json id>", ...]  and/or  [{"start": "0x..", "end": "0x.."}],
   "code": [{"entry": "0x..", "kind": "call"|"detour", "region": ["0x..", "0x.."],
             "exits": ["0x.."],                      # leave with stack depth 0 (tail call / return)
             "detours": {"0x<to>": "0x<resume>"},    # leave mid-frame, come back at <resume>
             "clobbers": ["r0", "fr8", ...],          # detour kind: registers it may write
             "accepted": [{"pc": "0x..", "why": "..."}]}]}   # a reviewed warning

What this does NOT establish: that the patch computes the right thing (gate 8, emulation),
that a detour's clobbered registers are dead at the hook (the spec asserts it; a reviewer
checks it), or that its RAM is unused (gate 6, rom_allocation.py --check-claims).
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import sh2e_disasm as D  # noqa: E402
import rom_checksum as CK  # noqa: E402
import rom_allocation as AL  # noqa: E402

DELAYED = {'bra', 'bsr', 'braf', 'bsrf', 'jmp', 'jsr', 'rts', 'rte', 'bt/s', 'bf/s'}
SLOT_ILLEGAL = DELAYED | {'bt', 'bf', 'trapa'}
CALLS = {'bsr', 'jsr', 'bsrf'}
NO_DST = {'cmp/eq', 'cmp/hs', 'cmp/ge', 'cmp/hi', 'cmp/gt', 'cmp/str', 'cmp/pz', 'cmp/pl',
          'tst', 'tst.b', 'fcmp/eq', 'fcmp/gt', 'jmp', 'jsr', 'bra', 'bsr', 'bt', 'bf', 'bt/s',
          'bf/s', 'braf', 'bsrf', 'rts', 'rte', 'nop', 'trapa', 'and.b', 'or.b', 'xor.b',
          'tas.b', 'clrt', 'sett', 'clrs', 'sets', 'clrmac', 'sleep', 'div0u'}
CALLEE_SAVED = {f'r{i}' for i in range(8, 15)} | {f'fr{i}' for i in range(12, 16)} | {'gbr', 'fpscr'}
# Mnemonics the SH7058 (SH-2E) has. Anything else that decodes is a region error.
SH2E = {
    'mov', 'mov.b', 'mov.w', 'mov.l', 'mova', 'movt', 'swap.b', 'swap.w', 'xtrct',
    'add', 'addc', 'addv', 'cmp/eq', 'cmp/hs', 'cmp/ge', 'cmp/hi', 'cmp/gt', 'cmp/pz', 'cmp/pl',
    'cmp/str', 'div1', 'div0s', 'div0u', 'dmuls.l', 'dmulu.l', 'dt', 'exts.b', 'exts.w',
    'extu.b', 'extu.w', 'mac.l', 'mac.w', 'mul.l', 'muls.w', 'mulu.w', 'neg', 'negc', 'sub',
    'subc', 'subv', 'and', 'and.b', 'not', 'or', 'or.b', 'tas.b', 'tst', 'tst.b', 'xor', 'xor.b',
    'rotl', 'rotr', 'rotcl', 'rotcr', 'shal', 'shar', 'shll', 'shlr', 'shll2', 'shlr2', 'shll8',
    'shlr8', 'shll16', 'shlr16', 'bf', 'bf/s', 'bt', 'bt/s', 'bra', 'braf', 'bsr', 'bsrf', 'jmp',
    'jsr', 'rts', 'clrmac', 'clrt', 'ldc', 'ldc.l', 'lds', 'lds.l', 'nop', 'rte', 'sett',
    'sleep', 'stc', 'stc.l', 'sts', 'sts.l', 'trapa', 'clrs', 'sets',
    'fabs', 'fadd', 'fcmp/eq', 'fcmp/gt', 'fdiv', 'fldi0', 'fldi1', 'flds', 'float', 'fmac',
    'fmov', 'fmov.s', 'fmul', 'fneg', 'fsts', 'fsub', 'ftrc'}


def h(x):
    return int(x, 16) if isinstance(x, str) else int(x)


def split_ops(s):
    out, depth, cur = [], 0, ''
    for ch in s:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        if ch == ',' and depth == 0:
            out.append(cur.strip()); cur = ''
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def parse(txt):
    parts = txt.split(None, 1)
    return parts[0], (split_ops(parts[1]) if len(parts) > 1 else [])


def target(ops):
    m = re.match(r'0x([0-9A-Fa-f]+)$', ops[0]) if ops else None
    return int(m.group(1), 16) if m else None


def pcrel(ops):
    for o in ops:
        m = re.match(r'@\(0x([0-9A-Fa-f]+)\)$', o)
        if m:
            return int(m.group(1), 16)
    return None


def writes(mn, ops):
    """Registers an instruction writes (excluding r15 stack effects, handled separately)."""
    w = set()
    for o in ops:
        m = re.match(r'@-?(r\d+)\+?$', o)
        if m and (o.startswith('@-') or o.endswith('+')):
            w.add(m.group(1))
    if mn in NO_DST or not ops:
        return w
    last = ops[-1]
    if re.match(r'^(r\d+|fr\d+|fpul|fpscr|pr|gbr|mach|macl|sr|vbr)$', last):
        w.add(last)
    if mn in CALLS:
        w.add('pr')
    return w


def stack_delta(mn, ops):
    if len(ops) == 2 and ops[1] == '@-r15':
        return -4, ops[0]
    if len(ops) >= 1 and ops[0] == '@r15+':
        return 4, None
    if mn == 'add' and len(ops) == 2 and ops[1] == 'r15' and ops[0].startswith('#'):
        return int(ops[0][1:]), None
    return 0, None


class Walk:
    def __init__(self, rom, spec):
        self.rom = rom
        self.entry = h(spec['entry'])
        self.kind = spec['kind']
        self.lo, self.hi = h(spec['region'][0]), h(spec['region'][1])
        self.exits = {h(x) for x in spec.get('exits', [])}
        self.clobbers = set(spec.get('clobbers', []))
        self.detours = {h(k): h(v) for k, v in spec.get('detours', {}).items()}
        self.accepted = {h(x['pc']): x['why'] for x in spec.get('accepted', [])}
        self.fail, self.warn, self.info = [], [], []
        self.insns = {}
        self.pool_reads = set()
        self.written, self.saved = set(), set()
        self.calls = []
        self.depth_at = {}

    def inside(self, a):
        return self.lo <= a <= self.hi

    def dec(self, pc):
        w = int.from_bytes(self.rom[pc:pc + 2], 'big')
        txt, _ = D.decode(w, pc)
        self.insns[pc] = txt
        return txt

    def check_insn(self, pc, txt, slot=False):
        mn, ops = parse(txt)
        if 'INVALID' in txt or mn == '.word' or mn not in SH2E:
            self.fail.append(f'{pc:06X} {txt}: not an SH-2E instruction (decoding data as code?)')
        if slot and mn in SLOT_ILLEGAL:
            self.fail.append(f'{pc:06X} {txt}: branch/trapa in a delay slot (slot-illegal exception)')
        ea = pcrel(ops)
        if ea is not None:
            if slot:
                self.warn.append(f'{pc:06X} {txt}: PC-relative load in a delay slot; verify the PC base by hand')
            if not self.inside(ea):
                self.fail.append(f'{pc:06X} {txt}: literal at {ea:#x} is outside the region')
            self.pool_reads.add(ea)
            if mn == 'mov.l' or mn == 'mova':
                self.pool_reads.update({ea + 1, ea + 2, ea + 3})
            else:
                self.pool_reads.add(ea + 1)
        self.written |= writes(mn, ops)
        return mn, ops

    def run(self):
        work = [(self.entry, 0, {})]
        while work:
            pc, depth, lits = work.pop()
            while True:
                if not self.inside(pc) and pc in self.detours:
                    pc, lits = self.detours[pc], {}      # detour returns here, same frame
                    continue
                if not self.inside(pc):
                    if pc in self.exits:
                        if depth != 0:
                            self.fail.append(f'exit to {pc:06X} with stack depth {depth}')
                    else:
                        self.fail.append(f'control reaches {pc:06X}, outside the region and not a declared exit')
                    break
                seen = self.depth_at.get(pc)
                if seen is not None:
                    if seen != depth:
                        self.fail.append(f'{pc:06X}: stack depth {depth} here, {seen} on another path')
                    break
                self.depth_at[pc] = depth
                txt = self.dec(pc)
                mn, ops = self.check_insn(pc, txt)
                d, pushed = stack_delta(mn, ops)
                depth += d
                if pushed:
                    self.saved.add(pushed)
                ea = pcrel(ops)
                if mn == 'mov.l' and ea is not None and self.inside(ea):
                    lits = dict(lits); lits[ops[1]] = int.from_bytes(self.rom[ea:ea + 4], 'big')
                elif mn == 'mova':
                    lits = dict(lits); lits['r0'] = ea
                else:
                    for r in writes(mn, ops):
                        if r in lits:
                            lits = dict(lits); lits.pop(r)
                if mn in DELAYED:
                    sp = pc + 2
                    if not self.inside(sp):
                        self.fail.append(f'{pc:06X} {txt}: delay slot outside the region')
                        break
                    self.depth_at.setdefault(sp, depth)
                    stxt = self.dec(sp)
                    smn, sops = self.check_insn(sp, stxt, slot=True)
                    sd, spushed = stack_delta(smn, sops)
                    if spushed:
                        self.saved.add(spushed)
                    after = depth + sd
                    if mn in ('rts', 'rte'):
                        if self.kind != 'call':
                            self.fail.append(f'{pc:06X} rts in a detour')
                        elif after != 0:
                            self.fail.append(f'{pc:06X} rts with stack depth {after}')
                        break
                    if mn in CALLS:
                        tgt = target(ops) if mn == 'bsr' else lits.get(ops[0].lstrip('@')) if mn == 'jsr' else None
                        self.calls.append((pc, tgt))
                        if tgt is None:
                            self.warn.append(f'{pc:06X} {txt}: dynamic call, target not a literal')
                        elif tgt >= CK.ROM_SIZE or self.rom[tgt:tgt + 2] == b'\xff\xff':
                            self.fail.append(f'{pc:06X} {txt}: call target {tgt:#x} is not code')
                        pc, depth = pc + 4, after
                        continue
                    if mn == 'jmp':
                        tgt = lits.get(ops[0].lstrip('@'))
                        if tgt is None:
                            self.fail.append(f'{pc:06X} {txt}: jmp target does not resolve to a literal')
                            break
                        pc, depth = tgt, after
                        continue
                    if mn in ('braf', 'bsrf'):
                        self.fail.append(f'{pc:06X} {txt}: computed branch, cannot be checked')
                        break
                    tgt = target(ops)
                    if mn == 'bra':
                        pc, depth = tgt, after
                        continue
                    work.append((tgt, after, lits))     # bt/s, bf/s taken
                    pc, depth = pc + 4, after
                    continue
                if mn in ('bt', 'bf'):
                    work.append((target(ops), depth, lits))
                pc += 2
        overlap = sorted(a for a in self.pool_reads if a in self.insns)
        if overlap:
            self.fail.append(f'literal pool overlaps executed code at {overlap[0]:06X}')
        if self.kind == 'call':
            bad = (self.written & CALLEE_SAVED) - self.saved
            if bad:
                self.fail.append(f'callee-saved register(s) written without a push: {sorted(bad)}')
            if self.calls and 'pr' not in self.saved:
                self.fail.append('calls out but never saves pr')
        else:
            extra = self.written - self.clobbers - {'pr'} if not self.calls else self.written - self.clobbers
            if extra:
                self.fail.append(f'detour writes {sorted(extra)}, not in its declared clobbers {sorted(self.clobbers)}')
        return self


def claim_ranges(spec, reg):
    by_id = {c['id']: c for c in reg['rom']}
    out = []
    for c in spec.get('claims', []):
        if isinstance(c, str):
            if c not in by_id:
                raise SystemExit(f'spec claims unknown allocation id {c!r}')
            out.append((by_id[c]['s'], by_id[c]['e']))
        else:
            out.append((h(c['start']), h(c['end'])))
    return out


def lint(spec, base, patched, allow_tables=False, label=''):
    reg = AL.load_registry()
    fails, warns = [], []
    ranges = claim_ranges(spec, reg)
    mask = AL.table_mask() if allow_tables else None
    stray = []
    for a in range(CK.ROM_SIZE):
        if base[a] == patched[a]:
            continue
        if any(s <= a <= e for s, e in ranges):
            continue
        if CK.TABLE <= a < CK.TERMINATOR_AT + 4 and (a - CK.TABLE) % CK.REC >= 8:
            continue
        if mask is not None and mask[a] == 1:
            continue
        stray.append(a)
    for s, e in AL.runs(stray):
        fails.append(f'gate 1: change at {s:#08x}-{e:#08x} is not in any claimed range')
    probs, _ = CK.check(patched)
    fails += [f'gate 2: {p}' for p in probs]
    for n in reg['never_touch']:
        for a in range(n['s'], n['e'] + 1):
            if base[a] != patched[a] and not (CK.TABLE <= a < CK.TERMINATOR_AT + 4 and (a - CK.TABLE) % CK.REC >= 8):
                fails.append(f'gate 3: never-touch byte {a:#08x} changed'); break
    for c in spec.get('code', []):
        w = Walk(patched, c).run()
        tag = f'entry {h(c["entry"]):06X}'
        fails += [f'gate 4/5 [{tag}]: {f}' for f in w.fail]
        for x in w.warn:
            pc = int(x[:6], 16) if re.match(r'[0-9A-F]{6} ', x) else None
            warns.append(f'[{tag}] {x}' + (f'  -- ACCEPTED: {w.accepted[pc]}' if pc in w.accepted else ''))
    print(f'== {label or spec.get("id")}: {"FAIL" if fails else "pass"}')
    for f in fails:
        print('  FAIL ' + f)
    for x in warns:
        print('  warn ' + x)
    return 1 if fails else 0


LIVE = os.path.join(REPO, 'docs', 'patch-specs')


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('args', nargs='*')
    ap.add_argument('--allow-table-edits', action='store_true')
    ap.add_argument('--live', action='store_true', help='lint every spec in docs/patch-specs against stock -> current rev')
    ap.add_argument('--explore', metavar='ENTRY')
    ap.add_argument('--region', nargs=2)
    a = ap.parse_args()

    if a.explore:
        rom = open(a.args[0], 'rb').read()
        e = h(a.explore)
        lo, hi = (h(a.region[0]), h(a.region[1])) if a.region else (e, e + 0x400)
        w = Walk(rom, {'entry': a.explore, 'kind': 'call', 'region': [hex(lo), hex(hi)]}).run()
        for pc in sorted(w.insns):
            print(f'{pc:06X} {w.insns[pc]}')
        print(f'written {sorted(w.written)}  saved {sorted(w.saved)}  calls {[(hex(p), hex(t) if t else None) for p, t in w.calls]}')
        for f in w.fail:
            print('FAIL ' + f)
        for x in w.warn:
            print('warn ' + x)
        return 0

    if a.live:
        base = open(os.path.join(REPO, 'rom', 'ae5l600l.bin'), 'rb').read()
        cur = sorted(p for p in os.listdir(os.path.join(REPO, 'rom')) if p.startswith('AE5L600L 20g rev 20.19'))[-1]
        patched = open(os.path.join(REPO, 'rom', cur), 'rb').read()
        rc = 0
        specs = sorted(f for f in os.listdir(LIVE) if f.endswith('.json'))
        for f in specs:
            s = json.load(open(os.path.join(LIVE, f)))
            # base is stock, so the bin carries every live patch: whitelist all registered claims
            rc |= lint({**s, 'claims': [x['id'] for x in AL.load_registry()['rom'] if not x.get('retired')]},
                       base, patched, allow_tables=True, label=f'{s["id"]} (stock -> {cur})')
        return rc

    if len(a.args) != 3:
        ap.error('SPEC BASE PATCHED')
    spec = json.load(open(a.args[0]))
    return lint(spec, open(a.args[1], 'rb').read(), open(a.args[2], 'rb').read(), a.allow_table_edits)


if __name__ == '__main__':
    sys.exit(main())
