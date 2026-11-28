#!/usr/bin/env python3
"""Emulation check for disassembly/analysis/launch_closure_trace.txt (2026-11-27).

    python3 scripts/trace/emu_launch_closure.py           # prints tables, exits 0 when every contract holds
    python3 scripts/trace/emu_launch_closure.py --quiet   # summary lines only

Entries exercised, in BOTH bins (rom/ae5l600l.bin = stock, rom/AE5L600L 20g rev 20.19c.bin = tuned):
    0x03B668  the rev-limit flag update (tuned: through the injected code at 0x0F1000 and back at 0x03B6B2)
    0x0F1000  the injected launch offset (tuned only; stock is erased 0xFF there)
    0x03B74A  the reset path that clears the three flag bytes
    0x03D2FC  the combiner that turns byte 0xFFFF7CB8 into the 16-bit mask 0xFFFF7D80
    0x03DCB6  a per-channel consumer of 0xFFFF7D80 (gates the call to 0x009C00)
    0x015624  the other reader of 0xFFFF7D80 (set-bit count -> 0xFFFF5DDD / 0xFFFF5DDE)
    0x016102  the other reader of cal 0x0CC504 (no launch offset there)

The ORACLE below is written from the step-1 reading of the bytes, not from any doc:

  0x03B668 (tuned)
    rpm  = f32 [0xFFFF6624]; spd = f32 [0xFFFF65FC]; q = f32 [0xFFFF620C]
    add  = byte [0xFFFF65D0] == 1 ? (spd < K ? [0x0F1050] : [0x0F1054])          K = f32 0x4100D311
                                  : (spd > K ? [0x0F1048] : [0x0F1050])          (2700 / 0.0 / 0.0 in 20.19c)
    x    = rpm + add                                                             (fr15)
    cut, res = [0x0CC500], [0x0CC504]          -- whatever the speed
  0x03B668 (stock)
    x    = rpm
    cut, res = [0x0CC500],[0x0CC504] if spd outside [-1, +1] else [0x0CC508],[0x0CC50C]
  both
    b1 = byte [0xFFFF7CB9]:  := 1 if not (cut > x);  := 0 elif res > x;  else unchanged
    b2 = byte [0xFFFF7CBA]:  same with [0x0CC510] / [0x0CC514]
    use_b2 = byte[0xFFFF65C5] != 1  and  (byte[0xFFFF65C0] == 1 or byte[0xFFFF971D] != 0)
                                    and  (byte[0xFFFF5E95] in (5, 7) or byte[0xFFFF971C] != 0)
    s  = b2 if use_b2 else b1
    b0 = byte [0xFFFF7CB8]:  := 1 if s == 1;  := 0 elif [0x0CC518] > q;  else unchanged
    returns by tail-jump to 0x03D2FC with r8-r14, r15, pr, fr12-fr15 as on entry

Deterministic: fixed grids, no randomness. Float arithmetic in the emulator is exact and
rounded toward zero (corrections item 106). The main grids use integer RPM values, for which
rpm + 2700 is exact and the result is the same under any rounding mode. test_rounding_edge
is the one place that depends on the last bit: at rpm = 4000 - 2^-12 and 3980 - 2^-12 the
fadd at 0x0F102E is an exact tie. It pins what the emulator (round toward zero) does there,
proves that round-to-nearest would give the other answer, and proves (exhaustively over every
float32 rpm in [3900, 4096)) that these are the only two such inputs. Which mode the chip runs
in after init is NOT settled (docs/open-holes.md item 11, point 4); nothing here decides it.

Review pass (third decode, 2026-11-27) added: the any-alignment and loader scans for
0x0CC508 / 0x0CC50C, the use of every literal in 0x0CC4C0..0x0CC51C, the 0x03D2FC read set,
the per-channel byte gate 0x063E34 in 0x03DCB6 (channels 0..7), the GBR scan around
0xFFFF7CB8..7CBA / 0xFFFF7D80, and the comparison with scripts/patch_emulate.py launch_oracle.

Audit pass (independent, 2026-11-27) added: audit_oracle, a second oracle written from a blind
re-derivation, run over inputs the grids above never use (NaN / inf / negative / 1e9 x, the
negative window edge, NaN / inf / -0.0 speed, flag 0x81 / 0xFF, start states 2 / 0xFF / mixed,
q = NaN, high-bit selector bytes); the complete RAM read set of 0x03B668..0x03D2FC; pr at the
patch entry through the host (0x03B6A8, not the caller's return address); the 0xFFFF8EDC gate in
0x04AA58 / 0x049BA4; the consumer 0x026CF4 of getter 0x03B76E (bit 5 of 0xFFFF6A29); the literal
base scan for 0xFFFF7CB8..7CBA; and launch_oracle's hard-coded 0.0 for [0x0F1048].
"""
import hashlib
import json
import math
import os
import re
import struct
import sys
from fractions import Fraction

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import sh2e_emu as E  # noqa: E402
import sh2e_disasm as D  # noqa: E402
CENSUS = os.path.join(ROOT, 'disassembly', 'maps', 'function_census.json')

QUIET = '--quiet' in sys.argv
TUNED = os.path.join(ROOT, 'rom', 'AE5L600L 20g rev 20.19c.bin')
STOCK = os.path.join(ROOT, 'rom', 'ae5l600l.bin')
MD5 = {TUNED: '92cae8275cd4f9b473a3a9e36efe6449', STOCK: 'a8ea39d447f977e270e27ee670243c88'}

RPM, SPD, Q620C = 0xFFFF6624, 0xFFFF65FC, 0xFFFF620C
SEL65C5, B65C0, B971D, B971C, B5E95, F65D0 = 0xFFFF65C5, 0xFFFF65C0, 0xFFFF971D, 0xFFFF971C, 0xFFFF5E95, 0xFFFF65D0
B0, B1, B2 = 0xFFFF7CB8, 0xFFFF7CB9, 0xFFFF7CBA
MASK = 0xFFFF7D80

checks = 0
fails = []


def check(cond, msg):
    global checks
    checks += 1
    if not cond:
        fails.append(msg)


def say(*a):
    if not QUIET:
        print(*a)


def f32(b, a):
    return struct.unpack('>f', b[a:a + 4])[0]


def u32(b, a):
    return struct.unpack('>I', b[a:a + 4])[0]


def b2f(x):
    return struct.unpack('>f', struct.pack('>I', x))[0]


def nextf(x, d):
    """Adjacent float32 (d = +1 / -1) of a positive float32."""
    i = struct.unpack('>I', struct.pack('>f', x))[0]
    return b2f(i + d)


def load(path):
    rom = open(path, 'rb').read()
    h = hashlib.md5(rom).hexdigest()
    check(h == MD5[path], f'md5 {os.path.basename(path)} = {h}')
    return rom


# ------------------------------------------------------------------ static facts
def static_facts(stock, tuned):
    say('== static bytes ==')
    # the two patched instruction pairs and the two redirected pool longs
    exp = {
        0x03B6AE: ('d23bf828', 'd03b402b'),
        0x03B6B8: ('d23af828d23af628', 'd03b402bd239f628'),
    }
    for a, (s, t) in exp.items():
        n = len(s) // 2
        check(stock[a:a + n].hex() == s, f'stock bytes at {a:06X}')
        check(tuned[a:a + n].hex() == t, f'tuned bytes at {a:06X}')
        say(f'  {a:06X}: stock {stock[a:a + n].hex()}  tuned {tuned[a:a + n].hex()}')
    for a, s, t in ((0x03B79C, 0x000CC500, 0x000F1000), (0x03B7A8, 0x000CC50C, 0x000F1000),
                    (0x03B7A0, 0x000CC504, 0x000CC504), (0x03B7A4, 0x000CC508, 0x000CC508)):
        check(u32(stock, a) == s and u32(tuned, a) == t, f'pool {a:06X}')
        say(f'  pool {a:06X}: stock {u32(stock, a):08X}  tuned {u32(tuned, a):08X}')
    check(stock[0x0F1000:0x0F1060] == b'\xff' * 0x60, 'stock 0x0F1000 erased')
    check(tuned[0x0F1058:0x0F1060] == b'\xff' * 8, 'tuned erased after 0x0F1058')
    say('  calibration scalars (f32):')
    for a in range(0x0CC500, 0x0CC51C, 4):
        say(f'    {a:06X}: stock {f32(stock, a):8.1f}   tuned {f32(tuned, a):8.1f}')
    want_s = [6700, 6650, 6700, 6650, 6700, 6650, 1260]
    want_t = [6700, 6680, 6700, 6680, 6700, 6680, 1260]
    for i, a in enumerate(range(0x0CC500, 0x0CC51C, 4)):
        check(f32(stock, a) == want_s[i], f'stock cal {a:06X}')
        check(f32(tuned, a) == want_t[i], f'tuned cal {a:06X}')
    for a, v in ((0x0F1048, 0.0), (0x0F104C, None), (0x0F1050, 2700.0), (0x0F1054, 0.0)):
        if v is not None:
            check(f32(tuned, a) == v, f'patch const {a:06X}')
    check(u32(tuned, 0x0F104C) == 0x4100D311, 'patch speed constant bits')
    say(f'  patch constants: 0F1048 {f32(tuned, 0x0F1048)}  0F104C {f32(tuned, 0x0F104C)!r}'
        f'  0F1050 {f32(tuned, 0x0F1050)}  0F1054 {f32(tuned, 0x0F1054)}')

    # every aligned pool long that names the second pair or the flag bytes / mask
    def refs(rom, val):
        p = struct.pack('>I', val)
        out, i = [], rom.find(p)
        while i != -1:
            if i % 4 == 0:
                out.append(i)
            i = rom.find(p, i + 1)
        return out
    for val in (0x0CC500, 0x0CC504, 0x0CC508, 0x0CC50C, 0xFFFF7CB8, 0xFFFF7D80):
        say(f'  pool longs = {val:08X}: stock {[hex(x) for x in refs(stock, val)]}  '
            f'tuned {[hex(x) for x in refs(tuned, val)]}')
    check(refs(tuned, 0x0CC50C) == [], 'tuned: no pool long names 0x0CC50C')
    check(refs(tuned, 0x0CC508) == [0x03B7A4], 'tuned: 0x0CC508 only at 0x03B7A4')
    check(refs(stock, 0x0CC508) == [0x03B7A4] and refs(stock, 0x0CC50C) == [0x03B7A8], 'stock second pair')
    check(refs(tuned, 0x0CC504) == [0x01619C, 0x03B7A0], 'tuned CC504 refs')
    check(refs(tuned, 0x0CC500) == [0x0F1044], 'tuned CC500 refs')

    # review: the same values at ANY byte alignment (a long can only be fetched aligned, but this
    # also rules out a misread of the scan)
    def anyref(rom, val):
        p, out = struct.pack('>I', val), []
        i = rom.find(p)
        while i != -1:
            out.append(i)
            i = rom.find(p, i + 1)
        return out
    check(anyref(tuned, 0x0CC50C) == [], 'tuned: 0x0CC50C at no alignment')
    check(anyref(tuned, 0x0CC508) == [0x03B7A4], 'tuned: 0x0CC508 only at 0x03B7A4, any alignment')
    say(f'  any alignment: 0x0CC508 at {[hex(x) for x in anyref(tuned, 0x0CC508)]}, '
        f'0x0CC50C at {[hex(x) for x in anyref(tuned, 0x0CC50C)]} (tuned)')

    # every mov.l @(disp,PC) that addresses a literal (slot-address PC convention, as fn_dump)
    def loaders(rom, lit):
        out = []
        for pc in range(max(0, lit - 0x400), lit, 2):
            w = (rom[pc] << 8) | rom[pc + 1]
            if w >> 12 == 0xD and ((pc + 4) & ~3) + (w & 0xFF) * 4 == lit:
                out.append(pc)
        return out
    check(loaders(tuned, 0x03B7A4) == [0x03B6BC], 'tuned: 0x03B7A4 loaded only at 0x03B6BC')
    check(loaders(stock, 0x03B7A4) == [0x03B6B8], 'stock: 0x03B7A4 loaded only at 0x03B6B8')
    check(D.decode((tuned[0x03B6BA] << 8) | tuned[0x03B6BB], 0x03B6BA)[0] == 'jmp @r0', 'tuned 0x03B6BA is jmp @r0')
    # the delay-slot PC convention is not settled; under a branch-target-relative PC the two slot
    # loads (0x03B6B2 D23B, 0x03B6BC D239) would read 0x0F10F0 / 0x0F10E8 -- erased in 20.19c
    for slot, alt in ((0x03B6B2, 0x0F10F0), (0x03B6BC, 0x0F10E8)):
        w = (tuned[slot] << 8) | tuned[slot + 1]
        check(((0x0F1000 + 4) & ~3) + (w & 0xFF) * 4 == alt and u32(tuned, alt) == 0xFFFFFFFF,
              f'alternative slot read for {slot:06X}')
    # r2 is not referenced between the patch entry and its rewrite at 0x0F1030
    r2use = [a for a in range(0x0F1000, 0x0F1030, 2)
             if re.search(r'\br2\b', D.decode((tuned[a] << 8) | tuned[a + 1], a)[0])]
    check(r2use == [], f'r2 referenced in 0x0F1000..0x0F102E at {r2use}')
    check(D.decode((tuned[0x0F1030] << 8) | tuned[0x0F1031], 0x0F1030)[0] == 'mov.l @(0x0F1044),r2',
          '0x0F1030 rewrites r2')
    literal_uses(tuned)


def _dec(rom, pc):
    return D.decode((rom[pc] << 8) | rom[pc + 1], pc)[0]


def _reg_uses(txt, n):
    """How register rn appears in one decoded instruction."""
    r = f'r{n}'
    mn, _, ops = txt.partition(' ')
    out = set()
    if re.search(rf'@\((-?\d+|0x[0-9A-Fa-f]+),{r}\)', ops):
        out.add('disp-base')
    if re.search(rf'@\(r0,{r}\)', ops) or (n == 0 and '@(r0,' in ops):
        out.add('index-base')
    if re.search(rf'@-{r}\b|@{r}\+', ops):
        out.add('auto-inc')
    if re.search(rf'(^|,)@{r}($|,)', ops):
        out.add('call-target' if mn in ('jsr', 'jmp') else 'deref')
    opl = [o for o in re.split(r',(?![^(]*\))', ops) if o]
    if r in opl:
        pure = (len(opl) == 2 and opl[1] == r and opl[0] != r
                and re.match(r'^(mov|mov\.[bwl]|movt|sts|sts\.l|stc|mova)$', mn))
        out.add('kill' if pure else 'value-use')
    return out


def literal_uses(rom):
    """Every aligned long in 0x0CC4C0..0x0CC51C, its loader(s), and every use of the loaded
    register along every control path until that register is rewritten (callees not entered;
    a path ends at rts / jmp). The two loaders that sit in jmp delay slots are reported apart."""
    say('  literals in 0x0CC4C0..0x0CC51C (tuned): loader -> uses of the loaded register')
    lits = [a for a in range(0, len(rom), 4) if 0x0CC4C0 <= u32(rom, a) <= 0x0CC51C]
    check(len(lits) == 24, f'24 literals in range, got {len(lits)}')
    byl = {a: [] for a in lits}
    for pc in range(0, len(rom), 2):
        w = (rom[pc] << 8) | rom[pc + 1]
        t = ((pc + 4) & ~3) + (w & 0xFF) * 4
        if w >> 12 == 0xD and t in byl:
            byl[t].append(pc)
    slot_loads = {}
    for lit in lits:
        check(len(byl[lit]) == 1, f'literal {lit:06X} has {len(byl[lit])} loaders')
        for pc in byl[lit]:
            n = ((rom[pc] << 8) | rom[pc + 1]) >> 8 & 15
            prev = _dec(rom, pc - 2).split()[0]
            if prev in ('jmp', 'rts'):
                slot_loads[pc] = u32(rom, lit)
                continue
            seen, work, uses = set(), [pc + 2], []
            while work:
                a = work.pop()
                while a not in seen:
                    seen.add(a)
                    t = _dec(rom, a)
                    u = _reg_uses(t, n)
                    mn, _, ops = t.partition(' ')
                    check('.word' not in t, f'walk from {pc:06X} decoded data at {a:06X}')
                    if u - {'kill'}:
                        uses.append((a, t, u))
                    if u == {'kill'}:
                        break
                    if mn in ('bt', 'bf'):
                        work.append(int(ops, 16))
                    elif mn in ('bt/s', 'bf/s', 'bra', 'jmp', 'rts', 'bsr', 'jsr'):
                        st = _dec(rom, a + 2)
                        su = _reg_uses(st, n)
                        seen.add(a + 2)
                        if su - {'kill'}:
                            uses.append((a + 2, st, su))
                        if su == {'kill'}:
                            break
                        if mn in ('bt/s', 'bf/s'):
                            work.append(int(ops, 16))
                        elif mn == 'bra':
                            a = int(ops, 16)
                            continue
                        elif mn in ('jmp', 'rts'):
                            break
                        a += 4
                        continue
                    a += 2
            kinds = set().union(*[u for _, _, u in uses]) if uses else set()
            check(kinds == {'deref'}, f'literal {lit:06X} via {pc:06X}: uses {kinds}')
            check(all(t.startswith('fmov.s @r') for _, t, _ in uses), f'literal {lit:06X}: non-fmov deref')
            say(f'    {lit:06X} = {u32(rom, lit):06X}  {pc:06X} r{n} -> '
                + ', '.join(f'{a:06X} {t}' for a, t, _ in uses))
    check(slot_loads == {0x03B6B2: 0x0CC504, 0x03B6BC: 0x0CC508}, f'jmp-slot loaders {slot_loads}')
    say('    jmp delay-slot loaders: 03B6B2 (0x0CC504; also executed as a normal instruction when 0x0F1034 '
        'returns, then fmov.s at 03B6B6) and 03B6BC (0x0CC508; r2 rewritten at 0F1030, never read)')


# ------------------------------------------------------------------ GBR reach of the flag bytes
def gbr_scan(tuned):
    """Every census function that installs a GBR within long-displacement reach (<= 1020 bytes)
    of 0xFFFF7CB8..7CBA or 0xFFFF7D80/81: evaluate every GBR displacement op in its body (the
    instructions control flow reaches from the entry, as fn_dump walks them -- pool words are
    not decoded) with that GBR, resolve the r0-indexed GBR ops, and scan the callees that
    inherit GBR without setting their own."""
    say('== GBR scan around 0xFFFF7CB8..7CBA / 0xFFFF7D80 (tuned, census functions) ==')
    sys.path.insert(0, os.path.join(ROOT, 'scripts', 'mapping'))
    import function_census as fc
    walker = fc.Census(tuned)
    walker.lit_addrs = set()
    fs = {}
    for line in open(CENSUS):
        line = line.strip().rstrip(',')
        if line.startswith('{"entry"'):
            f = json.loads(line)
            fs[f['entry']] = f
    T = set(range(0xFFFF7CB8, 0xFFFF7CBB)) | {0xFFFF7D80, 0xFFFF7D81}
    cand = [f for f in fs.values() if any(0 <= t - int(g, 16) <= 1020 for g in f['gbr'] for t in T)]
    size = {'b': 1, 'w': 2, 'l': 4}

    def gbr_ops(f):
        lo, hi = int(f['entry'], 16), int(f['end'], 16)
        _, visited, _ = walker.walk(lo, commit=False, limit=20000)
        for a in sorted(x for x in visited if lo <= x < hi):
            t = _dec(tuned, a)
            if ',gbr)' in t:
                yield a, t

    nops, hits, indexed = 0, [], []
    for f in cand:
        for g in f['gbr']:
            G = int(g, 16)
            for a, t in gbr_ops(f):
                m = re.search(r'@\((\d+),gbr\)', t)
                if m:
                    nops += 1
                    ea = G + int(m.group(1))
                    if set(range(ea, ea + size[t.split()[0].split('.')[1][0]])) & T:
                        hits.append((f['entry'], a, t))
                else:
                    prev = [_dec(tuned, a - k) for k in (2, 4)]
                    imm = [int(p.split('#')[1].split(',')[0]) for p in prev if re.match(r'mov #-?\d+,r0$', p)]
                    indexed.append((a, t, G + imm[0] if imm else None))
    check(len(cand) == 41, f'41 GBR functions in reach, got {len(cand)}')
    check(hits == [], f'GBR access to the flag bytes / mask: {hits}')
    got_idx = sorted((a, ea) for a, _, ea in indexed)
    check(got_idx == [(0x038EB0, 0xFFFF7B9F), (0x03A804, 0xFFFF7C5E), (0x03A80E, 0xFFFF7C5E)],
          f'r0-indexed GBR ops {[(hex(a), hex(e) if e else None) for a, e in got_idx]}')
    # callees reached while that GBR is live, which do not install their own
    inh, inh_ops = set(), 0
    for f in cand:
        stack = list(f['callees'])
        while stack:
            c = stack.pop()
            if c in inh or c not in fs or fs[c]['gbr']:
                continue
            inh.add(c)
            inh_ops += sum(1 for _ in gbr_ops(fs[c]))
            stack.extend(fs[c]['callees'])
    check(inh_ops == 0, f'{inh_ops} GBR ops in inherited-GBR callees')
    say(f'  {len(cand)} functions, {nops} GBR displacement ops evaluated, {len(hits)} reach 7CB8-7CBA / 7D80-7D81;'
        f' r0-indexed: ' + ', '.join(f'{a:06X} -> {ea:#010x}' for a, ea in got_idx)
        + f'; {len(inh)} inherited-GBR callees hold {inh_ops} GBR ops')


# ------------------------------------------------------------------ 0x0F1000 alone
def test_patch(tuned):
    say('== 0x0F1000 (tuned) run alone to its jmp target 0x03B6B2 ==')
    K = f32(tuned, 0x0F104C)
    speeds = [-5.0, 0.0, 0.5, 1.0, 5.0, nextf(K, -1), K, nextf(K, +1), 8.1, 30.0, 200.0,
              float('inf'), float('nan')]
    flags = [0, 1, 2, 0xFF]
    say(f'  {"spd":>14} ' + ' '.join(f'flag={f:#04x}' for f in flags))
    for s in speeds:
        row = []
        for fl in flags:
            emu = E.Emu(tuned)
            emu.ram_f32(SPD, s)
            emu.ram_u8(F65D0, fl)
            regs = {k: 0x1000 + k for k in range(16) if k not in (15,)}
            fregs = {k: 100.0 + k for k in range(16)}
            fregs[15] = 4000.0
            res = emu.call(0x0F1000, regs=regs, fregs=fregs, stop_at={0x03B6B2})
            check(res == 0x03B6B2, f'patch did not reach 0x03B6B2 (spd {s}, flag {fl})')
            add = emu.fr(15) - 4000.0
            if fl == 1:
                want = 2700.0 if s < K else 0.0
            else:
                want = 0.0 if s > K else 2700.0
            if math.isnan(s):
                want = 0.0 if fl == 1 else 2700.0
            check(add == want, f'patch add spd={s!r} flag={fl}: got {add} want {want}')
            check(emu.fr(8) == f32(tuned, 0x0CC500), 'patch leaves fr8 = [0x0CC500]')
            check(emu.R[2] == 0x0CC500, 'patch leaves r2 = 0x0CC500')
            check(emu.R[0] == 0x03B6B2, 'patch leaves r0 = 0x03B6B2')
            check(emu.fr(6) == K, 'patch leaves fr6 = K')
            check(emu.FR[9] == E.f2b(s) or (math.isnan(s) and math.isnan(emu.fr(9))), 'patch leaves fr9 = speed')
            changed = sorted(k for k in range(16) if k not in (0, 2, 15) and emu.R[k] != (regs.get(k, 0) & 0xFFFFFFFF))
            check(changed == [], f'patch changed r{changed}')
            fchanged = sorted(k for k in range(16) if k not in (6, 8, 9, 15) and emu.fr(k) != fregs[k])
            check(fchanged == [], f'patch changed fr{fchanged}')
            check(emu.R[15] == E.STACK_TOP and emu.writes == {}, 'patch touches no memory and no stack')
            check(emu.pr == E.RETURN_MAGIC, 'patch leaves pr')
            row.append(f'{add:9.0f}')
        say(f'  {s!r:>14} ' + ' '.join(f'{c:>9}' for c in row))
    # the flag is inert except at spd == K exactly and NaN -- in THIS calibration, because the
    # two "no offset" words 0x0F1048 and 0x0F1054 both hold 0.0
    check(f32(tuned, 0x0F1048) == 0.0 and f32(tuned, 0x0F1054) == 0.0, 'both no-offset words are 0.0')
    say('  => flag 0xFFFF65D0 changes the result ONLY at spd == K exactly and at spd = NaN '
        '(while [0x0F1048] == [0x0F1054])')

    # mutation: give the four constant words distinct values to prove which word each branch reads
    say('  mutated copy: [0x0F1048]=111, [0x0F1050]=2700, [0x0F1054]=555 (a modified in-memory copy of the bin; nothing is written to disk)')
    mut = bytearray(tuned)
    mut[0x0F1048:0x0F104C] = struct.pack('>f', 111.0)
    mut[0x0F1054:0x0F1058] = struct.pack('>f', 555.0)
    mut = bytes(mut)
    for s in (0.0, K, nextf(K, +1), 30.0, float('nan')):
        row = []
        for fl in (0, 1):
            emu = E.Emu(mut)
            emu.ram_f32(SPD, s)
            emu.ram_u8(F65D0, fl)
            emu.call(0x0F1000, fregs={15: 4000.0}, stop_at={0x03B6B2})
            add = emu.fr(15) - 4000.0
            if fl == 1:
                want = 2700.0 if s < K else 555.0          # 0x0F1018 mova 0x0F1054
            else:
                want = 111.0 if s > K else 2700.0          # 0x0F102A mova 0x0F1048
            check(add == want, f'mutated patch spd={s!r} flag={fl}: got {add} want {want}')
            row.append(f'{add:6.0f}')
        say(f'    spd={s!r:>20}  flag!=1 -> {row[0]}   flag==1 -> {row[1]}')
    say('  => byte==1 and speed >= K (or NaN) reads 0x0F1054; byte!=1 and speed > K reads 0x0F1048')


# ------------------------------------------------------------------ 0x03B668 grid
def oracle(rom, tuned, st):
    K = f32(rom, 0x0F104C) if tuned else None
    rpm, spd, q = st['rpm'], st['spd'], st['q']
    x = rpm
    if tuned:
        if st['f65d0'] == 1:
            on = spd < K
        else:
            on = not (spd > K)
        x = rpm + (2700.0 if on else 0.0)
        cut, res = f32(rom, 0x0CC500), f32(rom, 0x0CC504)
    else:
        outside = spd < -1.0 or spd > 1.0
        cut, res = (f32(rom, 0x0CC500), f32(rom, 0x0CC504)) if outside else (f32(rom, 0x0CC508), f32(rom, 0x0CC50C))

    def hyst(old, c, r):
        if not (c > x):
            return 1
        if r > x:
            return 0
        return old
    b1 = hyst(st['b1'], cut, res)
    b2 = hyst(st['b2'], f32(rom, 0x0CC510), f32(rom, 0x0CC514))
    use_b2 = (st['s65c5'] != 1) and (st['b65c0'] == 1 or st['b971d'] != 0) and \
             (st['b5e95'] in (5, 7) or st['b971c'] != 0)
    s = b2 if use_b2 else b1
    if s == 1:
        b0 = 1
    elif f32(rom, 0x0CC518) > q:
        b0 = 0
    else:
        b0 = st['b0']
    return b0, b1, b2, x, cut, res


def run_03B668(rom, st):
    emu = E.Emu(rom)
    emu.ram_f32(RPM, st['rpm'])
    emu.ram_f32(SPD, st['spd'])
    emu.ram_f32(Q620C, st['q'])
    emu.ram_u8(SEL65C5, st['s65c5'])
    emu.ram_u8(B65C0, st['b65c0'])
    emu.ram_u8(B971D, st['b971d'])
    emu.ram_u8(B971C, st['b971c'])
    emu.ram_u8(B5E95, st['b5e95'])
    emu.ram_u8(F65D0, st['f65d0'])
    emu.ram_u8(B0, st['b0'])
    emu.ram_u8(B1, st['b1'])
    emu.ram_u8(B2, st['b2'])
    regs = {k: 0x2000 + k for k in range(15)}
    fregs = {k: 50.0 + k for k in range(16)}
    res = emu.call(0x03B668, regs=regs, fregs=fregs, stop_at={0x03B6C0})
    check(res == 0x03B6C0, 'did not reach 0x03B6C0')
    at = (emu.fr(15), emu.fr(8), emu.fr(6))
    while emu.pc != 0x03D2FC:
        if emu.steps > 10000:
            raise E.EmuError('runaway')
        emu.step()
    # callee-saved state as on entry at the tail-jump
    for k in range(8, 15):
        check(emu.R[k] == regs[k], f'r{k} not restored')
    for k in (12, 13, 14, 15):
        check(emu.fr(k) == fregs[k], f'fr{k} not restored')
    check(emu.R[15] == E.STACK_TOP and emu.pr == E.RETURN_MAGIC, 'r15/pr not restored')
    wrote = sorted(a for a in emu.writes)
    check(set(wrote) <= {B0, B1, B2}, f'unexpected writes {[hex(a) for a in wrote]}')
    return (emu.read_u8(B0), emu.read_u8(B1), emu.read_u8(B2)), at, emu


def test_03B668(rom, tuned):
    name = 'tuned' if tuned else 'stock'
    say(f'== 0x03B668 ({name}) grid ==')
    K = f32(rom, 0x0F104C) if tuned else 8.051530838012695
    rpms = [0.0, 3000.0, 3979.0, 3980.0, 3999.0, 4000.0, 4001.0, 6000.0, 6649.0, 6650.0,
            6679.0, 6680.0, 6699.0, 6700.0, 6701.0, 8000.0]
    spds = [0.0, 1.0, nextf(1.0, +1), 5.0, nextf(K, -1), K, nextf(K, +1), 30.0, -3.0]
    n = 0
    seen_entry = {0x0F1000: 0, 0x03B6BE: 0}
    # main grid: selector default (b1 drives b0), q below 1260 so a cleared source clears b0
    for rpm in rpms:
        for spd in spds:
            for f65d0 in (0, 1):
                for b1 in (0, 1):
                    st = dict(rpm=rpm, spd=spd, q=1000.0, s65c5=0, b65c0=0, b971d=0, b971c=0, b5e95=0,
                              f65d0=f65d0, b0=b1, b1=b1, b2=b1)
                    got, at, emu = run_03B668(rom, st)
                    want = oracle(rom, tuned, st)
                    n += 1
                    check(got == want[:3], f'{name} 03B668 {st}: got {got} want {want[:3]}')
                    check(at == (want[3], want[4], want[5]),
                          f'{name} fr15/fr8/fr6 at 03B6C0 {at} want {want[3:]}')
                    for a in seen_entry:
                        if a in emu.executed:
                            seen_entry[a] += 1
                    if tuned:
                        check(at[1] == f32(rom, 0x0CC500) and at[2] == f32(rom, 0x0CC504),
                              'tuned: compared pair is always 0x0CC500/0x0CC504')
    # table: rising and falling sweep with launch on / off
    for spd in (0.0, 30.0):
        say(f'  spd={spd}  (flag65D0=0, start state 0 rising then 1 falling; b1 shown)')
        line_up, line_dn = [], []
        for rpm in (3970.0, 3979.0, 3980.0, 3999.0, 4000.0, 6649.0, 6650.0, 6679.0, 6680.0, 6699.0, 6700.0):
            st = dict(rpm=rpm, spd=spd, q=1000.0, s65c5=0, b65c0=0, b971d=0, b971c=0, b5e95=0,
                      f65d0=0, b0=0, b1=0, b2=0)
            up = run_03B668(rom, st)[0][1]
            st.update(b0=1, b1=1, b2=1)
            dn = run_03B668(rom, st)[0][1]
            line_up.append(f'{rpm:.0f}:{up}')
            line_dn.append(f'{rpm:.0f}:{dn}')
        say('    from 0: ' + ' '.join(line_up))
        say('    from 1: ' + ' '.join(line_dn))
    # selector grid at a fixed operating point where b1 != b2 is forced by different start states
    say('  selector (b1 start 1 / b2 start 0, rpm in the hysteresis band so both keep their value):')
    band_rpm = 6690.0 if tuned else 6660.0     # between resume and cut for both pairs
    for s65c5 in (0, 1, 2):
        for b65c0 in (0, 1, 2):
            for b971d in (0, 1):
                for b5e95 in (0, 5, 6, 7):
                    for b971c in (0, 0x80):
                        st = dict(rpm=band_rpm, spd=30.0, q=1000.0, s65c5=s65c5, b65c0=b65c0, b971d=b971d,
                                  b971c=b971c, b5e95=b5e95, f65d0=0, b0=0, b1=1, b2=0)
                        got = run_03B668(rom, st)[0]
                        want = oracle(rom, tuned, st)[:3]
                        n += 1
                        check(got == want, f'{name} selector {st}: got {got} want {want}')
    say('    use b2 (0xFFFF7CBA) only when [65C5] != 1 and ([65C0]==1 or [971D]!=0) and ([5E95] in {5,7} or [971C]!=0)')
    # b0 clear condition vs q and odd source values
    for q in (0.0, 1259.0, 1260.0, 1261.0, 5000.0):
        for src in (0, 1, 2, 0xFF):
            for b0 in (0, 1):
                st = dict(rpm=6660.0 if not tuned else 6690.0, spd=30.0, q=q, s65c5=0, b65c0=0, b971d=0,
                          b971c=0, b5e95=0, f65d0=0, b0=b0, b1=src, b2=0)
                got = run_03B668(rom, st)[0]
                want = oracle(rom, tuned, st)[:3]
                n += 1
                check(got == want, f'{name} b0 rule {st}: got {got} want {want}')
    say(f'  b0 := 1 if source byte == 1; := 0 if [0x0CC518]={f32(rom, 0x0CC518)} > [0xFFFF620C]; else kept')
    say(f'  cases {n}; 0x0F1000 executed in {seen_entry[0x0F1000]} main-grid runs; '
        f'0x03B6BE (load of the 2nd resume value) executed in {seen_entry[0x03B6BE]}')
    if tuned:
        check(seen_entry[0x03B6BE] == 0, 'tuned: 0x03B6BE never executes')
        check(seen_entry[0x0F1000] == len(rpms) * len(spds) * 4, 'tuned: every run goes through 0x0F1000')
    else:
        check(seen_entry[0x0F1000] == 0, 'stock: 0x0F1000 never executes')
        check(seen_entry[0x03B6BE] > 0, 'stock: stationary pair is used')


# ------------------------------------------------------------------ the one rounding-dependent input
def test_rounding_edge(tuned):
    """fadd fr8,fr15 at 0x0F102E with fr8 = 2700.0: for rpm in [2048, 4096) the float spacing is
    2^-12 and the sum lies in [4096, 8192) where it is 2^-11, so a sum with the 2^-12 bit set is an
    exact tie. Only the tie at 6700 - 2^-12 and at 6680 - 2^-12 can move a compare."""
    say('== rounding edge: rpm one float below 4000 / 3980, offset active (tuned, spd 0) ==')
    u = 2.0 ** -12
    cut, res = f32(tuned, 0x0CC500), f32(tuned, 0x0CC504)
    check((cut, res, f32(tuned, 0x0CC510), f32(tuned, 0x0CC514)) == (6700.0, 6680.0, 6700.0, 6680.0), 'tuned pairs')

    def hyst(old, x):
        return 1 if not (cut > x) else (0 if res > x else old)
    rows = []
    for rpm in (3980.0 - 2 * u, 3980.0 - u, 3980.0, 4000.0 - 2 * u, 4000.0 - u, 4000.0):
        check(E.b2f(E.f2b(rpm)) == rpm, f'{rpm!r} is a float32')
        for start in (0, 1):
            for fl in (0, 1):
                st = dict(rpm=rpm, spd=0.0, q=1000.0, s65c5=0, b65c0=0, b971d=0, b971c=0, b5e95=0,
                          f65d0=fl, b0=start, b1=start, b2=start)
                got, at, _ = run_03B668(tuned, st)
                exact = Fraction(rpm) + 2700
                x_rz = E.b2f(E.rz_bits(exact))
                x_rn = struct.unpack('>f', struct.pack('>f', rpm + 2700.0))[0]   # round to nearest even
                check(at[0] == x_rz, f'emulated fr15 at 03B6C0 is the truncated sum ({rpm!r})')
                check(got[1:] == (hyst(start, x_rz),) * 2, f'edge rpm {rpm!r} start {start}: {got}')
                tie = rpm in (4000.0 - u, 3980.0 - u)
                check((hyst(start, x_rn) != hyst(start, x_rz)) == (tie and start == (0 if rpm > 3990 else 1)),
                      f'RNE/RTZ difference at {rpm!r} start {start}')
                if fl == 0:
                    rows.append(f'    rpm {rpm!r:20} start {start}: exact {float(exact)!r:18} RTZ x {x_rz!r:18} '
                                f'b1/b2 {got[1]} (emulated)   RNE x {x_rn!r:8} b1/b2 {hyst(start, x_rn)}')
    for r in rows:
        say(r)
    # exhaustive over every float32 rpm in [3900, 4096): S = (rpm + 2700) * 2^12 is an integer,
    # representable sums are the even S. RTZ keeps S & ~1; RNE breaks a tie to the even multiple of 2^-11.
    diff = set()
    for m in range(3900 * 4096, 4096 * 4096):
        S = m + 2700 * 4096
        rz = S & ~1
        rn = S if not S & 1 else (S + 1 if ((S + 1) >> 1) % 2 == 0 else S - 1)
        for start in (0, 1):
            a = 1 if rz >= 6700 * 4096 else (0 if rz < 6680 * 4096 else start)
            b = 1 if rn >= 6700 * 4096 else (0 if rn < 6680 * 4096 else start)
            if a != b:
                diff.add((m, start))
    # the integer model matches the emulator's rounding helper and struct (RNE) at the ties
    for m in (3999 * 4096 + 4095, 3979 * 4096 + 4095, 3950 * 4096 + 1, 3950 * 4096 + 3):
        S = m + 2700 * 4096
        check(E.b2f(E.rz_bits(Fraction(S, 4096))) == (S & ~1) / 4096, f'RTZ model at m={m}')
    check(diff == {(4000 * 4096 - 1, 0), (3980 * 4096 - 1, 1)},
          f'rounding-dependent inputs in [3900, 4096): {sorted(diff)}')
    say('  exhaustive over float32 rpm in [3900, 4096): RTZ and RNE disagree on b1/b2 ONLY for '
        'rpm = 4000-2^-12 from 0 (RTZ: stays 0, RNE: sets) and rpm = 3980-2^-12 from 1 (RTZ: clears, RNE: holds)')


def test_oracle_compare(tuned):
    """scripts/patch_emulate.py launch_oracle (gate 8) against this file's unstubbed emulation.
    Asserts the state of patch_emulate.py as read on 2026-11-27: if it changes, re-check K4."""
    say('== comparison with scripts/patch_emulate.py launch_oracle (tuned) ==')
    import patch_emulate as P
    K = f32(tuned, 0x0F104C)
    u = 2.0 ** -12
    edge = (4000.0 - u, 3980.0 - u)
    spds = [0.0, 5.0, 8.05, nextf(K, -1), K, nextf(K, +1), 30.0]
    rpms = [3979.0, 3980.0 - u, 3980.0, 3990.0, 3999.9, 4000.0 - u, 4000.0, 4010.0, 6679.0, 6680.0, 6700.0]
    n, dis = 0, []
    for spd in spds:
        for fl in (0, 1, 0x81):
            for rpm in rpms:
                for prior in (0, 1):
                    st = dict(rpm=rpm, spd=spd, q=1000.0, s65c5=0, b65c0=0, b971d=0, b971c=0, b5e95=0,
                              f65d0=fl, b0=0, b1=prior, b2=prior)
                    got = run_03B668(tuned, st)[0]
                    want = P.launch_oracle(tuned, dict(speed=spd, flag_65d0=fl, rpm=rpm, prior=prior, path='A'))
                    n += 1
                    if (got[1], got[2]) != (want[B1], want[B2]):
                        active = (spd < K) if fl == 1 else not (spd > K)
                        dis.append((spd, fl, rpm, prior, active))
    check(n == 462, 'oracle grid size')
    check(all(r in edge and act for _, _, r, _, act in dis), f'disagreement outside the tie inputs: {dis[:4]}')
    check(len(dis) == 28, f'{len(dis)} disagreements (28 when read)')
    # gate 8's own setup (stubs 0x022CF4/0x0299AC/0x0299BC/0x0BE608, fixed selector bytes) at the ties
    for rpm, prior in ((edge[0], 0), (edge[1], 1)):
        p = dict(speed=0.0, flag_65d0=0, rpm=rpm, prior=prior, path='A')
        emu = E.Emu(tuned)
        P.launch_setup(emu, p)
        emu.call(0x03B668, stop_at={0x03D2FC})
        want = P.launch_oracle(tuned, p)
        # 4000-2^-12 from 0: emulator keeps 0, oracle sets 1; 3980-2^-12 from 1: emulator clears, oracle holds 1
        check((emu.read_u8(B1), want[B1]) == (0, 1),
              f'gate-8 setup at rpm {rpm!r}: emu {emu.read_u8(B1)} oracle {want[B1]}')
    check(P.r32(6700.0 - u) == 6700.0, 'launch_oracle r32 rounds the tie to nearest')
    check(set(P.launch_oracle(tuned, dict(speed=0.0, flag_65d0=0, rpm=4000.0, prior=0, path='A'))) == {B1, B2},
          'launch_oracle asserts only 0xFFFF7CB9 / 0xFFFF7CBA')
    say(f'  {n} cases, {len(dis)} disagree -- all at rpm in {{4000-2^-12, 3980-2^-12}} with the offset active; '
        f'gate 8 setup at those two inputs: emulator 0, oracle 1')


# ------------------------------------------------------------------ audit pass (independent, 2026-11-27)
def audit_oracle(rom, tuned, st):
    """A second oracle, written by the audit pass from its own reading of the listings (not from
    oracle() above): T-bit senses as the fcmp words give them, the fadd rounded as the emulator
    rounds it (toward zero), and every byte sign-/zero-extended exactly as the instruction does."""
    def i8(v):
        return v - 256 if v & 0x80 else v
    rpm, spd, q = st['rpm'], st['spd'], st['q']
    if tuned:
        K = f32(rom, 0x0F104C)
        if i8(st['f65d0']) == 1:                                        # 0F100A mov.b (sign-extends)
            add = f32(rom, 0x0F1050) if K > spd else f32(rom, 0x0F1054)  # 0F1012 F695: T = fr6 > fr9
        else:
            add = f32(rom, 0x0F1048) if spd > K else f32(rom, 0x0F1050)  # 0F101E F965: T = fr9 > fr6
        if math.isfinite(rpm) and add != 0.0:
            x = E.b2f(E.rz_bits(Fraction(rpm) + Fraction(add)))
        else:
            x = rpm + add
        cut, res = f32(rom, 0x0CC500), f32(rom, 0x0CC504)
    else:
        x = rpm
        outside = (-1.0 > spd) or (spd > 1.0)                            # 0BE60C F345 / 0BE616 F435
        cut, res = ((f32(rom, 0x0CC500), f32(rom, 0x0CC504)) if outside
                    else (f32(rom, 0x0CC508), f32(rom, 0x0CC50C)))

    def h(old, c, r):
        return 1 if not (c > x) else (0 if r > x else old)              # 03B6C0 F8F5 / 03B6CC F6F5
    b1 = h(st['b1'], cut, res)
    b2 = h(st['b2'], f32(rom, 0x0CC510), f32(rom, 0x0CC514))
    if i8(st['s65c5']) == 1:                                            # 022CF6 mov.b, cmp/eq #1
        src = b1
    else:
        p1 = (st['b65c0'] & 0xFF) == 1 or st['b971d'] != 0              # 03B6FA extu.b; 0299B0 tst
        p2 = (st['b5e95'] & 0xFF) in (5, 7) or st['b971c'] != 0         # 03B706 extu.b; 0299C0 tst
        src = b2 if (p1 and p2) else b1
    b0 = 1 if src == 1 else (0 if f32(rom, 0x0CC518) > q else st['b0'])  # 03B730 F8C5: T = fr8 > fr12
    return b0, b1, b2, x


def _same(a, b):
    return a == b or (math.isnan(a) and math.isnan(b))


def test_audit_grid(rom, tuned):
    """Inputs the earlier grids do not use: x = NaN / +-inf / negative / 1e9, speed at the NEGATIVE
    window edge, -0.0, NaN, +-inf, flag byte 0x81 / 0xFF, start states 2 / 0xFF / b1 != b2, q = NaN;
    then the selector bytes with the high bit set."""
    name = 'tuned' if tuned else 'stock'
    inf, nan = float('inf'), float('nan')
    rpms = [-500.0, -inf, inf, nan, 3990.0, 6660.0, 6690.0, 1.0e9]
    spds = [-1.0, nextf(1.0, +1) * -1.0, -0.0, nan, inf, -inf, 8.0, 8.1]
    n = 0
    for rpm in rpms:
        for spd in spds:
            for fl in ((0x81, 0xFF, 0x01, 0x00) if tuned else (0,)):
                for b0, b1, b2 in ((0, 0, 0), (2, 2, 2), (0xFF, 0xFF, 0xFF), (1, 0, 1), (0, 1, 0)):
                    for q in (nan, 1259.0, 1260.0):
                        st = dict(rpm=rpm, spd=spd, q=q, s65c5=0, b65c0=0, b971d=0, b971c=0, b5e95=0,
                                  f65d0=fl, b0=b0, b1=b1, b2=b2)
                        got, at, _ = run_03B668(rom, st)
                        want = audit_oracle(rom, tuned, st)
                        n += 1
                        check(got == want[:3], f'audit {name} {st}: got {got} want {want[:3]}')
                        check(_same(at[0], want[3]), f'audit {name} fr15 {st}: {at[0]!r} want {want[3]!r}')
    m = 0
    band = 6690.0 if tuned else 6660.0
    for s65c5 in (0x81, 0x01, 0xFF, 0x00):
        for b65c0 in (0x81, 0x01, 0x00, 0xFF):
            for b971d in (0x80, 0x00, 0xFF):
                for b5e95 in (0x85, 0x87, 0x05, 0x07, 0xFF):
                    for b971c in (0xFF, 0x00, 0x01):
                        st = dict(rpm=band, spd=30.0, q=1000.0, s65c5=s65c5, b65c0=b65c0, b971d=b971d,
                                  b971c=b971c, b5e95=b5e95, f65d0=0, b0=0, b1=1, b2=0)
                        got = run_03B668(rom, st)[0]
                        m += 1
                        check(got == audit_oracle(rom, tuned, st)[:3], f'audit {name} selector {st}: {got}')
    say(f'== audit grid ({name}): {n} new-input cases + {m} high-bit selector cases agree with the audit oracle ==')


class ReadAll(E.Emu):
    """Emu that records every RAM byte read outside the stack."""
    def read(self, a, n):
        a &= 0xFFFFFFFF
        if a >= 0xFFFF0000 and not (self.stack_low - 64 <= a < E.STACK_TOP):
            self.rd.update(range(a, a + n))
        return super().read(a, n)


def test_audit_readset(rom, tuned):
    """The complete RAM read set of 0x03B668 .. 0x03D2FC (stack excluded), over every selector
    branch and both window outcomes: exactly the inputs the 0x03B668 CONTRACT lists."""
    name = 'tuned' if tuned else 'stock'
    seen = set()
    for spd in (0.0, 30.0):
        for s65c5, b65c0, b971d, b5e95 in ((0, 1, 0, 5), (1, 0, 0, 0), (0, 0, 1, 0), (0, 0, 0, 0), (0, 1, 0, 0)):
            emu = ReadAll(rom)
            emu.rd = set()
            for a, v in ((RPM, 6690.0), (SPD, spd), (Q620C, 1000.0)):
                emu.ram_f32(a, v)
            for a, v in ((SEL65C5, s65c5), (B65C0, b65c0), (B971D, b971d), (B971C, 0), (B5E95, b5e95),
                         (F65D0, 0), (B0, 0), (B1, 1), (B2, 0)):
                emu.ram_u8(a, v)
            emu.rd = set()
            emu.call(0x03B668, stop_at={0x03D2FC})
            seen |= emu.rd
    want = set()
    for a in (RPM, SPD, Q620C):
        want |= set(range(a, a + 4))
    want |= {SEL65C5, B65C0, B971D, B971C, B5E95, B1, B2} | ({F65D0} if tuned else set())
    check(seen == want, f'audit {name} read set: extra {sorted(hex(a) for a in seen - want)} '
                        f'missing {sorted(hex(a) for a in want - seen)}')
    say(f'  audit read set ({name}) 0x03B668..0x03D2FC: ' + ' '.join(f'{a:08X}' for a in sorted(seen))
        + '  (0xFFFF7CB8 is written, never read, on this path)')


def test_audit_pr(tuned):
    """pr when the host enters the patch: the return address of the last jsr (0x0BE608 at 0x03B6A4),
    NOT the caller's return address, which sits on the stack (0x03B66C) until 0x03B742."""
    for spd in (0.0, 30.0):                      # inside / outside the window: 0x03B6BA / 0x03B6B0
        emu = E.Emu(tuned)
        emu.ram_f32(RPM, 3000.0)
        emu.ram_f32(SPD, spd)
        emu.ram_f32(Q620C, 1000.0)
        for a in (SEL65C5, B65C0, B971D, B971C, B5E95, F65D0, B0, B1, B2):
            emu.ram_u8(a, 0)
        res = emu.call(0x03B668, stop_at={0x0F1000})
        check(res == 0x0F1000 and emu.pr == 0x03B6A8, f'pr at 0x0F1000 entry {emu.pr:#x} (spd {spd})')
        check(emu.read_u32(E.STACK_TOP - 12) == E.RETURN_MAGIC, 'caller return address saved at 0x03B66C')
        while emu.pc != 0x03D2FC:
            emu.step()
        check(emu.pr == E.RETURN_MAGIC, 'pr restored by 0x03B742 before the tail-jump')
    say('  audit: pr at 0x0F1000 entry = 0x03B6A8 (both window outcomes); 0x03B742 restores the caller\'s pr')


def test_audit_gate(rom, name):
    """0x04AA58 calls 0x03B668 and 0x049BA4 calls 0x03B74A only when int8 [0xFFFF8EDC] == 0."""
    pre_a = [0x022E36, 0x01CF80, 0x01FCF0, 0x01FE46, 0x023D60, 0x023BA4, 0x024C6C, 0x0263F6, 0x0303C0]
    pre_b = [0x01FA9C, 0x01FAFC, 0x0207D0, 0x020E4E, 0x021B64, 0x0240C8, 0x024DC6, 0x022742, 0x03AB06, 0x03AB94]
    row = []
    for entry, pre, target, exit_pc in ((0x04AA58, pre_a, 0x03B668, 0x04AE62), (0x049BA4, pre_b, 0x03B74A, 0x049CE8)):
        for v in (0x00, 0x01, 0x80, 0xFF):
            emu = E.Emu(rom)
            for a in pre:
                emu.stub(a, r0=0)
            emu.ram_u8(0xFFFF8EDC, v)
            res = emu.call(entry, regs={4: 2}, stop_at={target})
            if v == 0:
                check(res == target, f'{name} {entry:06X} [8EDC]=0 reaches {target:06X}')
            else:
                check(res == 'return' and exit_pc in emu.executed and emu.writes == {}
                      and not any(a in emu.executed for a in pre),
                      f'{name} {entry:06X} [8EDC]={v:#x}: returns at {exit_pc:06X}, nothing called or written')
            row.append(f'{entry:06X}/[8EDC]={v:#04x}:{"call" if res == target else "skip"}')
    say(f'  audit gate ({name}): ' + ' '.join(row))


def test_026CF4(rom, name):
    """The consumer of getter 0x03B76E: byte [0xFFFF7CB8] == 1 makes 0x026CF4 clear bit 5 of byte
    [0xFFFF6A29] (GBR 0xFFFF6A29, and.b #223,@(r0,gbr) with r0 = 0); with every other condition met
    and b0 != 1 it sets the bit (or.b #32)."""
    def run(b0, over=None):
        emu = E.Emu(rom)
        st = {0xFFFF726C: 0, 0xFFFF7C9D: 0, 0xFFFF970B: 0, 0xFFFF69E8: 1, 0xFFFF6A51: 1, 0xFFFF6A4D: 1,
              0xFFFF6A4E: 1, 0xFFFF6A29: 0x00, B0: b0}
        fl = {0xFFFF6350: 20.0, 0xFFFF798C: 1.0, 0xFFFF6898: 600.0, Q620C: 800.0, 0xFFFF6354: 50.0}
        for k, v in (over or {}).items():
            (fl if isinstance(v, float) else st)[k] = v
        for a, v in st.items():
            emu.ram_u8(a, v)
        for a, v in fl.items():
            emu.ram_f32(a, v)
        emu.ram_u16(0xFFFF67EA, 100)
        res = emu.call(0x026CF4, regs={k: 0x4000 + k for k in range(15)})
        check(res == 'return', '026CF4 returns')
        check(set(emu.writes) == {0xFFFF6A29}, f'026CF4 writes only 0xFFFF6A29: {sorted(map(hex, emu.writes))}')
        return emu.read_u8(0xFFFF6A29)
    check((f32(rom, 0x0C4200), rom[0x0C41D2], f32(rom, 0x0C4204)) == (-40.0, 0, 120.0), '026CF4 cal values')
    out = {}
    for b0 in (0, 1, 2, 0xFF):
        out[b0] = (run(b0), run(b0, {0xFFFF6A29: 0xFF & ~0x80}), run(b0, {0xFFFF6354: 130.0}))
        want_set = b0 != 1
        check(out[b0][0] == (0x20 if want_set else 0x00), f'026CF4 b0={b0}: [6A29] {out[b0][0]:#x}')
        check(out[b0][1] == (0x7F if want_set else 0x5F), f'026CF4 b0={b0} from 0x7F: {out[b0][1]:#x}')
        check(out[b0][2] == (0x20 if want_set else 0x00), f'026CF4 b0={b0} [6354]=130: {out[b0][2]:#x}')
    # with b0 == 1 the bit is cleared whatever the other inputs are
    for over in ({0xFFFF6A4D: 0}, {0xFFFF726C: 1}, {0xFFFF6350: -50.0}, {0xFFFF6A29: 0xA0}, {0xFFFF798C: 0.0}):
        check(run(1, over) & 0x20 == 0, f'026CF4 b0=1 {over}: bit 5 not cleared')
    say(f'  audit 0x026CF4 ({name}): [0xFFFF7CB8]=1 -> bit 5 of [0xFFFF6A29] cleared; b0 != 1 with the other '
        f'conditions met -> set ({ {k: tuple(hex(x) for x in v) for k, v in out.items()} })')


def test_oracle_0F1048_gap(tuned):
    """scripts/patch_emulate.py:83 hard-codes 0.0 for the byte != 1, speed > K branch instead of
    reading [0x0F1048]. Equal in 20.19c (0.0); on a modified in-memory copy the oracle is wrong."""
    import patch_emulate as P
    mut = bytearray(tuned)
    mut[0x0F1048:0x0F104C] = struct.pack('>f', 111.0)
    mut = bytes(mut)
    st = dict(rpm=6600.0, spd=30.0, q=1000.0, s65c5=0, b65c0=0, b971d=0, b971c=0, b5e95=0,
              f65d0=0, b0=0, b1=0, b2=0)
    got = run_03B668(mut, st)[0]
    want = P.launch_oracle(mut, dict(speed=30.0, flag_65d0=0, rpm=6600.0, prior=0, path='A'))
    check(got[1:] == (1, 1) and (want[B1], want[B2]) == (0, 0),
          f'0x0F1048 gap: emulator {got[1:]} oracle {(want[B1], want[B2])}')
    check(audit_oracle(mut, True, st)[:3] == got, 'audit oracle follows [0x0F1048]')
    mut2 = bytearray(tuned)
    mut2[0x0F1054:0x0F1058] = struct.pack('>f', 111.0)
    mut2 = bytes(mut2)
    st2 = dict(st, f65d0=1)
    got2 = run_03B668(mut2, st2)[0]
    want2 = P.launch_oracle(mut2, dict(speed=30.0, flag_65d0=1, rpm=6600.0, prior=0, path='A'))
    check(got2[1:] == (want2[B1], want2[B2]) == (1, 1), 'oracle does read [0x0F1054]')
    say('  audit: launch_oracle ignores [0x0F1048] (hard-coded 0.0, patch_emulate.py:83) but reads [0x0F1054]; '
        'with [0x0F1048] = 111 at x = 6600, speed 30: emulator sets b1/b2, oracle does not')


def audit_base_scan(tuned):
    """Every mov.l @(disp,PC),Rn in 0x000000..0x0EFFFF whose literal is a RAM base within 60 bytes
    below 0xFFFF7CBA (the reach of mov.l @(disp,Rn); byte forms reach 15), then every @(d,Rn), @Rn
    and @(r0,Rn) (r0 from a preceding mov #imm) in the straight-line code after it, through the
    delay slot of the first delayed branch, until Rn is rewritten. Linear, not a CFG walk: a lower
    bound (it misses 0x03B736, reached from 0x03B71C only past a branch). find_writers.py --reads
    reports no read of 0xFFFF7CB9 at all although 0x03B71E reads it, so it is not used here."""
    T = {B0, B1, B2}
    hits, nload = set(), 0

    def eas(t, r, L, r0):
        out = []
        for m in re.finditer(rf'@\((\d+),{r}\)', t):
            sz = {'b': 1, 'w': 2, 'l': 4}.get(t.split()[0].split('.')[-1][:1], 1)
            out += [ea for ea in range(L + int(m.group(1)), L + int(m.group(1)) + sz) if ea in T]
        if re.search(rf'(^|,)@{r}($|,)', t.partition(' ')[2]) and L in T:
            out.append(L)
        if re.search(rf'@\(r0,{r}\)', t) and r0 is not None and L + r0 in T:
            out.append(L + r0)
        return out
    for pc in range(0, 0x0F0000, 2):
        w = (tuned[pc] << 8) | tuned[pc + 1]
        if w >> 12 != 0xD:
            continue
        L = u32(tuned, ((pc + 4) & ~3) + (w & 0xFF) * 4)
        if not (B2 - 60 <= L <= B2):
            continue
        nload += 1
        r, r0 = f'r{(w >> 8) & 15}', None
        for a in range(pc + 2, pc + 122, 2):
            t = _dec(tuned, a)
            mi = re.match(r'mov #(-?\d+),r0$', t)
            if mi:
                r0 = int(mi.group(1))
            for ea in eas(t, r, L, r0):
                hits.add((a, ea))
            mn = t.split()[0]
            if mn in ('rts', 'jmp', 'bra', 'bsr', 'jsr', 'braf', 'bsrf', 'rte'):
                for ea in eas(_dec(tuned, a + 2), r, L, r0):
                    hits.add((a + 2, ea))
                break
            ops = t.partition(' ')[2].split(',')
            if ops and ops[-1] == r and not mn.startswith(('cmp', 'tst')) and not re.match(r'mov\.[bwl] r\d+,@', t):
                break
    want = {(0x03AAAE, B0), (0x03B6CA, B1), (0x03B6D4, B1), (0x03B6E4, B2), (0x03B6F2, B2), (0x03B71A, B2),
            (0x03B71E, B1), (0x03B72A, B0), (0x03B75C, B0), (0x03B75E, B1), (0x03B760, B2), (0x03B770, B0),
            (0x03D324, B0)}
    check(hits == want, f'base scan hits {sorted((hex(a), hex(e)) for a, e in hits ^ want)}')
    check(nload == 67, f'{nload} loaders of a base within 60 bytes below 0xFFFF7CBA')
    readers = sorted(a for a, e in hits if e in (B1, B2) and not (0x03B6B2 <= a < 0x03B76E))
    check(readers == [], f'7CB9/7CBA touched outside 0x03B6B2..0x03B76D: {readers}')
    say(f'  audit base scan: {nload} literal bases within 60 bytes below 0xFFFF7CBA; 0xFFFF7CB9/7CBA are touched only '
        f'inside 0x03B6B2..0x03B760 (read only at 0x03B71A / 0x03B71E); 0xFFFF7CB8 also read at 0x03AAAE, 0x03B770, 0x03D324')


# ------------------------------------------------------------------ resets and consumers
def test_03B74A(rom, name):
    say(f'== 0x03B74A ({name}) ==')
    for v in (0, 1, 2):
        emu = E.Emu(rom)
        emu.ram_u8(0xFFFF65F6, v)
        for a in (B0, B1, B2):
            emu.ram_u8(a, 1)
        res = emu.call(0x03B74A, stop_at={0x03D2FC})
        out = tuple(emu.read_u8(a) for a in (B0, B1, B2))
        say(f'  [65F6]={v}: end={res if res == "return" else hex(res)} flags={out}')
        if v == 1:
            check(res == 0x03D2FC and out == (0, 0, 0) and emu.pr == E.RETURN_MAGIC, '03B74A clear path')
        else:
            check(res == 'return' and out == (1, 1, 1), '03B74A no-op path')


class ReadTrack(E.Emu):
    """Emu that records every read of the flag workspace 0xFFFF7C90..0xFFFF7D80 and 0xFFFFA17E..A181."""
    def read(self, a, n):
        a &= 0xFFFFFFFF
        if 0xFFFF7C90 <= a <= 0xFFFF7D80 or 0xFFFFA17E <= a <= 0xFFFFA181:
            self.rd.add(a)
        return super().read(a, n)


ALL_BYTES = [0xFFFF7CB8, 0xFFFF7CBC, 0xFFFF7CD5, 0xFFFF7CE8, 0xFFFF7CF4, 0xFFFF7D48]
GROUPS = [[0xFFFF7CA3 + k, 0xFFFF7CE1 + k, 0xFFFF7CFA + k, 0xFFFF7D14 + k, 0xFFFF7D2F + k, 0xFFFF7D4D + k]
          for k in range(4)]


def run_03D2FC(rom, flags):
    emu = ReadTrack(rom)
    emu.rd = set()
    emu.stub(0x00317C, r0=0x00)              # critical-section enter (ldc sr not emulated)
    emu.stub(0x003190)                       # leave
    for a in list(range(0xFFFF7CA0, 0xFFFF7D60)) + [0xFFFFA17E, 0xFFFFA17F, 0xFFFFA180, 0xFFFFA181]:
        emu.ram_u8(a, 0)
    for a, v in flags.items():
        emu.ram_u8(a, v)
    res = emu.call(0x03D2FC)
    check(res == 'return', '03D2FC did not return')
    code_reads = set(emu.rd)                 # reads made by the code; the test's own read of the mask follows
    mask = emu.read_u16(MASK)
    emu.rd = code_reads
    return mask, emu


def test_03D2FC(rom, name):
    say(f'== 0x03D2FC ({name}): mask word 0xFFFF7D80 ==')
    cases = [
        ({}, 0x0000),
        ({B0: 1}, 0xFFFF),
        ({B0: 2}, 0x0000),
        ({B1: 1, B2: 1}, 0x0000),          # the two hysteresis bytes are not read here
        ({0xFFFF7CBC: 1}, 0xFFFF),
        ({0xFFFF7CA3: 1}, 0x0001), ({0xFFFF7CA4: 1}, 0x0002), ({0xFFFF7CA5: 1}, 0x0004), ({0xFFFF7CA6: 1}, 0x0008),
        ({0xFFFFA17E: 1}, 0x0001), ({0xFFFFA181: 3}, 0x0008), ({0xFFFFA17F: 2}, 0x0000),
        ({0xFFFF7CA3: 1, 0xFFFF7D50: 1}, 0x0009),
        ({B0: 1, 0xFFFF7CA3: 1}, 0xFFFF),
    ]
    for fl, want in cases:
        got, emu = run_03D2FC(rom, fl)
        say(f'  {dict((hex(a), v) for a, v in fl.items())} -> {got:#06x}')
        check(got == want, f'03D2FC {fl}: got {got:#06x} want {want:#06x}')
        check(set(emu.writes) <= {MASK, MASK + 1}, '03D2FC writes only the mask')
    # review: the read set on the all-clear path, and every one of the 30 bytes on its own
    _, emu = run_03D2FC(rom, {})
    flag_reads = sorted(a for a in emu.rd if a < 0xFFFFA000)
    want_set = sorted(ALL_BYTES + [a for g in GROUPS for a in g])
    check(flag_reads == want_set, f'03D2FC read set {[hex(a) for a in flag_reads]}')
    check(sorted(a for a in emu.rd if a >= 0xFFFFA000) == [0xFFFFA17E, 0xFFFFA17F, 0xFFFFA180, 0xFFFFA181],
          '03D2FC helper bytes')
    for a in ALL_BYTES:
        check(run_03D2FC(rom, {a: 1})[0] == 0xFFFF, f'03D2FC {a:#x} alone -> 0xFFFF')
    for k, g in enumerate(GROUPS):
        for a in g:
            check(run_03D2FC(rom, {a: 1})[0] == 1 << k, f'03D2FC {a:#x} alone -> bit {k}')
    say(f'  all-clear path reads {len(flag_reads)} flag bytes (6 force 0xFFFF, 4 groups of 6 -> bits 0..3) '
        f'+ bit 0 of 0xFFFFA17E..A181; each of the 30 alone gives its effect')


def test_03DCB6(rom, name):
    say(f'== 0x03DCB6 ({name}): channel gate on 0xFFFF7D80 ==')
    check(rom[0x063DDC:0x063DFC] == b''.join(struct.pack('>H', 1 << i) for i in range(16)), 'table 0x063DDC = 1 << i')
    check(rom[0x063E30:0x063E3C].hex() == '000102030101010100' + '0adf5c', 'tables 0x063E30 / 0x063E34')
    for mask in (0x0000, 0x0001, 0x0004, 0x00F0, 0xFFFF):
        row = []
        for ch in range(8):
            emu = E.Emu(rom)
            calls, calls7 = [], []
            emu.stub(0x009C00, fn=lambda e, c=calls: c.append((e.R[4], e.R[5])))
            emu.stub(0x07CB28, fn=lambda e, c=calls7: c.append((e.R[4], e.fr(4))))
            emu.ram_u16(MASK, mask)
            emu.ram_u8(0xFFFF7E50, 0)
            emu.call(0x03DCB6, regs={4: ch}, fregs={4: 1000.0})
            bit_clear = not (mask >> ch) & 1
            gate = rom[0x063E34 + ch] == 1          # 0x03DCFC..0x03DD00: int8 [0x063E34 + ch] == 1
            want = [(rom[0x063E30 + ch], 4000)] if bit_clear and gate else []
            check(calls == want, f'03DCB6 mask {mask:#06x} ch {ch}: 0x009C00 calls {calls} want {want}')
            check(calls7 == ([(ch, 1000.0)] if bit_clear else []), f'03DCB6 mask {mask:#06x} ch {ch}: 0x07CB28 {calls7}')
            check(emu.read_u8(0xFFFF7E50) == (1 if bit_clear else 0), f'03DCB6 ch {ch}: 0x03DD46 sets 0xFFFF7E50')
            row.append(('9C00+' if calls else '') + ('7CB28' if calls7 else 'skip'))
        say(f'  mask {mask:#06x}: ch0..7 -> {row}')
    say('  bit set -> return at once; bit clear -> 0x009C00 (r4 = byte 0x063E30[ch], r5 = trunc(fr4 / 0.25)) only if '
        'byte 0x063E34[ch] == 1 (ch 0..3), then 0x03DD46 (byte 0xFFFF7E50 = 1) and 0x07CB28 (r4 = ch, fr4)')


def test_015624(rom, name):
    say(f'== 0x015624 ({name}): set-bit count of 0xFFFF7D80 ==')
    for mask, want in ((0x0000, (0, 0)), (0x0001, (0, 0)), (0x0003, (0, 1)), (0x0007, (0, 1)),
                       (0x000F, (1, 0)), (0xFFFF, (1, 0)), (0x8001, (0, 1))):
        emu = E.Emu(rom)
        emu.ram_u16(MASK, mask)
        emu.call(0x015624)
        got = (emu.read_u8(0xFFFF5DDD), emu.read_u8(0xFFFF5DDE))
        say(f'  {mask:#06x} -> [5DDD],[5DDE] = {got}')
        check(got == want, f'015624 {mask:#06x}: got {got} want {want}')


def test_016102(rom, name):
    say(f'== 0x016102 ({name}): the other reader of 0x0CC504 ==')
    res_v = f32(rom, 0x0CC504)
    for rpm in (res_v - 1.0, res_v, res_v + 1.0):
        for a, c, b6155 in ((0, 0, 0), (1, 0, 0), (0, 1, 0), (0, 0, 1)):
            emu = E.Emu(rom)
            emu.stub(0x058524, r0=a)
            emu.stub(0x02B220, r0=c)
            emu.ram_f32(RPM, rpm)
            emu.ram_u8(0xFFFF6155, b6155)
            emu.call(0x016102)
            got = emu.read_u8(0xFFFF5D85)
            want = int(a == 0 and c == 0 and res_v > rpm and b6155 == 0)
            check(got == want, f'016102 rpm {rpm} a {a} c {c} 6155 {b6155}: {got} want {want}')
    say(f'  [5D85] = 1 iff 0x058524()==0 and 0x02B220()==0 and [0x0CC504]={res_v} > [0xFFFF6624] and [6155]==0')


def main():
    stock, tuned = load(STOCK), load(TUNED)
    static_facts(stock, tuned)
    gbr_scan(tuned)
    test_patch(tuned)
    test_rounding_edge(tuned)
    test_oracle_compare(tuned)
    test_audit_pr(tuned)
    test_oracle_0F1048_gap(tuned)
    audit_base_scan(tuned)
    for rom, tuned_flag, name in ((stock, False, 'stock'), (tuned, True, 'tuned')):
        test_03B668(rom, tuned_flag)
        test_audit_grid(rom, tuned_flag)
        test_audit_readset(rom, tuned_flag)
        test_audit_gate(rom, name)
        test_03B74A(rom, name)
        test_03D2FC(rom, name)
        test_03DCB6(rom, name)
        test_015624(rom, name)
        test_016102(rom, name)
        test_026CF4(rom, name)
    print(f'checks: {checks}  failures: {len(fails)}')
    for f in fails[:30]:
        print('  FAIL', f)
    sys.exit(1 if fails else 0)


if __name__ == '__main__':
    main()
