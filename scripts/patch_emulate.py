#!/usr/bin/env python3
"""Flash-safety gate 8: run a patch in the SH-2E emulator over a grid and compare with an oracle.

    python3 scripts/patch_emulate.py --live            # every docs/patch-specs/*.json with an oracle
    python3 scripts/patch_emulate.py SPEC.json BIN     # one spec against one bin

An ORACLE is a Python function written from the patch's DOCUMENTED behaviour (its doc
and plan), never from the emulator or from its own code. It takes one grid point and
the ROM (for calibration DATA only) and returns the expected RAM outputs. The emulator
runs the real bytes; any disagreement is a FAIL. Oracles live in ORACLES below, keyed by
spec id, so that a new patch's plan must state its behaviour precisely enough to write one.

A run also fails if the code reads RAM the case did not set (a forgotten input), writes
RAM outside the spec's declared outputs, or the emulator raises (illegal instruction,
misaligned access, write to ROM, unmapped address, decoder disagreement).
"""
import argparse
import itertools
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import sh2e_emu as E  # noqa: E402


def f32(rom, a):
    return struct.unpack('>f', rom[a:a + 4])[0]


def r32(x):
    return E.b2f(E.f2b(x))


# ------------------------------------------------------------------ launch control
# Written from docs/rev-limit-patch.md ("The injected code", "The three rev-limit pairs"):
#   flag == 1 :  speed < threshold  -> +LC delta (0xF1050), else +FFS delta (0xF1054)
#   flag != 1 :  speed > threshold  -> +0.0 (0xF1048),     else +LC delta
#   eff = rpm + offset (float32)
#   stage 1 (flag byte 0xFFFF7CB9): set if eff >= cut 0xCC500; else clear if eff < resume
#            0xCC504; else hold.  Pair 2 (0xCC508/0xCC50C) is dead: both paths use pair 1.
#   stage 2 (flag byte 0xFFFF7CBA): the same with 0xCC510 / 0xCC514, also on eff.
LAUNCH_GRID = {
    # 'thr' = the exact stored threshold (0x0F104C): the only speed where the two flag
    # branches differ (rev-limit-patch.md: "only the boundary at exactly 5 mph differs")
    'speed': [0.0, 5.0, 8.05, 'thr', 8.06, 30.0],
    'flag_65d0': [0, 1],
    'rpm': [3990.0, 3999.9, 4000.0, 4010.0, 6679.0, 6680.0, 6690.0, 6700.0, 6710.0],
    'prior': [0, 1],
    'path': ['A', 'B'],
}


def _speed(rom, p):
    return f32(rom, 0x0F104C) if p['speed'] == 'thr' else p['speed']


def launch_setup(emu, p):
    emu.ram_f32(0xFFFF6624, p['rpm'])          # fr15 rpm
    emu.ram_f32(0xFFFF65FC, _speed(emu.rom, p))  # fr14 vehicle speed (km/h)
    emu.ram_f32(0xFFFF620C, 100.0)             # fr12 manifold pressure (only gates byte +0)
    emu.ram_u8(0xFFFF65C0, 0)                  # r13
    emu.ram_u8(0xFFFF65D0, p['flag_65d0'])     # the patch's state flag
    emu.ram_u8(0xFFFF7CB8, 0)
    emu.ram_u8(0xFFFF7CB9, p['prior'])
    emu.ram_u8(0xFFFF7CBA, p['prior'])
    rb = emu.rom
    emu.ram_u8(int.from_bytes(rb[0x03B794:0x03B798], 'big'), 0)   # r14 source byte
    emu.stub(0x022CF4, r0=0)
    emu.stub(0x0299AC, r0=0)
    emu.stub(0x0299BC, r0=0)
    emu.stub(0x0BE608, r0=1 if p['path'] == 'A' else 0)          # nonzero -> pair A


def launch_oracle(rom, p):
    thr, spd = f32(rom, 0x0F104C), r32(_speed(rom, p))
    if p['flag_65d0'] == 1:
        off = f32(rom, 0x0F1050) if thr > spd else f32(rom, 0x0F1054)
    else:
        off = 0.0 if spd > thr else f32(rom, 0x0F1050)
    eff = r32(r32(p['rpm']) + r32(off))

    def stage(cut, res):
        if eff >= f32(rom, cut):
            return 1
        if eff < f32(rom, res):
            return 0
        return p['prior']
    return {0xFFFF7CB9: stage(0x0CC500, 0x0CC504), 0xFFFF7CBA: stage(0x0CC510, 0x0CC514)}


# ------------------------------------------------------------------ valet limiter
# Written from docs/plans/valet-limiter.md (Design, Activation, Acceptance criteria).
#   ON  <=> state+0 == 0xA5 AND state+1 == 0x5A; anything else is OFF.
#   ON  : offset = max(launch offset, [0xCC500] - VALET_LIMIT)   (LIVE)
#         offset = launch offset                                 (SHADOW: limiter unchanged)
#         state+3 = 1 in both; OFF: state+3 = 0
#   hold: CANCEL pressed AND speed < MAX_SPEED AND not latched -> counter += 1 per host call;
#         at HOLD_TICKS -> toggle (OFF/garbage -> A5 5A, ON -> 00 00), latch, counter = 0.
#         released -> latch = 0, counter = 0.  moving while pressed -> counter = 0, latch kept.
# Placeholders are taken from the build script, so the oracle follows a settled value.
def _valet_build():
    sys.path.insert(0, os.path.join(HERE, 'patchbuild'))
    import valet_limiter as V
    return V


def valet_grid(mode):
    g = dict(LAUNCH_GRID)
    g['flag'] = ['on', 'off', 'a500', 'ffff']
    return g


VALET_FLAGS = {'on': (0xA5, 0x5A), 'off': (0, 0), 'a500': (0xA5, 0x00), 'ffff': (0xFF, 0xFF)}


def valet_setup(emu, p):
    V = _valet_build()
    launch_setup(emu, p)
    st = V.PLACEHOLDERS['STATE'][0]
    a, b = VALET_FLAGS[p['flag']]
    for i, v in enumerate((a, b, 0, 0)):
        emu.ram_u8(st + i, v)
    emu.ram_f32(st + 4, 0.0)
    emu.ram_u8(V.PLACEHOLDERS['BUTTON'][0], 0)


def valet_oracle_for(mode):
    def oracle(rom, p):
        V = _valet_build()
        st = V.PLACEHOLDERS['STATE'][0]
        want = dict(launch_oracle(rom, p))          # what launch alone would do
        on = p['flag'] == 'on'
        if on and mode == 'live':
            thr, spd = f32(rom, 0x0F104C), r32(_speed(rom, p))
            if p['flag_65d0'] == 1:
                loff = f32(rom, 0x0F1050) if thr > spd else f32(rom, 0x0F1054)
            else:
                loff = 0.0 if spd > thr else f32(rom, 0x0F1050)
            voff = r32(f32(rom, 0x0CC500) - V.VALET_LIMIT)
            eff = r32(r32(p['rpm']) + r32(max(loff, voff)))

            def stage(cut, res):
                if eff >= f32(rom, cut):
                    return 1
                if eff < f32(rom, res):
                    return 0
                return p['prior']
            want = {0xFFFF7CB9: stage(0x0CC500, 0x0CC504), 0xFFFF7CBA: stage(0x0CC510, 0x0CC514)}
        want[st + 3] = 1 if on else 0
        want[st + 2] = 0                             # button up: latch cleared
        return want
    return oracle


def valet_sequences(rom, mode):
    """Multi-call hold tests on one persistent RAM. Returns failure strings."""
    V = _valet_build()
    st, btn, n = V.PLACEHOLDERS['STATE'][0], V.PLACEHOLDERS['BUTTON'][0], int(V.PLACEHOLDERS['HOLD_TICKS'][0])
    fails = []

    def fresh(flag='off'):
        emu = E.Emu(rom)
        launch_setup(emu, {'rpm': 3000.0, 'speed': 0.0, 'flag_65d0': 0, 'prior': 0, 'path': 'A'})
        a, b = VALET_FLAGS[flag]
        for i, v in enumerate((a, b, 0, 0)):
            emu.ram_u8(st + i, v)
        emu.ram_f32(st + 4, 0.0)
        emu.ram_u8(btn, 0)
        for other in (0xFFFF5FC1, 0xFFFF5FC2, 0xFFFF5FC3, 0xFFFF5FD5, 0xFFFF5FD6):
            if other != btn:
                emu.ram_u8(other, 0)
        return emu

    def tick(emu, pressed, speed=0.0, other=None):
        emu.ram_u8(btn, 1 if pressed else 0)
        if other:
            emu.ram_u8(other, 1)
        emu.ram_f32(0xFFFF65FC, speed)
        emu.call(0x03B668, stop_at={0x03D2FC})

    def flag(emu):
        return 'on' if (emu.read_u8(st), emu.read_u8(st + 1)) == (0xA5, 0x5A) else 'off'

    def check(cond, what):
        if not cond:
            fails.append(what)

    emu = fresh()
    for _ in range(n - 1):
        tick(emu, True)
    check(flag(emu) == 'off', f'toggled before {n} ticks')
    tick(emu, True)
    check(flag(emu) == 'on', f'did not toggle ON at tick {n}')
    for _ in range(3 * n):
        tick(emu, True)
    check(flag(emu) == 'on', 'toggled again while still held (latch)')
    tick(emu, False)
    check(emu.read_u8(st + 2) == 0, 'latch not cleared on release')
    for _ in range(n):
        tick(emu, True)
    check(flag(emu) == 'off', 'second hold did not toggle OFF')
    emu = fresh()
    for _ in range(n // 2):
        tick(emu, True)
    tick(emu, True, speed=5.0)
    for _ in range(n // 2 + 1):
        tick(emu, True)
    check(flag(emu) == 'off', 'speed > MAX_SPEED mid-hold did not restart the count')
    emu = fresh()
    for _ in range(3 * n):
        tick(emu, True, speed=20.0)
    check(flag(emu) == 'off', 'toggled while moving')
    emu = fresh('a500')
    for _ in range(n):
        tick(emu, True)
    check(flag(emu) == 'on', 'garbage flag + hold did not become ON')
    emu = fresh()
    for _ in range(2 * n):
        tick(emu, False, other=0xFFFF5FC2 if btn != 0xFFFF5FC2 else 0xFFFF5FC3)
    check(flag(emu) == 'off', 'another cruise button toggled valet')
    emu = fresh('on')                                  # ON survives: a new Emu = a "warm start" of RAM
    tick(emu, False, speed=0.0)
    check(flag(emu) == 'on' and emu.read_u8(st + 3) == 1, 'ON state not honoured on a later call')
    return fails


def valet_entry(mode):
    V = _valet_build()
    st = V.PLACEHOLDERS['STATE'][0]
    return dict(entry=0x03B668, stop_at={0x03D2FC}, grid=valet_grid(mode), setup=valet_setup,
                oracle=valet_oracle_for(mode), outputs={0xFFFF7CB8, 0xFFFF7CB9, 0xFFFF7CBA} | set(range(st, st + 8)),
                sequences=lambda rom: valet_sequences(rom, mode))


ORACLES = {
    'launch_control': dict(entry=0x03B668, stop_at={0x03D2FC}, grid=LAUNCH_GRID,
                           setup=launch_setup, oracle=launch_oracle,
                           outputs={0xFFFF7CB8, 0xFFFF7CB9, 0xFFFF7CBA}),
    'valet_limiter@live': 'valet:live',
    'valet_limiter@shadow': 'valet:shadow',
}


def oracle_for(key):
    o = ORACLES[key]
    return valet_entry(o.split(':')[1]) if isinstance(o, str) else o


def run(spec_id, rom, verbose=False):
    o = oracle_for(spec_id)
    keys = list(o['grid'])
    fails, n, uninit, notes = [], 0, set(), set()
    for vals in itertools.product(*(o['grid'][k] for k in keys)):
        p = dict(zip(keys, vals))
        emu = E.Emu(rom)
        o['setup'](emu, p)
        try:
            emu.call(o['entry'], stop_at=o['stop_at'])
        except E.EmuError as e:
            fails.append(f'{p}: EmuError {e}'); continue
        n += 1
        want = o['oracle'](rom, p)
        for a, v in want.items():
            got = emu.read_u8(a)
            if got != v:
                fails.append(f'{p}: [{a:#010x}] = {got}, oracle says {v}')
        stray = sorted(a for a in emu.writes if a not in o['outputs'])
        if stray:
            fails.append(f'{p}: writes RAM outside declared outputs: {[hex(a) for a in stray[:6]]}')
        uninit |= emu.uninit_reads
        notes |= emu.notes
    if uninit:
        fails.append(f'reads RAM no case set: {sorted(hex(a) for a in uninit)}')
    if o.get('sequences'):
        try:
            fails += [f'sequence: {f}' for f in o['sequences'](rom)]
        except E.EmuError as e:
            fails.append(f'sequence: EmuError {e}')
    return n, fails, notes


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('args', nargs='*')
    ap.add_argument('--live', action='store_true')
    a = ap.parse_args()
    if a.live:
        cur = sorted(p for p in os.listdir(os.path.join(REPO, 'rom')) if p.startswith('AE5L600L 20g rev 20.19'))[-1]
        jobs = []
        for f in sorted(os.listdir(os.path.join(REPO, 'docs', 'patch-specs'))):
            if not f.endswith('.json'):
                continue
            s = json.load(open(os.path.join(REPO, 'docs', 'patch-specs', f)))
            if str(s.get('status', '')).upper().startswith('DRAFT'):
                print(f'== {s["id"]}: DRAFT, not on the car -- skipped here; run its build script with --gates')
                continue
            jobs.append((s['id'], os.path.join(REPO, 'rom', cur)))
    elif len(a.args) == 2:
        sid = a.args[0] if a.args[0] in ORACLES else json.load(open(a.args[0]))['id']
        jobs = [(sid, a.args[1])]
    else:
        ap.error('SPEC BIN, or --live')
    rc = 0
    for sid, path in jobs:
        if sid not in ORACLES:
            print(f'== {sid}: no oracle -- gate 8 NOT run (write one before this patch is changed)')
            continue
        n, fails, notes = run(sid, open(path, 'rb').read())
        print(f'== {sid} on {os.path.basename(path)}: {"FAIL" if fails else "pass"} ({n} grid points)')
        for f in fails[:20]:
            print('  FAIL ' + f)
        for x in sorted(notes):
            print('  note ' + x)
        rc |= bool(fails)
    return rc


if __name__ == '__main__':
    sys.exit(main())
