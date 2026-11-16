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


ORACLES = {
    'launch_control': dict(entry=0x03B668, stop_at={0x03D2FC}, grid=LAUNCH_GRID,
                           setup=launch_setup, oracle=launch_oracle,
                           outputs={0xFFFF7CB8, 0xFFFF7CB9, 0xFFFF7CBA}),
}


def run(spec_id, rom, verbose=False):
    o = ORACLES[spec_id]
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
    return n, fails, notes


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('args', nargs='*')
    ap.add_argument('--live', action='store_true')
    a = ap.parse_args()
    if a.live:
        cur = sorted(p for p in os.listdir(os.path.join(REPO, 'rom')) if p.startswith('AE5L600L 20g rev 20.19'))[-1]
        jobs = [(json.load(open(os.path.join(REPO, 'docs', 'patch-specs', f)))['id'], os.path.join(REPO, 'rom', cur))
                for f in sorted(os.listdir(os.path.join(REPO, 'docs', 'patch-specs'))) if f.endswith('.json')]
    elif len(a.args) == 2:
        jobs = [(json.load(open(a.args[0]))['id'], a.args[1])]
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
