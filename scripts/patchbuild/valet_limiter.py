#!/usr/bin/env python3
"""Build the valet-limiter bins (docs/plans/valet-limiter.md) -- SHADOW and LIVE.

    python3 scripts/patchbuild/valet_limiter.py            # writes out/valet-limiter/*.bin
    python3 scripts/patchbuild/valet_limiter.py --list     # print the assembled listing

!!! PLACEHOLDERS !!!  Every value in PLACEHOLDERS below is the owner-approved best
guess (2026-11-15), NOT a verified fact. scripts/rom_allocation.py --check-claims
refuses a RAM claim whose evidence starts with "PLACEHOLDER", so these bins cannot
pass the full gate set until V1/V2/V4/V6 settle. Building and emulating them is safe;
FLASHING THEM IS NOT.

What it does (both bins):
  * the launch detour's tail at 0x0F102E is redirected (`bra VALET`) to a new block in
    the ROM hole at 0x0F1060; fr8 already holds the launch offset there
  * VALET runs a hold detector on the cruise CANCEL flag: pressed, speed < MAX_SPEED,
    not latched -> count; at HOLD_TICKS -> toggle the A5 5A flag and latch until released
  * if the flag is ON: valet offset = [0xCC500] (cut) - VALET_LIMIT; state byte +3 = 1
  * LIVE takes the larger of the launch and valet offsets; SHADOW does everything except
    that one instruction (`fmov fr6,fr8` vs `nop`), so the limiter is unchanged
  * then the original tail: fr15 += fr8, fr8 = [0xCC500], back to 0x03B6B2
Registers written: r0, r2, fr6, fr8, fr9, fr15 -- the launch detour's own clobber set.
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, 'scripts'))
import sh2e_asm as A  # noqa: E402
import rom_checksum as CK  # noqa: E402

BASE = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19d.bin')
OUT = os.path.join(REPO, 'out', 'valet-limiter')

# ----------------------------------------------------------------------------------
PLACEHOLDERS = {
    # V6 (after V1): 8 bytes of battery-retained RAM nothing else touches.
    # Guess: top of the 712-byte literal-free gap 0xFFFF3D1C..0xFFFF3FE4.
    'STATE':      (0xFFFF3FD0, 'V1/V6: retained, unused 8 bytes'),
    # V2b: which flag is CANCEL. Guess: one of the five-switch group (0x06E2C6);
    # 5FD6 because SSM 0x0000D7 also reports it (getter 0x05DDF4, bit 0).
    'BUTTON':     (0xFFFF5FD6, 'V2b: the CANCEL flag'),
    # V4: calls per 5.0 s. Guess: a 25 ms task. The SHADOW log measures it (state +4).
    'HOLD_TICKS': (200.0, 'V4: host calls in 5.0 s'),
}
VALET_LIMIT = 4000.0      # owner decision Q2
MAX_SPEED = 1.0           # km/h: "at a standstill", tolerant of a noisy zero (V3)
# ----------------------------------------------------------------------------------
VALET_AT = 0x0F1060       # ROM hole, after the launch tables (0x0F1048..0x0F1057)
HOOK_AT = 0x0F102E        # launch detour: was `fadd fr8,fr15`

# State block (STATE, 4-aligned): +0 A5, +1 5A = ON | +2 latch | +3 valet active (logged)
#                                  +4..+7 hold counter (float32, logged)
VALET_SRC = r'''
VALET:      mov.l   @(P_STATE),r2
            mov.l   @(P_BTN),r0
            mov.b   @r0,r0
            cmp/eq  #1,r0
            bf      V_REL               ; button up -> clear latch, zero counter
            mova    @(C_MAXSPD),r0
            fmov.s  @r0,fr6
            fcmp/gt fr9,fr6             ; T = MAX_SPEED > speed (fr9 = speed, from 0x0F1002)
            bf      V_ZERO              ; moving: zero the counter, keep the latch
            mov.b   @(2,r2),r0
            cmp/eq  #0,r0
            bf      V_APPLY             ; latched: wait for release
            mov     r2,r0
            add     #4,r0
            fmov.s  @r0,fr6             ; counter
            fldi1   fr9
            fadd    fr9,fr6
            fmov.s  fr6,@r0
            mova    @(C_HOLD),r0
            fmov.s  @r0,fr9
            fcmp/gt fr6,fr9             ; T = HOLD_TICKS > counter -> keep counting
            bt      V_APPLY
            mov     #1,r0
            mov.b   r0,@(2,r2)          ; latch
            mov.b   @(0,r2),r0
            cmp/eq  #-91,r0             ; 0xA5
            bf      V_SETON
            mov.b   @(1,r2),r0
            cmp/eq  #90,r0              ; 0x5A
            bf      V_SETON
            mov     #0,r0               ; ON -> OFF
            mov.b   r0,@(0,r2)
            bra     V_ZERO
            mov.b   r0,@(1,r2)
V_SETON:    mov     #-91,r0             ; OFF/garbage -> ON
            mov.b   r0,@(0,r2)
            mov     #90,r0
            bra     V_ZERO
            mov.b   r0,@(1,r2)
V_REL:      mov     #0,r0
            mov.b   r0,@(2,r2)
V_ZERO:     fldi0   fr6
            mov     r2,r0
            add     #4,r0
            fmov.s  fr6,@r0
V_APPLY:    mov.b   @(0,r2),r0
            cmp/eq  #-91,r0
            bf      V_OFF
            mov.b   @(1,r2),r0
            cmp/eq  #90,r0
            bf      V_OFF
            mov.l   @(P_CUT),r0
            fmov.s  @r0,fr6             ; stage-1 cut
            mova    @(C_LIMIT),r0
            fmov.s  @r0,fr9
            fsub    fr9,fr6             ; fr6 = cut - VALET_LIMIT
            mov     #1,r0
            mov.b   r0,@(3,r2)          ; valet active
            fcmp/gt fr8,fr6             ; T = valet offset > launch offset
            bf      V_DONE
SWITCH:     {SWITCH}
            bra     V_DONE
            nop
V_OFF:      mov     #0,r0
            mov.b   r0,@(3,r2)
V_DONE:     fadd    fr8,fr15
            mov.l   @(P_CUT),r2
            mov.l   @(P_RET),r0
            jmp     @r0
            fmov.s  @r2,fr8
            .align  4
P_STATE:    .long   {STATE}
P_BTN:      .long   {BUTTON}
P_CUT:      .long   0x000CC500
P_RET:      .long   0x0003B6B2
C_MAXSPD:   .float  {MAX_SPEED}
C_HOLD:     .float  {HOLD_TICKS}
C_LIMIT:    .float  {VALET_LIMIT}
'''

HOOK_SRC = '''
            bra     {VALET:#x}
            nop
'''


def assemble(mode):
    src = VALET_SRC.format(SWITCH='fmov fr6,fr8' if mode == 'live' else 'nop',
                           STATE=hex(PLACEHOLDERS['STATE'][0]), BUTTON=hex(PLACEHOLDERS['BUTTON'][0]),
                           HOLD_TICKS=PLACEHOLDERS['HOLD_TICKS'][0], MAX_SPEED=MAX_SPEED,
                           VALET_LIMIT=VALET_LIMIT)
    body = A.assemble(src, VALET_AT)
    hook = A.assemble(HOOK_SRC.format(VALET=VALET_AT), HOOK_AT)
    return body, hook


def build(mode, base):
    body, hook = assemble(mode)
    rom = bytearray(base)
    for code in (hook, body):
        seg = rom[code.origin:code.end]
        if code is body and seg != b'\xff' * len(seg):
            raise SystemExit(f'{mode}: 0x{code.origin:06X}-0x{code.end - 1:06X} is not erased (0xFF) in the base')
        rom[code.origin:code.end] = code.bytes
    return CK.fix(bytes(rom)), body, hook


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--list', action='store_true')
    ap.add_argument('--gates', action='store_true', help='after building, run every flash-safety gate on both bins')
    a = ap.parse_args()
    base = open(BASE, 'rb').read()
    os.makedirs(OUT, exist_ok=True)
    out = {}
    for mode in ('shadow', 'live'):
        rom, body, hook = build(mode, base)
        path = os.path.join(OUT, f'AE5L600L 20.19d+valet-{mode}.bin')
        open(path, 'wb').write(rom)
        out[mode] = rom
        print(f'{mode:6s}: {os.path.relpath(path, REPO)}  body 0x{body.origin:06X}-0x{body.end - 1:06X} '
              f'({len(body.bytes)} B), hook 0x{hook.origin:06X}-0x{hook.end - 1:06X}')
        if a.list and mode == 'live':
            for pc, enc, txt in hook.listing + body.listing:
                print(f'   {pc:06X} {enc:>8s}  {txt}')
    diff = [i for i in range(len(base)) if out['shadow'][i] != out['live'][i] and not CK.TABLE <= i < CK.TERMINATOR_AT]
    print(f'shadow vs live differ at {[hex(i) for i in diff]} (the SWITCH instruction; plus checksum words)')
    print('PLACEHOLDERS (not verified -- do not flash):')
    for k, (v, why) in PLACEHOLDERS.items():
        print(f'   {k:11s} = {v if isinstance(v, float) else hex(v)}   <- {why}')
    return gates() if a.gates else 0


def gates():
    """Gates 1-5 (lint), 2 (checksum), 6 (claims), 8 (emulation) on both bins. Exit 1 on any FAIL."""
    import json
    import subprocess
    import tempfile
    spec = os.path.join(REPO, 'docs', 'patch-specs', 'valet_limiter.json')
    py, rc = sys.executable, 0
    print('\n== gates')
    for mode in ('shadow', 'live'):
        b = os.path.join(OUT, f'AE5L600L 20.19d+valet-{mode}.bin')
        for name, cmd in ((f'lint 1-5 [{mode}]', [py, 'scripts/patch_lint.py', spec, BASE, b]),
                          (f'checksum [{mode}]', [py, 'scripts/rom_checksum.py', '--quiet', b]),
                          (f'emulation [{mode}]', [py, 'scripts/patch_emulate.py', f'valet_limiter@{mode}', b])):
            p = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
            rc |= p.returncode != 0
            print(f'  {"pass" if p.returncode == 0 else "FAIL"}  {name}')
            if p.returncode:
                print('      ' + '\n      '.join(l for l in p.stdout.split('\n') if 'FAIL' in l)[:2000])
    j = json.load(open(spec))
    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
        json.dump({'rom': j['claims'], 'ram': j['ram']}, f)
    p = subprocess.run([py, 'scripts/rom_allocation.py', '--check-claims', f.name], cwd=REPO, capture_output=True, text=True)
    os.unlink(f.name)
    rc |= p.returncode != 0
    print(f'  {"pass" if p.returncode == 0 else "FAIL"}  claims (gate 6)')
    if p.returncode:
        print('      ' + '\n      '.join(l for l in p.stdout.split('\n') if 'FAIL' in l))
    print('\nNOT FLASHABLE' if rc else '\nall gates pass -- still needs the owner gate, shadow flash first')
    return 1 if rc else 0


if __name__ == '__main__':
    sys.exit(main())
