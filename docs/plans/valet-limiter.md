# Plan: valet-mode rev limiter that survives key-off

Track B item (`docs/pipeline-plan.md`). **Stage: draft built with PLACEHOLDERS (owner, 2026-11-15); NOT FLASHABLE until Gate 0 settles them.** Written
2026-11-15. No code is written until the verify items below are settled and the
owner approves this file (Gate 1).

## Goal

A valet mode that caps engine speed at **4000 RPM** until it is switched off again,
and that stays on across key-off and restart. The owner switches it on and off by
holding a cruise-control button at a standstill, with no laptop.

## Design in one paragraph

Extend the launch-control detour at `0x0F1000`, which already rewrites the rev
limiter's RPM input (`fr15`) before both limiter stages compare it
(`docs/rev-limit-patch.md`; gates 1-5 and 8 pass today). When valet is on, the
detour adds `6700 − valet_limit` to `fr15`. If launch control would also add its
offset, the larger offset wins, so the lower limit applies (owner, 2026-11-15). The on/off flag lives in
a two-byte pattern in **battery-retained RAM**. It counts as ON only when it reads
exactly `A5 5A`, so garbage after a battery reconnect reads as OFF. A small state
machine counts the activation sequence and toggles the flag.

## Activation sequence (owner chose: cruise-button hold)

```
precondition : vehicle speed (0xFFFF65FC) < 1.0 km/h for the whole hold
hold         : the cruise CANCEL button held continuously for 5.0 s
action       : toggle the flag once (OFF -> ON writes A5 5A; ON -> OFF writes 00 00);
               the button must be released before the next hold can count
abort        : speed > 0, or the button released before 5.0 s -> timer back to 0
```

- **Cannot fire while driving:** the speed must stay at exactly 0 for the whole
  hold. At a standstill, cruise control cannot engage, so a held button does
  nothing else.
- **The cruise switch inputs are not identified anywhere in this repo.** The
  definitions' "Cruise" tables are the steady-cruise *timing regime*, not cruise
  control: `0xFFFF90BE` is that regime flag (corrections item 38). V2 below finds
  the switch inputs.
- **Feedback:** with valet on, the limiter cuts at 4000. Rev the engine in neutral
  with the accelerator and you'll hear and feel the cut. The patch also writes the
  flag to a byte the SSM read patch can log. No light or chime: the owner chose
  that (Q5), so the patch writes no output.

## Draft build (2026-11-15): placeholders, not flashable

The owner chose to keep going on best guesses. The bins are built and gated now,
and each guess is a single constant in `scripts/patchbuild/valet_limiter.py`
(`PLACEHOLDERS`), so a verify result is a one-line change and a rebuild.

| placeholder | value | settled by | why this guess |
|---|---|---|---|
| `STATE` (8 B flag/latch/counter) | `0xFFFF3FD0` | V1 + V6 | near the top of a 712-byte gap no literal points into (`0xFFFF3D1C`-`0xFFFF3FE4`), next to the learned values (IAM `0xFFFF3234`); avoids the stack below SP `0xFFFFBFA0` |
| `BUTTON` (CANCEL flag) | `0xFFFF5FD6` | V2b log | one of the five-switch group; SSM `0x0000D7` bit 0 also reports it |
| `HOLD_TICKS` (5.0 s) | 200 calls | V4, or the shadow log (`STATE+4` counts up while CANCEL is held) | assumes a 25 ms task |

Fixed design values: valet limit 4000 RPM (Q2); "standstill" = speed < 1.0 km/h,
tolerant of a noisy zero. The plan's "exactly 0" was too brittle; V3 says what the
sensor reads.

```
python3 scripts/patchbuild/valet_limiter.py --gates     # build both bins, run every gate
```

| gate | shadow | live |
|---|---|---|
| 1-5 `patch_lint.py` (diff whitelist, checksum, never-touch, SH-2E legality, convention) | pass | pass |
| 2 `rom_checksum.py` | pass | pass |
| 8 `patch_emulate.py`: 1,728 grid points (launch behaviour x 4 valet flag states) plus hold sequences | pass | pass |
| 6 `rom_allocation.py --check-claims` | **FAIL by design: the RAM claim is a PLACEHOLDER** | same |

- **Shadow vs live:** they differ at exactly one instruction, `0x0F10D8` (`fmov
  fr6,fr8` vs `nop`), plus the checksum words.
- **Mutants:** seven, each caught. Hold count 150, speed check removed, `max()`
  reversed, wrong button, latch never set, and each bin run against the other
  mode's oracle.
- **No new registers:** the block writes only `r0`, `r2`, `fr6`, `fr8`, `fr9` and
  `fr15`, the launch detour's own clobber set. It uses 168 B at
  `0x0F1060`-`0x0F1107`, with a 4-byte hook at `0x0F102E` that `amends`
  `launch_body`.
- **Assembler:** `scripts/sh2e_asm.py`. Every instruction is round-tripped through
  `sh2e_disasm`, and it re-assembles the live launch detour byte for byte.

## Verify items: Gate 0, before this plan can be approved

Each one is a `rom new` item; its claim is in `docs/plans/valet-limiter.claims.md`.
**All must settle `confirmed` or `corrected`, and their corrected facts flow back
into this plan.**

| id | question | why the plan needs it |
|---|---|---|
| V1 | Which on-chip RAM survives key-off while the battery stays connected? What do the warm-start marker (`0xFFFFBFFC == 0x5AA5A55A`, tested at `0x00068A`, written at `0x000752`) and a cold start each clear? Is retained RAM covered by any checksum or integrity check besides the marker? | Persistence rests on it. A checksum we don't update could wipe learned values (IAM, FLKC) at the next start |
| V2 | **Discovery.** V2a is done: five discrete switch flags, `0xFFFF5FC1`/`5FC2`/`5FC3`/`5FD5`/`5FD6`, which a stuck-switch monitor at `0x06E2C6` reads as one group. V2b, your standstill button log, decides which one is CANCEL. Details in the claims file | the activation input |
| V3 | `0xFFFF65FC` is vehicle speed in km/h, and it is 0 at a standstill | precondition input; `DISASM-ONLY` today |
| V4 | Which scheduler task calls the rev-limiter host (`0x03B668`), and at what period? | the 5.0 s hold is counted in host calls, so the period must be known exactly |
| V5 | What is `0xFFFF65D0`, the launch patch's flag? Lead: SSM `0x000121` reports it as bit 7, next to the switch flags (V2a). The V2b log's clutch step should settle it | valet shares the detour; launch behaviour must stay the same |
| V6 | A retained-RAM range of 8 bytes that nothing reads or writes (direct, indexed `@(r0,Rn)`, displacement and GBR forms; `find_writers.py` plus a reader scan) | the RAM claim in `docs/allocation.json`. Sequenced after V1 |

## Repos affected

Main repo: ae6l600l. No other repo.

## Files to touch (at build, not now)

- `docs/allocation.json`: grow the `launch_body` claim, or add `valet_body` in the
  ROM hole after `0x0F1058`; add a RAM claim of 8 bytes from V6, with its evidence.
- `docs/patch-specs/launch_control.json`: becomes `launch_valet.json`, with new
  clobbers if any, and every existing check still passing.
- `scripts/patch_emulate.py`: a `launch_valet` oracle (below). The existing
  `launch_control` oracle must still pass on the valet bin with valet OFF.
- `docs/rev-limit-patch.md`: a valet section. `docs/corrections.md`: an entry for
  any fact V1-V6 corrects.
- Output bins in `out/valet-limiter/`, never in `rom/`: a shadow bin and a live bin
  built on the current rev.

## Acceptance criteria

1. With valet OFF (any flag value except `A5 5A`), the patched bin behaves exactly as
   the current rev on all 432 `launch_control` points, plus the valet grid's OFF half.
2. With valet ON, both limiter stages trip at 4000 RPM at any speed, and the
   launch limit still applies when it is lower.
3. The toggle fires on exactly a 5.0 s hold at speed 0. It doesn't fire on a 4.9 s
   hold, on another button, or if the speed reaches 1.0 km/h during the hold. It toggles
   both ways, once per hold.
4. The flag survives a simulated warm start: emulate the start-up path with the
   marker set, and the flag bytes are untouched. It reads OFF after a simulated cold
   start, whatever RAM held. V1 decides how to model both.
5. `patch_lint.py`: gates 1-5 pass. Calling convention holds on every path, the
   detour writes only its declared registers, and there is no SH-2A word.
6. `rom_allocation.py --check-claims`: the new ROM and RAM claims are clear, and the
   RAM claim carries V6's evidence.
7. `rom_checksum.py`: both bins are valid. ECUFlash recomputes on write anyway, but
   the bins we hand over must already pass.
8. Shadow-bin log review (the `reviewing-a-new-log` skill): the logged "valet would
   limit" byte follows the sequence as driven, survives a key-off/on, and the engine
   behaves exactly as the current rev.

## Test plan

- **Emulation (gate 8):** a `launch_valet` oracle written from this file, not from
  the code. One grid over (valet flag in {`A5 5A`, `00 00`, `A5 00`, `FF FF`, random})
  x speed x RPM x launch flag x prior stage state. Sequence tests drive the toggle
  with timed button traces: a 5.0 s hold, a 4.9 s hold, the wrong button, speed
  rising mid-hold, a held button not counting twice, ON to OFF.
- **Mutants:** the gate must catch at least a wrong hold time, the wrong button,
  a missing speed precondition, and the offsets swapped.
- **Shadow flash, then live flash,** each behind an owner gate. No exceptions.

## Risks and rollback

- **Retained RAM is not what we think (V1).** Worst case: the flag byte collides
  with a learned value, or an integrity check wipes learning. Mitigation: V1 and V6
  before any build, and the shadow bin logs the learned values next to the flag.
- **The cruise inputs turn out to be CAN-derived or debounced elsewhere (V2).** The
  hold logic then reads whatever the ECU itself uses; if that is not a stable byte,
  re-plan under Gate 1.
- **Accidental activation.** The hold only counts with the speed at exactly 0. A
  held button does nothing at a standstill otherwise. Turning it off again is the
  same hold.
- **Rollback:**
  - Reflash the current rev; valet code and flag are gone.
  - Or set the valet limit equal to the normal limit (a table edit, no code change).
  - Or disconnect the battery, which clears the flag (decision 3).

## Open questions for the owner

None. Gate 0 (the verify items) is what stands between this plan and approval.

## Decisions

- 2026-11-15: activation by a button sequence, not a laptop SSM write (owner).
- 2026-11-15: Q1 -- a cruise-button hold, not pedal pumps (owner).
- 2026-11-15: Q2 -- valet limit 4000 RPM, as a calibration constant (owner).
- 2026-11-15: Q3 -- a battery disconnect clears valet mode; that is acceptable (owner).
- 2026-11-15: Q4 -- with launch control also active, the lower limit wins (owner).
- 2026-11-15: Q6 -- persistence in battery-retained RAM, never the external EEPROM (owner).
- 2026-11-15: Q7 -- toggle by holding CANCEL for 5 s at a standstill (owner).
- 2026-11-15: Q5 -- feedback is the rev check in neutral plus the logged flag byte;
  no dash light, so no output is written (owner).

## Scope additions

## Objections
