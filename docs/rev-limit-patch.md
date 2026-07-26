# The `0x0F1000` Rev-Limit Patch (launch control / 2-step)

The second of two live code patches in every ROM flashed to this car, and the
safety-relevant one. Undocumented until 2026-07-26.

- **Location:** `0x0F1000`–`0x0F1057` (88 bytes), injected into the big ROM hole
  (`0x0DAE8C`–`0x0F8900`, which is `0xFF` in stock)
- **Entry:** two literal redirects, `0x03B79C` and `0x03B7A8`, both changed from
  `0x000CC500` / `0x000CC50C` to `0x000F1000`
- **Exit:** returns into the stock rev-limit path at `0x03B6B2`
- **Present in:** every rev 20.8 → 20.19b
- **Absent from:** stock, and from `13 20g Base rev 25 e garn.hex`

> **Diffing note:** a region-classified diff will MISS this patch. It lives in
> space classified `rom_hole`, not `code` — which is exactly where injected code
> goes. Diff the whole ROM and inspect `rom_hole` deltas.

---

## The host function

The rev limiter begins at `0x03B668`. Its inputs, resolved from the literal pool
at `0x03B778`:

| Register | Source | Meaning |
|---|---|---|
| `FR15` | `0xFFFF6624` | **rpm_current** |
| `FR14` | `0xFFFF65FC` | **vehicle speed (km/h)** — repo labels this `engine_load_current`, which is wrong; see `corrections.md` item 8 |
| `FR12` | `0xFFFF620C` | airflow_maf_current |

Stock then selects one of two cut/resume pairs based on a condition result:

```
03B6A8  extu.b r0,r2
03B6AA  tst r2,r2
03B6AC  bt 0x03B6B8          ; r2 == 0 -> pair B
        ; pair A
03B6AE  mov.l @(0x03B79C),r2 ; -> 0xCC500   cut
03B6B0  fmov.s @r2,fr8
03B6B2  mov.l @(0x03B7A0),r2 ; -> 0xCC504   resume
03B6B4  bra 0x03B6C0
03B6B6  fmov.s @r2,fr6
        ; pair B
03B6B8  mov.l @(0x03B7A4),r2 ; -> 0xCC508   cut
03B6BA  fmov.s @r2,fr8
03B6BC  mov.l @(0x03B7A8),r2 ; -> 0xCC50C   resume
03B6BE  fmov.s @r2,fr6
03B6C0  fcmp/gt fr15,fr8     ; T = (cut > RPM)  -> not over limit
```

Calibration values (rev 20.19b): `0xCC500` = 6700, `0xCC504` = 6680,
`0xCC508` = 6700, `0xCC50C` = 6680.

## What the patch changes

Both paths are diverted into `0x0F1000`, using the `jmp` **delay slot** to keep
the stock literal load:

```
03B6AE  mov.l @(0x03B79C),r0 ; -> 0x0F1000
03B6B0  jmp @r0
03B6B2  mov.l @(0x03B7A0),r2 ; delay slot: r2 = 0xCC504
```

## The injected code

```
0F1000  mov.l @(0x0F1038),r0   ; r0 = 0xFFFF65FC   VEHICLE SPEED (km/h)
0F1002  fmov.s @r0,fr9         ; FR9 = speed
0F1004  mova @(0x0F104C),r0
0F1006  fmov.s @r0,fr6         ; FR6 = 8.0515 km/h = 5 mph
0F1008  mov.l @(0x0F103C),r0   ; r0 = 0xFFFF65D0
0F100A  mov.b @r0,r0           ; r0 = state flag byte
0F100C  cmp/eq #1,r0
0F100E  bf/s 0x0F101E
0F1010  nop
        ; flag == 1
0F1012  fcmp/gt fr9,fr6        ; T = (5mph > speed)
0F1014  bt/s 0x0F1024          ; below 5 mph -> +2700
0F1016  nop
0F1018  mova @(0x0F1054),r0    ; 0.0
0F101A  bra 0x0F102C
0F101C  nop
        ; flag != 1
0F101E  fcmp/gt fr6,fr9        ; T = (speed > 5mph)
0F1020  bt/s 0x0F102A          ; above 5 mph -> +0.0
0F1022  nop
0F1024  mova @(0x0F1050),r0    ; 2700.0
0F1026  bra 0x0F102C
0F1028  nop
0F102A  mova @(0x0F1048),r0    ; 0.0
0F102C  fmov.s @r0,fr8
0F102E  fadd fr8,fr15          ; *** RPM += 0 or 2700 ***
0F1030  mov.l @(0x0F1044),r2   ; r2 = 0x000CC500
0F1032  mov.l @(0x0F1040),r0   ; r0 = 0x0003B6B2
0F1034  jmp @r0                ; back into the stock path
0F1036  fmov.s @r2,fr8         ; delay slot: FR8 = *0xCC500 = 6700
```

Embedded constants:

| Address | Value |
|---|---|
| `0x0F1038` | `0xFFFF65FC` — **vehicle speed (km/h)**, not load; see corrections.md item 8 |
| `0x0F103C` | `0xFFFF65D0` — state flag (byte) |
| `0x0F1040` | `0x0003B6B2` — return address |
| `0x0F1044` | `0x000CC500` — cut-RPM table |
| `0x0F1048` | `0.0` |
| `0x0F104C` | `8.0515` km/h = **5 mph** — LC disable speed threshold |
| `0x0F1050` | `2700.0` — **LC RPM delta** (ECUFlash table) |
| `0x0F1054` | `0.0` — **FFS RPM delta** (flat-foot shift; currently disabled) |

## What it does, in one line

**Below 5 mph, the patch adds 2700 RPM to the value the limiter compares against
— so the limiter trips at an actual 4000 RPM instead of 6700.**
(`6700 − 2700 = 4000`.)

That is launch control: hold 4000 RPM at a standstill, and the moment the car
exceeds 5 mph the normal 6700 limit returns. The threshold, the delta, and the
flat-foot-shift delta are all exposed as ECUFlash tables under the
**"tinywrex patches"** category (`docs/AE5L600L_table_inventory.md`):

| Table | Address | Value in 20.19b |
|---|---|---|
| LC disable speed(MPH) threshold | `0xF104C` | 5 mph (raw 8.0515 km/h) |
| LC RPM delta | `0xF1050` | 2700 |
| **FFS RPM delta** | `0xF1054` | **0 — flat-foot shift is OFF** |

Both branches of the flag test converge on the same behaviour (below threshold
⇒ +2700); only the boundary at exactly 5 mph differs.

## The three rev-limit pairs — which are live

All six are exposed as ECUFlash tables and all currently hold the same values
(6700 cut / 6680 resume), so today they are indistinguishable. They are **not**
equally reachable:

| Pair | Cut / Resume | Status | Notes |
|---|---|---|---|
| 1 | `0xCC500` / `0xCC504` | **LIVE** | First limiter stage; sets flag `@(1,r5)` |
| 2 | `0xCC508` / `0xCC50C` | **DEAD** | Bypassed by the patch — see below |
| 3 | `0xCC510` / `0xCC514` | **LIVE** | Second limiter stage at `0x03B6D6`/`0x03B6E6`; sets flag `@(2,r5)` |

`r5` = `0xFFFF7CB8`, so the two stages set independent status bytes at
`0xFFFF7CB9` and `0xFFFF7CBA`.

**Pair 3 also sees the launch-control offset.** The patch modifies `FR15` before
returning, and `FR15` is still live when stage 2 runs at `0x03B6D6` — so both
stages are shifted by the +2700 during launch control.

### Why pair 2 is dead

Both entries now jump to `0x0F1000`, and the patch always returns to `0x03B6B2`,
which loads `0xCC504` for the resume value. Path B's delay slot does set
`r2 = 0xCC508`, but the patch overwrites `r2` at `0x0F1030` before it is used.

**Editing `0xCC508`/`0xCC50C` will do nothing.** To change the limiter, edit
pair 1 (`0xCC500`/`0xCC504`) and pair 3 (`0xCC510`/`0xCC514`) — and change both,
or the two stages will disagree.

## Open question — `0xFFFF65D0`

Not in `disassembly/maps/ram_reference.txt`. Established facts only:

- A **byte**, read at 10 sites spanning idle control, ETB/boost (`0x050A90`,
  `0x0540B2`, `0x054B38`), CL/OL (`0x03AE88`), ignition (`0x03EEDC`), DTC
  (`0x0A95D0`) and the math/util region (`0x0BC74A`, `0x0BC8C6`).
- Compared against `1` at `0x014B92` and `0x03AE94`.
- Read at `0x0248A2` as part of a batch of adjacent state-flag bytes.
- No writer found among those sites.

A gear/neutral/clutch-state input fits the usage and would fit a launch-control
patch, **but this has not been verified** — do not treat it as identified.

## Why this file matters beyond the limiter

Together with [`ssm-read-patch.md`](ssm-read-patch.md), this is one of only two
pieces of custom code running on this ECU, and the better example of hooking
technique: it redirects via a **literal-pool value** rather than patching an
instruction, borrows the existing `jmp` delay slot to preserve the stock load,
and returns mid-function with registers set up exactly as the host expects.
Anyone writing new code for this ROM should read it first.
