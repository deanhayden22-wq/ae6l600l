# Injector rescale — AE5L600L

Everything in this ROM that has to change when the injectors are swapped, and —
just as important — the things whose names say "injector" that must **not**
change. Written 2026-07-28 against `rom/AE5L600L 20g rev 20.19c.bin`.

Tool: `python scripts/injector_rescale.py --new-cc <flow>`
Corrections this sweep produced: `docs/corrections.md` items 36–38.

## Decisions taken for this swap (2026-07-28)

| | |
|---|---|
| Target injectors | **~1000–1050 cc/min** |
| Rated at | **43.5 psi, the stock rail reference** — so no pressure conversion; the flow ratio applies directly |
| Fuel | **Pump gas** — no stoich/density correction on top |
| Per Injector PW Comp A–D | **Axes rescaled by k; %-data left at stock.** Superseded the original "leave entirely alone" call — see §3, leaving the axis introduces −3% to +6% of load-dependent, per-channel error |

Generated worksheets (group 2 axes included):

- `docs/injector-rescale-worksheet-1000cc.txt` — k = **0.550669**
- `docs/injector-rescale-worksheet-1050cc.txt` — k = **0.524447**

Neither loses more than 2% on any cell to storage-type rounding. Pick whichever
matches the injectors that actually arrive and re-run the tool if the flow
differs; the worksheet is cheap to regenerate.

---

## 1. The one constant everything else follows

**`Injector Flow Scaling` @ `0xCBE0C`**, float, raw `4916.0` — unchanged in
every rev from stock through 20.19c.

    ECUFlash display = 2707090 / raw = 550.669 cc/min
                       ("ESTIMATED Flow Rate - Gas Only")

`0x000CBE0C` has exactly **one** literal reference in the 1 MB image (pool at
`0x0303B0`). Its consumer is the function at `0x030378`:

```
030378  sts.l  pr,@-r15
03037A  mov.l  @(...),r2      ; = 0xFFFF63F8   engine load, g/rev
03037C  fmov.s @r2,fr4
030384  mov.l  @(...),r2      ; = 0x000CBE0C   flow scaling
030388  fmov.s @r2,fr8        ; fr8 = 4916.0
03038A  fmul   fr8,fr4        ; fr4 = load * 4916.0
03039C  jsr    @r2            ; 0xBE56C float clamp, lo = 0.0, hi = 131072.0
0303A6  fmov.s fr0,@r2        ; -> 0xFFFF7348
```

Injector on-time is directly proportional to this constant. So:

> **k = 550.669 / new_cc_min = new_raw / 4916.0**
>
> Every absolute-millisecond calibration in the ROM multiplies by **k**.
> Nothing that is a percentage, ratio, RPM, temperature or AFR changes at all.

Bigger injector → larger cc/min → **smaller** raw constant → shorter pulse width
for the same air mass.

### Before you pick a number

Two things decide what `new_cc` should be, and neither is on the ROM side:

- **Reference pressure.** The 550.669 figure is referenced to the stock fuel
  pressure. If the new injectors are rated at a different bar, convert first —
  flow scales with the square root of the pressure ratio.
- **Fuel.** The scaling is named "Gas Only". Straight pump gas needs no
  adjustment. Anything with a different stoichiometric ratio or density does,
  and that correction goes here, not into the AFR tables.

---

## 2. Scale the DATA by k

| Address | Table | Now | Why it scales |
|---|---|---|---|
| `0xCD2E6` | Cranking Fuel IPW **A** (ECT) | 140 → 5.0 ms | absolute on-time |
| `0xCD306` | Cranking Fuel IPW **B** (ECT) | 39 → 5.0 ms | " |
| `0xCD326` | Cranking Fuel IPW **C** (ECT) | 33.55 → 4.5 ms | " |
| `0xCD346` | Cranking Fuel IPW **D** (ECT) | 150 → 5.0 ms | " |
| `0xCD366` | Cranking Fuel IPW **E** (ECT) | 39 → 5.0 ms | " |
| `0xCD386` | Cranking Fuel IPW **F** (ECT) | 33.55 → 4.5 ms | " |
| `0xCED50` | Throttle Tip-in Enrichment **A** | 0.424 → 1.568 ms | additive on-time |
| `0xCEDBC` | Throttle Tip-in Enrichment **B** | 0.424 → 1.568 ms | " |
| `0xCC4A4` | Minimum Tip-in Enrichment Activation | 1.0 ms | ms threshold on the adder |
| `0xCC49C` | Overrun initial injector enrichment | 1.4 ms | additive on-time |
| `0xCE5F8` | CL→OL Transition with Delay (BPW) | 5.3 → 0.0 ms vs RPM | ms threshold vs computed BPW |
| `0xCC174` | CL→OL with Delay BPW Hysteresis | 0.756 ms | " |

Cranking IPW A–F are all at stock values; nothing in the 20.x series has touched
them. Tip-in A/B are **not** stock — they were raised from 0.352–1.352 ms.
Rescale what is there now, not the stock numbers.

### The last two are currently inert — scale them anyway

`CL to OL Delay_` @ `0xCBC62` is **0** in 20.19c (stock 750), which bypasses the
delay-based transition path that consumes both `0xCE5F8` and `0xCC174`. So today
an unrescaled BPW threshold cannot strand the ECU in closed loop.

Scale them regardless. They are the only absolute-pulse-width values anywhere in
the CL/OL path, and if the delay is ever re-enabled with stock-sized thresholds
the OL trigger lands in the wrong place — at roughly half the injector size, a
6.7 ms threshold is a pulse width the engine can no longer reach.

Note also that `0xCC174` currently sits at **0.756 ms against a stock 0.256 ms**.
That inflation is on the "don't do this" list for CL/OL oscillation (it risks a
lean OL→CL return). It is inert while the delay is 0, but it is worth deciding
whether to keep it at all rather than carrying it forward through the rescale.

---

## 3. Scale the ms AXIS by k, leave the %-data alone

| Axis address | Table | Axis now |
|---|---|---|
| `0xD0760` | Per Injector Pulse Width Compensation **A** @ `0xD07E8` | 1.0 … 16.0 ms |
| `0xD090C` | Per Injector Pulse Width Compensation **B** @ `0xD0994` | 1.0 … 16.0 ms |
| `0xD0AB8` | Per Injector Pulse Width Compensation **C** @ `0xD0B40` | 1.0 … 16.0 ms |
| `0xD0C64` | Per Injector Pulse Width Compensation **D** @ `0xD0CEC` | 1.0 … 16.0 ms |

Each is 17 RPM × 17 BPW of `(x*.78125)-100` percentage trim — neutral is raw
128. The data is dimensionless and does not scale; the **X axis** is
"Last Calculated Base Pulse Width" in milliseconds and does.

### These ARE the ROM's pulse-width compensation — there is no other one

Settled 2026-07-28 by tracing `0xFFFF7324` (`last_calc_base_pulse_width`), which
has only three pool references in the image. The decisive one is `0x038DCE`:

```
038DCE  mov.l  @(...),r2      ; = 0xFFFF7324  base pulse width
038DD0  fmov.s @r2,fr4
038DD2  fmov   fr4,fr14       ; keep a copy
038DD4  mov.l  @(...),r4      ; = 0x000AD738  dims 17x17, ax0 0xD0760, ax1 0xD07A4, data 0xD07E8  -> comp A
038DD8  jsr    @r14           ; 0xBE8E4, 2D lookup;  fr5 = RPM
038DE0  fmov.s fr0,@(r0,r13)  ; r13 = 0xFFFF7B78, r0 = -12
038DE2  mov.l  @(...),r4      ; = 0x000AD754  -> comp B   -> slot -8
038DEE  mov.l  @(...),r4      ; = 0x000AD770  -> comp C   -> slot -4
038DFA  mov.l  @(...),r4      ; = 0x000AD78C  -> comp D   -> slot  0
```

Four 2D lookups back to back, same base pulse width in FR4 and same RPM in FR5,
into four consecutive floats at `0xFFFF7B6C / 7B70 / 7B74 / 7B78`. Those four
slots are then consumed in parallel at `0x03024E / 3025E / 3026E / 30280`, each
`fmac`-ed into its own accumulator against a separate value from the fuel struct
(offsets −52, −48, −44, −40) and stored to four separate stack slots.

Four parallel channels, and the ATU struct init at `0x9860` loops exactly four
times over four cylinders. Per-cylinder is the well-supported reading. (What is
*proven* is four parallel channels in the fuel path; the mapping of A/B/C/D onto
cylinders 1–4 in that order is not independently confirmed.)

**So: no separate low-pulse-width linearisation table exists on this ROM.** The
`32BITBASE` feature of that name is not present here — the pulse-width-indexed
compensation is this set, and short-pulse behaviour is simply the low end of
their 1.0 ms axis. Nothing further to find, and nothing extra to populate.

The data does not have low-PW-linearisation shape either — column means sit near
0 to −2% from 1–6 ms then step to about −3% above 7 ms, with 5–16% of spread in
the *RPM* direction. It is dominated by RPM, not by pulse width.

### The axis question, re-answered — rescale it

**This reverses the advice given earlier in this session.** The original framing
("the data characterises the OEM injector, so moving the axis alone doesn't fix
that") is true but misleading: the axis and the data are separable, and
rescaling the axis is the **behaviour-preserving** choice.

The lookup is indexed by *actual computed* base pulse width. After a 1000 cc
swap the same physical operating point produces a pulse ~0.55x as long, so it
lands further down an unrescaled axis and picks up a different correction:

| Operating point | Correction today (A/B/C/D) | Axis LEFT alone | Error introduced |
|---|---|---|---|
| idle, ~2.0 ms, 800 rpm | −3.12 all four | −2.82 all four | +0.31% |
| light cruise, ~3.0 ms, 2000 | −0.78 / −5.47 / 0.00 / −3.12 | +0.17 / −1.56 / −0.31 / −1.26 | +0.95 / **+3.91** / −0.31 / +1.87 |
| mid cruise, ~5.0 ms, 2800 | +1.56 / 0.00 / +1.56 / −0.78 | −0.98 / −3.14 / −1.18 / −3.52 | **−2.55 / −3.14 / −2.74 / −2.74** |
| boost, ~10.0 ms, 4400 | −5.47 / −5.47 / −5.47 / −3.91 | +0.78 / −1.95 / +0.77 / +0.78 | **+6.25 / +3.52 / +6.24 / +4.69** |

Rescaling the axis by k makes every one of those deltas exactly zero, by
construction — same correction at the same physical operating point.

Two things make leaving it worse than the raw percentages suggest:

- The error is **load-dependent** and changes sign: ~−3% at mid cruise, ~+6% at
  boost. That is not something a single flow-scaling tweak can absorb, and it
  will fight the closed-loop trims across the cruise range.
- The error **differs per channel** — at boost, +6.25 on A but +3.52 on B. That
  manufactures cylinder-to-cylinder imbalance that does not exist today.

**Recommendation: rescale the axis, keep the data (option 1 below).** It keeps
the ECU doing exactly what it does now, which is the right default for a swap
where you want the flow constant to be the only variable under test.

The data being OEM-characterised is a real but *separate* question, and it is
one for after the first drive — not a reason to leave the axis wrong.

### Open question worth settling before you flash

A–D are all at stock values and they genuinely differ from one another — 151 to
249 of 289 cells differ between any two of them, spanning raw 116–138 (−9.4% to
+7.8%). That is real characterisation data for the **OEM injector**, whether it
is per-cylinder trim or a shared low-pulse-width linearisation curve.

Rescaling the axis puts the existing curve at the right pulse widths. It does
not make the curve correct for a different injector. The three options:

1. **Rescale the axis, keep the data.** Least disruptive; assumes the new
   injector's non-linearity resembles the old one's. Reasonable if the new
   injectors are the same basic type.
2. **Rescale the axis, zero the data to raw 128.** Neutral. Gives up the
   linearisation but tells no lies. Reasonable if the new injectors come with
   their own latency/linearisation data that you will enter elsewhere.
3. **Rescale the axis, substitute the new injector's data.** Correct, if the
   supplier publishes it. Most do not, at this resolution.

Not resolvable from the ROM — it depends on which injectors go in.

---

## 4. Replace from the data sheet — do NOT scale by k

**`Injector Latency_` @ `0xD106C`** — 3 rows × 5 columns, uint16,
display = raw × 0.00025 ms (raw 4000 = 1.000 ms exactly).

Battery axis @ `0xD104C`: `6.5, 9.0, 11.5, 14.0, 16.5` V
Current dead time: `3.147, 1.714, 1.125, 0.806, 0.673` ms

All three rows are identical — the secondary axis @ `0xD1060` is a
fuel-pressure delta (raw `−1000/0/+1000`, scaled `psirelative` to ±19.34 psi)
and is unused on this ROM. Keep all three rows identical unless you have
pressure-referenced data.

Dead time is a property of the injector and its driver circuit, not of a flow
ratio. Bigger injectors usually have *longer* dead time, so applying k here
would push the error in exactly the wrong direction. Take the new curve off the
data sheet and interpolate onto the 6.5/9/11.5/14/16.5 V axis (or move the axis
points — they are editable floats).

Dead time is also where a big-injector swap most visibly goes wrong: it
dominates at idle and light cruise, where the commanded pulse is short and the
dead-time fraction is large. Expect idle and tip-out to be the first places a
wrong latency curve shows up, well before anything at load.

---

## 5. Do NOT touch

### Misidentified — these are not injector tables at all

`0xD39A8` "Low Pulse Width Fuel Injector Compensation", its axis `0xD3988`, and
the two scalars `0xD2D28` / `0xD2D2C`.

The XML presents this as an 8-cell compensation on a 0.7–4.5 ms pulse-width axis,
sitting at **−100% on every cell** with the gates wide open — i.e. exactly what a
broken calibration looks like, and exactly the thing you would want on a big
injector swap. It is none of those things:

- Taken at face value the definition **describes a ROM that could not run**: all
  eight cells read −100%, and the two gates are at 10000 RPM / 10.0 ms, i.e.
  always satisfied. That is a total fuel cut below 4.5 ms of pulse width. The
  car idles. So something in the binding is wrong before any disassembly.
- The axis `0xD3988` is **engine speed** (700, 800, 900, 1400, 2000, 2500, 3500,
  4500 RPM). The only consumer is `0x0434C2`, and the lookup engine `0xBE874`
  takes its search key in **FR4**, which at that point holds `[0xFFFF6624]` —
  `rpm_current`, the most-referenced float in the ROM (301 sites) and a logged
  channel. FR4 is written exactly once in that function, at `0x04347C`, and only
  read afterwards. The search key really is FR0-from-FR4: `0xBECA8` walks the
  axis with `fmov.s @(r0,r1),fr1 / fcmp/gt fr0,fr1` and interpolates
  `(fr0−fr1)/(fr2−fr1)`, and `0xBE874` sets FR0 from FR4 in the delay slot.
- The function never reads `0xFFFF7324` (`last_calc_base_pulse_width`), which is
  the ROM's actual base-pulse-width variable and the feed a low-pulse-width
  compensation would have to use.

> **Retracted.** An earlier version of this file argued that 700/800/900/1400/…
> is "a bizarre axis" read as milliseconds. That argument is wrong and is
> withdrawn. 0.7/0.8/0.9/1.4/2.0/2.5/3.5/4.5 ms is a *perfectly sensible* low
> pulse width axis — fine steps through the non-linear region, coarser above it.
> The magnitudes do not discriminate either: this ROM stores a genuine ms axis
> as raw ×1000 (`0xD0760` holds 1000.0…16000.0 for 1–16 ms), so raw 700 = 0.7 ms
> is exactly the right convention. **Only the feed decides this.** Keeping a
> plausibility argument that does not hold would have been the same mistake this
> table already caused once.
- `0xD2D28` and `0xD2D2C` are the **lower and upper bounds of an RPM window**,
  both compared against FR4. `0xD2D2C` reading as "10.0 ms" is the XML applying
  `x*.001` to the number 10000. The window is `[10000, 10000)` — empty.
- The result byte goes to `0xFFFF80EC`, which `ram_reference.txt` calls
  `timing_comp_lowpw_state` — an **ignition** state, not a fuel path.
- The gates are the map-switch constants `0xD2A0C` (0.8798) and `0xD2A1C` (80.0),
  shared with the map-switching function at `0x03F49A`. And `0xD2D24` = 0.0 is
  tested as "continue only if `0.0 > vehicle speed`", so the branch is dead
  twice over.

Full derivation in `docs/corrections.md` item 36. The definition XMLs still
carry the wrong names — ECUFlash owns those files, so fixing them means editing
in its UI and pulling with `.\scripts\sync_defs.ps1 -Pull`, and the repo is
already ~37 tables ahead of ECUFlash so that pull needs checking first.

### Correctly named, but dimensionless — no rescale

| Address | Table | Why not |
|---|---|---|
| `0xCF704` `0xCF6B0` `0xCC868` `0xCC89C` `0xCC8BC` | Cranking Fuel IPW Compensation (RPM / MAP / Accel / IAT) | percentages on the cranking IPW |
| `0xCD118` `0xCD14C` `0xCD155` `0xCEDE0` `0xCEE00` `0xCEE40` | Tip-in Enrichment Compensation (RPM / Boost Error / ECT A–D) | percentages on the tip-in adder |
| `0xCC830` `0xCF8B8` `0xCF95C` | Min Primary Base Enrichment 1 | lambda-offset additive (0.5), not ms |
| `0xCEED0` | Overrun Fueling RPM Resume Threshold | 1000 RPM despite the scaling's name |
| `0xD8C9C` | MAF Sensor Scaling | airflow, upstream of fuelling |
| `0xD0244` `0xD0404` `0xCFD30` … | Primary Open Loop Fueling (all) | target AFR |
| `0xD91E0` | Ignition Dwell | in ms, but it is coil dwell — not injector |

`0xD91E0` is the one to watch when grepping: it matches an "everything in ms"
search and has nothing to do with fuel.

---

## 6. Adjacent, not part of the rescale

- **Fuel Pump Duty High (Running)** @ `0x4BBAC` = **66.7%** (Low/Idle `0x4BBB0`
  = 33.3%, Prime/Cranking `0x4BBA0` = 100%). Not injector-scaled, but bigger
  injectors at high IDC raise rail demand. Worth a look if the new setup targets
  meaningfully more fuel flow than the current ~100% IDC ceiling at ~17 psi.
- **Per-injector trim data** — see the open question in §3.
- **Nothing in the MAF, AFR, boost or timing layers changes.** If the rescale is
  right, logged AFR before and after should be indistinguishable. That is the
  test.

---

## 7. After the swap

The scaling is right when short-term fuel trim and AFL/AFC land back where they
were before the swap, across the whole load range — not just at cruise. Check in
this order, because each stage isolates a different constant:

1. **Cold crank and idle** — exercises `0xD106C` dead time and the cranking IPW
   tables. Wrong dead time shows here first.
2. **Warm idle and light cruise** — dead time again, plus the low end of the
   per-injector comp axis.
3. **Steady cruise, closed loop** — this is where `0xCBE0C` itself is judged.
   A uniform trim offset across all cells means the flow constant is off; a
   trim that varies with load means something else is.
4. **Tip-in** — `0xCED50` / `0xCEDBC`. Given the open cusp-knock work
   (`docs/tune-state.md`), do not change tip-in shape in the same rev as the
   rescale, or the two variables will be inseparable.
5. **Open loop under boost** — last, and only after 1–4 are clean.
