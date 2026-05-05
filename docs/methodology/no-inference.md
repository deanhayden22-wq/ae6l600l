# Methodology — don't infer-and-assert

Captured 2026-05-04. Verify with data before stating; flag uncertainty
when present. This is the rigor rule that everything else in `docs/`
relies on.

## The principle

Bad inferences propagate into bad design decisions. When the data is
saturated, lossy, or absent, say so — don't paper over it with a
confident-sounding claim.

The project's CLAUDE.md captures this directly:

> "you have access to multiple logs and disassembly, use it. when you
> present something I am going to push back, defend yourself. if you
> have a question, ask, don't make any assumptions."

## How to apply

1. **When reverse-engineering values from saturated/lossy data, state
   the ambiguity.** Example: `TPS = 102.4` means `ratio ≥ 1.0`, which
   could be any RQTQ from Base on up. Don't claim a specific RQTQ from
   a saturated TPS.
2. **When subsetting data, name what's included and excluded with a
   reason.** "Used 7 of 13 logs because X" not silent subsetting.
3. **When making a claim, lead with the verification path.** Numbers
   first. "From log0004 at t=15336s: APP=11.76, TPS=17.25, dRQTQ=4.82
   …" — not "the cliff is causing oscillation" without numbers.
4. **Defend the position when challenged — don't immediately fold.**
   The pushback is meant to test the claim, not to demand capitulation.
   If the claim is sound, defend it with data. If it isn't, retract
   and say what changed.
5. **Ask before assuming.** When SI-DRIVE map identity is unclear,
   check. When the log subset is in question, confirm.

## Past examples where this rule caught errors

- A claim that the user "lowered col 14 RQTQ to Base" was reverse-
  engineered from a TPS table where the relevant cells read 102.4 —
  saturated. Any RQTQ ≥ Base produces TPS=102.4. The actual RQTQ wasn't
  lowered. The right move would have been to flag the ambiguity instead
  of assert.
- An analysis silently used 7 of 13 logs for a MAF/driving profile —
  the user pushed back ("can you confirm you are using all logs and
  not just the 1"). The right move would have been to name the subset
  with a reason up front, or use all 13.

## Why it matters here specifically

Tuning decisions on this car are getting made on top of these analyses.
Knock margin, cruise smoothness, boost target — every one of these has
real consequences. The rigor isn't pedantry; it's how decisions don't
get poisoned by silent assumption.
