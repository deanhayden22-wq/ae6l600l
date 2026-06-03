"""5-28 20.15 log: is FLKC/FBKC firing correlated with overboost or with IAT?

Disassembly says the knock detector reads RPM, IAT, barometric pressure and the
knock-sensor ADC only -- never manifold pressure / mrp / load. This script tests
that empirically: does knock cluster on overboost margin (mrp - Trgt_Boost) or on
IAT (the only indirect path: hot intake -> lower RPM*IAT threshold)?
"""
import csv, statistics as st

PATH = r"logs/5-28 20.15/log0001.csv"

rows = []
with open(PATH, newline="") as fh:
    r = csv.DictReader(fh)
    for d in r:
        def f(k):
            try: return float(d[k])
            except (ValueError, KeyError, TypeError): return None
        rows.append({
            "t": f("time"), "rpm": f("RPM"), "load": f("load"), "mph": f("MPH"),
            "iat": f("IAT"), "map": f("MAP"), "mrp": f("mrp"), "tgt": f("Trgt_Boost"),
            "iam": f("IAM"), "flkc": f("FLKC"), "fbkc": f("FBKC"), "avcs": f("avcs"),
            "wgdc": f("wgdc"), "knock": f("KNOCK_FLAG"), "ect": f("ECT"),
            "timing": f("Timing"), "clol": f("CL/OL"),
        })

n = len(rows)
print(f"rows: {n}")

# --- 1. AVCS lockout check (known post-reflash quirk) ---
warm_moving = [x for x in rows if x["rpm"] and x["rpm"] > 2000 and x["ect"] and x["ect"] > 70]
avcs_vals = [x["avcs"] for x in warm_moving if x["avcs"] is not None]
if avcs_vals:
    avcs_vals.sort()
    p95 = avcs_vals[int(0.95 * (len(avcs_vals) - 1))]
    print(f"\n=== AVCS engagement (RPM>2000, ECT>70) ===")
    print(f"  samples={len(avcs_vals)}  median={st.median(avcs_vals):.1f}  "
          f"p95={p95:.1f}  max={max(avcs_vals):.1f}")
    print(f"  {'LOCKED OUT (p95<12) -> knock data contaminated' if p95 < 12 else 'AVCS engaging normally'}")

# --- 2. knock event counts ---
fbkc_ev = [x for x in rows if x["fbkc"] is not None and x["fbkc"] < 0]
flkc_neg = [x for x in rows if x["flkc"] is not None and x["flkc"] < 0]
knockflag = [x for x in rows if x["knock"] and x["knock"] != 0]
print(f"\n=== knock activity ===")
print(f"  FBKC<0 samples: {len(fbkc_ev)}  ({100*len(fbkc_ev)/n:.2f}%)")
print(f"  FLKC<0 samples: {len(flkc_neg)}  ({100*len(flkc_neg)/n:.2f}%)")
print(f"  KNOCK_FLAG!=0 : {len(knockflag)}")
iam_min = min((x["iam"] for x in rows if x["iam"] is not None), default=None)
print(f"  IAM min: {iam_min}")

# --- 3. overboost margin at FBKC events vs everywhere ---
def margin(x):
    if x["mrp"] is not None and x["tgt"] is not None:
        return x["mrp"] - x["tgt"]
    return None

# only consider "in boost" samples (mrp > spring ~ -? use mrp>5 psi as 'loaded')
inboost = [x for x in rows if x["mrp"] is not None and x["mrp"] > 5]
print(f"\n=== overboost margin (mrp - Trgt_Boost), psi ===")
for label, sub in [("all in-boost (mrp>5)", inboost),
                   ("FBKC<0 events", [x for x in fbkc_ev if x["mrp"] and x["mrp"] > 5])]:
    m = [margin(x) for x in sub if margin(x) is not None]
    if m:
        m.sort()
        over = sum(1 for v in m if v > 1.0)  # >1 psi over target
        print(f"  {label:24s} n={len(m):6d}  median={st.median(m):+.2f}  "
              f"p90={m[int(0.9*(len(m)-1))]:+.2f}  max={max(m):+.2f}  "
              f"%>+1psi over tgt={100*over/len(m):.1f}%")

# --- 4. IAT at FBKC events vs in-boost baseline (the indirect path) ---
print(f"\n=== IAT (deg) at knock vs baseline ===")
for label, sub in [("all in-boost (mrp>5)", inboost),
                   ("FBKC<0 events", [x for x in fbkc_ev if x["mrp"] and x["mrp"] > 5])]:
    iats = [x["iat"] for x in sub if x["iat"] is not None]
    if iats:
        iats.sort()
        print(f"  {label:24s} n={len(iats):6d}  median={st.median(iats):.0f}  "
              f"p90={iats[int(0.9*(len(iats)-1))]:.0f}  max={max(iats):.0f}")

# --- 5. dump the FBKC events: are they overboost, or hot-IAT, or neither? ---
print(f"\n=== FBKC<0 events detail (in-boost) ===")
print(f"  {'time':>8} {'rpm':>5} {'load':>5} {'mph':>4} {'mrp':>6} {'tgt':>6} "
      f"{'margin':>6} {'iat':>4} {'wgdc':>5} {'fbkc':>5} {'flkc':>5} {'tmg':>4}")
ev = [x for x in fbkc_ev if x["mrp"] and x["mrp"] > 5]
for x in ev[:60]:
    print(f"  {x['t']:>8.1f} {x['rpm']:>5.0f} {x['load']:>5.2f} {x['mph']:>4.0f} "
          f"{x['mrp']:>6.2f} {x['tgt']:>6.2f} {margin(x):>+6.2f} {x['iat']:>4.0f} "
          f"{x['wgdc']:>5.1f} {x['fbkc']:>5.2f} {x['flkc']:>5.2f} {x['timing']:>4.0f}")
print(f"  ... total in-boost FBKC<0 events: {len(ev)}")
