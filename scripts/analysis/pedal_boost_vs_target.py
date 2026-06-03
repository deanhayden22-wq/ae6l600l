"""
Empirical check: on the 25% and 31% pedal paths, what boost (mrp) do we ACTUALLY
make vs what the ECU targets (Trgt_Boost)?  And does the low-pedal target even
matter, or is boost just set by airflow / the 15 psi spring?

Reads logged Accelerator (pedal %), Trgt_Boost (final target incl comps), mrp
(actual boost, psi rel), RQTQ, RPM, etc. straight from the logs -- no modeling.
Splits steady vs accel-transient because a pedal % held at cruise behaves totally
differently from the same pedal % swept open during a pass.
"""
import csv, statistics as st
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPRING = 15.0

LOGS = [
    ("logs/5-22 20.13/log0001.csv", "20.13"),
    ("logs/5-23 20.14/log0001.csv", "20.14"),
    ("logs/5-23 20.14/log0003.csv", "20.14"),
    ("logs/5-25 20.15/log0001.csv", "20.15"),
    ("logs/5-26 20.15/log0001.csv", "20.15"),
    ("logs/5-28 20.15/log0001.csv", "20.15"),
    ("logs/5-30 20.16/log0001.csv", "20.16"),
]


def fnum(d, k):
    try:
        return float(d[k])
    except (ValueError, KeyError, TypeError):
        return None


def load_all():
    rows = []
    for rel, rev in LOGS:
        p = ROOT / rel
        if not p.exists():
            print("MISSING", rel); continue
        with open(p, newline="") as fh:
            rd = csv.DictReader(fh)
            if not rd.fieldnames or "Accelerator" not in rd.fieldnames or "Trgt_Boost" not in rd.fieldnames:
                print("skip (schema)", rel, rd.fieldnames[:6] if rd.fieldnames else None); continue
            prev_t = prev_rpm = None
            for d in rd:
                t = fnum(d, "time"); rpm = fnum(d, "RPM")
                drpm_dt = None
                if t is not None and rpm is not None and prev_t is not None and t > prev_t:
                    drpm_dt = (rpm - prev_rpm) / (t - prev_t)
                if t is not None and rpm is not None:
                    prev_t, prev_rpm = t, rpm
                rows.append(dict(
                    rev=rev, t=t, rpm=rpm, ped=fnum(d, "Accelerator"),
                    thr=fnum(d, "Throttle"), rqtq=fnum(d, "RQTQ"),
                    mrp=fnum(d, "mrp"), tgt=fnum(d, "Trgt_Boost"),
                    load=fnum(d, "load"), mph=fnum(d, "MPH"), ect=fnum(d, "ECT"),
                    wgdc=fnum(d, "wgdc"), clol=fnum(d, "CL/OL"), drpm_dt=drpm_dt,
                ))
    return rows


def pct(vals, q):
    vals = sorted(vals)
    return vals[int(q * (len(vals) - 1))] if vals else float("nan")


def main():
    rows = load_all()
    print(f"total rows: {len(rows)}")
    by_rev = {}
    for x in rows:
        by_rev.setdefault(x["rev"], 0); by_rev[x["rev"]] += 1
    print("by rev:", by_rev)

    # warm & moving, valid boost/target
    wm = [x for x in rows if x["ect"] and x["ect"] > 70 and x["mph"] and x["mph"] > 10
          and x["rpm"] and x["rpm"] > 1500 and x["ped"] is not None
          and x["mrp"] is not None and x["tgt"] is not None]
    print(f"warm & moving samples: {len(wm)}\n")

    fig, axes = plt.subplots(1, 2, figsize=(16, 6.5), sharey=True)

    for col, (band, ax) in enumerate(zip([25.0, 31.0], axes)):
        sub = [x for x in wm if abs(x["ped"] - band) <= 2.5]
        steady = [x for x in sub if x["drpm_dt"] is not None and abs(x["drpm_dt"]) < 250]
        accel = [x for x in sub if x["drpm_dt"] is not None and x["drpm_dt"] > 600]

        print(f"================  {band:.0f}% pedal  (±2.5)  ================")
        print(f"  n={len(sub)}   steady(|dRPM/dt|<250)={len(steady)}   accel(>600 rpm/s)={len(accel)}")
        for label, s in [("ALL", sub), ("STEADY", steady), ("ACCEL-transient", accel)]:
            if not s:
                continue
            mrp = [x["mrp"] for x in s]; tgt = [x["tgt"] for x in s]
            marg = [x["mrp"] - x["tgt"] for x in s]
            track = sum(1 for m in marg if abs(m) <= 1.5)
            under = sum(1 for m in marg if m < -1.5)
            over = sum(1 for m in marg if m > 1.5)
            atspring = sum(1 for x in s if x["mrp"] >= SPRING)
            print(f"   [{label:15s}] tgt med={st.median(tgt):+5.1f}  mrp med={st.median(mrp):+5.1f}  "
                  f"mrp p90={pct(mrp,0.9):+5.1f}  margin med={st.median(marg):+5.1f}  "
                  f"| track±1.5={100*track/len(s):4.0f}%  under={100*under/len(s):4.0f}%  "
                  f"over={100*over/len(s):4.0f}%  mrp>=15={100*atspring/len(s):4.0f}%")

        # RPM-binned medians
        print(f"   {'RPMbin':>7} {'n':>5} {'tgt':>6} {'mrp':>6} {'gap':>6} {'mph':>5}")
        bins = list(range(1500, 6500, 500))
        for lo in bins:
            hi = lo + 500
            b = [x for x in sub if lo <= x["rpm"] < hi]
            if len(b) < 8:
                continue
            tg = st.median([x["tgt"] for x in b]); mr = st.median([x["mrp"] for x in b])
            mph = st.median([x["mph"] for x in b])
            print(f"   {lo:>4}-{hi:<4} {len(b):>5} {tg:>6.1f} {mr:>6.1f} {mr-tg:>+6.1f} {mph:>5.0f}")
        print()

        # plot
        rp = [x["rpm"] for x in sub]; mr = [x["mrp"] for x in sub]
        ax.scatter(rp, mr, s=6, alpha=0.18, color="tab:blue", label="actual mrp (each sample)")
        # binned medians
        bx, btg, bmr = [], [], []
        for lo in range(1500, 6500, 250):
            b = [x for x in sub if lo <= x["rpm"] < lo + 250]
            if len(b) < 6:
                continue
            bx.append(lo + 125); btg.append(st.median([x["tgt"] for x in b])); bmr.append(st.median([x["mrp"] for x in b]))
        ax.plot(bx, btg, "-", color="red", lw=2.4, label="median Trgt_Boost (asked)")
        ax.plot(bx, bmr, "-o", color="navy", lw=2.4, ms=4, label="median actual mrp (got)")
        ax.axhline(SPRING, color="k", ls="--", lw=1.3, label="15 psi spring")
        ax.axhline(13, color="gray", ls=":", lw=1.2, label="13 psi TD gate")
        ax.set_title(f"{band:.0f}% pedal  (n={len(sub)})")
        ax.set_xlabel("RPM"); ax.grid(alpha=0.3)
        if col == 0:
            ax.set_ylabel("boost (psi rel.)")
        ax.legend(fontsize=8, loc="upper left")
        ax.set_ylim(-12, 24)

    fig.suptitle("Actual boost (mrp) vs target on the 25% & 31% pedal paths — warm & moving, pooled 20.13–20.16",
                 fontsize=13)
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    out = ROOT / "scripts" / "analysis" / "plots" / "pedal_boost_vs_target.png"
    fig.savefig(out, dpi=120)
    print("wrote", out)


if __name__ == "__main__":
    main()
