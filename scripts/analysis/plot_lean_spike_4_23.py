"""
Plots for the 4-23 lean-spike write-up.

For each log produces:
  - AFR trace vs time with accel-zone mask + lean events highlighted + MAP/wgdc overlay
  - AFR distribution histogram (accel zone)
  - AFR vs RPM scatter colored by load (accel zone)
  - Worst-spike zoom: AFR + wbo2 + load + IPW + Throttle around the peak lean event
"""

import csv
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

REPO = Path(__file__).resolve().parents[2]
LOGS = REPO / "logs" / "4-23"

RPM_MIN, RPM_MAX = 3000, 5000
LOAD_MIN, LOAD_MAX = 0.5, 0.9
MAF_MIN, MAF_MAX = 40, 70
AFR_LEAN = 13.0

SAVE_DIR = REPO / "logs" / "4-23" / "plots"
SAVE_DIR.mkdir(parents=True, exist_ok=True)
# Also copy final PNGs to the shared workspace folder at the end
SHARE_DIR = SAVE_DIR


def load(path):
    rows = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            try:
                rpm = float(r["RPM"])
                maf = float(r["MAF"])
                rows.append({
                    "sample": int(r["sample"]),
                    "time":   float(r["time"]),
                    "AFR":    float(r["AFR"]),
                    "wbo2":   float(r["wbo2"]),
                    "RPM":    rpm,
                    "MAF":    maf,
                    "load":   (maf * 60.0 / rpm) if rpm > 0 else 0.0,
                    "Throttle": float(r["Throttle"]),
                    "MAP":    float(r["MAP"]),
                    "wgdc":   float(r["wgdc"]),
                    "IPW":    float(r["IPW"]),
                    "CL/OL":  int(r["CL/OL"]),
                    "AFC":    float(r["AFC"]),
                    "FBKC":   float(r["FBKC"]),
                })
            except (ValueError, KeyError):
                continue
    return rows


def in_accel(r):
    return (RPM_MIN <= r["RPM"] <= RPM_MAX
            and LOAD_MIN <= r["load"] <= LOAD_MAX
            and MAF_MIN  <= r["MAF"]  <= MAF_MAX)


def make_plots(name, rows):
    t = np.array([r["time"] - rows[0]["time"] for r in rows])
    afr = np.array([r["AFR"] for r in rows])
    rpm = np.array([r["RPM"] for r in rows])
    maf = np.array([r["MAF"] for r in rows])
    load_ = np.array([r["load"] for r in rows])
    thrt = np.array([r["Throttle"] for r in rows])
    map_ = np.array([r["MAP"] for r in rows])
    wgdc = np.array([r["wgdc"] for r in rows])
    wbo2 = np.array([r["wbo2"] for r in rows])
    ipw  = np.array([r["IPW"] for r in rows])
    afc  = np.array([r["AFC"] for r in rows])

    accel_mask = np.array([in_accel(r) for r in rows])
    lean_mask  = accel_mask & (afr > AFR_LEAN)

    # ------- Plot 1: AFR trace over time with accel + lean markers -------
    fig, ax = plt.subplots(3, 1, figsize=(14, 9), sharex=True)

    ax[0].plot(t, afr, color="#444", lw=0.6, label="AFR")
    # accel zone as light band
    in_accel_idx = np.where(accel_mask)[0]
    if len(in_accel_idx):
        ax[0].scatter(t[in_accel_idx], afr[in_accel_idx],
                      s=6, c="#2a9d8f", alpha=0.5, label="accel zone")
    lean_idx = np.where(lean_mask)[0]
    if len(lean_idx):
        ax[0].scatter(t[lean_idx], afr[lean_idx],
                      s=16, c="#e63946", zorder=5, label=f"AFR > {AFR_LEAN} (accel zone)")
    ax[0].axhline(14.7, color="k", ls=":", lw=0.6, alpha=0.6)
    ax[0].axhline(AFR_LEAN, color="#e63946", ls=":", lw=0.6, alpha=0.6)
    ax[0].set_ylabel("AFR")
    ax[0].set_ylim(10, 21)
    ax[0].legend(loc="upper right", fontsize=8)
    ax[0].set_title(f"{name} — AFR trace (4-23, stock 20.8 ROM)")

    ax[1].plot(t, rpm, color="#264653", lw=0.7, label="RPM")
    axb = ax[1].twinx()
    axb.plot(t, load_, color="#e76f51", lw=0.7, alpha=0.8, label="load (g/rev)")
    ax[1].set_ylabel("RPM", color="#264653")
    axb.set_ylabel("load (g/rev)", color="#e76f51")
    ax[1].axhspan(RPM_MIN, RPM_MAX, color="#2a9d8f", alpha=0.08)

    ax[2].plot(t, map_, color="#6a4c93", lw=0.7, label="MAP (psi)")
    axc = ax[2].twinx()
    axc.plot(t, thrt, color="#457b9d", lw=0.7, alpha=0.8, label="Throttle %")
    ax[2].set_ylabel("MAP (psi)", color="#6a4c93")
    axc.set_ylabel("Throttle %", color="#457b9d")
    ax[2].set_xlabel("time since log start (s)")

    plt.tight_layout()
    out = SAVE_DIR / f"{name}_afr_trace.png"
    plt.savefig(out, dpi=120)
    plt.close(fig)
    print(f"  wrote {out}")

    # ------- Plot 2: AFR histogram in accel zone -------
    afr_a = afr[accel_mask]
    if len(afr_a):
        fig, ax = plt.subplots(figsize=(8, 4.5))
        ax.hist(afr_a, bins=np.arange(10.5, 17.5, 0.2), color="#2a9d8f",
                edgecolor="#1d3557", alpha=0.85)
        ax.axvline(14.7, color="k", ls="--", lw=0.8, label="14.7 (stoich)")
        ax.axvline(AFR_LEAN, color="#e63946", ls="--", lw=0.8, label=f"{AFR_LEAN} lean threshold")
        ax.set_xlabel("AFR")
        ax.set_ylabel("samples")
        ax.set_title(f"{name} — AFR distribution in accel zone (n={len(afr_a)})")
        ax.legend()
        plt.tight_layout()
        out = SAVE_DIR / f"{name}_afr_hist.png"
        plt.savefig(out, dpi=120)
        plt.close(fig)
        print(f"  wrote {out}")

    # ------- Plot 3: AFR vs RPM scatter, colored by load, in accel zone -------
    if len(afr_a):
        fig, ax = plt.subplots(figsize=(8, 5))
        sc = ax.scatter(rpm[accel_mask], afr[accel_mask],
                        c=load_[accel_mask], cmap="viridis",
                        s=14, alpha=0.8, edgecolor="k", linewidth=0.2)
        cb = plt.colorbar(sc, ax=ax, label="load (g/rev)")
        ax.axhline(14.7, color="k", ls=":", lw=0.6)
        ax.axhline(AFR_LEAN, color="#e63946", ls=":", lw=0.6)
        ax.set_xlabel("RPM")
        ax.set_ylabel("AFR")
        ax.set_title(f"{name} — AFR vs RPM (accel zone only, colored by load)")
        plt.tight_layout()
        out = SAVE_DIR / f"{name}_afr_vs_rpm.png"
        plt.savefig(out, dpi=120)
        plt.close(fig)
        print(f"  wrote {out}")

    # ------- Plot 4: worst-spike zoom -------
    if lean_idx.size:
        worst = lean_idx[np.argmax(afr[lean_idx])]
        start = max(0, worst - 40)
        end   = min(len(rows), worst + 40)
        sl = slice(start, end)

        fig, ax = plt.subplots(2, 1, figsize=(12, 7), sharex=True)
        ax[0].plot(t[sl], afr[sl],  color="#e63946", lw=1.3, label="AFR")
        ax[0].plot(t[sl], wbo2[sl], color="#6a4c93", lw=0.9, alpha=0.8,
                   label="wbo2 (raw voltage/scaled)")
        ax[0].axhline(14.7, color="k", ls=":", lw=0.6)
        ax[0].axhline(AFR_LEAN, color="#e63946", ls=":", lw=0.6)
        ax[0].axvline(t[worst], color="k", ls="--", lw=0.7, alpha=0.5)
        ax[0].set_ylabel("AFR / wbo2")
        ax[0].legend(loc="upper right", fontsize=8)
        ax[0].set_title(f"{name} — worst lean-spike zoom @ t={t[worst]:.2f}s  "
                        f"(peak AFR={afr[worst]:.2f})")

        ax[1].plot(t[sl], load_[sl], color="#2a9d8f", lw=1.1, label="load (g/rev)")
        ax[1].plot(t[sl], ipw[sl] / max(1e-9, ipw[sl].max()), color="#e76f51",
                   lw=0.9, alpha=0.7, label="IPW (norm)")
        axr = ax[1].twinx()
        axr.plot(t[sl], thrt[sl], color="#457b9d", lw=0.9, alpha=0.7, label="Throttle %")
        axr.plot(t[sl], map_[sl],  color="#6a4c93", lw=0.9, alpha=0.7, label="MAP psi")
        ax[1].set_ylabel("load / IPW(norm)")
        axr.set_ylabel("Throttle % / MAP psi")
        ax[1].set_xlabel("time (s)")
        ax[1].legend(loc="upper left", fontsize=8)
        axr.legend(loc="upper right", fontsize=8)
        plt.tight_layout()
        out = SAVE_DIR / f"{name}_worst_spike_zoom.png"
        plt.savefig(out, dpi=120)
        plt.close(fig)
        print(f"  wrote {out}")


def main():
    for p in [LOGS / "log0001.csv", LOGS / "log0002.csv"]:
        print(f"\n{p.name}:")
        rows = load(p)
        make_plots(p.stem, rows)

    print(f"\nAll plots saved to: {SAVE_DIR}")


if __name__ == "__main__":
    main()
