#!/usr/bin/env python3
"""Build cruise-residency heatmaps for OL, Base Timing, Knock Cruise, CL Fueling Comp A.
20.9 vs 20.10 side-by-side, sharing the same cruise filter as the AVCS analysis.
"""
import csv, json, os, struct, sys
from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.colors import LogNorm
from matplotlib.patches import Rectangle
import matplotlib.lines as mlines

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "logs" / "4-25" / "plots"
OUT.mkdir(parents=True, exist_ok=True)
ROM_DIR = REPO / "rom"
LOG = REPO / "logs" / "4-25" / "4-25 full.csv"
ROMS = {
    "20.9":  str(ROM_DIR / "AE5L600L 20g rev 20.9 tiny wrex.bin"),
    "20.10": str(ROM_DIR / "AE5L600L 20g rev 20.10 tiny wrex.bin"),
}

# (table_addr, load_addr, n_load, rpm_addr, n_rpm, dtype_word, scaler_fn, fmt, name, cliff_thresh)
def af_from_raw(raw):  return 14.7 / (1.0 + raw * 0.0078125)
def af_pts_from_raw(raw): return raw * 0.000224304213 - 7.35
def base_tim_from_raw(raw): return raw * 0.3515625 - 20.0
def knock_adv_from_raw(raw): return raw * 0.3515625

TABLES = {
    "OL_B_Low": dict(
        addr=0xd0244, load_addr=0xd01b8, nx=17, rpm_addr=0xd01fc, ny=18,
        word="B", scaler=af_from_raw, fmt="{:.2f}", units="AFR", cliff=0.5),
    "OL_B_High": dict(
        addr=0xd0404, load_addr=0xd0378, nx=17, rpm_addr=0xd03bc, ny=18,
        word="B", scaler=af_from_raw, fmt="{:.2f}", units="AFR", cliff=0.5),
    "Base_Timing_Cruise": dict(
        addr=0xd4714, load_addr=0xd4688, nx=17, rpm_addr=0xd46cc, ny=18,
        word="B", scaler=base_tim_from_raw, fmt="{:.1f}", units="deg BTDC", cliff=3.0),
    "Knock_Adv_Max_Cruise": dict(
        addr=0xd5904, load_addr=0xd5878, nx=17, rpm_addr=0xd58bc, ny=18,
        word="B", scaler=knock_adv_from_raw, fmt="{:.1f}", units="deg adv", cliff=2.0),
    "CL_Fuel_Comp_A_Load": dict(
        addr=0xd14d0, load_addr=0xd147c, nx=11, rpm_addr=0xd14a8, ny=10,
        word="H", scaler=af_pts_from_raw, fmt="{:+.2f}", units="AFR pts", cliff=0.30),
}

def read_floats(buf, off, n):
    return np.array(struct.unpack(">" + "f"*n, buf[off:off+4*n]))

def read_table(buf, off, nx, ny, word, scaler):
    sz = 1 if word == "B" else 2
    raw = struct.unpack(">" + word*(nx*ny), buf[off:off+sz*nx*ny])
    a = np.array([[raw[y*nx + x] for x in range(nx)] for y in range(ny)], dtype=float)
    return scaler(a)

# Read all tables from both ROMs
tab = {}
for tag, path in ROMS.items():
    with open(path, "rb") as f:
        buf = f.read()
    tab[tag] = {}
    for tname, spec in TABLES.items():
        tab[tag][tname] = dict(
            load=read_floats(buf, spec["load_addr"], spec["nx"]),
            rpm=read_floats(buf, spec["rpm_addr"], spec["ny"]),
            T=read_table(buf, spec["addr"], spec["nx"], spec["ny"], spec["word"], spec["scaler"]),
        )

# --- Read log + cruise filter (same as AVCS analysis) ---
data = []
with open(LOG) as f:
    r = csv.DictReader(f)
    for row in r:
        try:
            data.append((float(row["time"]), float(row["RPM"]), float(row["load"]),
                         float(row["MPH"]), float(row["Accelerator"]),
                         float(row["Throttle"]), int(row["CL/OL"])))
        except Exception:
            continue
arr = np.array(data, dtype=float)
t   = arr[:,0]; rpm = arr[:,1]; load = arr[:,2]; mph = arr[:,3]
accel = arr[:,4]; thr = arr[:,5]; clol = arr[:,6].astype(int)
dt = np.diff(t, prepend=t[0]); dt = np.clip(dt, 0, 0.5)
def rs(x, w=20):
    if len(x) < w: return np.zeros_like(x)
    c = np.cumsum(np.insert(x, 0, 0)); c2 = np.cumsum(np.insert(x*x, 0, 0))
    s = (c[w:] - c[:-w]) / w; s2 = (c2[w:] - c2[:-w]) / w
    var = np.maximum(s2 - s*s, 0); o = np.zeros_like(x); o[w-1:] = np.sqrt(var); return o
cruise = (clol == 8) & (mph > 20) & (rs(rpm) < 100) & (rs(accel) < 1.0) & (rs(thr) < 1.0)
print(f"Cruise samples: {cruise.sum()} / {len(cruise)}  ({dt[cruise].sum():.0f} s)", flush=True)

def edges(axis):
    e = np.empty(len(axis)+1)
    e[1:-1] = (axis[:-1] + axis[1:]) / 2
    e[0]    = axis[0] - (axis[1]-axis[0])/2
    e[-1]   = axis[-1] + (axis[-1]-axis[-2])/2
    return e

def cliffs(T, thresh):
    NY, NX = T.shape
    out = []
    for y in range(NY):
        for x in range(NX):
            if x+1 < NX and abs(T[y,x+1]-T[y,x]) >= thresh: out.append(((y,x),(y,x+1)))
            if y+1 < NY and abs(T[y+1,x]-T[y,x]) >= thresh: out.append(((y,x),(y+1,x)))
    return out

def nbmax(T, y, x):
    NY, NX = T.shape; nb=[]
    if x>0: nb.append(abs(T[y,x]-T[y,x-1]))
    if x<NX-1: nb.append(abs(T[y,x]-T[y,x+1]))
    if y>0: nb.append(abs(T[y,x]-T[y-1,x]))
    if y<NY-1: nb.append(abs(T[y,x]-T[y+1,x]))
    return max(nb) if nb else 0.0

def render_table(tname, spec):
    T9  = tab["20.9"][tname]["T"]
    T10 = tab["20.10"][tname]["T"]
    load_axis = tab["20.9"][tname]["load"]
    rpm_axis  = tab["20.9"][tname]["rpm"]
    NY, NX = T9.shape
    le, re_ = edges(load_axis), edges(rpm_axis)

    H, _, _ = np.histogram2d(rpm[cruise], load[cruise],
                             bins=[re_, le], weights=dt[cruise])

    c9  = cliffs(T9,  spec["cliff"])
    c10 = cliffs(T10, spec["cliff"])

    # Diff cells
    diff_cells = [(y,x, T10[y,x]-T9[y,x]) for y in range(NY) for x in range(NX)
                  if abs(T10[y,x]-T9[y,x]) >= 1e-3]

    # Per-table report
    print(f"\n=== {tname} ({spec['units']}) — cliff threshold={spec['cliff']} ===", flush=True)
    print(f"  shape: {NY} RPM x {NX} Load   "
          f"residency in grid: {H.sum():.0f}s   max-cell: {H.max():.0f}s", flush=True)
    print(f"  cliffs >=thresh: 20.9={len(c9)}  20.10={len(c10)}", flush=True)
    print(f"  cells changed 20.9->20.10: {len(diff_cells)}/{NY*NX}", flush=True)
    if diff_cells:
        print("    20.10 - 20.9 changes:")
        for y,x,d in diff_cells[:25]:
            print(f"      rpm={rpm_axis[y]:.0f}  load={load_axis[x]:.2f}  "
                  f"20.9={T9[y,x]:.3f}  20.10={T10[y,x]:.3f}  delta={d:+.3f}", flush=True)
    # cruise-on-cliff in 20.10
    print("  cruise-on-cliff (>=5s & nb-Δ>=cliff) on 20.10:")
    hits = []
    for y in range(NY):
        for x in range(NX):
            d = nbmax(T10, y, x)
            if H[y,x] >= 5 and d >= spec["cliff"]:
                hits.append((H[y,x], rpm_axis[y], load_axis[x], T10[y,x], d, T10[y,x]-T9[y,x]))
    hits.sort(reverse=True)
    for s,r_,l_,v,d,delta in hits[:20]:
        print(f"    rpm={r_:.0f} load={l_:.2f} cruise={s:.1f}s  val={v:.2f}  nb-Δ={d:.2f}  (20.10-20.9: {delta:+.2f})", flush=True)
    if not hits:
        print("    (none)", flush=True)

    # Plot
    fig, axes = plt.subplots(1, 2, figsize=(22, 11), sharey=True)
    Hp = np.ma.masked_where(H <= 0, H)
    norm = LogNorm(vmin=0.5, vmax=max(1.0, H.max()))
    cmap = plt.colormaps["YlOrRd"].copy(); cmap.set_bad(color="#f5f5f5")

    for ax, T, clist, sub in [
        (axes[0], T9, c9, "20.9"),
        (axes[1], T10, c10, "20.10"),
    ]:
        pcm = ax.pcolormesh(le, re_, Hp, cmap=cmap, norm=norm,
                            edgecolors="#cccccc", linewidth=0.4)
        for y in range(NY):
            for x in range(NX):
                lab = spec["fmt"].format(T[y,x])
                if H[y,x] >= 1.0:
                    lab = f"{spec['fmt'].format(T[y,x])}\n{H[y,x]:.0f}s"
                color = "white" if H[y,x] >= 30 else "black"
                ax.text(load_axis[x], rpm_axis[y], lab,
                        ha="center", va="center", fontsize=6.5, color=color)
        for (y1,x1),(y2,x2) in clist:
            if y1 == y2:
                xm = (load_axis[x1]+load_axis[x2])/2
                ax.plot([xm,xm], [re_[y1], re_[y1+1]], color="red", linewidth=2.0, alpha=0.9)
            else:
                ym = (rpm_axis[y1]+rpm_axis[y2])/2
                ax.plot([le[x1], le[x1+1]], [ym,ym], color="red", linewidth=2.0, alpha=0.9)
        cliff_cells = set()
        for (y1,x1),(y2,x2) in clist:
            cliff_cells.add((y1,x1)); cliff_cells.add((y2,x2))
        for (y,x) in cliff_cells:
            if H[y,x] >= 5.0:
                ax.add_patch(Rectangle((le[x], re_[y]),
                    le[x+1]-le[x], re_[y+1]-re_[y],
                    fill=False, edgecolor="#0033ff", linewidth=2.0))
        ax.set_xlabel("Engine Load (g/rev)")
        ax.set_ylabel("Engine Speed (RPM)")
        ax.set_title(f"{sub} {tname}  ({spec['units']} / cruise sec)", fontsize=11)
        ax.set_xlim(le[0], le[-1]); ax.set_ylim(re_[0], re_[-1])

    leg = [
        mlines.Line2D([],[], color="red", lw=2.0, label=f"Cliff edge (Δ ≥ {spec['cliff']})"),
        mlines.Line2D([],[], color="#0033ff", lw=2.0, label="Cruise-on-cliff cell (≥5s & adj. cliff)"),
    ]
    axes[1].legend(handles=leg, loc="upper right", fontsize=9, framealpha=0.95)
    cbar = fig.colorbar(pcm, ax=axes, fraction=0.025, pad=0.02)
    cbar.set_label("Cruise residency (seconds, log scale)")
    fig.suptitle(
        f"4-25 cruise residency on {tname}  --  filter: CL=8, MPH>20, RPM-std<100, accel-std<1, throttle-std<1\n"
        f"Total cruise: {dt[cruise].sum():.0f} s",
        fontsize=11)
    out_png = str(OUT / f"heatmap_{tname}_4-25.png")
    fig.savefig(out_png, dpi=140, bbox_inches="tight")
    plt.close(fig)
    print(f"  saved: {out_png}", flush=True)
    return out_png

outputs = []
for tname, spec in TABLES.items():
    outputs.append(render_table(tname, spec))

print("\nAll heatmaps:")
for p in outputs:
    print(" ", p)
