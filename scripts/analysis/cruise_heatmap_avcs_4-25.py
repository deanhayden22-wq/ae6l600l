#!/usr/bin/env python3
"""4-25 log cruise residency heatmap on Intake AVCS Cruise grid (20.9 vs 20.10)."""
import csv, json, os, sys
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.colors import LogNorm
from matplotlib.patches import Rectangle
import matplotlib.lines as mlines

OUT = "/sessions/tender-wizardly-brown/mnt/outputs"
LOG = "/sessions/tender-wizardly-brown/mnt/ae6l600l/logs/4-25/4-25 full.csv"

with open(os.path.join(OUT, "avcs_tables.json")) as f:
    avcs = json.load(f)
load_axis = np.array(avcs["20.9"]["load"])
rpm_axis  = np.array(avcs["20.9"]["rpm"])
T_209 = np.array(avcs["20.9"]["table"])
T_210 = np.array(avcs["20.10"]["table"])
NX, NY = len(load_axis), len(rpm_axis)

# Read log
data = []
with open(LOG) as f:
    r = csv.DictReader(f)
    for row in r:
        try:
            data.append((float(row["time"]), float(row["RPM"]), float(row["load"]),
                         float(row["MPH"]), float(row["Accelerator"]),
                         float(row["Throttle"]), int(row["CL/OL"]), float(row["avcs"])))
        except Exception:
            continue
arr = np.array(data, dtype=float)
t   = arr[:,0]; rpm = arr[:,1]; load = arr[:,2]; mph = arr[:,3]
accel = arr[:,4]; thr = arr[:,5]; clol = arr[:,6].astype(int)

dt = np.diff(t, prepend=t[0])
dt = np.clip(dt, 0, 0.5)

def rolling_std(x, w=20):
    if len(x) < w: return np.zeros_like(x)
    c = np.cumsum(np.insert(x, 0, 0))
    c2 = np.cumsum(np.insert(x*x, 0, 0))
    s  = (c[w:] - c[:-w]) / w
    s2 = (c2[w:] - c2[:-w]) / w
    var = np.maximum(s2 - s*s, 0)
    out = np.zeros_like(x)
    out[w-1:] = np.sqrt(var)
    return out

rpm_std   = rolling_std(rpm,   20)
accel_std = rolling_std(accel, 20)
thr_std   = rolling_std(thr,   20)

cruise = (clol == 8) & (mph > 20) & (rpm_std < 100) & (accel_std < 1.0) & (thr_std < 1.0)
print(f"Cruise samples: {cruise.sum()} / {len(cruise)} ({100*cruise.mean():.1f}%)", flush=True)
print(f"Cruise total seconds: {dt[cruise].sum():.0f}", flush=True)

def edges(axis):
    e = np.empty(len(axis)+1)
    e[1:-1] = (axis[:-1] + axis[1:]) / 2
    e[0]    = axis[0] - (axis[1]-axis[0])/2
    e[-1]   = axis[-1] + (axis[-1]-axis[-2])/2
    return e
load_edges = edges(load_axis)
rpm_edges  = edges(rpm_axis)

H, _, _ = np.histogram2d(rpm[cruise], load[cruise],
                         bins=[rpm_edges, load_edges], weights=dt[cruise])
print(f"Total cruise residency in grid (s): {H.sum():.1f}", flush=True)
print(f"Max single-cell residency (s): {H.max():.1f}", flush=True)

def cliffs(T, thresh=5.0):
    out = []
    for y in range(T.shape[0]):
        for x in range(T.shape[1]):
            if x+1 < T.shape[1] and abs(T[y,x+1]-T[y,x]) >= thresh:
                out.append(((y,x),(y,x+1)))
            if y+1 < T.shape[0] and abs(T[y+1,x]-T[y,x]) >= thresh:
                out.append(((y,x),(y+1,x)))
    return out

c209 = cliffs(T_209)
c210 = cliffs(T_210)
print(f"Cliffs (>=5deg) 20.9: {len(c209)}, 20.10: {len(c210)}", flush=True)

CRUISE_HOT = 5.0  # seconds threshold for "common cruise"

def draw(ax, T, cliff_list, title):
    Hp = np.ma.masked_where(H <= 0, H)
    norm = LogNorm(vmin=0.5, vmax=max(1.0, H.max()))
    cmap = plt.colormaps["YlOrRd"].copy()
    cmap.set_bad(color="#f5f5f5")
    pcm = ax.pcolormesh(load_edges, rpm_edges, Hp, cmap=cmap, norm=norm,
                        edgecolors="#cccccc", linewidth=0.4)
    for y in range(NY):
        for x in range(NX):
            label = f"{T[y,x]:.1f}"
            if H[y,x] >= 1.0:
                label = f"{T[y,x]:.1f}\n{H[y,x]:.0f}s"
            color = "white" if H[y,x] >= 30 else "black"
            ax.text(load_axis[x], rpm_axis[y], label, ha="center", va="center",
                    fontsize=6.5, color=color)
    for (y1,x1),(y2,x2) in cliff_list:
        if y1 == y2:
            xm = (load_axis[x1]+load_axis[x2])/2
            ax.plot([xm,xm], [rpm_edges[y1], rpm_edges[y1+1]],
                    color="red", linewidth=2.2, alpha=0.9)
        else:
            ym = (rpm_axis[y1]+rpm_axis[y2])/2
            ax.plot([load_edges[x1], load_edges[x1+1]], [ym,ym],
                    color="red", linewidth=2.2, alpha=0.9)
    cliff_cells = set()
    for (y1,x1),(y2,x2) in cliff_list:
        cliff_cells.add((y1,x1)); cliff_cells.add((y2,x2))
    for (y,x) in cliff_cells:
        if H[y,x] >= CRUISE_HOT:
            ax.add_patch(Rectangle((load_edges[x], rpm_edges[y]),
                load_edges[x+1]-load_edges[x], rpm_edges[y+1]-rpm_edges[y],
                fill=False, edgecolor="#0033ff", linewidth=2.0))
    ax.set_xlabel("Engine Load (g/rev)")
    ax.set_ylabel("Engine Speed (RPM)")
    ax.set_title(title, fontsize=11)
    ax.set_xlim(load_edges[0], load_edges[-1])
    ax.set_ylim(rpm_edges[0], rpm_edges[-1])
    return pcm

print("Drawing panels...", flush=True)
fig, axes = plt.subplots(1, 2, figsize=(22, 11), sharey=True)
draw(axes[0], T_209, c209, "20.9 Intake AVCS Cruise (deg / cruise sec)")
pcm = draw(axes[1], T_210, c210, "20.10 Intake AVCS Cruise (deg / cruise sec)")

leg = [
    mlines.Line2D([],[], color="red",     lw=2.2, label="Cliff edge (delta >= 5 deg)"),
    mlines.Line2D([],[], color="#0033ff", lw=2.0, label=f"Cruise-on-cliff cell (>={CRUISE_HOT:.0f}s & adj. cliff)"),
]
axes[1].legend(handles=leg, loc="upper right", fontsize=9, framealpha=0.95)
cbar = fig.colorbar(pcm, ax=axes, fraction=0.025, pad=0.02)
cbar.set_label("Cruise residency in cell (seconds, log scale)")
fig.suptitle(
    f"4-25 cruise residency on AVCS Intake (Cruise) grid  --  "
    f"filter: CL=8, MPH>20, RPM-std<100, accel-std<1, throttle-std<1\n"
    f"Total cruise: {dt[cruise].sum():.0f} s ({cruise.sum()} samples)", fontsize=11)

out_png = os.path.join(OUT, "avcs_cruise_heatmap_4-25_v2.png")
fig.savefig(out_png, dpi=140, bbox_inches="tight")
print("Saved:", out_png, flush=True)

def nbmax(T, y, x):
    nb = []
    if x>0:    nb.append(abs(T[y,x]-T[y,x-1]))
    if x<NX-1: nb.append(abs(T[y,x]-T[y,x+1]))
    if y>0:    nb.append(abs(T[y,x]-T[y-1,x]))
    if y<NY-1: nb.append(abs(T[y,x]-T[y+1,x]))
    return max(nb) if nb else 0.0

print("\n=== Cruise-on-cliff (>=5s & >=5deg neighbor delta) ===", flush=True)
for tag, T in [("20.9", T_209), ("20.10", T_210)]:
    print(f"-- {tag} --", flush=True)
    rows = []
    for y in range(NY):
        for x in range(NX):
            d = nbmax(T, y, x)
            if H[y,x] >= 5 and d >= 5.0:
                rows.append((H[y,x], rpm_axis[y], load_axis[x], T[y,x], d))
    rows.sort(reverse=True)
    for s, r_, l_, v, d in rows:
        print(f"  rpm={r_:.0f}  load={l_:.2f}  cruise={s:.1f}s  AVCS={v:.2f}  max-nb-delta={d:.2f}", flush=True)

print("\nTop 15 cruise cells:", flush=True)
flat = [(H[y,x], rpm_axis[y], load_axis[x], T_209[y,x], T_210[y,x])
        for y in range(NY) for x in range(NX) if H[y,x] > 0]
flat.sort(reverse=True)
for s, r_, l_, v9, v10 in flat[:15]:
    print(f"  rpm={r_:.0f}  load={l_:.2f}  time={s:.1f}s  20.9={v9:.2f}  20.10={v10:.2f}  delta={v10-v9:+.2f}", flush=True)
