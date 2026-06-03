"""
Explain the SHAPE of fixed-pedal target-boost curves by drawing the native
Target Boost_ table (torque x RPM) and overlaying the path each fixed pedal
traces across it. A fixed pedal is NOT a vertical line: the pedal->torque map
drops requested torque as RPM rises, so the pedal walks LEFT (toward lower
torque / lower boost) up top -- which is most of the 'taper' people blame on
the boost table.
"""
import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(HERE, "pedal_target_boost_compare.py")).read().split("if __name__")[0]
g = {"__file__": os.path.join(HERE, "pedal_target_boost_compare.py")}
exec(src, g)

rom = g["load"](g["ROM"], "Non-Cruise")
tq = rom["tb_tq"]; rpm = rom["tb_rpm"]; tb = rom["tb"]   # tb[rpm, tq]
req_torque = g["req_torque"]
nx, ny = len(tq), len(rpm)

fig, ax = plt.subplots(figsize=(13, 9))
im = ax.imshow(tb, origin="lower", aspect="auto", cmap="turbo",
               extent=[-0.5, nx - 0.5, -0.5, ny - 0.5], vmin=-10, vmax=22)
fig.colorbar(im, ax=ax, label="target boost (psi rel.)")

# annotate every cell
for i in range(ny):
    for j in range(nx):
        v = tb[i, j]
        ax.text(j, i, f"{v:.0f}", ha="center", va="center", fontsize=7,
                color="white" if (v < 4 or v > 19) else "black")

# 15 psi spring contour in index space
ax.contour(np.arange(nx), np.arange(ny), tb, levels=[15], colors="k", linewidths=2)

# overlay fixed-pedal paths (walk across torque axis as RPM rises)
prpm = rom["rpm_ax"]
colors = {25: "magenta", 31: "cyan", 80: "lime"}
for ped, c in colors.items():
    xs, ys = [], []
    for i, r in enumerate(rpm):
        rq = req_torque(rom, r, ped)                       # requested torque at this pedal/RPM
        xpos = np.interp(rq, tq, np.arange(nx))            # fractional torque-axis position
        xs.append(xpos); ys.append(i)
    ax.plot(xs, ys, "-o", color=c, lw=2.4, ms=5, label=f"{ped}% pedal path",
            markeredgecolor="k", markeredgewidth=0.4)

ax.set_xticks(range(nx)); ax.set_xticklabels([f"{t:.0f}" for t in tq])
ax.set_yticks(range(ny)); ax.set_yticklabels([f"{r:.0f}" for r in rpm])
ax.set_xlabel("Requested torque (raw ecu value)  ->  X axis of Target Boost_")
ax.set_ylabel("RPM")
ax.set_title("Target Boost_ @ 0xC1340 with fixed-pedal paths overlaid\n"
             "black line = 15 psi spring;  a fixed pedal drifts LEFT (less torque) as RPM climbs",
             fontsize=12)
ax.legend(loc="lower right", fontsize=10)
# highlight the two artifacts
ax.add_patch(plt.Rectangle((8.5, 6.5), 1.0, 1.0, fill=False, edgecolor="red", lw=2.5))   # 3600 x 350 divot
ax.text(8.2, 6.5, "3600x350\ndivot (18.5)", color="red", fontsize=8, ha="right", va="center")
fig.tight_layout()
out = os.path.join(HERE, "plots", "target_boost_shape_explain.png")
fig.savefig(out, dpi=120)
print("wrote", out)
