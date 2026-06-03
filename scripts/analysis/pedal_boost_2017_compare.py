"""
Recompute the 25% and 31% pedal-path target boost on the NEW 20.17 map and
compare to 20.16. Reads both bins' Target Boost_ tables and the pedal->torque
map directly (exact bytes). This is COMMANDED target (pedal->torque->table);
known to overstate actual at low load (airflow-limited), but it's the right
tool for seeing what the table edit did to these paths.
"""
import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(HERE, "pedal_target_boost_compare.py")).read().split("if __name__")[0]
g = {"__file__": os.path.join(HERE, "pedal_target_boost_compare.py")}
exec(src, g)
load = g["load"]; target_boost = g["target_boost"]

ROOT = Path(HERE).resolve().parents[1]
BIN16 = ROOT / "rom" / "AE5L600L 20g rev 20.16.bin"
BIN17 = ROOT / "rom" / "AE5L600L 20g rev 20.17.bin"
SPRING = 15.0

r16 = load(BIN16, "Non-Cruise")
r17 = load(BIN17, "Non-Cruise")

# verify pedal map unchanged
ped_changed = not np.allclose(r16["pedal"], r17["pedal"])
print("pedal->torque map changed 16->17?", ped_changed)

# print new native boost table (verify vs screenshot)
tq, rpm, tb = r17["tb_tq"], r17["tb_rpm"], r17["tb"]
print("\n=== 20.17 native Target Boost_ (psi): rows=RPM, cols=torque ===")
print("RPM\\tq " + "".join(f"{t:>7.0f}" for t in tq))
for i, rr in enumerate(rpm):
    print(f"{rr:>6.0f} " + "".join(f"{tb[i,j]:>7.2f}" for j in range(len(tq))))

RPM = r17["rpm_ax"]
print("\n=== Composed target boost on pedal paths: 20.16 -> 20.17 ===")
print(f"{'RPM':>6} | {'25% old':>8} {'25% new':>8} {'chg':>6} | {'31% old':>8} {'31% new':>8} {'chg':>6}")
for rr in RPM:
    a16 = target_boost(r16, rr, 25); a17 = target_boost(r17, rr, 25)
    b16 = target_boost(r16, rr, 31); b17 = target_boost(r17, rr, 31)
    print(f"{rr:>6.0f} | {a16:>8.1f} {a17:>8.1f} {a17-a16:>+6.1f} | {b16:>8.1f} {b17:>8.1f} {b17-b16:>+6.1f}")

fig, axes = plt.subplots(1, 2, figsize=(15, 6), sharey=True)
RPM_g = np.linspace(RPM.min(), 6400, 200)
for ax, ped in zip(axes, [25, 31]):
    y16 = [target_boost(r16, r, ped) for r in RPM_g]
    y17 = [target_boost(r17, r, ped) for r in RPM_g]
    ax.plot(RPM_g, y16, "--", color="gray", lw=2.2, label="20.16 (old)")
    ax.plot(RPM_g, y17, "-", color="crimson", lw=2.6, label="20.17 (new)")
    ax.axhline(SPRING, color="k", ls="--", lw=1.2, label="15 psi spring")
    ax.axhline(13, color="tab:blue", ls=":", lw=1.1, label="13 psi TD gate")
    ax.fill_between(RPM_g, y16, y17, where=(np.array(y17) > np.array(y16)),
                    color="crimson", alpha=0.12)
    ax.set_title(f"{ped}% pedal path — commanded target boost")
    ax.set_xlabel("RPM"); ax.grid(alpha=0.3); ax.set_ylim(-12, 24)
    ax.legend(fontsize=9, loc="upper left")
axes[0].set_ylabel("target boost (psi rel.)")
fig.suptitle("25% & 31% pedal paths: 20.16 vs 20.17 target boost map", fontsize=13)
fig.tight_layout(rect=[0, 0, 1, 0.96])
out = ROOT / "scripts" / "analysis" / "plots" / "pedal_boost_2016_vs_2017.png"
fig.savefig(out, dpi=120)
print("\nwrote", out)
