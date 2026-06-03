"""
Target boost vs commanded throttle on a common (RPM x pedal) grid.

Companion to pedal_throttle_compare.py. The throttle surface goes
  pedal -> RQTQ_pedal -> ratio(/RQTQ_base) -> throttle%
Target boost is NOT stored against pedal; it's stored against requested
torque (raw ecu value) x RPM. So we compose:
  RQTQ_pedal = bilinear(pedal_map; pedal, RPM)        # SI-DRIVE Sport, raw-ecu torque
  boost(psi) = bilinear(TargetBoost; RQTQ_pedal, RPM) # Target Boost_ @ 0xC1340

Both 'requested torque' quantities are the SAME raw-ecu unit (pedal map
RQTQ_SC=0.0078125 -> 0..~455; boost torque axis 'rawecuvalue' 0..420), so the
lookup is apples-to-apples. We evaluate on the pedal map's NATIVE breakpoints
(15 pedal angles x its RPM rows) so the throttle panel reproduces the table
Dean pasted exactly, and the boost panel lines up cell-for-cell.

NOTE: this uses DRIVER-DEMAND requested torque (pedal map output), same as the
throttle chart. The per-gear Requested Torque Limit (0xF9788/0xF98A0) clamps the
TOP of this in 4th/5th, so real on-road boost at high pedal in those gears is
capped below what the raw map shows. This is the commanded-map view, not the
gear-limited view.
"""
import struct
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[2]
ROM = ROOT / "rom" / "AE5L600L 20g rev 20.16.bin"

RQTQ_SC = 0.0078125
THR_SC = 0.002270655357

# pedal -> requested torque (SI-DRIVE Sport; i==s==sharp), 16 RPM x 15 APP, u16
A_PEDAL = 0xF99E0
A_PEDAL_APP = 0xF9960   # 15 floats
A_PEDAL_RPM = 0xF999C   # 16 floats
A_BASE = 0xF8B54        # 16 u16
A_BASE_RPM = 0xF8B14    # 16 floats
# throttle plate position (requested-torque-ratio) tables: 16 RPM x 16 ratio, u16
A_THR = {"Cruise": 0xF9004, "Non-Cruise": 0xF9284, "Maximum": 0xF9504}
A_THR_RATIO = {"Cruise": 0xF8F84, "Non-Cruise": 0xF9204, "Maximum": 0xF9484}
A_THR_RPM = {"Cruise": 0xF8FC4, "Non-Cruise": 0xF9244, "Maximum": 0xF94C4}

# Target Boost_ @ 0xC1340: 11 torque(X) x 15 RPM(Y), u16 -> psi relative
A_TB = 0xC1340
A_TB_TQ = 0xC12D8       # 11 floats (raw ecu value)
A_TB_RPM = 0xC1304      # 15 floats
TB_N_TQ, TB_N_RPM = 11, 15


def f32(b, a, n):
    return np.array([struct.unpack(">f", b[a + 4*i:a + 4*i + 4])[0] for i in range(n)])


def u16(b, a, n):
    return np.array([struct.unpack(">H", b[a + 2*i:a + 2*i + 2])[0] for i in range(n)], float)


def interp1(x, xp, fp):
    return np.interp(x, xp, fp)


def bilinear(xq, yq, xax, yax, grid):
    xi = np.clip(np.interp(xq, xax, np.arange(len(xax))), 0, len(xax) - 1)
    yi = np.clip(np.interp(yq, yax, np.arange(len(yax))), 0, len(yax) - 1)
    x0 = int(np.floor(xi)); x1 = min(x0 + 1, len(xax) - 1); fx = xi - x0
    y0 = int(np.floor(yi)); y1 = min(y0 + 1, len(yax) - 1); fy = yi - y0
    return (grid[y0, x0]*(1-fx)*(1-fy) + grid[y0, x1]*fx*(1-fy)
            + grid[y1, x0]*(1-fx)*fy + grid[y1, x1]*fx*fy)


def load(p, thr_table="Non-Cruise"):
    b = p.read_bytes()
    d = {}
    d["app_ax"] = f32(b, A_PEDAL_APP, 15)
    d["rpm_ax"] = f32(b, A_PEDAL_RPM, 16)
    d["pedal"] = u16(b, A_PEDAL, 16*15).reshape(16, 15) * RQTQ_SC   # [rpm, app]
    d["base_rpm"] = f32(b, A_BASE_RPM, 16)
    d["base"] = u16(b, A_BASE, 16) * RQTQ_SC
    d["thr_ratio"] = f32(b, A_THR_RATIO[thr_table], 16)
    d["thr_rpm"] = f32(b, A_THR_RPM[thr_table], 16)
    d["thr"] = u16(b, A_THR[thr_table], 16*16).reshape(16, 16) * THR_SC  # [rpm, ratio]
    # target boost
    d["tb_tq"] = f32(b, A_TB_TQ, TB_N_TQ)
    d["tb_rpm"] = f32(b, A_TB_RPM, TB_N_RPM)
    tb_raw = u16(b, A_TB, TB_N_TQ*TB_N_RPM).reshape(TB_N_RPM, TB_N_TQ)  # [rpm, tq]
    d["tb"] = (tb_raw - 760.0) * 0.01933677   # psi relative
    return d


def throttle(rom, rpm, app):
    rq = bilinear(app, rpm, rom["app_ax"], rom["rpm_ax"], rom["pedal"])
    base = interp1(rpm, rom["base_rpm"], rom["base"])
    ratio = rq / base if base > 0 else 0.0
    return bilinear(ratio, rpm, rom["thr_ratio"], rom["thr_rpm"], rom["thr"])


def req_torque(rom, rpm, app):
    return bilinear(app, rpm, rom["app_ax"], rom["rpm_ax"], rom["pedal"])


def target_boost(rom, rpm, app):
    rq = req_torque(rom, rpm, app)
    return bilinear(rq, rpm, rom["tb_tq"], rom["tb_rpm"], rom["tb"])


def fmt_table(title, rom, RPM, APP, fn, unit):
    out = [f"\n{title}  (units: {unit})"]
    out.append("RPM \\ pedal%  " + "".join(f"{a:>7.1f}" for a in APP))
    for r in RPM:
        row = "".join(f"{fn(rom, r, a):>7.1f}" for a in APP)
        out.append(f"{r:>11.0f}  {row}")
    return "\n".join(out)


SPRING = 15.0          # wastegate spring floor (psi). Map can't pull below this.
PEDAL_MIN, PEDAL_MAX = 25.0, 80.0   # curated slice: passing/roll-on band


def main():
    rom = load(ROM, "Non-Cruise")
    APP = rom["app_ax"]                       # 15 native pedal breakpoints
    RPM = rom["rpm_ax"]                        # 16 native pedal-map RPM rows
    APP_slice = APP[(APP >= PEDAL_MIN) & (APP <= PEDAL_MAX)]   # 25..80

    print("target-boost torque axis (raw ecu):", ", ".join(f"{x:g}" for x in rom["tb_tq"]))
    print("target-boost RPM axis             :", ", ".join(f"{x:g}" for x in rom["tb_rpm"]))

    print(fmt_table(f"TARGET BOOST  [pedal {PEDAL_MIN:g}-{PEDAL_MAX:g} only]",
                    rom, RPM, APP_slice, target_boost, "psi relative"))
    # excess over spring: positive = WGDC commanded to build ABOVE 15 (the part that matters)
    print(fmt_table(f"TARGET BOOST MINUS {SPRING:g} psi SPRING  (>0 = commanding boost above floor)",
                    rom, RPM, APP_slice,
                    lambda rm, r, a: target_boost(rm, r, a) - SPRING, "psi above spring"))

    # ---- focused figure: heatmap (diverging @ 15) + line plot vs RPM ----
    import matplotlib.colors as mcolors
    RPM_g = np.linspace(RPM.min(), 6400, 120)            # drop the 6450 rev-cut row
    APP_g = np.linspace(PEDAL_MIN, PEDAL_MAX, 120)
    Zb = np.array([[target_boost(rom, r, a) for r in RPM_g] for a in APP_g])

    fig, ax = plt.subplots(1, 2, figsize=(17, 6.5))

    vmin, vmax = float(np.floor(Zb.min())), float(np.ceil(Zb.max()))
    norm = mcolors.TwoSlopeNorm(vmin=min(vmin, SPRING - 0.1), vcenter=SPRING, vmax=max(vmax, SPRING + 0.1))
    im = ax[0].pcolormesh(RPM_g, APP_g, Zb, cmap="RdBu_r", norm=norm, shading="auto")
    ax[0].set_title(f"Target boost (psi rel.)  —  blue = at/under {SPRING:g} psi spring (moot),  red = commanded ABOVE spring")
    ax[0].set_xlabel("RPM"); ax[0].set_ylabel("Accelerator pedal %")
    fig.colorbar(im, ax=ax[0], label="psi (relative)")
    cs = ax[0].contour(RPM_g, APP_g, Zb, levels=[SPRING], colors="k", linewidths=2.0)
    ax[0].clabel(cs, fmt={SPRING: "15 psi spring"}, fontsize=9)

    for a in [25, 31, 37, 44, 52, 80]:
        y = [target_boost(rom, r, a) for r in RPM_g]
        ax[1].plot(RPM_g, y, label=f"{a}% pedal")
    ax[1].axhline(SPRING, color="k", ls="--", lw=1.5, label="15 psi spring (floor)")
    ax[1].set_title("Target boost vs RPM at fixed pedal  [25-80% slice]")
    ax[1].set_xlabel("RPM"); ax[1].set_ylabel("target boost (psi rel.)")
    ax[1].grid(alpha=0.3); ax[1].legend(fontsize=9, loc="lower center", ncol=2)

    fig.suptitle("AE5L600L rev 20.16 — target boost, pedal 25-80% slice   (driver-demand torque; only >15 psi is actionable)",
                 fontsize=13)
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    out = ROOT / "scripts" / "analysis" / "plots" / "pedal_target_boost_slice_25_80.png"
    out.parent.mkdir(exist_ok=True)
    fig.savefig(out, dpi=120)
    print("\nwrote", out)


if __name__ == "__main__":
    main()
