"""
Commanded-throttle comparison across ROMs: stock vs garn vs 20.13.

Computes commanded throttle plate angle through the full DBW chain on a
common (RPM x APP) grid, so ROMs with different axis breakpoints / scaling
are compared apples-to-apples (the values are throttle PLATE ANGLE %, an
absolute commanded quantity, not raw table cells).

Chain:
  RQTQ_pedal = bilinear(pedal_map; APP, RPM)           # SI-DRIVE map (i==s==sharp)
  RQTQ_base  = linear(base_rpm; RPM)
  ratio      = RQTQ_pedal / RQTQ_base
  throttle%  = bilinear(throttle_table; ratio, RPM)     # Non-Cruise by default

Addresses from definitions/AE5L600L 2013 USDM Impreza WRX MT.xml; verified to
decode sanely in all three bins (same memory map).
"""
import struct
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[2]
ROMS = {
    "stock":  ROOT / "rom" / "ae5l600l.bin",
    "garn":   ROOT / "rom" / "13 20g Base rev 25 e garn.hex",
    "20.13":  ROOT / "rom" / "AE5L600L 20g rev 20.13.bin",
}

RQTQ_SC = 0.0078125
THR_SC = 0.002270655357

# table / axis addresses
A_PEDAL = 0xF99E0      # Sport pedal map (i==s==sharp), 16 RPM x 15 APP, u16
A_PEDAL_APP = 0xF9960  # 15 floats
A_PEDAL_RPM = 0xF999C  # 16 floats
A_BASE = 0xF8B54       # 16 u16
A_BASE_RPM = 0xF8B14   # 16 floats
# throttle plate position (requested-torque-ratio) tables: 16 RPM x 16 ratio, u16
A_THR = {"Cruise": 0xF9004, "Non-Cruise": 0xF9284, "Maximum": 0xF9504}
A_THR_RATIO = {"Cruise": 0xF8F84, "Non-Cruise": 0xF9204, "Maximum": 0xF9484}
A_THR_RPM = {"Cruise": 0xF8FC4, "Non-Cruise": 0xF9244, "Maximum": 0xF94C4}


def f32(b, a, n):
    return np.array([struct.unpack(">f", b[a + 4 * i:a + 4 * i + 4])[0] for i in range(n)])


def u16(b, a, n):
    return np.array([struct.unpack(">H", b[a + 2 * i:a + 2 * i + 2])[0] for i in range(n)], float)


def interp1(x, xp, fp):
    return np.interp(x, xp, fp)


def bilinear(xq, yq, xax, yax, grid):
    """grid[i_y, i_x]; interpolate at (xq along xax, yq along yax)."""
    xi = np.clip(np.interp(xq, xax, np.arange(len(xax))), 0, len(xax) - 1)
    yi = np.clip(np.interp(yq, yax, np.arange(len(yax))), 0, len(yax) - 1)
    x0 = int(np.floor(xi)); x1 = min(x0 + 1, len(xax) - 1); fx = xi - x0
    y0 = int(np.floor(yi)); y1 = min(y0 + 1, len(yax) - 1); fy = yi - y0
    return (grid[y0, x0] * (1 - fx) * (1 - fy) + grid[y0, x1] * fx * (1 - fy)
            + grid[y1, x0] * (1 - fx) * fy + grid[y1, x1] * fx * fy)


def load_rom(p, thr_table="Non-Cruise"):
    b = p.read_bytes()
    app_ax = f32(b, A_PEDAL_APP, 15)
    rpm_ax = f32(b, A_PEDAL_RPM, 16)
    pedal = u16(b, A_PEDAL, 16 * 15).reshape(16, 15) * RQTQ_SC   # [rpm, app]
    base_rpm = f32(b, A_BASE_RPM, 16)
    base = u16(b, A_BASE, 16) * RQTQ_SC
    thr_ratio = f32(b, A_THR_RATIO[thr_table], 16)
    thr_rpm = f32(b, A_THR_RPM[thr_table], 16)
    thr = u16(b, A_THR[thr_table], 16 * 16).reshape(16, 16) * THR_SC  # [rpm, ratio]
    return dict(app_ax=app_ax, rpm_ax=rpm_ax, pedal=pedal, base_rpm=base_rpm,
                base=base, thr_ratio=thr_ratio, thr_rpm=thr_rpm, thr=thr)


def commanded_throttle(rom, rpm, app):
    rq_pedal = bilinear(app, rpm, rom["app_ax"], rom["rpm_ax"], rom["pedal"])
    rq_base = interp1(rpm, rom["base_rpm"], rom["base"])
    ratio = rq_pedal / rq_base if rq_base > 0 else 0.0
    return bilinear(ratio, rpm, rom["thr_ratio"], rom["thr_rpm"], rom["thr"]), ratio


def main(thr_table="Non-Cruise"):
    roms = {k: load_rom(p, thr_table) for k, p in ROMS.items()}
    RPM = np.arange(800, 6401, 100)
    APP_grid = np.linspace(0, 100, 51)
    APP_lines = [10, 16.5, 25, 40, 60, 100]

    fig, axes = plt.subplots(2, 3, figsize=(18, 9))
    fig.suptitle(f"Commanded throttle plate angle (%) — pedal->ratio->throttle chain "
                 f"[{thr_table} table]   |  i==s==sharp per ROM",
                 fontsize=14, y=0.98)

    vmax = 100
    for j, (name, rom) in enumerate(roms.items()):
        # heatmap
        Z = np.zeros((len(APP_grid), len(RPM)))
        for ia, a in enumerate(APP_grid):
            for ir, r in enumerate(RPM):
                Z[ia, ir] = commanded_throttle(rom, r, a)[0]
        ax = axes[0, j]
        im = ax.pcolormesh(RPM, APP_grid, np.clip(Z, 0, vmax), cmap="viridis",
                           vmin=0, vmax=vmax, shading="auto")
        ax.set_title(f"{name}", fontsize=12)
        ax.set_xlabel("RPM"); ax.set_ylabel("Accelerator Pedal %")
        fig.colorbar(im, ax=ax, label="throttle %")

        # line curves throttle vs RPM at fixed APP
        ax2 = axes[1, j]
        for a in APP_lines:
            y = [commanded_throttle(rom, r, a)[0] for r in RPM]
            ax2.plot(RPM, y, label=f"{a}% APP")
        ax2.set_title(f"{name}: throttle vs RPM at fixed pedal")
        ax2.set_xlabel("RPM"); ax2.set_ylabel("commanded throttle %")
        ax2.set_ylim(0, 105); ax2.grid(alpha=0.3)
        if j == 2:
            ax2.legend(fontsize=8, loc="upper right")

    fig.tight_layout(rect=[0, 0, 1, 0.96])
    out = ROOT / "scripts" / "analysis" / "plots" / f"pedal_throttle_compare_{thr_table.replace('-','').lower()}.png"
    out.parent.mkdir(exist_ok=True)
    fig.savefig(out, dpi=110)
    print("wrote", out)

    # also print the 16.5% APP throttle-vs-RPM table that motivated the question
    print(f"\nCommanded throttle % at 16.5% APP ({thr_table} table):")
    print("RPM   " + "  ".join(f"{name:>7}" for name in roms))
    for r in [800, 1200, 1600, 2000, 2400, 2800, 3200, 3600, 4000]:
        vals = [commanded_throttle(rom, r, 16.5)[0] for rom in roms.values()]
        print(f"{r:>5} " + "  ".join(f"{v:7.1f}" for v in vals))


if __name__ == "__main__":
    import sys
    main(sys.argv[1] if len(sys.argv) > 1 else "Non-Cruise")
