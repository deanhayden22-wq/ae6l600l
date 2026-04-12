#!/usr/bin/env python3
"""
Read CL Fueling Target Compensation and OL Fueling tables from AE5L600L ROM
to analyze the CL->OL transition boundary.

Architecture: Renesas SH7058, big-endian.
Axes: IEEE754 float (4 bytes each), already in engineering units (g/rev, RPM).
Data storage:
  - CL Comp tables: uint16 with AFR additive scaling
  - OL tables: uint8 with AFR scaling
"""

import struct
import os

ROM_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "rom", "ae5l600l.bin")


def read_rom(path):
    with open(path, "rb") as f:
        return f.read()


def read_float_be(data, offset, count):
    """Read count big-endian IEEE754 float values starting at offset."""
    values = []
    for i in range(count):
        val = struct.unpack_from(">f", data, offset + i * 4)[0]
        values.append(val)
    return values


def read_uint16_be(data, offset, count):
    """Read count big-endian uint16 values starting at offset."""
    values = []
    for i in range(count):
        val = struct.unpack_from(">H", data, offset + i * 2)[0]
        values.append(val)
    return values


def scale_afr_additive_1(raw_u16):
    """EstimatedAir/FuelRatioPoints(Additive)1:
    toexpr="(x*.000224304213)-7.35"
    storagetype=uint16
    Result is an AFR offset from 14.7 stoich base.
    """
    return (raw_u16 * 0.000224304213) - 7.35


def scale_afr_ol(raw_u8):
    """EstimatedAir/FuelRatio:
    toexpr="14.7/(1+x*.0078125)"
    storagetype=uint8
    Result is an absolute AFR value.
    """
    return 14.7 / (1.0 + raw_u8 * 0.0078125)


def print_3d_table(title, x_axis, y_axis, data_2d, data_label, fmt_data="%.3f",
                   fmt_x="%.2f"):
    """Print a 3D table in grid format.
    data_2d[row][col] where row=Y axis index, col=X axis index.
    """
    n_cols = len(x_axis)

    # Determine column width from format
    col_w = 7 if "%.2f" in fmt_data else 8

    print()
    print("=" * (10 + col_w * n_cols + 4))
    print(f"  {title}")
    print(f"  Values: {data_label}")
    print("=" * (10 + col_w * n_cols + 4))

    # Header row (X axis = load in g/rev)
    header = f"{'RPM\\Load':>10s}"
    for xv in x_axis:
        header += f"{xv:>{col_w}{fmt_x[-3:]}}"
    print(header)
    print("-" * (10 + col_w * n_cols))

    # Data rows
    for ri, yv in enumerate(y_axis):
        row_str = f"{yv:>10.0f}"
        for ci in range(n_cols):
            val = data_2d[ri][ci]
            if "%.3f" in fmt_data:
                row_str += f"{val:>{col_w}.3f}"
            else:
                row_str += f"{val:>{col_w}.2f}"
        print(row_str)
    print()


def print_boundary_extract(title, x_axis, y_axis, data_2d, fmt="%.3f",
                           load_lo=0.8, load_hi=2.0, rpm_lo=2000, rpm_hi=5200):
    """Print a focused subset of a table near the CL/OL boundary."""
    print(f"--- {title} ---")
    # Find qualifying axis indices
    x_idx = [i for i, v in enumerate(x_axis) if load_lo <= v <= load_hi]
    y_idx = [i for i, v in enumerate(y_axis) if rpm_lo <= v <= rpm_hi]

    if not x_idx or not y_idx:
        print("  (no data in specified range)")
        return

    # Header
    hdr = f"  {'RPM \\ Load':>12s}"
    for ci in x_idx:
        hdr += f"{x_axis[ci]:>8.2f}"
    print(hdr)
    print("  " + "-" * (12 + 8 * len(x_idx)))

    for ri in y_idx:
        row = f"  {y_axis[ri]:>12.0f}"
        for ci in x_idx:
            val = data_2d[ri][ci]
            if "%.3f" in fmt:
                row += f"{val:>8.3f}"
            else:
                row += f"{val:>8.2f}"
        print(row)
    print()


def main():
    rom = read_rom(ROM_PATH)
    print(f"ROM loaded: {len(rom)} bytes ({len(rom) // 1024} KB)")
    print()

    # =========================================================================
    # TABLE 1: CL Fueling Target Compensation A (Load)
    # Dimensions: 11 load (X) x 10 RPM (Y)
    # Scaling: EstimatedAir/FuelRatioPoints(Additive)1  (uint16)
    # Axes: float (already in g/rev and RPM)
    # Addresses: X=0xD147C, Y=0xD14A8, data=0xD14D0
    # Verification: X end = 0xD147C + 11*4 = 0xD14A8 = Y start (OK)
    #               Y end = 0xD14A8 + 10*4 = 0xD14D0 = data start (OK)
    # =========================================================================
    cl_a_nx = 11
    cl_a_ny = 10

    load_a = read_float_be(rom, 0xD147C, cl_a_nx)
    rpm_a = read_float_be(rom, 0xD14A8, cl_a_ny)

    data_a = []
    off = 0xD14D0
    for r in range(cl_a_ny):
        row = []
        for c in range(cl_a_nx):
            raw = struct.unpack_from(">H", rom, off)[0]
            row.append(scale_afr_additive_1(raw))
            off += 2
        data_a.append(row)

    print_3d_table(
        "TABLE 1: CL Fueling Target Compensation A (Load)",
        load_a, rpm_a, data_a,
        "AFR offset from 14.7 stoich (negative = richer)",
        fmt_data="%.3f", fmt_x="%.2f"
    )

    # =========================================================================
    # TABLE 2: CL Fueling Target Compensation B (Load)
    # Dimensions: 13 load (X) x 12 RPM (Y)  (ROM override)
    # Scaling: EstimatedAir/FuelRatioPoints(Additive)1  (uint16)
    # Addresses: X=0xD16DC, Y=0xD1710, data=0xD1740
    # Verification: X end = 0xD16DC + 13*4 = 0xD1710 = Y start (OK)
    #               Y end = 0xD1710 + 12*4 = 0xD1740 = data start (OK)
    # =========================================================================
    cl_b_nx = 13
    cl_b_ny = 12

    load_b = read_float_be(rom, 0xD16DC, cl_b_nx)
    rpm_b = read_float_be(rom, 0xD1710, cl_b_ny)

    data_b = []
    off = 0xD1740
    for r in range(cl_b_ny):
        row = []
        for c in range(cl_b_nx):
            raw = struct.unpack_from(">H", rom, off)[0]
            row.append(scale_afr_additive_1(raw))
            off += 2
        data_b.append(row)

    print_3d_table(
        "TABLE 2: CL Fueling Target Compensation B (Load)",
        load_b, rpm_b, data_b,
        "AFR offset from 14.7 stoich (negative = richer)",
        fmt_data="%.3f", fmt_x="%.2f"
    )

    # =========================================================================
    # TABLE 3: Primary Open Loop Fueling (KCA Alternate Mode)
    # Dimensions: 17 load (X) x 18 RPM (Y)
    # Scaling: EstimatedAir/FuelRatio  (uint8)
    # Addresses: X=0xCFCA4, Y=0xCFCE8, data=0xCFD30
    # Verification: X end = 0xCFCA4 + 17*4 = 0xCFCE8 = Y start (OK)
    #               Y end = 0xCFCE8 + 18*4 = 0xCFD30 = data start (OK)
    # =========================================================================
    ol_alt_nx = 17
    ol_alt_ny = 18

    load_ol_alt = read_float_be(rom, 0xCFCA4, ol_alt_nx)
    rpm_ol_alt = read_float_be(rom, 0xCFCE8, ol_alt_ny)

    data_ol_alt = []
    off = 0xCFD30
    for r in range(ol_alt_ny):
        row = []
        for c in range(ol_alt_nx):
            row.append(scale_afr_ol(rom[off]))
            off += 1
        data_ol_alt.append(row)

    print_3d_table(
        "TABLE 3: Primary Open Loop Fueling (KCA Alternate Mode)",
        load_ol_alt, rpm_ol_alt, data_ol_alt,
        "Estimated AFR (absolute)",
        fmt_data="%.2f", fmt_x="%.2f"
    )

    # =========================================================================
    # TABLE 4: Primary Open Loop Fueling (KCA Additive B Low)
    # Dimensions: 17 load (X) x 18 RPM (Y)
    # Scaling: EstimatedAir/FuelRatio  (uint8)
    # Addresses: X=0xD01B8, Y=0xD01FC, data=0xD0244
    # Verification: X end = 0xD01B8 + 17*4 = 0xD01FC = Y start (OK)
    #               Y end = 0xD01FC + 18*4 = 0xD0244 = data start (OK)
    # =========================================================================
    ol_blo_nx = 17
    ol_blo_ny = 18

    load_ol_blo = read_float_be(rom, 0xD01B8, ol_blo_nx)
    rpm_ol_blo = read_float_be(rom, 0xD01FC, ol_blo_ny)

    data_ol_blo = []
    off = 0xD0244
    for r in range(ol_blo_ny):
        row = []
        for c in range(ol_blo_nx):
            row.append(scale_afr_ol(rom[off]))
            off += 1
        data_ol_blo.append(row)

    print_3d_table(
        "TABLE 4: Primary Open Loop Fueling (KCA Additive B Low)",
        load_ol_blo, rpm_ol_blo, data_ol_blo,
        "Estimated AFR (absolute)",
        fmt_data="%.2f", fmt_x="%.2f"
    )

    # =========================================================================
    # ANALYSIS: CL->OL Transition Boundary
    # =========================================================================
    print()
    print("=" * 100)
    print("  TRANSITION BOUNDARY ANALYSIS")
    print("  CL effective target = 14.7 + Comp_A + Comp_B  (plus other minor comps)")
    print("  Focus: 0.8-2.0 g/rev load, 2000-5200 RPM")
    print("=" * 100)
    print()

    print_boundary_extract(
        "CL Comp A (AFR offset from 14.7)",
        load_a, rpm_a, data_a, fmt="%.3f"
    )
    print_boundary_extract(
        "CL Comp B (AFR offset from 14.7)",
        load_b, rpm_b, data_b, fmt="%.3f"
    )

    # Compute combined CL effective AFR where axes overlap
    print("--- Combined CL Effective Target AFR (14.7 + CompA + CompB) ---")
    print("    (Interpolated at Comp A grid points where Comp B provides nearest match)")
    # For each Comp A grid point in range, find nearest Comp B value and combine
    a_x_idx = [i for i, v in enumerate(load_a) if 0.8 <= v <= 2.0]
    a_y_idx = [i for i, v in enumerate(rpm_a) if 2000 <= v <= 5200]

    def nearest_idx(arr, target):
        return min(range(len(arr)), key=lambda i: abs(arr[i] - target))

    hdr = f"  {'RPM \\ Load':>12s}"
    for ci in a_x_idx:
        hdr += f"{load_a[ci]:>8.2f}"
    print(hdr)
    print("  " + "-" * (12 + 8 * len(a_x_idx)))

    for ri in a_y_idx:
        row = f"  {rpm_a[ri]:>12.0f}"
        for ci in a_x_idx:
            comp_a = data_a[ri][ci]
            # Find nearest Comp B value
            b_ci = nearest_idx(load_b, load_a[ci])
            b_ri = nearest_idx(rpm_b, rpm_a[ri])
            comp_b = data_b[b_ri][b_ci]
            effective = 14.7 + comp_a + comp_b
            row += f"{effective:>8.2f}"
        print(row)
    print()

    # OL boundary extracts
    print_boundary_extract(
        "OL KCA Alternate Mode (absolute AFR)",
        load_ol_alt, rpm_ol_alt, data_ol_alt, fmt="%.2f"
    )
    print_boundary_extract(
        "OL KCA Additive B Low (absolute AFR)",
        load_ol_blo, rpm_ol_blo, data_ol_blo, fmt="%.2f"
    )

    # Summary comparison
    print("--- AFR Step at CL->OL Transition ---")
    print("    Showing CL effective vs OL AFR at matching RPM/load points:")
    print(f"  {'RPM':>8s} {'Load':>8s} {'CL AFR':>8s} {'OL Alt':>8s} {'OL BLo':>8s} {'Step(Alt)':>10s} {'Step(BLo)':>10s}")
    print("  " + "-" * 70)

    for ri in a_y_idx:
        for ci in a_x_idx:
            ld = load_a[ci]
            rpm_val = rpm_a[ri]
            # CL
            comp_a = data_a[ri][ci]
            b_ci = nearest_idx(load_b, ld)
            b_ri = nearest_idx(rpm_b, rpm_val)
            comp_b = data_b[b_ri][b_ci]
            cl_afr = 14.7 + comp_a + comp_b

            # OL Alt
            ol_ci = nearest_idx(load_ol_alt, ld)
            ol_ri = nearest_idx(rpm_ol_alt, rpm_val)
            ol_alt_afr = data_ol_alt[ol_ri][ol_ci]

            # OL B Low
            ob_ci = nearest_idx(load_ol_blo, ld)
            ob_ri = nearest_idx(rpm_ol_blo, rpm_val)
            ol_blo_afr = data_ol_blo[ob_ri][ob_ci]

            step_alt = ol_alt_afr - cl_afr
            step_blo = ol_blo_afr - cl_afr

            print(f"  {rpm_val:>8.0f} {ld:>8.2f} {cl_afr:>8.2f} {ol_alt_afr:>8.2f} "
                  f"{ol_blo_afr:>8.2f} {step_alt:>+10.2f} {step_blo:>+10.2f}")

    print()
    print("  Negative step = OL is richer than CL was targeting")
    print("  Positive step = OL is leaner than CL was targeting")
    print()


if __name__ == "__main__":
    main()
