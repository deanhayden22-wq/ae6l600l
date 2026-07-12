#!/usr/bin/env python3
"""
combine_logs.py - Combine RomRaider log CSVs, add the derived columns, and file
the result into the repo's logs/ tree.

Replaces the LibreOffice Basic pipeline (CombineLogs.bas + Module2:LogBooster +
Module2:FillDown) with a single step.

Usage
-----
GUI (double-click, or run with no arguments):
    python combine_logs.py
        1. multi-select the raw logs
        2. confirm the order
        3. type a label (defaults to the logs' date, e.g. "7-12 20.19")
    -> writes logs/<label>/<label>.csv

CLI:
    python combine_logs.py -n "7-12 20.19" log0001.csv log0002.csv
    python combine_logs.py -n "7-12 20.19" --dir /path/to/romraider/logs
    python combine_logs.py -n "7-12 20.19" --file "7-12" ...   # folder != filename
    python combine_logs.py -o /any/path.csv ...                # bypass the tree

Derived columns (computed by NAME, not by column position)
----------------------------------------------------------
    correction = CL/OL == 8  -> AFC + AFL
                 CL/OL == 10 -> (1 - FFB / wbo2) * 100
                 otherwise   -> blank
    load       = MAF * 60 / RPM
    mrp        = MAP - ATM(psi)
    IDC        = IPW * RPM / 1200

This is LogBooster's canonical definition (confirmed with Dean 2026-07-12). The
stored `correction` column in older logs is NOT self-consistent - the formula was
hand-edited at various points - so this script recomputes it every run. Running it
over an old log normalizes that log to the canonical definition.

`correction` is left unfiltered on purpose. During DFCO/fuel-cut FFB runs 20-56,
so the open-loop branch produces large negative values. Filter downstream (the SOP
uses |correction| < 25 and FFB <= 14.7); do not bake the filter into the column.

Columns land in LogBooster's original slots, so output column order matches the
existing corpus. Idempotent: if the inputs already carry correction/load/mrp/IDC/
src/seam, those are dropped and rebuilt.

src / seam
----------
Appended at the far right, so nothing downstream shifts position.
    src  = source filename the row came from
    seam = 1 on the first row of each source log, else 0

`sample` is renumbered continuously, which is right for sorting but makes
non-contiguous logs look contiguous. The 5-17 20.12 set has gaps of 74 min, 5.6 hr
and 11.9 hr between adjacent logs. Any windowed calculation - tip-in dAPP/dt,
DFCO-resume, rate-of-change over N samples - will happily compute across a seam
and return a real-looking number that is garbage. Mask on `seam` or group on `src`.

Full precision is retained. The old LibreOffice path applied 2dp/0dp display
formats and exported "as shown", silently rounding the whole corpus
(Throttle 6.66667 -> 6.67, ATM 14.5098 -> 14.51). Not repeated here.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import shutil
import sys
from pathlib import Path

try:
    import numpy as np
    import pandas as pd
except ImportError as _e:  # pragma: no cover
    _msg = ("combine_logs.py needs pandas and numpy, and the Python that ran it "
            "doesn't have them.\n\n"
            "Install with:\n"
            "    py -3 -m pip install pandas\n\n"
            "(%s)" % _e)
    try:
        import tkinter as _tk
        from tkinter import messagebox as _mb
        _r = _tk.Tk()
        _r.withdraw()
        _mb.showerror("combine_logs.py - missing dependency", _msg)
    except Exception:
        pass
    print(_msg, file=sys.stderr)
    raise SystemExit(3)

DERIVED = ["correction", "load", "mrp", "IDC"]
BOOKKEEPING = ["src", "seam"]

REQUIRED = ["sample", "CL/OL", "AFC", "AFL", "FFB", "wbo2",
            "MAF", "RPM", "MAP", "ATM(psi)", "IPW"]

# (column, anchor, "before" | "after") - reproduces LogBooster's layout.
PLACEMENT = [
    ("correction", "RPM", "before"),
    ("load", "MPH", "before"),
    ("mrp", "Trgt_Boost", "before"),
    ("IDC", "IPW", "after"),
]

CL_CLOSED_LOOP = 8
CL_OPEN_LOOP = 10

# repo root = this file's parent's parent (scripts/ -> repo)
REPO = Path(__file__).resolve().parent.parent
LOGS_ROOT = REPO / "logs"


# ---------------------------------------------------------------------------
# ordering / naming
# ---------------------------------------------------------------------------

def natural_key(path):
    """log0002 < log0010. Digit runs compare numerically, the rest as text."""
    name = os.path.basename(path).lower()
    return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", name)]


def guess_label(paths):
    """Default label from the newest source file's mtime, formatted like the
    existing tree ('7-12'). Dean appends the rev by hand."""
    newest = max(os.path.getmtime(p) for p in paths)
    d = dt.datetime.fromtimestamp(newest)
    return "%d-%d" % (d.month, d.day)


def sanitize(name):
    bad = '<>:"/\\|?*'
    cleaned = "".join(c for c in name if c not in bad).strip()
    if not cleaned:
        raise ValueError("Label is empty after removing illegal characters.")
    return cleaned


def resolve_dest(args, paths):
    """Where the combined CSV goes."""
    if args.out:
        return Path(args.out)

    label = sanitize(args.name or guess_label(paths))
    fname = sanitize(args.file) if args.file else label
    root = Path(args.logs_root) if args.logs_root else LOGS_ROOT
    return root / label / (fname + ".csv")


# ---------------------------------------------------------------------------
# core
# ---------------------------------------------------------------------------

def load_one(path):
    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]
    return df.drop(columns=[c for c in DERIVED + BOOKKEEPING if c in df.columns])


def check_schemas(frames):
    """Every file must expose the same column set, and it must contain the
    channels the derived columns need. Refuse to guess."""
    items = list(frames.items())
    ref_name, ref = items[0]
    ref_cols = list(ref.columns)

    for name, df in items[1:]:
        if list(df.columns) != ref_cols:
            missing = [c for c in ref_cols if c not in df.columns]
            extra = [c for c in df.columns if c not in ref_cols]
            msg = ["Column mismatch: '%s' does not match '%s'." % (name, ref_name)]
            if missing:
                msg.append("  missing from %s: %s" % (name, missing))
            if extra:
                msg.append("  extra in %s: %s" % (name, extra))
            if not missing and not extra:
                msg.append("  same columns, different order:")
                msg.append("    %s: %s" % (ref_name, ref_cols))
                msg.append("    %s: %s" % (name, list(df.columns)))
            raise ValueError("\n".join(msg))

    absent = [c for c in REQUIRED if c not in ref_cols]
    if absent:
        raise ValueError(
            "Missing channels needed for the derived columns: %s\nFound: %s"
            % (absent, ref_cols))


def combine(paths):
    frames = {}
    for p in paths:
        name = os.path.basename(p)
        if name in frames:
            raise ValueError("Two selected files share the name '%s'. "
                             "`src` would be ambiguous - rename one." % name)
        frames[name] = load_one(p)

    check_schemas(frames)

    parts, report = [], []
    for name, df in frames.items():
        df = df.copy()
        df["src"] = name
        df["seam"] = 0
        if len(df):
            df.iloc[0, df.columns.get_loc("seam")] = 1
        parts.append(df)
        report.append({
            "file": name,
            "rows": len(df),
            "time_first": df["time"].iloc[0] if "time" in df and len(df) else None,
            "time_last": df["time"].iloc[-1] if "time" in df and len(df) else None,
        })

    out = pd.concat(parts, ignore_index=True)

    # Continuous sample numbering, anchored to the first log's first sample.
    start = int(out["sample"].iloc[0]) if len(out) else 0
    out["sample"] = np.arange(start, start + len(out), dtype=np.int64)

    return augment(out), report


def augment(df):
    """Add the LogBooster derived columns, by name."""
    num = {c: pd.to_numeric(df[c], errors="coerce") for c in REQUIRED if c != "sample"}

    rpm = num["RPM"]
    wbo2 = num["wbo2"]

    # Guard the denominators. LibreOffice emitted #DIV/0!; we emit blank.
    rpm_safe = rpm.where(rpm != 0)
    wbo2_safe = wbo2.where(wbo2 != 0)

    clol = num["CL/OL"]
    closed = num["AFC"] + num["AFL"]
    openl = (1 - num["FFB"] / wbo2_safe) * 100

    df["correction"] = np.select(
        [clol == CL_CLOSED_LOOP, clol == CL_OPEN_LOOP],
        [closed, openl],
        default=np.nan,
    )
    df["load"] = num["MAF"] * 60 / rpm_safe
    df["mrp"] = num["MAP"] - num["ATM(psi)"]
    df["IDC"] = num["IPW"] * rpm / 1200

    return df[output_order(df)]


def output_order(df):
    """LogBooster's column layout, by name, with src/seam last. Any channel we
    don't know about keeps its original relative position."""
    cols = [c for c in df.columns if c not in DERIVED + BOOKKEEPING]

    for col, anchor, side in PLACEMENT:
        if anchor in cols:
            i = cols.index(anchor)
            cols.insert(i if side == "before" else i + 1, col)
        else:
            cols.append(col)  # anchor absent - park it at the end rather than fail

    return cols + [c for c in BOOKKEEPING if c in df.columns]


def write_out(out, dest, paths, keep_sources, force):
    dest = Path(dest)
    if dest.exists() and not force:
        raise FileExistsError(
            "%s already exists.\nRe-run with --force to overwrite." % dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(dest, index=False)

    copied = []
    if keep_sources:
        for p in paths:
            tgt = dest.parent / os.path.basename(p)
            if Path(p).resolve() == tgt.resolve():
                continue
            if tgt.exists() and not force:
                continue
            shutil.copy2(p, tgt)
            copied.append(tgt.name)
    return copied


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------

def summarize(out, report, dest, copied):
    lines = ["Combined %d log(s), %s data rows." % (len(report), format(len(out), ",")), ""]
    lines.append("%-30s%9s  %22s" % ("file", "rows", "time span (s)"))
    lines.append("-" * 64)

    prev_end = None
    for r in report:
        span = "n/a" if r["time_first"] is None else \
            "%.2f -> %.2f" % (r["time_first"], r["time_last"])
        lines.append("%-30s%9s  %22s" % (r["file"][:29], format(r["rows"], ","), span))
        if prev_end is not None and r["time_first"] is not None:
            gap = r["time_first"] - prev_end
            if gap < 0:
                lines.append("%39s^ time RESETS (new key cycle)" % "")
            elif gap > 1.0:
                lines.append("%39s^ %.1f min gap before this log" % ("", gap / 60))
        prev_end = r["time_last"]

    lines += ["",
              "sample: %d -> %d (continuous)" % (out["sample"].iloc[0], out["sample"].iloc[-1]),
              "seams marked: %d" % int(out["seam"].sum())]
    if len(report) > 1:
        lines += ["",
                  "Logs are joined end-to-end but are NOT time-contiguous.",
                  "Mask on `seam` / group on `src` for any windowed or rate calc."]
    lines += ["", "Written: %s" % dest]
    if copied:
        lines.append("Sources copied alongside: %s" % ", ".join(copied))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# entry points
# ---------------------------------------------------------------------------

def run_gui():
    try:
        return _run_gui()
    except Exception:
        import traceback
        tb = traceback.format_exc()
        try:
            import tkinter as tk
            from tkinter import messagebox
            r = tk.Tk()
            r.withdraw()
            messagebox.showerror("combine_logs.py crashed", tb)
        except Exception:
            pass
        print(tb, file=sys.stderr)
        return 2


def _run_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog

    root = tk.Tk()
    root.withdraw()

    paths = filedialog.askopenfilenames(
        title="Select the raw log CSVs to combine",
        filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
    if not paths:
        return 0
    paths = sorted(paths, key=natural_key)

    order = "\n".join("%d. %s" % (i + 1, os.path.basename(p))
                      for i, p in enumerate(paths))
    if not messagebox.askokcancel(
            "Combine Logs", "Combining in this order:\n\n%s\n\nContinue?" % order):
        return 0

    label = simpledialog.askstring(
        "Label",
        "Folder / file label.\n\nWrites to:\n%s\\<label>\\<label>.csv\n\n"
        "Add the rev, e.g. \"7-12 20.19\":" % LOGS_ROOT,
        initialvalue=guess_label(paths))
    if not label:
        return 0

    try:
        out, report = combine(list(paths))
        dest = LOGS_ROOT / sanitize(label) / (sanitize(label) + ".csv")
        force = False
        if dest.exists():
            if not messagebox.askokcancel("Overwrite?",
                                          "%s\n\nalready exists. Overwrite?" % dest):
                return 0
            force = True
        copied = write_out(out, dest, paths, keep_sources=True, force=force)
    except Exception as e:
        messagebox.showerror("Combine failed", str(e))
        return 2

    messagebox.showinfo("Done", summarize(out, report, dest, copied))
    return 0


def run_cli(args):
    paths = list(args.logs)
    if args.dir:
        paths += [str(p) for p in Path(args.dir).glob("*.csv")]
    if not paths:
        print("No input logs. Pass files, or --dir <folder>.", file=sys.stderr)
        return 1
    paths = sorted(paths, key=natural_key)

    try:
        out, report = combine(paths)
        dest = resolve_dest(args, paths)
        copied = write_out(out, dest, paths,
                           keep_sources=not args.no_copy_sources, force=args.force)
    except Exception as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return 2

    print(summarize(out, report, dest, copied))
    return 0


def main():
    p = argparse.ArgumentParser(
        description="Combine RomRaider log CSVs, add derived columns, file into logs/.")
    p.add_argument("logs", nargs="*", help="log CSVs to combine")
    p.add_argument("-n", "--name",
                   help='label -> logs/<label>/<label>.csv (e.g. "7-12 20.19")')
    p.add_argument("--file",
                   help="filename stem, if it should differ from the folder label")
    p.add_argument("-o", "--out", help="explicit output path, bypassing logs/")
    p.add_argument("--dir", help="combine every .csv in this folder")
    p.add_argument("--logs-root", help="override the logs/ root")
    p.add_argument("--no-copy-sources", action="store_true",
                   help="don't copy the raw logs into the output folder")
    p.add_argument("--force", action="store_true", help="overwrite existing output")
    args = p.parse_args()

    if not args.logs and not args.dir:
        return run_gui()
    if not (args.name or args.out):
        p.error("need -n/--name (or -o/--out) in CLI mode")
    return run_cli(args)


if __name__ == "__main__":
    sys.exit(main())
