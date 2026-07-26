#!/usr/bin/env python3
"""
defs.py - load and RESOLVE the RomRaider/ECUFlash definition XMLs for AE5L600L.

The definitions are the project's ground truth for table identity, geometry and
units.  They are split across three files and the split is not decorative:

    definitions/32BITBASE.xml                            2117 <table>, 222 <scaling>
        ABSTRACT.  Names, categories, descriptions, axis shape, scaling refs.
        NO addresses -- it describes every Subaru 32-bit ROM, not this one.

    definitions/AE5L600L 2013 USDM Impreza WRX MT.xml     716 <table>,  17 <scaling>
        CONCRETE.  Same names + address= for THIS ROM, and a handful of
        overrides where the generic base entry is wrong for this ROM.
        Declares <include>32BITBASE</include>.

    definitions/AE5L600L MerpMod SD.xml                    19 <table>,   8 <scaling>
        Speed-density port.  Declares <include>AE5L600L</include>.
        Self-contained (every table carries its own type/scaling/address).

INHERITANCE (verified empirically against these files -- see resolve() below):

  * A project <table> binds to the base <table> with the SAME name.
    Base top-level names are unique (1144 elements / 1144 distinct names), so
    the binding is unambiguous.  399 of the 502 project tables bind; 103 do not
    and are project-unique.
  * Any attribute the project states WINS; anything it omits is inherited.
    In practice the project states address= (always) and category= (always,
    and it disagrees with the base category 381/399 times -- the project has
    its own taxonomy).  It almost never restates type= or scaling=.
  * <description> is inherited when the project element has none.
  * Axis children bind by name to the base's children (210/210 also line up
    positionally).  The project supplies address=, the base supplies
    type=/scaling=/elements=.
  * If the project declares NO children but the base has one, the base child is
    inherited whole.  All 95 such cases are `Static Y Axis` -- label-only axes
    that need no address.
  * elements= from the project OVERRIDES the base (50 axes).  The base counts
    are generic and wrong for this ROM in both directions (33 larger,
    17 smaller).  Using the base count silently reads the wrong region.

RAW vs DISPLAY: a <scaling> carries storagetype (how many bytes and how to
decode them) and toexpr (how to turn that number into the displayed value).
When toexpr is not the identity the STORED value is in different units from
the value the tuning software shows.  Scaling.raw_is_display is False for
those; Scaling.raw_note() spells out the difference.

API
---
    from defs import load
    d = load()                          # base + project (default)
    d = load(include_sd=True)           # + MerpMod SD port

    d.tables                            # list[Table], project order
    d.get("Target Boost_")              # exact-name lookup  -> Table
    d.search("wastegate")               # substring, case-insensitive
    d.by_category()                     # {category: [Table, ...]}
    d.at(0xf104c)                       # every Table whose data lives there
    d.scalings                          # {name: Scaling}
    d.problems()                        # list[Problem] - unresolvable defs
    d.summary()                         # dict of counts

    t = d.get("Engine Load Compensation Cruise (MP)")
    t.address, t.type, t.shape, t.byte_length
    t.scaling.units, t.scaling.storagetype, t.scaling.toexpr
    t.read_raw(rom)                     # stored numbers
    t.read(rom)                         # displayed values (toexpr applied)
    t.axes[0].read(rom)                 # axis breakpoints, displayed
    t.provenance                        # {'type': 'base', 'address': 'project', ...}

    d.audit_layout(rom)                 # cross-check geometry against ROM bytes

Every number this module returns for `read()` has had toexpr applied.  Use
read_raw() only when you specifically want the stored bytes' numeric value.
"""

from __future__ import annotations

import os
import re
import struct
from collections import Counter, OrderedDict, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
import xml.etree.ElementTree as ET

__all__ = [
    "load", "Defs", "Table", "Axis", "Scaling", "Problem",
    "DEFS_DIR", "BASE_XML", "PROJECT_XML", "SD_XML", "STOCK_ROM", "ROM_SIZE",
]

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(_HERE)
DEFS_DIR = os.path.join(REPO_ROOT, "definitions")

BASE_XML = os.path.join(DEFS_DIR, "32BITBASE.xml")
PROJECT_XML = os.path.join(DEFS_DIR, "AE5L600L 2013 USDM Impreza WRX MT.xml")
SD_XML = os.path.join(DEFS_DIR, "AE5L600L MerpMod SD.xml")

STOCK_ROM = os.path.join(REPO_ROOT, "rom", "ae5l600l.bin")
ROM_SIZE = 0x100000  # 1,048,576 bytes

# storagetype -> bytes per element.  SH-2E ROM is big-endian throughout;
# every non-bloblist scaling in these files declares endian="big".
_WIDTH = {
    "uint8": 1, "int8": 1,
    "uint16": 2, "int16": 2,
    "uint32": 4, "int32": 4,
    "float": 4,
}
_STRUCT = {
    ("uint8", "big"): ">B", ("uint8", "little"): "<B",
    ("int8", "big"): ">b", ("int8", "little"): "<b",
    ("uint16", "big"): ">H", ("uint16", "little"): "<H",
    ("int16", "big"): ">h", ("int16", "little"): "<h",
    ("uint32", "big"): ">I", ("uint32", "little"): "<I",
    ("int32", "big"): ">i", ("int32", "little"): "<i",
    ("float", "big"): ">f", ("float", "little"): "<f",
}

_IDENTITY_EXPRS = {"x", "x*1", "1*x", "x/1", "x+0", "x-0"}

AXIS_TYPES = ("X Axis", "Y Axis", "Static X Axis", "Static Y Axis")
STATIC_AXIS_TYPES = ("Static X Axis", "Static Y Axis")


# --------------------------------------------------------------------------
# Problems
# --------------------------------------------------------------------------

@dataclass
class Problem:
    kind: str
    table: str
    detail: str
    where: str = ""

    def __str__(self) -> str:
        w = " [%s]" % self.where if self.where else ""
        return "%-24s %-58s %s%s" % (self.kind, self.table, self.detail, w)


# --------------------------------------------------------------------------
# Scaling
# --------------------------------------------------------------------------

@dataclass
class Scaling:
    """A resolved <scaling>.  Converts stored bytes <-> displayed values."""
    name: str
    storagetype: Optional[str] = None
    endian: str = "big"
    toexpr: Optional[str] = None
    frexpr: Optional[str] = None
    units: str = ""
    min: Optional[float] = None
    max: Optional[float] = None
    inc: Optional[float] = None
    format: Optional[str] = None
    source: str = ""          # which XML defined it
    shadows: bool = False     # project redefined a name the base already had
    blob: List[Tuple[str, str]] = field(default_factory=list)  # bloblist entries
    line: Optional[int] = None

    _to: Any = field(default=None, repr=False, compare=False)
    _fr: Any = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        if self.toexpr:
            try:
                self._to = compile(self.toexpr, "<toexpr:%s>" % self.name, "eval")
            except SyntaxError:
                self._to = None
        if self.frexpr:
            try:
                self._fr = compile(self.frexpr, "<frexpr:%s>" % self.name, "eval")
            except SyntaxError:
                self._fr = None

    # -- geometry ---------------------------------------------------------
    @property
    def width(self) -> int:
        """Bytes per stored element."""
        if self.storagetype == "bloblist":
            return max((len(v) // 2 for _, v in self.blob), default=1)
        return _WIDTH.get(self.storagetype, 0)

    @property
    def is_blob(self) -> bool:
        return self.storagetype == "bloblist"

    # -- conversion -------------------------------------------------------
    @property
    def raw_is_display(self) -> bool:
        """True when the stored number IS the displayed number."""
        if self.is_blob:
            return False
        t = (self.toexpr or "").replace(" ", "")
        return t in _IDENTITY_EXPRS

    def to_display(self, x):
        """Stored value -> displayed value (applies toexpr)."""
        if self.is_blob:
            for nm, v in self.blob:
                if int(v, 16) == x:
                    return nm
            return x
        if self._to is None:
            return x
        try:
            return eval(self._to, {"__builtins__": {}}, {"x": x})
        except ZeroDivisionError:
            return float("inf")

    def from_display(self, y):
        """Displayed value -> stored value (applies frexpr)."""
        if self._fr is None:
            return y
        try:
            return eval(self._fr, {"__builtins__": {}}, {"x": y})
        except ZeroDivisionError:
            return float("inf")

    def decode(self, buf: bytes, addr: int, count: int) -> List[Any]:
        """Read `count` stored elements at `addr`. No toexpr applied."""
        if self.is_blob:
            return list(buf[addr:addr + count])
        fmt = _STRUCT.get((self.storagetype, self.endian))
        if fmt is None:
            raise ValueError("scaling %r: unsupported storagetype %r"
                             % (self.name, self.storagetype))
        w = self.width
        return [struct.unpack_from(fmt, buf, addr + i * w)[0] for i in range(count)]

    def fmt(self, v) -> str:
        """Format a DISPLAY value using the definition's format string."""
        if isinstance(v, str):
            return v
        f = self.format or "%.4g"
        try:
            return f % v
        except (TypeError, ValueError):
            return str(v)

    def raw_note(self) -> str:
        """Human-readable statement of raw-vs-display, for the units trap."""
        if self.is_blob:
            return "enumeration: %s" % ", ".join("%s=0x%s" % (n, v) for n, v in self.blob)
        if self.raw_is_display:
            return "raw == display (%s)" % (self.units or "unitless")
        return ("raw %s decoded, then display = %s  ->  displayed in %s"
                % (self.storagetype, self.toexpr, self.units or "?"))

    def __str__(self) -> str:
        return "%s(%s%s, %s -> %s)" % (
            self.name, self.storagetype,
            "" if self.raw_is_display else " *", self.toexpr, self.units or "?")


# --------------------------------------------------------------------------
# Axis
# --------------------------------------------------------------------------

@dataclass
class Axis:
    name: Optional[str]
    type: Optional[str]                 # 'X Axis' | 'Y Axis' | 'Static X/Y Axis'
    address: Optional[int] = None
    elements: Optional[int] = None
    scaling: Optional[Scaling] = None
    scaling_name: Optional[str] = None
    labels: List[str] = field(default_factory=list)   # Static axes only
    provenance: Dict[str, str] = field(default_factory=dict)
    line: Optional[int] = None

    @property
    def is_static(self) -> bool:
        return self.type in STATIC_AXIS_TYPES

    @property
    def byte_length(self) -> int:
        if self.is_static or self.address is None or self.scaling is None:
            return 0
        return (self.elements or 0) * self.scaling.width

    def read_raw(self, buf: bytes) -> List[Any]:
        if self.is_static:
            return list(self.labels)
        if self.address is None or self.scaling is None or not self.elements:
            raise ValueError("axis %r is not readable (address/scaling/elements missing)"
                             % (self.name,))
        return self.scaling.decode(buf, self.address, self.elements)

    def read(self, buf: bytes) -> List[Any]:
        if self.is_static:
            return list(self.labels)
        s = self.scaling
        return [s.to_display(v) for v in self.read_raw(buf)]

    def __str__(self) -> str:
        if self.is_static:
            return "%s [%s] %s" % (self.name, self.type, self.labels)
        return "%s [%s] @0x%s n=%s %s" % (
            self.name, self.type,
            ("%X" % self.address) if self.address is not None else "?",
            self.elements, self.scaling_name)


# --------------------------------------------------------------------------
# Table
# --------------------------------------------------------------------------

@dataclass
class Table:
    name: str
    category: Optional[str] = None
    description: Optional[str] = None
    address: Optional[int] = None
    type: Optional[str] = None          # '1D' | '2D' | '3D'
    scaling: Optional[Scaling] = None
    scaling_name: Optional[str] = None
    level: Optional[str] = None
    axes: List[Axis] = field(default_factory=list)
    source: str = "project"             # 'project' | 'merpmod-sd'
    base_matched: bool = False
    provenance: Dict[str, str] = field(default_factory=dict)
    line: Optional[int] = None
    base_line: Optional[int] = None
    sizex: Optional[int] = None         # explicit, MerpMod SD only
    sizey: Optional[int] = None

    # -- geometry ---------------------------------------------------------
    @property
    def x_axis(self) -> Optional[Axis]:
        for a in self.axes:
            if a.type in ("X Axis", "Static X Axis"):
                return a
        return None

    @property
    def y_axis(self) -> Optional[Axis]:
        for a in self.axes:
            if a.type in ("Y Axis", "Static Y Axis"):
                return a
        return None

    @property
    def shape(self) -> Tuple[int, int]:
        """(rows, cols).  3D = Y rows x X cols, X is the fast (contiguous) axis.

        Verified against ROM bytes: e.g. 'Engine Load Compensation Cruise (MP)'
        @0xC3C3C repeats with stride 11 = its X element count, and 11*14 bytes
        end at 0xC3CD6, immediately before the next table's axis at 0xC3CD8.
        """
        if self.type == "1D":
            return (1, 1)
        if self.type == "2D":
            n = 1
            for a in self.axes:
                if a.elements:
                    n = a.elements
                    break
            return (1, n)
        # 3D
        if self.sizex and self.sizey:
            return (self.sizey, self.sizex)
        x = self.x_axis
        y = self.y_axis
        return ((y.elements or 0) if y else 0, (x.elements or 0) if x else 0)

    @property
    def n_cells(self) -> int:
        r, c = self.shape
        return r * c

    @property
    def byte_length(self) -> int:
        if self.scaling is None:
            return 0
        return self.n_cells * self.scaling.width

    @property
    def end_address(self) -> Optional[int]:
        if self.address is None:
            return None
        return self.address + self.byte_length

    @property
    def readable(self) -> bool:
        return (self.address is not None and self.scaling is not None
                and self.n_cells > 0 and self.scaling.width > 0
                and self.address + self.byte_length <= ROM_SIZE)

    # -- data -------------------------------------------------------------
    def read_raw(self, buf: bytes):
        """Stored values.  1D -> scalar, 2D -> list, 3D -> list of rows."""
        if not self.readable:
            raise ValueError("table %r is not readable: %s"
                             % (self.name, self._why_unreadable()))
        flat = self.scaling.decode(buf, self.address, self.n_cells)
        if self.type == "1D":
            return flat[0]
        if self.type == "2D":
            return flat
        rows, cols = self.shape
        return [flat[r * cols:(r + 1) * cols] for r in range(rows)]

    def read(self, buf: bytes):
        """Displayed values (toexpr applied).  Same nesting as read_raw()."""
        s = self.scaling
        d = self.read_raw(buf)
        if self.type == "1D":
            return s.to_display(d)
        if self.type == "2D":
            return [s.to_display(v) for v in d]
        return [[s.to_display(v) for v in row] for row in d]

    def _why_unreadable(self) -> str:
        if self.address is None:
            return "no address"
        if self.scaling is None:
            return "scaling %r is not defined in any XML" % self.scaling_name
        if self.scaling.width == 0:
            return "unsupported storagetype %r" % self.scaling.storagetype
        if self.n_cells == 0:
            return "element count unresolved"
        if self.address + self.byte_length > ROM_SIZE:
            return "address 0x%X is outside the 1 MiB ROM (RAM/SSM?)" % self.address
        return "?"

    # -- presentation -----------------------------------------------------
    def show(self, buf: bytes, max_rows: int = 40) -> str:
        s = self.scaling
        out = ["%s   [%s]  @0x%05X  %s" % (
            self.name, self.category, self.address or 0, self.type)]
        out.append("  scaling %s" % (s and s.raw_note()))
        for a in self.axes:
            try:
                vals = a.read(buf)
                out.append("  %-14s %s" % (
                    (a.type or "axis") + ":",
                    " ".join(str(a.scaling.fmt(v)) if a.scaling else str(v) for v in vals)))
            except Exception as e:                      # noqa: BLE001
                out.append("  %-14s <%s>" % ((a.type or "axis") + ":", e))
        try:
            d = self.read(buf)
        except ValueError as e:
            out.append("  DATA: <%s>" % e)
            return "\n".join(out)
        if self.type == "1D":
            out.append("  value: %s %s" % (s.fmt(d), s.units))
        elif self.type == "2D":
            out.append("  data:  " + "  ".join(s.fmt(v) for v in d))
        else:
            for r, row in enumerate(d[:max_rows]):
                out.append("  %3d | %s" % (r, "  ".join(s.fmt(v) for v in row)))
        return "\n".join(out)

    def __str__(self) -> str:
        return "%s @0x%s %s %s" % (
            self.name,
            ("%05X" % self.address) if self.address is not None else "?????",
            self.type, self.shape)


# --------------------------------------------------------------------------
# Parsing helpers
# --------------------------------------------------------------------------

def _line_map(path: str, root: ET.Element) -> Dict[int, int]:
    """Map document-order index of each <table>/<scaling> to its source line.

    ElementTree drops line numbers, so pair document order against a regex
    scan.  '<table' never matches '</table>', so the counts line up exactly
    (checked: 716 / 2117 / 19).
    """
    out: Dict[str, List[int]] = {"table": [], "scaling": []}
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            for m in re.finditer(r"<(table|scaling)[\s/>]", line):
                out[m.group(1)].append(n)
    return out


def _parse_scalings(root: ET.Element, source: str, lines: List[int]) -> "OrderedDict[str, Scaling]":
    res: "OrderedDict[str, Scaling]" = OrderedDict()
    for i, el in enumerate(root.findall("scaling")):
        blob = [(d.get("name") or "", d.get("value") or "")
                for d in el.findall("data")]
        res[el.get("name")] = Scaling(
            name=el.get("name"),
            storagetype=el.get("storagetype"),
            endian=el.get("endian") or "big",
            toexpr=el.get("toexpr"),
            frexpr=el.get("frexpr"),
            units=el.get("units") or "",
            min=_num(el.get("min")),
            max=_num(el.get("max")),
            inc=_num(el.get("inc")),
            format=el.get("format"),
            source=source,
            blob=blob,
            line=lines[i] if i < len(lines) else None,
        )
    return res


def _num(v):
    if v is None:
        return None
    try:
        return float(v)
    except ValueError:
        return None


def _addr(v):
    if v is None:
        return None
    try:
        return int(v, 16)
    except ValueError:
        return None


def _int(v):
    if v is None:
        return None
    try:
        return int(v)
    except ValueError:
        return None


# --------------------------------------------------------------------------
# Defs
# --------------------------------------------------------------------------

class Defs:
    """Merged, inheritance-resolved view of the definition XMLs."""

    def __init__(self, base_xml: str = BASE_XML, project_xml: str = PROJECT_XML,
                 sd_xml: Optional[str] = None):
        self.base_xml = base_xml
        self.project_xml = project_xml
        self.sd_xml = sd_xml

        self._problems: List[Problem] = []

        # ---- base ----
        broot = ET.parse(base_xml).getroot()
        blines = _line_map(base_xml, broot)
        self.base_scalings = _parse_scalings(broot, "32BITBASE", blines["scaling"])
        self._base_elems = broot.findall("table")
        self._base_lines = self._toplevel_lines(broot, blines["table"])
        self.base_by_name: Dict[str, ET.Element] = {}
        for el in self._base_elems:
            n = el.get("name")
            if n in self.base_by_name:
                self._problems.append(Problem(
                    "duplicate-base-name", n, "32BITBASE defines this name twice"))
            self.base_by_name.setdefault(n, el)

        # ---- scalings (project layer shadows base by name) ----
        self.scalings: Dict[str, Scaling] = dict(self.base_scalings)
        proot = ET.parse(project_xml).getroot()
        plines = _line_map(project_xml, proot)
        proj_scalings = _parse_scalings(proot, "project", plines["scaling"])
        for k, v in proj_scalings.items():
            if k in self.scalings:
                v.shadows = True
                self._problems.append(Problem(
                    "scaling-shadow", k,
                    "project redefines a 32BITBASE scaling (base %s -> project %s)"
                    % (self.scalings[k].toexpr, v.toexpr),
                    "project XML line %s" % v.line))
            self.scalings[k] = v

        sroot = None
        if sd_xml:
            sroot = ET.parse(sd_xml).getroot()
            slines = _line_map(sd_xml, sroot)
            for k, v in _parse_scalings(sroot, "merpmod-sd", slines["scaling"]).items():
                if k in self.scalings:
                    v.shadows = True
                self.scalings[k] = v

        # ---- tables ----
        self.tables: List[Table] = []
        proj_top = proot.findall("table")
        proj_top_lines = self._toplevel_lines(proot, plines["table"])
        for el, ln in zip(proj_top, proj_top_lines):
            self.tables.append(self._resolve(el, ln, "project"))

        if sroot is not None:
            sd_top = sroot.findall("table")
            sd_top_lines = self._toplevel_lines(sroot, _line_map(sd_xml, sroot)["table"])
            for el, ln in zip(sd_top, sd_top_lines):
                self.tables.append(self._resolve(el, ln, "merpmod-sd"))

        self._by_name = {t.name: t for t in self.tables}
        self._audit()

    # -- line bookkeeping -------------------------------------------------
    @staticmethod
    def _toplevel_lines(root: ET.Element, all_lines: List[int]) -> List[int]:
        """Document-order line numbers of top-level <table> elements only."""
        out, i = [], 0
        for el in root.findall("table"):
            out.append(all_lines[i] if i < len(all_lines) else None)
            i += 1 + len(el.findall(".//table"))
        return out

    # -- the inheritance rule --------------------------------------------
    def _resolve(self, el: ET.Element, line: Optional[int], source: str) -> Table:
        name = el.get("name")
        base = self.base_by_name.get(name)
        prov: Dict[str, str] = {}

        def pick(attr, node=el, bnode=base):
            """Project attribute wins; otherwise inherit from the base entry."""
            v = node.get(attr)
            if v is not None:
                return v, "project"
            if bnode is not None and bnode.get(attr) is not None:
                return bnode.get(attr), "base"
            return None, "unset"

        typ, prov["type"] = pick("type")
        scl, prov["scaling"] = pick("scaling")
        cat, prov["category"] = pick("category")
        lvl, prov["level"] = pick("level")
        prov["address"] = "project" if el.get("address") else "unset"

        desc_el = el.find("description")
        if desc_el is not None and (desc_el.text or "").strip():
            desc, prov["description"] = desc_el.text.strip(), "project"
        elif base is not None and base.find("description") is not None:
            desc = (base.find("description").text or "").strip()
            prov["description"] = "base"
        else:
            desc, prov["description"] = None, "unset"

        t = Table(
            name=name,
            category=cat,
            description=desc,
            address=_addr(el.get("address")),
            type=typ,
            scaling_name=scl,
            scaling=self.scalings.get(scl) if scl else None,
            level=lvl,
            source=source,
            base_matched=base is not None,
            provenance=prov,
            line=line,
            base_line=self._base_line_of(name),
            sizex=_int(el.get("sizex")),
            sizey=_int(el.get("sizey")),
        )

        # ---- axes ----
        pchildren = el.findall("table")
        bchildren = base.findall("table") if base is not None else []
        bmap = {c.get("name"): c for c in bchildren}

        if pchildren:
            for c in pchildren:
                bc = bmap.get(c.get("name"))
                ap = {}
                atyp, ap["type"] = pick("type", c, bc)
                ascl, ap["scaling"] = pick("scaling", c, bc)
                ael, ap["elements"] = pick("elements", c, bc)
                ap["address"] = "project" if c.get("address") else "unset"
                t.axes.append(Axis(
                    name=c.get("name"),
                    type=atyp,
                    address=_addr(c.get("address")),
                    elements=_int(ael),
                    scaling_name=ascl,
                    scaling=self.scalings.get(ascl) if ascl else None,
                    labels=[(d.text or "").strip() for d in c.findall("data")]
                           or ([(d.text or "").strip() for d in bc.findall("data")]
                               if bc is not None else []),
                    provenance=ap,
                ))
        else:
            # project stated no children -> inherit the base's whole
            for c in bchildren:
                t.axes.append(Axis(
                    name=c.get("name"),
                    type=c.get("type"),
                    address=None,
                    elements=_int(c.get("elements")),
                    scaling_name=c.get("scaling"),
                    scaling=self.scalings.get(c.get("scaling")) if c.get("scaling") else None,
                    labels=[(d.text or "").strip() for d in c.findall("data")],
                    provenance={"type": "base", "scaling": "base",
                                "elements": "base", "address": "unset"},
                ))
        return t

    def _base_line_of(self, name: str) -> Optional[int]:
        try:
            i = [e.get("name") for e in self._base_elems].index(name)
        except ValueError:
            return None
        return self._base_lines[i] if i < len(self._base_lines) else None

    # -- audit ------------------------------------------------------------
    def _audit(self):
        for t in self.tables:
            if t.scaling_name and t.scaling is None:
                self._problems.append(Problem(
                    "undefined-scaling", t.name,
                    "scaling=%r is not defined in any XML" % t.scaling_name,
                    "project XML line %s" % t.line))
            if t.address is None:
                self._problems.append(Problem(
                    "no-address", t.name, "table has no address= -> unreadable",
                    "project XML line %s" % t.line))
            elif t.address >= ROM_SIZE:
                self._problems.append(Problem(
                    "address-outside-rom", t.name,
                    "0x%X >= 0x%X (RAM/SSM address, not a ROM offset)" % (t.address, ROM_SIZE),
                    "project XML line %s" % t.line))
            if t.type is None:
                self._problems.append(Problem(
                    "no-type", t.name, "type unresolved (no project type=, no base match)"))
            for a in t.axes:
                if a.is_static:
                    continue
                if a.address is None and t.address is not None:
                    self._problems.append(Problem(
                        "axis-no-address", t.name,
                        "axis %r (%s) has no address" % (a.name, a.type),
                        "project XML line %s" % t.line))
                if a.elements in (None, 0):
                    self._problems.append(Problem(
                        "axis-no-elements", t.name,
                        "axis %r has no element count" % (a.name,)))
                if a.scaling_name and a.scaling is None:
                    self._problems.append(Problem(
                        "undefined-scaling", t.name,
                        "axis %r scaling=%r undefined" % (a.name, a.scaling_name)))

    def problems(self, kind: Optional[str] = None) -> List[Problem]:
        if kind is None:
            return list(self._problems)
        return [p for p in self._problems if p.kind == kind]

    # -- lookup -----------------------------------------------------------
    def get(self, name: str) -> Table:
        return self._by_name[name]

    def find(self, name: str) -> Optional[Table]:
        return self._by_name.get(name)

    def search(self, needle: str) -> List[Table]:
        n = needle.lower()
        return [t for t in self.tables
                if n in (t.name or "").lower() or n in (t.category or "").lower()]

    def at(self, address: int, include_axes: bool = False) -> List[Any]:
        """Every table (and optionally axis) whose data starts at `address`."""
        out: List[Any] = [t for t in self.tables if t.address == address]
        if include_axes:
            for t in self.tables:
                out.extend(a for a in t.axes if a.address == address)
        return out

    def covering(self, address: int) -> List[Table]:
        """Tables whose data RANGE contains `address`."""
        return [t for t in self.tables
                if t.readable and t.address <= address < t.end_address]

    def by_category(self) -> "OrderedDict[str, List[Table]]":
        out: "OrderedDict[str, List[Table]]" = OrderedDict()
        for t in sorted(self.tables, key=lambda x: (x.category or "", x.name)):
            out.setdefault(t.category, []).append(t)
        return out

    def categories(self) -> Counter:
        return Counter(t.category for t in self.tables)

    # -- structural queries ----------------------------------------------
    def unique_to_project(self) -> List[Table]:
        """Project tables with no 32BITBASE counterpart of the same name."""
        return [t for t in self.tables if not t.base_matched]

    def unused_base_names(self) -> List[str]:
        used = {t.name for t in self.tables}
        return [n for n in self.base_by_name if n not in used]

    def shared_addresses(self, include_axes: bool = True) -> "OrderedDict[int, List[str]]":
        """Addresses reachable under more than one name/scaling."""
        m: Dict[int, List[str]] = defaultdict(list)
        for t in self.tables:
            if t.address is not None:
                m[t.address].append("TABLE %s (%s)" % (t.name, t.scaling_name))
            if include_axes:
                for a in t.axes:
                    if a.address is not None:
                        m[a.address].append("AXIS  %s / %s (%s)"
                                            % (t.name, a.name, a.scaling_name))
        return OrderedDict(sorted((k, v) for k, v in m.items() if len(v) > 1))

    def element_overrides(self) -> List[Tuple[str, str, Optional[str], Optional[int]]]:
        """Axes where the project's elements= disagrees with 32BITBASE."""
        out = []
        for t in self.tables:
            base = self.base_by_name.get(t.name)
            if base is None:
                continue
            bmap = {c.get("name"): c for c in base.findall("table")}
            for a in t.axes:
                if a.provenance.get("elements") != "project":
                    continue
                bc = bmap.get(a.name)
                be = bc.get("elements") if bc is not None else None
                if be != str(a.elements):
                    out.append((t.name, a.name or "", be, a.elements))
        return out

    def attribute_overrides(self, attr: str) -> List[Tuple[str, str, str]]:
        """Matched tables where the project restates `attr` differently."""
        out = []
        for t in self.tables:
            base = self.base_by_name.get(t.name)
            if base is None:
                continue
            pv = getattr(t, attr if attr != "scaling" else "scaling_name")
            bv = base.get(attr)
            if t.provenance.get(attr) == "project" and bv is not None and str(pv) != bv:
                out.append((t.name, bv, str(pv)))
        return out

    def used_scalings(self) -> Counter:
        c: Counter = Counter()
        for t in self.tables:
            if t.scaling_name:
                c[t.scaling_name] += 1
            for a in t.axes:
                if a.scaling_name:
                    c[a.scaling_name] += 1
        return c

    def raw_differs_from_display(self) -> List[Scaling]:
        """Scalings actually used where the stored value != the shown value."""
        used = self.used_scalings()
        out = [self.scalings[n] for n in used
               if n in self.scalings and not self.scalings[n].raw_is_display]
        return sorted(out, key=lambda s: (-used[s.name], s.name))

    # -- ROM cross-check --------------------------------------------------
    def audit_layout(self, buf: bytes) -> List[str]:
        """Sanity-check resolved geometry against the ROM image.

        Reports data ranges that run past the end of the ROM and 3D tables
        whose axes are NOT contiguous with the data (the normal Subaru layout
        is Y axis, X axis, then data -- or X, Y, data -- back to back, so a
        gap usually means a wrong element count).
        """
        notes = []
        for t in self.tables:
            if t.address is None or t.scaling is None:
                continue
            if t.address >= len(buf):
                notes.append("OUTSIDE ROM   %s @0x%X" % (t.name, t.address))
                continue
            if t.end_address and t.end_address > len(buf):
                notes.append("OVERRUNS ROM  %s @0x%X + %d bytes" %
                             (t.name, t.address, t.byte_length))
            real = [a for a in t.axes if not a.is_static and a.address is not None
                    and a.scaling is not None and a.elements]
            if not real:
                continue
            ends = sorted(a.address + a.byte_length for a in real)
            if ends and ends[-1] != t.address:
                gap = t.address - ends[-1]
                notes.append("AXIS GAP %+5d  %-52s data@0x%05X last-axis-end@0x%05X"
                             % (gap, t.name, t.address, ends[-1]))
        return notes

    # -- summary ----------------------------------------------------------
    def summary(self) -> "OrderedDict[str, Any]":
        used = self.used_scalings()
        undef = sorted({p.detail.split("'")[1] if "'" in p.detail else p.detail
                        for p in self.problems("undefined-scaling")})
        s: "OrderedDict[str, Any]" = OrderedDict()
        s["base_tables_total"] = len(self._base_elems)
        s["base_toplevel"] = len(self.base_by_name)
        s["base_scalings"] = len(self.base_scalings)
        s["project_toplevel"] = len([t for t in self.tables if t.source == "project"])
        s["project_with_base_match"] = len([t for t in self.tables if t.base_matched])
        s["project_unique"] = len(self.unique_to_project())
        s["base_names_never_used"] = len(self.unused_base_names())
        s["type_1D"] = len([t for t in self.tables if t.type == "1D"])
        s["type_2D"] = len([t for t in self.tables if t.type == "2D"])
        s["type_3D"] = len([t for t in self.tables if t.type == "3D"])
        s["axes_total"] = sum(len(t.axes) for t in self.tables)
        s["axes_static"] = sum(1 for t in self.tables for a in t.axes if a.is_static)
        s["axes_addressed"] = sum(1 for t in self.tables for a in t.axes
                                  if a.address is not None)
        s["element_overrides"] = len(self.element_overrides())
        s["scaling_overrides"] = len(self.attribute_overrides("scaling"))
        s["category_overrides"] = len(self.attribute_overrides("category"))
        s["scalings_referenced"] = len(used)
        s["scalings_raw_ne_display"] = len(self.raw_differs_from_display())
        s["scalings_undefined"] = len(undef)
        s["shared_addresses"] = len(self.shared_addresses())
        s["categories"] = len(self.categories())
        s["problems"] = len(self._problems)
        return s


def load(base_xml: str = BASE_XML, project_xml: str = PROJECT_XML,
         include_sd: bool = False, sd_xml: str = SD_XML) -> Defs:
    """Load and resolve the definitions.  This is the entry point."""
    return Defs(base_xml, project_xml, sd_xml if include_sd else None)


# --------------------------------------------------------------------------
# __main__
# --------------------------------------------------------------------------

def _main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Summarise the resolved AE5L600L definitions.")
    ap.add_argument("--sd", action="store_true", help="include the MerpMod SD port")
    ap.add_argument("--rom", default=STOCK_ROM, help="ROM image for the layout audit")
    ap.add_argument("--table", help="dump one table by exact name")
    ap.add_argument("--search", help="list tables matching a substring")
    args = ap.parse_args()

    d = load(include_sd=args.sd)

    if args.search:
        for t in d.search(args.search):
            print("  %-62s %-34s %s" % (t.name, t.category, t))
        return 0

    if args.table:
        t = d.find(args.table)
        if t is None:
            print("no such table: %r" % args.table)
            return 1
        buf = open(args.rom, "rb").read()
        print(t.show(buf))
        print("\n  provenance:", dict(t.provenance))
        print("  project XML line %s, 32BITBASE line %s" % (t.line, t.base_line))
        return 0

    print("=" * 78)
    print("AE5L600L definition summary")
    print("=" * 78)
    for k, v in d.summary().items():
        print("  %-28s %s" % (k, v))

    print("\n-- categories (project taxonomy) " + "-" * 44)
    for cat, n in sorted(d.categories().items(), key=lambda kv: (-kv[1], kv[0] or "")):
        print("  %5d  %s" % (n, cat))

    print("\n-- scalings where RAW != DISPLAY (top 20 by use) " + "-" * 28)
    used = d.used_scalings()
    for sc in d.raw_differs_from_display()[:20]:
        print("  %-52s x%-3d %-7s %-28s -> %s"
              % (sc.name, used[sc.name], sc.storagetype, sc.toexpr, sc.units))

    print("\n-- one address, several names " + "-" * 47)
    for addr, names in d.shared_addresses().items():
        print("  0x%05X" % addr)
        for n in names:
            print("      %s" % n)

    probs = d.problems()
    print("\n-- unresolved definitions (%d) " % len(probs) + "-" * 44)
    for p in probs:
        print("  " + str(p))

    if os.path.exists(args.rom):
        buf = open(args.rom, "rb").read()
        notes = d.audit_layout(buf)
        print("\n-- ROM layout audit vs %s (%d notes) " % (os.path.basename(args.rom), len(notes))
              + "-" * 12)
        for n in notes[:40]:
            print("  " + n)
        if len(notes) > 40:
            print("  ... %d more" % (len(notes) - 40))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
