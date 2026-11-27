#!/usr/bin/env python3
"""Function-level census of the ROM, derived from bytes.

    python scripts/mapping/function_census.py                 # summary
    python scripts/mapping/function_census.py --json disassembly/maps/function_census.json
    python scripts/mapping/function_census.py --rank 40       # untraced worklist
    python scripts/mapping/function_census.py --rom <path>

WHY THIS EXISTS
The project's coverage figure ("8.1% of code traced") counts instruction
addresses. That says how much has been read, not WHAT is left: it cannot answer
"which functions has nobody looked at", "which of those sit under a scheduler
task", or "which consume a table". This tool builds the missing denominator.

WHAT IT DOES
1. Recursive descent from proven entry points only: the exception vector table
   and every call/tail-jump target reached from them (bsr, and jsr/jmp through a
   register whose value is a PC-relative literal). Code is what control flow
   reaches -- NOT what rom_region_map.txt classifies as "code" (a 256-byte block
   heuristic, i.e. a derived product).
2. A second pass seeds from POINTERS: any aligned long, outside reached code,
   whose value is an even ROM address that decodes cleanly to a terminator.
   Those functions are tagged `ptr` -- reached through a table or a callback,
   which is exactly where a call-graph-only walk goes blind.
3. Per function: byte extent, instruction count, callers, callees, GBR bases,
   RAM / descriptor / calibration literals, FPU share, and how many of its
   instructions already appear byte-verified in disassembly/analysis/*.txt.

EVERYTHING IN THE OUTPUT IS MECHANICAL. Existing Ghidra label names are carried
in a `label_claim` field purely so a reader can find the function; they are
claims (CLAUDE.md rule 7), never used for ranking or classification.

LIMITS, STATED UP FRONT
* Function extents are the address-order partition [entry, next entry). Shared
  tails are attributed to the lower entry.
* `jsr @Rn` targets come from forward constant propagation over the control-flow
  graph (reg_states; corrections item 106), not a backward scan. A register that
  is not a constant on every path (computed dispatch, `bsrf`, `braf`, a value
  parked in RAM or the stack) is counted in `unresolved_calls`, not followed.
* `ptr` and `orphan` entries are a heuristic. They are reported separately so a
  count never silently mixes proven and inferred entries, and a seed whose bytes
  look like data (data_signature) is rejected and listed in `rejected_seeds`.
* Some census entries are fall-through targets of the code before them, so one
  function is split in two (30 in the corrected census; the batch-1
  helpers_interp trace counts them).
"""
import argparse
import collections
import glob
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
from sh2e_disasm import decode          # noqa: E402

REPO = os.path.normpath(os.path.join(HERE, '..', '..'))
DEFAULT_ROM = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
ANALYSIS = os.path.join(REPO, 'disassembly', 'analysis')
JAVA = os.path.join(REPO, 'disassembly', 'ghidra', 'ImportAE5L600L.java')

ROM_SIZE = 0x100000
# Two vector tables, both read from bytes:
#   0x000000  the reset/exception table the CPU uses before VBR is set. Only
#             the first 14 longs are vectors; code starts at 0x40.
#   0x0FFC50  the live table. Startup loads VBR from the literal at 0x00FCC4
#             (00FA3E: D2A1 mov.l / 00FA40: 422E ldc r2,vbr) -- corrections
#             item 3. It runs to the end of the image.
RESET_VECTORS = (0x000000, 0x000038)
VBR_LITERAL = 0x00FCC4
CODE_LO = 0x40
CAL_LO = 0xC0000               # calibration tables, then the erased hole
RAM_LO, RAM_HI = 0xFFFF0000, 0xFFFFC000
PERIPH_LO = 0xFFFFE000

# verify_disasm_v2's line shape: "  043A1E: 450B  jsr @r0"
LINE = re.compile(r'^\s*(?:0x)?([0-9A-Fa-f]{5,6})\s*:\s*([0-9A-Fa-f]{4})\s+\S')


def u16(rom, a):
    return struct.unpack_from('>H', rom, a)[0]


def u32(rom, a):
    return struct.unpack_from('>I', rom, a)[0]


# --------------------------------------------------------------------------
# instruction classification -- from the encoding, not from decode()'s text
# --------------------------------------------------------------------------

def flow_of(w, pc):
    """Return (kind, target, has_delay_slot).

    kind: 'seq' | 'cond' | 'jump' | 'call' | 'ijump' | 'icall' | 'ret' | 'bad'
    """
    op = w >> 12
    if w in (0x000B, 0x002B):
        return 'ret', None, True
    if op == 0x8:
        sub = (w >> 8) & 0xF
        if sub in (0x9, 0xB, 0xD, 0xF):
            d = w & 0xFF
            d = d - 0x100 if d & 0x80 else d
            return 'cond', pc + 4 + d * 2, sub in (0xD, 0xF)
    if op in (0xA, 0xB):
        d = w & 0xFFF
        d = d - 0x1000 if d & 0x800 else d
        return ('jump' if op == 0xA else 'call'), pc + 4 + d * 2, True
    if op == 0x4:
        lo = w & 0xFF
        if lo == 0x0B:
            return 'icall', (w >> 8) & 0xF, True
        if lo == 0x2B:
            return 'ijump', (w >> 8) & 0xF, True
    if op == 0x0 and (w & 0xF) == 0x3:
        m = (w >> 4) & 0xF
        if m == 0x0:
            return 'icall', None, True          # bsrf -- computed
        if m == 0x2:
            return 'ijump', None, True          # braf -- computed
    text, _ = decode(w, pc)
    if text.startswith('.word'):
        return 'bad', None, False
    return 'seq', None, False


def writes(w):
    """Set of general registers this instruction writes (conservative)."""
    op = w >> 12
    n, m, d4 = (w >> 8) & 0xF, (w >> 4) & 0xF, w & 0xF
    if op in (0xD, 0x9, 0xE, 0x7, 0x5):
        return {n}
    if op == 0x6:
        return {n, m} if d4 in (0x4, 0x5, 0x6) else {n}
    if op == 0x3:
        return set() if d4 in (0x0, 0x2, 0x3, 0x6, 0x7) else {n}
    if op == 0x2:
        if d4 in (0x4, 0x5, 0x6):
            return {n}                           # pre-decrement store
        return {n} if d4 in (0x9, 0xA, 0xB, 0xD, 0xE, 0xF) and d4 in (0x9, 0xA, 0xB, 0xD) else set()
    if op == 0x0:
        if d4 in (0xC, 0xD, 0xE, 0xA, 0x2):
            return {n}
        if d4 == 0x9 and m == 0x2:
            return {n}
        if d4 == 0x7:
            return set()                         # mul.l -> macl
        if d4 == 0xF:
            return {n, m}
        return set()
    if op == 0x4:
        lo = w & 0xFF
        if lo in (0x0B, 0x2B, 0x1B, 0x0A, 0x1A, 0x2A, 0x5A, 0x6A, 0x0E, 0x1E, 0x2E, 0x11, 0x15):
            return set()
        if d4 == 0xF:
            return {n, m}
        return {n}                               # shifts, dt, push/pop via Rn
    if op == 0x8:
        sub = (w >> 8) & 0xF
        return {0} if sub in (0x4, 0x5) else set()
    if op == 0xC:
        sub = (w >> 8) & 0xF
        return {0} if sub in (0x4, 0x5, 0x6, 0x7, 0x9, 0xA, 0xB) else set()
    if op == 0xF:
        if d4 == 0x9:
            return {m}                           # fmov.s @Rm+,FRn
        if d4 == 0xB:
            return {n}                           # fmov.s FRm,@-Rn
        return set()
    return set()


def dispatch_table(rom, pc, reg, floor):
    """Entries of a ROM pointer table an indirect call indexes, if provable.

    Recognises the load feeding `jsr/jmp @Rn`:
        mov.l @(r0,Rm),Rn   base = whichever of r0/Rm is a ROM literal
        mov.l @Rm,Rn        one cell, Rm a ROM literal
        mov.l @(d,Rm),Rn    one cell at literal + d
    Returns (table_address, [targets]) or None. The table is read while its
    longs are even ROM code addresses -- the run length is the table's own
    evidence, there is no count in the code.
    """
    a = pc - 2
    steps = 0
    while a >= floor and steps < 60:
        w = u16(rom, a)
        if reg in writes(w):
            op, n, m, d4 = w >> 12, (w >> 8) & 0xF, (w >> 4) & 0xF, w & 0xF
            if n != reg:
                return None
            cells = None
            if op == 0x0 and d4 == 0xE:
                for r in (0, m):
                    b = resolve_reg(rom, a, r, floor)
                    if b is not None and CODE_LO <= b < ROM_SIZE - 4 and not (b & 3):
                        cells = (b, 4096)
                        break
            elif op == 0x6 and d4 == 0x2:
                b = resolve_reg(rom, a, m, floor)
                if b is not None and CODE_LO <= b < ROM_SIZE - 4 and not (b & 3):
                    cells = (b, 1)
            elif op == 0x5:
                b = resolve_reg(rom, a, m, floor)
                if b is not None and CODE_LO <= b + d4 * 4 < ROM_SIZE - 4 and not (b & 3):
                    cells = (b + d4 * 4, 1)
            if cells is None:
                return None
            base, limit = cells
            out = []
            for i in range(limit):
                v = u32(rom, base + 4 * i)
                if not (CODE_LO <= v < 0xC0000) or (v & 1):
                    break
                out.append(v)
            return (base, out) if out else None
        a -= 2
        steps += 1
    return None


def lit_target(pc, w):
    """Address of the literal a PC-relative mov.l reads."""
    return ((pc + 4) & ~3) + (w & 0xFF) * 4


def resolve_reg(rom, pc, reg, floor, depth=0):
    """Value of `reg` at `pc`, if the nearest prior write is a literal load.

    Walks backwards in ADDRESS order to `floor`. That is a linear approximation
    of control flow; it is right for the overwhelmingly common
    `mov.l @(pool),Rn ... jsr @Rn` shape and returns None otherwise.
    """
    if depth > 3:
        return None
    a = pc - 2
    steps = 0
    while a >= floor and steps < 400:
        w = u16(rom, a)
        if reg in writes(w):
            op = w >> 12
            if op == 0xD and ((w >> 8) & 0xF) == reg:
                t = lit_target(a, w)
                return u32(rom, t) if t + 4 <= len(rom) else None
            if op == 0x9 and ((w >> 8) & 0xF) == reg:
                # mov.w @(disp,pc),Rn sign-extends. Low-ROM routines are called
                # this way (000662: mov.w @(0x00071C),r3 / jsr @r3).
                t = a + 4 + (w & 0xFF) * 2
                v = u16(rom, t)
                return v - 0x10000 + 0x100000000 if v & 0x8000 else v
            if op == 0x6 and (w & 0xF) == 0x3 and ((w >> 8) & 0xF) == reg:
                return resolve_reg(rom, a, (w >> 4) & 0xF, floor, depth + 1)
            return None
        a -= 2
        steps += 1
    return None



# --------------------------------------------------------------------------
# register values by forward constant propagation over the control-flow graph
# --------------------------------------------------------------------------
# resolve_reg() above walks backwards in ADDRESS order. Where a `jsr @Rn` is a
# branch target and the fall-through path reloads Rn, it names the fall-through's
# callee (0451CE: reached by `bt` from 04519E with r2 = 0x0BE554; the backward
# walk finds 0451B8, r2 = 0x0BE53C). Corrections item 106. reg_states() follows
# the real edges instead. Nodes are (pc, role): role None is the instruction
# executed in sequence, role = branch pc when it runs as that branch's delay
# slot -- one address can be both (0x058686 is).
M32 = 0xFFFFFFFF


def sx(v, bits):
    v &= (1 << bits) - 1
    return (v - (1 << bits)) & M32 if v >> (bits - 1) else v


SET_CAP = 4        # a register may hold one of up to this many known constants


def _k(v):
    return None if v is None else frozenset((v & M32,))


def _map1(f, a):
    return None if a is None else frozenset(f(x) & M32 for x in a)


def _map2(f, a, b):
    if a is None or b is None:
        return None
    out = frozenset(f(x, y) & M32 for x in a for y in b)
    return out if len(out) <= SET_CAP else None


def single(v):
    """The constant a register holds on every path, or None."""
    return next(iter(v)) if v is not None and len(v) == 1 else None


def transfer(rom, pc, w, R):
    """Register values after w at pc. Each value is None (unknown) or a frozenset
    of the constants it can hold -- a JOIN of two literal loads keeps both
    (02FBD0/02FBD4 load r4 = 0x0AC388 or 0x0AC394 before one call)."""
    R = list(R)
    op, n, m, d4 = w >> 12, (w >> 8) & 0xF, (w >> 4) & 0xF, w & 0xF
    if op == 0xD:
        t = ((pc + 4) & ~3) + (w & 0xFF) * 4
        R[n] = _k(u32(rom, t)) if t + 4 <= len(rom) else None
        return R
    if op == 0x9:
        t = pc + 4 + (w & 0xFF) * 2
        R[n] = _k(sx(u16(rom, t), 16)) if t + 2 <= len(rom) else None
        return R
    if op == 0xE:
        R[n] = _k(sx(w & 0xFF, 8))
        return R
    if op == 0x7:
        i = sx(w & 0xFF, 8)
        R[n] = _map1(lambda x: x + i, R[n])
        return R
    if op == 0xC:
        if n == 0x7:
            R[0] = _k(((pc + 4) & ~3) + (w & 0xFF) * 4)
            return R
        if n in (0x9, 0xA, 0xB):
            i = w & 0xFF
            R[0] = _map1((lambda x: x & i) if n == 0x9 else (lambda x: x ^ i) if n == 0xA else (lambda x: x | i), R[0])
            return R
    if op == 0x6:
        v = R[m]
        if d4 == 0x3:
            R[n] = v
            return R
        if d4 in (0xC, 0xD, 0xE, 0xF):
            f = {0xC: lambda x: x & 0xFF, 0xD: lambda x: x & 0xFFFF,
                 0xE: lambda x: sx(x, 8), 0xF: lambda x: sx(x, 16)}[d4]
            R[n] = _map1(f, v)
            return R
        if d4 in (0x4, 0x5, 0x6):
            R[n] = None
            if m != n:
                k = 1 << (d4 - 4)
                R[m] = _map1(lambda x: x + k, v)
            return R
        if d4 == 0xB:
            R[n] = _map1(lambda x: -x, v)
            return R
        if d4 == 0x7:
            R[n] = _map1(lambda x: ~x, v)
            return R
    if op == 0x3 and d4 in (0xC, 0x8):
        R[n] = _map2((lambda a, b: a + b) if d4 == 0xC else (lambda a, b: a - b), R[n], R[m])
        return R
    if op == 0x2 and d4 in (0x9, 0xA, 0xB):
        f = {0x9: lambda a, b: a & b, 0xA: lambda a, b: a ^ b, 0xB: lambda a, b: a | b}[d4]
        R[n] = _map2(f, R[n], R[m])
        return R
    if op == 0x2 and d4 in (0x4, 0x5, 0x6):
        k = 1 << (d4 - 4)
        R[n] = _map1(lambda x: x - k, R[n])
        return R
    if op == 0x4 and (w & 0xFF) in (0x08, 0x18, 0x28, 0x09, 0x19, 0x29, 0x00, 0x01):
        sh = {0x08: 2, 0x18: 8, 0x28: 16, 0x00: 1, 0x09: -2, 0x19: -8, 0x29: -16, 0x01: -1}[w & 0xFF]
        R[n] = _map1((lambda x: x << sh) if sh > 0 else (lambda x: x >> -sh), R[n])
        return R
    for x in writes(w):
        R[x] = None
    return R


def _join(a, b):
    if a is None or b is None:
        return None
    if a == b:
        return a
    u = a | b
    return u if len(u) <= SET_CAP else None


def reg_states(rom, entry, limit=40000, callee_saves=True):
    """In-state of every node reachable from entry without entering calls.

    Returns {(pc, role): tuple16}; each value None or a frozenset of constants.
    A call (bsr/jsr/bsrf) clobbers r0-r7 after its slot; r8-r14 survive it
    (Renesas SH ABI) when callee_saves is True.
    """
    NONE = (None,) * 16
    ins = {(entry, None): NONE}
    queue = collections.deque([(entry, None)])
    queued = {(entry, None)}
    while queue:
        node = queue.popleft()
        queued.discard(node)
        pc, role = node
        if pc < 0 or pc + 2 > len(rom) or (pc & 1):
            continue
        st = ins[node]
        w = u16(rom, pc)
        if role is None:
            kind, tgt, delay = flow_of(w, pc)
            if kind == 'bad':
                continue
            if delay:
                dw = u16(rom, pc + 2)
                if flow_of(dw, pc + 2)[0] != 'seq':
                    continue
                succ = [((pc + 2, pc), st)]          # branch writes no GPR (jsr/bsr write PR)
            elif kind == 'cond':
                succ = [((tgt, None), st), ((pc + 2, None), st)]
            elif kind == 'seq':
                succ = [((pc + 2, None), tuple(transfer(rom, pc, w, st)))]
            else:
                succ = []
        else:
            bw = u16(rom, role)
            kind, tgt, _ = flow_of(bw, role)
            out = transfer(rom, pc, w, st)
            if kind in ('call', 'icall'):
                out = ([None] * 8 + list(out[8:])) if callee_saves else [None] * 16
            out = tuple(out)
            if kind == 'cond':
                succ = [((tgt, None), out), ((role + 4, None), out)]
            elif kind == 'jump':
                succ = [((tgt, None), out)]
            elif kind in ('call', 'icall'):
                succ = [((role + 4, None), out)]
            else:
                succ = []                            # ret / ijump / braf
        for nd, s_ in succ:
            old = ins.get(nd)
            if old is None:
                new = s_
            else:
                new = tuple(_join(a, b) for a, b in zip(old, s_))
                if new == old:
                    continue
            ins[nd] = new
            if nd not in queued:
                if len(ins) > limit:
                    return ins
                queue.append(nd)
                queued.add(nd)
    return ins


def call_args(rom, states, pc):
    """Registers as the callee sees them at the call at pc (after its delay slot)."""
    st = states.get((pc + 2, pc))
    if st is None:
        return None
    return transfer(rom, pc + 2, u16(rom, pc + 2), st)


# --------------------------------------------------------------------------
# recursive descent
# --------------------------------------------------------------------------

class Census:
    def __init__(self, rom):
        self.rom = rom
        self.code = {}                 # addr -> word, every reached instruction
        self.entries = {}              # addr -> evidence class
        self.calls = collections.defaultdict(set)     # caller pc -> target
        self.unresolved = collections.Counter()       # entry-less pc list
        self.bad = set()
        self.tables = {}               # dispatch site -> (table address, entries)
        self.ptr_sources = {}          # ptr entry -> address of the long naming it
        self.known_data = set()
        self.flow = set()              # addresses walked as an instruction in sequence
                                       # (a delay slot alone is in code but not here)
        self.rs = {}                   # walk start -> reg_states()
        self.resolution = collections.Counter()   # how each indirect site was resolved
        self.disagree = {}             # site -> (cfg value, address-order value)
        self.last_joins = []           # where the last walk ran into committed code
        self.rejected_seeds = {}       # seed -> (class, source long or None, join pc)

    def valid_code_addr(self, a):
        return 0 <= a < ROM_SIZE - 2 and not (a & 1)

    def add_entry(self, a, why):
        if not self.valid_code_addr(a):
            return False
        if a in self.entries:
            # keep the strongest evidence class
            order = ['vector', 'call', 'tailjmp', 'table', 'tailbra', 'ptr', 'orphan']
            if order.index(why) < order.index(self.entries[a]):
                self.entries[a] = why
            return False
        self.entries[a] = why
        return True

    def walk(self, start, commit=True, limit=20000):
        """Follow control flow from `start`. Returns (ok, visited, new_entries).

        With commit=False nothing is recorded -- used to TRIAL a pointer seed.
        """
        rom = self.rom
        visited = {}
        walked = set()
        joins = []
        new_entries = []
        calls = []
        tables = []
        work = [start]
        ok = True
        terminated = False
        states = None
        while work:
            pc = work.pop()
            floor = start
            while True:
                # A delay slot is visited but not WALKED: a branch may still target
                # it and execution continues from there (0x058686 -- corrections
                # item 106). Stop only at addresses already walked in sequence.
                if pc in walked:
                    break
                if pc in self.flow:
                    joins.append(pc)
                    break
                if not self.valid_code_addr(pc) or len(visited) > limit:
                    ok = False
                    break
                w = u16(rom, pc)
                kind, tgt, delay = flow_of(w, pc)
                if kind == 'bad':
                    ok = False
                    if commit:
                        self.bad.add(pc)
                    break
                visited[pc] = w
                walked.add(pc)
                if delay:
                    ds = pc + 2
                    dw = u16(rom, ds)
                    dk, _, _ = flow_of(dw, ds)
                    if dk == 'bad':
                        ok = False
                        if commit:
                            self.bad.add(ds)
                        break
                    if dk != 'seq':
                        ok = False              # branch in a delay slot: illegal
                        break
                    visited[ds] = dw
                nxt = pc + (4 if delay else 2)
                if kind == 'seq':
                    pc = nxt
                    continue
                if kind == 'cond':
                    work.append(tgt)
                    pc = nxt
                    continue
                if kind == 'jump':
                    terminated = True
                    work.append(tgt)
                    break
                if kind == 'call':
                    new_entries.append((tgt, 'call'))
                    calls.append((pc, tgt))
                    pc = nxt
                    continue
                if kind in ('icall', 'ijump'):
                    v = None
                    if tgt is not None:
                        if states is None:
                            states = self.rs.get(start)
                            if states is None:
                                states = reg_states(rom, start)
                                if commit:
                                    self.rs[start] = states
                        st = states.get((pc, None))
                        lin = resolve_reg(rom, pc, tgt, floor)
                        if st is not None:
                            v = st[tgt]
                            how = ('cfg' if len(v) == 1 else 'cfg-set') if v is not None else 'cfg-unknown'
                            if v is not None and lin is not None and lin not in v and commit:
                                self.disagree[pc] = (min(v), lin)
                        else:
                            v = _k(lin)
                            how = 'address-order' if v is not None else 'unreached'
                        if commit:
                            self.resolution[how] += 1
                    if v is not None and all(CODE_LO <= x < ROM_SIZE and not (x & 1) for x in v):
                        for x in sorted(v):
                            new_entries.append((x, 'call' if kind == 'icall' else 'tailjmp'))
                            calls.append((pc, x))
                    else:
                        tab = dispatch_table(rom, pc, tgt, floor) if tgt is not None else None
                        if tab:
                            tables.append((pc, tab[0], len(tab[1])))
                            for t in tab[1]:
                                new_entries.append((t, 'table'))
                                calls.append((pc, t))
                        else:
                            calls.append((pc, None))
                    if kind == 'ijump':
                        terminated = True
                        break
                    pc = nxt
                    continue
                if kind == 'ret':
                    terminated = True
                    break
        self.last_joins = joins
        if commit:
            self.code.update(visited)
            self.flow.update(walked)
            for site, base, n in tables:
                self.tables[site] = (base, n)
            for pc, t in calls:
                if t is None:
                    self.unresolved[pc] += 1
                else:
                    self.calls[pc].add(t)
        return ok and terminated, visited, new_entries

    def descend(self, seeds):
        queue = list(seeds)
        while queue:
            a = queue.pop()
            _, _, new = self.walk(a)
            for t, why in new:
                if self.add_entry(t, why):
                    queue.append(t)
                elif t not in self.code:
                    queue.append(t)

    def seed_vectors(self):
        rom = self.rom
        seeds = []
        vbr = u32(rom, VBR_LITERAL)
        spans = [RESET_VECTORS]
        if vbr < ROM_SIZE and not (vbr & 3):
            spans.append((vbr, ROM_SIZE))
        self.vbr = vbr
        for lo, hi in spans:
            for a in range(lo, hi, 4):
                v = u32(rom, a)
                if CODE_LO <= v < ROM_SIZE and not (v & 1):
                    if self.add_entry(v, 'vector'):
                        seeds.append(v)
        return seeds

    # Mnemonics that occur NOWHERE in the 116,872 vector-rooted instructions
    # (measured 2026-11-27) and that data decoded as code produces readily.
    NEVER_IN_CODE = ('trapa', 'sleep', 'mac.l', 'mac.w')

    def data_signature(self, visited, start):
        """Why a trial walk looks like data decoded as code, or None.

        Each test is a property of the bytes, not a heuristic score:
          * an instruction from NEVER_IN_CODE;
          * a post-increment load into its own address register (`mov.l @r6+,r6`:
            architecturally undefined; zero occurrences in proven code);
          * a call or jump whose target the CFG resolves to a CONSTANT that is not
            a ROM code address (0x011954: `bra 0x0124C8 / mov #-46,r1` then
            `jsr @r1`, a call to 0xFFFFFFD2).
        Corrections item 106.
        """
        rom = self.rom
        for p, w in visited.items():
            t = decode(w, p)[0].split()[0]
            if t in self.NEVER_IN_CODE:
                return f'{t} at 0x{p:06X}'
            if (w >> 12) == 0x6 and (w & 0xF) in (4, 5, 6) and ((w >> 8) & 0xF) == ((w >> 4) & 0xF):
                return f'self-post-increment load at 0x{p:06X}'
        # every node the seed's register state reaches, INCLUDING code past the
        # point where the trial walk joined already-reached code (0x011954's bad
        # call is at 0x0124CC, beyond its join at 0x0124C8)
        states = reg_states(rom, start, limit=8000)
        for (p, role), st in states.items():
            if role is not None:
                continue
            w = u16(rom, p)
            if (w >> 12) == 0x4 and (w & 0xFF) in (0x0B, 0x2B):
                v = st[(w >> 8) & 0xF]
                if v is not None and not any(CODE_LO <= x < CAL_LO and not (x & 1) for x in v):
                    return f'constant call target 0x{min(v):08X} at 0x{p:06X}'
        return None

    def seed_pointers(self, lo=CODE_LO, hi=0xC0000):
        """Aligned longs outside reached code that point at clean code."""
        rom = self.rom
        added = 0
        changed = True
        while changed:
            changed = False
            for a in range(0, ROM_SIZE - 4, 4):
                if a in self.code or (a + 2) in self.code:
                    continue
                v = u32(rom, a)
                if not (lo <= v < hi) or (v & 1) or v in self.code or v in self.entries \
                        or v in self.rejected_seeds:
                    continue
                if rom[v:v + 4] in (b'\xff\xff\xff\xff', b'\x00\x00\x00\x00'):
                    continue
                # calibration and the erased hole hold no function pointers; a
                # long there that looks like one is table data (0x0C7F00 is 36
                # copies of 0x00080008)
                if CAL_LO <= a < self.vbr:
                    continue
                ok, visited, _ = self.walk(v, commit=False, limit=4000)
                if not ok or len(visited) < 4:
                    continue
                why = self.data_signature(visited, v)
                if why:
                    self.rejected_seeds[v] = ('ptr', a, why)
                    continue
                # must not run over an address already known to be a literal the
                # reached code reads -- that would be data decoded as code
                if any(p in self.lit_addrs for p in visited):
                    continue
                # ...nor over its OWN literals: real code never loads a constant
                # out of its instruction stream, data decoded as code often does
                if own_literals(visited) & set(visited):
                    continue
                # ...nor over a table descriptor record. Those are validated
                # structurally from bytes (count / typecode / pointer contiguity)
                # and a handful decode cleanly as instructions (0x0AF344 did)
                if any(p in self.known_data for p in visited):
                    continue
                self.add_entry(v, 'ptr')
                self.ptr_sources[v] = a
                self.descend([v])
                self.refresh_literals()
                added += 1
                changed = True
        return added

    def seed_orphans(self, lo=CODE_LO, hi=CAL_LO):
        """Unreferenced functions: clean code sitting right after a terminator.

        Some real functions have NO static reference at all -- no literal, no
        bsr, no table slot (0x008170, the flag readers at 0x029878..0x029AE0).
        They are dead unless something computes their address. They still
        count as code, so they are found here and tagged `orphan` rather than
        left out of the denominator.

        A candidate must start exactly where reached code or a literal pool
        ends, decode to a terminator, and collide with no literal or
        descriptor. That is a heuristic, which is why the class is separate.
        """
        rom = self.rom
        added = 0
        changed = True
        while changed:
            changed = False
            for a in range(lo, hi, 2):
                if a in self.code or a in self.lit_addrs or a in self.known_data or a in self.rejected_seeds:
                    continue
                prev_code = (a - 2) in self.code and (a - 4) in self.code and \
                    flow_of(self.code[a - 4], a - 4)[0] in ('ret', 'jump', 'ijump')
                prev_pool = (a - 2) in self.lit_addrs
                if not (prev_code or prev_pool):
                    continue
                w = u16(rom, a)
                if w in (0xFFFF, 0x0000, 0x0009):
                    continue                      # padding, not an entry
                ok, visited, _ = self.walk(a, commit=False, limit=4000)
                if not ok or len(visited) < 2:
                    continue
                why = self.data_signature(visited, a)
                if why:
                    self.rejected_seeds[a] = ('orphan', None, why)
                    continue
                if any(p in self.lit_addrs or p in self.known_data for p in visited):
                    continue
                if own_literals(visited) & set(visited):
                    continue
                self.add_entry(a, 'orphan')
                self.descend([a])
                self.refresh_literals()
                added += 1
                changed = True
        return added

    def split_tail_branches(self):
        """A `bra` that leaves its own function's extent is a tail call.

        The compiler tail-calls with a plain `bra` when the callee is in range
        (034F24: bra 0x0355B8 -- the routine open-holes #9 is about). Nothing
        else names such a callee, so without this pass it is silently merged
        into whichever function sits below it. Iterated to a fixpoint because
        each new entry moves the boundaries.
        """
        import bisect
        jumps = []
        for pc, w in self.code.items():
            if (w >> 12) == 0xA:
                d = w & 0xFFF
                d = d - 0x1000 if d & 0x800 else d
                jumps.append((pc, pc + 4 + d * 2))
        added = 0
        changed = True
        while changed:
            changed = False
            ents = sorted(self.entries)
            for pc, tgt in jumps:
                if tgt in self.entries or tgt not in self.code:
                    continue
                i = bisect.bisect_right(ents, pc) - 1
                if i < 0:
                    continue
                lo = ents[i]
                hi = ents[i + 1] if i + 1 < len(ents) else ROM_SIZE
                if not (lo <= tgt < hi):
                    self.entries[tgt] = 'tailbra'
                    self.calls[pc].add(tgt)
                    added += 1
                    changed = True
        return added

    def refresh_literals(self):
        self.lit_addrs = own_literals(self.code)


def own_literals(code):
    """Addresses a set of instructions reads PC-relatively (word granularity)."""
    lits = set()
    for pc, w in code.items():
        if (w >> 12) == 0xD:
            t = lit_target(pc, w)
            lits.update((t, t + 2))
        elif (w >> 12) == 0x9:
            lits.add(pc + 4 + (w & 0xFF) * 2)
    return lits


# --------------------------------------------------------------------------
# claims and prior work -- carried, never used as evidence
# --------------------------------------------------------------------------

def traced_addresses(rom):
    """Instruction addresses quoted in analysis files whose bytes match the ROM."""
    out = collections.defaultdict(set)
    for path in sorted(glob.glob(os.path.join(ANALYSIS, '*.txt'))):
        name = os.path.basename(path)
        with open(path, errors='replace') as fh:
            for line in fh:
                m = LINE.match(line)
                if not m:
                    continue
                a = int(m.group(1), 16)
                if a + 2 > len(rom) or a & 1:
                    continue
                if u16(rom, a) == int(m.group(2), 16):
                    out[a].add(name)
    return out


def java_labels():
    """Parsed-address -> (name, evidence tag). Keyed on the VALUE, not the text."""
    out = {}
    if not os.path.exists(JAVA):
        return out
    pat = re.compile(r'labelComment\(\s*(0x[0-9A-Fa-f]+)L?\s*,\s*"([^"]+)"\s*,\s*"((?:[^"\\]|\\.)*)"', re.S)
    with open(JAVA, errors='replace') as fh:
        text = fh.read()
    for m in pat.finditer(text):
        a = int(m.group(1), 16)
        tag = re.match(r'\[(\w[\w-]*)\]', m.group(3))
        out.setdefault(a, (m.group(2), tag.group(1) if tag else None))
    return out


def descriptor_addresses(rom):
    try:
        import coverage_map as cm
        return {d['addr'] for d in cm.scan_descriptors(rom)}
    except Exception:
        return set()


# --------------------------------------------------------------------------
# assemble
# --------------------------------------------------------------------------

def census(rom, descs=None):
    """Run the whole descent and return the Census object (calls, code, rs ...).

    Other tools import this to get call SITES, which the JSON does not carry.
    """
    if descs is None:
        descs = descriptor_addresses(rom)
    c = Census(rom)
    c.lit_addrs = set()
    c.known_data = {d + o for d in descs for o in range(0, 20, 2)}
    c.descend(c.seed_vectors())
    c.refresh_literals()
    c.stats = dict(proven_entries=len(c.entries), proven_code=len(c.code))
    c.stats['n_ptr'] = c.seed_pointers()
    c.refresh_literals()
    c.stats['referenced_code'] = len(c.code)
    c.stats['n_orphan'] = c.seed_orphans()
    c.stats['n_tailbra'] = c.split_tail_branches()
    return c


def build(rom_path):
    with open(rom_path, 'rb') as fh:
        rom = fh.read()
    descs = descriptor_addresses(rom)
    c = census(rom, descs)
    proven_entries = c.stats['proven_entries']
    proven_code = c.stats['proven_code']
    n_ptr = c.stats['n_ptr']
    referenced_code = c.stats['referenced_code']
    n_orphan = c.stats['n_orphan']
    n_tailbra = c.stats['n_tailbra']

    traced = traced_addresses(rom)
    labels = java_labels()

    entries = sorted(c.entries)
    callers = collections.defaultdict(set)
    code_sorted = sorted(c.code)

    import bisect

    def owner(pc):
        i = bisect.bisect_right(entries, pc) - 1
        return entries[i] if i >= 0 else None

    for pc, tgts in c.calls.items():
        o = owner(pc)
        for t in tgts:
            callers[t].add(o)

    funcs = []
    for i, e in enumerate(entries):
        hi = entries[i + 1] if i + 1 < len(entries) else ROM_SIZE
        lo_i = bisect.bisect_left(code_sorted, e)
        hi_i = bisect.bisect_left(code_sorted, hi)
        body = code_sorted[lo_i:hi_i]
        if not body:
            continue
        ram, periph, descr, cal, gbr = set(), set(), set(), set(), set()
        callees, unresolved, fpu = set(), 0, 0
        for pc in body:
            w = c.code[pc]
            op = w >> 12
            if op == 0xF:
                fpu += 1
            if op == 0xD:
                t = lit_target(pc, w)
                if t + 4 <= len(rom):
                    v = u32(rom, t)
                    if RAM_LO <= v < RAM_HI:
                        ram.add(v)
                    elif v >= PERIPH_LO:
                        periph.add(v)
                    elif v in descs:
                        descr.add(v)
                    elif 0xC0000 <= v < 0x100000:
                        cal.add(v)
            if op == 0x4 and (w & 0xFF) == 0x1E:          # ldc Rn,gbr
                st = c.rs.get(e)
                if st is None:
                    st = c.rs[e] = reg_states(rom, e)
                s_ = st.get((pc, None))
                v = single(s_[(w >> 8) & 0xF]) if s_ is not None else resolve_reg(rom, pc, (w >> 8) & 0xF, e)
                if v is not None:
                    gbr.add(v)
            if pc in c.calls:
                callees.update(c.calls[pc])
            if pc in c.unresolved:
                unresolved += 1
        n = len(body)
        tr = [pc for pc in body if pc in traced]
        files = collections.Counter(f for pc in tr for f in traced[pc])
        name, tag = labels.get(e, (None, None))
        funcs.append(dict(
            entry=f'0x{e:06X}', end=f'0x{body[-1] + 2:06X}', evidence=c.entries[e],
            insns=n, bytes=n * 2, traced=len(tr),
            traced_pct=round(100.0 * len(tr) / n, 1),
            traced_in=[f for f, _ in files.most_common(4)],
            fpu=fpu,
            callers=sorted(f'0x{x:06X}' for x in callers.get(e, ()) if x is not None),
            callees=sorted(f'0x{x:06X}' for x in callees),
            unresolved_calls=unresolved,
            gbr=sorted(f'0x{x:08X}' for x in gbr),
            ram=sorted(f'0x{x:08X}' for x in ram),
            periph=sorted(f'0x{x:08X}' for x in periph),
            descriptors=sorted(f'0x{x:06X}' for x in descr),
            cal=sorted(f'0x{x:06X}' for x in cal),
            label_claim=name, label_tag=tag,
        ))

    total = sum(f['insns'] for f in funcs)
    tr_total = sum(f['traced'] for f in funcs)
    summary = dict(
        rom=os.path.basename(rom_path),
        functions=len(funcs),
        entries_by_evidence=dict(collections.Counter(f['evidence'] for f in funcs)),
        vector_rooted_entries=proven_entries,
        vector_rooted_insns=proven_code,
        ptr_seeds_accepted=n_ptr,
        tail_branch_entries=n_tailbra,
        orphan_entries=n_orphan,
        orphan_insns=len(c.code) - referenced_code,
        insns=total, code_bytes=total * 2,
        traced_insns=tr_total,
        traced_pct=round(100.0 * tr_total / total, 2) if total else 0.0,
        functions_untouched=sum(1 for f in funcs if f['traced'] == 0),
        functions_partial=sum(1 for f in funcs if 0 < f['traced_pct'] < 90),
        functions_done=sum(1 for f in funcs if f['traced_pct'] >= 90),
        fpu_insns=sum(f['fpu'] for f in funcs),
        dispatch_tables={f'0x{s_:06X}': [f'0x{b:06X}', n] for s_, (b, n) in sorted(c.tables.items())},
        unresolved_indirect_sites=len(c.unresolved),
        indirect_resolution=dict(c.resolution),
        address_order_would_have_been_wrong={f'0x{p:06X}': [f'0x{a:08X}', f'0x{b:08X}'] for p, (a, b) in sorted(c.disagree.items())},
        rejected_seeds={f'0x{k:06X}': [cls, (f'0x{src:06X}' if src is not None else None), why]
                        for k, (cls, src, why) in sorted(c.rejected_seeds.items())},
        bad_decode_sites=len(c.bad),
        # analysis-file lines whose address is NOT a reached instruction. Almost
        # all are literal-pool words a *_raw.txt file printed in instruction
        # format, so they inflate any "instructions traced" count taken from
        # the verifier's line total.
        quoted_lines_not_code=sum(1 for a in traced if a not in c.code),
        quoted_lines_that_are_pool_words=sum(1 for a in traced if a not in c.code and a in c.lit_addrs),
    )
    return summary, funcs


def rank(funcs, top):
    """Untraced work, biggest unknowns first. Purely mechanical score."""
    rows = []
    for f in funcs:
        left = f['insns'] - f['traced']
        if left < 8:
            continue
        score = left * (1 + 0.5 * len(f['descriptors']) + 0.1 * len(f['callers']))
        rows.append((score, f))
    rows.sort(key=lambda r: -r[0])
    return [f for _, f in rows[:top]]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--rom', default=DEFAULT_ROM)
    ap.add_argument('--json')
    ap.add_argument('--rank', type=int, default=0)
    args = ap.parse_args()

    summary, funcs = build(args.rom)
    for k, v in summary.items():
        print(f'{k:42s} {v}')
    if args.rank:
        print()
        print(f'{"entry":9s} {"ev":7s} {"insns":>6s} {"traced":>6s} {"desc":>4s} {"calr":>4s}  gbr / label claim')
        for f in rank(funcs, args.rank):
            print(f'{f["entry"]:9s} {f["evidence"]:7s} {f["insns"]:6d} {f["traced_pct"]:5.1f}% '
                  f'{len(f["descriptors"]):4d} {len(f["callers"]):4d}  '
                  f'{",".join(f["gbr"]) or "-"}  {f["label_claim"] or ""}')
    if args.json:
        # One function per line: a regeneration diffs as the functions that changed,
        # not as 167,000 reflowed lines. Readers use json.load and do not care.
        with open(args.json, 'w', newline='\n') as fh:
            fh.write('{"summary": ' + json.dumps(summary, indent=1) + ',\n"functions": [\n')
            fh.write(',\n'.join(json.dumps(f, separators=(', ', ': ')) for f in funcs))
            fh.write('\n]}\n')
        print(f'\nwrote {args.json}')


if __name__ == '__main__':
    main()
