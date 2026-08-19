# Verification status registry

**GENERATED FILE — do not hand-edit.** Regenerate with:

```
python scripts/coverage_map.py
```

Machine-readable companion: [`verification-status.json`](verification-status.json) (schema v1). Generated 2026-08-19 10:28.

Every flag below is recomputed from scratch on each run: the definition side from `scripts/defs.py` over both definition XMLs, the disassembly side re-derived from ROM bytes (literal-pool dereference back-trace, table descriptors decoded out of ROM, and a RAM→lookup-axis feed trace). No conclusion is read out of a derived file and trusted. Agreement across derived files is not evidence.

## 1. Flag taxonomy

Exactly one flag per entity. The rules are evaluated in the order shown; the first that fires wins, so the ladder is total and unambiguous.

### 1. `CONFLICT`

**Means.** The definition side and the ROM-code side make incompatible claims about the SAME bytes. The record must name which side is suspect and why. A CONFLICT is never silently resolved by this script -- it is surfaced for a human to settle from bytes.

**Evidence required to claim it.** Both sides must have independently produced a claim about the same address, and the claims must be mutually exclusive. Accepted contradictions: (a) declared storagetype width vs the width ROM code actually dereferences the address with (fmov.s vs mov.b/w/l, from the literal-pool back-trace); (b) declared element count or bytes/cell vs the count/width in the ROM's own table descriptor; (c) for RAM, the physical quantity named in ram_reference.txt vs the physical quantity of the definition-named axis that this RAM variable is traced feeding.

**Invalidated by.** Showing the two claims are not about the same bytes (e.g. an alias table at the same address with a different but COMPATIBLE view -- two unit views of one float are not a conflict), or showing the code-side observation was a false positive (pool word matched by coincidence, register reloaded before the dereference, 0xFF hole bytes read as data). Downgrades to VERIFIED-BOTH or VERIFIED-BYTES once the losing side is corrected in its source file.

### 2. `BOUNDS-SUSPECT`

**Means.** Identity and geometry are fine, but the definition's own declared min/max is contradicted by the FACTORY ROM's own data. This is an editor-facing hazard, not a read error: ECUFlash/RomRaider clamp on write, so the bound can silently refuse a legitimate value. Kept separate from CONFLICT because the bytes are read correctly.

**Evidence required to claim it.** The STOCK ROM decodes through the declared scaling to a display value outside [min,max] by more than 1e-4 of the declared span (that tolerance exists because several bounds are rounded copies of the exact breakpoint). Stock is the test, not the tuned rev: a 20.19b-only excursion is Dean's edit, is recorded as a note, and does NOT set this flag.

**Invalidated by.** Correcting min/max in the XML so the factory data fits, or proving the scaling itself (not the bound) is wrong -- in which case the entity becomes CONFLICT instead.

### 3. `VERIFIED-BOTH`

**Means.** Definition and disassembly independently describe these bytes and AGREE, and the bytes decode sanely in both the stock and the current tuned ROM. Highest confidence available without a dyno/log experiment.

**Evidence required to claim it.** ALL of: (1) the definition resolves -- address, scaling, storagetype, element count -- and the extent lies inside the 1 MiB ROM; (2) every cell decodes in BOTH rom/ae5l600l.bin and rom/AE5L600L 20g rev 20.19b.bin with no NaN/Inf and, for axes, monotonic breakpoints; (3) stock data lies inside the declared min/max; (4) at least one INDEPENDENT code-side observation of the same address -- a literal-pool dereference whose access width matches the declared storagetype, or a ROM table descriptor whose bytes/cell and element count match the declared geometry -- and it does not contradict (1).

**Invalidated by.** Any edit to the address, scaling, storagetype or elements= of the table or its axes; a new ROM rev whose bytes fail the decode/range test; discovery of a second code path that dereferences the address with a different width. Flags are regenerated from scratch on every run, so an edit to either side invalidates automatically.

### 4. `VERIFIED-BYTES`

**Means.** The definition is self-consistent and survives contact with real ROM bytes in both revs, but NOTHING on the code side independently corroborates it. The bytes are readable and plausible; the IDENTITY rests on the definition alone.

**Evidence required to claim it.** Conditions (1)-(3) of VERIFIED-BOTH, and NO code-side observation either way. Typically the address is reached through a descriptor pointer or a computed offset rather than a raw pool literal, so the back-trace has nothing to find.

**Invalidated by.** Same as VERIFIED-BOTH. Additionally: this flag is an explicit statement that a wrong-identity error of the 0xC0BCC class would NOT be caught here. Do not cite a VERIFIED-BYTES entity as proof of what a table MEANS -- only of what it CONTAINS.

### 5. `DEFS-ONLY`

**Means.** A definition exists but cannot be checked against anything, because the definition itself is incomplete -- no address, or a scaling that is referenced but defined in no XML, so there is no storagetype and therefore no byte width. These are unopenable in ECUFlash/RomRaider too.

**Evidence required to claim it.** defs.py resolves the <table>, but Table.readable is False: address missing, scaling name not found in either XML, storagetype unsupported/absent, or element count unresolved.

**Invalidated by.** Supplying the missing <scaling> element or address= attribute. The entity then re-enters the ladder at whatever its bytes justify -- it does NOT jump straight to verified.

### 6. `DISASM-ONLY`

**Means.** The code side describes these bytes -- a ROM table descriptor points at them, or ram_reference.txt/cal_crossref.txt names them -- but no definition binds them. Nothing here has been checked against the definition XMLs, which are the project's primary ground truth for identity and units.

**Evidence required to claim it.** For ROM: a descriptor decoded from ROM bytes whose data or axis pointer lands in this extent, and no defs.py table/axis covering any byte of it. For RAM: an entry in ram_reference.txt (RAM is outside the ROM image, so no definition can ever cover it) with no definition-axis corroboration from the feed trace.

**Invalidated by.** Adding a <table> to the project XML that covers the extent (moves it into the definition ladder), or -- for RAM -- a feed trace that ties the address to a definition-named axis, which promotes it to VERIFIED-BOTH or exposes it as CONFLICT.

### 7. `UNMAPPED`

**Means.** Neither side says anything. For ROM this is data-classified bytes claimed by no definition and no descriptor. For RAM it is an address the ROM's own literal pools reference but ram_reference.txt does not name. This is the honest measure of what is not known.

**Evidence required to claim it.** ROM: byte falls in a block the region map classifies as float_data / uint8_data / mixed_data (not code, not a 0xFF hole) and is covered by no definition extent and no descriptor extent. RAM: address in 0xFFFF0000-0xFFFFBFFF appears as a 4-aligned literal-pool word and is absent from ram_reference.txt.

**Invalidated by.** Any definition, descriptor or named RAM entry that claims the address. UNMAPPED is a residue, computed by subtraction -- it can only shrink by someone doing work, never by re-running this script.

## 2. Coverage

4720 entities: every addressed definition table and axis, every calibration block a ROM descriptor points at, and every RAM address either named in `ram_reference.txt` or referenced by a ROM literal pool.

| Flag | Entities | Share |
|---|---:|---:|
| `CONFLICT` | 0 | 0.0% |
| `BOUNDS-SUSPECT` | 52 | 1.1% |
| `VERIFIED-BOTH` | 363 | 7.7% |
| `VERIFIED-BYTES` | 266 | 5.6% |
| `DEFS-ONLY` | 6 | 0.1% |
| `DISASM-ONLY` | 955 | 20.2% |
| `UNMAPPED` | 3078 | 65.2% |

### By entity kind

| Kind | `CONFLICT` | `BOUNDS-SUSPECT` | `VERIFIED-BOTH` | `VERIFIED-BYTES` | `DEFS-ONLY` | `DISASM-ONLY` | `UNMAPPED` |
|---|---|---|---|---|---|---|---|
| axis | 0 | 26 | 145 | 40 | 2 | 0 | 0 |
| ram | 0 | 0 | 6 | 0 | 0 | 230 | 3078 |
| rom-block | 0 | 0 | 0 | 0 | 0 | 725 | 0 |
| table | 0 | 26 | 212 | 226 | 4 | 0 | 0 |

`table` / `axis` are definition-backed. `rom-block` is a calibration block a ROM descriptor points at that no `<table>` covers. `ram` is a RAM variable — RAM is outside the ROM image, so no definition can ever cover it and the definition side contributes only indirectly, through the names of the axes a RAM variable is traced feeding.

### Unmapped ROM bytes

Bytes the region map classifies as data (not code, not a 0xFF hole) and that no definition extent and no descriptor extent claims:

- data bytes considered: **321,468**
- unmapped: **255,192 (79.4%)**
- of which 44,028 bytes lie inside the descriptor band `0x0A0000-0x0BE000` — those are descriptor STRUCTS and lookup-helper constants, not table cells, so they are unmapped by nature rather than by neglect. Excluding them, **211,164 of 277,440 calibration data bytes (76.1%) are claimed by nothing**.

Largest unmapped data blocks:

| Block | Region class | Unmapped bytes |
|---|---|---:|
| `0xA9D00`–`0xAF900` | float_data | 23,548 |
| `0xC4000`–`0xC7E00` | float_data | 9,779 |
| `0x47500`–`0x49600` | float_data | 8,448 |
| `0x01000`–`0x02C00` | float_data | 7,132 |
| `0x9A700`–`0x9C200` | float_data | 6,760 |
| `0x49A00`–`0x4B100` | float_data | 5,888 |
| `0xC0B00`–`0xC3F00` | float_data | 4,927 |
| `0xD1D00`–`0xD4500` | float_data | 4,839 |
| `0xD5800`–`0xD7400` | float_data | 4,805 |
| `0x03900`–`0x04A00` | float_data | 4,352 |
| `0xD8300`–`0xDAB00` | float_data | 4,309 |
| `0xC8400`–`0xCC300` | float_data | 3,886 |
| `0x00000`–`0x00F00` | float_data | 3,840 |
| `0xCD700`–`0xCF100` | float_data | 3,826 |
| `0x0DF00`–`0x0EC00` | float_data | 3,328 |

## 3. Per definition category

| Category | `CONFLICT` | `BOUNDS-SUSPECT` | `VERIFIED-BOTH` | `VERIFIED-BYTES` | `DEFS-ONLY` | `DISASM-ONLY` | `UNMAPPED` | total |
|---|---|---|---|---|---|---|---|---|
| Diagnostic Trouble Codes | 0 | 0 | 0 | 152 | 0 | 0 | 0 | 152 |
| Ignition Timing - Compensation | 0 | 2 | 39 | 8 | 0 | 0 | 0 | 49 |
| Map Switching - Cruise/Non-Cruise | 0 | 0 | 41 | 0 | 0 | 0 | 0 | 41 |
| Fueling - Tip-in Enrichment | 0 | 0 | 13 | 16 | 0 | 0 | 0 | 29 |
| Ignition Timing - Advance | 0 | 0 | 19 | 10 | 0 | 0 | 0 | 29 |
| Post Start Enrichment | 0 | 13 | 0 | 13 | 0 | 0 | 0 | 26 |
| Fueling - Primary Open Loop | 0 | 0 | 23 | 2 | 0 | 0 | 0 | 25 |
| Fueling - Cranking | 0 | 0 | 12 | 12 | 0 | 0 | 0 | 24 |
| Ignition Timing - Knock Control | 0 | 6 | 15 | 2 | 0 | 0 | 0 | 23 |
| Drive-by-Wire Throttle (DBW) | 0 | 0 | 20 | 0 | 0 | 0 | 0 | 20 |
| Fueling - CL/OL Transition | 0 | 6 | 12 | 1 | 1 | 0 | 0 | 20 |
| Boost Control - Turbo Dynamics | 0 | 0 | 15 | 3 | 0 | 0 | 0 | 18 |
| Fueling - Closed Loop | 0 | 0 | 11 | 7 | 0 | 0 | 0 | 18 |
| Fueling - Injectors | 0 | 0 | 15 | 1 | 0 | 0 | 0 | 16 |
| Boost Control - Wastegate | 0 | 0 | 11 | 3 | 1 | 0 | 0 | 15 |
| Mass Airflow / Engine Load | 0 | 0 | 14 | 1 | 0 | 0 | 0 | 15 |
| Map Switching - Timing Blend | 0 | 0 | 14 | 0 | 0 | 0 | 0 | 14 |
| tinywrex patches | 0 | 2 | 8 | 4 | 0 | 0 | 0 | 14 |
| Alpha Drive-by-Wire Throttle (DBW) | 0 | 0 | 12 | 0 | 0 | 0 | 0 | 12 |
| Boost Control - Target | 0 | 0 | 10 | 2 | 0 | 0 | 0 | 12 |
| Alpha Transient Fueling (Tau) | 0 | 6 | 0 | 5 | 0 | 0 | 0 | 11 |
| Alpha Idle Control | 0 | 2 | 6 | 0 | 0 | 0 | 0 | 8 |
| Fueling - Warm-Up Enrichment | 0 | 0 | 0 | 8 | 0 | 0 | 0 | 8 |
| Idle Control | 0 | 0 | 0 | 8 | 0 | 0 | 0 | 8 |
| Fueling - AF Correction / Learning | 0 | 1 | 2 | 0 | 4 | 0 | 0 | 7 |
| Miscellaneous - Limits | 0 | 1 | 3 | 3 | 0 | 0 | 0 | 7 |
| Alpha Per Gear Requested Torque | 0 | 2 | 4 | 0 | 0 | 0 | 0 | 6 |
| Alpha Variable Valve Timing (AVCS) | 0 | 2 | 4 | 0 | 0 | 0 | 0 | 6 |
| Boost Control - Limits | 0 | 0 | 6 | 0 | 0 | 0 | 0 | 6 |
| Idle control | 0 | 6 | 0 | 0 | 0 | 0 | 0 | 6 |
| Miscellaneous - Sensor Scalings | 0 | 0 | 6 | 0 | 0 | 0 | 0 | 6 |
| Miscellaneous - Thresholds | 0 | 0 | 6 | 0 | 0 | 0 | 0 | 6 |
| Variable Valve Timing (AVCS) | 0 | 0 | 6 | 0 | 0 | 0 | 0 | 6 |
| Alpha OverRun Fueling | 0 | 1 | 2 | 2 | 0 | 0 | 0 | 5 |
| Alpha Low PW Injector Comp | 0 | 1 | 3 | 0 | 0 | 0 | 0 | 4 |
| Alpha Ignition Dwell | 0 | 0 | 2 | 1 | 0 | 0 | 0 | 3 |
| Manifold Pressure Sensor | 0 | 1 | 2 | 0 | 0 | 0 | 0 | 3 |
| Alpha Engine Load Limit B Multiplier | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 1 |
| Alpha Fuel Pump | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 1 |
| Alpha Fueling - Injectors | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 1 |

## 4. `CONFLICT` — settle these from bytes

Two independent sides make incompatible claims about the same address. Nothing downstream of these should be trusted until a human settles them from ROM bytes — and settles them in the right direction. **0 entities.**

_None._

## 5. `BOUNDS-SUSPECT` — editor will clamp

The bytes are read correctly; the definition's declared min/max is contradicted by the factory ROM's own data. ECUFlash/RomRaider clamp on write, so these bounds can silently refuse a legitimate value. **52 entities.**

Collapsed by address: a shared axis (the ECT axis at `0xCC624` serves 34 tables) would otherwise repeat once per consumer.

- **`0xCC624`** — Table_Post_Start_Enrich_High_Speed_Decay_Initial_Start_1A / Coolant Temperature  (+16 more tables at this address)  
  _Post Start Enrichment_
  - 14 of 16 factory-ROM cells fall outside the declared min/max 188.6..221.0
  - **suspect side:** definition XML (declared min/max)
- **`0xCC664`** — Table_Post_Start_Enrich_Low_Speed_Decay_Delay_2 / Coolant Temperature  
  _Post Start Enrichment_
  - 14 of 16 factory-ROM cells fall outside the declared min/max 188.6..221.0
  - **suspect side:** definition XML (declared min/max)
- **`0xCCDCC`** — Tau Input A Rising Load Activation / Engine Load  
  _Alpha Transient Fueling (Tau)_
  - 1 of 3 factory-ROM cells fall outside the declared min/max 0.0..5.0
  - **suspect side:** definition XML (declared min/max)
- **`0xCFA14`** — Intake Duty Correction A / Engine Speed  
  _Alpha Variable Valve Timing (AVCS)_
  - 3 of 9 factory-ROM cells fall outside the declared min/max 0.0..2000.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D2 ROM table descriptor @0xAD620 — 2D, 90 cells x 1 byte (axis pointer); spacing to the next known table boundary implies nothing bytes/cell
- **`0xD11F8`** — Exhaust Duty Correction A / Engine Speed  
  _Alpha Variable Valve Timing (AVCS)_
  - 3 of 9 factory-ROM cells fall outside the declared min/max 0.0..2000.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D2 ROM table descriptor @0xAD848 — 2D, 90 cells x 2 bytes (axis pointer); spacing to the next known table boundary implies 2 bytes/cell
- **`0xD7E38`** — Idle Airflow Min Target Decel Adder (RPM x ECT) / Coolant Temp  
  _Alpha Idle Control_
  - 2 of 2 factory-ROM cells fall outside the declared min/max 188.6..221.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D2 ROM table descriptor @0xAF090 — 2D, 32 cells x 2 bytes (axis pointer); spacing to the next known table boundary implies 2 bytes/cell
  - evidence: D5 cal_crossref.txt:362 — Ghidra label cal_Coolant_Temp
- **`0xD7E80`** — Idle Speed Stability A / Idle Speed Error  
  _Idle control_
  - 7 of 17 factory-ROM cells fall outside the declared min/max 0.0..10000.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D2 ROM table descriptor @0xAF0AC — 2D, 153 cells x 2 bytes (axis pointer); spacing to the next known table boundary implies nothing bytes/cell
  - evidence: D5 cal_crossref.txt:364 — Ghidra label cal_Idle_Speed_Error
- **`0xD7EC4`** — Idle Speed Stability A / Engine Speed Delta  
  _Idle control_
  - 5 of 9 factory-ROM cells fall outside the declared min/max 0.0..10000.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D2 ROM table descriptor @0xAF0AC — 2D, 153 cells x 2 bytes (axis pointer); spacing to the next known table boundary implies nothing bytes/cell
  - evidence: D5 cal_crossref.txt:365 — Ghidra label cal_Engine_Speed_Delta
- **`0xD801C`** — Idle Speed Stability B / Idle Speed Error  
  _Idle control_
  - 7 of 17 factory-ROM cells fall outside the declared min/max 0.0..10000.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D2 ROM table descriptor @0xAF0C8 — 2D, 153 cells x 2 bytes (axis pointer); spacing to the next known table boundary implies nothing bytes/cell
  - evidence: D5 cal_crossref.txt:367 — Ghidra label cal_Idle_Speed_Error
- **`0xD8060`** — Idle Speed Stability B / Engine Speed Delta  
  _Idle control_
  - 5 of 9 factory-ROM cells fall outside the declared min/max 0.0..10000.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D2 ROM table descriptor @0xAF0C8 — 2D, 153 cells x 2 bytes (axis pointer); spacing to the next known table boundary implies nothing bytes/cell
  - evidence: D5 cal_crossref.txt:368 — Ghidra label cal_Engine_Speed_Delta
- **`0x35FFC`** — AF 3 Correction Limits  
  _Fueling - AF Correction / Learning_
  - 2 of 2 factory-ROM cells fall outside the declared min/max -30.0..30.0
  - **suspect side:** definition XML (declared min/max)
- **`0xC0BC8`** — Boost disable during fuel cut-Boost(psi) threshold  
  _tinywrex patches_
  - 1 of 1 factory-ROM cells fall outside the declared min/max -8.01..9.94
  - **suspect side:** definition XML (declared min/max)
  - evidence: D1 literal-pool dereference (re-derived from ROM bytes) — float x1
  - evidence: D5 cal_crossref.txt:471 — Ghidra label cal_Boost_disable_during_fuel_cut_Boost_bar_threshold
- **`0xC0BD0`** — Boost disable during fuel cut-RPM threshold  
  _tinywrex patches_
  - 1 of 1 factory-ROM cells fall outside the declared min/max 0.0..12000.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D1 literal-pool dereference (re-derived from ROM bytes) — float x1
  - evidence: D5 cal_crossref.txt:473 — Ghidra label cal_Boost_disable_during_fuel_cut_RPM_threshold
- **`0xCBC5A`** — CL Delay Engine Load Counter Threshold  
  _Fueling - CL/OL Transition_
  - 1 of 1 factory-ROM cells fall outside the declared min/max 1.0..100.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D1 literal-pool dereference (re-derived from ROM bytes) — int16 x1
- **`0xCBC5C`** — CL to OL Delay/Switch SI-DRIVE Intelligent  
  _Fueling - CL/OL Transition_
  - 1 of 1 factory-ROM cells fall outside the declared min/max 1.0..100.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D1 literal-pool dereference (re-derived from ROM bytes) — int16 x1
- **`0xCBC62`** — CL to OL Delay_  
  _Fueling - CL/OL Transition_
  - 1 of 1 factory-ROM cells fall outside the declared min/max 1.0..100.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D1 literal-pool dereference (re-derived from ROM bytes) — int16 x1
- **`0xCC180`** — CL Delay Maximum Engine Speed (Per Gear)  
  _Fueling - CL/OL Transition_
  - 10 of 10 factory-ROM cells fall outside the declared min/max 0.0..2000.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D1 literal-pool dereference (re-derived from ROM bytes) — float x1
- **`0xCC1A8`** — CL Delay Maximum Engine Speed (Neutral)  
  _Fueling - CL/OL Transition_
  - 2 of 2 factory-ROM cells fall outside the declared min/max 0.0..2000.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D1 literal-pool dereference (re-derived from ROM bytes) — float x1
- **`0xCC1D8`** — CL Delay Maximum (Throttle)  
  _Fueling - CL/OL Transition_
  - 1 of 1 factory-ROM cells fall outside the declared min/max 4.6..108.3
  - **suspect side:** definition XML (declared min/max)
  - evidence: D1 literal-pool dereference (re-derived from ROM bytes) — float x1
- **`0xCC498`** — Overrun Enrich RPM Delta Activation  
  _Alpha OverRun Fueling_
  - 1 of 1 factory-ROM cells fall outside the declared min/max 0.0..420.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D1 literal-pool dereference (re-derived from ROM bytes) — float x1
- **`0xCC500`** — Rev Limit (Fuel Cut)  
  _Miscellaneous - Limits_
  - 2 of 2 factory-ROM cells fall outside the declared min/max 0.0..2000.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D1 literal-pool dereference (re-derived from ROM bytes) — float x1
- **`0xD29DE`** — Feedback Correction Negative Advance Delay  
  _Ignition Timing - Knock Control_
  - 1 of 1 factory-ROM cells fall outside the declared min/max 1.0..100.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D1 literal-pool dereference (re-derived from ROM bytes) — int16 x1
  - evidence: D5 cal_crossref.txt:290 — Ghidra label cal_Feedback_Correction_Negative_Advance_Delay
- **`0xD29EE`** — Fine Correction Advance Delay  
  _Ignition Timing - Knock Control_
  - 1 of 1 factory-ROM cells fall outside the declared min/max 1.0..100.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D1 literal-pool dereference (re-derived from ROM bytes) — int16 x1
  - evidence: D5 cal_crossref.txt:291 — Ghidra label cal_Fine_Correction_Advance_Delay
- **`0xD2D38`** — Timing Compensation Per Gear Activation (RPM)  
  _Ignition Timing - Compensation_
  - 2 of 2 factory-ROM cells fall outside the declared min/max 0.0..2000.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D1 literal-pool dereference (re-derived from ROM bytes) — float x1
- **`0xD2D98`** — Timing Comp Maximum RPM (Per Cylinder)  
  _Ignition Timing - Compensation_
  - 1 of 1 factory-ROM cells fall outside the declared min/max 0.0..2000.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D1 literal-pool dereference (re-derived from ROM bytes) — float x1
- **`0xD2DAC`** — Feedback Correction Range (RPM)  
  _Ignition Timing - Knock Control_
  - 2 of 4 factory-ROM cells fall outside the declared min/max 0.0..2000.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D1 literal-pool dereference (re-derived from ROM bytes) — float x1
  - evidence: D5 cal_crossref.txt:294 — Ghidra label cal_Feedback_Correction_Range_RPM
- **`0xD2EBC`** — Rough Correction Range (RPM)  
  _Ignition Timing - Knock Control_
  - 2 of 4 factory-ROM cells fall outside the declared min/max 0.0..2000.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D1 literal-pool dereference (re-derived from ROM bytes) — float x1
  - evidence: D5 cal_crossref.txt:296 — Ghidra label cal_Rough_Correction_Range_RPM
- **`0xD2F0C`** — Fine Correction Rows (RPM)  
  _Ignition Timing - Knock Control_
  - 6 of 6 factory-ROM cells fall outside the declared min/max 0.0..2000.0
  - **suspect side:** definition XML (declared min/max)
- **`0xD2F6C`** — Fine Correction Range (RPM)  
  _Ignition Timing - Knock Control_
  - 2 of 4 factory-ROM cells fall outside the declared min/max 0.0..2000.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D1 literal-pool dereference (re-derived from ROM bytes) — float x2
  - evidence: D5 cal_crossref.txt:298 — Ghidra label cal_Fine_Correction_Range_RPM
- **`0xD39A8`** — Low Pulse Width Fuel Injector Compensation  
  _Alpha Low PW Injector Comp_
  - descriptor @0xAE000 typecode implies 4 byte(s)/cell, but every routine that consumes it (0xBE874) hardcodes the cell width and never reads the typecode -- the field is dead, so it is NOT evidence against the declared uint8
  - 8 of 8 factory-ROM cells fall outside the declared min/max -10.16..14.84
  - **suspect side:** definition XML (declared min/max)
  - evidence: D2 ROM table descriptor @0xAE000 — 1D, 8 cells x 4 bytes (data pointer); spacing to the next known table boundary implies 1 bytes/cell
- **`0xD64A4`** — Idle Airflow Min Target Decel Ramping Adder Decreasing  
  _Alpha Idle Control_
  - 1 of 1 factory-ROM cells fall outside the declared min/max 0.0..255.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D1 literal-pool dereference (re-derived from ROM bytes) — float x1
  - evidence: D5 cal_crossref.txt:354 — Ghidra label cal_Idle_Airflow_Min_Target_Decel_Ramping_Adder_Decreasing
- **`0xD7EE8`** — Idle Speed Stability A  
  _Idle control_
  - 45 of 153 factory-ROM cells fall outside the declared min/max 0.0..255.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D2 ROM table descriptor @0xAF0AC — 2D, 153 cells x 2 bytes (data pointer); spacing to the next known table boundary implies nothing bytes/cell
  - evidence: D5 cal_crossref.txt:366 — Ghidra label cal_Idle_Speed_Stability_A
- **`0xD8084`** — Idle Speed Stability B  
  _Idle control_
  - 45 of 153 factory-ROM cells fall outside the declared min/max 0.0..255.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D2 ROM table descriptor @0xAF0C8 — 2D, 153 cells x 2 bytes (data pointer); spacing to the next known table boundary implies nothing bytes/cell
  - evidence: D5 cal_crossref.txt:369 — Ghidra label cal_Idle_Speed_Stability_B
- **`0xD8AD8`** — Manifold Pressure Sensor Scaling_  
  _Manifold Pressure Sensor_
  - 1 of 2 factory-ROM cells fall outside the declared min/max -8.01..9.94
  - **suspect side:** definition XML (declared min/max)
  - evidence: D1 literal-pool dereference (re-derived from ROM bytes) — float x1
  - evidence: D5 cal_crossref.txt:372 — Ghidra label cal_Manifold_Pressure_Sensor_Scaling
- **`0xF9788`** — Requested Torque Limit A (Per Gear/Engine Speed)  
  _Alpha Per Gear Requested Torque_
  - 96 of 96 factory-ROM cells fall outside the declared min/max 0.0..455.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D2 ROM table descriptor @0xAF29C — 2D, 96 cells x 2 bytes (data pointer); spacing to the next known table boundary implies 2 bytes/cell
  - evidence: D5 cal_crossref.txt:403 — Ghidra label cal_Requested_Torque_Limit_A_Per_Gear_Engine_Speed
- **`0xF98A0`** — Requested Torque Limit B (Per Gear/Engine Speed)  
  _Alpha Per Gear Requested Torque_
  - 96 of 96 factory-ROM cells fall outside the declared min/max 0.0..455.0
  - **suspect side:** definition XML (declared min/max)
  - evidence: D2 ROM table descriptor @0xAF2B8 — 2D, 96 cells x 2 bytes (data pointer); spacing to the next known table boundary implies 2 bytes/cell
  - evidence: D5 cal_crossref.txt:406 — Ghidra label cal_Requested_Torque_Limit_B_Per_Gear_Engine_Speed

## 6. `DEFS-ONLY` — definition too incomplete to check

A `<table>` exists but has no usable storagetype or address, so it cannot be decoded here and cannot be opened in a tuning editor either. **6 entities.**

- **`None`** — AF 3 Correction Adder (Decrease) / None  
  _Fueling - AF Correction / Learning_
  - definition unreadable: no address
- **`None`** — AF 3 Correction Adder (Increase) B / TPS Opening %  
  _Fueling - AF Correction / Learning_
  - definition unreadable: no address
- **`None`** — AF 3 Correction Adder (Decrease)  
  _Fueling - AF Correction / Learning_
  - definition unreadable: no address
- **`None`** — AF 3 Correction Adder (Increase) B  
  _Fueling - AF Correction / Learning_
  - definition unreadable: no address
- **`0xC009E`** — Wastegate Duty Cycle Frequency  
  _Boost Control - Wastegate_
  - definition unreadable: scaling '0.01' is not defined in any XML
- **`0xCCDA0`** — CL to OL Enrichment Threshold (MAF)  
  _Fueling - CL/OL Transition_
  - definition unreadable: element count unresolved

## 6b. Watchlist — width disagreements deliberately NOT called conflicts

For these the descriptor's typecode field and the spacing to the next table boundary point at different cell widths, and the definition agrees with neither or with only one. Two weak signals disagreeing is not a conflict, so the flag ladder leaves these where the byte checks put them — but they are the best candidates for the next `0xC0BCC`-class find, so they are listed rather than buried.

_None._

## 7. `DISASM-ONLY` — RAM identities resting on one source

230 RAM variables are named only in `ram_reference.txt`, with no independent corroboration from the feed trace. Three of this project's four wrong-direction corrections were exactly this shape: a plausible name in one derived file, copied everywhere, never re-derived. The top entries by reference count are listed; the full set is in the JSON.

| Address | Claimed name | Code access widths |
|---|---|---|
| `0xFFFF65FC` | vehicle_speed_kmh | float x134 |
| `0xFFFF67EC` | dtc_maturation_counter_67EC | int16 x99 |
| `0xFFFF65C0` | diag_precondition_flag_65C0 | int8 x89 |
| `0xFFFF8E98` | cl_state_struct | int8 x83 |
| `0xFFFF4130` | battery_voltage | float x77 |
| `0xFFFF85D7` | fuel_system_state | int8 x59 |
| `0xFFFF6254` | flag_6254 | int8 x51 |
| `0xFFFF6898` | atm_pressure_current | float x48 |
| `0xFFFF620C` | manifold_pressure_map | float x43 |
| `0xFFFF8E46` | fuel_mode_flags | int8 x39 |
| `0xFFFF366C` | io_inj_driver_ctrl | int16 x3, int8 x33 |
| `0xFFFF895C` | injector_data | float x36 |
| `0xFFFFAF3B` | comms_state_byte | int8 x35 |
| `0xFFFF65BD` | engine_state_byte | int8 x34 |
| `0xFFFF6C48` | diag_status_code_6C48 | int8 x34 |
| `0xFFFF5BE3` | clutch_state | int8 x33 |
| `0xFFFF6155` | adc_channel_status | float x1, int8 x31 |
| `0xFFFF7C9D` | fuel_state_byte | int8 x32 |
| `0xFFFF8EDC` | ol_dispatch_gate | int16 x2, int8 x29 |
| `0xFFFF69F0` | ratio_0to1_69F0 | float x28 |
| `0xFFFF64D8` | accel_pedal_angle | float x27 |
| `0xFFFF61CC` | diag_monitor_status_bytes | int8 x26 |
| `0xFFFF43FC` | sensor_misc_state | float x25 |
| `0xFFFF81F0` | knock_learning_value | float x25 |
| `0xFFFF9094` | sched_task_GBR | float x24 |
| `0xFFFF65A9` | engine_state_extended | int8 x23 |
| `0xFFFF5FFC` | io_state_register | float x22 |
| `0xFFFF682C` | adc_processed_misc | float x22 |
| `0xFFFF4144` | ect_output_fmac | float x20 |
| `0xFFFF6228` | maf_voltage | float x20 |

_… 200 more in the JSON._

## 8. How to use this before trusting an area

1. Find the table, axis or RAM address in `verification-status.json` (`entities[].address`).
2. `VERIFIED-BOTH` — safe to reason from, including about identity.
3. `VERIFIED-BYTES` — safe to reason about *contents*, **not** about *meaning*. A wrong-identity error of the `0xC0BCC` class would not have been caught.
4. `BOUNDS-SUSPECT` — the value is right, the editor's limits are not. Do not conclude a value is out of spec because the tool clamped it.
5. `CONFLICT` — stop. Settle it from ROM bytes and record the result in `docs/corrections.md` before building anything on top.
6. `DEFS-ONLY` / `DISASM-ONLY` / `UNMAPPED` — there is no cross-check. State that in whatever you write, per rule 6 in `CLAUDE.md`.

