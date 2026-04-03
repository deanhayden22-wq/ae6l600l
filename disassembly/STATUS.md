# AE5L600L Disassembly Status

**ROM:** 2013 USDM Impreza WRX MT (Denso SH7058, SH-2 CPU)
**Last updated:** 2026-04-03 (100% named function coverage achieved)

---

## At a Glance

| Metric | Value |
|--------|-------|
| ROM size | 1,048,576 bytes (1 MB) |
| Active code+data | 853,100 bytes (81.4%) |
| Unused/free (0xFF) | 195,476 bytes (18.6%) |
| Ghidra functions found | 2,700 |
| Named functions | 329 (12.2%) |
| Unnamed (FUN_) | 2,283 (84.6%) |
| Thunks resolved | 88 (3.3%) |
| Named function coverage | 329/329 (100%) |
| Calibration defs (RomRaider) | 622 |
| Calibration defs mapped to Ghidra | 622 (100%) |
| Descriptors catalogued | 760 (1D: 621, 2D: 139) |
| RAM addresses catalogued | 4,456 |
| GBR bases identified | 459 (445 labeled, 14 already covered) |
| Ghidra label operations | 3,398 |
| Scheduler tasks documented | 59 |
| Analysis files produced | 80 |

---

## Completed Subsystems

Every named function in these subsystems is fully analyzed with disassembly, pseudocode, and RAM/calibration cross-references.

| Subsystem | Functions | Key Files |
|-----------|-----------|-----------|
| CL/OL Fuel Control | 16 | cl_ol_state_machine.txt, cl_ol_comprehensive_review.txt (6 files) |
| Fueling Pipeline | 39 entries | fueling_pipeline_analysis.txt (2-table dispatch, 19+20 entries) |
| Knock / FLKC | 5 | knock_flkc_analysis.txt (163 KB) |
| Ignition Timing | 3 | ignition_timing_analysis.txt + descriptors |
| Injection Timing | 3 | injection_timing_analysis.txt |
| ETB / DBW | 15 | etb_dbw_analysis.txt |
| Boost Control | 2 | boost_control_analysis.txt |
| Idle Control | covered | idle_control_analysis.txt |
| AVCS (Cam Timing) | covered | avcs_analysis.txt |
| Torque Management | 2 | torque_management_analysis.txt |
| MAF Scaling | 3 | maf_scaling_analysis.txt |
| AFC/AFL Fuel Trims | 7 | (within CL/OL and fueling files) |
| LTFT Learning | 2 | (within fueling files) |
| Startup Enrichment | covered | startup_enrichment_analysis.txt |
| Accel Enrichment | covered | accel_enrichment_analysis.txt |
| Tau/Alpha | covered | tau_alpha_analysis.txt |
| Map Switching | covered | map_switching_analysis.txt |
| Fuel Pump | covered | fuel_pump_analysis.txt |
| Task Scheduler | 6 | task_scheduler_analysis.txt, task_call_graph.txt |
| DTC Framework | covered | dtc_diagnostics_analysis.txt |
| Per-Cyl Injection Output | 7 stages | percyl_injection_output_analysis.txt |
| EVAP Workspace Init | 1 (+trampoline) | final_seven_analysis.txt |
| Peripheral I/O Library | 2 | final_seven_analysis.txt |
| Math/Utility Library | 4 | final_seven_analysis.txt |

---

## Region-by-Region Coverage

```
Region             Functions  Named   %     Status
--------------------------------------------------------------
0x000-0x00F (64K)    383       76    19%    Partial — RTOS, ISR, ADC, startup
0x010-0x01F (64K)    264        7     2%    SCOUTED — BSP/RTOS infra (low tuning value)
0x020-0x02F (64K)    364       30     8%    SCOUTED — engine control utility library
0x030-0x03F (64K)    257       54    21%    Partial — CL/OL, AFC, timing
0x040-0x04F (64K)    209       71    33%    BEST — knock, ignition, injection
0x050-0x05F (64K)    242       35    14%    Partial — ETB, boost, diagnostics
0x060-0x06F (64K)    173        7     4%    SCOUTED — OBD-II diagnostic monitors
0x070-0x07F (64K)    217        6     2%    SCOUTED — sensor diagnostics
0x080-0x08F (64K)    227        0     0%    ANALYZED — per-cyl output + diag monitors
0x090-0x09F (64K)    176       12     6%    Partial — DTC framework
0x0A0-0x0AF (64K)    133        7     5%    Partial — DTC handlers
0x0B0-0x0BF (64K)     55       24    43%    BEST % — math/utility library
```

---

## What's Left: Priority Targets

### HIGH (tuning-relevant, direct impact on table editing)

1. ~~**0x0640F4 — Parametric diagnostic monitor framework**~~ -- DONE
   - 597-entry dispatch table at 0x064100 with 95 unique handler stubs
   - See `analysis/diag_dispatch_table_analysis.txt`

2. ~~**0x020000-0x02FFFF — Systematic scout**~~ -- DONE
   - Identity: Engine control utility library (491 call targets, no task entry points)
   - 155 flag readers, 45 DTC flag readers, ~80 enrichment calculators
   - Misclassified code block at 0x028100-0x029700
   - See `analysis/region_020000_scout.txt`

3. ~~**Batch-label flag/DTC reader stubs in 0x020000**~~ -- Done. 40 new labels via byte pattern scanner (scripts/flag_reader_scan.py). Templates: T1 (flag readers), T2 (DTC flag readers), T5 (tiny return stubs).

### MEDIUM (diagnostic/sensor, useful for understanding DTCs)

4. **Sensor diagnostic dispatchers (0x071A76, 0x07D526)**
   - Task-level entry points controlling ~30+ sensor monitor functions
   - 0x07D6CC already cross-referenced from CL/OL as fuel trim diagnostic reader

5. **EEPROM adaptation persistence (0x070000 region)**
   - ~20 functions handling adaptation data storage
   - Relevant for understanding learned values and reset behavior

6. **Sensor rationality check (0x07CB30)**
   - Complex function with multiple sensor comparisons
   - Relevant for understanding sensor plausibility DTCs

### LOW (infrastructure, diminishing returns for tuning)

7. **BSP internal call targets in 0x010000**
   - Naming top 5 functions (0x016708, 0x016558, 0x011880, 0x014278, 0x01D742) would propagate labels to 200+ call sites
   - RTOS/hardware-level code, minimal tuning value

8. ~~**Math/utility library gaps (0x0BE000+)**~~ -- DONE
   - 4 functions analyzed: table_desc_2d_uint8, table_desc_2d_uint16, int_sat_sub, interp_1d_uint16_int
   - See `analysis/final_seven_analysis.txt`

9. **0x078000-0x078FFF sub-region**
   - Code blocks present but zero Ghidra-detected functions
   - Needs manual function creation in Ghidra

---

## Reference Maps & Tools

| Resource | Description |
|----------|-------------|
| `maps/rom_region_map.txt` | Full ROM layout with type classification per sub-region |
| `maps/descriptor_map.txt` | 760 calibration descriptors (scales, biases, axis ranges) |
| `maps/ram_map_raw.txt` | 4,456 RAM addresses with reference counts |
| `maps/gbr_structures.txt` | GBR workspace definitions with all offsets |
| `maps/gbr_registry.txt` | 459 GBR bases (445 labeled) |
| `maps/cal_crossref.txt` | RomRaider-to-Ghidra definition matching |
| `maps/task_call_graph.txt` | 59 scheduler tasks with calls, RAM, calibrations |
| `maps/thunk_resolution.txt` | 88 thunk functions resolved to targets |
| `maps/desc_func_xref.txt` | Descriptor-to-function cross-references |
| `maps/isr_map.txt` | Interrupt vectors and ISR architecture |
| `maps/gbr_labeling_stats.txt` | GBR bulk-labeling results and stats |
| `ghidra/ImportAE5L600L.java` | Ghidra import script (3,326 labels) |
| `ghidra/gbr_labels_generated.txt` | Auto-generated GBR label source (354 labels) |
| `scripts/sh2_disasm.py` | SH-2 disassembler for raw binary analysis |
| `scripts/ae5l600l_tools.py` | General analysis toolkit |
| `scripts/consolidate_defs.py` | RomRaider definition consolidation |
| `scripts/gbr_label_gen.py` | GBR bulk-labeling generator script |
| `scripts/flag_reader_scan.py` | Flag/DTC reader byte pattern scanner |

---

## Recommended Next Steps

### Phase 1: Low-hanging fruit (script-driven) -- COMPLETE
- ~~**Map remaining 463 calibration defs**~~ -- Done. All 622 RomRaider defs now in ImportAE5L600L.java.
- ~~**Bulk-label GBR bases**~~ -- Done. 354 new GBR workspace labels added (region-prefixed). Total Ghidra labels: 3,326.

### Phase 2: Targeted analysis -- COMPLETE
- ~~**Analyze 0x064100 dispatch table**~~ -- Done. 597-entry diagnostic monitor dispatch table with 95 handler stubs. DTC disable = replace func ptr with 0x05E76A (noop).
- ~~**Scout 0x020000-0x02FFFF**~~ -- Done. Engine control utility library: 155 flag readers, 45 DTC flag readers, ~80 enrichment calcs, ~80 fuel correction/IPW functions. No task entry points.

### Phase 3: Deepen existing coverage
- **Trace sensor diagnostic dispatchers** (0x071A76, 0x07D526) to understand DTC enable/disable paths.
- **Document EEPROM adaptation** functions for understanding learned value persistence.
- **Create function entries** in 0x078000-0x078FFF where Ghidra missed them.

### Phase 4: Polish
- **Propagate BSP labels** — Name 5 high-call-count BSP functions to label 200+ call sites.
- **Correct rom_region_map errors** — Several "float_data" blocks are actually code (0x010800, 0x01A300, 0x064100).
- ~~**Document utility library**~~ -- DONE. All 7 remaining named functions analyzed in `analysis/final_seven_analysis.txt`. Named function coverage: **329/329 (100%)**.

---

## Known Corrections Needed

1. **rom_region_map.txt** misclassifies several code blocks as "float_data":
   - 0x010800, 0x01A300 (BSP region)
   - 0x064100-0x065D00 (parametric monitor dispatch table)
   - 0x086500 (sensor float aggregation code)
   - 0x087100 (DTC check functions)

2. **descriptor_map.txt** entries at 0x0865xx and 0x0870xx point to calibration addresses not yet in any RomRaider definition.

3. **Region 0x080000** has 0% named functions despite being fully analyzed — the analysis identified function purposes but Ghidra labels haven't been updated yet.
