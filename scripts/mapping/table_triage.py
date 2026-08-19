"""Triage every ROM table descriptor that no definition XML names.

    python scripts/mapping/table_triage.py                     # summary + text table
    python scripts/mapping/table_triage.py --json out.json     # machine-readable
    python scripts/mapping/table_triage.py --rom <path>        # another rev
    python scripts/mapping/table_triage.py --live              # drop flat + diagnostic

WHAT THIS IS FOR
Each unnamed descriptor is a PROVEN table: the code reads it through
table_lookup, so geometry, cell type, scale/bias, axis breakpoints and data are
all recoverable from bytes. Only the MEANING is missing. This tool produces the
row you need before deciding whether a table is worth decoding, so that the
expensive step (tracing the consumer) is only spent on candidates that survive.

See docs/analysis-plan.md for the measured hit rate -- across the first 198
tables triaged, ~40% were flat and ~25% were OBD diagnostics.

TWO THINGS THAT MUST NOT BE CHANGED WITHOUT READING corrections.md item 87
  * A table is unnamed iff its DATA pointer is unclaimed. Definitions point at
    data, never at descriptor records. Including the axis pointer in the test
    undercounts the unnamed set by 161.
  * Where an axis ARRAY is shared with a defined table, the axis name is ground
    truth from the XML and is far better than any breakpoint heuristic -- a naive
    classifier calls the 4..80 g/s mass-airflow ladder a temperature axis.
"""
import argparse
import collections
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
import defs                      # noqa: E402
import desc_types as T           # noqa: E402

REPO = os.path.normpath(os.path.join(HERE, '..', '..'))
DEFAULT_ROM = os.path.join(REPO, 'rom', 'AE5L600L 20g rev 20.19c.bin')
DESC_MAP = os.path.join(REPO, 'disassembly', 'maps', 'descriptor_map.txt')
JAVA = os.path.join(REPO, 'disassembly', 'ghidra', 'ImportAE5L600L.java')

# ---------------------------------------------------------------------------
# CLASSIFICATION -- two independent signals, both HINTS, never identifications.
#
# 1. RAM signature: a workspace/GBR base or subsystem-specific variable seen near
#    the call site. Discriminating addresses only -- ect_current, rpm_current,
#    vehicle_speed_kmh and ect_gated_c are the four most common RAM references in
#    the whole corpus and classify nothing, so they are deliberately absent.
# 2. Consumer code region: which 4KB block the call site lives in. This turned
#    out to be the stronger signal. Only regions with a decoded anchor function
#    are listed; the anchor is cited so the claim is auditable.
#
# Several of the RAM labels these match on are themselves project guesses. Never
# name a table from this column -- see docs/analysis-plan.md.
# ---------------------------------------------------------------------------

RAM_SIGNATURES = [
    (('FFFFA160', 'FFFFA174', 'FFFFA290', 'FFFFA26C', 'FFFF8A84', 'FFFF8AC0',
      'FFFF8A88', 'FFFF8A98', 'FFFF65C0', 'gbr_diag_A650', 'gbr_diag_A670',
      'gbr_dtc_A8AC', 'diag_maturation_counter', 'diag_precondition_flag_65C0'),
     'diagnostic'),
    (('evap_pressure_baseline', 'evap_workspace_base', 'evap_cal_cache',
      'egr_timer'), 'evap / emissions'),
    (('sched_task_GBR', 'gbr_sched_90B0', 'gbr_sched_90B2', 'gbr_sched_984D',
      'sched_timer_base', 'sched_event_count'), 'scheduler / task'),
    (('adc_channel_status', 'gbr_adc_6078', 'gbr_adc_6A18', 'gbr_adc_6458',
      'adc_processed_secondary', 'adc_processed_misc', 'io_state_register',
      'gbr_io_5C3C', 'sensor_io_state_secondary'), 'ADC / I-O'),
    (('FFFF798C', 'FFFF79F8', 'FFFF79A4', 'FFFF79A8'), 'OL enrichment / thermal'),
    (('FFFF3234', 'FFFF323C', 'FFFF3244', 'FFFF8286', 'FFFF3248',
      'knock_flkc_workspace', 'flkc_grid'), 'FLKC'),
    (('FFFF8158', 'FFFF8258', 'FFFF81AC', 'FFFF4304', 'knock_level_accum',
      'knock_sensor_state_B', 'knock_det_GBR_base'), 'knock'),
    (('ignition_system_state', 'final_ign_timing_output', 'fuel_timing_corr'),
     'ignition timing'),
    (('FFFF7278', 'FFFF72A0', 'FFFF7288', 'FFFF726C', 'FFFF72D0',
      'coolant_decay_bank_base', 'transient_state_flag'), 'transient fuel'),
    (('FFFF77F0', 'FFFF77F4', 'FFFF782C', 'FFFF7448', 'clol_mode_flag',
      'cl_master_readiness', 'cl_strict_readiness'), 'CL/OL fuelling'),
    (('afc_output', 'gbr_afl_7B8C', 'gbr_afc_7874', 'afc_enable_flag_A',
      'afc_axis_val_A', 'correction_filter_base'), 'AFC / AFL trim'),
    (('base_fuel_map_output', 'gbr_fuel_7278', 'gbr_fuel_73B0', 'gbr_fuel_77F4',
      'gbr_fuel_7710', 'gbr_fuel_73E0', 'gbr_fuel_7354'), 'base fuelling'),
    (('FFFF62DC', 'FFFF64D8', 'accel_pedal_angle'), 'throttle / pedal'),
    (('FFFF7A20', 'FFFF7A24', 'FFFF7A2C', 'FFFF7A3C'), 'idle'),
    (('FFFF620C', 'FFFF5CB0', 'FFFF5CAC', 'manifold_pressure_map'), 'boost / MAP'),
]

# (lo, hi, name, anchor that establishes it)
CODE_REGIONS = [
    (0x02E000, 0x032000, 'transient fuel',    '0x02EFD2 coolant decay bank, item 88'),
    (0x032000, 0x033000, 'base fuelling',     '0x0320AE fuel_correction_final'),
    (0x033000, 0x035000, 'CL/OL fuelling',    '0x033304 cl_fuel_dispatcher; 0x03452A afl_learning_core'),
    (0x035000, 0x036000, 'evap / emissions',  'evap_workspace_base at the call sites'),
    (0x036000, 0x037000, 'OL enrichment / thermal', '0x03644E threshold bank, 0x03684A model, item 89'),
    (0x039000, 0x03A000, 'AFC / AFL trim',    '0x03952C, item 83'),
    (0x043000, 0x045000, 'knock',             '0x043750 knock_wrapper, 0x043782 knock_detector'),
    (0x045000, 0x047000, 'FLKC',              '0x045BFE flkc_path_J, 0x0463BA flkc_paths_FG'),
    (0x049000, 0x04B000, 'scheduler / task',  '0x04A94C sched_periodic_dispatch, item 84'),
    (0x050000, 0x056000, 'diagnostic',        'gbr_sens_* / diag_precondition_flag_65C0, item 87'),
    (0x077000, 0x079000, 'diagnostic',        'diag_monitor_GBR at the call sites'),
    (0x08A000, 0x090000, 'diagnostic',        'gbr_diag_A650 / gbr_diag_A670'),
    (0x0F8000, 0x0FB000, 'throttle / pedal',  'DBW pedal map 0x0F99E0, base RPM 0x0F8B54'),
]


def region_of(site):
    for lo, hi, name, _ in CODE_REGIONS:
        if lo <= site < hi:
            return name
    return ''


def load_rom(path):
    with open(path, 'rb') as fh:
        return fh.read()


def build_indexes(rom):
    """Every aligned occurrence of each 32-bit value, and every PC-relative target."""
    occ = collections.defaultdict(list)
    for a in range(0, len(rom) - 4, 4):
        occ[struct.unpack_from('>I', rom, a)[0]].append(a)
    pcref = collections.defaultdict(list)
    for a in range(0, len(rom) - 2, 2):
        w = struct.unpack_from('>H', rom, a)[0]
        if (w >> 12) == 0xD:
            pcref[(a & ~3) + 4 + ((w & 0xFF) * 4)].append(a)
    return occ, pcref


def definition_index():
    """data address -> table name, and axis address -> axis name."""
    d = defs.load()
    by_data, by_axis = {}, {}
    for t in d.tables:
        a = getattr(t, 'address', None)
        if isinstance(a, int):
            by_data.setdefault(a, t.name)
        for ax in (getattr(t, 'axes', None) or []):
            b = getattr(ax, 'address', None)
            if isinstance(b, int):
                by_axis.setdefault(b, ax.name)
    return by_data, by_axis


def ghidra_labels():
    if not os.path.exists(JAVA):
        return {}
    src = open(JAVA, encoding='utf-8', errors='replace').read()
    out = {}
    for m in re.finditer(r'labelComment\((0x[0-9A-Fa-f]+)L?,\s*"([^"]+)"', src):
        out.setdefault(int(m.group(1), 16), m.group(2))
    return out


def descriptor_candidates():
    txt = open(DESC_MAP, encoding='utf-8', errors='replace').read()
    return [a for a in sorted(set(int(x, 16) for x in re.findall(r'0x([0-9A-Fa-f]{5,6})\b', txt)))
            if 0xA0000 <= a < 0xC0000]


def ram_near(rom, site, span=0x100):
    out = []
    for a in range(max(0, site - span), min(len(rom) - 2, site + span), 2):
        w = struct.unpack_from('>H', rom, a)[0]
        if (w >> 12) != 0xD:
            continue
        t = (a & ~3) + 4 + ((w & 0xFF) * 4)
        if t + 4 > len(rom):
            continue
        v = struct.unpack_from('>I', rom, t)[0]
        if 0xFFFF0000 <= v <= 0xFFFFBFFF:
            out.append(v)
    return out


def triage(rom_path):
    rom = load_rom(rom_path)
    occ, pcref = build_indexes(rom)
    by_data, by_axis = definition_index()
    labels = ghidra_labels()

    rows, named, artefact = [], 0, 0
    for a in descriptor_candidates():
        try:
            two = T.is_2d(rom, a)
            off = T._OFF['2D' if two else '1D']
            data = struct.unpack_from('>I', rom, a + off['data'])[0]
            axes = ([struct.unpack_from('>I', rom, a + off['yaxis'])[0],
                     struct.unpack_from('>I', rom, a + off['xaxis'])[0]] if two else
                    [struct.unpack_from('>I', rom, a + off['axis'])[0]])
            tab = T.read_table(rom, a)
        except Exception:
            artefact += 1
            continue

        if data in by_data:                       # DATA pointer only -- item 87
            named += 1
            continue

        vals = ([v for r in tab['values'] for v in r] if two else list(tab['values']))
        if not vals:
            artefact += 1
            continue
        lo, hi = min(vals), max(vals)
        # scanner artefacts: absurd magnitudes or pointers outside the image
        if any(abs(v) > 1e6 or v != v for v in vals) or not all(0x10000 < p < len(rom)
                                                               for p in [data] + axes):
            artefact += 1
            continue

        sites = [c for s in occ.get(a, []) for c in pcref.get(s, [])]
        seen = collections.Counter()
        for s in sites:
            for v in ram_near(rom, s):
                seen[v] += 1
        labelled = [labels.get(v, '%08X' % v) for v, _ in seen.most_common(8)]
        raw = ['%08X' % v for v, _ in seen.most_common(8)]
        hay = set(labelled) | set(raw)
        sub = next((nm for keys, nm in RAM_SIGNATURES if any(k in hay for k in keys)), '')
        how = 'ram' if sub else ''
        if not sub and sites:
            sub = region_of(sites[0])
            how = 'region' if sub else ''

        rows.append(dict(
            desc='0x%05X' % a, dim=tab['dim'], type=tab['type_name'],
            shape=('%dx%d' % (len(tab['values']), len(tab['values'][0]))) if two
                  else 'x%d' % len(tab['values']),
            scale=tab['scale'], bias=tab['bias'],
            data='0x%05X' % data, lo=round(lo, 5), hi=round(hi, 5),
            flat=(lo == hi),
            axes=['0x%05X' % x for x in axes],
            axis_names=[by_axis.get(x) for x in axes],
            sites=['0x%05X' % s for s in sites],
            ram=[labels.get(v, '%08X' % v) for v, _ in seen.most_common(4)],
            subsystem=sub, matched_by=how,
        ))
    return rows, named, artefact


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--rom', default=DEFAULT_ROM)
    ap.add_argument('--json')
    ap.add_argument('--live', action='store_true',
                    help='drop flat and diagnostic rows')
    args = ap.parse_args()

    rows, named, artefact = triage(args.rom)
    if args.live:
        rows = [r for r in rows if not r['flat'] and r['subsystem'] != 'diagnostic']

    flat = sum(1 for r in rows if r['flat'])
    withaxis = sum(1 for r in rows if any(r['axis_names']))
    withsite = sum(1 for r in rows if r['sites'])
    print('ROM: %s' % os.path.basename(args.rom))
    print('  descriptors named by a definition : %d' % named)
    print('  scanner artefacts skipped         : %d' % artefact)
    print('  UNNAMED, triaged                  : %d' % len(rows))
    print('    flat (inert as shipped)         : %d' % flat)
    print('    axis identity known from a defn : %d' % withaxis)
    print('    with a direct call site         : %d' % withsite)
    print()
    print('  classified by RAM signature: %d, by code region: %d, unassigned: %d'
          % (sum(1 for r in rows if r['matched_by'] == 'ram'),
             sum(1 for r in rows if r['matched_by'] == 'region'),
             sum(1 for r in rows if not r['subsystem'])))
    print()
    print('  by subsystem hint:')
    for k, v in collections.Counter(r['subsystem'] or '(unassigned)'
                                    for r in rows).most_common():
        print('    %-24s %d' % (k, v))
    print()
    W = '%-9s %-3s %-8s %-8s %11s %11s %-5s %-22s %s'
    print(W % ('desc', 'dim', 'type', 'shape', 'min', 'max', 'flat', 'subsystem', 'axis names'))
    print('-' * 128)
    for r in sorted(rows, key=lambda r: r['desc']):
        print(W % (r['desc'], r['dim'], r['type'], r['shape'], r['lo'], r['hi'],
                   'FLAT' if r['flat'] else '', r['subsystem'] or '',
                   ', '.join(n for n in r['axis_names'] if n) or ''))
    if args.json:
        with open(args.json, 'w') as fh:
            json.dump(rows, fh, indent=1)
        print('\nwrote %s (%d rows)' % (args.json, len(rows)))


if __name__ == '__main__':
    main()
