#!/usr/bin/env python3
"""
consolidate_defs.py - Consolidate EcuFlash XML definitions

Assigns categories to uncategorized tables, adds descriptions where missing,
and appends newly-discovered table definitions.

Usage:
    python scripts/consolidate_defs.py
"""

import re
import os
import sys

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
XML_PATH = os.path.join(
    REPO_ROOT, "definitions",
    "AE5L600L 2013 USDM Impreza WRX MT.xml"
)

# Category rules - evaluated in order; first match wins.
# Each entry: (compiled regex, category string)
# The regex is tested against the table name (case-insensitive).
CATEGORY_RULES = [
    # DTC codes - must be early so they don't match other patterns
    (re.compile(r'\(P0|\(P1|\(P2|\(U0', re.IGNORECASE), 'Diagnostics / DTC'),

    # Knock / FLKC - before ignition so "Knock Correction Advance" goes here
    (re.compile(r'Knock|FLKC|Fine Correction|Rough Correction|Feedback Correction|DAM', re.IGNORECASE),
     'Ignition Timing - Knock'),

    # Boost / Wastegate / Turbo Dynamics
    (re.compile(r'Boost|Wastegate|WG |Turbo Dynamics|TD ', re.IGNORECASE), 'Boost Control'),

    # Ignition / Timing (but NOT Knock - already matched above)
    (re.compile(r'Base Timing|Timing Comp|Timing Correction|Ignition|Dwell', re.IGNORECASE),
     'Ignition Timing'),

    # AVCS / Cam
    (re.compile(r'AVCS|Cam Advance|Cam Retard|Intake Cam|Intake Duty Correction|Exhaust Duty Correction', re.IGNORECASE),
     'AVCS / Cam Timing'),

    # Idle
    (re.compile(r'Idle|ISC|Idle Speed|Idle Airflow', re.IGNORECASE), 'Idle Control'),

    # MAF / Airflow
    (re.compile(r'MAF|Mass Airflow|Airflow|MAF Sensor|MAF Limit|MAF Comp', re.IGNORECASE),
     'MAF / Airflow'),

    # Torque Management / DBW
    (re.compile(r'Requested Torque|Target Throttle|Torque Limit|Speed Limiting|Accelerator Pedal', re.IGNORECASE),
     'Torque Management / DBW'),

    # Rev Limit / Fuel Cut
    (re.compile(r'Rev Limit|Fuel Cut|Overrun|Speed Limit', re.IGNORECASE),
     'Fueling - Fuel Cut / Rev Limit'),

    # Injector
    (re.compile(r'Injector|Deadtime|Latency|Pulse Width|Flow Rate|Flow Scaling', re.IGNORECASE),
     'Fueling - Injector'),

    # A/F Learning
    (re.compile(r'A/F Learning|AFL|AF Learning|AF 3 Correction', re.IGNORECASE),
     'Fueling - AF Correction / Learning'),

    # CL/OL Transition
    (re.compile(r'CL to OL|Closed Loop|Open Loop|CL Delay|CL Fueling Target', re.IGNORECASE),
     'Fueling - CL/OL Transition'),

    # Base / Enrichment fueling
    (re.compile(
        r'Cranking|Post.?Start|Warmup|Cold Start|Primary Open Loop|Primary Base|'
        r'Enrichment|Tip.?in|Fuel Map Switch|Min Primary|Tau Input|'
        r'Front Oxygen|O2 Sensor Scaling|O2 Sensor Rich|O2 Sensor Comp',
        re.IGNORECASE),
     'Fueling - Base / Enrichment'),

    # Engine Load / Manifold Pressure / Sensors
    (re.compile(r'Engine Load Comp|Engine Load Limit|Load Limit|Manifold Pressure|'
                r'Sensor Scaling|Temp Sensor|Fuel Temp|Intake Temp Sensor|Coolant Temp Sensor|'
                r'Barometric', re.IGNORECASE),
     'Sensors / Calibration'),

    # Vehicle Speed / Transmission / Gear
    (re.compile(r'Vehicle Speed|Gear Comp|Gear Determination|Calculated Engine Torque', re.IGNORECASE),
     'Vehicle Speed / Transmission'),

    # Radiator / cooling
    (re.compile(r'Radiator Fan', re.IGNORECASE), 'Cooling'),

    # Fuel pump / cluster
    (re.compile(r'Fuel Pump|Cluster Display', re.IGNORECASE), 'Fuel System'),
]

# Default description for DTC tables
DTC_DESCRIPTION = "OBD-II diagnostic trouble code monitor. Enable/disable and threshold configuration."

# Missing tables to append before </rom>
# (name, address, category, scaling, description)
MISSING_TABLES = [
    # MAF / Airflow
    ('CL MAF Enable Threshold', 'cc020', 'MAF / Airflow', 'ThresholdFloat',
     'MAF threshold for CL learning enable. Stock: 70.0 g/s.'),
    ('CL MAF Hysteresis ON', 'cbe70', 'MAF / Airflow', 'Airflow_gs',
     'CL readiness MAF hysteresis ON threshold. Stock: 1000.0 g/s. Effectively disabled (MAF never reaches this).'),
    ('CL MAF Hysteresis OFF', 'cbe74', 'MAF / Airflow', 'Airflow_gs',
     'CL readiness MAF hysteresis OFF threshold. Stock: 1100.0 g/s. Effectively disabled.'),
    ('Barometric Pressure Offset', 'd8adc', 'Sensors / Calibration', 'MapSwitchFloat',
     'Barometric pressure calculation offset. baro = offset + normalized_MAP * scale. Stock: -414.0.'),

    # Torque Management
    ('Torque Request Minimum APP', 'cc570', 'Torque Management / DBW', 'ThresholdFloat',
     'Minimum accelerator pedal position for torque request enable. Stock: 0.46.'),
    ('Torque Request MAF Upper Gate', 'cc574', 'Torque Management / DBW', 'Airflow_gs',
     'MAF upper gate for torque request processing. Stock: 1000.0 g/s.'),
    ('Torque Request MAF Maximum', 'cc578', 'Torque Management / DBW', 'Airflow_gs',
     'MAF absolute maximum for torque request. Stock: 2000.0 g/s.'),
    ('MAF Hysteresis A ON (CL/OL)', 'cc588', 'Torque Management / DBW', 'Airflow_gs',
     'MAF-based CL/OL hysteresis flag A set threshold. Stock: 5600.0 g/s.'),
    ('MAF Hysteresis A OFF (CL/OL)', 'cc58c', 'Torque Management / DBW', 'Airflow_gs',
     'MAF-based CL/OL hysteresis flag A clear threshold. Stock: 5100.0 g/s.'),
    ('MAF Hysteresis B ON (CL/OL)', 'cc590', 'Torque Management / DBW', 'Airflow_gs',
     'MAF-based CL/OL hysteresis flag B set threshold. Stock: 4000.0 g/s.'),
    ('MAF Hysteresis B OFF (CL/OL)', 'cc594', 'Torque Management / DBW', 'Airflow_gs',
     'MAF-based CL/OL hysteresis flag B clear threshold. Stock: 3500.0 g/s.'),
    ('MAF Hysteresis C ON (CL/OL)', 'cc598', 'Torque Management / DBW', 'Airflow_gs',
     'MAF-based CL/OL hysteresis flag C set threshold. Stock: 2600.0 g/s.'),
    ('MAF Hysteresis C OFF (CL/OL)', 'cc59c', 'Torque Management / DBW', 'Airflow_gs',
     'MAF-based CL/OL hysteresis flag C clear threshold. Stock: 1900.0 g/s.'),
    ('MAF Hysteresis D ON (CL/OL)', 'cc5a0', 'Torque Management / DBW', 'Airflow_gs',
     'MAF-based CL/OL hysteresis flag D set threshold. Stock: 2600.0 g/s.'),

    # Boost Control
    ('Boost Control Enable Threshold', 'd6720', 'Boost Control', 'BoostThreshold',
     'Sensor threshold above which boost control activates. Stock: 4.0.'),
    ('Boost Control Disable Threshold', 'd6724', 'Boost Control', 'BoostThreshold',
     'Sensor threshold below which boost control deactivates. Stock: 5.0.'),
    ('Boost Feedback Filter Coefficient', 'd6748', 'Boost Control', 'CoefficientFloat',
     'IIR filter coefficient for boost feedback trim loop. Stock: 0.5.'),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def classify_table(name):
    """Return a category string for the given table name, or None."""
    for pattern, category in CATEGORY_RULES:
        if pattern.search(name):
            return category
    return None


def is_dtc_table(name):
    """Check if a table name looks like a DTC code entry."""
    return bool(re.match(r'\(P\d|^\(U\d', name))


def build_missing_table_xml(name, address, category, scaling, description):
    """Build an XML string for a missing 1D table definition."""
    lines = []
    lines.append(f'\t<table name="{name}" category="{category}" '
                 f'address="{address}" type="1D" scaling="{scaling}">')
    lines.append(f'\t\t<description>{description}</description>')
    lines.append('\t</table>')
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Main - uses text-based processing to preserve formatting
# ---------------------------------------------------------------------------

def main():
    if not os.path.isfile(XML_PATH):
        print(f"ERROR: XML file not found: {XML_PATH}")
        sys.exit(1)

    with open(XML_PATH, 'r', encoding='utf-8') as f:
        original = f.read()

    lines = original.split('\n')

    stats = {
        'categories_added': 0,
        'descriptions_added': 0,
        'tables_appended': 0,
        'tables_already_categorized': 0,
        'tables_uncategorized': [],
    }

    # We'll process line by line, looking for top-level <table> opening tags
    # that do NOT already have a category attribute.
    #
    # Strategy:
    #   - Track nesting depth to distinguish top-level tables from child tables.
    #   - For top-level tables without category, insert one based on the name.
    #   - For top-level tables without a <description> child, add one if we
    #     have a rule for it.

    output_lines = []
    table_depth = 0  # depth of <table> nesting (0 = outside any table)
    current_top_table_name = None
    current_top_table_line_idx = None
    current_top_table_has_category = False
    current_top_table_has_description = False
    inside_top_table = False  # True when we're between the opening and closing of a top-level table

    # Regex patterns
    re_table_open = re.compile(r'^(\s*)<table\s')
    re_table_self_close = re.compile(r'/>\s*$')
    re_table_close = re.compile(r'</table>')
    re_name_attr = re.compile(r'name="([^"]*)"')
    re_category_attr = re.compile(r'category="([^"]*)"')
    re_description_elem = re.compile(r'<description>')

    i = 0
    while i < len(lines):
        line = lines[i]

        # Check for table opening tag
        m_open = re_table_open.match(line)
        if m_open:
            m_name = re_name_attr.search(line)
            m_cat = re_category_attr.search(line)

            if table_depth == 0:
                # This is a top-level table
                current_top_table_name = m_name.group(1) if m_name else ''
                current_top_table_line_idx = len(output_lines)
                current_top_table_has_category = m_cat is not None
                current_top_table_has_description = False
                inside_top_table = True

                if m_cat:
                    stats['tables_already_categorized'] += 1

            # Track self-closing vs normal open
            if re_table_self_close.search(line):
                # Self-closing: <table ... />
                if table_depth == 0:
                    # Top-level self-closing table
                    if not current_top_table_has_category:
                        cat = classify_table(current_top_table_name)
                        if cat:
                            line = self_add_category(line, cat)
                            stats['categories_added'] += 1
                        else:
                            stats['tables_uncategorized'].append(current_top_table_name)

                    # Check if we need to add a description
                    desc = get_description(current_top_table_name)
                    if desc:
                        # Expand self-closing tag to open+description+close
                        # Replace trailing /> with >
                        expanded = re.sub(r'/>\s*$', '>', line)
                        output_lines.append(expanded)
                        output_lines.append(f'\t\t<description>{desc}</description>')
                        output_lines.append('\t</table>')
                        stats['descriptions_added'] += 1
                        inside_top_table = False
                        current_top_table_name = None
                        i += 1
                        continue

                    inside_top_table = False
                    current_top_table_name = None
                output_lines.append(line)
                i += 1
                continue
            else:
                table_depth += 1
                output_lines.append(line)
                i += 1
                continue

        # Check for </table>
        if re_table_close.search(line):
            if table_depth > 0:
                table_depth -= 1
                if table_depth == 0 and inside_top_table:
                    # Closing a top-level table - finalize
                    # Check if we need to add category to the opening tag
                    if not current_top_table_has_category:
                        cat = classify_table(current_top_table_name)
                        if cat:
                            # Modify the opening tag line in output_lines
                            idx = current_top_table_line_idx
                            output_lines[idx] = add_category_to_tag(output_lines[idx], cat)
                            stats['categories_added'] += 1
                        else:
                            stats['tables_uncategorized'].append(current_top_table_name)

                    # Check if we need to add description
                    if not current_top_table_has_description:
                        desc = get_description(current_top_table_name)
                        if desc:
                            # Insert description line before this closing tag
                            output_lines.append(f'\t\t<description>{desc}</description>')
                            stats['descriptions_added'] += 1

                    inside_top_table = False
                    current_top_table_name = None

            output_lines.append(line)
            i += 1
            continue

        # Inside a top-level table, check for description element
        if inside_top_table and table_depth == 1:
            if re_description_elem.search(line):
                current_top_table_has_description = True

        output_lines.append(line)
        i += 1

    # Append missing tables before </rom>
    # Find the </rom> line in output_lines
    result_text = '\n'.join(output_lines)

    # Build the new table XML blocks
    new_blocks = []
    for name, address, category, scaling, description in MISSING_TABLES:
        new_blocks.append(build_missing_table_xml(name, address, category, scaling, description))
        stats['tables_appended'] += 1

    # Insert before </rom>
    insertion = '\n\n'.join(new_blocks)
    result_text = result_text.replace(
        '\n</rom>',
        '\n\n' + insertion + '\n\n</rom>'
    )

    # Write output
    with open(XML_PATH, 'w', encoding='utf-8') as f:
        f.write(result_text)

    # Print summary
    print("=" * 60)
    print("consolidate_defs.py - Summary")
    print("=" * 60)
    print(f"  Categories added:            {stats['categories_added']}")
    print(f"  Descriptions added:          {stats['descriptions_added']}")
    print(f"  New tables appended:         {stats['tables_appended']}")
    print(f"  Tables already categorized:  {stats['tables_already_categorized']}")
    print()
    if stats['tables_uncategorized']:
        print(f"  Tables left uncategorized ({len(stats['tables_uncategorized'])}):")
        for name in stats['tables_uncategorized']:
            print(f"    - {name}")
    else:
        print("  All tables now have categories.")
    print()
    print(f"  Output written to: {XML_PATH}")


def add_category_to_tag(line, category):
    """Insert category="..." attribute into a <table> opening tag line."""
    # Insert after name="..." attribute
    m = re.search(r'(name="[^"]*")', line)
    if m:
        insert_pos = m.end()
        return line[:insert_pos] + f' category="{category}"' + line[insert_pos:]
    # Fallback: insert before the first > or />
    m2 = re.search(r'(/?>)', line)
    if m2:
        return line[:m2.start()] + f' category="{category}" ' + line[m2.start():]
    return line


def self_add_category(line, category):
    """Same as add_category_to_tag but for self-closing tags."""
    return add_category_to_tag(line, category)


def get_description(name):
    """Return a description string for tables that should get one, or None."""
    # DTC tables
    if is_dtc_table(name):
        return DTC_DESCRIPTION
    # Don't auto-generate descriptions for other tables -
    # we only add them for DTCs as specified
    return None


if __name__ == '__main__':
    main()
