#!/usr/bin/env python3
"""Merge 32BITBASE + AE5L600L stock + MerpMod ECUFlash XML defs into one file.

ECUFlash's <include> mechanism merges tables by name:
- 32BITBASE provides templates: category, type, scaling, description, axis info (NO addresses)
- ROM-specific def provides addresses for matching table names + axis addresses
- Child attributes override parent attributes

This script replicates that merge logic to produce a single self-contained XML.
"""

import xml.etree.ElementTree as ET
import copy
import re


def parse_rom(path):
    """Parse an ECUFlash ROM XML, return the root <rom> element."""
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    return ET.fromstring(content)


def extract_elements(rom_elem):
    """Extract romid, scalings, and tables from a <rom>."""
    romid = rom_elem.find('romid')
    scalings = rom_elem.findall('scaling')
    tables = rom_elem.findall('table')
    return romid, scalings, tables


def merge_table(base_t, stock_t):
    """Merge a base template table with a stock ROM-specific table.

    ECUFlash inheritance: stock (child) attributes override base (parent).
    The stock table typically provides just the address; the base provides
    category, type, scaling, description, axis element counts, etc.

    For sub-tables (axes), we merge by name as well.
    """
    merged = copy.deepcopy(base_t)

    # Stock attributes override base attributes
    for attr, val in stock_t.attrib.items():
        merged.set(attr, val)

    # Merge sub-tables (axes) by name
    base_subs = {sub.get('name'): sub for sub in merged.findall('table')}
    for stock_sub in stock_t.findall('table'):
        sub_name = stock_sub.get('name')
        if sub_name in base_subs:
            # Merge: stock axis attributes override base axis attributes
            for attr, val in stock_sub.attrib.items():
                base_subs[sub_name].set(attr, val)
        else:
            # Stock has an axis not in base - add it
            merged.append(copy.deepcopy(stock_sub))

    return merged


def indent(elem, level=0):
    """Add pretty-print indentation to an XML element tree."""
    i = "\n" + level * "\t"
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "\t"
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
        for child in elem:
            indent(child, level + 1)
        if not child.tail or not child.tail.strip():
            child.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i


def main():
    base_path = "32BITBASE.xml"
    stock_path = "AE5L600L 2013 USDM Impreza WRX MT.xml"
    merp_path = "AE5L600L MerpMod.xml"
    out_path = "AE5L600L MerpMod Combined.xml"

    print(f"Parsing {base_path}...")
    base_rom = parse_rom(base_path)
    _, base_scalings, base_tables = extract_elements(base_rom)

    print(f"Parsing {stock_path}...")
    stock_rom = parse_rom(stock_path)
    _, stock_scalings, stock_tables = extract_elements(stock_rom)

    print(f"Parsing {merp_path}...")
    merp_rom = parse_rom(merp_path)
    merp_romid, merp_scalings, merp_tables = extract_elements(merp_rom)

    # Build base table lookup by name
    base_table_map = {}
    for t in base_tables:
        name = t.get('name')
        if name:
            base_table_map[name] = t

    # ---- Build merged ROM ----
    merged = ET.Element('rom')

    # romid from MerpMod
    new_romid = ET.SubElement(merged, 'romid')
    for child in merp_romid:
        new_child = ET.SubElement(new_romid, child.tag)
        new_child.text = child.text
    xmlid_elem = new_romid.find('xmlid')
    if xmlid_elem is not None:
        xmlid_elem.text = 'AE5L600L_MerpMod_Combined'

    # ---- Scalings (deduplicated, last wins) ----
    scaling_map = {}
    for s in base_scalings:
        scaling_map[s.get('name', '')] = s
    for s in stock_scalings:
        scaling_map[s.get('name', '')] = s
    for s in merp_scalings:
        scaling_map[s.get('name', '')] = s

    print(f"Total unique scalings: {len(scaling_map)}")
    for s in scaling_map.values():
        merged.append(s)

    # ---- Tables ----
    # Strategy:
    # 1. For stock tables that match a base template by name: merge (base template + stock addresses)
    # 2. For stock tables with no base match: include as-is (ROM-specific, e.g. tinywrex)
    # 3. Skip base-only tables (templates for other ROMs, no address = useless)
    # 4. MerpMod tables: include as-is (self-contained with all attributes)

    merged_count = 0
    stock_only_count = 0
    skipped_base_count = 0

    stock_names_used = set()
    for t in stock_tables:
        name = t.get('name')
        if name in base_table_map:
            # Merge base template with stock addresses
            merged_t = merge_table(base_table_map[name], t)
            merged.append(merged_t)
            stock_names_used.add(name)
            merged_count += 1
        else:
            # Stock-only table (e.g. tinywrex patches, ROM-specific)
            merged.append(copy.deepcopy(t))
            stock_only_count += 1

    # Count skipped base-only templates
    for t in base_tables:
        if t.get('name') not in stock_names_used:
            skipped_base_count += 1

    # Add MerpMod tables as-is
    merp_count = 0
    for t in merp_tables:
        merged.append(copy.deepcopy(t))
        merp_count += 1

    print(f"Merged (base+stock): {merged_count}")
    print(f"Stock-only (ROM-specific): {stock_only_count}")
    print(f"MerpMod: {merp_count}")
    print(f"Skipped base templates (no AE5L600L address): {skipped_base_count}")
    print(f"Total tables in output: {merged_count + stock_only_count + merp_count}")

    # Pretty print
    indent(merged)

    # Write output
    tree = ET.ElementTree(merged)
    with open(out_path, 'wb') as f:
        tree.write(f, encoding='utf-8', xml_declaration=False)

    # Clean up xml declaration if present
    with open(out_path, 'r', encoding='utf-8') as f:
        content = f.read()
    content = re.sub(r'<\?xml[^?]*\?>\s*', '', content)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"\nWrote merged definition to: {out_path}")
    print("This file is fully self-contained - no <include> directives needed.")


if __name__ == '__main__':
    main()
