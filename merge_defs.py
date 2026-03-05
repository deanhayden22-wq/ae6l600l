#!/usr/bin/env python3
"""Merge 32BITBASE + AE5L600L stock + MerpMod ECUFlash XML defs into one file."""

import xml.etree.ElementTree as ET
import sys
import re

def parse_rom(path):
    """Parse an ECUFlash ROM XML, return the root <rom> element."""
    # ECUFlash XMLs may not have a proper declaration; wrap if needed
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    # Some files have bare <rom> without xml declaration - that's fine for ET
    return ET.fromstring(content)

def extract_elements(rom_elem):
    """Extract romid, includes, notes, scalings, and tables from a <rom>."""
    romid = rom_elem.find('romid')
    includes = [e.text for e in rom_elem.findall('include')]
    notes = rom_elem.find('notes')
    scalings = rom_elem.findall('scaling')
    tables = rom_elem.findall('table')
    return romid, includes, notes, scalings, tables

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
    base_romid, _, base_notes, base_scalings, base_tables = extract_elements(base_rom)

    print(f"Parsing {stock_path}...")
    stock_rom = parse_rom(stock_path)
    stock_romid, _, stock_notes, stock_scalings, stock_tables = extract_elements(stock_rom)

    print(f"Parsing {merp_path}...")
    merp_rom = parse_rom(merp_path)
    merp_romid, _, merp_notes, merp_scalings, merp_tables = extract_elements(merp_rom)

    # Build the merged ROM
    merged = ET.Element('rom')

    # Use MerpMod romid but with a new xmlid so it doesn't conflict
    new_romid = ET.SubElement(merged, 'romid')
    for child in merp_romid:
        new_child = ET.SubElement(new_romid, child.tag)
        new_child.text = child.text
    # Override xmlid
    xmlid_elem = new_romid.find('xmlid')
    if xmlid_elem is not None:
        xmlid_elem.text = 'AE5L600L_MerpMod_Combined'

    # No <include> directives - everything is self-contained

    # Track scaling names to avoid duplicates (last one wins)
    scaling_map = {}

    # Add scalings in order: 32BITBASE -> stock AE5L600L -> MerpMod
    for s in base_scalings:
        name = s.get('name', '')
        scaling_map[name] = s
    for s in stock_scalings:
        name = s.get('name', '')
        scaling_map[name] = s
    for s in merp_scalings:
        name = s.get('name', '')
        scaling_map[name] = s

    print(f"Total unique scalings: {len(scaling_map)}")

    # Add all scalings
    comment_added = set()
    for name, s in scaling_map.items():
        merged.append(s)

    # Add 32BITBASE tables first (these are the base/shared tables)
    print(f"32BITBASE tables: {len(base_tables)}")
    for t in base_tables:
        merged.append(t)

    # Add stock AE5L600L tables (ROM-specific)
    print(f"Stock AE5L600L tables: {len(stock_tables)}")
    for t in stock_tables:
        merged.append(t)

    # Add MerpMod tables
    print(f"MerpMod tables: {len(merp_tables)}")
    for t in merp_tables:
        merged.append(t)

    total = len(base_tables) + len(stock_tables) + len(merp_tables)
    print(f"Total tables: {total}")

    # Pretty print
    indent(merged)

    # Write output
    tree = ET.ElementTree(merged)
    with open(out_path, 'wb') as f:
        tree.write(f, encoding='utf-8', xml_declaration=False)

    # Re-read and clean up: ECUFlash expects no xml declaration
    with open(out_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Remove any xml declaration if present
    content = re.sub(r'<\?xml[^?]*\?>\s*', '', content)

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"\nWrote merged definition to: {out_path}")
    print("This file is fully self-contained - no <include> directives needed.")

if __name__ == '__main__':
    main()
