# import_disassembly.py - Ghidra Python script
#
# Parses disassembly.txt and applies labels and comments to the current
# Ghidra program. Run this after importing the ROM binary.
#
# Usage:
#   1. Import the ROM binary into Ghidra (raw binary, SH-2, base addr 0x0)
#   2. Script Manager > Run Script > select this file
#   3. When prompted, select disassembly.txt
#
# What it does:
#   - Creates labels for named exception vectors and handlers
#   - Creates labels for all calibration table entries
#   - Adds plate/EOL comments with table categories and metadata
#   - Adds section header comments (e.g. "EXCEPTION VECTOR TABLE")
#
# @category Import
# @author  Generated for AE5L600L ROM

import re
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit

def get_disassembly_path():
    """Prompt user for the disassembly.txt file path."""
    from ghidra.util.filechooser import GhidraFileChooser
    from java.io import File
    import os

    # Try to find it next to the script first
    script_dir = getSourceFile().getParentFile().getAbsolutePath() if getSourceFile() else None
    default_path = None
    if script_dir:
        candidate = os.path.join(script_dir, "disassembly.txt")
        if os.path.exists(candidate):
            default_path = candidate

    if default_path:
        choice = askChoice(
            "Disassembly File",
            "Found disassembly.txt next to script. Use it?",
            ["Yes - use " + default_path, "No - let me browse"],
            "Yes - use " + default_path
        )
        if choice.startswith("Yes"):
            return default_path

    f = askFile("Select disassembly.txt", "Open")
    return f.getAbsolutePath()


def sanitize_label(name):
    """Convert a table name into a valid Ghidra label."""
    # Replace characters not allowed in labels
    s = name.strip()
    s = re.sub(r'[^A-Za-z0-9_]', '_', s)
    # Collapse multiple underscores
    s = re.sub(r'_+', '_', s)
    # Remove leading/trailing underscores
    s = s.strip('_')
    # Ensure it doesn't start with a digit
    if s and s[0].isdigit():
        s = '_' + s
    # Truncate if too long
    if len(s) > 127:
        s = s[:127]
    return s


def parse_disassembly(filepath):
    """Parse disassembly.txt and extract structured data."""
    vectors = []       # (addr, comment)   from vector table
    handlers = []      # (addr, name)      from section headers like "NMI Handler"
    tables = []        # (addr, name, category_comment)  from calibration directory
    sections = []      # (addr, section_name)  from section header comments

    # Patterns
    vector_re = re.compile(
        r'^\s*([0-9A-Fa-f]{8}):\s+\.long\s+0x([0-9A-Fa-f]+)\s*;\s*(.*)'
    )
    section_re = re.compile(
        r'^;\s*(.+?)\s+@\s+0x([0-9A-Fa-f]+)\s*$'
    )
    # Calibration table entry: address followed by table name
    # e.g. "  00014004:  Max Wastegate Duty Limit Post-Compensation"
    cal_entry_re = re.compile(
        r'^\s*([0-9A-Fa-f]{8}):\s+([A-Za-z(].*)$'
    )
    # Calibration category comment line
    # e.g. "              ; Boost Control - Wastegate  [2D]  (Wastegate Duty Cycle (%))"
    cal_comment_re = re.compile(
        r'^\s*;\s+(.+)$'
    )

    in_vector_table = False
    in_calibration = False
    last_cal_addr = None
    last_cal_name = None

    with open(filepath, 'r') as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        stripped = line.rstrip()

        # Detect section headers
        m = section_re.match(stripped)
        if m:
            sec_name = m.group(1).strip()
            sec_addr = int(m.group(2), 16)
            sections.append((sec_addr, sec_name))

            if 'VECTOR TABLE' in sec_name.upper():
                in_vector_table = True
                in_calibration = False
            elif 'CALIBRATION' in sec_name.upper():
                in_calibration = True
                in_vector_table = False
            else:
                handlers.append((sec_addr, sec_name))
                in_vector_table = False
                in_calibration = False
            continue

        # Parse vector table entries
        if in_vector_table:
            m = vector_re.match(stripped)
            if m:
                addr = int(m.group(1), 16)
                target = int(m.group(2), 16)
                comment = m.group(3).strip()
                vectors.append((addr, target, comment))
                continue

        # Parse calibration table entries
        if in_calibration:
            m = cal_entry_re.match(stripped)
            if m:
                # Flush previous entry
                if last_cal_addr is not None:
                    tables.append((last_cal_addr, last_cal_name, ''))
                last_cal_addr = int(m.group(1), 16)
                last_cal_name = m.group(2).strip()
                continue

            m = cal_comment_re.match(stripped)
            if m and last_cal_addr is not None:
                comment = m.group(1).strip()
                tables.append((last_cal_addr, last_cal_name, comment))
                last_cal_addr = None
                last_cal_name = None
                continue

    # Flush last entry
    if last_cal_addr is not None:
        tables.append((last_cal_addr, last_cal_name, ''))

    return vectors, handlers, tables, sections


def apply_to_ghidra(vectors, handlers, tables, sections):
    """Apply parsed data to the current Ghidra program."""
    listing = currentProgram.getListing()
    symtab = currentProgram.getSymbolTable()
    mem = currentProgram.getMemory()
    af = currentProgram.getAddressFactory()

    created_labels = 0
    created_comments = 0
    skipped = 0

    def to_addr(val):
        return af.getDefaultAddressSpace().getAddress(val)

    # Apply vector table entries as comments at the vector addresses
    # and labels at the target addresses
    for addr_val, target_val, comment in vectors:
        addr = to_addr(addr_val)
        if mem.contains(addr):
            cu = listing.getCodeUnitAt(addr)
            if cu:
                cu.setComment(CodeUnit.EOL_COMMENT, comment)
                created_comments += 1

        # Create label at the target address referenced by the vector
        target = to_addr(target_val)
        if mem.contains(target):
            label = sanitize_label(comment)
            if label:
                symtab.createLabel(target, label, SourceType.USER_DEFINED)
                created_labels += 1
        else:
            skipped += 1

    # Apply handler/section labels
    for addr_val, name in handlers:
        addr = to_addr(addr_val)
        if mem.contains(addr):
            label = sanitize_label(name)
            if label:
                symtab.createLabel(addr, label, SourceType.USER_DEFINED)
                created_labels += 1
        else:
            skipped += 1

    # Apply calibration table labels and comments
    for addr_val, name, category in tables:
        addr = to_addr(addr_val)
        if mem.contains(addr):
            label = sanitize_label(name)
            if label:
                symtab.createLabel(addr, label, SourceType.USER_DEFINED)
                created_labels += 1

            if category:
                cu = listing.getCodeUnitAt(addr)
                if cu is None:
                    cu = listing.getCodeUnitContaining(addr)
                if cu:
                    cu.setComment(CodeUnit.EOL_COMMENT, name + " | " + category)
                    created_comments += 1
            else:
                cu = listing.getCodeUnitAt(addr)
                if cu is None:
                    cu = listing.getCodeUnitContaining(addr)
                if cu:
                    cu.setComment(CodeUnit.EOL_COMMENT, name)
                    created_comments += 1
        else:
            skipped += 1

    # Apply section header comments
    for addr_val, sec_name in sections:
        addr = to_addr(addr_val)
        if mem.contains(addr):
            cu = listing.getCodeUnitAt(addr)
            if cu is None:
                cu = listing.getCodeUnitContaining(addr)
            if cu:
                cu.setComment(CodeUnit.PLATE_COMMENT,
                    "=== " + sec_name + " ===")
                created_comments += 1

    return created_labels, created_comments, skipped


def run():
    filepath = get_disassembly_path()
    println("Parsing: " + filepath)

    vectors, handlers, tables, sections = parse_disassembly(filepath)

    println("Parsed:")
    println("  Vector entries: %d" % len(vectors))
    println("  Code sections/handlers: %d" % len(handlers))
    println("  Calibration tables: %d" % len(tables))
    println("  Section headers: %d" % len(sections))

    labels, comments, skipped = apply_to_ghidra(
        vectors, handlers, tables, sections
    )

    println("\nApplied:")
    println("  Labels created: %d" % labels)
    println("  Comments added: %d" % comments)
    println("  Skipped (addr not in memory): %d" % skipped)
    println("\nDone!")


run()
