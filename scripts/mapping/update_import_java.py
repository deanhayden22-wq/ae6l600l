#!/usr/bin/env python3
"""
Update ImportAE5L600L.java with:
1. 760 calibration descriptor labels
2. ISR dispatch table labels (54 entries)
3. Generic ISR handler + dispatch infrastructure labels

Inserts new label blocks before the final printf/count line.
"""
import os
import re
import struct
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DISASM_DIR = os.path.join(SCRIPT_DIR, "..", "disassembly")
JAVA_FILE = os.path.join(DISASM_DIR, "ImportAE5L600L.java")
DESC_LABELS_FILE = os.path.join(DISASM_DIR, "descriptor_labels.txt")

ROM_DIR = os.path.join(SCRIPT_DIR, "..", "rom")

def load_rom():
    p = os.path.join(ROM_DIR, "ae5l600l.bin")
    if os.path.isfile(p):
        with open(p, "rb") as f:
            return f.read()
    for fn in sorted(os.listdir(ROM_DIR)):
        if fn.lower().endswith(".bin"):
            with open(os.path.join(ROM_DIR, fn), "rb") as f:
                return f.read()
    sys.exit("No ROM found")

def r_u32(rom, a):
    return struct.unpack_from(">I", rom, a)[0]

def r_u16(rom, a):
    return struct.unpack_from(">H", rom, a)[0]


def build_isr_block(rom):
    """Build Java label block for ISR infrastructure."""
    rom_len = len(rom)
    lines = []

    # The interrupt dispatch infrastructure we found
    lines.append("        // ============================================================")
    lines.append("        // SH7058 INTERRUPT ARCHITECTURE")
    lines.append("        // All peripheral IRQs share one generic ISR entry at 0x0BAC")
    lines.append("        // 0x0BAC: saves R0-R7,PR,MACH,MACL; calls 0x0F4C; restores; RTE")
    lines.append("        // 0x0F4C: reads interrupt ID; dispatches via table at 0x0E5EC")
    lines.append("        // 0x0EE4: interrupt ID resolver (reads INTEVT/priority register)")
    lines.append("        // 0x0D78: interrupt acknowledge/clear")
    lines.append("        // 0x0BFA: exception trap (illegal instr/addr error = infinite loop)")
    lines.append("        // Exception vector table: 0x000-0x033 (13 vectors x 4 bytes)")
    lines.append("        //   0x000: initial PC = 0x000C0C (main entry)")
    lines.append("        //   0x004: initial SP = 0xFFFFBFA0 (RAM top)")
    lines.append("        //   0x010-0x020: all exceptions -> 0x0BFA (trap loop)")
    lines.append("        //   0x02C: peripheral IRQ vector -> 0x0BAC (generic ISR)")
    lines.append("        // ============================================================")
    lines.append("")

    # Exception vector table pointer labels
    lines.append("        // Exception vector table entries (ROM 0x000-0x033)")
    exception_vectors = [
        (0x000, "vtbl_reset_pc",    "Power-on reset initial PC = 0x000C0C (main entry)"),
        (0x004, "vtbl_reset_sp",    "Power-on reset initial SP = 0xFFFFBFA0 (RAM top)"),
        (0x008, "vtbl_mreset_pc",   "Manual reset initial PC = 0x000C0C"),
        (0x00C, "vtbl_mreset_sp",   "Manual reset initial SP = 0xFFFFBFA0"),
        (0x010, "vtbl_illegal_instr","Illegal instruction -> 0x0BFA trap"),
        (0x014, "vtbl_illegal_slot", "Illegal slot instruction -> 0x0BFA trap"),
        (0x018, "vtbl_cpu_addr_err", "CPU address error -> 0x0BFA trap"),
        (0x01C, "vtbl_dma_addr_err", "DMA bus error -> 0x0BFA trap"),
        (0x020, "vtbl_nmi",          "NMI -> 0x0BFA trap"),
        (0x024, "vtbl_user_break",   "User break/debug -> 0x0BFA trap"),
        (0x02C, "vtbl_periph_irq",   "All peripheral IRQs -> 0x0BAC generic ISR"),
    ]
    for offset, name, comment in exception_vectors:
        val = r_u32(rom, offset)
        lines.append(f"        count += labelComment(0x{offset:06X}L, \"{name}\", \"{comment} [val=0x{val:08X}]\");")
    lines.append("")

    # ISR infrastructure
    lines.append("        // ISR dispatch infrastructure")
    lines.append("        count += labelComment(0x000BACL, \"isr_generic_handler\",")
    lines.append("            \"Generic peripheral ISR: saves R0-R7/PR/MACH/MACL, calls isr_dispatch, RTE\");")
    lines.append("        count += labelComment(0x000BF6L, \"isr_generic_rte\",")
    lines.append("            \"Generic ISR RTE (return from interrupt) after register restore\");")
    lines.append("        count += labelComment(0x000BFAL, \"exc_trap_infinite_loop\",")
    lines.append("            \"Exception trap: illegal instruction / address error (infinite loop)\");")
    lines.append("        count += labelComment(0x000F4CL, \"isr_dispatch_manager\",")
    lines.append("            \"ISR sub-dispatch: identifies interrupt source, calls handler from isr_dispatch_table\");")
    lines.append("        count += labelComment(0x000EE4L, \"isr_intevt_resolver\",")
    lines.append("            \"Reads INTEVT/priority register to identify interrupt source, returns index\");")
    lines.append("        count += labelComment(0x000D78L, \"isr_int_acknowledge\",")
    lines.append("            \"Interrupt acknowledge/clear function\");")
    lines.append("        count += labelComment(0x000E5ECL, \"isr_dispatch_table\",")
    lines.append("            \"Interrupt dispatch table: 54 function pointers (4 bytes each)\");")
    lines.append("")

    # ISR dispatch table entries (54 handlers)
    TABLE_START = 0xE5EC
    TABLE_SIZE = 54

    # Known identities based on analysis
    # Entry [15] = task scheduler (confirmed)
    # Entries accessing 0xFFFF8EDC (RAM) = scheduler-related
    # Use generic names for now, with specific names for known ones
    known_isrs = {
        0: "isr_handler_0",
        1: "isr_handler_1",
        2: "isr_handler_2",
        3: "isr_handler_3",
        4: "isr_handler_4",
        5: "isr_handler_5",
        6: "isr_handler_6",
        7: "isr_handler_7",
        8: "isr_handler_8",
        9: "isr_handler_9",
        10: "isr_handler_10",
        11: "isr_handler_11",
        12: "isr_handler_12",
        13: "isr_handler_13",
        14: "isr_handler_14",
        15: "isr_task_scheduler",   # CMT/MTU timer tick -> 59-task scheduler
        16: "isr_handler_16",
        17: "isr_handler_17",
        18: "isr_handler_18",
        19: "isr_handler_19",
        20: "isr_handler_20",
        21: "isr_rcan0",             # accesses 0xFFFF36BE / 0xFFFF3D08 = CAN controller
        22: "isr_rcan1",             # accesses same CAN registers
        23: "isr_handler_23",
        24: "isr_handler_24",
        25: "isr_handler_25",
        26: "isr_handler_26",
        27: "isr_handler_27",
        28: "isr_handler_28",
        29: "isr_handler_29",
        30: "isr_handler_30",
        31: "isr_handler_31",
        32: "isr_handler_32",
        33: "isr_handler_33",
        34: "isr_handler_34",
        35: "isr_handler_35",
        36: "isr_handler_36",
        37: "isr_handler_37",
        38: "isr_handler_38",
        39: "isr_handler_39",
        40: "isr_handler_40",
        41: "isr_handler_41",
        42: "isr_handler_42",
        43: "isr_handler_43",
        44: "isr_handler_44",
        45: "isr_handler_45",
        46: "isr_handler_46",
        47: "isr_handler_47",
        48: "isr_handler_48",
        49: "isr_handler_49",
        50: "isr_handler_50",
        51: "isr_handler_51",
        52: "isr_handler_52",
        53: "isr_handler_53",
    }

    lines.append("        // ISR dispatch table entry labels (table at 0x0E5EC, 54 entries)")
    lines.append("        // Entry[N] address = 0x0E5EC + N*4 -> handler address")

    seen_handlers = set()
    for i in range(TABLE_SIZE):
        entry_addr = TABLE_START + i * 4
        handler = r_u32(rom, entry_addr)
        if not (0x1000 <= handler < rom_len):
            continue
        name = known_isrs.get(i, f"isr_handler_{i}")

        # Label the dispatch table entry (the pointer itself)
        lines.append(f"        count += labelComment(0x{entry_addr:06X}L, \"dtbl_{name}\", \"Dispatch table[{i}] -> 0x{handler:06X}\");")

        # Label the handler code (once per unique address)
        if handler not in seen_handlers:
            seen_handlers.add(handler)
            lines.append(f"        count += labelComment(0x{handler:06X}L, \"{name}\", \"ISR dispatch table entry {i}\");")

    lines.append("")
    return lines


def build_descriptor_block():
    """Read the generated descriptor labels file."""
    with open(DESC_LABELS_FILE, 'r') as f:
        return f.read().splitlines()


def main():
    rom = load_rom()
    print(f"Loaded ROM: {len(rom)} bytes")

    # Build ISR block
    isr_lines = build_isr_block(rom)
    print(f"ISR block: {len(isr_lines)} lines")

    # Read descriptor labels
    desc_lines = build_descriptor_block()
    print(f"Descriptor block: {len(desc_lines)} lines")

    # Read current Java file
    with open(JAVA_FILE, 'r', encoding='utf-8') as f:
        content = f.read()

    # Find insertion point: just before the final printf line
    insert_before = '        printf("ImportAE5L600L: Applied %d labels/comments.\\n", count);'
    if insert_before not in content:
        print(f"ERROR: Could not find insertion point in {JAVA_FILE}")
        sys.exit(1)

    # Build the new block to insert
    new_block_lines = []
    new_block_lines.append("")
    new_block_lines.extend(isr_lines)
    new_block_lines.extend(desc_lines)
    new_block_lines.append("")

    new_block = '\n'.join(new_block_lines)

    # Insert before the printf
    new_content = content.replace(insert_before, new_block + '\n' + insert_before)

    # Write back
    with open(JAVA_FILE, 'w', encoding='utf-8') as f:
        f.write(new_content)

    print(f"\nUpdated {JAVA_FILE}")

    # Count new labels
    total_new_labels = sum(1 for line in isr_lines + desc_lines if 'count += label' in line)
    print(f"New label() calls added: {total_new_labels}")

    # Count lines
    new_lines = new_content.count('\n')
    print(f"Total lines in updated file: {new_lines}")


if __name__ == "__main__":
    main()
