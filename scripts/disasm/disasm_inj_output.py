#!/usr/bin/env python3
"""
Layer 5: Find the REAL injection output path
- Scan for writes to SH7058 peripheral registers (injector driver)
- Scan for who writes to injector-related RAM
- Trace from fuel_pulse_width_calc output to hardware
"""

import struct

ROM_PATH = r"C:\Users\Dean\Documents\GitHub\ae6l600l\rom\ae5l600l.bin"

with open(ROM_PATH, "rb") as f:
    ROM = f.read()

def r16(d, a): return struct.unpack(">H", d[a:a+2])[0]
def r32(d, a): return struct.unpack(">I", d[a:a+4])[0]
def rf32(d, a): return struct.unpack(">f", d[a:a+4])[0]
def s8(v): return v - 256 if v > 127 else v
def s12(v): return v - 0x1000 if v > 0x7FF else v

print("=" * 90)
print("SCAN 1: Find literal pool references to SH7058 peripheral registers")
print("  Injector driver likely uses: MTU, port output, or DMA")
print("  Register ranges: 0xFFFE0000-0xFFFE8000 (peripherals)")
print("=" * 90)
print()

# Scan all literal pools for addresses in peripheral register range
hw_refs = []
for a in range(0, len(ROM) - 4, 4):
    val = r32(ROM, a)
    # SH7058 peripheral registers
    if 0xFFFE0000 <= val <= 0xFFFEFFFF:
        hw_refs.append((a, val))
    # Also check for FFFF0000-FFFF3FFF range (internal I/O on some SH variants)
    elif 0xFFFF0000 <= val <= 0xFFFF3FFF:
        hw_refs.append((a, val))

# Group by target address and show which ROM addresses reference them
from collections import Counter
target_counts = Counter(val for _, val in hw_refs)

print(f"Found {len(hw_refs)} peripheral register references")
print(f"\nMost-referenced peripheral registers:")
for addr, count in target_counts.most_common(40):
    refs = [a for a, v in hw_refs if v == addr]
    # Classify the register
    if 0xFFFE0000 <= addr <= 0xFFFE0FFF:
        region = "SCI0/1"
    elif 0xFFFE1000 <= addr <= 0xFFFE1FFF:
        region = "MTU2/TMR"
    elif 0xFFFE2000 <= addr <= 0xFFFE2FFF:
        region = "INTC"
    elif 0xFFFE3000 <= addr <= 0xFFFE3FFF:
        region = "DMAC"
    elif 0xFFFE4000 <= addr <= 0xFFFE4FFF:
        region = "MTU2_S"
    elif 0xFFFE5000 <= addr <= 0xFFFE5FFF:
        region = "POE"
    elif 0xFFFE6000 <= addr <= 0xFFFE6FFF:
        region = "A/D"
    elif 0xFFFE7000 <= addr <= 0xFFFE7FFF:
        region = "DAC"
    elif 0xFFFE8000 <= addr <= 0xFFFE8FFF:
        region = "Port"
    elif 0xFFFF0000 <= addr <= 0xFFFF3FFF:
        region = "InternalIO"
    else:
        region = "Unknown"

    ref_str = ", ".join(f"0x{r:06X}" for r in refs[:5])
    if len(refs) > 5:
        ref_str += f" (+{len(refs)-5} more)"
    print(f"  0x{addr:08X} [{region:10s}] refs={count:3d}  at: {ref_str}")


print()
print("=" * 90)
print("SCAN 2: Find who writes to fuel pipeline output addresses")
print("  Targets: 0xFFFF7344 struct, 0xFFFF895C (injector_data)")
print("=" * 90)
print()

# Search literal pools for key fuel output addresses
targets = {
    0xFFFF7344: "fuel_struct_base",
    0xFFFF7348: "fuel_base_factor",
    0xFFFF895C: "injector_data",
    0xFFFF80E4: "inj_pw_primary (TASK46 output)",
    0xFFFF80F8: "final_timing_output (TASK48 output)",
    0xFFFF80EC: "inj_comp_state (TASK47 output)",
    0xFFFF7828: "aggregator_struct_base",
    0xFFFF77BC: "fuel_pipeline_struct",
    0xFFFF76D4: "fuel_enrichment_A",
    0xFFFF7878: "fuel_enrichment_B",
    0xFFFF7AE4: "fuel_enrichment_C",
    0xFFFF7AB4: "afl_multiplier_output",
    0xFFFF7904: "aggregator_output_A",
}

for target, name in targets.items():
    refs = []
    for a in range(0, len(ROM) - 4, 4):
        val = r32(ROM, a)
        if val == target:
            refs.append(a)
    print(f"  {name} (0x{target:08X}): {len(refs)} pool refs")
    for r in refs[:10]:
        # Try to determine what function this is in
        # Look backwards for a function prologue pattern
        print(f"    pool @ 0x{r:06X}")


print()
print("=" * 90)
print("SCAN 3: Find ISR dispatch table entries")
print("  The ISR dispatch table at 0xE5EC handles timed events")
print("=" * 90)
print()

# Read ISR dispatch table
isr_table = 0x0E5EC
print(f"ISR dispatch table @ 0x{isr_table:06X}:")
for i in range(0, 54):
    addr = isr_table + i * 4
    handler = r32(ROM, addr)
    print(f"  [{i:2d}]: 0x{handler:08X}")


print()
print("=" * 90)
print("SCAN 4: Find MTU register accesses in code")
print("  SH7058 MTU2 base addresses:")
print("  TIER=0xFFFF1230, ch0-4 at various offsets")
print("=" * 90)
print()

# Search for known MTU register addresses in literal pools
mtu_regs = {
    0xFFFF1200: "TCR_0 (Timer Control Reg ch0)",
    0xFFFF1201: "TMDR_0 (Timer Mode Reg ch0)",
    0xFFFF1202: "TIORH_0 (Timer I/O ctrl ch0)",
    0xFFFF1204: "TIER_0 (Timer Int Enable ch0)",
    0xFFFF1205: "TSR_0 (Timer Status ch0)",
    0xFFFF1206: "TCNT_0 (Timer Counter ch0)",
    0xFFFF1208: "TGRA_0 (Timer Gen Reg A ch0)",
    0xFFFF120A: "TGRB_0 (Timer Gen Reg B ch0)",
    0xFFFF1230: "TIER_MTU0",
    0xFFFF1280: "TSTR (Timer Start Register)",
    0xFFFF1281: "TSYR (Timer Synchro Register)",
    # MTU channel 3/4 (16-bit)
    0xFFFF1200: "MTU_base",
    # Port output enable
    0xFFFF1420: "POECR (Port Output Enable Ctrl)",
    # ATU (Advanced Timer Unit) - SH7058 specific
    0xFFFF4000: "ATU_base",
    0xFFFF4024: "ATU_reg_24",
}

for reg_addr, name in sorted(mtu_regs.items()):
    refs = []
    for a in range(0, len(ROM) - 4, 4):
        val = r32(ROM, a)
        if val == reg_addr:
            refs.append(a)
    if refs:
        ref_str = ", ".join(f"0x{r:06X}" for r in refs[:8])
        print(f"  {name} @ 0x{reg_addr:08X}: {len(refs)} refs at {ref_str}")

# Also search for the ATU range more broadly
print(f"\n  ATU/Timer range 0xFFFF4000-0xFFFF4100:")
for target in range(0xFFFF4000, 0xFFFF4100, 4):
    refs = []
    for a in range(0, len(ROM) - 4, 4):
        val = r32(ROM, a)
        if val == target:
            refs.append(a)
    if refs:
        ref_str = ", ".join(f"0x{r:06X}" for r in refs[:5])
        print(f"    0x{target:08X}: {len(refs)} refs at {ref_str}")


print()
print("=" * 90)
print("SCAN 5: Exception vector table (injection-relevant interrupts)")
print("=" * 90)
print()

# Read vector table entries for injection-relevant interrupts
# SH7058 exception vectors at ROM 0x000
vectors = {
    67: "IRQ3",
    72: "MTU0_TGIA0", 73: "MTU0_TGIB0", 74: "MTU0_TGIC0", 75: "MTU0_TGID0",
    76: "MTU0_TCIV0",
    80: "MTU1_TGIA1", 81: "MTU1_TGIB1", 82: "MTU1_TCIV1",
    86: "MTU2_TGIA2", 87: "MTU2_TGIB2", 88: "MTU2_TCIV2",
    92: "MTU3_TGIA3", 93: "MTU3_TGIB3", 94: "MTU3_TGIC3", 95: "MTU3_TGID3",
    96: "MTU3_TCIV3",
    100: "MTU4_TGIA4", 101: "MTU4_TGIB4", 102: "MTU4_TGIC4", 103: "MTU4_TGID4",
    104: "MTU4_TCIV4",
    107: "MTU5_TGIW5",
    108: "POE0_OEI1",
    112: "DMAC0_DEI0", 113: "DMAC1_DEI1",
}

for vec_num, name in sorted(vectors.items()):
    addr = vec_num * 4
    handler = r32(ROM, addr)
    if handler != 0 and handler != 0x00000BAC:  # Skip default/unused
        print(f"  Vec {vec_num:3d} ({name:16s}): handler @ 0x{handler:08X}")

# Also dump ALL non-zero/non-default vectors
print(f"\n  All active (non-default) vectors:")
default_handler = r32(ROM, 0)  # Usually 0x00000BAC
for i in range(0, 256):
    addr = i * 4
    handler = r32(ROM, addr)
    if handler != 0 and handler != default_handler and handler < 0x100000:
        print(f"    Vec {i:3d}: 0x{handler:08X}")
