#!/usr/bin/env python3
"""Disassemble CL fuel target functions from Subaru ECU ROM - v2 with pseudocode."""

import struct

ROM_PATH = r"C:\Users\Dean\Documents\GitHub\ae6l600l\rom\AE5L600L 20g rev 20.5 tiny wrex.bin"

with open(ROM_PATH, "rb") as f:
    ROM = f.read()

def read16(addr):
    return struct.unpack(">H", ROM[addr:addr+2])[0]

def read32(addr):
    return struct.unpack(">I", ROM[addr:addr+4])[0]

def read_float(addr):
    return struct.unpack(">f", ROM[addr:addr+4])[0]

def is_plausible_float(raw):
    """Check if a 32-bit value looks like a plausible IEEE 754 float calibration value."""
    if raw == 0:
        return True
    exp = (raw >> 23) & 0xFF
    # Exponent 0xFF = infinity/NaN, not a cal value
    if exp == 0xFF:
        return False
    # Plausible floats for ECU: roughly 1e-6 to 1e6, or 0
    try:
        f = struct.unpack(">f", struct.pack(">I", raw))[0]
        if f == 0.0:
            return True
        if abs(f) > 1e-6 and abs(f) < 1e6:
            return True
    except:
        pass
    return False

def classify_literal(val):
    """Classify a 32-bit literal pool value."""
    if val >= 0xFFFF0000:
        return "RAM"
    elif val < len(ROM):
        # Could be a ROM address (code pointer, table pointer, or param block)
        # Check if it's a function address (code) vs data
        # Read what's at that address
        target = read32(val)
        if target >= 0xFFFF0000:
            # The ROM address holds a RAM pointer -- it's a param block
            return "PARAM_BLOCK"
        raw = val & 0xFFFFFFFF
        # If the value itself looks like a float
        if is_plausible_float(val):
            return "CONST_FLOAT"
        return "ROM_ADDR"
    else:
        # Inline constant
        if is_plausible_float(val):
            return "CONST_FLOAT"
        return "CONST"

# Known RAM addresses
RAM_NAMES = {
    0xFFFF77DC: "CL_target_comp_A_output",
    0xFFFF77E0: "CL_target_comp_B_output",
    0xFFFF77C8: "CL_base_params_struct",
    0xFFFF77D8: "CL_target_comp_output",
    0xFFFF77E4: "CL_target_comp_C_output",
    0xFFFF77E8: "CL_target_comp_D_output",
    0xFFFF77F0: "CL_target_rates_struct",
    0xFFFF781C: "AFC_pipeline_result",
    0xFFFF782A: "CL_target_comp_status",
    0xFFFF6624: "rpm_current",
    0xFFFF63F8: "iat_current",
    0xFFFF65F0: "CL_OL_status_byte",
    0xFFFF984D: "ATx_or_MTx_flag",
    0xFFFF7A44: "CL_integral_term",
}


# =================================================================
# Read the indirect param block pointers used by the dispatcher
# =================================================================
print("=" * 90)
print("  PRE-ANALYSIS: Dispatcher parameter blocks (ROM tables of RAM pointers)")
print("=" * 90)

param_block_addrs = [0x00063A2C, 0x00063A48, 0x00063A44, 0x00063A3C]
for pba in param_block_addrs:
    val = read32(pba)
    name = RAM_NAMES.get(val, "")
    print(f"  ROM 0x{pba:05X} -> 0x{val:08X}  {name}")
    # Read a few more entries from the param block
    for i in range(1, 6):
        v2 = read32(pba + i*4)
        n2 = RAM_NAMES.get(v2, "")
        print(f"    +{i*4:2d}: 0x{v2:08X}  {n2}")
    print()


# =================================================================
# Read the CL/OL status check ROM bytes
# =================================================================
print("=" * 90)
print("  PRE-ANALYSIS: CL/OL mode check values at ROM 0x000CBBD8")
print("=" * 90)
for i in range(8):
    b = ROM[0x000CBBD8 + i]
    print(f"  ROM 0x{0x000CBBD8+i:05X} = 0x{b:02X} ({b})")
print()


# =================================================================
# Verify key RAM contents from ROM pointers used in dispatcher calls
# =================================================================
print("=" * 90)
print("  PRE-ANALYSIS: What ROM 0x63A44 param block holds (used for cl_fuel_target_A)")
print("=" * 90)
base = 0x00063A44
for i in range(8):
    v = read32(base + i*4)
    n = RAM_NAMES.get(v, "")
    print(f"  @0x{base+i*4:05X} [+{i*4:2d}]: 0x{v:08X}  {n}")

print()
print("=" * 90)
print("  PRE-ANALYSIS: What ROM 0x63A48 param block holds (used for cl_fuel_target_B)")
print("=" * 90)
base = 0x00063A48
for i in range(8):
    v = read32(base + i*4)
    n = RAM_NAMES.get(v, "")
    print(f"  @0x{base+i*4:05X} [+{i*4:2d}]: 0x{v:08X}  {n}")


# =================================================================
# Check what the called subroutines at 0xBE8E4 etc actually are
# =================================================================
print()
print("=" * 90)
print("  PRE-ANALYSIS: Subroutine entry points referenced")
print("=" * 90)
sub_addrs = [0x00022CF4, 0x000BE8E4, 0x000BE830, 0x000BEA40, 0x000BE970,
             0x0003439E, 0x000343CE]
for sa in sub_addrs:
    if sa < len(ROM):
        first_word = read16(sa)
        print(f"  0x{sa:05X}: first opcode = 0x{first_word:04X}")


# =================================================================
# Check cal tables referenced by cl_fuel_target_B
# =================================================================
print()
print("=" * 90)
print("  PRE-ANALYSIS: Calibration constants in cl_fuel_target_B")
print("=" * 90)
cal_addrs_b = [0x000CBFB8, 0x000CBFBC, 0x000CBFC0, 0x000CBFC4, 0x000CBFC8, 0x000CBFCC]
for ca in cal_addrs_b:
    raw = read32(ca)
    fval = read_float(ca)
    print(f"  ROM 0x{ca:05X}: raw=0x{raw:08X}  float={fval:.6f}")

# Also check the table descriptor at 0x000ACE6C
print()
print("  Table descriptor at ROM 0x000ACE6C:")
for i in range(8):
    v = read32(0x000ACE6C + i*4)
    n = RAM_NAMES.get(v, "")
    if v >= 0xFFFF0000:
        print(f"    +{i*4:2d}: 0x{v:08X}  RAM {n}")
    elif v < len(ROM):
        fv = read_float(0x000ACE6C + i*4)
        if is_plausible_float(v):
            print(f"    +{i*4:2d}: 0x{v:08X}  (float? {fv})")
        else:
            print(f"    +{i*4:2d}: 0x{v:08X}  ROM ptr")
    else:
        print(f"    +{i*4:2d}: 0x{v:08X}")

# Also look at table descriptor for cl_fuel_target_A
print()
print("  Table descriptors for cl_fuel_target_A:")
for tbl in [0x000AD8D4, 0x000AD8B8, 0x000AD90C, 0x000AD8F0]:
    print(f"  Table at ROM 0x{tbl:05X}:")
    for i in range(8):
        v = read32(tbl + i*4)
        if v >= 0xFFFF0000:
            n = RAM_NAMES.get(v, "")
            print(f"    +{i*4:2d}: 0x{v:08X}  RAM {n}")
        elif v < len(ROM) and v > 0:
            # Could be axis pointer or data pointer
            print(f"    +{i*4:2d}: 0x{v:08X}  ROM")
        else:
            print(f"    +{i*4:2d}: 0x{v:08X}")
    print()


# =================================================================
# PSEUDOCODE
# =================================================================
print()
print("=" * 90)
print("  PSEUDOCODE ANALYSIS")
print("=" * 90)

print("""
================================================================================
  FUNCTION 1: CL Fueling Dispatcher at 0x33304
================================================================================

  void cl_fueling_dispatcher() {
      // Save R14, PR

      // Check CL/OL mode status
      byte status = RAM[0xFFFF65F0];   // CL_OL_status_byte

      // Compare status against 4 valid CL mode values from ROM table at 0xCBBD8
      // Values: 0x00, 0x06, 0x0C, 0x12 (read as sequential bytes)
      byte valid0 = ROM[0x000CBBD8];   // first valid CL mode
      byte valid1 = ROM[0x000CBBD9];   // second valid CL mode
      byte valid2 = ROM[0x000CBBDA];   // third valid CL mode
      byte valid3 = ROM[0x000CBBDB];   // fourth valid CL mode

      if (status != valid0 && status != valid1 &&
          status != valid2 && status != valid3) {
          // Not in a valid CL mode -- return immediately
          return;
      }

      // --- CL Mode Active: Run the 8-stage AFC pipeline ---

      R14 = 0;  // accumulated error = 0 initially

      // Stage 1: cl_fuel_target_B  (BSR 0x33D1C)
      //   R4 = param_block @0x63A2C -> points to FFFF77C8 struct
      //   R5 = param_block @0x63A48 -> points to FFFF77E0 (CL_target_comp_B_output)
      //   R6 = R14 (=0, first_call flag)
      cl_fuel_target_B(param_block_0x63A2C, param_block_0x63A48, R14=0);

      // Stage 2: cl_fuel_target_A  (BSR 0x33CC0)
      //   R4 = param_block @0x63A44 -> points to FFFF77DC (CL_target_comp_A_output)
      //   R5 = R14 (=0)
      cl_fuel_target_A(param_block_0x63A44, R14=0);

      // Stage 3: function at 0x33658 (BSR)
      //   R4 = param_block @0x63A3C -> points to FFFF782A
      //   R5 = param_block @0x63A2C -> points to FFFF77C8
      //   R6 = R14
      func_33658(param_block_0x63A3C, param_block_0x63A2C, R14);

      // Stage 4: function at 0x33FCE (BSR)
      //   R4 = param_block @0x63A44 -> points to FFFF77DC
      func_33FCE(param_block_0x63A44);

      // Stage 5: function at 0x340A0 (BSR)
      func_340A0();

      // Stage 6: function at 0x342A8 (BSR)
      func_342A8();

      // Stage 7: jsr @0x0003439E
      //   R4 = 0xFFFF781C (AFC_pipeline_result)
      //   R5 = R14
      func_3439E(0xFFFF781C, R14);

      // Stage 8: jsr @0x000343CE
      func_343CE();

      // Tail-call: bra 0x33460 (final aggregation/output)
      goto func_33460();  // tail call -- does NOT return to caller via rts here
  }

  NOTE: The bf at 0x33334 goes to 0x33370 which is the early-exit path
  (lds.l @R15+,PR; rts). The bt branches all converge at 0x33336 which
  is the "CL mode active" path.

  The tail-call BRA to 0x33460 means this function continues into another
  routine (likely the final AFC output writer) instead of returning.

================================================================================
  FUNCTION 2: cl_fuel_target_A at 0x33CC0 (writes FFFF77DC)
================================================================================

  void cl_fuel_target_A(R4=param_block_ptr, R5=mode_flag) {
      // Prologue: save R13, R14, PR, FR14, FR15
      R13 = R4;            // param_block_ptr

      FR15 = float[0xFFFF6624];  // engine_load (float)
      FR14 = float[0xFFFF63F8];  // RPM (float)

      // Call subroutine at 0x22CF4 (AT/MT detection?)
      // R14 = R5 (mode_flag, saved before call)
      R0 = sub_22CF4();
      R6 = R0 & 0xFF;      // result byte
      R14 = R14 & 0xFF;     // mode flag cleaned

      // Determine which lookup table to use
      if (R14 == 0) {
          // mode_flag == 0: use ROM[0xFFFF984D] as override
          R2 = byte[0xFFFF984D];  // AT/MT flag
      } else {
          R2 = 0;
      }

      R2 = R2 & 0xFF;
      if (R2 != 0) {
          // AT/MT flag is set
          if (R6 == 1) {       // sub_22CF4 returned 1
              R4 = 0x000AD90C; // table descriptor C (alt AT path)
          } else {
              R4 = 0x000AD8F0; // table descriptor D (alt MT path)
          }
      } else {
          // AT/MT flag is clear
          if (R6 == 1) {       // sub_22CF4 returned 1
              R4 = 0x000AD8D4; // table descriptor A
          } else {
              R4 = 0x000AD8B8; // table descriptor B
          }
      }

      // Call 2D interpolation subroutine at 0xBE8E4
      //   FR4 = FR14 = RPM
      //   FR5 = FR15 = engine_load
      //   R4 = table descriptor pointer
      FR0 = table_lookup_2D(R4, RPM, load);

      // Write result to output RAM address
      // R2 = [R13] = first word of param block = output RAM address
      R2 = long[R13];       // e.g. 0xFFFF77DC
      float[R2] = FR0;      // Write CL target comp A result

      // Epilogue: restore FR15, FR14, PR, R14, R13
      return;
  }

  SUMMARY: cl_fuel_target_A loads RPM and engine_load as floats, determines
  which 2D lookup table to use based on the AT/MT flag and a sub_22CF4
  result, performs a 2D table interpolation (RPM x Load), and stores the
  float result to the RAM address pointed to by param_block[0] (FFFF77DC).

================================================================================
  FUNCTION 3: cl_fuel_target_B at 0x33D1C (writes FFFF77E0)
================================================================================

  void cl_fuel_target_B(R4=param_block_ptr, R5=base_struct_ptr, R6=first_call_flag) {
      // Prologue: save R12, R13, R14, PR, FR14
      R13 = R5;                   // base_struct_ptr
      R6 = R6 & 0xFF;
      R14 = R4;                   // param_block_ptr

      if (R6 == 0) {
          // first_call_flag == 0: Initial call
          FR14 = float[0xFFFF7A44];  // CL_integral_term (previous value)
          R2 = byte[0xFFFF984D];     // AT/MT flag
      } else {
          // subsequent call
          FR14 = 0.0;               // fldi0
          R2 = 0;
      }

      R2 = R2 & 0xFF;
      R12 = 0xFFFF77F0;            // CL_target_rates_struct base

      if (R2 == 0) {
          // AT/MT flag clear -- use hardcoded rate constants
          // Store rate constants to rates struct:
          float[R12 - 8] = 0.050000;   // [0xFFFF77E8] = proportional gain
          float[R12 - 4] = 0.025000;   // [0xFFFF77EC] = derivative gain
          float[R12]     = 0.015000;   // [0xFFFF77F0] = integral gain
      } else {
          // AT/MT flag set -- use table lookup for derivative gain
          float[R12 - 8] = 0.050000;   // [0xFFFF77E8] = proportional gain (same)

          // 2D table lookup for derivative gain
          // R4 = table descriptor at 0x000ACE6C
          // FR4 = FR14 = CL_integral_term
          FR0 = table_lookup(0x000ACE6C, FR14);
          float[R12 - 4] = FR0;        // [0xFFFF77EC] = looked-up derivative gain

          float[R12]     = 0.015000;   // [0xFFFF77F0] = integral gain (same)
      }

      // Rate limiting / integration logic:
      // Compare proportional_gain (rate_P) with CL_integral_term
      FR8 = float[R12 - 8];    // proportional gain
      if (FR8 > FR14) {
          // CL_integral is below proportional threshold
          // Write 0.0 to output
          R2 = long[R14];      // output address (FFFF77E0)
          float[R2] = 0.0;
      } else {
          // CL_integral exceeds threshold -- apply derivative gain
          FR14 = FR14 * float[R12 - 4];  // integral * derivative_gain
          R2 = long[R14_struct];
          float[R2] = FR14;    // write to CL_target_comp_B_output
      }

      // Final output calculation:
      // FR5 = float[R13 + 12]  -- base struct value (from base_struct_ptr[3])
      // FR4 = float[output_addr] -- just-written value
      // Call clamp/blend function at 0xBEA40 with FR6=0.125, FR7 from ROM
      FR0 = clamp_blend(FR4, FR5, 0.125, ...);
      FR4 = FR0;

      // Call rate-limit function at 0xBE970
      //   FR4 = blended value
      //   FR5 = float[R12] = integral_gain (0.015)
      FR0 = rate_limit(FR4, integral_gain);

      // Write final result back to base_struct[3]
      R2 = long[R13 + 12];
      float[R2] = FR0;

      // Epilogue
      return;
  }

  SUMMARY: cl_fuel_target_B implements a PID-like controller for the CL
  fuel target. It uses three rate constants (P=0.05, D=0.025 or table-lookup,
  I=0.015). It reads the CL integral term, applies rate limiting, then
  blends and clamps the result with a gain factor of 0.125. The output is
  written to FFFF77E0 (CL_target_comp_B_output). When AT/MT flag is set,
  the derivative gain is looked up from a 2D table instead of using the
  fixed 0.025 constant.
""")

print()
print("=" * 90)
print("  PIPELINE CALL ORDER (from dispatcher)")
print("=" * 90)
print("""
  The dispatcher at 0x33304 sequences these calls when CL mode is active:

  1. BSR 0x33D1C  cl_fuel_target_B    -> writes FFFF77E0
  2. BSR 0x33CC0  cl_fuel_target_A    -> writes FFFF77DC (2D table: RPM x Load)
  3. BSR 0x33658  func_33658          -> param FFFF782A, FFFF77C8
  4. BSR 0x33FCE  func_33FCE          -> param FFFF77DC
  5. BSR 0x340A0  func_340A0
  6. BSR 0x342A8  func_342A8
  7. JSR 0x3439E  func_3439E          -> param FFFF781C (AFC_pipeline_result)
  8. JSR 0x343CE  func_343CE
  9. BRA 0x33460  tail-call aggregator

  CL mode gate: RAM[0xFFFF65F0] must match one of four valid mode bytes
  stored at ROM 0xCBBD8-0xCBBDB. If no match, function returns immediately
  without running the pipeline.
""")
