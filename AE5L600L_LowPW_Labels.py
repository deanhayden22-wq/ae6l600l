# AE5L600L_LowPW_Labels.py
# Ghidra script - labels and comments for AE5L600L Low PW Injector Comp analysis
#
# ROM: 2013 USDM Subaru Impreza WRX MT  |  Part: AE5L600L
# MCU: Renesas SH7058 (SH-2A with FPU, big-endian)
#
# HOW TO IMPORT THE ROM IN GHIDRA:
#   File > Import File > "AE5L600L 20g rev 20 tiny wrex.bin"
#   Format:  Raw Binary
#   Language: SuperH:BE:32:SH-2A  (or SuperH4:BE:32:default if SH-2A unavailable)
#   Base Address: 0x00000000
#   After import, add a second memory block for RAM:
#     Window > Memory Map > [+] Add Block
#       Name: RAM, Start: 0xFFFF8000, Length: 0x8000,
#       Initialized: no (uninitialized), Permissions: R/W
#
# HOW TO RUN:
#   Script Manager > [+] Add script directory containing this file
#   Double-click "AE5L600L_LowPW_Labels.py"
#
# @author  AE5L600L analysis
# @category AE5L600L
# @menupath Analysis.AE5L600L.Apply LowPW Labels

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.data import (FloatDataType, ByteDataType, DWordDataType,
                                        ArrayDataType, DataType, UnsignedIntegerDataType,
                                        UnsignedShortDataType)


def addr(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)


def label(offset, name, comment=None, comment_type=CodeUnit.PLATE_COMMENT):
    a = addr(offset)
    st = currentProgram.getSymbolTable()
    # Clear any previous user-defined label at this address
    for sym in list(st.getSymbols(a)):
        if sym.getSource() == SourceType.USER_DEFINED:
            sym.delete()
    st.createLabel(a, name, SourceType.USER_DEFINED)
    if comment:
        set_comment(offset, comment, comment_type)


def set_comment(offset, text, ctype=CodeUnit.PLATE_COMMENT):
    a = addr(offset)
    listing = currentProgram.getListing()
    cu = listing.getCodeUnitAt(a)
    if cu is None:
        cu = listing.getCodeUnitContaining(a)
    if cu:
        cu.setComment(ctype, text)
    else:
        # Address may be in undefined memory - create a byte first
        try:
            listing.createData(a, ByteDataType.dataType)
            cu = listing.getCodeUnitAt(a)
            if cu:
                cu.setComment(ctype, text)
        except Exception:
            pass


def define_floats(offset, count, label_name=None, comment=None):
    """Define 'count' consecutive float32 values starting at offset."""
    listing = currentProgram.getListing()
    dt = FloatDataType.dataType
    for i in range(count):
        a = addr(offset + i * 4)
        try:
            listing.clearCodeUnits(a, a.add(3), False)
            listing.createData(a, dt)
        except Exception:
            pass
    if label_name:
        label(offset, label_name, comment)


def define_bytes(offset, count, label_name=None, comment=None):
    """Define 'count' consecutive byte values starting at offset."""
    listing = currentProgram.getListing()
    dt = ByteDataType.dataType
    for i in range(count):
        a = addr(offset + i)
        try:
            listing.clearCodeUnits(a, a, False)
            listing.createData(a, dt)
        except Exception:
            pass
    if label_name:
        label(offset, label_name, comment)


def define_dwords(offset, count, label_name=None, comment=None):
    """Define 'count' consecutive uint32 values starting at offset."""
    listing = currentProgram.getListing()
    dt = DWordDataType.dataType
    for i in range(count):
        a = addr(offset + i * 4)
        try:
            listing.clearCodeUnits(a, a.add(3), False)
            listing.createData(a, dt)
        except Exception:
            pass
    if label_name:
        label(offset, label_name, comment)


# ─────────────────────────────────────────────────────────────────────────────
# FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

label(0x04346E, "LowPW_GateFunction",
    "Low PW Injector Comp gate function.\n"
    "Checks 6 conditions; if all pass, loads R4=AE000 and tail-calls LowPW_TableProcessor.\n"
    "Conditions (all must be true to apply compensation):\n"
    "  1. FR8 (@FFFF62F8) in range [D2A0C=0.8798, D2D20=100.0)\n"
    "  2. R14 byte from @FFFF5BE3 == 0\n"
    "  3. RAM byte @FFFF80ED == 1\n"
    "  4. FR9 (@FFFF65FC) < D2D24=0.0\n"
    "  5. FR4 (@FFFF6624) >= D2D28 (LowPW_MaxRPM=10000 -> currently disables feature)\n"
    "  6. FR4 (@FFFF6624)  < D2D2C (LowPW_MaxIPW=10000 -> currently disables feature)\n"
    "  7. FR6 (@FFFF6350) >= D2A1C=80.0 (ECT warmup guard)\n"
    "NOTE: With D2D28==D2D2C==10000, conditions 5&6 are mutually exclusive -> feature is\n"
    "permanently disabled in this ROM calibration (all table data is also 0x00).")

label(0x0BE874, "LowPW_TableProcessor",
    "Low PW Injector Comp table processor.\n"
    "Called by LowPW_GateFunction with R4=0x000AE000 (descriptor pointer).\n"
    "  R1 = *(R4+4) = AE004 -> D3988 (IPW Y-axis pointer)\n"
    "  calls sub at 0xBECA8 to do axis lookup\n"
    "  R1 = *(R4+8) = AE008 -> D39A8 (compensation data pointer)\n"
    "  applies interpolated uint8 correction value to current IPW\n"
    "Returns compensation factor to caller.")

label(0x0BECA8, "LowPW_AxisLookup",
    "Axis lookup/interpolation helper called by LowPW_TableProcessor.\n"
    "Input: R1 = pointer to float32 axis array.\n"
    "Performs binary search + linear interpolation on the axis.")

# ─────────────────────────────────────────────────────────────────────────────
# LITERAL POOL for LowPW_GateFunction (at 0x043540)
# ─────────────────────────────────────────────────────────────────────────────

set_comment(0x043540, "Literal pool for LowPW_GateFunction", CodeUnit.PRE_COMMENT)
define_dwords(0x043540, 8)
label(0x043540, "LowPW_LiteralPool_D2A0C",   "-> D2A0C (FR8 lower gate threshold = 0.8798)")
label(0x043544, "LowPW_LiteralPool_D2D20",   "-> D2D20 (FR8 upper gate threshold = 100.0)")
label(0x043548, "LowPW_LiteralPool_D2D24",   "-> D2D24 (FR9 comparison = 0.0)")
label(0x04354C, "LowPW_LiteralPool_D2D28",   "-> D2D28 (LowPW_MaxRPM = 10000.0)")
label(0x043550, "LowPW_LiteralPool_D2D2C",   "-> D2D2C (LowPW_MaxIPW = 10000.0)")
label(0x043554, "LowPW_LiteralPool_D2A1C",   "-> D2A1C (ECT lower bound = 80.0 degC)")
label(0x043558, "LowPW_LiteralPool_AE000",   "-> AE000 (descriptor pointer passed as R4)")
label(0x04355C, "LowPW_LiteralPool_BE874",   "-> BE874 (LowPW_TableProcessor address)")

# ─────────────────────────────────────────────────────────────────────────────
# GATE CONDITION THRESHOLDS (ROM scalars used in comparisons)
# ─────────────────────────────────────────────────────────────────────────────

define_floats(0xD2A0C, 1, "LowPW_GateThresh_FR8_Min",
    "Gate threshold: FR8 lower bound = 0.8798\n"
    "Loaded from @FFFF62F8; bt exits if FR8 < 0.8798.\n"
    "Likely a normalized parameter (lambda, duty-cycle, or similar).")

define_floats(0xD2A1C, 1, "LowPW_GateThresh_ECT_Min",
    "Gate threshold: ECT (coolant temp) lower bound = 80.0 degC\n"
    "Loaded from @FFFF6350 into FR6; bt exits if ECT < 80 degC.\n"
    "Warm-engine guard: compensation only applies after full warm-up.")

define_floats(0xD2D20, 1, "LowPW_GateThresh_FR8_Max",
    "Gate threshold: FR8 upper bound = 100.0\n"
    "bf exits if FR8 >= 100.0.")

define_floats(0xD2D24, 1, "LowPW_GateThresh_FR9_Zero",
    "Gate threshold: FR9 comparison = 0.0\n"
    "Loaded from @FFFF65FC into FR9; bf exits if FR9 >= 0.0.\n"
    "Feature only active when FR9 is negative (meaning unknown).")

define_floats(0xD2D28, 1, "LowPW_MaxRPM",
    "ALPHA Low PW Injector Comp - Maximum RPM scalar.\n"
    "RomRaider table: 'Low pulse width fuel injector compensation maximum RPM'\n"
    "Scaling: RPM (raw = displayed RPM).\n"
    "Current value: 10000.0 RPM (effectively disabled - impossible range with D2D2C).\n"
    "Gate: bt exits if FR4(@FFFF6624) < this value.\n"
    "In a calibrated ROM this would be set lower than D2D2C to create a valid range.")

define_floats(0xD2D2C, 1, "LowPW_MaxIPW",
    "ALPHA Low PW Injector Comp - Maximum IPW scalar.\n"
    "RomRaider table: 'Low pulse width fuel injector compensation maximum IPW'\n"
    "Scaling: BasePulseWidth(ms) (raw x 0.001 = displayed ms).\n"
    "Current value: 10000.0 raw = 10.0 ms displayed (effectively disabled).\n"
    "Gate: bf exits if FR4(@FFFF6624) >= this value.\n"
    "Compensation is active only for FR4 < this threshold.")

# ─────────────────────────────────────────────────────────────────────────────
# AE000 - LOW PW COMP DESCRIPTOR (12-byte header format)
# ─────────────────────────────────────────────────────────────────────────────

label(0xAE000, "LowPW_Comp_Descriptor",
    "Low PW Injector Comp descriptor (12-byte header format).\n"
    "Format: [count(2) | type(2)] [axis_ptr(4)] [data_ptr(4)]\n"
    "  AE000: 0x0008 = element count (8)\n"
    "  AE002: 0x0000 = type flag\n"
    "  AE004: 0x000D3988 -> LowPW_IPW_Axis\n"
    "  AE008: 0x000D39A8 -> LowPW_Comp_Data\n"
    "This pointer (0x000AE000) is passed as R4 to LowPW_TableProcessor.")

set_comment(0xAE000, "count=8, type=0", CodeUnit.EOL_COMMENT)
define_dwords(0xAE000, 3)

label(0xAE004, "LowPW_Comp_Descriptor_AxisPtr",
    "Pointer to LowPW_IPW_Axis (D3988)")
label(0xAE008, "LowPW_Comp_Descriptor_DataPtr",
    "Pointer to LowPW_Comp_Data (D39A8)")

# ─────────────────────────────────────────────────────────────────────────────
# D3988 - IPW Y-AXIS (8 float32 values)
# ─────────────────────────────────────────────────────────────────────────────

define_floats(0xD3988, 8, "LowPW_IPW_Axis",
    "ALPHA Low PW Injector Comp - Y Axis (Injector Pulse Width).\n"
    "RomRaider: 'Injector Pulse Width' axis, elements=8, scaling=BasePulseWidth(ms).\n"
    "Raw values (x 0.001 = displayed ms):\n"
    "  D3988: 700.0  = 0.700 ms\n"
    "  D398C: 800.0  = 0.800 ms\n"
    "  D3990: 900.0  = 0.900 ms\n"
    "  D3994: 1400.0 = 1.400 ms\n"
    "  D3998: 2000.0 = 2.000 ms\n"
    "  D399C: 2500.0 = 2.500 ms\n"
    "  D39A0: 3500.0 = 3.500 ms\n"
    "  D39A4: 4500.0 = 4.500 ms")

set_comment(0xD3988, "0.700 ms", CodeUnit.EOL_COMMENT)
set_comment(0xD398C, "0.800 ms", CodeUnit.EOL_COMMENT)
set_comment(0xD3990, "0.900 ms", CodeUnit.EOL_COMMENT)
set_comment(0xD3994, "1.400 ms", CodeUnit.EOL_COMMENT)
set_comment(0xD3998, "2.000 ms", CodeUnit.EOL_COMMENT)
set_comment(0xD399C, "2.500 ms", CodeUnit.EOL_COMMENT)
set_comment(0xD39A0, "3.500 ms", CodeUnit.EOL_COMMENT)
set_comment(0xD39A4, "4.500 ms", CodeUnit.EOL_COMMENT)

# ─────────────────────────────────────────────────────────────────────────────
# D39A8 - COMPENSATION DATA (8 uint8 values)
# ─────────────────────────────────────────────────────────────────────────────

define_bytes(0xD39A8, 8, "LowPW_Comp_Data",
    "ALPHA Low PW Injector Comp - compensation data (8 x uint8).\n"
    "RomRaider table: 'Low Pulse Width Fuel Injector Compensation'\n"
    "Scaling: InjectorPulseWidthCompensation  (x*0.78125)-100 = displayed %\n"
    "  0x80 (128) =   0.0%  neutral\n"
    "  0x00 (  0) = -100.0% (all current values = 0x00 = FEATURE DISABLED)\n"
    "  0xFF (255) = +99.2%\n"
    "All 8 bytes are currently 0x00 (-100%) -> compensation uncalibrated/disabled.")

set_comment(0xD39A8, "0x00 = -100% (disabled)", CodeUnit.EOL_COMMENT)

# ─────────────────────────────────────────────────────────────────────────────
# RELATED COMP TABLE AXES AND DATA
# ─────────────────────────────────────────────────────────────────────────────

# RPM axis for RPM-indexed IPW comp (ADFD8 entry)
define_floats(0xD3900, 16, "IPWComp_RPM_Axis_16",
    "16-element RPM axis for RPM-indexed IPW comp table (descriptor at ADFD8).\n"
    "Values: [0, 400, 800, 1200, 1600, 2000, 2400, 2800, 3200, 3600, 4000, 4400, 4800, 5200, 5600, 6000]")
define_bytes(0xD3940, 16, "IPWComp_RPM_Data_16",
    "16-element uint8 data for RPM-indexed IPW comp (descriptor at ADFD8).\n"
    "All 0x00 = feature disabled.")

# Gear axis (used by two gear-indexed entries)
define_floats(0xD3950, 5, "IPWComp_Gear_Axis_A",
    "5-element gear axis [1.0, 2.0, 3.0, 4.0, 5.0] for gear-indexed comp.\n"
    "Descriptor at ADFE8 (12-byte format): axis=D3950, data=D3964.")
define_bytes(0xD3964, 5, "IPWComp_Gear_Data_A",
    "5-element uint8 data for gear-indexed comp #1 (descriptor at ADFE8).\n"
    "All 0x00 = disabled. Followed by 3 padding bytes to D396C.")

define_floats(0xD396C, 5, "IPWComp_Gear_Axis_B",
    "5-element gear axis [1.0, 2.0, 3.0, 4.0, 5.0] for gear-indexed comp.\n"
    "Descriptor at ADFF4 (12-byte format): axis=D396C, data=D3980.")
define_bytes(0xD3980, 5, "IPWComp_Gear_Data_B",
    "5-element uint8 data for gear-indexed comp #2 (descriptor at ADFF4).\n"
    "All 0x00 = disabled. Followed by 3 padding bytes before LowPW_IPW_Axis at D3988.")

# 6-element IPW axis [440-760] (ADDBC entry)
define_floats(0xD33AC, 6, "IPWComp_IPW_Axis_6_A",
    "6-element IPW axis for comp descriptor at ADDBC.\n"
    "Values (raw, x0.001=ms): [440, 504, 568, 632, 696, 760] = [0.44 - 0.76 ms]")
define_bytes(0xD33C4, 6, "IPWComp_IPW_Data_6_A",
    "6-element uint8 data for comp descriptor at ADDBC.\n"
    "All 0x80 = 0% correction (neutral).")

# 7-element IPW axis [500-3200] (ADDE4 entry)
define_floats(0xD33F0, 7, "IPWComp_IPW_Axis_7_B",
    "7-element IPW axis for comp descriptor at ADDE4.\n"
    "Values (raw): [500, 1000, 1500, 2000, 2400, 2800, 3200] = [0.5 - 3.2 ms]")
define_bytes(0xD340C, 7, "IPWComp_IPW_Data_7_B",
    "7-element uint8 data for comp descriptor at ADDE4.\n"
    "Values: [0x00, 0x40, 0x80, 0x80, 0x80, 0x80, 0x80]\n"
    "  0x00 = -100% at 0.5ms, 0x40 = -50% at 1.0ms, 0x80 = 0% above 1.5ms")

# 7-element axis [0-30] (ADDD0 entry)
define_floats(0xD33CC, 7, "IPWComp_Axis_7_C",
    "7-element axis for comp descriptor at ADDD0.\n"
    "Values: [0.0, 5.0, 10.0, 15.0, 20.0, 25.0, 30.0]")
define_bytes(0xD33E8, 7, "IPWComp_Data_7_C",
    "7-element uint8 data for comp descriptor at ADDD0. All 0x80 = neutral.")

# ─────────────────────────────────────────────────────────────────────────────
# DESCRIPTOR ARRAY (ADD00 region - 20-byte format entries)
# ─────────────────────────────────────────────────────────────────────────────

set_comment(0xADD80, "Descriptor array region - 20-byte entries [axis_ptr][data_ptr][scale][bias][dims]",
    CodeUnit.PLATE_COMMENT)

label(0xADD94, "IPWComp_Desc_ECT_A",
    "20-byte descriptor: ECT-indexed IPW comp #1.\n"
    "axis=D2FCC (16-elem ECT axis -40..110 degC), data=D338A, scale=0.78125, bias=-100, dims=0x00100400")
define_dwords(0xADD94, 5)

label(0xADDA8, "IPWComp_Desc_ECT_B",
    "20-byte descriptor: ECT-indexed IPW comp #2.\n"
    "axis=D2FCC (16-elem ECT axis), data=D339A (6 bytes), scale=0.78125, bias=-100, dims=0x00060400")
define_dwords(0xADDA8, 5)

label(0xADDBC, "IPWComp_Desc_IPW_6",
    "20-byte descriptor: IPW-indexed comp 6-element.\n"
    "axis=D33AC [440-760 raw = 0.44-0.76ms], data=D33C4 (all 0x80), scale=0.0078125, dims=0x00060400")
define_dwords(0xADDBC, 5)

label(0xADDD0, "IPWComp_Desc_7_C",
    "20-byte descriptor: comp indexed by 7-element [0-30] axis.\n"
    "axis=D33CC [0,5,10,15,20,25,30], data=D33E8 (all 0x80), scale=0.0078125, dims=0x00070400")
define_dwords(0xADDD0, 5)

label(0xADDE4, "IPWComp_Desc_IPW_7_B",
    "20-byte descriptor: IPW-indexed comp 7-element with non-trivial data.\n"
    "axis=D33F0 [500-3200 raw], data=D340C [0x00,0x40,0x80...], scale=0.0078125, dims=0x00070400")
define_dwords(0xADDE4, 5)

label(0xADDF8, "IPWComp_Desc_IPW_22",
    "20-byte descriptor: IPW-indexed comp 22-element.\n"
    "axis=D3414, data=D3430 (all 0x80), scale=0.0078125, dims=0x00160400")
define_dwords(0xADDF8, 5)

label(0xADF38, "IPWComp_Desc_ECT_C",
    "20-byte descriptor: ECT-indexed IPW comp #3.\n"
    "axis=D2F8C (16-elem ECT axis), data=D3690, scale=0.0078125, dims=0x00100400")
define_dwords(0xADF38, 5)

label(0xADF4C, "IPWComp_Desc_ECT_D",
    "20-byte descriptor: ECT-indexed IPW comp #4.\n"
    "axis=D2F8C (16-elem ECT axis), data=D36A0, scale=0.0078125, dims=0x00150400")
define_dwords(0xADF4C, 5)

label(0xADFC4, "IPWComp_Desc_TimingECT",
    "20-byte descriptor: Timing compensation (ECT-indexed).\n"
    "axis=D38B0, data=D38F0, scale=0.3515625, bias=-20.0, dims=0x00100400")
define_dwords(0xADFC4, 5)

label(0xADFD8, "IPWComp_Desc_RPM_16",
    "20-byte descriptor: RPM-indexed IPW comp 16-element.\n"
    "axis=D3900 [0,400,800,...,6000 RPM], data=D3940 (all 0x00), scale=0.0078125, dims=0x00050000")
define_dwords(0xADFD8, 5)

# 12-byte format entries
label(0xADFE8, "IPWComp_Desc_Gear_A",
    "12-byte descriptor (AE-format): gear-indexed comp #1.\n"
    "Format: [count(4)=5][axis_ptr(4)=D3950][data_ptr(4)=D3964]\n"
    "axis=D3950 [1,2,3,4,5 gears], data=D3964 (5 zeros)")
define_dwords(0xADFE8, 3)

label(0xADFF4, "IPWComp_Desc_Gear_B",
    "12-byte descriptor (AE-format): gear-indexed comp #2.\n"
    "Format: [count(4)=5][axis_ptr(4)=D396C][data_ptr(4)=D3980]\n"
    "axis=D396C [1,2,3,4,5 gears], data=D3980 (5 zeros)")
define_dwords(0xADFF4, 3)

# ─────────────────────────────────────────────────────────────────────────────
# RAM / PERIPHERAL ADDRESSES (in RAM block 0xFFFF8000-0xFFFFFFFF)
# ─────────────────────────────────────────────────────────────────────────────

label(0xFFFF62F8, "RAM_LowPW_Param_FR8",
    "RAM: Peripheral float loaded into FR8 by LowPW_GateFunction.\n"
    "Must be in range [0.8798, 100.0) for compensation to activate.\n"
    "Likely: normalized engine parameter (lambda, duty cycle, or similar).")

label(0xFFFF65FC, "RAM_LowPW_Param_FR9",
    "RAM: Peripheral float loaded into FR9 by LowPW_GateFunction.\n"
    "Must be < 0.0 for compensation to activate.\n"
    "Likely: a signed correction/feedback term.")

label(0xFFFF6624, "RAM_LowPW_Param_FR4",
    "RAM: Peripheral float loaded into FR4 by LowPW_GateFunction.\n"
    "Compared against LowPW_MaxRPM (D2D28) and LowPW_MaxIPW (D2D2C).\n"
    "With both thresholds = 10000.0 the feature is permanently disabled.\n"
    "In a calibrated ROM this would be IPW or RPM in appropriate raw units.")

label(0xFFFF6350, "RAM_LowPW_Param_FR6_ECT",
    "RAM: Peripheral float loaded into FR6 by LowPW_GateFunction.\n"
    "Must be >= 80.0 (LowPW_GateThresh_ECT_Min).\n"
    "Likely: Engine Coolant Temperature in degrees Celsius.")

label(0xFFFF5BE3, "RAM_LowPW_Flag_R14",
    "RAM: Byte flag loaded into R14 by LowPW_GateFunction.\n"
    "tst R14,R14 / bf -> exits if non-zero.\n"
    "Must be 0 for compensation to activate.")

label(0xFFFF80EC, "RAM_LowPW_FlagArea",
    "RAM: Flag area checked by LowPW_GateFunction.\n"
    "Byte at offset +1 (0xFFFF80ED) must equal 0x01.")
label(0xFFFF80ED, "RAM_LowPW_Flag_80ED",
    "RAM: Must == 0x01 for LowPW compensation to activate.")

# ─────────────────────────────────────────────────────────────────────────────
# ECT AXES (referenced by multiple comp descriptors)
# ─────────────────────────────────────────────────────────────────────────────

define_floats(0xD2FCC, 16, "ECT_Axis_16_D2FCC",
    "16-element Engine Coolant Temperature axis [-40..110 degC, step 10].\n"
    "Used by IPWComp_Desc_ECT_A (ADD94) and IPWComp_Desc_ECT_B (ADDA8).")

define_floats(0xD2F8C, 16, "ECT_Axis_16_D2F8C",
    "16-element Engine Coolant Temperature axis [-40..110 degC, step 10].\n"
    "Used by IPWComp_Desc_ECT_C (ADF38) and IPWComp_Desc_ECT_D (ADF4C).")

# ECT comp data arrays
define_bytes(0xD338A, 16, "IPWComp_ECT_Data_A",
    "16-element uint8 data for ECT-indexed comp (descriptor at ADD94).\n"
    "InjectorPulseWidthCompensation: (x*0.78125)-100 = %\n"
    "  -40..30 degC: 0x80 = 0% (neutral)\n"
    "  40 degC: 0x73 = -10.2%  50 degC: 0x6D = -14.8%\n"
    "  60 degC: 0x66 = -20.3%  70..110 degC: 0x60 = -25.0%\n"
    "Interpretation: at warm ECT, IPW comp is reduced.")

define_bytes(0xD339A, 6, "IPWComp_ECT_Data_B",
    "6-element uint8 data for ECT-indexed comp #2 (descriptor at ADDA8).\n"
    "All 0x80 = 0% (neutral).")

define_bytes(0xD3690, 16, "IPWComp_ECT_Data_C",
    "16-element uint8 data for ECT-indexed comp #3 (descriptor at ADF38).\n"
    "InjectorPulseWidthCompensation scaling:\n"
    "  -40..30 degC: 0x26 = -70.3%  (heavy cold-start correction)\n"
    "  40 degC: 0x26=-70.3%  50: 0x33=-60.2%  60: 0x40=-50.0%  70: 0x60=-25.0%\n"
    "  80..110 degC: 0x80 = 0% (neutral, warm engine)")

define_bytes(0xD36A0, 16, "IPWComp_ECT_Data_D",
    "16-element uint8 data for ECT-indexed comp #4 (descriptor at ADF4C).\n"
    "Same cold-start correction profile as IPWComp_ECT_Data_C:\n"
    "  -40..30 degC: -70.3%, grading to 0% at 80+ degC.")

print("AE5L600L Low PW labels applied successfully.")
print("")
print("Summary of key addresses:")
print("  LowPW_GateFunction   @ 0x04346E")
print("  LowPW_TableProcessor @ 0x0BE874")
print("  LowPW_MaxRPM scalar  @ 0x0D2D28  (= 10000 RPM, currently disabled)")
print("  LowPW_MaxIPW scalar  @ 0x0D2D2C  (= 10000 raw = 10.0ms, currently disabled)")
print("  LowPW_IPW_Axis       @ 0x0D3988  (8-elem float: 700-4500 raw = 0.7-4.5ms)")
print("  LowPW_Comp_Data      @ 0x0D39A8  (8 uint8, all 0x00 = feature uncalibrated)")
print("  LowPW_Comp_Descriptor@ 0x0AE000  (12-byte header: count=8, axis->D3988, data->D39A8)")
