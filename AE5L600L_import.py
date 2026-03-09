# AE5L600L_import.py
# Ghidra import script for 2013 USDM Subaru WRX ECU ROM
# ROM: AE5L600L rev 20.x (tiny_wrex build)
# Architecture: SH-2 / SH-2E, big-endian, 1MB (0x100000)
#
# HOW TO USE:
#   1. In Ghidra, create a new project
#   2. Import the .bin as a Raw Binary:
#        Language: SH-2 (Hitachi) -> SH2 (big-endian)
#        Base address: 0x00000000
#   3. Open the imported file in CodeBrowser
#   4. Script Manager -> Run Script -> select this file
#
# The script will:
#   - Apply all known symbols (labels + comments)
#   - Mark the patch region as code vs data
#   - Add plate comments summarizing each region

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import (
    DataType, FloatDataType, DWordDataType, WordDataType, ByteDataType,
    ArrayDataType
)
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.address import AddressSet

def addr(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

def label(offset, name, comment=None):
    a = addr(offset)
    sym = currentProgram.getSymbolTable().createLabel(a, name, SourceType.USER_DEFINED)
    if comment:
        setPlateComment(a, comment)

def line_comment(offset, text):
    setEOLComment(addr(offset), text)

def pre_comment(offset, text):
    setPreComment(addr(offset), text)

def plate_comment(offset, text):
    setPlateComment(addr(offset), text)

def apply_float(offset, name):
    """Label an address and mark it as float32"""
    a = addr(offset)
    clearListing(a, a.add(3))
    createData(a, FloatDataType.dataType)
    label(offset, name)

def apply_u32(offset, name):
    a = addr(offset)
    clearListing(a, a.add(3))
    createData(a, DWordDataType.dataType)
    label(offset, name)

monitor.setMessage("AE5L600L: Applying symbols...")

# ============================================================
# RESET VECTORS (SH-2 vector table at 0x00000000)
# ============================================================
plate_comment(0x000000, "SH-2 Reset Vector Table")
apply_u32(0x000000, "VEC_RESET_SP")     # Initial stack pointer = 0x00000C0C
apply_u32(0x000004, "VEC_RESET_PC")     # Reset PC = 0xFFFFBFA0 (mapped to ROM)
line_comment(0x000000, "Initial SP = 0x00000C0C")
line_comment(0x000004, "Reset PC = 0xFFFFBFA0")

# ============================================================
# REV LIMITER TABLE @ CC500
# ============================================================
plate_comment(0x0CC500,
    "Rev Limiter On/Off Values\n"
    "Float32 pairs: [On, Off] per gear group\n"
    "Stock: On=6700 RPM, Off=6680 RPM\n"
    "LC/FFS patch reads CC500 as base rev limit")
apply_float(0x0CC500, "RevLimit_On_Stock")
apply_float(0x0CC504, "RevLimit_Off_Stock")
line_comment(0x0CC500, "6700.0 RPM fuel cut ON")
line_comment(0x0CC504, "6680.0 RPM fuel cut OFF")

# ============================================================
# LC/FFS PATCH REGION @ F1000-F105F
# ============================================================
plate_comment(0x0F1000,
    "tinywrex LC/FFS Patch - Injected Code\n"
    "Launch Control + Flat Foot Shift patch by tinywrex\n"
    "Hooked from original rev limiter function at 0x3B6AE (Path A) and 0x3B6B8 (Path B)\n"
    "Returns to 0x3B6B2\n"
    "\n"
    "Logic:\n"
    "  1. Load vehicle speed from FFFF65FC\n"
    "  2. Load speed threshold from F104C\n"
    "  3. Read clutch state from FFFF65D0 (1 = pressed)\n"
    "  4. If clutch==1 AND speed < threshold: LC mode -> use F1050 delta\n"
    "  5. If clutch==1 AND speed >= threshold: FFS mode -> use F1054 delta\n"
    "  6. If clutch==0 AND speed > threshold: normal -> use F1048 (should be 0.0)\n"
    "  7. Add selected delta to FR15 (current RPM) -> adjusts effective rev limit\n"
    "  8. JMP back to 0x3B6B2")

label(0x0F1000, "Patch_LC_FFS_Entry",
    "Entry point for LC/FFS patch\nCalled via JMP from 0x3B6AE and 0x3B6B8")

# Patch code labels
label(0x0F1000, "Patch_LoadVehicleSpeed")
line_comment(0x0F1000, "R0 = ptr to FFFF65FC (vehicle speed)")
line_comment(0x0F1002, "FR9 = float(vehicle speed)")
line_comment(0x0F1004, "R0 -> F104C (LC speed threshold)")
line_comment(0x0F1006, "FR6 = speed threshold")
line_comment(0x0F1008, "R0 = ptr to FFFF65D0 (clutch switch register)")
line_comment(0x0F100A, "R0 = clutch state byte")
line_comment(0x0F100C, "T = (clutch == 1)")
line_comment(0x0F100E, "if T==0 (clutch NOT pressed): branch to F101E")
line_comment(0x0F1012, "clutch pressed: FR6 = float from inherited R9 (speed comparison prep)")
line_comment(0x0F1014, "BT/S: if T==1 (still set from CMP) goto F1024 (LC path)")
label(0x0F1018, "Patch_FFS_Path")
line_comment(0x0F1018, "FFS path: R0 -> F1054 (FFS RPM delta)")
line_comment(0x0F101A, "BRA to F102C (common delta load)")
label(0x0F101E, "Patch_NoClutch_Path")
line_comment(0x0F101E, "no-clutch: FR9 = float from inherited R6")
line_comment(0x0F1020, "BT/S: T==0 here, never branches")
label(0x0F1024, "Patch_LC_Path")
line_comment(0x0F1024, "LC path: R0 -> F1050 (LC RPM delta)")
line_comment(0x0F1026, "BRA to F102C")
label(0x0F102A, "Patch_NormalDriving_Path")
line_comment(0x0F102A, "normal driving: R0 -> F1048 (should be 0.0)")
label(0x0F102C, "Patch_ApplyDelta")
line_comment(0x0F102C, "FR8 = selected RPM delta")
line_comment(0x0F102E, "FR15 += FR8  (adjust effective RPM vs rev limit)")
line_comment(0x0F1030, "R2 = 0x000CC500 (Rev Limit On address)")
line_comment(0x0F1032, "R0 = 0x0003B6B2 (return address)")
line_comment(0x0F1034, "JMP @R0 -> return to caller")
line_comment(0x0F1036, "delay slot: FR8 = RevLimit_On value (6700 RPM)")

# Patch literal pool
plate_comment(0x0F1038, "Patch Literal Pool")
apply_u32(0x0F1038, "Patch_Ptr_VehicleSpeedReg")
line_comment(0x0F1038, "-> FFFF65FC (vehicle speed RAM register)")
apply_u32(0x0F103C, "Patch_Ptr_ClutchReg")
line_comment(0x0F103C, "-> FFFF65D0 (clutch switch RAM register)")
apply_u32(0x0F1040, "Patch_ReturnAddr")
line_comment(0x0F1040, "-> 0x0003B6B2 (return into original rev limiter function)")
apply_u32(0x0F1044, "Patch_Ptr_RevLimitOn")
line_comment(0x0F1044, "-> 0x000CC500 (Rev Limit On table address)")

# Patch parameters
plate_comment(0x0F1048,
    "LC/FFS Patch Tunable Parameters\n"
    "All float32 big-endian\n"
    "Edit via EcuFlash XML (AE5L600L_2013_USDM_Impreza_WRX_MT.xml)")
apply_float(0x0F1048, "Param_NormalDriving_RPM_Delta")
line_comment(0x0F1048, "Delta when clutch-up + high speed. Should be 0.0 for stock behavior.")
apply_float(0x0F104C, "Param_LC_SpeedThreshold_KPH")
line_comment(0x0F104C, "Speed below which LC is active (kph). ~8.05 kph = ~5 mph")
apply_float(0x0F1050, "Param_LC_RPM_Delta")
line_comment(0x0F1050, "LC rev reduction delta. 2700.0 -> cut = 6700-2700 = 4000 RPM")
apply_float(0x0F1054, "Param_FFS_RPM_Delta")
line_comment(0x0F1054, "FFS rev reduction delta. 2000.0 -> cut = 6700-2000 = 4700 RPM")

# ============================================================
# HOOK SITES in original rev limiter function
# ============================================================
plate_comment(0x03B6AE,
    "LC/FFS Hook Site A\n"
    "Original instruction replaced with JMP to patch at F1000\n"
    "Delay slot: MOV.L -> R2 = 0x000CC504 (Rev Limit Off addr)\n"
    "Path taken when R2 != 0 (gear group 1)")
label(0x03B6AE, "Hook_A_JMP_to_Patch")
line_comment(0x03B6AE, "D03B = MOV.L @(PC+offset),R0 -> R0=0x000F1000")
line_comment(0x03B6B0, "402B = JMP @R0  (-> Patch_LC_FFS_Entry)")

plate_comment(0x03B6B2,
    "LC/FFS Patch Return Point\n"
    "Patch JMPs back here after adjusting FR15\n"
    "Continues with: load FR6=RevLimit_Off, hysteresis comparison")
label(0x03B6B2, "Patch_Return_Point")

plate_comment(0x03B6B8,
    "LC/FFS Hook Site B\n"
    "Original instruction replaced with JMP to patch at F1000\n"
    "Path taken when R2 == 0 (gear group 2)")
label(0x03B6B8, "Hook_B_JMP_to_Patch")

# ============================================================
# CHECKSUM VERIFICATION TABLE @ FFB80
# ============================================================
plate_comment(0x0FFB80,
    "ROM Checksum Verification Table\n"
    "Header: [count(4)][start_addr(4)]\n"
    "Entries: [checksum(4)][range_lo(4)][range_hi(4)] x N\n"
    "ECU verifies ROM integrity at startup by checking these ranges\n"
    "Entry 0 checksum at FFB88 is patched when using tinywrex patch\n"
    "Magic constant: 0x5AA5A55A")
label(0x0FFB80, "Checksum_Table_Header")
apply_u32(0x0FFB80, "Checksum_Table_Count")
apply_u32(0x0FFB84, "Checksum_Table_StartAddr")

label(0x0FFB88, "Checksum_Entry_0")
line_comment(0x0FFB88, "Entry 0: range 0x000BB400-0x000BBEFF (patched for tinywrex)")
label(0x0FFB94, "Checksum_Entry_1")
line_comment(0x0FFB94, "Entry 1: range 0x000BBF00-0x000BC9FF")
label(0x0FFBA0, "Checksum_Entry_2")
line_comment(0x0FFBA0, "Entry 2: range 0x000BCA00-0x000BD4FF")
label(0x0FFBAC, "Checksum_Entry_3")
label(0x0FFBB8, "Checksum_Entry_4")
label(0x0FFBC4, "Checksum_Entry_5")
label(0x0FFBD0, "Checksum_Entry_6")
label(0x0FFBDC, "Checksum_Entry_7")

# ============================================================
# KNOWN RAM REGISTERS (SH-2 external address space)
# These are at FFFF6xxx - not in the ROM file, but referenced by patch code
# ============================================================
# Can't create labels outside ROM address range in a raw binary import,
# but we document them here for reference:
pre_comment(0x0F1038,
    "RAM Registers (FFFF6xxx - not in ROM file):\n"
    "  FFFF65FC = Vehicle Speed (float32)\n"
    "  FFFF65D0 = Clutch Switch (byte, 1=pressed)\n"
    "  FFFF6620 = Engine RPM (float32, loaded into FR15 before hooks)")

# ============================================================
# TORQUE MAP REGION @ F99E0, F9C60
# ============================================================
plate_comment(0x0F99E0,
    "Requested Torque Map - SI-DRIVE Sport\n"
    "3D table: Accelerator Pedal % (X) vs Engine Speed RPM (Y)\n"
    "From EcuFlash XML: address=f99e0")
label(0x0F99E0, "Table_RequestedTorque_SIDrive_Sport")

plate_comment(0x0F9C60,
    "Requested Torque Map - SI-DRIVE Sport Sharp\n"
    "3D table: Accelerator Pedal % (X) vs Engine Speed RPM (Y)\n"
    "From EcuFlash XML: address=f9c60")
label(0x0F9C60, "Table_RequestedTorque_SIDrive_SportSharp")

# ============================================================
# FUEL INJECTOR TRIM TABLE @ CD058 / CD078
# ============================================================
plate_comment(0x0CD058,
    "Fuel Injector Trim Small IFW - RPM Axis\n"
    "8 elements, float32 big-endian\n"
    "Values: ~300, 350, 400, 450, 500, 550, 600, 650 RPM")
label(0x0CD058, "Axis_FuelInjTrimSmall_RPM")

plate_comment(0x0CD078,
    "Fuel Injector Trim Small IFW - Data\n"
    "8 x uint8, scaling: x/128 = multiplier\n"
    "Stock values: ~1.266, 1.164, 1.102, 1.055, 1.023, 1.008, 1.000, 1.000\n"
    "Clamped externally to [0.5, 1.5]")
label(0x0CD078, "Table_FuelInjTrimSmall_IFW")

# ============================================================
# Disassemble the patch code
# ============================================================
monitor.setMessage("AE5L600L: Disassembling patch code...")
patch_start = addr(0x0F1000)
patch_end   = addr(0x0F1037)
patch_set   = AddressSet(patch_start, patch_end)
cmd = DisassembleCommand(patch_set, None, True)
cmd.applyTo(currentProgram, monitor)

# Also disassemble the hook sites
for hook_addr in [0x03B6AE, 0x03B6B0, 0x03B6B2, 0x03B6B8, 0x03B6BA]:
    DisassembleCommand(
        AddressSet(addr(hook_addr), addr(hook_addr + 1)), None, True
    ).applyTo(currentProgram, monitor)

monitor.setMessage("AE5L600L: Done!")
print("AE5L600L import script complete.")
print("Symbols applied:")
print("  - Reset vectors @ 0x000000")
print("  - Rev limiter table @ 0xCC500")
print("  - LC/FFS patch code + params @ 0xF1000-0xF1057")
print("  - Hook sites @ 0x3B6AE, 0x3B6B8")
print("  - Checksum table @ 0xFFB80")
print("  - Torque maps @ 0xF99E0, 0xF9C60")
print("  - Fuel injector trim table @ 0xCD058/0xCD078")
print("")
print("NOTE: RAM registers (FFFF65xx) are not in ROM address space.")
print("They are documented in pre-comments on the patch literal pool.")
