#!/usr/bin/env python3
"""
AE5L600L MerpMod SD-Only ROM Patcher
=====================================
Directly patches a stock/tuned ROM with MerpMod Speed Density code.
No HEW compiler or SharpTune needed — hand-assembled SH-2 machine code.

All addresses verified from ROM binary bytes (2026-04-04).

Usage: python patch_rom.py <input_rom> [output_rom]
"""

import struct
import sys
import os

# =============================================================================
# ROM ADDRESSES (verified from AE5L600L.h and ROM binary)
# =============================================================================

ROM_SIZE            = 0x100000   # 1 MB
ROM_HOLE_START      = 0x0DAE8C   # Start of free space (verified 0xFF)
RAM_HOLE_START      = 0xFFFFC000 # MerpMod RAM workspace

# Hook points (literal pool entries patched)
HOOK_MEMORY_RESET   = 0x000D64   # Literal pool: was 0x065C → Initializer
HOOK_MAF_CALC       = 0x004A88   # Literal pool: was 0xBE830 → ComputeMassAirFlow
ORIG_MEMORY_RESET   = 0x0000065C # OEM RTOS startup
ORIG_PULL2D_FLOAT   = 0x000BE830 # table_desc_1d_float
ORIG_PULL3D_FLOAT   = 0x000BE8E4 # table_desc_2d_typed

# Engine parameter RAM pointers (all verified against ram_reference.txt)
P_ENGINE_SPEED      = 0xFFFF6624 # rpm_current (301 refs)
P_VEHICLE_SPEED     = 0xFFFF61CC # vehicle_speed (56 refs)
P_COOLANT_TEMP      = 0xFFFF6350 # ect_current (205 refs)
P_ATMO_PRESS        = 0xFFFF67EC # atm_pressure_current (99 refs) — CORRECTED
P_MAP               = 0xFFFF6898 # manifold_pressure (48 refs)
P_IAT               = 0xFFFF63F8 # iat_current (86 refs)
P_MAF               = 0xFFFF6254 # maf_current (51 refs)
P_MAF_VOLTAGE       = 0xFFFF4042 # raw MAF ADC (ADDR15)
P_ENGINE_LOAD       = 0xFFFF65FC # engine_load_current (135 refs)
P_THROTTLE          = 0xFFFF65C0 # throttle_position (89 refs)

# ECU identifiers
D_ECU_ID            = 0x00002004 # ECU identifier in ROM

# RamVariables struct offsets (SDOnly config)
RV_RAM_VARIABLE_START       = 0x00
RV_VIN_AUTH                 = 0x01
RV_ECU_IDENTIFIER           = 0x04  # unsigned long (4 bytes)
RV_HARD_RESET_FLAG          = 0x08
RV_SD_INIT_FLAG             = 0x0C
RV_MAF_MODE                 = 0x0D
RV_VOLUMETRIC_EFFICIENCY    = 0x10  # float
RV_MAF_FROM_SD              = 0x14  # float
RV_MAF_FROM_SENSOR          = 0x18  # float
RV_ATM_COMPENSATION         = 0x1C  # float
RV_DELTA_MAP_COMP           = 0x20  # float
RV_SD_MAF_BLEND_RATIO       = 0x24  # float
RV_SD_MAF_FROM_BLEND        = 0x28  # float
RV_RAM_HOLE_SPACE           = 0x2C
RV_RAM_HOLE_END_MARKER      = 0x30
RV_STRUCT_SIZE              = 0x31  # 49 bytes total

# MafMode enum values
MAF_MODE_SENSOR       = 0x01
MAF_MODE_SD           = 0x02
MAF_MODE_BLENDING     = 0x03

# =============================================================================
# SH-2 INSTRUCTION ENCODER
# =============================================================================

def be16(val):
    """Encode 16-bit value as big-endian bytes."""
    return struct.pack('>H', val & 0xFFFF)

def be32(val):
    """Encode 32-bit value as big-endian bytes."""
    return struct.pack('>I', val & 0xFFFFFFFF)

def float_bytes(val):
    """Encode float as big-endian IEEE 754."""
    return struct.pack('>f', val)

# --- Core SH-2 instruction encoders ---

def SH_NOP():
    return 0x0009

def SH_RTS():
    return 0x000B

def SH_MOV_IMM(imm8, rn):
    """MOV #imm8, Rn — sign-extended 8-bit immediate"""
    return 0xE000 | ((rn & 0xF) << 8) | (imm8 & 0xFF)

def SH_MOV_L_DISP_PC(disp8, rn):
    """MOV.L @(disp,PC), Rn — load from literal pool"""
    return 0xD000 | ((rn & 0xF) << 8) | (disp8 & 0xFF)

def SH_MOVA(disp8):
    """MOVA @(disp,PC), R0 — load address from literal pool"""
    return 0xC700 | (disp8 & 0xFF)

def SH_MOV_L_AT_RM(rm, rn):
    """MOV.L @Rm, Rn"""
    return 0x6002 | ((rn & 0xF) << 8) | ((rm & 0xF) << 4)

def SH_MOV_L_RM_AT_RN(rm, rn):
    """MOV.L Rm, @Rn"""
    return 0x2002 | ((rn & 0xF) << 8) | ((rm & 0xF) << 4)

def SH_MOV_L_RM_PREDEC(rm, rn):
    """MOV.L Rm, @-Rn (push)"""
    return 0x2006 | ((rn & 0xF) << 8) | ((rm & 0xF) << 4)

def SH_MOV_L_POSTINC(rm, rn):
    """MOV.L @Rm+, Rn (pop)"""
    return 0x6006 | ((rn & 0xF) << 8) | ((rm & 0xF) << 4)

def SH_MOV_B_AT_DISP_RN_R0(disp4, rn):
    """MOV.B @(disp,Rn), R0 — load byte with 4-bit displacement"""
    return 0x8400 | ((rn & 0xF) << 4) | (disp4 & 0xF)

def SH_MOV_B_R0_AT_DISP_RN(disp4, rn):
    """MOV.B R0, @(disp,Rn) — store byte with 4-bit displacement"""
    return 0x8000 | ((rn & 0xF) << 4) | (disp4 & 0xF)

def SH_MOV_B_RM_AT_RN(rm, rn):
    """MOV.B Rm, @Rn"""
    return 0x2000 | ((rn & 0xF) << 8) | ((rm & 0xF) << 4)

def SH_EXTU_B(rm, rn):
    """EXTU.B Rm, Rn — zero-extend byte"""
    return 0x600C | ((rn & 0xF) << 8) | ((rm & 0xF) << 4)

def SH_ADD_IMM(imm8, rn):
    """ADD #imm8, Rn — sign-extended 8-bit immediate"""
    return 0x7000 | ((rn & 0xF) << 8) | (imm8 & 0xFF)

def SH_ADD(rm, rn):
    """ADD Rm, Rn"""
    return 0x300C | ((rn & 0xF) << 8) | ((rm & 0xF) << 4)

def SH_CMP_EQ_IMM(imm8):
    """CMP/EQ #imm8, R0"""
    return 0x8800 | (imm8 & 0xFF)

def SH_CMP_GE(rm, rn):
    """CMP/GE Rm, Rn — signed Rn >= Rm"""
    return 0x3003 | ((rn & 0xF) << 8) | ((rm & 0xF) << 4)

def SH_BT(disp8):
    """BT disp — branch if T=1, PC + 4 + disp*2"""
    return 0x8900 | (disp8 & 0xFF)

def SH_BF(disp8):
    """BF disp — branch if T=0, PC + 4 + disp*2"""
    return 0x8B00 | (disp8 & 0xFF)

def SH_BRA(disp12):
    """BRA disp — unconditional, PC + 4 + disp*2 (12-bit signed)"""
    return 0xA000 | (disp12 & 0xFFF)

def SH_JSR(rn):
    """JSR @Rn"""
    return 0x400B | ((rn & 0xF) << 8)

def SH_STS_L_PR_PREDEC(rn):
    """STS.L PR, @-Rn — save return address to stack"""
    return 0x4022 | ((rn & 0xF) << 8)

def SH_LDS_L_POSTINC_PR(rn):
    """LDS.L @Rn+, PR — restore return address from stack"""
    return 0x4026 | ((rn & 0xF) << 8)

# --- FPU instructions ---

def SH_FMOV_S_AT_RM(rm, frn):
    """FMOV.S @Rm, FRn — load float from address in Rm"""
    return 0xF008 | ((frn & 0xF) << 8) | ((rm & 0xF) << 4)

def SH_FMOV_S_FRM_AT_RN(frm, rn):
    """FMOV.S FRm, @Rn — store float to address in Rn"""
    return 0xF00A | ((rn & 0xF) << 8) | ((frm & 0xF) << 4)

def SH_FMOV_S_AT_R0_RM(rm, frn):
    """FMOV.S @(R0,Rm), FRn — load float from R0+Rm"""
    return 0xF006 | ((frn & 0xF) << 8) | ((rm & 0xF) << 4)

def SH_FMOV_S_FRM_AT_R0_RN(frm, rn):
    """FMOV.S FRm, @(R0,Rn) — store float to R0+Rn"""
    return 0xF007 | ((rn & 0xF) << 8) | ((frm & 0xF) << 4)

def SH_FMOV_S_FRM_PREDEC(frm, rn):
    """FMOV.S FRm, @-Rn — push float to stack"""
    return 0xF00B | ((rn & 0xF) << 8) | ((frm & 0xF) << 4)

def SH_FMOV_S_POSTINC(rm, frn):
    """FMOV.S @Rm+, FRn — pop float from stack"""
    return 0xF009 | ((frn & 0xF) << 8) | ((rm & 0xF) << 4)

def SH_FMOV(frm, frn):
    """FMOV FRm, FRn — copy float register"""
    return 0xF00C | ((frn & 0xF) << 8) | ((frm & 0xF) << 4)

def SH_FADD(frm, frn):
    """FADD FRm, FRn — FRn = FRn + FRm"""
    return 0xF000 | ((frn & 0xF) << 8) | ((frm & 0xF) << 4)

def SH_FSUB(frm, frn):
    """FSUB FRm, FRn — FRn = FRn - FRm"""
    return 0xF001 | ((frn & 0xF) << 8) | ((frm & 0xF) << 4)

def SH_FMUL(frm, frn):
    """FMUL FRm, FRn — FRn = FRn * FRm"""
    return 0xF002 | ((frn & 0xF) << 8) | ((frm & 0xF) << 4)

def SH_FDIV(frm, frn):
    """FDIV FRm, FRn — FRn = FRn / FRm"""
    return 0xF003 | ((frn & 0xF) << 8) | ((frm & 0xF) << 4)

def SH_FCMP_GT(frm, frn):
    """FCMP/GT FRm, FRn — T = (FRn > FRm)"""
    return 0xF005 | ((frn & 0xF) << 8) | ((frm & 0xF) << 4)


# =============================================================================
# FUNCTION ASSEMBLER
# =============================================================================

class SH2Function:
    """Assembles an SH-2 function with automatic literal pool management."""

    def __init__(self, name, base_addr):
        self.name = name
        self.base_addr = base_addr
        self.code = []          # list of 16-bit instruction words
        self.pool = []          # list of (label, 32-bit value)
        self.pool_refs = []     # list of (code_index, pool_label, reg_or_mova)
        self.labels = {}        # label -> code_index

    def emit(self, word):
        """Emit a 16-bit instruction word."""
        self.code.append(word)

    def current_offset(self):
        """Current code offset in bytes from function start."""
        return len(self.code) * 2

    def label(self, name):
        """Mark current position with a label."""
        self.labels[name] = len(self.code)

    def pool_entry(self, label, value):
        """Add a literal pool entry (if not already present)."""
        for pl, pv in self.pool:
            if pl == label:
                return  # already exists
        self.pool.append((label, value))

    def emit_mov_l_pool(self, pool_label, rn):
        """MOV.L @(disp,PC), Rn — with deferred pool reference."""
        idx = len(self.code)
        self.code.append(0)  # placeholder
        self.pool_refs.append((idx, pool_label, ('mov_l', rn)))

    def emit_mova_pool(self, pool_label):
        """MOVA @(disp,PC), R0 — with deferred pool reference."""
        idx = len(self.code)
        self.code.append(0)  # placeholder
        self.pool_refs.append((idx, pool_label, ('mova',)))

    def emit_bf(self, target_label):
        """BF target — with deferred label reference."""
        idx = len(self.code)
        self.code.append(0)  # placeholder
        self.pool_refs.append((idx, target_label, ('bf',)))

    def emit_bt(self, target_label):
        """BT target — with deferred label reference."""
        idx = len(self.code)
        self.code.append(0)  # placeholder
        self.pool_refs.append((idx, target_label, ('bt',)))

    def emit_bra(self, target_label):
        """BRA target — with deferred label reference."""
        idx = len(self.code)
        self.code.append(0)  # placeholder
        self.pool_refs.append((idx, target_label, ('bra',)))

    def resolve(self):
        """Resolve all pool references and return final binary."""
        # Pad code to 4-byte alignment for literal pool
        if len(self.code) % 2 != 0:
            self.code.append(SH_NOP())

        # Record pool start index (in 16-bit words)
        pool_start_idx = len(self.code)

        # Build pool label → byte offset mapping
        pool_offsets = {}
        for i, (label, value) in enumerate(self.pool):
            byte_offset = (pool_start_idx * 2) + (i * 4)
            pool_offsets[label] = byte_offset

        # Resolve all references
        for code_idx, label, ref_type in self.pool_refs:
            instr_addr = self.base_addr + code_idx * 2

            if ref_type[0] in ('mov_l', 'mova'):
                # Literal pool reference
                pool_byte_offset = pool_offsets[label]
                target_addr = self.base_addr + pool_byte_offset

                # MOV.L: EA = (PC & ~3) + 4 + disp*4
                # MOVA:  EA = (PC & ~3) + 4 + disp*4
                pc_aligned = instr_addr & ~3
                disp = (target_addr - (pc_aligned + 4)) // 4

                if disp < 0 or disp > 255:
                    raise ValueError(
                        f"{self.name}: Pool ref '{label}' out of range: "
                        f"disp={disp} (instr@0x{instr_addr:X}, pool@0x{target_addr:X})")

                if ref_type[0] == 'mov_l':
                    rn = ref_type[1]
                    self.code[code_idx] = SH_MOV_L_DISP_PC(disp, rn)
                else:
                    self.code[code_idx] = SH_MOVA(disp)

            elif ref_type[0] in ('bt', 'bf', 'bra'):
                # Branch to label
                if label not in self.labels:
                    raise ValueError(f"{self.name}: Unknown label '{label}'")
                target_idx = self.labels[label]
                target_byte = self.base_addr + target_idx * 2

                # BT/BF: target = PC + 4 + disp*2 (8-bit signed)
                # BRA:   target = PC + 4 + disp*2 (12-bit signed)
                pc_plus_4 = instr_addr + 4
                disp = (target_byte - pc_plus_4) // 2

                if ref_type[0] == 'bt':
                    if disp < -128 or disp > 127:
                        raise ValueError(f"{self.name}: BT to '{label}' out of range: disp={disp}")
                    self.code[code_idx] = SH_BT(disp & 0xFF)
                elif ref_type[0] == 'bf':
                    if disp < -128 or disp > 127:
                        raise ValueError(f"{self.name}: BF to '{label}' out of range: disp={disp}")
                    self.code[code_idx] = SH_BF(disp & 0xFF)
                elif ref_type[0] == 'bra':
                    if disp < -2048 or disp > 2047:
                        raise ValueError(f"{self.name}: BRA to '{label}' out of range: disp={disp}")
                    self.code[code_idx] = SH_BRA(disp & 0xFFF)

        # Build final binary
        result = bytearray()
        for word in self.code:
            result += be16(word)
        for label, value in self.pool:
            result += be32(value)

        return bytes(result)

    def size(self):
        """Estimated total size including pool."""
        code_bytes = len(self.code) * 2
        if code_bytes % 4 != 0:
            code_bytes += 2  # alignment padding
        pool_bytes = len(self.pool) * 4
        return code_bytes + pool_bytes


# =============================================================================
# TABLE DATA (from SpeedDensityTables.c)
# =============================================================================

# VE Table 1: 24x24 uint16
VE_COLS = [100,200,300,400,500,600,700,800,900,1000,1100,1200,
           1300,1400,1500,1600,1700,1800,1900,2000,2100,2200,2300,2400]
VE_ROWS = [500,800,1200,1600,2000,2400,2800,3200,3600,4000,4200,4400,
           4600,4800,5000,5200,5400,5600,5800,6000,6400,6800,7200,7600]
VE_DATA = [
    7150,7449,9958,10351,10665,10794,10943,11089,11177,11242,11307,11383,11459,11535,11611,11687,11763,11839,11915,11991,12067,12143,12219,12295,
    7398,7646,9694,10132,10499,10716,10956,11076,11190,11255,11320,11396,11472,11548,11624,11700,11776,11852,11928,12004,12080,12156,12232,12308,
    8081,8447,9658,10002,10486,10716,10813,10959,11207,11272,11346,11422,11498,11574,11650,11726,11802,11878,11954,12030,12106,12182,12258,12334,
    8456,8796,9659,10001,10497,10742,10853,10998,11229,11301,11385,11474,11563,11652,11741,11830,11919,12008,12097,12186,12275,12364,12453,12542,
    8627,8928,9659,10042,10499,10768,10917,11037,11281,11371,11474,11578,11682,11786,11890,11994,12098,12202,12306,12410,12514,12618,12722,12826,
    8749,9024,9676,10121,10512,10795,10995,11186,11468,11668,11864,12058,12252,12446,12640,12834,13028,13222,13416,13610,13804,13998,14192,14386,
    8854,9128,9793,10224,10537,10848,11152,11475,11805,12323,12580,12710,12840,12970,13100,13230,13360,13490,13620,13750,13880,14010,14140,14270,
    9073,9334,9946,10365,10653,10986,11398,11864,12388,12983,13176,13240,13304,13368,13432,13496,13560,13624,13688,13752,13816,13880,13944,14008,
    9383,9620,10233,10738,11191,11716,12322,12721,13043,13291,13410,13501,13592,13683,13774,13865,13956,14047,14138,14229,14320,14411,14502,14593,
    9576,9821,10422,10978,11481,11999,12439,12800,13095,13305,13410,13501,13592,13683,13774,13865,13956,14047,14138,14229,14320,14411,14502,14593,
    9538,9777,10396,10953,11441,11968,12369,12749,13008,13199,13305,13370,13435,13500,13565,13630,13695,13760,13825,13890,13955,14020,14085,14150,
    9488,9736,10316,10884,11359,11860,12261,12607,12875,13047,13099,13139,13179,13219,13259,13299,13339,13379,13419,13459,13499,13539,13579,13619,
    9428,9668,10238,10789,11265,11740,12115,12435,12677,12815,12854,12842,12830,12818,12806,12794,12782,12770,12758,12746,12734,12722,12710,12698,
    9374,9593,10152,10682,11157,11606,11956,12220,12414,12517,12531,12454,12377,12300,12223,12146,12069,11992,11915,11838,11761,11684,11607,11530,
    9308,9528,10061,10572,11022,11420,11733,11936,12090,12130,12080,11951,11822,11693,11564,11435,11306,11177,11048,10919,10790,10661,10532,10403,
    9242,9464,9972,10452,10853,11215,11477,11630,11706,11679,11564,11435,11306,11177,11048,10919,10790,10661,10532,10403,10274,10145,10016,9887,
    9166,9375,9856,10312,10653,10966,11149,11240,11227,11151,11035,10906,10777,10648,10519,10390,10261,10132,10003,9874,9745,9616,9487,9358,
    9078,9298,9741,10160,10461,10684,10814,10817,10752,10659,10530,10402,10274,10146,10018,9890,9762,9634,9506,9378,9250,9122,8994,8866,
    8990,9221,9626,10008,10269,10402,10479,10394,10277,10167,10025,9898,9771,9644,9517,9390,9263,9136,9009,8882,8755,8628,8501,8374,
    8902,9144,9511,9856,10077,10120,10144,9971,9802,9675,9520,9394,9268,9142,9016,8890,8764,8638,8512,8386,8260,8134,8008,7882,
    8814,9067,9396,9704,9885,9838,9809,9548,9327,9183,9015,8890,8765,8640,8515,8390,8265,8140,8015,7890,7765,7640,7515,7390,
    8726,8990,9281,9552,9693,9556,9474,9125,8852,8691,8510,8386,8262,8138,8014,7890,7766,7642,7518,7394,7270,7146,7022,6898,
    8638,8913,9166,9400,9501,9274,9139,8702,8377,8199,8005,7882,7759,7636,7513,7390,7267,7144,7021,6898,6775,6652,6529,6406,
    8550,8836,9051,9248,9309,8992,8804,8279,7902,7707,7500,7378,7256,7134,7012,6890,6768,6646,6524,6402,6280,6158,6036,5914,
]

# Atmospheric Compensation: 7x7 uint16 — all 16384 (neutral 1.0x)
AC_COLS = [0, 333, 666, 1000, 1333, 1666, 2000]
AC_ROWS = [465, 525, 585, 645, 705, 765, 825]
AC_DATA = [16384] * 49

# SD Blending Table: 10x10 uint8
BT_COLS = [465, 525, 585, 645, 705, 765, 825, 885, 945, 1005]
BT_ROWS = [0, 500, 1000, 1250, 1500, 2000, 2500, 3000, 3500, 4000]
BT_DATA = [
    0,0,0,50,150,250,250,250,250,250,
    0,0,0,50,150,250,250,250,250,250,
    0,0,0,50,150,250,250,250,250,250,
    0,0,0,50,150,250,250,250,250,250,
    0,0,0,50,150,250,250,250,250,250,
    0,0,0,50,150,250,250,250,250,250,
    0,0,0,50,150,250,250,250,250,250,
    0,0,0,50,150,250,250,250,250,250,
    0,0,0,50,150,250,250,250,250,250,
    0,0,0,50,150,250,250,250,250,250,
]

# Constants
CELSIUS_TO_KELVIN   = 273.15
SD_CONSTANT         = 0.003871098
DISPLACEMENT        = 2.46


def build_threedtable(ncols, nrows, cols, rows, data, data_type, multiplier, offset, base_addr):
    """Build a ThreeDTable struct + axis arrays + data in ROM layout.
    Returns (descriptor_bytes, total_size).
    The descriptor points to axis/data arrays that follow it.
    """
    desc_size = 28  # ThreeDTable struct is 28 bytes (0x1C)

    # Axis arrays (floats)
    col_array = b''.join(float_bytes(v) for v in cols)
    row_array = b''.join(float_bytes(v) for v in rows)

    # Data array
    if data_type == 0x08000000:  # UInt16Table3D
        data_array = b''.join(struct.pack('>h', int(v)) for v in data)
    elif data_type == 0x04000000:  # UInt8Table3D
        data_array = bytes(int(v) & 0xFF for v in data)
    else:
        raise ValueError(f"Unknown table type: 0x{data_type:08X}")

    # Pad data to 4-byte alignment
    while len(data_array) % 4 != 0:
        data_array += b'\x00'

    # Compute addresses (descriptor first, then cols, rows, data)
    col_addr = base_addr + desc_size
    row_addr = col_addr + len(col_array)
    data_addr = row_addr + len(row_array)

    # Build descriptor struct
    desc = struct.pack('>hh', ncols, nrows)       # columnCount, rowCount
    desc += be32(col_addr)                          # columnHeaderArray pointer
    desc += be32(row_addr)                          # rowHeaderArray pointer
    desc += be32(data_addr)                         # tableCells pointer
    desc += be32(data_type)                         # tableType
    desc += float_bytes(multiplier)                 # multiplier
    desc += float_bytes(offset)                     # offset

    result = desc + col_array + row_array + data_array
    return result


# =============================================================================
# ASSEMBLE FUNCTIONS
# =============================================================================

def build_initializer(base_addr, addrs):
    """Assemble the Initializer function.

    Called from reset handler via hooked literal pool at 0x0D64.
    Receives: R4=0 (from OEM caller delay slot)
    Must: call OEM reset, clear RAM, populate defaults, return.
    """
    f = SH2Function("Initializer", base_addr)

    # Literal pool entries
    f.pool_entry('oem_reset', ORIG_MEMORY_RESET)
    f.pool_entry('ram_start', RAM_HOLE_START)
    f.pool_entry('ram_end', RAM_HOLE_START + RV_STRUCT_SIZE)
    f.pool_entry('ecu_id_addr', D_ECU_ID)
    f.pool_entry('default_maf_mode', MAF_MODE_SENSOR)

    # --- Prologue ---
    f.emit(SH_STS_L_PR_PREDEC(15))          # STS.L PR, @-R15
    f.emit(SH_MOV_L_RM_PREDEC(14, 15))      # MOV.L R14, @-R15

    # --- Call OEM reset ---
    f.emit_mov_l_pool('oem_reset', 3)        # MOV.L @(pool),R3 = 0x065C
    f.emit(SH_JSR(3))                        # JSR @R3
    f.emit(SH_NOP())                         # delay slot

    # --- ClearRamVariables: zero pRamHoleStart to end ---
    f.emit_mov_l_pool('ram_start', 14)       # R14 = 0xFFFFC000
    f.emit_mov_l_pool('ram_end', 3)          # R3 = end address
    f.emit(SH_MOV_IMM(0, 0))                # R0 = 0

    f.label('clear_loop')
    f.emit(SH_MOV_B_RM_AT_RN(0, 14))        # MOV.B R0, @R14  (*R14 = 0)
    f.emit(SH_ADD_IMM(1, 14))               # ADD #1, R14
    f.emit(SH_CMP_GE(3, 14))                # CMP/GE R3, R14 (R14 >= R3?)
    f.emit_bf('clear_loop')                  # BF clear_loop (if not, continue)

    # --- PopulateRamVariables ---
    f.emit_mov_l_pool('ram_start', 14)       # R14 = pRamVariables base

    # pRamVariables->MafMode = MafModeSensor (1)
    f.emit(SH_MOV_IMM(MAF_MODE_SENSOR, 0))  # R0 = 1
    f.emit(SH_MOV_B_R0_AT_DISP_RN(RV_MAF_MODE, 14))  # MOV.B R0, @(0x0D, R14)

    # pRamVariables->ECUIdentifier = *(unsigned long*)0x2004
    f.emit_mov_l_pool('ecu_id_addr', 3)      # R3 = 0x2004
    f.emit(SH_MOV_L_AT_RM(3, 3))            # R3 = *(u32*)0x2004
    f.emit(SH_ADD_IMM(RV_ECU_IDENTIFIER, 14))  # R14 += 4 (point to ECUIdentifier field)
    f.emit(SH_MOV_L_RM_AT_RN(3, 14))        # *R14 = R3 (store ECU ID)
    f.emit(SH_ADD_IMM(-RV_ECU_IDENTIFIER & 0xFF, 14))  # R14 -= 4 (restore base)

    # pRamVariables->HardResetFlag = 0 (already zeroed by ClearRamVariables)

    # --- Epilogue ---
    f.emit(SH_MOV_L_POSTINC(15, 14))        # MOV.L @R15+, R14
    f.emit(SH_LDS_L_POSTINC_PR(15))         # LDS.L @R15+, PR
    f.emit(SH_RTS())                         # RTS
    f.emit(SH_NOP())                         # delay slot

    return f.resolve()


def build_compute_maf(base_addr, addrs):
    """Assemble ComputeMassAirFlow function.

    Entry: R4 = TwoDTable* MafScalingTable, FR4 = float MafVoltage
    Returns: FR0 = airflow in g/s

    Implements SpeedDensity.c ComputeMassAirFlow() for SDOnly config.
    """
    f = SH2Function("ComputeMassAirFlow", base_addr)

    # Literal pool entries (ROM addresses of data/constants)
    f.pool_entry('p_ram_vars',     RAM_HOLE_START)
    f.pool_entry('pull2d',         ORIG_PULL2D_FLOAT)
    f.pool_entry('pull3d',         ORIG_PULL3D_FLOAT)
    f.pool_entry('ve_table',       addrs['ve_table'])
    f.pool_entry('atm_table',      addrs['atm_table'])
    f.pool_entry('blend_table',    addrs['blend_table'])
    f.pool_entry('p_map',          P_MAP)
    f.pool_entry('p_rpm',          P_ENGINE_SPEED)
    f.pool_entry('p_iat',          P_IAT)
    f.pool_entry('p_atmo',         P_ATMO_PRESS)
    f.pool_entry('c_kelvin',       addrs['const_kelvin'])
    f.pool_entry('c_displ',        addrs['const_displacement'])
    f.pool_entry('c_sdconst',      addrs['const_sd'])
    f.pool_entry('c_one',          addrs['const_one'])

    # --- Prologue: save callee-save registers ---
    f.emit(SH_STS_L_PR_PREDEC(15))          # STS.L PR, @-R15
    f.emit(SH_MOV_L_RM_PREDEC(14, 15))      # push R14
    f.emit(SH_MOV_L_RM_PREDEC(13, 15))      # push R13

    # R14 = pRamVariables
    f.emit_mov_l_pool('p_ram_vars', 14)      # R14 = 0xFFFFC000

    # =====================================================
    # Step 1: MafFromSensor = Pull2DHooked(table, voltage)
    # R4 = MafScalingTable (already set by OEM caller)
    # FR4 = MafVoltage (already set by OEM caller)
    # =====================================================
    f.emit_mov_l_pool('pull2d', 3)           # R3 = Pull2DFloat address
    f.emit(SH_JSR(3))                        # JSR @R3
    f.emit(SH_NOP())                         # delay slot
    # FR0 = MafFromSensor
    f.emit(SH_MOV_IMM(RV_MAF_FROM_SENSOR, 0))  # R0 = 0x18
    f.emit(SH_FMOV_S_FRM_AT_R0_RN(0, 14))  # store FR0 → @(R0,R14)

    # =====================================================
    # Step 2: VE = Pull3DHooked(&VETable1, MAP, RPM)
    # Pull3DFloat convention: R4=descriptor, FR4=col axis, FR5=row axis
    # VE table: columns=MAP(kPa), rows=RPM
    # =====================================================
    f.emit_mov_l_pool('p_map', 3)            # R3 = ptr to MAP
    f.emit(SH_FMOV_S_AT_RM(3, 4))           # FR4 = *pMAP
    f.emit_mov_l_pool('p_rpm', 3)            # R3 = ptr to RPM
    f.emit(SH_FMOV_S_AT_RM(3, 5))           # FR5 = *pRPM
    f.emit_mov_l_pool('ve_table', 4)         # R4 = &VETable1 descriptor
    f.emit_mov_l_pool('pull3d', 3)           # R3 = Pull3DFloat
    f.emit(SH_JSR(3))                        # call Pull3DFloat
    f.emit(SH_NOP())                         # delay slot
    # FR0 = VE
    f.emit(SH_MOV_IMM(RV_VOLUMETRIC_EFFICIENCY, 0))  # R0 = 0x10
    f.emit(SH_FMOV_S_FRM_AT_R0_RN(0, 14))  # store VE → RamVars

    # =====================================================
    # Step 3: IAT_K = *pIAT + 273.15 → push to stack
    # =====================================================
    f.emit_mov_l_pool('p_iat', 3)            # R3 = ptr to IAT
    f.emit(SH_FMOV_S_AT_RM(3, 0))           # FR0 = *pIAT
    f.emit_mova_pool('c_kelvin')             # R0 = addr of 273.15 constant
    f.emit(SH_FMOV_S_AT_RM(0, 1))           # FR1 = 273.15
    f.emit(SH_FADD(1, 0))                   # FR0 = IAT + 273.15
    f.emit(SH_FMOV_S_FRM_PREDEC(0, 15))     # push IAT_K to stack

    # =====================================================
    # Step 4: AtmComp = Pull3DHooked(&AtmCompTable, MAP, AtmoPress)
    # =====================================================
    f.emit_mov_l_pool('p_map', 3)
    f.emit(SH_FMOV_S_AT_RM(3, 4))           # FR4 = *pMAP
    f.emit_mov_l_pool('p_atmo', 3)
    f.emit(SH_FMOV_S_AT_RM(3, 5))           # FR5 = *pAtmoPress
    f.emit_mov_l_pool('atm_table', 4)        # R4 = &AtmCompTable
    f.emit_mov_l_pool('pull3d', 3)
    f.emit(SH_JSR(3))
    f.emit(SH_NOP())
    # FR0 = AtmComp
    f.emit(SH_MOV_IMM(RV_ATM_COMPENSATION, 0))  # R0 = 0x1C
    f.emit(SH_FMOV_S_FRM_AT_R0_RN(0, 14))  # store AtmComp → RamVars

    # =====================================================
    # Step 5: MafFromSD = Displacement * RPM * MAP * VE * AtmComp * SDConst / IAT_K
    # Build the product in FR0
    # =====================================================
    # Load Displacement
    f.emit_mova_pool('c_displ')              # R0 = addr of Displacement
    f.emit(SH_FMOV_S_AT_RM(0, 0))           # FR0 = 2.46

    # × RPM
    f.emit_mov_l_pool('p_rpm', 3)
    f.emit(SH_FMOV_S_AT_RM(3, 1))           # FR1 = *pRPM
    f.emit(SH_FMUL(1, 0))                   # FR0 *= RPM

    # × MAP
    f.emit_mov_l_pool('p_map', 3)
    f.emit(SH_FMOV_S_AT_RM(3, 1))           # FR1 = *pMAP
    f.emit(SH_FMUL(1, 0))                   # FR0 *= MAP

    # × VE (load from RamVars)
    f.emit(SH_MOV_IMM(RV_VOLUMETRIC_EFFICIENCY, 13))  # R13 = offset (temp)
    f.emit(SH_ADD(14, 13))                   # R13 = pRamVars + offset
    f.emit(SH_FMOV_S_AT_RM(13, 1))          # FR1 = VE
    f.emit(SH_FMUL(1, 0))                   # FR0 *= VE

    # × AtmComp (load from RamVars)
    f.emit(SH_MOV_IMM(RV_ATM_COMPENSATION, 13))
    f.emit(SH_ADD(14, 13))
    f.emit(SH_FMOV_S_AT_RM(13, 1))          # FR1 = AtmComp
    f.emit(SH_FMUL(1, 0))                   # FR0 *= AtmComp

    # × SDConstant
    f.emit_mova_pool('c_sdconst')
    f.emit(SH_FMOV_S_AT_RM(0, 1))           # FR1 = SDConstant
    f.emit(SH_FMUL(1, 0))                   # FR0 *= SDConst

    # ÷ IAT_K (pop from stack)
    f.emit(SH_FMOV_S_POSTINC(15, 1))        # FR1 = IAT_K (pop)
    f.emit(SH_FDIV(1, 0))                   # FR0 /= IAT_K

    # Store MafFromSD
    f.emit(SH_MOV_IMM(RV_MAF_FROM_SD, 13))
    f.emit(SH_ADD(14, 13))
    f.emit(SH_FMOV_S_FRM_AT_RN(0, 13))     # store MafFromSD
    # Keep FR0 = MafFromSD for later
    f.emit(SH_FMOV(0, 2))                   # FR2 = MafFromSD (save)

    # =====================================================
    # Step 6: Mode selection
    # =====================================================
    # Read MafMode byte
    f.emit(SH_MOV_B_AT_DISP_RN_R0(RV_MAF_MODE, 14))  # R0 = MafMode
    f.emit(SH_EXTU_B(0, 0))                 # zero-extend

    # Check MafModeSpeedDensity (0x02)
    f.emit(SH_CMP_EQ_IMM(MAF_MODE_SD))      # R0 == 2?
    f.emit_bt('mode_sd')

    # Check MafModeBlending (0x03)
    f.emit(SH_CMP_EQ_IMM(MAF_MODE_BLENDING))
    f.emit_bt('mode_blend')

    # Default: return MafFromSensor
    f.emit(SH_MOV_IMM(RV_MAF_FROM_SENSOR, 0))
    f.emit(SH_FMOV_S_AT_R0_RM(14, 0))      # FR0 = MafFromSensor
    f.emit_bra('epilogue')
    f.emit(SH_NOP())

    # --- SD mode: return MafFromSD ---
    f.label('mode_sd')
    f.emit(SH_FMOV(2, 0))                   # FR0 = MafFromSD (from FR2)
    f.emit_bra('epilogue')
    f.emit(SH_NOP())

    # --- Blend mode ---
    f.label('mode_blend')
    # BlendRatio = Pull3DHooked(&SDBlendingTable, MAP, RPM)
    f.emit_mov_l_pool('p_map', 3)
    f.emit(SH_FMOV_S_AT_RM(3, 4))           # FR4 = *pMAP
    f.emit_mov_l_pool('p_rpm', 3)
    f.emit(SH_FMOV_S_AT_RM(3, 5))           # FR5 = *pRPM
    f.emit_mov_l_pool('blend_table', 4)      # R4 = &SDBlendingTable
    f.emit_mov_l_pool('pull3d', 3)
    f.emit(SH_JSR(3))
    f.emit(SH_NOP())
    # FR0 = blend ratio

    # Store blend ratio — R0=offset (integer), FR0=ratio (float) — separate register files
    f.emit(SH_MOV_IMM(RV_SD_MAF_BLEND_RATIO, 0))
    f.emit(SH_FMOV_S_FRM_AT_R0_RN(0, 14))
    # FR0 = ratio, FR2 = MafFromSD (saved earlier)
    f.emit(SH_FMOV(0, 3))                   # FR3 = ratio

    # result = (MafFromSD × ratio) + (MafFromSensor × (1 - ratio))
    f.emit(SH_FMOV(2, 4))                   # FR4 = MafFromSD
    f.emit(SH_FMUL(3, 4))                   # FR4 = MafFromSD × ratio

    # Load 1.0
    f.emit_mova_pool('c_one')                # R0 = addr of 1.0
    f.emit(SH_FMOV_S_AT_RM(0, 5))           # FR5 = 1.0
    f.emit(SH_FSUB(3, 5))                   # FR5 = 1.0 - ratio

    # Load MafFromSensor
    f.emit(SH_MOV_IMM(RV_MAF_FROM_SENSOR, 0))
    f.emit(SH_FMOV_S_AT_R0_RM(14, 6))      # FR6 = MafFromSensor
    f.emit(SH_FMUL(5, 6))                   # FR6 = MafFromSensor × (1 - ratio)

    f.emit(SH_FADD(6, 4))                   # FR4 = blended result
    f.emit(SH_FMOV(4, 0))                   # FR0 = result

    # Store blended result
    f.emit(SH_MOV_IMM(RV_SD_MAF_FROM_BLEND, 0))
    f.emit(SH_FMOV_S_FRM_AT_R0_RN(0, 14))

    # =====================================================
    # Epilogue
    # =====================================================
    f.label('epilogue')
    f.emit(SH_MOV_L_POSTINC(15, 13))        # pop R13
    f.emit(SH_MOV_L_POSTINC(15, 14))        # pop R14
    f.emit(SH_LDS_L_POSTINC_PR(15))         # pop PR
    f.emit(SH_RTS())                         # RTS
    f.emit(SH_NOP())                         # delay slot

    return f.resolve()


# =============================================================================
# ROM HOLE LAYOUT BUILDER
# =============================================================================

def build_rom_hole():
    """Build the complete ROM hole payload.
    Returns (payload_bytes, initializer_addr, compute_maf_addr).
    """
    base = ROM_HOLE_START
    payload = bytearray()

    def align4():
        nonlocal payload
        while len(payload) % 4 != 0:
            payload += b'\x00'

    def current_addr():
        return base + len(payload)

    # --------------------------------------------------
    # Section 1: Float constants (directly in ROM hole)
    # --------------------------------------------------
    align4()
    addr_kelvin = current_addr()
    payload += float_bytes(CELSIUS_TO_KELVIN)      # 273.15

    addr_sd_const = current_addr()
    payload += float_bytes(SD_CONSTANT)             # 0.003871098

    addr_displacement = current_addr()
    payload += float_bytes(DISPLACEMENT)            # 2.46

    addr_one = current_addr()
    payload += float_bytes(1.0)                     # 1.0

    addr_default_blend = current_addr()
    payload += float_bytes(0.0)                     # 0.0 (default blend)

    # --------------------------------------------------
    # Section 2: VE Table 1 (24×24 uint16)
    # --------------------------------------------------
    align4()
    addr_ve_table = current_addr()
    ve_bytes = build_threedtable(
        24, 24, VE_COLS, VE_ROWS, VE_DATA,
        0x08000000,  # UInt16Table3D
        0.0000457763672,  # 1.5/32767
        0.0,
        addr_ve_table
    )
    payload += ve_bytes

    # --------------------------------------------------
    # Section 3: Atmospheric Compensation Table (7×7 uint16)
    # --------------------------------------------------
    align4()
    addr_atm_table = current_addr()
    atm_bytes = build_threedtable(
        7, 7, AC_COLS, AC_ROWS, AC_DATA,
        0x08000000,  # UInt16Table3D
        0.000061037,  # 2/32767
        0.0,
        addr_atm_table
    )
    payload += atm_bytes

    # --------------------------------------------------
    # Section 4: SD Blending Table (10×10 uint8)
    # --------------------------------------------------
    align4()
    addr_blend_table = current_addr()
    blend_bytes = build_threedtable(
        10, 10, BT_COLS, BT_ROWS, BT_DATA,
        0x04000000,  # UInt8Table3D
        0.003921568627451,  # 1/255
        0.0,
        addr_blend_table
    )
    payload += blend_bytes

    # --------------------------------------------------
    # Section 5: Initializer function
    # --------------------------------------------------
    align4()
    addr_initializer = current_addr()
    addrs = {}  # not needed for initializer
    init_code = build_initializer(addr_initializer, addrs)
    payload += init_code

    # --------------------------------------------------
    # Section 6: ComputeMassAirFlow function
    # --------------------------------------------------
    align4()
    addr_compute_maf = current_addr()
    addrs = {
        've_table': addr_ve_table,
        'atm_table': addr_atm_table,
        'blend_table': addr_blend_table,
        'const_kelvin': addr_kelvin,
        'const_displacement': addr_displacement,
        'const_sd': addr_sd_const,
        'const_one': addr_one,
    }
    maf_code = build_compute_maf(addr_compute_maf, addrs)
    payload += maf_code

    print(f"\n=== ROM Hole Layout ===")
    print(f"  Base:              0x{base:06X}")
    print(f"  Constants:         0x{addr_kelvin:06X} - 0x{addr_kelvin+20-1:06X}")
    print(f"  VE Table:          0x{addr_ve_table:06X} ({len(ve_bytes)} bytes)")
    print(f"  AtmComp Table:     0x{addr_atm_table:06X} ({len(atm_bytes)} bytes)")
    print(f"  Blending Table:    0x{addr_blend_table:06X} ({len(blend_bytes)} bytes)")
    print(f"  Initializer:       0x{addr_initializer:06X} ({len(init_code)} bytes)")
    print(f"  ComputeMassAirFlow:0x{addr_compute_maf:06X} ({len(maf_code)} bytes)")
    print(f"  Total payload:     {len(payload)} bytes")
    print(f"  ROM hole end:      0x{base + len(payload):06X}")
    print(f"  ROM hole available:0x0F8900 ({0x0F8900 - base - len(payload)} bytes remaining)")

    return bytes(payload), addr_initializer, addr_compute_maf


# =============================================================================
# MAIN PATCHER
# =============================================================================

def patch_rom(input_path, output_path):
    """Read ROM, apply MerpMod SD patch, write output."""

    print(f"Reading ROM: {input_path}")
    with open(input_path, 'rb') as f:
        rom = bytearray(f.read())

    if len(rom) != ROM_SIZE:
        print(f"WARNING: ROM size is {len(rom)} bytes, expected {ROM_SIZE}")

    # Verify hooks contain expected values
    hook1_val = struct.unpack('>I', rom[HOOK_MEMORY_RESET:HOOK_MEMORY_RESET+4])[0]
    hook2_val = struct.unpack('>I', rom[HOOK_MAF_CALC:HOOK_MAF_CALC+4])[0]

    print(f"\n=== Pre-patch verification ===")
    print(f"  Hook 1 @ 0x{HOOK_MEMORY_RESET:04X}: 0x{hook1_val:08X} (expected 0x{ORIG_MEMORY_RESET:08X})", end="")
    print(" OK" if hook1_val == ORIG_MEMORY_RESET else " MISMATCH!")
    print(f"  Hook 2 @ 0x{HOOK_MAF_CALC:04X}: 0x{hook2_val:08X} (expected 0x{ORIG_PULL2D_FLOAT:08X})", end="")
    print(" OK" if hook2_val == ORIG_PULL2D_FLOAT else " MISMATCH!")

    # Verify ROM hole is free
    hole_sample = rom[ROM_HOLE_START:ROM_HOLE_START+64]
    if all(b == 0xFF for b in hole_sample):
        print(f"  ROM hole @ 0x{ROM_HOLE_START:06X}: all 0xFF — OK")
    else:
        print(f"  ROM hole @ 0x{ROM_HOLE_START:06X}: NOT all 0xFF — already patched?")
        return

    # Build ROM hole payload
    payload, addr_init, addr_maf = build_rom_hole()

    # Write payload to ROM hole
    rom[ROM_HOLE_START:ROM_HOLE_START + len(payload)] = payload
    print(f"\n=== Patching ===")
    print(f"  Wrote {len(payload)} bytes to ROM hole at 0x{ROM_HOLE_START:06X}")

    # Patch hook 1: memory reset → Initializer
    rom[HOOK_MEMORY_RESET:HOOK_MEMORY_RESET+4] = be32(addr_init)
    print(f"  Hook 1 @ 0x{HOOK_MEMORY_RESET:04X}: 0x{ORIG_MEMORY_RESET:08X} -> 0x{addr_init:08X} (Initializer)")

    # Patch hook 2: MAF calc -> ComputeMassAirFlow
    rom[HOOK_MAF_CALC:HOOK_MAF_CALC+4] = be32(addr_maf)
    print(f"  Hook 2 @ 0x{HOOK_MAF_CALC:04X}: 0x{ORIG_PULL2D_FLOAT:08X} -> 0x{addr_maf:08X} (ComputeMassAirFlow)")

    # Write output
    print(f"\n=== Checksum ===")
    print(f"  NOTE: Subaru DBW checksum NOT updated.")
    print(f"  Fix checksum with ECUFlash or RomRaider before flashing.")

    print(f"\nWriting patched ROM: {output_path}")
    with open(output_path, 'wb') as f:
        f.write(rom)

    print(f"Done. {len(rom)} bytes written.")

    # Post-patch verification
    print(f"\n=== Post-patch verification ===")
    h1 = struct.unpack('>I', rom[HOOK_MEMORY_RESET:HOOK_MEMORY_RESET+4])[0]
    h2 = struct.unpack('>I', rom[HOOK_MAF_CALC:HOOK_MAF_CALC+4])[0]
    print(f"  Hook 1: 0x{h1:08X} -> Initializer @ 0x{addr_init:06X}")
    print(f"  Hook 2: 0x{h2:08X} -> ComputeMAF  @ 0x{addr_maf:06X}")
    print(f"  ROM hole first 16 bytes: {rom[ROM_HOLE_START:ROM_HOLE_START+16].hex()}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input_rom> [output_rom]")
        print(f"\nPatches an AE5L600L ROM with MerpMod Speed Density (SDOnly).")
        print(f"All addresses verified from ROM binary bytes.")
        sys.exit(1)

    input_rom = sys.argv[1]
    if len(sys.argv) >= 3:
        output_rom = sys.argv[2]
    else:
        base, ext = os.path.splitext(input_rom)
        output_rom = f"{base}.merpmod_sd{ext}"

    patch_rom(input_rom, output_rom)
