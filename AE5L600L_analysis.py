"""
AE5L600L ECU ROM — Ghidra analysis script
Subaru WRX (SH-7055/SH-7058, SH-2A core)

HOW TO USE:
  1. File → Import File → select the .bin
     Language:  Hitachi SH → SH-2A (or SH-2 if SH-2A isn't listed)
     Processor variant: SH-2A-FPU if available
     Base address: 0x00000000
  2. Let auto-analysis finish (or cancel it — we'll do it manually below)
  3. Script Manager → run this file

  The script will:
    • Add the internal-RAM memory block (0xFFFF8000–0xFFFFFFFF)
    • Disassemble and define every known function
    • Apply labels to all discovered RAM variables and ROM constants
    • Add comments at key branch / computation points

ROM notes:
  GBR is used as a base register (SH convention).
  Two GBR contexts appear in FLKC code:
    fn_043782  knock detector  → GBR = 0xFFFF80FC
    fn_0463ba  FLKC F/G update → GBR = 0xFFFF8290
"""

# ─────────────────────────────────────────────────────────────
# Ghidra API helpers
# ─────────────────────────────────────────────────────────────
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.mem    import MemoryBlockType
from ghidra.program.model.data   import ByteDataType, FloatDataType, WordDataType, DWordDataType

ST = SourceType.USER_DEFINED

def A(n):
    """int or hex-string → Ghidra Address"""
    if isinstance(n, str):
        n = int(n, 16)
    return toAddr(n)

def label(addr_int, name, comment=None):
    createLabel(A(addr_int), name, True, ST)
    if comment:
        setPreComment(A(addr_int), comment)

def fn(addr_int, name, comment=None):
    """Define/rename a function and optionally set a plate comment."""
    disassemble(A(addr_int))
    f = getFunctionAt(A(addr_int))
    if f is None:
        f = createFunction(A(addr_int), name)
    else:
        f.setName(name, ST)
    if comment and f:
        setPlateComment(A(addr_int), comment)

def cmt(addr_int, text):
    setEOLComment(A(addr_int), text)

def pre(addr_int, text):
    setPreComment(A(addr_int), text)

# ─────────────────────────────────────────────────────────────
# 1. Add internal-RAM memory block
# ─────────────────────────────────────────────────────────────
mem = currentProgram.getMemory()
try:
    ram_block = mem.getBlock(A(0xFFFF8000))
    if ram_block is None:
        mem.createUninitializedBlock(
            "IRAM", A(0xFFFF8000), 0x8000, False)
        print("Created IRAM block 0xFFFF8000–0xFFFFFFFF")
    else:
        print("IRAM block already present")
except Exception as e:
    print("RAM block: " + str(e))

# ─────────────────────────────────────────────────────────────
# 2. Function definitions
# ─────────────────────────────────────────────────────────────

fn(0x04A94C, "sched_periodic_dispatch",
   "Per-tick dispatcher called from scheduler table at ROM[0x00E628].\n"
   "Calls fn_043750 (knock wrapper) first, then 20+ other tasks.\n"
   "R4 = cylinder index (0/6/12/18) passed to knock wrapper.")

fn(0x043750, "knock_wrapper",
   "Checks cylinder index R4 ∈ {0,6,12,18} and counter < 4,\n"
   "then BSR to knock_detector (0x043782).")

fn(0x043782, "knock_detector",
   "Actual knock detector.\n"
   "GBR = 0xFFFF80FC while running.\n"
   "Writes [GBR+0xBE]=0xFFFF81BA  (knock flag: 1=knock, 0=no knock)\n"
   "Writes [GBR+0xBF]=0xFFFF81BB  (bank flag: which bank knocked)\n"
   "Called via BSR from knock_wrapper at 0x043774.")

fn(0x045BFE, "flkc_path_J",
   "FLKC fast-response correction — task [18] in task table.\n"
   "Path J: if [0xFFFF81BA]!=0 → FR13 -= base_step * 0.5\n"
   "At stock conditions: base_step=0.5, multiplier=0.5 → retard = -0.25 steps.\n"
   "Fires every cycle knock is detected. No bank discrimination.\n"
   "ROM[0x045DD8] = 0x3F000000 = 0.5 (the multiplier — tune here to change -0.25).")

fn(0x0463BA, "flkc_paths_FG",
   "FLKC sustained-knock correction — task [25] in task table.\n"
   "Paths F and G: FR4 -= 1.01 (or 2.80 for bank-1 path).\n"
   "GBR = 0xFFFF8290 while running.\n"
   "Requires 7 conditions including: [0xFFFF81BA]!=0, R4==1, counter>=90,\n"
   "cylinder index match, and FP range checks.\n"
   "Then branches on [0xFFFF81BB] (bank flag):\n"
   "  bank!=1 → PATH F: FR4 -= 1.01  (ROM[0xD2F50])\n"
   "  bank==1 → PATH F variant: FR4 -= 2.80  (ROM[0xD2F64])\n"
   "  early bailout → PATH G: FR4 -= 1.01  (ROM[0xD2F50])")

fn(0x043D68, "fn_043d68",
   "Periodic task [12] in task table.\n"
   "Writes [0xFFFF81D9] (NOT [0xFFFF81BA]) — do not confuse with knock flag.")

fn(0x04438C, "fn_04438c",
   "Periodic task [11] in task table. Reads [0xFFFF81BA].")

fn(0x029858, "fn_029858",
   "Helper called at entry of flkc_paths_FG (0x0463D4).")

# ─────────────────────────────────────────────────────────────
# 3. Scheduler / task tables
# ─────────────────────────────────────────────────────────────
label(0x00E628, "sched_table_main",
      "Scheduler table. Entry 0x0004A94C = sched_periodic_dispatch.")
label(0x04AD40, "task_table",
      "59-entry periodic task pointer table. Terminator = 0xFFFF8322.")
label(0x04AD6C, "task_table_11",  "[11] = fn_04438c  (reads knock flag)")
label(0x04AD70, "task_table_12",  "[12] = fn_043d68  (writes 0xFFFF81D9)")
label(0x04AD88, "task_table_18",  "[18] = flkc_path_J")
label(0x04ADA4, "task_table_25",  "[25] = flkc_paths_FG")
label(0x04AE2C, "task_table_end", "Table terminator (RAM addr 0xFFFF8322)")

# ─────────────────────────────────────────────────────────────
# 4. ROM constants (float literal pools)
# ─────────────────────────────────────────────────────────────
label(0x045DD8, "PATH_J_HALFSTEP_MULT",
      "0x3F000000 = 0.5  Path J multiplier.\n"
      "retard = RAM[0xFFFF323C] * this = 0.5*0.5 = 0.25 steps.\n"
      "Change to 0x3F800000(1.0) for full-step, 0x3F400000(0.75) for 3/4-step.")

label(0x000D2F50, "FLKC_RETARD_STEP_1p01",
      "0x3F8147AE = 1.01  Path F & Path G retard step (fn_0463ba).")
label(0x000D2F54, "tbl_d2f54_0p35",  "0x3EB33333 = 0.35")
label(0x000D2F58, "tbl_d2f58_0p35",  "0x3EB33333 = 0.35")
label(0x000D2F5C, "tbl_d2f5c_1p40",  "0x3FB33333 = 1.40")
label(0x000D2F60, "tbl_d2f60_1p40",  "0x3FB33333 = 1.40")
label(0x000D2F64, "FLKC_RETARD_STEP_BANK1_2p80",
      "0x40333333 = 2.80  Path F bank-1 retard step (when [0xFFFF81BB]==1).")
label(0x000D2F68, "tbl_d2f68_2p80",  "0x40333333 = 2.80")
label(0x000D2F40, "FLKC_FG_LIMIT_100", "0x42C80000 = 100.0  FR15 upper limit check in flkc_paths_FG.")
label(0x000D2F44, "tbl_d2f44_8p0",   "0x41000000 = 8.0")
label(0x000D2F48, "tbl_d2f48_0p25",  "0x3E800000 = 0.25")
label(0x000D2F4C, "tbl_d2f4c_n15",   "0xC1700000 = -15.0")

# ─────────────────────────────────────────────────────────────
# 5. RAM variables  (IRAM block, 0xFFFF8000 region)
# ─────────────────────────────────────────────────────────────

# — Knock detection outputs (GBR context 0xFFFF80FC in knock_detector) —
label(0xFFFF81BA, "KNOCK_FLAG",
      "Written by knock_detector (fn_043782) at 0x043B5A/5E.\n"
      "1 = knock detected this cycle, 0 = no knock.\n"
      "Read by flkc_path_J (fn_045bfe) and flkc_paths_FG (fn_0463ba).")
label(0xFFFF81BB, "KNOCK_BANK_FLAG",
      "Written by knock_detector at 0x043B62.\n"
      "Bank selector: 1 = bank 1 knocked, else bank 0.\n"
      "Used in flkc_paths_FG to choose -2.80 (bank1) vs -1.01 (bank0).")
label(0xFFFF81D9, "fn_043d68_output",
      "Written by fn_043d68 (task [12]). NOT the knock flag.")

# — FLKC path-J RAM variable —
label(0xFFFF323C, "FLKC_BASE_STEP",
      "Base correction step (float). = 0.5 at stock test conditions.\n"
      "Used in flkc_path_J: retard = this * ROM[0x045DD8](0.5) = 0.25 steps.")

# — fn_0463ba (GBR = 0xFFFF8290) state variables —
label(0xFFFF8294, "flkc_fg_counter",     "[GBR+0x04] word — cycle counter, must be >=90 to allow F/G retard.")
label(0xFFFF8298, "flkc_fg_cyl_index",   "[GBR+0x08] — current cylinder/bank index.")
label(0xFFFF829C, "flkc_fg_active",      "[GBR+0x0C] — active flag; cleared to 0 on knock entry.")
label(0xFFFF829D, "flkc_fg_retard_done", "[GBR+0x0D] — set to 1 after retard is applied.")
label(0xFFFF829E, "flkc_fg_enable",      "[GBR+0x0E] — must ==1 to enter main logic.")
label(0xFFFF82A0, "flkc_fg_exit_flag",   "[GBR+0x10] — set to 1 at normal exit.")
label(0xFFFF82A1, "flkc_fg_bank_route",  "[GBR+0x11] — routes post-retard clamp fn call.")
label(0xFFFF82AA, "flkc_fg_prev_cyl",    "[GBR+0x1A] — previous cylinder index; must match current to allow retard.")
label(0xFFFF8258, "flkc_fg_limit_FR15",  "Loaded into FR15 at flkc_paths_FG entry. Compared against 100.0 limit.")
label(0xFFFF3234, "flkc_fg_ref_FR14",    "Loaded into FR14 at flkc_paths_FG entry.")
label(0xFFFF3244, "flkc_fg_R0_init",     "Loaded into R0 early in flkc_paths_FG.")
label(0xFFFF3248, "flkc_fg_var_3248",    "Read early in flkc_paths_FG setup.")
label(0xFFFF8233, "flkc_fg_flag_8233",   "R4=0xFFFF8233 byte flag checked during FP setup.")
label(0xFFFF7D18, "sched_status_R1",     "Read into R1 at fn_0463ba entry via JSR fn_029858 area.")
label(0xFFFF3360, "flkc_output_table",   "Output table written by post-retard helper (word array indexed by cylinder).")
label(0xFFFF8290, "flkc_fg_GBR_base",   "GBR base pointer used by flkc_paths_FG (fn_0463ba).")
label(0xFFFF80FC, "knock_det_GBR_base", "GBR base pointer used by knock_detector (fn_043782).")
label(0xFFFF8EDC, "sched_disable_flag",
      "Read by sched_periodic_dispatch: if !=0, entire dispatch is skipped.")

# ─────────────────────────────────────────────────────────────
# 6. Key branch / computation comments inside functions
# ─────────────────────────────────────────────────────────────

# — flkc_path_J (fn_045bfe) —
pre(0x045C2A,  "Load base correction step: FR8 = RAM[0xFFFF323C] = 0.5")
pre(0x045C30,  "Stash base step on stack: [R15+4] = FR8 = 0.5")
pre(0x045CE0,  "PATH J ENTRY: [0xFFFF81BA] != 0 (knock detected)")
pre(0x045CE2,  "MOVA: R0 = 0x045DD8 (address of 0.5 ROM constant)")
pre(0x045CE4,  "FR8 = ROM[0x045DD8] = 0.5  (fixed multiplier)")
pre(0x045CE6,  "FR9 = FR9 * FR8 = 0.5 * 0.5 = 0.25")
pre(0x045CF0,  "PATH J RETARD: FR13 -= FR9(0.25)  → FLKC -= 0.25 steps")

# — knock_detector (fn_043782) —
pre(0x043796,  "Set GBR = 0xFFFF80FC for knock detector context")
pre(0x043B5A,  "KNOCK_FLAG = 1  (knock detected)")
pre(0x043B5E,  "KNOCK_FLAG = 0  (no knock)")
pre(0x043B62,  "KNOCK_BANK_FLAG = bank index (0 or 1)")

# — flkc_paths_FG (fn_0463ba) —
pre(0x0463C6,  "Set GBR = 0xFFFF8290 for F/G context")
pre(0x0463E0,  "R7 = [0xFFFF81BA]  (knock flag — loaded here, checked at 0x046460)")
pre(0x046460,  "GATE: TST R7,R7 — if R7==0 (no knock): NO-KNOCK path; else: KNOCK path")
pre(0x046618,  "KNOCK PATH entry: clear [0xFFFF8294] and [0xFFFF829C]")
pre(0x046622,  "Check FR15 limit: if ROM[d2f40]=100.0 > FR15 → PATH G")
pre(0x04662A,  "Check FR8 > FR4 → PATH G")
pre(0x046632,  "Check FR4 <= 0.0 → PATH G")
pre(0x04663C,  "R0 = [0xFFFF81BB]  (bank flag from knock_detector)")
pre(0x046642,  "BANK SPLIT: if bank==1 → fall through (-2.80); else → 0x046694 (-1.01)")
pre(0x046648,  "BANK-1 PATH: FR4 -= 2.80  (ROM[0xD2F64])")
pre(0x046694,  "PATH F ENTRY: [0xFFFF82A1] routing check")
pre(0x0466A0,  "PATH F RETARD: FR4 -= 1.01  (ROM[0xD2F50] = 0x3F8147AE)")
pre(0x04673A,  "PATH G RETARD: FR4 -= 1.01  (ROM[0xD2F50] = 0x3F8147AE)")

# — knock_wrapper —
pre(0x043754,  "Check cylinder index R4 ∈ {0,6,12,18} (each bank fires at 0,6,12,18 deg)")
pre(0x043770,  "Check counter < 4 before calling knock_detector")
pre(0x043774,  "BSR → knock_detector (0x043782)")

print("")
print("=== AE5L600L analysis script complete ===")
print("Labels applied:  functions, RAM vars, ROM constants, branch comments.")
print("")
print("Key addresses to review:")
print("  fn_045bfe  (flkc_path_J)     : Path J  -0.25 retard")
print("  fn_0463ba  (flkc_paths_FG)   : Path F/G -1.01 retard")
print("  fn_043782  (knock_detector)  : writes KNOCK_FLAG / KNOCK_BANK_FLAG")
print("  ROM[0x045DD8] = 0.5          : Path J multiplier (tune to change -0.25)")
print("  ROM[0xD2F50]  = 1.01         : Path F/G retard step")
print("  ROM[0xD2F64]  = 2.80         : Path F bank-1 retard step")
