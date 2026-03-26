// Ghidra script to import labels, comments, and memory map for AE5L600L ROM
// Usage:
//   1. Create new Ghidra project
//   2. Import the raw ROM binary:
//        File > Import File > select AE5L600L.bin
//        Language: SuperH:BE:32:SH-2A  (recommended — finds 41% more functions than SH-2)
//        Address: 0x00000000
//   3. Run this script: Script Manager > Run (or press the green play button)
//
// This script applies all labels and comments from disassembly.txt analysis.
// Verified against Ghidra 12.0.2 SH-2A export (rev 20.2, 139 symbols + 41 comments).
//
//@author  AE5L600L disassembly project
//@category Data

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.symbol.SourceType;

public class ImportAE5L600L extends GhidraScript {

    @Override
    protected void run() throws Exception {
        int count = 0;

        // =====================================================================
        // EXCEPTION VECTOR TABLE
        // =====================================================================
        count += label(0x00000000, "vec_PowerOnResetPC");
        count += label(0x00000004, "vec_PowerOnResetSP");
        count += label(0x00000008, "vec_ManualResetPC");
        count += label(0x0000000C, "vec_ManualResetSP");
        count += label(0x00000010, "vec_IllegalInstruction");
        count += label(0x00000024, "vec_CPUAddressError");
        count += label(0x00000028, "vec_DMAAddressError");
        count += label(0x0000002C, "vec_NMI");
        count += label(0x00000030, "vec_UserBreak");

        // =====================================================================
        // CODE FUNCTIONS
        // =====================================================================
        count += labelComment(0x00000BAC, "NMI_Handler",
            "NMI handler - saves all regs, checks NMI source, handles watchdog");
        count += labelComment(0x00000BFA, "DefaultExceptionHandler",
            "Default exception handler - infinite loop (bra self)");
        count += labelComment(0x00000C0C, "Entry",
            "Power-on reset entry point. Calls HW init, then main scheduler.");

        // Scheduler / Task table
        count += labelComment(0x0000E628, "sched_table_main",
            "Scheduler table, entry -> sched_periodic_dispatch @ 0x04A94C");
        count += labelComment(0x0004A94C, "sched_periodic_dispatch",
            "Per-tick dispatcher, calls 59 tasks from task_table @ 0x04AD40");
        count += labelComment(0x0004AD40, "task_table",
            "59-entry periodic task pointer table. Terminator = 0xFFFF8322");

        // PSE code
        count += labelComment(0x00030674, "PSE_code_entry",
            "Post Start Enrichment code function (0x30674-0x30A78). 26 descriptors at 0xAC948-0xACB3F.");

        // Knock detection & FLKC
        count += labelComment(0x00043750, "knock_wrapper",
            "Checks cyl index R4 in {0,6,12,18} and counter < 4, then BSR to knock_detector");
        count += labelComment(0x00043782, "knock_detector",
            "Knock detection. GBR=0xFFFF80FC. Writes KNOCK_FLAG [0xFFFF81BA] and KNOCK_BANK_FLAG [0xFFFF81BB]");
        count += labelComment(0x00043470, "LowPW_GateFunction",
            "Low PW Injector Comp gate: checks RPM < max and IPW < max");
        count += labelComment(0x0004438C, "task11_knock_flag_read",
            "Task [11] Knock flag consumer - reads KNOCK_FLAG+BANK_FLAG, dispatches knock response");
        count += labelComment(0x00043D68, "task12_knock_post",
            "Task [12] Knock post-process - writes 0xFFFF81D9, refs knock GBR base, cal 0xD2D60-74");
        count += labelComment(0x00045BFE, "flkc_path_J",
            "Task [18] FLKC fast-response. If KNOCK_FLAG!=0: FR13 -= base_step*0.5. ROM[0x045DD8]=0.5 multiplier.");
        count += labelComment(0x000463BA, "flkc_paths_FG",
            "Task [25] FLKC sustained-knock. GBR=0xFFFF8290. Requires 7 conditions. bank!=1->retard 1.01, bank==1->retard 2.80");

        // ── Scheduler tasks: complete 59-entry map ──
        // Timing / Per-Cylinder Compensation
        count += labelComment(0x00044188, "task00_timing_percyl",
            "Task [0] Per-cylinder timing comp. RPM+MAF, cal Timing Comp Max RPM/Min Load/Min ECT");
        // Knock → Timing Feedback
        count += labelComment(0x00045970, "task01_knock_timing_fb",
            "Task [1] Post-knock timing adjustment. Knock corr state RAM 0x8204-821C");
        // Knock Window Setup
        count += labelComment(0x00045098, "task02_knock_window",
            "Task [2] Knock window setup. KNOCK_FLAG+MAF, sets GBR, cal 0xD29E4/D2E60/D2E64");
        count += labelComment(0x00045670, "task03_knock_thresh",
            "Task [3] Knock threshold config. Feedback Corr Min Load (0xD2DA4), sets GBR");
        count += labelComment(0x000455E6, "task04_knock_thresh",
            "Task [4] Knock sensitivity config. MAF, cal 0xD2E9C-D2EB0, sets GBR");
        // Knock Detection
        count += labelComment(0x0004530A, "task05_knock_det",
            "Task [5] Knock detection. KNOCK_FLAG+MAF+IAM, sets GBR");
        count += labelComment(0x00045354, "task06_knock_det",
            "Task [6] Knock detection. KNOCK_FLAG+MAF, sets GBR");
        count += labelComment(0x000450AE, "task07_knock_det",
            "Task [7] Knock detection. KNOCK_FLAG+MAF, sets GBR");
        count += labelComment(0x00044E04, "task08_knock_window",
            "Task [8] Knock window setup. IAM+RPM, cal 0xD2E1C-2C");
        count += labelComment(0x00044DB0, "task09_knock_det",
            "Task [9] Knock detection. KNOCK_FLAG+IAM+RPM, sets GBR");
        count += labelComment(0x000448F4, "task10_knock_config",
            "Task [10] Knock config dispatcher. RPM+MAF+sched, multi-RAM refs");
        // Tasks 11/12 already labeled above
        // Rough Correction
        count += labelComment(0x00045A3E, "task13_rough_corr",
            "Task [13] Rough correction range. Rough Corr Min KC Advance (0xD2EDC)");
        count += labelComment(0x00044834, "task14_knock_thresh_lu",
            "Task [14] Knock threshold lookup. 8 cal params 0xD2DEC-0xD2E04");
        count += labelComment(0x00045A84, "task15_rough_corr",
            "Task [15] Rough correction range. Rough Corr Min KC Advance (0xD2EDC)");
        // FLKC Pipeline
        count += labelComment(0x00045BBC, "task16_flkc_pre",
            "Task [16] FLKC pre-process. KNOCK_FLAG+FLKC_BASE_STEP+IAM+MAF");
        count += labelComment(0x00045B44, "task17_flkc_pre",
            "Task [17] FLKC pre-process. FLKC_BASE_STEP+IAM, Advance Multiplier");
        // Tasks 18/25 already labeled above (flkc_path_J, flkc_paths_FG)
        count += labelComment(0x00045E96, "task19_flkc_post",
            "Task [19] FLKC post-process. Advance Multiplier application");
        count += labelComment(0x000459F6, "task20_knock_win_upd",
            "Task [20] Knock window per-cyl update. IAM+MAF, sets GBR");
        count += labelComment(0x000467AE, "task21_knock_win_upd",
            "Task [21] Knock window per-cyl update. MAF+cyl index, sets GBR");
        count += labelComment(0x000461D2, "task22_knock_percyl",
            "Task [22] Knock per-cyl config. Cyl index (0xFFFF8298), sets GBR");
        count += labelComment(0x000467F4, "task23_knock_cyl_track",
            "Task [23] Knock cyl tracking. KNOCK_FLAG+cyl index tracking");
        count += labelComment(0x000469A4, "task24_flkc_output",
            "Task [24] FLKC output stage. flkc_output_table+cal 0xD29F0");
        // Task 25 already labeled above
        count += labelComment(0x00046978, "task26_flkc_output",
            "Task [26] FLKC output stage. flkc output+cal 0xD29F0");
        count += labelComment(0x00046296, "task27_knock_timing",
            "Task [27] Knock timing correction. KNOCK_FLAG+timing output");
        count += labelComment(0x00045DF8, "task28_flkc_recovery",
            "Task [28] FLKC recovery. Advance recovery steps 0xD2EEC-0xD2F08");
        // Timing Pipeline
        count += labelComment(0x00044296, "task29_timing_percyl",
            "Task [29] Per-cyl timing comp. Load+knock state, sets GBR");
        count += labelComment(0x0003FCA2, "task30_base_timing",
            "Task [30] Base timing lookup. RPM+MAF+ECT+ATM, 14+ RAM refs");
        count += labelComment(0x0003FFD6, "task31_timing_blend_ratio",
            "Task [31] Timing blend ratio. Blend Floor/Ceiling 0xD2B18/1C");
        count += labelComment(0x0004004A, "task32_timing_blend_app",
            "Task [32] Timing blend application. Blend Min Ratio+RPM Limit");
        count += labelComment(0x00040918, "task33_timing_ws_init",
            "Task [33] Timing workspace init. Multi-GBR-write, 3 BSR calls");
        count += labelComment(0x00040516, "task34_timing_throttle",
            "Task [34] Timing throttle comp. Throttle+MAF voltage+injector");
        count += labelComment(0x000418AC, "task35_timing_corr",
            "Task [35] Timing correction stage. Cal 0xD2C04, timing state RAM");
        count += labelComment(0x000415B8, "task36_timing_percond",
            "Task [36] Timing per-condition. RPM+MAF+throttle+fuel rate");
        count += labelComment(0x000419BA, "task37_timing_multiaxis",
            "Task [37] Timing multi-axis. RPM+MAF, 3 cal params, 3 BSR calls");
        // Ignition Output
        count += labelComment(0x00042A78, "task38_ign_output",
            "Task [38] Ignition output. RPM+MAF+throttle, cal 0xD2CB0-CB8");
        count += labelComment(0x00042B90, "task39_ign_maf_corr",
            "Task [39] Ignition MAF correction. MAF, RAM 0xFFFF320C");
        count += labelComment(0x00042D20, "task40_ign_calc_a",
            "Task [40] Ignition calc A. MAF, cal 0xD2CC0-CCC");
        count += labelComment(0x00042D54, "task41_ign_calc_b",
            "Task [41] Ignition calc B. MAF, cal 0xD2CC8-CCC, BSR 0x42E6A");
        count += labelComment(0x00042F48, "task42_timing_comp_b",
            "Task [42] IAM-gated Timing Comp B. IAM+knock→Timing Comp B (IAT) activation");
        count += labelComment(0x0004322A, "task43_timing_out_load",
            "Task [43] Timing output with load. Load reference+descriptors");
        count += labelComment(0x0004317A, "task44_timing_lu_a",
            "Task [44] Timing lookup A. RPM+MAF, cal 0xD2D10");
        count += labelComment(0x000431B0, "task45_timing_lu_b",
            "Task [45] Timing lookup B. RPM+MAF, cal 0xD2D10");
        count += labelComment(0x00043368, "task46_inj_mps_timing",
            "Task [46] Injector/MPS timing comp. MAF V+MPS+boost, calls low_pw_table_proc");
        count += labelComment(0x00043464, "task47_mapswitch_lowpw",
            "Task [47] Map switch+Low PW. Map Switch thresholds+Low PW Injector Comp");
        count += labelComment(0x0004359C, "task48_final_timing",
            "Task [48] Final timing/injector output. Throttle+MAF+boost, 4 JSR");
        // Base Advance
        count += labelComment(0x0003F00C, "task49_base_advance",
            "Task [49] Base timing advance. RPM+MAF+load+ATM, 16+ RAM refs");
        count += labelComment(0x0003F368, "task50_timing_blend_int",
            "Task [50] Timing blend integration. RPM+MAF+cl_enable, blend output");
        // Boost / Wastegate
        count += labelComment(0x00054852, "task51_boost_wg_calc",
            "Task [51] Boost/WG target calc. Throttle+MAF V+ECT cal, sets GBR");
        count += labelComment(0x000549FA, "task52_boost_feedback",
            "Task [52] Boost feedback/trim. MAF, cal 0xD6748");
        // Diagnostics
        count += labelComment(0x000602DC, "task53_diag_monitor",
            "Task [53] Diagnostic monitor. Diag state RAM, cal 0xD9A4C");
        // Idle
        count += labelComment(0x0004BC20, "task54_idle_control",
            "Task [54] Idle speed control. Throttle RAM, no FPU, GBR state machine");
        // MPS Diag
        count += labelComment(0x000900B4, "task55_mps_diag",
            "Task [55] MPS diagnostics. MPS scaling/CEL, ATM cross-check");
        // EVAP
        count += labelComment(0x00066580, "task56_evap_purge",
            "Task [56] EVAP/purge control. No FPU, 2 BSR calls");
        // EGR
        count += labelComment(0x000758CA, "task57_egr_emissions",
            "Task [57] EGR/emissions control. MAF, high-addr RAM, sets GBR");
        // MAF Diag
        count += labelComment(0x0006F0B8, "task58_maf_diag",
            "Task [58] MAF sensor diagnostics. MAF+MPS cross-check");

        // Front O2 sensor processing
        count += labelComment(0x00021A40, "frontO2_process",
            "Front O2 sensor processing. Reads rich limit (0.75 lambda) inline, atm pressure comp via descriptor 0xAAE8C.");
        count += labelComment(0x0001FE54, "frontO2_comp_atm",
            "Front O2 atmospheric compensation sub-function. Accesses descriptor at 0xAAE78.");

        // CL Fueling Target computation
        count += labelComment(0x00033CC4, "cl_fuel_target_calc",
            "CL Fueling Target computation. Accesses both Comp A (0xD14D0) and Comp B (0xD1740) via descriptors.");

        // CL/OL transition sub-functions
        count += labelComment(0x00036070, "clol_main_transition",
            "CL/OL main transition function. Reads IAM vs 0xCC16C, CL->OL throttle and BPW thresholds.");
        count += labelComment(0x0003697A, "clol_hysteresis_sub",
            "CL/OL hysteresis sub-function. Reads CL->OL throttle and BPW descriptors.");

        // Front O2 sensor scaling (ADC processing)
        count += labelComment(0x00058902, "frontO2_scaling_lookup",
            "Front O2 sensor scaling table lookup. Accesses descriptor near 0xAF468.");
        count += labelComment(0x00004A2C, "frontO2_scaling_init",
            "Front O2 sensor scaling initialization/read. Accesses descriptor near 0xAF45C.");

        // AFC (Short-Term Fuel Correction) Pipeline
        count += labelComment(0x00033304, "afc_dispatcher",
            "CL fueling master controller. Sequences: target comp -> sensor prep -> PI controller -> clamp. Entry at 0x33304 with reg saves.");
        count += labelComment(0x00033D1C, "cl_fuel_target_B",
            "CL Fueling Target Comp B (load-based). Called from afc_dispatcher via BSR.");
        count += labelComment(0x00033CC0, "cl_fuel_target_A",
            "CL Fueling Target Comp A (load-based). Called from afc_dispatcher via BSR.");
        count += labelComment(0x00033658, "afc_sensor_prep",
            "AFC sensor state preparation/conditioning. Reads 0xFFFF7828, calls 0x22CF4.");
        count += labelComment(0x00033FCE, "afc_target_calc",
            "AFC target computation with compensation. Table lookups via 0xBE598/0xBE8E4. Outputs to 0xFFFF782C.");
        count += labelComment(0x00033DBE, "afc_cl_decision",
            "CL/OL AFC decision & hysteresis. GBR=0xFFFF77F4. CL check via 0x22F92. Active: correction from 0xACE8C. Inactive: writes 0.0. Thresholds 0xCBFD0-0xCBFE4.");
        count += labelComment(0x000340A0, "afc_pi_output",
            "AFC PI output stage. P-gains: 0xACEA0(load),0xACEB4(RPM). I-gains: 0xACEC8(load),0xACEDC(RPM). Blend: out=P*alpha+I*(1-alpha). Output: 0xFFFF7870.");
        count += labelComment(0x000342A8, "afc_pi_controller",
            "AFC PI controller - THE SHORT-TERM CORRECTION. Computes error (fsub), looks up gain (0xBEAB0), clamps to limits. ROM 0xCC000-0xCC00C. Output: 0xFFFF7864.");
        count += labelComment(0x0003439E, "afc_enable_gate",
            "AFC enable/disable gate. Calls 0x2BE2C/0x2BE38. Reads ROM 0xCC010.");
        count += labelComment(0x000343CE, "afc_output_clamp",
            "AFC output clamp. Upper=200% (0xCC014), Lower=190% (0xCC018). Reads/writes 0xFFFF7820.");
        count += labelComment(0x000320AE, "fuel_correction_final",
            "Final fuel correction accumulator. Combines AFC (0xFFFF77C8) + LTFT + enrichments into IPW multiplier.");

        // Undocumented pointer table
        count += labelComment(0x0008D838, "ptr_table_8D838",
            "Pointer table - purpose TBD (found in Ghidra analysis)");

        // =====================================================================
        // GENERIC TABLE PROCESSOR LIBRARY (0xBE608-0xBECA8)
        // =====================================================================

        // Float utility functions
        count += labelComment(0x000BE608, "float_deadband_check",
            "Returns 1 if |fr4-fr5| > fr6 (hysteresis/deadband comparison)");
        count += labelComment(0x000BE628, "float_safe_div",
            "fr4/fr5 with zero-division guard. If fr5==0: returns +/-max based on sign of fr4");
        count += labelComment(0x000BE800, "float_clamp_with_step",
            "Soft clamp from above. If fr4>fr5: 1, if fr4>fr5-fr6: 0, else: fr4");
        count += labelComment(0x000BE960, "float_max",
            "Returns max(fr4, fr5). Called by PI controller for I-term floor");
        count += labelComment(0x000BE970, "float_min",
            "Returns min(fr4, fr5). Called by PI controller for I-term cap");
        count += labelComment(0x000BEA40, "float_lerp",
            "Linear interpolation with NaN guard. result = fr4 + (fr5-fr4)*(1-fr6), convergence check via fr7");
        count += labelComment(0x000BEAB0, "float_abs_diff",
            "Returns |fr4 - fr5|. Called by PI controller for error magnitude");

        // Integer utility functions
        count += labelComment(0x000BE654, "int32_div_sat",
            "32-bit unsigned divide with saturation. Unrolled 32-iter div1 loop. Saturates at +/-0x7FFFFFFF");
        count += labelComment(0x000BE980, "uint8_unpack",
            "Extracts size from packed hi:~lo byte pair");
        count += labelComment(0x000BE990, "uint16_unpack",
            "Extracts size from packed hi:~lo word pair");
        count += labelComment(0x000BE9A0, "uint8_pack",
            "Packs byte into hi:~lo complement format");
        count += labelComment(0x000BE9B0, "uint16_pack",
            "Packs word into hi:~lo complement format");
        count += labelComment(0x000BE9C0, "int32_fixmul",
            "Signed 32x32 fixed-point multiply via dmuls.l, right-shift 14 bits");
        count += labelComment(0x000BEA6C, "int_fixpoint_lerp",
            "Integer fixed-point interpolation. result = r4 + (r5-r4)*frac, frac from uint16 r6");
        count += labelComment(0x000BEA98, "int_sat_sub",
            "Saturating subtraction r4-r5, clamps at +/-0x7FFFFFFF on overflow");
        count += labelComment(0x000BEAB8, "int_count_shifts",
            "Counts shift iterations until r5 >= r4*8");

        // Top-level 1D descriptor processors
        count += labelComment(0x000BE830, "table_desc_1d_float",
            "1D descriptor lookup, float output. Calls LowPW_AxisLookup + type-dispatched interp via 0xBE860. "
            + "Types: 0=f32, 1=i8, 2=i16, 3=u8, 4=u16. Used by afc_pi_output for P/I gain tables");
        count += labelComment(0x000BE874, "LowPW_TableProcessor",
            "1D descriptor lookup, uint8->int return. Calls LowPW_AxisLookup + interp_1d_uint8, ftrc to int");
        count += labelComment(0x000BE8AC, "table_desc_1d_uint16",
            "1D descriptor lookup, uint16->int return. Calls LowPW_AxisLookup + interp_1d_uint16, ftrc to int");

        // Top-level 2D descriptor processors
        count += labelComment(0x000BE88C, "table_desc_2d_uint8",
            "2D descriptor lookup, uint8 data. Calls axis_lookup_2d + interp_1d_uint8_int");
        count += labelComment(0x000BE8C4, "table_desc_2d_uint16",
            "2D descriptor lookup, uint16 data. Calls axis_lookup_2d + interp_1d_uint16_int");
        count += labelComment(0x000BE8E4, "table_desc_2d_typed",
            "2D descriptor lookup, type-dispatched. Calls axis_lookup_2d_typed. Jump table at 0xBE916. "
            + "Supports fmac correction. Used by afc_pi_output for 2D I-component table");
        count += labelComment(0x000BE928, "table_desc_2d_uint8_int",
            "2D descriptor, uint8 data, integer return. Calls axis_lookup_2d_typed + interp_2d_uint8");
        count += labelComment(0x000BE944, "table_desc_2d_uint16_int",
            "2D descriptor, uint16 data, integer return. Calls axis_lookup_2d_typed + interp_2d_uint16");

        // 1D data interpolation routines
        count += labelComment(0x000BEACC, "interp_1d_float32",
            "1D float32 interpolation. fmac-based: result = a + frac*(b-a)");
        count += labelComment(0x000BEAE4, "interp_1d_int8",
            "1D signed int8 interpolation with float conversion");
        count += labelComment(0x000BEB00, "interp_1d_int16",
            "1D signed int16 interpolation with float conversion");
        count += labelComment(0x000BEB20, "interp_1d_uint8",
            "1D unsigned uint8 interpolation with float conversion");
        count += labelComment(0x000BEB40, "interp_1d_uint8_int",
            "1D unsigned uint8 integer interpolation (no float). Uses dmulu.l for fractional part");
        count += labelComment(0x000BEB6C, "interp_1d_uint16",
            "1D unsigned uint16 interpolation with float conversion");
        count += labelComment(0x000BEB90, "interp_1d_uint16_int",
            "1D unsigned uint16 integer interpolation (no float)");

        // 2D bilinear interpolation routines
        count += labelComment(0x000BEBC0, "interp_2d_float32",
            "2D bilinear interpolation, float32 data. Two 1D interps + fmac cross-blend");
        count += labelComment(0x000BEBF0, "interp_2d_int8",
            "2D bilinear interpolation, int8 data");
        count += labelComment(0x000BEC1C, "interp_2d_int16",
            "2D bilinear interpolation, int16 data");
        count += labelComment(0x000BEC4C, "interp_2d_uint8",
            "2D bilinear interpolation, uint8 data");
        count += labelComment(0x000BEC78, "interp_2d_uint16",
            "2D bilinear interpolation, uint16 data");

        // Axis lookup routines
        count += labelComment(0x000BECA8, "LowPW_AxisLookup",
            "1D axis binary search. Input: r0=size, r1=axis_ptr, fr0=value. Output: r0=index, fr0=frac");
        count += labelComment(0x000BECDC, "axis_lookup_2d",
            "2D axis lookup (two sequential 1D searches)");
        count += labelComment(0x000BED98, "axis_lookup_2d_typed",
            "2D axis lookup with type-aware data stride");

        // =====================================================================
        // ROM CONSTANTS (FLKC literal pool)
        // =====================================================================
        count += labelComment(0x00045DD8, "PATH_J_HALFSTEP_MULT",
            "0x3F000000 = 0.5. Path J multiplier. Change to 0x3F800000 (1.0) for full-step.");
        count += labelComment(0x000D2F40, "FLKC_FG_LIMIT_100",
            "0x42C80000 = 100.0 (FR15 upper limit)");
        count += labelComment(0x000D2F44, "tbl_d2f44_8p0",
            "0x41000000 = 8.0");
        count += labelComment(0x000D2F48, "tbl_d2f48_0p25",
            "0x3E800000 = 0.25");
        count += labelComment(0x000D2F4C, "tbl_d2f4c_n15",
            "0xC1700000 = -15.0");
        count += labelComment(0x000D2F50, "FLKC_RETARD_STEP",
            "0x3F8147AE = 1.01 (Path F & G retard step)");
        count += labelComment(0x000D2F54, "tbl_d2f54_0p35",
            "0x3EB33333 = 0.35");
        count += labelComment(0x000D2F58, "tbl_d2f58_0p35",
            "0x3EB33333 = 0.35");
        count += labelComment(0x000D2F5C, "tbl_d2f5c_1p40",
            "0x3FB33333 = 1.40");
        count += labelComment(0x000D2F60, "tbl_d2f60_1p40",
            "0x3FB33333 = 1.40");
        count += labelComment(0x000D2F64, "FLKC_RETARD_BANK1",
            "0x40333333 = 2.80 (Path F bank-1 retard step)");
        count += labelComment(0x000D2F68, "tbl_d2f68_2p80",
            "0x40333333 = 2.80");

        // =====================================================================
        // RAM VARIABLES
        // =====================================================================
        count += labelComment(0xFFFF80FC, "knock_det_GBR_base",
            "GBR base for knock_detector");
        count += labelComment(0xFFFF81BA, "KNOCK_FLAG",
            "1=knock detected, 0=no knock (per cycle)");
        count += labelComment(0xFFFF81BB, "KNOCK_BANK_FLAG",
            "Bank selector: 1=bank1, 0=bank0");
        count += labelComment(0xFFFF81D9, "fn_043d68_output",
            "Written by task [12], NOT the knock flag");
        count += labelComment(0xFFFF323C, "FLKC_BASE_STEP",
            "Base correction step (float), = 0.5 stock");
        count += labelComment(0xFFFF8290, "flkc_fg_GBR_base",
            "GBR base for flkc_paths_FG");
        count += labelComment(0xFFFF8294, "flkc_fg_counter",
            "Cycle counter, must be >= 90 for F/G paths");
        count += labelComment(0xFFFF8298, "flkc_fg_cyl_index",
            "Current cylinder/bank index");
        count += labelComment(0xFFFF829C, "flkc_fg_active",
            "Active flag; cleared on knock entry");
        count += labelComment(0xFFFF829D, "flkc_fg_retard_done",
            "Set to 1 after retard applied");
        count += labelComment(0xFFFF829E, "flkc_fg_enable",
            "Must == 1 to enter main logic");
        count += labelComment(0xFFFF82A0, "flkc_fg_exit_flag",
            "Set to 1 at normal exit");
        count += labelComment(0xFFFF82A1, "flkc_fg_bank_route",
            "Routes post-retard clamp fn call");
        count += labelComment(0xFFFF82AA, "flkc_fg_prev_cyl",
            "Previous cylinder; must match for retard");
        count += labelComment(0xFFFF8258, "flkc_fg_limit_FR15",
            "Loaded into FR15, compared vs 100.0");
        count += labelComment(0xFFFF3234, "flkc_fg_ref_FR14",
            "Loaded into FR14 at entry");
        count += labelComment(0xFFFF3244, "flkc_fg_R0_init",
            "Early R0 setup");
        count += labelComment(0xFFFF3248, "flkc_fg_var_3248",
            "Read in setup");
        count += labelComment(0xFFFF8233, "flkc_fg_flag_8233",
            "Byte flag checked during FP setup");
        count += labelComment(0xFFFF7D18, "sched_status_R1",
            "Read at fn_0463ba (flkc_paths_FG) entry");
        count += labelComment(0xFFFF3360, "flkc_output_table",
            "FLKC output (word array indexed by cylinder)");
        count += labelComment(0xFFFF8EDC, "sched_disable_flag",
            "If != 0, entire scheduler dispatch is skipped");

        // =====================================================================
        // FUELING - IAM SWITCH & FAILSAFE
        // =====================================================================
        count += labelComment(0x000CC16C, "PrimaryOL_FuelMapSwitch_IAM",
            "IAM thresholds for failsafe fuel map switch. Thresh1=0.5 (begin), Thresh2=0.05 (full)");
        count += labelComment(0x000D05C4, "PrimaryOL_Fueling_Failsafe",
            "Failsafe fuel map. Max raw=0x46(70)->AFR 9.50. Root cause of 10.02 AFR at 2000RPM/2.60g/rev.");

        // =====================================================================
        // POST START ENRICHMENT DESCRIPTORS
        // =====================================================================
        count += labelComment(0x000CC624, "PSE_CT_Axis_1",
            "PSE Coolant Temp axis 1 - 16 float32, -40 to 110 deg F (used by 12 tables)");
        count += labelComment(0x000CC664, "PSE_CT_Axis_2",
            "PSE Coolant Temp axis 2 - 16 float32, -40 to 110 deg F (used by LSD Delay 2)");
        count += label(0x000AC948, "PSE_Desc_LSD_Initial_1A");
        count += label(0x000AC95C, "PSE_Desc_LSD_Initial_1B");
        count += label(0x000AC970, "PSE_Desc_LSD_Initial_2A");
        count += label(0x000AC984, "PSE_Desc_LSD_Initial_2B");
        count += label(0x000AC998, "PSE_Desc_LSD_Delay_1");
        count += label(0x000AC9A4, "PSE_Desc_HSD_InitStart_1A");
        count += label(0x000AC9E0, "PSE_Desc_HSD_InitStart_1B");
        count += label(0x000ACA08, "PSE_Desc_HSD_InitStart_2A");
        count += label(0x000ACA44, "PSE_Desc_HSD_InitStart_2B");
        count += label(0x000ACA6C, "PSE_Desc_LSD_Delay_2");
        count += label(0x000ACA78, "PSE_Desc_HSD_StepValue_1");
        count += label(0x000ACAA0, "PSE_Desc_HSD_StepValue_2");
        count += label(0x000ACAF0, "PSE_Desc_LSD_DelayMult");

        // PSE data tables
        count += label(0x000CD3A6, "PSE_LSD_Initial_1A");
        count += label(0x000CD3C6, "PSE_LSD_Initial_1B");
        count += label(0x000CD3E6, "PSE_LSD_Initial_2A");
        count += label(0x000CD406, "PSE_LSD_Initial_2B");
        count += label(0x000CD426, "PSE_LSD_Delay_1");
        count += label(0x000CD446, "PSE_HSD_InitStart_1A");
        count += label(0x000CD4A6, "PSE_HSD_InitStart_1B");
        count += label(0x000CD4E6, "PSE_HSD_InitStart_2A");
        count += label(0x000CD546, "PSE_HSD_InitStart_2B");
        count += label(0x000CD586, "PSE_LSD_Delay_2");
        count += label(0x000CD5A6, "PSE_HSD_StepValue_1");
        count += label(0x000CD5E6, "PSE_HSD_StepValue_2");
        count += label(0x000CD666, "PSE_LSD_DelayMult");

        // =====================================================================
        // AVCS DUTY CORRECTION
        // =====================================================================
        count += labelComment(0x000AD620, "AVCS_IntakeDutyCorr_Desc",
            "28-byte descriptor: bias=0, dims=10x9, Y=0xCF9EC, X=0xCFA14, data=0xCFA38, uint8, scale=0.2");
        count += label(0x000CF9EC, "AVCS_Intake_VVTError_Axis");
        count += label(0x000CFA14, "AVCS_Intake_RPM_Axis");
        count += labelComment(0x000CFA38, "AVCS_IntakeDutyCorrA",
            "90 uint8, 10x9, physical = raw * 0.2 degrees");

        count += labelComment(0x000AD848, "AVCS_ExhaustDutyCorr_Desc",
            "28-byte descriptor: bias=0, dims=10x9, Y=0xD11D0, X=0xD11F8, data=0xD121C, uint16, scale=0.000061");
        count += label(0x000D11D0, "AVCS_Exhaust_VVTError_Axis");
        count += label(0x000D11F8, "AVCS_Exhaust_RPM_Axis");
        count += labelComment(0x000D121C, "AVCS_ExhaustDutyCorrA",
            "90 uint16, 10x9, physical = raw * 0.003051758 - 100 degrees");

        // =====================================================================
        // LOW PULSE WIDTH INJECTOR COMPENSATION
        // =====================================================================
        count += labelComment(0x000D2D20, "LowPW_GateThresh_FR8_Max",
            "Max FR8 gate threshold for Low PW comp (float)");
        count += labelComment(0x000D3988, "LowPW_BasePW_Axis",
            "Y axis - 8 float32: 0.7 to 4.5 ms");
        count += labelComment(0x000D39A8, "LowPW_InjectorComp_Data",
            "8 x uint8, scaling: InjectorPulseWidthCompensation");
        count += labelComment(0x000D2D28, "LowPW_MaxRPM",
            "Max RPM gate (float). Currently 10000 = feature disabled.");
        count += labelComment(0x000D2D2C, "LowPW_MaxIPW",
            "Max IPW gate (float). Currently 10000 raw = 10.0 ms = feature disabled.");

        // =====================================================================
        // DTC TABLE
        // =====================================================================
        count += labelComment(0x0009A770, "DTC_Table_Start",
            "93 OBD-II DTC entries (0x9A770-0x9A82B). First: P0335 Crankshaft Pos Sensor A");

        // =====================================================================
        // CALIBRATION TABLES - KEY ENTRIES
        // =====================================================================

        // Boost control
        count += label(0x000C009E, "WastegateDutyCycleFreq");
        count += label(0x000C0F58, "MaxWastegateDuty");
        count += label(0x000C1150, "InitialWastegateDuty");
        count += label(0x000C1340, "TargetBoost");
        count += label(0x000D2560, "BoostLimit_FuelCut");

        // Fueling
        count += label(0x000CBE0C, "InjectorFlowScaling");
        count += label(0x000D0244, "PrimaryOL_KCA_Low");
        count += label(0x000D0404, "PrimaryOL_KCA_High");
        count += label(0x000CFD30, "PrimaryOL_KCA_Alternate");
        count += label(0x000D106C, "InjectorLatency");

        // Rev/speed limits
        count += label(0x000CC500, "RevLimitOn");
        count += label(0x000CC504, "RevLimitOff");
        count += label(0x000CC520, "SpeedLimitEnable_FuelCut");

        // Ignition timing
        count += label(0x000D4714, "BaseTimingPrimaryCruise");
        count += label(0x000D48D4, "BaseTimingPrimaryNonCruise");
        count += label(0x000D2EE0, "AdvanceMultiplier_Initial");
        count += label(0x000D2EE4, "AdvanceMultiplier_StepValue");
        count += label(0x000D2F0C, "FineCorrection_Rows_RPM");
        count += label(0x000D2F28, "FineCorrection_Cols_Load");

        // Knock control
        count += label(0x000D2DC8, "FeedbackCorr_RetardLimit");
        count += label(0x000D2DCC, "FeedbackCorr_RetardValue");
        count += label(0x000D2DD0, "FeedbackCorr_NegAdvanceValue");
        count += label(0x000D2F44, "FineCorr_AdvanceLimit");
        count += label(0x000D2F48, "FineCorr_AdvanceValue");
        count += label(0x000D2F4C, "FineCorr_RetardLimit");
        count += label(0x000D2F50, "FineCorr_RetardValue");

        // Map switching
        count += label(0x000D29AC, "MapSwitch_CruiseSwitchCounterA");
        count += label(0x000D2A08, "MapSwitch_EngineSpeedThreshold");
        count += label(0x000D2A74, "MapSwitch_PerGearRPM_1");

        // Timing blend
        count += label(0x000D2AE8, "TimingBlend_LookupThreshold");
        count += label(0x000D2AFC, "TimingBlend_CorrectionOffset");

        // Engine torque (DBW)
        count += label(0x000C1800, "CalcEngineTorqueA");
        count += label(0x000C1A80, "CalcEngineTorqueB");
        count += label(0x000C1D00, "CalcEngineTorqueC");
        count += label(0x000C1F80, "CalcEngineTorqueD");

        // MAF / load
        count += label(0x000C3100, "MAFLimit_Max");
        count += label(0x000C3608, "EngineLoadLimitB_Max_RPM");

        // Cranking fuel
        count += label(0x000CD2E6, "CrankingFuel_IPW_A");
        count += label(0x000CD306, "CrankingFuel_IPW_B");
        count += label(0x000CD326, "CrankingFuel_IPW_C");
        count += label(0x000CD346, "CrankingFuel_IPW_D");
        count += label(0x000CD366, "CrankingFuel_IPW_E");
        count += label(0x000CD386, "CrankingFuel_IPW_F");

        // =====================================================================
        // TRANSIENT FUEL CONTROL — TIP-IN ENRICHMENT
        // =====================================================================
        // Throttle-rate based: fires on rising throttle angle change.
        // Output: additional IPW (ms) added to base pulse width.
        count += label(0x000CED08, "TipIn_ThrottleAngleChange_Axis");
        count += label(0x000CED50, "TipInEnrichA");
        count += label(0x000CEDBC, "TipInEnrichB");
        count += label(0x000CD0D8, "TipIn_RPMComp_Axis");
        count += label(0x000CD118, "TipIn_RPMComp");
        count += label(0x000CD14C, "TipIn_BoostErrorComp");
        count += label(0x000CD155, "TipIn_ECTComp_A");
        count += label(0x000CEDE0, "TipIn_ECTComp_B");
        count += label(0x000CEE00, "TipIn_ECTComp_C");
        count += label(0x000CEE40, "TipIn_ECTComp_D");
        count += label(0x000CC4A0, "TipIn_MinThrottleActivation");
        count += label(0x000CC4A4, "TipIn_MinIPWActivation");
        count += label(0x000CBC08, "TipIn_AppliedCounterReset");
        count += label(0x000CD165, "TipIn_DisableCounter_A");
        count += label(0x000CD175, "TipIn_DisableCounter_B");
        count += label(0x000CEE60, "TipIn_CumulativeThreshold_A");
        count += label(0x000CEE80, "TipIn_CumulativeThreshold_B");

        // =====================================================================
        // TRANSIENT FUEL CONTROL — TAU (ALPHA TRANSIENT FUELING)
        // =====================================================================
        // Load-rate based: fires on engine load changes (rising AND falling).
        // Output: enrichment adder multiplier (dimensionless), scales base adder.
        // Trigger: delta(engine_load) per cycle (g/rev change rate).
        // Complements tip-in: tip-in fires first (throttle moves), tau fires
        // second (load follows with turbo lag). Tau also handles tip-OUT
        // (falling load) which tip-in does not.
        count += labelComment(0x000CCDCC, "Tau_RisingLoad_Axis",
            "Tau rising load axis: 3 float32 engine load breakpoints (g/rev).");
        count += labelComment(0x000CD6E6, "Tau_RisingLoad_A",
            "Tau rising load enrichment: 3x16 uint16 map (load x ECT). Scale 0.00048828125. "
            + "Cold=3.40x at -40F, warm=0.32x at 176F+.");
        count += labelComment(0x000CD746, "Tau_FallingLoad",
            "Tau falling load (decel): 16 uint16, ECT-indexed. Scale 0.00048828125. "
            + "Handles fuel film evaporation during falling load.");
        count += label(0x000CD766, "Tau_FallingLoad_A");
        count += label(0x000CD848, "Tau_FallingLoad_B");
        count += label(0x000CD868, "Tau_FallingLoad_C");

        // =====================================================================
        // TRANSIENT FUEL CONTROL — ACCELERATION ENRICHMENT
        // =====================================================================
        // Separate from tip-in: applies additional fuel during accel events.
        count += label(0x000CC51C, "AccelEnrich_TipInGain");
        count += label(0x000CC530, "AccelEnrich_TipOutGain");
        count += label(0x000CBC0B, "AccelEnrich_Cal_A");
        count += label(0x000CBC0C, "AccelEnrich_Cal_B");

        // =====================================================================
        // TRANSIENT FUEL CONTROL — OVERRUN (DECELERATION) FUEL CUTOFF
        // =====================================================================
        // Monitors RPM delta and airflow to trigger fuel cut on deceleration.
        count += labelComment(0x000CC498, "Overrun_RPMDelta_Activation",
            "RPM change threshold to trigger decel fuel cut mode.");
        count += labelComment(0x000CC49C, "Overrun_InitialEnrichment",
            "Initial injector enrichment on decel entry (ms pulse width adder).");
        count += labelComment(0x000CC4EC, "Overrun_FuelCut_RPMThreshold",
            "RPM below which overrun fuel cut applies.");
        count += labelComment(0x000CEED0, "Overrun_FuelResume_RPMThreshold",
            "RPM at which fuel resumes after overrun cut.");
        count += label(0x000D29AA, "Overrun_Cutoff_Cal");

        // Idle timing
        count += label(0x000D319D, "BaseTimingIdleMin");
        count += label(0x000D31A6, "BaseTimingIdleA_InGear");
        count += label(0x000D31C6, "BaseTimingIdleA_Neutral");

        // Per-gear timing comp
        count += label(0x000D5394, "TimingComp_Gear1");
        count += label(0x000D53C4, "TimingComp_Gear2");
        count += label(0x000D53F4, "TimingComp_Gear3");
        count += label(0x000D5424, "TimingComp_Gear4");
        count += label(0x000D5454, "TimingComp_Gear5");

        // Per-cylinder timing comp
        count += label(0x000D54B0, "TimingComp_CylA");
        count += label(0x000D5544, "TimingComp_CylB");
        count += label(0x000D55D8, "TimingComp_CylC");
        count += label(0x000D5670, "TimingComp_CylD");

        // =====================================================================
        // AFC / CLOSED-LOOP FUELING — DISPATCH TABLES
        // =====================================================================
        count += labelComment(0x000480B8, "fuel_dispatch_table_A",
            "Secondary dispatch table: 8 fueling function pointers (CL target, AFL, CL/OL transition)");
        count += labelComment(0x0004A0B8, "fuel_dispatch_table_B",
            "Secondary dispatch table: 6+ fueling function pointers (main loop, AFL core, OL map select)");

        // =====================================================================
        // AFC / CLOSED-LOOP FUELING — CODE FUNCTIONS
        // =====================================================================
        count += labelComment(0x000332A2, "fuel_main_entry",
            "Main fueling entry (non-returning). Dispatched from fuel_dispatch_table_B.");
        count += labelComment(0x00033278, "fuel_precalc",
            "Fueling pre-calculation. Dispatched from fuel_dispatch_table_A.");
        count += labelComment(0x0003452A, "afl_core_entry",
            "A/F Learning core entry. Calls CL active check, range selection, value update. Dispatch B.");
        count += labelComment(0x000344BA, "afl_range_loop",
            "A/F Learning 4-range loop. Iterates ranges A-D at FFFF316C, 8-byte stride.");
        count += labelComment(0x000344EE, "afl_validity_check",
            "A/F Learning range validity check. Iterates 4 ranges, calls 0xBDCB6.");
        count += labelComment(0x000345A4, "cl_active_check",
            "CL Active Check: 10-condition gate. Returns 1=CL active (learning OK), 0=inactive. "
            + "Checks FFFF8F24, CC020 (MAF<=70g/s), FFFF73A4, FFFF7354, FFFF7374, "
            + "FFFF7A14, FFFF7A20, FFFF7D18, FFFF7BE2.");
        count += labelComment(0x00034488, "afl_sub_dispatcher",
            "A/F Learning sub-dispatcher. Dispatched from fuel_dispatch_table_A.");
        count += labelComment(0x00034EC8, "afl_airflow_processor",
            "A/F Learning airflow range processor. Dispatch A. Refs CC074-CC090.");
        count += labelComment(0x00034EF4, "afl_airflow_update",
            "A/F Learning airflow update. Dispatched from fuel_dispatch_table_B.");
        count += labelComment(0x000357D0, "clol_transition_sub_B",
            "CL/OL transition sub B. Dispatched from fuel_dispatch_table_A.");
        count += labelComment(0x0003580C, "clol_transition_core",
            "CL/OL transition core. Dispatched from fuel_dispatch_table_B.");
        count += labelComment(0x00036008, "clol_delay_manager_A",
            "CL/OL delay manager A. Dispatched from fuel_dispatch_table_A.");
        count += labelComment(0x0003605E, "ol_fuel_map_selector",
            "OL fuel map selector. Reads IAM from FFFF3234, compares vs CC16C (0.5). Dispatch B.");
        count += labelComment(0x00036A98, "clol_hysteresis_handler",
            "CL/OL hysteresis handler. Refs CC178 (throttle hyst), CC174 (BPW hyst). Dispatch A.");
        count += labelComment(0x00036BF4, "clol_delay_manager_B",
            "CL/OL delay manager B. Dispatched from fuel_dispatch_table_A.");
        count += labelComment(0x00036C3C, "clol_state_cleanup",
            "CL/OL state cleanup. Dispatched from fuel_dispatch_table_B.");
        count += labelComment(0x00036E60, "fuel_post_transition",
            "Post-transition handler. Dispatched from fuel_dispatch_table_A.");

        // =====================================================================
        // TRANSIENT FUEL CONTROL — CODE FUNCTIONS (Pipeline B)
        // =====================================================================
        count += labelComment(0x00037186, "fuel_transient_comp",
            "Transient fuel compensation (tip-in/out). Reads FFFF7D68/6C, cal 0xC4200. Pipeline B.");
        count += labelComment(0x00037B68, "fuel_injector_comp",
            "Injector compensation. 2D maps 0xAC648/634, RPM/load indexed. Pipeline B.");
        count += labelComment(0x00039528, "fuel_wot_enrich_calc",
            "WOT enrichment factor calculation. 2D map 0xAD258. Pipeline B.");
        count += labelComment(0x0003BB6C, "fuel_accel_enrich",
            "Acceleration enrichment. Tip-in/out gains CC51C-530, cal 0xCBC0B/0C. Pipeline B.");
        count += labelComment(0x0003CD34, "fuel_warmup_enrich",
            "Warmup/cold-start enrichment. Reads ECT FFFF69FC, IAT FFFF69F0. Pipeline B.");
        count += labelComment(0x0003EB8C, "fuel_overrun_cutoff",
            "Overrun fuel cutoff. RPM/airflow thresholds, cal 0xD29AA, tail-calls 0x46BCC. Pipeline B.");

        // =====================================================================
        // AFC / CLOSED-LOOP FUELING — CALIBRATION TABLES
        // =====================================================================
        count += labelComment(0x000CC064, "AFL_Limits_Min",
            "A/F Learning #1 Limits Min = -0.250 (-25%). Float.");
        count += labelComment(0x000CC068, "AFL_Limits_Max",
            "A/F Learning #1 Limits Max = +0.250 (+25%). Float.");
        count += labelComment(0x000CC074, "AFL_AirflowRanges",
            "A/F Learning #1 Airflow Ranges: A=6-23, B=40-80, C=0.95-1.05, D=35-0(disabled) g/s. 8 floats.");
        count += labelComment(0x000CC020, "CL_MAF_Threshold",
            "MAF threshold for CL learning enable = 70.0 g/s. Float.");
        count += labelComment(0x000CBF9C, "CL_FuelTarget_ECT_Disable",
            "CL Fuel Target ECT Disable = 119.0 degF. Above this, ECT comp stops. Float.");
        count += labelComment(0x000CBC62, "CL_to_OL_Delay",
            "CL to OL Delay (base) = 0.0. ZERO = immediate CL->OL transition. Float.");
        count += labelComment(0x000CBC5C, "CL_to_OL_Delay_SIDRIVE",
            "CL to OL Delay SI-DRIVE Intelligent = 0.0. Float.");
        count += labelComment(0x000CBC5A, "CL_Delay_EngLoadCounterThresh",
            "CL Delay Engine Load Counter Threshold.");
        count += labelComment(0x000CC178, "CLOL_Throttle_Hysteresis",
            "CL->OL Throttle Hysteresis = 8.4 deg. Float.");
        count += labelComment(0x000CC174, "CLOL_BPW_Hysteresis",
            "CL->OL BPW Hysteresis = 756.0. Float.");
        count += labelComment(0x000CC17C, "CL_Delay_Min_ECT",
            "CL Delay Minimum ECT = -12.0 degF. Below this, CL delay cleared. Float.");
        count += labelComment(0x000CC180, "CL_Delay_MaxRPM_PerGear",
            "CL Delay Max Engine Speed Per Gear. 10 floats, 3200-3700 RPM.");
        count += labelComment(0x000CC1A8, "CL_Delay_MaxRPM_Neutral",
            "CL Delay Max Engine Speed Neutral. 6 floats, 6000-6100 RPM.");
        count += labelComment(0x000CC1D8, "CL_Delay_Max_Throttle",
            "CL Delay Max Throttle = 37.9-90.0 deg. 4 floats.");
        count += labelComment(0x000CC1F4, "CL_Delay_Max_VehSpeed",
            "CL Delay Max Vehicle Speed. 4 floats.");
        count += labelComment(0x000CC204, "CL_Delay_Max_EngLoad",
            "CL Delay Max Engine Load = 0.95-1.10 g/rev. 4 floats.");
        count += label(0x000CCD78, "CLOL_Delay_Throttle_Threshold");
        count += label(0x000CE5F8, "CLOL_Delay_BPW_Threshold");
        count += label(0x000CE640, "CLOL_CounterStep_MAF");
        count += labelComment(0x000D14D0, "CL_FuelTarget_CompA_Load",
            "CL Fueling Target Comp A (Load). 3D table, AFR additive adj. Typical -0.01 to -0.61.");
        count += label(0x000D1740, "CL_FuelTarget_CompB_Load");
        count += label(0x000D13B0, "CL_FuelTarget_Comp_ImmCruise_ECT");
        count += label(0x000D141C, "CL_FuelTarget_Comp_ImmNonCruise_ECT");

        // Front O2 Sensor
        count += labelComment(0x00021CAC, "FrontO2_RichLimit",
            "Front Oxygen Sensor Rich Limit = lambda 0.750 (AFR 11.02). Float.");
        count += labelComment(0x000D8D74, "FrontO2_Scaling_Yaxis",
            "Front O2 sensor scaling Y-axis: 13 float mA values, -1.3 to 0.74 mA (wideband).");
        count += labelComment(0x000D8DA8, "FrontO2_Scaling_Data",
            "Front O2 sensor scaling: 13 float lambda values, 0.7586-1.3793 (AFR 11.15-20.28).");
        count += labelComment(0x000C3708, "FrontO2_Comp_AtmPressure",
            "Front O2 atmospheric pressure compensation. Formula: ((AFR-14.7)*comp)+14.7.");

        // AFC P/I Gain Descriptors (UNDOCUMENTED — found via afc_pi_output decompilation)
        count += labelComment(0x000ACEA0, "AFC_PGain_A_Desc",
            "AFC P-gain A descriptor (1D by RPM). Used by afc_pi_output proportional chain.");
        count += labelComment(0x000ACEB4, "AFC_PGain_B_Desc",
            "AFC P-gain B descriptor (1D by coolant temp). Used by afc_pi_output proportional chain.");
        count += labelComment(0x000AC4FC, "AFC_PNorm_Desc",
            "AFC P normalizer descriptor (1D by airflow). Scales combined P gains.");
        count += labelComment(0x000AD928, "AFC_IComp_2D_Desc",
            "AFC I-component descriptor (2D: engine load x MAF). Used by afc_pi_output integral chain.");
        count += labelComment(0x000ACEC8, "AFC_IGain_A_Desc",
            "AFC I-gain A descriptor (1D by RPM). Used by afc_pi_output integral chain.");
        count += labelComment(0x000ACEDC, "AFC_IGain_B_Desc",
            "AFC I-gain B descriptor (1D by coolant temp). Used by afc_pi_output integral chain.");
        count += labelComment(0x000AC510, "AFC_INorm_Desc",
            "AFC I normalizer descriptor (1D by airflow). Scales combined I gains.");

        // AFC Alpha Blend Thresholds (UNDOCUMENTED — found via afc_pi_output decompilation)
        count += labelComment(0x000CBFF4, "AFC_AlphaActivation",
            "Alpha blend activation threshold. When exceeded, alpha=1.0 (full P weight). Float.");
        count += labelComment(0x000CBFF8, "AFC_AlphaStepUp",
            "Alpha blend step-up value. Added to alpha per cycle when condition met. Float.");
        count += labelComment(0x000CBFFC, "AFC_AlphaStepDown",
            "Alpha blend step-down value. Subtracted from alpha per cycle (default decay). Float.");

        // AF 3 Correction (rear O2 - disabled)
        count += labelComment(0x00035FFC, "AF3_CorrectionLimits",
            "AF 3 Correction Limits = 0.0/0.0 (DISABLED). Setting to 0 disables rear O2 input on target AFR.");

        // =====================================================================
        // AFC / CLOSED-LOOP FUELING — RAM VARIABLES
        // =====================================================================
        // PI controller internal state (relative to GBR=0xFFFF77C8)
        count += labelComment(0xFFFF7814, "afc_p_term",
            "AFC P-term output. Error value when |error| >= deadzone (2.0), else 0.0. Written by afc_pi_controller.");
        count += labelComment(0xFFFF7818, "afc_i_accum",
            "AFC I-term accumulator. Winds up/down by +/-1.0/cycle, bounded [0, 20%]. Written by afc_pi_controller.");
        count += labelComment(0xFFFF7828, "afc_active_flag",
            "AFC active flag (GBR+0x60). 1=PI controller was active last cycle.");
        count += labelComment(0xFFFF7865, "afc_prev_state",
            "AFC previous-cycle state (GBR+0x9D). Tracks CL/OL mode for transition detection.");
        count += labelComment(0xFFFF782A, "afc_state1_flag",
            "AFC state-1 flag (GBR+0x62). Set to 1 on fresh CL entry.");

        // PI output stage state
        count += labelComment(0xFFFF7838, "afc_p_load_out",
            "AFC P-gain by load output (float). Written by afc_pi_output.");
        count += labelComment(0xFFFF783C, "afc_p_rpm_out",
            "AFC P-gain by RPM output (float). Written by afc_pi_output.");
        count += labelComment(0xFFFF7840, "afc_p_norm_out",
            "AFC P normalizer output (float). Written by afc_pi_output.");
        count += labelComment(0xFFFF7844, "afc_i_2d_out",
            "AFC I-component 2D output (float). Written by afc_pi_output.");
        count += labelComment(0xFFFF7848, "afc_i_load_out",
            "AFC I-gain by load output (float). Written by afc_pi_output.");
        count += labelComment(0xFFFF784C, "afc_i_rpm_out",
            "AFC I-gain by RPM output (float). Written by afc_pi_output.");
        count += labelComment(0xFFFF7850, "afc_i_norm_out",
            "AFC I normalizer output (float). Written by afc_pi_output.");
        count += labelComment(0xFFFF7804, "afc_p_total",
            "AFC P_total = (P_load + P_rpm) * P_norm. Written by afc_pi_output.");
        count += labelComment(0xFFFF7808, "afc_i_total",
            "AFC I_total = (I_2d + I_load + I_rpm) * I_norm. Written by afc_pi_output.");
        count += labelComment(0xFFFF7810, "afc_pi_blend_out",
            "AFC final blend = P_total*alpha + I_total*(1-alpha). Written by afc_pi_output.");
        count += labelComment(0xFFFF8E7E, "afc_enable_flag_A",
            "PI output enable flag A (byte). Must == 1 for afc_pi_output to compute.");
        count += labelComment(0xFFFF85D7, "afc_enable_flag_B",
            "PI output enable flag B (byte). Controls alpha blend activation.");

        // Additional RAM used by fuel_correction_final
        count += labelComment(0xFFFF78B0, "afc_axis_val_A",
            "AFC additional axis value A (float). Input to P/I normalizer lookups.");
        count += labelComment(0xFFFF65FC, "afc_axis_val_B",
            "AFC additional axis value B (float). Alpha activation check input.");
        count += labelComment(0xFFFF68DC, "ram_coolant_alt",
            "Coolant temperature alternate/computed (float). Input to P/I gain lookups.");
        count += labelComment(0xFFFF653C, "ram_sensor_val",
            "Sensor value (float). Read by fuel_correction_final.");
        count += labelComment(0xFFFF7904, "fuel_corr_param_A",
            "Fuel correction parameter A (float). Read by fuel_correction_final.");
        count += labelComment(0xFFFF77D8, "fuel_corr_param_B",
            "Fuel correction parameter B (float). Read by fuel_correction_final.");
        count += labelComment(0xFFFF781C, "fuel_corr_param_C",
            "Fuel correction parameter C (float). Read by fuel_correction_final.");
        count += labelComment(0xFFFF77E4, "fuel_corr_param_D",
            "Fuel correction parameter D (float). Read by fuel_correction_final.");
        count += labelComment(0xFFFF77DC, "fuel_corr_cl_target_A",
            "CL target comp A output (float). Read by fuel_correction_final.");
        count += labelComment(0xFFFF63C4, "ram_engine_param",
            "Engine parameter (float). Read by fuel_correction_final secondary computation.");

        count += labelComment(0xFFFF316C, "afl_table_base",
            "A/F Learning table base in RAM (4 ranges x 8 bytes = 32 bytes)");
        count += labelComment(0xFFFF78A0, "afl_output_struct",
            "A/F Learning output data structure base (~100 bytes). +3=CL active flag.");
        count += labelComment(0xFFFF787F, "afl_airflow_range_idx",
            "Current A/F Learning airflow range index (byte, 0-3: A/B/C/D)");
        count += labelComment(0xFFFF8F24, "cl_global_enable",
            "Global CL enable flag (byte). Must be non-zero for CL fueling.");
        count += labelComment(0xFFFF7BE2, "cl_enable_final",
            "CL enable final check flag (byte). Last gate in cl_active_check.");
        count += labelComment(0xFFFF6350, "ram_RPM",
            "Current engine RPM (float)");
        count += labelComment(0xFFFF63F8, "ram_MAF",
            "Mass air flow (float, g/s)");
        count += labelComment(0xFFFF63CC, "ram_ECT",
            "Coolant temperature / ECT (float)");
        count += labelComment(0xFFFF6624, "ram_MAF_alt",
            "MAF alternate/computed value (float, g/s)");
        count += labelComment(0xFFFF3234, "ram_IAM",
            "Ignition Advance Multiplier current value (float). Also used by FLKC.");

        printf("ImportAE5L600L: Applied %d labels/comments.\n", count);
        printf("Done! ROM is labeled for AE5L600L analysis.\n");
    }

    private int label(long addr, String name) {
        try {
            Address a = toAddr(addr);
            createLabel(a, name, true);
            return 1;
        } catch (Exception e) {
            printf("  WARN: Could not label 0x%08X as %s: %s\n", addr, name, e.getMessage());
            return 0;
        }
    }

    private int labelComment(long addr, String name, String comment) {
        int result = label(addr, name);
        try {
            Address a = toAddr(addr);
            setEOLComment(a, comment);
        } catch (Exception e) {
            printf("  WARN: Could not set comment at 0x%08X: %s\n", addr, e.getMessage());
        }
        return result;
    }
}
