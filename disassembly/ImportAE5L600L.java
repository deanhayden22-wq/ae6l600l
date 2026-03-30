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
        count += labelComment(0x0009A770, "DTC_EnableFlags",
            "93-byte DTC enable/disable table. 0x01=enabled, 0x00=disabled. Indexed by DTC slot (0-92).");
        count += labelComment(0x0009A834, "DTC_DefinitionTable",
            "93-entry DTC struct table. 20 bytes/entry: [W0:class][W1:monitor_id][P-code][W3:subtype][params]. "
            + "P-codes: P0335(CKP), P0102(MAF-Lo), P0103(MAF-Hi), P0327(Knock-Lo), P0328(Knock-Hi), "
            + "P0301-304(Misfire), P0122/123(TPS), P0117/118(ECT), P0420(Cat), P0456(EVAP), P0604(ECM RAM), etc. "
            + "91/93 codes identified. See disassembly/dtc_table.txt for full decode.");

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

        // =====================================================================
        // PERIPHERAL INTERRUPT VECTOR TABLE (VBR = 0x000FFC50)
        // =====================================================================
        count += labelComment(0x000FFC50, "VBR_VectorTable",
            "Peripheral interrupt vector table base. VBR set to this address at 0x0FA40.");

        // ISR stubs (vector table entries point here)
        count += labelComment(0x0000207C, "ISR_IRQ0",
            "IRQ0 external interrupt stub -> dispatches to 0xE8D8");
        count += labelComment(0x00002094, "ISR_IRQ1",
            "IRQ1 external interrupt stub -> dispatches to 0xE8E4");
        count += labelComment(0x000020AC, "ISR_IRQ2",
            "IRQ2 external interrupt stub -> dispatches to 0xE8F0");
        count += labelComment(0x000020C4, "ISR_IRQ3",
            "IRQ3 external interrupt stub -> dispatches to 0xE8FC");
        count += labelComment(0x000020DC, "ISR_IRQ4",
            "IRQ4 external interrupt stub");
        count += labelComment(0x000020F4, "ISR_IRQ5",
            "IRQ5 external interrupt stub");
        count += labelComment(0x0000210C, "ISR_IRQ6",
            "IRQ6 external interrupt stub");
        count += labelComment(0x00002124, "ISR_IRQ7",
            "IRQ7 external interrupt stub");
        count += labelComment(0x0000219C, "ISR_ATU_ITV",
            "ATU interval timer ISR stub -> dispatches to 0xE970 (scheduler tick)");
        count += labelComment(0x000027E4, "ISR_CMT_CMI0",
            "CMT compare match timer 0 ISR stub -> dispatches to 0xF2F6");
        count += labelComment(0x00002814, "ISR_ADI0",
            "ADI0 A/D Group 0 conversion complete ISR stub -> dispatches to 0xF312");
        count += labelComment(0x00002904, "ISR_WDT",
            "Watchdog timer interrupt ISR stub");

        // ISR common dispatcher and epilogue
        count += labelComment(0x00002B8C, "ISR_CommonDispatcher",
            "ISR prologue: saves r2-r7, fr0-fr11, pr, mach, macl. Sets up epilogue.");
        count += labelComment(0x00002BD4, "ISR_CommonEpilogue",
            "ISR epilogue: restores all saved context, decrements nesting counter.");

        // ISR nesting context
        count += labelComment(0xFFFF1288, "ISR_NestingContext",
            "ISR nesting context struct. +8=nesting counter, +16=saved SR.");

        // =====================================================================
        // ADC / SENSOR PIPELINE
        // =====================================================================
        count += labelComment(0x000040E0, "ADC_BulkRead",
            "Synchronous ADC read: configures ADCSR0/1/2, starts all 3 groups, polls completion, bulk-reads all 32 channels to GBR-relative RAM.");
        count += labelComment(0x0000F312, "ADI0_Handler",
            "ADI0 actual handler: clears ADF flag, advances ADC state machine.");
        count += labelComment(0x0000F320, "ADI0_Handler2",
            "ADI0 second handler: calls ADC_DataCopy(0x7110), Sensor_Scaling(0x7D26), ADC_Notify(0xBB6C).");
        count += labelComment(0x0000E774, "ADC_StateMachine",
            "ADC conversion state machine dispatcher. Called from ISR and bulk read paths.");
        count += labelComment(0x0000E852, "ISR_SharedHalt",
            "Shared ISR handler for unused/error interrupts. Halts with infinite loop after logging error code.");
        count += labelComment(0x00007110, "ADC_DataCopy",
            "Copy ADC conversion results to working RAM structures.");
        count += labelComment(0x00007D26, "Sensor_Scaling",
            "Raw ADC value to engineering units conversion (int->float scaling).");
        count += labelComment(0x0000BB6C, "ADC_Notify",
            "Set flags/notifications after ADC processing complete.");

        // Knock ADC snapshot
        count += labelComment(0x0000437C, "Knock_ADC_ReadGroup0",
            "Re-reads all 12 Group 0 ADC channels for knock detection. Stores to 0xFFFF4064.");
        count += labelComment(0x00004410, "Knock_ADC_ReadGroup1",
            "Reads Group 1 ADC channels for knock detection. Stores to 0xFFFF407C. Dispatch by cylinder count.");

        // Knock ADC RAM structures
        count += labelComment(0xFFFF4064, "knock_adc_group0",
            "Knock ADC Group 0 snapshot: ADDR0-ADDR11 raw 16-bit values (24 bytes).");
        count += labelComment(0xFFFF407C, "knock_adc_group1",
            "Knock ADC Group 1 snapshot: ADDR12-ADDR23 raw 16-bit values (24 bytes).");
        count += labelComment(0xFFFF40AB, "knock_cylinder_count",
            "Cylinder count dispatch byte for knock ADC Group 1 read (1/4/8/12).");
        count += labelComment(0xFFFF4024, "knock_adc_working",
            "Knock ADC working copy (channels copied from snapshot during processing).");

        // VBR setup location
        count += labelComment(0x0000FA40, "VBR_Setup",
            "Sets VBR = 0x000FFC50 (peripheral interrupt vector table base). ldc r2,VBR.");
        // AFL / CL/OL PERSISTENCE ANALYSIS — ROM Functions
        // (from cl_ol_afl_persistence_analysis.txt)
        // =====================================================================

        // CL/OL Mode Flag Writer (Path B)
        count += labelComment(0x00031528, "clol_mode_flag_writer",
            "FFFF7448 writer. CL/OL mode flag (1=CL, 0=OL). Gates AFC + AFL learning. Called from task scheduler at 0x049EA4.");
        count += labelComment(0x00031590, "clol_cond_A_calc",
            "FFFF7449 computation: (FFFF7452==1 AND FFFF744E==2) ? 1 : 0");
        count += labelComment(0x000315BA, "clol_cond_B_calc",
            "FFFF744A computation: (FFFF7452==1 AND FFFF744E==1) ? 1 : 0");
        count += labelComment(0x00031966, "clol_master_readiness_writer",
            "FFFF7452 master CL readiness flag writer. GBR=FFFF7450. Throttle/load/RPM thresholds + hysteresis.");

        // OL Enrichment State Machine (Path A)
        count += labelComment(0x0003643A, "ol_condition_checker",
            "OL enrichment condition checker. Throttle/RPM/load thresholds for Path A (7-phase pipeline).");
        count += labelComment(0x0003606C, "ol_enrichment_dispatch",
            "OL enrichment dispatch. Reads FFFF79C6 mode state (always 0). Values 1/2 are dead code hooks.");

        // AFL Core Functions
        count += labelComment(0x00034488, "afl_sub_dispatcher",
            "AFL sub-dispatcher. Dispatch Table A entry [5]. Orchestrates AFL learning cycle.");
        count += labelComment(0x000344BA, "afl_range_loop",
            "AFL range loop. Iterates 4 learning ranges (0-3).");
        count += labelComment(0x000344EE, "afl_validity_check",
            "AFL validity check before learning cycle.");
        count += labelComment(0x0003452A, "afl_core_entry",
            "AFL core entry. Calls: airflow range -> CL check -> range select -> value update -> store -> max check -> transition.");
        count += labelComment(0x000345A4, "afl_cl_active_check",
            "AFL CL active check. 10-condition gate including FFFF8F24, MAF>70g/s, FFFF7BE2, etc.");
        count += labelComment(0x00034778, "afl_range_selection",
            "AFL range selection with additional enable logic.");
        count += labelComment(0x00034884, "afl_value_update",
            "AFL value update. Actual learning adjustment. Step size 0.001 (CC05C). Limits +/-25% (CC064/CC068).");
        count += labelComment(0x00034B1C, "afl_value_store",
            "AFL value store. Clamp + write to FFFF316C+(range*8) array.");
        count += labelComment(0x00034C18, "afl_clol_transition_handler",
            "AFL CL/OL transition handler. Calls afl_clol_mode_check at 0x34C54.");
        count += labelComment(0x00034C54, "afl_clol_mode_check",
            "AFL CL/OL mode check. Reads FFFF7448. When 0 (OL): AFL learning FROZEN.");
        count += labelComment(0x00034CC8, "afl_max_airflow_rate_check",
            "AFL max airflow learning rate check. <35g/s: 88 ticks, >=35g/s: 244 ticks (~2.8x slower).");
        count += labelComment(0x00034D52, "afl_airflow_range_determination",
            "AFL airflow range determination. Selects range 0-3 from breakpoints at CC074-CC07C.");
        count += labelComment(0x00034EC8, "afl_airflow_processor",
            "AFL airflow processor. Dispatch Table A entry [7].");
        count += labelComment(0x00034EF4, "afl_airflow_update",
            "AFL airflow update (Dispatch B entry).");

        // AFL Application (KEY: no CL/OL gate!)
        count += labelComment(0x00037ABA, "injector_trim_application",
            "Injector trim application. Uses A/F learning tables.");
        count += labelComment(0x00037B74, "afl_application",
            "AFL APPLICATION. Writes FFFF7AB4 multiplier. WARNING: Does NOT check FFFF7448 CL/OL mode. Does NOT check airflow max. Only gates: FFFF726C (transient), FFFF7C68 (status). AFL persists into OL.");
        count += labelComment(0x00037F00, "afl_multiplier_computation",
            "AFL multiplier computation subroutine. Reads FFFF31AC (primary) and FFFF31A4 (secondary) with weights CC2F4/CC2FC.");

        // Fuel Pulse Width (consumes AFL)
        count += labelComment(0x000301E4, "fuel_pulse_width_calc",
            "Fuel pulse width calculation. Reads FFFF7AB4 (AFL multiplier) at 0x030230. No CL/OL check — AFL applied unconditionally.");

        // AFC PI Controller
        count += labelComment(0x000342A8, "afc_pi_controller",
            "AFC PI controller. Reads FFFF7448 every cycle. When FFFF7448=0 (OL): AFC output=0. Drops immediately on CL->OL.");

        // =====================================================================
        // AFL / CL/OL PERSISTENCE ANALYSIS — RAM Addresses
        // =====================================================================
        count += labelComment(0xFFFF316C, "afl_range0_value",
            "AFL Range 0 learning value (float). Idle zone: 0-6.0 g/s.");
        count += labelComment(0xFFFF3174, "afl_range1_value",
            "AFL Range 1 learning value (float). Light cruise: 6.0-23.0 g/s.");
        count += labelComment(0xFFFF317C, "afl_range2_value",
            "AFL Range 2 learning value (float). Normal driving: 23.0-40.0 g/s.");
        count += labelComment(0xFFFF3184, "afl_range3_value",
            "AFL Range 3 learning value (float). Heavy load: 40.0-80.0 g/s (partially OL).");
        count += labelComment(0xFFFF31A4, "afl_interp_secondary",
            "AFL secondary interpolated output (float).");
        count += labelComment(0xFFFF31AC, "afl_interp_primary",
            "AFL primary interpolated output (float).");
        count += labelComment(0xFFFF726C, "transient_state_flag",
            "Transient state flag (byte). Gates AFL application — when set, forces FFFF7AB4=1.0.");
        count += labelComment(0xFFFF7448, "clol_mode_flag",
            "CL/OL mode flag (byte). 1=CL, 0=OL. Gates AFC + AFL learning. Written by 0x031528. Does NOT gate AFL application.");
        count += labelComment(0xFFFF7449, "clol_cond_A",
            "CL mode condition A (byte). (FFFF7452==1 AND FFFF744E==2) ? 1 : 0");
        count += labelComment(0xFFFF744A, "clol_cond_B",
            "CL mode condition B (byte). (FFFF7452==1 AND FFFF744E==1) ? 1 : 0");
        count += labelComment(0xFFFF744B, "cl_inhibit",
            "CL inhibit flag (byte). Copy of FFFF8E98 sensor flag. When !=0: FFFF7448=0.");
        count += labelComment(0xFFFF744C, "cl_readiness_A",
            "CL readiness A (byte). Copy of FFFF8F08.");
        count += labelComment(0xFFFF744D, "cl_readiness_B",
            "CL readiness B (byte). From func_021D9A.");
        count += labelComment(0xFFFF744E, "cl_mode_state",
            "CL mode state (byte). 0/1/2 from func_021D9A of FFFF8F24.");
        count += labelComment(0xFFFF7452, "cl_master_readiness",
            "Master CL readiness flag (byte). Written at 0x031966. Multiple conditions + hysteresis.");
        count += labelComment(0xFFFF79C4, "ol_delay_counter_B",
            "OL enrichment delay counter_B. Set by CBC62 (modified=0 for immediate OL enrichment).");
        count += labelComment(0xFFFF79C6, "ol_mode_state",
            "OL mode state flag (byte). NEVER WRITTEN — always 0. Values 1/2 are dead code hooks in FUN_0003606C.");
        count += labelComment(0xFFFF79F2, "ol_active_flag",
            "OL active flag (byte). Written by Path A state machine.");
        count += labelComment(0xFFFF7AB4, "afl_multiplier_output",
            "AFL multiplier output (float). Written by afl_application at 0x37B74. Consumed by fuel PW calc at 0x0301E4. Applied unconditionally in CL and OL.");
        count += labelComment(0xFFFF7C68, "engine_status_flag",
            "Engine status flag (byte). Gates AFL application — abnormal condition forces FFFF7AB4=1.0.");

        // =====================================================================
        // HIGH-FREQUENCY SHARED SUBROUTINES (by cross-reference count)
        // =====================================================================
        // Found via BSR/JSR call-target analysis. These are the most-called
        // unlabeled functions in the ROM — naming them unlocks readability
        // across the entire firmware.

        // ── Integer Arithmetic (saturating add/clamp) ──────────────────────
        count += labelComment(0x000BE554, "uint16_add_sat",
            "685 calls. r0 = min(r4+r5, 0xFFFF). Saturating uint16 add, returns in r0.");
        count += labelComment(0x000BE53C, "uint8_add_sat",
            "461 calls. r0 = min(r4+r5, 0xFF). Saturating uint8 add with carry check, returns in r0.");

        // ── Float-to-Descriptor Processor (NaN-safe) ───────────────────────
        count += labelComment(0x000BDBCC, "desc_read_float_safe",
            "309 calls. Reads float from descriptor ptr r4, NaN-checks via fcmp/eq self, "
            + "calls interrupt_priority_set(16) + interrupt_restore. Returns validated float or 0.");

        // ── Interrupt Priority Control ─────────────────────────────────────
        count += labelComment(0x0000317C, "interrupt_priority_set",
            "298 calls. Sets SR interrupt mask to level r4 (0-15). Reads SR, masks with 0x00F0, "
            + "shifts r4 into I-bits. Returns old SR in r0. Used by all descriptor reads for atomicity.");
        count += labelComment(0x00003190, "interrupt_restore",
            "181 calls. Restores SR interrupt mask from r4 (previously saved by interrupt_priority_set). "
            + "Checks flag at FFFF1288+0x18, may call 0x3664. Paired with interrupt_priority_set.");

        // ── Critical Section Enter/Exit ────────────────────────────────────
        count += labelComment(0x000BE81C, "critical_section_enter",
            "235 calls. Saves SR, sets interrupt level from mask 0xF0, stores old priority at @r4. "
            + "Returns old SR in r5. Wraps descriptor/table reads for data consistency.");
        count += labelComment(0x000BE82C, "critical_section_exit",
            "236 calls. Restores SR interrupt mask. Just: rts + ldc r4,sr. "
            + "Paired with critical_section_enter.");

        // ── Float Clamp/Range ──────────────────────────────────────────────
        count += labelComment(0x000BE56C, "float_clamp_range",
            "218 calls. Clamps fr4 to [fr6, fr5]. If fr4>fr5: fr7=fr5; elif fr4<fr6: fr7=fr6; else fr7=fr4. "
            + "Returns clamped value in fr0. Core range-limiter for calibration outputs.");

        // ── Float Axis Interpolation (fraction calc) ───────────────────────
        count += labelComment(0x000BE5D8, "axis_frac_to_uint16",
            "147 calls. Converts float axis position to uint16 index+fraction. "
            + "fr4=value, fr5=range divisor, fr6=axis base. Computes (value-base)/divisor, "
            + "ftrc to int, clamps [0, 0xFFFF]. Used by all 1D/2D table lookups.");
        count += labelComment(0x000BE5A8, "axis_frac_to_uint8",
            "113 calls. Same as axis_frac_to_uint16 but clamps to [0, 0xFF]. "
            + "Used by lower-resolution table lookups.");

        // ── Float fmac Interpolation Primitives ────────────────────────────
        count += labelComment(0x000BE598, "fmac_interp_uint16",
            "145 calls. Converts uint16 r4 fraction to float, then fmac blend: "
            + "fr0 = fr4 + fr3*(fr5-fr4). Core 1D interpolation for uint16-indexed tables.");
        count += labelComment(0x000BE588, "fmac_interp_uint8",
            "31 calls. Converts uint8 r4 fraction to float, then fmac blend. "
            + "Same as fmac_interp_uint16 but for uint8-indexed tables.");

        // ── DTC (Diagnostic Trouble Code) Framework ────────────────────────
        count += labelComment(0x0009EDEC, "dtc_set_code",
            "186 calls. Sets DTC by index r4. Checks FFFF36F4 enable, reads DTC_Table (0x9A770), "
            + "calls 0xA58D6 and 0xA5ABC. DTC set dispatcher.");
        count += labelComment(0x0009ED90, "dtc_clear_code",
            "140 calls. Clears DTC by index r4. Same gate check as dtc_set_code. "
            + "Calls 0xA1CC0 and 0xA240C. DTC clear dispatcher.");

        // ── Descriptor Read (integer, no NaN check) ────────────────────────
        count += labelComment(0x000BDCB6, "desc_read_int_safe",
            "120 calls. Reads integer value from descriptor ptr r4. Calls interrupt_priority_set(16), "
            + "reads data with boundary checks, calls interrupt_restore. Integer variant of desc_read_float_safe.");

        // ── Context Save/Restore (ISR prologue) ────────────────────────────
        count += labelComment(0x00002B8C, "isr_context_save",
            "118 calls. Full register save for ISR: saves r2-r7, fr0-fr10, FPUL, PR to stack. "
            + "Increments counter at FFFF1288+8. Returns address of restore routine in r0. "
            + "Used at entry of all interrupt handlers.");

        // ── CL/OL Mode Check Helpers ───────────────────────────────────────
        count += labelComment(0x00022F92, "check_cl_active",
            "111 calls. Reads FFFF65F6 byte, returns T-bit = (value==1). "
            + "Quick CL-mode gate used throughout fuel/timing/diagnostic code.");
        count += labelComment(0x00022CF4, "check_engine_running",
            "100 calls. Reads FFFF65C5 byte, returns T-bit = (value==1). "
            + "Engine-running gate used throughout fuel/timing/diagnostic code.");
        count += labelComment(0x0002F8EA, "check_transient_flag",
            "65 calls. Reads FFFF726C byte (transient flag), returns T-bit = (value==1). "
            + "Transient condition gate for AFL/fuel corrections.");
        count += labelComment(0x0003AB20, "check_engine_status",
            "35 calls. Reads FFFF7C68 byte (engine status), returns T-bit = (value==1). "
            + "Gates AFL application — forces multiplier=1.0 on abnormal.");

        // ── Diagnostic / Sensor Validation Framework ───────────────────────
        count += labelComment(0x000582D2, "diag_wrapper_set",
            "108 calls. Wrapper: saves PR, calls 0xA6728, restores PR. "
            + "Diagnostic flag set used by sensor monitor tasks.");
        count += labelComment(0x000582AC, "diag_check_status",
            "100 calls. Reads FFFF36F0, checks diagnostic mode byte. "
            + "Returns r0=2 if mode active. Multi-condition diagnostic gate.");
        count += labelComment(0x000582E0, "diag_read_pack_2val",
            "43 calls. Reads descriptor, packs 2 values via uint16_pack/uint8_pack, "
            + "calls interrupt_restore. Diagnostic data read with atomicity.");
        count += labelComment(0x000584C8, "diag_check_enable_B",
            "59 calls. Reads FFFFAE09 byte, returns T-bit = (value==1). "
            + "Diagnostic enable gate B.");
        count += labelComment(0x000584BE, "diag_check_enable_A",
            "43 calls. Reads FFFFAE08 byte, returns T-bit = (value==1). "
            + "Diagnostic enable gate A.");
        count += labelComment(0x00058524, "diag_helper_C",
            "11 calls. Diagnostic utility C. Short helper in diag framework.");

        // ── Scheduler / Timer Utilities ────────────────────────────────────
        count += labelComment(0x0000E6E4, "sched_event_post",
            "73 calls. Posts event to scheduler: reads SR mask, checks event queue word at @r4, "
            + "sets bits. Atomic scheduler event notification.");
        count += labelComment(0x0000E6C4, "sched_event_clear",
            "11 calls. Clears scheduler event flag. Paired with sched_event_post.");

        // ── Address / Offset Calculation ───────────────────────────────────
        count += labelComment(0x00006B5A, "calc_table_offset",
            "53 calls. Complex offset computation using calibration base 0xC0080 "
            + "and lookup tables at 0x1190C/0x11914/0x1193C. Returns computed address in r0. "
            + "Used by calibration descriptor reads to resolve table pointers.");

        // ── Peripheral I/O Wrappers ────────────────────────────────────────
        count += labelComment(0x00006BC4, "io_write_word_atomic",
            "35 calls. Atomic word write: critical_section_enter, "
            + "BSR to formatter, BSR to writer, critical_section_exit. "
            + "Used for peripheral register updates.");
        count += labelComment(0x00006BF0, "io_write_2word_atomic",
            "31 calls. Atomic 2-word write: critical_section_enter, "
            + "write 2 values, critical_section_exit. Extended I/O update.");
        count += labelComment(0x000067A6, "io_sched_event_atomic",
            "26 calls. Atomic scheduler event + I/O: calls subroutines for "
            + "event setup, sched_event_post, critical_section_exit.");
        count += labelComment(0x00067DC, "io_sched_event_atomic_2",
            "21 calls. Variant of io_sched_event_atomic with different event type.");

        // ── RAM Word Compare-and-Write ─────────────────────────────────────
        count += labelComment(0x0000B9E0, "ram_word_update",
            "44 calls. Compares word at @r14 with r5, if different: "
            + "calls 0x10800 with event code, writes new value. "
            + "Used for state change detection with notification.");
        count += labelComment(0x0000B99C, "ram_word_update_B",
            "22 calls. Variant of ram_word_update with different event routing.");
        count += labelComment(0x00010800, "event_notify",
            "15 calls. Event notification dispatcher. Called by ram_word_update "
            + "when state changes are detected.");

        // ── DTC Table Iterator ─────────────────────────────────────────────
        count += labelComment(0x0009CFEE, "dtc_scan_loop",
            "48 calls. Iterates DTC entries, calls handler per-entry via r13 (0x9CCF8). "
            + "Reads FFFFB6DF enable, checks DTC table. Bulk DTC processing.");

        // ── Communication / Serial ─────────────────────────────────────────
        count += labelComment(0x00058318, "comms_pack_response",
            "57 calls. Packs diagnostic response: calls interrupt_priority_set, "
            + "uint16_pack, uint8_pack multiple times, interrupt_restore. "
            + "Builds multi-byte response for diagnostic protocol (KWP2000/CAN).");
        count += labelComment(0x00058404, "comms_pack_response_B",
            "49 calls. Variant of comms_pack_response with different field layout.");

        // ── Descriptor / Table Walker ──────────────────────────────────────
        count += labelComment(0x0000DCE4, "desc_table_walk",
            "37 calls. Walks descriptor table: reads table pointer from lookup at 0x11B98, "
            + "iterates entries, processes each via shift+add loop. "
            + "Generic descriptor iterator for multi-entry calibration structures.");

        // ── Miscellaneous High-Call-Count ───────────────────────────────────
        count += labelComment(0x0004E0B8, "gbr_task_dispatcher",
            "40 calls. Sets GBR=0xFFFF83AB, allocates 64-byte workspace, copies r4-r7 args. "
            + "Writes multiple GBR-offset bytes from inputs. GBR-relative task setup.");
        count += labelComment(0x000297A0, "float_load_from_desc",
            "18 calls. Loads float from descriptor address. Small utility for descriptor access.");
        count += labelComment(0x000297B0, "float_load_from_desc_B",
            "16 calls. Variant of float_load_from_desc.");
        count += labelComment(0x000299BC, "float_store_to_ram",
            "14 calls. Stores float to RAM address from descriptor result.");
        count += labelComment(0x0002999C, "float_compare_and_flag",
            "10 calls. Compares float values and sets a RAM flag based on result.");

        // ── Sensor Reading Helpers ─────────────────────────────────────────
        count += labelComment(0x00045EEA, "knock_helper_leaf",
            "13 calls. Leaf function in knock processing pipeline. Short helper called by multiple knock tasks.");
        count += labelComment(0x00023E48, "fuel_desc_reader",
            "15 calls. Reads fuel-related descriptor. Called from PSE and fuel correction code (0x304F4-0x30C66).");
        count += labelComment(0x0001CF16, "engine_state_helper",
            "10 calls. Engine state utility. Called from AFL/timing/boost contexts.");
        count += labelComment(0x000281DC, "sensor_scale_helper",
            "15 calls. Sensor scaling/conversion utility. Called from AFL, fuel, and O2 processing.");
        count += labelComment(0x00021D9A, "cl_readiness_check",
            "12 calls. CL readiness evaluation. Called from CL/OL transition, fuel, and AFL code. "
            + "Referenced by clol_cond analysis.");
        count += labelComment(0x000717B2, "eeprom_read_helper",
            "25 calls. EEPROM/NV-memory read utility. Called from DTC and adaptation contexts.");
        count += labelComment(0x0005CC9A, "sensor_diag_helper",
            "20 calls. Sensor diagnostic utility. Called from O2 sensor, boost, and idle contexts.");

        // ── BDD88 family (appears in multiple peripheral I/O contexts) ─────
        count += labelComment(0x000BDD5A, "peripheral_io_read",
            "20 calls. Peripheral register read utility. Groups of read calls in I/O driver code.");
        count += labelComment(0x000BDD88, "peripheral_io_write",
            "10 calls. Peripheral register write utility. Paired with peripheral_io_read.");
        count += labelComment(0x000BDB92, "peripheral_io_init",
            "17 calls. Peripheral I/O initialization. Called during startup and reconfiguration.");
        count += labelComment(0x000BDC6A, "peripheral_io_config",
            "10 calls. Peripheral I/O configuration. Sets up register access parameters.");

        // ── Remaining High-Value Targets ───────────────────────────────────
        count += labelComment(0x00006828, "io_read_word_atomic",
            "15 calls. Atomic word read from I/O region with interrupt protection.");
        count += labelComment(0x00006884, "io_read_2word_atomic",
            "20 calls. Atomic 2-word read from I/O region.");
        count += labelComment(0x0000CA72, "timer_reload",
            "11 calls. Timer/counter reload function. Called in groups (0xCBC6-0xCBDA range).");
        count += labelComment(0x0000E794, "sched_timer_dispatch",
            "8 calls. Timer-based scheduler dispatch. Manages periodic callback timing.");
        count += labelComment(0x00002EDC, "stack_frame_setup",
            "8 calls. Stack frame setup utility for complex function prologues.");
        count += labelComment(0x000117E8, "hw_register_set",
            "16 calls. Hardware register write. Used for peripheral configuration.");
        count += labelComment(0x000117FC, "hw_register_get",
            "13 calls. Hardware register read. Paired with hw_register_set.");
        count += labelComment(0x00098686, "dtc_status_check",
            "14 calls. DTC status check for specific fault code. Returns fault state.");
        count += labelComment(0x0009D052, "dtc_counter_update",
            "14 calls. DTC maturation counter update. Increments fault detection counters.");
        count += labelComment(0x0009DD78, "dtc_vector_table",
            "17 calls. DTC handler vector dispatch. Called via pointer table from dtc_scan_loop.");
        count += labelComment(0x0009CABE, "dtc_freeze_frame",
            "11 calls. DTC freeze frame capture. Records operating conditions at fault time.");
        count += labelComment(0x0009884E, "dtc_monitor_helper",
            "12 calls. DTC monitor helper. Shared logic for OBD-II monitor routines.");
        count += labelComment(0x00098832, "dtc_monitor_gate",
            "10 calls. DTC monitor enable gate. Conditions check before monitor execution.");
        count += labelComment(0x0009DCEA, "dtc_history_update",
            "10 calls. DTC history memory update. Writes fault history for readout.");

        // ── Known RAM: Status Check Addresses ──────────────────────────────
        count += labelComment(0xFFFF65F6, "cl_active_flag",
            "Byte: 1=closed loop active. Read by check_cl_active (0x22F92), 111 calls.");
        count += labelComment(0xFFFF65C5, "engine_running_flag",
            "Byte: 1=engine running. Read by check_engine_running (0x22CF4), 100 calls.");
        count += labelComment(0xFFFFB71C, "dtc_master_enable",
            "Byte: DTC system master enable. Read by dtc_set_code/dtc_clear_code.");
        count += labelComment(0xFFFF36F0, "diag_mode_status",
            "DWord: Diagnostic mode status. Read by diag_check_status (0x582AC).");
        count += labelComment(0xFFFF36F4, "dtc_enable_flag",
            "Byte: DTC processing enable. Read by dtc_set_code/dtc_clear_code.");
        count += labelComment(0xFFFFAE08, "diag_enable_A",
            "Byte: Diagnostic enable A. Read by diag_check_enable_A (0x584BE).");
        count += labelComment(0xFFFFAE09, "diag_enable_B",
            "Byte: Diagnostic enable B. Read by diag_check_enable_B (0x584C8).");

        // =====================================================================
        // HIGH-REFERENCE RAM ADDRESSES (from literal pool scan, 4456 unique)
        // =====================================================================
        // Top addresses by reference count, identified by function context.
        // These appear in virtually every disassembly trace.

        // ── ADC / Sensor Processed Values (0xFFFF6xxx) ─────────────────────
        count += labelComment(0xFFFF6624, "rpm_current",
            "301 refs. Current RPM (float). Read by frontO2, AFL, CL/OL, timing, knock, boost, idle, diag. "
            + "THE most-referenced RAM address in the ROM.");
        count += labelComment(0xFFFF6350, "ect_current",
            "205 refs. Coolant temperature (float). Read by PSE, AFC, AFL, timing, idle, diag. "
            + "Second most-referenced address.");
        count += labelComment(0xFFFF65FC, "engine_load_current",
            "135 refs. Engine load (float, g/rev). Read by AFL, CL/OL transition, timing, fuel.");
        count += labelComment(0xFFFF67EC, "atm_pressure_current",
            "99 refs. Atmospheric/barometric pressure (float). Read by frontO2, PSE, AFL, timing.");
        count += labelComment(0xFFFF65C0, "throttle_position",
            "89 refs. Throttle position (float). Read by AFL, timing tasks 34/38, boost, idle.");
        count += labelComment(0xFFFF63F8, "iat_current",
            "86 refs. Intake air temperature (float). Read by AFL, CL/OL, timing.");
        count += labelComment(0xFFFF6354, "ect_raw_adc",
            "69 refs. ECT raw ADC value or secondary ECT (float). Read by PSE, AFL.");
        count += labelComment(0xFFFF6364, "ect_startup",
            "48 refs. ECT at engine start (float). Read by AFL, knock window setup.");
        count += labelComment(0xFFFF63C4, "ect_compensation",
            "43 refs. ECT compensation factor (float). Read by AFC, AFL, CL/OL.");
        count += labelComment(0xFFFF6254, "maf_current",
            "51 refs. MAF sensor value (float, g/s). Read by AFL pipeline.");
        count += labelComment(0xFFFF6228, "maf_voltage",
            "22 refs. MAF sensor voltage (float). Read by timing, fuel.");
        count += labelComment(0xFFFF61CC, "vehicle_speed",
            "56 refs. Vehicle speed (float). Read by timing, CL/OL, boost.");
        count += labelComment(0xFFFF62DC, "fuel_rate",
            "20 refs. Fuel injection rate (float). Read by timing, boost.");
        count += labelComment(0xFFFF6898, "manifold_pressure",
            "48 refs. Manifold pressure (float). Read by frontO2, PSE, CL/OL, base timing.");
        count += labelComment(0xFFFF69F0, "boost_pressure",
            "32 refs. Boost pressure (float). Read by AFL. GBR base (5 uses).");
        count += labelComment(0xFFFF6C48, "battery_voltage",
            "34 refs. Battery voltage (float). Read by injector latency, diag.");

        // ── ADC / Sensor Raw + Status (0xFFFF61xx-0xFFFF65xx) ──────────────
        count += labelComment(0xFFFF6155, "adc_channel_status",
            "36 refs. ADC channel status/index (byte). GBR base (4 uses).");
        count += labelComment(0xFFFF64D8, "throttle_raw",
            "29 refs. Throttle raw ADC or secondary throttle.");
        count += labelComment(0xFFFF65BD, "engine_state_byte",
            "34 refs. Engine state byte (cranking/running/etc).");
        count += labelComment(0xFFFF653C, "o2_sensor_voltage",
            "19 refs. O2 sensor voltage or lambda value.");

        // ── Sensor / Input Block (0xFFFF4xxx) ──────────────────────────────
        count += labelComment(0xFFFF4130, "ignition_switch_state",
            "77 refs. Ignition/key switch state. Read by frontO2, idle, boost. 4th most-referenced.");
        count += labelComment(0xFFFF4024, "sensor_group_base",
            "56 refs. Sensor processing group base. GBR base (1 use). Read by frontO2.");
        count += labelComment(0xFFFF43FC, "sensor_misc_state",
            "25 refs. Misc sensor state.");

        // ── Calibration Mirror Area (0xFFFF3xxx) ───────────────────────────
        count += labelComment(0xFFFF399E, "dtc_maturation_timer",
            "118 refs. DTC maturation timer/counter. Read primarily by DTC framework. 4th most-referenced.");
        count += labelComment(0xFFFF3B06, "dtc_debounce_state",
            "92 refs. DTC debounce state. Read by diag/DTC framework.");
        count += labelComment(0xFFFF3836, "dtc_monitor_state",
            "76 refs. DTC monitor state/counter. Read by DTC framework.");
        count += labelComment(0xFFFF3480, "cal_mirror_base",
            "45 refs. Calibration mirror base. Referenced by various subsystems.");
        count += labelComment(0xFFFF366C, "timer_counter_A",
            "41 refs. Timer/counter A.");
        count += labelComment(0xFFFF367C, "timer_counter_B",
            "25 refs. Timer/counter B.");
        count += labelComment(0xFFFF3674, "timer_counter_C",
            "25 refs. Timer/counter C.");
        count += labelComment(0xFFFF25CC, "system_tick_counter",
            "48 refs. System tick/event counter.");

        // ── Knock / FLKC Workspace (0xFFFF8xxx) ────────────────────────────
        count += labelComment(0xFFFF837E, "idle_control_GBR",
            "39 refs. Idle control GBR base (19 GBR uses). Primary GBR for task54_idle.");
        count += labelComment(0xFFFF83AC, "idle_workspace_GBR",
            "26 refs. Secondary idle GBR workspace (7 GBR uses).");
        count += labelComment(0xFFFF8E98, "sensor_fault_flags",
            "97 refs. Sensor fault flag register. Read by frontO2, AFL, idle. "
            + "Copied to cl_inhibit (FFFF744B). 8th most-referenced.");
        count += labelComment(0xFFFF85D7, "fuel_system_state",
            "60 refs. Fuel system state byte. Read by AFC, AFL, idle.");
        count += labelComment(0xFFFF81F0, "knock_state_base",
            "30 refs. Knock state workspace base. GBR base (5 uses). Read by task11 knock.");
        count += labelComment(0xFFFF895C, "injector_data",
            "37 refs. Injector data (pulse width or duty). Read by timing tasks.");
        count += labelComment(0xFFFF87E4, "timing_correction_A",
            "26 refs. Timing correction value A.");
        count += labelComment(0xFFFF8C9C, "timing_workspace_A",
            "17 refs. Timing workspace variable.");
        count += labelComment(0xFFFF8EA8, "sched_control_GBR",
            "14 refs. Scheduler control GBR base (5 GBR uses).");
        count += labelComment(0xFFFF8E46, "fuel_mode_flags",
            "39 refs. Fuel mode flags register.");

        // ── Diagnostic State (0xFFFFAxxx) ──────────────────────────────────
        count += labelComment(0xFFFFAD52, "diag_session_state",
            "107 refs. Diagnostic session state. Read by diag/DTC framework. 6th most-referenced.");
        count += labelComment(0xFFFFADAC, "diag_request_state",
            "69 refs. Diagnostic request/response state. Read by DTC framework.");
        count += labelComment(0xFFFFACE0, "diag_output_buffer",
            "32 refs. Diagnostic output buffer pointer.");
        count += labelComment(0xFFFFAC6C, "diag_protocol_GBR",
            "13 refs. Diagnostic protocol GBR base (4 GBR uses).");
        count += labelComment(0xFFFFA160, "diag_monitor_GBR",
            "21 refs. Diagnostic monitor GBR base (6 GBR uses).");
        count += labelComment(0xFFFFA198, "egr_diag_state",
            "13 refs. EGR/emissions diagnostic state. GBR base (3 uses).");
        count += labelComment(0xFFFFAF3B, "comms_state_byte",
            "36 refs. Communications protocol state byte.");
        count += labelComment(0xFFFFAF60, "comms_buffer_ptr",
            "Referenced in dtc_set_code literal pool. Comms buffer pointer.");

        // ── Scheduler / System (0xFFFF9xxx) ────────────────────────────────
        count += labelComment(0xFFFF9094, "sched_task_GBR",
            "36 refs. Scheduler task GBR base (6 GBR uses).");
        count += labelComment(0xFFFF9058, "sched_state_A",
            "32 refs. Scheduler state variable A.");
        count += labelComment(0xFFFF9FC6, "sched_timer_base",
            "22 refs. Scheduler timer base. GBR base (3 uses).");
        count += labelComment(0xFFFF9FA8, "sched_timer_B",
            "17 refs. Scheduler timer variable B.");
        count += labelComment(0xFFFF91C4, "sched_queue_base",
            "8 refs. Scheduler queue base. GBR base (3 uses).");
        count += labelComment(0xFFFF980C, "sched_periodic_GBR",
            "7 refs. Scheduler periodic timer GBR base (4 GBR uses).");

        // ── Fuel / Timing Working (0xFFFF7xxx) ─────────────────────────────
        count += labelComment(0xFFFF77C8, "afc_output",
            "19 refs. AFC output value. Referenced in fuel_correction_final.");
        count += labelComment(0xFFFF798C, "timing_state_var",
            "17 refs. Timing state variable. Referenced by task35_timing_corr.");
        count += labelComment(0xFFFF7E90, "timing_output_A",
            "25 refs. Timing output value A.");
        count += labelComment(0xFFFF7D68, "timing_blend_state",
            "19 refs. Timing blend state variable.");
        count += labelComment(0xFFFF7FBC, "timing_final_advance",
            "14 refs. Final timing advance value.");
        count += labelComment(0xFFFF7C9D, "fuel_state_byte",
            "32 refs. Fuel state byte/flag.");

        // ── Peripheral I/O Region (0xFFFF5xxx) ─────────────────────────────
        count += labelComment(0xFFFF5BE3, "peripheral_status",
            "33 refs. Peripheral status register.");
        count += labelComment(0xFFFF5C98, "peripheral_control_GBR",
            "15 refs. Peripheral control GBR base (3 uses).");
        count += labelComment(0xFFFF5FFC, "io_state_register",
            "23 refs. I/O state register.");

        // ── System State (0xFFFF2xxx) ──────────────────────────────────────
        count += labelComment(0xFFFF2004, "system_init_flags",
            "23 refs. System initialization flags.");

        // =====================================================================
        // SH7058 ON-CHIP PERIPHERAL REGISTERS (0xFFFF0000-0xFFFF1FFF)
        // =====================================================================
        // From SH7058 hardware manual + cross-reference with code context.
        // Only addresses actually referenced in the ROM are labeled.

        count += labelComment(0xFFFF0000, "SH7058_STBCR",
            "9 refs. Standby Control Register (power management). Module stop control bits.");
        count += labelComment(0xFFFF0004, "SH7058_STBCR2",
            "2 refs. Standby Control Register 2. Additional module stop bits.");
        count += labelComment(0xFFFF0008, "SH7058_STBCR3",
            "2 refs. Standby Control Register 3. Peripheral clock gating.");
        count += labelComment(0xFFFF0020, "SH7058_SYSCR",
            "2 refs. System Control Register. Bus width, endianness, clock divider.");
        count += labelComment(0xFFFF1230, "SH7058_TIER_MTU0",
            "3 refs. Timer Interrupt Enable Register (MTU channel 0). Used for periodic interrupts.");
        count += labelComment(0xFFFF12B0, "SH7058_SCI_SMR",
            "2 refs. Serial Mode Register (SCI). Baud rate, parity, data length config.");
        count += labelComment(0xFFFF12B4, "SH7058_SCI_BRR",
            "1 ref. Bit Rate Register (SCI). Baud rate divisor.");
        count += labelComment(0xFFFF12B5, "SH7058_SCI_SCR",
            "1 ref. Serial Control Register (SCI). TX/RX enable, interrupt enable.");
        count += labelComment(0xFFFF12B8, "SH7058_SCI_TDR",
            "5 refs. Transmit Data Register (SCI). Write byte to send.");
        count += labelComment(0xFFFF12C8, "SH7058_SCI_SSR",
            "2 refs. Serial Status Register (SCI). TX empty, RX full, error flags.");

        // =====================================================================
        // THUNK FUNCTIONS — Resolved Targets
        // =====================================================================
        // 378 mov.l+jmp thunks found, 64 resolve to known functions.
        // Most common thunk targets:
        //   interrupt_restore (15 thunks) — tail-call optimization from ISR handlers
        //   desc_read_float_safe (5+ thunks) — inlined descriptor read wrappers
        //   check_cl_active, check_engine_running — mode-check wrappers
        //
        // Full thunk resolution in disassembly/thunk_resolution.txt (359 lines)
        //
        // NOTE: Thunks are NOT labeled here individually — they are artifacts of
        // the compiler's branch range optimization. In Ghidra, use "Follow Thunk"
        // to resolve them. The 64 resolved thunks point to already-labeled functions.

        // =====================================================================
        // DESCRIPTOR-FUNCTION CROSS-REFERENCE SUMMARY
        // =====================================================================
        // Full cross-reference in disassembly/desc_func_xref.txt (1495 lines)
        //
        // Functions with most calibration descriptors:
        //   afl_pipeline:           61 descriptors (17x18, 12x13, 16x6 2D tables)
        //   task33_timing_ws_init:  30 descriptors
        //   PSE_code:               22 descriptors
        //   timing_knock:           20 descriptors
        //   task37_timing_multiaxis:19 descriptors
        //   task32_timing_blend:    14 descriptors
        //   frontO2_area:           12 descriptors
        //   knock_area:             12 descriptors
        //   fuel_pw_calc:           11 descriptors
        //   task36_timing_percond:  11 descriptors
        //   task34_timing_throttle:  8 descriptors
        //   afc_pi_output:           7 descriptors
        //   task30_base_timing:      6 descriptors
        //   task48_final_timing:     5 descriptors (all 5x3 2D)


        // ============================================================
        // SH7058 INTERRUPT ARCHITECTURE
        // All peripheral IRQs share one generic ISR entry at 0x0BAC
        // 0x0BAC: saves R0-R7,PR,MACH,MACL; calls 0x0F4C; restores; RTE
        // 0x0F4C: reads interrupt ID; dispatches via table at 0x0E5EC
        // 0x0EE4: interrupt ID resolver (reads INTEVT/priority register)
        // 0x0D78: interrupt acknowledge/clear
        // 0x0BFA: exception trap (illegal instr/addr error = infinite loop)
        // Exception vector table: 0x000-0x033 (13 vectors x 4 bytes)
        //   0x000: initial PC = 0x000C0C (main entry)
        //   0x004: initial SP = 0xFFFFBFA0 (RAM top)
        //   0x010-0x020: all exceptions -> 0x0BFA (trap loop)
        //   0x02C: peripheral IRQ vector -> 0x0BAC (generic ISR)
        // ============================================================

        // Exception vector table entries (ROM 0x000-0x033)
        count += labelComment(0x000000L, "vtbl_reset_pc", "Power-on reset initial PC = 0x000C0C (main entry) [val=0x00000C0C]");
        count += labelComment(0x000004L, "vtbl_reset_sp", "Power-on reset initial SP = 0xFFFFBFA0 (RAM top) [val=0xFFFFBFA0]");
        count += labelComment(0x000008L, "vtbl_mreset_pc", "Manual reset initial PC = 0x000C0C [val=0x00000C0C]");
        count += labelComment(0x00000CL, "vtbl_mreset_sp", "Manual reset initial SP = 0xFFFFBFA0 [val=0xFFFFBFA0]");
        count += labelComment(0x000010L, "vtbl_illegal_instr", "Illegal instruction -> 0x0BFA trap [val=0x00000BFA]");
        count += labelComment(0x000014L, "vtbl_illegal_slot", "Illegal slot instruction -> 0x0BFA trap [val=0x00000BFA]");
        count += labelComment(0x000018L, "vtbl_cpu_addr_err", "CPU address error -> 0x0BFA trap [val=0x00000BFA]");
        count += labelComment(0x00001CL, "vtbl_dma_addr_err", "DMA bus error -> 0x0BFA trap [val=0x00000BFA]");
        count += labelComment(0x000020L, "vtbl_nmi", "NMI -> 0x0BFA trap [val=0x00000BFA]");
        count += labelComment(0x000024L, "vtbl_user_break", "User break/debug -> 0x0BFA trap [val=0x00000BFA]");
        count += labelComment(0x00002CL, "vtbl_periph_irq", "All peripheral IRQs -> 0x0BAC generic ISR [val=0x00000BAC]");

        // ISR dispatch infrastructure
        count += labelComment(0x000BACL, "isr_generic_handler",
            "Generic peripheral ISR: saves R0-R7/PR/MACH/MACL, calls isr_dispatch, RTE");
        count += labelComment(0x000BF6L, "isr_generic_rte",
            "Generic ISR RTE (return from interrupt) after register restore");
        count += labelComment(0x000BFAL, "exc_trap_infinite_loop",
            "Exception trap: illegal instruction / address error (infinite loop)");
        count += labelComment(0x000F4CL, "isr_dispatch_manager",
            "ISR sub-dispatch: identifies interrupt source, calls handler from isr_dispatch_table");
        count += labelComment(0x000EE4L, "isr_intevt_resolver",
            "Reads INTEVT/priority register to identify interrupt source, returns index");
        count += labelComment(0x000D78L, "isr_int_acknowledge",
            "Interrupt acknowledge/clear function");
        count += labelComment(0x000E5ECL, "isr_dispatch_table",
            "Interrupt dispatch table: 54 function pointers (4 bytes each)");

        // ISR dispatch table entry labels (table at 0x0E5EC, 54 entries)
        // Entry[N] address = 0x0E5EC + N*4 -> handler address
        count += labelComment(0x00E5ECL, "dtbl_isr_handler_0", "Dispatch table[0] -> 0x010A46");
        count += labelComment(0x010A46L, "isr_handler_0", "ISR dispatch table entry 0");
        count += labelComment(0x00E5F0L, "dtbl_isr_handler_1", "Dispatch table[1] -> 0x00FC04");
        count += labelComment(0x00FC04L, "isr_handler_1", "ISR dispatch table entry 1");
        count += labelComment(0x00E5F4L, "dtbl_isr_handler_2", "Dispatch table[2] -> 0x005840");
        count += labelComment(0x005840L, "isr_handler_2", "ISR dispatch table entry 2");
        count += labelComment(0x00E5F8L, "dtbl_isr_handler_3", "Dispatch table[3] -> 0x00D658");
        count += labelComment(0x00D658L, "isr_handler_3", "ISR dispatch table entry 3");
        count += labelComment(0x00E5FCL, "dtbl_isr_handler_4", "Dispatch table[4] -> 0x00CBAC");
        count += labelComment(0x00CBACL, "isr_handler_4", "ISR dispatch table entry 4");
        count += labelComment(0x00E600L, "dtbl_isr_handler_5", "Dispatch table[5] -> 0x04907C");
        count += labelComment(0x04907CL, "isr_handler_5", "ISR dispatch table entry 5");
        count += labelComment(0x00E604L, "dtbl_isr_handler_6", "Dispatch table[6] -> 0x009A58");
        count += labelComment(0x009A58L, "isr_handler_6", "ISR dispatch table entry 6");
        count += labelComment(0x00E608L, "dtbl_isr_handler_7", "Dispatch table[7] -> 0x00D268");
        count += labelComment(0x00D268L, "isr_handler_7", "ISR dispatch table entry 7");
        count += labelComment(0x00E60CL, "dtbl_isr_handler_8", "Dispatch table[8] -> 0x00CBEE");
        count += labelComment(0x00CBEEL, "isr_handler_8", "ISR dispatch table entry 8");
        count += labelComment(0x00E610L, "dtbl_isr_handler_9", "Dispatch table[9] -> 0x0035A4");
        count += labelComment(0x0035A4L, "isr_handler_9", "ISR dispatch table entry 9");
        count += labelComment(0x00E614L, "dtbl_isr_handler_10", "Dispatch table[10] -> 0x00FE22");
        count += labelComment(0x00FE22L, "isr_handler_10", "ISR dispatch table entry 10");
        count += labelComment(0x00E618L, "dtbl_isr_handler_11", "Dispatch table[11] -> 0x00A878");
        count += labelComment(0x00A878L, "isr_handler_11", "ISR dispatch table entry 11");
        count += labelComment(0x00E61CL, "dtbl_isr_handler_12", "Dispatch table[12] -> 0x00D940");
        count += labelComment(0x00D940L, "isr_handler_12", "ISR dispatch table entry 12");
        count += labelComment(0x00E620L, "dtbl_isr_handler_13", "Dispatch table[13] -> 0x009A14");
        count += labelComment(0x009A14L, "isr_handler_13", "ISR dispatch table entry 13");
        count += labelComment(0x00E624L, "dtbl_isr_handler_14", "Dispatch table[14] -> 0x008528");
        count += labelComment(0x008528L, "isr_handler_14", "ISR dispatch table entry 14");
        count += labelComment(0x00E628L, "dtbl_isr_task_scheduler", "Dispatch table[15] -> 0x04A94C");
        count += labelComment(0x04A94CL, "isr_task_scheduler", "ISR dispatch table entry 15");
        count += labelComment(0x00E62CL, "dtbl_isr_handler_16", "Dispatch table[16] -> 0x04AA58");
        count += labelComment(0x04AA58L, "isr_handler_16", "ISR dispatch table entry 16");
        count += labelComment(0x00E630L, "dtbl_isr_handler_17", "Dispatch table[17] -> 0x009A34");
        count += labelComment(0x009A34L, "isr_handler_17", "ISR dispatch table entry 17");
        count += labelComment(0x00E634L, "dtbl_isr_handler_18", "Dispatch table[18] -> 0x0085AC");
        count += labelComment(0x0085ACL, "isr_handler_18", "ISR dispatch table entry 18");
        count += labelComment(0x00E638L, "dtbl_isr_handler_19", "Dispatch table[19] -> 0x00D3DC");
        count += labelComment(0x00D3DCL, "isr_handler_19", "ISR dispatch table entry 19");
        count += labelComment(0x00E63CL, "dtbl_isr_handler_20", "Dispatch table[20] -> 0x010D58");
        count += labelComment(0x010D58L, "isr_handler_20", "ISR dispatch table entry 20");
        count += labelComment(0x00E640L, "dtbl_isr_rcan0", "Dispatch table[21] -> 0x04793C");
        count += labelComment(0x04793CL, "isr_rcan0", "ISR dispatch table entry 21");
        count += labelComment(0x00E644L, "dtbl_isr_rcan1", "Dispatch table[22] -> 0x048732");
        count += labelComment(0x048732L, "isr_rcan1", "ISR dispatch table entry 22");
        count += labelComment(0x00E648L, "dtbl_isr_handler_23", "Dispatch table[23] -> 0x01076A");
        count += labelComment(0x01076AL, "isr_handler_23", "ISR dispatch table entry 23");
        count += labelComment(0x00E64CL, "dtbl_isr_handler_24", "Dispatch table[24] -> 0x004BCA");
        count += labelComment(0x004BCAL, "isr_handler_24", "ISR dispatch table entry 24");
        count += labelComment(0x00E650L, "dtbl_isr_handler_25", "Dispatch table[25] -> 0x010124");
        count += labelComment(0x010124L, "isr_handler_25", "ISR dispatch table entry 25");
        count += labelComment(0x00E654L, "dtbl_isr_handler_26", "Dispatch table[26] -> 0x047B66");
        count += labelComment(0x047B66L, "isr_handler_26", "ISR dispatch table entry 26");
        count += labelComment(0x00E658L, "dtbl_isr_handler_27", "Dispatch table[27] -> 0x049A7A");
        count += labelComment(0x049A7AL, "isr_handler_27", "ISR dispatch table entry 27");
        count += labelComment(0x00E65CL, "dtbl_isr_handler_28", "Dispatch table[28] -> 0x00C36C");
        count += labelComment(0x00C36CL, "isr_handler_28", "ISR dispatch table entry 28");
        count += labelComment(0x00E660L, "dtbl_isr_handler_29", "Dispatch table[29] -> 0x00A844");
        count += labelComment(0x00A844L, "isr_handler_29", "ISR dispatch table entry 29");
        count += labelComment(0x00E664L, "dtbl_isr_handler_30", "Dispatch table[30] -> 0x049BA4");
        count += labelComment(0x049BA4L, "isr_handler_30", "ISR dispatch table entry 30");
        count += labelComment(0x00E668L, "dtbl_isr_handler_31", "Dispatch table[31] -> 0x00C370");
        count += labelComment(0x00C370L, "isr_handler_31", "ISR dispatch table entry 31");
        count += labelComment(0x00E66CL, "dtbl_isr_handler_32", "Dispatch table[32] -> 0x005798");
        count += labelComment(0x005798L, "isr_handler_32", "ISR dispatch table entry 32");
        count += labelComment(0x00E670L, "dtbl_isr_handler_33", "Dispatch table[33] -> 0x049CF0");
        count += labelComment(0x049CF0L, "isr_handler_33", "ISR dispatch table entry 33");
        count += labelComment(0x00E674L, "dtbl_isr_handler_34", "Dispatch table[34] -> 0x00D4FC");
        count += labelComment(0x00D4FCL, "isr_handler_34", "ISR dispatch table entry 34");
        count += labelComment(0x00E678L, "dtbl_isr_handler_35", "Dispatch table[35] -> 0x00812C");
        count += labelComment(0x00812CL, "isr_handler_35", "ISR dispatch table entry 35");
        count += labelComment(0x00E67CL, "dtbl_isr_handler_36", "Dispatch table[36] -> 0x00ACFC");
        count += labelComment(0x00ACFCL, "isr_handler_36", "ISR dispatch table entry 36");
        count += labelComment(0x00E680L, "dtbl_isr_handler_37", "Dispatch table[37] -> 0x04A03E");
        count += labelComment(0x04A03EL, "isr_handler_37", "ISR dispatch table entry 37");
        count += labelComment(0x00E684L, "dtbl_isr_handler_38", "Dispatch table[38] -> 0x00658C");
        count += labelComment(0x00658CL, "isr_handler_38", "ISR dispatch table entry 38");
        count += labelComment(0x00E688L, "dtbl_isr_handler_39", "Dispatch table[39] -> 0x005980");
        count += labelComment(0x005980L, "isr_handler_39", "ISR dispatch table entry 39");
        count += labelComment(0x00E68CL, "dtbl_isr_handler_40", "Dispatch table[40] -> 0x0081C8");
        count += labelComment(0x0081C8L, "isr_handler_40", "ISR dispatch table entry 40");
        count += labelComment(0x00E690L, "dtbl_isr_handler_41", "Dispatch table[41] -> 0x04A420");
        count += labelComment(0x04A420L, "isr_handler_41", "ISR dispatch table entry 41");
        count += labelComment(0x00E694L, "dtbl_isr_handler_42", "Dispatch table[42] -> 0x04A674");
        count += labelComment(0x04A674L, "isr_handler_42", "ISR dispatch table entry 42");
        count += labelComment(0x00E698L, "dtbl_isr_handler_43", "Dispatch table[43] -> 0x04A6C6");
        count += labelComment(0x04A6C6L, "isr_handler_43", "ISR dispatch table entry 43");
        count += labelComment(0x00E69CL, "dtbl_isr_handler_44", "Dispatch table[44] -> 0x04A6FA");
        count += labelComment(0x04A6FAL, "isr_handler_44", "ISR dispatch table entry 44");
        count += labelComment(0x00E6A0L, "dtbl_isr_handler_45", "Dispatch table[45] -> 0x00D8D0");
        count += labelComment(0x00D8D0L, "isr_handler_45", "ISR dispatch table entry 45");
        count += labelComment(0x00E6A4L, "dtbl_isr_handler_46", "Dispatch table[46] -> 0x04AE7C");
        count += labelComment(0x04AE7CL, "isr_handler_46", "ISR dispatch table entry 46");
        count += labelComment(0x00E6A8L, "dtbl_isr_handler_47", "Dispatch table[47] -> 0x0099E4");
        count += labelComment(0x0099E4L, "isr_handler_47", "ISR dispatch table entry 47");
        count += labelComment(0x00E6ACL, "dtbl_isr_handler_48", "Dispatch table[48] -> 0x00D1F4");
        count += labelComment(0x00D1F4L, "isr_handler_48", "ISR dispatch table entry 48");
        count += labelComment(0x00E6B0L, "dtbl_isr_handler_49", "Dispatch table[49] -> 0x0084D8");
        count += labelComment(0x0084D8L, "isr_handler_49", "ISR dispatch table entry 49");
        count += labelComment(0x00E6B4L, "dtbl_isr_handler_50", "Dispatch table[50] -> 0x00A694");
        count += labelComment(0x00A694L, "isr_handler_50", "ISR dispatch table entry 50");
        count += labelComment(0x00E6B8L, "dtbl_isr_handler_51", "Dispatch table[51] -> 0x00BB32");
        count += labelComment(0x00BB32L, "isr_handler_51", "ISR dispatch table entry 51");
        count += labelComment(0x00E6BCL, "dtbl_isr_handler_52", "Dispatch table[52] -> 0x007D12");
        count += labelComment(0x007D12L, "isr_handler_52", "ISR dispatch table entry 52");
        count += labelComment(0x00E6C0L, "dtbl_isr_handler_53", "Dispatch table[53] -> 0x04AE82");
        count += labelComment(0x04AE82L, "isr_handler_53", "ISR dispatch table entry 53");

        // ============================================================
        // CALIBRATION DESCRIPTOR LABELS (760 total, auto-generated)
        // Format: desc_<type>_<dtype>_<size>[_<addr>] -> descriptor struct
        // Each descriptor struct points to axis data + calibration table
        // ============================================================

        // --- 1D_AtmPressure (6 descriptors) ---
        count += label(0x0AABB8L, "desc_1D_AtmPressure_u8_4");
        count += label(0x0AAEF4L, "desc_1D_AtmPressure_u8_8");
        count += label(0x0AB1A4L, "desc_1D_AtmPressure_u8_6_AB1A4");
        count += label(0x0AB1B8L, "desc_1D_AtmPressure_u8_6_AB1B8");
        count += label(0x0AB444L, "desc_1D_AtmPressure_i16_7");
        count += label(0x0ADDB8L, "desc_1D_AtmPressure_i16_6");

        // --- 1D_Boost (26 descriptors) ---
        count += label(0x0AA820L, "desc_1D_Boost_u8_5");
        count += label(0x0AB430L, "desc_1D_Boost_i16_16_AB430");
        count += label(0x0AB674L, "desc_1D_Boost_u8_8");
        count += label(0x0AC2D0L, "desc_1D_Boost_i16_16_AC2D0");
        count += label(0x0AC2E8L, "desc_1D_Boost_i16_16_AC2E8");
        count += label(0x0AC300L, "desc_1D_Boost_i16_16_AC300");
        count += label(0x0AC318L, "desc_1D_Boost_i16_16_AC318");
        count += label(0x0AC498L, "desc_1D_Boost_i16_16_AC498");
        count += label(0x0AC56CL, "desc_1D_Boost_i16_9_AC56C");
        count += label(0x0AC594L, "desc_1D_Boost_i16_9_AC594");
        count += label(0x0AC698L, "desc_1D_Boost_i16_16_AC698");
        count += label(0x0AC6ACL, "desc_1D_Boost_i16_16_AC6AC");
        count += label(0x0AC6D4L, "desc_1D_Boost_i16_16_AC6D4");
        count += label(0x0ACCBCL, "desc_1D_Boost_u8_11_ACCBC");
        count += label(0x0ACCD0L, "desc_1D_Boost_u8_11_ACCD0");
        count += label(0x0ACCE4L, "desc_1D_Boost_u8_11_ACCE4");
        count += label(0x0ACCF8L, "desc_1D_Boost_u8_11_ACCF8");
        count += label(0x0ACD0CL, "desc_1D_Boost_u8_11_ACD0C");
        count += label(0x0ACD20L, "desc_1D_Boost_u8_11_ACD20");
        count += label(0x0AD37CL, "desc_1D_Boost_u8_18");
        count += label(0x0AD47CL, "desc_1D_Boost_f32_16_AD47C");
        count += label(0x0AD494L, "desc_1D_Boost_f32_16_AD494");
        count += label(0x0AD4ACL, "desc_1D_Boost_f32_16_AD4AC");
        count += label(0x0ADAFCL, "desc_1D_Boost_i16_8");
        count += label(0x0ADDCCL, "desc_1D_Boost_i16_7");
        count += label(0x0AE14CL, "desc_1D_Boost_f32_16_AE14C");

        // --- 1D_Degrees (3 descriptors) ---
        count += label(0x0AAB18L, "desc_1D_Degrees_u8_15");
        count += label(0x0AEE80L, "desc_1D_Degrees_u8_12_AEE80");
        count += label(0x0AEE94L, "desc_1D_Degrees_u8_12_AEE94");

        // --- 1D_ECT (258 descriptors) ---
        count += label(0x0AA888L, "desc_1D_ECT_i16_16_AA888");
        count += label(0x0AA89CL, "desc_1D_ECT_i16_16_AA89C");
        count += label(0x0AA8B0L, "desc_1D_ECT_i16_16_AA8B0");
        count += label(0x0AA8C4L, "desc_1D_ECT_i16_16_AA8C4");
        count += label(0x0AA8D8L, "desc_1D_ECT_i16_16_AA8D8");
        count += label(0x0AA8ECL, "desc_1D_ECT_i16_16_AA8EC");
        count += label(0x0AA900L, "desc_1D_ECT_i16_16_AA900");
        count += label(0x0AADECL, "desc_1D_ECT_u8_16_AADEC");
        count += label(0x0AAE00L, "desc_1D_ECT_u8_16_AAE00");
        count += label(0x0AAE28L, "desc_1D_ECT_u8_16_AAE28");
        count += label(0x0AAE50L, "desc_1D_ECT_u8_16_AAE50");
        count += label(0x0AAEA0L, "desc_1D_ECT_u8_16_AAEA0");
        count += label(0x0AAEC0L, "desc_1D_ECT_u8_16_AAEC0");
        count += label(0x0AAEE0L, "desc_1D_ECT_u8_16_AAEE0");
        count += label(0x0AAF48L, "desc_1D_ECT_u8_16_AAF48");
        count += label(0x0AAF5CL, "desc_1D_ECT_u8_16_AAF5C");
        count += label(0x0AAF70L, "desc_1D_ECT_u8_16_AAF70");
        count += label(0x0AB41CL, "desc_1D_ECT_i16_16_AB41C");
        count += label(0x0AB7CCL, "desc_1D_ECT_f32_16_AB7CC");
        count += label(0x0AB7E4L, "desc_1D_ECT_f32_16_AB7E4");
        count += label(0x0AB7FCL, "desc_1D_ECT_f32_16_AB7FC");
        count += label(0x0AB994L, "desc_1D_ECT_f32_16_AB994");
        count += label(0x0AB9ACL, "desc_1D_ECT_f32_16_AB9AC");
        count += label(0x0AB9C4L, "desc_1D_ECT_f32_16_AB9C4");
        count += label(0x0AC2B0L, "desc_1D_ECT_f32_16_AC2B0");
        count += label(0x0AC338L, "desc_1D_ECT_i16_16_AC338");
        count += label(0x0AC374L, "desc_1D_ECT_i16_5");
        count += label(0x0AC388L, "desc_1D_ECT_i16_16_AC388");
        count += label(0x0AC3A0L, "desc_1D_ECT_i16_16_AC3A0");
        count += label(0x0AC3B8L, "desc_1D_ECT_i16_16_AC3B8");
        count += label(0x0AC3CCL, "desc_1D_ECT_i16_16_AC3CC");
        count += label(0x0AC3E0L, "desc_1D_ECT_i16_16_AC3E0");
        count += label(0x0AC41CL, "desc_1D_ECT_i16_16_AC41C");
        count += label(0x0AC430L, "desc_1D_ECT_i16_16_AC430");
        count += label(0x0AC470L, "desc_1D_ECT_i16_16_AC470");
        count += label(0x0AC484L, "desc_1D_ECT_i16_16_AC484");
        count += label(0x0AC620L, "desc_1D_ECT_i16_16_AC620");
        count += label(0x0AC648L, "desc_1D_ECT_i16_16_AC648");
        count += label(0x0AC65CL, "desc_1D_ECT_i16_16_AC65C");
        count += label(0x0AC670L, "desc_1D_ECT_i16_16_AC670");
        count += label(0x0AC684L, "desc_1D_ECT_i16_16_AC684");
        count += label(0x0AC6C0L, "desc_1D_ECT_i16_16_AC6C0");
        count += label(0x0AC6E8L, "desc_1D_ECT_i16_16_AC6E8");
        count += label(0x0AC774L, "desc_1D_ECT_i16_16_AC774");
        count += label(0x0AC7D8L, "desc_1D_ECT_i16_16_AC7D8");
        count += label(0x0AC7ECL, "desc_1D_ECT_i16_16_AC7EC");
        count += label(0x0AC804L, "desc_1D_ECT_u8_16_AC804");
        count += label(0x0AC818L, "desc_1D_ECT_u8_16_AC818");
        count += label(0x0AC82CL, "desc_1D_ECT_u8_16_AC82C");
        count += label(0x0AC840L, "desc_1D_ECT_u8_16_AC840");
        count += label(0x0AC854L, "desc_1D_ECT_u8_16_AC854");
        count += label(0x0AC868L, "desc_1D_ECT_u8_16_AC868");
        count += label(0x0AC87CL, "desc_1D_ECT_u8_16_AC87C");
        count += label(0x0AC890L, "desc_1D_ECT_u8_16_AC890");
        count += label(0x0AC8A4L, "desc_1D_ECT_u8_16_AC8A4");
        count += label(0x0AC8B8L, "desc_1D_ECT_u8_16_AC8B8");
        count += label(0x0AC8D0L, "desc_1D_ECT_u8_16_AC8D0");
        count += label(0x0AC8E4L, "desc_1D_ECT_u8_16_AC8E4");
        count += label(0x0AC8F8L, "desc_1D_ECT_u8_16_AC8F8");
        count += label(0x0AC90CL, "desc_1D_ECT_u8_16_AC90C");
        count += label(0x0AC920L, "desc_1D_ECT_u8_16_AC920");
        count += label(0x0AC934L, "desc_1D_ECT_u8_16_AC934");
        count += label(0x0AC948L, "desc_1D_ECT_u8_16_AC948");
        count += label(0x0AC95CL, "desc_1D_ECT_u8_16_AC95C");
        count += label(0x0AC970L, "desc_1D_ECT_u8_16_AC970");
        count += label(0x0AC984L, "desc_1D_ECT_u8_16_AC984");
        count += label(0x0AC998L, "desc_1D_ECT_u8_16_AC998");
        count += label(0x0AC9B8L, "desc_1D_ECT_u8_16_AC9B8");
        count += label(0x0AC9CCL, "desc_1D_ECT_u8_16_AC9CC");
        count += label(0x0AC9E0L, "desc_1D_ECT_u8_16_AC9E0");
        count += label(0x0AC9F4L, "desc_1D_ECT_u8_16_AC9F4");
        count += label(0x0ACA08L, "desc_1D_ECT_u8_16_ACA08");
        count += label(0x0ACA1CL, "desc_1D_ECT_u8_16_ACA1C");
        count += label(0x0ACA30L, "desc_1D_ECT_u8_16_ACA30");
        count += label(0x0ACA44L, "desc_1D_ECT_u8_16_ACA44");
        count += label(0x0ACA58L, "desc_1D_ECT_u8_16_ACA58");
        count += label(0x0ACA6CL, "desc_1D_ECT_u8_16_ACA6C");
        count += label(0x0ACA8CL, "desc_1D_ECT_u8_16_ACA8C");
        count += label(0x0ACAA0L, "desc_1D_ECT_u8_16_ACAA0");
        count += label(0x0ACAB4L, "desc_1D_ECT_u8_16_ACAB4");
        count += label(0x0ACAC8L, "desc_1D_ECT_u8_16_ACAC8");
        count += label(0x0ACADCL, "desc_1D_ECT_u8_16_ACADC");
        count += label(0x0ACAF0L, "desc_1D_ECT_u8_16_ACAF0");
        count += label(0x0ACB04L, "desc_1D_ECT_u8_16_ACB04");
        count += label(0x0ACB18L, "desc_1D_ECT_u8_16_ACB18");
        count += label(0x0ACB2CL, "desc_1D_ECT_u8_16_ACB2C");
        count += label(0x0ACB40L, "desc_1D_ECT_u8_16_ACB40");
        count += label(0x0ACB54L, "desc_1D_ECT_u8_16_ACB54");
        count += label(0x0ACB68L, "desc_1D_ECT_u8_16_ACB68");
        count += label(0x0ACB7CL, "desc_1D_ECT_u8_16_ACB7C");
        count += label(0x0ACB90L, "desc_1D_ECT_u8_16_ACB90");
        count += label(0x0ACBCCL, "desc_1D_ECT_u8_16_ACBCC");
        count += label(0x0ACBE0L, "desc_1D_ECT_u8_16_ACBE0");
        count += label(0x0ACC1CL, "desc_1D_ECT_u8_16_ACC1C");
        count += label(0x0ACC30L, "desc_1D_ECT_u8_16_ACC30");
        count += label(0x0ACC44L, "desc_1D_ECT_u8_16_ACC44");
        count += label(0x0ACC58L, "desc_1D_ECT_u8_16_ACC58");
        count += label(0x0ACD48L, "desc_1D_ECT_u8_16_ACD48");
        count += label(0x0ACD68L, "desc_1D_ECT_u8_16_ACD68");
        count += label(0x0ACD7CL, "desc_1D_ECT_u8_16_ACD7C");
        count += label(0x0ACD90L, "desc_1D_ECT_u8_16_ACD90");
        count += label(0x0ACDA4L, "desc_1D_ECT_u8_16_ACDA4");
        count += label(0x0ACDB8L, "desc_1D_ECT_u8_16_ACDB8");
        count += label(0x0ACDCCL, "desc_1D_ECT_u8_16_ACDCC");
        count += label(0x0ACDE0L, "desc_1D_ECT_u8_16_ACDE0");
        count += label(0x0ACDF4L, "desc_1D_ECT_u8_16_ACDF4");
        count += label(0x0ACE80L, "desc_1D_ECT_u8_16_ACE80");
        count += label(0x0ACEA0L, "desc_1D_ECT_u8_16_ACEA0");
        count += label(0x0ACEC8L, "desc_1D_ECT_u8_16_ACEC8");
        count += label(0x0ACF08L, "desc_1D_ECT_u8_16_ACF08");
        count += label(0x0AD054L, "desc_1D_ECT_u8_16_AD054");
        count += label(0x0AD118L, "desc_1D_ECT_u8_7_AD118");
        count += label(0x0AD12CL, "desc_1D_ECT_u8_7_AD12C");
        count += label(0x0AD140L, "desc_1D_ECT_u8_7_AD140");
        count += label(0x0AD154L, "desc_1D_ECT_u8_7_AD154");
        count += label(0x0AD1B8L, "desc_1D_ECT_u8_7_AD1B8");
        count += label(0x0AD1CCL, "desc_1D_ECT_u8_7_AD1CC");
        count += label(0x0AD1E0L, "desc_1D_ECT_u8_7_AD1E0");
        count += label(0x0AD1F4L, "desc_1D_ECT_u8_7_AD1F4");
        count += label(0x0AD258L, "desc_1D_ECT_u8_16_AD258");
        count += label(0x0AD26CL, "desc_1D_ECT_u8_16_AD26C");
        count += label(0x0AD280L, "desc_1D_ECT_u8_16_AD280");
        count += label(0x0AD294L, "desc_1D_ECT_u8_16_AD294");
        count += label(0x0AD2A8L, "desc_1D_ECT_u8_16_AD2A8");
        count += label(0x0AD2BCL, "desc_1D_ECT_u8_16_AD2BC");
        count += label(0x0AD2D0L, "desc_1D_ECT_u8_16_AD2D0");
        count += label(0x0AD2E4L, "desc_1D_ECT_u8_16_AD2E4");
        count += label(0x0AD2F8L, "desc_1D_ECT_u8_16_AD2F8");
        count += label(0x0AD30CL, "desc_1D_ECT_u8_16_AD30C");
        count += label(0x0AD320L, "desc_1D_ECT_u8_16_AD320");
        count += label(0x0AD334L, "desc_1D_ECT_u8_16_AD334");
        count += label(0x0AD348L, "desc_1D_ECT_u8_16_AD348");
        count += label(0x0AD35CL, "desc_1D_ECT_u8_16_AD35C");
        count += label(0x0AD390L, "desc_1D_ECT_u8_16_AD390");
        count += label(0x0AD3A4L, "desc_1D_ECT_u8_16_AD3A4");
        count += label(0x0AD3B8L, "desc_1D_ECT_u8_16_AD3B8");
        count += label(0x0AD3D8L, "desc_1D_ECT_u8_16_AD3D8");
        count += label(0x0AD3ECL, "desc_1D_ECT_u8_16_AD3EC");
        count += label(0x0AD420L, "desc_1D_ECT_u8_16_AD420");
        count += label(0x0AD4C4L, "desc_1D_ECT_f32_16_AD4C4");
        count += label(0x0ADA98L, "desc_1D_ECT_i16_16_ADA98");
        count += label(0x0ADAACL, "desc_1D_ECT_i16_16_ADAAC");
        count += label(0x0ADB4CL, "desc_1D_ECT_i16_16_ADB4C");
        count += label(0x0ADB60L, "desc_1D_ECT_i16_16_ADB60");
        count += label(0x0ADB74L, "desc_1D_ECT_i16_16_ADB74");
        count += label(0x0ADB88L, "desc_1D_ECT_i16_16_ADB88");
        count += label(0x0ADB9CL, "desc_1D_ECT_i16_16_ADB9C");
        count += label(0x0ADBB0L, "desc_1D_ECT_i16_16_ADBB0");
        count += label(0x0ADBC4L, "desc_1D_ECT_i16_16_ADBC4");
        count += label(0x0ADBD8L, "desc_1D_ECT_i16_16_ADBD8");
        count += label(0x0ADBECL, "desc_1D_ECT_i16_16_ADBEC");
        count += label(0x0ADC00L, "desc_1D_ECT_i16_16_ADC00");
        count += label(0x0ADC14L, "desc_1D_ECT_i16_16_ADC14");
        count += label(0x0ADD90L, "desc_1D_ECT_i16_16_ADD90");
        count += label(0x0ADDA4L, "desc_1D_ECT_i16_16_ADDA4");
        count += label(0x0ADE08L, "desc_1D_ECT_i16_16_ADE08");
        count += label(0x0ADF34L, "desc_1D_ECT_i16_16_ADF34");
        count += label(0x0ADF48L, "desc_1D_ECT_i16_16_ADF48");
        count += label(0x0ADFACL, "desc_1D_ECT_i16_16_ADFAC");
        count += label(0x0AE034L, "desc_1D_ECT_u8_16_AE034");
        count += label(0x0AE054L, "desc_1D_ECT_u8_16_AE054");
        count += label(0x0AE068L, "desc_1D_ECT_u8_16_AE068");
        count += label(0x0AE07CL, "desc_1D_ECT_u8_16_AE07C");
        count += label(0x0AE090L, "desc_1D_ECT_u8_16_AE090");
        count += label(0x0AE0A4L, "desc_1D_ECT_u8_16_AE0A4");
        count += label(0x0AE0C4L, "desc_1D_ECT_u8_16_AE0C4");
        count += label(0x0AE0D8L, "desc_1D_ECT_u8_16_AE0D8");
        count += label(0x0AE0ECL, "desc_1D_ECT_u8_16_AE0EC");
        count += label(0x0AE88CL, "desc_1D_ECT_u8_16_AE88C");
        count += label(0x0AE8A0L, "desc_1D_ECT_u8_16_AE8A0");
        count += label(0x0AE8C8L, "desc_1D_ECT_u8_16_AE8C8");
        count += label(0x0AE8DCL, "desc_1D_ECT_u8_16_AE8DC");
        count += label(0x0AE8F0L, "desc_1D_ECT_u8_16_AE8F0");
        count += label(0x0AE904L, "desc_1D_ECT_u8_16_AE904");
        count += label(0x0AE918L, "desc_1D_ECT_u8_16_AE918");
        count += label(0x0AE92CL, "desc_1D_ECT_u8_16_AE92C");
        count += label(0x0AE940L, "desc_1D_ECT_u8_16_AE940");
        count += label(0x0AE954L, "desc_1D_ECT_u8_16_AE954");
        count += label(0x0AE968L, "desc_1D_ECT_u8_16_AE968");
        count += label(0x0AE97CL, "desc_1D_ECT_u8_16_AE97C");
        count += label(0x0AE990L, "desc_1D_ECT_u8_16_AE990");
        count += label(0x0AE9A4L, "desc_1D_ECT_u8_16_AE9A4");
        count += label(0x0AE9B8L, "desc_1D_ECT_u8_16_AE9B8");
        count += label(0x0AE9CCL, "desc_1D_ECT_u8_16_AE9CC");
        count += label(0x0AE9E0L, "desc_1D_ECT_u8_16_AE9E0");
        count += label(0x0AE9F4L, "desc_1D_ECT_u8_16_AE9F4");
        count += label(0x0AEA08L, "desc_1D_ECT_u8_16_AEA08");
        count += label(0x0AEA1CL, "desc_1D_ECT_u8_16_AEA1C");
        count += label(0x0AEA30L, "desc_1D_ECT_u8_16_AEA30");
        count += label(0x0AEA44L, "desc_1D_ECT_u8_16_AEA44");
        count += label(0x0AEA58L, "desc_1D_ECT_u8_16_AEA58");
        count += label(0x0AEA6CL, "desc_1D_ECT_u8_16_AEA6C");
        count += label(0x0AEA80L, "desc_1D_ECT_u8_16_AEA80");
        count += label(0x0AEA94L, "desc_1D_ECT_u8_16_AEA94");
        count += label(0x0AEAA8L, "desc_1D_ECT_u8_16_AEAA8");
        count += label(0x0AEABCL, "desc_1D_ECT_u8_16_AEABC");
        count += label(0x0AEAE4L, "desc_1D_ECT_u8_16_AEAE4");
        count += label(0x0AEAF8L, "desc_1D_ECT_u8_16_AEAF8");
        count += label(0x0AEB0CL, "desc_1D_ECT_u8_16_AEB0C");
        count += label(0x0AEB20L, "desc_1D_ECT_u8_16_AEB20");
        count += label(0x0AEB34L, "desc_1D_ECT_u8_16_AEB34");
        count += label(0x0AEB48L, "desc_1D_ECT_u8_16_AEB48");
        count += label(0x0AEB5CL, "desc_1D_ECT_u8_16_AEB5C");
        count += label(0x0AEB70L, "desc_1D_ECT_u8_16_AEB70");
        count += label(0x0AEB84L, "desc_1D_ECT_u8_16_AEB84");
        count += label(0x0AEB98L, "desc_1D_ECT_u8_16_AEB98");
        count += label(0x0AEBACL, "desc_1D_ECT_u8_16_AEBAC");
        count += label(0x0AEBC0L, "desc_1D_ECT_u8_16_AEBC0");
        count += label(0x0AEBD4L, "desc_1D_ECT_u8_16_AEBD4");
        count += label(0x0AEBE8L, "desc_1D_ECT_u8_16_AEBE8");
        count += label(0x0AEC10L, "desc_1D_ECT_u8_16_AEC10");
        count += label(0x0AEC24L, "desc_1D_ECT_u8_16_AEC24");
        count += label(0x0AEC38L, "desc_1D_ECT_u8_16_AEC38");
        count += label(0x0AEC88L, "desc_1D_ECT_u8_16_AEC88");
        count += label(0x0AEC9CL, "desc_1D_ECT_u8_16_AEC9C");
        count += label(0x0AECB0L, "desc_1D_ECT_u8_16_AECB0");
        count += label(0x0AECC4L, "desc_1D_ECT_u8_16_AECC4");
        count += label(0x0AECD8L, "desc_1D_ECT_u8_16_AECD8");
        count += label(0x0AECECL, "desc_1D_ECT_u8_16_AECEC");
        count += label(0x0AED0CL, "desc_1D_ECT_u8_16_AED0C");
        count += label(0x0AED20L, "desc_1D_ECT_u8_16_AED20");
        count += label(0x0AED34L, "desc_1D_ECT_u8_16_AED34");
        count += label(0x0AED48L, "desc_1D_ECT_u8_16_AED48");
        count += label(0x0AED5CL, "desc_1D_ECT_u8_16_AED5C");
        count += label(0x0AED70L, "desc_1D_ECT_u8_16_AED70");
        count += label(0x0AED84L, "desc_1D_ECT_u8_16_AED84");
        count += label(0x0AED98L, "desc_1D_ECT_u8_16_AED98");
        count += label(0x0AEDACL, "desc_1D_ECT_u8_16_AEDAC");
        count += label(0x0AEDC0L, "desc_1D_ECT_u8_16_AEDC0");
        count += label(0x0AEDE0L, "desc_1D_ECT_u8_16_AEDE0");
        count += label(0x0AEDF4L, "desc_1D_ECT_u8_16_AEDF4");
        count += label(0x0AEE08L, "desc_1D_ECT_u8_16_AEE08");
        count += label(0x0AEEA8L, "desc_1D_ECT_u8_16_AEEA8");
        count += label(0x0AEEBCL, "desc_1D_ECT_u8_16_AEEBC");
        count += label(0x0AEED0L, "desc_1D_ECT_u8_16_AEED0");
        count += label(0x0AEEF8L, "desc_1D_ECT_u8_16_AEEF8");
        count += label(0x0AEFC0L, "desc_1D_ECT_f32_16_AEFC0");
        count += label(0x0AEFD8L, "desc_1D_ECT_f32_16_AEFD8");
        count += label(0x0AF3D4L, "desc_1D_ECT_u8_16_AF3D4");
        count += label(0x0AF3F4L, "desc_1D_ECT_u8_16_AF3F4");
        count += label(0x0AF408L, "desc_1D_ECT_u8_16_AF408");
        count += label(0x0AF4F0L, "desc_1D_ECT_i16_16_AF4F0");
        count += label(0x0AF504L, "desc_1D_ECT_f32_16_AF504");
        count += label(0x0AF56CL, "desc_1D_ECT_u8_16_AF56C");
        count += label(0x0AF580L, "desc_1D_ECT_f32_16_AF580");
        count += label(0x0AF5A0L, "desc_1D_ECT_f32_16_AF5A0");
        count += label(0x0AF5CCL, "desc_1D_ECT_u8_16_AF5CC");
        count += label(0x0AF6D8L, "desc_1D_ECT_i16_16_AF6D8");
        count += label(0x0AF6ECL, "desc_1D_ECT_i16_16_AF6EC");
        count += label(0x0AF700L, "desc_1D_ECT_i16_16_AF700");
        count += label(0x0AF714L, "desc_1D_ECT_i16_16_AF714");
        count += label(0x0AF750L, "desc_1D_ECT_i16_16_AF750");
        count += label(0x0AF764L, "desc_1D_ECT_i16_16_AF764");
        count += label(0x0AF778L, "desc_1D_ECT_i16_16_AF778");
        count += label(0x0AF78CL, "desc_1D_ECT_u8_16_AF78C");
        count += label(0x0AF7A0L, "desc_1D_ECT_u8_16_AF7A0");
        count += label(0x0AF7B4L, "desc_1D_ECT_u8_16_AF7B4");
        count += label(0x0AF7CCL, "desc_1D_ECT_u8_16_AF7CC");

        // --- 1D_IAT (5 descriptors) ---
        count += label(0x0AB660L, "desc_1D_IAT_u8_11_AB660");
        count += label(0x0AB688L, "desc_1D_IAT_u8_10");
        count += label(0x0AB69CL, "desc_1D_IAT_u8_11_AB69C");
        count += label(0x0AB76CL, "desc_1D_IAT_f32_4");
        count += label(0x0AF008L, "desc_1D_IAT_f32_11");

        // --- 1D_IPW (12 descriptors) ---
        count += label(0x0AABE0L, "desc_1D_IPW_f32_6_AABE0");
        count += label(0x0AABF8L, "desc_1D_IPW_f32_6_AABF8");
        count += label(0x0AB17CL, "desc_1D_IPW_i16_10");
        count += label(0x0AC5F8L, "desc_1D_IPW_i16_6_AC5F8");
        count += label(0x0AC60CL, "desc_1D_IPW_i16_6_AC60C");
        count += label(0x0ACE20L, "desc_1D_IPW_u8_13");
        count += label(0x0AD0B8L, "desc_1D_IPW_f32_10_AD0B8");
        count += label(0x0AD0D0L, "desc_1D_IPW_f32_10_AD0D0");
        count += label(0x0AD434L, "desc_1D_IPW_f32_9");
        count += label(0x0ADFE8L, "desc_1D_IPW_f32_5");
        count += label(0x0AF450L, "desc_1D_IPW_f32_16");
        count += label(0x0AF480L, "desc_1D_IPW_f32_30");

        // --- 1D_KnockIdx (4 descriptors) ---
        count += label(0x0AB56CL, "desc_1D_KnockIdx_u8_7_AB56C");
        count += label(0x0AB580L, "desc_1D_KnockIdx_u8_7_AB580");
        count += label(0x0ADC28L, "desc_1D_KnockIdx_i16_8");
        count += label(0x0AF1CCL, "desc_1D_KnockIdx_f32_24");

        // --- 1D_Load (24 descriptors) ---
        count += label(0x0AAA4CL, "desc_1D_Load_f32_16_AAA4C");
        count += label(0x0AB498L, "desc_1D_Load_u8_4");
        count += label(0x0AB9DCL, "desc_1D_Load_f32_5");
        count += label(0x0ABA0CL, "desc_1D_Load_f32_7_ABA0C");
        count += label(0x0ABA24L, "desc_1D_Load_f32_7_ABA24");
        count += label(0x0ACE0CL, "desc_1D_Load_u8_10");
        count += label(0x0ACE34L, "desc_1D_Load_f32_16_ACE34");
        count += label(0x0ACEB4L, "desc_1D_Load_u8_11_ACEB4");
        count += label(0x0ACEDCL, "desc_1D_Load_u8_11_ACEDC");
        count += label(0x0AD168L, "desc_1D_Load_u8_7_AD168");
        count += label(0x0AD17CL, "desc_1D_Load_u8_7_AD17C");
        count += label(0x0AD190L, "desc_1D_Load_u8_7_AD190");
        count += label(0x0AD1A4L, "desc_1D_Load_u8_7_AD1A4");
        count += label(0x0AE194L, "desc_1D_Load_f32_4_AE194");
        count += label(0x0AE1ACL, "desc_1D_Load_f32_4_AE1AC");
        count += label(0x0AE1C4L, "desc_1D_Load_f32_4_AE1C4");
        count += label(0x0AE1DCL, "desc_1D_Load_f32_4_AE1DC");
        count += label(0x0AE1F4L, "desc_1D_Load_f32_4_AE1F4");
        count += label(0x0AE20CL, "desc_1D_Load_f32_4_AE20C");
        count += label(0x0AE224L, "desc_1D_Load_f32_4_AE224");
        count += label(0x0AE23CL, "desc_1D_Load_f32_4_AE23C");
        count += label(0x0AE254L, "desc_1D_Load_f32_4_AE254");
        count += label(0x0AE2D8L, "desc_1D_Load_f32_8");
        count += label(0x0AF438L, "desc_1D_Load_f32_17");

        // --- 1D_MAF (2 descriptors) ---
        count += label(0x0AB21CL, "desc_1D_MAF_u8_14");
        count += label(0x0AC7C4L, "desc_1D_MAF_i16_9");

        // --- 1D_Pressure (11 descriptors) ---
        count += label(0x0AAAF0L, "desc_1D_Pressure_u8_6_AAAF0");
        count += label(0x0AAB04L, "desc_1D_Pressure_u8_6_AAB04");
        count += label(0x0AAB2CL, "desc_1D_Pressure_u8_9_AAB2C");
        count += label(0x0AAB54L, "desc_1D_Pressure_u8_4_AAB54");
        count += label(0x0AAB68L, "desc_1D_Pressure_u8_9_AAB68");
        count += label(0x0AAB90L, "desc_1D_Pressure_u8_9_AAB90");
        count += label(0x0AAC64L, "desc_1D_Pressure_f32_4_AAC64");
        count += label(0x0AAC7CL, "desc_1D_Pressure_f32_4_AAC7C");
        count += label(0x0ABAE4L, "desc_1D_Pressure_f32_6");
        count += label(0x0ABB74L, "desc_1D_Pressure_f32_4_ABB74");
        count += label(0x0AEAD0L, "desc_1D_Pressure_u8_4_AEAD0");

        // --- 1D_RPM (107 descriptors) ---
        count += label(0x0AA7C4L, "desc_1D_RPM_wide_u8_4_AA7C4");
        count += label(0x0AA7F8L, "desc_1D_RPM_wide_u8_4_AA7F8");
        count += label(0x0AA950L, "desc_1D_RPM_f32_5_AA950");
        count += label(0x0AA968L, "desc_1D_RPM_f32_5_AA968");
        count += label(0x0AAA20L, "desc_1D_RPM_i16_10_AAA20");
        count += label(0x0AAA34L, "desc_1D_RPM_f32_15_AAA34");
        count += label(0x0AAF84L, "desc_1D_RPM_u8_15_AAF84");
        count += label(0x0AAFACL, "desc_1D_RPM_f32_10_AAFAC");
        count += label(0x0AAFC4L, "desc_1D_RPM_f32_7");
        count += label(0x0AB168L, "desc_1D_RPM_i16_10_AB168");
        count += label(0x0AB2D8L, "desc_1D_RPM_i16_14_AB2D8");
        count += label(0x0AB2ECL, "desc_1D_RPM_i16_14_AB2EC");
        count += label(0x0AB300L, "desc_1D_RPM_i16_14_AB300");
        count += label(0x0AB314L, "desc_1D_RPM_i16_14_AB314");
        count += label(0x0AB328L, "desc_1D_RPM_wide_f32_13");
        count += label(0x0AB340L, "desc_1D_RPM_i16_13_AB340");
        count += label(0x0AB354L, "desc_1D_RPM_i16_13_AB354");
        count += label(0x0AB368L, "desc_1D_RPM_i16_14_AB368");
        count += label(0x0AB37CL, "desc_1D_RPM_i16_14_AB37C");
        count += label(0x0AB390L, "desc_1D_RPM_i16_14_AB390");
        count += label(0x0AB3A4L, "desc_1D_RPM_i16_14_AB3A4");
        count += label(0x0AB3B8L, "desc_1D_RPM_i16_14_AB3B8");
        count += label(0x0AB3CCL, "desc_1D_RPM_i16_14_AB3CC");
        count += label(0x0AB3E0L, "desc_1D_RPM_i16_14_AB3E0");
        count += label(0x0AB3F4L, "desc_1D_RPM_i16_14_AB3F4");
        count += label(0x0AB408L, "desc_1D_RPM_i16_14_AB408");
        count += label(0x0AB558L, "desc_1D_RPM_u8_10_AB558");
        count += label(0x0AB784L, "desc_1D_RPM_f32_14_AB784");
        count += label(0x0AB79CL, "desc_1D_RPM_f32_14_AB79C");
        count += label(0x0AB7B4L, "desc_1D_RPM_f32_14_AB7B4");
        count += label(0x0AB82CL, "desc_1D_RPM_f32_14_AB82C");
        count += label(0x0AB85CL, "desc_1D_RPM_f32_14_AB85C");
        count += label(0x0AB880L, "desc_1D_RPM_f32_10_AB880");
        count += label(0x0AB8A4L, "desc_1D_RPM_f32_10_AB8A4");
        count += label(0x0AB8C8L, "desc_1D_RPM_f32_14_AB8C8");
        count += label(0x0AB8E0L, "desc_1D_RPM_f32_14_AB8E0");
        count += label(0x0AB8F8L, "desc_1D_RPM_f32_14_AB8F8");
        count += label(0x0AB910L, "desc_1D_RPM_f32_14_AB910");
        count += label(0x0AB928L, "desc_1D_RPM_f32_14_AB928");
        count += label(0x0AB940L, "desc_1D_RPM_f32_14_AB940");
        count += label(0x0AB964L, "desc_1D_RPM_f32_14_AB964");
        count += label(0x0AB97CL, "desc_1D_RPM_f32_13");
        count += label(0x0AC450L, "desc_1D_RPM_f32_4");
        count += label(0x0AC4ACL, "desc_1D_RPM_wide_i16_16_AC4AC");
        count += label(0x0AC4FCL, "desc_1D_RPM_wide_i16_11_AC4FC");
        count += label(0x0AC510L, "desc_1D_RPM_wide_i16_11_AC510");
        count += label(0x0AC5BCL, "desc_1D_RPM_wide_i16_16_AC5BC");
        count += label(0x0AC634L, "desc_1D_RPM_wide_i16_16_AC634");
        count += label(0x0AC710L, "desc_1D_RPM_i16_7_AC710");
        count += label(0x0AC724L, "desc_1D_RPM_i16_7_AC724");
        count += label(0x0AC738L, "desc_1D_RPM_i16_7_AC738");
        count += label(0x0AC74CL, "desc_1D_RPM_i16_7_AC74C");
        count += label(0x0AC7B0L, "desc_1D_RPM_wide_i16_16_AC7B0");
        count += label(0x0ACBA4L, "desc_1D_RPM_wide_u8_16_ACBA4");
        count += label(0x0ACBB8L, "desc_1D_RPM_wide_u8_16_ACBB8");
        count += label(0x0ACBF4L, "desc_1D_RPM_wide_u8_16_ACBF4");
        count += label(0x0ACC08L, "desc_1D_RPM_wide_u8_16_ACC08");
        count += label(0x0ACC6CL, "desc_1D_RPM_wide_u8_16_ACC6C");
        count += label(0x0ACC80L, "desc_1D_RPM_wide_u8_16_ACC80");
        count += label(0x0ACD34L, "desc_1D_RPM_u8_8");
        count += label(0x0ACE54L, "desc_1D_RPM_wide_f32_6_ACE54");
        count += label(0x0AD090L, "desc_1D_RPM_wide_u8_9");
        count += label(0x0AD0A4L, "desc_1D_RPM_wide_u8_16_AD0A4");
        count += label(0x0AD0F0L, "desc_1D_RPM_wide_u8_16_AD0F0");
        count += label(0x0AD208L, "desc_1D_RPM_u8_7_AD208");
        count += label(0x0AD21CL, "desc_1D_RPM_u8_7_AD21C");
        count += label(0x0AD230L, "desc_1D_RPM_u8_7_AD230");
        count += label(0x0AD244L, "desc_1D_RPM_u8_7_AD244");
        count += label(0x0AD400L, "desc_1D_RPM_f32_8_AD400");
        count += label(0x0ADA84L, "desc_1D_RPM_i16_8");
        count += label(0x0ADDE0L, "desc_1D_RPM_i16_7_ADDE0");
        count += label(0x0ADDF4L, "desc_1D_RPM_i16_7_ADDF4");
        count += label(0x0ADE30L, "desc_1D_RPM_i16_13_ADE30");
        count += label(0x0ADFC0L, "desc_1D_RPM_wide_i16_16_ADFC0");
        count += label(0x0ADFD4L, "desc_1D_RPM_wide_i16_16_ADFD4");
        count += label(0x0AE000L, "desc_1D_RPM_f32_8_AE000");
        count += label(0x0AE10CL, "desc_1D_RPM_u8_7_AE10C");
        count += label(0x0AE120L, "desc_1D_RPM_wide_u8_16_AE120");
        count += label(0x0AE134L, "desc_1D_RPM_f32_10_AE134");
        count += label(0x0AE17CL, "desc_1D_RPM_f32_6");
        count += label(0x0AE26CL, "desc_1D_RPM_f32_18");
        count += label(0x0AE290L, "desc_1D_RPM_f32_10_AE290");
        count += label(0x0AE2A8L, "desc_1D_RPM_f32_10_AE2A8");
        count += label(0x0AE2C0L, "desc_1D_RPM_f32_10_AE2C0");
        count += label(0x0AE7D8L, "desc_1D_RPM_wide_i16_20_AE7D8");
        count += label(0x0AE7ECL, "desc_1D_RPM_wide_i16_20_AE7EC");
        count += label(0x0AEC60L, "desc_1D_RPM_wide_u8_20");
        count += label(0x0AEF60L, "desc_1D_RPM_f32_8_AEF60");
        count += label(0x0AEF78L, "desc_1D_RPM_wide_f32_8");
        count += label(0x0AEFF0L, "desc_1D_RPM_wide_f32_6_AEFF0");
        count += label(0x0AF144L, "desc_1D_RPM_u8_16_AF144");
        count += label(0x0AF158L, "desc_1D_RPM_u8_16_AF158");
        count += label(0x0AF16CL, "desc_1D_RPM_u8_16_AF16C");
        count += label(0x0AF180L, "desc_1D_RPM_u8_16_AF180");
        count += label(0x0AF1A8L, "desc_1D_RPM_f32_8_AF1A8");
        count += label(0x0AF3C0L, "desc_1D_RPM_mid_u8_5");
        count += label(0x0AF498L, "desc_1D_RPM_f32_15_AF498");
        count += label(0x0AF4D8L, "desc_1D_RPM_f32_15_AF4D8");
        count += label(0x0AF51CL, "desc_1D_RPM_u8_10_AF51C");
        count += label(0x0AF530L, "desc_1D_RPM_f32_10_AF530");
        count += label(0x0AF630L, "desc_1D_RPM_u8_16_AF630");
        count += label(0x0AF644L, "desc_1D_RPM_u8_16_AF644");
        count += label(0x0AF658L, "desc_1D_RPM_u8_16_AF658");
        count += label(0x0AF66CL, "desc_1D_RPM_u8_16_AF66C");
        count += label(0x0AF680L, "desc_1D_RPM_u8_16_AF680");
        count += label(0x0AF694L, "desc_1D_RPM_u8_16_AF694");
        count += label(0x0AF7E0L, "desc_1D_RPM_u8_15_AF7E0");

        // --- 1D_SmallRatio (5 descriptors) ---
        count += label(0x0AAB7CL, "desc_1D_SmallRatio_u8_15");
        count += label(0x0ACC94L, "desc_1D_SmallRatio_u8_13_ACC94");
        count += label(0x0ACCA8L, "desc_1D_SmallRatio_u8_13_ACCA8");
        count += label(0x0AE020L, "desc_1D_SmallRatio_i16_5");
        count += label(0x0AF468L, "desc_1D_SmallRatio_f32_13");

        // --- 1D_Throttle (41 descriptors) ---
        count += label(0x0AA760L, "desc_1D_Throttle_u8_16_AA760");
        count += label(0x0AA774L, "desc_1D_Throttle_u8_16_AA774");
        count += label(0x0AAA0CL, "desc_1D_Throttle_i16_6_AAA0C");
        count += label(0x0AABCCL, "desc_1D_Throttle_u8_5");
        count += label(0x0AAC10L, "desc_1D_Throttle_f32_10_AAC10");
        count += label(0x0AACACL, "desc_1D_Throttle_f32_10_AACAC");
        count += label(0x0AACC4L, "desc_1D_Throttle_f32_10_AACC4");
        count += label(0x0AAF08L, "desc_1D_Throttle_u8_21");
        count += label(0x0AAF1CL, "desc_1D_Throttle_f32_4");
        count += label(0x0AB11CL, "desc_1D_Throttle_f32_10_AB11C");
        count += label(0x0AB134L, "desc_1D_Throttle_f32_10_AB134");
        count += label(0x0AB638L, "desc_1D_Throttle_u8_9_AB638");
        count += label(0x0AB64CL, "desc_1D_Throttle_u8_9_AB64C");
        count += label(0x0ABA54L, "desc_1D_Throttle_f32_13");
        count += label(0x0AC360L, "desc_1D_Throttle_i16_10_AC360");
        count += label(0x0AC544L, "desc_1D_Throttle_i16_8_AC544");
        count += label(0x0AC5E4L, "desc_1D_Throttle_i16_6_AC5E4");
        count += label(0x0ADE1CL, "desc_1D_Throttle_i16_7");
        count += label(0x0ADE44L, "desc_1D_Throttle_i16_8_ADE44");
        count += label(0x0ADE58L, "desc_1D_Throttle_i16_8_ADE58");
        count += label(0x0ADE6CL, "desc_1D_Throttle_i16_8_ADE6C");
        count += label(0x0ADE80L, "desc_1D_Throttle_i16_8_ADE80");
        count += label(0x0ADE94L, "desc_1D_Throttle_i16_8_ADE94");
        count += label(0x0ADEA8L, "desc_1D_Throttle_i16_8_ADEA8");
        count += label(0x0ADEBCL, "desc_1D_Throttle_i16_8_ADEBC");
        count += label(0x0ADED0L, "desc_1D_Throttle_i16_8_ADED0");
        count += label(0x0ADEE4L, "desc_1D_Throttle_i16_8_ADEE4");
        count += label(0x0ADEF8L, "desc_1D_Throttle_i16_8_ADEF8");
        count += label(0x0ADF0CL, "desc_1D_Throttle_i16_8_ADF0C");
        count += label(0x0ADF20L, "desc_1D_Throttle_i16_8_ADF20");
        count += label(0x0AE7C4L, "desc_1D_Throttle_i16_11");
        count += label(0x0AE800L, "desc_1D_Throttle_i16_10_AE800");
        count += label(0x0AE814L, "desc_1D_Throttle_i16_10_AE814");
        count += label(0x0AE8B4L, "desc_1D_Throttle_u8_11_AE8B4");
        count += label(0x0AEF18L, "desc_1D_Throttle_f32_6_AEF18");
        count += label(0x0AEF30L, "desc_1D_Throttle_f32_6_AEF30");
        count += label(0x0AEF48L, "desc_1D_Throttle_f32_6_AEF48");
        count += label(0x0AF5E0L, "desc_1D_Throttle_i16_5_AF5E0");
        count += label(0x0AF5F4L, "desc_1D_Throttle_i16_5_AF5F4");
        count += label(0x0AF6A8L, "desc_1D_Throttle_u8_11_AF6A8");
        count += label(0x0AF81CL, "desc_1D_Throttle_u8_12");

        // --- 1D_TimingAdv (13 descriptors) ---
        count += label(0x0ABB44L, "desc_1D_TimingAdv_f32_7");
        count += label(0x0AC4E8L, "desc_1D_TimingAdv_i16_16");
        count += label(0x0ACF64L, "desc_1D_TimingAdv_u8_9_ACF64");
        count += label(0x0ACF78L, "desc_1D_TimingAdv_u8_9_ACF78");
        count += label(0x0ACFDCL, "desc_1D_TimingAdv_u8_9_ACFDC");
        count += label(0x0ACFF0L, "desc_1D_TimingAdv_u8_9_ACFF0");
        count += label(0x0AD004L, "desc_1D_TimingAdv_u8_9_AD004");
        count += label(0x0AD018L, "desc_1D_TimingAdv_u8_9_AD018");
        count += label(0x0AD02CL, "desc_1D_TimingAdv_u8_9_AD02C");
        count += label(0x0AD040L, "desc_1D_TimingAdv_u8_9_AD040");
        count += label(0x0AD068L, "desc_1D_TimingAdv_u8_8_AD068");
        count += label(0x0AD07CL, "desc_1D_TimingAdv_u8_8_AD07C");
        count += label(0x0AEBFCL, "desc_1D_TimingAdv_u8_7");

        // --- 1D_VehSpd (11 descriptors) ---
        count += label(0x0AA93CL, "desc_1D_VehSpd_u8_9_AA93C");
        count += label(0x0AB9F4L, "desc_1D_VehSpd_f32_8_AB9F4");
        count += label(0x0ABBBCL, "desc_1D_VehSpd_f32_8_ABBBC");
        count += label(0x0AC4C0L, "desc_1D_VehSpd_i16_9_AC4C0");
        count += label(0x0AC4D4L, "desc_1D_VehSpd_i16_9_AC4D4");
        count += label(0x0AC788L, "desc_1D_VehSpd_i16_7_AC788");
        count += label(0x0AC79CL, "desc_1D_VehSpd_i16_7_AC79C");
        count += label(0x0AE79CL, "desc_1D_VehSpd_i16_10_AE79C");
        count += label(0x0AE7B0L, "desc_1D_VehSpd_i16_10_AE7B0");
        count += label(0x0AEE1CL, "desc_1D_VehSpd_u8_9_AEE1C");
        count += label(0x0AEE30L, "desc_1D_VehSpd_u8_9_AEE30");

        // --- 1D_Voltage (2 descriptors) ---
        count += label(0x0AA788L, "desc_1D_Voltage_i16_5");
        count += label(0x0AF5B8L, "desc_1D_Voltage_u8_11");

        // --- 1D_range (91 descriptors) ---
        count += label(0x0AA79CL, "desc_1D_range_20_4096_u8_5");
        count += label(0x0AA7B0L, "desc_1D_range_0_3500_u8_8");
        count += label(0x0AA7D8L, "desc_1D_range_40_20_f32_12");
        count += label(0x0AA80CL, "desc_1D_range_40_20_u8_12");
        count += label(0x0AA914L, "desc_1D_range_160_160_u8_9");
        count += label(0x0AA928L, "desc_1D_range_240_0_u8_9");
        count += label(0x0AABA4L, "desc_1D_range_100_760_u8_5");
        count += label(0x0AAC94L, "desc_1D_range_20_0_f32_6");
        count += label(0x0AAE64L, "desc_1D_range_4000_7500_u8_8");
        count += label(0x0AAE78L, "desc_1D_range_3200_6000_u8_8");
        count += label(0x0AAE8CL, "desc_1D_range_524_758_u8_4");
        count += label(0x0AAFDCL, "desc_1D_range_15_60_f32_4");
        count += label(0x0AB154L, "desc_1D_range_20_80_i16_7");
        count += label(0x0AB190L, "desc_1D_range_0_0_u8_7_AB190");
        count += label(0x0AB230L, "desc_1D_range_200_1100_u8_10_AB230");
        count += label(0x0AB244L, "desc_1D_range_200_1100_u8_10_AB244");
        count += label(0x0AB258L, "desc_1D_range_200_1100_u8_10_AB258");
        count += label(0x0AB2A4L, "desc_1D_range_20_20_f32_4");
        count += label(0x0AB464L, "desc_1D_range_30_20_f32_6");
        count += label(0x0AB484L, "desc_1D_range_15_45_u8_5_AB484");
        count += label(0x0AB4ACL, "desc_1D_range_15_45_u8_5_AB4AC");
        count += label(0x0AB4C0L, "desc_1D_range_0_1000_u8_6");
        count += label(0x0AB4E0L, "desc_1D_range_0_1600_u8_12");
        count += label(0x0AB4F4L, "desc_1D_range_100_1000_u8_9");
        count += label(0x0AB5D4L, "desc_1D_range_7_25_u8_4_AB5D4");
        count += label(0x0AB5E8L, "desc_1D_range_7_27_u8_4");
        count += label(0x0AB5FCL, "desc_1D_range_7_25_u8_4_AB5FC");
        count += label(0x0AB610L, "desc_1D_range_7_25_u8_4_AB610");
        count += label(0x0AB624L, "desc_1D_range_7_25_u8_4_AB624");
        count += label(0x0AB754L, "desc_1D_range_20_20_f32_5");
        count += label(0x0ABA3CL, "desc_1D_range_7_30_f32_4");
        count += label(0x0ABA6CL, "desc_1D_range_7_26_f32_9");
        count += label(0x0ABA84L, "desc_1D_range_7_25_f32_4_ABA84");
        count += label(0x0ABA9CL, "desc_1D_range_7_25_f32_4_ABA9C");
        count += label(0x0ABAB4L, "desc_1D_range_7_35_f32_7");
        count += label(0x0ABACCL, "desc_1D_range_7_35_f32_6");
        count += label(0x0ABAFCL, "desc_1D_range_500_1000_f32_6");
        count += label(0x0ABB14L, "desc_1D_range_520_760_f32_7");
        count += label(0x0ABB2CL, "desc_1D_range_0_20000_f32_5");
        count += label(0x0ABB5CL, "desc_1D_range_520_840_f32_9");
        count += label(0x0ABB8CL, "desc_1D_range_525_750_f32_4_ABB8C");
        count += label(0x0ABBA4L, "desc_1D_range_525_750_f32_4_ABBA4");
        count += label(0x0AC26CL, "desc_1D_range_8_24_f32_4");
        count += label(0x0AC284L, "desc_1D_range_7_30_u8_5");
        count += label(0x0AC298L, "desc_1D_range_0_0_f32_24");
        count += label(0x0AC34CL, "desc_1D_range_184_760_i16_10");
        count += label(0x0AC3F4L, "desc_1D_range_3600_7200_i16_10_AC3F4");
        count += label(0x0AC408L, "desc_1D_range_3600_7200_i16_10_AC408");
        count += label(0x0AC524L, "desc_1D_range_0_0_f32_6_AC524");
        count += label(0x0AC558L, "desc_1D_range_0_110000_i16_12_AC558");
        count += label(0x0AC580L, "desc_1D_range_0_110000_i16_12_AC580");
        count += label(0x0AC5A8L, "desc_1D_range_10_0_i16_6");
        count += label(0x0AC5D0L, "desc_1D_range_11_89_i16_6");
        count += label(0x0AC760L, "desc_1D_range_300_650_i16_8");
        count += label(0x0ACE6CL, "desc_1D_range_0_0_u8_9");
        count += label(0x0ACEF0L, "desc_1D_range_0_0_f32_6_ACEF0");
        count += label(0x0ACF28L, "desc_1D_range_10_50_u8_5_ACF28");
        count += label(0x0ACF3CL, "desc_1D_range_0_110000_u8_12_ACF3C");
        count += label(0x0ACF50L, "desc_1D_range_0_110000_u8_12_ACF50");
        count += label(0x0ACF8CL, "desc_1D_range_0_110000_u8_12_ACF8C");
        count += label(0x0ACFA0L, "desc_1D_range_0_110000_u8_12_ACFA0");
        count += label(0x0ACFB4L, "desc_1D_range_10_50_u8_5_ACFB4");
        count += label(0x0ACFC8L, "desc_1D_range_10_50_u8_5_ACFC8");
        count += label(0x0AD104L, "desc_1D_range_0_0_u8_7_AD104");
        count += label(0x0AD44CL, "desc_1D_range_700_800_f32_16");
        count += label(0x0AD464L, "desc_1D_range_700_2500_f32_7");
        count += label(0x0ADAC0L, "desc_1D_range_1600_3200_i16_5_ADAC0");
        count += label(0x0ADAD4L, "desc_1D_range_1600_3200_i16_5_ADAD4");
        count += label(0x0ADAE8L, "desc_1D_range_1600_3200_i16_5_ADAE8");
        count += label(0x0ADB10L, "desc_1D_range_0_1500_i16_16");
        count += label(0x0ADB24L, "desc_1D_range_515_795_i16_5");
        count += label(0x0ADB38L, "desc_1D_range_400_2000_i16_9");
        count += label(0x0ADF5CL, "desc_1D_range_20_20_i16_21_ADF5C");
        count += label(0x0ADF70L, "desc_1D_range_20_20_i16_21_ADF70");
        count += label(0x0ADF84L, "desc_1D_range_20_20_i16_21_ADF84");
        count += label(0x0ADF98L, "desc_1D_range_20_20_i16_21_ADF98");
        count += label(0x0AE164L, "desc_1D_range_0_0_f32_5");
        count += label(0x0AE83CL, "desc_1D_range_146_146_u8_15");
        count += label(0x0AE850L, "desc_1D_range_0_0_f32_4_AE850");
        count += label(0x0AE868L, "desc_1D_range_0_0_f32_4_AE868");
        count += label(0x0AEC4CL, "desc_1D_range_400_1400_u8_6");
        count += label(0x0AEC74L, "desc_1D_range_200_200_u8_9");
        count += label(0x0AEE44L, "desc_1D_range_100_350_u8_10");
        count += label(0x0AEE58L, "desc_1D_range_60_0_u8_10_AEE58");
        count += label(0x0AEE6CL, "desc_1D_range_60_0_u8_10_AEE6C");
        count += label(0x0AEEE4L, "desc_1D_range_100_1000_u8_7");
        count += label(0x0AEF90L, "desc_1D_range_15_80_f32_5");
        count += label(0x0AEFA8L, "desc_1D_range_0_1400_f32_10");
        count += label(0x0AF194L, "desc_1D_range_504_760_u8_5");
        count += label(0x0AF7F4L, "desc_1D_range_0_0_u8_13_AF7F4");
        count += label(0x0AF808L, "desc_1D_range_0_0_u8_13_AF808");

        // --- 2D_AtmPressurexRPM (4 descriptors) ---
        count += label(0x0AA99CL, "desc_2D_AtmPressurexRPM_i16_6x6");
        count += label(0x0ABE7CL, "desc_2D_AtmPressurexRPM_u8_7x14_ABE7C");
        count += label(0x0ABE98L, "desc_2D_AtmPressurexRPM_u8_7x14_ABE98");
        count += label(0x0ADA24L, "desc_2D_AtmPressurexRPM_u8_6x6");

        // --- 2D_AtmPressurexrange (1 descriptors) ---
        count += label(0x0AA980L, "desc_2D_AtmPressurexrange_4000_7000_i16_6x4");

        // --- 2D_Boostxrange (2 descriptors) ---
        count += label(0x0AF058L, "desc_2D_Boostxrange_0_2000_i16_8x6_AF058");
        count += label(0x0AF074L, "desc_2D_Boostxrange_0_2000_i16_8x6_AF074");

        // --- 2D_ECTxECT (1 descriptors) ---
        count += label(0x0AE530L, "desc_2D_ECTxECT_i16_16x7");

        // --- 2D_ECTxIAT (1 descriptors) ---
        count += label(0x0AF0E4L, "desc_2D_ECTxIAT_u8_16x6");

        // --- 2D_ECTxLoad (3 descriptors) ---
        count += label(0x0AD5E8L, "desc_2D_ECTxLoad_i16_16x8");
        count += label(0x0AD604L, "desc_2D_ECTxLoad_i16_16x9");
        count += label(0x0AE46CL, "desc_2D_ECTxLoad_i16_16x6");

        // --- 2D_IATxIAT (1 descriptors) ---
        count += label(0x0AA834L, "desc_2D_IATxIAT_u8_18x17");

        // --- 2D_IATxrange (3 descriptors) ---
        count += label(0x0AD7A8L, "desc_2D_IATxrange_0_20000_i16_10x12");
        count += label(0x0AF11CL, "desc_2D_IATxrange_50_300_f32_11x8");
        count += label(0x0AF550L, "desc_2D_IATxrange_0_20000_u8_9x11");

        // --- 2D_KnockIdxxrange (2 descriptors) ---
        count += label(0x0AF020L, "desc_2D_KnockIdxxrange_0_2000_i16_8x6_AF020");
        count += label(0x0AF03CL, "desc_2D_KnockIdxxrange_0_2000_i16_8x6_AF03C");

        // --- 2D_LoadxRPM (49 descriptors) ---
        count += label(0x0AAA64L, "desc_2D_LoadxRPM_u8_16x16_AAA64");
        count += label(0x0AAA80L, "desc_2D_LoadxRPM_u8_16x16_AAA80");
        count += label(0x0AAA9CL, "desc_2D_LoadxRPM_u8_16x16_AAA9C");
        count += label(0x0AAAB8L, "desc_2D_LoadxRPM_u8_16x16_AAAB8");
        count += label(0x0ABC1CL, "desc_2D_LoadxRPM_f32_10x14");
        count += label(0x0ABDD4L, "desc_2D_LoadxRPM_u8_7x14_ABDD4");
        count += label(0x0ABDF0L, "desc_2D_LoadxRPM_u8_7x14_ABDF0");
        count += label(0x0ABE0CL, "desc_2D_LoadxRPM_u8_7x14_ABE0C");
        count += label(0x0ABE28L, "desc_2D_LoadxRPM_u8_7x14_ABE28");
        count += label(0x0ABE44L, "desc_2D_LoadxRPM_u8_7x14_ABE44");
        count += label(0x0ABE60L, "desc_2D_LoadxRPM_u8_7x14_ABE60");
        count += label(0x0AC014L, "desc_2D_LoadxRPM_f32_24x13_AC014");
        count += label(0x0AC064L, "desc_2D_LoadxRPM_f32_24x13_AC064");
        count += label(0x0AC08CL, "desc_2D_LoadxRPM_f32_18x14_AC08C");
        count += label(0x0AC0B4L, "desc_2D_LoadxRPM_f32_18x14_AC0B4");
        count += label(0x0AC0DCL, "desc_2D_LoadxRPM_f32_18x14_AC0DC");
        count += label(0x0AC104L, "desc_2D_LoadxRPM_f32_18x16");
        count += label(0x0AC12CL, "desc_2D_LoadxRPM_f32_18x14_AC12C");
        count += label(0x0AD4ECL, "desc_2D_LoadxRPM_i16_16x9_AD4EC");
        count += label(0x0AD508L, "desc_2D_LoadxRPM_i16_16x9_AD508");
        count += label(0x0AD658L, "desc_2D_LoadxRPM_wide_i16_16x10");
        count += label(0x0AD674L, "desc_2D_LoadxRPM_i16_17x18_AD674");
        count += label(0x0AD690L, "desc_2D_LoadxRPM_i16_17x18_AD690");
        count += label(0x0AD6ACL, "desc_2D_LoadxRPM_i16_15x18_AD6AC");
        count += label(0x0AD6C8L, "desc_2D_LoadxRPM_i16_17x18_AD6C8");
        count += label(0x0AD6E4L, "desc_2D_LoadxRPM_i16_17x18_AD6E4");
        count += label(0x0AD700L, "desc_2D_LoadxRPM_i16_17x18_AD700");
        count += label(0x0AD8B8L, "desc_2D_LoadxRPM_u8_11x10_AD8B8");
        count += label(0x0AD8D4L, "desc_2D_LoadxRPM_u8_11x10_AD8D4");
        count += label(0x0AD8F0L, "desc_2D_LoadxRPM_u8_13x12_AD8F0");
        count += label(0x0AD90CL, "desc_2D_LoadxRPM_u8_13x12_AD90C");
        count += label(0x0AD928L, "desc_2D_LoadxRPM_u8_11x10_AD928");
        count += label(0x0AD960L, "desc_2D_LoadxRPM_u8_12x15_AD960");
        count += label(0x0AD97CL, "desc_2D_LoadxRPM_u8_12x15_AD97C");
        count += label(0x0AD998L, "desc_2D_LoadxRPM_u8_12x13_AD998");
        count += label(0x0AD9B4L, "desc_2D_LoadxRPM_u8_12x13_AD9B4");
        count += label(0x0AD9D0L, "desc_2D_LoadxRPM_u8_12x13_AD9D0");
        count += label(0x0AE31CL, "desc_2D_LoadxRPM_i16_17x18_AE31C");
        count += label(0x0AE338L, "desc_2D_LoadxRPM_i16_17x18_AE338");
        count += label(0x0AE354L, "desc_2D_LoadxRPM_i16_17x18_AE354");
        count += label(0x0AE370L, "desc_2D_LoadxRPM_i16_17x18_AE370");
        count += label(0x0AE664L, "desc_2D_LoadxRPM_i16_15x18_AE664");
        count += label(0x0AE680L, "desc_2D_LoadxRPM_i16_17x18_AE680");
        count += label(0x0AE69CL, "desc_2D_LoadxRPM_i16_17x18_AE69C");
        count += label(0x0AF22CL, "desc_2D_LoadxRPM_u8_16x16_AF22C");
        count += label(0x0AF248L, "desc_2D_LoadxRPM_u8_16x16_AF248");
        count += label(0x0AF264L, "desc_2D_LoadxRPM_u8_16x16_AF264");
        count += label(0x0AF8D8L, "desc_2D_LoadxRPM_u8_18x16_AF8D8");
        count += label(0x0AF8F4L, "desc_2D_LoadxRPM_u8_18x16_AF8F4");

        // --- 2D_Loadxrange (3 descriptors) ---
        count += label(0x0AC1A4L, "desc_2D_Loadxrange_0_4500_f32_9x9");
        count += label(0x0AC1CCL, "desc_2D_Loadxrange_0_2000_f32_6x8");
        count += label(0x0ADA5CL, "desc_2D_Loadxrange_0_4000_f32_16x6");

        // --- 2D_PressurexIPW (2 descriptors) ---
        count += label(0x0AAD08L, "desc_2D_PressurexIPW_u8_11x6_AAD08");
        count += label(0x0AAD24L, "desc_2D_PressurexIPW_u8_11x6_AAD24");

        // --- 2D_PressurexLoad (1 descriptors) ---
        count += label(0x0AB26CL, "desc_2D_PressurexLoad_u8_7x5");

        // --- 2D_PressurexRPM (2 descriptors) ---
        count += label(0x0AA9F0L, "desc_2D_PressurexRPM_u8_11x15");
        count += label(0x0AD9ECL, "desc_2D_PressurexRPM_u8_10x7");

        // --- 2D_PressurexSmallRatio (2 descriptors) ---
        count += label(0x0AAD5CL, "desc_2D_PressurexSmallRatio_u8_5x5");
        count += label(0x0AADCCL, "desc_2D_PressurexSmallRatio_f32_4x5");

        // --- 2D_PressurexThrottle (1 descriptors) ---
        count += label(0x0AD7C4L, "desc_2D_PressurexThrottle_i16_15x16");

        // --- 2D_Pressurexrange (1 descriptors) ---
        count += label(0x0AF37CL, "desc_2D_Pressurexrange_800_2000_u8_8x4");

        // --- 2D_RPM (7 descriptors) ---
        count += label(0x0AE38CL, "desc_2D_RPM_widexLoad_i16_8x8");
        count += label(0x0AE514L, "desc_2D_RPM_midxLoad_i16_7x4");
        count += label(0x0AE5D8L, "desc_2D_RPM_midxLoad_i16_14x5_AE5D8");
        count += label(0x0AE5F4L, "desc_2D_RPM_midxLoad_i16_14x5_AE5F4");
        count += label(0x0AE610L, "desc_2D_RPM_midxLoad_i16_14x5_AE610");
        count += label(0x0AE62CL, "desc_2D_RPM_midxLoad_i16_14x6");
        count += label(0x0AF41CL, "desc_2D_RPM_widexLoad_u8_6x6");

        // --- 2D_RPMxBoost (1 descriptors) ---
        count += label(0x0AB058L, "desc_2D_RPMxBoost_u8_9x7");

        // --- 2D_RPMxIPW (2 descriptors) ---
        count += label(0x0AF29CL, "desc_2D_RPMxIPW_u8_16x6_AF29C");
        count += label(0x0AF2B8L, "desc_2D_RPMxIPW_u8_16x6_AF2B8");

        // --- 2D_RPMxLoad (1 descriptors) ---
        count += label(0x0AA86CL, "desc_2D_RPMxLoad_u8_6x6");

        // --- 2D_RPMxPressure (1 descriptors) ---
        count += label(0x0AF100L, "desc_2D_RPMxPressure_u8_16x16");

        // --- 2D_RPMxThrottle (1 descriptors) ---
        count += label(0x0AAD94L, "desc_2D_RPMxThrottle_u8_7x11");

        // --- 2D_RPMxVoltage (1 descriptors) ---
        count += label(0x0AF4B0L, "desc_2D_RPMxVoltage_f32_16x5");

        // --- 2D_RPMxrange (1 descriptors) ---
        count += label(0x0AB03CL, "desc_2D_RPMxrange_11_84_i16_15x31");

        // --- 2D_SmallRatioxrange (1 descriptors) ---
        count += label(0x0AAD78L, "desc_2D_SmallRatioxrange_5_2_u8_11x9");

        // --- 2D_ThrottlexMAF (1 descriptors) ---
        count += label(0x0AC154L, "desc_2D_ThrottlexMAF_f32_5x5");

        // --- 2D_ThrottlexRPM (5 descriptors) ---
        count += label(0x0AD620L, "desc_2D_ThrottlexRPM_i16_10x9");
        count += label(0x0AD848L, "desc_2D_ThrottlexRPM_u8_10x9");
        count += label(0x0AF2D4L, "desc_2D_ThrottlexRPM_u8_15x17_AF2D4");
        count += label(0x0AF2F0L, "desc_2D_ThrottlexRPM_u8_15x17_AF2F0");
        count += label(0x0AF30CL, "desc_2D_ThrottlexRPM_u8_15x17_AF30C");

        // --- 2D_ThrottlexThrottle (2 descriptors) ---
        count += label(0x0AF1F4L, "desc_2D_ThrottlexThrottle_i16_8x8_AF1F4");
        count += label(0x0AF210L, "desc_2D_ThrottlexThrottle_i16_8x8_AF210");

        // --- 2D_TimingAdvxRPM (1 descriptors) ---
        count += label(0x0AF398L, "desc_2D_TimingAdvxRPM_f32_16x13");

        // --- 2D_TimingAdvxrange (1 descriptors) ---
        count += label(0x0ABFD8L, "desc_2D_TimingAdvxrange_20_20_f32_8x5");

        // --- 2D_VVTErrorxRPM (4 descriptors) ---
        count += label(0x0AF830L, "desc_2D_VVTErrorxRPM_u8_9x9_AF830");
        count += label(0x0AF84CL, "desc_2D_VVTErrorxRPM_u8_9x9_AF84C");
        count += label(0x0AF868L, "desc_2D_VVTErrorxRPM_u8_9x9_AF868");
        count += label(0x0AF884L, "desc_2D_VVTErrorxRPM_u8_9x9_AF884");

        // --- 2D_VehSpdxSmallRatio (1 descriptors) ---
        count += label(0x0AAD40L, "desc_2D_VehSpdxSmallRatio_u8_5x5");

        // --- 2D_range (29 descriptors) ---
        count += label(0x0AA850L, "desc_2D_range_30_20_xrange_0_1400_u8_11x29");
        count += label(0x0AA9B8L, "desc_2D_range_120_350_xRPM_mid_u8_15x13_AA9B8");
        count += label(0x0AA9D4L, "desc_2D_range_120_350_xRPM_mid_u8_15x13_AA9D4");
        count += label(0x0AACECL, "desc_2D_range_200_800_xRPM_mid_u8_5x5");
        count += label(0x0AB004L, "desc_2D_range_210_960_xRPM_i16_11x14_AB004");
        count += label(0x0AB020L, "desc_2D_range_210_960_xRPM_i16_11x14_AB020");
        count += label(0x0AB088L, "desc_2D_range_520_760_xIAT_u8_4x5");
        count += label(0x0AB288L, "desc_2D_range_39_508_xLoad_u8_13x13");
        count += label(0x0ABED0L, "desc_2D_range_10_40_xrange_0_3001_f32_4x5");
        count += label(0x0ABF00L, "desc_2D_range_520_1120_xrange_520_1120_u8_16x16");
        count += label(0x0AC1F4L, "desc_2D_range_40_70_xrange_7_31_f32_5x10");
        count += label(0x0AC244L, "desc_2D_range_10_26_xrange_11_14_f32_5x4");
        count += label(0x0AD524L, "desc_2D_range_115_515_xrange_30_0_i16_5x7_AD524");
        count += label(0x0AD540L, "desc_2D_range_115_515_xrange_30_0_i16_5x7_AD540");
        count += label(0x0AD55CL, "desc_2D_range_115_515_xrange_30_0_i16_5x7_AD55C");
        count += label(0x0AD578L, "desc_2D_range_115_515_xTimingAdv_i16_5x7");
        count += label(0x0AD594L, "desc_2D_range_504_760_xrange_30_0_i16_5x4_AD594");
        count += label(0x0AD5B0L, "desc_2D_range_600_600_xIAT_i16_13x12");
        count += label(0x0AD5CCL, "desc_2D_range_504_760_xrange_30_0_i16_5x4_AD5CC");
        count += label(0x0AD63CL, "desc_2D_range_0_500000_xECT_i16_16x10");
        count += label(0x0AD738L, "desc_2D_range_1000_16000_xRPM_i16_17x17_AD738");
        count += label(0x0AD754L, "desc_2D_range_1000_16000_xRPM_i16_17x17_AD754");
        count += label(0x0AD770L, "desc_2D_range_1000_16000_xRPM_i16_17x17_AD770");
        count += label(0x0AD78CL, "desc_2D_range_1000_16000_xRPM_i16_17x17_AD78C");
        count += label(0x0AD864L, "desc_2D_range_4_60_xRPM_u8_8x9");
        count += label(0x0AE3E0L, "desc_2D_range_200_200_xrange_20_20_i16_9x9_AE3E0");
        count += label(0x0AE3FCL, "desc_2D_range_200_200_xrange_20_20_i16_9x9_AE3FC");
        count += label(0x0AF0ACL, "desc_2D_range_150_600_xIAT_u8_17x9_AF0AC");
        count += label(0x0AF0C8L, "desc_2D_range_150_600_xIAT_u8_17x9_AF0C8");


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
