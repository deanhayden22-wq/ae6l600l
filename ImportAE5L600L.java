// Ghidra script to import labels, comments, and memory map for AE5L600L ROM
// Usage:
//   1. Create new Ghidra project
//   2. Import the raw ROM binary:
//        File > Import File > select AE5L600L.bin
//        Language: SuperH:BE:32:SH-2  (or SH-2A if available)
//        Address: 0x00000000
//   3. Run this script: Script Manager > Run (or press the green play button)
//
// This script applies all labels and comments from disassembly.txt analysis.
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
        count += labelComment(0x0004438C, "fn_04438C",
            "Task [11] - reads knock flag");
        count += labelComment(0x00043D68, "fn_043D68",
            "Task [12] - writes 0xFFFF81D9, NOT the knock flag");
        count += labelComment(0x00045BFE, "flkc_path_J",
            "Task [18] FLKC fast-response. If KNOCK_FLAG!=0: FR13 -= base_step*0.5. ROM[0x045DD8]=0.5 multiplier.");
        count += labelComment(0x000463BA, "flkc_paths_FG",
            "Task [25] FLKC sustained-knock. GBR=0xFFFF8290. Requires 7 conditions. bank!=1->retard 1.01, bank==1->retard 2.80");

        // Undocumented pointer table
        count += labelComment(0x0008D838, "ptr_table_8D838",
            "Pointer table - purpose TBD (found in Ghidra analysis)");

        // Low PW helper functions
        count += labelComment(0x000BE874, "LowPW_TableProcessor",
            "Table lookup engine called by LowPW_GateFunction");
        count += labelComment(0x000BECA8, "LowPW_AxisLookup",
            "Axis lookup / interpolation helper for Low PW table processing");

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

        // Tip-in enrichment
        count += label(0x000CED50, "TipInEnrichA");
        count += label(0x000CEDBC, "TipInEnrichB");

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
