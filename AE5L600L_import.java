// AE5L600L_import.java
// Ghidra import script for 2013 USDM Subaru WRX ECU ROM
// ROM: AE5L600L rev 20.x (tiny_wrex build)
// Architecture: SH-2 / SH-2E, big-endian, 1MB (0x100000)
//
// HOW TO USE:
//   1. In Ghidra, create a new project
//   2. Import the .bin as Raw Binary:
//        Language: SH-2 (Hitachi) -> SH2 (big-endian)
//        Base address: 0x00000000
//   3. Open the imported file in CodeBrowser
//   4. Script Manager -> Run Script -> select this file
//
//@author Dean / Claude
//@category ECU
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;

public class AE5L600L_import extends GhidraScript {

    @Override
    public void run() throws Exception {

        monitor.setMessage("AE5L600L: Applying symbols...");

        // ============================================================
        // RESET VECTORS @ 0x000000
        // ============================================================
        plate(0x000000,
            "SH-2 Reset Vector Table\n" +
            "Offset 0: Initial Stack Pointer\n" +
            "Offset 4: Reset Program Counter");
        applyDword(0x000000, "VEC_RESET_SP");
        applyDword(0x000004, "VEC_RESET_PC");
        eol(0x000000, "Initial SP = 0x00000C0C");
        eol(0x000004, "Reset PC = 0xFFFFBFA0");

        // ============================================================
        // REV LIMITER TABLE @ CC500
        // ============================================================
        plate(0x0CC500,
            "Rev Limiter On/Off Values\n" +
            "Float32 big-endian pairs: [On, Off]\n" +
            "Stock: On=6700 RPM, Off=6680 RPM\n" +
            "LC/FFS patch reads CC500 as base rev limit");
        applyFloat(0x0CC500, "RevLimit_On_Stock");
        applyFloat(0x0CC504, "RevLimit_Off_Stock");
        eol(0x0CC500, "6700.0 RPM - fuel cut ON");
        eol(0x0CC504, "6680.0 RPM - fuel cut OFF");

        // ============================================================
        // LC/FFS PATCH REGION @ F1000
        // ============================================================
        plate(0x0F1000,
            "tinywrex LC/FFS Patch - Injected Code\n" +
            "Launch Control + Flat Foot Shift patch\n" +
            "Hooked from original rev limiter at 0x3B6AE (Path A) and 0x3B6B8 (Path B)\n" +
            "Returns to 0x3B6B2\n" +
            "\n" +
            "Logic:\n" +
            "  1. Load vehicle speed from FFFF65FC\n" +
            "  2. Load speed threshold from F104C (~5 mph)\n" +
            "  3. Read clutch state from FFFF65D0 (1 = pressed)\n" +
            "  4. clutch==1, speed < threshold  -> LC mode  -> delta from F1050\n" +
            "  5. clutch==1, speed >= threshold -> FFS mode -> delta from F1054\n" +
            "  6. clutch==0                     -> normal   -> delta from F1048 (0.0)\n" +
            "  7. FR15 += delta  (adjusts effective RPM vs rev limit)\n" +
            "  8. JMP back to 0x3B6B2");

        label(0x0F1000, "Patch_LC_FFS_Entry");
        eol(0x0F1000, "R0 = ptr to FFFF65FC (vehicle speed register)");
        eol(0x0F1002, "FR9 = float(vehicle speed)");
        eol(0x0F1004, "R0 -> F104C (LC speed threshold)");
        eol(0x0F1006, "FR6 = speed threshold");
        eol(0x0F1008, "R0 = ptr to FFFF65D0 (clutch switch register)");
        eol(0x0F100A, "R0 = clutch state byte");
        eol(0x0F100C, "T = (clutch == 1)");
        eol(0x0F100E, "BF/S: if T==0 (clutch NOT pressed) -> branch to F101E");
        eol(0x0F1010, "NOP (delay slot)");
        eol(0x0F1012, "clutch pressed: FR6 = float from @R9+ (speed compare prep)");
        eol(0x0F1014, "BT/S: T==1 (still set from CMP/EQ) -> goto LC_Path F1024");
        eol(0x0F1016, "NOP (delay slot)");

        label(0x0F1018, "Patch_FFS_Path");
        eol(0x0F1018, "FFS: R0 -> F1054 (FFS RPM delta)");
        eol(0x0F101A, "BRA -> F102C (common delta load)");
        eol(0x0F101C, "NOP (delay slot)");

        label(0x0F101E, "Patch_NoClutch_Path");
        eol(0x0F101E, "no-clutch: FR9 = float from @R6+");
        eol(0x0F1020, "BT/S: T==0 here, never branches");
        eol(0x0F1022, "NOP (delay slot)");

        label(0x0F1024, "Patch_LC_Path");
        eol(0x0F1024, "LC: R0 -> F1050 (LC RPM delta)");
        eol(0x0F1026, "BRA -> F102C (common delta load)");
        eol(0x0F1028, "NOP (delay slot)");

        label(0x0F102A, "Patch_NormalDriving_Path");
        eol(0x0F102A, "normal driving: R0 -> F1048 (delta=0.0)");

        label(0x0F102C, "Patch_ApplyDelta");
        eol(0x0F102C, "FR8 = selected RPM delta");
        eol(0x0F102E, "FR15 += FR8  (adjust effective RPM vs rev limit)");
        eol(0x0F1030, "R2 = 0x000CC500 (Rev Limit On address)");
        eol(0x0F1032, "R0 = 0x0003B6B2 (return address)");
        eol(0x0F1034, "JMP @R0 -> return to caller");
        eol(0x0F1036, "delay slot: FR8 = RevLimit_On value (6700.0 RPM)");

        // Patch literal pool
        plate(0x0F1038, "Patch Literal Pool - pointers used by patch code");
        applyDword(0x0F1038, "Patch_Ptr_VehicleSpeedReg");
        eol(0x0F1038, "-> FFFF65FC (vehicle speed RAM register, float32)");
        applyDword(0x0F103C, "Patch_Ptr_ClutchReg");
        eol(0x0F103C, "-> FFFF65D0 (clutch switch RAM register, byte, 1=pressed)");
        applyDword(0x0F1040, "Patch_ReturnAddr");
        eol(0x0F1040, "-> 0x0003B6B2 (return into original rev limiter function)");
        applyDword(0x0F1044, "Patch_Ptr_RevLimitOn");
        eol(0x0F1044, "-> 0x000CC500 (Rev Limit On table address)");

        // Patch tunable parameters
        plate(0x0F1048,
            "LC/FFS Patch Tunable Parameters (float32 big-endian)\n" +
            "Edit via EcuFlash XML: AE5L600L_2013_USDM_Impreza_WRX_MT.xml\n" +
            "\n" +
            "Current values verified from ROM:\n" +
            "  F1048 = 0.0    (normal driving delta - should stay 0)\n" +
            "  F104C = 8.05   kph = ~5 mph LC speed threshold\n" +
            "  F1050 = 2700.0 RPM delta -> LC cut = 6700-2700 = 4000 RPM\n" +
            "  F1054 = 2000.0 RPM delta -> FFS cut = 6700-2000 = 4700 RPM");
        applyFloat(0x0F1048, "Param_NormalDriving_RPM_Delta");
        eol(0x0F1048, "0.0 - delta when clutch-up + high speed. Keep at 0.0.");
        applyFloat(0x0F104C, "Param_LC_SpeedThreshold_KPH");
        eol(0x0F104C, "8.05 kph (~5 mph) - speed below which LC is active");
        applyFloat(0x0F1050, "Param_LC_RPM_Delta");
        eol(0x0F1050, "2700.0 - LC rev reduction: 6700 - 2700 = 4000 RPM cut");
        applyFloat(0x0F1054, "Param_FFS_RPM_Delta");
        eol(0x0F1054, "2000.0 - FFS rev reduction: 6700 - 2000 = 4700 RPM cut");

        // ============================================================
        // HOOK SITES in original rev limiter function
        // ============================================================
        plate(0x03B6AE,
            "LC/FFS Hook Site A\n" +
            "Original instruction replaced with MOV.L+JMP to F1000\n" +
            "Path taken when R2 != 0 (gear group 1)\n" +
            "Delay slot: R2 = 0x000CC504 (Rev Limit Off addr)");
        label(0x03B6AE, "Hook_A_JMP_to_Patch");
        eol(0x03B6AE, "MOV.L -> R0 = 0x000F1000");
        eol(0x03B6B0, "JMP @R0  (-> Patch_LC_FFS_Entry)");

        plate(0x03B6B2,
            "LC/FFS Patch Return Point\n" +
            "Patch JMPs back here after adjusting FR15\n" +
            "Continues: load FR6=RevLimit_Off, hysteresis comparison");
        label(0x03B6B2, "Patch_Return_Point");

        plate(0x03B6B8,
            "LC/FFS Hook Site B\n" +
            "Original instruction replaced with MOV.L+JMP to F1000\n" +
            "Path taken when R2 == 0 (gear group 2)");
        label(0x03B6B8, "Hook_B_JMP_to_Patch");
        eol(0x03B6B8, "MOV.L -> R0 = 0x000F1000");
        eol(0x03B6BA, "JMP @R0  (-> Patch_LC_FFS_Entry)");

        // ============================================================
        // CHECKSUM TABLE @ FFB80
        // ============================================================
        plate(0x0FFB80,
            "ROM Checksum Verification Table\n" +
            "Header (8 bytes): [count(4)][start_addr(4)]\n" +
            "Entries (12 bytes each): [checksum(4)][range_lo(4)][range_hi(4)]\n" +
            "ECU verifies ROM integrity at startup\n" +
            "Entry 0 checksum (FFB88) is patched by tinywrex tooling");
        label(0x0FFB80, "Checksum_Table_Header");
        applyDword(0x0FFB80, "Checksum_Table_Count");
        applyDword(0x0FFB84, "Checksum_Table_StartAddr");

        label(0x0FFB88, "Checksum_Entry_0");
        eol(0x0FFB88,  "checksum (patched for tinywrex)");
        eol(0x0FFB8C,  "range lo: 0x000BB400");
        eol(0x0FFB90,  "range hi: 0x000BBEFF");

        label(0x0FFB94, "Checksum_Entry_1");
        eol(0x0FFB94,  "range 0x000BBF00-0x000BC9FF");
        label(0x0FFBA0, "Checksum_Entry_2");
        eol(0x0FFBA0,  "range 0x000BCA00-0x000BD4FF");
        label(0x0FFBAC, "Checksum_Entry_3");
        label(0x0FFBB8, "Checksum_Entry_4");
        label(0x0FFBC4, "Checksum_Entry_5");
        label(0x0FFBD0, "Checksum_Entry_6");
        label(0x0FFBDC, "Checksum_Entry_7");

        // ============================================================
        // TORQUE MAPS
        // ============================================================
        plate(0x0F99E0,
            "Requested Torque Map - SI-DRIVE Sport\n" +
            "3D table: Accelerator Pedal % (X) vs Engine Speed RPM (Y)\n" +
            "Source: EcuFlash XML address=f99e0");
        label(0x0F99E0, "Table_RequestedTorque_SIDrive_Sport");

        plate(0x0F9C60,
            "Requested Torque Map - SI-DRIVE Sport Sharp\n" +
            "3D table: Accelerator Pedal % (X) vs Engine Speed RPM (Y)\n" +
            "Source: EcuFlash XML address=f9c60");
        label(0x0F9C60, "Table_RequestedTorque_SIDrive_SportSharp");

        // ============================================================
        // FUEL INJECTOR TRIM TABLE
        // ============================================================
        plate(0x0CD058,
            "Fuel Injector Trim Small IFW - RPM Axis\n" +
            "8 x float32 big-endian\n" +
            "Values: ~300, 350, 400, 450, 500, 550, 600, 650 RPM");
        label(0x0CD058, "Axis_FuelInjTrimSmall_RPM");

        plate(0x0CD078,
            "Fuel Injector Trim Small IFW - Data\n" +
            "8 x uint8, scaling: value/128 = multiplier\n" +
            "Stock: ~1.266, 1.164, 1.102, 1.055, 1.023, 1.008, 1.000, 1.000\n" +
            "Clamped externally to [0.5, 1.5]\n" +
            "EcuFlash storageaddress=0xCD078");
        label(0x0CD078, "Table_FuelInjTrimSmall_IFW");

        // ============================================================
        // DISASSEMBLE PATCH CODE
        // ============================================================
        monitor.setMessage("AE5L600L: Disassembling patch code...");

        // Patch body F1000-F1037
        AddressSet patchCode = new AddressSet(addr(0x0F1000), addr(0x0F1037));
        DisassembleCommand disCmd = new DisassembleCommand(patchCode, null, true);
        disCmd.applyTo(currentProgram, monitor);

        // Hook sites
        for (long hookAddr : new long[]{ 0x03B6AE, 0x03B6B0, 0x03B6B2, 0x03B6B8, 0x03B6BA }) {
            AddressSet hookSet = new AddressSet(addr(hookAddr), addr(hookAddr + 1));
            new DisassembleCommand(hookSet, null, true).applyTo(currentProgram, monitor);
        }

        monitor.setMessage("AE5L600L: Done!");
        println("=== AE5L600L import complete ===");
        println("Symbols applied:");
        println("  Reset vectors          @ 0x000000");
        println("  Rev limiter table      @ 0x0CC500");
        println("  LC/FFS patch + params  @ 0x0F1000-0x0F1057");
        println("  Hook sites             @ 0x03B6AE, 0x03B6B8");
        println("  Return point           @ 0x03B6B2");
        println("  Checksum table         @ 0x0FFB80");
        println("  Torque maps            @ 0x0F99E0, 0x0F9C60");
        println("  Fuel inj trim table    @ 0x0CD058/0x0CD078");
        println("");
        println("NOTE: RAM registers (FFFF65xx) are outside ROM address space.");
        println("To annotate them: Memory Map -> add block at 0xFFFF0000, size 0x10000.");
        println("  FFFF65FC = RAM_VehicleSpeed  (float32)");
        println("  FFFF65D0 = RAM_ClutchSwitch  (byte, 1=pressed)");
        println("  FFFF6620 = RAM_EngineRPM     (float32, loaded into FR15 before hooks)");
    }

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    private Address addr(long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private void label(long offset, String name) throws Exception {
        currentProgram.getSymbolTable().createLabel(addr(offset), name, SourceType.USER_DEFINED);
    }

    private void eol(long offset, String text) {
        setEOLComment(addr(offset), text);
    }

    private void plate(long offset, String text) {
        setPlateComment(addr(offset), text);
    }

    private void applyFloat(long offset, String name) throws Exception {
        Address a = addr(offset);
        clearListing(a, a.add(3));
        createData(a, FloatDataType.dataType);
        label(offset, name);
    }

    private void applyDword(long offset, String name) throws Exception {
        Address a = addr(offset);
        clearListing(a, a.add(3));
        createData(a, DWordDataType.dataType);
        label(offset, name);
    }
}
