// AE5L600L_AVCS_Labels.java
// Ghidra script - labels, data types, and comments for AVCS Duty Correction tables
//
// ROM: 2013 USDM Subaru Impreza WRX MT  |  Part: AE5L600L
// MCU: Renesas SH7058 (SH-2A with FPU, big-endian)
//
// HOW TO IMPORT THE ROM IN GHIDRA:
//   File > Import File > "AE5L600L 20g rev 20 tiny wrex.bin"
//   Format:  Raw Binary
//   Language: SuperH:BE:32:SH-2A  (or SuperH4:BE:32:default if SH-2A unavailable)
//   Base Address: 0x00000000
//
// HOW TO RUN:
//   Script Manager > [+] Add script directory containing this file
//   Double-click "AE5L600L_AVCS_Labels.java"
//
// Tables defined:
//   Intake Duty Correction A  - 10x9 uint8,  scale=0.2, at 0xCFA38
//   Exhaust Duty Correction A - 10x9 uint16, scale=0.000061, at 0xD121C
//
// @author  AE5L600L analysis
// @category AE5L600L
// @menupath Analysis.AE5L600L.Apply AVCS Labels

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class AE5L600L_AVCS_Labels extends GhidraScript {

    private Listing listing;
    private SymbolTable symbolTable;

    @Override
    protected void run() throws Exception {
        listing = currentProgram.getListing();
        symbolTable = currentProgram.getSymbolTable();

        println("=== AE5L600L AVCS Duty Correction Labels ===");

        // ─────────────────────────────────────────────────────────
        // Intake Duty Correction A
        // ─────────────────────────────────────────────────────────
        // Descriptor @ 0xAD620 (28 bytes):
        //   00000000 000A0009 000CF9EC 000CFA14 000CFA38 04000000 3E4CCCCC
        //   [bias=0] [10x9]   [Y_axis] [X_axis] [data]   [storage] [scale=0.2]

        defineDescriptor(0xAD620, "AVCS_Intake_DutyCorr_A_Descriptor",
            "ECU descriptor for Intake Duty Correction A table.\n" +
            "  bias    = 0x00000000 (no offset)\n" +
            "  dims    = 10 rows x 9 cols (VVT Error x RPM)\n" +
            "  Y_axis  = 0x000CF9EC (VVT Error, 10 floats)\n" +
            "  X_axis  = 0x000CFA14 (RPM, 9 floats)\n" +
            "  data    = 0x000CFA38 (90 uint8 values)\n" +
            "  storage = 0x04000000 (uint8)\n" +
            "  scale   = 0.2 (float 3E4CCCCC)");

        defineFloats(0xCF9EC, 10, "AVCS_Intake_DutyCorr_A_VVTError_Axis",
            "Intake Duty Correction A - VVT Error axis (Y, rows).\n" +
            "10 float32 values: [4, 6, 10, 15, 20, 25, 30, 40, 60, 80] degrees");

        defineFloats(0xCFA14, 9, "AVCS_Intake_DutyCorr_A_RPM_Axis",
            "Intake Duty Correction A - Engine Speed axis (X, columns).\n" +
            "9 float32 values: [650, 800, 1000, 1200, 1600, 2000, 2400, 3000, 3600] RPM");

        defineBytes(0xCFA38, 90, "AVCS_Intake_DutyCorr_A_Data",
            "Intake Duty Correction A - table data.\n" +
            "90 uint8 values (10 rows x 9 cols), scale = 0.2.\n" +
            "Physical value = raw_byte * 0.2 (correction in degrees).\n" +
            "Row order: VVT Error [4..80], Column order: RPM [650..3600]");

        // ─────────────────────────────────────────────────────────
        // Exhaust Duty Correction A
        // ─────────────────────────────────────────────────────────
        // Descriptor @ 0xAD848 (28 bytes):
        //   00000000 000A0009 000D11D0 000D11F8 000D121C 08000000 38800000
        //   [bias=0] [10x9]   [Y_axis] [X_axis] [data]   [storage] [scale=0.000061]

        defineDescriptor(0xAD848, "AVCS_Exhaust_DutyCorr_A_Descriptor",
            "ECU descriptor for Exhaust Duty Correction A table.\n" +
            "  bias    = 0x00000000 (no offset)\n" +
            "  dims    = 10 rows x 9 cols (VVT Error x RPM)\n" +
            "  Y_axis  = 0x000D11D0 (VVT Error, 10 floats)\n" +
            "  X_axis  = 0x000D11F8 (RPM, 9 floats)\n" +
            "  data    = 0x000D121C (90 uint16 values, 180 bytes)\n" +
            "  storage = 0x08000000 (uint16)\n" +
            "  scale   = 0.000061 (float 38800000)");

        defineFloats(0xD11D0, 10, "AVCS_Exhaust_DutyCorr_A_VVTError_Axis",
            "Exhaust Duty Correction A - VVT Error axis (Y, rows).\n" +
            "10 float32 values: [4, 6, 10, 15, 20, 25, 30, 40, 60, 80] degrees");

        defineFloats(0xD11F8, 9, "AVCS_Exhaust_DutyCorr_A_RPM_Axis",
            "Exhaust Duty Correction A - Engine Speed axis (X, columns).\n" +
            "9 float32 values: [650, 800, 1000, 1200, 1600, 2000, 2400, 3000, 3600] RPM");

        defineShorts(0xD121C, 90, "AVCS_Exhaust_DutyCorr_A_Data",
            "Exhaust Duty Correction A - table data.\n" +
            "90 uint16 values (10 rows x 9 cols, 180 bytes).\n" +
            "Physical value = raw_uint16 * 0.003051758 - 100 (correction in degrees).\n" +
            "Row order: VVT Error [4..80], Column order: RPM [650..3600]");

        println("=== Done: all AVCS labels applied ===");
    }

    /**
     * Create a label at the given offset, replacing any existing user-defined label.
     */
    private void setLabel(long offset, String name, String comment) throws Exception {
        Address a = toAddr(offset);

        // Remove existing user-defined labels at this address
        for (Symbol sym : symbolTable.getSymbols(a)) {
            if (sym.getSource() == SourceType.USER_DEFINED) {
                sym.delete();
            }
        }

        symbolTable.createLabel(a, name, SourceType.USER_DEFINED);

        if (comment != null) {
            CodeUnit cu = listing.getCodeUnitAt(a);
            if (cu == null) {
                cu = listing.getCodeUnitContaining(a);
            }
            if (cu != null) {
                cu.setComment(CodeUnit.PLATE_COMMENT, comment);
            }
        }

        println("  Label: " + name + " @ 0x" + String.format("%08X", offset));
    }

    /**
     * Clear any existing data/code units in the given address range.
     */
    private void clearRange(long offset, int byteLength) throws Exception {
        Address start = toAddr(offset);
        Address end = toAddr(offset + byteLength - 1);
        listing.clearCodeUnits(start, end, false);
    }

    /**
     * Define an array of float32 values and apply a label.
     */
    private void defineFloats(long offset, int count, String name, String comment)
            throws Exception {
        int byteLen = count * 4;
        clearRange(offset, byteLen);

        ArrayDataType arrayType = new ArrayDataType(FloatDataType.dataType, count, 4);
        listing.createData(toAddr(offset), arrayType);
        setLabel(offset, name, comment);
    }

    /**
     * Define an array of uint8 values and apply a label.
     */
    private void defineBytes(long offset, int count, String name, String comment)
            throws Exception {
        clearRange(offset, count);

        ArrayDataType arrayType = new ArrayDataType(ByteDataType.dataType, count, 1);
        listing.createData(toAddr(offset), arrayType);
        setLabel(offset, name, comment);
    }

    /**
     * Define an array of uint16 values and apply a label.
     */
    private void defineShorts(long offset, int count, String name, String comment)
            throws Exception {
        int byteLen = count * 2;
        clearRange(offset, byteLen);

        ArrayDataType arrayType = new ArrayDataType(UnsignedShortDataType.dataType, count, 2);
        listing.createData(toAddr(offset), arrayType);
        setLabel(offset, name, comment);
    }

    /**
     * Define the 28-byte ECU descriptor structure as 7 consecutive DWORDs.
     */
    private void defineDescriptor(long offset, String name, String comment)
            throws Exception {
        clearRange(offset, 28);

        ArrayDataType arrayType = new ArrayDataType(DWordDataType.dataType, 7, 4);
        listing.createData(toAddr(offset), arrayType);
        setLabel(offset, name, comment);
    }
}
