// AE5L600L_PostStartEnrich_Labels.java
// Ghidra script - labels and comments for AE5L600L Post Start Enrichment tables
//
// ROM: 2013 USDM Subaru Impreza WRX MT  |  Part: AE5L600L
// MCU: Renesas SH7058 (SH-2A with FPU, big-endian)
//
// HOW TO RUN:
//   Script Manager > [+] Add script directory containing this file
//   Double-click "AE5L600L_PostStartEnrich_Labels.java"
//
// WHAT THIS SCRIPT DOES:
//   - Labels 13 Post Start Enrichment calibration tables and their CT axes
//   - Defines the 20-byte descriptor structures at 0xAC948-0xACB3F
//   - Labels code literal pools referencing descriptor pointers
//   - Adds comments explaining descriptor format, scale factors, and data layout
//
// @author  AE5L600L analysis
// @category AE5L600L

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.DWordDataType;

public class AE5L600L_PostStartEnrich_Labels extends GhidraScript {

    private Listing listing;

    private Address addr(long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private void setLabel(long offset, String name, String comment) throws Exception {
        Address a = addr(offset);
        // Remove existing user labels
        var symbols = currentProgram.getSymbolTable().getSymbols(a);
        while (symbols.hasNext()) {
            var sym = symbols.next();
            if (sym.getSource() == SourceType.USER_DEFINED) {
                sym.delete();
            }
        }
        currentProgram.getSymbolTable().createLabel(a, name, SourceType.USER_DEFINED);
        if (comment != null) {
            setPlateComment(a, comment);
        }
    }

    private void setLabel(long offset, String name) throws Exception {
        setLabel(offset, name, null);
    }

    private void eolComment(long offset, String text) {
        Address a = addr(offset);
        CodeUnit cu = listing.getCodeUnitAt(a);
        if (cu == null) cu = listing.getCodeUnitContaining(a);
        if (cu != null) cu.setComment(CodeUnit.EOL_COMMENT, text);
    }

    private void preComment(long offset, String text) {
        Address a = addr(offset);
        CodeUnit cu = listing.getCodeUnitAt(a);
        if (cu == null) cu = listing.getCodeUnitContaining(a);
        if (cu != null) cu.setComment(CodeUnit.PRE_COMMENT, text);
    }

    private void defineFloats(long offset, int count, String name, String comment) throws Exception {
        FloatDataType dt = FloatDataType.dataType;
        for (int i = 0; i < count; i++) {
            Address a = addr(offset + i * 4);
            try {
                listing.clearCodeUnits(a, a.add(3), false);
                listing.createData(a, dt);
            } catch (Exception e) { /* ignore */ }
        }
        if (name != null) setLabel(offset, name, comment);
    }

    private void defineWords(long offset, int count, String name, String comment) throws Exception {
        UnsignedShortDataType dt = UnsignedShortDataType.dataType;
        for (int i = 0; i < count; i++) {
            Address a = addr(offset + i * 2);
            try {
                listing.clearCodeUnits(a, a.add(1), false);
                listing.createData(a, dt);
            } catch (Exception e) { /* ignore */ }
        }
        if (name != null) setLabel(offset, name, comment);
    }

    private void defineDwords(long offset, int count, String name, String comment) throws Exception {
        DWordDataType dt = DWordDataType.dataType;
        for (int i = 0; i < count; i++) {
            Address a = addr(offset + i * 4);
            try {
                listing.clearCodeUnits(a, a.add(3), false);
                listing.createData(a, dt);
            } catch (Exception e) { /* ignore */ }
        }
        if (name != null) setLabel(offset, name, comment);
    }

    private void defineDescriptor20(long offset, String name, long dataAddr,
                                     String scaleName, String scaleVal, long axisAddr) throws Exception {
        defineDwords(offset, 5, null, null);
        setLabel(offset, "PSE_Desc_" + name,
            "Post Start Enrichment descriptor for " + name + "\n" +
            "Format: [meta(4)][axis_ptr(4)][data_ptr(4)][scale_float(4)][pad(4)]\n" +
            "  meta:      0x00100800 (16 elements, uint16)\n" +
            "  axis_ptr:  0x" + String.format("%06X", axisAddr) + " (Coolant Temperature)\n" +
            "  data_ptr:  0x" + String.format("%06X", dataAddr) + " (" + name + ")\n" +
            "  scale:     " + scaleVal + " (" + scaleName + ")");
        eolComment(offset, "meta=0x00100800 (16 elem, uint16)");
        eolComment(offset + 4, "-> CT axis 0x" + String.format("%05X", axisAddr));
        eolComment(offset + 8, "-> data 0x" + String.format("%05X", dataAddr) + " (" + name + ")");
        eolComment(offset + 12, "scale = " + scaleVal + " (" + scaleName + ")");
    }

    private void defineDescriptor12(long offset, String name, long dataAddr, long axisAddr) throws Exception {
        defineDwords(offset, 3, null, null);
        setLabel(offset, "PSE_Desc_" + name,
            "Post Start Enrichment descriptor for " + name + " (12-byte, no scale)\n" +
            "Format: [meta(4)][axis_ptr(4)][data_ptr(4)]\n" +
            "  meta:      0x00100800 (16 elements, uint16)\n" +
            "  axis_ptr:  0x" + String.format("%06X", axisAddr) + " (Coolant Temperature)\n" +
            "  data_ptr:  0x" + String.format("%06X", dataAddr) + " (" + name + ")\n" +
            "  No scale field -> direct value (Decay3 scaling)");
        eolComment(offset, "meta=0x00100800 (16 elem, uint16)");
        eolComment(offset + 4, "-> CT axis 0x" + String.format("%05X", axisAddr));
        eolComment(offset + 8, "-> data 0x" + String.format("%05X", dataAddr) + " (" + name + ")");
    }

    @Override
    protected void run() throws Exception {
        listing = currentProgram.getListing();

        println("============================================================");
        println("AE5L600L Post Start Enrichment Labels");
        println("============================================================");

        // ─────────────────────────────────────────────────────────────
        // COOLANT TEMPERATURE AXES (16 float32 values each)
        // ─────────────────────────────────────────────────────────────

        println("Defining CT axes...");

        defineFloats(0xCC624, 16, "PSE_CT_Axis_1",
            "Post Start Enrichment - Coolant Temperature Axis #1\n" +
            "16 float32 values: -40 to 110 deg F in 10-degree steps.\n" +
            "Used by 12 of 13 post start enrichment tables.\n" +
            "RomRaider axis: 'Coolant Temperature', scaling=CoolantTemp(DegreesF)");

        defineFloats(0xCC664, 16, "PSE_CT_Axis_2",
            "Post Start Enrichment - Coolant Temperature Axis #2\n" +
            "16 float32 values: -40 to 110 deg F in 10-degree steps.\n" +
            "Used by LSD Delay 2 table only.");

        // ─────────────────────────────────────────────────────────────
        // LOW SPEED DECAY INITIAL (4 tables, Decay1 = x*0.00390625)
        // ─────────────────────────────────────────────────────────────

        println("Defining LSD Initial tables...");

        defineWords(0xCD3A6, 16, "PSE_LSD_Initial_1A",
            "Table_Post_Start_Enrich_Low_Speed_Decay_Initial_1A\n" +
            "16 x uint16, scaling = Post_Start_Enrich_Decay1 (x*0.00390625)\n" +
            "CT axis at 0xCC624 | Descriptor at 0xAC948\n" +
            "Scaled values: 2.50, 2.50, 1.75, 0.80, 0.73, 0.66, 0.48, 0.37,\n" +
            "               0.25, 0.25, 0.25, 0.15, 0.50, 0.50, 0.50, 0.50");

        defineWords(0xCD3C6, 16, "PSE_LSD_Initial_1B",
            "Table_Post_Start_Enrich_Low_Speed_Decay_Initial_1B\n" +
            "16 x uint16, scaling = Post_Start_Enrich_Decay1 (x*0.00390625)\n" +
            "CT axis at 0xCC624 | Descriptor at 0xAC95C\n" +
            "Scaled values: 1.00, 0.90, 0.40, 0.35, 0.15, 0.10, 0.10, 0.10,\n" +
            "               0.10, 0.10, 0.18, 0.25, 0.30, 0.30, 0.30, 0.30");

        defineWords(0xCD3E6, 16, "PSE_LSD_Initial_2A",
            "Table_Post_Start_Enrich_Low_Speed_Decay_Initial_2A\n" +
            "16 x uint16, scaling = Post_Start_Enrich_Decay1 (x*0.00390625)\n" +
            "CT axis at 0xCC624 | Descriptor at 0xAC970\n" +
            "Scaled values: 2.20, 1.50, 1.00, 0.80, 0.67, 0.60, 0.55, 0.37,\n" +
            "               0.17, 0.15, 0.15, 0.15, 0.50, 0.50, 0.50, 0.50");

        defineWords(0xCD406, 16, "PSE_LSD_Initial_2B",
            "Table_Post_Start_Enrich_Low_Speed_Decay_Initial_2B\n" +
            "16 x uint16, scaling = Post_Start_Enrich_Decay1 (x*0.00390625)\n" +
            "CT axis at 0xCC624 | Descriptor at 0xAC984\n" +
            "Scaled values: 1.00, 0.90, 0.40, 0.35, 0.13, 0.10, 0.10, 0.10,\n" +
            "               0.10, 0.10, 0.10, 0.25, 0.30, 0.30, 0.30, 0.30");

        // ─────────────────────────────────────────────────────────────
        // LOW SPEED DECAY DELAY (2 tables, Decay3 = direct, uint16)
        // ─────────────────────────────────────────────────────────────

        println("Defining LSD Delay tables...");

        defineWords(0xCD426, 16, "PSE_LSD_Delay_1",
            "Table_Post_Start_Enrich_Low_Speed_Decay_Delay_1\n" +
            "16 x uint16, scaling = Post_Start_Enrich_Decay3 (direct value)\n" +
            "CT axis at 0xCC624 | Descriptor at 0xAC998 (12-byte, no scale)\n" +
            "NOTE: 32BITBASE.xml defines Decay3 as uint8, but this ROM stores uint16.\n" +
            "All values = 38 (flat constant across all temperatures)");

        defineWords(0xCD586, 16, "PSE_LSD_Delay_2",
            "Table_Post_Start_Enrich_Low_Speed_Decay_Delay_2\n" +
            "16 x uint16, scaling = Post_Start_Enrich_Decay3 (direct value)\n" +
            "CT axis at 0xCC664 | Descriptor at 0xACA6C (12-byte, no scale)\n" +
            "NOTE: Uses CT axis #2. All values = 0 (disabled).");

        // ─────────────────────────────────────────────────────────────
        // HIGH SPEED DECAY INITIAL START (4 active + 6 zero-filled)
        // Decay = x*0.00024414062, uint16
        // ─────────────────────────────────────────────────────────────

        println("Defining HSD Initial Start tables...");

        defineWords(0xCD446, 16, "PSE_HSD_InitialStart_1A",
            "Table_Post_Start_Enrich_High_Speed_Decay_Initial_Start_1A\n" +
            "16 x uint16, scaling = Post_Start_Enrich_Decay (x*0.00024414062)\n" +
            "CT axis at 0xCC624 | Descriptor at 0xAC9A4\n" +
            "Scaled values: 0.850, 0.850, 0.750, 0.500, 0.420, 0.350, 0.300, 0.250,\n" +
            "               0.210, 0.170, 0.130, 0.125, 0.100, 0.100, 0.100, 0.100");

        defineWords(0xCD466, 16, "PSE_HSD_InitialStart_Zero_1",
            "HSD Initial Start - unused slot (all zeros). Descriptor at 0xAC9B8.");
        defineWords(0xCD486, 16, "PSE_HSD_InitialStart_Zero_2",
            "HSD Initial Start - unused slot (all zeros). Descriptor at 0xAC9CC.");

        defineWords(0xCD4A6, 16, "PSE_HSD_InitialStart_1B",
            "Table_Post_Start_Enrich_High_Speed_Decay_Initial_Start_1B\n" +
            "16 x uint16, scaling = Post_Start_Enrich_Decay (x*0.00024414062)\n" +
            "CT axis at 0xCC624 | Descriptor at 0xAC9E0\n" +
            "Scaled values: 0.600, 0.600, 0.550, 0.300, 0.100, 0.100, 0.100, 0.085,\n" +
            "               0.080, 0.095, 0.110, 0.080, 0.050, 0.050, 0.050, 0.050");

        defineWords(0xCD4C6, 16, "PSE_HSD_InitialStart_Zero_3",
            "HSD Initial Start - unused slot (all zeros). Descriptor at 0xAC9F4.");

        defineWords(0xCD4E6, 16, "PSE_HSD_InitialStart_2A",
            "Table_Post_Start_Enrich_High_Speed_Decay_Initial_Start_2A\n" +
            "16 x uint16, scaling = Post_Start_Enrich_Decay (x*0.00024414062)\n" +
            "CT axis at 0xCC624 | Descriptor at 0xACA08\n" +
            "Scaled values: 0.850, 0.850, 0.750, 0.500, 0.420, 0.350, 0.300, 0.250,\n" +
            "               0.210, 0.160, 0.150, 0.125, 0.100, 0.100, 0.100, 0.100");

        defineWords(0xCD506, 16, "PSE_HSD_InitialStart_Zero_4",
            "HSD Initial Start - unused slot (all zeros). Descriptor at 0xACA1C.");
        defineWords(0xCD526, 16, "PSE_HSD_InitialStart_Zero_5",
            "HSD Initial Start - unused slot (all zeros). Descriptor at 0xACA30.");

        defineWords(0xCD546, 16, "PSE_HSD_InitialStart_2B",
            "Table_Post_Start_Enrich_High_Speed_Decay_Initial_Start_2B\n" +
            "16 x uint16, scaling = Post_Start_Enrich_Decay (x*0.00024414062)\n" +
            "CT axis at 0xCC624 | Descriptor at 0xACA44\n" +
            "Scaled values: 0.310, 0.310, 0.250, 0.195, 0.120, 0.100, 0.100, 0.085,\n" +
            "               0.080, 0.095, 0.120, 0.080, 0.050, 0.050, 0.050, 0.050");

        defineWords(0xCD566, 16, "PSE_HSD_InitialStart_Zero_6",
            "HSD Initial Start - unused slot (all zeros). Descriptor at 0xACA58.");

        // ─────────────────────────────────────────────────────────────
        // HIGH SPEED DECAY STEP VALUE (2 active + 4 zero-filled)
        // Decay2 = x*0.00000095367432, uint16
        // ─────────────────────────────────────────────────────────────

        println("Defining HSD Step Value tables...");

        defineWords(0xCD5A6, 16, "PSE_HSD_StepValue_1",
            "Table_Post_Start_Enrich_High_Speed_Decay_Step_Value_1\n" +
            "16 x uint16, scaling = Post_Start_Enrich_Decay2 (x*0.00000095367432)\n" +
            "CT axis at 0xCC624 | Descriptor at 0xACA78\n" +
            "Raw values: 1049, 1049, 839, 629, 629, 629, 629, 839,\n" +
            "            839, 524, 524, 367, 367, 367, 367, 367");

        defineWords(0xCD5C6, 16, "PSE_HSD_StepValue_Zero_1",
            "HSD Step Value - unused slot (all zeros). Descriptor at 0xACA8C.");

        defineWords(0xCD5E6, 16, "PSE_HSD_StepValue_2",
            "Table_Post_Start_Enrich_High_Speed_Decay_Step_Value_2\n" +
            "16 x uint16, scaling = Post_Start_Enrich_Decay2 (x*0.00000095367432)\n" +
            "CT axis at 0xCC624 | Descriptor at 0xACAA0\n" +
            "Raw values: 1049, 1049, 839, 839, 839, 524, 524, 524,\n" +
            "            524, 524, 524, 367, 367, 367, 367, 367");

        defineWords(0xCD606, 16, "PSE_HSD_StepValue_Zero_2",
            "HSD Step Value - unused slot (all zeros). Descriptor at 0xACAB4.");
        defineWords(0xCD626, 16, "PSE_HSD_StepValue_Zero_3",
            "HSD Step Value - unused slot (all zeros). Descriptor at 0xACAC8.");
        defineWords(0xCD646, 16, "PSE_HSD_StepValue_Zero_4",
            "HSD Step Value - unused slot (all zeros). Descriptor at 0xACADC.");

        // ─────────────────────────────────────────────────────────────
        // LOW SPEED DECAY DELAY MULTIPLIER (1 active + 1 zero-filled)
        // Decay4 = x*0.0078125, uint16 in this ROM
        // ─────────────────────────────────────────────────────────────

        println("Defining LSD Delay Multiplier table...");

        defineWords(0xCD666, 16, "PSE_LSD_DelayMultiplier",
            "Table_Post_Start_Enrich_Low_Speed_Decay_Delay_Multiplier\n" +
            "16 x uint16, scaling = Post_Start_Enrich_Decay4 (x*0.0078125)\n" +
            "CT axis at 0xCC624 | Descriptor at 0xACAF0\n" +
            "NOTE: 32BITBASE.xml defines Decay4 as uint8, but this ROM stores uint16.\n" +
            "Scaled values: 1.0, 1.0, 1.0, 1.0, 2.0, 2.0, 1.80, 1.60,\n" +
            "               1.40, 1.20, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0\n" +
            "Higher multiplier at cold temps -> longer delay between decay steps.");

        defineWords(0xCD686, 16, "PSE_LSD_DelayMultiplier_Zero",
            "LSD Delay Multiplier - unused slot (all zeros). Descriptor at 0xACB04.");

        // ─────────────────────────────────────────────────────────────
        // DESCRIPTOR STRUCTURES at 0xAC948 - 0xACB3F
        // ─────────────────────────────────────────────────────────────

        println("Defining descriptor structures...");

        preComment(0xAC948,
            "Post Start Enrichment descriptor table\n" +
            "26 entries for the PSE function (code at 0x30674-0x30A78).\n" +
            "20-byte format: [meta(4)][axis_ptr(4)][data_ptr(4)][scale_float(4)][pad(4)]\n" +
            "12-byte format: [meta(4)][axis_ptr(4)][data_ptr(4)] (no scale = direct value)\n" +
            "Meta 0x00100800 = 16 elements, uint16 storage.\n" +
            "\n" +
            "Scale factor identification:\n" +
            "  0x3B800000 = 0.00390625     -> Post_Start_Enrich_Decay1 (LSD Initial)\n" +
            "  0x39800000 = 0.000244140625 -> Post_Start_Enrich_Decay  (HSD Initial Start)\n" +
            "  0x35800000 = 9.5367e-7      -> Post_Start_Enrich_Decay2 (HSD Step Value)\n" +
            "  0x3C000000 = 0.0078125      -> Post_Start_Enrich_Decay4 (LSD Delay Multiplier)\n" +
            "  (no scale)                  -> Post_Start_Enrich_Decay3 (LSD Delay, direct)");

        // LSD Initial descriptors (4x 20-byte)
        defineDescriptor20(0xAC948, "LSD_Initial_1A", 0xCD3A6, "Decay1", "0.00390625", 0xCC624);
        defineDescriptor20(0xAC95C, "LSD_Initial_1B", 0xCD3C6, "Decay1", "0.00390625", 0xCC624);
        defineDescriptor20(0xAC970, "LSD_Initial_2A", 0xCD3E6, "Decay1", "0.00390625", 0xCC624);
        defineDescriptor20(0xAC984, "LSD_Initial_2B", 0xCD406, "Decay1", "0.00390625", 0xCC624);

        // LSD Delay descriptors (2x 12-byte)
        defineDescriptor12(0xAC998, "LSD_Delay_1", 0xCD426, 0xCC624);
        defineDescriptor12(0xACA6C, "LSD_Delay_2", 0xCD586, 0xCC664);

        // HSD Initial Start descriptors (10x 20-byte)
        defineDescriptor20(0xAC9A4, "HSD_InitStart_1A",    0xCD446, "Decay", "0.000244140625", 0xCC624);
        defineDescriptor20(0xAC9B8, "HSD_InitStart_Zero1", 0xCD466, "Decay", "0.000244140625", 0xCC624);
        defineDescriptor20(0xAC9CC, "HSD_InitStart_Zero2", 0xCD486, "Decay", "0.000244140625", 0xCC624);
        defineDescriptor20(0xAC9E0, "HSD_InitStart_1B",    0xCD4A6, "Decay", "0.000244140625", 0xCC624);
        defineDescriptor20(0xAC9F4, "HSD_InitStart_Zero3", 0xCD4C6, "Decay", "0.000244140625", 0xCC624);
        defineDescriptor20(0xACA08, "HSD_InitStart_2A",    0xCD4E6, "Decay", "0.000244140625", 0xCC624);
        defineDescriptor20(0xACA1C, "HSD_InitStart_Zero4", 0xCD506, "Decay", "0.000244140625", 0xCC624);
        defineDescriptor20(0xACA30, "HSD_InitStart_Zero5", 0xCD526, "Decay", "0.000244140625", 0xCC624);
        defineDescriptor20(0xACA44, "HSD_InitStart_2B",    0xCD546, "Decay", "0.000244140625", 0xCC624);
        defineDescriptor20(0xACA58, "HSD_InitStart_Zero6", 0xCD566, "Decay", "0.000244140625", 0xCC624);

        // HSD Step Value descriptors (6x 20-byte)
        defineDescriptor20(0xACA78, "HSD_StepValue_1",     0xCD5A6, "Decay2", "9.5367e-7", 0xCC624);
        defineDescriptor20(0xACA8C, "HSD_StepValue_Zero1", 0xCD5C6, "Decay2", "9.5367e-7", 0xCC624);
        defineDescriptor20(0xACAA0, "HSD_StepValue_2",     0xCD5E6, "Decay2", "9.5367e-7", 0xCC624);
        defineDescriptor20(0xACAB4, "HSD_StepValue_Zero2", 0xCD606, "Decay2", "9.5367e-7", 0xCC624);
        defineDescriptor20(0xACAC8, "HSD_StepValue_Zero3", 0xCD626, "Decay2", "9.5367e-7", 0xCC624);
        defineDescriptor20(0xACADC, "HSD_StepValue_Zero4", 0xCD646, "Decay2", "9.5367e-7", 0xCC624);

        // LSD Delay Multiplier descriptors (2x 20-byte)
        defineDescriptor20(0xACAF0, "LSD_DelayMult",      0xCD666, "Decay4", "0.0078125", 0xCC624);
        defineDescriptor20(0xACB04, "LSD_DelayMult_Zero",  0xCD686, "Decay4", "0.0078125", 0xCC624);

        // Extra HSD Init descriptors (both zero-filled)
        defineDescriptor20(0xACB18, "HSD_InitStart_Extra1", 0xCD6A6, "Decay", "0.000244140625", 0xCC624);
        defineDescriptor20(0xACB2C, "HSD_InitStart_Extra2", 0xCD6C6, "Decay", "0.000244140625", 0xCC624);

        // ─────────────────────────────────────────────────────────────
        // CODE LITERAL POOLS
        // ─────────────────────────────────────────────────────────────

        println("Labeling code literal pools...");

        preComment(0x30674,
            "PSE literal pool: descriptor pointers for LSD Initial group.\n" +
            "0x30674 -> 0xAC970 (LSD Init 2A)\n" +
            "0x30684 -> 0xAC984 (LSD Init 2B)\n" +
            "0x30688 -> 0xAC948 (LSD Init 1A)\n" +
            "0x3068C -> 0xAC95C (LSD Init 1B)");

        preComment(0x306CC,
            "PSE literal pool: LSD Delay 1 descriptor pointer.\n" +
            "0x306CC -> 0xAC998 (LSD Delay 1, 12-byte descriptor)");

        preComment(0x309EC,
            "PSE literal pool: descriptor pointers for HSD Initial Start group.\n" +
            "10 descriptor pointers for HSD Init (4 active + 6 zero-filled).\n" +
            "Active entries:\n" +
            "  0x30A04 -> 0xAC9A4 (HSD Init 1A, data=0xCD446)\n" +
            "  0x30A10 -> 0xAC9E0 (HSD Init 1B, data=0xCD4A6)\n" +
            "  0x30A0C -> 0xACA08 (HSD Init 2A, data=0xCD4E6)\n" +
            "  0x30A18 -> 0xACA44 (HSD Init 2B, data=0xCD546)");

        preComment(0x30A3C,
            "PSE literal pool: LSD Delay 2 descriptor pointer.\n" +
            "0x30A3C -> 0xACA6C (LSD Delay 2, 12-byte, axis=0xCC664)");

        preComment(0x30A4C,
            "PSE literal pool: LSD Delay Multiplier + extra HSD Init descriptors.\n" +
            "0x30A4C -> 0xACAF0 (LSD Delay Mult, data=0xCD666)\n" +
            "0x30A50 -> 0xACB04 (LSD Delay Mult zero slot)\n" +
            "0x30A54 -> 0xACB18 (HSD Init extra, zero)\n" +
            "0x30A58 -> 0xACB2C (HSD Init extra, zero)");

        preComment(0x30A60,
            "PSE literal pool: HSD Step Value descriptor pointers.\n" +
            "6 descriptor pointers (2 active + 4 zero-filled).\n" +
            "Active entries:\n" +
            "  0x30A60 -> 0xACA78 (HSD Step 1, data=0xCD5A6)\n" +
            "  0x30A6C -> 0xACAA0 (HSD Step 2, data=0xCD5E6)");

        // ─────────────────────────────────────────────────────────────
        // EXTRA ZERO-FILLED DATA BLOCKS
        // ─────────────────────────────────────────────────────────────

        println("Labeling extra zero-filled data slots...");

        defineWords(0xCD6A6, 16, "PSE_HSD_InitStart_Extra1_Data",
            "HSD Initial Start - extra unused slot (all zeros).\n" +
            "Referenced from code at 0x30A54, descriptor at 0xACB18.");
        defineWords(0xCD6C6, 16, "PSE_HSD_InitStart_Extra2_Data",
            "HSD Initial Start - extra unused slot (all zeros).\n" +
            "Referenced from code at 0x30A58, descriptor at 0xACB2C.");

        // ─────────────────────────────────────────────────────────────
        // SUMMARY
        // ─────────────────────────────────────────────────────────────

        println("");
        println("Post Start Enrichment tables defined:");
        println("  LSD Initial 1A:    0xCD3A6  (active)");
        println("  LSD Initial 1B:    0xCD3C6  (active)");
        println("  LSD Initial 2A:    0xCD3E6  (active)");
        println("  LSD Initial 2B:    0xCD406  (active)");
        println("  LSD Delay 1:       0xCD426  (flat 38)");
        println("  LSD Delay 2:       0xCD586  (all zeros)");
        println("  HSD Init Start 1A: 0xCD446  (active)");
        println("  HSD Init Start 1B: 0xCD4A6  (active)");
        println("  HSD Init Start 2A: 0xCD4E6  (active)");
        println("  HSD Init Start 2B: 0xCD546  (active)");
        println("  HSD Step Value 1:  0xCD5A6  (active)");
        println("  HSD Step Value 2:  0xCD5E6  (active)");
        println("  LSD Delay Mult:    0xCD666  (active)");
        println("");
        println("CT axes:");
        println("  Axis #1: 0xCC624 (used by 12 tables)");
        println("  Axis #2: 0xCC664 (used by LSD Delay 2)");
        println("");
        println("Descriptors: 0xAC948 - 0xACB3F (26 entries)");
        println("");
        println("Done! 13 tables + 2 axes + 26 descriptors labeled.");
    }
}
