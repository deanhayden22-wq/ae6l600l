// Reports disassembly coverage for the AE5L600L ROM, with explicit FPU accounting.
// Run headless against an analyzed program:
//   analyzeHeadless <projDir> <projName> -process <file> \
//       -scriptPath disassembly/ghidra -postScript CoverageStats.java
//
//@author  AE5L600L disassembly project
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

public class CoverageStats extends GhidraScript {

    @Override
    protected void run() throws Exception {
        long instrCount = 0, instrBytes = 0;
        long fpuCount = 0;
        // instructions that CANNOT exist on SH-2E -- each one marks data read as code
        long impossible = 0;
        Map<String, Integer> mnemonicHist = new HashMap<>();
        Map<String, Integer> impossibleHist = new TreeMap<>();

        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            instrCount++;
            instrBytes += ins.getLength();
            String m = ins.getMnemonicString().toLowerCase();
            mnemonicHist.merge(m, 1, Integer::sum);

            if (m.startsWith("f") && !m.equals("for")) {
                fpuCount++;
            }
            // SH-2A-only / non-SH-2E forms
            if (m.startsWith("movi20") || m.equals("movu") || m.startsWith("fsqrt")
                    || m.startsWith("fschg") || m.startsWith("frchg")
                    || m.startsWith("fcnv") || ins.getLength() == 4) {
                impossible++;
                impossibleHist.merge(m + " @" + ins.getAddress(), 1, Integer::sum);
            }
        }

        long funcCount = 0, namedFunc = 0, funcBytes = 0;
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        while (fit.hasNext()) {
            Function f = fit.next();
            funcCount++;
            funcBytes += f.getBody().getNumAddresses();
            if (!f.getName().startsWith("FUN_")) namedFunc++;
        }

        println("================ AE5L600L COVERAGE ================");
        println("Program        : " + currentProgram.getName());
        println("Language       : " + currentProgram.getLanguageID());
        println("--------------------------------------------------");
        println("Instructions   : " + instrCount);
        println("Instr bytes    : " + instrBytes + "  ("
                + String.format("%.1f", 100.0 * instrBytes / 0x100000) + "% of 1MB ROM)");
        println("FPU instrs     : " + fpuCount + "  ("
                + String.format("%.1f", 100.0 * fpuCount / Math.max(1, instrCount)) + "% of instrs)");
        println("Functions      : " + funcCount + "   (named: " + namedFunc + ")");
        println("Function bytes : " + funcBytes);
        println("--------------------------------------------------");
        println("IMPOSSIBLE-ON-SH2E instrs: " + impossible);
        println("  (each is data misread as code -- expect few, at region edges)");
        int shown = 0;
        for (Map.Entry<String, Integer> e : impossibleHist.entrySet()) {
            println("    " + e.getKey());
            if (++shown >= 40) { println("    ... (" + (impossibleHist.size() - shown) + " more)"); break; }
        }
        println("==================================================");
    }
}
