// Finds -- and optionally clears -- instructions the SH7058 cannot execute.
//
// Ghidra's SuperH:BE:32:SH-2A is a SUPERSET of the SH-2E core in this ECU. It
// also decodes MOVI20/MOVI20S/MOVU, FSQRT/FSCHG/FRCHG/FCNVDS/FCNVSD, and the
// SH-2A 32-bit fixed-length forms. None of those exist on an SH-2E, so every
// one that appears marks DATA that was disassembled as code -- a region
// boundary error, never a finding. See docs/architecture.md.
//
// SH-2E instructions are all 2 bytes, so length == 4 is by itself proof.
//
// DRY_RUN is true by default: the script reports and changes nothing. Read the
// report, then set DRY_RUN = false to clear.
//
// Clearing policy:
//   * expand each hit to its contiguous run of instructions
//   * clear the WHOLE run unless something outside it FLOWS into it (call,
//     jump, fallthrough), or it sits inside a function that has callers.
//     Only a flow reference is evidence that a run is code.
//   * incoming DATA references are evidence of the OPPOSITE. A literal pool is
//     read by real code precisely because it is a literal pool, so data reads
//     are counted and reported but never treated as protection.
//   * runs left for review still get their impossible instructions cleared;
//     the surrounding run is left intact for a human to look at.
//
//@author  AE5L600L disassembly project
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ClearImpossibleSH2E extends GhidraScript {

    private static final boolean DRY_RUN = true;

    /** External incoming references into a run, split by kind. */
    private static final class Refs {
        int flow = 0;
        int data = 0;
        Address firstFlowFrom = null;
        boolean calledFunction = false;
        boolean isCode() { return flow > 0 || calledFunction; }
    }

    /** True if this instruction cannot exist on an SH-2E core. */
    private static boolean impossible(Instruction ins) {
        if (ins.getLength() == 4) return true;          // SH-2E is fixed 16-bit
        String m = ins.getMnemonicString().toLowerCase();
        while (m.startsWith("_")) m = m.substring(1);   // Ghidra prefixes some forms
        return m.startsWith("movi20") || m.startsWith("movu")
            || m.startsWith("fsqrt")  || m.startsWith("fschg")
            || m.startsWith("frchg")  || m.startsWith("fcnv");
    }

    /** First instruction of the contiguous run holding `ins`. */
    private Instruction runStart(Instruction ins) {
        Instruction cur = ins, prev;
        while ((prev = cur.getPrevious()) != null
               && prev.getMaxAddress().add(1).equals(cur.getMinAddress())) {
            cur = prev;
        }
        return cur;
    }

    /** Last instruction of the contiguous run holding `ins`. */
    private Instruction runEnd(Instruction ins) {
        Instruction cur = ins, next;
        while ((next = cur.getNext()) != null
               && cur.getMaxAddress().add(1).equals(next.getMinAddress())) {
            cur = next;
        }
        return cur;
    }

    private Refs classify(Address start, Address end) {
        Refs out = new Refs();
        Address a = start;
        while (a.compareTo(end) <= 0) {
            for (Reference r : getReferencesTo(a)) {
                Address from = r.getFromAddress();
                if (from == null) continue;
                if (from.compareTo(start) >= 0 && from.compareTo(end) <= 0) continue; // internal
                if (r.getReferenceType().isFlow()) {
                    out.flow++;
                    if (out.firstFlowFrom == null) out.firstFlowFrom = from;
                } else {
                    out.data++;
                }
            }
            Function f = getFunctionContaining(a);
            if (f != null && getReferencesTo(f.getEntryPoint()).length > 0) {
                out.calledFunction = true;
            }
            a = a.add(1);
        }
        return out;
    }

    @Override
    protected void run() throws Exception {
        // Collect first; never mutate while iterating the listing.
        List<Instruction> hits = new ArrayList<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (impossible(ins)) hits.add(ins);
        }
        if (hits.isEmpty()) {
            println("No impossible-on-SH2E instructions. Nothing to do.");
            return;
        }

        // Group hits by the contiguous run that contains them.
        Map<Address, Address> runs = new LinkedHashMap<>();      // start -> end
        Map<Address, Integer> hitsPerRun = new LinkedHashMap<>();
        for (Instruction ins : hits) {
            Address s = runStart(ins).getMinAddress();
            runs.put(s, runEnd(ins).getMaxAddress());
            hitsPerRun.merge(s, 1, Integer::sum);
        }

        // Classify every run once.
        Map<Address, Refs> verdict = new LinkedHashMap<>();
        for (Map.Entry<Address, Address> e : runs.entrySet()) {
            verdict.put(e.getKey(), classify(e.getKey(), e.getValue()));
        }

        println("================ IMPOSSIBLE-ON-SH2E ================");
        println("Mode           : " + (DRY_RUN ? "DRY RUN -- nothing will change" : "CLEARING"));
        println("Hits           : " + hits.size());
        println("Contiguous runs: " + runs.size());
        println("----------------------------------------------------");

        int clearedRuns = 0, flagged = 0;
        long clearedBytes = 0;

        for (Map.Entry<Address, Address> e : runs.entrySet()) {
            Address s = e.getKey(), end = e.getValue();
            long len = end.subtract(s) + 1;
            Refs r = verdict.get(s);

            if (!r.isCode()) {
                println(String.format("  CLEAR RUN   %s - %s  (%d bytes, %d hits)  %s",
                        s, end, len, hitsPerRun.get(s),
                        r.data > 0 ? r.data + " data reads in -- literal pool" : "unreferenced"));
                if (!DRY_RUN) clearListing(s, end);
                clearedRuns++;
                clearedBytes += len;
            } else {
                println(String.format("  REVIEW      %s - %s  (%d bytes, %d hits)  %d flow in%s%s",
                        s, end, len, hitsPerRun.get(s), r.flow,
                        r.firstFlowFrom != null ? " (first from " + r.firstFlowFrom + ")" : "",
                        r.calledFunction ? ", inside a called function" : ""));
                flagged++;
            }
        }

        // Review runs keep their shape, but the provably-bogus instructions go.
        int clearedHits = 0;
        for (Instruction ins : hits) {
            Address s = runStart(ins).getMinAddress();
            if (!verdict.get(s).isCode()) continue;     // whole run already handled
            if (!DRY_RUN) clearListing(ins.getMinAddress(), ins.getMaxAddress());
            clearedHits++;
        }

        println("----------------------------------------------------");
        println("Runs cleared whole  : " + clearedRuns + "  (" + clearedBytes + " bytes)");
        println("Runs left for review: " + flagged);
        println("Individual hits cleared inside review runs: " + clearedHits);
        if (DRY_RUN) println("DRY RUN -- set DRY_RUN = false and re-run to apply.");
        println("====================================================");
    }
}
