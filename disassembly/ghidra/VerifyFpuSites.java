// Spot-checks the functions that were 0%-covered under the old SH-2 import.
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class VerifyFpuSites extends GhidraScript {
    private void check(long a, String name) throws Exception {
        Address ad = toAddr(a);
        Instruction ins = getInstructionAt(ad);
        if (ins == null) { println(String.format("  %-26s 0x%06X  NOT DISASSEMBLED", name, a)); return; }
        StringBuilder sb = new StringBuilder();
        int n = 0; Instruction c = ins;
        while (c != null && n < 6) { sb.append(c.toString()).append(" | "); c = c.getNext(); n++; }
        println(String.format("  %-26s 0x%06X  OK: %s", name, a, sb));
    }
    @Override protected void run() throws Exception {
        println("===== previously-broken sites =====");
        check(0x0BE598L, "fmac_interp_uint16");
        check(0x0BE588L, "fmac_interp_uint8");
        check(0x002B8CL, "ISR prologue (118 callers)");
        check(0x005840L, "ISR[2] crank-angle FMAC");
        check(0x043750L, "KNOCK_DETECTOR");
        check(0x045BFEL, "FLKC_PATH_J");
        check(0x0463BAL, "FLKC_PATHS_FG");
        check(0x071B58L, "sensor_diag FPU callee");
        check(0x09A3B0L, "SSM read-addresses handler");
        println("===================================");
    }
}
