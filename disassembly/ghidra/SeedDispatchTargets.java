// Seeds functions that auto-analysis cannot reach because they are only called
// through dispatch tables (SSM getter table, diag monitor table, etc).
// Ghidra's flow-following never reaches these, so they stay undisassembled even
// under a correct language.
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class SeedDispatchTargets extends GhidraScript {

    private int made = 0, already = 0, failed = 0;

    private void seed(long a, String name) throws Exception {
        Address ad = toAddr(a);
        Function f = getFunctionAt(ad);
        if (f != null) { already++; return; }
        if (getInstructionAt(ad) == null) {
            if (!disassemble(ad)) { failed++; println("  FAILED disasm @ " + ad); return; }
        }
        f = createFunction(ad, name);
        if (f == null) { failed++; println("  FAILED function @ " + ad); return; }
        made++;
    }

    @Override
    protected void run() throws Exception {
        // 1. Known indirect-only entry points
        seed(0x09A3B0L, "ssm_read_addresses_handler");

        // 2. SSM getter function table @ 0x06423C, 848 entries (limit word @ 0x09A4DA)
        Address tbl = toAddr(0x06423CL);
        for (int i = 0; i < 848; i++) {
            long p = getInt(tbl.add(i * 4L)) & 0xFFFFFFFFL;
            if (p >= 0x1000 && p < 0x100000 && (p & 1) == 0) {
                seed(p, "ssm_getter_" + String.format("%03d", i));
            }
        }

        println("SeedDispatchTargets: created=" + made + " already=" + already + " failed=" + failed);
    }
}
