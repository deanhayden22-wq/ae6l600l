// Removes the label names retired on 2026-08-19 by corrections items 91, 92 and 93.
//
// WHY THIS EXISTS
// ImportAE5L600L.java labels with createLabel(addr, name, true), which ADDS a
// label and makes it primary. It never removes one, and Ghidra allows several
// labels per address. So deleting a labelComment call from the import script
// stops it being re-added but does NOT remove it from a program it was already
// applied to -- the stale name stays as a secondary symbol, still searchable and
// still shown in the Symbol Tree.
//
// The 129 names below were retired because the evidence contradicts them:
//   * 105 asserted an ISR dispatch table at 0x00E5EC-0x00E6C0 that does not
//     exist -- item 84 proved it is the literal pool of the 0x00E4xx task stubs,
//     and none of the 51 addresses it holds is in the 0x0-0x400 vector table.
//   *   5 put float/descriptor names on six-instruction byte flag readers.
//   *  the rest were duplicates or superseded identities.
//
// Safe to run more than once: a name that is already gone just reports 0.
// It removes ONLY these exact (address, name) pairs -- your own labels, and the
// current correct ones, are untouched.
//
//@author  AE5L600L disassembly project
//@category Data

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;

public class RetireStaleLabels extends GhidraScript {

    private int drop(long addr, String name) {
        try {
            Address a = toAddr(addr);
            for (Symbol s : getSymbols(name, null)) {
                if (s.getAddress().equals(a)) {
                    s.delete();
                    println("  removed " + name + " at " + a);
                    return 1;
                }
            }
        } catch (Exception e) {
            println("  WARN " + name + ": " + e.getMessage());
        }
        return 0;
    }

    @Override
    public void run() throws Exception {
        int n = 0;
        n += drop(0x000035A4L, "isr_handler_9");
        n += drop(0x00004BCAL, "isr_handler_24");
        n += drop(0x00005798L, "isr_handler_32");
        n += drop(0x00005840L, "isr_handler_2");
        n += drop(0x00005980L, "isr_handler_39");
        n += drop(0x0000658CL, "isr_handler_38");
        n += drop(0x00007D12L, "isr_handler_52");
        n += drop(0x0000812CL, "isr_handler_35");
        n += drop(0x000081C8L, "isr_handler_40");
        n += drop(0x000084D8L, "isr_handler_49");
        n += drop(0x00008528L, "isr_handler_14");
        n += drop(0x000085ACL, "isr_handler_18");
        n += drop(0x000099E4L, "isr_handler_47");
        n += drop(0x00009A14L, "isr_handler_13");
        n += drop(0x00009A34L, "isr_handler_17");
        n += drop(0x00009A58L, "isr_handler_6");
        n += drop(0x0000A694L, "isr_handler_50");
        n += drop(0x0000A844L, "isr_handler_29");
        n += drop(0x0000A878L, "isr_handler_11");
        n += drop(0x0000ACFCL, "isr_handler_36");
        n += drop(0x0000BB32L, "isr_handler_51");
        n += drop(0x0000C36CL, "isr_handler_28");
        n += drop(0x0000C370L, "isr_handler_31");
        n += drop(0x0000CBACL, "isr_handler_4");
        n += drop(0x0000CBEEL, "isr_handler_8");
        n += drop(0x0000D1F4L, "isr_handler_48");
        n += drop(0x0000D268L, "isr_handler_7");
        n += drop(0x0000D3DCL, "isr_handler_19");
        n += drop(0x0000D4FCL, "isr_handler_34");
        n += drop(0x0000D658L, "isr_handler_3");
        n += drop(0x0000D8D0L, "isr_handler_45");
        n += drop(0x0000D940L, "isr_handler_12");
        n += drop(0x0000E5ECL, "dtbl_isr_handler_0");
        n += drop(0x0000E5ECL, "isr_dispatch_table");
        n += drop(0x0000E5F0L, "dtbl_isr_handler_1");
        n += drop(0x0000E5F4L, "dtbl_isr_handler_2");
        n += drop(0x0000E5F8L, "dtbl_isr_handler_3");
        n += drop(0x0000E5FCL, "dtbl_isr_handler_4");
        n += drop(0x0000E600L, "dtbl_isr_handler_5");
        n += drop(0x0000E604L, "dtbl_isr_handler_6");
        n += drop(0x0000E608L, "dtbl_isr_handler_7");
        n += drop(0x0000E60CL, "dtbl_isr_handler_8");
        n += drop(0x0000E610L, "dtbl_isr_handler_9");
        n += drop(0x0000E614L, "dtbl_isr_handler_10");
        n += drop(0x0000E618L, "dtbl_isr_handler_11");
        n += drop(0x0000E61CL, "dtbl_isr_handler_12");
        n += drop(0x0000E620L, "dtbl_isr_handler_13");
        n += drop(0x0000E624L, "dtbl_isr_handler_14");
        n += drop(0x0000E628L, "dtbl_isr_task_scheduler");
        n += drop(0x0000E628L, "sched_table_main");
        n += drop(0x0000E62CL, "dtbl_isr_handler_16");
        n += drop(0x0000E630L, "dtbl_isr_handler_17");
        n += drop(0x0000E634L, "dtbl_isr_handler_18");
        n += drop(0x0000E638L, "dtbl_isr_handler_19");
        n += drop(0x0000E63CL, "dtbl_isr_handler_20");
        n += drop(0x0000E640L, "dtbl_isr_rcan0");
        n += drop(0x0000E644L, "dtbl_isr_rcan1");
        n += drop(0x0000E648L, "dtbl_isr_handler_23");
        n += drop(0x0000E64CL, "dtbl_isr_handler_24");
        n += drop(0x0000E650L, "dtbl_isr_handler_25");
        n += drop(0x0000E654L, "dtbl_isr_handler_26");
        n += drop(0x0000E658L, "dtbl_isr_handler_27");
        n += drop(0x0000E65CL, "dtbl_isr_handler_28");
        n += drop(0x0000E660L, "dtbl_isr_handler_29");
        n += drop(0x0000E664L, "dtbl_isr_handler_30");
        n += drop(0x0000E668L, "dtbl_isr_handler_31");
        n += drop(0x0000E66CL, "dtbl_isr_handler_32");
        n += drop(0x0000E670L, "dtbl_isr_handler_33");
        n += drop(0x0000E674L, "dtbl_isr_handler_34");
        n += drop(0x0000E678L, "dtbl_isr_handler_35");
        n += drop(0x0000E67CL, "dtbl_isr_handler_36");
        n += drop(0x0000E680L, "dtbl_isr_handler_37");
        n += drop(0x0000E684L, "dtbl_isr_handler_38");
        n += drop(0x0000E688L, "dtbl_isr_handler_39");
        n += drop(0x0000E68CL, "dtbl_isr_handler_40");
        n += drop(0x0000E690L, "dtbl_isr_handler_41");
        n += drop(0x0000E694L, "dtbl_isr_handler_42");
        n += drop(0x0000E698L, "dtbl_isr_handler_43");
        n += drop(0x0000E69CL, "dtbl_isr_handler_44");
        n += drop(0x0000E6A0L, "dtbl_isr_handler_45");
        n += drop(0x0000E6A4L, "dtbl_isr_handler_46");
        n += drop(0x0000E6A8L, "dtbl_isr_handler_47");
        n += drop(0x0000E6ACL, "dtbl_isr_handler_48");
        n += drop(0x0000E6B0L, "dtbl_isr_handler_49");
        n += drop(0x0000E6B4L, "dtbl_isr_handler_50");
        n += drop(0x0000E6B8L, "dtbl_isr_handler_51");
        n += drop(0x0000E6BCL, "dtbl_isr_handler_52");
        n += drop(0x0000E6C0L, "dtbl_isr_handler_53");
        n += drop(0x0000E774L, "ADC_StateMachine");
        n += drop(0x0000FC04L, "isr_handler_1");
        n += drop(0x0000FE22L, "isr_handler_10");
        n += drop(0x00010124L, "isr_handler_25");
        n += drop(0x0001076AL, "isr_handler_23");
        n += drop(0x00010800L, "event_notify");
        n += drop(0x00010A46L, "isr_handler_0");
        n += drop(0x00010D58L, "isr_handler_20");
        n += drop(0x00023E48L, "fuel_desc_reader");
        n += drop(0x000278D2L, "dwell_calculator");
        n += drop(0x000281DCL, "sensor_scale_helper");
        n += drop(0x000297A0L, "float_load_from_desc");
        n += drop(0x0002999CL, "flkc_flag_slot15");
        n += drop(0x000299BCL, "float_store_to_ram");
        n += drop(0x00047B66L, "isr_handler_26");
        n += drop(0x0004907CL, "isr_handler_5");
        n += drop(0x00049A7AL, "isr_handler_27");
        n += drop(0x00049BA4L, "isr_handler_30");
        n += drop(0x00049CF0L, "isr_handler_33");
        n += drop(0x0004A03EL, "isr_handler_37");
        n += drop(0x0004A420L, "isr_handler_41");
        n += drop(0x0004A674L, "isr_handler_42");
        n += drop(0x0004A6C6L, "isr_handler_43");
        n += drop(0x0004A6FAL, "isr_handler_44");
        n += drop(0x0004A94CL, "isr_task_scheduler");
        n += drop(0x0004AA58L, "isr_handler_16");
        n += drop(0x0004AE7CL, "isr_handler_46");
        n += drop(0x0004AE82L, "isr_handler_53");
        n += drop(0x000AD090L, "OL_Enrich_RampRate_Desc");
        n += drop(0x000AD090L, "desc_1D_RPM_wide_u16_9");
        n += drop(0x000AD620L, "desc_2D_ThrottlexRPM_u8_10x9");
        n += drop(0x000AD848L, "desc_2D_ThrottlexRPM_u16_10x9");
        n += drop(0x000AD928L, "desc_afc_pi_blend_2D");
        n += drop(0x000BEA40L, "float_lerp");
        n += drop(0x000BEAB0L, "table_lookup_err_scale");
        n += drop(0xFFFF1288L, "ISR_NestingContext");
        n += drop(0xFFFF20A0L, "system_state_cluster_base");
        n += drop(0xFFFF3234L, "flkc_fg_ref_FR14");
        n += drop(0xFFFF3248L, "flkc_fg_var_3248");
        n += drop(0xFFFF79A4L, "ol_condition_checker_GBR");
        n += drop(0xFFFF81ACL, "gbr_knock_81AC");
        println("RetireStaleLabels: removed " + n + " of 129 stale label(s).");
        println("Now re-run ImportAE5L600L to apply the current names.");
    }
}
