"""
Trace fuel_pulse_width_calc (0x301E4) and fuel_base_store (0x2FF74)
to resolve descriptor float -> fuel_pw_final relationship.
"""
import sys, struct
sys.stdout.reconfigure(encoding='utf-8')

with open('rom/ae5l600l.bin', 'rb') as f:
    rom = f.read()

def u16(a): return (rom[a] << 8) | rom[a+1]
def u32(a): return (rom[a] << 24) | (rom[a+1] << 16) | (rom[a+2] << 8) | rom[a+3]
def s8(v):  return v - 256 if v >= 128 else v
def s12(v): return v - 4096 if v >= 2048 else v

LABELS = {
    # XRAM
    0xFFFF3158: 'inj_descriptor.flags_w0',
    0xFFFF315A: 'inj_descriptor.flags_w1',
    0xFFFF315C: 'inj_descriptor.flags_w2',
    0xFFFF315E: 'inj_descriptor.flags_w3',
    0xFFFF3160: 'inj_descriptor.word_A',
    0xFFFF3164: 'inj_descriptor.base_pw_counts',
    0xFFFF3168: 'inj_descriptor.pw_counts',
    0xFFFF316C: 'inj_descriptor.afl_feedback_float',
    0xFFFF318C: 'inj_descriptor_B.afl_feedback_float',
    0xFFFF33A8: 'inj_timing_array_base',
    0xFFFF33B4: 'inj_timing_struct',
    0xFFFF33F0: 'inj_timing_struct_B',
    0xFFFF6254: 'gear_position_byte',
    0xFFFF65C0: 'engine_running_state',
    0xFFFF65F1: 'fuel_status_byte',
    0xFFFF6350: 'ECT_float',
    0xFFFF6364: 'IAT_float',
    0xFFFF63FC: 'MAP_float',
    0xFFFF64D8: 'AFC_load_input_float',
    0xFFFF65FC: 'base_pulse_width',
    0xFFFF67EC: 'RPM_raw_word',
    0xFFFF76C8: 'fuel_pw_final',
    0xFFFF76D4: 'fuel_enrichment_A',
    0xFFFF7820: 'AFC_clamped_output',
    0xFFFF781C: 'AFC_pipeline_result',
    0xFFFF7870: 'AFC_pi_blended_output',
    0xFFFF787F: 'afl_state_byte',
    0xFFFF78A0: 'AFL_working_struct',
    0xFFFF78A4: 'AFL_working_B',
    0xFFFF78B0: 'AFC_pi_working_struct',
    0xFFFF7874: 'AFL_working_A',
    0xFFFF7878: 'fuel_enrichment_B',
    0xFFFF7AE4: 'fuel_enrichment_C',
    0xFFFF1288: 'inj_gate_hook_ptr',
    0xFFFF1290: 'inj_state_flags',
    0xFFFF3474: 'inj_channel_enable',
    # ROM functions
    0x301E4:  'fuel_pulse_width_calc',
    0x2FF74:  'fuel_base_store',
    0x2F8EA:  'check_transient_flag',
    0x2FA68:  'fuel_cond_gate_A',
    0x2FB68:  'fuel_cond_gate_B',
    0x303C0:  'fuel_warmup_enrichment',
    0x30430:  'fuel_status_copy',
    0x30744:  'fuel_sensor_prep',
    0x30ACC:  'fuel_base_map_combine',
    0x30B68:  'fuel_base_table_calc',
    0x3160A:  'fuel_correction_calc',
    0x31C9C:  'fuel_cyl_arrays_init',
    0x34488:  'afl_sub_dispatcher',
    0x3A222:  'fuel_per_cyl_trim',
    0xBDBCC:  'desc_read_float_safe',
    0xBDCB6:  'desc_read_int_safe',
    0xBE56C:  'float_clamp_range',
    0xCC064:  'AFL_Limits_Min',
    0xCC068:  'AFL_Limits_Max',
    0xBE980:  'func_BE980',
    0xBE9A0:  'func_BE9A0',
    0xBE9B0:  'func_BE9B0',
    0xBE990:  'func_BE990',
}

def lbl(v):
    if v in LABELS: return f' <{LABELS[v]}>'
    if 0xFFFF0000 <= v <= 0xFFFFFFFF: return f' [XRAM+{v-0xFFFF0000:#x}]'
    if 0x000BE000 <= v <= 0x000BF000: return ' [ROM_peripheral]'
    return ''


def dis1(addr):
    op = u16(addr)
    hi = (op >> 12) & 0xF
    rn = (op >>  8) & 0xF
    rm = (op >>  4) & 0xF
    lo =  op        & 0xF
    imm8  = op & 0xFF
    extra = ''

    if op == 0x000B: return 'rts', ''
    if op == 0x0009: return 'nop', ''
    if op == 0x002B: return 'rte', ''
    if op == 0x0008: return 'clrt', ''
    if op == 0x0018: return 'sett', ''
    if op == 0x0028: return 'clrmac', ''
    if (op & 0xF0FF) == 0x0002: return f'stc SR,R{rn}', ''
    if (op & 0xF0FF) == 0x0032: return f'stc SSR,R{rn}', ''
    if (op & 0xF0FF) == 0x0042: return f'stc SPC,R{rn}', ''
    if (op & 0xF0FF) == 0x4007: return f'ldc.l @R{rn}+,SR', ''
    if (op & 0xF0FF) == 0x4017: return f'ldc.l @R{rn}+,GBR', ''
    if (op & 0xF0FF) == 0x4037: return f'ldc.l @R{rn}+,SSR', ''
    if (op & 0xF0FF) == 0x4047: return f'ldc.l @R{rn}+,SPC', ''
    if (op & 0xF0FF) == 0x400E: return f'ldc R{rn},SR', ''
    if (op & 0xF0FF) == 0x4006: return f'lds.l @R{rn}+,MACH', ''
    if (op & 0xF0FF) == 0x4016: return f'lds.l @R{rn}+,MACL', ''
    if (op & 0xF0FF) == 0x4026: return f'lds.l @R{rn}+,PR', ''
    if (op & 0xF0FF) == 0x4066: return f'lds.l @R{rn}+,FPSCR', ''
    if (op & 0xF0FF) == 0x4056: return f'lds.l @R{rn}+,FPUL', ''
    if (op & 0xF0FF) == 0x4002: return f'sts.l MACH,@-R{rn}', ''
    if (op & 0xF0FF) == 0x4012: return f'sts.l MACL,@-R{rn}', ''
    if (op & 0xF0FF) == 0x4022: return f'sts.l PR,@-R{rn}', ''
    if (op & 0xF0FF) == 0x4062: return f'sts.l FPSCR,@-R{rn}', ''
    if (op & 0xF0FF) == 0x4052: return f'sts.l FPUL,@-R{rn}', ''
    if (op & 0xF0FF) == 0x4003: return f'stc.l SR,@-R{rn}', ''
    if (op & 0xF0FF) == 0x4033: return f'stc.l SSR,@-R{rn}', ''
    if (op & 0xF0FF) == 0x4043: return f'stc.l SPC,@-R{rn}', ''
    if (op & 0xF0FF) == 0x402B: return f'jmp @R{rn}', ''
    if (op & 0xF0FF) == 0x400B: return f'jsr @R{rn}', ''
    if (op & 0xF0FF) == 0x4010: return f'dt R{rn}', ''
    if (op & 0xF0FF) == 0x4015: return f'cmp/pl R{rn}', ''
    if (op & 0xF0FF) == 0x4011: return f'cmp/pz R{rn}', ''
    if (op & 0xF0FF) == 0x4020: return f'shal R{rn}', ''
    if (op & 0xF0FF) == 0x4021: return f'shar R{rn}', ''
    if (op & 0xF0FF) == 0x4000: return f'shll R{rn}', ''
    if (op & 0xF0FF) == 0x4001: return f'shlr R{rn}', ''
    if (op & 0xF0FF) == 0x4008: return f'shll2 R{rn}', ''
    if (op & 0xF0FF) == 0x4009: return f'shlr2 R{rn}', ''
    if (op & 0xF0FF) == 0x4018: return f'shll8 R{rn}', ''
    if (op & 0xF0FF) == 0x4019: return f'shlr8 R{rn}', ''
    if (op & 0xF0FF) == 0x4028: return f'shll16 R{rn}', ''
    if (op & 0xF0FF) == 0x4029: return f'shlr16 R{rn}', ''
    if (op & 0xF00F) == 0x400C: return f'shad R{rm},R{rn}', ''
    if (op & 0xF00F) == 0x400D: return f'shld R{rm},R{rn}', ''
    if (op & 0xF00F) == 0x0007: return f'mul.l R{rm},R{rn}', ''
    if (op & 0xF00F) == 0x000C: return f'mov.b @(R0,R{rm}),R{rn}', ''
    if (op & 0xF00F) == 0x000D: return f'mov.w @(R0,R{rm}),R{rn}', ''
    if (op & 0xF00F) == 0x000E: return f'mov.l @(R0,R{rm}),R{rn}', ''
    if (op & 0xF0FF) == 0x0003: return f'bsrf R{rn}', ''
    if (op & 0xF0FF) == 0x0023: return f'braf R{rn}', ''
    if hi == 0xE:
        return f'mov #{s8(imm8)},R{rn}', ''
    if hi == 0x9:
        tgt = (addr + 4) + (imm8 * 2)
        v = u16(tgt) if tgt + 1 < len(rom) else 0
        return f'mov.w @({imm8*2},PC),R{rn}', f'  ; = 0x{v:04X}{lbl(v)}'
    if hi == 0xD:
        tgt = ((addr + 4) & ~3) + (imm8 * 4)
        v = u32(tgt) if tgt + 3 < len(rom) else 0
        try:
            fv = struct.unpack('>f', rom[tgt:tgt+4])[0]
            fstr = f'  float={fv:.6g}' if 1e-10 < abs(fv) < 1e10 else ''
        except: fstr = ''
        return f'mov.l @({imm8*4},PC),R{rn}', f'  ; = 0x{v:08X}{lbl(v)}{fstr}'
    if hi == 0x6:
        k = lo
        names = {0:'mov.b @Rm,Rn',1:'mov.w @Rm,Rn',2:'mov.l @Rm,Rn',3:'mov Rm,Rn',
                 4:'mov.b @Rm+,Rn',5:'mov.w @Rm+,Rn',6:'mov.l @Rm+,Rn',
                 7:'not Rm,Rn',8:'swap.b Rm,Rn',9:'swap.w Rm,Rn',
                 0xA:'negc Rm,Rn',0xB:'neg Rm,Rn',0xC:'extu.b Rm,Rn',
                 0xD:'extu.w Rm,Rn',0xE:'exts.b Rm,Rn',0xF:'exts.w Rm,Rn'}
        n = names.get(k, f'0x{op:04X}')
        return n.replace('Rm', f'R{rm}').replace('Rn', f'R{rn}'), ''
    if hi == 0x5:
        return f'mov.l @({lo*4},R{rm}),R{rn}', ''
    if hi == 0x1:
        return f'mov.l R{rn},@({lo*4},R{rm})', ''
    if hi == 0x2:
        k = lo
        names = {0:'mov.b Rn,@Rm',1:'mov.w Rn,@Rm',2:'mov.l Rn,@Rm',
                 4:'mov.b Rn,@-Rm',5:'mov.w Rn,@-Rm',6:'mov.l Rn,@-Rm',
                 7:'div0s Rm,Rn',8:'tst Rm,Rn',9:'and Rm,Rn',
                 0xA:'xor Rm,Rn',0xB:'or Rm,Rn'}
        n = names.get(k, f'0x{op:04X}')
        return n.replace('Rm', f'R{rm}').replace('Rn', f'R{rn}'), ''
    if hi == 0x3:
        ops = {0:'cmp/eq',2:'cmp/hs',3:'cmp/ge',4:'div1',5:'dmulu.l',
               6:'cmp/hi',7:'cmp/gt',8:'sub',0xA:'subc',0xB:'subv',
               0xC:'add',0xD:'dmuls.l',0xE:'addc',0xF:'addv'}
        return (f'{ops[lo]} R{rm},R{rn}' if lo in ops else f'0x{op:04X}'), ''
    if hi == 0x7:
        return f'add #{s8(imm8)},R{rn}', ''
    if hi == 0x8:
        k = (op >> 8) & 0xF
        if k == 0:  return f'mov.b R0,@({lo},R{rm})', ''
        if k == 1:  return f'mov.w R0,@({lo*2},R{rm})', ''
        if k == 4:  return f'mov.b @({lo},R{rm}),R0', ''
        if k == 5:  return f'mov.w @({lo*2},R{rm}),R0', ''
        if k == 8:  return f'bt 0x{addr+4+s8(imm8)*2:05X}', ''
        if k == 9:  return f'bt/s 0x{addr+4+s8(imm8)*2:05X}', ''
        if k == 0xA: return f'bf 0x{addr+4+s8(imm8)*2:05X}', ''
        if k == 0xB: return f'bf/s 0x{addr+4+s8(imm8)*2:05X}', ''
        return f'0x{op:04X}', ''
    if hi == 0xA:
        return f'bra 0x{addr+4+s12(op&0xFFF)*2:05X}', ''
    if hi == 0xB:
        return f'bsr 0x{addr+4+s12(op&0xFFF)*2:05X}', ''
    if hi == 0xC:
        k = (op >> 8) & 0xF
        if k == 7:
            tgt = ((addr + 4) & ~3) + imm8 * 4
            return f'mova @({imm8*4},PC),R0', f'  ; R0=0x{tgt:08X}'
        if k == 8:  return f'tst #{imm8},R0', ''
        if k == 9:  return f'and #{imm8},R0', ''
        if k == 0xA: return f'xor #{imm8},R0', ''
        if k == 0xB: return f'or #{imm8},R0', ''
        if k == 3:  return f'trapa #{imm8}', ''
        return f'0x{op:04X}', ''
    if hi == 0xF:
        k = lo
        # SH-2 FPU: lo=9 is fmov @Rm+,FRn; lo=8 is fmov @Rm,FRn; etc.
        if k == 0x0: return f'fmov FR{rm},FR{rn}', ''
        if k == 0x1: return f'fmov FR{rn},@R{rm}', ''
        if k == 0x2: return f'fmov FR{rn},@-R{rm}', ''
        if k == 0x3: return f'fmov FR{rn},@(R0,R{rm})', ''
        if k == 0x4: return f'fmov @R{rm},FR{rn}', ''
        if k == 0x5: return f'fmov @R{rm}+,FR{rn}', ''
        if k == 0x6: return f'fmov @(R0,R{rm}),FR{rn}', ''
        if k == 0x7: return f'fmov FR{rn},@(R0,R{rm})', ''
        if k == 0x8: return f'fmov @R{rm},FR{rn}', ''   # alternate lo=8 form
        if k == 0x9: return f'fmov @R{rm}+,FR{rn}', ''
        if k == 0xA: return f'fmov FR{rn},@-R{rm}', ''
        if k == 0xB: return f'fmov FR{rn},@R{rm}', ''   # fmov.s to @Rn
        if k == 0xC: return f'flds FR{rn},FPUL', ''
        if k == 0xD: return f'fsts FPUL,FR{rn}', ''
        if k == 0xE: return f'fmac FR0,FR{rm},FR{rn}', ''
        if k == 0xF:
            if (op >> 4) & 0xFF == 0x0F: return 'fschg', ''
            return f'fneg FR{rn}', ''
        return f'0x{op:04X}', ''
    return f'0x{op:04X}', ''


def disasm(start, end, title=''):
    if title:
        print(f'\n{"="*72}')
        print(f'{title}  [0x{start:05X}]')
        print(f'{"="*72}')
    addr = start
    while addr < end:
        m, ex = dis1(addr)
        print(f'  {addr:05X}: {u16(addr):04X}  {m}{ex}')
        addr += 2
        if m in ('rts', 'rte'):
            m2, ex2 = dis1(addr)
            print(f'  {addr:05X}: {u16(addr):04X}  {m2}{ex2}  <delay>')
            addr += 2
            break
        if addr - start > 600:
            print('  ... (truncated at 600 bytes)')
            break


disasm(0x2FF74, 0x301E4, 'fuel_base_store (0x2FF74)')
disasm(0x301E4, 0x303C0, 'fuel_pulse_width_calc (0x301E4)')
