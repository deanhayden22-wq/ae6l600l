"""
Trace afl_sub_dispatcher (0x34488) and related functions
to understand the descriptor float -> IPW relationship.
"""
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('rom/ae5l600l.bin', 'rb') as f:
    rom = f.read()

def u16(a): return (rom[a] << 8) | rom[a+1]
def u32(a): return (rom[a] << 24) | (rom[a+1] << 16) | (rom[a+2] << 8) | rom[a+3]
def s8(v): return v - 256 if v >= 128 else v
def s12(v): return v - 4096 if v >= 2048 else v

KNOWN_RAM = {
    0xFFFF316C: 'desc_float_base',
    0xFFFF3D08: 'desc_struct_base_A',
    0xFFFF3D10: 'desc_struct_base_B',
    0xFFFF76C8: 'fuel_pw_final',
    0xFFFF76D4: 'fuel_enrichment_A',
    0xFFFF7870: 'AFC_pi_blended_output',
    0xFFFF787F: 'afl_state_byte',
    0xFFFF7874: 'AFL_working_A',
    0xFFFF78A4: 'AFL_working_B',
    0xFFFF7878: 'fuel_enrichment_B',
    0xFFFF7AE4: 'fuel_enrichment_C',
    0xFFFF781C: 'AFC_pipeline_result',
    0xFFFF7820: 'AFC_clamped_output',
    0xFFFF6350: 'ECT_float',
    0xFFFF6364: 'IAT_float',
    0xFFFF63FC: 'MAP_float',
    0xFFFF65C0: 'engine_running_state',
    0xFFFF6254: 'gear_position_byte',
    0xFFFF36BE: 'cyl_descriptor_index',
    0xFFFF36B8: 'injection_mode_flags',
    0xFFFF33A8: 'inj_timing_array_base',
    0xFFFF33B4: 'inj_timing_struct',
    0xFFFF33F0: 'inj_timing_struct_B',
    0xFFFF1288: 'inj_gate_hook_ptr',
    0xFFFF1290: 'inj_state_flags',
}

KNOWN_SUB = {
    0x34488: 'afl_sub_dispatcher',
    0x344BA: 'afl_range_loop',
    0x344EE: 'afl_validity_check',
    0xBDBCC: 'cyl_injection_cb',
    0xBDCB6: 'func_BDCB6',
    0xBE56C: 'func_BE56C',
    0xCC068: 'func_CC068',
    0xCC064: 'func_CC064',
}

def label(v):
    if v in KNOWN_RAM: return f' <{KNOWN_RAM[v]}>'
    if v in KNOWN_SUB: return f' <{KNOWN_SUB[v]}>'
    return ''


def disasm(start, end, title=''):
    if title:
        print(f'\n{"="*72}')
        print(f'{title}  [0x{start:05X}]')
        print(f'{"="*72}')
    addr = start
    while addr < end:
        op = u16(addr)
        hi = (op >> 12) & 0xF
        rn = (op >> 8) & 0xF
        rm = (op >> 4) & 0xF
        lo = op & 0xF
        imm8 = op & 0xFF
        mnem = f'0x{op:04X}'
        extra = ''

        if op == 0x000B: mnem = 'rts'
        elif op == 0x0009: mnem = 'nop'
        elif op == 0x002B: mnem = 'rte'
        elif op == 0x0008: mnem = 'clrt'
        elif op == 0x0018: mnem = 'sett'
        elif op == 0x0028: mnem = 'clrmac'
        elif (op & 0xF0FF) == 0x0002: mnem = f'stc SR,R{rn}'
        elif (op & 0xF0FF) == 0x0032: mnem = f'stc SSR,R{rn}'
        elif (op & 0xF0FF) == 0x0042: mnem = f'stc SPC,R{rn}'
        elif (op & 0xF0FF) == 0x4007: mnem = f'ldc.l @R{rn}+,SR'
        elif (op & 0xF0FF) == 0x4017: mnem = f'ldc.l @R{rn}+,GBR'
        elif (op & 0xF0FF) == 0x4027: mnem = f'ldc.l @R{rn}+,VBR'
        elif (op & 0xF0FF) == 0x4037: mnem = f'ldc.l @R{rn}+,SSR'
        elif (op & 0xF0FF) == 0x4047: mnem = f'ldc.l @R{rn}+,SPC'
        elif (op & 0xF0FF) == 0x400E: mnem = f'ldc R{rn},SR'
        elif (op & 0xF0FF) == 0x401E: mnem = f'ldc R{rn},GBR'
        elif (op & 0xF0FF) == 0x4006: mnem = f'lds.l @R{rn}+,MACH'
        elif (op & 0xF0FF) == 0x4016: mnem = f'lds.l @R{rn}+,MACL'
        elif (op & 0xF0FF) == 0x4026: mnem = f'lds.l @R{rn}+,PR'
        elif (op & 0xF0FF) == 0x4066: mnem = f'lds.l @R{rn}+,FPSCR'
        elif (op & 0xF0FF) == 0x4056: mnem = f'lds.l @R{rn}+,FPUL'
        elif (op & 0xF0FF) == 0x400A: mnem = f'sts MACH,R{rn}'
        elif (op & 0xF0FF) == 0x401A: mnem = f'sts MACL,R{rn}'
        elif (op & 0xF0FF) == 0x402A: mnem = f'sts PR,R{rn}'
        elif (op & 0xF0FF) == 0x4002: mnem = f'sts.l MACH,@-R{rn}'
        elif (op & 0xF0FF) == 0x4012: mnem = f'sts.l MACL,@-R{rn}'
        elif (op & 0xF0FF) == 0x4022: mnem = f'sts.l PR,@-R{rn}'
        elif (op & 0xF0FF) == 0x4062: mnem = f'sts.l FPSCR,@-R{rn}'
        elif (op & 0xF0FF) == 0x4052: mnem = f'sts.l FPUL,@-R{rn}'
        elif (op & 0xF0FF) == 0x4003: mnem = f'stc.l SR,@-R{rn}'
        elif (op & 0xF0FF) == 0x4033: mnem = f'stc.l SSR,@-R{rn}'
        elif (op & 0xF0FF) == 0x4043: mnem = f'stc.l SPC,@-R{rn}'
        elif (op & 0xF0FF) == 0x402B: mnem = f'jmp @R{rn}'
        elif (op & 0xF0FF) == 0x400B: mnem = f'jsr @R{rn}'
        elif (op & 0xF0FF) == 0x4010: mnem = f'dt R{rn}'
        elif (op & 0xF0FF) == 0x4015: mnem = f'cmp/pl R{rn}'
        elif (op & 0xF0FF) == 0x4011: mnem = f'cmp/pz R{rn}'
        elif (op & 0xF0FF) == 0x401B: mnem = f'tas.b @R{rn}'
        elif (op & 0xF0FF) == 0x4020: mnem = f'shal R{rn}'
        elif (op & 0xF0FF) == 0x4021: mnem = f'shar R{rn}'
        elif (op & 0xF0FF) == 0x4000: mnem = f'shll R{rn}'
        elif (op & 0xF0FF) == 0x4001: mnem = f'shlr R{rn}'
        elif (op & 0xF0FF) == 0x4008: mnem = f'shll2 R{rn}'
        elif (op & 0xF0FF) == 0x4009: mnem = f'shlr2 R{rn}'
        elif (op & 0xF0FF) == 0x4018: mnem = f'shll8 R{rn}'
        elif (op & 0xF0FF) == 0x4019: mnem = f'shlr8 R{rn}'
        elif (op & 0xF0FF) == 0x4028: mnem = f'shll16 R{rn}'
        elif (op & 0xF0FF) == 0x4029: mnem = f'shlr16 R{rn}'
        elif (op & 0xF00F) == 0x400C: mnem = f'shad R{rm},R{rn}'
        elif (op & 0xF00F) == 0x400D: mnem = f'shld R{rm},R{rn}'
        elif (op & 0xF00F) == 0x0007: mnem = f'mul.l R{rm},R{rn}'
        elif (op & 0xF00F) == 0x000C: mnem = f'mov.b @(R0,R{rm}),R{rn}'
        elif (op & 0xF00F) == 0x000D: mnem = f'mov.w @(R0,R{rm}),R{rn}'
        elif (op & 0xF00F) == 0x000E: mnem = f'mov.l @(R0,R{rm}),R{rn}'
        elif (op & 0xF0FF) == 0x0003: mnem = f'bsrf R{rn}'
        elif (op & 0xF0FF) == 0x0023: mnem = f'braf R{rn}'
        elif hi == 0xE:
            mnem = f'mov #{s8(imm8)},R{rn}'
        elif hi == 0x9:
            tgt = (addr + 4) + (imm8 * 2)
            v = u16(tgt) if tgt + 1 < len(rom) else 0
            mnem = f'mov.w @({imm8*2},PC),R{rn}'
            extra = f'  ; = 0x{v:04X}{label(v)}'
        elif hi == 0xD:
            tgt = ((addr + 4) & ~3) + (imm8 * 4)
            v = u32(tgt) if tgt + 3 < len(rom) else 0
            mnem = f'mov.l @({imm8*4},PC),R{rn}'
            extra = f'  ; = 0x{v:08X}{label(v)}'
        elif hi == 0x6:
            k = lo
            if k == 3:    mnem = f'mov R{rm},R{rn}'
            elif k == 7:  mnem = f'not R{rm},R{rn}'
            elif k == 8:  mnem = f'swap.b R{rm},R{rn}'
            elif k == 9:  mnem = f'swap.w R{rm},R{rn}'
            elif k == 0xA: mnem = f'negc R{rm},R{rn}'
            elif k == 0xB: mnem = f'neg R{rm},R{rn}'
            elif k == 0xC: mnem = f'extu.b R{rm},R{rn}'
            elif k == 0xD: mnem = f'extu.w R{rm},R{rn}'
            elif k == 0xE: mnem = f'exts.b R{rm},R{rn}'
            elif k == 0xF: mnem = f'exts.w R{rm},R{rn}'
            elif k == 0:  mnem = f'mov.b @R{rm},R{rn}'
            elif k == 1:  mnem = f'mov.w @R{rm},R{rn}'
            elif k == 2:  mnem = f'mov.l @R{rm},R{rn}'
            elif k == 4:  mnem = f'mov.b @R{rm}+,R{rn}'
            elif k == 5:  mnem = f'mov.w @R{rm}+,R{rn}'
            elif k == 6:  mnem = f'mov.l @R{rm}+,R{rn}'
            else: mnem = f'0x{op:04X}'
        elif hi == 0x5:
            mnem = f'mov.l @({lo*4},R{rm}),R{rn}'
        elif hi == 0x1:
            mnem = f'mov.l R{rn},@({lo*4},R{rm})'
        elif hi == 0x2:
            k = lo
            if k == 0:    mnem = f'mov.b R{rn},@R{rm}'
            elif k == 1:  mnem = f'mov.w R{rn},@R{rm}'
            elif k == 2:  mnem = f'mov.l R{rn},@R{rm}'
            elif k == 4:  mnem = f'mov.b R{rn},@-R{rm}'
            elif k == 5:  mnem = f'mov.w R{rn},@-R{rm}'
            elif k == 6:  mnem = f'mov.l R{rn},@-R{rm}'
            elif k == 7:  mnem = f'div0s R{rm},R{rn}'
            elif k == 8:  mnem = f'tst R{rm},R{rn}'
            elif k == 9:  mnem = f'and R{rm},R{rn}'
            elif k == 0xA: mnem = f'xor R{rm},R{rn}'
            elif k == 0xB: mnem = f'or R{rm},R{rn}'
            else: mnem = f'0x{op:04X}'
        elif hi == 0x3:
            ops3 = {0:'cmp/eq',2:'cmp/hs',3:'cmp/ge',4:'div1',5:'dmulu.l',
                    6:'cmp/hi',7:'cmp/gt',8:'sub',0xA:'subc',0xB:'subv',
                    0xC:'add',0xD:'dmuls.l',0xE:'addc',0xF:'addv'}
            mnem = f'{ops3[lo]} R{rm},R{rn}' if lo in ops3 else f'0x{op:04X}'
        elif hi == 0x7:
            mnem = f'add #{s8(imm8)},R{rn}'
        elif hi == 0x8:
            k = (op >> 8) & 0xF
            if k == 0:    mnem = f'mov.b R0,@({lo},{rm})'
            elif k == 1:  mnem = f'mov.w R0,@({lo*2},{rm})'
            elif k == 4:  mnem = f'mov.b @({lo},{rm}),R0'
            elif k == 5:  mnem = f'mov.w @({lo*2},{rm}),R0'
            elif k == 8:
                tgt = addr + 4 + s8(imm8) * 2
                mnem = f'bt 0x{tgt:05X}'
            elif k == 9:
                tgt = addr + 4 + s8(imm8) * 2
                mnem = f'bt/s 0x{tgt:05X}'
            elif k == 0xA:
                tgt = addr + 4 + s8(imm8) * 2
                mnem = f'bf 0x{tgt:05X}'
            elif k == 0xB:
                tgt = addr + 4 + s8(imm8) * 2
                mnem = f'bf/s 0x{tgt:05X}'
            elif k == 0xC: mnem = f'tst.b #{imm8},@(R0,GBR)'
            elif k == 0xD: mnem = f'and.b #{imm8},@(R0,GBR)'
            elif k == 0xE: mnem = f'xor.b #{imm8},@(R0,GBR)'
            elif k == 0xF: mnem = f'or.b #{imm8},@(R0,GBR)'
            else: mnem = f'0x{op:04X}'
        elif hi == 0xA:
            tgt = addr + 4 + s12(op & 0xFFF) * 2
            mnem = f'bra 0x{tgt:05X}'
        elif hi == 0xB:
            tgt = addr + 4 + s12(op & 0xFFF) * 2
            mnem = f'bsr 0x{tgt:05X}'
        elif hi == 0xC:
            k = (op >> 8) & 0xF
            if k == 0:    mnem = f'mov.b R0,@({imm8},GBR)'
            elif k == 1:  mnem = f'mov.w R0,@({imm8*2},GBR)'
            elif k == 2:  mnem = f'mov.l R0,@({imm8*4},GBR)'
            elif k == 4:  mnem = f'mov.b @({imm8},GBR),R0'
            elif k == 5:  mnem = f'mov.w @({imm8*2},GBR),R0'
            elif k == 6:  mnem = f'mov.l @({imm8*4},GBR),R0'
            elif k == 7:
                tgt = ((addr + 4) & ~3) + imm8 * 4
                mnem = f'mova @({imm8*4},PC),R0'
                extra = f'  ; R0 = 0x{tgt:08X}'
            elif k == 8:  mnem = f'tst #{imm8},R0'
            elif k == 9:  mnem = f'and #{imm8},R0'
            elif k == 0xA: mnem = f'xor #{imm8},R0'
            elif k == 0xB: mnem = f'or #{imm8},R0'
            elif k == 3:  mnem = f'trapa #{imm8}'
            else: mnem = f'0x{op:04X}'
        elif hi == 0xF:
            k = lo
            if k == 0xD: mnem = f'fsts FPUL,FR{rn}'
            elif k == 0xC: mnem = f'flds FR{rn},FPUL'
            elif k == 0xA: mnem = f'fmul FR{rm},FR{rn}'
            elif k == 0xB: mnem = f'fadd FR{rm},FR{rn}'  # actually fadd in SH-2 is lo=0
            elif k == 0x8: mnem = f'fabs FR{rn}'         # fabs in SH-2
            elif k == 0x7: mnem = f'fneg FR{rn}'
            elif k == 0x6: mnem = f'fmov @(R0,R{rm}),FR{rn}'
            elif k == 0x5: mnem = f'fmov @R{rm}+,FR{rn}'
            elif k == 0x4: mnem = f'fmov @R{rm},FR{rn}'
            elif k == 0x3: mnem = f'fmov FR{rn},@(R0,R{rm})'
            elif k == 0x2: mnem = f'fmov FR{rn},@-R{rm}'
            elif k == 0x1: mnem = f'fmov FR{rn},@R{rm}'
            elif k == 0x0: mnem = f'fmov FR{rm},FR{rn}'
            elif k == 0x9: mnem = f'fmov @R{rm}+,FR{rn}'  # lo=9 in SH-2/SH-4
            elif k == 0xE: mnem = f'fmac FR0,FR{rm},FR{rn}'
            else: mnem = f'0x{op:04X}'

        print(f'  {addr:05X}: {op:04X}  {mnem}{extra}')
        addr += 2

        if mnem in ('rts', 'rte'):
            op2 = u16(addr)
            print(f'  {addr:05X}: {op2:04X}  <delay slot>')
            addr += 2
            break
        if addr - start > 600:
            print('  ... (truncated)')
            break


# Disassemble afl_sub_dispatcher and sub-functions
disasm(0x34488, 0x346B0, 'afl_sub_dispatcher (0x34488)')

# Also check: what function at 0x3A434 uses desc_float?
print()
print(f'Value at second desc_float ref pool (0x3A434): 0x{u32(0x3A434):08X}')
# Find what code loads from 0x3A434
with open('rom/ae5l600l.bin','rb') as f2:
    pass  # already loaded

for a in range(0x3A000, 0x3A434, 2):
    v = u16(a)
    if (v>>12)&0xF == 0xD:
        tgt = ((a+4)&~3) + (v&0xFF)*4
        if tgt == 0x3A434:
            print(f'  0x{a:05X}: D{((v>>8)&0xF):X}{v&0xFF:02X}  loads desc_float into R{(v>>8)&0xF}')
