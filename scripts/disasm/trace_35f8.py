import struct, sys

rom = open('rom/ae5l600l.bin','rb').read()

def w(a): return struct.unpack_from('>H', rom, a)[0]
def lw(a): return struct.unpack_from('>I', rom, a)[0]

KNOWN_SUBS = {
    0x317C:  "raise_ipl",
    0x3190:  "injector_output_gate",
    0x3440:  "func_3440 (inj_timer_setup)",
    0x3664:  "mtu_write_gate",
    0x35F8:  "func_35F8 (mtu_hw_write)",
    0x3440:  "inj_timer_setup",
}

KNOWN_RAM = {
    0xFFFF1288: "inj_gate_struct_base",
    0xFFFF12A0: "inj_gate_ctrl_ptr",
    0xFFFF3D08: "cyl1_desc_base",
    0xFFFF3D18: "cyl3_desc_base",
    0xFFFF316C: "cyl_desc_arr_base",
    0xFFFF76D4: "fuel_enrichment_A",
    0xFFFF7878: "fuel_enrichment_B",
    0xFFFF7AE4: "fuel_enrichment_C",
}

MTREG = {
    0xFFFFE380: "MTU0_TCR",
    0xFFFFE381: "MTU0_TMDR",
    0xFFFFE384: "MTU0_TCNT",
    0xFFFFE386: "MTU0_TGRA",
    0xFFFFE388: "MTU0_TGRB",
    0xFFFFE38A: "MTU0_TGRC",
    0xFFFFE38C: "MTU0_TGRD",
    0xFFFFE480: "MTU1_TCR",
    0xFFFFE490: "MTU2_TCR",
    0xFFFFE580: "MTU3_TCR",
    0xFFFFE680: "MTU4_TCR",
    0xFFFFE380: "MTU.TCR",
    0xFFFFE000: "MTU.TSTR",
    0xFFFFE001: "MTU.TSYR",
}

def disasm(addr, n=120, stop_on_rts=True):
    pc = addr
    count = 0
    while count < n:
        oa = pc
        word = w(pc)
        pc += 2
        count += 1
        op = f'0x{word:04X}'
        arg = ''
        h = (word >> 12) & 0xF
        nn = (word >> 8) & 0xF
        m = (word >> 4) & 0xF
        i8 = word & 0xFF
        i4 = word & 0xF

        if word == 0x0009: op = 'nop'
        elif word == 0x002B: op = 'rte'
        elif word == 0x000B: op = 'rts'
        elif word == 0x001B: op = 'sleep'
        elif (word & 0xFF00) == 0x8800:
            imm = i8 if i8 < 128 else i8 - 256
            op = f'cmp/eq #{imm},R0'
        elif h == 0xE:
            imm = i8 if i8 < 128 else i8 - 256
            op = f'mov #{imm},R{nn}'
        elif h == 0x9:
            disp = i8 << 1; tgt = pc + disp
            val = struct.unpack_from('>H', rom, tgt)[0]
            op = f'mov.w @(0x{i8:02X},PC),R{nn}'
            arg = f'0x{val:04X} @ {tgt:05X}'
        elif h == 0xD:
            disp = i8 << 2; tgt = (pc & ~3) + disp
            val = lw(tgt)
            op = f'mov.l @(0x{i8:02X},PC),R{nn}'
            lbl = KNOWN_SUBS.get(val) or KNOWN_RAM.get(val) or MTREG.get(val)
            arg = f'0x{val:08X}' + (f' ({lbl})' if lbl else '')
        elif h == 0x6:
            sub = i4
            if sub == 0: op = f'mov.b @R{m},R{nn}'
            elif sub == 1: op = f'mov.w @R{m},R{nn}'
            elif sub == 2: op = f'mov.l @R{m},R{nn}'
            elif sub == 3: op = f'mov R{m},R{nn}'
            elif sub == 4: op = f'mov.b @R{m}+,R{nn}'
            elif sub == 5: op = f'mov.w @R{m}+,R{nn}'
            elif sub == 6: op = f'mov.l @R{m}+,R{nn}'
            elif sub == 7: op = f'not R{m},R{nn}'
            elif sub == 8: op = f'swap.b R{m},R{nn}'
            elif sub == 9: op = f'swap.w R{m},R{nn}'
            elif sub == 0xA: op = f'negc R{m},R{nn}'
            elif sub == 0xB: op = f'neg R{m},R{nn}'
            elif sub == 0xC: op = f'extu.b R{m},R{nn}'
            elif sub == 0xD: op = f'extu.w R{m},R{nn}'
            elif sub == 0xE: op = f'exts.b R{m},R{nn}'
            elif sub == 0xF: op = f'exts.w R{m},R{nn}'
        elif h == 0x2:
            sub = i4
            ops2 = {0:'mov.b R{m},@R{n}',1:'mov.w R{m},@R{n}',2:'mov.l R{m},@R{n}',
                    4:'mov.b R{m},@-R{n}',5:'mov.w R{m},@-R{n}',6:'mov.l R{m},@-R{n}',
                    7:'div0s R{m},R{n}',8:'tst R{m},R{n}',9:'and R{m},R{n}',
                    0xA:'xor R{m},R{n}',0xB:'or R{m},R{n}',0xC:'cmp/str R{m},R{n}'}
            if sub in ops2:
                op = ops2[sub].replace('{m}', str(m)).replace('{n}', str(nn))
        elif h == 0x0:
            sub = i4
            if word == 0x0023: op = 'braf R0'
            elif word == 0x0003: op = 'bsrf R0'
            elif (word & 0xFF0F) == 0x0002: op = f'stc SR,R{nn}'
            elif (word & 0xFF0F) == 0x0012: op = f'stc GBR,R{nn}'
            elif (word & 0xFF0F) == 0x0022: op = f'stc VBR,R{nn}'
            elif (word & 0xF0FF) == 0x002A: op = f'sts PR,R{nn}'
            elif (word & 0xF0FF) == 0x001A: op = f'sts MACL,R{nn}'
            elif (word & 0xF0FF) == 0x000A: op = f'sts MACH,R{nn}'
            elif (word & 0xF0FF) == 0x005A: op = f'sts FPUL,R{nn}'
            elif (word & 0xF0FF) == 0x006A: op = f'sts FPSCR,R{nn}'
            elif sub == 0xC: op = f'mov.b @(R0,R{m}),R{nn}'
            elif sub == 0xD: op = f'mov.w @(R0,R{m}),R{nn}'
            elif sub == 0xE: op = f'mov.l @(R0,R{m}),R{nn}'
            elif sub == 4: op = f'mov.b R{m},@(R0,R{nn})'
            elif sub == 5: op = f'mov.w R{m},@(R0,R{nn})'
            elif sub == 6: op = f'mov.l R{m},@(R0,R{nn})'
            elif sub == 7: op = f'mul.l R{m},R{nn}'
            elif sub == 8: op = f'clrt'
            elif sub == 0xB: op = 'rts'
            elif sub == 0xA: op = f'sts PR,R{nn}' if (word & 0x0F00) else 'sts PR,R0'
        elif h == 0x4:
            sub = word & 0xFF
            if sub == 0x0B: op = f'jsr @R{nn}'
            elif sub == 0x2B: op = f'jmp @R{nn}'
            elif sub == 0x0E: op = f'ldc R{nn},SR'
            elif sub == 0x1E: op = f'ldc R{nn},GBR'
            elif sub == 0x2E: op = f'ldc R{nn},VBR'
            elif sub == 0x0A: op = f'lds R{nn},PR'
            elif sub == 0x1A: op = f'lds R{nn},MACL'
            elif sub == 0x06: op = f'lds.l @R{nn}+,MACH'
            elif sub == 0x16: op = f'lds.l @R{nn}+,MACL'
            elif sub == 0x26: op = f'lds.l @R{nn}+,FPSCR'
            elif sub == 0x56: op = f'lds.l @R{nn}+,FPUL'
            elif sub == 0x07: op = f'ldc.l @R{nn}+,SR'
            elif sub == 0x17: op = f'ldc.l @R{nn}+,GBR'
            elif sub == 0x27: op = f'ldc.l @R{nn}+,VBR'
            elif sub == 0x22: op = f'sts.l PR,@-R{nn}'
            elif sub == 0x12: op = f'sts.l MACL,@-R{nn}'
            elif sub == 0x02: op = f'sts.l MACH,@-R{nn}'
            elif sub == 0x62: op = f'sts.l FPSCR,@-R{nn}'
            elif sub == 0x52: op = f'sts.l FPUL,@-R{nn}'
            elif sub == 0x03: op = f'stc.l SR,@-R{nn}'
            elif sub == 0x13: op = f'stc.l GBR,@-R{nn}'
            elif sub == 0x23: op = f'stc.l VBR,@-R{nn}'
            elif sub == 0x10: op = f'dt R{nn}'
            elif sub == 0x11: op = f'cmp/pz R{nn}'
            elif sub == 0x15: op = f'cmp/pl R{nn}'
            elif sub == 0x21: op = f'shar R{nn}'
            elif sub == 0x20: op = f'shal R{nn}'
            elif sub == 0x01: op = f'shlr R{nn}'
            elif sub == 0x08: op = f'shll2 R{nn}'
            elif sub == 0x18: op = f'shll8 R{nn}'
            elif sub == 0x28: op = f'shll16 R{nn}'
            elif sub == 0x09: op = f'shlr2 R{nn}'
            elif sub == 0x19: op = f'shlr8 R{nn}'
            elif sub == 0x29: op = f'shlr16 R{nn}'
            elif (word & 0xF0FF) == 0x4060: op = f'rotl R{nn}'
            elif (word & 0xF0FF) == 0x4065: op = f'rotr R{nn}'
            elif sub == 0x24: op = f'rotcl R{nn}'
            elif sub == 0x25: op = f'rotcr R{nn}'
            elif (word & 0xFF0F) == 0x400C:
                rn2 = (word >> 4) & 0xF
                op = f'shad R{m},R{nn}'
            elif (word & 0xFF0F) == 0x400D:
                op = f'shld R{m},R{nn}'
        elif h == 0x5:
            disp = i4 * 4
            op = f'mov.l @(0x{disp:X},R{m}),R{nn}'
        elif h == 0x1:
            disp = i4 * 4
            op = f'mov.l R{m},@(0x{disp:X},R{nn})'
        elif h == 0x7:
            imm = i8 if i8 < 128 else i8 - 256
            op = f'add #{imm},R{nn}'
        elif h == 0x3:
            sub = i4
            ops3 = {0:'cmp/eq',2:'cmp/hs',3:'cmp/ge',4:'div1',5:'dmulu.l',6:'cmp/hi',
                    7:'cmp/gt',8:'sub',0xA:'subc',0xB:'subv',0xC:'add',0xE:'addc',0xF:'addv'}
            if sub in ops3: op = f'{ops3[sub]} R{m},R{nn}'
        elif h == 0xA:
            disp = word & 0xFFF
            if disp >= 0x800: disp -= 0x1000
            tgt = pc + disp * 2
            op = f'bra 0x{tgt:05X}'
        elif h == 0xB:
            disp = word & 0xFFF
            if disp >= 0x800: disp -= 0x1000
            tgt = pc + disp * 2
            op = f'bsr 0x{tgt:05X}'
        elif (word & 0xFF00) == 0x8900:
            disp = i8;
            if disp >= 0x80: disp -= 0x100
            tgt = pc + disp * 2
            op = f'bt 0x{tgt:05X}'
        elif (word & 0xFF00) == 0x8B00:
            disp = i8
            if disp >= 0x80: disp -= 0x100
            tgt = pc + disp * 2
            op = f'bf 0x{tgt:05X}'
        elif (word & 0xFF00) == 0x8D00:
            disp = i8
            if disp >= 0x80: disp -= 0x100
            tgt = pc + disp * 2
            op = f'bt/s 0x{tgt:05X}'
        elif (word & 0xFF00) == 0x8F00:
            disp = i8
            if disp >= 0x80: disp -= 0x100
            tgt = pc + disp * 2
            op = f'bf/s 0x{tgt:05X}'
        elif h == 0xF:
            sub = i4
            fn_ = nn; fm = m
            if sub == 0: op = f'fadd FR{fm},FR{fn_}'
            elif sub == 1: op = f'fsub FR{fm},FR{fn_}'
            elif sub == 2: op = f'fmul FR{fm},FR{fn_}'
            elif sub == 3: op = f'fdiv FR{fm},FR{fn_}'
            elif sub == 4: op = f'fcmp/eq FR{fm},FR{fn_}'
            elif sub == 5: op = f'fcmp/gt FR{fm},FR{fn_}'
            elif sub == 0xC: op = f'fmov.s @R{fm},FR{fn_}'
            elif sub == 0xA: op = f'fmov.s FR{fm},@R{fn_}'
            elif sub == 0x9: op = f'fmov.s FR{fm},@-R{fn_}'
            elif sub == 0x8: op = f'fmov.s @R{fm}+,FR{fn_}'
            elif sub == 0xE: op = f'fmac FR0,FR{fm},FR{fn_}'
            elif sub == 0xD:
                if fm == 0xF: op = f'fsca FPUL,DR{fn_}'
                elif fn_ == 0xD and fm == 0: op = 'ftrv XMTRX,FV0'
                else: op = f'0xF{fn_:X}{fm:X}D'
            elif sub == 0xB:
                if fm == 0: op = f'flds FR{fn_},FPUL'
                elif fm == 1: op = f'fsts FPUL,FR{fn_}'
                elif fm == 2: op = f'float FPUL,FR{fn_}'
                elif fm == 3: op = f'ftrc FR{fn_},FPUL'
                elif fm == 4: op = f'fneg FR{fn_}'
                elif fm == 5: op = f'fabs FR{fn_}'
                elif fm == 6: op = f'fsqrt FR{fn_}'
                elif fm == 8: op = f'fldi0 FR{fn_}'
                elif fm == 9: op = f'fldi1 FR{fn_}'
                else: op = f'0xF{fn_:X}{fm:X}B'
        elif h == 0xC:
            sub = (word >> 8) & 0xF
            disp = word & 0xFF
            if sub == 3: op = f'trapa #{disp}'
            elif sub == 7:
                tgt = (pc & ~3) + disp * 4
                val = lw(tgt)
                op = f'mova @(0x{disp*4:X},PC),R0'
                lbl = KNOWN_SUBS.get(val) or KNOWN_RAM.get(val)
                arg = f'-> 0x{tgt:05X} (= 0x{val:08X}' + (f', {lbl})' if lbl else ')')
            elif sub == 8: op = f'tst #{disp},R0'
            elif sub == 9: op = f'and #{disp},R0'
            elif sub == 0xA: op = f'xor #{disp},R0'
            elif sub == 0xB: op = f'or #{disp},R0'
            elif sub == 0: op = f'mov.b R0,@(0x{disp:X},GBR)'
            elif sub == 1: op = f'mov.w R0,@(0x{disp*2:X},GBR)'
            elif sub == 2: op = f'mov.l R0,@(0x{disp*4:X},GBR)'
            elif sub == 4: op = f'mov.b @(0x{disp:X},GBR),R0'
            elif sub == 5: op = f'mov.w @(0x{disp*2:X},GBR),R0'
            elif sub == 6: op = f'mov.l @(0x{disp*4:X},GBR),R0'
        elif h == 0x8:
            sub2 = (word >> 8) & 0xF
            if sub2 == 0: op = f'mov.b R0,@(0x{i4:X},R{m})'
            elif sub2 == 1: op = f'mov.w R0,@(0x{i4*2:X},R{m})'
            elif sub2 == 4: op = f'mov.b @(0x{i4:X},R{m}),R0'
            elif sub2 == 5: op = f'mov.w @(0x{i4*2:X},R{m}),R0'

        print(f'  0x{oa:05X}: {word:04X}  {op}' + (f'   ; {arg}' if arg else ''))
        if op in ('rts', 'rte') and stop_on_rts:
            nw = w(pc); print(f'  0x{pc:05X}: {nw:04X}  [delay slot]')
            break

targets = [0x35F8, 0x3440, 0x3664]
for t in targets:
    nm = {0x35F8:'func_35F8 (mtu_hw_write)', 0x3440:'func_3440 (inj_timer_setup)', 0x3664:'mtu_write_gate'}[t]
    print(f'\n{"="*60}')
    print(f'=== {nm} @ 0x{t:05X} ===')
    print(f'{"="*60}')
    disasm(t, 120)
