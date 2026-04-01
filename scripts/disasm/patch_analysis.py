import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('disassembly/analysis/fueling_pipeline_analysis.txt', 'r', encoding='utf-8') as f:
    content = f.read()

old_section = ('MTU_WRITE_GATE (func_3664) \u2014 partial trace:\n'
'  Struct base: FFFF1288 (8 pool refs in ROM, confirmed injection hardware)\n'
'  Stack saves SR, then:\n'
'    SR = @(FFFF1288+0x10)        ; load SR from struct (mask interrupts)\n'
'    word_A = @(FFFF1288+4)       ; read state A\n'
'    word_B = @(FFFF1288+6)       ; read state B\n'
'    if word_A == word_B: skip    ; already matched \u2192 no write\n'
'    pending = @(FFFF1288+8)\n'
'    if word_A & pending: skip    ; already in-progress\n'
'    @(FFFF1288+8) = word_B       ; commit pending state\n'
'    if @(0x3F2C) != 0:\n'
'        call func_300E(R4=2)     ; notification/logging\n'
'    jsr func_3440(R4=FFFF1288, R5=saved_SR, R6=@(FFFF1288+0x18))\n'
'  SR restored; returns 0.\n'
'  \u2192 func_3440 performs the actual MTU timer register write.\n'
'\n'
'REMAINING UNKNOWNS\n'
'  - func_4B298 @ 0x4B298: ISR epilogue/rte handler (not yet traced)\n'
'  - func_3440 @ 0x3440: actual MTU register write (final injection hardware step)\n'
'  - Gate struct at FFFF1288/FFFF12A0: what controls word_A/word_B/pending?\n'
'  - Descriptor init: what writes the float field and state words in FFFF316C etc?\n'
'  - How descriptor float relates to injection pulse width (fuel_pw_final FFFF76C8)')

new_section = """\
================================================================================
SECTION 17: INJECTION HARDWARE WRITE CHAIN -- COMPLETE TRACE
================================================================================

Complete call chain from ISR22 down to the external injector IC:

  ISR22 (func_48732)
    --> cyl_injection_cb (func_BDBCC)  [per-cylinder descriptor callback]
    --> raise_ipl (func_317C)          [IPL raised to 16, critical section]
    --> injector_output (func_3190)    [gate check]
    --> mtu_write_gate (func_3664)     [external RAM gate state machine]
    --> func_300E (0x300E)             [sets bit15 on external inj-IC register]
    --> func_35FC (0x35FC)             [injection channel timer setup, RAM-resident]
    --> func_2FEC (0x2FEC)             [final hardware write to inj-IC + XRAM]

---

EXTERNAL RAM STRUCT @ 0x10000100 (inj_gate_ctrl_ram):
  Layout (external SRAM, word/longword accesses):
    [+0x04]: uint16  current_slot     -- current channel/slot index
    [+0x06]: uint16  target_slot      -- requested channel/slot index
    [+0x08]: uint32  gate_flags       -- state flags (checked against 0x6EF6)
    [+0x10]: uint32  gate_ipl_sr      -- SR value for IPL masking on entry
    [+0x14]: uint32  channel_data_a   -- channel table field A
    [+0x18]: uint32  channel_data_ptr -- pointer to channel config table entry
  Note: The external RAM at 0x10000000 is the board-level SRAM chip.

EXTERNAL PERIPHERAL @ 0x00F00F00 (injector_hw_ctrl):
  Hardware I/O register on the external injection driver IC (ASIC/CPLD).
  func_300E: @(0x00F00F00) |= 0x8000   --> sets bit15 (triggers injection pulse)
  func_2FEC: @(0x00F00F00) &= 0x4000   --> reads/checks bit14 (injection status)

INTERNAL XRAM @ 0xFFFF1290 (inj_state_flags):
  func_2FEC: @(0xFFFF1290) |= 0xEE00   --> sets injection-in-progress flags
  func_300E: @(0xFFFF1290) &= 0x3F2C   --> clears those flags on completion

---

MTU_WRITE_GATE (func_3664) -- COMPLETE:
  Entry state: R4 = struct pointer, R5 = injection parameter
  Saves: R14, R13, PR to stack; R13 = stc SR (saves interrupt state)

  Load R14 = 0x10000100 (external RAM gate struct)
  SR = @(R14+0x10)              ; raise interrupt mask level
  word_A = @(R14+4)             ; read current_slot
  word_B = @(R14+6)             ; read target_slot
  if word_A == word_B: EXIT     ; already at target, skip write
  flags = @(R14+8)              ; read gate_flags
  if flags & 0x6EF6 != 0: EXIT  ; already in-progress, skip
  @(R14+8) = 0x1000             ; set in-progress flag
  if @(0xFFFF1288) != 0:
      call @(0x3F2C)            ; injection pre-hook via ROM pointer
  call func_300E(R4=0x10000100, R5=saved_SR, R6=@(R14+0x18))
  EXIT:
  SR = R13     ; restore interrupt state
  R0 = 0       ; return 0
  pop PR, R13; rts with delay-slot pop R14

func_300E (0x300E) -- injector IC trigger:
  Push PR
  @(0x00F00F00) |= 0x8000     ; trigger injection pulse on external IC
  call @(@(0x3F2C))            ; call ROM function-pointer at 0x3F2C
  @(0xFFFF1290) &= 0x3F2C     ; clear injection state flags
  Pop PR; rts

func_35FC (0x35FC) -- injection channel timer setup (RAM-resident):
  Entry: R4 = gate_struct (0x10000100), R5 = channel_index (0..3)
  R12 = R4
  R3 = channel_table_base   (PC-relative; resolves correctly from RAM only)
  R13 = sign_extend(R5) * 16 ; offset into channel config table (16B/entry)
  R13 += R3                  ; R13 = &channel_table[channel_index]
  R14 = @(R13+4)             ; channel entry field[+4]
  @(R12+4) = R5              ; write channel_index to gate struct
  @(R12+0x18) = R13          ; write channel_table_entry ptr to struct
  @(R12+0x14) = R14          ; write entry field[+4] to struct
  if @(0x3F84) != 0:
      call @(0x3F28)         ; channel-change notification hook
  @(R12+8) = 0               ; clear pending flag
  byte = @R14                ; check channel state byte
  if byte == 0:              ; channel ready
      @(R14+1) = @(R13+2)   ; write channel config byte
      @(R14+4) = @(R12+0xC) ; write saved stack_ptr to channel struct
      R4 = @(R13+8)          ; channel output parameter
      R5 = @(R12+0xC)        ; stack_ptr
      jmp func_2FEC          ; tail-call to hardware write
  else:                      ; channel busy
      R4 = @(R12+0xC)       ; stack_ptr
      dispatch via @(0x4090 + @R14 - @R13[0])  ; jump table by channel state
  NOTE: PC-relative literals resolve correctly only from RAM (code is copied
        to RAM at boot). From ROM the literals read as garbage instruction bytes.

func_2FEC (0x2FEC) -- final hardware write:
  Push PR
  @(0xFFFF1290) |= 0xEE00      ; set injection-active flags in XRAM
  R1 = 0xFFFDFFFC               ; external SRAM address of runtime fn-ptr
  R3 = @(R1)                    ; load runtime injection timing function ptr
  call R3                        ; call it
  R0 = @(0x00F00F00) & 0x4000  ; read injection IC status (bit14)
  Pop PR; rts
  NOTE: 0xFFFDFFFC is in external SRAM; the function pointer is set at boot.

---

EXTERNAL PERIPHERAL SUMMARY:
  Address       Name               Description
  0x00F00F00    injector_hw_ctrl   External injector ASIC/CPLD I/O register
  0xFFFDFFFC    inj_timing_fn_ptr  Runtime injection timing fn (ext SRAM ptr)
  0x10000100    inj_gate_ctrl_ram  Gate state machine struct (ext SRAM)

INTERNAL XRAM INJECTION ADDRESSES (confirmed this section):
  FFFF1288    inj_gate_hook_ptr    Non-zero = call injection pre-hook via 0x3F2C
  FFFF1290    inj_state_flags      Set/cleared by func_2FEC / func_300E
  FFFF3474    inj_channel_enable   0xFF = all 8 channels enabled (func_56022)

ROM FUNCTION POINTER TABLE (indirect call sites in injection chain):
  0x00003F2C  injection pre-hook target  (mtu_write_gate, func_300E)
  0x00003F28  channel-change notification hook  (func_35FC)
  0x00003F84  non-zero check triggers channel notification  (func_35FC)

---

EARLIER NOTE CORRECTION:
  The "MTU_WRITE_GATE partial trace" note above incorrectly mapped the struct
  to FFFF1288. Corrected: the main gate control struct is external RAM at
  0x10000100. FFFF1288 is a separate hook pointer checked within the function.

REMAINING UNKNOWNS
  - func_4B298 @ 0x4B298: ISR epilogue/rte handler (not yet traced)
  - func_3440 @ 0x3440: inj_timer_setup -- RAM-resident timer config; separate
    path from mtu_write_gate; gate-state machine with reset fallback.
  - What initialises the injection channel config table (used by func_35FC)?
  - What initialises external RAM struct at 0x10000100?
  - Gate struct at FFFF1288: what writes the hook pointer?
  - Descriptor init: what writes float field and state words in FFFF316C?
  - How descriptor float relates to injection pulse width (fuel_pw_final FFFF76C8)
  - fuel_enrichment_A/B/C writers (FFFF76D4, FFFF7878, FFFF7AE4) -- plan step 3
  - AFC stages 3-5 (0x33658, 0x33FCE, 0x340A0) -- plan step 1
  - AFC stages 7-8 (0x3439E, 0x343CE) -- plan step 2"""

new_content = content.replace(old_section, new_section)
if new_content == content:
    print('ERROR: replacement not applied')
else:
    with open('disassembly/analysis/fueling_pipeline_analysis.txt', 'w', encoding='utf-8') as f:
        f.write(new_content)
    with open('disassembly/analysis/fueling_pipeline_analysis.txt', 'r', encoding='utf-8') as f:
        lines = f.readlines()
    print(f'Done. Line count: {len(lines)}')
