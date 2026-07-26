# The SSM Read-Addresses Patch

The only **code** difference between the stock ROM and every ROM actually flashed
to this car. Undocumented until 2026-07-26. Your entire datalogging workflow
depends on it.

- **Location:** `0x09A3C2`–`0x09A473` (178 bytes), inside the function at `0x09A3B0`
- **Present in:** every rev 20.8 → 20.19b
- **Absent from:** `ae5l600l.bin`, `2013 STI Sedan.bin`, `2014_wrx.bin`,
  `AE5L700V.bin`, **and `13 20g Base rev 25 e garn.hex`**
- **Origin:** entered the lineage with the "tiny wrex" base at rev 20.8

---

## What the function is

The **SSM "Read Addresses" command handler**. Identified from the command bytes
it loads before dispatch:

```
E4A8  mov #-88,r4  /  644C extu.b r4,r4   -> 0xA8   SSM read-addresses request
E4E8  mov #-24,r4  /  644C extu.b r4,r4   -> 0xE8   SSM positive response
EB13  mov #19,r11                         -> 0x13   NRC: bad message length
EB12  mov #18,r11                         -> 0x12   NRC: sub-function not supported
```

## Stock behaviour — indices, not addresses

Stock reads a 3-byte value from the request, bounds-checks it against `848` (word
at `0x09A4DA`), then uses it as an **index** into a function-pointer table at
`0x06423C` and calls the getter, which returns one byte:

```
3182  cmp/hs r8,r1          ; reject if index >= 848
D523  mov.l @(0x09A4E4),r5  ; -> 0x06423C, getter table
6013  mov r1,r0
4008  shll2 r0              ; index * 4
065E  mov.l @(r0,r5),r6     ; fetch getter pointer
460B  jsr @r6               ; call it -> one byte
```

So on a stock ROM you can only read what Subaru wrote a getter for. The "address"
in an SSM request is not an address at all — it is a table index.

## Patched behaviour — real RAM reads, with a width tag

The patch inspects each entry's high byte. Tagged entries bypass the getter table
entirely and read RAM directly:

```
61C4  mov.b @r12+,r1    ; r1 = SIGN-EXTENDED tag byte
601E  exts.b r1,r0      ; r0 = tag, kept for comparison
4118  shll8 r1
62C4  mov.b @r12+,r2  / 622C extu.b r2,r2 / 312C add r2,r1
4118  shll8 r1
62C4  mov.b @r12+,r2  / 622C extu.b r2,r2 / 312C add r2,r1
                        ; r1 = (sext(tag)<<16) | b2<<8 | b3

88FF  cmp/eq #-1,r0   / E400 mov #0,r4    ; tag 0xFF -> r4=0 -> 1 byte
88F4  cmp/eq #-12,r0  / E403 mov #3,r4    ; tag 0xF4 -> r4=3 -> 4 bytes
88F2  cmp/eq #-14,r0  / E401 mov #1,r4    ; tag 0xF2 -> r4=1 -> 2 bytes

3E4C  add r4,r14        ; accumulate response length
E00F  mov #15,r0
4028  shll16 r0         ; r0 = 0x000F0000
210B  or  r0,r1         ; force high byte to 0xFF

6014  mov.b @r1+,r0     ; copy r4+1 bytes from RAM
2A00  mov.b r0,@r10
7A01  add #1,r10
4415  cmp/pl r4
74FF  add #-1,r4
89F9  bt <loop>
```

### The encoding trick

Sign-extending the tag byte and shifting left 16 puts it in the high half:

| Tag | `sext(tag) << 16` | `\| 0x000F0000` | Width |
|---|---|---|---|
| `0xFF` | `0xFFFF0000` | `0xFFFF0000` | 1 byte |
| `0xF2` | `0xFFF20000` | `0xFFFF0000` | 2 bytes |
| `0xF4` | `0xFFF40000` | `0xFFFF0000` | 4 bytes |

OR-ing `0x000F0000` forces the high nibble-pair to `0xFF` in all three cases, so
every tag lands on RAM base `0xFFFF0000` — while the tag's **low nibble**
(`F`/`2`/`4`) simultaneously selects the read width. One byte carries both the
address prefix and the data type, and the `2`/`4` literally name the byte count.

Untagged entries fall through to the stock getter-table path, so nothing breaks.

### In practice

| SSM address | Reads |
|---|---|
| `0xFF6624` | 1 byte at RAM `0xFFFF6624` (RPM) |
| `0xF26350` | 2 bytes at RAM `0xFFFF6350` (ECT) |
| `0xF465FC` | 4 bytes at RAM `0xFFFF65FC` (load) |

## Why it matters

Every extended channel in `logs/` — `AFC`, `AFL`, `FLKC`, `FBKC`, `avcs`, `wgdc`,
`IPW`, `IDC`, `KNOCK_FLAG` — is a direct RAM read with no stock getter. Without
these 178 bytes none of them are loggable, and essentially every conclusion in
this project traces back to logs that exist because of this patch.

It is also the best available **precedent for code modification on this ECU**: a
working, proven, in-service patch. Anyone planning injected code should read it
first — it shows the house style for hooking this ROM without disturbing the
surrounding control flow.

## Analysis note

The function is reachable only through a dispatch table, so Ghidra's flow
analysis never finds it. `disassembly/ghidra/SeedDispatchTargets.java` force-seeds
it (plus the 848 SSM getter targets — 192 of which auto-analysis also missed).
