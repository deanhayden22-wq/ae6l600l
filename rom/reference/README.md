# Reference ROMs — provenance and knock-window survey

Stock factory binaries, downloaded by Dean from the RomRaider Stock ROM List
(forum account required) on 2026-06-08, for the post-transient knock window
investigation. All 1,048,576-byte raw SH7058 images (the .hex files are raw
binary despite the extension).

**Do not flash any of these.** Reference only.

## Inventory + survey result

CALIDs verified from embedded ROM strings, not filenames. Model attribution
for AE5L700V corrected via Subaru TSB (P0341/P0346 reprogramming bulletin,
subaru.oemdtc.com/6867): V suffix = STI 6MT, L suffix = WRX 5MT.

| File | CALID | Model | Window B (post-transient knock) |
|---|---|---|---|
| `2012 STi STock rom.Hex` | AE5K500V | 2012 USDM STI 6MT | **438 (armed)** |
| `2013 STI Sedan.bin` | AE5L500V | 2013 USDM STI 6MT | **438 (armed)** |
| `AE5L700V.bin` | AE5L700V | 2013 USDM STI 6MT (TSB update of the 2013 STI line) | **438 (armed)** |
| `2013wrx.hex` | AE5L500L | 2013 USDM WRX 5MT | 0 (disabled) |
| `2014_wrx.bin` | AE5Q100L | 2014 USDM WRX 5MT | 0 (disabled) |
| `09 JDM Impreza wrx STi A-line 2.5turbo AT.hex` | AZ1G502L | 2009 JDM STI AT | unknown (older code rev — signature search needs looser mask) |
| `LAZ1L100X.hex` | AZ1L100X | 2013 USDM Forester XT | unknown (same) |
| `read image.hex` | EE5I920T | 2010 USDM Legacy GT MT | unknown (same) |

Pattern: window B armed on every EJ257 (STI) cal checked, zeroed on every
EJ255 (WRX) cal. Threshold-bleed cals are 0.015 on ALL of them (incl. our
AE5L600L) — Subaru only zeroed the duration on the WRX line.

Full mechanism trace, addresses, and open questions:
`disassembly/analysis/transient_knock_window_trace.txt`.
ECUFlash-editable defs for the window cals were added to
`definitions/32BITBASE.xml` + the AE5L600L car def on 2026-06-08.
