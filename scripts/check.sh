#!/usr/bin/env bash
# Run the verification gates. Linux/macOS twin of scripts/check.ps1 -- keep the two in step.
#
#     scripts/check.sh            # gates
#     scripts/check.sh --strict   # also count the 28 symbolic labels + 1 accepted passage
#     scripts/check.sh --full     # also the emulator + checksum self-tests (~2 min)
#
# 1. verify_disasm_v2.py    -- every committed disassembly line re-decoded from ROM bytes.
# 2. coverage_map.py --check -- the verification registry is current.
# 3. rom_checksum.py         -- every bin in rom/ carries a valid checksum table.
# 3b patch_lint/patch_emulate -- the patches on the car still pass gates 1-5 and 8.
# 4. doc_coherence.py        -- REPORT ONLY: docs older than a correction to an address they cite.
# 5. check_label_sync.py     -- REPORT ONLY: addresses discussed in corrections.md but never labelled.
set -u
cd "$(dirname "$0")/.."
PY=${PYTHON:-python3}

echo "== disassembly =="
if [ "${1:-}" = "--strict" ]; then $PY scripts/verify_disasm_v2.py --quiet --strict
else $PY scripts/verify_disasm_v2.py --quiet; fi
rc=$?
if [ $rc -ne 0 ]; then
    echo; echo "Disassembly regressed - later gates skipped."
    echo "Re-derive the offending lines from ROM bytes before trusting anything built on them."
    exit $rc
fi

echo; echo "== verification registry =="
$PY scripts/coverage_map.py --check
rc=$?
if [ $rc -ne 0 ]; then
    echo; echo "Registry is stale. Regenerate with:"; echo "    $PY scripts/coverage_map.py"
    exit $rc
fi

echo; echo "== ROM checksums =="
$PY scripts/rom_checksum.py --quiet rom/*.bin
rc=$?
if [ $rc -ne 0 ]; then
    echo; echo "A bin in rom/ fails its checksum table. Do not flash it."
    exit $rc
fi

echo; echo "== live patches: lint + emulation =="
$PY scripts/patch_lint.py --live >/dev/null && $PY scripts/patch_emulate.py --live | grep -v '^  note'
rc=$?
if [ $rc -ne 0 ]; then
    $PY scripts/patch_lint.py --live
    echo; echo "A live patch fails its lint or emulation gate."
    exit 1
fi

if [ "${1:-}" = "--full" ] || [ "${2:-}" = "--full" ]; then
    echo; echo "== self-tests (emulator oracles, checksum mutations) =="
    $PY scripts/sh2e_emu.py --selftest || exit 1
    $PY scripts/rom_checksum.py --selftest || exit 1
fi

echo; echo "== doc coherence (report only) =="
$PY scripts/doc_coherence.py | tail -n 40

echo; echo "== prose -> Ghidra label sync (report only) =="
$PY scripts/check_label_sync.py | tail -n 3

echo; echo "All gates clean."
exit 0
