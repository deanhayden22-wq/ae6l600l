#!/usr/bin/env bash
# Run the verification gates. Linux/macOS twin of scripts/check.ps1 -- keep the two in step.
#
#     scripts/check.sh            # gates
#     scripts/check.sh --strict   # also count the 28 symbolic labels + 1 accepted passage
#
# 1. verify_disasm_v2.py    -- every committed disassembly line re-decoded from ROM bytes.
# 2. coverage_map.py --check -- the verification registry is current.
# 3. rom_checksum.py         -- every bin in rom/ carries a valid checksum table.
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

echo; echo "== doc coherence (report only) =="
$PY scripts/doc_coherence.py | tail -n 40

echo; echo "== prose -> Ghidra label sync (report only) =="
$PY scripts/check_label_sync.py | tail -n 3

echo; echo "All gates clean."
exit 0
