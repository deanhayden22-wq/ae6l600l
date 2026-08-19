<#
    Run both verification gates.

        .\scripts\check.ps1

    1. verify_disasm_v2.py  -- every committed disassembly line re-decoded from
       ROM bytes, OPERANDS INCLUDED. Exit 0 means "nothing regressed", not
       "nothing found": the corpus has a known baseline of 28 symbolic labels
       plus one deliberate self-correcting passage, and those do not fail.
       Use -Strict to count those too.

    2. coverage_map.py --check -- exits nonzero if docs/verification-status.md
       and .json are stale relative to the definitions, the ROM and the
       disassembly corpus. Regenerate with: python scripts/coverage_map.py

    3. check_label_sync.py -- REPORT ONLY, never fails the run. Lists addresses
       that docs/corrections.md discusses but ImportAE5L600L.java never labels,
       so findings do not stay stranded in prose. Many addresses are cited in
       passing and deserve no label; this exists so the choice is deliberate.

    Windows PowerShell 5.1 has no '&&' operator, which is why this exists.
#>
param([switch]$Strict)

$ErrorActionPreference = 'Continue'
$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo
try {
    Write-Host "== disassembly ==" -ForegroundColor Cyan
    if ($Strict) { python scripts/verify_disasm_v2.py --quiet --strict }
    else         { python scripts/verify_disasm_v2.py --quiet }
    $disasm = $LASTEXITCODE

    if ($disasm -ne 0) {
        Write-Host "`nDisassembly regressed - registry check skipped." -ForegroundColor Red
        Write-Host "Re-derive the offending lines from ROM bytes before trusting anything built on them."
        exit $disasm
    }

    Write-Host "`n== verification registry ==" -ForegroundColor Cyan
    python scripts/coverage_map.py --check
    $registry = $LASTEXITCODE

    if ($registry -ne 0) {
        Write-Host "`nRegistry is stale. Regenerate with:" -ForegroundColor Yellow
        Write-Host "    python scripts/coverage_map.py"
        exit $registry
    }

    Write-Host "`n== prose -> Ghidra label sync (report only) ==" -ForegroundColor Cyan
    python scripts/check_label_sync.py | Select-Object -Last 3

    Write-Host "`nBoth gates clean." -ForegroundColor Green
    exit 0
}
finally { Pop-Location }
