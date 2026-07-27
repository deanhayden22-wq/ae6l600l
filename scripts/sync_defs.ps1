<#
    Keep the repo's definition XMLs and the ones ECUFlash actually loads in sync.

        .\scripts\sync_defs.ps1              # report only, changes nothing
        .\scripts\sync_defs.ps1 -Push        # repo  -> ECUFlash  (needs elevation)
        .\scripts\sync_defs.ps1 -Pull        # ECUFlash -> repo   (after editing in ECUFlash)

    WHY THIS EXISTS
    ECUFlash does not read the repo. Its definition directory is recorded in
    HKCU:\Software\OpenECU\EcuFlash\files -> "metadata directory", and by default
    points inside Program Files. So an edit made in ECUFlash never reaches the
    repo, and an edit made in the repo never reaches the car. Both sides drift
    while each looks correct on its own -- the same class of failure as every
    correction in docs/corrections.md.

    Hard links were considered and rejected: an application that saves by
    write-temp-then-rename severs the link silently, which would reintroduce the
    drift while appearing to have fixed it.

    -Push writes into Program Files and therefore needs an elevated shell. If
    that is a nuisance, move the metadata directory somewhere user-writable and
    repoint the registry value above -- no admin needed for that, and this script
    picks the new location up automatically because it reads the registry.
#>
param([switch]$Push, [switch]$Pull, [switch]$Force)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

# Where does ECUFlash actually look? Ask ECUFlash, do not assume.
$meta = (Get-ItemProperty 'HKCU:\Software\OpenECU\EcuFlash\files' -ErrorAction SilentlyContinue).'metadata directory'
if (-not $meta) { Write-Host "Could not read ECUFlash's metadata directory from the registry." -ForegroundColor Red; exit 2 }
$meta = $meta -replace '/', '\'
Write-Host "ECUFlash metadata directory: $meta" -ForegroundColor Cyan

$pairs = @(
    @{ Name = 'project'; Repo = Join-Path $repo 'definitions\AE5L600L 2013 USDM Impreza WRX MT.xml'
       Live = Join-Path $meta 'Impreza WRX\AE5L600L 2013 USDM Impreza WRX MT.xml' },
    @{ Name = 'base   '; Repo = Join-Path $repo 'definitions\32BITBASE.xml'
       Live = Join-Path $meta 'Bases\32BITBASE.xml' }
)

function Get-Sig([string]$p) {
    if (-not (Test-Path $p)) { return $null }
    [pscustomobject]@{
        Hash  = (Get-FileHash $p -Algorithm SHA256).Hash
        Size  = (Get-Item $p).Length
        Mtime = (Get-Item $p).LastWriteTime
    }
}

$diverged = $false
foreach ($p in $pairs) {
    $r = Get-Sig $p.Repo
    $l = Get-Sig $p.Live
    if (-not $r) { Write-Host "  $($p.Name)  repo copy MISSING" -ForegroundColor Red; continue }
    if (-not $l) { Write-Host "  $($p.Name)  ECUFlash copy MISSING" -ForegroundColor Red; $diverged = $true; continue }
    if ($r.Hash -eq $l.Hash) {
        Write-Host "  $($p.Name)  in sync ($($r.Size) bytes)" -ForegroundColor Green
        continue
    }
    $diverged = $true
    $newer = if ($r.Mtime -gt $l.Mtime) { 'REPO' } else { 'ECUFLASH' }
    Write-Host "  $($p.Name)  DIVERGED - $newer is newer" -ForegroundColor Yellow
    Write-Host ("        repo     {0,8} bytes  {1}" -f $r.Size, $r.Mtime)
    Write-Host ("        ecuflash {0,8} bytes  {1}" -f $l.Size, $l.Mtime)
}

if (-not $diverged) { Write-Host "`nNothing to do." -ForegroundColor Green; exit 0 }
if (-not ($Push -or $Pull)) {
    Write-Host "`nReport only. Re-run with -Push (repo -> ECUFlash) or -Pull (ECUFlash -> repo)." -ForegroundColor Cyan
    Write-Host "Check WHICH SIDE IS RIGHT before choosing - this repo has been burned five times"
    Write-Host "by corrections applied in the wrong direction."
    exit 1
}

foreach ($p in $pairs) {
    $from, $to = if ($Push) { $p.Repo, $p.Live } else { $p.Live, $p.Repo }
    if (-not (Test-Path $from)) { continue }
    if ((Get-Sig $from).Hash -eq (Get-Sig $to).Hash) { continue }
    $bak = "$to.bak-$(Get-Date -Format yyyyMMdd-HHmmss)"
    try {
        if (Test-Path $to) { Copy-Item $to $bak -Force }
        Copy-Item $from $to -Force
        Write-Host "  $($p.Name)  copied -> $to  (backup: $(Split-Path -Leaf $bak))" -ForegroundColor Green
    } catch {
        Write-Host "  $($p.Name)  FAILED: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "        Program Files needs an elevated shell for -Push." -ForegroundColor Yellow
        exit 3
    }
}
Write-Host "`nDone. Restart ECUFlash so it reloads the definitions." -ForegroundColor Cyan
exit 0
