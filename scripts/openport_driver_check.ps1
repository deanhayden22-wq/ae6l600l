<#
openport_driver_check.ps1 - why will Windows not load the Tactrix OpenPort 2.0 driver?

READ-ONLY. It changes nothing on the PC. The only thing it writes is a text
report next to itself (openport_driver_report.txt).

Run it on a NORMAL boot (not the F7 "disable driver signature enforcement"
boot), with the cable PLUGGED IN:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\openport_driver_check.ps1

If the window is not elevated the script asks Windows for administrator rights
(approve the prompt) and carries on in a new window, which stays open.

Background, researched 2026-11-22:

  * The OpenPort 2.0 driver is NOT an INF-only package. Since EcuFlash 1.44 it
    is Tactrix's own kernel driver, openport.sys (service "openport", package
    openport2.inf 1.0.0.4227 dated 2014-04-07), signed with Tactrix's old
    commercial certificate under Microsoft's retired cross-signing programme.
  * Windows 11 24H2 and later stopped trusting that class of driver with the
    April 2026 update ("Windows Driver Policy"). Each PC audits first, then
    switches itself to enforcement. After that openport.sys is refused at load
    time on every normal boot.
  * A self-signed certificate cannot fix that. Windows honours a locally
    trusted certificate for a package CATALOG at install time, never for a
    kernel .sys at load time. Microsoft: no per-driver exception exists.
  * What Microsoft does document is switching the whole policy off (July 2026
    update or later, elevated, then restart):
        CiTool.exe --remove-policy "{8F9CB695-5D48-48D6-A329-7202B44607E3}"
    https://support.microsoft.com/en-us/windows/hardware/drivers/the-windows-driver-policy
    Microsoft Learn says the opposite about the same policy ("Don't attempt to
    remove it to resolve a driver compatibility issue"), some users get
    access denied (0x80070005), and nobody is on record confirming it for a
    Tactrix cable. Use the GUID, never the friendly name: in CiTool's list the
    name "Microsoft Windows Driver Policy" belongs to a DIFFERENT policy
    ({d2bda982-...}, the vulnerable driver blocklist), which must stay.
  * Memory Integrity (HVCI) is a second, separate gate that can also refuse a
    2014 driver. Whether openport.sys passes it is unknown.

This script establishes which of those is actually happening on this PC.
#>

param([switch]$Relaunched)

$ErrorActionPreference = 'Continue'

$ENFORCE_ID   = '8F9CB695-5D48-48D6-A329-7202B44607E3'
$AUDIT_ID     = '784C4414-79F4-4C32-A6A5-F0FB42A51D0D'
$BLOCKLIST_ID = 'D2BDA982-CCF6-4344-AC5B-0B44427B6816'
$USB_MATCH    = 'VID_0403&PID_CC4[B-D]'

$script:report = @()
function Say {
    param([string]$Text = '')
    Write-Host $Text
    $script:report += $Text
}
function Head {
    param([string]$Text)
    Say ''
    Say ('=== ' + $Text + ' ===')
}
function OnOff {
    param($Value, [string]$IfTrue, [string]$IfFalse)
    if ($Value) { return $IfTrue }
    return $IfFalse
}
function EventField {
    param([string]$Xml, [string]$Name)
    $m = [regex]::Match($Xml, 'Name=[''"]' + [regex]::Escape($Name) + '[''"]>([^<]*)<')
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}
function HexStatus {
    param([string]$Raw)
    if (-not $Raw) { return '' }
    $r = $Raw.Trim()
    try {
        if ($r -match '^\d+$')  { return ('0x{0:X8}' -f [uint32]$r) }
        if ($r -match '^-\d+$') { return ('0x{0:X8}' -f [int]$r) }
    } catch { return $r }
    if ($r -match '^0x[0-9a-fA-F]+$') { return ('0x' + $r.Substring(2).ToUpper()) }
    return $r
}
$statusText = @{
    '0xC0000428' = 'signature could not be verified'
    '0xC0E90002' = 'BLOCKED by a Code Integrity policy'
    '0x80070005' = 'access denied'
}
function StatusMeaning {
    param([string]$Hex)
    if ($statusText.ContainsKey($Hex)) { return ('  (' + $statusText[$Hex] + ')') }
    return ''
}
function DevProps {
    param([string]$InstanceId, [string[]]$Keys)
    $inf = ''
    foreach ($key in $Keys) {
        try {
            $v = (Get-PnpDeviceProperty -InstanceId $InstanceId -KeyName $key -ErrorAction Stop).Data
            if ($null -eq $v -or [string]$v -eq '') { continue }
            if ($key -eq 'DEVPKEY_Device_ProblemStatus') { $v = HexStatus ([string]$v); $v = $v + (StatusMeaning $v) }
            if ($key -eq 'DEVPKEY_Device_DriverInfPath') { $inf = [string]$v }
            Say ('  ' + $key.Replace('DEVPKEY_Device_', '') + ' = ' + $v)
        } catch { }
    }
    return $inf
}

# ---------------------------------------------------------------- elevation
$isAdmin = $false
try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }
if ((-not $isAdmin) -and (-not $Relaunched) -and $PSCommandPath) {
    Write-Host 'This window is not elevated. Asking Windows for administrator rights (approve the prompt)...'
    try {
        $argLine = '-NoProfile -ExecutionPolicy Bypass -NoExit -File "' + $PSCommandPath + '" -Relaunched'
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argLine -ErrorAction Stop
        Write-Host 'An elevated window has opened and the results are in it. This window can be closed.'
        exit 0
    } catch {
        Write-Host ('Could not elevate (' + $_.Exception.Message + '). Carrying on without administrator rights.')
    }
}

Say ('OpenPort driver check, ' + (Get-Date -Format 'yyyy-MM-dd HH:mm'))
Say 'Read-only: nothing on this PC is changed.'
Say ('Elevated: ' + (OnOff $isAdmin 'yes' 'NO - the policy list and Secure Boot state will be missing'))
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Say ('WARNING: PowerShell language mode is ' + $ExecutionContext.SessionState.LanguageMode + ' (Smart App Control or an')
    Say '         App Control policy). Some sections below will fail; that is itself a finding.'
}

# ---------------------------------------------------------------- Windows
Head 'Windows'
$build = 0
$ubr = 0
$boot = $null
try {
    $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $build = [int]$cv.CurrentBuildNumber
    $ubr = [int]$cv.UBR
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $boot = $os.LastBootUpTime
    Say ('Product      : ' + $os.Caption)
    Say ('Version      : ' + $cv.DisplayVersion + '  build ' + $build + '.' + $ubr)
    Say ('Architecture : ' + $env:PROCESSOR_ARCHITECTURE)
    Say ('Last boot    : ' + $boot.ToString('yyyy-MM-dd HH:mm') + '  (with Fast Startup this is the last full restart)')
} catch {
    Say ('Could not read the Windows version: ' + $_.Exception.Message)
}
if ($build -ge 26100) {
    Say 'Policy scope : IN scope of the 2026 cross-signed driver policy (Windows 11 24H2 or later).'
    if ($build -eq 26100 -or $build -eq 26200) {
        # KB5101650, 2026-07-14: its page heading says 26100.8875 / 26200.8875, its title 26200.8870.
        Say ('July 2026 update or later (build .8870+): ' + (OnOff ($ubr -ge 8870) 'yes' 'NO - the CiTool off-switch needs it'))
    } elseif ($build -eq 26300) {
        Say 'July 2026 update or later: yes (26H2 was released after July 2026).'
    } else {
        Say 'July 2026 update or later: cannot tell from this build number; see Settings > Windows Update > Update history.'
    }
} elseif ($build -gt 0) {
    Say 'Policy scope : NOT in scope of the 2026 cross-signed driver policy (Windows 10, or Windows 11 23H2'
    Say '               and earlier). If the driver fails here, the cause is something else.'
}
if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
    Say 'ARM64 Windows: an x64 kernel driver can never load here. Nothing below will change that.'
}

# ---------------------------------------------------------------- boot security
Head 'Boot security'
try {
    $sb = Confirm-SecureBootUEFI -ErrorAction Stop
    Say ('Secure Boot             : ' + (OnOff $sb 'ON' 'OFF'))
} catch {
    Say ('Secure Boot             : unknown (' + $_.Exception.Message + ')')
}
$sso = ''
try {
    $sso = [string](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name SystemStartOptions -ErrorAction Stop).SystemStartOptions
} catch { }
Say ("Boot options            : '" + (($sso -replace '\s+', ' ').Trim()) + "'")
$relaxedBoot = $false
if ($sso -match 'TESTSIGNING') {
    Say '  -> test-signing mode is ON.'
}
if ($sso -match 'DISABLE_INTEGRITY_CHECKS|NOINTEGRITYCHECKS') {
    $relaxedBoot = $true
    Say '  -> signature enforcement looks DISABLED for this boot (F7). The results below'
    Say '     do not describe a normal boot. Restart normally and run this again.'
}
if ($sso -match 'FVEBOOT') {
    Say '  -> BitLocker / device encryption looks active on the boot drive. Any Secure Boot or'
    Say '     firmware change would ask for the recovery key.'
}
$hvci = $null
try {
    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
    $hvci = (@($dg.SecurityServicesRunning) -contains 2)
    Say ('Memory Integrity (HVCI) : ' + (OnOff $hvci 'RUNNING' 'not running'))
} catch {
    Say ('Memory Integrity (HVCI) : unknown (' + $_.Exception.Message + ')')
}

# ---------------------------------------------------------------- CI policies
Head 'Code Integrity policies (citool -lp -json)'
$policyMode = 'UNKNOWN'
$citool = Join-Path $env:windir 'System32\CiTool.exe'
if (-not (Test-Path -LiteralPath $citool)) {
    $policyMode = 'NO_CITOOL'
    Say 'CiTool.exe is not present (normal on Windows 10 and older Windows 11).'
} else {
    $raw = ''
    $code = -1
    try {
        $raw = (& $citool -lp -json 2>&1 | Out-String)
        $code = $LASTEXITCODE
    } catch {
        $raw = $_.Exception.Message
    }
    $parsed = $null
    if ($code -eq 0) {
        try { $parsed = $raw | ConvertFrom-Json -ErrorAction Stop } catch { $parsed = $null }
    }
    $policies = @()
    if ($null -ne $parsed -and $null -ne $parsed.Policies) { $policies = @($parsed.Policies) }
    if ($policies.Count -eq 0) {
        $hex = HexStatus ([string]$code)
        Say ('Could not read the policy list: CiTool returned ' + $hex + (StatusMeaning $hex) + '.')
        if (-not $isAdmin) { Say 'CiTool needs an elevated window.' }
        $trimmed = $raw.Trim()
        if ($trimmed.Length -gt 600) { $trimmed = $trimmed.Substring(0, 600) + ' ...' }
        Say ('Raw output: ' + $trimmed)
    } else {
        $enf = $null
        $aud = $null
        foreach ($p in $policies) {
            $id = ([string]$p.PolicyID).Trim('{', '}').ToUpper()
            $tag = ''
            if ($id -eq $ENFORCE_ID)   { $enf = $p; $tag = '  <== cross-signed driver policy, ENFORCEMENT variant' }
            if ($id -eq $AUDIT_ID)     { $aud = $p; $tag = '  <== cross-signed driver policy, AUDIT variant' }
            if ($id -eq $BLOCKLIST_ID) { $tag = '  <== vulnerable driver blocklist (a different policy; leave it alone)' }
            Say ('{' + $id + '}  enforced=' + $p.IsEnforced + '  authorized=' + $p.IsAuthorized + '  system=' + $p.IsSystemPolicy + '  "' + $p.FriendlyName + '"' + $tag)
        }
        if ($null -ne $enf -and $enf.IsEnforced -and $enf.IsAuthorized) {
            $policyMode = 'ENFORCEMENT'
        } elseif ($null -ne $aud -and $aud.IsEnforced -and $aud.IsAuthorized) {
            $policyMode = 'EVALUATION'
        } else {
            $policyMode = 'NOT_ACTIVE'
        }
    }
}
Say ('Cross-signed driver policy mode: ' + $policyMode)

# ---------------------------------------------------------------- device
Head 'OpenPort device'
$devs = @()
try {
    $devs = @(Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction Stop |
        Where-Object { $_.PNPDeviceID -match $USB_MATCH -or $_.Name -match 'openport|tactrix' })
} catch {
    Say ('Could not list devices: ' + $_.Exception.Message)
}
$problemText = @{
    0  = 'working'
    10 = 'device cannot start'
    28 = 'no driver installed'
    31 = 'driver could not be loaded for this device'
    39 = 'driver could not be loaded (missing, corrupt or BLOCKED)'
    48 = 'driver blocked from starting'
    52 = 'Windows cannot verify the digital signature'
}
$primary = $null
$primaryInf = ''
if ($devs.Count -eq 0) {
    Say 'NO OPENPORT IS PLUGGED IN (looked for USB VID_0403 PID_CC4B/CC4C/CC4D and the names'
    Say '"openport" / "tactrix"). The driver only tries to load when the cable is connected,'
    Say 'so plug it in and run this again. What Windows remembers about the cable:'
    try {
        $ghosts = @(Get-PnpDevice -ErrorAction Stop | Where-Object { $_.InstanceId -match $USB_MATCH })
        if ($ghosts.Count -eq 0) { Say '  nothing: this PC has no record of an OpenPort ever being connected.' }
        foreach ($g in $ghosts) {
            Say ('Remembered    : ' + $g.InstanceId + '   "' + $g.FriendlyName + '"')
            [void](DevProps $g.InstanceId @('DEVPKEY_Device_Service', 'DEVPKEY_Device_DriverInfPath', 'DEVPKEY_Device_DriverVersion', 'DEVPKEY_Device_LastArrivalDate', 'DEVPKEY_Device_LastRemovalDate'))
        }
    } catch {
        Say ('  could not list remembered devices: ' + $_.Exception.Message)
    }
}
foreach ($d in $devs) {
    $prob = -1
    try { $prob = [int]$d.ConfigManagerErrorCode } catch { }
    $meaning = '?'
    if ($problemText.ContainsKey($prob)) { $meaning = $problemText[$prob] }
    Say ('Name          : ' + $d.Name)
    Say ('Instance      : ' + $d.PNPDeviceID)
    Say ('Class         : ' + $d.PNPClass)
    Say ('Bound service : ' + $d.Service)
    Say ('Problem code  : ' + $prob + '  (' + $meaning + ')')
    $inf = DevProps $d.PNPDeviceID @('DEVPKEY_Device_DriverInfPath', 'DEVPKEY_Device_DriverProvider', 'DEVPKEY_Device_DriverVersion', 'DEVPKEY_Device_DriverDate', 'DEVPKEY_Device_ProblemStatus', 'DEVPKEY_Device_LastArrivalDate')
    Say ''
    $isJ2534 = ($d.PNPDeviceID -match 'PID_CC4D') -or ($d.PNPDeviceID -match 'PID_CC4C&MI_00')
    if ($null -eq $primary -or ($isJ2534 -and $primary.PNPDeviceID -notmatch 'PID_CC4D|PID_CC4C&MI_00')) {
        $primary = $d
        $primaryInf = [string]$inf
    }
}

# ---------------------------------------------------------------- driver packages
Head 'Driver packages in the driver store (pnputil /enum-drivers)'
try {
    $pn = (& pnputil.exe /enum-drivers 2>&1 | Out-String)
    $blocks = $pn -split '(?:\r?\n){2,}'
    $want = 'openport|tactrix'
    if ($primaryInf -match '^oem\d+\.inf$') { $want = $want + '|' + [regex]::Escape($primaryInf) }
    $hits = @($blocks | Where-Object { $_ -match $want })
    if ($hits.Count -eq 0) {
        Say 'No package mentioning "openport" or "Tactrix" is staged, and the cable is not bound to an OEM package.'
    }
    foreach ($b in $hits) {
        Say $b.Trim()
        Say ''
    }
} catch {
    Say ('pnputil failed: ' + $_.Exception.Message)
}

# ---------------------------------------------------------------- kernel driver file
Head 'Tactrix kernel driver (service "openport")'
$svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\openport'
if (-not (Test-Path -LiteralPath $svcKey)) {
    Say 'Service "openport" is not registered: the Tactrix driver has never been bound on this PC.'
} else {
    $img = ''
    try { $img = [string](Get-ItemProperty -LiteralPath $svcKey -Name ImagePath -ErrorAction Stop).ImagePath } catch { }
    $path = $img
    if ($path -match '^\\SystemRoot\\(.*)$') {
        $path = Join-Path $env:windir $Matches[1]
    } elseif ($path -match '^\\\?\?\\(.*)$') {
        $path = $Matches[1]
    } elseif ($path -and (-not [IO.Path]::IsPathRooted($path))) {
        $path = Join-Path $env:windir $path
    }
    Say ('ImagePath : ' + $img)
    if (-not $path -or -not (Test-Path -LiteralPath $path)) {
        Say ('Driver file is MISSING at: ' + $path)
        Say 'A missing file also gives problem code 39; that would be a broken install, not a policy block.'
    } else {
        try {
            $fi = Get-Item -LiteralPath $path -ErrorAction Stop
            Say ('File      : ' + $path)
            Say ('Version   : ' + $fi.VersionInfo.FileVersion + '   size ' + $fi.Length + '   modified ' + $fi.LastWriteTime.ToString('yyyy-MM-dd'))
            Say ('SHA-256   : ' + (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash)
            $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
            Say ('Signature : ' + $sig.Status + '  (type ' + $sig.SignatureType + ', OS binary ' + $sig.IsOSBinary + ')')
            if ($null -ne $sig.SignerCertificate) {
                $c = $sig.SignerCertificate
                Say ('  signer  : ' + $c.Subject)
                Say ('  issuer  : ' + $c.Issuer)
                Say ('  valid   : ' + $c.NotBefore.ToString('yyyy-MM-dd') + ' to ' + $c.NotAfter.ToString('yyyy-MM-dd') + '   cert algorithm ' + $c.SignatureAlgorithm.FriendlyName)
            }
            if ($null -ne $sig.TimeStamperCertificate) {
                Say ('  timestamp by: ' + $sig.TimeStamperCertificate.Subject)
            }
            Say 'Note: "Valid" here is the ordinary Authenticode check. The kernel policy is stricter,'
            Say '      so a Valid signature from a non-Microsoft signer is exactly what gets blocked.'
        } catch {
            Say ('Could not inspect the driver file: ' + $_.Exception.Message)
        }
    }
}

# ---------------------------------------------------------------- CI events
Head 'Code Integrity log (Microsoft-Windows-CodeIntegrity/Operational)'
$all = @()
$evErr = $null
try {
    $all = @(Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 5000 -ErrorAction Stop)
} catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
        $all = @()
    } else {
        $evErr = $_.Exception.Message
    }
}
$blockNow = $null
$mine = @()
if ($null -ne $evErr) {
    Say ('Could NOT read the log (this is not the same as "no events"): ' + $evErr)
} elseif ($all.Count -eq 0) {
    Say 'The log is empty.'
} else {
    $byId = @{}
    $others = @{}
    $nEnf = 0
    $nAud = 0
    foreach ($e in $all) {
        $byId[[int]$e.Id] = 1 + [int]$byId[[int]$e.Id]
        $xml = ''
        try { $xml = $e.ToXml() } catch { }
        $text = [string]$e.Message + ' ' + $xml
        $pol = 'no policy named'
        if ($text -match $BLOCKLIST_ID) { $pol = 'vulnerable driver blocklist' }
        if ($text -match $AUDIT_ID)     { $pol = 'cross-signed policy AUDIT'; $nAud++ }
        if ($text -match $ENFORCE_ID)   { $pol = 'cross-signed policy ENFORCEMENT'; $nEnf++ }
        if ($text -match 'openport') {
            $mine += New-Object PSObject -Property @{ Time = $e.TimeCreated; Id = $e.Id; Policy = $pol }
        } elseif ($pol -like 'cross-signed*') {
            $file = EventField $xml 'File Name'
            if (-not $file -and $text -match '([^\\\s]+\.sys)') { $file = $Matches[1] }
            if (-not $file) { $file = '(file name not readable)' }
            $others[$file.ToLower()] = $pol
        }
    }
    $newest = $all[0].TimeCreated
    $oldest = $all[$all.Count - 1].TimeCreated
    Say ('Events read : ' + $all.Count + ', covering ' + $oldest.ToString('yyyy-MM-dd HH:mm') + ' to ' + $newest.ToString('yyyy-MM-dd HH:mm'))
    $tally = @()
    foreach ($k in ($byId.Keys | Sort-Object)) { $tally += ([string]$k + ' x' + $byId[$k]) }
    Say ('By event id : ' + ($tally -join ', '))
    Say ('Naming the cross-signed policy: ' + $nEnf + ' enforcement, ' + $nAud + ' audit')
    Say ('Naming openport: ' + $mine.Count + '   (3076 = audited and allowed, 3077 = BLOCKED)')
    $shown = 0
    foreach ($m in $mine) {
        if ($shown -ge 12) { Say ('  ... and ' + ($mine.Count - $shown) + ' older'); break }
        $age = ''
        if ($null -ne $boot -and $m.Time -ge $boot) { $age = '   [since last boot]' }
        Say ('  ' + $m.Time.ToString('yyyy-MM-dd HH:mm:ss') + '   event ' + $m.Id + '   ' + $m.Policy + $age)
        $shown++
    }
    foreach ($m in $mine) {
        if ($m.Id -eq 3077 -and $m.Policy -eq 'cross-signed policy ENFORCEMENT') { $blockNow = $m; break }
    }
    if ($others.Count -gt 0) {
        Say ''
        Say 'Other drivers this PC has audited or blocked under the cross-signed policy'
        Say '(what else switching the policy off would let load again):'
        foreach ($k in ($others.Keys | Sort-Object | Select-Object -First 20)) {
            Say ('  ' + $k + '   (' + $others[$k] + ')')
        }
    }
}

# ---------------------------------------------------------------- load failures
Head 'Driver load failures Windows recorded (System log, Kernel-PnP event 219)'
$lastFail = $null
try {
    $pnp = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-PnP'; Id = 219 } -MaxEvents 500 -ErrorAction Stop)
    $fails = @()
    foreach ($e in $pnp) {
        $xml = ''
        try { $xml = $e.ToXml() } catch { }
        if (([string]$e.Message + ' ' + $xml) -match 'openport|VID_0403&PID_CC4') {
            $hex = HexStatus (EventField $xml 'Status')
            $fails += New-Object PSObject -Property @{ Time = $e.TimeCreated; Status = $hex }
        }
    }
    Say ('Event 219 entries read: ' + $pnp.Count + '   for the OpenPort: ' + $fails.Count)
    $shown = 0
    foreach ($f in $fails) {
        if ($shown -ge 8) { Say ('  ... and ' + ($fails.Count - $shown) + ' older'); break }
        Say ('  ' + $f.Time.ToString('yyyy-MM-dd HH:mm:ss') + '   status ' + $f.Status + (StatusMeaning $f.Status))
        $shown++
    }
    if ($fails.Count -gt 0) { $lastFail = $fails[0] }
} catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
        Say 'No event 219 entries at all in the System log.'
    } else {
        Say ('Could not read the System log: ' + $_.Exception.Message)
    }
}

# ---------------------------------------------------------------- J2534
Head 'J2534 registration (what EcuFlash / RomRaider look up)'
foreach ($viewName in 'Registry32', 'Registry64') {
    try {
        $view = [Enum]::Parse([Microsoft.Win32.RegistryView], $viewName)
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        $root = $base.OpenSubKey('SOFTWARE\PassThruSupport.04.04')
        if ($null -eq $root) {
            Say ($viewName + ': no PassThruSupport.04.04 key')
            continue
        }
        foreach ($n in $root.GetSubKeyNames()) {
            $sub = $root.OpenSubKey($n)
            $lib = [string]$sub.GetValue('FunctionLibrary')
            $state = 'no FunctionLibrary value'
            if ($lib) {
                $probe = $lib
                if ($viewName -eq 'Registry32') { $probe = $lib -ireplace '\\System32\\', '\SysWOW64\' }
                if (Test-Path -LiteralPath $probe) {
                    $state = 'file present, version ' + (Get-Item -LiteralPath $probe).VersionInfo.FileVersion
                } else {
                    $state = 'FILE MISSING'
                }
            }
            Say ($viewName + ': "' + $n + '"')
            Say ('    ' + $lib + '   (' + $state + ')')
        }
    } catch {
        Say ($viewName + ': could not read (' + $_.Exception.Message + ')')
    }
}

# ---------------------------------------------------------------- reading
Head 'Reading'
if (-not $isAdmin) {
    Say '* NOT ELEVATED: the policy mode could not be read. Run again and approve the prompt.'
}
if ($relaxedBoot) {
    Say '* This boot has signature enforcement disabled, so a working cable here proves nothing.'
}
if ($null -eq $primary) {
    Say '* CABLE NOT PLUGGED IN, so the driver has not tried to load. Plug it in and run again.'
    if ($null -ne $lastFail) {
        Say ('  Last recorded load failure: ' + $lastFail.Time.ToString('yyyy-MM-dd HH:mm') + ', status ' + $lastFail.Status + (StatusMeaning $lastFail.Status) + '.')
    }
    if ($null -ne $blockNow) {
        Say ('  The log does hold a cross-signed policy block of openport, newest ' + $blockNow.Time.ToString('yyyy-MM-dd HH:mm') + '.')
    }
} else {
    $svc = [string]$primary.Service
    $prob = -1
    try { $prob = [int]$primary.ConfigManagerErrorCode } catch { }
    if ($svc -and $svc -ne 'openport') {
        Say ('* The cable is bound to "' + $svc + '", not to Tactrix''s driver ("openport").')
        Say '  Tactrix''s op20pt32.dll, and so EcuFlash, only talk to openport.sys and will not see it.'
        Say '  Something (Zadig, NC Flash, Windows itself) put a different driver on the cable.'
    } elseif ($prob -eq 0) {
        Say '* Tactrix''s driver is LOADED and the cable reports no problem in this session.'
        if ($policyMode -eq 'EVALUATION') {
            Say '  The policy is still in evaluation: the driver is allowed for now, and each load'
            Say '  restarts the countdown. It can still flip to enforcement after a long spell unused.'
        }
        if ($policyMode -eq 'ENFORCEMENT' -and -not $relaxedBoot) {
            Say '  Unexpected with the policy enforcing: either this is an F7 boot that was not'
            Say '  detected, or Microsoft''s allow list covers this driver. Send the report.'
        }
    } elseif ($prob -eq 28) {
        Say '* No driver is installed for the cable at all (code 28). That is an install problem,'
        Say '  not a load-time block. Look at the driver package section above.'
    } else {
        Say ('* Tactrix''s driver is bound but NOT loaded (problem code ' + $prob + ').')
        if ($null -ne $blockNow) {
            Say ('  CONFIRMED cause: blocked by the cross-signed driver policy (event 3077, policy ' + $ENFORCE_ID + ',')
            Say ('  newest at ' + $blockNow.Time.ToString('yyyy-MM-dd HH:mm:ss') + '). This is the April 2026 Windows change.')
            Say '  Self-signing cannot fix it. See the header of this script for the documented off-switch.'
        } elseif ($policyMode -eq 'ENFORCEMENT') {
            Say '  LIKELY cause: the cross-signed driver policy is enforcing, but no block event naming'
            Say '  openport was found. Unplug and replug the cable, then run this again.'
        } else {
            Say ('  The cross-signed driver policy is not shown as the cause (mode ' + $policyMode + ').')
            Say '  Look at Memory Integrity, ProblemStatus and the load-failure status above.'
        }
    }
}
if ($hvci -eq $true) {
    Say '* Memory Integrity is running. It is a separate gate: a 2014 driver may still be refused'
    Say '  by it even with the cross-signed policy off. Not known either way for openport.sys.'
}
Say ''
Say 'Nothing was changed.'

# ---------------------------------------------------------------- save
$outDir = $PSScriptRoot
if (-not $outDir) { $outDir = (Get-Location).Path }
$outFile = Join-Path $outDir 'openport_driver_report.txt'
try {
    Set-Content -LiteralPath $outFile -Value $script:report -Encoding ASCII -ErrorAction Stop
    Write-Host ('Report saved to ' + $outFile)
} catch {
    Write-Host ('Could not save the report (' + $_.Exception.Message + '). Copy the text above instead.')
}
