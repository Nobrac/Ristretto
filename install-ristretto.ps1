#requires -RunAsAdministrator
param(
    # Skips the confirmation below, for a caller that has already asked.
    # Barista passes it: it runs this through powershell.exe -NonInteractive,
    # where Read-Host cannot prompt and throws instead, so without this the
    # install never gets past the question. Run the script by hand and leave
    # the switch off to get the prompt.
    [switch]$Confirmed
)
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Installs RistrettoFilter into the MSV1_0 Auth0 slot and ristretto.exe next
# to TacProvider.dll.
#
# Read this before running it on anything you care about:
#   * The filter is an UNSIGNED DLL that lsass loads. A fault in it is a
#     bugcheck, and a bugcheck on the logon path can mean a reboot loop.
#   * It needs RunAsPPL off. RunAsPPL is what stops credential dumping from
#     lsass, so turning it off makes the machine materially easier to loot.
#     Net effect on a production box: likely negative.
#   * Test VM only. Take a snapshot first.
# ---------------------------------------------------------------------------

$sddl = 'D:P(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)'   # SYSTEM + Administrators, inheritance blocked
$noPrev = '__none__'                            # sentinel: there was no Auth0 before us

function Set-KeyAclHard {
    param([Parameter(Mandatory)][string]$SubKey)
    # The config key holds the Mode kill switch and WindowSec. Anyone who can
    # write it can switch enforcement off, so it does not get to inherit
    # whatever HKLM\SOFTWARE happens to hand out.
    $sec = New-Object System.Security.AccessControl.RegistrySecurity
    $sec.SetSecurityDescriptorSddlForm($sddl)
    $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            $SubKey, 'ReadWriteSubTree', 'ChangePermissions')
    if (-not $k) { throw "Could not open HKLM\$SubKey to set its ACL." }
    try { $k.SetAccessControl($sec) } finally { $k.Close() }
}

# --- preconditions ---------------------------------------------------------

$dll = Join-Path $PSScriptRoot 'RistrettoFilter.dll'
$exe = Join-Path $PSScriptRoot 'ristretto.exe'
foreach ($f in @($dll, $exe)) {
    if (-not (Test-Path -LiteralPath $f)) { throw "Missing build output: $f. Run build-ristretto.bat first." }
}

$doppioKey = 'HKLM:\SOFTWARE\TheAdminCafe\2FA'
if (-not (Test-Path "$doppioKey\Rids")) {
    throw "Doppio not found ($doppioKey\Rids missing). Install and enroll with Doppio first."
}
if (-not (Test-Path 'C:\Program Files\TheAdminCafe\TacProvider.dll')) {
    throw "TacProvider.dll not found - install Doppio first."
}

$lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$msvKey = "$lsaKey\MSV1_0"
$cfgPathRel = 'SOFTWARE\TheAdminCafe\Ristretto'
$cfg    = "HKLM:\$cfgPathRel"

# A domain controller keeps its accounts in the directory, not in a local SAM.
# Doppio's RID index only knows local accounts, so on a DC the filter would
# check domain RIDs against it. install-subauth.ps1 refuses for the same reason.
# DomainRole 4 = backup DC, 5 = primary DC.
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) {
    throw "This is a domain controller. The filter only knows local accounts by RID; on a DC it would check domain RIDs against Doppio's index. Refusing."
}

# With LSA protection on, lsass only loads plug-ins with a Microsoft LSA
# signature, and this DLL has none. Without these checks the install looked
# fine, Auth0 changed, and the filter simply never loaded.
$lsaProps = Get-ItemProperty -Path $lsaKey
if ($lsaProps.RunAsPPL -or $lsaProps.RunAsPPLBoot) {
    throw "LSA protection (RunAsPPL or RunAsPPLBoot) is on - the unsigned filter will never load. Turn it off in the test VM first."
}

# The registry values are not the whole story: a UEFI variable or Windows' own
# default for new Windows 11 devices can turn LSA protection on as well. The
# proof at runtime is WinInit event 12, "LSASS.exe was started as a protected
# process with level: 4", in the System log. Event ID 12 is used by other
# sources too, hence the provider check.
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$pplEvent = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 12; StartTime = $boot } -ErrorAction SilentlyContinue |
            Where-Object { $_.ProviderName -like '*Wininit*' } | Select-Object -First 1
if ($pplEvent) {
    throw "lsass runs as a protected process since the last boot (WinInit event 12). It will not load the unsigned filter. Turn LSA protection off in the test VM first."
}

if (-not (Test-Path $msvKey)) { throw "$msvKey does not exist. Wrong machine?" }

$cur = (Get-ItemProperty $msvKey -Name Auth0 -ErrorAction SilentlyContinue).Auth0
if ($cur -and $cur -notin @('TacSubAuth', 'RistrettoFilter')) {
    throw "Auth0 belongs to '$cur'. Not touching another product's filter."
}

# What the uninstaller will restore. Checked here, before anything changes.
# An older version of this script wiped the config key on a second run (see
# below) and then recorded its own name, so the uninstaller "restored"
# Ristretto and Doppio's TacSubAuth never came back.
$prevRecorded = $null
if (Test-Path $cfg) {
    $prevRecorded = (Get-ItemProperty $cfg -Name PrevAuth0 -ErrorAction SilentlyContinue).PrevAuth0
}
if ($prevRecorded -eq 'RistrettoFilter') {
    throw "PrevAuth0 under $cfg is 'RistrettoFilter', left by an older version of this script. Set it to what Auth0 was before Ristretto ('TacSubAuth' for Doppio's filter, '$noPrev' for none) and run this again."
}
if ($cur -eq 'RistrettoFilter' -and -not $prevRecorded) {
    throw "Auth0 is already 'RistrettoFilter', but PrevAuth0 under $cfg is missing, so there is no record of what to restore. Set PrevAuth0 ('TacSubAuth' or '$noPrev') and run this again."
}

Write-Host ""
Write-Host "About to put an unsigned DLL in the lsass logon path on this machine." -ForegroundColor Yellow
Write-Host "If it faults, this box may not boot cleanly. Snapshot taken?" -ForegroundColor Yellow

if ($Confirmed) {
    # The two warnings above are printed either way, so they are in the
    # caller's log next to whatever it asked its own user.
    Write-Host "Confirmed by the caller (-Confirmed)."
} else {
    try {
        $answer = Read-Host "Type YES to continue"
    } catch {
        # -NonInteractive without -Confirmed. The raw error from Read-Host
        # says nothing about how to get past it.
        throw "No interactive console for the confirmation. Run this in a normal PowerShell window, or pass -Confirmed if the caller has already asked."
    }
    if ($answer -cne 'YES') { Write-Host "Aborted. Nothing changed."; return }
}

# --- config key, hardened before anything is written into it ---------------

# Create the keys only when they are missing. New-Item -Force on a registry
# key that exists does not open it: the registry provider deletes the key with
# all its values and subkeys and creates it again. That is how a second run
# used to lose PrevAuth0, Mode, WindowSec and every open gate.
if (-not (Test-Path $cfg)) { New-Item $cfg | Out-Null }
Set-KeyAclHard -SubKey $cfgPathRel
if (-not (Test-Path "$cfg\Gate")) { New-Item "$cfg\Gate" | Out-Null }
Set-KeyAclHard -SubKey "$cfgPathRel\Gate"

# Remember what Auth0 was, including "nothing". The old code stored
# 'TacSubAuth' when there was no Auth0 at all, so uninstalling invented a
# filter that was never registered and pointed lsass at a DLL that does not
# exist on this machine.
if (-not (Get-ItemProperty $cfg -Name PrevAuth0 -ErrorAction SilentlyContinue)) {
    if ($cur) { Set-ItemProperty $cfg -Name PrevAuth0 -Value $cur }
    else      { Set-ItemProperty $cfg -Name PrevAuth0 -Value $noPrev }
}
if (-not (Get-ItemProperty $cfg -Name Mode -ErrorAction SilentlyContinue)) {
    Set-ItemProperty $cfg -Name Mode -Value 1 -Type DWord
}
if (-not (Get-ItemProperty $cfg -Name WindowSec -ErrorAction SilentlyContinue)) {
    Set-ItemProperty $cfg -Name WindowSec -Value 300 -Type DWord   # 5 min; filter clamps 30-3600
}

# --- event source ----------------------------------------------------------

$src = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\TheAdminCafe Ristretto'
if (-not (Test-Path $src)) { New-Item $src | Out-Null }
Set-ItemProperty $src -Name EventMessageFile -Value '%SystemRoot%\System32\EventCreate.exe' -Type ExpandString
Set-ItemProperty $src -Name TypesSupported -Value 7 -Type DWord

# --- payload, then the registry switch -------------------------------------
# Order matters: the DLL has to be on disk before Auth0 names it, or the
# next boot looks for a filter that is not there.

Copy-Item $dll "$env:SystemRoot\System32\RistrettoFilter.dll" -Force

# Must sit next to TacProvider.dll: shared state.lock (see README).
Copy-Item $exe 'C:\Program Files\TheAdminCafe\ristretto.exe' -Force

Set-ItemProperty $msvKey -Name Auth0 -Value 'RistrettoFilter'

$shown = if ($cur) { $cur } else { '(none)' }
Write-Host ""
Write-Host "Auth0: '$shown' -> 'RistrettoFilter' (saved for restore). Reboot to load."
Write-Host "Default window is 300 s. Open a gate with: ristretto <user>"
