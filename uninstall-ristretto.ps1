#requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$msvKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
$cfg    = 'HKLM:\SOFTWARE\TheAdminCafe\Ristretto'
$src    = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\TheAdminCafe Ristretto'
$noPrev = '__none__'

$cur  = (Get-ItemProperty $msvKey -Name Auth0 -ErrorAction SilentlyContinue).Auth0
$prev = (Get-ItemProperty $cfg -Name PrevAuth0 -ErrorAction SilentlyContinue).PrevAuth0

# An older install-ristretto.ps1 recorded its own name when it ran twice.
# Restoring that would leave Ristretto registered, so stop before anything
# changes and say how to fix the record.
if ($prev -eq 'RistrettoFilter') {
    throw "PrevAuth0 under $cfg is 'RistrettoFilter', left by an older install-ristretto.ps1. Set it to what Auth0 was before Ristretto ('TacSubAuth' for Doppio's filter, '$noPrev' for none) and run this again. Nothing was changed."
}

# Restore Auth0 first: if anything below fails, the machine is already back
# on its original filter rather than half-uninstalled. Only touch it while it
# is still ours: if somebody gave the slot to another filter after the
# install, overwriting it with the old value would undo their change.
if ($cur -ne 'RistrettoFilter') {
    $shown = if ($cur) { "'$cur'" } else { '(none)' }
    Write-Warning "Auth0 is $shown, not 'RistrettoFilter'. Left as it is."
    $restored = "$shown (unchanged)"
} elseif ($prev -and $prev -ne $noPrev) {
    Set-ItemProperty $msvKey -Name Auth0 -Value $prev
    $restored = "'$prev'"
} else {
    # Either we recorded "there was nothing here", or the marker is gone.
    # Removing the value is the safe answer - a dangling Auth0 pointing at a
    # DLL that is not on disk is worse than no Auth0 at all.
    Remove-ItemProperty $msvKey -Name Auth0 -ErrorAction SilentlyContinue
    $restored = '(none, value removed)'
}

# Drop any open gates so a later reinstall cannot find a stale timestamp
# still inside its window.
Remove-Item "$cfg\Gate" -Recurse -Force -ErrorAction SilentlyContinue

# Clear the restore marker so a reinstall records the real previous state
# instead of reusing ours.
Remove-ItemProperty $cfg -Name PrevAuth0 -ErrorAction SilentlyContinue

Remove-Item $src -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item 'C:\Program Files\TheAdminCafe\ristretto.exe' -Force -ErrorAction SilentlyContinue

Write-Host "Auth0: $restored. Open gates cleared."
Write-Host "Reboot, THEN delete $env:SystemRoot\System32\RistrettoFilter.dll"
Write-Host "(lsass holds the DLL until the machine restarts)."
