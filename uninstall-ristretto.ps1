#requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$msvKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
$cfg    = 'HKLM:\SOFTWARE\TheAdminCafe\Ristretto'
$src    = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\TheAdminCafe Ristretto'
$noPrev = '__none__'

# Restore Auth0 first: if anything below fails, the machine is already back
# on its original filter rather than half-uninstalled.
$prev = (Get-ItemProperty $cfg -Name PrevAuth0 -ErrorAction SilentlyContinue).PrevAuth0

if ($prev -and $prev -ne $noPrev) {
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

Write-Host "Auth0 restored to $restored. Open gates cleared."
Write-Host "Reboot, THEN delete $env:SystemRoot\System32\RistrettoFilter.dll"
Write-Host "(lsass holds the DLL until the machine restarts)."
