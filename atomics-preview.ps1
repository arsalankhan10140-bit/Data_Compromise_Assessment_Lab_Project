#Requires -RunAsAdministrator
<#
  CA-Lab Phase 4: PREVIEW ONLY. Lists the Windows tests for each technique and checks prerequisites.
  Does NOT execute any test (-ShowDetailsBrief and -CheckPrereqs are read-only).
#>
param([string]$Techniques = 'T1059.001,T1003.001,T1053.005,T1547.001,T1136.001,T1105,T1218.011')
$ErrorActionPreference = 'Continue'; $ProgressPreference = 'SilentlyContinue'
if ((Get-CimInstance Win32_ComputerSystem).Model -notmatch 'VirtualBox') { Write-Host 'Not the lab VM - abort'; exit 1 }
Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force
$PSDefaultParameterValues['Invoke-AtomicTest:PathToAtomicsFolder'] = 'C:\AtomicRedTeam\atomics'

foreach ($t in ($Techniques -split ',')) {
    Write-Host "`n===== $t =====" -ForegroundColor Cyan
    Invoke-AtomicTest $t -ShowDetailsBrief 2>&1 | Out-String -Width 200 | Write-Host
    Write-Host "--- prereqs ---"
    Invoke-AtomicTest $t -CheckPrereqs 2>&1 | Out-String -Width 200 |
        ForEach-Object { $_ -split "`n" } | Where-Object { $_ -match 'Prerequisites|Test Number|met|not' } | Write-Host
}
