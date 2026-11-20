#Requires -RunAsAdministrator
<#
  CA-Lab Phase 4: run a curated, benign subset of Atomic Red Team tests INSIDE CA-WIN-01 only.
  One test per technique, each with prerequisites already met (no external attack tools downloaded).
  Flow per test: -CheckPrereqs, execute, -Cleanup. A UTC marker is printed before each so the
  manager alerts can be correlated by time. Nothing here targets the host; the VM is isolated
  (host-only + NAT) and gets reverted to snapshot "Clean Baseline v2" afterwards.

  Run over SSH:
    ssh ca-win powershell -NoProfile -ExecutionPolicy Bypass -File \\VBOXSVR\CA-Lab\scripts\run-atomics.ps1
#>
$ErrorActionPreference = 'Continue'; $ProgressPreference = 'SilentlyContinue'
if ((Get-CimInstance Win32_ComputerSystem).Model -notmatch 'VirtualBox') { Write-Host 'Not the lab VM - abort'; exit 1 }
Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force
$atomics = 'C:\AtomicRedTeam\atomics'

# technique = test number, each prereq already met in the preview
$tests = [ordered]@{
  'T1059.001' = '17'   # PowerShell Command Execution        -> 100120/100122
  'T1003.001' = '2'    # LSASS dump via comsvcs.dll          -> 100154/100111 (+ built-in 92900)
  'T1053.005' = '2'    # Scheduled task (Local)              -> 100130/100131
  'T1547.001' = '1'    # Reg Key Run                         -> 100140/100141
  'T1136.001' = '4'    # Create a new user (cmd)             -> 100156/100160
  'T1105'     = '9'    # BITSAdmin BITS Download             -> 100152
  'T1218.011' = '9'    # Rundll32 + pcwutl.dll launches exe  -> 100153
}

Write-Host ("CA-LAB-ATOMICS-START {0}" -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')) -ForegroundColor Cyan

foreach ($tech in $tests.Keys) {
  $num = $tests[$tech]
  Write-Host ("`n##### {0} test {1}  UTC {2} #####" -f $tech, $num, (Get-Date).ToUniversalTime().ToString('HH:mm:ss')) -ForegroundColor Cyan
  Invoke-AtomicTest $tech -TestNumbers $num -PathToAtomicsFolder $atomics -CheckPrereqs 2>&1 | Out-String -Width 160 | Write-Host
  Write-Host "  -- executing --"
  Invoke-AtomicTest $tech -TestNumbers $num -PathToAtomicsFolder $atomics -TimeoutSeconds 60 2>&1 | Out-String -Width 160 | Write-Host
  Start-Sleep 3
  Invoke-AtomicTest $tech -TestNumbers $num -PathToAtomicsFolder $atomics -Cleanup 2>&1 | Out-String -Width 160 | Write-Host
  Start-Sleep 15   # let the agent event queue drain between techniques (CA-Lab Phase 4)
}

# T1562.001 (atomic folder not in repo): benign custom equivalent - add + remove a Defender exclusion (5007 -> 100104)
Write-Host ("`n##### T1562.001 custom  UTC {0} #####" -f (Get-Date).ToUniversalTime().ToString('HH:mm:ss')) -ForegroundColor Cyan
Add-MpPreference -ExclusionPath 'C:\CALab-Atomic-Excl' -ErrorAction SilentlyContinue
Start-Sleep 3
Remove-MpPreference -ExclusionPath 'C:\CALab-Atomic-Excl' -ErrorAction SilentlyContinue
Write-Host "  Defender exclusion added and removed (benign)"

Write-Host ("`nCA-LAB-ATOMICS-END {0}" -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')) -ForegroundColor Cyan
