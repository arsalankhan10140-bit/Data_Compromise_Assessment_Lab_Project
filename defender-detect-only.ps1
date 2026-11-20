#Requires -RunAsAdministrator
<#
  CA-Lab Phase 4: put Microsoft Defender in DETECT-ONLY mode inside CA-WIN-01 (lab VM only).
  - Real-time protection stays ON, so detections (1116) are still logged and shipped to Wazuh.
  - Remediation action for all severities = Allow  -> no quarantine/delete/block of files.
  - Common ASR rules set to AuditMode (event 1122) instead of Block (1121).
  Needs Tamper Protection OFF (GUI). Undo: -Mode Restore (or revert snapshot "Clean Baseline v2").
#>
param([ValidateSet('DetectOnly','Restore','Status')][string]$Mode = 'Status')
$ErrorActionPreference = 'Continue'; $ProgressPreference = 'SilentlyContinue'
if ((Get-CimInstance Win32_ComputerSystem).Model -notmatch 'VirtualBox') { Write-Host 'Not the lab VM - abort'; exit 1 }

# ASR rule GUIDs (Microsoft documented)
$asr = @{
  'Block credential stealing from LSASS'                    = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
  'Block executable content from email/webmail'             = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'
  'Block Office apps creating child processes'              = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'
  'Block obfuscated scripts'                                = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'
  'Block JS/VBS launching downloaded content'               = 'd3e037e1-3eb8-44c8-a917-57927947596d'
  'Block process creations from PSExec and WMI'             = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
  'Block persistence through WMI event subscription'        = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'
  'Block untrusted/unsigned processes from USB'             = 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'
  'Use advanced protection against ransomware'              = 'c1db55ab-c21a-4637-bb3f-a12568109d35'
  'Block executable files unless prevalence/age/trusted'    = '01443614-cd74-433a-b99e-2ecdc07bfc25'
}

function Show-Status {
  $s = Get-MpComputerStatus; $p = Get-MpPreference
  [pscustomobject]@{
    RealTimeProtection = $s.RealTimeProtectionEnabled
    TamperProtected    = $s.IsTamperProtected
    LowAction          = $p.LowThreatDefaultAction
    ModerateAction     = $p.ModerateThreatDefaultAction
    HighAction         = $p.HighThreatDefaultAction
    SevereAction       = $p.SevereThreatDefaultAction
    ASR_Audit_Count    = @($p.AttackSurfaceReductionRules_Actions | Where-Object { $_ -eq 2 }).Count
    ASR_Block_Count    = @($p.AttackSurfaceReductionRules_Actions | Where-Object { $_ -eq 1 }).Count
  } | Format-List | Out-String
}

if ($Mode -eq 'Status') { Show-Status; exit 0 }

if ((Get-MpComputerStatus).IsTamperProtected) {
  Write-Host 'Tamper Protection is ON - turn it OFF in Windows Security first.' -ForegroundColor Yellow; Show-Status; exit 1
}

if ($Mode -eq 'DetectOnly') {
  # 6 = Allow. Detection is still logged (1116), no remediation.
  Set-MpPreference -LowThreatDefaultAction Allow -ModerateThreatDefaultAction Allow `
                   -HighThreatDefaultAction Allow -SevereThreatDefaultAction Allow -UnknownThreatDefaultAction Allow
  foreach ($k in $asr.Keys) { Add-MpPreference -AttackSurfaceReductionRules_Ids $asr[$k] -AttackSurfaceReductionRules_Actions AuditMode }
  Write-Host 'Defender set to DETECT-ONLY (Allow + ASR audit).' -ForegroundColor Green
} else {
  Set-MpPreference -LowThreatDefaultAction Clean -ModerateThreatDefaultAction Quarantine `
                   -HighThreatDefaultAction Quarantine -SevereThreatDefaultAction Quarantine -UnknownThreatDefaultAction Quarantine
  foreach ($k in $asr.Keys) { Remove-MpPreference -AttackSurfaceReductionRules_Ids $asr[$k] -ErrorAction SilentlyContinue }
  Write-Host 'Defender restored to default remediation.' -ForegroundColor Green
}
Show-Status
