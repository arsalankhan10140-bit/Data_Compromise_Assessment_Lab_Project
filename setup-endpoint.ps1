#Requires -RunAsAdministrator
<#
.SYNOPSIS
  CA-Lab Phase 2: endpoint visibility for the Windows victim VM (CA-WIN-01).
  Run INSIDE the Windows VM as Administrator. Never run it on the host.

.DESCRIPTION
  1. Installs the Wazuh agent 4.14.10 (manager 192.168.56.10, name CA-WIN-01)
  2. Installs Sysmon with the SwiftOnSecurity low-noise config
  3. Enables PowerShell Script Block and Module logging
  4. Enables 4688 process creation auditing with command line, plus account/group/logon auditing
  5. Adds eventchannel <localfile> entries to the agent ossec.conf
  6. Makes sure Microsoft Defender real-time protection is ON
  7. Restarts the agent and prints a verification summary

  The script is idempotent: it can be run again safely.

.EXAMPLE
  Set-ExecutionPolicy -Scope Process Bypass -Force
  & "\\VBOXSVR\CA-Lab\scripts\setup-endpoint.ps1"
#>
param(
    [string]$ToolsDir    = (Join-Path (Split-Path $PSScriptRoot -Parent) 'tools'),
    [string]$Manager     = '192.168.56.10',
    [string]$AgentName   = 'CA-WIN-01',
    [string]$AgentVersion = '4.14.10'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'   # progress bars fail in non-interactive (SSH) sessions
$LogFile = 'C:\CA-Lab-setup-endpoint.log'
Start-Transcript -Path $LogFile -Append | Out-Null

function Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "[OK]   $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
# Run a native exe without touching the console (works over SSH); judge success by exit code, not stderr.
function Native {
    param([string]$Exe, [Parameter(ValueFromRemainingArguments)][string[]]$Rest)
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $out = & $Exe @Rest 2>&1 | Out-String
    $code = $LASTEXITCODE; $ErrorActionPreference = $old
    if ($code -ne 0) { Warn "$([IO.Path]::GetFileName($Exe)) exit $code : $($out.Trim())" }
    return $out
}

# Safety check: refuse to run on anything that does not look like the lab VM
$model = (Get-CimInstance Win32_ComputerSystem).Model
if ($model -notmatch 'VirtualBox') {
    Write-Host "This does not look like a VirtualBox VM (model: $model). Aborting: run this only inside the victim VM." -ForegroundColor Red
    Stop-Transcript | Out-Null
    exit 1
}

$AgentDir  = 'C:\Program Files (x86)\ossec-agent'
$OssecConf = Join-Path $AgentDir 'ossec.conf'
$Msi       = Join-Path $ToolsDir "wazuh-agent\wazuh-agent-$AgentVersion-1.msi"
$Sysmon    = Join-Path $ToolsDir 'sysmon\Sysmon64.exe'
# Prefer the CA-Lab variant (SwiftOnSecurity + LSASS ProcessAccess) when present
$SysmonCfg = Join-Path (Split-Path $ToolsDir -Parent) 'configs\sysmonconfig-ca-lab.xml'
if (-not (Test-Path $SysmonCfg)) { $SysmonCfg = Join-Path $ToolsDir 'sysmon-config\sysmonconfig-export.xml' }

foreach ($f in $Msi, $Sysmon, $SysmonCfg) {
    if (-not (Test-Path $f)) { throw "Missing file: $f  (copy the CA-Lab tools folder into reach of this script)" }
}

# ---------------------------------------------------------------- 0. Network check
Step "Checking connectivity to the Wazuh manager $Manager"
foreach ($p in 1514, 1515) {
    if (Test-NetConnection $Manager -Port $p -InformationLevel Quiet -WarningAction SilentlyContinue) { Ok "Port $p reachable" }
    else { Warn "Port $p NOT reachable. Check that the VM's Adapter 2 is Host-only and the Wazuh VM is running." }
}

# ---------------------------------------------------------------- 1. Wazuh agent
Step "Wazuh agent $AgentVersion"
$svc = Get-Service WazuhSvc -ErrorAction SilentlyContinue
if (-not $svc) {
    $msiArgs = "/i `"$Msi`" /q WAZUH_MANAGER=`"$Manager`" WAZUH_REGISTRATION_SERVER=`"$Manager`" WAZUH_AGENT_NAME=`"$AgentName`" /l*v C:\CA-Lab-wazuh-agent-msi.log"
    $p = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "Wazuh agent MSI failed with exit code $($p.ExitCode). See C:\CA-Lab-wazuh-agent-msi.log" }
    Ok "Agent installed"
} else {
    Ok "Agent already installed (service WazuhSvc present), skipping MSI"
}

# ---------------------------------------------------------------- 2. Sysmon
Step "Sysmon (SwiftOnSecurity config)"
if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
    Native $Sysmon -accepteula -c $SysmonCfg | Out-Null
    Ok "Sysmon already installed, config updated"
} else {
    Native $Sysmon -accepteula -i $SysmonCfg | Out-Null
    Ok "Sysmon installed"
}
# Give the Sysmon log room (64 MB)
Native wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:67108864 | Out-Null

# ---------------------------------------------------------------- 3. PowerShell logging
Step "PowerShell Script Block + Module logging"
$psBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
New-Item -Path "$psBase\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty "$psBase\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -Type DWord
New-Item -Path "$psBase\ModuleLogging\ModuleNames" -Force | Out-Null
Set-ItemProperty "$psBase\ModuleLogging" -Name EnableModuleLogging -Value 1 -Type DWord
Set-ItemProperty "$psBase\ModuleLogging\ModuleNames" -Name '*' -Value '*' -Type String
Native wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:67108864 | Out-Null
Ok "Script Block logging (EID 4104) and Module logging (EID 4103) enabled"

# ---------------------------------------------------------------- 4. Audit policy
Step "Audit policy (4688 with command line, accounts, groups, logons)"
# Subcategory GUIDs are language-independent
$audit = [ordered]@{
    'Process Creation (4688)'          = '{0CCE922B-69AE-11D9-BED3-505054503030}'
    'User Account Management (4720)'   = '{0CCE9235-69AE-11D9-BED3-505054503030}'
    'Security Group Management (4732)' = '{0CCE9237-69AE-11D9-BED3-505054503030}'
    'Logon (4624/4625)'                = '{0CCE9215-69AE-11D9-BED3-505054503030}'
    'Other Object Access (4698 tasks)' = '{0CCE9227-69AE-11D9-BED3-505054503030}'
}
foreach ($k in $audit.Keys) {
    Native auditpol /set "/subcategory:$($audit[$k])" /success:enable /failure:enable | Out-Null
    Ok $k
}
$sysPol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item -Path $sysPol -Force | Out-Null
Set-ItemProperty $sysPol -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
Ok "Command line included in 4688"
# 1102 (log cleared) is always logged, no setting needed. Bigger Security log (128 MB):
Native wevtutil sl Security /ms:134217728 | Out-Null

# ---------------------------------------------------------------- 5. Agent log collection
Step "Wazuh agent <localfile> eventchannel entries"
$channels = @(
    'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-PowerShell/Operational',
    'Security',
    'System'
)
$conf = Get-Content $OssecConf -Raw
Copy-Item $OssecConf "$OssecConf.ca-lab.bak" -Force
$added = @()
foreach ($ch in $channels) {
    if ($conf -match "<location>$([regex]::Escape($ch))</location>") { Ok "Already present: $ch"; continue }
    $block = "  <!-- CA-Lab -->`r`n  <localfile>`r`n    <location>$ch</location>`r`n    <log_format>eventchannel</log_format>`r`n  </localfile>`r`n"
    $idx = $conf.LastIndexOf('</ossec_config>')
    $conf = $conf.Insert($idx, $block)
    $added += $ch
}
if ($added) {
    [IO.File]::WriteAllText($OssecConf, $conf, (New-Object Text.UTF8Encoding $false))
    $added | ForEach-Object { Ok "Added: $_" }
}
# Sanity check: the file must still be valid XML when wrapped (Wazuh allows several root blocks)
try { [xml]("<root>" + ((Get-Content $OssecConf -Raw) -replace '<\?xml[^>]*\?>','') + "</root>") | Out-Null; Ok "ossec.conf parses as XML" }
catch { Warn "ossec.conf XML check failed, restoring backup: $($_.Exception.Message)"; Copy-Item "$OssecConf.ca-lab.bak" $OssecConf -Force }

# ---------------------------------------------------------------- 6. Defender
Step "Microsoft Defender real-time protection"
try {
    $mp = Get-MpComputerStatus
    if (-not $mp.RealTimeProtectionEnabled) {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Start-Sleep 3
        $mp = Get-MpComputerStatus
    }
    Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -ErrorAction SilentlyContinue
    if ($mp.RealTimeProtectionEnabled) { Ok "Real-time protection ON (engine $($mp.AMEngineVersion), signatures $($mp.AntivirusSignatureVersion))" }
    else { Warn "Real-time protection is still OFF. Open Windows Security > Virus & threat protection and turn it on." }
    if ($mp.IsTamperProtected) { Ok "Tamper protection ON" }
} catch { Warn "Could not query Defender: $($_.Exception.Message)" }

# ---------------------------------------------------------------- 7. Restart and verify
Step "Restarting Wazuh agent"
Restart-Service WazuhSvc -Force
Start-Sleep 15

Step "VERIFICATION"
$state = Get-Content (Join-Path $AgentDir 'wazuh-agent.state') -ErrorAction SilentlyContinue | Select-String "^status="
$rows = @(
    [pscustomobject]@{Check='WazuhSvc service';      Result=(Get-Service WazuhSvc).Status}
    [pscustomobject]@{Check='Agent connection';      Result=$(if($state){$state.Line}else{'unknown (state file not written yet)'})}
    [pscustomobject]@{Check='Sysmon64 service';      Result=(Get-Service Sysmon64 -ErrorAction SilentlyContinue).Status}
    [pscustomobject]@{Check='Sysmon events present'; Result=[bool](Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -ErrorAction SilentlyContinue)}
    [pscustomobject]@{Check='ScriptBlockLogging';    Result=(Get-ItemProperty "$psBase\ScriptBlockLogging").EnableScriptBlockLogging}
    [pscustomobject]@{Check='ModuleLogging';         Result=(Get-ItemProperty "$psBase\ModuleLogging").EnableModuleLogging}
    [pscustomobject]@{Check='4688 cmdline';          Result=(Get-ItemProperty $sysPol).ProcessCreationIncludeCmdLine_Enabled}
    [pscustomobject]@{Check='Defender real-time';    Result=(Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled}
)
$rows | Format-Table -AutoSize
Write-Host "auditpol Process Creation:" ; Native auditpol /get "/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}" | Write-Host
Write-Host "`nLast agent log lines:"
Get-Content (Join-Path $AgentDir 'ossec.log') -Tail 8

Write-Host "`nDone. Full log: $LogFile" -ForegroundColor Cyan
Write-Host "NEXT: shut the VM down and take the VirtualBox snapshot 'Clean Baseline'." -ForegroundColor Yellow
Stop-Transcript | Out-Null
