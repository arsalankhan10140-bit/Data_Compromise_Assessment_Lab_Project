# CA-Lab Phase 3, VM side: apply the lab Sysmon config and prepare the FIM IOC test folder.
# Run inside CA-WIN-01 as admin (over SSH). Idempotent.
$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'
if ((Get-CimInstance Win32_ComputerSystem).Model -notmatch 'VirtualBox') { throw 'Not the lab VM' }

$cfg = '\\VBOXSVR\CA-Lab\configs\sysmonconfig-ca-lab.xml'
$old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
$out = & '\\VBOXSVR\CA-Lab\tools\sysmon\Sysmon64.exe' -accepteula -c $cfg 2>&1 | Out-String
$ErrorActionPreference = $old
"Sysmon config update exit=$LASTEXITCODE"
($out -split "`n" | Select-String 'updated|error|Configuration' | Select -First 3) -join "`n"

New-Item -ItemType Directory -Force C:\CA-IOC-Test | Out-Null
"C:\CA-IOC-Test ready"

$agent = 'C:\Program Files (x86)\ossec-agent'
$merged = Join-Path $agent 'shared\merged.mg'
"agent.conf received: " + [bool](Select-String -Path $merged -Pattern 'CA-IOC-Test' -Quiet -ErrorAction SilentlyContinue)
Restart-Service WazuhSvc -Force
Start-Sleep 20
"Agent: " + ((Get-Content "$agent\wazuh-agent.state" | Select-String '^status=').Line)
"--- FIM / SCA / syscollector lines in ossec.log ---"
Get-Content "$agent\ossec.log" -Tail 60 | Select-String 'syscheck|sca|syscollector|rootcheck|realtime|CA-IOC|ERROR|WARN' | Select -Last 12 | % { $_.Line.Substring(0, [Math]::Min(200, $_.Line.Length)) }
