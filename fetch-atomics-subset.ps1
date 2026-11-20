#Requires -RunAsAdministrator
<#
  CA-Lab Phase 4: fetch ONLY the needed technique folders from the official atomic-red-team repo
  (github.com/redcanaryco/atomic-red-team, branch master) into C:\AtomicRedTeam\atomics, inside CA-WIN-01.
  Used instead of the full ~300 MB zip (too slow over the VM's NAT link). Nothing is executed.
#>
param([string[]]$Techniques = @('T1059.001','T1003.001','T1053.005','T1547.001','T1136.001','T1562.001','T1105','T1218.011'))
$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'
if ((Get-CimInstance Win32_ComputerSystem).Model -notmatch 'VirtualBox') { Write-Host 'Not the lab VM - abort'; exit 1 }
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
$Techniques = $Techniques -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }   # works with -File over SSH
$api = 'https://api.github.com/repos/redcanaryco/atomic-red-team/contents'
$hdr = @{ 'User-Agent' = 'ca-lab-fetch' }
$root = 'C:\AtomicRedTeam'

function Get-Folder([string]$repoPath) {
    try { $items = Invoke-RestMethod "$api/$repoPath`?ref=master" -Headers $hdr }
    catch { Write-Host "    API error for $repoPath : $($_.Exception.Message)" -ForegroundColor Yellow; return }
    foreach ($it in $items) {
        $local = Join-Path $root ($it.path -replace '/', '\')
        if ($it.type -eq 'dir') { New-Item -ItemType Directory -Force $local | Out-Null; Get-Folder $it.path }
        elseif ($it.type -eq 'file' -and $it.path -notmatch '\.md$') {
            New-Item -ItemType Directory -Force (Split-Path $local) | Out-Null
            try { Invoke-WebRequest $it.download_url -OutFile $local -UseBasicParsing -Headers $hdr }
            catch { Write-Host "    skipped (likely Defender/AV or network): $($it.path)" -ForegroundColor Yellow }
        }
    }
}

foreach ($t in $Techniques) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Get-Folder "atomics/$t"
    $n = @(Get-ChildItem "$root\atomics\$t" -Recurse -File -ErrorAction SilentlyContinue).Count
    "{0,-10} files={1,-3} yaml={2} ({3:N0}s)" -f $t, $n, (Test-Path "$root\atomics\$t\$t.yaml"), $sw.Elapsed.TotalSeconds
}
Import-Module "$root\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
"Invoke-AtomicRedTeam module loaded: " + [bool](Get-Module Invoke-AtomicRedTeam)
