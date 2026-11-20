#Requires -RunAsAdministrator
<#
  CA-Lab Phase 4 prep: install the Invoke-AtomicRedTeam framework + atomics INSIDE CA-WIN-01 only.
  Source: official Red Canary repos (github.com/redcanaryco). Installs to C:\AtomicRedTeam.
  No tests are executed by this script.
#>
$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'
if ((Get-CimInstance Win32_ComputerSystem).Model -notmatch 'VirtualBox') { Write-Host 'Not the lab VM - abort'; exit 1 }
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'

if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue)) {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
}
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
if (-not (Get-Module -ListAvailable powershell-yaml)) { Install-Module powershell-yaml -Scope AllUsers -Force }

if (-not (Test-Path 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1')) {
    $inst = Invoke-WebRequest 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing
    Invoke-Expression $inst.Content
    Install-AtomicRedTeam -getAtomics -Force
}
Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force
"Invoke-AtomicRedTeam version: " + (Get-Module Invoke-AtomicRedTeam).Version
"Atomics folder present: " + (Test-Path 'C:\AtomicRedTeam\atomics')
foreach ($t in 'T1059.001','T1003.001','T1053.005','T1547.001','T1136.001','T1562.001','T1105','T1218.011') {
    "{0}: yaml present = {1}" -f $t, (Test-Path "C:\AtomicRedTeam\atomics\$t\$t.yaml")
}
