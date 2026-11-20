#Requires -RunAsAdministrator
# CA-Lab: install ONLY the Invoke-AtomicRedTeam framework (no full atomics zip). VM only.
$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'
if ((Get-CimInstance Win32_ComputerSystem).Model -notmatch 'VirtualBox') { Write-Host 'Not the lab VM'; exit 1 }
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue)) {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
}
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
if (-not (Get-Module -ListAvailable powershell-yaml)) { Install-Module powershell-yaml -Scope AllUsers -Force }
if (-not (Test-Path 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1')) {
    IEX (Invoke-WebRequest 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing).Content
    Install-AtomicRedTeam -Force   # framework only, NOT -getAtomics
}
New-Item -ItemType Directory -Force 'C:\AtomicRedTeam\atomics' | Out-Null
'Framework present: ' + (Test-Path 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1')
