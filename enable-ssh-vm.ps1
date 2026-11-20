#Requires -RunAsAdministrator
<#
  CA-Lab: enable OpenSSH Server INSIDE the Windows victim VM (CA-WIN-01), key-only login,
  so the lab operator (Claude on the host) can run the setup and tests over SSH.
  Run once inside the VM, in an Administrator PowerShell:
     Set-ExecutionPolicy -Scope Process Bypass -Force
     & \\VBOXSVR\CA-Lab\scripts\enable-ssh-vm.ps1
  Undo: Stop-Service sshd; Set-Service sshd -StartupType Disabled
#>
$ErrorActionPreference = 'Stop'

if ((Get-CimInstance Win32_ComputerSystem).Model -notmatch 'VirtualBox') {
    Write-Host "Not a VirtualBox VM - aborting. Run this only inside CA-WIN-01." -ForegroundColor Red; exit 1
}

$PubKey = 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKB+lWUf6MZib8IQIHKNIlA3Ee4mgZI1zgm8/ZQx3Fz5Qk6qfD3+I0o8xpFJhER++klRzFtn91X9AiKtlCtTLkc= ca-lab'

Write-Host "[1] Installing OpenSSH Server (needs internet via NAT, 1-5 min)..." -ForegroundColor Cyan
$cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*'
if ($cap.State -ne 'Installed') { Add-WindowsCapability -Online -Name $cap.Name | Out-Null }

Write-Host "[2] Starting sshd (automatic start)" -ForegroundColor Cyan
Set-Service sshd -StartupType Automatic
Start-Service sshd

Write-Host "[3] Authorizing the CA-Lab key for administrators" -ForegroundColor Cyan
$ak = 'C:\ProgramData\ssh\administrators_authorized_keys'
if (-not (Test-Path $ak) -or -not (Select-String -Path $ak -SimpleMatch $PubKey -Quiet)) {
    Add-Content -Path $ak -Value $PubKey -Encoding ascii
}
icacls $ak /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null

Write-Host "[4] Key-only login (password login over SSH disabled)" -ForegroundColor Cyan
$cfg = 'C:\ProgramData\ssh\sshd_config'
$c = Get-Content $cfg -Raw
if ($c -notmatch '(?m)^PasswordAuthentication no') { $c = "PasswordAuthentication no`r`n" + $c }
Set-Content $cfg $c -Encoding ascii
New-ItemProperty 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force | Out-Null
Restart-Service sshd

Write-Host "[5] Firewall rule for TCP 22" -ForegroundColor Cyan
if (-not (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
}

Write-Host "`nDONE. sshd: $((Get-Service sshd).Status)   user: $env:USERNAME" -ForegroundColor Green
Write-Host "Tell Claude: 'SSH ready'." -ForegroundColor Green
