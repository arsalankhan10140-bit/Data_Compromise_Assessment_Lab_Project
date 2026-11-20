#Requires -RunAsAdministrator
# CA-Lab Phase 3 re-test of the rules that were shadowed/lost in round 1 (benign). Run INSIDE CA-WIN-01 only.
# No Security-log clearing here, so 4720/4732 can reach the agent.
$ErrorActionPreference = 'Continue'; $ProgressPreference = 'SilentlyContinue'
if ((Get-CimInstance Win32_ComputerSystem).Model -notmatch 'VirtualBox') { Write-Host 'Not the lab VM - abort'; exit 1 }
function T($id, $what) { Write-Host ("[{0}] {1}  {2}" -f (Get-Date -Format 'HH:mm:ss'), $id, $what) }
function Q { param([string]$exe, [string[]]$a) & $exe @a 2>&1 | Out-Null }

T '100110/100111' 'Open LSASS with 0x1010, then close (nothing is read)'
Add-Type -Namespace CALab2 -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true)] public static extern System.IntPtr OpenProcess(int a, bool i, int p);
[DllImport("kernel32.dll")] public static extern bool CloseHandle(System.IntPtr h);
'@
$h = [CALab2.Native]::OpenProcess(0x1010, $false, (Get-Process lsass).Id)
if ($h -ne [IntPtr]::Zero) { [void][CALab2.Native]::CloseHandle($h) }

T '100140/100141' 'Run-key value add + delete (HKCU)'
Q reg.exe @('add', 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run', '/v', 'CALabRuleTest2', '/t', 'REG_SZ', '/d', 'C:\Windows\System32\cmd.exe /c echo calab', '/f')
Start-Sleep 2
Q reg.exe @('delete', 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run', '/v', 'CALabRuleTest2', '/f')

T '100160/100161' 'Local test user create + add to Administrators (Security 4720/4732)'
Q net.exe @('user', 'calab_test2', 'CaLab!Tmp2026', '/add')
Q net.exe @('localgroup', 'administrators', 'calab_test2', '/add')
Start-Sleep 20
Q net.exe @('user', 'calab_test2', '/delete')

T 100170 'FIM: re-create benign IOC test file (delete + write -> 553/554)'
Remove-Item 'C:\CA-IOC-Test\calab-ioc-test.txt' -ErrorAction SilentlyContinue
Start-Sleep 3
[IO.File]::WriteAllBytes('C:\CA-IOC-Test\calab-ioc-test2.txt', [Text.Encoding]::ASCII.GetBytes('CA-Lab benign IOC test file - not malware'))

T done 'Re-test finished'
