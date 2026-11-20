#Requires -RunAsAdministrator
<#
  CA-Lab Phase 3 LIVE rule validation (benign). Run INSIDE CA-WIN-01 only.
  Each step produces the real telemetry a CA-Lab rule should catch, then cleans up.
  Nothing here downloads or runs malware: URLs point to 127.0.0.1, "IOC" IP/domain are documentation
  ranges / .example, EICAR is the industry-standard AV test string.
  Revert afterwards: VirtualBox snapshot "Clean Baseline v2".
#>
$ErrorActionPreference = 'Continue'; $ProgressPreference = 'SilentlyContinue'
if ((Get-CimInstance Win32_ComputerSystem).Model -notmatch 'VirtualBox') { Write-Host 'Not the lab VM - abort'; exit 1 }
function T($id, $what) { Write-Host ("[{0}] {1}  {2}" -f (Get-Date -Format 'HH:mm:ss'), $id, $what) }
function Q { param([string]$exe, [string[]]$a) & $exe @a 2>&1 | Out-Null }   # run native quietly (SSH-safe)
$pub = 'C:\Users\Public'

T 100120 'Encoded PowerShell (benign Write-Output)'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output 'CA-Lab encoded test'"))
Q powershell.exe @('-NoProfile', '-enc', $enc)

T '100121/100122' 'IEX + FromBase64String in command line / script block (no download)'
Q powershell.exe @('-NoProfile', '-Command', "IEX ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('$enc')))")

T '100130/100131' 'Scheduled task create + delete'
Q schtasks.exe @('/create', '/tn', 'CA-Lab-RuleTest', '/tr', 'cmd.exe /c echo calab', '/sc', 'once', '/st', '23:59', '/f')
Start-Sleep 2
Q schtasks.exe @('/delete', '/tn', 'CA-Lab-RuleTest', '/f')

T 100140 'Run-key value add + delete (HKCU)'
Q reg.exe @('add', 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run', '/v', 'CALabRuleTest', '/t', 'REG_SZ', '/d', 'C:\Windows\System32\cmd.exe /c echo calab', '/f')
Start-Sleep 2
Q reg.exe @('delete', 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run', '/v', 'CALabRuleTest', '/f')

T 100150 'certutil -urlcache to 127.0.0.1 (nothing listening)'
Q certutil.exe @('-urlcache', '-split', '-f', 'http://127.0.0.1:9/calab.txt', "$pub\calab-cu.txt")

T 100151 'certutil -decode of a benign base64 file'
Set-Content "$pub\calab-b64.txt" ([Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('calab'))) -Encoding ascii
Q certutil.exe @('-decode', "$pub\calab-b64.txt", "$pub\calab-dec.txt")
Remove-Item "$pub\calab-b64.txt", "$pub\calab-dec.txt", "$pub\calab-cu.txt" -ErrorAction SilentlyContinue

T 100152 'bitsadmin job with /addfile to 127.0.0.1, then cancel'
Q bitsadmin.exe @('/create', 'calabtest')
Q bitsadmin.exe @('/addfile', 'calabtest', 'http://127.0.0.1:9/calab.txt', "$pub\calab-bits.txt")
Q bitsadmin.exe @('/cancel', 'calabtest')

T 100153 'rundll32 pointing at a non-existent DLL in C:\Users\Public'
# rundll32 shows a modal error box for a missing DLL; with no desktop (SSH) it would hang, so kill it after 3 s
$p = Start-Process rundll32.exe -ArgumentList "$pub\calab-none.dat,Start" -PassThru -WindowStyle Hidden
Start-Sleep 3; if (-not $p.HasExited) { $p | Stop-Process -Force }

T 100155 'Defender-tamper string in a command line (echo only, no change made)'
Q powershell.exe @('-NoProfile', '-Command', "Write-Output 'Add-MpPreference -ExclusionPath C:\calab-none'")

T '100156/100160' 'Local test user create'
Q net.exe @('user', 'calab_test', 'CaLab!Tmp2026', '/add')
T '100157/100161' 'Add test user to Administrators'
Q net.exe @('localgroup', 'administrators', 'calab_test', '/add')
Start-Sleep 2
Q net.exe @('user', 'calab_test', '/delete')

T 100110 'Open LSASS with 0x1010 (query-limited + VM read), then close; nothing is read'
Add-Type -Namespace CALab -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true)] public static extern System.IntPtr OpenProcess(int a, bool i, int p);
[DllImport("kernel32.dll")] public static extern bool CloseHandle(System.IntPtr h);
'@
$h = [CALab.Native]::OpenProcess(0x1010, $false, (Get-Process lsass).Id)
"    handle opened: $($h -ne [IntPtr]::Zero)"; if ($h -ne [IntPtr]::Zero) { [void][CALab.Native]::CloseHandle($h) }

T 100172 'DNS query for IOC test domain (NXDOMAIN)'
Resolve-DnsName evil-c2.example -ErrorAction SilentlyContinue | Out-Null

T 100171 'TCP connect attempt to IOC test IP 203.0.113.66:443 (TEST-NET, unroutable)'
try { $c = New-Object Net.Sockets.TcpClient; $c.BeginConnect('203.0.113.66', 443, $null, $null) | Out-Null; Start-Sleep 3; $c.Close() } catch {}

T 100170 'FIM: write benign IOC test file (hash is in ca-ioc-hashes)'
[IO.File]::WriteAllBytes('C:\CA-IOC-Test\calab-ioc-test.txt', [Text.Encoding]::ASCII.GetBytes('CA-Lab benign IOC test file - not malware'))

T '100103/100104' 'Defender exclusion add + remove (5007)'
Add-MpPreference -ExclusionPath 'C:\CALab-Excl-Test' -ErrorAction SilentlyContinue
Start-Sleep 3
Remove-MpPreference -ExclusionPath 'C:\CALab-Excl-Test' -ErrorAction SilentlyContinue

T '100100/100101' 'EICAR test string -> Defender 1116/1117'
$e1 = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$'; $e2 = 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
try { [IO.File]::WriteAllText("$pub\calab-eicar.com", $e1 + $e2) } catch { "    write blocked by Defender (expected)" }
Start-Sleep 8
"    EICAR still on disk: " + (Test-Path "$pub\calab-eicar.com")

T 100162 'Clear Security log (1102) - LAST step'
Q wevtutil.exe @('cl', 'Security')

T done 'All steps finished'
