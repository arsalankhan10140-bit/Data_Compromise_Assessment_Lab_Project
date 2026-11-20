@echo off
REM CA-Lab: let VirtualBox use VT-x directly (turns off "turtle/snail" mode).
REM Run on the HOST: right-click this file and choose "Run as administrator", then restart.
REM Undo later: bcdedit /set hypervisorlaunchtype auto  (and turn Memory integrity back on).

net session >nul 2>&1
if errorlevel 1 (
  echo.
  echo  ERROR: not running as administrator.
  echo  Right-click this file and choose "Run as administrator".
  echo.
  pause
  exit /b 1
)

echo [1] Hypervisor launch at boot: OFF
bcdedit /set hypervisorlaunchtype off

echo [2] VBS / Memory integrity / Windows Hello enhanced sign-in: OFF
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\WindowsHello" /v Enabled /t REG_DWORD /d 0 /f

echo [3] Windows features that start the hypervisor: OFF (errors for features that are not installed are OK)
dism /online /disable-feature /featurename:VirtualMachinePlatform /norestart /quiet
dism /online /disable-feature /featurename:HypervisorPlatform /norestart /quiet
dism /online /disable-feature /featurename:Microsoft-Hyper-V-All /norestart /quiet
dism /online /disable-feature /featurename:Containers-DisposableClientVM /norestart /quiet

echo.
echo ===== VERIFY: the line below must say "hypervisorlaunchtype    Off" =====
bcdedit /enum {current} | findstr /i hypervisorlaunchtype
echo.
echo Done. Close this window and RESTART the laptop.
pause
