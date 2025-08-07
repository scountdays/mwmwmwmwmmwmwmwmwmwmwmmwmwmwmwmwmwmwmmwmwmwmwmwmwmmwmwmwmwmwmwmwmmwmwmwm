Set objShell = CreateObject("WScript.Shell")

objShell.Run "sc config WinDefend start= auto", 0, True
objShell.Run "sc start WinDefend", 0, True

objShell.Run "reg add ""HKLM\Software\Policies\Microsoft\Windows Defender"" /v ""DisableAntiSpyware"" /t REG_DWORD /d 0 /f", 0, True
objShell.Run "reg add ""HKLM\Software\Policies\Microsoft\Windows Defender"" /v ""DisableRealtimeMonitoring"" /t REG_DWORD /d 0 /f", 0, True
objShell.Run "reg add ""HKLM\Software\Policies\Microsoft\Windows Defender"" /v ""DisableBehaviorMonitoring"" /t REG_DWORD /d 0 /f", 0, True
objShell.Run "reg add ""HKLM\Software\Policies\Microsoft\Windows Defender"" /v ""DisableScanOnRealtimeEnable"" /t REG_DWORD /d 0 /f", 0, True

objShell.Run "powershell -Command ""Set-MpPreference -DisableRealtimeMonitoring $false""", 0, True
objShell.Run "powershell -Command ""Set-MpPreference -DisableBehaviorMonitoring $false""", 0, True
objShell.Run "powershell -Command ""Set-MpPreference -DisableIOAVProtection $false""", 0, True
objShell.Run "powershell -Command ""Set-MpPreference -DisablePrivacyMode $false""", 0, True

objShell.Run "reg add ""HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService"" /v ""Start"" /t REG_DWORD /d 2 /f", 0, True
objShell.Run "reg add ""HKLM\SYSTEM\CurrentControlSet\Services\Sense"" /v ""Start"" /t REG_DWORD /d 2 /f", 0, True

objShell.Run "schtasks /Change /TN ""Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"" /Enable", 0, True
objShell.Run "schtasks /Change /TN ""Microsoft\Windows\Windows Defender\Windows Defender Cleanup"" /Enable", 0, True
objShell.Run "schtasks /Change /TN ""Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"" /Enable", 0, True
objShell.Run "schtasks /Change /TN ""Microsoft\Windows\Windows Defender\Windows Defender Verification"" /Enable", 0, True
