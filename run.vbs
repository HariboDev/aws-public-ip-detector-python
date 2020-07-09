Set WshShell = CreateObject("WScript.Shell") 
WshShell.Run python & chr(34) & "run.bat" & Chr(34), 0
Set WshShell = Nothing