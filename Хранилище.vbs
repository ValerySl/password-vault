' Starts the password vault with no console window (window style 0 = hidden).
Set fso = CreateObject("Scripting.FileSystemObject")
folder = fso.GetParentFolderName(WScript.ScriptFullName)
Set shell = CreateObject("WScript.Shell")
shell.CurrentDirectory = folder
shell.Run "python """ & folder & "\vault_gui.py""", 0, False
