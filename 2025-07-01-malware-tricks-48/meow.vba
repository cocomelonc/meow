Sub MeowMacro()
    Set shell_object = CreateObject("WScript.Shell")
    shell_object.Exec ("mspaint.exe")
End Sub

Sub AutoOpen()
    MeowMacro
End Sub

Sub Document_Open()
    MeowMacro
End Sub