Get-ChildItem -recurse HKLM:\SYSTEM\CurrentControlSet\Control\Print | Get-ItemProperty | where { $_ -match "\\\\(.*)\\(.*).dll" }
