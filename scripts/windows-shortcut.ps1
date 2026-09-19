param([string]$Destination, [string]$Python, [string]$Arguments,
      [string]$WorkingDirectory, [string]$Icon)
$ErrorActionPreference = 'Stop'
$shell = New-Object -ComObject WScript.Shell
$link = $shell.CreateShortcut($Destination)
$link.TargetPath = $Python
$link.Arguments = $Arguments
$link.WorkingDirectory = $WorkingDirectory
$link.IconLocation = "$Icon,0"
$link.Save()
