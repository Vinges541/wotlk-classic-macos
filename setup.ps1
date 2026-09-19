# Python 3.13+, Git and .NET SDK 10 must be available on PATH.
$ErrorActionPreference = 'Stop'
& python "$PSScriptRoot/scripts/bootstrap_windows.py" @args
exit $LASTEXITCODE
