[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $scriptDirectory '..\..\..'))
Push-Location $repositoryRoot
try {
    & go run ./packaging/windows/cmd/validate '--root' './packaging/windows'
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
finally {
    Pop-Location
}
