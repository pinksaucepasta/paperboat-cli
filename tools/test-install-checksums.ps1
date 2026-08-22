param(
  [Parameter(Mandatory = $true)][string]$Installer,
  [Parameter(Mandatory = $true)][string]$ChecksumFile,
  [Parameter(Mandatory = $true)][string]$LegacyChecksumFile
)

$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Installer, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw "Windows installer does not parse: $($errors[0].Message)" }
$parser = $ast.Find({
  param($node)
  $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-ReleaseChecksum'
}, $true)
if ($null -eq $parser) { throw 'Windows installer checksum parser is missing.' }
. ([scriptblock]::Create($parser.Extent.Text))

$source = [IO.File]::ReadAllText($Installer)
foreach ($required in @(
  '$asset = "paperboat_${version}_windows_${arch}.msi"',
  "[Environment]::GetFolderPath([Environment+SpecialFolder]::System)",
  "'msiexec.exe'",
  "'/i'", "'/qn'", "'/norestart'", "'/L*v'",
  'WaitForExit(1200000)',
  'function Assert-InstalledVersion',
  '-Verb RunAs',
  "'Paperboat\bin\pb.exe'",
  '& $installedPb pair --server $server --enrollment-token $token --name $name "--setup-mode=$setupMode"'
)) {
  if (-not $source.Contains($required)) { throw "Windows installer MSI contract is missing $required." }
}
if ($source.Contains('pb-windows-$arch.exe')) { throw 'Windows installer must not bootstrap pairing through a downloaded direct executable.' }
if ($source.Contains('\\bVersion\\s+') -or $source.Contains('\\s*$')) {
  throw 'Windows installer contains doubled regex escapes that do not match version output.'
}
$assertVersion = $ast.Find({
  param($node)
  $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-InstalledVersion'
}, $true)
if ($null -eq $assertVersion) { throw 'Windows installer version assertion is missing.' }
if (-not $assertVersion.Extent.Text.Contains('(?m)^.*\bVersion\s+')) {
  throw 'Windows installer version assertion does not use PowerShell regex word/whitespace escapes.'
}

foreach ($manifest in @($ChecksumFile, $LegacyChecksumFile)) {
  foreach ($asset in @('pb-linux-amd64', 'pb-windows-amd64.exe')) {
    $expected = ((Get-FileHash -LiteralPath (Join-Path (Split-Path -Parent $ChecksumFile) $asset) -Algorithm SHA256).Hash).ToLowerInvariant()
    $actual = Get-ReleaseChecksum $manifest $asset
    if ($actual -ne $expected) { throw "Windows installer rejected $([IO.Path]::GetFileName($manifest)) checksum for $asset." }
  }
}
