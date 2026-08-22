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

foreach ($manifest in @($ChecksumFile, $LegacyChecksumFile)) {
  foreach ($asset in @('pb-linux-amd64', 'pb-windows-amd64.exe')) {
    $expected = ((Get-FileHash -LiteralPath (Join-Path (Split-Path -Parent $ChecksumFile) $asset) -Algorithm SHA256).Hash).ToLowerInvariant()
    $actual = Get-ReleaseChecksum $manifest $asset
    if ($actual -ne $expected) { throw "Windows installer rejected $([IO.Path]::GetFileName($manifest)) checksum for $asset." }
  }
}
