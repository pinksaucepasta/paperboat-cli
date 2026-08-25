#!/bin/sh
set -eu

repository_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)

python3 - \
  "$repository_root/.github/workflows/release.yml" \
  "$repository_root/tools/build-release-asset.sh" \
  "$repository_root/tools/build-macos-pkg.sh" \
  "$repository_root/Makefile" \
  "$repository_root/tools/tuf-repository/main.go" \
  "$repository_root/packaging/windows/scripts/sign-and-verify.ps1" <<'PY'
import pathlib
import re
import sys

workflow_path, release_builder_path, pkg_builder_path, makefile_path, tuf_path, windows_signer_path = map(pathlib.Path, sys.argv[1:])
workflow = workflow_path.read_text(encoding='utf-8')
release_builder = release_builder_path.read_text(encoding='utf-8')
pkg_builder = pkg_builder_path.read_text(encoding='utf-8')
makefile = makefile_path.read_text(encoding='utf-8')
tuf_repository = tuf_path.read_text(encoding='utf-8')
windows_signer = windows_signer_path.read_text(encoding='utf-8')

required = {
    'release-authority:',
    'release-contract:',
    'release-linux:',
    'release-windows:',
    'release-macos:',
    'release-publication:',
    'runner: blacksmith-2vcpu-ubuntu-2404',
    'runner: blacksmith-2vcpu-ubuntu-2404-arm',
    'runner: blacksmith-2vcpu-windows-2025',
    'runner: windows-11-arm',
    'runs-on: blacksmith-6vcpu-macos-latest',
    'cache: true',
    'actions/download-artifact@',
    'merge-multiple: true',
    'actions/upload-artifact@',
    'go run ./tools/tuf-repository publish',
    'PAPERBOAT_GITHUB_REPOSITORY: ${{ github.repository }}',
    '-windows-amd64-native-evidence',
    '-windows-arm64-native-evidence',
    'paperboat.release-current/v1',
    "'assets': assets",
    'publish-tuf-origin.sh',
    'PAPERBOAT_RELEASE_BUNDLE_SHA256',
    'gh api "repos/$GITHUB_REPOSITORY/releases/tags/$RELEASE_VERSION"',
    'GitHub API did not return a digest',
    'gh release edit "$RELEASE_VERSION" --draft=false --target "$GITHUB_SHA"',
    'Publish release assets without changing Latest',
    'Mark the verified GitHub release latest',
    'APPLE_INSTALLER_SIGNING_IDENTITY',
    'xcrun notarytool submit',
    'xcrun stapler staple',
}
missing = sorted(value for value in required if value not in workflow)
if missing:
    raise SystemExit('release workflow is missing: ' + ', '.join(missing))

expected_assets = {
    'pb-windows-amd64.exe',
    'pb-windows-arm64.exe',
    'pb-linux-amd64',
    'pb-linux-arm64',
    'pb-darwin-arm64.pkg',
}
asset_literals = set(re.findall(r"['\"](pb-(?:windows|linux|darwin)-[a-z0-9-]+(?:\.exe|\.pkg)?)['\"]", workflow))
if not expected_assets.issubset(asset_literals):
    raise SystemExit(f'release workflow does not name all five assets: {sorted(asset_literals)}')

forbidden = (
    'pb-launcher',
    'paperboat-runtime',
    'paperboat-hostd',
    'paperboat-updater',
    'paperboat_{{',
    '.msi',
    '.zip',
    '.tar.gz',
    'SHA256SUMS',
    'WinGet',
    'winget',
    'actions/attest-build-provenance',
    'generate-release-checksums',
    'package-manifests',
)
for value in forbidden:
    if value.lower() in workflow.lower():
        raise SystemExit(f'release workflow retains retired packaging path: {value}')

if '-github-release-url' in workflow:
    raise SystemExit('release workflow uses the removed -github-release-url TUF option')

if 'cmd/pb-launcher' in release_builder or 'WindowsArtifactRole' in release_builder:
    raise SystemExit('release builder must compile only cmd/pb')
if './cmd/pb' not in release_builder:
    raise SystemExit('release builder does not compile cmd/pb')
for value in ('pre-unification', 'migration fallback', 'local = legacy', 'cli-" + platform'):
    if value in tuf_repository:
        raise SystemExit(f'TUF publisher retains a legacy split-artifact allowance: {value}')
if 'metadata.TargetFile().FromFile(local, "sha256")' not in tuf_repository:
    raise SystemExit('TUF publisher does not read the exact unified asset path')
if "@('.exe', '.msi')" in windows_signer or "-notin @('.exe', '.msi')" in windows_signer:
    raise SystemExit('Windows release signer retains MSI compatibility')
if "Only unified Paperboat PE .exe files may be signed" not in windows_signer:
    raise SystemExit('Windows release signer does not enforce unified .exe inputs')
for value in ('pkgbuild', 'productsign', '--sign', 'pkgutil --expand'):
    if value not in pkg_builder:
        raise SystemExit(f'macOS package builder is missing {value}')
for value in ('pb-launcher', 'launcher-windows', 'paperboat-runtime', 'paperboat-hostd', 'paperboat-updater'):
    if value in makefile:
        raise SystemExit(f'Makefile retains retired role artifact {value}')

if 'needs: [release-authority, release-contract]' not in workflow:
    raise SystemExit('platform builds must wait for the authority and focused contract gates')
if 'needs: [release-authority, release-contract, release-linux, release-windows, release-macos]' not in workflow:
    raise SystemExit('publication must wait for all five assets')
if not (workflow.index('Publish release assets without changing Latest') < workflow.index('Atomically activate current.json and TUF on the server') < workflow.index('Mark the verified GitHub release latest')):
    raise SystemExit('GitHub assets must be public before origin activation, while Latest is marked only after the exchange')
build_and_publish = workflow.split('  release-contract:', 1)[1]
if 'vars.PAPERBOAT_DEFAULT_SERVER_URL' in build_and_publish or 'vars.PAPERBOAT_DEFAULT_RELEASE_URL' in build_and_publish:
    raise SystemExit('build and publication jobs must consume authority outputs, not mutable URL variables')
if 'runner: windows-11-arm' not in workflow:
    raise SystemExit('Windows arm64 must use GitHub windows-11-arm')

print('five-asset release pipeline contract is valid')
PY
