# TUF release operations

Paperboat publishes exactly five native release assets. Every asset is the complete unified `pb` executable for its platform and architecture:

- `pb-windows-amd64.exe`
- `pb-windows-arm64.exe`
- `pb-linux-amd64`
- `pb-linux-arm64`
- `pb-darwin-arm64.pkg`

Linux assets are raw ELF executables. Windows assets are PE executables. The macOS asset is a signed and notarized arm64 installer package. The installed executable handles CLI, services, runtime, updates, and background roles through internal arguments.

## Distribution contract

GitHub Releases is the only binary distribution. The release origin serves only:

- `current.json`
- the shell installer at `/install`
- the PowerShell installer selected by the PowerShell user agent
- signed TUF metadata under `/tuf/metadata/`

The origin's `tuf/targets/` directory must be empty. No release binary bytes are copied to the origin.

Each TUF target is one of the five canonical asset names. Its custom metadata has schema `paperboat.tuf-asset/v1`, kind `github-release-asset`, and includes:

- `version`, `platform`, `architecture`, and `format`
- `asset_name`, `repository`, immutable GitHub `url`
- `sha256` and `length`
- the signed `release_index` policy

Clients refresh and verify TUF metadata, select their canonical asset target, validate the custom metadata, and download the bytes from its immutable GitHub URL. They verify the downloaded length and SHA-256 against the TUF target before installing or activating it.

## current.json

`current.json` uses `paperboat.release-current/v1` and is the discovery document for installers. It contains `schema`, `version`, `repository`, and an `assets` object with exactly the five asset names above. Every asset entry contains `platform`, `architecture`, `format`, `url`, `sha256`, and `length`. URLs must be of the form:

`https://github.com/<owner>/<repo>/releases/download/<version>/<asset>`

The server validates this shape before activating a release. The installer also validates the selected platform, architecture, URL, digest, and length.

## Release sequence

1. Create and push a release tag.
2. The workflow runs the release checks and native platform tests.
3. It builds exactly the five assets and verifies their local bytes.
4. It creates or updates the GitHub release through the GitHub API, uploads exactly those five assets, and verifies the API-reported size and digest.
5. The TUF signer publishes five signed asset targets with the GitHub URLs and inline release policy.
6. The workflow stages `current.json`, both installers, and TUF metadata, then atomically activates the server origin.

All pull requests run the reusable checks. The tag workflow repeats the small release contract checks and the required native checks before spending time on publication. No separate binary transfer or checksum-file handoff is part of the release.

## Installers

Users start with:

`curl -fsSL https://get.pprbt.dev/install | sh`

The shell installer fetches `current.json`, selects the Linux or macOS asset, downloads that asset from GitHub, verifies its length and SHA-256, and installs it. On macOS, the package installer places `pb` in `/usr/local/bin/pb`. On Linux, the raw executable is installed as `pb` in the selected directory.

PowerShell uses the same `current.json` and GitHub-only flow. It selects `pb-windows-amd64.exe` or `pb-windows-arm64.exe`, verifies it, and invokes that downloaded executable with `__install` for the elevated atomic installation. Services must point at the installed `pb.exe`.

## Windows qualification

`paperboat-tuf publish` requires one passed native qualification header for each Windows architecture. The evidence binds the release version, Windows architecture, Windows build, runner, and `native_tested` status. It does not publish a separate executable or package target.

## Signing and maintenance

Keep TUF private keys out of the repository and runtime machines. Online role keys are protected GitHub environment secrets; root keys remain offline. The signer runs on the approved release workstation or in the explicitly authorized CI mode.

Use the signer for the current five-asset repository:

First create and validate the canonical artifact manifest and signed deployment
policy from the exact five files. The policy revision passed to the signer must
match the plan's `policy_revision`.

```sh
go run ./tools/release-plan manifest \
  -version YYYY.MM.DD.X \
  -source-commit <40-or-64-char-commit> \
  -toolchain go1.27.1 \
  -artifacts /absolute/path/to/five-assets \
  -output /absolute/path/to/manifest.json

go run ./tools/release-plan plan \
  -manifest /absolute/path/to/manifest.json \
  -policy-revision 1 \
  -severity routine \
  -cohort-seed release-YYYY.MM.DD.X \
  -output /absolute/path/to/deployment-plan.json

go run ./tools/release-plan validate \
  -manifest /absolute/path/to/manifest.json \
  -plan /absolute/path/to/deployment-plan.json \
  -artifacts /absolute/path/to/five-assets

paperboat-tuf publish \
  -repository /Users/pujan.pm/.local/share/paperboat-release/tuf-production \
  -version YYYY.MM.DD.X \
  -artifacts /absolute/path/to/five-assets \
  -manifest /absolute/path/to/manifest.json \
  -deployment-plan /absolute/path/to/deployment-plan.json \
  -windows-amd64-native-evidence /absolute/path/to/windows-amd64-native-qualification.json \
  -windows-arm64-native-evidence /absolute/path/to/windows-arm64-native-qualification.json \
  -rollout-revision 1 \
  -severity routine

paperboat-tuf verify-published \
  -repository /Users/pujan.pm/.local/share/paperboat-release/tuf-production
```

`refresh`, `promote`, `pause`, and `quarantine` update signed TUF metadata only. Review and publish the complete metadata directory atomically. The origin remains metadata-only.

`promote`, `pause`, and `quarantine` mutate the single signed deployment policy
and require a strictly higher policy revision. `promote` may widen eligible
cohorts and sets `rollout_state=active`; `pause` sets `paused`; and `quarantine`
sets `quarantined`. Automatic consumers are eligible only while the signed
state is active. The quarantine command does not use the release index's
cryptographic revocation flag.

Before publication, verify that the GitHub release contains exactly the five expected asset names, that every URL in `current.json` and TUF points to that release, and that the origin's TUF target directory is empty.
