# TUF Release Operations

Production Paperboat updates use The Update Framework. The updater embeds the initial public
root and selects a fixed `release-index-stable-<os>-<arch>.json` target. Direct bootstrap and
CLI self-update select `pb-<os>-<arch>`, a signed byte-for-byte alias of the matching
`cli-<os>-<arch>` component. The control plane and
unsigned `current.json` may supply only the fixed repository URL as a cache hint. Private keys
must never be copied into this repository, Hetzner, or a runtime machine. Online release-role
keys are stored as protected GitHub Environment secrets; root keys remain offline.

The production signer is `/Users/pujan.pm/.local/bin/paperboat-tuf`. Its role-separated
Ed25519 seeds are macOS Keychain items under service
`com.pinksaucepasta.paperboat.tuf.production`. The local repository is
`/Users/pujan.pm/.local/share/paperboat-release/tuf-production`; `.signing-state.json` is
local signing state and must not be published. Root is 2-of-3 and targets is 2-of-2.
The current root-v2 online role aliases are `targets-1`, `targets-2`, `snapshot-1`, and
`timestamp-2`. `timestamp-1` was revoked by root v2 and must not be supplied to CI. A role
rotation must update both the protected GitHub Environment secret name and the workflow's
ephemeral signing-state binding before the next tag is created.
Every tag or manual release first enters the protected `paperboat-tuf-published` environment,
validates the install, server, and release HTTPS endpoints, then uses the protected SSH identity
only for a read-only readiness command proving that one running server container has the exact
parent bind mount
`/opt/paperboat/releases` to `/srv/paperboat-releases` read-only and resolves
`PAPERBOAT_RELEASE_DIRECTORY=/srv/paperboat-releases/current`. It also validates the release
version, fetches the served root and its numbered chain from the public HTTPS TUF repository,
verifies that chain from the client-embedded trusted root, and validates all four online secrets
against the active roles. A cheap Windows amd64 Git-Bash contract job then validates the release
workflow and first-party Windows packaging before any native platform job is allocated. Every
native platform must then qualify before any release package job is allocated. Publication
repeats the chain and signer validation against the freshly fetched
repository immediately before signing. The shared non-secret alias source is
`tools/tuf-repository/active-signing-state.json`; signer validation never writes metadata.

Build `cli`, `runtime`, `hostd`, `updater`, and `launcher` for every supported OS and
architecture. Name each file `<component>-<os>-<arch>`. Publishing fails if any component is
missing and creates one signed release index plus the required `pb-<os>-<arch>` CLI alias per
platform and architecture:

- Every macOS component must be signed with the production Developer ID, submitted to Apple
  notarization, and stapled before it enters the signed TUF repository. The updater runs both
  `codesign --verify --deep --strict` and a Gatekeeper `spctl --assess` check before activation.
- Windows components do not require Authenticode. Their exact TUF target digest, length, PE
  header, architecture, protected staging directory, and owner checks remain mandatory.
- Linux components have no native publisher-signature requirement in this release. Their exact
  TUF target digest, length, ELF header, architecture, protected staging directory, and owner
  checks remain mandatory.

The GitHub release workflow is globally serialized across versions. It builds and qualifies
artifacts, creates a non-latest GitHub release without replacing existing assets, downloads that
release again, and checks every downloaded byte against the immutable candidate manifest. It then
signs TUF with release-role keys from the `paperboat-tuf-published` environment and assembles an
isolated origin containing the canonical Unix `install` and Windows `windows` bootstrap scripts,
`metadata/`, `targets/`, and `current.json`.

Before any origin change, the real client consumers verify every component for Linux amd64 and
arm64, macOS arm64, and Windows amd64 and arm64 from the isolated origin. This gate also binds the
installers, direct bootstrap aliases, component targets, and Windows native evidence to the exact
downloaded GitHub assets. Only then does the workflow execute one final server-side
`renameat2(RENAME_EXCHANGE)` of the complete origin directory. After that exchange, it retries
marking the already-published GitHub release latest as a non-blocking convenience-pointer update.
If GitHub's API remains unavailable, the release is still valid and live through `current.json` and
TUF; retry `gh release edit <version> --draft=false --latest --target <commit>` later. The server
must mount `/opt/paperboat/releases` read-only at `/srv/paperboat-releases` and resolve `current`
per request; a legacy bind mount of `/opt/paperboat/releases/current` blocks activation. There is
no post-activation rollback or cleanup because clients may already have observed the newer TUF
timestamp. The workflow never advances `current.json` or TUF until the non-latest GitHub release
exists and every downloaded release asset has been byte-verified.
Root keys are never available to CI.
`PAPERBOAT_INSTALL_URL` is the exact user-facing HTTPS install endpoint, currently
`https://get.pprbt.dev/install`. The protected authority gate validates it before allocating
platform builders. The isolated pre-activation verifier compares both installer sources
byte-for-byte with the immutable GitHub release assets.

Windows publication is fail-closed for both architectures. `paperboat-tuf publish` requires
absolute `-windows-amd64-native-evidence` and `-windows-arm64-native-evidence` JSON files. The signer rejects a missing file, a non-passing
status, a false `native_tested` value, the wrong platform or architecture, missing components, or
any component path, SHA-256, or length that does not exactly match the final signed artifact. It
does not infer native qualification from `windows/amd64`.

Each evidence file is added as a signed TUF target named
`windows-<arch>-native-qualification.json`. Every Windows component target includes a signed
binding to that evidence target, its evidence digest, release version, Windows build, runner,
status, and that component's digest and length. Later rollout mutations revalidate those bindings
and refuse to re-sign a Windows release that lacks valid architecture-matching evidence.

Create evidence only after the final artifact bytes are available. If optional Authenticode
signing is used, create evidence after signing and RFC 3161 timestamping. It must use this exact
schema and cover `cli`, `runtime`, `hostd`,
`updater`, and `launcher` once each:

```json
{
  "schema": "paperboat.windows-native-qualification/v1",
  "release_version": "YYYY.MM.DD.X",
  "platform": "windows",
  "architecture": "<amd64-or-arm64>",
  "status": "passed",
  "native_tested": true,
  "windows_build": "26100",
  "runner": "windows-2025",
  "artifacts": [
    {
      "component": "cli",
      "target_path": "cli-windows-<arch>",
      "sha256": "<lowercase final artifact sha256>",
      "length": 12345,
      "platform": "windows",
      "architecture": "<amd64-or-arm64>",
      "status": "passed"
    }
  ]
}
```

`status` must be `passed` globally and per artifact. `windows_build` and `runner` identify the
native qualification environment. A cross-build, emulator run, skipped test, or evidence from
the other architecture cannot satisfy either gate. Both Windows architectures are stable and
must pass their native runner before publication.

The release workflow runs the full native MSI qualification on each native Windows runner. It
uses the final signed release MSI for the fresh install, builds an architecture-native upgrade
MSI and service fixture, requires the passed report to match both MSI hashes/version/architecture,
then produces both evidence files from the final release PE files. Publication includes both
architecture-specific evidence files in the release assets; a missing report, failed lifecycle
event, changed MSI, changed PE, or changed evidence blocks publication.

Windows packaging inputs are maintained in `packaging/windows`. The deterministic portable ZIP
builder and WiX source validation run in CI, while WiX MSI compilation requires a Windows
toolchain. The release authority compiles both MSIs for the stable channel, binds their exact
bytes into TUF, refreshes checksums, and only then renders
or submits the corresponding WinGet manifest template. Authenticode is optional and must never be
represented as present when no certificate was used. When optional signing is used, all evidence,
checksums, manifests, and TUF metadata are generated from the final timestamped bytes.

```sh
paperboat-tuf publish \
  -repository /Users/pujan.pm/.local/share/paperboat-release/tuf-production \
  -version YYYY.MM.DD.X \
  -artifacts /absolute/path/to/artifacts \
  -windows-amd64-native-evidence /absolute/path/to/windows-amd64-native-qualification.json \
  -windows-arm64-native-evidence /absolute/path/to/windows-arm64-native-qualification.json \
  -rollout-revision 1 \
  -percentage 5 \
  -severity routine
paperboat-tuf status \
  -repository /Users/pujan.pm/.local/share/paperboat-release/tuf-production
```

Use `-supervisor-maintenance` only when hostd, updater, or launcher must be activated. Those
components are staged automatically but use the separate maintenance approval flow while
protected workloads exist. Every release replaces all five components together: `cli`, `runtime`,
`hostd`, `updater`, and `launcher`. They use the same signed release index and TUF target bindings.

Publish only `metadata/` and `targets/` to the configured HTTPS origin. Promote the signed
cohort only after the public repository and canary continuity tests pass. Timestamp expires
after 24 hours and snapshot after seven days; refresh and republish them before expiry:

```sh
PAPERBOAT_TEST_TUF_REPOSITORY_URL=https://api.pprbt.dev/helper-releases/tuf \
PAPERBOAT_TEST_TUF_VERSION=YYYY.MM.DD.X \
go test ./internal/hostruntime/bootstrap -run '^TestProductionTUFRepository$' -count=1

paperboat-tuf refresh \
  -repository /Users/pujan.pm/.local/share/paperboat-release/tuf-production

paperboat-tuf verify-published \
  -repository /Users/pujan.pm/.local/share/paperboat-release/tuf-production
```

`verify-published` must pass against the complete directory that will be uploaded. It verifies
the signed roles and every versioned metadata file referenced by timestamp and snapshot. Upload
the whole verified `metadata/` and `targets/` trees as one staged publication; never copy only
the mutable `snapshot.json` or `timestamp.json` files.

Rollout changes are release-authority operations. The dashboard or control plane may request
them, but it cannot authorize them. Run the selected command on the signing workstation, review
the resulting metadata diff, and publish `metadata/` and the new consistent index targets:

```sh
paperboat-tuf promote -repository /Users/pujan.pm/.local/share/paperboat-release/tuf-production -rollout-revision 2 -percentage 25
paperboat-tuf pause -repository /Users/pujan.pm/.local/share/paperboat-release/tuf-production -rollout-revision 3
paperboat-tuf quarantine -repository /Users/pujan.pm/.local/share/paperboat-release/tuf-production -rollout-revision 4
```

Revisions must increase. `pause` signs a zero-percent cohort. `quarantine` additionally marks
the indexed release revoked. Clients accept these decisions only after normal TUF timestamp,
snapshot, targets, threshold-signature, expiry, and rollback verification.

Rotate one role at a time with `paperboat-tuf rotate -role <role>`. A root rotation is signed
by both the previous and new root key sets. Publish every numbered root metadata file; clients
must receive consecutive root versions. Retain revoked keys for incident recovery and audit.

An independent cryptographic review is required before treating the production hierarchy or
rotation ceremony as final.
