# TUF Release Operations

Production Paperboat updates use The Update Framework. The updater embeds the initial public
root and selects a fixed `release-index-stable-<os>-<arch>.json` target. The control plane and
unsigned `current.json` may supply only the fixed repository URL as a cache hint. Private keys
must never be copied into this repository, Hetzner, or a runtime machine. Online release-role
keys are stored as protected GitHub Environment secrets; root keys remain offline.

The production signer is `/Users/pujan.pm/.local/bin/paperboat-tuf`. Its role-separated
Ed25519 seeds are macOS Keychain items under service
`com.pinksaucepasta.paperboat.tuf.production`. The local repository is
`/Users/pujan.pm/.local/share/paperboat-release/tuf-production`; `.signing-state.json` is
local signing state and must not be published. Root is 2-of-3 and targets is 2-of-2.

Build `cli`, `runtime`, `hostd`, `updater`, and `launcher` for every supported OS and
architecture. Name each file `<component>-<os>-<arch>`. Publishing fails if any component is
missing and creates one signed release index per platform and architecture:

- Every macOS component must be signed with the production Developer ID, submitted to Apple
  notarization, and stapled before it enters the signed TUF repository. The updater runs both
  `codesign --verify --deep --strict` and a Gatekeeper `spctl --assess` check before activation.
- Windows components do not require Authenticode. Their exact TUF target digest, length, PE
  header, architecture, protected staging directory, and owner checks remain mandatory.
- Linux components have no native publisher-signature requirement in this release. Their exact
  TUF target digest, length, ELF header, architecture, protected staging directory, and owner
  checks remain mandatory.

The GitHub release workflow builds and qualifies artifacts, publishes immutable GitHub assets
without marking the release latest, signs
TUF with release-role keys from the `paperboat-tuf-published` environment, atomically publishes
`metadata/`, `targets/`, and `current.json`, verifies the public origin, and only then marks the
GitHub release latest. Root keys are never available to CI.

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

The release workflow produces both evidence files after each architecture's native qualification
and hashes the final release PE files. Publication includes both architecture-specific evidence
files in the release assets; a missing report, changed PE, or changed evidence blocks publication.

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
protected workloads exist. Ordinary releases replace only CLI and runtime.

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
