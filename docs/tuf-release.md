# TUF Release Operations

Production Paperboat updates use The Update Framework. The updater embeds the initial public
root and selects a fixed `release-index-stable-<os>-<arch>.json` target. The control plane and
unsigned `current.json` may supply only the fixed repository URL as a cache hint. Private keys
must never be copied into this repository, CI, Hetzner, or a runtime machine.

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
- Every Windows component must carry a valid production Authenticode signature before it enters
  the signed TUF repository. The updater checks `Get-AuthenticodeSignature` and accepts only a
  `Valid` chain status before activation.
- Linux components have no native publisher-signature requirement in this release. Their exact
  TUF target digest, length, ELF header, architecture, protected staging directory, and owner
  checks remain mandatory.

The GitHub release workflow builds artifacts only. It must not be used as evidence that macOS or
Windows artifacts are eligible for TUF publication: the platform signing and verification ceremony
is a required release-authority step, using keys outside GitHub Actions and CI.

```sh
paperboat-tuf publish \
  -repository /Users/pujan.pm/.local/share/paperboat-release/tuf-production \
  -version YYYY.MM.DD.X \
  -artifacts /absolute/path/to/artifacts \
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
```

Rotate one role at a time with `paperboat-tuf rotate -role <role>`. A root rotation is signed
by both the previous and new root key sets. Publish every numbered root metadata file; clients
must receive consecutive root versions. Retain revoked keys for incident recovery and audit.

An independent cryptographic review is required before treating the production hierarchy or
rotation ceremony as final.
