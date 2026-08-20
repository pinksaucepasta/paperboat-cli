# Paperboat Windows parity ledger

Status: seeded and intentionally not release-ready as of 2026-08-18.

This is the authoritative Windows support ledger for the approved native Windows 11
amd64 Stable and arm64 Beta plan. It covers native Windows without WSL, the client,
host, local runtime, server, dashboard, release authority, documentation, and support
surfaces.

The machine-readable source is [windows-parity.json](windows-parity.json). The JSON is
the canonical inventory, state matrix, evidence catalog, and gate record. This document
defines how that data must be interpreted. Run:

```text
go run ./tools/validate-windows-parity.go
```

The validator must pass before a ledger change is accepted. A green validator proves
ledger consistency only. It does not create native Windows evidence.

## Current release contract

| Target | Intended channel | Current ledger readiness | Native evidence | Promotion rule |
| --- | --- | --- | --- | --- |
| Windows amd64 | stable | blocked | required, not yet complete | every release-blocking feature and the full native amd64 matrix must reach `stable_ready` or its applicable native gate must pass |
| Windows arm64 | beta | beta blocked | `native_windows_arm64_e2e: blocked_no_hardware` | beta may ship only with the complete implementation, signed artifacts, and `arm64_cross_verified`; stable promotion is technically blocked until `arm64_native_verified` |

“Windows amd64 stable” is the target release contract, not a claim that the current
checkout is stable. “Windows arm64 beta” is the intended channel, not a substitute for
missing implementation. No feature is intentionally omitted for ARM64. The current
ledger contains no intentional feature omissions.

The user-approved Windows plan is the authoritative scope for this ledger and supersedes
older platform-limited planning material.

## Allowed feature states

These are the only states allowed in a feature evidence matrix:

| State | Meaning | What it does not prove |
| --- | --- | --- |
| `not_started` | The required implementation or evidence is absent. | It must not be treated as unsupported product policy or as a passing skip. |
| `implemented` | A code path or product contract exists, but the exact evidence dimension has not passed its qualification gate. | It does not prove native execution, interoperability, or release readiness. |
| `amd64_native_verified` | The feature passed the required native Windows 11 amd64 test on the exact role and dimension recorded. | It does not prove the other roles, architectures, interop directions, or UX contracts. |
| `arm64_cross_verified` | The Windows arm64 component compiled and passed applicable static and contract checks. | It does not prove native ARM64 execution. |
| `arm64_native_verified` | The feature passed its required test on native Windows arm64 hardware. | It does not by itself make the feature stable-ready. |
| `stable_ready` | Every required evidence dimension and release gate for that feature passed, with no unresolved blocker. | It cannot be assigned from a build, a skipped test, an emulator, or a source review alone. |

The ledger intentionally does not use `unsupported` as a feature state. An existing
unsupported Windows branch is recorded as an implementation blocker and must be removed
or replaced before release.

## Evidence dimensions

Each feature resolves against an applicability profile and a state profile. The validator
expands those profiles and requires a state or an explicit not-applicable declaration for
every dimension below. This prevents a feature from hiding a missing client, host, cross,
native, interoperability, or UX result.

| Dimension | Required evidence |
| --- | --- |
| `windows_amd64_client` | Native Windows 11 amd64 client execution. |
| `windows_amd64_host` | Native Windows 11 amd64 host and unattended runtime execution. |
| `windows_arm64_compile` | Every applicable package and test package cross-compiles for Windows arm64; static and contract checks pass. |
| `windows_arm64_native` | The same applicable behavior executes on real Windows arm64 hardware. Emulator results are development smoke evidence only. |
| `windows_to_windows` | Windows clients and hosts interoperate in both directions. |
| `windows_to_macos` | Windows client to macOS host interoperability. |
| `macos_to_windows` | macOS client to Windows host interoperability. |
| `windows_to_linux` | Windows client to Linux host interoperability. |
| `linux_to_windows` | Linux client to Windows host interoperability. |
| `human_ux` | Matching human-readable CLI, installer, dashboard, recovery, and support behavior. |
| `json_ux` | Matching JSON envelopes, stable error codes, progress, cancellation, redaction, and machine-readable output. |
| `server_control_plane` | Server admission, machine ownership, channel policy, release policy, telemetry, and API behavior. |
| `dashboard` | Windows status, beta disclosure, channel controls, downloads, recovery, and rollout UX. |
| `release_authority` | MSI, ZIP, WinGet, updater, rollback, signing, SBOM, provenance, TUF, and rollout authority. |
| `documentation_support` | Setup, troubleshooting, diagnostics, support output, release notes, and explicit beta disclosures. |

The required cross-platform matrix is directional. A single “interoperable” result is
not evidence for all five Windows/macOS/Linux directions.

## Gate rules

| Gate | Seeded status | Release meaning |
| --- | --- | --- |
| `windows_scope_authority` | `pass` | The approved Windows plan is recorded here as the authoritative platform scope. |
| `windows_amd64_cross_build` | `pass` | The full repository builds for Windows amd64; this is compile evidence only. |
| `windows_arm64_cross_build` | `pass` | The full repository builds for Windows arm64; this is compile evidence only. |
| `windows_amd64_native_full_matrix` | `in_progress` | Must pass on standard Windows 11 and the Windows 11 IoT Enterprise LTSC target, including installation, host, service, transport, interop, update, rollback, and uninstall. |
| `native_windows_arm64_e2e` | `blocked_no_hardware` | Explicitly skipped because no native ARM64 machine is available. This never counts as a pass. |
| `windows_arm64_beta_cross_gate` | `pass` | The complete ARM64 source, test-package, MSI, ZIP, updater, and release-policy cross gate passes. Native ARM64 evidence remains explicitly unavailable and is not counted. |
| `windows_amd64_stable_release` | `blocked` | Stable cannot be published while native amd64 qualification, host runtime, installer lifecycle, or interoperability is incomplete. |
| `windows_artifact_signing` | `blocked` | TUF, SHA-256, PE architecture, SBOM, provenance, and malware-scan evidence are required before publication. Authenticode is optional. |

Allowed gate statuses are `not_started`, `in_progress`, `blocked`,
`blocked_no_hardware`, `pass`, `fail`, and `not_applicable`. A skipped ARM64 native
test has `blocked_no_hardware`, not `pass` and not `arm64_native_verified`.

## Locked Windows setup and security invariants

The ledger treats these as product requirements, not optional implementation details:

- Host setup installs the exact WinGet package ID `Microsoft.OpenSSH.Preview` with a
  Paperboat-approved pinned version. It does not use `Add-WindowsCapability` and does
  not use display-name matching.
- Setup installs and verifies both OpenSSH Client and Server, verifies Microsoft
  publisher identity, architecture, version, paths, and signatures, and returns a
  typed failure if WinGet cannot be repaired through a supported Microsoft path.
- Paperboat owns a dedicated `PaperboatSshd` service and state under
  `C:\ProgramData\Paperboat\ssh\`. It binds only to `127.0.0.1` and `::1`, uses
  Paperboat-owned keys and authorized keys, requires public-key authentication, and
  enables only the required PTY, exec, scp, and sftp behavior.
- Existing administrator-owned `sshd`, keys, configuration, ports, firewall rules,
  and third-party installations remain untouched. Uninstall removes only Paperboat-owned
  state and changes.
- Machine-wide binaries use `C:\Program Files\Paperboat`; machine state uses
  `C:\ProgramData\Paperboat`; user state uses `%LOCALAPPDATA%\Paperboat` and
  `%APPDATA%\Paperboat`; local IPC uses `\\.\pipe\Paperboat-*`.
- Credential Manager and user-scoped DPAPI are preferred. Keys never appear in argv,
  environment variables, logs, diagnostics, or bug reports.
- Full unattended host behavior is mandatory. A logged-in-console-only fallback cannot
  satisfy the stable amd64 gate.
- TUF metadata, SHA-256 checksums, PE architecture validation, SBOM, provenance, and
  malware scanning are release evidence, not assumptions based on filenames.
  Authenticode and RFC 3161 timestamping are optional enhancements.

## Seed interpretation

The seeded matrix is deliberately conservative:

- Existing Windows adapters, OpenSSH provisioning code, credential storage, PE checks,
  and release-policy code are represented as `implemented` or `arm64_cross_verified`
  only where the current source and focused checks support that claim.
- Native evidence is assigned only to the exact dimensions exercised on Victus. No
  feature is marked `arm64_native_verified` or `stable_ready`; cross-compilation and
  source presence never substitute for native qualification.
- The current tree has native evidence for core OpenSSH, ConPTY, named pipes, MSI/SCM,
  owner-token S4U, and process-tree behavior. Broader config, profile-dependent,
  interoperability, signing, and release-matrix blockers remain recorded on their
  affected features rather than hidden by a platform-level claim.
- The existing CI workflow configuration is cataloged as configuration evidence only.
  It is not treated as a passing runner result.
- The JSON evidence catalog records source paths and their limits. A source path is not
  a test result.

The current native LTSC amd64 evidence is intentionally narrow:

- `os.credentials` has `windows_amd64_client: amd64_native_verified` for the recorded
  Credential Manager round-trip, DPAPI-protected fallback, deletion, missing-credential,
  and access-denied tests. Host-profile, multi-account, reboot, and service-profile
  evidence remains open.
- `local-api.named-pipe` has `windows_amd64_client: amd64_native_verified` and
  `windows_amd64_host: amd64_native_verified` for the recorded named-pipe transport,
  protected DACL, peer identity, snapshot/watch, peer stream, file-transfer lease, and
  cancellation tests. The broader local API operation and unattended daemon gates remain
  open.
- `os.known-folders` has native Windows amd64 evidence and `windows_arm64_compile: arm64_cross_verified` from the
  cross-compiled Known Folder test package. It has no native ARM64 state and remains
  blocked until real ARM64 hardware exists.
- `os.owner-token` and `os.process-tree` have `windows_amd64_host:
  amd64_native_verified` from a real SCM test with the enrolled owner logged out. The
  evidence covers LSA S4U, owner SID validation, loaded profile/environment,
  `CreateProcessAsUser`, suspended Job assignment, and descendant cleanup. It explicitly
  also proves decryption of an owner-created user-scoped DPAPI fixture, native Git
  repository access, outbound TCP, and execution of the supported Authenticode-signed
  native Codex 0.147.0 binary. The Codex client contract test separately confirms the
  remote endpoint, token environment, and working-directory flags Paperboat uses.
  EFS encryption fails with `ERROR_ACCESS_DENIED` in the logged-out S4U token, and
  credentialed SMB remains unqualified because S4U has no reusable user network
  credentials. Both remain stable-release blockers under the unattended-host contract.

The full Windows amd64 and arm64 build gates currently pass. These remain compile evidence
and do not replace native runtime or interoperability qualification.

## ARM64 cross-verification enforcement

`arm64_cross_verified` is permitted only for the `windows_arm64_compile` dimension. It
requires the passing `windows_arm64_cross_build` gate, whose evidence must compile the
complete Windows ARM64 Go source graph, compile every test package discovered by
`go list ./...` with `paperboat_native_e2e` and `paperboat_native_network_e2e` build tags,
and validate every generated PE as ARM64. A source review, a single-package test compile,
an ordinary binary build, a skipped native test, or an emulator result cannot satisfy it.

The `windows_arm64_beta_cross_gate` passes only because every feature applicable to
`windows_arm64_compile` has cross-verification and the package gate verifies ARM64 MSI, ZIP,
updater, and release-policy artifacts. This does not provide native execution evidence and
cannot promote ARM64 to stable.

## Complete feature inventory

Every item below is a release blocker in the seeded ledger. The feature’s full
requirement, applicability profile, state profile, evidence references, and blockers are
in the JSON record with the same ID.

### Windows integration and local API

- `local-api.named-pipe`
- `local-api.acl-token`
- `local-api.operations`
- `os.known-folders`
- `os.acl-reparse`
- `os.long-paths`
- `os.atomic-replacement`
- `os.credentials`
- `os.pe-authenticode`
- `os.winsock-observer`
- `os.services`
- `os.owner-token`
- `os.user-profile`
- `os.process-tree`
- `os.conpty`
- `os.workspace-smb-efs`

### Authentication and machine lifecycle

- `auth.login`
- `setup.host`
- `setup.pair`
- `setup.unpair`
- `machine.ownership`

### Configuration and repositories

- `config.sync`
- `config.git`
- `config.chezmoi`
- `config.restore`
- `config.flush`
- `config.conflicts`

### Managed SSH

- `ssh.provisioning`
- `ssh.client-server`
- `ssh.paperboat-service`
- `ssh.authorized-keys`
- `ssh.host-keys`
- `ssh.agent`
- `ssh.key-rotation`
- `ssh.proxy-command`
- `ssh.scp`
- `ssh.sftp`
- `ssh.firewall`
- `ssh.repair`

### Operations, distribution, and release

- `ops.diagnostics`
- `ops.bug-reports`
- `ops.completions`
- `ops.telemetry`
- `ops.update`
- `ops.rollback`
- `ops.repair`
- `ops.uninstall`
- `distribution.msi`
- `distribution.winget`
- `distribution.zip`
- `distribution.lifecycle`
- `distribution.arch-mismatch`
- `release.sbom-provenance-signing`
- `release.tuf`
- `release.channels-rollout`
- `server.platform-admission`
- `server.release-index`
- `dashboard.beta-status`
- `docs.support`
- `ci.windows-amd64`
- `ci.windows-arm64`

### Previews and serve

- `preview.private`
- `preview.public`
- `preview.http`
- `preview.websocket`
- `preview.sse`
- `preview.detached-serve`

### Terminal and sessions

- `terminal.interactive`
- `terminal.exec`
- `terminal.sessions`
- `terminal.replay`
- `terminal.resize`
- `terminal.cancellation`
- `terminal.reconnect`
- `terminal.shells`
- `terminal.utf8-vt`
- `terminal.ctrl-c`
- `terminal.descendant-cleanup`
- `codex.sessions`

### Transfers and inbox

- `transfer.send`
- `transfer.receive`
- `transfer.inbox`
- `transfer.encryption`
- `transfer.resume`
- `transfer.cancellation`

### Transport and network adaptation

- `transport.direct-quic`
- `transport.relayed-quic`
- `transport.wss`
- `transport.network-migration`
- `transport.sleep-wake`
- `transport.ipv4-ipv6`
- `transport.pmtu`
- `transport.vpn-nat-firewall-proxy`

## Promotion criteria

Windows amd64 can move from blocked to stable only when the ledger contains evidence
for all release-blocking features and all required dimensions, and all of these are
true:

1. Clean and existing-install Windows 11 IoT Enterprise LTSC host setup installs the
   exact approved OpenSSH package automatically, verifies Client and Server, creates
   and validates `PaperboatSshd`, and passes public-key, PTY, exec, scp, sftp, exit,
   cleanup, and loopback-only probes.
2. Native amd64 tests pass for the full client, host, service, local API, ConPTY,
   filesystem, credential, transport, preview, Codex, transfer, config, diagnostics,
   update, repair, rollback, uninstall, and reboot/logout matrix.
3. Windows-to-Windows, Windows-to-macOS, macOS-to-Windows, Windows-to-Linux, and
   Linux-to-Windows interoperability passes in both applicable roles.
4. MSI, WinGet manifest, ZIP, upgrade, repair, interrupted-install rollback, reboot
   continuation, silent install, architecture mismatch, and uninstall pass with spaces,
   Unicode, and long paths.
5. TUF metadata, SHA-256 checksums, PE architecture, SBOM, provenance, and malware
   scan evidence are verified for the final artifact bytes. Authenticode and RFC 3161
   timestamps are verified when present but are not release requirements.
6. The server, dashboard, CLI, installer, documentation, release notes, telemetry, and
   support output all show the same stable amd64 contract and JSON/human UX.

Windows arm64 can publish as beta only when the implementation has the same intended
feature set, every applicable build/test/release artifact is cross-verified and protected
by the same TUF, checksum, SBOM, and provenance controls,
the beta channel is explicit everywhere, and `native_windows_arm64_e2e` remains recorded
as `blocked_no_hardware`. It cannot be promoted to stable until the complete native
ARM64 matrix reaches `arm64_native_verified`.

## Updating the ledger

Every state change must include:

- the exact feature ID and evidence dimension;
- the command, test name, runner identity, Windows edition/build, architecture, and
  artifact or log location;
- whether the result was native, cross-compiled, emulated, or a source review;
- the corresponding evidence catalog entry and date;
- any remaining blocker or recovery action.

Never convert `blocked_no_hardware` to a pass because an emulator succeeded. Never mark
a whole group complete from one representative test. Run the validator and review the
diff before committing a ledger update.
