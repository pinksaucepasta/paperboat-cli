# Windows recovery acceptance

Scope: Windows only. Verify the installed release and fresh dashboard enrollment,
services, reboot, updater, doctor, preview and tunnel before declaring acceptance.

## Initial evidence

- 2026-09-05: production current.json advertises 2026.09.03.24 for all five assets.
- Victus password SSH succeeds. Key-only SSH is not configured for this account.
- PaperboatHostd, PaperboatLocalDaemon, PaperboatSshd and PaperboatUpdated are
  running with automatic startup.
- Installed CLI and runtime both report 2026.09.03.24.
- Doctor reports healthy: authentication, daemon, local state and UDP checks pass.
- Update status reports no pending activation or maintenance, but retains
  `last_failure=check_failed`. Cause and a fresh signed update check remain open.
- Fresh `pb update check --json` exits 1: `expired metadata error:
  timestamp.json is expired`. This is a confirmed release-metadata failure.
- Installed Windows AMD64 SHA-256 matches published .24:
  `0a39b56898c86294b0b07798fc9bc2cdff85572f24823667c1379ac22e9b5f65`.
- The SSH PowerShell session has an elevated administrator token.
- Operator correction: version command is `pb --version`; `pb version` is not a
  supported version command and is not a product regression.
- One uncommitted production_assembly.go retry change remains from the previous
  task. It is being reviewed separately and is not part of released .24.

## Pending acceptance

Fresh dashboard Windows Host command for `victus-recovery-0905` was executed
once in elevated PowerShell. It printed `Completing one-shot machine enrollment`
then `expired metadata error: timestamp.json is expired`. The outer PowerShell
command returned exit 0 despite that error. Fresh enrollment is failed, not passed;
token consumption and preservation of prior installation require inspection.

Post-failure inspection confirms all four Paperboat services were removed and
doctor cannot connect to the local named pipe. The fresh installer therefore
performed cleanup before failing signed metadata validation. This ordering is a
confirmed installation defect. Reboot, preview and tunnel acceptance are blocked
by failed installation and will run after its prerequisite is restored.

- Fresh dashboard-issued enrollment and installer completion evidence.
- Exact installed asset hash, native service configuration and health endpoint.
- Reboot persistence and identity preservation.
- Signed updater check and activation convergence.
- Preview first/second external request and supported stop.
- Tunnel first/second external request, diagnostics and supported deletion.

No acceptance requirement is inferred from compilation or previous releases.

## Recovery changes under verification

- Corrected managed SSH diagnosis: exact all-user effective key count is 65,
  above the existing64 cap. Fresh CLI session is active and authorized; target
  fingerprint is absent. RegisterClient intentionally rejects capacity with
  ErrUnavailable mapped404. Earlier one-key count was not the authoritative
  all-user count and did not rule this out. No credentials were deleted.

- Confirmed second-preview root cause: edge handler binds admissions once per
  accepted carrier. The second route reuses pvc_ses_cd707599eafe37a81bd69b869c443da7
  but is never dynamically attached/observed ready. Fix in progress in edge
  handler, with reused-session regression coverage. Nearby certificate errors
  are unrelated and must not be cited as this preview's cause.
- Native Victus TestFreshStandaloneInstallVerifiesBeforeCleanup passes: failed
  signed verification returns without calling recovery or purge callbacks.

- Correct second-preview trace: prv_e01bdfec571264a0663a44d8952392f3,
  created 01:12:05 UTC, operation op_a49c3cedb24b7c3e2a0162013ddc1cfd.
  Dispatch and admission ACK succeeded, but no edge readiness observation or
  host readiness callback occurred. Both readiness flags stayed false. Binding
  412s followed; certificate GET 404/distribution 503 require exact correlation.
  Root cause remains unproven. The first preview's origin-failure trace does
  not explain this second attempt with the live fixture.

- Cross-platform acceptance was requested after the combined release on the
  latest user steer. macOS/Linux implementation remains unchanged.
- Full local make check encountered macOS environment interference: scutil
  reports PAC enabled at http://127.0.0.1:50146/proxy.pac. HTTP-based CLI tests
  fail with automatic proxy unsupported. No system proxy setting was changed.
- Process-only NO_PROXY=127.0.0.1,localhost,::1 makes the previously failing
  focused CLI checks pass. Full gate is rerunning with that loopback bypass.
- Linux acceptance target Dadape is reachable via SSH port 6000 and is Linux
  aarch64; pb is not on its non-interactive PATH. Fresh installation is pending
  the combined release. This does not prove binaries are absent from disk.

- Reboot acceptance: Windows boot time is 2026-09-05 01:17:37 UTC.
  At 01:21 UTC all four Paperboat services are Running/Automatic, CLI/runtime
  remain .24, doctor is healthy, and updater has no pending activation or failure.
- Post-reboot machine/environment IDs and installation generation 1 are unchanged.
  Managed SSH remains degraded. Server registration requests returned 200 and
  one active key exists, ruling out the suspected registration-limit explanation.
- Current bootstrap/runtime race suites pass. Tunnel remains pending after reboot;
  restart alone did not repair activation.

- Metadata refresh workflow committed and pushed as `3c8e8e2`, scheduled every
  six hours. Manual recovery run `33935135322` dispatched; publication result
  succeeded. No release binaries rebuilt.
- Public timestamp is now version 244, expires
  `2026-09-06T01:06:55.379174548Z`; current release remains .24.
- A new dashboard-issued Host command for `victus-recovery-0905b` is running
  after metadata repair. The earlier failed bootstrap is not reused.
- Fresh enrollment completed successfully; all four automatic services running,
  doctor healthy, signed update check verified .24, update failure field cleared.
- Tunnel create `windows-recovery-0905` (port 38142) failed activation with
  uncertain outcome and preserved tunnel `tun_6pf0sSiOcfKRTAks3Mq_sA`.
  Exact error: `tunnel connector activation unavailable`. No retry performed yet.
- Preview command exits 1 with `preview readiness timed out`; first/second
  external loads could not run. Origin reachability and runtime cause under check.
- Correction: independent origin probe after timeout failed. The test fixture
  did not survive its launching SSH session. Preview timeout is inconclusive,
  not a proven product defect. Restarting fixture in a held foreground SSH
  session before repeating the feature test. Tunnel activation cause remains
  independently under investigation.
- Second preview attempt also timed out with the fixture held in foreground SSH.
  Independent origin probe after timeout returned 200. This second failure is
  a confirmed readiness defect; server/edge evidence is being collected.
- Pre-reboot identity: machine `mch_9f188aca6d2bf1fccaf63541bd8f42aa`,
  environment `env_ac24f98c7054bafd418d9974bca24779`, generation 1.
  Local status reports ready runtime, but managed SSH is degraded with
  `ssh_key_rejected`. This is separately recorded despite the general doctor
  reporting healthy.
- `pb update --json` succeeds at .24 with no update needed and no runtime change.
- Status recommends `pb ssh doctor <machine>`, but no such subcommand exists in
  current CLI wiring. This diagnostic recovery guidance is invalid.
- Native Windows E2E fixture is running on loopback port 38142 and returns
  HTTP 200 with exact `preview-http-ok\n` body at `/http`.

- Timestamp metadata version 243 expired 2026-09-04T13:00:53.982934222Z.
  Snapshot and targets remain valid. No scheduled refresh exists; release.yml
  only runs for tags/manual dispatch. Existing `tuf-repository refresh` safely
  refreshes snapshot/timestamp without changing release assets.
- Native Victus PowerShell test of the corrected wrapper reports exit 1 for
  a simulated installer exit 7 while still running finally cleanup.

- Dashboard Windows command now stops on download errors and throws on installer
  nonzero exit before its cleanup completes. Seven focused enrollment tests pass;
  diff whitespace check passes.
- Full dashboard type check is blocked by existing errors in
  environment-variables/page.tsx:432 (`enrollmentProof`) and
  environment-e2ee.ts:1189 (`ArrayBuffer | SharedArrayBuffer`). Neither file is
  changed in this recovery pass. These are outside the Windows runtime scope.

## Published 2026.09.05.0 acceptance in progress

- Release workflow 33937054688 succeeded for all five assets and TUF publication.
  Public `https://get.pprbt.dev/current.json` selects `2026.09.05.0`.
- Fresh dashboard-issued Windows Host installation, alias `victus-release-0905`,
  returned exit 0. Installed SHA256 is
  `e627c2b6659e716b8cb6e955dc716ad2ef433c98c84769ac5ef9ce8afd1248d0`,
  matching the published Windows amd64 asset.
- Windows machine `mch_b2979f85f7071eea9e88d7fb5cea7a88`, environment
  `env_13e7e04176adb06dc9868db1369de383`, generation 1. All four services
  (Hostd, LocalDaemon, Sshd, Updated) run automatically from the canonical binary.
  Doctor healthy; explicit `pb update --json` succeeds with no update needed.
- Reboot confirmed at `2026-09-05T01:59:11.5000000Z`. At 02:00 UTC, all four
  services are running automatically, identity remains generation 1, doctor healthy.
  Managed SSH still reports `ssh_key_rejected`, consistent with the recorded account
  key-cap failure. Updater status reports `last_failure: check_failed` at
  01:59:42 with next retry 02:04:42; this is unresolved evidence, not a healthy
  scheduled-check claim. Server-facing update health concurrently says healthy.
- macOS fresh dashboard-issued Host command for `mac-release-0905` installed the
  PKG and accepted enrollment, then failed `native service did not become ready:
  hostd` and rolled back, exit 1. No macOS code or network settings changed.
  launchd records hostd inactive at 07:29:16 and 07:29:26 local time, then removal.
  `/usr/local/bin/pb` is absent after rollback; hostd log is an empty root-owned file.
  This does not establish Developer ID/signing as the cause. macOS downstream
  feature acceptance cannot pass after this failed supported installation.
- Full edge `make check` passes after formatting-only correction to deployment.go.
  Same-carrier dynamic preview route reconciliation has unit and race coverage;
  live deployment and preview verification are still pending.
- Release publication now serves TUF timestamp 245, expiring
  `2026-09-06T01:50:12.495338843Z`. Expiry enforcement remains enabled.
- Fresh release tunnel test with independently verified live origin at
  `127.0.0.1:38142/http` still fails: `pb tunnel create windows-release-0905
  --port 38142 --duration 20m --wait --json` exits 1, preserves
  `tun_h_rZZ2FAjGjzsccHea2AIg`, and reports connector activation uncertain/unavailable.
  No external tunnel success is claimed. A redacted diagnostic bundle was captured:
  correlation `pb-e3a4fd21ff0e65d7c25fb174d357c659`, SHA256
  `2501a9a96289343e238ccf694212ae56622153e4fc0ca357bc8d835e15470a35`.
  It records repeated `metadata_warm` degradation and SSH key rejection but no
  exact tunnel activation diagnostic. Live root cause remains unproven.
- Windows scheduled updater retry at `2026-09-05T02:04:42.1150265Z` completed:
  `last_failure` is now absent, CLI/runtime remain 2026.09.05.0, no activation
  pending, next regular check `2026-09-05T08:24:40.835247693Z`. The boot-time
  check failure recovered through the existing scheduler without intervention.
- First fresh .05.0 preview on the prior edge image reached ready:
  `prv_5f0e005c9faca77796c3382a9b28ae4a`, endpoint
  `https://a235ijqyyiornemwae3a.preview.pprbt.dev`. External `/http` requests
  returned exact body and HTTP 200 in 0.836s and 0.692s; `/sse` delivered both
  events; `/stream` returned the exact POST body. Public `/ws` returned HTTP 502,
  while the same local origin returned HTTP 101 with the correct handshake.
  WebSocket E2E fails; this is independent of same-session route reconciliation.
- Supported `preview stop` succeeded and projected stopped/released/down.
  The observing foreground command then exited 1 with misleading session-invalid
  guidance. No evidence that the machine credential was revoked by the stop.
- Linux ARM64 .05.0 fresh dashboard installation on Dadape accepted enrollment
  but hostd failed `start stable managed_ssh_authority: managed SSH host authority
  is unavailable`, request `req_2eee8b461181b7c610395a4a`. Installer rolled back.
  Later platform tests are blocked by installation, not passed. Account key-cap
  saturation is correlated only; it is not a proven cause of this host failure.
