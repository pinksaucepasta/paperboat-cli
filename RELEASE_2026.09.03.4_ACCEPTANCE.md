# Paperboat 2026.09.03.4 clean-install acceptance

Status: testing in progress. No source fixes are permitted until the complete
macOS, Linux, and Windows test pass has been recorded here.

## Release under test

- Tag: `2026.09.03.4`
- Commit: `7d58d4de569330c091d87360ee7417bb6058157b`
- GitHub Actions run: `33694021891` (`success`)
- Published assets: exactly macOS arm64, Linux amd64/arm64, and Windows
  amd64/arm64.
- Production `current.json`: `2026.09.03.4`; all five sizes and SHA-256 values
  match the GitHub release.
- Development limitation, not a defect for this pass: the macOS PKG is not
  Developer ID signed or notarized because those credentials do not exist yet.

## Issue ledger

### MAC-001: complete uninstall leaves a dangling user CLI symlink

- Severity: functional cleanup defect
- Reproduction: run the supported `pb uninstall`, confirm both prompts, then
  inspect `~/.local/bin/pb`.
- Expected: no Paperboat executable or symlink remains.
- Actual: `~/.local/bin/pb` remained as a symlink to the removed
  `/Library/PrivilegedHelperTools/Paperboat/pb`.
- Evidence: `/tmp/paperboat-macos-postclean-20260902T232058Z.log`.
- Workaround used for continued testing: removed only the dangling
  Paperboat-owned symlink.
- Fix status: implemented; exact product-owned user symlink cleanup is covered
  by a deterministic uninstall regression test. Final platform retest pending.

### MAC-002: complete uninstall leaves Paperboat Keychain credentials

- Severity: blocker for genuine fresh enrollment
- Reproduction:
  1. Run the supported `pb uninstall` successfully.
  2. Prove runtime/config/state paths and services are absent.
  3. Run the dashboard-generated one-shot enrollment command for a fresh Host.
- Expected: enrollment creates or accepts the fresh account root and completes.
- Actual: installation succeeds, then pairing fails with
  `initialize Paperboat CLI session: enroll CLI peer identity: peer account root public key conflicts with local state`.
- Direct evidence: the login Keychain still contains generic-password records
  whose service is `paperboat` after uninstall.
- Likely boundary: product uninstall deletes indexed files before deleting the
  complete OS credential namespace, so secrets without a surviving profile
  index cannot be enumerated and removed.
- Fix status: implemented; uninstall now purges the complete production
  `paperboat` Keychain namespace instead of relying on surviving profile
  indexes. Final macOS retest pending.

### MAC-003: failed fresh pairing leaves a partially installed product

- Severity: lifecycle rollback defect
- Reproduction: after supported cleanup, run a fresh one-shot Host enrollment
  while the stale Keychain condition from MAC-002 exists.
- Expected: pairing failure rolls the package installation back to the clean
  pre-attempt state, or leaves a resumable transaction with a healthy service
  owner.
- Actual: `/usr/local/bin/pb` and
  `/Library/PrivilegedHelperTools/Paperboat` remain at `.4`, and user state is
  recreated, but hostd, updater, and local daemon are all absent. `pb doctor
  --json` waits for the missing local daemon and fails with a missing Unix
  socket plus `context deadline exceeded`.
- Fix status: implemented for POSIX and Windows fresh installers. Failed pair
  preserves its original exit code while rolling back product-owned user state,
  services, and the exact installed payload. Deterministic POSIX and Windows
  script-contract tests pass; final platform retest pending.

### LINUX-001: complete uninstall leaves a dangling user CLI symlink

- Severity: functional cleanup defect
- Reproduction: run supported `pb uninstall`, then inspect
  `/root/.local/bin/pb`.
- Expected: no Paperboat binary or symlink remains.
- Actual: a dangling, non-executable symlink remains and targets the removed
  canonical binary. This matches MAC-001 and is likely one cross-platform
  uninstall defect.
- Evidence: `/tmp/paperboat-linux-accept-20260902T232104Z-cleanup-residue.log`.
- Fix status: covered by the MAC-001 cross-platform uninstall fix. Final Linux
  retest pending.

### LINUX-002: Linux final-release harness uses an unset install directory

- Severity: acceptance tooling defect
- Reproduction: run `tools/accept-linux-final-release.sh` through its fresh
  release path.
- Actual: `$INSTALL_DIR` is unset at line 529. Testing continued with an
  in-memory substitution only; the repository file was not changed.
- Evidence: `/tmp/paperboat-linux-accept-20260902T232316Z-official-4.log`.
- Fix status: implemented with an explicit canonical install directory and a
  deterministic harness regression test.

### LINUX-003: acceptance harness uses enrollment-only endpoint as tokenless installer

- Severity: acceptance tooling defect
- Reproduction: the harness invokes `https://get.pprbt.dev/install` without a
  `p=` enrollment parameter for install-only verification.
- Expected: install-only verification uses the repository's `tools/install.sh`
  or verifies the immutable asset directly. The hosted `/install` endpoint is
  intentionally enrollment-only.
- Actual: the endpoint correctly returns HTTP 400
  `invalid enrollment parameter`, causing a false harness failure.
- Evidence: `/tmp/paperboat-linux-accept-20260902T232416Z-installer-contract.log`.
- Fix status: harness correction in progress. The server route remains
  enrollment-only; a proposed tokenless server path was reviewed and removed.

### LINUX-004: updater transiently fails after reboot

- Severity: reliability defect
- Actual: the updater initially failed fetching TUF root metadata with HTTP
  521, restarted once, and recovered. Health and doctor remained healthy.
- Evidence: `/tmp/paperboat-linux-accept-20260902T232839Z-post-reboot-stability.log`.
- Fix status: diagnosis pending; determine whether server availability or
  client retry/readiness ordering is responsible.

### LINUX-005: server machine observation returns HTTP 500 after reboot

- Severity: control-plane/runtime observation defect
- Actual: runtime observation repeatedly logs HTTP 500 even though local
  doctor is healthy.
- Evidence: `/tmp/paperboat-linux-accept-20260902T232839Z-post-reboot-stability.log`.
- Diagnosis: this is server-side, not a `.4` client request regression. The
  same server alternated 202 and 500 across multiple machine observations,
  logged database connection refusal during the reboot window, and continued
  returning 500 afterward. It must be repaired in the control plane/deployment
  batch, not by weakening client retries.
- Fix status: server-side follow-up required before final E2E acceptance.

### LINUX-006: managed SSH readiness rejects a normal wildcard sshd listener

- Severity: feature readiness defect
- Actual: server reports runtime, transfer, and preview ready but SSH
  unavailable. The system sshd listens on wildcard addresses, which is also
  reachable through `127.0.0.1:22` and `::1:22`; wildcard binding is not itself
  a readiness failure.
- Evidence: `/tmp/paperboat-linux-accept-20260902T232932Z-machine-readiness.log`
  and `/tmp/paperboat-linux-accept-20260902T232945Z-ssh-readiness-probe.log`.
- Root cause: Unix bootstrap calls `saveBootstrapRegistration(..., "", 0)` for
  Host mode. The resulting machine registration omits `ssh_user` and
  `ssh_port`, so production managed SSH is not constructed despite a healthy
  loopback target. Windows supplies its managed SSH user and port correctly.
- Fix status: source fix pending in the current batch.

### WIN-001: Windows fresh-acceptance harness does not parse

- Severity: acceptance blocker
- Reproduction: invoke `tools/test-windows-fresh-acceptance.ps1 -Phase Audit`
  with either Windows PowerShell or `pwsh`.
- Actual: PowerShell `ParserError` beginning at line 294 because expressions
  such as `-or Test-ReparsePoint ...` require a parenthesized function call.
  The same invalid form exists at lines 329, 557, 620, 623, 628, 652, and 669.
- Fix status: not started.

### WIN-002: supported unpair cannot persist the machine transition

- Severity: lifecycle defect
- Reproduction: run `pb unpair` on the existing Victus Host installation.
- Actual: first attempt returns temporarily unavailable; retry returns
  `save machine registration: invalid machine identity store`.
- Root cause: after changing the registration to `setup_mode=client`, unpair
  retained the host-only `ssh_user` and `ssh_port`. Registration validation
  correctly rejected that impossible client/SSH combination.
- Fix status: implemented by clearing the host-only SSH target atomically with
  the client transition. Final Windows retest pending.

### WIN-003: supported uninstall exits before user-state cleanup completes

- Severity: cleanup blocker
- Reproduction: run `pb uninstall` and provide both supported confirmations.
- Actual: the elevated cleanup helper starts, but the command exits 1 with
  `Failed: remove user Paperboat state`. Immediate helper status remains
  `removing`; services are absent but product roots/processes remain, so
  cleanup cannot yet be accepted.
- Fix status: not started. First determine whether the helper reaches a
  terminal state or is stuck.
- Follow-up at `2026-09-03T05:01+05:30`: cleanup did not converge. Hostd and
  Paperboat SSH services/processes returned to running, LocalDaemon remained
  installed but stopped, and all three product roots remained. No terminal
  uninstall status file was discoverable under LocalAppData.

### WIN-004: fresh-acceptance token input disagrees with dashboard output

- Severity: acceptance/install contract mismatch
- Actual: `pb machine add` emits an opaque hostname-bound 48-character `p=`
  parameter, while the Windows harness requires a raw 26-character enrollment
  token file. The supported dashboard output intentionally does not reveal
  that raw token.
- Fix status: not started.

## macOS test record

- Pre-clean inventory:
  `/tmp/paperboat-macos-preclean-20260902T231744Z.log`.
- Supported uninstall: succeeded and reported complete removal.
- Post-clean inventory:
  `/tmp/paperboat-macos-postclean-20260902T232058Z.log`.
- Fresh `.4` PKG download: SHA-256
  `08720203aace27a6c5ce889f546948fc1624fd07e96201a734d82d6a0510a7e1`,
  size `33487123`, matching `current.json`.
- Fresh enrollment: blocked by MAC-002 after package installation.
- Remaining tests pending: services, updater, restart, doctor, preview E2E,
  tunnel E2E, cleanup.

## Linux test record

Testing in progress on Hetzner `coolify`.

- Interim observation at `2026-09-02T23:27Z`: the machine is already running
  `.4` hostd, updater, local daemon, host service, and `.4` runtime worker.
  This is not yet accepted as a clean-install result because the agent's
  cleanup/install transcript and residue proof are still pending.
- Hosted `paperboat-server` and `paperboat-tunnel` containers/processes are
  separate infrastructure and must not be counted as user-runtime residue or
  removed by the fresh user-machine test.
- Supported cleanup completed. Runtime services, binaries, sockets, state, and
  indexed credentials were absent; LINUX-001 remained.
- Fresh one-shot enrollment and managed Host setup succeeded.
- Official `.4` Linux amd64 asset matched SHA-256
  `bb3a9092cd20d2c7f914e59b879c0e7c8dee9cbccd13ea783f6b1d31860cb7ad`
  and length `48967842`.
- Canonical binary, enabled/active hostd and updater, sockets, health, update
  check/status, and doctor passed before restart.
- Reboot persistence passed: boot ID changed; identity, `.4` hash, services,
  health, updater, and doctor remained valid after reconnect.
- Evidence:
  - `/tmp/paperboat-linux-accept-20260902T231943Z-cleanup-preflight.log`
  - `/tmp/paperboat-linux-accept-20260902T232025Z-cleanup.log`
  - `/tmp/paperboat-linux-accept-20260902T232233Z-fresh-enrollment.log`
  - `/tmp/paperboat-linux-accept-20260902T232509Z-verification-pre-restart.log`
  - `/tmp/paperboat-linux-accept-20260902T232549Z-restart-persistence.log`
  - `/tmp/paperboat-linux-accept-20260902T232806Z-post-reboot-doctor.log`
- Preview and tunnel E2E remain pending because the supplied Linux harness does
  not exercise them.

## Windows test record

Testing in progress on Victus.

- Interim pre-clean observation at `2026-09-03T04:58+05:30`: only
  `PaperboatHostd`, `PaperboatLocalDaemon`, and `PaperboatSshd` are registered;
  `PaperboatUpdated` is absent. Multiple hostd/local-daemon processes are live,
  and the active runtime worker reports `.3`. This confirms the known partial
  old installation but is not yet a `.4` fresh-install result.
- Pre-clean platform: Windows `10.0.26100.9168`, user `Pujan`.
- Existing `pb.exe`, ProgramData, and LocalAppData roots were non-reparse
  objects. Runtime metadata was valid but uncommitted and identified `.2`;
  the active worker identified `.3`.
- Runtime and Paperboat SSH listeners were healthy, and `pb doctor --json`
  passed before cleanup.
- Fresh acceptance is currently blocked by WIN-001 through WIN-004. No raw
  service deletion, firewall mutation, or broad deletion was used.

## Fix batch

In progress after completing the initial platform failure discovery:

- MAC-001/LINUX-001: user-state purge now includes the exact
  `~/.local/bin/pb` product link and removes dangling links without traversal.
- MAC-002: complete uninstall now purges the entire Paperboat-owned production
  credential namespace from macOS Keychain. Linux removes matching Secret
  Service items when a session store exists; Windows removes its dedicated
  DPAPI credential directory. This does not touch the separate TUF production
  signing service namespace.
- Focused config/uninstall tests pass normal and race. Windows amd64/arm64,
  Linux arm64, and macOS arm64 config test binaries cross-compile.
- MAC-003: the POSIX and Windows bootstrap installers now retain control of a
  failed fresh pair and roll back product-owned services, state, and the exact
  installed payload while preserving the original failure status.
- WIN-001/WIN-004: the PowerShell acceptance harness parses on Victus and can
  consume exactly one protected dashboard-generated enrollment URL, `p=`
  field, or command without logging the opaque material. Raw-token input stays
  available for isolated fixtures.
- WIN-002: unpair clears host-only SSH fields before saving the client-mode
  registration.
- WIN-003: Windows purge attempts all independently owned cleanup steps and
  removes restartable SCM declarations before terminating orphan processes.
  The installed CLI reports a protected helper handoff, not terminal success,
  because the helper must wait for that CLI process to exit before deleting
  the locked executable root; the acceptance harness proves terminal cleanup.
- LINUX-002: the final-release harness uses the canonical install directory and
  has a deterministic regression test.
- LINUX-006: Unix Host bootstrap persists the enrolled operating-system user
  and loopback port 22, allowing managed SSH readiness to be constructed.
- Full source gate: `GOTOOLCHAIN=go1.26.6 make preflight` passed contracts,
  dependency/source policy, metrics, hosted-image checks, formatting,
  generation, tidy, vet, all tests, the full race suite, all five release
  cross-builds, Windows release-pipeline validation, and workflow lint.

## Final retest

Not started.
