# Paperboat 2026.09.03.4 clean-install acceptance

Status: testing in progress. No source fixes are permitted until the complete
macOS, Linux, and Windows test pass has been recorded here.

This ledger continues across subsequent release candidates until one final
candidate passes the complete three-platform acceptance matrix.

## Release under test

### Final candidate 2026.09.03.10

- Tag: `2026.09.03.10`
- Commit: `5279785989da5fc16e127943da369e08d85a9b3e`
- GitHub Actions run: `33715204674` (`success`)
- Published at: `2026-09-03T04:35:05Z`
- GitHub release contains exactly the five expected assets. Their GitHub
  SHA-256 digests and lengths exactly match production
  `https://api.pprbt.dev/current.json`.
- The macOS arm64 package was downloaded independently, matched SHA-256
  `5b5122f7b479a9b415f05b2b841c1705701d66e2cd06255f39c4e561e5b28855`,
  installed successfully on the clean Mac, and both installed copies report
  `2026.09.03.10` with identical bytes.
- Fresh dashboard enrollment and the complete platform matrix remain in
  progress.

- Tag: `2026.09.03.4`
- Commit: `7d58d4de569330c091d87360ee7417bb6058157b`
- GitHub Actions run: `33694021891` (`success`)
- Published assets: exactly macOS arm64, Linux amd64/arm64, and Windows
  amd64/arm64.
- Production `current.json`: `2026.09.03.4`; all five sizes and SHA-256 values
  match the GitHub release.
- Development package status: the macOS PKG uses the established ad-hoc
  development signature. Controlled old/current LaunchDaemon execution proves
  this is accepted and is not a cause of the current runtime investigation.

## Issue ledger

### MAC-005: fresh `.10` Host service does not become ready

- Severity: fresh-enrollment blocker
- Reproduction: from a clean Mac, run the exact current dashboard-issued Host
  command with the unique name `mac-final-20260903`.
- Verified prerequisites: the displayed token hash exactly matched the current
  `awaiting_bootstrap` server row; the official macOS arm64 package downloaded,
  verified, and installed; pairing was accepted.
- Actual: native Host setup then returned `native service did not become ready:
  hostd`, classified the failure as `service_install`, and rolled the fresh
  installation back with exit status 1. The rollback removed the binaries,
  service definitions, and runtime state as designed.
- Status: root-cause capture in progress. No code change has been made.

### DASH-001: Copy enrollment command can leave a previous command in clipboard

- Severity: acceptance reliability defect
- Reproduction: create successive enrollments in the local dashboard and use
  `Copy one-shot enrollment command` after the new command is visible.
- Actual: the system clipboard retained the prior failed/expired command. The
  prior token hash was proven not to match the current enrollment row.
- Safety consequence: the copied stale command cannot claim the new enrollment,
  but it causes misleading `invalid_user_machine_pairing` failures.
- Workaround used for evidence only: read the currently rendered command and
  verify its token digest against the current server row before execution.
- Status: recorded for correction after the platform blocker is diagnosed.

### SERVER-001: dashboard POSIX enrollment response is not an executable script

- Severity: fresh-enrollment blocker
- Reproduction: issue a dashboard Host enrollment and pipe the protected
  `get.pprbt.dev/install?p=...` response to `bash`.
- Expected: the response begins with `#!/bin/sh`, exports the embedded one-shot
  enrollment values, and executes the installer.
- Actual: the response placed shell assignments before the shebang, so the
  bootstrap could silently do no installation.
- Root cause: `release_handlers.go` prepended assignments to the base script
  rather than injecting them after its shebang.
- Fix status: fixed and deployed in paperboat-server commit `e7b3ff4`. The
  response now keeps the shebang first, exports both values, and fails closed
  if the base installer has no exact shebang. Focused normal/race tests pass.

### MAC-004: release enrollment resolves the macOS user from poisoned environment

- Severity: fresh-enrollment and service-persistence blocker
- Reproduction: on UID 501 whose real account is `pujan.pm`, execute the
  dashboard-issued enrollment from an environment containing `USER=pujan`.
- Expected: the LaunchDaemon uses the authoritative UID 501 account name
  `pujan.pm`.
- Actual: the generated hostd plist used `UserName=pujan`. launchd failed
  account resolution and later reported service initialization failure. The
  same installed ad-hoc helper runs directly as the user and root and also
  succeeds under a minimal root LaunchDaemon, disproving signing, file mode,
  ownership, helper bytes, and helper path as the cause.
- Root cause: release assets are built with `CGO_ENABLED=0`; pure-Go
  `os/user.Current()` is environment-backed. Enrollment trusted that value
  instead of resolving the kernel UID.
- Fix status: fixed locally by resolving `os.Getuid()` through
  `user.LookupId`. A regression test poisons `USER` and `LOGNAME`; focused
  normal/race hostruntimecmd, hostinstall, and service tests pass. Final release
  and fresh macOS acceptance pending.

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
- Root cause: auxiliary ENV storage failed after durable machine presence had
  already succeeded, but the handler still converted that auxiliary failure
  into HTTP 500. A fresh Host also advertised ENV before its new recipient key
  was authorized, exercising this path continuously.
- Fix status: implemented on both sides. The server preserves HTTP 202 and
  reports typed auxiliary rejection codes after durable presence succeeds; the
  runtime withholds the ENV capability until the exact binding is active.

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
- Fix status: implemented in the current batch.

### LINUX-007: fresh Host advertises ENV Injection before its recipient key is authorized

- Severity: persistent control-plane heartbeat failure
- Reproduction: perform a fresh Host enrollment into an account whose encrypted
  ENV authority already exists, then inspect the runtime ENV cache, active
  authority bindings, and `/v1/runtime-observations` results.
- Expected: the runtime does not advertise `environment_injection` until its
  exact installation-generation recipient key is active, and pending key
  authorization cannot turn the otherwise healthy heartbeat into HTTP 500.
- Actual: the fresh Host created recipient
  `envk_cOVMa89_G8f2PgEeOKW8aXlk8ISI7oGIorxqoxcKKr8`, while the active authority
  had no binding for machine `mch_e8ce6d5666eb5c8be69f62768c5541c3`.
  Its cache remained authority-null but the runtime still sent the ENV
  capability and observation every 15 seconds. The server recorded machine
  presence, then its auxiliary ENV response path returned HTTP 500.
- Evidence: runtime cache and high-water files on Hetzner at
  `2026-09-03T00:01Z`, active authority generation 5 and binding inventory from
  PostgreSQL, plus the continuous hostd/server 500 logs already recorded for
  LINUX-005.
- Fix status: implemented. Capability publication requires exact verified
  binding state, while the server isolates transient auxiliary storage failure
  without weakening ENV integrity or machine heartbeat durability.

### WIN-001: Windows fresh-acceptance harness does not parse

- Severity: acceptance blocker
- Reproduction: invoke `tools/test-windows-fresh-acceptance.ps1 -Phase Audit`
  with either Windows PowerShell or `pwsh`.
- Actual: PowerShell `ParserError` beginning at line 294 because expressions
  such as `-or Test-ReparsePoint ...` require a parenthesized function call.
  The same invalid form exists at lines 329, 557, 620, 623, 628, 652, and 669.
- Fix status: fixed in the current tree. Function-call operands are
  parenthesized throughout the harness; final execution on Victus is pending.

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
- Root cause: the elevated helper inherited the SSH session's
  kill-on-job-close job because its process creation omitted
  `CREATE_BREAKAWAY_FROM_JOB`. It reached `removing` and was killed when the
  SSH caller closed. Release `2026.09.03.7` already contains the isolated
  breakaway fix and regression test.
- Fix status: source fixed. Final fresh Victus acceptance pending.
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
- Fix status: fixed in the current tree. The harness accepts the protected
  dashboard bootstrap URL/command through `EnrollmentBootstrapFile`, extracts
  only the exact `https://get.pprbt.dev/install?p=...` endpoint, and neither
  parses nor prints the opaque value. Final execution on Victus is pending.

### WIN-005: failed uninstall handoff leaves protected installation residue

- Severity: fresh-install blocker
- Read-only Victus inventory after the failed supported uninstall found no
  canonical binary and no Paperboat SCM services, but retained
  `C:\ProgramData\Paperboat\runtime-install.json`, `hostd.token`, managed SSH
  state, service lifecycle state, the stale machine PATH entry, and four
  stopped temporary uninstall helpers.
- The retained install metadata is version `2026.09.03.6`, `committed=false`;
  its configured runtime state root is absent. Windows event history proves
  Hostd and managed OpenSSH were registered during the attempt and later
  removed.
- Expected: the elevated uninstall helper reaches a durable terminal result and
  removes all product-owned state and PATH only after owned services/processes
  have stopped.
- Actual: the parent reported `remove user Paperboat state`, while the detached
  helpers never completed the protected residue cleanup.
- Additional root causes: machine PATH removal was conditional on successful
  lifecycle recovery, successful installs retained trusted bootstrap copies,
  and helper completion scheduled only the executable for reboot deletion,
  leaving its plan, status, and directory indefinitely.
- Fix status: fixed locally. Machine PATH and independently owned state cleanup
  now continue after lifecycle errors while service/binary mutation remains
  fail closed. The exact helper directory is scheduled child-first for
  removal, successful install removes its staging copy, and the Windows audit
  checks PATH and helper residue. Focused tests and Windows amd64/arm64 test
  compilation pass. Final Victus acceptance pending. The unrelated GitHub
  Actions runner and normal system OpenSSH remain explicitly out of scope.

### WIN-006: earlier helpers leave expired protected records

- Severity: clean-install blocker and disk residue.
- Victus retained thirteen direct `%TEMP%\\Paperboat Uninstall\\<32-hex>`
  directories. Four contained expired plans, statuses stuck in `removing`,
  and 50-70 MB helper executables; every recorded process was dead. Nine were
  empty. The pending reboot list contained only the four executable paths,
  proving the older helper did not schedule its plan, status, or directory.
- Fix status: fixed locally. Before creating a new helper, Paperboat now
  inspects only the fixed uninstall namespace and removes an entry only when
  it is direct 32-hex ownership, non-reparse, exact three-file shape with
  protected DACLs, a strict expired five-minute plan, and no live recorded
  process. Empty 32-hex legacy entries are removed. Unknown, malformed, and
  active records fail closed without mutation. The focused tests pass natively
  on Victus. Final release and clean-state acceptance pending.

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

### Linux final-release retest attempt

- Official `current.json` now reports `2026.09.03.5`; its Linux amd64 asset
  was downloaded and verified by the acceptance harness before touching the
  machine.
- Supported uninstall was run with the exact confirmations on Hetzner
  `coolify`. It completed successfully. The pre-fix `.4` user link was found
  as a dangling `/root/.local/bin/pb` symlink and was removed by the supported
  fresh-install rollback path; no Paperboat runtime state, services, sockets,
  or canonical binaries remain. Production server, tunnel, containers, and
  database were not touched.
- The protected dashboard enrollment command in
  `/tmp/paperboat-enroll-coolify-fresh-20260903.mgNsKZ` was supplied directly
  to the remote shell without logging its secret. The official installer
  downloaded `.5`, but server pairing returned HTTP 400
  `invalid_user_machine_pairing`. The installer completed its rollback and a
  second remote inventory confirmed the machine is clean.
- This enrollment artifact is consumed/invalid for the current server state;
  final `.5` Host setup, service/restart/boot persistence, doctor, and preview
  or tunnel E2E cannot be completed until a fresh valid dashboard-issued Host
  enrollment command is available. No credential was fabricated or retried
  through an unsupported path.

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

### Windows final-release retest checkpoint

- The `.5` acceptance harness correctly refused the existing partial install;
  it did not reach fresh installation or consume the protected enrollment
  artifact.
- Current exact state: `PaperboatHostd` and `PaperboatSshd` are running,
  `PaperboatLocalDaemon` is installed but stopped, `PaperboatUpdated` is
  absent, all three product roots remain, and four product `pb.exe` processes
  are running from Program Files.
- The temporary acceptance scheduled task was removed. Victus is neither
  clean nor accepted, and must not be reported as a `.5` result.

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

Started against official release `2026.09.03.5`.

### Control-plane and edge regressions fixed before machine mutation

- `paperboat-server` previously returned HTTP 500 after persisting runtime
  presence when an auxiliary environment, availability, or update observation
  failed. The handler now preserves the durable observation and returns HTTP
  202 with typed `auxiliary_rejections`. Focused normal and race checks passed;
  the production container is running and healthy and `/readyz` reports ready.
- `paperboat-tunnel` health counted only legacy routes, so a canonical route
  made Docker report unhealthy despite every transport component being ready.
  Health now counts legacy and canonical routes. Focused normal and race checks
  passed; the production tunnel container is running and healthy with
  `route_drift=false`.

### macOS final-release retest attempt

- Supported uninstall completed and removed binaries, state, and launchd
  services. The remaining empty product directory and package receipt contain
  no executable or runtime state.
- The official `.5` macOS arm64 package matched release metadata and installed
  successfully. Its established ad-hoc development signature is accepted and
  is not a defect or a supported root-cause hypothesis for this investigation.
- The protected dashboard enrollment command was supplied without logging its
  secret. Pairing returned HTTP 400 `invalid_user_machine_pairing`, confirming
  that the one-shot artifact was already consumed or invalid. The `.5`
  installer rollback then removed the package payload, state, and services.
- Final `.5` service, restart, updater, doctor, preview, and tunnel acceptance
  requires a fresh dashboard-issued Host enrollment command.

### Full diagnostic pass against `2026.09.03.6`

Status: evidence collection in progress. No additional product-code changes
are permitted until the macOS, Linux, and Windows diagnostic passes have all
finished and their complete failure sets are recorded.

- Release workflow `33701796581` completed successfully and production
  `current.json` reports `2026.09.03.6`.
- The macOS dashboard enrollment used a new unique Host name. Pairing was
  accepted, so the previous token and duplicate-name failures were not
  involved.
- Native service setup failed because hostd never served its loopback
  `/healthz`; the installer then rolled back the fresh package, services,
  executable, machine state, and Keychain credentials.
- The opt-in composed native launchd test also missed readiness, but that run
  did not preserve the live launchd projection and therefore did not prove a
  product launchd regression. A later controlled comparison used unique
  LaunchDaemon labels and identical root-owned paths for the known-working
  `2026.09.02.12` binary and current `2026.09.03.6` binary. Both were accepted
  and executed by system launchd. Developer ID, ad-hoc signing, package
  executability, and AppleSystemPolicy are therefore ruled out as causes.
- Both configured launchd stdout/stderr files remained empty and transactional
  rollback removed the declarations before launchd state could be inspected.
  This is a confirmed diagnostic-preservation defect in addition to the
  service readiness failure.
- Windows supported cleanup removed services, processes, scheduled tasks,
  listeners, PATH entry, and user identity state, but left the installed
  binary, ProgramData residue, and four uninstall-helper plans permanently in
  `removing`. Exact evidence is in
  `acceptance/WINDOWS_CLEANUP_EVIDENCE_2026-09-03.md`.
- Linux and Windows fresh `.6` diagnostic runs use separate dashboard-issued,
  hostname-bound one-shot enrollments. They are collecting every independent
  stage result before any new source fix is made.
- Linux release provenance and download succeeded, but the first installation
  exchange returned HTTP 410 and the subsequent pairing returned the generic
  HTTP 400 `invalid_user_machine_pairing`. Server state showed the supposedly
  fresh `coolify-diag-20260903` enrollment already `ready` and bound to a
  different machine identity before the Hetzner installer used it. The
  installer rolled back completely: no binary, services, sockets, runtime
  identity, doctor, preview, or tunnel prerequisite remained. This is a
  cross-machine dashboard enrollment isolation defect, not a reused-command
  retry; no replacement token was issued during the evidence pass.
- Windows began from the recorded incomplete-cleanup residue. The dashboard
  command entered the hosted installer, which launched a hidden elevated
  `RunAs -Wait` process. The elevated inner install wrote `inner_exit=0`, then
  removed the canonical binary and left no Paperboat service, but the outer
  non-interactive PowerShell/SSH process remained blocked for more than nine
  minutes. No prompt could be displayed or answered through that channel.
  This confirms both that the supported installer cannot complete unattended
  elevation over the documented remote acceptance surface and that its exit-0
  inner cleanup is not equivalent to a completed fresh installation. Service,
  updater, persistence, doctor, preview, and tunnel checks are consequently
  blocked by the failed installation prerequisite.

### Historical regression audit before the fix batch

- Enrollment isolation: before server commit `17f316c`, the control plane
  generated a 48-character opaque token and hashed the complete token. The
  Windows enrollment change introduced a 26-character token whose first two
  characters encode role and shell, but deliberately excluded those two
  characters from the credential hash. Dashboard commit `822ea0b` then began
  rewriting those characters locally when the user changed role or platform.
  This made multiple displayed commands aliases for the same one-shot
  credential and explains the cross-machine claim observed on Linux. The
  correct server request contract for immutable role and shell already exists;
  the fix restores full-token hashing and removes client-side token mutation.
- Windows elevation: no Paperboat history contains
  `CREATE_BREAKAWAY_FROM_JOB`; current and prior helpers use only
  `CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP`. The Victus native probe proves
  that an explicit breakaway child survives the SSH job while the shipped
  helper does not. Commit `3a15e5b` added a timeout only after blocking
  `Start-Process -Verb RunAs -Wait`, so it cannot bound the observed broker
  wait. Service declaration and restart persistence remain based on the
  established `790babd` ordered lifecycle and are not being rewritten.
- macOS launchd: the install transaction, binary staging, hostd/updater
  definitions, service arguments, controller, native test child, health port,
  and test executable-copy helper are unchanged from known-working
  `2026.09.02.12`. Unique-label system-launchd execution succeeds for both the
  old and current binaries. The failed reused-label native run was not valid
  evidence of a signing or executable-policy regression; the remaining
  investigation is limited to full runtime state and readiness dependencies.
- Historical production evidence at
  `/private/tmp/paperboat-macos-preclean-20260902T231744Z.log` records release
  `2026.09.03.3` running the same direct helper path as a system LaunchDaemon,
  with hostd, updater, socket, token, and `{"live":true}` health present.
  Comparing `790babd..1a4d61d` shows no production executable path, service
  identity, environment, activation ordering, or updater-declaration change.
- The AppleSystemPolicy rejection belongs only to the native test fixture:
  commit `5c3ff3c` introduced a raw copied `service.test` executable, and the
  retained launchd log reports an absent CMS blob for that fixture. Applying
  a full ad-hoc signature to the copied fixture did not change launchd's
  rejection, while packaged binaries from both the known-good and current
  releases execute under launchd. This is a package-provenance-invalid test
  fixture, not a Developer ID or product signing defect. The opt-in Darwin
  fixture tests now skip explicitly; final macOS acceptance uses the actual
  installed package.
- Dashboard source/test drift: current browser tests still describe an older
  downloaded-credential UI while the current page renders one-shot installer
  commands. This is recorded separately and is not being used to justify a
  product-contract change in this platform recovery batch.

### Dadape ARM64 pre-enrollment attempt against `2026.09.03.10`

Status: canonical product state is clean; fresh Host enrollment and all
post-enrollment checks are blocked because no protected dashboard-issued Host
bootstrap command was supplied.

- Target: `ssh -p 6000 anvit@152.67.0.60`, verified as `dadape`, Debian Linux
  `aarch64`, user `anvit`.
- Initial inventory found the stale user CLI
  `/home/anvit/.local/bin/pb`, version `2026.09.01.11`, plus user runtime
  state, a running `paperboat-local-daemon.service`, and no canonical hostd,
  updater, or privileged system units. Hostd/updater sockets were absent.
- The supported command
  `printf 'UNINSTALL PAPERBOAT\\n%s\\n' "$(hostname)" | "$HOME/.local/bin/pb" uninstall`
  was run twice with the exact confirmations and returned exit code 0 each
  time. The old CLI remained because the pre-fix binary did not remove its own
  user executable; user state, local daemon state, and system runtime state
  were removed.
- Production `current.json` was verified as schema
  `paperboat.release-current/v1`, version `2026.09.03.10`, repository
  `pinksaucepasta/paperboat-cli`. The ARM64 asset was downloaded from its
  immutable GitHub release URL and verified at exactly 44,171,426 bytes with
  SHA-256
  `0304f8ec7e6410480670e6981d9836f90d9aa6fa9c385f0b11c00ee155410812`.
- The no-parameter public bootstrap probe
  `curl -fsSL https://get.pprbt.dev/install | sh -s -- --version 2026.09.03.10 --no-setup`
  returned HTTP 400 (`invalid enrollment parameter`); it did not install or
  mutate the target. The observed shell pipeline status was 0 because the
  empty `sh` process was the final pipeline command; the HTTP response is the
  authoritative result.
- The verified `.10` binary was then used from a temporary path to invoke the
  supported `pb uninstall` confirmations once more. It returned exit code 0
  and removed the stale CLI. Final inventory confirmed no user CLI, user
  Paperboat state, `/var/lib/paperboat*` runtime files, `/usr/local/libexec/paperboat`,
  system or user Paperboat units, hostd/updater sockets, or Paperboat process.
- One empty legacy directory remains at `/var/lib/paperboat-hostd` (owned by
  `anvit`, mode `0700`), and the empty per-user runtime directory
  `/run/user/1000/paperboat` remains. `/var/lib/paperboat-hostd` is not a path
  referenced by the current host installer or purge code; no manual `rmdir`
  or broad deletion was performed.
- Filename-only searches on the local workspace and Dadape found no protected
  enrollment/bootstrap command, and all enrollment-related environment
  variables were unset. No dashboard token was fabricated, printed, retried,
  or written to the repository.
- Because enrollment input was absent, `.10` install/pair, updater apply,
  service/reboot persistence, `pb status`, `pb doctor`, preview E2E, and tunnel
  E2E were not attempted. The next required input is one fresh,
  hostname-bound dashboard Host bootstrap command, supplied through a
  protected file or directly to the interactive shell without logging it.

### Windows Victus `.10` acceptance attempt: target offline

Status: blocked before mutation. No dashboard command was consumed and no
Paperboat or OpenSSH state was changed.

- Read-only preflight command attempted on 2026-09-03:
  `ssh -o ConnectTimeout=10 -o PreferredAuthentications=password
  -o PubkeyAuthentication=no pujan@victus "hostname; whoami; powershell
  -NoLogo -NoProfile -NonInteractive -Command \"Get-Date -Format o;
  Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,
  BuildNumber,LastBootUpTime | Format-List; Get-Service | Where-Object {
  $_.Name -match 'Paperboat|paperboat|pb' } | Select-Object Name,Status,
  StartType | Format-Table -AutoSize\""`.
- Actual result: `ssh: connect to host victus port 22: Operation timed out`.
- Independent local Tailscale check: `tailscale ping --c 3 --timeout=5s victus`
  timed out on all three probes; `tailscale status --json` reported
  `Victus`, `100.109.59.7`, `online=false`, with no current handshake.
- The acceptance harness, fresh dashboard-issued one-shot install, supported
  cleanup, service checks, restart persistence, update, `pb status`, `pb doctor`,
  preview E2E, and tunnel E2E were not attempted because the target was not
  reachable. A fresh protected enrollment command is still required after the
  target returns online.

### macOS fresh one-shot `.10` enrollment failure

Status: reproduced twice with a hostname-bound dashboard command. Enrollment succeeds, but the native host service never becomes ready and the installer performs its documented fresh-install rollback.

- Target: local `apple`, macOS `darwin/arm64`, account `pujan.pm`.
- Exact fresh hostname used for the latest run: `mac-final-20260903e`.
- The one-shot dashboard command installed the signed `.pkg`, reported `Enrollment accepted`, and entered managed host-service setup.
- Running the command without cached sudo authorization displayed no administrator-password prompt and timed out at `native service did not become ready: hostd`.
- Repeating with `sudo -v` successfully authorized immediately beforehand produced the same hostd readiness failure. Therefore missing interactive sudo prompting is a separate installer UX defect, not the proven hostd startup root cause.
- The rollback removed `/usr/local/bin/pb`, both launchd jobs, and both plist declarations. The configured hostd/updater log files exist but contain no process output.
- No manual package install was used for this acceptance run. The dashboard one-shot command was the only installer entry point.
- Required fixes: preserve actionable launchd/bootstrap/process-exit diagnostics through rollback, correct the hostd launch/readiness regression, and make the piped one-shot installer obtain administrator authorization through the controlling terminal when sudo is not already authorized.

### Windows Victus `.10` fresh bootstrap: consumed run failed before installation

Status: blocked. The protected dashboard-issued command was transferred with an
integrity check and consumed exactly once. No retry or manual install/uninstall
was performed.

- Target: `ssh pujan@victus`, verified as `VICTUS`, Windows 11 IoT Enterprise
  LTSC, build `10.0.26100`, 64-bit. The SSH session was elevated
  (`IsInRole(Administrator) = True`).
- The tracked acceptance harness was copied only as acceptance tooling. Local
  Git blob hash: `9bd3986883f5a7b96bc589f21294604c920aba09`; local and remote
  byte SHA-256: `bc0ab9f8b5fccd0c21fcd26859a41e2d816af6bd7f8d5754a1e3200d5dc442df`;
  size: `43,539` bytes. `-Phase Audit` made no changes and returned the
  harness's generic failure because stale `.6` runtime state was present.
- The protected command file was copied to
  `C:\Users\Pujan\AppData\Local\Temp\pb-victus-enroll-command` with mode
  `0600`-equivalent ACLs (SYSTEM, Administrators, and Pujan only). Local and
  remote size: `198` bytes. Local and remote SHA-256:
  `b2cd772cae987ed7dfaaf120289cfb4f3135033996e57a761e9462c5602c12c2`.
- An initial wrapper parse error occurred before reading the protected file;
  the remote hash remained unchanged, so that attempt did not consume the
  command. The corrected elevated PowerShell wrapper then invoked the command
  once, removed the protected file in `finally`, and reported exactly:
  `bootstrap_exit=1` and `bootstrap_exception=System.Management.Automation.RemoteException`.
  The protected file was absent afterward.
- The wrapper redirected all child output with `*> $null`. Consequently the
  exact installer stdout/stderr from the consumed run was not retained and
  cannot be recovered from this execution. This is an observability loss in
  the wrapper, not evidence of a specific installer root cause.
- Read-only post-run inventory at `2026-09-03T05:25:17.8578083Z` found no
  Paperboat service, process, scheduled task, or temporary installer script.
  Existing state was unchanged: `runtime-install.json` still described
  artifact version `2026.09.03.6`, and no new profile or service state existed.
  No Paperboat-related Application or System event was present in the recent
  Windows Event Log query; the only recent service-install event was unrelated
  `UsbNcm Host Service` (Service Control Manager, event `7045`).
- A second read-only inventory at `2026-09-03T05:30:48.9802915Z` confirmed
  `elevated=True`, `PAPERBOAT_SERVICES=none`, `PAPERBOAT_PROCESSES=none`,
  `PAPERBOAT_TASKS=none`, and `temp_command_present=False`. The unchanged
  `runtime-install.json` SHA-256 was
  `179b2a07f1658000300a97e1d1b4842a8468b6eda88687a000fd1ad70efa929a`; its
  control URL remained `https://api.pprbt.dev`, state root remained
  `C:\Users\Pujan\AppData\Local\Paperboat\runtime`, and artifact remained
  `.6` / `pb-windows-amd64.exe` / `https://get.pprbt.dev/tuf`.
- The only retained Paperboat-state SSH service log is
  `C:\ProgramData\Paperboat\ssh\logs\service.log`, 80 bytes, SHA-256
  `dfecd45abb3148b962dec13a2e8b398bbe3c5b8cc8e2a458524430e7fd9497ca`, with
  exactly `Server listening on ::1 port 38222.` and `Server listening on
  127.0.0.1 port 38222.`. The lifecycle lock is zero bytes; no hostd/updater
  helper log or service entry was created by the consumed run.
- A direct Service Control Manager query for the last 60 minutes returned only
  the unrelated event `7045` at `2026-09-03T05:13:30Z` (`UsbNcm Host Service`,
  kernel driver). Application and System queries filtered for Paperboat,
  hostd, and updater returned `none`.
- The installer command itself returned a nested PowerShell remote exception,
  but the wrapper suppressed the nested error text. With no child output,
  service/helper event, process, or state transition, the exact product failure
  cannot be distinguished from an endpoint/download/elevation failure. Do not
  retry the consumed enrollment command until that root cause is proven and a
  new protected command is authorized.
- Since the required enrollment did not complete, `.10` version/service,
  updater, status/doctor, restart persistence, preview, and tunnel checks are
  blocked. Existing OpenSSH state was preserved.

### macOS launchd log-ownership validation and source regression evidence

Status: source fix validated locally on 2026-09-03; package acceptance remains
the required end-to-end check.

- The current `renderLaunchd` rule in
  `internal/hostruntime/service/service.go:312-320` emits `/var/log/<label>.log`
  only when `config.User == "root"`. User-scoped hostd retains its explicit
  `UserName`/`GroupName` at lines `321-325` but receives no privileged log
  path. The regression test at
  `internal/hostruntime/service/service_test.go:181-214` creates a `0600`
  root-only log fixture and asserts that a `pujan.pm` hostd plist has neither
  `StandardOutPath` nor `StandardErrorPath` nor `/var/log/`.
- The piped macOS installer prompt fix remains at `tools/install.sh:354-361`:
  `sudo installer` receives `/dev/tty` when available, while
  `prepare_privileges` already authenticates with `/dev/tty` at lines
  `157-184`. The shell syntax check passed; no password was printed or stored.
- Historical comparison: commit `1a4d61d64533923df92de50de52122a4c9afd639`
  (`preserve macOS service diagnostics and rollback credentials`) first added
  `StandardOutPath`/`StandardErrorPath` for Worker, Host, Hostd, and Updater in
  `internal/hostruntime/service/service.go`. The current guard is the minimal
  correction for non-root launchd jobs; no package payload, helper staging,
  ProgramArguments, ownership, or updater lifecycle change was made here.
- Isolated native launchd smoke used only labels
  `com.pinksaucepasta.paperboat.test-root-log` and
  `com.pinksaucepasta.paperboat.test-no-log`, each running `/bin/sleep 30` as
  `pujan.pm:staff`, from canonical `/Library/LaunchDaemons` plist paths. With
  the pre-existing `/var/log/com.pinksaucepasta.paperboat.hostd.log`
  (`0600`, uid 0, gid 0, zero bytes), the root-log job bootstrapped with rc 0
  but after two seconds reported `active count = 0`, `state = not running`,
  `last exit code = 78: EX_CONFIG`, and `execs = 0`. The no-log control
  bootstrapped with rc 0 and reported `state = running`, `execs = 1`, and a
  `pujan.pm` `/bin/sleep 30` process. Both bootouts returned rc 0.
- Cleanup completed: both temporary jobs were booted out, both temporary
  `/Library/LaunchDaemons` plists were unlinked, temporary `/tmp` plists were
  removed, both labels return `Could not find service`, and the pre-existing
  hostd log remains unchanged (`0600`, uid 0, gid 0, size 0).
- Targeted source checks passed:
  `go test ./internal/hostruntime/service -run
  'TestLaunchdDefinitionIsEscapedValidXML|TestLaunchdNonRootHostdDoesNotUsePreexistingRootOnlyLog|TestHostServiceDefinitionsRunAsRootInBootDomain' -count=1 -v`;
  `go test ./internal/hostruntime/service ./internal/hostruntimecmd
  ./internal/hostruntime/hostinstall`; `sh -n tools/install.sh`;
  `tools/test-macos-install-preservation.sh`; `tools/test-install-current-release.sh`;
  `tools/test-pair-install-rollback.sh`; and `git diff --check`.
- The opt-in composed lifecycle tests were invoked with
  `PAPERBOAT_NATIVE_SERVICE_TEST=1`; both intentionally skip at
  `internal/hostruntime/service/native_composed_darwin_test.go:20-24` and
  `native_darwin_test.go:115-119` because raw Go test binaries do not model
  installed macOS package provenance. They pass as skipped; real package
  acceptance remains the authoritative native lifecycle test.
- Reference evidence matches the ownership rule. Tailscale's system daemon
  plist at `/Users/pujan.pm/workspace/github.com/pujan-modha/tailscale/cmd/tailscaled/install_darwin.go:23-47`
  runs `/usr/local/bin/tailscaled` as a root LaunchDaemon and declares no
  stdout/stderr paths; its install/load/start flow is at lines `103-146`.
  Cloudflared's `/Users/pujan.pm/workspace/github.com/pujan-modha/cloudflared/cmd/cloudflared/macos_service.go:90-129`
  resolves root paths under `/Library` and user paths under the user's
  `~/Library`, including user-owned `~/Library/Logs`; lines `135-145`
  explicitly distinguish a system LaunchDaemon from a user LaunchAgent.
  Therefore a non-root Paperboat hostd must not target a pre-existing root-only
  `/var/log` file; omitting that path is consistent with both precedents.

### Windows Victus `.10` first corrected enrollment: endpoint succeeded, native services rolled back

Status: partially installed, then failed service acceptance. The corrected
dashboard-issued command was consumed once. No retry or manual install/uninstall
was performed by this acceptance run.

- Protected command source: local `/tmp/pb-victus-enroll-command-fixed`, mode
  `0600`, 182 bytes, SHA-256
  `6eff4dc530475125a4cf84c03b8ae19fd851bd6c1dcbf35fda4e161f4c34321f`.
  Remote copy had the same size and SHA-256 and ACL entries only for SYSTEM,
  Administrators, and Pujan. The PowerShell session reported
  `elevated=True` before invocation.
- Capture wrapper metadata is in
  `C:\Users\Pujan\AppData\Local\Temp\pb-victus-enroll-20260903T0540.meta.log`:
  `start_utc=2026-09-03T05:38:33.3980996Z`,
  `end_utc=2026-09-03T05:40:31.6908549Z`, `elevated=True`, `exit=1`,
  `stdout_bytes=0`, `stderr_bytes=395`. The wrapper process exited; no
  Paperboat process remained in the later exact-name query.
- Exact captured installer stdout was empty. Exact captured stderr was:
  `powershell.exe : Completing one-shot machine enrollment...`, followed by
  the standard PowerShell `NativeCommandError` record at the wrapper's
  `& powershell.exe` invocation, `CategoryInfo=NotSpecified` and
  `FullyQualifiedErrorId=NativeCommandError`. The wrapper console ended with
  `bootstrap_exit=1` and the SSH transport emitted only CLIXML progress
  records saying `Preparing modules for first use.` twice.
- The protected capture files remain at
  `C:\Users\Pujan\AppData\Local\Temp\pb-victus-enroll-20260903T0540.stdout.log`
  (0 bytes, SHA-256
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`) and
  `.stderr.log` (395 bytes, SHA-256
  `2a6fc1a15563de1dee13b08937b7a65a7dc2e6f2a4be012910b571c8aa4b18bd`), with
  metadata SHA-256
  `ecf1463756cc608c6fdbf57bed70d835530ef5505654ea866af048ca2a39ee4d`.
- The server trace for this run records the enrollment pairing POST as HTTP
  `201` and the installer endpoint as HTTP `200` at approximately
  `2026-09-03T05:39Z`; therefore the dashboard command itself reached the
  server and was not rejected as an invalid enrollment. The visible installer
  failure occurred after the endpoint began its one-shot enrollment.
- Read-only post-run inventory at `2026-09-03T05:46:31.6907352Z` found
  `C:\Program Files\Paperboat\bin\pb.exe`, 50,030,592 bytes, SHA-256
  `7dc9d4161a34624d8337d21a1cb1d755713bcf977e9f26ea37101f386a23ce8c`,
  matching the `.10` Windows AMD64 release asset. `pb.rollback` also remained
  at 50,030,592 bytes. `runtime-install.json` was absent.
- Service Control Manager recorded installation of `Paperboat OpenSSH Server`
  at `2026-09-03T05:40:21Z` and `PaperboatHostd` at
  `2026-09-03T05:40:30Z`. At `2026-09-03T05:47:07.9535741Z`, `sc.exe query`
  returned error `1060` (service does not exist) for `PaperboatHostd`,
  `Paperboat OpenSSH Server`, `PaperboatUpdater`, and `PaperboatUpdated`, and
  all four corresponding service registry keys were absent. Exact product
  process query returned `none`. No explicit service-delete event was found,
  but the install events followed by absent service definitions, absent
  runtime-install state, and the retained rollback binary prove the service
  setup was not durable and is consistent with installer rollback.
- The retained Paperboat-state SSH log remained only the two listener lines on
  ports 38222; no hostd/updater helper log was created. Existing OpenSSH
  state was preserved. Version/service/updater, restart persistence, status,
  doctor, preview, and tunnel checks remain blocked by the missing native
  services.

### Windows Victus `.11` fresh install and `.12` updater diagnosis

Status: `.11` fresh installation succeeded; `.12` was downloaded and verified
but its pre-cutover worker failed before readiness. Source fixes are locally
verified and final release acceptance is pending.

- The dashboard-issued one-shot Windows Host command installed `.11` through
  the supported installer and completed enrollment. `PaperboatHostd`,
  `PaperboatLocalDaemon`, `PaperboatUpdated`, and `PaperboatSshd` were Running,
  Automatic, LocalSystem, and bound to the canonical binary. `/healthz` returned
  `{"live":true}` and the machine appeared online through the control plane.
- `pb status` and `pb doctor` then exposed `control_plane_unavailable` even
  though direct authenticated inventory and server heartbeat were healthy. The
  verifier-only host lacked an account-root signing seed, and optional automatic
  E2EE approval incorrectly failed the entire inventory. The intended typed
  nonfatal behavior was recovered from historical commit
  `4b6dcca0deaada1b3a779c2e900de14d074d6ee4` and updated for the canonical
  `TrustedKeys` representation in commits `65a0412` and `7720faa` (`.12`).
- The normal `.11` `pb update --json` path downloaded the exact signed `.12`
  target, SHA-256 `8061d697038e0dc33240e6fb2b3b28eddd85a0de42f68acbfa2fd6b5987e485c`,
  length `50058752`, then left the activation journal at `rolling_back` with
  failure `EOF exit status 1`. The canonical `.11` binary and active Hostd,
  LocalDaemon, and SSH services remained intact; Updated stopped after its
  deliberate activator handoff.
- Root cause was introduced by `5c3ff3c`: the LocalSystem activator launched
  the staged candidate without the enrolled owner SID. The child inferred
  `S-1-5-18` and rejected the correct token ACL, which contains SYSTEM full,
  Administrators full, and the enrolled owner read. Direct execution as the
  enrolled owner reached `ready 2 1`, proving the protocol and staged binary
  were sound. The fix passes the exact enrolled SID and retains strict ACL
  validation.
- Two recovery defects were also recorded and fixed: candidate cleanup treated
  a confirmed already-exited child as fatal, and a pre-drain candidate failure
  did not restart the old updater before recording terminal rollback. Cleanup
  is now idempotent after process exit, and terminal candidate rollback is
  published only after the prior service set is live.
- Local evidence after the fixes: affected Windows packages pass normal and
  race tests; affected packages and `cmd/pb` cross-compile for Windows amd64
  and arm64; both Windows CLI binaries build; `git diff --check` passes. Final
  supported update, reboot persistence, status/doctor, preview, and tunnel E2E
  remain mandatory before Windows is accepted.
