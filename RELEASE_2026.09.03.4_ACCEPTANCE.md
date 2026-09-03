# Paperboat 2026.09.03.4 clean-install acceptance

Status: testing in progress. No source fixes are permitted until the complete
macOS, Linux, and Windows test pass has been recorded here.

This ledger continues across subsequent release candidates until one final
candidate passes the complete three-platform acceptance matrix.

## Release under test

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
