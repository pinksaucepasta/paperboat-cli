# Windows cleanup and release acceptance evidence

Date: 2026-09-03  
Host: `VICTUS`  
Scope: supported Paperboat cleanup diagnostics and the follow-up Windows release acceptance plan.

## Disposition

This records the pre-fix evidence snapshot. The subsequent source fix is
tracked in the release acceptance ledger; no enrollment credential or
protected bootstrap value is recorded here. The fresh Windows enrollment was
not consumed while this snapshot was collected.

The supported cleanup reached a runtime-clean state but did not reach a
product-clean state. The remaining product-owned paths and stale helper plans
are recorded below. They must remain available for the next diagnostic pass;
they must not be removed with ad-hoc filesystem commands.

## Authoritative Victus snapshot

The final read-only inventory was collected after the supported runtime purge,
the supported product uninstall handoff, removal of only temporary diagnostic
artifacts, and a second read-only probe.

| Area | Observed result |
| --- | --- |
| `Paperboat*` Windows services | None. This includes `PaperboatHostd`, `PaperboatLocalDaemon`, `PaperboatUpdated`, and `PaperboatSshd`. |
| Paperboat processes | None: no `pb.exe` or `paperboat-uninstall-helper.exe`. |
| Paperboat scheduled tasks | None under the Paperboat namespace. |
| Machine PATH | No Paperboat entry. |
| Paperboat listeners | None. TCP 22 is owned only by the normal OpenSSH service, PID 6308, on `::` and `0.0.0.0`. |
| User state | `C:\Users\Pujan\AppData\Local\Paperboat` absent; `C:\Users\Pujan\AppData\Roaming\Paperboat` absent. |
| Machine identity/config/token | `runtime-install.json`, `hostd.token`, and the machine identity state are absent. |
| Installed binary residue | `C:\Program Files\Paperboat\bin\pb.exe`, 70,396,416 bytes. |
| ProgramData residue | `availability-policy.json`, `PaperboatHostd-worker-startup-error.log`, `PaperboatUpdated-startup-error.log`, empty `service-lifecycle\service-lifecycle.lock`, and empty `ssh` directory. |
| Temporary helper state | Four stale helper directories contain an executable, `plan.json`, and `status.json`; each status is `state: "removing"`. Nine additional Paperboat uninstall directories are empty. |
| Test artifacts | The temporary source-built `pb-windows-clean.exe` and the detached-process marker were removed. |

### Stale helper plans

The plans below were left by supported uninstall attempts. Their recorded
process IDs no longer exist.

| Directory | Recorded process ID | Created | Last status update | Helper size |
| --- | ---: | --- | --- | ---: |
| `38aeceb253eef84e0cd677365c8d2d49` | 13564 | 2026-09-02 23:29:06Z | 2026-09-02 23:29:10Z | 70,396,416 bytes |
| `67328a245d5b697816e1dd88d9a12a2b` | 16364 | 2026-09-03 00:53:57Z | 2026-09-03 00:54:01Z | 70,404,608 bytes |
| `678f66461860ecd26a12caa5fc5ad2cc` | 2116 | 2026-09-03 00:49:45Z | 2026-09-03 00:49:49Z | 70,396,416 bytes |
| `aaf51ce13c52561b10110bd518a5cd09` | 16612 | 2026-09-02 19:23:15Z | 2026-09-02 19:23:20Z | 49,972,224 bytes |

The nine empty temporary directories are:

`1a0bdccbdeae14311238164a4896022a`,
`4e169943b6ea54b6fa268c6e955fd8c2`,
`5776418e6f6a4ab88ddde786cbe86850`,
`801161fe78a8dd8ed0487439f6903196`,
`86ac34280debd1bfc925f6e49399c481`,
`90a11a904d7e50a8639186defb1d1430`,
`b558f8f2909a50493c24c54e5ff2f494`,
`c253cf1290e5d940fb988cc6581db48f`, and
`e6befc30029b071f881648f0fdb8c8c7`.

## Supported cleanup evidence

The following sequence was exercised against the installed runtime and a
source-built development binary. The development binary was removed after the
probe. No Paperboat-owned state was deleted outside supported commands.

1. The installed `.3` `pb uninstall` was run with the exact confirmation and
   hostname prompts. It handed off to an elevated helper, reported user-state
   removal failure, and left services, processes, roots, and a helper status in
   `removing`.
2. The source-built `__runtime-service purge` exited successfully. It removed
   all Paperboat services and runtime processes, removed the Paperboat machine
   PATH entry, and left product-root/user-state cleanup to the product
   uninstall boundary.
3. The source-built supported `pb uninstall` exited successfully and reported
   that user state was removed and system cleanup had started. Its helper then
   disappeared while its status remained `removing`; the installed binary and
   ProgramData residue remained.
4. A final read-only probe confirmed the snapshot above. Normal OpenSSH on
   port 22 was intentionally left untouched.

## Root-cause evidence

Victus SSH session processes are members of a Windows job object. A native
read-only job query returned limit flags `0x2800`, which combine:

- `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (`0x2000`), and
- `JOB_OBJECT_LIMIT_BREAKAWAY_OK` (`0x0800`).

The affected `paperboat/internal/windows/elevation/bridge_windows.go` launched an
already-elevated detached child with `CREATE_NO_WINDOW |
CREATE_NEW_PROCESS_GROUP`, but omits `CREATE_BREAKAWAY_FROM_JOB`. Therefore an
uninstall helper launched from SSH inherits the kill-on-close job and is
terminated when the SSH caller exits. It has already written `removing`, but
cannot finish `performWindowsSystemUninstall`, write `completed` or `failed`,
or remove its plan and product root.

An independent native process-creation probe used the same no-window and new
process-group flags plus `CREATE_BREAKAWAY_FROM_JOB`. The child survived the
SSH session close and wrote a marker after the parent session exited. The
marker was then removed as a test artifact. This isolates process detachment as
the cleanup blocker rather than a service, listener, or user-state residue.

### Sanitized diagnostic probes

The probes used a preconfigured SSH connection and did not print credentials.
Equivalent sanitized commands are shown here; replace placeholders locally and
never put a password, token, private key, cookie, or authorization header in a
command line or evidence file.

```powershell
# Run from an elevated Windows PowerShell session on the target.
Get-CimInstance Win32_Service |
  Where-Object Name -like 'Paperboat*' |
  Select-Object Name,State,StartMode,StartName,ProcessId,PathName

Get-CimInstance Win32_Process |
  Where-Object Name -in @('pb.exe','paperboat-uninstall-helper.exe') |
  Select-Object Name,ProcessId,ParentProcessId,CommandLine,ExecutablePath

Get-ScheduledTask -ErrorAction SilentlyContinue |
  Where-Object { $_.TaskPath -like '\Paperboat\*' -or $_.TaskName -like 'Paperboat*' } |
  Select-Object TaskPath,TaskName,State

Get-NetTCPConnection -State Listen |
  Select-Object LocalAddress,LocalPort,OwningProcess

Get-ChildItem -LiteralPath 'C:\Program Files\Paperboat' -Force -Recurse
Get-ChildItem -LiteralPath 'C:\ProgramData\Paperboat' -Force -Recurse
Get-ChildItem -LiteralPath (Join-Path $env:LOCALAPPDATA 'Paperboat') -Force -Recurse -ErrorAction SilentlyContinue
```

The repository harness remains the canonical acceptance probe:

```powershell
& '<checkout>\paperboat\tools\test-windows-fresh-acceptance.ps1' -Phase Audit
```

## Verification evidence

Normal tests passed from the `paperboat` module:

```text
go test ./internal/windows/elevation ./internal/hostruntime/hostinstall
ok   github.com/pinksaucepasta/paperboat/internal/windows/elevation
ok   github.com/pinksaucepasta/paperboat/internal/hostruntime/hostinstall
```

Windows amd64 test compilation passed with `CGO_ENABLED=0` for:

```text
./internal/windows/elevation
./internal/hostruntime/hostinstall
./cmd/pb
```

The generated test executables were removed. This section records the
diagnostic state before the source fix.

## Failure-continuing Windows release checklist

Run the following as one diagnostic session on the disposable Windows host.
Each row is an independent acceptance stage. A failed row must record its UTC
timestamp, exit code, bounded duration, redacted stdout/stderr paths, and an
object/state snapshot, then continue to the next row. If prerequisites are
missing, mark the row `blocked-by-prerequisite` and still run its diagnostic
probes. Do not retry enrollment material automatically.

| Stage | Required actions | Pass evidence and failure continuation |
| --- | --- | --- |
| 0. Evidence setup | Create a private evidence directory outside the repository. Record host, OS build, architecture, current release, free disk, current user/admin status, and UTC start time. | The manifest contains only redacted metadata. Any setup failure is recorded, then the object inventory still runs. |
| 1. Clean preflight | Run `tools/test-windows-fresh-acceptance.ps1 -Phase Audit` and independently inspect services, legacy tasks, `pb.exe` processes, listeners, PATH, reparse attributes, ACL ownership, Program Files, ProgramData, LocalAppData, RoamingAppData, and the Paperboat temp helper directory. | Clean means no Paperboat-owned services/tasks/processes/listeners and no owned roots. If not clean, preserve every file/status/log, mark the release run blocked, and continue diagnostic collection. Do not use raw `Remove-Item` or `sc delete` to manufacture a clean baseline. |
| 2. Release provenance | Verify the pinned `current.json` schema, exact release version, Windows architecture asset, immutable release URL, declared byte length, SHA-256, and signature/provenance before installing. | Save metadata and digest only, never bootstrap contents. If provenance fails, record it and continue with service/state probes; do not install an unverified binary. |
| 3. Fresh install and enrollment | Generate one dashboard Host enrollment for a unique machine name that does not already exist. Place the protected bootstrap URL/command in a caller-owned file. Run the signed `tools/install.ps1` or `tools/test-windows-fresh-acceptance.ps1 -Phase Fresh` with the mutation gate and a protected bootstrap file. Consume the bootstrap exactly once; never echo, log, copy, or retry its opaque value. | Verify installed version, exact binary digest, installation metadata, setup mode, machine ID, environment ID, alias, and identity-file fingerprint. On install or pairing failure, capture rollback state, service/task/process/root inventories, and installer logs; continue to updater, reboot, doctor, preview, tunnel, and final cleanup probes as `blocked-by-prerequisite` where necessary. |
| 4. Runtime services | Verify exact `PaperboatHostd`, `PaperboatLocalDaemon`, and `PaperboatUpdated` SCM definitions, automatic start, LocalSystem account, executable path, role arguments, live process ownership, service logs, and restart policy. For Host mode also verify exact `PaperboatSshd`, owned `sshd.exe`, loopback-only listeners on `127.0.0.1` and `::1`, and no duplicate/legacy service names. | All expected roles are running from the installed canonical binary and no unexpected Paperboat service/process exists. If a role fails, record SCM queries, process trees, listeners, and logs, then continue without repeatedly restarting a crashing role. |
| 5. Runtime health | Validate the loopback `/healthz` response is HTTP 200 JSON with exactly `{"live":true}`. Run `pb status --json` and retain a redacted response with machine eligibility/runtime readiness. | Health, status, and identity agree. If health fails, capture endpoint errors and local runtime logs, then continue to updater and persistence diagnostics. |
| 6. Updater | Run `pb update status --json`, verify CLI/runtime versions, available runtime, no pending activation, no activation failure, and no supervisor maintenance requirement. For the update phase, invoke the signed `pb update --json` path once and poll the bounded status window. | TUF metadata and asset verification succeed, activation converges, services return healthy, and the machine identity fingerprint is unchanged. On failure, preserve updater metadata/logs and activation state, then continue to reboot and post-reboot checks. |
| 7. Service restart and reboot persistence | Capture an identity snapshot. Restart `PaperboatHostd`, wait for bounded readiness, recapture services, health, SSH, status, updater, and identity. Then reboot once through the normal Windows restart path, reconnect, and repeat the full service/listener/health inventory. | Service definitions, machine ID, environment ID, alias, setup mode, and identity fingerprint remain unchanged across restart and reboot. If reconnect or readiness fails, preserve boot/service logs and continue with doctor, preview, tunnel, and cleanup diagnostics. |
| 8. Doctor | Run `pb doctor --json`, `pb status --json`, and the supported local health checks. Record only redacted JSON and typed failure codes. | Doctor is healthy, authentication is valid, local state is valid, and machine/runtime reachability is ready. A doctor failure does not stop the session; continue to feature probes and collect the exact recovery class. |
| 9. Preview E2E | Start a deterministic local HTTP fixture on an unprivileged loopback port. Run `pb preview <port> --duration <bounded-duration> [--private]`, verify the returned preview reaches the fixture from an approved external test client, run `pb preview list --json`, then run `pb preview stop <id> --json`. | Preview reaches `ready`, serves the expected fixture, appears in list output, and reaches `stopped` with no orphan local carrier/session/state. Redact endpoint URLs if they contain opaque values. On failure, still run list/stop and inspect preview/runtime logs. |
| 10. Tunnel E2E | Use a disposable tunnel name and approved test route. Run the supported `pb tunnel` create/route/connector workflow, wait for the bounded operation result, verify connector readiness and the route from an external client, run tunnel health/doctor, then pause/delete or otherwise use the supported teardown. | The tunnel, route, connector, and edge report ready; data reaches the fixture; teardown converges; and no connector process/journal remains. If creation is uncertain, query the canonical tunnel and operation state before any retry, record the recovery command, and continue to log capture and cleanup. |
| 11. Log and support-bundle capture | Collect Paperboat service logs, updater/startup logs, Windows Application/System/SCM events for the run window, service/process/task/listener inventories, PATH, ACL/reparse results, health/status/doctor JSON, and preview/tunnel operation IDs. Use the supported tunnel doctor preview/write-bundle flow only when explicitly requested. | Every failure has a redacted, timestamped artifact and manifest hash. Never include enrollment bootstrap contents, auth headers, cookies, private keys, DPAPI material, control tokens, or full opaque URLs. If a collector fails, record the collector failure and continue with the remaining collectors. |
| 12. Supported uninstall and final clean audit | Stop active previews/tunnels through their supported commands. Run the exact supported `pb uninstall` confirmation flow once. Wait for the documented handoff/status protocol, then run the audit harness and independent inventory repeatedly within its bounded window. | Final clean means no Paperboat services, tasks, processes, listeners, PATH entries, binaries, ProgramData/user roots, identity/config/token files, or helper plans/status directories. Preserve any failed helper plan/log and report the exact residue; do not manually delete it. |

### Continue-on-failure execution contract

The operator or wrapper should model each row as an independent result rather
than using a fail-fast shell chain:

```powershell
$results = @()
foreach ($stage in $stages) {
    try {
        & $stage.Action
        $results += [pscustomobject]@{ Name = $stage.Name; State = 'passed' }
    } catch {
        # Store only a redacted error class and the artifact paths.
        $results += [pscustomobject]@{ Name = $stage.Name; State = 'failed' }
        & $stage.Diagnostic
    }
}
$results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath '<redacted-manifest>'
if (@($results | Where-Object State -ne 'passed').Count -gt 0) { exit 1 }
```

The wrapper must not treat a failed enrollment as permission to consume a new
bootstrap value, and must not treat a failed uninstall as permission to bypass
the supported cleanup boundary. A failed run exits nonzero only after all
independent diagnostics and redacted log capture have completed.
