# PROGRESS.md — paperboat-cli

Running record of what has been implemented and what release evidence remains.
Update this as work lands. (Repo docs live in [AGENTS.md](AGENTS.md);
product source of truth is the workspace `USERSTORY.md`.)

## Status at a glance

**Phase 10 security/operations implementation is complete; release evidence remains.**
CLI protocol negotiation and actionable incompatibility handling are implemented.
The production
descriptor target is a tunneled papercode HTTP/WSS endpoint plus scoped auth. The CLI now
uses that descriptor to attach through papercode WebSocket terminal RPC. Production
commands require a configured Paperboat server and authenticated profile; they never fall
back to a local shell or dummy credentials.

Release preparation now includes `make release-metadata`, which emits a
versioned binary, SHA-256 checksum, and provenance metadata. Signing, SBOM
generation, and publication remain release-pipeline responsibilities.

Tag releases now cross-build macOS/Linux/Windows for amd64/arm64 and publish
SHA-256 checksums, SPDX JSON SBOMs, and GitHub OIDC-backed provenance
attestations. Package-manager publication and a hosted workflow run remain
pending. Each release runner performs native binary version,
install, replacement-upgrade, alias (Unix), and uninstall smoke checks before
publishing.

The publish job derives checksum-bound Homebrew and Scoop manifests from the
actual release archives and uploads them with the signed release assets.

Operational runbooks now cover WorkOS, signing-key, agentunnel, Fly, papercode
authorization, device-grant, stolen-device, and staged-upload cleanup incidents.

`internal/telemetry` defines the metadata-only CLI event boundary and rejects
URLs, paths, whitespace-bearing values, and negative measurements before an
event reaches a sink. Production connects append validated events to a private
`0600` JSONL log beside the CLI config by default; the path is configurable and
managed installations can explicitly disable it.

The staged-image uploader records validated result/size/latency measurements,
and the terminal reconnect supervisor records reconnect outcomes and total
connection lifetime. Resolver, uploader, and reconnect supervision share the
production file sink.
Project resolution also records overall connect outcome/latency and cold-start
stage transitions with project/environment identifiers only.
Structured API errors preserve validated server request IDs for operator
correlation; unsafe or content-bearing identifiers are discarded and never
echoed.

The resolver now follows server-provided readiness retry hints, emits cold-start progress
on stderr, re-brokers for fresh terminal credentials once the route is ready, and validates
project, scheme, scope, and credential expiry fields before dialing.

Terminal sessions now report human input and agent output through the authenticated activity
endpoint with a one-event-per-second limiter and asynchronous callbacks that cannot block PTY
traffic. Each report obtains the current profile credential; a 401 forces one serialized
refresh-and-retry, so long-lived sessions continue resetting server-owned idle detection.

Ready descriptors are bound to the normalized Paperboat issuer. Unexpected transport loss is
supervised with bounded re-brokering and stable terminal reattach; failed writes are never
replayed, so reconnect cannot duplicate terminal input.

- Build: `make build` → `bin/pb`. `gofmt`/`go vet` clean, `go test ./...` green.
- Verified with automated control-plane and terminal protocol harnesses (see "Verification"
  below); hosted infrastructure validation remains.

### Real backend wiring (this pass)
- **`internal/api`** — bearer-authenticated paperboat-server control-plane client. Speaks
  the frozen JSON envelope (`{"data"}` / `{"error":{code,message}}`). Project listing
  follows the server's pagination contract. Methods: `Me`, `ListProjects`, `CLIConnect`,
  `ConnectionStatus`.
- **`internal/resolver.APIResolver`** — matches the requested token to a project by id then
  case-insensitive name, calls `cli-connect` (authorizes + reconciles agentunnel resources +
  resumes an idle machine), and polls `connection-status` until connectable, re-brokering
  once when the ready status lacks routing detail. Returns a client-safe papercode
  WebSocket `TerminalTarget` (+ file-upload `UploadTarget`). Poll timeout/interval are
  config-driven (`connect.*`).
- **`internal/tunnel.PapercodeWSTunnel`** — production terminal transport. Connects to the
  descriptor's `/ws` route with a WebSocket ticket, speaks papercode's Effect RPC JSON
  socket envelope, calls `terminal.attach` with `restartIfNotRunning: true`, streams output
  chunks, sends `terminal.write` and `terminal.resize`, closes with `terminal.close`, and
  returns remote exit status.
- **`internal/tunnel.SSHTunnel`** — retained only as optional debug/operator plumbing, not
  selected for real `server_url` attaches.
- **`cmd/pb`** — production connection commands require `server_url`; `doctor` verifies backend auth
  via `GET /api/me`, and `pb doctor <project>` brokers a descriptor, performs a real
  `terminal.attach`, validates a streamed RPC chunk and acknowledgement, then detaches without
  sending destructive `terminal.close`.
- **`cmd/pb projects`** — lists all paginated server projects. Connect and keep-alive
  resolution prefer exact IDs, accept only unambiguous case-insensitive names, and report
  matching IDs when a name is duplicated.

## What was built

### Command surface (`cmd/pb`)
- `pb <project>` asks the control plane to resume the VM and attaches its terminal. `paperboat` is an
  install-time symlink alias (urfave/cli derives the program name from argv[0]).
- Session-scoped `--agent` and `--size` overrides were removed in Phase 0 because neither
  had an implemented server/runtime contract. Presets and machine type remain project
  configuration applied through the control plane.
- Subcommands: `connect`, `projects`, `keep-alive`, `auth`, `doctor`, and `config path|show`.
- `normalizeArgs` reorders tokens so flags work **before or after** the project name
  (urfave/cli otherwise stops flag parsing at the first positional).

### Config and auth (`internal/config`)
- JSON config loaded from `$PAPERBOAT_CONFIG` or the user config dir; missing files are
  reported only when a command needs their policy. Connection timeouts, retries, accepted
  descriptor kinds, server URL, and upload policy come from the profile or broker descriptor.
- Versioned profiles contain normalized issuer, account/session metadata, token expiry, and
  opaque secret references. Tokens use the OS credential store by default; an explicit
  headless fallback enforces `0600`. Profile writes are atomic and inter-process locked.
- `pb auth login|status|logout|switch` implements device approval, cancellation, best-effort
  browser opening, account replacement, and session revocation. Expiring access tokens rotate
  under the profile lock; concurrency coverage verifies one refresh-token use.
- Revocation is durable and retryable: logout, account switching, and failed post-issuance
  validation move refresh tokens to OS-store-backed pending records. Local cleanup completes
  only after the server confirms revocation; later auth commands retry unfinished records.
- The native credential identifiers are aligned with papercode desktop's `keytar` adapter on
  macOS, Windows, and Linux. Papercode consumes schema-validated metadata in its main process;
  renderer code never receives Paperboat access or refresh tokens.

### Transparent terminal wrapper (`internal/session`)
- Raw mode (skipped when stdin isn't a TTY), SIGWINCH resize propagation (unix; no-op on
  windows via build tags), remote↔local stream copy, exit-code passthrough, clean teardown.
- `conn.Wait()` is the source of truth for session end (fixed a bug where normal output EOF
  looked like an error).

### Image-paste bridge (`internal/paste` + `internal/upload`) — the risk center
- Streaming bracketed-paste state machine (`ESC[200~ … ESC[201~`) that survives split reads,
  partial markers, and adjacent/multiple pastes.
- Asynchronous input recovery handles `ErrWriteUncertain` internally: it discards only the
  affected buffered paste, invokes the reconnecting destination's discard hook, and keeps
  subsequent queued input available after transport recovery.
- Fatal asynchronous destination errors are delivered directly to the session supervisor,
  which tears down the connection instead of leaving terminal input silently disabled.
- Watch-directory authorization and image preparation share one open descriptor; canonical
  containment is verified with `os.SameFile`, and growth is read through the configured
  byte limit rather than truncated to a stale stat size.
- Detects local image paths (strict quotes/`file://`, canonical symlink-resolved watch-dir
  containment), uploads via
  the `Uploader` interface, and rewrites the paste to the returned VM path. Non-image pastes
  pass through byte-for-byte. **Fail open, visibly**: on any failure the original paste is
  emitted and a notice is written to the local terminal.
- Encoder mirrors papercode's `UploadChatImageAttachment` format/limits (base64 dataURL,
  10 MB/image, 8 attachments, ~14 M dataURL chars, `image/*`) so the real transport is a
  drop-in.

## Production implementations

Production commands require `server_url`; local-shell, fake resolver, and fake uploader
implementations have been removed from production packages. Tests use focused in-test fakes
behind the same interfaces.

| Interface | Production | Remaining evidence |
| --- | --- | --- |
| `resolver.ProjectResolver` | `APIResolver` — resolve + `cli-connect` broker + readiness poll (`internal/resolver/api.go`) | Hosted control-plane validation. |
| `tunnel.Tunnel` | `PapercodeWSTunnel` — `terminal.attach` / `terminal.write` / `terminal.resize` / `terminal.close` over the tunneled papercode `/ws` endpoint | Hosted papercode validation. |
| `config.AuthSource` | Paperboat device session backed by the OS secure store | Cross-platform credential-store validation. |
| `upload.Uploader` | `HTTPUploader` using the brokered max-bytes/MIME policy; `DisabledUploader` fails open when no descriptor is available | Real-volume and hosted validation. |
| `buildinfo.Version` | stamped by release `-ldflags` | Tag-release evidence. |

## Frozen Phase 0 contracts

- Paperboat client authentication uses device authorization and scoped bearer sessions.
- Image staging uses multipart `POST /api/files/staged-images`, requires `file:stage`, and
  returns a VM-absolute `path`; the CLI uses this transport in production.
- Terminal compatibility is owned by papercode's versioned protocol fixture. Hand-written
  CLI wire types must be checked against that fixture and the real server.
- Project presets and machine shape are project configuration applied on restart. There
  are no session-scoped `--agent` or `--size` contracts.

## Remaining release evidence

- Package-manager publication, runbook drills, dashboards/alerts, measured revocation
  propagation, and exercised hosted release evidence.

## Verification (done)

- `gofmt -l .` clean, `go vet ./...` clean, `go test ./...` green
  (paste parser + upload pipeline unit tests: split reads, partial markers, adjacent pastes,
  non-image pass-through, upload-failure fail-open, dataURL limits).
- Real binary: exit-code passthrough (`exit 7`→7, `exit 0`→0), stream I/O, bracketed-paste
  image path rewritten to a VM path, plain-text paste untouched, unsupported session
- Cross-build verification: paste tests and the CLI compile for Windows/amd64 and
  Linux/amd64; interactive terminal evidence on each supported OS remains release work.
  overrides rejected, flags after project name, and the `paperboat` alias symlink.
- **Control-plane end-to-end** against a mock paperboat-server (session-cookie auth + the
  real connect flow), with the actual `bin/pb`:
  - `pb doctor` → authenticates via `GET /api/me` (`authenticated as … ✓`).
  - Previous mock control-plane E2E covered project resolution, `cli-connect` not-ready
    handling, and `connection-status` polling. It needs a new WebSocket terminal mock once
    Phase 4 lands.
  - Bad token → server 401 → `pb auth login` guidance.
  - Unknown project → `ErrProjectNotFound`.
- New unit tests: `internal/api` (bearer auth, `{data}`/`{error}` envelope, 401→sentinel,
  structured error, terminal decode) and `internal/resolver` (id/name match, poll-until-ready,
  re-broker when status lacks routing, not-found).
- Phase 4 WebSocket transport harness: local WebSocket server verifies `/ws?wsTicket=...`,
  `terminal.attach` payload, split terminal output reads, `terminal.write`,
  `terminal.resize`, and remote `exit 7` propagation.
