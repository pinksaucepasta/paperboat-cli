# PROGRESS.md — paperboat-cli

Running record of what has been implemented, how, and what is still a stub/dummy waiting
for real backends. Update this as work lands. (Repo docs live in [AGENTS.md](AGENTS.md);
product source of truth is the workspace `USERSTORY.md`.)

## Status at a glance

**CLI control-plane contract corrected for papercode WebSocket attach.** The production
descriptor target is a tunneled papercode HTTP/WSS endpoint plus scoped auth. The CLI now
uses that descriptor to attach through papercode WebSocket terminal RPC when `server_url`
is configured. With `server_url` unset the local dev stubs still run, so the CLI stays
exercisable offline.

- Build: `make build` → `bin/pb`. `gofmt`/`go vet` clean, `go test ./...` green.
- Verified end-to-end with the real binary against a mock paperboat-server implementing the
  session-cookie auth + connect flow (see "Verification" below).

### Real backend wiring (this pass)
- **`internal/api`** — paperboat-server control-plane client. Speaks the frozen JSON
  envelope (`{"data"}` / `{"error":{code,message}}`). Its current papercode-token-as-cookie
  authentication is transitional and superseded by the Phase 0 scoped Paperboat bearer
  session contract. Methods: `Me`, `ListProjects`, `CLIConnect`, `ConnectionStatus`.
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
- **`cmd/pb`** — `server_url` gates real vs. stub impls; `doctor` verifies backend auth
  via `GET /api/me`, and `pb doctor <project>` brokers a descriptor and verifies the
  papercode WebSocket route/auth handshake without attaching a terminal.

## What was built

### Command surface (`cmd/pb`)
- `pb <project>` resumes the VM (stubbed) and attaches its terminal. `paperboat` is an
  install-time symlink alias (urfave/cli derives the program name from argv[0]).
- Session-scoped `--agent` and `--size` overrides were removed in Phase 0 because neither
  had an implemented server/runtime contract. Presets and machine type remain project
  configuration applied through the control plane.
- Subcommands: `agents`, `sizes`, `doctor`, `config path|show`.
- `normalizeArgs` reorders tokens so flags work **before or after** the project name
  (urfave/cli otherwise stops flag parsing at the first positional).

### Config and auth (`internal/config`)
- JSON config loaded from `$PAPERBOAT_CONFIG` or the user config dir; missing file is not an
  error (defaults applied). Everything tunable is here (server URL, papercode path, upload
  endpoint/watch-dirs/limits) — no hardcoding in command logic.
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
- Detects local image paths (strips quotes/`file://`, honors config watch-dirs), uploads via
  the `Uploader` interface, and rewrites the paste to the returned VM path. Non-image pastes
  pass through byte-for-byte. **Fail open, visibly**: on any failure the original paste is
  emitted and a notice is written to the local terminal.
- Encoder mirrors papercode's `UploadChatImageAttachment` format/limits (base64 dataURL,
  10 MB/image, 8 attachments, ~14 M dataURL chars, `image/*`) so the real transport is a
  drop-in.

## Real vs. stub, by interface

Real implementations are selected when `server_url` is configured; stubs run otherwise so the
CLI stays exercisable offline. The interfaces are unchanged, so both drop in interchangeably.

| Interface | Real (server_url set) | Stub (local dev) | Still pending |
| --- | --- | --- | --- |
| `resolver.ProjectResolver` | `APIResolver` — resolve + `cli-connect` broker + readiness poll (`internal/resolver/api.go`) | `StubResolver` — local target | — |
| `tunnel.Tunnel` | `PapercodeWSTunnel` — `terminal.attach` / `terminal.write` / `terminal.resize` / `terminal.close` over the tunneled papercode `/ws` endpoint | `StubTunnel` — local `$SHELL` PTY | Real hosted papercode validation deferred to Phase 9. |
| `config.AuthSource` | Transitional `FileAuthSource`; superseded and not production-safe | same | Paperboat device session and OS secure-store implementation (Phase 3) |
| `catalog.Catalog` | No server implementation yet | `StubCatalog` — seed agents/sizes for offline listing UX | listing commands use placeholder seed data until a server catalog endpoint is agreed; attach has no agent/size overrides. |
| `upload.Uploader` | `HTTPUploader` when the broker returns an upload descriptor, using brokered max-bytes/MIME policy; otherwise `DisabledUploader` fails open | `StubUploader` — returns a VM path, transfers nothing | papercode must provide the VM-path upload endpoint for hosted validation. |
| `buildinfo.Version` | stamped by release `-ldflags` | `"dev"` | — |

## Frozen Phase 0 contracts

- Paperboat client authentication uses device authorization and scoped bearer sessions.
- Image staging uses multipart `POST /api/files/staged-images`, requires `file:stage`, and
  returns a VM-absolute `path`; the current base64 uploader is transitional.
- Terminal compatibility is owned by papercode's versioned protocol fixture. Hand-written
  CLI wire types must be checked against that fixture and the real server.
- Project presets and machine shape are project configuration applied on restart. There
  are no session-scoped `--agent` or `--size` contracts.

## Not yet done (deferred by design)

- Real papercode image-upload transport (pending the contract below); the `upload`
  hint is already plumbed through to the paste bridge's boundary.
- A paperboat-server catalog read endpoint for server-backed agent/preset listing.

## Verification (done)

- `gofmt -l .` clean, `go vet ./...` clean, `go test ./...` green
  (paste parser + upload pipeline unit tests: split reads, partial markers, adjacent pastes,
  non-image pass-through, upload-failure fail-open, dataURL limits).
- Real binary: exit-code passthrough (`exit 7`→7, `exit 0`→0), stream I/O, bracketed-paste
  image path rewritten to a VM path, plain-text paste untouched, unsupported session
  overrides rejected, flags after project name, and the `paperboat` alias symlink.
- **Control-plane end-to-end** against a mock paperboat-server (session-cookie auth + the
  real connect flow), with the actual `bin/pb`:
  - `pb doctor` → authenticates via `GET /api/me` (`authenticated as … ✓`).
  - Previous mock control-plane E2E covered project resolution, `cli-connect` not-ready
    handling, and `connection-status` polling. It needs a new WebSocket terminal mock once
    Phase 4 lands.
  - Bad token → server 401 → `pb auth login` guidance.
  - Unknown project → `ErrProjectNotFound`.
  - No `server_url` → local stub shell still runs (offline-safe).
- New unit tests: `internal/api` (cookie auth, `{data}`/`{error}` envelope, 401→sentinel,
  structured error, terminal decode) and `internal/resolver` (id/name match, poll-until-ready,
  re-broker when status lacks routing, not-found).
- Phase 4 WebSocket transport harness: local WebSocket server verifies `/ws?wsTicket=...`,
  `terminal.attach` payload, split terminal output reads, `terminal.write`,
  `terminal.resize`, and remote `exit 7` propagation.
