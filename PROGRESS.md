# PROGRESS.md — paperboat-cli

Running record of what has been implemented, how, and what is still a stub/dummy waiting
for real backends. Update this as work lands. (Repo docs live in [AGENTS.md](AGENTS.md);
product source of truth is the workspace `USERSTORY.md`.)

## Status at a glance

**CLI control-plane contract corrected for papercode WebSocket attach.** The production
descriptor target is a tunneled papercode HTTP/WSS endpoint plus scoped auth. Server-side
credential issuance is Phase 1 and the actual WebSocket terminal transport is Phase 4.
Until those exist, `pb <project>` refuses `server_url` backend attach before brokering a
connect session. With `server_url` unset the local dev stubs still run, so the CLI stays
exercisable offline.

- Build: `make build` → `bin/pb`. `gofmt`/`go vet` clean, `go test ./...` green.
- Verified end-to-end with the real binary against a mock paperboat-server implementing the
  session-cookie auth + connect flow (see "Verification" below).

### Real backend wiring (this pass)
- **`internal/api`** — paperboat-server control-plane client. Speaks the frozen JSON
  envelope (`{"data"}` / `{"error":{code,message}}`), authenticates with the
  `paperboat_session` cookie carrying the **reused papercode token** (the server has no
  bearer path; connect endpoints need no CSRF). Methods: `Me`, `ListProjects`, `CLIConnect`,
  `ConnectionStatus`. 401 → `ErrUnauthenticated`; other non-2xx → structured `*APIError`.
- **`internal/resolver.APIResolver`** — matches the requested token to a project by id then
  case-insensitive name, calls `cli-connect` (authorizes + reconciles agentunnel resources +
  resumes an idle machine), and polls `connection-status` until connectable, re-brokering
  once when the ready status lacks routing detail. Returns a client-safe papercode
  WebSocket `TerminalTarget` (+ file-upload `UploadTarget`). Poll timeout/interval are
  config-driven (`connect.*`).
- **`internal/tunnel.SSHTunnel`** — retained only as optional debug/operator plumbing.
  Production CLI attach must use papercode WebSocket terminal RPC; that transport is not
  implemented yet.
- **`cmd/pb`** — `server_url` gates real vs. stub impls; `doctor` now verifies backend auth
  via `GET /api/me`.

## What was built

### Command surface (`cmd/pb`)
- `pb <project>` resumes the VM (stubbed) and attaches its terminal. `paperboat` is an
  install-time symlink alias (urfave/cli derives the program name from argv[0]).
- Session-scoped, catalog-validated flags — deliberately **value-based**, not literal
  `--2x`/`--claude` booleans, to keep the catalog dynamic (no hardcoding):
  - `--agent, -a <name>` — launch a different agent this session.
  - `--size, -s <shape>` — machine shape to boot on the idle-resume.
- Subcommands: `agents`, `sizes`, `doctor`, `config path|show`.
- `normalizeArgs` reorders tokens so flags work **before or after** the project name
  (urfave/cli otherwise stops flag parsing at the first positional).

### Config + auth reuse (`internal/config`)
- JSON config loaded from `$PAPERBOAT_CONFIG` or the user config dir; missing file is not an
  error (defaults applied). Everything tunable is here (server URL, papercode path, upload
  endpoint/watch-dirs/limits, default agent/size) — no hardcoding in command logic.
- `AuthSource` reads papercode credentials **read-only**; the CLI never owns/writes creds.
  Missing creds → `ErrNoCredentials` (guides the user to sign in via papercode, no separate
  login).

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
| `tunnel.Tunnel` | Pending papercode WebSocket terminal transport (`internal/tunnel/ssh.go` now fails explicitly for production descriptors) | `StubTunnel` — local `$SHELL` PTY | Implement Phase 4: `terminal.open` / `terminal.attach` / `terminal.write` / `terminal.resize` / `terminal.close` over the tunneled papercode `/ws` endpoint. |
| `config.AuthSource` | `FileAuthSource` — reads papercode `auth.json`, sent as the `paperboat_session` cookie | same | exact papercode credential path/format (mapping-only change) |
| `catalog.Catalog` | `StubCatalog` — seed agents/sizes for **flag validation UX only** | same | no public catalog endpoint on paperboat-server (contracts frozen); left as placeholder seed data, not baked-in logic. Needs a server catalog endpoint agreed before wiring. |
| `upload.Uploader` | `StubUploader` — returns a VM path, transfers nothing | same | real papercode VM upload endpoint (see open contract below). `cli-connect` must not return upload auth until Phase 1 can issue credentials the VM papercode server validates. |
| `buildinfo.Version` | stamped by release `-ldflags` | `"dev"` | — |

## Known open contract question (needs the user / cross-project agreement)

The papercode **GUI** sends images as chat-turn *attachments* (base64 dataURL). A TUI wrapper
instead needs a VM-side *file path* to inject into the paste stream. So the real `Uploader`
requires a papercode-server endpoint that accepts an image and **returns a VM path** — a
cross-project contract to agree on before implementing. papercode was not modified.

## Not yet done (deferred by design)

- **papercode WebSocket terminal transport** — Phase 4 must replace the placeholder tunnel
  with a client for the existing papercode terminal RPC methods.
- Real papercode image-upload transport (pending the contract below); the `upload`
  hint is already plumbed through to the paste bridge's boundary.
- A paperboat-server **catalog endpoint** for agents/sizes (contracts frozen; needs
  agreement) — `--agent`/`--size` validate against seed data until then.
- Machine-resume shape selection (`--size` → boot machine-type) against the real Fly
  lifecycle: `cli-connect` resumes the machine, but mapping a session `--size` override to a
  boot shape needs the server-side contract (currently the project's configured shape boots).

## Verification (done)

- `gofmt -l .` clean, `go vet ./...` clean, `go test ./...` green
  (paste parser + upload pipeline unit tests: split reads, partial markers, adjacent pastes,
  non-image pass-through, upload-failure fail-open, dataURL limits).
- Real binary: exit-code passthrough (`exit 7`→7, `exit 0`→0), stream I/O, bracketed-paste
  image path rewritten to a VM path, plain-text paste untouched, flag validation
  (`--agent nope` rejected), flags after project name, and the `paperboat` alias symlink.
- **Control-plane end-to-end** against a mock paperboat-server (session-cookie auth + the
  real connect flow), with the actual `bin/pb`:
  - `pb doctor` → authenticates via `GET /api/me` (`authenticated as … ✓`).
  - Previous mock control-plane E2E covered project resolution, `cli-connect` not-ready
    handling, and `connection-status` polling. It needs a new WebSocket terminal mock once
    Phase 4 lands.
  - Bad token → server 401 → "sign in again with papercode".
  - Unknown project → `ErrProjectNotFound`.
  - No `server_url` → local stub shell still runs (offline-safe).
- New unit tests: `internal/api` (cookie auth, `{data}`/`{error}` envelope, 401→sentinel,
  structured error, terminal decode) and `internal/resolver` (id/name match, poll-until-ready,
  re-broker when status lacks routing, not-found).
