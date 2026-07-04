# PROGRESS.md — paperboat-cli

Running record of what has been implemented, how, and what is still a stub/dummy waiting
for real backends. Update this as work lands. (Repo docs live in [AGENTS.md](AGENTS.md);
product source of truth is the workspace `USERSTORY.md`.)

## Status at a glance

**CLI scaffold implemented and runnable end-to-end against local dev stubs.** No real
backend is wired yet (paperboat-server has no endpoints; agentunnel/papercode transport not
connected). All cross-service work sits behind Go interfaces, so real implementations drop
in without changing the command/flag surface.

- Build: `make build` → `bin/pb`. `gofmt`/`go vet` clean, `go test ./...` green.
- Verified end-to-end with the real binary (see "Verification" below).

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

## Stubs / dummies kept (replace when backends exist)

| Interface | Stub | File | Replace with |
| --- | --- | --- | --- |
| `catalog.Catalog` | `StubCatalog` — hard-seeded agents (claude/codex/cursor) + sizes (1x/2x/4x) | `internal/catalog/stub.go` | paperboat-server catalog endpoint. Values here are placeholder seed data, **not** a product catalog baked into logic. |
| `resolver.ProjectResolver` | `StubResolver` — resolves every project to a local target | `internal/resolver/stub.go` | paperboat-server project resolution + pre-connect broker. |
| `tunnel.Tunnel` | `StubTunnel` — spawns a local `$SHELL` PTY via `creack/pty` | `internal/tunnel/stub.go` | agentunnel-backed connection to the VM PTY. |
| `upload.Uploader` | `StubUploader` — returns a content-addressed `/workspace/.paperboat/attachments/<hash>.<ext>` path, transfers nothing | `internal/upload/stub.go` | papercode T3 WebSocket upload transport. |
| `config.AuthSource` | `FileAuthSource` — reads `~/.config/papercode/auth.json` | `internal/config/auth.go` | Real only needs the actual papercode credential path/format; interface stays. |
| `buildinfo.Version` | `"dev"` | `internal/buildinfo/buildinfo.go` | stamped by release `-ldflags`. |

Also placeholder: config default paths (`~/.config/paperboat`, `~/.config/papercode`) and the
stub uploader's VM base dir — all config-overridable.

## Known open contract question (needs the user / cross-project agreement)

The papercode **GUI** sends images as chat-turn *attachments* (base64 dataURL). A TUI wrapper
instead needs a VM-side *file path* to inject into the paste stream. So the real `Uploader`
requires a papercode-server endpoint that accepts an image and **returns a VM path** — a
cross-project contract to agree on before implementing. papercode was not modified.

## Not yet done (deferred by design)

- Real agentunnel transport (client protocol, TCP/SSH tunnel to the VM PTY).
- Real paperboat-server calls (project resolve, catalog, pre-connect authz).
- Real papercode image-upload transport (pending the contract above).
- Machine-resume semantics against the real Fly lifecycle (size → boot shape).

## Verification (done)

- `gofmt -l .` clean, `go vet ./...` clean, `go test ./...` green
  (paste parser + upload pipeline unit tests: split reads, partial markers, adjacent pastes,
  non-image pass-through, upload-failure fail-open, dataURL limits).
- Real binary: exit-code passthrough (`exit 7`→7, `exit 0`→0), stream I/O, bracketed-paste
  image path rewritten to a VM path, plain-text paste untouched, flag validation
  (`--agent nope` rejected), flags after project name, and the `paperboat` alias symlink.
