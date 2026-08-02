# paperboat

The Paperboat command-line client. `pb` authenticates the user, selects an environment,
attaches to helper-managed terminal sessions, and bridges local file pastes into remote
agent workflows.

The CLI uses Paperboat device sessions and stores secrets in the operating-system
credential store. It does not own remote PTYs, tunnel infrastructure, or reusable
connector credentials.

Control-plane requests identify the CLI and protocol version so incompatible clients receive
an actionable upgrade error instead of malformed session data. See
[docs/operations.md](docs/operations.md) for security and outage handling.

See [AGENTS.md](AGENTS.md) for repository ownership and engineering requirements, and
[docs/operations.md](docs/operations.md) for security and outage handling.

## Usage

```sh
pb <environment>             # attach a hosted project or machine terminal
pb environments               # list hosted projects and machines
pb auth login                # approve this installation in the dashboard
pb auth status               # show the active account for the configured server
pb auth switch               # replace the active account for this server
pb auth logout               # revoke and remove this installation's session
pb doctor                    # check auth + environment connectivity
pb config path|show          # inspect the local config
pb serve ./dist --public     # publish a local file or static directory
```

Flags may appear before or after the environment name.
Hosted projects and machines use the same durable terminal-session workflow:
`--new`, `--session`, and `pb sessions` apply to either environment type.

## Serve a file or directory

`pb serve [path]` publishes a regular file or static directory from the current device
through a public Paperboat preview. It binds the static server only to loopback, waits for
the public route to become ready before printing its URL, and stops both the listener and
preview on cancellation or expiry.

```sh
pb serve ./report.html --public
pb serve ./dist --public --spa --duration 1h
pb serve ./demo.pdf --public --detach
```

Without a path in an interactive terminal, `pb serve` opens the local file-and-directory
picker. Pasting or dropping one file stages a verified, collision-safe copy under
`Paperboat Inbox/serve` after public-access confirmation. The Inbox copy remains after the
preview stops. `--detach` transfers ownership to the local Paperboat runtime so serving
survives CLI exit, but local runtime or machine shutdown stops it. Stop either mode through
`pb preview revoke`.

Non-interactive and JSON invocations require both a path and `--public`. Use `--indefinite`
instead of `--duration` only when the preview should remain until explicitly revoked.

Interactive attaches forward `TERM`, `COLORTERM`, `TERM_PROGRAM`,
`TERM_PROGRAM_VERSION`, and locale variables when they are set locally.

## Interactive status bar

Compatible interactive terminals reserve one bottom row for local Paperboat context. The
remote PTY receives the remaining rows, and no status-bar bytes are sent remotely. By
default the bar inherits the terminal palette and temporarily releases its row when a
remote application enters the alternate screen, preventing editors and other full-screen
TUIs from losing or covering content.

```sh
pb config status-bar show
pb config status-bar preview
pb config status-bar set mode auto                 # auto, on, off
pb config status-bar set fullscreen hide           # hide, show
pb config status-bar set theme terminal             # terminal, dark, light, mono
pb config status-bar set privacy true
pb config status-bar set terminal-title true
pb config status-bar set left project,session
pb config status-bar set center activity
pb config status-bar set right credits,connection
pb config status-bar set accent '#00d7af'
pb config status-bar reset
```

Use `none` to empty a widget region. Supported widgets are `project`, `session`,
`connection`, `activity`, `config_sync`, `credits`, and `storage`; a widget can appear in
only one region. Color overrides accept ANSI names such as `bright_cyan`, `default`, or
`#RRGGBB`. `NO_COLOR` disables status-bar colors without disabling the bar.

Attach flags override saved behavior for one session:

```sh
pb demo --status-bar=off
pb demo --status-bar-fullscreen=show --status-bar-theme=mono
pb demo --transport=quic
```

Terminal attachments use `connect.terminal_transport`, with `auto` (the default), `quic`,
or `wss`. `auto` tries native QUIC over UDP 443 first and falls back to WSS over TCP 443 only
when QUIC cannot connect. `--transport` overrides the mode for one command without
rewriting configuration. Authentication, certificate, route, and protocol failures do not
fall back.

The bar automatically drops storage, credits, config-sync, session, and project widgets
in that order as width becomes constrained. Connection and active failure state retain
priority. Terminals narrower than 20 columns receive the full viewport without a bar.

## File drag and drop

Interactive `pb` attaches enable the standard terminal bracketed-paste mode. A
framed paste containing only absolute local file paths is staged and rewritten
to remote paths. Supported path forms include `file://` URIs, quoted paths, and
POSIX shell-escaped paths such as the escaped-space format emitted by WezTerm.
Every other input, including unframed drag-and-drop text, is forwarded exactly
as received; this prevents ordinary typed paths from triggering an upload.

Files are hashed once through the validated local descriptor, rewound, and streamed through
the resumable `/v1/file-transfers` API. Mixed and empty files are supported without MIME
restrictions. A paste is rewritten only after the whole batch publishes atomically; retries
reuse transfer IDs and confirmed offsets, and failures preserve the exact original paste.
Published remote files remain for seven days.

Use `pb send <path>... --to <machine>` to deliver files to another machine's configured
Paperboat Inbox. Session and user defaults are explicit, multi-attachment ambiguity never
selects the latest writer, and the sender exits successfully only after the destination
verifies size and SHA-256, fsyncs the file, avoids name collisions, and records a durable
receipt. Inbox files remain until the user removes them.

## Machines

Run `pb setup` to register the interactive installation and its Paperboat Inbox. Run
`pb pair` to add the host role to the same stable machine identity. Pairing verifies the
server-selected signed `pb` artifact, installs the minimum launchd or systemd services,
and waits for authenticated readiness.

Interactive-only setup does not run a terminal host or connector. After pairing, machines
use the same `pb <environment>` and durable terminal-session workflow as hosted projects.

When no observability path is configured, metadata-only events are appended to
`telemetry.jsonl` beside the CLI config with mode `0600`. Set
`observability.disable_event_log` to `true` to opt out. The log is bounded and
truncated at `observability.max_event_log_bytes` rather than growing without limit.

## Build

```sh
make build      # -> bin/pb
make release-metadata # binary checksum + provenance metadata in dist/
make install    # install pb
make test       # unit tests (paste parser + file-transfer pipeline)
```

`YYYY.MM.DD.X` tags publish signed-provenance archives for supported Android, Darwin,
Linux, and Windows architectures, plus checksums, an SPDX SBOM, and Homebrew/Scoop manifests. Use
`tools/release-version.sh next` to generate the next tag; tags have no `v` prefix.
Android archives target API 24 and link against Bionic so Termux uses Android's native DNS resolver.

## Stack

Go — distributed as a single static binary (Cobra, Go 1.25.7).

## Layout

- `cmd/pb` — CLI entrypoint (commands, flags, wiring).
- `internal/config` — local policy and secure, versioned credential profiles.
- `internal/resolver` — paginated environment resolution and validated connect descriptors.
- `internal/tunnel` — native QUIC-first and WSS terminal-v1 transports with bounded reconnect supervision.
- `internal/session` — transparent PTY wrapper (raw mode, resize, exit-code passthrough).
- `internal/paste` — bracketed-paste interceptor and atomic file-path batch rewriter.
- `internal/filetransfer` — resumable HTTP/3-first, HTTP/2-fallback file transport.
- `internal/inbox` — durable Paperboat Inbox download and receipt handling.

## License

MIT. See [LICENSE](LICENSE).
