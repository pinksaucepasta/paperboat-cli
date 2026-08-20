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
pb Studio -- git status      # execute an exact argv vector on a machine
pb exec Studio --cwd /src -- make test
pb config path|show          # inspect the local config
pb serve ./dist              # serve privately on this device
pb serve ./dist --public     # publish through a public preview
```

Flags may appear before or after the environment name.
Hosted projects and machines use the same durable terminal-session workflow:
`--new`, `--session`, and `pb sessions` apply to either environment type.

## Remote execution

`pb <machine> -- <argv...>` executes an exact argument vector without an implicit shell.
Use `pb exec` for execution controls such as `--cwd`, `--timeout`, repeated `--env
name=value`, `--pty`, and `--json`. Non-PTY execution keeps stdout and stderr separate;
PTY mode merges them and forwards terminal resize events. JSON mode emits the versioned
`paperboat.exec-event/v1` JSON Lines stream and returns the remote process exit status.

## Serve a file or directory

`pb serve [path]` serves a regular file or static directory privately on an IPv4 loopback
listener by default. It needs no Paperboat setup, account, machine runtime, or network
connection. `--listen-port` requests one specific loopback port; otherwise the OS selects
an available port. `--public` explicitly creates the existing public Paperboat preview and
does not accept `--listen-port`.

```sh
pb serve ./report.html
pb serve ./dist --spa --listen-port 8080
pb serve ./demo.pdf --detach
pb serve ./dist --public --duration 1h
```

Without a path in an interactive terminal, `pb serve` opens the local file-and-directory
picker. Pasting or dropping one file stages a verified, collision-safe copy under
`Paperboat Inbox/serve`; public mode asks for confirmation before publishing. The Inbox
copy remains after serving stops. `--detach` transfers ownership to an isolated local user
service so serving survives CLI exit. List it with `pb preview list` and stop it by name
with `pb preview revoke <name>`.

Non-interactive and JSON invocations require a path. Use `--indefinite` instead of
`--duration` only when the listener should remain until explicitly stopped.

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
pb demo --path=d
```

Terminal attachments use `connect.terminal_transport`, with `a` (the default), `d`, `q`,
`w`, or `r`. Auto races direct and relay paths, prefers direct, and keeps a relay standby
while the application is active. `--path` overrides the mode for one command without
rewriting configuration. Explicit path modes never select a path outside their contract.

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
server-selected TUF target, installs the minimum launchd or systemd services,
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

`YYYY.MM.DD.X` tags prepare provenance-attested archives for the supported Darwin, Linux,
and Windows architectures, plus checksums and an SPDX SBOM. Windows artifacts are not
described or published as signed unless the protected release signing gate has verified
Authenticode signatures, publisher identity, RFC 3161 timestamps, and post-signing checksums.
Use `tools/release-version.sh next` to generate the next tag; tags have no `v` prefix.
Android archives target API 24 and link against Bionic so Termux uses Android's native DNS resolver.

Native Windows MSI, portable ZIP, and WinGet packaging sources live in
[`packaging/windows`](packaging/windows). The MSI builder runs only with an installed WiX
Toolset on Windows and emits unsigned output; external Authenticode signing and RFC 3161
timestamping remain release-authority requirements. Windows amd64 is the stable target and
Windows arm64 is the explicit beta target until native ARM64 qualification exists.

## Stack

Go - distributed as native static binaries for Windows, macOS, and Linux (Cobra, Go 1.26.6).
Windows amd64 is stable after native release qualification. Windows arm64 ships the same
feature set as an explicit beta until native ARM64 hardware qualification is available.

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
