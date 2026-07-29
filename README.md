# paperboat-cli

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
pb <environment>             # attach a hosted project or user-machine terminal
pb environments               # list hosted projects and user machines
pb auth login                # approve this installation in the dashboard
pb auth status               # show the active account for the configured server
pb auth switch               # replace the active account for this server
pb auth logout               # revoke and remove this installation's session
pb doctor                    # check auth + environment connectivity
pb config path|show          # inspect the local config
```

Flags may appear before or after the environment name.
Hosted projects and user machines use the same durable terminal-session workflow:
`--new`, `--session`, and `pb sessions` apply to either environment type.

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

Files are hashed once through the validated local descriptor, rewound, and streamed
directly as a known-length multipart request. The CLI does not retain a full in-memory
copy. Upload progress appears in the status bar, retries reuse the same descriptor and
digest, and failed uploads preserve the original pasted path. The helper publishes private
random filenames under the operating system's cache directory and removes them after the
bounded retention period.

## User machines

BYOD enrollment starts in the dashboard. Its single-use command invokes
`pbh bootstrap` with the server, enrollment token, user-machine name, and absolute
workspace scope. The helper exchanges the token, verifies the server-selected signed helper
artifact, installs its launchd or systemd user service, and waits for authenticated readiness.

`pb` does not install or run a connector. After enrollment is ready, user machines use
the same `pb <environment>` and durable terminal-session workflow as hosted projects.

When no observability path is configured, metadata-only events are appended to
`telemetry.jsonl` beside the CLI config with mode `0600`. Set
`observability.disable_event_log` to `true` to opt out. The log is bounded and
truncated at `observability.max_event_log_bytes` rather than growing without limit.

## Build

```sh
make build      # -> bin/pb
make release-metadata # binary checksum + provenance metadata in dist/
make install    # install pb
make test       # unit tests (paste parser + upload pipeline)
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
- `internal/tunnel` — native QUIC-first and WSS terminal-v2 transports with bounded reconnect supervision.
- `internal/session` — transparent PTY wrapper (raw mode, resize, exit-code passthrough).
- `internal/paste` — bracketed-paste interceptor + image-path rewriter (the risk center).
- `internal/upload` — authenticated staged-image multipart transport.

## License

MIT. See [LICENSE](LICENSE).
