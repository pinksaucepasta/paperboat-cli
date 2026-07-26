# paperboat-cli

The Paperboat command-line client. `pb` authenticates the user, selects an environment,
attaches to helper-managed terminal sessions, and bridges local image pastes into remote
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
- `internal/tunnel` — Paperboat terminal WebSocket RPC and bounded reconnect supervision.
- `internal/session` — transparent PTY wrapper (raw mode, resize, exit-code passthrough).
- `internal/paste` — bracketed-paste interceptor + image-path rewriter (the risk center).
- `internal/upload` — authenticated staged-image multipart transport.

## License

MIT. See [LICENSE](LICENSE).
