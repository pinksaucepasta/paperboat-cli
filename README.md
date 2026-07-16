# paperboat-cli

The Paperboat command-line client — an **invisible terminal wrapper** that connects your
local machine to a Paperboat environment and gives you its terminal as if it were local.

The production target signs in through Paperboat's dashboard-approved device flow, connects
through agentunnel, and transparently bridges **local image pastes into remote TUIs**. The
CLI now uses Paperboat bearer sessions and stores secrets in the operating system credential
store; plaintext fallback is explicit and intended only for headless systems.

Control-plane requests identify the CLI and protocol version so incompatible clients receive
an actionable upgrade error instead of malformed session data. See
[docs/operations.md](docs/operations.md) for security and outage handling.

> **Status:** Production commands use Paperboat device sessions and never fall back to a
> local shell. `cli-connect` returns a tunneled papercode WSS terminal plus a separate
> staged-image upload descriptor.
> SSH is debug/operator access only, not the production CLI handoff. See
> [AGENTS.md](AGENTS.md) for design/conventions and the workspace
> `USERSTORY.md` for how this fits the platform.

## Usage

```sh
pb <environment>             # attach a hosted project or connected-machine terminal
pb environments               # list hosted projects and connected machines
pb auth login                # approve this installation in the dashboard
pb auth status               # show the active account for the configured server
pb auth switch               # replace the active account for this server
pb auth logout               # revoke and remove this installation's session
pb doctor                    # check auth + environment connectivity
pb config path|show          # inspect the local config
```

Flags may appear before or after the environment name. `paperboat` is an alias for `pb`.
Hosted projects and connected machines use the same durable terminal-session workflow:
`--new`, `--session`, and `pb sessions` apply to either environment type.

## Connected-machine connector

The public bootstrap command displayed in the dashboard is deployment configuration. It
starts with a local enrollment and ends with a signed, user-service installation:

```sh
paperboat-connect enroll --server https://api.example --name "Studio Mac" --workspace "$HOME"
paperboat-connect install \
  --manifest-url https://releases.example/manifest.json \
  --release-public-key "$PAPERBOAT_RELEASE_PUBLIC_KEY"
```

`install` requires an approved enrollment and a base64 Ed25519 **public** key. It verifies
the signed manifest and SHA-256 of each `paperboat-connect`, `papercode`, and `agentunnel`
artifact for the current OS/architecture, replaces the three binaries atomically, installs
the launchd or systemd user service, and restores the preceding binaries if activation
fails. The agentunnel enrollment token stays in the OS secret store (or the explicit 0600
file fallback), never in the service unit.

The manifest is canonical JSON signed over the object containing `version` and `artifacts`:

```json
{
  "version": "1.2.3",
  "artifacts": [
    {"component":"paperboat-connect","os":"darwin","arch":"arm64","url":"https://...","sha256":"..."},
    {"component":"papercode","os":"darwin","arch":"arm64","url":"https://...","sha256":"...","format":"tar.gz"},
    {"component":"agentunnel","os":"darwin","arch":"arm64","url":"https://...","sha256":"..."}
  ],
  "signature": "base64-ed25519-signature"
}
```

The release signer is local-only. Its private PKCS#8 Ed25519 PEM must remain outside the
repository; the public verification key may be published in the bootstrap command. Give the
signer an input file containing public URLs and local artifact paths, then publish the generated
manifest beside those immutable artifacts:

Build the Papercode input as a self-contained production bundle. The archive includes the selected
Node runtime, so the connected machine does not rely on a separately installed Node version:

```sh
scripts/package-papercode.sh ../papercode ./dist/papercode-darwin-arm64.tar.gz "$(command -v node)"
```

```json
[
  {"component":"paperboat-connect","os":"darwin","arch":"arm64","url":"https://releases.example/paperboat-connect","path":"./dist/paperboat-connect"},
  {"component":"papercode","os":"darwin","arch":"arm64","url":"https://releases.example/papercode.tar.gz","path":"./dist/papercode.tar.gz","format":"tar.gz"},
  {"component":"agentunnel","os":"darwin","arch":"arm64","url":"https://releases.example/agentunnel","path":"./dist/agentunnel"}
]
```

```sh
go run ./cmd/paperboat-release sign-manifest \
  --version 1.2.3 \
  --artifacts ./release-artifacts.json \
  --private-key "$HOME/.paperboat/release-signing/paperboat-release-ed25519.pem" \
  --output ./dist/connector-manifest.json
```

Connection policy is deployment/profile configuration, not compiled into the CLI:

```json
{
  "connect": {
    "ready_timeout_seconds": 180,
    "poll_interval_seconds": 3,
    "dial_retries": 6,
    "dial_retry_seconds": 2,
    "accepted_terminal_kinds": ["papercode_websocket"]
  },
  "observability": {
    "event_log_path": "/managed/path/paperboat-telemetry.jsonl",
    "max_event_log_bytes": 5242880
  },
  "status_bar": {
    "mode": "auto",
    "notice_seconds": 5,
    "sync_poll_seconds": 30,
    "left": ["project", "session"],
    "center": ["activity"],
    "right": ["credits", "connection"]
  }
}
```

`status_bar.mode` accepts `auto`, `on`, or `off`. In `auto` mode it is used
only on supported interactive terminals; redirected output, `TERM=dumb`, and
terminals shorter than two rows retain the ordinary transparent terminal flow.
The bar is divided into left, center, and right regions. Each region accepts an
ordered subset of `project`, `session`, `connection`, `activity`,
`config_sync`, `credits`, and `storage`; a widget can appear once and an
explicit empty array hides a region. `activity` shows active work with an ASCII
spinner, while `config_sync`, `credits`, and `storage` are refreshed from the
authenticated control plane.

When no observability path is configured, metadata-only events are appended to
`telemetry.jsonl` beside the CLI config with mode `0600`. Set
`observability.disable_event_log` to `true` to opt out. The log is bounded and
truncated at `observability.max_event_log_bytes` rather than growing without limit.

## Build

```sh
make build      # -> bin/pb
make release-metadata # binary checksum + provenance metadata in dist/
make install    # install pb + a `paperboat` alias symlink
make test       # unit tests (paste parser + upload pipeline)
```

Version tags trigger cross-platform release builds for macOS, Linux, and Windows
on amd64/arm64. Published assets include SHA-256 checksums, SPDX JSON SBOMs, and
GitHub build-provenance attestations. Each release also includes a checksum-bound
Homebrew formula (`paperboat.rb`) and Scoop manifest (`paperboat.json`).

## Stack

Go — distributed as a single static binary (`github.com/urfave/cli/v2`, Go 1.25).

## Layout

- `cmd/pb` — CLI entrypoint (commands, flags, wiring).
- `internal/config` — local policy and secure, versioned credential profiles.
- `internal/resolver` — paginated environment resolution and validated connect descriptors.
- `internal/tunnel` — papercode WebSocket RPC and bounded reconnect supervision.
- `internal/session` — transparent PTY wrapper (raw mode, resize, exit-code passthrough).
- `internal/paste` — bracketed-paste interceptor + image-path rewriter (the risk center).
- `internal/upload` — authenticated staged-image multipart transport.
