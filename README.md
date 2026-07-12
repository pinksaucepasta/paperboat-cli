# paperboat-cli

The Paperboat command-line client — an **invisible terminal wrapper** that connects your
local machine to your project's cloud VM and gives you its terminal as if it were local.

The production target signs in through Paperboat's dashboard-approved device flow, connects
through agentunnel, and transparently bridges **local image pastes into remote TUIs**. The
CLI now uses Paperboat bearer sessions and stores secrets in the operating system credential
store; plaintext fallback is explicit and intended only for headless systems.

> **Status:** Production commands use Paperboat device sessions and never fall back to a
> local shell. `cli-connect` returns a tunneled papercode WSS terminal plus a separate
> staged-image upload descriptor.
> SSH is debug/operator access only, not the production CLI handoff. See
> [AGENTS.md](AGENTS.md) for design/conventions and the workspace
> `USERSTORY.md` for how this fits the platform.

## Usage

```sh
pb <project>                 # resume the project VM (if idle) and attach its terminal
pb agents                    # list available agent presets
pb sizes                     # list available machine shapes
pb auth login                # approve this installation in the dashboard
pb auth status               # show the active account for the configured server
pb auth switch               # replace the active account for this server
pb auth logout               # revoke and remove this installation's session
pb doctor                    # check auth + project connectivity
pb config path|show          # inspect the local config
```

Flags may appear before or after the project name. `paperboat` is an alias for `pb`.

Connection policy is deployment/profile configuration, not compiled into the CLI:

```json
{
  "connect": {
    "ready_timeout_seconds": 180,
    "poll_interval_seconds": 3,
    "dial_retries": 2,
    "dial_retry_seconds": 2,
    "accepted_terminal_kinds": ["papercode_websocket"]
  }
}
```

## Build

```sh
make build      # -> bin/pb
make install    # install pb + a `paperboat` alias symlink
make test       # unit tests (paste parser + upload pipeline)
```

## Stack

Go — distributed as a single static binary (`github.com/urfave/cli/v2`, Go 1.25).

## Layout

- `cmd/pb` — CLI entrypoint (commands, flags, wiring).
- `internal/config` — local policy and secure, versioned credential profiles.
- `internal/catalog` — dynamic agent/machine-size catalog (interface + stub).
- `internal/resolver` — paginated project resolution and validated connect descriptors.
- `internal/tunnel` — papercode WebSocket RPC and bounded reconnect supervision.
- `internal/session` — transparent PTY wrapper (raw mode, resize, exit-code passthrough).
- `internal/paste` — bracketed-paste interceptor + image-path rewriter (the risk center).
- `internal/upload` — authenticated staged-image multipart transport.
