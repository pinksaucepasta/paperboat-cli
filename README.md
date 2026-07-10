# paperboat-cli

The Paperboat command-line client — an **invisible terminal wrapper** that connects your
local machine to your project's cloud VM and gives you its terminal as if it were local.

The production target signs in through Paperboat's dashboard-approved device flow, connects
through agentunnel, and transparently bridges **local image pastes into remote TUIs**. The
current scaffold still uses the superseded papercode JSON-token/cookie adapter; `pb auth
login`, secure credential storage, and bearer authentication land in integration Phases 1
and 3 before this is releasable.

> **Status:** CLI scaffold implemented with local dev stubs and transitional authentication.
> Device login is specified but not implemented. The production
> `cli-connect` contract is now papercode WebSocket based: `paperboat-server`
> will return a tunneled papercode HTTP/WSS endpoint after device sessions and the
> papercode credential issuer are implemented. The CLI's WebSocket terminal transport
> foundation exists, but production bearer auth and real-server compatibility remain.
> SSH is debug/operator access only, not the production CLI handoff. See
> [AGENTS.md](AGENTS.md) for design/conventions and the workspace
> `USERSTORY.md` for how this fits the platform.

## Usage

```sh
pb <project>                 # resume the project VM (if idle) and attach its terminal
pb agents                    # list available agent presets
pb sizes                     # list available machine shapes
pb doctor                    # check transitional auth + project connectivity
pb config path|show          # inspect the local config
```

Flags may appear before or after the project name. `paperboat` is an alias for `pb`.

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
- `internal/config` — transitional config/auth plus the future credential-profile boundary.
- `internal/catalog` — dynamic agent/machine-size catalog (interface + stub).
- `internal/resolver` — project-name → connect info (interface + stub).
- `internal/tunnel` — reach the VM terminal through agentunnel/papercode WebSocket RPC (interface + local-shell stub).
- `internal/session` — transparent PTY wrapper (raw mode, resize, exit-code passthrough).
- `internal/paste` — bracketed-paste interceptor + image-path rewriter (the risk center).
- `internal/upload` — papercode-compatible image encoder + uploader (interface + stub).
