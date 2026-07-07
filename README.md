# paperboat-cli

The Paperboat command-line client — an **invisible terminal wrapper** that connects your
local machine to your project's cloud VM and gives you its terminal as if it were local.

It reuses your existing Paperboat auth (from the global papercode config), connects through
agentunnel, and transparently bridges **local image pastes into remote TUIs**: when you paste
a local image into a coding agent running on the VM, the CLI uploads it to the VM and rewrites
the paste to the VM-side path before the agent sees it — so pasting "just works" remotely.

> **Status:** CLI scaffold implemented with local dev stubs. The production
> `cli-connect` contract is now papercode WebSocket based: `paperboat-server`
> will return a tunneled papercode HTTP/WSS endpoint plus scoped auth once the
> Phase 1 credential issuer exists, and the CLI will attach through papercode
> terminal RPC when the Phase 4 transport lands.
> SSH is debug/operator access only, not the production CLI handoff. See
> [AGENTS.md](AGENTS.md) for design/conventions and the workspace
> `USERSTORY.md` for how this fits the platform.

## Usage

```sh
pb <project>                 # resume the project VM (if idle) and attach its terminal
pb <project> --agent codex   # launch a different agent for this session (short: -a)
pb <project> --size 2x       # boot a different machine shape on resume (short: -s)
pb agents                    # list available agent presets
pb sizes                     # list available machine shapes
pb doctor                    # check papercode auth reuse + connectivity
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
- `internal/config` — local config + read-only reuse of papercode credentials.
- `internal/catalog` — dynamic agent/machine-size catalog (interface + stub).
- `internal/resolver` — project-name → connect info (interface + stub).
- `internal/tunnel` — reach the VM terminal through agentunnel/papercode WebSocket RPC (interface + local-shell stub).
- `internal/session` — transparent PTY wrapper (raw mode, resize, exit-code passthrough).
- `internal/paste` — bracketed-paste interceptor + image-path rewriter (the risk center).
- `internal/upload` — papercode-compatible image encoder + uploader (interface + stub).
