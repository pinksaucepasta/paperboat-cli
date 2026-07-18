# AGENTS.md - paperboat-cli

Inherit [`../AGENTS.md`](../AGENTS.md). CLI, `pb`, and client CLI mean this repo.
`../DX.md` is the interaction and scripting contract.

## Ownership

Device auth, account/environment/session selection, raw terminal lifecycle, resize,
signals, reconnect/replay, local image upload/paste rewriting, human activity,
diagnostics, output, and OS credential storage. Never run frpc, own remote PTYs, enforce
server policy, or receive reusable infrastructure credentials.

## Stack

Go `1.25.7`; Cobra; standard HTTP; Gorilla WebSocket; `x/term`; OS credential adapters.

## Local Rules

- Keep command wiring thin; workflows, resolution, auth, transport, formatting, paste,
  and terminal behavior live in cohesive packages.
- Human and JSON output are separate contracts. Data uses stdout; progress/diagnostics
  use stderr; commands use injected writers.
- Resolve and show the target before input affects it. Never guess ambiguous names.
- Restore terminal state on every exit path, preserve remote exit status, and never
  replay uncertain input.
- Readiness, reconnect, refresh, and replay are automatic only when safe, bounded,
  cancellable, and visible.
- Rewrite image paste only after validation and successful helper staging.
- Hide Fly, frp, Caddy, route, node, and connector details outside diagnostics.

## Verify

Run `make check` and relevant race tests. Release changes require cross-platform build and
install smoke tests. Test fragmentation, cancellation, restoration, replay gaps,
backpressure, concurrent refresh, JSON output, and paste failure.
