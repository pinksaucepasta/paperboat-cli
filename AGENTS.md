# AGENTS.md - paperboat

Inherit [`../AGENTS.md`](../AGENTS.md). Unified runtime, CLI, and `pb` mean this repo.
`../DX.md` is the interaction and scripting contract.

## Ownership

Device auth, machine identity and setup roles, account/environment/session selection,
terminal client and host lifecycle, resize, signals, reconnect/replay, machine-addressed
transfer and inbox behavior, preview runners, config sync, connectors, diagnostics,
updates, output, and OS credential storage. Server policy and reusable infrastructure
credentials remain outside this repository.

## Stack

Go `1.26.5`; Cobra; standard HTTP; Coder WebSocket; `x/term`; OS credential adapters.

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
- Rewrite file paste only after validation and atomic helper publication.
- Hide Fly, frp, Caddy, route, node, and connector details outside diagnostics.

## Verify

Run `make check` and relevant race tests. Release changes require cross-platform build and
install smoke tests. Test fragmentation, cancellation, restoration, replay gaps,
backpressure, concurrent refresh, JSON output, and paste failure.
