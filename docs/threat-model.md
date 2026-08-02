# Paperboat CLI Threat Model

## Assets and trust boundaries

- Paperboat access and refresh credentials are high-value assets. They remain in
  the OS credential store, with owner-only `0600` files used automatically when
  the credential service is unavailable on a headless system.
- Device codes are short-lived approval handles, not credentials. They are shown
  only in the terminal and browser URL; tokens are never placed in URLs.
- The CLI treats project descriptors, route URLs, VM paths, and server error
  messages as untrusted input. Descriptor validation and issuer binding happen
  before a terminal or file-transfer connection is opened.
- Terminal bytes and opaque file bytes cross the `paperboat-tunnel` data boundary to
  the unified `pb` host runtime. The CLI
  does not log or inspect them beyond the required terminal/file-transfer
  operation.

## Threats and controls

| Threat | CLI control | Residual owner |
| --- | --- | --- |
| Device-code phishing or brute force | Server-authoritative expiry/interval; user sees the complete URL and short code; no token in output | Server/dashboard rate limits and approval UX |
| Token theft or refresh replay | OS credential store, issuer-namespaced profiles, refresh rotation, durable revoke queue | Server session-family revocation |
| Malicious route or descriptor | HTTPS/WSS scheme and issuer/environment/scope/expiry validation; no raw VM or SSH fallback | Server route authorization and `paperboat-tunnel` enforcement |
| Terminal injection | Non-file bytes pass through unchanged; rewriting is limited to a bracketed paste frame | `pb` host-runtime terminal authorization |
| Compression side channel or decompression exhaustion | Each output event is an independent Zstandard frame with no dictionary or cross-session state; declared decoded size, frame content size, decoder memory, and concurrent codecs are bounded before delivery or ACK | A user controlling and observing the same authenticated terminal can still correlate its own input and output sizes |
| File traversal or substitution | Absolute regular files only; symlinks/traversal rejected; one descriptor is hashed and streamed; signed size policy | `pb` host-runtime transfer verification and cleanup |
| Static-serve traversal or source substitution | Loopback-only listener; pinned canonical source identity; root-scoped opens; dotfile, listing, traversal, and symlink-escape denial; identity revalidation before start and on every request | A user with local filesystem write access can make the source unavailable, but cannot silently replace the pinned source |
| Static-serve path disclosure | Source paths and browsing activity stay in owner-only local state and are omitted from control-plane, dashboard, telemetry, and diagnostics | An authorized local user can inspect their own descriptor and served path |
| Compromised VM | CLI receives only short-lived, scoped terminal/file credentials | VM isolation and server revocation |

## Incident actions

For a stolen device, revoke its client session in the dashboard and remove the
local profile with `pb auth logout`. For a suspected incompatible or tampered
server, stop retrying, capture only request/project/access-session IDs, and
upgrade from a verified release. Never bypass `paperboat-tunnel` or use SSH as a user
data path.

The CLI intentionally cannot prove downstream revocation propagation;
`paperboat-server`, `paperboat-tunnel`, and `paperboat` must provide that evidence
in the release review.
