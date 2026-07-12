# Paperboat CLI Threat Model

## Assets and trust boundaries

- Paperboat access and refresh credentials are high-value assets. They remain in
  the OS credential store (or the explicitly opted-in `0600` file fallback).
- Device codes are short-lived approval handles, not credentials. They are shown
  only in the terminal and browser URL; tokens are never placed in URLs.
- The CLI treats project descriptors, route URLs, VM paths, and server error
  messages as untrusted input. Descriptor validation and issuer binding happen
  before a terminal or upload connection is opened.
- Terminal bytes and image bytes cross the agentunnel data boundary. The CLI
  does not log, inspect, or proxy them beyond the required terminal/upload
  operation.

## Threats and controls

| Threat | CLI control | Residual owner |
| --- | --- | --- |
| Device-code phishing or brute force | Server-authoritative expiry/interval; user sees the complete URL and short code; no token in output | Server/dashboard rate limits and approval UX |
| Token theft or refresh replay | OS credential store, issuer-namespaced profiles, refresh rotation, durable revoke queue | Server session-family revocation |
| Malicious route or descriptor | HTTPS/WSS scheme and issuer/project/scope/expiry validation; no raw VM or SSH fallback | Server and agentunnel route authorization |
| Terminal injection | Non-image bytes pass through unchanged; image rewriting is limited to a bracketed paste frame | Papercode terminal authorization |
| Upload traversal/polyglots | Server-selected staging destination; descriptor MIME/size policy; local file opened and validated before upload | Papercode image decoder and cleanup |
| Compromised VM | CLI receives only short-lived, scoped terminal/file credentials | VM isolation and server revocation |

## Incident actions

For a stolen device, revoke its client session in the dashboard and remove the
local profile with `pb auth logout`. For a suspected incompatible or tampered
server, stop retrying, capture only request/project/access-session IDs, and
upgrade from a verified release. Never bypass agentunnel or use SSH as a user
data path.

The CLI intentionally cannot prove downstream revocation propagation; server,
agentunnel, and papercode must provide that evidence in the release review.
