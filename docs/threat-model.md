# Paperboat CLI Threat Model

## Assets and trust boundaries

- Paperboat access and refresh credentials are high-value assets. They remain in
  the OS credential store, with owner-only `0600` files used automatically when
  the credential service is unavailable on a headless system.
- Device codes are short-lived approval handles, not credentials. They are shown
  only in the terminal and browser URL; tokens are never placed in URLs.
- The CLI treats environment descriptors, route URLs, machine paths, and server error
  messages as untrusted input. Descriptor validation and issuer binding happen
  before a terminal or file-transfer connection is opened.
- Private terminal, exec, preview, Codex, SSH, and file content is end-to-end encrypted
  between the initiating CLI endpoint and the target machine endpoint. Direct QUIC, relay
  QUIC, WSS, relay HTTP/3, and relay HTTP/2 carry only authenticated ciphertext. WSS never
  carries file bytes. `paperboat-server` and `paperboat-tunnel` have no content-decryption
  key or support decryption path. Public-preview content is intentionally public and outside
  this claim.
- Endpoint certificates bind account, endpoint ID, role, generation, Noise key, QUIC key,
  serial, and expiry under the account root signature. Private root and endpoint keys stay in
  their endpoint credential boundary and never enter a server/tunnel request, database, log,
  metric, diagnostic bundle, or audit record.

### ENV host-recipient custody

Native hosts retain the approved OS/systemd secure-store paths for the dedicated X25519 ENV
recipient. Portable OCI hosts (including Docker and Podman) and Firecracker guests use the
runtime's default writable state instead: a domain-separated key derived from the local machine
identity seals a separate recipient key in an authenticated AES-GCM envelope at
`environment/host-key.sealed`. The recipient private key is never accepted from an environment
variable, setup flag, mount, or server response, and it is never written as plaintext.

The writable state and machine identity must survive a restart for offline ENV recovery. If the
identity or state is recreated, the old envelope cannot be opened; the runtime creates a new
recipient only in new state and requires the normal server authorization for it. The server can
authorize and revoke the public recipient but cannot derive or decrypt the local wrapping key.

## Exposed operational metadata

The control plane and tunnel may process only the metadata needed for authorization, routing,
abuse control, and accounting: account/environment/endpoint opaque identifiers, operation and
intent identifiers, endpoint certificate public material and fingerprints, carrier and relay
region, attempt/network/route generations, candidate addressing during authenticated signaling,
timestamps and expiry, ciphertext lengths and counters, health states, and typed failure codes.
They must not receive private-content plaintext, private keys, commands, paths, filenames,
terminal output, preview bodies, SSH payloads, or file manifests/chunks in plaintext.

## Threats and controls

| Threat | CLI control | Residual owner |
| --- | --- | --- |
| Device-code phishing or brute force | Server-authoritative expiry/interval; user sees the complete URL and short code; no token in output | Server/dashboard rate limits and approval UX |
| Token theft or refresh replay | OS credential store, issuer-namespaced profiles, refresh rotation, durable revoke queue | Server session-family revocation |
| Malicious route or descriptor | Scheme, issuer, environment, endpoint, scope, generation, and expiry validation; no raw VM/public-TCP fallback | Server route authorization and `paperboat-tunnel` enforcement |
| Compromised relay or control plane | Root-signed endpoint certificates, endpoint-authenticated QUIC/Noise handshakes, encrypted stream headers and records, replay/generation fencing | Traffic timing, endpoint addressing, ciphertext length, and authorized routing metadata remain observable |
| Carrier downgrade | Authentication, authorization, certificate, protocol, revocation, and generation failures are terminal; only availability failures may select the next equally encrypted carrier | A network observer can block preferred carriers and force an allowed encrypted fallback |
| Terminal injection | Non-file bytes pass through unchanged; rewriting is limited to a bracketed paste frame | `pb` host-runtime terminal authorization |
| Compression side channel or decompression exhaustion | Each output event is an independent Zstandard frame with no dictionary or cross-session state; declared decoded size, frame content size, decoder memory, and concurrent codecs are bounded before delivery or ACK | A user controlling and observing the same authenticated terminal can still correlate its own input and output sizes |
| File traversal or substitution | Absolute regular files only; symlinks/traversal rejected; one descriptor is hashed and streamed; signed size policy | `pb` host-runtime transfer verification and cleanup |
| Static-serve traversal or source substitution | Loopback-only listener; pinned canonical source identity; root-scoped opens; dotfile, listing, traversal, and symlink-escape denial; identity revalidation before start and on every request | A user with local filesystem write access can make the source unavailable, but cannot silently replace the pinned source |
| Static-serve path disclosure | Source paths and browsing activity stay in owner-only local state and are omitted from control-plane, dashboard, telemetry, and diagnostics | An authorized local user can inspect their own descriptor and served path |
| Compromised machine endpoint | CLI receives only short-lived, scoped operation credentials; endpoint revocation and generation fencing stop future authorization | Content already decrypted or keys already exposed on that endpoint cannot be recovered cryptographically |

## Incident actions

For a stolen device, revoke its client session and endpoint certificate, then remove the
local profile with `pb auth logout`. For a suspected incompatible or tampered server, stop
retrying, capture only stable opaque IDs and fingerprints, and upgrade from a verified release.
Never bypass the common Paperboat transport. `pb ssh` and the managed OpenSSH ProxyCommand are
approved only because their SSH byte stream uses that transport and terminates at the machine's
existing system `sshd`.

Loss or suspected compromise of the account root requires the explicit account recovery/reset
flow: revoke every endpoint certificate, advance the authorization generation, create a new
root in the endpoint credential boundary, and re-pair every CLI and machine endpoint. The server
must never fabricate a replacement root or silently trust an endpoint. Loss of one endpoint key
revokes and re-enrolls only that endpoint when the account root remains available.

The CLI intentionally cannot prove downstream revocation propagation;
`paperboat-server`, `paperboat-tunnel`, and `paperboat` must provide that evidence
in the release review.
