# Paperboat P2P Contracts v1

This contract family is approved by the workspace owner for the P2P-primary transport
release. JSON objects are closed world, field names are snake case, timestamps are UTC
RFC 3339 with second precision, and binary values use canonical unpadded base64url.
Unknown fields, duplicate fields, trailing data, non-canonical encodings, zero generations,
expired authority, and generation rollback are terminal protocol failures.

## Endpoint certificates

An account has one or more active Ed25519 trusted signing keys, one per enrolled CLI
endpoint. Canonical certificate bytes are the existing `PBEC` binary
encoding: ASCII `PBEC`, version byte `1`, big-endian uint16 account-ID length and bytes,
one role byte (`1` CLI, `2` machine), big-endian uint16 endpoint-ID length and bytes,
32-byte X25519 Noise key, 32-byte Ed25519 QUIC key, then big-endian uint64 generation,
serial, issued Unix second, and expiry Unix second. The final 64 bytes are the Ed25519
signature over every preceding byte. Generation and serial are positive and at most
`9007199254740991`, IDs match
`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`, keys are non-zero, and expiry is after issuance.
The HTTP document contains the signing `key_id`, canonical unpadded-base64url certificate
bytes, and indexed metadata; metadata must exactly equal the parsed bytes. Certificates
are immutable and identified by `(account_id, endpoint_id, generation, serial)`. A
generation may have one active certificate. Supersession and revocation are server-side
state and do not alter certificate bytes. Verification selects the active trusted key by
`key_id`, checks its fingerprint and signature, then checks role, validity, generation,
serial, endpoint binding, supersession, and revocation.

`GET /v1/e2ee/root` returns the authenticated account's complete active trusted-key set.
The first CLI uses idempotent `POST /v1/e2ee/bootstrap` to create its trusted key and its
key-signed generation-1 certificate in one transaction. A fresh CLI bootstrap adds one new
trusted key and certificate without revoking other active endpoints. The CLI endpoint ID
must equal the authenticated CLI session ID. Exact replay returns the same authority; a
different key is an identity conflict. Every trusted-key entry includes its `key_id`,
public key, fingerprint, and generation.

Each machine installation generates and durably retains its own X25519 Noise private key
and Ed25519 QUIC private key. It publishes only the corresponding public keys through
machine-proof-authenticated `POST /v1/machine-peer-identity`, bound to the current machine
ID and installation generation. The server retains the pending request for five minutes.
The host and CLI independently derive the displayed lowercase safety code from the first
five bytes of `BLAKE2s("paperboat-machine-endpoint-v1" || 0x00 || endpoint_id || 0x00 ||
big_endian_generation || noise_public_key || quic_public_key)`, rendered `xxxxx-xxxxx`.
The CLI lists pending requests through `GET /v1/e2ee/pending-endpoints` but signs one only
after the user supplies the exact compared code. Certificate registration must match the
pending endpoint, generation, and both public keys and fulfills that request atomically.
The machine retrieves only the active trusted-key set and its approved certificate through a fresh
machine-proof-authenticated `POST /v1/machine-peer-identity/status`, then verifies the
certificate with its identified trusted key and checks the exact local public-key binding
before persistence. Request/status replay is
deterministic. A missing, expired, mismatched, conflicting, or revoked authority fails
closed. Trusted signing-key private material never enters the machine runtime or server,
and no endpoint private key enters any control-plane request, response, database, log, or
audit.

Registration uses `PUT /v1/endpoints/{endpoint_id}/certificates/{generation}` with the
certificate document and an operation ID. Identical replay succeeds; conflicting replay is
`operation_conflict`. Retrieval uses `GET` on the same resource. Revocation uses `DELETE`
with `If-Match` set to the quoted serial and is idempotent.

## Peer attempt descriptors

`POST /v1/peer-attempts` is authenticated and idempotent by `operation_id`. It returns one
descriptor for an exact intent, endpoint pair, role, attempt generation, and network
generation. Both role views include the account ID, initiating CLI device ID, original
operation ID, current machine installation generation, and current runtime-connector
authorization generation. They include the complete active `trusted_keys` set, and each
entry in `endpoint_certificates` includes the signing `key_id` alongside the certificate.
They also include one exact server-authorized consumer;
interactive authority permits only `terminal`, `exec`, or `ssh`, while every private/probe
purpose permits only its canonical consumer. Both endpoints bind that field into the E2EE
transcript. The server resolves the machine's current admitted runtime connector and a fresh
ready
tunnel node; callers never select signaling, STUN, or relay infrastructure. Direct ICE
credentials are random per intent, encrypted at rest, and replayed exactly for the same
operation. The descriptor expires within five minutes and contains only currently authorized
paths. Clients do not follow redirects. Refresh creates a new attempt generation;
the same generation is never reissued with different authority. Cancellation uses
`DELETE /v1/peer-attempts/{intent_id}/{attempt_generation}` and revokes every included
credential and route handle.

The initiating CLI receives the controlling view directly. The machine retrieves the
controlled view through machine-proof-authenticated
`POST /v1/machine-peer-attempts/next`, fenced by its current installation generation. An
empty queue returns no descriptor. Both views contain identical immutable intent,
generation, certificate, ICE, relay, expiry, and policy authority and differ only in role
and the role-scoped signaling credential. Exact polling replay returns the same active
authority. A stale connector, machine generation, certificate, node, trusted key, client session,
or revoked/expired intent returns no usable descriptor and never downgrades.

Availability, timeout, UDP-blocked, and verified reachability errors are fallback-safe.
Authentication, authorization, certificate, protocol, revocation, generation, malformed
response, and policy errors are terminal and never downgrade.

## Relay admission

The server allocates an opaque route token for the exact intent, reciprocal endpoints,
carrier, attempt/network/route generations, expiry, and directional byte limits. Each
logical stream uses a distinct opaque one-time admission handle. Tokens and handles are
canonical base64url random values with at least 128 bits of entropy. A handle is consumed
atomically before forwarding. Replay, role mismatch, carrier substitution, stale generation,
expiry, revocation, or exhausted limits receives the same external rejection. QUIC and WSS
apply identical admission semantics. Drain rejects new streams while allowing admitted
streams until their deadline; reassignment always increments `route_generation`.
Descriptors advertise only relay carriers implemented by the selected node. A relay entry
must include at least one of `quic_url` or `wss_url`; absent carriers are omitted rather than
represented by an unusable URL.

## Relay PMTU probes

Each relay descriptor includes a `udp://host:port` PMTU endpoint and a distinct signed
`peer_pmtu` credential with exact scope `peer:pmtu`. The credential is bound to the intent,
environment, selected edge node, route allocation, endpoint pair, attempt/network/route
generations, and expiry. It grants no signaling, relay-stream, or application authority.

Relay PMTU datagrams are 1,200 through 1,500 bytes. Their network-byte-order layout is
ASCII `PBMT`, version byte `1`, kind byte (`1` request, `2` response), uint16 exact datagram
length, 16 random nonce bytes, and uint16 credential length. A request carries that many
credential bytes followed by zero padding. A response has zero credential length and zero
padding, with the final 32 bytes replaced by HMAC-SHA256 over every preceding response byte
using the exact PMTU credential bytes as key. The tunnel verifies signature, class, scope,
bindings, expiry, revocation, and rate limits before responding. The client accepts only the
configured source, exact size, nonce, and HMAC. Invalid traffic is silently discarded.
Probes use DF/packet-too-big socket controls; fragmented success is never evidence.

## File-transfer E2EE extension

The existing `/v1/file-transfers` identity, lifecycle, HTTP/3 then HTTP/2 fallback, limits,
expiry, completion, receipt, and cleanup remain authoritative. Version 1 adds an `e2ee`
envelope. Relays see only opaque identifiers, ordinals, ciphertext lengths, and ciphertext.
Transfer-key delivery uses the distinct peer-attempt purpose and private-stream consumer
`file_transfer_key`, with an exact transfer ID, generation, and expiry binding. It admits
one bounded key-control stream over direct QUIC, relay QUIC, or WSS and cannot dispatch an
interactive consumer. The recipient durably stores the key before acknowledging it.
The encrypted manifest binds transfer ID, generation, sender/receiver endpoint certificates,
ordered file metadata, chunk size, total plaintext bytes, and plaintext digest. Each chunk is
independently AEAD-sealed with a nonce derived from transfer generation and ordinal; ordinals
start at zero, never repeat, and resume only at an authenticated committed ordinal. The final
receipt authenticates the manifest digest, final ordinal, plaintext digest, and byte count.
The sender acknowledges the authenticated receipt digest through the existing receipt route;
the recipient retains the key across uncertain completion responses and erases it only after
that acknowledgement or bounded expiry. Receipt acknowledgement is idempotent.
WSS is ineligible for manifest, chunk, receipt, or any other file-content bytes.

## Private-preview E2EE extension

Private-preview streams use the distinct peer-attempt purpose and private-stream consumer
`private_preview`. This purpose cannot authorize terminal, exec, SSH, file-transfer key, or
other interactive application streams.

## Codex E2EE extension

Codex management HTTP and app-server WebSocket connections use the distinct peer-attempt
purpose and private-stream consumer `codex`. It admits only `native-health` and one
`codex-http` stream. The existing session-bound `codex_manage` or `codex_connect` credential
is still authenticated inside that stream. Codex session routes are never exposed by the
tunnel edge, and their logical `machine.paperboat.invalid` authority is not network-routable.
This purpose cannot authorize terminal, exec, SSH, preview, or file-transfer streams.

Authenticated user diagnostics use the distinct peer-attempt purpose and probe-only consumer
`health_probe`. It admits health exchanges on direct QUIC, relay QUIC, or WSS, opens no
application stream, and cannot authorize any interactive or transfer consumer.

## Managed SSH

Client public keys use `PUT/DELETE /v1/ssh/client-keys/{fingerprint}`. Machine targets use
`PUT/GET /v1/machines/{machine_id}/ssh-target`; host-key observations use
`PUT/GET /v1/machines/{machine_id}/ssh-host-keys`. Every mutation requires
`Idempotency-Key`, is replayed by its exact operation ID and request hash, and is fenced by a
positive generation. The first complete host-key set reported through authenticated machine
authority becomes active. A later changed set remains pending and cannot replace the active
set implicitly. Promotion uses
`POST /v1/machines/{machine_id}/ssh-host-keys/{set_id}/promote`, requires user authority, and
is fenced by the machine generation and the pending set's expected aggregate fingerprint.
Successful promotion supersedes the previous active set. Stale observation generations,
machine generations, set IDs, reconciliation versions, or fingerprints fail closed.
Readiness requires an active client key, a ready target, and an active host-key set. Audit
records contain IDs, generations, fingerprints, actor, action, result, and request ID, never
private keys or session content.

## Stable errors

All HTTP failures use the approved common error envelope. P2P contracts use these stable
codes: `authentication_required`, `permission_denied`, `not_found`, `operation_conflict`,
`invalid_request`, `invalid_certificate`, `certificate_expired`, `certificate_revoked`,
`generation_conflict`, `generation_exhausted`, `intent_revoked`, `descriptor_expired`,
`route_unavailable`, `udp_blocked`, `reachability_failed`, `admission_rejected`,
`byte_limit_exhausted`, `transfer_expired`, `ordinal_conflict`, `integrity_failed`,
`ssh_key_rejected`, `ssh_target_not_ready`, `ssh_host_key_changed`, `rate_limited`, and
`temporarily_unavailable`. Retry metadata is present only for `rate_limited`,
`temporarily_unavailable`, `route_unavailable`, `udp_blocked`, or `reachability_failed`.
