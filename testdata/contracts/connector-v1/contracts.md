# Paperboat connector control protocol v1

This document is the authority for the `paperboat.connector` v1 control
session. `fixtures/vectors.ndjson` contains normative wire examples. The Go
implementation in `paperboat/internal/connectorprotocol` is the canonical
implementation source; `sync-consumers.sh` copies it and the shared tests to
`paperboat-server` and `paperboat-tunnel`. Consumer copies must be byte
identical. Server-only SQL persistence is deliberately outside that shared
file set.

## 1. Wire envelope and bounds

Each message is a length-prefixed JSON `Frame`:

```json
{"type":"snapshot","version":"1.0","request_id":"req_1","payload":{}}
```

The four-byte length is big-endian and covers the JSON frame. `type` is one of
`hello`, `welcome`, `snapshot`, `delta`, `ack`, `ready`, `heartbeat`,
`heartbeat_ack`, `auth_renew`, `auth_renewed`, `drain`, `drain_ack`,
`credential_rotation_challenge`, `credential_rotation_proof`,
`credential_rotation_install`, `credential_rotation_ready`,
`credential_rotation_revoke`, `credential_rotation_ack`, `disconnect`, or
`reject`. `version` is exactly `1.0`; `request_id` is a
bounded protocol identifier. A frame is rejected before allocation or
application when it is empty, malformed, unknown, duplicated, trailing,
oversized, or nested beyond the JSON depth bound.

The complete frame limit is 4 MiB plus 64 KiB for the envelope. The typed
snapshot payload is at most 4 MiB and the typed delta payload is at most 1 MiB;
other typed payloads are at most 64 KiB. A frame writer must write all bytes or
return an error. Readers must not treat a partial frame as success.

All typed decoders reject unknown fields, duplicate object keys, trailing JSON,
and invalid JSON numbers. Canonical configuration JSON is
decoded with JSON-number preservation, recursively checked for a maximum depth
of 64, checked for secret-bearing names and values, then re-encoded with sorted
object keys before hashing. Fields such as `api_key`, `authorization`,
`bearer`, `cookie`, `headers`, `password`, `private_key`, `refresh_token`,
`secret`, `token`, URL userinfo, secret query parameters, and private-key
blocks are forbidden. Credential `*_reference` and thumbprint metadata are
allowed; reusable credential bytes are not.

## 1.1. Data-stream admission preface

Each byte stream opened over an authenticated carrier begins with one strict
connector-v1 `StreamOpen` preface. It is a four-byte big-endian JSON length
followed by a JSON object no larger than 16 KiB. The object carries
`protocol`, `version`, `account_id`, `tunnel_id`, `connector_id`, `session_id`,
`process_generation`, `generation`, `route_id`, `request_id`, and `kind`.
`kind` is one of `http`, `https`, `h2c`, `websocket`, `sse`, `grpc`,
`tcp_private`, `private_access_http`, or `private_access_tcp`. The edge rejects malformed, unknown-field, duplicate-key,
oversized, stale-identity, and unauthorized prefices before forwarding any
application bytes. The bearer or reusable session credential belongs only to
carrier authentication and is never repeated in this per-stream preface.

The client-initiated private-access kinds are used only by stable hostd after
the local Paperboat CONNECT proxy selects a private hostname. Immediately
after `StreamOpen`, hostd sends one bounded `private_access_stream` frame with
the short-lived server-signed grant and the exact server-normalized request
binding. The binding covers account, machine installation, resource, route,
carrier session, edge node/process epoch, and route/session/process/config/
assignment generations. The edge authorizes that signed grant with the control
plane before opening the target, then replies with one result carrying only
status `200`, `401`, `403`, or `503` and an expiry for `200`. Application bytes
follow only after `200`.

Browser cookies, browser authorization headers, browser-generated proof,
machine bearer credentials, and machine proof never enter the carrier
envelope. Hostd creates machine proof only for the grant-issuance control-plane
request. The edge uses its own edge credential when validating the signed grant.

## 1.2. Data-carrier TLS identity

Every connector data-carrier client certificate contains exactly one URI SAN
for its live connector identity. Paperboat does not use a private X.509
extension OID for this binding. The URI is:

```text
urn:paperboat:connector-v1:carrier:<raw-base64url-sha256>
```

The digest is SHA-256 over the UTF-8 bytes of this exact compact JSON
transcript, with fields in the shown order:

```json
{"account_id":"...","host_id":"...","tunnel_id":"...","connector_id":"...","session_id":"...","process_generation":1,"config_generation":1,"edge_process_epoch":"..."}
```

All identifiers, both non-zero generations, and the opaque edge process epoch
are required. The certificate
is accepted only when the URI SAN equals the expected authenticated admission
identity and the certificate public key equals the enrolled machine identity
key. Missing, duplicate, unrelated, or stale URI SANs fail closed. This exact
session, generation, and edge-process binding prevents overlapping old and
replacement host or edge processes that use the same enrolled machine key or
stable edge node ID from being confused. Route
IDs are excluded because one authenticated carrier multiplexes many
separately authorized `StreamOpen` routes.

## 2. Version, capability, and identity negotiation

The connector starts with `hello` and offers a numeric `min_version` and
`max_version`. Both must be canonical non-negative decimal versions and the
range must include exactly the server's `1.0`; overflowing components are
invalid, not zero. The server replies with `welcome` and the selected version.

The required capabilities are:

- `config.snapshot.v1`
- `config.delta.v1`
- `config.ack.v1`
- `session.heartbeat.v1`
- `auth.renew.v1`

`connector.drain.v1` is required before using drain messages. Capability names
are unique, bounded, and negotiated as the intersection of the two peers. A
missing required capability is a typed `capability_missing` rejection.

`hello` and its `auth` object must agree on account, tunnel, connector, host,
and process-generation identity. After `welcome`, every bound message repeats
account, tunnel, connector, session, and process-generation identity. The
server binds unbound snapshots and deltas at its internal offer boundary; a
client wire snapshot or delta must carry all of those fields and the client
requires each one to be non-empty and exact. A message from another account,
tunnel, connector, session, or process generation is rejected before state
changes.

The live registry key is `(connector_id, process_generation)`. A higher
process generation replaces the old session. Close, timeout, disconnect, and
cleanup operations compare the complete session reference, so an old session
cannot remove or mutate a newer one.

## 3. Renewable authentication

`auth` carries only identity and proof metadata:

- account, tunnel, connector, and host IDs;
- Ed25519 `identity_key_id` and RFC 7638-compatible key thumbprint;
- process and credential generations;
- a 16..128-byte nonce;
- `issued_at`, `expires_at`, and detached `signed_proof`.

The control wire never carries an operating-system credential reference,
bearer, cookie, private key, or secret. The connector keeps private material
behind its local authenticator. The server resolves the enrolled host/device
public identity and the active or overlap credential public key from durable
enrollment state, scoped by account, tunnel, connector, host, key ID, and
credential generation. It never persists bearer bytes.

`AuthProofPayload` is the UTF-8 JSON encoding of this exact transcript, with
the field names and order emitted by the canonical implementation:

```json
{"domain":"paperboat.connector.auth.v1","protocol":"paperboat.connector","version":"1.0","account_id":"...","tunnel_id":"...","connector_id":"...","host_id":"...","identity_key_id":"...","identity_key_thumbprint":"...","process_generation":1,"credential_generation":1,"nonce":"...","issued_at":"...","expires_at":"..."}
```

`RenewalProofPayload` uses domain `paperboat.connector.auth.renew.v1` and
binds the same identity plus `session_id`, `nonce`, and `requested_at`; it
does not include auth-only issue or expiry fields. The detached signature is
Ed25519 over those exact bytes. Changing any identity, generation, nonce,
timestamp, session, domain, protocol, or version invalidates the proof and
cannot be replayed in another context.

Auth `issued_at` and renewal `requested_at` must be within ±2 minutes of the
server clock. Auth validity is no longer than 15 minutes and its expiry must
still be in the future. Lease expiry cannot outlive credential expiry or the
configured maximum lease (24 hours). A renewal is a compare-and-swap against
the authenticated session and credential generation.

The server reserves the proof nonce and transcript digest in the durable,
dedicated `connector_proof_replays` ledger in the same database transaction as
credential authorization. The key scope is account, tunnel, connector,
proof kind, and nonce, with a unique proof digest, expiry, and bounded indexed
cleanup. Replays are rejected across process restarts and server replicas;
`operations` is not used as an auth replay ledger.

## 4. Snapshot, delta, and content hash

The first configuration after `welcome` is always a complete `snapshot` with
non-zero `generation`, canonical `payload`, and a SHA-256 `content_hash` in
`sha256:<64 lowercase hex>` form. The hash is over the exact canonical bytes
of `payload`, not the outer identity envelope.

The payload is exactly a `tunnel_config_snapshot` object:

```json
{
  "schema":"paperboat.preview-tunnel/v1",
  "kind":"tunnel_config_snapshot",
  "tunnel_id":"...",
  "generation":1,
  "name":"...",
  "desired_state":"active|paused|deleted",
  "access_mode":"public|private",
  "stable_endpoint":"https://<canonical-lowercase-uuid>.tunnels.pprbt.dev",
  "expires_at":null,
  "routes":[{"id":"...","name":"...","protocol":"http|tcp_private", "match_type":"managed_exact|exact|one_label_wildcard|catch_all", "match_hostname":"...", "wildcard_suffix":"...", "path_prefix":null, "origin_scheme":"http|https|h2c|unix|tcp", "origin_address":"...", "preserve_host":true, "host_override":null, "tls_verification":"not_applicable|system|custom_ca|mutual_tls|insecure_development", "tls_server_name":null, "ca_reference":null, "mtls_credential_reference":null, "connect_timeout_ms":10000, "idle_timeout_ms":90000, "max_concurrent_streams":128, "desired_state":"active|disabled|deleted"}]
}
```

All listed top-level fields and the base route fields are required. Nullable
route settings are sent as explicit nulls. Match hostname and wildcard suffix
are conditional: exact routes carry a hostname, one-label wildcard routes
carry a suffix, and catch-all routes carry neither. Routes are emitted in
deterministic server order. HTTP routes may use HTTP,
HTTPS, h2c, or Unix origins; `tcp_private` routes require a TCP origin. Match
type rules are mutually exclusive: exact forms carry a hostname, one-label
wildcards carry only a suffix, and catch-all carries neither. TLS settings
are only meaningful for HTTPS origins. References remain metadata, never
secret material.

A `delta` is also a complete canonical `tunnel_config_snapshot` payload for
the new generation. It carries `previous_generation`, `generation`,
`previous_content_hash`, and `content_hash`; generation must be exactly the
previous generation plus one, and the previous hash must equal the receiver's
active hash. The new hash must equal the payload hash. A missed generation,
wrong previous hash, or pending candidate produces a typed
`snapshot_required`/`generation_gap` recovery acknowledgement. No subsequent
delta is accepted until a full snapshot is applied. A same-generation,
different-hash value is immutable-state corruption and is rejected.

## 5. Apply, readiness, acknowledgements, and failure ordering

Configuration application is two phase. `ConfigApplier.PrepareSnapshot` or
`PrepareDelta` stages a candidate without changing active traffic and returns
a `PreparedConfig` with bounded-context `Activate` and `Abort`. A successful
apply acknowledgement records only the candidate. The old ready generation is
the last-known-good (LKG) and remains eligible while edge, route, and origin
readiness is evaluated. Only an all-true `ready` for the exact candidate hash
may activate and promote it. A failed prepare or activation aborts the
candidate and preserves the LKG. A not-ready readiness observation leaves the
candidate staged for another bounded readiness attempt; an explicit rejection
or persistence failure withdraws it and preserves the LKG. Cleanup is bounded
and its error is joined with the primary failure.

`ack.kind` is `snapshot`, `delta`, `ready`, or `auth_renew`; status is one of
`applied`, `duplicate`, `rejected`, or `snapshot_required`. Rejected acks carry
one finite known `code`; other statuses carry no code. A peer must send a
valid, identity-bound negative acknowledgement alongside a generation-gap or
apply error whenever the request was identifiable, so the sender receives the
recovery instruction even when application failed. SQL persistence records
negative apply/recovery acks as failure or recovery state and never advances
applied generation for them.

Readiness must repeat the exact account/session/tunnel/connector/process,
generation, and hash. Persistence changes the durable config generation to
active only after the new generation is ready, clears the previous active
generation's `activated_at`, and keeps the one-active-generation invariant.
Any persistence failure withdraws eligibility and requires reconnect or full
snapshot recovery. There is no silent in-memory-only production downgrade.

## 6. Leases, heartbeats, and liveness

The `welcome` lease's `session_id` equals `welcome.session_id`; heartbeat
interval is shorter than the lease. A connector heartbeat reports the exact
active generation/hash and has a `sent_at` within ±2 minutes of server time.
For one session, `sent_at` must be strictly increasing. Equal or older
heartbeats are stale and do not renew a lease. A heartbeat with a generation or
hash different from active readiness withdraws readiness, retains the LKG,
and requests a full snapshot. Before the first snapshot, heartbeat is invalid
and snapshot recovery is required.

The server renews the lease only after identity, generation, freshness, active
credential, and content-hash checks. Direct SQL persistence repeats the
account/session checks under row locks and cannot regress heartbeat timestamps.
Lease timeout, credential expiry, context cancellation, and server shutdown
produce typed disconnect state. Cleanup uses a detached short timeout when the
caller context is already canceled.

## 7. Drain protocol

Drain requires the negotiated `connector.drain.v1` capability. A server
`drain` request carries account, tunnel, connector, session, process
generation, exact active generation/hash, an operation `drain_id`, a future
deadline, `stop_new_streams:true`, and `force_after_deadline`. The connector
must stop admitting new streams before counting existing streams.

`drain_ack` statuses are `accepted`, `progress`, `completed`, `forced_close`,
and `rejected`. Accepted/progress report a bounded active-stream count and no
code. Completed reports zero streams. Forced close reports zero streams,
`forced_close:true`, and `drain_timeout`. Rejected reports
`forced_close:false` and `drain_rejected`. All acks repeat the exact identity,
drain ID, generation, and hash. The same drain ID is idempotent; a different
ID or stale generation cannot affect the session.

The client adapter exposes `StopNewStreams`, bounded `ActiveStreams`, and
bounded `ForceClose`; the control package does not own data-plane streams. The
server changes `ready` to `draining` immediately, so `Current` is no longer
eligible for new traffic while existing streams drain. Completion, forced
close, and rejection are persisted against the exact drain operation ID,
account, connector, and operation type (`connector.drain` or
`connector.revoke`).

## 8. Disconnect, rejection, and operations

Disconnect reasons are finite: `protocol_mismatch`, `capability_missing`,
`malformed_message`, `authentication_failed`, `credential_expired`,
`lease_expired`, `heartbeat_timeout`, `session_replaced`,
`stale_generation`, `snapshot_rejected`, `generation_gap`,
`credential_rotation`, `canceled`, `server_shutdown`, and
`protocol_closed`. Rejection and acknowledgement codes are likewise finite
typed values. Callers branch on these values, retry flags, and recovery status,
never error-message text. A disconnect or persistence failure withdraws new
traffic eligibility immediately; the durable session and operation are marked
uncertain/recoverable with the exact connector and process generation.

The production server adapter persists authentication, negotiated session
metadata, applied/rejected/recovery acknowledgements, readiness, heartbeat,
renewal, drain, rotation, and exact-generation disconnect transitions against
the connector/session/config-generation rows. It requires metadata and drain
persistence at construction, uses a dedicated durable proof-replay ledger,
and fails closed on persistence errors. Cleanup uses a detached bounded
context. The server operation worker owns discovery and resume through the
bounded `ListCredentialRotationPlans` and `ResumeRotation` boundary; it must
not reconstruct a plan from a fresh connector listing.

### 8.1 Credential rotation

Credential rotation is an aggregate operation scoped to one tunnel. At
request time the server locks the connector rows, captures a sorted immutable
target set `(connector_id, host_id, old_generation, new_generation)`, computes
`target_set_hash`, and stores `overlap_until` and
`new_credential_valid_until` in the same transaction as the operation. A
connector enrolled after that transaction is not a target. Retries and
restart recovery must load this exact set and hash; they may not recapture
current connectors or alter either deadline.

For each target, the server sends one `credential_rotation_challenge` to the
old session. It contains only that connector's target, the operation/hash,
old and new generations, the old public identity, a fresh nonce, the old
session/process identity, challenge expiry, overlap deadline, and new
credential deadline. The complete target list is never sent to a connector.
The session must have negotiated `credential.rotate.v1`; otherwise the target
is rejected without issuing a challenge. An expired challenge may be
re-issued only for the same operation, target, hash, generations, and stored
deadlines, with a new nonce and replacement session/process identity.

The connector answers with `credential_rotation_proof`. Its old-key
signature and new Ed25519 public-key proof both cover the canonical,
domain-separated rotation transcript: protocol/version, account, tunnel,
operation, connector, host, session/process generation, target-set hash, old
and new generations and key identities, new public key/reference, challenge
nonce, issued time, and new credential deadline. The server resolves the old
public key under a row lock and reserves the proof digest/nonce in the durable
replay table in the same transaction. References and thumbprints are metadata;
private keys, bearer tokens, cookies, and reusable secrets never cross or enter
the database.

After proof verification, the server stores the new public key/reference in
overlap state while leaving the old credential authoritative. The connector
installs the replacement process and returns an exact-session `installed`
acknowledgement. A replacement session then sends `credential_rotation_ready`
with a strictly newer process generation, the old-session link, new key
identity/generation, config generation/hash, and all edge/route/origin
readiness flags true. The server promotes the new credential and connector
pointer only after this exact readiness is durably committed, clears the old
generation's active marker, and keeps it valid only through the stored overlap
deadline. Failed prepare, install, readiness, or persistence leaves the old
last-known-good credential authoritative and marks the target failed; it must
not switch the pointer early.

Only after every target is ready does the server send an exact-session
`credential_rotation_revoke`. A valid revoke acknowledgement transitions the
old generation to revoked. Revoke is idempotent and cannot overwrite revoked
or forced-closed terminal state. The aggregate succeeds only when every target
is revoked; any typed target failure fails the aggregate and includes only
server-owned, redacted recovery text. A forced close is a successful terminal
outcome for `connector.revoke` but a failed/uncertain outcome for ordinary
`connector.drain`.

Target transitions and audit events use exact operation ID, account, target
set hash, connector, session, process generation, and credential generation
CAS predicates. `applied`, `ready`, `revoke`, negative acknowledgements,
disconnect recovery, and audit writes are idempotent. A duplicate, wrong
session/process, wrong target, stale generation, missing capability, replayed
nonce, or cross-account message is rejected without advancing any target.
`RecordCredentialRotationResult` must validate the complete aggregate summary
and target membership before accepting a terminal result. On restart, workers
list bounded pending/uncertain plans, load their immutable target rows, resume
valid phases, and re-issue only expired challenges; impossible or incomplete
phase records fail closed for operator recovery.

### 8.2 WebSocket control transport

The connector opens `GET
/v1/tunnels/{tunnel_id}/connectors/{connector_id}/control` over HTTPS and MUST
offer exactly the WebSocket subprotocol `paperboat.connector.v1`. The server
selects that subprotocol or closes the connection. Binary WebSocket messages
carry the existing length-prefixed connector-v1 frames without compression.
The URL has no query parameters.

The signed connector-v1 `Hello` is the sole authentication exchange. The
upgrade request carries no bearer authorization, cookie session, browser
credential, query token, or alternate authentication header. The path tunnel
and connector IDs are only routing fences and MUST equal the signed `Hello`
identity. The first frame MUST be `Hello`; a missing, malformed, mismatched, or
unverifiable `Hello` fails closed without creating an active session.

### 8.3 Carrier bootstrap descriptor

After `Welcome` and the first exact configuration snapshot, the stable host
requests data-carrier endpoints with `POST
/v1/tunnels/{tunnel_id}/connectors/{connector_id}/carrier-bootstrap`. This is
a separate HTTPS request authenticated by the current renewable machine
identity and a detached `X-Paperboat-Machine-Proof` over the exact method,
path, and body. `Idempotency-Key`, `X-Paperboat-Machine-Identity`, and
`X-Paperboat-Machine-Proof` are each required exactly once. The proof's
account, host, and operation ID MUST match the active control session and the
idempotency key. Browser sessions, connector bearer tokens, query credentials,
and cookies cannot authorize this endpoint.

The `application/json` request body is exactly:

```json
{"schema":"paperboat.connector-bootstrap/v1","kind":"carrier_bootstrap_request","session_id":"session_01","process_generation":2,"config_generation":4,"config_content_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
```

Unknown or missing fields are rejected. The session, process, config
generation, and config content hash MUST equal the active signed control
session. A stale tuple returns the typed `connector_session_stale` error and
requires reconnect before retry.

Success is a `no-store` JSON response whose `data` is exactly one
`carrier_bootstrap_descriptor`. It binds `account_id`, `tunnel_id`,
`connector_id`, `host_id`, and the server-owned immutable `stable_endpoint_id`
(a canonical lowercase UUID) to the requested account and tunnel, along with
`session_id`, `process_generation`, `credential_generation`,
`config_generation`, and `config_content_hash` to the active control session.
The host passes this exact endpoint identity into production assembly; it never
derives one from a tunnel name or URL. `issued_at` and `expires_at` are UTC
timestamps; expiry is strictly after issue and no more than two minutes later.

The descriptor contains one to four carriers. Every carrier has a distinct
`failure_domain` and distinct `(edge_node_id, edge_process_epoch)` pair. Each
has exactly two authority-only endpoints: exactly one `tls://host:port` and
exactly one `quic://host:port`. The connector authenticates the carrier using
both `server_spki_sha256` in `sha256:<64 lowercase hex>` form and a bounded,
parseable `server_certificate_chain_pem`. The descriptor and every error are
secret-free: private keys, bearer tokens, cookies, authorization values, query
credentials, and reusable proofs are forbidden.

Bootstrap errors use the preview-tunnel v1 structured error envelope. Finite
codes are `invalid_content_type`, `invalid_request`,
`machine_identity_required`, `machine_identity_invalid`,
`connector_access_forbidden`, `connector_session_stale`,
`carrier_unavailable`, `connector_control_invalid`, and
`connector_control_unavailable`. Callers branch on `code`, `retryable`, and
`repair_action`, never on message text.

### 8.4 Enrollment exchange activation

`POST /v1/tunnels/{tunnel_id}/connectors/enrollments/exchange` completes with
HTTP `202` and `Cache-Control: no-store`. Its `data` is exactly one
`connector_activation` object with schema `paperboat.preview-tunnel/v1`:

```json
{"schema":"paperboat.preview-tunnel/v1","kind":"connector_activation","account_id":"account_01","tunnel_id":"tunnel_01","connector_id":"connector_01","host_id":"host_01","stable_endpoint_id":"11111111-1111-4111-8111-111111111111","credential_generation":1,"process_generation":1,"operation":{"schema":"paperboat.preview-tunnel/v1","kind":"operation","id":"operation_01","resource_kind":"connector","resource_id":"connector_01","phase":"connecting","state":"running","progress":0,"retrying":false,"correlation_id":"correlation_01","created_at":"2026-08-31T10:00:00Z","updated_at":"2026-08-31T10:00:00Z"}}
```

The server returns the tunnel's persisted `stable_endpoint_id` alongside both
positive generations. This is the immutable canonical lowercase UUID for the
managed tunnel endpoint. The host MUST pass it through to production assembly;
it never derives the endpoint identity from a tunnel name, host identity, or
URL. The server reserves both positive generations in the same durable
enrollment transaction and binds them to the returned running connector
operation. The host MUST use these exact values in its first signed `Hello`; it
never guesses, increments, or derives either generation. The tuple is immutable
for the operation. An exact idempotent exchange replay returns byte-equivalent
activation data with the same account, tunnel, stable endpoint identity,
connector, host, operation, credential generation, and process generation. A
changed request under the same idempotency key conflicts instead of allocating
a new tuple. The activation is secret-free and supersedes the obsolete
operation-only exchange response.

## 9. Verification and ownership

Run `contracts/connector-v1/validate.sh` from the workspace root. It verifies
the family manifest and digests, validates all normative vectors and bootstrap
schema vectors, checks all three consumer copies, and runs
`sync-consumers.sh --check` so implementation
drift is detected. The root frozen contract approval ledger is intentionally
unchanged; this family has its own versioned manifest and validator.
