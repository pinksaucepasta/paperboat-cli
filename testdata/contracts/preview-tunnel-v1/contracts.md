# Paperboat Preview and Tunnel Contract v1

This family is the single language-neutral source for preview and tunnel resource
names, lifecycle state, health, errors, and events. The authoritative product behavior
is `PREVIEW_TUNNEL_OVERHAUL.md`. Consumers copy these artifacts into repository-local
testdata and must not read the workspace copy at runtime.

## Fixed vocabulary

- A `preview_lease` is temporary, owns one random managed endpoint and local target, and is
  bound to an owner device and owner session. It is never restored after reboot. It may
  request up to eight normalized exact, apex, or one-label wildcard domain aliases.
- A `tunnel` is durable desired state owned by an account. Its stable identity is not
  a connector session.
- A `route` maps protocol, hostname and optional path to an origin.
- A `domain_binding` owns hostname verification, DNS instructions and certificate
  state independently from connector availability. Its `target_kind` is exactly one
  of `tunnel_route` or `preview_lease`; tunnel bindings require only `tunnel_id` and
  `route_id`, while preview bindings require only `preview_id`. Supplying both target
  families, or neither, is invalid.
- A `connector` is one replaceable authenticated host attachment to a tunnel.
- A `config_generation` is an immutable validated desired-state snapshot.
- A `tunnel_config_snapshot` is the canonical inner desired-state payload sent
  to a connector. It contains the complete tunnel projection and active routes,
  uses wire protocol names (`tcp_private`, `managed_exact`), and is serialized
  deterministically with routes ordered by priority, name, and ID.
- An `operation` records resumable long-running mutation progress.
- A `log_entry` is a bounded, redacted diagnostic record with an opaque resume
  cursor. A `dns_instructions` resource describes only provider-supported
  records and the persisted verification state; it never claims DNS or TLS
  readiness without external proof.
- `health`, `error`, and `event` are typed contracts, never prose-only status.

No public contract uses `serve`, `preview_session`, `preview_route`, `helper`, or a v2
name for these resources.

## Exposure and creation

`public` is the default access mode for previews and tunnels. There is no positive `--public` option.
`private` means the edge authenticates and authorizes a same-account device before forwarding.

A preview requires `owner_device_id` and `owner_session_id`, has
  `persistent: false`, accepts an optional maximum `user_deadline`, and ends on stop,
  deadline, or owner loss beyond the reconnect grace period. The create request may
  include `domains`, a sorted, duplicate-free list of normalized IDNA hostnames. A
  bare name is an exact/apex alias; a leading `*.` is permitted only for one-label
  wildcard matching. The random managed endpoint is always primary and is
  readiness-gated independently from aliases. `owner_session_id` is an opaque preview-owner nonce
selected for this lease and bound to the selected machine and create operation. It is
  not a browser session ID; closing a dashboard or browser session does not stop the
  preview. Device-authenticated local CLI creation uses the machine identity path and
  the verified machine ID, never a CLI client-session ID as `owner_device_id`.

The managed preview endpoint is `https://<opaque-id>.preview.pprbt.dev` in production
(or the same opaque label under a configured development base). The server generates
the DNS-safe leftmost label, keeps it immutable for the lease, and never prefixes it
with `preview-` or derives it from a user-controlled name.

A ready preview resource exposes bounded `domains` summaries. Every summary uses
`target_kind: "preview_lease"` and the owning `preview_id`, and contains only DNS,
certificate, generation, ETag, and optional safe DNS instructions. Domain summaries
never contain tunnel or route IDs, credentials, bearer material, or ACME challenge
secrets. Stopping or expiring a lease withdraws every alias; it never leaves an
active domain binding behind.

A tunnel is created only by a host-scoped actor. It has stable `id` and
`stable_endpoint_id`, persistent desired state, optional expiry, multiple routes and
multiple connectors. Connector loss never deletes the tunnel, route, domain binding,
DNS state, or certificate state.

The managed tunnel endpoint is `https://<canonical-lowercase-uuid>.tunnels.pprbt.dev`
under the production tunnel base (or the same UUID label under a configured
development base). The leftmost label is a server-generated opaque endpoint UUID,
not the tunnel name, display name, host name, internal tunnel ID, connector ID, or
any other user-controlled value. The endpoint UUID is immutable, persisted with the
tunnel, and replayed unchanged after retries or tunnel renames.

## Mutation and reconciliation

Every create accepts an idempotency key. Mutable durable resources have a positive
monotonic `generation` and strong `etag`; stale mutations require `If-Match` and fail
before state changes. Deletes are idempotent.

Connectors receive a complete validated `config_generation` before ordered deltas.
Missed generations require a full snapshot. Last-known-good state remains active when
new state is malformed, unauthorized, incomplete, or unavailable. Replacement becomes
ready before old work is drained.

## Preview dispatch

Every client calls `paperboat-server` only. After the server commits the preview lease
and its `preview.create` operation, it dispatches one canonical projection to the
selected online owner machine at the machine's active host-runtime route:
`POST /v1/preview-launches`. This includes a create initiated on the owner machine.
The stable host runtime, not the invoking CLI process, owns the machine carrier and
routes every preview owner session over that one authenticated carrier identity.

The JSON request has `kind: "preview_dispatch"` and the following fixed field order:
`schema`, `kind`, `preview_id`, `operation_id`, `account_id`, `actor_id`,
`owner_device_id`, `owner_session_id`, `target`, `access_mode`, `endpoint`,
`lease_deadline`, optional `user_deadline`, `lease_etag`, `state`, `allocation_state`,
`edge_state`, `origin_state`, `created_at`, `last_renewed_at`, `expected_generation`,
`idempotency_key`, `request_id`, `correlation_id`, `request_hash`. The request hash is
the lowercase SHA-256 digest of the deterministic JSON projection excluding
`request_hash`, including `lease_etag` and all trace fields. The projection contains
no URL credential, bearer token, private key, or reusable secret.

The server authenticates the request with a short-lived, single-use
`preview_launch` credential. Its claims and the request must exactly agree on account,
actor, owner machine and session, preview, operation, typed target, access mode,
endpoint, lease and user deadlines, lease ETag, lifecycle dimensions, expected
generation, request hash, idempotency key, request ID, and correlation ID. A mismatch,
replay, expired lease, stale generation, or inactive route is rejected without
starting a second carrier.

The only safe dispatch response is `{schema, kind, preview_id, operation_id, state,
generation}`, where `state` is `accepted`, `ready`, or `failed`. `accepted` is only a
transport acknowledgement; it never completes the create operation. The owner machine
must observe real edge and origin readiness through the device-auth-only
`POST /v1/previews/{id}/readiness` endpoint, using the server operation ID as both the
machine proof operation and `Idempotency-Key`, and the exact strong lease ETag in
`If-Match`. Only that compare-and-swap observation can complete the create operation.
An exact readiness replay returns the same ready projection and ETag. A timeout or
other uncertain dispatch keeps the same operation and lease uncertain for retry; an
explicit rejection fails them. No dispatch outcome reports a preview ready before
readiness observation.

## Domain DNS and managed TLS

Managed certificate issuance uses delegated DNS-01. For each verified domain the
server assigns one immutable, server-owned challenge target below its configured
challenge zone. DNS instructions expose a customer record of the form
`_acme-challenge.<domain> CNAME pb-<stable-domain-token>.<paperboat-challenge-zone>`;
the customer hostname remains the ACME authorization name, while Paperboat writes
the short-lived TXT value only at the delegated target. The target is derived from
the domain, account, tunnel, and server-issued challenge reference and cannot be
changed by a client or provider request. A domain is not TLS-ready until CNAME/TXT
propagation, ACME validation, and every bound edge certificate distribution target
have completed. A CAA denial, delegation mismatch, propagation timeout, revoked
certificate, or stale edge generation is surfaced as a typed certificate/DNS
diagnostic and leaves the prior last-known-good certificate active.

A wildcard binding such as `*.user.me` uses the same contract. The customer points
the wildcard traffic record at the stable Paperboat DNS target and delegates
`_acme-challenge.user.me` to the returned challenge target. Under the default
`managed` strategy, Paperboat owns wildcard issuance, renewal, distribution,
replacement, and revocation. No certificate or private-key upload is part of the
API. `on_demand_leaf` remains an explicit alternative that issues exact one-label
certificates under the verified wildcard; it is not required for managed wildcard
TLS.

Certificate private keys and provider credentials are write-only references. They
never appear in resource views, DNS instructions, operations, audit events, logs,
distribution envelopes after acknowledgement, or edge disk storage. Renewal and
replacement stage a new certificate on every captured edge target, wait for exact
ready acknowledgements, activate the new generation atomically, and only then
retire the old generation. Revocation is a distinct terminal state and is retried
against the durable target set after restart.

The server's `POST /v1/previews` response includes the durable create operation ID in
the safe `X-Paperboat-Operation-ID` header on both the 202 operation response and an
exact 200 replay. The CLI observes that operation while the stable host runtime resumes
carrier work; the operation ID is not copied into the public preview resource.

## Preview carrier attachment

`preview_carrier_attachment` is the secret-free, generation-fenced link between one
preview create operation, one owner session, one stable host carrier identity, one
ephemeral route, and one edge node. It is never a bearer credential and never contains
a token, private key, password, authorization header, or reusable secret.

The server owns attachment allocation and all terminal generations. The owner host
requests or renews an attachment using renewable machine identity and proof, the exact
lease ETag in `If-Match`, and the create operation ID as its idempotency and proof
operation. The binding fixes account, preview, operation, owner device and owner
session, host, lease generation, tunnel, connector, carrier session and process/config
generations, route and edge node. `host_id` must equal `owner_device_id`; tunnel and
connector IDs must differ. `edge_process_epoch` fences an old process that briefly
overlaps a replacement using the same stable edge node ID. Endpoint addresses are
transport metadata only. The two
carrier endpoints are `tls://` for authenticated TCP multiplexing and `quic://` for
authenticated QUIC; they are not mislabeled as HTTP or WebSocket endpoints.

Each edge process mints one in-memory TLS server leaf and key for both carrier
transports. Authenticated node registration binds its bounded public certificate chain
and `carrier_server_spki_sha256` to the exact edge node and process epoch. Attachments
project these as `edge_carrier_server_certificate_chain_pem` and
`edge_carrier_server_spki_sha256`. The host trusts only that admission-scoped chain,
verifies the carrier endpoint hostname and certificate validity, and then checks the
SPKI pin. Replacement processes use a new key and pin; system roots, static deployment
keys, `InsecureSkipVerify`, and private-key projection are forbidden.

The edge pulls a complete node-scoped snapshot from
`POST /v1/edge/previews/carrier-admissions`. A valid response has `schema`,
`kind: "preview_carrier_attachment"`, `complete: true`, non-null `admissions` and
`detachments` arrays, and at most 4,096 items in each array. An incomplete, malformed,
over-limit, or unavailable snapshot leaves the previous last-known-good set active.
Absence from a successful complete snapshot removes local ingress but does not invent a
server terminal generation.

The edge ACKs admission only after installing the exact binding and route generation.
It reports `edge_ready` separately. The host reports origin readiness separately after
a real probe. Only the server may project the attachment and preview ready after both
observations match the current generations. Local expiry, carrier loss, and shutdown
are informational observations. Only an exact server-issued detachment command may be
ACKed as terminal, and stale carrier sessions or process generations cannot remove a
replacement.

All previews for one machine installation and selected edge share one stable carrier
identity while retaining distinct route IDs and owner-session IDs. Independent CLI
processes never open competing machine carriers. The host runtime owns that carrier and
uses a bounded local owner-session lease to stop only the preview whose invoking CLI
exits, disconnects, or misses its heartbeat. Dashboard-dispatched previews use the same
host-runtime dispatcher and do not depend on a browser connection remaining open.

An admitted preview may also carry at most 64 requested custom-domain aliases. Each
alias is a metadata-only record containing `domain_id`, `hostname`, `match_type`, and
the `preview_generation`, `domain_generation`, and `certificate_generation` fences. The
edge rejects duplicate domain IDs or hostnames, stale preview generations, zero or
missing domain/certificate generations, and recursive wildcards. An alias is installable
only when all three generations match the current server projection; it never replaces
the random managed endpoint. Alias withdrawal on stop, expiry, revocation, or a complete
server snapshot omission removes ingress without inventing a terminal server state.

Credential material is write-only. Read models contain only `credential_reference`,
rotation generation and safe metadata. Reusable secrets, bearer tokens, private keys,
authorization headers and payload content are forbidden.

## Private access authorization

Private preview and tunnel routes use one local-runtime and edge authorization boundary:

```text
Browser -> narrow PAC/system proxy -> stable hostd -> authenticated route-bound carrier -> edge -> target carrier
```

The PAC or operating-system rule sends only Paperboat private hostnames to a
literal-loopback hostd proxy. Hostd checks its current renewable machine session for
every CONNECT/request and opens a fresh route-bound access stream. The browser sends no
Paperboat credential and has no Paperboat login, access cookie, callback, redirect,
extension, copied token, or JavaScript localhost check. Direct public-edge traffic never
becomes authorized private traffic.

The server-issued current-accessor snapshot is complete, machine-scoped, and bounded to
4,096 admissions. Each durable-tunnel admission carries validated `tunnel_name` and
`route_name` selector metadata. Stable hostd resolves `pb access tunnel
<tunnel-or-route>` against exact IDs or these exact case-sensitive names only within
that snapshot. It does not enumerate global or cross-account resources. Zero matches
return non-enumerating forbidden access. Multiple matches, including a name colliding
with another route ID, return unavailable without opening a listener or carrier.
Preview admissions never carry durable tunnel or route names.

Hostd verifies its renewable machine session and `POST`s a route-only grant request to
`/v1/edge/private-access/grants` with the machine credential and proof before opening
the access carrier. The carrier then carries only the short-lived signed `grant` and
the server-normalized signed `request` returned by that call. After receiving the
carrier, the edge sends that normalized `request` to
`/v1/edge/private-access/authorize` with its own authenticated edge control
channel and the grant in a write-only header. Browser request headers are never an
identity source. The request body never accepts an account, device, or client
session as authority. The server derives those values from the verified machine
proof and returns them only as safe binding metadata in the grant response.

The grant response is `{schema, kind, grant, expires_at, request_id, correlation_id,
request}`. `grant` is write-only, short-lived, audience-bound, and must not be logged,
cached, persisted, or returned by an edge decision. The normalized `request` is the
exact input for the second call and includes the verified account, accessor device and
access session, route, carrier session, connector (for durable tunnels), process,
config, and route generations. A caller must not substitute the preview owner device
or owner session for the accessing device/session.

The authorize request is a full normalized request. The edge supplies the grant in a
write-only header and the current authenticated edge node and process epoch in the
control headers. The server re-resolves the resource on every call and requires exact
account, resource, route, audience, protocol, accessor identity, carrier session,
connector, route generation, process generation, config generation, and edge
node/process binding. The three audiences are deliberately non-interchangeable:
`paperboat-preview-http`, `paperboat-tunnel-http`, and `paperboat-tunnel-tcp`.

For HTTPS CONNECT, the edge carries the allowed route and generation tuple on the
specific internal connection into its TLS terminator. After TLS termination, the
host/path match must equal that connection binding before forwarding. A shared
listener secret is not sufficient, and a grant for one route never authorizes a
sibling path route or a different hostname on the same connection.

An allowed decision contains only the safe binding and a short expiry. A denial has a
stable typed `reason` and never contains resource, route, connector, session, or
generation identifiers, so missing, cross-account, signed-out, revoked, expired, and
stale resources are non-enumerating. The edge may cache decision metadata only until
`expires_at`; it must close an active stream at that deadline and reauthorize before
reuse. Revocation, replacement, route changes, malformed or oversized responses, and
redirects fail closed. Idempotency keys are bound to the complete request fingerprint;
reusing one key with a different fingerprint is a typed conflict and never overwrites
the earlier result.

Private authorization is a policy check, not a transport credential. The edge removes
all proof and grant headers before forwarding HTTP, and raw TCP carries only the
authorized opaque carrier stream. No fixture or safe audit record contains bearer,
proof, private-key, cookie, authorization-header, origin-body, or reusable-secret
bytes.

The local proxy returns `401 Unauthorized` when the machine session is missing, logged
out, expired, or revoked; `403 Forbidden` when an authenticated device is not allowed
to use the route; and `503 Service Unavailable` when hostd, the carrier, or control-plane
verification is temporarily unavailable. Cross-account responses remain
non-enumerating. Private TCP uses the same authorization boundary through a bounded
literal-loopback listener created by `pb access`.

Connector enrollment proof transcripts bind the SHA-256 digest of the one-time
enrollment token, never the token bytes. Ed25519 credential verifier material is
public-only and uses the RFC 7638 JWK thumbprint as the unprefixed thumbprint;
connector wire key IDs use the `ed25519:` prefix.

## Routing

Hostname normalization uses ASCII IDNA, lowercase and no terminal dot. Host precedence
is exact, then the longest one-label wildcard suffix, then the most specific path, then
explicit priority, then a configured catch-all.

`*.example.com` matches `app.example.com` and does not match `a.b.example.com` or the
apex. A route preserves the public Host by default. Origin Host and TLS SNI are separate
explicit controls.

HTTPS origins verify the server certificate and hostname against the system trust store by
default. `custom_ca` requires an opaque Paperboat credential reference, and optional mTLS
uses a separate opaque client-credential reference. These fields never contain PEM, private
keys, bearer tokens, or raw filesystem paths. Explicit SNI controls certificate verification;
`preserve_host` and `host_override` independently control the HTTP Host header. Cleartext
HTTP/2 uses the explicit `h2c` scheme and is never silently downgraded to HTTP/1.1.

`insecure_development` is an explicit development-only exception. The server rejects it
unless development policy permits it, records an audit event without credential references
or resolved bytes, and surfaces a warning. Production policy never enables this mode.
Origin probes and live requests use the same TLS policy. A generation replacement creates
fresh transports, drains the old generation, and cannot reuse stale CA, SNI, or mTLS state.

## Typed health

Health has these dimensions:

`service`, `edge`, `config`, `route`, `origin`, `dns`, `certificate`, `access`, `update`.

Each dimension uses `unknown`, `ready`, `degraded`, `down`, or `not_applicable` and
includes a stable code, summary, start time, retry state, optional next retry, safe
repair action and correlation ID. Overall health is a deterministic projection of the
most actionable problem.

## Errors and events

Errors include stable `code`, component, safe message, outcome certainty, retryability,
optional retry time, repair action, request ID and correlation ID. Callers never branch
on message text.

Lifecycle events include a resumable opaque `cursor`, stable event type, resource kind
and ID, occurrence time, actor, correlation ID and safe metadata. Events never contain
credentials, headers, request bodies or response bodies.

## Compatibility ownership

The public family is `paperboat.preview-tunnel` version `1.0.0`:

- `paperboat-server` owns desired state, authorization, generations, operations, audit,
  DNS and certificate coordination.
- `paperboat` owns foreground preview leases, host service, local persistence,
  connectors, origins and updates.
- `paperboat-tunnel` owns ingress, TLS termination, route and connector selection,
  forwarding, draining and edge health.
- `paperboat-web` consumes safe server read models and never connector credentials,
  private keys or edge-private configuration.

There is no compatibility implementation for the superseded unreleased preview/serve
model and no v2 surface.
