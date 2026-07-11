# Paperboat CLI End-to-End Integration Plan

Status: planning complete; integration implementation in progress from existing foundations.

This document is the canonical implementation and tracking plan for authenticating
`paperboat-cli` through the Paperboat dashboard, starting and connecting to a project's
Fly.io machine, attaching to the VM-local papercode (T3 Code) terminal over agentunnel,
and translating local image pastes into VM-local image paths.

Phases below order implementation, review, and verification. They are not reduced product
versions. The integration is releasable only after every phase is complete with production
evidence. Test doubles may be used in automated tests, but no stub, dummy credential,
offline shell fallback, or placeholder provider is allowed in a production path.

## Sources Reviewed

- Workspace `AGENTS.md` and `USERSTORY.md`
- `paperboat-cli/AGENTS.md`, current CLI implementation, and `PROGRESS.md`
- `paperboat-server/AGENTS.md`, `docs/PLAN.md`, access contracts, and VM runtime
- `paperboat-dashboard/AGENTS.md` and current WorkOS/BFF implementation
- `agentunnel/AGENTS.md`, API/runtime docs, and cloud-agent plan
- `papercode/AGENTS.md`, remote architecture, connection runtime, environment auth,
  terminal RPC, and server HTTP contracts

## Progress Tracking

Update this table after every implementation pass. A phase is `Complete` only when its
checklist, acceptance criteria, tests, documentation, and evidence are complete.

| Phase | Area | Status | Owner | Evidence |
| --- | --- | --- | --- | --- |
| 0 | Product decisions and cross-repo contract freeze | Implemented | Codex | Workspace user story plus server CLI auth/OpenAPI, dashboard approval, agentunnel data-plane, papercode schema/fixture, and CLI contracts are aligned; immutable commit links remain release evidence. |
| 1 | Paperboat device authorization and CLI sessions | Implemented | Codex | `paperboat-server` has durable grants/client sessions, hashed access and rotating refresh tokens, cookie-or-scoped-bearer middleware, device/refresh/revoke/client APIs, shared rate limits, redacted request logging, and automated state/replay/race tests. Linked papercode terminal/file credentials are invalidated through the implemented Phase 4 signed revocation path. Postgres execution evidence remains before `Complete`. |
| 2 | Dashboard device approval experience | Implemented | Codex | Dashboard implements the external `/cli/authorize` flow, validated login return, explicit approve/deny states, and authorized-device revocation; unit tests, lint, typecheck, and production build pass. |
| 3 | Shared client identity and secure credential storage | Implemented | Codex | CLI has issuer-namespaced versioned profiles, aligned OS keyring storage, recoverable locked refresh rotation, durable retryable revocation, bearer auth, and device login/status/logout/switch. Papercode desktop schema-validates shared profiles and authenticates their access credentials against each issuer entirely in its main process. Cross-platform manual evidence and login UX goldens remain before `Complete`. |
| 4 | Papercode control-plane credential minting | Implemented | Codex | Minting/exchange, protected stable VM identity provisioning, signed client/user/project/enforcement revocation with durable retry, and signing-key overlap/rollback behavior are implemented and covered by automated tests. Real-infrastructure evidence is intentionally deferred to Phase 11. |
| 5 | Agentunnel HTTP/WebSocket data path and revocation | In progress | TBD | Agentunnel forwards HTTP/WebSocket and server provisions access resources; real hosted route, per-session revocation, and end-to-end evidence remain. |
| 6 | Fly project VM runtime and readiness | In progress | TBD | Project image, papercode/agentunnel startup, Fly orchestration, and readiness foundations exist; production auth provisioning and real Fly evidence remain. |
| 7 | Papercode staged-image upload contract | In progress | TBD | Schema-owned path/response/errors and `file:stage` are frozen; the existing base64 terminal-upload route remains transitional and must be replaced. |
| 8 | CLI production connection and terminal behavior | In progress | TBD | API resolver, readiness polling, papercode WebSocket terminal RPC, raw terminal handling, resize, and exit propagation exist; auth and real-server compatibility remain. |
| 9 | CLI image-paste bridge completion | In progress | TBD | Bracketed-paste parsing, fail-open rewriting, and uploader tests exist; the real staged-image transport, bounded async ordering, and cross-platform evidence remain. |
| 10 | Security, observability, operations, and distribution | Not started | TBD | None |
| 11 | Full real-infrastructure release validation | Not started | TBD | None |

Status values:

- `Not started`: no implementation work has landed.
- `In progress`: production implementation is underway.
- `Blocked`: an explicit decision, credential, or external dependency prevents progress.
- `Implemented`: code and automated tests exist, but release evidence is incomplete.
- `Complete`: all acceptance criteria and evidence are complete.

## Decisions Made By This Plan

These decisions close the CLI-related open questions in `USERSTORY.md`. Phase 0 must copy
the approved wording into the source-of-truth and contract documents before code changes.

### Authentication UX: OAuth Device Authorization

Use an OAuth 2.0 Device Authorization Grant-style flow, matching GitHub CLI:

1. `pb auth login` requests a short-lived device authorization from `paperboat-server`.
2. The CLI prints a short user code and dashboard verification URL, attempts to open the
   complete URL in the default browser, and always leaves copyable instructions for
   headless systems.
3. The dashboard uses the existing WorkOS browser session. After login, it shows the CLI
   name, operating system, requested scopes, code, and expiry, then requires explicit
   approval or denial.
4. Browser approval moves the grant to `approved` without issuing credentials. The CLI
   polls at the server-provided interval; exactly one successful poll consumes the approved
   grant while returning a short-lived access token and rotating refresh token. Denial,
   expiry, cancellation, and slow-down responses remain distinct outcomes.

This is preferred over a loopback callback because it works unchanged in local terminals,
remote shells, containers, and headless machines. `verification_uri_complete` removes the
need to type the code in the common case; the short code remains the safe fallback.

### Identity Ownership

WorkOS plus `paperboat-server` is the only Paperboat identity authority. The existing CLI
assumption that a papercode JSON token can be sent as a `paperboat_session` cookie is
removed.

The CLI and papercode are separate public clients of the same Paperboat account. Each
device installation receives its own revocable client session. On a desktop where both are
installed, they may use the same documented Paperboat credential-store profile, but neither
client parses the other's private application state. Browser cookies are never copied into
CLI configuration.

### Data And Control Paths

```text
Authentication and authorization (control path)

pb -> paperboat-server -> dashboard/WorkOS approval
pb -> paperboat-server -> project ownership, entitlement, credit, Fly readiness
paperboat-server -> papercode mint endpoint through agentunnel

Terminal and upload traffic (data path)

pb -> agentunnel HTTPS/WSS route -> VM-local papercode server
                                      |- terminal RPC -> VM PTY
                                      `- staged-image HTTP API -> VM filesystem
```

`paperboat-server` never proxies terminal bytes, WebSocket frames, or image bodies. SSH is
operator/debug access only and is not the production `pb` transport.

### Environment Authorization

Use papercode's existing Paperboat control-plane mint flow:

- The VM is provisioned with Paperboat's JWKS URL, issuer/audience configuration, stable
  environment ID, and linked Paperboat owner ID.
- For an authorized connect, `paperboat-server` signs one one-time `environment:connect`
  proof per downstream papercode session, each bound to exactly one environment, user,
  Paperboat client session, nonce/JTI, and expiry.
- The proof is posted to papercode's `POST /api/paperboat/mint-credential` through the
  project's agentunnel route.
- One bootstrap credential is exchanged at `/oauth/token` for a terminal-only
  bearer `terminal:operate` access session, from which a single-use WebSocket ticket is
  requested. The terminal bearer is retained by `paperboat-server` and never returned.
- A separate proof/bootstrap exchange creates a file-only `file:stage` bearer session.
  That short-lived bearer is returned as upload auth. Both downstream session ids are
  recorded against the Paperboat client session.

The proof is an Ed25519 compact JWS with `alg=EdDSA`,
`typ=t3-cloud-mint+jwt`, and a required JWKS `kid`. It binds `iss`,
`aud=t3-env:<environmentId>`, Paperboat owner `sub`, `jti`, `iat`, `exp`, environment id,
Paperboat client-session id, nonce, and exactly `scope=["environment:connect"]`. The
Paperboat profile omits `clientProofKeyThumbprint` and `cnf`; neither the CLI nor
`paperboat-server` owns or registers a downstream proof key. `paperboat-server` exchanges
each bootstrap credential without a DPoP header so papercode intentionally issues the
scoped bearer sessions described above. Maximum lifetime is 300 seconds and accepted clock skew is
60 seconds. JTI and nonce are atomically single-use through expiry plus skew. Unknown keys
trigger one JWKS refresh and otherwise fail closed; rotation overlap lasts only while the
old key remains published.

The normalized Paperboat issuer publishes public Ed25519 keys at
`GET /.well-known/jwks.json` using `kty=OKP`, `crv=Ed25519`, `alg=EdDSA`, `use=sig`, `kid`,
and `x`. Cache and rotation-overlap durations are dynamic configuration.

No agentunnel API key, machine token, Fly credential, mint signing key, SSH key, or reusable
bootstrap credential is returned to the CLI.

### Image Upload

Add an authenticated papercode endpoint that stages one image into the VM workspace and
returns its absolute VM path. Use streaming multipart upload rather than base64 JSON to
avoid unnecessary memory and bandwidth expansion. Authorization uses `file:stage`; terminal
permission alone does not imply arbitrary file upload.

Files are written atomically below a server-controlled workspace directory, never to a
client-selected destination. Limits, allowed MIME types, retention, and directory name are
runtime configuration supplied in the connect descriptor.

## Cross-Repo Ownership

| Repository | Owns | Must not own |
| --- | --- | --- |
| `paperboat-cli` | Device-login UX, secure local credentials, project selection, descriptor refresh, terminal wrapper, paste detection/upload/rewrite | WorkOS sessions, entitlement decisions, Fly lifecycle truth, tunnel provisioning, VM auth minting |
| `paperboat-server` | Device grants, CLI sessions, WorkOS identity mapping, entitlement and ownership checks, Fly resume/readiness, agentunnel provisioning, papercode proof signing/exchange, descriptor issuance, audit | Live terminal/upload data proxying, PTY behavior |
| `paperboat-dashboard` | WorkOS login continuation, device-code approval/denial UI, authorized-client management | Token minting, token storage in browser JavaScript, project authorization rules |
| `agentunnel` | Authenticated machine-to-relay route, HTTPS/WSS forwarding, route lifecycle/status, resource revocation | Paperboat user identity, billing, papercode RPC authorization |
| `papercode` | Environment auth verification, scoped sessions, WebSocket tickets, terminal RPC/PTys, staged-image storage, environment-session revocation | Paperboat account login, Fly lifecycle, agentunnel provisioning |

## Frozen Contract Targets

Phase 0 may refine field names, but implementation must freeze one machine-readable version
across all consumers before work proceeds past that phase.

### Device Authorization

`POST /api/auth/device/authorize` is unauthenticated and rate-limited.

Request:

```json
{
  "client_id": "paperboat-cli",
  "client_label": "Pujan's MacBook Pro",
  "device_type": "desktop",
  "os": "darwin",
  "scopes": ["account:read", "clients:revoke", "projects:read", "projects:connect", "session:refresh"]
}
```

Response uses the Paperboat `{ "data": ... }` envelope:

```json
{
  "data": {
    "device_code": "secret-high-entropy-value",
    "user_code": "ABCD-EFGH",
    "verification_uri": "https://dashboard.example.com/cli/authorize",
    "verification_uri_complete": "https://dashboard.example.com/cli/authorize?code=ABCD-EFGH",
    "expires_in": 600,
    "interval": 5
  }
}
```

`POST /api/auth/device/token` accepts exactly `client_id` and `device_code`. It returns one
of `authorization_pending`, `slow_down`, `access_denied`, `expired_token`, `invalid_grant`,
or a token set. Errors use the standard Paperboat error envelope. `slow_down` returns the
next interval in `error.details`; general limiting is HTTP `429 rate_limited` with
`Retry-After`.

The CLI requests exactly those five scopes; ordering is insignificant, while missing,
duplicate, additional, and unknown scopes return `invalid_scope`. Unknown clients return
`invalid_client`; other malformed requests return `validation_failed`.

```json
{
  "data": {
    "access_token": "opaque-access-token",
    "refresh_token": "opaque-rotating-refresh-token",
    "token_type": "Bearer",
    "expires_in": 900,
    "scope": "account:read clients:revoke projects:read projects:connect session:refresh",
    "client_session_id": "cls_..."
  }
}
```

Dashboard approval and denial use cookie session plus CSRF:

- `GET /api/auth/device/requests/{user_code}`
- `POST /api/auth/device/requests/{user_code}/approve`
- `POST /api/auth/device/requests/{user_code}/deny`

Refresh sends the current refresh token only as a bearer credential, rotates it on every
success, serializes concurrent family refresh, and revokes the device-session family on
detected reuse. Revoke accepts the current access or refresh bearer and is idempotent:

- `POST /api/auth/token/refresh`
- `POST /api/auth/token/revoke`
- `GET /api/auth/clients`
- `DELETE /api/auth/clients/{client_session_id}`

Authorized-client listing accepts `limit`, `offset`, and optional `state=active|revoked`.
Its `data` is `{items, pagination}`. Items contain client/session identity, label, device/OS,
normalized scopes, state, creation/approval/last-use/revocation timestamps, revocation
reason, and whether the item is the calling session. Pagination contains `limit`, `offset`,
`total`, and nullable `next_offset`; the exact fields are schema-owned by
`paperboat-server/docs/openapi.json`.

For bearer callers, listing requires `account:read` and deleting another authorized client
requires `clients:revoke`. Dashboard cookie callers retain cookie authentication plus CSRF
for deletion. Self-family logout through `POST /api/auth/token/revoke` does not require the
client-management mutation scope.

Device codes, user codes, access tokens, and refresh tokens are stored only as hashes.
User-code lookup uses a separate keyed hash so the short code is not recoverable from the
database. Approval transactionally changes `pending` to `approved`; the single successful
token poll changes `approved` to `consumed` while issuing credentials.

Device grant lifetime, access-token lifetime, polling interval, and rate thresholds are
dynamic server configuration; responses are authoritative. Initial production defaults are
600 seconds, 900 seconds, and 5 seconds. Device codes have at least 256 bits of entropy.
Rate limits apply independently by network, grant, and account. The exact contract and
credential-profile rules live in `paperboat-server/docs/contracts/cli-authorization.md`.

### CLI Connect Descriptor

`POST /api/projects/{project_id}/cli-connect` requires a Paperboat bearer token with
`projects:connect`. It remains responsible for ownership, entitlement, credit, project
state, Fly start/resume, agentunnel reconciliation, and papercode credential minting.

Ready Paperboat response `data` payload:

```json
{
  "project_id": "prj_...",
  "project_state": "running",
  "connectable": true,
  "status": "ready",
  "reason": "ready",
  "retry_after_seconds": 0,
  "expires_at": "2026-07-10T12:00:00Z",
  "environment": {
    "environment_id": "env_...",
    "display_name": "Project name",
    "project_root": "/workspace/project"
  },
  "terminal": {
    "kind": "papercode_websocket",
    "websocket_base_url": "wss://route.example.com",
    "auth": {
      "method": "websocket_ticket",
      "ticket": "single-use-ticket",
      "expires_at": "2026-07-10T12:00:00Z",
      "scopes": ["terminal:operate"]
    },
    "thread_id": "paperboat-cli",
    "terminal_id": "term_...",
    "cwd": "/workspace/project"
  },
  "upload": {
    "kind": "papercode_staged_image",
    "http_base_url": "https://route.example.com",
    "path": "/api/files/staged-images",
    "auth": {
      "method": "bearer",
      "token": "short-lived-environment-token",
      "expires_at": "2026-07-10T12:00:00Z",
      "scopes": ["file:stage"]
    },
    "max_bytes": 10485760,
    "allowed_mime_types": ["image/png", "image/jpeg", "image/webp"],
    "retention_seconds": 604800
  }
}
```

Not-ready responses use HTTP `202`, `connectable: false`, a stable status/reason, and a
server-provided retry interval. `GET /api/projects/{project_id}/connection-status` reports
readiness but does not return stale credentials. Once ready, the CLI calls `cli-connect`
again to mint fresh, single-use auth material.

Frozen readiness pairs are `machine_starting` with `machine_start_queued` or
`machine_not_running`, `tunnel_connecting` with `tunnel_offline`, and
`papercode_starting` with `papercode_unhealthy`. Pending pairs require
`connectable: false` and a positive retry interval. The only ready shape is
`connectable: true`, `status: ready`, `reason: ready`, and `retry_after_seconds: 0`.

The existing browser-cookie-plus-CSRF behavior in `paperboat-cli/internal/api` must be
replaced with bearer access tokens. A CLI must never synthesize dashboard cookies.

### Papercode Staged Image

`POST /api/files/staged-images` accepts one multipart file part named `image` plus an
optional text part named `display_filename`. The server derives the extension from
validated content, not the name.

Success response:

```json
{
  "path": "/workspace/project/.paperboat/uploads/2026/07/img_...png",
  "mime_type": "image/png",
  "size_bytes": 123456,
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "expires_at": "2026-07-17T12:00:00Z"
}
```

Required errors include `unauthenticated`, `insufficient_scope`, `payload_too_large`,
`unsupported_media_type`, `invalid_image`, `workspace_unavailable`, and
`storage_unavailable`. The endpoint must stream with a hard byte limit, validate magic
bytes and decoding, reject SVG and polyglot content, use atomic no-follow creation, and
never accept a destination path from the client.

### Terminal RPC

The CLI consumes papercode's schema-owned RPC contract through the versioned
`packages/contracts/fixtures/paperboat-cli-terminal-v1.json` protocol fixture. The Go repo
vendors that exact fixture, pins `paperboat-terminal-rpc/v1`, and tests its wire constants
against it. The CLI sends an Effect RPC `Ack` with the matching string `requestId` after
processing every streamed `Chunk`; without that acknowledgement papercode applies
backpressure and does not send the next chunk. Fixture refresh and real-server compatibility
tests are required in the same cross-repo change whenever the terminal schema changes.

Required terminal operations are attach with `restartIfNotRunning`, write, resize, output
subscription, exit, and close. Exact tags, payload fields, framing, errors, and protocol version must be tested
against the real papercode server in CI.

## Phase 0: Product Decisions And Contract Freeze

Repositories: all five integration repos plus workspace docs.

- [x] Update `USERSTORY.md`: device authorization, client-specific sessions, exact
      pre-connect role, papercode mint flow, and agentunnel HTTP/WSS data path.
- [x] Update `paperboat-cli/AGENTS.md`: replace read-only papercode credential reuse with
      the approved shared Paperboat credential-store/session model.
- [x] Reconcile `paperboat-server/docs/contracts/access-handoff.md`, OpenAPI, and this plan.
- [x] Freeze device-auth endpoint fields, scopes, polling errors, expiry, rate limits,
      refresh rotation, logout, and revocation semantics.
- [x] Freeze papercode mint proof claims, signing algorithm, JWKS/key rotation, audience,
      nonce/replay storage, and clock-skew bounds.
- [x] Freeze the staged-image endpoint and add `file:stage` to papercode auth schemas.
- [x] Freeze terminal RPC compatibility/export mechanism.
- [x] Define environment identity as stable per project, surviving machine replacement.
- [x] Remove or contractually define unsupported CLI flags. In particular, `--size` must
      not imply a per-session Fly resize contrary to the user story's restart-apply rule.
      `--agent` is also removed because no agent-launch RPC contract exists.
- [x] Record the owning contract links in every affected repo's contract/progress document.

Acceptance criteria:

- No open field-name, scope, issuer, expiry, ownership, or revocation question remains for
  implementation phases.
- The workspace user story and all repo-local contracts describe the same flow.

Evidence:

- Workspace: `USERSTORY.md`.
- CLI: `AGENTS.md`, `PROGRESS.md`, and the vendored terminal fixture compatibility test.
- Server: `docs/contracts/cli-authorization.md`, `access-handoff.md`, and
  `docs/openapi.json`.
- Dashboard: `docs/cli-device-authorization.md`.
- Papercode: `docs/cloud/environment-auth.md`, schema-owned Paperboat/staged-image
  contracts, and the terminal fixture.
- Agentunnel: `docs/paperboat-integration.md`.
- Immutable approved commit links remain required before changing Phase 0 to `Complete`.

## Phase 1: Paperboat Device Authorization And CLI Sessions

Repository: `paperboat-server`.

- [x] Add durable device grants, client sessions, access-token hashes, rotating refresh
      token families, approval metadata, expiry, revocation, and audit migrations.
- [x] Implement device authorization, polling, refresh, revoke, and client-list APIs.
- [x] Authenticate non-browser APIs with scoped bearer tokens while preserving dashboard
      cookie sessions and CSRF for browser mutations.
- [x] Enforce exact client and scope allowlists from dynamic server configuration.
- [x] Generate human-readable codes without ambiguous characters; compare in constant time.
- [x] Enforce polling interval and `slow_down`; rate-limit by network, device grant, and
      account without making NAT-shared users unusable.
- [x] Make approval, poll consumption, denial, and expiry transitions race-safe across
      server replicas.
- [x] Rotate refresh tokens on every use; revoke the family on replay.
- [x] Add explicit client-session revocation hooks for CLI family logout, account
      suspension, and administrator action. Dashboard logout remains scoped to its browser
      session and does not revoke independent CLI installations.
- [x] Propagate those hooks to actual papercode terminal and file sessions through the
      Phase 4 signed revocation endpoint, with durable exact-session retry after downstream
      delivery failures.
- [x] Redact every token and code from logs, traces, errors, and audit metadata.
- [x] Publish OpenAPI and API documentation.

Acceptance criteria:

- A public CLI obtains a session only after the matching authenticated user explicitly
  approves it.
- A copied/expired/denied code, polling abuse, refresh replay, or revoked session cannot
  produce a usable access token.
- Cookie and bearer authentication cannot be confused or substituted.

Evidence:

- Migration tests, state-machine tests with a fake clock, concurrent approval/poll tests,
  refresh replay tests, rate-limit tests, and OpenAPI contract tests.

## Phase 2: Dashboard Device Approval Experience

Repository: `paperboat-dashboard`.

- [x] Add `/cli/authorize` outside the paid dashboard shell so an unauthenticated visitor
      can sign in through WorkOS and return to the exact pending request.
- [x] Preserve only the user code through login; never put device/access/refresh secrets in
      a URL, browser storage, analytics, or client logs.
- [x] Show recognizable client label, OS/device type, requested permissions, issue time,
      expiry, and the user code before approval.
- [x] Require an explicit Approve or Deny command; protect both with CSRF.
- [x] Handle invalid, expired, already-used, denied, wrong-account, and server-failure states.
- [x] Add an authorized-clients settings view with last-used time and per-device revoke.
- [x] Follow `DESIGN.md` and the dashboard reference codebases in the implementation.
- [x] Avoid gating identity authorization on payment; entitlement remains enforced when the
      CLI lists or connects to projects.

Acceptance criteria:

- The browser returns to the approval screen after WorkOS login and clearly confirms the
  approved device without exposing credentials.
- Revoking a client makes its next API call or refresh fail predictably.

Evidence:

- Unit tests, lint, typecheck, production build, and reviewed route/component implementation.

## Phase 3: Shared Client Identity And Secure Credential Storage

Repositories: `paperboat-cli` and `papercode`.

- [x] Define a versioned Paperboat client profile containing server identity, account
      metadata, client-session ID, token expiry, and a reference to secure secrets.
- [x] Store access and refresh secrets in macOS Keychain, Windows Credential Manager, and
      Linux Secret Service. A file fallback is disabled by default and, if explicitly
      enabled for a headless environment, requires `0600` permissions and a visible warning.
- [x] Use an inter-process refresh lock plus atomic metadata updates so CLI and desktop
      papercode cannot corrupt a shared profile.
      The cross-platform lock is the documented atomic `.lock.d/owner.json` lease; a
      versioned `credentials-location.json` pointer shares configured `auth.profile_dir`
      overrides with desktop papercode.
- [x] Namescope credentials by normalized Paperboat server/issuer so staging and production
      accounts cannot collide.
- [x] Add `pb auth login`, `pb auth status`, `pb auth logout`, and account switching.
- [x] Make browser opening best-effort and platform-native; always print the URL and code.
- [x] Handle Ctrl-C by cancelling the local poll without approving or leaking the grant.
- [x] Teach papercode desktop to consume the same documented profile when appropriate;
      mobile and web keep device-local sessions through the same Paperboat identity APIs.
- [x] Provide explicit migration from any shipped papercode JSON-token assumption; never
      silently reinterpret an old token as a Paperboat session.

Acceptance criteria:

- Login works from GUI desktops and headless shells.
- Secrets never appear in `pb config show`, process arguments, shell history, crash reports,
  or ordinary files under default configuration.
- Logout removes local credentials and revokes the server session even if one side fails;
  retry is idempotent.

Evidence:

- OS-specific secure-store tests, refresh concurrency tests, login UX golden tests, and
  manual evidence on macOS, Windows, and Linux.

## Phase 4: Papercode Control-Plane Credential Minting

Repositories: `papercode` and `paperboat-server`.

- [x] Finalize papercode's dedicated `/api/paperboat/mint-credential` profile without
      changing the existing relay `/api/t3-connect/mint-credential` contract.
- [x] Provision a stable environment ID, linked Paperboat owner ID, issuer, audience, and
      Paperboat public mint keys into each project VM.
- [x] Implement server-side mint signing with a managed key provider and published key IDs;
      no signing key is stored in source, database plaintext, or VM images.
      The server-side provider, proof signer, JWKS endpoint, external secret-file loading,
      and rotation-overlap tests are implemented and wired into `cli-connect`.
- [x] Bind each proof to environment, user, Paperboat client session, requested scopes,
      nonce/JTI, and a very short expiry; omit downstream proof-key claims for this bearer
      profile.
- [x] Validate exact issuer/audience/scope, linked owner, key ID, time bounds, and replay at
      papercode before issuing a one-time bootstrap credential.
- [x] Have `paperboat-server` exchange each bootstrap credential without DPoP, retain the
      terminal bearer only long enough to request the WebSocket ticket, and return the
      separate file bearer only as scoped upload descriptor material.
      Both bearer sessions are bounded to the connect descriptor lifetime, and partially
      issued sessions are revoked when later issuance or persistence steps fail. Failed
      cleanup after access-session persistence errors is retained in a dedicated durable
      outbox until papercode acknowledges every issued session ID.
- [x] Persist downstream papercode session IDs against the Paperboat access session.
- [x] Add a signed control-plane revocation endpoint so logout, entitlement loss, project
      suspension/deletion, and account revocation terminate active environment sessions.
      Signed client/user/project revocation is implemented with exact proof scope, JWKS
      verification, replay guards, client-subject binding, and persisted downstream IDs.
      Client, user, project, and credit/entitlement enforcement persist local revocation
      before downstream delivery and retry each exact failed session on later worker passes;
      an unavailable environment does not block independent revocations. Project tunnel
      cleanup is attempted even when papercode is unavailable and is durably retried after
      provider failures. Revocation retries run even when Fly observation or metering fails.
- [x] Support signing-key rotation with an overlap window and tested rollback.
      JWKS publication accepts active plus overlap keys; unknown keys force one refresh,
      and rollback to the still-published prior key is covered by automated tests.

Acceptance criteria:

- A proof for another project, owner, client, scope, audience, expired time, or replayed JTI
  is rejected.
- Real-provider `cli-connect` no longer fails with `credential_issuer_unavailable` when a
  correctly provisioned project is ready.
- Revocation prevents both new WebSocket tickets and continued use of the environment token.

Evidence:

- Cross-repo contract fixtures, adversarial proof tests, key-rotation/rollback tests,
  VM auth-provisioning smoke tests, and server-side mint/exchange/revocation protocol tests.
- Real papercode mint/exchange/ticket/revoke and deployed key-rotation evidence is owned by
  Phase 11 and is not remaining Phase 4 implementation work.

## Phase 5: Agentunnel HTTP/WebSocket Data Path And Revocation

Repositories: `agentunnel` and `paperboat-server`.

- [ ] Provision one stable, idempotent agentunnel HTTP route per project to the VM-local
      papercode server; verify both HTTP and WebSocket upgrade forwarding.
- [ ] Keep the route hostname, TLS, local papercode port, readiness timeout, and retry policy
      configuration-driven.
- [ ] Ensure the route exposes no VM address or agentunnel machine credential and that all
      papercode application endpoints still enforce papercode auth.
- [ ] Start the Fly machine before readiness polling and distinguish machine starting,
      machine failed, tunnel offline, papercode unhealthy, entitlement, and credit errors.
- [ ] Reattach the machine-side agentunnel client after VM restart without changing the
      project route identity.
- [ ] Revoke/suspend agentunnel resources on project suspension/deletion and close live
      routes where supported.
- [ ] Verify proxy limits permit configured image sizes without buffering unbounded bodies.
- [ ] Emit correlation-safe route/session events without payloads or credentials.

Acceptance criteria:

- The same agentunnel route carries papercode HTTP auth calls, image uploads, and WebSocket
  terminal RPC after cold start and machine restart.
- Direct public Fly ports are unnecessary and closed.

Evidence:

- HTTP/WSS forwarding integration tests, reconnect tests, upload limit tests, and route
  revocation tests against a real agentunnel deployment.

## Phase 6: Fly Project VM Runtime And Readiness

Repository: `paperboat-server` (project VM image and orchestration).

- [ ] Build papercode and agentunnel into the production image from pinned, reproducible
      sources; remove the production-disabled papercode build option from release artifacts.
- [ ] Clone/restore the project and config before papercode reports ready.
- [ ] Start papercode headlessly, bound only to the VM loopback interface used by agentunnel.
- [ ] Inject environment auth configuration and machine credentials through Fly secrets or
      one-time secret handoff, never reusable image layers or ordinary environment output.
- [ ] Make entrypoint supervision fail-fast, signal-aware, restart-safe, and observable.
- [ ] Define readiness as workspace ready, papercode healthy/auth-configured, agentunnel
      connected, and project route serving.
- [ ] Reconcile partial boot, replacement machine, volume remount, tunnel reconnect, and
      unhealthy papercode states.
- [ ] Preserve stable environment/project identity across stop/start and machine replacement.
- [ ] Report trusted human/agent activity so server-owned idle stopping does not terminate an
      active session; stop promptly after the configured idle timeout when truly idle.

Acceptance criteria:

- A server-created project cold-starts from stopped state and becomes connectable without
  manual Fly, SSH, agentunnel, or papercode commands.
- Machine replacement retains project data and route/environment identity while rotating
  machine credentials.

Evidence:

- Image SBOM/signature, boot logs with redaction review, Fly cold-start/restart/replacement
  tests, readiness timing, and idle/credit enforcement tests.

## Phase 7: Papercode Staged-Image Upload Contract

Repository: `papercode`.

- [ ] Add `file:stage` to schema-owned auth scopes and method authorization.
- [ ] Implement streaming multipart upload with hard request and decoded-image limits.
- [ ] Detect type from bytes, decode to validate, reject unsupported/unsafe formats, and
      normalize the extension independently of the supplied filename.
- [ ] Resolve the configured project workspace server-side and create only below the
      configured staging directory using symlink-safe, atomic file operations.
- [ ] Generate unguessable filenames, set restrictive permissions, and return an absolute
      VM path plus metadata.
- [ ] Implement configurable retention and a restart-safe garbage collector that cannot
      traverse outside the staging root or delete a file still being written.
- [ ] Account for workspace/volume availability and free space; return structured failures.
- [ ] Record metadata-only audit/telemetry without image bytes, paths containing secrets, or
      bearer tokens.
- [ ] Export the endpoint and errors from `packages/contracts` and document the contract.

Acceptance criteria:

- A valid uploaded image is readable by the terminal user at the returned path.
- Oversized, forged-MIME, malformed, SVG, polyglot, symlink, traversal, interrupted, and
  out-of-space uploads fail without partial files or writes outside the staging root.

Evidence:

- Contract tests, fuzz tests, filesystem security tests, retention tests, and a real-volume
  upload/read test inside the project image.

## Phase 8: CLI Production Connection And Terminal Behavior

Repository: `paperboat-cli`.

- [ ] Remove the `server_url`-missing local-shell/stub selection from production commands;
      test doubles remain dependency-injected in tests only.
- [ ] Replace cookie/CSRF emulation with Paperboat bearer auth and automatic safe refresh.
- [ ] Resolve projects by exact ID or unambiguous name using paginated server results; add a
      project list command and clear ambiguity errors.
- [ ] Call `cli-connect`, show cold-start progress on stderr without corrupting terminal
      stdout, follow server retry hints, and mint a fresh descriptor after readiness.
- [ ] Validate descriptor kind, HTTPS/WSS schemes, issuer/host policy, scope, expiry, project,
      and environment before dialing.
- [ ] Consume the frozen papercode terminal RPC contract rather than hand-maintained guesses.
- [ ] Preserve raw mode, bracketed paste, resize, signal forwarding, remote exit code,
      half-close, and terminal restoration on every exit path.
- [ ] Refresh expired descriptors before dial and after authentication-specific disconnects;
      use bounded reconnect for transient route loss without duplicating terminal input.
- [ ] Send rate-limited CLI activity through the authenticated control path while real user
      input or agent output is active.
- [ ] Make `pb doctor` verify secure storage, Paperboat auth, entitlement, project state, Fly
      readiness, agentunnel route, papercode auth, and terminal protocol compatibility with
      actionable structured results.
- [ ] Keep all provider URLs, timeouts, accepted descriptor kinds, and limits sourced from
      signed/server-authored configuration or local profile, not source constants.

Acceptance criteria:

- `pb <project>` cold-starts the Fly VM when needed and behaves like a local interactive
  terminal through papercode/agentunnel.
- Disconnect, Ctrl-C, terminal close, server restart, token expiry, credit exhaustion, and
  project suspension restore the local terminal and return a meaningful exit status.
- No production command silently runs a local shell or accepts dummy credentials.

Evidence:

- Unit/fuzz tests, real papercode protocol CI, PTY integration tests on Unix and Windows,
  reconnect tests, and exit/signal/resize compatibility evidence.

## Phase 9: CLI Image-Paste Bridge Completion

Repository: `paperboat-cli`.

- [ ] Replace the current base64 chat-attachment-compatible uploader with the frozen
      staged-image multipart client.
- [ ] Detect only bracketed-paste payloads that unambiguously reference an allowed local
      image file; pass all other bytes through exactly.
- [ ] Support configured terminal temp-file patterns and platform paths without assuming a
      single terminal application or operating system.
- [ ] Open and validate the local file safely, enforce descriptor limits before upload, and
      prevent time-of-check/time-of-use file swaps where the platform permits.
- [ ] Upload asynchronously while remote output continues. Preserve input order by buffering
      only subsequent local input behind the affected paste with a bounded queue and visible
      backpressure.
- [ ] Rewrite only the image path within the original bracketed-paste frame; preserve framing,
      surrounding text, adjacent pastes, and split marker reads.
- [ ] On failure, emit the original paste unchanged and print one concise local diagnostic to
      stderr. Never inject error prose into the remote PTY input stream.
- [ ] Cancel uploads and release file handles on disconnect or Ctrl-C.
- [ ] Refresh/rebroker once on upload authentication expiry without uploading twice when the
      server has already accepted the body; use an idempotency/content digest contract.
- [ ] Keep image bytes and local/VM paths out of logs and telemetry.

Acceptance criteria:

- Pasting a local PNG/JPEG/WebP into Codex/Claude inside the remote TUI gives the agent a
  readable VM path with no manual upload step.
- Plain text, multiple files, unsupported images, missing files, large files, upload failure,
  rapid adjacent pastes, slow networks, and disconnects never corrupt or reorder terminal
  input.

Evidence:

- Deterministic parser tests, fuzz tests, slow/failing uploader tests, bounded-buffer tests,
  and manual paste tests from supported terminals on macOS, Windows, and Linux.

## Phase 10: Security, Observability, Operations, And Distribution

Repositories: all affected repos.

- [ ] Threat-model device phishing, code brute force, token theft/replay, malicious routes,
      compromised VMs, mint proof replay, upload traversal/polyglots, and terminal injection.
- [ ] Add structured audit events for device request/approval/denial, refresh replay,
      connect authorization, Fly resume, mint, route readiness, revocation, and upload result.
- [ ] Add metrics for device completion, login latency, cold-start stages, connect failures,
      WebSocket lifetime/reconnect, upload size/latency/failure, and revocation propagation.
- [ ] Correlate control-plane, agentunnel, and papercode events with non-secret request,
      project, environment, and access-session IDs.
- [ ] Add runbooks for WorkOS outage, signing-key rotation, agentunnel outage, Fly failure,
      papercode auth mismatch, stuck device grants, stolen device, and upload cleanup.
- [ ] Add compatibility/version negotiation so an old CLI receives an upgrade message rather
      than a malformed session when server/papercode contracts change.
- [ ] Produce signed, checksummed release artifacts and package-manager releases for supported
      operating systems and architectures; generate SBOMs and provenance.
- [ ] Remove stale README/PROGRESS claims, stub documentation, and deprecated auth formats.

Acceptance criteria:

- Operators can identify which stage failed without secrets or terminal/image content.
- Revocation reaches Paperboat, papercode, and agentunnel within the documented bound.
- Installed binaries verify provenance and fail clearly on incompatible server versions.

Evidence:

- Threat-model sign-off, redaction tests, dashboards/alerts, exercised runbooks, dependency
  scan, artifact signatures, SBOMs, and install/upgrade/uninstall tests.

## Phase 11: Full Real-Infrastructure Release Validation

Repositories: all five integration repos.

- [ ] Run the complete flow with production-shaped WorkOS, Postgres, dashboard, Polar test
      entitlement, paperboat-server, Fly.io, agentunnel, and the real project VM image.
- [ ] Authenticate a fresh CLI through the dashboard using complete URL and manually entered
      code paths; cover denial, expiry, logout, revoke, and account switch.
- [ ] Run logged-out and logged-in dashboard browser E2E for device approval and
      authorized-client revocation.
- [ ] Validate keyboard/focus behavior, reduced motion, screen-reader output, responsive
      layout, and automated accessibility checks for the dashboard authorization flows.
- [ ] Capture and review desktop/mobile screenshots of device approval and
      authorized-client revocation.
- [ ] Create a project from GitHub, allocate a real volume, cold-start its Fly machine, wait
      for readiness, and attach a terminal without manual infrastructure commands.
- [ ] Run Codex and Claude terminal sessions, resize, suspend/resume the laptop, interrupt,
      reconnect, and verify exit-code behavior.
- [ ] Paste supported local images and prove the remote agent can read each returned VM path.
- [ ] Test VM auto-stop, reconnect auto-start, machine restart/replacement, volume persistence,
      config restore, agentunnel reconnect, and papercode restart.
- [ ] Test concurrent projects, concurrent CLI/papercode clients, refresh rotation, logout,
      entitlement loss, credit exhaustion, project deletion, and downstream session revocation.
- [ ] Exercise the real papercode mint/exchange/WebSocket-ticket flow, verify
      `credential_issuer_unavailable` is absent for a correctly provisioned ready project,
      measure signed revocation propagation, and rotate then roll back deployed Ed25519 keys
      through the configured JWKS overlap window.
- [ ] Measure login, cold-start, terminal input/output, and image-upload latency against
      explicit release budgets established before this phase.
- [ ] Run load, soak, network-loss, provider-failure, and recovery tests with no leaked
      machines, routes, tokens, sessions, temp files, or stuck terminal state.
- [ ] Complete security review and release checklist; attach dated evidence links.

Acceptance criteria:

- Every primary and failure journey works end to end on real infrastructure.
- There are no production stubs, fake issuers, manual setup steps, unresolved contract TODOs,
  or deferred release blockers.
- All repo-specific verification commands pass, including Go format/vet/test and papercode
  `vp check` plus `vp run typecheck`.

Evidence:

- Dated test report with environment/config versions, redacted logs, screenshots/recording,
  latency results, failure-recovery results, artifact versions, and commit links.

## End-to-End Sequence

```text
1. pb auth login
2. CLI -> server: create device grant
3. CLI -> browser: dashboard verification_uri_complete
4. Browser -> WorkOS -> dashboard: authenticated approval
5. CLI -> server: poll, receive client access/refresh session
6. pb <project>
7. CLI -> server: list/resolve project, request cli-connect
8. Server: authorize owner + entitlement + credits; start/reconcile Fly machine
9. VM: restore workspace, start papercode and agentunnel
10. Server: wait for Fly + papercode + agentunnel readiness
11. Server -> papercode through agentunnel: signed mint proof
12. Server -> papercode: exchange bootstrap, mint WebSocket ticket
13. Server -> CLI: short-lived terminal and upload descriptor
14. CLI -> agentunnel WSS -> papercode: attach terminal RPC
15. User pastes image
16. CLI -> agentunnel HTTPS -> papercode: stage image
17. Papercode -> CLI: absolute VM path
18. CLI -> papercode terminal RPC: original bracketed paste with path rewritten
19. Papercode PTY -> agent: VM-local image path
```

## Global Release Invariants

- WorkOS/paperboat-server is the Paperboat identity authority; papercode authorizes only its
  environment-local capabilities.
- `paperboat-server` controls access but never carries live terminal or image data.
- All live CLI traffic reaches papercode through agentunnel; no raw Fly application port is
  exposed.
- Every project maps to one stable environment identity, one Fly machine, and one volume.
- Every client, environment token, WebSocket ticket, and mint proof is scoped, expiring,
  revocable, and auditable.
- Dynamic values remain configuration/catalog/descriptor data: URLs, domains, scopes,
  expiries, polling intervals, retry limits, upload policy, paths, MIME types, and retention.
- The CLI treats server and VM data as untrusted, validates descriptors, and fails closed for
  authentication/authorization while failing open only for the affected image paste.
- Non-image terminal input and output is never inspected, logged, reordered, or modified.
- Production builds contain no stubs, dummy credentials, disabled papercode runtime, or local
  shell fallback.

## Definition Of Done

This plan is complete only when every phase is `Complete`, every evidence cell links to
reviewable artifacts, the workspace user story and repo contracts match the implemented
behavior, and a newly installed `pb` can authenticate through the dashboard, start and
attach to a real stopped Fly project VM through agentunnel/papercode, paste a local image
into a remote coding-agent TUI, and cleanly revoke the entire access chain.
