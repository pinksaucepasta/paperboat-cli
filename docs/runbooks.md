# Paperboat CLI Integration Runbooks

Capture only timestamps and stable request, project, environment, and access-session
IDs. Never capture codes, tokens, URLs containing credentials, terminal output,
image bytes, or local/VM paths.

## WorkOS outage

Detection: device authorization cannot reach approval or authenticated dashboard
requests fail while existing client sessions remain otherwise healthy.

1. Stop device-login retries that could amplify the outage; honor server retry hints.
2. Confirm the failure is isolated to browser identity rather than Paperboat API reachability.
3. Keep existing sessions operating until their normal expiry; do not bypass WorkOS.
4. After recovery, complete one fresh device flow and verify denial and expiry still work.

## Signing-key rotation or rollback

Detection: helper credential verification rejects an otherwise authorized environment with
an unknown key or signature error.

1. Confirm the active `kid`, issuer, audience, and configured JWKS overlap without recording proofs.
2. Keep the previous public key published during the configured overlap window.
3. Roll back the active signing key if new proofs fail while old-key verification succeeds.
4. Verify one new connect, one old-key overlap verification, and revocation before retiring the old key.

## Tunnel outage

Detection: control-plane authorization succeeds but route readiness or WSS/HTTPS
dialing fails across projects.

1. Use `pb doctor <environment>` to distinguish route readiness from helper health.
2. Stop reconnect storms and honor configured retry bounds.
3. Do not expose a Fly port or fall back to SSH.
4. After recovery, verify terminal attach, reconnect, staged upload, and revoked-route rejection.

## Fly start or machine failure

Detection: readiness remains in a machine-starting state, reports machine failure,
or times out before route/helper checks.

1. Correlate the project and machine lifecycle event in the control plane.
2. Confirm entitlement, credits, volume attachment, image identity, and runtime health.
3. Avoid repeated replacement while volume ownership is uncertain.
4. After recovery, run `pb doctor <project>`, attach once, and verify the persistent workspace.

## Helper authorization mismatch

Detection: route and runtime are healthy but mint, token exchange, WebSocket ticket,
terminal scope, or file-stage scope is rejected.

1. Compare issuer, environment ID, owner ID, audience, scope, and clock configuration.
2. Revoke the affected downstream sessions; never broaden a credential scope to diagnose.
3. Reconcile the VM identity configuration and re-broker a new descriptor.
4. Verify terminal-only credentials cannot upload and file-only credentials cannot attach.

## Stuck device grant

Detection: polling remains pending beyond the authoritative expiry or an approved
grant cannot be consumed exactly once.

1. Stop polling at expiry and preserve no device code locally.
2. Check grant state transitions and rate-limit events by hashed grant/network identifiers.
3. Expire or deny the grant through the server-owned operation; do not issue tokens manually.
4. Verify a new flow succeeds and the old code remains unusable.

## Stolen device

1. Revoke the device's client session from the dashboard immediately.
2. Verify the Paperboat token family, helper sessions, and tunnel access are revoked within the configured bound.
3. Run `pb auth logout` on the device if recovered so queued local cleanup completes.
4. Review metadata-only access events; rotate unrelated account credentials only if evidence warrants it.

## Staged-upload cleanup failure

Detection: retained staged files exceed configured age/space bounds or cleanup
reports repeated failures.

1. Stop accepting uploads if storage safety limits are threatened; terminal access remains separately scoped.
2. Inspect counts, sizes, ages, and environment IDs only, never image contents or paths.
3. Restore the helper cleanup worker and run its idempotent cleanup operation.
4. Verify expired files are gone, active files remain readable, traversal is rejected, and new uploads obey retention.

## Recovery evidence

For every incident, record the redacted timeline, affected stable IDs, configured
version/protocol, root cause, containment, recovery verification, and whether
alerts or thresholds need adjustment. Exercise these runbooks against a
production-shaped environment before release.
