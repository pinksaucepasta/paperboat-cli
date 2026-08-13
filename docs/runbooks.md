# Paperboat CLI Integration Runbooks

Capture only timestamps and stable request, project, environment, endpoint, intent, and operation
IDs. Never capture codes, tokens, URLs containing credentials, terminal output,
file/preview bytes, private keys, candidate addresses, or local/machine paths.

## WorkOS outage

Detection: device authorization cannot reach approval or authenticated dashboard
requests fail while existing client sessions remain otherwise healthy.

1. Stop device-login retries that could amplify the outage; honor server retry hints.
2. Confirm the failure is isolated to browser identity rather than Paperboat API reachability.
3. Keep existing sessions operating until their normal expiry; do not bypass WorkOS.
4. After recovery, complete one fresh device flow and verify denial and expiry still work.

## Signing-key rotation or rollback

Detection: runtime or endpoint-certificate verification rejects an otherwise authorized environment with
an unknown key or signature error.

1. Confirm the active `kid`, issuer, audience, and configured JWKS overlap without recording proofs.
2. Keep the previous public key published during the configured overlap window.
3. Roll back the active signing key if new proofs fail while old-key verification succeeds.
4. Verify one new connect, one old-key overlap verification, and revocation before retiring the old key.

## Tunnel outage

Detection: control-plane authorization succeeds but route readiness or WSS/HTTPS
dialing fails across projects.

1. Use `pb doctor <environment>` to distinguish route readiness from host-runtime health.
2. Stop reconnect storms and honor configured retry bounds.
3. Do not expose a machine port or bypass Paperboat with raw SSH. `pb ssh` is valid only when
   its byte stream succeeds through the same direct/relay/WSS transport policy.
4. After recovery, verify terminal attach, reconnect, resumable file transfer, and revoked-route rejection.

## Local daemon unavailable

Detection: `pb status` or `pb wait` cannot open the owner-only local API after its bounded
lazy-start attempt.

1. Verify the socket path and parent directory are owned by the current user and are not
   symlinks or group/world writable. Do not delete an unfamiliar socket or lock file.
2. Check `systemctl --user status paperboat-local-daemon.service` on Linux or
   `launchctl print gui/<uid>/com.pinksaucepasta.paperboat.local-daemon` on macOS.
3. If the service is active, preserve its typed health state and inspect only bounded,
   redacted service diagnostics. Do not bypass the local API with direct control-plane
   polling.
4. Retry `pb status`; it may repair a missing definition only when the socket is absent or
   refusing connections. Permission, protocol, and invalid-state failures require fixing
   ownership or upgrading `pb`, not repeated reinstall attempts.
5. Verify one snapshot read, one watch transition, service restart, stale-socket recovery,
   and `pb uninstall` unloading the service before state removal.

## Codex session interruption

Detection: `pb codex` reports a bridge interruption or Codex exits after a remote WebSocket loss.

1. Do not replay app-server frames or expose a fallback TCP/SSH route.
2. Confirm the environment connector and authenticated runtime route are healthy without recording paths, arguments, credentials, or Codex output.
3. Refresh the descriptor, relaunch local Codex, and use its normal resume picker.
4. If the abandoned lease expired, create a new session and verify the previous runtime state was cleaned.

## Fly start or machine failure

Detection: readiness remains in a machine-starting state, reports machine failure,
or times out before route/runtime checks.

1. Correlate the project and machine lifecycle event in the control plane.
2. Confirm entitlement, credits, volume attachment, image identity, and runtime health.
3. Avoid repeated replacement while volume ownership is uncertain.
4. After recovery, run `pb doctor <project>`, attach once, and verify the persistent workspace.

## Host-runtime authorization mismatch

Detection: route and runtime are healthy but mint, token exchange, WebSocket ticket,
terminal scope, or `file:transfer` scope is rejected.

1. Compare issuer, environment ID, owner ID, audience, scope, and clock configuration.
2. Revoke the affected downstream sessions; never broaden a credential scope to diagnose.
3. Reconcile the machine endpoint identity and host generation, then broker a new descriptor.
4. Verify terminal-only credentials cannot transfer files and file-only credentials cannot attach.

## Endpoint or account-root key compromise

1. Stop new private operations and record only endpoint IDs, certificate fingerprints, generations,
   and timestamps. Never export private key material for diagnosis.
2. For one endpoint, revoke its certificate, advance authorization state, remove its local endpoint
   state through the supported logout/unpair flow, and re-enroll it under the existing account root.
3. For account-root loss or suspected compromise, revoke every endpoint certificate, advance the
   account authorization generation, complete the explicit root reset/recovery flow, and re-pair
   every CLI and machine. The server must not fabricate or escrow a replacement root.
4. Verify old certificates, descriptors, relay admissions, and encrypted transfer resources fail;
   then verify one newly paired terminal and file transfer on the new generations.

## Stuck device grant

Detection: polling remains pending beyond the authoritative expiry or an approved
grant cannot be consumed exactly once.

1. Stop polling at expiry and preserve no device code locally.
2. Check grant state transitions and rate-limit events by hashed grant/network identifiers.
3. Expire or deny the grant through the server-owned operation; do not issue tokens manually.
4. Verify a new flow succeeds and the old code remains unusable.

## Stolen device

1. Revoke the device's client session from the dashboard immediately.
2. Verify the Paperboat token family, endpoint certificate, runtime sessions, and tunnel access
   are revoked within the configured bound.
3. Run `pb auth logout` on the device if recovered so queued local cleanup completes.
4. Review metadata-only access events; rotate unrelated account credentials only if evidence warrants it.

## File-transfer cleanup failure

Detection: staged or pending files exceed configured age/space bounds or cleanup
reports repeated failures.

1. Stop accepting transfers if storage safety limits are threatened; terminal access remains separately scoped.
2. Inspect counts, sizes, ages, and environment IDs only, never file contents or source paths.
3. Restore the host-runtime cleanup worker and run its idempotent cleanup operation.
4. Verify expired files are gone, active files remain readable, traversal is rejected, and new transfers obey retention.

## Served preview workload drift

Detection: a served preview has no ready local listener, a detached listener has no active
preview, a source identity is invalid, or an expired descriptor remains installed.

1. Identify the preview, machine, operation, and descriptor generation without recording
   the source path, directory entries, public URL, or contents.
2. Use `pb preview revoke <id>` to converge public and local state. Do not kill only the
   listener or delete only the descriptor.
3. For a replaced or escaping source, keep the workload stopped; have the owning user
   select the intended source again. Never update a descriptor to accept a new identity.
4. If shutdown cleanup was interrupted, revoke the preview before removing the inactive
   service definition and descriptor.
5. Verify no loopback listener, service definition, descriptor, credential renewal loop,
   or public route remains. Preserve successfully copied `Paperboat Inbox/serve` files.

## Recovery evidence

For every incident, record the redacted timeline, affected stable IDs, configured
version/protocol, root cause, containment, recovery verification, and whether
alerts or thresholds need adjustment. Exercise these runbooks against a
production-shaped environment before release.
