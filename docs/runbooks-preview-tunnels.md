# Preview And Tunnel Runbooks

Record stable resource, operation, connector, session, assignment, and
configuration-generation IDs before repair. Never record credentials, signed
grants, certificate private keys, provider tokens, origin payloads, or private
request headers. Retry a mutation only with its original idempotency key.

## Preview does not become ready

1. Confirm the foreground `pb preview` process and stable host runtime are
   running.
2. Check origin reachability, the preview owner lease, absolute expiry, carrier
   state, and the edge attachment generation.
3. Keep the managed hostname and owner identity unchanged while the origin or
   carrier reconnects. Do not create a second preview as recovery.
4. Stop a terminal or unwanted lease with `pb preview stop <preview>`. An
   expired, stopped, or ownership-lost preview must not return after reboot.

## Private URL fails

1. Confirm the request uses the hostd-owned narrow PAC/system proxy. Direct
   browser-to-edge traffic is not private authorization.
2. For `401`, restore the current machine login or renewable session. For
   `403`, confirm account membership, route access, and revocation state. For
   `503`, restore hostd, carrier, current edge binding, or server authority and
   retry after reconciliation.
3. Compare the machine installation/session, route, connector, carrier,
   configuration, assignment, edge node, and process epoch. Reject stale or
   partial bindings.
4. Never copy browser cookies, access headers, or grants into a request. There
   is no browser login or redirect fallback.

## Origin unavailable or replacement rejected

1. Run `pb tunnel status <tunnel> --json` and identify the `origin` or
   `configuration` health dimension and rejected generation.
2. Verify the origin is listening on the configured address and protocol. For
   HTTPS, check CA reference, server name, client credential reference, and
   clock before weakening verification.
3. Keep the last-known-good route active. A new generation must pass carrier,
   route, and origin readiness before the old generation drains.
4. After correction, use the normal route update or resume operation and wait
   for desired and applied generations to agree.

## Connector offline, drain, or rotation stuck

1. Use `pb tunnel connector list <tunnel> --json` and record the exact
   connector, session, process, and credential generations.
2. Add and confirm a replacement before draining the old connector. A final
   connector going offline does not delete durable state.
3. For rotation, verify every captured target has installed and proved the new
   credential generation. Old-credential readiness cannot complete rotation.
4. For a stale session or disconnect, let reconciliation mark the target
   uncertain and resume with the same aggregate operation. Do not create a
   duplicate rotation.
5. Revoke only a compromised or permanently retired connector. Late drain
   acknowledgements must not overwrite `revoked` or `forced_closed` state.

## DNS verification or certificate issuance fails

1. Run `pb tunnel domain instructions <tunnel> <domain> --json` and compare the
   authoritative records exactly, including provider proxy mode, DNSSEC, CAA,
   and delegated `_acme-challenge` CNAME target.
2. Correct DNS at the authoritative provider, then run `pb tunnel domain verify
   <tunnel> <domain> --wait --timeout 10m --json`.
3. Separate ownership, ACME, renewal, and edge-distribution failure. Keep the
   previous valid certificate and managed Paperboat hostname active.
4. Do not retry issuance concurrently, move provider credentials to an edge,
   or delete user-owned DNS during repair.
5. Close only after every captured edge process acknowledges the current
   certificate generation and HTTPS serves the expected hostname.

## Edge, server, or database outage

1. Stop new mutations and preserve established last-known-good traffic.
2. Check the complete control snapshot, node process epoch, connector session,
   assignment generation, and observation age. Reject incomplete or stale
   acknowledgements.
3. Restore the failed compatible service. Do not hand-edit snapshots,
   operations, assignments, or database rows.
4. Resume the original operations and wait for idempotent reconciliation.
5. Verify public routing, private PAC/CONNECT, private TCP, DNS/TLS, connector
   drain, and stale-generation rejection before reopening changes.

## Update rollback or quarantine

1. Stop rollout when signature, hash, architecture, compatibility, process,
   route-generation, origin, edge-canary, or certificate checks fail.
2. Keep the previous signed release and last-known-good connector active while
   the update journal restores it.
3. Confirm rollback begins within 30 seconds of the qualifying failure and the
   known-good connector returns within 120 seconds on a supported system.
4. Keep the failed version quarantined. Do not edit the release selector or
   bypass TUF verification.
5. Reopen rollout only after the signed manifest and deployment plan, runtime
   verifier, server readiness check, endpoint continuity, and rollback test all
   agree.

## Overload, leak, or slow consumer

1. Check active streams, queue depth, flow-control stalls, goroutines, file
   descriptors, memory, retry delay, and oldest operation age using bounded
   metrics.
2. Drain new assignments from an affected edge or connector. Preserve active
   streams within their deadlines and do not raise limits before identifying
   the leak or unfair workload.
3. Confirm admission rejects before the configured ceiling, stream
   cancellation releases permits, and control heartbeats are not starved.
4. After repair, repeat the sustained soak and compare latency percentiles and
   resource deltas with the prior clean baseline.

## Support bundle

1. Run `pb tunnel doctor <tunnel>` and review each typed health dimension.
2. Preview the bounded support-bundle manifest before upload.
3. Remove credentials, private keys, signed URLs or grants, headers, payloads,
   private hostnames, origin content, local paths, and candidate addresses.
4. Include only stable IDs, generations, typed error codes, retry decisions,
   correlation IDs, sanitized resource trends, and the incident timeline.
5. Close the incident only when durable and observed state agree, old
   generations are fenced, retry queues drain, and the bundle redaction review
   passes.
