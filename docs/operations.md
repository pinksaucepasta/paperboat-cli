# CLI Security And Operations

The CLI sends `X-Paperboat-Client: paperboat` and
`X-Paperboat-Protocol: 1` on control-plane requests. Release builds also send a
versioned `User-Agent`. Unsupported protocols must be rejected with HTTP 426 or
`incompatible_client_version`; `pb` reports the upgrade message and does not
retry.

- Never put device, access, or refresh tokens in URLs or logs.
- A rejected access token requires `pb auth login`; there is no local-shell fallback.
- Upload failures are fail-open only for the affected paste. Image bytes and paths are never logged.
- For a stolen device, revoke its client session in the dashboard, then run `pb auth logout`.
- During outages, use `pb doctor`; never bypass `paperboat-tunnel` or attach over SSH.
- `pb codex` credentials, remote paths, command arguments, and Codex output are never
  written to logs. The remote environment owns its Codex login and configuration.

Production connection metrics are written as validated JSONL to
`observability.event_log_path`, or `telemetry.jsonl` beside the CLI config by
default. The file is restricted to mode `0600` and never contains endpoints,
credentials, terminal bytes, image data, or local/VM paths. Its configured size
limit bounds disk usage; the oldest accumulated events are truncated when the
next record would exceed that limit.

Terminal output compression is application framing shared by QUIC and WSS. Terminal
sequence, replay, queue, and PTY byte counters describe decoded user bytes; connector
and edge wire counters describe encoded bytes and therefore need not match. Repeated
terminal codec failures indicate an incompatible or corrupt peer: stop reconnecting,
retain only typed diagnostics and counters, and upgrade both runtime endpoints. Never
capture a terminal payload for diagnosis.

Each ended or replaced client transport connection records metadata-only
`terminal.compression` events for raw/Zstandard frame counts, decoded and encoded bytes,
decode nanoseconds, and typed failure count. These events intentionally omit project,
environment, session, request, and user identifiers and never include payload bytes.

The client output queue is bounded by 256 complete decoded events. Each event is bounded
by `MaxTerminalOutputBytes`, so its worst-case decoded admission is
`helperOutputQueueDecodedLimit` (about 64 MiB) regardless of encoded size. Output received
before attach completion is separately bounded to 64 events, 1 MiB encoded, and 1 MiB
decoded before any payload is queued.

Threat-model sign-off, cross-service metrics and audit events, artifact signing,
SBOM/provenance, and revocation propagation evidence remain release work in the
owning repositories.

`make release-metadata` emits a versioned binary, SHA-256 checksum, and
provenance JSON containing the version, protocol, commit, and Go toolchain. The
release pipeline must sign these files and attach an SBOM before publishing.

Pushing a validated `YYYY.MM.DD.X` tag runs `.github/workflows/release.yml`. It cross-builds the six
supported OS/architecture combinations, creates checksums and SPDX JSON SBOMs,
attests each archive with GitHub's OIDC-backed artifact attestation, and uploads
the assets to the GitHub release. Verify an installed archive with `gh
attestation verify <archive> --repo <owner>/<repo>` and its adjacent checksum
before installation.

Incident procedures are maintained in [runbooks.md](runbooks.md).

## Machine runtime services

`pb pair` installs the terminal host and its `runtime` connector. Configuration sync is a
separate per-user `__runtime-config` service and starts only while the local machine has an
assignment. Neither process initializes preview monitoring.

`pb preview create` starts one per-user service per preview. `--machine` resolves an owned,
online paired machine and uses a two-minute `preview_launch` credential to ask that
machine's host runtime to install the same isolated service. Each runner owns one preview
connector whose connector ID is the server-issued preview key. Its durable descriptor
stores the original absolute expiry; after reboot the runner resumes only a matching,
active server record and uses the remaining lifetime. Expiry or server revocation removes
the route, descriptor, and service definition. A crash retains the descriptor so the OS
service can retry without extending expiry.

`pb serve` uses the same preview service namespace and inventory. Foreground mode first
acquires a bounded `local_runtime_control/1.0` management lease from the loopback runtime
using an owner-only local token, renews it while attached, and stops the workload if renewal
fails. The runtime expires abandoned leases and reconciles the preview route. The CLI owns
an ephemeral `127.0.0.1` static listener and drains it before canceling the preview runner.
`--detach` installs `__runtime-serve`; its v1 descriptor contains
only the canonical source path and filesystem identity, file/directory kind, SPA policy,
bind address, assigned loopback port, owner mode, preview record, service definition,
service generation, and original absolute expiry. It contains no credential. The detached
unit is active only for the current machine runtime and is not enabled for the next boot.
Server revocation and capacity eviction are observed by the existing
preview reconciliation loop and stop the listener, descriptor, and service. Successfully
ingested Inbox files remain user-owned.

`pb doctor` verifies the local lease protocol and compares served descriptors with their
loopback listeners without returning source paths. Session-mode transitions, unpair, and
uninstall retire all durable preview services before authority or state is removed.

Machine-control credentials renew in memory and are bound to the enrolled Ed25519 key and
installation generation. Reinstall, unpair, or machine revocation invalidates them. Never
copy a runtime state directory to another machine or edit preview service descriptors.
