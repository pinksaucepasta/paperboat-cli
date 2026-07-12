# CLI Security And Operations

The CLI sends `X-Paperboat-Client: paperboat-cli` and
`X-Paperboat-Protocol: 1` on control-plane requests. Release builds also send a
versioned `User-Agent`. Unsupported protocols must be rejected with HTTP 426 or
`incompatible_client_version`; `pb` reports the upgrade message and does not
retry.

- Never put device, access, or refresh tokens in URLs or logs.
- A rejected access token requires `pb auth login`; there is no local-shell fallback.
- Upload failures are fail-open only for the affected paste. Image bytes and paths are never logged.
- For a stolen device, revoke its client session in the dashboard, then run `pb auth logout`.
- During outages, use `pb doctor`; never bypass agentunnel or attach over SSH.

Production connection metrics are written as validated JSONL to
`observability.event_log_path`, or `telemetry.jsonl` beside the CLI config by
default. The file is restricted to mode `0600` and never contains endpoints,
credentials, terminal bytes, image data, or local/VM paths. Its configured size
limit bounds disk usage; the oldest accumulated events are truncated when the
next record would exceed that limit.

Threat-model sign-off, cross-service metrics and audit events, artifact signing,
SBOM/provenance, and revocation propagation evidence remain release work in the
owning repositories.

`make release-metadata` emits a versioned binary, SHA-256 checksum, and
provenance JSON containing the version, protocol, commit, and Go toolchain. The
release pipeline must sign these files and attach an SBOM before publishing.

Pushing a `v*` tag runs `.github/workflows/release.yml`. It cross-builds the six
supported OS/architecture combinations, creates checksums and SPDX JSON SBOMs,
attests each archive with GitHub's OIDC-backed artifact attestation, and uploads
the assets to the GitHub release. Verify an installed archive with `gh
attestation verify <archive> --repo <owner>/<repo>` and its adjacent checksum
before installation.

Incident procedures are maintained in [runbooks.md](runbooks.md).
