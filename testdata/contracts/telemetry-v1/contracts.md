# Paperboat telemetry v1

This family freezes the internal detailed health snapshot used by the
Paperboat control plane, stable host runtime, and tunnel. It is the
`paperboat.health/v1` diagnostic contract, not the public preview resource
health projection. A consumer may decode the same snapshot from any of the
three services.

## Snapshot

Every snapshot is a JSON object with exactly `schema`, `updated_at`, `overall`,
`dimensions`, and `etag`. `schema` is `paperboat.health/v1`. All timestamps are
RFC 3339 UTC values ending in `Z`; all text and identifiers are bounded and
printable. Strings containing URLs, hostnames, bearer/basic credentials,
private-key PEM, or credential-like key/value material are not valid health
content. Health output is safe to include in local diagnostics and structured
logs.

`etag` is a lowercase `sha256:` digest with 64 hexadecimal characters. The
producer computes it from the canonical JSON snapshot before the populated ETag
is inserted. Consumers use it for change detection and must not treat it as a
credential or as an authorization token.

## Fixed dimensions

`dimensions` contains exactly these nine independently actionable dimensions:

`service`, `edge`, `config`, `route`, `origin`, `dns`, `certificate`, `access`,
and `update`.

Each dimension and `overall` contains `status`, `code`, `since`, `summary`,
`repair_action`, and `retry`. Optional fields are `broken_since`,
`correlation_id`, `next_retry_at`, and (for a dimension) `suppressed_by`.

The allowed statuses are `unknown`, `ready`, `degraded`, `down`, and
`not_applicable`. `degraded` and `down` require `broken_since`; other statuses
must omit it. `retry` is `none`, `wait_for_change`, or `not_retryable` when
`next_retry_at` is absent, and is `scheduled` only when `next_retry_at` is
present. `suppressed_by`, when present, is one of the nine dimension names and
means the named dependency is the actionable root. Unknown fields, dimensions,
statuses, retry combinations, or secret-bearing values are rejected.

The JSON Schema is the executable contract. Its vectors intentionally include
positive snapshots and negative mutations for secret text, hostname/URL text,
unknown dimensions/status, retry mismatch, broken-state mismatch, and missing
required fields.
