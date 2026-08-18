# Paperboat containers

The hosted and self-hosted images run a stable `paperboat-hostd` process and a
separate root `paperboat-updated` process. Hostd owns terminal PTYs, managed
SSH channels, file transfers, previews, Codex processes, and live relay or
direct streams. The updater owns only TUF verification, release staging,
cutover, rollback, and bounded cleanup.

The `/var/lib/paperboat` volume is mandatory and contains three separate
ownership domains:

| Path | Owner | Purpose |
| --- | --- | --- |
| `releases/` | root, not writable by the runtime user | active, rollback, and staged runtime and CLI artifacts |
| `updated/` | root, mode `0700` | updater journal and TUF metadata |
| `runtime/` and `hostd/` | `paperboat` UID/GID `10001`, mode `0700` | durable workload state and hostd capability token |

`/workspace` is a second persistent volume owned by the `paperboat` runtime
user. Never mount either volume from a less-trusted container. Never copy the
release volume between machines because it contains installation-local state.

The root filesystem is read-only in both supplied Compose definitions. Only
the fixed state and workspace volumes plus tmpfs `/run` and `/tmp` are
writable. The entrypoint rejects a non-HTTPS release repository, mutable path
overrides, unexpected ownership, symlinks, and malformed capability tokens.

## Hosted container

Use [../hosted/compose.yaml](../hosted/compose.yaml). The hosted container
requires `PAPERBOAT_SSH_USER=paperboat`; this is intentional. The SSH daemon
binds only `127.0.0.1` and accepts the same unprivileged account that owns
Paperboat workloads. It is reached only through Paperboat managed SSH, never
through a published container port.

The image first places its release-matched runtime and CLI into empty release
slots. On every later boot it keeps the existing verified active slots. The
updater independently resolves the fixed signed TUF index before it stages
anything. A new runtime therefore replaces only the fenced runtime child
under the running hostd process.

## Self-hosted container

Use [../self-hosted/compose.yaml](../self-hosted/compose.yaml). The first
start consumes the normal one-time BYOD enrollment credential. Remove that
credential from the deployment configuration after enrollment. No SSH daemon
or host port is exposed by this mode; all connectivity uses normal Paperboat
direct or relay paths.

## Operational boundary

Ordinary runtime and CLI updates are invisible and preserve hostd-owned work.
A container image replacement, pod eviction, node loss, or administrator
container restart is supervisor-class maintenance and is outside that
continuity guarantee. Schedule such work through the maintenance approval
flow when protected workloads are present. Keep the two volumes attached and
use normal durable recovery after a restart.
