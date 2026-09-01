# TunnelManager reference assessment

Paperboat's durable reconciler uses these source-level precedents. They are
evidence, not copied contracts.

- cloudflared `orchestration/orchestrator.go:77-123,149-200` and
  `orchestration/orchestrator_test.go:51-187`: reject stale or invalid config,
  retain the prior proxy on failure, start the replacement before swapping,
  then stop the prior proxy. Paperboat adds crash-safe desired/LKG persistence
  and stable tunnel and connector identities.
- tailscale `ipn/store/stores.go:157-226`: strict state parsing, restrictive
  permissions, and atomic writes. `ipn/serve.go:28-83` distinguishes persisted
  serving state from foreground session-owned state. Paperboat follows that
  split by restoring durable tunnels but never preview leases.
- headscale `hscontrol/types/node.go:185-204` and
  `hscontrol/poll.go:140-193`: monotonic session generations and exact-session
  cleanup prevent a stale disconnect from deleting a replacement. Paperboat
  passes durable connector and generation identity into every prepared runtime.
- zrok `agent/agent.go:129-238` and `agent/retry.go:174-280`: restore persisted
  shares after restart and retry failed activation. Paperboat retains the useful
  reconciliation loop but does not recreate identities or tokens and only
  promotes a validated generation after origin readiness and durable commit.
- localtunnel `lib/Tunnel.js:55-137` and `lib/TunnelCluster.js:35-125`: reopen
  failed connections and expose an endpoint after the first carrier is open.
  It has no durable identity, generation, or LKG state, so it is not sufficient
  for Paperboat tunnel recovery.
