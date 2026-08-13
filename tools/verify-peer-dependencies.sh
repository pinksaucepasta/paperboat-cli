#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

command -v rg >/dev/null 2>&1 || {
  echo "peer dependencies: rg is required" >&2
  exit 2
}

require_module() {
  path=$1
  version=$2
  actual=$(go list -m -f '{{.Version}}' "$path")
  [ "$actual" = "$version" ] || {
    echo "peer dependency mismatch: $path is $actual, want $version" >&2
    exit 1
  }
}

require_module github.com/pion/ice/v4 v4.4.0
require_module github.com/pion/stun/v3 v3.1.6
require_module github.com/pion/transport/v4 v4.0.2
require_module github.com/flynn/noise v1.1.0
require_module github.com/adrg/xdg v0.5.3
require_module github.com/coreos/go-systemd/v22 v22.6.0
require_module github.com/google/renameio/v2 v2.0.2
require_module github.com/quic-go/quic-go v0.61.0
require_module github.com/tailscale/peercred v0.0.0-20250107143737-35a0c7bd7edc
require_module github.com/tailscale/squibble v0.0.0-20260411062017-141f5d618bc4
require_module go.uber.org/goleak v1.3.0
require_module golang.org/x/crypto v0.54.0
require_module howett.net/plist v1.0.1
require_module pgregory.net/rapid v1.3.0
require_module tailscale.com v1.102.1

v3_edges=$(go mod graph | awk '$2 ~ /^github.com\/pion\/transport\/v3@/ { print }')
[ "$v3_edges" = "github.com/pion/mdns/v2@v2.1.0 github.com/pion/transport/v3@v3.1.1" ] || {
  echo "unexpected pion/transport/v3 module edge:" >&2
  printf '%s\n' "$v3_edges" >&2
  exit 1
}

if go list -deps -test ./... | grep -q '^github.com/pion/transport/v3\($\|/\)'; then
  echo "pion/transport/v3 entered the compiled package graph" >&2
  exit 1
fi

if rg -n --glob '*.go' 'github\.com/pion/(turn|mdns)|github\.com/pion/transport/v3' .; then
  echo "owned source imports a forbidden Pion package" >&2
  exit 1
fi

if rg -n --glob '*.go' 'github\.com/gorilla/websocket' .; then
  echo "owned source imports forbidden Gorilla WebSocket package" >&2
  exit 1
fi

if rg -n --glob '*.go' --glob '!**/*_test.go' 'Getsockopt(Ucred|Xucred)|SO_PEERCRED|LOCAL_PEERCRED' internal cmd; then
  echo "owned source bypasses the peercred facade" >&2
  exit 1
fi

if go list -deps -test ./... | grep -q '^github.com/gorilla/websocket$'; then
  echo "Gorilla WebSocket entered the compiled package graph" >&2
  exit 1
fi

default_http=$(rg -n --glob '*.go' --glob '!**/*_test.go' 'http\.(DefaultClient|DefaultTransport|Get|Post)\b' internal cmd || true)
unexpected_default_http=$(printf '%s\n' "$default_http" | grep -Ev '^internal/hostruntime/preview/proxy\.go:[0-9]+:[[:space:]]*config\.Transport = http\.DefaultTransport$' || true)
if [ -n "$unexpected_default_http" ]; then
  echo "owned external HTTP path bypasses the shared transport:" >&2
  printf '%s\n' "$unexpected_default_http" >&2
  exit 1
fi

if rg -n --glob '*.go' '\.(UnsafeKey|Cipher|SetNonce)\(' internal/peertransport; then
  echo "owned E2EE source uses a forbidden Noise cipher API" >&2
  exit 1
fi

for import in $(rg -o --no-filename --glob '*.go' 'tailscale\.com/[^"[:space:]]+' . | sort -u); do
  case "$import" in
    tailscale.com/net/netmon|tailscale.com/net/portmapper|tailscale.com/net/portmapper/portmappertype|tailscale.com/net/wsconn|tailscale.com/util/eventbus) ;;
    *)
      echo "owned source imports forbidden Tailscale package: $import" >&2
      exit 1
      ;;
  esac
done

unexpected_eventbus=$(rg -n --glob '*.go' 'tailscale\.com/util/eventbus' . | grep -Ev '^\./internal/peertransport/networkmonitor/(monitor|renewal)(_test)?\.go:[0-9]+:' || true)
if [ -n "$unexpected_eventbus" ]; then
	echo "owned source imports Tailscale eventbus outside the network-monitor facade:" >&2
  printf '%s\n' "$unexpected_eventbus" >&2
	exit 1
fi

unexpected_portmappertype=$(rg -n --glob '*.go' 'tailscale\.com/net/portmapper/portmappertype' . | grep -Ev '^\./internal/peertransport/networkmonitor/renewal(_test)?\.go:[0-9]+:' || true)
if [ -n "$unexpected_portmappertype" ]; then
	echo "owned source imports Tailscale port-mapping event types outside the renewal facade:" >&2
	printf '%s\n' "$unexpected_portmappertype" >&2
	exit 1
fi

echo "peer dependencies: valid"
