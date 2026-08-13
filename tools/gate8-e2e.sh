#!/usr/bin/env bash

set -u
set -o pipefail

TARGET="${TARGET:-hn-byod-ready}"
RESULT_ROOT="${RESULT_ROOT:-$HOME/gate8-results/$(date -u +%Y%m%dT%H%M%SZ)}"
REPEAT="${REPEAT:-5}"
TEST_TIMEOUT="${TEST_TIMEOUT:-45}"
mkdir -p "$RESULT_ROOT/cases"
available_kb="$(df -Pk "$RESULT_ROOT" | awk 'NR==2 {print $4}')"
if test -z "$available_kb" || test "$available_kb" -lt 1048576; then
  printf 'insufficient persistent space for Gate 8 evidence: %s KiB available\n' "${available_kb:-unknown}" >&2
  exit 2
fi
RESULTS="$RESULT_ROOT/results.jsonl"
: >"$RESULTS"
: >"$RESULT_ROOT/assertions.jsonl"
exec 9>>"$RESULTS"
exec 8>>"$RESULT_ROOT/assertions.jsonl"

json_string() {
  jq -Rn --arg value "$1" '$value'
}

run_case() {
  local category="$1" transport="$2" name="$3"
  shift 3
  local id safe_id stdout_file stderr_file meta_file start_ns end_ns elapsed_ms rc
  id="${category}-${transport}-${name}"
  safe_id="$(printf '%s' "$id" | tr -c 'A-Za-z0-9._-' '_')"
  stdout_file="$RESULT_ROOT/cases/$safe_id.stdout"
  stderr_file="$RESULT_ROOT/cases/$safe_id.stderr"
  meta_file="$RESULT_ROOT/cases/$safe_id.command"
  printf '%q ' "$@" >"$meta_file"
  printf '\n' >>"$meta_file"
  start_ns="$(date +%s%N)"
  timeout --foreground --signal=TERM --kill-after=5 "$TEST_TIMEOUT" setsid "$@" >"$stdout_file" 2>"$stderr_file"
  rc=$?
  end_ns="$(date +%s%N)"
  elapsed_ms=$(((end_ns - start_ns) / 1000000))
  local record
  record="$(jq -cn \
    --arg id "$id" --arg category "$category" --arg transport "$transport" --arg name "$name" \
    --arg command "$(<"$meta_file")" --arg stdout_file "$stdout_file" --arg stderr_file "$stderr_file" \
    --arg stdout_sha256 "$(sha256sum "$stdout_file" | cut -d' ' -f1)" \
    --arg stderr_sha256 "$(sha256sum "$stderr_file" | cut -d' ' -f1)" \
    --argjson exit_code "$rc" --argjson elapsed_ms "$elapsed_ms" \
    --argjson stdout_bytes "$(wc -c <"$stdout_file")" --argjson stderr_bytes "$(wc -c <"$stderr_file")" \
    '{id:$id,category:$category,transport:$transport,name:$name,exit_code:$exit_code,elapsed_ms:$elapsed_ms,command:$command,stdout_file:$stdout_file,stderr_file:$stderr_file,stdout_bytes:$stdout_bytes,stderr_bytes:$stderr_bytes,stdout_sha256:$stdout_sha256,stderr_sha256:$stderr_sha256}')"
  flock 9
  printf '%s\n' "$record" >&9
  flock -u 9
  printf '%s\n' "$record"
  local expected="${EXPECTED_EXIT:-0}" assertion
  if test "$expected" = nonzero; then
    assertion="$(jq -cn --argjson record "$record" '{id:$record.id,assertion:"expected_nonzero_exit",passed:($record.exit_code!=0),detail:("actual="+($record.exit_code|tostring))}')"
  elif test "$expected" = 0or1; then
    assertion="$(jq -cn --argjson record "$record" '{id:$record.id,assertion:"expected_exit_0_or_1",passed:($record.exit_code==0 or $record.exit_code==1),detail:("actual="+($record.exit_code|tostring))}')"
  else
    assertion="$(jq -cn --argjson record "$record" --argjson expected "$expected" \
      '{id:$record.id,assertion:"expected_exit",passed:($record.exit_code==$expected),detail:("expected="+($expected|tostring)+" actual="+($record.exit_code|tostring))}')"
  fi
  flock 8
  printf '%s\n' "$assertion" >&8
  flock -u 8
  return 0
}

expect_exit() {
  local expected="$1"
  shift
  EXPECTED_EXIT="$expected" run_case "$@"
}

assert_case() {
  local id="$1" assertion="$2" passed="$3" detail="$4"
  local record
  record="$(jq -cn --arg id "$id" --arg assertion "$assertion" --arg detail "$detail" --argjson passed "$passed" \
    '{id:$id,assertion:$assertion,passed:$passed,detail:$detail}')"
  flock 8
  printf '%s\n' "$record" >&8
  flock -u 8
}

snapshot() {
  local name="$1"
  pb status --json >"$RESULT_ROOT/status-$name.json" 2>"$RESULT_ROOT/status-$name.stderr" || true
  ps -ef >"$RESULT_ROOT/processes-$name.txt"
}

selected_path() {
  local value
  value="$(pb status "$TARGET" --json 2>/dev/null | jq -r '.machines[0].selected_path // "none"')"
  test "$value" = direct && value=direct_quic
  test "$value" = relay && value=relay_quic
  printf '%s\n' "$value"
}

wait_path() {
  local expected="$1" deadline=$((SECONDS + 30)) value
  while ((SECONDS < deadline)); do
    value="$(selected_path)"
    test "$value" = relay && value=relay_quic
    case ",$expected," in
      *",$value,"*) printf '%s\n' "$value"; return 0 ;;
    esac
    sleep 0.2
  done
  value="$(selected_path)"
  test "$value" = relay && value=relay_quic
  printf '%s\n' "$value"
  return 1
}

record_path_until_stopped() {
  local destination="$1" stop_file="$2" value previous=""
  while ! test -e "$stop_file"; do
    value="$(selected_path)"
    if test "$value" != "$previous"; then
      printf '%s\t%s\n' "$(date +%s%3N)" "$value" >>"$destination"
      previous="$value"
    fi
    sleep 0.1
  done
}

transition_case() {
  local mode="$1" id="$2" output history stop_file
	output="$RESULT_ROOT/cases/transition-$id.output"
  history="$RESULT_ROOT/cases/transition-$id.paths"
  stop_file="$RESULT_ROOT/cases/transition-$id.stop"
  rm -f "$stop_file"
  sudo /usr/local/sbin/paperboat-gate8-network allow-udp
  pb exec "$TARGET" --transport "$mode" -- sh -c 'i=0; while test "$i" -lt 900; do printf "%s\n" "$i"; i=$((i+1)); sleep 0.2; done' >"$output" 2>"$RESULT_ROOT/cases/transition-$id.stderr" &
  local client_pid=$!
  record_path_until_stopped "$history" "$stop_file" &
  local observer_pid=$!
  local initial relay_only blocked relay_restored restored blocked_again relay_restored_again restored_again
  initial="$(wait_path direct_quic,relay_quic,wss || true)"
  if test "$mode" = a; then
    sudo /usr/local/sbin/paperboat-gate8-network relay-only-udp
    relay_only="$(wait_path relay_quic || true)"
  else
    relay_only="$initial"
  fi
  sudo /usr/local/sbin/paperboat-gate8-network block-udp
  blocked="$(wait_path wss || true)"
  sudo /usr/local/sbin/paperboat-gate8-network relay-only-udp
  relay_restored="$(wait_path relay_quic || true)"
  if test "$mode" = a; then
    sudo /usr/local/sbin/paperboat-gate8-network allow-udp
    restored="$(wait_path direct_quic || true)"
  else
    restored="$relay_restored"
  fi

  sudo /usr/local/sbin/paperboat-gate8-network block-udp
  blocked_again="$(wait_path wss || true)"
  sudo /usr/local/sbin/paperboat-gate8-network relay-only-udp
  relay_restored_again="$(wait_path relay_quic || true)"
  if test "$mode" = a; then
    sudo /usr/local/sbin/paperboat-gate8-network allow-udp
    restored_again="$(wait_path direct_quic || true)"
  else
    restored_again="$relay_restored_again"
  fi
	sudo /usr/local/sbin/paperboat-gate8-network allow-udp
  kill -TERM "$client_pid" 2>/dev/null || true
  wait "$client_pid" 2>/dev/null || true
  touch "$stop_file"
  wait "$observer_pid" 2>/dev/null || true
  local path_sequence=false
  if test "$blocked" = wss && test "$relay_restored" = relay_quic && test "$blocked_again" = wss && test "$relay_restored_again" = relay_quic; then
    if test "$mode" = a && test "$relay_only" = relay_quic && test "$restored" = direct_quic && test "$restored_again" = direct_quic; then
      path_sequence=true
    elif test "$mode" = r && test "$restored" = relay_quic && test "$restored_again" = relay_quic; then
      path_sequence=true
    fi
  fi
  assert_case "transition-$id" path-sequence "$path_sequence" \
    "initial=$initial relay_only=$relay_only blocked=$blocked relay_restored=$relay_restored restored=$restored blocked_again=$blocked_again relay_restored_again=$relay_restored_again restored_again=$restored_again"
  assert_case "transition-$id" continuous-output \
    "$(awk 'NR==1{p=$1;next}{if($1!=p+1)exit 1;p=$1}END{if(NR<3)exit 1}' "$output" && echo true || echo false)" \
    "lines=$(wc -l <"$output")"
}

snapshot before
trap 'sudo /usr/local/sbin/paperboat-gate8-network allow-udp >/dev/null 2>&1 || true' EXIT INT TERM
for required in pb jq timeout setsid flock script ssh scp sftp curl sudo python3 sha256sum; do
  command -v "$required" >/dev/null || { printf 'missing required command: %s\n' "$required" >&2; exit 2; }
done
sudo -n /usr/local/sbin/paperboat-gate8-network allow-udp

# Installed artifact and service preflight. Expected hashes are supplied by
# the matched build/deploy step; an unset value is an acceptance failure.
dadape_hash="$(sha256sum "$(command -v pb)" | cut -d' ' -f1)"
assert_case preflight installed-hash "$(test -n "${EXPECTED_DADAPE_SHA256:-}" -a "$dadape_hash" = "${EXPECTED_DADAPE_SHA256:-missing}" && echo true || echo false)" "actual=$dadape_hash expected=${EXPECTED_DADAPE_SHA256:-unset}"
assert_case preflight user-daemon "$(systemctl --user is-active paperboat-local-daemon.service >/dev/null 2>&1 && echo true || echo false)" exact
assert_case preflight host-services "$(systemctl is-active paperboat-runtime-host.service paperboat-runtime-privileged.service 2>/dev/null | awk 'BEGIN{ok=1} $0!="active"{ok=0} END{print ok ? "true" : "false"}')" exact
source_evidence="${GATE8_SOURCE_EVIDENCE:-/tmp/gate8-source-evidence.txt}"
source_evidence_hash="$(sha256sum "$source_evidence" 2>/dev/null | cut -d' ' -f1 || true)"
assert_case preflight source-evidence "$(test -n "${EXPECTED_SOURCE_EVIDENCE_SHA256:-}" -a "$source_evidence_hash" = "${EXPECTED_SOURCE_EVIDENCE_SHA256:-missing}" && grep -q '^result=PASS$' "$source_evidence" && echo true || echo false)" "actual=$source_evidence_hash expected=${EXPECTED_SOURCE_EVIDENCE_SHA256:-unset}"
deployment_evidence="${GATE8_DEPLOYMENT_EVIDENCE:-/tmp/gate8-deployment-evidence.txt}"
deployment_evidence_hash="$(sha256sum "$deployment_evidence" 2>/dev/null | cut -d' ' -f1 || true)"
assert_case preflight deployment-evidence "$(test -n "${EXPECTED_DEPLOYMENT_EVIDENCE_SHA256:-}" -a "$deployment_evidence_hash" = "${EXPECTED_DEPLOYMENT_EVIDENCE_SHA256:-missing}" && grep -q '^result=PASS$' "$deployment_evidence" && echo true || echo false)" "actual=$deployment_evidence_hash expected=${EXPECTED_DEPLOYMENT_EVIDENCE_SHA256:-unset}"

run_case inventory none environments pb environments --json
run_case inventory none machine-list pb machine list --json
run_case inventory none status pb status "$TARGET" --json
run_case readiness none wait-runtime pb wait "$TARGET" --for runtime --timeout 30s --json
run_case readiness none wait-transport pb wait "$TARGET" --for transport --timeout 30s --json
run_case readiness none wait-ssh pb wait "$TARGET" --for ssh --timeout 30s --json
run_case diagnostics none doctor-local pb doctor --json
EXPECTED_EXIT=0or1 run_case diagnostics none doctor-target pb doctor "$TARGET" --json
doctor_target_rc="$(jq -r 'select(.id=="diagnostics-none-doctor-target") | .exit_code' "$RESULTS")"
doctor_target_overall="$(jq -r '.overall // empty' "$RESULT_ROOT/cases/diagnostics-none-doctor-target.stdout")"
assert_case diagnostics-none-doctor-target structured-result \
  "$(test "$doctor_target_rc" = 0 -o "$doctor_target_rc" = 1 && test -n "$doctor_target_overall" && echo true || echo false)" \
  "exit=$doctor_target_rc overall=$doctor_target_overall"
run_case ssh none doctor pb ssh doctor "$TARGET"

for transport in a d q w r; do
  for run in $(seq 1 "$REPEAT"); do
    run_case ping "$transport" "$run" pb ping "$TARGET" --transport "$transport" --count 3 --json
    ping_file="$RESULT_ROOT/cases/ping-${transport}-${run}.stdout"
    assert_case "ping-$transport-$run" zero-loss \
      "$(jq -e '(.lost // .packet_loss // 0) == 0' "$ping_file" >/dev/null 2>&1 && echo true || echo false)" exact
  done
done

for transport in a d q w r; do
  for run in $(seq 1 "$REPEAT"); do
    expect_exit 7 exec "$transport" "$run" pb exec "$TARGET" --transport "$transport" -- \
      sh -c "printf 'exec-$transport-$run'; printf 'err-$transport-$run' >&2; exit 7"
  done
done

for transport in a d q w r; do
  expect_exit 6 exec_json "$transport" events pb exec "$TARGET" --transport "$transport" --json -- sh -c 'printf json-out; printf json-err >&2; exit 6'
  run_case exec_pty "$transport" pty pb exec "$TARGET" --transport "$transport" --pty -- sh -c 'test -t 0 && test -t 1 && printf pty-ok'
  workspace_root="$(pb status "$TARGET" --json | jq -r '.machines[0].workspace_root')"
  run_case exec_env "$transport" env pb exec "$TARGET" --transport "$transport" --env G8_VALUE=transport-ok --cwd "$workspace_root" -- sh -c 'test "$PWD" = "$HOME" && test "$G8_VALUE" = transport-ok && printf env-ok'
  expect_exit 124 exec_timeout "$transport" timeout pb exec "$TARGET" --transport "$transport" --timeout 1s -- sh -c 'sleep 30'
done

for transport in a d q w r; do
  for run in $(seq 1 "$REPEAT"); do
    run_case ssh "$transport" "$run" pb ssh "$TARGET" --transport "$transport" --user root -- true
  done
done

# Remove only terminal fixtures left by prior Gate 8 runs.
pb sessions "$TARGET" --json | jq -r '.sessions[] | select(.name | startswith("g8-")) | .name' | while IFS= read -r stale; do
  pb sessions close "$TARGET" "$stale" --yes --json >/dev/null 2>&1 || true
done

# Terminal create/attach lifecycle uses a readiness-driven PTY harness. It
# repeatedly sends an idempotent marker until the remote shell returns it; no
# fixed startup sleep can turn transport latency into a false product failure.
for transport in a d q w r; do
  terminal_name="g8-${transport}-$(date +%s%N)"
  run_case terminal "$transport" create python3 /tmp/gate8-terminal-ready.py "$TARGET" "$transport" "$terminal_name" "terminal-$transport" "$RESULT_ROOT/cases/terminal-${transport}-pty.raw"
  terminal_stdout="$RESULT_ROOT/cases/terminal-${transport}-pty.raw"
  assert_case "terminal-${transport}-create" canary \
    "$(grep -q "terminal-$transport" "$terminal_stdout" && echo true || echo false)" \
    "expected terminal-$transport"
  run_case sessions "$transport" list pb sessions "$TARGET" --json --wide
  run_case sessions "$transport" rename pb sessions rename "$TARGET" "$terminal_name" "${terminal_name}-renamed"
  run_case sessions "$transport" close pb sessions close "$TARGET" "${terminal_name}-renamed" --yes --json
  run_case sessions "$transport" delete pb sessions delete "$TARGET" "${terminal_name}-renamed" --yes --json
done

# File transfer uses its fixed direct HTTP/3 -> relay HTTP/3 -> relay HTTP/2
# policy and intentionally has no transport selector.
mkdir -p "$RESULT_ROOT/payload"
dd if=/dev/urandom of="$RESULT_ROOT/payload/random.bin" bs=1048576 count=8 status=none
printf 'paperboat gate 8\n' >"$RESULT_ROOT/payload/small.txt"
mkdir -p "$RESULT_ROOT/payload/tree/sub"
cp "$RESULT_ROOT/payload/small.txt" "$RESULT_ROOT/payload/tree/sub/value.txt"
run_case transfer none destination pb transfer destination --json
run_case transfer none send-small pb send "$RESULT_ROOT/payload/small.txt" --to "$TARGET" --json
run_case transfer none send-binary pb send "$RESULT_ROOT/payload/random.bin" --to "$TARGET" --json
sudo /usr/local/sbin/paperboat-gate8-network relay-only-udp
run_case transfer relay-h3 send pb send "$RESULT_ROOT/payload/small.txt" --to "$TARGET" --json
sudo /usr/local/sbin/paperboat-gate8-network block-udp
run_case transfer relay-h2 send pb send "$RESULT_ROOT/payload/small.txt" --to "$TARGET" --json
sudo /usr/local/sbin/paperboat-gate8-network allow-udp
for transfer_file in "$RESULT_ROOT/cases/transfer-none-send-small.stdout" "$RESULT_ROOT/cases/transfer-none-send-binary.stdout" "$RESULT_ROOT/cases/transfer-relay-h3-send.stdout" "$RESULT_ROOT/cases/transfer-relay-h2-send.stdout"; do
  assert_case "transfer-$(basename "$transfer_file" .stdout)" delivered "$(jq -e '.. | objects | select(has("state")) | .state == "delivered" or .state == "published"' "$transfer_file" >/dev/null 2>&1 && echo true || echo false)" "$transfer_file"
done
run_case transfer none list pb transfer list --on "$TARGET" --limit 50 --json
transfer_batch_id="$(jq -r '..|.batch_id? // empty' "$RESULT_ROOT/cases/transfer-none-send-binary.stdout" 2>/dev/null | head -1 || true)"
transfer_id="$(jq -r --arg batch "$transfer_batch_id" '.. | objects | select(.batch_id? == $batch) | .transfer_id? // empty' "$RESULT_ROOT/cases/transfer-none-list.stdout" 2>/dev/null | head -1 || true)"
assert_case transfer-none-status-id item-present "$(test -n "$transfer_id" && echo true || echo false)" "batch=$transfer_batch_id transfer=$transfer_id"
test -z "$transfer_id" || run_case transfer none status pb transfer status "$transfer_id" --on "$TARGET" --json

# Ordinary OpenSSH tooling exercises the managed opaque SSH stream contract.
run_case openssh auto command ssh -o BatchMode=yes -o ConnectTimeout=20 "root@$TARGET.pprbt.dev" true
pb exec "$TARGET" --transport a -- rm -f /tmp/g8-scp-upload.bin /tmp/g8-sftp-upload.bin >/dev/null 2>&1 || true
payload_hash="$(sha256sum "$RESULT_ROOT/payload/random.bin" | cut -d' ' -f1)"
for run in $(seq 1 "$REPEAT"); do
  run_case scp auto "upload-$run" scp -q -o BatchMode=yes -o ConnectTimeout=20 "$RESULT_ROOT/payload/random.bin" "root@$TARGET.pprbt.dev:/tmp/g8-scp-upload-$run.bin"
  run_case scp auto "download-$run" scp -q -o BatchMode=yes -o ConnectTimeout=20 "root@$TARGET.pprbt.dev:/tmp/g8-scp-upload-$run.bin" "$RESULT_ROOT/payload/scp-download-$run.bin"
  assert_case "scp-roundtrip-$run" sha256 "$(test "$payload_hash" = "$(sha256sum "$RESULT_ROOT/payload/scp-download-$run.bin" 2>/dev/null | cut -d' ' -f1)" && echo true || echo false)" exact
  run_case sftp auto "put-get-$run" sh -c "printf 'put $RESULT_ROOT/payload/random.bin /tmp/g8-sftp-upload-$run.bin\\nget /tmp/g8-sftp-upload-$run.bin $RESULT_ROOT/payload/sftp-download-$run.bin\\nquit\\n' | sftp -q -oBatchMode=yes -oConnectTimeout=20 root@$TARGET.pprbt.dev"
  assert_case "sftp-roundtrip-$run" sha256 "$(test "$payload_hash" = "$(sha256sum "$RESULT_ROOT/payload/sftp-download-$run.bin" 2>/dev/null | cut -d' ' -f1)" && echo true || echo false)" exact
done

# Private machine preview: browser-to-loopback HTTP/1.1, direct-only remote
# HTTP/3. The target fixture runs on Hetzner at 127.0.0.1:38142.
private_preview_name="g8-machine-private-$(date +%s)"
private_listen=39195
run_case preview private create pb preview create --machine "$TARGET" --port 38142 --listen-port "$private_listen" --detach --duration 15m --name "$private_preview_name" --json
machine_private_name="$(jq -r '.data.name // empty' "$RESULT_ROOT/cases/preview-private-create.stdout")"
machine_private_url="$(jq -r '.data.url // empty' "$RESULT_ROOT/cases/preview-private-create.stdout")"
assert_case preview-private-create identity "$(test "$machine_private_name" = "$private_preview_name" -a "$machine_private_url" = "http://127.0.0.1:$private_listen" && echo true || echo false)" "name=$machine_private_name url=$machine_private_url"
run_case preview private http curl --fail --silent --show-error --max-time 30 "http://127.0.0.1:$private_listen/http"
assert_case preview-private-http exact-body "$(test "$(cat "$RESULT_ROOT/cases/preview-private-http.stdout")" = preview-http-ok && echo true || echo false)" exact
run_case preview private sse curl --no-buffer --fail --silent --show-error --max-time 30 "http://127.0.0.1:$private_listen/sse"
assert_case preview-private-sse events "$(grep -q 'data: one' "$RESULT_ROOT/cases/preview-private-sse.stdout" && grep -q 'data: two' "$RESULT_ROOT/cases/preview-private-sse.stdout" && echo true || echo false)" exact
run_case preview private websocket /tmp/gate8-preview-ws "ws://127.0.0.1:$private_listen/ws" gate8-ws
assert_case preview-private-websocket exact-echo "$(test "$(cat "$RESULT_ROOT/cases/preview-private-websocket.stdout")" = echo:gate8-ws && echo true || echo false)" exact
dd if=/dev/urandom of="$RESULT_ROOT/payload/preview-stream.bin" bs=1048576 count=8 status=none
run_case preview private stream curl --fail --silent --show-error --max-time 45 --data-binary "@$RESULT_ROOT/payload/preview-stream.bin" "http://127.0.0.1:$private_listen/stream"
assert_case preview-private-stream sha256 "$(test "$(sha256sum "$RESULT_ROOT/payload/preview-stream.bin" | cut -d' ' -f1)" = "$(sha256sum "$RESULT_ROOT/cases/preview-private-stream.stdout" | cut -d' ' -f1)" && echo true || echo false)" exact
for run in 1 2 3 4; do run_case preview_concurrent private "$run" curl --fail --silent --show-error --max-time 30 "http://127.0.0.1:$private_listen/http" & done
wait
sudo /usr/local/sbin/paperboat-gate8-network block-udp
EXPECTED_EXIT=nonzero run_case preview private direct-loss curl --fail --silent --show-error --max-time 5 "http://127.0.0.1:$private_listen/http"
sudo /usr/local/sbin/paperboat-gate8-network allow-udp
private_recovered=false
for _ in $(seq 1 60); do if curl --fail --silent --max-time 2 "http://127.0.0.1:$private_listen/http" | grep -q preview-http-ok; then private_recovered=true; break; fi; sleep 0.5; done
assert_case preview-private-recovery restored "$private_recovered" exact
run_case preview private revoke pb preview revoke "$machine_private_name" --yes --json
assert_case preview-private-listener removed "$( ! ss -ltn | grep -q ":$private_listen " && echo true || echo false)" exact

# Local private serve and public serve lifecycle. Public is verified over H3,
# then with UDP blocked so the typed relay HTTP/2 fallback is mandatory.
mkdir -p "$RESULT_ROOT/site"
printf '<!doctype html><title>gate8</title><h1>gate8-preview</h1>\n' >"$RESULT_ROOT/site/index.html"
private_name="g8-private-$(date +%s)"
public_name="g8-public-$(date +%s)"
run_case serve private create pb serve "$RESULT_ROOT/site" --detach --duration 15m --name "$private_name" --json
run_case serve public create pb serve "$RESULT_ROOT/site" --public --detach --duration 15m --name "$public_name" --json
run_case preview none list pb preview list --json
run_case previews none list pb previews --json
private_identity="$(jq -r '.data.name // empty' "$RESULT_ROOT/cases/serve-private-create.stdout" 2>/dev/null)"
public_id="$(jq -r '..|.preview_id? // .id? // empty' "$RESULT_ROOT/cases/serve-public-create.stdout" 2>/dev/null | head -1 || true)"
private_url="$(jq -r '..|.url? // empty' "$RESULT_ROOT/cases/serve-private-create.stdout" 2>/dev/null | head -1 || true)"
public_url="$(jq -r '..|.url? // empty' "$RESULT_ROOT/cases/serve-public-create.stdout" 2>/dev/null | head -1 || true)"
assert_case serve-private-create identity "$(test "$private_identity" = "$private_name" -a -n "$private_url" && echo true || echo false)" "name=$private_identity url=$private_url"
assert_case serve-public-create identity "$(test -n "$public_id" -a -n "$public_url" && echo true || echo false)" "id=$public_id url=$public_url"
systemctl --user restart paperboat-local-daemon.service
sleep 2
assert_case serve-restart daemon-active "$(systemctl --user is-active paperboat-local-daemon.service >/dev/null 2>&1 && echo true || echo false)" exact
test -z "$private_url" || run_case preview private fetch curl --fail --silent --show-error --max-time 30 "$private_url"
public_ready=false
if test -n "$public_url"; then
  for ready_run in $(seq 1 30); do
    ready_code="$(curl --http3-only --silent --output "$RESULT_ROOT/cases/preview-public-ready-$ready_run.stdout" --write-out '%{http_code}' --max-time 5 "$public_url" 2>"$RESULT_ROOT/cases/preview-public-ready-$ready_run.stderr" || true)"
    printf '%s run=%s http3=%s\n' "$(date -u +%FT%T.%3NZ)" "$ready_run" "$ready_code" >>"$RESULT_ROOT/cases/preview-public-readiness.timeline"
    if test "$ready_code" = 200; then public_ready=true; break; fi
    sleep 0.5
  done
fi
assert_case preview-public-readiness reachable "$public_ready" "$(tail -1 "$RESULT_ROOT/cases/preview-public-readiness.timeline" 2>/dev/null || true)"
test -z "$public_url" || run_case preview public h3 curl --http3-only --fail --silent --show-error --max-time 30 "$public_url"
sudo /usr/local/sbin/paperboat-gate8-network block-udp
test -z "$public_url" || run_case preview public h2 curl --http2 --fail --silent --show-error --max-time 30 "$public_url"
sudo /usr/local/sbin/paperboat-gate8-network allow-udp
test -z "$private_identity" || run_case preview private revoke pb preview revoke "$private_identity" --yes --json
test -z "$public_id" || run_case preview public revoke pb preview revoke "$public_id" --yes --json
run_case preview none final-list pb preview list --json
assert_case preview-final-list empty "$(jq -e '(.previews // .items // []) | length == 0' "$RESULT_ROOT/cases/preview-none-final-list.stdout" >/dev/null 2>&1 && echo true || echo false)" exact

# Diagnostics and support artifacts.
run_case diagnostics none bugreport pb bugreport --record --json
run_case diagnostics none bugreport-upload pb bugreport --record --upload --json

# Seamless live path changes use the standalone authoritative runner. It waits
# for application bytes and the published standby path, records transition
# timestamps, uses forced client exit to test process ownership, and requires
# cleanup before starting the next case.
transition_result="$RESULT_ROOT/transition-matrix"
mkdir -p "$transition_result"
if RESULT_ROOT="$transition_result" TARGET="$TARGET" REPEAT="${TRANSITION_REPEAT:-3}" tools/gate8-transitions.sh >"$RESULT_ROOT/cases/transition-runner.stdout" 2>"$RESULT_ROOT/cases/transition-runner.stderr"; then
  transition_runner_pass=true
else
  transition_runner_pass=false
fi
assert_case transitions standalone-runner "$transition_runner_pass" "result=$transition_result"
if test -f "$transition_result/assertions.jsonl"; then
  while IFS= read -r assertion; do
    printf '%s\n' "$assertion" >&8
  done <"$transition_result/assertions.jsonl"
fi
assert_case transitions-cleanup udp-restored \
  "$(sudo /usr/local/sbin/paperboat-gate8-network status | grep -q '^udp_allowed$' && echo true || echo false)" exact
run_case transitions none post-ping pb ping "$TARGET" --transport a --count 1 --json

for transport in a d q w r; do
  run_case exec_eof "$transport" stdin pb exec "$TARGET" --transport "$transport" -- sh -c 'cat >/dev/null; printf eof-ok' </dev/null
  run_case exec_half_close "$transport" stdin pb exec "$TARGET" --transport "$transport" -- sh -c 'cat >/tmp/g8-half-close; printf half-close-ok' <<EOF
half-close-$transport
EOF
  run_case exec_backpressure "$transport" output pb exec "$TARGET" --transport "$transport" -- sh -c 'dd if=/dev/zero bs=1048576 count=8 2>/dev/null'
done

# Cancellation must release the daemon consumer promptly without a restart.
pb exec "$TARGET" --transport a -- sh -c 'sleep 120' >"$RESULT_ROOT/cases/cancel-auto.stdout" 2>"$RESULT_ROOT/cases/cancel-auto.stderr" &
cancel_pid=$!
sleep 2
kill -TERM "$cancel_pid" 2>/dev/null || true
wait "$cancel_pid" 2>/dev/null || true
cancel_clean=false
for _ in $(seq 1 25); do
  consumers="$(pb status "$TARGET" --json | jq -r '.machines[0].active_consumers // -1')"
  if test "$consumers" = 0; then cancel_clean=true; break; fi
  sleep 0.2
done
assert_case cancellation-auto consumer-release "$cancel_clean" "active_consumers=${consumers:-unknown}"

# Overlapping consumers share one active machine session and closing one does
# not tear down the other. The final release removes all per-machine carriers.
pb exec "$TARGET" --transport a -- sh -c 'sleep 8; printf overlap-one' >"$RESULT_ROOT/cases/overlap-one.stdout" 2>"$RESULT_ROOT/cases/overlap-one.stderr" & overlap_one=$!
pb exec "$TARGET" --transport a -- sh -c 'sleep 8; printf overlap-two' >"$RESULT_ROOT/cases/overlap-two.stdout" 2>"$RESULT_ROOT/cases/overlap-two.stderr" & overlap_two=$!
overlap_seen=false
for _ in $(seq 1 30); do
  overlap_consumers="$(pb status "$TARGET" --json | jq -r '.machines[0].active_consumers // -1')"
  if test "$overlap_consumers" -ge 2; then overlap_seen=true; break; fi
  sleep 0.2
done
assert_case overlap active-consumers "$overlap_seen" "active_consumers=${overlap_consumers:-unknown}"
wait "$overlap_one"; overlap_one_rc=$?
wait "$overlap_two"; overlap_two_rc=$?
assert_case overlap exact-output "$(test "$overlap_one_rc" = 0 -a "$overlap_two_rc" = 0 -a "$(cat "$RESULT_ROOT/cases/overlap-one.stdout")" = overlap-one -a "$(cat "$RESULT_ROOT/cases/overlap-two.stdout")" = overlap-two && echo true || echo false)" exact
idle_clean=false
for _ in $(seq 1 25); do
  status_line="$(pb status "$TARGET" --json | jq -r '.machines[0] | "\(.active_consumers // -1):\(.selected_path // "unknown")"')"
  if test "$status_line" = "0:none"; then idle_clean=true; break; fi
  sleep 0.2
done
assert_case overlap final-cleanup "$idle_clean" "$status_line"

for transport in a d q w r; do
  for run in 1 2 3; do
    run_case concurrent "$transport" "$run" pb exec "$TARGET" --transport "$transport" -- sh -c 'sleep 3; printf concurrent-ok' &
  done
  wait
done

snapshot after
run_case cleanup none remote-files pb exec "$TARGET" --transport a -- sh -c 'rm -f /tmp/g8-scp-upload-*.bin /tmp/g8-sftp-upload-*.bin /tmp/g8-half-close'

jq -n --slurpfile results "$RESULTS" --slurpfile assertions "$RESULT_ROOT/assertions.jsonl" \
  '{total:($results|length),zero_exit:($results|map(select(.exit_code==0))|length),nonzero_exit:($results|map(select(.exit_code!=0))|length),assertions:($assertions|length),failed_assertions:($assertions|map(select(.passed==false))|length),by_category:($results|group_by(.category)|map({category:.[0].category,total:length,nonzero:map(select(.exit_code!=0))|length})),failures:($results|map(select(.exit_code!=0))),assertion_failures:($assertions|map(select(.passed==false)))}' >"$RESULT_ROOT/summary.json"
printf 'RESULT_ROOT=%s\n' "$RESULT_ROOT"
cat "$RESULT_ROOT/summary.json"
failed="$(jq '.failed_assertions' "$RESULT_ROOT/summary.json")"
test "$failed" -eq 0
