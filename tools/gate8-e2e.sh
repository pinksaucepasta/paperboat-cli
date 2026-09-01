#!/usr/bin/env bash

set -u
set -o pipefail

TARGET="${TARGET:-hn-byod-ready}"
RESULT_ROOT="${RESULT_ROOT:-$HOME/gate8-results/$(date -u +%Y%m%dT%H%M%SZ)}"
REPEAT="${REPEAT:-5}"
TEST_TIMEOUT="${TEST_TIMEOUT:-45}"
SCRIPT_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
TERMINAL_READY="${GATE8_TERMINAL_READY:-$SCRIPT_ROOT/gate8-terminal-ready.py}"
TRANSITION_RUNNER="${GATE8_TRANSITION_RUNNER:-$SCRIPT_ROOT/gate8-transitions.sh}"
case "$RESULT_ROOT" in
  "$HOME"/*) ;;
  *) printf 'Gate 8 evidence must be stored under %s: %s\n' "$HOME" "$RESULT_ROOT" >&2; exit 2 ;;
esac
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
  # GNU timeout owns a process group unless --foreground is used. Keep the
  # command and descendants in that group so timed-out SSH ProxyCommands do
  # not retain daemon transport leases after their parent exits.
  timeout --signal=TERM --kill-after=5 "$TEST_TIMEOUT" "$@" >"$stdout_file" 2>"$stderr_file"
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

cleanup_network() {
  local pid
  for pid in "${forward_pid:-}"; do
    test -z "$pid" || kill -TERM "$pid" 2>/dev/null || true
  done
  sudo /usr/local/sbin/paperboat-gate8-network allow-udp >/dev/null 2>&1 || true
}
trap cleanup_network EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for required in pb jq timeout flock script ssh scp sftp rsync git curl sudo python3 sha256sum ss pgrep cmp; do
  command -v "$required" >/dev/null || { printf 'missing required command: %s\n' "$required" >&2; exit 2; }
done
test -r "$TERMINAL_READY" || { printf 'missing terminal fixture: %s\n' "$TERMINAL_READY" >&2; exit 2; }
test -x "$TRANSITION_RUNNER" || { printf 'missing transition runner: %s\n' "$TRANSITION_RUNNER" >&2; exit 2; }
sudo -n /usr/local/sbin/paperboat-gate8-network allow-udp
snapshot before

# Installed artifact and service preflight. Expected hashes are supplied by
# the matched build/deploy step; an unset value is an acceptance failure.
dadape_hash="$(sha256sum "$(command -v pb)" | cut -d' ' -f1)"
assert_case preflight installed-hash "$(test -n "${EXPECTED_DADAPE_SHA256:-}" -a "$dadape_hash" = "${EXPECTED_DADAPE_SHA256:-missing}" && echo true || echo false)" "actual=$dadape_hash expected=${EXPECTED_DADAPE_SHA256:-unset}"
assert_case preflight user-daemon "$(systemctl --user is-active paperboat-local-daemon.service >/dev/null 2>&1 && echo true || echo false)" exact
assert_case preflight host-services "$(systemctl is-active paperboat-runtime-host.service paperboat-runtime-privileged.service 2>/dev/null | awk 'BEGIN{ok=1} $0!="active"{ok=0} END{print ok ? "true" : "false"}')" exact
source_evidence="${GATE8_SOURCE_EVIDENCE:-$HOME/gate8-source-evidence.txt}"
source_evidence_hash="$(sha256sum "$source_evidence" 2>/dev/null | cut -d' ' -f1 || true)"
assert_case preflight source-evidence "$(test -n "${EXPECTED_SOURCE_EVIDENCE_SHA256:-}" -a "$source_evidence_hash" = "${EXPECTED_SOURCE_EVIDENCE_SHA256:-missing}" && grep -q '^result=PASS$' "$source_evidence" && echo true || echo false)" "actual=$source_evidence_hash expected=${EXPECTED_SOURCE_EVIDENCE_SHA256:-unset}"
deployment_evidence="${GATE8_DEPLOYMENT_EVIDENCE:-$HOME/gate8-deployment-evidence.txt}"
deployment_evidence_hash="$(sha256sum "$deployment_evidence" 2>/dev/null | cut -d' ' -f1 || true)"
assert_case preflight deployment-evidence "$(test -n "${EXPECTED_DEPLOYMENT_EVIDENCE_SHA256:-}" -a "$deployment_evidence_hash" = "${EXPECTED_DEPLOYMENT_EVIDENCE_SHA256:-missing}" && grep -q '^result=PASS$' "$deployment_evidence" && echo true || echo false)" "actual=$deployment_evidence_hash expected=${EXPECTED_DEPLOYMENT_EVIDENCE_SHA256:-unset}"

run_case inventory none environments pb environments --json
run_case inventory none machine-list pb machine list --json
run_case inventory none status pb status "$TARGET" --json
run_case inventory none status-repeat pb status "$TARGET" --json
offline_target="$(jq -r --arg target "$TARGET" '.machines[] | select(.online == false and .alias != $target) | .alias' "$RESULT_ROOT/cases/inventory-none-machine-list.stdout" | head -1)"
run_case readiness none wait-runtime pb wait "$TARGET" --for runtime --timeout 30s --json
run_case readiness none wait-transport pb wait "$TARGET" --for transport --timeout 30s --json
run_case readiness none wait-ssh pb wait "$TARGET" --for ssh --timeout 30s --json
test -z "$offline_target" || EXPECTED_EXIT=nonzero run_case readiness none wait-offline pb wait "$offline_target" --for runtime --timeout 1s --json
run_case diagnostics none doctor-local pb doctor --json
EXPECTED_EXIT=0or1 run_case diagnostics none doctor-target pb doctor "$TARGET" --json
run_case diagnostics none doctor-local-repeat pb doctor --json
EXPECTED_EXIT=0or1 run_case diagnostics none doctor-target-repeat pb doctor "$TARGET" --json
doctor_target_rc="$(jq -r 'select(.id=="diagnostics-none-doctor-target") | .exit_code' "$RESULTS")"
doctor_target_overall="$(jq -r '.overall // empty' "$RESULT_ROOT/cases/diagnostics-none-doctor-target.stdout")"
assert_case diagnostics-none-doctor-target structured-result \
  "$(test "$doctor_target_rc" = 0 -o "$doctor_target_rc" = 1 && test -n "$doctor_target_overall" && echo true || echo false)" \
  "exit=$doctor_target_rc overall=$doctor_target_overall"
run_case ssh none doctor pb ssh doctor "$TARGET"
run_case ssh auto default-setup-user pb ssh "$TARGET" -- true
run_case ssh auto user-at-machine pb ssh "root@$TARGET" -- true
run_case config none show pb config show --json
run_case config none status pb config status "$TARGET" --json
isolated_config="$RESULT_ROOT/isolated-config.json"
active_server="$(jq -r '.server_url' "$RESULT_ROOT/cases/config-none-show.stdout")"
run_case config none isolated-set pb --config "$isolated_config" config set server "$active_server"
run_case config none isolated-show pb --config "$isolated_config" config show --json
assert_case config-isolated-show server \
  "$(jq -e --arg server "$active_server" '.server_url == $server' "$RESULT_ROOT/cases/config-none-isolated-show.stdout" >/dev/null 2>&1 && echo true || echo false)" exact
run_case machine none pending-trust pb machine pending --json
target_workspace="$(jq -er --arg target "$TARGET" '.machines[] | select(.alias == $target) | .workspace_root | select(type == "string" and startswith("/"))' "$RESULT_ROOT/status-before.json")"
run_case codex auto version pb codex "$TARGET" --path "$target_workspace" -- --version
assert_case codex-auto-version recognizable \
  "$(grep -Eq '^codex-cli [0-9]+\.[0-9]+\.[0-9]+' "$RESULT_ROOT/cases/codex-auto-version.stdout" && echo true || echo false)" exact

for transport in a d q w r; do
  for run in $(seq 1 "$REPEAT"); do
    run_case ping "$transport" "$run" pb ping "$TARGET" --transport "$transport" --count 3 --json
    ping_file="$RESULT_ROOT/cases/ping-${transport}-${run}.stdout"
    assert_case "ping-$transport-$run" zero-loss \
      "$(jq -e '(.lost // .packet_loss // 0) == 0' "$ping_file" >/dev/null 2>&1 && echo true || echo false)" exact
  done
done

TEST_TIMEOUT=120 run_case exec auto silent-90 pb exec "$TARGET" --transport a -- sh -c 'sleep 90; printf silent-exec-ok'
assert_case exec-auto-silent-90 canary \
  "$(test "$(cat "$RESULT_ROOT/cases/exec-auto-silent-90.stdout")" = silent-exec-ok && echo true || echo false)" exact

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
  run_case terminal "$transport" create python3 "$TERMINAL_READY" "$TARGET" "$transport" "$terminal_name" "terminal-$transport" "$RESULT_ROOT/cases/terminal-${transport}-pty.raw"
  terminal_stdout="$RESULT_ROOT/cases/terminal-${transport}-pty.raw"
  assert_case "terminal-${transport}-create" canary \
    "$(grep -Eq 'GATE8_READY:[0-9]+' "$terminal_stdout" && echo true || echo false)" \
    "computed shell canary"
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
transfer_receipt="$(jq -r '.. | objects | select(.batch_id? == $batch) | .receipt_path? // empty' --arg batch "$transfer_batch_id" "$RESULT_ROOT/cases/transfer-none-send-binary.stdout" | head -1)"
transfer_remote_hash=""
if test -n "$transfer_receipt"; then
  transfer_remote_hash="$(pb exec "$TARGET" --transport a -- sh -c 'inbox=$(pb inbox path); sha256sum "$(dirname "$inbox")/$1"' sh "$transfer_receipt" 2>/dev/null | awk '{print $1}')"
fi
assert_case transfer-none-send-binary receipt-sha256 \
  "$(test -n "$transfer_receipt" -a "$transfer_remote_hash" = "$(sha256sum "$RESULT_ROOT/payload/random.bin" | cut -d' ' -f1)" && echo true || echo false)" \
  "receipt=$transfer_receipt remote_sha256=${transfer_remote_hash:-missing}"

# Ordinary OpenSSH tooling exercises the managed opaque SSH stream contract.
run_case openssh auto command ssh -o BatchMode=yes -o ConnectTimeout=20 "root@$TARGET.pprbt" true
pb exec "$TARGET" --transport a -- rm -f /tmp/g8-scp-upload.bin /tmp/g8-sftp-upload.bin >/dev/null 2>&1 || true
payload_hash="$(sha256sum "$RESULT_ROOT/payload/random.bin" | cut -d' ' -f1)"
for run in $(seq 1 "$REPEAT"); do
  run_case scp auto "upload-$run" scp -q -o BatchMode=yes -o ConnectTimeout=20 "$RESULT_ROOT/payload/random.bin" "root@$TARGET.pprbt:/tmp/g8-scp-upload-$run.bin"
  run_case scp auto "download-$run" scp -q -o BatchMode=yes -o ConnectTimeout=20 "root@$TARGET.pprbt:/tmp/g8-scp-upload-$run.bin" "$RESULT_ROOT/payload/scp-download-$run.bin"
  assert_case "scp-roundtrip-$run" sha256 "$(test "$payload_hash" = "$(sha256sum "$RESULT_ROOT/payload/scp-download-$run.bin" 2>/dev/null | cut -d' ' -f1)" && echo true || echo false)" exact
  run_case sftp auto "put-get-$run" sh -c "printf 'put $RESULT_ROOT/payload/random.bin /tmp/g8-sftp-upload-$run.bin\\nget /tmp/g8-sftp-upload-$run.bin $RESULT_ROOT/payload/sftp-download-$run.bin\\nquit\\n' | sftp -q -oBatchMode=yes -oConnectTimeout=20 root@$TARGET.pprbt"
  assert_case "sftp-roundtrip-$run" sha256 "$(test "$payload_hash" = "$(sha256sum "$RESULT_ROOT/payload/sftp-download-$run.bin" 2>/dev/null | cut -d' ' -f1)" && echo true || echo false)" exact
done


# The managed OpenSSH configuration must remain compatible with common tools.
printf 'gate8-rsync\n' >"$RESULT_ROOT/payload/rsync.txt"
run_case rsync auto upload rsync -a -e "ssh -o BatchMode=yes -o ConnectTimeout=20" "$RESULT_ROOT/payload/rsync.txt" "root@$TARGET.pprbt:/tmp/g8-rsync.txt"
run_case rsync auto download rsync -a -e "ssh -o BatchMode=yes -o ConnectTimeout=20" "root@$TARGET.pprbt:/tmp/g8-rsync.txt" "$RESULT_ROOT/payload/rsync-download.txt"
assert_case rsync-auto-roundtrip exact \
  "$(cmp -s "$RESULT_ROOT/payload/rsync.txt" "$RESULT_ROOT/payload/rsync-download.txt" && echo true || echo false)" exact
run_case git auto prepare ssh -o BatchMode=yes -o ConnectTimeout=20 "root@$TARGET.pprbt" \
  'set -eu; rm -rf /tmp/g8.git /tmp/g8-work; git init -q /tmp/g8-work; cd /tmp/g8-work; git config user.name Gate8; git config user.email gate8@paperboat.test; printf gate8-git >canary.txt; git add canary.txt; git commit -qm gate8; git clone -q --bare . /tmp/g8.git'
GIT_SSH_COMMAND='ssh -o BatchMode=yes -o ConnectTimeout=20' run_case git auto clone git clone -q "root@$TARGET.pprbt:/tmp/g8.git" "$RESULT_ROOT/payload/git-clone"
assert_case git-auto-clone canary \
  "$(test "$(cat "$RESULT_ROOT/payload/git-clone/canary.txt" 2>/dev/null)" = gate8-git && echo true || echo false)" exact

forward_port=39218
ssh -o BatchMode=yes -o ConnectTimeout=20 -o ExitOnForwardFailure=yes -N -L "127.0.0.1:$forward_port:127.0.0.1:38142" "root@$TARGET.pprbt" >"$RESULT_ROOT/cases/forward-auto-local.stdout" 2>"$RESULT_ROOT/cases/forward-auto-local.stderr" &
forward_pid=$!
forward_ready=false
forward_deadline=$((SECONDS + 20))
while ((SECONDS < forward_deadline)); do
  if test "$(curl --fail --silent --max-time 1 "http://127.0.0.1:$forward_port/http" 2>/dev/null || true)" = preview-http-ok; then
    forward_ready=true
    break
  fi
  sleep 0.2
done
kill -TERM "$forward_pid" 2>/dev/null || true
wait "$forward_pid" 2>/dev/null || true
assert_case forward-auto-local reachable "$forward_ready" exact

# Diagnostics and support artifacts.
run_case diagnostics none bugreport pb bugreport --record --json </dev/null
run_case diagnostics none bugreport-upload pb bugreport --record --upload --json </dev/null
TEST_TIMEOUT=10 EXPECTED_EXIT=nonzero run_case diagnostics none bugreport-upload-failure pb --server https://api.pprbt.dev:1 bugreport --record --upload --json </dev/null

# Seamless live path changes use the standalone authoritative runner. It waits
# for application bytes and the published standby path, records transition
# timestamps, uses forced client exit to test process ownership, and requires
# cleanup before starting the next case.
transition_result="$RESULT_ROOT/transition-matrix"
mkdir -p "$transition_result"
if RESULT_ROOT="$transition_result" TARGET="$TARGET" REPEAT="${TRANSITION_REPEAT:-3}" "$TRANSITION_RUNNER" >"$RESULT_ROOT/cases/transition-runner.stdout" 2>"$RESULT_ROOT/cases/transition-runner.stderr"; then
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
