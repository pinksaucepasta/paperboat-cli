#!/usr/bin/env bash

set -u
set -o pipefail

TARGET="${TARGET:-hn-byod-ready}"
RESULT_ROOT="${RESULT_ROOT:-$HOME/gate8-results/transitions-$(date -u +%Y%m%dT%H%M%SZ)}"
REPEAT="${REPEAT:-3}"
mkdir -p "$RESULT_ROOT/cases"
: >"$RESULT_ROOT/assertions.jsonl"
exec 8>>"$RESULT_ROOT/assertions.jsonl"

assert_case() {
  local id="$1" assertion="$2" passed="$3" detail="$4"
  flock 8
  jq -cn --arg id "$id" --arg assertion "$assertion" --arg detail "$detail" --argjson passed "$passed" \
    '{id:$id,assertion:$assertion,passed:$passed,detail:$detail}' >&8
  flock -u 8
}

selected_path() {
  local value
  value="$(pb status "$TARGET" --json 2>/dev/null | jq -r '.machines[0].selected_path // "none"')"
  test "$value" = direct && value=direct_quic
  test "$value" = relay && value=relay_quic
  printf '%s\n' "$value"
}

standby_path() {
  local value
  value="$(pb status "$TARGET" --json 2>/dev/null | jq -r '.machines[0].standby_path // "none"')"
  test "$value" = direct && value=direct_quic
  test "$value" = relay && value=relay_quic
  printf '%s\n' "$value"
}

wait_output() {
  local output="$1" deadline=$((SECONDS + 30))
  while ((SECONDS < deadline)); do
    test -s "$output" && return 0
    sleep 0.1
  done
  return 1
}

wait_cleanup() {
  local deadline=$((SECONDS + 10)) value
  while ((SECONDS < deadline)); do
    value="$(pb status "$TARGET" --json 2>/dev/null | jq -r '.machines[0].active_consumers // 0')"
    test "$value" = 0 && return 0
    sleep 0.1
  done
  return 1
}

assert_client_alive() {
  local id="$1" pid="$2"
  if kill -0 "$pid" 2>/dev/null; then
    assert_case "transition-$id" client-alive true running
    return 0
  fi
  assert_case "transition-$id" client-alive false "client exited before transition completed"
  return 1
}

udp_drop_packets() {
  local value
  value="$(sudo /usr/local/sbin/paperboat-gate8-network dropped-packets 2>/dev/null || true)"
  case "$value" in
    ''|*[!0-9]*) printf '0\n' ;;
    *) printf '%s\n' "$value" ;;
  esac
}

require_udp_drop() {
  local id="$1" deadline=$((SECONDS + 5)) packets=0
  while ((SECONDS < deadline)); do
    packets="$(udp_drop_packets)"
    if test "$packets" -gt 0; then
      assert_case "transition-$id" udp-fault-active true "dropped_packets=$packets"
      return 0
    fi
    sleep 0.1
  done
  assert_case "transition-$id" udp-fault-active false "dropped_packets=$packets"
  return 1
}

wait_standby() {
  local expected="$1" deadline=$((SECONDS + 30)) value
  while ((SECONDS < deadline)); do
    value="$(standby_path)"
    case ",$expected," in
      *",$value,"*) printf '%s\n' "$value"; return 0 ;;
    esac
    sleep 0.1
  done
  standby_path
  return 1
}

require_standby() {
  local id="$1" expected="$2" actual
  if actual="$(wait_standby "$expected")"; then
    assert_case "transition-$id" standby-ready true "expected=$expected actual=$actual"
    return 0
  fi
  actual="$(standby_path)"
  assert_case "transition-$id" standby-ready false "expected=$expected actual=$actual"
  return 1
}

wait_path() {
  local expected="$1" deadline=$((SECONDS + 30)) value
  while ((SECONDS < deadline)); do
    value="$(selected_path)"
    case ",$expected," in
      *",$value,"*) printf '%s\n' "$value"; return 0 ;;
    esac
    sleep 0.2
  done
  selected_path
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
  local mode="$1" id="$2" output history stop_file output_fifo
  output="$RESULT_ROOT/cases/transition-$id.output"
  history="$RESULT_ROOT/cases/transition-$id.paths"
  stop_file="$RESULT_ROOT/cases/transition-$id.stop"
  output_fifo="$RESULT_ROOT/cases/transition-$id.fifo"
  rm -f "$output_fifo"
  mkfifo "$output_fifo"
  sudo /usr/local/sbin/paperboat-gate8-network allow-udp
  awk '{command="date +%s%3N"; command | getline received; close(command); print $1, received; fflush()}' <"$output_fifo" >"$output" &
  local reader_pid=$!
  pb exec "$TARGET" --transport "$mode" -- sh -c 'i=0; while :; do printf "%s\n" "$i"; i=$((i+1)); sleep 0.2; done' >"$output_fifo" 2>"$RESULT_ROOT/cases/transition-$id.stderr" &
  local client_pid=$!
  record_path_until_stopped "$history" "$stop_file" &
  local observer_pid=$!
  local initial relay_only blocked relay_restored restored blocked_again relay_restored_again restored_again
  initial="$(wait_path direct_quic,relay_quic,wss || true)"
	if ! wait_output "$output"; then
	  assert_case "transition-$id" application-started false "no output before fault injection"
	  kill -KILL "$client_pid" 2>/dev/null || true
	  wait "$client_pid" 2>/dev/null || true
	  wait "$reader_pid" 2>/dev/null || true
	  rm -f "$output_fifo"
	  touch "$stop_file"
	  wait "$observer_pid" 2>/dev/null || true
	  return
	fi
	assert_case "transition-$id" application-started true "first byte observed"
  if test "$mode" = a; then
	if ! require_standby "$id-before-direct-failure" relay_quic,wss; then
	  kill -KILL "$client_pid" 2>/dev/null || true
	  wait "$client_pid" 2>/dev/null || true
	  wait "$reader_pid" 2>/dev/null || true
	  rm -f "$output_fifo"
	  touch "$stop_file"
	  wait "$observer_pid" 2>/dev/null || true
	  return
	fi
    sudo /usr/local/sbin/paperboat-gate8-network relay-only-udp
    require_udp_drop "$id-direct-failure" || true
    relay_only="$(wait_path relay_quic || true)"
  else
    relay_only="$initial"
  fi
	if ! require_standby "$id-before-udp-failure" wss; then
	  kill -KILL "$client_pid" 2>/dev/null || true
	  wait "$client_pid" 2>/dev/null || true
	  wait "$reader_pid" 2>/dev/null || true
	  rm -f "$output_fifo"
	  touch "$stop_file"
	  wait "$observer_pid" 2>/dev/null || true
	  return
	fi
  sudo /usr/local/sbin/paperboat-gate8-network block-udp
  require_udp_drop "$id-first-udp-failure" || true
  blocked="$(wait_path wss || true)"
  assert_client_alive "$id-after-first-udp-failure" "$client_pid" || true
  sudo /usr/local/sbin/paperboat-gate8-network relay-only-udp
  relay_restored="$(wait_path relay_quic || true)"
  if test "$mode" = a; then
    sudo /usr/local/sbin/paperboat-gate8-network allow-udp
    restored="$(wait_path direct_quic || true)"
  else
    restored="$relay_restored"
  fi
	if test "$restored" = direct_quic; then
	  required_standby=relay_quic,wss
	else
	  required_standby=wss
	fi
	if ! require_standby "$id-before-second-failure" "$required_standby"; then
	  kill -KILL "$client_pid" 2>/dev/null || true
	  wait "$client_pid" 2>/dev/null || true
	  wait "$reader_pid" 2>/dev/null || true
	  rm -f "$output_fifo"
	  touch "$stop_file"
	  wait "$observer_pid" 2>/dev/null || true
	  return
	fi
  sudo /usr/local/sbin/paperboat-gate8-network block-udp
  require_udp_drop "$id-second-udp-failure" || true
  blocked_again="$(wait_path wss || true)"
  assert_client_alive "$id-after-second-udp-failure" "$client_pid" || true
  sudo /usr/local/sbin/paperboat-gate8-network relay-only-udp
  relay_restored_again="$(wait_path relay_quic || true)"
  if test "$mode" = a; then
    sudo /usr/local/sbin/paperboat-gate8-network allow-udp
    restored_again="$(wait_path direct_quic || true)"
  else
    restored_again="$relay_restored_again"
  fi
  sudo /usr/local/sbin/paperboat-gate8-network allow-udp
  kill -KILL "$client_pid" 2>/dev/null || true
  wait "$client_pid" 2>/dev/null || true
  wait "$reader_pid" 2>/dev/null || true
  rm -f "$output_fifo"
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
  assert_case "transition-$id" path-sequence "$path_sequence" "initial=$initial relay_only=$relay_only blocked=$blocked relay_restored=$relay_restored restored=$restored blocked_again=$blocked_again relay_restored_again=$relay_restored_again restored_again=$restored_again"
  assert_case "transition-$id" continuous-output "$(awk 'NR==1{p=$1; t=$2; next}{if($1!=p+1 || $2<t || $2-t>2000)exit 1;p=$1;t=$2}END{if(NR<10)exit 1}' "$output" && echo true || echo false)" "lines=$(wc -l <"$output")"
  if ! wait_cleanup; then
    assert_case "transition-$id" case-cleanup false "active_consumers=$(pb status "$TARGET" --json 2>/dev/null | jq -r '.machines[0].active_consumers // 0')"
  else
    assert_case "transition-$id" case-cleanup true exact
  fi
}

trap 'sudo /usr/local/sbin/paperboat-gate8-network allow-udp >/dev/null 2>&1 || true' EXIT INT TERM
for run in $(seq 1 "$REPEAT"); do
  transition_case a "auto-$run"
  transition_case r "relay-$run"
done
deadline=$((SECONDS+3))
while ((SECONDS < deadline)) && test "$(pb status "$TARGET" --json 2>/dev/null | jq -r '.machines[0].active_consumers')" != 0; do sleep 0.1; done
assert_case transitions cleanup "$(test "$(pb status "$TARGET" --json 2>/dev/null | jq -r '.machines[0].active_consumers')" = 0 && echo true || echo false)" exact
jq -s '{assertions:length,passed:map(select(.passed))|length,failed:map(select(.passed|not))}' "$RESULT_ROOT/assertions.jsonl" >"$RESULT_ROOT/summary.json"
printf 'RESULT_ROOT=%s\n' "$RESULT_ROOT"
cat "$RESULT_ROOT/summary.json"
test "$(jq '.failed|length' "$RESULT_ROOT/summary.json")" = 0
