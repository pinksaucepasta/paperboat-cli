#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Destructive operations are deliberately gated by an exact release argument.
# With --snapshot-only this script only reads the target. The mutating path
# downloads the official immutable asset before it contacts the VM, then uses
# the supported installer and `pb setup` lifecycle path without deleting local
# state.

readonly SSH_KEY=/Users/pujan.pm/keys/def.pem
readonly SSH_TARGET=root@157.180.74.88
readonly METADATA_URL=https://get.pprbt.dev/current.json
readonly INSTALLER_URL=https://get.pprbt.dev/install
readonly RELEASE_REPOSITORY=pinksaucepasta/paperboat-cli
readonly MACHINE_NAME=hetzner-env
readonly SSH_PORT=22

usage() {
  printf '%s\n' \
    "Usage: $0 EXPECTED_RELEASE_VERSION" \
    "       $0 --snapshot-only" \
    "" \
    "The release argument is mandatory for any install, setup, restart, or" \
    "assertion that mutates the Hetzner VM. It must exactly match current.json."
}

die() {
  printf 'accept-linux: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

require_command ssh

if [[ ! -r "$SSH_KEY" ]]; then
  die "SSH key is not readable: $SSH_KEY"
fi

remote() {
  ssh -o BatchMode=yes -o ConnectTimeout=10 -i "$SSH_KEY" "$SSH_TARGET" bash -s -- "$@"
}

if [[ "${1:-}" == --snapshot-only ]]; then
  [[ "$#" -eq 1 ]] || { usage >&2; exit 2; }
  remote "" "" "" "" "$METADATA_URL" "$INSTALLER_URL" "$MACHINE_NAME" "$SSH_PORT" snapshot <<'REMOTE'
set -Eeuo pipefail

state_root=/root/.local/state/paperboat/runtime
pb=/usr/local/libexec/paperboat/pb

read_value() {
  local expression=$1
  local path=$2
  jq -er "$expression" "$path" 2>/dev/null || printf 'missing'
}

capture_identity() {
  local machine_identity="$state_root/machine-identity.json"
  local registration="$state_root/machine-registration.json"
  local runtime_identity="$state_root/runtime-identity.json"

  if [[ -f "$machine_identity" ]]; then
    machine_identity_sha=$(sha256sum "$machine_identity" | awk '{print $1}')
    machine_identity_key_id=$(read_value '.key_id' "$machine_identity")
  else
    machine_identity_sha=missing
    machine_identity_key_id=missing
  fi
  if [[ -f "$registration" ]]; then
    registration_machine_id=$(read_value '.machine_id' "$registration")
    registration_environment_id=$(read_value '.environment_id' "$registration")
    registration_generation=$(read_value '.installation_generation' "$registration")
    registration_public_key=$(read_value '.public_identity_key' "$registration")
    registration_setup_mode=$(read_value '.setup_mode' "$registration")
    registration_server_url=$(read_value '.server_url' "$registration")
  else
    registration_machine_id=missing
    registration_environment_id=missing
    registration_generation=missing
    registration_public_key=missing
    registration_setup_mode=missing
    registration_server_url=missing
  fi
  if [[ -f "$runtime_identity" ]]; then
    runtime_machine_id=$(read_value '.machine_id' "$runtime_identity")
    runtime_environment_id=$(read_value '.environment_id' "$runtime_identity")
    runtime_helper_id=$(read_value '.helper_id' "$runtime_identity")
  else
    runtime_machine_id=missing
    runtime_environment_id=missing
    runtime_helper_id=missing
  fi
}

print_identity() {
  local prefix=$1
  printf '%s_machine_identity_sha256=%s\n' "$prefix" "$machine_identity_sha"
  printf '%s_machine_identity_key_id=%s\n' "$prefix" "$machine_identity_key_id"
  printf '%s_registration_machine_id=%s\n' "$prefix" "$registration_machine_id"
  printf '%s_registration_environment_id=%s\n' "$prefix" "$registration_environment_id"
  printf '%s_registration_generation=%s\n' "$prefix" "$registration_generation"
  printf '%s_registration_public_identity_key=%s\n' "$prefix" "$registration_public_key"
  printf '%s_registration_setup_mode=%s\n' "$prefix" "$registration_setup_mode"
  printf '%s_registration_server_url=%s\n' "$prefix" "$registration_server_url"
  printf '%s_runtime_machine_id=%s\n' "$prefix" "$runtime_machine_id"
  printf '%s_runtime_environment_id=%s\n' "$prefix" "$runtime_environment_id"
  printf '%s_runtime_helper_id=%s\n' "$prefix" "$runtime_helper_id"
}

resume_summary() {
  local path="$state_root/bootstrap-resume.json"
  if [[ -f "$path" ]]; then
    jq -c '{schema,server_url,display_name,setup_mode,authenticated_setup,setup_operation_id,expected_user_machine_id,expected_installation_generation,material:(.material | if type == "object" then {user_machine_id,environment_id,helper_id,expires_at,installation_generation,setup_mode,helper_listen_address,artifact_version:(.artifact.version // "")} else null end)}' "$path" 2>/dev/null || printf 'invalid'
  else
    printf 'absent'
  fi
}

one_line() {
  tr '\r\n' ' ' | sed 's/[[:space:]][[:space:]]*/ /g'
}

observe() {
  local label=$1
  shift
  local output
  if output=$("$@" 2>&1); then
    printf '%s=%s\n' "$label" "$(printf '%s' "$output" | one_line)"
  else
    printf '%s_error=%s\n' "$label" "$(printf '%s' "$output" | one_line)"
  fi
}

listen_address() {
  local descriptor="$state_root/runtime/worker-local.json"
  local resume="$state_root/bootstrap-resume.json"
  if [[ -f "$descriptor" ]]; then
    read_value '.listen_address' "$descriptor"
    return
  fi
  if [[ -f "$resume" ]]; then
    jq -er '.material.helper_listen_address' "$resume" 2>/dev/null || true
  fi
}

snapshot() {
  local label=$1
  printf 'snapshot_label=%s\n' "$label"
  printf 'snapshot_utc='; date -u +%Y-%m-%dT%H:%M:%SZ
  printf 'hostname='; hostname
  printf 'os='; uname -srm
  capture_identity
  print_identity "$label"
  printf '%s_resume_summary=' "$label"; resume_summary
  for path in "$pb" /root/.local/bin/pb /usr/local/bin/pb; do
    if [[ -x "$path" ]]; then
      printf '%s_binary=%s\n' "$label" "$path"
      printf '%s_binary_sha256=' "$label"; sha256sum "$path" | awk '{print $1}'
      observe "${label}_version_$(basename "$path")" "$path" --version
    else
      printf '%s_binary=%s absent\n' "$label" "$path"
    fi
  done
  for unit in paperboat-hostd.service paperboat-updated.service; do
    printf '%s_unit_%s_enabled=' "$label" "$unit"; systemctl is-enabled "$unit" 2>&1 || true
    printf '%s_unit_%s_active=' "$label" "$unit"; systemctl is-active "$unit" 2>&1 || true
  done
  for socket in /run/paperboat-hostd/hostd.sock /run/paperboat-updated/control.sock; do
    if [[ -S "$socket" ]]; then
      printf '%s_socket=%s present\n' "$label" "$socket"
    else
      printf '%s_socket=%s absent\n' "$label" "$socket"
    fi
  done
  local address
  address=$(listen_address || true)
  printf '%s_health_address=%s\n' "$label" "${address:-absent}"
  if [[ "$address" == 127.0.0.1:* || "$address" == '[::1]:'* ]]; then
    observe "${label}_healthz" curl --noproxy '*' --fail --silent --show-error --max-time 5 "http://${address}/healthz"
  elif [[ -n "$address" ]]; then
    printf '%s_healthz_error=health address is not literal loopback\n' "$label"
  fi
  if [[ -x "$pb" ]]; then
    observe "${label}_update_check_json" "$pb" update check --json
    observe "${label}_update_status_json" "$pb" update status --json
    observe "${label}_doctor_json" "$pb" doctor --json
  fi
}

snapshot before-read-only
REMOTE
  exit 0
fi

[[ "$#" -eq 1 ]] || { usage >&2; exit 2; }
expected_version=$1
[[ "$expected_version" =~ ^20[0-9]{2}\.[0-9]{2}\.[0-9]{2}\.[0-9]+$ ]] || die "invalid release version: $expected_version"
[[ "$MACHINE_NAME" =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid machine name"
[[ "$SSH_PORT" =~ ^[1-9][0-9]{0,4}$ ]] || die "invalid SSH port"

for command in curl jq sha256sum wc awk sed mktemp ssh; do
  require_command "$command"
done

temporary=$(mktemp -d "${TMPDIR:-/tmp}/paperboat-linux-accept.XXXXXX")
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT HUP INT TERM

metadata="$temporary/current.json"
asset="$temporary/pb-linux-amd64"
curl --fail --location --silent --show-error --retry 5 --connect-timeout 15 --max-time 120 \
  --proto '=https' --proto-redir '=https' --tlsv1.2 "$METADATA_URL" -o "$metadata"

asset_url=$(jq -er --arg version "$expected_version" --arg repository "$RELEASE_REPOSITORY" \
  '.assets["pb-linux-amd64"].url' "$metadata")
expected_sha=$(jq -er '.assets["pb-linux-amd64"].sha256' "$metadata")
expected_length=$(jq -er '.assets["pb-linux-amd64"].length | tostring' "$metadata")
expected_url="https://github.com/${RELEASE_REPOSITORY}/releases/download/${expected_version}/pb-linux-amd64"
jq -e --arg version "$expected_version" --arg repository "$RELEASE_REPOSITORY" --arg url "$expected_url" '
  .schema == "paperboat.release-current/v1" and
  .version == $version and
  .repository == $repository and
  (.assets | type == "object") and
  (.assets["pb-linux-amd64"] | type == "object") and
  .assets["pb-linux-amd64"].platform == "linux" and
  .assets["pb-linux-amd64"].architecture == "amd64" and
  .assets["pb-linux-amd64"].format == "elf" and
  .assets["pb-linux-amd64"].url == $url and
  (.assets["pb-linux-amd64"].sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
  (.assets["pb-linux-amd64"].length | type == "number" and . >= 1)
' "$metadata" >/dev/null || die "current.json is not the requested official release"
[[ "$asset_url" == "$expected_url" ]] || die "release URL is not the immutable GitHub asset"
[[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]] || die "current.json contains an invalid SHA-256"
[[ "$expected_length" =~ ^[1-9][0-9]*$ ]] || die "current.json contains an invalid asset length"

printf 'official_release_version=%s\n' "$expected_version"
printf 'official_asset_url=%s\n' "$asset_url"
printf 'official_asset_sha256=%s\n' "$expected_sha"
printf 'official_asset_length=%s\n' "$expected_length"

# Download and verify the immutable bytes locally before any VM mutation. The
# remote installer repeats these checks before replacing its canonical binary.
curl --fail --location --silent --show-error --retry 5 --connect-timeout 15 --max-time 900 \
  --proto '=https' --proto-redir '=https' --tlsv1.2 "$asset_url" -o "$asset"
actual_length=$(wc -c < "$asset" | tr -d '[:space:]')
actual_sha=$(sha256sum "$asset" | awk '{print $1}')
[[ "$actual_length" == "$expected_length" ]] || die "official asset length mismatch: $actual_length != $expected_length"
[[ "$actual_sha" == "$expected_sha" ]] || die "official asset SHA-256 mismatch: $actual_sha != $expected_sha"
printf 'preflight_asset_sha256=%s\n' "$actual_sha"
printf 'preflight_asset_length=%s\n' "$actual_length"

remote "$expected_version" "$expected_sha" "$expected_length" "$asset_url" "$METADATA_URL" "$INSTALLER_URL" "$MACHINE_NAME" "$SSH_PORT" install <<'REMOTE'
set -Eeuo pipefail

expected_version=$1
expected_sha=$2
expected_length=$3
expected_url=$4
metadata_url=$5
installer_url=$6
machine_name=$7
ssh_port=$8
mode=$9

state_root=/root/.local/state/paperboat/runtime
pb=/usr/local/libexec/paperboat/pb
install_dir=/usr/local/libexec/paperboat
readonly hostd_socket=/run/paperboat-hostd/hostd.sock
readonly updater_socket=/run/paperboat-updated/control.sock

die() {
  printf 'accept-linux(remote): %s\n' "$*" >&2
  exit 1
}

read_value() {
  local expression=$1
  local path=$2
  jq -er "$expression" "$path" 2>/dev/null || printf 'missing'
}

capture_identity() {
  local machine_identity="$state_root/machine-identity.json"
  local registration="$state_root/machine-registration.json"
  local runtime_identity="$state_root/runtime-identity.json"

  if [[ -f "$machine_identity" ]]; then
    machine_identity_sha=$(sha256sum "$machine_identity" | awk '{print $1}')
    machine_identity_key_id=$(read_value '.key_id' "$machine_identity")
  else
    machine_identity_sha=missing
    machine_identity_key_id=missing
  fi
  if [[ -f "$registration" ]]; then
    registration_machine_id=$(read_value '.machine_id' "$registration")
    registration_environment_id=$(read_value '.environment_id' "$registration")
    registration_generation=$(read_value '.installation_generation' "$registration")
    registration_public_key=$(read_value '.public_identity_key' "$registration")
    registration_setup_mode=$(read_value '.setup_mode' "$registration")
    registration_server_url=$(read_value '.server_url' "$registration")
  else
    registration_machine_id=missing
    registration_environment_id=missing
    registration_generation=missing
    registration_public_key=missing
    registration_setup_mode=missing
    registration_server_url=missing
  fi
  if [[ -f "$runtime_identity" ]]; then
    runtime_machine_id=$(read_value '.machine_id' "$runtime_identity")
    runtime_environment_id=$(read_value '.environment_id' "$runtime_identity")
    runtime_helper_id=$(read_value '.helper_id' "$runtime_identity")
  else
    runtime_machine_id=missing
    runtime_environment_id=missing
    runtime_helper_id=missing
  fi
}

print_identity() {
  local prefix=$1
  printf '%s_machine_identity_sha256=%s\n' "$prefix" "$machine_identity_sha"
  printf '%s_machine_identity_key_id=%s\n' "$prefix" "$machine_identity_key_id"
  printf '%s_registration_machine_id=%s\n' "$prefix" "$registration_machine_id"
  printf '%s_registration_environment_id=%s\n' "$prefix" "$registration_environment_id"
  printf '%s_registration_generation=%s\n' "$prefix" "$registration_generation"
  printf '%s_registration_public_identity_key=%s\n' "$prefix" "$registration_public_key"
  printf '%s_registration_setup_mode=%s\n' "$prefix" "$registration_setup_mode"
  printf '%s_registration_server_url=%s\n' "$prefix" "$registration_server_url"
  printf '%s_runtime_machine_id=%s\n' "$prefix" "$runtime_machine_id"
  printf '%s_runtime_environment_id=%s\n' "$prefix" "$runtime_environment_id"
  printf '%s_runtime_helper_id=%s\n' "$prefix" "$runtime_helper_id"
}

resume_summary() {
  local path="$state_root/bootstrap-resume.json"
  if [[ -f "$path" ]]; then
    jq -c '{schema,server_url,display_name,setup_mode,authenticated_setup,setup_operation_id,expected_user_machine_id,expected_installation_generation,material:(.material | if type == "object" then {user_machine_id,environment_id,helper_id,expires_at,installation_generation,setup_mode,helper_listen_address,artifact_version:(.artifact.version // "")} else null end)}' "$path" 2>/dev/null || printf 'invalid'
  else
    printf 'absent'
  fi
}

one_line() {
  tr '\r\n' ' ' | sed 's/[[:space:]][[:space:]]*/ /g'
}

observe() {
  local label=$1
  shift
  local output
  if output=$("$@" 2>&1); then
    printf '%s=%s\n' "$label" "$(printf '%s' "$output" | one_line)"
  else
    printf '%s_error=%s\n' "$label" "$(printf '%s' "$output" | one_line)"
  fi
}

listen_address() {
  local descriptor="$state_root/runtime/worker-local.json"
  local resume="$state_root/bootstrap-resume.json"
  if [[ -f "$descriptor" ]]; then
    read_value '.listen_address' "$descriptor"
    return
  fi
  if [[ -f "$resume" ]]; then
    jq -er '.material.helper_listen_address' "$resume" 2>/dev/null || true
  fi
}

snapshot() {
  local label=$1
  printf 'snapshot_label=%s\n' "$label"
  printf 'snapshot_utc='; date -u +%Y-%m-%dT%H:%M:%SZ
  printf 'hostname='; hostname
  printf 'os='; uname -srm
  capture_identity
  print_identity "$label"
  printf '%s_resume_summary=' "$label"; resume_summary
  for path in "$pb" /root/.local/bin/pb /usr/local/bin/pb; do
    if [[ -x "$path" ]]; then
      printf '%s_binary=%s\n' "$label" "$path"
      printf '%s_binary_sha256=' "$label"; sha256sum "$path" | awk '{print $1}'
      observe "${label}_version_$(basename "$path")" "$path" --version
    else
      printf '%s_binary=%s absent\n' "$label" "$path"
    fi
  done
  for unit in paperboat-hostd.service paperboat-updated.service; do
    printf '%s_unit_%s_enabled=' "$label" "$unit"; systemctl is-enabled "$unit" 2>&1 || true
    printf '%s_unit_%s_active=' "$label" "$unit"; systemctl is-active "$unit" 2>&1 || true
  done
  for socket in "$hostd_socket" "$updater_socket"; do
    if [[ -S "$socket" ]]; then
      printf '%s_socket=%s present\n' "$label" "$socket"
    else
      printf '%s_socket=%s absent\n' "$label" "$socket"
    fi
  done
  local address
  address=$(listen_address || true)
  printf '%s_health_address=%s\n' "$label" "${address:-absent}"
  if [[ -n "$address" ]]; then
    observe "${label}_healthz" curl --noproxy '*' --fail --silent --show-error --max-time 5 "http://${address}/healthz"
  fi
  if [[ -x "$pb" ]]; then
    observe "${label}_update_check_json" "$pb" update check --json
    observe "${label}_update_status_json" "$pb" update status --json
    observe "${label}_doctor_json" "$pb" doctor --json
  fi
}

verify_identity() {
  capture_identity
  print_identity after
  [[ "$machine_identity_sha" == "$before_machine_identity_sha" ]] || die "machine identity file changed"
  [[ "$machine_identity_key_id" == "$before_machine_identity_key_id" ]] || die "machine identity key binding changed"
  [[ "$registration_machine_id" == "$before_registration_machine_id" ]] || die "machine ID changed"
  [[ "$registration_environment_id" == "$before_registration_environment_id" ]] || die "environment binding changed"
  [[ "$registration_generation" == "$before_registration_generation" ]] || die "installation generation changed"
  [[ "$registration_public_key" == "$before_registration_public_key" ]] || die "public identity key changed"
  [[ "$registration_setup_mode" == "$before_registration_setup_mode" ]] || die "setup mode changed"
  [[ "$registration_server_url" == "$before_registration_server_url" ]] || die "server binding changed"
  [[ "$runtime_machine_id" == "$before_runtime_machine_id" ]] || die "runtime machine ID changed"
  [[ "$runtime_environment_id" == "$before_runtime_environment_id" ]] || die "runtime environment ID changed"
  if [[ "$runtime_helper_id" != "$before_runtime_helper_id" ]]; then
    printf 'identity_note=runtime helper ID rotated (%s -> %s); stable machine/account binding is unchanged\n' "$before_runtime_helper_id" "$runtime_helper_id"
  fi
  printf 'identity_preserved=true\n'
}

verify() {
  local label=$1
  printf 'verification_label=%s\n' "$label"
  [[ -x "$pb" ]] || die "canonical pb binary is absent"
  local binary_sha
  binary_sha=$(sha256sum "$pb" | awk '{print $1}')
  printf 'canonical_pb_sha256=%s\n' "$binary_sha"
  [[ "$binary_sha" == "$expected_sha" ]] || die "canonical pb SHA-256 does not match official asset"
  local version_output
  version_output=$("$pb" --version 2>&1) || die "canonical pb --version failed: $version_output"
  printf 'canonical_pb_version=%s\n' "$(printf '%s' "$version_output" | one_line)"
  grep -F "Version $expected_version" <<<"$version_output" >/dev/null || die "canonical pb version is not $expected_version"

  local unit expected_argument enabled active pid executable proc_sha exec_start
  for unit in paperboat-hostd.service paperboat-updated.service; do
    expected_argument=__runtime-hostd
    [[ "$unit" == paperboat-updated.service ]] && expected_argument=__runtime-updated
    enabled=$(systemctl is-enabled "$unit" 2>&1 || true)
    active=$(systemctl is-active "$unit" 2>&1 || true)
    printf 'unit=%s enabled=%s active=%s\n' "$unit" "$enabled" "$active"
    [[ "$enabled" == enabled ]] || die "$unit is not enabled"
    [[ "$active" == active ]] || die "$unit is not active"
    exec_start=$(systemctl show -p ExecStart --value "$unit" 2>/dev/null || true)
    [[ "$exec_start" == *"$pb"* ]] || die "$unit does not invoke the canonical pb binary"
    [[ "$exec_start" == *"$expected_argument"* ]] || die "$unit does not invoke the expected runtime role"
    printf 'unit=%s exec_start=%s\n' "$unit" "$(printf '%s' "$exec_start" | one_line)"
    pid=$(systemctl show -p MainPID --value "$unit" 2>/dev/null || true)
    [[ "$pid" =~ ^[0-9]+$ ]] && (( pid > 1 )) || die "$unit has no live MainPID"
    executable=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
    proc_sha=$(sha256sum "/proc/$pid/exe" 2>/dev/null | awk '{print $1}' || true)
    printf 'unit=%s pid=%s executable=%s sha256=%s\n' "$unit" "$pid" "$executable" "$proc_sha"
    [[ "$executable" == "$pb" ]] || die "$unit is running an unexpected executable"
    [[ "$proc_sha" == "$expected_sha" ]] || die "$unit runtime SHA-256 does not match official asset"
  done

  [[ -S "$hostd_socket" ]] || die "missing $hostd_socket"
  [[ -S "$updater_socket" ]] || die "missing $updater_socket"
  printf 'socket=%s present\n' "$hostd_socket"
  printf 'socket=%s present\n' "$updater_socket"

  local address health_body
  address=$(listen_address || true)
  [[ "$address" == 127.0.0.1:* || "$address" == '[::1]:'* ]] || die "health address is not literal loopback: ${address:-absent}"
  printf 'health_address=%s\n' "$address"
  health_body=$(curl --noproxy '*' --fail --silent --show-error --max-time 5 "http://${address}/healthz") || die "healthz request failed"
  printf 'healthz=%s\n' "$(printf '%s' "$health_body" | one_line)"
  jq -e '.live == true' <<<"$health_body" >/dev/null || die "healthz did not report live=true"

  local check_json status_json doctor_json
  check_json=$("$pb" update check --json 2>&1) || die "pb update check failed: $(printf '%s' "$check_json" | one_line)"
  printf 'update_check_json=%s\n' "$(printf '%s' "$check_json" | one_line)"
  jq -e --arg version "$expected_version" '
    .ok == true and .data.installed_version == $version and
    .data.latest_version == $version and .data.update_available == false and
    .data.verified == true
  ' <<<"$check_json" >/dev/null || die "pb update check did not verify the installed current release"

  status_json=$("$pb" update status --json 2>&1) || die "pb update status failed: $(printf '%s' "$status_json" | one_line)"
  printf 'update_status_json=%s\n' "$(printf '%s' "$status_json" | one_line)"
  jq -e --arg version "$expected_version" '
    .ok == true and .data.cli_version == $version and
    .data.runtime_version == $version and .data.runtime_available == true and
    .data.activation_pending == false and (.data.activation_failure // "") == "" and
    (.data.last_failure // "") == "" and
    ((.data.supervisor.maintenance_required // false) == false)
  ' <<<"$status_json" >/dev/null || die "pb update status reports pending or failed runtime state"

  if doctor_json=$("$pb" doctor --json 2>&1); then
    printf 'doctor_json=%s\n' "$(printf '%s' "$doctor_json" | one_line)"
  else
    printf 'doctor_json=%s\n' "$(printf '%s' "$doctor_json" | one_line)"
    die "pb doctor failed"
  fi
  jq -e '.schema == "paperboat.doctor/v1" and .overall == "healthy"' <<<"$doctor_json" >/dev/null || die "pb doctor is not healthy"
  printf 'verification_healthy=true\n'
}

snapshot before
capture_identity
before_machine_identity_sha=$machine_identity_sha
before_machine_identity_key_id=$machine_identity_key_id
before_registration_machine_id=$registration_machine_id
before_registration_environment_id=$registration_environment_id
before_registration_generation=$registration_generation
before_registration_public_key=$registration_public_key
before_registration_setup_mode=$registration_setup_mode
before_registration_server_url=$registration_server_url
before_runtime_machine_id=$runtime_machine_id
before_runtime_environment_id=$runtime_environment_id
before_runtime_helper_id=$runtime_helper_id
[[ "$before_machine_identity_sha" != missing ]] || die "existing machine identity is missing; refusing a fresh enrollment"
[[ "$before_registration_machine_id" != missing ]] || die "existing machine registration is missing; refusing a fresh enrollment"
[[ "$before_registration_public_key" != missing ]] || die "existing public identity key is missing; refusing a fresh enrollment"

printf 'install_stage=official_installer\n'
export PAPERBOAT_RELEASE_METADATA_URL="$metadata_url"
export PAPERBOAT_GITHUB_REPOSITORY=pinksaucepasta/paperboat-cli
curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' --tlsv1.2 "$installer_url" |
  sh -s -- --version "$expected_version" --install-dir "$install_dir" --no-setup

[[ -x "$pb" ]] || die "official installer did not create $pb"
installed_sha=$(sha256sum "$pb" | awk '{print $1}')
[[ "$installed_sha" == "$expected_sha" ]] || die "installed CLI SHA-256 mismatch"
printf 'installed_cli_sha256=%s\n' "$installed_sha"

printf 'setup_stage=pb_setup_host\n'
timeout --foreground 300 "$pb" setup --mode host --ssh-port "$ssh_port" --name "$machine_name"

verify_identity
verify after-setup

printf 'restart_stage=systemctl_restart_hostd_updated\n'
systemctl restart paperboat-hostd.service paperboat-updated.service
sleep 3
verify_identity
verify after-restart

printf 'journal_stage=hostd_updated_current_boot\n'
journalctl -u paperboat-hostd.service -u paperboat-updated.service -b --no-pager -n 100 -o short-iso 2>&1 || true
printf 'acceptance_complete=true\n'
REMOTE
