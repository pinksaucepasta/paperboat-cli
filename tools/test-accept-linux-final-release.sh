#!/usr/bin/env bash
set -Eeuo pipefail

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
acceptance_script="$repository_root/tools/accept-linux-final-release.sh"

bash -n "$acceptance_script"

# The mutating acceptance path is sent to the VM as a quoted heredoc. Extract
# that exact body so this test verifies the variable used by the installer
# invocation, without contacting or changing a remote machine.
remote_body=$(awk '
  /^remote / && / install <</ && /REMOTE/ { capture=1; next }
  capture && /^REMOTE$/ { exit }
  capture { print }
' "$acceptance_script")

[[ -n "$remote_body" ]] || {
  echo 'could not locate the mutating remote acceptance body' >&2
  exit 1
}
[[ "$remote_body" == *'install_dir=/usr/local/libexec/paperboat'* ]] || {
  echo 'remote acceptance body does not define the canonical install directory' >&2
  exit 1
}
[[ "$remote_body" == *'--install-dir "$install_dir" --no-setup'* ]] || {
  echo 'remote official-installer invocation does not use the canonical install directory' >&2
  exit 1
}
if [[ "$remote_body" == *'${INSTALL_DIR}'* || "$remote_body" == *'$INSTALL_DIR'* ]]; then
  echo 'remote acceptance body still references unset INSTALL_DIR' >&2
  exit 1
fi

echo 'accept-linux-final-release: syntax and canonical installer directory checks passed'
