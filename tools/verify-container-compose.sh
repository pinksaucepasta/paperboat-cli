#!/bin/sh
# Validate Compose syntax and interpolation without talking to a Docker daemon.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

if docker compose version >/dev/null 2>&1; then
  compose() { docker compose "$@"; }
elif command -v docker-compose >/dev/null 2>&1; then
  compose() { docker-compose "$@"; }
else
  echo "container compose validation: Docker Compose is required" >&2
  exit 1
fi

run_compose() {
  PAPERBOAT_IMAGE=example.invalid/paperboat:test \
  PAPERBOAT_RELEASE_REPOSITORY=https://releases.paperboat.test \
  PAPERBOAT_MACHINE_ID=mch_container_test \
  PAPERBOAT_CONTROL_URL=https://api.paperboat.test \
  PAPERBOAT_SSH_PORT=22 \
  PAPERBOAT_PROJECT_ID=prj_container_test \
  PAPERBOAT_REPOSITORY_URL=https://github.com/example/project.git \
  PAPERBOAT_MACHINE_GENERATION=1 \
  PAPERBOAT_ENROLLMENT_CREDENTIAL=test-enrollment \
  compose -f "$1" config >/dev/null
}

run_compose deploy/hosted/compose.yaml
run_compose deploy/self-hosted/compose.yaml
echo "container compose: valid"
