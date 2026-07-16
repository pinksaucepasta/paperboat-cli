#!/bin/sh
set -eu

root=${1:?Papercode repository path is required}
output=${2:?output tar.gz path is required}
node_binary=${3:-$(command -v node)}

if [ ! -x "$node_binary" ]; then
  echo "Node runtime is not executable: $node_binary" >&2
  exit 1
fi

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM

# pnpm deploy resolves the production closure into a directory with no links
# back to the developer checkout. The archive installer rejects links by design.
if [ -n "${PAPERBOAT_PAPERCODE_DEPLOY_DIR:-}" ]; then
  cp -R "$PAPERBOAT_PAPERCODE_DEPLOY_DIR" "$stage/app"
else
  pnpm --dir "$root" --pm-on-fail=ignore --filter t3 deploy --legacy --prod "$stage/app"
fi
cp "$node_binary" "$stage/node"
printf '%s\n' '#!/bin/sh' 'exec "$(dirname "$0")/node" "$(dirname "$0")/app/dist/bin.mjs" "$@"' > "$stage/papercode"
chmod 700 "$stage/papercode" "$stage/node"
mkdir -p "$(dirname "$output")"
tar -C "$stage" -czf "$output" papercode node app
