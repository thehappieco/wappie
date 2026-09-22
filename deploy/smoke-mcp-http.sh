#!/usr/bin/env bash
# Smoke test for the mcp-http container in the topology compose.yaml uses:
# the reader shares another container's network namespace and is published
# from that container. Needs only the reader image and a stock node image, no
# API or database, so CI can run it right after `docker build`.
#   deploy/smoke-mcp-http.sh wappie-mcp-http:local
# Asserts: the loopback probe with the relay bearer is 200; without the bearer
# it is 401; the same probe through the published port is 404, because the
# port proxy is not a loopback peer; public discovery through the published
# port is 200.
set -euo pipefail
image="${1:?usage: smoke-mcp-http.sh <image>}"
suffix="$$"
stub="wappie-mcp-smoke-stub-$suffix"
reader="wappie-mcp-smoke-reader-$suffix"
relay="wappie-mcp-smoke-relay-$suffix"
state="wappie-mcp-smoke-state-$suffix"
port="${WAPPIE_MCP_SMOKE_PORT:-18193}"
cleanup() {
  docker rm -f "$reader" "$stub" >/dev/null 2>&1 || true
  docker volume rm -f "$relay" "$state" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# The secret lives in a volume owned by the reader's uid, as the reader
# refuses any other owner or mode; it never touches the host filesystem.
docker run --rm -v "$relay:/s" alpine sh -c \
  'head -c 36 /dev/urandom | base64 | tr -d "\n" > /s/relay && chown 10001:10001 /s/relay && chmod 600 /s/relay' >/dev/null
docker run -d --name "$stub" -p "127.0.0.1:$port:18093" node:22-bookworm-slim sleep 600 >/dev/null
docker run -d --name "$reader" --network "container:$stub" --read-only --tmpfs /tmp \
  -v "$relay:/run/secrets:ro" -v "$state:/var/lib/wappie-mcp" \
  -e WAPPIE_MCP_PUBLIC_ORIGIN=https://api.example.test \
  -e WAPPIE_MCP_CONSOLE_URL=https://app.example.test/console \
  -e WAPPIE_MCP_RELAY_SECRET_FILE=/run/secrets/relay \
  -e WAPPIE_MCP_ARCHIVE_URL=http://127.0.0.1:8090 \
  "$image" >/dev/null
for _ in $(seq 1 30); do
  docker logs "$reader" 2>&1 | grep -q '"event":"listening"' && break
  sleep 1
done
docker logs "$reader" 2>&1 | grep -q '"event":"listening"' || { docker logs "$reader"; echo 'reader did not start' >&2; exit 1; }

secret="$(docker run --rm -v "$relay:/s:ro" alpine cat /s/relay)"
probe() { # probe <bearer|none> -> status and body from inside the shared namespace
  docker exec "$stub" node -e '
    const headers = process.argv[1] === "none" ? {} : { authorization: "Bearer " + process.argv[1] }
    fetch("http://127.0.0.1:18093/internal/healthz", { headers }).then(async r => console.log(r.status, await r.text()))' "$1"
}
expect() { [[ "$2" == "$3" ]] || { echo "$1: got '$2', want '$3'" >&2; exit 1; }; echo "ok: $1"; }
expect 'loopback probe with bearer' "$(probe "$secret")" '200 {"ok":true}'
expect 'loopback probe without bearer' "$(probe none)" '401 {"code":"unauthorized"}'
expect 'published port is not a loopback peer' \
  "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $secret" "http://127.0.0.1:$port/internal/healthz")" 404
expect 'published port serves discovery' \
  "$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: api.example.test' "http://127.0.0.1:$port/.well-known/oauth-authorization-server")" 200
