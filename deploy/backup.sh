#!/bin/sh
# Local snapshot before a release. Copy it to independent encrypted storage.
set -eu
cd /opt/wappie
umask 077
snapshot="backups/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$snapshot"
sudo docker compose exec -T db pg_dump -U postgres -d wappie -Fc > "$snapshot/database.dump.partial"
mv "$snapshot/database.dump.partial" "$snapshot/database.dump"
sudo docker run --rm --network none --read-only -v wappie_objects:/objects:ro --entrypoint tar debian:bookworm-slim -C /objects -cf - . > "$snapshot/objects.tar"
sha256sum "$snapshot/database.dump" "$snapshot/objects.tar" > "$snapshot/SHA256SUMS"
printf '%s\n' "$snapshot"
