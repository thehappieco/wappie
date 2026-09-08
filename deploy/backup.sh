#!/bin/sh
# Local snapshot before a release. Copy it to independent encrypted storage.
set -eu
cd /opt/wappie
umask 077
snapshot="backups/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$snapshot"
database="$(sudo python3 - <<'PYDB'
from pathlib import Path
from urllib.parse import urlsplit
p = Path('runtime.env')
values = dict(line.split('=', 1) for line in p.read_text().splitlines() if '=' in line) if p.exists() else {}
print(urlsplit(values['WS_POSTGRES_DSN']).path.lstrip('/') if 'WS_POSTGRES_DSN' in values else 'wappie')
PYDB
)"
objects="$(sudo docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' "$(sudo docker compose ps -q objects)")"
test -n "$objects"
sudo docker compose exec -T db pg_dump -U postgres -d "$database" -Fc > "$snapshot/database.dump.partial"
mv "$snapshot/database.dump.partial" "$snapshot/database.dump"
sudo docker run --rm --network none --read-only -v "$objects":/objects:ro --entrypoint tar debian:bookworm-slim -C /objects -cf - . > "$snapshot/objects.tar"
sha256sum "$snapshot/database.dump" "$snapshot/objects.tar" > "$snapshot/SHA256SUMS"
printf '%s\n' "$snapshot"
