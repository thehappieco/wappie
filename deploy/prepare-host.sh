#!/bin/sh
set -eu
cd /opt/wappie
umask 077
if [ ! -f .env ]; then
 python3 - <<'PY'
import secrets
from pathlib import Path
Path('.env').write_text('\n'.join(k+'='+secrets.token_hex(32) for k in ['DB_ROOT_PASSWORD','DB_APP_PASSWORD','STORAGE_PASSWORD'])+'\n')
PY
fi
mkdir -p certs/db certs/objects release site
if [ ! -f certs/ca.crt ]; then
 openssl req -x509 -newkey rsa:3072 -nodes -keyout certs/ca.key -out certs/ca.crt -days 3650 -subj /CN=Wappie-Internal-CA 2>/dev/null
fi
for service in db objects; do
 if [ ! -f "certs/$service/server.crt" ]; then
  openssl req -newkey rsa:2048 -nodes -keyout "certs/$service/server.key" -out "certs/$service/request.csr" -subj "/CN=$service" 2>/dev/null
  printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$service" > "certs/$service/extensions"
  openssl x509 -req -in "certs/$service/request.csr" -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out "certs/$service/server.crt" -days 365 -extfile "certs/$service/extensions" 2>/dev/null
 fi
done
cp certs/objects/server.crt certs/objects/public.crt
cp certs/objects/server.key certs/objects/private.key
cp certs/ca.crt release/ca.crt
chmod 644 release/ca.crt certs/ca.crt certs/db/server.crt
chmod 755 release site certs/db
sudo chown 999:999 certs/db/server.key
sudo chmod 600 certs/db/server.key
