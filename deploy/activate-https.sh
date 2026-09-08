#!/bin/sh
set -eu
cd /opt/wappie
expected=54.73.145.199
for name in wappie.thehappie.co console.wappie.thehappie.co app.wappie.thehappie.co api.wappie.thehappie.co; do
 actual=$(dig +short A "$name" @1.1.1.1)
 if [ "$actual" != "$expected" ]; then
  printf 'DNS pending for %s (expected %s)\n' "$name" "$expected" >&2
  exit 1
 fi
done
sudo certbot certonly --non-interactive --webroot -w /var/www/wappie-acme \
 --cert-name wappie.thehappie.co \
 -d wappie.thehappie.co -d console.wappie.thehappie.co -d app.wappie.thehappie.co -d api.wappie.thehappie.co
sudo cp /etc/nginx/sites-available/wappie /etc/nginx/sites-available/wappie.previous
sudo install -m 644 nginx-https.conf /etc/nginx/sites-available/wappie
if ! sudo nginx -t; then
 sudo cp /etc/nginx/sites-available/wappie.previous /etc/nginx/sites-available/wappie
 exit 1
fi
sudo systemctl reload nginx
for name in wappie.thehappie.co console.wappie.thehappie.co app.wappie.thehappie.co; do
 curl -fsS -o /dev/null "https://$name/"
done
