#!/bin/sh
# PID 1's script inside the reader enclave (docs/mcp-enclave.md §1, §10).
# The enclave has no network device, only vsock. Every hop below is a byte
# pipe: TLS to KMS, api. and ACME, and the public TLS, terminate in Node.
#
# Nothing written here reaches the parent: the enclave's console is only
# readable in debug mode, and the reader's only output channel is the log
# sink (vsock 7002), which carries createLog lines alone. So Node, and every
# socat, runs with stdout and stderr on /dev/null.
set -eu

ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
ip link set dev lo up

# The three outbound names resolve to their own loopback address, so each
# gets its own vsock-proxy on the parent (and that proxy's allowlist entry).
printf '%s\n' \
  '127.0.0.2 kms.eu-west-1.amazonaws.com' \
  '127.0.0.3 api.wappie.thehappie.co' \
  '127.0.0.4 acme-v02.api.letsencrypt.org' >> /etc/hosts

# TLS key and certificate of this boot (§10.3): RAM only, like the whole
# root filesystem of an enclave, and it survives a Node restart.
mkdir -p /run/wappie
chmod 0700 /run/wappie

# Keeps one socat alive. A bridge that dies (it should not: fork mode) comes
# back after a second instead of leaving the reader deaf or mute until the
# next boot. The arguments are socat's two addresses.
bridge() {
  while :; do
    socat "$1" "$2" > /dev/null 2>&1 < /dev/null || true
    sleep 1
  done &
}

# Outbound: loopback -> parent (CID 3). Never vsock 9000: nitro-cli uses it
# for the boot heartbeat (spike, Day 1).
bridge TCP-LISTEN:443,bind=127.0.0.2,reuseaddr,fork VSOCK-CONNECT:3:8000   # KMS
bridge TCP-LISTEN:443,bind=127.0.0.3,reuseaddr,fork VSOCK-CONNECT:3:8001   # api.wappie.thehappie.co
bridge TCP-LISTEN:443,bind=127.0.0.4,reuseaddr,fork VSOCK-CONNECT:3:8002   # Let's Encrypt ACME
bridge TCP-LISTEN:7000,bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:3:7000  # role credentials
bridge TCP-LISTEN:7001,bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:3:7001  # boot.json
bridge TCP-LISTEN:7002,bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:3:7002  # log sink

# Inbound: parent haproxy -> vsock -> the listeners Node binds on 127.0.0.1.
# 5443 public HTTPS and 5444 /internal/* start with PROXY v2; 5445 answers
# only the ACME TLS-ALPN-01 challenge.
bridge VSOCK-LISTEN:5443,reuseaddr,fork TCP:127.0.0.1:5443
bridge VSOCK-LISTEN:5444,reuseaddr,fork TCP:127.0.0.1:5444
bridge VSOCK-LISTEN:5445,reuseaddr,fork TCP:127.0.0.1:5445

# Node is restarted in a loop rather than exec'd, so a crash (exit 70), a
# refused boot (exit 78) or a state conflict (§8) costs one process, not the
# enclave: the TLS key in /run/wappie and this boot's certificate survive,
# and the parent's supervisor only steps in when the whole enclave is gone.
# Backoff 5 s doubling to 60 s; a run that lasted 5 minutes resets it.
delay=5
while :; do
  started=$(date +%s)
  node /app/packages/mcp-http/enclave/main.mjs > /dev/null 2>&1 < /dev/null || true
  if [ $(( $(date +%s) - started )) -ge 300 ]; then
    delay=5
  fi
  sleep "$delay"
  delay=$(( delay * 2 ))
  if [ "$delay" -gt 60 ]; then
    delay=60
  fi
done
