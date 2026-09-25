# Attested MCP reader: the image nitro-cli turns into the enclave EIF
# (docs/mcp-enclave.md). Build from the PUBLIC repository root, on arm64:
#   docker build -f deploy/enclave/Dockerfile \
#     --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" -t wappie-reader .
# deploy/enclave/build.sh does this from a copy of the commit with the two KMS
# key ARNs written into constants.mjs, then builds the EIF and measurements.json.
# Built straight from the tree (CI, make enclave-image) the markers stay and
# the image refuses to boot (constants_invalid), which is what a test build wants.
#
# Everything in this image is measured into PCR0, so every input is pinned:
# base images by digest (the defaults below; build.sh records them), npm and
# cargo dependencies by lockfile, and file times clamped to SOURCE_DATE_EPOCH.
# The spike found that PCR0 changes between clean builds because of file times
# and /var/log/apk.log (commercial/docs/enclave-spike-plan.md, Day 5), so both
# are handled here. The Alpine packages (socat, iproute2) still come from the
# branch's current index: a rebuild weeks later can differ, which is why each
# release publishes the exact image by digest.
#
# Only classic Dockerfile syntax (no RUN --mount, no heredocs): the parent's
# Docker may run the legacy builder.

# node:22-alpine and rust:1-alpine, multi-arch index digests (spike, Days 2-3).
ARG NODE_IMAGE=node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402
ARG RUST_IMAGE=rust:1-alpine@sha256:7cc1c22d77d9432f7fe012a70e6d3e555af54c2a6832700ed7d553f1769ae89f

# The NSM attestation helper: a static musl binary built from the committed
# Cargo.lock. Only the three inputs are copied, never a local target/ tree.
FROM ${RUST_IMAGE} AS nsm
RUN apk add --no-cache musl-dev
WORKDIR /nsm
COPY deploy/enclave/nsm-attest/Cargo.toml deploy/enclave/nsm-attest/Cargo.lock ./
COPY deploy/enclave/nsm-attest/src/ ./src/
RUN cargo build --release --locked && cp target/release/nsm-attest /nsm-attest

# Production dependencies per package, then a link-free copy (the pattern of
# deploy/Dockerfile.mcp-http). The enclave's own dependencies (KMS client and
# the rest of packages/mcp-http/enclave/package.json) come from its nested
# lockfile; it sits inside mcp-http so bare imports of @whatserver2/mcp resolve
# to the one copy provider.mjs uses (one SDK instance).
FROM ${NODE_IMAGE} AS build
ARG SOURCE_DATE_EPOCH
RUN test -n "${SOURCE_DATE_EPOCH}" || { echo "SOURCE_DATE_EPOCH is required (git log -1 --format=%ct)" >&2; exit 1; }
WORKDIR /src/packages
COPY packages/client/ ./client/
COPY packages/mcp/ ./mcp/
COPY packages/mcp-http/ ./mcp-http/
# src/ and test/ are pruned everywhere, as in the pilot images. A dependency
# that ships runtime code under src/ would break here: deploy/enclave/check-image.sh
# imports every enclave dependency, so CI catches that.
RUN rm -rf client/node_modules client/dist mcp/node_modules mcp-http/node_modules mcp-http/enclave/node_modules \
 && test -f mcp-http/enclave/package-lock.json \
 && cd client && npm ci --no-audit --no-fund && npm run build && rm -rf node_modules && npm ci --omit=dev --no-audit --no-fund \
 && cd ../mcp && npm ci --omit=dev --no-audit --no-fund \
 && cd ../mcp-http && npm ci --omit=dev --no-audit --no-fund \
 && cd enclave && npm ci --omit=dev --no-audit --no-fund \
 && mkdir -p /out/packages && for n in client mcp mcp-http; do cp -RL "/src/packages/$n" "/out/packages/$n"; done \
 && find /out -type d \( -name src -o -name test \) -prune -exec rm -rf {} + \
 && find /out -type f \( -name '*.map' -o -name '*.ts' \) -delete \
 && test -z "$(find /out -type l)" \
 && test -f /out/packages/mcp-http/enclave/main.mjs \
 && mkdir /.sde && touch -d "@${SOURCE_DATE_EPOCH}" /.sde/ref \
 && find /out -newer /.sde/ref -exec touch -h -r /.sde/ref {} +

# The enclave's root filesystem, assembled and clamped in one stage...
FROM ${NODE_IMAGE} AS rootfs
ARG SOURCE_DATE_EPOCH
# socat bridges vsock and loopback; iproute2 brings loopback up. apk.log holds
# install times, so it never reaches the image.
RUN apk add --no-cache socat iproute2 && rm -f /var/log/apk.log
COPY --from=build /out/packages/ /app/packages/
COPY --from=nsm /nsm-attest /usr/local/bin/nsm-attest
COPY deploy/enclave/entrypoint.sh /entrypoint.sh
# Clamp every time newer than SOURCE_DATE_EPOCH (the apk files, the copied
# trees and every directory they touched) to it; the base image's older times
# stay. The reference directory is removed and / is re-clamped last, because
# removing it changes the time of /. The runtime mounts are skipped.
RUN chmod 0555 /entrypoint.sh /usr/local/bin/nsm-attest \
 && mkdir /.sde && touch -d "@${SOURCE_DATE_EPOCH}" /.sde/ref \
 && find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /.sde \
      -o -path /etc/hosts -o -path /etc/hostname -o -path /etc/resolv.conf \) -prune \
      -o -newer /.sde/ref -exec touch -h -r /.sde/ref {} + \
 && rm -r /.sde && touch -h -d "@${SOURCE_DATE_EPOCH}" /

# ...then copied whole into an empty image as a single layer. A layer that
# only changes a directory's time is not recorded (the layer differ skips
# metadata-only directory changes: /app and the apk directories kept their
# build time when the clamp ran as a layer of its own), so the clamped tree is
# written out fresh, every entry with its clamped time.
FROM scratch
COPY --from=rootfs / /
# PATH because this image starts from scratch (the base image's value); the
# rest of the reader's settings are constants in
# packages/mcp-http/enclave/constants.mjs, measured with the image.
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    NODE_ENV=production
CMD ["/bin/sh", "/entrypoint.sh"]
