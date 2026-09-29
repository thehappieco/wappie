# The jail check of deploy/enclave/check-image.sh --jail (docs/mcp-enclave.md
# §16.13 JAIL and CORPUS): the reader image under test, unchanged, plus what
# the check needs beside it. Never released, never an EIF. Build from the
# PUBLIC repository root:
#   docker build -f deploy/enclave/jailcheck/Dockerfile --build-arg READER_IMAGE=<image> .
# Run privileged on an arm64 host with cgroup v2 (check-image.sh does both).

ARG READER_IMAGE
ARG RUST_IMAGE=rust:1-alpine@sha256:7cc1c22d77d9432f7fe012a70e6d3e555af54c2a6832700ed7d553f1769ae89f

# The A0 probe's escape tests, one static binary (deploy/enclave/probe/tests).
FROM ${RUST_IMAGE} AS jailtest
RUN apk add --no-cache musl-dev build-base linux-headers
COPY deploy/enclave/probe/tests/jailtest.c /tests/jailtest.c
RUN cc -static -O2 -Wall -o /jailtest /tests/jailtest.c

# The same media-jail source with the emulate-old-kernel feature, for the
# check-4.14 target: never in the reader image.
FROM ${RUST_IMAGE} AS emulate
RUN apk add --no-cache musl-dev
WORKDIR /mj
COPY deploy/enclave/media-jail/Cargo.toml deploy/enclave/media-jail/Cargo.lock ./
COPY deploy/enclave/media-jail/src/ ./src/
COPY deploy/enclave/media-jail/profiles/ ./profiles/
RUN cargo build --release --locked --features emulate-old-kernel && cp target/release/media-jail /media-jail

FROM ${READER_IMAGE} AS check
# The escape tests run as the image worker of a stand-in /opt/media, mounted
# over the real one only while they run: media-jail's table admits nothing
# but the three workers, so the driver execs jailtest in the worker's place.
COPY --from=jailtest /jailtest /opt/jailcheck/media/bin/jailtest
COPY deploy/enclave/jailcheck/driver.mjs /opt/jailcheck/media/worker/image.mjs
COPY deploy/enclave/jailcheck/driver.mjs /opt/jailcheck/media/worker/pdf.mjs
COPY deploy/enclave/jailcheck/driver.mjs /opt/jailcheck/media/worker/office.mjs
# The corpus generator and the reader's frame checks, beside the workers, so
# they import the workers' own sharp and SheetJS.
COPY packages/mcp-http/enclave/media/worker/test/ /opt/media/worker/test/
COPY deploy/enclave/jailcheck/run.sh deploy/enclave/jailcheck/jail-check.mjs deploy/enclave/jailcheck/trace.mjs /opt/jailcheck/
ENTRYPOINT ["/bin/sh", "/opt/jailcheck/run.sh"]

# The check again with every fallback the 4.14 blob kernel needs forced on a
# newer kernel (media-jail/src/emulate.rs): move+chroot root, SIGKILL of the
# job's init instead of cgroup.kill, media-jail's own OOM group, the affinity
# pin instead of cpuset, KILL_THREAD.
FROM check AS check-4.14
COPY --from=emulate /media-jail /usr/local/bin/media-jail
ENV MEDIA_JAIL_EMULATE=no-cgroup-kill,no-oom-group,no-peak,no-cpuset,no-pivot-root,kill-thread

# trace-profile.sh only: strace, whose libraries would join the /usr/lib the
# jail binds, so the check itself (the target above) runs without it.
FROM check AS trace
RUN apk add --no-cache strace > /dev/null
