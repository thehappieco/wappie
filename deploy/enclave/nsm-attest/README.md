# nsm-attest

Two in-enclave helpers for the Nitro Secure Module, built from one crate.

## nsm-attest

Asks the NSM for an attestation document:

```
nsm-attest <public_key_hex|-> <nonce_hex|-> <user_data_hex|->
```

Exactly three arguments; `-` means absent. The reader passes the per-boot RSA
SubjectPublicKeyInfo (DER) for a KMS `Recipient` document, and the raw 32-byte
X25519 key of a consent request, with the browser's nonce and the 32-byte
`user_data`, for a request document (`docs/mcp-enclave.md` §6.2). The helper
does not interpret the bytes.

- Limits: `public_key` 1..=1024 bytes, `nonce` and `user_data` 0..=512 bytes.
- On success it writes only the raw attestation document (COSE_Sign1 CBOR) to stdout.
- Exit codes: 0 ok, 1 NSM error, 2 `/dev/nsm` cannot be opened, 3 bad arguments
  (checked before the device is opened). Failures print one line to stderr,
  never document bytes or argument contents.

It uses `aws-nitro-enclaves-nsm-api =0.5.2` (MSRV 1.92): `Request::Attestation`
through `nsm_init` / `nsm_process_request` / `nsm_exit`.

## nsm-timefeed

Feeds NSM time to chronyd's SOCK reference clock, and writes what it sees
for the reader:

```
nsm-timefeed <chrony_sock> <state_dir>
```

- Exit codes: 2 `/dev/nsm` cannot be opened, 3 bad arguments (two absolute
  paths, the socket path short enough for a unix socket; checked before the
  device is opened), 1 an NSM request hung past the 5 s alarm or a fatal error
  such as a state directory it cannot write. Otherwise it never exits; the
  clock start script runs it in a loop.
- Every 4 s it asks the NSM for three attestation documents, each with a fresh
  random nonce, and keeps the one with the smallest round trip. A document
  must decode (COSE_Sign1, with or without tag 18), use SHA384, name a module,
  echo the nonce, carry this boot's PCR0 and a timestamp after 2026-11-01 and
  before 2100. The sample is also refused when the clock was stepped during
  the request, when its round trip breaks the keep rule, or when NSM time
  jumps against MONOTONIC_RAW (a new level is taken after three agreeing
  samples).
- `offset = NSM time + 0.5 ms - system time` at the request's midpoint
  (positive: the system clock is behind). It goes to chronyd as a 40-byte
  `sock_sample`.
- The first good sample of the enclave boot decides the boot gate: within
  600 s it feeds, otherwise `boot_refused` for the whole boot.
- The ledger watches `REALTIME - MONOTONIC_RAW` once the clock is within 1 s
  of NSM time: more than 5 s of change within an hour or 10 s within a day is
  `cap_exceeded`, which stops the feed for the rest of the boot.
- `<state_dir>` holds `state.json` (rewritten every cycle), `boot`, `pcr0`
  and `ledger`; the formats and states are described in `src/timefeed/`.
- The `fake-drift` feature (probe builds only) scales NSM time by +200 ppm.
  The image builds with no features; its binary must not contain
  `WAPPIE_FAKE_DRIFT`.

Constants marked "settled by P0" in `src/timefeed/mod.rs` (the cycle, the
attempts per cycle, the round-trip rule and the timestamp rounding) are the
plan's values until the clock probe's P0 run measures NSM latency on the
enclave.

## Build and tests

Both binaries are measured into PCR0 and PCR2, so every input is pinned:
exact crate versions in `Cargo.toml`, the committed `Cargo.lock` (built with
`--locked`), and the Rust image digest passed to `deploy/enclave/Dockerfile`.
The static musl binaries come from the Dockerfile's `nsm` stage. Outside an
enclave both exit 2, which is what the image check expects.

`make nsm-attest-check` runs `cargo test --locked` (with and without
`fake-drift`) and the release build in the Dockerfile's pinned Rust image,
checks the exit codes and the fake-drift marker. The tests run only there
(Linux: they use its clocks and adjtimex). `tests/fixtures/` holds two
attestation documents made by `tests/fixtures/make-fixtures.mjs`.
