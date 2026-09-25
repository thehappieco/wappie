# nsm-attest

In-enclave helper that asks the Nitro Secure Module for an attestation document:

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

The binary is measured into PCR0 and PCR2, so every input is pinned: exact
crate versions in `Cargo.toml`, the committed `Cargo.lock` (built with
`--locked`), and the Rust image digest passed to `deploy/enclave/Dockerfile`.
The static musl binary comes from the Dockerfile's `nsm` stage. Outside an
enclave it exits 2, which is what the image check expects.
