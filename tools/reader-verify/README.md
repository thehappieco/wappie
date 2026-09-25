# reader-verify

Checks that `https://mcp.wappie.thehappie.co` is served by a released Wappie
reader image running in an AWS Nitro Enclave. Anyone can run it; it needs no
account and no key.

It sends a fresh random nonce to the reader's public `GET /attestation`,
verifies the returned attestation document with the same verifier the console
uses (`packages/client`, `attestation.verifyAttestation`) against a release's
`measurements.json`, and then checks that the TLS certificate that answered has
the key the document commits to (`tls_spki_sha256`). What passing means:

- the document is signed by AWS Nitro hardware, chained to the pinned AWS Nitro
  Enclaves root (G1);
- the enclave runs the image whose PCR0, PCR1 and PCR2 the release publishes,
  not in debug mode;
- the enclave was answering this nonce, now (within 10 minutes);
- its KMS key policy hash is one the release publishes;
- this TLS connection ended inside that enclave.

## Run

```sh
npm --prefix packages/client ci && npm --prefix packages/client run build
npm --prefix tools/reader-verify ci
node tools/reader-verify/reader-verify.mjs \
  --measurements https://github.com/thehappieco/wappie/releases/download/reader-v0.2.0/measurements.json
```

Options:

| Option | Meaning |
|---|---|
| `--measurements <url or file>` | A release's `measurements.json`. Repeat it to accept several releases (during a PCR0 change). URLs must be `https://`. |
| `--sha256 <hex>` | Pins each `--measurements` file by SHA-256, in the same order (the values in the console's `reader-releases.json`). |
| `--host <name[:port]>` | Default `mcp.wappie.thehappie.co`. A boot name (`<boot_id>.boot.mcp.wappie.thehappie.co`) reaches the same enclave. |
| `--record <file>` | Appends the attested `tls_spki_sha256` to this file, once per key, for `tools/ct-watch`. |

It prints one JSON line and exits 0 on success:

```json
{"ok":true,"host":"mcp.wappie.thehappie.co","reader_version":"0.2.0","pcr0":"…","policy_sha256":"…","policy_phase":"steady","tls_spki_sha256":"…","module_id":"…","timestamp":1790268502945,"document_sha256":"…"}
```

On failure it prints `{"ok":false,"code":"…"}` and exits 1. The `attestation_*`
codes are the verifier's; the others are `usage`, `measurements_invalid`,
`measurements_fetch`, `measurements_unreadable`, `measurements_url`,
`measurements_sha256`, `fetch_failed`, `fetch_timeout`, `http_<status>`,
`response_invalid`, `response_too_large`, `tls_spki_unknown` and
`tls_spki_mismatch`.

## Test

```sh
npm --prefix tools/reader-verify test
```

The tests use synthetic documents from `packages/client/test/attestationFixtures.mjs`
and make no network request.
