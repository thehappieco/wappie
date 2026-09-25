# Real Nitro attestation documents

Captured on 2026-09-24 from the enclave spike (instance `i-05cdefb4833fdf39e`,
eu-west-1), base64 as the NSM returned them, with the nonce each one was asked
with (hex):

- `att.b64`, `att.nonce`: a production-mode enclave (`Flags: NONE`).
  `measurements.json` holds the `Measurements` nitro-cli printed for that EIF.
- `att-debug.b64`, `att-debug.nonce`: the same EIF run with `--debug-mode`, so
  PCR0, PCR1 and PCR2 are zero (PCR3 and PCR4, the role and the instance, are not).

They predate the `user_data` binding of milestone 2a and carry the spike's RSA
KMS-recipient key as `public_key`, so they exercise every check up to
`user_data`; `test/attestation.spec.ts` covers the rest with a synthetic chain.
The certificates in them expired on 2026-09-24, so tests pass `now` explicitly.
