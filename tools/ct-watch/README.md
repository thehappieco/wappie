# ct-watch

Certificate Transparency watch for the attested reader at
`mcp.wappie.thehappie.co`. Anyone can run it.

The reader's TLS key is generated inside the enclave at each boot and never
leaves it, and every attestation commits to that key's SPKI hash. So a
certificate that can serve `mcp.wappie.thehappie.co` on any other key means
someone other than the enclave obtained one, and publicly trusted certificates
all appear in CT logs. This script asks [crt.sh](https://crt.sh) for every
certificate naming:

- `mcp.wappie.thehappie.co`;
- anything under `.mcp.wappie.thehappie.co` (the per-boot names and `*.mcp.`);
- the wildcard `*.wappie.thehappie.co`, which would also cover `mcp.`;

downloads each one it has not seen, and flags those whose SPKI SHA-256 is not in
the attested list. The CAA records on `mcp.` should make such a certificate
impossible to obtain from a compliant CA; this is how a failure of that would
be seen.

## Run

```sh
node tools/reader-verify/reader-verify.mjs --measurements <release> --record attested-spki.txt
node tools/ct-watch/ct-watch.mjs --attested attested-spki.txt --cache ct-cache.json
```

| Option | Meaning |
|---|---|
| `--attested <file>` | SPKI SHA-256 hashes the enclave attested: one per line (`#` comments allowed) or a JSON array. `reader-verify --record` writes this file. |
| `--spki <hex>` | Adds one hash; may be repeated. |
| `--since <date>` | Ignores certificates whose `notBefore` is earlier (for names that had certificates before the enclave). |
| `--cache <file>` | Remembers the SPKI of certificates already downloaded, so a periodic run fetches only new ones. |

It prints one JSON line:

```json
{"ok":false,"checked":3,"flagged":[{"id":123,"serial":"…","issuer":"…","not_before":"…","not_after":"…","names":["mcp.wappie.thehappie.co"],"spki_sha256":"…","url":"https://crt.sh/?id=123"}],"unchecked":[]}
```

Exit codes: 0 nothing flagged; 1 at least one certificate on an unattested key;
2 the check could not be completed (crt.sh unavailable, a certificate that
could not be downloaded or did not match its listing). Alarm on 1 and on 2.

Each boot of the enclave has a new key, so the attested list has to gain the
new SPKI at every boot: run `reader-verify --record` after each deploy and on
its hourly schedule, before `ct-watch`.

## Test

```sh
npm --prefix tools/ct-watch test
```

The tests use a fake crt.sh and make no network request. They build
certificates with `packages/client/test/attestationFixtures.mjs`.
