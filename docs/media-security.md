# Media security boundaries and follow-up

This documents the implementation reviewed on 2026-09-17. It is a source review,
not an inspection of production objects or proof that any existing object is
unencrypted. The hardening below is pending; this document changes no runtime
behavior.

## Current boundaries

| Data or operation | Current behavior |
| --- | --- |
| Ordinary encrypted WhatsApp attachment received from the CDN | The downloader preserves the AES-CBC ciphertext and trailing MAC. It checks `fileEncSHA256` when present. The media key, embedded thumbnail and file name are sealed in the archive. |
| Object storage | Receives the downloaded bytes without a second application encryption layer. HTTPS and any provider-managed storage encryption are separate protections. |
| Outbound attachment | The browser sends prepared plaintext bytes over HTTPS. The server's whatsmeow `UploadReader` encrypts the stream into a temporary ciphertext file, then uploads it. Plaintext exists in server memory. The archive downloads the encrypted CDN copy. |
| WhatsApp contact or group picture | Ordinary image bytes arrive over HTTPS, are visible in server memory and are sealed before archive persistence. |
| Wappie account or workspace avatar | A validated image data URL stored as shared profile metadata, without archive encryption. Base64 encoding is not encryption. |
| Client retrieval | The HTTP media endpoint returns stored bytes. Supported encrypted attachments are opened in the browser or CLI. `wsctl media -raw` retrieves stored bytes; it does not configure storage encryption. |
| MCP connectors | The hosted metadata connector (`api.`) reports attachment type, MIME type, size and download status; the filename stays locked. The attested reader (`mcp.`) also opens the sealed filename for a text connection. Neither downloads media, opens the sealed media key or thumbnail, or returns attachment bytes. The attested reader's key would technically open the media key and thumbnail, because one key per number opens every sealed field; the reader simply never asks for them. |

The archive private key stays with authorized clients. This does not make the
live server blind: it has WhatsApp session secrets, sees incoming message
content and media keys, holds current symmetric archive content keys while
sealing, and handles outbound plaintext. A compromised running process has a
different exposure from a database or object-store leak. Routing and attachment
metadata also remain readable.

## Known gap

The ingestion and download paths currently accept media without a sealed media
key or `fileEncSHA256`. The fetcher copies the response bytes and skips its hash
check if that hash is absent. The object-key fallback is shared within the
workspace (`<tenant>/unhashed/`), so distinct unhashed attachments can also
collide. Object storage adds no archive envelope to compensate for either case.

The pinned whatsmeow newsletter upload explicitly permits media without a
media key or encrypted-file hash. Preserving such bytes does not establish
encryption at rest; a supplied hash alone proves integrity, not encryption.
These are source-level risks, not findings about inspected customer objects.

Relevant implementation: [normalization](../internal/wa/normalize/content.go),
[ingestion](../internal/ingest/pipeline.go),
[download verification](../internal/media/fetch.go),
[worker and object keys](../internal/media/worker.go),
[object writes](../internal/blob/blob.go), and
[outbound uploads](../internal/media/upload.go).

## Required hardening and safe migration

1. **Validate before storage.** Reject or quarantine unsupported key/hash
   combinations, require valid hash lengths and verify integrity. Eliminate the
   shared unhashed object key. Keyless media must either remain explicitly
   unavailable or gain an archive encryption envelope before persistence.
2. **Version any new format.** Use authenticated encryption, bounded streaming,
   unique nonces, sealed keys and binding to the archive namespace/media identity.
   Specify deduplication, accounting and transfer behavior. Update browser, SDK
   and CLI readers before writing it; unknown formats must fail clearly. Do not
   repurpose existing fields or infer encryption from a MIME type or file name.
3. **Migrate explicitly.** Begin with metadata-only counts and ambiguous object
   references. Metadata cannot prove encryption or recover overwritten bytes.
   Content inspection or re-encryption requires an authorized operation and the
   needed keys, without plaintext logs or staging files. Preserve verified
   originals, switch references atomically, and support restart/rollback,
   retention and backups. Relabeling existing bytes is not re-encryption.
4. **Test the gap and migration.** Cover malformed/missing keys and hashes,
   synthetic keyless newsletter input, two distinct unhashed objects, hash
   mismatch, interrupted/concurrent writes, client interoperability, migration
   restart/rollback and authorization. Check plaintext canaries against object
   and temporary storage where encryption is promised.

`TestTheServerStoresCiphertextItCannotRead` and
`TestTheMediaEndpointServesCiphertextAndNothingElse` cover ordinary encrypted
attachments. They do not establish safety for missing-key/hash input.
