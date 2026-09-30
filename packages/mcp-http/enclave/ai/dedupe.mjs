// Reuse of a result within the workspace (docs/mcp-enclave.md §18.8). A tag
// is an HMAC under a key derived from the number's DSK over the hash of the
// plaintext this enclave verified itself (I6), never the sender's claimed
// `file_sha256`, and over everything that makes a result what it is: the
// function, provider, model, prompt version and language. Go stores it
// beside the record and can match tags, never compute one.
//
//   k_dd[d]    = HKDF-SHA256(DSK(d, e), salt = ns[d], info = "wappie-ai-dedupe/v1" ‖ device_id ‖ u16be e)
//   dedupe_tag = HMAC-SHA256(k_dd[d], "wappie-ai-dedupe/v1" ‖ 0x00 ‖ source_sha256 (32 bytes) ‖ 0x00 ‖ feature
//                            ‖ 0x00 ‖ provider ‖ 0x00 ‖ model ‖ 0x00 ‖ prompt_version ‖ 0x00 ‖ (lang or ""))
import { createHmac } from 'node:crypto'
import { numberKey } from '@whatserver2/mcp/reader'

export const DEDUPE_LABEL = 'wappie-ai-dedupe/v1'

/** The 32-byte tag of one number for one result's inputs. `dsk` is the caller's to zero. */
export function dedupeTag(dsk, scope, { source_sha256, feature, provider, model, prompt_version, lang }) {
  if (!/^[0-9a-f]{64}$/.test(source_sha256 ?? '')) throw new Error('invalid_dedupe')
  const key = numberKey(dsk, DEDUPE_LABEL, scope)
  try {
    const zero = Buffer.from([0])
    return createHmac('sha256', key).update(Buffer.concat([
      Buffer.from(DEDUPE_LABEL), zero, Buffer.from(source_sha256, 'hex'), zero, Buffer.from(feature), zero, Buffer.from(provider), zero,
      Buffer.from(model), zero, Buffer.from(prompt_version), zero, Buffer.from(lang ?? ''),
    ])).digest()
  } finally { key.fill(0) }
}

/**
 * Whether a stored record found under an equal tag may stand for this job
 * (§18.8): the same verified hash, function, provider, model, prompt version
 * and language (absent meaning none). A record that differs in any is
 * ignored, whatever its tag. A refusal and a transcript without speech are
 * reused too: they are stored so the file is not sent again.
 */
export function reusable(record, job) {
  return record.source_sha256 === job.source_sha256 && record.feature === job.feature && record.provider === job.provider &&
    record.model === job.model && record.prompt_version === job.prompt_version && (record.lang ?? '') === (job.lang ?? '')
}
