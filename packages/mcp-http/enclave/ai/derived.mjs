// Derived records, sealed here (docs/mcp-enclave.md §18.8): a transcript,
// description or summary, under a key derived from the DSK that opened its
// source (I5), for exactly one namespace, number, message, function and
// epoch. The reader (packages/mcp/reader.mjs `openDerived`) and the console
// (packages/client/src/crypto/derived.ts) open them; the envelope and the
// record's checks are the reader's, which the enclave shares, and
// packages/client/testdata/node-derived.json holds records sealed here that
// all three open.
//
//   k        = HKDF-SHA256(DSK, salt = ns, info = "wappie-derived/v1" ‖ device_id ‖ u16be epoch)
//   envelope = "WDRV" ‖ 0x01 ‖ u16be epoch ‖ IV (12) ‖ AES-256-GCM(k, IV, plaintext, AAD)
import { createCipheriv, randomBytes } from 'node:crypto'
import { DERIVED_MAGIC, DERIVED_MAX_BYTES, derivedAAD, derivedKey, openDerivedWith, validateDerivedRecord } from '@whatserver2/mcp/reader'

export { openDerivedWith, derivedKey }

/**
 * A record in §18.8's order (`lang` only when set), checked. `usage` keeps
 * only the counts it has, in the order input, output, seconds.
 */
export function makeRecord({ feature, text, lang, provider, model, prompt_version, created_at, source_sha256, usage = {}, flags = [] }) {
  const counts = {}
  for (const name of ['input_tokens', 'output_tokens', 'seconds']) if (usage[name] !== undefined) counts[name] = usage[name]
  return validateDerivedRecord({
    v: 1, feature, text, ...(lang ? { lang } : {}), provider, model, prompt_version, created_at, source_sha256, usage: counts, flags: [...flags],
  }, feature)
}

/** Seals `record` for `scope` with `key` (derivedKey's, which the caller zeroes). */
export function sealDerivedWith(key, scope, record) {
  if (record.feature !== scope.feature) throw new Error('invalid_derived')
  const plain = Buffer.from(JSON.stringify(makeRecord(record)))
  try {
    if (plain.length > DERIVED_MAX_BYTES) throw new Error('invalid_derived')
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', key, iv)
    cipher.setAAD(derivedAAD(scope))
    const epoch = Buffer.alloc(2)
    epoch.writeUInt16BE(scope.epoch)
    return Buffer.concat([DERIVED_MAGIC, Buffer.from([1]), epoch, iv, cipher.update(plain), cipher.final(), cipher.getAuthTag()])
  } finally { plain.fill(0) }
}

/** Seals `record` for `scope` under DSK(device, epoch); `k` is zeroed here, the DSK is the caller's. */
export function sealDerived(dsk, scope, record) {
  const key = derivedKey(dsk, scope)
  try { return sealDerivedWith(key, scope, record) } finally { key.fill(0) }
}
