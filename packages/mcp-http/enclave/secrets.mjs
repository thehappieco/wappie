// The relay secret shared with Go, and its rotation without a reboot
// (docs/mcp-enclave.md §4). The enclave signs with its current secret and
// accepts the current and the previous one; the previous is dropped the first
// time Go signs with the current one, which is how the enclave learns that Go
// finished switching. The secret only ever arrives as KMS ciphertext under the
// boot key, opened with Recipient inside this process.

const secretShape = /^[A-Za-z0-9_-]{43}$/

export class SecretError extends Error {
  constructor(code) { super(code); this.name = 'SecretError'; this.code = code }
}

/**
 * A relay secret from KMS plaintext bytes: 43 base64url characters (32 random
 * bytes as Go's configuration requires), with at most one trailing newline
 * forgiven because `aws kms encrypt --plaintext fileb://…` keeps what the file
 * had. The bytes are zeroed here.
 */
export function secretFrom(plaintext) {
  try {
    let text
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(plaintext) } catch { throw new SecretError('bad_request') }
    if (text.endsWith('\n')) text = text.slice(0, -1)
    if (!secretShape.test(text)) throw new SecretError('bad_request')
    return text
  } finally { plaintext.fill(0) }
}

/**
 * `open(ciphertext)` resolves to the KMS plaintext bytes (Decrypt under the
 * boot key with Recipient, KeyId pinned). `log` records rotations by count only.
 */
export function createSecrets({ current, open, log = { event() {} } }) {
  if (!secretShape.test(current ?? '')) throw new SecretError('relay_secret_invalid')
  let previous = null
  return {
    get current() { return current },
    get previous() { return previous },
    count: () => (previous ? 2 : 1),
    /** Every secret an inbound signature may use, current first. */
    accepted: () => (previous ? [current, previous] : [current]),
    /** Called with the secret a request verified under. */
    used(secret) {
      if (secret === current && previous !== null) { previous = null; log.event('relay_secret_previous_dropped') }
    },
    /** POST /internal/relay-secret: `ciphertext` is the decoded CiphertextBlob. */
    async rotate(ciphertext) {
      let plaintext
      try { plaintext = await open(ciphertext) } catch { throw new SecretError('kms_failed') }
      const next = secretFrom(plaintext)
      if (next === current) return
      previous = current
      current = next
      log.event('relay_secret_rotated')
    },
  }
}
