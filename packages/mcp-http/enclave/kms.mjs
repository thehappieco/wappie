// KMS calls with Recipient. KMS encrypts its answer to the per-boot RSA key
// named in a fresh attestation document and leaves Plaintext empty, so the
// parent (which relays the TLS bytes and holds the role credentials) never
// sees key material. The key policies pin the image (PCR0), so only this
// image's documents work. Every Decrypt names its KeyId: without it KMS would
// pick whatever key the ciphertext names, and a blob made under a key the
// operator controls would open here.
import { generateKeyPairSync } from 'node:crypto'
import { DecryptCommand, GenerateDataKeyCommand, GetKeyPolicyCommand, KMSClient } from '@aws-sdk/client-kms'
import { openRecipientCms } from './cms.mjs'
import { REGION } from './constants.mjs'

const REFRESH_BEFORE_MS = 5 * 60_000
const NAME = /^[A-Za-z][A-Za-z0-9]{0,63}$/

/**
 * Short, secret-free code for logs and responses: one of our own codes
 * (cms_decrypt), a KMS error name reduced to snake case
 * (AccessDeniedException -> kms_access_denied_exception), a socket code, or
 * 'error'. Never a message. Log codes must match ^[a-z][a-z0-9_]{0,47}$.
 */
export function codeOf(error) {
  const snake = name => name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().slice(0, 43)
  if (/^[a-z][a-z0-9_]{1,47}$/.test(error?.message ?? '')) return error.message
  if (error?.$fault && NAME.test(error.name)) return `kms_${snake(error.name)}`.slice(0, 48)
  if (typeof error?.code === 'string' && /^E[A-Z0-9_]{1,39}$/.test(error.code)) return error.code.toLowerCase()
  return 'error'
}

/** KMS answered and refused (a client fault): not something a retry fixes. */
export const refusedByKms = error => error?.$fault === 'client'

function credentialsFrom(text) {
  let body
  try { body = JSON.parse(text) } catch { throw new Error('creds_invalid') }
  const { Code, AccessKeyId, SecretAccessKey, Token, Expiration } = body ?? {}
  const expiration = new Date(Expiration)
  const present = [AccessKeyId, SecretAccessKey, Token].every(value => typeof value === 'string' && value.length > 0)
  if ((Code !== undefined && Code !== 'Success') || !present || Number.isNaN(expiration.getTime())) throw new Error('creds_invalid')
  return { accessKeyId: AccessKeyId, secretAccessKey: SecretAccessKey, sessionToken: Token, expiration }
}

/**
 * Credential provider for the SDK over the parent's IMDSv2 relay (`readText`
 * returns its JSON: AccessKeyId, SecretAccessKey, Token, Expiration). Cached
 * until 5 minutes before Expiration; concurrent callers share one fetch.
 */
export function roleCredentials(readText, now = Date.now) {
  let cached = null
  let pending = null
  const load = async () => {
    let text
    try { text = await readText() } catch { throw new Error('creds_unavailable') }
    cached = credentialsFrom(text)
    return cached
  }
  return async () => {
    if (cached && cached.expiration.getTime() - now() > REFRESH_BEFORE_MS) return cached
    pending ??= load().finally(() => { pending = null })
    return pending
  }
}

// Default endpoint https://kms.eu-west-1.amazonaws.com: the enclave's /etc/hosts
// sends it to the local socat bridge, and TLS is verified here, not on the parent.
export function kmsClient(credentials) {
  return new KMSClient({
    region: REGION,
    credentials,
    maxAttempts: 2,
    // A stalled vsock proxy must fail the call rather than hang the boot.
    requestHandler: { connectionTimeout: 5000, requestTimeout: 15000 },
  })
}

/** The per-boot RSA-2048 recipient key: never exported, never persisted. */
export function recipientKeys() {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  return { privateKey, spki: publicKey.export({ type: 'spki', format: 'der' }) }
}

/**
 * `decrypt(keyArn, ciphertext, context)` -> Buffer plaintext (caller zeroes it).
 * `dataKey(keyArn, context)` -> { key, ciphertextBlob } (caller zeroes key).
 * `keyPolicy(keyArn)` -> the policy document text (no Recipient: it is public
 * to anyone who may read the key, and the parent could read it too).
 * `keys` is recipientKeys(); `attest` returns a fresh document for a
 * `{ publicKey }` request (the RSA SPKI, never a consent key); `log(op, fields)`
 * receives timings and outcomes only.
 */
export function createKms({ client, keys, attest, log = () => {} }) {
  const recipient = async () => ({
    KeyEncryptionAlgorithm: 'RSAES_OAEP_SHA_256',
    AttestationDocument: await attest({ publicKey: keys.spki }),
  })

  async function send(op, command) {
    const started = Date.now()
    try {
      const out = await client.send(command)
      log(op, { ms: Date.now() - started, ok: true })
      return out
    } catch (error) {
      log(op, { ms: Date.now() - started, ok: false })
      throw error
    }
  }

  // With a Recipient, key material may only arrive as CiphertextForRecipient.
  function opened(out) {
    if (out.Plaintext?.length) {
      out.Plaintext.fill(0)
      throw new Error('kms_plaintext_returned')
    }
    if (!out.CiphertextForRecipient?.length) throw new Error('kms_no_recipient_ciphertext')
    return openRecipientCms(out.CiphertextForRecipient, keys.privateKey)
  }

  async function decrypt(keyArn, ciphertext, context) {
    const command = new DecryptCommand({
      KeyId: keyArn, CiphertextBlob: ciphertext, EncryptionContext: context, Recipient: await recipient(),
    })
    return opened(await send('kms_decrypt', command))
  }

  async function dataKey(keyArn, context) {
    const command = new GenerateDataKeyCommand({
      KeyId: keyArn, KeySpec: 'AES_256', EncryptionContext: context, Recipient: await recipient(),
    })
    const out = await send('kms_data_key', command)
    const key = opened(out)
    if (key.length !== 32 || !out.CiphertextBlob?.length) {
      key.fill(0)
      throw new Error('kms_bad_data_key')
    }
    return { key, ciphertextBlob: Buffer.from(out.CiphertextBlob) }
  }

  async function keyPolicy(keyArn) {
    const out = await send('kms_key_policy', new GetKeyPolicyCommand({ KeyId: keyArn, PolicyName: 'default' }))
    if (typeof out.Policy !== 'string' || !out.Policy) throw new Error('kms_no_policy')
    return out.Policy
  }

  return { decrypt, dataKey, keyPolicy }
}
