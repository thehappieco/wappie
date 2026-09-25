// kms.mjs and cms.mjs: KMS answers with Recipient arrive as CMS EnvelopedData
// (RSAES-OAEP-SHA256 key transport, AES-256-CBC content). The envelopes here
// are built two ways, independently of the opener: with asn1js (definite
// lengths) and, when an OpenSSL binary is present, with `openssl cms -stream`
// (BER with indefinite lengths and chunked OCTET STRINGs, as KMS sends).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { constants, createCipheriv, generateKeyPairSync, publicEncrypt, randomBytes } from 'node:crypto'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import * as asn1js from 'asn1js'
import { openRecipientCms } from '../cms.mjs'
import { codeOf, createKms, recipientKeys, refusedByKms, roleCredentials } from '../kms.mjs'

const OID = { data: '1.2.840.113549.1.7.1', enveloped: '1.2.840.113549.1.7.3', oaep: '1.2.840.113549.1.1.7', mgf1: '1.2.840.113549.1.1.8', sha256: '2.16.840.1.101.3.4.2.1', aes256cbc: '2.16.840.1.101.3.4.1.42' }
const alg = (id, params) => new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: id }), ...(params ? [params] : [])] })
const ctx = (tag, inner) => new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: tag }, value: [inner] })

/** EnvelopedData the way KMS shapes it (subjectKeyIdentifier rid, OAEP-SHA256 params). */
function envelope(publicKey, plaintext, { hash = OID.sha256, content = OID.aes256cbc, recipients = 1 } = {}) {
  const cek = randomBytes(32), iv = randomBytes(16)
  const cipher = createCipheriv('aes-256-cbc', cek, iv)
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()])
  const wrapped = publicEncrypt({ key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, cek)
  const oaepParams = new asn1js.Sequence({ value: [ctx(0, alg(hash)), ctx(1, alg(OID.mgf1, alg(hash)))] })
  const recipient = new asn1js.Sequence({ value: [
    new asn1js.Integer({ value: 2 }),
    new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 }, valueHex: randomBytes(20) }),
    alg(OID.oaep, oaepParams),
    new asn1js.OctetString({ valueHex: wrapped }),
  ] })
  const content_ = new asn1js.Sequence({ value: [
    new asn1js.ObjectIdentifier({ value: OID.data }), alg(content, new asn1js.OctetString({ valueHex: iv })),
    new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 }, valueHex: encrypted }),
  ] })
  const enveloped = new asn1js.Sequence({ value: [new asn1js.Integer({ value: 2 }), new asn1js.Set({ value: Array(recipients).fill(recipient) }), content_] })
  return Buffer.from(new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: OID.enveloped }), ctx(0, enveloped)] }).toBER(false))
}

test('cms: opens a KMS-shaped envelope; tampering, wrong key, wrong algorithms and trailing bytes all fail with fixed codes', () => {
  const keys = recipientKeys()
  const publicKey = keys.privateKey // publicEncrypt derives the public half
  const secret = randomBytes(32)
  assert.deepEqual(openRecipientCms(envelope(publicKey, secret), keys.privateKey), secret)
  const other = recipientKeys()
  assert.throws(() => openRecipientCms(envelope(other.privateKey, secret), keys.privateKey), { message: 'cms_decrypt' })
  const flipped = envelope(publicKey, secret); flipped[flipped.length - 5] ^= 1
  assert.throws(() => openRecipientCms(flipped, keys.privateKey), { message: 'cms_decrypt' })
  assert.throws(() => openRecipientCms(envelope(publicKey, secret, { hash: '1.3.14.3.2.26' }), keys.privateKey), { message: 'cms_oaep_hash' })
  assert.throws(() => openRecipientCms(envelope(publicKey, secret, { content: '2.16.840.1.101.3.4.1.2' }), keys.privateKey), { message: 'cms_not_aes256cbc' })
  assert.throws(() => openRecipientCms(envelope(publicKey, secret, { recipients: 2 }), keys.privateKey), { message: 'cms_recipients' })
  assert.throws(() => openRecipientCms(Buffer.concat([envelope(publicKey, secret), Buffer.from([0])]), keys.privateKey), { message: 'cms_parse' })
  assert.throws(() => openRecipientCms(randomBytes(64), keys.privateKey), { message: 'cms_parse' })
})

test('cms: opens OpenSSL streaming BER (indefinite lengths, chunked octets)', async t => {
  try { execFileSync('openssl', ['version'], { stdio: 'pipe' }) } catch { t.skip('no openssl'); return }
  const dir = await mkdtemp(join(tmpdir(), 'wappie-cms-'))
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  // openssl cms wants a certificate for the recipient; x509.mjs signs only EC, so let openssl make it.
  await writeFile(join(dir, 'key.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }))
  execFileSync('openssl', ['req', '-x509', '-key', join(dir, 'key.pem'), '-subj', '/CN=r', '-days', '1', '-out', join(dir, 'cert.pem')], { stdio: 'pipe' })
  const secret = randomBytes(32)
  await writeFile(join(dir, 'in.bin'), secret)
  try {
    execFileSync('openssl', ['cms', '-encrypt', '-binary', '-stream', '-aes256', '-in', join(dir, 'in.bin'), '-recip', join(dir, 'cert.pem'), '-keyid',
      '-keyopt', 'rsa_padding_mode:oaep', '-keyopt', 'rsa_oaep_md:sha256', '-keyopt', 'rsa_mgf1_md:sha256', '-outform', 'DER', '-out', join(dir, 'out.ber')], { stdio: 'pipe' })
  } catch { t.skip('this openssl cannot write OAEP CMS'); return }
  const ber = await readFile(join(dir, 'out.ber'))
  assert.deepEqual(openRecipientCms(ber, privateKey), secret)
})

test('kms: every call carries a fresh attested Recipient, Decrypt pins KeyId, Plaintext is refused, and codes are log-safe', async () => {
  const keys = recipientKeys()
  const sent = []
  let attested = 0
  const answer = { Decrypt: null, GenerateDataKey: null, GetKeyPolicy: { Policy: '{"a":1}' } }
  const client = { async send(command) { sent.push(command); const name = command.constructor.name.replace('Command', ''); if (answer[name] instanceof Error) throw answer[name]; return answer[name] } }
  const kms = createKms({ client, keys, attest: async ({ publicKey }) => { attested++; assert.deepEqual(publicKey, keys.spki); return Buffer.from('doc') } })
  const secret = randomBytes(32)
  answer.Decrypt = { CiphertextForRecipient: envelope(keys.privateKey, secret) }
  assert.deepEqual(await kms.decrypt('arn:aws:kms:eu-west-1:1:key/a', Buffer.from('blob'), { purpose: 'p' }), secret)
  assert.equal(sent[0].input.KeyId, 'arn:aws:kms:eu-west-1:1:key/a')
  assert.deepEqual(sent[0].input.EncryptionContext, { purpose: 'p' })
  assert.equal(sent[0].input.Recipient.KeyEncryptionAlgorithm, 'RSAES_OAEP_SHA_256')
  answer.GenerateDataKey = { CiphertextForRecipient: envelope(keys.privateKey, secret), CiphertextBlob: Buffer.from('blob') }
  const dataKey = await kms.dataKey('arn:aws:kms:eu-west-1:1:key/a', { purpose: 'p' })
  assert.deepEqual(dataKey.key, secret)
  assert.equal(sent[1].input.KeySpec, 'AES_256')
  assert.equal(attested, 2, 'a fresh document per call')
  assert.equal(await kms.keyPolicy('arn:aws:kms:eu-west-1:1:key/a'), '{"a":1}')
  assert.equal(sent[2].input.PolicyName, 'default')
  assert.equal(sent[2].input.Recipient, undefined)
  answer.Decrypt = { Plaintext: Buffer.from(secret), CiphertextForRecipient: envelope(keys.privateKey, secret) }
  await assert.rejects(kms.decrypt('k', Buffer.from('b'), {}), { message: 'kms_plaintext_returned' })
  answer.Decrypt = Object.assign(new Error('User is not authorized'), { name: 'AccessDeniedException', $fault: 'client' })
  const error = await kms.decrypt('k', Buffer.from('b'), {}).catch(caught => caught)
  assert.equal(codeOf(error), 'kms_access_denied_exception')
  assert.equal(refusedByKms(error), true)
  assert.equal(codeOf(Object.assign(new Error('connect ECONNREFUSED 127.0.0.2:443'), { code: 'ECONNREFUSED' })), 'econnrefused')
  assert.equal(codeOf(new Error('Some message with secrets inside')), 'error')
})

test('role credentials: cached until five minutes before expiry, refused when malformed', async () => {
  let at = 0, reads = 0
  const body = expires => JSON.stringify({ Code: 'Success', AccessKeyId: 'AKIA', SecretAccessKey: 's', Token: 't', Expiration: new Date(expires).toISOString() })
  const provider = roleCredentials(async () => { reads++; return body(Date.parse('2026-09-25T12:00:00Z')) }, () => at)
  at = Date.parse('2026-09-25T11:00:00Z')
  await provider(); await provider()
  assert.equal(reads, 1)
  at = Date.parse('2026-09-25T11:56:00Z')
  await provider()
  assert.equal(reads, 2)
  await assert.rejects(roleCredentials(async () => '{"Code":"Failure"}')(), { message: 'creds_invalid' })
  await assert.rejects(roleCredentials(async () => { throw new Error('x') })(), { message: 'creds_unavailable' })
})
