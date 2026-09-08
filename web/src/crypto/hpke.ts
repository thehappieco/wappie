// HPKE (RFC 9180) base mode.
//
// Suite, frozen to match internal/crypto/seal: DHKEM(X25519, HKDF-SHA256) /
// HKDF-SHA256 / AES-256-GCM. Nothing is negotiated, so there is no downgrade to
// negotiate.
//
// Written against WebCrypto with no third-party dependency. The alternative was
// a crypto library from npm or Go compiled to WASM; both put the archive key
// behind code that is harder to audit than sixty lines, and the supply chain of
// a package that can read every message is not a small thing. WebCrypto's X25519
// is native in current browsers and in Node.
//
// The risk of a second implementation is that it is silently wrong: it opens
// everything it sealed itself and fails only against real data. That is what
// internal/crypto/seal/testdata/vectors.json is for — Go seals, this opens, and
// the negative cases fail if the AAD binding is missing.
//
// Both directions now, and the sending half needs the same treatment in
// reverse. It exists because pairing happens here: the browser generates a
// device archive key and seals it to each account that should be able to read
// that WhatsApp number, so the private half never crosses the wire. A grant
// sealed wrong is not a visible failure — it stores fine, and the archive it
// unlocks is unreadable forever. testdata/grant.json is the check: this seals,
// Go opens.

import { type Bytes, concat, i2osp2, encodeUTF8 } from './bytes'

const KEM_ID = 0x0020 // DHKEM(X25519, HKDF-SHA256)
const KDF_ID = 0x0001 // HKDF-SHA256
const AEAD_ID = 0x0002 // AES-256-GCM

const N_SECRET = 32 // KEM shared secret
const N_K = 32 // AES-256 key
const N_N = 12 // AES-GCM nonce
const HASH_LEN = 32 // SHA-256

/** The X25519 encapsulated key: a public key, 32 bytes. */
export const ENC_LEN = 32

const HPKE_V1 = encodeUTF8('HPKE-v1')
const KEM_SUITE = concat(encodeUTF8('KEM'), i2osp2(KEM_ID))
const HPKE_SUITE = concat(
  encodeUTF8('HPKE'),
  i2osp2(KEM_ID),
  i2osp2(KDF_ID),
  i2osp2(AEAD_ID),
)

// ---------------------------------------------------------------------------
// HKDF, split into Extract and Expand.
//
// WebCrypto's HKDF only offers the two fused together, and HPKE needs a PRK
// from one Extract fed into several Expands. So both halves are built on HMAC,
// which WebCrypto does expose.
// ---------------------------------------------------------------------------

async function hmac(key: Bytes, data: Bytes): Promise<Bytes> {
  const k = await crypto.subtle.importKey(
    'raw',
    key.length === 0 ? new Uint8Array(HASH_LEN) : key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, data))
}

async function extract(salt: Bytes, ikm: Bytes): Promise<Bytes> {
  return hmac(salt, ikm)
}

async function expand(prk: Bytes, info: Bytes, length: number): Promise<Bytes> {
  const out = new Uint8Array(length)
  let previous = new Uint8Array(0)
  let at = 0
  for (let counter = 1; at < length; counter++) {
    previous = await hmac(prk, concat(previous, info, new Uint8Array([counter])))
    const take = Math.min(previous.length, length - at)
    out.set(previous.subarray(0, take), at)
    at += take
  }
  return out
}

function labeledIKM(suite: Bytes, label: string, ikm: Bytes): Bytes {
  return concat(HPKE_V1, suite, encodeUTF8(label), ikm)
}

async function labeledExtract(
  suite: Bytes,
  salt: Bytes,
  label: string,
  ikm: Bytes,
): Promise<Bytes> {
  return extract(salt, labeledIKM(suite, label, ikm))
}

async function labeledExpand(
  suite: Bytes,
  prk: Bytes,
  label: string,
  info: Bytes,
  length: number,
): Promise<Bytes> {
  return expand(prk, concat(i2osp2(length), HPKE_V1, suite, encodeUTF8(label), info), length)
}

// ---------------------------------------------------------------------------
// X25519 over WebCrypto.
// ---------------------------------------------------------------------------

// WebCrypto imports an X25519 private key from PKCS#8 and nothing shorter, so
// the 32 raw bytes get the fixed DER prefix for id-X25519 wrapped round them.
const PKCS8_X25519_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
])

// The X25519 base point. Multiplying a private key by it is how the matching
// public key is recovered — WebCrypto will not export a public half from a key
// imported as private, and DHKEM needs the recipient public key in its context.
const BASE_POINT = new Uint8Array(32)
BASE_POINT[0] = 9

async function importPrivate(raw: Bytes): Promise<CryptoKey> {
  if (raw.length !== 32) throw new Error('uma chave privada X25519 tem 32 bytes')
  return crypto.subtle.importKey(
    'pkcs8',
    concat(PKCS8_X25519_PREFIX, raw),
    { name: 'X25519' },
    false,
    ['deriveBits'],
  )
}

async function importPublic(raw: Bytes): Promise<CryptoKey> {
  if (raw.length !== 32) throw new Error('uma chave pública X25519 tem 32 bytes')
  return crypto.subtle.importKey('raw', raw, { name: 'X25519' }, true, [])
}

async function dh(priv: CryptoKey, publicRaw: Bytes): Promise<Bytes> {
  const pub = await importPublic(publicRaw)
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: pub }, priv, 256))
}

/** publicFromPrivate recovers the public half of an X25519 key. */
export async function publicFromPrivate(privRaw: Bytes): Promise<Bytes> {
  return dh(await importPrivate(privRaw), BASE_POINT)
}

/**
 * PrivateKey is an imported archive key, kept as a CryptoKey so the raw bytes
 * can be dropped after unlocking.
 */
export interface PrivateKey {
  readonly key: CryptoKey
  /** The public half, which DHKEM needs in its context on every open. */
  readonly publicRaw: Bytes
}

/** KeyPair is a fresh X25519 pair: an archive key, or an account key. */
export interface KeyPair {
  publicKey: Bytes
  privateKey: Bytes
}

// WebCrypto exports an X25519 private key as PKCS#8 and nothing shorter, so the
// raw 32 bytes come out from under the same fixed DER prefix used to import one.
const PKCS8_PREFIX_LEN = 16

/**
 * generateKeyPair mints an X25519 pair with the private half in the clear.
 *
 * Extractable on purpose, and it is the only place in this client that is: both
 * callers have to hold the raw private key for a moment. An account wraps it
 * under a password; a device archive key is sealed to each account that may
 * read it and then dropped. Neither is ever transmitted.
 */
export async function generateKeyPair(): Promise<KeyPair> {
  const pair = (await crypto.subtle.generateKey({ name: 'X25519' }, true, [
    'deriveBits',
  ])) as CryptoKeyPair
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey))
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))
  return {
    publicKey: raw as Bytes,
    privateKey: pkcs8.slice(PKCS8_PREFIX_LEN) as Bytes,
  }
}

export async function importArchiveKey(privRaw: Bytes): Promise<PrivateKey> {
  const key = await importPrivate(privRaw)
  const publicRaw = await dh(key, BASE_POINT)
  return { key, publicRaw }
}

// ---------------------------------------------------------------------------
// DHKEM and the key schedule.
// ---------------------------------------------------------------------------

/**
 * encap generates an ephemeral keypair and derives the shared secret.
 *
 * A fresh key per seal, which is what makes the base mode safe without a
 * sequence number: no two seals share a context, so no nonce is ever reused.
 */
async function encap(publicRaw: Bytes): Promise<{ enc: Bytes; shared: Bytes }> {
  const ephemeral = (await crypto.subtle.generateKey({ name: 'X25519' }, true, [
    'deriveBits',
  ])) as CryptoKeyPair
  const enc = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey)) as Bytes
  const shared = await dh(ephemeral.privateKey, publicRaw)

  const context = concat(enc, publicRaw)
  const prk = await labeledExtract(KEM_SUITE, new Uint8Array(0), 'eae_prk', shared)
  return { enc, shared: await labeledExpand(KEM_SUITE, prk, 'shared_secret', context, N_SECRET) }
}

async function decap(priv: PrivateKey, enc: Bytes): Promise<Bytes> {
  const shared = await dh(priv.key, enc)
  const context = concat(enc, priv.publicRaw)
  const prk = await labeledExtract(KEM_SUITE, new Uint8Array(0), 'eae_prk', shared)
  return labeledExpand(KEM_SUITE, prk, 'shared_secret', context, N_SECRET)
}

interface Context {
  key: CryptoKey
  baseNonce: Bytes
}

async function keySchedule(shared: Bytes, info: Bytes, use: KeyUsage): Promise<Context> {
  const empty = new Uint8Array(0)
  const mode = new Uint8Array([0x00]) // base: no PSK, no sender authentication

  const pskIDHash = await labeledExtract(HPKE_SUITE, empty, 'psk_id_hash', empty)
  const infoHash = await labeledExtract(HPKE_SUITE, empty, 'info_hash', info)
  const context = concat(mode, pskIDHash, infoHash)

  const secret = await labeledExtract(HPKE_SUITE, shared, 'secret', empty)
  const keyBytes = await labeledExpand(HPKE_SUITE, secret, 'key', context, N_K)
  const baseNonce = await labeledExpand(HPKE_SUITE, secret, 'base_nonce', context, N_N)

  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, [use])
  return { key, baseNonce }
}

/**
 * seal produces a single-shot HPKE ciphertext.
 *
 * The mirror of open below, and the reason both live in one file: the key
 * schedule has to be identical in both directions, and two copies of it in
 * different files is how they drift.
 */
export async function seal(
  publicRaw: Bytes,
  info: Bytes,
  aad: Bytes,
  plaintext: Bytes,
): Promise<{ enc: Bytes; ciphertext: Bytes }> {
  const { enc, shared } = await encap(publicRaw)
  const ctx = await keySchedule(shared, info, 'encrypt')
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: ctx.baseNonce, additionalData: aad, tagLength: 128 },
      ctx.key,
      plaintext,
    ),
  ) as Bytes
  return { enc, ciphertext }
}

/**
 * open reverses a single-shot HPKE seal.
 *
 * Single-shot only: the sequence number stays at zero, so the nonce is the base
 * nonce unchanged. The server seals one value per context and never reuses one,
 * which is what makes that safe.
 */
export async function open(
  priv: PrivateKey,
  enc: Bytes,
  info: Bytes,
  aad: Bytes,
  ciphertext: Bytes,
): Promise<Bytes> {
  const shared = await decap(priv, enc)
  const ctx = await keySchedule(shared, info, 'decrypt')
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ctx.baseNonce, additionalData: aad, tagLength: 128 },
    ctx.key,
    ciphertext,
  )
  return new Uint8Array(plaintext)
}
