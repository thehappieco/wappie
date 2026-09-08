// An account: what a password turns into, and what that opens.
//
// The password never leaves this file. Argon2id turns it into a master key,
// which is split into two independent branches:
//
//   auth — sent to the server and stored there only as a slow hash. Proves who
//          you are. Useless for opening anything.
//   wrap — never transmitted. Unwraps the account's X25519 private key.
//
// That private key opens key grants, and each grant is one device's archive key.
// So signing in is what turns a sealed archive into a readable one, and nobody
// has to keep 32 bytes in a text file — which is precisely how the first
// archive this project stored was lost.
//
// # Why Argon2id here, and only here
//
// The rest of the client refuses crypto dependencies: HPKE and the archive
// format are sixty lines of WebCrypto, easier to audit than a package that can
// read every message. The password is the one place where that answer is wrong.
// WebCrypto offers PBKDF2 and nothing memory-hard, and the wrapped key sits in
// the server's database — which is the threat this whole system is built
// against. An attacker with a dump gets an offline target, and PBKDF2 is what
// makes that cheap. So one dependency, scoped to this file, doing one thing.

import { argon2id } from '@noble/hashes/argon2.js'

import { concat, encodeUTF8, fromBase64, toBase64, type Bytes } from './bytes'
import { generateKeyPair } from './hpke'

/** KDFParams mirror what the server stores, so the cost can be raised later. */
export interface KDFParams {
  alg: string
  /** Memory in KiB. */
  m: number
  /** Passes. */
  t: number
  p: number
}

export const defaultKDFParams: KDFParams = { alg: 'argon2id', m: 64 * 1024, t: 3, p: 1 }

const SALT_LEN = 16
const NONCE_LEN = 12

export class AccountError extends Error {
  constructor(
    message: string,
    readonly code: 'password' | 'kdf' | 'wrap' | 'recovery',
  ) {
    super(message)
    this.name = 'AccountError'
  }
}

/** Derived is the pair a password becomes. Neither half is the password. */
export interface Derived {
  /** Sent to the server, as base64. */
  authKey: string
  /** Stays here. Wraps and unwraps the account private key. */
  wrapKey: CryptoKey
}

/**
 * derive turns a password into the two branches.
 *
 * The split is HKDF with distinct labels rather than two halves of one output,
 * so the branches stay independent of each other even if the Argon2id output
 * length ever changes.
 */
export async function derive(password: string, salt: Bytes, params: KDFParams): Promise<Derived> {
  if (params.alg !== 'argon2id') {
    throw new AccountError(`derivação desconhecida: ${params.alg}`, 'kdf')
  }
  const master = await stretch(password, salt, params)

  const base = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveBits'])
  const branch = (label: string) =>
    crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(0),
        info: encodeUTF8(label),
      },
      base,
      256,
    )

  const [auth, wrap] = await Promise.all([
    branch('whatserver2/auth'),
    branch('whatserver2/wrap'),
  ])
  master.fill(0)

  return {
    authKey: toBase64(new Uint8Array(auth)),
    wrapKey: await crypto.subtle.importKey('raw', wrap, { name: 'AES-GCM' }, false, [
      'encrypt',
      'decrypt',
    ]),
  }
}

/**
 * stretch runs Argon2id, in a worker where there is one.
 *
 * The fallback is the same function called directly, which is what the test
 * suite uses: there is no Worker in Node, and a derivation that behaved
 * differently under test than in a browser would be worse than a slow one.
 */
async function stretch(password: string, salt: Bytes, params: KDFParams): Promise<Bytes> {
  const direct = () =>
    argon2id(encodeUTF8(password), salt, {
      m: params.m,
      t: params.t,
      p: params.p,
      dkLen: 32,
    }) as Bytes

  if (typeof Worker === 'undefined') return direct()

  try {
    const worker = new Worker(new URL('./kdf.worker.ts', import.meta.url), { type: 'module' })
    try {
      return await new Promise<Bytes>((resolve, reject) => {
        worker.onmessage = (event: MessageEvent<{ ok: boolean; master?: Bytes; error?: string }>) => {
          if (event.data.ok && event.data.master) resolve(event.data.master)
          else reject(new AccountError(event.data.error ?? 'a derivação falhou', 'kdf'))
        }
        worker.onerror = () => reject(new AccountError('a derivação falhou', 'kdf'))
        worker.postMessage({ password, salt, m: params.m, t: params.t, p: params.p })
      })
    } finally {
      worker.terminate()
    }
  } catch {
    // No module workers, or the bundle could not load one. Slower and
    // blocking, but a login that works beats one that does not.
    return direct()
  }
}

export function freshSalt(): Bytes {
  return crypto.getRandomValues(new Uint8Array(SALT_LEN))
}

// ---------------------------------------------------------------------------
// The account keypair
// ---------------------------------------------------------------------------

export interface AccountKeys {
  /** The public half. Grants are sealed to it, so the server holds it. */
  publicKey: Bytes
  /** The private half, raw. Held only long enough to be wrapped. */
  privateKey: Bytes
}

/** generateAccountKeys creates the keypair a person's grants are sealed to. */
export async function generateAccountKeys(): Promise<AccountKeys> {
  return generateKeyPair()
}

/**
 * The wrap is bound to the account it belongs to.
 *
 * Every other seal in this system carries the row it was made for as
 * additional data, so a blob moved between rows fails to open. The account
 * wrap did not: whoever could write the users table could swap one person's
 * wrapped_usk for another's, and the tag would not object. It would still not
 * open — the wrong password — but "does not open" and "was tampered with"
 * should not look the same, and the rule should not have one exception.
 *
 * Version 2 prefixes a byte and binds to the address the account signed up
 * with, which is the one thing about an account both sides know before it
 * exists. Version 1 blobs are the bare nonce ‖ ciphertext and are still
 * opened, so nobody is locked out by the change; a client that opens one
 * re-wraps it on the way in.
 */
const WRAP_V2 = 0x02

function wrapAAD(email: string): Bytes {
  return encodeUTF8('whatserver2/usk|' + email.trim().toLowerCase())
}

/** wrapPrivateKey seals the account private key under a derived key. */
export async function wrapPrivateKey(
  privateKey: Bytes,
  under: CryptoKey,
  email: string,
): Promise<Bytes> {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN))
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: wrapAAD(email) },
      under,
      privateKey,
    ),
  )
  return concat(new Uint8Array([WRAP_V2]), nonce, sealed)
}

/** Unwrapped is the key, and whether the blob it came from needs re-wrapping. */
export interface Unwrapped {
  privateKey: Bytes
  /** True for a version 1 blob, which carries no binding. */
  stale: boolean
}

/**
 * unwrapPrivateKey reverses it. A wrong password fails here and nowhere else.
 *
 * A version 2 blob is tried under its binding first; a blob that does not
 * open that way is tried as version 1. A version 1 blob whose first byte
 * happens to be the version marker costs one extra failed decryption and
 * nothing else.
 */
export async function unwrapPrivateKey(
  blob: Bytes,
  under: CryptoKey,
  email: string,
): Promise<Unwrapped> {
  if (blob.length > NONCE_LEN + 1 && blob[0] === WRAP_V2) {
    try {
      const plain = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: blob.subarray(1, 1 + NONCE_LEN),
          additionalData: wrapAAD(email),
        },
        under,
        blob.subarray(1 + NONCE_LEN),
      )
      return { privateKey: new Uint8Array(plain) as Bytes, stale: false }
    } catch {
      // Not a v2 blob for this account, or the wrong key. Try v1 below.
    }
  }
  if (blob.length <= NONCE_LEN) throw new AccountError('a chave guardada está truncada', 'wrap')
  try {
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: blob.subarray(0, NONCE_LEN) },
      under,
      blob.subarray(NONCE_LEN),
    )
    return { privateKey: new Uint8Array(plain) as Bytes, stale: true }
  } catch {
    throw new AccountError('senha incorreta', 'wrap')
  }
}

// ---------------------------------------------------------------------------
// The recovery code
// ---------------------------------------------------------------------------

// Crockford's base32: no I, L, O or U, so nothing reads as a digit and back.
// A code is written down by hand and typed back by hand, and this alphabet is
// what stops a 0/O or 1/l from costing somebody their archive.
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
const CODE_GROUPS = 6
const GROUP_LEN = 5

/**
 * newRecoveryCode returns a 150-bit code, grouped for transcription.
 *
 * It is the second way back into an account, and the only one that survives a
 * forgotten password. The schema has had a column for this since the first
 * migration and nothing ever wrote to it; the archive that was lost is what
 * that omission cost.
 */
export function newRecoveryCode(): string {
  const raw = crypto.getRandomValues(new Uint8Array(CODE_GROUPS * GROUP_LEN))
  const chars = Array.from(raw, (b) => ALPHABET[b % ALPHABET.length])
  const groups: string[] = []
  for (let i = 0; i < CODE_GROUPS; i++) {
    groups.push(chars.slice(i * GROUP_LEN, (i + 1) * GROUP_LEN).join(''))
  }
  return groups.join('-')
}

/** normaliseRecoveryCode accepts what somebody actually types back. */
export function normaliseRecoveryCode(code: string): string {
  const cleaned = code
    .toUpperCase()
    .replace(/[^0-9A-Z]/g, '')
    // The letters the alphabet leaves out, mapped to what they were meant to be.
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1')
    .replace(/U/g, 'V')
  if (cleaned.length !== CODE_GROUPS * GROUP_LEN) {
    throw new AccountError(
      `um código de recuperação tem ${CODE_GROUPS * GROUP_LEN} caracteres`,
      'recovery',
    )
  }
  const groups: string[] = []
  for (let i = 0; i < CODE_GROUPS; i++) {
    groups.push(cleaned.slice(i * GROUP_LEN, (i + 1) * GROUP_LEN))
  }
  return groups.join('-')
}

/**
 * recoveryKey derives the wrapping key for a recovery code.
 *
 * Cheaper than the password derivation on purpose: the code is 150 random bits,
 * so there is nothing to slow an attacker down for. Making it as slow as a
 * password would only punish the person using it.
 *
 * Two branches, like the password: this one never leaves the page, and
 * recoveryProof travels. They are independent HKDF outputs, so holding the
 * proof — which the server stores as a hash — says nothing about this key.
 */
export async function recoveryKey(code: string): Promise<CryptoKey> {
  const bits = await recoveryBranch(code, 'whatserver2/recovery')
  return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

/**
 * recoveryProof is the branch of the code that is sent to the server.
 *
 * It is what the server hands the recovery wrap back against. Without it the
 * wrap would be given to anyone who asked, which is safe against the 150 bits
 * in theory and careless in practice: it makes a database leak public.
 */
export async function recoveryProof(code: string): Promise<string> {
  return toBase64(new Uint8Array(await recoveryBranch(code, 'whatserver2/recovery-auth')))
}

async function recoveryBranch(code: string, label: string): Promise<ArrayBuffer> {
  const material = await crypto.subtle.importKey(
    'raw',
    encodeUTF8(normaliseRecoveryCode(code)),
    'HKDF',
    false,
    ['deriveBits'],
  )
  return crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: encodeUTF8(label),
    },
    material,
    256,
  )
}

export { toBase64, fromBase64 }
