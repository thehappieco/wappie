import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath, URL } from 'node:url'

import {
  derive,
  freshSalt,
  generateAccountKeys,
  newRecoveryCode,
  normaliseRecoveryCode,
  recoveryKey,
  recoveryProof,
  unwrapPrivateKey,
  wrapPrivateKey,
  AccountError,
  defaultKDFParams,
} from '../src/crypto/account'
import { fromBase64, parseUUID } from '../src/crypto/bytes'
import { importArchiveKey } from '../src/crypto/hpke'
import { grantRow, Kind, openDirect, SealError } from '../src/crypto/seal'

// The password is the root of everything a person can open, and a grant is what
// it opens. Both derivations exist twice — once in Go, once here — and both are
// silent when wrong: a login that works and an archive that will not open.

// Deliberately cheap. The real parameters take seconds by design; a test suite
// that ran them would be slow enough that somebody would turn it off.
const cheap = { alg: 'argon2id', m: 8, t: 1, p: 1 }

describe('what a password becomes', () => {
  it('produces two branches, and only one of them travels', async () => {
    const salt = freshSalt()
    const a = await derive('correct horse battery staple', salt, cheap)
    const b = await derive('correct horse battery staple', salt, cheap)
    expect(a.authKey).toBe(b.authKey)

    // The wrap key is a CryptoKey and not extractable, so nothing — including
    // this code — can read its bytes back out. The auth key is a string
    // because it is the half that is meant to leave.
    expect(typeof a.authKey).toBe('string')
    expect(a.wrapKey.extractable).toBe(false)
  })

  it('gives a different auth key for a different password', async () => {
    const salt = freshSalt()
    const right = await derive('right', salt, cheap)
    const wrong = await derive('wrong', salt, cheap)
    expect(right.authKey).not.toBe(wrong.authKey)
  })

  it('gives a different auth key under a different salt', async () => {
    const one = await derive('same', freshSalt(), cheap)
    const two = await derive('same', freshSalt(), cheap)
    expect(one.authKey).not.toBe(two.authKey)
  })

  it('refuses a derivation it does not know', async () => {
    await expect(derive('x', freshSalt(), { ...cheap, alg: 'scrypt' })).rejects.toThrow(AccountError)
  })

  it('agrees with the parameters the server hands out', () => {
    // Not a preference: the browser must reproduce exactly what was recorded
    // at signup, and a mismatch is a login that fails for nobody's fault.
    expect(defaultKDFParams.alg).toBe('argon2id')
    expect(defaultKDFParams.m).toBe(64 * 1024)
    expect(defaultKDFParams.t).toBe(3)
  })
})

describe('the account key', () => {
  it('survives a wrap and an unwrap', async () => {
    const keys = await generateAccountKeys()
    const derived = await derive('senha correta', freshSalt(), cheap)

    const wrapped = await wrapPrivateKey(keys.privateKey, derived.wrapKey, 'ana@example.com')
    const { privateKey: back, stale } = await unwrapPrivateKey(wrapped, derived.wrapKey, 'ana@example.com')
    expect(stale).toBe(false)
    expect(Array.from(back)).toEqual(Array.from(keys.privateKey))
    expect(back.length).toBe(32)
  })

  it('does not unwrap under the wrong password', async () => {
    const keys = await generateAccountKeys()
    const salt = freshSalt()
    const right = await derive('right', salt, cheap)
    const wrong = await derive('wrong', salt, cheap)

    const wrapped = await wrapPrivateKey(keys.privateKey, right.wrapKey, 'a@x.io')
    // This is where a wrong password is detected, and the only place. The
    // server compared a hash; this compares nothing — it just fails to open.
    await expect(unwrapPrivateKey(wrapped, wrong.wrapKey, 'a@x.io')).rejects.toThrow(/senha/)
  })

  it('is bound to the address, so a wrap moved between accounts does not open', async () => {
    const keys = await generateAccountKeys()
    const derived = await derive('correct horse', freshSalt(), cheap)
    const wrapped = await wrapPrivateKey(keys.privateKey, derived.wrapKey, 'ana@example.com')
    await expect(unwrapPrivateKey(wrapped, derived.wrapKey, 'bob@example.com')).rejects.toThrow(
      AccountError,
    )
    // The address is normalised the way the server normalises it.
    const back = await unwrapPrivateKey(wrapped, derived.wrapKey, '  Ana@Example.com ')
    expect(Array.from(back.privateKey)).toEqual(Array.from(keys.privateKey))
  })

  it('still opens a wrap from before the binding, and says it is stale', async () => {
    const keys = await generateAccountKeys()
    const derived = await derive('correct horse', freshSalt(), cheap)
    // A version 1 blob: bare nonce ‖ ciphertext, no additional data.
    const nonce = crypto.getRandomValues(new Uint8Array(12))
    const sealed = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, derived.wrapKey, keys.privateKey),
    )
    const v1 = new Uint8Array(nonce.length + sealed.length)
    v1.set(nonce)
    v1.set(sealed, nonce.length)
    const back = await unwrapPrivateKey(v1, derived.wrapKey, 'ana@example.com')
    expect(back.stale).toBe(true)
    expect(Array.from(back.privateKey)).toEqual(Array.from(keys.privateKey))
  })

  it('produces a public half the rest of the crypto accepts', async () => {
    const keys = await generateAccountKeys()
    const imported = await importArchiveKey(keys.privateKey)
    expect(Array.from(imported.publicRaw)).toEqual(Array.from(keys.publicKey))
  })
})

describe('the recovery code', () => {
  it('opens the same key the password does', async () => {
    const keys = await generateAccountKeys()
    const code = newRecoveryCode()

    const wrapped = await wrapPrivateKey(keys.privateKey, await recoveryKey(code), 'a@x.io')
    const back = await unwrapPrivateKey(wrapped, await recoveryKey(code), 'a@x.io')
    expect(Array.from(back.privateKey)).toEqual(Array.from(keys.privateKey))
  })

  it('forgives how somebody actually writes it down', async () => {
    const code = newRecoveryCode()
    // Lower case, spaces instead of dashes, and the characters the alphabet
    // leaves out because they are the ones people confuse.
    const mangled = code.toLowerCase().replace(/-/g, ' ')
    expect(normaliseRecoveryCode(mangled)).toBe(code)

    const keys = await generateAccountKeys()
    const wrapped = await wrapPrivateKey(keys.privateKey, await recoveryKey(code), 'a@x.io')
    const back = await unwrapPrivateKey(wrapped, await recoveryKey(mangled), 'a@x.io')
    expect(Array.from(back.privateKey)).toEqual(Array.from(keys.privateKey))
  })

  it('refuses a code of the wrong length rather than deriving nonsense', () => {
    expect(() => normaliseRecoveryCode('ABC-DEF')).toThrow(AccountError)
  })

  it('is not the same twice', () => {
    expect(newRecoveryCode()).not.toBe(newRecoveryCode())
  })

  it('splits into a proof that travels and a key that does not', async () => {
    const code = newRecoveryCode()
    const proof = await recoveryProof(code)
    // Stable, so the server can hash it once and compare later, and
    // forgiving of transcription the same way the key is.
    expect(await recoveryProof(code.toLowerCase().replace(/-/g, ' '))).toBe(proof)
    expect(await recoveryProof(newRecoveryCode())).not.toBe(proof)

    // The proof is not the wrapping key under another name: a wrap made with
    // the key does not open under a key built from the proof's bytes.
    const keys = await generateAccountKeys()
    const wrapped = await wrapPrivateKey(keys.privateKey, await recoveryKey(code), 'a@x.io')
    const fromProof = await crypto.subtle.importKey(
      'raw',
      fromBase64(proof),
      { name: 'AES-GCM' },
      false,
      ['decrypt'],
    )
    await expect(unwrapPrivateKey(wrapped, fromProof, 'a@x.io')).rejects.toThrow(AccountError)
  })
})

// The grant is what turns a sealed archive into a readable one, and the row it
// binds to is derived on both sides from (device, user, epoch). Getting that
// derivation wrong fails authentication with the correct key in hand — which
// looks like tampering rather than like a bug.
interface Vectors {
  tenant: string
  device: string
  private_key: string
  grant: { user: string; epoch: number; sealed: string; device_key: string }
}

const vectors: Vectors = JSON.parse(
  readFileSync(
    fileURLToPath(new URL('../../internal/crypto/seal/testdata/vectors.json', import.meta.url)),
    'utf8',
  ),
)

describe('a key grant sealed by the server', () => {
  it('opens to the device archive key', async () => {
    const tenant = parseUUID(vectors.tenant)
    const device = parseUUID(vectors.device)
    const user = parseUUID(vectors.grant.user)
    const account = await importArchiveKey(fromBase64(vectors.private_key))

    const row = await grantRow(tenant, device, user, vectors.grant.epoch)
    const opened = await openDirect(
      account,
      Kind.DeviceGrant,
      tenant,
      row,
      fromBase64(vectors.grant.sealed),
    )
    expect(Buffer.from(opened).toString('base64')).toBe(vectors.grant.device_key)
    expect(opened.length).toBe(32)
  })

  it('does not open as somebody else', async () => {
    const tenant = parseUUID(vectors.tenant)
    const device = parseUUID(vectors.device)
    const account = await importArchiveKey(fromBase64(vectors.private_key))

    // A grant issued to one account presented as another's. Binding the user
    // into the row is what refuses it.
    const other = parseUUID('00000000-0000-4000-8000-0000000000aa')
    const row = await grantRow(tenant, device, other, vectors.grant.epoch)
    await expect(
      openDirect(account, Kind.DeviceGrant, tenant, row, fromBase64(vectors.grant.sealed)),
    ).rejects.toThrow(SealError)
  })

  it('does not open for another device', async () => {
    const tenant = parseUUID(vectors.tenant)
    const user = parseUUID(vectors.grant.user)
    const account = await importArchiveKey(fromBase64(vectors.private_key))

    const other = parseUUID('00000000-0000-4000-8000-0000000000bb')
    const row = await grantRow(tenant, other, user, vectors.grant.epoch)
    await expect(
      openDirect(account, Kind.DeviceGrant, tenant, row, fromBase64(vectors.grant.sealed)),
    ).rejects.toThrow(SealError)
  })
})
