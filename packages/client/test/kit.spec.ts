import { describe, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath, URL } from 'node:url'

import {
  AccountError,
  defaultKDFParams,
  derive,
  freshSalt,
  generateAccountKeys,
  newRecoveryCode,
  normaliseRecoveryCode,
  recoveryKey,
  recoveryProof,
  unwrapPrivateKey,
  wrapPrivateKey,
} from '../src/crypto/account'
import { validBrowserKeyEnvelope, sealBrowserAccountKey } from '../src/crypto/browserAccount'
import { formatUUID, parseUUID, type Bytes } from '../src/crypto/bytes'
import { importArchiveKey, publicFromPrivate, type PrivateKey } from '../src/crypto/hpke'
import { unwrapPasskey, wrapPasskey } from '../src/crypto/passkey'
import { ContentKey, draftRow, grantRow, kindName, openDirect, sealDirect } from '../src/crypto/seal'

// The shared kit's vectors, run through this client's own modules. The kit
// proves its code reproduces what this client and the Go server sealed and
// wrapped before the move; these prove the wrappers bind Wappie's profile
// (magic, labels, kind names, the email binding, the passkey AAD) and keep
// this client's messages. test/kit holds copies taken by test/kit/copy.mjs
// from the kit version the Go module requires; Go's TestFixturesMatchTheKit
// checks they still match it.

interface Case {
  id: string
  op: string
  langs?: string[]
  // Vector inputs and outputs are loosely shaped JSON by design.
  in: any
  out?: any
  error?: string
  reason?: string
}

interface VectorFile {
  format: string
  keys?: Record<string, { private_key_b64: string; public_key_b64: string }>
  cases: Case[]
}

function load(name: string): VectorFile {
  const f = JSON.parse(readFileSync(fileURLToPath(new URL(`./kit/${name}`, import.meta.url)), 'utf8')) as VectorFile
  if (f.format !== 'thehappieco-kit-vectors/1' || f.cases.length === 0) throw new Error(`${name}: not a kit vector file`)
  return f
}

const forTS = (c: Case) => !c.langs || c.langs.includes('ts')
const b64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64')) as Bytes
const toB64 = (b: Uint8Array) => Buffer.from(b).toString('base64')
const u = parseUUID
const aesKey = (raw: Bytes) => crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])

const PKCS8_X25519 = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20])

/**
 * withDraws runs fn with crypto.getRandomValues serving the recorded bytes and
 * X25519 generateKey importing the recorded private keys, in order, and
 * checks fn drew exactly those: how a recorded seal is replayed byte for byte.
 */
async function withDraws<T>(draws: { bytes?: Bytes[]; x25519?: Bytes[] }, fn: () => Promise<T> | T): Promise<T> {
  const bytes = [...(draws.bytes ?? [])]
  const x25519 = [...(draws.x25519 ?? [])]
  const generate = crypto.subtle.generateKey.bind(crypto.subtle)
  const getRandom = vi.spyOn(crypto, 'getRandomValues').mockImplementation(((array: ArrayBufferView) => {
    const next = bytes.shift()
    if (!next || next.length !== array.byteLength) throw new Error(`unexpected draw of ${array.byteLength} bytes`)
    new Uint8Array(array.buffer, array.byteOffset, array.byteLength).set(next)
    return array
  }) as never)
  const generateKey = vi.spyOn(crypto.subtle, 'generateKey').mockImplementation((async (algorithm: AlgorithmIdentifier, extractable: boolean, usages: KeyUsage[]) => {
    const name = typeof algorithm === 'string' ? algorithm : algorithm.name
    if (name !== 'X25519') return generate(algorithm as never, extractable, usages)
    const raw = x25519.shift()
    if (!raw) throw new Error('unexpected X25519 key generation')
    const privateKey = await crypto.subtle.importKey('pkcs8', new Uint8Array([...PKCS8_X25519, ...raw]), { name: 'X25519' }, extractable, usages)
    const publicKey = await crypto.subtle.importKey('raw', await publicFromPrivate(raw), { name: 'X25519' }, true, [])
    return { privateKey, publicKey }
  }) as never)
  try {
    const value = await fn()
    expect(bytes.length, 'recorded bytes left undrawn').toBe(0)
    expect(x25519.length, 'recorded X25519 keys left unused').toBe(0)
    return value
  } finally {
    getRandom.mockRestore()
    generateKey.mockRestore()
  }
}

async function failure(fn: () => unknown): Promise<unknown> {
  try {
    await fn()
  } catch (err) {
    return err
  }
  return undefined
}

// The kit's derivations these wrappers do not expose (the envelope's AAD, info
// and bare rows, the content key's row and id, the account and passkey AADs).
// The kit's tests run them; every envelope and wrap below depends on them.
const notWrapped = new Set(['seal.info', 'seal.aad', 'seal.row', 'seal.content_key_row', 'seal.content_key_id', 'account.wrap_aad', 'passkey.aad'])

function cases(f: VectorFile): Case[] {
  return f.cases.filter(c => forTS(c) && !notWrapped.has(c.op))
}

for (const name of ['seal-go.json', 'seal-ts.json']) {
  const f = load(name)
  describe(`kit ${name}`, async () => {
    const keys = new Map<string, { priv: PrivateKey; pub: Bytes }>()
    for (const [id, k] of Object.entries(f.keys ?? {})) keys.set(id, { priv: await importArchiveKey(b64(k.private_key_b64)), pub: b64(k.public_key_b64) })
    for (const c of cases(f)) {
      it(c.id, async () => {
        const i = c.in
        const priv = keys.get(i.key)?.priv as PrivateKey
        const code = async (fn: () => unknown) => ((await failure(fn)) as { code?: string } | undefined)?.code ?? 'none'
        switch (c.op) {
          case 'seal.generate_key_pair':
            expect(toB64(await publicFromPrivate(b64(c.out.private_key_b64)))).toBe(c.out.public_key_b64)
            return
          case 'seal.kind_name':
            expect(kindName(i.kind)).toBe(c.out.name)
            return
          case 'seal.grant_row':
            expect(formatUUID(await grantRow(u(i.tenant), u(i.device), u(i.user), i.epoch))).toBe(c.out.row)
            return
          case 'wappie.draft_row':
            expect(formatUUID(await draftRow(u(i.tenant), u(i.device), u(i.connection), u(i.draft), i.reply ? u(i.reply) : null, i.chat_key))).toBe(c.out.row)
            return
          case 'seal.seal_direct':
            if (c.error) {
              expect(await code(() => sealDirect(keys.get(i.key)?.pub ?? new Uint8Array(0) as Bytes, i.kind, u(i.tenant), u(i.row), i.epoch, b64(i.plaintext_b64)))).toBe(c.error)
              return
            }
            expect(toB64(await openDirect(priv, i.kind, u(i.tenant), u(i.row), b64(c.out.envelope_b64)))).toBe(i.plaintext_b64)
            if (i.ephemeral_private_key_b64) {
              const again = await withDraws({ x25519: [b64(i.ephemeral_private_key_b64)] },
                () => sealDirect(keys.get(i.key)!.pub, i.kind, u(i.tenant), u(i.row), i.epoch, b64(i.plaintext_b64)))
              expect(toB64(again)).toBe(c.out.envelope_b64)
            }
            return
          case 'seal.open_direct': {
            const attempt = () => openDirect(priv, i.kind, u(i.tenant), u(i.row), b64(i.envelope_b64))
            if (c.error) expect(await code(attempt)).toBe(c.error)
            else expect(toB64(await attempt())).toBe(c.out.plaintext_b64)
            return
          }
          case 'seal.new_content_key': {
            const key = await ContentKey.unwrap(priv, u(i.tenant), u(i.device), i.id, b64(c.out.sealed_b64))
            expect([key.id, key.epoch]).toEqual([i.id, i.epoch])
            return
          }
          case 'seal.open_content_key': {
            const attempt = () => ContentKey.unwrap(priv, u(i.tenant), u(i.device), i.id, b64(i.sealed_b64))
            if (c.error) expect(await code(attempt)).toBe(c.error)
            else expect((await attempt()).epoch).toBe(c.out.epoch)
            return
          }
          case 'seal.seal_batch':
          case 'seal.open_batch': {
            const ck = await ContentKey.unwrap(priv, u(i.content_key.tenant), u(i.content_key.device), i.content_key.id, b64(i.content_key.sealed_b64))
            if (c.op === 'seal.seal_batch') {
              expect(toB64(await ck.open(i.kind, u(i.tenant), u(i.row), b64(c.out.envelope_b64)))).toBe(i.plaintext_b64)
              return
            }
            const attempt = () => ck.open(i.kind, u(i.tenant), u(i.row), b64(i.envelope_b64))
            if (c.error) expect(await code(attempt)).toBe(c.error)
            else expect(toB64(await attempt())).toBe(c.out.plaintext_b64)
            return
          }
          case 'seal.sealer': {
            // Go's sealer is Go only; everything it produced must open here.
            const stored = new Map<number, string>(c.out.content_keys.map((k: { id: number; sealed_b64: string }) => [k.id, k.sealed_b64]))
            const open = async (keyID: number, kind: number, row: string, envelope: string) =>
              toB64(await (await ContentKey.unwrap(priv, u(i.tenant), u(i.device), keyID, b64(stored.get(keyID)!))).open(kind, u(i.tenant), u(row), b64(envelope)))
            for (const [n, step] of (i.steps as { action: string; kind: number; row: string; plaintext_b64: string; values?: { kind: number; plaintext_b64: string }[] }[]).entries()) {
              const got = c.out.steps[n]
              if (step.action === 'seal') expect(await open(got.key_id, step.kind, step.row, got.envelope_b64)).toBe(step.plaintext_b64)
              if (step.action === 'seal_all') {
                for (const [j, v] of step.values!.entries()) expect(await open(got.key_id, v.kind, step.row, got.envelopes[j].envelope_b64)).toBe(v.plaintext_b64)
              }
            }
            return
          }
        }
        throw new Error(`op ${c.op} is not handled`)
      })
    }
  })
}

// What this client has always said for each refusal. The console translates
// by the source text, so these must not move.
const accountMessages: Record<string, string> = {
  unsupported_alg: 'Esta conta usa uma proteção que esta versão ainda não reconhece.',
  kdf_failed: 'Não foi possível preparar a proteção da conta. Tente novamente.',
  truncated: 'a chave guardada está truncada',
  wrong_key: 'senha incorreta',
  recovery_length: 'um código de recuperação tem 30 caracteres',
}

describe('kit account-ts.json', () => {
  const expectRefusal = async (c: Case, fn: () => unknown) => {
    const err = await failure(fn)
    expect(err).toBeInstanceOf(AccountError)
    const e = err as AccountError
    expect([e.code, e.reason, e.message]).toEqual([c.error, c.reason, accountMessages[c.reason!]])
  }
  for (const c of cases(load('account-ts.json'))) {
    it(c.id, async () => {
      const i = c.in
      switch (c.op) {
        case 'account.default_kdf_params':
          expect(defaultKDFParams).toEqual(c.out.params)
          return
        case 'account.derive': {
          if (c.error) return expectRefusal(c, () => derive(i.password, b64(i.salt_b64), i.params))
          const d = await derive(i.password, b64(i.salt_b64), i.params)
          expect(d.authKey).toBe(c.out.auth_key)
          // The wrap key is non-extractable: it must seal what the recorded bytes seal.
          const iv = new Uint8Array(12).fill(7)
          const probe = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, d.wrapKey, new Uint8Array(4))
          const want = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(b64(c.out.wrap_b64)), new Uint8Array(4))
          expect(toB64(new Uint8Array(probe))).toBe(toB64(new Uint8Array(want)))
          return
        }
        case 'account.wrap': {
          const key = await aesKey(b64(i.wrap_key_b64))
          const blob = await withDraws({ bytes: [b64(i.nonce_b64)] }, () => wrapPrivateKey(b64(i.private_key_b64), key, i.email))
          expect(toB64(blob)).toBe(c.out.blob_b64)
          const back = await unwrapPrivateKey(blob, key, i.email)
          expect([toB64(back.privateKey), back.stale]).toEqual([i.private_key_b64, false])
          return
        }
        case 'account.unwrap': {
          const attempt = async () => unwrapPrivateKey(b64(i.blob_b64), await aesKey(b64(i.wrap_key_b64)), i.email)
          if (c.error) return expectRefusal(c, attempt)
          const back = await attempt()
          expect([toB64(back.privateKey), back.stale]).toEqual([c.out.private_key_b64, c.out.stale])
          return
        }
        case 'account.recovery_code':
          expect(await withDraws({ bytes: [b64(i.random_b64)] }, newRecoveryCode)).toBe(c.out.code)
          return
        case 'account.normalise_recovery_code':
          if (c.error) return expectRefusal(c, () => normaliseRecoveryCode(i.code))
          expect(normaliseRecoveryCode(i.code)).toBe(c.out.code)
          return
        case 'account.recovery_key': {
          const iv = new Uint8Array(12).fill(3)
          const a = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await recoveryKey(i.code), new Uint8Array(4))
          const b = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(b64(c.out.key_b64)), new Uint8Array(4))
          expect(toB64(new Uint8Array(a))).toBe(toB64(new Uint8Array(b)))
          return
        }
        case 'account.recovery_proof':
          if (c.error) return expectRefusal(c, () => recoveryProof(i.code))
          expect(await recoveryProof(i.code)).toBe(c.out.proof)
          return
        case 'account.generate_keys': {
          const pair = await withDraws({ x25519: [b64(i.x25519_private_key_b64)] }, generateAccountKeys)
          expect([toB64(pair.privateKey), toB64(pair.publicKey)]).toEqual([c.out.private_key_b64, c.out.public_key_b64])
          return
        }
        case 'account.fresh_salt':
          expect(toB64(await withDraws({ bytes: [b64(i.random_b64)] }, freshSalt))).toBe(c.out.salt_b64)
          return
      }
      throw new Error(`op ${c.op} is not handled`)
    })
  }
})

const passkeyMessages: Record<string, string> = {
  bad_prf: 'A passkey não forneceu uma chave de desbloqueio válida.',
  bad_key: 'Chave da conta inválida.',
  bad_envelope: 'O registro desta passkey está inválido. Entre com sua senha.',
  open_failed: 'Esta passkey não conseguiu abrir seus dados. Entre com sua senha e cadastre uma passkey compatível.',
}

describe('kit passkey-ts.json', () => {
  for (const c of cases(load('passkey-ts.json'))) {
    it(c.id, async () => {
      const i = c.in
      const binding = { rpID: i.rp_id, userID: i.user_id, credentialID: i.credential_id }
      const refused = async (fn: () => unknown) => expect(((await failure(fn)) as Error | undefined)?.message).toBe(passkeyMessages[c.error!])
      switch (c.op) {
        case 'passkey.key': {
          // The derived key is never exposed: an envelope sealed under the
          // recorded key, with the AAD Wappie binds, must open through the wrapper.
          const iv = new Uint8Array(12) as Bytes
          const aad = new TextEncoder().encode(JSON.stringify(['wappie/passkey-vault', 1, binding.rpID, binding.userID, binding.credentialID]))
          const key = await crypto.subtle.importKey('raw', b64(c.out.key_b64), 'AES-GCM', false, ['encrypt'])
          const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, new Uint8Array(32)))
          const envelope = new Uint8Array([1, ...iv, ...sealed]) as Bytes
          expect(toB64(await unwrapPasskey(envelope, b64(i.prf_b64), binding))).toBe(toB64(new Uint8Array(32)))
          return
        }
        case 'passkey.wrap': {
          const attempt = () => withDraws({ bytes: [b64(i.nonce_b64)] }, () => wrapPasskey(b64(i.private_key_b64), b64(i.prf_b64), binding))
          if (c.error) return refused(attempt)
          expect(toB64(await attempt())).toBe(c.out.envelope_b64)
          return
        }
        case 'passkey.unwrap': {
          const attempt = () => unwrapPasskey(b64(i.envelope_b64), b64(i.prf_b64), binding)
          if (c.error) return refused(attempt)
          expect(toB64(await attempt())).toBe(c.out.private_key_b64)
          return
        }
      }
      throw new Error(`op ${c.op} is not handled`)
    })
  }
})

describe('kit browser-account-ts.json', () => {
  for (const c of cases(load('browser-account-ts.json'))) {
    it(c.id, async () => {
      const i = c.in
      switch (c.op) {
        case 'browser_account.aad': {
          // The AAD is not exposed: what the wrapper seals must open under the recorded one.
          const envelope = await sealBrowserAccountKey(crypto.getRandomValues(new Uint8Array(32)) as Bytes, b64(i.public_key_b64), i.user_id)
          await expect(crypto.subtle.decrypt({ name: 'AES-GCM', iv: envelope.nonce, additionalData: b64(c.out.aad_b64) }, envelope.key, envelope.ciphertext)).resolves.toBeDefined()
          return
        }
        case 'browser_account.valid_envelope': {
          const key = i.algorithm === 'HMAC'
            ? await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256', length: 256 }, i.extractable, ['sign'])
            : await crypto.subtle.generateKey({ name: 'AES-GCM', length: i.length }, i.extractable, i.usages)
          const envelope = { version: i.version, key, nonce: new Uint8Array(i.nonce_len), ciphertext: new ArrayBuffer(i.ciphertext_len), publicRaw: new Uint8Array(i.public_len) }
          expect(validBrowserKeyEnvelope(envelope)).toBe(c.out.valid)
          return
        }
      }
      throw new Error(`op ${c.op} is not handled`)
    })
  }
})
