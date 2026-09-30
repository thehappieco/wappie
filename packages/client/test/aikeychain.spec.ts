import { describe, expect, it } from 'vitest'

import { concat, encodeUTF8, toBase64, type Bytes } from '../src/crypto/bytes'
import { generateKeyPair, importArchiveKey, seal as hpkeSeal } from '../src/crypto/hpke'
import { KeychainError, keychainSuffix, openKeychainItem, sealKeychainItem, type KeychainInput } from '../src/crypto/aikeychain'

// The AI keychain (docs/mcp-enclave.md §18.6): a person's provider keys,
// sealed in their browser under a key only their account's private key
// derives, and stored by Go as an opaque envelope. Go knows the account's
// public key and nothing else, so no item it makes opens (N-AI-2), and an
// item opens only for its own origin, account, id and provider.

const account = await importArchiveKey((await generateKeyPair()).privateKey)
const input: KeychainInput = {
  server_origin: 'https://api.wappie.thehappie.co', user_id: '018f3a2b-2222-7000-8000-00000000aaaa', id: '018f3a2b-2222-7000-8000-0000000000c1',
  provider: 'google', api_key: 'wappie-test-key-google-aaaaaaaaaaaaaaaa', label: 'Gemini para a Wappie', created_at: '2026-10-01T09:30:15.123Z',
}
const row = (envelope: Bytes | string, change: Partial<KeychainInput> = {}) => ({ server_origin: input.server_origin, user_id: input.user_id, id: input.id, provider: input.provider, envelope, ...change })

describe('an item', () => {
  it('opens for its account, origin, id and provider, from bytes or Go\'s base64', async () => {
    const envelope = await sealKeychainItem(account, input)
    expect([...envelope.subarray(0, 4)]).toEqual([...encodeUTF8('WKC1')])
    const opened = await openKeychainItem(account, row(envelope))
    expect(opened).toEqual({ provider: 'google', api_key: input.api_key, label: input.label, created_at: input.created_at })
    expect(await openKeychainItem(account, row(toBase64(envelope)))).toEqual(opened)
    // Go's keychain routes take and list the envelope in unpadded base64url.
    const url = toBase64(envelope).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    expect(await openKeychainItem(account, row(url))).toEqual(opened)
    for (const bad of [url + '===', url.slice(0, -1) + '*', ' ' + url]) await expect(openKeychainItem(account, row(bad))).rejects.toThrow(KeychainError)
    expect(keychainSuffix(input.api_key)).toBe('aaaa')
  })

  it('refuses another origin, account, item, and a provider Go changed on the row', async () => {
    const envelope = await sealKeychainItem(account, input)
    for (const change of [
      { server_origin: 'https://evil.example' }, { user_id: '018f3a2b-2222-7000-8000-00000000bbbb' },
      { id: '018f3a2b-2222-7000-8000-0000000000c2' }, { provider: 'openai' as const },
    ]) await expect(openKeychainItem(account, row(envelope, change))).rejects.toThrow(KeychainError)
    const other = await importArchiveKey((await generateKeyPair()).privateKey)
    await expect(openKeychainItem(other, row(envelope))).rejects.toThrow(KeychainError)
    const flipped = new Uint8Array(envelope)
    flipped[flipped.length - 1] ^= 1
    await expect(openKeychainItem(account, row(flipped))).rejects.toThrow(KeychainError)
  })

  it('seals only a well-formed item', async () => {
    for (const change of [
      { api_key: 'short' }, { api_key: 'wappie test key with spaces, not printable ascii' }, { label: '' }, { label: 'x'.repeat(61) },
      { label: 'a\u0000b' }, { provider: 'mistral' as never }, { created_at: 'yesterday' }, { user_id: 'nobody' }, { server_origin: 'http://api.example' },
    ]) await expect(sealKeychainItem(account, { ...input, ...change })).rejects.toThrow(KeychainError)
  })
})

describe('N-AI-2: an item Go made', () => {
  it('never opens, sealed to the account\'s public key or keyed from it', async () => {
    const plaintext = encodeUTF8(JSON.stringify({ provider: input.provider, api_key: 'wappie-test-key-google-gggggggggggggggg', label: 'Go', created_at: input.created_at }))
    const aad = encodeUTF8(JSON.stringify(['wappie/ai-keychain', 1, input.server_origin, input.user_id, input.id, input.provider]))
    // HPKE base mode to the public key, which Go holds.
    const { enc, ciphertext } = await hpkeSeal(account.publicRaw as Bytes, encodeUTF8('wappie/ai-keychain/v1'), aad, plaintext)
    await expect(openKeychainItem(account, row(concat(encodeUTF8('WKC1'), enc.subarray(0, 12) as Bytes, ciphertext)))).rejects.toThrow(KeychainError)
    // AES-256-GCM under HKDF of the public key: all Go could derive.
    const base = await crypto.subtle.importKey('raw', account.publicRaw as Bytes, 'HKDF', false, ['deriveKey'])
    const key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: encodeUTF8(input.user_id), info: encodeUTF8('wappie/ai-keychain/v1') }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt'])
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, plaintext))
    await expect(openKeychainItem(account, row(concat(encodeUTF8('WKC1'), iv, sealed)))).rejects.toThrow(KeychainError)
  })
})
