import { describe, expect, it, vi } from 'vitest'
import { generateAccountKeys } from '../src/crypto/account'
import { openBrowserAccountKey, sealBrowserAccountKey } from '../src/crypto/browserAccount'

describe('local account envelope', () => {
  it('reopens the original key using an AES handle, without exporting an X25519 key', async () => {
    const pair = await generateAccountKeys()
    const exported = vi.spyOn(crypto.subtle, 'exportKey')
    try {
      const envelope = await sealBrowserAccountKey(pair.privateKey, pair.publicKey, 'user-one')
      const second = await sealBrowserAccountKey(pair.privateKey, pair.publicKey, 'user-one')
      expect(envelope.key.extractable).toBe(false)
      expect(envelope.key.algorithm.name).toBe('AES-GCM')
      expect(envelope.ciphertext.byteLength).toBe(48)
      expect(envelope.nonce).not.toEqual(second.nonce)
      const restored = await openBrowserAccountKey(structuredClone(envelope), 'user-one')
      expect(restored.publicRaw).toEqual(pair.publicKey)
      expect(restored.key.extractable).toBe(false)
      expect(exported).not.toHaveBeenCalled()
    } finally { pair.privateKey.fill(0); exported.mockRestore() }
  })

  it('rejects account, public-key and ciphertext substitution', async () => {
    const pair = await generateAccountKeys()
    const envelope = await sealBrowserAccountKey(pair.privateKey, pair.publicKey, 'user-one')
    pair.privateKey.fill(0)
    await expect(openBrowserAccountKey(envelope, 'user-two')).rejects.toThrow()
    const publicRaw = envelope.publicRaw.slice(); publicRaw[0] ^= 1
    await expect(openBrowserAccountKey({ ...envelope, publicRaw }, 'user-one')).rejects.toThrow()
    const ciphertext = envelope.ciphertext.slice(0); new Uint8Array(ciphertext)[0] ^= 1
    await expect(openBrowserAccountKey({ ...envelope, ciphertext }, 'user-one')).rejects.toThrow()
  })
})
