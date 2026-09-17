import { describe, expect, it } from 'vitest'
import { generateKeyPair, importArchiveKey, seal } from '../src/crypto/hpke.js'
import { encodeUTF8, toBase64 } from '../src/crypto/bytes.js'
import { MAX_CONTACT_PLAINTEXT_BYTES, openContactPack, sealContactPack, validateContactPack, validateContactPackDocument } from '../src/crypto/contactPack.js'

const scope = { server_url: 'https://archive.example.test', workspace_id: '018f3a2b-2222-7000-8000-00000000bbbb',
  service_user_id: '018f3a2b-2222-7000-8000-00000000aaaa', device_ids: ['018f3a2b-2222-7000-8000-00000000dddd'] }
const contacts = [{ name: 'Synthetic contact', phones: ['+5511987654321'] }]
const created = '2026-09-17T12:34:56.000Z'
const b64 = (bytes: Uint8Array<ArrayBuffer>) => toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

describe('encrypted MCP contact snapshots', () => {
  it('round trips only documented contacts with a creation time and canonical fixed scope', async () => {
    const pair = await generateKeyPair()
    const pack = await sealContactPack(pair.publicKey, { ...scope, workspace_id: scope.workspace_id.toUpperCase() }, contacts, created)
    expect(pack).toMatchObject({ ...scope, version: 1 })
    expect(JSON.stringify(pack)).not.toContain(contacts[0].name)
    expect(JSON.stringify(pack)).not.toContain(contacts[0].phones[0])
    expect(await openContactPack(await importArchiveKey(pair.privateKey), pack, scope)).toEqual({ version: 1, created_at: created, contacts })
    expect(validateContactPack(pack, scope)).not.toBe(pack)
  })

  it('binds the ciphertext to its origin, workspace, recipient and exact number set', async () => {
    const pair = await generateKeyPair(), key = await importArchiveKey(pair.privateKey)
    const pack = await sealContactPack(pair.publicKey, scope, contacts, created)
    for (const override of [{ server_url: 'https://other.example.test' }, { workspace_id: scope.service_user_id },
      { service_user_id: scope.workspace_id }, { device_ids: [scope.workspace_id] }]) {
      const changed = { ...scope, ...override }
      await expect(openContactPack(key, pack, changed)).rejects.toThrow('invalid_contact_pack')
      await expect(openContactPack(key, { ...pack, ...override }, changed)).rejects.toThrow('invalid_contact_pack')
    }
    await expect(openContactPack(await importArchiveKey((await generateKeyPair()).privateKey), pack, scope)).rejects.toThrow('invalid_contact_pack')
    const tampered = pack.ciphertext.slice(0, 3) + (pack.ciphertext[3] === 'A' ? 'B' : 'A') + pack.ciphertext.slice(4)
    await expect(openContactPack(key, { ...pack, ciphertext: tampered }, scope)).rejects.toThrow('invalid_contact_pack')
  })

  it('sorts number sets and rejects ambiguous, extended or invalid scope/envelope values', async () => {
    const pair = await generateKeyPair()
    const unordered = { ...scope, device_ids: [scope.workspace_id, ...scope.device_ids] }
    const pack = await sealContactPack(pair.publicKey, unordered, contacts, created)
    expect(pack.device_ids).toEqual([...unordered.device_ids].sort())
    expect(validateContactPack(pack, { ...unordered, device_ids: [...unordered.device_ids].reverse() })).toEqual(pack)
    for (const override of [{ device_ids: [] }, { device_ids: [scope.device_ids[0], scope.device_ids[0].toUpperCase()] },
      { server_url: 'https://archive.example.test/path' }, { service_user_id: 'invalid' },
      { extra: 'ignored?' }, { version: 2 }, { enc: pack.enc + '=' }, { ciphertext: '' }]) {
      expect(() => validateContactPack({ ...pack, ...override }, unordered)).toThrow('invalid_contact_pack')
    }
  })

  it('validates document limits and rejects fields that could carry unrelated personal data', async () => {
    const document = { version: 1, created_at: created, contacts }
    for (const override of [{ version: 2 }, { created_at: 'yesterday' }, { extra: true },
      { contacts: [{ ...contacts[0], email: 'private@example.test' }] },
      { contacts: [{ name: '', phones: contacts[0].phones }] },
      { contacts: [{ name: 'Name\u0000', phones: contacts[0].phones }] },
      { contacts: [{ name: 'x'.repeat(257), phones: contacts[0].phones }] },
      { contacts: [{ name: 'Name', phones: ['5511987654321'] }] },
      { contacts: [{ name: 'Name', phones: [contacts[0].phones[0], contacts[0].phones[0]] }] },
      { contacts: Array(10_001).fill(contacts[0]) }]) {
      expect(() => validateContactPackDocument({ ...document, ...override })).toThrow('invalid_contact_pack')
    }
    const pair = await generateKeyPair()
    const huge = Array(10_000).fill({ name: 'x'.repeat(256), phones: Array.from({ length: 64 }, (_, i) => `+55119876${String(i).padStart(5, '0')}`) })
    expect(() => validateContactPackDocument({ ...document, contacts:huge })).toThrow('invalid_contact_pack')
    await expect(sealContactPack(pair.publicKey, scope, huge, created)).rejects.toThrow('invalid_contact_pack')
    expect(MAX_CONTACT_PLAINTEXT_BYTES).toBe(5 * 1024 * 1024)
  })

  it('validates authenticated plaintext as strictly as newly sealed input', async () => {
    const pair = await generateKeyPair()
    const info = encodeUTF8('wappie/mcp-contacts/hpke/v1')
    const aad = encodeUTF8(JSON.stringify(['wappie/mcp-contacts', 1, scope.server_url, scope.workspace_id, scope.service_user_id, scope.device_ids]))
    const sealed = await seal(pair.publicKey, info, aad, encodeUTF8(JSON.stringify({ version: 1, created_at: created, contacts, unexpected: 'private' })))
    await expect(openContactPack(await importArchiveKey(pair.privateKey), { ...scope, version: 1, enc: b64(sealed.enc), ciphertext: b64(sealed.ciphertext) }, scope)).rejects.toThrow('invalid_contact_pack')
  })
})
