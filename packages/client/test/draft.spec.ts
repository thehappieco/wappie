import { describe, expect, it } from 'vitest'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { fileURLToPath, URL } from 'node:url'

import { encodeUTF8, formatUUID, fromBase64, parseUUID, toBase64, type Bytes } from '../src/crypto/bytes'
import { generateKeyPair, importArchiveKey } from '../src/crypto/hpke'
import { draftRow, Kind, kindName, openDirect, sealDirect, SealError } from '../src/crypto/seal'

// An assistant's draft (docs/mcp-enclave.md §17.6): sealed in the attested
// reader, in Node, with this package's sealDirect, stored by Go in the ledger,
// and opened in the person's browser with the row rebuilt from the ledger's
// fields. Three places meet on draftRow, and the console must open nothing a
// ledger moved to another chat, reply, connection or draft.
//
// Go writes internal/crypto/seal/testdata/draft-vectors.json (its rows and a
// draft it sealed, which this file opens), and this file writes
// testdata/node-draft.json (a draft sealed here, which Go opens in
// internal/crypto/seal/draft_test.go).

interface Row { device: string; connection: string; draft: string; reply: string | null; chat_key: string; row: string; note?: string }
interface Vectors {
  tenant: string
  private_key: string
  public_key: string
  rows: Row[]
  draft: Row & { epoch: number; plaintext: string; sealed: string }
  negatives: (Row & { why: string; kind: number })[]
}

const vectors: Vectors = JSON.parse(readFileSync(fileURLToPath(new URL('../../../internal/crypto/seal/testdata/draft-vectors.json', import.meta.url)), 'utf8'))
const tenant = parseUUID(vectors.tenant)
const rowOf = (r: Row) => draftRow(tenant, parseUUID(r.device), parseUUID(r.connection), parseUUID(r.draft), r.reply ? parseUUID(r.reply) : null, r.chat_key)
const priv = await importArchiveKey(fromBase64(vectors.private_key))

describe('the draft kind', () => {
  it('is 0x0E, named as Go names it, and 0x0F stays reserved', () => {
    expect(Kind.McpDraft).toBe(0x0e)
    expect(kindName(Kind.McpDraft)).toBe('mcp_draft')
    expect(kindName(0x0f)).toBe('kind(0xf)')
  })
})

describe('draftRow', () => {
  for (const r of vectors.rows) {
    it(`derives what Go derives: ${r.note}`, async () => {
      expect(formatUUID(await rowOf(r))).toBe(r.row)
    })
  }

  it('refuses an id that is not 16 bytes rather than hashing a short one', async () => {
    const id = parseUUID(vectors.draft.device)
    await expect(draftRow(tenant, id.subarray(0, 15) as Bytes, id, id, null, 'x')).rejects.toThrow(SealError)
    await expect(draftRow(tenant, id, id, id, new Uint8Array(15) as Bytes, 'x')).rejects.toThrow(SealError)
  })
})

describe('a draft Go sealed', () => {
  it('opens with the number\'s key under the row its ledger fields derive', async () => {
    const opened = await openDirect(priv, Kind.McpDraft, tenant, await rowOf(vectors.draft), fromBase64(vectors.draft.sealed))
    expect(new TextDecoder().decode(opened)).toBe(vectors.draft.plaintext)
  })

  for (const bad of vectors.negatives) {
    it(`does not open when ${bad.why.replace(/_/g, ' ')}`, async () => {
      await expect(openDirect(priv, bad.kind, tenant, await rowOf(bad), fromBase64(vectors.draft.sealed))).rejects.toThrow(SealError)
    })
  }
})

const nodePath = fileURLToPath(new URL('../testdata/node-draft.json', import.meta.url))

describe('a draft sealed in Node', () => {
  it('keeps a vector Go opens', async () => {
    // Written once and left alone, as browser-grant.json is; regenerate with
    // WS_REGEN_VECTORS=1 npm test, then run the Go tests.
    const ids = {
      tenant: '018f3a2b-0000-7000-8000-000000000011', device: '018f3a2b-0000-7000-8000-000000000012',
      connection: '018f3a2b-0000-7000-8000-000000000013', draft: '0b6f8a52-1c1e-4b3f-9d6a-3c0e2a7f4d11',
      reply_to_uid: '018f3a2b-0000-7000-8000-000000000014',
    }
    const chatKey = '120363041234567890@g.us'
    const epoch = 2
    const row = await draftRow(parseUUID(ids.tenant), parseUUID(ids.device), parseUUID(ids.connection), parseUUID(ids.draft), parseUUID(ids.reply_to_uid), chatKey)
    if (process.env.WS_REGEN_VECTORS || !existsSync(nodePath)) {
      const key = await generateKeyPair()
      const plaintext = JSON.stringify({ v: 1, connection_id: ids.connection, device_id: ids.device, chat_key: chatKey, reply_to_uid: ids.reply_to_uid,
        text: 'Combinado: sexta às 15h.\nLevo os documentos.', created_at: '2026-10-01T09:30:15.123Z', cross_chat: [] })
      const sealed = await sealDirect(key.publicKey, Kind.McpDraft, parseUUID(ids.tenant), row, epoch, encodeUTF8(plaintext))
      mkdirSync(dirname(nodePath), { recursive: true })
      writeFileSync(nodePath, JSON.stringify({
        note: 'Sealed by packages/client/test/draft.spec.ts as the attested reader seals a draft, opened by Go in internal/crypto/seal/draft_test.go. ' +
          'Regenerate with: cd packages/client && WS_REGEN_VECTORS=1 npm test',
        ...ids, chat_key: chatKey, epoch, archive_private_key: toBase64(key.privateKey), archive_public_key: toBase64(key.publicKey),
        draft_row: formatUUID(row), plaintext, sealed: toBase64(sealed),
      }, null, 2) + '\n')
      key.privateKey.fill(0)
    }
    const vector = JSON.parse(readFileSync(nodePath, 'utf8')) as { draft_row: string; archive_private_key: string; plaintext: string; sealed: string }
    expect(vector.draft_row).toBe(formatUUID(row))
    const opened = await openDirect(await importArchiveKey(fromBase64(vector.archive_private_key)), Kind.McpDraft, parseUUID(ids.tenant), row, fromBase64(vector.sealed))
    expect(new TextDecoder().decode(opened)).toBe(vector.plaintext)
  })
})
