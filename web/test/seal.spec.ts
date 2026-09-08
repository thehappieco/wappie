import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath, URL } from 'node:url'

import { fromBase64, parseUUID } from '../src/crypto/bytes'
import { importArchiveKey } from '../src/crypto/hpke'
import { ContentKey, Kind, SealError, openDirect } from '../src/crypto/seal'

// The whole reason this file exists: the browser is a second implementation of
// the archive format, and a second implementation that is subtly wrong opens
// everything it sealed itself while failing on real data. So it is checked
// against blobs Go actually produced.
//
// Regenerate the fixture deliberately:
//   go test ./internal/crypto/seal -run Vectors -update

interface Vector {
  kind: number
  kind_name: string
  row: string
  sealed: string
  plaintext: string
  note?: string
}

interface Negative {
  why: string
  mode: string
  kind: number
  row: string
  sealed: string
}

interface Vectors {
  tenant: string
  device: string
  private_key: string
  public_key: string
  content_key: { id: number; epoch: number; sealed: string }
  batch: Vector[]
  direct: Vector[]
  negatives: Negative[]
}

const vectors: Vectors = JSON.parse(
  readFileSync(
    fileURLToPath(new URL('../../internal/crypto/seal/testdata/vectors.json', import.meta.url)),
    'utf8',
  ),
)

const tenant = parseUUID(vectors.tenant)
// Content keys are sealed to a device's archive key, and their row identity is
// derived from the device — so opening one against the wrong device fails with
// the correct key in hand.
const device = parseUUID(vectors.device)
const priv = await importArchiveKey(fromBase64(vectors.private_key))

describe('the archive key', () => {
  it('recovers the public half the fixture recorded', () => {
    // DHKEM puts the recipient public key in its context, and WebCrypto will
    // not export a public half from a key imported as private — so it is
    // recomputed. Getting that wrong breaks every open with an
    // indistinguishable authentication failure.
    expect(Array.from(priv.publicRaw)).toEqual(Array.from(fromBase64(vectors.public_key)))
  })
})

describe('a content key sealed by the server', () => {
  it('unwraps in the browser', async () => {
    const key = await ContentKey.unwrap(
      priv,
      tenant,
      device,
      vectors.content_key.id,
      fromBase64(vectors.content_key.sealed),
    )
    expect(key.id).toBe(vectors.content_key.id)
    expect(key.epoch).toBe(vectors.content_key.epoch)
  })

  it('refuses to unwrap under the wrong id, because the row is derived from it', async () => {
    await expect(
      ContentKey.unwrap(
        priv,
        tenant,
        device,
        vectors.content_key.id + 1,
        fromBase64(vectors.content_key.sealed),
      ),
    ).rejects.toThrow(SealError)
  })

  it('refuses to unwrap for another device, which is the point of the change', async () => {
    // A reader holding one account's key must be unable to open another's,
    // whatever the server hands over. That has to be arithmetic, not a rule.
    const other = parseUUID('00000000-0000-4000-8000-0000000000ff')
    await expect(
      ContentKey.unwrap(
        priv,
        tenant,
        other,
        vectors.content_key.id,
        fromBase64(vectors.content_key.sealed),
      ),
    ).rejects.toThrow(SealError)
  })
})

const contentKey = await ContentKey.unwrap(
      priv,
      tenant,
      device,
      vectors.content_key.id,
  fromBase64(vectors.content_key.sealed),
)

describe('values sealed under a content key', () => {
  for (const v of vectors.batch) {
    it(`opens a ${v.kind_name}${v.note ? ` — ${v.note}` : ''}`, async () => {
      const got = await contentKey.open(v.kind as Kind, tenant, parseUUID(v.row), fromBase64(v.sealed))
      expect(Array.from(got)).toEqual(Array.from(fromBase64(v.plaintext)))
    })
  }
})

describe('values sealed straight to the archive key', () => {
  for (const v of vectors.direct) {
    it(`opens a ${v.kind_name}`, async () => {
      const got = await openDirect(priv, v.kind as Kind, tenant, parseUUID(v.row), fromBase64(v.sealed))
      expect(Array.from(got)).toEqual(Array.from(fromBase64(v.plaintext)))
    })
  }
})

describe('what the binding must refuse', () => {
  // Each of these is an attacker with write access to the database moving a
  // blob somewhere it does not belong. An implementation that skipped the AAD
  // passes every test above and fails every one of these.
  for (const bad of vectors.negatives) {
    it(bad.why.replace(/_/g, ' '), async () => {
      const attempt =
        bad.mode === 'direct'
          ? openDirect(priv, bad.kind as Kind, tenant, parseUUID(bad.row), fromBase64(bad.sealed))
          : contentKey.open(bad.kind as Kind, tenant, parseUUID(bad.row), fromBase64(bad.sealed))
      await expect(attempt).rejects.toThrow(SealError)
    })
  }

  it('refuses a foreign blob outright', async () => {
    const notAnEnvelope = new Uint8Array(64)
    await expect(
      contentKey.open(Kind.Body, tenant, parseUUID(vectors.batch[0].row), notAnEnvelope),
    ).rejects.toThrow(/não é um envelope/)
  })

  it('refuses an envelope from another tenant', async () => {
    const other = parseUUID('00000000-0000-4000-8000-000000000000')
    await expect(
      contentKey.open(
        Kind.Body,
        other,
        parseUUID(vectors.batch[0].row),
        fromBase64(vectors.batch[0].sealed),
      ),
    ).rejects.toThrow(SealError)
  })
})
