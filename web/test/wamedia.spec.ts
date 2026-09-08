import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath, URL } from 'node:url'

import { fromBase64 } from '../src/crypto/bytes'
import { MediaError, decrypt, deriveKeys, type MediaType } from '../src/crypto/wamedia'

// Regenerate deliberately:
//   go test ./internal/crypto/wamedia -run Vectors -update

interface Vector {
  type: string
  media_key: string
  plaintext: string
  enc: string
  iv: string
  cipher_key: string
  mac_key: string
  note?: string
}

const vectors: { vectors: Vector[] } = JSON.parse(
  readFileSync(
    fileURLToPath(new URL('../../internal/crypto/wamedia/testdata/vectors.json', import.meta.url)),
    'utf8',
  ),
)

describe('the key expansion', () => {
  for (const v of vectors.vectors) {
    it(`derives ${v.type} keys${v.note ? ` — ${v.note}` : ''}`, async () => {
      const k = await deriveKeys(fromBase64(v.media_key), v.type as MediaType)
      // Reported separately so a failure says which of the three went wrong,
      // rather than only that the MAC did.
      expect(Array.from(k.iv)).toEqual(Array.from(fromBase64(v.iv)))
      expect(Array.from(k.cipher)).toEqual(Array.from(fromBase64(v.cipher_key)))
      expect(Array.from(k.mac)).toEqual(Array.from(fromBase64(v.mac_key)))
    })
  }
})

describe('ciphertext as the CDN serves it', () => {
  for (const v of vectors.vectors) {
    it(`decrypts ${v.type} of ${fromBase64(v.plaintext).length} bytes`, async () => {
      const got = await decrypt(fromBase64(v.enc), fromBase64(v.media_key), v.type as MediaType)
      expect(Array.from(got)).toEqual(Array.from(fromBase64(v.plaintext)))
    })
  }
})

describe('what it must refuse', () => {
  const sample = vectors.vectors[0]

  it('a flipped ciphertext bit, before decrypting it', async () => {
    const enc = fromBase64(sample.enc)
    enc[0] ^= 0x01
    await expect(decrypt(enc, fromBase64(sample.media_key), sample.type as MediaType)).rejects.toThrow(
      MediaError,
    )
  })

  it('a flipped MAC bit', async () => {
    const enc = fromBase64(sample.enc)
    enc[enc.length - 1] ^= 0x01
    await expect(decrypt(enc, fromBase64(sample.media_key), sample.type as MediaType)).rejects.toThrow(
      /MAC/,
    )
  })

  it('the wrong media type, which derives different keys', async () => {
    await expect(
      decrypt(fromBase64(sample.enc), fromBase64(sample.media_key), 'document'),
    ).rejects.toThrow(/MAC/)
  })

  it('a mediaKey that is not 32 bytes', async () => {
    await expect(decrypt(fromBase64(sample.enc), new Uint8Array(16), 'image')).rejects.toThrow(
      /32/,
    )
  })
})
