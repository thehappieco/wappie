import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath, URL } from 'node:url'

import type { KeySource } from '../src/api/opener'
import { Opener } from '../src/api/opener'
import type * as P from '../src/api/protocol'
import * as Proto from '../src/api/protocol'
import { parseUUID } from '../src/crypto/bytes'
import { importArchiveKey } from '../src/crypto/hpke'

// seal.spec.ts proves the TypeScript can open what Go sealed. It cannot prove
// this client asks for the *right* row and the right kind — and it never
// would, because both sides of that test agree by construction.
//
// These are whole frames, sealed exactly as the ingest pipeline seals them.
// Point the opener at the wrong uid or the wrong kind and every field below
// comes back tampered, with the correct archive key in hand.
//
//   go test ./internal/wsapi -run Fixtures -update

interface Frames {
  tenant: string
  device: string
  private_key: string
  content_key: { id: number; sealed: string }
  message: P.SealedMessage
  expected: {
    body: string
    payload: string
    media_key: string
    thumbnail: string
    file_name: string
  }
  chat: P.ChatSummary
  chat_name: string
  contact: P.ContactSummary
  contact_names: { push: string; full: string; business: string }
  avatar: P.Avatar
  avatar_bytes: string
  relocated: P.SealedMessage
}

const frames: Frames = JSON.parse(
  readFileSync(
    fileURLToPath(new URL('../../internal/wsapi/testdata/frames.json', import.meta.url)),
    'utf8',
  ),
)

/** A key source that answers from the fixture, so no socket is involved. */
const keys: KeySource = {
  async request<T>(type: string, payload: unknown, _want: string): Promise<T> {
    if (type !== Proto.TypeKeysGet) throw new Error(`unexpected request ${type}`)
    const ids = (payload as P.KeysRequest).ids
    return {
      keys: ids
        .filter((id) => id === frames.content_key.id)
        .map((id) => ({ id, sealed: frames.content_key.sealed })),
    } as T
  },
}

const priv = await importArchiveKey(
  Uint8Array.from(Buffer.from(frames.private_key, 'base64')) as Uint8Array<ArrayBuffer>,
)
const opener = new Opener(
  keys,
  parseUUID(frames.tenant),
  parseUUID(frames.device),
  frames.device,
  priv,
)

describe('a message frame', () => {
  it('opens its body against the message uid', async () => {
    const opened = await opener.body(frames.message)
    expect(opened.state).toBe('ok')
    expect(opened.state === 'ok' && opened.value).toBe(frames.expected.body)
  })

  it('opens its structured payload', async () => {
    const opened = await opener.payload(frames.message)
    expect(opened.state).toBe('ok')
    expect(opened.state === 'ok' && opened.value.mentions).toEqual([
      '5511999999999@s.whatsapp.net',
    ])
  })

  it('opens the media key that decrypts the attachment', async () => {
    const opened = await opener.mediaKey(frames.message)
    expect(opened.state).toBe('ok')
    if (opened.state !== 'ok') return
    expect(Buffer.from(opened.value).toString('base64')).toBe(frames.expected.media_key)
    // Thirty-two bytes or the whole media path fails much later with a MAC
    // error and nothing to point at.
    expect(opened.value.length).toBe(32)
  })

  it('opens the inline thumbnail', async () => {
    const opened = await opener.thumbnail(frames.message)
    expect(opened.state).toBe('ok')
    expect(opened.state === 'ok' && Buffer.from(opened.value).toString('base64')).toBe(
      frames.expected.thumbnail,
    )
  })

  it('opens the file name, which is sealed under the contact-name kind', async () => {
    // Reads oddly and is the format. A client that "corrected" this to a
    // filename kind would fail on every document in the archive.
    const opened = await opener.fileName(frames.message)
    expect(opened.state).toBe('ok')
    expect(opened.state === 'ok' && opened.value).toBe(frames.expected.file_name)
  })
})

describe('a chat and a contact', () => {
  it('opens a chat name against the chat uid, not the chat key', async () => {
    const opened = await opener.chatName(frames.chat)
    expect(opened.state).toBe('ok')
    expect(opened.state === 'ok' && opened.value).toBe(frames.chat_name)
  })

  it('opens all three contact names, each under its own kind', async () => {
    const names = await opener.contactNames(frames.contact)
    expect(names.push.state === 'ok' && names.push.value).toBe(frames.contact_names.push)
    expect(names.full.state === 'ok' && names.full.value).toBe(frames.contact_names.full)
    expect(names.business.state === 'ok' && names.business.value).toBe(
      frames.contact_names.business,
    )
  })

  it('opens a profile picture against the contact uid', async () => {
    const opened = await opener.avatar(frames.avatar)
    expect(opened.state).toBe('ok')
    expect(opened.state === 'ok' && Buffer.from(opened.value).toString('base64')).toBe(
      frames.avatar_bytes,
    )
  })
})

describe('a value moved to another row', () => {
  it('is reported as tampered, not as missing', async () => {
    // An attacker with write access to Postgres swaps a body between two
    // messages. The client must say so — rendering this as "could not load"
    // would hide the one event the binding exists to detect.
    const opened = await opener.body(frames.relocated)
    expect(opened.state).toBe('tampered')
  })
})

describe('the key cache', () => {
  it('asks for a content key once, however many fields need it', async () => {
    let calls = 0
    const counting: KeySource = {
      async request<T>(type: string, payload: unknown, want: string): Promise<T> {
        calls += 1
        return keys.request<T>(type, payload, want)
      },
    }
    const fresh = new Opener(counting, parseUUID(frames.tenant), parseUUID(frames.device), frames.device, priv)
    await fresh.prefetch([frames.content_key.id, frames.content_key.id])
    await Promise.all([
      fresh.body(frames.message),
      fresh.mediaKey(frames.message),
      fresh.fileName(frames.message),
      fresh.chatName(frames.chat),
    ])
    // One asymmetric unwrap for a whole page, which is the difference between
    // a conversation opening instantly and a device stalling on a large one.
    expect(calls).toBe(1)
  })

  it('does not ask again for a key the server does not have', async () => {
    let calls = 0
    const empty: KeySource = {
      async request<T>(): Promise<T> {
        calls += 1
        return { keys: [] } as T
      },
    }
    const fresh = new Opener(empty, parseUUID(frames.tenant), parseUUID(frames.device), frames.device, priv)
    const first = await fresh.body(frames.message)
    const second = await fresh.body(frames.message)
    expect(first.state).toBe('locked')
    expect(second.state).toBe('locked')
    expect(calls).toBe(1)
  })
})
