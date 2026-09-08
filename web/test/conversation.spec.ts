import { describe, expect, it } from 'vitest'

import type { SealedMessage } from '../src/api/protocol'
import { project, standing, wasEdited } from '../src/state/conversation'

// The projection is where a chat window is reconstructed from what the archive
// actually stores, and every interesting case is one where the two disagree: an
// edit is a separate row, so is a deletion, so is every reaction. Getting it
// wrong is silent — the message simply shows the text it was first sent with,
// and nobody notices until they compare against a phone.

let seq = 0

function row(over: Partial<SealedMessage> & Pick<SealedMessage, 'wa_id'>): SealedMessage {
  seq += 1
  return {
    uid: `00000000-0000-4000-8000-${String(seq).padStart(12, '0')}`,
    seq,
    device_id: 'dev',
    chat_key: '5511999999999@s.whatsapp.net',
    is_from_me: false,
    kind: 'message',
    type: 'text',
    source: 'live',
    ...over,
  }
}

describe('a plain conversation', () => {
  it('keeps one line per message, in sequence order', () => {
    const rows = [row({ wa_id: 'A' }), row({ wa_id: 'B' }), row({ wa_id: 'C' })]
    const { entries, orphans } = project(rows)
    expect(entries.map((e) => e.row.wa_id)).toEqual(['A', 'B', 'C'])
    expect(orphans).toEqual([])
  })

  it('orders correctly however the rows arrive', () => {
    const a = row({ wa_id: 'A' })
    const b = row({ wa_id: 'B' })
    const { entries } = project([b, a])
    expect(entries.map((e) => e.row.wa_id)).toEqual(['A', 'B'])
  })

  it('shows a message once when a live frame repeats a replayed page', () => {
    const a = row({ wa_id: 'A' })
    const { entries } = project([a, { ...a }])
    expect(entries).toHaveLength(1)
  })
})

describe('an edited message', () => {
  it('displays the newest version and keeps every earlier one', () => {
    const original = row({ wa_id: 'A' })
    const first = row({ wa_id: 'E1', kind: 'edit', target_wa_id: 'A', target_rel: 'message' })
    const second = row({ wa_id: 'E2', kind: 'edit', target_wa_id: 'A', target_rel: 'message' })

    const { entries } = project([original, first, second])
    expect(entries).toHaveLength(1)

    const entry = entries[0]
    expect(wasEdited(entry)).toBe(true)
    // Three versions: what was sent, and what it became twice. The whole point
    // of the archive is that the first two did not disappear.
    expect(entry.versions.map((v) => v.wa_id)).toEqual(['A', 'E1', 'E2'])
    expect(entry.current.wa_id).toBe('E2')
  })

  it('does not put the edit on the timeline as a message of its own', () => {
    const { entries } = project([
      row({ wa_id: 'A' }),
      row({ wa_id: 'E1', kind: 'edit', target_wa_id: 'A', target_rel: 'message' }),
    ])
    expect(entries.map((e) => e.row.wa_id)).toEqual(['A'])
  })
})

describe('a deleted message', () => {
  it('is still there, marked, with its content intact', () => {
    const original = row({ wa_id: 'A', body_sealed: 'c2VhbGVk' })
    const revoke = row({ wa_id: 'D1', kind: 'delete', target_wa_id: 'A', target_rel: 'message' })

    const { entries } = project([original, revoke])
    expect(entries).toHaveLength(1)
    expect(entries[0].deleted).toBeTruthy()
    // This is the product: WhatsApp removed it, the archive did not.
    expect(entries[0].current.body_sealed).toBe('c2VhbGVk')
  })
})

describe('reactions', () => {
  it('keeps only the newest from each party standing', () => {
    const target = row({ wa_id: 'A' })
    const first = row({
      wa_id: 'R1',
      kind: 'reaction',
      target_wa_id: 'A',
      target_rel: 'message',
      sender_key: 'ana@s.whatsapp.net',
    })
    const second = row({
      wa_id: 'R2',
      kind: 'reaction',
      target_wa_id: 'A',
      target_rel: 'message',
      sender_key: 'ana@s.whatsapp.net',
    })

    const { entries } = project([target, first, second])
    const alive = standing(entries[0])
    expect(alive.map((r) => r.row.wa_id)).toEqual(['R2'])
    // The superseded one is kept on the entry, because the history panel shows it.
    expect(entries[0].reactions).toHaveLength(2)
  })

  it('keeps one per party rather than one in total', () => {
    const target = row({ wa_id: 'A' })
    const { entries } = project([
      target,
      row({ wa_id: 'R1', kind: 'reaction', target_wa_id: 'A', sender_key: 'ana@s.whatsapp.net' }),
      row({ wa_id: 'R2', kind: 'reaction', target_wa_id: 'A', sender_key: 'bia@s.whatsapp.net' }),
    ])
    expect(standing(entries[0])).toHaveLength(2)
  })

  it('separates our own reaction from a contact with no sender key', () => {
    const target = row({ wa_id: 'A' })
    const { entries } = project([
      target,
      row({ wa_id: 'R1', kind: 'reaction', target_wa_id: 'A', is_from_me: true }),
      row({ wa_id: 'R2', kind: 'reaction', target_wa_id: 'A', sender_key: 'ana@s.whatsapp.net' }),
    ])
    // Our rows carry no sender key. Treating that as one party would make our
    // reaction supersede theirs.
    expect(standing(entries[0])).toHaveLength(2)
  })

  it('drops one that was revoked', () => {
    const target = row({ wa_id: 'A' })
    const reaction = row({
      wa_id: 'R1',
      kind: 'reaction',
      target_wa_id: 'A',
      sender_key: 'ana@s.whatsapp.net',
    })
    const revoke = row({ wa_id: 'D1', kind: 'delete', target_wa_id: 'R1', target_rel: 'reaction' })

    const { entries } = project([target, reaction, revoke])
    expect(standing(entries[0])).toHaveLength(0)
    expect(entries[0].reactions[0].revoked).toBe(true)
    // And it must not have been mistaken for a deletion of the message itself.
    expect(entries[0].deleted).toBeUndefined()
  })

  it('promotes the earlier reaction when the newer one is revoked', () => {
    const target = row({ wa_id: 'A' })
    const { entries } = project([
      target,
      row({ wa_id: 'R1', kind: 'reaction', target_wa_id: 'A', sender_key: 'ana@s.whatsapp.net' }),
      row({ wa_id: 'R2', kind: 'reaction', target_wa_id: 'A', sender_key: 'ana@s.whatsapp.net' }),
      row({ wa_id: 'D1', kind: 'delete', target_wa_id: 'R2', target_rel: 'reaction' }),
    ])
    expect(standing(entries[0]).map((r) => r.row.wa_id)).toEqual(['R1'])
  })
})

describe('a control row whose target is on an older page', () => {
  it('is held rather than dropped', () => {
    const edit = row({ wa_id: 'E1', kind: 'edit', target_wa_id: 'OLD', target_rel: 'message' })
    const { entries, orphans } = project([edit])
    expect(entries).toEqual([])
    // Dropping it would silently lose an edit every time one straddled a page
    // boundary, and the message would show text it no longer has.
    expect(orphans.map((o) => o.wa_id)).toEqual(['E1'])
  })

  it('is applied once the older page arrives', () => {
    const edit = row({ wa_id: 'E1', kind: 'edit', target_wa_id: 'A', target_rel: 'message' })
    const original = { ...row({ wa_id: 'A' }), seq: 0 }
    const { entries, orphans } = project([edit, original])
    expect(orphans).toEqual([])
    expect(entries[0].current.wa_id).toBe('E1')
  })
})
