import { beforeAll, describe, expect, it } from 'vitest'

import type { SealedMessage } from '../src/api/protocol'
import { project } from '../src/state/conversation'
import {
  count,
  digest,
  fromBase64,
  hashesOf,
  limitOf,
  nextSelection,
  type Vote,
} from '../src/state/polls'

// Counting a poll is the one thing in this product the server structurally
// cannot do. It holds the poll and every vote and can match neither to the
// other: the options are sealed content, and a vote on the wire is nothing but
// SHA-256 of the option text. So this module is the tally, and every failure
// here is quiet — a poll that four people answered showing nobody, or showing
// nine votes, looks exactly like a poll.

let n = 0

function voter(over: Partial<Vote> & Pick<Vote, 'key'>): Vote {
  n += 1
  return {
    who: over.key,
    fromMe: false,
    at: new Date(2026, 0, 1, 12, 0, n),
    selected: [],
    opened: true,
    ...over,
  }
}

const options = ['Sexta', 'Sábado', 'Domingo']
let hashes: string[] = []

beforeAll(async () => {
  hashes = await hashesOf(options)
})

describe('matching votes to options', () => {
  it('counts a vote under the option whose text hashes to it', async () => {
    const tally = count(options, hashes, [voter({ key: 'ana', selected: [hashes[1]] })])

    expect(tally.options[1].voters.map((v) => v.key)).toEqual(['ana'])
    expect(tally.options[0].voters).toHaveLength(0)
    expect(tally.voters).toBe(1)
  })

  it('keeps only the last vote of somebody who changed their mind', () => {
    // WhatsApp replaces a voter's previous answer rather than adding to it.
    // Summing the rows would report one person as three.
    const tally = count(options, hashes, [
      voter({ key: 'ana', selected: [hashes[0]], at: new Date(2026, 0, 1, 12, 0, 0) }),
      voter({ key: 'ana', selected: [hashes[1]], at: new Date(2026, 0, 1, 12, 0, 5) }),
    ])

    expect(tally.voters).toBe(1)
    expect(tally.options[0].voters).toHaveLength(0)
    expect(tally.options[1].voters.map((v) => v.key)).toEqual(['ana'])
  })

  it('treats an empty selection as a withdrawal, not as an answer', () => {
    const tally = count(options, hashes, [
      voter({ key: 'ana', selected: [hashes[0]], at: new Date(2026, 0, 1, 12, 0, 0) }),
      voter({ key: 'ana', selected: [], at: new Date(2026, 0, 1, 12, 0, 9) }),
    ])

    expect(tally.voters).toBe(0)
    expect(tally.options[0].voters).toHaveLength(0)
    expect(tally.unmatched).toBe(0)
  })

  it('counts one person once however many options they ticked', () => {
    // A poll that allows three choices is still answered by one person.
    // "6 votos" on a poll three people answered is wrong in a way nobody
    // reading it could see.
    const tally = count(options, hashes, [
      voter({ key: 'ana', selected: [hashes[0], hashes[2]] }),
    ])

    expect(tally.voters).toBe(1)
    expect(tally.options[0].voters).toHaveLength(1)
    expect(tally.options[2].voters).toHaveLength(1)
  })

  it('reports a vote for an option it cannot see rather than dropping it', () => {
    // The option was edited, or came from a poll variant this client does not
    // parse. Silently ignoring it would report fewer voters than there were.
    const tally = count(options, hashes, [voter({ key: 'ana', selected: ['ff'.repeat(32)] })])

    expect(tally.unmatched).toBe(1)
    expect(tally.voters).toBe(1)
    expect(tally.options.every((o) => o.voters.length === 0)).toBe(true)
  })

  it('counts a vote nobody could open as somebody having answered', () => {
    // The archive missed the selection, not the vote. Leaving it out would
    // understate how many people responded, which is the number a reader
    // actually looks at.
    const tally = count(options, hashes, [voter({ key: 'ana', opened: false })])

    expect(tally.sealed).toBe(1)
    expect(tally.voters).toBe(1)
  })

  it('marks the option this account chose', () => {
    const tally = count(options, hashes, [
      voter({ key: '@me', fromMe: true, selected: [hashes[2]] }),
    ])

    expect(tally.options[2].mine).toBe(true)
    expect(tally.options[0].mine).toBe(false)
  })
})

describe('hashing', () => {
  it('is plain SHA-256 of the option text', async () => {
    // Against a known vector, not against itself. Pinned on the server too, by
    // TestPollOptionsAreHashedWithSHA256: the two ends have to agree on the
    // digest or every vote stores and none ever matches an option again, and
    // the poll simply looks unanswered.
    expect(await digest('a')).toBe(
      'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
    )
    // Non-ASCII goes in as UTF-8, which is what WhatsApp hashes. Latin-1 would
    // give a different digest for every option with an accent in it — that is
    // most of them, in this archive.
    expect(await digest('Sábado')).toBe(
      'f7a8575b1a8fe0094d86318e44c81618152725d554d72d8aa2046ede1b4e98cc',
    )
  })

  it('reads a selection out of the base64 Go writes', async () => {
    const hex = await digest('Sexta')
    const bytes = hex.match(/../g)!.map((h) => parseInt(h, 16))
    const b64 = btoa(String.fromCharCode(...bytes))

    expect(fromBase64(b64)).toBe(hex)
  })

  it('refuses to turn junk into a hash that could match an option', () => {
    // A malformed selection must match nothing rather than collide with
    // whatever happens to hash to an empty string.
    expect(fromBase64('not base64 at all !!')).toBe('')
  })
})

describe('placing votes in a conversation', () => {
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

  it('folds a vote onto its poll instead of drawing it as a line', () => {
    // A vote is stored with kind "message" — the four kinds are a CHECK
    // constraint from the first migration and a vote is not an edit, a
    // deletion or a reaction. But a chat window with eleven "voted" bubbles
    // between the poll and the next sentence is not what anybody wants.
    const conv = project([
      row({ wa_id: 'POLL', type: 'poll' }),
      row({ wa_id: 'V1', type: 'poll_vote', target_wa_id: 'POLL' }),
      row({ wa_id: 'V2', type: 'poll_vote', target_wa_id: 'POLL' }),
      row({ wa_id: 'NEXT' }),
    ])

    expect(conv.entries.map((e) => e.row.wa_id)).toEqual(['POLL', 'NEXT'])
    expect(conv.entries[0].votes.map((v) => v.wa_id)).toEqual(['V1', 'V2'])
  })

  it('keeps a vote whose poll is on an older page', () => {
    // Dropping it would lose an answer whenever a poll straddled a page
    // boundary, and paging back would never bring it home.
    const conv = project([row({ wa_id: 'V1', type: 'poll_vote', target_wa_id: 'ELSEWHERE' })])

    expect(conv.entries).toHaveLength(0)
    expect(conv.orphans.map((o) => o.wa_id)).toEqual(['V1'])
  })
})


describe('how many options a voter may pick', () => {
  const three = ['Sexta', 'Sábado', 'Domingo']

  it('reads a stated limit of one as one', () => {
    expect(limitOf({ selectable_count: 1, options: three })).toBe(1)
  })

  it('reads no stated limit as multiple, not as one', () => {
    // The bug this replaced. WhatsApp carries 1 for a single-answer poll —
    // that is what the field is for — and whatsmeow normalises anything out of
    // range to 0, so 0 is a poll that stated no limit at all. Reading it as 1
    // refused the second tick on every multiple-choice poll in the archive,
    // silently, while the same poll on a phone accepted it.
    expect(limitOf({ selectable_count: 0, options: three })).toBe(3)
    expect(limitOf({ options: three })).toBe(3)
  })

  it('never lets a poll claim a limit larger than itself', () => {
    expect(limitOf({ selectable_count: 9, options: three })).toBe(3)
  })

  it('never returns zero, which would refuse every press', () => {
    expect(limitOf({})).toBe(1)
    expect(limitOf({ selectable_count: 0, options: [] })).toBe(1)
  })
})

describe('pressing an option', () => {
  it('adds it when there is room', () => {
    expect(nextSelection(['Sexta'], 'Sábado', 3)).toEqual({
      options: ['Sexta', 'Sábado'],
      refused: false,
    })
  })

  it('takes back one already chosen, keeping the rest', () => {
    // A vote replaces the previous answer, so withdrawing one choice means
    // sending the others without it.
    expect(nextSelection(['Sexta', 'Sábado'], 'Sexta', 3)).toEqual({
      options: ['Sábado'],
      refused: false,
    })
  })

  it('replaces the choice in a single-answer poll', () => {
    // At a limit of one, the old choice must come out or nothing can ever be
    // changed — but only by pressing it. Pressing a different option with one
    // already held is a refusal, and the UI says so.
    expect(nextSelection(['Sexta'], 'Sexta', 1).options).toEqual([])
    expect(nextSelection(['Sexta'], 'Sábado', 1).refused).toBe(true)
  })

  it('refuses at the limit rather than silently unticking the oldest', () => {
    // Dropping the oldest to make room was the alternative. It unticks
    // something the person chose deliberately, and the only evidence would be
    // a count that failed to go up.
    const at = nextSelection(['Sexta', 'Sábado'], 'Domingo', 2)
    expect(at.refused).toBe(true)
    expect(at.options).toEqual(['Sexta', 'Sábado'])
  })

  it('lets an already-chosen option out even at the limit', () => {
    // Otherwise a full selection can never be changed at all.
    expect(nextSelection(['Sexta', 'Sábado'], 'Sexta', 2)).toEqual({
      options: ['Sábado'],
      refused: false,
    })
  })
})
