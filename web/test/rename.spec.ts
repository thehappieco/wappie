// Repairing a chat-list label after a name arrives late.
//
// The directory is loaded once at sign-in and is a plain Map, deliberately not
// reactive — five thousand people made reactive to catch the handful that
// change is a poor trade. So a name learned afterwards changes nothing until
// the rows on screen are told, and this is the rule that tells them.
//
// Both of its conditions were wrong once, and neither failure showed up as an
// error. The first guarded on nameFor(), which falls back to a rendered
// identifier and is therefore never empty — so the pass fired on every direct
// conversation and overwrote its name with a phone number about a tenth of a
// second after the list drew. Names turning into numbers, produced by the
// feature whose entire purpose is numbers turning into names.

import { describe, expect, it } from 'vitest'

import {
  ASK_AGAIN_MS,
  AVATAR_ASK_AGAIN_MS,
  AVATAR_IN_FLIGHT,
  byRecency,
  renameTo,
  type ChatView,
} from '../src/state/archive'

const direct = { name: 'LID 42631895773279', nameState: 'absent' as const, isGroup: false, isStatus: false }

describe('repairing a chat label', () => {
  it('applies a name that was learned after the row was drawn', () => {
    expect(renameTo(direct, 'José Silva')).toBe('José Silva')
  })

  // The regression. An empty string is what "nobody has named this" has to look
  // like; a caller passing nameFor() hands over "LID 4263…" or "+55 (11) …"
  // instead, and the row is rewritten to it.
  it('leaves the row alone when nobody has a name for it', () => {
    expect(renameTo(direct, '')).toBeNull()
  })

  it('leaves a conversation that carries its own sealed name alone', () => {
    // toChatView prefers the sealed chat name over a contact's. Overriding it
    // here would make the list say one thing on load and another a moment
    // later, with nothing a reader could point at to explain the change.
    const named = { ...direct, name: 'Trabalho', nameState: 'ok' as const }
    expect(renameTo(named, 'José Silva')).toBeNull()
  })

  it('still repairs a row whose sealed name refused to open', () => {
    // 'tampered' and 'locked' are not names. They are reasons there is no name,
    // and a contact that can be named is strictly better than either.
    for (const nameState of ['tampered', 'locked'] as const) {
      expect(renameTo({ ...direct, nameState }, 'José Silva')).toBe('José Silva')
    }
  })

  it('never touches a group', () => {
    // A group's name lives on the chat row, sealed. Its contacts row exists
    // only to hang a picture on and carries no name at all, so a group would be
    // renamed to whatever displayFallback makes of its numeric id.
    expect(renameTo({ ...direct, isGroup: true }, 'algum nome')).toBeNull()
  })

  it('never touches the status feed, which is not a conversation', () => {
    expect(renameTo({ ...direct, isStatus: true, name: 'Status' }, 'algum nome')).toBeNull()
  })

  it('does not churn when the name is already what it should be', () => {
    expect(renameTo({ ...direct, name: 'José Silva' }, 'José Silva')).toBeNull()
  })
})

// Two questions that age differently, and the window that has to differ with
// them.
//
// A name nobody has is usually about to arrive: a push name lands with the
// first message somebody sends, so asking again in half a minute is right. A
// face nobody has is usually permanent — no picture, or privacy settings hide
// it — and the server records that so its own worker stops asking. Putting both
// on the same short window turned every badge remount (filtering the list,
// switching conversation) into another request for exactly the contacts whose
// answer never changes: invisible on screen, visible only as traffic over the
// device's own socket.
describe('how long "nothing known" is trusted', () => {
  it('trusts a missing face far longer than a missing name', () => {
    expect(AVATAR_ASK_AGAIN_MS).toBeGreaterThan(ASK_AGAIN_MS)
  })

  it('still re-asks for a face eventually, rather than never', () => {
    // The shape before this was a permanent Set: asked once, never again for
    // the life of the tab. A picture the paced worker fetched a minute later
    // then needed a reload to appear.
    expect(Number.isFinite(AVATAR_ASK_AGAIN_MS)).toBe(true)
  })
})

// Where a group you just joined ends up in the list.
//
// A conversation exists from the moment the account is in the group — no
// message, and therefore no timestamp to sort by. Ordering on the timestamp
// alone puts every one of them behind every conversation that has ever been
// spoken in, in no particular order among themselves. On the archive this was
// found on that was 1029 behind 592, and the answer to "where is the group I
// just joined" was that it was somewhere in the middle of a thousand others.
describe('ordering conversations with no message', () => {
  const chat = (over: Partial<ChatView>): ChatView =>
    ({
      key: 'k', uid: 'u', isGroup: false, isStatus: false, name: 'n',
      nameState: 'absent', lastSeq: 0, lastKind: '', lastType: '',
      unread: 0, pinned: false, archived: false, preview: '',
      previewState: 'absent', avatarKey: 'k', ...over,
    }) as ChatView

  const sort = (cs: ChatView[]) => [...cs].sort(byRecency).map((c) => c.key)

  it('puts conversations that have been spoken in first', () => {
    const spoken = chat({ key: 'falada', lastTS: new Date('2026-01-01') })
    // Recorded today but never spoken in: still below a conversation from January.
    const quiet = chat({ key: 'calada', createdAt: new Date('2026-09-03') })
    expect(sort([quiet, spoken])).toEqual(['falada', 'calada'])
  })

  it('orders the quiet ones newest first', () => {
    const old = chat({ key: 'antigo', createdAt: new Date('2024-01-01') })
    const fresh = chat({ key: 'novo', createdAt: new Date('2026-09-03') })
    expect(sort([old, fresh])).toEqual(['novo', 'antigo'])
  })

  it('still keeps pinned conversations on top', () => {
    const pinned = chat({ key: 'fixado', pinned: true })
    const recent = chat({ key: 'recente', lastTS: new Date('2026-09-03') })
    expect(sort([recent, pinned])).toEqual(['fixado', 'recente'])
  })
})

// How many profile pictures may be asked for at once.
//
// There was no limit, and it worked while the sidebar held a few hundred rows.
// Every badge asks as it mounts, so when the list grew to sixteen hundred the
// tab opened sixteen hundred simultaneous requests against a server whose API
// pool is sixteen connections. Most sat past the twenty second timeout, the
// failure was swallowed, and each had already been marked as asked — so nothing
// retried for ten minutes. What a person saw was photographs that used to be
// there and were not any more.
describe('asking for profile pictures', () => {
  it('keeps a small number in flight', () => {
    expect(AVATAR_IN_FLIGHT).toBeGreaterThan(0)
    expect(AVATAR_IN_FLIGHT).toBeLessThanOrEqual(8)
  })
})
