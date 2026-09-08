import { describe, expect, it } from 'vitest'
import { computed, isRef } from 'vue'

import type { MessageView } from '../src/state/archive'
import { EDIT_WINDOW_MS, canDelete, canEdit, editableFor, myReaction, nowTick } from '../src/state/actions'

// The rules the action strip promises. Every one of them is a refusal the
// client makes locally, and the reason to make it locally is the same each
// time: a round trip that ends in "WhatsApp said no" is a worse answer than one
// that was never sent.

function message(over: Partial<MessageView> = {}): MessageView {
  const row = {
    uid: 'u1',
    seq: 1,
    device_id: 'd',
    wa_id: 'WA1',
    chat_key: 'c@g.us',
    is_from_me: true,
    is_group: true,
    kind: 'message',
    type: 'text',
    source: 'live',
    content_key_id: 0,
  }
  return {
    uid: 'u1',
    waID: 'WA1',
    seq: 1,
    ts: new Date(nowTick.value),
    fromMe: true,
    isGroup: true,
    isStatus: false,
    senderKey: '@me',
    senderName: 'você',
    type: 'text',
    unsupported: '',
    body: 'oi',
    bodyState: 'ok',
    reactions: [],
    edited: false,
    versionCount: 1,
    deleted: false,
    viewOnce: false,
    ephemeral: false,
    forwarded: false,
    forwardingScore: 0,
    entry: { row, versions: [row], current: row, reactions: [] },
    ...over,
  } as MessageView
}

describe('editing a message', () => {
  it('is offered on my own message inside the window', () => {
    expect(canEdit(message())).toBe(true)
  })

  it('is not offered on somebody else\'s message', () => {
    // WhatsApp would refuse it, and offering what cannot be promised is worse
    // than not offering it.
    expect(canEdit(message({ fromMe: false }))).toBe(false)
  })

  it('closes twenty minutes after the message was sent', () => {
    const old = message({ ts: new Date(nowTick.value - EDIT_WINDOW_MS - 1000) })
    expect(canEdit(old)).toBe(false)
    expect(editableFor(old)).toBeLessThan(0)
  })

  it('counts down rather than reporting a constant', () => {
    const halfway = message({ ts: new Date(nowTick.value - EDIT_WINDOW_MS / 2) })
    const left = editableFor(halfway)
    expect(left).toBeGreaterThan(0)
    expect(left).toBeLessThan(EDIT_WINDOW_MS)
  })

  it('is not offered on a message that was deleted', () => {
    expect(canEdit(message({ deleted: true }))).toBe(false)
  })

  it('is not offered on a message that has not been sent yet', () => {
    expect(canEdit(message({ pending: 'sending' }))).toBe(false)
  })
})

describe('deleting a message', () => {
  it('is offered on my own', () => {
    expect(canDelete(message())).toBe(true)
  })

  it('is not offered on somebody else\'s', () => {
    // WhatsApp allows a group admin to, and the protocol carries the field —
    // but nothing in this system knows who administers which group, so the
    // request would fail in a way the person could not have predicted.
    expect(canDelete(message({ fromMe: false }))).toBe(false)
  })

  it('has no window: an old message can still be deleted', () => {
    const ancient = message({ ts: new Date(nowTick.value - 30 * 24 * 3600 * 1000) })
    expect(canDelete(ancient)).toBe(true)
    expect(canEdit(ancient)).toBe(false)
  })
})

describe('reacting', () => {
  it('reports nothing when this account has not reacted', () => {
    expect(myReaction(message())).toBe('')
  })

  it('reports my emoji and not somebody else\'s', () => {
    const m = message({
      reactions: [
        { emoji: '😂', who: 'alguém', fromMe: false },
        { emoji: '👍', who: 'você', fromMe: true },
      ],
    })
    expect(myReaction(m)).toBe('👍')
  })
})

// The clock has to be a ref, and it was not.
//
// nowTick was a plain object literal with a setInterval writing to it. Vue does
// not track a plain object, so every computed reading it evaluated once and
// never again: the interval ran for the life of the tab, updating a value
// nothing was watching. Two things depend on it and both silently stopped
// moving — the edit countdown, and the chip that turns "temporária" into
// "expirada" when a disappearing message passes its date.
//
// It reads correctly at first draw either way, which is what makes it hard to
// see: the countdown shows the right number, then never shows another one.
describe('the ticking clock', () => {
  it('is reactive, or nothing that depends on it ever moves', () => {
    expect(isRef(nowTick)).toBe(true)
  })

  it('is watched by a computed that reads it', () => {
    const seen: number[] = []
    const label = computed(() => nowTick.value)
    seen.push(label.value)
    nowTick.value = nowTick.value + 60_000
    seen.push(label.value)
    expect(seen[1]).toBe(seen[0] + 60_000)
  })
})
