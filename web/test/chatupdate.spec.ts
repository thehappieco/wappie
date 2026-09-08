import { beforeEach, describe, expect, it } from 'vitest'

import { applyChatUpdate, state } from '../src/state/archive'

// A conversation's badge and its disappearing timer both live on the chat row,
// and until this frame existed the only thing that carried either was the reply
// to a chats.list request. So a badge moved when the sidebar happened to be
// refetched and at no other moment, and a timer the other side changed was
// invisible until a reload.
//
// The rule that matters here is that this is a PATCH. Absent means "this event
// says nothing about that field"; zero is a real value for both — a badge of
// zero is a conversation just read, a timer of zero is disappearing messages
// turned off — so a truthiness test would silently refuse to apply either.

function chat(over: Record<string, unknown> = {}) {
  return {
    key: '5511999999999@s.whatsapp.net',
    keys: ['5511999999999@s.whatsapp.net', '224437861388494@lid'],
    unread: 3,
    ephemeral: 86400,
    ...over,
  }
}

beforeEach(() => {
  state.deviceID = 'dev-1'
  state.chats = [chat()] as never
})

describe('a live chat update', () => {
  it('applies a badge', () => {
    applyChatUpdate({ device_id: 'dev-1', chat_key: state.chats[0].key, unread: 7 })
    expect(state.chats[0].unread).toBe(7)
  })

  it('applies a badge of zero, which is the whole point of reading', () => {
    applyChatUpdate({ device_id: 'dev-1', chat_key: state.chats[0].key, unread: 0 })
    expect(state.chats[0].unread).toBe(0)
  })

  it('applies a timer of zero, which is how it gets turned off', () => {
    applyChatUpdate({ device_id: 'dev-1', chat_key: state.chats[0].key, ephemeral: 0 })
    expect(state.chats[0].ephemeral).toBe(0)
  })

  it('leaves alone what the event does not mention', () => {
    // An event about a badge says nothing about the timer. Treating absent as
    // zero would clear one every time the other moved.
    applyChatUpdate({ device_id: 'dev-1', chat_key: state.chats[0].key, unread: 1 })
    expect(state.chats[0].ephemeral).toBe(86400)

    applyChatUpdate({ device_id: 'dev-1', chat_key: state.chats[0].key, ephemeral: 604800 })
    expect(state.chats[0].unread).toBe(1)
  })

  it('finds the conversation by any key it is stored under', () => {
    // One person can hold a LID row and a phone-number row, folded into one
    // line. The server announces whichever row changed.
    applyChatUpdate({ device_id: 'dev-1', chat_key: '224437861388494@lid', unread: 9 })
    expect(state.chats[0].unread).toBe(9)
  })

  it('ignores an update for another device', () => {
    applyChatUpdate({ device_id: 'other', chat_key: state.chats[0].key, unread: 99 })
    expect(state.chats[0].unread).toBe(3)
  })

  it('ignores a conversation it has never listed, rather than inventing one', () => {
    // The message that creates a chat brings the listing with it. A half-empty
    // row made here would put a nameless conversation in the sidebar.
    applyChatUpdate({ device_id: 'dev-1', chat_key: 'nobody@s.whatsapp.net', unread: 4 })
    expect(state.chats).toHaveLength(1)
    expect(state.chats[0].unread).toBe(3)
  })
})
