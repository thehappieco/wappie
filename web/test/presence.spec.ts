// Somebody typing, which is true for a few seconds and then is not.
//
// Nothing about it is stored, on either side, so the only thing keeping it
// honest on screen is the expiry. WhatsApp does not promise a "paused" for
// every "composing" — a phone that goes into a tunnel mid-sentence sends
// nothing further — so a client that waited for one shows somebody typing
// forever, in a conversation they left an hour ago.

import { beforeEach, describe, expect, it } from 'vitest'

import type { PresenceEvent } from '../src/api/protocol'
import { people, state } from '../src/state/archive'
import { applyPresence, availabilityIn, forgetPresence, typingIn } from '../src/state/presence'

const CHAT = '120363000000000000@g.us'

function event(over: Partial<PresenceEvent>): PresenceEvent {
  return {
    device_id: state.deviceID,
    chat_key: CHAT,
    sender_key: '111@lid',
    sender_lid: '111@lid',
    state: 'composing',
    ...over,
  } as PresenceEvent
}

beforeEach(() => {
  forgetPresence()
  people().clear()
  state.deviceID = 'dev'
  state.connected = true
  state.quiet = false
})

describe('a contact online state', () => {
  const peer = '123@lid'
  it('distinguishes unavailable information from a reported offline state', () => {
    expect(availabilityIn(peer)).toBe('unknown')
    applyPresence(event({ chat_key: peer, state: 'available' }))
    expect(availabilityIn(peer)).toBe('online')
    expect(typingIn(peer)).toEqual([])
    applyPresence(event({ chat_key: peer, state: 'unavailable' }))
    expect(availabilityIn(peer)).toBe('offline')
  })
  it('does not leak presence across devices or retain stale online claims', () => {
    applyPresence(event({ chat_key: peer, device_id: 'different', state: 'available' }))
    expect(availabilityIn(peer)).toBe('unknown')
    applyPresence(event({ chat_key: peer, state: 'available' }))
    expect(availabilityIn(peer, Date.now() + 90_001)).toBe('unknown')
  })
  it('matches the phone and LID only through explicit event aliases', () => {
    applyPresence(event({ chat_key: peer, sender_lid: peer, sender_pn: '555@s.whatsapp.net', state: 'available' }))
    expect(availabilityIn('555@s.whatsapp.net')).toBe('online')
    expect(availabilityIn('555@lid')).toBe('unknown')
  })
  it('does not mistake matching phone and LID digits for a known identity mapping', () => {
    people().add({ key: '666@s.whatsapp.net', uid: 'test', pn: '666@s.whatsapp.net', isGroup: false,
      full: 'Example', business: '', push: '', hasAvatar: false })
    applyPresence(event({ chat_key: '666@lid', sender_key: '666@lid', sender_lid: '666@lid', state: 'available' }))
    expect(availabilityIn('666@s.whatsapp.net')).toBe('unknown')
    expect(availabilityIn('666@lid')).toBe('online')
  })
  it('hides prior state while incognito or disconnected and clears on logout', () => {
    applyPresence(event({ chat_key: peer, state: 'available' }))
    state.quiet = true
    expect(availabilityIn(peer)).toBe('unknown')
    state.quiet = false
    state.connected = false
    expect(availabilityIn(peer)).toBe('unknown')
    state.connected = true
    forgetPresence()
    expect(availabilityIn(peer)).toBe('unknown')
  })
  it('does not interpret new or malformed event states as typing', () => {
    applyPresence(event({ state: 'future-status' }))
    expect(typingIn(CHAT)).toEqual([])
  })
})

describe('a typing notification', () => {
  it('shows the person typing', () => {
    applyPresence(event({}))
    expect(typingIn(CHAT)).toHaveLength(1)
  })

  it('is taken back by a pause', () => {
    applyPresence(event({}))
    applyPresence(event({ state: 'paused' }))
    expect(typingIn(CHAT)).toHaveLength(0)
  })

  // The whole reliability model. Without it, a "composing" whose "paused" never
  // arrives leaves somebody typing on screen for the life of the tab.
  it('expires on its own when no pause ever arrives', () => {
    applyPresence(event({}))
    const muchLater = Date.now() + 60_000
    expect(typingIn(CHAT, muchLater)).toHaveLength(0)
  })

  it('distinguishes recording from typing', () => {
    applyPresence(event({ media: 'audio' }))
    expect(typingIn(CHAT)[0].media).toBe('audio')
  })

  // A group can have several people typing at once, and they are different
  // people rather than one person changing their mind.
  it('keeps several people apart in a group', () => {
    applyPresence(event({ sender_key: '111@lid' }))
    applyPresence(event({ sender_key: '222@lid' }))
    expect(typingIn(CHAT)).toHaveLength(2)
    applyPresence(event({ sender_key: '111@lid', state: 'paused' }))
    expect(typingIn(CHAT)).toHaveLength(1)
  })

  // A presence frame names a device. One belonging to another of the account's
  // devices is not about the conversation on screen.
  it('ignores a notification for another device', () => {
    applyPresence(event({ device_id: 'outro' }))
    expect(typingIn(CHAT)).toHaveLength(0)
  })

  it('is forgotten when the session ends', () => {
    applyPresence(event({}))
    forgetPresence()
    expect(typingIn(CHAT)).toHaveLength(0)
  })
})
