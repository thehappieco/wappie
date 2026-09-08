// The "temporária" marker, which came and went.
//
// Reported from the field: the chip appeared on some disappearing messages and
// not on others that all had an expiry date. The cause is that two different
// facts are stored — `ephemeral` says the message travelled inside the
// disappearing envelope, `expiration` says what timer it declared — and only
// the first was read. They normally agree, because send.wrap makes sure of it
// on the way out, and they do not agree on rows that came from a history sync
// or from a client that wrote the timer without the wrapper.
//
// The failure is quiet in the worst way for this product: a message the archive
// knows was meant to vanish is presented as an ordinary one.

import { describe, expect, it } from 'vitest'

import { expiryLabel, hasExpired, isEphemeral, timerLabel } from '../src/state/ephemeral'

const NOW = Date.UTC(2026, 8, 2, 12, 0, 0)
const soon = new Date(NOW + 3_600_000)
const past = new Date(NOW - 3_600_000)

describe('deciding a message was meant to disappear', () => {
  it('accepts the envelope flag', () => {
    expect(isEphemeral({ ephemeral: true, expiration: 0 })).toBe(true)
  })

  it('accepts a declared timer with no flag', () => {
    expect(isEphemeral({ ephemeral: false, expiration: 604_800 })).toBe(true)
  })

  it('accepts an expiry date with neither', () => {
    expect(isEphemeral({ ephemeral: false, expiration: 0, expiresAt: soon })).toBe(true)
  })

  it('says no to an ordinary message', () => {
    expect(isEphemeral({ ephemeral: false, expiration: 0 })).toBe(false)
  })
})

describe('the chip on the bubble', () => {
  it('says nothing for an ordinary message', () => {
    expect(expiryLabel({ ephemeral: false, expiration: 0 }, NOW)).toBe('')
  })

  it('says temporária while the timer is still running', () => {
    expect(expiryLabel({ ephemeral: true, expiration: 86_400, expiresAt: soon }, NOW)).toBe(
      'temporária',
    )
  })

  // "expirada", not "apagada". Nothing was deleted and the message is still
  // here — that is the point of the archive. What it says is that the sender's
  // timer has run out, so on every other client in the conversation this text
  // is gone.
  it('says expirada once the moment has passed', () => {
    expect(expiryLabel({ ephemeral: true, expiration: 86_400, expiresAt: past }, NOW)).toBe(
      'expirada',
    )
  })

  it('stays temporária when a timer was declared but no date was computed', () => {
    expect(expiryLabel({ ephemeral: false, expiration: 86_400 }, NOW)).toBe('temporária')
    expect(hasExpired({ ephemeral: false, expiration: 86_400 }, NOW)).toBe(false)
  })
})

describe('naming a timer', () => {
  it('uses WhatsApp’s own words for its own presets', () => {
    expect(timerLabel(0)).toBe('desativadas')
    expect(timerLabel(86_400)).toBe('24 horas')
    expect(timerLabel(604_800)).toBe('7 dias')
    expect(timerLabel(7_776_000)).toBe('90 dias')
  })

  // The protocol accepts any number of seconds, and a value that did not come
  // from a preset has to be visible as such rather than rounded to the nearest
  // one — otherwise a chat set to something unusual reads as a normal chat.
  it('spells out a value that is not a preset', () => {
    expect(timerLabel(3_600)).toBe('1 horas')
    expect(timerLabel(172_800)).toBe('2 dias')
    expect(timerLabel(90)).toBe('90 s')
  })
})
