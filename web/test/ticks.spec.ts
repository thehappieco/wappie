// What the ticks claim, and what they must refuse to claim.
//
// The owner's rule: one grey means sent, two grey means EVERYONE received it,
// two blue means everyone read it, three blue means everyone played it. The
// word doing the work is "everyone", and it is the reason a denominator is not
// an implementation detail — two acknowledgements mean everything between two
// people and almost nothing in a group of forty.
//
// Every test here is about the same failure: telling somebody a message was
// received or read when the archive does not know that. It is the one lie this
// screen can tell that a person would act on.

import { describe, expect, it } from 'vitest'

import { denominatorFor, noAcks, playable, tickReport, type Acks, type Ticked } from '../src/state/ticks'

const mine: Ticked = { fromMe: true, type: 'text', viewOnce: false }
const acks = (over: Partial<Acks>): Acks => ({ ...noAcks(), ...over })

describe('a message nobody else sent', () => {
  it('draws nothing on an incoming message', () => {
    expect(tickReport({ ...mine, fromMe: false }, acks({ read: 5 }), 1).tick).toBe('')
  })

  it('draws a clock while it is still leaving', () => {
    expect(tickReport({ ...mine, pending: 'sending' }, noAcks(), 1).tick).toBe('pending')
  })

  it('draws nothing on one that never went', () => {
    expect(tickReport({ ...mine, pending: 'failed' }, noAcks(), 1).tick).toBe('')
  })
})

describe('a direct conversation, where everyone is one person', () => {
  it('is one grey until the other side has it', () => {
    expect(tickReport(mine, noAcks(), 1).tick).toBe('sent')
  })

  it('is two grey when they received it', () => {
    expect(tickReport(mine, acks({ delivered: 1 }), 1).tick).toBe('delivered')
  })

  it('is blue when they read it', () => {
    expect(tickReport(mine, acks({ delivered: 1, read: 1 }), 1).tick).toBe('read')
  })
})

describe('a group, where everyone is everyone', () => {
  // The whole point. Four of nine having received it is not "delivered", and
  // drawing it as such is a claim about five people who may not have their
  // phones on.
  it('does not say delivered until everybody has', () => {
    const r = tickReport(mine, acks({ delivered: 4 }), 9)
    expect(r.tick).toBe('sent')
    expect(r.caveat).toContain('4 de 9')
  })

  it('says delivered when everybody has', () => {
    expect(tickReport(mine, acks({ delivered: 9 }), 9).tick).toBe('delivered')
  })

  it('says read only when everybody read', () => {
    expect(tickReport(mine, acks({ delivered: 9, read: 8 }), 9).tick).toBe('delivered')
    expect(tickReport(mine, acks({ delivered: 9, read: 9 }), 9).tick).toBe('read')
  })
})

describe('when the denominator is not known', () => {
  // A group whose size nobody has asked WhatsApp about. Falling through to 1
  // would paint a message to forty people blue the moment one of them read it,
  // and there is nothing on screen to suggest the number was invented.
  it('refuses to promote, and says why', () => {
    const r = tickReport(mine, acks({ delivered: 3, read: 3 }), undefined)
    expect(r.tick).toBe('sent')
    expect(r.caveat).toContain('quantos')
  })

  it('treats a broadcast list as unknown rather than as one person', () => {
    expect(denominatorFor({ isGroup: false, isStatus: false }, '123@broadcast')).toBeUndefined()
    expect(denominatorFor({ isGroup: false, isStatus: false }, '123@newsletter')).toBeUndefined()
  })

  it('is one for a direct conversation and everyone-but-us for a group', () => {
    expect(denominatorFor({ isGroup: false, isStatus: false }, '55@s.whatsapp.net')).toBe(1)
    expect(denominatorFor({ isGroup: true, isStatus: false, audience: 9 }, '1@g.us')).toBe(8)
    expect(denominatorFor({ isGroup: true, isStatus: false }, '1@g.us')).toBeUndefined()
  })
})

describe('the third tick', () => {
  // Reading "playable" as "has an attachment" leaves every photograph at two
  // blue ticks forever, waiting for a state WhatsApp never reports for one.
  it('exists for voice notes and view-once, and nothing else', () => {
    expect(playable({ ...mine, type: 'ptt' })).toBe(true)
    expect(playable({ ...mine, type: 'image', viewOnce: true })).toBe(true)
    expect(playable({ ...mine, type: 'image' })).toBe(false)
    expect(playable({ ...mine, type: 'video' })).toBe(false)
  })

  it('is not reached by a message that has no third step', () => {
    const photo: Ticked = { fromMe: true, type: 'image', viewOnce: false }
    expect(tickReport(photo, acks({ delivered: 1, read: 1, played: 1 }), 1).tick).toBe('read')
  })

  it('is reached by a voice note everybody played', () => {
    const note: Ticked = { fromMe: true, type: 'ptt', viewOnce: false }
    expect(tickReport(note, acks({ delivered: 1, read: 1, played: 1 }), 1).tick).toBe('played')
  })
})

describe('acknowledgements that are not acknowledgements', () => {
  // A message stuck in retry looks delivered from every angle except the one
  // that matters, and saying so is the most misleading thing this can do.
  it('never promotes a message being retried', () => {
    const r = tickReport(mine, acks({ delivered: 1, retrying: true }), 1)
    expect(r.tick).toBe('sent')
    expect(r.caveat).toContain('tentada')
  })

  it('never promotes one the server refused', () => {
    expect(tickReport(mine, acks({ delivered: 1, failed: true }), 1).tick).toBe('sent')
  })

  // More acknowledgements than recipients means the denominator is not
  // describing this message — somebody left the group, or one person was
  // counted as two. Promoting on it is promoting on a number known to be wrong.
  it('refuses to promote when there are more acknowledgements than people', () => {
    const r = tickReport(mine, acks({ delivered: 5, read: 5 }), 3)
    expect(r.tick).toBe('sent')
    expect(r.caveat).toContain('composição do grupo mudou')
  })
})
