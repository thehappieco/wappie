import { describe, expect, it } from 'vitest'

import { Directory } from '../src/state/directory'
import { displayFallback, initials } from '../src/state/jid'

// Ten unnamed people in one group used to render as ten copies of "contato sem
// número" — which reads as one person saying all of it, and is worse than an
// ugly label. Whatever is shown for somebody with no name has to differ between
// two people, and must never look like a phone number they deliberately hid.

describe('somebody with no name', () => {
  it('is distinguishable from somebody else with no name', () => {
    const one = displayFallback('42631895773279@lid')
    const two = displayFallback('19284756102938@lid')
    expect(one).not.toBe(two)
  })

  it('does not pretend a LID is a phone number', () => {
    const label = displayFallback('42631895773279@lid')
    expect(label).toContain('LID')
    expect(label).not.toMatch(/^\+/)
  })

  it('keeps every digit, because a short tail collides', () => {
    // This account has 883 distinct group senders. A four-digit suffix collides
    // among that many with near certainty, which would put the bug back.
    expect(displayFallback('42631895773279@lid')).toContain('42631895773279')
  })

  it('says so plainly when there is no identifier at all', () => {
    expect(displayFallback('@lid')).toBe('sem identificação')
  })
})

describe('the badge mark', () => {
  it('is initials for a real name', () => {
    expect(initials('Felipe Restum')).toBe('FR')
  })

  it('does not reduce every unnamed person to the same two letters', () => {
    // initials() of "LID 4263…" is "L4" for everybody, so the component keys the
    // mark off the identifier instead when the name is not a name. This test
    // pins the property the component depends on: the label has no letters to
    // work with beyond the prefix.
    const label = displayFallback('42631895773279@lid')
    expect(label.replace(/^LID\s/, '')).not.toMatch(/\p{L}/u)
  })
})

// The two questions a directory gets asked, and why they need different answers.
//
// nameFor() exists so a row always has something to draw, so it falls back to a
// rendered identifier and is never empty. That makes it silently wrong for the
// other question — "does anybody actually know who this is?" — and the wrongness
// only shows up as behaviour that never happens: a truthy fallback satisfies an
// `if (named)` guard, so the code after it is unreachable and looks fine.
//
// Two real defects came from exactly that. `nameFor(lid) || nameFor(pn)` never
// reached pn, defeating the "try both identifiers" it was written for. And a
// list-repair pass guarded on nameFor overwrote every direct conversation with
// a rendered phone number, replacing names with numbers — the opposite of its
// purpose. Neither failed a test, because both produce a perfectly ordinary
// screen.

describe('asking a directory whether it knows somebody', () => {
  const dir = new Directory()
  dir.add({
    key: '5511999999999@s.whatsapp.net',
    uid: 'u1',
    pn: '5511999999999@s.whatsapp.net',
    isGroup: false,
    full: 'José Silva',
    business: '',
    push: '',
    hasAvatar: false,
  })

  it('nameFor never comes back empty, which is what it is for', () => {
    expect(dir.nameFor('42631895773279@lid')).toBe(displayFallback('42631895773279@lid'))
    expect(dir.nameFor('42631895773279@lid')).not.toBe('')
  })

  it('knownName comes back empty when nobody has named the identifier', () => {
    expect(dir.knownName('42631895773279@lid')).toBe('')
  })

  it('knownName returns the real name when there is one', () => {
    expect(dir.knownName('5511999999999@s.whatsapp.net')).toBe('José Silva')
  })

  // The concrete regression: with nameFor, this expression short-circuits on an
  // unknown LID and the phone number beside it — which IS named — is never
  // consulted. The person shows as a LID with their name one column away.
  it('lets a caller try both halves of an identity', () => {
    const lid = '42631895773279@lid'
    const pn = '5511999999999@s.whatsapp.net'
    expect(dir.nameFor(lid) || dir.nameFor(pn)).not.toBe('José Silva')
    expect(dir.knownName(lid) || dir.knownName(pn)).toBe('José Silva')
  })

  it('isKnown agrees with knownName, because it is the same question', () => {
    expect(dir.isKnown('5511999999999@s.whatsapp.net')).toBe(true)
    expect(dir.isKnown('42631895773279@lid')).toBe(false)
    expect(dir.isKnown(undefined)).toBe(false)
  })
})
