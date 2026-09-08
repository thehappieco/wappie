import { describe, expect, it } from 'vitest'

import type { ReaderRevision } from '../src/api/protocol'
import { revisionsOf } from '../src/state/archive'

// The reader mapping had no test at all, and it is the kind of code that fails
// without saying anything: a missing revision reads as "nobody received this
// version", which is the same shape as the truth and therefore invisible.
//
// The panel asks about a revision by NUMBER. Every mistake here is a mistake
// about which number goes with which time.

function row(over: Partial<ReaderRevision> & Pick<ReaderRevision, 'revision'>): ReaderRevision {
  return { ...over }
}

describe('a reader per-version record', () => {
  it('is keyed by revision number, not by position', () => {
    // The revisions a reader acknowledged are not necessarily 0..n. Indexing by
    // position puts one version's delivery time under another's heading, and
    // both are plausible times so nothing looks wrong.
    const revs = revisionsOf([
      row({ revision: 0, delivered: '2026-09-03T10:01:00Z' }),
      row({ revision: 2, delivered: '2026-09-03T10:20:00Z' }),
    ])

    expect(revs.get(0)?.delivered?.toISOString()).toBe('2026-09-03T10:01:00.000Z')
    expect(revs.get(2)?.delivered?.toISOString()).toBe('2026-09-03T10:20:00.000Z')
    expect(revs.get(1)).toBeUndefined()
  })

  it('reports a version nobody acknowledged as absent, not as zero', () => {
    // "Never delivered" and "delivered at the epoch" are different facts, and
    // one of them is a date the panel would happily print.
    const revs = revisionsOf([row({ revision: 1 })])

    expect(revs.get(1)).toBeDefined()
    expect(revs.get(1)?.delivered).toBeUndefined()
    expect(revs.get(1)?.read).toBeUndefined()
  })

  it('never claims a version was confirmed when nobody read it', () => {
    // confirmed qualifies a read. Sitting on its own it is a value the panel
    // renders as "confirmado" for a version nobody looked at. The server omits
    // it in that case, so the client must not invent a default of true.
    const revs = revisionsOf([row({ revision: 0, delivered: '2026-09-03T10:01:00Z' })])

    expect(revs.get(0)?.confirmed).toBe(false)
  })

  it('keeps an inferred read distinguishable from a confirmed one', () => {
    const revs = revisionsOf([
      row({ revision: 0, read: '2026-09-03T10:05:00Z', confirmed: true }),
      row({ revision: 1, read: '2026-09-03T10:12:00Z' }),
    ])

    expect(revs.get(0)?.confirmed).toBe(true)
    expect(revs.get(1)?.confirmed).toBe(false)
  })

  it('survives a reader the server sent no revisions for', () => {
    // The field is omitempty on the wire. An empty map is an answer; a throw
    // in the middle of the panel is not.
    expect(revisionsOf(undefined).size).toBe(0)
    expect(revisionsOf([]).size).toBe(0)
  })
})
