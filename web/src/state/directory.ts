// Who is who.
//
// A contact is reachable under two identifiers — a LID and a phone number — and
// which one a given row carries is not something a client gets to choose. A
// message may name the LID while the contact row was saved under the number, so
// both are indexed to the same person. Getting this wrong does not fail; it
// shows a phone number where a name should be, which is exactly the symptom
// that took a database query to explain the last time.

import { displayFallback, parseJID, SERVER_LID, SERVER_USER } from './jid'

export interface Person {
  /** The contact key as the server stores it. */
  key: string
  uid: string
  lid?: string
  pn?: string
  isGroup: boolean
  /** What this account saved them as. */
  full: string
  /** What WhatsApp verified about a business. */
  business: string
  /** What they call themselves. */
  push: string
  hasAvatar: boolean
  avatarKeyID?: number
  /** Set when a sealed name refused to open, which is not the same as absent. */
  tampered?: boolean
}

/**
 * bestName picks which of the three claims to show.
 *
 * Saved name first, because someone who bothered to save a contact meant that
 * name. Then the verified business name, which is a claim WhatsApp checked.
 * Then the push name, which is whatever the person typed about themselves and
 * anyone can set to anything.
 */
export function bestName(person: Person | undefined, fallbackJID: string): string {
  const name = person && (person.full || person.business || person.push)
  return name || displayFallback(fallbackJID)
}

export class Directory {
  private readonly byKey = new Map<string, Person>()
  private readonly byUser = new Map<string, Person>()

  add(person: Person): void {
    this.byKey.set(person.key, person)
    for (const alias of [person.key, person.lid, person.pn]) {
      if (!alias) continue
      this.byKey.set(alias, person)
      const { user } = parseJID(alias)
      if (user) this.byUser.set(user, person)
    }
  }

  get size(): number {
    return this.byKey.size
  }

  all(): Person[] {
    return [...new Set(this.byKey.values())]
  }

  /**
   * find resolves an identifier to a person.
   *
   * Falls back to matching the user part alone, which catches a row carrying a
   * device suffix and one where only the server differs.
   */
  find(jid: string | undefined): Person | undefined {
    if (!jid) return undefined
    const exact = this.byKey.get(jid)
    if (exact) return exact
    const { user, server } = parseJID(jid)
    if (!user) return undefined
    // Only for the two servers that name a person. A group id that happens to
    // share digits with a phone number must not resolve to that contact.
    if (server === SERVER_USER || server === SERVER_LID || server === '') {
      return this.byUser.get(user)
    }
    return undefined
  }

  /**
   * nameFor is what to RENDER for an identifier. It never comes back empty.
   *
   * That is the whole point of it — a row always has something to draw — and it
   * is a trap for any caller asking a different question. `nameFor(unknownLID)`
   * returns the string "LID 4263189", which is truthy, so
   * `const n = nameFor(a) || nameFor(b); if (n) return n` always returns on the
   * first identifier and never looks at the second. Callers deciding whether a
   * name is KNOWN want knownName below.
   */
  nameFor(jid: string | undefined): string {
    if (!jid) return ''
    return bestName(this.find(jid), jid)
  }

  /**
   * knownName is the name actually recorded for an identifier, or nothing.
   *
   * The counterpart to nameFor: no fallback, so an empty result means "nobody
   * here can name this", which is a question several callers need to ask and
   * none of them could ask through nameFor.
   */
  knownName(jid: string | undefined): string {
    if (!jid) return ''
    const person = this.find(jid)
    return (person && (person.full || person.business || person.push)) || ''
  }

  /** isKnown separates "no name yet" from "we have never seen this identifier". */
  isKnown(jid: string | undefined): boolean {
    return this.knownName(jid) !== ''
  }

  clear(): void {
    this.byKey.clear()
    this.byUser.clear()
  }
}
