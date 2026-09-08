// Turning archived rows into a conversation.
//
// The archive stores what happened, not what a chat window looks like. An edit
// is its own row, so is a deletion, so is every reaction — and a page of a
// conversation contains all of them mixed together in sequence order. This
// module is the projection from one to the other.
//
// It is deliberately the *inline* projection: enough to draw the timeline
// without a round trip per message. The authoritative version, the one that
// also says which reader had which revision on screen, comes from the server's
// message.history and is what the detail panel shows. Two projections rather
// than one because they answer different questions, and the expensive one
// should not run while scrolling.

import type { SealedMessage } from '../api/protocol'

/** Reaction is one reaction row and what later became of it. */
export interface Reaction {
  row: SealedMessage
  /** The same party reacted again later. WhatsApp allows one per party. */
  superseded: boolean
  /** A revoke row removed it. */
  revoked: boolean
}

/** Entry is one line in the conversation, with everything that acted on it. */
export interface Entry {
  /** The original row. Its uid is the identity used everywhere else. */
  row: SealedMessage
  /**
   * Every version in order, the original first. Each carries its own sealed
   * body, so opening `current` is what the timeline renders and the rest is
   * what the history panel reveals.
   */
  versions: SealedMessage[]
  current: SealedMessage
  /** Set when a revoke row targeted this message. The content is still here. */
  deleted?: { row: SealedMessage; at?: string }
  reactions: Reaction[]
  /**
   * Answers to this poll, when it is one.
   *
   * A vote is stored as a message rather than a control row — it has a kind of
   * "message" in the database, because the four kinds are a CHECK constraint
   * from the first migration and a vote is not an edit, a deletion or a
   * reaction. But it is not a line in a conversation either: nobody wants a
   * chat window with eleven "voted" bubbles between the poll and the next
   * sentence. So it is folded here, where the poll can count it.
   */
  votes: SealedMessage[]
}

export interface Conversation {
  entries: Entry[]
  /**
   * Control rows whose target is not in the loaded window.
   *
   * Not an error and not dropped: the target is on an older page, and paging
   * further back resolves them. Dropping them would silently lose an edit
   * whenever it straddled a page boundary.
   */
  orphans: SealedMessage[]
}

/** whoSent identifies a party. Our own rows carry no sender key. */
export function whoSent(row: SealedMessage): string {
  if (row.is_from_me) return '@me'
  return row.sender_key || row.chat_key
}

/**
 * project builds the conversation from rows in sequence order.
 *
 * Rows may arrive in any order and may repeat — a live message can also appear
 * in a replayed page — so the identity is the message id, and a repeat replaces
 * rather than duplicates.
 */
export function project(rows: Iterable<SealedMessage>): Conversation {
  const entries = new Map<string, Entry>()
  const controls: SealedMessage[] = []
  const seen = new Set<string>()

  const ordered = [...rows].filter((row) => {
    const id = `${row.uid || row.wa_id}`
    if (seen.has(id)) return false
    seen.add(id)
    return true
  })
  ordered.sort(bySequence)

  for (const row of ordered) {
    if (row.kind === 'message' && row.type !== 'poll_vote') {
      entries.set(row.wa_id, { row, versions: [row], current: row, reactions: [], votes: [] })
    } else {
      controls.push(row)
    }
  }

  const orphans: SealedMessage[] = []
  const reactionRows: SealedMessage[] = []

  // Edits and deletions first, so a revoke of a reaction can be resolved
  // against reactions that are already placed.
  for (const row of controls) {
    switch (row.kind) {
      case 'edit': {
        const entry = entries.get(row.target_wa_id ?? '')
        if (!entry) {
          orphans.push(row)
          break
        }
        entry.versions.push(row)
        break
      }
      case 'delete': {
        if (row.target_rel === 'reaction') {
          // Handled below, once the reactions exist.
          reactionRows.push(row)
          break
        }
        const entry = entries.get(row.target_wa_id ?? '')
        if (!entry) {
          orphans.push(row)
          break
        }
        entry.deleted = { row, at: row.ts }
        break
      }
      case 'reaction': {
        const entry = entries.get(row.target_wa_id ?? '')
        if (!entry) {
          orphans.push(row)
          break
        }
        entry.reactions.push({ row, superseded: false, revoked: false })
        break
      }
      case 'message': {
        // A poll vote; nothing else of kind "message" reaches here. Orphaned
        // when the poll is on an older page, like any other control row, so
        // that paging back resolves it instead of losing an answer.
        const entry = entries.get(row.target_wa_id ?? '')
        if (!entry) {
          orphans.push(row)
          break
        }
        entry.votes.push(row)
        break
      }
      default:
        orphans.push(row)
    }
  }

  // A revoke against a reaction. Its target is the reaction's own message id.
  const revoked = new Set<string>()
  for (const row of reactionRows) {
    if (row.target_wa_id) revoked.add(row.target_wa_id)
    else orphans.push(row)
  }

  for (const entry of entries.values()) {
    entry.votes.sort(bySequence)
    entry.versions.sort(bySequence)
    entry.current = entry.versions[entry.versions.length - 1]

    entry.reactions.sort(bySequence2)
    const newestPerParty = new Map<string, SealedMessage>()
    for (const reaction of entry.reactions) {
      reaction.revoked = revoked.has(reaction.row.wa_id)
      if (reaction.revoked) continue
      newestPerParty.set(whoSent(reaction.row), reaction.row)
    }
    for (const reaction of entry.reactions) {
      if (reaction.revoked) continue
      reaction.superseded = newestPerParty.get(whoSent(reaction.row)) !== reaction.row
    }
  }

  // Reactions that survived are the ones a UI draws. Everything else stays on
  // the entry so the history panel can show what was withdrawn.
  //
  // Ordered by when each message was SENT, and by the original rather than the
  // current version — editing a message three days later must not move it to
  // the bottom of the conversation.
  //
  // Everything above this line is still ordered by seq, and deliberately: seq
  // is arrival order, which is what decides who superseded whom. An edit
  // carries a timestamp the sender controls, so applying revisions in time
  // order would let a clock decide which version wins.
  const list = [...entries.values()].sort((a, b) => byTime(a.row, b.row))

  // An orphan whose target arrived in the same batch after it was checked
  // cannot happen — the entries are all placed first — so anything left here is
  // genuinely on an older page.
  return { entries: list, orphans }
}

/** standing returns the reactions a chat window should draw. */
export function standing(entry: Entry): Reaction[] {
  return entry.reactions.filter((r) => !r.revoked && !r.superseded)
}

/** wasEdited reports whether the text on screen is not the text first sent. */
export function wasEdited(entry: Entry): boolean {
  return entry.versions.length > 1
}

/**
 * byTime orders the conversation the way a person reads it.
 *
 * seq is the tenant's insertion counter: a backfilled message from last year
 * gets today's number, and WhatsApp delivers history newest-first. Sorting the
 * timeline by seq therefore shows the history upside down and drops it wherever
 * the sync happened to run.
 *
 * Parsed rather than compared as text: the server sends RFC 3339 with an
 * offset, and two offsets make string order the wrong order.
 */
function byTime(a: SealedMessage, b: SealedMessage): number {
  const at = a.ts ? Date.parse(a.ts) : 0
  const bt = b.ts ? Date.parse(b.ts) : 0
  if (at !== bt) return at - bt
  // Whole-second timestamps make ties ordinary, and seq settles them.
  return bySequence(a, b)
}

function bySequence(a: SealedMessage, b: SealedMessage): number {
  if (a.seq !== b.seq) return a.seq - b.seq
  return a.uid < b.uid ? -1 : a.uid > b.uid ? 1 : 0
}

function bySequence2(a: Reaction, b: Reaction): number {
  return bySequence(a.row, b.row)
}
