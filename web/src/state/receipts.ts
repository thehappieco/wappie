/**
 * What each message collected, kept where the timeline cannot lose it.
 *
 * state.timeline is reassigned WHOLESALE on every live frame — an arriving row
 * can be an edit, a deletion or a reaction against a line already on screen, so
 * the conversation is reprojected rather than patched. Anything hung on a
 * MessageView therefore lives until the next frame and no longer, which is why
 * ticks used to reflect only what had crossed this particular connection: open a
 * conversation cold and everything showed one grey tick, including messages read
 * months ago.
 *
 * Counts are of PEOPLE. One reader with a phone and a laptop is one person who
 * received it, and a tick that waits for everyone must not be waiting on a
 * device count nobody can name.
 */

import { shallowReactive } from 'vue'

import * as P from '../api/protocol'
import { noAcks, type Acks } from './ticks'

/**
 * Two sources for one fact, and they are kept apart on purpose.
 *
 * A page carries counts — folded server-side, where the whole set of
 * acknowledgements is in hand. Live frames carry one reader at a time, so this
 * tab folds those itself into sets.
 *
 * The displayed count is the larger of the two, which under-counts when a live
 * reader is somebody the page had not counted yet. That direction is chosen:
 * under-counting delays a tick, over-counting claims a message was read by
 * people who have not read it. The next page load settles it either way.
 */
interface Entry {
  base: Acks
  delivered: Set<string>
  read: Set<string>
  played: Set<string>
}

const entries = shallowReactive(new Map<string, Entry>())

function entryFor(waID: string): Entry {
  let e = entries.get(waID)
  if (!e) {
    e = { base: noAcks(), delivered: new Set(), read: new Set(), played: new Set() }
    entries.set(waID, e)
  }
  return e
}

/** acksFor is what to draw for one message. */
export function acksFor(waID: string): Acks {
  const e = entries.get(waID)
  if (!e) return noAcks()
  return {
    delivered: Math.max(e.base.delivered, e.delivered.size),
    read: Math.max(e.base.read, e.read.size),
    played: Math.max(e.base.played, e.played.size),
    deliveredAt: e.base.deliveredAt,
    readAt: e.base.readAt,
    playedAt: e.base.playedAt,
    readByUs: e.base.readByUs,
    retrying: e.base.retrying,
    failed: e.base.failed,
  }
}

/**
 * absorbReceipts takes the counts a page carried.
 *
 * Order-independent: a page that arrives after a live receipt must not undo it,
 * and a count never goes down. Receipts are facts that accumulate — nothing
 * un-receives a message — so the merge is a maximum and needs no generation
 * counter to be safe against either arriving first.
 */
export function absorbReceipts(rows: P.MessageAcks[] | undefined): void {
  for (const r of rows ?? []) {
    const e = entryFor(r.wa_id)
    const base = e.base
    e.base = {
      delivered: Math.max(base.delivered, r.delivered ?? 0),
      read: Math.max(base.read, r.read ?? 0),
      played: Math.max(base.played, r.played ?? 0),
      deliveredAt: earliest(base.deliveredAt, r.delivered_at),
      readAt: earliest(base.readAt, r.read_at),
      playedAt: earliest(base.playedAt, r.played_at),
      readByUs: base.readByUs || r.read_by_us,
      retrying: base.retrying || r.retrying,
      failed: base.failed || r.failed,
    }
    // Replaced rather than mutated: a shallowReactive Map does not notice a
    // change inside a value it already holds, and the ticks would not redraw.
    entries.set(r.wa_id, { ...e })
  }
}

/**
 * applyReceipt folds one live acknowledgement in.
 *
 * Only for messages this tab is holding. A receipt frame names a device, not a
 * conversation, so without that filter the map would grow for the whole account
 * for as long as the tab is open — and none of it would ever be drawn.
 */
export function applyReceipt(ev: P.ReceiptEvent, holding: (waID: string) => boolean): void {
  // Ours. Never counted: WhatsApp's "sender" receipt is our OWN device
  // confirming it received something we sent, and counting it puts two grey
  // ticks on every message in a direct conversation the instant our own handset
  // acknowledges — with the recipient's phone possibly switched off. It is the
  // bug this replaced.
  if (ev.is_from_me) {
    if (ev.kind !== 'read' && ev.kind !== 'played') return
    for (const waID of ev.wa_ids ?? []) {
      if (!holding(waID)) continue
      const e = entryFor(waID)
      entries.set(waID, { ...e, base: { ...e.base, readByUs: true } })
    }
    return
  }

  // The person, not the device.
  const person = ev.reader_person || ev.reader_key
  if (!person) return

  for (const waID of ev.wa_ids ?? []) {
    if (!holding(waID)) continue
    const e = entryFor(waID)
    const next: Entry = {
      base: e.base,
      delivered: new Set(e.delivered),
      read: new Set(e.read),
      played: new Set(e.played),
    }
    switch (ev.kind) {
      case 'delivered':
        next.delivered.add(person)
        break
      case 'read':
        next.read.add(person)
        break
      case 'played':
        next.played.add(person)
        break
      // retry and error are not acknowledgements. A message stuck in retry
      // looks delivered and is not, so they are carried only by the page,
      // where they land in fields no tick rule reads.
      default:
        return
    }
    entries.set(waID, next)
  }
}

/** forgetReceipts drops everything, when the conversation or device changes. */
export function forgetReceipts(): void {
  entries.clear()
}

function earliest(have: Date | undefined, incoming: string | undefined): Date | undefined {
  if (!incoming) return have
  const at = new Date(incoming)
  if (!have) return at
  return at < have ? at : have
}
