/**
 * Who is typing, right now.
 *
 * Nothing here is stored anywhere, on either side. It is true for a few seconds
 * and then it is not, so an archive that kept it would be recording a fact that
 * had stopped being one before anybody could read the row.
 *
 * Which means it also expires here. WhatsApp does not promise a "paused" for
 * every "composing" — a phone that goes into a tunnel mid-sentence sends
 * nothing more — so a client that waited for one would show somebody typing
 * forever. The timeout is the whole reliability model.
 */

import { reactive } from 'vue'

import * as P from '../api/protocol'
import { connection, people, state } from './archive'
import { parseJID, SERVER_LID, SERVER_USER } from './jid'

/**
 * How long a typing notification is believed.
 *
 * WhatsApp's own clients re-send roughly every ten seconds while somebody keeps
 * typing, so this is a little longer than one interval: long enough not to
 * flicker between two of them, short enough that a dropped "paused" clears on
 * its own rather than leaving a lie on screen.
 */
const BELIEVE_MS = 12_000

export interface Typing {
  /** Who, for a group. Empty in a direct conversation, where it can only be them. */
  senderKey: string
  senderLID: string
  senderPN: string
  /** 'audio' while recording a voice note, empty while typing. */
  media: string
  at: number
}

/** Keyed on the chat, then on the person: a group can have several at once. */
export const typing = reactive(new Map<string, Map<string, Typing>>())

const availability = reactive(new Map<string, { online: boolean; at: number; lastSeen?: string }>())
const AVAILABILITY_MS = 90_000

function aliases(key: string): string[] {
  const jid = parseJID(key)
  const canonical = jid.server ? `${jid.user}@${jid.server}` : key
  const person = people().find(key)
  const known = [person?.key, person?.lid, person?.pn].filter((k): k is string => Boolean(k))
  // A phone number and LID can coincidentally have the same digits. Only
  // explicit aliases connect their live status; Directory's display fallback
  // alone is not enough evidence that they are the same contact.
  return known.includes(canonical) ? [key, canonical, ...known] : [key, canonical]
}

export function availabilityIn(chatKey: string, now = Date.now()): 'online' | 'offline' | 'unknown' {
  if (state.quiet || !state.connected) return 'unknown'
  const candidates = aliases(chatKey).map(key => availability.get(key)).filter(item => item !== undefined)
  const latest = candidates.sort((a, b) => b.at - a.at)[0]
  if (!latest || now - latest.at >= AVAILABILITY_MS) return 'unknown'
  return latest.online ? 'online' : 'offline'
}

/** Ask only about the visible direct conversation. Never change receipt mode. */
export async function watchPresence(chat: string): Promise<void> {
  const { server } = parseJID(chat)
  const conn = connection()
  if (!conn || !state.connected || state.quiet || ![SERVER_LID, SERVER_USER].includes(server)) return
  const device = state.deviceID
  try {
    const result = await conn.request<P.PresenceSubscription>(P.TypePresenceWatch,
      { device_id: device, chat }, P.TypePresenceWatch)
    if (device !== state.deviceID || connection() !== conn) return
    if (!result.subscribed) for (const alias of aliases(chat)) availability.delete(alias)
  } catch {
    if (device === state.deviceID && connection() === conn) {
      for (const alias of aliases(chat)) availability.delete(alias)
    }
  }
}

/** applyPresence folds one notification in, or takes it back. */
export function applyPresence(ev: P.PresenceEvent): void {
  if (ev.device_id !== state.deviceID) return
  const chat = ev.chat_key
  if (!chat) return

  if (ev.state === 'available' || ev.state === 'unavailable') {
    const status = { online: ev.state === 'available', at: Date.now(), lastSeen: ev.last_seen }
    for (const key of [chat, ev.sender_key, ev.sender_lid, ev.sender_pn]) {
      if (!key) continue
      for (const alias of aliases(key)) availability.set(alias, status)
    }
    return
  }
  if (ev.state !== 'composing' && ev.state !== 'paused') return

  const who = ev.sender_key || chat
  const inChat = typing.get(chat) ?? new Map<string, Typing>()

  if (ev.state === 'paused') {
    inChat.delete(who)
  } else {
    inChat.set(who, {
      senderKey: ev.sender_key ?? '',
      senderLID: ev.sender_lid ?? '',
      senderPN: ev.sender_pn ?? '',
      media: ev.media ?? '',
      at: Date.now(),
    })
  }

  if (inChat.size === 0) typing.delete(chat)
  else typing.set(chat, inChat)
}

/**
 * typingIn is who is typing in a conversation, with the stale entries dropped.
 *
 * Expiry happens on read rather than on a timer, so a conversation nobody is
 * looking at costs nothing — and the value is recomputed by the same reactivity
 * that redraws it, which a sweeping interval would fight with.
 */
export function typingIn(chatKey: string, now = Date.now()): Typing[] {
  const inChat = typing.get(chatKey)
  if (!inChat) return []
  const live: Typing[] = []
  for (const t of inChat.values()) {
    if (now - t.at < BELIEVE_MS) live.push(t)
  }
  return live
}

/** forgetPresence drops everything, when the device or session changes. */
export function forgetPresence(): void {
  typing.clear()
  availability.clear()
}

// ---------------------------------------------------------------------------
// Telling the other side
// ---------------------------------------------------------------------------

/**
 * Whether our own typing may leave. The incognito switch owns this, and the
 * server refuses independently — this is so the tab stops asking, not so it can
 * be trusted to.
 */
let enabled = true

export function setTypingNotifications(on: boolean): void {
  enabled = on
  if (!on) { stopTyping(); forgetPresence() }
}

let sending = ''
let repeat: ReturnType<typeof setInterval> | undefined

/**
 * startTyping says we are composing, and keeps saying it.
 *
 * Repeated because a notification expires on the other side too — WhatsApp's
 * own clients re-send while somebody keeps typing, and one notification at the
 * start of a long message would have the bubble disappear halfway through it.
 */
export function startTyping(media: '' | 'audio' = ''): void {
  if (!enabled || !state.openChatKey) return
  const want = state.openChatKey + '|' + media
  if (sending === want) return
  sending = want
  void send('composing', media)
  if (repeat) clearInterval(repeat)
  repeat = setInterval(() => void send('composing', media), 8_000)
}

/** stopTyping takes it back. Cheap to call twice. */
export function stopTyping(): void {
  if (repeat) clearInterval(repeat)
  repeat = undefined
  if (!sending) return
  const [chat] = sending.split('|')
  sending = ''
  if (enabled && chat) void send('paused', '', chat)
}

async function send(stateName: string, media: string, chat = state.openChatKey): Promise<void> {
  const conn = connection()
  if (!conn || !chat) return
  try {
    await conn.request(
      P.TypeChatTyping,
      {
        device_id: state.deviceID,
        chat,
        state: stateName,
        media: media || undefined,
      } satisfies P.ChatPresenceRequest,
      P.TypeSendResult,
    )
  } catch {
    // Not retried and not surfaced. A typing notification that did not arrive
    // is a bubble the other side did not see, which is the least consequential
    // failure in this client — and the next keystroke tries again anyway.
  }
}
