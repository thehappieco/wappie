import { t } from '../ui/i18n'
// What a person can do to a message that is already sent.
//
// All four verbs exist on the server and are archived through the same pipeline
// as anything arriving from WhatsApp — an edit becomes a new version of the
// original, a deletion marks it without removing it, a reaction attaches and
// supersedes the last one from the same party. So none of this needs rendering
// code: project() in conversation.ts already folds every one of them onto the
// message they refer to, and the live subscription re-projects on arrival.
//
// Which means the work here is only the outbound half, and the interesting part
// of it is what to refuse locally. A round trip that ends in "WhatsApp said no"
// is a worse answer than one the client never sent.

import { ref } from 'vue'

import * as P from '../api/protocol'
import {
  connection,
  openChat,
  redrawTimeline,
  refreshChats,
  state,
  type MessageView,
} from './archive'

/** How long WhatsApp allows an edit. Refused past it, by them and by us. */
export const EDIT_WINDOW_MS = 20 * 60 * 1000

/**
 * now, ticking.
 *
 * The edit window closes while somebody is looking at it, so the countdown has
 * to move on its own. Once every ten seconds is enough for a twenty-minute
 * budget and cheap enough to leave running.
 *
 * A ref, and it has to be one. This was a plain object literal, which Vue's
 * reactivity does not track at all — so every computed reading it evaluated
 * once and never again, and nothing that depended on the clock actually moved
 * on screen. The interval ran the whole time, writing to a value nobody was
 * watching, which is why it looked right in the source and did nothing in the
 * product. Both the edit countdown and the "temporária → expirada" chip depend
 * on this.
 */
export const nowTick = ref(Date.now())
setInterval(() => {
  nowTick.value = Date.now()
}, 10_000)

/**
 * editableFor reports how long is left to edit a message, in milliseconds.
 *
 * Zero or less means the window has closed. Negative is not clamped on purpose:
 * a caller that wants to say "expired two minutes ago" can.
 */
export function editableFor(m: MessageView): number {
  if (!m.fromMe || !m.ts || m.deleted) return 0
  return m.ts.getTime() + EDIT_WINDOW_MS - nowTick.value
}

/** canEdit is the whole rule: mine, still inside the window, not deleted. */
export function canEdit(m: MessageView): boolean {
  // Not on an attachment. The edit is built as a text message replacing the
  // original, with no media fields in it at all — so what the recipient's
  // WhatsApp does when an ExtendedTextMessage arrives to replace a photograph
  // is not something this system decides or can promise. Our own archive would
  // look right either way, showing the picture with the new caption and an
  // "editada" tag, which is exactly what makes it worth refusing here: the
  // archive would not be evidence that anything reached the other side.
  if (m.media) return false
  return m.fromMe && !m.deleted && !m.pending && editableFor(m) > 0
}

/**
 * canDelete reports whether this client should offer to delete for everyone.
 *
 * Own messages only. WhatsApp also lets a group admin delete somebody else's,
 * and the protocol carries the field for it — but nothing in this system knows
 * who is an admin of which group, so offering it would mean sending a request
 * that WhatsApp refuses and reporting a failure the person could not have
 * predicted. Better not to offer what cannot be promised.
 */
export function canDelete(m: MessageView): boolean {
  return m.fromMe && !m.deleted && !m.pending
}

/** myReaction is the emoji this account currently has on a message, if any. */
export function myReaction(m: MessageView): string {
  return m.reactions.find((r) => r.fromMe)?.emoji ?? ''
}

function socket() {
  const conn = connection()
  if (!conn) throw new Error(t('sem conexão com o servidor'))
  return conn
}

function say(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/**
 * react adds, changes or withdraws this account's reaction.
 *
 * Tapping the emoji already on the message removes it: WhatsApp has no separate
 * "unreact", it is a reaction whose emoji is the empty string, and the archive
 * records that as a withdrawal rather than as an empty reaction.
 */
export async function react(m: MessageView, emoji: string): Promise<void> {
  state.actionError = ''
  const wanted = myReaction(m) === emoji ? '' : emoji
  try {
    await socket().request(
      P.TypeReact,
      {
        device_id: state.deviceID,
        chat: state.openChatKey,
        target_id: m.waID,
        sender: m.fromMe ? '' : m.senderKey,
        emoji: wanted,
      } satisfies P.ReactRequest,
      P.TypeSendResult,
    )
  } catch (err) {
    state.actionError = say(err)
  }
}

/**
 * openConversation opens the chat with somebody named on a contact card.
 *
 * The card gives a phone number and this archive is keyed by LID first, so the
 * number may not be the key the conversation is stored under — a chat carries
 * every key it has been seen as, and a match against any of them is a match.
 *
 * A number nobody here has ever spoken to has no conversation to open, and that
 * is said rather than papered over: creating an empty chat row for it would
 * invent a conversation that does not exist.
 */
export async function openConversation(jid: string): Promise<boolean> {
  state.actionError = ''
  const user = jid.split('@')[0]
  const chat = state.chats.find((c) =>
    [c.key, ...c.keys].some((k) => !c.isGroup && k.split('@')[0] === user),
  )
  if (!chat) {
    state.actionError = t('não há conversa com esse número neste histórico')
    return false
  }
  await openChat(chat.key)
  return true
}

/** ownKey is this device's own identifier, LID first, as everywhere else. */
function ownKey(): string {
  const device = state.devices.find((d) => d.id === state.deviceID)
  return device?.lid || device?.pn || ''
}

/**
 * vote answers a poll.
 *
 * The option text is sent, not an index, because the server hashes it: a vote
 * on the wire is SHA-256 of the option string and nothing else. The exact
 * strings this client rendered are what go out — anything else hashes to
 * something no client can match to an option, and the vote would be counted by
 * nobody, including us.
 *
 * A replacement, not an addition. WhatsApp treats a vote as superseding the
 * voter's previous one, so passing an empty list is how somebody withdraws.
 */
export async function vote(m: MessageView, options: string[]): Promise<boolean> {
  state.actionError = ''
  if (!m.payload?.poll) return false
  if (m.fromMe && !ownKey()) {
    state.actionError = t('este dispositivo ainda não sabe a própria identidade')
    return false
  }
  try {
    await socket().request(
      P.TypePollVote,
      {
        device_id: state.deviceID,
        chat: state.openChatKey,
        poll_id: m.waID,
        // The poll's author. Our own polls carry no sender key, so the device's
        // own identity stands in — the key derivation needs a JID either way.
        poll_sender: m.fromMe ? ownKey() : m.senderKey,
        poll_from_me: m.fromMe,
        options,
      } satisfies P.PollVoteRequest,
      P.TypeSendResult,
    )
    return true
  } catch (err) {
    state.actionError = say(err)
    return false
  }
}

/**
 * edit replaces the text of a message already sent.
 *
 * The send time travels with it so the server can refuse a stale edit before
 * spending a round trip on a stanza WhatsApp would reject. Checked here too,
 * because the window can close while the box is open.
 */
export async function edit(m: MessageView, body: string): Promise<void> {
  state.actionError = ''
  const text = body.trim()
  if (!text) return
  if (!canEdit(m)) {
    state.actionError = t('a janela de vinte minutos para editar já passou')
    return
  }
  try {
    await socket().request(
      P.TypeEdit,
      {
        device_id: state.deviceID,
        chat: state.openChatKey,
        target_id: m.waID,
        body: text,
        sent_at: m.ts?.toISOString(),
      } satisfies P.EditRequest,
      P.TypeSendResult,
    )
  } catch (err) {
    state.actionError = say(err)
  }
}

/**
 * revoke deletes a message for everyone.
 *
 * For everyone else. The archive keeps it, deliberately: a deletion is recorded
 * as a deletion, with what was there before still readable to whoever holds the
 * key. That is the difference between an archive and a client, and it is the
 * reason this project exists.
 */
export async function revoke(m: MessageView): Promise<void> {
  state.actionError = ''
  try {
    await socket().request(
      P.TypeRevoke,
      {
        device_id: state.deviceID,
        chat: state.openChatKey,
        target_id: m.waID,
        sender: m.fromMe ? '' : m.senderKey,
      } satisfies P.RevokeRequest,
      P.TypeSendResult,
    )
    await redrawTimeline()
  } catch (err) {
    state.actionError = say(err)
  }
}

/**
 * joinGroup accepts an invitation that arrived as a message.
 *
 * The code travels from here rather than being looked up on the server, and
 * that is the design rather than a limitation. An invite code is a capability —
 * whoever holds it walks into the group — so it is sealed with the rest of the
 * message and the server cannot read what it stored. This tab can, because it
 * holds the archive key.
 *
 * Deliberately not retried and not optimistic. Joining is outward facing and
 * there is no undo on this side: the account becomes a member and everyone
 * already in the group sees it. A silent retry on a timeout could join twice
 * over, and an optimistic line would claim membership this tab cannot confirm.
 */
export async function joinGroup(m: MessageView): Promise<boolean> {
  const invite = m.payload?.group_invite
  const conn = connection()
  if (!conn || !invite?.code || !invite.group_jid) return false

  // The inviter is whoever sent the message. WhatsApp validates the code
  // against the pair, so a missing sender is a refusal rather than a guess.
  const inviter = m.senderKey
  if (!inviter) {
    state.actionError = t('não dá para saber quem enviou o convite')
    return false
  }
  if (invite.expiration && invite.expiration * 1000 <= Date.now()) {
    state.actionError = t('esse convite expirou; peça outro')
    return false
  }

  try {
    await conn.request<P.GroupJoined>(
      P.TypeGroupJoin,
      {
        device_id: state.deviceID,
        group_jid: invite.group_jid,
        inviter,
        code: invite.code,
        expiration: invite.expiration,
      } satisfies P.GroupJoinRequest,
      P.TypeGroupJoined,
    )
    // The group now exists and nothing has been said in it, so no message will
    // arrive to put it in the sidebar. The server writes the conversation when
    // WhatsApp reports the join; this is what makes it visible without a
    // reload.
    await refreshChats()
    return true
  } catch (err) {
    state.actionError = err instanceof Error ? err.message : String(err)
    return false
  }
}
