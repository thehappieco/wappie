/**
 * Who is in a group, and what has happened to it.
 *
 * The history starts when this archive does. WhatsApp delivers a group's
 * current composition and its live changes, never its past — so "who removed
 * Fulano" is answerable from the moment we began listening and not before. The
 * panel says so, because an empty history is not a peaceful one and a reader
 * cannot tell the two apart by looking.
 */

import { reactive } from 'vue'

import * as P from '../api/protocol'
import { applyChatUpdate, connection, state } from './archive'

export const groups = reactive(new Map<string, P.Group>())

/** loading is which chat is being fetched, so a panel can say so. */
export const loadingGroup = reactive({ key: '' })

/**
 * loadGroup fetches a group, refreshing the composition from WhatsApp.
 *
 * Refreshed on open rather than trusted from the archive: a membership list a
 * week old, presented without saying so, is a worse answer than a round trip.
 * The reply reports which of the two it managed, and the panel repeats it.
 */
export async function loadGroup(chatKey: string, refresh = true): Promise<void> {
  const conn = connection()
  if (!conn || !chatKey) return
  const deviceID = state.deviceID
  const tenantID = state.tenantID
  const stillCurrent = () => connection() === conn && state.deviceID === deviceID && state.tenantID === tenantID
  loadingGroup.key = chatKey
  try {
    const g = await conn.request<P.Group>(
      P.TypeGroupGet,
      { device_id: deviceID, chat: chatKey, refresh } satisfies P.GroupRequest,
      P.TypeGroupFrame,
    )
    if (stillCurrent()) groups.set(chatKey, g)
  } catch (err) {
    if (stillCurrent()) state.actionError = err instanceof Error ? err.message : String(err)
  } finally {
    if (stillCurrent() && loadingGroup.key === chatKey) loadingGroup.key = ''
  }
}

export function forgetGroups(): void {
  groups.clear()
}

/**
 * setChatTimer turns disappearing messages on or off for a conversation.
 *
 * A chat setting rather than a message option, because that is all WhatsApp
 * has: there is no way to make one message vanish and leave the next alone.
 * Every message sent into the conversation afterwards carries the timer, and
 * the change is announced to everyone in it by WhatsApp itself — it is not a
 * quiet setting.
 */
export async function setChatTimer(chatKey: string, seconds: number): Promise<boolean> {
  const conn = connection()
  if (!conn || !chatKey) return false
  try {
    const set = await conn.request<P.ChatTimerResult>(
      P.TypeChatTimer,
      { device_id: state.deviceID, chat: chatKey, seconds } satisfies P.ChatTimerRequest,
      P.TypeChatTimerSet,
    )
    // Applied from the reply, which is the server saying what WhatsApp
    // accepted. Nothing is drawn before that: the select used to be left to a
    // re-listing, so it repainted the old value the instant Vue re-rendered
    // and only corrected itself if the round trip happened to win the race.
    applyChatUpdate({
      device_id: state.deviceID,
      chat_key: chatKey,
      ephemeral: set.seconds ?? seconds,
    })
    return true
  } catch (err) {
    state.actionError = err instanceof Error ? err.message : String(err)
    return false
  }
}
