/**
 * Reporting what has been read.
 *
 * Incognito viewing preserves unread messages in the archive as well as
 * withholding WhatsApp receipts. A MarkRead request changes the archive even
 * when the server suppresses the outgoing receipt, so the client must not send
 * that request while discreet. Read events from the phone still update the
 * archive normally; this gate only controls this client's own reports.
 *
 * In active mode, three further conditions are necessary:
 *
 *   - the message is on screen, not merely loaded. A conversation holds sixty
 *     messages and a reader sees five of them.
 *   - the tab has focus. A window behind another window is not being read, and
 *     an archive that reports otherwise is lying on the reader's behalf.
 *   - it is somebody else's message, not ours, and not already read.
 *
 * By POSITION once it fires, which is what WhatsApp does: acknowledging a
 * message clears everything under it. That is what makes the badge mean "how
 * much is left at the end of this conversation" rather than "how many
 * individual rows remain unticked".
 */

import * as P from '../api/protocol'
import { connection, state } from './archive'

/**
 * How long a message has to stay on screen before it counts as read.
 *
 * Scrolling past something is not reading it. Without this, dragging the
 * scrollbar through a conversation reports every message in it as read, which
 * is both untrue and irreversible — a read receipt cannot be taken back.
 */
const DWELL_MS = 600

/** How long to gather ids before sending. One frame per burst, not per message. */
const BATCH_MS = 400

const seen = new Map<string, number>()
const pending = new Set<string>()
let timer: ReturnType<typeof setTimeout> | undefined

/**
 * Whether this client may mark anything read. Unknown posture starts quiet.
 * The server independently controls whether receipts reach WhatsApp.
 */
let outbound = false

export function setReadReceipts(on: boolean): void {
  // Reading while discreet must not be reported later when active mode is
  // restored. Entering incognito also cancels a batch waiting to leave.
  if (on !== outbound || !on) forgetSeen()
  outbound = on
}

export function readReceiptsEnabled(): boolean {
  return outbound
}

/**
 * queued is what would be reported on the next flush.
 *
 * A seam for the tests, and it earns its place: the conditions in this file are
 * all refusals, and without a way to see what survived them the tests could
 * only re-read the switch they had just set — which is what they used to do.
 */
export function queued(): string[] {
  return [...pending]
}

/**
 * sawMessage records that a message is on screen right now.
 *
 * Called repeatedly while it stays there. The first sighting starts the clock;
 * the one that finds the clock has run sends it.
 */
export function sawMessage(waID: string, focused: boolean): void {
  if (!outbound || !waID || !focused) {
    // Losing focus discards the clock rather than pausing it: a message
    // glimpsed for a moment before the window went behind another was not read.
    seen.delete(waID)
    pending.delete(waID)
    return
  }
  const first = seen.get(waID)
  if (first === undefined) {
    seen.set(waID, Date.now())
    return
  }
  if (Date.now() - first < DWELL_MS) return
  pending.add(waID)
  if (timer) return
  timer = setTimeout(() => {
    timer = undefined
    void flush()
  }, BATCH_MS)
}

/** forgetSeen drops the dwell clocks, when the conversation changes. */
export function forgetSeen(): void {
  seen.clear()
  pending.clear()
  if (timer) clearTimeout(timer)
  timer = undefined
}

async function flush(): Promise<void> {
  const ids = [...pending]
  pending.clear()
  const conn = connection()
  if (!outbound || !conn || ids.length === 0 || !state.openChatKey) return

  try {
    await conn.request(
      P.TypeMarkRead,
      {
        device_id: state.deviceID,
        chat: state.openChatKey,
        ids,
      } satisfies P.MarkReadRequest,
      P.TypeSendResult,
    )
  } catch {
    // Deliberately not retried. A read receipt that failed to send is a signal
    // that did not leave, which is the safe direction — and retrying a batch
    // whose fate is unknown risks telling somebody twice.
  }
}

/**
 * playedMessage reports that a voice note finished, or a view-once was opened.
 *
 * Separate from reading because it is a separate signal on the sender's screen,
 * and because it fires on a deliberate act rather than on a message drifting
 * into view.
 */
export async function playedMessage(waID: string): Promise<void> {
  const conn = connection()
  if (!outbound || !conn || !waID || !state.openChatKey) return
  try {
    await conn.request(
      P.TypeMarkRead,
      {
        device_id: state.deviceID,
        chat: state.openChatKey,
        ids: [waID],
        played: true,
      } satisfies P.MarkReadRequest,
      P.TypeSendResult,
    )
  } catch {
    // As above.
  }
}
