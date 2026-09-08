/**
 * Reporting what has been read.
 *
 * Two different things used to be one thing here, and separating them is what
 * this module is now about. Telling the ARCHIVE what has been read is how a
 * badge clears; telling WHATSAPP is a signal that leaves this machine. They
 * were the same call behind the same switch, so a device in the default
 * discreet mode sent nothing, and therefore cleared nothing: opening a
 * conversation and reading every word in it left the badge exactly where it
 * was, forever.
 *
 * So the report always goes to our own server, and the server decides
 * separately whether a receipt reaches WhatsApp — ReceiptPolicy.MarkRead
 * refuses in passive mode, which is the gate that actually matters and the one
 * place it can be audited. Nothing new is disclosed by reporting here: the
 * archive already holds every message this is about.
 *
 * Three conditions, all necessary:
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
 * Whether a read reaches WhatsApp. Kept because the UI says so, and because a
 * reader deserves to be told what the switch does.
 *
 * It no longer gates the report to our own server. The server refuses to
 * forward in passive mode — that refusal is the gate — and gating here as well
 * meant the badge could never clear while discreet.
 */
let outbound = true

export function setReadReceipts(on: boolean): void {
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
  if (!waID || !focused) {
    // Losing focus discards the clock rather than pausing it: a message
    // glimpsed for a moment before the window went behind another was not read.
    seen.delete(waID)
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
}

async function flush(): Promise<void> {
  const ids = [...pending]
  pending.clear()
  const conn = connection()
  if (!conn || ids.length === 0 || !state.openChatKey) return

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
  if (!conn || !waID || !state.openChatKey) return
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
