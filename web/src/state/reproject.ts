/**
 * Looking again at messages the archive could not classify when they arrived.
 *
 * A row filed as "unsupported" is not lost — the protobuf that produced it was
 * sealed and kept, exactly so a later build can go back for it. What it is, is
 * frozen: classification happens once, on the way in, so a message that arrived
 * before its type was supported stays that way for good unless something
 * revisits it.
 *
 * The work is split for a reason that is the whole design, not a workaround.
 * The server cannot open its own archive; this tab can. The server holds the
 * classifier and the public key, and sealing needs only the public key. So the
 * browser opens each stored protobuf and hands it back, and the archive key
 * never leaves. A version of this that pasted the key into a terminal would put
 * the one secret the system is built around into a shell history, permanently.
 *
 * What does cross is the message in the clear, for every row still filed as
 * unsupported. That is the same exposure outbound text already carries. It
 * used to be bounded to a press of a button; it now happens on its own each
 * time the archive opens, because the button had turned into a chore that
 * never ended — an archive whose backlog was long done kept offering the same
 * hundred and thirty rows nothing could change. The trade is named here rather
 * than glossed: a few more sealed rows are opened locally and shown to a server
 * that already saw them arrive.
 */

import * as P from '../api/protocol'
import { toBase64 } from '../crypto/bytes'
import { archiveOpener, connection, refreshChats, state } from './archive'
import { Kind } from '../crypto/seal'

export interface ReprojectProgress {
  /** How many rows the server offered. */
  total: number
  /** How many this tab managed to open. */
  opened: number
  /** How many actually changed type. */
  changed: number
  /** Rows that stayed unsupported: the ordinary outcome. */
  stillUnknown: number
  /**
   * Rows that are not messages at all — key distribution and other protocol
   * traffic, which an older build stored and the current one skips on the way
   * in. Not a failure and not a type waiting to be implemented.
   */
  machinery: number
  /** Rows this tab could not open at all — wrong key, or tampered. */
  unreadable: number
  /** Rows the server declined to rewrite, with its reason. */
  skipped: string[]
  /** What the run produced, by new type. */
  byType: Record<string, number>
  done: boolean
  error?: string
}

function empty(): ReprojectProgress {
  return {
    total: 0, opened: 0, changed: 0, stillUnknown: 0, machinery: 0, unreadable: 0,
    skipped: [], byType: {}, done: false,
  }
}

/**
 * reproject walks every unsupported row and reports what happened.
 *
 * All of them, in pages, following a cursor — not one page per press. Most rows
 * stay unsupported, because they are types this build still does not
 * understand, so a page-at-a-time button hands back the same unconvertible
 * rows and never reaches what is behind them. Newest first, because a message
 * somebody noticed last night was otherwise at position 748 of 750.
 *
 * onProgress is called as it goes: opening a thousand sealed values is a
 * thousand HPKE operations, and a progress report that only appears at the end
 * is not a progress report.
 */
export async function reproject(
  onProgress?: (p: ReprojectProgress) => void,
  limit = 200,
): Promise<ReprojectProgress> {
  const p = empty()
  const conn = connection()
  const opener = archiveOpener()
  const deviceID = state.deviceID
  if (!conn || !opener) {
    p.error = 'o arquivo não está destravado'
    p.done = true
    return p
  }
  const current = () => connection() === conn && archiveOpener() === opener && state.deviceID === deviceID

  let before = 0
  // A bound rather than a while(true). A cursor that failed to advance would
  // otherwise spin against the server for the life of the tab, and the failure
  // would look like a page that had simply stopped responding.
  for (let page = 0; page < 200; page++) {
    if (!current()) break
    let rows: P.UnsupportedRow[]
    try {
      const reply = await conn.request<P.Unsupported>(
        P.TypeReprojectGet,
        { device_id: deviceID, limit, before_seq: before } satisfies P.ReprojectRequest,
        P.TypeUnsupportedRows,
      )
      rows = reply.rows ?? []
    } catch (err) {
      p.error = err instanceof Error ? err.message : String(err)
      break
    }
    if (!current()) break
    if (rows.length === 0) break

    // The cursor is the oldest row of this page. Advancing it is what stops
    // the unconvertible ones being fetched again on the next round.
    const oldest = rows.reduce((min, r) => (r.seq && r.seq < min ? r.seq : min), Number.MAX_SAFE_INTEGER)
    if (oldest === Number.MAX_SAFE_INTEGER || oldest === before) break
    before = oldest

    p.total += rows.length
    onProgress?.({ ...p })
    await walk(rows, conn, opener, deviceID, current, p, onProgress)
    if (rows.length < limit) break
  }

  p.done = true
  if (current()) onProgress?.({ ...p })
  return p
}

async function walk(
  rows: P.UnsupportedRow[],
  conn: NonNullable<ReturnType<typeof connection>>,
  opener: NonNullable<ReturnType<typeof archiveOpener>>,
  deviceID: string,
  current: () => boolean,
  p: ReprojectProgress,
  onProgress?: (p: ReprojectProgress) => void,
): Promise<void> {
  for (const row of rows) {
    if (!current()) return
    const opened = await opener.raw(row.content_key_id, row.uid, Kind.RawProto, row.raw_sealed)
    if (!current()) return
    if (opened.state !== 'ok') {
      // Not a failure of this feature. A row whose key this account was never
      // granted, or one that really was tampered with, both land here — and
      // both are worth counting rather than retrying.
      p.unreadable++
      onProgress?.({ ...p })
      continue
    }
    p.opened++

    try {
      const done = await conn.request<P.Reprojected>(
        P.TypeReprojectPut,
        {
          device_id: deviceID,
          uid: row.uid,
          raw: toBase64(opened.value),
        } satisfies P.ReprojectRequest,
        P.TypeReprojected,
      )
      if (!current()) return
      // Machinery is now retyped as protocol, so it is both: a row that
      // changed, and one that was never a message. Counted as both, because
      // the panel says two different things with the two numbers.
      if (done.machinery) p.machinery++
      if (done.changed) {
        p.changed++
        p.byType[done.type] = (p.byType[done.type] ?? 0) + 1
      } else if (done.machinery) {
        // Retyped and nothing else to say.
      } else if (done.note) {
        // Capped. A run now covers the whole archive, and a thousand identical
        // lines is not a report — it is the same sentence a thousand times.
        if (p.skipped.length < 20) p.skipped.push(`${row.wa_id}: ${done.note}`)
      } else {
        p.stillUnknown++
      }
    } catch (err) {
      p.skipped.push(`${row.wa_id}: ${err instanceof Error ? err.message : String(err)}`)
    }
    if (current()) onProgress?.({ ...p })
  }
}

/**
 * survey lists what is waiting, without changing anything.
 *
 * So the panel can say what is left after the automatic pass, by the field
 * each row carried. A count with no breakdown says nothing about what to
 * implement next; the field name is the whole clue.
 */
export async function survey(limit = 500): Promise<{ total: number; byField: Record<string, number>; error?: string }> {
  const out: { total: number; byField: Record<string, number>; error?: string } = {
    total: 0,
    byField: {},
  }
  const conn = connection()
  if (!conn || !state.deviceID) {
    out.error = 'nenhum aparelho selecionado'
    return out
  }
  try {
    const reply = await conn.request<P.Unsupported>(
      P.TypeReprojectGet,
      { device_id: state.deviceID, limit } satisfies P.ReprojectRequest,
      P.TypeUnsupportedRows,
    )
    for (const row of reply.rows ?? []) {
      out.total++
      const f = row.field || '(sem nome)'
      out.byField[f] = (out.byField[f] ?? 0) + 1
    }
  } catch (err) {
    out.error = err instanceof Error ? err.message : String(err)
  }
  return out
}

let activeSweep: { deviceID: string; opener: ReturnType<typeof archiveOpener>; conn: ReturnType<typeof connection> } | null = null
let inflight: Promise<void> | null = null

/**
 * sweepDone resolves once no automatic pass is running.
 *
 * For tests, which otherwise race the pass that start() kicks off: a test that
 * counts the frames its own reproject() sent would also count the sweep's.
 */
export function sweepDone(): Promise<void> {
  return inflight ?? Promise.resolve()
}

/**
 * sweepUnsupported is the automatic pass, run when the archive opens.
 *
 * Everything still filed as unsupported is opened here and shown to the
 * classifier; what it can now name is converted, and what it cannot is
 * counted into state.unsupported by the field it carried. The sidebar is
 * refreshed when anything changed, because it carries a projection of each
 * conversation's newest message and would otherwise go on saying "tipo não
 * suportado" about a photograph.
 *
 * One per current device context. A switch cancels the old pass at its next
 * asynchronous boundary and lets the newly selected device start immediately.
 */
export async function sweepUnsupported(): Promise<void> {
  const deviceID = state.deviceID
  const conn = connection()
  const opener = archiveOpener()
  if (!deviceID || !conn || !opener) return
  if (activeSweep?.deviceID === deviceID && activeSweep.conn === conn && activeSweep.opener === opener) return
  const sweep = { deviceID, conn, opener }
  activeSweep = sweep
  const current = () => activeSweep === sweep && connection() === conn && archiveOpener() === opener && state.deviceID === deviceID
  let finish!: () => void
  inflight = new Promise<void>((resolve) => (finish = resolve))
  state.unsupported = { ...state.unsupported, running: true, error: undefined }
  try {
    const run = await reproject()
    if (!current()) return
    if (run.changed) await refreshChats()
    if (!current()) return
    const left = await survey(1000)
    if (!current()) return
    state.unsupported = {
      total: left.total,
      byField: left.byField,
      running: false,
      sweptAt: new Date(),
      lastRun: run,
      error: left.error ?? run.error,
    }
  } catch (err) {
    if (!current()) return
    state.unsupported = {
      ...state.unsupported,
      running: false,
      error: err instanceof Error ? err.message : String(err),
    }
  } finally {
    if (activeSweep === sweep) {
      activeSweep = null
      inflight = null
    }
    finish()
  }
}
