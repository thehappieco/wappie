// The opener: sealed bytes in, readable content out.
//
// This is the only place in the client that holds the archive key, and the only
// place that knows which row a sealed value is bound to. Everything above it
// works with plain strings and objects.
//
// One asymmetric unwrap per content key rather than per message. That batching
// is the difference between a conversation opening instantly and a device
// stalling for half a minute on a large history, and it is why keys are
// prefetched for a whole page before any message is opened.

import type { Bytes } from '../crypto/bytes'
import { fromBase64, parseUUID } from '../crypto/bytes'
import type { PrivateKey } from '../crypto/hpke'
import { ContentKey, Kind, SealError } from '../crypto/seal'
import * as P from './protocol'

/**
 * KeySource is the part of the connection this needs: somewhere to ask for
 * sealed content keys.
 *
 * Narrower than Connection on purpose, so the bindings below can be exercised
 * against frames the server actually produced without standing up a socket.
 */
export interface KeySource {
  request<T>(type: string, payload: unknown, wantType: string): Promise<T>
}

/**
 * Opened is the outcome of unsealing one value.
 *
 * 'tampered' is deliberately its own state and not an error string. It means
 * the AAD binding refused: the blob beside that row is not the blob that was
 * sealed for it. A UI that rendered that as "could not load" would hide the one
 * event the binding exists to detect.
 */
export type Opened<T> =
  | { state: 'absent' }
  | { state: 'ok'; value: T }
  | { state: 'locked'; reason: string }
  | { state: 'tampered' }

export const absent = { state: 'absent' } as const

export class Opener {
  private readonly cache = new Map<number, ContentKey>()
  private readonly inFlight = new Map<number, Promise<void>>()
  private readonly missing = new Set<number>()

  constructor(
    private conn: KeySource,
    private readonly tenant: Bytes,
    /**
     * The device whose archive key this opener holds.
     *
     * One at a time: content keys are per device, so an opener serves the
     * account currently selected. Switching accounts builds a new one, which
     * also drops a key cache that would no longer open anything.
     */
    private readonly device: Bytes,
    private readonly deviceID: string,
    private readonly archive: PrivateKey,
  ) {}

  /**
   * rebind points the opener at a new connection, keeping what it has unwrapped.
   *
   * A reconnect does not invalidate a content key: it is the same tenant and
   * the same archive key. Rebuilding the opener would throw the cache away and
   * make every reconnect pay for the asymmetric unwraps again.
   */
  rebind(conn: KeySource): void {
    this.conn = conn
  }

  /**
   * prefetch fetches every key a batch of rows needs, in one round trip.
   *
   * Without it, opening a fifty-message page issues fifty sequential requests
   * for what is usually one or two keys.
   */
  async prefetch(ids: Iterable<number | undefined>): Promise<void> {
    const wanted = new Set<number>()
    for (const id of ids) {
      if (id && !this.cache.has(id) && !this.missing.has(id)) wanted.add(id)
    }
    if (wanted.size === 0) return
    await this.fetchKeys([...wanted])
  }

  private async fetchKeys(ids: number[]): Promise<void> {
    // Requests already in flight are joined rather than duplicated: a live
    // message and the page it lands on routinely want the same key.
    const pending = ids.filter((id) => this.inFlight.has(id)).map((id) => this.inFlight.get(id)!)
    const fresh = ids.filter((id) => !this.inFlight.has(id))

    // Large chat lists can span more than the protocol's 500 keys per frame.
    // Keep the same shared in-flight/cache handling for every bounded batch.
    for (let offset = 0; offset < fresh.length; offset += 500) {
      const batch = fresh.slice(offset, offset + 500)
      const work = this.load(batch)
      for (const id of batch) this.inFlight.set(id, work)
      pending.push(work)
    }
    await Promise.all(pending)
  }

  private async load(ids: number[]): Promise<void> {
    try {
      const reply = await this.conn.request<P.Keys>(
        P.TypeKeysGet,
        { device_id: this.deviceID, ids } satisfies P.KeysRequest,
        P.TypeKeys,
      )
      const returned = new Set<number>()
      for (const k of reply.keys ?? []) {
        returned.add(k.id)
        try {
          this.cache.set(
            k.id,
            await ContentKey.unwrap(this.archive, this.tenant, this.device, k.id, fromBase64(k.sealed)),
          )
        } catch {
          // The key is there and will not open: a different archive key, or a
          // blob that was altered. Remembering it as missing stops every
          // message under it from asking again.
          this.missing.add(k.id)
        }
      }
      for (const id of ids) if (!returned.has(id)) this.missing.add(id)
    } finally {
      for (const id of ids) this.inFlight.delete(id)
    }
  }

  async key(id: number): Promise<ContentKey | null> {
    const cached = this.cache.get(id)
    if (cached) return cached
    if (this.missing.has(id)) return null
    await this.fetchKeys([id])
    return this.cache.get(id) ?? null
  }

  /** raw opens a sealed value into bytes. */
  async raw(
    keyID: number | undefined,
    rowUID: string,
    kind: Kind,
    sealed: string | undefined,
  ): Promise<Opened<Bytes>> {
    if (!sealed) return absent
    if (!keyID) return { state: 'locked', reason: 'a linha não diz qual chave abre isto' }

    let row: Bytes
    try {
      row = parseUUID(rowUID)
    } catch {
      return { state: 'locked', reason: 'identificador de linha inválido' }
    }

    const key = await this.key(keyID)
    if (!key) return { state: 'locked', reason: `chave de conteúdo ${keyID} indisponível` }

    try {
      return { state: 'ok', value: await key.open(kind, this.tenant, row, fromBase64(sealed)) }
    } catch (err) {
      if (err instanceof SealError && err.code === 'authentication') return { state: 'tampered' }
      return { state: 'locked', reason: err instanceof Error ? err.message : String(err) }
    }
  }

  /** text opens a sealed value that is UTF-8. */
  async text(
    keyID: number | undefined,
    rowUID: string,
    kind: Kind,
    sealed: string | undefined,
  ): Promise<Opened<string>> {
    const opened = await this.raw(keyID, rowUID, kind, sealed)
    if (opened.state !== 'ok') return opened
    return { state: 'ok', value: new TextDecoder().decode(opened.value) }
  }

  /** payload opens the structured content: a location, a poll, an event, mentions. */
  async payload(message: P.SealedMessage): Promise<Opened<P.Payload>> {
    const opened = await this.raw(
      message.content_key_id,
      message.uid,
      Kind.Payload,
      message.payload_sealed,
    )
    if (opened.state !== 'ok') return opened
    try {
      return { state: 'ok', value: JSON.parse(new TextDecoder().decode(opened.value)) as P.Payload }
    } catch {
      return { state: 'locked', reason: 'o conteúdo estruturado não é JSON válido' }
    }
  }

  /** body opens a message body, or the emoji of a reaction — the same field. */
  body(message: P.SealedMessage): Promise<Opened<string>> {
    return this.text(message.content_key_id, message.uid, Kind.Body, message.body_sealed)
  }

  /** mediaKey opens the 32 bytes that decrypt an attachment. */
  mediaKey(message: P.SealedMessage): Promise<Opened<Bytes>> {
    return this.raw(
      message.content_key_id,
      message.uid,
      Kind.MediaKey,
      message.media?.media_key_sealed,
    )
  }

  /** thumbnail opens the inline preview a media message carries. */
  thumbnail(message: P.SealedMessage): Promise<Opened<Bytes>> {
    return this.raw(message.content_key_id, message.uid, Kind.Thumbnail, message.media?.thumb_sealed)
  }

  /**
   * fileName opens a document's name.
   *
   * Sealed under Kind.ContactName, which reads oddly but is the format: the
   * server reuses that kind for it. The row binding is the message either way,
   * so a contact name still cannot be presented as a file name.
   */
  fileName(message: P.SealedMessage): Promise<Opened<string>> {
    return this.text(
      message.content_key_id,
      message.uid,
      Kind.ContactName,
      message.media?.filename_sealed,
    )
  }

  /**
   * chatPreview opens the newest message of a conversation for the list.
   *
   * Bound to the message, not to the chat — the two uids sit side by side in
   * the same frame and using the wrong one fails authentication.
   */
  chatPreview(chat: P.ChatSummary): Promise<Opened<string>> {
    if (!chat.last_uid) return Promise.resolve(absent)
    return this.text(chat.last_body_key_id, chat.last_uid, Kind.Body, chat.last_body_sealed)
  }

  /** chatName opens the name of a conversation, bound to the chat's own uid. */
  chatName(chat: P.ChatSummary): Promise<Opened<string>> {
    return this.text(chat.name_key_id, chat.uid, Kind.ContactName, chat.name_sealed)
  }

  /**
   * contactNames opens all three names a contact can have.
   *
   * Three rather than one because they are three different claims — what
   * someone calls themselves, what this account saved them as, and what
   * WhatsApp verified about a business — and which to show is the client's
   * decision, not the server's.
   */
  async contactNames(contact: P.ContactSummary): Promise<{
    full: Opened<string>
    business: Opened<string>
    push: Opened<string>
  }> {
    const [full, business, push] = await Promise.all([
      this.text(contact.content_key_id, contact.uid, Kind.FullName, contact.full_name_sealed),
      this.text(
        contact.content_key_id,
        contact.uid,
        Kind.BusinessName,
        contact.business_name_sealed,
      ),
      this.text(contact.content_key_id, contact.uid, Kind.PushName, contact.push_name_sealed),
    ])
    return { full, business, push }
  }

  /** avatar opens a profile picture. */
  avatar(frame: P.Avatar): Promise<Opened<Bytes>> {
    return this.raw(frame.key_id, frame.uid, Kind.Avatar, frame.sealed)
  }
}
