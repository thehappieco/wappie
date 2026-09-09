// The wire protocol, mirroring internal/wsapi/protocol.go.
//
// Sealed fields arrive as base64 strings, because that is what Go's encoding/json
// does with a []byte. They are decoded at the edge, in opener.ts, so nothing
// above this layer has to remember which strings are text and which are
// ciphertext.

export const VERSION = 1

/** Frame is the envelope for every message in both directions. */
export interface Frame {
  t: string
  r?: string
  p?: unknown
}

// Client to server.
export const TypeHello = 'hello'
export const TypeSubscribe = 'subscribe'
export const TypeDevicesList = 'devices.list'
export const TypeChatsList = 'chats.list'
export const TypeContacts = 'contacts.list'
export const TypeResolve = 'contacts.resolve'
export const TypeAvatar = 'contacts.avatar'
export const TypeChatPage = 'chat.page'
export const TypeHistory = 'message.history'
export const TypeMessageGet = 'message.get'
export const TypeKeysGet = 'keys.get'
export const TypeMediaExpired = 'media.expired'
export const TypeBackfill = 'history.backfill'
export const TypeUsersList = 'users.list'
export const TypeDevicesStats = 'devices.stats'
export const TypeDeviceInfo = 'device.info'
export const TypeDeviceDelete = 'device.delete'
export const TypeDeviceStop = 'device.stop'
export const TypeDeviceStart = 'device.start'
export const TypeDeviceRename = 'device.rename'
export const TypePair = 'pair'
export const TypePairCancel = 'pair.cancel'
export const TypeKeysList = 'apikeys.list'
export const TypeKeyCreate = 'apikeys.create'
export const TypeKeyRevoke = 'apikeys.revoke'
export const TypeGrantAdd = 'grant.add'
export const TypeGrantRevoke = 'grant.revoke'
export const TypeSend = 'message.send'
export const TypeSendMedia = 'message.send.media'
export const TypeEdit = 'message.edit'
export const TypeRevoke = 'message.revoke'
export const TypeReact = 'message.react'
export const TypePollVote = 'message.poll.vote'
export const TypeMarkRead = 'message.read'
export const TypeGroupJoin = 'group.join'
export const TypeGroupGet = 'group.info'
export const TypeChatTimer = 'chat.timer'
export const TypeChatTyping = 'chat.presence'
export const TypeDeviceMode = 'device.mode'
export const TypeReprojectGet = 'reproject.list'
export const TypeReprojectPut = 'reproject.apply'
export const TypePing = 'ping'

// Server to client.
export const TypeWelcome = 'welcome'
export const TypeDevices = 'devices'
export const TypeReplayBegin = 'replay.begin'
export const TypeReplayEnd = 'replay.end'
export const TypeMessage = 'message'
export const TypeReceipt = 'receipt'
export const TypeLag = 'lag'
export const TypeChats = 'chats'
export const TypeContactList = 'contacts'
export const TypeGroupJoined = 'group.joined'
export const TypeGroupFrame = 'group'
export const TypeChatTimerSet = 'chat.timer.set'
export const TypePresence = 'presence'
export const TypeChatUpdate = 'chat.update'
export const TypeUnsupportedRows = 'reproject.rows'
export const TypeReprojected = 'reproject.done'
export const TypeAvatarFrame = 'avatar'
export const TypePage = 'page'
export const TypeHistoryFrame = 'history'
export const TypeMessageFrame = 'message.one'
export const TypeKeys = 'keys'
export const TypeExpiredList = 'media.expired.list'
export const TypeBackfillSent = 'history.backfill.sent'
export const TypeDeviceStatus = 'device.status'
export const TypeUsers = 'users'
export const TypeDeviceStats = 'devices.stats.result'
export const TypeDeviceDetail = 'device.detail'
export const TypeDeviceGone = 'device.deleted'
export const TypeAPIKeys = 'apikeys'
export const TypeAPIKeyNew = 'apikeys.created'
export const TypeAPIKeyGone = 'apikeys.revoked'
export const TypeReaders = 'device.readers'
export const TypePairQR = 'pair.qr'
export const TypePairCode = 'pair.code'
export const TypePairSuccess = 'pair.success'
export const TypePairTimeout = 'pair.timeout'
export const TypeSendResult = 'message.sent'
export const TypeError = 'error'
export const TypePong = 'pong'

/**
 * Hello authenticates the connection. Exactly one credential is expected: an
 * API key for a program, a session for a person who signed in.
 */
export interface Hello {
  api_key?: string
  session?: string
  version: number
  client_id?: string
}

export interface Welcome {
  version: number
  tenant_id: string
  features: string[]
  /** Who signed in. Empty for an API key, which is a program and not a person. */
  account?: string
  role?: string
  server_ts: number
}

export interface DeviceInfo {
  id: string
  label: string
  lid?: string
  pn?: string
  push_name?: string
  status: string
  status_reason?: string
  receipt_mode: string
  running: boolean
  created_at: string
  /** When it last reached "online" — not when it went offline. */
  last_connected_at?: string
  paused?: boolean
  can_manage?: boolean
  profile_key?: string
}

export interface Devices {
  devices: DeviceInfo[]
}

export interface DeviceStatus {
  device_id: string
  status: string
  reason?: string
}

// ---------------------------------------------------------------------------
// The tenant console
// ---------------------------------------------------------------------------

export interface UserSummary {
  id: string
  email: string
  role: string
  /** X25519, base64. A key grant is sealed to it, which is why the server has it. */
  public_key: string
}

export interface Users {
  users: UserSummary[]
}

export interface DeviceStat {
  device_id: string
  chats: number
  messages: number
  media: number
  media_bytes: number
  last_at?: string
}

export interface DeviceStats {
  stats: DeviceStat[]
}

/** KeyHolder is one account that can open a device's archive. */
export interface KeyHolder {
  user_id: string
  email: string
  role: string
  epoch: number
  granted_at: string
  granted_by?: string
}

export interface DeviceDetail {
  device: DeviceInfo
  stats: DeviceStat
  readers: KeyHolder[]
  epoch: number
}

/**
 * DeleteRequest destroys an archive, so confirm has to repeat the device id.
 * A mis-click in a list is otherwise indistinguishable from an intention.
 */
export interface DeleteRequest {
  device_id: string
  confirm: string
  unlink?: boolean
}

export interface DeviceDeleted {
  device_id: string
  chats: number
  messages: number
  media: number
  unlinked: boolean
  note?: string
}

export interface APIKeyInfo {
  prefix: string
  name: string
  scope?: KeyScope
  acts_as?: string
  created_by?: string
  created_at: string
  last_used_at?: string
  revoked_at?: string
}

export interface APIKeys {
  keys: APIKeyInfo[]
}

/** What a key may do. Each level includes the one before. */
export type KeyScope = 'read' | 'send' | 'full'

export interface APIKeyRequest {
  name: string
  scope: KeyScope
  /** A service account the key acts as: it carries that account's grants. */
  acts_as?: string
}

/** The plaintext key exists in this frame and nowhere else, ever again. */
export interface APIKeyCreated {
  key: string
  info: APIKeyInfo
}

export interface APIKeyRef {
  prefix: string
}

/**
 * GrantRequest hands one account the key to one device.
 *
 * The ciphertext is produced by a client that already holds the device key,
 * because only such a client can produce it. The epoch is sent so the server
 * can refuse a grant recorded against a generation the device is not sealing
 * under — that would look like access and fail to open.
 */
export interface GrantRequest {
  device_id: string
  user_id: string
  epoch: number
  /** base64 */
  sealed_dsk: string
}

export interface GrantRevoke {
  device_id: string
  user_id: string
}

export interface Readers {
  device_id: string
  readers: KeyHolder[]
}

/** KeyGrant is one account's copy of a device archive key, sealed here. */
export interface KeyGrant {
  user_id: string
  /** base64 */
  sealed_dsk: string
}

export interface PairRequest {
  label?: string
  /** "qr" or "code". */
  method: string
  phone?: string
  display_name?: string
  receipt_mode?: string
  /** Chosen here, because grants bind to it and are sealed before the row exists. */
  device_id: string
  /** base64. The private half is generated here and never sent. */
  archive_public_key: string
  grants: KeyGrant[]
  resume?: boolean
}

/** Retry a pending device without generating or replacing encryption material. */
export interface PairResumeRequest {
  device_id: string
  resume: true
  method: 'qr' | 'code'
  phone?: string
  display_name?: string
}

export interface PairCode {
  device_id: string
  code: string
  expires: string
}

export interface PairResult {
  device_id: string
}

export interface DeviceRef {
  device_id: string
}

/**
 * SendRequest asks the device to send a message.
 *
 * `id` is minted by the client, which is what makes a retry idempotent — and
 * more usefully here, it means the client knows the message's WhatsApp id
 * before the server answers. The archived row arrives on the live subscription
 * carrying that same id, often before the reply to this request, so it is the
 * only thing the two can be matched on.
 */
export interface SendRequest extends SendOptions {
  device_id: string
  chat: string
  body: string
  id?: string
  /** Quoting needs the text too: the archive is sealed, so the server cannot look it up. */
  reply_to?: string
  reply_sender?: string
  reply_body?: string
}

/**
 * SendOptions are the flags a message carries beyond its content.
 *
 * Shared by text and attachments because the server shares them
 * (wsapi.sendCommon), and because a flag that worked on a sentence and not on a
 * photograph would be exactly the quiet divergence this codebase avoids.
 */
export interface SendOptions {
  /**
   * Forwarded draws the "encaminhada" badge on the recipient's screen.
   *
   * forwarding_score alone does nothing: the server only reads the score inside
   * `if opts.Forwarded`, so a score without this flag produces an ordinary
   * message with no badge. Five or more is what WhatsApp renders as
   * "encaminhada muitas vezes".
   */
  forwarded?: boolean
  forwarding_score?: number
  /** The recipient may open it once. Media only; on text it renders as an error. */
  view_once?: boolean
  mentions?: string[]
  /**
   * A disappearing timer for this message alone, in seconds.
   *
   * Omitted normally: the server reads the conversation's timer and applies it,
   * envelope included. A value here overrides it for this one message, which is
   * a real thing on the wire — the timer travels in every message's context
   * info rather than on the chat.
   */
  expiration?: number
  /** Forces the disappearing envelope. Follows from expiration; sent with it. */
  ephemeral?: boolean
}

/**
 * UploadRef is the answer from POST /v1/upload, passed back untouched.
 *
 * Untouched is not a style preference. Go renders []byte as base64 strings, and
 * a client that decodes these to arrays and re-serialises them produces JSON Go
 * cannot read — which the server reports as "upload is required", pointing at
 * the wrong thing entirely. Nothing in this client should ever look inside
 * these three fields.
 */
export interface UploadRef {
  /**
   * The kind the upload encrypted for, echoed back by the endpoint.
   *
   * The server compares it with the frame's own type and refuses a send where
   * they disagree — bytes sealed under the image label inside a document
   * message would open for nobody. Nothing here needs to set it: it arrives in
   * the response and is forwarded with everything else.
   */
  type?: string
  url: string
  direct_path: string
  media_key: string
  file_sha256: string
  file_enc_sha256: string
  file_length: number
}

/**
 * SendMediaRequest sends an attachment already uploaded to WhatsApp.
 *
 * `type` must be the same value that was passed as ?type= to the upload. That
 * parameter picks the HKDF label the media key is derived from, so uploading as
 * one kind and sending as another produces a file that opens for nobody — the
 * recipient, and this archive too — with no error raised anywhere.
 */
export interface SendMediaRequest extends SendOptions {
  device_id: string
  chat: string
  type: string
  upload: UploadRef
  /** Required: the recipient decides how to render it from this alone. */
  mimetype: string
  id?: string
  /** Refused outright on audio, voice notes and round video notes. */
  caption?: string
  /** Required on a document, and what the recipient's download is called. */
  filename?: string
  width?: number
  height?: number
  seconds?: number
  /** Base64. The 64-bar sketch behind a voice note; audio only. */
  waveform?: string
  /** Base64 JPEG. Read for image, video, round video note and document. */
  thumbnail?: string
  /** A video that loops silently. WhatsApp has no GIF type, only this flag. */
  is_gif?: boolean
  is_animated?: boolean
  reply_to?: string
  reply_sender?: string
  reply_body?: string
}

export interface EditRequest {
  device_id: string
  chat: string
  target_id: string
  body: string
  /** RFC 3339. Lets the server refuse a stale edit without a round trip. */
  sent_at?: string
}

export interface RevokeRequest {
  device_id: string
  chat: string
  target_id: string
  /** The original author. Empty deletes our own. */
  sender?: string
}

export interface ReactRequest {
  device_id: string
  chat: string
  target_id: string
  sender?: string
  /** Empty removes. Not an empty reaction — a withdrawal. */
  emoji: string
}

/**
 * PollVoteRequest answers a poll.
 *
 * The options travel as text because the server hashes them: a vote on the wire
 * is SHA-256 of the option string. It cannot check them against the poll — the
 * poll's options are sealed and the server has never been able to read them —
 * so what goes out has to be the exact strings this client rendered.
 *
 * An empty list withdraws: WhatsApp replaces a voter's previous answer rather
 * than adding to it.
 */
export interface PollVoteRequest {
  device_id: string
  chat: string
  poll_id: string
  poll_sender: string
  poll_from_me?: boolean
  options: string[]
}

export interface SendResult {
  id: string
  uid?: string
  seq?: number
  timestamp: string
}

export interface Subscribe {
  since_seq: number
  live_only?: boolean
  devices?: string[]
}

export interface ReplayBegin {
  through_seq: number
}

export interface ReplayEnd {
  last_seq: number
  count: number
}

/** Lag says the stream was not continuous, and where to resume from. */
export interface Lag {
  from_seq: number
  dropped: number
}

/** SealedMedia is an attachment as it leaves the server. */
export interface SealedMedia {
  media_type: string
  mimetype?: string
  file_length?: number
  file_enc_sha256?: string
  width?: number
  height?: number
  seconds?: number
  /** The amplitude sketch behind a voice note. Not sealed: it carries no speech. */
  waveform?: string
  is_gif?: boolean

  media_key_sealed?: string
  thumb_sealed?: string
  filename_sealed?: string

  download_status: string
}

/**
 * SealedMessage is one archived message.
 *
 * Routing travels readable so a client can order and group without unwrapping
 * anything; content travels exactly as it sits on disk.
 */
export interface SealedMessage {
  uid: string
  seq: number
  /** Set only on type "unsupported": the protobuf field this build did not know. */
  unsupported?: string

  device_id: string
  wa_id: string
  chat_key: string
  sender_key?: string
  sender_lid?: string
  sender_pn?: string

  ts?: string
  is_from_me: boolean
  is_group?: boolean

  kind: string
  type: string

  target_wa_id?: string
  target_uid?: string
  target_rel?: string
  reply_to?: string

  is_forwarded?: boolean
  forwarding_score?: number

  expiration?: number
  expires_at?: string
  view_once?: boolean
  ephemeral?: boolean

  source: string

  content_key_id?: number
  body_sealed?: string
  payload_sealed?: string

  media?: SealedMedia
}

export interface ChatSummary {
  uid: string
  chat_key: string
  chat_lid?: string
  chat_pn?: string
  is_group?: boolean
  last_seq: number
  last_ts?: string
  /**
   * When the conversation was first recorded. It is what orders the ones with
   * no message at all: a group is a conversation from the moment the account
   * is in it, and has nothing else to sort by until somebody speaks.
   */
  created_at?: string
  /** When the group itself was made. What orders a conversation with no message. */
  group_created_at?: string
  last_kind?: string
  last_type?: string
  unread?: number
  archived?: boolean
  pinned?: boolean
  name_sealed?: string
  name_key_id?: number
  /**
   * Every conversation folded into this one, usually just its own.
   *
   * The same contact addressed by phone number for years and by LID since is
   * stored under both keys, and live traffic arrives addressed by whichever
   * one WhatsApp used — so a row has to recognise a message naming its other
   * half.
   */
  keys?: string[]
  /** Disappearing-message timer on the conversation, in seconds. Zero is off. */
  ephemeral?: number
  /** People in the group, including us. The denominator behind the ticks. */
  audience?: number

  // The newest message in the conversation, so a list can draw a preview
  // without a request per row. Bound to last_uid, not to the chat.
  last_uid?: string
  last_body_sealed?: string
  last_body_key_id?: number
}

export interface Chats {
  device_id: string
  chats: ChatSummary[]
}

export interface ContactSummary {
  uid: string
  contact_key: string
  contact_lid?: string
  contact_pn?: string
  is_group?: boolean
  content_key_id?: number
  push_name_sealed?: string
  full_name_sealed?: string
  business_name_sealed?: string
  has_avatar?: boolean
  avatar_id?: string
  avatar_key_id?: number
}

export interface Contacts {
  device_id: string
  contacts: ContactSummary[]
}

/**
 * ContactsResolveRequest asks who particular identifiers belong to.
 *
 * The answer comes back as an ordinary `contacts` frame, holding only the rows
 * asked about. It exists because contacts.list is loaded once and a client then
 * meets identifiers that list did not have — a conversation started since, a
 * group participant who has never sent anything here — and reloading five
 * thousand rows to learn one name is the wrong shape.
 *
 * Answering it also nudges the server's picture worker, so a face somebody is
 * looking at right now does not wait behind a paced sweep of every contact.
 */
export interface ContactsResolveRequest {
  device_id: string
  contact_keys: string[]
}

export interface AvatarRequest {
  device_id: string
  contact_key: string
}

export interface Avatar {
  device_id: string
  contact_key: string
  uid: string
  key_id?: number
  sealed?: string
}

/**
 * ChatPageRequest asks for a page of one conversation.
 *
 * The cursor is a pair. A conversation is ordered by when each message was
 * sent, WhatsApp timestamps are whole seconds, and a burst inside one second is
 * ordinary — so seq breaks the tie. A cursor on time alone would skip messages
 * or repeat them at every page boundary.
 */
export interface ChatPageRequest {
  device_id: string
  chat_key: string
  /** Both halves, or neither. Omitted means the latest page. */
  before_ts?: string
  before_seq?: number
  limit?: number
}
/**
 * One message's ticks, as counts of PEOPLE.
 *
 * Not rows and not devices: one reader with a phone and a laptop is one person
 * who received it. Our own acknowledgements are excluded from the counts and
 * reported in read_by_us — WhatsApp's "sender" receipt is our own handset
 * confirming it received a message we sent, and counting it draws two grey
 * ticks with the recipient having received nothing.
 *
 * retrying and failed are apart, and no tick rule reads them: a message stuck
 * in retry looks delivered and is not.
 */
export interface MessageAcks {
  wa_id: string
  delivered?: number
  read?: number
  played?: number
  delivered_at?: string
  read_at?: string
  played_at?: string
  read_by_us?: boolean
  retrying?: boolean
  failed?: boolean
}

export interface Page {
  chat_key: string
  messages: SealedMessage[]
  /** Receipts for the messages above, so ticks survive a reload. */
  receipts?: MessageAcks[]
  has_more: boolean
  /** The cursor for the page before this one. Sent, not derived. */
  next_ts?: string
  next_seq?: number
}

export interface HistoryRequest {
  device_id: string
  uid?: string
  chat_key?: string
  wa_id?: string
}

export interface MessageVersion {
  revision: number
  message: SealedMessage
  from?: string
  until?: string
}

export interface MessageDeletion {
  message: SealedMessage
  by_author: boolean
  at?: string
}

export interface MessageReaction {
  message: SealedMessage
  superseded?: boolean
  revoked?: boolean
  revoked_at?: string
}

/**
 * MessageReader is one party's acknowledgements and which revision they saw.
 *
 * `confirmed` is the part a UI must not round off: when it is false the higher
 * revision was inferred by comparing clocks that were never synchronised, and
 * rendering it as fact claims someone read a correction they may never have
 * been shown.
 */
export interface MessageReader {
  key: string
  lid?: string
  pn?: string
  is_from_me?: boolean
  delivered?: string
  read?: string
  played?: string
  saw_revision: number
  confirmed_revision: number
  confirmed: boolean
  /**
   * Which of this person's devices produced the read the three fields above
   * describe, and what each device acknowledged.
   *
   * Those three belong to a DEVICE: which text somebody had on screen is
   * decided by what that handset had received. The top-level times are the
   * earliest across devices — "received at 14:02 and again at 19:40" is one
   * person with two phones, and when they got it is the first one.
   */
  read_device?: string
  devices?: ReaderDevice[]
  /**
   * The same acknowledgements told per version.
   *
   * What a panel opened on one revision has to draw. The flat `delivered`
   * above is the earliest across every version — "did this reach them at all"
   * — and putting that under a revision heading claims the correction was
   * delivered on the strength of the original having been.
   */
  revisions?: ReaderRevision[]
}

/**
 * ReaderRevision is what one party acknowledged about ONE version.
 *
 * `delivered` is exact: each version is a stanza with a WhatsApp id of its own
 * and collects its own delivery receipts. `read` and `played` are usually exact
 * too — editing a message makes it unread again, and reading it afresh sends a
 * receipt naming the edit's own stanza. They fall back to inference only for
 * our own devices, which mark a line read under the original's id whatever
 * version is on screen; `confirmed` is what tells the two apart, and means
 * nothing without `read`.
 */
export interface ReaderRevision {
  revision: number
  delivered?: string
  read?: string
  played?: string
  confirmed?: boolean
}

export interface ReaderDevice {
  key: string
  agent?: number
  device?: number
  delivered?: string
  read?: string
  played?: string
  saw_revision: number
  confirmed_revision: number
  confirmed: boolean
  revisions?: ReaderRevision[]
}

export interface History {
  device_id: string
  chat_key: string
  wa_id: string
  versions: MessageVersion[]
  deletion?: MessageDeletion
  reactions?: MessageReaction[]
  readers?: MessageReader[]
}

/** ReceiptEvent is one acknowledgement. It shares the tenant sequence with messages. */
export interface ReceiptEvent {
  seq: number
  device_id: string
  chat_key: string
  wa_ids: string[]
  /** The identifier as WhatsApp addressed it, device suffix and all. */
  reader_key: string
  /**
   * The same reader folded to a person, which is what a count must key on.
   *
   * A group of eight where three people carry two devices each produces eleven
   * acknowledgements and has eight readers, and a tick waiting for everyone
   * would wait on a number that does not exist.
   */
  reader_person?: string
  reader_lid?: string
  reader_pn?: string
  is_from_me?: boolean
  kind: string
  ts: string
}

/**
 * KeysRequest asks for sealed content keys by id.
 *
 * Scoped to a device, because content keys are: each is sealed to that
 * device's archive key and ids are counted per device, so id 7 names a
 * different key on every account.
 */
export interface KeysRequest {
  device_id: string
  ids: number[]
}

export interface SealedKey {
  id: number
  sealed: string
}

export interface Keys {
  device_id: string
  keys: SealedKey[]
}

export interface ExpiredMediaRequest {
  device_id: string
  limit?: number
}

export interface ExpiredMedia {
  uids: string[]
}

export interface BackfillRequest {
  device_id: string
  chat: string
  count?: number
}

export interface BackfillSent {
  chat: string
  anchor_id: string
  count: number
}

export interface WireError {
  code: string
  message: string
}

/** Stable error codes, so a client can branch without parsing prose. */
export const ErrUnauthorized = 'unauthorized'
export const ErrBadRequest = 'bad_request'
export const ErrVersionMismatch = 'version_mismatch'
export const ErrNotFound = 'not_found'
export const ErrConflict = 'conflict'
export const ErrInternal = 'internal'
export const ErrRateLimited = 'rate_limited'

/**
 * The message kinds the archive stores.
 *
 * Only 'message' is a line in a conversation. The other three are control rows
 * that act on one — which is why an edit does not appear beneath the message it
 * replaced, and a deleted message is still there with its text intact.
 */
export type MessageKind = 'message' | 'edit' | 'delete' | 'reaction'

/** The content types. */
export type MessageType =
  | 'text'
  | 'image'
  | 'video'
  | 'ptv'
  | 'audio'
  | 'ptt'
  | 'document'
  | 'sticker'
  | 'location'
  | 'live_location'
  | 'contact'
  | 'contact_array'
  | 'poll'
  | 'poll_vote'
  | 'event'
  | 'album'
  | 'template'
  // The business formats, all text plus the labels of what was offered.
  | 'interactive'
  | 'buttons'
  | 'list'
  | 'button_reply'
  // A message the phone masked from linked devices. It exists on the
  // handset; here there is a slot where it should be, and nothing a later
  // build could do about it.
  | 'placeholder'
  | 'reaction'
  | 'protocol'
  // Kept rather than dropped: WhatsApp adds message types continuously, and a
  // client that discarded what it did not know would leave holes nobody can
  // explain later.
  | 'unsupported'
  // Distinct from unsupported: WhatsApp itself could not decrypt this one, and
  // the remedy is a resend request rather than a newer client.
  | 'undecryptable'

/** What a control row's target points at. */
export type TargetRel = '' | 'message' | 'reaction'

const mediaTypes = new Set(['image', 'video', 'ptv', 'audio', 'ptt', 'document', 'sticker'])

export function hasMedia(type: string): boolean {
  return mediaTypes.has(type)
}

/** The structured content a message can carry, mirroring domain.Payload. */
export interface Location {
  lat: number
  lon: number
  name?: string
  address?: string
  accuracy_m?: number
  speed?: number
  seq?: number
}

export interface ContactCard {
  display_name?: string
  vcard?: string
}

export interface Poll {
  question?: string
  options?: string[]
  /**
   * How many options one voter may pick. Read it through limitOf, never
   * literally: 1 is a single-answer poll, and 0 or absent is a poll that stated
   * no limit — which is what "allow multiple answers" produces, not a single
   * choice. See state/polls.ts.
   */
  selectable_count?: number
}

/**
 * PollVote is somebody's answer, as SHA-256 hashes of the option text.
 *
 * Hashes because that is what WhatsApp transmits, and because the server could
 * not resolve them if it wanted to: a poll's options are sealed content it has
 * never been able to read. Resolving them is this client's job — it opens the
 * poll, hashes each option, and looks for the result here. See state/polls.ts.
 *
 * Each entry is base64, which is how Go writes a byte slice as JSON.
 */
export interface PollVote {
  selected?: string[]
}

/**
 * Album is the header WhatsApp sends before a batch of pictures.
 *
 * It declares how many follow and carries none of them; the pictures arrive as
 * ordinary messages of their own, and nothing in the protobuf links one back to
 * this. So it is rendered as what it says it is rather than as a grid somebody
 * guessed the membership of.
 */
export interface Album {
  images?: number
  videos?: number
}

export interface CalendarEvent {
  name?: string
  description?: string
  location?: Location
  join_link?: string
  start_time?: string
  end_time?: string
  is_canceled?: boolean
  extra_guests_allowed?: boolean
}

/**
 * An invitation to join a group, sent into a conversation.
 *
 * The code is a capability: whoever holds it can join, without the sender being
 * asked again. It is sealed with the rest of the payload for that reason, which
 * is also why accepting has to start here — the server stored the code and
 * cannot read it, so the browser opens it and hands it back for one exchange.
 */
export interface GroupInvite {
  group_jid?: string
  code?: string
  /** Unix seconds. WhatsApp refuses a code past this. */
  expiration?: number
  name?: string
  caption?: string
  /** A small JPEG of the group picture, base64 like every other sealed blob. */
  thumbnail?: string
}

export interface GroupJoinRequest {
  device_id: string
  group_jid: string
  inviter: string
  code: string
  expiration?: number
}

/**
 * MarkReadRequest tells the other side a message was read.
 *
 * Always explicit — nothing on the server's ingest path sends one — which is
 * what makes silence the default posture and makes the incognito switch a
 * matter of not calling this rather than of asking the server to suppress it.
 *
 * By position: acknowledging a message clears everything under it, which is
 * what WhatsApp does and what makes an unread badge mean "how much is left at
 * the end of this conversation".
 */
export interface MarkReadRequest {
  device_id: string
  chat: string
  sender?: string
  ids: string[]
  /** Voice notes and view-once media: a separate signal from read. */
  played?: boolean
}

/**
 * Saying we are typing, or have stopped.
 *
 * The most continuous signal this account emits: it names a conversation
 * somebody has open, at this exact moment, several times a minute. The server
 * refuses to send it in the quiet posture, and the client stops asking — both,
 * because one of the two being wrong should not be enough to leak it.
 */
export interface ChatPresenceRequest {
  device_id: string
  chat: string
  /** 'composing' or 'paused'. */
  state: string
  /** 'audio' while recording a voice note, absent while typing. */
  media?: string
}

/** Somebody else typing. Carries no sequence and is never replayed. */
/**
 * A change to a conversation itself, pushed as it happens.
 *
 * A patch, not a snapshot. Every field is optional and absent means "this event
 * says nothing about that" — which is not the same as zero, and zero is a real
 * value for both: a badge of zero is a conversation just read, and a timer of
 * zero is disappearing messages turned off. Treating an absent field as zero
 * would clear one whenever the other moved.
 */
export interface ChatUpdateEvent {
  device_id: string
  chat_key: string
  unread?: number
  ephemeral?: number
}

export interface PresenceEvent {
  device_id: string
  chat_key: string
  sender_key?: string
  sender_lid?: string
  sender_pn?: string
  state: string
  media?: string
}

/** Changing what a device tells the other side, while it runs. */
export interface DeviceModeRequest {
  device_id: string
  /** 'passive' (quiet, and what incognito means) or 'active'. */
  receipt_mode: string
}

export interface GroupRequest {
  device_id: string
  chat: string
  /** Ask WhatsApp rather than answering from the archive alone. */
  refresh?: boolean
}

/**
 * One participant.
 *
 * The identifiers are readable, exactly as they already are on messages and
 * receipts; the NAME is not here, because a name is content and lives sealed in
 * contacts. A client resolves it there, the same way it resolves the author of
 * any message.
 */
export interface GroupMember {
  key: string
  lid?: string
  pn?: string
  is_admin?: boolean
  is_super_admin?: boolean
}

export interface GroupChange {
  ts: string
  action: string
  actor_key?: string
  actor_lid?: string
  actor_pn?: string
  subject_key?: string
  subject_lid?: string
  subject_pn?: string
  detail?: string
}

export interface Group {
  chat_key: string
  members: GroupMember[]
  changes?: GroupChange[]
  /**
   * When this archive's record of the group begins.
   *
   * Before it nothing is known and nothing is claimed: WhatsApp does not
   * deliver a group's past, so an empty history is not a peaceful one and a
   * reader has to be told which they are looking at.
   */
  since?: string
  refreshed?: boolean
}

/** Turning disappearing messages on or off for a conversation. */
export interface ChatTimerRequest {
  device_id: string
  chat: string
  /** Seconds. Zero turns them off. */
  seconds: number
}

export interface ChatTimerResult {
  chat: string
  seconds: number
}

export interface GroupJoined {
  group_jid: string
}

/**
 * Looking again at messages the archive could not classify when they arrived.
 *
 * Classification happens once, on the way in, so a message that reached the
 * archive before its type was supported stays "unsupported" for good. The
 * protobuf that produced it was sealed and kept precisely so a later build can
 * look again — but the server cannot open its own archive, which is the premise
 * everything rests on.
 *
 * So the work is split: this tab holds the key and opens raw_sealed, and the
 * server holds the classifier and re-seals with the public half. The archive key
 * never leaves the browser. What does leave, for the rows somebody explicitly
 * asked about, is the message itself — the same exposure outbound text already
 * carries, and far smaller than pasting the archive key into a terminal.
 */
export interface ReprojectRequest {
  device_id: string
  limit?: number
  /**
   * Page cursor: rows older than this sequence.
   *
   * A cursor rather than an offset because most rows stay unsupported and come
   * back on every pass, so a second request without one returns the same
   * unconvertible page for ever.
   */
  before_seq?: number
  uid?: string
  /** The opened protobuf, base64 like every other byte field. */
  raw?: string
}

export interface UnsupportedRow {
  uid: string
  seq: number
  wa_id: string
  /** The protobuf field this build could not classify. */
  field?: string
  content_key_id?: number
  raw_sealed?: string
}

export interface Unsupported {
  device_id: string
  rows: UnsupportedRow[]
}

export interface Reprojected {
  uid: string
  type: string
  changed: boolean
  note?: string
  /** Protocol traffic rather than a message. Not a failure. */
  machinery?: boolean
}

export interface LinkPreview {
  url?: string
  title?: string
  description?: string
  thumbnail?: string
}

export interface Payload {
  mentions?: string[]
  location?: Location
  contacts?: ContactCard[]
  poll?: Poll
  event?: CalendarEvent
  link_preview?: LinkPreview
  group_invite?: GroupInvite
  album?: Album
  buttons?: string[]
  poll_vote?: PollVote
}
