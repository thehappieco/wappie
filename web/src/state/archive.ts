import { t } from '../ui/i18n'
// The application state.
//
// One store, no framework beyond Vue's own reactivity. It owns the connection,
// the opener that holds the archive key, and the projection from archived rows
// to something a person can read.
//
// The shape follows what the server actually offers: a chat list and pages,
// pushed live traffic on one cursor shared by messages and receipts, and a
// per-message history that is asked for only when someone looks at it. Nothing
// here keeps a local database — the archive is the database, and it is sealed.

import { reactive, shallowReactive } from 'vue'

import { origin } from '../api/endpoint'
import { readLastDevice, rememberLastDevice, type DevicePreferenceScope } from '../ui/lastDevice'
import { clearWorkspaceDeviceURL, setWorkspaceDeviceURL } from '../ui/workspaceNavigation'
import { Connection, ProtocolError } from '../api/client'
import { applyPresence, forgetPresence, setTypingNotifications } from './presence'
import { setReadReceipts } from './reading'
import { absorbReceipts, applyReceipt, forgetReceipts } from './receipts'
import { Media, type MediaState } from '../api/media'
import { Opener, type Opened } from '../api/opener'
import * as P from '../api/protocol'
import type { Bytes } from '../crypto/bytes'
import { parseUUID } from '../crypto/bytes'
import type { Session } from './session'
import { Directory, type Person } from './directory'
import { displayFallback, isGroup, isStatus } from './jid'
import { project, standing, type Entry } from './conversation'
import { count, fromBase64, hashesOf, type Tally, type Vote } from './polls'
import { sweepUnsupported, type ReprojectProgress } from './reproject'
import { floorScore } from '../media/plan'
import { discard, type Prepared } from '../media/prepare'

export const PAGE_SIZE = 60

/** OpenState mirrors Opened without the value, for rendering. */
export type OpenState = 'ok' | 'absent' | 'locked' | 'tampered'

function stateOf<T>(o: Opened<T>): OpenState {
  return o.state
}

export interface ChatView {
  key: string
  /** Every key this conversation is stored under. Usually just `key`. */
  keys: string[]
  uid: string
  isGroup: boolean
  /** The status feed, which is not a conversation and is not a group either. */
  isStatus: boolean
  name: string
  nameState: OpenState
  lastSeq: number
  lastTS?: Date
  /** When the conversation row was written here. The last-resort sort key. */
  createdAt?: Date
  /** When the group itself was made, which is what orders a quiet group. */
  groupCreatedAt?: Date
  lastKind: string
  lastType: string
  unread: number
  pinned: boolean
  archived: boolean
  /** The newest message, opened, for the list. Empty when it carries no text. */
  preview: string
  previewState: OpenState
  /** Disappearing-message timer on the conversation, in seconds. Zero is off. */
  ephemeral: number
  /** People in the group, including us. Undefined when nobody has asked. */
  audience?: number
  /** The contact key to ask for a picture, which for a group is the group itself. */
  avatarKey: string
}

export interface MediaView {
  type: string
  mimetype: string
  fileLength: number
  width: number
  height: number
  seconds: number
  isGIF: boolean
  waveform?: number[]
  fileName: string
  status: string
  /** The inline preview the message carried, already opened. */
  thumbURL?: string
  /** Filled once someone asks for the full attachment. */
  full?: MediaState
  /**
   * A local object URL for an attachment on its way out.
   *
   * The file is right here, in this tab, and has been since somebody picked
   * it — so the bubble draws the real picture immediately rather than a
   * placeholder, and keeps drawing it after the archived row arrives. Without
   * this the photograph blinks out at the moment it is archived and is
   * replaced by the small sealed thumbnail until the download worker has
   * fetched the full copy back from WhatsApp's CDN, which takes as long as it
   * takes.
   */
  localURL?: string
  /**
   * How much of the upload has left this tab.
   *
   * Kept apart from `full`, whose 'pending' state means the opposite thing —
   * the server has the attachment and has not finished fetching it. Rendering
   * an upload through that would tell somebody their own file is "ainda no
   * servidor" while it is still on their disk.
   */
  upload?: { sent: number; total: number }
}

export interface ReactionView {
  emoji: string
  who: string
  fromMe: boolean
}

/** PollView is a poll and what the archive knows about its answers. */
export interface PollView {
  tally: Tally
  /** Whether every vote in the window could be opened and matched. */
  complete: boolean
}

export interface MessageView {
  uid: string
  waID: string
  seq: number
  ts?: Date
  fromMe: boolean
  isGroup: boolean
  /** A status post. Not a group, but still written by somebody who has to be named. */
  isStatus: boolean
  /** The key this message was addressed under. One conversation can have two. */
  chatKey: string
  senderKey: string
  senderName: string
  type: string
  /** For an unsupported message, the protobuf field the server could not read. */
  unsupported: string
  body: string
  bodyState: OpenState
  payload?: P.Payload
  media?: MediaView
  reactions: ReactionView[]
  /** Set on a poll, once its answers have been opened and counted. */
  poll?: PollView
  edited: boolean
  versionCount: number
  deleted: boolean
  deletedAt?: Date
  viewOnce: boolean
  /**
   * Whether the message travelled in the disappearing envelope.
   *
   * Not enough on its own to decide whether to say "temporária": a row can
   * carry a timer without the flag, which is how the marker came and went on
   * messages that all had an expiry date. See ephemeralOf.
   */
  ephemeral: boolean
  /** The timer the message was sent with, in seconds. */
  expiration: number
  expiresAt?: Date
  forwarded: boolean
  forwardingScore: number
  replyTo?: string
  /**
   * Where an outgoing message is in its journey. Absent on everything that came
   * out of the archive, which is everything except a line this tab just sent.
   *
   * 'unarchived' is the awkward one and it is real: the server reports a send
   * that reached WhatsApp but could not be written down as a success, because
   * it is one — the message is on the recipient's phone either way, and failing
   * the call would invite a retry that sends it twice. But no row will ever
   * arrive for it, so the line would sit at "enviando…" for the rest of the
   * session unless it is named.
   */
  pending?: 'sending' | 'failed' | 'unarchived'
  failure?: string
  /** The rows behind this line, kept so the panel can work without refetching. */
  entry: Entry
}

export interface UnsupportedSummary {
  total: number
  byField: Record<string, number>
  running: boolean
  sweptAt?: Date
  /** What the last sweep did, for the panel to say. */
  lastRun?: ReprojectProgress
  error?: string
}

export interface ReaderView {
  key: string
  name: string
  fromMe: boolean
  /** The earliest across this person's devices: when THEY got it. */
  delivered?: Date
  read?: Date
  played?: Date
  sawRevision: number
  confirmedRevision: number
  confirmed: boolean
  /**
   * Which of this person's devices produced the read the revision fields
   * describe, and what each device acknowledged.
   *
   * Kept because those fields belong to a device. Which text somebody had on
   * screen is decided by what THAT handset had received, and a person reading
   * on a phone whose laptop is three edits ahead is ordinary rather than a
   * puzzle. It is also the answer to "why does this person appear twice with
   * different times" — they do not; they have two phones.
   */
  readDevice: string
  devices: ReaderDeviceView[]
  /** The same acknowledgements, told per version. Keyed by revision. */
  revisions: Map<number, ReaderRevisionView>
}

/**
 * What one party acknowledged about ONE version of a message.
 *
 * Receipt IDs establish per-version delivery, reading and playback. Ambiguous
 * receipts are not shown as evidence for a version.
 */
export interface ReaderRevisionView {
  revision: number
  delivered?: Date
  read?: Date
  played?: Date
  confirmed: boolean
  playedConfirmed?: boolean
}

export interface ReaderDeviceView {
  key: string
  /** WhatsApp's two-part device axis, for a stable label. */
  agent: number
  device: number
  delivered?: Date
  read?: Date
  played?: Date
  sawRevision: number
  confirmedRevision: number
  confirmed: boolean
  revisions: Map<number, ReaderRevisionView>
}

export interface VersionView {
  revision: number
  body: string
  bodyState: OpenState
  from?: Date
  until?: Date
}

export interface HistoryView {
  uid: string
  waID: string
  versions: VersionView[]
  deletion?: { byAuthor: boolean; byAdmin?: boolean; at?: Date }
  /**
   * Every reaction row, in the order they happened.
   *
   * A timeline rather than a list, because the archive kept the whole sequence
   * and the sequence is the interesting part: somebody put a heart, changed it
   * to a laugh an hour later, then took it back. WhatsApp shows only the last
   * of those, and only while it stands.
   */
  reactions: {
    emoji: string
    who: string
    superseded: boolean
    revoked: boolean
    at?: Date
    revokedAt?: Date
  }[]
  readers: ReaderView[]
}

interface State {
  phase: 'locked' | 'connecting' | 'ready' | 'error'
  /**
   * Which screen is up. The archive and the console share one connection and
   * one session, so this is a view and not a route: switching does not
   * reconnect, re-derive a key or re-fetch a conversation.
   */
  view: 'archive' | 'admin'
  error: string
  label: string
  /** The account signed in, and its role. Empty when a key was pasted. */
  account: string
  role: string
  /**
   * Whether the account's recovery code can be redeemed. False for a pasted
   * key, and for an account from before recovery worked — which is shown a
   * nudge to generate one, because a forgotten password with no code behind
   * it is an archive nobody can read.
   */
  hasRecovery: boolean
  /** Invalidates views derived from the session's refreshed key envelopes. */
  accessRevision: number
  tenantID: string
  connected: boolean
  /** Handshake and initial device/chat loading must finish before switching. */
  initializingConnection: boolean
  closedReason: string
  /** Set while waiting to retry. Seconds, counted down for the status line. */
  reconnectIn: number

  devices: P.DeviceInfo[]
  deviceID: string
  /**
   * Set when this account holds no key for the selected device.
   *
   * Distinct from an error: the account is fine, the server is fine, and this
   * WhatsApp number is simply not one it may read. Somebody with the device
   * has to grant it.
   */
  unreadable: boolean

  chats: ChatView[]
  chatFilter: string
  contactsLoaded: number

  openChatKey: string
  openChatName: string
  timeline: MessageView[]
  hasOlder: boolean
  loadingChat: boolean
  loadingOlder: boolean

  selectedUID: string
  history: HistoryView | null
  historyError: string
  historyLoading: boolean

  /** Whether this person is discreet on the selected number. Mirrors the server. */
  quiet: boolean
  /**
   * What the archive holds that this build cannot read, counted at connect.
   *
   * Filled by sweepUnsupported, which runs when the archive opens: whatever
   * an older build filed as unsupported and the current classifier now
   * understands is converted quietly, and what is left is counted here by the
   * protobuf field it carried. That name is what says what to implement next.
   */
  unsupported: UnsupportedSummary
  /** Whether the group panel is open beside the conversation. */
  groupPanel: boolean
  liveCount: number
  lagged: boolean

  /** What went wrong with the last reaction, edit or deletion. */
  actionError: string
}

export const state = reactive<State>({
  phase: 'locked',
  view: 'archive',
  error: '',
  label: '',
  account: '',
  role: '',
  hasRecovery: false,
  accessRevision: 0,
  tenantID: '',
  connected: false,
  initializingConnection: false,
  closedReason: '',
  reconnectIn: 0,

  devices: [],
  deviceID: '',
  unreadable: false,

  chats: [],
  chatFilter: '',
  contactsLoaded: 0,

  openChatKey: '',
  openChatName: '',
  timeline: [],
  hasOlder: false,
  loadingChat: false,
  loadingOlder: false,

  selectedUID: '',
  history: null,
  historyError: '',
  historyLoading: false,

  quiet: true,
  unsupported: { total: 0, byField: {}, running: false },
  groupPanel: false,
  liveCount: 0,
  lagged: false,
  actionError: '',
})

/** avatars maps a contact key to an object URL, filled in as the list draws. */
export const avatars = shallowReactive(new Map<string, string>())

let conn: Connection | null = null
let opener: Opener | null = null
let media: Media | null = null
let tenantBytes: Bytes | null = null
const directory = new Directory()

/**
 * The session is kept so the connection can be rebuilt without asking for the
 * passphrase again. It holds the archive key, which is why nothing outside this
 * module is given a reference to it.
 */
let session: Session | null = null
let openerDeviceID = ''
let stopped = false
let attempt = 0
let retryTimer: ReturnType<typeof setTimeout> | undefined
let countdown: ReturnType<typeof setInterval> | undefined
let connectionAttempt = 0

// Requests and decryptions can finish after a device switch or sign-out.
// Holding the opener and generation together keeps those results out of the
// next device's directory, pictures and conversation.
let archiveGeneration = 0
let chatsGeneration = 0
let conversationGeneration = 0
let directoryLoading: number | null = null

interface ArchiveContext {
  generation: number
  deviceID: string
  connection: Connection
  open: Opener
}

function archiveContext(): ArchiveContext | null {
  if (!conn || !opener) return null
  return { generation: archiveGeneration, deviceID: state.deviceID, connection: conn, open: opener }
}

function currentArchive(context: ArchiveContext): boolean {
  return !stopped && context.generation === archiveGeneration &&
    context.deviceID === state.deviceID && context.connection === conn && context.open === opener
}

/** Rows for the open conversation, kept so paging older can re-project. */
let openRows: P.SealedMessage[] = []

/**
 * Messages this tab has sent and not yet seen come back.
 *
 * Separate from state.timeline rather than pushed into it, because the timeline
 * is not a list anyone appends to: every live frame reassigns it from
 * buildTimeline(openRows), so an optimistic line put there is erased by the
 * next message that arrives. Keyed by the WhatsApp id, which the client mints
 * itself — that is the only identifier both this map and the archived row carry.
 *
 * A pending line cannot be built by the normal path either: it has no sealed
 * body, and the opener would report it as absent. So it is assembled here and
 * merged at the end of buildTimeline.
 */
const outbox = new Map<string, MessageView>()

/**
 * Local previews of attachments this tab sent, by WhatsApp id.
 *
 * Kept past the moment the archived row replaces the optimistic line, which is
 * the whole point. The row carries the small sealed thumbnail and a media
 * record whose download_status is 'pending' until the server has fetched the
 * full attachment back from WhatsApp's CDN — so without this, a photograph
 * shrinks to a blurred stamp the instant it is archived, for however long that
 * fetch takes, with the original sitting in memory the entire time.
 *
 * Bounded and revoked on eviction, the same discipline the download cache
 * keeps: a session that sends thirty photographs must not hold thirty of them.
 */
const previews = new Map<string, string>()
const PREVIEW_LIMIT = 12

/**
 * Opened inline thumbnails, by message uid.
 *
 * The sealed preview inside a message has to become an object URL to be drawn,
 * and the conversation is rebuilt from scratch on every live frame — so minting
 * one per rebuild leaks a blob for every attachment on screen, every time
 * anything happens. Kept and reused instead, bounded like everything else here.
 */
const thumbs = new Map<string, string>()
const THUMB_LIMIT = 200

function thumbURL(uid: string, bytes: Uint8Array): string {
  const held = thumbs.get(uid)
  if (held) return held
  const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type: 'image/jpeg' }))
  thumbs.set(uid, url)
  while (thumbs.size > THUMB_LIMIT) {
    const oldest = thumbs.keys().next()
    if (oldest.done) break
    const evicted = thumbs.get(oldest.value)
    thumbs.delete(oldest.value)
    if (evicted) URL.revokeObjectURL(evicted)
  }
  return url
}

function keepPreview(waID: string, url: string): void {
  if (!url) return
  forgetPreview(waID)
  previews.set(waID, url)
  for (const oldest of [...previews.keys()]) {
    if (previews.size <= PREVIEW_LIMIT) break
    // Never the one still on its way out: an optimistic line holds this same
    // string and is not re-read from here, so revoking it under the line turns
    // the picture somebody is watching upload into a broken image.
    if (outbox.has(oldest)) continue
    forgetPreview(oldest)
  }
}

function forgetPreview(waID: string): void {
  const held = previews.get(waID)
  if (!held) return
  URL.revokeObjectURL(held)
  previews.delete(waID)
}

function clearPreviews(): void {
  for (const url of previews.values()) URL.revokeObjectURL(url)
  previews.clear()
  for (const url of thumbs.values()) URL.revokeObjectURL(url)
  thumbs.clear()
}

/**
 * Which rebuild is current.
 *
 * buildTimeline awaits — it fetches content keys — so two live frames arriving
 * close together can interleave and the slower one can overwrite the fresher
 * result. The counter makes a stale build drop its own answer.
 */
let timelineGen = 0

/**
 * Where the next older page starts, as the server reported it.
 *
 * Kept rather than derived from openRows. The conversation is ordered by send
 * time and paged on (time, seq), so "the oldest row I hold" is a different
 * question from "where the last page ended" the moment a page boundary falls
 * inside one second — and the server is the side that knows.
 */
let olderCursor: { ts: string; seq: number } | null = null

/**
 * When each contact was last asked about, so nothing is asked twice in a row
 * and nothing is asked once and then never again.
 *
 * A plain "already asked" set was the shape here, and it is wrong in one
 * direction that matters: the answer for an identifier nobody had named yet was
 * "nothing", and the set then made that permanent for the life of the tab. A
 * push name that arrived a second later — which is the normal case for a
 * conversation that has only just started — would never be picked up. A
 * timestamp lets the next draw try again without letting every draw ask.
 */
const namesAsked = new Map<string, number>()
const avatarsAsked = new Map<string, number>()

/**
 * How long an answer of "nothing known" is trusted before asking again.
 *
 * Two windows, because the two questions age differently. A name nobody has is
 * usually a name that is about to arrive — a push name lands with the first
 * message somebody sends — so a short window is right. A face nobody has is
 * usually permanent: the contact has no picture, or their privacy settings hide
 * it, and the server records that so its own worker stops asking. Putting both
 * on thirty seconds turned every badge remount — filtering the list, switching
 * conversation — into another round of requests for exactly the contacts where
 * the answer never changes.
 */
export const ASK_AGAIN_MS = 30_000
export const AVATAR_ASK_AGAIN_MS = 10 * 60_000

/** Identifiers waiting to go out in the next resolve request. */
const pendingNames = new Set<string>()
let resolveTimer: ReturnType<typeof setTimeout> | undefined

/**
 * How long to gather identifiers before asking.
 *
 * Long enough that drawing a conversation of sixty messages asks once, short
 * enough that nobody watches a LID sit on screen. The request is off the render
 * path either way: nothing waits for it, and the names appear when they appear.
 */
const RESOLVE_DEBOUNCE_MS = 150

function askedRecently(at: Map<string, number>, key: string, within = ASK_AGAIN_MS): boolean {
  const last = at.get(key)
  return last !== undefined && Date.now() - last < within
}

/**
 * inOpenChat reports whether a chat key belongs to the conversation on screen.
 *
 * By key set, not by equality. The same contact addressed by phone number for
 * years and by LID since is one conversation stored under two keys, and live
 * traffic arrives addressed by whichever one WhatsApp used — so comparing
 * against the single key the reader clicked drops half the messages on the
 * floor, silently, in exactly the conversations that already looked broken.
 */
export function inOpenChat(chatKey: string): boolean {
  if (!state.openChatKey) return false
  if (chatKey === state.openChatKey) return true
  const open = state.chats.find((c) => c.key === state.openChatKey)
  return open ? open.keys.includes(chatKey) : false
}

export function people(): Directory {
  return directory
}

/**
 * archiveOpener is the unlocked opener for the device on screen, or null.
 *
 * Exposed so the reprojection can open stored protobufs. It is the only thing
 * in the process that can: the server holds the public half and cannot read
 * what it stored, which is the property the whole archive rests on.
 */
export function archiveOpener(): Opener | null {
  return opener
}

/**
 * connection exposes the open socket to the console.
 *
 * One socket for both screens rather than a second one for administration: the
 * server counts connections, a second handshake would spend another password
 * verification, and two sockets on one credential drift apart on a reconnect.
 *
 * Null while reconnecting, which callers have to handle — the console is a
 * screen somebody can be sitting on when the server restarts.
 */
export function connection(): Connection | null {
  return conn && conn.isOpen ? conn : null
}

/**
 * credential exposes how this session reaches the server.
 *
 * Only for the console, which has to make one call outside the websocket:
 * re-deriving the account key to seal a grant. The archive key itself is not
 * exposed and never will be — nothing outside this module holds a reference.
 */
export function credential(): { serverURL: string; kind: string; token: string } | null {
  if (!session) return null
  return {
    serverURL: session.serverURL,
    kind: session.credential.kind,
    token: session.credential.token,
  }
}

/** readableDevices is what this session holds a key for, by device id. */
export function readableDevices(): Set<string> {
  void state.accessRevision
  return new Set(session?.readable.map((r) => r.deviceID) ?? [])
}

/** Reloads the current identity's key envelopes without crossing a workspace or
 * connection change while the HTTP request and decryptions are in flight. */
export async function refreshCurrentAccess(): Promise<boolean> {
  const capturedSession = session
  const capturedConnection = conn
  const capturedTenant = state.tenantID
  if (!capturedSession?.refreshAccess) return false
  const previousKeys = new Map(capturedSession.readable.map(device => [device.deviceID, capturedSession.archiveFor(device.deviceID)]))
  await capturedSession.refreshAccess()
  if (session !== capturedSession || conn !== capturedConnection || state.tenantID !== capturedTenant) return false
  state.accessRevision++
  if (state.deviceID && !capturedSession.archiveFor(state.deviceID)) {
    archiveGeneration++; conversationGeneration++; timelineGen++
    clearDeviceState()
    opener = null; openerDeviceID = ''
    state.unreadable = true
    applyReceiptMode('passive')
  } else if (state.deviceID && previousKeys.get(state.deviceID) !== capturedSession.archiveFor(state.deviceID)) {
    // A replacement grant for this same number must replace the opener too;
    // its cache and archive private key are both bound to the old envelope.
    opener = null; openerDeviceID = ''
    openerFor(state.deviceID)
  } else if (state.deviceID && state.unreadable) {
    openerFor(state.deviceID)
  }
  return true
}

function devicePreferenceScope(): DevicePreferenceScope | null {
  const account = session?.account
  if (!session || session.credential.kind !== 'session' || !account?.userID || account.tenantID !== state.tenantID) return null
  try { return { serverOrigin: origin(session.serverURL).origin, userID: account.userID, workspaceID: state.tenantID } }
  catch { return null }
}

/** Preference is only a hint within the latest server list and readable grants. */
export function preferredReadableDevice(currentFirst = false): P.DeviceInfo | undefined {
  if (!session) return undefined
  const readable = readableDevices()
  const canOpen = (device: P.DeviceInfo) => session?.credential.kind === 'api_key' || readable.has(device.id)
  const candidates = state.devices.filter(canOpen)
  const query = typeof location === 'undefined' ? null : new URLSearchParams(location.search)
  const requested = !query?.get('workspace') || query.get('workspace') === state.tenantID ? query?.get('device') : null
  const remembered = readLastDevice(devicePreferenceScope())
  const current = candidates.find(device => device.id === state.deviceID)
  const linked = candidates.find(device => device.id === requested)
  return (currentFirst ? current ?? linked : linked ?? current) ??
    candidates.find(device => device.id === remembered) ??
    candidates.find(device => device.running) ?? candidates[0]
}

function rememberCurrentDevice(): void {
  rememberLastDevice(devicePreferenceScope(), state.deviceID)
  setWorkspaceDeviceURL(state.tenantID, state.deviceID)
}

/**
 * refreshDevices re-reads the device list without reconnecting.
 *
 * Called after pairing or deleting, so the reader and the console agree about
 * what exists. If the open device is gone, the reader falls back the same way
 * it does on connect.
 */
export async function refreshDevices(): Promise<void> {
  const capturedConnection = conn
  const capturedSession = session
  const capturedTenant = state.tenantID
  if (!capturedConnection) return
  const devices = await capturedConnection.request<P.Devices>(P.TypeDevicesList, {}, P.TypeDevices)
  if (conn !== capturedConnection || session !== capturedSession || state.tenantID !== capturedTenant) return
  state.devices = devices.devices ?? []
  const current = state.devices.find((d) => d.id === state.deviceID)
  if (state.deviceID && !current) {
    state.deviceID = ''
    state.chats = []
    state.timeline = []
    state.openChatKey = ''
    opener = null
    openerDeviceID = ''
    return
  }
  // A fresh listing is the server's current word on the posture, and another
  // browser may have changed it since this one asked. The list is where the
  // switch used to read from directly; now it reads the same flag the gates
  // and the palette do, so the listing has to feed that flag.
  if (current) applyDeviceReceiptMode(current)
}

export function currentMedia(): Media | null {
  return media
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

export async function start(open: Session): Promise<void> {
  session = open
  if (open.account?.tenantID === '00000000-0000-0000-0000-000000000000') {
    state.phase = 'ready'; state.view = 'admin'; state.account = open.account.email; state.role = '';
    state.tenantID = open.account.tenantID; state.label = open.label; state.hasRecovery = open.account.hasRecovery; return
  }
  stopped = false
  attempt = 0
  state.phase = 'connecting'
  state.error = ''
  state.label = open.label
  state.hasRecovery = open.account?.hasRecovery ?? false
  await connect()
}

/**
 * rotateCredential swaps the session token after a password change.
 *
 * The change revokes every session, including this one; the server answers
 * with a fresh token, and everything that authenticates from here on — the
 * next reconnect, the media endpoint — has to use it. The socket already open
 * stays open: it was authenticated when it was opened.
 */
export async function rotateCredential(token: string, expiresAt?: Date): Promise<void> {
  if (!session || session.credential.kind !== 'session') return
  session.credential.token = token
  if (expiresAt) await session.rotate?.(token, expiresAt)
}

/** recoverySet records that the account now holds a redeemable code. */
export function recoverySet(): void {
  if (session?.account) session.account.hasRecovery = true
  state.hasRecovery = true
}

/**
 * connect opens the socket and loads what the client needs to draw.
 *
 * Called again on every reconnect, so it must be safe to repeat: the opener
 * keeps its unwrapped content keys, the chat list and contacts are reloaded
 * because they may have moved on, and an open conversation is re-read from the
 * archive because the live traffic that happened while the socket was down was
 * missed.
 */
async function connect(): Promise<void> {
  if (!session || stopped) return
  const open = session
  const generation = ++archiveGeneration
  const initializing = ++connectionAttempt
  state.initializingConnection = true
  const resuming = state.phase === 'ready'
  const reopen = state.openChatKey
  let openedConnection: Connection | null = null

  try {
    const connected = await Connection.connect({
      serverURL: open.serverURL,
      credential: open.credential,
      clientID: 'web',
      onFrame: (frame) => {
        if (openedConnection && conn === openedConnection && session === open && !stopped) void handleFrame(frame)
      },
      onClose: (reason) => {
        if (stopped || session !== open || (openedConnection && conn !== openedConnection)) return
        state.connected = false
        forgetPresence()
        state.closedReason = reason
        if (state.phase !== 'connecting') scheduleReconnect()
      },
    })
    if (stopped || session !== open || generation !== archiveGeneration) {
      connected.close()
      return
    }
    conn = connected
    openedConnection = connected

    attempt = 0
    clearCountdown()
    state.reconnectIn = 0
    state.tenantID = conn.welcome.tenant_id
    state.account = conn.welcome.account ?? ''
    state.role = conn.welcome.role ?? ''
    state.connected = true
    state.closedReason = ''

    tenantBytes = parseUUID(conn.welcome.tenant_id)
    media ??= new Media(open.serverURL, open.credential.token)

    const devices = await conn.request<P.Devices>(P.TypeDevicesList, {}, P.TypeDevices)
    if (stopped || session !== open || generation !== archiveGeneration) return
    state.devices = devices.devices ?? []
    const previousDevice = state.deviceID
    const preferred = preferredReadableDevice(resuming)
    const consoleRoute = typeof location !== 'undefined' && (location.hostname === 'console.wappie.thehappie.co' || location.pathname.startsWith('/console'))
    if (!preferred || consoleRoute) {
      // Not an error: a tenant with no devices is a tenant that has not paired
      // one yet, and there is now a screen for doing that.
      clearDeviceState()
      opener = null; openerDeviceID = ''
      state.phase = 'ready'
      state.deviceID = ''
      state.view = 'admin'
      return
    }

    if (previousDevice && previousDevice !== preferred.id) {
      conversationGeneration++; timelineGen++; clearDeviceState()
    }
    state.deviceID = preferred.id
    // The posture follows the device the moment it is chosen, here as well as
    // in selectDevice. This call was missing, and the gap showed: `quiet`
    // starts true so that a device whose posture is not yet known emits nothing,
    // and nothing here corrected it — so a loud device booted with a dark
    // palette, a switch drawn from the device row saying the opposite, and gates
    // that agreed with neither until somebody toggled.
    applyDeviceReceiptMode(preferred)
    openerFor(preferred.id)
    // A large address book must not delay the conversation list. Names enrich
    // the already-visible rows when their independent request finishes.
    void loadContacts().catch(() => {})
    await loadChats()
    if (stopped || generation !== archiveGeneration) return

    // Live only. Replaying from zero would stream the whole archive down this
    // socket before the first chat drew, and the pages already have the history.
    conn.send(P.TypeSubscribe, 'live', { since_seq: 0, live_only: true } satisfies P.Subscribe)
    state.phase = 'ready'
    rememberCurrentDevice()

    // Look again at what an older build could not read, now that the key is in
    // hand. Not awaited: it is housekeeping, and the conversation list is
    // already on screen.
    void sweepUnsupported()

    if (reopen && previousDevice === preferred.id) await openChat(reopen)
  } catch (err) {
    if (stopped || session !== open || generation !== archiveGeneration) return
    // Initialization includes devices, chat pages and content keys. A failure
    // after welcome must leave the spinner and close this incomplete socket.
    const message = err instanceof Error ? err.message : String(err)
    openedConnection?.close()
    conn = null
    archiveGeneration++
    directoryLoading = null
    state.connected = false
    if (retryTimer) clearTimeout(retryTimer)
    retryTimer = undefined
    clearCountdown()
    state.reconnectIn = 0
    const refused = err instanceof ProtocolError && err.code === P.ErrUnauthorized
    if (!resuming || refused) {
      state.phase = 'error'
      state.error = message
      return
    }
    state.closedReason = message
    scheduleReconnect()
  } finally {
    if (initializing === connectionAttempt) state.initializingConnection = false
  }
}

/**
 * scheduleReconnect backs off and tries again.
 *
 * A dropped socket used to leave the client showing a close code and nothing
 * else until someone reloaded the page — which reads as the archive having
 * stopped working. Backoff rather than a tight loop, because the usual reason
 * the server is unreachable is that it is restarting.
 */
function scheduleReconnect(): void {
  if (stopped || retryTimer) return
  attempt += 1
  const seconds = Math.min(30, 2 ** Math.min(attempt, 5))
  state.reconnectIn = seconds

  clearCountdown()
  countdown = setInterval(() => {
    state.reconnectIn = Math.max(0, state.reconnectIn - 1)
  }, 1000)

  retryTimer = setTimeout(() => {
    retryTimer = undefined
    void connect()
  }, seconds * 1000)
}

function clearCountdown(): void {
  if (countdown) clearInterval(countdown)
  countdown = undefined
}

export function stop(options?: { logout?: boolean; transitioning?: boolean }): void {
  stopped = true
  connectionAttempt++
  archiveGeneration++
  conversationGeneration++
  timelineGen++
  directoryLoading = null
  // Best effort, and not awaited: the session is being torn down either way,
  // and a revocation that fails still expires on its own.
  if (options?.logout !== false) { clearWorkspaceDeviceURL(); void session?.close() }
  else session?.dispose?.()
  session = null
  if (retryTimer) clearTimeout(retryTimer)
  retryTimer = undefined
  clearCountdown()
  conn?.close()
  media?.release()
  for (const url of avatars.values()) URL.revokeObjectURL(url)
  avatars.clear()
  forgetPresence()
  avatarsAsked.clear()
  namesAsked.clear()
  pendingNames.clear()
  if (resolveTimer) clearTimeout(resolveTimer)
  resolveTimer = undefined
  directory.clear()
  // Messages this tab sent and had not seen come back. They belong to the
  // session that sent them; left here they would reappear as pending lines in
  // whatever conversation opened next.
  outbox.clear()
  clearPreviews()
  conn = null
  opener = null
  openerDeviceID = ''
  media = null
  openRows = []
  // The receipts belong to the rows that were held. Keeping them would
  // grow the map for the life of the tab and would draw ticks for a
  // conversation nobody is looking at.
  forgetReceipts()
  Object.assign(state, {
    // A workspace navigation disposes this workspace without signing out.
    // Keep the loading screen visible until the next document restores it.
    phase: options?.transitioning && options.logout === false ? 'connecting' : 'locked',
    tenantID: '',
    deviceID: '',
    selectedUID: '',
    view: 'archive',
    account: '',
    role: '',
    hasRecovery: false,
    devices: [],
    chats: [],
    timeline: [],
    openChatKey: '',
    history: null,
    contactsLoaded: 0,
    openChatName: '',
    loadingChat: false,
    loadingOlder: false,
    historyLoading: false,
    groupPanel: false,
    connected: false,
    initializingConnection: false,
    closedReason: '',
    reconnectIn: 0,
  })
}

export async function selectDevice(deviceID: string): Promise<void> {
  if (!session || !state.devices.some((device) => device.id === deviceID)) return
  if (state.initializingConnection || !conn?.isOpen) {
    throw new Error(t('Aguarde a reconexão antes de trocar de dispositivo.'))
  }
  if (session.credential.kind === 'session' && !session.readable.some((device) => device.deviceID === deviceID)) return
  archiveGeneration++
  conversationGeneration++
  timelineGen++
  state.deviceID = deviceID
  // The gates follow the device, not the session: two devices of one account
  // can be in different postures, and carrying one's over to the other would
  // start emitting receipts from a device somebody had set to stay quiet.
  applyDeviceReceiptMode(state.devices.find((d) => d.id === deviceID))
  clearDeviceState()
  openerFor(deviceID)
  const context = archiveContext()
  void loadContacts().catch(() => {})
  try {
    await loadChats()
    if (context && currentArchive(context)) { rememberCurrentDevice(); void sweepUnsupported() }
  } catch (err) {
    if (!context || !currentArchive(context)) return
    state.chats = []
    state.loadingChat = false
    state.loadingOlder = false
    state.actionError = err instanceof Error ? err.message : String(err)
    throw err
  }
}

function clearDeviceState(): void {
  state.chats = []
  state.timeline = []
  state.openChatKey = ''
  state.openChatName = ''
  state.selectedUID = ''
  state.history = null
  state.historyLoading = false
  state.groupPanel = false
  state.contactsLoaded = 0
  state.loadingChat = false
  state.loadingOlder = false
  state.hasOlder = false
  state.actionError = ''
  state.unsupported = { total: 0, byField: {}, running: false }
  openRows = []
  olderCursor = null
  forgetReceipts()
  forgetPresence()
  media?.release()
  clearPreviews()
  for (const url of avatars.values()) URL.revokeObjectURL(url)
  avatars.clear()
  directory.clear()
  avatarsAsked.clear()
  namesAsked.clear()
  pendingNames.clear()
  if (resolveTimer) clearTimeout(resolveTimer)
  resolveTimer = undefined
}

/**
 * openerFor points the opener at one account.
 *
 * Rebuilt rather than reused when the device changes: the archive key is per
 * device, so a cache of content keys unwrapped for one account cannot open
 * anything belonging to another. Reconnecting to the same device keeps the
 * cache, which is what rebind is for.
 */
function openerFor(deviceID: string): void {
  if (!conn || !tenantBytes || !session) return
  if (opener && openerDeviceID === deviceID) {
    opener.rebind(conn)
    return
  }
  const archive = session.archiveFor(deviceID)
  if (!archive) {
    // No grant for this account. Not an error and not a blank screen: the
    // conversation list still draws, and every sealed value reports that the
    // key is unavailable — which is the truth.
    opener = null
    openerDeviceID = ''
    state.unreadable = true
    return
  }
  state.unreadable = false
  opener = new Opener(conn, tenantBytes, parseUUID(deviceID), deviceID, archive)
  openerDeviceID = deviceID
}

// ---------------------------------------------------------------------------
// Contacts and chats
// ---------------------------------------------------------------------------

async function loadContacts(): Promise<void> {
  const context = archiveContext()
  if (!context) return
  directoryLoading = context.generation
  try {
    const reply = await context.connection.request<P.Contacts>(
      P.TypeContacts,
      { device_id: context.deviceID },
      P.TypeContactList,
    )
    if (!currentArchive(context)) return
    await absorb(reply.contacts ?? [], context)
  } finally {
    if (currentArchive(context)) {
      directoryLoading = null
      applyNames()
      for (const chat of state.chats) if (!chat.isStatus) wantIdentity(chat.key)
    }
  }
}

/** absorb opens a batch of contact rows and files them in the directory. */
async function absorb(rows: P.ContactSummary[], context = archiveContext()): Promise<void> {
  if (!context || !currentArchive(context) || rows.length === 0) return
  await context.open.prefetch(rows.map((c) => c.content_key_id))

  // Bounded batches keep WebCrypto busy without queueing thousands of jobs
  // on a phone. A generation check surrounds every asynchronous batch.
  for (let offset = 0; offset < rows.length; offset += 24) {
    if (!currentArchive(context)) return
    const opened = await Promise.all(rows.slice(offset, offset + 24).map(async (contact) => ({
      contact, names: await context.open.contactNames(contact),
    })))
    if (!currentArchive(context)) return
    for (const { contact, names } of opened) {
      const person: Person = {
        key: contact.contact_key,
        uid: contact.uid,
        lid: contact.contact_lid,
        pn: contact.contact_pn,
        isGroup: Boolean(contact.is_group),
        full: names.full.state === 'ok' ? names.full.value : '',
        business: names.business.state === 'ok' ? names.business.value : '',
        push: names.push.state === 'ok' ? names.push.value : '',
        hasAvatar: Boolean(contact.has_avatar),
        avatarKeyID: contact.avatar_key_id,
        tampered:
          names.full.state === 'tampered' ||
          names.business.state === 'tampered' ||
          names.push.state === 'tampered',
      }
      directory.add(person)
    }
  }
  state.contactsLoaded = directory.size
}

/**
 * renameTo decides whether a learned contact name replaces a row's label.
 *
 * Pulled out and exported because both of its conditions were wrong once, in
 * ways nothing failed on.
 *
 * The first: the caller must pass knownName, which is empty when nobody has a
 * name, and not nameFor, which falls back to a rendered identifier and is
 * therefore never empty. Guarded on nameFor this rewrote every direct
 * conversation to a phone number a tenth of a second after the list drew —
 * replacing names with numbers, which is the precise defect the surrounding
 * feature exists to remove, arriving as its side effect.
 *
 * The second: a conversation that carries a sealed name of its own keeps it.
 * toChatView prefers that name over a contact's, so overriding it here would
 * make the two disagree and the list would say one thing on load and another a
 * moment later, for no reason a reader could see.
 *
 * Returns null to leave the row alone.
 */
export function renameTo(
  chat: Pick<ChatView, 'name' | 'nameState' | 'isGroup' | 'isStatus'>,
  known: string,
): string | null {
  if (chat.isStatus || chat.isGroup) return null
  if (chat.nameState === 'ok') return null
  if (!known || known === chat.name) return null
  return known
}

/**
 * applyNames pushes newly learned names into what is already on screen.
 *
 * The directory is a plain Map and is deliberately not reactive: it holds five
 * thousand people and making every one of them a reactive object to catch the
 * handful that change would be a poor trade. The consequence is that a name
 * learned after a row was drawn changes nothing by itself, so the rows have to
 * be told. Without this the whole resolve path works perfectly and the reader
 * still sees a LID until the tab is reloaded — the exact bug it exists to fix.
 */
function applyNames(): void {
  for (const chat of state.chats) {
    const next = renameTo(chat, directory.knownName(chat.key))
    if (next) chat.name = next
  }
  if (state.openChatKey) {
    const open = state.chats.find((c) => c.key === state.openChatKey)
    if (open) state.openChatName = open.name
  }
  // Senders inside the open conversation. Rebuilt rather than patched: a line's
  // name is one of several things derived from the same row, and two places
  // deriving it is how they come to disagree.
  if (state.timeline.length > 0) void redrawTimeline()
}

/**
 * wantIdentity says a name is about to be drawn for an identifier nobody here
 * can name.
 *
 * Called from the render path and returns immediately: the draw goes ahead with
 * the fallback, and if a name arrives the directory changes and Vue redraws the
 * row on its own. That is the whole fix for a sidebar that showed a LID until
 * the tab was reloaded — the contact list is loaded once at sign-in, and every
 * conversation that starts after it was permanently nameless.
 */
export function wantIdentity(primary: string | undefined, ...aliases: (string | undefined)[]): void {
  if (directoryLoading === archiveGeneration) return
  // Known under any of its identifiers means known. A contact row carries only
  // the half it was learned under, so a person saved by phone number is a miss
  // when looked up by LID, and asking again would be asking about somebody the
  // directory can already name.
  for (const alias of [primary, ...aliases]) {
    if (alias && directory.isKnown(alias)) return
  }
  // Only the primary is enqueued, and that matters on the server rather than
  // here: a key nothing has a row for gets one created, so enqueueing the LID
  // and the phone number of one person would ask the archive to hold two rows
  // for them — and hand the picture worker two faces to fetch, which is two
  // questions over the device's own socket for one person.
  const key = primary || aliases.find(Boolean)
  if (!key || askedRecently(namesAsked, key)) return
  pendingNames.add(key)
  if (resolveTimer) return
  resolveTimer = setTimeout(() => {
    resolveTimer = undefined
    void flushIdentities()
  }, RESOLVE_DEBOUNCE_MS)
}

/**
 * How many identifiers one request may carry.
 *
 * The server caps at the same number and drops the tail in silence. Capping
 * here as well, and leaving the remainder queued, is what stops the tail being
 * dropped for good: marking a key as asked before it has actually gone means a
 * key past the cap is never asked and never asked again, and since the queue
 * rebuilds in the same order it is always the same keys that lose.
 */
const RESOLVE_MAX = 200

async function flushIdentities(): Promise<void> {
  // Nothing to send through. The queue is left exactly as it is and nothing is
  // marked as asked — the reconnect redraws the list, which asks again. Draining
  // it here would be the same defect the stamping order below exists to avoid,
  // arriving through the one door that is open precisely when the request
  // cannot be made.
  const context = archiveContext()
  if (!context) return

  const keys = [...pendingNames].slice(0, RESOLVE_MAX)
  if (keys.length === 0) return
  for (const key of keys) pendingNames.delete(key)
  // Stamped here, not when queued: a key is "asked" once it has actually left.
  const now = Date.now()
  for (const key of keys) namesAsked.set(key, now)
  // Whatever did not fit goes out on the next tick rather than being forgotten.
  if (pendingNames.size > 0 && !resolveTimer) {
    resolveTimer = setTimeout(() => {
      resolveTimer = undefined
      void flushIdentities()
    }, RESOLVE_DEBOUNCE_MS)
  }
  try {
    const before = directory.size
    const reply = await context.connection.request<P.Contacts>(
      P.TypeResolve,
      { device_id: context.deviceID, contact_keys: keys } satisfies P.ContactsResolveRequest,
      P.TypeContactList,
    )
    if (!currentArchive(context)) return
    await absorb(reply.contacts ?? [], context)
    if (!currentArchive(context)) return
    if (directory.size !== before || (reply.contacts ?? []).length > 0) applyNames()
  } catch {
    // Nothing to report. The rows are already drawn with the fallback, and a
    // failed lookup is the same outcome as an identifier nobody has a name for
    // — which is an ordinary thing for a LID to be.
  }
}

/**
 * refreshChats re-reads the sidebar.
 *
 * For the moments when a conversation appears without a message arriving in it
 * — joining a group is the one that exists today. The list is otherwise built
 * once at sign-in and kept current by traffic, so a group joined in silence
 * stays invisible until somebody speaks in it.
 */
export async function refreshChats(): Promise<void> {
  await loadChats()
}

export async function loadChats(): Promise<void> {
  const context = archiveContext()
  if (!context) return
  const generation = ++chatsGeneration
  const current = () => currentArchive(context) && generation === chatsGeneration
  const reply = await context.connection.request<P.Chats>(
    P.TypeChatsList,
    { device_id: context.deviceID },
    P.TypeChats,
  )
  if (!current()) return
  const rows = reply.chats ?? []
  // Preview bodies often use different keys from group names. Omitting them
  // made each distinct preview key pay another sequential network round trip.
  await context.open.prefetch(rows.flatMap((c) => [c.name_key_id, c.last_body_key_id]))

  const decrypted: Array<{ chat: P.ChatSummary; name: Opened<string>; preview: Opened<string> }> = []
  for (let offset = 0; offset < rows.length; offset += 24) {
    if (!current()) return
    const opened = await Promise.all(rows.slice(offset, offset + 24).map(async (chat) => ({
      chat, values: await Promise.all([context.open.chatName(chat), context.open.chatPreview(chat)]),
    })))
    if (!current()) return
    for (const { chat, values: [name, preview] } of opened) decrypted.push({ chat, name, preview })
  }
  if (!current()) return
  // Contacts can finish between decryption batches. Resolve names and enqueue
  // unknown identities at publication time, against the current directory.
  state.chats = decrypted.map(({ chat, name, preview }) => toChatView(chat, name, preview)).sort(byRecency)
}

function toChatView(
  chat: P.ChatSummary,
  name: Opened<string>,
  preview: Opened<string>,
): ChatView {
  const status = isStatus(chat.chat_key)
  // The live and history paths disagree about whether status is a group —
  // whatsmeow says yes, the history importer says no — and neither answer is
  // useful, because it is not a conversation at all.
  const group = !status && (Boolean(chat.is_group) || isGroup(chat.chat_key))
  // A chat name is only stored for groups; for a person the name lives on the
  // contact, under whichever of their two identifiers this row carries.
  const resolved = status
    ? 'Status'
    : name.state === 'ok' && name.value
      ? name.value
      : group
        ? displayFallback(chat.chat_key)
        : personName(chat.chat_lid, chat.chat_pn, chat.chat_key)

  // Nothing names this row, so ask. Groups included: a group carries its name
  // on the chat, but its picture hangs on a contact row, and a group whose
  // history sync never named it has neither.
  if (!status && (group ? name.state !== 'ok' || !name.value : !directory.isKnown(chat.chat_key))) {
    wantIdentity(chat.chat_key, chat.chat_lid, chat.chat_pn)  // primary, then aliases
  }

  return {
    key: chat.chat_key,
    keys: chat.keys?.length ? chat.keys : [chat.chat_key],
    uid: chat.uid,
    isGroup: group,
    isStatus: status,
    name: resolved,
    nameState: stateOf(name),
    lastSeq: chat.last_seq,
    lastTS: chat.last_ts ? new Date(chat.last_ts) : undefined,
    createdAt: chat.created_at ? new Date(chat.created_at) : undefined,
    groupCreatedAt: chat.group_created_at ? new Date(chat.group_created_at) : undefined,
    lastKind: chat.last_kind ?? '',
    lastType: chat.last_type ?? '',
    unread: chat.unread ?? 0,
    pinned: Boolean(chat.pinned),
    archived: Boolean(chat.archived),
    preview: preview.state === 'ok' ? preview.value : '',
    previewState: stateOf(preview),
    ephemeral: chat.ephemeral ?? 0,
    audience: chat.audience,
    avatarKey: chat.chat_key,
  }
}

export function byRecency(a: ChatView, b: ChatView): number {
  if (a.pinned !== b.pinned) return a.pinned ? -1 : 1
  // One key for everything: the newest message if there is one, otherwise when
  // the group was MADE. A group is a conversation from the moment the account
  // is in it, and a group created yesterday belongs where yesterday belongs —
  // not below every conversation last spoken in two years ago, which is where
  // a separate bucket for the quiet ones put it.
  //
  // Ordered by when a message was SENT, never by insertion order: keying off
  // that put a conversation at the top because a backfill had just written a
  // piece of its history.
  const at = a.lastTS?.getTime() ?? a.groupCreatedAt?.getTime()
  const bt = b.lastTS?.getTime() ?? b.groupCreatedAt?.getTime()
  if (at !== bt) {
    if (at === undefined) return 1
    if (bt === undefined) return -1
    return bt - at
  }
  // Neither has a date that means anything. Newest row first, which is the
  // only thing left, and deliberately last in the comparison: it is when this
  // archive wrote the row, and for the groups a boot sync found that is one
  // instant for all of them.
  const ac = a.createdAt?.getTime() ?? 0
  const bc = b.createdAt?.getTime() ?? 0
  if (ac !== bc) return bc - ac
  return b.lastSeq - a.lastSeq
}

/**
 * avatarFor fetches and opens one profile picture, once.
 *
 * Pictures are not in the chat list on purpose: a thousand contacts with a
 * picture each is tens of megabytes, and a list needs the names now and the
 * faces as it draws them.
 */
export async function avatarFor(contactKey: string): Promise<void> {
  const context = archiveContext()
  if (!context || !contactKey) return
  if (avatars.has(contactKey) || askedRecently(avatarsAsked, contactKey, AVATAR_ASK_AGAIN_MS)) {
    return
  }
  avatarsAsked.set(contactKey, Date.now())
  await avatarQueue(() => fetchAvatar(contactKey, context))
}

/**
 * How many pictures may be in flight at once.
 *
 * There was no limit, and it worked while the sidebar held a few hundred rows.
 * Every badge asks as it mounts, so the moment the list grew to sixteen hundred
 * the tab opened sixteen hundred simultaneous requests against a server whose
 * API pool is sixteen connections. Most of them sat in a queue past the twenty
 * second timeout, the failure was swallowed, and — the part that made it stick
 * — each one had already been marked as asked, so nothing retried for ten
 * minutes. What a person saw was photographs that used to be there and were
 * not any more.
 *
 * Six is comfortably above the round trip and far below anything that queues.
 */
export const AVATAR_IN_FLIGHT = 6

let avatarActive = 0
const avatarWaiting: Array<() => void> = []

/** avatarQueue runs work with at most AVATAR_IN_FLIGHT of it at a time. */
async function avatarQueue(work: () => Promise<void>): Promise<void> {
  if (avatarActive >= AVATAR_IN_FLIGHT) {
    await new Promise<void>((resume) => avatarWaiting.push(resume))
  }
  avatarActive++
  try {
    await work()
  } finally {
    avatarActive--
    avatarWaiting.shift()?.()
  }
}

async function fetchAvatar(contactKey: string, context: ArchiveContext): Promise<void> {
  if (!currentArchive(context)) return
  try {
    const frame = await context.connection.request<P.Avatar>(
      P.TypeAvatar,
      { device_id: context.deviceID, contact_key: contactKey } satisfies P.AvatarRequest,
      P.TypeAvatarFrame,
    )
    if (!currentArchive(context) || !frame.sealed) return
    const opened = await context.open.avatar(frame)
    if (!currentArchive(context) || opened.state !== 'ok') return
    avatars.set(contactKey, URL.createObjectURL(new Blob([opened.value as BlobPart], { type: 'image/jpeg' })))
  } catch (err) {
    // A contact with no picture answers not_found, which is ordinary. A
    // timeout is not: it means the request never got an answer, and leaving it
    // marked as asked would make a transient failure look like a contact with
    // no face for the next ten minutes. Forgetting it lets the next draw try.
    if (currentArchive(context) && !(err instanceof ProtocolError)) avatarsAsked.delete(contactKey)
  }
}

// ---------------------------------------------------------------------------
// One conversation
// ---------------------------------------------------------------------------

/** A fence for navigation that may span several older-page requests. */
export function conversationPagingContext(): { current: () => boolean; cursor: () => string | null } | null {
  const context = archiveContext()
  if (!context || !state.openChatKey) return null
  const generation = conversationGeneration
  const chatKey = state.openChatKey
  const view = state.view
  const tenantID = state.tenantID
  return {
    current: () => currentArchive(context) && generation === conversationGeneration &&
      state.openChatKey === chatKey && state.tenantID === tenantID && state.view === view,
    cursor: () => olderCursor ? JSON.stringify([olderCursor.ts, olderCursor.seq]) : null,
  }
}

export interface OlderPageProgress {
  status: 'loaded' | 'idle' | 'stale'
  before?: string
  after?: string | null
}

export async function openChat(chatKey: string): Promise<void> {
  const context = archiveContext()
  if (!context) return
  const generation = ++conversationGeneration
  const current = () => currentArchive(context) && generation === conversationGeneration && state.openChatKey === chatKey
  timelineGen++
  state.openChatKey = chatKey
  state.openChatName = state.chats.find((c) => c.key === chatKey)?.name ?? chatKey
  state.selectedUID = ''
  state.history = null
  state.loadingChat = true
  state.loadingOlder = false
  state.hasOlder = false
  state.timeline = []
  openRows = []
  forgetReceipts()
  olderCursor = null

  try {
    const page = await context.connection.request<P.Page>(
      P.TypeChatPage,
      { device_id: context.deviceID, chat_key: chatKey, limit: PAGE_SIZE } satisfies P.ChatPageRequest,
      P.TypePage,
    )
    if (!current()) return
    openRows = page.messages ?? []
    absorbReceipts(page.receipts)
    state.hasOlder = page.has_more
    olderCursor = page.next_ts ? { ts: page.next_ts, seq: page.next_seq ?? 0 } : null
    await redraw()
  } catch (err) {
    if (current()) state.error = err instanceof Error ? err.message : String(err)
  } finally {
    if (current()) state.loadingChat = false
  }
}

export async function loadOlder(): Promise<OlderPageProgress> {
  const context = archiveContext()
  if (!context || !state.hasOlder || state.loadingOlder || !olderCursor) return { status: 'idle' }
  const generation = conversationGeneration
  const chatKey = state.openChatKey
  const current = () => currentArchive(context) && generation === conversationGeneration && state.openChatKey === chatKey
  const before = JSON.stringify([olderCursor.ts, olderCursor.seq])

  state.loadingOlder = true
  try {
    const page = await context.connection.request<P.Page>(
      P.TypeChatPage,
      {
        device_id: context.deviceID,
        chat_key: state.openChatKey,
        before_ts: olderCursor.ts,
        before_seq: olderCursor.seq,
        limit: PAGE_SIZE,
      } satisfies P.ChatPageRequest,
      P.TypePage,
    )
    if (!current()) return { status: 'stale' }
    openRows = [...(page.messages ?? []), ...openRows]
    absorbReceipts(page.receipts)
    state.hasOlder = page.has_more
    olderCursor = page.next_ts ? { ts: page.next_ts, seq: page.next_seq ?? 0 } : null
    await redraw()
    if (!current()) return { status: 'stale' }
    return { status: 'loaded', before, after: olderCursor ? JSON.stringify([olderCursor.ts, olderCursor.seq]) : null }
  } finally {
    if (current()) state.loadingOlder = false
  }
}

async function buildTimeline(rows: P.SealedMessage[]): Promise<MessageView[]> {
  const context = archiveContext()
  if (!context) return []
  // Every key the page needs, in one round trip, before anything is opened.
  await context.open.prefetch(rows.map((r) => r.content_key_id))
  if (!currentArchive(context)) return []

  const { entries } = project(rows)
  const views: MessageView[] = []
  const archived = new Set<string>()
  for (const entry of entries) {
    const view = await toMessageView(entry, context)
    if (!currentArchive(context)) return []
    if (view) views.push(view)
    archived.add(entry.row.wa_id)
  }

  // Anything the archive has now caught up with stops being pending: the real
  // row is in the list above, and leaving the optimistic copy would show the
  // message twice.
  for (const id of archived) outbox.delete(id)
  // Only the ones belonging here. The outbox is a session-wide map, and
  // without this filter a message still on its way out follows the reader into
  // whatever conversation they open next — which for an attachment also means
  // an upload in flight rendering into a chat it has nothing to do with.
  for (const line of outbox.values()) {
    const from = line.entry.row
    // Both, because a chat key is not unique across devices: two paired
    // accounts in the same group have the same one. Scoping on the chat alone
    // shows a message sent from one device inside another device's view of it,
    // where nothing will ever arrive to reap it.
    if (inOpenChat(from.chat_key) && from.device_id === state.deviceID) {
      views.push(line)
    }
  }
  return views
}

/**
 * redraw rebuilds the open conversation, discarding its own result if another
 * rebuild started while it was fetching keys.
 */
export async function redrawTimeline(): Promise<void> {
  await redraw()
}

async function redraw(): Promise<void> {
  const gen = ++timelineGen
  const chatKey = state.openChatKey
  const next = await buildTimeline(openRows)
  if (gen === timelineGen && state.openChatKey === chatKey) state.timeline = next
}

/**
 * personName resolves somebody who has two identifiers and might be known under
 * either.
 *
 * A message carries both halves — whatsmeow merges SenderAlt — but a contact row
 * carries only the one it was learned under, so a person saved by phone number
 * is a miss when looked up by LID. The lookup used to try the LID alone and then
 * hand that same LID to the fallback, which prints "contato sem número" for a
 * person whose number is sitting in the next column.
 *
 * So: try both identifiers, and when neither has a name, describe them by
 * whichever identifier actually says something. A phone number is a worse label
 * than a name and a far better one than "contato sem número".
 */
function personName(lid: string | undefined, pn: string | undefined, fallbackKey: string): string {
  // knownName, not nameFor. nameFor falls back to a rendered identifier and is
  // therefore never empty, so `nameFor(lid) || nameFor(pn)` returns "LID 4263…"
  // for a LID nobody has named and never reaches pn at all — defeating the
  // "try both identifiers" this function exists for, and, once there was one,
  // making the ask below unreachable.
  const named = directory.knownName(lid) || directory.knownName(pn) || directory.knownName(fallbackKey)
  if (named) return named
  // About to draw an identifier at somebody. Ask who it is; the row redraws if
  // an answer comes back.
  // fallbackKey is the sender key, which is what a contact row is keyed on;
  // the two halves are aliases used only to decide we do not already know them.
  wantIdentity(fallbackKey || lid || pn, lid, pn)
  if (pn) return displayFallback(pn)
  return displayFallback(lid || fallbackKey)
}

/**
 * revisionsOf keys a reader's per-version record by revision.
 *
 * A Map rather than an array, because every consumer is asking about one
 * revision it already knows the number of, and an array invites indexing by
 * position — which is the same number only until a version is missing from the
 * middle, and then it is somebody else's delivery time under the wrong heading.
 */
export function revisionsOf(
  rows: P.ReaderRevision[] | undefined,
): Map<number, ReaderRevisionView> {
  const out = new Map<number, ReaderRevisionView>()
  for (const r of rows ?? []) {
    out.set(r.revision, {
      revision: r.revision,
      delivered: r.delivered ? new Date(r.delivered) : undefined,
      read: r.read ? new Date(r.read) : undefined,
      played: r.played ? new Date(r.played) : undefined,
      confirmed: Boolean(r.confirmed),
      playedConfirmed: Boolean(r.played_confirmed),
    })
  }
  return out
}

/**
 * tallyOf counts a poll's answers.
 *
 * Every vote has to be opened one at a time, because each is sealed on its own,
 * and the options have to be hashed before anything can be matched to them.
 * Both are why this is here rather than on the server: the server holds the
 * poll and the votes and can read neither.
 *
 * A vote whose payload will not open still counts as somebody having answered.
 * Reporting five voters on a poll six people answered would be a quieter kind
 * of wrong than admitting one answer could not be read.
 */
async function tallyOf(poll: P.Poll, entry: Entry, open: Opener): Promise<PollView> {
  const options = poll.options ?? []
  const hashes = await hashesOf(options)

  const votes: Vote[] = []
  for (const row of entry.votes) {
    const payload = row.payload_sealed ? await open.payload(row) : null
    // The presence of the poll_vote object is what says the vote was opened at
    // all. An empty selection inside it is a withdrawal — somebody took their
    // vote back — which is a different fact from a vote nobody could decrypt,
    // and the two are indistinguishable if only the list is looked at.
    const vote = payload?.state === 'ok' ? payload.value.poll_vote : undefined
    votes.push({
      who: row.is_from_me
        ? t('você')
        : personName(row.sender_lid, row.sender_pn, row.sender_key || ''),
      key: row.is_from_me ? '@me' : row.sender_key || row.chat_key,
      fromMe: Boolean(row.is_from_me),
      at: row.ts ? new Date(row.ts) : undefined,
      selected: (vote?.selected ?? []).map(fromBase64),
      opened: vote !== undefined,
    })
  }

  const tally = count(options, hashes, votes)
  return { tally, complete: tally.sealed === 0 && tally.unmatched === 0 }
}

async function toMessageView(entry: Entry, context: ArchiveContext): Promise<MessageView | null> {
  const open = context.open
  const row = entry.current
  const original = entry.row

  const body = await open.body(row)
  const payload =
    row.payload_sealed || original.payload_sealed
      ? await open.payload(row.payload_sealed ? row : original)
      : null
  if (!currentArchive(context)) return null

  const reactions: ReactionView[] = []
  for (const reaction of standing(entry)) {
    const emoji = await open.body(reaction.row)
    if (!currentArchive(context)) return null
    // WhatsApp withdraws a reaction by sending one with an empty emoji, and
    // empty is a property of the sealed body — so the withdrawal is only
    // visible once it is opened.
    if (emoji.state !== 'ok' || emoji.value === '') continue
    reactions.push({
      emoji: emoji.value,
      who: directory.nameFor(reaction.row.sender_key) || displayFallback(reaction.row.sender_key ?? ''),
      fromMe: Boolean(reaction.row.is_from_me),
    })
  }

  const senderKey = original.sender_lid || original.sender_pn || original.sender_key || ''

  const poll =
    payload?.state === 'ok' && payload.value.poll
      ? await tallyOf(payload.value.poll, entry, open)
      : undefined
  if (!currentArchive(context)) return null

  return {
    uid: original.uid,
    waID: original.wa_id,
    chatKey: original.chat_key,
    seq: row.seq,
    ts: original.ts ? new Date(original.ts) : undefined,
    fromMe: Boolean(original.is_from_me),
    isGroup: Boolean(original.is_group),
    isStatus: isStatus(original.chat_key),
    senderKey,
    senderName: original.is_from_me
      ? t('você')
      : personName(original.sender_lid, original.sender_pn, original.sender_key || ''),
    type: original.type,
    unsupported: original.unsupported ?? '',
    body: body.state === 'ok' ? body.value : '',
    bodyState: stateOf(body),
    payload: payload?.state === 'ok' ? payload.value : undefined,
    media: await toMediaView(original, context),
    reactions,
    poll,
    edited: entry.versions.length > 1,
    versionCount: entry.versions.length,
    deleted: Boolean(entry.deleted),
    deletedAt: entry.deleted?.at ? new Date(entry.deleted.at) : undefined,
    viewOnce: Boolean(original.view_once),
    ephemeral: Boolean(original.ephemeral),
    expiration: original.expiration ?? 0,
    expiresAt: original.expires_at ? new Date(original.expires_at) : undefined,
    forwarded: Boolean(original.is_forwarded),
    forwardingScore: original.forwarding_score ?? 0,
    replyTo: original.reply_to,
    entry,
  }
}

async function toMediaView(row: P.SealedMessage, context: ArchiveContext): Promise<MediaView | undefined> {
  if (!row.media || !currentArchive(context)) return undefined
  const m = row.media

  const [thumb, fileName] = await Promise.all([context.open.thumbnail(row), context.open.fileName(row)])
  if (!currentArchive(context)) return undefined
  const view: MediaView = {
    type: m.media_type,
    mimetype: m.mimetype ?? '',
    fileLength: m.file_length ?? 0,
    width: m.width ?? 0,
    height: m.height ?? 0,
    seconds: m.seconds ?? 0,
    isGIF: Boolean(m.is_gif),
    fileName: fileName.state === 'ok' ? fileName.value : '',
    status: m.download_status,
  }
  if (thumb.state === 'ok' && thumb.value.length > 0) {
    view.thumbURL = thumbURL(row.uid, thumb.value)
  }
  if (m.waveform) {
    // Not sealed: it is envelope shape, carries no speech, and is needed to
    // draw the placeholder before the audio is fetched.
    const raw = atob(m.waveform)
    view.waveform = Array.from(raw, (c) => c.charCodeAt(0))
  }
  // An attachment this tab sent is still in this tab. Showing the copy we
  // already have beats showing the sealed stamp while the server fetches the
  // full one back from the CDN.
  const held = previews.get(row.wa_id)
  if (held) view.localURL = held
  return view
}

/** fetchMedia downloads and decrypts the full attachment behind one message. */
export async function fetchMedia(view: MessageView): Promise<void> {
  const context = archiveContext()
  const downloading = media
  const target = view.media
  if (!context || !downloading || !target) return
  const current = () => currentArchive(context) && downloading === media
  const row = view.entry.row
  if (!row.media || row.device_id !== context.deviceID) return

  const key = await context.open.mediaKey(row)
  if (!current()) return
  if (key.state !== 'ok') {
    target.full = {
      state: 'error',
      message:
        key.state === 'tampered'
          ? t('a chave da mídia não confere com esta linha')
          : t('a chave da mídia não abriu'),
    }
    return
  }
  target.full = { state: 'pending', status: 'baixando' }
  const result = await downloading.open(row, key.value)
  if (current()) target.full = result
}

/** A forwarding action reads the verified bytes directly, without fetching a blob URL through CSP. */
export async function readMediaBlob(view: MessageView): Promise<Blob | undefined> {
  const context = archiveContext()
  const source = media
  const uid = view.entry.row.uid
  if (!context || !source || view.entry.row.device_id !== context.deviceID) return
  await fetchMedia(view)
  if (!currentArchive(context) || media !== source || view.entry.row.uid !== uid || view.media?.full?.state !== 'ready') return
  return source.peekBlob(uid)
}

// ---------------------------------------------------------------------------
// The history of one message: what WhatsApp hides
// ---------------------------------------------------------------------------

export async function loadHistory(view: MessageView): Promise<void> {
  const context = archiveContext()
  if (!context) return
  const current = () => currentArchive(context) && state.selectedUID === view.uid
  state.selectedUID = view.uid
  state.history = null
  state.historyError = ''
  state.historyLoading = true

  try {
    const reply = await context.connection.request<P.History>(
      P.TypeHistory,
      { device_id: context.deviceID, uid: view.uid } satisfies P.HistoryRequest,
      P.TypeHistoryFrame,
    )
    if (!current()) return
    const history = await toHistoryView(reply, context.open)
    if (current()) state.history = history
  } catch (err) {
    if (current()) state.historyError = err instanceof Error ? err.message : String(err)
  } finally {
    if (current()) state.historyLoading = false
  }
}

async function toHistoryView(reply: P.History, open: Opener): Promise<HistoryView> {
  await open.prefetch([
    ...(reply.versions ?? []).map((v) => v.message.content_key_id),
    ...(reply.reactions ?? []).map((r) => r.message.content_key_id),
  ])

  const versions: VersionView[] = []
  for (const version of reply.versions ?? []) {
    const body = await open.body(version.message)
    versions.push({
      revision: version.revision,
      body: body.state === 'ok' ? body.value : '',
      bodyState: stateOf(body),
      from: version.from ? new Date(version.from) : undefined,
      until: version.until ? new Date(version.until) : undefined,
    })
  }

  const reactions: HistoryView['reactions'] = []
  for (const reaction of reply.reactions ?? []) {
    const emoji = await open.body(reaction.message)
    reactions.push({
      // An empty emoji is how a reaction is withdrawn, and the panel says so
      // rather than hiding the row.
      emoji: emoji.state === 'ok' ? emoji.value : '',
      who: reaction.message.is_from_me
        ? t('você')
        : directory.nameFor(reaction.message.sender_key) ||
          displayFallback(reaction.message.sender_key ?? ''),
      superseded: Boolean(reaction.superseded),
      revoked: Boolean(reaction.revoked),
      at: reaction.message.ts ? new Date(reaction.message.ts) : undefined,
      revokedAt: reaction.revoked_at ? new Date(reaction.revoked_at) : undefined,
    })
  }

  const readers: ReaderView[] = (reply.readers ?? []).map((r) => ({
    key: r.key,
    name: r.is_from_me ? t('você') : personName(r.lid, r.pn, r.key),
    readDevice: r.read_device ?? '',
    revisions: revisionsOf(r.revisions),
    devices: (r.devices ?? []).map((d) => ({
      key: d.key,
      agent: d.agent ?? 0,
      device: d.device ?? 0,
      delivered: d.delivered ? new Date(d.delivered) : undefined,
      read: d.read ? new Date(d.read) : undefined,
      played: d.played ? new Date(d.played) : undefined,
      sawRevision: d.saw_revision,
      confirmedRevision: d.confirmed_revision,
      confirmed: d.confirmed,
      revisions: revisionsOf(d.revisions),
    })),
    fromMe: Boolean(r.is_from_me),
    delivered: r.delivered ? new Date(r.delivered) : undefined,
    read: r.read ? new Date(r.read) : undefined,
    played: r.played ? new Date(r.played) : undefined,
    sawRevision: r.saw_revision,
    confirmedRevision: r.confirmed_revision,
    confirmed: r.confirmed,
  }))

  return {
    uid: reply.versions?.[0]?.message.uid ?? '',
    waID: reply.wa_id,
    versions,
    deletion: reply.deletion
      ? {
          byAuthor: reply.deletion.by_author,
          byAdmin: reply.deletion.by_admin,
          at: reply.deletion.at ? new Date(reply.deletion.at) : undefined,
        }
      : undefined,
    reactions,
    readers,
  }
}

/**
 * applyChatUpdate patches a conversation from a live push.
 *
 * The badge and the disappearing timer both live on the chat row, and until
 * this existed the only frame that carried either was the reply to a
 * chats.list request — so a badge moved when the sidebar happened to be
 * refetched and at no other moment, and a timer the other side changed was
 * invisible until a reload.
 *
 * Each field is applied only when present. Absent means the event says nothing
 * about it; zero is a real value for both — a badge of zero is a conversation
 * just read, a timer of zero is disappearing messages turned off — so a
 * truthiness test here would silently refuse to clear either.
 *
 * A chat this client has never listed is ignored rather than invented. The
 * message that created it arrives on its own path and brings the listing with
 * it; making a half-empty row here would put a nameless conversation in the
 * sidebar.
 */
export function applyChatUpdate(ev: P.ChatUpdateEvent): void {
  if (ev.device_id !== state.deviceID) return
  const chat = state.chats.find((c) => c.key === ev.chat_key || c.keys.includes(ev.chat_key))
  if (!chat) return
  if (ev.unread !== undefined) chat.unread = ev.unread
  if (ev.ephemeral !== undefined) chat.ephemeral = ev.ephemeral
}

// ---------------------------------------------------------------------------
// Live traffic
// ---------------------------------------------------------------------------

async function handleFrame(frame: P.Frame): Promise<void> {
  switch (frame.t) {
    case P.TypeReaderMode: {
      const preference = frame.p as P.DeviceModeRequest
      if (preference.receipt_mode !== 'active' && preference.receipt_mode !== 'passive') break
      const device = state.devices.find((d) => d.id === preference.device_id)
      if (device) device.reader_receipt_mode = preference.receipt_mode
      if (state.deviceID === preference.device_id) applyReceiptMode(preference.receipt_mode)
      break
    }
    case P.TypeMessage:
      await onMessage(frame.p as P.SealedMessage)
      break
    case P.TypePresence:
      applyPresence(frame.p as P.PresenceEvent)
      break
    case P.TypeChatUpdate:
      applyChatUpdate(frame.p as P.ChatUpdateEvent)
      break
    case P.TypeReceipt:
      onReceipt(frame.p as P.ReceiptEvent)
      break
    case P.TypeLag:
      // The stream was not continuous. Rather than pretend otherwise, the gap
      // is shown and the open conversation is reloaded from the archive.
      state.lagged = true
      if (state.openChatKey) await openChat(state.openChatKey)
      break
    case P.TypeDeviceStatus: {
      const status = frame.p as P.DeviceStatus
      const device = state.devices.find((d) => d.id === status.device_id)
      if (device) {
        device.status = status.status
        device.running = status.status === 'online'
      }
      break
    }
    default:
      break
  }
}

async function onMessage(row: P.SealedMessage): Promise<void> {
  if (row.device_id !== state.deviceID) return
  const context = archiveContext()
  if (!context) return
  state.liveCount += 1

  await bumpChat(row)

  if (!currentArchive(context) || !inOpenChat(row.chat_key)) return
  openRows = [...openRows, row]
  // Re-projected rather than appended: the row may be an edit, a deletion or a
  // reaction, none of which is a new line — and all of which change one that is
  // already on screen.
  await redraw()
}

/**
 * sendText sends a message and shows it before the server has confirmed it.
 *
 * The id is minted here rather than by the server. It makes a retry idempotent,
 * which is what the field is for, but the reason it matters on this side is
 * ordering: the archived row is published to the live subscription inside the
 * same call that answers this request, so the message frame regularly arrives
 * BEFORE the reply. Without a shared id there is nothing to match the two on,
 * and the message would appear twice.
 *
 * The optimistic line lives in the outbox and is reaped by buildTimeline the
 * moment the real row shows up.
 */
export async function sendText(body: string, replyTo?: MessageView, marks?: Marks): Promise<void> {
  const text = body.trim()
  if (!conn || !text || !state.openChatKey) return
  // Cleared on the way in, like every other action. A banner left over from
  // something that failed a minute ago reads as a description of what is
  // happening now.
  state.actionError = ''

  const id = newWAID()
  const chat = state.openChatKey
  outbox.set(id, pendingLine(id, chat, text, replyTo, marks))
  await redraw()

  const request: P.SendRequest = {
    device_id: state.deviceID,
    chat,
    body: text,
    id,
  }
  if (replyTo) {
    request.reply_to = replyTo.waID
    request.reply_sender = replyTo.senderKey
    // The quoted text has to travel with it: the archive is sealed, so the
    // server cannot look up what was said.
    request.reply_body = replyTo.body
  }
  applyMarks(request, marks)

  try {
    const result = await conn.request<P.SendResult>(P.TypeSend, request, P.TypeSendResult)
    // Otherwise nothing to do: either the archived row has already arrived and
    // reaped the pending line, or it is about to.
    if (!result.uid) await unarchived(id)
  } catch (err) {
    failed(id, err)
    await redraw()
  }
}

/**
 * Marks are what a message says about itself beyond its content.
 *
 * Rarely wanted, which is why they live behind a disclosure in the composer
 * rather than beside the send button — but they are part of what a message is,
 * and this archive can already read them on the way in. Being able to read a
 * flag and not to set one is a gap, not a policy.
 */
export interface Marks {
  forwarded: boolean
  /** Five or more is what WhatsApp renders as "encaminhada muitas vezes". */
  score: number
  /**
   * The recipient may open it once.
   *
   * Attachments only. The same flag on text is refused by the server, and
   * WhatsApp itself renders such a message as having come from an older
   * version of the app — so the composer never offers it for a sentence.
   */
  viewOnce: boolean
  /**
   * The disappearing timer for this message alone, in seconds.
   *
   * Undefined means "whatever the conversation says", which is the normal
   * case and the one the server already handles: it reads the chat's timer and
   * applies it, envelope included.
   *
   * A number here overrides it for this message. That is a real thing on the
   * wire — the timer travels in every message's context info, not on the chat
   * — and it is the only per-message control there is. Changing the timer of a
   * message already sent is not possible: no operation in the protocol does
   * it, so the message menu states the timer rather than offering to edit it.
   */
  expiration?: number
}

export function noMarks(): Marks {
  return { forwarded: false, score: 0, viewOnce: false }
}

/**
 * applyMarks copies the flags onto an outbound request.
 *
 * Through floorScore rather than directly, because two of the rules are silent
 * when broken: the server reads the score only inside `if forwarded`, so a
 * score on its own evaporates, and a forwarded message with a score of zero
 * draws no badge at all on the recipient's screen.
 */
function applyMarks(request: P.SendOptions, marks?: Marks): void {
  // The timer first, and outside the forwarded gate: the two are unrelated,
  // and an early return here silently dropped it.
  if (marks?.expiration !== undefined) {
    request.expiration = marks.expiration
    // Expiration implies the envelope. The rule lives in send.wrap on the
    // server and no caller can get around it, but saying so here means the
    // request describes the message it is asking for rather than half of it.
    request.ephemeral = marks.expiration > 0
  }
  const { forwarded, score } = floorScore(marks?.forwarded ?? false, marks?.score ?? 0)
  if (!forwarded) return
  request.forwarded = true
  request.forwarding_score = score
}

/**
 * unarchived marks a message that was sent and will never be archived.
 *
 * The server says so by answering with no uid: it reached WhatsApp, and writing
 * the row failed. Nothing will arrive on the subscription to reap this line, so
 * without this it stays at "enviando…" until the session ends — which reads as
 * a message that never went, when the opposite is true.
 */
async function unarchived(waID: string): Promise<void> {
  const line = outbox.get(waID)
  if (!line) return
  line.pending = 'unarchived'
  if (line.media) line.media.upload = undefined
  await redraw()
}

/** showProgress reports how much of an attachment has left this tab. */
function showProgress(waID: string, progress: { sent: number; total: number }): void {
  const line = state.timeline.find((view) => view.waID === waID)
  if (line?.media) line.media.upload = progress
}

/** failed marks an outgoing line as never having left, and says why. */
function failed(waID: string, err: unknown): void {
  const line = outbox.get(waID)
  if (!line) return
  line.pending = 'failed'
  line.failure = err instanceof Error ? err.message : String(err)
  if (line.media) line.media.upload = undefined
}

/**
 * sendMedia uploads an attachment and then sends the message that points at it.
 *
 * Two legs, and they fail differently. The upload is an ordinary HTTP request
 * that can be refused for reasons the websocket knows nothing about — a device
 * that went offline, a file over the server's ceiling — and it happens before
 * any frame is sent, which is why the optimistic line exists before the upload
 * starts rather than after it. There would otherwise be nothing on screen to
 * mark as failed.
 *
 * `prepared.kind` is passed twice on purpose, as the upload's type and as the
 * frame's. They pick the HKDF label and the protobuf field respectively, and
 * they must be the same string: uploading as one kind and sending as another
 * succeeds at every step and produces an attachment that will never open
 * again, for the recipient or for this archive.
 */
export async function sendMedia(
  prepared: Prepared,
  caption: string,
  replyTo?: MessageView,
  marks?: Marks,
): Promise<void> {
  state.actionError = ''
  if (!conn || !media || !state.openChatKey) {
    // Only reachable if the connection dropped between choosing the file and
    // sending it. Said out loud rather than swallowed: the composer has
    // already let go of the attachment by now, so silence here is a file that
    // vanished on its way out.
    state.actionError = t('A conexão caiu antes do anexo sair. Escolha o arquivo de novo.')
    discard(prepared)
    return
  }
  const chat = state.openChatKey
  // Captured, not read twice. An upload can take a minute, and reading the
  // device again afterwards would let a switch in the meantime send the
  // attachment from an account it was never uploaded for.
  const device = state.deviceID
  const id = newWAID()
  const text = prepared.plan.captionAllowed ? caption.trim() : ''
  const line = pendingMediaLine(id, chat, prepared, text, replyTo, marks)
  outbox.set(id, line)
  // Handed to the keeper straight away, so the picture survives the moment the
  // archived row replaces this line. The keeper owns it from here; `discard`
  // is only for a prepared attachment that never became a message.
  keepPreview(id, prepared.previewURL)
  await redraw()

  let upload: P.UploadRef
  try {
    upload = await media.upload({
      deviceID: device,
      kind: prepared.kind,
      blob: prepared.blob,
      // Written onto the line the timeline holds rather than the one captured
      // here. They are the same object today, because an outbox line is
      // reactive — but a progress bar that silently stops moving when that
      // stops being true is not a failure anyone would trace back.
      onProgress: (progress) => showProgress(id, progress),
    })
  } catch (err) {
    failed(id, err)
    await redraw()
    return
  }
  if (line.media) line.media.upload = undefined

  const request: P.SendMediaRequest = {
    device_id: device,
    chat,
    type: prepared.kind,
    // Forwarded exactly as it came back. Go renders []byte as base64 strings,
    // and decoding these here to re-encode them produces JSON the server
    // cannot read — which it reports as "upload is required", pointing at the
    // wrong thing entirely.
    upload,
    mimetype: prepared.mimetype,
    id,
    // Sent for every type, though only a document renders it. The archived
    // envelope keeps it regardless, and a photograph whose name this archive
    // recorded is worth more than one it did not.
    filename: prepared.fileName,
  }
  if (text) request.caption = text
  // Only where the field is read. Everything else is dropped in silence on the
  // way out, and would sit in our own archive describing something the
  // recipient never saw.
  if (prepared.plan.wantsDimensions && prepared.width) {
    request.width = prepared.width
    request.height = prepared.height
  }
  if (prepared.plan.wantsDuration && prepared.seconds) request.seconds = prepared.seconds
  if (prepared.plan.wantsWaveform && prepared.waveform) request.waveform = prepared.waveform
  if (prepared.plan.wantsThumbnail && prepared.thumbnail) request.thumbnail = prepared.thumbnail
  if (prepared.isGIF) request.is_gif = true
  if (prepared.isAnimated) request.is_animated = true
  if (marks?.viewOnce && prepared.plan.viewOnceAllowed) request.view_once = true
  if (replyTo) {
    request.reply_to = replyTo.waID
    request.reply_sender = replyTo.senderKey
    request.reply_body = replyTo.body
  }
  applyMarks(request, marks)

  try {
    const result = await conn.request<P.SendResult>(P.TypeSendMedia, request, P.TypeSendResult)
    if (!result.uid) await unarchived(id)
  } catch (err) {
    failed(id, err)
    await redraw()
  }
}

/** discardFailed removes a message that never went, so the column stops nagging. */
export async function discardFailed(waID: string): Promise<void> {
  outbox.delete(waID)
  forgetPreview(waID)
  await redraw()
}

/**
 * newWAID mints an id in WhatsApp's own shape: uppercase hex, 32 characters.
 *
 * Chosen by the client because the server offers no way to reserve one, and
 * because a message needs its identity before it is sent — see sendText.
 */
function newWAID(): string {
  const raw = crypto.getRandomValues(new Uint8Array(16))
  return [...raw].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase()
}

/**
 * pendingLine is the bubble for a message that has left this tab and not yet
 * come back from the archive.
 *
 * Built by hand rather than through project(): those paths open sealed columns,
 * and this message has none — it has never been sealed, because it has never
 * been stored. Everything it claims is what this tab knows first-hand.
 */
function pendingLine(
  id: string,
  chat: string,
  text: string,
  replyTo?: MessageView,
  marks?: Marks,
): MessageView {
  return skeleton(id, chat, 'text', text, replyTo, marks)
}

/**
 * pendingMediaLine is the bubble for an attachment on its way out.
 *
 * Everything MediaBlock reads has to be here on the first frame, because it is
 * mounted the moment this line appears and non-null-asserts the media record.
 * The values are all first-hand: the file is in this tab, so its size, its
 * dimensions and its duration are known facts rather than claims from a row.
 */
function pendingMediaLine(
  id: string,
  chat: string,
  prepared: Prepared,
  caption: string,
  replyTo?: MessageView,
  marks?: Marks,
): MessageView {
  const line = skeleton(id, chat, prepared.kind, caption, replyTo, marks)
  line.viewOnce = Boolean(marks?.viewOnce && prepared.plan.viewOnceAllowed)
  line.media = {
    type: prepared.kind,
    mimetype: prepared.mimetype,
    fileLength: prepared.blob.size,
    width: prepared.width,
    height: prepared.height,
    seconds: prepared.seconds,
    isGIF: prepared.isGIF,
    fileName: prepared.fileName,
    // Anything but 'gone', which is the one value the bubble compares against.
    // 'local' is the truth: the attachment is here and has been nowhere else.
    status: 'local',
    waveform: prepared.waveform ? unpackWaveform(prepared.waveform) : undefined,
    localURL: prepared.previewURL,
    thumbURL: prepared.thumbnail ? `data:image/jpeg;base64,${prepared.thumbnail}` : undefined,
    upload: { sent: 0, total: prepared.blob.size },
  }
  return line
}

/** unpackWaveform reverses the base64 the wire carries, for the local bubble. */
function unpackWaveform(encoded: string): number[] {
  const raw = atob(encoded)
  return Array.from(raw, (c) => c.charCodeAt(0))
}

function skeleton(
  id: string,
  chat: string,
  type: string,
  body: string,
  replyTo?: MessageView,
  marks?: Marks,
): MessageView {
  const { forwarded, score } = floorScore(marks?.forwarded ?? false, marks?.score ?? 0)
  const row: P.SealedMessage = {
    uid: id,
    seq: Number.MAX_SAFE_INTEGER,
    device_id: state.deviceID,
    wa_id: id,
    // Recorded rather than read back from state later: by the time this line
    // is reaped the reader may have opened another conversation, and this is
    // what says the line does not belong there.
    chat_key: chat,
    ts: new Date().toISOString(),
    is_from_me: true,
    is_group: isGroup(chat),
    kind: 'message',
    type,
    source: 'live',
    content_key_id: 0,
  }
  // Reactive in its own right, which the archived lines do not need to be.
  // The upload's progress is written straight onto this object while it is on
  // screen — there is no redraw to hang it off, and sixty rebuilds of the
  // conversation for one file would be absurd. A plain object here is not the
  // same object the template reads through, so those writes would land
  // nowhere and the bar would sit at zero for the whole upload.
  return reactive<MessageView>({
    uid: id,
    waID: id,
    chatKey: row.chat_key || state.openChatKey,
    seq: row.seq,
    ts: new Date(),
    fromMe: true,
    isGroup: Boolean(row.is_group),
    isStatus: false,
    senderKey: '@me',
    senderName: t('você'),
    type,
    unsupported: '',
    body,
    bodyState: 'ok',
    reactions: [],
    edited: false,
    versionCount: 1,
    deleted: false,
    viewOnce: false,
    ephemeral: false,
    expiration: 0,
    forwarded,
    forwardingScore: score,
    replyTo: replyTo?.waID,
    pending: 'sending',
    entry: { row, versions: [row], current: row, reactions: [], votes: [] },
  })
}

/**
 * canSend reports whether this session may put a message into this chat.
 *
 * Three separate reasons it might not, and they are not interchangeable: the
 * archive is open read-only, this account holds no key for the device, or the
 * device is not connected to WhatsApp right now.
 */
export function canSend(): boolean {
  if (!state.openChatKey || state.unreadable || !state.connected) return false
  const device = state.devices.find((d) => d.id === state.deviceID)
  return Boolean(device?.running)
}

async function bumpChat(row: P.SealedMessage): Promise<void> {
  const context = archiveContext()
  if (!context) return
  // By key set, not by equality: one conversation can be stored under both a
  // phone number and a LID, and a message naming the half the row is not keyed
  // on would otherwise look like a conversation nobody has seen — reloading
  // the whole list on every message of an ordinary chat.
  const chat = state.chats.find((c) => c.keys.includes(row.chat_key))
  if (!chat) {
    // A conversation nobody has seen before. Reloading the list is cheap and
    // gets the name and the counters right in one step.
    await loadChats()
    return
  }
  chat.lastSeq = row.seq
  chat.lastTS = row.ts ? new Date(row.ts) : new Date()
  chat.lastKind = row.kind
  chat.lastType = row.type
  state.chats = [...state.chats].sort(byRecency)

  // The preview is opened here rather than left stale. A list that keeps
  // showing yesterday's line while a message arrives beside it reads as a
  // client that has stopped working.
  const body = await context.open.body(row)
  if (!currentArchive(context)) return
  chat.preview = body.state === 'ok' ? body.value : ''
  chat.previewState = stateOf(body)
}

/**
 * onReceipt folds one live acknowledgement into the receipt store.
 *
 * Not onto the message: state.timeline is reassigned wholesale on the next
 * frame, so anything written there survives until then and no further. That is
 * why a conversation opened cold used to show one grey tick on everything, and
 * it is why this writes somewhere the reprojection cannot reach.
 *
 * Filtered to messages this tab is actually holding, because a receipt frame
 * names a device and not a conversation: without it the map grows for the whole
 * account for as long as the tab is open, and none of it is ever drawn.
 */
function onReceipt(receipt: P.ReceiptEvent): void {
  if (receipt.device_id !== state.deviceID) return
  applyReceipt(receipt, holdingMessage)
}

/** holdingMessage reports whether this tab has the message on hand. */
function holdingMessage(waID: string): boolean {
  if (outbox.has(waID)) return true
  return openRows.some((r) => r.wa_id === waID)
}

/** A person's preference never inherits the number's shared/API policy. */
function applyDeviceReceiptMode(device?: P.DeviceInfo): void {
  applyReceiptMode(session?.credential.kind === 'session'
    ? device?.reader_receipt_mode ?? 'passive'
    : device?.receipt_mode ?? 'passive')
}

/** Changes this person's reading preference for this number. API-key clients
 * retain the explicit shared device policy used by the CLI and integrations. */
export async function setReceiptMode(mode: 'passive' | 'active'): Promise<boolean> {
  const capturedConnection = connection()
  const capturedSession = session
  const deviceID = state.deviceID
  if (!capturedConnection || !deviceID) return false
  try {
    if (capturedSession?.credential.kind === 'session') {
      const preference = await capturedConnection.request<P.DeviceModeRequest>(
        P.TypeReaderMode, { device_id: deviceID, receipt_mode: mode } satisfies P.DeviceModeRequest, P.TypeReaderMode,
      )
      if (session !== capturedSession || conn !== capturedConnection) return false
      const device = state.devices.find((d) => d.id === deviceID)
      const answer = preference.receipt_mode === 'active' ? 'active' : 'passive'
      if (device) device.reader_receipt_mode = answer
      if (state.deviceID === deviceID) applyReceiptMode(answer)
    } else {
      const detail = await capturedConnection.request<{ device: P.DeviceInfo }>(
        P.TypeDeviceMode, { device_id: deviceID, receipt_mode: mode } satisfies P.DeviceModeRequest, P.TypeDeviceDetail,
      )
      if (session !== capturedSession || conn !== capturedConnection) return false
      const device = state.devices.find((d) => d.id === deviceID)
      if (device) device.receipt_mode = detail.device?.receipt_mode ?? mode
      if (state.deviceID === deviceID) applyReceiptMode(detail.device?.receipt_mode ?? mode)
    }
    return true
  } catch (err) {
    state.actionError = err instanceof Error ? err.message : String(err)
    return false
  }
}

/** applyReceiptMode points the client's own gates at the server's answer. */
export function applyReceiptMode(mode: string): void {
  const active = mode === 'active'
  state.quiet = !active
  setReadReceipts(active)
  setTypingNotifications(active)
}

/** Opens a device's own profile picture without changing the selected chat.
 * Private keys stay inside this module, and results cannot cross a session or
 * workspace switch while requests and decryptions are in flight. */
export async function deviceProfilePicture(deviceID: string, contactKey: string): Promise<Blob | null> {
  const capturedSession = session
  const capturedConnection = conn
  const capturedTenant = state.tenantID
  if (!capturedSession || !capturedConnection || !tenantBytes) return null
  if (!capturedSession.archiveFor(deviceID)) {
    await capturedSession.refreshAccess?.()
    if (session !== capturedSession || conn !== capturedConnection || state.tenantID !== capturedTenant) return null
  }
  const key = capturedSession.archiveFor(deviceID)
  if (!key) return null
  const profileOpener = new Opener(capturedConnection, tenantBytes, parseUUID(deviceID), deviceID, key)
  const frame = await capturedConnection.request<P.Avatar>(P.TypeAvatar,
    { device_id: deviceID, contact_key: contactKey } satisfies P.AvatarRequest, P.TypeAvatarFrame)
  const picture = await profileOpener.avatar(frame)
  if (session !== capturedSession || conn !== capturedConnection || state.tenantID !== capturedTenant || picture.state !== 'ok') return null
  return new Blob([picture.value as BlobPart], { type: 'image/jpeg' })
}
