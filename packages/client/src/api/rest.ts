import type { KeySource } from './opener.js'
import type * as P from './protocol.js'

export interface WorkspaceReply { tenant_id: string }
export type ArchiveDevices = WorkspaceReply & P.Devices
export type ArchiveChats = WorkspaceReply & P.Chats & { limit: number; truncated: boolean }
export type ArchivePage = WorkspaceReply & P.Page
export type ArchiveMessage = WorkspaceReply & P.SealedMessage
export type ArchiveHistory = WorkspaceReply & P.History & { requested_uid: string }
export type ArchiveKeys = WorkspaceReply & P.Keys
export interface ArchiveGrants extends WorkspaceReply {
  user_id: string
  grants: { device_id: string; archive_tenant_id?: string; label?: string; epoch: number; sealed_dsk: string }[]
}
export interface ArchiveCursor { ts: string; seq: number }
export interface ArchiveClientOptions {
  serverURL: string
  workspaceID: string
  token: string
  fetch?: typeof fetch
  timeoutMS?: number
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const maxResponseBytes = 32 * 1024 * 1024
const codes = new Set(['bad_request', 'unauthorized', 'not_authorized', 'not_found', 'internal', 'rate_limited'])
export class ArchiveError extends Error {
  constructor(readonly code: string, readonly status = 0) {
    // Server diagnostics may echo credentials or private upstream data. Keep
    // errors safe for logs and model-facing adapters without losing the code.
    super(`Archive request failed (${code}${status ? `, HTTP ${status}` : ''}).`)
    this.name = 'ArchiveError'
  }
}
export function archiveOrigin(value: string): string {
  let url: URL
  try { url = new URL(value) } catch { throw new ArchiveError('invalid_origin') }
  if (url.username || url.password || url.pathname !== '/' || url.search || url.hash ||
    (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) throw new ArchiveError('invalid_origin')
  return url.origin
}
function identifier(value: string): string {
  if (typeof value !== 'string' || !uuid.test(value)) throw new ArchiveError('invalid_identifier')
  return value.toLowerCase()
}
function limit(value: number | undefined, fallback: number, max: number): number {
  const result = value ?? fallback
  if (!Number.isSafeInteger(result) || result < 1 || result > max) throw new ArchiveError('invalid_limit')
  return result
}
function valid(condition: unknown): asserts condition {
  if (!condition) throw new ArchiveError('invalid_response')
}
function record(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value) }
function isID(value: unknown): value is string { return typeof value === 'string' && uuid.test(value) }
function nonnegative(value: unknown): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 }
function messageShape(value: unknown): asserts value is P.SealedMessage {
  valid(record(value) && isID(value.uid) && isID(value.device_id) && typeof value.chat_key === 'string' &&
    typeof value.wa_id === 'string' && nonnegative(value.seq) && typeof value.is_from_me === 'boolean' &&
    typeof value.kind === 'string' && typeof value.type === 'string' && typeof value.source === 'string')
  valid(value.chat_key.length <= 512 && value.wa_id.length <= 512)
  for (const key of ['body_sealed', 'payload_sealed', 'ts', 'target_uid']) valid(value[key as keyof P.SealedMessage] === undefined || typeof value[key as keyof P.SealedMessage] === 'string')
  valid(value.content_key_id === undefined || (nonnegative(value.content_key_id) && value.content_key_id > 0))
  valid(value.media === undefined || record(value.media))
}

/** Read-only archive HTTP client. Origin and workspace are immutable per client. */
export class ArchiveClient {
  readonly serverURL: string
  readonly workspaceID: string
  private readonly token: string
  private readonly fetcher: typeof fetch
  private readonly timeoutMS: number
  constructor(options: ArchiveClientOptions) {
    this.serverURL = archiveOrigin(options.serverURL)
    this.workspaceID = identifier(options.workspaceID)
    if (!options.token || /[\r\n]/.test(options.token)) throw new ArchiveError('invalid_credential')
    this.token = options.token
    this.fetcher = options.fetch ?? fetch
    this.timeoutMS = limit(options.timeoutMS, 30_000, 120_000)
  }
  private async get<T extends WorkspaceReply>(path: string, query: Record<string, string> = {}): Promise<T> {
    const url = new URL(path, this.serverURL)
    for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value)
    let response: Response
    try {
      response = await this.fetcher(url, {
        method: 'GET', headers: { Authorization: `Bearer ${this.token}` },
        credentials: 'omit', cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(this.timeoutMS),
      })
    } catch { throw new ArchiveError('unavailable') }
    const reader = response.body?.getReader(), parts: Uint8Array[] = []
    let size = 0
    if (reader) try {
      for (;;) {
        const next = await reader.read()
        if (next.done) break
        size += next.value.length
        if (size > maxResponseBytes) { await reader.cancel(); throw new ArchiveError('response_too_large', response.status) }
        parts.push(next.value)
      }
    } catch (error) {
      if (error instanceof ArchiveError) throw error
      throw new ArchiveError('unavailable', response.status)
    } finally { reader.releaseLock() }
    const data = new Uint8Array(size)
    let offset = 0
    for (const part of parts) { data.set(part, offset); offset += part.length }
    let parsed: T & { code?: string }
    try { parsed = JSON.parse(new TextDecoder().decode(data)) } catch { throw new ArchiveError('invalid_response', response.status) }
    if (!response.ok) throw new ArchiveError(codes.has(parsed?.code ?? '') ? parsed.code! : 'request_failed', response.status)
    valid(record(parsed) && isID(parsed.tenant_id))
    if (parsed.tenant_id !== this.workspaceID) throw new ArchiveError('workspace_mismatch', response.status)
    return parsed
  }
  async listDevices(): Promise<ArchiveDevices> {
    const result = await this.get<ArchiveDevices>('/v1/devices')
    valid(Array.isArray(result.devices) && result.devices.every(device => record(device) && isID(device.id) && typeof device.label === 'string' && device.label.length <= 8192 && typeof device.status === 'string'))
    return result
  }
  async listChats(deviceID: string, options: { limit?: number } = {}): Promise<ArchiveChats> {
    const id = identifier(deviceID)
    const result = await this.get<ArchiveChats>(`/v1/devices/${id}/chats`, { limit: String(limit(options.limit, 100, 3000)) })
    valid(isID(result.device_id) && Array.isArray(result.chats) && result.chats.length <= limit(options.limit, 100, 3000) && result.chats.every(chat => record(chat) && isID(chat.uid) && typeof chat.chat_key === 'string' && nonnegative(chat.last_seq)) &&
      typeof result.truncated === 'boolean' && nonnegative(result.limit))
    if (result.device_id !== id) throw new ArchiveError('device_mismatch')
    return result
  }
  async listMessages(deviceID: string, options: { chatKey: string; limit?: number; before?: ArchiveCursor }): Promise<ArchivePage> {
    const id = identifier(deviceID)
    if (typeof options.chatKey !== 'string' || !options.chatKey.length || new TextEncoder().encode(options.chatKey).length > 512) throw new ArchiveError('invalid_chat')
    const query: Record<string, string> = { chat_key: options.chatKey, limit: String(limit(options.limit, 50, 200)) }
    if (options.before) {
      if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(options.before.ts) ||
        !Number.isFinite(Date.parse(options.before.ts)) || !Number.isSafeInteger(options.before.seq) || options.before.seq < 1) throw new ArchiveError('invalid_cursor')
      query.before_ts = options.before.ts; query.before_seq = String(options.before.seq)
    }
    const result = await this.get<ArchivePage>(`/v1/devices/${id}/messages`, query)
    valid(Array.isArray(result.messages) && result.messages.length <= limit(options.limit, 50, 200) && typeof result.chat_key === 'string' && typeof result.has_more === 'boolean')
    for (const message of result.messages) messageShape(message)
    valid(!result.has_more || (typeof result.next_ts === 'string' && Number.isFinite(Date.parse(result.next_ts)) && nonnegative(result.next_seq) && result.next_seq > 0))
    if (result.messages.some(message => message.device_id !== id)) throw new ArchiveError('device_mismatch')
    if (result.chat_key !== options.chatKey) throw new ArchiveError('chat_mismatch')
    return result
  }
  async getMessage(uid: string): Promise<ArchiveMessage> {
    const id = identifier(uid), result = await this.get<ArchiveMessage>(`/v1/messages/${id}`)
    messageShape(result)
    if (result.uid !== id) throw new ArchiveError('message_mismatch')
    return result
  }
  async history(uid: string): Promise<ArchiveHistory> {
    const id = identifier(uid), result = await this.get<ArchiveHistory>(`/v1/messages/${id}/history`)
    valid(isID(result.device_id) && isID(result.requested_uid) && typeof result.chat_key === 'string' && typeof result.wa_id === 'string' && Array.isArray(result.versions))
    if (result.requested_uid !== id) throw new ArchiveError('message_mismatch')
    for (const version of result.versions) {
      valid(record(version) && nonnegative(version.revision)); messageShape(version.message)
      if (version.message.device_id !== result.device_id) throw new ArchiveError('device_mismatch')
    }
    if (result.deletion !== undefined) { valid(record(result.deletion)); messageShape(result.deletion.message) }
    if (result.reactions !== undefined) {
      valid(Array.isArray(result.reactions))
      for (const reaction of result.reactions) { valid(record(reaction)); messageShape(reaction.message) }
    }
    const entries = [...result.versions.map(version => version.message), ...(result.deletion ? [result.deletion.message] : []), ...(result.reactions?.map(reaction => reaction.message) ?? [])]
    // A control-row UID resolves to its original message's thread. requested_uid
    // binds the response to the route even if that row is folded into metadata.
    if (entries.some(message => message.device_id !== result.device_id)) throw new ArchiveError('device_mismatch')
    if (entries.some(message => message.chat_key !== result.chat_key)) throw new ArchiveError('chat_mismatch')
    return result
  }
  async grants(): Promise<ArchiveGrants> {
    const result = await this.get<ArchiveGrants>('/v1/grants')
    valid(isID(result.user_id) && Array.isArray(result.grants) && result.grants.every(grant => record(grant) && isID(grant.device_id) &&
      (grant.archive_tenant_id === undefined || isID(grant.archive_tenant_id)) && nonnegative(grant.epoch) && grant.epoch > 0 && grant.epoch <= 65535 && typeof grant.sealed_dsk === 'string'))
    return result
  }
  async contentKeys(deviceID: string, ids: number[]): Promise<ArchiveKeys> {
    const id = identifier(deviceID)
    if (!Array.isArray(ids) || ids.length < 1 || ids.length > 500 || ids.some(value => !Number.isSafeInteger(value) || value <= 0 || value > 2147483647)) throw new ArchiveError('invalid_keys')
    const result = await this.get<ArchiveKeys>(`/v1/devices/${id}/keys`, { ids: [...new Set(ids)].join(',') })
    valid(isID(result.device_id) && (result.archive_tenant_id === undefined || isID(result.archive_tenant_id)) && Array.isArray(result.keys) &&
      result.keys.every(key => record(key) && nonnegative(key.id) && key.id > 0 && typeof key.sealed === 'string' && ids.includes(key.id)))
    if (result.device_id !== id) throw new ArchiveError('device_mismatch')
    return result
  }
  /** Adapter for local decryption. It can request only this device's sealed keys. */
  keySource(deviceID: string): KeySource {
    const id = identifier(deviceID)
    return { request: async <T>(type: string, payload: unknown, wantType: string): Promise<T> => {
      const input = payload as { device_id?: string; ids?: number[] }
      if (type !== 'keys.get' || wantType !== 'keys' || input?.device_id !== id) throw new ArchiveError('invalid_key_request')
      return await this.contentKeys(id, input.ids!) as T
    } }
  }
}
