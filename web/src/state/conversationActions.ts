import { reactive } from 'vue'
import * as P from '../api/protocol'
import { ProtocolError } from '../api/client'
import { connection, credential, loadChats, openChat, state } from './archive'
import { groups, loadGroup } from './groups'
import { t } from '../ui/i18n'

export interface ActionOutcome { ok: boolean; stale?: boolean; uncertain?: boolean; error?: string; warning?: string; chat?: string; failed?: string[] }
export interface PollInput { question: string; options: string[]; multiple: boolean }
export const conversationOperations = reactive(new Set<string>())
const connectionIDs = new WeakMap<object, number>()
let nextConnectionID = 0
const size = (value: string) => [...value].length

export function normalizePhone(value: string): string {
  if (!/^[+\d\s().-]+$/.test(value.trim())) return ''
  const digits = value.replace(/[\s().-]/g, '').replace(/^\+/, '')
  return /^[1-9]\d{6,14}$/.test(digits) ? '+' + digits : ''
}
export function participantID(value: string): string {
  const trimmed = value.trim()
  if (/^[1-9]\d{0,19}@(s\.whatsapp\.net|lid)$/.test(trimmed)) return trimmed
  return normalizePhone(trimmed)
}
export function participantsFromText(value: string): string[] { return value.split(/[\n,;]+/).map(part => part.trim()).filter(Boolean) }
export function participantsValidation(values: string[]): string {
  if (!values.length || values.length > 32) return t('Informe de 1 a 32 participantes por vez.')
  const normalized = values.map(participantID)
  if (normalized.some(value => !value)) return t('Use números com código do país, como +5511999999999, um por linha.')
  const canonical = normalized.map(value => value.startsWith('+') ? value.slice(1) + '@s.whatsapp.net' : value)
  if (new Set(canonical).size !== canonical.length) return t('Há participantes repetidos na lista.')
  return ''
}
export function groupValidation(input: { name: string; participants: string[] }): string {
  if (!input.name.trim() || size(input.name.trim()) > 100) return t('O nome do grupo deve ter de 1 a 100 caracteres.')
  return participantsValidation(input.participants)
}
export function pollValidation(input: PollInput): string {
  if (!input.question.trim() || size(input.question.trim()) > 255) return t('A pergunta deve ter de 1 a 255 caracteres.')
  if (input.options.length < 2 || input.options.length > 12) return t('Adicione de 2 a 12 opções à enquete.')
  const options = input.options.map(option => option.trim())
  if (options.some(option => !option || size(option) > 100)) return t('Cada opção deve ter de 1 a 100 caracteres.')
  if (new Set(options.map(option => option.toLowerCase())).size !== options.length) return t('As opções da enquete devem ser diferentes.')
  return ''
}

export function canConversationAction(action: string): boolean {
  const conn = connection()
  const device = state.devices.find(device => device.id === state.deviceID)
  if (!conn || !state.connected || state.initializingConnection || state.unreadable || !device?.running || !credential()) return false
  if (!conn.welcome.features.includes(action)) return false
  return [P.TypeChatStart, P.TypePollCreate, P.TypeLocationSend, P.TypeEventCreate].includes(action) ? device.can_send === true : device.can_manage === true
}
function context() {
  return { conn: connection(), token: credential()?.token, tenant: state.tenantID, device: state.deviceID, chat: state.openChatKey, view: state.view }
}
type Context = ReturnType<typeof context>
function current(captured: Context, includeChat = true): boolean {
  return connection() === captured.conn && credential()?.token === captured.token && state.tenantID === captured.tenant && state.deviceID === captured.device
    && state.view === captured.view && (!includeChat || state.openChatKey === captured.chat)
}
function operationKey(captured: Context, action: string): string {
  if (!captured.conn) return ''
  if (!connectionIDs.has(captured.conn)) connectionIDs.set(captured.conn, ++nextConnectionID)
  return `${connectionIDs.get(captured.conn)}:${captured.tenant}:${captured.device}:${action}:${captured.chat}`
}
async function perform<T>(action: string, payload: Record<string, unknown>, response: string): Promise<{ outcome: ActionOutcome; data?: T; captured?: Context }> {
  const captured = context()
  if (!canConversationAction(action) || !captured.conn) return { outcome: { ok: false, error: t('Seu acesso ou a conexão atual não permite esta ação.') } }
  const key = operationKey(captured, action)
  if (conversationOperations.has(key)) return { outcome: { ok: false, error: t('Esta ação já está em andamento.') } }
  conversationOperations.add(key)
  try {
    const data = await captured.conn.request<T>(action, { ...payload, device_id: captured.device }, response)
    if (!current(captured)) return { outcome: { ok: false, stale: true } }
    return { outcome: { ok: true }, data, captured }
  } catch (error) {
    if (!current(captured)) return { outcome: { ok: false, stale: true } }
    const uncertain = !(error instanceof ProtocolError) || ['internal', 'timeout', 'unavailable'].includes(error.code)
      || error.code === P.ErrConflict && [P.TypeGroupCreate, P.TypeGroupParticipants, P.TypeGroupLeave, P.TypePollCreate, P.TypeLocationSend, P.TypeEventCreate].includes(action)
    return { outcome: { ok: false, uncertain, error: uncertain
      ? t('A confirmação não chegou. A ação pode ter sido concluída no WhatsApp. Verifique antes de tentar novamente.')
      : error instanceof Error ? error.message : String(error) } }
  } finally { conversationOperations.delete(key) }
}
async function openCreated(chat: string, captured: Context): Promise<ActionOutcome> {
  let warning = ''
  try { await loadChats() } catch { warning = t('O WhatsApp confirmou a ação, mas a lista ainda não foi atualizada. Atualize as conversas.') }
  if (!current(captured)) return { ok: true, stale: true, chat }
  try { await openChat(chat) } catch { warning = t('O WhatsApp confirmou a ação, mas a lista ainda não foi atualizada. Atualize as conversas.') }
  return current(captured, false) ? { ok: true, chat, warning } : { ok: true, stale: true, chat }
}
export async function startConversation(phone: string): Promise<ActionOutcome> {
  const normalized = normalizePhone(phone)
  if (!normalized) return { ok: false, error: t('Use um número com código do país, como +5511999999999.') }
  const result = await perform<P.ChatStarted>(P.TypeChatStart, { phone: normalized }, P.TypeChatStarted)
  return result.data && result.captured ? openCreated(result.data.chat, result.captured) : result.outcome
}
export async function createGroup(input: { name: string; participants: string[] }): Promise<ActionOutcome> {
  const error = groupValidation(input)
  if (error) return { ok: false, error }
  const result = await perform<P.GroupChanged>(P.TypeGroupCreate, { name: input.name.trim(), participants: input.participants.map(participantID) }, P.TypeGroupChanged)
  if (!result.data || !result.captured) return result.outcome
  const opened = await openCreated(result.data.chat, result.captured)
  return { ...opened, failed: result.data.participants?.filter(participant => participant.error).map(participant => participant.jid) ?? [] }
}
function groupAllows(action: 'add' | 'remove' | 'leave'): boolean {
  const group = groups.get(state.openChatKey)
  return Boolean(group?.permissions_known && group.refreshed && group.is_member && (action === 'leave' || group.can_manage))
}
export function canChangeGroup(action: 'add' | 'remove' | 'leave'): boolean {
  return canConversationAction(action === 'leave' ? P.TypeGroupLeave : P.TypeGroupParticipants) && groupAllows(action)
}
export async function changeGroupParticipants(action: 'add' | 'remove', participants: string[]): Promise<ActionOutcome> {
  const error = participantsValidation(participants)
  if (error) return { ok: false, error }
  if (!canChangeGroup(action)) return { ok: false, error: t('Atualize o grupo para confirmar sua permissão no WhatsApp.') }
  const result = await perform<P.GroupChanged>(P.TypeGroupParticipants, { chat: state.openChatKey, action, participants: participants.map(participantID) }, P.TypeGroupChanged)
  if (!result.data || !result.captured) return result.outcome
  await loadGroup(result.captured.chat)
  if (!current(result.captured)) return { ok: true, stale: true }
  return { ok: true, failed: result.data.participants?.filter(participant => participant.error).map(participant => participant.jid) ?? [] }
}
export async function leaveGroup(): Promise<ActionOutcome> {
  if (!canChangeGroup('leave')) return { ok: false, error: t('Atualize o grupo para confirmar sua permissão no WhatsApp.') }
  const device = state.devices.find(device => device.id === state.deviceID)
  const self = new Set([device?.pn, device?.lid].filter((value): value is string => Boolean(value)))
  const result = await perform<P.GroupChanged>(P.TypeGroupLeave, { chat: state.openChatKey }, P.TypeGroupChanged)
  if (!result.data || !result.captured) return result.outcome
  const group = groups.get(result.captured.chat)
  if (group) {
    group.is_member = false
    group.can_manage = false
    // Only this device's confirmed departure is known. Other participants
    // remain as recorded; the departed device cannot reliably refresh them.
    group.members = group.members.filter(member => ![member.key, member.pn, member.lid].some(alias => alias && self.has(alias)))
  }
  await loadChats().catch(() => {})
  return current(result.captured) ? { ok: true } : { ok: true, stale: true }
}
export async function createPoll(input: PollInput): Promise<ActionOutcome> {
  const error = pollValidation(input)
  if (error) return { ok: false, error }
  if (!state.openChatKey) return { ok: false, error: t('Abra uma conversa para criar a enquete.') }
  return (await perform<P.SendResult>(P.TypePollCreate, { chat: state.openChatKey, question: input.question.trim(),
    options: input.options.map(option => option.trim()), selectable_count: input.multiple ? 0 : 1 }, P.TypeSendResult)).outcome
}

export interface LocationInput { lat: number; lon: number; name?: string; address?: string; accuracy_m?: number }
export function locationValidation(input: LocationInput): string {
  if (!Number.isFinite(input.lat) || input.lat < -90 || input.lat > 90 || !Number.isFinite(input.lon) || input.lon < -180 || input.lon > 180)
    return t('Informe latitude de −90 a 90 e longitude de −180 a 180.')
  if (size(input.name?.trim() ?? '') > 100 || size(input.address?.trim() ?? '') > 500)
    return t('Use até 100 caracteres no nome e 500 no endereço.')
  if (input.accuracy_m !== undefined && (!Number.isInteger(input.accuracy_m) || input.accuracy_m < 0 || input.accuracy_m > 4294967295))
    return t('A precisão da localização é inválida.')
  return ''
}
export async function sendLocation(input: LocationInput): Promise<ActionOutcome> {
  const error = locationValidation(input)
  if (error) return { ok: false, error }
  if (!state.openChatKey) return { ok: false, error: t('Abra uma conversa para enviar a localização.') }
  return (await perform<P.SendResult>(P.TypeLocationSend, { chat: state.openChatKey, id: crypto.randomUUID(), lat: input.lat, lon: input.lon,
    name: input.name?.trim() || undefined, address: input.address?.trim() || undefined, accuracy_m: input.accuracy_m }, P.TypeSendResult)).outcome
}

export type EventInput = Omit<P.EventCreateRequest, 'device_id' | 'chat' | 'id'>

/** RFC3339 instants only: Date.parse alone silently accepts impossible days. */
function eventInstant(value: string): number {
  const parts = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})$/.exec(value)
  if (!parts) return NaN
  const [, year, month, day, hour, minute, second, zone] = parts
  const calendar = new Date(`${year}-${month}-${day}T00:00:00Z`)
  if (!Number.isFinite(calendar.getTime()) || calendar.getUTCFullYear() !== Number(year)
    || calendar.getUTCMonth() + 1 !== Number(month) || calendar.getUTCDate() !== Number(day)
    || Number(hour) > 23 || Number(minute) > 59 || Number(second) > 59
    || zone !== 'Z' && (Number(zone!.slice(1, 3)) > 23 || Number(zone!.slice(4)) > 59)) return NaN
  // WhatsApp timestamps use whole Unix seconds.
  return Math.floor(Date.parse(value) / 1000) * 1000
}

export function eventValidation(input: EventInput, now = Date.now()): string {
  if (!input.name.trim() || size(input.name.trim()) > 100) return t('O nome do evento deve ter de 1 a 100 caracteres.')
  if (size(input.description?.trim() ?? '') > 2048) return t('A descrição do evento permite até 2048 caracteres.')
  if (size(input.location_name?.trim() ?? '') > 500) return t('O local do evento permite até 500 caracteres.')
  const start = eventInstant(input.start_time)
  const limit = Date.UTC(2200, 0, 1)
  if (!Number.isFinite(start) || start >= limit) return t('Informe uma data e hora de início válidas, anteriores ao ano 2200.')
  if (start <= now) return t('Escolha uma data e hora de início no futuro.')
  if (input.end_time) {
    const end = eventInstant(input.end_time)
    if (!Number.isFinite(end) || end >= limit || end <= start) return t('O término deve ser posterior ao início e anterior ao ano 2200.')
  }
  const link = input.join_link?.trim()
  if (link) {
    let valid = false
    try {
      const url = new URL(link)
      valid = new TextEncoder().encode(link).length <= 2048 && !/[\s\u0000-\u001f\u007f\\]/u.test(link)
        && url.protocol === 'https:' && url.hostname === 'call.whatsapp.com' && !url.port
        && !url.username && !url.password && url.pathname.replace(/^\/+|\/+$/g, '').length > 0
    } catch { /* Keep malformed links in the form instead of sending them. */ }
    if (!valid) return t('Use um link de chamada https://call.whatsapp.com/. Outros links podem ser incluídos na descrição.')
  }
  return ''
}

export async function createEvent(input: EventInput): Promise<ActionOutcome> {
  const error = eventValidation(input)
  if (error) return { ok: false, error }
  if (!state.openChatKey) return { ok: false, error: t('Abra uma conversa para criar o evento.') }
  return (await perform<P.SendResult>(P.TypeEventCreate, { chat: state.openChatKey, id: crypto.randomUUID(),
    name: input.name.trim(), description: input.description?.trim() || undefined,
    start_time: input.start_time, end_time: input.end_time || undefined,
    location_name: input.location_name?.trim() || undefined, join_link: input.join_link?.trim() || undefined,
  }, P.TypeSendResult)).outcome
}
