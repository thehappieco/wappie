import { watch } from 'vue'
import * as P from '../api/protocol'
import { ProtocolError } from '../api/client'
import { uploadAttachment } from '../api/upload'
import { toBase64 } from '../crypto/bytes'
import { animatedWebP, MAX_BYTES } from '../media/plan'
import { connection, credential, people, readMediaBlob, state, type MessageView } from './archive'
import { normalizePhone } from './conversationActions'
import { t } from '../ui/i18n'

export type ForwardMark = 'forwarded' | 'many' | 'none'
export interface ForwardOutcome { ok: boolean; stale?: boolean; uncertain?: boolean; error?: string; warning?: string; chat?: string }
const mediaKinds = new Set(['image', 'video', 'ptv', 'audio', 'ptt', 'document', 'sticker'])
const running = new Set<string>()

/** Deliberately rebuild context: quotes, mentions and source timers belong to the original conversation. */
export function forwardOptions(mark: ForwardMark): P.SendOptions {
  return { forwarded: mark !== 'none', forwarding_score: mark === 'many' ? 5 : mark === 'forwarded' ? 1 : 0 }
}

export function forwardableContent(message: MessageView): boolean {
  if (message.pending || message.deleted || message.viewOnce || message.isStatus) return false
  if (message.media) return mediaKinds.has(message.media.type)
    && (message.bodyState === 'ok' || message.bodyState === 'absent' && !message.entry.row.body_sealed)
  return message.bodyState === 'ok' && message.type === 'text' && Boolean(message.body.trim())
}

export function canForward(message: MessageView): boolean {
  const conn = connection()
  const device = state.devices.find(value => value.id === state.deviceID)
  return Boolean(forwardableContent(message) && conn && credential() && state.connected && !state.initializingConnection && !state.unreadable
    && device?.running && device.can_send === true && message.entry.row.device_id === state.deviceID
    && conn.welcome.features.includes(message.media ? P.TypeSendMedia : P.TypeSend))
}

export function destinationJID(value: string): string {
  return /^(?:[1-9]\d{0,19}@(s\.whatsapp\.net|lid)|[1-9]\d{0,24}(?:-\d{1,24})?@g\.us)$/.test(value) ? value : ''
}

function messageID(): string {
  return [...crypto.getRandomValues(new Uint8Array(16))].map(byte => byte.toString(16).padStart(2, '0')).join('').toUpperCase()
}

/** Downloads can be shared with a visible bubble. Closing this action need not await that shared work. */
function abortable<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) { void work.catch(() => {}); return Promise.reject(signal.reason) }
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason)
    signal.addEventListener('abort', abort, { once: true })
    work.then(value => { signal.removeEventListener('abort', abort); resolve(value) }, error => { signal.removeEventListener('abort', abort); reject(error) })
  })
}

/** One explicit confirmation owns one ID, one recipient and one captured account. No automatic send retries. */
export function createForwarder(source: MessageView) {
  const captured = { conn: connection(), credential: credential(), tenant: state.tenantID, device: state.deviceID, chat: state.openChatKey, view: state.view }
  const id = messageID()
  const key = `${captured.tenant}:${captured.device}:${source.uid}`
  const controller = new AbortController()
  let busy = false
  let settled: ForwardOutcome | undefined
  let disposed = false
  const current = () => !disposed && connection() === captured.conn && credential()?.token === captured.credential?.token
    && credential()?.serverURL === captured.credential?.serverURL && state.tenantID === captured.tenant && state.deviceID === captured.device
    && state.openChatKey === captured.chat && state.view === captured.view
  const stop = watch(() => [state.tenantID, state.deviceID, state.openChatKey, state.view, state.connected], () => {
    if (!current() || !state.connected) controller.abort()
  }, { flush: 'sync' })
  function valid() { return current() && !controller.signal.aborted && canForward(source) }
  function stale(): ForwardOutcome { return { ok: false, stale: true } }

  async function forward(destination: string, mark: ForwardMark): Promise<ForwardOutcome> {
    if (settled) return settled
    if (!valid() || !captured.conn || !captured.credential) return stale()
    if (busy || running.has(key)) return { ok: false, error: t('Esta ação já está em andamento.') }
    if (!['forwarded', 'many', 'none'].includes(mark)) return { ok: false, error: t('Escolha como a mensagem será identificada.') }
    const phone = normalizePhone(destination)
    let chat = destinationJID(destination)
    if (!chat && (!phone || !captured.conn.welcome.features.includes(P.TypeChatStart))) {
      return { ok: false, error: t('Escolha uma conversa ou informe um número com código do país.') }
    }
    busy = true
    running.add(key)
    let dispatched = false
    try {
      if (!chat) {
        const result = await captured.conn.request<P.ChatStarted>(P.TypeChatStart, { device_id: captured.device, phone }, P.TypeChatStarted)
        if (!valid()) return stale()
        chat = destinationJID(result.chat)
        if (!chat) throw new Error(t('O servidor não confirmou um destinatário válido.'))
      }
      const options = forwardOptions(mark)
      let request: P.SendRequest | P.SendMediaRequest
      if (source.media) {
        const media = { ...source.media }
        // Use the verified full attachment; a thumbnail or an old sealed UploadRef is not the file.
        const blob = await abortable(readMediaBlob(source), controller.signal)
        if (!valid()) return stale()
        if (!blob) throw new Error(t('O anexo completo ainda não está disponível para reencaminhar.'))
        if (!blob.size || blob.size > MAX_BYTES) throw new Error(t('O arquivo está vazio ou ultrapassa o limite de envio.'))
        const upload = await abortable(uploadAttachment({ serverURL: captured.credential.serverURL, token: captured.credential.token,
          deviceID: captured.device, kind: media.type, blob, signal: controller.signal }), controller.signal)
        if (!valid()) return stale()
        if (upload.type && upload.type !== media.type) throw new Error(t('O tipo do anexo enviado não corresponde à mensagem.'))
        const mediaRequest: P.SendMediaRequest = { ...options, device_id: captured.device, chat, id, type: media.type, upload,
          mimetype: media.mimetype || blob.type || 'application/octet-stream', filename: media.fileName || (media.type === 'document' ? 'arquivo' : undefined) }
        if (['image', 'video', 'document'].includes(media.type) && source.body.trim()) mediaRequest.caption = source.body.trim()
        if (['image', 'video', 'ptv', 'sticker'].includes(media.type) && media.width > 0 && media.height > 0) {
          mediaRequest.width = media.width; mediaRequest.height = media.height
        }
        if (['video', 'ptv', 'audio', 'ptt'].includes(media.type) && media.seconds > 0) mediaRequest.seconds = media.seconds
        if (['audio', 'ptt'].includes(media.type) && media.waveform?.length === 64) mediaRequest.waveform = toBase64(Uint8Array.from(media.waveform))
        if (media.type === 'video' && media.isGIF) mediaRequest.is_gif = true
        if (media.type === 'sticker') mediaRequest.is_animated = animatedWebP(new Uint8Array(await blob.slice(0, 21).arrayBuffer()))
        request = mediaRequest
      } else {
        request = { ...options, device_id: captured.device, chat, id, body: source.body.trim() }
      }
      if (!valid()) return stale()
      dispatched = true
      const result = await captured.conn.request<P.SendResult>(source.media ? P.TypeSendMedia : P.TypeSend, request, P.TypeSendResult)
      // A successful send remains settled even if navigation happened while awaiting its acknowledgement.
      settled = { ok: true, chat, ...(!result.uid ? { warning: t('A mensagem foi enviada, mas não foi adicionada ao histórico.') } : {}) }
      return current() ? settled : { ...settled, stale: true }
    } catch (error) {
      const uncertain = dispatched && (!(error instanceof ProtocolError) || !['bad_request', 'not_authorized', 'not_found', 'unsupported'].includes(error.code))
      const outcome: ForwardOutcome = { ok: false, uncertain, error: uncertain
        ? t('A confirmação não chegou. Verifique a conversa de destino antes de reencaminhar novamente.')
        : error instanceof Error ? error.message : String(error) }
      if (uncertain) settled = outcome
      return current() ? outcome : { ...outcome, stale: true }
    } finally { busy = false; running.delete(key) }
  }
  return { forward, dispose() { disposed = true; controller.abort(); stop() } }
}

export const MAX_FORWARD_RECIPIENTS = 10
export interface ForwardRecipient { key: string; name: string }
export type ForwardRecipientState = 'pending' | 'sending' | 'sent' | 'failed' | 'uncertain' | 'duplicate' | 'cancelled'
export interface ForwardRecipientResult { recipient: ForwardRecipient; chat?: string; state: ForwardRecipientState; outcome?: ForwardOutcome }
export interface ForwardBatchOutcome { results: ForwardRecipientResult[]; error?: string; stale?: boolean }

/** Match exact, recorded aliases. Equal digits alone never prove a PN and a LID are the same person. */
export function forwardRecipientResolver(): (value: string) => string {
  const parents = new Map<string, string>()
  function root(key: string): string {
    const parent = parents.get(key)
    if (!parent || parent === key) return key
    const canonical = root(parent); parents.set(key, canonical); return canonical
  }
  function join(values: (string | undefined)[]) {
    const keys = values.filter((value): value is string => Boolean(value && destinationJID(value)))
    if (!keys.length) return
    // Group identities and individual identities can never be aliases.
    for (const group of [false, true]) {
      const set = keys.filter(key => key.endsWith('@g.us') === group).map(root)
      const canonical = set.sort((a, b) => Number(b.endsWith('@s.whatsapp.net')) - Number(a.endsWith('@s.whatsapp.net')) || a.localeCompare(b))[0]
      if (canonical) for (const key of set) parents.set(key, canonical)
    }
  }
  for (const person of people().all()) join([person.key, person.pn, person.lid])
  for (const chat of state.chats) if (!chat.isStatus) join([chat.key, ...chat.keys])
  return value => {
    const phone = normalizePhone(value)
    const jid = phone ? phone.slice(1) + '@s.whatsapp.net' : destinationJID(value.trim())
    return jid ? root(jid) : ''
  }
}

const batches = new Set<string>()

/** A confirmed batch is immutable and is attempted once. Each destination owns its own message ID. */
export function createForwardBatch(source: MessageView) {
  const captured = { conn: connection(), credential: credential(), tenant: state.tenantID, device: state.deviceID, chat: state.openChatKey, view: state.view }
  const key = `${captured.tenant}:${captured.device}:${source.uid}`
  const controller = new AbortController()
  let disposed = false
  let work: Promise<ForwardBatchOutcome> | undefined
  let active: ReturnType<typeof createForwarder> | undefined
  const current = () => !disposed && connection() === captured.conn && credential()?.token === captured.credential?.token
    && credential()?.serverURL === captured.credential?.serverURL && state.tenantID === captured.tenant && state.deviceID === captured.device
    && state.openChatKey === captured.chat && state.view === captured.view && state.connected && canForward(source)
  const stop = watch(() => [state.tenantID, state.deviceID, state.openChatKey, state.view, state.connected], () => {
    if (!current()) { controller.abort(); active?.dispose() }
  }, { flush: 'sync' })

  function forward(recipients: ForwardRecipient[], mark: ForwardMark, onUpdate?: (results: ForwardRecipientResult[]) => void): Promise<ForwardBatchOutcome> {
    if (work) return work
    if (!current() || !captured.conn || !captured.credential) return Promise.resolve({ results: [], stale: true })
    if (!recipients.length || recipients.length > MAX_FORWARD_RECIPIENTS) return Promise.resolve({ results: [], error: t('Selecione de 1 a {max} destinatários.', { max: MAX_FORWARD_RECIPIENTS }) })
    if (!['forwarded', 'many', 'none'].includes(mark)) return Promise.resolve({ results: [], error: t('Escolha como a mensagem será identificada.') })
    if (batches.has(key)) return Promise.resolve({ results: [], error: t('Esta ação já está em andamento.') })
    const results: ForwardRecipientResult[] = recipients.map(recipient => ({ recipient: { ...recipient }, state: 'pending' }))
    const snapshot = () => results.map(row => ({ ...row, recipient: { ...row.recipient } }))
    const publish = () => onUpdate?.(snapshot())
    const stopped = (): ForwardBatchOutcome => {
      for (const row of results) if (row.state === 'pending') row.state = 'cancelled'
      publish()
      return { results: snapshot(), stale: true }
    }
    batches.add(key)
    work = (async (): Promise<ForwardBatchOutcome> => {
      try {
        const identity = forwardRecipientResolver()
        const original = new Set<string>()
        const destinations = new Set<string>()
        publish()
        // Resolve every phone before sending any copy. This catches aliases in the confirmed list.
        for (const row of results) {
          if (!current() || controller.signal.aborted) return stopped()
          const canonical = identity(row.recipient.key)
          if (!canonical) { row.state = 'failed'; row.outcome = { ok: false, error: t('Escolha uma conversa ou informe um número com código do país.') }; continue }
          if (original.has(canonical)) { row.state = 'duplicate'; continue }
          original.add(canonical)
          try {
            const phone = normalizePhone(row.recipient.key)
            let chat = destinationJID(row.recipient.key.trim())
            if (!chat && phone && captured.conn!.welcome.features.includes(P.TypeChatStart)) {
              const result = await abortable(captured.conn!.request<P.ChatStarted>(P.TypeChatStart, { device_id: captured.device, phone }, P.TypeChatStarted), controller.signal)
              if (!current() || controller.signal.aborted) return stopped()
              chat = destinationJID(result.chat)
            }
            if (!chat) throw new Error(t('O servidor não confirmou um destinatário válido.'))
            row.chat = chat
            const target = identity(chat)
            if (destinations.has(target)) row.state = 'duplicate'
            else destinations.add(target)
          } catch (error) {
            if (!current() || controller.signal.aborted) return stopped()
            row.state = 'failed'; row.outcome = { ok: false, error: error instanceof Error ? error.message : String(error) }
          }
        }
        publish()
        for (const row of results) {
          if (row.state !== 'pending' || !row.chat) continue
          if (!current() || controller.signal.aborted) return stopped()
          active = createForwarder(source)
          row.state = 'sending'; publish()
          try {
            const outcome = await active.forward(row.chat, mark)
            row.outcome = outcome
            row.state = outcome.ok ? 'sent' : outcome.uncertain ? 'uncertain' : outcome.stale ? 'cancelled' : 'failed'
          } catch {
            // A surprising failure after entering the sender must not invite a duplicate copy.
            row.state = 'uncertain'; row.outcome = { ok: false, uncertain: true, error: t('A confirmação não chegou. Verifique a conversa de destino antes de reencaminhar novamente.') }
          } finally { active.dispose(); active = undefined }
          publish()
          if (!current() || controller.signal.aborted) return stopped()
        }
        return { results: snapshot() }
      } finally { batches.delete(key) }
    })()
    return work
  }
  return { forward, dispose() { disposed = true; controller.abort(); active?.dispose(); stop() } }
}
