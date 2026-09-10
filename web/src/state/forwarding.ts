import { watch } from 'vue'
import * as P from '../api/protocol'
import { ProtocolError } from '../api/client'
import { uploadAttachment } from '../api/upload'
import { toBase64 } from '../crypto/bytes'
import { animatedWebP, MAX_BYTES } from '../media/plan'
import { connection, credential, readMediaBlob, state, type MessageView } from './archive'
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
