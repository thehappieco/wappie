// The cheap checks of an open_attachment call (docs/mcp-enclave.md §16.5,
// steps 3 and 9 to 16), from the request and the row alone: no key is
// opened and no ciphertext asked for before every one of them has passed.
// `whyNot` is the same order for get_message's `openable` (§16.7).
import { ArchiveError } from '@whatserver2/client'
import { CAP_BYTES, HOST_WAIT_MS, MEDIA_KINDS, MEDIA_TYPES, PDF_PAGES_PER_REQUEST } from './policy.mjs'

/**
 * A refusal the reader turns into its §16.7 answer. `retry_after_s` (a
 * RETRY_AFTER_S value) and `facts` (what the guidance quotes, and the row's
 * visible metadata) ride along as own properties.
 */
export function refusal(code, { retry_after_s, facts } = {}) {
  const error = new ArchiveError(code)
  if (retry_after_s !== undefined) error.retry_after_s = retry_after_s
  if (facts !== undefined) error.facts = facts
  return error
}

/** `media_off` as Go sent it, cut to the kinds this reader knows. */
export const knownKinds = value => (Array.isArray(value) ? [...new Set(value.filter(word => MEDIA_KINDS.includes(word)))].sort() : [])

/** The host profile of a redirect host: itself when it is one with a profile, else 'default'. */
export const hostOf = redirectHost => (redirectHost === 'chatgpt.com' || redirectHost === 'claude.ai' ? redirectHost : 'default')
/**
 * The host profile of a record (docs/mcp-enclave.md §19.23): from reader
 * 0.6.0 its own `profile`, the tested entry's (`default` for a client nobody
 * tested and for a console token), never its redirect host, which a loopback
 * client shares with its vendor's web client; a record 0.5.0 wrote keeps
 * `hostOf(redirect_host)`.
 */
export const profileOf = record => (typeof record?.profile === 'string' ? hostOf(record.profile) : hostOf(record?.redirect_host))
export const waitFor = host => HOST_WAIT_MS[host] ?? HOST_WAIT_MS.default

/** The row's visible metadata an error line repeats, and the console link of its message when there is one (§16.7). */
export function rowFacts(row, openURL) {
  const media = row?.media ?? {}
  const facts = {}
  if (typeof media.media_type === 'string') facts.media_type = media.media_type
  if (typeof media.mimetype === 'string') facts.mimetype = media.mimetype
  if (Number.isSafeInteger(media.file_length)) facts.file_length = media.file_length
  if (typeof openURL === 'string') facts.open_url = openURL
  return facts
}

/**
 * Step 3: `cursor` with `pages`, or a range backwards or over
 * PDF_PAGES_PER_REQUEST pages, is `invalid_cursor`. Returns the parsed
 * request: `cursor` as {unit, at} and `pages` as {from, to}.
 */
export function parseRequest({ uid, cursor, pages, images = true }) {
  if (cursor !== undefined && pages !== undefined) throw refusal('invalid_cursor')
  let range
  if (pages !== undefined) {
    const [from, to = from] = pages.split('-').map(Number)
    if (!Number.isSafeInteger(from) || !Number.isSafeInteger(to) || from < 1 || to < from || to - from + 1 > PDF_PAGES_PER_REQUEST) throw refusal('invalid_cursor')
    range = { from, to }
  }
  let at
  if (cursor !== undefined) {
    const match = /^([pc])(\d{1,9})$/.exec(cursor)
    if (!match) throw refusal('invalid_cursor')
    at = { unit: match[1] === 'p' ? 'page' : 'char', at: Number(match[2]) }
  }
  return { uid, cursor: at, pages: range, images: images !== false }
}

/** The kind an attachment is known to be before its plaintext is sniffed: 'image' for images, stickers and a video's preview. */
export function kindBeforeSniff(mediaType) {
  const family = MEDIA_TYPES[mediaType]?.family
  if (family === 'image' || family === 'video') return 'image'
  if (family === 'audio') return 'audio'
  return null
}

/** A document is refused before the fetch only when every kind it could sniff as is off. */
const documentKinds = ['pdf', 'office', 'text', 'zip', 'image']

const hash32 = value => {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return null
  const decoded = Buffer.from(value, 'base64')
  return decoded.length === 32 && decoded.toString('base64') === value ? decoded : null
}

/**
 * Steps 9 to 16 but the byte budget, in order, on the row: returns
 * `{family, label, preview, kind, encSHA256}` or throws the refusal, whose
 * facts carry `openURL` when given. `preview` is a video's path (no fetch,
 * the sealed preview only); `hasPreview` says whether it has one.
 */
export function checkRow(row, request, mediaOff, openURL) {
  const media = row.media
  const facts = rowFacts(row, openURL)
  const refuse = (code, extra = {}) => refusal(code, { facts: { ...facts, ...extra } })
  if (row.view_once === true) throw refuse('view_once_excluded')
  const type = Object.hasOwn(MEDIA_TYPES, media.media_type) ? MEDIA_TYPES[media.media_type] : null
  if (!type) throw refuse('attachment_unsupported')
  if (type.family === 'audio') throw refuse('transcription_unavailable')
  if ((type.family === 'image' || type.family === 'video') && (request.cursor || request.pages)) throw refuse('invalid_cursor')
  const kind = kindBeforeSniff(media.media_type)
  if (kind && mediaOff.includes(kind)) throw refuse('media_not_allowed')
  if (type.family === 'document' && documentKinds.every(item => mediaOff.includes(item))) throw refuse('media_not_allowed')
  if (type.family === 'video') return { family: 'video', label: type.label, preview: true, hasPreview: typeof media.thumb_sealed === 'string' && media.thumb_sealed.length > 0, kind }
  if (media.download_status !== 'done') {
    if (['pending', 'downloading', 'failed'].includes(media.download_status)) throw refuse('attachment_pending')
    if (media.download_status === 'gone') throw refuse('attachment_expired')
    throw refuse('read_failed')
  }
  const encSHA256 = hash32(media.file_enc_sha256)
  if (typeof media.media_key_sealed !== 'string' || !media.media_key_sealed || !encSHA256) throw refuse('attachment_unverifiable')
  const cap = CAP_BYTES[type.family]
  if (media.file_length !== undefined && (!Number.isSafeInteger(media.file_length) || media.file_length > cap)) {
    throw refuse('attachment_too_large', { size: media.file_length, cap, family: type.family })
  }
  return { family: type.family, label: type.label, preview: false, kind, encSHA256 }
}

/**
 * Why get_message's attachment cannot be opened, from the row alone, or
 * null (§16.7): `view_once`, `unsupported`, `not_transcribed`, `expired`,
 * `pending`, `unverifiable`, `too_large`, `kind_off`, in that order. A video
 * is openable whenever its view-once and kind checks pass. With `aiCap` (the
 * audio cap of a reader that declares ai_v1, §18.12), audio and voice notes
 * are no longer `not_transcribed`: they go through the download, hash and
 * size checks like a document, with kind `audio`, and open_attachment
 * answers whether an AI integration covers them.
 */
export function whyNot(row, mediaOff, aiCap) {
  const media = row?.media
  if (!media) return null
  if (row.view_once === true) return 'view_once'
  const type = Object.hasOwn(MEDIA_TYPES, media.media_type) ? MEDIA_TYPES[media.media_type] : null
  if (!type) return 'unsupported'
  if (type.family === 'audio' && aiCap !== undefined) {
    if (media.download_status === 'gone') return 'expired'
    if (media.download_status !== 'done') return 'pending'
    if (typeof media.media_key_sealed !== 'string' || !media.media_key_sealed || !hash32(media.file_enc_sha256)) return 'unverifiable'
    if (media.file_length !== undefined && (!Number.isSafeInteger(media.file_length) || media.file_length > aiCap)) return 'too_large'
    return mediaOff.includes('audio') ? 'kind_off' : null
  }
  if (type.family === 'audio') return 'not_transcribed'
  const kind = kindBeforeSniff(media.media_type)
  const off = (kind && mediaOff.includes(kind)) || (type.family === 'document' && documentKinds.every(item => mediaOff.includes(item)))
  if (type.family === 'video') return off ? 'kind_off' : null
  if (media.download_status === 'gone') return 'expired'
  if (media.download_status !== 'done') return 'pending'
  if (typeof media.media_key_sealed !== 'string' || !media.media_key_sealed || !hash32(media.file_enc_sha256)) return 'unverifiable'
  if (media.file_length !== undefined && (!Number.isSafeInteger(media.file_length) || media.file_length > CAP_BYTES[type.family])) return 'too_large'
  return off ? 'kind_off' : null
}
