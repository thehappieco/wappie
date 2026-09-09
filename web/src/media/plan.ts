import { t } from '../ui/i18n'
// How a file is going to be sent, decided before anything is read.
//
// WhatsApp has one file and several ways of carrying it, and they are not
// interchangeable: the same photograph is a compressed picture, a full-quality
// picture, or a document, and the same recording is an audio file or a voice
// note. The recipient's screen differs in each case, and so does what our own
// archive keeps.
//
// This module is the whole decision and none of the work. It touches no DOM,
// reads no bytes and makes no request, which is why every rule below can be
// tested — and every one of them is a refusal that would otherwise cost a
// round trip, or worse, produce a message that arrives and cannot be opened.

/**
 * Kind is what the wire calls an attachment.
 *
 * Fixed on the server side (internal/domain/envelope.go) and repeated in three
 * places that must agree: the `?type=` on the upload, which picks the HKDF
 * label the media key is derived from; the `type` on the send frame, which
 * picks the protobuf field; and the media_type stored in the archive, which is
 * what this client later derives its decryption keys from. Two of the three
 * disagreeing produces a file nobody can open, with no error anywhere.
 */
export type Kind = 'image' | 'video' | 'ptv' | 'audio' | 'ptt' | 'document' | 'sticker'

/** Choice is a way of sending, as somebody would describe it. */
export type Choice =
  /** A picture, resized the way a phone does it. */
  | 'photo'
  /** A picture at full resolution. */
  | 'photo_hd'
  /** The bytes untouched, as a document. What "enviar como arquivo" means. */
  | 'file'
  | 'video'
  /** A video that loops silently. WhatsApp has no GIF type, only this flag. */
  | 'gif'
  /** A round video note. */
  | 'ptv'
  /** An audio file, with an ordinary player. */
  | 'audio'
  /** A voice note: waveform, play button, and "ouvida" instead of "lida". */
  | 'voice'
  | 'sticker'

/** Plan is everything the rest of the pipeline needs, and nothing it does not. */
export interface Plan {
  choice: Choice
  kind: Kind
  /** Shown in the picker. */
  label: string
  /** What the recipient gets, in a few words. Worth saying: the choices differ. */
  note: string
  /** Re-encode to this, or empty to send the bytes exactly as they are. */
  encodeTo: '' | 'image/jpeg' | 'image/webp'
  /**
   * The longest side to fit within, when re-encoding. Zero leaves it alone.
   *
   * Not arbitrary: a picture already smaller than this is passed through rather
   * than re-encoded, because recompressing an image that needs no resizing only
   * loses detail.
   */
  maxLongSide: number
  /** JPEG/WebP quality when re-encoding. */
  quality: number
  /**
   * Whether `encodeTo` is the only format that will do.
   *
   * A photograph is happy as a PNG or a JPEG, so one already small enough is
   * passed through rather than recompressed. A sticker is not: WhatsApp's
   * sticker message is WebP, and a PNG inside one is a bubble that does not
   * render — so a small PNG chosen as a sticker still has to be converted.
   */
  strictFormat: boolean
  captionAllowed: boolean
  viewOnceAllowed: boolean
  /** A document without one leaves the recipient an unnamed download. */
  needsFileName: boolean
  /** Worth measuring before sending: absent means the player shows nothing. */
  wantsDuration: boolean
  wantsDimensions: boolean
  wantsWaveform: boolean
  wantsThumbnail: boolean
  isGIF: boolean
}

/**
 * MAX_BYTES mirrors the server's default ceiling (WS_MEDIA_MAX_BYTES).
 *
 * Checked here as well as there because the server checks it *after* streaming
 * the whole file to WhatsApp: a file over the limit would upload completely,
 * show a progress bar reaching the end, and only then be refused. The server
 * remains the authority — a deployment may have lowered it — so a refusal from
 * it is still reported rather than assumed impossible.
 */
export const MAX_BYTES = 256 * 1024 * 1024

/** WhatsApp's own ceiling for a picture sent as a picture, roughly. */
const PHOTO_LONG_SIDE = 1600
/**
 * What "HD" means here.
 *
 * There is no HD flag in the protobuf this build compiles against; HD is
 * nothing but the resolution of the bytes uploaded. So the honest distinction
 * is a larger bound and a higher quality, and the note in the picker says so.
 */
const HD_LONG_SIDE = 3000
/** A sticker is square and small. WhatsApp's own are 512×512 WebP. */
const STICKER_SIDE = 512

const base: Omit<Plan, 'choice' | 'kind' | 'label' | 'note'> = {
  encodeTo: '',
  maxLongSide: 0,
  quality: 0.8,
  strictFormat: false,
  captionAllowed: true,
  viewOnceAllowed: false,
  needsFileName: false,
  wantsDuration: false,
  wantsDimensions: false,
  wantsWaveform: false,
  wantsThumbnail: false,
  isGIF: false,
}

const PLANS: Record<Choice, Plan> = {
  photo: {
    ...base,
    choice: 'photo',
    kind: 'image',
    get label() { return t('Foto') },
    get note() { return t('reduzida para {v0} px no lado maior', { v0: PHOTO_LONG_SIDE }) },
    encodeTo: 'image/jpeg',
    maxLongSide: PHOTO_LONG_SIDE,
    quality: 0.72,
    viewOnceAllowed: true,
    wantsDimensions: true,
    wantsThumbnail: true,
  },
  photo_hd: {
    ...base,
    choice: 'photo_hd',
    kind: 'image',
    get label() { return t('Foto HD') },
    get note() { return t('até {v0} px, com menos compressão', { v0: HD_LONG_SIDE }) },
    encodeTo: 'image/jpeg',
    maxLongSide: HD_LONG_SIDE,
    quality: 0.9,
    viewOnceAllowed: true,
    wantsDimensions: true,
    wantsThumbnail: true,
  },
  file: {
    ...base,
    choice: 'file',
    kind: 'document',
    get label() { return t('Arquivo') },
    get note() { return t('os bytes originais, sem recompressão') },
    needsFileName: true,
    wantsThumbnail: true,
  },
  video: {
    ...base,
    choice: 'video',
    kind: 'video',
    get label() { return t('Vídeo') },
    get note() { return t('com legenda e controles') },
    viewOnceAllowed: true,
    wantsDuration: true,
    wantsDimensions: true,
    wantsThumbnail: true,
  },
  gif: {
    ...base,
    choice: 'gif',
    kind: 'video',
    get label() { return t('GIF') },
    get note() { return t('roda em loop, sem som') },
    isGIF: true,
    viewOnceAllowed: true,
    wantsDuration: true,
    wantsDimensions: true,
    wantsThumbnail: true,
  },
  ptv: {
    ...base,
    choice: 'ptv',
    kind: 'ptv',
    get label() { return t('Vídeo redondo') },
    // Refused by the server, not dropped: a caption on a round video note is an
    // error, because there is no field for it to travel in.
    get note() { return t('recortado em círculo pelo destinatário; não aceita legenda') },
    captionAllowed: false,
    viewOnceAllowed: true,
    wantsDuration: true,
    wantsDimensions: true,
    wantsThumbnail: true,
  },
  audio: {
    ...base,
    choice: 'audio',
    kind: 'audio',
    get label() { return t('Áudio') },
    get note() { return t('toca como arquivo de música; não aceita legenda') },
    captionAllowed: false,
    viewOnceAllowed: true,
    wantsDuration: true,
  },
  voice: {
    ...base,
    choice: 'voice',
    kind: 'ptt',
    get label() { return t('Mensagem de voz') },
    get note() { return t('onda sonora, e conta como ouvida e não como lida') },
    captionAllowed: false,
    viewOnceAllowed: true,
    wantsDuration: true,
    wantsWaveform: true,
  },
  sticker: {
    ...base,
    choice: 'sticker',
    kind: 'sticker',
    get label() { return t('Figurinha') },
    get note() { return t('WebP de {v0}×{v1}; a legenda seria descartada', { v0: STICKER_SIDE, v1: STICKER_SIDE }) },
    encodeTo: 'image/webp',
    maxLongSide: STICKER_SIDE,
    quality: 0.9,
    strictFormat: true,
    captionAllowed: false,
    // A StickerMessage reads width and height, and reads no thumbnail at all.
    wantsDimensions: true,
  },
}

export function planFor(choice: Choice): Plan {
  return PLANS[choice]
}

/**
 * offer lists the ways this particular file can sensibly be sent, best first.
 *
 * Every file can be sent as a document, so that option is always last rather
 * than absent: it is the one that never re-encodes anything, and the one to
 * fall back on when the browser cannot decode what was picked.
 */
export function offer(file: { name: string; type: string }): Choice[] {
  switch (family(file)) {
    case 'image':
      // An animated source leads with the one choice that keeps the animation.
      // Everything else here re-encodes through a canvas, which sees a single
      // frame — a GIF sent as a photograph arrives frozen, and nothing in the
      // send reports that anything was lost.
      if (animatedSource(file)) return ['file', 'sticker', 'photo', 'photo_hd']
      // Compressed first otherwise, because that is what a phone does and what
      // most people mean by "mandar a foto".
      return ['photo', 'photo_hd', 'sticker', 'file']
    case 'video':
      return ['video', 'gif', 'ptv', 'file']
    case 'audio':
      // The voice note first only when the file is what WhatsApp records one
      // as. Anything else can still be sent as one — it is offered second, and
      // the picker says what is uncertain about it.
      return opusAudio(file) ? ['voice', 'audio', 'file'] : ['audio', 'voice', 'file']
    default:
      return ['file']
  }
}

/** family is the broad sort of file this is, from its mime type or its name. */
export function family(file: { name: string; type: string }): 'image' | 'video' | 'audio' | 'other' {
  const mime = (file.type || '').toLowerCase()
  if (mime.startsWith('image/')) return mime === 'image/svg+xml' ? 'other' : 'image'
  if (mime.startsWith('video/')) return 'video'
  if (mime.startsWith('audio/')) return 'audio'

  // Falling back to the extension, because a file dragged from some places
  // arrives with an empty type and picking "documento" for a photograph is a
  // worse answer than reading its name.
  switch (extension(file.name)) {
    case 'jpg':
    case 'jpeg':
    case 'png':
    case 'gif':
    case 'webp':
    case 'heic':
    case 'heif':
    case 'bmp':
      return 'image'
    case 'mp4':
    case 'mov':
    case 'm4v':
    case '3gp':
    case 'webm':
    case 'mkv':
      return 'video'
    case 'ogg':
    case 'opus':
    case 'oga':
    case 'm4a':
    case 'mp3':
    case 'aac':
    case 'wav':
    case 'flac':
      return 'audio'
    default:
      return 'other'
  }
}

export function extension(name: string): string {
  const dot = name.lastIndexOf('.')
  if (dot <= 0 || dot === name.length - 1) return ''
  return name.slice(dot + 1).toLowerCase()
}

/**
 * mimeFor is what the recipient renders from, so it is never left to chance.
 *
 * A plan that re-encodes dictates it. Everything else keeps the file's own type
 * when it has one, falls back to the extension, and only then to the type that
 * means "some bytes" — which renders as a download rather than as nothing.
 */
export function mimeFor(plan: Plan, file: { name: string; type: string }): string {
  if (plan.encodeTo) return plan.encodeTo
  return sourceMime(file)
}

/**
 * sourceMime is what the file already is, ignoring what a plan would make it.
 *
 * Needed on its own because a re-encoding plan does not always re-encode: a
 * picture already inside the bound is passed through untouched, and describing
 * those bytes by the format they were *going* to become is the exact mistake
 * the plan is careful not to make elsewhere.
 */
export function sourceMime(file: { name: string; type: string }): string {
  if (file.type) return file.type
  const byExtension: Record<string, string> = {
    jpg: 'image/jpeg',
    jpeg: 'image/jpeg',
    png: 'image/png',
    gif: 'image/gif',
    webp: 'image/webp',
    mp4: 'video/mp4',
    mov: 'video/quicktime',
    m4v: 'video/x-m4v',
    '3gp': 'video/3gpp',
    webm: 'video/webm',
    // Opus in an Ogg container is what WhatsApp records voice notes as, and
    // what its clients draw a waveform for.
    ogg: 'audio/ogg; codecs=opus',
    opus: 'audio/ogg; codecs=opus',
    oga: 'audio/ogg',
    m4a: 'audio/mp4',
    mp3: 'audio/mpeg',
    aac: 'audio/aac',
    wav: 'audio/wav',
    pdf: 'application/pdf',
    doc: 'application/msword',
    docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    xls: 'application/vnd.ms-excel',
    xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ppt: 'application/vnd.ms-powerpoint',
    pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    txt: 'text/plain',
    csv: 'text/csv',
    zip: 'application/zip',
    json: 'application/json',
  }
  return byExtension[extension(file.name)] ?? 'application/octet-stream'
}

/**
 * nameFor is what the download is called on the recipient's side.
 *
 * A plan that re-encodes has changed the bytes, so the old extension would be a
 * lie — a .png sent as JPEG under its original name is a file that will not
 * open in some readers.
 */
export function nameFor(plan: Plan, name: string): string {
  if (!plan.encodeTo) return name || t('arquivo')
  const stem = name.replace(/\.[^.]+$/, '') || 'imagem'
  return `${stem}.${plan.encodeTo === 'image/webp' ? 'webp' : 'jpg'}`
}

/** opusAudio reports whether this is what a voice note is normally made of. */
export function opusAudio(file: { name: string; type: string }): boolean {
  const mime = (file.type || '').toLowerCase()
  if (mime.includes('opus')) return true
  if (mime.startsWith('audio/ogg')) return true
  return ['ogg', 'opus', 'oga'].includes(extension(file.name))
}

/**
 * unusualVoiceNote reports a voice note made of something unexpected.
 *
 * Not refused: WhatsApp accepts the message and most clients play it. But it is
 * not what its own recorder produces, and a phone that will not play it gives
 * no reason — so it is worth saying before rather than wondering after.
 */
export function unusualVoiceNote(plan: Plan, file: { name: string; type: string }): boolean {
  return plan.choice === 'voice' && !opusAudio(file)
}

/** animatedSource reports whether the file could hold more than one frame. */
export function animatedSource(file: { name: string; type: string }): boolean {
  const mime = (file.type || '').toLowerCase()
  if (mime === 'image/gif' || mime === 'image/webp' || mime === 'image/apng') return true
  return ['gif', 'webp', 'apng'].includes(extension(file.name))
}

/**
 * losesAnimation reports a choice that will quietly flatten a moving image.
 *
 * Worth saying out loud in the picker. Re-encoding goes through a canvas, which
 * holds one frame; the send succeeds, the recipient gets a still, and nothing
 * anywhere reports that the other frames were dropped.
 */
export function losesAnimation(plan: Plan, file: { name: string; type: string }): boolean {
  if (!animatedSource(file)) return false
  // A WebP sticker is passed through rather than re-encoded when it already
  // fits, so it keeps whatever frames it had. See passesThrough.
  if (plan.choice === 'sticker' && isWebP(file)) return false
  return plan.encodeTo !== ''
}

function isWebP(file: { name: string; type: string }): boolean {
  return (file.type || '').toLowerCase() === 'image/webp' || extension(file.name) === 'webp'
}

/**
 * animatedWebP reports whether WebP bytes carry more than one frame.
 *
 * Read from the container rather than guessed from the extension, because it
 * decides is_animated on the outbound sticker — and a still sticker marked
 * animated, or the reverse, is a rendering difference on somebody else's
 * screen that this side never sees.
 *
 * The layout is RIFF: "RIFF" ???? "WEBP", then chunks. Only the extended form
 * (VP8X) can be animated, and it says so in bit 1 of its flag byte.
 */
export function animatedWebP(bytes: Uint8Array): boolean {
  if (bytes.length < 21) return false
  const tag = (at: number) => String.fromCharCode(bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3])
  if (tag(0) !== 'RIFF' || tag(8) !== 'WEBP') return false
  if (tag(12) !== 'VP8X') return false
  // Byte 20 is the flags. 0x02 is the animation bit.
  return (bytes[20] & 0x02) !== 0
}

/**
 * refuse reports why this cannot be sent, before anything is uploaded.
 *
 * Every one of these is something the server refuses too, and three of the four
 * come back from it as an *internal* error rather than a bad request — so
 * without this the person would be told the server broke when what happened is
 * that a voice note cannot carry a caption.
 */
export function refuse(plan: Plan, file: { name: string; size: number }, caption: string): string {
  if (file.size === 0) {
    return t('Este arquivo está vazio.')
  }
  if (file.size > MAX_BYTES) {
    return t('Arquivo de {v0} MB; o limite é {v1} MB.', { v0: Math.round(file.size / 1024 / 1024), v1: MAX_BYTES / 1024 / 1024 })
  }
  if (caption.trim() && !plan.captionAllowed) {
    // Refused here for all of them, though the wire treats them differently:
    // audio, voice notes and round video notes come back as an error, while a
    // sticker's caption is simply dropped on the floor with nothing said. The
    // second is the worse one to inherit — text somebody typed disappearing
    // between here and the recipient is indistinguishable from a lost message.
    return t('{v0} não leva legenda — o WhatsApp não tem campo para ela.', { v0: plan.label })
  }
  if (plan.needsFileName && !nameFor(plan, file.name).trim()) {
    return t('Um documento precisa de um nome, senão chega como um download sem título.')
  }
  return ''
}

/**
 * fitWithin scales dimensions down to a bound, never up.
 *
 * Separated out because it is the whole of what "HD" means in this system and
 * it is worth being able to check: there is no HD field in the protobuf, only
 * the resolution of the bytes that were uploaded.
 */
export function fitWithin(width: number, height: number, longSide: number): { width: number; height: number } {
  if (!longSide || width <= 0 || height <= 0) return { width, height }
  const longest = Math.max(width, height)
  if (longest <= longSide) return { width, height }
  const scale = longSide / longest
  return {
    width: Math.max(1, Math.round(width * scale)),
    height: Math.max(1, Math.round(height * scale)),
  }
}

/**
 * floorScore matches what the server does with a forwarding score.
 *
 * Two rules, and both are silent when broken. A score without the forwarded
 * flag is ignored entirely — the server only reads it inside `if forwarded` —
 * and a forwarded message with a score of zero draws no badge at all, because
 * the badge is drawn from the count. So the flag implies at least one.
 */
export function floorScore(forwarded: boolean, score: number): { forwarded: boolean; score: number } {
  const on = forwarded || score > 0
  if (!on) return { forwarded: false, score: 0 }
  return { forwarded: true, score: Math.max(1, Math.floor(score)) }
}
