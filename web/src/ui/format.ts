// Rendering helpers.

const time = new Intl.DateTimeFormat('pt-BR', { hour: '2-digit', minute: '2-digit' })
const dayLong = new Intl.DateTimeFormat('pt-BR', { day: '2-digit', month: 'long', year: 'numeric' })
const dayShort = new Intl.DateTimeFormat('pt-BR', { day: '2-digit', month: '2-digit' })
const full = new Intl.DateTimeFormat('pt-BR', {
  dateStyle: 'short',
  timeStyle: 'medium',
})

export function hhmm(at: Date | undefined): string {
  return at ? time.format(at) : ''
}

export function stamp(at: Date | undefined): string {
  return at ? full.format(at) : '—'
}

export function dayLabel(at: Date | undefined): string {
  if (!at) return 'sem data'
  const today = startOfDay(new Date())
  const that = startOfDay(at)
  const days = Math.round((today.getTime() - that.getTime()) / 86_400_000)
  if (days === 0) return 'hoje'
  if (days === 1) return 'ontem'
  return dayLong.format(at)
}

/** listStamp is the right-hand column of the chat list: time today, date before. */
export function listStamp(at: Date | undefined): string {
  if (!at) return ''
  const today = startOfDay(new Date())
  const that = startOfDay(at)
  const days = Math.round((today.getTime() - that.getTime()) / 86_400_000)
  if (days === 0) return time.format(at)
  if (days === 1) return 'ontem'
  return dayShort.format(at)
}

export function sameDay(a: Date | undefined, b: Date | undefined): boolean {
  if (!a || !b) return a === b
  return startOfDay(a).getTime() === startOfDay(b).getTime()
}

function startOfDay(at: Date): Date {
  return new Date(at.getFullYear(), at.getMonth(), at.getDate())
}

/**
 * since says how long ago something was, in words.
 *
 * Coarse on purpose: "online há 3h" is what somebody wants from a device list,
 * and a timestamp to the second would have to be read rather than glanced at.
 */
export function since(at: Date | undefined): string {
  if (!at) return ''
  const seconds = Math.max(0, Math.round((Date.now() - at.getTime()) / 1000))
  if (seconds < 60) return 'agora há pouco'
  const minutes = Math.round(seconds / 60)
  if (minutes < 60) return `há ${minutes} min`
  const hours = Math.round(minutes / 60)
  if (hours < 24) return `há ${hours} h`
  const days = Math.round(hours / 24)
  if (days < 30) return `há ${days} d`
  return dayLong.format(at)
}

/** count formats a number the way a Brazilian reader expects it. */
const decimal = new Intl.NumberFormat('pt-BR')

export function count(n: number | undefined): string {
  return decimal.format(n ?? 0)
}

export function bytes(n: number): string {
  if (!n) return ''
  const units = ['B', 'kB', 'MB', 'GB']
  let value = n
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value < 10 && unit > 0 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`
}

export function duration(seconds: number): string {
  if (!seconds) return ''
  const m = Math.floor(seconds / 60)
  const s = Math.floor(seconds % 60)
  return `${m}:${String(s).padStart(2, '0')}`
}

/** typeLabel names a content type for a chat list preview. */
export function typeLabel(type: string): string {
  switch (type) {
    case 'text':
      // Nothing. A preview that says "text" beside the text is noise, and a
      // bubble whose body is already on screen does not need naming.
      return ''
    case 'image':
      return 'foto'
    case 'video':
      return 'vídeo'
    case 'ptv':
      return 'vídeo redondo'
    case 'audio':
      return 'áudio'
    case 'ptt':
      return 'mensagem de voz'
    case 'document':
      return 'documento'
    case 'sticker':
      return 'figurinha'
    case 'location':
      return 'localização'
    case 'live_location':
      return 'localização em tempo real'
    case 'contact':
    case 'contact_array':
      return 'contato'
    case 'poll':
      return 'enquete'
    case 'poll_vote':
      return 'voto'
    case 'event':
      return 'evento'
    case 'group_invite':
      return 'convite de grupo'
    case 'reaction':
      return 'reação'
    case 'interactive':
      return 'mensagem interativa'
    case 'buttons':
      return 'mensagem com botões'
    case 'list':
      return 'lista de opções'
    case 'button_reply':
      return 'resposta por botão'
    case 'placeholder':
      return 'mensagem só no celular'
    case 'protocol':
      return 'aviso do sistema'
    case 'unsupported':
      return 'tipo não suportado'
    case 'undecryptable':
      return 'não foi possível decifrar'
    default:
      return type
  }
}

export function kindLabel(kind: string): string {
  switch (kind) {
    case 'edit':
      return 'editou'
    case 'delete':
      return 'apagou'
    case 'reaction':
      return 'reagiu'
    default:
      return ''
  }
}

/** Splits text into runs so links and mentions render without v-html. */
export interface Run {
  text: string
  href?: string
  /** The JID this run mentions, when it is a mention. */
  mention?: string
}

const linkPattern = /\b(?:https?:\/\/|www\.)[^\s<>"']+/gi

/**
 * A mention on the wire is always the numeric form: "@5511999999999", never
 * "@Zé". The name is the reader's own resolution of the JID beside it, which is
 * why a client that has not loaded its contacts shows the number — and why the
 * list of mentioned JIDs has to be passed in rather than guessed from the text.
 */
const mentionPattern = /@(\d{5,20})\b/g

/**
 * runs splits a body into pieces that render as plain text, a link, or a
 * mention.
 *
 * Mentions are matched against the JIDs the message actually carried. An "@"
 * followed by digits that no mention names is left as ordinary text: people
 * write "@11" meaning eleven o'clock, and highlighting that as a person would
 * be an invention. The reverse — a mentioned JID whose number never appears in
 * the text — is also normal, and those are reported separately by
 * unmatchedMentions so a reader is not told about somebody it never showed.
 */
export function runs(text: string, mentions: string[] = []): Run[] {
  const byNumber = new Map<string, string>()
  for (const jid of mentions) {
    const user = jid.split('@')[0]?.split(':')[0]
    if (user) byNumber.set(user, jid)
  }

  type Hit = { start: number; end: number; run: Run }
  const hits: Hit[] = []

  for (const match of text.matchAll(linkPattern)) {
    const start = match.index ?? 0
    // Trailing punctuation is almost never part of the address.
    let found = match[0]
    const trailing = found.match(/[.,;:!?)\]]+$/)
    if (trailing) found = found.slice(0, found.length - trailing[0].length)
    hits.push({
      start,
      end: start + found.length,
      run: { text: found, href: found.startsWith('http') ? found : `https://${found}` },
    })
  }

  if (byNumber.size > 0) {
    for (const match of text.matchAll(mentionPattern)) {
      const jid = byNumber.get(match[1])
      if (!jid) continue
      const start = match.index ?? 0
      // A number inside a URL is part of the address, not a mention.
      if (hits.some((h) => start >= h.start && start < h.end)) continue
      hits.push({ start, end: start + match[0].length, run: { text: match[0], mention: jid } })
    }
    hits.sort((a, b) => a.start - b.start)
  }

  const out: Run[] = []
  let at = 0
  for (const hit of hits) {
    if (hit.start < at) continue
    if (hit.start > at) out.push({ text: text.slice(at, hit.start) })
    out.push(hit.run)
    at = hit.end
  }
  if (at < text.length) out.push({ text: text.slice(at) })
  return out
}

/**
 * unmatchedMentions names the people a message tagged whose number is not in
 * its text.
 *
 * That happens: a mention can be stripped by an edit, or carried by a caption
 * whose text was replaced. Those still belong on screen — somebody was tagged
 * and told about it — but as a footnote rather than inline, because there is no
 * place inline to put them.
 */
export function unmatchedMentions(text: string, mentions: string[] = []): string[] {
  if (mentions.length === 0) return []
  const shown = new Set<string>()
  for (const run of runs(text, mentions)) {
    if (run.mention) shown.add(run.mention)
  }
  return mentions.filter((jid) => !shown.has(jid))
}
