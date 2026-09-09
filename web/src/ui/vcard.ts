import { t } from './i18n'
// Reading a contact card.
//
// WhatsApp sends a contact as a vCard: the whole card, as text, inside the
// sealed payload. The archive stores it exactly as it arrived and this is where
// it becomes something a person can look at.
//
// Parsed rather than pattern-matched, and the difference is not academic. The
// cards that arrive here are produced by phones, and they use the parts of RFC
// 6350 that a regular expression gets wrong: continuation lines that fold a
// long name across two lines, quoted-printable for every name with an accent in
// it — which in this archive is most of them — and parameters carrying the one
// field that makes the card actionable.
//
// That field is WhatsApp's own: TEL carries a `waid` parameter holding the
// account's number without punctuation. It is the only thing in the card that
// can be turned into a conversation, because the printed number is written
// however the sender's phone felt like writing it.

export interface CardNumber {
  label: string
  number: string
  /** The WhatsApp account, when the card names one. Digits only. */
  waid: string
}

export interface Card {
  name: string
  organisation: string
  title: string
  numbers: CardNumber[]
  emails: { label: string; address: string }[]
  /** Anything else worth showing: birthday, note, address. */
  notes: string[]
}

/** parse reads one vCard. A card it cannot make sense of comes back empty. */
export function parse(vcard: string): Card {
  const card: Card = { name: '', organisation: '', title: '', numbers: [], emails: [], notes: [] }

  for (const line of unfold(vcard)) {
    const colon = line.indexOf(':')
    if (colon < 0) continue
    const head = line.slice(0, colon)
    const params = head.split(';')
    const name = params[0].split('.').pop()!.toUpperCase()
    const value = decode(line.slice(colon + 1), params)

    switch (name) {
      case 'FN':
        // FN wins over N: it is the name the sender's phone chose to display,
        // and N is the same name taken apart by a machine.
        card.name = value
        break
      case 'N':
        if (!card.name) card.name = value.split(';').filter(Boolean).reverse().join(' ').trim()
        break
      case 'ORG':
        card.organisation = value.split(';').filter(Boolean).join(' · ')
        break
      case 'TITLE':
        card.title = value
        break
      case 'TEL':
        if (value) card.numbers.push({ label: labelOf(params), number: value, waid: waidOf(params) })
        break
      case 'EMAIL':
        if (value) card.emails.push({ label: labelOf(params), address: value })
        break
      case 'BDAY':
        if (value) card.notes.push(`nascimento: ${value}`)
        break
      case 'ADR': {
        const where = value.split(';').filter(Boolean).join(', ')
        if (where) card.notes.push(where)
        break
      }
      case 'NOTE':
        if (value) card.notes.push(value)
        break
    }
  }
  return card
}

/**
 * unfold joins continuation lines back together.
 *
 * A vCard wraps long values by starting the next line with a space or a tab,
 * which means a name can arrive split down the middle. Anything that reads the
 * card line by line without this shows half a name and drops the rest.
 */
function unfold(vcard: string): string[] {
  const out: string[] = []
  for (const raw of vcard.split(/\r?\n/)) {
    if (/^[ \t]/.test(raw) && out.length) {
      out[out.length - 1] += raw.slice(1)
      continue
    }
    // Quoted-printable folds with a trailing "=" instead, and the continuation
    // starts at column zero — so the fold has to be undone before the decoding.
    if (out.length && out[out.length - 1].endsWith('=')) {
      out[out.length - 1] = out[out.length - 1].slice(0, -1) + raw
      continue
    }
    if (raw.trim()) out.push(raw)
  }
  return out
}

/** labelOf reads the TYPE parameter, which is where "celular" comes from. */
function labelOf(params: string[]): string {
  const types: string[] = []
  for (const p of params.slice(1)) {
    const [key, value] = split(p)
    if (key === 'type' && value) types.push(value)
    else if (!value && !known(key)) types.push(key)
  }
  return types.map(friendly).filter(Boolean).join(' ')
}

function waidOf(params: string[]): string {
  for (const p of params.slice(1)) {
    const [key, value] = split(p)
    // Digits only. The parameter is WhatsApp's and is always a bare number,
    // but a card is text somebody else wrote and this becomes a JID.
    if (key === 'waid' && /^\d{5,20}$/.test(value)) return value
  }
  return ''
}

function split(param: string): [string, string] {
  const eq = param.indexOf('=')
  if (eq < 0) return [param.toLowerCase(), '']
  return [param.slice(0, eq).toLowerCase(), unquote(param.slice(eq + 1))]
}

function unquote(s: string): string {
  return s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1) : s
}

function known(key: string): boolean {
  return key === 'encoding' || key === 'charset' || key === 'value' || key === 'pref'
}

const labels: Record<string, string> = {
  cell: 'celular',
  mobile: 'celular',
  home: 'casa',
  work: 'trabalho',
  main: 'principal',
  fax: 'fax',
  iphone: 'celular',
  voice: '',
  internet: '',
  pref: '',
}

function friendly(type: string): string {
  const key = type.toLowerCase()
  return key in labels ? (labels[key] ? t(labels[key]) : '') : type
}

/**
 * decode undoes the value escaping.
 *
 * Quoted-printable first, because it is a property of the bytes: a name in
 * quoted-printable is UTF-8 written as =C3=A1 pairs, and reading it as text
 * before decoding produces mojibake that no later step can repair.
 */
function decode(value: string, params: string[]): string {
  let out = value
  if (params.slice(1).some((p) => split(p)[1].toLowerCase() === 'quoted-printable')) {
    out = quotedPrintable(out)
  }
  return out.replace(/\\n/gi, '\n').replace(/\\([,;\\])/g, '$1').trim()
}

function quotedPrintable(s: string): string {
  const bytes: number[] = []
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '=' && i + 2 < s.length && /^[0-9a-f]{2}$/i.test(s.slice(i + 1, i + 3))) {
      bytes.push(parseInt(s.slice(i + 1, i + 3), 16))
      i += 2
      continue
    }
    // Anything outside ASCII is already a character rather than an escape; put
    // its own bytes back so a half-encoded card still reads.
    for (const b of new TextEncoder().encode(s[i])) bytes.push(b)
  }
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(bytes))
  } catch {
    return s
  }
}

/** summary is the one-line form, for a chat bubble. */
export function summary(card: Card): string {
  return [...card.numbers.map((n) => n.number), ...card.emails.map((e) => e.address)].join(' · ')
}
