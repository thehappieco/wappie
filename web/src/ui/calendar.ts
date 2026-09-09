import { t } from './i18n'
// Turning an event message into a calendar file.
//
// Generated here rather than fetched, and that is the whole point: the event's
// name, description and location are sealed content, so handing them to a
// calendar service to render would undo the one property this archive exists
// for. The file is built in the browser out of what the browser opened, offered
// as a blob, and never leaves the machine unless somebody saves it.
//
// The output is RFC 5545, which is fussy in three specific ways that all fail
// silently — a calendar simply refuses the file, or imports it with the
// description missing:
//
//   - lines end in CRLF and are folded at 75 octets, counted in UTF-8 bytes
//     rather than characters;
//   - commas, semicolons and backslashes are escaped inside values, and a
//     newline becomes a literal \n;
//   - DTSTAMP and UID are required, not optional.

export interface EventLike {
  name?: string
  description?: string
  location?: { name?: string; address?: string }
  join_link?: string
  start_time?: string
  end_time?: string
  is_canceled?: boolean
}

/**
 * ics renders one event.
 *
 * uid identifies the event across imports: re-importing the same message must
 * update the entry rather than make a second one, so the message id is used.
 * now is passed in rather than read, so the output is a function of its inputs.
 */
export function ics(event: EventLike, uid: string, now: Date): string {
  const start = when(event.start_time)
  const lines = [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    'PRODID:-//whatserver2//arquivo selado//PT',
    'CALSCALE:GREGORIAN',
    // A cancelled event is still worth importing: somebody with the earlier
    // version in their calendar needs this one to remove it.
    ...(event.is_canceled ? ['METHOD:CANCEL'] : []),
    'BEGIN:VEVENT',
    `UID:${escape(uid)}`,
    `DTSTAMP:${stamp(now)}`,
    ...(start ? [`DTSTART:${start}`] : []),
    ...(when(event.end_time) ? [`DTEND:${when(event.end_time)}`] : []),
    `SUMMARY:${escape(event.name || 'Evento')}`,
    ...(description(event) ? [`DESCRIPTION:${escape(description(event))}`] : []),
    ...(place(event) ? [`LOCATION:${escape(place(event))}`] : []),
    ...(event.join_link ? [`URL:${escape(event.join_link)}`] : []),
    ...(event.is_canceled ? ['STATUS:CANCELLED'] : ['STATUS:CONFIRMED']),
    'END:VEVENT',
    'END:VCALENDAR',
  ]
  return lines.flatMap(fold).join('\r\n') + '\r\n'
}

/** filename is what the download is called. */
export function filename(event: EventLike): string {
  const base = (event.name || 'evento')
    .normalize('NFD')
    .replace(/\p{Diacritic}/gu, '')
    .replace(/[^a-zA-Z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 60)
  return `${base || t('evento')}.ics`
}

function description(event: EventLike): string {
  // The join link goes in the description too. URL is the correct field and
  // several calendars do not show it, which for a call is the one line
  // somebody actually needs.
  return [event.description, event.join_link].filter(Boolean).join('\n\n')
}

function place(event: EventLike): string {
  return [event.location?.name, event.location?.address].filter(Boolean).join(', ')
}

/**
 * when renders an instant in UTC.
 *
 * UTC rather than a local time with a VTIMEZONE block: the archive stores the
 * instant, and writing a wall-clock time would need the sender's zone, which
 * WhatsApp does not send. A calendar shows it in the reader's own zone either
 * way, which is what a person wants.
 */
function when(iso: string | undefined): string {
  if (!iso) return ''
  const at = new Date(iso)
  if (Number.isNaN(at.getTime())) return ''
  return stamp(at)
}

function stamp(at: Date): string {
  return at.toISOString().replace(/[-:]/g, '').replace(/\.\d+/, '')
}

function escape(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/\n/g, '\\n')
    .replace(/,/g, '\\,')
    .replace(/;/g, '\\;')
    .replace(/\r/g, '')
}

/**
 * fold wraps a long line, counting octets rather than characters.
 *
 * A description with accents in it is longer in bytes than in characters, and a
 * fold placed by character count lands mid-character — which produces a file
 * that imports with the text mangled from that point on.
 */
function fold(line: string): string[] {
  const bytes = new TextEncoder().encode(line)
  if (bytes.length <= 75) return [line]

  const out: string[] = []
  let start = 0
  let limit = 75
  while (start < bytes.length) {
    let end = Math.min(start + limit, bytes.length)
    // Never split a UTF-8 sequence: back up off any continuation byte.
    while (end < bytes.length && (bytes[end] & 0xc0) === 0x80) end--
    const chunk = new TextDecoder().decode(bytes.slice(start, end))
    out.push(out.length ? ` ${chunk}` : chunk)
    start = end
    // Continuation lines carry a leading space, which counts toward the limit.
    limit = 74
  }
  return out
}
