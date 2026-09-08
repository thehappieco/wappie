import { describe, expect, it } from 'vitest'

import { filename, ics } from '../src/ui/calendar'

// The .ics is built in the browser out of what the browser opened, because the
// event's name, description and location are sealed and handing them to a
// calendar service would undo the whole arrangement.
//
// RFC 5545 is fussy in ways that fail silently: a calendar refuses the file, or
// imports it with the description missing, and nothing says why.

const now = new Date('2026-09-03T12:00:00Z')

function lines(text: string): string[] {
  return text.split('\r\n')
}

describe('writing an event', () => {
  it('ends every line with CRLF', () => {
    // Bare newlines are the most common reason a calendar rejects a file
    // outright, and it rejects it without saying anything useful.
    const out = ics({ name: 'Reunião' }, 'uid-1', now)
    expect(out.includes('\r\n')).toBe(true)
    expect(out.split('\n').every((l) => l === '' || l.endsWith('\r'))).toBe(true)
  })

  it('carries the required stamp and identity', () => {
    // Both are required by the spec. An import without UID makes a second copy
    // of the event every time somebody opens the file.
    const out = lines(ics({ name: 'Reunião' }, 'uid-1', now))
    expect(out).toContain('UID:uid-1')
    expect(out).toContain('DTSTAMP:20260903T120000Z')
  })

  it('writes times in UTC', () => {
    // The archive stores the instant. Writing a wall-clock time would need the
    // sender's zone, which WhatsApp does not send.
    const out = lines(ics({ name: 'Reunião', start_time: '2026-09-10T18:30:00-03:00' }, 'u', now))
    expect(out).toContain('DTSTART:20260910T213000Z')
  })

  it('escapes the characters that would end the line early', () => {
    // An unescaped comma or semicolon truncates the value at that point, so a
    // description arrives with its second half missing.
    const out = ics({ name: 'Almoço, com o time; sala 2' }, 'u', now)
    expect(out).toContain('SUMMARY:Almoço\\, com o time\\; sala 2')
  })

  it('turns a newline in the description into the escape a calendar reads', () => {
    const out = ics({ name: 'x', description: 'linha um\nlinha dois' }, 'u', now)
    expect(out).toContain('DESCRIPTION:linha um\\nlinha dois')
  })

  it('folds a long line without splitting a character in half', () => {
    // Folded at 75 octets, counted in bytes. A fold placed by character count
    // lands mid-character and the text is mangled from there on.
    const long = 'ação '.repeat(40)
    const out = ics({ name: 'x', description: long }, 'u', now)
    for (const line of lines(out)) {
      expect(new TextEncoder().encode(line).length).toBeLessThanOrEqual(75)
    }
    // Unfolding it must give the text back, accents intact.
    const body = lines(out)
      .filter((l) => l.startsWith('DESCRIPTION:') || l.startsWith(' '))
      .map((l, i) => (i === 0 ? l.slice('DESCRIPTION:'.length) : l.slice(1)))
      .join('')
    expect(body).toBe(long.replace(/\n/g, '\\n'))
  })

  it('says a cancelled event is cancelled', () => {
    // Worth importing precisely because it is cancelled: somebody holding the
    // earlier version needs this one to remove it.
    const out = lines(ics({ name: 'x', is_canceled: true }, 'u', now))
    expect(out).toContain('STATUS:CANCELLED')
    expect(out).toContain('METHOD:CANCEL')
  })

  it('leaves out a time it cannot read rather than writing a wrong one', () => {
    const out = lines(ics({ name: 'x', start_time: 'amanhã de tarde' }, 'u', now))
    expect(out.some((l) => l.startsWith('DTSTART'))).toBe(false)
  })

  it('names the file after the event, without accents or spaces', () => {
    expect(filename({ name: 'Reunião do time, sexta' })).toBe('Reuniao-do-time-sexta.ics')
    expect(filename({})).toBe('evento.ics')
  })
})
