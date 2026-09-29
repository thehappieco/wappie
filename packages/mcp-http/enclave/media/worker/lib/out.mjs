// What an office parser produces: SECTION objects and text, in order, held
// until the parse ends so the HEADER (which carries the totals) can go
// first. Text is counted in UTF-8 bytes; once it passes the job's
// `text_bytes`, the parse stops (STOP) and the frame writer cuts it to the
// byte (frames.mjs TextSink), which ends the job with DONE {"cut": true}.

export const STOP = Symbol('stop')

export class Out {
  constructor(limit) {
    this.limit = limit
    this.items = []
    this.bytes = 0
  }

  section(value) {
    if (this.bytes > this.limit) throw STOP
    this.items.push({ section: value })
  }

  text(s) {
    if (!s) return
    if (this.bytes > this.limit) throw STOP
    this.items.push({ text: s })
    this.bytes += Buffer.byteLength(s, 'utf8')
    if (this.bytes > this.limit) throw STOP
  }
}

/** One table row as `| a | b |`, cells on one line with `|` escaped. */
export function tableRow(cells) {
  return `| ${cells.map((c) => c.replace(/\s+/g, ' ').trim().replace(/\|/g, '\\|')).join(' | ')} |`
}
