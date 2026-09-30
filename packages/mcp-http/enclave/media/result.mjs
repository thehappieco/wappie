// What an open answers (docs/mcp-enclave.md §16.7): the header, in its order,
// the body of one part, and the images that follow it. packages/mcp's
// server.mjs adds `notes` and `source` and turns this into the MCP result.
import { refusal } from './gate.mjs'
import { CAPTION_MAX_CHARS, FILENAME_MAX_CHARS, IMAGES_PER_RESULT, PART_MAX_CHARS, PDF_MAX_PAGES, PDF_SCANNED_BELOW, SHEET_ROWS, SHEETS_MAX, ZIP_LISTED } from './policy.mjs'

/** The header's fields in their order (§16.7, and an AI transcript's `derived`, §18.12); `notes` and `source` are the reader's. */
export const HEADER_ORDER = Object.freeze(['uid', 'media_type', 'sniffed', 'file_length', 'filename', 'caption', 'pages', 'sheets', 'slides', 'entries',
  'seconds_claimed', 'derived', 'animated', 'part', 'scanned_pages', 'image_pages', 'next_cursor', 'status', 'retry_after_s', 'truncated', 'images', 'images_withheld', 'open_url'])
const TRUNCATED_ORDER = ['text_cap', 'page_cap', 'page_too_long', 'sheet_cap', 'row_cap', 'entry_cap']
const invalidCursor = () => refusal('invalid_cursor')

/** `fields` in HEADER_ORDER, without what does not apply. */
export function orderHeader(fields) {
  const header = {}
  for (const key of HEADER_ORDER) if (fields[key] !== undefined) header[key] = fields[key]
  return header
}

const isHigh = code => code >= 0xd800 && code <= 0xdbff
/** At most `max` code units of `text`, never ending inside a surrogate pair. */
export function cut(text, max) {
  if (text.length <= max) return text
  return text.slice(0, isHigh(text.charCodeAt(max - 1)) ? max - 1 : max)
}

/**
 * The facts every result of one attachment repeats: from the row, the opened
 * filename and caption, what its jobs found, and `openURL`, the console link
 * of its message (§16.7), when there is one. `truncated` is what of the whole
 * attachment the reader cannot read.
 */
export function factsOf(row, opened, found = {}, openURL) {
  const media = row.media
  const facts = { uid: row.uid, media_type: media.media_type, sniffed: found.sniffed }
  if (Number.isSafeInteger(media.file_length)) facts.file_length = media.file_length
  if (typeof opened?.filename === 'string') facts.filename = cut(opened.filename, FILENAME_MAX_CHARS)
  if (typeof opened?.caption === 'string') facts.caption = cut(opened.caption, CAPTION_MAX_CHARS)
  for (const key of ['pages', 'sheets', 'slides', 'entries']) if (found[key] !== undefined) facts[key] = found[key]
  if (found.seconds_claimed !== undefined) facts.seconds_claimed = found.seconds_claimed
  facts.truncated = TRUNCATED_ORDER.filter(item => found.truncated?.includes(item))
  if (typeof openURL === 'string') facts.open_url = openURL
  return facts
}

/** A finished result: the header with its status and image counts. */
export function finish(facts, { body = '', images = [], withheld, part, next, extra = {}, tooLong = false, suggest } = {}) {
  const truncated = TRUNCATED_ORDER.filter(item => facts.truncated.includes(item) || (item === 'page_too_long' && tooLong))
  const header = orderHeader({
    ...facts, ...extra, part, next_cursor: next, truncated: truncated.length ? truncated : undefined,
    status: next || truncated.length ? 'partial' : 'complete', images: images.length, images_withheld: withheld,
  })
  return { header, body, images: images.map(image => ({ mimeType: image.mimeType, data: image.data })), ...(suggest ? { suggest_pages: suggest } : {}) }
}

/**
 * An answer while the open goes on, or waits its turn: no body, no images.
 * `ai` marks one whose AI job goes on (§18.12), which the reader notes as such.
 */
export function pending(uid, mediaType, retryAfterS, openURL, ai = false) {
  return { header: orderHeader({ uid, media_type: mediaType, status: 'pending', retry_after_s: retryAfterS, open_url: openURL ?? undefined }), body: '', images: [], ...(ai ? { ai: true } : {}) }
}

/**
 * An AI transcript as open_attachment answers it (§18.12): the header in its
 * order (`sniffed: "transcript"`, `derived` with what made it, a character
 * part), the record's text paged by `c` cursors, no images, and `ai` for the
 * reader's notes. `record` is an opened derived record.
 */
export function transcript(row, record, request, openURL) {
  const part = charPart(record.text, request.cursor)
  const seconds = typeof row.media.seconds === 'number' && Number.isFinite(row.media.seconds) && row.media.seconds >= 0 ? row.media.seconds : undefined
  const derived = { feature: record.feature, provider: record.provider, model: record.model, created_at: record.created_at,
    ...(record.lang ? { lang: record.lang } : {}), ...(record.flags.length ? { flags: [...record.flags] } : {}) }
  const header = orderHeader({
    uid: row.uid, media_type: row.media.media_type, sniffed: 'transcript', file_length: Number.isSafeInteger(row.media.file_length) ? row.media.file_length : undefined,
    seconds_claimed: seconds, derived, part: part.part, next_cursor: part.next, status: part.next ? 'partial' : 'complete', open_url: openURL ?? undefined,
  })
  return { header, body: part.body, images: [], ai: true }
}

/**
 * The part of a rendered text a `c<N>` cursor (or none) asks for: at most
 * PART_MAX_CHARS code units from N, never ending inside a surrogate pair.
 */
export function charPart(text, cursor) {
  if (cursor && cursor.unit !== 'char') throw invalidCursor()
  const from = cursor ? cursor.at : 0
  if (from >= text.length && !(from === 0 && text.length === 0)) throw invalidCursor()
  const body = cut(text.slice(from), PART_MAX_CHARS)
  const to = from + body.length
  return { body, part: { unit: 'char', from, to }, next: to < text.length ? `c${to}` : null }
}

/** Removes what a heading must not carry from a sheet name. */
const sheetName = name => name.replace(/["\u0000-\u001f\u007f-\u009f]/g, '')

/**
 * The text the reader renders from an office worker's output (§16.7's body
 * table), and the facts it found: its totals and what it could not read.
 */
export function renderOffice(output) {
  const { header } = output
  const found = { sniffed: header.sniffed, truncated: [] }
  for (const key of ['sheets', 'slides', 'entries']) if (header[key] !== undefined) found[key] = header[key]
  if (output.cut) found.truncated.push('text_cap')
  let text = ''
  for (const { section, text: part } of output.sections) {
    if (section?.sheet !== undefined) {
      const name = sheetName(section.sheet)
      text += (section.rows > 0 ? `--- sheet "${name}" (rows 1-${section.rows} of ${section.total_rows}) ---` : `--- sheet "${name}" (empty) ---`) + '\n' + part + '\n'
      if (section.total_rows > SHEET_ROWS) found.truncated.includes('row_cap') || found.truncated.push('row_cap')
    } else if (section?.slide !== undefined) text += `--- slide ${section.slide} ---\n${part}\n`
    else text += part
  }
  if (header.sheets !== undefined && header.sheets > SHEETS_MAX) found.truncated.push('sheet_cap')
  if (header.entries !== undefined && header.entries > ZIP_LISTED) found.truncated.push('entry_cap')
  return { text, found }
}

/**
 * A PDF text job's window (§16.9): the pages it read, from `from`, ending at
 * its last complete page when the text limit cut it short (the next window
 * starts at the page it was in). Null when it read nothing.
 */
export function pdfWindow(output, from, expires) {
  const pages = output.sections.map(item => ({ page: item.section.page, text: item.text }))
  if (output.cut && pages.length > 1) pages.pop()
  if (!pages.length) return null
  return { from, to: pages.at(-1).page, texts: pages.map(item => item.text), expires }
}

export const scanned = text => text.trim().length < PDF_SCANNED_BELOW
const block = (page, text) => `--- page ${page}${scanned(text) ? ' (scanned)' : ''} ---\n${text}\n`

/** The last page any cursor can name: the PDF's, up to PDF_MAX_PAGES. */
export const lastPage = total => Math.min(total, PDF_MAX_PAGES)

/**
 * Whole page blocks from page `from` while they fit in PART_MAX_CHARS, at
 * least one (a single block over the cap is cut: `tooLong`), never past
 * `to` or the window. `text(page)` gives a page's text.
 */
export function pageBlocks(from, to, text) {
  const blocks = []
  let length = 0, page = from, tooLong = false
  for (; page <= to; page++) {
    const next = block(page, text(page))
    const added = next.length + (blocks.length ? 1 : 0)
    if (blocks.length && length + added > PART_MAX_CHARS) break
    if (!blocks.length && next.length > PART_MAX_CHARS) { blocks.push(cut(next, PART_MAX_CHARS)); tooLong = true; page++; break }
    blocks.push(next)
    length += added
  }
  return { body: blocks.join('\n'), from, to: page - 1, tooLong }
}

/**
 * The part a page cursor (or none) asks for, within `window`, and what page
 * images it needs: with `images`, the first IMAGES_PER_RESULT scanned pages
 * of the part, and a suggested range for the scanned pages after them.
 */
export function pdfPart(window, at, total, images) {
  const text = page => window.texts[page - window.from]
  const part = pageBlocks(at, window.to, text)
  const scannedPages = []
  for (let page = part.from; page <= part.to; page++) if (scanned(text(page))) scannedPages.push(page)
  const wanted = images ? scannedPages.slice(0, IMAGES_PER_RESULT) : []
  const left = images ? scannedPages.slice(IMAGES_PER_RESULT) : []
  return {
    body: part.body, part: { unit: 'page', from: part.from, to: part.to }, tooLong: part.tooLong,
    next: part.to < lastPage(total) ? `p${part.to + 1}` : null, scannedPages, wanted,
    withheld: !images && scannedPages.length ? 'request' : undefined,
    suggest: left.length ? `${left[0]}-${Math.min(left[0] + 3, window.to)}` : undefined,
  }
}

/** Exactly the pages of a `pages` request, from their texts (cut at the cap like a part). */
export function pagesPart(range, text) {
  const part = pageBlocks(range.from, range.to, text)
  const scannedPages = []
  for (let page = part.from; page <= part.to; page++) if (scanned(text(page))) scannedPages.push(page)
  return { body: part.body, part: { unit: 'page', from: part.from, to: part.to }, tooLong: part.tooLong, next: null, scannedPages }
}
