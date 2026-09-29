// Flowing text out of one XML part: paragraphs as lines, list items as "- "
// lines, tables as `| a | b |` rows (docs/mcp-enclave.md §16.7 body table).
// One renderer, three vocabularies: WordprocessingML (docx), DrawingML text
// (a pptx slide) and ODF text (odt). What each leaves out is in its `skip`:
// tracked deletions, field instructions, comments and footnotes, and the
// fallback copy of alternate content, which repeats the text of the choice.

import { parseXml } from './xml.mjs'
import { tableRow } from './out.mjs'

// An ODF table's repeated rows and cells are drawn at most this many times.
const MAX_REPEAT = 64

export const DOCX = {
  paragraphs: new Set(['w:p']),
  textIn: new Set(['w:t']),
  newline: new Set(['w:br', 'w:cr']),
  tab: new Set(['w:tab']),
  dash: new Set(['w:noBreakHyphen']),
  // Paragraph properties hold tab stops (w:tab) and the list marker (w:numPr).
  props: new Set(['w:pPr']),
  list: 'w:numPr',
  table: 'w:tbl',
  row: 'w:tr',
  cell: new Set(['w:tc']),
  skip: new Set(['w:del', 'w:moveFrom', 'w:delText', 'w:instrText', 'w:delInstrText', 'mc:Fallback', 'w:rPr']),
}

export const SLIDE = {
  paragraphs: new Set(['a:p']),
  textIn: new Set(['a:t']),
  newline: new Set(['a:br']),
  tab: new Set(),
  dash: new Set(),
  props: new Set(['a:pPr', 'a:rPr', 'a:endParaRPr']),
  list: null,
  table: 'a:tbl',
  row: 'a:tr',
  cell: new Set(['a:tc']),
  skip: new Set(['mc:Fallback']),
}

export const ODT = {
  paragraphs: new Set(['text:p', 'text:h']),
  // ODF text is character data of any text: element, white space collapsed.
  textPrefix: 'text:',
  newline: new Set(['text:line-break']),
  tab: new Set(['text:tab']),
  dash: new Set(),
  spaces: 'text:s',
  props: new Set(),
  listItem: 'text:list-item',
  table: 'table:table',
  row: 'table:table-row',
  cell: new Set(['table:table-cell', 'table:covered-table-cell']),
  skip: new Set([
    'text:tracked-changes',
    'office:annotation',
    'text:note',
    'office:forms',
    'office:scripts',
    'text:sequence-decls',
    'text:variable-decls',
    'text:user-field-decls',
    'office:automatic-styles',
    'office:font-face-decls',
  ]),
}

const repeat = (value) => Math.min(Math.max(parseInt(value ?? '1', 10) || 1, 1), MAX_REPEAT)

/** Render one part's text into `out` (lib/out.mjs). */
export function renderFlow(xml, out, spec) {
  const paragraphs = []
  const tables = []
  const path = []
  let skip = 0
  let props = 0
  let listPending = false
  let blank = true

  const emit = (line) => {
    // A paragraph that holds another (a text box) is left out when it has no
    // text of its own: its content went out as its own lines already.
    if (paragraphs.length) paragraphs.at(-1).holds = true
    const table = tables.at(-1)
    if (table?.cell) {
      table.cell.lines.push(line)
      return
    }
    if (!line.trim()) {
      if (blank) return
      blank = true
    } else {
      blank = false
    }
    out.text(`${line}\n`)
  }
  const append = (s) => {
    if (paragraphs.length) paragraphs.at(-1).text += s
  }

  parseXml(xml, {
    open(name, attrs) {
      if (skip || spec.skip.has(name)) {
        skip++
        return
      }
      path.push(name)
      if (spec.props.has(name)) {
        props++
        return
      }
      if (props) {
        if (name === spec.list && paragraphs.length) paragraphs.at(-1).list = true
        return
      }
      if (spec.paragraphs.has(name)) {
        paragraphs.push({ text: '', list: listPending })
        listPending = false
      } else if (name === spec.listItem) {
        listPending = true
      } else if (spec.newline.has(name)) {
        append('\n')
      } else if (spec.tab.has(name)) {
        append('\t')
      } else if (spec.dash.has(name)) {
        append('-')
      } else if (name === spec.spaces) {
        append(' '.repeat(repeat(attrs['text:c'])))
      } else if (name === spec.table) {
        tables.push({ rows: [], row: null, cell: null })
      } else if (name === spec.row && tables.length) {
        tables.at(-1).row = { cells: [], repeat: repeat(attrs['table:number-rows-repeated']) }
      } else if (spec.cell.has(name) && tables.length) {
        tables.at(-1).cell = { lines: [], repeat: repeat(attrs['table:number-columns-repeated']) }
      }
    },
    text(s) {
      if (skip || props || !paragraphs.length) return
      const inner = path.at(-1)
      if (spec.textIn) {
        if (spec.textIn.has(inner)) append(s)
      } else if (inner.startsWith(spec.textPrefix)) {
        append(s.replace(/[ \t\r\n]+/g, ' '))
      }
    },
    close(name) {
      if (skip) {
        skip--
        return
      }
      path.pop()
      if (spec.props.has(name)) {
        props--
        return
      }
      if (props) return
      if (spec.paragraphs.has(name)) {
        const p = paragraphs.pop()
        const text = spec.textPrefix ? p.text.replace(/^ /, '') : p.text
        if (p.holds && !text.trim()) return
        emit(p.list && text.trim() ? `- ${text}` : text)
      } else if (spec.cell.has(name) && tables.at(-1)?.cell) {
        const table = tables.at(-1)
        const text = table.cell.lines.filter((l) => l.trim()).join(' ')
        for (let k = 0; k < table.cell.repeat; k++) table.row?.cells.push(text)
        table.cell = null
      } else if (name === spec.row && tables.at(-1)?.row) {
        const table = tables.at(-1)
        for (let k = 0; k < table.row.repeat; k++) table.rows.push(table.row.cells)
        table.row = null
      } else if (name === spec.table && tables.length) {
        const table = tables.pop()
        for (const cells of table.rows) if (cells.some((c) => c)) emit(tableRow(cells))
      } else if (name === spec.listItem) {
        listPending = false
      }
    },
  })
}
