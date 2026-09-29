// OpenDocument spreadsheets (ods) from content.xml, by hand: each table of
// office:spreadsheet is a sheet, and each cell's shown text (its text:p
// paragraphs, what the application displays) is its value. Formulas are
// never read. Repetition is counted, never expanded: an empty row or cell
// repeated a million times (how producers pad a sheet to its full size) only
// moves a counter, and a non-empty one is drawn only while the sheet is within
// `limits.sheet_rows` rows, MAX_COLUMNS columns and the job's text budget.

import { parseXml } from './xml.mjs'
import { SheetCsv, sheetName, trimRow } from './csv.mjs'

// The widest sheet LibreOffice and Excel allow.
const MAX_COLUMNS = 16_384
const MAX_TOTAL = 1_000_000

const count = (value) => {
  const n = parseInt(value ?? '1', 10)
  return Number.isSafeInteger(n) && n > 0 ? n : 1
}

/** Read content.xml into `out` (lib/out.mjs); returns { sheets: total } and a renderer. */
export function readOds(xml, out, limits) {
  const sheets = []
  let total = 0
  let depth = 0
  let spreadsheetDepth = -1
  let sheet = null
  let row = null
  let cell = null
  let skip = 0
  let tableDepth = -1
  const path = []
  const budget = { left: out.limit - out.bytes }

  parseXml(xml, {
    open(name, attrs) {
      depth++
      if (skip || name === 'office:annotation') {
        skip++
        return
      }
      path.push(name)
      if (name === 'office:spreadsheet') spreadsheetDepth = depth
      else if (name === 'table:table' && depth === spreadsheetDepth + 1) {
        total++
        tableDepth = depth
        sheet = total <= limits.sheets ? newSheet(attrs['table:name'], total - 1, budget) : null
      } else if (!sheet) {
        return
      } else if (name === 'table:table-row') {
        row = { cells: [], empties: 0, repeat: count(attrs['table:number-rows-repeated']) }
      } else if ((name === 'table:table-cell' || name === 'table:covered-table-cell') && row) {
        cell = { text: '', paragraphs: 0, repeat: count(attrs['table:number-columns-repeated']) }
      } else if (cell) {
        if (name === 'text:p' && cell.paragraphs++) cell.text += '\n'
        else if (name === 'text:line-break') cell.text += '\n'
        else if (name === 'text:tab') cell.text += '\t'
        else if (name === 'text:s') cell.text += ' '.repeat(Math.min(count(attrs['text:c']), 64))
      }
    },
    text(s) {
      if (skip || !cell) return
      if (path.at(-1).startsWith('text:')) cell.text += s.replace(/[ \t\r\n]+/g, ' ')
    },
    close(name) {
      depth--
      if (skip) {
        skip--
        return
      }
      path.pop()
      if (name === 'table:table' && depth + 1 === tableDepth) {
        if (sheet) sheets.push(sheet)
        sheet = null
        tableDepth = -1
      } else if (!sheet) {
        return
      } else if ((name === 'table:table-cell' || name === 'table:covered-table-cell') && cell && row) {
        addCell(row, cell)
        cell = null
      } else if (name === 'table:table-row' && row) {
        addRow(sheet, row, limits)
        row = null
      }
    },
  })

  return {
    sheets: total,
    render() {
      for (const s of sheets) {
        s.csv.trim()
        out.section({ sheet: s.name, rows: s.csv.rows.length, total_rows: Math.min(Math.max(s.rows, s.csv.rows.length), MAX_TOTAL) })
        out.text(s.csv.text())
      }
    },
  }
}

function newSheet(name, index, budget) {
  return { name: sheetName(name, index), rows: 0, emptyRows: 0, csv: new SheetCsv(budget) }
}

function addCell(row, cell) {
  const text = cell.text.replace(/^ /, '')
  if (!text) {
    row.empties += cell.repeat
    return
  }
  for (let k = 0; k < row.empties && row.cells.length < MAX_COLUMNS; k++) row.cells.push('')
  row.empties = 0
  for (let k = 0; k < cell.repeat && row.cells.length < MAX_COLUMNS; k++) row.cells.push(text)
}

// `rows` counts the sheet through its last row with a value; empty rows wait
// in `emptyRows` until a row with a value follows them, and are dropped if
// none does.
function addRow(sheet, row, limits) {
  const cells = trimRow(row.cells)
  if (!cells.length) {
    sheet.emptyRows += row.repeat
    return
  }
  for (let k = 0; k < sheet.emptyRows && sheet.csv.rows.length < limits.sheet_rows; k++) sheet.csv.add([])
  for (let k = 0; k < row.repeat && sheet.csv.rows.length < limits.sheet_rows; k++) {
    if (!sheet.csv.add(cells)) break
  }
  sheet.rows += sheet.emptyRows + row.repeat
  sheet.emptyRows = 0
}
