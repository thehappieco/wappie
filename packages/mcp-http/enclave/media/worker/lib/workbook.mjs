// xlsx and xls through SheetJS (the CDN tarball the lock pins): cached values
// only. Formulas are never read, so never evaluated; macros, external links,
// styles and properties are not read either. SheetJS stops each sheet at
// `limits.sheet_rows` rows; its `!fullref` still says how many the sheet
// declares. An xlsx reaches here as a stored zip of its entries, each
// inflated with the counts and checks of lib/zip.mjs (office.mjs), so its own
// zip reader finds only the directory those checks read and inflates nothing.

import * as XLSX from 'xlsx'
import * as cptable from 'xlsx/dist/cpexcel.full.mjs'
import { refuse } from './frames.mjs'
import { SheetCsv, sheetName, trimRow } from './csv.mjs'

// Legacy workbooks (BIFF5 and older) name their codepage; SheetJS needs the
// tables to read their strings.
XLSX.set_cptable(cptable)

/** Read the workbook into `out` (lib/out.mjs); returns { sheets: total }. */
export function readWorkbook(input, out, limits) {
  let wb
  try {
    wb = XLSX.read(input, {
      type: 'buffer',
      dense: true,
      sheetRows: limits.sheet_rows,
      sheets: Array.from({ length: limits.sheets }, (_, i) => i),
      cellFormula: false,
      cellHTML: false,
      cellText: true,
      cellDates: false,
      cellNF: false,
      cellStyles: false,
      bookVBA: false,
      bookFiles: false,
      bookDeps: false,
      bookProps: false,
      sheetStubs: false,
      WTF: false,
    })
  } catch (e) {
    if (/password|encrypt/i.test(String(e?.message))) throw refuse('encrypted')
    throw refuse('damaged')
  }
  const names = wb.SheetNames ?? []
  return {
    sheets: names.length,
    render() {
      const budget = { left: out.limit - out.bytes }
      for (let i = 0; i < Math.min(names.length, limits.sheets); i++) {
        sheet(wb.Sheets[names[i]], sheetName(names[i], i), out, limits, budget)
      }
    },
  }
}

function sheet(ws, name, out, limits, budget) {
  const rows = ws?.['!data'] ?? []
  const declared = declaredRows(ws)
  const csv = new SheetCsv(budget)
  const last = Math.min(rows.length, limits.sheet_rows)
  for (let r = 0; r < last && !csv.full; r++) {
    const row = rows[r] ?? []
    const cells = []
    for (let c = 0; c < row.length; c++) cells.push(text(row[c]))
    csv.add(trimRow(cells))
  }
  csv.trim()
  const shown = csv.rows.length
  out.section({ sheet: name, rows: shown, total_rows: Math.max(declared, shown) })
  out.text(csv.text())
}

function text(cell) {
  if (!cell) return ''
  if (typeof cell.w === 'string') return cell.w
  return cell.v === undefined || cell.v === null ? '' : String(cell.v)
}

function declaredRows(ws) {
  const ref = ws?.['!fullref'] ?? ws?.['!ref']
  if (typeof ref !== 'string') return 0
  try {
    return Math.min(XLSX.utils.decode_range(ref).e.r + 1, 1_000_000)
  } catch {
    return 0
  }
}
