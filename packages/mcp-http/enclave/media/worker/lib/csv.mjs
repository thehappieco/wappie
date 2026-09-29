// A sheet as §16.11 sends it: SECTION {"sheet", "rows", "total_rows"}, then
// RFC 4180 CSV of its first rows with "\n" line ends. Each row ends at its
// last cell with a value: padding every row to the widest one would turn one
// far-right cell into thousands of commas per row. Shared by the SheetJS
// reader (xlsx, xls) and the ODS reader.

const CONTROLS = /[\u0000-\u001f\u007f-\u009f]/g

/**
 * A SECTION name: 1 to 100 UTF-16 code units, no control characters and no
 * split surrogate pair, short enough that the SECTION stays within its 512
 * bytes whatever JSON escaping it needs.
 */
export function sheetName(raw, index) {
  let name = String(raw ?? '').replace(CONTROLS, '')
  if (!name) name = `Sheet${index + 1}`
  const fits = (s) => Buffer.byteLength(JSON.stringify({ sheet: s, rows: 0, total_rows: 0 })) + 16 <= 512
  let end = Math.min(name.length, 100)
  for (;;) {
    if (end < name.length && /[\ud800-\udbff]/.test(name[end - 1])) end--
    if (fits(name.slice(0, end))) return name.slice(0, end)
    end--
  }
}

export function csvField(value) {
  return /[",\n\r]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value
}

/**
 * A running CSV of one sheet. `budget` ({ left }) is shared by every sheet of
 * a job: rows are kept until their text uses it up, after which `full` is set
 * and no more rows are kept, so a workbook never holds much more text than
 * the job may send. The caller emits SECTION with `rows` and then `text()`.
 */
export class SheetCsv {
  constructor(budget) {
    this.budget = budget
    this.rows = []
  }

  get full() {
    return this.budget.left < 0
  }

  /** Add one row of cell strings (trailing empty cells already dropped). */
  add(cells) {
    if (this.full) return false
    this.rows.push(cells)
    this.budget.left -= 1
    for (const c of cells) this.budget.left -= Buffer.byteLength(c) + 1
    return true
  }

  /** Drop trailing empty rows (a sheet's last rows with no value at all). */
  trim() {
    while (this.rows.length && this.rows.at(-1).length === 0) this.rows.pop()
  }

  text() {
    let s = ''
    for (const cells of this.rows) s += `${cells.map(csvField).join(',')}\n`
    return s
  }
}

/** Cells of a row with its trailing empty ones removed. */
export function trimRow(cells) {
  let end = cells.length
  while (end > 0 && !cells[end - 1]) end--
  return end === cells.length ? cells : cells.slice(0, end)
}
