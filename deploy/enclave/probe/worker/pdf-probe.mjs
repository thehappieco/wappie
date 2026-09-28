// The jailed PDF worker for the A0 probe: the A1 pdfjs-dist text path, run
// inside media-jail. It proves pdf.js extracts text WITHOUT @napi-rs/canvas
// (§16 F2) under the memcg, and measures the memory and time of a 50-page
// document. Reads the corpus PDF from a path (under /opt, bound read-only) and
// writes a JSON line to stdout.
//
// The legacy build is the one that runs without a DOM; text extraction needs no
// canvas, so the optional native canvas dependency is never loaded here.
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const path = process.argv[2]
if (!path) {
  process.stdout.write(JSON.stringify({ ok: false, error: 'no input path' }))
  process.exit(1)
}

// pdf.js warns once at import time that it cannot load the optional
// @napi-rs/canvas (we pruned it, §16 F2). Silence console.warn across the
// dynamic import so the probe console carries only the report; text extraction
// needs no canvas.
const savedWarn = console.warn
console.warn = () => {}
const pdfjs = await import('pdfjs-dist/legacy/build/pdf.mjs')
console.warn = savedWarn

// Standard-14 font metrics ship in the package; pointing pdf.js at them keeps
// text extraction quiet and correct without any canvas.
const standardFontDataUrl = fileURLToPath(
  new URL('./node_modules/pdfjs-dist/standard_fonts/', import.meta.url),
)

let loadingTask
try {
  const data = new Uint8Array(readFileSync(path))
  loadingTask = pdfjs.getDocument({
    data,
    isEvalSupported: false,
    useSystemFonts: false,
    disableFontFace: true,
    standardFontDataUrl,
    verbosity: 0, // errors only: no canvas/DOMMatrix warnings on stderr
  })
  const doc = await loadingTask.promise
  let chars = 0
  const pages = doc.numPages
  for (let p = 1; p <= pages; p++) {
    const page = await doc.getPage(p)
    const text = await page.getTextContent()
    for (const item of text.items) chars += item.str ? item.str.length : 0
    page.cleanup()
  }
  process.stdout.write(JSON.stringify({ ok: true, node: process.versions.node, pages, chars }))
} catch (e) {
  process.stdout.write(JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }))
  process.exitCode = 1
} finally {
  if (loadingTask) {
    try {
      await loadingTask.destroy()
    } catch {
      /* nothing to clean up */
    }
  }
}
