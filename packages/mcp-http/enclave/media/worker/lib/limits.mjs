// The §16.8 values a worker needs itself (docs/mcp-enclave.md). A worker never
// imports the reader's enclave/media/policy.mjs: it lives in its own package
// under /opt/media, and the job header carries every per-job limit. What is
// here is either framing (the sizes §16.11 fixes) or a ceiling a header value
// may not exceed, so a header can only ask for less than the reader's own
// constants, never more. The ladders are the image output rules of §16.11.
// Each name is policy.mjs's; test/limits.test.mjs checks them against it when
// the reader's file is present.

export const STDIN_HEADER_MAX = 4_096
// CAP_BYTES.document: the largest input the reader sends.
export const INPUT_MAX = 33_554_432

export const FRAME_MAX = Object.freeze({
  1: 16_384,
  2: 65_536,
  3: 512,
  4: 2 + 307_200,
  8: 256,
  9: 64,
})

// Ceilings for the job header's limits.
export const IMAGE_MAX_PIXELS = 40_000_000
export const IMAGE_LONG_EDGE = 1_568
export const IMAGE_MAX_BYTES = 307_200
export const STICKER_LONG_EDGE = 512
export const STICKER_MAX_BYTES = 102_400
export const JOB_TEXT_MAX_BYTES = 4_194_304
export const PDF_MAX_PAGES = 2_000
export const PDF_PAGES_PER_JOB = 300
export const PDF_MAX_IMAGE_PIXELS = 16_000_000
export const IMAGES_PER_RESULT = 4
export const ZIP_MAX_ENTRIES = 2_000
export const ZIP_MAX_INFLATED = 104_857_600
export const ZIP_MAX_RATIO = 100
export const ZIP_LISTED = 200
export const SHEETS_MAX = 50
export const SHEET_ROWS = 2_000

// The output ladders (§16.11 per worker).
export const JPEG_QUALITIES = Object.freeze([80, 70, 60])
export const IMAGE_FALLBACK_EDGE = 1_024
export const STICKER_EDGES = Object.freeze([512, 384, 256])
