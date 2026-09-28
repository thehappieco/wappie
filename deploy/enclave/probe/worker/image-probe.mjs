// The jailed image worker for the A0 probe: the A1 sharp path, run inside
// media-jail, so the probe measures a real 12 MP decode + re-encode under the
// memcg and reports whether it fits (§16.8 image caps). Reads the corpus JPEG
// from a path (under /opt, bound read-only into the jail) and writes a JSON
// line to stdout. sharp/libvips is pinned in the probe image; @napi-rs is not
// used here (that is pdf-render's concern in A1).
import sharp from 'sharp'

const path = process.argv[2]
if (!path) {
  process.stdout.write(JSON.stringify({ ok: false, error: 'no input path' }))
  process.exit(1)
}

// §16.8: 40 MP input cap, loaders limited, block untrusted libvips operations.
// VIPS_BLOCK_UNTRUSTED is set by the probe runner in the environment; A1 sets it
// in the jail itself.
const LIMIT = 40 * 1024 * 1024

try {
  const meta = await sharp(path, { limitInputPixels: LIMIT }).metadata()
  const out = await sharp(path, { limitInputPixels: LIMIT })
    .rotate() // apply and strip EXIF orientation
    .resize({ width: 1568, height: 1568, fit: 'inside', withoutEnlargement: true })
    .jpeg({ quality: 80 })
    .toBuffer()
  process.stdout.write(
    JSON.stringify({
      ok: true,
      node: process.versions.node,
      input: { width: meta.width, height: meta.height, format: meta.format },
      output_bytes: out.length,
    }),
  )
} catch (e) {
  process.stdout.write(JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }))
  process.exit(1)
}
