// The jailed image worker for the A0 probe: the A1 sharp path, run inside
// media-jail, so the probe measures a real 12 MP decode + re-encode under the
// memcg and reports whether it fits (§16.8 image caps). Reads the corpus JPEG
// from a path (under /opt/probe, bound read-only into the jail) and writes a
// JSON line to stdout. Its stderr is /dev/null in the jail, so every failure,
// including a failed import, is reported on stdout. sharp/libvips is pinned in
// the probe image; @napi-rs is not used here (that is pdf-render's concern in A1).

const path = process.argv[2]
if (!path) {
  process.stdout.write(JSON.stringify({ ok: false, error: 'no input path' }))
  process.exit(1)
}

// §16.8: 40 MP input cap, loaders limited, block untrusted libvips operations.
// The jail passes the worker UV_USE_IO_URING=0 and no VIPS_* variables (§16.6
// step 7), so libvips is configured here, in code, as A1's worker will be:
// one libvips thread, every loader blocked except the formats accepted.
const LIMIT = 40 * 1024 * 1024
const ALLOWED_LOADERS = [
  'VipsForeignLoadJpegFile', 'VipsForeignLoadJpegBuffer',
  'VipsForeignLoadPngFile', 'VipsForeignLoadPngBuffer',
  'VipsForeignLoadWebpFile', 'VipsForeignLoadWebpBuffer',
]

try {
  const { default: sharp } = await import('sharp')
  sharp.concurrency(1)
  sharp.block({ operation: ['VipsForeignLoad'] })
  sharp.unblock({ operation: ALLOWED_LOADERS })

  // The block must hold: an SVG (a loader outside the list) is refused.
  let blockedRefused = false
  try {
    await sharp(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"/>')).metadata()
  } catch {
    blockedRefused = true
  }

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
      vips: { version: sharp.versions.vips, concurrency: sharp.concurrency(), svg_loader_refused: blockedRefused },
      input: { width: meta.width, height: meta.height, format: meta.format },
      output_bytes: out.length,
    }),
  )
} catch (e) {
  process.stdout.write(JSON.stringify({ ok: false, error: String(e && e.message ? e.message : e) }))
  process.exit(1)
}
