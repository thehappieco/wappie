// Argon2id, off the main thread.
//
// The derivation is deliberately expensive — that is the entire point of a
// memory-hard KDF — and on the main thread it freezes the tab for the whole of
// it. A page that stops responding does not read as "working hard", it reads as
// broken, and somebody will reload it halfway through creating an account.

import { argon2id } from '@noble/hashes/argon2.js'

export interface KDFRequest {
  password: string
  salt: Uint8Array
  m: number
  t: number
  p: number
}

self.onmessage = (event: MessageEvent<KDFRequest>) => {
  const { password, salt, m, t, p } = event.data
  try {
    const out = argon2id(new TextEncoder().encode(password), salt, { m, t, p, dkLen: 32 })
    // Transferred rather than copied: the buffer is done with here.
    ;(self as unknown as Worker).postMessage({ ok: true, master: out }, [out.buffer])
  } catch (err) {
    ;(self as unknown as Worker).postMessage({
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    })
  }
}
