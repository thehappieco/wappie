// The sealed archive.
//
// Mirrors internal/crypto/seal. The server holds only a public key; everything
// below runs in the browser with the private half, which is the only place it
// ever exists.
//
// The envelope is the shared kit's (@thehappieco/kit/seal), bound here to
// Wappie's profile: the magic "WS", the label "wsv1" and the kind names, which
// are wire format and frozen, since data already stored opens only with them.
// What the kinds mean, and the draft row of the MCP ledger, stay here.
//
// Pinned against Go by test/seal.spec.ts, which opens the vectors that package
// generates — including the ones that must fail.

import { bind, SealError, type ContentKey as KitContentKey } from '@thehappieco/kit/seal'
import { wappieSeal } from '@thehappieco/kit/profiles/wappie'
import { encodeUTF8, type Bytes } from './bytes.js'

export { Kind, kindName } from '@thehappieco/kit/profiles/wappie'
export { MODE_BATCH, MODE_DIRECT, SealError, SUITE_V1, VERSION, type Header } from '@thehappieco/kit/seal'

export const MAGIC0 = wappieSeal.magic[0] // 'W'
export const MAGIC1 = wappieSeal.magic[1] // 'S'

const wappie = bind(wappieSeal)

/** parseHeader validates the prefix before any key material is touched. */
export const parseHeader = wappie.parseHeader

/**
 * sealDirect seals a value straight to a public key.
 *
 * The only thing this client seals is a key grant: one device's private archive
 * key, encrypted to an account's public key so that person can read that
 * WhatsApp number by signing in. It happens here because the device key is
 * generated here and must not leave — the server stores ciphertext it cannot
 * open, which is the whole arrangement.
 *
 * Getting the binding wrong fails silently in the worst possible way: the grant
 * stores, pairing reports success, and the archive it was supposed to unlock is
 * unreadable by anyone, forever. test/grant.spec.ts seals a vector here that Go
 * has to open.
 *
 * The attested reader seals one more thing with it, in Node: an assistant's
 * draft (Kind.McpDraft, draftRow), to the number's archive public key, which
 * only the person's browser can open. test/draft.spec.ts keeps that vector.
 */
export const sealDirect = wappie.sealDirect

/**
 * openDirect opens a value sealed straight to the archive key: content keys
 * and grants. Every failure after the header is `authentication`, as on the
 * server.
 */
export const openDirect = wappie.openDirect

/**
 * ContentKey is a symmetric key covering a batch of sealed values, unwrapped
 * with a device's archive private key (ContentKey.unwrap).
 */
export type ContentKey = KitContentKey
export const ContentKey = wappie.ContentKey

/**
 * grantRow derives the row a key grant binds to: one device's private archive
 * key sealed to one person's public key, bound to (device, user, epoch).
 */
export const grantRow = wappie.grantRow

/**
 * draftRow derives the row an assistant's draft binds to (docs/mcp-enclave.md
 * §17.6): the number, the connection, the draft, the message it replies to
 * (sixteen zero bytes for none) and the chat.
 *
 * Every routing field is in it because the ledger that carries the envelope
 * is the server's: a row rebuilt with another chat, another reply target or
 * another connection opens nothing, so a draft the person was shown for one
 * recipient can never be delivered to another.
 */
export async function draftRow(
  tenant: Bytes,
  device: Bytes,
  connection: Bytes,
  draft: Bytes,
  reply: Bytes | null,
  chatKey: string,
): Promise<Bytes> {
  for (const id of [device, connection, draft, ...(reply ? [reply] : [])]) {
    if (id.length !== 16) throw new SealError('a draft row takes 16-byte ids', 'short')
  }
  const key = encodeUTF8(chatKey)
  const name = new Uint8Array(64 + key.length) as Bytes
  name.set(device, 0)
  name.set(connection, 16)
  name.set(draft, 32)
  if (reply) name.set(reply, 48)
  name.set(key, 64)
  return wappie.row(tenant, name)
}
