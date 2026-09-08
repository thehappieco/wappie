// The sealed archive.
//
// Mirrors internal/crypto/seal. The server holds only a public key; everything
// below runs in the browser with the private half, which is the only place it
// ever exists.
//
// Pinned against Go by test/seal.spec.ts, which opens the vectors that package
// generates — including the ones that must fail.

import {
  type Bytes,
  concat,
  encodeUTF8,
  formatUUID,
  readUint16BE,
  readUint32BE,
  uuidV5,
} from './bytes'
import { ENC_LEN, open as hpkeOpen, seal as hpkeSeal, type PrivateKey } from './hpke'

export const MAGIC0 = 0x57 // 'W'
export const MAGIC1 = 0x53 // 'S'
export const VERSION = 0x01
export const SUITE_V1 = 0x01

export const MODE_DIRECT = 0x01
export const MODE_BATCH = 0x02

const HEADER_LEN = 8
const NONCE_LEN = 12
const TAG_LEN = 16

/** Kind identifies what a sealed value is, and is bound into the AAD. */
export enum Kind {
  Body = 0x01,
  RawProto = 0x02,
  MediaKey = 0x03,
  Thumbnail = 0x04,
  ContactName = 0x05,
  ContentKey = 0x06,
  DeviceGrant = 0x07,
  UserWrap = 0x08,
  Payload = 0x09,
  PushName = 0x0a,
  FullName = 0x0b,
  BusinessName = 0x0c,
  Avatar = 0x0d,
}

// The names go into the HPKE info string, so they are part of the wire format
// rather than labels for humans. They must match Kind.String() in Go exactly.
const kindNames: Record<number, string> = {
  [Kind.Body]: 'body',
  [Kind.RawProto]: 'raw_proto',
  [Kind.MediaKey]: 'media_key',
  [Kind.Thumbnail]: 'thumbnail',
  [Kind.ContactName]: 'contact_name',
  [Kind.ContentKey]: 'content_key',
  [Kind.DeviceGrant]: 'device_grant',
  [Kind.UserWrap]: 'user_wrap',
  [Kind.Payload]: 'payload',
  [Kind.PushName]: 'push_name',
  [Kind.FullName]: 'full_name',
  [Kind.BusinessName]: 'business_name',
  [Kind.Avatar]: 'avatar',
}

export function kindName(kind: number): string {
  // Go's default branch is fmt.Sprintf("kind(%#x)", byte(k)), which prints the
  // hex without leading zeros.
  return kindNames[kind] ?? `kind(0x${kind.toString(16)})`
}

/** SealError distinguishes a wrong key from a blob that was moved or altered. */
export class SealError extends Error {
  constructor(
    message: string,
    readonly code:
      | 'short'
      | 'magic'
      | 'version'
      | 'suite'
      | 'mode'
      | 'key_mismatch'
      | 'authentication',
  ) {
    super(message)
    this.name = 'SealError'
  }
}

export interface Header {
  version: number
  suite: number
  mode: number
  epoch: number
}

/**
 * parseHeader validates the prefix before any key material is touched.
 *
 * The suite byte is checked here rather than guessed at, because a parser that
 * guessed would be the downgrade path the byte exists to close.
 */
export function parseHeader(envelope: Bytes): Header {
  if (envelope.length < HEADER_LEN) throw new SealError('envelope curto demais', 'short')
  if (envelope[0] !== MAGIC0 || envelope[1] !== MAGIC1) {
    throw new SealError('não é um envelope', 'magic')
  }
  const h: Header = {
    version: envelope[2],
    suite: envelope[3],
    mode: envelope[4],
    epoch: readUint16BE(envelope, 5),
  }
  if (h.version !== VERSION) throw new SealError(`versão desconhecida: ${h.version}`, 'version')
  if (h.suite !== SUITE_V1) throw new SealError(`suíte desconhecida: ${h.suite}`, 'suite')
  if (h.mode !== MODE_DIRECT && h.mode !== MODE_BATCH) {
    throw new SealError(`modo desconhecido: ${h.mode}`, 'mode')
  }
  return h
}

const AAD_PREFIX = encodeUTF8('wsv1')

/**
 * buildAAD binds a sealed value to where it lives and to its own header.
 *
 * Leaving any of these out is the failure mode that matters: an attacker with
 * write access to the database moves a blob to another row, and a client that
 * did not bind the row decrypts it happily — content swapped between
 * conversations, with no integrity failure anywhere.
 */
function buildAAD(kind: Kind, tenant: Bytes, row: Bytes, header: Bytes): Bytes {
  return concat(AAD_PREFIX, new Uint8Array([kind]), tenant, row, header)
}

/** infoFor gives each use of the tenant key its own HPKE domain. */
function infoFor(kind: Kind, tenant: Bytes, epoch: number): Bytes {
  return encodeUTF8(`wsv1/${kindName(kind)}/${formatUUID(tenant)}/${epoch}`)
}

/**
 * encodeHeader writes the eight bytes every envelope starts with.
 *
 * The last byte is reserved and must be zero: it is part of the AAD, so a
 * client that wrote anything else there would produce blobs the server's own
 * reader rejects.
 */
function encodeHeader(mode: number, epoch: number): Bytes {
  const b = new Uint8Array(HEADER_LEN) as Bytes
  b[0] = MAGIC0
  b[1] = MAGIC1
  b[2] = VERSION
  b[3] = SUITE_V1
  b[4] = mode
  new DataView(b.buffer).setUint16(5, epoch, false)
  return b
}

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
 */
export async function sealDirect(
  publicRaw: Bytes,
  kind: Kind,
  tenant: Bytes,
  row: Bytes,
  epoch: number,
  plaintext: Bytes,
): Promise<Bytes> {
  const header = encodeHeader(MODE_DIRECT, epoch)
  const { enc, ciphertext } = await hpkeSeal(
    publicRaw,
    infoFor(kind, tenant, epoch),
    buildAAD(kind, tenant, row, header),
    plaintext,
  )
  return concat(header, enc, ciphertext)
}

/**
 * openDirect opens a value sealed straight to the archive key.
 *
 * Used only for content keys and grants. One asymmetric operation per value is
 * what makes opening a large history slow, which is why message content never
 * takes this path.
 */
export async function openDirect(
  priv: PrivateKey,
  kind: Kind,
  tenant: Bytes,
  row: Bytes,
  envelope: Bytes,
): Promise<Bytes> {
  const h = parseHeader(envelope)
  if (h.mode !== MODE_DIRECT) throw new SealError('esperava modo direto', 'mode')
  if (envelope.length < HEADER_LEN + ENC_LEN + TAG_LEN) {
    throw new SealError('envelope curto demais', 'short')
  }

  const header = envelope.subarray(0, HEADER_LEN)
  const enc = envelope.subarray(HEADER_LEN, HEADER_LEN + ENC_LEN)
  const ciphertext = envelope.subarray(HEADER_LEN + ENC_LEN)

  try {
    return await hpkeOpen(
      priv,
      enc,
      infoFor(kind, tenant, h.epoch),
      buildAAD(kind, tenant, row, header),
      ciphertext,
    )
  } catch {
    // Deliberately opaque, as on the server: telling "wrong key" apart from
    // "moved row" apart from "tampered" hands an attacker an oracle for
    // probing the binding.
    throw new SealError('autenticação falhou', 'authentication')
  }
}

/**
 * ContentKey is a symmetric key covering a batch of sealed values.
 *
 * Batching is a requirement, not a tuning knob: one X25519 operation per
 * message is twelve to thirty seconds to open a ten-thousand message history on
 * a mid-range phone, and it recurs on every new device.
 */
export class ContentKey {
  private constructor(
    readonly id: number,
    readonly epoch: number,
    private readonly key: CryptoKey,
  ) {}

  /**
   * unwrap opens a stored content key with a device's archive private key.
   *
   * The device is part of it because the archive key is per device: content
   * key ids are counted per device, so id 7 names a different key on every
   * account, and the row the value binds to is derived from both.
   */
  static async unwrap(
    priv: PrivateKey,
    tenant: Bytes,
    device: Bytes,
    id: number,
    sealed: Bytes,
  ): Promise<ContentKey> {
    const h = parseHeader(sealed)
    const row = await contentKeyRow(tenant, device, id)
    const raw = await openDirect(priv, Kind.ContentKey, tenant, row, sealed)
    if (raw.length !== 32) {
      throw new SealError(`a chave de conteúdo tem ${raw.length} bytes, esperava 32`, 'short')
    }
    const key = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt'])
    return new ContentKey(id, h.epoch, key)
  }

  async open(
    kind: Kind,
    tenant: Bytes,
    row: Bytes,
    envelope: Bytes,
  ): Promise<Bytes> {
    const h = parseHeader(envelope)
    if (h.mode !== MODE_BATCH) throw new SealError('esperava modo em lote', 'mode')
    if (envelope.length < HEADER_LEN + 4 + NONCE_LEN + TAG_LEN) {
      throw new SealError('envelope curto demais', 'short')
    }
    const wants = readUint32BE(envelope, HEADER_LEN)
    if (wants !== this.id) {
      throw new SealError(
        `o envelope precisa da chave de conteúdo ${wants}, esta é a ${this.id}`,
        'key_mismatch',
      )
    }

    const header = envelope.subarray(0, HEADER_LEN)
    const nonce = envelope.subarray(HEADER_LEN + 4, HEADER_LEN + 4 + NONCE_LEN)
    const ciphertext = envelope.subarray(HEADER_LEN + 4 + NONCE_LEN)

    try {
      const plaintext = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: nonce,
          additionalData: buildAAD(kind, tenant, row, header),
          tagLength: 128,
        },
        this.key,
        ciphertext,
      )
      return new Uint8Array(plaintext)
    } catch {
      throw new SealError('autenticação falhou', 'authentication')
    }
  }
}

/**
 * contentKeyRow derives the row identity a content key is bound to.
 *
 * Derived rather than stored, so a key sealed for one slot cannot be presented
 * as another — or as another device's.
 */
async function contentKeyRow(tenant: Bytes, device: Bytes, id: number): Promise<Bytes> {
  const name = new Uint8Array(20)
  name.set(device, 0)
  new DataView(name.buffer).setUint32(16, id, false)
  return uuidV5(tenant, name)
}

/**
 * grantRow derives the row a key grant binds to.
 *
 * A grant is one device's private archive key sealed to one person's public
 * key. Binding it to (device, user, epoch) stops a grant issued for one device
 * being presented as the grant for another.
 */
export async function grantRow(
  tenant: Bytes,
  device: Bytes,
  user: Bytes,
  epoch: number,
): Promise<Bytes> {
  const name = new Uint8Array(34)
  name.set(device, 0)
  name.set(user, 16)
  new DataView(name.buffer).setUint16(32, epoch, false)
  return uuidV5(tenant, name)
}
