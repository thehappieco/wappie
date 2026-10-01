// Byte plumbing shared by the crypto modules.
//
// The implementation is the shared kit's (@thehappieco/kit/bytes), which
// started as this file: the encodings, which is where a reimplementation
// quietly goes wrong, are written once for every product. This module keeps
// the names the rest of the client imports.
//
// uuidV5 must match Go's uuid.NewSHA1 byte for byte: a content key's row is
// derived from its own id rather than stored, and a derivation that drifted
// would open no content key at all.

export {
  type Bytes,
  concat,
  encodeUTF8,
  equal,
  formatUUID,
  fromBase64,
  fromHex,
  i2osp2,
  newUUIDv7,
  parseUUID,
  readUint16BE,
  readUint32BE,
  toBase64,
  toHex,
  uuidV5,
} from '@thehappieco/kit/bytes'
