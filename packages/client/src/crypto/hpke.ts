// HPKE (RFC 9180) base mode.
//
// Suite, frozen to match internal/crypto/seal: DHKEM(X25519, HKDF-SHA256) /
// HKDF-SHA256 / AES-256-GCM. Nothing is negotiated, so there is no downgrade to
// negotiate.
//
// The implementation is the shared kit's (@thehappieco/kit/hpke), which started
// as this file: WebCrypto with no third-party dependency, pinned against Go's
// crypto/hpke in both directions. Go seals and this opens
// (internal/crypto/seal/testdata/vectors.json, with the cases that must fail);
// this seals and Go opens (testdata/browser-grant.json, a grant sealed here).
// A grant sealed wrong is not a visible failure: it stores fine, and the
// archive it unlocks is unreadable forever.
//
// The kit calls importArchiveKey importPrivateKey, since the key may be any
// X25519 key; this client keeps the name its callers use.

export {
  ENC_LEN,
  generateKeyPair,
  importPrivateKey as importArchiveKey,
  open,
  publicFromPrivate,
  seal,
  type KeyPair,
  type PrivateKey,
} from '@thehappieco/kit/hpke'
