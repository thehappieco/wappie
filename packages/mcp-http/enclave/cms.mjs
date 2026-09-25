// Opens KMS CiphertextForRecipient: a CMS ContentInfo(EnvelopedData) with one
// KeyTransRecipientInfo (RSAES-OAEP, SHA-256) and AES-256-CBC content. This is
// the shape aws-nitro-enclaves-sdk-c (source/cms.c) parses. KMS sends BER with
// indefinite lengths and chunked OCTET STRINGs, so DER-only parsing is not enough.
import * as asn1js from 'asn1js'
import { constants, createDecipheriv, privateDecrypt } from 'node:crypto'

const OID = {
  data: '1.2.840.113549.1.7.1',
  envelopedData: '1.2.840.113549.1.7.3',
  rsaesOaep: '1.2.840.113549.1.1.7',
  mgf1: '1.2.840.113549.1.1.8',
  pSpecified: '1.2.840.113549.1.1.9',
  sha256: '2.16.840.1.101.3.4.2.1',
  aes256cbc: '2.16.840.1.101.3.4.1.42',
}

const fail = code => { throw new Error(code) }
const kids = node => node?.idBlock?.isConstructed ? node.valueBlock.value : fail('cms_parse')
const seq = node => node instanceof asn1js.Sequence ? kids(node) : fail('cms_parse')
const oid = node => node instanceof asn1js.ObjectIdentifier ? node.getValue() : fail('cms_parse')
const isContext = (node, tag) => node?.idBlock?.tagClass === 3 && node.idBlock.tagNumber === tag
// The single element inside an EXPLICIT [n] tag.
const explicit = node => { const [inner, ...rest] = kids(node); return inner && !rest.length ? inner : fail('cms_parse') }
const algorithmOid = node => oid(seq(node)[0])

// OCTET STRING contents, primitive or constructed. BER may split the value into
// segments, which may themselves be constructed; asn1js keeps them as children.
function octets(node) {
  if (!node.idBlock.isConstructed) return Buffer.from(node.valueBlock.valueHexView)
  return Buffer.concat(kids(node).map(part => part instanceof asn1js.OctetString ? octets(part) : fail('cms_parse')))
}
const octetString = node => node instanceof asn1js.OctetString ? octets(node) : fail('cms_parse')

// RSAES-OAEP-params ::= SEQUENCE { hashAlgorithm [0], maskGenAlgorithm [1],
// pSourceAlgorithm [2] }, all EXPLICIT with SHA-1 defaults. Node's OAEP uses one
// hash for both OAEP and MGF1, so anything but SHA-256/MGF1-SHA-256 is refused.
// Absent parameters are accepted: the request itself fixed RSAES_OAEP_SHA_256.
function checkOaep(algorithm) {
  const [id, params, ...rest] = seq(algorithm)
  if (rest.length) fail('cms_parse')
  if (oid(id) !== OID.rsaesOaep) fail('cms_not_oaep')
  if (params === undefined) return
  const fields = seq(params)
  if (!fields.every(field => [0, 1, 2].some(tag => isContext(field, tag)))) fail('cms_parse')
  const [hash, mgf, label] = [0, 1, 2].map(tag => fields.find(field => isContext(field, tag)))
  if (!hash || algorithmOid(explicit(hash)) !== OID.sha256) fail('cms_oaep_hash')
  if (!mgf) fail('cms_oaep_hash')
  const [mgfId, mgfHash, ...more] = seq(explicit(mgf))
  if (more.length || oid(mgfId) !== OID.mgf1 || algorithmOid(mgfHash) !== OID.sha256) fail('cms_oaep_hash')
  if (label) {
    const [labelId, value] = seq(explicit(label))
    if (oid(labelId) !== OID.pSpecified || octetString(value).length) fail('cms_not_oaep')
  }
}

// KeyTransRecipientInfo ::= SEQUENCE { version, rid, keyEncryptionAlgorithm, encryptedKey }.
// rid is issuerAndSerialNumber (a SEQUENCE) or [0] subjectKeyIdentifier, which
// is what KMS sends. The other RecipientInfo kinds are tagged [1] to [4].
function keyTransport(recipientInfos) {
  if (!(recipientInfos instanceof asn1js.Set)) fail('cms_parse')
  const infos = kids(recipientInfos)
  if (infos.length !== 1 || !(infos[0] instanceof asn1js.Sequence)) fail('cms_recipients')
  const [version, rid, algorithm, encryptedKey, ...rest] = kids(infos[0])
  if (rest.length || !(version instanceof asn1js.Integer)) fail('cms_parse')
  if (!(rid instanceof asn1js.Sequence) && !isContext(rid, 0)) fail('cms_parse')
  checkOaep(algorithm)
  return octetString(encryptedKey)
}

// EncryptedContentInfo ::= SEQUENCE { contentType, contentEncryptionAlgorithm,
// encryptedContent [0] IMPLICIT OCTET STRING }. AES-CBC carries its IV as the
// algorithm parameter (RFC 3565).
function encryptedContent(info) {
  const [type, algorithm, content, ...rest] = seq(info)
  if (rest.length || oid(type) !== OID.data || !isContext(content, 0)) fail('cms_parse')
  const [id, iv, ...more] = seq(algorithm)
  if (oid(id) !== OID.aes256cbc) fail('cms_not_aes256cbc')
  const ivBytes = octetString(iv)
  const ciphertext = octets(content)
  if (more.length || ivBytes.length !== 16 || !ciphertext.length || ciphertext.length % 16) fail('cms_parse')
  return { iv: ivBytes, ciphertext }
}

// ContentInfo -> EnvelopedData ::= SEQUENCE { version, originatorInfo [0] IMPLICIT
// OPTIONAL, recipientInfos, encryptedContentInfo, unprotectedAttrs [1] OPTIONAL }.
function envelope(ber) {
  if (!(ber instanceof Uint8Array) || !ber.length) fail('cms_parse')
  const { offset, result } = asn1js.fromBER(ber)
  if (offset !== ber.byteLength) fail('cms_parse') // -1 on error, short on trailing bytes
  const [contentType, wrapped, ...rest] = seq(result)
  if (oid(contentType) !== OID.envelopedData) fail('cms_not_enveloped')
  if (rest.length || !isContext(wrapped, 0)) fail('cms_parse')
  const [version, ...fields] = seq(explicit(wrapped))
  if (!(version instanceof asn1js.Integer)) fail('cms_parse')
  if (isContext(fields[0], 0)) fields.shift() // originatorInfo: certificates and CRLs, not needed here
  const [recipientInfos, contentInfo, ...tail] = fields
  if (tail.length > 1 || (tail.length && !isContext(tail[0], 1))) fail('cms_parse')
  return { encryptedKey: keyTransport(recipientInfos), ...encryptedContent(contentInfo) }
}

function parse(ber) {
  try {
    return envelope(ber)
  } catch (error) {
    throw /^cms_[a-z0-9_]+$/.test(error?.message) ? error : new Error('cms_parse')
  }
}

/**
 * Returns the plaintext of a KMS CiphertextForRecipient as a Buffer the caller
 * must zero after use. `privateKey` is the enclave's RSA key (a KeyObject).
 * Every decryption failure is the same 'cms_decrypt', so errors reveal nothing
 * about which step (OAEP or CBC padding) went wrong.
 */
export function openRecipientCms(ber, privateKey) {
  const { encryptedKey, iv, ciphertext } = parse(ber)
  // head is out here because update() already holds every block but the last
  // one (all of a 32-byte data key) when final() throws on bad padding.
  let cek, head
  try {
    cek = privateDecrypt({ key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, encryptedKey)
    if (cek.length !== 32) fail('cms_decrypt')
    const decipher = createDecipheriv('aes-256-cbc', cek, iv)
    head = decipher.update(ciphertext)
    const tail = decipher.final()
    try { return Buffer.concat([head, tail]) } finally { tail.fill(0) }
  } catch {
    throw new Error('cms_decrypt')
  } finally {
    cek?.fill(0)
    head?.fill(0)
  }
}
