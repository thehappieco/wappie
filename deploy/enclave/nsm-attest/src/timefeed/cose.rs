// One attestation document: the COSE_Sign1 array
//   [protected: bstr, unprotected: map, payload: bstr, signature: bstr]
// with or without COSE tag 18 in front, whose payload is the NSM's
// AttestationDoc. The signature is not checked: inside the enclave /dev/nsm
// is the hypervisor's own device, and checking the chain would need a trusted
// clock, which is what this is building. The checks below catch parsing
// bugs, a stale or cached answer (the nonce) and nonsense.
use super::{DATE_CEIL_MS, DATE_FLOOR_MS};
use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
use serde_bytes::ByteBuf;
use serde_cbor::Value;

/// The one-byte CBOR head of tag 18 (major type 6, value 18).
const TAG_18: u8 = 0xd2;
/// PCRs are SHA-384 values.
const PCR_LEN: usize = 48;

/// What a sample needs from a checked document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Doc {
    pub timestamp_ms: u64,
    pub pcr0: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DocError {
    /// Not a COSE_Sign1 array (or a tag other than 18 in front).
    NotSign1,
    /// The payload is not an AttestationDoc.
    Payload,
    Digest,
    ModuleId,
    Nonce,
    Pcr0,
    Timestamp,
}

/// Decodes `bytes` and checks it was made for `nonce`.
pub fn decode(bytes: &[u8], nonce: &[u8]) -> Result<Doc, DocError> {
    let body = match bytes.first() {
        Some(&TAG_18) => &bytes[1..],
        // Any other tag: serde_cbor would skip it silently, so refuse here.
        Some(b) if b >> 5 == 6 => return Err(DocError::NotSign1),
        _ => bytes,
    };
    // A 4-tuple only matches an array of exactly four items, and from_slice
    // refuses trailing bytes.
    let (_protected, unprotected, payload, _signature): (ByteBuf, Value, ByteBuf, ByteBuf) =
        serde_cbor::from_slice(body).map_err(|_| DocError::NotSign1)?;
    if !matches!(unprotected, Value::Map(_)) {
        return Err(DocError::NotSign1);
    }
    let doc = AttestationDoc::from_binary(&payload).map_err(|_| DocError::Payload)?;
    check(&doc, nonce)
}

/// The checks on a decoded document.
pub fn check(doc: &AttestationDoc, nonce: &[u8]) -> Result<Doc, DocError> {
    if doc.digest != Digest::SHA384 {
        return Err(DocError::Digest);
    }
    if doc.module_id.is_empty() {
        return Err(DocError::ModuleId);
    }
    if doc.nonce.as_deref().map(|n| n.as_slice()) != Some(nonce) {
        return Err(DocError::Nonce);
    }
    let pcr0 = match doc.pcrs.get(&0) {
        Some(value) if value.len() == PCR_LEN => value.to_vec(),
        _ => return Err(DocError::Pcr0),
    };
    if !(doc.timestamp > DATE_FLOOR_MS && doc.timestamp < DATE_CEIL_MS) {
        return Err(DocError::Timestamp);
    }
    Ok(Doc { timestamp_ms: doc.timestamp, pcr0 })
}
