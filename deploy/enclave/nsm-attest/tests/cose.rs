// Decoding and checking attestation documents (src/timefeed/cose.rs).
mod common;

use aws_nitro_enclaves_nsm_api::api::Digest;
use common::{sign1, DocSpec, T0_MS};
use nsm_attest::timefeed::cose::{decode, Doc, DocError};
use nsm_attest::timefeed::{DATE_CEIL_MS, DATE_FLOOR_MS};

const TAGGED: &[u8] = include_bytes!("fixtures/attest-tag18.doc");
const UNTAGGED: &[u8] = include_bytes!("fixtures/attest-untagged.doc");

/// The fixtures' nonce: bytes 0 to 31 (tests/fixtures/make-fixtures.mjs).
fn fixture_nonce() -> Vec<u8> {
    (0..32).collect()
}

#[test]
fn the_fixture_decodes_with_and_without_tag_18() {
    let want = Doc { timestamp_ms: T0_MS, pcr0: vec![0xab; 48] };
    assert_eq!(TAGGED[0], 0xd2);
    assert_eq!(&TAGGED[1..], UNTAGGED);
    assert_eq!(decode(TAGGED, &fixture_nonce()), Ok(want.clone()));
    assert_eq!(decode(UNTAGGED, &fixture_nonce()), Ok(want));
}

#[test]
fn nonce_mismatch() {
    let mut other = fixture_nonce();
    other[31] ^= 1;
    assert_eq!(decode(UNTAGGED, &other), Err(DocError::Nonce));
    assert_eq!(decode(TAGGED, &[]), Err(DocError::Nonce));
    let mut spec = DocSpec::new(T0_MS, &[7; 32]);
    spec.nonce = None;
    assert_eq!(decode(&spec.document(), &[7; 32]), Err(DocError::Nonce), "no nonce in the document");
}

#[test]
fn another_tag_or_trailing_bytes_are_refused() {
    let mut tag17 = TAGGED.to_vec();
    tag17[0] = 0xd1;
    assert_eq!(decode(&tag17, &fixture_nonce()), Err(DocError::NotSign1));
    let mut trailing = UNTAGGED.to_vec();
    trailing.push(0);
    assert_eq!(decode(&trailing, &fixture_nonce()), Err(DocError::NotSign1));
    assert_eq!(decode(&UNTAGGED[..UNTAGGED.len() - 1], &fixture_nonce()), Err(DocError::NotSign1));
    assert_eq!(decode(&[], &fixture_nonce()), Err(DocError::NotSign1));
}

#[test]
fn not_a_sign1_array() {
    // Three items, five items, and a payload that is not a byte string.
    let three = serde_cbor::to_vec(&(serde_bytes::ByteBuf::new(), serde_cbor::Value::Map(Default::default()), serde_bytes::ByteBuf::new())).unwrap();
    assert_eq!(decode(&three, &[]), Err(DocError::NotSign1));
    let mut five = UNTAGGED.to_vec();
    five[0] = 0x85;
    five.push(0xf6);
    assert_eq!(decode(&five, &fixture_nonce()), Err(DocError::NotSign1));
    let unprotected_not_map = serde_cbor::to_vec(&(
        serde_bytes::ByteBuf::new(),
        0u8,
        serde_bytes::ByteBuf::from(DocSpec::new(T0_MS, &[1; 32]).payload()),
        serde_bytes::ByteBuf::new(),
    ))
    .unwrap();
    assert_eq!(decode(&unprotected_not_map, &[1; 32]), Err(DocError::NotSign1));
}

#[test]
fn a_payload_that_is_not_an_attestation_doc() {
    let payload = serde_cbor::to_vec(&std::collections::BTreeMap::from([("module_id", "x")])).unwrap();
    assert_eq!(decode(&sign1(&payload), &[]), Err(DocError::Payload));
}

#[test]
fn digest_module_id_and_pcr0() {
    let nonce = [3u8; 32];
    let mut spec = DocSpec::new(T0_MS, &nonce);
    spec.digest = Digest::SHA256;
    assert_eq!(decode(&spec.document(), &nonce), Err(DocError::Digest));
    let mut spec = DocSpec::new(T0_MS, &nonce);
    spec.module_id = String::new();
    assert_eq!(decode(&spec.document(), &nonce), Err(DocError::ModuleId));
    let mut spec = DocSpec::new(T0_MS, &nonce);
    spec.pcr0 = None;
    assert_eq!(decode(&spec.document(), &nonce), Err(DocError::Pcr0));
    spec.pcr0 = Some(vec![0; 32]);
    assert_eq!(decode(&spec.document(), &nonce), Err(DocError::Pcr0), "not 48 bytes");
}

#[test]
fn timestamp_between_the_floor_and_2100() {
    let nonce = [4u8; 32];
    let at = |ms| decode(&DocSpec::new(ms, &nonce).document(), &nonce).map(|d| d.timestamp_ms);
    assert_eq!(at(DATE_FLOOR_MS), Err(DocError::Timestamp));
    assert_eq!(at(DATE_FLOOR_MS + 1), Ok(DATE_FLOOR_MS + 1));
    assert_eq!(at(DATE_CEIL_MS - 1), Ok(DATE_CEIL_MS - 1));
    assert_eq!(at(DATE_CEIL_MS), Err(DocError::Timestamp));
    assert_eq!(at(0), Err(DocError::Timestamp));
    // The floor is 2026-11-01T00:00:00Z.
    assert_eq!(DATE_FLOOR_MS, 1_793_491_200_000);
}
