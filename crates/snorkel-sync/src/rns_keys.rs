//! Deriving RNS storage keys from a name.
//!
//! The snorkel computes every key it asks about. It never accepts a key
//! from the courier — a courier that chose the key could answer a
//! different question than the one asked and the proof would still
//! verify, because the proof only ever attests "this key holds this
//! value".
//!
//! ## Cross-repo drift protection
//!
//! These derivations mirror the chain's storage layout, which lives in
//! a different repository. The tests below assert against the *exact*
//! hex the runtime's own pinned golden vectors produce
//! (`rns_golden_vectors.rs` in the gemini runtime, which fails the
//! chain build on drift). If the pallet layout, a hasher, or a key
//! encoding ever changes, one of these two sides fails rather than the
//! snorkel silently deriving keys nobody stores anything under.
//!
//! ## Namehash
//!
//! ```text
//! hash_label(l)            = keccak_256(ascii_lowercase(l))
//! encode_with_node(p, lh)  = keccak_256(p ‖ lh)      // both H256, SCALE = raw
//! namehash("alice")        = encode_with_node(BASENODE, hash_label("alice"))
//! namehash("sub.alice")    = encode_with_node(namehash("alice"), hash_label("sub"))
//! ```

use blake2::digest::consts::U16;
use blake2::{Blake2b, Digest as _};
use sha3::{Digest as _, Keccak256};

use crate::wire::H256;

/// Namehash of `"rst"` — the Rostro basenode (`rns_types::RST_BASENODE`).
/// Duplicated as a literal so a changed basenode fails a test here.
pub const RST_BASENODE: H256 = [
    161, 35, 83, 185, 48, 192, 248, 170, 91, 171, 154, 39, 99, 61, 120, 167, 226, 225, 102, 211,
    121, 182, 144, 34, 106, 234, 186, 142, 117, 132, 223, 126,
];

fn keccak256(data: &[u8]) -> H256 {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Keccak256::digest(data));
    out
}

fn blake2_128(data: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&Blake2b::<U16>::digest(data));
    out
}

/// xxHash64 seed 0, little-endian — Substrate's `twox_64`.
fn twox_64(data: &[u8]) -> [u8; 8] {
    use core::hash::Hasher as _;
    let mut h = twox_hash::XxHash64::with_seed(0);
    h.write(data);
    h.finish().to_le_bytes()
}

/// `twox_64(seed 0) ‖ twox_64(seed 1)`, both little-endian.
fn twox_128(data: &[u8]) -> [u8; 16] {
    use core::hash::Hasher as _;
    let mut a = twox_hash::XxHash64::with_seed(0);
    a.write(data);
    let mut b = twox_hash::XxHash64::with_seed(1);
    b.write(data);
    let mut out = [0u8; 16];
    out.get_mut(..8).map(|s| s.copy_from_slice(&a.finish().to_le_bytes()));
    out.get_mut(8..).map(|s| s.copy_from_slice(&b.finish().to_le_bytes()));
    out
}

/// `twox128(pallet) ‖ twox128(item)`.
fn prefix(pallet: &str, item: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(32);
    v.extend_from_slice(&twox_128(pallet.as_bytes()));
    v.extend_from_slice(&twox_128(item.as_bytes()));
    v
}

/// Transparent hasher: `twox64(key) ‖ key`.
fn twox64_concat(key: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(key.len().saturating_add(8));
    v.extend_from_slice(&twox_64(key));
    v.extend_from_slice(key);
    v
}

/// Transparent hasher: `blake2_128(key) ‖ key`.
fn blake2_128_concat(key: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(key.len().saturating_add(16));
    v.extend_from_slice(&blake2_128(key));
    v.extend_from_slice(key);
    v
}

/// Reject labels the chain would reject, so a malformed query fails
/// here rather than deriving a key for a name that cannot exist.
fn valid_label(label: &[u8]) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        && label.first() != Some(&b'-')
        && label.last() != Some(&b'-')
}

fn hash_label(label: &[u8]) -> Option<H256> {
    if !valid_label(label) {
        return None;
    }
    let lowered: Vec<u8> = label.iter().map(|b| b.to_ascii_lowercase()).collect();
    Some(keccak256(&lowered))
}

fn encode_with_node(parent: &H256, label_hash: &H256) -> H256 {
    let mut buf = [0u8; 64];
    buf.get_mut(..32).map(|s| s.copy_from_slice(parent));
    buf.get_mut(32..).map(|s| s.copy_from_slice(label_hash));
    keccak256(&buf)
}

/// Namehash for a name relative to the basenode. Accepts `"alice"` or
/// `"sub.alice"`; deeper nesting is rejected, matching the chain.
pub fn namehash(name: &[u8], base_node: &H256) -> Option<H256> {
    match name.iter().position(|b| *b == b'.') {
        None => Some(encode_with_node(base_node, &hash_label(name)?)),
        Some(dot) => {
            let sub = name.get(..dot)?;
            let domain = name.get(dot.saturating_add(1)..)?;
            if domain.contains(&b'.') {
                return None;
            }
            let domain_hash = encode_with_node(base_node, &hash_label(domain)?);
            Some(encode_with_node(&domain_hash, &hash_label(sub)?))
        }
    }
}

/// `RnsResolvers::Records(namehash, record_type)`.
pub fn records_key(nh: &H256, record_type: u8) -> Vec<u8> {
    let mut k = prefix("RnsResolvers", "Records");
    k.extend_from_slice(&twox64_concat(nh));
    k.extend_from_slice(&twox64_concat(&[record_type]));
    k
}

/// `RnsNft::Tokens(class_id, namehash)` — ownership. Names live in
/// class `ClassId::default()`.
pub fn tokens_key(nh: &H256, class_id: u32) -> Vec<u8> {
    let mut k = prefix("RnsNft", "Tokens");
    k.extend_from_slice(&twox64_concat(&class_id.to_le_bytes()));
    k.extend_from_slice(&twox64_concat(nh));
    k
}

/// `RnsRegistrar::RegistrarInfos(namehash)` — carries expiry.
pub fn registrar_infos_key(nh: &H256) -> Vec<u8> {
    let mut k = prefix("RnsRegistrar", "RegistrarInfos");
    k.extend_from_slice(&blake2_128_concat(nh));
    k
}

/// `RnsRegistrar::OfferedNames(namehash)` — a pending gift makes a name
/// DNS-dark while it is unaccepted.
pub fn offered_names_key(nh: &H256) -> Vec<u8> {
    let mut k = prefix("RnsRegistrar", "OfferedNames");
    k.extend_from_slice(&blake2_128_concat(nh));
    k
}

/// `Timestamp::Now` — chain time at the anchor, needed to evaluate
/// expiry without trusting wall clock.
pub fn timestamp_now_key() -> Vec<u8> {
    prefix("Timestamp", "Now")
}

/// Every key a single record lookup must prove: the existence trio,
/// chain time, and the record itself.
pub fn existence_and_record_keys(nh: &H256, record_type: u8) -> Vec<Vec<u8>> {
    vec![
        tokens_key(nh, 0),
        registrar_infos_key(nh),
        offered_names_key(nh),
        timestamp_now_key(),
        records_key(nh, record_type),
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::wire::{from_hex, to_hex};

    const NH: H256 = [0x11u8; 32];

    /// These are the EXACT strings the gemini runtime's golden vectors
    /// pin (`rns_golden_vectors.rs`, which fails the chain build on
    /// drift). Matching them proves the snorkel derives the same keys
    /// the chain stores under, across two repositories.
    #[test]
    fn matches_the_runtimes_pinned_golden_vectors() {
        assert_eq!(
            to_hex(&prefix("RnsResolvers", "Records")),
            "0xb247837125de091547c87145cef93ea7bb8fcc88c3da5bf159c1e1a5f46fe432"
        );
        assert_eq!(
            to_hex(&prefix("RnsNft", "Tokens")),
            "0xafdcd3898b04e97e9ba2fc3cbbd6450399971b5749ac43e0235e41b0d3786918"
        );
        assert_eq!(
            to_hex(&prefix("RnsRegistrar", "RegistrarInfos")),
            "0x001ff227791bc3d66982508f77445fd1feb9b93572009b68729be1ba5f85ffd1"
        );
        assert_eq!(
            to_hex(&prefix("RnsRegistrar", "OfferedNames")),
            "0x001ff227791bc3d66982508f77445fd1c82c4571c92c77ef70912f6749c207c6"
        );
        assert_eq!(
            to_hex(&timestamp_now_key()),
            "0xf0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb"
        );
    }

    /// Full keys, including the transparent-hasher suffixes.
    #[test]
    fn full_keys_match_the_runtime() {
        // RecordType::A is variant index 11 — NOT the IANA number, a
        // trap the runtime's vectors exist to pin.
        assert_eq!(
            to_hex(&records_key(&NH, 0x0b)),
            "0xb247837125de091547c87145cef93ea7bb8fcc88c3da5bf159c1e1a5f46fe432\
             c99bd9a68183033a\
             1111111111111111111111111111111111111111111111111111111111111111\
             b64c9c63c7c092f50b"
                .replace(['\n', ' '], "")
                .as_str()
        );
        assert_eq!(
            to_hex(&tokens_key(&NH, 0)),
            "0xafdcd3898b04e97e9ba2fc3cbbd6450399971b5749ac43e0235e41b0d3786918\
             b4def25cfda6ef3a00000000\
             c99bd9a68183033a\
             1111111111111111111111111111111111111111111111111111111111111111"
                .replace(['\n', ' '], "")
                .as_str()
        );
        assert_eq!(
            to_hex(&registrar_infos_key(&NH)),
            "0x001ff227791bc3d66982508f77445fd1feb9b93572009b68729be1ba5f85ffd1\
             7f9c299f1d9bbe856fbf2c98f0f91435\
             1111111111111111111111111111111111111111111111111111111111111111"
                .replace(['\n', ' '], "")
                .as_str()
        );
    }

    /// The basenode is `keccak_256("rst")`.
    #[test]
    fn basenode_is_the_hash_of_rst() {
        assert_eq!(keccak256(b"rst"), RST_BASENODE);
    }

    #[test]
    fn namehash_is_deterministic_and_case_insensitive() {
        let a = namehash(b"alice", &RST_BASENODE).unwrap();
        let b = namehash(b"ALICE", &RST_BASENODE).unwrap();
        assert_eq!(a, b, "labels are lowercased before hashing");
        assert_ne!(a, namehash(b"bob", &RST_BASENODE).unwrap());
    }

    #[test]
    fn subdomain_nests_under_its_parent() {
        let parent = namehash(b"alice", &RST_BASENODE).unwrap();
        let sub = namehash(b"www.alice", &RST_BASENODE).unwrap();
        assert_eq!(sub, encode_with_node(&parent, &hash_label(b"www").unwrap()));
    }

    #[test]
    fn invalid_labels_are_refused() {
        assert!(namehash(b"", &RST_BASENODE).is_none());
        assert!(namehash(b"-bad", &RST_BASENODE).is_none());
        assert!(namehash(b"bad-", &RST_BASENODE).is_none());
        assert!(namehash(b"has space", &RST_BASENODE).is_none());
        assert!(namehash(&[b'a'; 64], &RST_BASENODE).is_none());
        assert!(namehash(b"a.b.c", &RST_BASENODE).is_none(), "one level of nesting only");
    }

    #[test]
    fn a_lookup_proves_the_existence_trio_plus_the_record() {
        let nh = namehash(b"alice", &RST_BASENODE).unwrap();
        let keys = existence_and_record_keys(&nh, 14);
        assert_eq!(keys.len(), 5);
        assert!(keys.contains(&timestamp_now_key()));
        assert!(keys.contains(&records_key(&nh, 14)));
        // Distinct keys — no accidental duplication.
        let mut sorted = keys.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 5);
        let _ = from_hex("00");
    }
}
