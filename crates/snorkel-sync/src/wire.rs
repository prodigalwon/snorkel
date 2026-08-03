//! Frozen wire structs of the Rostro sync contract (SYNC-CONTRACT.md §6).
//!
//! These are DELIBERATE local mirrors of the server-side definitions in
//! Rostro's `rostro-sync-rpc` crate: the contract requires clients to
//! define the frozen structs locally rather than import the chain
//! workspace's dependency graph. Drift between the two copies is caught
//! by the shared golden vectors (the hex constants in this file's tests
//! are byte-identical to the server crate's), not by a code dependency.
//!
//! Every response envelope is a single `0x`-hex SCALE blob; the bytes
//! decoded here are the exact bytes the courier produced, and the
//! load-bearing fields (`header`, `justification`) stay canonical —
//! they are hashed and signature-checked as received, never re-encoded.

use parity_scale_codec::{Decode, Encode};

/// 32-byte hash, contract-side. Kept as a plain array so no chain
/// crate is needed.
pub type H256 = [u8; 32];

/// Contract version this client implements: major.minor packed as
/// upper/lower 16 bits. A courier with a different MAJOR is refused
/// (contract §2).
pub const CONTRACT_VERSION: u32 = 0x0001_0000;

/// Storage schema version this client understands. Dual-tolerance rule:
/// a release must accept N and N+1.
pub const SCHEMA_VERSION: u16 = 1;

#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
pub struct Retention {
    pub justification_cadence: u32,
    pub state_window: u32,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
pub struct HandshakeInfo {
    pub contract_version: u32,
    pub schema_version: u16,
    pub genesis_hash: H256,
    pub finalized_height: u64,
    pub finalized_hash: H256,
    pub capabilities: u32,
    pub retention: Retention,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
pub struct FinalizedHead {
    pub height: u64,
    pub hash: H256,
    /// Canonical SCALE header bytes (contains `state_root`).
    pub header: Vec<u8>,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
pub struct JustifiedHeader {
    pub header: Vec<u8>,
    pub justification: Vec<u8>,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
pub struct SnapshotPage {
    pub entries: Vec<(Vec<u8>, Vec<u8>)>,
    pub range_proof: Vec<Vec<u8>>,
    pub next_key: Option<Vec<u8>>,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
pub struct NibblePath {
    pub nibbles: Vec<u8>,
    pub flags: u8,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
pub struct TrieNodes {
    pub nodes: Vec<Option<Vec<u8>>>,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
pub struct NameProof {
    pub anchor_header: Vec<u8>,
    pub proof: Vec<Vec<u8>>,
    pub entries: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Hex decode ("0x"-tolerant). Local helper: no hex-crate dependency.
pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    let raw = s.strip_prefix("0x").unwrap_or(s);
    if !raw.len().is_multiple_of(2) {
        return Err(format!("odd-length hex ({} chars)", raw.len()));
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    let bytes = raw.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let pair = bytes.get(i..i + 2).ok_or("hex bounds")?;
        let hi = hex_val(*pair.first().ok_or("hex bounds")?)?;
        let lo = hex_val(*pair.get(1).ok_or("hex bounds")?)?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        other => Err(format!("bad hex byte 0x{other:02x}")),
    }
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Golden vectors shared byte-for-byte with the server crate
    /// (`rostro-sync-rpc` tests). If either side drifts, its copy of
    /// these constants fails, and the drift is a contract event.
    #[test]
    fn scale_wire_golden_vectors() {
        let retention = Retention { justification_cadence: 512, state_window: 7200 };
        assert_eq!(to_hex(&retention.encode()), "0x00020000201c0000");

        let head = FinalizedHead {
            height: 42,
            hash: [0xab; 32],
            header: vec![1, 2, 3],
        };
        assert_eq!(
            to_hex(&head.encode()),
            "0x2a00000000000000abababababababababababababababababababababababababababababababab0c010203"
        );

        let jh = JustifiedHeader { header: vec![7], justification: vec![8, 9] };
        assert_eq!(to_hex(&jh.encode()), "0x0407080809");
    }

    #[test]
    fn envelope_roundtrip() {
        let info = HandshakeInfo {
            contract_version: CONTRACT_VERSION,
            schema_version: SCHEMA_VERSION,
            genesis_hash: [9; 32],
            finalized_height: 7,
            finalized_hash: [1; 32],
            capabilities: 0,
            retention: Retention { justification_cadence: 512, state_window: 7200 },
        };
        let hexed = to_hex(&info.encode());
        let raw = from_hex(&hexed).unwrap();
        let back = HandshakeInfo::decode(&mut raw.as_slice()).unwrap();
        assert_eq!(back, info);
    }

    #[test]
    fn hex_rejects_garbage() {
        assert!(from_hex("0x123").is_err());
        assert!(from_hex("0xzz").is_err());
        assert_eq!(from_hex("0x").unwrap(), Vec::<u8>::new());
    }
}
