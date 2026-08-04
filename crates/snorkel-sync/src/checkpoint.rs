//! The trust checkpoint (SYNC-SPEC.md §5).
//!
//! `{format_version, genesis_hash, height, block_hash, state_root,
//! set_id, authorities, self_hash}` — SCALE on disk, never
//! human-readable (a CLI debug verb renders it). Release-baked copies
//! inherit release signing; the store-persisted rolling copy is
//! tamper-EVIDENT via `self_hash` (blake2b-256 of the SCALE bytes
//! above it), not tamper-proof: a disk-writing attacker owns the
//! machine, the same threat class as a node keystore.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use parity_scale_codec::{Decode, Encode};

use crate::wire::H256;

type Blake2b256 = Blake2b<U32>;

/// Checkpoint format version (independent of the spec version:
/// this struct is client-persisted state, not wire).
pub const CHECKPOINT_FORMAT: u16 = 1;

/// One authority: hybrid-PQ public key bytes (opaque here; the
/// verifier interprets them) + voting weight.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
pub struct Authority {
    pub public: Vec<u8>,
    pub weight: u64,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
pub struct Checkpoint {
    pub format_version: u16,
    pub genesis_hash: H256,
    pub height: u64,
    pub block_hash: H256,
    pub state_root: H256,
    pub set_id: u64,
    pub authorities: Vec<Authority>,
    /// blake2b-256 over the SCALE encoding of every field above.
    pub self_hash: H256,
}

/// Body = every field except `self_hash`; the hash commits to this.
#[derive(Encode)]
struct CheckpointBody<'a> {
    format_version: u16,
    genesis_hash: &'a H256,
    height: u64,
    block_hash: &'a H256,
    state_root: &'a H256,
    set_id: u64,
    authorities: &'a Vec<Authority>,
}

fn body_hash(c: &Checkpoint) -> H256 {
    let body = CheckpointBody {
        format_version: c.format_version,
        genesis_hash: &c.genesis_hash,
        height: c.height,
        block_hash: &c.block_hash,
        state_root: &c.state_root,
        set_id: c.set_id,
        authorities: &c.authorities,
    };
    let digest = Blake2b256::digest(body.encode());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

impl Checkpoint {
    /// Build with a freshly computed `self_hash`.
    pub fn sealed(
        genesis_hash: H256,
        height: u64,
        block_hash: H256,
        state_root: H256,
        set_id: u64,
        authorities: Vec<Authority>,
    ) -> Self {
        let mut c = Checkpoint {
            format_version: CHECKPOINT_FORMAT,
            genesis_hash,
            height,
            block_hash,
            state_root,
            set_id,
            authorities,
            self_hash: [0; 32],
        };
        c.self_hash = body_hash(&c);
        c
    }

    /// Decode + integrity-check persisted bytes. Any mismatch —
    /// truncation, bit-flip, format drift — surfaces here as an error,
    /// never as a silently-wrong trust base.
    pub fn load(bytes: &[u8]) -> Result<Self, String> {
        let c = Checkpoint::decode(&mut &bytes[..])
            .map_err(|e| format!("checkpoint decode: {e}"))?;
        if c.format_version != CHECKPOINT_FORMAT {
            return Err(format!(
                "checkpoint format {} != supported {CHECKPOINT_FORMAT}",
                c.format_version
            ));
        }
        if body_hash(&c) != c.self_hash {
            return Err("checkpoint self-hash mismatch (tampered or corrupt)".into());
        }
        Ok(c)
    }

    pub fn store_bytes(&self) -> Vec<u8> {
        self.encode()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn sample() -> Checkpoint {
        Checkpoint::sealed(
            [9; 32],
            100,
            [1; 32],
            [2; 32],
            7,
            vec![Authority { public: vec![0xaa; 48], weight: 1 }],
        )
    }

    #[test]
    fn roundtrip() {
        let c = sample();
        let loaded = Checkpoint::load(&c.store_bytes()).unwrap();
        assert_eq!(loaded, c);
    }

    #[test]
    fn tamper_is_evident() {
        let c = sample();
        let mut bytes = c.store_bytes();
        // Flip one bit inside the height field.
        bytes[40] ^= 0x01;
        assert!(Checkpoint::load(&bytes).is_err());
    }

    #[test]
    fn truncation_is_evident() {
        let c = sample();
        let bytes = c.store_bytes();
        assert!(Checkpoint::load(&bytes[..bytes.len() - 3]).is_err());
    }

    #[test]
    fn self_hash_edit_is_evident() {
        let c = sample();
        let mut bytes = c.store_bytes();
        let n = bytes.len();
        bytes[n - 1] ^= 0xff;
        assert!(Checkpoint::load(&bytes).is_err());
    }
}
