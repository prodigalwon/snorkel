//! Bootstrap: from 64 bytes to a usable trust base.
//!
//! This is the path that makes a standalone snorkel viable. It takes one
//! authentic anchor head and produces a [`Checkpoint`] the follow loop
//! can run from — without trusting any validator, without a
//! weak-subjectivity window, and without walking justifications.
//!
//! ```text
//! authentic head (64 B, cross-checked out of band)
//!   → fold sealed headers                        keccak only
//!   → last sealed header's state_root            verified by the fold
//!   → Merkle-prove Authorities + CurrentSetId    against that root
//!   → Checkpoint                                 authority set DERIVED
//! ```
//!
//! Every input except the head comes from the courier and is
//! self-checking: fabricated headers fold to a different head, and a
//! fabricated proof fails against the folded state root. The head is
//! the single trust input, and being 64 bytes it is uniquely cheap to
//! obtain from several independent sources and compare.
//!
//! Contrast with walking justifications, which costs 172 KB per hop at
//! 32 validators (3.5 MB at 700) and only works inside the unbonding
//! period, since past it the signers have withdrawn their stake and can
//! collude freely. Folding costs ~300 bytes per sealed header and never
//! expires.

use parity_scale_codec::Decode;

use crate::anchor::{verify_chain, AnchorError, H512};
use crate::checkpoint::Checkpoint;
use crate::proof::{FinalityVerified, ProofError, RecordQuery, VerifiedAnchor};
use crate::verify::Authority;
use crate::wire::H256;

/// `twox128("Grandpa") ++ twox128("Authorities")`. A plain
/// `StorageValue`, so the key is the whole prefix with nothing appended.
pub const GRANDPA_AUTHORITIES_KEY: &str =
    "5f9cc45b7a00c5899361e1c6099678dc5e0621c4869aa60c02be9adcc98a0d1d";

/// `twox128("Grandpa") ++ twox128("CurrentSetId")`.
pub const GRANDPA_CURRENT_SET_ID_KEY: &str =
    "5f9cc45b7a00c5899361e1c6099678dc8a2d09463effcc78a22d75b9cb87dffc";

/// Hybrid public key length — what an `AuthorityId` is on the wire.
const AUTHORITY_ID_BYTES: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub enum BootstrapError {
    Anchor(AnchorError),
    Proof(ProofError),
    /// The authority set or set id could not be decoded from proven
    /// bytes. Distinct from a proof failure: the proof was good, the
    /// contents were not what this schema expects.
    Decode(String),
    /// An empty authority set cannot verify anything.
    EmptyAuthoritySet,
}

/// Result of a completed bootstrap: a checkpoint plus the anchor its
/// state was read at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bootstrapped {
    pub checkpoint: Checkpoint,
    pub anchor: VerifiedAnchor,
}

/// Derive a trust base from an authentic anchor head.
///
/// `expected_head` MUST come from outside the courier — a published
/// feed, a release, or several independent sources agreeing. Everything
/// else here is checked against it.
pub fn bootstrap(
    genesis_hash: H256,
    from_head: &H512,
    expected_head: &H512,
    sealed_headers: &[Vec<u8>],
    state_proof: &[Vec<u8>],
) -> Result<Bootstrapped, BootstrapError> {
    // 1. The fold. Nothing below this line is trusted until it passes.
    let anchored =
        verify_chain(from_head, sealed_headers, expected_head).map_err(BootstrapError::Anchor)?;

    // 2. A fold-verified state root is a legitimate proof anchor. This
    //    is the second path to `FinalityVerified` alongside justification
    //    checking, and arguably the stronger one: it rests on Keccak-512
    //    rather than on validators still being honest or still bonded.
    let anchor = VerifiedAnchor::from_verified_header(
        anchored.state_root,
        anchored.height,
        FinalityVerified::assert(),
    );

    // 3. Read the authority set out of proven state.
    let authorities = prove_authorities(&anchor, state_proof)?;
    if authorities.is_empty() {
        return Err(BootstrapError::EmptyAuthoritySet);
    }
    let set_id = prove_set_id(&anchor, state_proof)?;

    // The block hash of the sealed header is not recovered here: the
    // follow loop re-derives it when it adopts its first justified head,
    // and inventing one would be a value nothing verified.
    let checkpoint = Checkpoint::sealed(
        genesis_hash,
        anchored.height,
        [0u8; 32],
        anchored.state_root,
        set_id,
        authorities,
    );

    Ok(Bootstrapped { checkpoint, anchor })
}

fn prove_authorities(
    anchor: &VerifiedAnchor,
    proof: &[Vec<u8>],
) -> Result<Vec<Authority>, BootstrapError> {
    let key = crate::wire::from_hex(GRANDPA_AUTHORITIES_KEY)
        .map_err(|e| BootstrapError::Decode(format!("authorities key: {e}")))?;
    let q = RecordQuery { storage_key: key, record_type: 0 };
    let rec = crate::proof::verify_record(anchor, &q, proof).map_err(BootstrapError::Proof)?;
    decode_authorities(&rec.value)
}

fn prove_set_id(anchor: &VerifiedAnchor, proof: &[Vec<u8>]) -> Result<u64, BootstrapError> {
    let key = crate::wire::from_hex(GRANDPA_CURRENT_SET_ID_KEY)
        .map_err(|e| BootstrapError::Decode(format!("set id key: {e}")))?;
    let q = RecordQuery { storage_key: key, record_type: 0 };
    let rec = crate::proof::verify_record(anchor, &q, proof).map_err(BootstrapError::Proof)?;
    u64::decode(&mut rec.value.as_slice())
        .map_err(|e| BootstrapError::Decode(format!("set id: {e}")))
}

/// `BoundedVec<(AuthorityId, u64)>`: compact length, then 64-byte
/// public key and little-endian weight per entry.
fn decode_authorities(bytes: &[u8]) -> Result<Vec<Authority>, BootstrapError> {
    let mut input = bytes;
    let count = u32::from(
        parity_scale_codec::Compact::<u32>::decode(&mut input)
            .map_err(|e| BootstrapError::Decode(format!("authority count: {e}")))?
            .0,
    );
    // The count is proven state, not courier input, so it cannot be a
    // hostile allocation hint — but bound it anyway, since a schema
    // change should surface as an error rather than a huge allocation.
    if count > 10_000 {
        return Err(BootstrapError::Decode(format!("implausible authority count {count}")));
    }
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        let public = input
            .get(..AUTHORITY_ID_BYTES)
            .ok_or_else(|| BootstrapError::Decode(format!("authority {i}: truncated key")))?
            .to_vec();
        input = input.get(AUTHORITY_ID_BYTES..).unwrap_or(&[]);
        let weight = u64::decode(&mut input)
            .map_err(|e| BootstrapError::Decode(format!("authority {i} weight: {e}")))?;
        out.push(Authority { public, weight });
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::anchor::genesis_head;
    use crate::wire::from_hex;

    /// Captured from a live `gemini-node --dev`: the chain's own
    /// AnchorHead, the sealed header, and a real `state_getReadProof`
    /// covering Authorities + CurrentSetId at that block.
    struct Fx {
        head: H512,
        headers: Vec<Vec<u8>>,
        proof: Vec<Vec<u8>>,
    }

    fn fx() -> Fx {
        let raw = include_str!("../vectors/bootstrap_dev.txt");
        let mut l = raw.lines();
        let mut head = [0u8; 64];
        head.copy_from_slice(&from_hex(l.next().unwrap().trim()).unwrap());
        let headers = vec![from_hex(l.next().unwrap().trim()).unwrap()];
        let proof = l
            .next()
            .unwrap()
            .split('|')
            .map(|h| from_hex(h).unwrap())
            .collect();
        Fx { head, headers, proof }
    }

    /// The whole path: 64 bytes in, usable trust base out, no validator
    /// trusted at any step.
    #[test]
    fn derives_a_trust_base_from_one_authentic_head() {
        let f = fx();
        let b = bootstrap([9u8; 32], &genesis_head(), &f.head, &f.headers, &f.proof).unwrap();
        assert_eq!(b.checkpoint.set_id, 0);
        assert_eq!(b.checkpoint.authorities.len(), 1);
        assert_eq!(b.checkpoint.authorities[0].public.len(), 64, "hybrid pubkey");
        assert_eq!(b.checkpoint.authorities[0].weight, 1);
        assert_eq!(b.anchor.state_root(), &b.checkpoint.state_root);
        // The checkpoint must survive its own integrity check.
        assert_eq!(
            Checkpoint::load(&b.checkpoint.store_bytes()).unwrap(),
            b.checkpoint
        );
    }

    /// A wrong head rejects before any state is read — the fold is the
    /// gate, and nothing downstream runs on unverified input.
    #[test]
    fn wrong_head_rejects_before_reading_state() {
        let f = fx();
        let mut wrong = f.head;
        wrong[0] ^= 0x01;
        assert!(matches!(
            bootstrap([9u8; 32], &genesis_head(), &wrong, &f.headers, &f.proof),
            Err(BootstrapError::Anchor(AnchorError::HeadMismatch { .. }))
        ));
    }

    /// Substituted history is caught even though the state proof itself
    /// is genuine: the forged header yields a different state root, and
    /// the proof no longer verifies under it.
    #[test]
    fn substituted_history_defeats_a_genuine_proof() {
        let f = fx();
        let mut forged = f.headers.clone();
        forged[0][40] ^= 0x01;
        assert!(bootstrap([9u8; 32], &genesis_head(), &f.head, &forged, &f.proof).is_err());
    }

    /// A tampered state proof fails against the fold-verified root.
    #[test]
    fn tampered_state_proof_is_rejected() {
        let f = fx();
        for i in 0..f.proof.len() {
            let mut p = f.proof.clone();
            p[i][0] ^= 0x01;
            if let Ok(b) = bootstrap([9u8; 32], &genesis_head(), &f.head, &f.headers, &p) {
                panic!("tampering with proof node {i} still produced {:?}", b.checkpoint.set_id);
            }
        }
    }

    #[test]
    fn authority_decoding_matches_the_wire_shape() {
        // 1 authority: compact(1) ++ 64-byte key ++ u64 weight = 73 bytes,
        // which is exactly what the live chain returned.
        let mut v = vec![0x04u8];
        v.extend_from_slice(&[0xabu8; 64]);
        v.extend_from_slice(&1u64.to_le_bytes());
        assert_eq!(v.len(), 73);
        let a = decode_authorities(&v).unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].weight, 1);
        assert_eq!(a[0].public.len(), 64);
    }

    #[test]
    fn truncated_authority_list_is_an_error_not_a_panic() {
        let mut v = vec![0x08u8]; // claims 2 authorities
        v.extend_from_slice(&[0xabu8; 64]);
        v.extend_from_slice(&1u64.to_le_bytes());
        assert!(matches!(decode_authorities(&v), Err(BootstrapError::Decode(_))));
    }
}
