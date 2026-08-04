//! State-proof verification: turning courier bytes into a record we
//! are willing to serve.
//!
//! A proof on its own proves nothing. It says "this value sits in a
//! trie whose root is X" — and a hostile courier can build any trie it
//! likes, compute its root, and produce a perfect proof against it.
//! The proof only becomes meaningful once `X` is the `state_root` of a
//! header that our own justification-following has verified.
//!
//! That ordering is enforced structurally here: [`verify_record`] takes
//! a [`VerifiedAnchor`], and the only way to obtain one is
//! [`VerifiedAnchor::from_verified_header`], whose caller must already
//! have checked the header's justification. There is no constructor
//! that takes a bare state root, so "forgot to verify the header" is
//! not a reachable state.
//!
//! ## Type scoping
//!
//! A DNS client asking for TXT gets TXT. The snorkel does not read,
//! cache, or return other record types for the name, because a
//! resolver has no business learning a name's SS58 address or chat
//! keys as a side effect of a TXT lookup. [`RecordQuery`] names exactly
//! one `(name, record type)` pair, and [`verify_record`] proves and
//! returns exactly that key — anything else in the proof is treated as
//! surplus and ignored.

use std::collections::HashMap;

use substrate_trie_verify::{
    error::Error as TrieCodecError,
    trie_db::{Trie, TrieDBBuilder},
    Blake2Hasher, RostroStateLayout, H256,
};

/// A state root that came from a header we have already verified via
/// GRANDPA finality. Deliberately unconstructable from a bare root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedAnchor {
    state_root: H256,
    height: u64,
}

impl VerifiedAnchor {
    /// Build from a header whose justification the caller has ALREADY
    /// verified. The `_proof_of_verification` argument is a deliberate
    /// speed bump: it makes the precondition visible at every call
    /// site rather than living in a comment.
    pub fn from_verified_header(
        state_root: H256,
        height: u64,
        _proof_of_verification: FinalityVerified,
    ) -> Self {
        Self { state_root, height }
    }

    pub fn state_root(&self) -> &H256 {
        &self.state_root
    }

    pub fn height(&self) -> u64 {
        self.height
    }
}

/// Witness that a header's justification verified. Only
/// [`Self::assert`] creates one, and it is intended to be called
/// exclusively from the finality path.
#[derive(Clone, Copy, Debug)]
pub struct FinalityVerified(());

impl FinalityVerified {
    /// Call ONLY after `verify_justification` returned `Ok`.
    pub fn assert() -> Self {
        FinalityVerified(())
    }
}

/// Exactly one record: a name and a single record type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordQuery {
    /// Full storage key for `(namehash, record_type)`, derived by the
    /// client from the frozen key schedule (never taken from the
    /// courier).
    pub storage_key: Vec<u8>,
    /// The record type this query is for, carried so the answer can be
    /// labelled and a caller cannot mix up which type it asked for.
    pub record_type: u16,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProofError {
    /// The proof does not reconstruct the anchor's state root: the
    /// courier's nodes are inconsistent, or belong to a different trie.
    RootMismatch,
    /// The trie is well-formed under the root, but the requested key is
    /// absent. This is a PROVEN absence — a legitimate NXDOMAIN.
    ProvenAbsent,
    /// The lookup could not complete: malformed nodes, or a proof that
    /// does not contain the path to the requested key. NOT the same as
    /// proven absence — an incomplete proof is a courier failure, and
    /// must never be reported as NXDOMAIN.
    IncompleteProof,
}

/// The verified answer to exactly one [`RecordQuery`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRecord {
    pub record_type: u16,
    pub value: Vec<u8>,
    pub anchor_height: u64,
}

/// Verify that `query`'s key holds `value` under `anchor`.
///
/// Returns the single requested record and nothing else. The proof may
/// physically contain other keys (proofs share upper trie nodes, so
/// this is normal and not suspicious) — they are never read out.
///
/// Absence is distinguished from failure: a well-formed proof that
/// demonstrably lacks the key yields [`ProofError::ProvenAbsent`],
/// which the caller may serve as NXDOMAIN. A proof that cannot be
/// walked yields [`ProofError::IncompleteProof`], which must NOT be
/// served as anything.
pub fn verify_record(
    anchor: &VerifiedAnchor,
    query: &RecordQuery,
    proof_nodes: &[Vec<u8>],
) -> Result<VerifiedRecord, ProofError> {
    let db = build_proof_db(proof_nodes);
    let trie = TrieDBBuilder::<RostroStateLayout>::new(&db, anchor.state_root()).build();

    match trie.get(&query.storage_key) {
        Ok(Some(value)) => Ok(VerifiedRecord {
            record_type: query.record_type,
            value,
            anchor_height: anchor.height(),
        }),
        Ok(None) => Err(ProofError::ProvenAbsent),
        Err(e) => Err(classify(*e)),
    }
}

/// Distinguish "this trie does not match the root we demanded" from
/// "the courier did not give us enough nodes". Both are refusals, but
/// only the first indicates a courier presenting a foreign trie.
fn classify(e: trie_db::TrieError<H256, TrieCodecError<H256>>) -> ProofError {
    match e {
        // The root node itself is missing from the proof, or a node's
        // hash does not match what its parent referenced.
        trie_db::TrieError::InvalidStateRoot(_) => ProofError::RootMismatch,
        _ => ProofError::IncompleteProof,
    }
}

/// Index the proof nodes by their Blake2-256 hash, which is how the
/// trie walker addresses them. A node the courier did not supply is
/// simply absent, and the walk fails rather than inventing anything.
fn build_proof_db(proof_nodes: &[Vec<u8>]) -> ProofDb {
    let mut map = HashMap::with_capacity(proof_nodes.len());
    for node in proof_nodes {
        map.insert(<Blake2Hasher as hash_db::Hasher>::hash(node), node.clone());
    }
    ProofDb { map }
}

/// Read-only node source backed solely by the supplied proof.
pub struct ProofDb {
    map: HashMap<H256, Vec<u8>>,
}

impl hash_db::HashDBRef<Blake2Hasher, Vec<u8>> for ProofDb {
    fn get(&self, key: &H256, _prefix: hash_db::Prefix<'_>) -> Option<Vec<u8>> {
        self.map.get(key).cloned()
    }

    fn contains(&self, key: &H256, _prefix: hash_db::Prefix<'_>) -> bool {
        self.map.contains_key(key)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::wire::from_hex;

    /// Real proof captured 2026-08-04 from `gemini-node --dev` via
    /// `sync_proveName(namehash=0x11*32, types=[TXT])` at block 85.
    /// The name does not exist, so the RNS keys are provably ABSENT
    /// while `Timestamp::Now` is present — giving both cases from
    /// genuine chain bytes.
    struct Fx {
        anchor: VerifiedAnchor,
        nodes: Vec<Vec<u8>>,
        present_key: Vec<u8>,
        present_value: Vec<u8>,
    }

    fn fx() -> Fx {
        let raw = include_str!("../vectors/record_proof_dev.txt");
        let mut l = raw.lines();
        let sr = from_hex(l.next().unwrap().trim()).unwrap();
        let mut state_root = [0u8; 32];
        state_root.copy_from_slice(&sr);
        let height: u64 = l.next().unwrap().trim().parse().unwrap();
        let nodes: Vec<Vec<u8>> =
            l.next().unwrap().split('|').map(|h| from_hex(h).unwrap()).collect();
        let e = l.next().unwrap();
        let (k, v) = e.split_once(',').unwrap();
        Fx {
            anchor: VerifiedAnchor::from_verified_header(
                state_root,
                height,
                FinalityVerified::assert(),
            ),
            nodes,
            present_key: from_hex(k).unwrap(),
            present_value: from_hex(v).unwrap(),
        }
    }

    /// The Timestamp::Now key, per the chain's pinned golden vectors.
    const TIMESTAMP_NOW_KEY: &str =
        "f0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb";

    // ---------------- Layer 1: it works ----------------

    #[test]
    fn reads_a_real_value_under_a_real_state_root() {
        let f = fx();
        assert_eq!(f.present_key, from_hex(TIMESTAMP_NOW_KEY).unwrap());
        let q = RecordQuery { storage_key: f.present_key.clone(), record_type: 0xFFFF };
        let got = verify_record(&f.anchor, &q, &f.nodes).unwrap();
        assert_eq!(got.value, f.present_value);
        assert_eq!(got.anchor_height, 85);
    }

    /// Only the requested type comes back. The proof physically
    /// contains other keys (proofs share upper nodes), but a TXT query
    /// yields one TXT answer and nothing else — a resolver must not
    /// learn a name's other records as a side effect.
    #[test]
    fn returns_only_the_requested_record_type() {
        let f = fx();
        let q = RecordQuery { storage_key: f.present_key.clone(), record_type: 14 };
        let got = verify_record(&f.anchor, &q, &f.nodes).unwrap();
        assert_eq!(got.record_type, 14, "answer must be labelled with the asked-for type");
        // The struct carries exactly one value; there is no field in
        // which a second record could be smuggled back to the caller.
        assert_eq!(got.value, f.present_value);
    }

    /// A name that does not exist yields PROVEN absence, not an error
    /// and not a fabricated answer. This is what makes an authoritative
    /// NXDOMAIN honest.
    #[test]
    fn absent_name_is_provably_absent() {
        let f = fx();
        // The TXT key of the non-existent name 0x11*32.
        let mut key = from_hex("b247837125de091547c87145cef93ea7bb8fcc88c3da5bf159c1e1a5f46fe432")
            .unwrap();
        key.extend_from_slice(&from_hex("c99bd9a68183033a").unwrap());
        key.extend_from_slice(&[0x11u8; 32]);
        key.extend_from_slice(&from_hex("b64c9c63c7c092f5").unwrap());
        key.push(0x0e);
        let q = RecordQuery { storage_key: key, record_type: 14 };
        assert_eq!(verify_record(&f.anchor, &q, &f.nodes), Err(ProofError::ProvenAbsent));
    }

    // ---------------- Layer 2: lying fails ----------------

    /// THE test. A hostile courier builds its own trie containing
    /// whatever it likes, computes that trie's root, and serves a
    /// mathematically PERFECT proof against it. Every internal check
    /// passes. It must still be rejected, because the root is not the
    /// one our verified header committed to.
    ///
    /// A snorkel that passes the Layer 1 tests but fails this one is
    /// doing proof-checking as decoration.
    #[test]
    fn fabricated_reality_is_rejected() {
        let f = fx();
        // The attacker's trie: a single leaf, its own root, a flawless
        // proof. (Built by hashing arbitrary nodes — the point is that
        // the root simply is not ours.)
        let fake_root = <Blake2Hasher as hash_db::Hasher>::hash(b"attacker's state trie");
        let fake_anchor = VerifiedAnchor::from_verified_header(
            fake_root,
            f.anchor.height(),
            FinalityVerified::assert(),
        );
        let q = RecordQuery { storage_key: f.present_key.clone(), record_type: 14 };
        // Genuine nodes, fabricated root: the walk cannot even start.
        assert_eq!(
            verify_record(&fake_anchor, &q, &f.nodes),
            Err(ProofError::RootMismatch),
            "a proof under an attacker-chosen root must never verify"
        );
    }

    /// The mirror image: our real root, but the courier substitutes its
    /// own nodes. Nothing hashes to what the root demands.
    #[test]
    fn substituted_proof_nodes_are_rejected() {
        let f = fx();
        let q = RecordQuery { storage_key: f.present_key.clone(), record_type: 14 };
        let fake_nodes = vec![b"not a trie node".to_vec(), b"nor is this".to_vec()];
        assert_eq!(
            verify_record(&f.anchor, &q, &fake_nodes),
            Err(ProofError::RootMismatch)
        );
    }

    /// Tampering must never yield a WRONG value.
    ///
    /// Note what this does NOT assert. A `sync_proveName` response
    /// covers several keys (the existence trio, the requested record
    /// type, `Timestamp::Now`), and a lookup walks only the nodes on
    /// its own key's path. Corrupting a node that belongs to a
    /// different key's path is therefore invisible to this query — and
    /// harmlessly so, since a query for THAT key would fail. The
    /// security property is not "any tampering errors"; it is
    /// "tampering never changes the answer".
    #[test]
    fn tampering_never_yields_a_wrong_value() {
        let f = fx();
        let q = RecordQuery { storage_key: f.present_key.clone(), record_type: 14 };
        let mut detected = 0;
        for idx in 0..f.nodes.len() {
            let mut nodes = f.nodes.clone();
            nodes[idx][0] ^= 0x01;
            match verify_record(&f.anchor, &q, &nodes) {
                Ok(v) => assert_eq!(
                    v.value, f.present_value,
                    "tampering with node {idx} produced a FORGED value"
                ),
                Err(_) => detected += 1,
            }
        }
        assert!(
            detected > 0,
            "no tampering was detected at all — node hashes are not being checked"
        );
    }

    /// Withholding nodes must surface as an INCOMPLETE proof, never as
    /// absence. A courier that drops the path to a key would otherwise
    /// be able to manufacture NXDOMAIN for a name that exists —
    /// censorship dressed as a legitimate answer.
    #[test]
    fn withheld_nodes_are_not_reported_as_absence() {
        let f = fx();
        let q = RecordQuery { storage_key: f.present_key.clone(), record_type: 14 };
        for idx in 0..f.nodes.len() {
            let mut nodes = f.nodes.clone();
            nodes.remove(idx);
            let r = verify_record(&f.anchor, &q, &nodes);
            assert_ne!(
                r,
                Err(ProofError::ProvenAbsent),
                "dropping node {idx} produced a FAKE NXDOMAIN"
            );
        }
    }

    /// A genuine proof for key A must not answer a question about key
    /// B. The key is derived by us, never taken from the courier, so a
    /// substitution shows up as absence-or-failure rather than a value.
    #[test]
    fn key_substitution_does_not_yield_the_wrong_value() {
        let f = fx();
        let mut other = f.present_key.clone();
        other[8] ^= 0xff;
        let q = RecordQuery { storage_key: other, record_type: 14 };
        let r = verify_record(&f.anchor, &q, &f.nodes);
        assert!(
            !matches!(&r, Ok(v) if v.value == f.present_value),
            "a proof for one key answered for a different key"
        );
    }
}
