//! The follow loop: deciding whether to advance the trust checkpoint.
//!
//! Each heartbeat the courier offers a finalized head. This module
//! decides whether to believe it. The decision logic is a pure function
//! ([`evaluate_candidate`]) so it can be tested against real captured
//! bytes with no network involved; `main.rs` supplies the I/O.
//!
//! ## The link that makes a state root trustworthy
//!
//! A justification proves that ≥2/3 of the authority set finalized a
//! **block hash**. It says nothing about any particular sequence of
//! header bytes. So a courier holding a genuine justification for block
//! N can pair it with a *fabricated* header — same claimed height,
//! different `state_root` — and every signature still checks out.
//!
//! The defence is to never take the courier's word for which header the
//! justification is about. We hash the header ourselves and require the
//! justification to be for *that* hash:
//!
//! ```text
//! block_hash := blake2_256(header_bytes)      // computed, not received
//! verify_justification(.., expected_hash = block_hash, ..)
//! → only then is header.state_root usable
//! ```
//!
//! A fabricated header hashes to something else, so the justification
//! targets a different block and verification fails with `WrongTarget`.
//! [`tests::fabricated_header_with_real_justification_is_refused`]
//! exercises exactly this.

use blake2::{digest::consts::U32, Blake2b, Digest};
use parity_scale_codec::{Compact, Decode};

use crate::checkpoint::Checkpoint;
use crate::proof::{FinalityVerified, VerifiedAnchor};
use crate::rules::{judge_anchor, AnchorVerdict};
use crate::verify::{verify_justification, HybridVerify, VerifyError};
use crate::wire::H256;

/// What a header yields once we have decided to trust it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Adoption {
    pub height: u64,
    pub block_hash: H256,
    pub state_root: H256,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Header bytes are not a well-formed header.
    MalformedHeader(String),
    /// The offered head is at or below what we already hold: nothing to
    /// do. Not an attack on its own — a courier that has not advanced
    /// looks exactly like this.
    NotNewer { held: u64, offered: u64 },
    /// The offered head is below the checkpoint: a rollback attempt.
    Rollback { held: u64, offered: u64 },
    /// The justification did not verify against the held authority set.
    /// Also what a genuine authority-set change looks like from here,
    /// which is why the set id is reported.
    Unverified { set_id: u64, err: VerifyError },
}

/// Decide whether `header_bytes` + `justification` justify advancing
/// past `checkpoint`.
///
/// Everything the courier said is treated as a claim. The height comes
/// from the header we hash ourselves; the authority set and set id come
/// from our own checkpoint, never from the response.
pub fn evaluate_candidate<V: HybridVerify>(
    checkpoint: &Checkpoint,
    verifier: &V,
    header_bytes: &[u8],
    justification: &[u8],
) -> Result<Adoption, Refusal> {
    let parsed = parse_header(header_bytes).map_err(Refusal::MalformedHeader)?;

    // Computed from the bytes in hand — NOT taken from the courier.
    let block_hash = blake2_256(header_bytes);

    // Rule 2. The verified head is the checkpoint height: nothing above
    // it has been verified yet, which is precisely what this call is
    // about to establish.
    match judge_anchor(checkpoint.height, checkpoint.height, parsed.number) {
        AnchorVerdict::BelowCheckpoint =>
            return Err(Refusal::Rollback { held: checkpoint.height, offered: parsed.number }),
        // "Above the verified head" is the normal case here — it is why
        // we are verifying. Equal height means no progress.
        AnchorVerdict::AboveVerifiedHead | AnchorVerdict::Adopt =>
            if parsed.number <= checkpoint.height {
                return Err(Refusal::NotNewer {
                    held: checkpoint.height,
                    offered: parsed.number,
                });
            },
    }

    verify_justification(
        verifier,
        justification,
        checkpoint.set_id,
        &checkpoint.authorities,
        &block_hash,
        u32::try_from(parsed.number)
            .map_err(|_| Refusal::MalformedHeader("block number exceeds u32".into()))?,
    )
    .map_err(|err| Refusal::Unverified { set_id: checkpoint.set_id, err })?;

    Ok(Adoption { height: parsed.number, block_hash, state_root: parsed.state_root })
}

impl Adoption {
    /// Roll the checkpoint forward. The authority set carries over: a
    /// set change is a separate event, signalled by verification
    /// failing under the current set.
    pub fn advance(&self, previous: &Checkpoint) -> Checkpoint {
        Checkpoint::sealed(
            previous.genesis_hash,
            self.height,
            self.block_hash,
            self.state_root,
            previous.set_id,
            previous.authorities.clone(),
        )
    }

    /// The anchor records may now be proven against. Constructing this
    /// requires [`FinalityVerified`], which this function is entitled
    /// to mint because `evaluate_candidate` produced the `Adoption`
    /// only after `verify_justification` returned `Ok`.
    pub fn anchor(&self) -> VerifiedAnchor {
        VerifiedAnchor::from_verified_header(
            self.state_root,
            self.height,
            FinalityVerified::assert(),
        )
    }
}

struct ParsedHeader {
    number: u64,
    state_root: H256,
}

/// `parent_hash(32) ‖ compact(number) ‖ state_root(32) ‖
/// extrinsics_root(32) ‖ digest`. Only the first three fields are read;
/// the digest is not needed to anchor a proof.
fn parse_header(bytes: &[u8]) -> Result<ParsedHeader, String> {
    if bytes.len() < 32 {
        return Err("shorter than parent_hash".into());
    }
    let mut rest = &bytes[32..];
    let number = u64::from(
        Compact::<u32>::decode(&mut rest).map_err(|e| format!("block number: {e}"))?.0,
    );
    if rest.len() < 32 {
        return Err("truncated before state_root".into());
    }
    let mut state_root = [0u8; 32];
    state_root.copy_from_slice(&rest[..32]);
    Ok(ParsedHeader { number, state_root })
}

fn blake2_256(bytes: &[u8]) -> H256 {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Blake2b::<U32>::digest(bytes));
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::checkpoint::Authority;
    use crate::hybrid::HybridVerifier;
    use crate::wire::from_hex;

    /// The block-1 justification fixture, plus its header, captured
    /// from `gemini-node --dev`.
    fn fixture() -> (Checkpoint, Vec<u8>, Vec<u8>) {
        let raw = include_str!("../vectors/justification_dev_block1.txt");
        let mut l = raw.lines();
        let bh = from_hex(l.next().unwrap().trim()).unwrap();
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&bh);
        let _number: u32 = l.next().unwrap().trim().parse().unwrap();
        let set_id: u64 = l.next().unwrap().trim().parse().unwrap();
        let justification = from_hex(l.next().unwrap().trim()).unwrap();
        let authorities: Vec<Authority> = l
            .filter(|x| !x.trim().is_empty())
            .map(|x| {
                let mut it = x.split_whitespace();
                Authority {
                    public: from_hex(it.next().unwrap()).unwrap(),
                    weight: it.next().unwrap().parse().unwrap(),
                }
            })
            .collect();
        let header = from_hex(include_str!("../vectors/header_dev_block1.txt").trim()).unwrap();
        // Checkpoint sits at genesis, about to adopt block 1.
        let cp = Checkpoint::sealed([0; 32], 0, [0; 32], [0; 32], set_id, authorities);
        (cp, header, justification)
    }

    #[test]
    fn header_hashes_to_the_justified_block() {
        let (_, header, _) = fixture();
        let raw = include_str!("../vectors/justification_dev_block1.txt");
        let expected = from_hex(raw.lines().next().unwrap().trim()).unwrap();
        assert_eq!(blake2_256(&header).to_vec(), expected, "fixture header/hash mismatch");
    }

    #[test]
    fn adopts_a_genuine_head() {
        let (cp, header, just) = fixture();
        let a = evaluate_candidate(&cp, &HybridVerifier, &header, &just).unwrap();
        assert_eq!(a.height, 1);
        let next = a.advance(&cp);
        assert_eq!(next.height, 1);
        assert_eq!(next.state_root, a.state_root);
        assert_eq!(next.set_id, cp.set_id, "set carries over absent a set change");
        // The anchor is usable for record proofs only via this path.
        assert_eq!(a.anchor().state_root(), &a.state_root);
    }

    /// THE header test. Take a genuine justification, pair it with a
    /// header whose `state_root` has been altered. Signatures are
    /// untouched and still valid — but they attest to a different block
    /// hash, so the pairing is refused. Without the self-computed hash,
    /// this would hand the snorkel an attacker-chosen state root under
    /// a real quorum's signatures.
    #[test]
    fn fabricated_header_with_real_justification_is_refused() {
        let (cp, header, just) = fixture();
        let mut forged = header.clone();
        // Flip a byte inside state_root (after parent_hash + compact).
        let sr_off = 32 + 1;
        forged[sr_off] ^= 0x01;
        let r = evaluate_candidate(&cp, &HybridVerifier, &forged, &just);
        assert!(
            matches!(r, Err(Refusal::Unverified { .. })),
            "a fabricated header rode in on a real justification: {r:?}"
        );
    }

    #[test]
    fn rollback_is_refused() {
        let (mut cp, header, just) = fixture();
        cp = Checkpoint::sealed(cp.genesis_hash, 500, [7; 32], [8; 32], cp.set_id, cp.authorities);
        let r = evaluate_candidate(&cp, &HybridVerifier, &header, &just);
        assert!(matches!(r, Err(Refusal::Rollback { held: 500, offered: 1 })));
    }

    #[test]
    fn replaying_the_current_head_is_not_progress() {
        let (cp, header, just) = fixture();
        let a = evaluate_candidate(&cp, &HybridVerifier, &header, &just).unwrap();
        let advanced = a.advance(&cp);
        // Same head offered again.
        let r = evaluate_candidate(&advanced, &HybridVerifier, &header, &just);
        assert!(matches!(r, Err(Refusal::NotNewer { held: 1, offered: 1 })));
    }

    /// A set change (or a courier substituting a set) surfaces as
    /// unverified rather than being silently accepted.
    #[test]
    fn foreign_authority_set_refuses_adoption() {
        let (cp, header, just) = fixture();
        let wrong = Checkpoint::sealed(
            cp.genesis_hash,
            cp.height,
            cp.block_hash,
            cp.state_root,
            cp.set_id,
            vec![Authority { public: vec![0xaa; 64], weight: 1 }],
        );
        let r = evaluate_candidate(&wrong, &HybridVerifier, &header, &just);
        assert!(matches!(r, Err(Refusal::Unverified { .. })));
    }

    #[test]
    fn malformed_header_is_refused() {
        let (cp, _, just) = fixture();
        assert!(matches!(
            evaluate_candidate(&cp, &HybridVerifier, &[0u8; 10], &just),
            Err(Refusal::MalformedHeader(_))
        ));
    }
}
