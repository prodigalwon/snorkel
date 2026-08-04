//! GRANDPA justification verification (SYNC-SPEC.md D1).
//!
//! Grounded against the Rostro fork 2026-08-03. The finality scheme is
//! `rostro_hybrid` = **ed25519 + SLH-DSA-SHA2-128s, both-must-verify**
//! (memory's "ML-DSA" was wrong; corrected here). A precommit vote is
//! signed over:
//!
//! ```text
//! domain  = b"rostro/finality-vote/hybrid/v1"   (FINALITY_VOTE_DOMAIN)
//! message = (Message::Precommit(precommit), round, set_id).encode()
//! ```
//!
//! where `Message` is finality-grandpa's enum (Prevote=0, Precommit=1,
//! PrimaryPropose=2) so the payload begins with the byte `0x01`, and
//! `precommit = { target_hash: H256, target_number: u32 }`.
//!
//! A justification finalizes its commit target iff precommits from a
//! set of distinct authorities whose summed weight is **> 2/3 of total
//! weight** each verify over that payload. Byte layout of the wire
//! justification is mirrored locally (spec discipline: no `sp-*`
//! graph), decoding only the prefix we need — `round` + `commit` —
//! and ignoring the trailing `votes_ancestries` header list.
//!
//! ## Conservative target rule
//!
//! We require every counted precommit to target the commit target hash
//! DIRECTLY, rather than validating the ancestry proof that lets a
//! precommit target a descendant. Honest voters don't vote past
//! set-change blocks, so real justifications satisfy this; the rule can
//! only reject unusual-but-valid justifications, never accept a bad
//! one — the safe direction. Revisit if a legitimate justification is
//! ever seen to fail it.
//!
//! ## Crypto: independent, in this repo
//!
//! [`HybridVerify`] is implemented by [`crate::hybrid::HybridVerifier`],
//! the snorkel's own verify-only implementation over crates.io
//! `ed25519-dalek` plus the vendored `slh-dsa` in `external/`. No
//! dependency on Rostro's `rostro-hybrid-sig`; the trait stays so the
//! quorum logic remains testable with a stub. Agreement with the chain
//! is pinned by two fixtures: a signature from the chain's signer
//! (`hybrid.rs`) and a real justification from a running node
//! (`live_fixture_tests` below).

use parity_scale_codec::{Compact, Decode, Input};

use crate::wire::H256;

/// The exact finality-vote domain the keystore signs under
/// (`rostro-hybrid-sig::FINALITY_VOTE_DOMAIN`). Duplicated as a byte
/// literal deliberately: a mismatch must fail loudly in tests, not
/// silently import a changed value.
pub const FINALITY_VOTE_DOMAIN: &[u8] = b"rostro/finality-vote/hybrid/v1";

pub const HYBRID_PK_BYTES: usize = 64;
pub const HYBRID_SIG_BYTES: usize = 7920;

/// The both-must-verify hybrid primitive, abstracted so the quorum
/// logic is testable without the (cross-repo) crypto crates. The
/// production impl forwards to `rostro-hybrid-sig`.
pub trait HybridVerify {
    /// `true` iff BOTH ed25519 and SLH-DSA verify `sig` over `msg`
    /// under `domain` for `public`. Any malformed input → `false`.
    fn verify(&self, public: &[u8], domain: &[u8], msg: &[u8], sig: &[u8]) -> bool;
}

/// A single authority in the active set: hybrid public key + weight.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Authority {
    pub public: Vec<u8>,
    pub weight: u64,
}

/// Locally-mirrored precommit (`finality_grandpa::Precommit`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Precommit {
    pub target_hash: H256,
    pub target_number: u32,
}

/// One signed precommit from the commit.
#[derive(Clone, Debug)]
pub struct SignedPrecommit {
    pub precommit: Precommit,
    pub signature: Vec<u8>,
    pub id: Vec<u8>,
}

/// The commit prefix we verify (`round` + commit target + precommits).
#[derive(Clone, Debug)]
pub struct Commit {
    pub round: u64,
    pub target_hash: H256,
    pub target_number: u32,
    pub precommits: Vec<SignedPrecommit>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    Decode(String),
    /// Summed weight of valid distinct-authority precommits did not
    /// exceed 2/3 of total set weight.
    InsufficientWeight { got: u128, needed: u128 },
    /// The justification's commit target is not the block we asked
    /// about.
    WrongTarget,
    /// Total set weight is zero — an empty/broken authority set.
    EmptySet,
}

fn read_h256<I: Input>(input: &mut I) -> Result<H256, VerifyError> {
    let mut h = [0u8; 32];
    input.read(&mut h).map_err(|e| VerifyError::Decode(format!("h256: {e}")))?;
    Ok(h)
}

fn read_bytes<I: Input>(input: &mut I, n: usize) -> Result<Vec<u8>, VerifyError> {
    let mut v = vec![0u8; n];
    input.read(&mut v).map_err(|e| VerifyError::Decode(format!("bytes[{n}]: {e}")))?;
    Ok(v)
}

/// Decode the justification PREFIX: `round: u64`, then
/// `commit { target_hash, target_number, precommits: Vec<SignedPrecommit> }`.
/// The trailing `votes_ancestries: Vec<Header>` is intentionally not
/// read (we don't need it under the conservative target rule, and
/// decoding it would require the chain's Header layout).
pub fn decode_commit(justification: &[u8]) -> Result<Commit, VerifyError> {
    let mut input = justification;
    let round =
        u64::decode(&mut input).map_err(|e| VerifyError::Decode(format!("round: {e}")))?;
    let target_hash = read_h256(&mut input)?;
    let target_number =
        u32::decode(&mut input).map_err(|e| VerifyError::Decode(format!("target_number: {e}")))?;
    let count = u32::from(
        Compact::<u32>::decode(&mut input)
            .map_err(|e| VerifyError::Decode(format!("precommit count: {e}")))?
            .0,
    );
    // Rule 1: the courier is an adversary. `count` is attacker-
    // controlled (Compact<u32>, up to ~4.3e9); it MUST NOT drive an
    // eager allocation. Cap the reserve at a sane authority-set bound —
    // the loop still reads exactly `count` items but fails fast on
    // input underrun, so a lie about the count only wastes the caller's
    // own bytes, never memory. Each real precommit is 8020+ wire bytes,
    // so a genuine `count` is bounded by the justification length
    // anyway.
    const PRECOMMIT_RESERVE_CAP: u32 = 100_000;
    let reserve = count.min(PRECOMMIT_RESERVE_CAP) as usize;
    let mut precommits = Vec::with_capacity(reserve);
    for _ in 0..count {
        let ph = read_h256(&mut input)?;
        let pn = u32::decode(&mut input)
            .map_err(|e| VerifyError::Decode(format!("precommit number: {e}")))?;
        let signature = read_bytes(&mut input, HYBRID_SIG_BYTES)?;
        let id = read_bytes(&mut input, HYBRID_PK_BYTES)?;
        precommits.push(SignedPrecommit {
            precommit: Precommit { target_hash: ph, target_number: pn },
            signature,
            id,
        });
    }
    Ok(Commit { round, target_hash, target_number, precommits })
}

/// The exact bytes a precommit is signed over:
/// `(Message::Precommit(precommit), round, set_id).encode()`.
/// `Message::Precommit` is enum variant index 1, so the buffer opens
/// with `0x01`.
pub fn vote_payload(precommit: &Precommit, round: u64, set_id: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 32 + 4 + 8 + 8);
    buf.push(0x01); // Message::Precommit discriminant
    buf.extend_from_slice(&precommit.target_hash);
    buf.extend_from_slice(&precommit.target_number.to_le_bytes());
    buf.extend_from_slice(&round.to_le_bytes());
    buf.extend_from_slice(&set_id.to_le_bytes());
    buf
}

/// Verify a justification finalizes `(expected_hash, expected_number)`
/// under `authorities`/`set_id`. Returns `Ok(())` on a >2/3 weight of
/// valid, distinct-authority precommits all targeting the commit
/// target, which must equal the expected block.
#[allow(clippy::too_many_arguments)]
pub fn verify_justification<V: HybridVerify>(
    verifier: &V,
    justification: &[u8],
    set_id: u64,
    authorities: &[Authority],
    expected_hash: &H256,
    expected_number: u32,
) -> Result<(), VerifyError> {
    let total_weight: u128 = authorities.iter().map(|a| u128::from(a.weight)).sum();
    if total_weight == 0 {
        return Err(VerifyError::EmptySet);
    }

    let commit = decode_commit(justification)?;
    if &commit.target_hash != expected_hash || commit.target_number != expected_number {
        return Err(VerifyError::WrongTarget);
    }

    // > 2/3 total weight, integer-exact: got * 3 > total * 2.
    let needed_strictly_above = total_weight.saturating_mul(2);

    let mut counted: u128 = 0;
    let mut seen: Vec<&[u8]> = Vec::new();
    for sp in &commit.precommits {
        // Conservative target rule: only precommits on the commit
        // target itself are counted.
        if sp.precommit.target_hash != commit.target_hash
            || sp.precommit.target_number != commit.target_number
        {
            continue;
        }
        // Find the authority; skip unknown ids (a courier can pad the
        // list with garbage, it just doesn't count).
        let Some(auth) = authorities.iter().find(|a| a.public.as_slice() == sp.id.as_slice())
        else {
            continue;
        };
        // One vote per authority: ignore duplicates.
        if seen.iter().any(|s| *s == sp.id.as_slice()) {
            continue;
        }
        let payload = vote_payload(&sp.precommit, commit.round, set_id);
        if !verifier.verify(&sp.id, FINALITY_VOTE_DOMAIN, &payload, &sp.signature) {
            continue;
        }
        seen.push(sp.id.as_slice());
        counted = counted.saturating_add(u128::from(auth.weight));
    }

    if counted.saturating_mul(3) > needed_strictly_above {
        Ok(())
    } else {
        Err(VerifyError::InsufficientWeight {
            got: counted,
            needed: needed_strictly_above / 3 + 1,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use parity_scale_codec::Encode;

    /// A test verifier that "accepts" a signature iff it equals the
    /// authority id repeated (a deterministic stand-in for a real
    /// hybrid sig). Lets the quorum logic be exercised exactly.
    struct MockVerify;
    impl HybridVerify for MockVerify {
        fn verify(&self, public: &[u8], domain: &[u8], _msg: &[u8], sig: &[u8]) -> bool {
            domain == FINALITY_VOTE_DOMAIN && !public.is_empty() && sig == good_sig(public)
        }
    }

    fn good_sig(id: &[u8]) -> Vec<u8> {
        let mut s = vec![0u8; HYBRID_SIG_BYTES];
        s[..id.len().min(HYBRID_SIG_BYTES)]
            .copy_from_slice(&id[..id.len().min(HYBRID_SIG_BYTES)]);
        s
    }

    fn auth(id_byte: u8, weight: u64) -> Authority {
        Authority { public: vec![id_byte; HYBRID_PK_BYTES], weight }
    }

    /// Build a wire justification with the given precommits, matching
    /// the fork's SCALE layout (round, target, Vec<SignedPrecommit>,
    /// then an empty votes_ancestries).
    fn build(
        round: u64,
        target: H256,
        number: u32,
        votes: &[(u8, bool)], // (authority id byte, sign-correctly?)
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        round.encode_to(&mut buf);
        buf.extend_from_slice(&target);
        number.encode_to(&mut buf);
        Compact(votes.len() as u32).encode_to(&mut buf);
        for (idb, ok) in votes {
            buf.extend_from_slice(&target);
            number.encode_to(&mut buf);
            let id = vec![*idb; HYBRID_PK_BYTES];
            let sig = if *ok { good_sig(&id) } else { vec![0xFFu8; HYBRID_SIG_BYTES] };
            buf.extend_from_slice(&sig);
            buf.extend_from_slice(&id);
        }
        // votes_ancestries: empty Vec<Header> — ignored by the decoder,
        // present for realism.
        Compact(0u32).encode_to(&mut buf);
        buf
    }

    fn set4() -> Vec<Authority> {
        vec![auth(1, 1), auth(2, 1), auth(3, 1), auth(4, 1)]
    }

    #[test]
    fn three_of_four_finalizes() {
        let target = [7u8; 32];
        let j = build(9, target, 100, &[(1, true), (2, true), (3, true)]);
        assert!(verify_justification(&MockVerify, &j, 5, &set4(), &target, 100).is_ok());
    }

    #[test]
    fn exactly_two_of_four_is_not_enough() {
        // 2/4 = 50% is not > 2/3.
        let target = [7u8; 32];
        let j = build(9, target, 100, &[(1, true), (2, true)]);
        assert!(matches!(
            verify_justification(&MockVerify, &j, 5, &set4(), &target, 100),
            Err(VerifyError::InsufficientWeight { .. })
        ));
    }

    #[test]
    fn bad_signatures_dont_count() {
        let target = [7u8; 32];
        let j = build(9, target, 100, &[(1, true), (2, false), (3, false)]);
        assert!(matches!(
            verify_justification(&MockVerify, &j, 5, &set4(), &target, 100),
            Err(VerifyError::InsufficientWeight { got, .. }) if got == 1
        ));
    }

    #[test]
    fn duplicate_authority_counts_once() {
        let target = [7u8; 32];
        // authority 1 votes three times; only one counts → 1/4, not enough.
        let j = build(9, target, 100, &[(1, true), (1, true), (1, true)]);
        assert!(matches!(
            verify_justification(&MockVerify, &j, 5, &set4(), &target, 100),
            Err(VerifyError::InsufficientWeight { got, .. }) if got == 1
        ));
    }

    #[test]
    fn unknown_authority_is_ignored() {
        let target = [7u8; 32];
        // id 9 is not in the set; ids 1,2 are. 2/4 → not enough,
        // proving the stranger didn't count.
        let j = build(9, target, 100, &[(1, true), (2, true), (9, true)]);
        assert!(matches!(
            verify_justification(&MockVerify, &j, 5, &set4(), &target, 100),
            Err(VerifyError::InsufficientWeight { got, .. }) if got == 2
        ));
    }

    #[test]
    fn wrong_target_rejected() {
        let target = [7u8; 32];
        let other = [8u8; 32];
        let j = build(9, target, 100, &[(1, true), (2, true), (3, true)]);
        assert_eq!(
            verify_justification(&MockVerify, &j, 5, &set4(), &other, 100),
            Err(VerifyError::WrongTarget)
        );
    }

    #[test]
    fn weighted_supermajority() {
        // One heavy authority (weight 10) + three light (weight 1):
        // total 13, need > 8.67. The heavy alone (10) suffices.
        let set = vec![auth(1, 10), auth(2, 1), auth(3, 1), auth(4, 1)];
        let target = [7u8; 32];
        let j = build(9, target, 100, &[(1, true)]);
        assert!(verify_justification(&MockVerify, &j, 5, &set, &target, 100).is_ok());
    }

    #[test]
    fn empty_set_rejected() {
        let target = [7u8; 32];
        let j = build(9, target, 100, &[]);
        assert_eq!(
            verify_justification(&MockVerify, &j, 5, &[], &target, 100),
            Err(VerifyError::EmptySet)
        );
    }

    #[test]
    fn absurd_precommit_count_does_not_preallocate() {
        // A hostile courier claims ~4.29e9 precommits in a tiny blob.
        // Before the fix this drove Vec::with_capacity(4.29e9) -> OOM
        // abort. Now decoding just fails fast on input underrun (the
        // promised precommits aren't there), returning a decode error
        // and touching no unbounded memory.
        let mut buf = Vec::new();
        9u64.encode_to(&mut buf); // round
        buf.extend_from_slice(&[7u8; 32]); // target_hash
        100u32.encode_to(&mut buf); // target_number
        Compact(u32::MAX).encode_to(&mut buf); // count = 4.29e9, a lie
        // ...and no precommit bytes follow.
        let err = decode_commit(&buf).unwrap_err();
        assert!(matches!(err, VerifyError::Decode(_)));
    }

    #[test]
    fn payload_opens_with_precommit_discriminant() {
        let p = Precommit { target_hash: [3u8; 32], target_number: 42 };
        let payload = vote_payload(&p, 9, 5);
        assert_eq!(payload[0], 0x01, "Message::Precommit variant index");
        assert_eq!(&payload[1..33], &[3u8; 32]);
        assert_eq!(&payload[33..37], &42u32.to_le_bytes());
        assert_eq!(&payload[37..45], &9u64.to_le_bytes());
        assert_eq!(&payload[45..53], &5u64.to_le_bytes());
    }
}

/// End-to-end verification against a REAL justification captured from a
/// running gemini node. This is the test the whole crate exists for:
/// it exercises the wire decode, the signed-payload construction, the
/// quorum arithmetic, and the hybrid crypto together, against bytes the
/// chain actually produced rather than bytes we invented.
///
/// Fixture: `vectors/justification_dev_block1.txt`, captured
/// 2026-08-04 via `sync_justification(1)` on `gemini-node --dev`.
/// Lines: block hash, block number, set_id, justification hex, then
/// one `pubkey_hex weight` per authority.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod live_fixture_tests {
    use super::*;
    use crate::hybrid::HybridVerifier;
    use crate::wire::from_hex;

    struct Fixture {
        block_hash: H256,
        number: u32,
        set_id: u64,
        justification: Vec<u8>,
        authorities: Vec<Authority>,
    }

    fn fixture() -> Fixture {
        let raw = include_str!("../vectors/justification_dev_block1.txt");
        let mut lines = raw.lines();
        let bh = from_hex(lines.next().unwrap().trim()).unwrap();
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&bh);
        let number: u32 = lines.next().unwrap().trim().parse().unwrap();
        let set_id: u64 = lines.next().unwrap().trim().parse().unwrap();
        let justification = from_hex(lines.next().unwrap().trim()).unwrap();
        let authorities = lines
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let mut it = l.split_whitespace();
                let public = from_hex(it.next().unwrap()).unwrap();
                let weight: u64 = it.next().unwrap().parse().unwrap();
                Authority { public, weight }
            })
            .collect();
        Fixture { block_hash, number, set_id, justification, authorities }
    }

    #[test]
    fn verifies_a_real_chain_justification() {
        let f = fixture();
        let r = verify_justification(
            &HybridVerifier,
            &f.justification,
            f.set_id,
            &f.authorities,
            &f.block_hash,
            f.number,
        );
        assert_eq!(
            r,
            Ok(()),
            "failed to verify a genuine justification from a running node"
        );
    }

    /// The set_id is inside the signed payload, so a wrong one must
    /// make every signature fail — proving the payload really is
    /// scoped to the authority set.
    #[test]
    fn wrong_set_id_fails() {
        let f = fixture();
        let r = verify_justification(
            &HybridVerifier,
            &f.justification,
            f.set_id + 1,
            &f.authorities,
            &f.block_hash,
            f.number,
        );
        assert!(matches!(r, Err(VerifyError::InsufficientWeight { .. })));
    }

    /// A courier substituting a different authority set must not be
    /// able to make the justification verify.
    #[test]
    fn foreign_authority_set_fails() {
        let f = fixture();
        let fake = vec![Authority { public: vec![0xaa; 64], weight: 1 }];
        let r = verify_justification(
            &HybridVerifier,
            &f.justification,
            f.set_id,
            &fake,
            &f.block_hash,
            f.number,
        );
        assert!(matches!(r, Err(VerifyError::InsufficientWeight { .. })));
    }

    /// Tampering with any signature byte must break the quorum.
    #[test]
    fn tampered_signature_fails() {
        let f = fixture();
        let mut j = f.justification.clone();
        let n = j.len();
        j[n - 100] ^= 0x01;
        let r = verify_justification(
            &HybridVerifier,
            &j,
            f.set_id,
            &f.authorities,
            &f.block_hash,
            f.number,
        );
        assert!(r.is_err());
    }
}
