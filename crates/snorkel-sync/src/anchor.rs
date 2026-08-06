//! History-anchor verification: establishing trust without trusting
//! validators.
//!
//! The chain folds sealed headers into a running Keccak-512 chain
//! (`pallet-rostro-history-anchor`):
//!
//! ```text
//! head_0   = keccak_512(DOMAIN_TAG)
//! head_i+1 = keccak_512(head_i ‖ header_bytes_i)
//! ```
//!
//! Each seal is a pure transcription — the chain enforces at inclusion
//! time that `blake2_256(header_bytes) == parent_hash`, so the fold
//! commits to real headers while the primary hasher is known sound.
//!
//! ## Why this is the bootstrap keystone
//!
//! A justification proves who agreed *now*, and costs 172 KB at 32
//! validators or 3.5 MB at 700. Walking them backwards to establish
//! trust from an old checkpoint is unaffordable, and it only works
//! within the weak-subjectivity window anyway: past the unbonding
//! period the validators who signed have withdrawn their stake and can
//! collude to sign an alternative history at no cost.
//!
//! Folding is different in kind. Given ONE authentic head, verifying
//! the entire sealed history is hashing — no signatures, no validator
//! trust, no expiry. A long-range attacker who reconstructs an
//! alternative branch produces a chain that folds to a *different*
//! head, and defeating that requires a Keccak-512 collision rather
//! than cooperative ex-validators. So the trust input shrinks from "a
//! checkpoint fresher than the unbonding period" to "64 bytes anyone
//! can cross-check", and it never goes stale.
//!
//! ## What this does NOT do
//!
//! A fold authenticates a *path*, never an *endpoint*. Fold from a
//! trusted head with attacker-supplied headers and you get a head —
//! just not a meaningful one. [`verify_chain`] therefore demands the
//! expected terminal head as an argument: the caller must have
//! obtained it independently. There is deliberately no function that
//! folds forward and returns whatever it lands on.
//!
//! Nor does it establish what is true *now*. It authenticates sealed
//! history; the current head still needs a justification.

use sha3::{Digest, Keccak512};

/// Domain-separation tag (`pallet-rostro-history-anchor::DOMAIN_TAG`).
/// Duplicated as a byte literal on purpose: a divergence must fail a
/// test here rather than silently track a changed value.
pub const DOMAIN_TAG: &[u8] = b"rostro-history-anchor-v0";

/// A 64-byte anchor head.
pub type H512 = [u8; 64];

/// `head_0` — the fold's starting value, before any seal.
pub fn genesis_head() -> H512 {
    let mut out = [0u8; 64];
    out.copy_from_slice(&Keccak512::digest(DOMAIN_TAG));
    out
}

/// One fold step: `keccak_512(head ‖ header_bytes)`.
pub fn fold(head: &H512, header_bytes: &[u8]) -> H512 {
    let mut hasher = Keccak512::new();
    hasher.update(head);
    hasher.update(header_bytes);
    let mut out = [0u8; 64];
    out.copy_from_slice(&hasher.finalize());
    out
}

#[derive(Debug, PartialEq, Eq)]
pub enum AnchorError {
    /// The supplied headers do not fold to the expected head. Either
    /// the courier substituted history, or the head is not the one
    /// this chain produced.
    HeadMismatch { expected: H512, computed: H512 },
    /// No headers supplied, so nothing was verified. Refused
    /// explicitly rather than trivially "succeeding".
    Empty,
    /// A sealed header could not be parsed.
    MalformedHeader(String),
}

/// The result of a verified fold: the state root of the last sealed
/// header, usable as a proof anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchoredState {
    pub height: u64,
    pub state_root: [u8; 32],
    pub head: H512,
}

/// Verify that `headers`, folded in order from `from`, reach
/// `expected_head`; return the final sealed header's anchor.
///
/// `expected_head` is REQUIRED and must come from outside this
/// function's inputs — a release-baked value, a published feed, or
/// several independent sources agreeing. Supplying a head derived from
/// the same courier that supplied the headers verifies nothing.
pub fn verify_chain(
    from: &H512,
    headers: &[Vec<u8>],
    expected_head: &H512,
) -> Result<AnchoredState, AnchorError> {
    if headers.is_empty() {
        return Err(AnchorError::Empty);
    }

    let mut head = *from;
    for h in headers {
        head = fold(&head, h);
    }

    if &head != expected_head {
        return Err(AnchorError::HeadMismatch { expected: *expected_head, computed: head });
    }

    // Only now, with the fold confirmed, is it safe to read the last
    // header's contents.
    let last = headers.last().ok_or(AnchorError::Empty)?;
    let parsed = parse_sealed_header(last).map_err(AnchorError::MalformedHeader)?;
    Ok(AnchoredState { height: parsed.0, state_root: parsed.1, head })
}

/// `parent_hash(32) ‖ compact(number) ‖ state_root(32) ‖ …`
fn parse_sealed_header(bytes: &[u8]) -> Result<(u64, [u8; 32]), String> {
    if bytes.len() < 33 {
        return Err("shorter than parent_hash + number".into());
    }
    // SCALE compact, first two bits select the width.
    let b0 = bytes.get(32).copied().ok_or("truncated")?;
    let (number, next) = match b0 & 0b11 {
        0 => (u64::from(b0 >> 2), 33),
        1 => {
            let lo = u64::from(b0);
            let hi = u64::from(*bytes.get(33).ok_or("truncated u16 compact")?);
            ((lo | (hi << 8)) >> 2, 34)
        }
        2 => {
            let mut v: u64 = 0;
            for (i, off) in (32..36).enumerate() {
                v |= u64::from(*bytes.get(off).ok_or("truncated u32 compact")?) << (8 * i);
            }
            (v >> 2, 36)
        }
        _ => return Err("big-integer compact block number unsupported".into()),
    };
    let sr = bytes.get(next..next + 32).ok_or("truncated before state_root")?;
    let mut state_root = [0u8; 32];
    state_root.copy_from_slice(sr);
    Ok((number, state_root))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Real anchor data captured from `gemini-node --dev`: the sealed
    /// headers and the `AnchorHead` the chain itself computed. If our
    /// fold disagrees with the runtime's, this fails.
    fn fixture() -> (Vec<Vec<u8>>, H512) {
        let raw = include_str!("../vectors/anchor_dev.txt");
        let mut lines = raw.lines();
        let head_hex = lines.next().unwrap().trim();
        let mut head = [0u8; 64];
        head.copy_from_slice(&crate::wire::from_hex(head_hex).unwrap());
        let headers: Vec<Vec<u8>> = lines
            .filter(|l| !l.trim().is_empty())
            .map(|l| crate::wire::from_hex(l.trim()).unwrap())
            .collect();
        (headers, head)
    }

    /// The keystone: our independent fold reproduces the head the
    /// runtime computed, starting from the domain tag alone.
    #[test]
    fn reproduces_the_chains_own_anchor_head() {
        let (headers, expected) = fixture();
        let got = verify_chain(&genesis_head(), &headers, &expected).unwrap();
        assert_eq!(got.head, expected);
        assert_ne!(got.state_root, [0u8; 32], "anchored state root must be real");
    }

    /// Substituting any sealed header breaks the fold — this is the
    /// long-range defence in one assertion.
    #[test]
    fn substituted_history_is_rejected() {
        let (headers, expected) = fixture();
        for i in 0..headers.len() {
            let mut forged = headers.clone();
            forged[i][0] ^= 0x01;
            assert!(
                matches!(
                    verify_chain(&genesis_head(), &forged, &expected),
                    Err(AnchorError::HeadMismatch { .. })
                ),
                "tampering with sealed header {i} was not detected"
            );
        }
    }

    /// Order is part of the commitment.
    #[test]
    fn reordered_history_is_rejected() {
        let (mut headers, expected) = fixture();
        if headers.len() < 2 {
            return;
        }
        headers.swap(0, 1);
        assert!(matches!(
            verify_chain(&genesis_head(), &headers, &expected),
            Err(AnchorError::HeadMismatch { .. })
        ));
    }

    /// Dropping or appending history is rejected — a courier cannot
    /// truncate the chain to hide a period, nor extend it.
    #[test]
    fn truncated_or_extended_history_is_rejected() {
        let (headers, expected) = fixture();
        if headers.len() >= 2 {
            let short = &headers[..headers.len() - 1];
            assert!(verify_chain(&genesis_head(), short, &expected).is_err());
        }
        let mut long = headers.clone();
        long.push(vec![0u8; 64]);
        assert!(verify_chain(&genesis_head(), &long, &expected).is_err());
    }

    #[test]
    fn empty_chain_is_refused_not_trivially_accepted() {
        assert_eq!(
            verify_chain(&genesis_head(), &[], &genesis_head()),
            Err(AnchorError::Empty)
        );
    }

    #[test]
    fn genesis_head_matches_the_pallet_constant() {
        // keccak_512(b"rostro-history-anchor-v0") — recomputed here so
        // a changed DOMAIN_TAG fails loudly.
        let h = genesis_head();
        assert_eq!(h.len(), 64);
        assert_eq!(h, fold_free_genesis());
    }

    fn fold_free_genesis() -> H512 {
        let mut out = [0u8; 64];
        out.copy_from_slice(&Keccak512::digest(b"rostro-history-anchor-v0"));
        out
    }
}
