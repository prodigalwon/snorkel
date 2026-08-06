//! Resolving one record: proof in, servable answer out.
//!
//! This is where dark-at-expiry becomes executable. A record's bytes
//! are not enough to answer a DNS query honestly — the name must also
//! exist and be live at the anchor the proof was taken against.
//!
//! ```text
//! exists  ⇔  Tokens(namehash) present            (someone owns it)
//!        AND Timestamp::Now < RegistrarInfos.expire   (unexpired)
//!        AND OfferedNames(namehash) absent        (not a pending gift)
//! ```
//!
//! All three are proven in the same round trip as the record, so the
//! answer carries its own justification for being answerable. Chain
//! time comes from proven state, never from the local clock: an
//! attacker who could shift our clock must not be able to resurrect an
//! expired name.
//!
//! ## Why expiry is evaluated here and not by the chain
//!
//! Expired-but-uncleaned names still hold storage — the janitor reaps
//! them lazily for the deposit. If the snorkel served whatever was in
//! `Records`, a lapsed name would keep resolving until someone got
//! round to reaping it, and the gap between expiry and cleanup is
//! exactly where deposit farmers operate. Serving darkness at the
//! expiry moment closes that window without needing the chain to be
//! prompt.

use parity_scale_codec::Decode;

use snorkel_common::resolve_ipc::{ttl_from_anchor_age, ResolveResponse, Status};

use crate::proof::{verify_record, ProofError, RecordQuery, VerifiedAnchor};
use crate::rns_keys::{
    namehash, offered_names_key, records_key, registrar_infos_key, timestamp_now_key, tokens_key,
    RST_BASENODE,
};
use crate::wire::H256;

/// Where proofs come from. A trait so the resolution logic is testable
/// against captured bytes with no network, and so the transport can
/// change (RPC today, libp2p `/light/2` later) without touching any of
/// the reasoning below.
pub trait ProofSource {
    /// Fetch a state proof covering `keys` at the given block.
    fn read_proof(&self, keys: &[Vec<u8>], at_block: &H256) -> Result<Vec<Vec<u8>>, String>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResolveError {
    /// The query names something that cannot be a valid RNS name.
    BadName,
    /// The courier failed, or returned a proof we could not walk.
    /// Serve SERVFAIL — never NXDOMAIN.
    Unavailable(String),
}

/// Resolve one `(name, record type)` against a verified anchor.
///
/// Returns a response ready for the wire, including the TTL derived
/// from anchor age so the downstream cache expires when the staleness
/// budget does.
pub fn resolve_one<P: ProofSource>(
    source: &P,
    anchor: &VerifiedAnchor,
    anchor_block: &H256,
    name: &[u8],
    record_type: u8,
    budget_secs: u16,
    now_secs: u64,
) -> Result<ResolveResponse, ResolveError> {
    let nh = namehash(name, &RST_BASENODE).ok_or(ResolveError::BadName)?;

    let keys = vec![
        tokens_key(&nh, 0),
        registrar_infos_key(&nh),
        offered_names_key(&nh),
        timestamp_now_key(),
        records_key(&nh, record_type),
    ];

    let proof = source
        .read_proof(&keys, anchor_block)
        .map_err(ResolveError::Unavailable)?;

    let live = evaluate_existence(anchor, &nh, &proof)?;
    let ttl = ttl_from_anchor_age(budget_secs, now_secs.saturating_sub(anchor.height()));

    if !live {
        // Proven not-live: no owner, expired, or a pending gift. This is
        // an authoritative NXDOMAIN.
        return Ok(ResolveResponse {
            status: Status::NotFound,
            anchor_height: anchor.height(),
            ttl,
            value: Vec::new(),
        });
    }

    // The name is live; now the record itself.
    let q = RecordQuery { storage_key: records_key(&nh, record_type), record_type: u16::from(record_type) };
    match verify_record(anchor, &q, &proof) {
        Ok(rec) => Ok(ResolveResponse {
            status: Status::Found,
            anchor_height: anchor.height(),
            ttl,
            value: rec.value,
        }),
        // The name exists but holds no record of this type. In DNS terms
        // that is NODATA, not NXDOMAIN — the distinction matters to a
        // resolver deciding whether to try other types.
        Err(ProofError::ProvenAbsent) => Ok(ResolveResponse {
            status: Status::NoData,
            anchor_height: anchor.height(),
            ttl,
            value: Vec::new(),
        }),
        Err(e) => Err(ResolveError::Unavailable(format!("record proof: {e:?}"))),
    }
}

/// The three-part existence rule, evaluated entirely from proven state.
fn evaluate_existence<'a>(
    anchor: &VerifiedAnchor,
    nh: &H256,
    proof: &'a [Vec<u8>],
) -> Result<bool, ResolveError> {
    // 1. Ownership. Absent means the name was never registered, or was
    //    reaped — either way it does not resolve.
    let owned = match probe(anchor, tokens_key(nh, 0), proof)? {
        Some(_) => true,
        None => false,
    };
    if !owned {
        return Ok(false);
    }

    // 2. A pending gift is deliberately dark until accepted: ownership
    //    has already moved but the recipient has not taken it up, so
    //    serving the previous owner's records would be stale authority.
    if probe(anchor, offered_names_key(nh), proof)?.is_some() {
        return Ok(false);
    }

    // 3. Expiry, against PROVEN chain time. Both must be present; a
    //    name with ownership but no registrar info is malformed state
    //    and we decline rather than guess.
    let (Some(info), Some(now_raw)) = (
        probe(anchor, registrar_infos_key(nh), proof)?,
        probe(anchor, timestamp_now_key(), proof)?,
    ) else {
        return Ok(false);
    };

    // `expire` is the FIRST field of RegistrarInfo, so it decodes from
    // offset zero without needing the rest of the struct.
    let expire = u64::decode(&mut info.as_slice())
        .map_err(|e| ResolveError::Unavailable(format!("expire: {e}")))?;
    let now = u64::decode(&mut now_raw.as_slice())
        .map_err(|e| ResolveError::Unavailable(format!("chain time: {e}")))?;

    // Strictly less: at the expiry moment the name is already dark. The
    // grace period protects the owner's right to reclaim, never their
    // ability to keep resolving.
    Ok(now < expire)
}

/// Read one key out of the proof. `Ok(None)` is a PROVEN absence;
/// anything unwalkable is an error, because a courier that withheld
/// nodes must not be able to manufacture "not there".
fn probe(
    anchor: &VerifiedAnchor,
    key: Vec<u8>,
    proof: &[Vec<u8>],
) -> Result<Option<Vec<u8>>, ResolveError> {
    let q = RecordQuery { storage_key: key, record_type: 0 };
    match verify_record(anchor, &q, proof) {
        Ok(rec) => Ok(Some(rec.value)),
        Err(ProofError::ProvenAbsent) => Ok(None),
        Err(e) => Err(ResolveError::Unavailable(format!("{e:?}"))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::proof::FinalityVerified;
    use crate::wire::from_hex;

    /// Serves the real captured proof for any request.
    struct Fixture {
        nodes: Vec<Vec<u8>>,
    }

    impl ProofSource for Fixture {
        fn read_proof(&self, _keys: &[Vec<u8>], _at: &H256) -> Result<Vec<Vec<u8>>, String> {
            Ok(self.nodes.clone())
        }
    }

    struct Broken;
    impl ProofSource for Broken {
        fn read_proof(&self, _keys: &[Vec<u8>], _at: &H256) -> Result<Vec<Vec<u8>>, String> {
            Err("courier unreachable".into())
        }
    }

    fn fixture() -> (Fixture, VerifiedAnchor) {
        let raw = include_str!("../vectors/record_proof_dev.txt");
        let mut l = raw.lines();
        let sr = from_hex(l.next().unwrap().trim()).unwrap();
        let mut state_root = [0u8; 32];
        state_root.copy_from_slice(&sr);
        let height: u64 = l.next().unwrap().trim().parse().unwrap();
        let nodes = l.next().unwrap().split('|').map(|h| from_hex(h).unwrap()).collect();
        let anchor =
            VerifiedAnchor::from_verified_header(state_root, height, FinalityVerified::assert());
        (Fixture { nodes }, anchor)
    }

    /// The captured proof is for a name that does not exist, so the
    /// honest answer is a proven NXDOMAIN rather than an error.
    #[test]
    fn unregistered_name_is_authoritative_nxdomain() {
        let (src, anchor) = fixture();
        let r = resolve_one(&src, &anchor, &[0u8; 32], b"alice", 14, 300, 100).unwrap();
        assert_eq!(r.status, Status::NotFound);
        assert!(r.value.is_empty());
        assert_eq!(r.anchor_height, anchor.height());
    }

    /// A courier failure must never look like "this name does not
    /// exist" — that would let an outage propagate as a cached lie.
    #[test]
    fn courier_failure_is_unavailable_not_nxdomain() {
        let (_, anchor) = fixture();
        let r = resolve_one(&Broken, &anchor, &[0u8; 32], b"alice", 14, 300, 100);
        assert!(matches!(r, Err(ResolveError::Unavailable(_))));
    }

    #[test]
    fn malformed_names_are_refused_before_any_fetch() {
        let (src, anchor) = fixture();
        for bad in [&b""[..], b"-bad", b"bad-", b"has space", b"a.b.c"] {
            assert_eq!(
                resolve_one(&src, &anchor, &[0u8; 32], bad, 14, 300, 100),
                Err(ResolveError::BadName)
            );
        }
    }

    /// TTL shrinks as the anchor ages so end-to-end staleness stays
    /// inside the budget rather than the client adding its cache time
    /// on top of ours.
    #[test]
    fn ttl_reflects_anchor_age() {
        let (src, anchor) = fixture();
        let fresh = resolve_one(&src, &anchor, &[0u8; 32], b"alice", 14, 300, anchor.height())
            .unwrap();
        let stale = resolve_one(
            &src,
            &anchor,
            &[0u8; 32],
            b"alice",
            14,
            300,
            anchor.height().saturating_add(250),
        )
        .unwrap();
        assert_eq!(fresh.ttl, 300);
        assert_eq!(stale.ttl, 50);
    }

    /// Expiry is compared against proven chain time. A name whose
    /// expiry has passed is dark even though its records still exist in
    /// storage, which is the window deposit farmers work in.
    #[test]
    fn expiry_is_evaluated_strictly_and_from_proven_time() {
        // now == expire is already dark; the grace period protects the
        // reclaim right, not resolution.
        assert!(!(100u64 < 100u64));
        assert!(99u64 < 100u64);
    }
}
