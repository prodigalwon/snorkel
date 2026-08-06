//! `snorkel-dns` ↔ `snorkel-sync` resolve protocol.
//!
//! Separate from [`crate::ipc`], which is a fire-and-forget dns→janitor
//! wake signal capped at 16 bytes. This is request/response between a
//! different pair, carrying variable-length payloads.
//!
//! ## Why the fill path goes through sync at all
//!
//! `snorkel-dns` is the process that eats unauthenticated UDP from
//! anyone who can reach the listener, so it deliberately carries no
//! chain dependencies: no trie code, no signature verification, no
//! SCALE. All of that lives in `snorkel-sync`, which already holds the
//! verified anchor. One unix-socket round trip on a cache miss buys
//! that separation, and on a loopback socket it costs microseconds
//! against a fetch measured in milliseconds.
//!
//! ## The three-way answer is load-bearing
//!
//! [`Status::NotFound`] means *proven absent* — the state proof showed
//! the key genuinely is not there, which a resolver may serve as an
//! authoritative NXDOMAIN. [`Status::Unavailable`] means the snorkel
//! cannot currently answer: no verified anchor, catching up, or an
//! incomplete proof. That must become SERVFAIL, never NXDOMAIN.
//!
//! Collapsing those two would let a snorkel that is merely behind
//! assert that a name does not exist. Resolvers cache negative answers
//! and treat them as authoritative, so the lie would propagate and
//! outlive the outage that caused it.

/// Protocol version. Bumped on any wire change; both sides refuse a
/// mismatch rather than guessing.
pub const RESOLVE_PROTOCOL_VERSION: u8 = 1;

/// Default socket for the resolve channel.
pub const DEFAULT_RESOLVE_SOCKET: &str = "/run/snorkel/resolve.sock";

/// A DNS name cannot exceed 255 bytes on the wire (RFC 1035).
pub const MAX_NAME_BYTES: usize = 255;

/// Upper bound on a record payload, matching the chain's per-record cap.
pub const MAX_VALUE_BYTES: usize = 4096;

/// Largest request: version + opcode + qtype + len + name.
pub const MAX_REQUEST_BYTES: usize = 1 + 1 + 2 + 1 + MAX_NAME_BYTES;

/// Largest response: version + status + height + ttl + len + value.
pub const MAX_RESPONSE_BYTES: usize = 1 + 1 + 8 + 2 + 2 + MAX_VALUE_BYTES;

const OP_RESOLVE: u8 = 1;

/// Resolve exactly one `(name, record type)`.
///
/// One type per request on purpose: a TXT lookup must not cause the
/// snorkel to fetch, cache, or return a name's other records. A
/// resolver has no business learning an address or chat key as a side
/// effect of a TXT query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveRequest {
    /// The record type, as the chain's `RecordType` variant index.
    pub qtype: u16,
    /// The name being resolved, zone suffix already stripped.
    pub name: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    /// Verified record follows.
    Found = 1,
    /// Proven absent against a verified anchor — safe to serve as
    /// authoritative NXDOMAIN.
    NotFound = 2,
    /// Cannot answer right now. MUST become SERVFAIL, never NXDOMAIN.
    Unavailable = 3,
}

impl Status {
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Found),
            2 => Some(Self::NotFound),
            3 => Some(Self::Unavailable),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveResponse {
    pub status: Status,
    /// Height of the anchor this answer was proven against. Zero when
    /// not applicable.
    pub anchor_height: u64,
    /// Seconds the answer may be cached downstream. Computed by sync as
    /// `staleness_budget - anchor_age`, so the client's copy expires
    /// exactly when the end-to-end staleness bound is reached rather
    /// than adding its cache time on top of ours.
    pub ttl: u16,
    /// Raw RDATA. Empty unless `status == Found`.
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveCodecError {
    Truncated,
    UnknownVersion,
    UnknownOpcode,
    UnknownStatus,
    TooLarge,
}

pub fn encode_request(req: &ResolveRequest, out: &mut [u8]) -> Result<usize, ResolveCodecError> {
    if req.name.len() > MAX_NAME_BYTES {
        return Err(ResolveCodecError::TooLarge);
    }
    let need = req.name.len().saturating_add(5);
    if out.len() < need {
        return Err(ResolveCodecError::Truncated);
    }
    let qt = req.qtype.to_le_bytes();
    // Length checked above; assign through get_mut to satisfy the
    // workspace's no-indexing lint.
    for (slot, byte) in out.iter_mut().zip(
        [RESOLVE_PROTOCOL_VERSION, OP_RESOLVE, qt[0], qt[1]]
            .iter()
            .copied()
            .chain(core::iter::once(req.name.len() as u8))
            .chain(req.name.iter().copied()),
    ) {
        *slot = byte;
    }
    Ok(need)
}

pub fn decode_request(bytes: &[u8]) -> Result<ResolveRequest, ResolveCodecError> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(ResolveCodecError::TooLarge);
    }
    let version = *bytes.first().ok_or(ResolveCodecError::Truncated)?;
    if version != RESOLVE_PROTOCOL_VERSION {
        return Err(ResolveCodecError::UnknownVersion);
    }
    if *bytes.get(1).ok_or(ResolveCodecError::Truncated)? != OP_RESOLVE {
        return Err(ResolveCodecError::UnknownOpcode);
    }
    let lo = *bytes.get(2).ok_or(ResolveCodecError::Truncated)?;
    let hi = *bytes.get(3).ok_or(ResolveCodecError::Truncated)?;
    let qtype = u16::from_le_bytes([lo, hi]);
    let len = usize::from(*bytes.get(4).ok_or(ResolveCodecError::Truncated)?);
    let end = len.saturating_add(5);
    let name = bytes.get(5..end).ok_or(ResolveCodecError::Truncated)?.to_vec();
    if bytes.len() != end {
        return Err(ResolveCodecError::TooLarge);
    }
    Ok(ResolveRequest { qtype, name })
}

pub fn encode_response(
    resp: &ResolveResponse,
    out: &mut [u8],
) -> Result<usize, ResolveCodecError> {
    if resp.value.len() > MAX_VALUE_BYTES {
        return Err(ResolveCodecError::TooLarge);
    }
    let need = resp.value.len().saturating_add(14);
    if out.len() < need {
        return Err(ResolveCodecError::Truncated);
    }
    let h = resp.anchor_height.to_le_bytes();
    let t = resp.ttl.to_le_bytes();
    let vl = (resp.value.len() as u16).to_le_bytes();
    let header = [
        RESOLVE_PROTOCOL_VERSION,
        resp.status as u8,
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
        t[0], t[1],
        vl[0], vl[1],
    ];
    for (slot, byte) in out
        .iter_mut()
        .zip(header.iter().copied().chain(resp.value.iter().copied()))
    {
        *slot = byte;
    }
    Ok(need)
}

pub fn decode_response(bytes: &[u8]) -> Result<ResolveResponse, ResolveCodecError> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ResolveCodecError::TooLarge);
    }
    let version = *bytes.first().ok_or(ResolveCodecError::Truncated)?;
    if version != RESOLVE_PROTOCOL_VERSION {
        return Err(ResolveCodecError::UnknownVersion);
    }
    let status = Status::from_byte(*bytes.get(1).ok_or(ResolveCodecError::Truncated)?)
        .ok_or(ResolveCodecError::UnknownStatus)?;
    let mut h = [0u8; 8];
    for (i, slot) in h.iter_mut().enumerate() {
        *slot = *bytes.get(i.saturating_add(2)).ok_or(ResolveCodecError::Truncated)?;
    }
    let anchor_height = u64::from_le_bytes(h);
    let ttl = u16::from_le_bytes([
        *bytes.get(10).ok_or(ResolveCodecError::Truncated)?,
        *bytes.get(11).ok_or(ResolveCodecError::Truncated)?,
    ]);
    let vlen = usize::from(u16::from_le_bytes([
        *bytes.get(12).ok_or(ResolveCodecError::Truncated)?,
        *bytes.get(13).ok_or(ResolveCodecError::Truncated)?,
    ]));
    let vend = vlen.saturating_add(14);
    let value = bytes.get(14..vend).ok_or(ResolveCodecError::Truncated)?.to_vec();
    if bytes.len() != vend {
        return Err(ResolveCodecError::TooLarge);
    }
    Ok(ResolveResponse { status, anchor_height, ttl, value })
}

/// Downstream TTL from anchor age: the client's cached copy expires
/// exactly when the end-to-end staleness budget is spent.
///
/// Returning zero is meaningful — it says "do not cache", which is the
/// honest answer when the anchor has already consumed the budget. The
/// caller decides whether to serve at all.
pub fn ttl_from_anchor_age(budget_secs: u16, anchor_age_secs: u64) -> u16 {
    let age = u16::try_from(anchor_age_secs).unwrap_or(u16::MAX);
    budget_secs.saturating_sub(age)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        let req = ResolveRequest { qtype: 14, name: b"alice".to_vec() };
        let mut buf = [0u8; MAX_REQUEST_BYTES];
        let n = encode_request(&req, &mut buf).unwrap();
        assert_eq!(decode_request(&buf[..n]).unwrap(), req);
    }

    #[test]
    fn response_roundtrip_preserves_provenance() {
        let resp = ResolveResponse {
            status: Status::Found,
            anchor_height: 1024,
            ttl: 200,
            value: b"v=spf1 -all".to_vec(),
        };
        let mut buf = [0u8; MAX_RESPONSE_BYTES];
        let n = encode_response(&resp, &mut buf).unwrap();
        let got = decode_response(&buf[..n]).unwrap();
        assert_eq!(got, resp);
        assert_eq!(got.anchor_height, 1024, "answers carry the anchor they were proven at");
    }

    /// The distinction a resolver acts on differently.
    #[test]
    fn absent_and_unavailable_are_distinct_on_the_wire() {
        let mut a = [0u8; MAX_RESPONSE_BYTES];
        let mut b = [0u8; MAX_RESPONSE_BYTES];
        let na = encode_response(
            &ResolveResponse { status: Status::NotFound, anchor_height: 5, ttl: 60, value: vec![] },
            &mut a,
        )
        .unwrap();
        let nb = encode_response(
            &ResolveResponse { status: Status::Unavailable, anchor_height: 0, ttl: 0, value: vec![] },
            &mut b,
        )
        .unwrap();
        assert_ne!(a[..na], b[..nb]);
        assert_eq!(decode_response(&a[..na]).unwrap().status, Status::NotFound);
        assert_eq!(decode_response(&b[..nb]).unwrap().status, Status::Unavailable);
    }

    #[test]
    fn ttl_shrinks_with_anchor_age_and_floors_at_zero() {
        assert_eq!(ttl_from_anchor_age(300, 0), 300);
        assert_eq!(ttl_from_anchor_age(300, 100), 200);
        assert_eq!(ttl_from_anchor_age(300, 300), 0);
        assert_eq!(ttl_from_anchor_age(300, 100_000), 0, "no underflow on a stale anchor");
    }

    #[test]
    fn oversized_inputs_are_refused() {
        let req = ResolveRequest { qtype: 1, name: vec![0u8; MAX_NAME_BYTES + 1] };
        let mut buf = [0u8; MAX_REQUEST_BYTES];
        assert_eq!(encode_request(&req, &mut buf), Err(ResolveCodecError::TooLarge));
        assert_eq!(decode_request(&[0u8; MAX_REQUEST_BYTES + 1]), Err(ResolveCodecError::TooLarge));
    }

    #[test]
    fn truncated_and_wrong_version_are_rejected() {
        assert_eq!(decode_request(&[]), Err(ResolveCodecError::Truncated));
        assert_eq!(decode_request(&[99, 1, 0, 0, 0]), Err(ResolveCodecError::UnknownVersion));
        assert_eq!(decode_response(&[1, 1, 0]), Err(ResolveCodecError::Truncated));
        assert_eq!(decode_response(&[1, 99]), Err(ResolveCodecError::UnknownStatus));
    }

    /// A length field claiming more than was sent must not over-read.
    #[test]
    fn lying_length_field_cannot_over_read() {
        let mut buf = vec![RESOLVE_PROTOCOL_VERSION, OP_RESOLVE, 1, 0, 200];
        buf.extend_from_slice(b"short");
        assert_eq!(decode_request(&buf), Err(ResolveCodecError::Truncated));
    }
}
