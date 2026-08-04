//! Client rules 2 and 3 (SYNC-SPEC.md §7) as pure functions.
//!
//! Rule 2 — height monotonicity + no-future: never adopt an anchor
//! below the held checkpoint, never adopt one above the
//! justification-verified head. Monotonicity kills rollback; no-future
//! kills "future" anchors whose quorum an attacker cannot have forged.
//!
//! Rule 3 — recency bound k: serve authoritatively only while
//! `verified_head - anchor <= k`; past k, stop and alarm, because valid
//! proofs against an old anchor are exactly how revoked records outlive
//! themselves.

/// Recency bound in blocks (testnet-tunable; frozen relation:
/// `max_TTL <= k x block_time`).
pub const RECENCY_BOUND_K: u64 = 60;

/// Heartbeat cadence: k/4.
pub const HEARTBEAT_BLOCKS: u64 = RECENCY_BOUND_K / 4;

#[derive(Debug, PartialEq, Eq)]
pub enum AnchorVerdict {
    /// Adopt: above the held checkpoint, at or below the verified head.
    Adopt,
    /// Below the held checkpoint height — rollback attempt or stale
    /// courier. Never adopted.
    BelowCheckpoint,
    /// Above the justification-verified head — unverifiable future.
    /// Never adopted.
    AboveVerifiedHead,
}

/// Rule 2. `held` = current checkpoint height, `verified_head` = the
/// height our own justification-following has verified up to.
pub fn judge_anchor(held: u64, verified_head: u64, candidate: u64) -> AnchorVerdict {
    if candidate < held {
        AnchorVerdict::BelowCheckpoint
    } else if candidate > verified_head {
        AnchorVerdict::AboveVerifiedHead
    } else {
        AnchorVerdict::Adopt
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ServeState {
    /// Within the recency bound: serve authoritatively.
    Fresh,
    /// Past the bound: stop serving authoritatively and alarm.
    StaleAlarm,
}

/// Rule 3. Saturating: a verified head below the anchor (impossible
/// under rule 2, but belt-and-braces) counts as fresh.
pub fn serve_state(verified_head: u64, anchor: u64) -> ServeState {
    if verified_head.saturating_sub(anchor) <= RECENCY_BOUND_K {
        ServeState::Fresh
    } else {
        ServeState::StaleAlarm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonicity_rejects_rollback() {
        assert_eq!(judge_anchor(100, 200, 99), AnchorVerdict::BelowCheckpoint);
        assert_eq!(judge_anchor(100, 200, 100), AnchorVerdict::Adopt);
    }

    #[test]
    fn no_future_rejects_unverified() {
        assert_eq!(judge_anchor(100, 200, 201), AnchorVerdict::AboveVerifiedHead);
        assert_eq!(judge_anchor(100, 200, 200), AnchorVerdict::Adopt);
    }

    #[test]
    fn recency_cliff_is_exact() {
        assert_eq!(serve_state(1000, 1000 - RECENCY_BOUND_K), ServeState::Fresh);
        assert_eq!(
            serve_state(1000, 1000 - RECENCY_BOUND_K - 1),
            ServeState::StaleAlarm
        );
    }

    #[test]
    fn heartbeat_precedes_cliff() {
        // Several missed heartbeats fit inside the bound, so the alarm
        // never fires on the first hiccup.
        assert!(HEARTBEAT_BLOCKS * 3 < RECENCY_BOUND_K);
    }
}
