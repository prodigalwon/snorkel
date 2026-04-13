use std::collections::HashMap;
use std::net::IpAddr;

const MAX_TRACKED_SUBNETS: usize = 4096;
const MAX_TRACKED_LABELS: usize = 4096;

const SRC_MAX_TOKENS: u32 = 10;
const SRC_MICROS_PER_TOKEN: u64 = 100_000;

const ZONE_MAX_TOKENS: u32 = 50;
const ZONE_MICROS_PER_TOKEN: u64 = 20_000;

pub fn subnet_key(addr: IpAddr) -> [u8; 4] {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            [o[0], o[1], o[2], 4]
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            [o[0], o[1], o[2], 6]
        }
    }
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: u32,
    last_refill_micros: u64,
}

fn refill_and_consume(
    bucket: &mut Bucket,
    now_micros: u64,
    max_tokens: u32,
    micros_per_token: u64,
) -> bool {
    let elapsed = now_micros.saturating_sub(bucket.last_refill_micros);
    let refill = elapsed.checked_div(micros_per_token).unwrap_or(0);
    if refill > 0 {
        let refill_u32 = u32::try_from(refill).unwrap_or(u32::MAX);
        bucket.tokens = bucket.tokens.saturating_add(refill_u32).min(max_tokens);
        let consumed = refill.saturating_mul(micros_per_token);
        bucket.last_refill_micros = bucket.last_refill_micros.saturating_add(consumed);
    }

    if bucket.tokens > 0 {
        bucket.tokens = bucket.tokens.saturating_sub(1);
        true
    } else {
        false
    }
}

pub struct SourceRateLimiter {
    buckets: HashMap<[u8; 4], Bucket>,
}

impl SourceRateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: HashMap::with_capacity(MAX_TRACKED_SUBNETS),
        }
    }

    pub fn check_and_consume(&mut self, subnet: [u8; 4], now_micros: u64) -> bool {
        let known = self.buckets.contains_key(&subnet);
        if !known && self.buckets.len() >= MAX_TRACKED_SUBNETS {
            return false;
        }

        let bucket = self.buckets.entry(subnet).or_insert(Bucket {
            tokens: SRC_MAX_TOKENS,
            last_refill_micros: now_micros,
        });

        refill_and_consume(bucket, now_micros, SRC_MAX_TOKENS, SRC_MICROS_PER_TOKEN)
    }
}

impl Default for SourceRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ZoneRateLimiter {
    buckets: HashMap<Vec<u8>, Bucket>,
}

impl ZoneRateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: HashMap::with_capacity(MAX_TRACKED_LABELS),
        }
    }

    pub fn check_and_consume(&mut self, label: &[u8], now_micros: u64) -> bool {
        if let Some(bucket) = self.buckets.get_mut(label) {
            return refill_and_consume(
                bucket,
                now_micros,
                ZONE_MAX_TOKENS,
                ZONE_MICROS_PER_TOKEN,
            );
        }

        if self.buckets.len() >= MAX_TRACKED_LABELS {
            return false;
        }

        let mut bucket = Bucket {
            tokens: ZONE_MAX_TOKENS,
            last_refill_micros: now_micros,
        };
        let allowed = refill_and_consume(
            &mut bucket,
            now_micros,
            ZONE_MAX_TOKENS,
            ZONE_MICROS_PER_TOKEN,
        );
        self.buckets.insert(label.to_vec(), bucket);
        allowed
    }
}

impl Default for ZoneRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn subnet_key_collapses_last_octet() {
        let k1 = subnet_key(ip(10, 0, 0, 1));
        let k2 = subnet_key(ip(10, 0, 0, 255));
        assert_eq!(k1, k2);
    }

    #[test]
    fn subnet_key_distinguishes_third_octet() {
        let k1 = subnet_key(ip(10, 0, 0, 1));
        let k2 = subnet_key(ip(10, 0, 1, 1));
        assert_ne!(k1, k2);
    }

    #[test]
    fn fresh_subnet_allows_burst_then_blocks() {
        let mut rl = SourceRateLimiter::new();
        let subnet = subnet_key(ip(10, 0, 0, 1));
        for _ in 0..10 {
            assert!(rl.check_and_consume(subnet, 0));
        }
        assert!(!rl.check_and_consume(subnet, 0));
    }

    #[test]
    fn last_octet_rotation_cannot_bypass_source_limit() {
        let mut rl = SourceRateLimiter::new();
        for last in 0..=255_u8 {
            let subnet = subnet_key(ip(10, 0, 0, last));
            rl.check_and_consume(subnet, 0);
        }
        // All 256 IPs collapse to one subnet key, so the bucket is exhausted.
        assert!(!rl.check_and_consume(subnet_key(ip(10, 0, 0, 0)), 0));
    }

    #[test]
    fn zone_rate_limiter_bounds_per_label() {
        let mut zrl = ZoneRateLimiter::new();
        for _ in 0..50 {
            assert!(zrl.check_and_consume(b"alice", 0));
        }
        assert!(!zrl.check_and_consume(b"alice", 0));
        // Different label has its own bucket
        assert!(zrl.check_and_consume(b"bob", 0));
    }
}
