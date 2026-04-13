use std::collections::HashMap;

use crate::bloom::DoubleBloom;

const MAX_NEG_CACHE: usize = 20_000;
const MAX_FIRST_SEEN: usize = 4_096;
const NEG_CACHE_TTL_MICROS: u64 = 60_000_000;
const FIRST_SEEN_TTL_MICROS: u64 = 10_000_000;
const BLOOM_BITS: u64 = 1_000_000;
const BLOOM_HASHES: u32 = 7;
const BLOOM_SATURATION: u64 = 80_000;
const PRUNE_INTERVAL_MICROS: u64 = 30_000_000;

pub struct NegCache {
    neg_cache: HashMap<Vec<u8>, u64>,
    first_seen: HashMap<Vec<u8>, u64>,
    bloom: DoubleBloom,
    last_prune_micros: u64,
}

impl NegCache {
    pub fn new() -> Self {
        Self {
            neg_cache: HashMap::with_capacity(MAX_NEG_CACHE),
            first_seen: HashMap::with_capacity(MAX_FIRST_SEEN),
            bloom: DoubleBloom::new(BLOOM_BITS, BLOOM_HASHES, BLOOM_SATURATION),
            last_prune_micros: 0,
        }
    }

    pub fn is_negative(&self, name: &[u8]) -> bool {
        if !self.bloom.check(name) {
            return false;
        }
        self.neg_cache.contains_key(name)
    }

    /// Record an NXDOMAIN observation. Returns true if this is the second
    /// observation within the first-seen window and the name has been
    /// promoted to the real negative cache.
    pub fn observe_nxdomain(&mut self, name: &[u8], now_micros: u64) -> bool {
        self.maybe_prune(now_micros);

        if self.neg_cache.contains_key(name) {
            return false;
        }

        if let Some(&first_seen_at) = self.first_seen.get(name) {
            if now_micros.saturating_sub(first_seen_at) < FIRST_SEEN_TTL_MICROS {
                if self.neg_cache.len() < MAX_NEG_CACHE {
                    self.neg_cache.insert(name.to_vec(), now_micros);
                    self.bloom.set(name);
                }
                self.first_seen.remove(name);
                return true;
            }
            self.first_seen.insert(name.to_vec(), now_micros);
            return false;
        }

        if self.first_seen.len() < MAX_FIRST_SEEN {
            self.first_seen.insert(name.to_vec(), now_micros);
        }
        false
    }

    fn maybe_prune(&mut self, now_micros: u64) {
        if now_micros.saturating_sub(self.last_prune_micros) < PRUNE_INTERVAL_MICROS {
            return;
        }
        self.last_prune_micros = now_micros;

        let neg_cutoff = now_micros.saturating_sub(NEG_CACHE_TTL_MICROS);
        self.neg_cache.retain(|_, inserted_at| *inserted_at > neg_cutoff);

        let fs_cutoff = now_micros.saturating_sub(FIRST_SEEN_TTL_MICROS);
        self.first_seen.retain(|_, seen_at| *seen_at > fs_cutoff);
    }
}

impl Default for NegCache {
    fn default() -> Self {
        Self::new()
    }
}
