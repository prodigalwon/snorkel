use std::collections::HashMap;

const MAX_ENTRIES: usize = 4096;
const PRUNE_INTERVAL_MICROS: u64 = 60_000_000;
const TTL_MICROS: u64 = 5 * 60 * 1_000_000;

#[derive(Clone, Copy)]
struct Penalty {
    strikes: u8,
    blocked_until_micros: u64,
}

pub struct PenaltyTracker {
    entries: HashMap<[u8; 4], Penalty>,
    last_prune_micros: u64,
}

impl PenaltyTracker {
    pub fn new() -> Self {
        Self {
            entries: HashMap::with_capacity(MAX_ENTRIES),
            last_prune_micros: 0,
        }
    }

    pub fn is_penalized(&self, subnet: &[u8; 4], now_micros: u64) -> bool {
        match self.entries.get(subnet) {
            Some(p) => now_micros < p.blocked_until_micros,
            None => false,
        }
    }

    pub fn record_strike(&mut self, subnet: [u8; 4], now_micros: u64) {
        self.maybe_prune(now_micros);

        let existing = self.entries.get(&subnet).copied();
        let new_penalty = match existing {
            Some(prev) => {
                let strikes = prev.strikes.saturating_add(1);
                let block_micros: u64 = match strikes {
                    1 => 1_000_000,
                    2 => 10_000_000,
                    _ => 60_000_000,
                };
                Penalty {
                    strikes,
                    blocked_until_micros: now_micros.saturating_add(block_micros),
                }
            }
            None => {
                if self.entries.len() >= MAX_ENTRIES {
                    return;
                }
                Penalty {
                    strikes: 1,
                    blocked_until_micros: now_micros.saturating_add(1_000_000),
                }
            }
        };
        self.entries.insert(subnet, new_penalty);
    }

    fn maybe_prune(&mut self, now_micros: u64) {
        if now_micros.saturating_sub(self.last_prune_micros) < PRUNE_INTERVAL_MICROS {
            return;
        }
        self.last_prune_micros = now_micros;
        let cutoff = now_micros.saturating_sub(TTL_MICROS);
        self.entries.retain(|_, p| p.blocked_until_micros > cutoff);
    }
}

impl Default for PenaltyTracker {
    fn default() -> Self {
        Self::new()
    }
}
