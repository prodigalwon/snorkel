use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use snorkel_common::types::NameRecord;

use crate::dispatch::CacheLookup;
use crate::rpc::RpcClient;

/// Cache entry TTL.  Both positive (`Present`) and negative entries refresh
/// from the chain after this duration.
///
/// The localsnorkel does not yet subscribe to chain events (`RecordsChanged`,
/// `NameRegistered`) for cache invalidation — that is the spec §11.4
/// merkle-verified, event-driven cache, deferred to a later revision.  This
/// TTL-based polling is the simpler intermediate: stale data is bounded by
/// `ENTRY_TTL`, which is good enough for DNS where most resolvers cache for
/// 60–900s anyway.
const ENTRY_TTL: Duration = Duration::from_secs(30);

pub struct MemCache {
    records: RwLock<HashMap<Vec<u8>, CacheEntry>>,
    rpc: Arc<RpcClient>,
}

struct CacheEntry {
    state: EntryState,
    inserted_at: Instant,
}

enum EntryState {
    /// Name exists on-chain and has web2 DNS records.
    Present(NameRecord),
    /// Name does not exist or has no web2 records.
    Negative,
}

impl CacheEntry {
    fn is_fresh(&self) -> bool {
        self.inserted_at.elapsed() < ENTRY_TTL
    }
}

impl MemCache {
    pub fn new(rpc: Arc<RpcClient>) -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
            rpc,
        }
    }

    pub fn insert(&self, label: Vec<u8>, record: NameRecord) {
        let mut map = self.records.write().unwrap_or_else(|e| e.into_inner());
        map.insert(
            label,
            CacheEntry {
                state: EntryState::Present(record),
                inserted_at: Instant::now(),
            },
        );
    }
}

impl CacheLookup for MemCache {
    fn lookup(&self, label: &[u8]) -> Option<NameRecord> {
        // Fast path: fresh cache hit (any state — Present or Negative).
        {
            let map = self.records.read().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = map.get(label) {
                if entry.is_fresh() {
                    return match &entry.state {
                        EntryState::Present(r) => Some(r.clone()),
                        EntryState::Negative => None,
                    };
                }
                // Stale entry — drop through to RPC re-fetch.
            }
        }

        // Cache miss or stale: ask the chain.
        let label_str = std::str::from_utf8(label).ok()?;
        let result = self.rpc.lookup_name(label_str);

        match result {
            Ok(Some(record)) => {
                let mut map = self.records.write().unwrap_or_else(|e| e.into_inner());
                map.insert(
                    label.to_vec(),
                    CacheEntry {
                        state: EntryState::Present(record.clone()),
                        inserted_at: Instant::now(),
                    },
                );
                Some(record)
            }
            Ok(None) => {
                let mut map = self.records.write().unwrap_or_else(|e| e.into_inner());
                map.insert(
                    label.to_vec(),
                    CacheEntry {
                        state: EntryState::Negative,
                        inserted_at: Instant::now(),
                    },
                );
                None
            }
            Err(_) => {
                // RPC failed — don't cache, don't lie. Return None so
                // the worker sends SERVFAIL (not NxDomain).
                None
            }
        }
    }
}
