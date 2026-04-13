use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use snorkel_common::types::NameRecord;

use crate::dispatch::CacheLookup;
use crate::rpc::RpcClient;

pub struct MemCache {
    records: RwLock<HashMap<Vec<u8>, CacheEntry>>,
    rpc: Arc<RpcClient>,
}

enum CacheEntry {
    /// Name exists on-chain and has web2 DNS records.
    Present(NameRecord),
    /// Name does not exist or has no web2 records. Cached to avoid
    /// repeated RPC calls for the same non-existent name.
    Negative,
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
        map.insert(label, CacheEntry::Present(record));
    }
}

impl CacheLookup for MemCache {
    fn lookup(&self, label: &[u8]) -> Option<NameRecord> {
        // Fast path: check cache under read lock.
        {
            let map = self.records.read().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = map.get(label) {
                return match entry {
                    CacheEntry::Present(r) => Some(r.clone()),
                    CacheEntry::Negative => None,
                };
            }
        }

        // Cache miss: ask the chain.
        let label_str = std::str::from_utf8(label).ok()?;
        let result = self.rpc.lookup_name(label_str);

        match result {
            Ok(Some(record)) => {
                let mut map = self.records.write().unwrap_or_else(|e| e.into_inner());
                map.insert(label.to_vec(), CacheEntry::Present(record.clone()));
                Some(record)
            }
            Ok(None) => {
                let mut map = self.records.write().unwrap_or_else(|e| e.into_inner());
                map.insert(label.to_vec(), CacheEntry::Negative);
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
