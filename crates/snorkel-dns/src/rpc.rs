//! Synchronous JSON-RPC client for querying RNS chain state.
//!
//! Uses HTTP POST to the node's RPC endpoint. Connection is kept alive
//! via HTTP keep-alive. If the connection drops, `ureq` reconnects on
//! the next request automatically.

use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};
use snorkel_common::types::NameRecord;

/// Wire codes for DNS record types we care about.
const WIRE_A: u32 = 1;
const WIRE_AAAA: u32 = 28;
const WIRE_CNAME: u32 = 5;
const WIRE_TXT: u32 = 16;

pub struct RpcClient {
    url: String,
    agent: Mutex<ureq::Agent>,
    next_id: Mutex<u64>,
}

#[derive(Debug)]
pub enum RpcError {
    Http(String),
    Json(String),
}

impl RpcClient {
    pub fn new(url: &str) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(5)))
            .build()
            .new_agent();
        Self {
            url: url.to_string(),
            agent: Mutex::new(agent),
            next_id: Mutex::new(1),
        }
    }

    fn next_id(&self) -> u64 {
        let mut id = self.next_id.lock().unwrap_or_else(|e| e.into_inner());
        let current = *id;
        *id = id.wrapping_add(1);
        current
    }

    /// Call `rns_lookupByName` for web2 record types.
    /// Returns a `NameRecord` populated with whatever the chain has,
    /// or `None` if the name doesn't exist or has no web records.
    pub fn lookup_name(&self, label: &str) -> Result<Option<NameRecord>, RpcError> {
        let id = self.next_id();
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "rns_lookupByName",
            "params": [label, [WIRE_A, WIRE_AAAA, WIRE_TXT]]
        });

        let agent = self.agent.lock().unwrap_or_else(|e| e.into_inner());
        let mut resp = agent
            .post(&self.url)
            .header("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|e| RpcError::Http(format!("{e}")))?;

        let json: Value = resp
            .body_mut()
            .read_json()
            .map_err(|e| RpcError::Json(format!("{e}")))?;

        let result = match json.get("result") {
            Some(v) if !v.is_null() => v,
            _ => return Ok(None),
        };

        let arr = match result.as_array() {
            Some(a) if !a.is_empty() => a,
            _ => return Ok(None),
        };

        let mut record = NameRecord::default();
        let mut has_web_record = false;

        for entry in arr {
            let code = entry.get(0).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let bytes = decode_byte_array(entry.get(1));

            match code {
                WIRE_A if bytes.len() == 4 => {
                    let mut addr = [0u8; 4];
                    addr.copy_from_slice(&bytes);
                    record.a = Some(addr);
                    has_web_record = true;
                }
                WIRE_AAAA if bytes.len() == 16 => {
                    let mut addr = [0u8; 16];
                    addr.copy_from_slice(&bytes);
                    record.aaaa = Some(addr);
                    has_web_record = true;
                }
                WIRE_CNAME => {
                    record.cname = Some(bytes);
                    has_web_record = true;
                }
                WIRE_TXT => {
                    record.txt = Some(bytes);
                    has_web_record = true;
                }
                _ => {} // SS58, ORIGIN, etc. — not web2, skip.
            }
        }

        if has_web_record {
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }
}

/// Substrate JSON-RPC returns byte arrays as JSON arrays of integers: [93,184,216,34]
fn decode_byte_array(val: Option<&Value>) -> Vec<u8> {
    let Some(arr) = val.and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
        .collect()
}
