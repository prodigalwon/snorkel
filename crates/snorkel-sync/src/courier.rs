//! Typed client for the co-located courier's `sync_*` surface.
//!
//! The courier is the node on this box (`127.0.0.1:9944`, the
//! localsnorkel invariant) and is an ADVERSARY BY ASSUMPTION (client
//! rule 1): nothing returned here is trusted until proof/signature
//! verification. Nothing in this module may condition on the courier's
//! address — that neutrality is what makes stage-2 remote couriers a
//! config change instead of a redesign.

use std::sync::Mutex;
use std::time::Duration;

use parity_scale_codec::Decode;
use serde_json::{json, Value};

use crate::wire::{
    from_hex, FinalizedHead, HandshakeInfo, JustifiedHeader, SPEC_VERSION, SCHEMA_VERSION,
};

pub struct Courier {
    url: String,
    agent: Mutex<ureq::Agent>,
    next_id: Mutex<u64>,
}

#[derive(Debug)]
pub enum CourierError {
    Http(String),
    Rpc { code: i64, message: String },
    Envelope(String),
    /// Spec major-version mismatch: refuse the courier outright.
    VersionRefused { server: u32, client: u32 },
    /// Schema outside our N/N+1 tolerance.
    SchemaRefused { server: u16, client: u16 },
}

impl Courier {
    pub fn new(url: &str) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(10)))
            .build();
        Courier {
            url: url.to_owned(),
            agent: Mutex::new(config.into()),
            next_id: Mutex::new(1),
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<String, CourierError> {
        let id = {
            let mut guard = self.next_id.lock().map_err(|_| poisoned())?;
            let id = *guard;
            *guard = guard.wrapping_add(1);
            id
        };
        let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let response: Value = {
            let agent = self.agent.lock().map_err(|_| poisoned())?;
            agent
                .post(&self.url)
                .send_json(&body)
                .map_err(|e| CourierError::Http(e.to_string()))?
                .body_mut()
                .read_json()
                .map_err(|e| CourierError::Http(e.to_string()))?
        };
        if let Some(err) = response.get("error") {
            return Err(CourierError::Rpc {
                code: err.get("code").and_then(Value::as_i64).unwrap_or(0),
                message: err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
            });
        }
        response
            .get("result")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| CourierError::Envelope("result is not a hex string".into()))
    }

    fn call_scale<T: Decode>(&self, method: &str, params: Value) -> Result<T, CourierError> {
        let hexed = self.call(method, params)?;
        let raw = from_hex(&hexed).map_err(CourierError::Envelope)?;
        T::decode(&mut raw.as_slice())
            .map_err(|e| CourierError::Envelope(format!("{method}: SCALE decode: {e}")))
    }

    /// First call, always. Enforces the §2 version gate:
    /// major-mismatch = refuse; schema outside {N, N+1} = refuse.
    pub fn handshake(&self) -> Result<HandshakeInfo, CourierError> {
        let info: HandshakeInfo = self.call_scale("sync_handshake", json!([]))?;
        if info.spec_version >> 16 != SPEC_VERSION >> 16 {
            return Err(CourierError::VersionRefused {
                server: info.spec_version,
                client: SPEC_VERSION,
            });
        }
        let s = info.schema_version;
        if s != SCHEMA_VERSION && s != SCHEMA_VERSION.saturating_add(1) {
            return Err(CourierError::SchemaRefused { server: s, client: SCHEMA_VERSION });
        }
        Ok(info)
    }

    pub fn finalized(&self) -> Result<FinalizedHead, CourierError> {
        self.call_scale("sync_finalized", json!([]))
    }

    pub fn justification(&self, height: u64) -> Result<JustifiedHeader, CourierError> {
        self.call_scale("sync_justification", json!([height]))
    }

    pub fn authority_handoffs(
        &self,
        from_set_id: u64,
        limit: u32,
    ) -> Result<Vec<JustifiedHeader>, CourierError> {
        self.call_scale("sync_authorityHandoffs", json!([from_set_id, limit]))
    }
}

fn poisoned() -> CourierError {
    CourierError::Http("internal mutex poisoned".into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::wire::Retention;

    fn info(spec_version: u32, schema_version: u16) -> HandshakeInfo {
        HandshakeInfo {
            spec_version,
            schema_version,
            genesis_hash: [0; 32],
            finalized_height: 0,
            finalized_hash: [0; 32],
            capabilities: 0,
            retention: Retention { justification_cadence: 512, state_window: 7200 },
        }
    }

    /// The gate logic, extracted for testing without a server.
    fn gate(i: &HandshakeInfo) -> Result<(), CourierError> {
        if i.spec_version >> 16 != SPEC_VERSION >> 16 {
            return Err(CourierError::VersionRefused {
                server: i.spec_version,
                client: SPEC_VERSION,
            });
        }
        let s = i.schema_version;
        if s != SCHEMA_VERSION && s != SCHEMA_VERSION.saturating_add(1) {
            return Err(CourierError::SchemaRefused { server: s, client: SCHEMA_VERSION });
        }
        Ok(())
    }

    #[test]
    fn version_gate() {
        assert!(gate(&info(SPEC_VERSION, SCHEMA_VERSION)).is_ok());
        // Minor revisions are additive: accepted.
        assert!(gate(&info(SPEC_VERSION + 5, SCHEMA_VERSION)).is_ok());
        // Major bump: refused.
        assert!(matches!(
            gate(&info(0x0002_0000, SCHEMA_VERSION)),
            Err(CourierError::VersionRefused { .. })
        ));
        // Schema N+1 tolerated, N+2 refused.
        assert!(gate(&info(SPEC_VERSION, SCHEMA_VERSION + 1)).is_ok());
        assert!(matches!(
            gate(&info(SPEC_VERSION, SCHEMA_VERSION + 2)),
            Err(CourierError::SchemaRefused { .. })
        ));
    }
}
