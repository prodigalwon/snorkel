//! # localsnorkel
//!
//! Reference DNS server for RNS, deployed on the **same box** as a
//! Rostro node.  Communication with the
//! chain is over plain HTTP on `127.0.0.1:9944` — kernel-resident loopback,
//! no TLS handshake, no nginx hop, no network round-trip on cache miss.
//! That property is the *defining* invariant of the localsnorkel pattern,
//! so [`RPC_URL`] is intentionally **not** an environment variable.  If you
//! want to talk to a remote chain, you don't want a localsnorkel.
//!
//! ## Deployment knobs (env vars)
//!
//! | Variable             | Default            | Notes                                     |
//! | -------------------- | ------------------ | ----------------------------------------- |
//! | `SNORKEL_BIND`       | `127.0.0.1:5353`   | Set to `<public-ip>:53` in production.    |
//! | `SNORKEL_ZONE`       | `dot`              | Set to your delegated subzone, e.g.       |
//! |                      |                    | `paseo.substrate.icu`.                    |
//! | `SNORKEL_GATEWAY_V4` | unset              | Optional `a.b.c.d` — fallback A target    |
//! |                      |                    | for names that have only `CONTENT`.       |
//!
//! ## Spec deviations (v1)
//!
//! - **Single-process**, not the spec §11.4 two-process IPC isolation.  The
//!   localsnorkel runs co-located with the chain, so the trust boundary the
//!   IPC split was designed to enforce isn't applicable here.
//! - **TTL-based cache** (see `memcache.rs`), not merkle-verified +
//!   event-driven.  Stale data is bounded by `ENTRY_TTL` (30s) instead of
//!   invalidated on `RecordsChanged` events.
//! - **No bundled janitor.**  Manual cleanup via on-chain extrinsics.

mod bloom;
mod builder;
mod dispatch;
mod memcache;
mod metrics;
mod negcache;
mod parser;
mod penalty;
mod ratelimit;
mod rpc;
mod worker;

use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::dispatch::Dispatcher;
use crate::memcache::MemCache;
use crate::metrics::Metrics;
use crate::rpc::RpcClient;
use crate::worker::{InFlightCap, WorkerShared, create_worker_socket, worker_loop};

/// Chain RPC URL.  HARDCODED — the localsnorkel invariant: chain runs on
/// the same box and is reached via kernel-loopback HTTP.  Not configurable.
const RPC_URL: &str = "http://127.0.0.1:9944";

/// Default bind address used when `SNORKEL_BIND` is not set.  Loopback so
/// an unconfigured snorkel does NOT accidentally serve external traffic.
const DEFAULT_BIND: &str = "127.0.0.1:5353";

/// Default zone if `SNORKEL_ZONE` is not set.  Matches the chain's native
/// basenode for local dev.
const DEFAULT_ZONE: &str = "dot";

const MIN_RESPONSE_MICROS: u64 = 2_000;
const INFLIGHT_MAX: u64 = 100;
const METRICS_LOG_INTERVAL_SECS: u64 = 60;

#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
fn main() -> Result<(), Box<dyn Error>> {
    let bind_str = std::env::var("SNORKEL_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let bind_addr: SocketAddr = bind_str.parse()?;

    let zone_string = std::env::var("SNORKEL_ZONE").unwrap_or_else(|_| DEFAULT_ZONE.to_string());
    let zone: Vec<u8> = zone_string.clone().into_bytes();

    let gateway_v4: Option<[u8; 4]> = std::env::var("SNORKEL_GATEWAY_V4").ok().and_then(parse_v4);

    let rpc = Arc::new(RpcClient::new(RPC_URL));
    let cache = MemCache::new(Arc::clone(&rpc));

    let dispatcher = Dispatcher {
        zone: &zone,
        gateway_v4,
        gateway_v6: None,
        cache: &cache,
    };

    let metrics = Arc::new(Metrics::new());
    let inflight = Arc::new(InFlightCap::new(INFLIGHT_MAX));

    let num_workers = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let core_ids = core_affinity::get_core_ids().unwrap_or_default();

    println!(
        "snorkel-dns listening on {} with {} worker(s), zone {:?}, rpc={}, gateway_v4={:?}, min_response_micros={}, inflight_max={}",
        bind_addr,
        num_workers,
        zone_string,
        RPC_URL,
        gateway_v4,
        MIN_RESPONSE_MICROS,
        INFLIGHT_MAX,
    );

    // Metrics logger thread.
    let metrics_for_logger = Arc::clone(&metrics);
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(METRICS_LOG_INTERVAL_SECS));
            metrics_for_logger.log_snapshot();
        }
    });

    thread::scope(|s| {
        for instance in 0..num_workers {
            let dispatcher_ref = &dispatcher;
            let metrics_ref: &Metrics = &metrics;
            let inflight_ref: &InFlightCap = &inflight;
            let core_id = core_ids.get(instance).copied();

            s.spawn(move || {
                if let Some(core) = core_id {
                    if !core_affinity::set_for_current(core) {
                        eprintln!("worker {instance} failed to pin to core {core:?}");
                    }
                }

                match create_worker_socket(bind_addr) {
                    Ok(socket) => {
                        println!("worker {instance} bound");
                        let shared = WorkerShared {
                            dispatcher: dispatcher_ref,
                            metrics: metrics_ref,
                            inflight: inflight_ref,
                            min_response_micros: MIN_RESPONSE_MICROS,
                        };
                        worker_loop(socket, shared);
                    }
                    Err(e) => {
                        eprintln!("worker {instance} bind failed: {e}");
                    }
                }
            });
        }
    });

    Ok(())
}

/// Parse a dotted-quad IPv4 string into 4 octets.  Returns `None` on any
/// malformed input so the caller (env-var parser) can ignore garbage rather
/// than panic.
fn parse_v4(s: String) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.parse::<u8>().ok()?;
    }
    Some(out)
}
