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

const BIND_ADDR: &str = "0.0.0.0:5353";
const ZONE: &[u8] = b"dot";
const MIN_RESPONSE_MICROS: u64 = 2_000;
const INFLIGHT_MAX: u64 = 100;
const METRICS_LOG_INTERVAL_SECS: u64 = 60;
const RPC_URL: &str = "http://127.0.0.1:9944";

#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
fn main() -> Result<(), Box<dyn Error>> {
    let bind_addr: SocketAddr = BIND_ADDR.parse()?;

    let rpc = Arc::new(RpcClient::new(RPC_URL));
    let cache = MemCache::new(Arc::clone(&rpc));

    let dispatcher = Dispatcher {
        zone: ZONE,
        gateway_v4: Some([198, 51, 100, 1]),
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
        "snorkel-dns listening on {} with {} worker(s), zone {:?}, rpc={}, min_response_micros={}, inflight_max={}",
        bind_addr,
        num_workers,
        std::str::from_utf8(ZONE).unwrap_or("<binary>"),
        RPC_URL,
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
