//! # snorkel-sync
//!
//! Checkpoint finality-follower for the Rostro resolution sync spec
//! (SYNC-SPEC.md). One of the three snorkel processes; the quarantine
//! zone for every chain-adjacent dependency, so `snorkel-dns` stays
//! lean and serves only from the local store.
//!
//! ## What it does each heartbeat
//!
//! 1. Handshake (spec-version gate, genesis check).
//! 2. Ask the courier for its finalized head.
//! 3. Ask for that height's justification.
//! 4. Hash the header ourselves, require the justification to be for
//!    that hash, and verify it against the authority set we hold.
//! 5. Only then roll the checkpoint forward, in one store transaction.
//!
//! Nothing the courier says is taken on trust: not the block hash, not
//! the height, not the authority set. See `follow.rs` for why step 4
//! computes the hash instead of accepting one.
//!
//! ## No trust on first use
//!
//! The loop needs a starting authority set, and taking that from the
//! courier would defeat the whole exercise. So the checkpoint comes
//! from the store, or from a file named by `SNORKEL_CHECKPOINT`, or the
//! process refuses to start. There is deliberately no path that
//! bootstraps trust from whatever the node happens to say.
//!
//! Env: `SNORKEL_STORE` (default `./snorkel-sync.redb`),
//! `SNORKEL_CHECKPOINT` (SCALE checkpoint file, first run only).

mod anchor;
mod bootstrap;
mod checkpoint;
mod courier;
mod follow;
mod hybrid;
mod proof;
mod rns_keys;
mod rules;
mod store;
mod verify;
mod wire;

use std::path::PathBuf;
use std::time::Duration;

use checkpoint::Checkpoint;
use courier::Courier;
use follow::{evaluate_candidate, Refusal};
use hybrid::HybridVerifier;
use rules::{serve_state, ServeState, HEARTBEAT_BLOCKS};
use store::Store;

/// The localsnorkel invariant: the courier is the node on this box.
const RPC_URL: &str = "http://127.0.0.1:9944";

/// Poll cadence: heartbeat = k/4 blocks at ~6s blocks.
const HEARTBEAT_SECS: u64 = HEARTBEAT_BLOCKS * 6;

fn main() {
    let store_path = std::env::var("SNORKEL_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./snorkel-sync.redb"));

    let store = match Store::open(&store_path) {
        Ok(s) => s,
        Err(e) => fatal(&format!("cannot open store {}: {e}", store_path.display())),
    };

    let mut held = match load_checkpoint(&store) {
        Ok(c) => c,
        Err(e) => fatal(&e),
    };
    println!(
        "snorkel-sync: trust base height={} set_id={} authorities={}",
        held.height,
        held.set_id,
        held.authorities.len()
    );

    let courier = Courier::new(RPC_URL);

    loop {
        if let Some(next) = cycle(&courier, &store, &held) {
            held = next;
        }
        std::thread::sleep(Duration::from_secs(HEARTBEAT_SECS));
    }
}

/// Store first, then the supplied file. Never the courier.
fn load_checkpoint(store: &Store) -> Result<Checkpoint, String> {
    match store.checkpoint() {
        Ok(Some(c)) => return Ok(c),
        // A corrupt persisted checkpoint is an alarm, not a prompt to
        // re-baseline from whatever happens to be reachable.
        Err(e) => return Err(format!("persisted checkpoint REJECTED: {e}")),
        Ok(None) => {}
    }
    let path = std::env::var("SNORKEL_CHECKPOINT").map_err(|_| {
        "no checkpoint: the store is empty and SNORKEL_CHECKPOINT is unset. \
         Refusing to start rather than trusting the courier for an initial \
         authority set."
            .to_string()
    })?;
    let bytes = std::fs::read(&path).map_err(|e| format!("reading {path}: {e}"))?;
    let c = Checkpoint::load(&bytes)?;
    store.put_checkpoint(&c)?;
    println!("snorkel-sync: adopted release checkpoint from {path}");
    Ok(c)
}

/// One heartbeat. Returns the new checkpoint if a head was verified and
/// adopted.
fn cycle(courier: &Courier, store: &Store, held: &Checkpoint) -> Option<Checkpoint> {
    let info = match courier.handshake() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("snorkel-sync: handshake failed: {e:?} — alarm, retrying next heartbeat");
            return None;
        }
    };
    if info.genesis_hash != held.genesis_hash {
        eprintln!("snorkel-sync: courier is on a DIFFERENT CHAIN (genesis mismatch) — refusing");
        return None;
    }

    let head = match courier.finalized() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("snorkel-sync: finalized poll failed: {e:?}");
            return None;
        }
    };

    if head.height <= held.height {
        report_freshness(held.height, held.height);
        return None;
    }

    // Justifications are only STORED periodically, so the head usually
    // has none. Fall back to the most recent cadence point the courier
    // advertises, which is where one is guaranteed to exist.
    let cadence = u64::from(info.retention.justification_cadence.max(1));
    let candidates: Vec<u64> = [head.height, (head.height / cadence) * cadence, 1]
        .into_iter()
        .filter(|h| *h > held.height)
        .collect();

    let mut candidate = None;
    for h in candidates {
        if let Ok(j) = courier.justification(h) {
            candidate = Some(j);
            break;
        }
    }
    let Some(candidate) = candidate else {
        println!(
            "snorkel-sync: head={} but no justification available at or below it \
             (cadence {cadence}); holding anchor at {}",
            head.height, held.height
        );
        report_freshness(head.height, held.height);
        return None;
    };

    match evaluate_candidate(held, &HybridVerifier, &candidate.header, &candidate.justification) {
        Ok(adoption) => {
            let next = adoption.advance(held);
            // Rule 6: the checkpoint advance commits in ONE transaction.
            // Replica writes join this transaction when they land.
            if let Err(e) = store.put_checkpoint(&next) {
                eprintln!("snorkel-sync: checkpoint persist FAILED: {e} — not advancing");
                return None;
            }
            println!(
                "snorkel-sync: VERIFIED and adopted height {} (was {})",
                next.height, held.height
            );
            report_freshness(next.height, next.height);
            Some(next)
        }
        Err(Refusal::Unverified { set_id, err }) => {
            eprintln!(
                "snorkel-sync: justification for height {} did NOT verify under set {set_id} \
                 ({err:?}) — either an authority-set change we have not walked, or a lying \
                 courier. Not advancing.",
                head.height
            );
            report_freshness(head.height, held.height);
            None
        }
        Err(r) => {
            eprintln!("snorkel-sync: refused height {}: {r:?}", head.height);
            report_freshness(head.height, held.height);
            None
        }
    }
}

fn report_freshness(verified_head: u64, anchor: u64) {
    if matches!(serve_state(verified_head, anchor), ServeState::StaleAlarm) {
        eprintln!(
            "snorkel-sync: anchor {anchor} is stale past the recency bound \
             (head {verified_head}) — a serving build would stop answering here"
        );
    }
}

fn fatal(msg: &str) -> ! {
    eprintln!("snorkel-sync: {msg}");
    std::process::exit(1);
}
