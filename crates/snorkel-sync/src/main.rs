//! # snorkel-sync
//!
//! Checkpoint finality-follower and verified replica maintainer for
//! the Rostro resolution sync contract (SYNC-CONTRACT.md). One of the
//! three snorkel processes; the quarantine zone for every
//! chain-adjacent dependency (snorkel-dns stays lean and serves only
//! from the local store).
//!
//! ## v0 status: OBSERVE MODE, on purpose
//!
//! Client rule 1 says no served byte is trusted before verification,
//! and the hybrid-PQ justification verifier is not implemented yet. So
//! this binary deliberately REFUSES to advance the trust checkpoint:
//! it handshakes (version gate enforced), polls the finalized head on
//! the heartbeat, evaluates client rules 2/3 against the held
//! checkpoint, logs what it would do — and stops short of adoption,
//! loudly, every cycle. Wiring `verify::justification()` (next) is
//! what flips observe mode into the real loop; nothing else changes
//! shape. An observe-mode process serves nothing and invalidates
//! nothing.
//!
//! Deployment knob (env): `SNORKEL_STORE` — store path, default
//! `./snorkel-sync.redb`.

mod checkpoint;
mod courier;
mod rules;
mod store;
mod verify;
mod wire;

use std::path::PathBuf;
use std::time::Duration;

use courier::Courier;
use rules::{judge_anchor, serve_state, AnchorVerdict, ServeState, HEARTBEAT_BLOCKS};
use store::Store;

/// The localsnorkel invariant: the courier is the node on this box.
/// Deliberately not configurable (see snorkel-dns/src/main.rs).
const RPC_URL: &str = "http://127.0.0.1:9944";

/// Poll cadence in seconds: heartbeat = k/4 blocks at ~6s blocks.
const HEARTBEAT_SECS: u64 = HEARTBEAT_BLOCKS * 6;

fn main() {
    let store_path = std::env::var("SNORKEL_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./snorkel-sync.redb"));

    let store = match Store::open(&store_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("snorkel-sync: cannot open store {}: {e}", store_path.display());
            std::process::exit(1);
        }
    };

    let held = match store.checkpoint() {
        Ok(Some(c)) => {
            println!(
                "snorkel-sync: resuming from persisted checkpoint height={} set_id={}",
                c.height, c.set_id
            );
            Some(c)
        }
        Ok(None) => {
            println!(
                "snorkel-sync: fresh store (no release-baked checkpoint wired yet); \
                 observe mode only"
            );
            None
        }
        Err(e) => {
            // A corrupt/tampered checkpoint is an alarm, not a shrug:
            // refuse to run rather than silently re-baseline.
            eprintln!("snorkel-sync: persisted checkpoint REJECTED: {e}");
            eprintln!("snorkel-sync: refusing to start; move the store aside to re-baseline");
            std::process::exit(1);
        }
    };

    let courier = Courier::new(RPC_URL);

    loop {
        cycle(&courier, held.as_ref());
        std::thread::sleep(Duration::from_secs(HEARTBEAT_SECS));
    }
}

fn cycle(courier: &Courier, held: Option<&checkpoint::Checkpoint>) {
    let info = match courier.handshake() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("snorkel-sync: handshake failed: {e:?} (alarm; retrying on heartbeat)");
            return;
        }
    };

    let head = match courier.finalized() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("snorkel-sync: finalized poll failed: {e:?}");
            return;
        }
    };

    // Rules 2/3 evaluated against the held checkpoint. The "verified
    // head" is the checkpoint height itself until the justification
    // verifier lands — the honest number, since nothing newer has been
    // verified.
    let held_height = held.map(|c| c.height).unwrap_or(0);
    let verified_head = held_height;
    let verdict = judge_anchor(held_height, verified_head, head.height);
    let freshness = serve_state(verified_head, held_height);

    println!(
        "snorkel-sync[observe]: courier finalized={} (contract {:#x}, schema {}) \
         held={held_height} verdict={verdict:?} freshness={freshness:?} — \
         NOT adopting: justification verifier not yet implemented",
        head.height, info.contract_version, info.schema_version,
    );

    if matches!(verdict, AnchorVerdict::AboveVerifiedHead) {
        // Expected in observe mode: everything the courier offers is
        // above what we've verified, because we verify nothing yet.
        // The log line above is the alarm.
    }
    if matches!(freshness, ServeState::StaleAlarm) {
        eprintln!(
            "snorkel-sync: held checkpoint is stale past the recency bound; \
             a verifying build would stop serving here"
        );
    }
}
