# Vendored Substrate trie codec (verify-only subset)

## What and why

Rostro chain state lives in a Blake2-256 hexary Merkle-Patricia trie.
A record proof only means anything if it is checked with *exactly* the
node encoding the chain uses: a subtle mismatch either rejects every
genuine proof (loud) or accepts a malformed one (silent, and much
worse). Reimplementing that encoding would be a guess, so it is
vendored instead.

## Source

`node_codec.rs`, `node_header.rs`, `error.rs` copied **unmodified**
from Rostro's `substrate/primitives/trie/src/` (`sp-trie` 43.0.0),
which is itself unmodified from upstream Substrate.

These three files are self-contained by construction — their only
dependencies are `codec`, `hash-db` and `trie-db`, with no `sp-core`
reference anywhere. That is what makes the subset extractable.

## What this crate adds

Only the glue `sp-trie` normally takes from `sp-core`:

- `Blake2Hasher` — the state-trie hasher, over the `blake2` crate,
  using `Hash256StdHasher` for `StdHasher` exactly as `sp-core` does.
- `trie_constants` — restated because `sp-trie` keeps the module
  private.
- `TRIE_VALUE_NODE_THRESHOLD = 33` — load-bearing: it changes node
  encoding, so a wrong value silently breaks proofs.
- `LayoutV1` — gemini declares `system_version: 1`, selecting state
  version 1: no extension nodes, empty tries allowed, values of 33
  bytes or more stored by hash.

## Why not depend on sp-trie

The snorkel is a separate, self-contained codebase; someone auditing
the resolver should not need the chain tree to see every byte that
verifies a record. `sp-trie` would pull `sp-core` and
`sp-externalities` and a good deal behind them, for three files' worth
of actual need.

## Correctness pinning

`crates/snorkel-sync/vectors/record_proof_dev.txt` holds a real proof
captured from a running `gemini-node --dev` (state root, height, nodes,
entries). The tests in `crates/snorkel-sync/src/proof.rs` verify a
genuine value under a genuine state root through this codec. If the
chain's trie layout, hasher, or value threshold ever changes, those
tests fail here rather than the snorkel rejecting real records in
production.

## Updating

Re-copy from `sp-trie` only alongside a Substrate bump in the chain,
and re-capture the proof fixture from a node built at that version.
Any divergence from the chain's layout means the snorkel rejects real
records, so the two must move together.
