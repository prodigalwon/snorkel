//! Minimal verify-only subset of Substrate's state-trie codec.
//!
//! Rostro's chain state lives in a Blake2-256 hexary Merkle-Patricia
//! trie, and a record proof is only meaningful if it is checked with
//! *exactly* the same node encoding the chain uses. Reimplementing that
//! encoding would be the worst kind of guess: a subtle mismatch either
//! rejects every genuine proof (visible) or, far worse, accepts a
//! malformed one (invisible).
//!
//! So `node_codec.rs`, `node_header.rs` and `error.rs` are vendored
//! from `sp-trie` **unmodified**. They are self-contained by
//! construction — their only dependencies are `codec`, `hash-db` and
//! `trie-db`, with no `sp-core` reference anywhere — which is what
//! makes this subset extractable at all.
//!
//! What this crate adds is only the glue `sp-trie` gets from `sp-core`:
//! the Blake2-256 [`Hasher`] and the [`LayoutV1`] parameters.
//!
//! See `VENDOR.md` for provenance and the update rule.

#![forbid(unsafe_code)]

extern crate alloc;

pub mod error;
pub mod node_codec;
pub mod node_header;

use core::marker::PhantomData;

use blake2::{digest::consts::U32, Blake2b, Digest};
use hash_db::Hasher;
use trie_db::TrieLayout;

pub use node_codec::NodeCodec;
pub use trie_db;

/// Node-header prefix constants, verbatim from `sp-trie`'s private
/// `trie_constants` module (it is not exported, so it is restated here
/// rather than copied wholesale).
pub mod trie_constants {
    const FIRST_PREFIX: u8 = 0b_00 << 6;
    pub const LEAF_PREFIX_MASK: u8 = 0b_01 << 6;
    pub const BRANCH_WITHOUT_MASK: u8 = 0b_10 << 6;
    pub const BRANCH_WITH_MASK: u8 = 0b_11 << 6;
    pub const EMPTY_TRIE: u8 = FIRST_PREFIX | (0b_00 << 4);
    pub const ALT_HASHING_LEAF_PREFIX_MASK: u8 = FIRST_PREFIX | (0b_1 << 5);
    pub const ALT_HASHING_BRANCH_WITH_MASK: u8 = FIRST_PREFIX | (0b_01 << 4);
    pub const ESCAPE_COMPACT_HEADER: u8 = EMPTY_TRIE | 0b_00_01;
}

/// Values at least this long are stored by hash rather than inline
/// (`sp_core::storage::TRIE_VALUE_NODE_THRESHOLD`). Load-bearing: it
/// changes node encoding, so a wrong value silently breaks proofs.
pub const TRIE_VALUE_NODE_THRESHOLD: u32 = 33;

/// Blake2-256, the chain's state-trie hasher.
///
/// `sp-core` supplies this to `sp-trie`; we supply our own so the
/// vendored codec needs nothing from the chain's primitives graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Blake2Hasher;

impl Hasher for Blake2Hasher {
    type Out = [u8; 32];
    type StdHasher = hash256_std_hasher::Hash256StdHasher;
    const LENGTH: usize = 32;

    fn hash(x: &[u8]) -> Self::Out {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Blake2b::<U32>::digest(x));
        out
    }
}

/// The trie layout Rostro's runtime uses.
///
/// gemini declares `system_version: 1`, which selects state version 1,
/// i.e. `sp-trie`'s `LayoutV1`: no extension nodes, empty tries
/// allowed, and values of [`TRIE_VALUE_NODE_THRESHOLD`] bytes or more
/// stored by hash.
pub struct LayoutV1<H>(PhantomData<H>);

impl<H: Hasher> TrieLayout for LayoutV1<H> {
    const USE_EXTENSION: bool = false;
    const ALLOW_EMPTY: bool = true;
    const MAX_INLINE_VALUE: Option<u32> = Some(TRIE_VALUE_NODE_THRESHOLD);

    type Hash = H;
    type Codec = NodeCodec<Self::Hash>;
}

/// The concrete layout for Rostro chain state.
pub type RostroStateLayout = LayoutV1<Blake2Hasher>;

/// A 32-byte state root / node hash.
pub type H256 = [u8; 32];
