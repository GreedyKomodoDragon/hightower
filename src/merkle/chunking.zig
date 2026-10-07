//! Merkleization public API.
//!
//! SSZ objects get two related encodings: `serialize(value)` gives
//! canonical bytes, `HashTreeRoot(value)` gives the canonical 32-byte
//! commitment, computed by reducing the value to 32-byte chunks and
//! hashing pairs until one root remains. Nested values hash
//! recursively: a nested container, vector or list first computes its
//! own root, which becomes one leaf in its parent's tree.
//!
//! Layout of this module:
//! - `GetChunks` / `HashTreeRoot` are thin kind-dispatchers (see
//!   `get_chunks.zig`, `hash_tree_root.zig`)
//! - per-kind packing rules live in `strategy.zig`, bit packing in
//!   `bitlist.zig`, EIP-7495/7916 progression in `progressive.zig`
//! - `Merkleize` is the core pairwise-reduction primitive
//!   (see `merkleize.zig`)

const get_chunks_mod = @import("get_chunks.zig");
const hash_tree_root_mod = @import("hash_tree_root.zig");
const merkleize_mod = @import("merkleize.zig");

pub const GetChunks = get_chunks_mod.GetChunks;
pub const HashTreeRoot = hash_tree_root_mod.HashTreeRoot;
pub const Merkleize = merkleize_mod.Merkleize;
