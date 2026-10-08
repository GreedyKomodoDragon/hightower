//! Hash-tree roots: chunk a value, Merkleize the chunks, and for
//! length-prefixed types (List, BitList, ByteList) mix the current
//! length into the resulting root.
//!
//! Different SSZ types have different Merkleization rules:
//!
//!   - bool / uint: encoded into a 32-byte chunk, zero-padded
//!   - Vector of basic values: packed into 32-byte chunks, Merkleized
//!   - Container: each field contributes one 32-byte hash-tree root
//!   - List: contents Merkleized under the maximum capacity, then the
//!     current length is mixed into the resulting root
//!
//! Serialization and Merkleization share the same SSZ schema but are
//! separate operations: `serialize(value)` gives canonical bytes,
//! `HashTreeRoot(value)` gives the canonical 32-byte commitment.

const std = @import("std");
const desc_mod = @import("type_descriptor");
const bit_list_mod = @import("bitlist");
const get_chunks_mod = @import("get_chunks.zig");
const merkleize_mod = @import("merkleize.zig");
const strategy_mod = @import("strategy.zig");
const progressive_mod = @import("progressive.zig");

// HashTreeRoot will be used in the following:
//
// beacon code
//     uses HashTreeRoot(...)
//
// SSZ code
//     HashTreeRoot(...)
//         calls GetChunks(...)
//         calls Merkleize(...)
pub fn HashTreeRoot(
    allocator: std.mem.Allocator,
    value: anytype,
) ![32]u8 {
    const T = @TypeOf(value);
    const desc = comptime desc_mod.SszType(T);

    switch (desc.kind) {
        .ProgressiveContainer => {
            return progressive_mod.progressiveHashTreeRoot(allocator, value);
        },
        .BitList, .ByteList, .List => {
            const chunks = try get_chunks_mod.GetChunks(
                allocator,
                value,
            );
            defer allocator.free(chunks);

            const content_root = try merkleize_mod.Merkleize(
                allocator,
                chunks,
                strategy_mod.limitChunks(T),
            );

            return bit_list_mod.mixInLength(
                content_root,
                value.data.len,
            );
        },
        else => {
            // get all the chunks for a specific value
            const chunks = try get_chunks_mod.GetChunks(allocator, value);
            defer allocator.free(chunks);

            // then do the pairwise SHA-256 reduction
            return merkleize_mod.Merkleize(allocator, chunks, null);
        },
    }
}
