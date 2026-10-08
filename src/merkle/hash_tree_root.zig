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
const errors = @import("ssz_errors");
const get_chunks_mod = @import("get_chunks.zig");
const merkleize_mod = @import("merkleize.zig");
const strategy_mod = @import("strategy.zig");
const progressive_mod = @import("progressive.zig");

pub const SszError = errors.SszError;

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
) (std.mem.Allocator.Error || SszError)![32]u8 {
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

            return mixInLength(
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

/// Length mix-in: hash(content_root ++ little-endian length word).
/// Pure (infallible); lives beside its only caller.
fn mixInLength(
    root: [32]u8,
    length: usize,
) [32]u8 {
    var length_chunk = [_]u8{0} ** 32;

    var length_bytes: [8]u8 = undefined;
    std.mem.writeInt(
        u64,
        &length_bytes,
        @intCast(length),
        .little,
    );

    @memcpy(length_chunk[0..8], &length_bytes);

    var input: [64]u8 = undefined;

    @memcpy(input[0..32], &root);
    @memcpy(input[32..64], &length_chunk);

    var result: [32]u8 = undefined;

    std.crypto.hash.sha2.Sha256.hash(
        &input,
        &result,
        .{},
    );

    return result;
}
