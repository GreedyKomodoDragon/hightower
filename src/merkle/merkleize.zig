//! Core Merkle tree primitive: pairwise SHA-256 reduction of
//! 32-byte chunks, with optional limit-aware width and zero padding.

const std = @import("std");
const errors = @import("ssz_errors");

pub const SszError = errors.SszError;

// Merkleize will do something like this:
//
//      ROOT
//     /    \
//   H0      H1
//  / \      / \
// A   B    C   D
pub fn Merkleize(
    allocator: std.mem.Allocator,
    chunks: []const [32]u8,
    limit: ?usize,
) (std.mem.Allocator.Error || SszError)![32]u8 {
    const count = chunks.len;

    // A capacity sets the tree width instead, rounded up to a power of two.
    const width = if (limit) |l| blk: {
        if (l < count) return error.MerkleizeLimit;
        break :blk nextPow2(l);
    } else nextPow2(count);

    // No data under a capacity roots to that width's zero tree.
    if (count == 0) {
        if (limit != null) return zeroTreeRoot(width);
        return [_]u8{0} ** 32;
    }

    if (width == 1) {
        return chunks[0];
    }

    var level = try allocator.alloc([32]u8, width);
    defer allocator.free(level);

    @memset(level, [_]u8{0} ** 32);

    for (chunks, 0..) |chunk, i| {
        level[i] = chunk;
    }

    var current_len = width;

    while (current_len > 1) {
        var i: usize = 0;
        var parent: usize = 0;

        while (i < current_len) : ({
            i += 2;
            parent += 1;
        }) {
            var input: [64]u8 = undefined;

            @memcpy(input[0..32], &level[i]);
            @memcpy(input[32..64], &level[i + 1]);

            // block is taking two 32-byte child nodes and hashing them into one 32-byte parent node
            // done compress many leaves into one cryptographic commitment
            std.crypto.hash.sha2.Sha256.hash(
                &input,
                &level[parent],
                .{},
            );
        }

        current_len /= 2;
    }

    return level[0];
}

/// Smallest power of two greater than or equal to x. Returns 1 for 0.
fn nextPow2(x: usize) usize {
    if (x <= 1) return 1;
    return std.math.ceilPowerOfTwo(usize, x) catch unreachable;
}

/// Root of the all-zero perfect binary tree spanning `width` leaves.
/// `width` must be a power of two.
fn zeroTreeRoot(width: usize) [32]u8 {
    var node = [_]u8{0} ** 32;
    var n = width;
    while (n > 1) : (n /= 2) {
        var input: [64]u8 = undefined;
        @memcpy(input[0..32], &node);
        @memcpy(input[32..64], &node);
        std.crypto.hash.sha2.Sha256.hash(&input, &node, .{});
    }
    return node;
}
