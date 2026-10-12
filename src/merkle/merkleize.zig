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

    const populated_width = nextPow2(count);
    var level = try allocator.alloc([32]u8, populated_width);
    defer allocator.free(level);

    @memset(level, [_]u8{0} ** 32);

    for (chunks, 0..) |chunk, i| {
        level[i] = chunk;
    }

    var current_len = populated_width;

    while (current_len > 1) {
        var i: usize = 0;
        var parent: usize = 0;

        while (i < current_len) : ({
            i += 2;
            parent += 1;
        }) {
            level[parent] = hashPair(level[i], level[i + 1]);
        }

        current_len /= 2;
    }

    var root = level[0];
    var subtree_width = populated_width;
    while (subtree_width < width) : (subtree_width *= 2) {
        root = hashPair(root, zeroTreeRoot(subtree_width));
    }
    return root;
}

fn hashPair(left: [32]u8, right: [32]u8) [32]u8 {
    var input: [64]u8 = undefined;
    @memcpy(input[0..32], &left);
    @memcpy(input[32..64], &right);
    var root: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&input, &root, .{});
    return root;
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
