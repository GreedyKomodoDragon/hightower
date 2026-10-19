//! SSZ generalized indices identify nodes in a binary Merkle tree: the root
//! is 1, and each node's children are `2*i` and `2*i+1`. A proof folds sibling
//! roots upward in leaf-to-root order; left/right ordering determines the hash.
//!
//!          1
//!        /   \
//!       2     3
//!      / \   / \
//!     4   5 6   7
//!
//! This API uses u64 indices (maximum depth 63), rejects zero/overflow indices,
//! and verifies roots without modifying consensus state.

const std = @import("std");

pub const GeneralizedIndex = u64;
pub const ProofError = error{
    InvalidGeneralizedIndex,
    GeneralizedIndexOverflow,
};

pub fn generalizedIndexLength(index: GeneralizedIndex) ProofError!usize {
    if (index == 0) return error.InvalidGeneralizedIndex;
    return @bitSizeOf(GeneralizedIndex) - @clz(index) - 1;
}

/// Positions count upward from the least significant bit (the leaf's edge).
pub fn generalizedIndexBit(index: GeneralizedIndex, position: usize) ProofError!bool {
    const depth = try generalizedIndexLength(index);
    if (position >= depth) return error.InvalidGeneralizedIndex;
    return (index & (@as(GeneralizedIndex, 1) << @intCast(position))) != 0;
}

pub fn generalizedIndexSibling(index: GeneralizedIndex) ProofError!GeneralizedIndex {
    if (index == 0) return error.InvalidGeneralizedIndex;
    const sibling = index ^ 1;
    if (sibling == 0) return error.InvalidGeneralizedIndex;
    return sibling;
}

pub fn generalizedIndexChild(index: GeneralizedIndex, right_side: bool) ProofError!GeneralizedIndex {
    if (index == 0) return error.InvalidGeneralizedIndex;
    const doubled = std.math.mul(GeneralizedIndex, index, 2) catch
        return error.GeneralizedIndexOverflow;
    return std.math.add(GeneralizedIndex, doubled, @intFromBool(right_side)) catch
        return error.GeneralizedIndexOverflow;
}

pub fn generalizedIndexParent(index: GeneralizedIndex) ProofError!GeneralizedIndex {
    if (index <= 1) return error.InvalidGeneralizedIndex;
    return index / 2;
}

/// Returns helper-node indices in the descending order used by SSZ multiproofs.
pub fn getHelperIndices(
    allocator: std.mem.Allocator,
    indices: []const GeneralizedIndex,
) (std.mem.Allocator.Error || ProofError)![]GeneralizedIndex {
    if (indices.len == 0) return error.InvalidGeneralizedIndex;

    const sorted_indices = try allocator.dupe(GeneralizedIndex, indices);
    defer allocator.free(sorted_indices);
    std.mem.sort(GeneralizedIndex, sorted_indices, {}, lessThan);
    for (sorted_indices, 0..) |index, i| {
        if (index == 0 or (i > 0 and sorted_indices[i - 1] == index)) {
            return error.InvalidGeneralizedIndex;
        }
        var ancestor = index / 2;
        while (ancestor > 0) : (ancestor /= 2) {
            if (containsSorted(sorted_indices, ancestor)) return error.InvalidGeneralizedIndex;
        }
    }

    var paths: std.ArrayList(GeneralizedIndex) = .empty;
    defer paths.deinit(allocator);
    var branches: std.ArrayList(GeneralizedIndex) = .empty;
    defer branches.deinit(allocator);

    for (indices) |index| {
        var node = index;
        while (true) {
            try paths.append(allocator, node);
            if (node == 1) break;
            try branches.append(allocator, node ^ 1);
            node /= 2;
        }
    }

    std.mem.sort(GeneralizedIndex, paths.items, {}, lessThan);
    std.mem.sort(GeneralizedIndex, branches.items, {}, lessThan);
    const unique_paths = uniqueSorted(paths.items);
    const unique_branches = uniqueSorted(branches.items);

    var helpers: std.ArrayList(GeneralizedIndex) = .empty;
    errdefer helpers.deinit(allocator);
    for (unique_branches) |branch| {
        if (!containsSorted(unique_paths, branch)) try helpers.append(allocator, branch);
    }
    std.mem.sort(GeneralizedIndex, helpers.items, {}, greaterThan);
    return try helpers.toOwnedSlice(allocator);
}

pub fn verifyMerkleProof(
    leaf: [32]u8,
    proof: []const [32]u8,
    index: GeneralizedIndex,
    root: [32]u8,
) bool {
    const depth = generalizedIndexLength(index) catch return false;
    if (proof.len != depth) return false;

    var node = leaf;
    for (proof, 0..) |sibling, position| {
        const is_right = generalizedIndexBit(index, position) catch return false;
        node = if (is_right) hashPair(sibling, node) else hashPair(node, sibling);
    }
    return std.mem.eql(u8, &node, &root);
}

pub fn verifyMerkleMultiproof(
    allocator: std.mem.Allocator,
    leaves: []const [32]u8,
    proof: []const [32]u8,
    indices: []const GeneralizedIndex,
    root: [32]u8,
) std.mem.Allocator.Error!bool {
    if (leaves.len == 0 or leaves.len != indices.len) return false;
    const helper_indices = getHelperIndices(allocator, indices) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return false,
    };
    defer allocator.free(helper_indices);
    if (proof.len != helper_indices.len) return false;

    const capacity = std.math.add(usize, leaves.len, proof.len) catch return false;
    var current = try allocator.alloc(Node, capacity);
    defer allocator.free(current);
    var next = try allocator.alloc(Node, capacity);
    defer allocator.free(next);

    for (indices, leaves, 0..) |index, value, i| current[i] = .{ .index = index, .root = value };
    for (helper_indices, proof, 0..) |index, value, i| {
        current[leaves.len + i] = .{ .index = index, .root = value };
    }

    var count = capacity;
    while (count > 1) {
        std.mem.sort(Node, current[0..count], {}, nodeGreaterThan);
        var read: usize = 0;
        var written: usize = 0;
        var merged = false;
        while (read < count) {
            if (read + 1 < count and current[read].index ^ 1 == current[read + 1].index) {
                const left = if (current[read].index & 1 == 0) current[read] else current[read + 1];
                const right = if (current[read].index & 1 == 1) current[read] else current[read + 1];
                next[written] = .{ .index = left.index / 2, .root = hashPair(left.root, right.root) };
                read += 2;
                merged = true;
            } else {
                next[written] = current[read];
                read += 1;
            }
            written += 1;
        }
        if (!merged) return false;
        const swap = current;
        current = next;
        next = swap;
        count = written;
    }
    return current[0].index == 1 and std.mem.eql(u8, &current[0].root, &root);
}

const Node = struct {
    index: GeneralizedIndex,
    root: [32]u8,
};

fn lessThan(_: void, left: GeneralizedIndex, right: GeneralizedIndex) bool {
    return left < right;
}

fn greaterThan(_: void, left: GeneralizedIndex, right: GeneralizedIndex) bool {
    return left > right;
}

fn nodeGreaterThan(_: void, left: Node, right: Node) bool {
    return left.index > right.index;
}

fn uniqueSorted(values: []GeneralizedIndex) []const GeneralizedIndex {
    if (values.len == 0) return values;
    var written: usize = 1;
    for (values[1..]) |value| {
        if (value != values[written - 1]) {
            values[written] = value;
            written += 1;
        }
    }
    return values[0..written];
}

fn containsSorted(values: []const GeneralizedIndex, target: GeneralizedIndex) bool {
    return std.sort.binarySearch(GeneralizedIndex, values, target, compareToTarget) != null;
}

fn compareToTarget(target: GeneralizedIndex, value: GeneralizedIndex) std.math.Order {
    return std.math.order(target, value);
}

fn hashPair(left: [32]u8, right: [32]u8) [32]u8 {
    var input: [64]u8 = undefined;
    @memcpy(input[0..32], &left);
    @memcpy(input[32..64], &right);
    var output: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&input, &output, .{});
    return output;
}
