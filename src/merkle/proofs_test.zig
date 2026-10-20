const std = @import("std");
const testing = std.testing;
const merkle = @import("chunking.zig");

fn hashPair(left: [32]u8, right: [32]u8) [32]u8 {
    var input: [64]u8 = undefined;
    @memcpy(input[0..32], &left);
    @memcpy(input[32..64], &right);
    var output: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&input, &output, .{});
    return output;
}

test "generalized-index helpers match SSZ examples and reject invalid indices" {
    try testing.expectEqual(@as(usize, 3), try merkle.generalizedIndexLength(8));
    try testing.expect(try merkle.generalizedIndexBit(5, 0));
    try testing.expect(!(try merkle.generalizedIndexBit(5, 1)));
    try testing.expectEqual(@as(u64, 5), try merkle.generalizedIndexSibling(4));
    try testing.expectEqual(@as(u64, 5), try merkle.generalizedIndexChild(2, true));
    try testing.expectEqual(@as(u64, 2), try merkle.generalizedIndexParent(5));
    try testing.expectError(error.InvalidGeneralizedIndex, merkle.generalizedIndexLength(0));
    try testing.expectError(error.InvalidGeneralizedIndex, merkle.generalizedIndexParent(1));
    try testing.expectError(error.GeneralizedIndexOverflow, merkle.generalizedIndexChild(std.math.maxInt(u64), true));
}

test "single Merkle proof verifies leaf-to-root branches and rejects malformed proofs" {
    const a = [_]u8{0x11} ** 32;
    const b = [_]u8{0x22} ** 32;
    const c = [_]u8{0x33} ** 32;
    const d = [_]u8{0x44} ** 32;
    const left = hashPair(a, b);
    const right = hashPair(c, d);
    const root = hashPair(left, right);
    const proof = [_][32]u8{ d, left };

    try testing.expect(merkle.verifyMerkleProof(c, &proof, 6, root));
    try testing.expect(!merkle.verifyMerkleProof(c, proof[0..1], 6, root));
    try testing.expect(!merkle.verifyMerkleProof(c, &proof, 0, root));
    try testing.expect(!merkle.verifyMerkleProof(a, &proof, 6, root));
}

test "multiproof helper indices and verification match SSZ ordering" {
    const a = [_]u8{0x11} ** 32;
    const b = [_]u8{0x22} ** 32;
    const c = [_]u8{0x33} ** 32;
    const d = [_]u8{0x44} ** 32;
    const left = hashPair(a, b);
    const right = hashPair(c, d);
    const root = hashPair(left, right);
    const indices = [_]u64{ 4, 6 };
    const leaves = [_][32]u8{ a, c };
    const proof = [_][32]u8{ d, b };

    const helpers = try merkle.getHelperIndices(testing.allocator, &indices);
    defer testing.allocator.free(helpers);
    try testing.expectEqualSlices(u64, &.{ 7, 5 }, helpers);
    try testing.expect(try merkle.verifyMerkleMultiproof(testing.allocator, &leaves, &proof, &indices, root));
    try testing.expect(!try merkle.verifyMerkleMultiproof(testing.allocator, &leaves, proof[0..1], &indices, root));
    try testing.expect(!try merkle.verifyMerkleMultiproof(testing.allocator, &leaves, &proof, &.{ 4, 4 }, root));
    try testing.expect(!try merkle.verifyMerkleMultiproof(testing.allocator, &leaves, &proof, &.{ 2, 4 }, root));
}

test "multiproof matches the consensus spec example for indices 8, 9, and 14" {
    var leaves: [8][32]u8 = undefined;
    for (&leaves, 0..) |*leaf, i| leaf.* = [_]u8{@intCast(i + 1)} ** 32;

    const level_one = [_][32]u8{
        hashPair(leaves[0], leaves[1]),
        hashPair(leaves[2], leaves[3]),
        hashPair(leaves[4], leaves[5]),
        hashPair(leaves[6], leaves[7]),
    };
    const level_two = [_][32]u8{
        hashPair(level_one[0], level_one[1]),
        hashPair(level_one[2], level_one[3]),
    };
    const root = hashPair(level_two[0], level_two[1]);
    const indices = [_]u64{ 8, 9, 14 };
    const proof = [_][32]u8{
        leaves[7],
        level_one[2],
        level_one[1],
    };
    const proved_leaves = [_][32]u8{ leaves[0], leaves[1], leaves[6] };

    const helpers = try merkle.getHelperIndices(testing.allocator, &indices);
    defer testing.allocator.free(helpers);
    try testing.expectEqualSlices(u64, &.{ 15, 6, 5 }, helpers);
    try testing.expect(try merkle.verifyMerkleMultiproof(
        testing.allocator,
        &proved_leaves,
        &proof,
        &indices,
        root,
    ));
    try testing.expect(!try merkle.verifyMerkleMultiproof(
        testing.allocator,
        &proved_leaves,
        &proof,
        &indices,
        [_]u8{0xff} ** 32,
    ));
}
