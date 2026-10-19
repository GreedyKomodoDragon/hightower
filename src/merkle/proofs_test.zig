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
