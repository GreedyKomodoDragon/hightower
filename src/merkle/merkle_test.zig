const std = @import("std");
const testing = std.testing;

const merkle = @import("chunking.zig");

fn hashPair(left: [32]u8, right: [32]u8) [32]u8 {
    var input: [64]u8 = undefined;

    @memcpy(input[0..32], &left);
    @memcpy(input[32..64], &right);

    var out: [32]u8 = undefined;

    std.crypto.hash.sha2.Sha256.hash(
        &input,
        &out,
        .{},
    );

    return out;
}

test "Merkleize one chunk returns chunk unchanged" {
    const allocator = testing.allocator;

    const a = [_]u8{0x11} ** 32;

    const root = try merkle.Merkleize(
        allocator,
        &.{a},
    );

    try testing.expectEqualSlices(
        u8,
        &a,
        &root,
    );
}

test "Merkleize two chunks hashes pair" {
    const allocator = testing.allocator;

    const a = [_]u8{0x11} ** 32;
    const b = [_]u8{0x22} ** 32;

    const expected = hashPair(a, b);

    const root = try merkle.Merkleize(
        allocator,
        &.{ a, b },
    );

    try testing.expectEqualSlices(
        u8,
        &expected,
        &root,
    );
}

test "Merkleize three chunks pads fourth leaf with zero chunk" {
    const allocator = testing.allocator;

    const a = [_]u8{0x11} ** 32;
    const b = [_]u8{0x22} ** 32;
    const c = [_]u8{0x33} ** 32;
    const zero = [_]u8{0} ** 32;

    const left = hashPair(a, b);
    const right = hashPair(c, zero);

    const expected = hashPair(left, right);

    const root = try merkle.Merkleize(
        allocator,
        &.{ a, b, c },
    );

    try testing.expectEqualSlices(
        u8,
        &expected,
        &root,
    );
}

test "Merkleize four chunks builds two tree levels" {
    const allocator = testing.allocator;

    const a = [_]u8{0x11} ** 32;
    const b = [_]u8{0x22} ** 32;
    const c = [_]u8{0x33} ** 32;
    const d = [_]u8{0x44} ** 32;

    const left = hashPair(a, b);
    const right = hashPair(c, d);

    const expected = hashPair(left, right);

    const root = try merkle.Merkleize(
        allocator,
        &.{ a, b, c, d },
    );

    try testing.expectEqualSlices(
        u8,
        &expected,
        &root,
    );
}

test "Merkleize five chunks pads tree to eight leaves" {
    const allocator = testing.allocator;

    const a = [_]u8{0x11} ** 32;
    const b = [_]u8{0x22} ** 32;
    const c = [_]u8{0x33} ** 32;
    const d = [_]u8{0x44} ** 32;
    const e = [_]u8{0x55} ** 32;
    const zero = [_]u8{0} ** 32;

    // First level
    const h0 = hashPair(a, b);
    const h1 = hashPair(c, d);
    const h2 = hashPair(e, zero);
    const h3 = hashPair(zero, zero);

    // Second level
    const h4 = hashPair(h0, h1);
    const h5 = hashPair(h2, h3);

    // Root
    const expected = hashPair(h4, h5);

    const root = try merkle.Merkleize(
        allocator,
        &.{ a, b, c, d, e },
    );

    try testing.expectEqualSlices(
        u8,
        &expected,
        &root,
    );
}
