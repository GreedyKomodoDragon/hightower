const std = @import("std");
const testing = std.testing;

const merkle = @import("chunking.zig");

test "MerkleizeChunks u8 produces one padded chunk" {
    const allocator = std.testing.allocator;
    const chunks = try merkle.Chunk(allocator, @as(u8, 0x2a));
    defer allocator.free(chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);

    const expected = [_]u8{
        0x2a,
    } ++ [_]u8{0} ** 31;

    try testing.expectEqualSlices(
        u8,
        &expected,
        &chunks[0],
    );
}

test "MerkleizeChunks u16 uses little endian and padding" {
    const allocator = std.testing.allocator;
    const chunks = try merkle.Chunk(allocator, @as(u16, 0x1234));
    defer allocator.free(chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);

    var expected = [_]u8{0} ** 32;
    expected[0] = 0x34;
    expected[1] = 0x12;

    try testing.expectEqualSlices(
        u8,
        &expected,
        &chunks[0],
    );
}

test "MerkleizeChunks u64 uses one chunk" {
    const allocator = std.testing.allocator;
    const chunks = try merkle.Chunk(allocator, @as(u64, 1));
    defer allocator.free(chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);

    var expected = [_]u8{0} ** 32;
    expected[0] = 0x01;

    try testing.expectEqualSlices(
        u8,
        &expected,
        &chunks[0],
    );
}

test "MerkleizeChunks true produces 0x01 followed by zeroes" {
    const allocator = std.testing.allocator;
    const chunks = try merkle.Chunk(allocator, true);
    defer allocator.free(chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);

    var expected = [_]u8{0} ** 32;
    expected[0] = 0x01;

    try testing.expectEqualSlices(
        u8,
        &expected,
        &chunks[0],
    );
}

test "MerkleizeChunks false produces zero chunk" {
    const allocator = std.testing.allocator;
    const chunks = try merkle.Chunk(allocator, false);
    defer allocator.free(chunks);

    try testing.expectEqual(@as(usize, 1), chunks.len);

    const expected = [_]u8{0} ** 32;

    try testing.expectEqualSlices(
        u8,
        &expected,
        &chunks[0],
    );
}
