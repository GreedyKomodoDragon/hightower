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

test "Chunk packs short u8 array into one chunk" {
    const allocator = testing.allocator;

    const value = [_]u8{
        13,
        45,
        67,
    };

    const chunks = try merkle.Chunk(allocator, value);
    defer allocator.free(chunks);

    try testing.expectEqual(
        @as(usize, 1),
        chunks.len,
    );

    var expected = [_]u8{0} ** 32;
    expected[0] = 13;
    expected[1] = 45;
    expected[2] = 67;

    try testing.expectEqualSlices(
        u8,
        &expected,
        &chunks[0],
    );
}

test "Chunk packs exactly 32 u8 values into one chunk" {
    const allocator = testing.allocator;

    var value: [32]u8 = undefined;

    for (&value, 0..) |*item, i| {
        item.* = @intCast(i);
    }

    const chunks = try merkle.Chunk(allocator, value);
    defer allocator.free(chunks);

    try testing.expectEqual(
        @as(usize, 1),
        chunks.len,
    );

    try testing.expectEqualSlices(
        u8,
        &value,
        &chunks[0],
    );
}

test "Chunk splits 33 u8 values across two chunks" {
    const allocator = testing.allocator;

    var value: [33]u8 = undefined;

    for (&value, 0..) |*item, i| {
        item.* = @intCast(i + 1);
    }

    const chunks = try merkle.Chunk(allocator, value);
    defer allocator.free(chunks);

    try testing.expectEqual(
        @as(usize, 2),
        chunks.len,
    );

    try testing.expectEqualSlices(
        u8,
        value[0..32],
        &chunks[0],
    );

    var expected_second = [_]u8{0} ** 32;
    expected_second[0] = 33;

    try testing.expectEqualSlices(
        u8,
        &expected_second,
        &chunks[1],
    );
}
