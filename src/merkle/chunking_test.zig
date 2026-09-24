const std = @import("std");
const testing = std.testing;

const merkle = @import("chunking.zig");

test "MerkleizeChunks u8 produces one padded chunk" {
    const allocator = std.testing.allocator;
    const chunks = try merkle.GetChunks(allocator, @as(u8, 0x2a));
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
    const chunks = try merkle.GetChunks(allocator, @as(u16, 0x1234));
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
    const chunks = try merkle.GetChunks(allocator, @as(u64, 1));
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
    const chunks = try merkle.GetChunks(allocator, true);
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
    const chunks = try merkle.GetChunks(allocator, false);
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

    const chunks = try merkle.GetChunks(allocator, value);
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

    const chunks = try merkle.GetChunks(allocator, value);
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

    const chunks = try merkle.GetChunks(allocator, value);
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

test "container fields each become one 32-byte root" {
    const allocator = testing.allocator;

    const Example = struct {
        a: u64,
        b: bool,
    };

    const value = Example{
        .a = 5,
        .b = true,
    };

    const chunks = try merkle.GetChunks(
        allocator,
        value,
    );
    defer allocator.free(chunks);

    try testing.expectEqual(
        @as(usize, 2),
        chunks.len,
    );

    var expected_a = [_]u8{0} ** 32;
    expected_a[0] = 0x05;

    var expected_b = [_]u8{0} ** 32;
    expected_b[0] = 0x01;

    try testing.expectEqualSlices(
        u8,
        &expected_a,
        &chunks[0],
    );

    try testing.expectEqualSlices(
        u8,
        &expected_b,
        &chunks[1],
    );
}

test "GetChunks simple struct produces one root per field" {
    const allocator = testing.allocator;

    const Example = struct {
        a: u64,
        b: bool,
    };

    const value = Example{
        .a = 5,
        .b = true,
    };

    const chunks = try merkle.GetChunks(allocator, value);
    defer allocator.free(chunks);

    try testing.expectEqual(
        @as(usize, 2),
        chunks.len,
    );

    const expected_a = try merkle.HashTreeRoot(
        allocator,
        value.a,
    );

    const expected_b = try merkle.HashTreeRoot(
        allocator,
        value.b,
    );

    try testing.expectEqualSlices(
        u8,
        &expected_a,
        &chunks[0],
    );

    try testing.expectEqualSlices(
        u8,
        &expected_b,
        &chunks[1],
    );
}

test "GetChunks preserves struct field order" {
    const allocator = testing.allocator;

    const Example = struct {
        first: u16,
        second: u32,
        third: bool,
    };

    const value = Example{
        .first = 0x1234,
        .second = 0x55667788,
        .third = true,
    };

    const chunks = try merkle.GetChunks(allocator, value);
    defer allocator.free(chunks);

    try testing.expectEqual(
        @as(usize, 3),
        chunks.len,
    );

    const first_root = try merkle.HashTreeRoot(
        allocator,
        value.first,
    );

    const second_root = try merkle.HashTreeRoot(
        allocator,
        value.second,
    );

    const third_root = try merkle.HashTreeRoot(
        allocator,
        value.third,
    );

    try testing.expectEqualSlices(
        u8,
        &first_root,
        &chunks[0],
    );

    try testing.expectEqualSlices(
        u8,
        &second_root,
        &chunks[1],
    );

    try testing.expectEqualSlices(
        u8,
        &third_root,
        &chunks[2],
    );
}

test "GetChunks nested struct uses nested root as one field chunk" {
    const allocator = testing.allocator;

    const Inner = struct {
        x: u64,
        enabled: bool,
    };

    const Outer = struct {
        slot: u64,
        inner: Inner,
    };

    const value = Outer{
        .slot = 42,
        .inner = .{
            .x = 99,
            .enabled = true,
        },
    };

    const chunks = try merkle.GetChunks(allocator, value);
    defer allocator.free(chunks);

    try testing.expectEqual(
        @as(usize, 2),
        chunks.len,
    );

    const expected_slot = try merkle.HashTreeRoot(
        allocator,
        value.slot,
    );

    const expected_inner = try merkle.HashTreeRoot(
        allocator,
        value.inner,
    );

    try testing.expectEqualSlices(
        u8,
        &expected_slot,
        &chunks[0],
    );

    try testing.expectEqualSlices(
        u8,
        &expected_inner,
        &chunks[1],
    );
}

test "GetChunks deeply nested struct" {
    const allocator = testing.allocator;

    const Level3 = struct {
        value: u16,
        flag: bool,
    };

    const Level2 = struct {
        count: u32,
        inner: Level3,
    };

    const Level1 = struct {
        slot: u64,
        inner: Level2,
    };

    const value = Level1{
        .slot = 1,
        .inner = .{
            .count = 2,
            .inner = .{
                .value = 3,
                .flag = true,
            },
        },
    };

    const chunks = try merkle.GetChunks(allocator, value);
    defer allocator.free(chunks);

    try testing.expectEqual(
        @as(usize, 2),
        chunks.len,
    );

    const expected_slot = try merkle.HashTreeRoot(
        allocator,
        value.slot,
    );

    const expected_inner = try merkle.HashTreeRoot(
        allocator,
        value.inner,
    );

    try testing.expectEqualSlices(
        u8,
        &expected_slot,
        &chunks[0],
    );

    try testing.expectEqualSlices(
        u8,
        &expected_inner,
        &chunks[1],
    );
}

test "GetChunks struct containing fixed byte array" {
    const allocator = testing.allocator;

    const Example = struct {
        slot: u64,
        root: [32]u8,
    };

    var root = [_]u8{0} ** 32;
    root[0] = 0xaa;
    root[31] = 0xff;

    const value = Example{
        .slot = 7,
        .root = root,
    };

    const chunks = try merkle.GetChunks(allocator, value);
    defer allocator.free(chunks);

    try testing.expectEqual(
        @as(usize, 2),
        chunks.len,
    );

    const expected_slot = try merkle.HashTreeRoot(
        allocator,
        value.slot,
    );

    const expected_root = try merkle.HashTreeRoot(
        allocator,
        value.root,
    );

    try testing.expectEqualSlices(
        u8,
        &expected_slot,
        &chunks[0],
    );

    try testing.expectEqualSlices(
        u8,
        &expected_root,
        &chunks[1],
    );
}

test "GetChunks struct containing basic integer array" {
    const allocator = testing.allocator;

    const Example = struct {
        epoch: u64,
        balances: [5]u64,
    };

    const value = Example{
        .epoch = 10,
        .balances = .{
            100,
            200,
            300,
            400,
            500,
        },
    };

    const chunks = try merkle.GetChunks(allocator, value);
    defer allocator.free(chunks);

    try testing.expectEqual(
        @as(usize, 2),
        chunks.len,
    );

    const epoch_root = try merkle.HashTreeRoot(
        allocator,
        value.epoch,
    );

    const balances_root = try merkle.HashTreeRoot(
        allocator,
        value.balances,
    );

    try testing.expectEqualSlices(
        u8,
        &epoch_root,
        &chunks[0],
    );

    try testing.expectEqualSlices(
        u8,
        &balances_root,
        &chunks[1],
    );
}

test "GetChunks struct containing array of structs" {
    const allocator = testing.allocator;

    const Item = struct {
        id: u64,
        enabled: bool,
    };

    const Example = struct {
        count: u16,
        items: [2]Item,
    };

    const value = Example{
        .count = 2,
        .items = .{
            .{
                .id = 100,
                .enabled = true,
            },
            .{
                .id = 200,
                .enabled = false,
            },
        },
    };

    const chunks = try merkle.GetChunks(allocator, value);
    defer allocator.free(chunks);

    try testing.expectEqual(
        @as(usize, 2),
        chunks.len,
    );

    const count_root = try merkle.HashTreeRoot(
        allocator,
        value.count,
    );

    const items_root = try merkle.HashTreeRoot(
        allocator,
        value.items,
    );

    try testing.expectEqualSlices(
        u8,
        &count_root,
        &chunks[0],
    );

    try testing.expectEqualSlices(
        u8,
        &items_root,
        &chunks[1],
    );
}

test "GetChunks array of structs produces one root per element" {
    const allocator = testing.allocator;

    const Item = struct {
        value: u64,
        flag: bool,
    };

    const value = [_]Item{
        .{
            .value = 1,
            .flag = true,
        },
        .{
            .value = 2,
            .flag = false,
        },
        .{
            .value = 3,
            .flag = true,
        },
    };

    const chunks = try merkle.GetChunks(allocator, value);
    defer allocator.free(chunks);

    try testing.expectEqual(
        @as(usize, 3),
        chunks.len,
    );

    inline for (value, 0..) |item, i| {
        const expected = try merkle.HashTreeRoot(
            allocator,
            item,
        );

        try testing.expectEqualSlices(
            u8,
            &expected,
            &chunks[i],
        );
    }
}

test "GetChunks nested struct with two nested children" {
    const allocator = testing.allocator;

    const Child = struct {
        number: u32,
        active: bool,
    };

    const Parent = struct {
        left: Child,
        right: Child,
    };

    const value = Parent{
        .left = .{
            .number = 10,
            .active = true,
        },
        .right = .{
            .number = 20,
            .active = false,
        },
    };

    const chunks = try merkle.GetChunks(allocator, value);
    defer allocator.free(chunks);

    try testing.expectEqual(
        @as(usize, 2),
        chunks.len,
    );

    const left_root = try merkle.HashTreeRoot(
        allocator,
        value.left,
    );

    const right_root = try merkle.HashTreeRoot(
        allocator,
        value.right,
    );

    try testing.expectEqualSlices(
        u8,
        &left_root,
        &chunks[0],
    );

    try testing.expectEqualSlices(
        u8,
        &right_root,
        &chunks[1],
    );
}

test "GetChunks ethereum-like checkpoint container" {
    const allocator = testing.allocator;

    const Checkpoint = struct {
        epoch: u64,
        root: [32]u8,
    };

    var root = [_]u8{0} ** 32;
    root[0] = 0xde;
    root[1] = 0xad;

    const value = Checkpoint{
        .epoch = 123,
        .root = root,
    };

    const chunks = try merkle.GetChunks(
        allocator,
        value,
    );
    defer allocator.free(chunks);

    try testing.expectEqual(
        @as(usize, 2),
        chunks.len,
    );

    const epoch_root = try merkle.HashTreeRoot(
        allocator,
        value.epoch,
    );

    const root_root = try merkle.HashTreeRoot(
        allocator,
        value.root,
    );

    try testing.expectEqualSlices(
        u8,
        &epoch_root,
        &chunks[0],
    );

    try testing.expectEqualSlices(
        u8,
        &root_root,
        &chunks[1],
    );
}

test "GetChunks ethereum-like nested attestation data" {
    const allocator = testing.allocator;

    const Checkpoint = struct {
        epoch: u64,
        root: [32]u8,
    };

    const AttestationData = struct {
        slot: u64,
        index: u64,
        beacon_block_root: [32]u8,
        source: Checkpoint,
        target: Checkpoint,
    };

    var block_root = [_]u8{0} ** 32;
    block_root[0] = 0xaa;

    var source_root = [_]u8{0} ** 32;
    source_root[0] = 0xbb;

    var target_root = [_]u8{0} ** 32;
    target_root[0] = 0xcc;

    const value = AttestationData{
        .slot = 10,
        .index = 2,
        .beacon_block_root = block_root,
        .source = .{
            .epoch = 3,
            .root = source_root,
        },
        .target = .{
            .epoch = 4,
            .root = target_root,
        },
    };

    const chunks = try merkle.GetChunks(
        allocator,
        value,
    );
    defer allocator.free(chunks);

    try testing.expectEqual(
        @as(usize, 5),
        chunks.len,
    );

    const slot_root = try merkle.HashTreeRoot(
        allocator,
        value.slot,
    );

    const index_root = try merkle.HashTreeRoot(
        allocator,
        value.index,
    );

    const block_root_root = try merkle.HashTreeRoot(
        allocator,
        value.beacon_block_root,
    );

    const source_checkpoint_root = try merkle.HashTreeRoot(
        allocator,
        value.source,
    );

    const target_checkpoint_root = try merkle.HashTreeRoot(
        allocator,
        value.target,
    );

    try testing.expectEqualSlices(
        u8,
        &slot_root,
        &chunks[0],
    );

    try testing.expectEqualSlices(
        u8,
        &index_root,
        &chunks[1],
    );

    try testing.expectEqualSlices(
        u8,
        &block_root_root,
        &chunks[2],
    );

    try testing.expectEqualSlices(
        u8,
        &source_checkpoint_root,
        &chunks[3],
    );

    try testing.expectEqualSlices(
        u8,
        &target_checkpoint_root,
        &chunks[4],
    );
}
