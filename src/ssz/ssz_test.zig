const std = @import("std");
const ssz = @import("ssz");
const testing = std.testing;

test "SSZ encodes fixed-size container" {
    const Example = struct {
        count: u16,
        slot: u64,
    };

    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const value = Example{
        .count = 0x1234,
        .slot = 1,
    };

    try ssz.serialize(&writer, value);

    try testing.expectEqualSlices(
        u8,
        &.{
            0x34, 0x12,
            0x01, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
        },
        writer.buffered(),
    );
}

test "SSZ encodes u8" {
    var buf: [16]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try ssz.serialize(&writer, @as(u8, 0x7f));

    try testing.expectEqualSlices(
        u8,
        &.{0x7f},
        writer.buffered(),
    );
}

test "SSZ encodes u16 little endian" {
    var buf: [16]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try ssz.serialize(&writer, @as(u16, 0x1234));

    try testing.expectEqualSlices(
        u8,
        &.{ 0x34, 0x12 },
        writer.buffered(),
    );
}

test "SSZ encodes u32 little endian" {
    var buf: [16]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try ssz.serialize(&writer, @as(u32, 0x12345678));

    try testing.expectEqualSlices(
        u8,
        &.{ 0x78, 0x56, 0x34, 0x12 },
        writer.buffered(),
    );
}

test "SSZ encodes u64 little endian" {
    var buf: [16]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try ssz.serialize(&writer, @as(u64, 0x0102030405060708));

    try testing.expectEqualSlices(
        u8,
        &.{
            0x08, 0x07, 0x06, 0x05,
            0x04, 0x03, 0x02, 0x01,
        },
        writer.buffered(),
    );
}

test "SSZ encodes zero u64 as eight zero bytes" {
    var buf: [16]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try ssz.serialize(&writer, @as(u64, 0));

    try testing.expectEqualSlices(
        u8,
        &.{
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        },
        writer.buffered(),
    );
}

test "SSZ encodes max u16" {
    var buf: [16]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try ssz.serialize(&writer, @as(u16, 0xffff));

    try testing.expectEqualSlices(
        u8,
        &.{ 0xff, 0xff },
        writer.buffered(),
    );
}

test "SSZ encodes fixed byte array exactly" {
    var buf: [16]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const value = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };

    try ssz.serialize(&writer, value);

    try testing.expectEqualSlices(
        u8,
        &.{ 0xaa, 0xbb, 0xcc, 0xdd },
        writer.buffered(),
    );
}

test "SSZ encodes zero-length fixed byte array" {
    var buf: [16]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const value = [_]u8{};

    try ssz.serialize(&writer, value);

    try testing.expectEqualSlices(
        u8,
        &.{},
        writer.buffered(),
    );
}

test "SSZ encodes array of u16 values" {
    var buf: [32]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const value = [_]u16{
        0x1234,
        0xabcd,
    };

    try ssz.serialize(&writer, value);

    try testing.expectEqualSlices(
        u8,
        &.{
            0x34, 0x12,
            0xcd, 0xab,
        },
        writer.buffered(),
    );
}

test "SSZ encodes array of u32 values" {
    var buf: [32]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const value = [_]u32{
        1,
        2,
        3,
    };

    try ssz.serialize(&writer, value);

    try testing.expectEqualSlices(
        u8,
        &.{
            0x01, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00,
        },
        writer.buffered(),
    );
}

test "SSZ encodes simple fixed-size container" {
    const Example = struct {
        count: u16,
        slot: u64,
    };

    var buf: [32]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const value = Example{
        .count = 0x1234,
        .slot = 1,
    };

    try ssz.serialize(&writer, value);

    try testing.expectEqualSlices(
        u8,
        &.{
            0x34, 0x12,
            0x01, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
        },
        writer.buffered(),
    );
}

test "SSZ container field order matters" {
    const Example = struct {
        a: u8,
        b: u16,
        c: u32,
    };

    var buf: [32]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const value = Example{
        .a = 0xaa,
        .b = 0x1234,
        .c = 0x01020304,
    };

    try ssz.serialize(&writer, value);

    try testing.expectEqualSlices(
        u8,
        &.{
            0xaa,
            0x34,
            0x12,
            0x04,
            0x03,
            0x02,
            0x01,
        },
        writer.buffered(),
    );
}

test "SSZ encodes nested fixed-size container" {
    const Inner = struct {
        x: u16,
        y: u16,
    };

    const Outer = struct {
        id: u8,
        inner: Inner,
        tail: u32,
    };

    var buf: [32]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const value = Outer{
        .id = 0xaa,
        .inner = .{
            .x = 0x1122,
            .y = 0x3344,
        },
        .tail = 0x55667788,
    };

    try ssz.serialize(&writer, value);

    try testing.expectEqualSlices(
        u8,
        &.{
            0xaa,
            0x22,
            0x11,
            0x44,
            0x33,
            0x88,
            0x77,
            0x66,
            0x55,
        },
        writer.buffered(),
    );
}

test "SSZ encodes container with fixed byte root" {
    const Example = struct {
        slot: u64,
        root: [4]u8,
    };

    var buf: [32]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const value = Example{
        .slot = 7,
        .root = .{ 0xde, 0xad, 0xbe, 0xef },
    };

    try ssz.serialize(&writer, value);

    try testing.expectEqualSlices(
        u8,
        &.{
            0x07, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0xde, 0xad, 0xbe, 0xef,
        },
        writer.buffered(),
    );
}

test "SSZ encodes checkpoint-like container" {
    const Checkpoint = struct {
        epoch: u64,
        root: [32]u8,
    };

    var buf: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    var root = [_]u8{0} ** 32;
    root[0] = 0xaa;
    root[31] = 0xff;

    const value = Checkpoint{
        .epoch = 5,
        .root = root,
    };

    try ssz.serialize(&writer, value);

    try testing.expectEqual(
        @as(usize, 40),
        writer.buffered().len,
    );

    try testing.expectEqualSlices(
        u8,
        &.{
            0x05, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        },
        writer.buffered()[0..8],
    );

    try testing.expectEqualSlices(
        u8,
        &root,
        writer.buffered()[8..40],
    );
}

test "SSZ encodes multiple nested containers" {
    const Point = struct {
        x: u16,
        y: u16,
    };

    const Example = struct {
        first: Point,
        second: Point,
    };

    var buf: [32]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const value = Example{
        .first = .{
            .x = 1,
            .y = 2,
        },
        .second = .{
            .x = 3,
            .y = 4,
        },
    };

    try ssz.serialize(&writer, value);

    try testing.expectEqualSlices(
        u8,
        &.{
            0x01, 0x00,
            0x02, 0x00,
            0x03, 0x00,
            0x04, 0x00,
        },
        writer.buffered(),
    );
}

test "SSZ encodes false as 0x00" {
    var buf: [10]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try ssz.serialize(&writer, false);

    try testing.expectEqualSlices(
        u8,
        &.{0x00},
        writer.buffered(),
    );
}

test "SSZ encodes true as 0x01" {
    var buf: [10]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try ssz.serialize(&writer, true);

    try testing.expectEqualSlices(
        u8,
        &.{0x01},
        writer.buffered(),
    );
}

test "SSZ encodes boolean array" {
    var buf: [10]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const values = [_]bool{
        true,
        false,
        true,
        true,
    };

    try ssz.serialize(&writer, values);

    try testing.expectEqualSlices(
        u8,
        &.{
            0x01,
            0x00,
            0x01,
            0x01,
        },
        writer.buffered(),
    );
}

test "SSZ encodes container containing boolean" {
    const Example = struct {
        enabled: bool,
        count: u16,
    };

    var buf: [10]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const value = Example{
        .enabled = true,
        .count = 0x1234,
    };

    try ssz.serialize(&writer, value);

    try testing.expectEqualSlices(
        u8,
        &.{
            0x01,
            0x34,
            0x12,
        },
        writer.buffered(),
    );
}

test "SSZ encodes container with multiple booleans" {
    const Flags = struct {
        a: bool,
        b: bool,
        c: bool,
    };

    var buf: [10]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const value = Flags{
        .a = true,
        .b = false,
        .c = true,
    };

    try ssz.serialize(&writer, value);

    try testing.expectEqualSlices(
        u8,
        &.{
            0x01,
            0x00,
            0x01,
        },
        writer.buffered(),
    );
}

test "SSZ deeply nested fixed-size structs" {
    const Level4 = struct {
        a: u16,
        b: bool,
    };

    const Level3 = struct {
        x: u32,
        inner: Level4,
    };

    const Level2 = struct {
        flag: bool,
        inner: Level3,
        count: u8,
    };

    const Level1 = struct {
        slot: u64,
        inner: Level2,
    };

    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const value = Level1{
        .slot = 1,
        .inner = .{
            .flag = true,
            .inner = .{
                .x = 0x12345678,
                .inner = .{
                    .a = 0xabcd,
                    .b = false,
                },
            },
            .count = 0x7f,
        },
    };

    try ssz.serialize(&writer, value);

    try testing.expectEqualSlices(
        u8,
        &.{
            // slot: u64 = 1
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,

            // flag: true
            0x01,

            // x: u32 = 0x12345678
            0x78, 0x56, 0x34,
            0x12,

            // a: u16 = 0xabcd
            0xcd, 0xab,

            // b: false
            0x00,

            // count: u8
            0x7f,
        },
        writer.buffered(),
    );
}

// deserialize
test "SSZ deserializes false" {
    const input = [_]u8{0x00};

    var reader: std.Io.Reader = .fixed(&input);

    const value = try ssz.deserialize(bool, &reader);

    try testing.expectEqual(false, value);
}

test "SSZ deserializes true" {
    const input = [_]u8{0x01};

    var reader: std.Io.Reader = .fixed(&input);

    const value = try ssz.deserialize(bool, &reader);

    try testing.expectEqual(true, value);
}

test "SSZ rejects invalid boolean" {
    const input = [_]u8{0x02};

    var reader: std.Io.Reader = .fixed(&input);

    try testing.expectError(
        error.InvalidBoolean,
        ssz.deserialize(bool, &reader),
    );
}

test "SSZ deserializes u16 little endian" {
    const input = [_]u8{
        0x34,
        0x12,
    };

    var reader: std.Io.Reader = .fixed(&input);

    const value = try ssz.deserialize(u16, &reader);

    try testing.expectEqual(
        @as(u16, 0x1234),
        value,
    );
}

test "SSZ deserializes u32 little endian" {
    const input = [_]u8{
        0x78,
        0x56,
        0x34,
        0x12,
    };

    var reader: std.Io.Reader = .fixed(&input);

    const value = try ssz.deserialize(u32, &reader);

    try testing.expectEqual(
        @as(u32, 0x12345678),
        value,
    );
}

test "SSZ deserializes u64 little endian" {
    const input = [_]u8{
        0x08,
        0x07,
        0x06,
        0x05,
        0x04,
        0x03,
        0x02,
        0x01,
    };

    var reader: std.Io.Reader = .fixed(&input);

    const value = try ssz.deserialize(u64, &reader);

    try testing.expectEqual(
        @as(u64, 0x0102030405060708),
        value,
    );
}

test "SSZ deserializes fixed byte array" {
    const input = [_]u8{
        0xaa,
        0xbb,
        0xcc,
        0xdd,
    };

    var reader: std.Io.Reader = .fixed(&input);

    const value = try ssz.deserialize([4]u8, &reader);

    try testing.expectEqualSlices(
        u8,
        &.{
            0xaa,
            0xbb,
            0xcc,
            0xdd,
        },
        &value,
    );
}

test "SSZ deserializes array of u16" {
    const input = [_]u8{
        0x01, 0x00,
        0x02, 0x00,
        0x03, 0x00,
    };

    var reader: std.Io.Reader = .fixed(&input);

    const value = try ssz.deserialize([3]u16, &reader);

    try testing.expectEqual(
        @as(u16, 1),
        value[0],
    );

    try testing.expectEqual(
        @as(u16, 2),
        value[1],
    );

    try testing.expectEqual(
        @as(u16, 3),
        value[2],
    );
}

test "SSZ deserializes simple struct" {
    const Example = struct {
        enabled: bool,
        count: u16,
        slot: u64,
    };

    const input = [_]u8{
        0x01,

        0x34,
        0x12,

        0x2a,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };

    var reader: std.Io.Reader = .fixed(&input);

    const value = try ssz.deserialize(
        Example,
        &reader,
    );

    try testing.expectEqual(
        true,
        value.enabled,
    );

    try testing.expectEqual(
        @as(u16, 0x1234),
        value.count,
    );

    try testing.expectEqual(
        @as(u64, 42),
        value.slot,
    );
}

test "SSZ deserializes nested struct" {
    const Inner = struct {
        x: u16,
        flag: bool,
    };

    const Outer = struct {
        slot: u64,
        inner: Inner,
        tail: u32,
    };

    const input = [_]u8{
        // slot = 1
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,

        // inner.x = 0x1234
        0x34, 0x12,

        // inner.flag = true
        0x01,

        // tail = 0x55667788
        0x88,
        0x77, 0x66, 0x55,
    };

    var reader: std.Io.Reader = .fixed(&input);

    const value = try ssz.deserialize(
        Outer,
        &reader,
    );

    try testing.expectEqual(
        @as(u64, 1),
        value.slot,
    );

    try testing.expectEqual(
        @as(u16, 0x1234),
        value.inner.x,
    );

    try testing.expectEqual(
        true,
        value.inner.flag,
    );

    try testing.expectEqual(
        @as(u32, 0x55667788),
        value.tail,
    );
}

test "SSZ deserializes array of structs" {
    const Item = struct {
        flag: bool,
        value: u16,
    };

    const input = [_]u8{
        0x01,
        0x34,
        0x12,

        0x00,
        0x78,
        0x56,
    };

    var reader: std.Io.Reader = .fixed(&input);

    const value = try ssz.deserialize(
        [2]Item,
        &reader,
    );

    try testing.expectEqual(
        true,
        value[0].flag,
    );

    try testing.expectEqual(
        @as(u16, 0x1234),
        value[0].value,
    );

    try testing.expectEqual(
        false,
        value[1].flag,
    );

    try testing.expectEqual(
        @as(u16, 0x5678),
        value[1].value,
    );
}

// serialize and deserialisation
test "SSZ round trip simple struct" {
    const Example = struct {
        enabled: bool,
        count: u16,
        slot: u64,
    };

    const original = Example{
        .enabled = true,
        .count = 0x1234,
        .slot = 42,
    };

    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try ssz.serialize(&writer, original);

    var reader: std.Io.Reader = .fixed(writer.buffered());

    const decoded = try ssz.deserialize(Example, &reader);

    try testing.expectEqual(original.enabled, decoded.enabled);
    try testing.expectEqual(original.count, decoded.count);
    try testing.expectEqual(original.slot, decoded.slot);
}

test "SSZ round trip nested struct" {
    const Inner = struct {
        x: u16,
        active: bool,
    };

    const Outer = struct {
        slot: u64,
        inner: Inner,
        count: u32,
    };

    const original = Outer{
        .slot = 123456,
        .inner = .{
            .x = 0xabcd,
            .active = true,
        },
        .count = 9001,
    };

    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try ssz.serialize(&writer, original);

    var reader: std.Io.Reader = .fixed(writer.buffered());

    const decoded = try ssz.deserialize(Outer, &reader);

    try testing.expectEqual(original.slot, decoded.slot);
    try testing.expectEqual(original.inner.x, decoded.inner.x);
    try testing.expectEqual(original.inner.active, decoded.inner.active);
    try testing.expectEqual(original.count, decoded.count);
}

test "SSZ round trip struct containing array" {
    const Example = struct {
        epoch: u64,
        values: [4]u16,
    };

    const original = Example{
        .epoch = 7,
        .values = .{ 10, 20, 30, 40 },
    };

    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try ssz.serialize(&writer, original);

    var reader: std.Io.Reader = .fixed(writer.buffered());

    const decoded = try ssz.deserialize(Example, &reader);

    try testing.expectEqual(original.epoch, decoded.epoch);

    try testing.expectEqualSlices(
        u16,
        &original.values,
        &decoded.values,
    );
}

test "SSZ round trip array of structs" {
    const Item = struct {
        enabled: bool,
        value: u16,
    };

    const Example = struct {
        id: u32,
        items: [3]Item,
    };

    const original = Example{
        .id = 123,
        .items = .{
            .{ .enabled = true, .value = 10 },
            .{ .enabled = false, .value = 20 },
            .{ .enabled = true, .value = 30 },
        },
    };

    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try ssz.serialize(&writer, original);

    var reader: std.Io.Reader = .fixed(writer.buffered());

    const decoded = try ssz.deserialize(Example, &reader);

    try testing.expectEqual(original.id, decoded.id);

    for (original.items, decoded.items) |expected, actual| {
        try testing.expectEqual(expected.enabled, actual.enabled);
        try testing.expectEqual(expected.value, actual.value);
    }
}

test "SSZ round trip deeply nested struct" {
    const Leaf = struct {
        flag: bool,
        number: u16,
    };

    const Branch = struct {
        left: Leaf,
        right: Leaf,
    };

    const Root = struct {
        slot: u64,
        branch: Branch,
        tail: u32,
    };

    const original = Root{
        .slot = 999,
        .branch = .{
            .left = .{
                .flag = true,
                .number = 0x1234,
            },
            .right = .{
                .flag = false,
                .number = 0xabcd,
            },
        },
        .tail = 0x11223344,
    };

    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try ssz.serialize(&writer, original);

    var reader: std.Io.Reader = .fixed(writer.buffered());

    const decoded = try ssz.deserialize(Root, &reader);

    try testing.expectEqual(original.slot, decoded.slot);

    try testing.expectEqual(
        original.branch.left.flag,
        decoded.branch.left.flag,
    );

    try testing.expectEqual(
        original.branch.left.number,
        decoded.branch.left.number,
    );

    try testing.expectEqual(
        original.branch.right.flag,
        decoded.branch.right.flag,
    );

    try testing.expectEqual(
        original.branch.right.number,
        decoded.branch.right.number,
    );

    try testing.expectEqual(original.tail, decoded.tail);
}

test "SSZ round trip whole struct equality" {
    const Example = struct {
        a: u16,
        b: u64,
        c: bool,
    };

    const original = Example{
        .a = 12,
        .b = 999,
        .c = true,
    };

    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try ssz.serialize(&writer, original);

    var reader: std.Io.Reader = .fixed(writer.buffered());

    const decoded = try ssz.deserialize(Example, &reader);

    try testing.expectEqual(original, decoded);
}

test "SSZ ByteVector round trip" {
    const types = @import("types");
    const T = types.ByteVector(4);

    const original = T{ .data = .{ 0xde, 0xad, 0xbe, 0xef } };

    var buf: [8]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try ssz.serialize(&writer, original);

    try testing.expectEqualSlices(
        u8,
        &.{ 0xde, 0xad, 0xbe, 0xef },
        writer.buffered(),
    );

    var reader: std.Io.Reader = .fixed(writer.buffered());

    const decoded = try ssz.deserialize(T, &reader);

    try testing.expectEqualSlices(u8, &original.data, &decoded.data);
}

test "SSZ ByteVector embeds fixed-size in container" {
    const types = @import("types");
    const T = types.ByteVector(4);

    const Example = struct {
        id: u16,
        hash: T,
    };

    const original = Example{
        .id = 1,
        .hash = .{ .data = .{ 0xde, 0xad, 0xbe, 0xef } },
    };

    var buf: [16]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try ssz.serialize(&writer, original);

    try testing.expectEqualSlices(
        u8,
        &.{ 0x01, 0x00, 0xde, 0xad, 0xbe, 0xef },
        writer.buffered(),
    );

    var reader: std.Io.Reader = .fixed(writer.buffered());

    const decoded = try ssz.deserialize(Example, &reader);

    try testing.expectEqual(original.id, decoded.id);
    try testing.expectEqualSlices(u8, &original.hash.data, &decoded.hash.data);
}

test "SSZ round trip container with list field" {
    const types = @import("types");
    const allocator = testing.allocator;

    const Example = struct {
        id: u16,
        vals: types.List(u32, 16),
    };

    const items = [_]u32{ 1, 2, 3 };
    const original = Example{
        .id = 0x1234,
        .vals = .{ .data = &items },
    };

    var buf: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try ssz.serialize(&writer, original);

    // id ++ offset(6) ++ payload
    try testing.expectEqualSlices(
        u8,
        &.{
            0x34, 0x12,
            0x06, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00,
        },
        writer.buffered(),
    );

    var reader: std.Io.Reader = .fixed(writer.buffered());
    const decoded = try ssz.deserializeAlloc(allocator, Example, &reader);
    defer ssz.freeDecoded(allocator, Example, decoded);

    try testing.expectEqual(original.id, decoded.id);
    try testing.expectEqualSlices(u32, &items, decoded.vals.data);
}

test "SSZ round trip container with mixed fixed variable fixed" {
    const types = @import("types");
    const allocator = testing.allocator;

    const Example = struct {
        a: u8,
        xs: types.List(u16, 8),
        b: u32,
    };

    const items = [_]u16{ 0xabcd, 0x1234 };
    const original = Example{
        .a = 0x7f,
        .xs = .{ .data = &items },
        .b = 0x01020304,
    };

    var buf: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try ssz.serialize(&writer, original);

    try testing.expectEqualSlices(
        u8,
        &.{
            0x7f,
            0x09, 0x00, 0x00, 0x00,
            0x04, 0x03, 0x02, 0x01,
            0xcd, 0xab,
            0x34, 0x12,
        },
        writer.buffered(),
    );

    var reader: std.Io.Reader = .fixed(writer.buffered());
    const decoded = try ssz.deserializeAlloc(allocator, Example, &reader);
    defer ssz.freeDecoded(allocator, Example, decoded);

    try testing.expectEqual(original.a, decoded.a);
    try testing.expectEqualSlices(u16, &items, decoded.xs.data);
    try testing.expectEqual(original.b, decoded.b);
}

test "SSZ round trip nested variable containers" {
    const types = @import("types");
    const allocator = testing.allocator;

    const Inner = struct {
        flag: bool,
        vals: types.List(u8, 8),
    };
    const Outer = struct {
        tag: u8,
        inner: Inner,
        tail: u16,
    };

    const bytes = [_]u8{ 9, 8, 7 };
    const original = Outer{
        .tag = 0xaa,
        .inner = .{
            .flag = true,
            .vals = .{ .data = &bytes },
        },
        .tail = 0x1234,
    };

    var buf: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try ssz.serialize(&writer, original);

    var reader: std.Io.Reader = .fixed(writer.buffered());
    const decoded = try ssz.deserializeAlloc(allocator, Outer, &reader);
    defer ssz.freeDecoded(allocator, Outer, decoded);

    try testing.expectEqual(original.tag, decoded.tag);
    try testing.expectEqual(original.inner.flag, decoded.inner.flag);
    try testing.expectEqualSlices(u8, &bytes, decoded.inner.vals.data);
    try testing.expectEqual(original.tail, decoded.tail);
}

test "SSZ round trip fixed array of lists" {
    const types = @import("types");
    const allocator = testing.allocator;

    const Example = struct {
        groups: [2]types.List(u16, 4),
    };

    const g0 = [_]u16{1};
    const g1 = [_]u16{ 2, 3 };
    const original = Example{
        .groups = .{
            .{ .data = &g0 },
            .{ .data = &g1 },
        },
    };

    var buf: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try ssz.serialize(&writer, original);

    // container offset(4) ++ [off0, off1] ++ payloads
    try testing.expectEqualSlices(
        u8,
        &.{
            0x04, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00,
            0x0a, 0x00, 0x00, 0x00,
            0x01, 0x00,
            0x02, 0x00,
            0x03, 0x00,
        },
        writer.buffered(),
    );

    var reader: std.Io.Reader = .fixed(writer.buffered());
    const decoded = try ssz.deserializeAlloc(allocator, Example, &reader);
    defer ssz.freeDecoded(allocator, Example, decoded);

    try testing.expectEqualSlices(u16, &g0, decoded.groups[0].data);
    try testing.expectEqualSlices(u16, &g1, decoded.groups[1].data);
}

test "SSZ rejects container with bad first offset" {
    const types = @import("types");
    const allocator = testing.allocator;

    const Example = struct {
        id: u16,
        vals: types.List(u32, 16),
    };

    // offset 7 instead of 6
    const input = [_]u8{
        0x34, 0x12,
        0x07, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
    };

    var reader: std.Io.Reader = .fixed(&input);
    try testing.expectError(
        error.InvalidOffset,
        ssz.deserializeAlloc(allocator, Example, &reader),
    );
}

test "SSZ rejects container with decreasing offsets" {
    const types = @import("types");
    const allocator = testing.allocator;

    const Example = struct {
        a: types.List(u8, 8),
        b: types.List(u8, 8),
    };

    // fixed section 8 bytes; second offset goes backwards
    const input = [_]u8{
        0x08, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x00, 0x00,
        0xaa, 0xbb,
    };

    var reader: std.Io.Reader = .fixed(&input);
    try testing.expectError(
        error.InvalidOffset,
        ssz.deserializeAlloc(allocator, Example, &reader),
    );
}

test "SSZ rejects container with offset past end" {
    const types = @import("types");
    const allocator = testing.allocator;

    const Example = struct {
        id: u16,
        vals: types.List(u32, 16),
    };

    const input = [_]u8{
        0x34, 0x12,
        0xff, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
    };

    var reader: std.Io.Reader = .fixed(&input);
    try testing.expectError(
        error.InvalidOffset,
        ssz.deserializeAlloc(allocator, Example, &reader),
    );
}

test "SSZ rejects truncated container" {
    const types = @import("types");
    const allocator = testing.allocator;

    const Example = struct {
        id: u16,
        vals: types.List(u32, 16),
    };

    const input = [_]u8{ 0x34, 0x12, 0x06 };

    var reader: std.Io.Reader = .fixed(&input);
    try testing.expectError(
        error.EndOfStream,
        ssz.deserializeAlloc(allocator, Example, &reader),
    );
}

test "SSZ rejects trailing byte on fixed container" {
    const allocator = testing.allocator;

    const Example = struct {
        a: u16,
        b: u8,
    };

    const input = [_]u8{ 0x34, 0x12, 0x7f, 0x00 };

    var reader: std.Io.Reader = .fixed(&input);
    try testing.expectError(
        error.TrailingBytes,
        ssz.deserializeAlloc(allocator, Example, &reader),
    );
}

test "SSZ plain deserialize refuses variable container" {
    const types = @import("types");

    const Example = struct {
        id: u16,
        vals: types.List(u32, 16),
    };

    const input = [_]u8{
        0x34, 0x12,
        0x06, 0x00, 0x00, 0x00,
    };

    var reader: std.Io.Reader = .fixed(&input);
    try testing.expectError(
        error.NeedsAllocator,
        ssz.deserialize(Example, &reader),
    );
}

test "SSZ round trip bytelist" {
    const types = @import("types");
    const allocator = testing.allocator;

    const T = types.ByteList(16);
    const bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const original = T{ .data = &bytes };

    var buf: [16]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try ssz.serialize(&writer, original);
    try testing.expectEqualSlices(u8, &bytes, writer.buffered());

    var reader: std.Io.Reader = .fixed(writer.buffered());
    const decoded = try ssz.deserializeAlloc(allocator, T, &reader);
    defer ssz.freeDecoded(allocator, T, decoded);
    try testing.expectEqualSlices(u8, &bytes, decoded.data);
}

test "SSZ round trip empty bytelist" {
    const types = @import("types");
    const allocator = testing.allocator;

    const T = types.ByteList(16);
    const original = T{ .data = &.{} };

    var buf: [1]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try ssz.serialize(&writer, original);
    try testing.expectEqual(@as(usize, 0), writer.buffered().len);

    var reader: std.Io.Reader = .fixed(writer.buffered());
    const decoded = try ssz.deserializeAlloc(allocator, T, &reader);
    defer ssz.freeDecoded(allocator, T, decoded);
    try testing.expectEqual(@as(usize, 0), decoded.data.len);
}

test "SSZ rejects bytelist over limit" {
    const types = @import("types");
    const allocator = testing.allocator;

    const T = types.ByteList(2);
    const input = [_]u8{ 0x01, 0x02, 0x03 };

    var reader: std.Io.Reader = .fixed(&input);
    try testing.expectError(
        error.ByteListTooLong,
        ssz.deserializeAlloc(allocator, T, &reader),
    );
}

test "SSZ round trip bitlist" {
    const types = @import("types");
    const allocator = testing.allocator;

    const T = types.BitList(16);
    const bits = [_]bool{ true, false, true, true, false };
    const original = T{ .data = &bits };

    var buf: [8]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try ssz.serialize(&writer, original);
    try testing.expectEqualSlices(u8, &.{0x2d}, writer.buffered());

    var reader: std.Io.Reader = .fixed(writer.buffered());
    const decoded = try ssz.deserializeAlloc(allocator, T, &reader);
    defer ssz.freeDecoded(allocator, T, decoded);
    try testing.expectEqualSlices(bool, &bits, decoded.data);
}

test "SSZ round trip empty bitlist" {
    const types = @import("types");
    const allocator = testing.allocator;

    const T = types.BitList(16);
    const bits = [_]bool{};
    const original = T{ .data = &bits };

    var buf: [8]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try ssz.serialize(&writer, original);
    try testing.expectEqualSlices(u8, &.{0x01}, writer.buffered());

    var reader: std.Io.Reader = .fixed(writer.buffered());
    const decoded = try ssz.deserializeAlloc(allocator, T, &reader);
    defer ssz.freeDecoded(allocator, T, decoded);
    try testing.expectEqual(@as(usize, 0), decoded.data.len);
}

test "SSZ round trip single-bit bitlists" {
    const types = @import("types");
    const allocator = testing.allocator;

    const T = types.BitList(16);

    const t = [_]bool{true};
    var buf: [8]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try ssz.serialize(&writer, T{ .data = &t });
    try testing.expectEqualSlices(u8, &.{0x03}, writer.buffered());
    var reader: std.Io.Reader = .fixed(writer.buffered());
    const dt = try ssz.deserializeAlloc(allocator, T, &reader);
    defer ssz.freeDecoded(allocator, T, dt);
    try testing.expectEqualSlices(bool, &t, dt.data);

    const f = [_]bool{false};
    var buf2: [8]u8 = undefined;
    var writer2: std.Io.Writer = .fixed(&buf2);
    try ssz.serialize(&writer2, T{ .data = &f });
    try testing.expectEqualSlices(u8, &.{0x02}, writer2.buffered());
    var reader2: std.Io.Reader = .fixed(writer2.buffered());
    const df = try ssz.deserializeAlloc(allocator, T, &reader2);
    defer ssz.freeDecoded(allocator, T, df);
    try testing.expectEqualSlices(bool, &f, df.data);
}

test "SSZ rejects bitlist without delimiter" {
    const types = @import("types");
    const allocator = testing.allocator;

    const T = types.BitList(16);

    const zero = [_]u8{0x00};
    var reader: std.Io.Reader = .fixed(&zero);
    try testing.expectError(
        error.NoDelimiterBit,
        ssz.deserializeAlloc(allocator, T, &reader),
    );

    const trailing_zero = [_]u8{ 0x01, 0x00 };
    var reader2: std.Io.Reader = .fixed(&trailing_zero);
    try testing.expectError(
        error.NoDelimiterBit,
        ssz.deserializeAlloc(allocator, T, &reader2),
    );

    const empty = [_]u8{};
    var reader3: std.Io.Reader = .fixed(&empty);
    try testing.expectError(
        error.EndOfStream,
        ssz.deserializeAlloc(allocator, T, &reader3),
    );
}

test "SSZ rejects bitlist over limit" {
    const types = @import("types");
    const allocator = testing.allocator;

    const T = types.BitList(8);
    const input = [_]u8{ 0x00, 0x10 };

    var reader: std.Io.Reader = .fixed(&input);
    try testing.expectError(
        error.BitListTooLong,
        ssz.deserializeAlloc(allocator, T, &reader),
    );
}

test "SSZ plain deserialize refuses bitlist and bytelist" {
    const types = @import("types");

    const BL = types.BitList(8);
    const input = [_]u8{0x03};
    var reader: std.Io.Reader = .fixed(&input);
    try testing.expectError(
        error.NeedsAllocator,
        ssz.deserialize(BL, &reader),
    );

    const YL = types.ByteList(8);
    var reader2: std.Io.Reader = .fixed(&input);
    try testing.expectError(
        error.NeedsAllocator,
        ssz.deserialize(YL, &reader2),
    );
}

test "SSZ round trip multi-byte bitlist" {
    const types = @import("types");
    const allocator = testing.allocator;

    const T = types.BitList(16);
    const bits = [_]bool{ true, false, true, false, true, false, true, false, true };
    const original = T{ .data = &bits };

    var buf: [8]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try ssz.serialize(&writer, original);
    // 9 data bits + delimiter in second byte: 0x55, 0x03
    try testing.expectEqualSlices(u8, &.{ 0x55, 0x03 }, writer.buffered());

    var reader: std.Io.Reader = .fixed(writer.buffered());
    const decoded = try ssz.deserializeAlloc(allocator, T, &reader);
    defer ssz.freeDecoded(allocator, T, decoded);
    try testing.expectEqualSlices(bool, &bits, decoded.data);
}
