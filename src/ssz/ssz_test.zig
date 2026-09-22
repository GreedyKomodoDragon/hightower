const std = @import("std");
const ssz = @import("ssz.zig");
const testing = std.testing;

const Example = struct {
    count: u16,
    slot: u64,
};

test "SSZ encodes fixed-size container" {
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
