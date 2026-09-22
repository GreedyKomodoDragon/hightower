const std = @import("std");
const testing = std.testing;

const rlp = @import("rlp.zig");

test "RLP encodes empty list as 0xc0" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const list = [_][]const u8{};

    try rlp.rlp(&writer, list);
    try testing.expectEqualSlices(
        u8,
        &[_]u8{0xc0},
        writer.buffered(),
    );
}

test "rlp encodes test string" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try rlp.rlp(&writer, "test");

    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x84, 0x74, 0x65, 0x73, 0x74 },
        writer.buffered(),
    );
}

test "RLP encodes empty string as 0x80" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try rlp.rlp(&writer, "");

    try testing.expectEqualSlices(
        u8,
        &[_]u8{0x80},
        writer.buffered(),
    );
}

test "RLP encodes list of cat and dog" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const list = [_][]const u8{
        "cat",
        "dog",
    };

    try rlp.rlp(&writer, list);

    try testing.expectEqualSlices(
        u8,
        &.{
            0xc8,
            0x83,
            'c',
            'a',
            't',
            0x83,
            'd',
            'o',
            'g',
        },
        writer.buffered(),
    );
}

test "RLP encodes empty string" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try rlp.rlp(&writer, "");

    try testing.expectEqualSlices(
        u8,
        &.{0x80},
        writer.buffered(),
    );
}

test "RLP encodes single byte below 0x80 as itself" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const value = [_]u8{0x7f};

    try rlp.rlp(&writer, value);

    try testing.expectEqualSlices(
        u8,
        &.{0x7f},
        writer.buffered(),
    );
}

test "RLP encodes single byte 0x80 with string prefix" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const value = [_]u8{0x80};

    try rlp.rlp(&writer, value);

    try testing.expectEqualSlices(
        u8,
        &.{
            0x81,
            0x80,
        },
        writer.buffered(),
    );
}

test "RLP encodes dog" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try rlp.rlp(&writer, "dog");

    try testing.expectEqualSlices(
        u8,
        &.{
            0x83,
            'd',
            'o',
            'g',
        },
        writer.buffered(),
    );
}

test "RLP encodes empty list" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const list = [_][]const u8{};

    try rlp.rlp(&writer, list);

    try testing.expectEqualSlices(
        u8,
        &.{0xc0},
        writer.buffered(),
    );
}

test "RLP encodes list containing empty string" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const list = [_][]const u8{
        "",
    };

    try rlp.rlp(&writer, list);

    try testing.expectEqualSlices(
        u8,
        &.{
            0xc1,
            0x80,
        },
        writer.buffered(),
    );
}

test "RLP encodes list of a b c" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const list = [_][]const u8{
        "a",
        "b",
        "c",
    };

    try rlp.rlp(&writer, list);

    try testing.expectEqualSlices(
        u8,
        &.{
            0xc3,
            'a',
            'b',
            'c',
        },
        writer.buffered(),
    );
}

test "RLP encodes 55 byte string" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const value = [_]u8{'a'} ** 55;

    try rlp.rlp(&writer, value);

    try testing.expectEqual(
        @as(u8, 0xb7),
        writer.buffered()[0],
    );

    try testing.expectEqual(
        @as(usize, 56),
        writer.buffered().len,
    );

    try testing.expectEqualSlices(
        u8,
        &value,
        writer.buffered()[1..],
    );
}

test "RLP encodes 56 byte string" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    const value = [_]u8{'a'} ** 56;

    try rlp.rlp(&writer, value);

    const encoded = writer.buffered();

    try testing.expectEqual(
        @as(usize, 58),
        encoded.len,
    );

    try testing.expectEqualSlices(
        u8,
        &.{ 0xb8, 0x38 },
        encoded[0..2],
    );

    try testing.expectEqualSlices(
        u8,
        &value,
        encoded[2..],
    );
}
