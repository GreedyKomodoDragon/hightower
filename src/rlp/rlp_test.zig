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

test "RLP propagates string and list buffer exhaustion" {
    var buf: [1]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try testing.expectError(error.WriteFailed, rlp.rlp(&writer, "dog"));
    writer = .fixed(&buf);
    const slice: []const u8 = "dog";
    try testing.expectError(error.WriteFailed, rlp.rlp(&writer, slice));

    const oversized = [_]u8{'x'} ** 4096;
    const list = [_][]const u8{&oversized};
    var output: [8192]u8 = undefined;
    writer = .fixed(&output);
    try testing.expectError(error.WriteFailed, rlp.rlp(&writer, list));
    try testing.expectEqual(@as(usize, 0), writer.buffered().len);
}

test "RLP encodes unsigned integers with minimal big-endian encoding" {
    const cases = [_]struct {
        value: u16,
        expected: []const u8,
    }{
        .{ .value = 0, .expected = &.{0x80} },
        .{ .value = 127, .expected = &.{0x7f} },
        .{ .value = 128, .expected = &.{ 0x81, 0x80 } },
        .{ .value = 1024, .expected = &.{ 0x82, 0x04, 0x00 } },
    };

    for (cases) |case| {
        var buf: [100]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buf);

        try rlp.rlp(&writer, case.value);

        try testing.expectEqualSlices(u8, case.expected, writer.buffered());
    }
}

test "RLP integer encoding is big-endian regardless of host endianness" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try rlp.rlp(&writer, @as(u32, 0x01020304));

    try testing.expectEqualSlices(
        u8,
        &.{ 0x84, 0x01, 0x02, 0x03, 0x04 },
        writer.buffered(),
    );
}

test "RLP encodes 55 byte integer with short string prefix" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try rlp.rlp(&writer, @as(u440, std.math.maxInt(u440)));

    const expected = [_]u8{0xff} ** 55;
    const encoded = writer.buffered();
    try testing.expectEqual(@as(usize, 56), encoded.len);
    try testing.expectEqual(@as(u8, 0xb7), encoded[0]);
    try testing.expectEqualSlices(u8, &expected, encoded[1..]);
}

test "RLP encodes 56 byte integer with long string prefix" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try rlp.rlp(&writer, @as(u448, std.math.maxInt(u448)));

    const expected = [_]u8{0xff} ** 56;
    const encoded = writer.buffered();
    try testing.expectEqual(@as(usize, 58), encoded.len);
    try testing.expectEqualSlices(u8, &.{ 0xb8, 0x38 }, encoded[0..2]);
    try testing.expectEqualSlices(u8, &expected, encoded[2..]);
}

test "RLP rejects signed integers" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try testing.expectError(
        error.SignedIntegerUnsupported,
        rlp.rlp(&writer, @as(i32, 5)),
    );
}
