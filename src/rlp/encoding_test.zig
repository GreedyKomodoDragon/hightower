const std = @import("std");
const testing = std.testing;

const encoding = @import("encoding.zig");

test "RLP list header uses short form for payloads up to 55 bytes" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try encoding.encodeListHeader(&writer, 0);
    try encoding.encodeListHeader(&writer, 3);
    try encoding.encodeListHeader(&writer, 55);

    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0xc0, 0xc3, 0xf7 },
        writer.buffered(),
    );
}

test "RLP list header switches to long form at 56 bytes" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try encoding.encodeListHeader(&writer, 56);

    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0xf8, 0x38 },
        writer.buffered(),
    );
}

test "RLP list header encodes multi-byte lengths" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try encoding.encodeListHeader(&writer, 5000);

    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0xf9, 0x13, 0x88 },
        writer.buffered(),
    );
}

test "RLP encodes empty string as 0x80" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try encoding.encodeString(&writer, "");

    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{0x80},
        writer.buffered(),
    );
}

test "RLP encodes dog" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try encoding.encodeString(&writer, "dog");
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x83, 'd', 'o', 'g' },
        writer.buffered(),
    );
}
