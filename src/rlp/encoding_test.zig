const std = @import("std");
const testing = std.testing;

const encoding = @import("encoding.zig");

test "RLP encodes single byte below 0x80 as itself" {
    var buf: [100]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);

    try encoding.encodeBytes(&writer, &[_]u8{0x7f});

    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{0x7f},
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
