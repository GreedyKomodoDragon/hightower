// Devp2p v5 compresses every capability body after Hello with Snappy. The
// uncompressed length comes first; verify it before allocation because a tiny
// peer frame can otherwise expand beyond the transaction message limit.
// Compression emits literal chunks; decompression accepts all four tag forms.
//
// bounded frame -> Snappy size gate -> bounded capability body
const std = @import("std");

pub const max_body_size = 10 * 1024 * 1024;

/// Encode a bounded body using valid Snappy literal chunks.
pub fn encode(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    if (body.len > max_body_size) return error.MessageTooLarge;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var remaining = body.len;
    while (true) {
        const byte: u8 = @intCast(remaining & 0x7f);
        remaining >>= 7;
        try out.append(allocator, byte | if (remaining != 0) @as(u8, 0x80) else 0);
        if (remaining == 0) break;
    }
    var offset: usize = 0;
    while (offset < body.len) {
        const length = @min(body.len - offset, 64 * 1024);
        const count = length - 1;
        if (length <= 60) {
            try out.append(allocator, @intCast(count << 2));
        } else if (length <= 256) {
            try out.appendSlice(allocator, &.{ 60 << 2, @intCast(count) });
        } else {
            try out.append(allocator, 61 << 2);
            try out.append(allocator, @truncate(count));
            try out.append(allocator, @truncate(count >> 8));
        }
        try out.appendSlice(allocator, body[offset .. offset + length]);
        offset += length;
    }
    return out.toOwnedSlice(allocator);
}

/// Decode a Snappy body after bounding its declared output length.
pub fn decode(allocator: std.mem.Allocator, wire: []const u8) ![]u8 {
    var offset: usize = 0;
    var expected: usize = 0;
    var shift: u6 = 0;
    while (true) {
        if (offset == wire.len or shift >= 35) return error.InvalidSnappy;
        const byte = wire[offset];
        offset += 1;
        expected |= @as(usize, byte & 0x7f) << shift;
        if (expected > max_body_size) return error.MessageTooLarge;
        if (byte & 0x80 == 0) break;
        shift += 7;
    }
    const result = try allocator.alloc(u8, expected);
    errdefer allocator.free(result);
    var written: usize = 0;
    while (offset < wire.len) {
        const tag = wire[offset];
        offset += 1;
        if (tag & 3 == 0) {
            const count_field = tag >> 2;
            var length: usize = 0;
            if (count_field < 60) {
                length = @as(usize, count_field) + 1;
            } else {
                const width: usize = count_field - 59;
                if (offset + width > wire.len) return error.InvalidSnappy;
                for (wire[offset .. offset + width], 0..) |byte, i| length |= @as(usize, byte) << @intCast(8 * i);
                length += 1;
                offset += width;
            }
            if (length > expected - written or length > wire.len - offset) return error.InvalidSnappy;
            @memcpy(result[written .. written + length], wire[offset .. offset + length]);
            written += length;
            offset += length;
            continue;
        }
        const kind = tag & 3;
        const width: usize = if (kind == 1) 1 else if (kind == 2) 2 else 4;
        if (offset + width > wire.len) return error.InvalidSnappy;
        var distance: usize = if (kind == 1) @as(usize, tag & 0xe0) << 3 else 0;
        for (wire[offset .. offset + width], 0..) |byte, i| distance |= @as(usize, byte) << @intCast(8 * i);
        offset += width;
        const length: usize = if (kind == 1) 4 + ((tag >> 2) & 7) else 1 + (tag >> 2);
        if (distance == 0 or distance > written or length > expected - written) return error.InvalidSnappy;
        for (0..length) |i| result[written + i] = result[written + i - distance];
        written += length;
    }
    if (written != expected) return error.InvalidSnappy;
    return result;
}

test "Snappy round trips bounded literals and accepts overlapping copy tags" {
    const a = std.testing.allocator;
    const plain = "a" ** 100_000;
    const compressed = try encode(a, plain);
    defer a.free(compressed);
    const restored = try decode(a, compressed);
    defer a.free(restored);
    try std.testing.expectEqualStrings(plain, restored);
    const copied = try decode(a, &.{ 9, 0, 'a', 0x1e, 1, 0 });
    defer a.free(copied);
    try std.testing.expectEqualStrings("aaaaaaaaa", copied);
    try std.testing.expectError(error.MessageTooLarge, decode(a, &.{ 0xff, 0xff, 0xff, 0x05 }));
}
