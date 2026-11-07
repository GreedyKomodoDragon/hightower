// Yamux gives gossip and each Req/Resp request an independent ordered stream
// inside one authenticated TCP connection. Stream IDs are assigned by the
// opener; SYN opens, DATA advances its receive window, and FIN ends only that
// stream. A malformed header must be rejected before application dispatch.
//
//   Noise record -> 12-byte Yamux header -> bounded stream payload
// This codec accepts version 0, at most 16 KiB of DATA per frame, and the
// four Yamux frame types needed for stream flow control and shutdown.
const std = @import("std");

pub const header_size: usize = 12;
pub const max_data: usize = 16 * 1024;
pub const initial_window: u32 = 256 * 1024;

pub const Kind = enum(u8) { data = 0, window_update = 1, ping = 2, go_away = 3 };
pub const Flags = packed struct(u16) {
    syn: bool = false,
    ack: bool = false,
    fin: bool = false,
    rst: bool = false,
    reserved: u12 = 0,
};

pub const Frame = struct {
    kind: Kind,
    flags: Flags = .{},
    stream_id: u32,
    /// Window delta, ping tag, or shutdown reason for non-DATA frames.
    value: u32 = 0,
    data: []const u8 = &.{},
};

/// Encode one bounded Yamux frame; the caller owns the returned bytes.
pub fn encode(allocator: std.mem.Allocator, frame: Frame) ![]u8 {
    try validate(frame);
    const result = try allocator.alloc(u8, header_size + frame.data.len);
    result[0] = 0;
    result[1] = @intFromEnum(frame.kind);
    std.mem.writeInt(u16, result[2..4], @bitCast(frame.flags), .big);
    std.mem.writeInt(u32, result[4..8], frame.stream_id, .big);
    std.mem.writeInt(u32, result[8..12], if (frame.kind == .data) @intCast(frame.data.len) else frame.value, .big);
    @memcpy(result[header_size..], frame.data);
    return result;
}

/// Decode exactly one bounded frame from an authenticated Noise record.
pub fn decode(bytes: []const u8) !Frame {
    if (bytes.len < header_size or bytes[0] != 0) return error.InvalidYamuxFrame;
    if (bytes[1] > @intFromEnum(Kind.go_away)) return error.InvalidYamuxFrame;
    const kind: Kind = @enumFromInt(bytes[1]);
    const flags: Flags = @bitCast(std.mem.readInt(u16, bytes[2..4], .big));
    const stream_id = std.mem.readInt(u32, bytes[4..8], .big);
    const value = std.mem.readInt(u32, bytes[8..12], .big);
    const frame: Frame = .{ .kind = kind, .flags = flags, .stream_id = stream_id, .value = if (kind == .data) 0 else value, .data = bytes[header_size..] };
    if (kind == .data and value != frame.data.len) return error.InvalidYamuxFrame;
    try validate(frame);
    return frame;
}

/// Require only supported flag and payload combinations for each frame type.
fn validate(frame: Frame) !void {
    if (frame.flags.reserved != 0 or frame.data.len > max_data) return error.InvalidYamuxFrame;
    switch (frame.kind) {
        .data => {
            if (frame.stream_id == 0) return error.InvalidYamuxFrame;
            if (frame.flags.rst and (frame.data.len != 0 or frame.flags.syn or frame.flags.fin)) return error.InvalidYamuxFrame;
        },
        .window_update => {
            if (frame.stream_id == 0 or frame.data.len != 0) return error.InvalidYamuxFrame;
        },
        .ping => {
            if (frame.stream_id != 0 or frame.data.len != 0 or frame.flags.fin or frame.flags.rst) return error.InvalidYamuxFrame;
            if (frame.flags.syn and frame.flags.ack) return error.InvalidYamuxFrame;
        },
        .go_away => {
            if (frame.stream_id != 0 or frame.data.len != 0 or @as(u16, @bitCast(frame.flags)) != 0 or frame.value > 2) return error.InvalidYamuxFrame;
        },
    }
}

test "Yamux codec keeps streams separate and rejects invalid frames" {
    const allocator = std.testing.allocator;
    const first = try encode(allocator, .{ .kind = .data, .flags = .{ .syn = true }, .stream_id = 1, .data = "gossip" });
    defer allocator.free(first);
    const second = try encode(allocator, .{ .kind = .data, .flags = .{ .syn = true }, .stream_id = 3, .data = "status" });
    defer allocator.free(second);
    try std.testing.expectEqual(@as(u32, 1), (try decode(first)).stream_id);
    try std.testing.expectEqual(@as(u32, 3), (try decode(second)).stream_id);
    var altered = try allocator.dupe(u8, first);
    defer allocator.free(altered);
    altered[11] += 1;
    try std.testing.expectError(error.InvalidYamuxFrame, decode(altered));
    try std.testing.expectError(error.InvalidYamuxFrame, encode(allocator, .{ .kind = .data, .stream_id = 0, .data = "bad" }));
    const ack = try encode(allocator, .{ .kind = .window_update, .flags = .{ .ack = true }, .stream_id = 1, .value = 0 });
    defer allocator.free(ack);
    try std.testing.expect((try decode(ack)).flags.ack);
}
