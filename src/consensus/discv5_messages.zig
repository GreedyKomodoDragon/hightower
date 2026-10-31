// Discv5 encrypted UDP packets carry a one-byte message type followed by an
// RLP list. PING and PONG establish liveness and ENR sequence freshness;
// FINDNODE asks for peers by logarithmic distance. Request IDs are echoed
// unchanged so replies can be tied to the right in-flight query.
//
//   authenticated packet -> type byte + canonical RLP -> bounded message
// Packet encryption and the NODES response are handled separately.
const std = @import("std");
const rlp = @import("rlp");

pub const RequestId = struct {
    bytes: [8]u8 = [_]u8{0} ** 8,
    len: u8 = 0,

    /// Copy a request ID of at most eight bytes.
    pub fn init(value: []const u8) !RequestId {
        if (value.len > 8) return error.InvalidRequestId;
        var result: RequestId = .{ .len = @intCast(value.len) };
        @memcpy(result.bytes[0..value.len], value);
        return result;
    }

    /// Return the used request ID bytes.
    pub fn slice(self: *const RequestId) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const Ping = struct { request_id: RequestId, enr_sequence: u64 };
pub const Pong = struct { request_id: RequestId, enr_sequence: u64, recipient_ip: [16]u8, ip_len: u8, recipient_port: u16 };
pub const FindNode = struct { request_id: RequestId, distances: [16]u16 = [_]u16{0} ** 16, count: u8 = 0 };
pub const Message = union(enum) { ping: Ping, pong: Pong, findnode: FindNode };

/// Encode one bounded plaintext message for an authenticated discv5 packet.
pub fn encode(allocator: std.mem.Allocator, message: Message) ![]u8 {
    var payload = std.Io.Writer.Allocating.init(allocator);
    defer payload.deinit();
    const kind: u8 = switch (message) {
        .ping => |ping| blk: {
            try rlp.encoding.encodeString(&payload.writer, ping.request_id.slice());
            try writeInt(&payload.writer, ping.enr_sequence);
            break :blk 1;
        },
        .pong => |pong| blk: {
            if (pong.ip_len != 4 and pong.ip_len != 16 or pong.recipient_port == 0) return error.InvalidEndpoint;
            try rlp.encoding.encodeString(&payload.writer, pong.request_id.slice());
            try writeInt(&payload.writer, pong.enr_sequence);
            try rlp.encoding.encodeString(&payload.writer, pong.recipient_ip[0..pong.ip_len]);
            try writeInt(&payload.writer, pong.recipient_port);
            break :blk 2;
        },
        .findnode => |find| blk: {
            if (find.count == 0 or find.count > 16) return error.InvalidDistance;
            try rlp.encoding.encodeString(&payload.writer, find.request_id.slice());
            var nested = std.Io.Writer.Allocating.init(allocator);
            defer nested.deinit();
            for (find.distances[0..find.count]) |distance| {
                if (distance > 256) return error.InvalidDistance;
                try writeInt(&nested.writer, distance);
            }
            try rlp.encoding.encodeListHeader(&payload.writer, nested.written().len);
            try payload.writer.writeAll(nested.written());
            break :blk 3;
        },
    };
    var output = std.Io.Writer.Allocating.init(allocator);
    errdefer output.deinit();
    try output.writer.writeByte(kind);
    try rlp.encoding.encodeListHeader(&output.writer, payload.written().len);
    try output.writer.writeAll(payload.written());
    const bytes = try output.toOwnedSlice();
    if (bytes.len > 1280) {
        allocator.free(bytes);
        return error.MessageTooLarge;
    }
    return bytes;
}

/// Parse and canonically validate one bounded plaintext discv5 message.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !Message {
    if (bytes.len < 2 or bytes.len > 1280) return error.InvalidMessage;
    var value = try rlp.decode.decodeAll(allocator, bytes[1..]);
    defer value.deinit(allocator);
    const items = switch (value) {
        .list => |list| list,
        else => return error.InvalidMessage,
    };
    const message: Message = switch (bytes[0]) {
        1 => blk: {
            if (items.len != 2) return error.InvalidMessage;
            break :blk .{ .ping = .{ .request_id = try RequestId.init(try string(items[0])), .enr_sequence = try integer(u64, try string(items[1])) } };
        },
        2 => blk: {
            if (items.len != 4) return error.InvalidMessage;
            const ip = try string(items[2]);
            if (ip.len != 4 and ip.len != 16) return error.InvalidEndpoint;
            var pong = Pong{ .request_id = try RequestId.init(try string(items[0])), .enr_sequence = try integer(u64, try string(items[1])), .recipient_ip = [_]u8{0} ** 16, .ip_len = @intCast(ip.len), .recipient_port = try integer(u16, try string(items[3])) };
            @memcpy(pong.recipient_ip[0..ip.len], ip);
            break :blk .{ .pong = pong };
        },
        3 => blk: {
            if (items.len != 2) return error.InvalidMessage;
            const distances = switch (items[1]) {
                .list => |list| list,
                else => return error.InvalidMessage,
            };
            if (distances.len == 0 or distances.len > 16) return error.InvalidDistance;
            var find = FindNode{ .request_id = try RequestId.init(try string(items[0])) };
            for (distances, 0..) |distance, index| {
                find.distances[index] = try integer(u16, try string(distance));
                if (find.distances[index] > 256) return error.InvalidDistance;
            }
            find.count = @intCast(distances.len);
            break :blk .{ .findnode = find };
        },
        else => return error.UnsupportedMessage,
    };
    const canonical = try encode(allocator, message);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, bytes, canonical)) return error.InvalidMessage;
    return message;
}

/// Return an RLP byte string without accepting a nested list.
fn string(value: rlp.decode.Value) ![]const u8 {
    return switch (value) {
        .string => |data| data,
        else => error.InvalidMessage,
    };
}

/// Read a minimal big-endian RLP integer into a bounded Zig type.
fn integer(comptime T: type, bytes: []const u8) !T {
    if (bytes.len > @sizeOf(T) or (bytes.len > 0 and bytes[0] == 0)) return error.InvalidMessage;
    var result: T = 0;
    for (bytes) |byte| result = (result << 8) | byte;
    return result;
}

/// Write one minimal big-endian RLP integer.
fn writeInt(writer: *std.Io.Writer, number: anytype) !void {
    var buffer: [8]u8 = undefined;
    try rlp.encoding.encodeString(writer, rlp.encoding.encodeBigEndian(&buffer, number));
}

test "discv5 ping, pong, and findnode plaintext is canonical and bounded" {
    const allocator = std.testing.allocator;
    const request_id = try RequestId.init(&.{ 1, 2, 3 });
    const ping = try encode(allocator, .{ .ping = .{ .request_id = request_id, .enr_sequence = 7 } });
    defer allocator.free(ping);
    try std.testing.expectEqualSlices(u8, &.{ 1, 0xc5, 0x83, 1, 2, 3, 7 }, ping);
    try std.testing.expectEqual(@as(u64, 7), (try decode(allocator, ping)).ping.enr_sequence);
    const pong = try encode(allocator, .{ .pong = .{ .request_id = request_id, .enr_sequence = 8, .recipient_ip = .{ 127, 0, 0, 1 } ++ [_]u8{0} ** 12, .ip_len = 4, .recipient_port = 9000 } });
    defer allocator.free(pong);
    try std.testing.expectEqual(@as(u16, 9000), (try decode(allocator, pong)).pong.recipient_port);
    var find = FindNode{ .request_id = request_id, .count = 2 };
    find.distances[0] = 0;
    find.distances[1] = 256;
    const find_bytes = try encode(allocator, .{ .findnode = find });
    defer allocator.free(find_bytes);
    try std.testing.expectEqual(@as(u16, 256), (try decode(allocator, find_bytes)).findnode.distances[1]);
    try std.testing.expectError(error.InvalidMessage, decode(allocator, &.{ 1, 0xc3, 0x81, 0x01, 0x01 }));
    try std.testing.expectError(error.InvalidRequestId, RequestId.init(&.{ 0, 1, 2, 3, 4, 5, 6, 7, 8 }));
}
