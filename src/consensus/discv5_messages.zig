// Discv5 encrypted UDP packets carry a one-byte message type followed by an
// RLP list. PING and PONG establish liveness and ENR sequence freshness;
// FINDNODE asks for peers by logarithmic distance. Request IDs are echoed
// unchanged so replies can be tied to the right in-flight query.
//
//   authenticated packet -> type byte + canonical RLP -> bounded message
// Packet encryption and discovery scheduling are handled separately.
const std = @import("std");
const rlp = @import("rlp");
const enr = @import("enr.zig");

// 1280-byte UDP packet minus ordinary-packet IV, header, node ID, and GCM tag.
pub const max_plaintext_size: usize = 1280 - 16 - 23 - 32 - 16;

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
pub const Nodes = struct {
    request_id: RequestId,
    total: u8,
    records: [16]enr.Record = undefined,
    encoded: [16][300]u8 = undefined,
    encoded_len: [16]u16 = undefined,
    count: u8 = 0,

    /// Return the canonical signed ENR bytes at a validated reply index.
    pub fn raw(self: *const Nodes, index: usize) []const u8 {
        std.debug.assert(index < self.count);
        return self.encoded[index][0..self.encoded_len[index]];
    }
};

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
    if (bytes.len > max_plaintext_size) {
        allocator.free(bytes);
        return error.MessageTooLarge;
    }
    return bytes;
}

/// Parse and canonically validate one bounded plaintext discv5 message.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !Message {
    if (bytes.len < 2 or bytes.len > max_plaintext_size) return error.InvalidMessage;
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

/// Encode a NODES reply from signed ENRs, each verified for the current fork.
pub fn encodeNodes(allocator: std.mem.Allocator, request_id: RequestId, total: u8, records: []const []const u8, fork_digest: [4]u8) ![]u8 {
    if (total == 0 or total > 16 or records.len > 16) return error.InvalidNodes;
    var nested = std.Io.Writer.Allocating.init(allocator);
    defer nested.deinit();
    for (records) |bytes| {
        const record = try enr.decode(allocator, bytes);
        try enr.requireFork(record, fork_digest);
        try nested.writer.writeAll(bytes);
    }
    var payload = std.Io.Writer.Allocating.init(allocator);
    defer payload.deinit();
    try rlp.encoding.encodeString(&payload.writer, request_id.slice());
    try writeInt(&payload.writer, total);
    try rlp.encoding.encodeListHeader(&payload.writer, nested.written().len);
    try payload.writer.writeAll(nested.written());
    var output = std.Io.Writer.Allocating.init(allocator);
    errdefer output.deinit();
    try output.writer.writeByte(4);
    try rlp.encoding.encodeListHeader(&output.writer, payload.written().len);
    try output.writer.writeAll(payload.written());
    const bytes = try output.toOwnedSlice();
    if (bytes.len > max_plaintext_size) {
        allocator.free(bytes);
        return error.MessageTooLarge;
    }
    return bytes;
}

/// Verify a canonical NODES reply and its signed ENRs before exposing peers.
pub fn decodeNodes(allocator: std.mem.Allocator, bytes: []const u8, fork_digest: [4]u8) !Nodes {
    if (bytes.len < 2 or bytes.len > max_plaintext_size or bytes[0] != 4) return error.InvalidNodes;
    var value = try rlp.decode.decodeAll(allocator, bytes[1..]);
    defer value.deinit(allocator);
    const items = switch (value) {
        .list => |list| list,
        else => return error.InvalidNodes,
    };
    if (items.len != 3) return error.InvalidNodes;
    var canonical = std.Io.Writer.Allocating.init(allocator);
    defer canonical.deinit();
    try writeValue(allocator, &canonical.writer, value);
    if (!std.mem.eql(u8, bytes[1..], canonical.written())) return error.InvalidNodes;
    const records = switch (items[2]) {
        .list => |list| list,
        else => return error.InvalidNodes,
    };
    if (records.len > 16) return error.InvalidNodes;
    var result = Nodes{ .request_id = try RequestId.init(try string(items[0])), .total = try integer(u8, try string(items[1])) };
    if (result.total == 0 or result.total > 16) return error.InvalidNodes;
    for (records, 0..) |item, index| {
        var encoded_record = std.Io.Writer.Allocating.init(allocator);
        defer encoded_record.deinit();
        try writeValue(allocator, &encoded_record.writer, item);
        result.records[index] = try enr.decode(allocator, encoded_record.written());
        try enr.requireFork(result.records[index], fork_digest);
        result.encoded_len[index] = @intCast(encoded_record.written().len);
        @memcpy(result.encoded[index][0..result.encoded_len[index]], encoded_record.written());
    }
    result.count = @intCast(records.len);
    return result;
}

/// Re-encode a bounded RLP value so altered noncanonical bytes can be rejected.
fn writeValue(allocator: std.mem.Allocator, writer: *std.Io.Writer, value: rlp.decode.Value) !void {
    switch (value) {
        .string => |data| return rlp.encoding.encodeString(writer, data),
        .list => |items| {
            var payload = std.Io.Writer.Allocating.init(allocator);
            defer payload.deinit();
            for (items) |item| try writeValue(allocator, &payload.writer, item);
            try rlp.encoding.encodeListHeader(writer, payload.written().len);
            return writer.writeAll(payload.written());
        },
    }
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
    var result: u64 = 0;
    for (bytes) |byte| result = (result << 8) | byte;
    return @intCast(result);
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

test "discv5 nodes reply verifies embedded ENRs and fork before admission" {
    const allocator = std.testing.allocator;
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
    const key = try Ecdsa.KeyPair.generateDeterministic([_]u8{7} ** 32);
    const fork_digest = [4]u8{ 1, 2, 3, 4 };
    const local = enr.Local{ .sequence = 1, .ip = .{ 127, 0, 0, 1 }, .udp_port = 9000, .tcp_port = 9001, .fork_id = .{ 1, 2, 3, 4, 6, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255 }, .next_fork_digest = .{0} ** 4, .custody_group_count = 4 };
    const record = try enr.encode(allocator, key, local);
    defer allocator.free(record);
    const request_id = try RequestId.init(&.{ 9, 8, 7 });
    const message = try encodeNodes(allocator, request_id, 1, &.{record}, fork_digest);
    defer allocator.free(message);
    const parsed = try decodeNodes(allocator, message, fork_digest);
    try std.testing.expectEqual(@as(u8, 1), parsed.count);
    try std.testing.expectEqualSlices(u8, request_id.slice(), parsed.request_id.slice());
    try std.testing.expectEqual(@as(u16, 9000), parsed.records[0].udp_port);
    try std.testing.expectError(error.InvalidForkContext, decodeNodes(allocator, message, .{ 9, 2, 3, 4 }));
    const tampered = try allocator.dupe(u8, message);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(error.SignatureVerificationFailed, decodeNodes(allocator, tampered, fork_digest));
    try std.testing.expectError(error.InvalidNodes, decodeNodes(allocator, &.{ 4, 0xc0 }, fork_digest));
    try std.testing.expectError(error.InvalidNodes, decodeNodes(allocator, &.{ 4, 0xc4, 0x80, 0x81, 0x01, 0xc0 }, fork_digest));
}
